#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_socket.h>

#include "ngx_http_rwd_module.h"
#include "ngx_http_rwd_config.h"
#include "rwd.pb-c.h"

#define NGX_HTTP_RWD_DEFAULT_SHM_SIZE   (32*1024*1024)

typedef struct {
    ngx_flag_t rwd_enable;
    ngx_str_t rwd_copy_req_sock;
} ngx_http_rwd_main_conf_t;

static void *ngx_http_rwd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_rwd_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_rwd_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rwd_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_rwd_block_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_rwd_copy_request_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_rwd_commands[] = {
    {
        ngx_string("rwd"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_rwd_main_conf_t, rwd_enable),
        NULL
    },
    {
        ngx_string("rwd_copy_req_sock"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_rwd_main_conf_t, rwd_copy_req_sock),
        NULL
    },
    {
        ngx_string("rwd_config"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_rwd_config,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    },
    ngx_null_command
};

static ngx_http_module_t ngx_http_rwd_module_ctx = {
    NULL,                          /* preconfiguration */
    ngx_http_rwd_init,             /* postconfiguration */

    ngx_http_rwd_create_main_conf, /* create main configuration */
    ngx_http_rwd_init_main_conf,   /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    NULL,                          /* create location configuration */
    NULL                           /* merge location configuration */
};

ngx_module_t ngx_http_rwd_module = {
    NGX_MODULE_V1,
    &ngx_http_rwd_module_ctx,      /* module context */
    ngx_http_rwd_commands,         /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    ngx_http_rwd_init_worker,      /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_socket_t ngx_rwd_copy_req_fd = 0;
static ngx_shm_zone_t *ngx_rwd_shm_zone = NULL;

ngx_http_rwd_ctx_t ngx_rwd_ctx;

static void *
ngx_http_rwd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_rwd_main_conf_t *conf;

    conf = (ngx_http_rwd_main_conf_t *)ngx_pcalloc(
        cf->pool, sizeof(ngx_http_rwd_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->rwd_enable = NGX_CONF_UNSET;
    ngx_str_null(&(conf->rwd_copy_req_sock));

    return conf;
}

static char *
ngx_http_rwd_init_main_conf(ngx_conf_t *cf, void *conf)
{
    (void) cf;
    (void) conf;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rwd_init_shm_zone(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_http_rwd_ctx_t *octx = (ngx_http_rwd_ctx_t *)data;
    ngx_http_rwd_ctx_t *ctx = (ngx_http_rwd_ctx_t *)shm_zone->data;

    if (octx) {
        ctx->sh = octx->sh;
        ctx->shpool = octx->shpool;

        return NGX_OK;
    }

    ctx->shpool = (ngx_slab_pool_t *)shm_zone->shm.addr;
    ctx->sh = (ngx_http_rwd_shctx_t *)ngx_slab_alloc(
        ctx->shpool, sizeof(ngx_http_rwd_shctx_t));
    if (ctx->sh == NULL) {
        return NGX_ERROR;
    }

    ngx_rbtree_init(&ctx->sh->dm_cfg_rbtree, &ctx->sh->dm_cfg_sentinel,
                    ngx_http_rwd_dm_cfg_rbtree_insert);

    return NGX_OK;
}

static ngx_int_t
ngx_http_rwd_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;
    ngx_str_t shm_name = ngx_string("rwd");

    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(
        cf, ngx_http_core_module);

    ngx_rwd_shm_zone = ngx_shared_memory_add(cf, &shm_name,
                                             NGX_HTTP_RWD_DEFAULT_SHM_SIZE,
                                             &ngx_http_rwd_module);
    if (ngx_rwd_shm_zone == NULL) {
        return NGX_ERROR;
    }
    ngx_rwd_shm_zone->init = ngx_http_rwd_init_shm_zone;
    ngx_rwd_shm_zone->data = &ngx_rwd_ctx;

    h = (ngx_http_handler_pt *)ngx_array_push(
        &cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_rwd_block_handler;

    h = (ngx_http_handler_pt *)ngx_array_push(
        &cmcf->phases[NGX_HTTP_LOG_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_rwd_copy_request_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_rwd_init_worker(ngx_cycle_t *cycle)
{
    struct sockaddr_un copy_req_addr;
    ngx_http_rwd_main_conf_t *rmcf;

    rmcf = (ngx_http_rwd_main_conf_t *)ngx_http_cycle_get_module_main_conf(
        cycle, ngx_http_rwd_module);

    if (rmcf->rwd_copy_req_sock.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "[rwd] rwd_copy_req_sock not set");
        return NGX_OK;
    }

    ngx_rwd_copy_req_fd = ngx_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (ngx_rwd_copy_req_fd == -1) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                      "[rwd] create ngx_rwd_copy_req_fd failed: %s",
                      strerror(ngx_errno));
        return NGX_ERROR;
    }
    ngx_memzero(&copy_req_addr, sizeof(copy_req_addr));
    copy_req_addr.sun_family = AF_UNIX;
    (void) ngx_copy(copy_req_addr.sun_path, rmcf->rwd_copy_req_sock.data,
                    rmcf->rwd_copy_req_sock.len);

    if (connect(ngx_rwd_copy_req_fd, (struct sockaddr *)&copy_req_addr,
                sizeof(copy_req_addr)) != 0) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "[rwd] connect ngx_rwd_copy_req_fd failed: %s",
                      strerror(ngx_errno));
    }

    return NGX_OK;
}

static char *
rwd_pstrdup(ngx_pool_t *pool, ngx_str_t *src)
{
    char *dst;

    dst = (char *)ngx_pnalloc(pool, src->len + 1);
    if (dst == NULL) {
        return NULL;
    }

    (void) ngx_copy(dst, src->data, src->len);
    dst[src->len] = '\0';

    return dst;
}

static ngx_int_t
ngx_http_rwd_block_handler(ngx_http_request_t *r)
{
    //ngx_uint_t client_ip;
    ngx_http_rwd_main_conf_t *rmcf;

    rmcf = (ngx_http_rwd_main_conf_t *)ngx_http_get_module_main_conf(
        r, ngx_http_rwd_module);
    if (!rmcf->rwd_enable) {
        return NGX_DECLINED;
    }

    // check if client IP address in blacklist
    //if (r->connection->sockaddr->sa_family == AF_INET) {
    //    client_ip = (uint32_t)
    //        ((struct sockaddr_in *)r->connection->sockaddr)->sin_addr.s_addr;
    //}

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_rwd_copy_request_handler(ngx_http_request_t *r)
{
    ngx_http_rwd_main_conf_t *rmcf;
    RwdCopyReqMsg rcrm = RWD_COPY_REQ_MSG__INIT;
    uint8_t *buf;
    size_t n;

    rmcf = (ngx_http_rwd_main_conf_t *)ngx_http_get_module_main_conf(
        r, ngx_http_rwd_module);
    if (!rmcf->rwd_enable) {
        return NGX_DECLINED;
    }

    // client address
    if (r->connection->sockaddr->sa_family == AF_INET) {
        rcrm.client_ip = (uint32_t)
            ((struct sockaddr_in *)r->connection->sockaddr)->sin_addr.s_addr;
    }

    // request URI
    rcrm.uri = rwd_pstrdup(r->pool, &r->uri);

    n = rwd_copy_req_msg__get_packed_size(&rcrm);
    buf = (uint8_t *)ngx_palloc(r->pool, n);
    if (buf == NULL) {
        return NGX_DECLINED;
    }
    rwd_copy_req_msg__pack(&rcrm, buf);

    send(ngx_rwd_copy_req_fd, buf, n, MSG_DONTWAIT);
    ngx_pfree(r->pool, buf);

    return NGX_DECLINED;
}
