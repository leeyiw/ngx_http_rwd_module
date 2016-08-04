#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_socket.h>

#include "ngx_http_rwd_module.h"
#include "ngx_http_rwd_config.h"
#include "ngx_http_rwd_block.h"
#include "ngx_http_rwd_copy_request.h"

#define NGX_HTTP_RWD_DEFAULT_SHM_SIZE   (32*1024*1024)

static void *ngx_http_rwd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_rwd_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_rwd_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rwd_init_worker(ngx_cycle_t *cycle);

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
    ngx_http_rwd_main_conf_t *rmcf;

    rmcf = (ngx_http_rwd_main_conf_t *)ngx_http_cycle_get_module_main_conf(
        cycle, ngx_http_rwd_module);

    if (rmcf->rwd_copy_req_sock.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "[rwd] rwd_copy_req_sock not set");
        return NGX_OK;
    }

    ngx_http_rwd_copy_request_init(cycle, rmcf);

    return NGX_OK;
}
