#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_socket.h>

#include <jansson.h>

#include "rwd.pb-c.h"

#define NGX_HTTP_RWD_DEFAULT_SHM_SIZE   (32*1024*1024)

typedef struct {
    ngx_flag_t rwd_enable;
    ngx_str_t rwd_copy_req_sock;
} ngx_http_rwd_main_conf_t;

typedef enum {
    NGX_HTTP_RWD_BL_ITEM_TYPE_IP
} ngx_http_rwd_bl_item_type_t;

typedef enum {
    NGX_HTTP_RWD_ACTION_DENY
} ngx_http_rwd_action_t;

typedef struct {
    ngx_rbtree_node_t node;
    ngx_http_rwd_bl_item_type_t type;
    ngx_str_t key;
    union {
        ngx_uint_t ip;
    } value;
    ngx_http_rwd_action_t action;
} ngx_http_rwd_bl_item_t;

typedef struct {
    ngx_rbtree_t rbtree;
    ngx_rbtree_node_t sentinel;
} ngx_http_rwd_bl_t;

typedef struct {
    ngx_http_rwd_bl_t ip_bl;
} ngx_http_rwd_shctx_t;

typedef struct {
    ngx_http_rwd_shctx_t *sh;
    ngx_slab_pool_t *shpool;
} ngx_http_rwd_ctx_t;

typedef ngx_uint_t ngx_http_rwd_config_handler_pt(ngx_http_request_t *r);
typedef struct {
    ngx_str_t uri;
    ngx_int_t method;
    ngx_http_handler_pt handler;
} ngx_http_rwd_config_handler_t;

static void *ngx_http_rwd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_rwd_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_rwd_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rwd_init_worker(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_rwd_preaccess_handler(ngx_http_request_t *r);
static char *ngx_http_rwd_config(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);
static ngx_int_t ngx_http_rwd_config_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_rwd_config_dynamic_bl_add(ngx_http_request_t *r);

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
static ngx_http_rwd_ctx_t ngx_rwd_ctx;
static ngx_http_rwd_config_handler_t ngx_rwd_config_handlers[] = {
    {
        ngx_string("/dynamic_bl/add"),
        NGX_HTTP_POST,
        ngx_http_rwd_config_dynamic_bl_add
    }
};

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

    ngx_rbtree_init(&ctx->sh->ip_bl.rbtree,
                    &ctx->sh->ip_bl.sentinel,
                    ngx_rbtree_insert_value);

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
    *h = ngx_http_rwd_preaccess_handler;

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
ngx_http_rwd_preaccess_handler(ngx_http_request_t *r)
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

static char *
ngx_http_rwd_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(
        cf, ngx_http_core_module);
    clcf->handler = ngx_http_rwd_config_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rwd_config_handler(ngx_http_request_t *r)
{
    size_t i;
    ngx_http_rwd_config_handler_t *rch;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "[rwd] config API %V called", &r->uri);

    for (i = 0;
         i < sizeof(ngx_rwd_config_handlers)/sizeof(ngx_rwd_config_handlers[0]);
         i++) {
        rch = &ngx_rwd_config_handlers[i];
        if (ngx_strncmp(rch->uri.data, r->uri.data, rch->uri.len) == 0) {
            if (!(r->method & rch->method)) {
                return NGX_HTTP_NOT_ALLOWED;
            }
            return rch->handler(r);
        }
    }

    return NGX_OK;
}

static json_t *
ngx_http_rwd_parse_request_body_into_json(ngx_http_request_t *r)
{
    u_char *buf, *p = NULL;
    size_t len;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    json_t *json;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NULL;
    }

    if (r->request_body->bufs->next == NULL) {
        b = r->request_body->bufs->buf;
        if (ngx_buf_size(b) == 0 || !ngx_buf_in_memory_only(b)) {
            return NULL;
        }
        buf = b->pos;
        len = b->end - b->pos;
    } else {
        len = 0;
        for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
            if (!ngx_buf_in_memory_only(cl->buf)) {
                return NULL;
            }
            len += ngx_buf_size(cl->buf);
        }
        buf = (u_char *)ngx_palloc(r->pool, len);
        if (buf == NULL) {
            return NULL;
        }
        for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, ngx_buf_size(cl->buf));
        }
    }

    json = json_loadb((const char *)buf, len, 0, NULL);
    if (p) {
        ngx_pfree(r->pool, buf);
    }

    return json;
}

static ngx_http_rwd_bl_item_t *
ngx_http_rwd_parse_bl_item(json_t *item)
{
    json_t *type, *action, *value;
    const char *type_str, *action_str;
    ngx_http_rwd_bl_item_t *bl_item = NULL;
    ngx_rbtree_key_t key;

    bl_item = (ngx_http_rwd_bl_item_t *)ngx_slab_alloc_locked(
        ngx_rwd_ctx.shpool, sizeof(ngx_http_rwd_bl_item_t));
    ngx_memzero(bl_item, sizeof(ngx_http_rwd_bl_item_t));

    type = json_object_get(item, "type");
    if (type == NULL || !json_is_string(type)) {
        goto error;
    }
    type_str = json_string_value(type);

    if (ngx_strcasecmp((u_char *)type_str, (u_char *)"ip") == 0) {
        value = json_object_get(item, "value");
        if (value == NULL || !json_is_integer(value)) {
            goto error;
        }
        bl_item->type = NGX_HTTP_RWD_BL_ITEM_TYPE_IP;
        ngx_str_null(&bl_item->key);
        bl_item->value.ip = json_integer_value(value);
        key = bl_item->value.ip;
    } else {
        goto error;
    }

    bl_item->node.key = key;

    action = json_object_get(item, "action");
    if (action == NULL || !json_is_string(action)) {
        goto error;
    }
    action_str = json_string_value(action);
    if (ngx_strcasecmp((u_char *)action_str, (u_char *)"deny") == 0) {
        bl_item->action = NGX_HTTP_RWD_ACTION_DENY;
    } else {
        goto error;
    }

    return bl_item;

error:
    ngx_slab_free_locked(ngx_rwd_ctx.shpool, bl_item);
    return NULL;
}

static ngx_int_t
ngx_http_rwd_config_dynamic_bl_add(ngx_http_request_t *r)
{
    size_t i;
    json_t *json, *item_arr, *item;
    ngx_http_rwd_bl_item_t *bl_item;

    json = ngx_http_rwd_parse_request_body_into_json(r);
    if (json == NULL) {
        goto error;
    }

    item_arr = json_object_get(json, "items");
    if (item_arr == NULL || !json_is_array(item_arr)) {
        goto error;
    }

    json_array_foreach(item_arr, i, item) {
        bl_item = ngx_http_rwd_parse_bl_item(item);
        if (bl_item == NULL) {
            goto error;
        }
        switch (bl_item->type) {
        case NGX_HTTP_RWD_BL_ITEM_TYPE_IP:
            ngx_rbtree_insert(&ngx_rwd_ctx.sh->ip_bl.rbtree,
                              (ngx_rbtree_node_t *)bl_item);
            break;
        default:
            ngx_slab_free_locked(ngx_rwd_ctx.shpool, bl_item);
            goto error;
        }
    }

    return NGX_HTTP_INTERNAL_SERVER_ERROR;

error:
    if (json != NULL) {
        json_decref(json);
    }
    return NGX_HTTP_BAD_REQUEST;
}
