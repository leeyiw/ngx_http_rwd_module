#include <sys/socket.h>
#include <sys/un.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_socket.h>

typedef struct
{
    ngx_flag_t rwd_enable;
    ngx_str_t rwd_copy_req_sock;
} ngx_http_rwd_main_conf_t;

static void *ngx_http_rwd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_rwd_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_rwd_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rwd_preaccess_handler(ngx_http_request_t *r);
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
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rwd_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt *h;
    ngx_http_core_main_conf_t *cmcf;

    cmcf = (ngx_http_core_main_conf_t *)ngx_http_conf_get_module_main_conf(
        cf, ngx_http_core_module);

    h = (ngx_http_handler_pt *)ngx_array_push(
        &cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_rwd_preaccess_handler;

    return NGX_OK;
}

static ngx_int_t
ngx_http_rwd_preaccess_handler(ngx_http_request_t *r)
{
    ngx_http_rwd_main_conf_t *rmcf;

    rmcf = (ngx_http_rwd_main_conf_t *)ngx_http_get_module_main_conf(
        r, ngx_http_rwd_module);
    if (!rmcf->rwd_enable) {
        return NGX_DECLINED;
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_rwd_init_worker(ngx_cycle_t *cycle)
{
    struct sockaddr_un copy_req_addr;
    ngx_http_rwd_main_conf_t *rmcf;

    rmcf = (ngx_http_rwd_main_conf_t *)ngx_http_cycle_get_module_main_conf(
        cycle, ngx_http_rwd_module);

    if (rmcf->rwd_copy_req_sock.data == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "rwd_copy_req_sock not set");
        return NGX_OK;
    }

    ngx_rwd_copy_req_fd = ngx_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (ngx_rwd_copy_req_fd == -1) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                      "create ngx_rwd_copy_req_fd failed: %s",
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
                      "connect ngx_rwd_copy_req_fd failed: %s",
                      strerror(ngx_errno));
    }

    return NGX_OK;
}
