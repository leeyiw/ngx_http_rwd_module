#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
    ngx_flag_t rwd_enable;
} ngx_http_rwd_main_conf_t;

static void *ngx_http_rwd_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_rwd_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_rwd_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_rwd_preaccess_handler(ngx_http_request_t *r);

static ngx_command_t ngx_http_rwd_commands[] = {
    {
        ngx_string("rwd"),
        NGX_HTTP_MAIN_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_rwd_main_conf_t, rwd_enable),
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
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

static void *
ngx_http_rwd_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_rwd_main_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_rwd_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }
    conf->rwd_enable = NGX_CONF_UNSET;

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

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
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

    rmcf = ngx_http_get_module_main_conf(r, ngx_http_rwd_module);
    if (!rmcf->rwd_enable) {
        return NGX_DECLINED;
    }

    return NGX_DECLINED;
}
