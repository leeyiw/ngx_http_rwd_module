#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_rwd_module.h"

ngx_int_t
ngx_http_rwd_block_handler(ngx_http_request_t *r)
{
    ngx_http_rwd_main_conf_t *rmcf;
    ngx_http_rwd_module_ctx_t *rctx;

    rmcf = (ngx_http_rwd_main_conf_t *)ngx_http_get_module_main_conf(
        r, ngx_http_rwd_module);
    if (!rmcf->rwd_enable) {
        return NGX_DECLINED;
    }

    rctx = (ngx_http_rwd_module_ctx_t *)ngx_http_get_module_ctx(r,
        ngx_http_rwd_module);
    if (rctx == NULL) {
        rctx = (ngx_http_rwd_module_ctx_t *)ngx_palloc(r->pool,
            sizeof(ngx_http_rwd_module_ctx_t));
        if (rctx == NULL) {
            return NGX_DECLINED;
        }
        ngx_memzero(rctx, sizeof(ngx_http_rwd_module_ctx_t));
    }

    if (rctx->host.len == 0) {
        rctx->host = r->headers_in.server;
    }

    // TODO domain blacklist
    // TODO default domain blacklist

    return NGX_DECLINED;
}
