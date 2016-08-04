#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_rwd_module.h"

ngx_int_t
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
