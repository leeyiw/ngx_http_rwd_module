#ifndef _NGX_HTTP_RWD_COPY_REQUEST_H_
#define _NGX_HTTP_RWD_COPY_REQUEST_H_

#include <ngx_core.h>
#include <ngx_http.h>

extern ngx_int_t ngx_http_rwd_copy_request_handler(ngx_http_request_t *r);
extern ngx_int_t ngx_http_rwd_copy_request_init(
    ngx_cycle_t *cycle, ngx_http_rwd_main_conf_t *rmcf);

#endif /* ifndef _NGX_HTTP_RWD_COPY_REQUEST_H_ */
