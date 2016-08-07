#include <ngx_core.h>
#include <ngx_http.h>

#include "ngx_http_rwd_module.h"
#include "rwd.pb-c.h"

static ngx_socket_t copy_req_fd = 0;
static ngx_int_t copy_req_connected = 0;

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

ngx_int_t
ngx_http_rwd_copy_request_init(ngx_cycle_t *cycle,
                               ngx_http_rwd_main_conf_t *rmcf)
{
    struct sockaddr_un copy_req_addr;

    copy_req_fd = ngx_socket(AF_UNIX, SOCK_DGRAM, 0);
    if (copy_req_fd == -1) {
        ngx_log_error(NGX_LOG_CRIT, cycle->log, 0,
                      "[rwd] create copy_req_fd failed: %s",
                      strerror(ngx_errno));
        return NGX_ERROR;
    }
    ngx_memzero(&copy_req_addr, sizeof(copy_req_addr));
    copy_req_addr.sun_family = AF_UNIX;
    (void) ngx_copy(copy_req_addr.sun_path, rmcf->rwd_copy_req_sock.data,
                    rmcf->rwd_copy_req_sock.len);

    if (connect(copy_req_fd, (struct sockaddr *)&copy_req_addr,
                sizeof(copy_req_addr)) != 0) {
        ngx_log_error(NGX_LOG_WARN, cycle->log, 0,
                      "[rwd] connect copy_req_fd failed: %s",
                      strerror(ngx_errno));
        return NGX_ERROR;
    }
    
    copy_req_connected = 1;

    return NGX_OK;
}

ngx_int_t
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

    if (!copy_req_connected) {
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

    send(copy_req_fd, buf, n, MSG_DONTWAIT);
    ngx_pfree(r->pool, buf);

    return NGX_DECLINED;
}
