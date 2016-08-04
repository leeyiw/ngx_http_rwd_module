#ifndef _NGX_HTTP_RWD_MODULE_H_
#define _NGX_HTTP_RWD_MODULE_H_

#include "ngx_http_rwd_config.h"

typedef struct {
    ngx_rbtree_t dm_cfg_rbtree;
    ngx_rbtree_node_t dm_cfg_sentinel;
} ngx_http_rwd_shctx_t;

typedef struct {
    ngx_http_rwd_shctx_t *sh;
    ngx_slab_pool_t *shpool;
} ngx_http_rwd_ctx_t;

extern ngx_http_rwd_ctx_t ngx_rwd_ctx;

#endif /* ifndef _NGX_HTTP_RWD_MODULE_H_ */
