#ifndef _NGX_HTTP_RWD_UTILS_H_
#define _NGX_HTTP_RWD_UTILS_H_

#include <ngx_core.h>

typedef ngx_int_t (*ngx_http_rwd_rbtree_compare_pt)(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t*node);

extern void ngx_http_rwd_rbtree_insert_value(
    ngx_rbtree_node_t *temp, ngx_rbtree_node_t *node,
    ngx_rbtree_node_t *sentinel, ngx_http_rwd_rbtree_compare_pt compare_func);
extern ngx_rbtree_node_t *ngx_http_rwd_rbtree_lookup_value(
    ngx_rbtree_t *rbtree, ngx_rbtree_node_t *target,
    ngx_http_rwd_rbtree_compare_pt compare_func);

#endif /* ifndef _NGX_HTTP_RWD_UTILS_H_ */
