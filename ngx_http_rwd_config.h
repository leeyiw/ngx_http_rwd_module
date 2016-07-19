#ifndef _NGX_HTTP_RWD_CONFIG_H_
#define _NGX_HTTP_RWD_CONFIG_H_

#include <ngx_core.h>
#include <ngx_http.h>

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
    ngx_str_t uri;
    ngx_int_t method;
    union {
        ngx_http_handler_pt get_handler;
        ngx_http_client_body_handler_pt post_handler;
    } handler;
} ngx_http_rwd_config_handler_t;

extern char *ngx_http_rwd_config(ngx_conf_t *cf, ngx_command_t *cmd,
                                 void *conf);

#endif /* ifndef _NGX_HTTP_RWD_CONFIG_H_ */
