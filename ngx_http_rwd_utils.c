#include "ngx_http_rwd_utils.h"

void
ngx_http_rwd_rbtree_insert_value(ngx_rbtree_node_t *temp,
                                 ngx_rbtree_node_t *node,
                                 ngx_rbtree_node_t *sentinel,
                                 ngx_http_rwd_rbtree_compare_pt compare_func)
{
    ngx_int_t compare_result;
    ngx_rbtree_node_t **p;

    for (;;) {
        compare_result = compare_func(temp, node);
        if (compare_result == 0) {
            return;
        }
        p = compare_result < 0 ? &temp->left : &temp->right;
        if (*p == sentinel) {
            break;
        }
        temp = *p;
    }

    *p = node;
    node->parent = temp;
    node->left = sentinel;
    node->right = sentinel;
    ngx_rbt_red(node);
}

ngx_rbtree_node_t *
ngx_http_rwd_rbtree_lookup_value(ngx_rbtree_t *rbtree,
                                 ngx_rbtree_node_t *target,
                                 ngx_http_rwd_rbtree_compare_pt compare_func)
{
    ngx_rbtree_node_t *tmpnode = rbtree->root;

    while (tmpnode != rbtree->sentinel) {
        if (compare_func(target, tmpnode) == 0) {
            return tmpnode;
        }
    }

    return NULL;
}
