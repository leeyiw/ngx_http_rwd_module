#include <jansson.h>

#include "ngx_http_rwd_config.h"
#include "ngx_http_rwd_module.h"
#include "ngx_http_rwd_utils.h"

static ngx_int_t ngx_http_rwd_config_handler(ngx_http_request_t *r);
static void ngx_http_rwd_config_dynamic_bl_add(ngx_http_request_t *r);

static ngx_http_rwd_config_handler_t ngx_rwd_config_handlers[] = {
    {
        ngx_string("/dynamic_bl/add"),
        NGX_HTTP_POST,
        {.post_handler = ngx_http_rwd_config_dynamic_bl_add}
    }
};

char *
ngx_http_rwd_config(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = (ngx_http_core_loc_conf_t *)ngx_http_conf_get_module_loc_conf(
        cf, ngx_http_core_module);
    clcf->handler = ngx_http_rwd_config_handler;

    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_rwd_ip_bl_rbtree_compare(ngx_rbtree_node_t *temp,
                                  ngx_rbtree_node_t *node)
{
    ngx_http_rwd_bl_item_t *t = (ngx_http_rwd_bl_item_t *)temp;
    ngx_http_rwd_bl_item_t *n = (ngx_http_rwd_bl_item_t *)node;

    if (node->key != temp->key) {
        return (node->key < temp->key) ? -1 : 1;
    } else if (n->value.ip != t->value.ip) {
        return (n->value.ip < t->value.ip) ? -1 : 1;
    } else {
        return 0;
    }
}

void
ngx_http_rwd_ip_bl_rbtree_insert(ngx_rbtree_node_t *temp,
                                  ngx_rbtree_node_t *node,
                                  ngx_rbtree_node_t *sentinel)
{
    return ngx_http_rwd_rbtree_insert_value(temp, node, sentinel,
        ngx_http_rwd_ip_bl_rbtree_compare);
}

//static ngx_rbtree_node_t *
//ngx_http_rwd_ip_bl_rbtree_lookup(ngx_rbtree_t *rbtree,
//                                  ngx_rbtree_node_t *target)
//{
//    return ngx_http_rwd_rbtree_lookup_value(rbtree, target,
//        ngx_http_rwd_ip_bl_rbtree_compare);
//}

static ngx_int_t
ngx_http_rwd_dm_cfg_rbtree_compare(ngx_rbtree_node_t *temp,
                                   ngx_rbtree_node_t *node)
{
    ngx_http_rwd_dm_cfg_t *t = (ngx_http_rwd_dm_cfg_t *)temp;
    ngx_http_rwd_dm_cfg_t *n = (ngx_http_rwd_dm_cfg_t *)node;

    if (node->key != temp->key) {
        return (node->key < temp->key) ? -1 : 1;
    } else if (n->dm.len != t->dm.len) {
        return (n->dm.len < t->dm.len) ? -1 : 1;
    } else {
        return ngx_strncmp(n->dm.data, t->dm.data, n->dm.len);
    }
}

void
ngx_http_rwd_dm_cfg_rbtree_insert(ngx_rbtree_node_t *temp,
                                  ngx_rbtree_node_t *node,
                                  ngx_rbtree_node_t *sentinel)
{
    return ngx_http_rwd_rbtree_insert_value(temp, node, sentinel,
        ngx_http_rwd_dm_cfg_rbtree_compare);
}

static ngx_rbtree_node_t *
ngx_http_rwd_dm_cfg_rbtree_lookup(ngx_rbtree_t *rbtree,
                                  ngx_rbtree_node_t *target)
{
    return ngx_http_rwd_rbtree_lookup_value(rbtree, target,
        ngx_http_rwd_dm_cfg_rbtree_compare);
}

static ngx_http_rwd_dm_cfg_t *
ngx_http_rwd_dm_cfg_rbtree_get(ngx_http_rwd_dm_cfg_t *target)
{
    ngx_http_rwd_dm_cfg_t *dm_cfg = NULL;

    dm_cfg = (ngx_http_rwd_dm_cfg_t *)ngx_http_rwd_dm_cfg_rbtree_lookup(
        &ngx_rwd_ctx.sh->dm_cfg_rbtree, &target->node);
    if (dm_cfg != NULL) {
        return dm_cfg;
    }

    dm_cfg = (ngx_http_rwd_dm_cfg_t *)ngx_slab_alloc_locked(
        ngx_rwd_ctx.shpool, sizeof(ngx_http_rwd_dm_cfg_t));
    if (dm_cfg == NULL) {
        goto error;
    }
    dm_cfg->node.key = target->node.key;
    dm_cfg->dm.len = target->dm.len;
    dm_cfg->dm.data = (u_char *)ngx_slab_alloc_locked(ngx_rwd_ctx.shpool,
        dm_cfg->dm.len);
    if (dm_cfg->dm.data == NULL) {
        goto error;
    }
    ngx_memcpy(dm_cfg->dm.data, target->dm.data, dm_cfg->dm.len);
    ngx_rbtree_init(&dm_cfg->ip_bl.rbtree, &dm_cfg->ip_bl.sentinel,
        ngx_http_rwd_ip_bl_rbtree_insert);

    ngx_rbtree_insert(&ngx_rwd_ctx.sh->dm_cfg_rbtree, &dm_cfg->node);

    return dm_cfg;

error:
    if (dm_cfg != NULL) {
        if (dm_cfg->dm.data != NULL) {
            ngx_slab_free_locked(ngx_rwd_ctx.shpool, dm_cfg->dm.data);
        }
        ngx_slab_free_locked(ngx_rwd_ctx.shpool, dm_cfg);
    }
    return NULL;
}

static ngx_int_t
ngx_http_rwd_config_default_handler(ngx_http_request_t *r)
{
    return NGX_OK;
}

static ngx_int_t
ngx_http_rwd_config_handler(ngx_http_request_t *r)
{
    size_t i;
    ngx_int_t rc;
    ngx_http_rwd_config_handler_t *rch;

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0,
                  "[rwd] config API %V called", &r->uri);

    for (i = 0;
         i < sizeof(ngx_rwd_config_handlers)/sizeof(ngx_rwd_config_handlers[0]);
         i++) {
        rch = &ngx_rwd_config_handlers[i];
        if (ngx_strncmp(rch->uri.data, r->uri.data, rch->uri.len) == 0) {
            if (!(r->method & rch->method)) {
                return NGX_HTTP_NOT_ALLOWED;
            }
            if (r->method == NGX_HTTP_POST) {
                rc = ngx_http_read_client_request_body(
                    r, rch->handler.post_handler);
                if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
                    return rc;
                }
                return NGX_DONE;
            } else {
                return rch->handler.get_handler(r);
            }
        }
    }

    return ngx_http_rwd_config_default_handler(r);
}

static void
ngx_http_rwd_send_config_response(ngx_http_request_t *r, ngx_int_t status,
                                  json_t *json)
{
    r->headers_out.status = NGX_HTTP_OK;
    r->header_only = 1;
    r->headers_out.content_length_n = 0;
    ngx_http_finalize_request(r, ngx_http_send_header(r));
}

static json_t *
ngx_http_rwd_parse_request_body_into_json(ngx_http_request_t *r)
{
    u_char *buf, *p = NULL;
    size_t len;
    ngx_buf_t *b;
    ngx_chain_t *cl;
    json_t *json;

    if (r->request_body == NULL || r->request_body->bufs == NULL) {
        return NULL;
    }

    if (r->request_body->bufs->next == NULL) {
        b = r->request_body->bufs->buf;
        if (ngx_buf_size(b) == 0 || !ngx_buf_in_memory_only(b)) {
            return NULL;
        }
        buf = b->pos;
        len = ngx_buf_size(b);
    } else {
        len = 0;
        for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
            if (!ngx_buf_in_memory_only(cl->buf)) {
                return NULL;
            }
            len += ngx_buf_size(cl->buf);
        }
        buf = (u_char *)ngx_palloc(r->pool, len);
        if (buf == NULL) {
            return NULL;
        }
        for (cl = r->request_body->bufs; cl != NULL; cl = cl->next) {
            p = ngx_copy(p, cl->buf->pos, ngx_buf_size(cl->buf));
        }
    }

    json = json_loadb((const char *)buf, len, 0, NULL);
    if (p) {
        ngx_pfree(r->pool, buf);
    }

    return json;
}

static ngx_http_rwd_bl_item_t *
ngx_http_rwd_parse_bl_item(json_t *item)
{
    json_t *type, *action, *value;
    const char *type_str, *action_str;
    ngx_http_rwd_bl_item_t *bl_item = NULL;
    ngx_rbtree_key_t key;

    bl_item = (ngx_http_rwd_bl_item_t *)ngx_slab_alloc_locked(
        ngx_rwd_ctx.shpool, sizeof(ngx_http_rwd_bl_item_t));
    ngx_memzero(bl_item, sizeof(ngx_http_rwd_bl_item_t));

    type = json_object_get(item, "type");
    if (type == NULL || !json_is_string(type)) {
        goto error;
    }
    type_str = json_string_value(type);

    if (ngx_strcasecmp((u_char *)type_str, (u_char *)"ip") == 0) {
        value = json_object_get(item, "value");
        if (value == NULL || !json_is_integer(value)) {
            goto error;
        }
        bl_item->type = NGX_HTTP_RWD_BL_ITEM_TYPE_IP;
        ngx_str_null(&bl_item->key);
        bl_item->value.ip = json_integer_value(value);
        key = bl_item->value.ip;
    } else {
        goto error;
    }

    bl_item->node.key = key;

    action = json_object_get(item, "action");
    if (action == NULL || !json_is_string(action)) {
        goto error;
    }
    action_str = json_string_value(action);
    if (ngx_strcasecmp((u_char *)action_str, (u_char *)"deny") == 0) {
        bl_item->action = NGX_HTTP_RWD_ACTION_DENY;
    } else {
        goto error;
    }

    return bl_item;

error:
    ngx_slab_free_locked(ngx_rwd_ctx.shpool, bl_item);
    return NULL;
}

static void
ngx_http_rwd_config_dynamic_bl_add(ngx_http_request_t *r)
{
    size_t i;
    const char *key;
    json_t *json, *item_arr, *item;
    ngx_http_rwd_dm_cfg_t target_dm_cfg, *dm_cfg;
    ngx_http_rwd_bl_item_t *bl_item;

    json = ngx_http_rwd_parse_request_body_into_json(r);
    if (json == NULL) {
        goto error;
    }

    json_object_foreach(json, key, item_arr) {
        if (item_arr == NULL || !json_is_array(item_arr)) {
            goto error;
        }
        /* get domain config, or create new domain config */
        target_dm_cfg.dm.data = (u_char *)key;
        target_dm_cfg.dm.len = ngx_strlen(key);
        target_dm_cfg.node.key = ngx_crc32_short(target_dm_cfg.dm.data,
                                                 target_dm_cfg.dm.len);
        dm_cfg = ngx_http_rwd_dm_cfg_rbtree_get(&target_dm_cfg);
        if (dm_cfg == NULL) {
            goto error;
        }
        json_array_foreach(item_arr, i, item) {
            bl_item = ngx_http_rwd_parse_bl_item(item);
            if (bl_item == NULL) {
                goto error;
            }
            switch (bl_item->type) {
            case NGX_HTTP_RWD_BL_ITEM_TYPE_IP:
                ngx_rbtree_insert(&dm_cfg->ip_bl.rbtree, &bl_item->node);
                break;
            default:
                ngx_slab_free_locked(ngx_rwd_ctx.shpool, bl_item);
                goto error;
            }
        }
    }

    if (json != NULL) {
        json_decref(json);
    }
    return ngx_http_rwd_send_config_response(r, NGX_HTTP_OK, NULL);

error:
    if (json != NULL) {
        json_decref(json);
    }
    return ngx_http_rwd_send_config_response(r, NGX_HTTP_BAD_REQUEST, NULL);
}
