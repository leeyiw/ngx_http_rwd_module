#include <jansson.h>

#include "ngx_http_rwd_config.h"
#include "ngx_http_rwd_module.h"

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

    return NGX_OK;
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
    json_t *json, *item_arr, *item;
    ngx_http_rwd_bl_item_t *bl_item;

    json = ngx_http_rwd_parse_request_body_into_json(r);
    if (json == NULL) {
        goto error;
    }

    item_arr = json_object_get(json, "items");
    if (item_arr == NULL || !json_is_array(item_arr)) {
        goto error;
    }

    json_array_foreach(item_arr, i, item) {
        bl_item = ngx_http_rwd_parse_bl_item(item);
        if (bl_item == NULL) {
            goto error;
        }
        switch (bl_item->type) {
        case NGX_HTTP_RWD_BL_ITEM_TYPE_IP:
            ngx_rbtree_insert(&ngx_rwd_ctx.sh->ip_bl.rbtree,
                              (ngx_rbtree_node_t *)bl_item);
            break;
        default:
            ngx_slab_free_locked(ngx_rwd_ctx.shpool, bl_item);
            goto error;
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
