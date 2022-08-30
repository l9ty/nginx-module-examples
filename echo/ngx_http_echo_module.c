#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

static ngx_int_t ngx_http_echo_handler(ngx_http_request_t *r);
static char *ngx_http_echo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_echo_get_raw_headers(ngx_http_request_t *r, ngx_chain_t *out);
static void ngx_http_echo_post_read_body(ngx_http_request_t *r);


static ngx_command_t ngx_http_echo_commands[] = {
    { ngx_string("echo"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_http_echo,
      0,
      0,
      NULL },
    ngx_null_command
};


static ngx_http_module_t ngx_http_echo_module_ctx = {
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL
};


ngx_module_t ngx_http_echo_module = {
    NGX_MODULE_V1,
    &ngx_http_echo_module_ctx,
    ngx_http_echo_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};


typedef struct {
    ngx_chain_t *body;
    unsigned readbody:1;
    unsigned readheader:1;
} ngx_http_echo_ctx_t;


static ngx_int_t
ngx_http_echo_get_raw_headers(ngx_http_request_t *r, ngx_chain_t *out)
{
    ngx_chain_t             *cl;
    size_t                  size;
    ngx_buf_t               *b, *start, **bps;
    u_char                  *data, *last, *p;
    ngx_int_t               i, nbp;
    ngx_connection_t        *c  = r->connection;
    ngx_http_connection_t   *hc = r->http_connection;


    size = 0;
    start = NULL;
    b = c->buffer;

    if (r->request_line.data >= b->start &&
        r->request_line.data + r->request_line.len <= b->last)
    {
        start = b;
        size += b->pos - r->request_line.data;
    }

    i = nbp = 0;
    bps = NULL;
    if (hc->nbusy) {
        bps = ngx_palloc(r->pool, sizeof(ngx_buf_t *) * hc->nbusy);
        if (bps == NULL) {
            return NGX_ERROR;
        }

        for (cl = hc->busy; cl != NULL; cl = cl->next ) {
            b = cl->buf;

            if (start == NULL && r->request_line.data >= b->start &&
                r->request_line.data + r->request_line.len <= b->pos )
            {
                start = b;
                size += b->pos - r->request_line.data;
                bps[i++] = b;
                break;
            }

            if (i > 0 || r->header_in == b ) {
                size += b->pos - b->start;
                bps[i++] = b;
            }
        }
        nbp = i;
    }

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
    out->buf = b;
    out->next = NULL;

    data = ngx_palloc(r->pool, size + 1);
    if (data == NULL) {
        return NGX_ERROR;
    }
    last = data;
    b->pos = data;
    b->memory = 1;

    if (!start) {
        return NGX_ERROR;
    }

    if (r->header_in == c->buffer) {
        /* The whole raw_header is in c->buffer */
        last = ngx_copy(last, r->request_line.data, size);
        while (last > r->request_line.data && last[-1] != LF) {
            last--;
        }

    } else if (nbp) {
        i = nbp - 1;

        if (start != c->buffer) {
            last = ngx_copy(last, r->request_line.data,
                         bps[i]->last - r->request_line.data);
            i--;
            while (last > r->request_line.data && last[-1] != LF) {
                last--;
            }

        }

        for ( ; i >= 0; i--) {
            b = bps[i];
            last = ngx_copy(last, b->start, b->pos - b->start);
            while (last > b->start && last[-1] != LF) {
                last--;
            }
        }
    }

    /* fixup zero byte */
    for (i = 0, p = data; p < last - 1; p++) {
        if (*p != '\0') {
            continue;
        }

        if (*(p+1) == ' ') {
            *p = ':';
        } else if (*(p+1) == LF) {
            *p = CR;
        } else {
            *p = LF;
        }
    }

    *last = '\0';
    if ((p = (u_char *)ngx_strstr(data, CRLF CRLF)) != NULL) {
        last = p + sizeof(CRLF CRLF) - 1;
    } else if ((p = (u_char *)ngx_strstr(data, CRLF "\n")) != NULL) {
        last = p + sizeof(CRLF "\n") - 1;
    } else if ((p = (u_char *)ngx_strstr(data, "\n" CRLF)) != NULL) {
        last = p + sizeof("\n" CRLF) - 1;
    }

    out->buf->last = last;
    return NGX_OK;
}


static void
ngx_http_echo_post_read_body(ngx_http_request_t *r)
{
    ngx_http_echo_ctx_t *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_echo_module);
    ctx->readbody = 0;
}


static ngx_int_t
ngx_http_echo_handler(ngx_http_request_t *r)
{
    ngx_int_t           rc;
    ngx_chain_t         *out, *cl;
    ngx_http_echo_ctx_t *ctx;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "http echo handler");

    ctx = ngx_http_get_module_ctx(r, ngx_http_echo_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_echo_ctx_t));
        if (ctx == NULL) {
            return NGX_ERROR;
        }
        ctx->readbody = 1;
        ngx_http_set_ctx(r, ctx, ngx_http_echo_module);
    }

    if (ctx->readbody) {
        rc = ngx_http_read_client_request_body(r, ngx_http_echo_post_read_body);
        if (rc != NGX_OK) {
            return rc;
        }
    }

    out = ngx_alloc_chain_link(r->pool);
    if (out == NULL) {
        return NGX_ERROR;
    }

    rc = ngx_http_echo_get_raw_headers(r, out);
    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    if (r->request_body && r->request_body->bufs) {

        for (cl = out; cl->next != NULL; cl = cl->next);
        cl->next = r->request_body->bufs;
    }

    for (cl = out; cl->next != NULL; cl = cl->next) {
        if (ngx_buf_in_memory(cl->buf)) {
            cl->buf->memory = 1;
        }
    }

    cl->buf->last_buf = (r == r->main) ? 1 : 0;
    cl->buf->last_in_chain = 1;

    r->headers_out.status = NGX_HTTP_OK;

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only ) {
        return rc;
    }
    return ngx_http_output_filter(r, out);
}

static char*
ngx_http_echo(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_echo_handler;

    return NGX_CONF_OK;
}
