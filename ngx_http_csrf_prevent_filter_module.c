#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

typedef struct {
    ngx_flag_t         enable;
} ngx_csrf_prevent_conf_t;

static ngx_int_t ngx_http_csrf_prevent_filter_init(ngx_conf_t *cf);
static void* ngx_http_csrf_prevent_filter_create_conf(ngx_conf_t *cf);
static char* ngx_http_csrf_prevent_filter_merge_conf(ngx_conf_t *cf, void* parent, void* child);


static ngx_command_t ngx_http_csrf_prevent_filter_commands[] = {
    {
        ngx_string("csrf_prevent"),
        NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_csrf_prevent_conf_t, enable),
        NULL

    },

    ngx_null_command
};


static ngx_http_module_t  ngx_http_csrf_prevent_filter_module_ctx = {
    NULL,      /* preconfiguration */
    ngx_http_csrf_prevent_filter_init,     /* postconfiguration */

    NULL,     /* create main configuration */
    NULL,       /* init main configuration */

    NULL,      /* create server configuration */
    NULL,       /* merge server configuration */

    ngx_http_csrf_prevent_filter_create_conf,      /* create location configuration */
    ngx_http_csrf_prevent_filter_merge_conf        /* merge location configuration */
};


ngx_module_t  ngx_http_csrf_prevent_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_csrf_prevent_filter_module_ctx,       /* module context */
    ngx_http_csrf_prevent_filter_commands,          /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

// static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;

//from https://www.nginx.com/resources/wiki/start/topics/examples/headers_management/
static ngx_table_elt_t *
search_headers_in(ngx_http_request_t *r, u_char *name, size_t len) {
    ngx_list_part_t            *part;
    ngx_table_elt_t            *h;
    ngx_uint_t                  i;

    /*
       Get the first part of the list. There is usual only one part.
       */
    part = &r->headers_in.headers.part;
    h = part->elts;

    /*
       Headers list array may consist of more than one part,
       so loop through all of it
       */
    for (i = 0; /* void */ ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                /* The last part, search is done. */
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        /*
           Just compare the lengths and then the names case insensitively.
           */
        if (len != h[i].key.len || ngx_strcasecmp(name, h[i].key.data) != 0) {
            /* This header doesn't match. */
            continue;
        }

        /*
           Ta-da, we got one!
           Note, we'v stop the search at the first matched header
           while more then one header may fit.
           */
        return &h[i];
    }

    /*
       No headers was found
       */
    return NULL;
}

ngx_int_t
prefix_cmp(const u_char* s1, const u_char* s2)
{
    while(*s1)
    {
        if (*s1 == *s2)
        {
            ++s1;
            ++s2;
        }
        else
            return 0;
    }
    return 1;
}

static ngx_int_t
ngx_http_csrf_prevent_header_filter(ngx_http_request_t *r)
{
    ngx_csrf_prevent_conf_t  *conf;
    conf = ngx_http_get_module_loc_conf(r, ngx_http_csrf_prevent_filter_module);
    if (!conf->enable)
        return NGX_OK;

    ngx_http_headers_in_t headers = r->headers_in;
    u_char* host = headers.host->value.data;
    //ngx_log_stderr(0, "Host: %s", host);

    u_char* str = NULL;
    if (r->headers_in.referer)
    {
        str = r->headers_in.referer->value.data;
        //ngx_log_stderr(0, "Referer set: %s", str);
    }
    else
    {
        u_char *origin_str = (u_char *) "Origin";
        ngx_table_elt_t* origin = search_headers_in(r, origin_str, ngx_strlen(origin_str));
        if (origin)
        {
            str = origin->value.data;
            //ngx_log_stderr(0, "Origin set: %s", str);
        }
    }

    if (str)
    {
        //+1 for null terminator
        ngx_int_t len = ngx_strlen(str) + 1;
        u_char* new = ngx_alloc(len, r->connection->log);

        int offset = 0;

        if (prefix_cmp((u_char *)"http://", str))
            offset = 7;
        else if (prefix_cmp((u_char *)"https://", str))
            offset = 8;

        ngx_memcpy(new, str + offset, len-offset);

        u_char* pos = (u_char*) ngx_strchr(new, '/');
        if (pos)
            *pos = '\0';

        //ngx_log_stderr(0, "Resulting string: %s", new);

        //return 403 if our new != host
        if (ngx_strcmp(new, host) != 0)
        {
            ngx_free(new);
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "**possible CSRF attempt**");
            return NGX_HTTP_FORBIDDEN;
        }
        ngx_free(new);
    }


    return NGX_OK;
}


static ngx_int_t
ngx_http_csrf_prevent_filter_init(ngx_conf_t *cf)
{
    /*
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_csrf_prevent_header_filter;
    */

    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_csrf_prevent_header_filter;

    return NGX_OK;
}

static void *
ngx_http_csrf_prevent_filter_create_conf(ngx_conf_t *cf)
{
    ngx_csrf_prevent_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_csrf_prevent_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_csrf_prevent_filter_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_csrf_prevent_conf_t *prev = parent;
    ngx_csrf_prevent_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);

    return NGX_CONF_OK;
}


