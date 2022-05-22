/**
 * Copyright (C) 2014 Julie Koubova <juliekoubova@icloud.com>
 *
 * Based on 'ngx_http_auth_basic_module.c' by Igor Sysoev and
 * 'ngx_http_auth_pam_module.c' by Sergio Talens-Oliag.
 *
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <sasl/sasl.h>
#include <sasl/saslplug.h>
#include <sasl/saslutil.h>
#include "sasl_header_parser.h"
#include "sc_map.h"

/*
 * Our per-location configuration.
 */
typedef struct {
  ngx_str_t realm;
  ngx_str_t service_name;
  ngx_str_t sasl_realm;
  ngx_str_t mechs;
  ngx_str_t db_path;
  //ngx_shm_zone_t *shm_zone;
  struct sc_map_64v *conns;
  sasl_callback_t *callbacks;
} ngx_http_auth_sasl_loc_conf_t;

static ngx_str_t    shm_name = ngx_string("sasl_contexts");

#define SAMPLE_SEC_BUF_SIZE (2048)
#define HTTP_SERVICE_NAME "HTTP"

/*
 * The public interface of this module.
 */
ngx_module_t ngx_http_auth_sasl_module;

static int http_auth_sasl_getopt(void *context, const char *plugin_name,
                  const char *option,
                  const char **result, unsigned *len) {
  ngx_http_auth_sasl_loc_conf_t *dconf = (ngx_http_auth_sasl_loc_conf_t *) context;
  if (dconf) {
    if (!strcmp(option, "sasldb_path")) {
      if (dconf->db_path.data) {
        *result = (char*) dconf->db_path.data;
        if (len) {
          *len = (unsigned) dconf->db_path.len;
        }
      }
    } else if (!strcmp(option, "mech_list")) {
      if (dconf->mechs.data) {
        *result = (char*) dconf->mechs.data;
        if (len) {
          *len = (unsigned) dconf->mechs.len;
        }
      }
    }
    return SASL_OK;
  }
  return SASL_FAIL;
}

static const sasl_callback_t callbacks[] = {
  {
    SASL_CB_GETOPT, (sasl_callback_ft) http_auth_sasl_getopt, NULL
  }, {
    SASL_CB_LIST_END, NULL, NULL
  }
};

/* ========================================================================================
 * Access Handler
 * ======================================================================================== */

/*
 * Sends a WWW-Authenticate header with realm name
 * and returns HTTP 401 Authorization Required status.
 */
static ngx_int_t
ngx_http_auth_sasl_unauthorized(ngx_http_request_t *r, const ngx_http_auth_sasl_loc_conf_t  *lcf)
{
    static const u_char   HEADER_NAME[]   = "WWW-Authenticate";
    static const size_t HEADER_NAME_LEN = sizeof(HEADER_NAME) - 1;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = (size_t) HEADER_NAME_LEN;
    r->headers_out.www_authenticate->key.data = (u_char*) HEADER_NAME;

    // WWW-Authenticate: SASL s2s="",realm="SASL http auth test",mech="OPAQUE"
    static const char   PREFIX[]   = "SASL realm=\"";
    static const size_t PREFIX_LEN = sizeof(PREFIX) - 1;

    static const char   MECH[]   = "\",mech=\"";
    static const size_t MECH_LEN = sizeof(MECH) - 1;

    u_char     *processed;
    u_char     *p;
    size_t      len;

    len = PREFIX_LEN + lcf->realm.len + MECH_LEN + lcf->mechs.len + 1;

    processed = ngx_palloc(r->pool, len);
    if (processed == NULL) {
      return NGX_ERROR;
    }

    p = ngx_cpymem(processed, PREFIX, PREFIX_LEN);
    p = ngx_cpymem(p, lcf->realm.data, lcf->realm.len);
    p = ngx_cpymem(p, MECH, MECH_LEN);
    p = ngx_cpymem(p, lcf->mechs.data, lcf->mechs.len);
    *p = '"';

    r->headers_out.www_authenticate->value.data = processed;
    r->headers_out.www_authenticate->value.len = len;

    return NGX_HTTP_UNAUTHORIZED;
}

static void store_conn(ngx_http_auth_sasl_loc_conf_t  *lcf, sasl_conn_t *conn, long *id) {
  do {
    *id = ngx_random();
    if(*id==0) continue; // never allow 0 id
    (void) sc_map_get_64v(lcf->conns, *id);
  } while(sc_map_found(lcf->conns));
  sc_map_put_64v(lcf->conns, *id, conn);
}

static ngx_int_t
ngx_http_auth_sasl_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "SASL HANDLER");

    ngx_http_auth_sasl_loc_conf_t  *lcf;
    //ngx_int_t                       rc;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_sasl_module);

    if (lcf->realm.len == 0) {
        /* SASL authentication is not enabled at this location. */
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "SASL HANDLER REALM: %s", lcf->realm.data);

    sasl_conn_t *conn = NULL;
    if(r->headers_in.authorization) {
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "Authorize Header: %s", r->headers_in.authorization->value.data);

      // parse auth line
      sasl_header_fields_t parsed={0};
      parse_header(&parsed,
                   r->headers_in.authorization->value.data,
                   r->headers_in.authorization->value.len);

      const char *clientin = NULL;
      unsigned clientinlen = 0;
      char buf[SAMPLE_SEC_BUF_SIZE];
      if(parsed.c2s) {
        if (SASL_OK == sasl_decode64(parsed.c2s, (unsigned) strlen(parsed.c2s),
                                     buf, SAMPLE_SEC_BUF_SIZE, &clientinlen)) {
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "decoded c2s");
          clientin = buf;
        }
      }

      const char *serverout;
      unsigned serveroutlen;
      int result;
      long id=0;
      if(parsed.mech) {
        result = sasl_server_new(HTTP_SERVICE_NAME,
                                 NULL,               /* my fully qualified domain name;
                                                        NULL says use gethostname() */
                                 (char*)lcf->realm.data,    /* The user realm used for password
                                                             lookups; NULL means default to serverFQDN
                                                             Note: This does not affect Kerberos */
                                 NULL, NULL,         /* IP Address information strings */
                                 lcf->callbacks,     /* Callbacks supported only for this connection */
                                 SASL_SUCCESS_DATA,  /* security flags (security layers are enabled
                                                        using security properties, separately) */
                                 &conn);
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "new sasl_server: %d", result);
        if(SASL_OK == result) {
          store_conn(lcf, conn, &id);
          result = sasl_server_start(conn, parsed.mech,
                                     clientin, clientinlen,
                                     &serverout, &serveroutlen);
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                        "starting sasl_server: %d", result);
        }
      } else {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "loading sasl_server");
        conn = sc_map_get_64v(lcf->conns, parsed.s2s);
        if (!sc_map_found(lcf->conns)) {
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                        "sasl context not found, restarting auth dance");
          //conn = NULL;

          if(r->headers_out.www_authenticate) {
            const unsigned int vallen = strlen("SASL s2c=\"\",s2s=\"\"") + 16;
            unsigned char val[vallen], *p;
            p = ngx_snprintf(val, vallen, "SASL s2c=\"\",s2s=\"%p\"", parsed.s2s);
            if(vallen != (p - val)) {
              return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if(ngx_memcmp(val, r->headers_out.www_authenticate->value.data, vallen)==0) {
              return NGX_OK;
            }
          }
          return NGX_HTTP_UNAUTHORIZED;
        }
        result = sasl_server_step(conn, clientin, clientinlen, &serverout, &serveroutlen);
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "stepping sasl_server: %d", result);
        id = parsed.s2s;
      }

      if (result != SASL_OK && result != SASL_CONTINUE) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "ERROR starting SASL negotiation: %s",
                      sasl_errstring(result, NULL, NULL));
        return NGX_HTTP_UNAUTHORIZED;
      }

      unsigned int len;
      int result2 = sasl_encode64(serverout, serveroutlen, buf, SAMPLE_SEC_BUF_SIZE, &len);
      if (result2 == SASL_OK) {
        //r->err_headers_out,
        //  (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate" : "WWW-Authenticate",
        //  apr_psprintf(r->pool, "SASL s2c=\"%s\",s2s=\"%s\"", buf, s2s)
        const unsigned int vallen = strlen("SASL s2c=\"\",s2s=\"\"") + len + 16;
        unsigned char *val, *p;
        val = ngx_palloc(r->pool, vallen);
        p = ngx_snprintf(val, vallen, "SASL s2c=\"%s\",s2s=\"%p\"", buf, id);
        if(vallen != (p - val)) {
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        static const u_char   HEADER_NAME[]   = "WWW-Authenticate";
        static const size_t HEADER_NAME_LEN = sizeof(HEADER_NAME) - 1;

        r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
        if (r->headers_out.www_authenticate == NULL) {
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
        r->headers_out.www_authenticate->hash = 1;
        r->headers_out.www_authenticate->key.len = (size_t) HEADER_NAME_LEN;
        r->headers_out.www_authenticate->key.data = (u_char*) HEADER_NAME;
        r->headers_out.www_authenticate->value.data = val;
        r->headers_out.www_authenticate->value.len = vallen;
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sasl header set");

        if (result == SASL_OK) {
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sasl_ok");
          // todo? in the apache mod it sets some env vars for subprocess.
          //const char *user;
          //r->user = "unknown";
          //if (sasl_getprop(conn, SASL_USERNAME, (const void**) &user) == SASL_OK) {
          //  r->user = apr_pstrdup(r->pool, user);
          //}
          //note = apr_psprintf(r->pool, "r->user = %s", r->user);
          //trace_nocontext(r->pool, __FILE__, __LINE__, note);
          //apr_table_setn(r->subprocess_env, "SASL_SECURE", "yes");
          //set_prop_envvar(conn, r->subprocess_env, SASL_MECHNAME, "SASL_MECH");
          //char *realm = dconf->server_realm;
          //if (realm) {
          //  apr_table_setn(r->subprocess_env, "SASL_REALM", realm);
          //} else {
          //  apr_table_unset(r->subprocess_env, "SASL_REALM");
          //}
          ///*
          //  Unusable s2s so don't set SASL_S2S
          //  apr_table_setn(r->subprocess_env, "SASL_S2S", s2s);
          //*/
          //apr_table_unset(r->subprocess_env, "SASL_S2S");
          //apr_table_unset(r->subprocess_env, "SASL_S2S_");
          //rc = OK;

          ///* remove cyrus sasl connection for hash table ... */
          (void) sc_map_del_64v(lcf->conns, id);
          if (!sc_map_found(lcf->conns)) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          }
          ///* ... and dispose it */
          sasl_dispose(&conn);
          return NGX_OK;
        }
      }
      //sc_map_term_64v(&map);

      // cleanup
      clear_parsed(&parsed);

      //if(NGX_OK != rc) {
      //  return NGX_ERROR;
      //}
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sasl returning 401");
      return NGX_HTTP_UNAUTHORIZED;
    }

    // no authorize header
    return ngx_http_auth_sasl_unauthorized(r, lcf);
}

static ngx_int_t
ngx_http_aut_sasl_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t    *shpool;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    //nconn = ngx_slab_alloc(shpool, 4);
    //if (nconn == NULL) {
    //    return NGX_ERROR;
    //}

    //*nconn = 0;

    //shm_zone->data = nconn;

    return NGX_OK;
}


/* ========================================================================================
 * Configuration
 * ======================================================================================== */

/*
 * Registers our request access phase handler.
 */
static ngx_int_t
ngx_http_auth_sasl_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_sasl_handler;

    // initialize sasl_server
    int result = sasl_server_init(NULL, NULL);
    if (result != SASL_OK) {
      return NGX_ERROR;
    }
    ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "sasl_server_init succeeded");

#ifdef DEBUG_SASL
    const char **mechlist = sasl_global_listmech();
    char *mech;
    while ((mech = (char*) *mechlist++) != NULL) {
      ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "mech: %s", mech);
    }
#endif

    // todo
    //lmcf->shm_zone = ngx_shared_memory_add(cf, &shm_name, ngx_pagesize * 2,
    //                                     &ngx_http_auth_sasl_module);
    //if (lmcf->shm_zone == NULL) {
    //    return NGX_ERROR;
    //}

    //lmcf->shm_zone->init = ngx_rtmp_limit_shm_init;

    return NGX_OK;
}

/*
 * Creates an instance of per-location configuration.
 */
static void *
ngx_http_auth_sasl_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_auth_sasl_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_sasl_loc_conf_t));
    if (conf == NULL) {
		return NGX_CONF_ERROR;
    }

    conf->conns = ngx_pcalloc(cf->pool, sizeof(struct sc_map_64v));
    sc_map_init_64v(conf->conns, 0, 0);

    sasl_callback_t *sasl_callbacks = ngx_pcalloc(cf->pool, sizeof(callbacks));
    if (sasl_callbacks == NULL) {
		return NGX_CONF_ERROR;
    }
    memcpy(sasl_callbacks, callbacks, sizeof(callbacks));
    sasl_callbacks[0].context = conf;

    conf->callbacks = sasl_callbacks;

    return conf;
}

/*
 * Overrides inherited configuration.
 */
static char *
ngx_http_auth_sasl_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_auth_sasl_loc_conf_t *prev = parent;
    ngx_http_auth_sasl_loc_conf_t *conf = child;

    if (conf->realm.data == NULL) {
        conf->realm = prev->realm;
    }

    if (conf->sasl_realm.data == NULL) {
        conf->sasl_realm = prev->sasl_realm;
    }

    if (conf->mechs.data == NULL) {
        conf->mechs = prev->mechs;
    }

    if (conf->db_path.data == NULL) {
        conf->db_path = prev->db_path;
    }

    return NGX_CONF_OK;
}

/*
 * If the realm name equals "off", the value is discarded, and
 * SASL authentication is disabled at this location.
 */
static char *
ngx_http_auth_sasl_post_handler(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *realm = data;

    if (ngx_strcmp(realm->data, "off") == 0) {
        realm->len = 0;
        realm->data = (u_char *) "";
    }

    return NGX_CONF_OK;
}

static ngx_conf_post_t ngx_http_auth_sasl_post = {
    ngx_http_auth_sasl_post_handler          /* post_handler */
};

static ngx_command_t ngx_http_auth_sasl_commands[] = {

    /* auth_sasl off | <realm name>; */
    {
        ngx_string("auth_sasl"),                        /* name */
        NGX_HTTP_MAIN_CONF |                            /* allow in main config */
        NGX_HTTP_SRV_CONF  |                            /* allow in server block */
        NGX_HTTP_LOC_CONF  |                            /* allow in location block */
        NGX_HTTP_LMT_CONF  |                            /* allow in limit_except block */
        NGX_CONF_TAKE1,                                 /* take one argument */
        ngx_conf_set_str_slot,                          /* set string value */
        NGX_HTTP_LOC_CONF_OFFSET,                       /* configuration to set */
        offsetof(ngx_http_auth_sasl_loc_conf_t, realm), /* field to set */
        &ngx_http_auth_sasl_post                        /* config post processing */
    },
	{
		ngx_string("sasl_realm"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_sasl_loc_conf_t, sasl_realm),
		NULL
	},
	{
		ngx_string("sasl_mechanisms"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_sasl_loc_conf_t, mechs),
		NULL
	},
	{
		ngx_string("sasl_db_path"),
		NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LMT_CONF|NGX_CONF_TAKE1,
		ngx_conf_set_str_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_auth_sasl_loc_conf_t, db_path),
		NULL
	},
	ngx_null_command
};


/* ========================================================================================
 * Module Interface
 * ======================================================================================== */

static ngx_http_module_t ngx_http_auth_sasl_module_ctx = {
    NULL,                                 /* preconfiguration */
    ngx_http_auth_sasl_init,              /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_auth_sasl_create_loc_conf,   /* create location configuration */
    ngx_http_auth_sasl_merge_loc_conf     /* merge location configuration */
};

ngx_module_t ngx_http_auth_sasl_module = {
    NGX_MODULE_V1,
    &ngx_http_auth_sasl_module_ctx,       /* module context */
    ngx_http_auth_sasl_commands,          /* module directives */
    NGX_HTTP_MODULE,                      /* module type */
    NULL,                                 /* init master */
    NULL,                                 /* init module */
    NULL,                                 /* init process */
    NULL,                                 /* init thread */
    NULL,                                 /* exit thread */
    NULL,                                 /* exit process */
    NULL,                                 /* exit master */
    NGX_MODULE_V1_PADDING
};
