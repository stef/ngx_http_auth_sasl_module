/**
 * Copyright (C) 2022 Stefan Marsiske <opaque@ctrlc.hu>
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

typedef struct {
	ngx_int_t secure;
	ngx_int_t mech;
	ngx_int_t user;
} ngx_http_auth_sasl_var_index_t;

static ngx_http_auth_sasl_var_index_t ngx_http_sasl_var_index;

//static ngx_str_t    shm_name = ngx_string("sasl_contexts");

#define NGX_SASL_SEC_BUF_SIZE (2048)
#define NGX_SASL_HTTP_SERVICE_NAME "HTTP"

static ngx_str_t ngx_http_auth_sasl_secure_var = ngx_string("sasl_secure");
static ngx_str_t ngx_http_auth_sasl_mech_var = ngx_string("sasl_mech");
static ngx_str_t ngx_http_auth_sasl_realm_var = ngx_string("sasl_realm");
static ngx_str_t ngx_http_auth_sasl_user_var = ngx_string("sasl_user");
static ngx_str_t ngx_http_auth_sasl_yes = ngx_string("yes");

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
    u_char                *processed;
    u_char                *p;
    size_t                len;
    static const char     PREFIX[]        = "SASL realm=\"";
    static const char     MECH[]          = "\",mech=\"";
    static const u_char   HEADER_NAME[]   = "WWW-Authenticate";
    static const size_t   HEADER_NAME_LEN = sizeof(HEADER_NAME) - 1;
    static const size_t   PREFIX_LEN      = sizeof(PREFIX) - 1;
    static const size_t   MECH_LEN        = sizeof(MECH) - 1;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if (r->headers_out.www_authenticate == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_out.www_authenticate->hash = 1;
    r->headers_out.www_authenticate->key.len = (size_t) HEADER_NAME_LEN;
    r->headers_out.www_authenticate->key.data = (u_char*) HEADER_NAME;

    /* WWW-Authenticate: SASL s2s="",realm="SASL http auth test",mech="OPAQUE" */

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

static ngx_int_t ngx_http_auth_sasl_set_var(ngx_http_request_t *r,
                                            const ngx_uint_t index,
                                            ngx_str_t *val) {
  ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                "setting variable idx(%d): %s", index, val->data);
  ngx_http_variable_value_t *v;
  // copying behavior from
  // https://github.com/nginx-shib/nginx-http-shibboleth/blob/fffdfb8f7c298dc97f4a1b04fb96f4b87ddd6105/ngx_http_shibboleth_module.c#L468=
  v = &r->variables[index];
  if(NULL == v) {
    return NGX_ERROR;
  }

  v->valid = 1;
  v->not_found = 0;
  v->no_cacheable = 1;
  v->len = val->len;
  v->data = val->data;

  return NGX_OK;
}

static ngx_int_t
ngx_http_auth_sasl_handler(ngx_http_request_t *r) {

    sasl_conn_t                    *conn = NULL;
    ngx_http_auth_sasl_loc_conf_t  *lcf;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "SASL HANDLER");

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_sasl_module);

    if (lcf->realm.len == 0) {
        /* SASL authentication is not enabled at this location. */
        return NGX_OK;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "SASL HANDLER REALM: %s", lcf->realm.data);

    if(r->headers_in.authorization) {
      int                  result;
      int                  result2;
      char                 buf[NGX_SASL_SEC_BUF_SIZE];
      long                 id=0;
      unsigned             clientinlen = 0;
      unsigned             serveroutlen = 0;
      unsigned             len;
      const char           *clientin = NULL;
      const char           *serverout;
      sasl_header_fields_t parsed={0};

      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                    "Authorize Header: %s", r->headers_in.authorization->value.data);

      // parse auth line
      parse_header(&parsed,
                   r->headers_in.authorization->value.data,
                   r->headers_in.authorization->value.len);

      if(parsed.c2s) {
        if (SASL_OK == sasl_decode64(parsed.c2s, parsed.c2s_len,
                                     buf, NGX_SASL_SEC_BUF_SIZE, &clientinlen)) {
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "decoded c2s");
          clientin = buf;
        }
      }

      if(parsed.mech) {
        result = sasl_server_new(NGX_SASL_HTTP_SERVICE_NAME,
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
          do {
            id = ngx_random();
            if(id==0) continue; // never allow 0 id
            (void) sc_map_get_64v(lcf->conns, id);
          } while(sc_map_found(lcf->conns));
          sc_map_put_64v(lcf->conns, id, conn);
          char mech[parsed.mech_len+1];
          ngx_memcpy(mech,parsed.mech,parsed.mech_len);
          mech[parsed.mech_len]=0;
          result = sasl_server_start(conn, mech,
                                     clientin, clientinlen,
                                     &serverout, &serveroutlen);
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                        "starting sasl_server: %d", result);
        }
      } else {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "loading sasl_server");
        conn = sc_map_get_64v(lcf->conns, parsed.s2s);
        if (!sc_map_found(lcf->conns)) {
          if(r->headers_out.www_authenticate) {
            const unsigned int  vallen = strlen("SASL s2c=\"\",s2s=\"\"") + 16;
            unsigned char       val[vallen], *p;

            p = ngx_snprintf(val, vallen, "SASL s2c=\"\",s2s=\"%p\"", parsed.s2s);
            if(vallen != (p - val)) {
              return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if(ngx_memcmp(val, r->headers_out.www_authenticate->value.data, vallen)==0) {
              return NGX_OK;
            }
          }
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                        "sasl context not found, restarting auth dance");
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

      result2 = sasl_encode64(serverout, serveroutlen, buf, NGX_SASL_SEC_BUF_SIZE, &len);
      if (result2 == SASL_OK) {
        unsigned char       *val, *p;
        const unsigned int  vallen          = strlen("SASL s2c=\"\",s2s=\"\"") + len + 16;
        static const u_char HEADER_NAME[]   = "WWW-Authenticate";
        static const size_t HEADER_NAME_LEN = sizeof(HEADER_NAME) - 1;

        // todo? apachemod does:
        //r->err_headers_out,
        //  (PROXYREQ_PROXY == r->proxyreq) ? "Proxy-Authenticate" : "WWW-Authenticate",
        //  apr_psprintf(r->pool, "SASL s2c=\"%s\",s2s=\"%s\"", buf, s2s)

        val = ngx_palloc(r->pool, vallen);
        if (NULL == val) {
          return NGX_ERROR;
        }
        p = ngx_snprintf(val, vallen, "SASL s2c=\"%s\",s2s=\"%p\"", buf, id);
        if(vallen != (p - val)) {
          return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

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
          /* successfully authenticated */
          ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sasl_ok");

          /* set variable: sasl_user */
          ngx_str_t user;
          char *user_p;
          if (sasl_getprop(conn, SASL_USERNAME, (const void**) &user_p) != SASL_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to query SASL_USERNAME");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          }
          user.len = ngx_strlen(user_p);
          user.data = ngx_palloc(r->pool, user.len);
          if (user.data == NULL) {
            return NGX_ERROR;
          }
          ngx_memcpy(user.data, user_p, user.len);
          if(NGX_OK!=ngx_http_auth_sasl_set_var(r,ngx_http_sasl_var_index.user, &user)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to set variable: user");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          };

          /* set variable: sasl_secure */
          if(NGX_OK!=ngx_http_auth_sasl_set_var(r,ngx_http_sasl_var_index.secure,
                                                &ngx_http_auth_sasl_yes)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to set variable: secure");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          };

          /* set variable: sasl_mech */
          ngx_str_t mech;
          char *mech_p;
          if (sasl_getprop(conn, SASL_MECHNAME, (const void**) &mech_p) != SASL_OK) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "failed to query SASL_MECHNAME");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          }
          mech.len = ngx_strlen(mech_p);
          mech.data = ngx_palloc(r->pool, mech.len);
          if (mech.data == NULL) {
            return NGX_ERROR;
          }
          ngx_memcpy(mech.data, mech_p, mech.len);
          if(NGX_OK!=ngx_http_auth_sasl_set_var(r,ngx_http_sasl_var_index.mech, &mech)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "failed to set variable: mech");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
          };

          /* remove cyrus sasl connection for hash table ... */
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

      //if(NGX_OK != rc) {
      //  return NGX_ERROR;
      //}
      ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sasl returning 401");
      return NGX_HTTP_UNAUTHORIZED;
    }

    // no authorize header
    return ngx_http_auth_sasl_unauthorized(r, lcf);
}

/* Variables */
static ngx_int_t ngx_http_auth_sasl_get_realm_var (ngx_http_request_t *r,
                                                   ngx_http_variable_value_t *v,
                                                   uintptr_t data) {
    u_char  *p;
    ngx_http_auth_sasl_loc_conf_t  *lcf;
    lcf = ngx_http_get_module_loc_conf(r, ngx_http_auth_sasl_module);

    p = ngx_pnalloc(r->pool, lcf->sasl_realm.len);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = lcf->sasl_realm.len;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = lcf->sasl_realm.data;

    return NGX_OK;
}

static ngx_int_t ngx_http_auth_sasl_variable(ngx_http_request_t *r,
                                             ngx_http_variable_value_t *v, uintptr_t data) {
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "get http auth sasl variable");
    //v->not_found = 0;
    return NGX_OK;
}


/*
static ngx_int_t
ngx_http_aut_sasl_shm_init(ngx_shm_zone_t *shm_zone, void *data)
{
    ngx_slab_pool_t    *shpool;

    if (data) {
        shm_zone->data = data;
        return NGX_OK;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    nconn = ngx_slab_alloc(shpool, 4);
    if (nconn == NULL) {
        return NGX_ERROR;
    }

    *nconn = 0;

    shm_zone->data = nconn;

    return NGX_OK;
}
*/


/* ========================================================================================
 * Configuration
 * ======================================================================================== */

static ngx_int_t ngx_http_auth_sasl_preconf(ngx_conf_t * cf) {
  ngx_int_t n;
  ngx_http_variable_t  *v;
  ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "sasl_preconf()");

  v = ngx_http_add_variable(cf, &ngx_http_auth_sasl_realm_var, 0);
  if (v == NULL) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to add variable sasl_realm");
    return NGX_ERROR;
  }
  v->get_handler=ngx_http_auth_sasl_get_realm_var;

  v = ngx_http_add_variable(cf, &ngx_http_auth_sasl_secure_var, 0);
  if (v == NULL) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to add variable sasl_secure");
    return NGX_ERROR;
  }
  v->get_handler=ngx_http_auth_sasl_variable;
  n = ngx_http_get_variable_index(cf, &ngx_http_auth_sasl_secure_var);
  if (n == NGX_ERROR) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to get variable index sasl_secure");
    return NGX_ERROR;
  }
  ngx_http_sasl_var_index.secure = n;
  //ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "sasl_secure idx=%d", ngx_http_sasl_var_index.secure);

  v = ngx_http_add_variable(cf, &ngx_http_auth_sasl_mech_var, 0);
  if (v == NULL) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to add variable sasl_mech");
    return NGX_ERROR;
  }
  v->get_handler=ngx_http_auth_sasl_variable;
  n = ngx_http_get_variable_index(cf, &ngx_http_auth_sasl_mech_var);
  if (n == NGX_ERROR) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to get variable index sasl_mech");
    return NGX_ERROR;
  }
  ngx_http_sasl_var_index.mech = n;
  //ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "sasl_mech idx=%d", ngx_http_sasl_var_index.mech);

  v = ngx_http_add_variable(cf, &ngx_http_auth_sasl_user_var, 0);
  if (v == NULL) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to add variable sasl_user");
    return NGX_ERROR;
  }
  v->get_handler=ngx_http_auth_sasl_variable;
  n = ngx_http_get_variable_index(cf, &ngx_http_auth_sasl_user_var);
  if (n == NGX_ERROR) {
    ngx_conf_log_error(NGX_LOG_ERR, cf, 0, "failed to get variable index sasl_user");
    return NGX_ERROR;
  }
  ngx_http_sasl_var_index.user = n;
  //ngx_conf_log_error(NGX_LOG_DEBUG, cf, 0, "sasl_user idx=%d", ngx_http_sasl_var_index.user);

  return NGX_OK;
}

/*
 * Registers our request access phase handler.
 */
static ngx_int_t
ngx_http_auth_sasl_init(ngx_conf_t *cf)
{
    int                        result;
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_auth_sasl_handler;

    // initialize sasl_server
    result = sasl_server_init(NULL, NULL);
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
    sasl_callback_t               *sasl_callbacks;
    ngx_http_auth_sasl_loc_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_auth_sasl_loc_conf_t));
    if (conf == NULL) {
		return NGX_CONF_ERROR;
    }

    conf->conns = ngx_pcalloc(cf->pool, sizeof(struct sc_map_64v));
    sc_map_init_64v(conf->conns, 0, 0);

    sasl_callbacks = ngx_pcalloc(cf->pool, sizeof(callbacks));
    if (sasl_callbacks == NULL) {
		return NGX_CONF_ERROR;
    }
    ngx_memcpy(sasl_callbacks, callbacks, sizeof(callbacks));
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
    ngx_http_auth_sasl_preconf,           /* preconfiguration */
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
