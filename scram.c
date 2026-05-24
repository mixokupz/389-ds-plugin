```c
/*
 * 389-ds PRE_BIND plugin implementing
 * custom SCRAM-SHA-256 SASL authentication
 * using GNU SASL (GSASL).
 *
 * NOTE:
 * This is a minimal working architecture.
 * Multi-step SCRAM continuation storage
 * is intentionally simplified.
 */

#include <slapi-plugin.h>
#include <ldap.h>

#include <gsasl.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>


/* ============================================================
 * TEST USER DATABASE
 * ============================================================
 */

typedef struct {
    const char* user;
    const char* salt;
    const char* stored_key;
    const char* server_key;
    int iters;
} users_rec;


static users_rec users[] = {
    {
        "ivan",
        "7seVPKYFtfYD12LKLt7tFA==",
        "6IH8az74JUcX6rKN320v/t5KnQ/Zx/rDk53iO5cvZF0=",
        "BE8t22q3xkMKv+jCIGNNXi/LNXnmnoi/SjnIDBoUCMU=",
        4096
    },

    {NULL, NULL, NULL, NULL, 0}
};


/* ============================================================
 * GSASL CALLBACK
 * ============================================================
 */

static int
server_callback(Gsasl* ctx,
                Gsasl_session* sess,
                Gsasl_property prop)
{
    const char* authid;
    char buf[32];

    authid = gsasl_property_fast(sess,
                                 GSASL_AUTHID);

    if (!authid)
        return GSASL_NO_CALLBACK;

    for (int i = 0; users[i].user != NULL; i++) {

        if (strcmp(authid,
                   users[i].user) == 0) {

            switch (prop) {

                case GSASL_SCRAM_ITER:

                    snprintf(buf,
                             sizeof(buf),
                             "%d",
                             users[i].iters);

                    gsasl_property_set(sess,
                                       GSASL_SCRAM_ITER,
                                       buf);

                    return GSASL_OK;


                case GSASL_SCRAM_SALT:

                    gsasl_property_set(sess,
                                       GSASL_SCRAM_SALT,
                                       users[i].salt);

                    return GSASL_OK;


                case GSASL_SCRAM_STOREDKEY:

                    gsasl_property_set(sess,
                                       GSASL_SCRAM_STOREDKEY,
                                       users[i].stored_key);

                    return GSASL_OK;


                case GSASL_SCRAM_SERVERKEY:

                    gsasl_property_set(sess,
                                       GSASL_SCRAM_SERVERKEY,
                                       users[i].server_key);

                    return GSASL_OK;


                default:
                    return GSASL_NO_CALLBACK;
            }
        }
    }

    return GSASL_NO_CALLBACK;
}


/* ============================================================
 * SCRAM STATE
 * ============================================================
 */

typedef struct {

    Gsasl *ctx;

    Gsasl_session *session;

} scram_state;


/*
 * WARNING:
 *
 * This example uses global state for simplicity.
 *
 * Real implementation should store:
 *
 * Connection* -> scram_state
 *
 * because SCRAM is multi-step.
 */

static scram_state *global_state = NULL;


/* ============================================================
 * CREATE GSASL SESSION
 * ============================================================
 */

static scram_state *
scram_state_new(void)
{
    scram_state *st;

    st = slapi_ch_malloc(sizeof(*st));

    memset(st,
           0,
           sizeof(*st));

    if (gsasl_init(&st->ctx) != GSASL_OK)
        goto fail;

    gsasl_callback_set(st->ctx,
                       server_callback);

    if (gsasl_server_start(st->ctx,
                           "SCRAM-SHA-256",
                           &st->session) != GSASL_OK)
        goto fail;

    return st;

fail:

    if (st->session)
        gsasl_finish(st->session);

    if (st->ctx)
        gsasl_done(st->ctx);

    slapi_ch_free((void **)&st);

    return NULL;
}


/* ============================================================
 * FREE GSASL SESSION
 * ============================================================
 */

static void
scram_state_free(scram_state *st)
{
    if (!st)
        return;

    if (st->session)
        gsasl_finish(st->session);

    if (st->ctx)
        gsasl_done(st->ctx);

    slapi_ch_free((void **)&st);
}


/* ============================================================
 * PRE_BIND HANDLER
 * ============================================================
 */

static int
scram_pre_bind(Slapi_PBlock *pb)
{
    int method = 0;

    char *mech = NULL;

    struct berval *cred = NULL;

    Connection *conn = NULL;

    char *out = NULL;

    int rc;


    /* --------------------------------------------
     * GET BIND METHOD
     * --------------------------------------------
     */

    slapi_pblock_get(pb,
                     SLAPI_BIND_METHOD,
                     &method);


    /*
     * Ignore non-SASL bind
     */

    if (method != LDAP_AUTH_SASL)
        return 0;


    /* --------------------------------------------
     * GET SASL MECHANISM
     * --------------------------------------------
     */

    slapi_pblock_get(pb,
                     SLAPI_BIND_SASLMECHANISM,
                     &mech);


    if (!mech)
        return 0;


    /*
     * Handle only our mechanism
     */

    if (strcmp(mech,
               "NEW-SCRAM-SHA-256") != 0)
        return 0;


    /* --------------------------------------------
     * GET SASL PAYLOAD
     * --------------------------------------------
     */

    slapi_pblock_get(pb,
                     SLAPI_BIND_CREDENTIALS,
                     &cred);


    if (!cred)
        goto auth_fail;


    /* --------------------------------------------
     * GET CONNECTION
     * --------------------------------------------
     */

    slapi_pblock_get(pb,
                     SLAPI_CONNECTION,
                     &conn);


    if (!conn)
        goto auth_fail;


    /* --------------------------------------------
     * CREATE OR RESTORE SCRAM STATE
     * --------------------------------------------
     */

    /*
     * Real implementation:
     * lookup state by connection.
     */

    if (!global_state) {

        global_state = scram_state_new();

        if (!global_state)
            goto auth_fail;
    }


    /* --------------------------------------------
     * PROCESS SCRAM STEP
     * --------------------------------------------
     */

    rc = gsasl_step64(global_state->session,
                      cred->bv_val,
                      &out);


    /* --------------------------------------------
     * NEEDS MORE DATA
     * --------------------------------------------
     */

    if (rc == GSASL_NEEDS_MORE) {

        struct berval resp;

        resp.bv_val = out;
        resp.bv_len = strlen(out);


        slapi_log_error(SLAPI_LOG_PLUGIN,
                        "scram-plugin",
                        "SCRAM continuation\n");


        send_ldap_result(pb,
                         LDAP_SASL_BIND_IN_PROGRESS,
                         NULL,
                         NULL,
                         0,
                         &resp);

        gsasl_free(out);

        return 1;
    }


    /* --------------------------------------------
     * AUTH SUCCESS
     * --------------------------------------------
     */

    if (rc == GSASL_OK) {

        const char *authid;


        authid = gsasl_property_fast(
            global_state->session,
            GSASL_AUTHID
        );


        if (!authid)
            goto auth_fail;


        slapi_log_error(
            SLAPI_LOG_PLUGIN,
            "scram-plugin",
            "SCRAM success authid=%s\n",
            authid
        );


        /*
         * Mark connection authenticated
         */

        bind_credentials_set_nolock(
            conn,
            SLAPD_AUTH_SASL,
            slapi_ch_strdup(authid),
            NULL,
            NULL,
            NULL,
            NULL
        );


        /*
         * Update operation context
         */

        slapi_pblock_set(
            pb,
            SLAPI_CONN_DN,
            (void *)authid
        );


        /*
         * Send LDAP success
         */

        send_ldap_result(
            pb,
            LDAP_SUCCESS,
            NULL,
            NULL,
            0,
            NULL
        );


        /*
         * Destroy state
         */

        scram_state_free(global_state);

        global_state = NULL;

        gsasl_free(out);

        return 1;
    }


/* ============================================================
 * AUTH FAILURE
 * ============================================================
 */

auth_fail:

    slapi_log_error(
        SLAPI_LOG_PLUGIN,
        "scram-plugin",
        "SCRAM auth failed\n"
    );


    send_ldap_result(
        pb,
        LDAP_INVALID_CREDENTIALS,
        NULL,
        NULL,
        0,
        NULL
    );


    if (out)
        gsasl_free(out);


    if (global_state) {

        scram_state_free(global_state);

        global_state = NULL;
    }

    return 1;
}


/* ============================================================
 * PLUGIN INIT
 * ============================================================
 */

int
scram_plugin_init(Slapi_PBlock *pb)
{
    slapi_log_error(
        SLAPI_LOG_PLUGIN,
        "scram-plugin",
        "Initializing SCRAM plugin\n"
    );


    slapi_pblock_set(
        pb,
        SLAPI_PLUGIN_VERSION,
        SLAPI_PLUGIN_VERSION_01
    );


    slapi_pblock_set(
        pb,
        SLAPI_PLUGIN_DESCRIPTION,
        (void *)"SCRAM-SHA-256 plugin"
    );


    slapi_pblock_set(
        pb,
        SLAPI_PLUGIN_PRE_BIND_FN,
        (void *)scram_pre_bind
    );


    return 0;
}
```
