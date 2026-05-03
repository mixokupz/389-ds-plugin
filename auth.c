#include "slapi-plugin.h"
#include <string.h>

static int my_pre_bind(Slapi_PBlock *pb) {
    char *dn = NULL;
    struct berval *creds = NULL;
    int rc = LDAP_INVALID_CREDENTIALS;

    slapi_pblock_get(pb, SLAPI_BIND_TARGET, &dn);
    slapi_pblock_get(pb, SLAPI_BIND_CREDENTIALS, &creds);

    if (!dn || !creds || !creds->bv_val) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "custom-bind",
                        "Missing DN or credentials\n");
        rc = LDAP_INVALID_CREDENTIALS;
        goto done;
    }

    char *password = creds->bv_val;

    slapi_log_error(SLAPI_LOG_PLUGIN, "custom-bind",
                    "Bind attempt DN: %s\n", dn);

    /*
     *
     * Здесь пример: фиксированный пароль
     * Замени на:
     *  - проверку в БД
     *  - REST API
     *  - файл
     */

    if (strcmp(password, "secret123") == 0) {
        rc = LDAP_SUCCESS;
        slapi_log_error(SLAPI_LOG_PLUGIN, "custom-bind",
                        "Authentication SUCCESS for %s\n", dn);
    } else {
        rc = LDAP_INVALID_CREDENTIALS;
        slapi_log_error(SLAPI_LOG_PLUGIN, "custom-bind",
                        "Authentication FAILED for %s\n", dn);
    }

done:
    /*
    
     * Говорим серверу:
     *  - результат уже определён
     *  - НЕ выполнять стандартную проверку
     */

    slapi_pblock_set(pb, SLAPI_PLUGIN_OPRETURN, &rc);

    /*
     * Иногда полезно явно указать DN как аутентифицированный
     * (особенно если используешь success)
     */
    if (rc == LDAP_SUCCESS && dn) {
        slapi_pblock_set(pb, SLAPI_CONN_DN, dn);
    }

    return rc;
}

int my_plugin_init(Slapi_PBlock *pb) {
    int rc;

    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                          SLAPI_PLUGIN_VERSION_01);
    if (rc != 0) return rc;

    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
        (void *)"Custom Pre-Bind Authentication Plugin");
    if (rc != 0) return rc;

    rc = slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN,
                          (void *)my_pre_bind);

    return rc;
}
