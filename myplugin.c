#include "slapi-plugin.h"

static int my_pre_bind(Slapi_PBlock *pb) {
    char *dn = NULL;

    slapi_pblock_get(pb, SLAPI_BIND_TARGET, &dn);

    if (dn) {
        slapi_log_err(SLAPI_LOG_PLUGIN, "force-bind",
                      "Forcing SUCCESS for DN: %s\n", dn);
    }

    /*
     * Сообщаем серверу:
     * операция уже обработана
     */
    slapi_pblock_set(pb, SLAPI_PLUGIN_OPRETURN, LDAP_SUCCESS);

    /*
     * Говорим не выполнять стандартную обработку bind
     */
    return SLAPI_PLUGIN_NOOP;
}

static int my_plugin_init(Slapi_PBlock *pb) {
    slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                     SLAPI_PLUGIN_VERSION_01);

    slapi_pblock_set(pb, SLAPI_PLUGIN_DESCRIPTION,
                     "Force Bind Success Plugin");

    slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN,
                     (void *)my_pre_bind);

    return 0;
}
