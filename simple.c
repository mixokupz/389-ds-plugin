#include "slapi-plugin.h"

int my_pre_bind(Slapi_PBlock *pb) {
    char *dn = NULL;

    slapi_pblock_get(pb, SLAPI_BIND_TARGET, &dn);

    if (dn) {
        slapi_log_error(SLAPI_LOG_PLUGIN, "force-bind",
                        "Bind attempt DN: %s\n", dn);
    }

    return LDAP_SUCCESS;
}

int my_plugin_init(Slapi_PBlock *pb) {
    slapi_pblock_set(pb, SLAPI_PLUGIN_VERSION,
                     SLAPI_PLUGIN_VERSION_01);

    slapi_pblock_set(pb, SLAPI_PLUGIN_PRE_BIND_FN,
                     (void *)my_pre_bind);

    return 0;
}
