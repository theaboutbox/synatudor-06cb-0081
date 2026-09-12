#include "host-identity.h"

enum host_identity_relation host_identity_compare(
    guint8 existing_bus, guint8 existing_addr, const gchar *existing_state_id,
    guint8 requested_bus, guint8 requested_addr,
    const gchar *requested_state_id) {
    gboolean same_usb = existing_bus == requested_bus &&
                        existing_addr == requested_addr;
    gboolean same_state = g_strcmp0(existing_state_id, requested_state_id) == 0;

    if(same_usb && same_state) return HOST_IDENTITY_EXACT;
    if(same_state) return HOST_IDENTITY_SAME_STATE;
    if(same_usb) return HOST_IDENTITY_SAME_USB;
    return HOST_IDENTITY_DISTINCT;
}

enum host_launch_action host_identity_launch_action(
    enum host_identity_relation relation, gboolean alive, gboolean orphan) {
    if(relation == HOST_IDENTITY_DISTINCT) return HOST_LAUNCH_KEEP;
    if(relation == HOST_IDENTITY_EXACT && alive && !orphan)
        return HOST_LAUNCH_REJECT;
    if(alive && !orphan) return HOST_LAUNCH_RETIRE_NOTIFY;
    return HOST_LAUNCH_RETIRE;
}

gboolean host_identity_can_adopt(enum host_identity_relation relation,
                                 gboolean alive, gboolean orphan) {
    return relation == HOST_IDENTITY_EXACT && alive && orphan;
}
