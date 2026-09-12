#ifndef TUDOR_HOST_LAUNCHER_HOST_IDENTITY_H
#define TUDOR_HOST_LAUNCHER_HOST_IDENTITY_H

#include <glib.h>

enum host_identity_relation {
    HOST_IDENTITY_DISTINCT,
    HOST_IDENTITY_EXACT,
    HOST_IDENTITY_SAME_STATE,
    HOST_IDENTITY_SAME_USB
};

enum host_launch_action {
    HOST_LAUNCH_KEEP,
    HOST_LAUNCH_REJECT,
    HOST_LAUNCH_RETIRE,
    HOST_LAUNCH_RETIRE_NOTIFY
};

enum host_identity_relation host_identity_compare(
    guint8 existing_bus, guint8 existing_addr, const gchar *existing_state_id,
    guint8 requested_bus, guint8 requested_addr,
    const gchar *requested_state_id);

enum host_launch_action host_identity_launch_action(
    enum host_identity_relation relation, gboolean alive, gboolean orphan);
gboolean host_identity_can_adopt(enum host_identity_relation relation,
                                 gboolean alive, gboolean orphan);

#endif
