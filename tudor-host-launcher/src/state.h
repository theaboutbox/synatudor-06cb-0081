#ifndef TUDOR_HOST_LAUNCHER_STATE_H
#define TUDOR_HOST_LAUNCHER_STATE_H

#include <glib.h>

void init_state(void);
void uninit_state(void);
gboolean state_id_is_valid(const char *id);
gboolean state_write_private_file(const char *path, const void *data,
                                  gsize size, GError **error);
guint state_socket_watch(int fd, const char *state_id);

#endif
