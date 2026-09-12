#ifndef TUDOR_HOST_LAUNCHER_STATE_H
#define TUDOR_HOST_LAUNCHER_STATE_H

#include <glib.h>

void init_state(void);
void uninit_state(void);
guint state_socket_watch(int fd);

#endif
