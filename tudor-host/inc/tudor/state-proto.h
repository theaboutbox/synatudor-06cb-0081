#ifndef TUDOR_HOST_STATE_PROTO_H
#define TUDOR_HOST_STATE_PROTO_H

#include <stdint.h>

#include <tudor/state.h>

#define TUDOR_STATE_SOCKET_FD 3
#define TUDOR_STATE_ID_SIZE 128
#define TUDOR_STATE_PROPERTY_NAME_SIZE 64
#define TUDOR_STATE_MAX_VALUE_SIZE (64 * 1024)
#define TUDOR_STATE_MAX_MESSAGE_SIZE \
    (sizeof(struct tudor_state_store_request) + TUDOR_STATE_MAX_VALUE_SIZE)

enum tudor_state_msg_type {
    TUDOR_STATE_MSG_LOAD = 0x54530001,
    TUDOR_STATE_MSG_LOAD_RESPONSE,
    TUDOR_STATE_MSG_STORE,
    TUDOR_STATE_MSG_STORE_RESPONSE
};

struct tudor_state_load_request {
    uint32_t type;
    char state_id[TUDOR_STATE_ID_SIZE + 1];
    char name[TUDOR_STATE_PROPERTY_NAME_SIZE + 1];
};

struct tudor_state_load_response {
    uint32_t type;
    int32_t status;
    uint32_t found;
    uint32_t value_type;
    uint8_t data[];
};

struct tudor_state_store_request {
    uint32_t type;
    char state_id[TUDOR_STATE_ID_SIZE + 1];
    char name[TUDOR_STATE_PROPERTY_NAME_SIZE + 1];
    uint32_t value_type;
    uint8_t data[];
};

struct tudor_state_store_response {
    uint32_t type;
    int32_t status;
};

#endif
