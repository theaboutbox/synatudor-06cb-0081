#ifndef TUDOR_HOST_RESET_OWNERSHIP_H
#define TUDOR_HOST_RESET_OWNERSHIP_H

#include <stdbool.h>
#include <stddef.h>

#include <tudor/state.h>

typedef bool (*tudor_host_state_get_fnc)(
    const char *name, enum tudor_state_value_type *type,
    void **data, size_t *data_size);
typedef void (*tudor_host_state_set_fnc)(
    const char *name, enum tudor_state_value_type type,
    const void *data, size_t data_size);
typedef bool (*tudor_host_reset_fnc)(void);

enum tudor_host_reset_ownership_outcome {
    TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED,
    TUDOR_HOST_RESET_OWNERSHIP_INVALID_REQUEST,
    TUDOR_HOST_RESET_OWNERSHIP_CLEANUP_PENDING,
    TUDOR_HOST_RESET_OWNERSHIP_SUCCEEDED,
    TUDOR_HOST_RESET_OWNERSHIP_FAILED
};

enum tudor_host_reset_ownership_outcome
tudor_host_process_reset_ownership(tudor_host_state_get_fnc get_state,
                                   tudor_host_state_set_fnc set_state,
                                   tudor_host_reset_fnc reset_ownership);

#endif
