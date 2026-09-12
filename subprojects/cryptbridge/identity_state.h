#ifndef CRYPTBRIDGE_IDENTITY_STATE_H
#define CRYPTBRIDGE_IDENTITY_STATE_H

#include <stdbool.h>
#include <stddef.h>

enum cryptbridge_identity_result {
    CRYPTBRIDGE_IDENTITY_ERROR = -1,
    CRYPTBRIDGE_IDENTITY_NOT_FOUND = 0,
    CRYPTBRIDGE_IDENTITY_FOUND = 1,
    CRYPTBRIDGE_IDENTITY_INACTIVE = 2
};

enum cryptbridge_identity_result
cryptbridge_identity_state_load(void **data, size_t *data_size);
enum cryptbridge_identity_result
cryptbridge_identity_state_resolve(
    const void *candidate, size_t candidate_size,
    void **data, size_t *data_size);
bool cryptbridge_identity_state_take_pairing_role(void);

#endif
