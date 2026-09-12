#ifndef CRYPTBRIDGE_IDENTITY_H
#define CRYPTBRIDGE_IDENTITY_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum cryptbridge_identity_load_result {
    CRYPTBRIDGE_IDENTITY_LOAD_ERROR = -1,
    CRYPTBRIDGE_IDENTITY_LOAD_NOT_FOUND = 0,
    CRYPTBRIDGE_IDENTITY_LOAD_FOUND = 1
};

enum cryptbridge_identity_key_role {
    CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED = 0,
    CRYPTBRIDGE_IDENTITY_KEY_PAIRING = 1
};

/* A successful load transfers a malloc-compatible buffer to cryptbridge. */
typedef enum cryptbridge_identity_load_result
(*cryptbridge_identity_load_callback)(void *context, void **data,
                                      size_t *data_size);
typedef bool (*cryptbridge_identity_store_callback)(void *context,
                                                    const void *data,
                                                    size_t data_size);

/* Passing NULL callbacks restores process-local key generation. */
void cryptbridge_identity_set_state_callbacks(
    cryptbridge_identity_load_callback load_callback,
    cryptbridge_identity_store_callback store_callback,
    void *context);

/* A role scope is thread-local and authorizes at most one generated key.
 * End leaves the role unscoped if that authorization was consumed, including
 * in a nested scope, so restoring a previous PAIRING value cannot re-arm it.
 * Unscoped generation always remains ephemeral. */
enum cryptbridge_identity_key_role cryptbridge_identity_begin_key_role(
    enum cryptbridge_identity_key_role role);
void cryptbridge_identity_end_key_role(
    enum cryptbridge_identity_key_role previous_role);

#ifdef __cplusplus
}
#endif

#endif
