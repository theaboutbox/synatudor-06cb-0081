#ifndef CRYPTBRIDGE_REGISTRY_H
#define CRYPTBRIDGE_REGISTRY_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum cryptbridge_registry_load_result {
    CRYPTBRIDGE_REGISTRY_LOAD_ERROR = -1,
    CRYPTBRIDGE_REGISTRY_LOAD_NOT_FOUND = 0,
    CRYPTBRIDGE_REGISTRY_LOAD_FOUND = 1
};

/* A successful load transfers a malloc-compatible buffer to cryptbridge. */
typedef enum cryptbridge_registry_load_result
(*cryptbridge_registry_load_callback)(void *context, void **data,
                                      size_t *data_size);
typedef bool (*cryptbridge_registry_store_callback)(void *context,
                                                    const void *data,
                                                    size_t data_size);

/* Passing NULL callbacks restores the standalone filesystem backend. */
void cryptbridge_registry_set_state_callbacks(
    cryptbridge_registry_load_callback load_callback,
    cryptbridge_registry_store_callback store_callback,
    void *context);

#ifdef __cplusplus
}
#endif

#endif
