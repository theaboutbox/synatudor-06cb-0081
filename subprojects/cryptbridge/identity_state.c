#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cryptbridge/identity.h>

#include "identity_state.h"

#define IDENTITY_MAX_SIZE 4096u

enum identity_load_status {
    IDENTITY_UNLOADED,
    IDENTITY_LOADED,
    IDENTITY_LOAD_FAILED
};

static pthread_mutex_t identity_mutex = PTHREAD_MUTEX_INITIALIZER;
static cryptbridge_identity_load_callback identity_load_callback;
static cryptbridge_identity_store_callback identity_store_callback;
static void *identity_callback_context;
static enum identity_load_status identity_status = IDENTITY_UNLOADED;
static void *identity_data;
static size_t identity_data_size;

static void wipe_bytes(void *data, size_t size)
{
    volatile unsigned char *bytes = data;
    while(size--) *bytes++ = 0;
}

static void clear_identity(void)
{
    if(identity_data) wipe_bytes(identity_data, identity_data_size);
    free(identity_data);
    identity_data = NULL;
    identity_data_size = 0;
}

void cryptbridge_identity_set_state_callbacks(
    cryptbridge_identity_load_callback load_callback,
    cryptbridge_identity_store_callback store_callback,
    void *context)
{
    pthread_mutex_lock(&identity_mutex);
    clear_identity();
    identity_load_callback = load_callback;
    identity_store_callback = store_callback;
    identity_callback_context = context;
    identity_status = IDENTITY_UNLOADED;
    pthread_mutex_unlock(&identity_mutex);
}

static bool ensure_identity_loaded(void)
{
    if(identity_status == IDENTITY_LOADED) return true;
    if(identity_status == IDENTITY_LOAD_FAILED || !identity_load_callback ||
       !identity_store_callback)
        return false;

    void *data = NULL;
    size_t data_size = 0;
    enum cryptbridge_identity_load_result result =
        identity_load_callback(identity_callback_context, &data, &data_size);
    if(result == CRYPTBRIDGE_IDENTITY_LOAD_NOT_FOUND) {
        if(data || data_size) {
            if(data && data_size <= IDENTITY_MAX_SIZE)
                wipe_bytes(data, data_size);
            free(data);
            identity_status = IDENTITY_LOAD_FAILED;
            return false;
        }
        identity_status = IDENTITY_LOADED;
        return true;
    }
    if(result != CRYPTBRIDGE_IDENTITY_LOAD_FOUND || !data || !data_size ||
       data_size > IDENTITY_MAX_SIZE) {
        if(data && data_size <= IDENTITY_MAX_SIZE)
            wipe_bytes(data, data_size);
        free(data);
        identity_status = IDENTITY_LOAD_FAILED;
        return false;
    }

    identity_data = data;
    identity_data_size = data_size;
    identity_status = IDENTITY_LOADED;
    return true;
}

static enum cryptbridge_identity_result copy_identity(
    void **data, size_t *data_size)
{
    void *copy = malloc(identity_data_size);
    if(!copy) return CRYPTBRIDGE_IDENTITY_ERROR;
    memcpy(copy, identity_data, identity_data_size);
    *data = copy;
    *data_size = identity_data_size;
    return CRYPTBRIDGE_IDENTITY_FOUND;
}

enum cryptbridge_identity_result
cryptbridge_identity_state_load(void **data, size_t *data_size)
{
    if(!data || !data_size) return CRYPTBRIDGE_IDENTITY_ERROR;
    *data = NULL;
    *data_size = 0;

    pthread_mutex_lock(&identity_mutex);
    if(!identity_load_callback && !identity_store_callback) {
        pthread_mutex_unlock(&identity_mutex);
        return CRYPTBRIDGE_IDENTITY_INACTIVE;
    }
    if(!ensure_identity_loaded()) {
        pthread_mutex_unlock(&identity_mutex);
        return CRYPTBRIDGE_IDENTITY_ERROR;
    }
    enum cryptbridge_identity_result result = identity_data
        ? copy_identity(data, data_size)
        : CRYPTBRIDGE_IDENTITY_NOT_FOUND;
    pthread_mutex_unlock(&identity_mutex);
    return result;
}

enum cryptbridge_identity_result
cryptbridge_identity_state_resolve(
    const void *candidate, size_t candidate_size,
    void **data, size_t *data_size)
{
    if(!candidate || !candidate_size || candidate_size > IDENTITY_MAX_SIZE ||
       !data || !data_size)
        return CRYPTBRIDGE_IDENTITY_ERROR;
    *data = NULL;
    *data_size = 0;

    pthread_mutex_lock(&identity_mutex);
    if(!identity_load_callback && !identity_store_callback) {
        pthread_mutex_unlock(&identity_mutex);
        return CRYPTBRIDGE_IDENTITY_INACTIVE;
    }
    if(!ensure_identity_loaded()) {
        pthread_mutex_unlock(&identity_mutex);
        return CRYPTBRIDGE_IDENTITY_ERROR;
    }
    if(identity_data) {
        enum cryptbridge_identity_result result =
            copy_identity(data, data_size);
        pthread_mutex_unlock(&identity_mutex);
        return result;
    }

    void *cached = malloc(candidate_size);
    void *resolved = malloc(candidate_size);
    if(!cached || !resolved) {
        free(cached);
        free(resolved);
        pthread_mutex_unlock(&identity_mutex);
        return CRYPTBRIDGE_IDENTITY_ERROR;
    }
    memcpy(cached, candidate, candidate_size);
    memcpy(resolved, candidate, candidate_size);
    if(!identity_store_callback(identity_callback_context, candidate,
                                candidate_size)) {
        wipe_bytes(cached, candidate_size);
        wipe_bytes(resolved, candidate_size);
        free(cached);
        free(resolved);
        pthread_mutex_unlock(&identity_mutex);
        return CRYPTBRIDGE_IDENTITY_ERROR;
    }

    identity_data = cached;
    identity_data_size = candidate_size;
    *data = resolved;
    *data_size = candidate_size;
    pthread_mutex_unlock(&identity_mutex);
    return CRYPTBRIDGE_IDENTITY_FOUND;
}
