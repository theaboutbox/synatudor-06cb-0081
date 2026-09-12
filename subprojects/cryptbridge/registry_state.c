#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cryptbridge/registry.h>

#include "registry_state.h"

#define REGISTRY_BLOB_MAX_SIZE (64u * 1024u)
#define REGISTRY_BLOB_HEADER_SIZE 12u
#define REGISTRY_BLOB_RECORD_SIZE 17u

static const unsigned char registry_blob_magic[8] = {
    'C', 'B', 'R', 'G', 'R', 'E', 'G', '1'
};

struct state_key {
    char *path;
    struct state_key *next;
};

struct state_value {
    char *path;
    char *name;
    DWORD type;
    BYTE *data;
    DWORD data_size;
    struct state_value *next;
};

struct state_store {
    struct state_key *keys;
    struct state_value *values;
};

enum state_load_status {
    STATE_UNLOADED,
    STATE_LOADED,
    STATE_LOAD_FAILED
};

static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static cryptbridge_registry_load_callback state_load_callback;
static cryptbridge_registry_store_callback state_store_callback;
static void *state_callback_context;
static enum state_load_status state_status = STATE_UNLOADED;
static struct state_store registry_state;

static const char *const allowed_key_paths[] = {
    "HKCU/Software",
    "HKCU/Software/Wine",
    "HKCU/Software/Wine/Crypto",
    "HKCU/Software/Wine/Crypto/RSA",
    "HKCU/Software/Wine/Crypto/RSA/VFS key container",
    "HKLM/Software",
    "HKLM/Software/Wine",
    "HKLM/Software/Wine/Crypto",
    "HKLM/Software/Wine/Crypto/RSA",
    "HKLM/Software/Wine/Crypto/RSA/VFS key container",
    NULL
};

static const char *const container_paths[] = {
    "HKCU/Software/Wine/Crypto/RSA/VFS key container",
    "HKLM/Software/Wine/Crypto/RSA/VFS key container",
    NULL
};

struct allowed_value {
    const char *name;
    DWORD type;
};

static const struct allowed_value allowed_values[] = {
    {"KeyExchangeKeyPair", REG_BINARY},
    {"SignatureKeyPair", REG_BINARY},
    {"KeyExchangePermissions", REG_DWORD},
    {"SignaturePermissions", REG_DWORD},
    {NULL, 0}
};

static void free_store(struct state_store *store)
{
    struct state_key *key = store->keys;
    while(key) {
        struct state_key *next = key->next;
        free(key->path);
        free(key);
        key = next;
    }

    struct state_value *value = store->values;
    while(value) {
        struct state_value *next = value->next;
        free(value->path);
        free(value->name);
        free(value->data);
        free(value);
        value = next;
    }
    memset(store, 0, sizeof(*store));
}

static const struct allowed_value *find_allowed_value(const char *name)
{
    if(!name) return NULL;
    for(size_t i = 0; allowed_values[i].name; i++) {
        if(strcmp(name, allowed_values[i].name) == 0)
            return &allowed_values[i];
    }
    return NULL;
}

static bool is_allowed_key_path(const char *path)
{
    if(!path) return false;
    if(strcmp(path, "HKCU") == 0 || strcmp(path, "HKLM") == 0)
        return true;
    for(size_t i = 0; allowed_key_paths[i]; i++) {
        if(strcmp(path, allowed_key_paths[i]) == 0) return true;
    }
    return false;
}

static bool is_container_path(const char *path)
{
    if(!path) return false;
    for(size_t i = 0; container_paths[i]; i++) {
        if(strcmp(path, container_paths[i]) == 0) return true;
    }
    return false;
}

static struct state_key *find_key(const struct state_store *store,
                                  const char *path)
{
    for(struct state_key *key = store->keys; key; key = key->next) {
        if(strcmp(key->path, path) == 0) return key;
    }
    return NULL;
}

static struct state_value *find_value(const struct state_store *store,
                                      const char *path, const char *name)
{
    for(struct state_value *value = store->values; value;
        value = value->next) {
        if(strcmp(value->path, path) == 0 &&
           strcmp(value->name, name) == 0)
            return value;
    }
    return NULL;
}

static int add_key_exact(struct state_store *store, const char *path)
{
    if(find_key(store, path)) return 0;
    struct state_key *key = calloc(1, sizeof(*key));
    if(!key) return -1;
    key->path = strdup(path);
    if(!key->path) {
        free(key);
        return -1;
    }
    key->next = store->keys;
    store->keys = key;
    return 1;
}

static int add_key_hierarchy(struct state_store *store, const char *path)
{
    char *current = strdup(path);
    if(!current) return -1;
    int changed = 0;

    for(char *separator = strchr(current, '/'); separator;
        separator = strchr(separator + 1, '/')) {
        char saved = *separator;
        *separator = 0;
        if(strcmp(current, "HKCU") != 0 && strcmp(current, "HKLM") != 0) {
            int result = add_key_exact(store, current);
            if(result < 0) {
                free(current);
                return -1;
            }
            changed |= result;
        }
        *separator = saved;
    }

    int result = add_key_exact(store, current);
    free(current);
    if(result < 0) return -1;
    return changed | result;
}

static bool clone_store(const struct state_store *source,
                        struct state_store *destination)
{
    memset(destination, 0, sizeof(*destination));
    struct state_key **key_tail = &destination->keys;
    for(struct state_key *key = source->keys; key; key = key->next) {
        struct state_key *copy = calloc(1, sizeof(*copy));
        if(!copy || !(copy->path = strdup(key->path))) {
            free(copy);
            free_store(destination);
            return false;
        }
        *key_tail = copy;
        key_tail = &copy->next;
    }

    struct state_value **value_tail = &destination->values;
    for(struct state_value *value = source->values; value;
        value = value->next) {
        struct state_value *copy = calloc(1, sizeof(*copy));
        if(!copy) {
            free_store(destination);
            return false;
        }
        copy->path = strdup(value->path);
        copy->name = strdup(value->name);
        copy->type = value->type;
        copy->data_size = value->data_size;
        if(value->data_size) {
            copy->data = malloc(value->data_size);
            if(copy->data) memcpy(copy->data, value->data,
                                  value->data_size);
        }
        if(!copy->path || !copy->name ||
           (value->data_size && !copy->data)) {
            free(copy->path);
            free(copy->name);
            free(copy->data);
            free(copy);
            free_store(destination);
            return false;
        }
        *value_tail = copy;
        value_tail = &copy->next;
    }
    return true;
}

static void write_u32(unsigned char *output, uint32_t value)
{
    output[0] = (unsigned char) value;
    output[1] = (unsigned char) (value >> 8);
    output[2] = (unsigned char) (value >> 16);
    output[3] = (unsigned char) (value >> 24);
}

static uint32_t read_u32(const unsigned char *input)
{
    return (uint32_t) input[0] |
           (uint32_t) input[1] << 8 |
           (uint32_t) input[2] << 16 |
           (uint32_t) input[3] << 24;
}

static bool add_blob_size(size_t *size, size_t amount)
{
    if(amount > REGISTRY_BLOB_MAX_SIZE - *size) return false;
    *size += amount;
    return true;
}

static bool serialize_store(const struct state_store *store,
                            void **data, size_t *data_size)
{
    uint32_t record_count = 0;
    size_t size = REGISTRY_BLOB_HEADER_SIZE;
    for(struct state_key *key = store->keys; key; key = key->next) {
        size_t path_size = strlen(key->path);
        if(path_size > UINT32_MAX ||
           !add_blob_size(&size, REGISTRY_BLOB_RECORD_SIZE) ||
           !add_blob_size(&size, path_size))
            return false;
        record_count++;
    }
    for(struct state_value *value = store->values; value;
        value = value->next) {
        size_t path_size = strlen(value->path);
        size_t name_size = strlen(value->name);
        if(path_size > UINT32_MAX || name_size > UINT32_MAX ||
           !add_blob_size(&size, REGISTRY_BLOB_RECORD_SIZE) ||
           !add_blob_size(&size, path_size) ||
           !add_blob_size(&size, name_size) ||
           !add_blob_size(&size, value->data_size))
            return false;
        record_count++;
    }

    unsigned char *blob = malloc(size);
    if(!blob) return false;
    memcpy(blob, registry_blob_magic, sizeof(registry_blob_magic));
    write_u32(blob + 8, record_count);
    size_t offset = REGISTRY_BLOB_HEADER_SIZE;

    for(struct state_key *key = store->keys; key; key = key->next) {
        uint32_t path_size = (uint32_t) strlen(key->path);
        blob[offset++] = 1;
        write_u32(blob + offset, path_size); offset += 4;
        write_u32(blob + offset, 0); offset += 4;
        write_u32(blob + offset, 0); offset += 4;
        write_u32(blob + offset, 0); offset += 4;
        memcpy(blob + offset, key->path, path_size); offset += path_size;
    }
    for(struct state_value *value = store->values; value;
        value = value->next) {
        uint32_t path_size = (uint32_t) strlen(value->path);
        uint32_t name_size = (uint32_t) strlen(value->name);
        blob[offset++] = 2;
        write_u32(blob + offset, path_size); offset += 4;
        write_u32(blob + offset, name_size); offset += 4;
        write_u32(blob + offset, value->type); offset += 4;
        write_u32(blob + offset, value->data_size); offset += 4;
        memcpy(blob + offset, value->path, path_size); offset += path_size;
        memcpy(blob + offset, value->name, name_size); offset += name_size;
        if(value->data_size) {
            memcpy(blob + offset, value->data, value->data_size);
            offset += value->data_size;
        }
    }

    *data = blob;
    *data_size = size;
    return true;
}

static bool take_bytes(const unsigned char *blob, size_t blob_size,
                       size_t *offset, size_t amount,
                       const unsigned char **bytes)
{
    if(*offset > blob_size || amount > blob_size - *offset) return false;
    *bytes = blob + *offset;
    *offset += amount;
    return true;
}

static char *copy_blob_string(const unsigned char *bytes, uint32_t size)
{
    if(!size || memchr(bytes, 0, size)) return NULL;
    char *string = malloc((size_t) size + 1);
    if(!string) return NULL;
    memcpy(string, bytes, size);
    string[size] = 0;
    return string;
}

static bool parse_store(const void *data, size_t data_size,
                        struct state_store *store)
{
    memset(store, 0, sizeof(*store));
    if(!data || data_size < REGISTRY_BLOB_HEADER_SIZE ||
       data_size > REGISTRY_BLOB_MAX_SIZE)
        return false;
    const unsigned char *blob = data;
    if(memcmp(blob, registry_blob_magic, sizeof(registry_blob_magic)) != 0)
        return false;
    uint32_t record_count = read_u32(blob + 8);
    if(record_count > 1024) return false;

    size_t offset = REGISTRY_BLOB_HEADER_SIZE;
    for(uint32_t i = 0; i < record_count; i++) {
        const unsigned char *record;
        if(!take_bytes(blob, data_size, &offset,
                       REGISTRY_BLOB_RECORD_SIZE, &record))
            goto error;
        unsigned int kind = record[0];
        uint32_t path_size = read_u32(record + 1);
        uint32_t name_size = read_u32(record + 5);
        DWORD value_type = read_u32(record + 9);
        uint32_t value_size = read_u32(record + 13);
        const unsigned char *path_bytes, *name_bytes, *value_bytes;
        if(!take_bytes(blob, data_size, &offset, path_size, &path_bytes) ||
           !take_bytes(blob, data_size, &offset, name_size, &name_bytes) ||
           !take_bytes(blob, data_size, &offset, value_size, &value_bytes))
            goto error;

        char *path = copy_blob_string(path_bytes, path_size);
        if(!path || !is_allowed_key_path(path) ||
           strcmp(path, "HKCU") == 0 || strcmp(path, "HKLM") == 0) {
            free(path);
            goto error;
        }

        if(kind == 1) {
            if(name_size || value_type || value_size || find_key(store, path)) {
                free(path);
                goto error;
            }
            struct state_key *key = calloc(1, sizeof(*key));
            if(!key) {
                free(path);
                goto error;
            }
            key->path = path;
            key->next = store->keys;
            store->keys = key;
            continue;
        }

        char *name = copy_blob_string(name_bytes, name_size);
        const struct allowed_value *allowed = find_allowed_value(name);
        if(kind != 2 || !is_container_path(path) || !name || !allowed ||
           allowed->type != value_type ||
           (value_type == REG_DWORD && value_size != sizeof(DWORD)) ||
           find_value(store, path, name)) {
            free(path);
            free(name);
            goto error;
        }
        struct state_value *value = calloc(1, sizeof(*value));
        if(!value) {
            free(path);
            free(name);
            goto error;
        }
        value->path = path;
        value->name = name;
        value->type = value_type;
        value->data_size = value_size;
        if(value_size) {
            value->data = malloc(value_size);
            if(!value->data) {
                free(value->path);
                free(value->name);
                free(value);
                goto error;
            }
            memcpy(value->data, value_bytes, value_size);
        }
        value->next = store->values;
        store->values = value;
    }

    if(offset != data_size) goto error;
    for(struct state_value *value = store->values; value;
        value = value->next) {
        if(!find_key(store, value->path)) goto error;
    }
    return true;

error:
    free_store(store);
    return false;
}

static bool ensure_state_loaded(void)
{
    if(state_status == STATE_LOADED) return true;
    if(state_status == STATE_LOAD_FAILED || !state_load_callback ||
       !state_store_callback)
        return false;

    void *data = NULL;
    size_t data_size = 0;
    enum cryptbridge_registry_load_result result =
        state_load_callback(state_callback_context, &data, &data_size);
    if(result == CRYPTBRIDGE_REGISTRY_LOAD_NOT_FOUND) {
        if(data || data_size) {
            free(data);
            state_status = STATE_LOAD_FAILED;
            return false;
        }
        state_status = STATE_LOADED;
        return true;
    }
    if(result != CRYPTBRIDGE_REGISTRY_LOAD_FOUND ||
       !parse_store(data, data_size, &registry_state)) {
        free(data);
        state_status = STATE_LOAD_FAILED;
        return false;
    }
    free(data);
    state_status = STATE_LOADED;
    return true;
}

static bool persist_and_take_store(struct state_store *candidate)
{
    void *data;
    size_t data_size;
    if(!serialize_store(candidate, &data, &data_size)) return false;
    bool stored = state_store_callback(state_callback_context, data,
                                       data_size);
    free(data);
    if(!stored) return false;

    free_store(&registry_state);
    registry_state = *candidate;
    memset(candidate, 0, sizeof(*candidate));
    return true;
}

static char *normalize_subkey(const char *subkey)
{
    if(!subkey) return NULL;
    size_t size = strlen(subkey);
    char *normalized = malloc(size + 1);
    if(!normalized) return NULL;
    size_t output = 0;
    for(size_t i = 0; i < size; i++) {
        char c = subkey[i] == '\\' ? '/' : subkey[i];
        if(!output && c == '/') continue;
        normalized[output++] = c;
    }
    while(output && normalized[output - 1] == '/') output--;
    normalized[output] = 0;
    return normalized;
}

static char *key_path(HKEY key)
{
    if(key == HKEY_CURRENT_USER) return strdup("HKCU");
    if(key == HKEY_LOCAL_MACHINE) return strdup("HKLM");
    if(key == HKEY_CLASSES_ROOT || key == HKEY_USERS ||
       key == HKEY_CURRENT_CONFIG || !key)
        return NULL;
    const char *path = (const char*) key;
    if(!is_allowed_key_path(path)) return NULL;
    return strdup(path);
}

static char *joined_key_path(HKEY key, const char *subkey)
{
    char *parent = key_path(key);
    char *normalized = normalize_subkey(subkey);
    if(!parent || !normalized) {
        free(parent);
        free(normalized);
        return NULL;
    }
    size_t parent_size = strlen(parent);
    size_t subkey_size = strlen(normalized);
    char *path = malloc(parent_size + (subkey_size ? 1 : 0) +
                        subkey_size + 1);
    if(path) {
        memcpy(path, parent, parent_size);
        size_t offset = parent_size;
        if(subkey_size) path[offset++] = '/';
        memcpy(path + offset, normalized, subkey_size + 1);
    }
    free(parent);
    free(normalized);
    if(path && !is_allowed_key_path(path)) {
        free(path);
        return NULL;
    }
    return path;
}

void cryptbridge_registry_set_state_callbacks(
    cryptbridge_registry_load_callback load_callback,
    cryptbridge_registry_store_callback store_callback,
    void *context)
{
    pthread_mutex_lock(&state_mutex);
    free_store(&registry_state);
    state_load_callback = load_callback;
    state_store_callback = store_callback;
    state_callback_context = context;
    state_status = STATE_UNLOADED;
    pthread_mutex_unlock(&state_mutex);
}

bool cryptbridge_registry_state_active(void)
{
    pthread_mutex_lock(&state_mutex);
    bool active = state_load_callback || state_store_callback;
    pthread_mutex_unlock(&state_mutex);
    return active;
}

LSTATUS cryptbridge_registry_state_create_key(
    HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult,
    LPDWORD lpdwDisposition)
{
    if(!hKey || !lpSubKey) return ERROR_INVALID_PARAMETER;
    char *path = joined_key_path(hKey, lpSubKey);
    if(!path) return ERROR_ACCESS_DENIED;

    pthread_mutex_lock(&state_mutex);
    if(!ensure_state_loaded()) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_ACCESS_DENIED;
    }
    bool existed = find_key(&registry_state, path) != NULL;
    char *handle_path = phkResult ? strdup(path) : NULL;
    if(phkResult && !handle_path) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_NOT_ENOUGH_MEMORY;
    }

    if(!existed) {
        struct state_store candidate;
        if(!clone_store(&registry_state, &candidate)) {
            pthread_mutex_unlock(&state_mutex);
            free(handle_path);
            free(path);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        if(add_key_hierarchy(&candidate, path) < 0) {
            free_store(&candidate);
            pthread_mutex_unlock(&state_mutex);
            free(handle_path);
            free(path);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        if(!persist_and_take_store(&candidate)) {
            free_store(&candidate);
            pthread_mutex_unlock(&state_mutex);
            free(handle_path);
            free(path);
            return ERROR_ACCESS_DENIED;
        }
    }
    pthread_mutex_unlock(&state_mutex);

    if(phkResult) *phkResult = (HKEY) handle_path;
    if(lpdwDisposition)
        *lpdwDisposition = existed ? REG_OPENED_EXISTING_KEY
                                   : REG_CREATED_NEW_KEY;
    free(path);
    return ERROR_SUCCESS;
}

LSTATUS cryptbridge_registry_state_open_key(
    HKEY hKey, LPCSTR lpSubKey, PHKEY phkResult)
{
    if(!hKey || !lpSubKey || !phkResult) return ERROR_INVALID_PARAMETER;
    char *path = joined_key_path(hKey, lpSubKey);
    if(!path) return ERROR_ACCESS_DENIED;

    pthread_mutex_lock(&state_mutex);
    bool loaded = ensure_state_loaded();
    bool found = loaded && find_key(&registry_state, path);
    pthread_mutex_unlock(&state_mutex);
    if(!loaded) {
        free(path);
        return ERROR_ACCESS_DENIED;
    }
    if(!found) {
        free(path);
        return ERROR_FILE_NOT_FOUND;
    }
    *phkResult = (HKEY) path;
    return ERROR_SUCCESS;
}

LSTATUS cryptbridge_registry_state_set_value(
    HKEY hKey, LPCSTR lpValueName, DWORD dwType,
    const BYTE *lpData, DWORD cbData)
{
    char *path = key_path(hKey);
    const struct allowed_value *allowed = find_allowed_value(lpValueName);
    if(!path || !is_container_path(path) || !allowed ||
       allowed->type != dwType || (cbData && !lpData) ||
       (dwType == REG_DWORD && cbData != sizeof(DWORD))) {
        free(path);
        return ERROR_ACCESS_DENIED;
    }

    pthread_mutex_lock(&state_mutex);
    if(!ensure_state_loaded()) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_ACCESS_DENIED;
    }
    if(!find_key(&registry_state, path)) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_PATH_NOT_FOUND;
    }

    struct state_store candidate;
    if(!clone_store(&registry_state, &candidate)) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    struct state_value *value = find_value(&candidate, path, lpValueName);
    if(!value) {
        value = calloc(1, sizeof(*value));
        if(value) {
            value->path = strdup(path);
            value->name = strdup(lpValueName);
        }
        if(!value || !value->path || !value->name) {
            if(value) {
                free(value->path);
                free(value->name);
                free(value);
            }
            free_store(&candidate);
            pthread_mutex_unlock(&state_mutex);
            free(path);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        value->next = candidate.values;
        candidate.values = value;
    } else {
        free(value->data);
        value->data = NULL;
    }
    value->type = dwType;
    value->data_size = cbData;
    if(cbData) {
        value->data = malloc(cbData);
        if(!value->data) {
            free_store(&candidate);
            pthread_mutex_unlock(&state_mutex);
            free(path);
            return ERROR_NOT_ENOUGH_MEMORY;
        }
        memcpy(value->data, lpData, cbData);
    }

    bool stored = persist_and_take_store(&candidate);
    free_store(&candidate);
    pthread_mutex_unlock(&state_mutex);
    free(path);
    return stored ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

LSTATUS cryptbridge_registry_state_query_value(
    HKEY hKey, LPCSTR lpValueName, LPDWORD lpType,
    LPBYTE lpData, LPDWORD lpcbData)
{
    if(!lpcbData) return ERROR_INVALID_PARAMETER;
    char *path = key_path(hKey);
    if(!path || !is_container_path(path) ||
       !find_allowed_value(lpValueName)) {
        free(path);
        return ERROR_ACCESS_DENIED;
    }

    pthread_mutex_lock(&state_mutex);
    if(!ensure_state_loaded()) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_ACCESS_DENIED;
    }
    struct state_value *value = find_value(&registry_state, path,
                                           lpValueName);
    if(!value) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_FILE_NOT_FOUND;
    }
    if(lpType) *lpType = value->type;
    DWORD provided = *lpcbData;
    *lpcbData = value->data_size;
    if(lpData && provided < value->data_size) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_MORE_DATA;
    }
    if(lpData && value->data_size)
        memcpy(lpData, value->data, value->data_size);
    pthread_mutex_unlock(&state_mutex);
    free(path);
    return ERROR_SUCCESS;
}

LSTATUS cryptbridge_registry_state_delete_key(HKEY hKey, LPCSTR lpSubKey)
{
    char *path = joined_key_path(hKey, lpSubKey);
    if(!path || !is_container_path(path)) {
        free(path);
        return ERROR_ACCESS_DENIED;
    }

    pthread_mutex_lock(&state_mutex);
    if(!ensure_state_loaded()) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_ACCESS_DENIED;
    }
    if(!find_key(&registry_state, path)) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_FILE_NOT_FOUND;
    }

    struct state_store candidate;
    if(!clone_store(&registry_state, &candidate)) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_NOT_ENOUGH_MEMORY;
    }
    struct state_key **key = &candidate.keys;
    while(*key) {
        if(strcmp((*key)->path, path) == 0) {
            struct state_key *removed = *key;
            *key = removed->next;
            free(removed->path);
            free(removed);
            break;
        }
        key = &(*key)->next;
    }
    struct state_value **value = &candidate.values;
    while(*value) {
        if(strcmp((*value)->path, path) == 0) {
            struct state_value *removed = *value;
            *value = removed->next;
            removed->next = NULL;
            struct state_store temporary = {.values = removed};
            free_store(&temporary);
        } else {
            value = &(*value)->next;
        }
    }

    bool stored = persist_and_take_store(&candidate);
    free_store(&candidate);
    pthread_mutex_unlock(&state_mutex);
    free(path);
    return stored ? ERROR_SUCCESS : ERROR_ACCESS_DENIED;
}

static const char *direct_child(const char *parent, const char *candidate)
{
    size_t parent_size = strlen(parent);
    if(strncmp(parent, candidate, parent_size) != 0 ||
       candidate[parent_size] != '/')
        return NULL;
    const char *child = candidate + parent_size + 1;
    return strchr(child, '/') ? NULL : child;
}

LSTATUS cryptbridge_registry_state_enum_key(
    HKEY hKey, DWORD dwIndex, LPSTR lpName, LPDWORD lpcName,
    LPFILETIME lpftLastWriteTime)
{
    if(!lpcName) return ERROR_INVALID_PARAMETER;
    char *path = key_path(hKey);
    if(!path) return ERROR_ACCESS_DENIED;

    pthread_mutex_lock(&state_mutex);
    if(!ensure_state_loaded()) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_ACCESS_DENIED;
    }

    const char *name = NULL;
    DWORD index = 0;
    for(struct state_key *key = registry_state.keys; key; key = key->next) {
        const char *child = direct_child(path, key->path);
        if(!child) continue;
        if(index++ == dwIndex) {
            name = child;
            break;
        }
    }
    if(!name) {
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_NO_MORE_ITEMS;
    }

    size_t name_size = strlen(name);
    if(!lpName || *lpcName <= name_size) {
        *lpcName = (DWORD) name_size + 1;
        pthread_mutex_unlock(&state_mutex);
        free(path);
        return ERROR_MORE_DATA;
    }
    memcpy(lpName, name, name_size + 1);
    *lpcName = (DWORD) name_size;
    if(lpftLastWriteTime) memset(lpftLastWriteTime, 0,
                                sizeof(*lpftLastWriteTime));
    pthread_mutex_unlock(&state_mutex);
    free(path);
    return ERROR_SUCCESS;
}
