#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cryptbridge/registry.h>
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "registry_state.h"

#define RegOpenKeyExA(key, subkey, options, access, result) \
    cryptbridge_registry_state_open_key((key), (subkey), (result))
#define RegCreateKeyExA(key, subkey, reserved, class_name, options, access, \
                        security, result, disposition) \
    cryptbridge_registry_state_create_key((key), (subkey), (result), \
                                           (disposition))
#define RegSetValueExA(key, name, reserved, type, data, size) \
    cryptbridge_registry_state_set_value((key), (name), (type), (data), \
                                          (size))
#define RegQueryValueExA(key, name, reserved, type, data, size) \
    cryptbridge_registry_state_query_value((key), (name), (type), (data), \
                                            (size))
#define RegDeleteKeyA(key, subkey) \
    cryptbridge_registry_state_delete_key((key), (subkey))
#define RegEnumKeyExA(key, index, name, name_size, reserved, class_name, \
                      class_size, modified) \
    cryptbridge_registry_state_enum_key((key), (index), (name), (name_size), \
                                         (modified))
#define RegCloseKey(key) (free((void*)(key)), ERROR_SUCCESS)

static void *saved_blob;
static size_t saved_blob_size;
static unsigned int load_count;
static unsigned int store_count;
static bool fail_store;

static enum cryptbridge_registry_load_result
load_registry(void *context, void **data, size_t *data_size) {
    assert(context == &load_count);
    load_count++;
    if(!saved_blob) return CRYPTBRIDGE_REGISTRY_LOAD_NOT_FOUND;
    *data = malloc(saved_blob_size);
    assert(*data);
    memcpy(*data, saved_blob, saved_blob_size);
    *data_size = saved_blob_size;
    return CRYPTBRIDGE_REGISTRY_LOAD_FOUND;
}

static bool store_registry(void *context, const void *data,
                           size_t data_size) {
    assert(context == &load_count);
    store_count++;
    if(fail_store) return false;
    void *copy = malloc(data_size);
    assert(copy);
    memcpy(copy, data, data_size);
    free(saved_blob);
    saved_blob = copy;
    saved_blob_size = data_size;
    return true;
}

static void reload_registry(void) {
    cryptbridge_registry_set_state_callbacks(
        load_registry, store_registry, &load_count);
}

static HKEY open_container(void) {
    HKEY key = NULL;
    assert(RegOpenKeyExA(
        HKEY_CURRENT_USER,
        "Software\\Wine\\Crypto\\RSA\\VFS key container",
        0, KEY_READ | KEY_WRITE, &key) == ERROR_SUCCESS);
    assert(key);
    return key;
}

int main(void) {
    static const char *container_path =
        "Software\\Wine\\Crypto\\RSA\\VFS key container";
    static const BYTE key_pair[] = {0, 1, 2, 0xfe, 0xff};
    DWORD permissions = 0x12345678;
    HKEY key = NULL;

    reload_registry();
    assert(RegOpenKeyExA(HKEY_CURRENT_USER, container_path, 0, KEY_READ,
                         &key) == ERROR_FILE_NOT_FOUND);
    assert(load_count == 1);
    assert(!saved_blob);

    DWORD disposition = 0;
    assert(RegCreateKeyExA(HKEY_CURRENT_USER, container_path, 0, NULL, 0,
                           KEY_READ | KEY_WRITE, NULL, &key,
                           &disposition) == ERROR_SUCCESS);
    assert(disposition == REG_CREATED_NEW_KEY);
    assert(store_count == 1 && saved_blob_size > 12);
    assert(RegSetValueExA(key, "KeyExchangeKeyPair", 0, REG_BINARY,
                          key_pair, sizeof(key_pair)) == ERROR_SUCCESS);
    assert(RegSetValueExA(key, "KeyExchangePermissions", 0, REG_DWORD,
                          (const BYTE*)&permissions,
                          sizeof(permissions)) == ERROR_SUCCESS);
    assert(store_count == 3);
    assert(RegCloseKey(key) == ERROR_SUCCESS);

    reload_registry();
    key = open_container();
    assert(load_count == 2);

    DWORD type = 0, size = 0;
    assert(RegQueryValueExA(key, "KeyExchangeKeyPair", NULL, &type, NULL,
                            &size) == ERROR_SUCCESS);
    assert(type == REG_BINARY && size == sizeof(key_pair));
    BYTE pair_output[sizeof(key_pair)] = {0};
    assert(RegQueryValueExA(key, "KeyExchangeKeyPair", NULL, &type,
                            pair_output, &size) == ERROR_SUCCESS);
    assert(type == REG_BINARY && size == sizeof(key_pair));
    assert(!memcmp(pair_output, key_pair, sizeof(key_pair)));

    DWORD permission_output = 0;
    size = sizeof(permission_output);
    assert(RegQueryValueExA(key, "KeyExchangePermissions", NULL, &type,
                            (BYTE*)&permission_output,
                            &size) == ERROR_SUCCESS);
    assert(type == REG_DWORD && size == sizeof(permission_output));
    assert(permission_output == permissions);

    size = sizeof(pair_output) - 1;
    assert(RegQueryValueExA(key, "KeyExchangeKeyPair", NULL, &type,
                            pair_output, &size) == ERROR_MORE_DATA);
    assert(size == sizeof(key_pair));

    assert(RegSetValueExA(key, "UnexpectedValue", 0, REG_BINARY,
                          key_pair, sizeof(key_pair)) == ERROR_ACCESS_DENIED);
    assert(RegSetValueExA(key, "KeyExchangePermissions", 0, REG_BINARY,
                          key_pair, sizeof(key_pair)) == ERROR_ACCESS_DENIED);

    fail_store = true;
    DWORD changed_permissions = 7;
    assert(RegSetValueExA(key, "KeyExchangePermissions", 0, REG_DWORD,
                          (const BYTE*)&changed_permissions,
                          sizeof(changed_permissions)) ==
           ERROR_ACCESS_DENIED);
    fail_store = false;
    permission_output = 0;
    size = sizeof(permission_output);
    assert(RegQueryValueExA(key, "KeyExchangePermissions", NULL, &type,
                            (BYTE*)&permission_output,
                            &size) == ERROR_SUCCESS);
    assert(permission_output == permissions);
    assert(RegCloseKey(key) == ERROR_SUCCESS);

    HKEY base = NULL;
    assert(RegOpenKeyExA(HKEY_CURRENT_USER,
                         "Software\\Wine\\Crypto\\RSA", 0, KEY_READ,
                         &base) == ERROR_SUCCESS);
    char name[32];
    DWORD name_size = sizeof(name);
    assert(RegEnumKeyExA(base, 0, name, &name_size, NULL, NULL, NULL,
                         NULL) == ERROR_SUCCESS);
    assert(!strcmp(name, "VFS key container"));
    assert(name_size == strlen(name));
    assert(RegCloseKey(base) == ERROR_SUCCESS);

    HKEY rejected = NULL;
    assert(RegCreateKeyExA(HKEY_CURRENT_USER,
                           "Software\\Wine\\Crypto\\RSA\\Other", 0,
                           NULL, 0, KEY_WRITE, NULL, &rejected, NULL) ==
           ERROR_ACCESS_DENIED);

    void *valid_blob = malloc(saved_blob_size);
    assert(valid_blob);
    memcpy(valid_blob, saved_blob, saved_blob_size);
    size_t valid_blob_size = saved_blob_size;

    ((BYTE*)saved_blob)[0] ^= 0xff;
    reload_registry();
    assert(RegCreateKeyExA(HKEY_CURRENT_USER, container_path, 0, NULL, 0,
                           KEY_WRITE, NULL, &key, NULL) ==
           ERROR_ACCESS_DENIED);

    free(saved_blob);
    saved_blob_size = 64 * 1024 + 1;
    saved_blob = calloc(1, saved_blob_size);
    assert(saved_blob);
    reload_registry();
    assert(RegCreateKeyExA(HKEY_CURRENT_USER, container_path, 0, NULL, 0,
                           KEY_WRITE, NULL, &key, NULL) ==
           ERROR_ACCESS_DENIED);

    free(saved_blob);
    saved_blob = valid_blob;
    saved_blob_size = valid_blob_size;
    reload_registry();
    assert(RegDeleteKeyA(HKEY_CURRENT_USER, container_path) ==
           ERROR_SUCCESS);
    reload_registry();
    assert(RegOpenKeyExA(HKEY_CURRENT_USER, container_path, 0, KEY_READ,
                         &key) == ERROR_FILE_NOT_FOUND);

    cryptbridge_registry_set_state_callbacks(NULL, NULL, NULL);
    free(saved_blob);
    return 0;
}
