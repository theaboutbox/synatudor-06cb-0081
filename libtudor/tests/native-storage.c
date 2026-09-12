#include <assert.h>
#include <stddef.h>
#include <string.h>

#include "tudor/internal.h"

static_assert(sizeof(WINBIO_IDENTITY) == 76,
              "WINBIO_IDENTITY must match the Windows ABI");
static_assert(offsetof(WINBIO_IDENTITY, TemplateGuid) == 0x04,
              "WINBIO_IDENTITY.TemplateGuid must match the Windows ABI");
static_assert(offsetof(WINBIO_IDENTITY, Wildcard) == 0x04,
              "WINBIO_IDENTITY.Wildcard must match the Windows ABI");
static_assert(offsetof(WINBIO_PIPELINE, StorageHandle) == 0x10,
              "WINBIO_PIPELINE.StorageHandle must match the Windows ABI");
static_assert(offsetof(WINBIO_PIPELINE, StorageInterface) == 0x28,
              "WINBIO_PIPELINE.StorageInterface must match the Windows ABI");
static_assert(offsetof(WINBIO_PIPELINE, StorageContext) == 0x40,
              "WINBIO_PIPELINE.StorageContext must match the Windows ABI");
static_assert(offsetof(WINBIO_STORAGE_INTERFACE, DeleteRecord) == 0x70,
              "WINBIO_STORAGE_INTERFACE.DeleteRecord must match the Windows ABI");

static HRESULT open_result;
static HRESULT create_result;
static HRESULT delete_result;
static unsigned int open_calls;
static unsigned int create_calls;
static unsigned int delete_calls;
static WINBIO_IDENTITY deleted_identity;
static UCHAR deleted_subfactor;

static void assert_database_args(GUID *database_id,
                                 const char16_t *file_path,
                                 const char16_t *connect_string) {
    GUID expected = DEFINE_GUID(D833B48E, 3178, 4DF0, AEE3, 2803155883D4);
    assert(database_id);
    assert(memcmp(database_id, &expected, sizeof(expected)) == 0);
    assert(file_path && file_path[0] == 0);
    assert(connect_string && connect_string[0] == 0);
}

static HRESULT __winfnc mock_open_database(WINBIO_PIPELINE *pipeline,
                                            GUID *database_id,
                                            const char16_t *file_path,
                                            const char16_t *connect_string) {
    open_calls++;
    assert_database_args(database_id, file_path, connect_string);
    if(open_result == ERROR_SUCCESS)
        pipeline->StorageHandle = (HANDLE) (uintptr_t) 1;
    return open_result;
}

static HRESULT __winfnc mock_create_database(WINBIO_PIPELINE *pipeline,
                                              GUID *database_id,
                                              ULONG factor,
                                              GUID *format,
                                              const char16_t *file_path,
                                              const char16_t *connect_string,
                                              SIZE_T index_count,
                                              SIZE_T initial_size) {
    GUID null_guid = {0};
    create_calls++;
    assert_database_args(database_id, file_path, connect_string);
    assert(factor == WINBIO_TYPE_FINGERPRINT);
    assert(format && memcmp(format, &null_guid, sizeof(null_guid)) == 0);
    assert(index_count == 0);
    assert(initial_size == 0x20);
    if(create_result == ERROR_SUCCESS)
        pipeline->StorageHandle = (HANDLE) (uintptr_t) 1;
    return create_result;
}

static HRESULT __winfnc mock_delete_record(WINBIO_PIPELINE *pipeline,
                                            WINBIO_IDENTITY *identity,
                                            UCHAR subfactor) {
    (void) pipeline;
    delete_calls++;
    deleted_identity = *identity;
    deleted_subfactor = subfactor;
    return delete_result;
}

static WINBIO_STORAGE_INTERFACE mock_storage = {
    .Version = {1, 0},
    .Type = 3,
    .Size = 0xb8,
    .OpenDatabase = mock_open_database,
    .CreateDatabase = mock_create_database,
    .DeleteRecord = mock_delete_record
};

static struct windrv_dll mock_adapter;

static void reset_calls(void) {
    open_result = ERROR_SUCCESS;
    create_result = ERROR_SUCCESS;
    delete_result = ERROR_SUCCESS;
    open_calls = create_calls = delete_calls = 0;
    deleted_identity = (WINBIO_IDENTITY) {0};
    deleted_subfactor = 0;
}

int main(void) {
    WINBIO_PIPELINE pipeline = {
        .StorageHandle = INVALID_HANDLE_VALUE,
        .StorageInterface = &mock_storage
    };
    struct tudor_device device = {
        .pipeline = &pipeline,
        .records_head = NULL
    };
    tudor_native_storage_adapter = &mock_storage;
    tudor_adapter_dll = &mock_adapter;

    assert(tudor_uses_native_storage(&device));
    assert(tudor_add_record(&device, (RECGUID) {0},
                            TUDOR_FINGER_RH_INDEX_FINGER,
                            NULL, 0));
    assert(device.records_head == NULL);

    reset_calls();
    assert(tudor_open_native_storage_database(&device));
    assert(open_calls == 1 && create_calls == 0);

    reset_calls();
    pipeline.StorageHandle = INVALID_HANDLE_VALUE;
    open_result = WINBIO_E_DATABASE_CANT_FIND;
    assert(tudor_open_native_storage_database(&device));
    assert(open_calls == 1 && create_calls == 1);

    reset_calls();
    pipeline.StorageHandle = INVALID_HANDLE_VALUE;
    open_result = WINBIO_E_DATABASE_CANT_OPEN;
    assert(!tudor_open_native_storage_database(&device));
    assert(open_calls == 1 && create_calls == 0);

    RECGUID guid = {
        .PartA = 0x2195dc59,
        .PartB = 0x1234,
        .PartC = 0x5678,
        .PartD = 0x9abc,
        .PartE = 0x123456789abc
    };
    reset_calls();
    assert(tudor_wipe_records(&device, &guid,
                              TUDOR_FINGER_RH_INDEX_FINGER) == 1);
    assert(delete_calls == 1);
    assert(deleted_identity.Type == WINBIO_ID_TYPE_GUID);
    assert(memcmp(&deleted_identity.TemplateGuid, &guid, sizeof(guid)) == 0);
    assert(deleted_subfactor == TUDOR_FINGER_RH_INDEX_FINGER);

    reset_calls();
    assert(tudor_wipe_records(&device, NULL, TUDOR_FINGER_ANY) == 1);
    assert(delete_calls == 1);
    assert(deleted_identity.Type == WINBIO_ID_TYPE_WILDCARD);
    assert(deleted_identity.Wildcard == 0x25066282);
    assert(deleted_subfactor == WINBIO_SUBTYPE_ANY);

    reset_calls();
    delete_result = WINBIO_E_DATABASE_NO_SUCH_RECORD;
    assert(tudor_wipe_records(&device, &guid,
                              TUDOR_FINGER_RH_INDEX_FINGER) == 0);

    pipeline.StorageInterface = tudor_storage_adapter;
    assert(!tudor_uses_native_storage(&device));
    return 0;
}
