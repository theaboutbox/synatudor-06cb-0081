#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "tudor/internal.h"

extern void tudor_internal_test_set_pairing_strategy_ready(bool ready);

enum lifecycle_event {
    SENSOR_ATTACH,
    ENGINE_ATTACH,
    STORAGE_ATTACH,
    STORAGE_OPEN,
    STORAGE_CREATE,
    ENGINE_INIT,
    SENSOR_INIT,
    SENSOR_RESET,
    ENGINE_ACTIVATE,
    SENSOR_ACTIVATE,
    SENSOR_DEACTIVATE,
    ENGINE_DEACTIVATE,
    SENSOR_CLEANUP,
    ENGINE_CLEANUP,
    STORAGE_CLOSE,
    STORAGE_DETACH,
    ENGINE_DETACH,
    SENSOR_DETACH,
};

static enum lifecycle_event events[64];
static size_t event_count;
static int fail_event = -1;
static HRESULT open_result;
static HRESULT create_result;
static bool invalid_context;
static bool invalid_database_args;

static void record_event(enum lifecycle_event event) {
    assert(event_count < sizeof(events) / sizeof(events[0]));
    events[event_count++] = event;
}

static HRESULT event_result(enum lifecycle_event event) {
    record_event(event);
    return fail_event == (int) event ? E_INVALIDARG : ERROR_SUCCESS;
}

static void check_empty_contexts(WINBIO_PIPELINE *pipeline) {
    if(pipeline->SensorContext || pipeline->EngineContext ||
       pipeline->StorageContext)
        invalid_context = true;
}

static void check_database_args(GUID *database_id,
                                const char16_t *file_path,
                                const char16_t *connect_string) {
    const GUID expected =
        DEFINE_GUID(D833B48E, 3178, 4DF0, AEE3, 2803155883D4);
    if(!database_id || memcmp(database_id, &expected, sizeof(expected)) ||
       !file_path || file_path[0] ||
       !connect_string || connect_string[0])
        invalid_database_args = true;
}

static HRESULT __winfnc sensor_attach(WINBIO_PIPELINE *pipeline) {
    check_empty_contexts(pipeline);
    return event_result(SENSOR_ATTACH);
}

static HRESULT __winfnc sensor_detach(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(SENSOR_DETACH);
}

static HRESULT __winfnc sensor_reset(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(SENSOR_RESET);
}

static HRESULT __winfnc sensor_query_status(WINBIO_PIPELINE *pipeline,
                                             ULONG *status) {
    (void) pipeline;
    *status = WINBIO_SENSOR_READY;
    return ERROR_SUCCESS;
}

static HRESULT __winfnc sensor_init(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(SENSOR_INIT);
}

static HRESULT __winfnc sensor_cleanup(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(SENSOR_CLEANUP);
}

static HRESULT __winfnc sensor_activate(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(SENSOR_ACTIVATE);
}

static HRESULT __winfnc sensor_deactivate(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(SENSOR_DEACTIVATE);
}

static HRESULT __winfnc engine_attach(WINBIO_PIPELINE *pipeline) {
    check_empty_contexts(pipeline);
    return event_result(ENGINE_ATTACH);
}

static HRESULT __winfnc engine_detach(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(ENGINE_DETACH);
}

static HRESULT __winfnc engine_init(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(ENGINE_INIT);
}

static HRESULT __winfnc engine_cleanup(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(ENGINE_CLEANUP);
}

static HRESULT __winfnc engine_activate(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(ENGINE_ACTIVATE);
}

static HRESULT __winfnc engine_deactivate(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(ENGINE_DEACTIVATE);
}

static HRESULT __winfnc storage_attach(WINBIO_PIPELINE *pipeline) {
    check_empty_contexts(pipeline);
    return event_result(STORAGE_ATTACH);
}

static HRESULT __winfnc storage_detach(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    return event_result(STORAGE_DETACH);
}

static HRESULT __winfnc storage_open(WINBIO_PIPELINE *pipeline,
                                      GUID *database_id,
                                      const char16_t *file_path,
                                      const char16_t *connect_string) {
    record_event(STORAGE_OPEN);
    check_database_args(database_id, file_path, connect_string);
    if(open_result == ERROR_SUCCESS)
        pipeline->StorageHandle = (HANDLE) (uintptr_t) 1;
    return open_result;
}

static HRESULT __winfnc storage_create(WINBIO_PIPELINE *pipeline,
                                        GUID *database_id, ULONG factor,
                                        GUID *format,
                                        const char16_t *file_path,
                                        const char16_t *connect_string,
                                        SIZE_T index_count,
                                        SIZE_T initial_size) {
    const GUID null_guid = {0};
    record_event(STORAGE_CREATE);
    check_database_args(database_id, file_path, connect_string);
    if(factor != WINBIO_TYPE_FINGERPRINT || !format ||
       memcmp(format, &null_guid, sizeof(null_guid)) || index_count != 0 ||
       initial_size != 0x20)
        invalid_database_args = true;
    if(create_result == ERROR_SUCCESS)
        pipeline->StorageHandle = (HANDLE) (uintptr_t) 1;
    return create_result;
}

static HRESULT __winfnc storage_close(WINBIO_PIPELINE *pipeline) {
    pipeline->StorageHandle = INVALID_HANDLE_VALUE;
    return event_result(STORAGE_CLOSE);
}

/* If the v1 size guard regresses, these callbacks make the unexpected access
 * visible in the event trace instead of silently succeeding. */
static HRESULT __winfnc storage_optional_init(WINBIO_PIPELINE *pipeline) {
    (void) pipeline;
    invalid_database_args = true;
    return E_INVALIDARG;
}

static WINBIO_SENSOR_INTERFACE mock_sensor = {
    .Version = {1, 0},
    .Size = offsetof(WINBIO_SENSOR_INTERFACE, Deactivate) +
            sizeof(mock_sensor.Deactivate),
    .Attach = sensor_attach,
    .Detach = sensor_detach,
    .QueryStatus = sensor_query_status,
    .Reset = sensor_reset,
    .PipelineInit = sensor_init,
    .PipelineCleanup = sensor_cleanup,
    .Activate = sensor_activate,
    .Deactivate = sensor_deactivate,
};

static WINBIO_ENGINE_INTERFACE mock_engine = {
    .Version = {1, 0},
    .Size = offsetof(WINBIO_ENGINE_INTERFACE, Deactivate) +
            sizeof(mock_engine.Deactivate),
    .Attach = engine_attach,
    .Detach = engine_detach,
    .PipelineInit = engine_init,
    .PipelineCleanup = engine_cleanup,
    .Activate = engine_activate,
    .Deactivate = engine_deactivate,
};

static WINBIO_STORAGE_INTERFACE mock_storage = {
    .Version = {1, 0},
    .Type = 3,
    .Size = offsetof(WINBIO_STORAGE_INTERFACE, ControlUnitPrivileged) +
            sizeof(mock_storage.ControlUnitPrivileged),
    .Attach = storage_attach,
    .Detach = storage_detach,
    .CreateDatabase = storage_create,
    .OpenDatabase = storage_open,
    .CloseDatabase = storage_close,
    .PipelineInit = storage_optional_init,
    .PipelineCleanup = storage_optional_init,
    .Activate = storage_optional_init,
    .Deactivate = storage_optional_init,
};

_Static_assert(offsetof(WINBIO_STORAGE_INTERFACE, NotifyPowerChange) == 0xb8,
               "0081 storage v1 boundary changed");

static struct windrv_dll mock_adapter;

static void reset_scenario(void) {
    event_count = 0;
    fail_event = -1;
    open_result = ERROR_SUCCESS;
    create_result = ERROR_SUCCESS;
    invalid_context = false;
    invalid_database_args = false;
}

static void assert_events(const enum lifecycle_event *expected,
                          size_t expected_count) {
    assert(event_count == expected_count);
    assert(memcmp(events, expected, expected_count * sizeof(expected[0])) == 0);
    assert(!invalid_context);
    assert(!invalid_database_args);
}

static void test_success(bool create_database) {
    static const enum lifecycle_event open_existing[] = {
        SENSOR_ATTACH, ENGINE_ATTACH, STORAGE_ATTACH, STORAGE_OPEN,
        ENGINE_INIT, SENSOR_INIT, SENSOR_RESET, ENGINE_ACTIVATE,
        SENSOR_ACTIVATE, SENSOR_DEACTIVATE, ENGINE_DEACTIVATE,
        SENSOR_CLEANUP, ENGINE_CLEANUP, STORAGE_CLOSE, STORAGE_DETACH,
        ENGINE_DETACH, SENSOR_DETACH,
    };
    static const enum lifecycle_event create_new[] = {
        SENSOR_ATTACH, ENGINE_ATTACH, STORAGE_ATTACH, STORAGE_OPEN,
        STORAGE_CREATE, ENGINE_INIT, SENSOR_INIT, SENSOR_RESET,
        ENGINE_ACTIVATE, SENSOR_ACTIVATE, SENSOR_DEACTIVATE,
        ENGINE_DEACTIVATE, SENSOR_CLEANUP, ENGINE_CLEANUP, STORAGE_CLOSE,
        STORAGE_DETACH, ENGINE_DETACH, SENSOR_DETACH,
    };
    struct tudor_device device;

    memset(&device, 0, sizeof(device));
    reset_scenario();
    if(create_database)
        open_result = WINBIO_E_DATABASE_CANT_FIND;
    assert(tudor_open(&device, NULL, NULL));
    assert(tudor_close(&device));
    assert(device.pipeline == NULL);
    if(create_database)
        assert_events(create_new, sizeof(create_new) / sizeof(create_new[0]));
    else
        assert_events(open_existing,
                      sizeof(open_existing) / sizeof(open_existing[0]));
}

static void test_open_failure(void) {
    static const enum lifecycle_event expected[] = {
        SENSOR_ATTACH, ENGINE_ATTACH, STORAGE_ATTACH, STORAGE_OPEN,
        STORAGE_DETACH, ENGINE_DETACH, SENSOR_DETACH,
    };
    struct tudor_device device;

    memset(&device, 0, sizeof(device));
    reset_scenario();
    open_result = WINBIO_E_DATABASE_CANT_OPEN;
    assert(!tudor_open(&device, NULL, NULL));
    assert(device.pipeline == NULL);
    assert_events(expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_init_failure(void) {
    static const enum lifecycle_event expected[] = {
        SENSOR_ATTACH, ENGINE_ATTACH, STORAGE_ATTACH, STORAGE_OPEN,
        ENGINE_INIT, STORAGE_CLOSE, STORAGE_DETACH, ENGINE_DETACH,
        SENSOR_DETACH,
    };
    struct tudor_device device;

    memset(&device, 0, sizeof(device));
    reset_scenario();
    fail_event = ENGINE_INIT;
    assert(!tudor_open(&device, NULL, NULL));
    assert(device.pipeline == NULL);
    assert_events(expected, sizeof(expected) / sizeof(expected[0]));
}

static void test_late_failure(void) {
    static const enum lifecycle_event expected[] = {
        SENSOR_ATTACH, ENGINE_ATTACH, STORAGE_ATTACH, STORAGE_OPEN,
        ENGINE_INIT, SENSOR_INIT, SENSOR_RESET, ENGINE_ACTIVATE,
        SENSOR_ACTIVATE, ENGINE_DEACTIVATE, SENSOR_CLEANUP, ENGINE_CLEANUP,
        STORAGE_CLOSE, STORAGE_DETACH, ENGINE_DETACH, SENSOR_DETACH,
    };
    struct tudor_device device;

    memset(&device, 0, sizeof(device));
    reset_scenario();
    fail_event = SENSOR_ACTIVATE;
    assert(!tudor_open(&device, NULL, NULL));
    assert(device.pipeline == NULL);
    assert_events(expected, sizeof(expected) / sizeof(expected[0]));
}

int main(void) {
    struct windrv_dll *saved_adapter = tudor_adapter_dll;
    WINBIO_SENSOR_INTERFACE *saved_sensor = tudor_sensor_adapter;
    WINBIO_ENGINE_INTERFACE *saved_engine = tudor_engine_adapter;
    WINBIO_STORAGE_INTERFACE *saved_storage = tudor_native_storage_adapter;

    assert(mock_storage.Size == 0xb8);
    tudor_adapter_dll = &mock_adapter;
    tudor_sensor_adapter = &mock_sensor;
    tudor_engine_adapter = &mock_engine;
    tudor_native_storage_adapter = &mock_storage;
    tudor_internal_test_set_pairing_strategy_ready(true);

    test_success(false);
    test_success(true);
    test_open_failure();
    test_init_failure();
    test_late_failure();

    tudor_native_storage_adapter = saved_storage;
    tudor_engine_adapter = saved_engine;
    tudor_sensor_adapter = saved_sensor;
    tudor_adapter_dll = saved_adapter;
    tudor_internal_test_set_pairing_strategy_ready(false);
    return 0;
}
