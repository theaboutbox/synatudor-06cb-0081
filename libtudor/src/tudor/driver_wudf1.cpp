#include "winapi/windows.h"
#include "internal.h"
// #include <ksguid.h>
#include <stdio.h>
#include <cstdint>
#include <cwchar>
#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <unistd.h>
#include <codecvt>
#include <string>
#include <locale>
#include <atomic>
#include <cstddef>
#include <cstdlib>
#include <pthread.h>
#include <time.h>

#include <cryptbridge/registry.h>
#include <cryptbridge/identity.h>
#include <tudor/state-properties.h>

#define _Analysis_mode_(...)
#define _Notliteral_
#define __user_driver
#define _Out_writes_bytes_opt_
#define _In_reads_bytes_opt_(...)

#include "wudf1_minimal.h"

// #include "winbio_ioctl.h"

#define NTDDI_VERSION NTDDI_WIN7

// extern "C" {
// HRESULT PropVariantToInt32(REFPROPVARIANT propvarIn, LONG *ret);
//
// int PropVariantToStringAlloc(
//   REFPROPVARIANT propvar,
//   PWSTR          *ppszOut
// );
// }

// typedef DllGetClassObject_t(_In_ REFCLSID rclsid, _In_ REFIID riid, _Out_ LPVOID* ppv);


IDriverEntry *inst = NULL;
IWDFDriver* aDriver = NULL;

bool tudor_log_traces = false;

int goIdle = 0;

static winmodule ntdll_module = {
    .name = "ntdll.dll",
    .cmdline = "ntdll.dll",
    .environ = (const char*[]) { NULL }
};

#define DLL_PROCESS_ATTACH 1
#define DLL_PROCESS_DETACH 0
#define DLL_THREAD_ATTACH 2
#define DLL_THREAD_DETACH 3
typedef BOOL __winfnc (*api_DllMain)(HANDLE hinstDLL, int fdwReason, void *lpReserved);

struct windrv_dll *tudor_adapter_dll, *tudor_driver_dll;
WINBIO_SENSOR_INTERFACE *tudor_sensor_adapter;
WINBIO_ENGINE_INTERFACE *tudor_engine_adapter;
WINBIO_STORAGE_INTERFACE *tudor_native_storage_adapter;

static DRIVER_OBJECT umdf_driver;
struct winwdf_driver *tudor_wdf_driver;

/* These RVAs are specific to the pinned synaWudfBioUsb.dll.  The lifecycle
 * observer also checks the loaded module and exact CaptureThread address, so
 * an unrelated Windows worker can never enter this path. */
static constexpr uintptr_t SYNA_CAPTURE_THREAD_RVA = 0x1c40c;
static constexpr useconds_t SYNA_CAPTURE_RECOVERY_DELAY_US = 250000;
static constexpr ULONG SYNA_CAPTURE_IOCTL = 0x440014;
static constexpr ULONG SYNA_RESET_OWNERSHIP_IOCTL = 0x442040;
static constexpr HRESULT SYNA_OWNERSHIP_FAILURE_CAP_STATUS = 0x800710dfu;
/* Leave enough room for the host to persist a terminal result before the
 * surrounding fprintd/helper process deadline. */
static constexpr unsigned int SYNA_RESET_OWNERSHIP_WAIT_MS = 15000;

/* A restored counter describes an earlier attempt and must not block this
 * one.  Only an exact VT_UINT write made after OnPrepareHardware starts is
 * evidence that the current ownership handshake failed.  Latch nonzero
 * writes so a later zero cannot hide a failure before the init thread checks
 * it.  uint64_t leaves every possible 32-bit property value available. */
static constexpr uint64_t OWNERSHIP_FAILURE_NOT_WRITTEN = UINT64_MAX;
static std::atomic<uint64_t> ownership_failure_write{
    OWNERSHIP_FAILURE_NOT_WRITTEN
};

static void ownership_failure_reset(void) {
    ownership_failure_write.store(OWNERSHIP_FAILURE_NOT_WRITTEN,
                                  std::memory_order_release);
}

static void ownership_failure_observe(const std::string& name,
                                      const PROPVARIANT *value) {
    if(name != "SetOwnershipFailureCount" || !value ||
       value->vt != VT_UINT)
        return;

    const uint64_t count = value->uintVal;
    if(count != 0) {
        ownership_failure_write.store(count, std::memory_order_release);
        return;
    }

    /* Record an explicit zero only while no failure has been observed. */
    uint64_t expected = OWNERSHIP_FAILURE_NOT_WRITTEN;
    ownership_failure_write.compare_exchange_strong(
        expected, 0, std::memory_order_release, std::memory_order_relaxed);
}

static uint64_t ownership_failure_observed(void) {
    return ownership_failure_write.load(std::memory_order_acquire);
}

static void ownership_failure_store_marker(bool detected) {
    if(!tudor_set_state_fnc) return;

    const uint8_t value = detected ? 1 : 0;
    tudor_set_state_fnc(TUDOR_STATE_OWNERSHIP_FAILURE_DETECTED,
                        TUDOR_STATE_VALUE_BOOL, &value, sizeof(value));
}

static void ownership_failure_start_init(bool ownership_reset_mode) {
    /* Clear a stale result at the earliest normal initialization boundary,
     * before an unrelated DLL or hardware failure can end this run. */
    if(!ownership_reset_mode) ownership_failure_store_marker(false);
}

static void ownership_failure_record_prepare_status(
    HRESULT status, bool ownership_reset_mode) {
    if(!ownership_reset_mode &&
       status == SYNA_OWNERSHIP_FAILURE_CAP_STATUS)
        ownership_failure_store_marker(true);
}

static bool ownership_failure_should_reject(bool ownership_reset_mode) {
    if(ownership_reset_mode) return false;

    const uint64_t count = ownership_failure_observed();
    return count != OWNERSHIP_FAILURE_NOT_WRITTEN && count != 0;
}

static bool ownership_failure_reject_init(const char *stage,
                                          bool ownership_reset_mode) {
    if(!ownership_failure_should_reject(ownership_reset_mode)) return false;

    const uint64_t count = ownership_failure_observed();
    ownership_failure_store_marker(true);
    log_error("Vendor ownership handshake failed during %s "
              "(SetOwnershipFailureCount=%llu); refusing to expose an "
              "unsafe adapter",
              stage, (unsigned long long) count);
    return true;
}

/* MyRequest is defined below.  This helper atomically validates and claims a
 * stalled request under the lifecycle lock, then invokes vendor code after
 * dropping the lock. */
static bool capture_request_recover(uint64_t request_generation,
                                    uint64_t worker_generation);

struct capture_worker_observation {
    void *cookie;
    uint64_t request_generation;
    uint64_t worker_generation;
    capture_worker_observation *next;
};

static struct {
    pthread_mutex_t lock;
    pthread_cond_t cond;
    pthread_t relay_thread;
    bool relay_started;
    bool stopping;

    struct winmodule *module;
    void *capture_proc;

    void *active_request;
    uint64_t request_generation;
    bool cancel_requested;
    bool recovery_reported;

    uint64_t worker_generation;
    capture_worker_observation *workers;

    bool recovery_pending;
    uint64_t recovery_request_generation;
    uint64_t recovery_worker_generation;
} capture_relay = {
    PTHREAD_MUTEX_INITIALIZER,
    PTHREAD_COND_INITIALIZER,
};

static void capture_request_started(void *request) {
    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    if(capture_relay.relay_started && !capture_relay.stopping) {
        capture_relay.request_generation++;
        capture_relay.active_request = request;
        capture_relay.cancel_requested = false;
        capture_relay.recovery_reported = false;
        capture_relay.recovery_pending = false;
        cant_fail_ret(pthread_cond_broadcast(&capture_relay.cond));
    }
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
}

static void capture_request_finished(void *request) {
    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    if(capture_relay.active_request == request) {
        capture_relay.active_request = nullptr;
        capture_relay.cancel_requested = true;
        capture_relay.request_generation++;
        capture_relay.recovery_pending = false;
        cant_fail_ret(pthread_cond_broadcast(&capture_relay.cond));
    }
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
}

static void capture_request_cancelled(void *request) {
    capture_request_finished(request);
}

static void capture_thread_lifecycle(struct winmodule *module,
                                     void *start_proc, void *start_param,
                                     void *thread_cookie, bool created) {
    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));

    if(!capture_relay.relay_started || capture_relay.stopping ||
       module != capture_relay.module ||
       start_proc != capture_relay.capture_proc) {
        cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
        return;
    }

    if(created) {
        capture_worker_observation *worker =
            static_cast<capture_worker_observation*>(
                malloc(sizeof(*worker)));
        if(!worker) {
            log_error("Could not track Synaptics capture worker lifecycle");
            cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
            return;
        }

        worker->cookie = thread_cookie;
        worker->request_generation = capture_relay.request_generation;
        worker->worker_generation = ++capture_relay.worker_generation;
        worker->next = capture_relay.workers;
        capture_relay.workers = worker;

        /* A newer worker supersedes any delayed recovery for an older one. */
        capture_relay.recovery_pending = false;
        cant_fail_ret(pthread_cond_broadcast(&capture_relay.cond));
        cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
        return;
    }

    capture_worker_observation **link = &capture_relay.workers;
    capture_worker_observation *worker = nullptr;
    while(*link) {
        if((*link)->cookie == thread_cookie) {
            worker = *link;
            *link = worker->next;
            break;
        }
        link = &(*link)->next;
    }

    if(worker && capture_relay.active_request &&
       !capture_relay.cancel_requested &&
       worker->request_generation == capture_relay.request_generation &&
       worker->worker_generation == capture_relay.worker_generation) {
        capture_relay.recovery_pending = true;
        capture_relay.recovery_request_generation =
            worker->request_generation;
        capture_relay.recovery_worker_generation =
            worker->worker_generation;
        cant_fail_ret(pthread_cond_broadcast(&capture_relay.cond));
    }

    free(worker);
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
}

static bool capture_relay_snapshot_valid(uint64_t request_generation,
                                         uint64_t worker_generation) {
    return capture_relay.relay_started && !capture_relay.stopping &&
           capture_relay.active_request &&
           !capture_relay.cancel_requested &&
           capture_relay.request_generation == request_generation &&
           capture_relay.worker_generation == worker_generation;
}

static void *capture_relay_main(void *) {
    winmodule_set_cur(capture_relay.module);
    win_init_tib();

    for(;;) {
        cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
        while(!capture_relay.stopping && !capture_relay.recovery_pending)
            cant_fail_ret(pthread_cond_wait(&capture_relay.cond,
                                            &capture_relay.lock));

        if(capture_relay.stopping) {
            cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
            return nullptr;
        }

        uint64_t request_generation =
            capture_relay.recovery_request_generation;
        uint64_t worker_generation =
            capture_relay.recovery_worker_generation;
        capture_relay.recovery_pending = false;
        cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));

        /* The lifecycle callback runs just before the pthread wrapper exits.
         * Give it time to become fully joinable before invoking OnCancel from
         * this separate thread. */
        usleep(SYNA_CAPTURE_RECOVERY_DELAY_US);

        for(;;) {
            bool report_recovery = false;
            cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
            bool valid = capture_relay_snapshot_valid(request_generation,
                                                       worker_generation);
            if(valid && !capture_relay.recovery_reported) {
                capture_relay.recovery_reported = true;
                report_recovery = true;
            }
            cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
            if(!valid) break;

            if(report_recovery) {
                log_warn("Vendor capture worker exited with its WUDF1 request "
                         "pending; cancelling it so a fresh capture can start");
            }

            winmodule_set_cur(capture_relay.module);
            bool cancelled = capture_request_recover(request_generation,
                                                      worker_generation);

            if(cancelled) {
                log_debug("Cancelled stalled WUDF1 capture request");
                break;
            }

            /* MarkCancelable can race a very short-lived worker.  Retry only
             * while this exact request and worker generation remain current. */
            usleep(SYNA_CAPTURE_RECOVERY_DELAY_US);
        }
    }
}

static bool capture_relay_start(void) {
    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    capture_relay.stopping = false;
    capture_relay.relay_started = true;
    capture_relay.module = &tudor_driver_dll->module;
    capture_relay.capture_proc = static_cast<uint8_t*>(
        tudor_driver_dll->image.base_addr) + SYNA_CAPTURE_THREAD_RVA;
    capture_relay.active_request = nullptr;
    capture_relay.cancel_requested = false;
    capture_relay.recovery_pending = false;
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));

    int err = pthread_create(&capture_relay.relay_thread, nullptr,
                             capture_relay_main, nullptr);
    if(err) {
        log_error("Could not start Synaptics capture relay: %s",
                  strerror(err));
        cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
        capture_relay.relay_started = false;
        capture_relay.stopping = true;
        cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
        return false;
    }

    win_set_thread_lifecycle_observer(capture_thread_lifecycle);
    return true;
}

static void capture_relay_stop(void) {
    /* Prevent new callbacks first.  A callback which already loaded the old
     * pointer still serializes on this mutex and observes stopping. */
    win_set_thread_lifecycle_observer(nullptr);

    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    bool join_relay = capture_relay.relay_started;
    capture_relay.stopping = true;
    capture_relay.active_request = nullptr;
    capture_relay.cancel_requested = true;
    capture_relay.request_generation++;
    capture_relay.recovery_pending = false;
    cant_fail_ret(pthread_cond_broadcast(&capture_relay.cond));
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));

    if(join_relay)
        cant_fail_ret(pthread_join(capture_relay.relay_thread, nullptr));

    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    capture_relay.relay_started = false;
    while(capture_relay.workers) {
        capture_worker_observation *worker = capture_relay.workers;
        capture_relay.workers = worker->next;
        free(worker);
    }
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
}

static enum cryptbridge_registry_load_result
load_crypto_registry(void *, void **data, size_t *data_size) {
    *data = nullptr;
    *data_size = 0;
    if(!tudor_get_state_fnc) return CRYPTBRIDGE_REGISTRY_LOAD_ERROR;

    enum tudor_state_value_type type;
    if(!tudor_get_state_fnc("CryptoRegistry", &type, data, data_size))
        return CRYPTBRIDGE_REGISTRY_LOAD_NOT_FOUND;
    if(type != TUDOR_STATE_VALUE_BLOB) {
        log_error("CryptoRegistry device state has an invalid value type");
        free(*data);
        *data = nullptr;
        *data_size = 0;
        return CRYPTBRIDGE_REGISTRY_LOAD_ERROR;
    }
    return CRYPTBRIDGE_REGISTRY_LOAD_FOUND;
}

static bool store_crypto_registry(void *, const void *data,
                                  size_t data_size) {
    if(!tudor_set_state_fnc) return false;
    tudor_set_state_fnc("CryptoRegistry", TUDOR_STATE_VALUE_BLOB,
                        data, data_size);
    return true;
}

static enum cryptbridge_identity_load_result
load_secure_channel_identity(void *, void **data, size_t *data_size) {
    *data = nullptr;
    *data_size = 0;
    if(!tudor_get_state_fnc) return CRYPTBRIDGE_IDENTITY_LOAD_ERROR;

    enum tudor_state_value_type type;
    if(!tudor_get_state_fnc("SecureChannelIdentity", &type, data,
                            data_size))
        return CRYPTBRIDGE_IDENTITY_LOAD_NOT_FOUND;
    if(type != TUDOR_STATE_VALUE_BLOB) {
        log_error("SecureChannelIdentity device state has an invalid value type");
        free(*data);
        *data = nullptr;
        *data_size = 0;
        return CRYPTBRIDGE_IDENTITY_LOAD_ERROR;
    }
    return CRYPTBRIDGE_IDENTITY_LOAD_FOUND;
}

static bool store_secure_channel_identity(void *, const void *data,
                                          size_t data_size) {
    if(!tudor_set_state_fnc) return false;
    tudor_set_state_fnc("SecureChannelIdentity", TUDOR_STATE_VALUE_BLOB,
                        data, data_size);
    return true;
}

static void configure_crypto_state(void) {
    if(tudor_get_state_fnc || tudor_set_state_fnc) {
        cryptbridge_registry_set_state_callbacks(
            load_crypto_registry, store_crypto_registry, nullptr);
        cryptbridge_identity_set_state_callbacks(
            load_secure_channel_identity, store_secure_channel_identity,
            nullptr);
    } else {
        cryptbridge_registry_set_state_callbacks(nullptr, nullptr, nullptr);
        cryptbridge_identity_set_state_callbacks(nullptr, nullptr, nullptr);
    }
}

extern uint8_t _binary_libtudor_synaAdvAdapter_dll_start, _binary_libtudor_synaAdvAdapter_dll_end;
extern uint8_t _binary_libtudor_synaWudfBioUsb_dll_start, _binary_libtudor_synaWudfBioUsb_dll_end;

#define NUM_WINDRV_DLLS 2
struct windrv_dll tudor_windrv_dlls[] = {
    {
        .module = {
            .name = "synaWudfBioUsb.dll",
            .cmdline = "synaWudfBioUsb.dll",
            .environ = (const char*[]) { NULL }
        },
        .pe_image = &_binary_libtudor_synaWudfBioUsb_dll_start, .pe_image_end = &_binary_libtudor_synaWudfBioUsb_dll_end,
        .is_adapter = false, .is_driver = true
    },
    {
        .module = {
            .name = "synaAdvAdapter.dll",
            .cmdline = "synaAdvAdapter.dll",
            .environ = (const char*[]) { NULL }
        },
        .pe_image = &_binary_libtudor_synaAdvAdapter_dll_start, .pe_image_end = &_binary_libtudor_synaAdvAdapter_dll_end,
        .is_adapter = true, .is_driver = false
    }
};



#define DEFINE_GUID11(name, a, b, c, d, e, f, g, h, i, j, k) \
    static const GUID_DLL name = { \
        (a), (b), (c), \
        {(d), (e), (f), (g), (h), (i), (j), (k)} \
    }

// DEFINE_GUID11(SYNA_CLSID, 0x96710705, 0xb080, 0x4b29, 0xa3, 0xec, 0xb1, 0x69, 0x35, 0xae, 0x66, 0x3a);
DEFINE_GUID11(SYNA_CLSID, 0x96710705, 0xb080, 0x4b29, 0xa3, 0xec, 0xb1, 0x69, 0x35, 0xae, 0x66, 0x3a);


// 1BEC7499-8881-4F2B-B01C-A1A907304AFC
DEFINE_GUID11(IID_IDriverEntry, 0x1BEC7499, 0x8881, 0x4F2B, 0xB0, 0x1C, 0xA1, 0xA9, 0x07, 0x30, 0x4A, 0xFC);

DEFINE_GUID11(IID_IQueueCallbackDeviceIoControl, 0xC5411408, 0x0F1E, 0x4ed6, 0xA4, 0x12, 0x36, 0xDD, 0x15, 0xEE, 0xE7, 0x07);

DEFINE_GUID11(IID_IPnpCallbackHardware, 0x51433BD3, 0xC7C1, 0x4bd8, 0xB4, 0xC1, 0xAB, 0x1E, 0x03, 0x46, 0x26, 0xCC);

DEFINE_GUID11(IID_IPnpCallback, 0x27c32374, 0xcc45, 0x4840, 0x85, 0x7e, 0x8e, 0x5e, 0xf7, 0xc0, 0xeb, 0xff);

DEFINE_GUID11(IID_IWDFPropertyStoreFactory, 0x45BE7E06, 0x9B65, 0x434d, 0xA7, 0xD6, 0x95, 0x72, 0xD7, 0xF7, 0x3D, 0x53);

DEFINE_GUID11(IID_IUnknown, 0x00000000, 0x0000, 0x0000, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);
// DEFINE_GUID11(IID_IUnknown, 0x00000001, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

DEFINE_GUID11( GUID_DEVINTERFACE_BIOMETRIC_READER,
             0xe2b5183a, 0x99ea, 0x4cc3, 0xad, 0x6b, 0x80, 0xca, 0x8d, 0x71, 0x5b, 0x80);

void print_guid(const GUID_DLL* g) {
    if (!g) {
        printf("NULL GUID pointer\n");
        return;
    }
    printf("{%08lX-%04hX-%04hX-", 
           g->Data1, g->Data2, g->Data3);
    // Print first 2 bytes of Data4
    printf("%02hhX%02hhX-", g->Data4[0], g->Data4[1]);
    // Print last 6 bytes of Data4
    printf("%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
           g->Data4[2], g->Data4[3], g->Data4[4], 
           g->Data4[5], g->Data4[6], g->Data4[7]);
    printf("\r\n");
}

bool StringFromIID(REFIID rclsid, LPOLESTR *lplpsz) {
    if (!rclsid || !lplpsz) {
        return false;
    }

    // Windows uses wide strings (OLESTR = wchar_t*)
    // Allocate enough space: 38 chars + 2 (braces + null) = 39
    // Wide chars, so malloc sizeof(wchar_t).
    const int len = 39;
    wchar_t *buf = (wchar_t *)malloc(sizeof(wchar_t) * (len + 1));
    if (!buf) {
        return false;
    }

    swprintf(buf, len + 1,
             L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
             rclsid->Data1,
             rclsid->Data2,
             rclsid->Data3,
             rclsid->Data4[0], rclsid->Data4[1],
             rclsid->Data4[2], rclsid->Data4[3],
             rclsid->Data4[4], rclsid->Data4[5],
             rclsid->Data4[6], rclsid->Data4[7]);

    *lplpsz = buf;
    return true;
}

void* CoTaskMemAlloc(size_t cb)
{
    return malloc(cb);
}

void CoTaskMemFree(void* pv)
{
    free(pv);
}


bool IsEqualIID(REFIID riid1, REFIID riid2) {
    if (!riid1 || !riid2) return false;
    return memcmp(riid1, riid2, sizeof(GUID)) == 0;
}

std::string utf16le_to_utf8(const char16_t* input) {
    if (!input) return {};

    // Wrap raw pointer into std::u16string
    std::u16string u16str(input);

    // Convert UTF-16 to UTF-8
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;
    return convert.to_bytes(u16str);
}

char16_t* utf8_to_utf16le(const std::string& input) {
    // Converter from UTF-8 to UTF-16
    std::wstring_convert<std::codecvt_utf8_utf16<char16_t>, char16_t> convert;

    std::u16string u16str = convert.from_bytes(input);

    // Allocate new buffer (+1 for null terminator)
    char16_t* buffer = new char16_t[u16str.size() + 1];

    // Copy content
    std::copy(u16str.begin(), u16str.end(), buffer);
    buffer[u16str.size()] = u'\0'; // null terminator

    return buffer; // caller must delete[]
}

static std::string tudor_state_path(const std::string& name,
                                    const char *extension) {
    const char *state_dir = getenv("SYNA_TUDOR_STATE_DIR");
    if(state_dir && state_dir[0])
        return std::string(state_dir) + "/" + name + extension;
    return name + extension;
}

static bool tudor_state_name_valid(const std::string& name) {
    if(name.empty() || name.size() > 64) return false;
    for(unsigned char c : name) {
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9')))
            return false;
    }
    return true;
}

static bool tudor_load_state_value(const std::string& name,
                                   enum tudor_state_value_type *type,
                                   std::vector<uint8_t> *data) {
    if(!tudor_state_name_valid(name)) {
        log_error("Rejected invalid device-state property name '%s'",
                  name.c_str());
        return false;
    }

    if(tudor_get_state_fnc) {
        void *raw_data = nullptr;
        size_t raw_size = 0;
        if(!tudor_get_state_fnc(name.c_str(), type, &raw_data, &raw_size))
            return false;
        if(raw_size && !raw_data) {
            log_error("State callback returned a null buffer for '%s'",
                      name.c_str());
            return false;
        }
        if(raw_size) {
            const uint8_t *bytes = static_cast<const uint8_t*>(raw_data);
            data->assign(bytes, bytes + raw_size);
        } else {
            data->clear();
        }
        free(raw_data);
        return true;
    }

    std::ifstream blob_input(tudor_state_path(name, ".blob"),
                             std::ios::binary);
    if(blob_input) {
        *type = TUDOR_STATE_VALUE_BLOB;
        data->assign(std::istreambuf_iterator<char>(blob_input),
                     std::istreambuf_iterator<char>());
        return true;
    }

    std::ifstream uint_input(tudor_state_path(name, ".uint"));
    if(uint_input) {
        uint32_t value;
        if(!(uint_input >> value)) {
            log_error("Invalid uint device-state value for '%s'",
                      name.c_str());
            return false;
        }
        *type = TUDOR_STATE_VALUE_UINT32;
        data->resize(sizeof(value));
        memcpy(data->data(), &value, sizeof(value));
        return true;
    }

    std::ifstream bool_input(tudor_state_path(name, ".bool"),
                             std::ios::binary);
    if(bool_input) {
        std::string text(std::istreambuf_iterator<char>(bool_input), {});
        if(text != "0\n" && text != "1\n") {
            log_error("Invalid bool device-state value for '%s'",
                      name.c_str());
            return false;
        }
        *type = TUDOR_STATE_VALUE_BOOL;
        data->assign(1, static_cast<uint8_t>(text[0] - '0'));
        return true;
    }

    return false;
}

static void tudor_store_state_value(const std::string& name,
                                    enum tudor_state_value_type type,
                                    const void *data, size_t data_size) {
    if(!tudor_state_name_valid(name)) {
        log_error("Rejected invalid device-state property name '%s'",
                  name.c_str());
        return;
    }

    if(tudor_set_state_fnc) {
        tudor_set_state_fnc(name.c_str(), type, data, data_size);
        return;
    }

    if(type == TUDOR_STATE_VALUE_UINT32 && data_size == sizeof(uint32_t)) {
        uint32_t value;
        memcpy(&value, data, sizeof(value));
        std::ofstream output(tudor_state_path(name, ".uint"));
        output << value << std::endl;
    } else if(type == TUDOR_STATE_VALUE_BLOB) {
        std::ofstream output(tudor_state_path(name, ".blob"),
                             std::ios::binary);
        if(data_size) {
            const char *bytes = static_cast<const char*>(data);
            output.write(bytes, data_size);
        }
    } else if(type == TUDOR_STATE_VALUE_BOOL && data &&
              data_size == sizeof(uint8_t) &&
              *static_cast<const uint8_t*>(data) <= 1) {
        std::ofstream output(tudor_state_path(name, ".bool"),
                             std::ios::binary);
        const char text[] = {
            *static_cast<const uint8_t*>(data) ? '1' : '0', '\n'
        };
        output.write(text, sizeof(text));
    }
}

struct IObjectCleanup;

class MyDevInit : public IWDFDeviceInitialize {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            printf("QueryInterface\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("Release\r\n");
            return 0;
        }

    public:
        virtual void STDMETHODCALLTYPE SetFilter( void) {
            printf("SetFilter\r\n");
        }
        
        virtual void STDMETHODCALLTYPE SetLockingConstraint( 
            /* [annotation][in] */ 
            _In_  WDF_CALLBACK_CONSTRAINT LockType) {
            printf("SetLockingConstraint: %d\r\n", (int)LockType);
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
            /* [annotation][unique][in] */ 
            _In_opt_  PCWSTR pcwszServiceName,
            /* [annotation][in] */ 
            _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
            /* [annotation][out] */ 
            _Out_  IWDFNamedPropertyStore **ppPropStore,
            /* [annotation][unique][out] */ 
            _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *pDisposition) {
            printf("RetrieveDevicePropertyStore\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE SetPowerPolicyOwnership( 
            /* [annotation][in] */ 
            _In_  BOOL fTrue) {
            printf("SetPowerPolicyOwnership\r\n");
        }
        
        virtual void STDMETHODCALLTYPE AutoForwardCreateCleanupClose( 
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE State) {
            printf("AutoForwardCreateCleanupClose\r\n");
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId( 
            /* [annotation][unique][out][string] */ 
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwSizeInChars) {
            printf("RetrieveDeviceInstanceId\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE SetPnpCapability( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_CAPABILITY Capability,
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE Value) {
            printf("SetPnpCapability\r\n");
        }
        
        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpCapability( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_CAPABILITY Capability) {
            printf("GetPnpCapability\r\n");
            return WdfFalse;
        }
};


struct MyNamedPropertyStore : public IWDFNamedPropertyStore2 {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            //printf("MyMem::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  IObjectCleanup *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE GetNamedValue(  // 24
            /* [annotation][string][in] */ 
            _In_  LPCWSTR pszName,
            /* [annotation][out] */ 
            _Out_  PROPVARIANT *pv){
            std::string fname = utf16le_to_utf8(pszName);
            std::cout << "=====================================\n"
                      << "GetNamedValue " << fname << '\n'
                      << "=====================================" << std::endl;

            memset(pv, 0, sizeof(*pv));

            enum tudor_state_value_type type;
            std::vector<uint8_t> data;
            if(!tudor_load_state_value(fname, &type, &data)) return 0;

            /* The vendor writes a zero-length calibration blob while a fresh
             * calibration is in progress.  If that intermediate value
             * survives a restart, Windows reports it as an empty property so
             * the driver calibrates again.  PairingData is different: its
             * zero-length blob is an intentional presence marker. */
            if(fname == "CalibrationData" &&
               type == TUDOR_STATE_VALUE_BLOB && data.empty()) {
                std::cout << "Ignoring incomplete empty CalibrationData"
                          << std::endl;
                return 0;
            }

            if(type == TUDOR_STATE_VALUE_UINT32 &&
               data.size() == sizeof(pv->uintVal)) {
                pv->vt = VT_UINT;
                memcpy(&pv->uintVal, data.data(), sizeof(pv->uintVal));
                std::cout << "Restored uint " << fname << " = "
                          << pv->uintVal << std::endl;
            } else if(type == TUDOR_STATE_VALUE_BOOL && data.size() == 1 &&
                      data[0] <= 1) {
                pv->vt = VT_BOOL;
                pv->boolVal = data[0] ? -1 : 0;
                std::cout << "Restored bool " << fname << " = "
                          << static_cast<unsigned>(data[0]) << std::endl;
            } else if(type == TUDOR_STATE_VALUE_BLOB) {
                pv->vt = VT_BLOB;
                pv->blob.cbSize = data.size();
                pv->blob.pBlobData = nullptr;
                if(!data.empty()) {
                    pv->blob.pBlobData =
                        (BYTE*) CoTaskMemAlloc(pv->blob.cbSize);
                    std::copy(data.begin(), data.end(), pv->blob.pBlobData);
                }
                std::cout << "Restored " << data.size() << " bytes of "
                          << fname << std::endl;
            } else {
                log_error("Invalid stored type or size for device-state "
                          "property '%s'", fname.c_str());
            }
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE SetNamedValue(  // 32
            /* [annotation][string][in] */ 
            _In_  LPCWSTR pszName,
            /* [annotation][in] */ 
            _In_  const PROPVARIANT *pv){
            //wchar_t *buf = L"<error>";
            //LONG num = 118;
            //PropVariantToInt32(*pv, &num);
            //PropVariantToStringAlloc(*pv, &buf);

            std::string str_u8 = utf16le_to_utf8(pszName);
            std::cout << "=====================================\n"
                      << "SetNamedValue " << str_u8 << '=' << pv->vt << '\n'
                      << "=====================================" << std::endl;
            ownership_failure_observe(str_u8, pv);
            switch(pv->vt) {
                case VT_BOOL: {
                    const uint8_t value = pv->boolVal != 0;
                    tudor_store_state_value(str_u8,
                                            TUDOR_STATE_VALUE_BOOL,
                                            &value, sizeof(value));
                    printf("VT_BOOL: %u\n", value);
                    break;
                }
                case VT_I1:
                    printf("VT_I1: %d\n", pv->cVal);
                    break;
                case VT_UINT:
                    tudor_store_state_value(str_u8,
                                            TUDOR_STATE_VALUE_UINT32,
                                            &pv->uintVal,
                                            sizeof(pv->uintVal));
                    printf("VT_UINT: %d\n", pv->uintVal);
                    break;
                case VT_BLOB:
                    tudor_store_state_value(str_u8,
                                            TUDOR_STATE_VALUE_BLOB,
                                            pv->blob.pBlobData,
                                            pv->blob.cbSize);
                    printf("Stored blob value: %u bytes\n",
                           pv->blob.cbSize);
                    break;
            }
            std::wcout << L"=====================================" << std::endl;
            //CoTaskMemFree(buf);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE GetNameCount( 
            /* [annotation][out] */ 
            _Out_  DWORD *pdwCount){
            std::wcout << L"GetNameCount " << std::endl;
            *pdwCount = 0;
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE GetNameAt( 
            /* [annotation][in] */ 
            _In_  DWORD iProp,
            /* [annotation][string][out] */ 
            _Out_  PWSTR *ppwszName){
            std::wcout << L"GetNameAt " << iProp << std::endl;
            *ppwszName = L"";
            return 0;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE DeleteNamedValue( 
            /* [annotation][string][in] */ 
            _In_  LPCWSTR pwszName){
            std::cout << "DeleteNamedValue " << utf16le_to_utf8(pwszName) << std::endl;
            return 0;
        }

};

struct MyMem : public IWDFMemory {
    public:
        MyMem(void *b, SIZE_T s) {
            buf = b;
            size = s;
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyMem::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            //printf("MyMem::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE CopyFromMemory( 
            /* [annotation][in] */ 
            _In_  IWDFMemory *Source,
            /* [annotation][unique][in] */ 
            _In_opt_  PWDFMEMORY_OFFSET SourceOffset){
            printf("CopyFromMemory\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CopyToBuffer( 
            /* [annotation][in] */ 
            _In_  ULONG_PTR SourceOffset,
            /* [annotation][size_is][in] */ 
             void *TargetBuffer,
            /* [annotation][in] */ 
            _In_  SIZE_T NumOfBytesToCopyTo){
            printf("CopyToBuffer\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CopyFromBuffer( 
            /* [annotation][in] */ 
            _In_  ULONG_PTR DestOffset,
            /* [annotation][size_is][in] */ 
            void *SourceBuffer,
            /* [annotation][in] */ 
            _In_  SIZE_T NumOfBytesToCopyFrom){
            printf("CopyFromBuffer\r\n");
            return 0;
        }

        
        virtual SIZE_T STDMETHODCALLTYPE GetSize( void){
            printf("GetSize\r\n");
            return size;
        }

        
        virtual void *STDMETHODCALLTYPE GetDataBuffer( 
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *BufferSize){
            if(BufferSize) {
                *BufferSize = size;
            }
            // Sleep(5000);
            return buf;
        }

        
        virtual void STDMETHODCALLTYPE SetBuffer( 
            /* [annotation][size_is][in] */ 
            void *Buffer,
            /* [annotation][in] */ 
            _In_  SIZE_T BufferSize){
            printf("SetBuffer\r\n");
            buf = Buffer;
            size = BufferSize;
        }

    void * buf;
    SIZE_T size;
};

struct MyRequest final : public IWDFIoRequest {
    public:
        static constexpr uintptr_t CANCEL_CALLBACK_CLAIMED = 1;

        MyRequest(WDF_REQUEST_TYPE t, ULONG c, void *out, SIZE_T out_size,
                  void *in, SIZE_T in_size, OVERLAPPED *overlapped)
            : reqType(t), ctl(c), complete(false), informationSize(0),
              completionStatus(STATUS_PENDING), cancelState(0),
              nativeRefs(1), ovlp(overlapped),
              outMem(out, out_size), inMem(in, in_size) {}

        WDF_REQUEST_TYPE reqType;
        ULONG ctl;
        std::atomic<bool> complete;
        std::atomic<SIZE_T> informationSize;
        std::atomic<HRESULT> completionStatus;
        /* Zero means unmarked, a callback pointer means cancelable, and the
         * sentinel means cancellation atomically claimed that callback. */
        std::atomic<uintptr_t> cancelState;
        std::atomic<unsigned int> nativeRefs;
        OVERLAPPED *ovlp;
        MyMem outMem, inMem;

        void retain_native() {
            nativeRefs.fetch_add(1, std::memory_order_relaxed);
        }

        void release_native() {
            if(nativeRefs.fetch_sub(1, std::memory_order_acq_rel) == 1)
                delete this;
        }

        void clear_cancel_callback() {
            uintptr_t state = cancelState.load(std::memory_order_acquire);
            while(state > CANCEL_CALLBACK_CLAIMED &&
                  !cancelState.compare_exchange_weak(
                      state, 0, std::memory_order_acq_rel,
                      std::memory_order_acquire)) {}
        }

        IRequestCallbackCancel *claim_cancel_callback() {
            uintptr_t state = cancelState.load(std::memory_order_acquire);
            while(state > CANCEL_CALLBACK_CLAIMED) {
                if(cancelState.compare_exchange_weak(
                       state, CANCEL_CALLBACK_CLAIMED,
                       std::memory_order_acq_rel,
                       std::memory_order_acquire)) {
                    return reinterpret_cast<IRequestCallbackCancel*>(state);
                }
            }
            return nullptr;
        }

        void finish(HRESULT status, SIZE_T information) {
            /* Completion callbacks may clean up the request on another
             * thread before winio_complete_overlapped returns. */
            retain_native();
            clear_cancel_callback();
            completionStatus.store(status, std::memory_order_relaxed);
            if(complete.exchange(true, std::memory_order_acq_rel)) {
                log_warn("Ignoring duplicate WUDF1 request completion [code 0x%x status 0x%x]",
                         ctl, (unsigned int) status);
                release_native();
                return;
            }

            if(ctl == SYNA_CAPTURE_IOCTL)
                capture_request_finished(this);

            /* The 0081 performs identification against its database on the
             * sensor.  Record just the documented result header so we can
             * distinguish an on-sensor no-match from a later engine/storage
             * translation failure without logging biometric payload data. */
            if(ctl == 0x442004 && status == ERROR_SUCCESS &&
               information >= 0x54 && outMem.buf) {
                const BYTE *result = static_cast<const BYTE*>(outMem.buf);
                DWORD identity_type, identify_status;
                memcpy(&identity_type, result, sizeof(identity_type));
                memcpy(&identify_status, result + 0x50,
                       sizeof(identify_status));
                printf("[WUDF1-IDENTIFY] identity-type=%u subtype=0x%02x "
                       "status=0x%08x size=%zu\r\n",
                       identity_type, result[0x4c], identify_status,
                       information);
            }

            if(ovlp)
                winio_complete_overlapped(ovlp, (NTSTATUS) status,
                                          information);
            release_native();
        }

        bool cancel() {
            retain_native();
            IRequestCallbackCancel *callback = claim_cancel_callback();
            if(!callback) {
                release_native();
                return false;
            }

            if(ctl == SYNA_CAPTURE_IOCTL)
                capture_request_cancelled(this);
            callback->OnCancel(this);
            release_native();
            return true;
        }
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyRequest::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyRequest::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE CompleteWithInformation( 
            /* [annotation][in] */ 
            _In_  HRESULT CompletionStatus,
            /* [annotation][in] */ 
            _In_  SIZE_T Information){
            printf("CompleteWithInformation: status=%lx size=%zu\r\n",
                   (unsigned long) CompletionStatus, Information);
            informationSize.store(Information, std::memory_order_relaxed);
            finish(CompletionStatus, Information);
        }

        
        virtual void STDMETHODCALLTYPE SetInformation( 
            /* [annotation][in] */ 
            _In_  ULONG_PTR Information){
	        TRACE_PRINTF("SetInformation size=%lld\r\n", Information);
            informationSize.store((SIZE_T) Information, std::memory_order_relaxed);
        }

        
        virtual void STDMETHODCALLTYPE Complete( 
            /* [annotation][in] */ 
            _In_  HRESULT CompletionStatus){
	        TRACE_PRINTF("Complete: %lx\r\n", (unsigned long)CompletionStatus);
            finish(CompletionStatus,
                   informationSize.load(std::memory_order_relaxed));
        }

        
        virtual void STDMETHODCALLTYPE SetCompletionCallback( 
            /* [annotation][in] */ 
            _In_  void *pCompletionCallback,
            /* [annotation][unique][in] */ 
            _In_opt_  void *pContext){
            printf("SetCompletionCallback\r\n");
        }

        
        virtual WDF_REQUEST_TYPE STDMETHODCALLTYPE GetType( void){
            printf("GetType\r\n");
            return reqType;
        }

        
        virtual void STDMETHODCALLTYPE GetCreateParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pOptions,
            /* [annotation][unique][out] */ 
            _Out_opt_  USHORT *pFileAttributes,
            /* [annotation][unique][out] */ 
            _Out_opt_  USHORT *pShareAccess){
            printf("GetCreateParameters\r\n");
        }

        
        virtual void STDMETHODCALLTYPE GetReadParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */ 
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pulKey){
            printf("GetReadParameters\r\n");
        }

        
        virtual void STDMETHODCALLTYPE GetWriteParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pSizeInBytes,
            /* [annotation][unique][out] */ 
            _Out_opt_  LONGLONG *pullOffset,
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pulKey){
            printf("GetWriteParameters\r\n");
        }

        
        virtual void STDMETHODCALLTYPE GetDeviceIoControlParameters( 
            /* [annotation][unique][out] */ 
            _Out_opt_  ULONG *pControlCode,
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pInBufferSize,
            /* [annotation][unique][out] */ 
            _Out_opt_  SIZE_T *pOutBufferSize){
            //printf("GetDeviceIoControlParameters %p %p %p\r\n", pControlCode, pInBufferSize, pOutBufferSize);
            *pControlCode = ctl;
            *pInBufferSize = inMem.size;
            *pOutBufferSize = outMem.size;
        }

        
        virtual void STDMETHODCALLTYPE GetOutputMemory( 
            /* [annotation][out] */ 
            _Out_  IWDFMemory **ppWdfMemory){
            *ppWdfMemory = &outMem;
            //printf("GetOutputMemory\r\n");
        }
        
        virtual void STDMETHODCALLTYPE GetInputMemory( 
            /* [annotation][out] */ 
            _Out_  IWDFMemory **ppWdfMemory){
            *ppWdfMemory = &inMem;
            // printf("GetInputMemory\r\n");
        }

        
        virtual void STDMETHODCALLTYPE MarkCancelable( 
            /* [annotation][in] */ 
            _In_  IRequestCallbackCancel *pCancelCallback){
	        TRACE_PRINTF("MarkCancelable\r\n");
            uintptr_t callback = reinterpret_cast<uintptr_t>(pCancelCallback);
            if(callback <= CANCEL_CALLBACK_CLAIMED) {
                log_error("Invalid WUDF1 cancellation callback pointer");
                abort();
            }
            uintptr_t expected = 0;
            if(!cancelState.compare_exchange_strong(
                   expected, callback, std::memory_order_release,
                   std::memory_order_acquire)) {
                log_warn("Ignoring WUDF1 MarkCancelable after cancellation "
                         "was already marked or claimed [code 0x%x]", ctl);
            }
        }

        virtual HRESULT STDMETHODCALLTYPE UnmarkCancelable( void){
	        TRACE_PRINTF("UnmarkCancelable\r\n");
            uintptr_t state = cancelState.load(std::memory_order_acquire);
            for(;;) {
                if(state == CANCEL_CALLBACK_CLAIMED)
                    return (HRESULT) 0x800703e3; /* HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED) */
                if(state == 0) return 0;
                if(cancelState.compare_exchange_weak(
                       state, 0, std::memory_order_acq_rel,
                       std::memory_order_acquire))
                    return 0;
            }
        }

        
        virtual BOOL STDMETHODCALLTYPE CancelSentRequest( void){
            printf("CancelSentRequest\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE ForwardToIoQueue( 
            /* [annotation][in] */ 
            _In_  IWDFIoQueue *pDestination){
            printf("ForwardToIoQueue\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE Send( 
            /* [annotation][in] */ 
            _In_  void *pIoTarget,
            /* [annotation][in] */ 
            _In_  ULONG Flags,
            /* [annotation][in] */ 
            _In_  LONGLONG Timeout){
            printf("Send\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetFileObject( 
            /* [annotation][out] */ 
            _Out_  void **ppFileObject){
            printf("GetFileObject\r\n");
        }

        
        virtual void STDMETHODCALLTYPE FormatUsingCurrentType( void){
            printf("FormatUsingCurrentType\r\n");
        }

        
        virtual ULONG STDMETHODCALLTYPE GetRequestorProcessId( void){
            printf("GetRequestorProcessId\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetIoQueue( 
            /* [annotation][out] */ 
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            printf("GetIoQueue\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE Impersonate( 
            /* [annotation][in] */ 
            _In_  SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
            /* [annotation][in] */ 
            _In_  void *pCallback,
            /* [annotation][unique][in] */ 
            _In_opt_  void *pvCallbackContext){
            printf("Impersonate\r\n");
            return 0;
        }

        
        virtual BOOL STDMETHODCALLTYPE IsFrom32BitProcess( void){
            printf("IsFrom32BitProcess\r\n");
            return 1;
        }

        
        virtual void STDMETHODCALLTYPE GetCompletionParams( 
            /* [annotation][out] */ 
            _Out_  IWDFRequestCompletionParams **ppCompletionParams){
            printf("GetCompletionParams\r\n");
        }

        
};

static bool capture_request_recover(uint64_t request_generation,
                                    uint64_t worker_generation) {
    MyRequest *request = nullptr;
    IRequestCallbackCancel *callback = nullptr;

    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    if(capture_relay_snapshot_valid(request_generation,
                                    worker_generation)) {
        request = static_cast<MyRequest*>(capture_relay.active_request);
        request->retain_native();
        callback = request->claim_cancel_callback();
        if(callback) {
            /* Commit the recovery before invoking vendor code.  A completion
             * callback can now start the next request without clearing it. */
            capture_relay.active_request = nullptr;
            capture_relay.cancel_requested = true;
            capture_relay.request_generation++;
            capture_relay.recovery_pending = false;
            cant_fail_ret(pthread_cond_broadcast(&capture_relay.cond));
        }
    }
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));

    if(!request) return false;
    if(!callback) {
        request->release_native();
        return false;
    }

    callback->OnCancel(request);
    request->release_native();
    return true;
}

#ifdef TUDOR_RECOVERY_TEST_HOOK
class RecoveryTestCancelCallback final : public IRequestCallbackCancel {
public:
    std::atomic<unsigned int> calls{0};

    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID, void **object) override {
        if(!object) return (HRESULT) 0x80070057u;
        *object = this;
        return ERROR_SUCCESS;
    }

    ULONG STDMETHODCALLTYPE AddRef(void) override { return 1; }
    ULONG STDMETHODCALLTYPE Release(void) override { return 1; }

    void STDMETHODCALLTYPE OnCancel(IWDFIoRequest *wdf_request) override {
        calls.fetch_add(1, std::memory_order_relaxed);
        MyRequest *request = static_cast<MyRequest*>(wdf_request);

        /* Model the strongest real ordering: OnCancel completes the request,
         * and its newly spawned completion callback drops the owning reference
         * before OnCancel itself returns.  The recovery pin must keep the
         * request alive until capture_request_recover is done with it. */
        request->Complete((HRESULT) 0x800703e3u);
        request->release_native();
    }
};

extern "C" __attribute__((visibility("hidden")))
int tudor_internal_test_capture_recovery(void) {
    RecoveryTestCancelCallback callback;
    MyRequest *request = new MyRequest(
        WdfRequestTypeOther, SYNA_CAPTURE_IOCTL,
        nullptr, 0, nullptr, 0, nullptr);
    request->MarkCancelable(&callback);

    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    if(capture_relay.relay_started) {
        cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));
        request->release_native();
        return 1;
    }
    capture_relay.relay_started = true;
    capture_relay.stopping = false;
    capture_relay.active_request = request;
    capture_relay.request_generation = 17;
    capture_relay.cancel_requested = false;
    capture_relay.recovery_reported = false;
    capture_relay.worker_generation = 23;
    capture_relay.recovery_pending = true;
    capture_relay.recovery_request_generation = 17;
    capture_relay.recovery_worker_generation = 23;
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));

    bool stale_request = capture_request_recover(16, 23);
    bool stale_worker = capture_request_recover(17, 22);
    bool recovered = capture_request_recover(17, 23);
    bool recovered_twice = capture_request_recover(17, 23);
    unsigned int callback_calls =
        callback.calls.load(std::memory_order_relaxed);

    cant_fail_ret(pthread_mutex_lock(&capture_relay.lock));
    capture_relay.relay_started = false;
    capture_relay.stopping = false;
    capture_relay.active_request = nullptr;
    capture_relay.cancel_requested = false;
    capture_relay.recovery_pending = false;
    cant_fail_ret(pthread_mutex_unlock(&capture_relay.lock));

    if(!recovered) request->release_native();
    if(stale_request) return 2;
    if(stale_worker) return 3;
    if(!recovered) return 4;
    if(recovered_twice) return 5;
    if(callback_calls != 1) return 6;
    return 0;
}

extern "C" __attribute__((visibility("hidden")))
int tudor_internal_test_ownership_failure_guard(void) {
    PROPVARIANT value = {};

    ownership_failure_reset();
    if(ownership_failure_observed() != OWNERSHIP_FAILURE_NOT_WRITTEN)
        return 1;

    value.vt = VT_UINT;
    value.uintVal = 4;
    ownership_failure_observe("OtherCounter", &value);
    if(ownership_failure_observed() != OWNERSHIP_FAILURE_NOT_WRITTEN)
        return 2;

    value.vt = VT_BOOL;
    ownership_failure_observe("SetOwnershipFailureCount", &value);
    if(ownership_failure_observed() != OWNERSHIP_FAILURE_NOT_WRITTEN)
        return 3;

    value.vt = VT_UINT;
    value.uintVal = 0;
    ownership_failure_observe("SetOwnershipFailureCount", &value);
    if(ownership_failure_observed() != 0) return 4;

    value.uintVal = 3;
    ownership_failure_observe("SetOwnershipFailureCount", &value);
    if(ownership_failure_observed() != 3) return 5;

    value.uintVal = 0;
    ownership_failure_observe("SetOwnershipFailureCount", &value);
    if(ownership_failure_observed() != 3) return 6;

    if(!ownership_failure_should_reject(false)) return 7;
    if(ownership_failure_should_reject(true)) return 8;

    ownership_failure_reset();
    if(ownership_failure_observed() != OWNERSHIP_FAILURE_NOT_WRITTEN)
        return 9;
    return 0;
}

static unsigned int ownership_marker_test_writes;
static bool ownership_marker_test_valid;
static uint8_t ownership_marker_test_values[4];
static uint64_t ownership_marker_test_observations[4];

static void ownership_marker_test_store(
    const char *name, enum tudor_state_value_type type,
    const void *data, size_t data_size) {
    if(ownership_marker_test_writes >= 4 ||
       strcmp(name, TUDOR_STATE_OWNERSHIP_FAILURE_DETECTED) != 0 ||
       type != TUDOR_STATE_VALUE_BOOL || data_size != sizeof(uint8_t) ||
       !data || *(const uint8_t*) data > 1) {
        ownership_marker_test_valid = false;
        return;
    }

    const unsigned int index = ownership_marker_test_writes++;
    ownership_marker_test_values[index] = *(const uint8_t*) data;
    ownership_marker_test_observations[index] =
        ownership_failure_observed();
}

extern "C" __attribute__((visibility("hidden")))
int tudor_internal_test_ownership_failure_marker(void) {
    auto previous_state_callback = tudor_set_state_fnc;
    tudor_set_state_fnc = ownership_marker_test_store;
    ownership_marker_test_writes = 0;
    ownership_marker_test_valid = true;

    PROPVARIANT value = {};
    value.vt = VT_UINT;
    value.uintVal = 3;
    ownership_failure_observe("SetOwnershipFailureCount", &value);

    int result = 0;
    ownership_failure_start_init(false);
    if(!ownership_marker_test_valid || ownership_marker_test_writes != 1 ||
       ownership_marker_test_values[0] != 0)
        result = 1;
    else if(ownership_marker_test_observations[0] != 3)
        result = 2;
    ownership_failure_reset();
    if(!result && ownership_failure_observed() !=
                  OWNERSHIP_FAILURE_NOT_WRITTEN)
        result = 3;

    value.uintVal = 2;
    ownership_failure_observe("SetOwnershipFailureCount", &value);
    if(!result && !ownership_failure_reject_init("marker test", false))
        result = 4;
    else if(!result &&
            (ownership_marker_test_writes != 2 ||
             ownership_marker_test_values[1] != 1))
        result = 5;

    unsigned int writes_before_maintenance = ownership_marker_test_writes;
    if(!result && ownership_failure_reject_init("marker test", true))
        result = 6;
    ownership_failure_start_init(true);
    if(!result &&
       ownership_marker_test_writes != writes_before_maintenance)
        result = 7;

    ownership_failure_record_prepare_status((HRESULT) 0x80004005u, false);
    if(!result &&
       ownership_marker_test_writes != writes_before_maintenance)
        result = 8;

    ownership_failure_record_prepare_status(
        SYNA_OWNERSHIP_FAILURE_CAP_STATUS, true);
    if(!result &&
       ownership_marker_test_writes != writes_before_maintenance)
        result = 9;

    ownership_failure_record_prepare_status(
        SYNA_OWNERSHIP_FAILURE_CAP_STATUS, false);
    if(!result &&
       (ownership_marker_test_writes != writes_before_maintenance + 1 ||
        ownership_marker_test_values[writes_before_maintenance] != 1))
        result = 10;

    tudor_set_state_fnc = previous_state_callback;
    ownership_failure_reset();
    return result;
}
#endif

struct MyPropertyStoreFactory : public IWDFPropertyStoreFactory {
public:
    virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
        LPOLESTR str;
        StringFromIID(riid, &str);
        std::wcout << L"MyPropertyStoreFactory::QueryInterface " << str << std::endl;
        *ppvObject = this;
        printf("ppvObject=%p\r\n", *ppvObject);
        return 0; 
    }
    virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
        printf("AddRef\r\n");
        return 0; 
    }
    virtual ULONG STDMETHODCALLTYPE Release(void) {
        printf("MyPropertyStoreFactory::Release\r\n");
        return 0;
    }

public:
    virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
        /* [annotation][in] */ 
        _In_  PWDF_PROPERTY_STORE_ROOT RootSpecifier,
        /* [annotation][in] */ 
        _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS Flags,
        /* [annotation][in] */ 
        _In_  DWORD DesiredAccess,
        /* [annotation][unique][in] */ 
        _In_opt_  PCWSTR SubkeyPath,
        /* [annotation][out] */ 
        _Out_  IWDFNamedPropertyStore2 **PropertyStore,
        /* [annotation][unique][out] */ 
        _Out_opt_  WDF_PROPERTY_STORE_DISPOSITION *Disposition){


        printf("RetrieveDevicePropertyStore\r\n");
        *PropertyStore = new MyNamedPropertyStore();
        return 0;
    }

};

struct MyQueue : public IWDFIoQueue {
    public:
        MyQueue(IUnknown *pCallbackInterface) {
            pCallbackInterface->AddRef();
            pCallbackInterface->QueryInterface(&IID_IQueueCallbackDeviceIoControl, (LPVOID*)&ioctl);
            printf("ioctl=%p\r\n", ioctl);
        }

        IQueueCallbackDeviceIoControl *ioctl = NULL;

    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyQueue::QueryInterface " << str << std::endl;
            *ppvObject = this;
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyQueue::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }
    public:
        virtual void STDMETHODCALLTYPE GetDevice( 
            /* [annotation][out] */ 
            _Out_  IWDFDevice **ppWdfDevice){
            printf("GetDevice\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching( 
            /* [annotation][in] */ 
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */ 
            _In_  BOOL Forward){
            printf("MyQueue::ConfigureRequestDispatching\r\n");
            return 0;
        }

        
        virtual WDF_IO_QUEUE_STATE STDMETHODCALLTYPE GetState( 
            /* [annotation][out] */ 
            _Out_  ULONG *pulNumOfRequestsInQueue,
            /* [annotation][out] */ 
            _Out_  ULONG *pulNumOfRequestsInDriver){
            printf("GetState\r\n");
            return (WDF_IO_QUEUE_STATE)(WdfIoQueueAcceptRequests | 
                    WdfIoQueueDispatchRequests | 
                    WdfIoQueueNoRequests | 
                    WdfIoQueueDriverNoRequests);
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequest( 
            /* [annotation][out] */ 
            _Out_  IWDFIoRequest **ppRequest){
            printf("RetrieveNextRequest\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveNextRequestByFileObject( 
            /* [annotation][in] */ 
            _In_  IWDFFile *pFile,
            /* [annotation][out] */ 
            _Out_  IWDFIoRequest **ppRequest){
            printf("RetrieveNextRequestByFileObject\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE Start( void){
            printf("Start\r\n");
        }

        
        virtual void STDMETHODCALLTYPE Stop( 
            /* [annotation][unique][in] */ 
            _In_opt_  IQueueCallbackStateChange *pStopComplete){
            printf("Stop\r\n");
        }

        
        virtual void STDMETHODCALLTYPE StopSynchronously( void){
            printf("StopSynchronously\r\n");
        }

        
        virtual void STDMETHODCALLTYPE Drain( 
            /* [annotation][unique][in] */ 
            _In_opt_  IQueueCallbackStateChange *pDrainComplete){
            printf("Drain\r\n");
        }

        
        virtual void STDMETHODCALLTYPE DrainSynchronously( void){
            printf("Drain\r\n");
        }

        
        virtual void STDMETHODCALLTYPE Purge( 
            /* [annotation][unique][in] */ 
            _In_opt_  IQueueCallbackStateChange *pPurgeComplete){
            printf("Purge\r\n");
        }

        
        virtual void STDMETHODCALLTYPE PurgeSynchronously( void){
            printf("Purge\r\n");
        }


};


MyQueue *myQueue = NULL;



struct MyDevice : public IWDFDevice3 {
    public:
        MyDevice(IUnknown *pCallbackInterface) {
            pCallbackInterface->AddRef();
            pCallbackInterface->QueryInterface(&IID_IPnpCallbackHardware, (LPVOID*)&pnphwcb);
            pCallbackInterface->QueryInterface(&IID_IPnpCallback, (LPVOID*)&pnpcb);
            printf("pnphwcb=%p pnpcb=%p\r\n", pnphwcb, pnpcb);
        }

        IPnpCallbackHardware *pnphwcb;
        IPnpCallback *pnpcb;
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            LPOLESTR str;
            StringFromIID(riid, &str);
            std::wcout << L"MyDevice::QueryInterface " << str << std::endl;

            if(IsEqualIID(riid, &IID_IWDFPropertyStoreFactory)) {
                printf("is IID_IWDFPropertyStoreFactory\r\n");
                *ppvObject = new MyPropertyStoreFactory();
            } else {
                printf("is IID_IWDFDevice3\r\n");
                *ppvObject = (IWDFDevice3*)this;
            }
            printf("ppvObject=%p\r\n", *ppvObject);
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyDevice::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE RetrieveDevicePropertyStore( 
            /* [annotation][unique][in] */ 
            _In_opt_  PCWSTR pcwszServiceName,
            /* [annotation][in] */ 
            _In_  WDF_PROPERTY_STORE_RETRIEVE_FLAGS  Flags,
            /* [annotation][out] */ 
            _Out_  IWDFNamedPropertyStore **ppPropStore,
            /* [annotation][unique][out] */ 
            WDF_PROPERTY_STORE_DISPOSITION* pDisposition){
            printf("RetrieveDevicePropertyStore\r\n");
            *ppPropStore = new MyNamedPropertyStore();
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDriver( 
            /* [annotation][out] */ 
            _Out_  IWDFDriver **ppWdfDriver){
            printf("GetDriver\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceInstanceId( 
            /* [annotation][unique][out][string] */ 
            _Out_opt_  PWSTR Buffer,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwSizeInChars){
            printf("RetrieveDeviceInstanceId\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDefaultIoTarget( 
            /* [annotation][out] */ 
            _Out_  IWDFIoTarget **ppWdfIoTarget){
            printf("GetDefaultIoTarget\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateWdfFile( 
            /* [annotation][string][unique][in] */ 
            _In_opt_  LPCWSTR pcwszFileName,
            /* [annotation][out] */ 
            _Out_  IWDFDriverCreatedFile **ppFile){
            printf("CreateWdfFile\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDefaultIoQueue( 
            /* [annotation][out] */ 
            _Out_  IWDFIoQueue **ppWdfIoQueue){
            printf("GetDefaultIoQueue\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateIoQueue( 
            /* [annotation][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][in] */ 
            _In_  BOOL bDefaultQueue,
            /* [annotation][in] */ 
            _In_  WDF_IO_QUEUE_DISPATCH_TYPE DispatchType,
            /* [annotation][in] */ 
            _In_  BOOL bPowerManaged,
            /* [annotation][in] */ 
            _In_  BOOL bAllowZeroLengthRequests,
            /* [annotation][out] */ 
            _Out_  IWDFIoQueue **ppIoQueue){
            printf("MyDevice::CreateIoQueue\r\n");
            *ppIoQueue = myQueue = new MyQueue(pCallbackInterface);
            printf("new queue=%p\r\n", *ppIoQueue);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateDeviceInterface( 
            /* [annotation][in] */ 
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][unique][string][in] */ 
            _In_opt_  PCWSTR pReferenceString){
            //printf("CreateDeviceInterface\r\n");
            LPOLESTR str;
            StringFromIID(pDeviceInterfaceGuid, &str);
            std::wcout << L"MyDevice::CreateDeviceInterface "
                        << str
                        << std::endl;
            fflush(stdout);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE AssignDeviceInterfaceState( 
            /* [annotation][in] */ 
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][unique][string][in] */ 
            _In_opt_  PCWSTR pReferenceString,
            /* [annotation][in] */ 
            _In_  BOOL Enable){
            //printf("AssignDeviceInterfaceState\r\n");
            LPOLESTR str;
            StringFromIID(pDeviceInterfaceGuid, &str);
            std::wcout << L"MyDevice::AssignDeviceInterfaceState "
                        << str
                        << L"="
                        << Enable
                        << std::endl;
            fflush(stdout);
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE RetrieveDeviceName( 
            /* [annotation][unique][out][string] */ 
            char16_t* pDeviceName,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwDeviceNameLength)


        {
            printf("RetrieveDeviceName %p %p %u\r\n", pDeviceName, pdwDeviceNameLength, *pdwDeviceNameLength );
            fflush(stdout);

            if (!pdwDeviceNameLength) {
                return -1;
            }
            static const char16_t name[] = u"C:\\usb.txt";

            // Required length (including null terminator)
            DWORD requiredLength = static_cast<DWORD>(std::char_traits<char16_t>::length(name) + 1);

            if (pDeviceName == nullptr) {
                // Caller only wants the size
                *pdwDeviceNameLength = requiredLength;
                return 0;
            }

            if (*pdwDeviceNameLength < requiredLength) {
                // Buffer too small
                *pdwDeviceNameLength = requiredLength;
                return -1;
            }

            memcpy(pDeviceName, name, requiredLength * sizeof(char16_t));
            *pdwDeviceNameLength = requiredLength;

            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE PostEvent( 
            /* [annotation][in] */ 
            _In_  REFGUID EventGuid,
            /* [annotation][in] */ 
            _In_  WDF_EVENT_TYPE EventType,
            /* [annotation][size_is][in] */ 
            BYTE *pbData,
            /* [annotation][in] */ 
            _In_  DWORD cbDataSize){
            printf("PostEvent\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE ConfigureRequestDispatching( 
            /* [annotation][in] */ 
            _In_  IWDFIoQueue *pQueue,
            /* [annotation][in] */ 
            _In_  WDF_REQUEST_TYPE RequestType,
            /* [annotation][in] */ 
            _In_  BOOL Forward){
            printf("MyDevice::ConfigureRequestDispatching\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE SetPnpState( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_STATE State,
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE Value){
            printf("SetPnpState\r\n");
        }

        
        virtual WDF_TRI_STATE STDMETHODCALLTYPE GetPnpState( 
            /* [annotation][in] */ 
            _In_  WDF_PNP_STATE State){
            printf("GetPnpState\r\n");
            return WdfFalse;
        }

        
        virtual void STDMETHODCALLTYPE CommitPnpState( void){
            printf("CommitPnpState\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateRequest( 
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  IWDFIoRequest **ppRequest){
            printf("CreateRequest\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLink( 
            /* [annotation][unique][string][in] */ 
            _In_  PCWSTR pSymbolicLink){
            printf("CreateSymbolicLink\r\n");
            return 0;
        }

    // Device2
        virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettings( 
            /* [annotation][in] */ 
            _In_  WDF_POWER_POLICY_S0_IDLE_CAPABILITIES IdleCaps,
            /* [annotation][in] */ 
            _In_  DEVICE_POWER_STATE DxState,
            /* [annotation][in] */ 
            _In_  ULONG IdleTimeout,
            /* [annotation][in] */ 
            _In_  WDF_POWER_POLICY_S0_IDLE_USER_CONTROL UserControlOfIdleSettings,
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE Enabled){
            printf("AssignS0IdleSettings\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE StopIdle( 
            /* [annotation][in] */ 
            _In_  BOOL WaitForD0){
	        TRACE_PRINTF("StopIdle\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE ResumeIdle( void){
            goIdle = 1;
	        TRACE_PRINTF("ResumeIdle\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateSymbolicLinkWithReferenceString( 
            /* [annotation][unique][string][in] */ 
            _In_  PCWSTR pSymbolicLink,
            /* [annotation][unique][string][in] */ 
            _In_opt_  PCWSTR pReferenceString){
            printf("CreateSymbolicLinkWithReferenceString\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE RegisterRemoteInterfaceNotification( 
            /* [annotation][in] */ 
            _In_  LPCGUID pDeviceInterfaceGuid,
            /* [annotation][in] */ 
            _In_  BOOL IncludeExistingInterfaces){
            printf("RegisterRemoteInterfaceNotification\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateRemoteInterface( 
            /* [annotation][in] */ 
            _In_  void *pRemoteInterfaceInit,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */ 
            _Out_  void **ppRemoteInterface){
            printf("CreateRemoteInterface\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateRemoteTarget( 
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  void **ppRemoteTarget){
            printf("CreateRemoteTarget\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE GetDeviceStackIoTypePreference( 
            /* [annotation][out] */ 
            _Out_  WDF_DEVICE_IO_TYPE *ReadWritePreference,
            /* [annotation][out] */ 
            _Out_  WDF_DEVICE_IO_TYPE *IoControlPreference){
            printf("GetDeviceStackIoTypePreference\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE AssignSxWakeSettings( 
            /* [annotation][in] */ 
            _In_  DEVICE_POWER_STATE DxState,
            /* [annotation][in] */ 
            _In_  WDF_POWER_POLICY_SX_WAKE_USER_CONTROL UserControlOfWakeSettings,
            /* [annotation][in] */ 
            _In_  WDF_TRI_STATE Enabled){
            printf("AssignSxWakeSettings\r\n");
            return 0;
        }

        
        virtual POWER_ACTION STDMETHODCALLTYPE GetSystemPowerAction( void){
            printf("GetSystemPowerAction\r\n");
            return PowerActionNone;
        }

    // Device3
    public:
        virtual HRESULT STDMETHODCALLTYPE MapIoSpace( 
            /* [annotation][in] */ 
            _In_  PHYSICAL_ADDRESS PhysicalAddress,
            /* [annotation][in] */ 
            _In_  SIZE_T NumberOfBytes,
            /* [annotation][in] */ 
            _In_  MEMORY_CACHING_TYPE CacheType,
            /* [annotation][out] */ 
            _Out_  void **pPseudoBaseAddress){
            printf("MapIoSpace\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE UnmapIoSpace( 
            /* [annotation][in] */ 
            _In_  void *PseudoBaseAddress,
            /* [annotation][in] */ 
            _In_  SIZE_T NumberOfBytes){
            printf("UnmapIoSpace\r\n");
        }

        
        virtual void *STDMETHODCALLTYPE GetHardwareRegisterMappedAddress( 
            /* [annotation][in] */ 
            _In_  void *PseudoBaseAddress){
            printf("GetHardwareRegisterMappedAddress\r\n");
            return 0;
        }

        
        virtual SIZE_T STDMETHODCALLTYPE ReadFromHardware( 
            /* [annotation][in] */ 
            _In_  WDF_DEVICE_HWACCESS_TARGET_TYPE Type,
            /* [annotation][in] */ 
            _In_  WDF_DEVICE_HWACCESS_TARGET_SIZE Size,
            /* [annotation][in] */ 
            _In_  void *Address,
            /* [annotation][out] */ 
            void *Buffer,
            /* [annotation][in] */ 
            _In_opt_  ULONG Count){
            printf("ReadFromHardware\r\n");
            return 0;
        }

        
        virtual void STDMETHODCALLTYPE WriteToHardware( 
            /* [annotation][in] */ 
            _In_  WDF_DEVICE_HWACCESS_TARGET_TYPE Type,
            /* [annotation][in] */ 
            _In_  WDF_DEVICE_HWACCESS_TARGET_SIZE Size,
            /* [annotation][in] */ 
            _In_  void *Address,
            /* [annotation][in] */ 
            _In_  SIZE_T Value,
            /* [annotation][in] */ 
            void *Buffer,
            /* [annotation][in] */ 
            _In_opt_  ULONG Count){
            printf("WriteToHardware\r\n");
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateInterrupt( 
            /* [annotation][in] */ 
            _In_  void* Configuration,
            /* [annotation][out] */ 
            _Out_  void **ppInterrupt){
            printf("CreateInterrupt\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE CreateWorkItem( 
            /* [annotation][in] */ 
            _In_  void* pConfig,
            /* [annotation][in] */ 
            _In_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  void **ppWorkItem){
            printf("CreateWorkItem\r\n");
            return 0;
        }

        
        virtual HRESULT STDMETHODCALLTYPE AssignS0IdleSettingsEx( 
            /* [annotation][in] */ 
            _In_  PWUDF_DEVICE_POWER_POLICY_IDLE_SETTINGS IdleSettings){
	        TRACE_PRINTF("AssignS0IdleSettingsEx\r\n");
            return 0;
        }

        
};

MyDevice* myDevice = NULL;


struct MyDriver : public IWDFDriver {
    public:
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void **ppvObject) { 
            printf("QueryInterface\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE AddRef(void) { 
            printf("AddRef\r\n");
            return 0; 
        }
        virtual ULONG STDMETHODCALLTYPE Release(void) {
            printf("MyDriver::Release\r\n");
            return 0;
        }
    public:

        virtual HRESULT STDMETHODCALLTYPE DeleteWdfObject( void) {
            printf("DeleteWdfObject\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE AssignContext( 
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pCleanupCallback,
            /* [annotation][unique][in] */ 
            _In_opt_ __drv_aliasesMem  void *pContext) { 
            printf("AssignContext\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveContext( 
            /* [annotation][out] */ 
            _Out_  void **ppvContext) {
            printf("RetrieveContext\r\n");
            return 0;
        }
        
        virtual void STDMETHODCALLTYPE AcquireLock( void) {
            printf("AcquireLock\r\n");
        }
        
        virtual void STDMETHODCALLTYPE ReleaseLock( void) {
            printf("ReleaseLock\r\n");
        }

    public:
        virtual HRESULT STDMETHODCALLTYPE CreateDevice( 
            /* [annotation][in] */ 
            _In_  IWDFDeviceInitialize *pDeviceInit,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][out] */ 
            _Out_  IWDFDevice **ppDevice) {
            printf("[CreateDevice]\r\n");
            printf("pDevInit = %p\n", pDeviceInit);
            printf("pCallbackInterface = %p\n", pCallbackInterface);
            printf("ppDevice = %p\n", ppDevice);
            myDevice = new MyDevice(pCallbackInterface);
            *ppDevice = myDevice;
            printf("new device=%p\r\n", *ppDevice);
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE CreateWdfObject( 
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  IWDFObject **ppWdfObject) {
            printf("CreateWdfObject\r\n");
            return 0;
        }
        
        virtual HRESULT STDMETHODCALLTYPE CreatePreallocatedWdfMemory( 
            /* [annotation][size_is][in] */ 
            BYTE *pBuff,
            /* [annotation][in] */ 
            _In_  SIZE_T BufferSize,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  IWDFMemory **ppWdfMemory) { 
            printf("CreatePreallocatedWdfMemory\r\n");
            return 0; 
        }
        
        virtual HRESULT STDMETHODCALLTYPE CreateWdfMemory( 
            /* [annotation][in] */ 
            _In_  SIZE_T BufferSize,
            /* [annotation][unique][in] */ 
            _In_opt_  IUnknown *pCallbackInterface,
            /* [annotation][unique][in] */ 
            _In_opt_  IWDFObject *pParentObject,
            /* [annotation][out] */ 
            _Out_  IWDFMemory **ppWdfMemory) { 
            printf("CreateWdfMemory\r\n");
            return 0;
        }
        
        virtual BOOL STDMETHODCALLTYPE IsVersionAvailable( 
            /* [annotation][in] */ 
            _In_  void *pMinimumVersion) { 
            printf("IsVersionAvailable\r\n");
            return true;
        }
        
        virtual HRESULT STDMETHODCALLTYPE RetrieveVersionString( 
            /* [annotation][unique][out][string] */ 
            PWSTR pVersion,
            /* [annotation][out][in] */ 
            _Inout_  DWORD *pdwVersionLength) {
            printf("RetrieveVersionString\r\n");
            return 0;
        }
};


#define __winfnc __attribute__((ms_abi))

// typedef a function-pointer type that uses MS x64 ABI
using DLLGetClassObject_t = HRESULT (__winfnc *)(void*, void*, void**);

#define INTERFACE_HAS_MEMBER(interface_ptr, interface_type, member) \
    ((interface_ptr)->Size >= offsetof(interface_type, member) + \
                              sizeof((interface_ptr)->member) && \
     (interface_ptr)->member != NULL)



static NTSTATUS tudor_devctrl_wudf1(struct tudor_device *device, OVERLAPPED *ovlp, 
                                   ULONG code, void *in_buf, size_t in_size, 
                                   void *out_buf, size_t out_size, 
                                   struct winwdf_request **req) {
    
    if (LOG_LEVEL <= LOG_VERBOSE) {
        printf("[WUDF1-DEVCTRL] -> code 0x%x (size 0x%lx)\r\n", code, in_size);
    }

    /* A very late asynchronous ownership failure can arrive after initial
     * adapter publication. Guard again before entering the vendor's capture
     * path, which is where the mismatched-state crash was observed. */
    if(code == SYNA_CAPTURE_IOCTL &&
       ownership_failure_reject_init("capture dispatch", false))
        return STATUS_INTERNAL_ERROR;

    if (myQueue && myQueue->ioctl) {
        MyRequest *wudf_req = new MyRequest(WdfRequestTypeOther, code,
                                             out_buf, out_size,
                                             in_buf, in_size, ovlp);
        *req = reinterpret_cast<struct winwdf_request*>(wudf_req);

        if(code == SYNA_CAPTURE_IOCTL)
            capture_request_started(wudf_req);

	TRACE_PRINTF("about to ioctl: 0x%x\r\n", code);
        struct winmodule *caller_module = winmodule_get_cur();
        winmodule_set_cur(&tudor_driver_dll->module);
        if(code == SYNA_CAPTURE_IOCTL &&
           ownership_failure_reject_init("capture dispatch", false)) {
            capture_request_finished(wudf_req);
            winmodule_set_cur(caller_module);
            *req = nullptr;
            wudf_req->release_native();
            return STATUS_INTERNAL_ERROR;
        }
        myQueue->ioctl->OnDeviceIoControl(myQueue, wudf_req, code,
                                           0, 0);
        winmodule_set_cur(caller_module);
        return STATUS_SUCCESS;
    }

    log_error("WUDF1 IOCTL queue is not initialized");
    return STATUS_INTERNAL_ERROR;
}

static NTSTATUS tudor_cancel_wudf1(struct tudor_device *device, OVERLAPPED *ovlp, struct winwdf_request *req) {
    MyRequest *wudf_req = reinterpret_cast<MyRequest*>(req);
    wudf_req->retain_native();
    ULONG code = wudf_req->ctl;
    struct winmodule *caller_module = winmodule_get_cur();
    winmodule_set_cur(&tudor_driver_dll->module);
    if(!wudf_req->cancel()) {
        log_warn("WUDF1 request has no registered cancellation callback [code 0x%x]",
                 code);
    }
    winmodule_set_cur(caller_module);
    wudf_req->release_native();
    return STATUS_SUCCESS;
}

static void tudor_cleanup_wudf1(struct tudor_device *device, OVERLAPPED *ovlp, struct winwdf_request *req) {
    MyRequest *wudf_req = reinterpret_cast<MyRequest*>(req);
    if(wudf_req->ctl == SYNA_CAPTURE_IOCTL)
        capture_request_finished(wudf_req);
    wudf_req->release_native();
}

bool tudor_get_sensor_database_size(uint64_t *record_count) {
    if(!record_count || !myQueue || !myQueue->ioctl) return false;

    uint8_t result[sizeof(*record_count)] = {0};
    MyRequest req(WdfRequestTypeOther, 0x44202c,
                  result, sizeof(result), nullptr, 0, nullptr);

    struct winmodule *caller_module = winmodule_get_cur();
    winmodule_set_cur(&tudor_driver_dll->module);
    myQueue->ioctl->OnDeviceIoControl(myQueue, &req, 0x44202c, 0, 0);
    while(!req.complete.load(std::memory_order_acquire)) usleep(1000);
    winmodule_set_cur(caller_module);

    HRESULT status = req.completionStatus.load(std::memory_order_acquire);
    SIZE_T information =
        req.informationSize.load(std::memory_order_acquire);
    if(status != ERROR_SUCCESS || information < sizeof(result)) {
        log_error("Sensor database-size query failed [status 0x%x size %zu]",
                  (unsigned int) status, information);
        return false;
    }

    memcpy(record_count, result, sizeof(*record_count));
    return true;
}

typedef void ownership_reset_dispatch_fnc(MyRequest *request, void *context);

struct ownership_reset_dispatch_context {
    MyRequest *request;
    struct winmodule *module;
    ownership_reset_dispatch_fnc *dispatch;
    void *dispatch_context;
    std::atomic<bool> call_returned;

    ownership_reset_dispatch_context(
        MyRequest *request, struct winmodule *module,
        ownership_reset_dispatch_fnc *dispatch, void *dispatch_context)
        : request(request), module(module), dispatch(dispatch),
          dispatch_context(dispatch_context), call_returned(false) {}
};

static void *ownership_reset_dispatch_main(void *opaque) {
    auto *context = static_cast<ownership_reset_dispatch_context*>(opaque);

    /* Raw pthreads do not pass through the Win32 CreateThread shim.  Set the
     * two pieces of per-thread emulation state that shim establishes before
     * entering code from the Windows driver. */
    winmodule_set_cur(context->module);
    win_init_tib();
    context->dispatch(context->request, context->dispatch_context);
    context->call_returned.store(true, std::memory_order_release);
    return nullptr;
}

static bool ownership_reset_dispatch_done(
    const ownership_reset_dispatch_context *context) {
    return context->call_returned.load(std::memory_order_acquire) &&
           context->request->complete.load(std::memory_order_acquire);
}

static uint64_t monotonic_milliseconds(void) {
    struct timespec now;
    cant_fail(clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t) now.tv_sec * 1000 +
           (uint64_t) now.tv_nsec / 1000000;
}

static bool ownership_reset_dispatch_wait(
    const ownership_reset_dispatch_context *context,
    unsigned int timeout_ms) {
    uint64_t deadline = monotonic_milliseconds() + timeout_ms;

    for(;;) {
        if(ownership_reset_dispatch_done(context)) return true;

        uint64_t now = monotonic_milliseconds();
        if(now >= deadline) return ownership_reset_dispatch_done(context);

        uint64_t remaining_ms = deadline - now;
        usleep((useconds_t) (remaining_ms > 1 ? 1000 :
                            remaining_ms * 1000));
    }
}

static void ownership_reset_vendor_dispatch(MyRequest *request, void *) {
    myQueue->ioctl->OnDeviceIoControl(myQueue, request,
                                      SYNA_RESET_OWNERSHIP_IOCTL, 0, 0);
}

static bool tudor_dispatch_reset_ownership(void) {
    if(!myQueue || !myQueue->ioctl) {
        log_error("WUDF1 IOCTL queue is not initialized for ownership reset");
        return false;
    }

    /* The exact vendor unpairing callback can block synchronously.  Dispatch
     * it from an initialized Windows-emulation thread so this function can
     * enforce its deadline while the USB event thread continues to run. */
    MyRequest *req = new MyRequest(WdfRequestTypeOther,
                                   SYNA_RESET_OWNERSHIP_IOCTL,
                                   nullptr, 0, nullptr, 0, nullptr);
    auto *dispatch = new ownership_reset_dispatch_context(
        req, &tudor_driver_dll->module,
        ownership_reset_vendor_dispatch, nullptr);
    pthread_t dispatch_thread;
    int thread_error = pthread_create(&dispatch_thread, nullptr,
                                      ownership_reset_dispatch_main,
                                      dispatch);
    if(thread_error != 0) {
        log_error("Could not start vendor ownership-reset dispatch: %s",
                  strerror(thread_error));
        delete dispatch;
        req->release_native();
        return false;
    }

    bool completed = ownership_reset_dispatch_wait(
        dispatch, SYNA_RESET_OWNERSHIP_WAIT_MS);
    bool call_returned =
        dispatch->call_returned.load(std::memory_order_acquire);
    if(call_returned) {
        cant_fail_ret(pthread_join(dispatch_thread, nullptr));
    } else {
        /* The host exits immediately after a maintenance result.  If vendor
         * code is still running, detach it and retain both heap objects until
         * that process boundary rather than racing a late access. */
        int detach_error = pthread_detach(dispatch_thread);
        if(detach_error != 0)
            log_warn("Could not detach timed-out ownership-reset dispatch: %s",
                     strerror(detach_error));
    }

    if(!completed) {
        log_error("Vendor ownership-reset dispatch and completion did not "
                  "both finish within %u ms; outcome is indeterminate",
                  SYNA_RESET_OWNERSHIP_WAIT_MS);
        if(call_returned) delete dispatch;
        /* Keep the request's sole native reference: completion can still
         * arrive from a vendor worker after OnDeviceIoControl returns. */
        return false;
    }

    HRESULT status = req->completionStatus.load(std::memory_order_acquire);
    req->release_native();
    delete dispatch;
    if(status != ERROR_SUCCESS) {
        log_error("Vendor ownership-reset request failed [status 0x%x]",
                  (unsigned int) status);
        return false;
    }

    log_info("Vendor ownership-reset request completed successfully");
    return true;
}

#ifdef TUDOR_RECOVERY_TEST_HOOK
struct ownership_reset_dispatch_test_context {
    struct winmodule *expected_module;
    pthread_t caller_thread;
    std::atomic<bool> invoked{false};
    std::atomic<bool> module_valid{false};
    std::atomic<bool> separate_thread{false};
    std::atomic<bool> release{false};
    bool block_after_completion;

    ownership_reset_dispatch_test_context(struct winmodule *module,
                                          bool block)
        : expected_module(module), caller_thread(pthread_self()),
          block_after_completion(block) {}
};

static void ownership_reset_test_dispatch(MyRequest *request, void *opaque) {
    auto *test =
        static_cast<ownership_reset_dispatch_test_context*>(opaque);
    test->module_valid.store(
        winmodule_get_cur() == test->expected_module,
        std::memory_order_relaxed);
    test->separate_thread.store(
        !pthread_equal(pthread_self(), test->caller_thread),
        std::memory_order_relaxed);
    request->Complete(ERROR_SUCCESS);
    test->invoked.store(true, std::memory_order_release);

    while(test->block_after_completion &&
          !test->release.load(std::memory_order_acquire))
        usleep(1000);
}

static bool ownership_reset_test_wait_invoked(
    const ownership_reset_dispatch_test_context *test) {
    uint64_t deadline = monotonic_milliseconds() + 500;
    while(!test->invoked.load(std::memory_order_acquire)) {
        if(monotonic_milliseconds() >= deadline) return false;
        usleep(1000);
    }
    return true;
}

extern "C" __attribute__((visibility("hidden")))
int tudor_internal_test_ownership_reset_dispatch(void) {
    /* Completion alone is insufficient: model a synchronous vendor callback
     * which completes its request and then stalls before returning. */
    MyRequest *blocked_request = new MyRequest(
        WdfRequestTypeOther, SYNA_RESET_OWNERSHIP_IOCTL,
        nullptr, 0, nullptr, 0, nullptr);
    ownership_reset_dispatch_test_context blocked_test(&ntdll_module, true);
    ownership_reset_dispatch_context blocked_dispatch(
        blocked_request, &ntdll_module,
        ownership_reset_test_dispatch, &blocked_test);
    pthread_t blocked_thread;
    int error = pthread_create(&blocked_thread, nullptr,
                               ownership_reset_dispatch_main,
                               &blocked_dispatch);
    if(error != 0) {
        blocked_request->release_native();
        return 1;
    }

    bool invoked = ownership_reset_test_wait_invoked(&blocked_test);
    bool completed_before_return = invoked &&
        ownership_reset_dispatch_wait(&blocked_dispatch, 20);
    blocked_test.release.store(true, std::memory_order_release);
    cant_fail_ret(pthread_join(blocked_thread, nullptr));
    bool blocked_done = ownership_reset_dispatch_done(&blocked_dispatch);
    bool blocked_module_valid =
        blocked_test.module_valid.load(std::memory_order_relaxed);
    bool blocked_separate_thread =
        blocked_test.separate_thread.load(std::memory_order_relaxed);
    blocked_request->release_native();

    if(!invoked) return 2;
    if(completed_before_return) return 3;
    if(!blocked_done) return 4;
    if(!blocked_module_valid) return 5;
    if(!blocked_separate_thread) return 6;

    /* The ordinary path must observe both completion and callback return. */
    MyRequest *request = new MyRequest(
        WdfRequestTypeOther, SYNA_RESET_OWNERSHIP_IOCTL,
        nullptr, 0, nullptr, 0, nullptr);
    ownership_reset_dispatch_test_context test(&ntdll_module, false);
    ownership_reset_dispatch_context dispatch(
        request, &ntdll_module, ownership_reset_test_dispatch, &test);
    pthread_t thread;
    error = pthread_create(&thread, nullptr,
                           ownership_reset_dispatch_main, &dispatch);
    if(error != 0) {
        request->release_native();
        return 7;
    }

    bool completed = ownership_reset_dispatch_wait(&dispatch, 500);
    cant_fail_ret(pthread_join(thread, nullptr));
    bool module_valid = test.module_valid.load(std::memory_order_relaxed);
    bool separate_thread =
        test.separate_thread.load(std::memory_order_relaxed);
    request->release_native();

    if(!completed) return 8;
    if(!module_valid) return 9;
    if(!separate_thread) return 10;
    return 0;
}
#endif

void print_vtable(void* obj, int N) {
    void** vtable = *reinterpret_cast<void***>(obj);
    for (int i = 0; i < N; i++) {
        printf("%d: %p\n", i, vtable[i]);
    }
    fflush(stdout);
}


static bool tudor_init_internal(bool ownership_reset_mode) {

    ownership_failure_start_init(ownership_reset_mode);

    /* The sandbox has no writable filesystem. Install the per-device state
     * backends before the vendor can create its pairing identity or acquire
     * its RSA key container. */
    configure_crypto_state();

    winmodule_register(&ntdll_module);
    winreg_set_handler(tudor_reg_handler, NULL);

    print_guid(&SYNA_CLSID);
    print_guid(&IID_IUnknown);

    tudor_adapter_dll = tudor_driver_dll = NULL;
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];
        if(!load_dll(&dll->image, dll->module.name, dll->pe_image, dll->pe_image_end - dll->pe_image)) {
            log_error("Error loading driver DLL!");
            return false;
        }
        winmodule_register(&dll->module);
        log_info("Loaded driver DLL '%s' [%ld bytes]", dll->module.name, dll->pe_image_end - dll->pe_image);

        if(dll->is_adapter) tudor_adapter_dll = dll;
        if(dll->is_driver) tudor_driver_dll = dll;
    }

    if(!tudor_adapter_dll) abort();
    if(!tudor_driver_dll) abort();

    // //Initialize driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];

        if(dll->image.entry_point) {
            log_info("Initializing driver DLL '%s'...", dll->module.name);
            winmodule_set_cur(&dll->module);
            if(!((api_DllMain) dll->image.entry_point)(dll->module.handle, DLL_PROCESS_ATTACH, NULL)) {
                log_error("Error initializing driver DLL '%s'!", dll->module.name);
                return false;
            }
        }
    }

    winmodule_set_cur(&tudor_driver_dll->module);

    DLLGetClassObject_t proc = (DLLGetClassObject_t) (void*) find_dll_export(&tudor_driver_dll->image, "DllGetClassObject");
    IClassFactory *fact = NULL;

    printf("Received proc: %p\n", proc);

    printf("about to create factory\r\n");
    void* a = (void*) &SYNA_CLSID;
    void* b = (void*) &IID_IUnknown;
    void** c = (void**) &fact;

    // uint32_t proc_res = call_DllGetClassObject_windows_abi((void*)proc, &SYNA_CLSID, &IID_IUnknown, c);
    HRESULT proc_res = proc(a, b, c);
    printf("done\r\n");
    printf("proc res: %d\n", proc_res);


    void* dibr = NULL;
    proc_res = proc((void*)&GUID_DEVINTERFACE_BIOMETRIC_READER, (void*)&IID_IUnknown, &dibr);
    printf("GUID_DEVINTERFACE rc = %d\n", proc_res);


    printf("about to create instance fact = %p\r\n", fact);
    if(!fact) {
        puts("SYNA_CLSID not found in DLL");
        return 0;
    }
    HRESULT res = fact->CreateInstance(NULL, &IID_IDriverEntry, (void**)&inst);

    if (res != 0) {
        printf("Failed to create instance: %d\n", res);
        // return 0;
    }

    printf("Received instance: %p\n", inst);

    HRESULT rc;

    // MyDriver *aDriver = new MyDriver();
    aDriver = new MyDriver();
    printf("about to init %p\r\n", aDriver);

    rc = inst->OnInitialize(aDriver);

    printf("OnInitialize rc = %lx\r\n", rc);
    if(rc < 0) {
        printf("Couldn't initialize\n");
        abort();
    }

    printf("Successfully initialized Driver\n");

    MyDevInit *devinit = new MyDevInit();
    printf("about to add device %p\r\n", devinit);
    rc = inst->OnDeviceAdd(aDriver, devinit);
    // printf("OnDeviceAdd rc = %lx\r\n", rc);
    // if(rc < 0) {
    //     return 0;
    // }
    printf("OnDeviceAdd finished, rc = %d\n", rc);
    fflush(stdout);


    printf("about to prepare hw\r\n");
    print_vtable(myDevice->pnphwcb, 5); 

    ownership_failure_reset();
    rc = myDevice->pnphwcb->OnPrepareHardware(myDevice);
    printf("OnPrepareHardware rc = %lx\r\n", rc);
    fflush(stdout);
    if(rc != 0) {
        ownership_failure_record_prepare_status(rc, ownership_reset_mode);
        (void) ownership_failure_reject_init(
            "failing OnPrepareHardware", ownership_reset_mode);
        log_error("Vendor OnPrepareHardware failed: 0x%x",
                  (unsigned int) rc);
        return false;
    }
    usleep(1000000);
    if(ownership_failure_reject_init("OnPrepareHardware",
                                     ownership_reset_mode))
        return false;

    printf("about to enter D0 state\r\n");
    rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    printf("OnD0Entry rc = %lx\r\n", rc);
    fflush(stdout);
    if(rc != 0) {
        (void) ownership_failure_reject_init(
            "failing OnD0Entry", ownership_reset_mode);
        log_error("Vendor OnD0Entry failed: 0x%x", (unsigned int) rc);
        return false;
    }

    /* Reset before the normal post-D0 delay: a mismatched pairing identity
     * otherwise causes the vendor's automatic recovery loop to start about
     * one second after D0 entry.  This explicit maintenance path never
     * queries or exposes the WinBio adapters. */
    if(ownership_reset_mode) return tudor_dispatch_reset_ownership();

    usleep(5000000);
    if(ownership_failure_reject_init("OnD0Entry", false)) return false;


    //Query WINBIO interfaces
    winmodule_set_cur(&tudor_adapter_dll->module);

    HRESULT hres;
    if((hres = ((api_WbioQuerySensorInterface) find_dll_export(&tudor_adapter_dll->image, "WbioQuerySensorInterface"))(&tudor_sensor_adapter)) != 0) {
        log_error("Error querying sensor interface: 0x%x!", hres);
        return false;
    }
    if((hres = ((api_WbioQueryEngineInterface) find_dll_export(&tudor_adapter_dll->image, "WbioQueryEngineInterface"))(&tudor_engine_adapter)) != 0) {
        log_error("Error querying engine interface: 0x%x!", hres);
        return false;
    }
    tudor_native_storage_adapter = nullptr;
    auto query_storage = reinterpret_cast<api_WbioQueryStorageInterface>(
        try_find_dll_export(&tudor_adapter_dll->image,
                            "WbioQueryStorageInterface"));
    if(!query_storage) {
        log_error("Required WbioQueryStorageInterface export is absent");
        return false;
    }
    if((hres = query_storage(&tudor_native_storage_adapter)) != 0 ||
       !tudor_native_storage_adapter) {
        log_error("Error querying required native storage interface: 0x%x!",
                  hres);
        return false;
    }

    const size_t required_storage_size =
        offsetof(WINBIO_STORAGE_INTERFACE, ControlUnitPrivileged) +
        sizeof(tudor_native_storage_adapter->ControlUnitPrivileged);
    if(tudor_native_storage_adapter->Version.MajorVersion != 1 ||
       tudor_native_storage_adapter->Size < required_storage_size) {
        log_error("Unsupported native storage interface %u.%u size 0x%zx; "
                  "0081 requires the complete v1 table (at least 0x%zx)",
                  tudor_native_storage_adapter->Version.MajorVersion,
                  tudor_native_storage_adapter->Version.MinorVersion,
                  (size_t) tudor_native_storage_adapter->Size,
                  required_storage_size);
        return false;
    }
    if(!tudor_native_storage_adapter->Attach ||
       !tudor_native_storage_adapter->Detach ||
       !tudor_native_storage_adapter->ClearContext ||
       !tudor_native_storage_adapter->CreateDatabase ||
       !tudor_native_storage_adapter->EraseDatabase ||
       !tudor_native_storage_adapter->OpenDatabase ||
       !tudor_native_storage_adapter->CloseDatabase ||
       !tudor_native_storage_adapter->GetDataFormat ||
       !tudor_native_storage_adapter->GetDatabaseSize ||
       !tudor_native_storage_adapter->AddRecord ||
       !tudor_native_storage_adapter->DeleteRecord ||
       !tudor_native_storage_adapter->QueryBySubject ||
       !tudor_native_storage_adapter->QueryByContent ||
       !tudor_native_storage_adapter->GetRecordCount ||
       !tudor_native_storage_adapter->FirstRecord ||
       !tudor_native_storage_adapter->NextRecord ||
       !tudor_native_storage_adapter->GetCurrentRecord ||
       !tudor_native_storage_adapter->ControlUnit ||
       !tudor_native_storage_adapter->ControlUnitPrivileged) {
        log_error("Native storage v1 interface has a missing required method");
        return false;
    }

    log_info("Sensor adapter interface %u.%u, size %zu",
             tudor_sensor_adapter->Version.MajorVersion,
             tudor_sensor_adapter->Version.MinorVersion,
             (size_t) tudor_sensor_adapter->Size);
    log_info("Engine adapter interface %u.%u, size %zu",
             tudor_engine_adapter->Version.MajorVersion,
             tudor_engine_adapter->Version.MinorVersion,
             (size_t) tudor_engine_adapter->Size);
    const uint8_t *storage_id = reinterpret_cast<const uint8_t *>(
        &tudor_native_storage_adapter->AdapterId);
    log_info("Native storage adapter interface %u.%u, size 0x%zx, "
             "adapter %08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             tudor_native_storage_adapter->Version.MajorVersion,
             tudor_native_storage_adapter->Version.MinorVersion,
             (size_t) tudor_native_storage_adapter->Size,
             tudor_native_storage_adapter->AdapterId.PartA,
             tudor_native_storage_adapter->AdapterId.PartB,
             tudor_native_storage_adapter->AdapterId.PartC,
             storage_id[8], storage_id[9], storage_id[10], storage_id[11],
             storage_id[12], storage_id[13], storage_id[14], storage_id[15]);

    if(ownership_failure_reject_init("adapter publication", false))
        return false;
    if(!capture_relay_start()) return false;

    printf("tudor_init finish!\n");
    return true;

}

bool tudor_init() {
    return tudor_init_internal(false);
}

bool tudor_reset_ownership(void) {
    static std::atomic<bool> started{false};
    bool expected = false;
    if(!started.compare_exchange_strong(expected, true,
                                        std::memory_order_acq_rel,
                                        std::memory_order_acquire)) {
        log_error("Ownership reset was already attempted in this process");
        return false;
    }
    return tudor_init_internal(true);
}

bool tudor_shutdown() {
    capture_relay_stop();

    //Unload the driver
    winmodule_set_cur(&tudor_driver_dll->module);

    inst->OnDeinitialize(aDriver);
    printf("======================================================\r\n");
    printf("Sleeping 10 secons....\r\n");
    printf("======================================================\r\n");
    usleep(5000);


    //Uninitialize driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) {
        struct windrv_dll *dll = &tudor_windrv_dlls[i];

        if(dll->image.entry_point) {
            log_info("Uninitializing driver DLL '%s'...", dll->module.name);
            winmodule_set_cur(&dll->module);
            if(!((api_DllMain) dll->image.entry_point)(dll->module.handle, DLL_PROCESS_DETACH, NULL)) {
                log_error("Error uninitializing driver DLL '%s'!", dll->module.name);
                return false;
            }
        }
        winmodule_unregister(&dll->module);
    }

    //Destroy driver DLLs
    for(int i = 0; i < NUM_WINDRV_DLLS; i++) destroy_dll(&tudor_windrv_dlls[i].image);

    //Unregister dummy modules
    winmodule_unregister(&ntdll_module);

    cryptbridge_registry_set_state_callbacks(nullptr, nullptr, nullptr);
    cryptbridge_identity_set_state_callbacks(nullptr, nullptr, nullptr);

    return true;
}

bool device_init()
{
    // MyDevInit *devinit = new MyDevInit();
    // printf("about to add device %p\r\n", devinit);
    // HRESULT rc = inst->OnDeviceAdd(aDriver, devinit);
    // printf("OnDeviceAdd rc = %lx\r\n", rc);
    // if(rc < 0) {
    //     return false;
    // }
    //
    // goIdle = 0;
    //
    // usleep(100);
    // printf("about to prepare hw\r\n");
    // rc = myDevice->pnphwcb->OnPrepareHardware(myDevice);
    // printf("OnPrepareHardware rc = %lx\r\n", rc);
    //
    // if(rc < 0) {
    //     return false;
    // }
    //
    // usleep(100);
    // printf("about to enter D0 state\r\n");
    // rc = myDevice->pnpcb->OnD0Entry(myDevice, WdfPowerDeviceInvalid);
    // printf("OnD0Entry rc = %lx\r\n", rc);
    return true;
}

struct tudor_open_progress {
    bool sensor_attached = false;
    bool engine_attached = false;
    bool storage_attached = false;
    bool sensor_initialized = false;
    bool engine_initialized = false;
    bool storage_initialized = false;
    bool sensor_activated = false;
    bool engine_activated = false;
    bool storage_activated = false;
    bool storage_database_open = false;
};

static void tudor_unwind_failed_open(struct tudor_device *device,
                                     const tudor_open_progress& progress)
{
    winmodule_set_cur(&tudor_adapter_dll->module);
    auto unwind_pipeline = [&](const char *name,
                               HRESULT (__winfnc *fnc)(WINBIO_PIPELINE*)) {
        if(!fnc) return;
        HRESULT hres = fnc(device->pipeline);
        if(hres != ERROR_SUCCESS) {
            log_error("Error unwinding WINBIO pipeline function '%s': 0x%x!",
                      name, hres);
        }
    };

    if(progress.sensor_activated &&
       INTERFACE_HAS_MEMBER(tudor_sensor_adapter, WINBIO_SENSOR_INTERFACE,
                            Deactivate))
        unwind_pipeline("SensorInterface->Deactivate",
                        tudor_sensor_adapter->Deactivate);
    if(progress.engine_activated &&
       INTERFACE_HAS_MEMBER(tudor_engine_adapter, WINBIO_ENGINE_INTERFACE,
                            Deactivate))
        unwind_pipeline("EngineInterface->Deactivate",
                        tudor_engine_adapter->Deactivate);
    if(progress.storage_activated &&
       INTERFACE_HAS_MEMBER(device->pipeline->StorageInterface,
                            WINBIO_STORAGE_INTERFACE, Deactivate))
        unwind_pipeline("StorageInterface->Deactivate",
                        device->pipeline->StorageInterface->Deactivate);

    if(progress.sensor_initialized &&
       INTERFACE_HAS_MEMBER(tudor_sensor_adapter, WINBIO_SENSOR_INTERFACE,
                            PipelineCleanup))
        unwind_pipeline("SensorInterface->PipelineCleanup",
                        tudor_sensor_adapter->PipelineCleanup);
    if(progress.engine_initialized &&
       INTERFACE_HAS_MEMBER(tudor_engine_adapter, WINBIO_ENGINE_INTERFACE,
                            PipelineCleanup))
        unwind_pipeline("EngineInterface->PipelineCleanup",
                        tudor_engine_adapter->PipelineCleanup);
    if(progress.storage_initialized &&
       INTERFACE_HAS_MEMBER(device->pipeline->StorageInterface,
                            WINBIO_STORAGE_INTERFACE, PipelineCleanup))
        unwind_pipeline("StorageInterface->PipelineCleanup",
                        device->pipeline->StorageInterface->PipelineCleanup);

    if(progress.storage_database_open)
        unwind_pipeline("StorageInterface->CloseDatabase",
                        device->pipeline->StorageInterface->CloseDatabase);

    if(progress.storage_attached)
        unwind_pipeline("StorageInterface->Detach",
                        device->pipeline->StorageInterface->Detach);
    if(progress.engine_attached)
        unwind_pipeline("EngineInterface->Detach",
                        tudor_engine_adapter->Detach);
    if(progress.sensor_attached)
        unwind_pipeline("SensorInterface->Detach",
                        tudor_sensor_adapter->Detach);

    if(device->winbio_file) {
        winhandle_destroy(device->winbio_file);
        device->winbio_file = NULL;
    }
    free(device->pipeline);
    device->pipeline = NULL;
    cant_fail_ret(pthread_mutex_destroy(&device->records_lock));
}

bool tudor_open(struct tudor_device *device, libusb_device_handle *usb_dev, struct tudor_device_state *state)
{
    if(ownership_failure_reject_init("pipeline open", false)) return false;

    tudor_open_progress progress;
    device->state = state ? *state : (struct tudor_device_state) {0};
    device->enrolling = false;
    device->pipeline = NULL;
    device->winbio_file = NULL;
    cant_fail_ret(pthread_mutex_init(&device->records_lock, NULL));
    device->records_head = NULL;
    device->result_records_head = device->result_records_cursor = NULL;

    auto open_pipeline = [&](const char *name, HRESULT result) {
        if(result == ERROR_SUCCESS) return true;
        log_error("Error in WINBIO pipeline function '%s': 0x%x!",
                  name, result);
        tudor_unwind_failed_open(device, progress);
        return false;
    };

    device_init();

    //This is dumb, but otherwise we run into race conditions
    cant_fail(usleep(3000));

    //Initialize the pipeline
    winmodule_set_cur(&tudor_adapter_dll->module);

    log_debug("Initializing WINBIO pipeline...");
    device->pipeline = (WINBIO_PIPELINE*) malloc(sizeof(WINBIO_PIPELINE));
    if(!device->pipeline) { perror("Error allocating WINBIO pipeline"); abort(); }
    *device->pipeline = (WINBIO_PIPELINE) {0};
    device->pipeline->EngineInterface = tudor_engine_adapter;
    device->pipeline->SensorInterface = tudor_sensor_adapter;
    device->pipeline->StorageInterface = tudor_native_storage_adapter;
    // device->pipeline->SensorHandle = device->winbio_file = winio_create_file(device, true, NULL, NULL, (winio_devctrl_fnc*) tudor_devctrl, (winio_cancel_fnc*) tudor_cancel, (winio_cleanup_fnc*) tudor_cleanup, NULL);
    device->pipeline->SensorHandle = device->winbio_file = winio_create_file(
        device, 
        true, 
        NULL, 
        NULL, 
        (winio_devctrl_fnc*) tudor_devctrl_wudf1,  // New function needed
        (winio_cancel_fnc*) tudor_cancel_wudf1,    // New function needed
        (winio_cleanup_fnc*) tudor_cleanup_wudf1,  // New function needed
        NULL
    );

    device->pipeline->EngineHandle = INVALID_HANDLE_VALUE;
    device->pipeline->StorageHandle = INVALID_HANDLE_VALUE;
    /* All adapter contexts must be NULL before Attach.  In particular, the
     * vendor storage Attach rejects a pre-populated StorageContext. */
    device->pipeline->StorageContext = NULL;

    log_debug("Attaching interfaces to pipeline...");
    if(!open_pipeline("SensorInterface->Attach",
                      tudor_sensor_adapter->Attach(device->pipeline)))
        return false;
    progress.sensor_attached = true;
    if(!open_pipeline("EngineInterface->Attach",
                      tudor_engine_adapter->Attach(device->pipeline)))
        return false;
    progress.engine_attached = true;
    if(!open_pipeline("StorageInterface->Attach",
                      device->pipeline->StorageInterface->Attach(
                          device->pipeline)))
        return false;
    progress.storage_attached = true;

    /* The 0081 engine expects the vendor database to be open before its
     * PipelineInit loads the match-in-sensor enrollment catalog. */
    if(!tudor_open_native_storage_database(device)) {
        tudor_unwind_failed_open(device, progress);
        return false;
    }
    progress.storage_database_open = true;

    log_debug("Initializing pipeline interfaces...");
    if(INTERFACE_HAS_MEMBER(device->pipeline->StorageInterface,
                            WINBIO_STORAGE_INTERFACE, PipelineInit)) {
        if(!open_pipeline("StorageInterface->PipelineInit",
                          device->pipeline->StorageInterface->PipelineInit(
                              device->pipeline)))
            return false;
        progress.storage_initialized = true;
    }
    if(INTERFACE_HAS_MEMBER(tudor_engine_adapter, WINBIO_ENGINE_INTERFACE, PipelineInit)) {
        if(!open_pipeline("EngineInterface->PipelineInit",
                          tudor_engine_adapter->PipelineInit(device->pipeline)))
            return false;
        progress.engine_initialized = true;
    }
    if(INTERFACE_HAS_MEMBER(tudor_sensor_adapter, WINBIO_SENSOR_INTERFACE, PipelineInit)) {
        if(!open_pipeline("SensorInterface->PipelineInit",
                          tudor_sensor_adapter->PipelineInit(device->pipeline)))
            return false;
        progress.sensor_initialized = true;
    }

    //Reset the sensor
    log_debug("Resetting sensor...");
    if(!open_pipeline("SensorInterface->Reset",
                      tudor_sensor_adapter->Reset(device->pipeline)))
        return false;

    //Activate the pipeline
    log_debug("Activating pipeline...");
    if(INTERFACE_HAS_MEMBER(device->pipeline->StorageInterface,
                            WINBIO_STORAGE_INTERFACE, Activate)) {
        if(!open_pipeline("StorageInterface->Activate",
                          device->pipeline->StorageInterface->Activate(
                              device->pipeline)))
            return false;
        progress.storage_activated = true;
    }
    if(INTERFACE_HAS_MEMBER(tudor_engine_adapter, WINBIO_ENGINE_INTERFACE, Activate)) {
        if(!open_pipeline("EngineInterface->Activate",
                          tudor_engine_adapter->Activate(device->pipeline)))
            return false;
        progress.engine_activated = true;
    }
    if(INTERFACE_HAS_MEMBER(tudor_sensor_adapter, WINBIO_SENSOR_INTERFACE, Activate)) {
        if(!open_pipeline("SensorInterface->Activate",
                          tudor_sensor_adapter->Activate(device->pipeline)))
            return false;
        progress.sensor_activated = true;
    }

    //Check the sensor status
    log_debug("Checking sensor status...");
    ULONG sensor_status = WINBIO_SENSOR_FAILURE;
    if(!open_pipeline("SensorInterface->QueryStatus",
                      tudor_sensor_adapter->QueryStatus(device->pipeline,
                                                        &sensor_status)))
        return false;
    if(sensor_status != WINBIO_SENSOR_READY) {
        log_error("Sensor didn't return ready status! [status 0x%x]",
                  sensor_status);
        tudor_unwind_failed_open(device, progress);
        return false;
    }

    if(ownership_failure_reject_init("pipeline publication", false)) {
        tudor_unwind_failed_open(device, progress);
        return false;
    }

    return true;
}

bool tudor_close(struct tudor_device *device)
{
    bool success = true;

    winmodule_set_cur(&tudor_adapter_dll->module);
    auto call_pipeline = [&](const char *name,
                             HRESULT (__winfnc *fnc)(WINBIO_PIPELINE*)) {
        if(!fnc) return;
        HRESULT hres = fnc(device->pipeline);
        if(hres != ERROR_SUCCESS) {
            log_error("Error in WINBIO pipeline close function '%s': 0x%x!",
                      name, hres);
            success = false;
        }
    };

    log_debug("Deactivating pipeline...");
    if(INTERFACE_HAS_MEMBER(tudor_sensor_adapter, WINBIO_SENSOR_INTERFACE,
                            Deactivate))
        call_pipeline("SensorInterface->Deactivate",
                      tudor_sensor_adapter->Deactivate);
    if(INTERFACE_HAS_MEMBER(tudor_engine_adapter, WINBIO_ENGINE_INTERFACE,
                            Deactivate))
        call_pipeline("EngineInterface->Deactivate",
                      tudor_engine_adapter->Deactivate);
    if(INTERFACE_HAS_MEMBER(device->pipeline->StorageInterface,
                            WINBIO_STORAGE_INTERFACE, Deactivate))
        call_pipeline("StorageInterface->Deactivate",
                      device->pipeline->StorageInterface->Deactivate);

    log_debug("Cleaning up pipeline interfaces...");
    if(INTERFACE_HAS_MEMBER(tudor_sensor_adapter, WINBIO_SENSOR_INTERFACE,
                            PipelineCleanup))
        call_pipeline("SensorInterface->PipelineCleanup",
                      tudor_sensor_adapter->PipelineCleanup);
    if(INTERFACE_HAS_MEMBER(tudor_engine_adapter, WINBIO_ENGINE_INTERFACE,
                            PipelineCleanup))
        call_pipeline("EngineInterface->PipelineCleanup",
                      tudor_engine_adapter->PipelineCleanup);
    if(INTERFACE_HAS_MEMBER(device->pipeline->StorageInterface,
                            WINBIO_STORAGE_INTERFACE, PipelineCleanup))
        call_pipeline("StorageInterface->PipelineCleanup",
                      device->pipeline->StorageInterface->PipelineCleanup);

    if(tudor_uses_native_storage(device))
        call_pipeline("StorageInterface->CloseDatabase",
                      device->pipeline->StorageInterface->CloseDatabase);

    log_debug("Detaching pipeline interfaces...");
    call_pipeline("StorageInterface->Detach",
                  device->pipeline->StorageInterface->Detach);
    call_pipeline("EngineInterface->Detach", tudor_engine_adapter->Detach);
    call_pipeline("SensorInterface->Detach", tudor_sensor_adapter->Detach);

    if(device->winbio_file) {
        winhandle_destroy(device->winbio_file);
        device->winbio_file = NULL;
    }
    free(device->pipeline);
    device->pipeline = NULL;

    /* This closes one WinBio pipeline, not the physical PnP device.  Calling
     * OnD0Exit/OnReleaseHardware here powers down and re-enumerates the 0081
     * on every client close.  Driver-wide teardown belongs to
     * tudor_shutdown(), after all pipelines have been detached. */

    cant_fail_ret(pthread_mutex_lock(&device->records_lock));
    for(struct tudor_record *record = device->records_head, *next = NULL;
        record; record = next) {
        next = record->next;
        free(record->data);
        free(record->identity);
        free(record);
    }
    device->records_head = NULL;
    device->result_records_head = device->result_records_cursor = NULL;
    cant_fail_ret(pthread_mutex_unlock(&device->records_lock));
    cant_fail_ret(pthread_mutex_destroy(&device->records_lock));

    return success;
}
