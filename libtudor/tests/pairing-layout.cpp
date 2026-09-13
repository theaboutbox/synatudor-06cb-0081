#include <atomic>
#include <cassert>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>

#include "loader.h"
#include "winapi/windows.h"

extern "C" void *tudor_internal_test_vendor_device_layout(
    const struct dll_image *, const void *, const void *, const void *);
extern "C" void tudor_internal_test_vendor_pairing_fields(
    void *, HANDLE *, void **);
extern "C" bool tudor_internal_test_vendor_pairing_join(void *);
extern "C" unsigned int tudor_internal_test_vendor_capture_readiness(
    const void *);
extern "C" const struct dll_callsite_hook *
tudor_internal_test_vendor_calibration_hook();

typedef DWORD __winfnc PairingThread(void *);
extern "C" HANDLE __winfnc CreateThread(
    void *, SIZE_T, PairingThread *, void *, DWORD, DWORD *);
extern "C" BOOL __winfnc CloseHandle(HANDLE);

/* Match the native synchronization shim's Windows critical-section layout. */
struct TestCriticalSection {
    void *DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    DWORD SpinCount;
};
static_assert(sizeof(TestCriticalSection) == 0x28);
extern "C" void __winfnc InitializeCriticalSection(TestCriticalSection *);
extern "C" void __winfnc DeleteCriticalSection(TestCriticalSection *);

static std::atomic<void*> observed_pairing_device{nullptr};
static unsigned char test_strategy;
static void *original_pairing_target;
static void *original_calibration_target;
static void *original_calibration_retry_target;
static void *expected_calibration_device;
static DWORD calibration_status;
static bool calibration_retry;
static unsigned int calibration_calls;

/* Run deviceCalibrate's real flag/state writes, substituting only the SDK
 * routine that would read calibration data or talk to the sensor. */
static DWORD __winfnc calibrate_without_hardware(void *device, DWORD force) {
    assert(device == expected_calibration_device);
    assert(force == (calibration_calls == 0 ? 0u : 1u));
    ++calibration_calls;
    if(calibration_retry && calibration_calls == 1) return 0xd7;
    return calibration_status;
}

/* The real pinned PairingThread entry still runs.  Replace only its call to
 * ProcessPairing so this regression cannot communicate with a reader. */
static DWORD __winfnc process_pairing_without_hardware(void *device) {
    observed_pairing_device.store(device, std::memory_order_release);
    void *strategy = &test_strategy;
    std::memcpy(static_cast<uint8_t*>(device) + 0x1c0, &strategy,
                sizeof(strategy));
    return 0x1234;
}

static struct dll_callsite_hook pairing_test_hook = {
    "pairing-layout-test.dll", 0x21d34, 0x23738,
    {0xe8, 0xff, 0x19, 0x00, 0x00},
    reinterpret_cast<void*>(&process_pairing_without_hardware),
    &original_pairing_target, nullptr
};

static struct dll_callsite_hook calibration_test_hook = {
    "pairing-layout-test.dll", 0x25c7b, 0x1a644,
    {0xe8, 0xc4, 0x49, 0xff, 0xff},
    reinterpret_cast<void*>(&calibrate_without_hardware),
    &original_calibration_target, nullptr
};
static struct dll_callsite_hook calibration_retry_test_hook = {
    "pairing-layout-test.dll", 0x25d77, 0x1a644,
    {0xe8, 0xc8, 0x48, 0xff, 0xff},
    reinterpret_cast<void*>(&calibrate_without_hardware),
    &original_calibration_retry_target, nullptr
};

/* Copy the production descriptor into process-lifetime test storage. Only
 * the image name changes; the production wrapper and its original-target
 * slot still run, and the real calibration SDK remains mocked below. */
static struct dll_callsite_hook calibration_observer_test_hook;
static void *observer_received_device;
static DWORD observer_return_status;

static DWORD __winfnc observer_original_without_hardware(void *device) {
    observer_received_device = device;
    return observer_return_status;
}

typedef DWORD __winfnc DeviceCalibrate(void *);

static DeviceCalibrate *calibration_observer_trampoline(
    const struct dll_image& image) {
    const auto& hook = calibration_observer_test_hook;
    auto *base = static_cast<uint8_t*>(image.base_addr);
    assert(hook.call_rva + 5u <= static_cast<size_t>(image.image_size));
    assert(base[hook.call_rva] == 0xe8);
    int32_t displacement;
    std::memcpy(&displacement, base + hook.call_rva + 1,
                sizeof(displacement));
    const int64_t rva = static_cast<int64_t>(hook.call_rva) + 5 + displacement;
    assert(rva >= 0 && static_cast<uint64_t>(rva) + 14 <= image.mapping_size);
    auto *trampoline = base + rva;
    assert(trampoline[0] == 0xff && trampoline[1] == 0x25);
    uint32_t indirect_displacement;
    std::memcpy(&indirect_displacement, trampoline + 2,
                sizeof(indirect_displacement));
    assert(indirect_displacement == 0);
    void *replacement;
    std::memcpy(&replacement, trampoline + 6, sizeof(replacement));
    assert(replacement == hook.replacement);
    return reinterpret_cast<DeviceCalibrate*>(trampoline);
}

static void test_calibration_observer_binding(const struct dll_image& image) {
    auto *base = static_cast<uint8_t*>(image.base_addr);
    auto **target = calibration_observer_test_hook.original_target;
    assert(target && *target == base + 0x25b00);
    auto *observer = calibration_observer_trampoline(image);
    void *original = *target;
    *target = reinterpret_cast<void*>(&observer_original_without_hardware);
    uint8_t synthetic_device = 0;
    for(DWORD status : {0u, 0x800700c9u, 0xffffffffu}) {
        observer_received_device = nullptr;
        observer_return_status = status;
        assert(observer(&synthetic_device) == status);
        assert(observer_received_device == &synthetic_device);
    }
    *target = original;
}

template<size_t N>
static void assert_code(const struct dll_image& image, uintptr_t rva,
                         const uint8_t (&bytes)[N]) {
    assert(rva + N <= static_cast<size_t>(image.image_size));
    assert(!std::memcmp(static_cast<uint8_t*>(image.base_addr) + rva,
                        bytes, N));
}

static void put_pointer(uint8_t *object, size_t offset, const void *pointer) {
    std::memcpy(object + offset, &pointer, sizeof(pointer));
}

static void put_dword(uint8_t *object, size_t offset, DWORD value) {
    std::memcpy(object + offset, &value, sizeof(value));
}

int pairing_layout_test(const char *driver_path) {
    FILE *driver = std::fopen(driver_path, "rb");
    assert(driver);
    assert(std::fseek(driver, 0, SEEK_END) == 0);
    long size = std::ftell(driver);
    assert(size > 0 && static_cast<unsigned long>(size) <= UINT32_MAX);
    assert(std::fseek(driver, 0, SEEK_SET) == 0);
    std::vector<uint8_t> driver_data(static_cast<size_t>(size));
    assert(std::fread(driver_data.data(), 1, driver_data.size(), driver) ==
           driver_data.size());
    assert(std::fclose(driver) == 0);

    dll_register_callsite_hook(&pairing_test_hook);
    dll_register_callsite_hook(&calibration_test_hook);
    dll_register_callsite_hook(&calibration_retry_test_hook);
    const auto *production = tudor_internal_test_vendor_calibration_hook();
    assert(production && !std::strcmp(production->image_name,
                                      "synaWudfBioUsb.dll"));
    assert(production->call_rva == 0x23b14);
    assert(production->expected_target_rva == 0x25b00);
    const uint8_t calibration_call[] = {0xe8, 0xe7, 0x1f, 0x00, 0x00};
    assert(!std::memcmp(production->expected_instruction, calibration_call,
                        sizeof(calibration_call)));
    calibration_observer_test_hook = *production;
    calibration_observer_test_hook.image_name = pairing_test_hook.image_name;
    calibration_observer_test_hook.next = nullptr;
    dll_register_callsite_hook(&calibration_observer_test_hook);
    struct dll_image image = {};
    assert(load_dll(&image, pairing_test_hook.image_name, driver_data.data(),
                    static_cast<uint32_t>(driver_data.size())));
    auto *image_base = static_cast<uint8_t*>(image.base_addr);
    assert(original_pairing_target == image_base + 0x23738);
    assert(original_calibration_target == image_base + 0x1a644);
    assert(original_calibration_retry_target == image_base + 0x1a644);
    test_calibration_observer_binding(image);

    /* Bind the object fixture to the actual pinned instructions.  The
     * hardware thunk adjusts this by 0x258; OnPrepareHardware passes the
     * primary object as CreateThread's fourth argument and stores its result
     * in that same object's field at 0x1a8. */
    assert_code(image, 0x18300,
        {0x48, 0x81, 0xe9, 0x58, 0x02, 0x00, 0x00});
    assert_code(image, 0x39871,
        {0x48, 0x2d, 0x58, 0x02, 0x00, 0x00});
    assert_code(image, 0x39895, {0xff, 0x50, 0x30});
    assert_code(image, 0x22739,
        {0x4c, 0x8b, 0x8c, 0x24, 0x60, 0x03, 0x00, 0x00,
         0x4c, 0x8d, 0x05, 0xd4, 0xf5, 0xff, 0xff,
         0x33, 0xd2, 0x33, 0xc9,
         0xff, 0x15, 0x56, 0x6b, 0x0f, 0x00,
         0x48, 0x8b, 0x8c, 0x24, 0x60, 0x03, 0x00, 0x00,
         0x48, 0x89, 0x81, 0xa8, 0x01, 0x00, 0x00});
    assert_code(image, 0x19989,
        {0x48, 0xc7, 0x80, 0xa8, 0x01, 0x00, 0x00, 0, 0, 0, 0});
    assert_code(image, 0x199d2,
        {0x48, 0xc7, 0x80, 0xc0, 0x01, 0x00, 0x00, 0, 0, 0, 0});

    /* Bind the diagnostic field widths and polarity to Capture's real
     * conditional branches, and calibration to its actual success/failure
     * writers. A worker can exit with a pending request before completion. */
    assert_code(image, 0x1acfb,
        {0x83, 0xb8, 0xf4, 0, 0, 0, 0,
         0x0f, 0x84, 0xf8, 0, 0, 0});
    assert_code(image, 0x1ae08,
        {0x48, 0x83, 0xb8, 0x70, 0x01, 0, 0, 0, 0x74, 0x6d});
    assert_code(image, 0x1b41a,
        {0x83, 0xb8, 0x50, 0x01, 0, 0, 0,
         0x0f, 0x84, 0x3b, 0x07, 0, 0});
    assert_code(image, 0x1b42f,
        {0x83, 0xb8, 0x4c, 0x01, 0, 0, 0,
         0x0f, 0x84, 0x26, 0x07, 0, 0});
    assert_code(image, 0x1eacd,
        {0xc7, 0x80, 0x4c, 0x01, 0, 0, 1, 0, 0, 0});
    assert_code(image, 0x25db3,
        {0xc7, 0x80, 0x50, 0x01, 0, 0, 1, 0, 0, 0});
    assert_code(image, 0x25df0,
        {0xc7, 0x80, 0x50, 0x01, 0, 0, 0, 0, 0, 0});
    assert_code(image, 0x2641b,
        {0xc7, 0x80, 0xf4, 0, 0, 0, 1, 0, 0, 0});

    alignas(void*) uint8_t object[0x500] = {};
    void *hardware = object + 0x258;
    void *pnp = object + 0x8;
    put_pointer(object, 0, image_base + 0x119e08);
    put_pointer(object, 0x8, image_base + 0x119ea0);
    put_pointer(object, 0x258, image_base + 0x119f70);
    void *derived = tudor_internal_test_vendor_device_layout(
        &image, hardware, hardware, pnp);
    assert(derived == object);
    assert(derived != hardware);

    /* Execute the DLL's real hardware and PnP AddRef thunks.  Both must adjust
     * their respective COM subobject to the one primary refcount at +0x28. */
    typedef ULONG __winfnc AddRef(void *);
    auto *hardware_addref = reinterpret_cast<AddRef*>(image_base + 0x18300);
    auto *pnp_addref = reinterpret_cast<AddRef*>(image_base + 0x182dc);
    assert(hardware_addref(hardware) == 1);
    assert(pnp_addref(pnp) == 2);
    uint32_t references;
    std::memcpy(&references, object + 0x28, sizeof(references));
    assert(references == 2);

    assert(!tudor_internal_test_vendor_device_layout(
        &image, pnp, hardware, pnp));
    assert(!tudor_internal_test_vendor_device_layout(
        &image, hardware, hardware, object + 0x10));
    assert(!tudor_internal_test_vendor_device_layout(
        &image, nullptr, nullptr, nullptr));

    /* A similar-looking interface or table must fail before its state can be
     * read.  Use the relocated real DLL tables, rather than a table of fake
     * native function pointers, for every accepted fixture. */
    put_pointer(object, 0x258, image_base + 0x119ea0);
    assert(!tudor_internal_test_vendor_device_layout(
        &image, hardware, hardware, pnp));
    put_pointer(object, 0x258, image_base + 0x119f70);
    put_pointer(object, 0x8, image_base + 0x119f10);
    assert(!tudor_internal_test_vendor_device_layout(
        &image, hardware, hardware, pnp));
    put_pointer(object, 0x8, image_base + 0x119ea0);
    put_pointer(object, 0, image_base + 0x11b6f8);
    assert(!tudor_internal_test_vendor_device_layout(
        &image, hardware, hardware, pnp));
    put_pointer(object, 0, image_base + 0x119e08);

    struct dll_image truncated = image;
    truncated.image_size = 0x119f70;
    assert(!tudor_internal_test_vendor_device_layout(
        &truncated, hardware, hardware, pnp));

    assert(tudor_internal_test_vendor_capture_readiness(nullptr) == 0);
    for(unsigned int flags = 0; flags != 16; ++flags) {
        put_dword(object, 0x14c, (flags & 1) ? 0x80000000u : 0);
        put_dword(object, 0x150, (flags & 2) ? 1 : 0);
        put_dword(object, 0xf4, (flags & 4) ? 2 : 0);
        put_pointer(object, 0x170, (flags & 8) ? &test_strategy : nullptr);
        assert(tudor_internal_test_vendor_capture_readiness(derived) == flags);
    }

    auto *critical = reinterpret_cast<TestCriticalSection*>(object + 0x178);
    InitializeCriticalSection(critical);
    auto *device_calibrate = calibration_observer_trampoline(image);
    expected_calibration_device = derived;
    put_dword(object, 0xf4, 0);
    put_dword(object, 0x14c, 1);
    put_pointer(object, 0x170, nullptr);
    for(unsigned int scenario = 0; scenario != 3; ++scenario) {
        put_dword(object, 0x150, 0);
        put_dword(object, 0x154, 0);
        calibration_calls = 0;
        calibration_retry = scenario == 2;
        calibration_status = scenario == 1 ? 0xc9 : 0;
        DWORD status = device_calibrate(derived);
        assert((status == 0) == (scenario != 1));
        assert(calibration_calls == (calibration_retry ? 2u : 1u));
        assert(tudor_internal_test_vendor_capture_readiness(derived) ==
               (scenario == 1 ? 1u : 3u));
    }

    /* Execute the real CaptureThread's blocked path. It returns success
     * while leaving the request untouched, proving that worker status alone
     * does not establish capture completion. This path reaches no USB call. */
    put_dword(object, 0xf4, 1);
    put_pointer(object, 0x170, &test_strategy);
    auto *capture_entry = reinterpret_cast<PairingThread*>(
        image_base + 0x1c40c);
    assert(capture_entry(derived) == 0);
    assert(tudor_internal_test_vendor_capture_readiness(derived) == 15);
    put_dword(object, 0xf4, 0);
    put_pointer(object, 0x170, nullptr);
    DeleteCriticalSection(critical);

    /* Run the real PairingThread entry through the compatibility CreateThread
     * implementation.  The bounded production join must find its handle and
     * the strategy at the derived primary base.  The formerly used hardware
     * subobject sees zero at those offsets and is rejected. */
    auto *pairing_entry = reinterpret_cast<PairingThread*>(image_base + 0x21d1c);
    HANDLE thread = CreateThread(nullptr, 0, pairing_entry, derived, 0, nullptr);
    assert(thread);
    put_pointer(object, 0x1a8, thread);
    assert(!tudor_internal_test_vendor_pairing_join(hardware));
    assert(tudor_internal_test_vendor_pairing_join(derived));
    assert(observed_pairing_device.load(std::memory_order_acquire) == derived);
    HANDLE observed_thread = nullptr;
    void *observed_strategy = nullptr;
    tudor_internal_test_vendor_pairing_fields(
        derived, &observed_thread, &observed_strategy);
    assert(observed_thread == thread);
    assert(observed_strategy == &test_strategy);
    assert(CloseHandle(thread));

    destroy_dll(&image);
    assert(!original_pairing_target);
    assert(!original_calibration_target);
    assert(!original_calibration_retry_target);
    assert(!*calibration_observer_test_hook.original_target);

    /* A mismatched pinned instruction rejects the image before publishing
     * targets. The same descriptors then rebind on a fresh valid load. */
    calibration_observer_test_hook.expected_instruction[1] ^= 1u;
    struct dll_image rejected = {};
    assert(!load_dll(&rejected, pairing_test_hook.image_name,
                     driver_data.data(),
                     static_cast<uint32_t>(driver_data.size())));
    assert(!*calibration_observer_test_hook.original_target);
    calibration_observer_test_hook.expected_instruction[1] ^= 1u;
    assert(load_dll(&image, pairing_test_hook.image_name, driver_data.data(),
                    static_cast<uint32_t>(driver_data.size())));
    test_calibration_observer_binding(image);
    destroy_dll(&image);
    assert(!*calibration_observer_test_hook.original_target);
    return 0;
}
