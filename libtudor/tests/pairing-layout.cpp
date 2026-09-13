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

typedef DWORD __winfnc PairingThread(void *);
extern "C" HANDLE __winfnc CreateThread(
    void *, SIZE_T, PairingThread *, void *, DWORD, DWORD *);
extern "C" BOOL __winfnc CloseHandle(HANDLE);

static std::atomic<void*> observed_pairing_device{nullptr};
static unsigned char test_strategy;
static void *original_pairing_target;

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
    struct dll_image image = {};
    assert(load_dll(&image, pairing_test_hook.image_name, driver_data.data(),
                    static_cast<uint32_t>(driver_data.size())));
    auto *image_base = static_cast<uint8_t*>(image.base_addr);
    assert(original_pairing_target == image_base + 0x23738);

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
    return 0;
}
