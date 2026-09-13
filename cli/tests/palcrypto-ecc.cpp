#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <cryptbridge/identity.h>
#include "loader.h"
#include "winapi/api.h"

/* Exercise the actual pinned vendor crypto boundary.  No device is created,
 * no hardware callbacks run, and all identity state exists only in memory. */
static std::vector<uint8_t> saved_identity;
static unsigned identity_stores;

static cryptbridge_identity_load_result load_identity(
    void *, void **data, size_t *size) {
    if(saved_identity.empty()) return CRYPTBRIDGE_IDENTITY_LOAD_NOT_FOUND;
    *size = saved_identity.size();
    *data = std::malloc(*size);
    assert(*data);
    std::memcpy(*data, saved_identity.data(), *size);
    return CRYPTBRIDGE_IDENTITY_LOAD_FOUND;
}

static bool store_identity(void *, const void *data, size_t size) {
    ++identity_stores;
    const auto *bytes = static_cast<const uint8_t*>(data);
    saved_identity.assign(bytes, bytes + size);
    return true;
}

template<class Function>
static Function *vendor_function(const dll_image& image, uintptr_t rva) {
    assert(rva < static_cast<uintptr_t>(image.image_size));
    return reinterpret_cast<Function*>(
        static_cast<uint8_t*>(image.base_addr) + rva);
}

template<size_t N>
static void assert_instruction(const dll_image& image, uintptr_t rva,
                               const uint8_t (&bytes)[N]) {
    assert(rva + N <= static_cast<uintptr_t>(image.image_size));
    assert(!std::memcmp(static_cast<uint8_t*>(image.base_addr) + rva,
                        bytes, N));
}

using DllMain = BOOL __winfnc(HANDLE, DWORD, void *);
using EccInit = DWORD __winfnc(const uint32_t *, void **);
using Keygen = DWORD __winfnc(void *, void *, void **, void **);
using PublicExport = DWORD __winfnc(void *, uint32_t *, void *, void *, void *);
using PrivateExport = DWORD __winfnc(void *, uint32_t *, void *, void *);
using PrivateImport = DWORD __winfnc(void *, uint32_t, const void *, void **);
using Sign = DWORD __winfnc(void *, void *, const void *, uint32_t,
                           void *, uint32_t *);
using Verify = DWORD __winfnc(void *, void *, const void *, uint32_t,
                             const void *, uint32_t);
using Free = DWORD __winfnc(void **);

static void sign_and_verify(const dll_image& image, void *context,
                            void *public_key,
                            const std::vector<uint8_t>& encoding) {
    const auto original_encoding = encoding;
    void *private_key = nullptr;
    assert(vendor_function<PrivateImport>(image, 0xe5bd0)(
        context, encoding.size(), encoding.data(), &private_key) == 0);
    assert(private_key);

    std::array<uint8_t, 32> hash{};
    for(size_t i = 0; i < hash.size(); ++i) hash[i] = i + 1;
    std::array<uint8_t, 145> signature{};
    uint32_t signature_size = 0;
    assert(vendor_function<Sign>(image, 0xe7000)(
        context, private_key, hash.data(), hash.size(), nullptr,
        &signature_size) == 0x74);
    assert(signature_size == signature.size());

    /* This invokes the vendor's own ECCPRIVATEBLOB construction, CNG import,
     * signing, and ASN.1 signature encoding. */
    assert(vendor_function<Sign>(image, 0xe7000)(
        context, private_key, hash.data(), hash.size(), signature.data(),
        &signature_size) == 0);
    assert(signature_size > 0 && signature_size <= signature.size());
    assert(vendor_function<Verify>(image, 0xe7540)(
        context, public_key, signature.data(), signature_size,
        hash.data(), hash.size()) == 0);
    hash[0] ^= 1;
    assert(vendor_function<Verify>(image, 0xe7540)(
        context, public_key, signature.data(), signature_size,
        hash.data(), hash.size()) != 0);
    vendor_function<Free>(image, 0xe3660)(&private_key);
    assert(!private_key);
    assert(encoding == original_encoding);
}

static void reject_invalid_private_key(const dll_image& image, void *context,
                                       const std::vector<uint8_t>& encoding) {
    const auto original_encoding = encoding;
    void *private_key = nullptr;
    /* The vendor import caches bytes; the CNG import occurs inside Sign. */
    assert(vendor_function<PrivateImport>(image, 0xe5bd0)(
        context, encoding.size(), encoding.data(), &private_key) == 0);
    std::array<uint8_t, 32> hash{};
    std::array<uint8_t, 145> signature{};
    uint32_t signature_size = signature.size();
    assert(vendor_function<Sign>(image, 0xe7000)(
        context, private_key, hash.data(), hash.size(), signature.data(),
        &signature_size) == 0x259);
    vendor_function<Free>(image, 0xe3660)(&private_key);
    assert(!private_key && encoding == original_encoding);
}

int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *driver = std::fopen(argv[1], "rb");
    assert(driver);
    assert(std::fseek(driver, 0, SEEK_END) == 0);
    long size = std::ftell(driver);
    assert(size > 0 && static_cast<unsigned long>(size) <= UINT32_MAX);
    assert(std::fseek(driver, 0, SEEK_SET) == 0);
    std::vector<uint8_t> driver_data(size);
    assert(std::fread(driver_data.data(), 1, driver_data.size(), driver) ==
           driver_data.size());
    assert(std::fclose(driver) == 0);

    dll_image image{};
    assert(load_dll(&image, "palcrypto-ecc-test.dll", driver_data.data(),
                    driver_data.size()));
    /* Bind the regression to the pinned ECC generation and signing imports,
     * rather than testing a native approximation of the vendor call flow. */
    assert_instruction(image, 0xe72a6, {0xe8, 0xe9, 0x0d, 0x03, 0x00});
    assert_instruction(image, 0xe7321, {0xe8, 0x86, 0x0d, 0x03, 0x00});
    assert_instruction(image, 0xe7207, {0x8b, 0x49, 0x1c});
    assert_instruction(image, 0x6df9d, {0xe8, 0x9e, 0xc2, 0x06, 0x00});

    const char *environment[] = {nullptr};
    winmodule module{};
    module.name = "palcrypto-ecc-test.dll";
    module.cmdline = "software-only-palcrypto-test";
    module.environ = environment;
    winmodule_register(&module);
    winmodule_set_cur(&module);
    win_init_tib();
    assert(image.entry_point);
    assert(reinterpret_cast<DllMain*>(image.entry_point)(
        module.handle, 1, nullptr));
    cryptbridge_identity_set_state_callbacks(
        load_identity, store_identity, nullptr);

    std::vector<uint8_t> first_encoding;
    for(unsigned round = 0; round < 2; ++round) {
        const uint32_t curve[] = {1, 256, 32};
        void *context = nullptr, *public_key = nullptr, *private_key = nullptr;
        assert(vendor_function<EccInit>(image, 0xe51b0)(curve, &context) == 0);
        const auto previous_role = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
        const DWORD generated = vendor_function<Keygen>(image, 0xe6480)(
            context, nullptr, &public_key, &private_key);
        cryptbridge_identity_end_key_role(previous_role);
        assert(generated == 0 && public_key && private_key);
        assert(identity_stores == 1 && saved_identity.size() == 104);

        std::array<uint8_t, 68> x{}, y{};
        uint32_t component_size = x.size();
        assert(vendor_function<PublicExport>(image, 0xe5f50)(
            context, &component_size, x.data(), y.data(), public_key) == 0);
        assert(component_size == 32);
        uint32_t encoding_size = 0;
        assert(vendor_function<PrivateExport>(image, 0xe6200)(
            context, &encoding_size, nullptr, private_key) == 0x74);
        assert(encoding_size == 96);
        std::vector<uint8_t> encoding(encoding_size);
        assert(vendor_function<PrivateExport>(image, 0xe6200)(
            context, &encoding_size, encoding.data(), private_key) == 0);
        assert(encoding_size == encoding.size());
        assert(!std::memcmp(encoding.data(), x.data(), component_size));
        assert(!std::memcmp(encoding.data() + component_size,
                            y.data(), component_size));
        if(round == 0) first_encoding = encoding;
        else assert(encoding == first_encoding);
        sign_and_verify(image, context, public_key, encoding);

        /* Security setup 0x6dd70 zeroes all 96 bytes and derives only d at
         * offset 64.  Its subsequent private import and signing require CNG
         * to reconstruct Q=dG when both supplied coordinates are zero. */
        std::memset(encoding.data(), 0, 2 * component_size);
        sign_and_verify(image, context, public_key, encoding);

        auto invalid_encoding = encoding;
        std::memset(invalid_encoding.data() + 2 * component_size,
                    0, component_size);
        reject_invalid_private_key(image, context, invalid_encoding);
        /* Vendor encoding reverses each CNG big-endian component. */
        const uint8_t order_le[32] = {
            0x51, 0x25, 0x63, 0xfc, 0xc2, 0xca, 0xb9, 0xf3,
            0x84, 0x9e, 0x17, 0xa7, 0xad, 0xfa, 0xe6, 0xbc,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
        };
        invalid_encoding = encoding;
        std::memcpy(invalid_encoding.data() + 2 * component_size,
                    order_le, component_size);
        reject_invalid_private_key(image, context, invalid_encoding);
        ++invalid_encoding[2 * component_size];
        reject_invalid_private_key(image, context, invalid_encoding);
        std::memset(invalid_encoding.data() + 2 * component_size,
                    0xff, component_size);
        reject_invalid_private_key(image, context, invalid_encoding);
        invalid_encoding = encoding;
        invalid_encoding[0] = 1;
        reject_invalid_private_key(image, context, invalid_encoding);
        invalid_encoding = first_encoding;
        std::memset(invalid_encoding.data() + component_size,
                    0, component_size);
        reject_invalid_private_key(image, context, invalid_encoding);
        invalid_encoding = first_encoding;
        invalid_encoding[0] ^= 1;
        reject_invalid_private_key(image, context, invalid_encoding);

        vendor_function<Free>(image, 0xe3660)(&public_key);
        vendor_function<Free>(image, 0xe3660)(&private_key);
        vendor_function<Free>(image, 0xe3660)(&context);
        assert(!public_key && !private_key && !context);
    }

    cryptbridge_identity_set_state_callbacks(nullptr, nullptr, nullptr);
    assert(reinterpret_cast<DllMain*>(image.entry_point)(
        module.handle, 0, nullptr));
    winmodule_set_cur(nullptr);
    winmodule_unregister(&module);
    destroy_dll(&image);
    return 0;
}
