#include <array>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <cryptbridge/identity.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/obj_mac.h>
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
/* These APIs resolve directly to cryptbridge's C definitions: its NTSTATUS
 * is signed and its WCHAR is unsigned short, unlike the loader's aliases. */
using NativeStatus = int32_t;
using NativeWide = uint16_t;
using OpenAlgorithm = NativeStatus __winfnc(void **, const NativeWide *,
                                            const NativeWide *, ULONG);
using ImportKey = NativeStatus __winfnc(void *, void *, const NativeWide *,
                                       void **, UCHAR *, ULONG, ULONG);
using Agreement = NativeStatus __winfnc(void *, void *, void **, ULONG);
using DestroyKey = NativeStatus __winfnc(void *);
using CloseAlgorithm = NativeStatus __winfnc(void *, ULONG);
using PalDerive = DWORD __winfnc(void *, const void *, uint32_t, void *,
                                 uint32_t, void *, uint32_t);

template<class Function>
static Function *windows_function(const char *name) {
    auto *function = reinterpret_cast<Function*>(resolve_windows_api(name));
    assert(function);
    return function;
}

static std::array<uint8_t, 32> independent_ecdh_secret(void) {
    /* Independently compute dQ from the synthetic CNG private blob. */
    assert(saved_identity.size() == 104);
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX *context = BN_CTX_new();
    BIGNUM *x = BN_bin2bn(saved_identity.data() + 8, 32, nullptr);
    BIGNUM *y = BN_bin2bn(saved_identity.data() + 40, 32, nullptr);
    BIGNUM *d = BN_bin2bn(saved_identity.data() + 72, 32, nullptr);
    BIGNUM *shared_x = BN_new();
    assert(group && context && x && y && d && shared_x);
    EC_POINT *peer = EC_POINT_new(group);
    EC_POINT *shared = EC_POINT_new(group);
    assert(peer && shared);
    assert(EC_POINT_set_affine_coordinates(group, peer, x, y, context) == 1);
    assert(EC_POINT_mul(group, shared, nullptr, peer, d, context) == 1);
    assert(EC_POINT_get_affine_coordinates(
        group, shared, shared_x, nullptr, context) == 1);
    std::array<uint8_t, 32> secret{};
    assert(BN_bn2binpad(shared_x, secret.data(), secret.size()) == 32);
    EC_POINT_free(shared);
    EC_POINT_free(peer);
    BN_clear_free(shared_x);
    BN_clear_free(d);
    BN_free(y);
    BN_free(x);
    BN_CTX_free(context);
    EC_GROUP_free(group);
    return secret;
}

static std::array<uint8_t, 32> independent_hmac(
    const std::array<uint8_t, 32>& secret,
    const std::vector<uint8_t>& message) {
    std::array<uint8_t, 32> output{};
    unsigned size = output.size();
    assert(HMAC(EVP_sha256(), secret.data(), secret.size(), message.data(),
                 message.size(), output.data(), &size));
    assert(size == output.size());
    return output;
}

static void test_tls_master_secret(const dll_image& image) {
    assert_instruction(image, 0x7b508, {0x41, 0xb8, 0x0d, 0, 0, 0});
    assert_instruction(image, 0x7b516, {0xe8, 0x75, 0x6f, 0x06, 0});
    assert_instruction(image, 0xe2645, {0x89, 0x4c, 0x04, 0x78});
    assert_instruction(image, 0xe25bc,
        {0xc7, 0x44, 0x24, 0x5c, 0x03, 0x03, 0, 0});

    void *algorithm = nullptr, *private_key = nullptr, *public_key = nullptr;
    assert(windows_function<OpenAlgorithm>("BCryptOpenAlgorithmProvider")(
        &algorithm, reinterpret_cast<const NativeWide*>(u"ECDH_P256"),
        nullptr, 0) == 0);
    const auto original_identity = saved_identity;
    assert(windows_function<ImportKey>("BCryptImportKeyPair")(
        algorithm, nullptr, reinterpret_cast<const NativeWide*>(u"ECCPRIVATEBLOB"), &private_key,
        saved_identity.data(), saved_identity.size(), 0) == 0);
    std::vector<uint8_t> public_blob(saved_identity.begin(),
                                     saved_identity.begin() + 72);
    const uint32_t public_magic = 0x314b4345;
    std::memcpy(public_blob.data(), &public_magic, sizeof(public_magic));
    assert(windows_function<ImportKey>("BCryptImportKeyPair")(
        algorithm, nullptr, reinterpret_cast<const NativeWide*>(u"ECCPUBLICBLOB"), &public_key,
        public_blob.data(), public_blob.size(), 0) == 0);

    const char label[] = "master secret";
    std::array<uint8_t, 64> seed{};
    for(size_t i = 0; i < seed.size(); ++i) seed[i] = 0x80 + i;
    const auto original_seed = seed;
    const auto secret = independent_ecdh_secret();
    /* TLS 1.2 P_SHA256, independently assembled using OpenSSL HMAC rather
     * than calling the bridge's EVP TLS1-PRF implementation. */
    std::vector<uint8_t> input(13 + seed.size());
    std::memcpy(input.data(), label, 13);
    std::memcpy(input.data() + 13, seed.data(), seed.size());
    auto a = independent_hmac(secret, input);
    std::array<uint8_t, 48> expected{};
    for(size_t offset = 0; offset < expected.size(); offset += a.size()) {
        std::vector<uint8_t> block_input(a.begin(), a.end());
        block_input.insert(block_input.end(), input.begin(), input.end());
        const auto block = independent_hmac(secret, block_input);
        const size_t remaining = expected.size() - offset;
        std::memcpy(expected.data() + offset, block.data(),
                    remaining < block.size() ? remaining : block.size());
        a = independent_hmac(secret, std::vector<uint8_t>(a.begin(), a.end()));
    }

    struct VendorBlob { uint32_t size, padding; void *data; };
    auto derive = [&](const void *label_data, uint32_t label_size,
                       uint32_t seed_size, uint32_t output_size,
                       void *output, uint32_t mode) {
        void *agreed_secret = nullptr;
        assert(windows_function<Agreement>("BCryptSecretAgreement")(
            private_key, public_key, &agreed_secret, 0) == 0);
        std::array<uint8_t, 13> encoding{};
        const uint32_t magic = 0x21485342;
        std::memcpy(encoding.data(), &magic, sizeof(magic));
        encoding[4] = sizeof(agreed_secret);
        std::memcpy(encoding.data() + 5, &agreed_secret,
                    sizeof(agreed_secret));
        const auto original_encoding = encoding;
        VendorBlob wrapped{encoding.size(), 0, encoding.data()};
        VendorBlob seed_blob{seed_size, 0, seed.data()};
        /* PAL consumes the real CNG agreed-secret handle even on a KDF
         * failure. Its initial NULL-output check occurs before consumption. */
        const DWORD status = vendor_function<PalDerive>(image, 0xe2490)(
            &wrapped, label_data, label_size, &seed_blob,
            output_size, output, mode);
        if(!output)
            assert(windows_function<DestroyKey>("BCryptDestroySecret")(
                agreed_secret) == 0);
        assert(encoding == original_encoding);
        return status;
    };

    std::array<uint8_t, 49> output{};
    for(uint32_t label_size : {13u, 14u}) {
        output.fill(0xa5);
        /* Before the bounded-label fix the real 13-byte vendor call returns
         * 0x259 here, despite the 14-byte form succeeding. */
        assert(derive(label, label_size, 64, 48, output.data(), 0) == 0);
        assert(!std::memcmp(output.data(), expected.data(), expected.size()));
        assert(output.back() == 0xa5);
    }
    assert(derive(label, 13, 63, 48, output.data(), 0) == 0x259);
    assert(derive(label, 13, 65, 48, output.data(), 0) == 0x259);
    assert(derive(label, 0, 64, 48, output.data(), 0) == 0x259);
    assert(derive(label, 13, 64, 47, output.data(), 0) == 0x259);
    assert(derive(label, 13, 64, 48, output.data(), 2) == 0x6f);
    assert(derive(label, 13, 64, 48, nullptr, 0) == 0x70);
    assert(seed == original_seed && saved_identity == original_identity);
    assert(windows_function<DestroyKey>("BCryptDestroyKey")(public_key) == 0);
    assert(windows_function<DestroyKey>("BCryptDestroyKey")(private_key) == 0);
    assert(windows_function<CloseAlgorithm>("BCryptCloseAlgorithmProvider")(
        algorithm, 0) == 0);
}

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

    test_tls_master_secret(image);
    cryptbridge_identity_set_state_callbacks(nullptr, nullptr, nullptr);
    assert(reinterpret_cast<DllMain*>(image.entry_point)(
        module.handle, 0, nullptr));
    winmodule_set_cur(nullptr);
    winmodule_unregister(&module);
    destroy_dll(&image);
    return 0;
}
