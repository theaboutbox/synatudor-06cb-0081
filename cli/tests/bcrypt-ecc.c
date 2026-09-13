#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <cryptbridge/identity.h>
#include "bcrypt_ecc_util.h"
#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "bcrypt.h"

extern void *resolve_windows_api( const char *name );
NTSTATUS WINAPI BCryptExportKey( BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE, LPCWSTR,
                                 PUCHAR, ULONG, ULONG *, ULONG );
NTSTATUS WINAPI BCryptSecretAgreement( BCRYPT_KEY_HANDLE, BCRYPT_KEY_HANDLE,
                                       void **, ULONG );
NTSTATUS WINAPI BCryptDeriveKey( void *, LPCWSTR, void *, PUCHAR, ULONG,
                                 ULONG *, ULONG );
NTSTATUS WINAPI BCryptDestroySecret( void * );
NTSTATUS WINAPI BCryptSignHash( BCRYPT_KEY_HANDLE, void *, PUCHAR, ULONG,
                                PUCHAR, ULONG, ULONG *, ULONG );

struct test_secret
{
    PUCHAR data;
    size_t size;
};

struct test_kdf_buffer
{
    ULONG size;
    ULONG type;
    void *data;
};

struct test_kdf_buffers
{
    ULONG version;
    ULONG count;
    struct test_kdf_buffer *buffers;
};

#define P256_COMPONENT_SIZE 32
#define P256_PRIVATE_BLOB_SIZE (sizeof(BCRYPT_ECCKEY_BLOB) + 3 * P256_COMPONENT_SIZE)

static void *saved_identity;
static size_t saved_identity_size;
static unsigned int identity_loads;
static unsigned int identity_stores;
static bool reject_identity_store;

static enum cryptbridge_identity_load_result load_identity(
    void *context, void **data, size_t *data_size)
{
    assert(context == &identity_loads);
    identity_loads++;
    if(!saved_identity) return CRYPTBRIDGE_IDENTITY_LOAD_NOT_FOUND;
    *data = malloc(saved_identity_size);
    assert(*data);
    memcpy(*data, saved_identity, saved_identity_size);
    *data_size = saved_identity_size;
    return CRYPTBRIDGE_IDENTITY_LOAD_FOUND;
}

static bool store_identity(void *context, const void *data, size_t data_size)
{
    assert(context == &identity_loads);
    identity_stores++;
    if(reject_identity_store) return false;
    void *copy = malloc(data_size);
    assert(copy);
    memcpy(copy, data, data_size);
    free(saved_identity);
    saved_identity = copy;
    saved_identity_size = data_size;
    return true;
}

static void enable_identity_callbacks(void)
{
    cryptbridge_identity_set_state_callbacks(
        load_identity, store_identity, &identity_loads);
}

static void test_component_padding(void)
{
    UCHAR dst[P256_COMPONENT_SIZE];
    UCHAR short_component[31];
    UCHAR exact_component[32];
    UCHAR signed_component[33];
    gnutls_datum_t datum;

    memset(short_component, 0x11, sizeof(short_component));
    datum.data = short_component;
    datum.size = sizeof(short_component);
    assert(cryptbridge_copy_be_component(dst, sizeof(dst), &datum));
    assert(dst[0] == 0);
    assert(!memcmp(dst + 1, short_component, sizeof(short_component)));

    memset(exact_component, 0x22, sizeof(exact_component));
    datum.data = exact_component;
    datum.size = sizeof(exact_component);
    assert(cryptbridge_copy_be_component(dst, sizeof(dst), &datum));
    assert(!memcmp(dst, exact_component, sizeof(exact_component)));

    signed_component[0] = 0;
    memset(signed_component + 1, 0x33, sizeof(signed_component) - 1);
    datum.data = signed_component;
    datum.size = sizeof(signed_component);
    assert(cryptbridge_copy_be_component(dst, sizeof(dst), &datum));
    assert(!memcmp(dst, signed_component + 1, sizeof(dst)));

    signed_component[0] = 1;
    assert(!cryptbridge_copy_be_component(dst, sizeof(dst), &datum));
}

static void test_random(void)
{
    BCRYPT_ALG_HANDLE algorithm;
    UCHAR first[32] = {0}, second[32] = {0};
    const UCHAR zeros[32] = {0};

    assert(!BCryptGenRandom(NULL, first, sizeof(first),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG));
    assert(memcmp(first, zeros, sizeof(first)));

    assert(!BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_RNG_ALGORITHM,
                                         MS_PRIMITIVE_PROVIDER, 0));
    assert(!BCryptGenRandom(algorithm, second, sizeof(second), 0));
    assert(memcmp(second, zeros, sizeof(second)));
    assert(memcmp(first, second, sizeof(first)));
    assert(BCryptGenRandom(NULL, second, sizeof(second), 0) ==
           STATUS_INVALID_HANDLE);
    assert(BCryptGenRandom(algorithm, NULL, 1, 0) ==
           STATUS_INVALID_PARAMETER);
    assert(!BCryptCloseAlgorithmProvider(algorithm, 0));
}

static void test_tls_prf_known_answer(void)
{
    /* OpenSSL's TLS 1.2 PRF-SHA256 known-answer vector, sourced from NIST. */
    UCHAR secret_bytes[] = {
        0xf8, 0x93, 0x8e, 0xcc, 0x9e, 0xde, 0xbc, 0x50,
        0x30, 0xc0, 0xc6, 0xa4, 0x41, 0xe2, 0x13, 0xcd,
        0x24, 0xe6, 0xf7, 0x70, 0xa5, 0x0d, 0xda, 0x07,
        0x87, 0x6f, 0x8d, 0x55, 0xda, 0x06, 0x2b, 0xca,
        0xdb, 0x38, 0x6b, 0x41, 0x1f, 0xd4, 0xfe, 0x43,
        0x13, 0xa6, 0x04, 0xfc, 0xe6, 0xc1, 0x7f, 0xbc,
    };
    UCHAR seed[] = {
        0x36, 0xc1, 0x29, 0xd0, 0x1a, 0x32, 0x00, 0x89,
        0x4b, 0x91, 0x79, 0xfa, 0xac, 0x58, 0x9d, 0x98,
        0x35, 0xd5, 0x87, 0x75, 0xf9, 0xb5, 0xea, 0x35,
        0x87, 0xcb, 0x8f, 0xd0, 0x36, 0x4c, 0xae, 0x8c,
        0xf6, 0xc9, 0x57, 0x5e, 0xd7, 0xdd, 0xd7, 0x3e,
        0x1f, 0x7d, 0x16, 0xec, 0xa1, 0x15, 0x41, 0x58,
        0x12, 0xa4, 0x3c, 0x2b, 0x74, 0x7d, 0xaa, 0xaa,
        0xe0, 0x43, 0xab, 0xfb, 0x50, 0x05, 0x3f, 0xce,
    };
    const UCHAR expected[] = {
        0x20, 0x2c, 0x88, 0xc0, 0x0f, 0x84, 0xa1, 0x7a,
        0x20, 0x02, 0x70, 0x79, 0x60, 0x47, 0x87, 0x46,
        0x11, 0x76, 0x45, 0x55, 0x39, 0xe7, 0x05, 0xbe,
        0x73, 0x08, 0x90, 0x60, 0x2c, 0x28, 0x9a, 0x50,
        0x01, 0xe3, 0x4e, 0xeb, 0x3a, 0x04, 0x3e, 0x5d,
        0x52, 0xa6, 0x5e, 0x66, 0x12, 0x51, 0x88, 0xbf,
    };
    UCHAR derived[sizeof(expected)];
    char label[] = "master secret";
    DWORD protocol = 0x0303;
    const WCHAR tls_prf[] = {'T','L','S','_','P','R','F',0};
    struct test_secret secret = { secret_bytes, sizeof(secret_bytes) };
    struct test_kdf_buffer kdf_buffer[] = {
        { sizeof(label), 4, label },
        { sizeof(seed), 5, seed },
        { sizeof(protocol), 7, &protocol },
    };
    struct test_kdf_buffers kdf = {
        0, sizeof(kdf_buffer) / sizeof(kdf_buffer[0]), kdf_buffer
    };
    ULONG derived_size = 0;

    assert(!BCryptDeriveKey(&secret, tls_prf, &kdf, derived,
                            sizeof(derived), &derived_size, 0));
    assert(derived_size == sizeof(derived));
    assert(!memcmp(derived, expected, sizeof(expected)));

    /* The pinned TLS caller bounds the label without including its NUL. */
    char bounded_label[sizeof(label) - 1];
    memcpy(bounded_label, label, sizeof(bounded_label));
    kdf_buffer[0].data = bounded_label;
    kdf_buffer[0].size = sizeof(bounded_label);
    memset(derived, 0xff, sizeof(derived));
    derived_size = 0;
    assert(!BCryptDeriveKey(&secret, tls_prf, &kdf, derived,
                            sizeof(derived), &derived_size, 0));
    assert(derived_size == sizeof(derived));
    assert(!memcmp(derived, expected, sizeof(expected)));
}

int main(void)
{
    BCRYPT_ALG_HANDLE algorithm;
    UCHAR previous[P256_PRIVATE_BLOB_SIZE] = {0};
    unsigned int i;

    test_component_padding();
    test_random();
    test_tls_prf_known_answer();

    assert(resolve_windows_api( "BCryptGenerateKeyPair" ));
    assert(resolve_windows_api( "BCryptFinalizeKeyPair" ));
    assert(resolve_windows_api( "BCryptExportKey" ));
    assert(resolve_windows_api( "BCryptSecretAgreement" ));
    assert(!BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_ECDH_P256_ALGORITHM,
                                         MS_PRIMITIVE_PROVIDER, 0 ));

    for (i = 0; i < 64; ++i)
    {
        BCRYPT_KEY_HANDLE generated, imported;
        BCRYPT_ECCKEY_BLOB *header;
        UCHAR blob[P256_PRIVATE_BLOB_SIZE];
        ULONG blob_size = 0;

        assert(!BCryptGenerateKeyPair( algorithm, &generated, 256, 0 ));
        assert(!BCryptFinalizeKeyPair( generated, 0 ));
        assert(BCryptFinalizeKeyPair( generated, 0 ) == STATUS_INVALID_HANDLE);
        assert(!BCryptExportKey( generated, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 NULL, 0, &blob_size, 0 ));
        assert(blob_size == sizeof(blob));
        assert(!BCryptExportKey( generated, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 blob, sizeof(blob), &blob_size, 0 ));

        header = (BCRYPT_ECCKEY_BLOB *)blob;
        assert(header->dwMagic == BCRYPT_ECDH_PRIVATE_P256_MAGIC);
        assert(header->cbKey == P256_COMPONENT_SIZE);
        if (i) assert(memcmp(previous, blob, sizeof(blob)));
        memcpy(previous, blob, sizeof(blob));

        assert(!BCryptImportKeyPair( algorithm, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                     &imported, blob, sizeof(blob), 0 ));
        assert(!BCryptDestroyKey( imported ));
        assert(!BCryptDestroyKey( generated ));
    }

    {
        BCRYPT_KEY_HANDLE first, second;
        UCHAR first_blob[P256_PRIVATE_BLOB_SIZE];
        UCHAR second_blob[P256_PRIVATE_BLOB_SIZE];
        ULONG blob_size = 0;

        /* Registered persistence alone never changes generic or TLS-style
         * generation. */
        enable_identity_callbacks();
        assert(!BCryptGenerateKeyPair( algorithm, &first, 256, 0 ));
        assert(!BCryptFinalizeKeyPair( first, 0 ));
        assert(!BCryptExportKey( first, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 first_blob, sizeof(first_blob), &blob_size, 0 ));
        assert(blob_size == sizeof(first_blob));

        enable_identity_callbacks();
        assert(!BCryptGenerateKeyPair( algorithm, &second, 256, 0 ));
        assert(!BCryptFinalizeKeyPair( second, 0 ));
        assert(!BCryptExportKey( second, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 second_blob, sizeof(second_blob), &blob_size,
                                 0 ));
        assert(blob_size == sizeof(second_blob));
        assert(memcmp(first_blob, second_blob, sizeof(first_blob)));
        assert(identity_loads == 0 && identity_stores == 0);
        assert(!saved_identity);

        assert(!BCryptDestroyKey( second ));
        assert(!BCryptDestroyKey( first ));
        cryptbridge_identity_set_state_callbacks(NULL, NULL, NULL);
    }

    {
        BCRYPT_KEY_HANDLE first, second, one_shot, corrupted;
        UCHAR first_blob[P256_PRIVATE_BLOB_SIZE];
        UCHAR second_blob[P256_PRIVATE_BLOB_SIZE];
        UCHAR one_shot_blob[P256_PRIVATE_BLOB_SIZE];
        ULONG blob_size = 0;
        enum cryptbridge_identity_key_role previous, outer_previous;

        /* A pairing role persists exactly one generation and resolves the
         * same identity after a simulated replacement-host callback reset. */
        enable_identity_callbacks();
        previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
        assert(previous == CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        assert(!BCryptGenerateKeyPair( algorithm, &first, 256, 0 ));
        assert(!BCryptFinalizeKeyPair( first, 0 ));
        cryptbridge_identity_end_key_role(previous);
        previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        assert(previous == CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        cryptbridge_identity_end_key_role(previous);
        assert(!BCryptExportKey( first, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 first_blob, sizeof(first_blob), &blob_size, 0 ));
        assert(blob_size == sizeof(first_blob));
        assert(saved_identity && identity_loads == 1 && identity_stores == 1);

        enable_identity_callbacks();
        outer_previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
        assert(outer_previous == CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
        assert(previous == CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
        assert(!BCryptGenerateKeyPair( algorithm, &second, 256, 0 ));
        assert(!BCryptFinalizeKeyPair( second, 0 ));
        cryptbridge_identity_end_key_role(previous);
        assert(!BCryptExportKey( second, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 second_blob, sizeof(second_blob), &blob_size,
                                 0 ));
        assert(blob_size == sizeof(second_blob));
        assert(!memcmp(first_blob, second_blob, sizeof(first_blob)));
        assert(identity_loads == 2 && identity_stores == 1);

        /* Ending the inner scope must not restore and re-arm the consumed
         * outer pairing role.  The next generation therefore stays fresh. */
        assert(!BCryptGenerateKeyPair( algorithm, &one_shot, 256, 0 ));
        assert(!BCryptFinalizeKeyPair( one_shot, 0 ));
        cryptbridge_identity_end_key_role(outer_previous);
        previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        assert(previous == CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        cryptbridge_identity_end_key_role(previous);
        assert(!BCryptExportKey( one_shot, NULL, BCRYPT_ECCPRIVATE_BLOB,
                                 one_shot_blob, sizeof(one_shot_blob),
                                 &blob_size, 0 ));
        assert(blob_size == sizeof(one_shot_blob));
        assert(memcmp(second_blob, one_shot_blob, sizeof(second_blob)));
        assert(identity_loads == 2 && identity_stores == 1);

        /* Persisted private material is still validated before import. */
        assert(saved_identity_size == sizeof(first_blob));
        ((UCHAR *)saved_identity)[sizeof(BCRYPT_ECCKEY_BLOB)] ^= 1;
        enable_identity_callbacks();
        previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
        assert(!BCryptGenerateKeyPair( algorithm, &corrupted, 256, 0 ));
        assert(BCryptFinalizeKeyPair( corrupted, 0 ) ==
               STATUS_INVALID_PARAMETER);
        cryptbridge_identity_end_key_role(previous);
        assert(!BCryptDestroyKey( corrupted ));
        assert(identity_loads == 3 && identity_stores == 1);

        assert(!BCryptDestroyKey( one_shot ));
        assert(!BCryptDestroyKey( second ));
        assert(!BCryptDestroyKey( first ));
        cryptbridge_identity_set_state_callbacks(NULL, NULL, NULL);
        free(saved_identity);
        saved_identity = NULL;
        saved_identity_size = 0;
    }

    {
        BCRYPT_KEY_HANDLE generated;
        enum cryptbridge_identity_key_role previous;

        /* A pairing generation fails closed when durable storage rejects the
         * new identity, and its one-shot role is still consumed. */
        reject_identity_store = true;
        enable_identity_callbacks();
        previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
        assert(!BCryptGenerateKeyPair( algorithm, &generated, 256, 0 ));
        assert(BCryptFinalizeKeyPair( generated, 0 ) ==
               STATUS_INTERNAL_ERROR);
        cryptbridge_identity_end_key_role(previous);
        previous = cryptbridge_identity_begin_key_role(
            CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        assert(previous == CRYPTBRIDGE_IDENTITY_KEY_UNSCOPED);
        cryptbridge_identity_end_key_role(previous);
        assert(!BCryptDestroyKey( generated ));
        cryptbridge_identity_set_state_callbacks(NULL, NULL, NULL);
        reject_identity_store = false;
        assert(!saved_identity);
    }

    {
        BCRYPT_KEY_HANDLE first, second, first_public, second_public;
        void *first_secret, *second_secret;
        struct test_secret *first_data, *second_data;
        UCHAR first_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 2 * P256_COMPONENT_SIZE];
        UCHAR second_blob[sizeof(BCRYPT_ECCKEY_BLOB) + 2 * P256_COMPONENT_SIZE];
        UCHAR first_derived[48], second_derived[48], seed[64];
        char label[] = "TUDOR secure channel";
        DWORD protocol = 0x0303;
        const WCHAR tls_prf[] = {'T','L','S','_','P','R','F',0};
        struct test_kdf_buffer kdf_buffer[] = {
            { sizeof(label), 4, label },
            { sizeof(seed), 5, seed },
            { sizeof(protocol), 7, &protocol },
        };
        struct test_kdf_buffers kdf = {
            0, sizeof(kdf_buffer) / sizeof(kdf_buffer[0]), kdf_buffer
        };
        BCRYPT_ECCKEY_BLOB *header;
        ULONG blob_size = 0, derived_size = 0;

        memset(seed, 0x5a, sizeof(seed));

        assert(!BCryptGenerateKeyPair( algorithm, &first, 256, 0 ));
        assert(!BCryptGenerateKeyPair( algorithm, &second, 256, 0 ));
        assert(!BCryptFinalizeKeyPair( first, 0 ));
        assert(!BCryptFinalizeKeyPair( second, 0 ));

        assert(!BCryptExportKey( first, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                 first_blob, sizeof(first_blob), &blob_size, 0 ));
        assert(blob_size == sizeof(first_blob));
        header = (BCRYPT_ECCKEY_BLOB *)first_blob;
        assert(header->dwMagic == BCRYPT_ECDH_PUBLIC_P256_MAGIC);
        assert(header->cbKey == P256_COMPONENT_SIZE);
        assert(!BCryptExportKey( second, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                 second_blob, sizeof(second_blob), &blob_size, 0 ));
        assert(blob_size == sizeof(second_blob));

        assert(!BCryptImportKeyPair( algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                     &first_public, first_blob,
                                     sizeof(first_blob), 0 ));
        assert(!BCryptImportKeyPair( algorithm, NULL, BCRYPT_ECCPUBLIC_BLOB,
                                     &second_public, second_blob,
                                     sizeof(second_blob), 0 ));
        assert(!BCryptSecretAgreement( first, second_public,
                                       &first_secret, 0 ));
        assert(!BCryptSecretAgreement( second, first_public,
                                       &second_secret, 0 ));

        first_data = first_secret;
        second_data = second_secret;
        assert(first_data->size == P256_COMPONENT_SIZE);
        assert(second_data->size == P256_COMPONENT_SIZE);
        assert(!memcmp(first_data->data, second_data->data, P256_COMPONENT_SIZE));

        assert(!BCryptDeriveKey(first_secret, tls_prf, &kdf, NULL, 0,
                                &derived_size, 0));
        assert(derived_size == sizeof(first_derived));
        assert(BCryptDeriveKey(first_secret, tls_prf, &kdf, first_derived,
                               sizeof(first_derived) - 1, &derived_size, 0) ==
               STATUS_BUFFER_TOO_SMALL);
        assert(!BCryptDeriveKey(first_secret, tls_prf, &kdf, first_derived,
                                sizeof(first_derived), &derived_size, 0));
        assert(!BCryptDeriveKey(second_secret, tls_prf, &kdf, second_derived,
                                sizeof(second_derived), &derived_size, 0));
        assert(!memcmp(first_derived, second_derived, sizeof(first_derived)));

        assert(!BCryptDestroySecret( first_secret ));
        assert(!BCryptDestroySecret( second_secret ));
        assert(!BCryptDestroyKey( first_public ));
        assert(!BCryptDestroyKey( second_public ));
        assert(!BCryptDestroyKey( first ));
        assert(!BCryptDestroyKey( second ));
    }

    {
        BCRYPT_ALG_HANDLE signing_algorithm;
        BCRYPT_KEY_HANDLE signing_key;
        BCRYPT_ECCKEY_BLOB *header = (BCRYPT_ECCKEY_BLOB *)previous;
        UCHAR hash[P256_COMPONENT_SIZE];
        UCHAR first_signature[2 * P256_COMPONENT_SIZE];
        UCHAR second_signature[2 * P256_COMPONENT_SIZE];
        ULONG signature_size = 0;

        memset(hash, 0xa5, sizeof(hash));
        header->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;

        assert(!BCryptOpenAlgorithmProvider( &signing_algorithm,
                                             BCRYPT_ECDSA_P256_ALGORITHM,
                                             MS_PRIMITIVE_PROVIDER, 0 ));
        assert(!BCryptImportKeyPair( signing_algorithm, NULL,
                                     BCRYPT_ECCPRIVATE_BLOB, &signing_key,
                                     previous, sizeof(previous), 0 ));

        assert(!BCryptSignHash( signing_key, NULL, hash, sizeof(hash),
                                NULL, 0, &signature_size, 0 ));
        assert(signature_size == sizeof(first_signature));
        assert(BCryptSignHash( signing_key, NULL, hash, sizeof(hash),
                               first_signature, sizeof(first_signature) - 1,
                               &signature_size, 0 ) == STATUS_BUFFER_TOO_SMALL);
        assert(!BCryptSignHash( signing_key, NULL, hash, sizeof(hash),
                                first_signature, sizeof(first_signature),
                                &signature_size, 0 ));
        assert(!BCryptSignHash( signing_key, NULL, hash, sizeof(hash),
                                second_signature, sizeof(second_signature),
                                &signature_size, 0 ));
        assert(memcmp(first_signature, second_signature,
                      P256_COMPONENT_SIZE));
        assert(!BCryptVerifySignature( signing_key, NULL, hash, sizeof(hash),
                                       first_signature, sizeof(first_signature),
                                       0 ));
        assert(!BCryptVerifySignature( signing_key, NULL, hash, sizeof(hash),
                                       second_signature,
                                       sizeof(second_signature), 0 ));
        first_signature[0] ^= 1;
        assert(BCryptVerifySignature( signing_key, NULL, hash, sizeof(hash),
                                      first_signature,
                                      sizeof(first_signature), 0 ) ==
               STATUS_INVALID_SIGNATURE);

        assert(!BCryptDestroyKey( signing_key ));
        assert(!BCryptCloseAlgorithmProvider( signing_algorithm, 0 ));
    }

    assert(!BCryptCloseAlgorithmProvider( algorithm, 0 ));
    return 0;
}
