#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <cryptbridge/registry.h>
#include "winapi/api.h"
#include "winapi/crypt/crypt.h"

#define CRYPT_VERIFYCONTEXT 0xf0000000u
#define CRYPT_NEWKEYSET     0x00000008u
#define CRYPT_DELETEKEYSET  0x00000010u
#define AT_SIGNATURE        2u
#define PUBLICKEYBLOB       0x6u
#define NTE_BAD_SIGNATURE   0x80090006u

typedef BOOL (__winfnc *crypt_acquire_w_fnc)(HCRYPTPROV *, LPCWSTR, LPCWSTR,
                                              DWORD, DWORD);

extern __winfnc BOOL CryptAcquireContextA(HCRYPTPROV *, LPCSTR, LPCSTR,
                                          DWORD, DWORD);
extern __winfnc BOOL CryptReleaseContext(HCRYPTPROV, DWORD);
extern __winfnc BOOL CryptGenRandom(HCRYPTPROV, DWORD, BYTE *);
extern __winfnc BOOL CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY *);
extern __winfnc BOOL CryptExportKey(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD,
                                    BYTE *, DWORD *);
extern __winfnc BOOL CryptDestroyKey(HCRYPTKEY);
extern __winfnc BOOL CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD,
                                     HCRYPTHASH *);
extern __winfnc BOOL CryptHashData(HCRYPTHASH, const BYTE *, DWORD, DWORD);
extern __winfnc BOOL CryptGetHashParam(HCRYPTHASH, DWORD, BYTE *, DWORD *,
                                       DWORD);
extern __winfnc BOOL CryptDestroyHash(HCRYPTHASH);
extern __winfnc BOOL CryptSignHashA(HCRYPTHASH, DWORD, LPCSTR, DWORD,
                                    BYTE *, DWORD *);
extern __winfnc BOOL CryptVerifySignatureA(HCRYPTHASH, const BYTE *, DWORD,
                                           HCRYPTKEY, LPCSTR, DWORD);
extern __winfnc DWORD GetLastError(void);

static void *registry_blob;
static size_t registry_blob_size;

static enum cryptbridge_registry_load_result
load_registry(void *context, void **data, size_t *data_size)
{
    (void) context;
    if(!registry_blob) return CRYPTBRIDGE_REGISTRY_LOAD_NOT_FOUND;
    *data = malloc(registry_blob_size);
    assert(*data);
    memcpy(*data, registry_blob, registry_blob_size);
    *data_size = registry_blob_size;
    return CRYPTBRIDGE_REGISTRY_LOAD_FOUND;
}

static bool store_registry(void *context, const void *data, size_t data_size)
{
    (void) context;
    void *copy = malloc(data_size);
    assert(copy);
    memcpy(copy, data, data_size);
    free(registry_blob);
    registry_blob = copy;
    registry_blob_size = data_size;
    return true;
}

int main(void)
{
    crypt_acquire_w_fnc acquire_w = (crypt_acquire_w_fnc)
        resolve_windows_api("CryptAcquireContextW");
    HCRYPTPROV wide_provider = 0, ansi_provider = 0;
    HCRYPTHASH hash = 0;
    const BYTE input[] = "adapter enrollment template";
    const BYTE expected[] = {
        0xb8, 0xbc, 0x92, 0x41, 0x71, 0x5f, 0x2f, 0x44, 0x69, 0xbd,
        0xfd, 0xc2, 0xbb, 0xca, 0x4c, 0x97, 0xd4, 0x76, 0x97, 0xf9
    };
    BYTE digest[20] = {0};
    BYTE first_random[32] = {0}, second_random[32] = {0};
    const BYTE zeros[32] = {0};
    DWORD digest_size = sizeof(digest);

    assert(acquire_w != NULL);
    assert(resolve_windows_api("CryptGenRandom") != NULL);
    assert(resolve_windows_api("CryptGenKey") != NULL);
    assert(resolve_windows_api("CryptExportKey") != NULL);
    assert(resolve_windows_api("CryptSignHashA") != NULL);
    assert(resolve_windows_api("CryptSignHashW") != NULL);
    assert(resolve_windows_api("CryptVerifySignatureA") != NULL);
    assert(resolve_windows_api("CryptVerifySignatureW") != NULL);

    /* Exercise the hidden rsaenh Reg* calls through the public crypto bridge:
     * a missing named container is created, persisted, and reopened. */
    cryptbridge_registry_set_state_callbacks(load_registry, store_registry,
                                               NULL);
    HCRYPTPROV named_provider = 0, verification_provider = 0;
    assert(!CryptAcquireContextA(&named_provider, "VFS key container", NULL,
                                 PROV_RSA_FULL, 0));
    assert(named_provider == 0);
    assert(CryptAcquireContextA(&named_provider, "VFS key container", NULL,
                                PROV_RSA_FULL, CRYPT_NEWKEYSET));

    HCRYPTKEY signing_key = 0;
    HCRYPTHASH signing_hash = 0, verification_hash = 0;
    DWORD public_blob_size = 0, signature_size = 0;
    BYTE *public_blob, *signature;

    assert(CryptGenKey(named_provider, AT_SIGNATURE,
                       CRYPT_EXPORTABLE | (1024u << 16), &signing_key));
    assert(signing_key != 0);
    assert(CryptExportKey(signing_key, 0, PUBLICKEYBLOB, 0, NULL,
                          &public_blob_size));
    assert(public_blob_size > sizeof(BLOBHEADER));
    public_blob = malloc(public_blob_size);
    assert(public_blob);
    assert(CryptExportKey(signing_key, 0, PUBLICKEYBLOB, 0, public_blob,
                          &public_blob_size));
    assert(((BLOBHEADER *)public_blob)->bType == PUBLICKEYBLOB);
    free(public_blob);

    assert(CryptCreateHash(named_provider, CALG_SHA_256, 0, 0,
                           &signing_hash));
    assert(CryptHashData(signing_hash, input, sizeof(input) - 1, 0));
    assert(CryptSignHashA(signing_hash, AT_SIGNATURE, NULL, 0, NULL,
                          &signature_size));
    assert(signature_size == 128);
    signature = malloc(signature_size);
    assert(signature);
    assert(CryptSignHashA(signing_hash, AT_SIGNATURE, NULL, 0, signature,
                          &signature_size));

    /* CryptoAPI keys can be consumed by another context for the same CSP;
     * rsaenh keeps the CSP-private handles in one shared table. */
    assert(CryptAcquireContextA(&verification_provider, NULL, NULL,
                                PROV_RSA_FULL, CRYPT_VERIFYCONTEXT));
    assert(CryptCreateHash(verification_provider, CALG_SHA_256, 0, 0,
                           &verification_hash));
    assert(CryptHashData(verification_hash, input, sizeof(input) - 1, 0));
    assert(CryptVerifySignatureA(verification_hash, signature, signature_size,
                                 signing_key, NULL, 0));
    signature[0] ^= 1;
    assert(!CryptVerifySignatureA(verification_hash, signature,
                                  signature_size, signing_key, NULL, 0));
    assert(GetLastError() == NTE_BAD_SIGNATURE);
    free(signature);
    assert(CryptDestroyHash(verification_hash));
    assert(CryptReleaseContext(verification_provider, 0));
    assert(CryptDestroyHash(signing_hash));
    assert(CryptDestroyKey(signing_key));
    assert(CryptReleaseContext(named_provider, 0));
    cryptbridge_registry_set_state_callbacks(load_registry, store_registry,
                                               NULL);
    named_provider = 0;
    assert(CryptAcquireContextA(&named_provider, "VFS key container", NULL,
                                PROV_RSA_FULL, 0));
    signing_hash = 0;
    signature_size = 0;
    assert(CryptCreateHash(named_provider, CALG_SHA_256, 0, 0,
                           &signing_hash));
    assert(CryptHashData(signing_hash, input, sizeof(input) - 1, 0));
    assert(CryptSignHashA(signing_hash, AT_SIGNATURE, NULL, 0, NULL,
                          &signature_size));
    assert(signature_size == 128);
    signature = malloc(signature_size);
    assert(signature);
    assert(CryptSignHashA(signing_hash, AT_SIGNATURE, NULL, 0, signature,
                          &signature_size));
    free(signature);
    assert(CryptDestroyHash(signing_hash));
    assert(CryptReleaseContext(named_provider, 0));
    cryptbridge_registry_set_state_callbacks(NULL, NULL, NULL);
    free(registry_blob);
    registry_blob = NULL;
    registry_blob_size = 0;

    /* Failed acquisitions must not expose the temporary outer provider. */
    HCRYPTPROV failed_provider = (HCRYPTPROV) (uintptr_t) 1;
    assert(!CryptAcquireContextA(&failed_provider, "invalid-with-verify", NULL,
                                 PROV_RSA_FULL, CRYPT_VERIFYCONTEXT));
    assert(failed_provider == 0);
    failed_provider = (HCRYPTPROV) (uintptr_t) 1;
    assert(!CryptAcquireContextA(&failed_provider, NULL, NULL, PROV_RSA_FULL,
                                 CRYPT_VERIFYCONTEXT | CRYPT_DELETEKEYSET));
    assert(failed_provider == 0);

    assert(acquire_w(&wide_provider, NULL, NULL, PROV_RSA_FULL,
                     CRYPT_VERIFYCONTEXT));
    assert(CryptAcquireContextA(&ansi_provider, NULL, NULL, PROV_RSA_FULL,
                                CRYPT_VERIFYCONTEXT));
    assert(wide_provider != 0 && ansi_provider != 0);
    assert(wide_provider != ansi_provider);

    assert(CryptGenRandom(wide_provider, sizeof(first_random), first_random));
    assert(CryptGenRandom(wide_provider, sizeof(second_random),
                          second_random));
    assert(memcmp(first_random, zeros, sizeof(first_random)));
    assert(memcmp(first_random, second_random, sizeof(first_random)));
    assert(!CryptGenRandom(wide_provider, 1, NULL));
    assert(GetLastError() == ERROR_INVALID_PARAMETER);

    assert(CryptCreateHash(wide_provider, CALG_SHA1, 0, 0, &hash));
    assert(CryptHashData(hash, input, sizeof(input) - 1, 0));
    assert(CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_size, 0));
    assert(digest_size == sizeof(digest));
    assert(!memcmp(digest, expected, sizeof(digest)));
    assert(CryptDestroyHash(hash));

    assert(CryptReleaseContext(ansi_provider, 0));
    assert(CryptReleaseContext(wide_provider, 0));
    return 0;
}
