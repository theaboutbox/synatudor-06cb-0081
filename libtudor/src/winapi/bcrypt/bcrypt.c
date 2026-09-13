#include <openssl/evp.h>
#include <cryptbridge/identity.h>
#include "winapi/windows.h"
// #include "windef.h"
#include "winapi/crypt/wincrypt.h"
#include "winapi/api.h"
#include "bcrypt.h"
#include "loader.h"

/* These two sites are the only direct callers of palCryptoEccKeypairGenerate
 * in the pinned synaWudfBioUsb.dll.  The security-management site generates
 * the pairing identity; the TLS site generates an ephemeral ECDH key. */
#define SYNA_KEYPAIR_GENERATE_RVA 0x0e6480u
#define SYNA_PAIRING_KEYGEN_CALL_RVA 0x06d00bu
#define SYNA_TLS_KEYGEN_CALL_RVA 0x07e9d2u
#define SYNA_PROCESS_PAIRING_CALL_RVA 0x021d34u
#define SYNA_PROCESS_PAIRING_RVA 0x023738u

typedef DWORD (__winfnc *syna_keypair_generate_fnc)(
    void *curve, void *seed, void **public_key, void **private_key);

static void *syna_keypair_generate_target;

static __winfnc DWORD syna_pairing_keypair_generate(
    void *curve, void *seed, void **public_key, void **private_key)
{
    syna_keypair_generate_fnc generate =
        (syna_keypair_generate_fnc)syna_keypair_generate_target;
    if(!generate) {
        log_error("Pinned pairing key generation target is unavailable");
        return (DWORD)STATUS_INTERNAL_ERROR;
    }

    log_info("Pinned pairing key generation started");
    enum cryptbridge_identity_key_role previous =
        cryptbridge_identity_begin_key_role(CRYPTBRIDGE_IDENTITY_KEY_PAIRING);
    DWORD result = generate(curve, seed, public_key, private_key);
    cryptbridge_identity_end_key_role(previous);
    log_info("Pinned pairing key generation returned status 0x%x", result);
    return result;
}

static struct dll_callsite_hook syna_pairing_keygen_hook = {
    .image_name = "synaWudfBioUsb.dll",
    .call_rva = SYNA_PAIRING_KEYGEN_CALL_RVA,
    .expected_target_rva = SYNA_KEYPAIR_GENERATE_RVA,
    .expected_instruction = {0xe8, 0x70, 0x94, 0x07, 0x00},
    .replacement = &syna_pairing_keypair_generate,
    .original_target = &syna_keypair_generate_target,
};

/* Validation-only: this call must remain pointed directly at the shared
 * helper, outside the pairing role scope. */
static struct dll_callsite_hook syna_tls_keygen_validation = {
    .image_name = "synaWudfBioUsb.dll",
    .call_rva = SYNA_TLS_KEYGEN_CALL_RVA,
    .expected_target_rva = SYNA_KEYPAIR_GENERATE_RVA,
    .expected_instruction = {0xe8, 0xa9, 0x7a, 0x06, 0x00},
};

typedef DWORD (__winfnc *syna_process_pairing_fnc)(void *device);
static void *syna_process_pairing_target;

static __winfnc DWORD syna_process_pairing_observe(void *device)
{
    syna_process_pairing_fnc process =
        (syna_process_pairing_fnc)syna_process_pairing_target;
    if(!process) {
        log_error("Pinned pairing worker target is unavailable");
        return (DWORD)STATUS_INTERNAL_ERROR;
    }

    log_info("Pinned pairing worker started");
    DWORD result = process(device);
    log_info("Pinned pairing worker returned status 0x%x", result);
    return result;
}

/* ProcessPairing preserves a failed DoPairing result and can also fail at
 * later initialization stages. Observe the pinned worker's terminal status
 * without changing its behavior or logging device/context/key data. */
static struct dll_callsite_hook syna_process_pairing_observer = {
    .image_name = "synaWudfBioUsb.dll",
    .call_rva = SYNA_PROCESS_PAIRING_CALL_RVA,
    .expected_target_rva = SYNA_PROCESS_PAIRING_RVA,
    .expected_instruction = {0xe8, 0xff, 0x19, 0x00, 0x00},
    .replacement = &syna_process_pairing_observe,
    .original_target = &syna_process_pairing_target,
};

__constr static void register_syna_keygen_callsite_hooks(void)
{
    dll_register_callsite_hook(&syna_pairing_keygen_hook);
    dll_register_callsite_hook(&syna_tls_keygen_validation);
    dll_register_callsite_hook(&syna_process_pairing_observer);
}


__winfnc NTSTATUS  BCryptOpenAlgorithmProvider( BCRYPT_ALG_HANDLE *handle, LPCWSTR id, LPCWSTR implementation, DWORD flags );
WINAPI(BCryptOpenAlgorithmProvider)



__winfnc NTSTATUS BCryptGenerateKeyPair(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE *, ULONG, ULONG);
WINAPI(BCryptGenerateKeyPair)

__winfnc NTSTATUS  BCryptFinalizeKeyPair(BCRYPT_KEY_HANDLE, ULONG);
WINAPI(BCryptFinalizeKeyPair)

__winfnc NTSTATUS  BCryptDestroyKey(BCRYPT_KEY_HANDLE);
WINAPI(BCryptDestroyKey)

__winfnc NTSTATUS  BCryptExportKey( BCRYPT_KEY_HANDLE export_key, BCRYPT_KEY_HANDLE encrypt_key, LPCWSTR type,
                                 PUCHAR output, ULONG output_len, ULONG *size, ULONG flags );
WINAPI(BCryptExportKey)

__winfnc NTSTATUS  BCryptCloseAlgorithmProvider( BCRYPT_ALG_HANDLE handle, DWORD flags );
WINAPI(BCryptCloseAlgorithmProvider)

__winfnc NTSTATUS  BCryptImportKeyPair( BCRYPT_ALG_HANDLE algorithm, BCRYPT_KEY_HANDLE decrypt_key, const WCHAR *type,
                                     BCRYPT_KEY_HANDLE *ret_key, UCHAR *input, ULONG input_len, ULONG flags );
WINAPI(BCryptImportKeyPair)

__winfnc NTSTATUS  BCryptSignHash(
  BCRYPT_KEY_HANDLE hKey,
  void              *pPaddingInfo,
  PUCHAR            pbInput,
  ULONG             cbInput,
  PUCHAR            pbOutput,
  ULONG             cbOutput,
  ULONG             *pcbResult,
  ULONG             dwFlags
);
WINAPI(BCryptSignHash)

__winfnc NTSTATUS  BCryptVerifySignature(BCRYPT_KEY_HANDLE, void *, UCHAR *, ULONG, UCHAR *, ULONG, ULONG);
WINAPI(BCryptVerifySignature)

__winfnc NTSTATUS  BCryptSecretAgreement(
  BCRYPT_KEY_HANDLE    hPrivKey,
  BCRYPT_KEY_HANDLE    hPubKey,
  void* *phAgreedSecret,
  ULONG                dwFlags
);
WINAPI(BCryptSecretAgreement)

typedef struct _BCryptBuffer {
  ULONG cbBuffer;
  ULONG BufferType;
  PVOID pvBuffer;
} BCryptBuffer, *PBCryptBuffer;

typedef struct _BCryptBufferDesc {
  ULONG         ulVersion;
  ULONG         cBuffers;
  PBCryptBuffer pBuffers;
} BCryptBufferDesc, *PBCryptBufferDesc;

typedef void *BCRYPT_SECRET_HANDLE;

__winfnc NTSTATUS  BCryptDeriveKey(
  BCRYPT_SECRET_HANDLE hSharedSecret,
  LPCWSTR              pwszKDF,
  BCryptBufferDesc     *pParameterList,
  PUCHAR               pbDerivedKey,
  ULONG                cbDerivedKey,
  ULONG                *pcbResult,
  ULONG                dwFlags
);
/* Observe only the result of TLS derivation; labels, secrets, and output bytes
 * must never enter the service log. Preserve the CNG return value unchanged. */
static __winfnc NTSTATUS tudor_bcrypt_derive_key(
    BCRYPT_SECRET_HANDLE secret, LPCWSTR kdf, BCryptBufferDesc *parameters,
    PUCHAR output, ULONG output_size, ULONG *result_size, ULONG flags)
{
    NTSTATUS result = BCryptDeriveKey(secret, kdf, parameters, output,
                                     output_size, result_size, flags);
    log_info("TLS key derivation returned status 0x%x", (unsigned int)result);
    return result;
}

static struct __winapi_descr tudor_bcrypt_derive_key_descr = {
    .name = "BCryptDeriveKey",
    .func = &tudor_bcrypt_derive_key,
};

__constr static void register_tudor_bcrypt_derive_key(void)
{
    __register_windows_api(&tudor_bcrypt_derive_key_descr);
}

__winfnc NTSTATUS  BCryptDestroySecret(
  BCRYPT_SECRET_HANDLE hSecret);
WINAPI(BCryptDestroySecret)
