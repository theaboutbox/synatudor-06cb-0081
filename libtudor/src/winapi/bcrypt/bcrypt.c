#include <openssl/evp.h>
#include "winapi/windows.h"
// #include "windef.h"
#include "winapi/crypt/wincrypt.h"
#include "winapi/api.h"
#include "bcrypt.h"


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
WINAPI(BCryptDeriveKey)

__winfnc NTSTATUS  BCryptDestroySecret(
  BCRYPT_SECRET_HANDLE hSecret);
WINAPI(BCryptDestroySecret)
