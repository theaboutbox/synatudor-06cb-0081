#ifndef LIBTUDOR_WINAPI_CRYPT_CRYPT_H
#define LIBTUDOR_WINAPI_CRYPT_CRYPT_H

#include <tudor/libcrypto.h>
#include "wincrypt.h"
#include "winapi/api.h"

struct crypt_provider;
struct crypt_key;

typedef BOOL crypt_import_key_fnc(struct crypt_provider *prov, const BLOBHEADER *data, size_t data_size, DWORD dwFlags, void **key);
typedef void crypt_destroy_key_fnc(struct crypt_provider *prov, void *key);
typedef BOOL crypt_set_key_fnc(struct crypt_provider* prov, void** key, DWORD dwParam, const BYTE *pbData, DWORD dwFlags);

#define RSAENH_PERSONALITY_BASE        0u
#define RSAENH_PERSONALITY_STRONG      1u
#define RSAENH_PERSONALITY_ENHANCED    2u
#define RSAENH_PERSONALITY_SCHANNEL    3u
#define RSAENH_PERSONALITY_AES         4u

#define RSAENH_MAGIC_CONTAINER         0x26384993u

#define RSAENH_MAGIC_KEY           0x73620457u
#define RSAENH_MAX_KEY_SIZE        64
#define RSAENH_MAX_BLOCK_SIZE      24
#define RSAENH_KEYSTATE_IDLE       0
#define RSAENH_KEYSTATE_ENCRYPTING 1
#define RSAENH_KEYSTATE_MASTERKEY  2

#define CRYPT_IPSEC_HMAC_KEY 0x0100

#define CRYPT_MODE_CBC          1
#define CRYPT_MODE_ECB          2
#define CRYPT_MODE_OFB          3
#define CRYPT_MODE_CFB          4

#define CRYPT_EXPORTABLE        0x00000001
#define CRYPT_USER_PROTECTED    0x00000002
#define CRYPT_CREATE_SALT       0x00000004
#define CRYPT_UPDATE_KEY        0x00000008
#define CRYPT_NO_SALT           0x00000010
#define CRYPT_PREGEN            0x00000040
#define CRYPT_SERVER            0x00000400
#define CRYPT_ARCHIVABLE        0x00004000

#define CRYPT_ENCRYPT           0x0001 
#define CRYPT_DECRYPT           0x0002
#define CRYPT_EXPORT            0x0004
#define CRYPT_READ              0x0008
#define CRYPT_WRITE             0x0010
#define CRYPT_MAC               0x0020
#define CRYPT_EXPORT_KEY        0x0040
#define CRYPT_IMPORT_KEY        0x0080
#define CRYPT_ARCHIVE           0x0100

#define MAX_PATH  256

typedef DATA_BLOB CRYPT_DATA_BLOB, *PCRYPT_DATA_BLOB;

struct tagOBJECTHDR;
typedef struct tagOBJECTHDR OBJECTHDR;

typedef void (*DESTRUCTOR)(OBJECTHDR *object);
struct tagOBJECTHDR
{
    DWORD       dwType;
    LONG        refcount;
    DESTRUCTOR  destructor;
};

typedef struct DUMMY_PAD { uint8_t pad[16]; } DUMMY_PAD;

typedef struct _SCHANNEL_ALG {
  DWORD  dwUse;
  ALG_ID Algid;
  DWORD  cBits;
  DWORD  dwFlags;
  DWORD  dwReserved;
} SCHANNEL_ALG, *PSCHANNEL_ALG;

typedef struct _RSAENH_SCHANNEL_INFO 
{
    SCHANNEL_ALG saEncAlg;
    SCHANNEL_ALG saMACAlg;
    CRYPT_DATA_BLOB blobClientRandom;
    CRYPT_DATA_BLOB blobServerRandom;
} RSAENH_SCHANNEL_INFO;

typedef DUMMY_PAD KEY_CONTEXT;

typedef unsigned int ALG_ID;
typedef ULONG_PTR HCRYPTPROV;
typedef ULONG_PTR HINSTANCE;
typedef ULONG_PTR HCRYPTPROV_OR_NCRYPT_KEY_HANDLE;
typedef ULONG_PTR HCRYPTPROV_LEGACY;
typedef ULONG_PTR HCRYPTKEY;
typedef ULONG_PTR HCRYPTHASH;
typedef ULONG_PTR HMODULE;
typedef void *HCERTSTORE;
typedef void *HCRYPTMSG;
typedef void *HCERTSTOREPROV;
typedef void *HCRYPTOIDFUNCSET;
typedef void *HCRYPTOIDFUNCADDR;
typedef void *HCRYPTDEFAULTCONTEXT;
typedef const char* LPCSTR;

typedef struct tagKEYCONTAINER
{
    OBJECTHDR    header;
    DWORD        dwFlags;
    DWORD        dwPersonality;
    DWORD        dwEnumAlgsCtr;
    DWORD        dwEnumContainersCtr;
    CHAR         szName[MAX_PATH];
    CHAR         szProvName[MAX_PATH];
    HCRYPTKEY    hKeyExchangeKeyPair;
    HCRYPTKEY    hSignatureKeyPair;
} KEYCONTAINER;

struct crypt_provider {
    crypt_import_key_fnc *import_key;
    crypt_destroy_key_fnc *destroy_key;
    crypt_set_key_fnc *set_key;

    KEYCONTAINER key_container;
};

struct crypt_key {
    struct crypt_provider *prov;
    void *key_data;  // CRYPTKEY*

    void *plain_data;
    size_t plain_size;
};

extern struct crypt_provider crypt_prov_rsa_aes;

struct crypt_hash_algorithm;
struct crypt_hash;

typedef BOOL crypt_create_hash_fnc(struct crypt_hash_algorithm *algo, struct crypt_key *key, void **hash);
typedef BOOL crypt_duplicate_hash_fnc(struct crypt_hash_algorithm *algo, void *hash, void **nhash);
typedef BOOL crypt_get_hash_param_fnc(struct crypt_hash_algorithm *algo, void *hash, DWORD param, void *data, size_t *data_size);
typedef BOOL crypt_set_hash_param_fnc(struct crypt_hash_algorithm *algo, void *hash, DWORD param, const void *data);
typedef BOOL crypt_update_hash_fnc(struct crypt_hash_algorithm *algo, void *hash, const void *data, size_t data_size);
typedef void crypt_destroy_hash_fnc(struct crypt_hash_algorithm *algo, void *hash);

struct crypt_hash_algorithm {
    crypt_create_hash_fnc *create_hash;
    crypt_duplicate_hash_fnc *duplicate_hash;
    crypt_get_hash_param_fnc *get_hash_param;
    crypt_set_hash_param_fnc *set_hash_param;
    crypt_update_hash_fnc *update_hash;
    crypt_destroy_hash_fnc *destroy_hash;
};

struct crypt_hash {
    struct crypt_hash_algorithm *algo;
    void *hash_data;
};

extern struct evp_md_algorithm crypt_hash_algo_sha1, crypt_hash_algo_sha256, crypt_hash_algo_sha384, crypt_hash_algo_sha512;
extern struct crypt_hash_algorithm crypt_hash_algo_hmac;

typedef void* FARPROC;
typedef char* LPSTR;
typedef char16_t* LPCWSTR;

typedef struct _VTableProvStruc {
    DWORD    Version;
#ifdef WINE_STRICT_PROTOTYPES
    BOOL     (WINAPI *FuncVerifyImage)(LPCSTR,BYTE*);
    void     (WINAPI *FuncReturnhWnd)(HWND*);
#else
    FARPROC  FuncVerifyImage;
    FARPROC  FuncReturnhWnd;
#endif
    DWORD    dwProvType;
    BYTE    *pbContextInfo;
    DWORD    cbContextInfo;
    LPSTR    pszProvName;
} VTableProvStruc, *PVTableProvStruc;


typedef struct tagPROVFUNCS
{
	BOOL (*pCPAcquireContext)(HCRYPTPROV *phProv, LPSTR pszContainer, DWORD dwFlags, PVTableProvStruc pVTable);
	BOOL (*pCPCreateHash)(HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);
	BOOL (*pCPDecrypt)(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
	BOOL (*pCPDeriveKey)(HCRYPTPROV hProv, ALG_ID     Algid, HCRYPTHASH hBaseData, DWORD dwFlags, HCRYPTKEY *phKey);
	BOOL (*pCPDestroyHash)(HCRYPTPROV hProv, HCRYPTHASH hHash);
	BOOL (*pCPDestroyKey)(HCRYPTPROV hProv, HCRYPTKEY hKey);
	BOOL (*pCPDuplicateHash)(HCRYPTPROV hUID, HCRYPTHASH hHash, DWORD *pdwReserved, DWORD dwFlags, HCRYPTHASH *phHash);
	BOOL (*pCPDuplicateKey)(HCRYPTPROV hUID, HCRYPTKEY hKey, DWORD *pdwReserved, DWORD dwFlags, HCRYPTKEY *phKey);
	BOOL (*pCPEncrypt)(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen);
	BOOL (*pCPExportKey)(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTKEY hPubKey, DWORD dwBlobType, DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);
	BOOL (*pCPGenKey)(HCRYPTPROV hProv, ALG_ID Algid, DWORD dwFlags, HCRYPTKEY *phKey);
	BOOL (*pCPGenRandom)(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);
	BOOL (*pCPGetHashParam)(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
	BOOL (*pCPGetKeyParam)(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
	BOOL (*pCPGetProvParam)(HCRYPTPROV hProv, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);
	BOOL (*pCPGetUserKey)(HCRYPTPROV hProv, DWORD dwKeySpec, HCRYPTKEY *phUserKey);
	BOOL (*pCPHashData)(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);
	BOOL (*pCPHashSessionKey)(HCRYPTPROV hProv, HCRYPTHASH hHash, HCRYPTKEY hKey, DWORD dwFlags);
	BOOL (*pCPImportKey)(HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey);
	BOOL (*pCPReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);
	BOOL (*pCPSetHashParam)(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, const BYTE *pbData, DWORD dwFlags);
	BOOL (*pCPSetKeyParam)(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, const BYTE *pbData, DWORD dwFlags);
	BOOL (*pCPSetProvParam)(HCRYPTPROV hProv, DWORD dwParam, const BYTE *pbData, DWORD dwFlags);
	BOOL (*pCPSignHash)(HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwKeySpec, LPCWSTR sDescription, DWORD dwFlags, BYTE *pbSignature, DWORD *pdwSigLen);
	BOOL (*pCPVerifySignature)(HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbSignature, DWORD dwSigLen, HCRYPTKEY hPubKey, LPCWSTR sDescription, DWORD dwFlags);
} PROVFUNCS, *PPROVFUNCS;

#define MAGIC_CRYPTPROV 0xA39E741F
#define MAGIC_CRYPTKEY  0xA39E741E
#define MAGIC_CRYPTHASH 0xA39E741D

typedef struct tagCRYPTPROV
{
	DWORD dwMagic;
	UINT refcount;
	HMODULE hModule;
	PPROVFUNCS pFuncs;
    HCRYPTPROV hPrivate;  /*CSP's handle - Should not be given to application under any circumstances!*/
	PVTableProvStruc pVTable;
} CRYPTPROV, *PCRYPTPROV;

typedef struct tagCRYPTKEY
{
	DWORD dwMagic;
	PCRYPTPROV pProvider;
    HCRYPTKEY hPrivate;    /*CSP's handle - Should not be given to application under any circumstances!*/
} CRYPTKEY, *PCRYPTKEY;

typedef struct tagCRYPTHASH
{
	DWORD dwMagic;
	PCRYPTPROV pProvider;
        HCRYPTHASH hPrivate;    /*CSP's handle - Should not be given to application under any circumstances!*/
} CRYPTHASH, *PCRYPTHASH;

#define MAXPROVTYPES 999

// extern unsigned char *CRYPT_DEShash( unsigned char *dst, const unsigned char *key,
//                                      const unsigned char *src ) DECLSPEC_HIDDEN;
// extern unsigned char *CRYPT_DESunhash( unsigned char *dst, const unsigned char *key,
//                                        const unsigned char *src ) DECLSPEC_HIDDEN;

struct ustring {
    DWORD Length;
    DWORD MaximumLength;
    unsigned char *Buffer;
};


#endif
