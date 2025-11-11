#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include "crypt.h"
#include "assert.h"

struct protect_data_t
{
    DWORD       count0;
    DATA_BLOB   info0;        /* using this to hold crypt_magic_str */
    DWORD       count1;
    DATA_BLOB   info1;
    DWORD       null0;
    WCHAR *     szDataDescr;  /* serialized differently than the DATA_BLOBs */
    ALG_ID      cipher_alg;
    DWORD       cipher_key_len;
    DATA_BLOB   data0;
    DWORD       null1;
    ALG_ID      hash_alg;
    DWORD       hash_len;
    DATA_BLOB   salt;
    DATA_BLOB   cipher;
    DATA_BLOB   fingerprint;
};

#define CRYPT_Alloc malloc
#define CRYPT_Free free

static PCRYPTPROV CRYPT_LoadProvider()
{
	PCRYPTPROV provider;

	if ( !(provider = (PCRYPTPROV) malloc(sizeof(CRYPTPROV))) ) goto error;
	if ( !(provider->pFuncs = CRYPT_Alloc(sizeof(PROVFUNCS))) ) goto error;
	if ( !(provider->pVTable = CRYPT_Alloc(sizeof(VTableProvStruc))) ) goto error;
	// if ( !(provider->hModule = LoadLibraryW(pImage)) )
	provider->dwMagic = MAGIC_CRYPTPROV;
	provider->refcount = 1;
	provider->pVTable->Version = 3;
	provider->pVTable->FuncVerifyImage = NULL;
	provider->pVTable->FuncReturnhWnd = NULL;
	provider->pVTable->dwProvType = 0;
	provider->pVTable->pbContextInfo = NULL;
	provider->pVTable->cbContextInfo = 0;
	provider->pVTable->pszProvName = NULL;
    printf("Created provider\n");
    printf("pVtable = %p\n", provider->pVTable);

	return provider;

error:
    abort();
	return NULL;
}

__winfnc BOOL  RSAENH_CPGenRandom(HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer);

__winfnc BOOL RSAENH_CPAcquireContext(HCRYPTPROV *phProv, LPSTR pszContainer,
                   DWORD dwFlags, PVTableProvStruc pVTable);


__winfnc BOOL 
RSAENH_CPEncrypt(
    HCRYPTPROV hProv, 
    HCRYPTKEY hKey, 
    HCRYPTHASH hHash, 
    BOOL Final, 
    DWORD dwFlags, 
    BYTE *pbData,
    DWORD *pdwDataLen, 
    DWORD dwBufLen
);

__winfnc BOOL RSAENH_CPDecrypt(HCRYPTPROV hProv, HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, 
                             DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen);

__winfnc BOOL RSAENH_CPReleaseContext(HCRYPTPROV hProv, DWORD dwFlags);

__winfnc BOOL RSAENH_CPImportKey(HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen,
                               HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey);


__winfnc BOOL RSAENH_CPCreateHash( HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey, DWORD dwFlags, HCRYPTHASH *phHash);

__winfnc BOOL RSAENH_CPSetHashParam( HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD dwFlags);

__winfnc BOOL RSAENH_CPGetHashParam( HCRYPTPROV hProv, HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData, DWORD *pdwDataLen, DWORD dwFlags);

__winfnc BOOL RSAENH_CPDestroyHash( HCRYPTPROV hProv, HCRYPTHASH hHash);

__winfnc BOOL RSAENH_CPHashData( HCRYPTPROV hProv, HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags);

__winfnc BOOL  RSAENH_CPSetKeyParam(HCRYPTPROV hProv, HCRYPTKEY hKey, DWORD dwParam, BYTE *pbData, 
                                 DWORD dwFlags);

__winfnc BOOL RSAENH_CPDestroyKey(HCRYPTPROV hProv, HCRYPTKEY hKey);

__winfnc BOOL RSAENH_CPDuplicateHash(HCRYPTPROV hUID, HCRYPTHASH hHash, DWORD *pdwReserved, 
                                   DWORD dwFlags, HCRYPTHASH *phHash);

__winfnc BOOL DllMainRSAENH(HINSTANCE hInstance, DWORD fdwReason, PVOID reserved);

__winfnc BOOL CryptAcquireContextA (HCRYPTPROV *phProv, LPCSTR pszContainer,
		LPCSTR pszProvider, DWORD dwProvType, DWORD dwFlags) {
    TRACE();
    DllMainRSAENH(0, 1, 0);
    printf("Prov type: %d\n", dwProvType);
    printf("Cont name: %s\n", pszContainer);
    printf("Prov name: %s\n", pszProvider);
    // sleep(1);
	PCRYPTPROV pProv = NULL;

    pProv = CRYPT_LoadProvider();

	if (!pszProvider || !*pszProvider)
	{
        pProv->pVTable->pszProvName = strdup("Microsoft Enhanced RSA and AES Cryptographic Provider");
    } else {
        pProv->pVTable->pszProvName = strdup(pszProvider);
    }

	pProv->pVTable->dwProvType = dwProvType;

    assert(pProv != NULL);

	//    sleep(1);
	bool res = (RSAENH_CPAcquireContext(&pProv->hPrivate, pszContainer, dwFlags, pProv->pVTable));
    DWORD err = GetErrorFromLib();
    printf("Error after lib: %x\n", err);
    winerr_set_code(err);
    printf("After call rc = %d hPrivate = %lu\n", (int) res, pProv->hPrivate);
	//    sleep(1);
	//
    if (res) {
       printf("AcquireContextA success\n");
       *phProv = (HCRYPTPROV)pProv;
       return TRUE;
    }
	//
	//    printf("AcquireContextA fail!\n");
	//    abort();
    return res;
}
WINAPI(CryptAcquireContextA)

__winfnc BOOL CryptReleaseContext(HCRYPTPROV prov, DWORD flags) {
    TRACE();
    RSAENH_CPReleaseContext(prov, flags);
    return TRUE;
}
WINAPI(CryptReleaseContext)


__winfnc BOOL CryptImportKey(HCRYPTPROV hProv, const BYTE *pbData, DWORD dwDataLen,
                               HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY *phKey)
{
    TRACE();

	PCRYPTPROV prov = (PCRYPTPROV)hProv;
	PCRYPTKEY pubkey = (PCRYPTKEY)hPubKey, importkey;

    printf("prov = %p key = %p", prov, phKey);

	if (!prov || !pbData || !dwDataLen || !phKey ||
		prov->dwMagic != MAGIC_CRYPTPROV ||
		(pubkey && pubkey->dwMagic != MAGIC_CRYPTKEY))
	{
        printf("A\n");
		return FALSE;
	}

	if ( !(importkey = CRYPT_Alloc(sizeof(CRYPTKEY))) )
	{
        printf("B\n");
		return FALSE;
	}

	importkey->pProvider = prov;
	importkey->dwMagic = MAGIC_CRYPTKEY;
    printf("hPrivate: %lu\n", prov->hPrivate);
	if (RSAENH_CPImportKey(prov->hPrivate, pbData, dwDataLen,
			pubkey ? pubkey->hPrivate : 0, dwFlags, &importkey->hPrivate))
	{
		*phKey = (HCRYPTKEY)importkey;
        TRACE_OK();
		return TRUE;
	}

	importkey->dwMagic = 0;
	// CRYPT_Free(importkey);
	return FALSE;
}
WINAPI(CryptImportKey)

__winfnc BOOL CryptDestroyKey(HCRYPTKEY hKey) {
    TRACE();

	PCRYPTKEY key = (PCRYPTKEY)hKey;
	PCRYPTPROV prov;
	BOOL ret;

	// TRACE("(0x%lx)\n", hKey);

	if (!key)
	{
		winerr_set_code(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	if (!key->pProvider || key->dwMagic != MAGIC_CRYPTKEY ||
		key->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = key->pProvider;
	ret = RSAENH_CPDestroyKey(prov->hPrivate, key->hPrivate);
	key->dwMagic = 0;
	CRYPT_Free(key);
	return ret;
}
WINAPI(CryptDestroyKey)

__winfnc BOOL CryptCreateHash (HCRYPTPROV hProv, ALG_ID Algid, HCRYPTKEY hKey,
		DWORD dwFlags, HCRYPTHASH *phHash)
{
    TRACE();
	PCRYPTPROV prov = (PCRYPTPROV)hProv;
	PCRYPTKEY key = (PCRYPTKEY)hKey;
	PCRYPTHASH hash;

	printf("(0x%lx, 0x%x, 0x%lx, %08x, %p)\n", hProv, Algid, hKey, dwFlags, phHash);

	if (!prov || !phHash || prov->dwMagic != MAGIC_CRYPTPROV ||
		(key && key->dwMagic != MAGIC_CRYPTKEY))
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}
	if (dwFlags)
	{
		winerr_set_code(NTE_BAD_FLAGS);
		return FALSE;
	}
	if ( !(hash = CRYPT_Alloc(sizeof(CRYPTHASH))) )
	{
		winerr_set_code(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}

	hash->pProvider = prov;
	hash->dwMagic = MAGIC_CRYPTHASH;
	if (RSAENH_CPCreateHash(prov->hPrivate, Algid,
			key ? key->hPrivate : 0, 0, &hash->hPrivate))
        {
            *phHash = (HCRYPTHASH)hash;
            return TRUE;
        }

	/* CSP error! */
	hash->dwMagic = 0;
	CRYPT_Free(hash);
	*phHash = 0;
	return FALSE;
}
WINAPI(CryptCreateHash)

__winfnc BOOL CryptDestroyHash (HCRYPTHASH hHash)
{
	PCRYPTHASH hash = (PCRYPTHASH)hHash;
	PCRYPTPROV prov;
	BOOL ret;

    TRACE();
	// TRACE("(0x%lx)\n", hHash);

	if (!hash)
	{
		winerr_set_code(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	if (!hash->pProvider || hash->dwMagic != MAGIC_CRYPTHASH ||
		hash->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = hash->pProvider;
	ret = RSAENH_CPDestroyHash(prov->hPrivate, hash->hPrivate);
	hash->dwMagic = 0;
	CRYPT_Free(hash);
	return ret;
}
WINAPI(CryptDestroyHash)

__winfnc BOOL  CryptDuplicateHash (HCRYPTHASH hHash, DWORD *pdwReserved,
		DWORD dwFlags, HCRYPTHASH *phHash)
{
    TRACE();

    PCRYPTPROV prov;
	PCRYPTHASH orghash, newhash;

	// TRACE("(0x%lx, %p, %08x, %p)\n", hHash, pdwReserved, dwFlags, phHash);

	orghash = (PCRYPTHASH)hHash;
	if (!orghash || pdwReserved || !phHash || !orghash->pProvider ||
		orghash->dwMagic != MAGIC_CRYPTHASH || orghash->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = orghash->pProvider;

	if ( !(newhash = CRYPT_Alloc(sizeof(CRYPTHASH))) )
	{
		winerr_set_code(ERROR_NOT_ENOUGH_MEMORY);
		return FALSE;
	}

	newhash->pProvider = prov;
	newhash->dwMagic = MAGIC_CRYPTHASH;
	if (RSAENH_CPDuplicateHash(prov->hPrivate, orghash->hPrivate, pdwReserved, dwFlags, &newhash->hPrivate))
	{
		*phHash = (HCRYPTHASH)newhash;
		return TRUE;
	}
	newhash->dwMagic = 0;
	CRYPT_Free(newhash);
	return FALSE;
}
WINAPI(CryptDuplicateHash)

__winfnc BOOL  CryptGetHashParam (HCRYPTHASH hHash, DWORD dwParam, BYTE *pbData,
		DWORD *pdwDataLen, DWORD dwFlags)
{
	PCRYPTPROV prov;
	PCRYPTHASH hash = (PCRYPTHASH)hHash;

    TRACE();
	// TRACE("(0x%lx, %d, %p, %p, %08x)\n", hHash, dwParam, pbData, pdwDataLen, dwFlags);

	if (!hash || !pdwDataLen || !hash->pProvider ||
		hash->dwMagic != MAGIC_CRYPTHASH || hash->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = hash->pProvider;
	return RSAENH_CPGetHashParam(prov->hPrivate, hash->hPrivate, dwParam,
			pbData, pdwDataLen, dwFlags);
}
WINAPI(CryptGetHashParam)


__winfnc BOOL CryptSetHashParam (HCRYPTHASH hHash, DWORD dwParam, const BYTE *pbData, DWORD dwFlags)
{
	PCRYPTPROV prov;
	PCRYPTHASH hash = (PCRYPTHASH)hHash;

    TRACE();
	// TRACE("(0x%lx, %d, %p, %08x)\n", hHash, dwParam, pbData, dwFlags);

	if (!hash || !pbData || !hash->pProvider ||
		hash->dwMagic != MAGIC_CRYPTHASH || hash->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = hash->pProvider;
	return RSAENH_CPSetHashParam(prov->hPrivate, hash->hPrivate,
			dwParam, pbData, dwFlags);
}
WINAPI(CryptSetHashParam)

__winfnc BOOL CryptHashData (HCRYPTHASH hHash, const BYTE *pbData, DWORD dwDataLen, DWORD dwFlags)
{
	PCRYPTHASH hash = (PCRYPTHASH)hHash;
	PCRYPTPROV prov;

    TRACE();
	// TRACE("(0x%lx, %p, %d, %08x)\n", hHash, pbData, dwDataLen, dwFlags);

	if (!hash)
	{
		winerr_set_code(ERROR_INVALID_HANDLE);
		return FALSE;
	}
	if (!hash->pProvider || hash->dwMagic != MAGIC_CRYPTHASH ||
		hash->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = hash->pProvider;
	return RSAENH_CPHashData(prov->hPrivate, hash->hPrivate, pbData, dwDataLen, dwFlags);
}
WINAPI(CryptHashData)

__winfnc BOOL CryptSetKeyParam (HCRYPTKEY hKey, DWORD dwParam, const BYTE *pbData, DWORD dwFlags)
{
	PCRYPTPROV prov;
	PCRYPTKEY key = (PCRYPTKEY)hKey;

	// TRACE("(0x%lx, %d, %p, %08x)\n", hKey, dwParam, pbData, dwFlags);

	if (!key || !pbData || !key->pProvider ||
		key->dwMagic != MAGIC_CRYPTKEY || key->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = key->pProvider;
	return RSAENH_CPSetKeyParam(prov->hPrivate, key->hPrivate,
			dwParam, pbData, dwFlags);
}
WINAPI(CryptSetKeyParam)

__winfnc BOOL CryptEncodeObject(DWORD cert_enc_type, const char *struct_type, void *struct_info, BYTE *enc, DWORD *enc_size) {
    //Handle integer constants
    if(!(((uintptr_t) struct_type) & (128llu << sizeof(uintptr_t)))) {
        switch((uintptr_t) struct_type) {
            case X509_ECC_SIGNATURE: {
                CERT_ECC_SIGNATURE *ecc_sig = (CERT_ECC_SIGNATURE*) struct_info;

                //Create signature
                ECDSA_SIG *sig;
                LIBCRYPTO_ERR(sig = ECDSA_SIG_new());

                BIGNUM *sig_r, *sig_s;
                LIBCRYPTO_ERR(sig_r = BN_new());
                LIBCRYPTO_ERR(sig_s = BN_new());
                LIBCRYPTO_ERR(BN_lebin2bn(ecc_sig->r.pbData, ecc_sig->r.cbData, sig_r));
                LIBCRYPTO_ERR(BN_lebin2bn(ecc_sig->s.pbData, ecc_sig->s.cbData, sig_s));
                LIBCRYPTO_ERR(ECDSA_SIG_set0(sig, sig_r, sig_s));

                //Encode signature
                int sig_size = i2d_ECDSA_SIG(sig, NULL);
                if(enc && *enc_size >= sig_size) {
                    i2d_ECDSA_SIG(sig, &enc);
                } else if(enc) {
                    ECDSA_SIG_free(sig);
                    winerr_set_code(ERROR_INSUFFICIENT_BUFFER);
                    return FALSE;
                }

                ECDSA_SIG_free(sig);
                *enc_size = sig_size;
                return TRUE;
            }
            default: {
                log_debug("CryptEncodeObject | Unsupported arguments! cert_enc_type %x struct_type %lx", cert_enc_type, (uintptr_t) struct_type);
                winerr_set();
                return FALSE;
            }
        }
    }

    log_debug("CryptEncodeObject | Unsupported arguments! cert_enc_type %x struct_type '%s'", cert_enc_type, struct_type);
    winerr_set();
    return FALSE;
}
WINAPI(CryptEncodeObject)


__winfnc BOOL  CryptEncrypt (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final,
		DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen, DWORD dwBufLen)
{
	PCRYPTPROV prov;
	PCRYPTKEY key = (PCRYPTKEY)hKey;
	PCRYPTHASH hash = (PCRYPTHASH)hHash;

	printf("(0x%lx, 0x%lx, %d, %08x, %p, %p, %d)\n", hKey, hHash, Final, dwFlags, pbData, pdwDataLen, dwBufLen);
        printf("To be encrypted: ");
        for(int i=0;i<*pdwDataLen;i++) {
            if(i > 3000000) {
                printf("...");
                break;
            } else {
                printf("%02x", pbData[i]);
            }
        }
        printf("\n");

	if (!key || !pdwDataLen || !key->pProvider ||
		key->dwMagic != MAGIC_CRYPTKEY || key->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = key->pProvider;
	BOOL rc = RSAENH_CPEncrypt(prov->hPrivate, key->hPrivate, hash ? hash->hPrivate : 0,
			Final, dwFlags, pbData, pdwDataLen, dwBufLen);
        printf("Encrypted: ");
        for(int i=0;i<*pdwDataLen;i++) {
            if(i > 30) {
                printf("...");
                break;
            } else {
                printf("%02x", pbData[i]);
            }
        }
        printf("\n");
        return rc;
}
WINAPI(CryptEncrypt)


__winfnc BOOL  CryptDecrypt (HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final,
		DWORD dwFlags, BYTE *pbData, DWORD *pdwDataLen)
{
	PCRYPTPROV prov;
	PCRYPTKEY key = (PCRYPTKEY)hKey;
	PCRYPTHASH hash = (PCRYPTHASH)hHash;

	printf("(0x%lx, 0x%lx, %d, %08x, %p, %p)\n", hKey, hHash, Final, dwFlags, pbData, pdwDataLen);

        printf("To be decrypted: ");
        for(int i=0;i<*pdwDataLen;i++) {
            if(i > 30) {
                printf("...");
                break;
            } else {
                printf("%02x", pbData[i]);
            }
        }
        printf("\n");
	if (!key || !pbData || !pdwDataLen ||
		!key->pProvider || key->dwMagic != MAGIC_CRYPTKEY ||
		key->pProvider->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	prov = key->pProvider;
	BOOL rc = RSAENH_CPDecrypt(prov->hPrivate, key->hPrivate, hash ? hash->hPrivate : 0,
			Final, dwFlags, pbData, pdwDataLen);
        printf("Decrypted: ");
        for(int i=0;i<*pdwDataLen;i++) {
            if(i > 3000000) {
                printf("...");
                break;
            } else {
                printf("%02x", pbData[i]);
            }
        }
        printf("\n");
        return rc;
}
WINAPI(CryptDecrypt)

__winfnc BOOL CryptDecodeObject(DWORD cert_enc_type, const char *struct_type, const BYTE *enc, DWORD enc_size, DWORD flags, void *struct_info, DWORD *struct_info_size) {
    //Handle integer constants
    if(!(((uintptr_t) struct_type) & (128llu << sizeof(uintptr_t)))) {
        switch((uintptr_t) struct_type) {
            case X509_ECC_SIGNATURE: {
                //Decode signature
                ECDSA_SIG *sig;
                LIBCRYPTO_ERR(sig = d2i_ECDSA_SIG(NULL, &enc, (long) enc_size));

                //Store signature
                const BIGNUM *sig_r = ECDSA_SIG_get0_r(sig), *sig_s = ECDSA_SIG_get0_s(sig);
                int sig_size = sizeof(CERT_ECC_SIGNATURE) + BN_num_bytes(sig_r) + BN_num_bytes(sig_s);
                if(struct_info && *struct_info_size >= sig_size) {
                    CERT_ECC_SIGNATURE *ecc_sig = (CERT_ECC_SIGNATURE*) struct_info;
                    ecc_sig->r.cbData = BN_num_bytes(sig_r);
                    ecc_sig->r.pbData = (BYTE*) struct_info + sizeof(CERT_ECC_SIGNATURE);
                    ecc_sig->s.cbData = BN_num_bytes(sig_s);
                    ecc_sig->s.pbData = (BYTE*) struct_info + sizeof(CERT_ECC_SIGNATURE) + ecc_sig->r.cbData;
                    LIBCRYPTO_ERR(BN_bn2lebinpad(sig_r, ecc_sig->r.pbData, ecc_sig->r.cbData));
                    LIBCRYPTO_ERR(BN_bn2lebinpad(sig_s, ecc_sig->s.pbData, ecc_sig->s.cbData));
                } else if(struct_info) { winerr_set_code(ERROR_INSUFFICIENT_BUFFER); return FALSE; }

                *struct_info_size = sig_size;
                ECDSA_SIG_free(sig);
                return TRUE;
            }
            default: {
                log_debug("CryptDecodeObject | Unsupported arguments! cert_enc_type %x struct_type %lx", cert_enc_type, (uintptr_t) struct_type);
                winerr_set();
                return FALSE;
            }
        }
    }

    log_debug("CryptDecodeObject | Unsupported arguments! cert_enc_type %x struct_type '%s'", cert_enc_type, struct_type);
    winerr_set();
    return FALSE;
}
WINAPI(CryptDecodeObject)

__winfnc BOOL CryptProtectData(DATA_BLOB *in, const char16_t *descr, DATA_BLOB *entropy, void *reserved, void *prompt_struct, DWORD flags, DATA_BLOB *out) {
    TRACE();

    out->pbData = malloc(in->cbData);
    out->cbData = in->cbData;
    memcpy(out->pbData, in->pbData, in->cbData);

    printf("in = %p out = %p\n", in, out);
    print_hex_str("Protect input", in->pbData, in->cbData);
    return TRUE;
}
WINAPI(CryptProtectData)



__winfnc BOOL CryptUnprotectData(
                               DATA_BLOB* in,
                               wchar_t * ppszDataDescr,
                               DATA_BLOB* pOptionalEntropy,
                               PVOID pvReserved,
                               void* pPromptStruct,
                               DWORD dwFlags,
                               DATA_BLOB* out)

{
    TRACE();
    out->pbData = malloc(in->cbData);
    out->cbData = in->cbData;
    memcpy(out->pbData, in->pbData, in->cbData);
    printf("in = %p out = %p\n", in, out);
    print_hex_str("Unprotect output", out->pbData, out->cbData);
    printf("out->cbData: %d\n", out->cbData);
    return TRUE;
}
WINAPI(CryptUnprotectData)

__winfnc BOOL CryptProtectMemory(void *data, DWORD size, DWORD flags) {
    TRACE();
    return TRUE;
}
WINAPI(CryptProtectMemory);

__winfnc BOOL CryptUnprotectMemory(void *data, DWORD size, DWORD flags) {
    TRACE();
    return TRUE;
}
WINAPI(CryptUnprotectMemory);


__winfnc BOOL CryptGenRandom (HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer)
{
    TRACE();
    // TRACE("(hProv=%08lx, dwLen=%d, pbBuffer=%p)\n", hProv, dwLen, pbBuffer);
    
	PCRYPTPROV prov = (PCRYPTPROV)hProv;

	printf("(0x%lx, %d, %p)\n", hProv, dwLen, pbBuffer);

	if (!hProv)
	{
		winerr_set_code(ERROR_INVALID_HANDLE);
		return FALSE;
	}

	if (prov->dwMagic != MAGIC_CRYPTPROV)
	{
		winerr_set_code(ERROR_INVALID_PARAMETER);
		return FALSE;
	}

	return RSAENH_CPGenRandom(prov->hPrivate, dwLen, pbBuffer);

}
WINAPI(CryptGenRandom)
