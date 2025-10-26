#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include "crypt.h"

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



__winfnc BOOL CryptAcquireContextA(struct crypt_provider **prov, const char *cont_name, const char *prov_name, DWORD prov_type, DWORD flags) {
    TRACE();
    printf("Prov type: %d\n", prov_type);
    printf("Cont name: %s\n", cont_name);
    printf("Prov name: %s\n", prov_name);
    switch(prov_type) {
        case PROV_RSA_AES: *prov = &crypt_prov_rsa_aes; return TRUE;
        case PROV_RSA_FULL: *prov = &crypt_prov_rsa_aes; return TRUE;
        default: {
            log_warn("CryptAcquireContextA | Couldn't find provider for container '%s' provider '%s' provider type 0x%x flags 0x%x", cont_name, prov_name, prov_type, flags);
            return FALSE;
        }
    }
}
WINAPI(CryptAcquireContextA)

__winfnc BOOL CryptReleaseContext(struct crypt_provider *prov, DWORD flags) {
    TRACE();
    return TRUE;
}
WINAPI(CryptReleaseContext)

__winfnc BOOL CryptImportKey(struct crypt_provider *prov, const BLOBHEADER *data, DWORD data_len, struct crypt_key *pub_key, DWORD flags, struct crypt_key **out) {
    TRACE();
    if(!prov->import_key) { winerr_set(); return FALSE; }
    if(pub_key) {
        log_warn("CryptImportKey called with encrypted key data!");
        winerr_set();
        return FALSE;
    }

    if(data_len < sizeof(BLOBHEADER)) { winerr_set_code(ERROR_INSUFFICIENT_BUFFER); return FALSE; }

    //Allocate key
    struct crypt_key *key = (struct crypt_key*) malloc(sizeof(struct crypt_key));
    if(!key) { winerr_set_errno(); return FALSE; }
    key->prov = prov;
    key->key_data = NULL;

    if(data->bType == type_PLAINTEXTKEYBLOB) {
        //Copy plaintext data
        PLAINTEXTKEYBLOB *blob = (PLAINTEXTKEYBLOB*) data;
        if(data_len < sizeof(PLAINTEXTKEYBLOB) + blob->dwKeySize) { winerr_set_code(ERROR_INSUFFICIENT_BUFFER); return FALSE; }

        key->plain_data = malloc(blob->dwKeySize);
        key->plain_size = blob->dwKeySize;
        if(!key->plain_data) {
            winerr_set_errno();
            free(key);
            return FALSE;
        }
        memcpy(key->plain_data, blob+1, blob->dwKeySize);
    } else {
        key->plain_data = NULL;
        key->plain_size = 0;
    }

    //Import key
    if(!prov->import_key(prov, data, data_len, &key->key_data)) {
        winerr_set_errno();
        free(key->plain_data);
        free(key);
        return FALSE;
    }

    *out = key;
    return TRUE;
}
WINAPI(CryptImportKey)

__winfnc BOOL CryptDestroyKey(struct crypt_key *key) {
    TRACE();
    if(key->prov->destroy_key) key->prov->destroy_key(key->prov, key->key_data);
    free(key->plain_data);
    free(key);
    return TRUE;
}
WINAPI(CryptDestroyKey)

__winfnc BOOL CryptCreateHash(struct crypt_provider *prov, ALG_ID alg_id, struct crypt_key *key, DWORD flags, struct crypt_hash **out) {
    TRACE();
    printf("Alg id: %x\n", alg_id);
    //Get the algorithm
    struct crypt_hash_algorithm *algo;
    switch(alg_id) {
        case CALG_SHA1: algo = (struct crypt_hash_algorithm*) &crypt_hash_algo_sha1; printf("SHA1\n"); break;
        case CALG_SHA_256: algo = (struct crypt_hash_algorithm*) &crypt_hash_algo_sha256;printf("SHA256\n"); break;
        case CALG_SHA_384: algo = (struct crypt_hash_algorithm*) &crypt_hash_algo_sha384; printf("SHA384\n");break;
        case CALG_SHA_512: algo = (struct crypt_hash_algorithm*) &crypt_hash_algo_sha512; printf("SHA512\n"); break;
        case CALG_HMAC: algo = &crypt_hash_algo_hmac; break;
        default: {
            log_warn("CryptCreateHash | Couldn't find algorithm id 0x%x flags 0x%x", alg_id, flags);
            return FALSE;
        }
    }

    //Allocate and create hash
    struct crypt_hash *hash = (struct crypt_hash*) malloc(sizeof(struct crypt_hash));
    if(!hash) { winerr_set_errno(); return FALSE; }
    hash->algo = algo;
    hash->hash_data = NULL;

    if(!algo->create_hash(algo, key, &hash->hash_data)) {
        free(hash);
        return FALSE;
    }

    *out = hash;
    printf("Created hash: %p\n", hash);
    return TRUE;
}
WINAPI(CryptCreateHash)

__winfnc BOOL CryptDestroyHash(struct crypt_hash *hash) {
    TRACE();
    if(hash->algo->destroy_hash) hash->algo->destroy_hash(hash->algo, hash->hash_data);
    free(hash);
    return TRUE;
}
WINAPI(CryptDestroyHash)

__winfnc BOOL CryptDuplicateHash(struct crypt_hash *hash, DWORD *reserved, DWORD flags, struct crypt_hash **out) {
    TRACE();
    //Allocate and duplicate hash
    struct crypt_hash *nhash = (struct crypt_hash*) malloc(sizeof(struct crypt_hash));
    if(!nhash) { winerr_set_errno(); return FALSE; }
    nhash->algo = hash->algo;
    nhash->hash_data = NULL;

    if(!hash->algo->duplicate_hash(hash->algo, hash->hash_data, &nhash->hash_data)) {
        free(nhash);
        return FALSE;
    }

    *out = nhash;
    return TRUE;
}
WINAPI(CryptDuplicateHash)

__winfnc BOOL CryptGetHashParam(struct crypt_hash *hash, DWORD param, BYTE *data, DWORD *data_len, DWORD flags) {
    TRACE();
    size_t buf_size = *data_len;
    printf("Hash: %p Param: %d\n", hash, param);
    BOOL suc = hash->algo->get_hash_param(hash->algo, hash->hash_data, param, data, &buf_size);
    *data_len = (size_t) buf_size;
    printf("Ret: %d\n", (int) suc);
    return suc;
}
WINAPI(CryptGetHashParam)

__winfnc BOOL CryptSetHashParam(struct crypt_hash *hash, DWORD param, const BYTE *data, DWORD flags) {
    TRACE();
    return hash->algo->set_hash_param(hash->algo, hash->hash_data, param, data);
}
WINAPI(CryptSetHashParam)

__winfnc BOOL CryptHashData(struct crypt_hash *hash, const BYTE *data, DWORD data_len, DWORD flags) {
    TRACE();
    printf("Data (%lu bytes): ", (unsigned long)data_len);
    printf("Hash input: ");
    for (DWORD i = 0; i < data_len; i++) {
        printf("%02X", data[i]);  // two-digit uppercase hex
    }
    printf("\n");
    fflush(stdout);
    bool ret = hash->algo->update_hash(hash->algo, hash->hash_data, data, data_len);
    printf("Ret: %d\n", (int) ret);
    return ret;
}
WINAPI(CryptHashData)

__winfnc BOOL CryptSetKeyParam(struct crypt_key *key, DWORD param, const BYTE *data, DWORD flags) {
    // return hash->algo->set_hash_param(hash->algo, hash->hash_data, param, data);
    TRACE();
    struct crypt_provider* prov = NULL;


    if (!key || !data || !key->prov)
    {
        return FALSE;
    }

    prov = key->prov;
    return prov->set_key(prov, &key, param, data, flags);
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

__winfnc BOOL CryptEncrypt(
  struct crypt_key*  hKey,
  struct crypt_hash* hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen,
  DWORD      dwBufLen) 
{
    TRACE();
    printf("%d %d %p %p %d\n", (int) Final, dwFlags, pbData, pdwDataLen, dwBufLen);
    if (pbData == NULL) {
        if (pdwDataLen == NULL) {
            return false;

        }
        printf("Data len requested: %d\n", *pdwDataLen);

        return true;
    }

    if (pdwDataLen != NULL) {
        printf("Data len: %d\n", *pdwDataLen);

    }
    return true;
}
WINAPI(CryptEncrypt)

__winfnc BOOL CryptDecrypt(
  struct crypt_key*  hKey,
  struct crypt_hash* hHash,
  BOOL       Final,
  DWORD      dwFlags,
  BYTE       *pbData,
  DWORD      *pdwDataLen) 
{
    TRACE();
    printf("%d %d %p %p\n", (int) Final, dwFlags, pbData, pdwDataLen);
    if (pbData == NULL) {
        if (pdwDataLen == NULL) {
            return false;

        }
        printf("Data len requested: %d\n", *pdwDataLen);

        return true;
    }

    if (pdwDataLen != NULL) {
        printf("Data len: %d\n", *pdwDataLen);

    }
    return true;
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
    if (in->cbData == 96) {
        out->cbData = 242;
    } else {
        out->cbData = in->cbData * 3;
    }


    out->pbData = (BYTE*) malloc(out->cbData);

    uint8_t* src = (uint8_t*)in->pbData;
    uint8_t* dst = (uint8_t*)out->pbData;

    printf("Protect data input:\n");
    for (int i = 0; i < in->cbData; ++i) {
        printf("%02x", src[i]);
    }
    printf("\n");
    memset(dst, 0, out->cbData);
    for (int i = 0; i < in->cbData; ++i) {
        dst[out->cbData-i-1] = src[i];
    }

    // Store size as first few bytes
    int* size_out = (int*)out->pbData;
    *size_out = in->cbData;

    printf("Ret: 1\n");
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
    int* size_in = in->pbData;
    int size = *size_in;

    out->cbData = (DWORD) size;
    out->pbData = (BYTE*) malloc(out->cbData);

    uint8_t* src = (uint8_t*)in->pbData;
    uint8_t* dst = (uint8_t*)out->pbData;
    memset(dst, 0, out->cbData);
    for (int i = 0; i < out->cbData; ++i) {
        dst[i] = src[in->cbData - i - i];
    }

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

__winfnc BOOL CryptGenRandom(HANDLE prov, DWORD len, BYTE *buf) {
    TRACE();
    LIBCRYPTO_ERR(RAND_bytes(buf, (int) len));
    return TRUE;
}
WINAPI(CryptGenRandom)
