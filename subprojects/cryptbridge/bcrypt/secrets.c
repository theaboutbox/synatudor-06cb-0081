
#include "config.h"
#include "wine/port.h"

#include <stdarg.h>
#include <limits.h>
#ifdef HAVE_COMMONCRYPTO_COMMONCRYPTOR_H
#include <AvailabilityMacros.h>
#include <CommonCrypto/CommonCryptor.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "ntsecapi.h"
#include "bcrypt.h"

#include "bcrypt_internal.h"

// #include "wine/debug.h"
#include "wine/heap.h"
#include "wine/library.h"
#include "wine/unicode.h"

#include <openssl/err.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>

#define CURVE_NID NID_X9_62_prime256v1



typedef void *BCRYPT_SECRET_HANDLE;

// WINE_DEFAULT_DEBUG_CHANNEL(bcrypt);
// WINE_DECLARE_DEBUG_CHANNEL(winediag);

#define SONAME_LIBCRYPTO "libcrypto.so"

static void *libgnutls_handle;

#define MAKE_FUNCPTR(f) static typeof(f) * p##f
MAKE_FUNCPTR(EVP_PKEY_CTX_new);
MAKE_FUNCPTR(BN_CTX_new);
MAKE_FUNCPTR(EC_GROUP_new_by_curve_name);
MAKE_FUNCPTR(EC_POINT_new);
MAKE_FUNCPTR(BN_bin2bn);
MAKE_FUNCPTR(EC_POINT_mul);
MAKE_FUNCPTR(EC_POINT_point2buf);
MAKE_FUNCPTR(BN_new);
MAKE_FUNCPTR(BN_free);
MAKE_FUNCPTR(EC_POINT_free);
MAKE_FUNCPTR(EC_GROUP_free);
MAKE_FUNCPTR(BN_CTX_free);
MAKE_FUNCPTR(CRYPTO_free);
MAKE_FUNCPTR(BN_bn2binpad);
MAKE_FUNCPTR(ECDSA_SIG_get0);
MAKE_FUNCPTR(ECDSA_do_sign_ex);
MAKE_FUNCPTR(ECDSA_sign_setup);
MAKE_FUNCPTR(EC_KEY_set_public_key_affine_coordinates);
MAKE_FUNCPTR(EC_KEY_new_by_curve_name);
MAKE_FUNCPTR(ERR_get_error);
MAKE_FUNCPTR(ERR_error_string);
MAKE_FUNCPTR(EC_KEY_set_private_key);
MAKE_FUNCPTR(BN_bn2hex);
MAKE_FUNCPTR(BN_hex2bn);
MAKE_FUNCPTR(EVP_PKEY_derive_init);
MAKE_FUNCPTR(EVP_PKEY_derive_set_peer);
MAKE_FUNCPTR(EVP_PKEY_derive);
MAKE_FUNCPTR(EVP_PKEY_new);
MAKE_FUNCPTR(EVP_PKEY_set1_EC_KEY);
MAKE_FUNCPTR(EVP_PKEY_CTX_new_id);
MAKE_FUNCPTR(EVP_PKEY_derive_init);
MAKE_FUNCPTR(EVP_sha256);
MAKE_FUNCPTR(EVP_PKEY_CTX_ctrl);
#undef MAKE_FUNCPTR

BOOL
openssl_init(void)
{
    // if (!(libgnutls_handle = wine_dlopen( SONAME_LIBCRYPTO, RTLD_NOW, NULL, 0 )))
    // {
    //     ERR_(winediag)( "failed to load openssl, no support for encryption\n" );
    //     return FALSE;
    // }

#define LOAD_FUNCPTR(f) \
    p##f = f; 
    // if (!(p##f = wine_dlsym( libgnutls_handle, #f, NULL, 0 ))) \
    // { \
    //     ERR( "failed to load %s\n", #f ); \
    //     goto fail; \
    // }

    LOAD_FUNCPTR(EVP_PKEY_CTX_new)
    LOAD_FUNCPTR(BN_CTX_new)
    LOAD_FUNCPTR(EC_GROUP_new_by_curve_name)
    LOAD_FUNCPTR(EC_POINT_new)
    LOAD_FUNCPTR(BN_bin2bn)
    LOAD_FUNCPTR(EC_POINT_mul)
    LOAD_FUNCPTR(EC_POINT_point2buf)
    LOAD_FUNCPTR(BN_new)
    LOAD_FUNCPTR(BN_free)
    LOAD_FUNCPTR(EC_POINT_free)
    LOAD_FUNCPTR(EC_GROUP_free)
    LOAD_FUNCPTR(BN_CTX_free)
    LOAD_FUNCPTR(CRYPTO_free)
    LOAD_FUNCPTR(BN_bn2binpad)
    LOAD_FUNCPTR(ECDSA_SIG_get0)
    LOAD_FUNCPTR(ECDSA_do_sign_ex)
    LOAD_FUNCPTR(ECDSA_sign_setup)
    LOAD_FUNCPTR(EC_KEY_set_public_key_affine_coordinates)
    LOAD_FUNCPTR(EC_KEY_new_by_curve_name)
    LOAD_FUNCPTR(ERR_get_error)
    LOAD_FUNCPTR(ERR_error_string)
    LOAD_FUNCPTR(EC_KEY_set_private_key)
    LOAD_FUNCPTR(BN_bn2hex)
    LOAD_FUNCPTR(BN_hex2bn)
    LOAD_FUNCPTR(EVP_PKEY_derive_init)
    LOAD_FUNCPTR(EVP_PKEY_derive_set_peer)
    LOAD_FUNCPTR(EVP_PKEY_derive)
    LOAD_FUNCPTR(EVP_PKEY_new)
    LOAD_FUNCPTR(EVP_PKEY_set1_EC_KEY)
    LOAD_FUNCPTR(EVP_PKEY_CTX_new_id)
    LOAD_FUNCPTR(EVP_PKEY_derive_init)
    LOAD_FUNCPTR(EVP_sha256)
    LOAD_FUNCPTR(EVP_PKEY_CTX_ctrl)
#undef LOAD_FUNCPTR

    return TRUE;
fail:
    wine_dlclose( libgnutls_handle, NULL, 0 );
    libgnutls_handle = NULL;
    return FALSE;
}

const char *
sBN_bn2hex(BIGNUM *bn)
{
    static char buf[2048];
    char *p;
    p = BN_bn2hex(bn);
    lstrcpynA(buf, p, sizeof(buf));
    CRYPTO_free(p, OPENSSL_FILE, OPENSSL_LINE);
    return buf;
}

int
derive_ec_pubkey(unsigned char *buf)
{
    BIGNUM *prv = NULL;
    EC_POINT *pub = NULL;
    EC_GROUP *curve = NULL;
    BN_CTX *ctx = NULL;
    unsigned char out[65];
    int result = -1;

    if(!buf) return -1;
    ctx = BN_CTX_new();
    curve = EC_GROUP_new_by_curve_name(CURVE_NID);
    if(!ctx || !curve) goto done;
    pub = EC_POINT_new(curve);
    prv = BN_bin2bn(buf + 64, 32, NULL);
    if(!pub || !prv || BN_is_zero(prv)) goto done;
    if(EC_POINT_mul(curve, pub, prv, NULL, NULL, ctx) != 1) goto done;
    if(EC_POINT_point2oct(curve, pub, POINT_CONVERSION_UNCOMPRESSED,
                         out, sizeof(out), ctx) != sizeof(out)) goto done;

    memcpy(buf, out + 1, 64);
    result = 0;

done:
    BN_free(prv);
    EC_POINT_free(pub);
    EC_GROUP_free(curve);
    BN_CTX_free(ctx);
    return result;
}

int ecc_sign(
            PUCHAR px, ULONG sx,
            PUCHAR py, ULONG sy,
            PUCHAR pd, ULONG sd,
            PUCHAR src, ULONG src_len,
            PUCHAR dst)
{
    EC_KEY *key = NULL;
    ECDSA_SIG *sig = NULL;
    BIGNUM *x = NULL, *y = NULL, *d = NULL;
    const BIGNUM *r, *s;
    int result = -1;

    if(!px || !py || !pd || !src || !dst || src_len > INT_MAX) return -1;

    key = EC_KEY_new_by_curve_name(CURVE_NID);
    x = BN_bin2bn(px, sx, NULL);
    y = BN_bin2bn(py, sy, NULL);
    d = BN_bin2bn(pd, sd, NULL);
    if(!key || !x || !y || !d) goto done;

    if(!EC_KEY_set_private_key(key, d)) goto done;
    if(!EC_KEY_set_public_key_affine_coordinates(key, x, y)) goto done;
    if(EC_KEY_check_key(key) != 1) goto done;

    sig = ECDSA_do_sign(src, (int)src_len, key);
    if(!sig) goto done;

    ECDSA_SIG_get0(sig, &r, &s);
    if(BN_bn2binpad(r, dst, 32) != 32) goto done;
    if(BN_bn2binpad(s, dst + 32, 32) != 32) goto done;

    result = 0;

done:
    ECDSA_SIG_free(sig);
    BN_free(d);
    BN_free(y);
    BN_free(x);
    EC_KEY_free(key);
    return result;
}

struct my_secret {
    PUCHAR secret;
    size_t secret_size;
};

NTSTATUS WINAPI BCryptSecretAgreement(
  BCRYPT_KEY_HANDLE    hPrivKey,
  BCRYPT_KEY_HANDLE    hPubKey,
  BCRYPT_SECRET_HANDLE *phAgreedSecret,
  ULONG                dwFlags
)
{
    gnutls_ecc_curve_t curve;
    gnutls_datum_t myX = {0}, myY = {0}, myD = {0};
    BIGNUM *myXbn = NULL, *myYbn = NULL, *myDbn = NULL;
    BIGNUM *peerXbn = NULL, *peerYbn = NULL;
    EC_KEY *myKey = NULL, *peerKey = NULL;
    struct my_secret *secret = NULL;
    struct key *privKeyInt = hPrivKey;
    struct key *peerKeyInt = hPubKey;
    BCRYPT_ECCKEY_BLOB *ecc_blob;
    NTSTATUS status = STATUS_INTERNAL_ERROR;
    int secret_size;

    if(!phAgreedSecret || dwFlags) return STATUS_INVALID_PARAMETER;
    *phAgreedSecret = NULL;

    if(!privKeyInt || privKeyInt->hdr.magic != MAGIC_KEY ||
       privKeyInt->alg_id != ALG_ID_ECDH_P256) {
        status = STATUS_INVALID_HANDLE;
        goto done;
    }

    if(get_gnutls_ecc_key_params(hPrivKey, &curve, &myX, &myY, &myD))
        goto done;
    if(curve != GNUTLS_ECC_CURVE_SECP256R1) {
        status = STATUS_NOT_SUPPORTED;
        goto done;
    }

    myKey = EC_KEY_new_by_curve_name(CURVE_NID);
    myXbn = BN_bin2bn(myX.data, myX.size, NULL);
    myYbn = BN_bin2bn(myY.data, myY.size, NULL);
    myDbn = BN_bin2bn(myD.data, myD.size, NULL);
    if(!myKey || !myXbn || !myYbn || !myDbn) goto done;
    if(!EC_KEY_set_public_key_affine_coordinates(myKey, myXbn, myYbn)) goto done;
    if(!EC_KEY_set_private_key(myKey, myDbn)) goto done;
    if(EC_KEY_check_key(myKey) != 1) goto done;

    if(!peerKeyInt || peerKeyInt->hdr.magic != MAGIC_KEY ||
       peerKeyInt->alg_id != ALG_ID_ECDH_P256 ||
       !peerKeyInt->u.a.pubkey ||
       peerKeyInt->u.a.pubkey_len < sizeof(*ecc_blob) + 64) {
        status = STATUS_INVALID_HANDLE;
        goto done;
    }

    ecc_blob = (BCRYPT_ECCKEY_BLOB *)peerKeyInt->u.a.pubkey;
    if(ecc_blob->dwMagic != BCRYPT_ECDH_PUBLIC_P256_MAGIC || ecc_blob->cbKey != 32) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    peerKey = EC_KEY_new_by_curve_name(CURVE_NID);
    peerXbn = BN_bin2bn((unsigned char *)(ecc_blob + 1), ecc_blob->cbKey, NULL);
    peerYbn = BN_bin2bn((unsigned char *)(ecc_blob + 1) + ecc_blob->cbKey,
                        ecc_blob->cbKey, NULL);
    if(!peerKey || !peerXbn || !peerYbn) goto done;
    if(!EC_KEY_set_public_key_affine_coordinates(peerKey, peerXbn, peerYbn)) goto done;

    secret = heap_alloc(sizeof(*secret));
    if(!secret) {
        status = STATUS_NO_MEMORY;
        goto done;
    }
    secret->secret_size = 32;
    secret->secret = heap_alloc(secret->secret_size);
    if(!secret->secret) {
        status = STATUS_NO_MEMORY;
        goto done;
    }

    secret_size = ECDH_compute_key(secret->secret, secret->secret_size,
                                   EC_KEY_get0_public_key(peerKey), myKey, NULL);
    if(secret_size <= 0) goto done;

    secret->secret_size = secret_size;
    *phAgreedSecret = secret;
    secret = NULL;
    status = STATUS_SUCCESS;

done:
    if(secret) {
        heap_free(secret->secret);
        heap_free(secret);
    }
    EC_KEY_free(peerKey);
    EC_KEY_free(myKey);
    BN_free(peerYbn);
    BN_free(peerXbn);
    BN_free(myDbn);
    BN_free(myYbn);
    BN_free(myXbn);
    gnutls_free(myD.data);
    gnutls_free(myY.data);
    gnutls_free(myX.data);
    return status;
}


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

NTSTATUS WINAPI BCryptDeriveKey(
  BCRYPT_SECRET_HANDLE hSharedSecret,
  LPCWSTR              pwszKDF,
  BCryptBufferDesc     *pParameterList,
  PUCHAR               pbDerivedKey,
  ULONG                cbDerivedKey,
  ULONG                *pcbResult,
  ULONG                dwFlags
)
{
    struct my_secret *secret = hSharedSecret;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char derived[48];
    const char *label = NULL;
    PUCHAR seed = NULL;
    size_t label_size = 0, derived_size = sizeof(derived);
    BOOL have_label = FALSE;
    NTSTATUS status = STATUS_INTERNAL_ERROR;

    if(!secret || !secret->secret || !secret->secret_size ||
       secret->secret_size > INT_MAX || !pwszKDF ||
       !pParameterList || !pcbResult || dwFlags ||
       (pParameterList->cBuffers && !pParameterList->pBuffers))
        return STATUS_INVALID_PARAMETER;

    // FIXME("hSharedSecret=%p pwszKDF=%s pParameterList=%p pbDerivedKey=%p cbDerivedKey=%d pcbResult=%p dwFlags=%x\n", 
    //             hSharedSecret,
    //             debugstr_w(pwszKDF),
    //             pParameterList,
    //             pbDerivedKey,
    //             cbDerivedKey,
    //             pcbResult,
    //             dwFlags
    //         );

    if(pParameterList) {
        for(ULONG i=0;i<pParameterList->cBuffers;i++) {
            PBCryptBuffer bcb = pParameterList->pBuffers + i;            
            switch(bcb->BufferType) {
                case 4:
                    if(!bcb->cbBuffer || !bcb->pvBuffer)
                        return STATUS_INVALID_PARAMETER;
                    label = bcb->pvBuffer;
                    label_size = strnlen(label, bcb->cbBuffer);
                    if(label_size == bcb->cbBuffer || label_size > INT_MAX)
                        return STATUS_INVALID_PARAMETER;
                    have_label = TRUE;
                    break;

                case 7:
                    if(bcb->cbBuffer != sizeof(DWORD) || !bcb->pvBuffer)
                        return STATUS_INVALID_PARAMETER;
                    break;

                case 5:
                    if(bcb->cbBuffer != 64 || !bcb->pvBuffer)
                        return STATUS_INVALID_PARAMETER;
                    seed = bcb->pvBuffer;
                    break;

                default:
                    FIXME("Unsupported KDF parameter type %04x (%u bytes)\n",
                          bcb->BufferType, bcb->cbBuffer);
            }
        }
    }

    if(!have_label || !seed) return STATUS_INVALID_PARAMETER;
    *pcbResult = sizeof(derived);
    if(!pbDerivedKey) return STATUS_SUCCESS;
    if(cbDerivedKey < sizeof(derived)) return STATUS_BUFFER_TOO_SMALL;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if(!pctx || EVP_PKEY_derive_init(pctx) <= 0) goto done;

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
                         EVP_PKEY_CTRL_TLS_MD, 0,
                         (void *)EVP_sha256()) <= 0) goto done;

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
                         EVP_PKEY_CTRL_TLS_SECRET, secret->secret_size,
                         (void *)secret->secret) <= 0) goto done;

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
                         EVP_PKEY_CTRL_TLS_SEED, label_size,
                         (void *)label) <= 0) goto done;

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE,
                         EVP_PKEY_CTRL_TLS_SEED, 64,
                         (void *)seed) <= 0) goto done;

    if(EVP_PKEY_derive(pctx, derived, &derived_size) <= 0 ||
       derived_size != sizeof(derived)) goto done;

    memcpy(pbDerivedKey, derived, sizeof(derived));
    status = STATUS_SUCCESS;

done:
    OPENSSL_cleanse(derived, sizeof(derived));
    EVP_PKEY_CTX_free(pctx);
    return status;
}

NTSTATUS WINAPI BCryptDestroySecret(
  BCRYPT_SECRET_HANDLE hSecret
)
{
    FIXME("BCryptDestroySecret %p\n", hSecret);
    struct my_secret *secret = hSecret;
    if(!secret) return STATUS_INVALID_HANDLE;
    heap_free(secret->secret);
    heap_free(secret);
    return STATUS_SUCCESS;
}
