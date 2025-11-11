
#include "config.h"
#include "wine/port.h"

#include <stdarg.h>
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
    BIGNUM *prv;
    EC_POINT *pub;
    EC_GROUP *curve;
    BN_CTX *ctx = BN_CTX_new();
    unsigned char *out;

    curve = EC_GROUP_new_by_curve_name(CURVE_NID);

    pub = EC_POINT_new(curve);
    prv = BN_bin2bn(buf+32*2, 32, NULL);

    ERR("d=%s\n", sBN_bn2hex(prv));

    if (1 != EC_POINT_mul(curve, pub, prv, NULL, NULL, ctx))
        puts("oops, EC_POINT_mul");

    if(65 != EC_POINT_point2buf(curve, pub, POINT_CONVERSION_UNCOMPRESSED, &out, ctx))
        puts("oops, EC_POINT_point2buf");

    memmove(buf, out+1, 32*2);

    pCRYPTO_free(out, OPENSSL_FILE, OPENSSL_LINE);
    BN_free(prv);
    EC_POINT_free(pub);
    EC_GROUP_free(curve);
    BN_CTX_free(ctx);

    return 0;
}


int ecc_sign(
            PUCHAR px, ULONG sx,
            PUCHAR py, ULONG sy,
            PUCHAR pd, ULONG sd,
            PUCHAR src, ULONG src_len, 
            PUCHAR dst)
{
    ERR("Enter ecc_sign\n");
    ERR("px ptr = %p size = %ul\n", px, sx);
    ERR("py ptr = %p size = %ul\n", py, sy);
    ERR("pd ptr = %p size = %ul\n", pd, sd);
    ERR("src ptr = %p size = %ul\n", src, src_len);
    ERR("dst ptr = %p\n", dst);

    EC_KEY *key = EC_KEY_new_by_curve_name(CURVE_NID);
    BIGNUM *x = BN_bin2bn(px, sx, NULL);
    BIGNUM *y = BN_bin2bn(py, sy, NULL);
    BIGNUM *d = BN_bin2bn(pd, sd, NULL);

    if(!x || !y || !d) {
        ERR("oops, one of pBN_bin2bn failed (%p %p %p)\n", x, y, d);
        return -1;
    }

    ERR("x=%s\n", sBN_bn2hex(x));
    ERR("y=%s\n", sBN_bn2hex(y));
    ERR("d=%s\n", sBN_bn2hex(d));

    if(!EC_KEY_set_private_key(key, d)) {
        ERR("oops, EC_KEY_set_public_key_affine_coordinates failed: %s\n", pERR_error_string(pERR_get_error(), NULL));
        return -1;
    }
    ERR("After Set private key\n");
#if 1
    if(!EC_KEY_set_public_key_affine_coordinates(key, x, y)) {
        ERR("oops, EC_KEY_set_public_key_affine_coordinates failed: %s\n", pERR_error_string(pERR_get_error(), NULL));
        return -1;
    }
    ERR("After Set public key\n");
#endif

    BIGNUM *kinv = BN_new();
    BIGNUM *rp = BN_new();;

    if(!ECDSA_sign_setup(key, NULL, &kinv, &rp)) {
        ERR("oops, ECDSA_sign_setup failed\n");
        return -1;
    }
    ERR("kinv=%s\n", sBN_bn2hex(kinv));
    ERR("rp=%s\n", sBN_bn2hex(rp));

    ERR("After BIGNUM convert");
    ECDSA_SIG *sig = ECDSA_do_sign_ex(src, src_len, kinv, rp, key);
    BN_free(kinv);
    BN_free(rp);

    if(sig == NULL) {
        ERR("oops, ECDSA_do_sign failed\n");
        return -1;
    }

    const BIGNUM *r = NULL;
    const BIGNUM *s = NULL;

    ECDSA_SIG_get0(sig, &r, &s);

    if(!BN_bn2binpad(r, dst, 32)) {
        ERR("oops, BN_bn2binpad failed for r\n");
        return -1;
    }

    if(!BN_bn2binpad(s, dst+32, 32)) {
        ERR("oops, BN_bn2binpad failed for s\n");
        return -1;
    }

    BN_free(r);
    BN_free(s);
    BN_free(d);
    BN_free(y);
    BN_free(x);

    return 0;
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
    gnutls_datum_t myX, myY, myD;
    BIGNUM *myXbn, *myYbn, *myDbn;
    EC_KEY *myKey = EC_KEY_new_by_curve_name(CURVE_NID);

    NTSTATUS ret;

    // my private key
    ret = get_gnutls_ecc_key_params(hPrivKey, &curve, &myX, &myY, &myD);
    if(ret) {
        ERR("oops, get_gnutls_ecc_key_params failed for my key\n");
        return STATUS_INTERNAL_ERROR;
    }
    
    myXbn = BN_bin2bn(myX.data, myX.size, NULL);
    ERR("my x=%s\n", sBN_bn2hex(myXbn));
    myYbn = BN_bin2bn(myY.data, myY.size, NULL);
    ERR("my y=%s\n", sBN_bn2hex(myYbn));
    myDbn = BN_bin2bn(myD.data, myD.size, NULL);
    ERR("my d=%s\n", sBN_bn2hex(myDbn));


    if(!myXbn || !myYbn || !myDbn) {
        ERR("oops, one of pBN_bin2bn failed\n");
        return STATUS_INTERNAL_ERROR;
    }

    if(!EC_KEY_set_public_key_affine_coordinates(myKey, myXbn, myYbn)) {
        ERR("oops, EC_KEY_set_public_key_affine_coordinates failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    if(!EC_KEY_set_private_key(myKey, myDbn)) {
        ERR("oops, EC_KEY_set_public_key_affine_coordinates failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
        return -1;
    }

    // peer pub key
    BIGNUM *peerXbn, *peerYbn;
    EC_KEY *peerKey = EC_KEY_new_by_curve_name(CURVE_NID);

    struct key *peerKeyInt = hPubKey;
    BCRYPT_ECCKEY_BLOB *ecc_blob = (BCRYPT_ECCKEY_BLOB *)peerKeyInt->u.a.pubkey;

    peerXbn = BN_bin2bn((unsigned char *)(ecc_blob+1), ecc_blob->cbKey, NULL);
    ERR("peer x=%s\n", BN_bn2hex(peerXbn));
    peerYbn = BN_bin2bn((unsigned char *)(ecc_blob+1) + ecc_blob->cbKey, ecc_blob->cbKey, NULL);
    ERR("peer y=%s\n", BN_bn2hex(peerYbn));

    if(!peerXbn || !peerYbn) {
        ERR("oops, one of pBN_bin2bn failed\n");
        return STATUS_INTERNAL_ERROR;
    }

    if(!EC_KEY_set_public_key_affine_coordinates(peerKey, peerXbn, peerYbn)) {
        ERR("oops, EC_KEY_set_public_key_affine_coordinates failed: %s\n", pERR_error_string(pERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    ERR("Yay! created both keys!\n");

    // shared secret
    

    EVP_PKEY *priv = EVP_PKEY_new(), *pub = EVP_PKEY_new();
    EVP_PKEY_set1_EC_KEY(priv, myKey);
    EVP_PKEY_set1_EC_KEY(pub, peerKey);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if(!ctx) {
        ERR("oops, pEVP_PKEY_CTX_new failed");
        return STATUS_INTERNAL_ERROR;
    }

    ERR("ctx created\n");

    if(EVP_PKEY_derive_init(ctx) <= 0) {
        ERR("oops, pEVP_PKEY_CTX_new failed");
        return STATUS_INTERNAL_ERROR;
    }

    ERR("derive initiated\n");

    if(EVP_PKEY_derive_set_peer(ctx, pub) <= 0) {
        ERR("oops, EVP_PKEY_derive_set_peer failed");
        return STATUS_INTERNAL_ERROR;
    }

    ERR("peer set\n");

    struct my_secret *secret = heap_alloc(sizeof(struct my_secret));
    *phAgreedSecret = secret;

    size_t sz = 0;

    if(EVP_PKEY_derive(ctx, NULL, &sz) <= 0) {
        ERR("oops, EVP_PKEY_derive failed");
        return STATUS_INTERNAL_ERROR;
    }

    secret->secret = heap_alloc(sz);

    if(EVP_PKEY_derive(ctx, secret->secret, &secret->secret_size) <= 0) {
        ERR("oops, EVP_PKEY_derive failed");
        return STATUS_INTERNAL_ERROR;
    }


    // FIXME - release all the memory
    // FIXME - fix error handling
    
    return STATUS_SUCCESS;
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
    char label[1024];
    PUCHAR seed = NULL;
    DWORD proto = 0;

    label[0] = 0;

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
        for(int i=0;i<pParameterList->cBuffers;i++) {
            PBCryptBuffer bcb = pParameterList->pBuffers + i;            
            char hex[1024], *p;
            int j;

            switch(bcb->BufferType) {
                case 4:
                    memcpy(label, bcb->pvBuffer, bcb->cbBuffer);
                    label[bcb->cbBuffer] = 0;
                    FIXME("  Label: %s\n", label);
                    break;

                case 7:
                    proto = *(DWORD*)bcb->pvBuffer;
                    FIXME("  Protocol: %x\n", proto);
                    break;

                case 5:
                    if(bcb->cbBuffer != 64) {
                        ERR("Seed must be 64 bytes long\n");
                        return STATUS_INTERNAL_ERROR;
                    }
                    seed = bcb->pvBuffer;

                    p = hex;
                    for(j=0;j<64;j++) {
                        p += sprintf(p, "%02x", seed[j]);
                    }
                    *p = 0;
                    FIXME("  Seed: %s\n", hex);
                    break;

                default:
                    p = hex;
                    for(j=0;j<bcb->cbBuffer;j++) {
                        p += sprintf(p, "%02x", ((PUCHAR)bcb->pvBuffer)[j]);
                    }
                    *p = 0;
                    FIXME("  %04x: %s\n", bcb->BufferType, hex);
            }
        }
    }


    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_TLS1_PRF, NULL);
    if (EVP_PKEY_derive_init(pctx) <= 0) {
        ERR("EVP_PKEY_derive_init: %s\n", pERR_error_string(pERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_MD, 0, (void *)EVP_sha256()) <= 0) {
        ERR("EVP_PKEY_CTX_set_tls1_prf_md: %s\n", pERR_error_string(pERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_SECRET, secret->secret_size, (void *)secret->secret) <= 0) {
        ERR("EVP_PKEY_CTX_set1_tls1_prf_secret: %s\n", pERR_error_string(pERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_SEED, strlen(label), (void *)label) <= 0) {
        ERR("EVP_PKEY_CTX_add1_tls1_prf_seed(label): %s\n", pERR_error_string(pERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    if(EVP_PKEY_CTX_ctrl(pctx, -1, EVP_PKEY_OP_DERIVE, EVP_PKEY_CTRL_TLS_SEED, 64, (void *)seed) <= 0) {
        ERR("EVP_PKEY_CTX_add1_tls1_prf_seed(seed): %s\n", pERR_error_string(pERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    unsigned char buf[48];
    size_t sz = sizeof(buf);

    if (EVP_PKEY_derive(pctx, buf, &sz) <= 0) {
        ERR("EVP_PKEY_derive: %s\n", pERR_error_string(pERR_get_error(), NULL));
        return STATUS_INTERNAL_ERROR;
    }

    if(sz != sizeof(buf)) {
        ERR("EVP_PKEY_derive was expected to return %ld bytes instead of %ld?\n", sizeof(buf), sz);
        return STATUS_INTERNAL_ERROR;
    }

    char hex[1024], *p = hex;
    for(int i=0;i < sz;i++)
        p += sprintf(p, "%02x", buf[i]);
    *p = 0;
    ERR("tls_prf: %s\n", hex);

    ERR("%d < %ld?\n", cbDerivedKey, sz);

    if(pbDerivedKey && cbDerivedKey >= sz) {
        memcpy(pbDerivedKey, buf, sz);
    } else {
        return STATUS_INTERNAL_ERROR;
    }

    if(pcbResult) {
        *pcbResult = sz;
    }

    return STATUS_SUCCESS;
}

NTSTATUS WINAPI BCryptDestroySecret(
  BCRYPT_SECRET_HANDLE hSecret
)
{
    FIXME("BCryptDestroySecret %p\n", hSecret);
    // FIXME
    return STATUS_SUCCESS;
}
