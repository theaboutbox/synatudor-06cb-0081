#include "crypt.h"


static void rsa_aes_destroy_key(struct crypt_provider *prov, void *key) {
    printf("rsa_aes_destroy_key\n");
}


static BOOL rsa_aes_set_key(struct crypt_key* prov, void** key, DWORD dwParam, const BYTE *pbData, DWORD dwFlags) {
    printf("rsa_aes_set_key\n");
    return true;
}

struct crypt_provider crypt_prov_rsa_aes = {
    .import_key = (crypt_import_key_fnc*) NULL,
    .destroy_key = (crypt_destroy_key_fnc*) rsa_aes_destroy_key,
    .set_key = (crypt_set_key_fnc*) rsa_aes_set_key
};
