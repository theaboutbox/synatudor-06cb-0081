
BOOL openssl_init(void) DECLSPEC_HIDDEN;

int derive_ec_pubkey(unsigned char *buf) DECLSPEC_HIDDEN;

int ecc_sign(
            PUCHAR x, ULONG sx,
            PUCHAR y, ULONG sy,
            PUCHAR d, ULONG sd,
            PUCHAR src, ULONG src_len,
            PUCHAR dst) DECLSPEC_HIDDEN;
