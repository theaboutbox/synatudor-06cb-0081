
BOOL openssl_init();

int derive_ec_pubkey(unsigned char *buf);

int ecc_sign(
            PUCHAR x, ULONG sx,
            PUCHAR y, ULONG sy,
            PUCHAR d, ULONG sd,
            PUCHAR src, ULONG src_len, 
            PUCHAR dst);
