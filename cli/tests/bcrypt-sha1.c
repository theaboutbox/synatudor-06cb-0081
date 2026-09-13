#include <assert.h>
#include <string.h>

#include "windef.h"
#include "bcrypt.h"

extern void *resolve_windows_api( const char *name );

static const UCHAR sha1_empty[20] = {
    0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
    0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
};

static const UCHAR sha1_abc[20] = {
    0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e,
    0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
};

static const UCHAR sha1_long[20] = {
    0x84, 0x98, 0x3e, 0x44, 0x1c, 0x3b, 0xd2, 0x6e, 0xba, 0xae,
    0x4a, 0xa1, 0xf9, 0x51, 0x29, 0xe5, 0xe5, 0x46, 0x70, 0xf1
};

static const UCHAR sha1_abcdef[20] = {
    0x1f, 0x8a, 0xc1, 0x0f, 0x23, 0xc5, 0xb5, 0xbc, 0x11, 0x67,
    0xbd, 0xa8, 0x4b, 0x83, 0x3e, 0x5c, 0x05, 0x7a, 0x77, 0xd2
};

static const UCHAR sha1_abcxyz[20] = {
    0x0e, 0x3b, 0xbd, 0x26, 0xf4, 0x60, 0x12, 0xcc, 0xec, 0x47,
    0x76, 0xd1, 0x71, 0xf3, 0x14, 0xa0, 0x0c, 0x02, 0x2d, 0x98
};

static const UCHAR hmac_sha1[20] = {
    0xb6, 0x17, 0x31, 0x86, 0x55, 0x05, 0x72, 0x64, 0xe2, 0x8b,
    0xc0, 0xb6, 0xfb, 0x37, 0x8c, 0x8e, 0xf1, 0x46, 0xbe, 0x00
};

static void expect_hash( BCRYPT_ALG_HANDLE algorithm, const UCHAR *input,
                         ULONG input_size, const UCHAR expected[20] )
{
    BCRYPT_HASH_HANDLE hash;
    UCHAR output[20];

    assert(BCryptCreateHash( algorithm, NULL, NULL, 0, NULL, 0, 0 ) != 0);
    assert(BCryptCreateHash( algorithm, &hash, NULL, 0, NULL, 1, 0 ) != 0);
    assert(!BCryptCreateHash( algorithm, &hash, NULL, 0, NULL, 0, 0 ));
    ULONG length = 0, returned = 0;
    assert(!BCryptGetProperty(hash, BCRYPT_HASH_LENGTH, (UCHAR *)&length,
                             sizeof(length), &returned, 0));
    assert(length == 20 && returned == sizeof(length));
    assert(!BCryptHashData( hash, (UCHAR *)input, input_size, 0 ));
    assert(!BCryptFinishHash( hash, output, sizeof(output), 0 ));
    assert(!memcmp( output, expected, sizeof(output) ));
    assert(!BCryptDestroyHash( hash ));
}

static void test_duplicate( BCRYPT_ALG_HANDLE algorithm )
{
    static UCHAR prefix[] = "abc";
    static UCHAR original_suffix[] = "def";
    static UCHAR copy_suffix[] = "xyz";
    BCRYPT_HASH_HANDLE original, copy;
    UCHAR output[20];

    assert(!BCryptCreateHash( algorithm, &original, NULL, 0, NULL, 0, 0 ));
    assert(!BCryptHashData( original, prefix, sizeof(prefix) - 1, 0 ));
    assert(!BCryptDuplicateHash( original, &copy, NULL, 0, 0 ));

    assert(!BCryptHashData( original, original_suffix, sizeof(original_suffix) - 1, 0 ));
    assert(!BCryptFinishHash( original, output, sizeof(output), 0 ));
    assert(!memcmp( output, sha1_abcdef, sizeof(output) ));

    assert(!BCryptHashData( copy, copy_suffix, sizeof(copy_suffix) - 1, 0 ));
    assert(!BCryptFinishHash( copy, output, sizeof(output), 0 ));
    assert(!memcmp( output, sha1_abcxyz, sizeof(output) ));

    assert(!BCryptDestroyHash( copy ));
    assert(!BCryptDestroyHash( original ));
}

static void test_reusable( BCRYPT_ALG_HANDLE algorithm )
{
    static UCHAR input[] = "abc";
    BCRYPT_HASH_HANDLE hash;
    UCHAR output[20];
    unsigned int i;

    assert(!BCryptCreateHash( algorithm, &hash, NULL, 0, NULL, 0,
                              BCRYPT_HASH_REUSABLE_FLAG ));
    for (i = 0; i < 2; ++i)
    {
        assert(!BCryptHashData( hash, input, sizeof(input) - 1, 0 ));
        assert(!BCryptFinishHash( hash, output, sizeof(output), 0 ));
        assert(!memcmp( output, sha1_abc, sizeof(output) ));
    }
    assert(!BCryptDestroyHash( hash ));
}

static void test_hmac(void)
{
    static UCHAR key[20] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    static UCHAR input[] = "Hi There";
    BCRYPT_ALG_HANDLE algorithm;
    BCRYPT_HASH_HANDLE hash;
    UCHAR output[20];

    assert(!BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA1_ALGORITHM,
                                         MS_PRIMITIVE_PROVIDER,
                                         BCRYPT_ALG_HANDLE_HMAC_FLAG ));
    assert(!BCryptCreateHash( algorithm, &hash, NULL, 0, key, sizeof(key), 0 ));
    assert(!BCryptHashData( hash, input, sizeof(input) - 1, 0 ));
    assert(!BCryptFinishHash( hash, output, sizeof(output), 0 ));
    assert(!memcmp( output, hmac_sha1, sizeof(output) ));
    assert(!BCryptDestroyHash( hash ));
    assert(!BCryptCloseAlgorithmProvider( algorithm, 0 ));
}

int main(void)
{
    static UCHAR empty[] = "";
    static UCHAR abc[] = "abc";
    static UCHAR long_input[] =
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    BCRYPT_ALG_HANDLE algorithm;

    assert(resolve_windows_api( "BCryptOpenAlgorithmProvider" ));
    assert(!BCryptOpenAlgorithmProvider( &algorithm, BCRYPT_SHA1_ALGORITHM,
                                         MS_PRIMITIVE_PROVIDER, 0 ));
    expect_hash( algorithm, empty, 0, sha1_empty );
    expect_hash( algorithm, abc, sizeof(abc) - 1, sha1_abc );
    expect_hash( algorithm, long_input, sizeof(long_input) - 1, sha1_long );
    test_duplicate( algorithm );
    test_reusable( algorithm );
    assert(!BCryptCloseAlgorithmProvider( algorithm, 0 ));

    test_hmac();
    return 0;
}
