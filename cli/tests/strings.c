#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "winapi/api.h"

#define CP_UTF8 65001
#define MB_ERR_INVALID_CHARS 0x00000008
#define WC_ERR_INVALID_CHARS 0x00000080

extern __winfnc int MultiByteToWideChar(UINT, DWORD, const char *, int,
                                        char16_t *, int);
extern __winfnc int WideCharToMultiByte(UINT, DWORD, const char16_t *, int,
                                        char *, int, void *, void *);
extern __winfnc DWORD GetLastError(void);

static void test_utf16_to_utf8(void) {
    static const char16_t input[] = {u'A', 0x00e9, 0xd83d, 0xde00, 0};
    static const char expected[] = "A\xc3\xa9\xf0\x9f\x98\x80";
    char output[sizeof(expected)] = {0};

    assert(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1,
                               NULL, 0, NULL, NULL) == sizeof(expected));
    assert(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1,
                               output, sizeof(output), NULL, NULL) ==
           sizeof(expected));
    assert(!memcmp(output, expected, sizeof(expected)));

    memset(output, 0x5a, sizeof(output));
    assert(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, 4,
                               output, sizeof(output), NULL, NULL) ==
           sizeof(expected) - 1);
    assert(!memcmp(output, expected, sizeof(expected) - 1));

    assert(!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, input, -1,
                                output, sizeof(output) - 1, NULL, NULL));
    assert(GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    static const char16_t malformed_high[] = {0xd83d, u'A'};
    static const char16_t malformed_low[] = {0xde00};
    assert(!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                malformed_high, 2, NULL, 0, NULL, NULL));
    assert(GetLastError() == ERROR_NO_UNICODE_TRANSLATION);
    assert(!WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                                malformed_low, 1, NULL, 0, NULL, NULL));
    assert(GetLastError() == ERROR_NO_UNICODE_TRANSLATION);
}

static void test_utf8_to_utf16(void) {
    static const char input[] = "A\xc3\xa9\xf0\x9f\x98\x80";
    static const char16_t expected[] = {u'A', 0x00e9, 0xd83d, 0xde00, 0};
    char16_t output[sizeof(expected) / sizeof(expected[0])] = {0};

    assert(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                               NULL, 0) == 5);
    assert(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                               output, 5) == 5);
    assert(!memcmp(output, expected, sizeof(expected)));

    memset(output, 0x5a, sizeof(output));
    assert(MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input,
                               sizeof(input) - 1, output, 5) == 4);
    assert(!memcmp(output, expected, sizeof(expected) - sizeof(expected[0])));

    assert(!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, input, -1,
                                output, 4));
    assert(GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    static const char malformed[] = "\xf0\x28\x8c\x28";
    assert(!MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, malformed,
                                sizeof(malformed) - 1, NULL, 0));
    assert(GetLastError() == ERROR_NO_UNICODE_TRANSLATION);
}

int main(void) {
    test_utf16_to_utf8();
    test_utf8_to_utf16();

    char16_t *wide = winstr_from_str("Sensor \xc3\xa9 \xf0\x9f\x98\x80");
    assert(wide);
    char *roundtrip = winstr_to_str(wide);
    assert(roundtrip);
    assert(!strcmp(roundtrip, "Sensor \xc3\xa9 \xf0\x9f\x98\x80"));
    free(roundtrip);
    free(wide);
    return 0;
}
