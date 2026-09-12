#include "internal.h"
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <stdint.h>

#define MAX_DEFAULTCHAR 2
#define MAX_LEADBYTES 12

typedef struct {
    UINT MaxCharSize;
    BYTE DefaultChar[MAX_DEFAULTCHAR];
    BYTE LeadByte[MAX_LEADBYTES];
} CPINFO;

__winfnc UINT GetACP() {
    return 1200; //UTF-16
}
WINAPI(GetACP)

__winfnc BOOL IsValidCodePage(UINT code_page) {
    TRACE();
    switch(code_page) {
        case 65001: return TRUE; //UTF-8
        case 1200: return TRUE; //UTF-16
        case 12000: return TRUE; //UTF-32
        default: return FALSE;
    }
}
WINAPI(IsValidCodePage)

__winfnc BOOL GetCPInfo(UINT code_page, CPINFO *info) {
    TRACE();
    switch(code_page) {
        case 65001: *info = (CPINFO) { .MaxCharSize = 1, .DefaultChar = { '?' } }; return TRUE; //UTF-8
        case 1200: *info = (CPINFO) { .MaxCharSize = 2, .DefaultChar = { '?' } }; return TRUE; //UTF-16
        case 12000: *info = (CPINFO) { .MaxCharSize = 4, .DefaultChar = { '?' } }; return TRUE; //UTF-32
        default: return FALSE;
    }
}
WINAPI(GetCPInfo)

#define CP_ACP          0       // Default to ANSI code page
#define CP_OEMCP        1       // Default to OEM code page  
#define CP_MACCP        2       // Default to MAC code page
#define CP_THREAD_ACP   3       // Current thread's ANSI code page
#define CP_SYMBOL       42      // Symbol code page
#define CP_UTF7         65000   // UTF-7 translation
#define CP_UTF8         65001   // UTF-8 translation

static enum win_utf_result utf8_size(const char *input, size_t input_size,
                                     size_t *output_size) {
    size_t offset = 0, required = 0;

    while(offset < input_size) {
        const unsigned char *bytes = (const unsigned char*) input + offset;
        uint32_t codepoint;
        size_t sequence_size;

        if(bytes[0] < 0x80) {
            codepoint = bytes[0];
            sequence_size = 1;
        } else if(bytes[0] >= 0xc2 && bytes[0] <= 0xdf) {
            codepoint = bytes[0] & 0x1f;
            sequence_size = 2;
        } else if(bytes[0] >= 0xe0 && bytes[0] <= 0xef) {
            codepoint = bytes[0] & 0x0f;
            sequence_size = 3;
        } else if(bytes[0] >= 0xf0 && bytes[0] <= 0xf4) {
            codepoint = bytes[0] & 0x07;
            sequence_size = 4;
        } else {
            return WIN_UTF_INVALID;
        }

        if(sequence_size > input_size - offset) return WIN_UTF_INVALID;
        for(size_t i = 1; i < sequence_size; i++) {
            if((bytes[i] & 0xc0) != 0x80) return WIN_UTF_INVALID;
            codepoint = (codepoint << 6) | (bytes[i] & 0x3f);
        }

        if((sequence_size == 3 && bytes[0] == 0xe0 && bytes[1] < 0xa0) ||
           (sequence_size == 3 && bytes[0] == 0xed && bytes[1] >= 0xa0) ||
           (sequence_size == 4 && bytes[0] == 0xf0 && bytes[1] < 0x90) ||
           (sequence_size == 4 && bytes[0] == 0xf4 && bytes[1] >= 0x90) ||
           codepoint > 0x10ffff ||
           (codepoint >= 0xd800 && codepoint <= 0xdfff))
            return WIN_UTF_INVALID;

        size_t units = codepoint > 0xffff ? 2 : 1;
        if(required > SIZE_MAX - units) return WIN_UTF_OVERFLOW;
        required += units;
        offset += sequence_size;
    }

    *output_size = required;
    return WIN_UTF_OK;
}

enum win_utf_result win_utf8_to_utf16(const char *input, size_t input_size,
                                      char16_t *output, size_t output_size,
                                      size_t *converted_size) {
    if(!input) return WIN_UTF_INVALID;

    size_t required;
    enum win_utf_result result = utf8_size(input, input_size, &required);
    if(result != WIN_UTF_OK) return result;
    if(converted_size) *converted_size = required;
    if(!output) return WIN_UTF_OK;
    if(output_size < required) return WIN_UTF_BUFFER_TOO_SMALL;

    size_t input_offset = 0, output_offset = 0;
    while(input_offset < input_size) {
        const unsigned char *bytes =
            (const unsigned char*) input + input_offset;
        uint32_t codepoint;
        size_t sequence_size;
        if(bytes[0] < 0x80) {
            codepoint = bytes[0];
            sequence_size = 1;
        } else if(bytes[0] <= 0xdf) {
            codepoint = bytes[0] & 0x1f;
            sequence_size = 2;
        } else if(bytes[0] <= 0xef) {
            codepoint = bytes[0] & 0x0f;
            sequence_size = 3;
        } else {
            codepoint = bytes[0] & 0x07;
            sequence_size = 4;
        }
        for(size_t i = 1; i < sequence_size; i++)
            codepoint = (codepoint << 6) | (bytes[i] & 0x3f);

        if(codepoint <= 0xffff) {
            output[output_offset++] = (char16_t) codepoint;
        } else {
            codepoint -= 0x10000;
            output[output_offset++] =
                (char16_t) (0xd800 + (codepoint >> 10));
            output[output_offset++] =
                (char16_t) (0xdc00 + (codepoint & 0x3ff));
        }
        input_offset += sequence_size;
    }
    return WIN_UTF_OK;
}

static enum win_utf_result utf16_size(const char16_t *input,
                                      size_t input_size,
                                      size_t *output_size) {
    size_t required = 0;

    for(size_t i = 0; i < input_size; i++) {
        uint32_t codepoint = input[i];
        if(codepoint >= 0xd800 && codepoint <= 0xdbff) {
            if(++i >= input_size || input[i] < 0xdc00 || input[i] > 0xdfff)
                return WIN_UTF_INVALID;
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) +
                        (input[i] - 0xdc00);
        } else if(codepoint >= 0xdc00 && codepoint <= 0xdfff) {
            return WIN_UTF_INVALID;
        }

        size_t bytes = codepoint < 0x80 ? 1 :
                       codepoint < 0x800 ? 2 :
                       codepoint < 0x10000 ? 3 : 4;
        if(required > SIZE_MAX - bytes) return WIN_UTF_OVERFLOW;
        required += bytes;
    }

    *output_size = required;
    return WIN_UTF_OK;
}

enum win_utf_result win_utf16_to_utf8(const char16_t *input,
                                      size_t input_size, char *output,
                                      size_t output_size,
                                      size_t *converted_size) {
    if(!input) return WIN_UTF_INVALID;

    size_t required;
    enum win_utf_result result = utf16_size(input, input_size, &required);
    if(result != WIN_UTF_OK) return result;
    if(converted_size) *converted_size = required;
    if(!output) return WIN_UTF_OK;
    if(output_size < required) return WIN_UTF_BUFFER_TOO_SMALL;

    size_t output_offset = 0;
    for(size_t i = 0; i < input_size; i++) {
        uint32_t codepoint = input[i];
        if(codepoint >= 0xd800 && codepoint <= 0xdbff) {
            uint32_t low = input[++i];
            codepoint = 0x10000 + ((codepoint - 0xd800) << 10) +
                        (low - 0xdc00);
        }

        if(codepoint < 0x80) {
            output[output_offset++] = (char) codepoint;
        } else if(codepoint < 0x800) {
            output[output_offset++] = (char) (0xc0 | (codepoint >> 6));
            output[output_offset++] = (char) (0x80 | (codepoint & 0x3f));
        } else if(codepoint < 0x10000) {
            output[output_offset++] = (char) (0xe0 | (codepoint >> 12));
            output[output_offset++] =
                (char) (0x80 | ((codepoint >> 6) & 0x3f));
            output[output_offset++] = (char) (0x80 | (codepoint & 0x3f));
        } else {
            output[output_offset++] = (char) (0xf0 | (codepoint >> 18));
            output[output_offset++] =
                (char) (0x80 | ((codepoint >> 12) & 0x3f));
            output[output_offset++] =
                (char) (0x80 | ((codepoint >> 6) & 0x3f));
            output[output_offset++] = (char) (0x80 | (codepoint & 0x3f));
        }
    }
    return WIN_UTF_OK;
}

static int utf_result_to_win32(enum win_utf_result result, size_t converted) {
    if(result == WIN_UTF_OK && converted <= INT_MAX) return (int) converted;
    if(result == WIN_UTF_BUFFER_TOO_SMALL)
        winerr_set_code(ERROR_INSUFFICIENT_BUFFER);
    else
        winerr_set_code(ERROR_NO_UNICODE_TRANSLATION);
    return 0;
}

__winfnc int MultiByteToWideChar(UINT code_page, DWORD flags,
        const char *mbstr, int mblen, char16_t *wstr, int wlen) {
    TRACE();
    (void) code_page;
    (void) flags;
    if(!mbstr || mblen == 0 || mblen < -1 || wlen < 0) {
        winerr_set_code(ERROR_INVALID_PARAMETER);
        return 0;
    }

    size_t input_size = mblen == -1 ? strlen(mbstr) + 1 : (size_t) mblen;
    size_t converted = 0;
    enum win_utf_result result = win_utf8_to_utf16(
        mbstr, input_size, wstr, wstr ? (size_t) wlen : 0, &converted);
    return utf_result_to_win32(result, converted);
}
WINAPI(MultiByteToWideChar)

__winfnc int WideCharToMultiByte(UINT code_page, DWORD flags,
        const char16_t *wstr, int wlen, char *mbstr, int mblen,
        void *lpDefaultChar, void *lpUsedDefaultChar) {
    TRACE();
    (void) code_page;
    (void) flags;
    (void) lpDefaultChar;
    if(lpUsedDefaultChar) *(BOOL*) lpUsedDefaultChar = FALSE;
    if(!wstr || wlen == 0 || wlen < -1 || mblen < 0) {
        winerr_set_code(ERROR_INVALID_PARAMETER);
        return 0;
    }

    size_t input_size = wlen == -1 ? (size_t) winstr_len(wstr) + 1
                                   : (size_t) wlen;
    size_t converted = 0;
    enum win_utf_result result = win_utf16_to_utf8(
        wstr, input_size, mbstr, mbstr ? (size_t) mblen : 0, &converted);
    return utf_result_to_win32(result, converted);
}
WINAPI(WideCharToMultiByte)


__winfnc int GetStringTypeW(DWORD info_type, const char16_t *str, int strlen, WORD* char_types) {
    TRACE();
    if(strlen < 0) strlen = winstr_len(str);

    //TODO
    memset(char_types, 0, strlen * sizeof(WORD));
    return 0;
}
WINAPI(GetStringTypeW)

__winfnc int LCMapStringW(DWORD lcid, DWORD flags, const char16_t *in, int inlen, char16_t *out, int outlen) {
    TRACE();
    if(inlen < 0) inlen = winstr_len(in);
    if(outlen == 0) return (inlen + 1) * sizeof(char16_t);

    //TODO
    if(outlen < inlen) {
        winerr_set();
        return 0;
    }

    memcpy(out, in, (inlen + 1) * sizeof(char16_t));
    return outlen;
}
WINAPI(LCMapStringW)

typedef const wchar_t* PCWSTR;
typedef const wchar_t* LPCWSTR;
typedef wchar_t* LPWSTR;
typedef wchar_t* PWSTR;
typedef void* LPVOID;
typedef wchar_t* LPOLESTR;

__winfnc int LCMapStringEx(
  LPCWSTR          lpLocaleName,
  DWORD            dwMapFlags,
  LPCWSTR          in,
  int              inlen,
  LPWSTR           out,
  int              outlen,
  void* lpVersionInformation,
  LPVOID           lpReserved,
  DWORD           sortHandle)
{
    TRACE();


    if(inlen < 0) inlen = winstr_len(in);
    if(outlen == 0) return (inlen + 1) * sizeof(char16_t);

    //TODO
    if(outlen < inlen) {
        winerr_set();
        return 0;
    }

    memcpy(out, in, (inlen + 1) * sizeof(char16_t));
    return outlen;
}
WINAPI(LCMapStringEx)

__winfnc void RtlInitUnicodeString(UNICODE_STRING *dst, const char16_t *src) {
    TRACE();
    if(src) {
        int len = winstr_len(src);
        dst->Length = dst->MaximumLength = len+1;
        dst->Buffer = (char16_t*) malloc((len+1) * sizeof(char16_t));
        if(!dst->Buffer) { perror("Couldn't allocate UNICODE_STRING buffer"); abort(); }
        memcpy(dst->Buffer, src, (len+1) * sizeof(char16_t));
    } else {
        dst->Length = dst->MaximumLength = 0;
        dst->Buffer = NULL;
    }
}
WINAPI(RtlInitUnicodeString)

__winfnc int lstrlenA(const char *str) {
    TRACE();
    printf("Strlen: %s\n", str);
    fflush(stdout);
    return (int) strlen(str);
}
WINAPI(lstrlenA)

__winfnc char16_t *lstrcpynW(char16_t *dst, const char16_t *src, int max_len) {
    TRACE();
    for(; *src && max_len > 0; src++, dst++, max_len--) *dst = *src;
    *dst = 0;
    return dst;
}
WINAPI(lstrcpynW);

__winfnc int lstrcmpW(const char16_t *a, const char16_t *b) {
    TRACE();
    int a_len = winstr_len(a), b_len = winstr_len(b);
    if(a_len < b_len) return -1;
    if(a_len > b_len) return -1;
    return memcmp(a, b, a_len * sizeof(char16_t));
}
WINAPI(lstrcmpW);
