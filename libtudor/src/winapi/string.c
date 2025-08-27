#include "internal.h"
#include <iconv.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
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

__winfnc int MultiByteToWideChar(UINT code_page, DWORD flags, const char *mbstr, int mblen, char16_t *wstr, int wlen) {
    TRACE();
    if(mblen < 0) mblen = strlen(mbstr);
    if(mblen == 0) {
        winerr_set();
        return 0;
    }

    mbstate_t mbs = {0};
    int sz = mbrtoc16((0 < wlen) ? wstr : NULL, mbstr, mblen, &mbs);
    if(sz > 0) return sz;
    winerr_set();
    return 0;
}
WINAPI(MultiByteToWideChar)


#define CP_ACP          0       // Default to ANSI code page
#define CP_OEMCP        1       // Default to OEM code page  
#define CP_MACCP        2       // Default to MAC code page
#define CP_THREAD_ACP   3       // Current thread's ANSI code page
#define CP_SYMBOL       42      // Symbol code page
#define CP_UTF7         65000   // UTF-7 translation
#define CP_UTF8         65001   // UTF-8 translation


__winfnc int WideCharToMultiByte(UINT code_page, DWORD flags, const char16_t *wstr, int wlen, char *mbstr, int mblen, void* lpDefaultChar, void* lpUsedDefaultChar) {
    TRACE();
    // Ignore code_page, flags, lpDefaultChar, lpUsedDefaultChar as specified
    (void)code_page;
    (void)flags;
    (void)lpDefaultChar;
    (void)lpUsedDefaultChar;
    
    // Handle null input
    if (wstr == NULL) {
        return 0;
    }
    
    // Calculate input length if not specified
    size_t input_len;
    if (wlen == -1) {
        // Find null terminator
        input_len = 0;
        while (wstr[input_len] != 0) {
            input_len++;
        }
        input_len++; // Include null terminator
    } else {
        input_len = (size_t)wlen;
    }
    
    // Convert input length to bytes (UTF-16LE uses 2 bytes per character)
    size_t input_bytes = input_len * sizeof(char16_t);
    
    // Open iconv conversion descriptor
    iconv_t cd = iconv_open("UTF-8", "UTF-16LE");
    if (cd == (iconv_t)-1) {
        return 0; // Failed to open converter
    }
    
    // If mbstr is NULL, calculate required buffer size
    if (mbstr == NULL) {
        // Create temporary buffer for size calculation
        char temp_buffer[4096];
        char *outbuf = temp_buffer;
        size_t outbytesleft = sizeof(temp_buffer);
        const char *inbuf = (const char*)wstr;
        size_t inbytesleft = input_bytes;
        
        size_t total_output = 0;
        
        while (inbytesleft > 0) {
            outbuf = temp_buffer;
            outbytesleft = sizeof(temp_buffer);
            
            size_t result = iconv(cd, (char**)&inbuf, &inbytesleft, &outbuf, &outbytesleft);
            size_t converted = sizeof(temp_buffer) - outbytesleft;
            total_output += converted;
            
            if (result == (size_t)-1) {
                if (errno == E2BIG) {
                    // Buffer full, continue with next chunk
                    continue;
                } else {
                    // Conversion error
                    iconv_close(cd);
                    return 0;
                }
            }
        }
        
        iconv_close(cd);
        return (int)total_output;
    }
    
    // Perform actual conversion
    char *outbuf = mbstr;
    size_t outbytesleft = (size_t)mblen;
    const char *inbuf = (const char*)wstr;
    size_t inbytesleft = input_bytes;
    
    size_t result = iconv(cd, (char**)&inbuf, &inbytesleft, &outbuf, &outbytesleft);
    
    iconv_close(cd);
    
    if (result == (size_t)-1) {
        if (errno == E2BIG) {
            // Output buffer too small
            return 0;
        } else {
            // Other conversion error
            return 0;
        }
    }
    
    // Return number of bytes written (excluding null terminator if present)
    size_t bytes_written = (size_t)mblen - outbytesleft;
    
    // If there's space and input was null-terminated, ensure output is null-terminated
    if (wlen == -1 && bytes_written < (size_t)mblen) {
        mbstr[bytes_written] = '\0';
    }
    
    return (int)bytes_written;
    
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
