#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <uchar.h>

#include "internal.h"

static struct __winapi_descr *descr_head;

void __register_windows_api(struct __winapi_descr *descr) {
    descr->next = descr_head;
    descr_head = descr;
}

void *resolve_windows_api(const char *name) {
    for(struct __winapi_descr *d = descr_head; d; d = d->next) {
        if(strcmp(d->name, name) == 0) return d->func;
    }
    printf("Can't resolve win API! %s\n", name);
    return NULL;
}

int winstr_len(const char16_t *str) {
    int len = 0;
    for(const char16_t *p = str; *p; p++) len++;
    return len;
}

/*
char16_t* winstr_from_str(const char *str) {
    if (!str) return NULL;

    iconv_t cd = iconv_open("UTF-16LE", "UTF-8");
    if (cd == (iconv_t)(-1)) return NULL;

    size_t inbytes = strlen(str);
    size_t outbytes = (inbytes + 1) * sizeof(char16_t);
    char16_t *outbuf = malloc(outbytes);
    if (!outbuf) {
        iconv_close(cd);
        return NULL;
    }

    char *inptr = (char *)str;
    char *outptr = (char *)outbuf;
    size_t inleft = inbytes;
    size_t outleft = outbytes;

    if (iconv(cd, &inptr, &inleft, &outptr, &outleft) == (size_t)(-1)) {
        free(outbuf);
        iconv_close(cd);
        return NULL;
    }

    // Null-terminate
    if (outleft >= 2) {
        *(char16_t *)outptr = 0;
    } else {
        outbuf[(outbytes / sizeof(char16_t)) - 1] = 0;
    }

    iconv_close(cd);
    return outbuf;
}
*/

char16_t *winstr_from_str(const char *str) {
    if(!str) return NULL;

    size_t input_size = strlen(str) + 1;
    size_t output_size;
    if(win_utf8_to_utf16(str, input_size, NULL, 0, &output_size) !=
       WIN_UTF_OK)
        return NULL;

    char16_t *wstr = malloc(output_size * sizeof(*wstr));
    if(!wstr) { perror("Couldn't allocate memory for string"); abort(); }
    if(win_utf8_to_utf16(str, input_size, wstr, output_size, NULL) !=
       WIN_UTF_OK) {
        free(wstr);
        return NULL;
    }
    return wstr;
}

char *winstr_to_str(const char16_t *wstr) {
    if(!wstr) return NULL;

    size_t input_size = (size_t) winstr_len(wstr) + 1;
    size_t output_size;
    if(win_utf16_to_utf8(wstr, input_size, NULL, 0, &output_size) !=
       WIN_UTF_OK)
        return NULL;

    char *str = malloc(output_size);
    if(!str) { perror("Couldn't allocate memory for string"); abort(); }
    if(win_utf16_to_utf8(wstr, input_size, str, output_size, NULL) !=
       WIN_UTF_OK) {
        free(str);
        return NULL;
    }
    return str;
}

void print_hex_str(const char* name, uint8_t* buf, size_t size)
{
    if (name != NULL) printf("[Hex] %s %d:\n", name, (int) size);
    for (size_t i = 0; i < size; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}
