#ifndef CRYPTBRIDGE_BCRYPT_ECC_UTIL_H
#define CRYPTBRIDGE_BCRYPT_ECC_UTIL_H

#include <stddef.h>
#include <string.h>

#include <gnutls/gnutls.h>

static inline int cryptbridge_copy_be_component(
    unsigned char *dst, size_t size, const gnutls_datum_t *component)
{
    const unsigned char *src;
    size_t src_size;

    if (!dst || !size || !component ||
        (!component->data && component->size)) return 0;

    src = component->data;
    src_size = component->size;
    while (src_size > size && src[0] == 0)
    {
        ++src;
        --src_size;
    }
    if (src_size > size) return 0;

    memset(dst, 0, size);
    if (src_size) memcpy(dst + size - src_size, src, src_size);
    return 1;
}

#endif
