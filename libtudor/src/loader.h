#ifndef LIBTUDOR_LOADER_H
#define LIBTUDOR_LOADER_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct dll_export {
    char *name;
    void *addr;
};

struct dll_image {
    void *base_addr;
    int image_size;
    size_t mapping_size;

    void *entry_point;

    int num_exports;
    struct dll_export *exports;
};

/* Validate one direct x86-64 CALL in a pinned PE image and, when replacement
 * is non-NULL, redirect it through a nearby trampoline.  original_target then
 * receives the relocated address that the replacement can call to continue
 * the vendor implementation.  Descriptors must have process lifetime. */
struct dll_callsite_hook {
    const char *image_name;
    uint32_t call_rva;
    uint32_t expected_target_rva;
    uint8_t expected_instruction[5];
    void *replacement;
    void **original_target;
    struct dll_callsite_hook *next;
};

void dll_register_callsite_hook(struct dll_callsite_hook *hook);

bool load_dll(struct dll_image *dll, const char *name, uint8_t *data, uint32_t size);
void destroy_dll(struct dll_image *dll);

void *try_find_dll_export(struct dll_image *dll, const char *name);
void *find_dll_export(struct dll_image *dll, const char *name);

#ifdef __cplusplus
}
#endif

#endif
