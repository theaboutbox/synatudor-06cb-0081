#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <tudor/log.h>
#include "pe/pe.h"
#include "winapi/api.h"
#include "loader.h"
#include "stub.h"

#define CALL_INSTRUCTION_SIZE 5u
#define CALLSITE_THUNK_SIZE 16u

static struct dll_callsite_hook *callsite_hooks;

void dll_register_callsite_hook(struct dll_callsite_hook *hook) {
    if(!hook) return;
    hook->next = callsite_hooks;
    callsite_hooks = hook;
}

static bool callsite_hook_matches(const struct dll_callsite_hook *hook,
                                  const char *image_name) {
    return hook->image_name && image_name &&
           strcmp(hook->image_name, image_name) == 0;
}

static size_t count_callsite_hooks(const char *image_name,
                                   bool replacements_only) {
    size_t count = 0;

    for(struct dll_callsite_hook *hook = callsite_hooks; hook;
        hook = hook->next) {
        if(callsite_hook_matches(hook, image_name) &&
           (!replacements_only || hook->replacement))
            count++;
    }
    return count;
}

static void reset_callsite_hook_targets(const char *image_name) {
    for(struct dll_callsite_hook *hook = callsite_hooks; hook;
        hook = hook->next) {
        if(callsite_hook_matches(hook, image_name) && hook->original_target)
            *hook->original_target = NULL;
    }
}

static bool validate_callsite_hooks(const char *image_name,
                                    const uint8_t *image_mem,
                                    size_t image_size) {
    for(struct dll_callsite_hook *hook = callsite_hooks; hook;
        hook = hook->next) {
        if(!callsite_hook_matches(hook, image_name)) continue;

        if(hook->call_rva > image_size ||
           image_size - hook->call_rva < CALL_INSTRUCTION_SIZE ||
           hook->expected_target_rva >= image_size) {
            log_error("Pinned call-site hook for %s is outside the PE image",
                      image_name);
            return false;
        }

        const uint8_t *call = image_mem + hook->call_rva;
        if(memcmp(call, hook->expected_instruction,
                  CALL_INSTRUCTION_SIZE) != 0) {
            log_error("Pinned call-site bytes for %s do not match the "
                      "supported driver", image_name);
            return false;
        }

        int32_t displacement;
        memcpy(&displacement, call + 1, sizeof(displacement));
        int64_t target = (int64_t)hook->call_rva + CALL_INSTRUCTION_SIZE +
                         displacement;
        if(target != hook->expected_target_rva) {
            log_error("Pinned call-site target for %s does not match the "
                      "supported driver", image_name);
            return false;
        }

        for(struct dll_callsite_hook *other = hook->next; other;
            other = other->next) {
            if(callsite_hook_matches(other, image_name) &&
               other->call_rva == hook->call_rva) {
                log_error("Duplicate pinned call-site hook for %s", image_name);
                return false;
            }
        }
    }
    return true;
}

static bool apply_callsite_hooks(const char *image_name, uint8_t *image_mem,
                                 size_t image_size, uint8_t *thunk_mem,
                                 size_t thunk_size) {
    size_t thunk_offset = 0;

    reset_callsite_hook_targets(image_name);

    /* Validate every site, including validation-only entries, before changing
     * a single instruction.  A different vendor binary therefore fails
     * closed instead of running with an incorrectly classified key role. */
    if(!validate_callsite_hooks(image_name, image_mem, image_size)) return false;

    for(struct dll_callsite_hook *hook = callsite_hooks; hook;
        hook = hook->next) {
        if(!callsite_hook_matches(hook, image_name) || !hook->replacement)
            continue;
        if(thunk_offset > thunk_size ||
           thunk_size - thunk_offset < CALLSITE_THUNK_SIZE) {
            log_error("Insufficient trampoline space for %s", image_name);
            return false;
        }

        uint8_t *call = image_mem + hook->call_rva;
        uint8_t *thunk = thunk_mem + thunk_offset;
        uintptr_t replacement = (uintptr_t)hook->replacement;

        memset(thunk, 0xcc, CALLSITE_THUNK_SIZE);
        /* jmp qword ptr [rip] keeps every argument and volatile register
         * unchanged while reaching a native address anywhere under ASLR. */
        thunk[0] = 0xff;
        thunk[1] = 0x25;
        memset(thunk + 2, 0, 4);
        memcpy(thunk + 6, &replacement, sizeof(replacement));

        uintptr_t call_next = (uintptr_t)call + CALL_INSTRUCTION_SIZE;
        uintptr_t thunk_address = (uintptr_t)thunk;
        if(thunk_address < call_next ||
           thunk_address - call_next > INT32_MAX) {
            log_error("Pinned call-site trampoline for %s is out of range",
                      image_name);
            return false;
        }
        int32_t displacement = (int32_t)(thunk_address - call_next);
        memcpy(call + 1, &displacement, sizeof(displacement));
        thunk_offset += CALLSITE_THUNK_SIZE;
    }

    for(struct dll_callsite_hook *hook = callsite_hooks; hook;
        hook = hook->next) {
        if(callsite_hook_matches(hook, image_name) && hook->replacement &&
           hook->original_target)
            *hook->original_target = image_mem + hook->expected_target_rva;
    }

    __builtin___clear_cache((char *)image_mem,
                            (char *)image_mem + image_size);
    if(thunk_mem)
        __builtin___clear_cache((char *)thunk_mem,
                                (char *)thunk_mem + thunk_offset);
    return true;
}

static void clear_callsite_hook_targets(const void *image_mem,
                                        size_t image_size) {
    if(!image_mem || !image_size) return;
    uintptr_t begin = (uintptr_t)image_mem;
    if(image_size > UINTPTR_MAX - begin) return;
    uintptr_t end = begin + image_size;

    for(struct dll_callsite_hook *hook = callsite_hooks; hook;
        hook = hook->next) {
        if(!hook->original_target || !*hook->original_target) continue;
        uintptr_t target = (uintptr_t)*hook->original_target;
        if(target >= begin && target < end) *hook->original_target = NULL;
    }
}

void register_windows_api(char *name, void *api) {
    log_verbose("Registered Windows API function %s", name);
}

static void ord_stub() {
    log_error("Ordinal import called!");
    abort();
}

#ifndef DBGIMPORT
static void unresolved_stub() {
    log_error("Unresolved import called!");
    abort();
}
#endif

static void *resolve_import(const char *lib, const char *name) {
    //Try to resolve the import
    void *winapi = resolve_windows_api(name);
    if(winapi) return winapi;

    //Return a stub
    log_verbose("Couldn't resolve import %s@%s", name, lib);
#ifdef DBGIMPORT
    return create_import_stub(lib, name);
#else
    return &unresolved_stub;
#endif
}

bool load_dll(struct dll_image *dll, const char *name, uint8_t *data, uint32_t size) {
    if(!dll) return false;
    *dll = (struct dll_image){0};
    if(!name || !data || !size || size > INT_MAX) return false;
    reset_callsite_hook_targets(name);

    //Parse the PE file
    struct pe_file pe = {0};
    if(!pe_parse(&pe, data, size)) {
        pe_destroy(&pe);
        return false;
    }
    log_debug("DLL %s: %s image", name, pe.is_pe32_plus ? "PE+" : "PE");
    log_debug("-> machine: %x", pe.machine);
    log_debug("-> image size: %08x", pe.image_size);
    log_debug("-> entry point: %08x", pe.entry_point_off);
    log_debug("-> num data dirs: %d", pe.num_data_dirs);
    log_debug("-> num sections: %d", pe.num_sects);
    log_debug("-> num relocations: %d", pe.num_relocs);

    if(
        !(sizeof(void*) == 4 && pe.machine == PE_MACHINE_x86 && !pe.is_pe32_plus) &&
        !(sizeof(void*) == 8 && pe.machine == PE_MACHINE_x86_64 && pe.is_pe32_plus)
    ) {
        log_error("DLL target architecture incompatbile with host program!");
        pe_destroy(&pe);
        return false;
    }
    if(!pe.image_size || pe.image_size > INT_MAX) {
        log_error("DLL image size is invalid for this loader");
        pe_destroy(&pe);
        return false;
    }

    size_t hook_count = count_callsite_hooks(name, false);
    size_t replacement_count = count_callsite_hooks(name, true);
    if(hook_count && !pe.is_pe32_plus) {
        log_error("Pinned call-site hooks require an x86-64 PE image");
        pe_destroy(&pe);
        return false;
    }

    size_t image_span = pe.image_size;
    size_t thunk_span = 0;
    size_t mapping_size = pe.image_size;
    long page_size_long = sysconf(_SC_PAGESIZE);
    if(replacement_count) {
        if(page_size_long <= 0 ||
           pe.image_size > SIZE_MAX - ((size_t)page_size_long - 1) ||
           replacement_count > SIZE_MAX / CALLSITE_THUNK_SIZE) {
            log_error("Could not size pinned call-site trampolines for %s",
                      name);
            pe_destroy(&pe);
            return false;
        }
        size_t page_size = (size_t)page_size_long;
        image_span = ((size_t)pe.image_size + page_size - 1) / page_size *
                     page_size;
        size_t thunk_bytes = replacement_count * CALLSITE_THUNK_SIZE;
        if(thunk_bytes > SIZE_MAX - (page_size - 1)) {
            log_error("Could not size pinned call-site trampolines for %s",
                      name);
            pe_destroy(&pe);
            return false;
        }
        thunk_span = (thunk_bytes + page_size - 1) / page_size * page_size;
        if(image_span > SIZE_MAX - thunk_span) {
            log_error("Could not size pinned call-site mapping for %s", name);
            pe_destroy(&pe);
            return false;
        }
        mapping_size = image_span + thunk_span;
    }

    //Map the image memory
    uint8_t *image_mem = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if(image_mem == MAP_FAILED) {
        perror("Couldn't create DLL image memory mapping");
        pe_destroy(&pe);
        return false;
    }

    //Copy data
    pe_copy_mem(&pe, 0, pe.image_size, image_mem);
    log_debug("Copied image memory to mapping at %p - %p", image_mem, image_mem + pe.image_size);

    //Resolve imports
    for(int i = 0; i < pe.num_import_libs; i++) {
        struct pe_import_lib *lib = &pe.import_libs[i];
        for(int j = 0; j < lib->num_imports; j++) {
            struct pe_import *imp = &lib->imports[j];

            //Resolve the import
            void *resolv_addr;
            if(imp->ord >= 0) {
                log_warn("DLL %s has ordinal import %s#%d!", name, lib->name, imp->ord);
                resolv_addr = &ord_stub;
            } else {
                resolv_addr = resolve_import(lib->name, imp->name);
            }

            //Write the address into the image
            if(!pe.is_pe32_plus) {
                uint32_t value = (uint32_t)(uintptr_t)resolv_addr;
                memcpy(image_mem + imp->addr_off, &value, sizeof(value));
            } else {
                uint64_t value = (uint64_t)(uintptr_t)resolv_addr;
                memcpy(image_mem + imp->addr_off, &value, sizeof(value));
            }
        }
    }

    //Apply relocations
    for(int i = 0; i < pe.num_relocs; i++) {
        struct pe_reloc *reloc = &pe.relocations[i];
        if(reloc->addr_bits == 32) {
            uint32_t value = (uint32_t)((uintptr_t)image_mem + reloc->delta);
            memcpy(image_mem + reloc->offset, &value, sizeof(value));
        } else if(reloc->addr_bits == 64) {
            uint64_t value = (uint64_t)(uintptr_t)image_mem + reloc->delta;
            memcpy(image_mem + reloc->offset, &value, sizeof(value));
        } else {
            log_error("Unsupported number of relocation bits! [%d]", reloc->addr_bits);
            goto fail_mapping;
        }
    }
    log_debug("Applied %d relocations", pe.num_relocs);

    if(hook_count &&
       !apply_callsite_hooks(name, image_mem, pe.image_size,
                             replacement_count ? image_mem + image_span : NULL,
                             thunk_span))
        goto fail_mapping;

    //Apply section protections
    log_debug("Applying memory protections to image");

    if(mprotect(image_mem, image_span, PROT_READ)) {
        perror("Could't apply default image protection");
        goto fail_mapping;
    }

    for(int i = 0; i < pe.num_sects; i++) {
        struct pe_section *sec = &pe.sections[i];

        int prot = 0;
        if(sec->flags & PE_SECTION_CAN_READ) prot |= PROT_READ;
        if(sec->flags & PE_SECTION_CAN_WRITE) prot |= PROT_WRITE;
        if(sec->flags & PE_SECTION_CAN_EXECUTE) prot |= PROT_EXEC;
        if(mprotect(image_mem + sec->mem_off, sec->mem_size, prot)) {
            perror("Could't apply image section protection");
            goto fail_mapping;
        }

        log_debug("-> section %10s | %p - %p | %c%c%c", sec->name, image_mem + sec->mem_off, image_mem + sec->mem_off + sec->mem_size, (prot & PROT_READ) ? 'r' : '-', (prot & PROT_WRITE) ? 'w' : '-', (prot & PROT_EXEC) ? 'x' : '-');
    }

    if(thunk_span &&
       mprotect(image_mem + image_span, thunk_span, PROT_READ | PROT_EXEC)) {
        perror("Could't apply call-site trampoline protection");
        goto fail_mapping;
    }

    struct dll_export *exports = NULL;
    int initialized_exports = 0;
    if(pe.num_exports < 0 ||
       (size_t)pe.num_exports > SIZE_MAX / sizeof(*exports)) {
        log_error("Invalid export count in %s", name);
        goto fail_exports;
    }
    if(pe.num_exports) {
        exports = calloc((size_t)pe.num_exports, sizeof(*exports));
        if(!exports) {
            log_error("Could not allocate exports for %s", name);
            goto fail_exports;
        }
    }
    for(int i = 0; i < pe.num_exports; i++) {
        struct pe_export *pexp = &pe.exports[i];
        struct dll_export *dexp = &exports[i];

        dexp->name = pexp->name ? strdup(pexp->name) : NULL;
        if(!dexp->name) {
            log_error("Could not copy an export name for %s", name);
            goto fail_exports;
        }
        initialized_exports++;
        printf("DLL export: %s\n", dexp->name);
        dexp->addr = image_mem + pexp->offset;
    }

    //Initialize DLL structure only after every fallible load step succeeded.
    dll->base_addr = image_mem;
    dll->image_size = pe.image_size;
    dll->mapping_size = mapping_size;
    dll->entry_point = pe.entry_point_off ? image_mem + pe.entry_point_off : NULL;
    dll->num_exports = pe.num_exports;
    dll->exports = exports;

    //Cleanup
    pe_destroy(&pe);

    return true;

fail_exports:
    for(int i = 0; i < initialized_exports; i++) free(exports[i].name);
    free(exports);
fail_mapping:
    clear_callsite_hook_targets(image_mem, pe.image_size);
    munmap(image_mem, mapping_size);
    pe_destroy(&pe);
    *dll = (struct dll_image){0};
    return false;
}

void destroy_dll(struct dll_image *dll) {
    if(!dll) return;
    //Free allocated memory
    for(int i = 0; i < dll->num_exports; i++) free(dll->exports[i].name);
    free(dll->exports);

    clear_callsite_hook_targets(dll->base_addr, (size_t)dll->image_size);
    size_t mapping_size = dll->mapping_size ? dll->mapping_size :
                                              (size_t)dll->image_size;
    if(dll->base_addr && mapping_size) munmap(dll->base_addr, mapping_size);
    *dll = (struct dll_image){0};
}

void *try_find_dll_export(struct dll_image *dll, const char *name) {
    for(int i = 0; i < dll->num_exports; i++) {
        if(strcmp(dll->exports[i].name, name) == 0) return dll->exports[i].addr;
    }

    return NULL;
}

void *find_dll_export(struct dll_image *dll, const char *name) {
    void *export = try_find_dll_export(dll, name);
    if(export) return export;

    log_error("Couldn't find DLL export '%s'!", name);
    abort();
}
