#include <stdlib.h>
#include <endian.h>
#include <tudor/log.h>
#include "internal.h"

bool pe_parse_import_dir(struct pe_file *pe, struct pe_data_dir *dir) {
    if(dir->size <= 0) return true;

    //Determine number of imported libraries
    int num_import_libs = 0;
    for(int i = 0;; i++) {
        if(dir->size < (i+1) * sizeof(struct PEs_import_dir_entry)) {
            log_error("Import directory entry %d has invalid bounds! [end 0x%x > directory end 0x%x]", i, (i+1) * (uint32_t) sizeof(struct PEs_import_dir_entry), dir->size);
            return false;
        }

        struct PEs_import_dir_entry *entry = (struct PEs_import_dir_entry*) (dir->data + i * sizeof(struct PEs_import_dir_entry));

        //Is the entry empty?
        if(entry->ImportLookupTableRVA == 0 && entry->TimeDateStamp == 0 && entry->ForwarderChain == 0 && entry->NameRVA == 0 && entry->ImportAddressTableRVA == 0) break;

        num_import_libs++;
    }

    pe->import_libs = (struct pe_import_lib*) calloc(num_import_libs ? num_import_libs : 1, sizeof(struct pe_import_lib));
    if(!pe->import_libs) {
        log_error("Couldn't allocate PE import library table!");
        return false;
    }
    pe->num_import_libs = num_import_libs;

    //Iterate over imported libraries
    for(int i = 0; i < pe->num_import_libs; i++) {
        struct PEs_import_dir_entry *entry = (struct PEs_import_dir_entry*) (dir->data + i * sizeof(struct PEs_import_dir_entry));
        struct pe_import_lib *lib = &pe->import_libs[i];

        //Extract info
        uint32_t lookup_table_rva = le32toh(entry->ImportLookupTableRVA), name_rva = le32toh(entry->NameRVA), addr_table_rva = le32toh(entry->ImportAddressTableRVA);
        lib->name = pe_copy_mem_string(pe, name_rva);
        if(!lib->name) return false;

        //A missing lookup table means the address table doubles as one
        if(lookup_table_rva == 0) lookup_table_rva = addr_table_rva;

        //Determine number of imports (the table must end inside the image)
        size_t entry_size = pe->is_pe32_plus ? sizeof(uint64_t) : sizeof(uint32_t);
        int num_imports = 0;
        for(;; num_imports++) {
            uint64_t entry_end = (uint64_t) lookup_table_rva + ((uint64_t) num_imports + 1) * entry_size;
            if(entry_end > pe->image_size || (uint64_t) addr_table_rva + ((uint64_t) num_imports + 1) * entry_size > pe->image_size) {
                log_error("Import table of library %d runs past the end of the image!", i);
                return false;
            }
            uint64_t bits = pe->is_pe32_plus
                ? pe_peek_mem_i64(pe, lookup_table_rva + num_imports*sizeof(uint64_t))
                : pe_peek_mem_i32(pe, lookup_table_rva + num_imports*sizeof(uint32_t));
            if(bits == 0) break;
        }

        lib->imports = (struct pe_import*) calloc(num_imports ? num_imports : 1, sizeof(struct pe_import));
        if(!lib->imports) {
            log_error("Couldn't allocate PE import table!");
            return false;
        }
        lib->num_imports = num_imports;

        //Iterate over imports
        for(int i = 0; i < lib->num_imports; i++) {
            struct pe_import *import = &lib->imports[i];
            if(!pe->is_pe32_plus) {
                uint32_t bits = pe_peek_mem_i32(pe, lookup_table_rva + i*sizeof(uint32_t));
                if(bits & (UINT32_C(1) << 31)) {
                    import->ord = bits & UINT32_C(0xffff);
                    import->name = NULL;
                } else {
                    import->ord = -1;
                    import->name = pe_copy_mem_string(
                        pe, (bits & ~(UINT32_C(1) << 31)) + 2);
                    if(!import->name) return false;
                }
                import->addr_off = addr_table_rva + i*sizeof(uint32_t);
            } else {
                uint64_t bits = pe_peek_mem_i64(
                    pe, lookup_table_rva + i*sizeof(uint64_t));
                if(bits & (UINT64_C(1) << 63)) {
                    import->ord = bits & UINT64_C(0xffff);
                    import->name = NULL;
                } else {
                    import->ord = -1;
                    import->name = pe_copy_mem_string(
                        pe, (uint32_t)(bits & ~(UINT64_C(1) << 63)) + 2);
                    if(!import->name) return false;
                }
                import->addr_off = addr_table_rva + i*sizeof(uint64_t);
            }
        }
    }

    return true;
}
