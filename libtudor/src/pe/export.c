#include <stdlib.h>
#include <endian.h>
#include <tudor/log.h>
#include "internal.h"

bool pe_parse_export_dir(struct pe_file *pe, struct pe_data_dir *dir) {
    if(dir->size <= 0) return true;

    //Parse export directory
    if(dir->size < sizeof(struct PEs_export_dir)) {
        log_error("Export directory is too small! [%d < %d]", dir->size, (int) sizeof(struct PEs_export_dir));
        return false;
    }
    struct PEs_export_dir *export_dir = (struct PEs_export_dir*) dir->data;

    int ord_base = (int) le32toh(export_dir->OrdinalBase);
    uint32_t num_exports = le32toh(export_dir->NumberOfAddressTableEntries), num_names = le32toh(export_dir->NumberOfNamePointers);
    uint32_t address_table_rva = le32toh(export_dir->ExportAddressTableRVA), name_table_rva = le32toh(export_dir->NamePointerRVA), ord_table_rva = le32toh(export_dir->OrdinalTableRVA);

    //All three tables must lie inside the image
    if((uint64_t) address_table_rva + (uint64_t) num_exports * sizeof(uint32_t) > pe->image_size ||
       (uint64_t) name_table_rva + (uint64_t) num_names * sizeof(uint32_t) > pe->image_size ||
       (uint64_t) ord_table_rva + (uint64_t) num_names * sizeof(uint16_t) > pe->image_size ||
       num_exports > INT32_MAX || num_names > INT32_MAX) {
        log_error("Export tables run past the end of the image!");
        return false;
    }

    pe->export_lib_name = pe_copy_mem_string(pe, le32toh(export_dir->NameRVA));
    if(!pe->export_lib_name) return false;
    pe->exports = (struct pe_export*) calloc(num_exports ? num_exports : 1, sizeof(struct pe_export));
    if(!pe->exports) {
        log_error("Couldn't allocate PE export table!");
        return false;
    }
    pe->num_exports = (int) num_exports;

    //Iterate over exports
    for(int i = 0; i < pe->num_exports; i++) {
        struct pe_export *export = &pe->exports[i];

        //Init export
        export->ord = ord_base + i;
        export->name = NULL;

        //Get RVA
        uint32_t export_rva = pe_peek_mem_i32(pe, address_table_rva + i*sizeof(uint32_t));
        if(dir->offset <= export_rva && export_rva < dir->offset + dir->size) {
            export->offset = 0;
            export->forwarder = pe_copy_mem_string(pe, export_rva);
            if(!export->forwarder) return false;
        } else {
            export->offset = export_rva;
            export->forwarder = NULL;
        }
    }

    //Assign names to exports
    for(int i = 0; i < (int) num_names; i++) {
        uint32_t name_rva = pe_peek_mem_i32(pe, name_table_rva + i*sizeof(uint32_t));
        int export_idx = pe_peek_mem_i16(pe, ord_table_rva + i*sizeof(uint16_t));

        if(export_idx < 0 || pe->num_exports <= export_idx) {
            log_error("Export name %d references invalid export index! [%d >= %d]", i, export_idx, pe->num_exports);
            return false;
        }

        free(pe->exports[export_idx].name);
        pe->exports[export_idx].name = pe_copy_mem_string(pe, name_rva);
        if(!pe->exports[export_idx].name) return false;
    }

    return true;
}