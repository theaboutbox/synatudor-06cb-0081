#include <stdlib.h>
#include <endian.h>
#include <tudor/log.h>
#include "internal.h"

bool pe_parse_reloc_dir(struct pe_file *pe, struct pe_data_dir *dir) {
    if(dir->size <= 0) return true;

    //Determine number of relocations
    size_t num_relocs = 0;
    uint32_t block_off = 0;
    for(int i = 0; block_off < dir->size; i++) {
        uint32_t rem_size = dir->size - block_off;
        if(rem_size < sizeof(struct PEs_reloc_block)) {
            log_error("Relocation block %d doesn't fit! [%d < %d]", i, rem_size, (int) sizeof(struct PEs_reloc_block));
            return false;
        }

        struct PEs_reloc_block *block = (struct PEs_reloc_block*) (dir->data + block_off);
        uint32_t block_size = le32toh(block->BlockSize);
        if(block_size < sizeof(struct PEs_reloc_block) || block_size > rem_size ||
           (block_size - sizeof(struct PEs_reloc_block)) % sizeof(int16_t) != 0) {
            log_error("Relocation block %d has invalid size! [%d, %d remaining]", i, block_size, rem_size);
            return false;
        }

        block_off += block_size;
        num_relocs += (block_size - sizeof(struct PEs_reloc_block)) / sizeof(int16_t);
    }

    pe->relocations = (struct pe_reloc*) calloc(num_relocs ? num_relocs : 1, sizeof(struct pe_reloc));
    if(!pe->relocations) {
        log_error("Couldn't allocate PE relocation table!");
        return false;
    }

    //Parse relocations
    block_off = 0;
    pe->num_relocs = 0;
    while(block_off < dir->size) {
        struct PEs_reloc_block *block = (struct PEs_reloc_block*) (dir->data + block_off);
        uint32_t block_size = le32toh(block->BlockSize), page_rva = le32toh(block->PageRVA);
        int num_block_relocs = (block_size - sizeof(struct PEs_reloc_block)) / sizeof(int16_t);

        for(int j = 0; j < num_block_relocs; j++) {
            uint16_t bits = le16toh(block->TypeOffsets[j]);
            uint32_t off = page_rva + (bits & 0xfff);

            //Check type
            int type = (bits >> 12) & 0xf;
            switch(type) {
                case PE_RELOC_NOP: continue;
                case PE_RELOC_HIGHLOW: {
                    if((uint64_t) off + 4 > pe->image_size) {
                        log_error("Relocation target 0x%x lies outside the image!", off);
                        return false;
                    }
                    pe->relocations[pe->num_relocs].addr_bits = 32;
                    pe->relocations[pe->num_relocs].offset = off;
                    pe->relocations[pe->num_relocs].delta = pe_peek_mem_i32(pe, off) - pe->desired_base;
                    pe->num_relocs++;
                } break;
                case PE_RELOC_DIR64: {
                    if((uint64_t) off + 8 > pe->image_size) {
                        log_error("Relocation target 0x%x lies outside the image!", off);
                        return false;
                    }
                    pe->relocations[pe->num_relocs].addr_bits = 64;
                    pe->relocations[pe->num_relocs].offset = off;
                    pe->relocations[pe->num_relocs].delta = pe_peek_mem_i64(pe, off) - pe->desired_base;
                    pe->num_relocs++;
                } break;
                default: {
                    log_error("Unsupported relocation type %d!", type);
                    return false;
                }
            }
        }

        block_off += le32toh(block->BlockSize);
    }

    return true;
}