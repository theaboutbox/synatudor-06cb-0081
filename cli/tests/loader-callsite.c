#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "loader.h"

#define SYNA_KEYPAIR_GENERATE_RVA 0x0e6480u
#define SYNA_PAIRING_KEYGEN_CALL_RVA 0x06d00bu
#define SYNA_TLS_KEYGEN_CALL_RVA 0x07e9d2u
#define SYNA_PROCESS_PAIRING_CALL_RVA 0x021d34u
#define SYNA_PROCESS_PAIRING_RVA 0x023738u
#define SYNA_TEXT_RVA 0x1000u
#define SYNA_TEXT_FILE_OFFSET 0x400u

static void *lifecycle_original_target;

static void lifecycle_replacement(void)
{
}

static struct dll_callsite_hook lifecycle_hook = {
    .image_name = "loader-callsite-lifecycle.dll",
    .call_rva = SYNA_PAIRING_KEYGEN_CALL_RVA,
    .expected_target_rva = SYNA_KEYPAIR_GENERATE_RVA,
    .expected_instruction = {0xe8, 0x70, 0x94, 0x07, 0x00},
    .replacement = &lifecycle_replacement,
    .original_target = &lifecycle_original_target,
};

static uint8_t *rel32_call_target(struct dll_image *image, uint32_t rva)
{
    uint8_t *call = (uint8_t *)image->base_addr + rva;
    int32_t displacement;

    assert(call[0] == 0xe8);
    memcpy(&displacement, call + 1, sizeof(displacement));
    return call + 5 + displacement;
}

static void assert_empty_image(const struct dll_image *image)
{
    assert(!image->base_addr);
    assert(image->image_size == 0);
    assert(image->mapping_size == 0);
    assert(!image->entry_point);
    assert(image->num_exports == 0);
    assert(!image->exports);
}

static void assert_executable_not_writable(const void *address)
{
    FILE *maps = fopen("/proc/self/maps", "r");
    assert(maps);
    char line[512];

    while(fgets(line, sizeof(line), maps)) {
        uintptr_t start, end;
        char permissions[5];
        if(sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s",
                  &start, &end, permissions) == 3 &&
           (uintptr_t)address >= start && (uintptr_t)address < end) {
            assert(permissions[0] == 'r');
            assert(permissions[1] != 'w');
            assert(permissions[2] == 'x');
            assert(fclose(maps) == 0);
            return;
        }
    }
    assert(fclose(maps) == 0);
    assert(!"address was absent from /proc/self/maps");
}

static uint8_t *read_driver(const char *path, size_t *size)
{
    FILE *driver = fopen(path, "rb");
    assert(driver);
    assert(fseek(driver, 0, SEEK_END) == 0);
    long length = ftell(driver);
    assert(length > 0 && (unsigned long)length <= UINT32_MAX);
    assert(fseek(driver, 0, SEEK_SET) == 0);

    uint8_t *contents = malloc((size_t)length);
    assert(contents);
    assert(fread(contents, 1, (size_t)length, driver) == (size_t)length);
    assert(fclose(driver) == 0);
    *size = (size_t)length;
    return contents;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    size_t driver_size;
    uint8_t *driver_data = read_driver(argv[1], &driver_size);
    struct dll_image image = {0};

    assert(load_dll(&image, "synaWudfBioUsb.dll", driver_data,
                    (uint32_t)driver_size));

    uint8_t *pairing_target = rel32_call_target(
        &image, SYNA_PAIRING_KEYGEN_CALL_RVA);
    uint8_t *tls_target = rel32_call_target(&image, SYNA_TLS_KEYGEN_CALL_RVA);
    uint8_t *original_target =
        (uint8_t *)image.base_addr + SYNA_KEYPAIR_GENERATE_RVA;

    assert(pairing_target != original_target);
    assert(pairing_target >= (uint8_t *)image.base_addr + image.image_size);
    assert(pairing_target + 14 <=
           (uint8_t *)image.base_addr + image.mapping_size);
    assert(pairing_target[0] == 0xff && pairing_target[1] == 0x25);
    assert(!memcmp(pairing_target + 2, "\0\0\0\0", 4));
    assert(tls_target == original_target);
    assert_executable_not_writable(
        (uint8_t *)image.base_addr + SYNA_PAIRING_KEYGEN_CALL_RVA);
    assert_executable_not_writable(pairing_target);
    uint8_t *worker_target = rel32_call_target(
        &image, SYNA_PROCESS_PAIRING_CALL_RVA);
    assert(worker_target !=
           (uint8_t *)image.base_addr + SYNA_PROCESS_PAIRING_RVA);
    assert(worker_target >= (uint8_t *)image.base_addr + image.image_size);
    assert(worker_target + 14 <=
           (uint8_t *)image.base_addr + image.mapping_size);
    assert(worker_target[0] == 0xff && worker_target[1] == 0x25);
    assert_executable_not_writable(worker_target);
    destroy_dll(&image);
    assert_empty_image(&image);

    /* A changed TLS site must reject the whole pinned hook set before the
     * pairing call can be redirected. */
    uint8_t *changed_driver = malloc(driver_size);
    assert(changed_driver);
    memcpy(changed_driver, driver_data, driver_size);
    size_t tls_file_offset = SYNA_TEXT_FILE_OFFSET +
                             SYNA_TLS_KEYGEN_CALL_RVA - SYNA_TEXT_RVA;
    assert(tls_file_offset + 5 <= driver_size);
    changed_driver[tls_file_offset + 1] ^= 1;

    struct dll_image rejected = {
        .base_addr = (void *)1,
        .image_size = 1,
        .mapping_size = 1,
        .entry_point = (void *)1,
        .num_exports = 1,
        .exports = (void *)1,
    };
    assert(!load_dll(&rejected, "synaWudfBioUsb.dll", changed_driver,
                     (uint32_t)driver_size));
    assert_empty_image(&rejected);

    /* The worker observer must also reject an unsupported call site before
     * any pairing identity hook can run. */
    memcpy(changed_driver, driver_data, driver_size);
    size_t worker_file_offset = SYNA_TEXT_FILE_OFFSET +
                                SYNA_PROCESS_PAIRING_CALL_RVA - SYNA_TEXT_RVA;
    assert(worker_file_offset + 5 <= driver_size);
    changed_driver[worker_file_offset + 1] ^= 1;
    assert(!load_dll(&rejected, "synaWudfBioUsb.dll", changed_driver,
                     (uint32_t)driver_size));
    assert_empty_image(&rejected);

    /* A failed load must not poison a later load of the supported image. */
    assert(load_dll(&image, "synaWudfBioUsb.dll", driver_data,
                    (uint32_t)driver_size));
    assert(rel32_call_target(&image, SYNA_TLS_KEYGEN_CALL_RVA) ==
           (uint8_t *)image.base_addr + SYNA_KEYPAIR_GENERATE_RVA);
    destroy_dll(&image);
    assert_empty_image(&image);

    /* Exercise the public original-target lifecycle directly with a
     * process-lifetime test descriptor. */
    dll_register_callsite_hook(&lifecycle_hook);
    lifecycle_original_target = (void *)1;
    memcpy(changed_driver, driver_data, driver_size);
    size_t pairing_file_offset = SYNA_TEXT_FILE_OFFSET +
                                 SYNA_PAIRING_KEYGEN_CALL_RVA - SYNA_TEXT_RVA;
    assert(pairing_file_offset + 5 <= driver_size);
    changed_driver[pairing_file_offset + 1] ^= 1;
    assert(!load_dll(&rejected, "loader-callsite-lifecycle.dll",
                     changed_driver, (uint32_t)driver_size));
    assert_empty_image(&rejected);
    assert(!lifecycle_original_target);

    assert(load_dll(&image, "loader-callsite-lifecycle.dll", driver_data,
                    (uint32_t)driver_size));
    assert(lifecycle_original_target ==
           (uint8_t *)image.base_addr + SYNA_KEYPAIR_GENERATE_RVA);
    uint8_t *lifecycle_thunk = rel32_call_target(
        &image, SYNA_PAIRING_KEYGEN_CALL_RVA);
    uintptr_t lifecycle_replacement_address;
    assert(lifecycle_thunk[0] == 0xff && lifecycle_thunk[1] == 0x25);
    memcpy(&lifecycle_replacement_address, lifecycle_thunk + 6,
           sizeof(lifecycle_replacement_address));
    assert(lifecycle_replacement_address ==
           (uintptr_t)&lifecycle_replacement);
    destroy_dll(&image);
    assert_empty_image(&image);
    assert(!lifecycle_original_target);

    free(changed_driver);
    free(driver_data);
    return 0;
}
