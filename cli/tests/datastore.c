#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include "datastore.h"

static FILE *failing_output(void) {
    FILE *file = fopen("/dev/full", "w");
    assert(file);
    assert(setvbuf(file, NULL, _IONBF, 0) == 0);
    return file;
}

int main(void) {
    const unsigned char bytes[] = {1, 2, 3};
    struct tudor_pair_data pdata = {(void *)bytes, sizeof(bytes)};
    set_pair_data("test", &pdata);
    FILE *file = failing_output();
    assert(!save_datastore_pair_data(file));
    fclose(file);
    /* This deadlocks if the failed write did not release pdata_lock. */
    assert(get_pair_data("test"));
    file = tmpfile();
    assert(file && save_datastore_pair_data(file));
    rewind(file);
    free_pair_data();
    assert(load_datastore_pair_data(file));
    const struct tudor_pair_data *loaded = get_pair_data("test");
    assert(loaded && loaded->data_size == sizeof(bytes));
    assert(memcmp(loaded->data, bytes, sizeof(bytes)) == 0);
    fclose(file);
    free_pair_data();

    /* Every truncated field must release temporary allocations. */
    const unsigned char truncated[] = {4, 't', 'e'};
    for(size_t size = 1; size <= sizeof(truncated); size++) {
        file = fmemopen((void *)truncated, size, "r");
        assert(file && !load_datastore_pair_data(file));
        fclose(file);
    }

    struct tudor_device dev = {0};
    assert(pthread_mutex_init(&dev.records_lock, NULL) == 0);
    struct tudor_record record = {.data = (void *)bytes, .data_size = sizeof(bytes)};
    dev.records_head = &record;
    file = failing_output();
    assert(!save_datastore_records(file, &dev));
    fclose(file);
    assert(pthread_mutex_trylock(&dev.records_lock) == 0);
    assert(pthread_mutex_unlock(&dev.records_lock) == 0);
    const unsigned char invalid_marker[] = {255};
    file = fmemopen((void *)invalid_marker, sizeof(invalid_marker), "r");
    assert(file && !load_datastore_records(file, &dev));
    fclose(file);
    assert(pthread_mutex_destroy(&dev.records_lock) == 0);
    return 0;
}
