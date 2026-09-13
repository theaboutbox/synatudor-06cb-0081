#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include "winapi/internal.h"

extern __winfnc BOOL ReadFile(HANDLE, void *, DWORD, DWORD *, OVERLAPPED *);

static atomic_uint callbacks;
static unsigned int cleanups;
static NTSTATUS immediate_status;

static void cleanup_read(void *ctx, OVERLAPPED *ovlp, void *op_ctx) {
    (void)ctx; (void)ovlp;
    free(op_ctx);
    cleanups++;
}

static NTSTATUS immediate_read(void *ctx, OVERLAPPED *ovlp, off_t off,
                               void *buf, size_t size, void **op_ctx) {
    (void)ctx; (void)off; (void)buf; (void)size;
    *op_ctx = malloc(8);
    assert(*op_ctx);
    if(immediate_status == STATUS_SUCCESS)
        winio_complete_overlapped(ovlp, STATUS_SUCCESS, 7);
    return immediate_status;
}

static void test_immediate_operations(void) {
    HANDLE file = winio_create_file(NULL, false, immediate_read, NULL, NULL,
                                    NULL, cleanup_read, NULL);
    char buffer[7];
    DWORD count;
    immediate_status = STATUS_SUCCESS;
    assert(ReadFile(file, buffer, sizeof(buffer), &count, NULL));
    assert(count == 7 && cleanups == 1);
    immediate_status = STATUS_CANCELLED;
    assert(!ReadFile(file, buffer, sizeof(buffer), &count, NULL));
    assert(cleanups == 2);
    winhandle_destroy(file);
}

static NTSTATUS start_read(void *ctx, OVERLAPPED *ovlp, off_t off,
                           void *buf, size_t size, void **op_ctx) {
    (void)ctx; (void)ovlp; (void)off; (void)buf; (void)size; (void)op_ctx;
    return STATUS_SUCCESS;
}

static void completed(OVERLAPPED *ovlp, NTSTATUS status, void *ctx) {
    (void)ctx;
    assert(status == STATUS_SUCCESS);
    assert(__atomic_load_n(&ovlp->Internal, __ATOMIC_ACQUIRE) == STATUS_SUCCESS);
    assert(ovlp->InternalHigh == 7);
    winio_cleanup_overlapped(ovlp);
    atomic_fetch_add(&callbacks, 1);
}

static void *complete_read(void *ovlp) {
    winio_complete_overlapped(ovlp, STATUS_SUCCESS, 7);
    return NULL;
}

int main(void) {
    test_immediate_operations();
    HANDLE file = winio_create_file(NULL, true, start_read, NULL, NULL,
                                    NULL, NULL, NULL);
    for(unsigned int i = 0; i < 2000; i++) {
        OVERLAPPED ovlp = {0};
        char buffer[7];
        assert(!ReadFile(file, buffer, sizeof(buffer), NULL, &ovlp));
        pthread_t worker;
        assert(pthread_create(&worker, NULL, complete_read, &ovlp) == 0);
        winio_set_overlapped_callback(&ovlp, completed, NULL, false);
        assert(pthread_join(worker, NULL) == 0);
        assert(atomic_load(&callbacks) == i + 1);
        assert(ovlp.Pointer == NULL);
        winhandle_destroy(ovlp.hEvent);
    }
    winhandle_destroy(file);
    return 0;
}
