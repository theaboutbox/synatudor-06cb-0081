#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "internal.h"

extern HANDLE __winfnc CreateEventA(void *, BOOL, BOOL, const char *);
extern BOOL __winfnc SetEvent(HANDLE);
extern BOOL __winfnc ResetEvent(HANDLE);
extern BOOL __winfnc CloseHandle(HANDLE);
extern DWORD __winfnc WaitForSingleObject(HANDLE, DWORD);
typedef DWORD __winfnc start_fn(void *);
extern HANDLE __winfnc CreateThread(void *, SIZE_T, start_fn *, void *, DWORD, DWORD *);

static pthread_mutex_t lifecycle_lock = PTHREAD_MUTEX_INITIALIZER;
static struct winmodule *created_module;
static struct winmodule *returned_module;
static void *created_proc;
static void *returned_proc;
static void *created_param;
static void *returned_param;
static void *created_cookie;
static void *returned_cookie;
static unsigned int created_count;
static unsigned int returned_count;
static unsigned int filter_count;
static unsigned int filtered_worker_runs;

static void observe_thread_lifecycle(struct winmodule *module,
                                     void *start_proc, void *start_param,
                                     void *thread_cookie, bool created) {
    assert(pthread_mutex_lock(&lifecycle_lock) == 0);
    if(created) {
        created_module = module;
        created_proc = start_proc;
        created_param = start_param;
        created_cookie = thread_cookie;
        created_count++;
    } else {
        returned_module = module;
        returned_proc = start_proc;
        returned_param = start_param;
        returned_cookie = thread_cookie;
        returned_count++;
    }
    assert(pthread_mutex_unlock(&lifecycle_lock) == 0);
}

static double now_ms(void) {
    struct timespec t;
    assert(clock_gettime(CLOCK_MONOTONIC, &t) == 0);
    return t.tv_sec * 1000.0 + t.tv_nsec / 1000000.0;
}

static void *signal_later(void *event) {
    usleep(50000);
    assert(SetEvent(event));
    return NULL;
}

static DWORD __winfnc finish_later(void *unused) {
    (void) unused;
    usleep(80000);
    return 0;
}

static DWORD __winfnc filtered_worker(void *unused) {
    (void) unused;
    filtered_worker_runs++;
    return 0;
}

static bool suppress_filtered_worker(struct winmodule *module,
                                     void *start_proc, void *start_param) {
    assert(module == winmodule_get_cur());
    assert(start_proc == (void*)filtered_worker);
    assert(start_param == &filtered_worker_runs);
    filter_count++;
    return false;
}

int main(void) {
    HANDLE event = CreateEventA(NULL, FALSE, FALSE, NULL);
    assert(event);
    assert(WaitForSingleObject(event, 0) == WAIT_TIMEOUT);
    double start = now_ms();
    assert(WaitForSingleObject(event, 30) == WAIT_TIMEOUT);
    assert(now_ms() - start >= 20);

    pthread_t signaler;
    assert(pthread_create(&signaler, NULL, signal_later, event) == 0);
    start = now_ms();
    assert(WaitForSingleObject(event, 1000) == 0);
    assert(now_ms() - start >= 30);
    assert(pthread_join(signaler, NULL) == 0);
    assert(WaitForSingleObject(event, 0) == WAIT_TIMEOUT); /* auto-reset */
    assert(CloseHandle(event));

    event = CreateEventA(NULL, TRUE, TRUE, NULL);
    assert(WaitForSingleObject(event, 0) == 0);
    assert(WaitForSingleObject(event, 0) == 0); /* manual-reset */
    assert(ResetEvent(event));
    assert(WaitForSingleObject(event, 0) == WAIT_TIMEOUT);
    assert(CloseHandle(event));

    int lifecycle_param;
    struct winmodule *lifecycle_module = winmodule_get_cur();
    win_set_thread_lifecycle_observer(observe_thread_lifecycle);
    HANDLE thread = CreateThread(NULL, 0, finish_later, &lifecycle_param,
                                 0, NULL);
    assert(thread);

    assert(pthread_mutex_lock(&lifecycle_lock) == 0);
    assert(created_count == 1);
    assert(created_module == lifecycle_module);
    assert(created_proc == (void *) finish_later);
    assert(created_param == &lifecycle_param);
    assert(created_cookie != NULL);
    assert(pthread_mutex_unlock(&lifecycle_lock) == 0);

    start = now_ms();
    assert(WaitForSingleObject(thread, 20) == WAIT_TIMEOUT);
    assert(now_ms() - start >= 10);
    assert(WaitForSingleObject(thread, 1000) == 0);
    assert(WaitForSingleObject(thread, 0) == 0);

    assert(pthread_mutex_lock(&lifecycle_lock) == 0);
    assert(returned_count == 1);
    assert(returned_module == created_module);
    assert(returned_proc == created_proc);
    assert(returned_param == created_param);
    assert(returned_cookie == created_cookie);
    assert(pthread_mutex_unlock(&lifecycle_lock) == 0);

    win_set_thread_lifecycle_observer(NULL);
    assert(CloseHandle(thread));

    win_set_thread_start_filter(suppress_filtered_worker);
    thread = CreateThread(NULL, 0, filtered_worker, &filtered_worker_runs,
                          0, NULL);
    assert(thread);
    win_set_thread_start_filter(NULL);
    assert(win_wait_sync_obj(thread, 1000) == 0);
    assert(filter_count == 1);
    assert(filtered_worker_runs == 0);
    assert(CloseHandle(thread));
    puts("PASS: timed event and thread waits, signals, and reset semantics");
    return 0;
}
