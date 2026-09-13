#include <pthread.h>
#include <errno.h>
#include "internal.h"

typedef DWORD __winfnc THREAD_START_ROUTINE(void *param);

#define CREATE_SUSPENDED 0x00000004

static win_thread_lifecycle_observer_fnc *thread_lifecycle_observer;
static win_thread_start_filter_fnc *thread_start_filter;

void win_set_thread_lifecycle_observer(
        win_thread_lifecycle_observer_fnc *observer) {
    __atomic_store_n(&thread_lifecycle_observer, observer, __ATOMIC_RELEASE);
}

void win_set_thread_start_filter(win_thread_start_filter_fnc *filter) {
    __atomic_store_n(&thread_start_filter, filter, __ATOMIC_RELEASE);
}

struct win_thread {
    struct win_sync_object sync_obj;
    HANDLE handle;

    pthread_mutex_t lock;
    pthread_t thread;
    DWORD thread_id;
    bool has_detached;

    pthread_cond_t suspend_cond;
    int suspend_cntr;

    pthread_cond_t start_cond;
    struct winmodule *start_module;
    THREAD_START_ROUTINE *start_proc;
    void *start_param;
    bool run_start_proc;

    /* One reference for the Windows HANDLE and one for the running thread,
     * so closing the handle while the thread still runs (the usual
     * CreateThread/CloseHandle idiom) cannot free state the thread uses. */
    int refcnt;
};

static void thread_release(struct win_thread *thread) {
    if(__atomic_sub_fetch(&thread->refcnt, 1, __ATOMIC_ACQ_REL) != 0) return;
    cant_fail_ret(pthread_mutex_destroy(&thread->lock));
    cant_fail_ret(pthread_cond_destroy(&thread->suspend_cond));
    free(thread);
}

static void notify_thread_lifecycle(struct win_thread *thread, bool created) {
    win_thread_lifecycle_observer_fnc *observer =
        __atomic_load_n(&thread_lifecycle_observer, __ATOMIC_ACQUIRE);
    if(observer) {
        observer(thread->start_module, (void*) thread->start_proc,
                 thread->start_param, thread, created);
    }
}

static void thread_destr(void *data) {
    struct win_thread *thread = (struct win_thread*) data;
    //Let the pthread reclaim itself if nobody joined it, then drop the
    //handle's reference; the thread drops its own when it exits
    if(!thread->has_detached) cant_fail_ret(pthread_detach(thread->thread));
    thread_release(thread);
}

static DWORD thread_wait(struct win_sync_object *sync_obj, DWORD timeout) {
    struct win_thread *thread = (struct win_thread*) sync_obj;
    TRACE();
    if(thread->has_detached) return 0;

    if(timeout == INFINITE) {
        cant_fail_ret(pthread_join(thread->thread, NULL));
    } else {
        struct timespec deadline = win_wait_deadline(timeout);
        int err = pthread_timedjoin_np(thread->thread, NULL, &deadline);
        if(err == ETIMEDOUT) return WAIT_TIMEOUT;
        cant_fail_ret(err);
    }

    thread->has_detached = TRUE;
    return 0;
}

static void thread_wait_resume(struct win_thread *thread) {
    cant_fail_ret(pthread_mutex_lock(&thread->lock));
    while(thread->suspend_cntr > 0) cant_fail_ret(pthread_cond_wait(&thread->suspend_cond, &thread->lock));
    cant_fail_ret(pthread_mutex_unlock(&thread->lock));
}

/* Runs when the start routine returns and also when it leaves through
 * ExitThread(), so the lifecycle observer and the reference drop happen
 * exactly once either way. */
static void thread_exit_cleanup(void *arg) {
    struct win_thread *thread = (struct win_thread*) arg;
    notify_thread_lifecycle(thread, false);
    thread_release(thread);
}

static void *thread_entry(void *arg) {
    struct win_thread *thread = (struct win_thread*) arg;

    cant_fail_ret(pthread_mutex_lock(&thread->lock));

    //Initialize state
    winmodule_set_cur(thread->start_module);
    thread->thread_id = win_get_thread_id();
    win_init_tib();

    //Signal start thread that we've started
    cant_fail_ret(pthread_cond_signal(&thread->start_cond));
    cant_fail_ret(pthread_mutex_unlock(&thread->lock));

    pthread_cleanup_push(thread_exit_cleanup, thread);

    //Call the thread start routine
    thread_wait_resume(thread);
    DWORD result = thread->run_start_proc ? thread->start_proc(thread->start_param) : 0;
    log_debug("Windows thread %u returned from %p with status 0x%x",
              thread->thread_id, (void*) thread->start_proc, result);

    pthread_cleanup_pop(1);
    return (void*) 0;
}

__winfnc HANDLE CreateThread(void *security_attrs, SIZE_T stack_size, THREAD_START_ROUTINE *start_proc, void *param, DWORD flags, DWORD *id) {
    TRACE();
    //Allocate thread
    struct win_thread *thread = (struct win_thread*) malloc(sizeof(struct win_thread));
    if(!thread) { winerr_set_errno(); return NULL; }
    thread->sync_obj.wait_fnc = thread_wait;

    cant_fail_ret(pthread_mutex_init(&thread->lock, NULL));
    thread->suspend_cntr = ((flags & CREATE_SUSPENDED) != 0) ? 1 : 0;
    cant_fail_ret(pthread_cond_init(&thread->suspend_cond, NULL));

    cant_fail_ret(pthread_cond_init(&thread->start_cond, NULL));
    thread->start_module = winmodule_get_cur();
    thread->start_proc = start_proc;
    thread->start_param = param;
    win_thread_start_filter_fnc *filter =
        __atomic_load_n(&thread_start_filter, __ATOMIC_ACQUIRE);
    thread->run_start_proc = !filter ||
        filter(thread->start_module, (void*)start_proc, param);

    thread->refcnt = 2;
    thread->handle = winhandle_create(thread, thread_destr);

    /* Notify before pthread_create: a short-lived Windows worker can return
     * before CreateThread itself regains the CPU. */
    notify_thread_lifecycle(thread, true);

    //Create the actual thread
    thread->has_detached = FALSE;
    cant_fail_ret(pthread_mutex_lock(&thread->lock));
    cant_fail_ret(pthread_create(&thread->thread, NULL, thread_entry, thread));
    cant_fail_ret(pthread_cond_wait(&thread->start_cond, &thread->lock));
    cant_fail_ret(pthread_cond_destroy(&thread->start_cond));
    cant_fail_ret(pthread_mutex_unlock(&thread->lock));

    if(id) *id = thread->thread_id;

    return thread->handle;
}
WINAPI(CreateThread)

__winfnc DWORD GetThreadId(HANDLE handle) {
    TRACE();
    struct win_thread *thread = (struct win_thread*) handle->data;
    return thread->thread_id;
}
WINAPI(GetThreadId)

__winfnc DWORD ResumeThread(HANDLE handle) {
    TRACE();
    struct win_thread *thread = (struct win_thread*) handle->data;

    //Decrement the suspend counter
    cant_fail_ret(pthread_mutex_lock(&thread->lock));
    DWORD suspend_ctr = thread->suspend_cntr;
    if(thread->suspend_cntr > 0) thread->suspend_cntr--;
    cant_fail_ret(pthread_cond_signal(&thread->suspend_cond));
    cant_fail_ret(pthread_mutex_unlock(&thread->lock));

    return suspend_ctr;
}
WINAPI(ResumeThread)

__winfnc void ExitThread(DWORD exit_code) {
    TRACE();
    pthread_exit((void*) (uintptr_t) exit_code);
}
WINAPI(ExitThread)
