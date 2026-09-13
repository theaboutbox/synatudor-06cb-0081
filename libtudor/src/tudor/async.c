#include "internal.h"
#include <errno.h>
#include <time.h>

#define SUCCESS_PENDING -1

tudor_async_res_t async_new_res(struct tudor_device *dev, OVERLAPPED *ovlp) {
    tudor_async_res_t res = (tudor_async_res_t) malloc(sizeof(struct _async_res));
    if(!res) { perror("Couldn't allocate async result"); abort(); }
    *res = (struct _async_res) {
        .dev = dev,
        .ovlp = ovlp,
        .success = SUCCESS_PENDING,
        .cb_fnc = NULL,
        .cb_ctx = NULL
    };
    cant_fail_ret(pthread_mutex_init(&res->lock, NULL));
    cant_fail_ret(pthread_cond_init(&res->compl_cond, NULL));
    return res;
}

void async_complete_op(tudor_async_res_t res, bool success) {
    cant_fail_ret(pthread_mutex_lock(&res->lock));
    res->success = success;
    cant_fail_ret(pthread_cond_signal(&res->compl_cond));

    //Store callback data
    tudor_async_cb_fnc *cb_fnc = res->cb_fnc;
    void *cb_ctx = res->cb_ctx;

    cant_fail_ret(pthread_mutex_unlock(&res->lock));

    //Invoke callback
    if(cb_fnc) cb_fnc(res, success, cb_ctx);
}

void tudor_set_async_callback(tudor_async_res_t res, tudor_async_cb_fnc *cb, void *ctx) {
    bool call_now = false;
    bool success = false;

    cant_fail_ret(pthread_mutex_lock(&res->lock));
    if(res->success != SUCCESS_PENDING) {
        call_now = true;
        success = (bool) res->success;
    } else {
        res->cb_fnc = cb;
        res->cb_ctx = ctx;
    }
    cant_fail_ret(pthread_mutex_unlock(&res->lock));

    /* A callback can clean up and destroy this result, so never invoke it
     * while holding the result's own mutex. */
    if(call_now) cb(res, success, ctx);
}

void tudor_cancel_async(tudor_async_res_t res) {
    winio_cancel_overlapped(res->ovlp);
}

bool tudor_wait_async(tudor_async_res_t res) {
    cant_fail_ret(pthread_mutex_lock(&res->lock));
    while(res->success == SUCCESS_PENDING) cant_fail_ret(pthread_cond_wait(&res->compl_cond, &res->lock));
    bool success = (bool)res->success;
    cant_fail_ret(pthread_mutex_unlock(&res->lock));
    return success;
}

bool tudor_wait_async_timeout(tudor_async_res_t res, unsigned int timeout_ms,
                              bool *timed_out) {
    struct timespec deadline;
    cant_fail(clock_gettime(CLOCK_MONOTONIC, &deadline));
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_nsec += (long) (timeout_ms % 1000) * 1000000L;
    if(deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }

    if(timed_out) *timed_out = false;
    cant_fail_ret(pthread_mutex_lock(&res->lock));
    while(res->success == SUCCESS_PENDING) {
        int rc = pthread_cond_clockwait(&res->compl_cond, &res->lock,
                                        CLOCK_MONOTONIC, &deadline);
        if(rc == ETIMEDOUT && res->success == SUCCESS_PENDING) {
            if(timed_out) *timed_out = true;
            cant_fail_ret(pthread_mutex_unlock(&res->lock));
            return false;
        }
        if(rc != 0 && rc != ETIMEDOUT) {
            errno = rc;
            perror("Error waiting for async result");
            abort();
        }
    }

    bool success = (bool) res->success;
    cant_fail_ret(pthread_mutex_unlock(&res->lock));
    return success;
}

void tudor_cleanup_async(tudor_async_res_t res) {
    cant_fail_ret(pthread_cond_destroy(&res->compl_cond));
    cant_fail_ret(pthread_mutex_destroy(&res->lock));
    winio_cleanup_overlapped(res->ovlp);
    free(res);
}
