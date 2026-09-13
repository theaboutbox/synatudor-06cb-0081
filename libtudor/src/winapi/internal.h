#ifndef LIBTUDOR_WINAPI_INTERNAL_H
#define LIBTUDOR_WINAPI_INTERNAL_H

#include "api.h"
#include <stddef.h>
#include <time.h>

enum win_utf_result {
    WIN_UTF_OK = 0,
    WIN_UTF_INVALID,
    WIN_UTF_BUFFER_TOO_SMALL,
    WIN_UTF_OVERFLOW
};

enum win_utf_result win_utf8_to_utf16(const char *input, size_t input_size,
                                      char16_t *output, size_t output_size,
                                      size_t *converted_size);
enum win_utf_result win_utf16_to_utf8(const char16_t *input,
                                      size_t input_size, char *output,
                                      size_t output_size,
                                      size_t *converted_size);

//Threading
void win_init_tib();
DWORD win_get_thread_id();

//Synchronization
struct win_sync_object;

#define INFINITE 0xffffffff
#define WAIT_TIMEOUT 0x00000102L

/* pthread timed waits take an absolute deadline, while WinAPI takes ms. */
static inline struct timespec win_wait_deadline(DWORD timeout) {
    struct timespec deadline;
    cant_fail(clock_gettime(CLOCK_MONOTONIC, &deadline));
    deadline.tv_sec += timeout / 1000;
    deadline.tv_nsec += (long) (timeout % 1000) * 1000000L;
    if(deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec++;
        deadline.tv_nsec -= 1000000000L;
    }
    return deadline;
}

typedef DWORD win_sync_obj_wait_fnc(struct win_sync_object *sync_obj, DWORD timeout);

struct win_sync_object {
    win_sync_obj_wait_fnc *wait_fnc;
};

HANDLE win_create_event(const char *name, bool initial_state, bool manual_reset);
void win_set_event(HANDLE evt);
void win_reset_event(HANDLE evt);

#endif
