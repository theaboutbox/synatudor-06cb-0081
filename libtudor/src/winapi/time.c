#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "internal.h"


/*
 * Expose CLOCK_MONOTONIC as a Windows performance counter.  The counter and
 * frequency must use the same units; mixing microseconds for tv_sec with raw
 * nanoseconds for tv_nsec made the old counter jump backwards at every
 * second boundary.
 */
__winfnc BOOL QueryPerformanceCounter(LONGLONG *counter) {
    TRACE();
    struct timespec time;
    if(clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
        winerr_set_errno();
        return FALSE;
    }

    *counter = (LONGLONG) time.tv_sec * 1000000000LL + time.tv_nsec;
    return TRUE;
}
WINAPI(QueryPerformanceCounter)

__winfnc BOOL QueryPerformanceFrequency(LONGLONG *frequency) {
    TRACE();
    if(!frequency) {
        winerr_set_code(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    *frequency = 1000000000LL;
    return TRUE;
}
WINAPI(QueryPerformanceFrequency)

__winfnc ULONGLONG GetTickCount64() {
    TRACE();
    struct timespec time;
    if(clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
        log_error("clock_gettime(CLOCK_MONOTONIC) failed!");
        abort();
    }

    return (ULONGLONG) time.tv_sec * 1000ULL +
           (ULONGLONG) time.tv_nsec / 1000000ULL;
}
WINAPI(GetTickCount64)

__winfnc DWORD GetTickCount() {
    TRACE();
    return (DWORD) GetTickCount64();
}
WINAPI(GetTickCount)

__winfnc void GetSystemTimeAsFileTime(FILETIME *outTime) {
    TRACE();
    struct timeval time;
    cant_fail(gettimeofday(&time, NULL));

    /* FILETIME is 100-nanosecond ticks since 1601-01-01 UTC. */
    uint64_t ticks = ((uint64_t) time.tv_sec + 11644473600ULL) * 10000000ULL +
                     (uint64_t) time.tv_usec * 10ULL;
    outTime->dwLowDateTime =  (DWORD) ((ticks >>  0) & 0xffffffffu);
    outTime->dwHighDateTime = (DWORD) ((ticks >> 32) & 0xffffffffu);
}
WINAPI(GetSystemTimeAsFileTime)
