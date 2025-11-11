#include <assert.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>
#include "internal.h"


__winfnc BOOL QueryPerformanceCounter(uint64_t *counter) {
    TRACE();
    struct timespec time;
    if(clock_gettime(CLOCK_MONOTONIC, &time) != 0) {
        printf("Q perf counter failed!\n");
        winerr_set_errno();
        return FALSE;
    }

    *counter = time.tv_sec * 1000000lu + time.tv_nsec;
    printf("Perf counter: %lu\n", *counter);
    return TRUE;
}
WINAPI(QueryPerformanceCounter)

__winfnc DWORD GetTickCount() {
    TRACE();
    uint64_t counter;
    if(!QueryPerformanceCounter(&counter)) { log_error("QueryPerformanceCounter failed!"); abort(); }

    printf("Tick count: %lu\n", counter);
    return (DWORD) counter;
}
WINAPI(GetTickCount)

__winfnc void GetSystemTimeAsFileTime(FILETIME *outTime) {
    TRACE();
    struct timeval time;
    assert(gettimeofday(&time, NULL) == 0);

    uint64_t us = time.tv_sec * 10000lu + time.tv_usec;
    outTime->dwLowDateTime =  (DWORD) ((us >>  0) & 0xffffffffu);
    outTime->dwHighDateTime = (DWORD) ((us >> 32) & 0xffffffffu);
}
WINAPI(GetSystemTimeAsFileTime)
