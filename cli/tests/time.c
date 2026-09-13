#undef NDEBUG
#include <assert.h>
#include <stdint.h>
#include <sys/time.h>
#include "winapi/api.h"

extern __winfnc void GetSystemTimeAsFileTime(FILETIME *);

static uint64_t filetime_now(void) {
    struct timeval now;
    assert(gettimeofday(&now, NULL) == 0);
    return ((uint64_t)now.tv_sec + 11644473600ULL) * 10000000ULL +
           (uint64_t)now.tv_usec * 10;
}

int main(void) {
    uint64_t before = filetime_now();
    FILETIME time;
    GetSystemTimeAsFileTime(&time);
    uint64_t after = filetime_now();
    uint64_t actual = ((uint64_t)time.dwHighDateTime << 32) | time.dwLowDateTime;
    assert(before <= actual && actual <= after);
    return 0;
}
