#include "internal.h"

__winfnc void WppAutoLogStart(DRIVER_OBJECT *driver, UNICODE_STRING *reg_path) {}
WINAPI(WppAutoLogStart)

__winfnc void WppAutoLogStop(DRIVER_OBJECT *driver) {}
WINAPI(WppAutoLogStop)

/* See TraceMessage(): the USHORT message number is widened so that it can
 * legally be the last named parameter before the variadic list. */
__winfnc NTSTATUS WppAutoLogTrace(void *context, UCHAR level, ULONG flags, GUID *guid, unsigned int num_arg, ...) {
    USHORT num = (USHORT) num_arg;
    win_va_list vas;
    win_va_start(vas, num_arg);
    winlog_trace(*guid, num, vas);
    win_va_end(vas);
    return ERROR_SUCCESS;
}
WINAPI(WppAutoLogTrace)