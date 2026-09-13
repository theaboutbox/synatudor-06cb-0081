#include "internal.h"
#include <errno.h>
#include <libusb.h>
#include <limits.h>
#include <unistd.h>

typedef enum _USBD_PIPE_TYPE {
  UsbdPipeTypeControl,
  UsbdPipeTypeIsochronous,
  UsbdPipeTypeBulk,
  UsbdPipeTypeInterrupt
} USBD_PIPE_TYPE;

const ULONG PIPE_TRANSFER_TIMEOUT = 0x03;

typedef struct _WINUSB_PIPE_INFORMATION {
  USBD_PIPE_TYPE PipeType;
  UCHAR          PipeId;
  USHORT         MaximumPacketSize;
  UCHAR          Interval;
} WINUSB_PIPE_INFORMATION, *PWINUSB_PIPE_INFORMATION;

typedef struct _WINUSB_SETUP_PACKET {
  UCHAR  RequestType;
  UCHAR  Request;
  USHORT Value;
  USHORT Index;
  USHORT Length;
} WINUSB_SETUP_PACKET, *PWINUSB_SETUP_PACKET;

static const WINUSB_PIPE_INFORMATION pipe_types[] = {
    { UsbdPipeTypeBulk, 0x01, 0x40, 0 },
    { UsbdPipeTypeBulk, 0x81, 0x40, 0 },
    { UsbdPipeTypeBulk, 0x82, 0x40, 0 },
    { UsbdPipeTypeInterrupt, 0x83, 0x08, 4 },
    { UsbdPipeTypeInterrupt, 0x84, 0x10, 10 },
};

struct driver_info {
    // char padding[0x18];
    libusb_context *ctx;
    struct {
        long vend_id;
        long prod_id;
    } supported_devices[100];
    int supported_devices_cnt;
    struct libusb_device_descriptor descr;
    libusb_device_handle * dev;
    bool owns_ctx;
    bool owns_dev;
    bool interface_claimed;

    DWORD timeouts[0x100];
    pthread_mutex_t pipe_lock;
    pthread_cond_t pipe_cond;
    bool active[0x100];
    bool abort_requested[0x100];
    uint64_t completed[0x100];

    FILE *script;
    int playback;
    int script_line;
};

/* The old playback path reserved an eight-megabyte array in every caller's
 * stack frame, even when playback was disabled.  Keep the historical input
 * limit, but allocate it only while a script record is actually being read. */
#define USB_PLAYBACK_MAX_TRANSFER_LENGTH 4000000U
#define USB_PLAYBACK_LINE_SLACK 64U

static int playback_hex_digit(char value) {
    if(value >= '0' && value <= '9') return value - '0';
    if(value >= 'a' && value <= 'f') return value - 'a' + 10;
    if(value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static char *playback_skip_horizontal_space(char *cursor) {
    while(*cursor == ' ' || *cursor == '\t') cursor++;
    return cursor;
}

static BOOL playback_transfer(struct driver_info *info, int expected_selector,
                              const char *expected_direction, PUCHAR buffer,
                              ULONG buffer_length, PULONG length_transferred,
                              bool compare_output) {
    static const char prefix[] = "blackbox: usb ";

    if(!length_transferred) {
        log_error("USB playback requires a transfer-length output");
        winerr_set_code(87); /* ERROR_INVALID_PARAMETER */
        return FALSE;
    }
    *length_transferred = 0;

    if(!info || !info->script || (!buffer && buffer_length != 0)) {
        log_error("USB playback received invalid arguments");
        winerr_set_code(87); /* ERROR_INVALID_PARAMETER */
        return FALSE;
    }
    if(buffer_length > USB_PLAYBACK_MAX_TRANSFER_LENGTH) {
        log_error("USB playback transfer is too large: %lu bytes",
                  (unsigned long)buffer_length);
        winerr_set_code(122); /* ERROR_INSUFFICIENT_BUFFER */
        return FALSE;
    }

    size_t line_capacity = (size_t)buffer_length * 2U +
                           USB_PLAYBACK_LINE_SLACK;
    char *line = malloc(line_capacity);
    if(!line) {
        log_error("Allocating the USB playback input buffer failed");
        winerr_set_code(8); /* ERROR_NOT_ENOUGH_MEMORY */
        return FALSE;
    }

    info->script_line++;
    if(!fgets(line, (int)line_capacity, info->script)) {
        log_error("Missing USB playback record on script line %d",
                  info->script_line);
        free(line);
        winerr_set_code(38); /* ERROR_HANDLE_EOF */
        return FALSE;
    }

    size_t line_length = strlen(line);
    if(line_length == line_capacity - 1U &&
       line[line_length - 1U] != '\n') {
        log_error("USB playback record exceeds its bounded input on script line %d",
                  info->script_line);
        free(line);
        winerr_set_code(13); /* ERROR_INVALID_DATA */
        return FALSE;
    }

    char *cursor = line;
    if(strncmp(cursor, prefix, sizeof(prefix) - 1U) != 0) {
        log_error("Malformed USB playback prefix on script line %d",
                  info->script_line);
        goto invalid_record;
    }
    cursor += sizeof(prefix) - 1U;

    errno = 0;
    char *selector_end = NULL;
    long selector = strtol(cursor, &selector_end, 10);
    if(errno == ERANGE || selector_end == cursor || selector < 0 ||
       selector > INT_MAX ||
       (*selector_end != ' ' && *selector_end != '\t')) {
        log_error("Malformed USB selector on script line %d",
                  info->script_line);
        goto invalid_record;
    }
    if(selector != expected_selector) {
        log_error("Wrong USB selector on script line %d (expected %ld, requested %d)",
                  info->script_line, selector, expected_selector);
        goto invalid_record;
    }
    cursor = playback_skip_horizontal_space(selector_end);

    size_t direction_length = strlen(expected_direction);
    if(strncmp(cursor, expected_direction, direction_length) != 0 ||
       (cursor[direction_length] != ' ' &&
        cursor[direction_length] != '\t')) {
        log_error("Wrong USB direction on script line %d (requested %s)",
                  info->script_line, expected_direction);
        goto invalid_record;
    }
    cursor = playback_skip_horizontal_space(cursor + direction_length);

    char *hex = cursor;
    while(*cursor && *cursor != ' ' && *cursor != '\t' &&
          *cursor != '\r' && *cursor != '\n')
        cursor++;
    size_t hex_length = (size_t)(cursor - hex);
    cursor = playback_skip_horizontal_space(cursor);
    while(*cursor == '\r' || *cursor == '\n') cursor++;
    if(*cursor != '\0' || (hex_length & 1U) != 0) {
        log_error("Malformed USB hex payload on script line %d",
                  info->script_line);
        goto invalid_record;
    }

    size_t transfer_length = hex_length / 2U;
    if(transfer_length > buffer_length ||
       (compare_output && transfer_length != buffer_length)) {
        log_error("USB playback length mismatch on script line %d "
                  "(script %zu, buffer %lu)", info->script_line,
                  transfer_length, (unsigned long)buffer_length);
        goto invalid_record;
    }

    for(size_t i = 0; i < transfer_length; i++) {
        int high = playback_hex_digit(hex[i * 2U]);
        int low = playback_hex_digit(hex[i * 2U + 1U]);
        if(high < 0 || low < 0) {
            log_error("Invalid USB hex byte on script line %d at byte %zu",
                      info->script_line, i);
            goto invalid_record;
        }

        UCHAR value = (UCHAR)((high << 4) | low);
        if(compare_output) {
            if(buffer[i] != value) {
                log_error("USB output mismatch on script line %d at byte %zu",
                          info->script_line, i);
                goto invalid_record;
            }
        } else {
            buffer[i] = value;
        }
    }

    *length_transferred = (ULONG)transfer_length;
    free(line);
    winerr_clear();
    return TRUE;

invalid_record:
    free(line);
    winerr_set_code(13); /* ERROR_INVALID_DATA */
    return FALSE;
}

/* The TOD host receives an already-open device FD over IPC and wraps it in
 * its sandbox-owned libusb context.  OnPrepareHardware runs during
 * tudor_init(), so make that handle available before the vendor driver calls
 * WinUsb_Initialize.  Each host process owns one sensor and sets this only
 * before init or after shutdown, so no synchronization is required here. */
static libusb_device_handle *borrowed_usb_dev;

void tudor_set_usb_device(libusb_device_handle *usb_dev) {
    borrowed_usb_dev = usb_dev;
}

static bool usb_call_succeeded(const char *operation, int status) {
    if(status == LIBUSB_SUCCESS) return true;
    log_error("%s failed: %d [%s]", operation, status,
              libusb_error_name(status));
    return false;
}

static bool supported_device(const struct driver_info *info,
                             const struct libusb_device_descriptor *descr) {
    for(int i = 0; i < info->supported_devices_cnt; i++) {
        if(info->supported_devices[i].vend_id == descr->idVendor &&
           info->supported_devices[i].prod_id == descr->idProduct)
            return true;
    }
    return false;
}

static bool prepare_device(struct driver_info *info) {
    libusb_device *device = libusb_get_device(info->dev);
    if(!device) {
        log_error("The libusb handle has no device");
        return false;
    }

    int status = libusb_get_device_descriptor(device, &info->descr);
    if(!usb_call_succeeded("Getting USB device descriptor", status))
        return false;
    if(!supported_device(info, &info->descr)) {
        log_error("Refusing unexpected USB device %04x:%04x",
                  info->descr.idVendor, info->descr.idProduct);
        return false;
    }

    int config;
    status = libusb_get_configuration(info->dev, &config);
    if(!usb_call_succeeded("Getting USB configuration", status))
        return false;

    /* Re-applying the active configuration can reset the device. */
    if(config != 1) {
        status = libusb_set_configuration(info->dev, 1);
        if(!usb_call_succeeded("Setting USB configuration", status))
            return false;
    }

    status = libusb_claim_interface(info->dev, 0);
    if(!usb_call_succeeded("Claiming USB interface 0", status))
        return false;
    info->interface_claimed = true;
    return true;
}

static bool claim_device(struct driver_info *info) {
    libusb_device **dev_list = NULL;
    ssize_t dev_cnt = libusb_get_device_list(info->ctx, &dev_list);
    if(dev_cnt < 0) {
        log_error("Listing USB devices failed: %d [%s]", (int)dev_cnt,
                  libusb_error_name((int)dev_cnt));
        return false;
    }

    bool found = false;
    for(ssize_t i = 0; i < dev_cnt; i++) {
        struct libusb_device_descriptor descriptor;
        int status = libusb_get_device_descriptor(dev_list[i], &descriptor);
        if(status != LIBUSB_SUCCESS) continue;
        if(!supported_device(info, &descriptor)) continue;

        printf("Found device %04x:%04x\n", descriptor.idVendor,
               descriptor.idProduct);
        status = libusb_open(dev_list[i], &info->dev);
        if(!usb_call_succeeded("Opening USB device", status)) break;
        info->owns_dev = true;
        found = prepare_device(info);
        if(!found) {
            libusb_close(info->dev);
            info->dev = NULL;
            info->owns_dev = false;
        }
        break;
    }

    libusb_free_device_list(dev_list, true);
    if(!found) {
        log_error("No usable Synaptics 06cb:0081 device found");
    } else {
        printf("libusb initialized, device = %p\n", info->dev);
    }
    return found;
}

static void free_driver_info(struct driver_info *info) {
    if(!info) return;

    if(info->interface_claimed) {
        int status = libusb_release_interface(info->dev, 0);
        if(status != LIBUSB_SUCCESS && status != LIBUSB_ERROR_NO_DEVICE)
            log_warn("Releasing USB interface 0 failed: %d [%s]", status,
                     libusb_error_name(status));
    }
    if(info->owns_dev && info->dev) libusb_close(info->dev);
    if(info->owns_ctx && info->ctx) libusb_exit(info->ctx);
    if(info->script) fclose(info->script);
    cant_fail_ret(pthread_cond_destroy(&info->pipe_cond));
    cant_fail_ret(pthread_mutex_destroy(&info->pipe_lock));
    free(info);
}


__winfnc BOOL
WinUsb_Initialize (HANDLE DeviceHandle, void** InterfaceHandle)
{
    TRACE();
    printf("Winusb_initialize enter\n");
    fflush(stdout);
    if(!InterfaceHandle || DeviceHandle == INVALID_HANDLE_VALUE) return FALSE;
    *InterfaceHandle = NULL;

    struct driver_info *info = calloc(1, sizeof(*info));
    if(!info) return FALSE;
    cant_fail_ret(pthread_mutex_init(&info->pipe_lock, NULL));
    cant_fail_ret(pthread_cond_init(&info->pipe_cond, NULL));

    printf("DeviceHandle: %p\n", DeviceHandle);
    printf("ppInterfaceHandle: %p\n", InterfaceHandle);
    printf("pInterfaceHandle: %p\n", info);

    // o.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    long vend_id, prod_id;

    vend_id = 0x06cb;
    prod_id = 0x0081;

    info->supported_devices[info->supported_devices_cnt].vend_id = vend_id;
    info->supported_devices[info->supported_devices_cnt].prod_id = prod_id; 

    info->supported_devices_cnt = 1;

    info->script = NULL;
    info->script_line = 0;
    info->playback = 0;

    if(info->playback) {
        info->script = fopen("usb_script.txt", "rt");
        info->playback = 1;
        if(info->script == NULL) {
            log_error("failed to open the USB script \n");
            free_driver_info(info);
            return FALSE;
        }

        info->script_line = 0;
        *InterfaceHandle = info;
        return TRUE;

    } else {
        bool ready;
        if(borrowed_usb_dev) {
            info->dev = borrowed_usb_dev;
            ready = prepare_device(info);
        } else {
            int status = libusb_init(&info->ctx);
            if(!usb_call_succeeded("Initializing fallback libusb context",
                                   status)) {
                free_driver_info(info);
                return FALSE;
            }
            info->owns_ctx = true;
            ready = claim_device(info);
        }

        if(!ready) {
            free_driver_info(info);
            return FALSE;
        }
        *InterfaceHandle = info;
        return TRUE;
    }

}
WINAPI(WinUsb_Initialize)


__winfnc BOOL WinUsb_Free(HANDLE InterfaceHandle)
{
    TRACE();
    if(!InterfaceHandle) return FALSE;
    free_driver_info((struct driver_info*)InterfaceHandle);
    return TRUE;
}
WINAPI(WinUsb_Free)



/* Keep cancellation bounded without spinning in AbortPipe. No-data polling
 * timeouts are internal; the caller's timeout is one monotonic deadline. */
#define USB_CANCEL_POLL_MS 200U

static BOOL transfer_result(int status) {
    if(status >= 0) {
        winerr_clear();
        return TRUE;
    }
    switch(status) {
        case LIBUSB_ERROR_TIMEOUT: winerr_set_code(121); break; /* ERROR_SEM_TIMEOUT */
        case LIBUSB_ERROR_NO_DEVICE: winerr_set_code(1167); break; /* ERROR_DEVICE_NOT_CONNECTED */
        case LIBUSB_ERROR_INVALID_PARAM: winerr_set_code(ERROR_INVALID_PARAMETER); break;
        case LIBUSB_ERROR_NO_MEM: winerr_set_code(8); break;
        default: winerr_set_code(ERROR_GEN_FAILURE); break;
    }
    return FALSE;
}

static const WINUSB_PIPE_INFORMATION *find_pipe(UCHAR id) {
    for(size_t i = 0; i < sizeof(pipe_types) / sizeof(*pipe_types); i++)
        if(pipe_types[i].PipeId == id) return &pipe_types[i];
    return NULL;
}

static uint64_t usb_monotonic_ms(void) {
    struct timespec now;
    cant_fail(clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

__winfnc BOOL WinUsb_GetDescriptor(HANDLE InterfaceHandle, UCHAR DescriptorType,
        UCHAR Index, USHORT LanguageID, PUCHAR Buffer, ULONG BufferLength,
        PULONG LengthTransferred) {
    struct driver_info *info = (struct driver_info *)InterfaceHandle;
    if(LengthTransferred) *LengthTransferred = 0;
    if(!info || (!Buffer && BufferLength) || BufferLength > UINT16_MAX)
        return transfer_result(LIBUSB_ERROR_INVALID_PARAM);
    uint16_t selector = (uint16_t)((DescriptorType << 8) | Index);
    if(info->playback)
        return playback_transfer(info, selector, "dsc", Buffer, BufferLength,
                                 LengthTransferred, false);
    int rc = libusb_control_transfer(info->dev, LIBUSB_ENDPOINT_IN,
        LIBUSB_REQUEST_GET_DESCRIPTOR, selector, LanguageID, Buffer,
        (uint16_t)BufferLength, 1000);
    if(rc >= 0 && LengthTransferred) *LengthTransferred = (ULONG)rc;
    return transfer_result(rc);
}
WINAPI(WinUsb_GetDescriptor)

__winfnc BOOL WinUsb_QueryInterfaceSettings(HANDLE InterfaceHandle,
        UCHAR AlternateInterfaceNumber, void *UsbAltInterfaceDescriptor) {
    return FALSE;
}
WINAPI(WinUsb_QueryInterfaceSettings)

__winfnc BOOL WinUsb_ControlTransfer(HANDLE InterfaceHandle,
        WINUSB_SETUP_PACKET SetupPacket, PUCHAR Buffer, ULONG BufferLength,
        PULONG LengthTransferred, LPOVERLAPPED Overlapped) {
    struct driver_info *info = (struct driver_info *)InterfaceHandle;
    if(LengthTransferred) *LengthTransferred = 0;
    if(!info || (!Buffer && SetupPacket.Length) ||
       SetupPacket.Length > BufferLength)
        return transfer_result(LIBUSB_ERROR_INVALID_PARAM);
    if(info->playback) {
        if(LengthTransferred) *LengthTransferred = SetupPacket.Length;
        return transfer_result(LIBUSB_SUCCESS);
    }
    int rc = libusb_control_transfer(info->dev, SetupPacket.RequestType,
        SetupPacket.Request, SetupPacket.Value, SetupPacket.Index, Buffer,
        SetupPacket.Length, 10000);
    if(rc >= 0 && LengthTransferred) *LengthTransferred = (ULONG)rc;
    return transfer_result(rc);
}
WINAPI(WinUsb_ControlTransfer)

static BOOL pipe_transfer(struct driver_info *dev, UCHAR pipe_id,
        PUCHAR buffer, ULONG length, PULONG transferred, bool read) {
    if(transferred) *transferred = 0;
    const WINUSB_PIPE_INFORMATION *pipe = find_pipe(pipe_id);
    if(!dev || !pipe || (!buffer && length) || length > INT_MAX ||
       ((pipe_id & LIBUSB_ENDPOINT_IN) != 0) != read)
        return transfer_result(LIBUSB_ERROR_INVALID_PARAM);
    if(dev->playback)
        return playback_transfer(dev, pipe_id, read ? "<<<" : ">>>", buffer,
                                 length, transferred, !read);

    cant_fail_ret(pthread_mutex_lock(&dev->pipe_lock));
    /* Serialize synchronous transfers on each endpoint, as WinUSB does. */
    while(dev->active[pipe_id])
        cant_fail_ret(pthread_cond_wait(&dev->pipe_cond, &dev->pipe_lock));
    dev->active[pipe_id] = true;
    dev->abort_requested[pipe_id] = false;
    DWORD timeout = dev->timeouts[pipe_id];
    cant_fail_ret(pthread_mutex_unlock(&dev->pipe_lock));

    uint64_t deadline = timeout ? usb_monotonic_ms() + timeout : 0;
    int rc, count = 0, total = 0;
    bool aborted;
    for(;;) {
        unsigned int slice = USB_CANCEL_POLL_MS;
        if(timeout) {
            uint64_t now = usb_monotonic_ms();
            if(now >= deadline) { rc = LIBUSB_ERROR_TIMEOUT; break; }
            if(deadline - now < slice) slice = (unsigned int)(deadline - now);
        }
        if(pipe->PipeType == UsbdPipeTypeInterrupt)
            rc = libusb_interrupt_transfer(dev->dev, pipe_id, buffer ? buffer + total : NULL,
                                            (int)length - total, &count, slice);
        else
            rc = libusb_bulk_transfer(dev->dev, pipe_id, buffer ? buffer + total : NULL,
                                      (int)length - total, &count, slice);

        cant_fail_ret(pthread_mutex_lock(&dev->pipe_lock));
        aborted = dev->abort_requested[pipe_id];
        cant_fail_ret(pthread_mutex_unlock(&dev->pipe_lock));
        /* libusb may transfer bytes even when a polling slice times out.
         * Continue only with the remainder so no data is lost or resent. */
        total += count;
        if(aborted || rc != LIBUSB_ERROR_TIMEOUT) break;
        if(total == (int)length) { rc = LIBUSB_SUCCESS; break; }
    }

    cant_fail_ret(pthread_mutex_lock(&dev->pipe_lock));
    aborted = dev->abort_requested[pipe_id];
    dev->active[pipe_id] = false;
    dev->completed[pipe_id]++;
    cant_fail_ret(pthread_cond_broadcast(&dev->pipe_cond));
    cant_fail_ret(pthread_mutex_unlock(&dev->pipe_lock));

    if(transferred) *transferred = (ULONG)total;
    if(aborted) {
        winerr_set_code(995); /* ERROR_OPERATION_ABORTED */
        return FALSE;
    }
    return transfer_result(rc);
}

__winfnc BOOL WinUsb_ReadPipe(HANDLE InterfaceHandle, UCHAR PipeID,
        PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred,
        LPOVERLAPPED Overlapped) {
    return pipe_transfer((struct driver_info *)InterfaceHandle, PipeID,
                         Buffer, BufferLength, LengthTransferred, true);
}
WINAPI(WinUsb_ReadPipe)

__winfnc BOOL WinUsb_WritePipe(HANDLE InterfaceHandle, UCHAR PipeID,
        PUCHAR Buffer, ULONG BufferLength, PULONG LengthTransferred,
        LPOVERLAPPED Overlapped) {
    return pipe_transfer((struct driver_info *)InterfaceHandle, PipeID,
                         Buffer, BufferLength, LengthTransferred, false);
}
WINAPI(WinUsb_WritePipe)

__winfnc BOOL
WinUsb_QueryPipe(
            HANDLE InterfaceHandle,
            UCHAR AlternateInterfaceNumber,
            UCHAR PipeIndex,
            PWINUSB_PIPE_INFORMATION PipeInformation)
{
    TRACE();
	    TRACE_PRINTF("alt-if=%d pipe=%d\n", AlternateInterfaceNumber, PipeIndex);

    if(PipeIndex >= sizeof(pipe_types) / sizeof(*pipe_types)) {
        winerr_set_code(ERROR_NO_MORE_ITEMS);
        return FALSE;
    }

    *PipeInformation = pipe_types[PipeIndex];

    return TRUE;
}
WINAPI(WinUsb_QueryPipe)


__winfnc BOOL
WinUsb_ResetPipe (HANDLE InterfaceHandle, UCHAR PipeID)
{
    TRACE();
	    TRACE_PRINTF("pipe=%d\n", PipeID);
    return TRUE;
}
WINAPI(WinUsb_ResetPipe)

// ============================================================

__winfnc BOOL
WinUsb_SetPipePolicy(
            HANDLE InterfaceHandle,
            UCHAR PipeID,
            ULONG PolicyType,
            ULONG ValueLength,
            PVOID Value)
{
    struct driver_info *info = (struct driver_info *)InterfaceHandle;
    if(!info || !find_pipe(PipeID) || !Value)
        return transfer_result(LIBUSB_ERROR_INVALID_PARAM);
    if(PolicyType == PIPE_TRANSFER_TIMEOUT) {
        if(ValueLength != sizeof(DWORD))
            return transfer_result(LIBUSB_ERROR_INVALID_PARAM);
        DWORD timeout;
        memcpy(&timeout, Value, sizeof(timeout));
        cant_fail_ret(pthread_mutex_lock(&info->pipe_lock));
        info->timeouts[PipeID] = timeout;
        cant_fail_ret(pthread_mutex_unlock(&info->pipe_lock));
    }
    return transfer_result(LIBUSB_SUCCESS);
}
WINAPI(WinUsb_SetPipePolicy)

__winfnc BOOL
WinUsb_FlushPipe (HANDLE InterfaceHandle, UCHAR PipeID)
{
    TRACE();
    return TRUE;
}
WINAPI(WinUsb_FlushPipe)

__winfnc BOOL
WinUsb_AbortPipe (HANDLE InterfaceHandle, UCHAR PipeID)
{
    struct driver_info *dev = (struct driver_info *)InterfaceHandle;
    if(!dev || !find_pipe(PipeID))
        return transfer_result(LIBUSB_ERROR_INVALID_PARAM);
    cant_fail_ret(pthread_mutex_lock(&dev->pipe_lock));
    if(dev->active[PipeID]) {
        uint64_t generation = dev->completed[PipeID];
        dev->abort_requested[PipeID] = true;
        while(dev->completed[PipeID] == generation)
            cant_fail_ret(pthread_cond_wait(&dev->pipe_cond, &dev->pipe_lock));
    }
    cant_fail_ret(pthread_mutex_unlock(&dev->pipe_lock));
    return transfer_result(LIBUSB_SUCCESS);
}
WINAPI(WinUsb_AbortPipe)

__winfnc BOOL
WinUsb_SetPowerPolicy(
            HANDLE InterfaceHandle,
            ULONG PolicyType,
            ULONG ValueLength,
            PVOID Value)
{
    TRACE();
    return TRUE;
}
WINAPI(WinUsb_SetPowerPolicy)


__winfnc BOOL
WinUsb_GetPowerPolicy (HANDLE InterfaceHandle, ULONG PolicyType, PULONG ValueLength, PVOID Value)
{
    TRACE();
    return FALSE;
}
WINAPI(WinUsb_GetPowerPolicy)


__winfnc BOOL
WinUsb_GetPipePolicy(
            HANDLE InterfaceHandle,
            UCHAR PipeID,
            ULONG PolicyType,
            PULONG ValueLength,
            PVOID Value)
{
    struct driver_info *info = (struct driver_info *)InterfaceHandle;
    if(!info || !find_pipe(PipeID) || !ValueLength || !Value ||
       PolicyType != PIPE_TRANSFER_TIMEOUT)
        return transfer_result(LIBUSB_ERROR_INVALID_PARAM);
    if(*ValueLength < sizeof(DWORD)) {
        *ValueLength = sizeof(DWORD);
        winerr_set_code(122); /* ERROR_INSUFFICIENT_BUFFER */
        return FALSE;
    }
    cant_fail_ret(pthread_mutex_lock(&info->pipe_lock));
    DWORD timeout = info->timeouts[PipeID];
    cant_fail_ret(pthread_mutex_unlock(&info->pipe_lock));
    memcpy(Value, &timeout, sizeof(timeout));
    *ValueLength = sizeof(DWORD);
    return transfer_result(LIBUSB_SUCCESS);
}
WINAPI(WinUsb_GetPipePolicy)
