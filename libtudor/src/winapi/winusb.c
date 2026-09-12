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

WINUSB_PIPE_INFORMATION pipe_types[] = {
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
    volatile char abort[0x100];

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



__winfnc BOOL WinUsb_GetDescriptor(
            HANDLE InterfaceHandle, 
            UCHAR DescriptorType, 
            UCHAR Index,
            USHORT LanguageID,
            PUCHAR Buffer,
            ULONG BufferLength,
            PULONG LengthTransferred)
{
    TRACE();

    struct driver_info *info = InterfaceHandle;
    int rc;
    uint16_t dti = (uint16_t)((DescriptorType << 8) | Index);

    if (info->playback) {
        return playback_transfer(info, dti, "dsc", Buffer, BufferLength,
                                 LengthTransferred, false);
    }



        rc = libusb_control_transfer(info->dev, LIBUSB_ENDPOINT_IN,
                    LIBUSB_REQUEST_GET_DESCRIPTOR, dti,
                    LanguageID, Buffer, (uint16_t) BufferLength, 1000);


        // if(rc >= 0) {
        //     fprintf(info->script, "blackbox: usb %d dsc ", dti);
        //     for(i=0;i<rc;i++) {
        //         fprintf(info->script, "%02x", Buffer[i]);
        //     }
        //     fprintf(info->script, "\r\n");
        //     fflush(info->script);
        // }

	    TRACE_PRINTF("rc = %d\n", rc);
    *LengthTransferred = rc;

    if(rc < 0)
        return FALSE;

    return TRUE;
}
WINAPI(WinUsb_GetDescriptor)

__winfnc BOOL WinUsb_QueryInterfaceSettings(
            HANDLE InterfaceHandle, 
            UCHAR AlternateInterfaceNumber, 
            void* UsbAltInterfaceDescriptor)
{
    TRACE();
    return FALSE;
}
WINAPI(WinUsb_QueryInterfaceSettings)

__winfnc BOOL WinUsb_ControlTransfer(
            HANDLE InterfaceHandle, 
            WINUSB_SETUP_PACKET SetupPacket,
            PUCHAR Buffer,
            ULONG BufferLength, 
            PULONG LengthTransferred, 
            LPOVERLAPPED Overlapped)
{
    struct driver_info *info = InterfaceHandle;
    TRACE();
    int rc, i;

	    TRACE_PRINTF("%x %x %x %x %x\n",
                SetupPacket.RequestType, 
                SetupPacket.Request, 
                SetupPacket.Value, 
                SetupPacket.Index,
                SetupPacket.Length);
#if 0
    printf("Before: ");
    for(i=0;i<BufferLength;i++) {
        if(i > 80000) {
            printf("...");
            break;
        } else {
            printf("%02x", Buffer[i]);
        }
    }
    printf("\r\n");
#endif
    if (info->playback) {
        rc = SetupPacket.Length;
        *LengthTransferred = rc;
        return TRUE;
    }
    rc = libusb_control_transfer(info->dev,
        SetupPacket.RequestType, SetupPacket.Request, SetupPacket.Value, SetupPacket.Index,
        Buffer, SetupPacket.Length, 10000);
    
    if(rc < 0) 
        return FALSE;
#if 0 
    printf("After: ");
    for(i=0;i<BufferLength;i++)
        printf("%02x ", Buffer[i]);
    printf("\r\n");
#endif
	    TRACE_PRINTF("ControlTransfer rc = %d\n", rc);

    ULONG res = (ULONG) rc;
    *LengthTransferred = res;
    winerr_clear();
    usleep(500000);
    return TRUE;
}
WINAPI(WinUsb_ControlTransfer)

__winfnc BOOL
WinUsb_ReadPipe(
            HANDLE InterfaceHandle, 
            UCHAR PipeID, 
            PUCHAR Buffer, 
            ULONG BufferLength, 
            PULONG LengthTransferred, 
            LPOVERLAPPED Overlapped)
{
    TRACE();
    struct driver_info *dev = InterfaceHandle;
    WINUSB_PIPE_INFORMATION *wpi = NULL;
    int i, rc;
    bool was_aborted = false;


	    TRACE_PRINTF("PipeID=%d\n", PipeID);

    for(i=0;i<sizeof(pipe_types)/sizeof(*pipe_types);i++) {
        if(pipe_types[i].PipeId == PipeID)
            wpi = pipe_types + i;
    }
    if(!wpi) {
        printf("unknown pipe!\n");
        return FALSE;
    }

    if (dev->playback) {
        return playback_transfer(dev, PipeID, "<<<", Buffer, BufferLength,
                                 LengthTransferred, false);
    }

    switch(wpi->PipeType) {
        case UsbdPipeTypeBulk:
	            TRACE_PRINTF("bulk xfer\n");
            rc = libusb_bulk_transfer(
                    dev->dev, 
                    PipeID, 
                    Buffer, 
                    BufferLength, 
                    (int*)LengthTransferred, 
                    dev->timeouts[PipeID]+1000);
            //sleep(3);
	            TRACE_PRINTF("LengthTransferred: %d\n", *LengthTransferred);
            break;

        case UsbdPipeTypeInterrupt:
	            TRACE_PRINTF("interrupt xfer?\n");
            dev->abort[PipeID] = 1;
            for(i=0;;) {
                rc = libusb_interrupt_transfer(
                        dev->dev, 
                        PipeID, 
                        Buffer, 
                        BufferLength, 
                        (int*)LengthTransferred, 
                        200);
                
	                TRACE_PRINTF("libusb_interrupt_transfer=%d!\n", rc);

                if(rc == LIBUSB_ERROR_TIMEOUT) {
                    if(dev->abort[PipeID] == 2) {
                        printf("W: Pipe was aborted!\n");
                        was_aborted = true;
                        break;
                    }

                    if(dev->timeouts[PipeID]) {
                        if(i > dev->timeouts[PipeID])
                            break;
                        else
                            i += 200;
                    }
                    continue;
                }

                break;
            }
            dev->abort[PipeID] = 0;
            break;

        default:
            printf("E: unknown pipe type!\n");
            return FALSE;
    }

    if(was_aborted) {
        /* An aborted read is not a successful zero-byte interrupt packet. */
        *LengthTransferred = 0;
        winerr_set_code(995); /* ERROR_OPERATION_ABORTED */
        return FALSE;
    }

    if(rc < 0)  {
        printf("E: xfer Failed - %s\n", libusb_error_name(rc));

        if(rc == LIBUSB_ERROR_TIMEOUT) {
            winerr_set_code(121); /* ERROR_SEM_TIMEOUT */
            return FALSE;
        }

        exit(0); // Don't know what to do, panic quit
    }

    return TRUE;
}
WINAPI(WinUsb_ReadPipe)



__winfnc BOOL
WinUsb_WritePipe(
            HANDLE InterfaceHandle, 
            UCHAR PipeID,
            PUCHAR Buffer,
            ULONG BufferLength, 
            PULONG LengthTransferred, 
            LPOVERLAPPED Overlapped)
{
    int rc;
    struct driver_info *dev = InterfaceHandle;
    int send;

    TRACE();
	    TRACE_PRINTF("PipeID=%x\n", PipeID);
    

    // if(Buffer[0] == 0x10 && Buffer[1] == 0 && Buffer[2] == 0) {
    //     abort();
    //     return FALSE;
    // }
    if (dev->playback) {
        return playback_transfer(dev, PipeID, ">>>", Buffer, BufferLength,
                                 LengthTransferred, true);
    }

    rc = libusb_bulk_transfer(dev->dev,
            PipeID,
            Buffer,
            BufferLength, 
            &send, 
            dev->timeouts[PipeID]+1000);
	    TRACE_PRINTF("rc=%d send=%d\n", rc, send);

    if(rc < 0) {
        printf("E: xfer Failed - %s\n", libusb_error_name(rc));
        exit(0);
        return FALSE;
    }
    *LengthTransferred = send;

    return TRUE;
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
    struct driver_info *info = InterfaceHandle;

    TRACE();
	    TRACE_PRINTF("pipe=%d, policy type=%d, val length=%d, val=%x\n", PipeID, PolicyType, ValueLength, *(DWORD*)Value);

    if(PolicyType == PIPE_TRANSFER_TIMEOUT) {
        info->timeouts[PipeID] = *(DWORD*)Value;
    }
    return TRUE;
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
    struct driver_info *dev = InterfaceHandle;
    TRACE();
	    TRACE_PRINTF("%x\n", PipeID);
    if(dev->abort[PipeID] == 1) {
        dev->abort[PipeID] = 2;

        while(dev->abort[PipeID] != 0)
            usleep(200);
    }
	    TRACE_PRINTF("abort complete\n");
    return TRUE;
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
    struct driver_info *info = InterfaceHandle;

	    TRACE_PRINTF("PipeID=%d PolicyType=%d ValueLength=%d\n",
                PipeID, 
                PolicyType,
                *ValueLength);
    if(PolicyType == PIPE_TRANSFER_TIMEOUT) {
        *(DWORD*)Value = info->timeouts[PipeID];
    }
	    TRACE_PRINTF("PipeID=%d PolicyType=%d ValueLength=%d Value=%x\n",
                PipeID, 
                PolicyType,
                *ValueLength,
                *(DWORD*)Value);
    return TRUE;
}
WINAPI(WinUsb_GetPipePolicy)
