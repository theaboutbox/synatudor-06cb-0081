#include "internal.h"
#include <libusb.h>
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
    libusb_context *ctx;
    struct {
        long vend_id;
        long prod_id;
    } supported_devices[100];
    int supported_devices_cnt;
    struct libusb_device_descriptor descr;
    libusb_device_handle * dev;

    DWORD timeouts[0x100];
    volatile char abort[0x100];

    FILE *script;
    int playback;
    int script_line;
};

void err(int ec)
{
    if (ec != 0) {
        printf("Encountered libusb error!\n");
        abort();
    }
}

bool claim_device(struct driver_info *info)
{
    libusb_device ** dev_list;
    int i, j;
    int dev_cnt = libusb_get_device_list(info->ctx, &dev_list);

    for (i = 0; i < dev_cnt; i++) {
        struct libusb_device_descriptor descriptor;

        libusb_get_device_descriptor(dev_list[i], &descriptor);

        for(j = 0;j < info->supported_devices_cnt;j++) {
            if (info->supported_devices[j].vend_id == descriptor.idVendor && 
                    info->supported_devices[j].prod_id == descriptor.idProduct) {
                printf("Found device %04x:%04x\n", descriptor.idVendor, descriptor.idProduct);

                err(libusb_get_device_descriptor(dev_list[i], &info->descr));
                err(libusb_open(dev_list[i], &info->dev));
                err(libusb_reset_device(info->dev));
                err(libusb_set_configuration(info->dev, 1));
                err(libusb_claim_interface(info->dev, 0));

                return TRUE;
            }
        }
    }

    printf("!!!!!!!!!!!! No matching devices found\n");
    return FALSE;
}


__winfnc BOOL
WinUsb_Initialize (HANDLE DeviceHandle, void** InterfaceHandle)
{
    TRACE();
    printf("Winusb_initialize enter\n");
    fflush(stdout);
    struct driver_info *info = malloc(sizeof(struct driver_info));

    memset(info, 0, sizeof(*info));

    *InterfaceHandle = info;

    if(DeviceHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    // o.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    long vend_id, prod_id;

    vend_id = 0x06cb;
    prod_id = 0x0081;

    info->supported_devices[info->supported_devices_cnt].vend_id = vend_id;
    info->supported_devices[info->supported_devices_cnt].prod_id = prod_id; 

    info->supported_devices_cnt = 1;

    info->script = NULL;
    info->playback = 0;

    info->dev = NULL;
    libusb_init(&info->ctx);

    return claim_device(info);
}
WINAPI(WinUsb_Initialize)


__winfnc bool WinUsb_Free(HANDLE InterfaceHandle)
{
    TRACE();
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
    struct driver_info *info = InterfaceHandle;
    int rc, i;
    uint16_t dti = (uint16_t)((DescriptorType << 8) | Index);

    TRACE();

        rc = libusb_control_transfer(info->dev, LIBUSB_ENDPOINT_IN,
                    LIBUSB_REQUEST_GET_DESCRIPTOR, dti,
                    LanguageID, Buffer, (uint16_t) BufferLength, 1000);


        if(rc >= 0) {
            fprintf(info->script, "blackbox: usb %d dsc ", dti);
            for(i=0;i<rc;i++) {
                fprintf(info->script, "%02x", Buffer[i]);
            }
            fprintf(info->script, "\r\n");
            fflush(info->script);
        }

    printf("rc = %d\n", rc);
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

__winfnc BOOL 
WinUsb_ControlTransfer(
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

    printf("%x %x %x %x %x\n", 
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
    if(!info->playback) {
        rc = libusb_control_transfer(info->dev,
            SetupPacket.RequestType, SetupPacket.Request, SetupPacket.Value, SetupPacket.Index,
            Buffer, SetupPacket.Length, 10000);
    }
    
    if(rc < 0) 
        return FALSE;
#if 0 
    printf("After: ");
    for(i=0;i<BufferLength;i++)
        printf("%02x ", Buffer[i]);
    printf("\r\n");
#endif

    *LengthTransferred = rc;
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
    struct driver_info *dev = InterfaceHandle;
    WINUSB_PIPE_INFORMATION *wpi = NULL;
    int i, rc;


    printf("PipeID=%d\n", PipeID);

    for(i=0;i<sizeof(pipe_types)/sizeof(*pipe_types);i++) {
        if(pipe_types[i].PipeId == PipeID)
            wpi = pipe_types + i;
    }
    if(!wpi) {
        printf("unknown pipe!\n");
        return FALSE;
    }
    if(!dev->playback) {
        switch(wpi->PipeType) {
            case UsbdPipeTypeBulk:
                printf("bulk xfer\n");
                rc = libusb_bulk_transfer(
                        dev->dev, 
                        PipeID, 
                        Buffer, 
                        BufferLength, 
                        (int*)LengthTransferred, 
                        dev->timeouts[PipeID]+1000);
                //sleep(3);
                break;

            case UsbdPipeTypeInterrupt:
                printf("interrupt xfer?\n");
                dev->abort[PipeID] = 1;
                for(i=0;;) {
                    rc = libusb_interrupt_transfer(
                            dev->dev, 
                            PipeID, 
                            Buffer, 
                            BufferLength, 
                            (int*)LengthTransferred, 
                            200);
                    
                    printf("libusb_interrupt_transfer=%d!\n", rc);

                    if(rc == LIBUSB_ERROR_TIMEOUT) {
                        if(dev->abort[PipeID] == 2) {
                            printf("W: Pipe was aborted!\n");
                            rc = 0;
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

        if(rc < 0)  {
            printf("E: xfer Failed - %s\n", libusb_error_name(rc));

            if(rc == LIBUSB_ERROR_TIMEOUT) {
                // SetLastError(ERROR_SEM_TIMEOUT);
                return FALSE;
            }

            exit(0); // Don't know what to do, panic quit
        }
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
    printf("PipeID=%x\n", PipeID);
    

    // if(Buffer[0] == 0x10 && Buffer[1] == 0 && Buffer[2] == 0) {
    //     abort();
    //     return FALSE;
    // }

    rc = libusb_bulk_transfer(dev->dev,
            PipeID,
            Buffer,
            BufferLength, 
            &send, 
            dev->timeouts[PipeID]+1000);
    printf("rc=%d send=%d\n", rc, send);

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
    printf("alt-if=%d pipe=%d\n", AlternateInterfaceNumber, PipeIndex);

    *PipeInformation = pipe_types[PipeIndex];

    return TRUE;
}
WINAPI(WinUsb_QueryPipe)


__winfnc BOOL
WinUsb_ResetPipe (HANDLE InterfaceHandle, UCHAR PipeID)
{
    TRACE();
    printf("pipe=%d\n", PipeID);
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
    printf("pipe=%d, policy type=%d, val length=%d, val=%x\n", PipeID, PolicyType, ValueLength, *(DWORD*)Value);

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
    printf("%x\n", PipeID);
    if(dev->abort[PipeID] == 1) {
        dev->abort[PipeID] = 2;

        while(dev->abort[PipeID] != 0)
            usleep(200);
    }
    printf("abort complete\n");
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

    printf("PipeID=%d PolicyType=%d ValueLength=%d\n", 
                PipeID, 
                PolicyType,
                *ValueLength);
    if(PolicyType == PIPE_TRANSFER_TIMEOUT) {
        *(DWORD*)Value = info->timeouts[PipeID];
    }
    printf("PipeID=%d PolicyType=%d ValueLength=%d Value=%x\n", 
                PipeID, 
                PolicyType,
                *ValueLength,
                *(DWORD*)Value);
    return TRUE;
}
WINAPI(WinUsb_GetPipePolicy)

