#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>

#include <libusb.h>
#include <tudor/tudor.h>

#include "winapi/api.h"

extern __winfnc BOOL WinUsb_Initialize(HANDLE device_handle,
                                       void **interface_handle);
extern __winfnc BOOL WinUsb_Free(HANDLE interface_handle);
extern __winfnc BOOL WinUsb_GetDescriptor(HANDLE interface_handle,
                                           UCHAR descriptor_type, UCHAR index,
                                           USHORT language_id, PUCHAR buffer,
                                           ULONG buffer_length,
                                           PULONG length_transferred);
extern __winfnc BOOL WinUsb_ReadPipe(HANDLE interface_handle, UCHAR pipe_id,
                                     PUCHAR buffer, ULONG buffer_length,
                                     PULONG length_transferred,
                                     LPOVERLAPPED overlapped);
extern __winfnc BOOL WinUsb_WritePipe(HANDLE interface_handle, UCHAR pipe_id,
                                      PUCHAR buffer, ULONG buffer_length,
                                      PULONG length_transferred,
                                      LPOVERLAPPED overlapped);

static unsigned char fake_handle_storage;
static unsigned char fake_device_storage;
static unsigned char fake_native_handle_storage;

#define FAKE_USB_HANDLE \
    ((libusb_device_handle *)(void *)&fake_handle_storage)
#define FAKE_USB_DEVICE ((libusb_device *)(void *)&fake_device_storage)
#define FAKE_NATIVE_HANDLE ((HANDLE)(void *)&fake_native_handle_storage)

static struct {
    int get_device;
    int get_descriptor;
    int get_configuration;
    int set_configuration;
    int claim_interface;
    int release_interface;
    int init;
    int get_device_list;
    int free_device_list;
    int open;
    int reset;
    int close;
    int exit;
    int bulk_transfer;
    int control_transfer;
} calls;

static uint16_t descriptor_vendor;
static uint16_t descriptor_product;
static int active_configuration;
static int claim_status;
static int sequence;
static int set_configuration_sequence;
static int claim_sequence;

static void reset_fakes(void)
{
    memset(&calls, 0, sizeof(calls));
    descriptor_vendor = 0x06cb;
    descriptor_product = 0x0081;
    active_configuration = 1;
    claim_status = LIBUSB_SUCCESS;
    sequence = 0;
    set_configuration_sequence = 0;
    claim_sequence = 0;
}

static void assert_no_discovery_or_owned_cleanup(void)
{
    assert(calls.init == 0);
    assert(calls.get_device_list == 0);
    assert(calls.free_device_list == 0);
    assert(calls.open == 0);
    assert(calls.reset == 0);
    assert(calls.close == 0);
    assert(calls.exit == 0);
}

libusb_device *LIBUSB_CALL
libusb_get_device(libusb_device_handle *handle)
{
    assert(handle == FAKE_USB_HANDLE);
    calls.get_device++;
    return FAKE_USB_DEVICE;
}

int LIBUSB_CALL
libusb_get_device_descriptor(libusb_device *device,
                             struct libusb_device_descriptor *descriptor)
{
    assert(device == FAKE_USB_DEVICE);
    calls.get_descriptor++;
    memset(descriptor, 0, sizeof(*descriptor));
    descriptor->idVendor = descriptor_vendor;
    descriptor->idProduct = descriptor_product;
    return LIBUSB_SUCCESS;
}

int LIBUSB_CALL
libusb_get_configuration(libusb_device_handle *handle, int *configuration)
{
    assert(handle == FAKE_USB_HANDLE);
    calls.get_configuration++;
    *configuration = active_configuration;
    return LIBUSB_SUCCESS;
}

int LIBUSB_CALL
libusb_set_configuration(libusb_device_handle *handle, int configuration)
{
    assert(handle == FAKE_USB_HANDLE);
    assert(configuration == 1);
    calls.set_configuration++;
    set_configuration_sequence = ++sequence;
    return LIBUSB_SUCCESS;
}

int LIBUSB_CALL
libusb_claim_interface(libusb_device_handle *handle, int interface_number)
{
    assert(handle == FAKE_USB_HANDLE);
    assert(interface_number == 0);
    calls.claim_interface++;
    claim_sequence = ++sequence;
    return claim_status;
}

int LIBUSB_CALL
libusb_release_interface(libusb_device_handle *handle, int interface_number)
{
    assert(handle == FAKE_USB_HANDLE);
    assert(interface_number == 0);
    calls.release_interface++;
    return LIBUSB_SUCCESS;
}

int LIBUSB_CALL
libusb_init(libusb_context **context)
{
    calls.init++;
    if(context) *context = NULL;
    return LIBUSB_ERROR_OTHER;
}

ssize_t LIBUSB_CALL
libusb_get_device_list(libusb_context *context, libusb_device ***list)
{
    (void)context;
    calls.get_device_list++;
    if(list) *list = NULL;
    return LIBUSB_ERROR_OTHER;
}

void LIBUSB_CALL
libusb_free_device_list(libusb_device **list, int unref_devices)
{
    (void)list;
    (void)unref_devices;
    calls.free_device_list++;
}

int LIBUSB_CALL
libusb_open(libusb_device *device, libusb_device_handle **handle)
{
    (void)device;
    calls.open++;
    if(handle) *handle = NULL;
    return LIBUSB_ERROR_OTHER;
}

int LIBUSB_CALL
libusb_reset_device(libusb_device_handle *handle)
{
    (void)handle;
    calls.reset++;
    return LIBUSB_ERROR_OTHER;
}

void LIBUSB_CALL
libusb_close(libusb_device_handle *handle)
{
    (void)handle;
    calls.close++;
}

void LIBUSB_CALL
libusb_exit(libusb_context *context)
{
    (void)context;
    calls.exit++;
}

const char *LIBUSB_CALL
libusb_error_name(int error_code)
{
    (void)error_code;
    return "fake libusb error";
}

int LIBUSB_CALL
libusb_bulk_transfer(libusb_device_handle *handle, unsigned char endpoint,
                     unsigned char *data, int length, int *transferred,
                     unsigned int timeout)
{
    assert(handle == FAKE_USB_HANDLE);
    assert(endpoint == 0x01 || endpoint == 0x81);
    assert(data != NULL);
    assert(length == 32);
    assert(timeout == 1000);
    calls.bulk_transfer++;

    if(endpoint == 0x81) memset(data, 0xa5, (size_t)length);
    *transferred = length;
    return LIBUSB_SUCCESS;
}

int LIBUSB_CALL
libusb_control_transfer(libusb_device_handle *handle, uint8_t request_type,
                        uint8_t request, uint16_t value, uint16_t index,
                        unsigned char *data, uint16_t length,
                        unsigned int timeout)
{
    assert(handle == FAKE_USB_HANDLE);
    assert(request_type == LIBUSB_ENDPOINT_IN);
    assert(request == LIBUSB_REQUEST_GET_DESCRIPTOR);
    assert(value == 0x0100);
    assert(index == 0);
    assert(data != NULL);
    assert(length == 32);
    assert(timeout == 1000);
    calls.control_transfer++;

    memset(data, 0x3c, length);
    return length;
}

static HANDLE initialize_borrowed(void)
{
    void *interface_handle = (void *)(uintptr_t)0x1;
    assert(WinUsb_Initialize(FAKE_NATIVE_HANDLE, &interface_handle) == TRUE);
    assert(interface_handle != NULL);
    return (HANDLE)interface_handle;
}

static void test_active_configuration(void)
{
    reset_fakes();
    HANDLE interface_handle = initialize_borrowed();

    assert(calls.get_device == 1);
    assert(calls.get_descriptor == 1);
    assert(calls.get_configuration == 1);
    assert(calls.set_configuration == 0);
    assert(calls.claim_interface == 1);
    assert_no_discovery_or_owned_cleanup();

    assert(WinUsb_Free(interface_handle) == TRUE);
    assert(calls.release_interface == 1);
    assert_no_discovery_or_owned_cleanup();
}

static void test_configuration_change(void)
{
    reset_fakes();
    active_configuration = 2;
    HANDLE interface_handle = initialize_borrowed();

    assert(calls.set_configuration == 1);
    assert(calls.claim_interface == 1);
    assert(set_configuration_sequence < claim_sequence);
    assert(WinUsb_Free(interface_handle) == TRUE);
    assert(calls.release_interface == 1);
    assert_no_discovery_or_owned_cleanup();
}

static void test_rejects_unexpected_device(void)
{
    reset_fakes();
    descriptor_product = 0x00be;
    void *interface_handle = (void *)(uintptr_t)0x1;

    assert(WinUsb_Initialize(FAKE_NATIVE_HANDLE, &interface_handle) == FALSE);
    assert(interface_handle == NULL);
    assert(calls.get_descriptor == 1);
    assert(calls.get_configuration == 0);
    assert(calls.claim_interface == 0);
    assert(calls.release_interface == 0);
    assert_no_discovery_or_owned_cleanup();
}

static void test_claim_failure(void)
{
    reset_fakes();
    claim_status = LIBUSB_ERROR_BUSY;
    void *interface_handle = (void *)(uintptr_t)0x1;

    assert(WinUsb_Initialize(FAKE_NATIVE_HANDLE, &interface_handle) == FALSE);
    assert(interface_handle == NULL);
    assert(calls.claim_interface == 1);
    assert(calls.release_interface == 0);
    assert_no_discovery_or_owned_cleanup();
}

struct pipe_io_context {
    HANDLE interface_handle;
    BOOL succeeded;
};

static void *run_pipe_io(void *opaque)
{
    struct pipe_io_context *context = opaque;
    unsigned char output[32];
    unsigned char input[32];
    ULONG transferred = 0;

    context->succeeded = WinUsb_GetDescriptor(context->interface_handle, 1, 0,
                                               0, input, sizeof(input),
                                               &transferred);
    if(!context->succeeded || transferred != sizeof(input)) return NULL;
    for(size_t i = 0; i < sizeof(input); i++) {
        if(input[i] != 0x3c) {
            context->succeeded = FALSE;
            return NULL;
        }
    }

    memset(output, 0x5a, sizeof(output));
    transferred = 0;
    context->succeeded = WinUsb_WritePipe(context->interface_handle, 0x01,
                                          output, sizeof(output),
                                          &transferred, NULL);
    if(!context->succeeded || transferred != sizeof(output)) return NULL;

    transferred = 0;
    context->succeeded = WinUsb_ReadPipe(context->interface_handle, 0x81,
                                         input, sizeof(input), &transferred,
                                         NULL);
    if(!context->succeeded || transferred != sizeof(input)) return NULL;

    for(size_t i = 0; i < sizeof(input); i++) {
        if(input[i] != 0xa5) {
            context->succeeded = FALSE;
            break;
        }
    }
    return NULL;
}

static void test_winusb_io_with_small_stack(void)
{
    reset_fakes();
    HANDLE interface_handle = initialize_borrowed();
    struct pipe_io_context context = {
        .interface_handle = interface_handle,
        .succeeded = FALSE,
    };
    pthread_attr_t attributes;
    pthread_t thread;

    assert(pthread_attr_init(&attributes) == 0);
    assert(pthread_attr_setstacksize(&attributes, 64U * 1024U) == 0);
    assert(pthread_create(&thread, &attributes, run_pipe_io, &context) == 0);
    assert(pthread_attr_destroy(&attributes) == 0);
    assert(pthread_join(thread, NULL) == 0);

    assert(context.succeeded == TRUE);
    assert(calls.bulk_transfer == 2);
    assert(calls.control_transfer == 1);
    assert(WinUsb_Free(interface_handle) == TRUE);
}

int main(void)
{
    tudor_set_usb_device(FAKE_USB_HANDLE);
    test_active_configuration();
    test_configuration_change();
    test_rejects_unexpected_device();
    test_claim_failure();
    test_winusb_io_with_small_stack();
    tudor_set_usb_device(NULL);
    return 0;
}
