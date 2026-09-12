#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <stdatomic.h>

#include <tudor/log.h>
#include <tudor/libcrypto.h>
#include <tudor/tudor.h>
#include <tudor/state-proto.h>
#include "sandbox.h"
#include "ipc.h"
#include "handler.h"

static pthread_t usb_thread;
static atomic_bool usb_thread_exit = false;

static void *usb_thread_func(void *arg) {
    //Polling loop
    while(!atomic_load_explicit(&usb_thread_exit, memory_order_relaxed)) {
        int usb_err;
        if((usb_err = libusb_handle_events((libusb_context*) arg)) != 0) {
            if(atomic_load_explicit(&usb_thread_exit, memory_order_relaxed))
                break;
            int err = errno;
            log_warn("Error in USB polling thread: %d [%s] (errno %d [%s])", usb_err, libusb_error_name(usb_err), err, strerror(err));
        }
    }

    return NULL;
}

static char state_id[TUDOR_STATE_ID_SIZE + 1];
static pthread_mutex_t state_ipc_lock = PTHREAD_MUTEX_INITIALIZER;

static bool valid_state_id(const char *id) {
    size_t len = strnlen(id, TUDOR_STATE_ID_SIZE + 1);
    if(!len || len > TUDOR_STATE_ID_SIZE) return false;
    for(size_t i = 0; i < len; i++) {
        unsigned char c = id[i];
        if(!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
             (c >= '0' && c <= '9') || c == '-'))
            return false;
    }
    return true;
}

static void state_send_packet(const void *buf, size_t size) {
    ssize_t written = write(TUDOR_STATE_SOCKET_FD, buf, size);
    if(written < 0) abort_perror("Failed to send device-state request");
    if((size_t) written != size) {
        log_error("Truncated device-state request");
        abort();
    }
}

static size_t state_recv_packet(void *buf, uint32_t expected_type,
                                size_t min_size, size_t max_size) {
    ssize_t size = read(TUDOR_STATE_SOCKET_FD, buf, max_size);
    if(size < 0) abort_perror("Failed to receive device-state response");
    if((size_t) size < min_size) {
        log_error("Truncated device-state response");
        abort();
    }
    uint32_t type;
    memcpy(&type, buf, sizeof(type));
    if(type != expected_type) {
        log_error("Unexpected device-state response 0x%x (expected 0x%x)",
                  type, expected_type);
        abort();
    }
    return size;
}

static bool get_state_cb(const char *name, enum tudor_state_value_type *type,
                         void **data, size_t *data_size) {
    struct tudor_state_load_request req = {
        .type = TUDOR_STATE_MSG_LOAD,
        .state_id = {0},
        .name = {0}
    };
    strncpy(req.state_id, state_id, TUDOR_STATE_ID_SIZE);
    strncpy(req.name, name, TUDOR_STATE_PROPERTY_NAME_SIZE);

    void *buf = malloc(TUDOR_STATE_MAX_MESSAGE_SIZE);
    if(!buf) abort_perror("Couldn't allocate state response buffer");

    cant_fail_ret(pthread_mutex_lock(&state_ipc_lock));
    state_send_packet(&req, sizeof(req));
    size_t size = state_recv_packet(
        buf, TUDOR_STATE_MSG_LOAD_RESPONSE,
        sizeof(struct tudor_state_load_response),
        TUDOR_STATE_MAX_MESSAGE_SIZE);
    cant_fail_ret(pthread_mutex_unlock(&state_ipc_lock));

    struct tudor_state_load_response *resp =
        (struct tudor_state_load_response*) buf;
    if(resp->status != 0) {
        log_error("State launcher failed to load '%s' [status %d]",
                  name, resp->status);
        free(buf);
        abort();
    }
    if(!resp->found) {
        free(buf);
        return false;
    }

    size_t value_size = size - sizeof(*resp);
    if((resp->value_type != TUDOR_STATE_VALUE_UINT32 &&
        resp->value_type != TUDOR_STATE_VALUE_BLOB &&
        resp->value_type != TUDOR_STATE_VALUE_BOOL) ||
       (resp->value_type == TUDOR_STATE_VALUE_UINT32 &&
        value_size != sizeof(uint32_t)) ||
       (resp->value_type == TUDOR_STATE_VALUE_BOOL &&
        (value_size != sizeof(uint8_t) || resp->data[0] > 1))) {
        log_error("State launcher returned an invalid value for '%s'", name);
        free(buf);
        abort();
    }

    void *value = value_size ? malloc(value_size) : NULL;
    if(value_size && !value)
        abort_perror("Couldn't allocate device-state value");
    if(value_size) memcpy(value, resp->data, value_size);
    *type = (enum tudor_state_value_type) resp->value_type;
    *data = value;
    *data_size = value_size;
    free(buf);
    return true;
}

static void set_state_cb(const char *name, enum tudor_state_value_type type,
                         const void *data, size_t data_size) {
    if(data_size > TUDOR_STATE_MAX_VALUE_SIZE) {
        log_error("Device-state value '%s' exceeds the maximum size", name);
        abort();
    }

    size_t req_size = sizeof(struct tudor_state_store_request) + data_size;
    struct tudor_state_store_request *req =
        (struct tudor_state_store_request*) calloc(1, req_size);
    if(!req) abort_perror("Couldn't allocate state request buffer");
    req->type = TUDOR_STATE_MSG_STORE;
    strncpy(req->state_id, state_id, TUDOR_STATE_ID_SIZE);
    strncpy(req->name, name, TUDOR_STATE_PROPERTY_NAME_SIZE);
    req->value_type = type;
    if(data_size) memcpy(req->data, data, data_size);

    struct tudor_state_store_response resp;
    cant_fail_ret(pthread_mutex_lock(&state_ipc_lock));
    state_send_packet(req, req_size);
    state_recv_packet(&resp, TUDOR_STATE_MSG_STORE_RESPONSE,
                      sizeof(resp), sizeof(resp));
    cant_fail_ret(pthread_mutex_unlock(&state_ipc_lock));
    free(req);

    if(resp.status != 0) {
        log_error("State launcher failed to store '%s' [status %d]",
                  name, resp.status);
        abort();
    }
}

static void recv_init_msg(int sock, int *usb_dev_fd, uint8_t *usb_bus,
                          uint8_t *usb_addr) {
    struct ipc_msg_init init_msg;
    ipc_recv_msg(sock, &init_msg, IPC_MSG_INIT, sizeof(init_msg), sizeof(init_msg), usb_dev_fd);

    LOG_LEVEL = init_msg.log_level;
    *usb_bus = init_msg.usb_bus;
    *usb_addr = init_msg.usb_addr;
    init_msg.state_id[TUDOR_STATE_ID_SIZE] = 0;
    if(!valid_state_id(init_msg.state_id)) {
        log_error("Received invalid device-state ID");
        abort();
    }
    strcpy(state_id, init_msg.state_id);

    switch(LOG_LEVEL) {
        case LOG_VERBOSE:
        case LOG_DEBUG:
            setenv("LIBUSB_DEBUG", "1", 1);
            libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_DEBUG);
        break;
        case LOG_INFO: libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_INFO); break;
        case LOG_WARN: libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_WARNING); break;
        case LOG_ERROR: libusb_set_option(NULL, LIBUSB_OPTION_LOG_LEVEL, LIBUSB_LOG_LEVEL_ERROR); break;
    }
}

static bool has_sensor_name;
static int pdata_ipc_sock;
static const struct tudor_pair_data *get_pdata_cb(const char *name) {
    log_info("Getting pairing data for sensor '%s'...", name);

    //Send an IPC message to the module
    struct ipc_msg_load_pdata msg = { .type = IPC_MSG_LOAD_PDATA, .sensor_name = {0} };
    strncpy(msg.sensor_name, name, IPC_SENSOR_NAME_SIZE);
    ipc_send_msg(pdata_ipc_sock, &msg, sizeof(msg));

    if(has_sensor_name && strcmp(name, probe_sensor_name) != 0){
        log_error("Attempted multiple different sensor pairing data loads!");
        abort();
    } else if(!has_sensor_name) {
        strncpy(probe_sensor_name, name, IPC_SENSOR_NAME_SIZE);
        has_sensor_name = true;
    }

    //Receive the response
    struct {
        struct ipc_msg_resp_load_pdata msg;
        char buf[IPC_MAX_PDATA_SIZE];
    } resp;
    size_t pdata_sz = ipc_recv_msg(pdata_ipc_sock, &resp, IPC_MSG_RESP_LOAD_PDATA, sizeof(resp.msg), sizeof(resp), NULL) - sizeof(resp.msg);

    //Leak the pairing data buffer ¯\_(ツ)_/¯
    struct tudor_pair_data *pdata = (struct tudor_pair_data*) malloc(sizeof(struct tudor_pair_data) + pdata_sz);
    if(!pdata) {
        perror("Couldn't allocate pairing data buffer");
        abort();
    }
    pdata->data = pdata+1;
    pdata->data_size = pdata_sz;
    memcpy(pdata->data, resp.msg.pdata, pdata->data_size);

    return pdata;
}

static void set_pdata_cb(const char *name, const struct tudor_pair_data *data) {
    if(data->data_size > IPC_MAX_PDATA_SIZE) {
        log_error("Pairing data over maximum size!");
        abort();
    }
    log_info("Setting pairing data for sensor '%s'...", name);

    //Send an IPC message to the module
    struct {
        struct ipc_msg_store_pdata msg;
        char buf[IPC_MAX_PDATA_SIZE];
    } msg = { .msg.type = IPC_MSG_STORE_PDATA, .msg.sensor_name = {0} };
    strncpy(msg.msg.sensor_name, name, IPC_SENSOR_NAME_SIZE);
    memcpy(msg.msg.pdata, data->data, data->data_size);
    ipc_send_msg(pdata_ipc_sock, &msg, sizeof(msg.msg) + data->data_size);

    //Wait for ACK
    enum ipc_msg_type resp;
    ipc_recv_msg(pdata_ipc_sock, &resp, IPC_MSG_ACK, sizeof(resp), sizeof(resp), NULL);
}

int main() {
    //Configure stdout/stderr buffering
    cant_fail(setvbuf(stdout, NULL, _IOLBF, 1024));
    cant_fail(setvbuf(stderr, NULL, _IOLBF, 1024));

    //Check if stdin is a UNIX socket
    struct stat stdin_stat;
    cant_fail(fstat(STDIN_FILENO, &stdin_stat));
    if(!S_ISSOCK(stdin_stat.st_mode)) {
        fputs("This program isn't intended to be executed directly.\n", stderr);
        return EXIT_FAILURE;
    }

    int stdin_dom;
    socklen_t stdin_dom_sz = sizeof(stdin_dom);
    cant_fail(getsockopt(STDIN_FILENO, SOL_SOCKET, SO_DOMAIN, &stdin_dom, &stdin_dom_sz));
    if(stdin_dom != AF_UNIX) {
        log_error("The given socket isn't a UNIX socket!");
        return EXIT_FAILURE;
    }
    int sock = STDIN_FILENO;

    //Validate the dedicated state channel before activating the sandbox.
    int state_sock_type;
    socklen_t state_sock_type_size = sizeof(state_sock_type);
    cant_fail(getsockopt(TUDOR_STATE_SOCKET_FD, SOL_SOCKET, SO_TYPE,
                         &state_sock_type, &state_sock_type_size));
    if(state_sock_type != SOCK_SEQPACKET) {
        log_error("The device-state descriptor isn't a sequenced-packet socket!");
        return EXIT_FAILURE;
    }

    //Activate sandbox
    activate_sandbox();
    log_info("Activated sandbox");

    //Receive the init message
    int usb_dev_fd;
    uint8_t usb_bus, usb_addr;
    recv_init_msg(sock, &usb_dev_fd, &usb_bus, &usb_addr);
    setup_usb_sbox(usb_dev_fd, usb_bus, usb_addr);
    log_info("Received init message - USB device %hhd-%hhd", usb_bus, usb_addr);

    //Initialize libcrypto
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    log_info("Initialized libcrypto");

    //Initialize libusb
    int usb_err;
    if((usb_err = libusb_set_option(NULL, LIBUSB_OPTION_NO_DEVICE_DISCOVERY, true)) != 0) {
        int err = errno;
        log_error("Error disabling libusb device discovery: %d [%s] (errno %d [%s])", usb_err, libusb_error_name(usb_err), err, strerror(err));
        return EXIT_FAILURE;
    }

    libusb_context *usb_ctx;
    if((usb_err = libusb_init(&usb_ctx)) != 0) {
        int err = errno;
        log_error("Error initializing libusb: %d [%s] (errno %d [%s])", usb_err, libusb_error_name(usb_err), err, strerror(err));
        return EXIT_FAILURE;
    }
    log_info("Initialized libusb");

    //Wrap the device before driver initialization. The vendor driver invokes
    //WinUsb_Initialize from OnPrepareHardware during tudor_init().
    libusb_device_handle *usb_dev;
    if((usb_err = libusb_wrap_sys_device(usb_ctx, usb_dev_fd, &usb_dev)) < 0) {
        int err = errno;
        log_error("Error opening USB device: %d [%s] (errno %d [%s])", usb_err, libusb_error_name(usb_err), err, strerror(err));
        return EXIT_FAILURE;
    }
    tudor_set_usb_device(usb_dev);
    log_info("Opened USB device");

    //Start the USB thread
    cant_fail_ret(pthread_create(&usb_thread, NULL, usb_thread_func, usb_ctx));
    log_debug("Started USB polling thread");

    //Initialize driver
    tudor_get_pdata_fnc = get_pdata_cb;
    tudor_set_pdata_fnc = set_pdata_cb;
    tudor_get_state_fnc = get_state_cb;
    tudor_set_state_fnc = set_state_cb;
    pdata_ipc_sock = sock;
    if(!tudor_init()) {
        log_error("Couldn't initialize tudor driver!");
        return EXIT_FAILURE;
    }
    log_info("Initialized tudor driver");

    //Open device
    struct tudor_device dev;
    struct tudor_device_state state = {0};
    if(!tudor_open(&dev, usb_dev, &state)) {
        log_error("Couldn't open tudor device!");
        return EXIT_FAILURE;
    }
    log_info("Opened tudor device");

    //Older sensors expose a registry pairing-data key whose value name also
    //serves as the probe identity.  The 0081 keeps its identity on-sensor and
    //never touches that key, so use the stable USB-derived state ID instead.
    if(!has_sensor_name) {
        strncpy(probe_sensor_name, state_id, IPC_SENSOR_NAME_SIZE);
        probe_sensor_name[IPC_SENSOR_NAME_SIZE] = 0;
        log_info("Sensor did not request host pairing data; using state ID "
                 "'%s' as its probe identity", probe_sensor_name);
    }

    //Send ready message
    enum ipc_msg_type ready_type = IPC_MSG_READY;
    ipc_send_msg(sock, &ready_type, sizeof(ready_type));
    log_info("Sent ready message");

    //Enter handler loop
    run_handler_loop(&dev, sock);

    //Close device
    if(!tudor_close(&dev)) {
        log_error("Couldn't close tudor device!");
    }
    log_info("Closed tudor device");

    //Shutdown tudor driver
    if(!tudor_shutdown()) {
        log_error("Couldn't shutdown tudor driver!");
        return EXIT_FAILURE;
    }
    tudor_get_state_fnc = NULL;
    tudor_set_state_fnc = NULL;
    tudor_set_usb_device(NULL);
    log_info("Shutdown tudor driver");

    //Stop event handling before releasing any resource it can observe.
    atomic_store_explicit(&usb_thread_exit, true, memory_order_relaxed);
    libusb_interrupt_event_handler(usb_ctx);
    cant_fail_ret(pthread_join(usb_thread, NULL));

    //libusb_wrap_sys_device borrows the OS descriptor; close both objects.
    libusb_close(usb_dev);
    cant_fail(close(usb_dev_fd));
    libusb_exit(usb_ctx);
    log_info("Shutdown libusb");

    return EXIT_SUCCESS;
}
