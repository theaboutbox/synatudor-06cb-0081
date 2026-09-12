#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "handler.h"

pthread_mutex_t LOG_LOCK = PTHREAD_MUTEX_INITIALIZER;
enum log_level LOG_LEVEL = LOG_ERROR;

static _Atomic bool native_storage = true;
static unsigned int wipe_calls;
static unsigned int add_calls;
static unsigned int enroll_commit_calls;
static RECGUID *last_wipe_guid;
static enum tudor_finger last_wipe_finger;
static tudor_async_cb_fnc *pending_callback;
static void *pending_context;
static tudor_async_res_t pending_result =
    (tudor_async_res_t) (uintptr_t) 0x1234;

bool tudor_uses_native_storage(struct tudor_device *device) {
    (void) device;
    return native_storage;
}

int tudor_wipe_records(struct tudor_device *device, RECGUID *guid,
                       enum tudor_finger finger) {
    (void) device;
    wipe_calls++;
    last_wipe_guid = guid;
    last_wipe_finger = finger;
    return 1;
}

bool tudor_add_record(struct tudor_device *device, RECGUID guid,
                      enum tudor_finger finger, const void *data,
                      size_t data_size) {
    (void) device;
    (void) guid;
    (void) finger;
    (void) data;
    (void) data_size;
    add_calls++;
    return true;
}

bool tudor_enroll_start(struct tudor_device *device, RECGUID guid,
                        enum tudor_finger finger) {
    (void) device;
    (void) guid;
    (void) finger;
    return true;
}

bool tudor_enroll_capture(struct tudor_device *device, bool *done,
                          tudor_async_res_t *result) {
    (void) device;
    *done = true;
    *result = pending_result;
    return true;
}

bool tudor_enroll_commit(struct tudor_device *device, bool *is_duplicate) {
    (void) device;
    enroll_commit_calls++;
    *is_duplicate = false;
    return true;
}

bool tudor_enroll_discard(struct tudor_device *device) {
    (void) device;
    return true;
}

void tudor_set_async_callback(tudor_async_res_t result,
                              tudor_async_cb_fnc *callback, void *context) {
    assert(result == pending_result);
    pending_callback = callback;
    pending_context = context;
}

void tudor_cleanup_async(tudor_async_res_t result) {
    assert(result == pending_result);
}

void tudor_cancel_async(tudor_async_res_t result) {
    (void) result;
    assert(false);
}

bool tudor_verify(struct tudor_device *device, RECGUID guid,
                  enum tudor_finger finger, bool *retry, bool *matches,
                  tudor_async_res_t *result) {
    (void) device;
    (void) guid;
    (void) finger;
    (void) retry;
    (void) matches;
    (void) result;
    assert(false);
    return false;
}

bool tudor_identify(struct tudor_device *device, bool *retry,
                    bool *found_match, RECGUID *guid,
                    enum tudor_finger *finger, tudor_async_res_t *result) {
    (void) device;
    (void) retry;
    (void) found_match;
    (void) guid;
    (void) finger;
    (void) result;
    assert(false);
    return false;
}

static void *handler_thread(void *arg) {
    int socket = *(int *) arg;
    struct tudor_device device;
    memset(&device, 0, sizeof(device));
    run_handler_loop(&device, socket);
    return NULL;
}

static void send_packet(int socket, const void *packet, size_t size) {
    assert(send(socket, packet, size, 0) == (ssize_t) size);
}

static void expect_ack(int socket) {
    enum ipc_msg_type response = IPC_MSG_INIT;
    assert(recv(socket, &response, sizeof(response), 0) == sizeof(response));
    assert(response == IPC_MSG_ACK);
}

int main(void) {
    int sockets[2];
    pthread_t thread;

    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, sockets) == 0);
    assert(pthread_create(&thread, NULL, handler_thread, &sockets[1]) == 0);

    /* Restoring libfprint metadata must not insert a second host record when
     * the sensor owns the enrolled template. */
    const struct ipc_msg_add_record add = {
        .type = IPC_MSG_ADD_RECORD,
        .guid = {.PartA = 0x2195dc59},
        .finger = TUDOR_FINGER_RH_INDEX_FINGER,
    };
    send_packet(sockets[0], &add, sizeof(add));
    expect_ack(sockets[0]);
    assert(add_calls == 0);
    assert(wipe_calls == 0);

    /* Orphaning a host is transient cleanup and must leave native templates
     * alone.  The explicit clear command must still reach sensor storage. */
    enum ipc_msg_type message = IPC_MSG_CLEAR_HOST_RECORDS;
    send_packet(sockets[0], &message, sizeof(message));
    expect_ack(sockets[0]);
    assert(wipe_calls == 0);

    message = IPC_MSG_CLEAR_RECORDS;
    send_packet(sockets[0], &message, sizeof(message));
    expect_ack(sockets[0]);
    assert(wipe_calls == 1);
    assert(last_wipe_guid == NULL);
    assert(last_wipe_finger == TUDOR_FINGER_ANY);

    native_storage = false;
    message = IPC_MSG_CLEAR_HOST_RECORDS;
    send_packet(sockets[0], &message, sizeof(message));
    expect_ack(sockets[0]);
    assert(wipe_calls == 2);
    assert(last_wipe_guid == NULL);
    assert(last_wipe_finger == TUDOR_FINGER_ANY);

    /* A completed match-on-chip enrollment returns only GUID/finger metadata:
     * the response has no trailing host template bytes. */
    native_storage = true;
    const struct ipc_msg_enroll enroll = {
        .type = IPC_MSG_ENROLL,
        .guid = {.PartA = 0x10203040},
        .finger = TUDOR_FINGER_RH_INDEX_FINGER,
    };
    send_packet(sockets[0], &enroll, sizeof(enroll));
    expect_ack(sockets[0]);
    assert(pending_callback);
    pending_callback(pending_result, true, pending_context);

    struct ipc_msg_resp_enroll enroll_response;
    ssize_t response_size = recv(sockets[0], &enroll_response,
                                 sizeof(enroll_response), MSG_TRUNC);
    assert(response_size == sizeof(enroll_response));
    assert(enroll_response.type == IPC_MSG_RESP_ENROLL);
    assert(!enroll_response.retry);
    assert(enroll_response.done);
    assert(enroll_commit_calls == 1);
    assert(add_calls == 0);

    message = IPC_MSG_SHUTDOWN;
    send_packet(sockets[0], &message, sizeof(message));
    assert(pthread_join(thread, NULL) == 0);
    close(sockets[1]);
    close(sockets[0]);
    return 0;
}
