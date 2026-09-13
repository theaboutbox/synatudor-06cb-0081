#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <gio/gunixfdmessage.h>
#include "../src/ipc.h"

struct result { gboolean done; IPCMessageBuf *msg; GError *error; };
static void received(GObject *source, GAsyncResult *async, gpointer opaque) {
    struct result *result = opaque;
    result->msg = g_task_propagate_pointer(G_TASK(async), &result->error);
    result->done = TRUE;
}

static void test_receive(gconstpointer opaque) {
    guint scenario = GPOINTER_TO_UINT(opaque);
    int pair[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair), ==, 0);
    GError *error = NULL;
    FpiDeviceTudor *tdev = g_object_new(FPI_TYPE_DEVICE_TUDOR, NULL);
    tdev->ipc_socket = g_socket_new_from_fd(pair[0], &error);
    g_assert_no_error(error);
    tdev->ipc_cancel = g_cancellable_new();
    tdev->host_has_id = TRUE;
    GSocket *host = g_socket_new_from_fd(pair[1], &error);
    g_assert_no_error(error);
    gsize size = scenario == 0 ? IPC_MAX_MESSAGE_SIZE + 1 : sizeof(enum ipc_msg_type);
    g_autofree guint8 *payload = g_malloc0(size);
    *(enum ipc_msg_type *)payload = IPC_MSG_ACK;
    GOutputVector vector = {payload, size};
    GSocketControlMessage *control = g_unix_fd_message_new();
    int source_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(source_fd, >=, 0);
    for(guint i = 0; i < (scenario == 1 ? 2 : 1); i++) {
        g_assert_true(g_unix_fd_message_append_fd(G_UNIX_FD_MESSAGE(control), source_fd, &error));
        g_assert_no_error(error);
    }
    struct result result = {0};
    recv_ipc_msg(tdev, received, &result);
    g_assert_cmpint(g_socket_send_message(host, NULL, &vector, 1, &control, 1, 0, NULL, &error), ==, size);
    g_assert_no_error(error);
    g_object_unref(control);
    close(source_fd);
    while(!result.done) g_main_context_iteration(NULL, TRUE);
    if(scenario < 2) {
        g_assert_null(result.msg);
        g_assert_error(result.error, FP_DEVICE_ERROR, FP_DEVICE_ERROR_PROTO);
        g_clear_error(&result.error);
    } else {
        g_assert_no_error(result.error);
        g_assert_nonnull(result.msg);
        g_assert_cmpint(fcntl(result.msg->transfer_fd, F_GETFD), >=, 0);
        ipc_msg_buf_free(result.msg);
    }
    tdev->host_has_id = FALSE;
    g_clear_object(&tdev->ipc_socket);
    g_clear_object(&tdev->ipc_cancel);
    g_object_unref(tdev);
    g_object_unref(host);
}

static void test_send(void) {
    int pair[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair), ==, 0);
    GError *error = NULL;
    FpiDeviceTudor *tdev = g_object_new(FPI_TYPE_DEVICE_TUDOR, NULL);
    tdev->ipc_socket = g_socket_new_from_fd(pair[0], &error);
    g_assert_no_error(error);
    tdev->ipc_cancel = g_cancellable_new();
    tdev->host_has_id = TRUE;
    tdev->usb_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    g_assert_cmpint(tdev->usb_fd, >=, 0);
    IPCMessageBuf *msg = ipc_msg_buf_new();
    msg->type = IPC_MSG_ACK;
    msg->size = sizeof(msg->type);
    for(guint i = 0; i < 2; i++) {
        int transferred = dup(tdev->usb_fd);
        msg->transfer_fd = transferred;
        if(i) g_cancellable_cancel(tdev->ipc_cancel);
        g_assert_cmpint(send_ipc_msg(tdev, msg, &error), ==, i == 0);
        if(i) {
            g_assert_error(error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
            g_clear_error(&error);
        } else g_assert_no_error(error);
        g_assert_cmpint(msg->transfer_fd, ==, -1);
        g_assert_cmpint(fcntl(transferred, F_GETFD), ==, -1);
        g_assert_cmpint(errno, ==, EBADF);
        g_assert_cmpint(fcntl(tdev->usb_fd, F_GETFD), >=, 0);
    }
    ipc_msg_buf_free(msg);
    tdev->host_has_id = FALSE;
    g_clear_object(&tdev->ipc_socket);
    g_clear_object(&tdev->ipc_cancel);
    g_object_unref(tdev);
    close(pair[1]);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_data_func("/ipc/truncated", GUINT_TO_POINTER(0), test_receive);
    g_test_add_data_func("/ipc/extra-fds", GUINT_TO_POINTER(1), test_receive);
    g_test_add_data_func("/ipc/single-fd", GUINT_TO_POINTER(2), test_receive);
    g_test_add_func("/ipc/send-ownership", test_send);
    return g_test_run();
}
