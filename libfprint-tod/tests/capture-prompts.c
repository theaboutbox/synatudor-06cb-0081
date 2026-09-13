#include <errno.h>
#include <sys/socket.h>
#include "../src/ipc.h"

/* Exercise production IPC callbacks with a socket-backed host. Intercept
 * libfprint reports so the fixture can count user-visible results without
 * needing a USB device or an active libfprint authentication session. */
static guint reports, completions, registrations, prompts;
static GError *completion_error;
static FpiMatchResult match_result;
static gboolean scan_retry;

static void fixture_register(FpiDeviceTudor *tdev) {
    registrations++;
    tdev->cancel_handler_id = 1;
    tdev->has_canceled = false;
}
static void fixture_unregister(FpiDeviceTudor *tdev) {
    tdev->cancel_handler_id = 0;
}
static gboolean fixture_prompt(FpDevice *dev, FpFingerStatusFlags added,
                                FpFingerStatusFlags removed) {
    prompts++;
    return TRUE;
}
static void fixture_complete(FpDevice *dev, GError *error) {
    completions++;
    completion_error = error;
}
static void fixture_verify_report(FpDevice *dev, FpiMatchResult result,
                                  FpPrint *print, GError *error) {
    reports++;
    match_result = result;
    scan_retry = error && error->domain == FP_DEVICE_RETRY;
    g_clear_error(&error);
}
static void fixture_identify_report(FpDevice *dev, FpPrint *match,
                                    FpPrint *print, GError *error) {
    fixture_verify_report(dev, match ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL,
                          print, error);
}

#define register_cancel_handler fixture_register
#define unregister_cancel_handler fixture_unregister
#define fpi_device_report_finger_status_changes fixture_prompt
#define fpi_device_verify_report fixture_verify_report
#define fpi_device_identify_report fixture_identify_report
#define fpi_device_verify_complete fixture_complete
#define fpi_device_identify_complete fixture_complete
#include "../src/verify.c"
#include "../src/identify.c"

static void settle(void) {
    gint64 deadline = g_get_monotonic_time() + 20 * 1000;
    while(g_get_monotonic_time() < deadline) {
        g_main_context_iteration(NULL, FALSE);
        g_usleep(100);
    }
}

static void send_packet(int host, const void *packet, size_t size) {
    g_assert_cmpint(send(host, packet, size, 0), ==, size);
    settle();
}

static void expect_request(int host, gboolean identify) {
    struct ipc_msg_verify msg;
    ssize_t size = recv(host, &msg, sizeof(msg), MSG_DONTWAIT);
    g_assert_cmpint(size, ==, identify ? sizeof(enum ipc_msg_type) : sizeof(msg));
    g_assert_cmpint(msg.type, ==, identify ? IPC_MSG_IDENTIFY : IPC_MSG_VERIFY);
    if(!identify) {
        g_assert_cmpuint(msg.guid.PartA, ==, 42);
        g_assert_cmpint(msg.finger, ==, TUDOR_FINGER_RH_INDEX_FINGER);
    }
}

static void send_result(int host, gboolean identify, guint8 retry,
                        gboolean match) {
    if(identify) {
        struct ipc_msg_resp_identify msg = {
            .type = IPC_MSG_RESP_IDENTIFY, .retry = retry, .did_match = match,
            .guid = {.PartA = 42}, .finger = TUDOR_FINGER_RH_INDEX_FINGER,
        };
        send_packet(host, &msg, sizeof(msg));
    } else {
        struct ipc_msg_resp_verify msg = {
            .type = IPC_MSG_RESP_VERIFY, .retry = retry, .did_match = match,
        };
        send_packet(host, &msg, sizeof(msg));
    }
}

enum ending { MATCH, NO_MATCH, BAD_SCAN, CANCEL_BEFORE_RESTART, CANCEL_BEFORE_ACK };

static void run_case(gconstpointer data) {
    guint scenario = GPOINTER_TO_UINT(data);
    gboolean identify = scenario / 5;
    enum ending ending = scenario % 5;
    int pair[2];
    GError *error = NULL;
    reports = completions = registrations = prompts = 0;
    scan_retry = FALSE;
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair), ==, 0);
    FpiDeviceTudor *tdev = g_object_new(FPI_TYPE_DEVICE_TUDOR, NULL);
    tdev->ipc_socket = g_socket_new_from_fd(pair[0], &error);
    g_assert_no_error(error);
    tdev->ipc_cancel = g_cancellable_new();
    tdev->host_has_id = TRUE;

    if(identify) {
        struct identify_params *params = g_slice_new0(struct identify_params);
        params->tdev = tdev;
        params->prints = g_array_new(FALSE, FALSE, sizeof(struct identify_print));
        g_array_set_clear_func(params->prints, (GDestroyNotify) clear_identify_print);
        struct identify_print print = {.print = fp_print_new(FP_DEVICE(tdev))};
        print.record = new_record((RECGUID) {.PartA = 42},
                                  TUDOR_FINGER_RH_INDEX_FINGER,
                                  g_bytes_new(NULL, 0), print.print);
        g_array_append_val(params->prints, print);
        start_identify_capture(params);
    } else {
        struct verify_params *params = g_slice_new0(struct verify_params);
        params->tdev = tdev;
        params->guid.PartA = 42;
        params->finger = TUDOR_FINGER_RH_INDEX_FINGER;
        start_verify_capture(params);
    }
    enum ipc_msg_type ack = IPC_MSG_ACK;
    expect_request(pair[1], identify);
    send_packet(pair[1], &ack, sizeof(ack));

    /* An arbitrarily long sequence must not finish/restart the public action,
     * re-register cancellation, or emit more finger-needed/retry prompts. */
    for(guint i = 0; i < 25; i++) {
        send_result(pair[1], identify, TUDOR_RETRY_CAPTURE_RESTART, FALSE);
        expect_request(pair[1], identify);
        send_packet(pair[1], &ack, sizeof(ack));
        g_assert_cmpuint(reports, ==, 0);
        g_assert_cmpuint(completions, ==, 0);
        g_assert_cmpuint(registrations, ==, 1);
        g_assert_cmpuint(prompts, ==, 1);
    }

    if(ending == CANCEL_BEFORE_RESTART || ending == CANCEL_BEFORE_ACK) {
        if(ending == CANCEL_BEFORE_RESTART) tdev->has_canceled = TRUE;
        send_result(pair[1], identify, TUDOR_RETRY_CAPTURE_RESTART, FALSE);
        if(ending == CANCEL_BEFORE_ACK) {
            expect_request(pair[1], identify);
            tdev->has_canceled = TRUE;
            send_packet(pair[1], &ack, sizeof(ack));
            g_assert_true(tdev->has_canceled);
        }
        /* Model the host ACK for cancellation, including a PAM timeout. */
        send_packet(pair[1], &ack, sizeof(ack));
        g_assert_error(completion_error, G_IO_ERROR, G_IO_ERROR_CANCELLED);
        g_clear_error(&completion_error);
        g_assert_cmpuint(reports, ==, 0);
    } else {
        send_result(pair[1], identify,
                    ending == BAD_SCAN ? TUDOR_RETRY_SCAN : TUDOR_RETRY_NONE,
                    ending == MATCH);
        g_assert_no_error(completion_error);
        g_assert_cmpuint(reports, ==, 1);
        g_assert_cmpint(scan_retry, ==, ending == BAD_SCAN);
        if(ending != BAD_SCAN || !identify)
            g_assert_cmpint(match_result, ==, ending == BAD_SCAN ? FPI_MATCH_ERROR :
                            ending == MATCH ? FPI_MATCH_SUCCESS : FPI_MATCH_FAIL);
    }
    g_assert_cmpuint(completions, ==, 1);
    g_assert_cmpuint(registrations, ==, 1);
    g_assert_cmpuint(prompts, ==, 1);
    g_assert_cmpuint(tdev->cancel_handler_id, ==, 0);
    char extra;
    g_assert_cmpint(recv(pair[1], &extra, 1, MSG_DONTWAIT), ==, -1);
    g_assert_cmpint(errno, ==, EAGAIN);
    tdev->host_has_id = FALSE;
    g_clear_object(&tdev->ipc_socket);
    g_clear_object(&tdev->ipc_cancel);
    g_object_unref(tdev);
    close(pair[1]);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    const char *names[] = { "match", "no-match", "bad-scan", "cancel-before-restart", "cancel-before-ack" };
    for(guint i = 0; i < 10; i++) {
        gchar *path = g_strdup_printf("/capture-prompts/%s/%s", i / 5 ? "identify" : "verify", names[i % 5]);
        g_test_add_data_func(path, GUINT_TO_POINTER(i), run_case);
        g_free(path);
    }
    return g_test_run();
}
