#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gio/gio.h>
#include <glib/gstdio.h>
#include <tudor/state-proto.h>

#include "state.h"

static const char state_id[] = "06cb-0081-testdevice";

static void dispatch_request(void) {
    g_assert_true(g_main_context_iteration(NULL, TRUE));
}

static int32_t send_store_status(int fd, const char *name,
                                 enum tudor_state_value_type type,
                                 const void *data, size_t data_size) {
    size_t size = sizeof(struct tudor_state_store_request) + data_size;
    struct tudor_state_store_request *req = g_malloc0(size);
    req->type = TUDOR_STATE_MSG_STORE;
    g_strlcpy(req->state_id, state_id, sizeof(req->state_id));
    g_strlcpy(req->name, name, sizeof(req->name));
    req->value_type = type;
    if(data_size) memcpy(req->data, data, data_size);

    g_assert_cmpint(write(fd, req, size), ==, (ssize_t) size);
    g_free(req);
    dispatch_request();

    struct tudor_state_store_response resp;
    g_assert_cmpint(read(fd, &resp, sizeof(resp)), ==, sizeof(resp));
    g_assert_cmphex(resp.type, ==, TUDOR_STATE_MSG_STORE_RESPONSE);
    return resp.status;
}

static void send_store(int fd, const char *name,
                       enum tudor_state_value_type type,
                       const void *data, size_t data_size) {
    g_assert_cmpint(send_store_status(fd, name, type, data, data_size), ==, 0);
}

static GByteArray *send_load(int fd, const char *name,
                             enum tudor_state_value_type expected_type) {
    struct tudor_state_load_request req = {
        .type = TUDOR_STATE_MSG_LOAD,
        .state_id = {0},
        .name = {0}
    };
    g_strlcpy(req.state_id, state_id, sizeof(req.state_id));
    g_strlcpy(req.name, name, sizeof(req.name));
    ssize_t sent = write(fd, &req, sizeof(req));
    if(sent < 0) g_error("Failed to send load for %s: %s", name,
                         g_strerror(errno));
    g_assert_cmpint(sent, ==, sizeof(req));
    dispatch_request();

    guint8 buf[TUDOR_STATE_MAX_MESSAGE_SIZE];
    ssize_t size = read(fd, buf, sizeof(buf));
    g_assert_cmpint(size, >=, sizeof(struct tudor_state_load_response));
    struct tudor_state_load_response *resp =
        (struct tudor_state_load_response*) buf;
    g_assert_cmphex(resp->type, ==, TUDOR_STATE_MSG_LOAD_RESPONSE);
    g_assert_cmpint(resp->status, ==, 0);
    g_assert_cmpuint(resp->found, ==, TRUE);
    g_assert_cmpuint(resp->value_type, ==, expected_type);

    return g_byte_array_new_take(
        g_memdup2(resp->data, size - sizeof(*resp)),
        size - sizeof(*resp));
}

static void assert_load_missing(int fd, const char *name) {
    struct tudor_state_load_request req = {
        .type = TUDOR_STATE_MSG_LOAD,
        .state_id = {0},
        .name = {0}
    };
    g_strlcpy(req.state_id, state_id, sizeof(req.state_id));
    g_strlcpy(req.name, name, sizeof(req.name));
    g_assert_cmpint(write(fd, &req, sizeof(req)), ==, sizeof(req));
    dispatch_request();

    struct tudor_state_load_response resp;
    g_assert_cmpint(read(fd, &resp, sizeof(resp)), ==, sizeof(resp));
    g_assert_cmphex(resp.type, ==, TUDOR_STATE_MSG_LOAD_RESPONSE);
    g_assert_cmpint(resp.status, ==, 0);
    g_assert_cmpuint(resp.found, ==, FALSE);
}

static void assert_load_rejected(int fd, const char *name) {
    struct tudor_state_load_request req = {
        .type = TUDOR_STATE_MSG_LOAD,
        .state_id = {0},
        .name = {0}
    };
    g_strlcpy(req.state_id, state_id, sizeof(req.state_id));
    g_strlcpy(req.name, name, sizeof(req.name));
    g_assert_cmpint(write(fd, &req, sizeof(req)), ==, sizeof(req));
    dispatch_request();

    struct tudor_state_load_response resp;
    g_assert_cmpint(read(fd, &resp, sizeof(resp)), ==, sizeof(resp));
    g_assert_cmphex(resp.type, ==, TUDOR_STATE_MSG_LOAD_RESPONSE);
    g_assert_cmpint(resp.status, ==, -EINVAL);
    g_assert_cmpuint(resp.found, ==, FALSE);
}

static void assert_load_error(int fd, const char *name) {
    struct tudor_state_load_request req = {
        .type = TUDOR_STATE_MSG_LOAD,
        .state_id = {0},
        .name = {0}
    };
    g_strlcpy(req.state_id, state_id, sizeof(req.state_id));
    g_strlcpy(req.name, name, sizeof(req.name));
    g_assert_cmpint(write(fd, &req, sizeof(req)), ==, sizeof(req));
    dispatch_request();

    struct tudor_state_load_response resp;
    g_assert_cmpint(read(fd, &resp, sizeof(resp)), ==, sizeof(resp));
    g_assert_cmphex(resp.type, ==, TUDOR_STATE_MSG_LOAD_RESPONSE);
    g_assert_cmpint(resp.status, ==, -EIO);
    g_assert_cmpuint(resp.found, ==, FALSE);
}

static void test_state_round_trip(void) {
    GError *error = NULL;
    gchar *root = g_dir_make_tmp("tudor-state-test-XXXXXX", &error);
    g_assert_no_error(error);
    g_assert_nonnull(root);
    g_setenv("STATE_DIRECTORY", root, TRUE);

    const guint8 calibration[] = { 0x10, 0x20, 0x30, 0x40 };
    gchar *bootstrap = g_build_filename(root, "CalibrationData.blob", NULL);
    g_assert_true(g_file_set_contents(
        bootstrap, (const gchar*) calibration, sizeof(calibration), &error));
    g_assert_no_error(error);

    init_state();
    int sockets[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets), ==, 0);
    guint source_id = state_socket_watch(sockets[0]);

    GByteArray *loaded = send_load(
        sockets[1], "CalibrationData", TUDOR_STATE_VALUE_BLOB);
    g_assert_cmpuint(loaded->len, ==, sizeof(calibration));
    g_assert_cmpmem(loaded->data, loaded->len,
                    calibration, sizeof(calibration));
    g_byte_array_unref(loaded);

    uint32_t counter = 37;
    send_store(sockets[1], "deviceInitializeFailures",
               TUDOR_STATE_VALUE_UINT32, &counter, sizeof(counter));
    loaded = send_load(sockets[1], "deviceInitializeFailures",
                       TUDOR_STATE_VALUE_UINT32);
    g_assert_cmpuint(loaded->len, ==, sizeof(counter));
    g_assert_cmpmem(loaded->data, loaded->len, &counter, sizeof(counter));
    g_byte_array_unref(loaded);

    gchar *device_dir = g_build_filename(root, "devices", state_id, NULL);
    gchar *calibration_path = g_build_filename(
        device_dir, "CalibrationData.blob", NULL);
    gchar *counter_path = g_build_filename(
        device_dir, "deviceInitializeFailures.uint", NULL);
    gchar *pairing_path = g_build_filename(
        device_dir, "PairingData.blob", NULL);
    gchar *pairing_context_blob_path = g_build_filename(
        device_dir, "PairingContext.blob", NULL);
    gchar *pairing_context_uint_path = g_build_filename(
        device_dir, "PairingContext.uint", NULL);
    gchar *pairing_context_bool_path = g_build_filename(
        device_dir, "PairingContext.bool", NULL);
    gchar *unpairing_context_path = g_build_filename(
        device_dir, "UnpairingContext.bool", NULL);
    gchar *wake_from_sleep_path = g_build_filename(
        device_dir, "WakeFromSleepState.bool", NULL);
    struct stat statbuf;
    g_assert_cmpint(g_stat(device_dir, &statbuf), ==, 0);
    g_assert_cmpuint(statbuf.st_mode & 0777, ==, 0700);
    g_assert_cmpint(g_stat(calibration_path, &statbuf), ==, 0);
    g_assert_cmpuint(statbuf.st_mode & 0777, ==, 0600);
    g_assert_cmpint(g_stat(counter_path, &statbuf), ==, 0);
    g_assert_cmpuint(statbuf.st_mode & 0777, ==, 0600);

    gchar *counter_text = NULL;
    gsize counter_text_size = 0;
    g_assert_true(g_file_get_contents(
        counter_path, &counter_text, &counter_text_size, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(counter_text, ==, "37\n");
    g_free(counter_text);

    /* An interrupted calibration can leave an empty blob.  It must be
     * reported as missing so the vendor retries calibration, while its empty
     * PairingData marker must remain present. */
    send_store(sockets[1], "CalibrationData", TUDOR_STATE_VALUE_BLOB,
               NULL, 0);
    assert_load_missing(sockets[1], "CalibrationData");
    send_store(sockets[1], "PairingData", TUDOR_STATE_VALUE_BLOB, NULL, 0);
    loaded = send_load(sockets[1], "PairingData", TUDOR_STATE_VALUE_BLOB);
    g_assert_cmpuint(loaded->len, ==, 0);
    g_byte_array_unref(loaded);

    /* These optional vendor properties are valid even before they have a
     * value.  Unknown names remain outside the persistence allowlist. */
    assert_load_missing(sockets[1], "PairingContext");
    assert_load_missing(sockets[1], "UnpairingContext");
    assert_load_missing(sockets[1], "WakeFromSleepState");
    assert_load_rejected(sockets[1], "UnexpectedProperty");

    /* Boolean state has a one-byte, normalized wire value and an exact 0/1
     * text representation on disk.  Changing a property's type removes all
     * stale files for its prior types. */
    send_store(sockets[1], "PairingContext", TUDOR_STATE_VALUE_BLOB, NULL, 0);
    g_assert_true(g_file_test(pairing_context_blob_path,
                              G_FILE_TEST_EXISTS));
    send_store(sockets[1], "PairingContext", TUDOR_STATE_VALUE_UINT32,
               &counter, sizeof(counter));
    g_assert_false(g_file_test(pairing_context_blob_path,
                               G_FILE_TEST_EXISTS));
    g_assert_true(g_file_test(pairing_context_uint_path,
                              G_FILE_TEST_EXISTS));

    const uint8_t true_value = 1;
    const uint8_t false_value = 0;
    send_store(sockets[1], "PairingContext", TUDOR_STATE_VALUE_BOOL,
               &true_value, sizeof(true_value));
    g_assert_false(g_file_test(pairing_context_uint_path,
                               G_FILE_TEST_EXISTS));
    loaded = send_load(sockets[1], "PairingContext",
                       TUDOR_STATE_VALUE_BOOL);
    g_assert_cmpuint(loaded->len, ==, sizeof(true_value));
    g_assert_cmpmem(loaded->data, loaded->len,
                    &true_value, sizeof(true_value));
    g_byte_array_unref(loaded);

    gchar *bool_text = NULL;
    gsize bool_text_size = 0;
    g_assert_true(g_file_get_contents(pairing_context_bool_path, &bool_text,
                                      &bool_text_size, &error));
    g_assert_no_error(error);
    g_assert_cmpuint(bool_text_size, ==, 2);
    g_assert_cmpmem(bool_text, bool_text_size, "1\n", 2);
    g_free(bool_text);
    g_assert_cmpint(g_stat(pairing_context_bool_path, &statbuf), ==, 0);
    g_assert_cmpuint(statbuf.st_mode & 0777, ==, 0600);

    send_store(sockets[1], "UnpairingContext", TUDOR_STATE_VALUE_BOOL,
               &false_value, sizeof(false_value));
    loaded = send_load(sockets[1], "UnpairingContext",
                       TUDOR_STATE_VALUE_BOOL);
    g_assert_cmpuint(loaded->len, ==, sizeof(false_value));
    g_assert_cmpmem(loaded->data, loaded->len,
                    &false_value, sizeof(false_value));
    g_byte_array_unref(loaded);

    send_store(sockets[1], "WakeFromSleepState", TUDOR_STATE_VALUE_BOOL,
               &true_value, sizeof(true_value));
    loaded = send_load(sockets[1], "WakeFromSleepState",
                       TUDOR_STATE_VALUE_BOOL);
    g_assert_cmpuint(loaded->len, ==, sizeof(true_value));
    g_assert_cmpmem(loaded->data, loaded->len,
                    &true_value, sizeof(true_value));
    g_byte_array_unref(loaded);

    const uint8_t invalid_bool = 2;
    g_test_expect_message(NULL, G_LOG_LEVEL_WARNING,
                          "*Failed to store state*UnpairingContext*0 or 1*");
    g_assert_cmpint(send_store_status(
        sockets[1], "UnpairingContext", TUDOR_STATE_VALUE_BOOL,
        &invalid_bool, sizeof(invalid_bool)), ==, -EIO);
    g_test_assert_expected_messages();
    g_test_expect_message(NULL, G_LOG_LEVEL_WARNING,
                          "*Failed to store state*UnpairingContext*0 or 1*");
    g_assert_cmpint(send_store_status(
        sockets[1], "UnpairingContext", TUDOR_STATE_VALUE_BOOL,
        NULL, 0), ==, -EIO);
    g_test_assert_expected_messages();

    g_assert_true(g_file_set_contents(pairing_context_bool_path, "true\n", 5,
                                      &error));
    g_assert_no_error(error);
    g_test_expect_message(NULL, G_LOG_LEVEL_WARNING,
                          "*Failed to load state*PairingContext*Invalid bool*");
    assert_load_error(sockets[1], "PairingContext");
    g_test_assert_expected_messages();
    send_store(sockets[1], "PairingContext", TUDOR_STATE_VALUE_BOOL,
               &true_value, sizeof(true_value));

    /* The legacy bootstrap path follows the same empty-calibration rule and
     * must not copy an empty file into device-specific state. */
    g_assert_cmpint(g_unlink(calibration_path), ==, 0);
    g_assert_true(g_file_set_contents(bootstrap, "", 0, &error));
    g_assert_no_error(error);
    assert_load_missing(sockets[1], "CalibrationData");
    g_assert_false(g_file_test(calibration_path, G_FILE_TEST_EXISTS));

    struct tudor_state_load_request invalid_req = {
        .type = TUDOR_STATE_MSG_LOAD,
        .state_id = "../escape",
        .name = "CalibrationData"
    };
    g_assert_cmpint(write(sockets[1], &invalid_req, sizeof(invalid_req)),
                    ==, sizeof(invalid_req));
    dispatch_request();
    struct tudor_state_load_response invalid_resp;
    g_assert_cmpint(read(sockets[1], &invalid_resp, sizeof(invalid_resp)),
                    ==, sizeof(invalid_resp));
    g_assert_cmphex(invalid_resp.type, ==,
                    TUDOR_STATE_MSG_LOAD_RESPONSE);
    g_assert_cmpint(invalid_resp.status, ==, -EINVAL);

    GSource *source = g_main_context_find_source_by_id(NULL, source_id);
    g_assert_nonnull(source);
    g_source_destroy(source);
    close(sockets[0]);
    close(sockets[1]);
    uninit_state();

    g_assert_cmpint(g_unlink(counter_path), ==, 0);
    g_assert_cmpint(g_unlink(pairing_path), ==, 0);
    g_assert_cmpint(g_unlink(pairing_context_bool_path), ==, 0);
    g_assert_cmpint(g_unlink(unpairing_context_path), ==, 0);
    g_assert_cmpint(g_unlink(wake_from_sleep_path), ==, 0);
    g_assert_cmpint(g_unlink(bootstrap), ==, 0);
    g_assert_cmpint(g_rmdir(device_dir), ==, 0);
    gchar *devices_dir = g_build_filename(root, "devices", NULL);
    g_assert_cmpint(g_rmdir(devices_dir), ==, 0);
    g_assert_cmpint(g_rmdir(root), ==, 0);

    g_free(devices_dir);
    g_free(wake_from_sleep_path);
    g_free(unpairing_context_path);
    g_free(pairing_context_bool_path);
    g_free(pairing_context_uint_path);
    g_free(pairing_context_blob_path);
    g_free(pairing_path);
    g_free(counter_path);
    g_free(calibration_path);
    g_free(device_dir);
    g_free(bootstrap);
    g_free(root);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/tudor/state/round-trip", test_state_round_trip);
    return g_test_run();
}
