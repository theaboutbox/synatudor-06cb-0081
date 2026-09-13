#include <glib.h>
#include <sys/socket.h>
#include <string.h>

/* Include the production static initialization/error and disposal callbacks.
 * Constructing the object directly does not run its async USB probe. */
#include "../src/open.c"

typedef struct {
    GTestDBus *bus;
    GDBusConnection *server, *client;
    GDBusNodeInfo *node;
    guint registration;
    GDBusMethodInvocation *pending;
    guint requested_id;
    guint cleanup_callbacks;
    guint log_handler;
    gboolean failure_completed;
    gboolean finalized;
} Fixture;

static void iterate_until(gboolean *done, guint timeout_msec) {
    gint64 deadline = g_get_monotonic_time() + timeout_msec * 1000;
    while(!*done && g_get_monotonic_time() < deadline) {
        g_main_context_iteration(NULL, FALSE);
        g_usleep(1000);
    }
    g_assert_true(*done);
}

static void wait_for_request(Fixture *fixture) {
    gint64 deadline = g_get_monotonic_time() + G_TIME_SPAN_SECOND;
    while(!fixture->pending && g_get_monotonic_time() < deadline) {
        g_main_context_iteration(NULL, FALSE);
        g_usleep(1000);
    }
    g_assert_nonnull(fixture->pending);
    g_assert_cmpuint(fixture->requested_id, ==, 41);
}

static void wait_for_cleanup_callback(Fixture *fixture, guint timeout_msec) {
    gint64 deadline = g_get_monotonic_time() + timeout_msec * 1000;
    while(!fixture->cleanup_callbacks && g_get_monotonic_time() < deadline) {
        g_main_context_iteration(NULL, FALSE);
        g_usleep(1000);
    }
    g_assert_cmpuint(fixture->cleanup_callbacks, ==, 1);
}

static void method_call(GDBusConnection *con, const gchar *sender,
                        const gchar *path, const gchar *interface,
                        const gchar *method, GVariant *params,
                        GDBusMethodInvocation *invocation, gpointer data) {
    Fixture *fixture = data;
    g_assert_cmpstr(method, ==, TUDOR_HOST_LAUNCHER_KILL_METHOD);
    g_assert_null(fixture->pending);
    g_variant_get(params, "(u)", &fixture->requested_id);
    fixture->pending = g_object_ref(invocation);
    /* Deliberately retain the invocation without replying. */
}

static const GDBusInterfaceVTable vtable = { .method_call = method_call };

static gboolean allow_expected_warning(const gchar *domain,
                                        GLogLevelFlags level,
                                        const gchar *message, gpointer data) {
    return !(level & G_LOG_LEVEL_WARNING) ||
        !g_str_has_prefix(message,
                          "Error cleaning up Tudor host process ID 41:");
}

static void cleanup_warning(const gchar *domain, GLogLevelFlags level,
                            const gchar *message, gpointer data) {
    Fixture *fixture = data;
    g_assert_nonnull(strstr(message,
                           "Error cleaning up Tudor host process ID 41:"));
    fixture->cleanup_callbacks++;
}

static GDBusConnection *connect_private_bus(Fixture *fixture) {
    GError *error = NULL;
    GDBusConnection *con = g_dbus_connection_new_for_address_sync(
        g_test_dbus_get_bus_address(fixture->bus),
        G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
        G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION, NULL, NULL, &error);
    g_assert_no_error(error);
    g_assert_nonnull(con);
    return con;
}

static void setup(Fixture *fixture, gconstpointer data) {
    fixture->bus = g_test_dbus_new(G_TEST_DBUS_NONE);
    g_test_dbus_up(fixture->bus);
    fixture->server = connect_private_bus(fixture);
    fixture->client = connect_private_bus(fixture);

    GError *error = NULL;
    GVariant *ret = g_dbus_connection_call_sync(fixture->server,
        "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
        "RequestName", g_variant_new("(su)", TUDOR_HOST_LAUNCHER_SERVICE, 0),
        G_VARIANT_TYPE("(u)"), G_DBUS_CALL_FLAGS_NONE, 1000, NULL, &error);
    g_assert_no_error(error);
    g_assert_nonnull(ret);
    guint result;
    g_variant_get(ret, "(u)", &result);
    g_assert_cmpuint(result, ==, 1);
    g_variant_unref(ret);

    fixture->node = g_dbus_node_info_new_for_xml(
        "<node><interface name='" TUDOR_HOST_LAUNCHER_INTERF "'>"
        "<method name='" TUDOR_HOST_LAUNCHER_KILL_METHOD "'>"
        "<arg type='u' direction='in'/></method></interface></node>", &error);
    g_assert_no_error(error);
    fixture->registration = g_dbus_connection_register_object(
        fixture->server, TUDOR_HOST_LAUNCHER_OBJ, fixture->node->interfaces[0],
        &vtable, fixture, NULL, &error);
    g_assert_no_error(error);
    g_assert_cmpuint(fixture->registration, !=, 0);

    g_test_log_set_fatal_handler(allow_expected_warning, NULL);
    fixture->log_handler = g_log_set_handler(NULL,
        G_LOG_LEVEL_WARNING | G_LOG_FLAG_FATAL | G_LOG_FLAG_RECURSION,
        cleanup_warning, fixture);
}

static void teardown(Fixture *fixture, gconstpointer data) {
    g_log_remove_handler(NULL, fixture->log_handler);
    g_test_log_set_fatal_handler(NULL, NULL);
    /* A server invocation owns the original dispatch reference until a reply
     * completes it, including when the client has already timed out. */
    if(fixture->pending)
        g_dbus_method_invocation_return_dbus_error(fixture->pending,
            "net.reactivated.TudorHostLauncher.Fixture", "fixture teardown");
    g_clear_object(&fixture->pending);
    g_dbus_connection_unregister_object(fixture->server, fixture->registration);
    g_dbus_node_info_unref(fixture->node);
    g_dbus_connection_close_sync(fixture->client, NULL, NULL);
    g_dbus_connection_close_sync(fixture->server, NULL, NULL);
    g_clear_object(&fixture->client);
    g_clear_object(&fixture->server);
    g_test_dbus_down(fixture->bus);
    g_clear_object(&fixture->bus);
}

static GSocket *new_socket(void) {
    int pair[2];
    g_assert_cmpint(socketpair(AF_UNIX, SOCK_DGRAM, 0, pair), ==, 0);
    close(pair[1]);
    GError *error = NULL;
    GSocket *socket = g_socket_new_from_fd(pair[0], &error);
    g_assert_no_error(error);
    return socket;
}

static FpiDeviceTudor *new_device(Fixture *fixture) {
    FpiDeviceTudor *tdev = g_object_new(FPI_TYPE_DEVICE_TUDOR, NULL);
    tdev->dbus_con = g_object_ref(fixture->client);
    tdev->host_has_id = true;
    tdev->host_dead = true;
    tdev->host_id = 41;
    tdev->ipc_socket = new_socket();
    tdev->ipc_cancel = g_cancellable_new();
    tdev->pdata_sensor_name = g_strdup("fixture");
    g_ptr_array_add(tdev->db_records, g_object_new(G_TYPE_OBJECT, NULL));
    return tdev;
}

static void assert_disposed(FpiDeviceTudor *tdev) {
    g_assert_false(tdev->host_has_id);
    g_assert_false(tdev->host_dead);
    g_assert_cmpuint(tdev->host_id, ==, 0);
    g_assert_null(tdev->ipc_socket);
    g_assert_null(tdev->ipc_cancel);
    g_assert_null(tdev->pdata_sensor_name);
    g_assert_null(tdev->close_task);
    g_assert_cmpuint(tdev->db_records->len, ==, 0);
}

static void failed_open_cb(GObject *object, GAsyncResult *result, gpointer data) {
    Fixture *fixture = data;
    GError *error = NULL;
    g_task_propagate_int(G_TASK(result), &error);
    g_assert_error(error, G_IO_ERROR, G_IO_ERROR_FAILED);
    g_clear_error(&error);
    assert_disposed(FPI_DEVICE_TUDOR(object));
    g_assert_false(fixture->failure_completed);
    fixture->failure_completed = TRUE;
}

static void reply_late(Fixture *fixture) {
    g_dbus_method_invocation_return_dbus_error(fixture->pending,
        "net.reactivated.TudorHostLauncher.Fixture", "delayed cleanup reply");
    g_clear_object(&fixture->pending);
    wait_for_cleanup_callback(fixture, 1000);
}

static void failure_does_not_wait(Fixture *fixture, gconstpointer data) {
    FpiDeviceTudor *tdev = new_device(fixture);
    /* This is the same outer initialization task that feeds probe_open_cb.
     * Inject the receive failure through the production init_recv_cb. */
    GTask *outer = g_task_new(tdev, NULL, failed_open_cb, fixture);
    GTask *receive = g_task_new(tdev, NULL, init_recv_cb, outer);
    g_task_return_new_error(receive, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "fixture host initialization failed");
    g_object_unref(receive);
    iterate_until(&fixture->failure_completed, 1000);
    wait_for_request(fixture);
    g_assert_cmpuint(fixture->cleanup_callbacks, ==, 0);

    /* A delayed reply for ID 41 must not mutate the new host's state. */
    tdev->host_has_id = true;
    tdev->host_id = 42;
    tdev->ipc_socket = new_socket();
    tdev->ipc_cancel = g_cancellable_new();
    GSocket *new_socket_ptr = tdev->ipc_socket;
    reply_late(fixture);
    g_assert_true(tdev->host_has_id);
    g_assert_cmpuint(tdev->host_id, ==, 42);
    g_assert_true(tdev->ipc_socket == new_socket_ptr);
    g_assert_nonnull(tdev->ipc_cancel);
    tdev->host_has_id = false;
    dispose_dev(tdev);
    g_object_unref(tdev);
}

static void finalized_cb(gpointer data, GObject *object) {
    ((Fixture *) data)->finalized = TRUE;
}

static void cleanup_does_not_retain_device(Fixture *fixture, gconstpointer data) {
    FpiDeviceTudor *tdev = new_device(fixture);
    g_object_weak_ref(G_OBJECT(tdev), finalized_cb, fixture);
    dispose_dev(tdev);
    assert_disposed(tdev);
    g_object_unref(tdev);
    g_assert_true(fixture->finalized);
    wait_for_request(fixture);
    reply_late(fixture);
}

static gboolean heartbeat(gpointer data) {
    (*(guint *) data)++;
    return G_SOURCE_CONTINUE;
}

static void cleanup_timeout_keeps_loop_live(Fixture *fixture, gconstpointer data) {
    guint ticks = 0;
    guint heartbeat_id = g_timeout_add(10, heartbeat, &ticks);
    kill_host_process_async(fixture->client, 41);
    wait_for_request(fixture);
    wait_for_cleanup_callback(fixture, 6500);
    g_source_remove(heartbeat_id);
    g_assert_cmpuint(ticks, >, 100);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add("/tudor/cleanup/failure-does-not-wait", Fixture, NULL,
               setup, failure_does_not_wait, teardown);
    g_test_add("/tudor/cleanup/no-device-retention", Fixture, NULL,
               setup, cleanup_does_not_retain_device, teardown);
    g_test_add("/tudor/cleanup/timeout-keeps-loop-live", Fixture, NULL,
               setup, cleanup_timeout_keeps_loop_live, teardown);
    return g_test_run();
}
