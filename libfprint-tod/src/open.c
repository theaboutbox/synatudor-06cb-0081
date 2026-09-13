#include <sys/socket.h>
#include <libusb.h>
#include <gusb.h>
#include <tudor/dbus-launcher.h>
#include "open.h"
#include "data.h"
#include "ipc.h"
#include "suspend.h"

static void dispose_dev(FpiDeviceTudor *tdev) {
    /* Even a dead host has launcher resources to release. Snapshot its ID
     * before clearing local state; a launcher reply must not delay disposal. */
    guint old_host_id = tdev->host_has_id ? tdev->host_id : 0;
    /* The launcher may already have retired this ID after a USB
     * re-enumeration. Local cleanup must still make a later open start from a
     * complete connection rather than reusing an ID with no IPC socket. */
    tdev->host_has_id = false;
    tdev->host_dead = false;
    tdev->host_id = 0;

    //Close the sleep inhibitor (if we got one)
    if(tdev->host_sleep_inhib >= 0) {
        close_sleep_inhibitor(tdev->host_sleep_inhib);
        tdev->host_sleep_inhib = -1;
    }

    //Cancel pending timeouts
    if(tdev->close_timeout_src){
        g_source_destroy(tdev->close_timeout_src);
        tdev->close_timeout_src = NULL;
    }

    //Clear DB mirror array
    g_ptr_array_set_size(tdev->db_records, 0);

    //Free object references
    g_clear_object(&tdev->ipc_cancel);
    g_clear_object(&tdev->ipc_socket);
    g_clear_pointer(&tdev->pdata_sensor_name, g_free);
    g_clear_object(&tdev->close_task);

    if(old_host_id) kill_host_process_async(tdev->dbus_con, old_host_id);

    g_debug("Disposed tudor device resources");
}

static void host_died_signal_cb(GDBusConnection *con, const gchar *sender, const gchar *obj, const gchar *interf, const gchar *signal, GVariant *params, gpointer user_data) {
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(user_data);

    //Check and get parameters
    if(!g_variant_check_format_string(params, "(ui)", FALSE)) {
        g_warning("Received invalid parameters from tudor host launcher HostDied signal!");
        return;
    }

    guint host_id;
    gint status;
    g_variant_get(params, "(ui)", &host_id, &status);

    //Check host ID
    if(!tdev->host_has_id || tdev->host_dead || tdev->host_id != host_id) return;

    //Mark host as dead
    tdev->host_dead = true;

    //Log status
    if(status != EXIT_SUCCESS) g_warning("Tudor host process died! Exit Code %d", status);

    //Cancel IPC
    if(tdev->ipc_cancel) {
        g_cancellable_cancel(tdev->ipc_cancel);
        g_debug("Cancelled tudor host process ID %u IPC", tdev->host_id);
    }

    //If we have a close task, we have to dispose the device and complete the action here
    if(tdev->close_task) {
        g_task_return_int(tdev->close_task, 0);
        dispose_dev(tdev);
    }
}

static gboolean state_component_is_safe(const gchar *value) {
    size_t len = value ? strlen(value) : 0;
    if(!len || len > 96) return FALSE;
    for(size_t i = 0; i < len; i++) {
        if(!g_ascii_isalnum(value[i])) return FALSE;
    }
    return TRUE;
}

static gchar *make_state_id(GUsbDevice *usb_dev) {
    gchar *serial = NULL;
    GError *error = NULL;
    guint8 serial_index = g_usb_device_get_serial_number_index(usb_dev);
    if(serial_index)
        serial = g_usb_device_get_string_descriptor(
            usb_dev, serial_index, &error);
    if(error) {
        g_warning("Could not read fingerprint sensor serial number: %s",
                  error->message);
        g_clear_error(&error);
    }

    gchar *component;
    if(state_component_is_safe(serial)) {
        component = g_strdup(serial);
    } else {
        const gchar *fallback = serial && serial[0]
            ? serial : g_usb_device_get_platform_id(usb_dev);
        if(!fallback || !fallback[0])
            fallback = "unknown-usb-device";
        component = g_compute_checksum_for_string(
            G_CHECKSUM_SHA256, fallback, -1);
        component[32] = 0;
        g_warning("Using a hashed USB path as the fingerprint sensor state ID");
    }

    gchar *state_id = g_strdup_printf(
        "%04x-%04x-%s", g_usb_device_get_vid(usb_dev),
        g_usb_device_get_pid(usb_dev), component);
    g_free(component);
    g_free(serial);
    return state_id;
}

void register_host_process_monitor(FpiDeviceTudor *tdev) {
    if(tdev->host_died_subscription_id) return;
    //Register a signal listener
    tdev->host_died_subscription_id = g_dbus_connection_signal_subscribe(tdev->dbus_con,
        TUDOR_HOST_LAUNCHER_SERVICE, TUDOR_HOST_LAUNCHER_INTERF, TUDOR_HOST_LAUNCHER_HOST_DIED_SIGNAL, TUDOR_HOST_LAUNCHER_OBJ,
        NULL, G_DBUS_SIGNAL_FLAGS_NONE,
        host_died_signal_cb, tdev, NULL
    );
}

static void init_recv_cb(GObject *src_obj, GAsyncResult *res, gpointer user_data) {
    GTask *mtask = G_TASK(res);
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(src_obj);
    GTask *task = G_TASK(user_data);

    //Get the message buffer
    GError *error = NULL;
    IPCMessageBuf *msg = (IPCMessageBuf*) g_task_propagate_pointer(mtask, &error);
    if(!msg) {
        /* HostDied cancels the receive task to wake its socket source. GTask
         * then overrides the protocol error with G_IO_ERROR_CANCELLED. During
         * probe this is an initialization failure, not caller cancellation:
         * libfprint skips its pending-device decrement for cancelled probes. */
        if(tdev->host_dead &&
           g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
            g_clear_error(&error);
            error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO,
                "Tudor host process died during initialization");
        }
        goto error;
    }

    //Handle message
    switch(msg->type) {
        case IPC_MSG_LOAD_PDATA: {
            if(!check_ipc_msg_size(msg, sizeof(msg->load_pdata), &error)) goto error;

            //Check sensor name
            msg->load_pdata.sensor_name[IPC_SENSOR_NAME_SIZE] = 0;
            if(!tdev->pdata_sensor_name) tdev->pdata_sensor_name = g_strdup(msg->load_pdata.sensor_name);
            else if(strcmp(tdev->pdata_sensor_name, msg->load_pdata.sensor_name) != 0) {
                error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "Disallowed load of sensor pairing data '%s'", msg->load_pdata.sensor_name);
                goto error;
            }

            //Load pairing data
            GByteArray *pdata = NULL;
            if(!load_pdata(tdev, tdev->pdata_sensor_name, &pdata, &error)) goto error;

            if(pdata && pdata->len > IPC_MAX_PDATA_SIZE) {
                error = fpi_device_error_new_msg(FP_DEVICE_ERROR_DATA_INVALID, "Stored Tudor pairing data length exceeds maximum! [%d > %d]", pdata->len, IPC_MAX_PDATA_SIZE);
                g_byte_array_unref(pdata);
                goto error;
            }

            //Send response
            tdev->send_msg->size = sizeof(struct ipc_msg_resp_load_pdata) + (pdata ? pdata->len : 0);
            tdev->send_msg->resp_load_pdata = (struct ipc_msg_resp_load_pdata) {
                .type = IPC_MSG_RESP_LOAD_PDATA,
                .has_pdata = (pdata != NULL)
            };
            if(pdata) {
                memcpy(tdev->send_msg->resp_load_pdata.pdata, pdata->data, pdata->len);
                g_byte_array_unref(pdata);
            }
            if(!send_ipc_msg(tdev, tdev->send_msg, &error)) goto error;

            //Receive further messages
            recv_ipc_msg(tdev, init_recv_cb, task);
        } break;
        case IPC_MSG_STORE_PDATA: {
            if(!check_ipc_msg_size(msg, sizeof(msg->store_pdata), &error)) goto error;

            //Check sensor name
            msg->store_pdata.sensor_name[IPC_SENSOR_NAME_SIZE] = 0;
            if(!tdev->pdata_sensor_name) tdev->pdata_sensor_name = g_strdup(msg->store_pdata.sensor_name);
            else if(strcmp(tdev->pdata_sensor_name, msg->store_pdata.sensor_name) != 0) {
                error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "Disallowed store of sensor pairing data '%s'", msg->store_pdata.sensor_name);
                goto error;
            }

            //Create pairing data array
            size_t pdata_len = msg->size - sizeof(struct ipc_msg_store_pdata);
            if(pdata_len > IPC_MAX_PDATA_SIZE) {
                error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "Pairing data exceeds maximum size");
                goto error;
            }

            if(!check_ipc_msg_size(msg, sizeof(msg->store_pdata) + pdata_len, &error)) goto error;

            GByteArray *pdata = g_byte_array_new_take(g_memdup2(msg->store_pdata.pdata, pdata_len), pdata_len);

            //Store pairing data
            if(!store_pdata(tdev, tdev->pdata_sensor_name, pdata, &error)) {
                g_byte_array_unref(pdata);
                goto error;
            }
            g_byte_array_unref(pdata);

            //Send ACK
            tdev->send_msg->size = sizeof(enum ipc_msg_type);
            tdev->send_msg->type = IPC_MSG_ACK;
            if(!send_ipc_msg(tdev, tdev->send_msg, &error)) goto error;

            //Receive further messages
            recv_ipc_msg(tdev, init_recv_cb, task);
        } break;
        case IPC_MSG_READY: {
            //Complete the open procedure
            g_info("Tudor host process ID reported ready state");
            g_task_return_int(task, 0);
            g_object_unref(task);
        } break;
        default: error = fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "Unexpected message in init sequence: 0x%x", msg->type); goto error;
    }

    ipc_msg_buf_free(msg);
    return;

    error:;
    if(msg) ipc_msg_buf_free(msg);
    dispose_dev(tdev);
    g_task_return_error(task, error);
    g_object_unref(task);
}

static gboolean prepare_host_usb(FpiDeviceTudor *tdev, GUsbDevice *usb_dev,
                                 GError **error) {
    if(tdev->usb_fd >= 0) {
        if(tdev->state_id) return TRUE;
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_FAILED,
                            "Fingerprint sensor descriptor has no state ID");
        return FALSE;
    }

    //Open the USB device before choosing a launcher host so its stable state
    //identity can be checked as part of adoption and replacement.
    if(!g_usb_device_open(usb_dev, error)) return FALSE;

    //Get the USB device's private data
#if G_USB_CHECK_VERSION(0, 4, 0)
    //0.4+ uses the glib private class data mechanism
    void **dev_priv = (void**) g_type_instance_get_private(&usb_dev->parent_instance.g_type_instance, G_USB_TYPE_DEVICE);
#else
    void **dev_priv = usb_dev->priv;
#endif

    //Get the FD using cursed offset magic
    libusb_device_handle *dev_handle = (libusb_device_handle*) (dev_priv[3]); //(GUsbDevicePrivate*)->handle
    int dev_fd = ((int*) dev_handle)[10 + 2 + 4 + 2 + 1 + 1]; //(struct linux_device_handle_priv*)->fd
    tdev->usb_fd = dup(dev_fd);
    if(tdev->usb_fd < 0) {
        int err = errno;
        g_usb_device_close(usb_dev, NULL);
        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(err),
                    "Failed to duplicate fingerprint sensor descriptor: %s",
                    g_strerror(err));
        return FALSE;
    }

    if(!tdev->state_id) tdev->state_id = make_state_id(usb_dev);

    if(!g_usb_device_close(usb_dev, error)) {
        g_assert_no_errno(close(tdev->usb_fd));
        tdev->usb_fd = -1;
        return FALSE;
    }

    return TRUE;
}

static void init_host_proc(FpiDeviceTudor *tdev, GTask *task, GUsbDevice *usb_dev) {
    GError *error = NULL;

    //Send the init message
    enum log_level loglvl;
    const char *loglvl_env = g_getenv("TUDOR_LOGLVL");
    char *loglvl_env_end = NULL;
    if(loglvl_env) loglvl = (enum log_level) strtol(loglvl_env, &loglvl_env_end, 10);
    if(loglvl_env == loglvl_env_end) loglvl = LOG_INFO;
    if(loglvl < LOG_VERBOSE) loglvl = LOG_VERBOSE;
    if(loglvl > LOG_ERROR) loglvl = LOG_ERROR;

    /* The device retains usb_fd across host restarts. The message owns a
     * separate copy, including when sending or initialization fails. */
    tdev->send_msg->transfer_fd = dup(tdev->usb_fd);
    if(tdev->send_msg->transfer_fd < 0) {
        int saved_errno = errno;
        dispose_dev(tdev);
        g_task_return_new_error(task, G_IO_ERROR,
            g_io_error_from_errno(saved_errno),
            "Duplicating USB descriptor for IPC: %s", g_strerror(saved_errno));
        g_object_unref(task);
        return;
    }
    tdev->send_msg->size = sizeof(struct ipc_msg_init); 
    tdev->send_msg->init = (struct ipc_msg_init) {
        .type = IPC_MSG_INIT,
        .log_level = loglvl,
        .usb_bus = g_usb_device_get_bus(usb_dev),
        .usb_addr = g_usb_device_get_address(usb_dev),
        .state_id = {0}
    };
    if(!tdev->state_id) tdev->state_id = make_state_id(usb_dev);
    strncpy(tdev->send_msg->init.state_id, tdev->state_id,
            TUDOR_STATE_ID_SIZE);
    if(!send_ipc_msg(tdev, tdev->send_msg, &error)) {
        dispose_dev(tdev);
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }
    g_debug("Initialized tudor host process ID %d", tdev->host_id);

    //Receive IPC messages
    g_clear_pointer(&tdev->pdata_sensor_name, g_free);
    recv_ipc_msg(tdev, init_recv_cb, task);
}

void open_device(FpiDeviceTudor *tdev, GAsyncReadyCallback callback, gpointer user_data) {
    GError *error = NULL;

    //Create task
    GTask *task = g_task_new(tdev, NULL, callback, user_data);

    //Reuse only a live, completely connected host. A HostDied signal can
    //arrive while the device is idle, with no pending receive to dispose it.
    if(tdev->host_has_id && !tdev->host_dead && tdev->ipc_socket) {
        g_task_return_int(task, 0);
        g_object_unref(task);
        return;
    }
    if(tdev->host_has_id) dispose_dev(tdev);

    //Open a DBus connection
    if(!open_dbus_con(tdev, &error)) {
        dispose_dev(tdev);
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    //Create a sleep inhibitor
    if(!create_sleep_inhibitor(tdev, &error)) {
        dispose_dev(tdev);
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    GUsbDevice *usb_dev = fpi_device_get_usb_device(FP_DEVICE(tdev));
    int sock_fd;

    if(!prepare_host_usb(tdev, usb_dev, &error)) {
        dispose_dev(tdev);
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }

    //Try to adopt a host process
    guint8 usb_bus = g_usb_device_get_bus(usb_dev), usb_addr = g_usb_device_get_address(usb_dev);

    bool did_adopt = adopt_host_process(
        tdev, usb_bus, usb_addr, tdev->state_id, &sock_fd, &error);
    if(!did_adopt) {
        if(error) {
            g_warning("Failed to adopt Tudor host process - is tudor-host-launcher.service running? Error: '%s' (%s code %d)", error->message, g_quark_to_string(error->domain), error->code);
            dispose_dev(tdev);
            g_task_return_error(task, error);
            g_object_unref(task);
            return;
        }

        //Start a host process
        if(!start_host_process(
               tdev, usb_bus, usb_addr, tdev->state_id, &sock_fd, &error)) {
            g_warning("Failed to start Tudor host process - is tudor-host-launcher.service running? Error: '%s' (%s code %d)", error->message, g_quark_to_string(error->domain), error->code);
            dispose_dev(tdev);
            g_task_return_error(task, error);
            g_object_unref(task);
            return;
        }
        g_info("Started tudor host process ID %u for USB bus 0x%04hx addr 0x%04hx", tdev->host_id, usb_bus, usb_addr);
    } else g_info("Adopted tudor host process ID %u for USB bus 0x%04hx addr 0x%04hx", tdev->host_id, usb_bus, usb_addr);

    //An adopted host already owns the descriptor from its original launch.
    if(did_adopt) {
        g_assert_no_errno(close(tdev->usb_fd));
        tdev->usb_fd = -1;
    }

    //Create the IPC socket
    tdev->ipc_socket = g_socket_new_from_fd(sock_fd, &error);
    if(!tdev->ipc_socket) {
        g_assert_no_errno(close(sock_fd));
        dispose_dev(tdev);
        g_task_return_error(task, error);
        g_object_unref(task);
        return;
    }
    g_socket_set_timeout(tdev->ipc_socket, IPC_TIMEOUT_SECS);
    tdev->ipc_cancel = g_cancellable_new();

    //Initialize the host process if we started a new one
    if(!did_adopt) init_host_proc(tdev, task, usb_dev);
    else {
        g_task_return_int(task, 0);
        g_object_unref(task);
    }
}

static void shutdown_timeout_cb(FpDevice *dev, gpointer user_data) {
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(dev);

    //Check if there's a close task
    if(tdev->close_task) {
        g_warning("Tudor host process hit shut down timeout!");
        g_task_return_int(tdev->close_task, 0);
        dispose_dev(tdev);
    }
}

static void shutdown_host(FpiDeviceTudor *tdev) {
    //The close may already have completed (host death, timeout)
    if(!tdev->close_task) return;

    //Send shutdown message
    tdev->send_msg->size = sizeof(enum ipc_msg_type);
    tdev->send_msg->type = IPC_MSG_SHUTDOWN;

    GError *error = NULL;
    if(!send_ipc_msg(tdev, tdev->send_msg, &error)) {
        g_task_return_error(tdev->close_task, error);
        dispose_dev(tdev);
        return;
    }

    //Add timeout
    g_assert_null(tdev->close_timeout_src);
    tdev->close_timeout_src = fpi_device_add_timeout(FP_DEVICE(tdev), SHUTDOWN_TIMEOUT_SECS * 1000, shutdown_timeout_cb, NULL, NULL);
}

static void orphan_clear_acked_cb(GObject *src_obj, GAsyncResult *res, gpointer user_data) {
    GTask *task = G_TASK(res);
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(src_obj);

    //Check for errors
    GError *error = NULL;
    IPCMessageBuf *msg = g_task_propagate_pointer(task, &error);
    if(!tdev->close_task) {
        //The close already completed through another path
        g_clear_pointer(&msg, ipc_msg_buf_free);
        g_clear_error(&error);
        return;
    }
    if(!msg) goto error;
    ipc_msg_buf_free(msg);

    g_debug("Tudor host ACKed record clearing for orphaning");

    //Orphan the host process
    if(!orphan_host_process(tdev, &error)) goto error;

    g_info("Orphaned Tudor device host ID %u", tdev->host_id);

    g_task_return_int(tdev->close_task, 0);
    dispose_dev(tdev);
    return;

    error:;
    g_warning("Failed to orphan Tudor host process: %s (%s code %d)", error->message, g_quark_to_string(error->domain), error->code);
    g_clear_error(&error);

    shutdown_host(tdev);
}

void close_device(FpiDeviceTudor *tdev, bool orphan_host, GAsyncReadyCallback callback, gpointer user_data) {
    //Create task
    GTask *task = g_task_new(tdev, NULL, callback, user_data);

    if(!tdev->host_has_id || tdev->host_dead) {
        //Dispose the device directly
        dispose_dev(tdev);
        g_task_return_int(task, 0);
        g_object_unref(task);
        return;
    }

    tdev->close_task = task;

    if(orphan_host) {
        //Clear the host prints, then orphan
        tdev->send_msg->size = sizeof(enum ipc_msg_type);
        tdev->send_msg->type = IPC_MSG_CLEAR_HOST_RECORDS;
        send_acked_ipc_msg(tdev, tdev->send_msg, orphan_clear_acked_cb, NULL);
    } else shutdown_host(tdev);
}


static void probe_recv_cb(GObject *src_obj, GAsyncResult *res, gpointer user_data) {
    GTask *task = G_TASK(res);
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(src_obj);

    //Check for errors
    GError *error = NULL;
    IPCMessageBuf *msg = g_task_propagate_pointer(task, &error);
    if(!msg) {
        fpi_device_probe_complete(FP_DEVICE(tdev), NULL, NULL, error);
        return;
    }

    //Handle the message
    switch(msg->type) {
        case IPC_MSG_RESP_PROBE: {
            if(!check_ipc_msg_size(msg, sizeof(msg->resp_probe), &error)) {
                fpi_device_probe_complete(FP_DEVICE(tdev), NULL, NULL, error);
                break;
            }

            msg->resp_probe.sensor_name[IPC_SENSOR_NAME_SIZE] = 0;
            g_info("Probed Tudor host process ID %u - sensor name '%s'", tdev->host_id, msg->resp_probe.sensor_name);
            fpi_device_probe_complete(FP_DEVICE(tdev), msg->resp_probe.sensor_name, NULL, NULL);
        } break;
        default: {
            fpi_device_probe_complete(FP_DEVICE(tdev), NULL, NULL,  fpi_device_error_new_msg(FP_DEVICE_ERROR_PROTO, "Unexpected message in probe sequence: 0x%x", msg->type));
        } break;
    }

    ipc_msg_buf_free(msg);
}

static void probe_open_cb(GObject *src_obj, GAsyncResult *res, gpointer user_data) {
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(src_obj);
    GTask *task = G_TASK(res);

    //Check for errors
    GError *error = NULL;
    g_task_propagate_int(task, &error);
    if(error) {
        fpi_device_probe_complete(FP_DEVICE(tdev), NULL, NULL, error);
        return;
    }

    //Send a probe message
    tdev->send_msg->size = sizeof(enum ipc_msg_type);
    tdev->send_msg->type = IPC_MSG_PROBE;
    if(!send_ipc_msg(tdev, tdev->send_msg, &error)) {
        fpi_device_probe_complete(FP_DEVICE(tdev), NULL, NULL, error);
        return;
    }
    recv_ipc_msg(tdev, probe_recv_cb, NULL);
}

void fpi_device_tudor_probe(FpDevice *dev) {
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(dev);

    //Open the device
    open_device(tdev, probe_open_cb, NULL);
}

static void dev_open_cb(GObject *src_obj, GAsyncResult *res, gpointer user_data) {
    FpiDeviceTudor *tdev = FPI_DEVICE_TUDOR(src_obj);
    GTask *task = G_TASK(res);

    //Check for errors
    GError *error = NULL;
    g_task_propagate_int(task, &error);
    if(error) {
        fpi_device_open_complete(FP_DEVICE(tdev), error);
        return;
    }

    //Complete the action
    fpi_device_open_complete(FP_DEVICE(tdev), NULL);
}

void fpi_device_tudor_open(FpDevice *dev) {
    //Close the USB device
    GError *error = NULL;
    if(!g_usb_device_close(fpi_device_get_usb_device(dev), &error)) {
        fpi_device_open_complete(dev, error);
        return;
    }

    //Open the device
    open_device(FPI_DEVICE_TUDOR(dev), dev_open_cb, NULL);
}

void fpi_device_tudor_close(FpDevice *dev) {
    //Open the USB device
    GError *error = NULL;
    if(!g_usb_device_open(fpi_device_get_usb_device(dev), &error)) {
        fpi_device_close_complete(dev, error);
        return;
    }

    fpi_device_close_complete(dev, NULL);
}
