#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <gio/gio.h>
#include <glib-unix.h>
#include <glib/gstdio.h>
#include <tudor/state-proto.h>

#include "state.h"

static gchar *state_root;

static void wipe_bytes(void *data, size_t size) {
    volatile unsigned char *bytes = data;
    while(size--) *bytes++ = 0;
}

static const char *const allowed_properties[] = {
    "CalibrationData",
    "CryptoRegistry",
    "IdleInWorkingState",
    "LastUpdateSystemTimeStamp",
    "OldCalDataDeleted",
    "PairingContext",
    "PairingData",
    "SecureChannelIdentity",
    "SetOwnershipFailureCount",
    "SystemWakeEnabled",
    "UnpairingContext",
    "UpdateFirmwareFailureCount",
    "WakeFromSleepState",
    "deviceInitializeFailures",
    NULL
};

gboolean state_id_is_valid(const char *id) {
    if(!id) return false;
    size_t len = strnlen(id, TUDOR_STATE_ID_SIZE + 1);
    if(!len || len > TUDOR_STATE_ID_SIZE) return false;
    for(size_t i = 0; i < len; i++) {
        unsigned char c = id[i];
        if(!g_ascii_isalnum(c) && c != '-') return false;
    }
    return true;
}

static bool valid_property_name(const char *name) {
    size_t len = strnlen(name, TUDOR_STATE_PROPERTY_NAME_SIZE + 1);
    if(!len || len > TUDOR_STATE_PROPERTY_NAME_SIZE) return false;
    for(size_t i = 0; allowed_properties[i]; i++) {
        if(strcmp(name, allowed_properties[i]) == 0) return true;
    }
    return false;
}

static gchar *device_dir_path(const char *state_id) {
    return g_build_filename(state_root, "devices", state_id, NULL);
}

static const char *state_extension(enum tudor_state_value_type type) {
    switch(type) {
        case TUDOR_STATE_VALUE_UINT32: return ".uint";
        case TUDOR_STATE_VALUE_BLOB: return ".blob";
        case TUDOR_STATE_VALUE_BOOL: return ".bool";
        default: return NULL;
    }
}

static gchar *state_file_path(const char *state_id, const char *name,
                              enum tudor_state_value_type type) {
    gchar *dir = device_dir_path(state_id);
    gchar *base = g_strconcat(name, state_extension(type), NULL);
    gchar *path = g_build_filename(dir, base, NULL);
    g_free(base);
    g_free(dir);
    return path;
}

static gboolean write_private_file(const char *path, const void *data,
                                   gsize size, GError **error) {
    GFile *file = g_file_new_for_path(path);
    GFileOutputStream *stream = g_file_replace(
        file, NULL, FALSE,
        G_FILE_CREATE_PRIVATE | G_FILE_CREATE_REPLACE_DESTINATION,
        NULL, error);
    g_object_unref(file);
    if(!stream) return FALSE;

    char empty = 0;
    gboolean success = g_output_stream_write_all(
        G_OUTPUT_STREAM(stream), size ? data : &empty, size,
        NULL, NULL, error);
    if(success) {
        success = g_output_stream_close(G_OUTPUT_STREAM(stream), NULL, error);
    } else {
        g_output_stream_close(G_OUTPUT_STREAM(stream), NULL, NULL);
    }
    g_object_unref(stream);
    return success;
}

static gboolean store_state_value(const char *state_id, const char *name,
                                  enum tudor_state_value_type type,
                                  const void *data, gsize size,
                                  GError **error) {
    if(type == TUDOR_STATE_VALUE_UINT32 && size != sizeof(uint32_t)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "A uint state value must contain four bytes");
        return FALSE;
    }
    if(type == TUDOR_STATE_VALUE_BOOL &&
       (size != sizeof(uint8_t) || !data || *(const uint8_t*) data > 1)) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "A bool state value must be one byte containing 0 or 1");
        return FALSE;
    }
    if(type != TUDOR_STATE_VALUE_UINT32 &&
       type != TUDOR_STATE_VALUE_BLOB &&
       type != TUDOR_STATE_VALUE_BOOL) {
        g_set_error_literal(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                            "Unknown state value type");
        return FALSE;
    }

    gchar *dir = device_dir_path(state_id);
    if(g_mkdir_with_parents(dir, 0700) < 0) {
        int err = errno;
        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(err),
                    "Failed to create state directory '%s': %s",
                    dir, g_strerror(err));
        g_free(dir);
        return FALSE;
    }
    if(g_chmod(dir, 0700) < 0) {
        int err = errno;
        g_set_error(error, G_IO_ERROR, g_io_error_from_errno(err),
                    "Failed to protect state directory '%s': %s",
                    dir, g_strerror(err));
        g_free(dir);
        return FALSE;
    }
    g_free(dir);

    gchar *path = state_file_path(state_id, name, type);
    gboolean success;
    if(type == TUDOR_STATE_VALUE_UINT32) {
        uint32_t value;
        memcpy(&value, data, sizeof(value));
        gchar *text = g_strdup_printf("%u\n", value);
        success = write_private_file(path, text, strlen(text), error);
        g_free(text);
    } else if(type == TUDOR_STATE_VALUE_BOOL) {
        const char text[] = {
            *(const uint8_t*) data ? '1' : '0', '\n'
        };
        success = write_private_file(path, text, sizeof(text), error);
    } else {
        success = write_private_file(path, data, size, error);
    }
    g_free(path);
    if(!success) return FALSE;

    const enum tudor_state_value_type value_types[] = {
        TUDOR_STATE_VALUE_BLOB,
        TUDOR_STATE_VALUE_UINT32,
        TUDOR_STATE_VALUE_BOOL
    };
    for(size_t i = 0; i < G_N_ELEMENTS(value_types); i++) {
        if(value_types[i] == type) continue;
        gchar *old_path = state_file_path(state_id, name, value_types[i]);
        if(g_unlink(old_path) < 0 && errno != ENOENT)
            g_warning("Failed to remove stale state file '%s': %s",
                      old_path, g_strerror(errno));
        g_free(old_path);
    }

    return TRUE;
}

static gboolean load_uint_file(const char *path, void **data, gsize *size,
                               GError **error) {
    gchar *text;
    gsize text_size;
    if(!g_file_get_contents(path, &text, &text_size, error)) return FALSE;

    errno = 0;
    char *end;
    guint64 parsed = g_ascii_strtoull(text, &end, 10);
    while(*end && g_ascii_isspace(*end)) end++;
    if(errno || end == text || *end || parsed > G_MAXUINT32) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "Invalid uint state file '%s'", path);
        g_free(text);
        return FALSE;
    }
    g_free(text);

    uint32_t *value = g_new(uint32_t, 1);
    *value = (uint32_t) parsed;
    *data = value;
    *size = sizeof(*value);
    return TRUE;
}

static gboolean load_bool_file(const char *path, void **data, gsize *size,
                               GError **error) {
    gchar *text;
    gsize text_size;
    if(!g_file_get_contents(path, &text, &text_size, error)) return FALSE;

    if(text_size != 2 || (text[0] != '0' && text[0] != '1') ||
       text[1] != '\n') {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "Invalid bool state file '%s'", path);
        g_free(text);
        return FALSE;
    }

    uint8_t *value = g_new(uint8_t, 1);
    *value = (uint8_t) (text[0] - '0');
    g_free(text);
    *data = value;
    *size = sizeof(*value);
    return TRUE;
}

static gboolean load_blob_file(const char *path, void **data, gsize *size,
                               GError **error) {
    gchar *contents;
    if(!g_file_get_contents(path, &contents, size, error)) return FALSE;
    if(*size > TUDOR_STATE_MAX_VALUE_SIZE) {
        g_set_error(error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                    "State file '%s' exceeds %u bytes", path,
                    TUDOR_STATE_MAX_VALUE_SIZE);
        wipe_bytes(contents, *size);
        g_free(contents);
        return FALSE;
    }
    *data = contents;
    return TRUE;
}

static gboolean load_state_value(const char *state_id, const char *name,
                                 gboolean *found,
                                 enum tudor_state_value_type *type,
                                 void **data, gsize *size, GError **error) {
    *found = FALSE;
    *data = NULL;
    *size = 0;

    const enum tudor_state_value_type types[] = {
        TUDOR_STATE_VALUE_BLOB,
        TUDOR_STATE_VALUE_UINT32,
        TUDOR_STATE_VALUE_BOOL
    };
    for(size_t i = 0; i < G_N_ELEMENTS(types); i++) {
        gchar *path = state_file_path(state_id, name, types[i]);
        gboolean exists = g_file_test(path, G_FILE_TEST_EXISTS);
        if(!exists) {
            g_free(path);
            continue;
        }

        gboolean success;
        switch(types[i]) {
            case TUDOR_STATE_VALUE_BLOB:
                success = load_blob_file(path, data, size, error);
                break;
            case TUDOR_STATE_VALUE_UINT32:
                success = load_uint_file(path, data, size, error);
                break;
            case TUDOR_STATE_VALUE_BOOL:
                success = load_bool_file(path, data, size, error);
                break;
            default:
                g_assert_not_reached();
        }
        g_free(path);
        if(!success) return FALSE;
        /* CalibrationData is generated by the sensor driver.  It can write an
         * empty blob as an intermediate value, which must look missing after
         * an interrupted calibration so the next start retries.  Other empty
         * blobs, especially PairingData, remain meaningful presence markers. */
        if(types[i] == TUDOR_STATE_VALUE_BLOB && *size == 0 &&
           strcmp(name, "CalibrationData") == 0) {
            g_free(*data);
            *data = NULL;
            return TRUE;
        }
        *found = TRUE;
        *type = types[i];
        return TRUE;
    }

    /* A single top-level calibration file is the installation/bootstrap
     * format.  Copy it into the first sensor-specific directory on use. */
    if(strcmp(name, "CalibrationData") == 0) {
        gchar *legacy_path = g_build_filename(
            state_root, "CalibrationData.blob", NULL);
        if(g_file_test(legacy_path, G_FILE_TEST_EXISTS)) {
            if(!load_blob_file(legacy_path, data, size, error)) {
                g_free(legacy_path);
                return FALSE;
            }
            if(*size == 0) {
                g_free(*data);
                *data = NULL;
                g_free(legacy_path);
                return TRUE;
            }
            *found = TRUE;
            *type = TUDOR_STATE_VALUE_BLOB;

            GError *migration_error = NULL;
            if(!store_state_value(state_id, name, *type, *data, *size,
                                  &migration_error)) {
                g_warning("Loaded bootstrap calibration but could not copy it "
                          "to sensor state: %s", migration_error->message);
                g_clear_error(&migration_error);
            }
        }
        g_free(legacy_path);
    }

    return TRUE;
}

static gboolean send_packet(int fd, const void *data, size_t size) {
    ssize_t sent = write(fd, data, size);
    if(sent == (ssize_t) size) return TRUE;
    if(sent < 0)
        g_warning("Failed to send Tudor state response: %s", g_strerror(errno));
    else
        g_warning("Sent a truncated Tudor state response");
    return FALSE;
}

static gboolean handle_load(int fd, const char *state_id,
                            const void *buf, size_t size) {
    if(size != sizeof(struct tudor_state_load_request)) return FALSE;
    const struct tudor_state_load_request *req = buf;
    gboolean valid_id = state_id_is_valid(req->state_id);
    gboolean matching_id = valid_id && strcmp(req->state_id, state_id) == 0;
    if(!matching_id || !valid_property_name(req->name)) {
        const struct tudor_state_load_response resp = {
            .type = TUDOR_STATE_MSG_LOAD_RESPONSE,
            .status = valid_id && !matching_id ? -EPERM : -EINVAL,
            .found = FALSE,
            .value_type = 0
        };
        return send_packet(fd, &resp, sizeof(resp));
    }

    gboolean found;
    enum tudor_state_value_type value_type = 0;
    void *value = NULL;
    gsize value_size = 0;
    GError *error = NULL;
    gboolean success = load_state_value(req->state_id, req->name, &found,
                                        &value_type, &value, &value_size,
                                        &error);
    size_t resp_size = sizeof(struct tudor_state_load_response) +
                       (success && found ? value_size : 0);
    struct tudor_state_load_response *resp = g_malloc0(resp_size);
    resp->type = TUDOR_STATE_MSG_LOAD_RESPONSE;
    resp->status = success ? 0 : -EIO;
    resp->found = success && found;
    resp->value_type = success && found ? value_type : 0;
    if(success && found && value_size)
        memcpy(resp->data, value, value_size);

    if(error) {
        g_warning("Failed to load state '%s/%s': %s", req->state_id,
                  req->name, error->message);
        g_clear_error(&error);
    }
    if(value) wipe_bytes(value, value_size);
    g_free(value);
    gboolean sent = send_packet(fd, resp, resp_size);
    wipe_bytes(resp, resp_size);
    g_free(resp);
    return sent;
}

static gboolean handle_store(int fd, const char *state_id,
                             const void *buf, size_t size) {
    if(size < sizeof(struct tudor_state_store_request)) return FALSE;
    const struct tudor_state_store_request *req = buf;
    size_t value_size = size - sizeof(*req);
    gboolean valid_id = state_id_is_valid(req->state_id);
    gboolean matching_id = valid_id && strcmp(req->state_id, state_id) == 0;
    if(!matching_id || !valid_property_name(req->name) ||
       value_size > TUDOR_STATE_MAX_VALUE_SIZE) {
        const struct tudor_state_store_response resp = {
            .type = TUDOR_STATE_MSG_STORE_RESPONSE,
            .status = valid_id && !matching_id ? -EPERM : -EINVAL
        };
        return send_packet(fd, &resp, sizeof(resp));
    }

    GError *error = NULL;
    gboolean success = store_state_value(
        req->state_id, req->name,
        (enum tudor_state_value_type) req->value_type,
        req->data, value_size, &error);
    struct tudor_state_store_response resp = {
        .type = TUDOR_STATE_MSG_STORE_RESPONSE,
        .status = success ? 0 : -EIO
    };
    if(error) {
        g_warning("Failed to store state '%s/%s': %s", req->state_id,
                  req->name, error->message);
        g_clear_error(&error);
    }
    return send_packet(fd, &resp, sizeof(resp));
}

static gboolean state_socket_ready(gint fd, GIOCondition condition,
                                   gpointer user_data) {
    const char *state_id = user_data;
    if(!(condition & G_IO_IN)) return G_SOURCE_REMOVE;

    void *buf = g_malloc(TUDOR_STATE_MAX_MESSAGE_SIZE + 1);
    ssize_t size = read(fd, buf, TUDOR_STATE_MAX_MESSAGE_SIZE + 1);
    if(size <= 0 || (size_t) size > TUDOR_STATE_MAX_MESSAGE_SIZE) {
        if(size < 0)
            g_warning("Failed to receive Tudor state request: %s",
                      g_strerror(errno));
        if(size > 0) wipe_bytes(buf, (size_t) size);
        g_free(buf);
        return G_SOURCE_REMOVE;
    }

    gboolean keep;
    uint32_t type;
    if((size_t) size < sizeof(type)) {
        keep = FALSE;
    } else {
        memcpy(&type, buf, sizeof(type));
        switch(type) {
            case TUDOR_STATE_MSG_LOAD:
                keep = handle_load(fd, state_id, buf, size);
                break;
            case TUDOR_STATE_MSG_STORE:
                keep = handle_store(fd, state_id, buf, size);
                break;
            default:
                keep = FALSE;
        }
    }
    if(!keep) {
        g_warning("Closing invalid Tudor state channel");
        shutdown(fd, SHUT_RDWR);
    }
    wipe_bytes(buf, (size_t) size);
    g_free(buf);
    return keep ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

guint state_socket_watch(int fd, const char *state_id) {
    g_return_val_if_fail(state_id_is_valid(state_id), 0);
    return g_unix_fd_add_full(
        G_PRIORITY_DEFAULT, fd,
        G_IO_IN | G_IO_HUP | G_IO_ERR | G_IO_NVAL,
        state_socket_ready, g_strdup(state_id), g_free);
}

void init_state(void) {
    const gchar *dir = g_getenv("STATE_DIRECTORY");
    if(!dir || !dir[0]) g_error("State directory environment variable not set!");
    state_root = g_strdup(dir);

    gchar *devices_dir = g_build_filename(state_root, "devices", NULL);
    if(g_mkdir_with_parents(devices_dir, 0700) < 0)
        g_error("Failed to create Tudor device-state directory '%s': %s",
                devices_dir, g_strerror(errno));
    if(g_chmod(devices_dir, 0700) < 0)
        g_error("Failed to protect Tudor device-state directory '%s': %s",
                devices_dir, g_strerror(errno));
    g_free(devices_dir);
}

void uninit_state(void) {
    g_clear_pointer(&state_root, g_free);
}
