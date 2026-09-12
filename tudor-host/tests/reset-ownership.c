#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <tudor/state-proto.h>

#include "reset-ownership.h"

#define MAX_STORES 4

struct store_event {
    char name[TUDOR_STATE_PROPERTY_NAME_SIZE + 1];
    enum tudor_state_value_type type;
    uint8_t data[sizeof(uint32_t)];
    size_t size;
};

struct mock_value {
    bool found;
    enum tudor_state_value_type type;
    uint8_t data[sizeof(uint32_t)];
    size_t size;
};

static struct {
    struct mock_value request;
    struct mock_value result;
    bool reset_success;
    unsigned int reset_calls;
    struct store_event stores[MAX_STORES];
    size_t store_count;
} mock;

static void reset_mock(void) {
    memset(&mock, 0, sizeof(mock));
    mock.request.type = TUDOR_STATE_VALUE_BOOL;
    mock.result.type = TUDOR_STATE_VALUE_UINT32;
}

static bool mock_get_state(const char *name,
                           enum tudor_state_value_type *type,
                           void **data, size_t *data_size) {
    struct mock_value *value;
    if(strcmp(name, TUDOR_STATE_RESET_OWNERSHIP_REQUEST) == 0)
        value = &mock.request;
    else if(strcmp(name, TUDOR_STATE_RESET_OWNERSHIP_RESULT) == 0)
        value = &mock.result;
    else
        g_assert_not_reached();
    if(!value->found) return false;

    *type = value->type;
    *data_size = value->size;
    *data = value->size ? malloc(value->size) : NULL;
    g_assert_true(!value->size || *data != NULL);
    if(value->size) memcpy(*data, value->data, value->size);
    return true;
}

static void mock_set_state(const char *name,
                           enum tudor_state_value_type type,
                           const void *data, size_t data_size) {
    g_assert_cmpuint(mock.store_count, <, MAX_STORES);
    g_assert_cmpuint(data_size, <=, sizeof(mock.stores[0].data));
    struct store_event *event = &mock.stores[mock.store_count++];
    g_strlcpy(event->name, name, sizeof(event->name));
    event->type = type;
    event->size = data_size;
    if(data_size) memcpy(event->data, data, data_size);
}

static uint32_t event_uint(const struct store_event *event) {
    uint32_t value;
    g_assert_cmpuint(event->size, ==, sizeof(value));
    memcpy(&value, event->data, sizeof(value));
    return value;
}

static bool mock_reset_ownership(void) {
    mock.reset_calls++;

    /* All state transitions that make the operation one-shot must be
     * durable before vendor code is entered. */
    g_assert_cmpuint(mock.store_count, ==, 3);
    g_assert_cmpstr(mock.stores[0].name, ==,
                    TUDOR_STATE_RESET_OWNERSHIP_RESULT);
    g_assert_cmpint(mock.stores[0].type, ==, TUDOR_STATE_VALUE_UINT32);
    g_assert_cmpuint(event_uint(&mock.stores[0]), ==,
                     TUDOR_RESET_OWNERSHIP_RESULT_IN_PROGRESS);
    g_assert_cmpstr(mock.stores[1].name, ==,
                    TUDOR_STATE_RESET_OWNERSHIP_REQUEST);
    g_assert_cmpint(mock.stores[1].type, ==, TUDOR_STATE_VALUE_BOOL);
    g_assert_cmpuint(mock.stores[1].size, ==, sizeof(uint8_t));
    g_assert_cmpuint(mock.stores[1].data[0], ==, 0);
    g_assert_cmpstr(mock.stores[2].name, ==, "SetOwnershipFailureCount");
    g_assert_cmpint(mock.stores[2].type, ==, TUDOR_STATE_VALUE_UINT32);
    g_assert_cmpuint(event_uint(&mock.stores[2]), ==, 0);
    return mock.reset_success;
}

static void test_not_requested(void) {
    reset_mock();
    g_assert_cmpint(tudor_host_process_reset_ownership(
        mock_get_state, mock_set_state, mock_reset_ownership), ==,
        TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED);
    g_assert_cmpuint(mock.store_count, ==, 0);
    g_assert_cmpuint(mock.reset_calls, ==, 0);

    mock.request.found = true;
    mock.request.size = sizeof(uint8_t);
    mock.request.data[0] = 0;
    g_assert_cmpint(tudor_host_process_reset_ownership(
        mock_get_state, mock_set_state, mock_reset_ownership), ==,
        TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED);
    g_assert_cmpuint(mock.store_count, ==, 0);
    g_assert_cmpuint(mock.reset_calls, ==, 0);
}

static void test_invalid_request(void) {
    reset_mock();
    mock.request.found = true;
    mock.request.type = TUDOR_STATE_VALUE_UINT32;
    mock.request.size = sizeof(uint32_t);
    mock.request.data[0] = 1;
    g_assert_cmpint(tudor_host_process_reset_ownership(
        mock_get_state, mock_set_state, mock_reset_ownership), ==,
        TUDOR_HOST_RESET_OWNERSHIP_INVALID_REQUEST);
    g_assert_cmpuint(mock.store_count, ==, 0);
    g_assert_cmpuint(mock.reset_calls, ==, 0);
}

static void set_result(uint32_t result) {
    mock.result.found = true;
    mock.result.size = sizeof(result);
    memcpy(mock.result.data, &result, sizeof(result));
}

static void test_cleanup_barrier(void) {
    const uint32_t blocked_results[] = {
        TUDOR_RESET_OWNERSHIP_RESULT_IN_PROGRESS,
        TUDOR_RESET_OWNERSHIP_RESULT_SUCCEEDED,
        TUDOR_RESET_OWNERSHIP_RESULT_FAILED
    };
    for(size_t i = 0; i < G_N_ELEMENTS(blocked_results); i++) {
        reset_mock();
        set_result(blocked_results[i]);
        /* Even an enabled request cannot cross an existing result barrier. */
        mock.request.found = true;
        mock.request.size = sizeof(uint8_t);
        mock.request.data[0] = 1;
        g_assert_cmpint(tudor_host_process_reset_ownership(
            mock_get_state, mock_set_state, mock_reset_ownership), ==,
            TUDOR_HOST_RESET_OWNERSHIP_CLEANUP_PENDING);
        g_assert_cmpuint(mock.store_count, ==, 0);
        g_assert_cmpuint(mock.reset_calls, ==, 0);
    }

    reset_mock();
    set_result(TUDOR_RESET_OWNERSHIP_RESULT_NONE);
    g_assert_cmpint(tudor_host_process_reset_ownership(
        mock_get_state, mock_set_state, mock_reset_ownership), ==,
        TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED);

    reset_mock();
    set_result(TUDOR_RESET_OWNERSHIP_RESULT_FAILED + 1);
    g_assert_cmpint(tudor_host_process_reset_ownership(
        mock_get_state, mock_set_state, mock_reset_ownership), ==,
        TUDOR_HOST_RESET_OWNERSHIP_INVALID_REQUEST);
}

static void assert_terminal_result(bool success) {
    reset_mock();
    mock.request.found = true;
    mock.request.size = sizeof(uint8_t);
    mock.request.data[0] = 1;
    mock.reset_success = success;

    enum tudor_host_reset_ownership_outcome outcome =
        tudor_host_process_reset_ownership(
            mock_get_state, mock_set_state, mock_reset_ownership);
    g_assert_cmpint(outcome, ==,
        success ? TUDOR_HOST_RESET_OWNERSHIP_SUCCEEDED
                : TUDOR_HOST_RESET_OWNERSHIP_FAILED);
    g_assert_cmpuint(mock.reset_calls, ==, 1);
    g_assert_cmpuint(mock.store_count, ==, 4);
    g_assert_cmpstr(mock.stores[3].name, ==,
                    TUDOR_STATE_RESET_OWNERSHIP_RESULT);
    g_assert_cmpint(mock.stores[3].type, ==, TUDOR_STATE_VALUE_UINT32);
    g_assert_cmpuint(event_uint(&mock.stores[3]), ==,
        success ? TUDOR_RESET_OWNERSHIP_RESULT_SUCCEEDED
                : TUDOR_RESET_OWNERSHIP_RESULT_FAILED);
}

static void test_success(void) {
    assert_terminal_result(true);
}

static void test_failure(void) {
    assert_terminal_result(false);
}

int main(int argc, char **argv) {
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/reset-ownership/not-requested", test_not_requested);
    g_test_add_func("/reset-ownership/invalid-request", test_invalid_request);
    g_test_add_func("/reset-ownership/cleanup-barrier",
                    test_cleanup_barrier);
    g_test_add_func("/reset-ownership/success", test_success);
    g_test_add_func("/reset-ownership/failure", test_failure);
    return g_test_run();
}
