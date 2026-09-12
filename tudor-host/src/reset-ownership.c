#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <tudor/state-proto.h>

#include "reset-ownership.h"

static void wipe_bytes(void *data, size_t size) {
    volatile unsigned char *bytes = data;
    while(size--) *bytes++ = 0;
}

static enum tudor_host_reset_ownership_outcome
check_cleanup_barrier(tudor_host_state_get_fnc get_state) {
    enum tudor_state_value_type type;
    void *data = NULL;
    size_t data_size = 0;
    if(!get_state(TUDOR_STATE_RESET_OWNERSHIP_RESULT, &type, &data,
                  &data_size))
        return TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED;

    uint32_t result = TUDOR_RESET_OWNERSHIP_RESULT_NONE;
    bool valid = type == TUDOR_STATE_VALUE_UINT32 &&
                 data_size == sizeof(result) && data;
    if(valid) {
        memcpy(&result, data, sizeof(result));
        valid = result <= TUDOR_RESET_OWNERSHIP_RESULT_FAILED;
    }
    if(data) {
        wipe_bytes(data, data_size);
        free(data);
    }
    if(!valid) return TUDOR_HOST_RESET_OWNERSHIP_INVALID_REQUEST;

    /* A nonzero result is also a recovery barrier.  The reset host exits
     * before the privileged helper can stop fprintd and discard the old
     * identity.  Reject any automatic reopen until that helper completes
     * local cleanup and removes the result file. */
    return result == TUDOR_RESET_OWNERSHIP_RESULT_NONE
        ? TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED
        : TUDOR_HOST_RESET_OWNERSHIP_CLEANUP_PENDING;
}

enum tudor_host_reset_ownership_outcome
tudor_host_process_reset_ownership(tudor_host_state_get_fnc get_state,
                                   tudor_host_state_set_fnc set_state,
                                   tudor_host_reset_fnc reset_ownership) {
    /* Read the result first.  IN_PROGRESS is the durable transaction barrier:
     * once it exists, neither an enabled nor a consumed request may cause a
     * second reset or allow normal startup with the old local identity. */
    enum tudor_host_reset_ownership_outcome barrier =
        check_cleanup_barrier(get_state);
    if(barrier != TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED)
        return barrier;

    enum tudor_state_value_type type;
    void *data = NULL;
    size_t data_size = 0;
    if(!get_state(TUDOR_STATE_RESET_OWNERSHIP_REQUEST, &type, &data,
                  &data_size))
        return TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED;

    bool valid = type == TUDOR_STATE_VALUE_BOOL &&
                 data_size == sizeof(uint8_t) && data &&
                 *(const uint8_t*) data <= 1;
    bool requested = valid && *(const uint8_t*) data != 0;
    if(data) {
        wipe_bytes(data, data_size);
        free(data);
    }
    if(!valid) return TUDOR_HOST_RESET_OWNERSHIP_INVALID_REQUEST;
    if(!requested) return TUDOR_HOST_RESET_OWNERSHIP_NOT_REQUESTED;

    /* Establish the barrier before consuming the request.  A crash before
     * this point has executed no vendor operation and may retry; a crash at
     * any later point is blocked by the nonzero result. */
    uint32_t result = TUDOR_RESET_OWNERSHIP_RESULT_IN_PROGRESS;
    set_state(TUDOR_STATE_RESET_OWNERSHIP_RESULT, TUDOR_STATE_VALUE_UINT32,
              &result, sizeof(result));

    const uint8_t request_consumed = 0;
    set_state(TUDOR_STATE_RESET_OWNERSHIP_REQUEST, TUDOR_STATE_VALUE_BOOL,
              &request_consumed, sizeof(request_consumed));

    /* The vendor refuses another ownership attempt once this persisted
     * counter reaches its cap.  Recovery has already been durably claimed,
     * so clear the counter before loading vendor code. */
    const uint32_t failure_count = 0;
    set_state("SetOwnershipFailureCount", TUDOR_STATE_VALUE_UINT32,
              &failure_count, sizeof(failure_count));

    bool success = reset_ownership();
    result = success ? TUDOR_RESET_OWNERSHIP_RESULT_SUCCEEDED
                     : TUDOR_RESET_OWNERSHIP_RESULT_FAILED;
    set_state(TUDOR_STATE_RESET_OWNERSHIP_RESULT, TUDOR_STATE_VALUE_UINT32,
              &result, sizeof(result));

    return success ? TUDOR_HOST_RESET_OWNERSHIP_SUCCEEDED
                   : TUDOR_HOST_RESET_OWNERSHIP_FAILED;
}
