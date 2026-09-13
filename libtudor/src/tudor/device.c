#include <unistd.h>
#include "internal.h"

/* HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED), returned by the vendor's
 * WUDF cancellation callback.  A stalled capture uses this status to request
 * a fresh capture while other transport failures remain fatal. */
#define TUDOR_CAPTURE_RESTART_STATUS ((NTSTATUS) 0x800703e3u)

bool tudor_enroll_start(struct tudor_device *device, RECGUID guid, enum tudor_finger finger) {
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hres;

    if(device->enrolling) {
        log_error("Already enrolling a finger!");
        return false;
    }

    //Follow https://docs.microsoft.com/en-us/windows/win32/secbiomet/adapter-workflow - WinBioEnrollBegin
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->ClearContext, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->ClearContext, device->pipeline);
    WINBIO_CALL_PIPELINE(device->pipeline->StorageInterface->ClearContext, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->CreateEnrollment, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->SetEnrollmentParameters, device->pipeline, &(WINBIO_EXTENDED_ENROLLMENT_PARAMETERS) {
        .Size = sizeof(WINBIO_EXTENDED_ENROLLMENT_PARAMETERS),
        .SubFactor = (UCHAR) finger
    });

    device->enrolling = true;
    device->enroll_guid = guid;
    device->enroll_finger = finger;
    return true;
}

static void enroll_cb(OVERLAPPED *ovlp, NTSTATUS status, void *context) {
    tudor_async_res_t res = context;
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hres;
    bool success = false, done = true;

    if(status != STATUS_SUCCESS) {
        log_error("Error starting capture: 0x%x!", status);
        if(status == TUDOR_CAPTURE_RESTART_STATUS) done = false;
        goto exit;
    }

    //Follow https://docs.microsoft.com/en-us/windows/win32/secbiomet/adapter-workflow - WinBioEnrollCapture
    ULONG reject_detail;
    if((hres = tudor_sensor_adapter->FinishCapture(res->dev->pipeline, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) done = false;
        log_error("Error finishing sensor capture: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };
    if((hres = tudor_sensor_adapter->PushDataToEngine(res->dev->pipeline, WINBIO_PURPOSE_ENROLL, 0, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) done = false;
        log_error("Error pushing sensor data to engine: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };

    log_debug("Updating enrollment...");
    if((hres = tudor_engine_adapter->UpdateEnrollment(res->dev->pipeline, &reject_detail)) != ERROR_SUCCESS && hres != WINBIO_I_MORE_DATA) {
        if(hres == WINBIO_E_BAD_CAPTURE) done = false;
        log_error("Error updating enrollment: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };

    success = true;
    done = hres != WINBIO_I_MORE_DATA;

    exit:;
    *res->args.enroll.done = done;
    async_complete_op(res, success);
}

bool tudor_enroll_capture(struct tudor_device *device, bool *done, tudor_async_res_t *res) {
    winmodule_set_cur(&tudor_adapter_dll->module);
    *res = NULL;
    HRESULT hres;

    *done = true;
    if(!device->enrolling) {
        log_error("Not currently enrolling a finger!");
        return false;
    }

    log_debug("Capturing sample...");
    OVERLAPPED *ovlp;
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->StartCapture, device->pipeline, WINBIO_PURPOSE_ENROLL, &ovlp);

    *res = async_new_res(device, ovlp);
    (*res)->args.enroll = (struct async_args_enroll) { .done = done };
    winio_set_overlapped_callback(ovlp, enroll_cb, *res, true);
    return true;
}

bool tudor_enroll_commit(struct tudor_device *device, bool *is_duplicate) {
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hres;

    *is_duplicate = false;
    if(!device->enrolling) {
        log_error("Not currently enrolling a finger!");
        return false;
    }

    //Follow https://docs.microsoft.com/en-us/windows/win32/secbiomet/adapter-workflow - WinBioEnrollCommit
    log_debug("Checking for duplicate enrollment...");
    BOOLEAN is_dupl;
    WINBIO_IDENTITY dupl_ident;
    UCHAR dupl_finger;
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->CheckForDuplicate, device->pipeline, &dupl_ident, &dupl_finger, &is_dupl);
    if(is_dupl) {
        *is_duplicate = true;
        return false;
    }

    log_debug("Committing enrollment...");

    //The driver doesn't support enrollment hashes (so we don't call GetEnrollmentHash)
    if((hres = tudor_engine_adapter->CommitEnrollment(device->pipeline, &(WINBIO_IDENTITY) {
        .Type = WINBIO_ID_TYPE_GUID,
        .TemplateGuid = winbio_guid(device->enroll_guid)
    }, (UCHAR) device->enroll_finger, NULL, 0)) != ERROR_SUCCESS) {
        log_error("Error commiting enrollment: 0x%x!", hres);
        if(hres == WINBIO_E_DUPLICATE_ENROLLMENT) *is_duplicate = true;
        return false;
    }

    /* RefreshCache is an optional tail method.  Failure must not turn a
     * committed sensor-side enrollment into a reported enrollment failure. */
    tudor_refresh_native_storage_cache(device);

    device->enrolling = false;
    return true;
}

bool tudor_enroll_discard(struct tudor_device *device) {
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hres;

    if(!device->enrolling) {
        log_error("Not currently enrolling a finger!");
        return false;
    }

    log_info("Discarding enrollment of guid=%08x... finger=%x", device->enroll_guid.PartA, device->enroll_finger);

    //Follow https://docs.microsoft.com/en-us/windows/win32/secbiomet/adapter-workflow - WinBioEnrollDiscard
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->DiscardEnrollment, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_engine_adapter->ClearContext, device->pipeline);
    WINBIO_CALL_PIPELINE(device->pipeline->StorageInterface->ClearContext, device->pipeline);
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->ClearContext, device->pipeline);

    device->enrolling = false;
    return true;
}

static void verify_cb(OVERLAPPED *ovlp, NTSTATUS status, void *context) {
    tudor_async_res_t res = context;
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hres;
    bool success = false, matches = false;
    enum tudor_capture_retry retry = TUDOR_RETRY_NONE;

    if(status != STATUS_SUCCESS) {
        log_error("Error starting capture: 0x%x!", status);
        if(status == TUDOR_CAPTURE_RESTART_STATUS) retry = TUDOR_RETRY_CAPTURE_RESTART;
        goto exit;
    }

    ULONG reject_detail;
    if((hres = tudor_sensor_adapter->FinishCapture(res->dev->pipeline, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) retry = TUDOR_RETRY_SCAN;
        log_error("Error finishing sensor capture: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };
    if((hres = tudor_sensor_adapter->PushDataToEngine(res->dev->pipeline, WINBIO_PURPOSE_VERIFY, 0, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) retry = TUDOR_RETRY_SCAN;
        log_error("Error pushing sensor data to engine: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };

    log_debug("Verifying sample...");
    BOOLEAN is_match;
    UCHAR *payload_ptr, *hash_ptr;
    SIZE_T payload_size, hash_size;
    if((hres = tudor_engine_adapter->VerifyFeatureSet(res->dev->pipeline, &(WINBIO_IDENTITY) {
        .Type = WINBIO_ID_TYPE_GUID,
        .TemplateGuid = winbio_guid(res->args.verify.guid)
    }, (UCHAR) res->args.verify.finger, &is_match, &payload_ptr, &payload_size, &hash_ptr, &hash_size, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) retry = TUDOR_RETRY_SCAN;
        if(hres == WINBIO_E_NO_MATCH) {
            success = true;
            matches = false;
            goto exit;
        }

        log_error("Error verifying sample: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };

    success = true;
    matches = is_match;

    exit:;
    *(res->args.verify.retry) = retry;
    *(res->args.verify.matches) = matches;
    async_complete_op(res, success);
}

bool tudor_verify(struct tudor_device *device, RECGUID guid, enum tudor_finger finger, enum tudor_capture_retry *retry, bool *matches, tudor_async_res_t *res) {
    winmodule_set_cur(&tudor_adapter_dll->module);
    *res = NULL;
    HRESULT hres;

    *retry = TUDOR_RETRY_NONE;
    *matches = false;
    if(device->enrolling) {
        log_error("Currently enrolling a finger!");
        return false;
    }

    log_debug("Capturing sample...");
    OVERLAPPED *ovlp;
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->StartCapture, device->pipeline, WINBIO_PURPOSE_VERIFY, &ovlp);

    *res = async_new_res(device, ovlp);
    (*res)->args.verify = (struct async_args_verify) { .retry = retry, .guid = guid, .finger = finger, .matches = matches };
    winio_set_overlapped_callback(ovlp, verify_cb, *res, true);
    return true;
}

static void identify_cb(OVERLAPPED *ovlp, NTSTATUS status, void *context) {
    tudor_async_res_t res = context;
    winmodule_set_cur(&tudor_adapter_dll->module);
    HRESULT hres;
    bool success = false, found_match = false;
    enum tudor_capture_retry retry = TUDOR_RETRY_NONE;

    if(status != STATUS_SUCCESS) {
        log_error("Error starting capture: 0x%x!", status);
        if(status == TUDOR_CAPTURE_RESTART_STATUS) retry = TUDOR_RETRY_CAPTURE_RESTART;
        goto exit;
    }

    ULONG reject_detail;
    if((hres = tudor_sensor_adapter->FinishCapture(res->dev->pipeline, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) retry = TUDOR_RETRY_SCAN;
        log_error("Error finishing sensor capture: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };
    if((hres = tudor_sensor_adapter->PushDataToEngine(res->dev->pipeline, WINBIO_PURPOSE_IDENTIFY, 0, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) retry = TUDOR_RETRY_SCAN;
        log_error("Error pushing sensor data to engine: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };

    log_debug("Identifying sample...");
    WINBIO_IDENTITY identity;
    UCHAR subfactor;
    UCHAR *payload_ptr, *hash_ptr;
    SIZE_T payload_size, hash_size;
    if((hres = tudor_engine_adapter->IdentifyFeatureSet(res->dev->pipeline, &identity, &subfactor, &payload_ptr, &payload_size, &hash_ptr, &hash_size, &reject_detail)) != ERROR_SUCCESS) {
        if(hres == WINBIO_E_BAD_CAPTURE) retry = TUDOR_RETRY_SCAN;
        if(hres == WINBIO_E_UNKNOWN_ID) {
            success = true;
            found_match = false;
            goto exit;
        }

        log_error("Error identifying sample: 0x%x! [reject detail 0x%x]", hres, reject_detail);
        goto exit;
    };
    if(identity.Type != WINBIO_ID_TYPE_GUID) {
        log_error("Invalid identification ID type: %d!", identity.Type);
        goto exit;
    }

    success = true;
    found_match = true;
    *(res->args.identify.guid) = tudor_guid(identity.TemplateGuid);
    *(res->args.identify.finger) = (enum tudor_finger) subfactor;

    exit:;
    *(res->args.identify.retry) = retry;
    *(res->args.identify.found_match) = found_match;
    async_complete_op(res, success);
}

bool tudor_identify(struct tudor_device *device, enum tudor_capture_retry *retry, bool *found_match, RECGUID *guid, enum tudor_finger *finger, tudor_async_res_t *res) {
    winmodule_set_cur(&tudor_adapter_dll->module);
    *res = NULL;
    HRESULT hres;

    *retry = TUDOR_RETRY_NONE;
    *found_match = false;
    if(device->enrolling) {
        log_error("Currently enrolling a finger!");
        return false;
    }

    log_debug("Capturing sample...");
    OVERLAPPED *ovlp;
    WINBIO_CALL_PIPELINE(tudor_sensor_adapter->StartCapture, device->pipeline, WINBIO_PURPOSE_IDENTIFY, &ovlp);

    *res = async_new_res(device, ovlp);
    (*res)->args.identify = (struct async_args_identify) { .retry = retry, .found_match = found_match, .guid = guid, .finger = finger };
    winio_set_overlapped_callback(ovlp, identify_cb, *res, true);
    return true;
}
