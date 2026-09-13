#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <tudor/log.h>
#include "cli.h"

static bool abort_cmd_loop = false;
static void sigint_handler(int sig) {
    if(abort_cmd_loop) {
        log_warn("Forcefully exitting!");
        exit(EXIT_FAILURE);
    }
    abort_cmd_loop = false;
}

static bool wait_capture(tudor_async_res_t res, bool *capture_timed_out) {
    if(capture_timed_out) *capture_timed_out = false;
    const char *timeout_env = secure_getenv("SYNA_TUDOR_CAPTURE_TIMEOUT_SECONDS");
    if(!timeout_env || !timeout_env[0]) return tudor_wait_async(res);

    char *end = NULL;
    unsigned long timeout_seconds = strtoul(timeout_env, &end, 10);
    if(end == timeout_env || *end != '\0' || timeout_seconds == 0 ||
       timeout_seconds > UINT_MAX / 1000) {
        log_warn("Ignoring invalid SYNA_TUDOR_CAPTURE_TIMEOUT_SECONDS='%s'",
                 timeout_env);
        return tudor_wait_async(res);
    }

    bool timed_out = false;
    bool success = tudor_wait_async_timeout(res,
                                             (unsigned int) timeout_seconds * 1000,
                                             &timed_out);
    if(!timed_out) return success;
    if(capture_timed_out) *capture_timed_out = true;

    log_warn("Capture timed out after %lu seconds; cancelling request...",
             timeout_seconds);
    tudor_cancel_async(res);
    (void) tudor_wait_async(res);
    return false;
}

void cli_main_loop(struct tudor_device *device) {
    signal(SIGINT, sigint_handler);

    //Command loop
    while(!abort_cmd_loop) {
        //Read command
        puts("");
        puts("Commands:");
        puts("  e - enroll finger");
        puts("  v - verify finger");
        puts("  i - identify finger");
        puts("  q - query information about enrolled fingers");
        puts("  d - query on-sensor database size");
        puts("  w - wipe enrolled finger(s)");
        puts("  s - shutdown driver");

        printf("> ");
        char cmd = getchar();
        while(!abort_cmd_loop && isspace(cmd)) cmd = getchar();
        if(abort_cmd_loop) break;

        //Execute command
        switch(tolower(cmd)) {
            case 'e': {
                //Read identity GUID
                RECGUID guid = {0};
                printf("Enter identity index: ");
                scanf("%u", &guid.PartA);
                while(!abort_cmd_loop && getchar() != '\n') continue;
                if(abort_cmd_loop) goto cmdend;

                //Read finger
                enum tudor_finger finger;
                printf("Enter finger index (1-5 = right hand thumb - little finger | 6-10 = left hand thumb - little finger): ");
                scanf("%d", (int*) &finger);
                while(!abort_cmd_loop && getchar() != '\n') continue;
                if(abort_cmd_loop) goto cmdend;
                if(finger < TUDOR_FINGER_RH_THUMB || TUDOR_FINGER_LH_LITTLE_FINGER < finger) {
                    printf("Invalid finger index!");
                    goto cmdend;
                }

                //Do enrollment
                if(!tudor_enroll_start(device, guid, finger)) {
                    log_error("Error starting enrollment!");
                    goto cmdend;
                }

                puts("Put your finger on the sensor");
                unsigned int consecutive_timeouts = 0;
                while(true) {
                    //Update enrollment
                    bool is_done;
                    bool timed_out = false;
                    tudor_async_res_t async_res = NULL;
                    if(!tudor_enroll_capture(device, &is_done, &async_res) || !wait_capture(async_res, &timed_out)) {
                        if(async_res) tudor_cleanup_async(async_res);

                        /* Cancelling one capture does not discard the engine's
                         * enrollment. Keep accepted samples through transient
                         * stalls, but bound repeated no-progress attempts. */
                        if(timed_out && ++consecutive_timeouts < 12) {
                            log_warn("Retrying stalled capture; keeping accepted enrollment samples (%u/12 timeouts)",
                                     consecutive_timeouts);
                            puts("Put your finger on the sensor");
                            continue;
                        }

                        if(!is_done) {
                            log_warn("Retrying enrollment update...");
                            puts("Put your finger on the sensor");
                            continue;
                        }

                        log_error("Error capturing sample for enrollment!");
                        tudor_enroll_discard(device);
                        goto cmdend;
                    }
                    tudor_cleanup_async(async_res);
                    consecutive_timeouts = 0;

                    if(is_done) break;
                    puts("Driver requested more samples");
                }

                //Commit the enrollment
                bool is_dupl;
                if(!tudor_enroll_commit(device, &is_dupl)) {
                    if(is_dupl) {
                        log_warn("Detected duplicate enrollment!");
                        tudor_enroll_discard(device);
                        goto cmdend;
                    }

                    log_error("Error commiting enrollment!");
                    tudor_enroll_discard(device);
                    goto cmdend;
                }

                puts("Successfully enrolled finger");
            } goto cmdend;
            case 'v': {
                //Read identity GUID
                RECGUID guid = {0};
                printf("Enter identity index: ");
                scanf("%u", &guid.PartA);
                while(!abort_cmd_loop && getchar() != '\n') continue;
                if(abort_cmd_loop) goto cmdend;

                bool matches;
                puts("Put your finger on the sensor");
                while(true) {
                    //Capture and verify sample
                    enum tudor_capture_retry retry;
                    tudor_async_res_t async_res = NULL;
                    if(!tudor_verify(device, guid, TUDOR_FINGER_ANY, &retry, &matches, &async_res) || !wait_capture(async_res, NULL)) {
                        if(async_res) tudor_cleanup_async(async_res);

                        if(retry) {
                            if(retry == TUDOR_RETRY_SCAN)
                                puts("Scan unsuccessful. Please try again.");
                            continue;
                        }

                        log_error("Error verifying captured sample!");
                        goto cmdend;
                    }
                    tudor_cleanup_async(async_res);
                    break;
                }
                puts(matches ? "VERIFICATION SUCCESS" : "VERIFICATION FAILURE");
            } goto cmdend;
            case 'i': {
                bool found_match;
                RECGUID match_guid;
                enum tudor_finger match_finger;

                puts("Put your finger on the sensor");
                while(true) {
                    //Capture and identify sample
                    enum tudor_capture_retry retry;
                    tudor_async_res_t async_res = NULL;
                    if(!tudor_identify(device, &retry, &found_match, &match_guid, &match_finger, &async_res) || !wait_capture(async_res, NULL)) {
                        if(async_res) tudor_cleanup_async(async_res);

                        if(retry) {
                            if(retry == TUDOR_RETRY_SCAN)
                                puts("Scan unsuccessful. Please try again.");
                            continue;
                        }

                        log_error("Error identifying captured sample!");
                        goto cmdend;
                    }
                    tudor_cleanup_async(async_res);
                    break;
                }   

                //Print match
                if(found_match) {
                    printf("Found match: identity index=%u finger=%d\n", match_guid.PartA, match_finger);
                } else puts("Found no match");
            } goto cmdend;
            case 'q': {
                //Read identity GUID
                bool all_guids = false;
                RECGUID guid = {0};
                printf("Enter identity index (invalid number for all): ");
                if(scanf("%u", &guid.PartA) < 1) all_guids = true;
                while(!abort_cmd_loop && getchar() != '\n') continue;
                if(abort_cmd_loop) goto cmdend;

                //Print records
                cant_fail_ret(pthread_mutex_lock(&device->records_lock));

                int num_matched = 0;
                for(struct tudor_record *rec = device->records_head; rec; rec = rec->next) {
                    if(!all_guids && memcmp(&guid, &rec->guid, sizeof(RECGUID)) != 0) continue;
                    printf("RECORD | identity index=%10u finger=%d\n", rec->guid.PartA, rec->finger);
                    num_matched++;
                }
                printf("Total: %d record(s)\n", num_matched);

                cant_fail_ret(pthread_mutex_unlock(&device->records_lock));
            } goto cmdend;
            case 'd': {
                uint64_t record_count;
                if(tudor_get_sensor_database_size(&record_count))
                    printf("On-sensor database: %llu record(s)\n",
                           (unsigned long long) record_count);
                else
                    log_error("Could not query on-sensor database size");
            } goto cmdend;
            case 'w': {
                //Read identity GUID
                bool all_guids = false;
                RECGUID guid = {0};
                printf("Enter identity index (invalid number for all): ");
                if(scanf("%u", &guid.PartA) < 1) all_guids = true;
                while(!abort_cmd_loop && getchar() != '\n') continue;
                if(abort_cmd_loop) goto cmdend;

                //Read finger
                enum tudor_finger finger;
                printf("Enter finger index (invalid number for all): ");
                if(scanf("%d", (int*) &finger) < 1) finger = TUDOR_FINGER_ANY;
                while(!abort_cmd_loop && getchar() != '\n') continue;
                if(abort_cmd_loop) goto cmdend;

                //Ask for confirmation
                printf("Do you really want to wipe all enrolled fingers with identity index=%u finger=%d?\n", guid.PartA, finger);
                printf("y/n: ");
                char yn = getchar();
                while(!abort_cmd_loop && getchar() != '\n') continue;
                if(yn != 'y') {
                    puts("Aborted wipe");
                    goto cmdend;
                }

                //Wipe records
                int num_wiped = tudor_wipe_records(device, all_guids ? NULL: &guid, finger);
                printf("Succesfully wiped %d enrolled finger(s)\n", num_wiped);
            } goto cmdend;
            case 's': abort_cmd_loop = true; goto cmdend;
            default: printf("Unknown command '%c'!\n", cmd);
        }
        cmdend:;
    }
}
