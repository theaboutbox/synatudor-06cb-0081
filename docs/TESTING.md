# Testing

## Automated tests

Install the build requirements and point the build at the checksum-matching
Lenovo package if it is already available. Without the environment variable,
the build downloads the same package from Lenovo.

```console
$ export SYNA_TUDOR_INSTALLER=/path/to/huy103af07m6.exe
$ meson setup build -DDBGIMPORT=true -DDBGWDF=false -DTOD=true -DUNMOUNTFS=true
$ meson compile -C build
$ meson test -C build --print-errorlogs
$ bash tests/reset-ownership.sh
$ bash tests/setup.sh
```

The suite covers Windows wait, thread-start filtering, and string behavior;
cryptographic context, random generation, RSA key generation/export/signing,
SHA-1, P-256 key generation, ECDH agreement, and ECDSA signing, including the
pinned DLL's scalar-only signing-key import and invalid-scalar rejection;
persistent crypto-registry state; WinUSB access and bounded diagnostic playback; capture
recovery; suppression of internal-restart prompts and cancellation before a
restart or its ACK; preservation of scan-retry and no-match feedback; native storage calls, lifecycle, and IPC; stable host identity;
persistent launcher state; the joined pairing-worker and nonnull-strategy
guard; the host's one-shot vendor-unpair transaction; its resumable
pending-validation marker, its conditional one-to-zero completion, and its
durable replay guard; and the privileged helper's refusal, cleanup, and
service-mask paths. A private mock launcher verifies that failed initialization
completes without waiting for cleanup, that delayed cleanup cannot change a new
host, and that its timeout leaves the main loop responsive. It also tests real
HostDied cancellation during initialization and signal subscriptions through
device destruction and replacement. Calibration fixtures
verify that reader-scoped and legacy blobs are bound to the exact `06cb:0081`
USB serial.

For a Clang sanitizer build:

```console
$ CC=clang CXX=clang++ meson setup build-asan \
    -DDBGIMPORT=true -DDBGWDF=false -DTOD=true -DUNMOUNTFS=true \
    -Db_sanitize=address,undefined
$ meson compile -C build-asan
$ meson test -C build-asan --print-errorlogs
```

## Static analysis and focused memory checks

After a normal build, install `cppcheck`, `shellcheck`, and `valgrind` alongside
Clang, then run `python3 tools/analyze.py build`. Diagnostics are saved under
`build-analysis`; a nonzero exit indicates findings or a scanner failure, not
necessarily a confirmed defect. The script only analyzes source code.

For focused memory and descriptor checks:

```sh
meson test -C build --timeout-multiplier 10 --print-errorlogs \
  --wrapper 'valgrind --error-exitcode=97 --leak-check=full --errors-for-leak-kinds=definite' \
  winapi-overlapped wdf-lifecycle winusb-borrowed datastore tudor-ipc tudor-state
```

Tests need permission to create local Unix sockets and a private D-Bus bus.
The release timestamp test compiles the implementation with `NDEBUG` even in a
debug build. See [the September 2026 review](CODE-REVIEW-2026-09-13.md) for the
reviewed issues, evidence, and remaining validation limits.

## Hardware validation

The [September 13 local validation](HARDWARE-VALIDATION-2026-09-13.md) records
results for the reviewed `12.1` build, including successful fingerprint checks
and USB recovery, and a failed service-only restart.

Automated tests do not prove that a vendor-driver ABI works on hardware. The
package revision 12 candidate should pass this sequence on USB `06cb:0081`.
Keep password login available. The optional vendor-unpair step changes pairing
and local enrollment state and may invalidate existing Windows and Linux
enrollments; it is not a proven secure erase of the sensor database.

1. Run `synatudor-setup` with the sensor uncovered. Confirm that it makes no
   more than three ordinary initialization attempts and never invokes the
   vendor-unpair callback. If `SetOwnershipFailureCount` becomes nonzero,
   confirm the value is reported only as diagnostic context and a later normal
   attempt can continue after USB re-enumeration.
2. Confirm that a successful start joins the exact vendor pairing worker,
   observes a nonnull capture-strategy pointer, opens every biometric pipeline
   stage, reaches `WINBIO_SENSOR_READY`, and only then clears
   `OwnershipFailureDetected.bool` and advertises the device. In a controlled
   incomplete-pairing test, confirm a missing strategy never reaches capture
   or `READY`.
3. If explicitly validating recovery, run `synatudor-reset-ownership` once.
   Confirm that it creates a private backup, consumes its one-shot request
   before the custom `OnResetOwnership` to `DoUnpairing` callback, suppresses
   only the exact normal pairing worker during maintenance, records the callback
   result, and never identifies the operation as standard
   `IOCTL_BIOMETRIC_RESET` or a proven template erase.
4. After reported callback success, confirm that incompatible per-reader
   pairing, every legacy `.tpd` record, and every local user's stale fprintd
   state for this driver are removed. Confirm that matching legacy calibration
   is migrated into the exact reader directory and all unscoped variants are
   removed. Confirm D-Bus activation cannot reopen either service during
   protected backup or cleanup.
5. Confirm the helper durably sets
   `OwnershipResetPendingValidation.bool` before removing its transaction
   barrier and makes at most three ordinary validation cycles. A complete safe
   open must change the marker to zero. In an injected validation failure, both services
   must remain runtime-masked and rerunning the helper must retry validation
   without invoking the vendor callback again. Inject interrupted and failed
   request/result combinations and confirm that stale enabled requests are
   disabled without replay, malformed combinations fail unchanged, and a
   separate callback requires a later explicit `--new`. Confirm ordinary
   `synatudor-reset` refuses to bypass a pending or malformed validation marker.
6. Run `synatudor-setup` and enroll one finger with `fprintd-enroll`.
7. Match it repeatedly with `fprintd-verify` and confirm that a different
   finger is rejected.
8. Restart `fprintd` and the launcher, then repeat both checks.
9. Reset or re-enumerate the USB device, confirm that only one host remains for
   the reader, then repeat both checks.
10. Reboot, then repeat both checks.
11. Delete the enrolled finger, confirm that it no longer matches, and enroll
    it again.
12. If PAM integration is enabled, test sudo, polkit, the Omarchy lock screen,
    and password fallback separately. For sudo, run `sudo -k` followed by
    `sudo true` and leave the reader untouched: the initial finger prompt
    should appear once, internal capture restarts should remain quiet, and
    the default fingerprint timeout should lead to the password prompt.
    Repeat with a non-enrolled finger and confirm no-match feedback, then
    authenticate with the enrolled finger. Startup time and cancellation
    cleanup can add time outside PAM's 30-second fingerprint wait.

The earlier `06cb:0081` bring-up passed the automated suite with GCC and Clang,
AddressSanitizer/UndefinedBehaviorSanitizer, and ThreadSanitizer. It also passed
enrollment, correct and incorrect finger checks, service restart, USB reset,
sudo, polkit, and the Omarchy lock screen on a Lenovo Yoga C930-13IKB running
Arch Linux with Omarchy. Reinstall testing later exposed the incomplete-pairing
capture failure described in
[Validation](VALIDATION.md). The joined-worker guard, corrected cryptographic
pairing support, and vendor-unpair validation lifecycle in package revision 12
have now passed normal startup, enrollment, and a fingerprint match. Frequent
capture retries remain. Wrong-finger rejection, persistence across restart,
USB reset and reboot, explicit recovery, and each PAM consumer still require
revalidation; the earlier results do not validate those paths. Other laptop
models remain unverified.
