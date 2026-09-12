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
```

The suite covers Windows wait and string behavior, cryptographic context and
SHA-1 behavior, random standalone P-256 key generation, persistent per-reader
identity reload and corruption rejection, ECDH agreement, ECDSA signing,
persistent crypto-registry state, WinUSB ownership and bounded diagnostic
playback, capture recovery, native storage calls and lifecycle, native storage
IPC, stable host identity, persistent launcher state, ownership-failure
guarding, the host's one-shot ownership-reset transaction, and the privileged
reset helper's refusal and cleanup paths. Calibration fixtures verify that
reader-scoped and legacy blobs are bound to the exact `06cb:0081` USB serial.

For a Clang sanitizer build:

```console
$ CC=clang CXX=clang++ meson setup build-asan \
    -DDBGIMPORT=true -DDBGWDF=false -DTOD=true -DUNMOUNTFS=true \
    -Db_sanitize=address,undefined
$ meson compile -C build-asan
$ meson test -C build-asan --print-errorlogs
```

## Hardware validation

Automated tests do not prove that a vendor-driver ABI works on hardware. A
release candidate should pass this sequence on USB `06cb:0081`. The
ownership-reset portion permanently erases the sensor database, so back up any
state needed for investigation and keep password login available:

1. Present a known mismatched local identity and confirm that one bounded
   initialization writes a nonzero ownership-failure count, exits before
   advertising the adapters, records `OwnershipFailureDetected.bool` for this
   run, and never enters capture. Confirm `synatudor-reset` clears a stale
   marker while services are stopped and a successful run records false.
2. Run `synatudor-reset-ownership`; confirm that it creates a private backup,
   establishes its barrier and consumes its request before the vendor call,
   reports success, clears incompatible per-reader pairing, every legacy
   `.tpd` pairing record, and every local user's stale fprintd state for this
   driver, and does not run a second reset during service restart. Confirm that
   a matching legacy calibration is migrated into the exact reader directory
   and all unscoped variants are removed. Confirm that D-Bus activation cannot
   reopen either service while backup or local cleanup is in progress.
3. Run `synatudor-setup` and confirm that the first clean initialization leaves
   the ownership-failure marker false, leaves the vendor counter absent or
   zero, and generates or reuses only calibration belonging to that reader.
4. Enroll one finger with `fprintd-enroll`.
5. Match it repeatedly with `fprintd-verify`.
6. Confirm that a different finger is rejected.
7. Restart `fprintd` and the launcher, then repeat both checks.
8. Reset or re-enumerate the USB device, confirm that only one host remains
   for the reader, then repeat both checks.
9. Reboot, then repeat both checks.
10. Delete the enrolled finger, confirm that it no longer matches, and enroll it
   again.
11. If PAM integration is enabled, test sudo, polkit, the Omarchy lock screen,
   and password fallback separately.

The earlier `06cb:0081` bring-up passed the automated suite with GCC and Clang,
AddressSanitizer/UndefinedBehaviorSanitizer, and ThreadSanitizer. It also passed
enrollment, correct and incorrect finger checks, service restart, USB reset,
sudo, polkit, and the Omarchy lock screen on a Lenovo Yoga C930-13IKB running
Arch Linux with Omarchy. Reinstall testing later exposed the mismatched
ownership capture failure described in [Validation](VALIDATION.md). The new
guard and ownership-reset flow still require the complete hardware sequence
above; the earlier results do not validate that recovery path. Other laptop
models remain unverified.
