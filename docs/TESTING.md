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
SHA-1 behavior, fresh P-256 key generation, ECDH agreement, ECDSA signing,
persistent crypto-registry state, WinUSB ownership and bounded diagnostic
playback, capture recovery, native storage calls and lifecycle, native storage
IPC, and persistent launcher state.

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
release candidate should pass this sequence on USB `06cb:0081`:

1. Start from an empty, backed-up Tudor state directory and let first
   initialization generate calibration without touching the sensor.
2. Enroll one finger with `fprintd-enroll`.
3. Match it repeatedly with `fprintd-verify`.
4. Confirm that a different finger is rejected.
5. Restart `fprintd` and the launcher, then repeat both checks.
6. Reset or re-enumerate the USB device, then repeat both checks.
7. Reboot, then repeat both checks.
8. Delete the enrolled finger, confirm that it no longer matches, and enroll it
   again.
9. If PAM integration is enabled, test sudo, polkit, the Omarchy lock screen,
   and password fallback separately.

The initial `06cb:0081` port passed the automated suite with GCC and Clang,
AddressSanitizer/UndefinedBehaviorSanitizer, and ThreadSanitizer. It also passed
enrollment, correct and incorrect finger checks, service restart, USB reset,
sudo, polkit, and the Omarchy lock screen on a Lenovo Yoga C930-13IKB running
Arch Linux with Omarchy. Other laptop models remain unverified.
