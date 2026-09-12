# Validation record

This page records the checks completed for the initial `06cb:0081` port. It is
a result summary rather than a hardware support guarantee. Logs and reader
state are intentionally excluded because they can contain device-specific,
cryptographic, or biometric-derived data.

## Current release-candidate status

Reinstall testing on 2026-09-12 exposed a pairing failure that the earlier
bridge did not handle safely. A fresh host restored its saved software
identity, but the vendor asynchronously wrote a nonzero
`SetOwnershipFailureCount`. The host still reported the device ready, and a
subsequent verification entered `CaptureImage` with incomplete vendor state
and crashed inside `synaWudfBioUsb.dll`. Restoring an older identity made
enumeration return but did not stop the ownership-failure write, confirming
that the identity file alone is not the complete pairing state.

The current candidate adds three protections:

- normal startup latches the vendor's current ownership-failure write and
  refuses to expose the WinBio adapters when it is nonzero, while recording a
  separate current-run result for setup
- an explicitly authorized, reader-scoped request invokes the vendor's real
  ownership-reset path once, records its result, and clears incompatible local
  pairing, the older unscoped pairing store, and every local user's stale
  enrollment references after success
- the launcher validates both reader-scoped and legacy calibration against the
  USB serial before the vendor can consume it, then performs a durable one-shot
  migration of matching legacy data

These checks cover the reproduced mismatched-state path and are designed to
stop it before capture. They have dedicated automated test coverage. A
successful on-hardware ownership reset, new pairing, enrollment, verification,
restart, and USB-reset sequence has not yet been recorded for this candidate.
The results below are the earlier bring-up baseline; they do not validate the
new recovery path.

## Validated system

Baseline validation was completed on 2026-09-11 with:

| Component | Value |
| --- | --- |
| Laptop | Lenovo Yoga C930-13IKB, type 81C4 |
| USB reader | Synaptics `06cb:0081` |
| Sensor firmware | 6.7 |
| Operating system | Omarchy 4.0.0, based on Arch Linux |
| Kernel | 7.1.8-arch1-3 |
| Architecture | x86-64 |
| fprintd | 1.94.5-2 |
| libfprint-tod | 1.95.2+tod1-1 |
| Lenovo driver | 5.5.2731.1050 |
| Lenovo package SHA-256 | `2713966a9ce5906fce12d33ead81f8c15a72d7b1cbe4e523613147181ce32343` |

## Automated checks

For the current recovery candidate, fresh release-mode GCC 16.2.1 and Clang
builds completed all 202 build steps and passed all 14 Meson tests. The same
14 tests passed under AddressSanitizer plus UndefinedBehaviorSanitizer and
under ThreadSanitizer. The separate shell fixture suite passed the privileged
helper's identity checks, broad backup and cleanup behavior, service-mask
recovery, durable marker ordering, and injected failure paths. These checks do
not replace the pending hardware sequence above.

The release installer was also run in `--build-only` mode from the committed,
curated source archive. It verified both source inputs, completed all 202 build
steps, passed all 14 Meson tests and the shell fixture suite, and produced the
`0.1.0-6` Arch package without changing installed packages or reader state.
Repeated archive generations spanning packaging-metadata commits were
byte-identical and matched the SHA-256 pinned in `PKGBUILD`.

For the earlier baseline, fresh GCC and Clang builds completed with the TOD
module and restricted host enabled. The Meson suite passed 13 of 13 tests in
each normal build. Separate sanitizer runs passed the suite with
AddressSanitizer plus
UndefinedBehaviorSanitizer and with ThreadSanitizer.

The covered behavior includes:

- Windows wait, thread, and string compatibility
- SHA-1 and cryptographic-context behavior
- random standalone P-256 keys, persistent reader identity, fixed-width key
  blobs, ECDH agreement, and randomized ECDSA signing
- persistent cryptographic registry state
- stable host replacement across USB re-enumeration and state-ID binding
- WinUSB ownership and bounded diagnostic playback
- asynchronous capture recovery
- native biometric storage calls and lifecycle
- native-storage IPC framing and validation
- persistent launcher state, including interrupted empty calibration

The baseline release installer was also run in `--build-only` mode from its
curated source archive. It verified both source inputs, completed 198 build
steps, passed all 13 tests, produced an Arch package, and made no package or
authentication changes. Building the archive twice from the same committed
input produced byte-identical output.

## Hardware checks

Before the later regression was found, the tested reader completed:

- first initialization and no-touch, reader-specific calibration
- enrollment through fprintd
- repeated correct-finger matches
- rejection of a different finger
- matching after restarting fprintd and the Tudor launcher
- matching after resetting and re-enumerating the USB reader
- deletion followed by a fresh enrollment
- sudo authentication with password fallback
- polkit authentication with password fallback
- Omarchy lock-screen authentication with password fallback

The port has not yet been validated across a full operating-system upgrade,
on a different laptop, or on a different physical `06cb:0081` reader. A reboot
check remains part of the release checklist in [Testing](TESTING.md).
