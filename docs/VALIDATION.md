# Validation record

This page records the checks completed for the initial `06cb:0081` port. It is
a result summary rather than a hardware support guarantee. Logs and reader
state are intentionally excluded because they can contain device-specific,
cryptographic, or biometric-derived data.

## Current release-candidate status

Reinstall testing on 2026-09-12 exposed a pairing failure that the earlier
bridge did not handle safely. A fresh host restored saved software state, but
the vendor asynchronously wrote a nonzero `SetOwnershipFailureCount`. The host
still reported the device ready, and a subsequent verification entered
`CaptureImage` without a vendor capture strategy and crashed inside
`synaWudfBioUsb.dll`.

Further analysis of the pinned DLL corrected the original diagnosis. This
property is a generic `DoPairing` failure counter, not an ownership-mismatch
verdict. Values one through four can occur while a recoverable pairing
transition continues in another process after USB re-enumeration. The actual
safety defect was that `OnPrepareHardware` starts pairing asynchronously,
`OnD0Entry` does not join it, and the bridge exposed the device without proving
that the worker had initialized the strategy later dereferenced by capture.

The package revision 8 candidate adds these protections:

- normal startup joins the exact pairing worker, requires the pinned
  capture-strategy pointer to be nonnull, and opens the complete biometric
  pipeline through `WINBIO_SENSOR_READY` before exposing the device; the
  failure counter remains diagnostic
- `synatudor-setup` allows up to three bounded ordinary starts across USB
  re-enumeration and never invokes vendor unpairing automatically
- an explicitly authorized, reader-scoped maintenance request suppresses the
  exact pairing worker and invokes private WUDF control code `0x442040`, which
  the pinned DLL dispatches through `OnResetOwnership` to `DoUnpairing`; this
  is not standard `IOCTL_BIOMETRIC_RESET`, and success does not prove physical
  erasure of the sensor's template database
- successful callback cleanup durably arms a pending-validation marker before
  removing its transaction barrier; the helper then makes up to three normal
  validation cycles, and an interrupted or failed validation can resume
  without repeating the vendor callback; only an armed marker changes to a
  durable completed value, which blocks another callback unless `--new` is
  supplied explicitly
- request, result, and validation markers are reconciled as one durable state
  machine; interrupted or failed callbacks cannot replay automatically, stale
  enabled requests are retired before a later `--new` operation, and ordinary
  USB reset cannot bypass pending ownership-reset validation
- the launcher validates reader-scoped and legacy calibration against the USB
  serial before the vendor can consume it, then performs a durable one-shot
  migration of matching legacy data

A superseded package demonstrated that the custom vendor callback could return
success and that protected local cleanup could complete on the tested reader.
Its subsequent clean pairing did not reach the safe capture boundary, so that
result is not a successful end-to-end recovery validation. The corrected
package revision 8 candidate still needs a fresh on-hardware normal pairing,
optional vendor-unpair recovery, enrollment, verification, restart, and USB
reset sequence. The results below are the earlier bring-up baseline; they do
not validate the corrected lifecycle.

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

The corrected package revision 8 candidate is still under validation. Its
expanded tests cover random-number generation, the classic CryptoAPI operations
used during clean pairing, exact pairing-worker synchronization, strategy
gating, and resumable post-unpair validation. Fresh post-fix sanitizer builds
completed 264 steps with Clang 22.1.8 AddressSanitizer plus
UndefinedBehaviorSanitizer and with GCC 16.2.1 ThreadSanitizer. All 15 Meson
tests passed in both builds with leak detection and halt-on-error enabled; the
complete text, JSON, and JUnit logs contained no sanitizer, undefined-behavior,
memory-leak, or data-race diagnostic. Fresh release-mode GCC 16.2.1 and Clang
22.1.8 builds also completed 264 steps and passed all 15 tests, then passed all
15 again without rebuilding. All four builds used the pinned Lenovo installer
and enabled TOD plus the restricted host while disabling debug imports and WDF
logging. The shell fixture also passed its
protected-state permissions, marker-transition, replay-guard, service-mask,
ordinary-reset gating, and injected-failure cases. `bash -n` passed for the
three installed helpers and the fixture, and `git diff --check` was clean.
Two archives generated independently from committed tree
`9d6ca339989da1957fef180350a1ba0ab8c7deb1` were byte-identical. The curated
316-entry payload included the loader call-site test, contained no forbidden
private/proprietary extension, and has SHA-256
`81c1ea9da6f63949065cb435a209556d62d28ef20782fab1bbcf416a5690ad5c`.
The installer then consumed exact final commit
`802651417c4ad2df5239e592ef5b2ce487d2c31a` in `--build-only` mode, verified
both source checksums, completed 264 package-build steps, passed all 15 Meson
tests and the shell fixture, and produced `synatudor-0081-0.1.0-8-x86_64`
without changing installed packages, authentication, services, or reader
state. The private package was mode 0600; all 20 declared dependencies were
satisfied, its 39-entry manifest matched the expected install layout, its five
installed helper scripts matched the committed sources, and its paths contained
no `/var/lib` state or standalone vendor/private file. Its x86-64 ELF objects
had no absolute RPATH or RUNPATH leakage.
The package remains private because `libtudor.so` embeds the vendor DLL payload
and `.BUILDINFO` records local build paths and the installed-package inventory.
No automated result substitutes for the pending hardware sequence above.

A superseded recovery candidate completed fresh release-mode GCC 16.2.1 and
Clang builds and passed all 14 Meson tests. The same tests passed under
AddressSanitizer plus UndefinedBehaviorSanitizer and under ThreadSanitizer. Its
shell fixtures passed the privileged helper's identity checks, broad backup
and cleanup behavior, service-mask recovery, durable marker ordering, and
injected failure paths. The release installer also passed in `--build-only`
mode and produced a local package without changing installed packages or
reader state. Those tests encoded the earlier nonzero-counter guard and did not
exercise the missing clean-pairing cryptography or joined-worker boundary, so
they do not validate revision 8.

For the earlier baseline, fresh GCC and Clang builds completed with the TOD
module and restricted host enabled. The Meson suite passed 13 of 13 tests in
each normal build. Separate sanitizer runs passed the suite with
AddressSanitizer plus
UndefinedBehaviorSanitizer and with ThreadSanitizer.

The covered behavior includes:

- Windows wait, thread, and string compatibility
- SHA-1 and cryptographic-context behavior
- random standalone P-256 keys, fixed-width key blobs, ECDH agreement, and
  randomized ECDSA signing
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
