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

On-hardware setup with package revision 8 on 2026-09-12 failed on all three
ordinary starts before enrollment. Each restricted host reported successful
`OnPrepareHardware` and `OnD0Entry` callbacks, then exited because its pairing
worker handle appeared absent. Static analysis identified a bridge layout
error: `IPnpCallbackHardware` is a subobject at `CBiometricDevice + 0x258`, not
the complete device object. Revision 8 incorrectly read the worker handle and
capture strategy relative to that subobject. Its tests used a synthetic base
and did not verify the actual vendor interface layout.

The revision 9 candidate derives the complete object only after checking the
pinned hardware and power callback layouts, and tests that derivation against
the actual pinned DLL without using the reader. Status-only pairing diagnostics
distinguish any remaining protocol or cryptographic failure
after the corrected worker check. A missing strategy continues to block capture.

After revision 9 was installed, the vendor's startup counter-limit branch
restored a count of five, saved zero, and returned `0x800710df` before starting
the worker. Static analysis confirms this is a one-start, self-clearing
`ERROR_DEVICE_NOT_AVAILABLE` response. A controlled ordinary USB reset and
initialization then started and joined the pairing worker from count zero.
The persisted P-256 identity imported successfully and the pinned pairing key
generator returned zero, but the worker subsequently returned `0x80070259`
without a capture strategy. The host rejected that state before enrollment.
This confirms the revision 9 layout correction and safe failure boundary, but
does not validate successful pairing or recovery.

The revision 9 failure was reproduced without a reader at the real pinned DLL
boundary. The vendor's certificate-signing setup zeroes a 96-byte private-key
encoding, then derives only the last 32-byte scalar. Its later CNG ECDSA import
expects the provider to compute the omitted public coordinates. The bridge's
hardened import instead rejected those coordinates before signing, producing
the observed vendor `0x259` and worker `0x80070259` results. Revision 10 permits
this omission only for ECDSA P-256 with both coordinates entirely zero, derives
the public key in a copy, and retains checks on nonzero supplied coordinates.
It explicitly rejects zero or out-of-range scalars. Persisted pairing identity
validation remains strict and uses the separate ECDH path.

The new `palcrypto-ecc` regression runs the pinned DLL's actual key generation,
export, import, signing, signature encoding, and verification with synthetic
in-memory identities. It passes full-coordinate and scalar-only signing for a
new and a reused identity, rejects altered hashes, malformed coordinates, and
scalars zero, the curve order, above the curve order, or all-ones, and verifies
that input private-key encodings remain unchanged. No hardware callback runs.

Revision 10 also makes failed-open disposal independent of a launcher's
`KillHost` reply. Local host and socket state is cleared immediately, and the
cleanup request runs asynchronously with a five-second timeout. Its callback
retains only the old host ID, so it cannot change a later device session.
The previous synchronous cleanup used a practically unbounded timeout before
returning the initialization error. This removes a known blocking path; the
exact blocking site in the observed fprintd timeout was not captured.
The `tudor-host-cleanup` fixture injects an error through the production
initialization callback against a private mock D-Bus launcher. It verifies
that initialization fails within one second with the cleanup reply withheld,
that local resources clear, that a delayed reply cannot change the next host,
and that disposal permits device finalization before the reply. A separate
case checks the five-second timeout while a main-loop heartbeat continues.

The software DLL regression exposed unowned dynamic `GetProcAddress` stub
names under LeakSanitizer. The API library now owns their names and executable
pages in a mutex-protected pool and releases both at library teardown.

On hardware, revision 10 imported the persisted identity, completed signing
and certificate verification, and reached ECDH/TLS preparation. Its subsequent
pairing workers returned `0x800700cc` without a capture strategy. Several
separate initialization objects ran during the same fprintd startup, followed
by the counter-limit cooldown and a service timeout. The repeated objects are
consistent with USB hotplug during initialization; that trigger has not been
proved from the service log alone.

A second compatibility regression was reproduced at the pinned DLL's real
TLS derivation boundary. Its TLS caller passes the 13 bytes of `master secret`
without including the NUL in the length. The public bridge had added a NUL
requirement and a test expecting rejection; the development bridge accepted
the bounded label. The actual vendor PAL call returned `0x259` with length 13
and succeeded with length 14. Revision 11 accepts both bounded forms and checks
their outputs against an independent ECDH and HMAC-based TLS PRF calculation.
This failure matches the hardware timeline, but the final worker status alone
does not identify every possible TLS failure. Static analysis confirms a
client TLS path that propagates this `0x259` and maps it to `0xcc`; the exact
runtime branch was not traced. Status-only derivation logging
is included to verify the boundary on the next hardware run.

The startup timeout also has a concrete initialization error path. Host death
cancels the internal receive task. GTask substitutes `G_IO_ERROR_CANCELLED`
for its error, and the pinned libfprint `v1.95.2+tod1` initialization callback
returns on that error before decrementing `pending_devices`. Enumeration then
waits on that counter. Revision 11 translates cancellation caused by host death
to an initialization protocol error before disposal, while retaining ordinary
cancellation when the host has not died. The fixture uses the real receive and
HostDied callbacks and models the installed pending-count gate; it does not
perform real USB enumeration.

Failed device objects also discarded their HostDied and suspend signal
subscription IDs while retaining raw device pointers as callback data on a
shared D-Bus connection. Revision 11 owns both IDs and unsubscribes before
finalization releases that connection, preserving subscriptions across an
ordinary close/reopen of the same object. The private-bus fixture checks the
actual HostDied subscription through object destruction and replacement.

The next revision 11 hardware run completed TLS derivation and pairing with
status zero. Its first worker returned success before creating the capture
strategy. Static analysis identifies a pinned `UpdateFirmwareExtension`
transition that permits this staged startup; the exact runtime branch was not
traced. The following ordinary session created the strategy, opened the full biometric
pipeline and native database, and sent READY. The initial device-list query
appears to have returned before that later session was ready. No further code change was
needed for this transition. A subsequent device-list check found the reader and
reported no enrolled fingers. Enrollment, verification, restart, USB reset, and
reboot validation remain pending.

The subsequent enrollment attempt displayed a graphical authorization dialog
and repeatedly reported `enroll-retry-scan`. The captured service-log window
contained identification retries, all caused by capture workers exiting with
their WUDF requests pending, followed by cancellation status `0x800703e3`.
It contained no enrollment or fingerprint-quality failure messages. The installed
polkit PAM configuration tries fingerprint authentication before a password;
this supports an authorization-stage identification attempt, but the caller was
not correlated with the log window. Core capture recovery matches the earlier
working development source, so a new recovery-delay regression is not established.

Revision 12 completes sudo authorization before its scan instructions and runs
only the enrollment client as root, with the regular user's name supplied
explicitly. Status-only diagnostics also observe the pinned calibration call
and the vendor's capture prerequisites. Static analysis shows that ProcessPairing
can overwrite a calibration error with capture-strategy initialization success;
saved calibration passing the helper's format and reader-ID checks does not
prove that the vendor accepted it. These changes still require hardware testing.

The package candidate adds these protections:

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
package revision 11 candidate has now reached normal pairing and safe open;
it still needs the subsequent device-list check,
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

Revision 12 passed all 18 Meson tests and both shell fixtures in its fresh GCC
build-only package build. The setup fixture verifies that sudo authentication
finishes before scan instructions, preserves the explicit desktop username in
the noninteractive enrollment command, and stops before enrollment when
authentication fails. The changed capture-recovery and pairing-layout tests
passed 2/2 under Clang ASan/UBSan with leak detection and halt-on-error enabled,
and 2/2 under GCC TSan with halt-on-error enabled. These focused runs contained
no sanitizer diagnostic; the native shims and fixture are instrumented, while
the pinned vendor DLL's machine code is not. The fixture executes real vendor
calibration success, failure, and retry paths with both hardware SDK callsites
replaced, and checks a blocked capture worker leaving its request pending.

The revision 12 installer built source commit
`3c51fe9a458b7170457c1491b1c85f96facc34c9` through metadata commit
`0fe9d9b8e78f84a39d29371d555c4e9c6703d4e3`. Two independently generated source
archives were byte-identical, with SHA-256
`fa416774e6d8d2226bb1cef0cce8c90a9f6aad4dc776e83b4916f20dfe7e808b`.
The private package SHA-256 is
`47df2a0a9812b3f98cc9136c26089754e9a2741a51e1aed424cfdd616b7351f7`.
Its manifest matches revision 11, its five helpers and notices match committed
source, all 20 dependencies are satisfied, and none of its six ELF binaries
exports a test hook or changes dependency/search paths. The source payload has
289 regular files, matches committed bytes, and passes the private-identity,
binary-payload, link, and archive-metadata checks. This build changed no
installed packages, services, authentication settings, or reader state. These
results do not establish successful enrollment on hardware.

Revision 11 passed all 18 Meson tests in the fresh GCC package build and the
updated Clang AddressSanitizer plus UndefinedBehaviorSanitizer build. Leak
detection and halt-on-error were enabled. The updated GCC ThreadSanitizer
build passed all 17 tests outside `tudor-host-cleanup`, which retains the GLib
connection-setup limitation recorded below. The complete text, JSON, and
JUnit logs from both sanitizer runs contained no diagnostic. No suppression
was added. The actual PAL regression covers bounded TLS labels and an
independent ECDH/TLS PRF reference; the six-case private-bus fixture covers
host-death cancellation, ordinary cancellation, disposal, delayed cleanup,
the bounded timeout, and signal subscription lifetime. Native CNG test
function types were corrected to match the signed status and 16-bit string
types of the implementation, rather than suppressing UBSan's mismatch report.

The revision 11 build-only installer used source commit
`dc18f59fb5c64ba10a224952b304ae4b7b4a478f` through metadata commit
`a515f7649411b6d123b87e11161fb82c22812377`. It verified both pinned inputs,
completed 276 build steps, passed all 18 Meson tests and the shell recovery
fixture, and changed no installed package, authentication, service, or reader
state. Two independently generated archives were byte-identical, with SHA-256
`70871a2281a7568c3918508645cdeaaf73b257cb0b0154c8b039b7dff64242e4`.
All 288 regular files and 32 directory headers match committed bytes, types,
modes, and canonical metadata; the new blobs and archive passed the private-data
and binary-content audit. The private package has SHA-256
`d13bb94b1b5c1648126624e0643594e882eb5e3dc338fc9c081e334ba8c6bfce`.
Its exact 39-entry manifest matches revision 10, its five helpers and license
files match committed source, all six x86-64 ELF objects retain their expected
dependencies and search paths, and no test hooks are exported. All 20 runtime
dependencies are satisfied. The package is mode 0600 in a mode 0700 cache;
`git diff --check` passed. The later hardware transition is recorded above;
enrollment and the remaining lifecycle checks are pending.

Revision 10 passed all 18 Meson tests in its fresh GCC package build and the
updated Clang AddressSanitizer plus UndefinedBehaviorSanitizer build, with leak
detection and halt-on-error enabled. The complete text, JSON, and JUnit logs contained no sanitizer
diagnostic. GCC ThreadSanitizer passed all 17 tests outside the new
mock-launcher fixture, also with no diagnostic in those complete logs.
ThreadSanitizer reports a cross-thread allocation/free in
the installed GLib library while the mock fixture opens its private D-Bus
connection, before the cleanup code runs. A standalone program linked only
to GLib/GObject/GIO reproduces the same report. This establishes a dependency
limitation for that run, without determining whether the report represents a
GLib defect or missing sanitizer synchronization visibility. The 17-test
ThreadSanitizer run excludes `tudor-host-cleanup`; there are no suppressions.

The revision 10 build-only installer used source commit
`197de2950b0f06b94e3df2eb035c444f3ba111d5` through metadata commit
`cba891d06a136c292baf4be1f4c4fffbf7050b13`. It verified both pinned inputs,
completed 276 build steps, passed the 18 Meson tests and shell recovery
fixture, and changed no installed package, authentication, service, or reader
state. Helper syntax checks and `git diff --check` passed. Two independently
generated source archives were byte-identical, with SHA-256
`aaee1fdb59f58bdbd615e1d964396f1cdc0b16dcb9d578e34563d28f73757fcf`.
The curated archive's 288 regular files and 32 directory headers match the
committed source bytes, types, modes, and canonical metadata. The new source
blobs and archive passed the private-data and binary-content audit.
The private package has SHA-256
`e3e915e312b86a2b4b33566a500ef27224f6d0383587243d2d4ea7c50e6144d6`.
Its exact 39-entry manifest matches revision 9; its five helpers, license,
and notice match committed source. All six x86-64 runtime ELF objects retain
their expected dependencies and search paths, with no exported test hooks.
All 20 declared runtime dependencies are satisfied. The package is mode 0600
in a mode 0700 cache and remains private for the vendor-payload reasons below.
These automated results do not validate normal pairing on hardware.

Revision 9 passed all 16 Meson tests in the fresh GCC package build and a fresh
Clang AddressSanitizer plus UndefinedBehaviorSanitizer build. The final changes
also passed all 16 tests in the updated GCC ThreadSanitizer build. Complete text,
JSON, and JUnit test logs contained no sanitizer diagnostic. The new
`pairing-layout` regression uses the real pinned DLL's COM thunks and pairing
thread with its hardware operation replaced before execution; it verifies the
correct base, bounded join, and strategy read, and rejects the revision 8 base
and mismatched layouts. Its assertions remain enabled in the Arch package build.
The shell recovery fixture, helper syntax checks, and `git diff --check` passed.

The revision 9 build-only installer used committed tree
`58796f974469b4158aa6917cbaa876ba829eb74a` through metadata commit
`3863379` and changed no installed package, authentication, service, or reader
state. Two independently generated source archives were byte-identical, with
SHA-256 `8d21d0d855d51fe0b7e7d779d81126d6c7044f638b4c0fd14aaa383654d0f34e`.
The private revision 9 package has SHA-256
`930d7d07d53646d841ba28ee64b052a234cab36f8a715617ea82166aa1c3f556`.
It retained the expected 39-entry layout, matched its committed helper sources,
and satisfied all 20 declared dependencies. Its file was mode 0600 in a mode
0700 cache. These automated results do not validate normal pairing on hardware.

Package revision 8 passed automated checks but failed the hardware setup
described above. Its expanded tests covered random-number generation, the classic CryptoAPI operations
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
they do not validate revisions 8 or 9.

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
