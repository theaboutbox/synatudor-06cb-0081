# Development history

This note preserves the post-fork engineering context for maintainers and
coding agents. It distinguishes the original bring-up, later regressions, and
subsequent repairs. Revision numbers describe tested package candidates, not
independent hardware support guarantees.

For installation and current limitations, start with the [README](../README.md).
The [validation record](VALIDATION.md) retains detailed revision evidence and
build provenance; the dated reports below record later review and hardware work.

## Inherited foundation and the `06cb:0081` port

This repository builds on the relink branch of
[Popax21/synaTudor](https://github.com/Popax21/synaTudor) and subsequent work in
[rstar000/synaTudor](https://github.com/rstar000/synaTudor). The inherited
project supplied the Windows-driver relinking approach, compatibility host,
and libfprint integration. Wine and CodeWeavers contributors supplied parts
of the cryptographic compatibility code. Authorship and licensing are
recorded in the Git history, [NOTICE](../NOTICE), and source-file notices.

Getting this reader working through a normal Linux installation required more
than adding a USB ID. The port and subsequent hardening include:

- USB discovery and a WUDF 1 object model matching the pinned vendor DLL.
- Windows API and cryptographic compatibility for clean pairing, secure-channel
  setup, fixed-width P-256 serialization, and fresh random key generation.
- Persistent pairing, calibration, and cryptographic registry state scoped to
  the physical reader, with protected state IPC across the host sandbox.
- Host replacement across USB re-enumeration, bounded initialization, and a
  complete pairing and capture-readiness check before publishing the reader.
- The vendor's native biometric storage adapter and exact GUID/finger mapping.
  An earlier in-memory shim could report success without committing a template
  to the sensor's database.
- Asynchronous capture completion and cancellation handling, plus bounded
  WinUSB diagnostic playback within the host's 64 KiB stack.
- Local Arch packaging with pinned vendor inputs and a tested TOD-enabled
  libfprint, guided setup, Omarchy PAM integration, rollback, and recovery tools.

See [Architecture](ARCHITECTURE.md) for the implementation and state model.
These changes describe this project's work; they do not establish whether
other forks work on their own tested hardware and software combinations.

## Initial bring-up and pairing corrections through revision 12

The initial Lenovo Yoga C930-13IKB bring-up passed initialization, calibration,
enrollment/deletion, repeated matching and wrong-finger rejection, persistence
across service restarts and USB reset, and sudo, polkit, and lock-screen use
with password fallback. The initial automated suite passed under GCC, Clang,
ASan/UBSan, and TSan. Later candidates needed their own revalidation: these
baseline results must not be treated as proof for every subsequent build.

The following account was moved from the README. Its pending checks and capture
retry limitation describe the revision 12 milestone; later results follow below.

Later reinstall testing reproduced incomplete pairing: the vendor driver
wrote `SetOwnershipFailureCount`, the earlier bridge advertised the device
before its asynchronous pairing worker had established the capture strategy,
and capture then crashed inside the vendor DLL. Reverse engineering showed
that this value is a generic `DoPairing` failure counter. A nonzero value,
especially during the first few attempts, can be part of a recoverable
multi-process or USB re-enumeration transition and is not by itself proof of
an ownership mismatch.

The package revision 11 candidate joins the exact vendor pairing worker,
requires its capture-strategy pointer to be nonnull, and opens the full
pipeline through the sensor's ready status before exposing the device. The
counter remains diagnostic. It also reconstructs omitted ECDSA P-256 public
coordinates for the vendor's scalar-only certificate-signing keys, while
validating the scalar and any supplied coordinates, and accepts the vendor's
bounded TLS labels without requiring a trailing NUL. Revision 12 completes
enrollment authorization before scan instructions and logs the vendor's
calibration result and capture prerequisites. Normal pairing, device listing,
enrollment, and a successful fingerprint match have now passed hardware
revalidation. Capture still produces frequent retries before completing.
Restart, USB reset, reboot, and explicit recovery validation remain pending.
See [Validation](VALIDATION.md) for the recorded results. At this milestone,
the priorities were capture reliability, persistence, and installation on
another supported machine; the [roadmap](ROADMAP.md) tracks remaining work.

## Reliability review and hardware follow-up on 2026-09-13

The [code review](CODE-REVIEW-2026-09-13.md) records repairs to USB error
reporting, cancellation, timeout and partial-transfer handling; concurrent
thread waits and overlapped completion; WDF object lifetime and event queues;
release-build timestamps; IPC validation and descriptor ownership; datastore
cleanup; and cryptographic buffer handling. It also records removal of fixed
control-transfer sleeps. The mock timing improvement is not a sensor latency
benchmark.

An intermittent signing failure during packaging exposed the vendor PAL's
fixed-width reads of decoded ECC signature components. Separate zero-padded
backing storage corrected that compatibility defect. Deterministic regressions
and 1,000 repeated crypto tests passed. The report retains unresolved analyzer,
TSan, and vendor-PAL Memcheck findings rather than treating passing tests as a
complete safety guarantee.

The [revision 12.1 hardware report](HARDWARE-VALIDATION-2026-09-13.md) records
matching, rejection, cancellation, and preserved enrollment after ordinary USB
reset. Restarting both services without USB reset failed because pairing did
not create a capture strategy. The initialization guard rejected the device;
`synatudor-reset` recovered it. No comparison established whether that failure
was a regression, and later capture testing did not retest the service-only
restart path.

## Capture input lifetime: revisions 12.2–12.4

The [latency investigation](LATENCY-INVESTIGATION-2026-09-13.md) traces the
repeated capture retries to a concrete lifetime defect: asynchronous WUDF1
requests borrowed input from an adapter stack buffer. The worker could read it
after the caller reused the stack, producing an invalid capture mode.
Buffered/direct IOCTL requests now own an input copy for their lifetime;
METHOD_NEITHER retains its pointer semantics. The regression overwrites the
original input before the request reads it and fails against the old code.

Revision 12.2 supplied diagnostic traces, 12.3 tested the fix with diagnostics,
and production revision 12.4 removed those temporary hooks. Normal and
ASan/UBSan suites passed all 24 tests; the fixed diagnostic and production
packages also passed the shell-helper suites.

On revision 12.4, five guided matching-finger checks and one unenrolled-finger
rejection passed in 1.04–1.32 seconds including startup and finger placement.
No timeout, pending-worker recovery, or capture error appeared in that sequence.
This supports the input-lifetime repair but does not establish long-term
reliability or resolve the separate service-restart limitation. Suspend/resume,
reboot, and installation on another supported machine remain unvalidated.

The same investigation records a local polkit preference of fingerprint for
up to ten seconds followed by password entry. That is a test-machine setting,
not the repository's default PAM configuration; a fresh fallback timing check
remained pending. Do not infer a repository default from that local experiment.

## Recovery design retained from the README

The detailed recovery behavior belongs alongside the engineering context.
For operator instructions, use [Installation](INSTALL.md#pairing-and-first-setup);
for the state machine, use
[Architecture](ARCHITECTURE.md#explicit-vendor-unpair-recovery).

Use `synatudor-reset-ownership` only when you deliberately want to change the
reader's pairing state after ordinary setup attempts have failed. This
destructive maintenance command invokes the pinned vendor DLL's custom
`OnResetOwnership` to `DoUnpairing` callback. It is not the standard
`IOCTL_BIOMETRIC_RESET`, and static analysis does not prove that it physically
erases the sensor's template database. Do not use it as a secure-erase tool;
assume existing Windows and Linux enrollments may stop working.

The command makes a private backup below
`/var/lib/tudor/migration-backups`, consumes a one-shot request before calling
the vendor callback, and removes incompatible local pairing state and this
driver's fprintd metadata for every local user after reported success. It also
backs up and removes all legacy `.tpd` pairing records managed by the driver
because that older store did not identify the physical reader. Any older
unscoped calibration is backed up; an exact match is migrated into this
reader's directory and every unscoped calibration value is then removed.
After cleanup, a durable pending-validation marker remains until a normal host
passes the full safe-open boundary. The helper makes up to three ordinary
validation attempts. If they fail, it leaves both fingerprint services stopped
behind helper-owned runtime masks; rerunning the helper resumes validation
without issuing the vendor callback again. A successful open changes that
existing marker to a durable completed value. Later helper invocations preserve
and report the completed result without invoking the callback; another reset
requires the explicit `--new` option. A failed or interrupted callback is also
never replayed automatically. Recovery first disables any stale request, and a
later `--new` invocation is required to authorize a separate operation.

Use `synatudor-uninstall --purge` only when you also want to delete every
fingerprint fprintd exposes for your user and all Tudor state, including
recovery backups. A local purge alone does not invoke the reader's vendor
unpair callback.
