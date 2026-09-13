# Troubleshooting

## Confirm the hardware ID

```console
$ lsusb -d 06cb:0081
```

If this prints nothing, this driver does not match the connected reader. A
different Synaptics product ID can require a different vendor DLL, protocol,
or compatibility implementation.

## Inspect the installed stack

On Arch Linux:

```console
$ pacman -Q libfprint-tod fprintd synatudor-0081
$ systemctl status tudor-host-launcher.service fprintd.service
$ journalctl -b -u tudor-host-launcher.service -u fprintd.service
```

The first initialization can take longer because the vendor driver establishes
pairing and performs no-touch calibration. Leave the sensor uncovered until
the operation completes. Run `synatudor-setup` rather than repeatedly invoking
fprintd commands during first initialization; setup makes at most three bounded
ordinary attempts and safely restarts the USB session between them.

## Device missing while pairing is incomplete

The reader can retain pairing that no longer matches private state under
`/var/lib/tudor`. This can happen after switching from Windows Hello, using an
older experimental build, or deleting only part of the Linux state. It can
also take more than one host process to establish new pairing after the reader
re-enumerates.

`SetOwnershipFailureCount` is the pinned DLL's generic `DoPairing` failure
counter. A nonzero value is not by itself proof that ownership is incompatible.
Values one through four can describe a recoverable pairing transition; the
vendor has separate capped-counter behavior after repeated failures. Preserve
the value as diagnostic context instead of using it as a reset decision.

Normal startup waits for the exact asynchronous pairing worker, requires the
vendor's capture strategy to exist, and opens the complete biometric pipeline
through `WINBIO_SENSOR_READY`. It exposes the reader only after that safe
boundary. This prevents the capture crash seen when an earlier build entered
verification with a null strategy. When the boundary is not reached, fprintd
may report no device or an initialization timeout while the services
themselves remain available.

Run guided setup:

```console
$ synatudor-setup
```

It makes up to three bounded ordinary starts with a USB/session restart between
attempts. It never invokes vendor unpairing. Success requires the host's
reader-scoped safe-open marker, and the failure count appears only as a
diagnostic. If all three attempts fail, inspect the ordinary service errors
before choosing any destructive maintenance.

To invoke the vendor's unpair maintenance callback explicitly, run:

```console
$ synatudor-reset-ownership
```

This command changes pairing and local enrollment state and may invalidate
Windows and Linux enrollments. It sends the pinned DLL's private control code
to `OnResetOwnership`, which calls `DoUnpairing`. It is not the standard
`IOCTL_BIOMETRIC_RESET`, and a successful return does not prove physical
erasure of the sensor's template database. Do not use it for secure erase.

After the callback succeeds, the helper backs up private state, removes
incompatible local pairing data and this driver's fprintd references, and sets
a durable pending-validation marker. It then makes up to three ordinary normal
starts. If none reaches the full safe-open boundary, both fingerprint services
remain stopped behind helper-owned runtime masks. Run
`synatudor-reset-ownership` again to resume normal validation; it recognizes
the pending marker and does not issue another vendor-unpair request. A
successful open changes the marker to a durable completed value. Later helper
invocations report that completion without issuing another callback; use
`synatudor-reset-ownership --new` only to authorize a separate vendor-unpair
operation. Once validation succeeds, run `synatudor-setup` to enroll again.

If the vendor callback itself does not report success, its physical outcome
may be indeterminate. It is not retried automatically. Review the service
errors and keep the private backup. If the failed transaction still contains
an enabled request, rerun the helper once to disable that request. A later
`synatudor-reset-ownership --new` invocation explicitly authorizes a separate
maintenance transaction.

## Reset a wedged USB session

Stop both consumers and reset the reader with the supplied helper:

```console
$ ./scripts/reset
```

Then retry `fprintd-verify`. The helper reloads the services after the USB
reset. It preserves enrollment, pairing, identity, and calibration state; it
clears only the previous safe-open failure marker while both services are
stopped so the next initialization gets a fresh result. It refuses to run
while ownership-reset validation is pending or its marker is malformed; use
`synatudor-reset-ownership` to resume that recovery.

Do not delete one pairing or cryptographic state file by itself. The values
must remain mutually consistent with the reader. A local
`synatudor-uninstall --purge` does not invoke the vendor's reader-side unpair
callback. If unpair maintenance is necessary, run
`synatudor-reset-ownership` while the driver is installed, then use the purge
option if you also want to remove all remaining local state.

## Authorization dialog and repeated scan retries

Guided setup completes sudo authorization before printing scan instructions and
enrolls for your regular user explicitly. Keep the reader uncovered while
authorizing. A manually invoked `fprintd-enroll` may print `Enrolling` before
its separate graphical authorization dialog finishes.

Repeated `enroll-retry-scan` does not necessarily mean poor finger contact. If
the service log reports a capture worker exiting with its request pending and
cancellation status `0x800703e3`, capture did not produce a usable image. Inspect
the status-only calibration result and capture-prerequisite diagnostics rather
than repeatedly changing finger placement. Saved calibration matching the reader
proves its format and association, not that the vendor accepted it at runtime.

## Improve finger contact

This is a small swipe-style pad presented as a touch reader. Place a broad part
of the fingertip across the upper center of the pad, use light pressure, and
hold it steady until fprintd reports the result. Enroll several slightly
different placements instead of repeatedly touching the exact same point.

## Build cannot obtain the Windows driver

Download `huy103af07m6.exe` from Lenovo's support page and provide it locally:

```console
$ export SYNA_TUDOR_INSTALLER=/path/to/huy103af07m6.exe
$ sha256sum "$SYNA_TUDOR_INSTALLER"
2713966a9ce5906fce12d33ead81f8c15a72d7b1cbe4e523613147181ce32343  /path/to/huy103af07m6.exe
```

The build deliberately refuses a package with a different digest.

## Reporting a failure

Follow `CONTRIBUTING.md`. State and verbose logs can include sensor-specific or
biometric-derived material. Describe the failure and include ordinary service
errors first; do not publish files from `/var/lib/tudor` or `/var/lib/fprint`.
