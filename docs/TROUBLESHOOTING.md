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
fprintd commands during first initialization; setup bounds the attempt and
checks for an ownership mismatch before it retries anything.

## Device missing after an ownership failure

The reader can retain ownership that no longer matches the private identity
under `/var/lib/tudor`. This can happen after switching from Windows Hello,
using an older experimental build, or deleting only part of the Linux state.
The vendor records the mismatch by incrementing
`SetOwnershipFailureCount`; the host separately records that the current run
detected the mismatch.

Normal startup deliberately rejects that initialization before exposing the
biometric adapters. This guard prevents the later capture crash seen when an
earlier build allowed the mismatched state to reach verification. In this
case, fprintd may report no device or an initialization timeout while the
services themselves remain available.

Run guided setup:

```console
$ synatudor-setup
```

It makes one bounded probe and uses the approved ownership reset only when that
probe fails and the host's reader-scoped marker says the current run rejected
ownership. The older failure count appears only as a diagnostic. A successful
probe is never treated as a mismatch because of stale state. The prompt is
destructive: the reset erases all fingerprints on the reader, including
Windows Hello enrollments. It backs up private local state before proceeding,
removes this driver's stale fprintd metadata for every local user, and backs up
and removes the older unscoped pairing records for every reader managed by the
driver. Old unscoped calibration is backed up and migrated only when its
embedded reader identity matches. It never repeats the destructive request
automatically.

If it does not report success, the physical outcome may be indeterminate.
Rerunning the command explicitly can reset the reader a second time; first
keep the private backup and review the ordinary service errors.

To perform only the ownership recovery, run:

```console
$ synatudor-reset-ownership
```

Then run `synatudor-setup` to initialize and enroll again. If the first clean
initialization after a successful reset records another ownership failure,
stop and collect the ordinary service errors described below; do not keep
resetting the reader.

## Reset a wedged USB session

Stop both consumers and reset the reader with the supplied helper:

```console
$ ./scripts/reset
```

Then retry `fprintd-verify`. The helper reloads the services after the USB
reset. It preserves enrollment, pairing, identity, and calibration state; it
clears only the transient ownership-failure marker while both services are
stopped so the next initialization gets a fresh result.

Do not delete `SecureChannelIdentity.blob` by itself. The key must remain
consistent with the sensor's pairing and cryptographic registry state. A local
`synatudor-uninstall --purge` also cannot clear ownership stored inside the
sensor. If a complete reset is necessary, run
`synatudor-reset-ownership` while the driver is installed, then use the purge
option if you also want to remove all remaining local state.

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
