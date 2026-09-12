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
the operation completes. An interrupted calibration can be retried by
restarting the two services.

## Reset a wedged USB session

Stop both consumers and reset the reader with the supplied helper:

```console
$ ./scripts/reset
```

Then retry `fprintd-verify`. The helper reloads the services after the USB
reset.

Do not delete `SecureChannelIdentity.blob` by itself. The key must remain
consistent with the sensor's pairing state. If a complete reset is necessary,
use `synatudor-uninstall --purge` so enrollments and Tudor state are handled
together, then reinstall.

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
