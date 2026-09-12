# Synaptics `06cb:0081` fingerprint support for Linux

This project makes the Synaptics Tudor fingerprint reader with USB ID
`06cb:0081` available to `fprintd` on x86-64 Linux. It runs the matching
Windows biometric driver in a restricted compatibility host and connects it
to libfprint through the TOD ABI.

The current release targets Arch Linux and [Omarchy](https://omarchy.org/). It
has been tested on a Lenovo Yoga C930-13IKB. Other laptops with the same USB ID
are especially useful test cases.

> [!WARNING]
> This is experimental system software. Initializing the reader may replace
> fingerprints enrolled through Windows Hello. Keep password login available,
> and use it at your own risk. The project comes without warranty; failures in
> this compatibility layer or the vendor driver could affect the reader,
> authentication, or system security.

## Install on Arch Linux or Omarchy

Confirm that the reader has the exact supported USB ID:

```console
$ lsusb -d 06cb:0081
Bus 001 Device 003: ID 06cb:0081 Synaptics, Inc. Metallica MIS Touch Fingerprint Reader
```

Then clone the repository and run the installer as your regular desktop user:

```console
$ git clone https://github.com/theaboutbox/synatudor-06cb-0081.git
$ cd synatudor-06cb-0081
$ ./scripts/install
```

The installer ensures that the exact tested TOD-enabled libfprint package is
installed, builds the driver as a local Arch package, and guides you through
reader calibration, fingerprint enrollment, and a test match. On Omarchy it
can also configure fingerprint authentication for sudo, polkit, and the lock
screen while preserving password fallback.

Enrollment is interactive, so the complete setup cannot run unattended. To
install the driver now and enroll later:

```console
$ ./scripts/install --driver-only
$ synatudor-setup
```

See [Installation](docs/INSTALL.md) for all installer modes and the manual
build path. See [Troubleshooting](docs/TROUBLESHOOTING.md) if initialization or
capture stalls.

## What the local build downloads

No Synaptics or Lenovo binary is stored in this repository or its source
release. During the build, the project downloads Lenovo package
`huy103af07m6.exe`, requires SHA-256
`2713966a9ce5906fce12d33ead81f8c15a72d7b1cbe4e523613147181ce32343`, and
extracts only the two required DLLs without running the Windows installer.
The resulting Arch package is for local use and contains those vendor files in
embedded form, subject to their vendor terms.

The installer also builds a pinned, signed `libfprint-tod` release because the
regular Arch `libfprint` package does not expose the required TOD driver ABI.

## Support status

The initial hardware port has passed:

- first initialization and reader-specific calibration
- enrollment and deletion through `fprintd`
- repeated matching and wrong-finger rejection
- persistence across service restarts and a USB reset
- a locally generated per-reader P-256 identity kept in root-only state
- fresh channel secrets and randomized ECDSA signatures
- sudo, polkit, and the Omarchy lock screen with password fallback
- the full automated suite under GCC, Clang, ASan/UBSan, and TSan

The commands, software versions, and limits of those checks are recorded in
[Validation](docs/VALIDATION.md).

Only the following combination has received hardware validation:

| Component | Validated value |
| --- | --- |
| USB device | Synaptics `06cb:0081` |
| Laptop | Lenovo Yoga C930-13IKB (type 81C4) |
| Sensor firmware | 6.7 |
| Operating system | Arch Linux with Omarchy |
| Architecture | x86-64 |
| Lenovo driver | 5.5.2731.1050, package `huy103af07m6.exe` |

A matching vendor ID alone is insufficient. Other Synaptics product IDs can
use different firmware, protocols, and driver ABIs.

## Privacy and device state

Calibration, pairing, the secure-channel identity, cryptographic registry
state, and enrollment metadata are stored under root-only `/var/lib/tudor`.
Calibration and the secure-channel identity are specific to one physical
reader. Never copy or publish files from `/var/lib/tudor` or `/var/lib/fprint`,
fingerprint captures, or unedited verbose logs.

Keep `~/.cache/synatudor-0081` private as well. It contains Lenovo's downloaded
package and the locally built Arch package, which embeds the vendor DLL data.

The normal uninstaller preserves this state so a reinstall can reuse it:

```console
$ synatudor-uninstall
```

Use `synatudor-uninstall --purge` only when you also want to delete every
fingerprint fprintd exposes for your user and all Tudor device state.

## How it works

```text
PAM and desktop clients
          |
       fprintd
          |
 libfprint TOD ABI
          |
   libtudor_tod.so
          |
 sandboxed Tudor host
          |
 Windows driver + libusb
          |
 Synaptics 06cb:0081
```

The bridge implements the WinAPI and WUDF behavior needed by this particular
driver, including its secure channel, persistent state, asynchronous capture,
and native biometric storage interfaces. [Architecture](docs/ARCHITECTURE.md)
describes the components and the work required for this sensor.

## Development

Build instructions and the hardware release checklist are in
[Testing](docs/TESTING.md). Completed checks are recorded in
[Validation](docs/VALIDATION.md). Please read [Contributing](CONTRIBUTING.md)
before posting diagnostics; state and logs can contain sensitive material.

This repository retains the history and work of
[Popax21/synaTudor](https://github.com/Popax21/synaTudor) and
[rstar000/synaTudor](https://github.com/rstar000/synaTudor). Wine-derived
compatibility code keeps its original copyright and license notices. See
[NOTICE](NOTICE) and [LICENSE](LICENSE).
