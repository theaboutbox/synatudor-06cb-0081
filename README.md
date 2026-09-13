# Synaptics `06cb:0081` fingerprint support for Linux

Use a Synaptics Tudor fingerprint reader with USB ID `06cb:0081` through
`fprintd` on x86-64 Linux. This project runs the matching Windows biometric
driver in a restricted compatibility host and connects it to libfprint through
the TOD ABI, enabling enrollment and fingerprint authentication in Linux.

The installer targets **Arch Linux and [Omarchy](https://omarchy.org/)**.
Hardware testing has been on a Lenovo Yoga C930-13IKB (type 81C4), with sensor
firmware 6.7 and Lenovo driver 5.5.2731.1050. Other computers with the exact
same USB ID need testing; other Synaptics product IDs are not supported by
this port.

> [!WARNING]
> This is experimental system software. Initializing the reader may replace
> fingerprints enrolled through Windows Hello. Keep password login available.
> Failures in the compatibility layer or vendor driver could affect the reader,
> authentication, or system security. The project comes without warranty.

## Install

Confirm the exact supported USB ID:

```console
$ lsusb -d 06cb:0081
Bus 001 Device 003: ID 06cb:0081 Synaptics, Inc. Metallica MIS Touch Fingerprint Reader
```

Clone and run the installer from a terminal as your regular desktop user:

```console
$ git clone https://github.com/theaboutbox/synatudor-06cb-0081.git
$ cd synatudor-06cb-0081
$ ./scripts/install
```

The installer builds the tested TOD-enabled libfprint and driver packages,
then guides you through initialization, reader-specific calibration, enrollment,
and a test match. Keep the sensor uncovered until prompted to scan. Enrollment
is interactive. On Omarchy, setup also configures fingerprint authentication
for sudo, polkit, and the lock screen with password fallback. On plain Arch,
it leaves PAM configuration to you.

No Synaptics or Lenovo binary is stored in this repository. The local build
downloads a pinned Lenovo driver package, verifies its SHA-256, and extracts two
DLLs without running the Windows installer. The locally built package embeds
those DLLs and remains subject to their vendor terms.

To install now and enroll later, run `./scripts/install --driver-only`, then
`synatudor-setup` when ready. To uninstall, use `synatudor-uninstall`; it preserves
device state for a later reinstall. See [Installation](docs/INSTALL.md) for
requirements, build options, updates, recovery, and removal.

## Known issues and validation limits

Normal pairing and enrollment have passed on the tested laptop. The latest
recorded production build passed five matching-finger checks and one
unenrolled-finger rejection without timeouts or the earlier capture retry loop.
The [latest hardware results](docs/LATENCY-INVESTIGATION-2026-09-13.md#final-guided-hardware-results)
include timings and the limits of that short test series.

- **Service restarts can leave the reader unavailable.** This occurred in an
  earlier tested build and has not been retested after the capture fix.
  Ordinary USB reset with `sudo synatudor-reset` restored the reader and its
  enrollment. See [Troubleshooting](docs/TROUBLESHOOTING.md).
- **Lifecycle coverage is incomplete.** Suspend/resume and reboot remain
  untested. New enrollment/deletion and each PAM consumer still need rechecking
  on the latest build; earlier success does not validate every later change.
- **Broader reliability is unproven.** Another laptop, a clean install on another
  reader, upgrades, and long-term use need validation. Explicit vendor-unpair
  recovery has not passed a complete end-to-end recovery test on the corrected
  lifecycle.
- **Password entry can follow a fingerprint wait.** With the configured PAM
  sequence, administrative dialogs may wait for fingerprint authentication to
  time out before showing a password field. See the
  [authorization guidance](docs/TROUBLESHOOTING.md#authorization-dialog-and-repeated-scan-retries).
- **Automated checks have limits.** The review records passing native and
  ASan/UBSan suites alongside unresolved TSan, static-analysis, and vendor-PAL
  Memcheck findings. The proprietary DLL is not sanitizer-instrumented. See
  the [code review](docs/CODE-REVIEW-2026-09-13.md).

Keep `/var/lib/tudor`, `/var/lib/fprint`, and `~/.cache/synatudor-0081` private.
They contain device state, enrollment references, or locally packaged vendor
code. Do not share fingerprint captures or unedited debug logs. The separate
`synatudor-reset-ownership` command changes pairing state and may invalidate
Windows and Linux enrollments; read the [recovery instructions](docs/INSTALL.md#pairing-and-first-setup)
before using it. It is not a proven secure-erase tool.

## Why this repository exists

The upstream projects supplied the foundation for running Synaptics Windows
drivers on Linux. Making this particular reader usable through normal
installation, enrollment, authentication, and recovery required substantial
additional work:

- **Device compatibility:** the pinned driver's WUDF and cryptographic APIs,
  secure-channel setup, and native biometric storage, so enrollment actually
  commits templates to the sensor.
- **Reliable operation:** pairing completion and capture-readiness checks,
  asynchronous request lifetime fixes, and repairs to USB cancellation,
  timeouts, threading, and cleanup.
- **Persistent state and recovery:** reader-specific calibration and pairing,
  protected storage across the sandbox, ordinary USB recovery, and explicit
  one-shot vendor-unpair maintenance with resumable validation.
- **Installation and maintenance:** reproducible source packaging, pinned build
  inputs, Arch installation helpers, Omarchy authentication setup and rollback,
  regression tests, and recorded hardware validation.

This repository brings that work together as an installable, documented
`06cb:0081` project. The [development history](docs/DEVELOPMENT-HISTORY.md)
explains the engineering decisions and post-fork fixes; [Architecture](docs/ARCHITECTURE.md)
describes how the components fit together.

## Credits

Built on [Popax21/synaTudor](https://github.com/Popax21/synaTudor), particularly
its relink branch, and the subsequent work in
[rstar000/synaTudor](https://github.com/rstar000/synaTudor). Their work made this
port possible, and the repository retains their history and authorship.
Wine and CodeWeavers contributors are credited in the inherited compatibility
code and its original license notices.

See [NOTICE](NOTICE), [LICENSE](LICENSE), and individual source-file notices.
The vendor driver remains the work of Synaptics and Lenovo; this project is
not affiliated with or endorsed by either company.

## Documentation

| Document | What it covers |
| --- | --- |
| [Installation](docs/INSTALL.md) | Setup, manual builds, updates, recovery, and uninstall. |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Device discovery, stalled captures, authorization, and diagnostics. |
| [Architecture](docs/ARCHITECTURE.md) | Components, sandbox, device state, pairing, and recovery design. |
| [Testing](docs/TESTING.md) | Automated checks and the hardware validation checklist. |
| [Validation record](docs/VALIDATION.md) | Build provenance and recorded results, with links to later checks. |
| [Roadmap](docs/ROADMAP.md) | Remaining reliability and hardware validation work. |
| [Development history](docs/DEVELOPMENT-HISTORY.md) | Post-fork engineering history and revision context for maintainers and agents. |
| [Code review — 2026-09-13](docs/CODE-REVIEW-2026-09-13.md) | Reliability repairs, regression coverage, and unresolved analysis findings. |
| [Hardware validation — 2026-09-13](docs/HARDWARE-VALIDATION-2026-09-13.md) | Matching, cancellation, service-restart failure, and USB recovery checks. |
| [Latency investigation — 2026-09-13](docs/LATENCY-INVESTIGATION-2026-09-13.md) | Capture input-lifetime fix, latest guided results, and local polkit observations. |

Read [Contributing](CONTRIBUTING.md) before submitting changes or diagnostics.
Reports from another `06cb:0081` machine are especially useful.
