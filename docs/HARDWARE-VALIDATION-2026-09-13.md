# Local hardware validation — 2026-09-13

This records the initial revision 12.1 installation. Subsequent latency debugging
and the administrative password configuration are documented in the
[latency investigation](LATENCY-INVESTIGATION-2026-09-13.md).

Installed and tested the reviewed driver on the attached Synaptics `06cb:0081`
reader using the existing right-index enrollment. No vendor unpair, template
deletion, reenrollment, PAM changes, suspend, or reboot was performed.

## Installed build

- Local Arch package: `synatudor-0081 0.1.0-12.1` (previously `0.1.0-12`).
- Dependencies: `libfprint-tod 1.95.2+tod1-1`, `fprintd 1.94.5-2`.
- Isolated source snapshot: `6b8110bd2025cf800da48fb92bb922de68d53050`.
  The original working tree remains uncommitted. Production sources and tests
  were compared byte-for-byte with this snapshot after installation.
- Package SHA-256:
  `255d1e6d740329d94efc07b34e36991287daf59e9da3b967942597467c908e17`.
- `pacman -Qkk`: 36 files, zero altered files. The installed host, launcher,
  bridge libraries, and TOD module also match the package payload hashes.
- The final Arch build passes all 24 Meson tests and both shell-helper suites,
  with no compiler warnings in its build log. The final full ASan/UBSan suite
  also passes 24/24 tests.

The initial package build exposed an intermittent ECC decode/storage bug.
The repair, deterministic regression, 1,000 repeated crypto test runs, and
remaining analyzer findings are described in the
[code review](CODE-REVIEW-2026-09-13.md#installation-follow-up).

## Live results

| Check | Result |
| --- | --- |
| Installation followed by ordinary USB reset | Pass. Pairing and calibration restored; safe pipeline publication and host ready message observed. Startup took approximately six seconds. |
| Existing enrollment | Pass. `fprintd-list` reports the right index finger. |
| Untouched reader, cancel after eight seconds | Pass. Client exits on the requested interrupt without a forced kill; the next verification can claim the reader. |
| Enrolled right index finger | Pass. `fprintd-verify` returns `verify-match`. |
| Different finger, following the unenrolled-finger prompt | Pass. `fprintd-verify` returns `verify-no-match`. |
| Restart both fingerprint services without USB reset | **Fail.** The pairing worker returns without a capture strategy. The initialization guard rejects the open and the host exits with code 1; fprintd reports no devices. |
| Recovery using `synatudor-reset` | Pass. USB reset restores a ready pipeline and the existing enrollment. |
| Right-index verification after recovery | Pass. A second `verify-match` confirms that the saved enrollment still works. |

Frequent vendor capture-worker exits with pending requests and internal capture
retries remain in the journal. The successful checks do not establish that
capture throughput or reliability has improved. User response time was included
in these interactive sessions, so their elapsed times are not fingerprint
recognition latency benchmarks.

The service-restart failure is an observed limitation of this installed build.
This session did not perform a controlled comparison with the previous package
to establish whether it is a regression. The driver was left working after the
ordinary USB reset and successful second match. Use `sudo synatudor-reset` for
this recovery; the separate ownership-reset command is not needed for it.

Reboot, suspend/resume, new enrollment/deletion, and individual PAM consumers
remain untested with this build.

## Local evidence and rollback material

Package, snapshot, build logs, and private hardware journal excerpts are kept
under `~/.cache/synatudor-0081/`; the validation directory is
`review-install-20260913-075310`. These are local artifacts, not public release
attachments. Raw hardware logs include device identifiers.

Before installing, both services were stopped with runtime activation masked,
and a root-only state backup was saved at
`/var/backups/synatudor-0081/review-20260913-075310/state.tar`. The prior revision
12 package remains in the private package cache. No state restore was needed.
