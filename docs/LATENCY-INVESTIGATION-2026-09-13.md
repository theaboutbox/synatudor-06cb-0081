# Capture latency investigation — 2026-09-13

The user reported alternating fast and very slow verification and an apparent
lack of password entry in administrative dialogs. These are separate paths.

## Capture input lifetime

A local diagnostic package (`0.1.0-12.2`) logged only worker timing, mode,
status, and readiness fields at validated call sites in the pinned vendor DLL.
It did not record fingerprint images, templates, or cryptographic material.

Two successive six-second verification sessions, with no finger on the reader,
produced markedly different traces:

- First: one mode-1 capture, 6,111,250 microseconds in the capture function,
  ending with status `0x67` on cancellation.
- Second: 24 mode-0 attempts, each returning `0x6f` in 0–14 microseconds.
  The existing recovery relay restarted these approximately every 250 ms.

The WUDF1 bridge borrowed the caller's input pointer in `MyRequest`. The capture
IOCTL (`0x440014`) uses METHOD_BUFFERED, but its asynchronous worker can read
that input after the adapter has returned and reused its stack. Vendor code
copies the request input and reads byte 4 as the capture mode. This makes input
lifetime a concrete defect and a candidate explanation for the invalid modes.
The pinned adapter confirms the stack lifetime: RVA `0x6a13` passes
`rbp - 1` as the 32-byte input to the IOCTL at `0x6a27`; RVA `0x6979`
writes its mode at `rbp + 3` (input byte 4). The driver copies the input
inside its asynchronous worker at RVA `0x1ae75`.

`MyRequest` now owns a copy of buffered/direct IOCTL input for the request's
lifetime. METHOD_NEITHER retains its pointer semantics. Output storage retains
its existing caller-owned behavior; this change does not claim complete Windows
buffer aliasing emulation. Dispatch validates nonempty buffers and reports
allocation failure instead of letting `std::bad_alloc` escape the boundary.

The regression overwrites the original input before retrieving the request's
input memory. It fails before the fix (check 1, exit 11), passes after the fix,
and also checks empty input and output storage. All 24 tests pass in both the
normal and ASan/UBSan builds.

Windows documents the captured input buffer for buffered and direct IOCTLs in
[Buffer descriptions for I/O control codes](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/buffer-descriptions-for-i-o-control-codes).

The fixed diagnostic package `0.1.0-12.3` and production package `0.1.0-12.4`
both built successfully and passed all 24 package tests plus shell-helper suites.
The production snapshot is `eb62c7ca6579af4a646d462fdfa74ffc7a984d0d`; it excludes
the temporary timing hooks. Package SHA-256:
`5f7cc8d4634dc884150de3dec59167241c841f0fbb8767e283711eb1c20ff7c8`.

The fixed diagnostic package `0.1.0-12.3` was installed successfully. Two
successive untouched-reader captures now dispatch and execute mode 1, taking
5,909,510 and 6,074,099 microseconds before cancellation. Neither emits a
pending-worker recovery or the former mode-0 retry loop. This is a controlled
hardware improvement over revision 12.2.

Two subsequent interactive windows (30 and 60 seconds) expired without a match
or no-match result. Finger contact during these windows has not been confirmed;
they do not establish whether actual recognition still stalls. All four
captures used mode 1. Guided checks with a visible terminal and an explicit
start prompt have been prepared to eliminate prompt timing ambiguity. The
initial service-only restart failure has not yet been retested.

The final production package `0.1.0-12.4` is installed. `fprintd-list` confirms
the existing right-index enrollment. `pacman -Qkk` reports 36 files with zero
altered files. The final guided checks passed as recorded below.

## Final guided hardware results

On production revision `0.1.0-12.4`, the user started each check from a visible
terminal, then placed the indicated finger. All six checks passed:

| Check | Finger | Result | Total elapsed seconds |
| --- | --- | --- | --- |
| 1 | right index | verify-match | 1.316 |
| 2 | right index | verify-match | 1.243 |
| 3 | right index | verify-match | 1.146 |
| 4 | right index | verify-match | 1.230 |
| 5 | a DIFFERENT, UNENROLLED finger | verify-no-match | 1.040 |
| 6 | right index | verify-match | 1.264 |

Times include process startup and human finger placement; they are not isolated
recognition latency. There were no timeouts, and the journal records the same
five matches and one rejection without pending-worker recovery or capture
errors during the sequence. The final right-index match also verifies recovery
after a normal no-match. The user reported that the checks went smoothly.

Together with the before/after no-finger traces, these results strongly support
the borrowed stack input as the cause of the observed retry-loop delays. This
short series does not establish long-term failure rates or fix the separately
observed service-only restart issue. Suspend/resume and reboot remain untested.
Raw guided results remain in the private local `guided-checks.json`; journals
and package artifacts are kept in the same validation cache.

## Administrative password entry

The local polkit PAM stack ran `pam_fprintd.so` before `pam_unix.so`. Omarchy's
Quickshell polkit agent shows its password field only when PAM requests a
response. Consequently, the default fingerprint wait postponed password entry.
The [pam_fprintd manual](https://man.archlinux.org/man/pam_fprintd.8.en) documents
the default 30-second timeout and sequential PAM authentication limitation.

Initially removed only the managed fingerprint block from `/etc/pam.d/polkit-1`,
leaving its password authentication and account/session rules. A local screenshot
confirmed immediate "Enter password" entry, and authentication then successfully
installed revision 12.3.

The user subsequently selected **fingerprint for up to 10 seconds, then password**.
The local installation script restored the managed fingerprint block with
`pam_fprintd.so timeout=10`, retaining the lid-closed skip and subsequent
`pam_unix.so` password prompt. That configuration is installed on the test
machine; it is not a change to the repository's default PAM setup. A fresh dialog
fallback timing check remains pending. Sudo and lock-screen PAM files are unchanged.
Reapplying the repository's setup helper may reset this local timeout preference.

Original PAM configuration and pre-update fingerprint state are backed up under
`/var/backups/synatudor-0081/latency-20260913/` with root-only access. No enrollment
or pairing data was deleted. Diagnostic sources and build logs are private local
artifacts under `~/.cache/synatudor-0081/latency-20260913/`.
