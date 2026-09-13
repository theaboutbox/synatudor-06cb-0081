# Next steps

Normal startup and enrollment passed on a Lenovo Yoga C930-13IKB with USB
reader `06cb:0081`. On 2026-09-13, production revision `0.1.0-12.4` passed five
guided matches and one unenrolled-finger rejection after the capture
input-lifetime fix, without timeouts or the former retry loop. The
[latency investigation](LATENCY-INVESTIGATION-2026-09-13.md) records the build,
results, and limits of that short series.

1. Investigate service-only restart failure. Revision 12.1 could not initialize
   the capture strategy after restarting both fingerprint services; ordinary
   USB reset restored the reader and its existing enrollment. Retest on the
   latest build and trace the remaining startup failure if it reproduces.
2. Complete lifecycle and authentication validation. Check suspend/resume,
   reboot, service restart, and USB reset on the latest build. Recheck
   enrollment/deletion, cancellation, sudo, polkit, the lock screen, and password
   fallback separately. Preserve enrolled state during ordinary restart tests.
   Extend matching and rejection tests to longer use before claiming a
   long-term reliability improvement.
3. Validate installation on another supported machine. Test a clean install
   from GitHub on another `06cb:0081` reader, followed by an upgrade and ordinary
   recovery. Use these results to decide when the experimental installer is
   ready for wider use and whether to submit the packaging to the AUR.

See [Testing](TESTING.md) for the detailed checks and
[Validation](VALIDATION.md) for completed results. Explicit vendor-unpair
maintenance is a separate recovery test, not a prerequisite for using an
already working reader.
