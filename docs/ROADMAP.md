# Next steps after revision 12

The 2026-09-12 milestone is successful normal startup, enrollment, and a
fingerprint match on a Lenovo Yoga C930-13IKB with USB reader `06cb:0081`.
The tested package is `synatudor-0081 0.1.0-12`. The validation record identifies
the exact source, package checksum, automated checks, and hardware results.

1. Reduce capture retries. The successful run still repeatedly exited vendor
   capture workers with requests pending despite successful calibration and
   ready capture prerequisites. Determine why those workers leave the request
   unfinished, then verify that a fix reduces retries without disrupting
   cancellation or correct and incorrect finger handling.
2. Validate persistence and authentication. Check repeated correct matches,
   wrong-finger rejection, service restart, USB reset, and reboot. Exercise
   sudo, polkit, the lock screen, and password fallback separately. Preserve
   the enrolled state while testing the ordinary restart paths.
3. Validate installation on another supported machine. Test a clean install
   from GitHub on another `06cb:0081` reader, followed by an upgrade and ordinary
   recovery. Use these results to decide when the experimental installer is
   ready for wider use and whether to submit the packaging to the AUR.

See [Testing](TESTING.md) for the detailed checks and
[Validation](VALIDATION.md) for completed results. Explicit vendor-unpair
maintenance is a separate recovery test, not a prerequisite for using an
already working reader.
