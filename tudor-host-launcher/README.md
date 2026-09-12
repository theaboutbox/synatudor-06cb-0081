# tudor-host-launcher
This folder contains a simple DBus service capable of launching and managing
tudor_host processes. This is necessary because fprintd is sandboxed in such a
way that the host's own sandbox fails to properly initialize. Because the host
launcher is outside of this sandbox (it does still employ systemd unit
sandboxing, but only to the extend possible when maintaining the host's
functionality), it can properly launch these host processes, and because it
provides its services using the DBus, the libfprint-tod module can interact with
it and take over IPC once the process has been started.

## Persistent device state

The systemd unit creates a private state directory (normally
`/var/lib/tudor`). The launcher, which remains outside the vendor-driver
sandbox, stores named device properties below:

```
/var/lib/tudor/devices/<vid>-<pid>-<usb-serial>/
```

The host and launcher use a dedicated sequenced-packet socket for state I/O.
The host never receives a directory or regular-file descriptor. Property names
are allowlisted, state identifiers are restricted to safe path-component
characters, writes use private replacement files, and blobs are capped at 64
KiB.

For migration from an older installation, the launcher accepts a root-owned,
mode `0600` `/var/lib/tudor/CalibrationData.blob` only when its exact size and
embedded reader ID match the `06cb:0081` USB serial. It durably copies that
blob into the sensor-specific directory and removes the unscoped source after
the first use. Reader-scoped calibration gets the same identity check. Invalid
calibration is treated as missing so the attached reader is calibrated instead.
The state directory itself remains `root:root` mode `0700`; systemd applies
that mode through `StateDirectoryMode=`.
