# Architecture

This project runs the original x86-64 Synaptics Windows biometric driver inside
a restricted Linux host and connects it to `fprintd` through libfprint's TOD
ABI. It is a compatibility layer for USB `06cb:0081`, not a native
reimplementation of the sensor protocol.

```text
PAM / desktop / fprintd clients
              |
           fprintd
              |
       libfprint TOD ABI
              |
        libtudor_tod.so
              |
  system D-Bus launcher service
              |
    sandboxed tudor_host process
              |
 WinAPI + WUDF compatibility layer
              |
  Synaptics Windows DLLs + libusb
              |
      USB 06cb:0081 sensor
```

## Components

- `libfprint-tod` presents the reader to libfprint and translates open,
  enroll, verify, identify, delete, suspend, and resume operations into the
  project's IPC protocol.
- `tudor-host-launcher` is a system D-Bus service. It starts one host process
  with the USB file descriptor and owns persistent state outside the host
  sandbox.
- `tudor-host` services IPC requests. It drops privileges and capabilities,
  creates namespaces, applies resource limits and seccomp restrictions, and
  gives the loaded driver only the resources needed for USB and IPC.
- `libtudor` loads the two PE DLLs, implements the Win32, cryptographic, and
  WUDF calls they use, and exposes the Windows Biometric Framework sensor,
  engine, and storage interfaces.
- `subprojects/cryptbridge` implements additional Windows cryptography and
  registry behavior used while the sensor establishes its secure channel. It
  generates a random P-256 pairing identity once for each reader, commits it
  to protected device state, and reloads it when the sensor re-enumerates.
  Channel secrets are derived during each handshake.
- `cli` is a development interface and has a less restrictive threat model
  than the fprintd path.

The persistent P-256 generation behavior matches the pinned Synaptics DLL's
ownership flow. A different vendor DLL must be traced and validated before it
can use this compatibility path.

## Vendor driver handling

The repository contains no Synaptics or Lenovo binary. During a local build,
`libtudor/download_driver.sh` obtains Lenovo package `huy103af07m6.exe`, checks
its pinned SHA-256, and uses `innoextract` to copy only
`synaAdvAdapter.dll` and `synaWudfBioUsb.dll`. Meson converts those DLLs to
binary objects and embeds them in the locally built `libtudor.so`.

## Persistent state

The launcher stores state under a root-only directory:

```text
/var/lib/tudor/devices/<vid>-<pid>-<usb-serial>/
```

The allowlisted values include calibration, pairing state, the P-256
secure-channel identity, the emulated cryptographic registry, and a small set
of device counters. The host asks for these values over a dedicated
sequenced-packet socket bound to the reader's stable state ID. It never
receives a path or regular-file descriptor for the state directory. Values
are bounded, names are checked, and replacements are written privately.
Writes are flushed with their containing directory before the launcher
acknowledges them, which gives the ownership-reset transaction a stable-storage
ordering boundary.

Older builds also stored vendor registry pairing values as top-level `.tpd`
files keyed by a vendor-generated sensor name. That format contains no proven
mapping to the USB serial used by the per-reader directory. Ownership recovery
therefore backs up and clears every legacy `.tpd` record managed by this driver
before allowing the newly unpaired reader to initialize.

Older installations can also have one top-level `CalibrationData.blob`. For an
`06cb:0081` reader, the launcher accepts calibration only as a 40,780-byte blob
whose embedded six-byte reader ID matches the nibble-swapped USB serial in the
state ID. This applies to both device-scoped data and the legacy fallback. A
valid fallback is durably copied into the exact reader directory and then
removed; malformed or wrong-reader data is treated as missing so the vendor
can calibrate the attached reader instead.

The launcher also keys live hosts by that stable ID. If ownership work resets
the USB device and changes its bus address, the launcher closes the previous
state channel and retires the stale process before starting its replacement.

On a new sensor, the vendor driver performs its own no-touch calibration and
writes the resulting blob through this channel. Calibration is sensor-specific
and must never be copied from another machine.

The `06cb:0081` driver exposes its own Windows biometric storage adapter. The
Linux bridge uses that adapter for enrollment, lookup, and deletion, so the
full fingerprint template lives in the sensor-managed database. The fprintd
record contains the Windows biometric GUID, finger identifier, and an empty
compatibility payload that lets later requests address the sensor record.

## Ownership failure guard

Reader ownership is not represented by the P-256 identity alone. The pinned
vendor driver also uses sensor-side pairing and values in its emulated
cryptographic registry. If those parts disagree, `OnPrepareHardware` can still
return success and report the device ready before an asynchronous registry
write reveals the failure. An earlier bridge then allowed verification to
enter `CaptureImage` with incomplete vendor state, where the vendor DLL could
crash.

The normal initialization path now resets an in-process observer immediately
before `OnPrepareHardware`. It latches only an exact, nonzero `VT_UINT` write
to `SetOwnershipFailureCount` made during that initialization. After the
vendor's asynchronous preparation window, and again after `OnD0Entry`, the
host rejects initialization if the latch is nonzero. The WinBio interfaces and
host `READY` message are never exposed in that state. Before normal
initialization, the host also stores `OwnershipFailureDetected.bool` as false;
it stores true only when that run rejects the exact nonzero write or the
vendor's capped-counter error. Setup requires a failed probe and this marker
before starting destructive recovery. A previously persisted vendor counter
is diagnostic only and does not drive the in-process guard. The transport
reset used by setup removes any old marker while the services are stopped, so
an early failure in the next host cannot inherit a true result from a previous
attempt.

## Explicit ownership recovery

Ownership recovery is a reader-scoped, one-shot maintenance path. The
privileged helper writes `ResetOwnershipRequest.bool` and initializes
`ResetOwnershipResult.uint` in the exact device-state directory. When the host
starts, it records an in-progress barrier and consumes the request before
calling any destructive vendor code, clears the vendor's capped failure
counter, and initializes in recovery mode. Recovery mode may pass the
ownership guard only long enough to issue WUDF IOCTL `0x442040`, which the
pinned DLL dispatches to `OnResetOwnership` and its unpairing routine. It never
queries WinBio adapters or sends `READY`.

The host records success or failure and exits as its teardown boundary. On
success, the helper removes local values that no longer match the unpaired
sensor, removes fprintd references for this driver from every local user,
removes the older unscoped pairing records for every reader managed by the
driver, and preserves calibration only when it belongs to this physical
reader. A matching legacy calibration is migrated into the reader directory,
and all unscoped calibration values are removed. It then resets USB and starts
the services. The helper creates and flushes a root-only backup before changing
anything. The durable barrier
blocks another reset and ordinary startup until privileged cleanup finishes;
the helper then removes the barrier. A crash, USB disconnect, or service retry
therefore cannot repeat the ownership reset without another explicit request.
The transport-reset and ownership-reset helpers also share an exclusive
root-owned runtime lock so they cannot manipulate the same reader concurrently.
While either helper requires both services to remain down, it temporarily
runtime-masks them so another local D-Bus client cannot reactivate fprintd or
the launcher in the middle of protected state work. A root-only runtime token
distinguishes helper-owned masks from administrator-created masks and lets a
later invocation repair or release a partial mask operation.

## Changes needed for `06cb:0081`

The inherited relinking project already loaded a related Synaptics driver, but
this device needed additional compatibility work:

- USB discovery and udev matching for `06cb:0081`
- a WUDF 1 object model and ABI layout matching this driver build
- Windows string, wait, time, property, process, pipe, WinUSB, and crypto calls
- generated per-reader P-256 identity and fixed-width key serialization
- persistent device and crypto-registry state
- stable-reader host replacement across USB re-enumeration
- secure state IPC across the host sandbox boundary
- an ownership-failure startup guard and explicit one-shot sensor unpairing
- capture completion recovery for the driver's asynchronous request pattern
- the vendor's native biometric storage ABI and lifecycle
- exact GUID and finger mapping between fprintd and Windows Biometric Framework
- bounded WinUSB diagnostic playback so the host stays within its 64 KiB stack

The native storage path matters: an earlier in-memory storage shim made the
Linux operation appear successful but never committed a template to the
sensor's database.
