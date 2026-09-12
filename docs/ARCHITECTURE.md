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
  registry behavior used while the sensor pairs and establishes its secure
  channel. Generic CNG key generation produces fresh keys; persistent pairing
  and key-container state is kept only through explicitly scoped device-state
  and registry paths.
- `cli` is a development interface and has a less restrictive threat model
  than the fprintd path.

The pairing lifecycle and cryptographic call coverage match the pinned
Synaptics DLL. A different vendor DLL must be traced and validated before it
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

The allowlisted values include calibration, pairing state, the emulated
cryptographic registry, maintenance transaction markers, and a small set of
device counters. The host asks for these values over a dedicated
sequenced-packet socket bound to the reader's stable state ID. It never
receives a path or regular-file descriptor for the state directory. Values
are bounded, names are checked, and replacements are written privately.
Writes are flushed with their containing directory before the launcher
acknowledges them, which gives the vendor-unpair transaction a stable-storage
ordering boundary.

Older builds also stored vendor registry pairing values as top-level `.tpd`
files keyed by a vendor-generated sensor name. That format contains no proven
mapping to the USB serial used by the per-reader directory. Explicit
vendor-unpair recovery therefore backs up and clears every legacy `.tpd`
record managed by this driver before allowing the reader to pair again.

Older installations can also have one top-level `CalibrationData.blob`. For an
`06cb:0081` reader, the launcher accepts calibration only as a 40,780-byte blob
whose embedded six-byte reader ID matches the nibble-swapped USB serial in the
state ID. This applies to both device-scoped data and the legacy fallback. A
valid fallback is durably copied into the exact reader directory and then
removed; malformed or wrong-reader data is treated as missing so the vendor
can calibrate the attached reader instead.

The launcher also keys live hosts by that stable ID. If maintenance resets
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

## Pairing completion boundary

The pinned vendor driver combines sensor-side pairing with values in its
emulated cryptographic registry. `OnPrepareHardware` creates an asynchronous
pairing worker and stores its thread handle in the pinned
`CBiometricDevice` layout. `OnD0Entry` does not join that worker or propagate
its result. Only the worker's successful pairing state initializes the
strategy pointer later dereferenced unconditionally by capture. An earlier
bridge proceeded after the synchronous callbacks returned, exposed the reader,
and allowed `CaptureImage` to enter the DLL with a null strategy.

Normal initialization now joins that exact worker with a bounded wait after
`OnD0Entry`. It verifies the strategy pointer at the pinned offset before it
queries the WinBio adapters, checks it again before adapter publication, and
rechecks it at capture dispatch. It then opens every normal pipeline stage and
requires the sensor adapter to return `WINBIO_SENSOR_READY`. This joined worker,
nonnull strategy, and complete pipeline open is the only successful validation
boundary. The host cannot publish `READY` before it reaches that boundary.

`SetOwnershipFailureCount` is an observed `VT_UINT` property written by the
vendor's `DoPairing` failure path. It is a generic attempt counter. A nonzero
value, particularly one through four, can be a recoverable transition that
continues after USB re-enumeration in another host process. It is retained for
diagnostics and does not itself block adapters or authorize unpairing. The
historically named `OwnershipFailureDetected.bool` is armed true before every
fallible normal initialization so an earlier success cannot be reused after an
early failure; it does not prove an ownership mismatch. Only a full successful
pipeline open writes it false. `synatudor-setup` can make up to three ordinary
starts, resetting the USB session between them, and never invokes the separate
vendor-unpair path.

## Explicit vendor-unpair recovery

Vendor unpairing is a reader-scoped, one-shot maintenance path reached only by
an explicit `synatudor-reset-ownership` invocation. The privileged helper
writes `ResetOwnershipRequest.bool` and initializes
`ResetOwnershipResult.uint` in the exact device-state directory. When the host
starts, it records an in-progress barrier and consumes the request before
calling vendor code. Recovery initialization installs a thread-start filter
that suppresses only the exact normal pairing worker from the pinned DLL while
still returning a valid completed thread handle to the vendor. It then performs
`OnPrepareHardware`, `OnD0Entry`, and the synthetic worker join before issuing
private WUDF control code `0x442040`. The pinned DLL dispatches that code through
`OnResetOwnership` to `DoUnpairing`. Recovery never queries WinBio adapters or
sends `READY`.

This private control is not the standard `IOCTL_BIOMETRIC_RESET`. Static
analysis establishes the vendor callback and local TLS/pairing cleanup path,
but it does not prove physical erasure of the sensor's template database. The
operation is still destructive to pairing and local references and may make
existing Windows or Linux enrollments unusable. It must not be presented as a
secure-erase tool.

The host records callback success or failure and exits as its teardown
boundary. On reported success, the helper removes local values that no longer
match the unpaired sensor, removes fprintd references for this driver from
every local user, removes the older unscoped pairing records for every reader
managed by the driver, and preserves calibration only when it belongs to this
physical reader. A matching legacy calibration is migrated into the reader
directory, and all unscoped calibration values are removed. The helper creates
and flushes a root-only backup before changing anything.

After cleanup, the helper durably writes
`OwnershipResetPendingValidation.bool=1` before removing the reset transaction
barrier. It then makes up to three normal initialization attempts, each with an
ordinary USB reset and fresh host. Only the full pairing and pipeline boundary
changes this marker from one to zero; an ordinary successful open never creates
the marker. If all validation attempts fail, the helper leaves both fingerprint
services stopped behind its runtime masks. A later invocation recognizes the
pending marker and retries only normal validation; with no reset transaction
present, it cannot dispatch the vendor callback again. Zero remains as the
durable completed result. The helper reports it without dispatching another
callback unless the operator explicitly starts a new operation with `--new`.

The durable request/result barrier prevents ordinary startup until privileged
cleanup reaches the pending-validation boundary. A crash, USB disconnect, or
service retry therefore cannot repeat the vendor callback automatically. The
helper treats the request, result, and validation marker as one ordered state
machine. An interrupted or failed result becomes a durable no-replay barrier;
an enabled stale request is disabled in a standalone recovery invocation, and
only a later explicit `--new` invocation can authorize another callback. The
ordinary transport-reset helper validates the same marker and refuses to
bypass pending recovery. The transport-reset and vendor-unpair helpers also
share an exclusive root-owned
runtime lock so they cannot manipulate the reader concurrently. While either
helper requires both services to remain down, it runtime-masks them so another
local D-Bus client cannot reactivate fprintd or the launcher in the middle of
protected state work. A root-only runtime token distinguishes helper-owned
masks from administrator-created masks and lets a later invocation repair or
release a partial mask operation.

## Changes needed for `06cb:0081`

The inherited relinking project already loaded a related Synaptics driver, but
this device needed additional compatibility work:

- USB discovery and udev matching for `06cb:0081`
- a WUDF 1 object model and ABI layout matching this driver build
- Windows string, wait, time, property, process, pipe, WinUSB, and crypto calls
- fresh random generation, fixed-width P-256 key serialization, and the
  classic CryptoAPI operations used during clean pairing
- persistent device and crypto-registry state
- stable-reader host replacement across USB re-enumeration
- secure state IPC across the host sandbox boundary
- an exact pairing-worker join, capture-strategy guard, and complete safe-open
  boundary
- explicit one-shot vendor unpairing with resumable normal validation
- capture completion recovery for the driver's asynchronous request pattern
- the vendor's native biometric storage ABI and lifecycle
- exact GUID and finger mapping between fprintd and Windows Biometric Framework
- bounded WinUSB diagnostic playback so the host stays within its 64 KiB stack

The native storage path matters: an earlier in-memory storage shim made the
Linux operation appear successful but never committed a template to the
sensor's database.
