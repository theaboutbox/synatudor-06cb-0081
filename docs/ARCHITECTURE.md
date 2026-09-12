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
  registry behavior used while the sensor establishes its secure channel.
- `cli` is a development interface and has a less restrictive threat model
  than the fprintd path.

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
cryptographic registry, and a small set of device counters. The host asks for
these values over a dedicated sequenced-packet socket. It never receives a
path or regular-file descriptor for the state directory. Values are bounded,
names are checked, and replacements are written privately.

On a new sensor, the vendor driver performs its own no-touch calibration and
writes the resulting blob through this channel. Calibration is sensor-specific
and must never be copied from another machine.

The `06cb:0081` driver exposes its own Windows biometric storage adapter. The
Linux bridge uses that adapter for enrollment, lookup, and deletion, so the
full fingerprint template lives in the sensor-managed database. The fprintd
record contains the Windows biometric GUID, finger identifier, and an empty
compatibility payload that lets later requests address the sensor record.

## Changes needed for `06cb:0081`

The inherited relinking project already loaded a related Synaptics driver, but
this device needed additional compatibility work:

- USB discovery and udev matching for `06cb:0081`
- a WUDF 1 object model and ABI layout matching this driver build
- Windows string, wait, time, property, process, pipe, WinUSB, and crypto calls
- persistent device and crypto-registry state
- secure state IPC across the host sandbox boundary
- capture completion recovery for the driver's asynchronous request pattern
- the vendor's native biometric storage ABI and lifecycle
- exact GUID and finger mapping between fprintd and Windows Biometric Framework
- bounded WinUSB diagnostic playback so the host stays within its 64 KiB stack

The native storage path matters: an earlier in-memory storage shim made the
Linux operation appear successful but never committed a template to the
sensor's database.
