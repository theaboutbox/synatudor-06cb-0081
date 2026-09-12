# Contributing

Reports from another `06cb:0081` machine are especially useful. Include the
laptop model, distribution, kernel, `fprintd` version, and the output of:

```console
$ lsusb -d 06cb:0081
$ pacman -Q libfprint-tod fprintd synatudor-0081
```

Describe whether first initialization, enrollment, correct-finger matching,
wrong-finger rejection, deletion, and matching after a reboot worked. Do not
attach `CalibrationData.blob`, `PairingData.blob`,
`SecureChannelIdentity.blob`, `CryptoRegistry.blob`, files from
`/var/lib/tudor` or `/var/lib/fprint`, fingerprint captures, or unedited debug
logs or core dumps. They can contain sensor-specific state, enrollment
metadata, cryptographic material, or biometric-derived data.

Build and run the automated tests before submitting code:

```console
$ export SYNA_TUDOR_INSTALLER=/path/to/huy103af07m6.exe
$ meson setup build -DDBGIMPORT=true -DDBGWDF=false -DTOD=true
$ meson compile -C build
$ meson test -C build --print-errorlogs
```

Keep changes focused and retain existing authorship and license notices. New
hardware IDs need their own hardware validation; a shared Synaptics vendor ID
does not imply protocol or ABI compatibility.
