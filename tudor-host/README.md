# tudor-host
This folder contains the Tudor host process. It's launched by the
[tudor-host-launcher](../tudor-host-launcher/README.md), and its job is to
provide [libtudor](../libtudor/README.md)'s functionality over a secured and
sandboxed IPC connection.

## Build Options
Currently, the following build options are defined:

Flag | Description
----- | ---------------------------
`UNMOUNTFS=true` | Replace the host's filesystem view with the read-only installed driver directory. Persistent device state is exchanged with the launcher over a dedicated socket. Enabled by default; disable when debugging with a tool such as GDB.

## Documentation
**TODO**
