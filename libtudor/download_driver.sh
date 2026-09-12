#!/usr/bin/env bash
set -Eeuo pipefail

HASH_FILE="$1"
TMP_DIR="$2"
OUT_DIR="$3"
shift 3

mkdir -p "$TMP_DIR"

# This repository does not redistribute Synaptics' proprietary DLLs. Download
# Lenovo's official package into Meson's private build directory, or accept an
# explicit local package for offline/reproducible builds.
readonly DRIVER_URL='https://download.lenovo.com/consumer/mobiles/huy103af07m6.exe'
if [[ -n ${SYNA_TUDOR_INSTALLER:-} ]]; then
    INSTALLER=$SYNA_TUDOR_INSTALLER
elif [[ -r "$TMP_DIR/huy103af07m6.exe" ]]; then
    INSTALLER="$TMP_DIR/huy103af07m6.exe"
else
    INSTALLER="$TMP_DIR/huy103af07m6.exe"
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --show-error --silent \
            "$DRIVER_URL" --output "$INSTALLER"
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet "$DRIVER_URL" --output-document "$INSTALLER"
    else
        echo 'curl or wget is required to download the Lenovo driver package' >&2
        exit 1
    fi
fi

if [[ ! -r "$INSTALLER" ]]; then
    echo "Fingerprint driver installer not found: $INSTALLER" >&2
    exit 1
fi

expected_hash=$(tr -d '[:space:]' < "$HASH_FILE")
actual_hash=$(sha256sum "$INSTALLER" | cut -d' ' -f1)
if [[ $actual_hash != "$expected_hash" ]]; then
    echo "Fingerprint driver checksum mismatch: $INSTALLER" >&2
    echo "expected SHA-256: $expected_hash" >&2
    echo "actual SHA-256:   $actual_hash" >&2
    exit 1
fi

# Extract the driver without executing the Windows installer.
WINDRV="$TMP_DIR/windrv"
mkdir -p "$WINDRV"
innoextract -d "$WINDRV" "$INSTALLER"

# Copy only the two DLLs used by libtudor.
mkdir -p "$OUT_DIR"
for dll in "$@"
do
    dll_path="$(find "$WINDRV" -name "$dll" -print -quit)"
    if [[ -z "$dll_path" ]]; then
        echo "Driver DLL not found after extraction: $dll" >&2
        exit 1
    fi
    cp "$dll_path" "$OUT_DIR/$dll"
done
