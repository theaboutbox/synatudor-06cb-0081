#!/usr/bin/env bash
set -Eeuo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
script=$repo_dir/scripts/reset-ownership

fail() {
  printf 'reset-ownership test failed: %s\n' "$*" >&2
  exit 1
}

bash -n "$script"
# shellcheck disable=SC1090,SC1091
source "$script"

help_text=$(usage)
grep -Fq 'for every local user' <<<"$help_text" ||
  fail 'help does not disclose system-wide local metadata removal'
grep -Fq 'unscoped calibration' <<<"$help_text" ||
  fail 'help does not disclose legacy calibration migration and removal'

tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/usb/1-1"
printf '06cb\n' >"$tmp/usb/1-1/idVendor"
printf '0081\n' >"$tmp/usb/1-1/idProduct"
printf 'a1b2c3d4e5f6\n' >"$tmp/usb/1-1/serial"

sensor=$(find_sensor "$tmp/usb")
[[ $sensor == "$tmp/usb/1-1" ]] || fail 'did not select the exact sensor'
derive_sensor_identity "$sensor"
# Assigned by derive_sensor_identity from the sourced helper.
# shellcheck disable=SC2154
[[ $sensor_state_id == 06cb-0081-a1b2c3d4e5f6 ]] ||
  fail 'state ID differs from libfprint-tod'
# shellcheck disable=SC2154
[[ $sensor_calibration_id == 1a2b3c4d5e6f ]] ||
  fail 'calibration reader ID was derived incorrectly'

mkdir -p "$tmp/usb/1-2"
printf '06cb\n' >"$tmp/usb/1-2/idVendor"
printf '0081\n' >"$tmp/usb/1-2/idProduct"
printf '001122334455\n' >"$tmp/usb/1-2/serial"
if (find_sensor "$tmp/usb" >/dev/null 2>&1); then
  fail 'accepted more than one matching sensor'
fi
rm -rf -- "$tmp/usb/1-2"
printf 'not-a-serial\n' >"$tmp/usb/1-1/serial"
if (derive_sensor_identity "$tmp/usb/1-1" >/dev/null 2>&1); then
  fail 'accepted an ambiguous USB serial'
fi
printf 'a1b2c3d4e5f6\n' >"$tmp/usb/1-1/serial"

calibration=$tmp/CalibrationData.blob
truncate -s 40780 "$calibration"
printf '\x1a\x2b\x3c\x4d\x5e\x6f' |
  dd of="$calibration" bs=1 seek=32 conv=notrunc status=none
calibration_is_valid "$calibration" 1a2b3c4d5e6f ||
  fail 'rejected matching calibration'
if calibration_is_valid "$calibration" 001122334455; then
  fail 'accepted calibration from another reader'
fi
truncate -s 64 "$calibration"
if calibration_is_valid "$calibration" 1a2b3c4d5e6f; then
  fail 'accepted malformed calibration length'
fi

state=$tmp/state
mkdir "$state"
printf keep >"$state/CalibrationData.blob"
printf keep >"$state/SystemWakeEnabled.bool"
for name in CryptoRegistry OwnershipFailureDetected PairingContext PairingData \
            SecureChannelIdentity SetOwnershipFailureCount UnpairingContext \
            deviceInitializeFailures; do
  printf remove >"$state/$name.blob"
  printf remove >"$state/$name.uint"
  printf remove >"$state/$name.bool"
done
printf remove >"$state/ResetOwnershipRequest.bool"
printf remove >"$state/ResetOwnershipResult.uint"

clear_incompatible_reader_state "$state" 1
[[ -f $state/CalibrationData.blob ]] || fail 'removed valid calibration'
[[ -f $state/SystemWakeEnabled.bool ]] || fail 'removed unrelated reader state'
[[ -f $state/ResetOwnershipRequest.bool ]] || fail 'removed reset request result'
[[ -f $state/ResetOwnershipResult.uint ]] || fail 'removed reset status result'
if find "$state" -maxdepth 1 -type f \
    \( -name 'CryptoRegistry.*' -o -name 'PairingContext.*' -o \
       -name 'PairingData.*' -o -name 'SecureChannelIdentity.*' -o \
       -name 'OwnershipFailureDetected.*' -o \
       -name 'SetOwnershipFailureCount.*' -o -name 'UnpairingContext.*' -o \
       -name 'deviceInitializeFailures.*' \) -print -quit | grep -q .; then
  fail 'left incompatible pairing state behind'
fi

clear_incompatible_reader_state "$state" 0
[[ ! -e $state/CalibrationData.blob ]] || fail 'kept invalid calibration'

clear_reset_markers "$state"
[[ ! -e $state/ResetOwnershipRequest.bool ]] || fail 'left reset request marker'
[[ ! -e $state/ResetOwnershipResult.uint ]] || fail 'left reset result marker'

marker_order=$tmp/reset-marker-order
mkdir -p "$marker_order"
printf '0\n' >"$marker_order/ResetOwnershipRequest.bool"
printf '2\n' >"$marker_order/ResetOwnershipResult.uint"
set +e
(
  sync() { return 1; }
  clear_reset_markers "$marker_order"
) >/dev/null 2>&1
marker_order_status=$?
set -e
[[ $marker_order_status == 1 ]] ||
  fail 'marker cleanup ignored the durability failure between request and result'
[[ ! -e $marker_order/ResetOwnershipRequest.bool &&
   -e $marker_order/ResetOwnershipResult.uint ]] ||
  fail 'marker cleanup did not preserve the success barrier after request removal'
clear_reset_markers "$marker_order"
[[ ! -e $marker_order/ResetOwnershipResult.uint ]] ||
  fail 'marker cleanup did not release the final success barrier'

legacy_root=$tmp/legacy-pairing
legacy_backup=$tmp/legacy-pairing-backup
mkdir -p "$legacy_root"
printf first >"$legacy_root/ABC123.tpd"
printf second >"$legacy_root/sensor9.tpd"
printf keep >"$legacy_root/unrelated.txt"
chmod 0600 "$legacy_root"/*.tpd
legacy_pairing_name_is_valid "$legacy_root/ABC123.tpd" ||
  fail 'rejected a valid legacy pairing-state name'
if legacy_pairing_name_is_valid "$legacy_root/.tpd" ||
   legacy_pairing_name_is_valid "$legacy_root/bad-name.tpd" ||
   legacy_pairing_name_is_valid \
     "$legacy_root/$(printf 'a%.0s' {1..129}).tpd"; then
  fail 'accepted an invalid legacy pairing-state name'
fi
if (assert_legacy_pairing_file "$legacy_root/ABC123.tpd") \
    >/dev/null 2>&1; then
  fail 'accepted a legacy pairing file that was not owned by root'
fi

# Retain the production name/size checks but replace the root-ownership guard
# for this unprivileged fixture.
assert_legacy_pairing_file() {
  legacy_pairing_name_is_valid "$1" && [[ -f $1 && ! -L $1 ]] &&
    (( $(stat -Lc '%s' -- "$1") <= 16384 ))
}
backup_legacy_pairing_data "$legacy_root" "$legacy_backup"
[[ -f $legacy_backup/ABC123.tpd &&
   -f $legacy_backup/sensor9.tpd ]] ||
  fail 'did not back up every legacy pairing record'
[[ ! -e $legacy_backup/unrelated.txt ]] ||
  fail 'backed up an unrelated top-level file'
clear_legacy_pairing_data "$legacy_root"
[[ ! -e $legacy_root/ABC123.tpd && ! -e $legacy_root/sensor9.tpd ]] ||
  fail 'left legacy pairing records behind'
[[ -f $legacy_root/unrelated.txt ]] ||
  fail 'removed an unrelated top-level file'

legacy_calibration_root=$tmp/legacy-calibration
legacy_calibration_backup=$tmp/legacy-calibration-backup
mkdir -p "$legacy_calibration_root"
truncate -s 40780 "$legacy_calibration_root/CalibrationData.blob"
printf '\x1a\x2b\x3c\x4d\x5e\x6f' |
  dd of="$legacy_calibration_root/CalibrationData.blob" bs=1 seek=32 \
    conv=notrunc status=none
printf stale >"$legacy_calibration_root/CalibrationData.uint"
printf stale >"$legacy_calibration_root/CalibrationData.bool"
printf keep >"$legacy_calibration_root/unrelated.txt"
chmod 0600 "$legacy_calibration_root"/CalibrationData.*

if (assert_legacy_calibration_file \
    "$legacy_calibration_root/CalibrationData.blob") >/dev/null 2>&1; then
  fail 'accepted legacy calibration that was not owned by root'
fi

# Retain the production regular-file and private-mode checks while replacing
# only the root-ownership guard for this unprivileged fixture.
assert_legacy_calibration_file() {
  [[ -f $1 && ! -L $1 && $(stat -Lc '%a' -- "$1") == 600 ]] &&
    (( $(stat -Lc '%s' -- "$1") <= 65536 ))
}
backup_legacy_calibration_data \
  "$legacy_calibration_root" "$legacy_calibration_backup"
[[ -f $legacy_calibration_backup/CalibrationData.blob &&
   -f $legacy_calibration_backup/CalibrationData.uint &&
   -f $legacy_calibration_backup/CalibrationData.bool ]] ||
  fail 'did not back up every unscoped calibration value'

calibration_is_valid \
  "$legacy_calibration_root/CalibrationData.blob" 1a2b3c4d5e6f ||
  fail 'did not recognize matching unscoped calibration'
legacy_calibration_device=$tmp/legacy-calibration-device
mkdir -p "$legacy_calibration_device"
migrate_legacy_calibration_data \
  "$legacy_calibration_root" "$legacy_calibration_device" 1a2b3c4d5e6f
calibration_is_valid \
  "$legacy_calibration_device/CalibrationData.blob" 1a2b3c4d5e6f ||
  fail 'did not migrate matching calibration into reader-scoped state'
clear_legacy_calibration_data "$legacy_calibration_root"
[[ ! -e $legacy_calibration_root/CalibrationData.blob &&
   ! -e $legacy_calibration_root/CalibrationData.uint &&
   ! -e $legacy_calibration_root/CalibrationData.bool ]] ||
  fail 'did not consume all unscoped calibration after migration'

truncate -s 64 "$legacy_calibration_root/CalibrationData.blob"
chmod 0600 "$legacy_calibration_root/CalibrationData.blob"
calibration_is_valid \
  "$legacy_calibration_root/CalibrationData.blob" 1a2b3c4d5e6f &&
  fail 'accepted malformed unscoped calibration'
invalid_legacy_backup=$tmp/invalid-legacy-calibration-backup
backup_legacy_calibration_data \
  "$legacy_calibration_root" "$invalid_legacy_backup"
[[ $(stat -Lc '%s' -- \
     "$invalid_legacy_backup/CalibrationData.blob") == 64 ]] ||
  fail 'did not back up malformed unscoped calibration before removal'
clear_legacy_calibration_data "$legacy_calibration_root"
[[ ! -e $legacy_calibration_root/CalibrationData.blob ]] ||
  fail 'left malformed unscoped calibration behind'
[[ -f $legacy_calibration_root/unrelated.txt ]] ||
  fail 'removed unrelated top-level state with unscoped calibration'

truncate -s 40780 "$legacy_calibration_root/CalibrationData.blob"
printf '\x00\x11\x22\x33\x44\x55' |
  dd of="$legacy_calibration_root/CalibrationData.blob" bs=1 seek=32 \
    conv=notrunc status=none
chmod 0600 "$legacy_calibration_root/CalibrationData.blob"
if calibration_is_valid \
    "$legacy_calibration_root/CalibrationData.blob" 1a2b3c4d5e6f; then
  fail 'accepted unscoped calibration from another reader'
fi
clear_legacy_calibration_data "$legacy_calibration_root"
[[ ! -e $legacy_calibration_root/CalibrationData.blob ]] ||
  fail 'left wrong-reader unscoped calibration behind'

# Consumed through the sourced helper's global state.
# shellcheck disable=SC2034
request_file=$tmp/missing-reset-request.bool
reset_request_is_disabled ||
  fail 'did not treat a missing request as disabled for success resumption'

# A durable SUCCEEDED result is authoritative even if a previous recovery
# failed before replacing an enabled request with Request=0.
(
  resume_dir=$tmp/resume-success
  mkdir -p "$resume_dir"
  device_state_dir=$resume_dir
  request_file=$resume_dir/ResetOwnershipRequest.bool
  result_file=$resume_dir/ResetOwnershipResult.uint
  printf '1\n' >"$request_file"
  printf '2\n' >"$result_file"
  printf stale >"$resume_dir/ResetOwnershipRequest.uint"
  recovery_armed=0
  reset_completed=0
  atomic_write_status() { printf '%s\n' "$2" >"$1"; }
  resume_successful_reset_cleanup
  [[ $(<"$request_file") == 0 &&
     ! -e $resume_dir/ResetOwnershipRequest.uint &&
     $recovery_armed == 1 && $reset_completed == 1 ]] ||
    fail 'could not resume cleanup from success plus an enabled request'
)

# A failure before local cleanup finishes must leave a success barrier that
# can resume cleanup. Once cleanup has finished and the barrier is released,
# a transport/service failure must never recreate it over a new identity.
mkdir -p "$tmp/recovery-before" "$tmp/recovery-after"
set +e
(
  recovery_armed=1
  reset_completed=1
  cleanup_completed=0
  services_stopped=1
  request_file=$tmp/recovery-before/ResetOwnershipRequest.bool
  result_file=$tmp/recovery-before/ResetOwnershipResult.uint
  trigger_pid=
  stop_trigger() { :; }
  stop_services() { services_stopped=1; return 0; }
  timeout() { return 0; }
  atomic_write_status() { printf '%s\n' "$2" >"$1"; }
  false
  recover_after_failure
) >/dev/null 2>&1
before_status=$?
(
  recovery_armed=1
  reset_completed=1
  cleanup_completed=1
  services_stopped=1
  request_file=$tmp/recovery-after/ResetOwnershipRequest.bool
  result_file=$tmp/recovery-after/ResetOwnershipResult.uint
  trigger_pid=
  stop_trigger() { :; }
  stop_services() { services_stopped=1; return 0; }
  timeout() { return 0; }
  atomic_write_status() { printf '%s\n' "$2" >"$1"; }
  false
  recover_after_failure
) >/dev/null 2>&1
after_status=$?
set -e
[[ $before_status == 1 && $after_status == 1 ]] ||
  fail 'failure recovery did not preserve the original exit status'
[[ $(<"$tmp/recovery-before/ResetOwnershipRequest.bool") == 0 ]] ||
  fail 'pre-cleanup recovery left the one-shot request enabled'
[[ $(<"$tmp/recovery-before/ResetOwnershipResult.uint") == 2 ]] ||
  fail 'pre-cleanup recovery did not preserve the success barrier'
[[ ! -e $tmp/recovery-after/ResetOwnershipRequest.bool &&
   ! -e $tmp/recovery-after/ResetOwnershipResult.uint ]] ||
  fail 'post-cleanup recovery recreated an ownership-reset barrier'

# If the helper cannot prove both services are quiescent, it must not inspect
# or rewrite an outcome that a still-running host could change concurrently.
quiescence_case=$tmp/quiescence-failure
mkdir -p "$quiescence_case"
printf '1\n' >"$quiescence_case/ResetOwnershipRequest.bool"
printf '0\n' >"$quiescence_case/ResetOwnershipResult.uint"
set +e
(
  recovery_armed=1
  reset_completed=0
  cleanup_completed=0
  services_stopped=0
  request_file=$quiescence_case/ResetOwnershipRequest.bool
  result_file=$quiescence_case/ResetOwnershipResult.uint
  trigger_pid=
  stop_trigger() { :; }
  stop_services() { return 1; }
  atomic_write_status() { : >"$quiescence_case/state-mutated"; }
  start_services() { : >"$quiescence_case/restarted"; }
  false
  recover_after_failure
) >/dev/null 2>&1
quiescence_status=$?
set -e
[[ $quiescence_status == 1 ]] ||
  fail 'quiescence failure did not preserve the original exit status'
[[ $(<"$quiescence_case/ResetOwnershipRequest.bool") == 1 &&
   $(<"$quiescence_case/ResetOwnershipResult.uint") == 0 ]] ||
  fail 'quiescence failure changed protected reset state'
[[ ! -e $quiescence_case/state-mutated &&
   ! -e $quiescence_case/restarted ]] ||
  fail 'quiescence failure mutated state or restarted services'

# A helper killed after writing Request=1 may leave its runtime masks for the
# next invocation to adopt. An early failure in that invocation must not
# release those masks or start a host until the stale request is proven safe.
for stopped_state in 0 1; do
  early_case=$tmp/early-pending-request-$stopped_state
  mkdir -p "$early_case"
  printf '1\n' >"$early_case/ResetOwnershipRequest.bool"
  printf '0\n' >"$early_case/ResetOwnershipResult.uint"
  set +e
  (
    recovery_armed=0
    reset_completed=0
    cleanup_completed=0
    services_stopped=$stopped_state
    service_management_armed=1
    request_file=$early_case/ResetOwnershipRequest.bool
    result_file=$early_case/ResetOwnershipResult.uint
    trigger_pid=
    stop_trigger() { :; }
    reset_request_is_disabled() { return 1; }
    reset_result_blocks_startup() { return 1; }
    start_services() { : >"$early_case/restarted"; }
    false
    recover_after_failure
  ) >/dev/null 2>&1
  early_status=$?
  set -e
  [[ $early_status == 1 ]] ||
    fail "early pending-request stopped=$stopped_state lost its exit status"
  [[ ! -e $early_case/restarted ]] ||
    fail "early pending-request stopped=$stopped_state restarted services"
done

early_safe_case=$tmp/early-disabled-request
mkdir -p "$early_safe_case"
set +e
(
  recovery_armed=0
  reset_completed=0
  cleanup_completed=0
  services_stopped=0
  service_management_armed=1
  request_file=$early_safe_case/ResetOwnershipRequest.bool
  result_file=$early_safe_case/ResetOwnershipResult.uint
  trigger_pid=
  stop_trigger() { :; }
  reset_request_is_disabled() { return 0; }
  reset_result_blocks_startup() { return 1; }
  start_services() { : >"$early_safe_case/restarted"; }
  false
  recover_after_failure
) >/dev/null 2>&1
early_safe_status=$?
set -e
[[ $early_safe_status == 1 && -e $early_safe_case/restarted ]] ||
  fail 'early failure did not restore services after proving startup safe'

# If protected status writes fail, recovery may restart services only after a
# separate read-back proves that either the request is disabled or a result
# barrier will block it.
set +e
(
  recovery_armed=1
  reset_completed=0
  cleanup_completed=0
  services_stopped=1
  request_file=$tmp/unsafe-request.bool
  result_file=$tmp/unsafe-result.uint
  trigger_pid=
  stop_trigger() { :; }
  stop_services() { services_stopped=1; return 0; }
  timeout() { return 0; }
  atomic_write_status() { return 1; }
  reset_request_is_disabled() { return 1; }
  reset_result_blocks_startup() { return 1; }
  start_services() { : >"$tmp/unsafe-restarted"; }
  false
  recover_after_failure
) >/dev/null 2>&1
unsafe_status=$?
(
  recovery_armed=1
  reset_completed=0
  cleanup_completed=0
  services_stopped=1
  request_file=$tmp/safe-request.bool
  result_file=$tmp/safe-result.uint
  trigger_pid=
  stop_trigger() { :; }
  stop_services() { services_stopped=1; return 0; }
  timeout() { return 0; }
  atomic_write_status() { return 1; }
  reset_request_is_disabled() { return 0; }
  reset_result_blocks_startup() { return 1; }
  start_services() { : >"$tmp/safe-restarted"; }
  false
  recover_after_failure
) >/dev/null 2>&1
safe_status=$?
set -e
[[ $unsafe_status == 1 && $safe_status == 1 ]] ||
  fail 'fail-closed recovery did not preserve the original exit status'
[[ ! -e $tmp/unsafe-restarted ]] ||
  fail 'restarted services without a disabled request or result barrier'
[[ -e $tmp/safe-restarted ]] ||
  fail 'did not restart services after proving the request was disabled'

# Exercise the same restart gate with real fixture status files. Each case
# begins with an enabled request and a nonblocking NONE result. Faults are
# injected independently into the two recovery writes so the helper must
# prove safety from whichever write, if any, reached stable local state.
run_status_write_fault_case() {
  local name=$1 fail_request_write=$2 fail_result_write=$3 expect_restart=$4
  local case_dir=$tmp/status-write-$name status

  mkdir -p "$case_dir"
  printf '1\n' >"$case_dir/ResetOwnershipRequest.bool"
  printf '0\n' >"$case_dir/ResetOwnershipResult.uint"

  set +e
  (
    recovery_armed=1
    reset_completed=0
    cleanup_completed=0
    services_stopped=1
    request_file=$case_dir/ResetOwnershipRequest.bool
    result_file=$case_dir/ResetOwnershipResult.uint
    trigger_pid=
    stop_trigger() { :; }
    stop_services() { services_stopped=1; return 0; }
    timeout() { return 0; }
    assert_status_file() {
      [[ -f $1 && ! -L $1 && $(stat -Lc '%s' -- "$1") == 2 ]] ||
        die "malformed fixture status file: $1"
    }
    atomic_write_status() {
      local path=$1 value=$2
      if [[ $path == "$request_file" && $fail_request_write == 1 ]] ||
         [[ $path == "$result_file" && $fail_result_write == 1 ]]; then
        return 1
      fi
      printf '%s\n' "$value" >"$path"
    }
    start_services() { : >"$case_dir/restarted"; }
    false
    recover_after_failure
  ) >/dev/null 2>&1
  status=$?
  set -e

  [[ $status == 1 ]] ||
    fail "$name recovery did not preserve the original exit status"
  if (( expect_restart )); then
    [[ -e $case_dir/restarted ]] ||
      fail "$name recovery did not restart services after proving safety"
  else
    [[ ! -e $case_dir/restarted ]] ||
      fail "$name recovery restarted services without a safe status state"
  fi
}

run_status_write_fault_case both-succeed 0 0 1
run_status_write_fault_case request-only 0 1 1
run_status_write_fault_case barrier-only 1 0 1
run_status_write_fault_case both-fail 1 1 0

# Exercise the installed signal/EXIT trap chain itself. SIGTERM must retain
# its conventional status while the EXIT handler disables the request and
# establishes a blocking result before it allows a service restart.
signal_case=$tmp/signal-recovery
mkdir -p "$signal_case"
printf '1\n' >"$signal_case/ResetOwnershipRequest.bool"
printf '0\n' >"$signal_case/ResetOwnershipResult.uint"
set +e
(
  recovery_armed=1
  reset_completed=0
  cleanup_completed=0
  services_stopped=1
  request_file=$signal_case/ResetOwnershipRequest.bool
  result_file=$signal_case/ResetOwnershipResult.uint
  trigger_pid=
  stop_trigger() { :; }
  stop_services() { services_stopped=1; return 0; }
  timeout() { return 0; }
  assert_status_file() {
    [[ -f $1 && ! -L $1 && $(stat -Lc '%s' -- "$1") == 2 ]] ||
      die "malformed fixture status file: $1"
  }
  atomic_write_status() { printf '%s\n' "$2" >"$1"; }
  start_services() { : >"$signal_case/restarted"; }
  trap recover_after_failure EXIT
  trap 'exit 143' TERM
  kill -TERM "$BASHPID"
) >/dev/null 2>&1
signal_status=$?
set -e
[[ $signal_status == 143 ]] ||
  fail 'SIGTERM recovery did not preserve status 143'
[[ $(<"$signal_case/ResetOwnershipRequest.bool") == 0 ]] ||
  fail 'SIGTERM recovery left the one-shot request enabled'
[[ $(<"$signal_case/ResetOwnershipResult.uint") == 3 ]] ||
  fail 'SIGTERM recovery did not establish the failure barrier'
[[ -e $signal_case/restarted ]] ||
  fail 'SIGTERM recovery did not restart services after proving safety'

# The result file is authoritative if the host reports success before the
# helper's polling loop updates its in-memory flag. Recovery must preserve the
# success barrier and keep services down for the still-pending local cleanup.
observed_success_case=$tmp/observed-success
mkdir -p "$observed_success_case"
printf '0\n' >"$observed_success_case/ResetOwnershipRequest.bool"
printf '2\n' >"$observed_success_case/ResetOwnershipResult.uint"
set +e
(
  recovery_armed=1
  reset_completed=0
  cleanup_completed=0
  services_stopped=0
  request_file=$observed_success_case/ResetOwnershipRequest.bool
  result_file=$observed_success_case/ResetOwnershipResult.uint
  trigger_pid=
  stop_trigger() { :; }
  stop_services() { services_stopped=1; return 0; }
  timeout() { return 0; }
  assert_status_file() {
    [[ -f $1 && ! -L $1 && $(stat -Lc '%s' -- "$1") == 2 ]] ||
      die "malformed fixture status file: $1"
  }
  atomic_write_status() { printf '%s\n' "$2" >"$1"; }
  start_services() { : >"$observed_success_case/restarted"; }
  false
  recover_after_failure
) >/dev/null 2>&1
observed_success_status=$?
set -e
[[ $observed_success_status == 1 ]] ||
  fail 'observed-success recovery did not preserve the original exit status'
[[ $(<"$observed_success_case/ResetOwnershipRequest.bool") == 0 ]] ||
  fail 'observed-success recovery enabled the consumed request'
[[ $(<"$observed_success_case/ResetOwnershipResult.uint") == 2 ]] ||
  fail 'observed-success recovery downgraded the terminal result to failure'
[[ ! -e $observed_success_case/restarted ]] ||
  fail 'observed-success recovery restarted services before local cleanup'

# Once the vendor reset has completed, any later failure keeps services down.
# A failed attempt to reconstruct the success barrier must not fall through to
# the pre-reset restart gate, and completed cleanup must not recreate markers.
for cleanup_state in 0 1; do
  case_dir=$tmp/post-reset-$cleanup_state
  mkdir -p "$case_dir"
  printf '1\n' >"$case_dir/ResetOwnershipRequest.bool"
  printf '0\n' >"$case_dir/ResetOwnershipResult.uint"
  set +e
  (
    recovery_armed=1
    reset_completed=1
    cleanup_completed=$cleanup_state
    services_stopped=1
    request_file=$case_dir/ResetOwnershipRequest.bool
    result_file=$case_dir/ResetOwnershipResult.uint
    trigger_pid=
    stop_trigger() { :; }
    stop_services() { services_stopped=1; return 0; }
    timeout() { return 0; }
    atomic_write_status() {
      : >"$case_dir/write-attempted"
      return 1
    }
    start_services() { : >"$case_dir/restarted"; }
    false
    recover_after_failure
  ) >/dev/null 2>&1
  post_reset_status=$?
  set -e

  [[ $post_reset_status == 1 ]] ||
    fail "post-reset cleanup=$cleanup_state did not preserve the exit status"
  [[ ! -e $case_dir/restarted ]] ||
    fail "post-reset cleanup=$cleanup_state restarted fingerprint services"
  if (( cleanup_state )); then
    [[ ! -e $case_dir/write-attempted ]] ||
      fail 'completed cleanup recreated a reset barrier during recovery'
  else
    [[ -e $case_dir/write-attempted ]] ||
      fail 'incomplete cleanup did not try to reconstruct its success barrier'
  fi
done

# Model systemd enablement state to exercise partial masking, retry, release,
# administrator-mask preservation, and adoption after a killed helper.
(
  SERVICE_MASK_OWNER_FILE=$tmp/service-mask-owner
  temporary_runtime_masks=()
  service_management_armed=0
  activation_inhibited=0
  declare -A mock_unit_state=(
    [fprintd.service]=static
    [tudor-host-launcher.service]=static
  )
  fail_mask_once=tudor-host-launcher.service

  chown() { return 0; }
  service_mask_owner_file_is_valid() {
    [[ -f $SERVICE_MASK_OWNER_FILE && ! -L $SERVICE_MASK_OWNER_FILE &&
       $(stat -Lc '%a' -- "$SERVICE_MASK_OWNER_FILE") == 600 &&
       $(stat -Lc '%s' -- "$SERVICE_MASK_OWNER_FILE") == 15 &&
       $(<"$SERVICE_MASK_OWNER_FILE") == synatudor-0081 ]]
  }
  timeout() {
    shift 2
    "$@"
  }
  systemctl() {
    local action=$1 unit
    shift
    case $action in
      is-enabled)
        unit=$1
        printf '%s\n' "${mock_unit_state[$unit]}"
        [[ ${mock_unit_state[$unit]} != masked &&
           ${mock_unit_state[$unit]} != masked-runtime ]]
        ;;
      mask)
        [[ $1 == --runtime ]]
        unit=$2
        if [[ $fail_mask_once == "$unit" ]]; then
          fail_mask_once=
          return 1
        fi
        mock_unit_state[$unit]=masked-runtime
        ;;
      unmask)
        [[ $1 == --runtime ]]
        unit=$2
        [[ ${mock_unit_state[$unit]} != masked ]] &&
          mock_unit_state[$unit]=static
        ;;
      show)
        printf 'inactive\n'
        ;;
      stop|kill|start|reset-failed)
        return 0
        ;;
      *) return 1 ;;
    esac
  }

  if inhibit_service_activation; then
    fail 'partial service mask unexpectedly succeeded'
  fi
  [[ -f $SERVICE_MASK_OWNER_FILE &&
     ${mock_unit_state[fprintd.service]} == masked-runtime &&
     ${mock_unit_state[tudor-host-launcher.service]} == static ]] ||
    fail 'partial service mask did not retain recoverable ownership state'
  inhibit_service_activation || fail 'could not repair a partial service mask'
  [[ ${mock_unit_state[fprintd.service]} == masked-runtime &&
     ${mock_unit_state[tudor-host-launcher.service]} == masked-runtime ]] ||
    fail 'service masks were not verified after repair'
  allow_service_activation || fail 'could not release helper-owned masks'
  [[ ${mock_unit_state[fprintd.service]} == static &&
     ${mock_unit_state[tudor-host-launcher.service]} == static &&
     ! -e $SERVICE_MASK_OWNER_FILE ]] ||
    fail 'helper-owned service masks were not fully released'

  temporary_runtime_masks=()
  service_management_armed=0
  mock_unit_state[fprintd.service]=masked-runtime
  if inhibit_service_activation >/dev/null 2>&1; then
    fail 'accepted a pre-existing administrator runtime mask'
  fi
  [[ ${mock_unit_state[fprintd.service]} == masked-runtime &&
     ! -e $SERVICE_MASK_OWNER_FILE && $service_management_armed == 0 ]] ||
    fail 'altered a pre-existing administrator runtime mask'

  mock_unit_state[fprintd.service]=masked-runtime
  mock_unit_state[tudor-host-launcher.service]=static
  printf 'synatudor-0081\n' >"$SERVICE_MASK_OWNER_FILE"
  chmod 0600 "$SERVICE_MASK_OWNER_FILE"
  temporary_runtime_masks=()
  service_management_armed=0
  inhibit_service_activation || fail 'could not adopt a stale owned mask'
  allow_service_activation || fail 'could not release adopted service masks'
  [[ ${mock_unit_state[fprintd.service]} == static &&
     ${mock_unit_state[tudor-host-launcher.service]} == static &&
     ! -e $SERVICE_MASK_OWNER_FILE ]] ||
    fail 'adopted service masks were not restored'

  printf 'synatudor-0081\n' >"$SERVICE_MASK_OWNER_FILE"
  chmod 0600 "$SERVICE_MASK_OWNER_FILE"
  temporary_runtime_masks=()
  service_management_armed=1
  allow_service_activation ||
    fail 'could not finish owner-token cleanup after mask release'
  [[ ! -e $SERVICE_MASK_OWNER_FILE ]] ||
    fail 'left a service-mask owner token after release'
)

fprint_root=$tmp/fprint
fprint_backup=$tmp/fprint-backup
mkdir -p \
  "$fprint_root/alice/syna_tudor_relink/device-a" \
  "$fprint_root/alice/unrelated_driver" \
  "$fprint_root/bob/syna_tudor_relink/device-b" \
  "$fprint_root/.service/syna_tudor_relink/device-c"
printf alice >"$fprint_root/alice/syna_tudor_relink/device-a/right-index"
printf unrelated >"$fprint_root/alice/unrelated_driver/left-thumb"
printf bob >"$fprint_root/bob/syna_tudor_relink/device-b/left-index"
printf service >"$fprint_root/.service/syna_tudor_relink/device-c/right-thumb"

# The production callers validate root ownership and private modes. Replace
# those guards only inside this unprivileged fixture so backup/removal path
# selection can be tested without sudo.
assert_secure_dir() { :; }
assert_secure_tree() { :; }
backup_libfprint_metadata "$fprint_root" "$fprint_backup"
[[ -f $fprint_backup/alice/syna_tudor_relink/device-a/right-index ]] ||
  fail 'did not preserve the first user path in the backup'
[[ -f $fprint_backup/bob/syna_tudor_relink/device-b/left-index ]] ||
  fail 'did not preserve the second user path in the backup'
[[ -f $fprint_backup/.service/syna_tudor_relink/device-c/right-thumb ]] ||
  fail 'did not preserve a hidden user path in the backup'
[[ ! -e $fprint_backup/alice/unrelated_driver ]] ||
  fail 'backed up metadata for an unrelated driver'

clear_libfprint_metadata "$fprint_root"
[[ ! -e $fprint_root/alice/syna_tudor_relink ]] ||
  fail 'left the first user metadata behind'
[[ ! -e $fprint_root/bob/syna_tudor_relink ]] ||
  fail 'left the second user metadata behind'
[[ ! -e $fprint_root/.service/syna_tudor_relink ]] ||
  fail 'left hidden-user metadata behind'
[[ -f $fprint_root/alice/unrelated_driver/left-thumb ]] ||
  fail 'removed metadata for an unrelated driver'

printf 'reset-ownership helper tests passed\n'
