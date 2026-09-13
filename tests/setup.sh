#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT

fail() {
  printf 'FAIL: %s\n' "$*" >&2
  exit 1
}

# Exercise only the production enrollment helper. The child shell has its own
# errexit setting, unaffected by the parent's exit-status assertions.
cat >"$tmp/driver.sh" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
source <(sed -n '/^enroll_finger() {$/,/^}$/p' "$1/scripts/setup")
declare -F enroll_finger >/dev/null
sudo() {
  if [[ $# == 1 && $1 == -v ]]; then
    if [[ ${SYNATUDOR_MOCK_AUTH_FAIL:-0} == 1 ]]; then
      printf 'mock-auth-failed\n'
      return 1
    fi
    printf 'mock-auth-completed\n'
    return 0
  fi
  printf '%s\n' "$@" >"$SYNATUDOR_MOCK_ARGS"
  printf 'mock-enrollment-command\n'
}
enroll_finger right-index-finger fixture-desktop-user
EOF

SYNATUDOR_MOCK_ARGS=$tmp/args bash "$tmp/driver.sh" "$repo_root" >"$tmp/output"
printf '%s\n' -n -- /usr/bin/fprintd-enroll -f right-index-finger \
  fixture-desktop-user >"$tmp/expected-args"
cmp -s "$tmp/args" "$tmp/expected-args" ||
  fail 'enrollment did not preserve the explicit desktop username and noninteractive sudo arguments'
auth_line=$(grep -n -F 'mock-auth-completed' "$tmp/output" | cut -d: -f1)
scan_line=$(grep -n -F 'Enroll right-index-finger.' "$tmp/output" | cut -d: -f1)
command_line=$(grep -n -F 'mock-enrollment-command' "$tmp/output" | cut -d: -f1)
(( auth_line < scan_line && scan_line < command_line )) ||
  fail 'scan instructions or enrollment ran before authorization completed'

rm -- "$tmp/args"
status=0
SYNATUDOR_MOCK_AUTH_FAIL=1 SYNATUDOR_MOCK_ARGS=$tmp/args \
  bash "$tmp/driver.sh" "$repo_root" >"$tmp/failure-output" || status=$?
(( status != 0 )) || fail 'authorization failure did not stop setup'
[[ ! -e $tmp/args ]] || fail 'enrollment ran after authorization failed'
if grep -q -F 'Enroll right-index-finger.' "$tmp/failure-output"; then
  fail 'scan instructions appeared after authorization failed'
fi

printf 'setup authorization tests passed\n'
