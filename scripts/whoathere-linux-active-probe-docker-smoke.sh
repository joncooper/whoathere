#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-linux-active-probe-docker-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_SMOKE_TIMEOUT_SECONDS:-60}"
DOCKER_IMAGE="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_IMAGE:-whoathere/linux-active-probe:local}"
BUILD_IMAGE="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_BUILD_IMAGE:-1}"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere linux active probe docker smoke temp=%s\n' "$RUN_DIR"
  fi
}
trap cleanup EXIT

run_with_timeout() {
  local seconds="$1"
  shift
  python3 - "$seconds" "$@" <<'PY'
import shlex
import subprocess
import sys

timeout = float(sys.argv[1])
command = sys.argv[2:]
try:
    raise SystemExit(subprocess.run(command, timeout=timeout).returncode)
except subprocess.TimeoutExpired:
    printable = " ".join(shlex.quote(part) for part in command)
    print(
        f"whoathere linux active probe docker smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

require_output() {
  local output_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$output_path"; then
    printf 'whoathere linux active probe docker smoke missing expected output: %s\n' "$pattern" >&2
    printf 'whoathere linux active probe docker smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

main() {
  local output_path stderr_path command_code
  output_path="$RUN_DIR/docker.json"
  stderr_path="$RUN_DIR/docker.stderr"

  if [[ "$BUILD_IMAGE" == "1" ]]; then
    WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_IMAGE="$DOCKER_IMAGE" \
      "$ROOT_DIR/scripts/whoathere-build-linux-active-probe-image.sh" >"$RUN_DIR/build.log" 2>&1
  fi

  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    evidence linux-active-probe-docker --json --execute \
    --subject launch-sha256-smoke \
    --context-hash sha256:smoke-context \
    --vault-host 127.0.0.1:4873 \
    --image "$DOCKER_IMAGE" >"$output_path" 2>"$stderr_path"
  command_code="$?"
  set -e

  printf 'whoathere linux active probe docker smoke command_exit=%s\n' "$command_code"
  test "$command_code" -eq 20

  require_output "$output_path" '"command": "whoathere evidence linux-active-probe-docker"'
  require_output "$output_path" '"execute_requested": true'
  require_output "$output_path" '"docker_invoked": true'
  require_output "$output_path" '"container_network": "none"'
  require_output "$output_path" '"container_user": "65532:65532"'
  require_output "$output_path" '"docker_exit_code": 0'
  require_output "$output_path" '"image_contract": "whoathere-linux-active-probe.v1"'
  require_output "$output_path" '"image_contract_valid": true'
  require_output "$output_path" '"authorization": false'
  require_output "$output_path" '"proof_minted": false'
  require_output "$output_path" '"execution_allowed": false'
  require_output "$output_path" '"status": "fail_closed"'
  require_output "$output_path" '"satisfied": false'
  require_output "$output_path" '"network_namespace_isolated": true'
  require_output "$output_path" '"user_namespace_uid": "65532"'
  require_output "$output_path" '"user_namespace_gid": "65532"'
  require_output "$output_path" '"user_namespace_uid_map": "0:0:4294967295"'
  require_output "$output_path" '"user_namespace_gid_map": "0:0:4294967295"'
  require_output "$output_path" '"nested_user_namespace_attempt": "denied"'
  require_output "$output_path" '"nested_user_namespace_created": false'
  require_output "$output_path" '"no_new_privs": true'
  require_output "$output_path" '"seccomp_filter_enforced": true'
  require_output "$output_path" '"cgroup_scoped": true'
  require_output "$output_path" '"denied_probe_count": 15'
  require_output "$output_path" 'linux_active_probe_user_namespace_not_isolated'
  require_output "$output_path" 'linux_active_probe_default_deny_not_attested'
  require_output "$output_path" 'linux_active_probe_vault_probe_missing'

  python3 - "$output_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

receipt = data["active_probe_receipt"]
docker = data["docker"]
assert data["exit_code"] == 20
assert data["authorization"] is False
assert data["proof_minted"] is False
assert data["execution_allowed"] is False
assert docker["docker_invoked"] is True
assert docker["container_network"] == "none"
assert docker["container_user"] == "65532:65532"
assert docker["image_contract"] == "whoathere-linux-active-probe.v1"
assert docker["image_contract_valid"] is True
assert receipt["user_namespace_uid"] == "65532"
assert receipt["user_namespace_gid"] == "65532"
assert receipt["user_namespace_uid_map"] == "0:0:4294967295"
assert receipt["user_namespace_gid_map"] == "0:0:4294967295"
assert receipt["nested_user_namespace_attempt"] == "denied"
assert receipt["nested_user_namespace_created"] is False
assert receipt["denied_probe_count"] == data["challenge"]["probe_destination_count"]
assert receipt["missing_probe_destinations"] == []
print("whoathere linux active probe docker smoke json ok")
PY

  printf 'whoathere linux active probe docker smoke ok\n'
}

main "$@"
