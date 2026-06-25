#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-linux-active-probe-internal-vault-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_LINUX_ACTIVE_PROBE_INTERNAL_VAULT_SMOKE_TIMEOUT_SECONDS:-90}"
DOCKER_IMAGE="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_IMAGE:-whoathere/linux-active-probe:local}"
BUILD_IMAGE="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_BUILD_IMAGE:-1}"
NETWORK_NAME="whoathere-active-probe-internal-$$"
FIXTURE_NAME="whoathere-vault-fixture-$$"
FIXTURE_ALIAS="whoathere-vault-fixture"
VAULT_HOST="$FIXTURE_ALIAS:4873"

cleanup() {
  docker rm -f "$FIXTURE_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere linux active probe internal vault smoke temp=%s\n' "$RUN_DIR"
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
        f"whoathere linux active probe internal vault smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

require_output() {
  local output_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$output_path"; then
    printf 'whoathere linux active probe internal vault smoke missing expected output: %s\n' "$pattern" >&2
    printf 'whoathere linux active probe internal vault smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

reject_output() {
  local output_path="$1"
  local pattern="$2"
  if grep -q "$pattern" "$output_path"; then
    printf 'whoathere linux active probe internal vault smoke found rejected output: %s\n' "$pattern" >&2
    printf 'whoathere linux active probe internal vault smoke output follows: %s\n' "$output_path" >&2
    cat "$output_path" >&2 || true
    return 1
  fi
}

wait_for_fixture() {
  local attempt
  for attempt in {1..20}; do
    if docker run --rm --network "$NETWORK_NAME" --entrypoint /bin/sh "$DOCKER_IMAGE" \
      -c "nc -z -w 2 $FIXTURE_ALIAS 4873" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

main() {
  local output_path stderr_path command_code network_internal
  output_path="$RUN_DIR/internal-vault.json"
  stderr_path="$RUN_DIR/internal-vault.stderr"

  if [[ "$BUILD_IMAGE" == "1" ]]; then
    WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_IMAGE="$DOCKER_IMAGE" \
      "$ROOT_DIR/scripts/whoathere-build-linux-active-probe-image.sh" >"$RUN_DIR/build.log" 2>&1
  fi

  docker network create --internal "$NETWORK_NAME" >/dev/null
  network_internal="$(docker network inspect --format '{{.Internal}}' "$NETWORK_NAME")"
  test "$network_internal" = "true"

  docker run -d --rm \
    --name "$FIXTURE_NAME" \
    --network "$NETWORK_NAME" \
    --network-alias "$FIXTURE_ALIAS" \
    --entrypoint /bin/sh \
    "$DOCKER_IMAGE" \
    -c 'while true; do printf "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" | nc -l -p 4873; done' \
    >"$RUN_DIR/fixture.cid"

  wait_for_fixture

  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    evidence linux-active-probe-docker --json --execute \
    --subject launch-sha256-smoke \
    --context-hash sha256:smoke-context \
    --vault-host "$VAULT_HOST" \
    --image "$DOCKER_IMAGE" \
    --docker-network "$NETWORK_NAME" >"$output_path" 2>"$stderr_path"
  command_code="$?"
  set -e

  printf 'whoathere linux active probe internal vault smoke command_exit=%s\n' "$command_code"
  test "$command_code" -eq 20

  require_output "$output_path" '"command": "whoathere evidence linux-active-probe-docker"'
  require_output "$output_path" '"execute_requested": true'
  require_output "$output_path" '"docker_invoked": true'
  require_output "$output_path" '"container_user": "65532:65532"'
  require_output "$output_path" '"network_internal_verified": true'
  require_output "$output_path" '"configured_vault_probe_attempted": true'
  require_output "$output_path" '"configured_vault_probe_allowed": true'
  require_output "$output_path" '"image_contract": "whoathere-linux-active-probe.v1"'
  require_output "$output_path" '"image_contract_valid": true'
  require_output "$output_path" '"authorization": false'
  require_output "$output_path" '"proof_minted": false'
  require_output "$output_path" '"execution_allowed": false'
  require_output "$output_path" '"status": "fail_closed"'
  require_output "$output_path" '"satisfied": false'
  require_output "$output_path" '"default_deny_except_configured_vault": true'
  require_output "$output_path" '"user_namespace_uid": "65532"'
  require_output "$output_path" '"user_namespace_gid": "65532"'
  require_output "$output_path" '"user_namespace_uid_map": "0:0:4294967295"'
  require_output "$output_path" '"user_namespace_gid_map": "0:0:4294967295"'
  require_output "$output_path" '"nested_user_namespace_attempt": "denied"'
  require_output "$output_path" '"nested_user_namespace_created": false'
  require_output "$output_path" '"allowed_probe_count": 1'
  require_output "$output_path" '"denied_probe_count": 14'
  require_output "$output_path" 'linux_active_probe_user_namespace_not_isolated'
  reject_output "$output_path" 'linux_active_probe_default_deny_not_attested'
  reject_output "$output_path" 'linux_active_probe_vault_probe_missing'
  reject_output "$output_path" 'linux_active_probe_vault_probe_denied'

  python3 - "$output_path" "$NETWORK_NAME" "$VAULT_HOST" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

network_name = sys.argv[2]
vault_host = sys.argv[3]
receipt = data["active_probe_receipt"]
docker = data["docker"]
assert data["exit_code"] == 20
assert data["authorization"] is False
assert data["proof_minted"] is False
assert data["execution_allowed"] is False
assert docker["container_network"] == network_name
assert docker["container_user"] == "65532:65532"
assert docker["network_internal_verified"] is True
assert docker["configured_vault_probe_attempted"] is True
assert docker["configured_vault_probe_allowed"] is True
assert receipt["user_namespace_uid"] == "65532"
assert receipt["user_namespace_gid"] == "65532"
assert receipt["user_namespace_uid_map"] == "0:0:4294967295"
assert receipt["user_namespace_gid_map"] == "0:0:4294967295"
assert receipt["nested_user_namespace_attempt"] == "denied"
assert receipt["nested_user_namespace_created"] is False
assert receipt["allowed_probe_destinations"] == [vault_host]
assert receipt["denied_probe_count"] == data["challenge"]["probe_destination_count"] - 1
assert vault_host not in receipt["denied_probe_destinations"]
assert receipt["missing_probe_destinations"] == []
assert receipt["allowed_non_vault_destinations"] == []
print("whoathere linux active probe internal vault smoke json ok")
PY

  printf 'whoathere linux active probe internal vault smoke ok\n'
}

main "$@"
