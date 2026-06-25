#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-linux-active-probe-docker-admission-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_ADMISSION_SMOKE_TIMEOUT_SECONDS:-90}"
DOCKER_IMAGE="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_IMAGE:-whoathere/linux-active-probe:local}"
BUILD_IMAGE="${WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_BUILD_IMAGE:-1}"
REPLAY_STORE="$RUN_DIR/replay-store.txt"
NETWORK_NAME="whoathere-active-probe-admission-$$"
FIXTURE_NAME="whoathere-vault-admission-fixture-$$"
FIXTURE_ALIAS="whoathere-vault-admission-fixture"
VAULT_HOST="$FIXTURE_ALIAS:4873"

cleanup() {
  docker rm -f "$FIXTURE_NAME" >/dev/null 2>&1 || true
  docker network rm "$NETWORK_NAME" >/dev/null 2>&1 || true
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere linux active probe docker admission smoke temp=%s\n' "$RUN_DIR"
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
        f"whoathere linux active probe docker admission smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
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

run_docker_admission() {
  local name="$1"
  local expected_exit="$2"
  shift 2
  local output_path="$RUN_DIR/$name.json"
  local stderr_path="$RUN_DIR/$name.stderr"
  local command_code

  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    evidence linux-active-probe-docker --json --admit \
    --subject launch-sha256-smoke \
    --context-hash sha256:smoke-context \
    --image "$DOCKER_IMAGE" \
    "$@" >"$output_path" 2>"$stderr_path"
  command_code="$?"
  set -e

  printf 'whoathere linux active probe docker admission smoke %s_exit=%s\n' "$name" "$command_code"
  test "$command_code" -eq "$expected_exit"
  python3 - "$output_path" "$name" "$VAULT_HOST" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

name = sys.argv[2]
vault_host = sys.argv[3]
docker = data["docker"]
admission = data["admission"]
receipt = data["active_probe_receipt"]
replay_store = data["replay_store"]

assert data["command"] == "whoathere evidence linux-active-probe-docker"
assert data["authorization"] is False
assert data["proof_minted"] is False
assert data["execution_allowed"] is False
assert data["admission_applied"] is True
assert data["status"] == "fail_closed"
assert admission is not None
assert admission["accepted"] is False
assert docker["container_user"] == "65532:65532"
assert receipt["satisfied"] is False
assert "linux_active_probe_user_namespace_not_isolated" in admission["reason_codes"]

if name == "stored_no_network":
    assert replay_store["configured"] is True
    assert replay_store["operation"] == "consume"
    assert replay_store["available"] is True
    assert replay_store["reason_codes"] == []
else:
    assert replay_store["configured"] is False
    assert replay_store["operation"] == "none"
    assert replay_store["available"] is True

if name in ("no_network", "stored_no_network"):
    assert admission["replay_decision"]["accepted"] is True
    assert docker["docker_invoked"] is True
    assert docker["container_network"] == "none"
    assert docker["configured_vault_probe_attempted"] is False
    assert receipt["default_deny_except_configured_vault"] is False
    assert "linux_active_probe_default_deny_not_attested" in admission["reason_codes"]
    assert "linux_active_probe_vault_probe_missing" in admission["reason_codes"]
elif name == "internal_vault":
    assert admission["replay_decision"]["accepted"] is True
    assert docker["docker_invoked"] is True
    assert docker["network_internal_verified"] is True
    assert docker["configured_vault_probe_attempted"] is True
    assert docker["configured_vault_probe_allowed"] is True
    assert receipt["default_deny_except_configured_vault"] is True
    assert receipt["allowed_probe_destinations"] == [vault_host]
    assert receipt["missing_probe_destinations"] == []
    assert receipt["allowed_non_vault_destinations"] == []
    assert "linux_active_probe_default_deny_not_attested" not in admission["reason_codes"]
    assert "linux_active_probe_vault_probe_missing" not in admission["reason_codes"]
elif name == "replay":
    assert data["preconsume"]["accepted"] is True
    assert admission["replay_decision"]["accepted"] is False
    assert "provider_challenge_replayed" in admission["reason_codes"]
else:
    raise AssertionError(name)
PY
}

main() {
  if [[ "$BUILD_IMAGE" == "1" ]]; then
    WHOATHERE_LINUX_ACTIVE_PROBE_DOCKER_IMAGE="$DOCKER_IMAGE" \
      "$ROOT_DIR/scripts/whoathere-build-linux-active-probe-image.sh" >"$RUN_DIR/build.log" 2>&1
  fi

  run_docker_admission no_network 20 --execute --vault-host 127.0.0.1:4873
  WHOATHERE_REPLAY_STORE="$REPLAY_STORE" \
    run_docker_admission stored_no_network 20 --execute --vault-host 127.0.0.1:4873
  python3 - "$REPLAY_STORE" <<'PY'
import os
import stat
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as handle:
    contents = handle.read()

assert "whoathere.provider_challenge_replay_store.v1" in contents
assert "challenge_nonce_digest=" in contents
assert "proof-nonce-" not in contents
assert contents.count("record ") == 1
assert " consumed=true" in contents
assert stat.S_IMODE(os.stat(path).st_mode) & 0o077 == 0
PY
  run_docker_admission replay 20 --replay --vault-host 127.0.0.1:4873

  docker network create --internal "$NETWORK_NAME" >/dev/null
  test "$(docker network inspect --format '{{.Internal}}' "$NETWORK_NAME")" = "true"
  docker run -d --rm \
    --name "$FIXTURE_NAME" \
    --network "$NETWORK_NAME" \
    --network-alias "$FIXTURE_ALIAS" \
    --entrypoint /bin/sh \
    "$DOCKER_IMAGE" \
    -c 'while true; do printf "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" | nc -l -p 4873; done' \
    >"$RUN_DIR/fixture.cid"
  wait_for_fixture

  run_docker_admission internal_vault 20 --execute --vault-host "$VAULT_HOST" --docker-network "$NETWORK_NAME"
  printf 'whoathere linux active probe docker admission smoke ok\n'
}

main "$@"
