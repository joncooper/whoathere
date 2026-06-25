#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-linux-active-probe-admission-smoke.XXXXXX")"
COMMAND_TIMEOUT_SECONDS="${WHOATHERE_LINUX_ACTIVE_PROBE_ADMISSION_SMOKE_TIMEOUT_SECONDS:-60}"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere linux active probe admission smoke temp=%s\n' "$RUN_DIR"
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
        f"whoathere linux active probe admission smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

run_admission() {
  local name="$1"
  local expected_exit="$2"
  shift 2
  local output_path="$RUN_DIR/$name.json"
  local stderr_path="$RUN_DIR/$name.stderr"
  local command_code

  set +e
  run_with_timeout "$COMMAND_TIMEOUT_SECONDS" \
    cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    evidence linux-active-probe-admission --json \
    --subject launch-sha256-smoke \
    --context-hash sha256:smoke-context \
    --vault-host 127.0.0.1:4873 \
    "$@" >"$output_path" 2>"$stderr_path"
  command_code="$?"
  set -e

  printf 'whoathere linux active probe admission smoke %s_exit=%s\n' "$name" "$command_code"
  test "$command_code" -eq "$expected_exit"
  python3 - "$output_path" "$name" "$expected_exit" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)

name = sys.argv[2]
expected_exit = int(sys.argv[3])
assert data["command"] == "whoathere evidence linux-active-probe-admission"
assert data["authorization"] is False
assert data["proof_minted"] is False
assert data["execution_allowed"] is False
assert data["exit_code"] == expected_exit
admission = data["admission"]
receipt = data["active_probe_receipt"]
if name == "accepted":
    assert data["status"] == "ok"
    assert admission["accepted"] is True
    assert admission["reason_codes"] == []
    assert admission["replay_decision"]["accepted"] is True
    assert receipt["satisfied"] is True
elif name == "replay":
    assert data["status"] == "fail_closed"
    assert admission["accepted"] is False
    assert "provider_challenge_replayed" in admission["reason_codes"]
    assert data["preconsume"]["accepted"] is True
    assert receipt["satisfied"] is True
elif name == "unknown":
    assert admission["accepted"] is False
    assert "provider_challenge_not_issued" in admission["reason_codes"]
    assert receipt["satisfied"] is True
elif name == "mutated":
    assert admission["accepted"] is False
    assert "provider_challenge_context_mutated" in admission["reason_codes"]
    assert receipt["satisfied"] is True
elif name == "incomplete":
    assert admission["accepted"] is False
    assert admission["replay_decision"]["accepted"] is True
    assert "linux_active_probe_not_complete" in admission["reason_codes"]
    assert receipt["satisfied"] is False
else:
    raise AssertionError(name)
PY
}

main() {
  run_admission accepted 0 --profile complete
  run_admission replay 20 --profile complete --replay
  run_admission unknown 20 --profile complete --unknown-challenge
  run_admission mutated 20 --profile complete --mutate-context
  run_admission incomplete 20 --profile incomplete
  printf 'whoathere linux active probe admission smoke ok\n'
}

main "$@"
