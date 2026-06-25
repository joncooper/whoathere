#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
BIN_PATH="$ROOT_DIR/whoathere/target/debug/whoathere"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-replay-store-stress.XXXXXX")"
WORKER_COUNT="${WHOATHERE_REPLAY_STORE_STRESS_WORKERS:-12}"
STORE_PATH="$RUN_DIR/replay-store.txt"
AUDIT_DIR="$RUN_DIR/audit"

cleanup() {
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere replay-store stress smoke temp=%s\n' "$RUN_DIR"
  fi
}
trap cleanup EXIT

mkdir -p "$AUDIT_DIR"
cargo build --manifest-path "$MANIFEST_PATH" -p whoathere-cli >/dev/null

for worker in $(seq 1 "$WORKER_COUNT"); do
  (
    set +e
    "$BIN_PATH" evidence linux-active-probe-docker \
      --json \
      --admit \
      --replay-store "$STORE_PATH" \
      --audit-path "$AUDIT_DIR/audit-$worker.jsonl" \
      --subject "stress-$worker" \
      --context-hash "sha256:stress-$worker" \
      --vault-host "127.0.0.1:4873" \
      >"$RUN_DIR/out-$worker.json" 2>"$RUN_DIR/err-$worker.log"
    code="$?"
    printf '%s\n' "$code" >"$RUN_DIR/code-$worker.txt"
    exit 0
  ) &
done

wait

python3 - "$RUN_DIR" "$STORE_PATH" "$AUDIT_DIR" "$WORKER_COUNT" <<'PY'
import json
import pathlib
import sys

run_dir = pathlib.Path(sys.argv[1])
store_path = pathlib.Path(sys.argv[2])
audit_dir = pathlib.Path(sys.argv[3])
worker_count = int(sys.argv[4])

for worker in range(1, worker_count + 1):
    code_path = run_dir / f"code-{worker}.txt"
    out_path = run_dir / f"out-{worker}.json"
    err_path = run_dir / f"err-{worker}.log"
    assert code_path.exists(), f"missing exit code for worker {worker}"
    code = int(code_path.read_text(encoding="utf-8").strip())
    assert code == 20, f"worker {worker} exit {code}: {err_path.read_text(encoding='utf-8')}"
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["status"] == "fail_closed"
    assert data["authorization"] is False
    assert data["proof_minted"] is False
    assert data["execution_allowed"] is False
    assert data["admission_applied"] is True
    assert data["replay_store"]["configured"] is True
    assert data["replay_store"]["available"] is True
    assert data["replay_store"]["operation"] == "consume"
    assert data["audit"]["status"] == "written"
    assert data["admission"]["replay_decision"]["status"] == "Accepted"

store = store_path.read_text(encoding="utf-8")
assert store.count("record ") == worker_count
assert store.count(" consumed=true") == worker_count
assert "challenge_nonce_digest=" in store
assert "proof-nonce-" not in store
assert not pathlib.Path(str(store_path) + ".lock").exists()

audit_files = sorted(audit_dir.glob("audit-*.jsonl"))
assert len(audit_files) == worker_count
for audit_path in audit_files:
    lines = audit_path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1
    event = json.loads(lines[0])
    assert event["event_id"] == "linux-active-probe-docker-replay-store-admission"
    assert event["decision"] == "deny"
    assert event["replay_store_summary"]["configured"] is True
    assert event["replay_store_summary"]["operation"] == "consume"
    assert event["replay_store_summary"]["available"] is True
    assert event["replay_store_summary"]["replay_status"] == "Accepted"
    assert event["replay_store_summary"]["accepted"] is False
    text = lines[0]
    assert "proof-nonce-" not in text
    assert str(store_path) not in text
    assert str(audit_path) not in text

print("whoathere replay-store stress smoke json ok")
PY

printf 'whoathere replay-store stress smoke workers=%s\n' "$WORKER_COUNT"
printf 'whoathere replay-store stress smoke ok\n'
