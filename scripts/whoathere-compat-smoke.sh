#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST_PATH="$ROOT_DIR/whoathere/Cargo.toml"
RUN_DIR="$(mktemp -d "${TMPDIR:-/tmp}/whoathere-compat-smoke.XXXXXX")"
SERVER_PID=""
SERVER_WAIT_ATTEMPTS="${WHOATHERE_SMOKE_SERVER_WAIT_ATTEMPTS:-300}"
SERVER_WAIT_SLEEP_SECONDS="${WHOATHERE_SMOKE_SERVER_WAIT_SLEEP_SECONDS:-0.1}"
NPM_TIMEOUT_SECONDS="${WHOATHERE_SMOKE_NPM_TIMEOUT_SECONDS:-60}"
PIP_TIMEOUT_SECONDS="${WHOATHERE_SMOKE_PIP_TIMEOUT_SECONDS:-60}"
CHECK_TIMEOUT_SECONDS="${WHOATHERE_SMOKE_CHECK_TIMEOUT_SECONDS:-10}"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "${WHOATHERE_KEEP_SMOKE_TEMP:-0}" != "1" ]]; then
    rm -rf "$RUN_DIR"
  else
    printf 'whoathere compat smoke temp=%s\n' "$RUN_DIR"
  fi
}
trap cleanup EXIT

print_log() {
  local label="$1"
  local log_path="$2"
  printf 'whoathere compat smoke %s log follows: %s\n' "$label" "$log_path" >&2
  cat "$log_path" >&2 || true
}

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
        f"whoathere compat smoke command timed out after {timeout:g}s: {printable}",
        file=sys.stderr,
    )
    raise SystemExit(124)
PY
}

pick_port() {
  python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

start_server() {
  local port="$1"
  local log_path="$2"
  local max_requests="${3:-3}"
  cargo run --manifest-path "$MANIFEST_PATH" -p whoathere-cli -- \
    vault dev-serve \
    --bind "127.0.0.1:${port}" \
    --max-requests "$max_requests" \
    --idle-timeout-ms 120000 >"$log_path" 2>&1 &
  SERVER_PID="$!"

  for ((attempt = 1; attempt <= SERVER_WAIT_ATTEMPTS; attempt += 1)); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      wait "$SERVER_PID" 2>/dev/null || true
      SERVER_PID=""
      printf 'whoathere compat smoke server exited before readiness on port %s\n' "$port" >&2
      print_log "server-startup" "$log_path"
      return 1
    fi
    if curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1; then
      if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        wait "$SERVER_PID" 2>/dev/null || true
        SERVER_PID=""
        printf 'whoathere compat smoke server exited immediately after readiness on port %s\n' "$port" >&2
        print_log "server-startup" "$log_path"
        return 1
      fi
      return
    fi
    sleep "$SERVER_WAIT_SLEEP_SECONDS"
  done

  printf 'whoathere compat smoke server did not become ready on port %s\n' "$port" >&2
  print_log "server-startup" "$log_path"
  return 1
}

wait_for_server_exit() {
  local log_path="$1"
  local expected_requests="${2:-3}"
  local pid="$SERVER_PID"
  for ((attempt = 1; attempt <= SERVER_WAIT_ATTEMPTS; attempt += 1)); do
    if ! kill -0 "$pid" 2>/dev/null; then
      if ! wait "$pid"; then
        SERVER_PID=""
        printf 'whoathere compat smoke server exited with failure\n' >&2
        print_log "server-exit" "$log_path"
        return 1
      fi
      SERVER_PID=""
      grep -q "served_requests=${expected_requests}" "$log_path"
      grep -q 'request_body_logged=false' "$log_path"
      grep -q 'response_body_logged=false' "$log_path"
      return
    fi
    sleep "$SERVER_WAIT_SLEEP_SECONDS"
  done
  printf 'whoathere compat smoke server did not exit after expected requests\n' >&2
  print_log "server-timeout" "$log_path"
  return 1
}

require_log_entry() {
  local log_path="$1"
  local pattern="$2"
  if ! grep -q "$pattern" "$log_path"; then
    printf 'whoathere compat smoke missing expected log pattern: %s\n' "$pattern" >&2
    print_log "server-missing-pattern" "$log_path"
    return 1
  fi
}

wait_for_server_exit_and_routes() {
  local log_path="$1"
  local first_route="$2"
  local second_route="$3"
  local expected_requests="${4:-3}"
  wait_for_server_exit "$log_path" "$expected_requests"
  require_log_entry "$log_path" "$first_route"
  require_log_entry "$log_path" "$second_route"
}

run_npm_smoke() {
  local port="$1"
  local workdir cache
  workdir="$(mktemp -d "$RUN_DIR/npm-work.XXXXXX")"
  cache="$(mktemp -d "$RUN_DIR/npm-cache.XXXXXX")"
  (
    cd "$workdir"
    run_with_timeout "$NPM_TIMEOUT_SECONDS" env npm_config_update_notifier=false npm install fixture@1.0.0 \
      --registry "http://127.0.0.1:${port}/v1/registry-compat/npm" \
      --package-lock-only \
      --ignore-scripts \
      --no-audit \
      --no-fund \
      --cache "$cache" \
      --prefer-online || return 1
    test -f package-lock.json || return 1
    grep -q '"lockfileVersion"' package-lock.json || return 1
    grep -q '"integrity"' package-lock.json || return 1
    grep -q "\"http://127.0.0.1:${port}/v1/registry-compat/npm/tarballs/fixture/1.0.0/fixture-1.0.0.tgz\"" package-lock.json || return 1
    run_with_timeout "$NPM_TIMEOUT_SECONDS" env npm_config_update_notifier=false npm ci \
      --registry "http://127.0.0.1:${port}/v1/registry-compat/npm" \
      --ignore-scripts \
      --no-audit \
      --no-fund \
      --cache "$cache" \
      --prefer-online || return 1
    run_with_timeout "$CHECK_TIMEOUT_SECONDS" node -e 'const pkg=require("./node_modules/fixture/package.json"); if (pkg.name !== "fixture" || pkg.version !== "1.0.0") process.exit(1);' || return 1
  )
}

run_pip_smoke() {
  local port="$1"
  local wheel_hash="$2"
  local workdir target cache
  workdir="$(mktemp -d "$RUN_DIR/pip-work.XXXXXX")"
  target="$workdir/target"
  cache="$(mktemp -d "$RUN_DIR/pip-cache.XXXXXX")"
  cat >"$workdir/requirements.txt" <<REQ
fixture==1.0.0 --hash=sha256:${wheel_hash}
REQ
  run_with_timeout "$PIP_TIMEOUT_SECONDS" python3 -m pip install \
    --disable-pip-version-check \
    -r "$workdir/requirements.txt" \
    --require-hashes \
    --no-deps \
    --index-url "http://127.0.0.1:${port}/v1/registry-compat/pypi/simple" \
    --target "$target" \
    --cache-dir "$cache" || return 1
  run_with_timeout "$CHECK_TIMEOUT_SECONDS" python3 -c 'from pathlib import Path; import sys; target=Path(sys.argv[1]); meta=target/"fixture-1.0.0.dist-info"/"METADATA"; init=target/"fixture"/"__init__.py"; assert meta.exists() and init.exists(); text=meta.read_text(); assert "Name: fixture" in text and "Version: 1.0.0" in text' "$target" || return 1
  rm -rf "$target"
  mkdir -p "$target"
  cat >"$workdir/requirements-bad-hash.txt" <<'REQ'
fixture==1.0.0 --hash=sha256:0000000000000000000000000000000000000000000000000000000000000000
REQ
  if run_with_timeout "$PIP_TIMEOUT_SECONDS" python3 -m pip install \
    --disable-pip-version-check \
    -r "$workdir/requirements-bad-hash.txt" \
    --require-hashes \
    --no-deps \
    --index-url "http://127.0.0.1:${port}/v1/registry-compat/pypi/simple" \
    --target "$target" \
    --cache-dir "$cache"; then
    printf 'whoathere compat smoke pip bad hash unexpectedly succeeded\n' >&2
    return 1
  fi
  test ! -e "$target/fixture-1.0.0.dist-info" || return 1
}

compute_pypi_fixture_hash() {
  local port="$1"
  local wheel_path="$2"
  run_with_timeout "$CHECK_TIMEOUT_SECONDS" curl -fsS \
    "http://127.0.0.1:${port}/v1/registry-compat/pypi/files/pypi/fixture/1.0.0/fixture-1.0.0-py3-none-any.whl" \
    -o "$wheel_path" || return 1
  shasum -a 256 "$wheel_path" | awk '{print $1}'
}

main() {
  local npm_port npm_log pip_hash_port pip_hash_log pip_wheel pip_hash pip_port pip_log

  npm_port="$(pick_port)"
  npm_log="$RUN_DIR/npm-server.log"
  start_server "$npm_port" "$npm_log" 3
  run_npm_smoke "$npm_port" || {
    print_log "npm-server" "$npm_log"
    return 1
  }
  wait_for_server_exit_and_routes "$npm_log" 'route_kind=registry_npm_metadata' 'route_kind=registry_npm_tarball' 3

  pip_hash_port="$(pick_port)"
  pip_hash_log="$RUN_DIR/pip-hash-server.log"
  pip_wheel="$RUN_DIR/fixture-1.0.0-py3-none-any.whl"
  start_server "$pip_hash_port" "$pip_hash_log" 2
  pip_hash="$(compute_pypi_fixture_hash "$pip_hash_port" "$pip_wheel")" || {
    print_log "pip-hash-server" "$pip_hash_log"
    return 1
  }
  wait_for_server_exit_and_routes "$pip_hash_log" 'route_kind=registry_pypi_file' 'route_kind=registry_pypi_file' 2

  pip_port="$(pick_port)"
  pip_log="$RUN_DIR/pip-server.log"
  start_server "$pip_port" "$pip_log" 5
  run_pip_smoke "$pip_port" "$pip_hash" || {
    print_log "pip-server" "$pip_log"
    return 1
  }
  wait_for_server_exit_and_routes "$pip_log" 'route_kind=registry_pypi_metadata' 'route_kind=registry_pypi_file' 5

  printf 'whoathere compat smoke ok\n'
}

main "$@"
