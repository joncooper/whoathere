#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CACHE_DIR=${WHOATHERE_SCANNER_CACHE_DIR:-${WHOATHERE_SCANNER_CACHE:-"$HOME/.whoathere/scanners"}}
BIN_DIR="$CACHE_DIR/bin"
TMP_DIR="$CACHE_DIR/tmp"
RECEIPT="$CACHE_DIR/scanner-bootstrap.json"
RECORDS="$CACHE_DIR/scanner-bootstrap.records"

mkdir -p "$BIN_DIR" "$TMP_DIR"
: > "$RECORDS"

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

json_string() {
  printf '"%s"' "$(json_escape "$1")"
}

shell_quote() {
  printf "'%s'" "$(printf '%s' "$1" | sed "s/'/'\\\\''/g")"
}

materialize_scanner_path() {
  name=$1
  path_value=$2
  case "$path_value" in
    "$BIN_DIR/$name")
      printf '%s\n' "$path_value"
      return 0
      ;;
    /*)
      if [ -x "$path_value" ]; then
        ln -sf "$path_value" "$BIN_DIR/$name" 2>/dev/null || return 1
        printf '%s\n' "$BIN_DIR/$name"
        return 0
      fi
      ;;
  esac
  return 1
}

materialize_uvx_wrapper() {
  name=$1
  uvx_path=$2
  target="$BIN_DIR/$name"
  temp_target="$target.$$"
  {
    printf '%s\n' '#!/bin/sh'
    printf 'exec %s %s "$@"\n' "$(shell_quote "$uvx_path")" "$(shell_quote "$name")"
  } > "$temp_target"
  chmod 0755 "$temp_target"
  mv "$temp_target" "$target"
  printf '%s\n' "$target"
}

append_record() {
  name=$1
  role=$2
  status=$3
  path_value=$4
  version_value=$5
  method=$6
  failure=$7
  if [ -s "$RECORDS" ]; then
    printf ',\n' >> "$RECORDS"
  fi
  {
    printf '    {"name": '
    json_string "$name"
    printf ', "role": '
    json_string "$role"
    printf ', "status": '
    json_string "$status"
    printf ', "path": '
    if [ -n "$path_value" ]; then json_string "$path_value"; else printf 'null'; fi
    printf ', "version": '
    if [ -n "$version_value" ]; then json_string "$version_value"; else printf 'null'; fi
    printf ', "install_method": '
    json_string "$method"
    printf ', "failure": '
    if [ -n "$failure" ]; then json_string "$failure"; else printf 'null'; fi
    printf '}'
  } >> "$RECORDS"
}

command_path() {
  if [ -x "$BIN_DIR/$1" ]; then
    printf '%s\n' "$BIN_DIR/$1"
    return 0
  fi
  command -v "$1" 2>/dev/null || true
}

scanner_version() {
  cmd=$1
  base=$(basename "$cmd")
  if [ "$base" = "scorecard" ]; then
    "$cmd" version 2>&1 | tr -d '\r' | sed -n '/[0-9]/p' | sed -n '1p' || true
    return 0
  fi
  "$cmd" --version 2>&1 | tr -d '\r' | sed -n '/[0-9]/p' | sed -n '1p' || true
}

install_uv_tool() {
  name=$1
  package=$2
  if command -v uv >/dev/null 2>&1; then
    uv tool install "$package" >/dev/null 2>&1 || return 1
  elif command -v uvx >/dev/null 2>&1; then
    uvx "$package" --version >/dev/null 2>&1 || return 1
  else
    return 1
  fi
}

install_brew_formula() {
  formula=$1
  if command -v brew >/dev/null 2>&1; then
    brew install "$formula" >/dev/null 2>&1 || return 1
  else
    return 1
  fi
}

install_github_release() {
  name=$1
  repo=$2
  pattern=$3
  work="$TMP_DIR/$name"
  rm -rf "$work"
  mkdir -p "$work"
  if ! command -v gh >/dev/null 2>&1; then
    return 1
  fi
  gh release download --repo "$repo" --pattern "$pattern" --dir "$work" >/dev/null 2>&1 || return 1
  for archive in "$work"/*; do
    [ -e "$archive" ] || continue
    case "$archive" in
      *.tar.gz|*.tgz)
        tar -xzf "$archive" -C "$work" >/dev/null 2>&1 || true
        ;;
      *.zip)
        unzip -q "$archive" -d "$work" >/dev/null 2>&1 || true
        ;;
      *)
        chmod +x "$archive" >/dev/null 2>&1 || true
        ;;
    esac
  done
  found=$(find "$work" -type f -perm -111 -name "$name" -print -quit 2>/dev/null || true)
  if [ -z "$found" ] && [ "$name" = "osv-scanner" ]; then
    found=$(find "$work" -type f -perm -111 -name "osv-scanner*" -print -quit 2>/dev/null || true)
  fi
  if [ -z "$found" ]; then
    return 1
  fi
  cp "$found" "$BIN_DIR/$name"
  chmod +x "$BIN_DIR/$name"
}

bootstrap_scanner() {
  name=$1
  role=$2
  method=$3
  formula=$4
  repo=$5
  pattern=$6
  package=$7

  path_value=$(command_path "$name")
  if [ -n "$path_value" ]; then
    cache_path=$(materialize_scanner_path "$name" "$path_value" || printf '%s\n' "$path_value")
    append_record "$name" "$role" "available" "$cache_path" "$(scanner_version "$cache_path")" "existing" ""
    return 0
  fi

  case "$method" in
    uv)
      if install_uv_tool "$name" "$package"; then
        path_value=$(command_path "$name")
        if [ -n "$path_value" ]; then
          cache_path=$(materialize_scanner_path "$name" "$path_value" || printf '%s\n' "$path_value")
          append_record "$name" "$role" "installed" "$cache_path" "$(scanner_version "$cache_path")" "uv_tool" ""
          return 0
        fi
        uvx_path=$(command -v uvx 2>/dev/null || true)
        if [ -n "$uvx_path" ]; then
          cache_path=$(materialize_uvx_wrapper "$name" "$uvx_path")
          append_record "$name" "$role" "uvx_available" "$cache_path" "$(scanner_version "$cache_path")" "uvx" ""
          return 0
        fi
      fi
      append_record "$name" "$role" "missing" "" "" "uv_tool" "uv tool or uvx install failed"
      ;;
    brew_github)
      if install_brew_formula "$formula"; then
        path_value=$(command_path "$name")
        if [ -n "$path_value" ]; then
          cache_path=$(materialize_scanner_path "$name" "$path_value" || printf '%s\n' "$path_value")
          append_record "$name" "$role" "installed" "$cache_path" "$(scanner_version "$cache_path")" "homebrew" ""
          return 0
        fi
      fi
      if install_github_release "$name" "$repo" "$pattern"; then
        path_value=$(command_path "$name")
        cache_path=$(materialize_scanner_path "$name" "$path_value" || printf '%s\n' "$path_value")
        append_record "$name" "$role" "installed" "$cache_path" "$(scanner_version "$cache_path")" "github_release" ""
        return 0
      fi
      append_record "$name" "$role" "missing" "" "" "homebrew_or_github_release" "install failed or no supported installer available"
      ;;
    *)
      append_record "$name" "$role" "missing" "" "" "unknown" "unknown install method"
      ;;
  esac
}

bootstrap_scanner "guarddog" "core" "uv" "" "" "" "guarddog"
bootstrap_scanner "pip-audit" "core" "uv" "" "" "" "pip-audit"
bootstrap_scanner "osv-scanner" "core" "brew_github" "osv-scanner" "google/osv-scanner" "*darwin*arm64*" ""
bootstrap_scanner "syft" "core" "brew_github" "syft" "anchore/syft" "*darwin*arm64*.tar.gz" ""
bootstrap_scanner "grype" "core" "brew_github" "grype" "anchore/grype" "*darwin*arm64*.tar.gz" ""
bootstrap_scanner "trivy" "report_only" "brew_github" "trivy" "aquasecurity/trivy" "*macOS-ARM64*.tar.gz" ""
bootstrap_scanner "scorecard" "report_only" "brew_github" "scorecard" "ossf/scorecard" "*darwin*arm64*" ""

core_total=$(grep -c '"role": "core"' "$RECORDS" 2>/dev/null || true)
core_ready=$(grep '"role": "core"' "$RECORDS" | grep -E -c '"status": "(available|installed|uvx_available)"' 2>/dev/null || true)
created_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

{
  printf '{\n'
  printf '  "schema_version": "whoathere.scanner_bootstrap.v1",\n'
  printf '  "created_at": '
  json_string "$created_at"
  printf ',\n'
  printf '  "cache_dir": '
  json_string "$CACHE_DIR"
  printf ',\n'
  printf '  "bin_dir": '
  json_string "$BIN_DIR"
  printf ',\n'
  printf '  "core_scanner_count": %s,\n' "$core_total"
  printf '  "core_scanner_ready_count": %s,\n' "$core_ready"
  printf '  "scanner_public_package_auto_trust_ready": '
  if [ "$core_total" = "$core_ready" ]; then printf 'true'; else printf 'false'; fi
  printf ',\n'
  printf '  "scanners": [\n'
  cat "$RECORDS"
  printf '\n  ]\n'
  printf '}\n'
} > "$RECEIPT"

printf 'scanner_bootstrap_receipt=%s\n' "$RECEIPT"
printf 'core_scanner_count=%s\n' "$core_total"
printf 'core_scanner_ready_count=%s\n' "$core_ready"
if [ "$core_total" = "$core_ready" ]; then
  printf 'scanner_public_package_auto_trust_ready=true\n'
else
  printf 'scanner_public_package_auto_trust_ready=false\n'
fi
