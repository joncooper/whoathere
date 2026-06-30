#!/bin/sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLI="$ROOT_DIR/whoathere/target/debug/whoathere"
WORK_DIR=${WHOATHERE_REAL_PROJECT_WORK_DIR:-"${TMPDIR:-/tmp}/whoathere-real-project-compatibility.$$"}
STATE_DIR="$WORK_DIR/state"
SUMMARY="$WORK_DIR/summary.tsv"
RUN_SCANNERS=${WHOATHERE_REAL_PROJECT_RUN_SCANNERS:-0}

usage() {
  cat <<'USAGE'
Usage:
  scripts/whoathere-real-project-compatibility.sh <workspace[:auto|npm|pypi|uv]> [...]

Runs WhoaThere package-risk assessment against existing real projects without host package
execution. By default it does not run external scanners. Set
WHOATHERE_REAL_PROJECT_RUN_SCANNERS=1 to run scanner receipts before package-risk assessment.

Outputs:
  real_project_compatibility_summary=<path>
  real_project_compatibility_work_dir=<path>
USAGE
}

json_field() {
  field=$1
  file=$2
  sed -n "s/.*\"$field\": \"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

json_bool() {
  field=$1
  file=$2
  awk -v field="$field" '
    index($0, "\"" field "\"") {
      if (index($0, "true")) {
        print "true"
        exit
      }
      if (index($0, "false")) {
        print "false"
        exit
      }
    }
  ' "$file" | head -n 1
}

package_count() {
  file=$1
  grep -o '"package_name":' "$file" 2>/dev/null | wc -l | tr -d ' '
}

classify_spec() {
  spec=$1
  ecosystem=auto
  path=$spec
  case "$spec" in
    *:auto|*:npm|*:pypi|*:uv)
      ecosystem=${spec##*:}
      path=${spec%:*}
      ;;
  esac
  printf '%s\t%s\n' "$path" "$ecosystem"
}

scanner_ecosystem_for() {
  ecosystem=$1
  case "$ecosystem" in
    uv)
      printf 'pypi\n'
      ;;
    *)
      printf '%s\n' "$ecosystem"
      ;;
  esac
}

run_capture() {
  output=$1
  shift
  set +e
  "$@" >"$output" 2>&1
  status=$?
  set -e
  return "$status"
}

if [ "$#" -eq 0 ]; then
  usage >&2
  exit 64
fi

cargo build --manifest-path "$ROOT_DIR/whoathere/Cargo.toml" -p whoathere-cli --bin whoathere >/dev/null
mkdir -p "$WORK_DIR" "$STATE_DIR"
printf 'workspace\tecosystem\tscanner_ecosystem\tpackage_risk_exit\tverdict\tpackage_count\tscanner_exit\tscanner_clean\telapsed_seconds\toutput\tscanner_output\n' > "$SUMMARY"

index=0
for spec in "$@"; do
  index=$((index + 1))
  parsed=$(classify_spec "$spec")
  workspace=$(printf '%s' "$parsed" | awk -F '\t' '{print $1}')
  ecosystem=$(printf '%s' "$parsed" | awk -F '\t' '{print $2}')
  scanner_ecosystem=$(scanner_ecosystem_for "$ecosystem")
  if [ ! -d "$workspace" ]; then
    printf 'real_project_case=%s status=missing workspace=%s\n' "$index" "$workspace" >&2
    continue
  fi

  case_dir="$WORK_DIR/case-$index"
  mkdir -p "$case_dir"
  scanner_output="$case_dir/scanner.json"
  package_output="$case_dir/package-risk.json"
  scanner_exit=skipped
  scanner_clean=skipped
  scanner_args=

  started=$(date +%s)
  if [ "$RUN_SCANNERS" = "1" ]; then
    if run_capture "$scanner_output" "$CLI" scanners run --workspace "$workspace" --ecosystem "$scanner_ecosystem" --state-dir "$STATE_DIR" --execute --json; then
      scanner_exit=0
    else
      scanner_exit=$?
    fi
    scanner_clean=$(json_bool scanner_clean "$scanner_output")
    scanner_args="--scanner-receipt $scanner_output"
  fi

  set +e
  # shellcheck disable=SC2086
  "$CLI" package-risk assess --workspace "$workspace" --ecosystem "$ecosystem" --state-dir "$STATE_DIR" $scanner_args --json > "$package_output" 2>&1
  package_status=$?
  set -e
  ended=$(date +%s)
  elapsed=$((ended - started))
  verdict=$(json_field overall_verdict "$package_output")
  count=$(package_count "$package_output")
  [ -n "$verdict" ] || verdict=unknown
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$workspace" "$ecosystem" "$scanner_ecosystem" "$package_status" "$verdict" "$count" "$scanner_exit" "$scanner_clean" "$elapsed" "$package_output" "$scanner_output" >> "$SUMMARY"
  printf 'real_project_case=%s ecosystem=%s scanner_ecosystem=%s package_risk_exit=%s verdict=%s package_count=%s scanner_exit=%s scanner_clean=%s elapsed_seconds=%s output=%s scanner_output=%s\n' \
    "$workspace" "$ecosystem" "$scanner_ecosystem" "$package_status" "$verdict" "$count" "$scanner_exit" "$scanner_clean" "$elapsed" "$package_output" "$scanner_output"
done

printf 'real_project_compatibility_summary=%s\n' "$SUMMARY"
printf 'real_project_compatibility_work_dir=%s\n' "$WORK_DIR"
