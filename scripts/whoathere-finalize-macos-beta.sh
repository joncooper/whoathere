#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${WHOATHERE_DIST_DIR:-"$REPO_ROOT/dist"}
STATE_DIR=${WHOATHERE_STATE_DIR:-"$HOME/.whoathere/macos-vm-validation"}
VERSION=""
REPO=${WHOATHERE_GITHUB_REPO:-}
RUN_HANDOFF=false
PUBLISH=false

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-finalize-macos-beta.sh --version <artifact-version> [--state-dir <dir>] [--run-handoff] [--publish --repo <owner/name>]

Finalizes the macOS local beta validation evidence for an existing packaged preview artifact.

Without --run-handoff, this only checks readiness and prints the remaining handoff command when the
VM guest or sync-back receipts are stale. With --run-handoff, it executes the generated runtime
reprovision handoff; that may prompt for sudo in an interactive terminal.

With --publish, readiness must be true and the script uploads the runtime qualification and
six-stage readiness report to the matching GitHub release.
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --version)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      VERSION=$2
      shift 2
      ;;
    --version=*)
      VERSION=${1#--version=}
      shift
      ;;
    --state-dir)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      STATE_DIR=$2
      shift 2
      ;;
    --state-dir=*)
      STATE_DIR=${1#--state-dir=}
      shift
      ;;
    --repo)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      REPO=$2
      shift 2
      ;;
    --repo=*)
      REPO=${1#--repo=}
      shift
      ;;
    --run-handoff)
      RUN_HANDOFF=true
      shift
      ;;
    --publish)
      PUBLISH=true
      shift
      ;;
    --help|-h)
      usage
      ;;
    *)
      usage
      ;;
  esac
done

if [ -z "$VERSION" ]; then
  usage
fi

PACKAGE_NAME="whoathere-macos-arm64-preview-$VERSION"
ARCHIVE="$DIST_DIR/$PACKAGE_NAME.tar.gz"
READINESS_REPORT="$DIST_DIR/$PACKAGE_NAME-six-stage-readiness.txt"
RUNTIME_RECEIPT="$DIST_DIR/$PACKAGE_NAME-runtime-qualification.json"
HANDOFF="$DIST_DIR/$PACKAGE_NAME-runtime-reprovision.sh"
TAG="macos-local-beta-$VERSION"

if [ ! -f "$ARCHIVE" ]; then
  echo "archive_missing=$ARCHIVE" >&2
  exit 64
fi

if [ "$RUN_HANDOFF" = "true" ]; then
  if [ ! -x "$HANDOFF" ]; then
    echo "runtime_reprovision_handoff_missing=$HANDOFF" >&2
    exit 64
  fi
  "$HANDOFF"
fi

set +e
"$SCRIPT_DIR/whoathere-macos-beta-readiness-check.sh" \
  --version "$VERSION" \
  --state-dir "$STATE_DIR" \
  --report "$READINESS_REPORT"
readiness_status=$?
set -e

if [ "$readiness_status" -ne 0 ]; then
  echo "macos_beta_ready=false" >&2
  if [ -x "$HANDOFF" ]; then
    echo "remaining_runtime_reprovision_handoff=$HANDOFF" >&2
    echo "next_command=$HANDOFF" >&2
  fi
  exit "$readiness_status"
fi

echo "macos_beta_ready=true"
echo "readiness_report=$READINESS_REPORT"

if [ "$PUBLISH" = "true" ]; then
  if [ -z "$REPO" ]; then
    echo "github_repo_required_for_publish=true" >&2
    exit 64
  fi
  if ! command -v gh >/dev/null 2>&1; then
    echo "gh_cli_required=true" >&2
    exit 69
  fi
  gh auth status >/dev/null
  gh release view "$TAG" --repo "$REPO" >/dev/null

  uploads="$READINESS_REPORT"
  if [ -f "$RUNTIME_RECEIPT" ]; then
    uploads="$uploads $RUNTIME_RECEIPT"
  fi

  # shellcheck disable=SC2086
  gh release upload "$TAG" --repo "$REPO" --clobber $uploads
  echo "github_release_evidence_uploaded=true"
  echo "repo=$REPO"
  echo "tag=$TAG"
fi
