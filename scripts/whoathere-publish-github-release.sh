#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
DIST_DIR=${WHOATHERE_DIST_DIR:-"$REPO_ROOT/dist"}
VERSION=${WHOATHERE_PREVIEW_VERSION:-$(git -C "$REPO_ROOT" rev-parse --short HEAD)}
TAG=${WHOATHERE_GITHUB_TAG:-"macos-local-beta-$VERSION"}
REPO=${WHOATHERE_GITHUB_REPO:-}
TARGET=${WHOATHERE_RELEASE_TARGET:-$(git -C "$REPO_ROOT" rev-parse HEAD)}
TITLE=${WHOATHERE_RELEASE_TITLE:-"WhoaThere macOS local beta $VERSION"}

usage() {
  cat >&2 <<'EOF'
usage:
  whoathere-publish-github-release.sh --repo <owner/name> [--tag <tag>] [--version <artifact-version>] [--target <git-ref>] [--draft]

Publishes an existing signed/notarized macOS preview archive from dist/ to a GitHub Release.
It uploads both versioned assets and stable "latest" assets used by whoathere-install-from-github.sh.

Required local files:
  dist/whoathere-macos-arm64-preview-<version>.tar.gz
  dist/whoathere-macos-arm64-preview-<version>.tar.gz.sha256

Optional local files are uploaded when present:
  dist/whoathere-macos-arm64-preview-<version>-notarization.zip.notarytool.json
  dist/whoathere-macos-arm64-preview-<version>-runtime-qualification.json
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
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
    --tag)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      TAG=$2
      shift 2
      ;;
    --tag=*)
      TAG=${1#--tag=}
      shift
      ;;
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
    --target)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      TARGET=$2
      shift 2
      ;;
    --target=*)
      TARGET=${1#--target=}
      shift
      ;;
    --draft)
      DRAFT=true
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

if [ -z "$REPO" ]; then
  echo "github_repo_required=true" >&2
  usage
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh_cli_required=true" >&2
  exit 69
fi

gh auth status >/dev/null
gh repo view "$REPO" >/dev/null

ARCHIVE="$DIST_DIR/whoathere-macos-arm64-preview-$VERSION.tar.gz"
CHECKSUM="$ARCHIVE.sha256"
NOTARY_JSON="$DIST_DIR/whoathere-macos-arm64-preview-$VERSION-notarization.zip.notarytool.json"
RUNTIME_JSON="$DIST_DIR/whoathere-macos-arm64-preview-$VERSION-runtime-qualification.json"

if [ ! -f "$ARCHIVE" ]; then
  echo "archive_missing=$ARCHIVE" >&2
  exit 66
fi
if [ ! -f "$CHECKSUM" ]; then
  echo "checksum_missing=$CHECKSUM" >&2
  exit 66
fi

(
  cd "$(dirname "$ARCHIVE")"
  shasum -a 256 -c "$(basename "$CHECKSUM")"
)

WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-github-release.XXXXXX")
cleanup() {
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT HUP INT TERM

LATEST_ARCHIVE="$WORK_DIR/whoathere-macos-arm64-preview-latest.tar.gz"
LATEST_CHECKSUM="$WORK_DIR/whoathere-macos-arm64-preview-latest.tar.gz.sha256"
VERSIONED_ARCHIVE="$WORK_DIR/$(basename "$ARCHIVE")"
VERSIONED_CHECKSUM="$WORK_DIR/$(basename "$CHECKSUM")"
NOTES="$WORK_DIR/release-notes.md"

cp "$ARCHIVE" "$LATEST_ARCHIVE"
cp "$ARCHIVE" "$VERSIONED_ARCHIVE"
(
  cd "$WORK_DIR"
  shasum -a 256 "$(basename "$LATEST_ARCHIVE")" > "$LATEST_CHECKSUM"
  shasum -a 256 "$(basename "$VERSIONED_ARCHIVE")" > "$VERSIONED_CHECKSUM"
)

cat > "$NOTES" <<EOF
# WhoaThere macOS Local Beta $VERSION

Apple Silicon macOS-only local beta archive.

Install on a clean Apple Silicon Mac from the private repository:

\`\`\`sh
gh auth login -h github.com
gh repo clone $REPO
cd whoathere
scripts/whoathere-install-from-github.sh --private --repo $REPO --tag $TAG --prefix "\$HOME/.whoathere"
\`\`\`

Then run:

\`\`\`sh
export PATH="\$HOME/.whoathere/bin:\$PATH"
whoathere doctor --json
\`\`\`

This beta is CLI-only. It improves local Python and Node development safety by using VM-backed
detonation, scanner evidence, package-risk gates, and deny-by-default sync-back for risky package
classes. It does not prove arbitrary packages safe and does not provide runtime application
protection.

Uploaded assets include a versioned archive plus stable latest archive names for installer use.
EOF

if gh release view "$TAG" --repo "$REPO" >/dev/null 2>&1; then
  echo "release_exists=true"
else
  if [ "${DRAFT:-false}" = "true" ]; then
    gh release create "$TAG" --repo "$REPO" --target "$TARGET" --title "$TITLE" --notes-file "$NOTES" --draft
  else
    gh release create "$TAG" --repo "$REPO" --target "$TARGET" --title "$TITLE" --notes-file "$NOTES" --prerelease
  fi
fi

UPLOADS="$VERSIONED_ARCHIVE $VERSIONED_CHECKSUM $LATEST_ARCHIVE $LATEST_CHECKSUM"
if [ -f "$NOTARY_JSON" ]; then
  UPLOADS="$UPLOADS $NOTARY_JSON"
fi
if [ -f "$RUNTIME_JSON" ]; then
  UPLOADS="$UPLOADS $RUNTIME_JSON"
fi

# shellcheck disable=SC2086
gh release upload "$TAG" --repo "$REPO" --clobber $UPLOADS

echo "github_release_published=true"
echo "repo=$REPO"
echo "tag=$TAG"
echo "version=$VERSION"
echo "private_install_command=scripts/whoathere-install-from-github.sh --private --repo $REPO --tag $TAG --prefix \\\"\\$HOME/.whoathere\\\""
