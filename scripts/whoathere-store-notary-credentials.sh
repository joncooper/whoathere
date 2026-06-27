#!/bin/sh
set -eu

PROFILE=${WHOATHERE_NOTARY_PROFILE:-whoathere-notary}
APPLE_ID=${WHOATHERE_NOTARY_APPLE_ID:-jon.cooper@gmail.com}
TEAM_ID=${WHOATHERE_NOTARY_TEAM_ID:-U7BVS8X483}
SYNC=false
VALIDATE=true

usage() {
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-store-notary-credentials.sh [--profile <name>] [--apple-id <email>] [--team-id <team-id>] [--sync] [--no-validate]

Stores Apple notarization credentials in macOS Keychain using xcrun notarytool.
The script does not read or store the app-specific password itself. When Apple ID and Team ID are
provided, notarytool prompts securely for the app-specific password.

Defaults:
  --profile whoathere-notary
  --apple-id jon.cooper@gmail.com
  --team-id U7BVS8X483
EOF
  exit 64
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --profile)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      PROFILE=$2
      shift 2
      ;;
    --profile=*)
      PROFILE=${1#--profile=}
      shift
      ;;
    --apple-id)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      APPLE_ID=$2
      shift 2
      ;;
    --apple-id=*)
      APPLE_ID=${1#--apple-id=}
      shift
      ;;
    --team-id)
      if [ "$#" -lt 2 ]; then
        usage
      fi
      TEAM_ID=$2
      shift 2
      ;;
    --team-id=*)
      TEAM_ID=${1#--team-id=}
      shift
      ;;
    --sync)
      SYNC=true
      shift
      ;;
    --no-validate)
      VALIDATE=false
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

if [ "$(uname -s)" != "Darwin" ]; then
  echo "macos_host_required=true" >&2
  exit 64
fi

if [ -z "$PROFILE" ] || [ -z "$APPLE_ID" ] || [ -z "$TEAM_ID" ]; then
  echo "notary_profile_apple_id_and_team_id_required=true" >&2
  exit 64
fi

if [ ! -t 0 ]; then
  echo "interactive_tty_required_for_secure_notarytool_password_prompt=true" >&2
  exit 64
fi

echo "notary_credentials_profile=$PROFILE"
echo "notary_credentials_apple_id=$APPLE_ID"
echo "notary_credentials_team_id=$TEAM_ID"
echo "notary_credentials_sync=$SYNC"
echo "notary_credentials_validate=$VALIDATE"

set -- notarytool store-credentials "$PROFILE" --apple-id "$APPLE_ID" --team-id "$TEAM_ID"
if [ "$SYNC" = "true" ]; then
  set -- "$@" --sync
fi
if [ "$VALIDATE" = "false" ]; then
  set -- "$@" --no-validate
fi

xcrun "$@"

echo "notary_credentials_stored=true"
echo "next_command=WHOATHERE_NOTARY_PROFILE=$PROFILE scripts/whoathere-notarize-macos-release.sh --submit dist/whoathere-macos-arm64-preview-\$(git rev-parse --short HEAD).tar.gz"
