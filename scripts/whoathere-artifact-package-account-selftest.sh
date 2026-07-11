#!/bin/sh
set -eu

REPO_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$REPO_ROOT/whoathere/helpers/macos-vm-helper/scripts/artifact-package-account-lib.sh"

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/whoathere-package-account-selftest.XXXXXX")
cleanup() {
  case "$ROOT" in
    "${TMPDIR:-/tmp}"/whoathere-package-account-selftest.*) rm -rf "$ROOT" ;;
  esac
}
trap cleanup EXIT HUP INT TERM

make_node() {
  NODE_ROOT=$1
  mkdir -p "$NODE_ROOT/var/db/dslocal/nodes/Default/users"
  mkdir -p "$NODE_ROOT/var/db/dslocal/nodes/Default/groups"
  chmod 0700 "$NODE_ROOT" "$NODE_ROOT/var/db/dslocal/nodes/Default"
}

write_account_records() {
  ACCOUNT_ROOT=$1
  ACCOUNT_NAME=$2
  ACCOUNT_UID=$3
  ACCOUNT_GID=$4
  ACCOUNT_NODE="$ACCOUNT_ROOT/var/db/dslocal/nodes/Default"
  cat > "$ACCOUNT_NODE/users/$ACCOUNT_NAME.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>IsHidden</key><array><string>1</string></array>
<key>authentication_authority</key><array><string>;DisabledUser;</string></array>
<key>generateduid</key><array><string>11111111-1111-1111-1111-111111111111</string></array>
<key>gid</key><array><string>$ACCOUNT_GID</string></array>
<key>home</key><array><string>/var/empty</string></array>
<key>name</key><array><string>$ACCOUNT_NAME</string></array>
<key>passwd</key><array><string>*</string></array>
<key>shell</key><array><string>/usr/bin/false</string></array>
<key>uid</key><array><string>$ACCOUNT_UID</string></array>
</dict></plist>
EOF
  cat > "$ACCOUNT_NODE/groups/$ACCOUNT_NAME.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>generateduid</key><array><string>22222222-2222-2222-2222-222222222222</string></array>
<key>gid</key><array><string>$ACCOUNT_GID</string></array>
<key>name</key><array><string>$ACCOUNT_NAME</string></array>
<key>users</key><array><string>$ACCOUNT_NAME</string></array>
</dict></plist>
EOF
  chmod 0600 "$ACCOUNT_NODE/users/$ACCOUNT_NAME.plist" "$ACCOUNT_NODE/groups/$ACCOUNT_NAME.plist"
}

CURRENT_UID=$(id -u)
SUCCESS_ROOT="$ROOT/success"
make_node "$SUCCESS_ROOT"
write_account_records "$SUCCESS_ROOT" _whoatherepkg 499 499
whoathere_provision_package_account "$SUCCESS_ROOT" _whoatherepkg 499 499 "$CURRENT_UID"
whoathere_provision_package_account "$SUCCESS_ROOT" _whoatherepkg 499 499 "$CURRENT_UID"

SUCCESS_NODE="$SUCCESS_ROOT/var/db/dslocal/nodes/Default"
cat > "$SUCCESS_NODE/groups/admin.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>gid</key><array><string>80</string></array>
<key>name</key><array><string>admin</string></array>
<key>users</key><array><string>_whoatherepkg</string></array>
</dict></plist>
EOF
chmod 0600 "$SUCCESS_NODE/groups/admin.plist"
set +e
OUTPUT=$(whoathere_provision_package_account "$SUCCESS_ROOT" _whoatherepkg 499 499 "$CURRENT_UID" 2>&1)
STATUS=$?
set -e
[ "$STATUS" -eq 70 ]
printf '%s\n' "$OUTPUT" | grep -q '^reason_code=artifact_supervisor_package_account_privileged$'

NESTED_ROOT="$ROOT/nested"
make_node "$NESTED_ROOT"
write_account_records "$NESTED_ROOT" _whoatherepkg 499 499
NESTED_NODE="$NESTED_ROOT/var/db/dslocal/nodes/Default"
cat > "$NESTED_NODE/groups/admin.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>gid</key><array><string>80</string></array>
<key>name</key><array><string>admin</string></array>
<key>nestedgroups</key><array><string>22222222-2222-2222-2222-222222222222</string></array>
</dict></plist>
EOF
chmod 0600 "$NESTED_NODE/groups/admin.plist"
set +e
OUTPUT=$(whoathere_provision_package_account "$NESTED_ROOT" _whoatherepkg 499 499 "$CURRENT_UID" 2>&1)
STATUS=$?
set -e
[ "$STATUS" -eq 70 ]
printf '%s\n' "$OUTPUT" | grep -q '^reason_code=artifact_supervisor_package_account_privileged$'

COLLISION_ROOT="$ROOT/collision"
make_node "$COLLISION_ROOT"
COLLISION_NODE="$COLLISION_ROOT/var/db/dslocal/nodes/Default"
write_account_records "$COLLISION_ROOT" collision 499 700
set +e
OUTPUT=$(whoathere_provision_package_account "$COLLISION_ROOT" _whoatherepkg 499 499 "$CURRENT_UID" 2>&1)
STATUS=$?
set -e
[ "$STATUS" -eq 70 ]
printf '%s\n' "$OUTPUT" | grep -q '^reason_code=artifact_supervisor_package_uid_collision$'

echo "artifact_package_account_selftest=passed"
