#!/bin/sh

whoathere_plist_first_value() {
  WHOATHERE_PLIST_PATH=$1
  WHOATHERE_PLIST_KEY=$2
  plutil -extract "$WHOATHERE_PLIST_KEY.0" raw "$WHOATHERE_PLIST_PATH" 2>/dev/null || true
}

whoathere_provision_package_account() {
  WHOATHERE_ACCOUNT_DATA_MOUNT=$1
  WHOATHERE_ACCOUNT_NAME=$2
  WHOATHERE_ACCOUNT_UID=$3
  WHOATHERE_ACCOUNT_GID=$4
  WHOATHERE_ACCOUNT_RECORD_OWNER=${5:-0}
  WHOATHERE_DSLOCAL_NODE="$WHOATHERE_ACCOUNT_DATA_MOUNT/var/db/dslocal/nodes/Default"
  WHOATHERE_USERS_DIR="$WHOATHERE_DSLOCAL_NODE/users"
  WHOATHERE_GROUPS_DIR="$WHOATHERE_DSLOCAL_NODE/groups"
  case "$WHOATHERE_ACCOUNT_UID:$WHOATHERE_ACCOUNT_GID" in
    :*|*:|0:*|*:0|0[0-9]*:*|*:0[0-9]*|*[!0-9:]*|*:*:*)
      echo "reason_code=artifact_supervisor_package_identity_invalid" >&2
      return 70
      ;;
  esac
  if [ "$WHOATHERE_ACCOUNT_NAME" != _whoatherepkg ]; then
    echo "reason_code=artifact_supervisor_package_identity_invalid" >&2
    return 70
  fi
  if [ ! -d "$WHOATHERE_USERS_DIR" ] || [ ! -d "$WHOATHERE_GROUPS_DIR" ] \
    || [ -L "$WHOATHERE_DSLOCAL_NODE" ] || [ -L "$WHOATHERE_USERS_DIR" ] \
    || [ -L "$WHOATHERE_GROUPS_DIR" ]; then
    echo "reason_code=artifact_supervisor_dslocal_node_missing_or_unsafe" >&2
    return 70
  fi

  for WHOATHERE_USER_PLIST in "$WHOATHERE_USERS_DIR"/*.plist; do
    [ -f "$WHOATHERE_USER_PLIST" ] || continue
    if [ -L "$WHOATHERE_USER_PLIST" ]; then
      echo "reason_code=artifact_supervisor_dslocal_record_unsafe" >&2
      return 70
    fi
    WHOATHERE_OBSERVED_UID=$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" uid)
    WHOATHERE_OBSERVED_NAME=$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" name)
    if [ "$WHOATHERE_OBSERVED_UID" = "$WHOATHERE_ACCOUNT_UID" ] \
      && [ "$WHOATHERE_OBSERVED_NAME" != "$WHOATHERE_ACCOUNT_NAME" ]; then
      echo "reason_code=artifact_supervisor_package_uid_collision" >&2
      return 70
    fi
  done
  for WHOATHERE_GROUP_PLIST in "$WHOATHERE_GROUPS_DIR"/*.plist; do
    [ -f "$WHOATHERE_GROUP_PLIST" ] || continue
    if [ -L "$WHOATHERE_GROUP_PLIST" ]; then
      echo "reason_code=artifact_supervisor_dslocal_record_unsafe" >&2
      return 70
    fi
    WHOATHERE_OBSERVED_GID=$(whoathere_plist_first_value "$WHOATHERE_GROUP_PLIST" gid)
    WHOATHERE_OBSERVED_NAME=$(whoathere_plist_first_value "$WHOATHERE_GROUP_PLIST" name)
    if [ "$WHOATHERE_OBSERVED_GID" = "$WHOATHERE_ACCOUNT_GID" ] \
      && [ "$WHOATHERE_OBSERVED_NAME" != "$WHOATHERE_ACCOUNT_NAME" ]; then
      echo "reason_code=artifact_supervisor_package_gid_collision" >&2
      return 70
    fi
  done

  whoathere_guest_dscl() {
    dscl -q -f "$WHOATHERE_DSLOCAL_NODE" localonly "$@"
  }
  WHOATHERE_USER_RECORD="/Local/Target/Users/$WHOATHERE_ACCOUNT_NAME"
  WHOATHERE_GROUP_RECORD="/Local/Target/Groups/$WHOATHERE_ACCOUNT_NAME"
  WHOATHERE_USER_PLIST="$WHOATHERE_USERS_DIR/$WHOATHERE_ACCOUNT_NAME.plist"
  WHOATHERE_GROUP_PLIST="$WHOATHERE_GROUPS_DIR/$WHOATHERE_ACCOUNT_NAME.plist"

  if [ ! -f "$WHOATHERE_GROUP_PLIST" ]; then
    whoathere_guest_dscl -create "$WHOATHERE_GROUP_RECORD" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_GROUP_RECORD" RecordName "$WHOATHERE_ACCOUNT_NAME" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_GROUP_RECORD" PrimaryGroupID "$WHOATHERE_ACCOUNT_GID" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_GROUP_RECORD" RealName "WhoaThere package sandbox" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_GROUP_RECORD" GeneratedUID "$(uuidgen)" || return 70
  fi
  if [ ! -f "$WHOATHERE_USER_PLIST" ]; then
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" RecordName "$WHOATHERE_ACCOUNT_NAME" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" UniqueID "$WHOATHERE_ACCOUNT_UID" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" PrimaryGroupID "$WHOATHERE_ACCOUNT_GID" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" RealName "WhoaThere package sandbox" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" NFSHomeDirectory /var/empty || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" UserShell /usr/bin/false || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" IsHidden 1 || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" GeneratedUID "$(uuidgen)" || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" AuthenticationAuthority ';DisabledUser;' || return 70
    whoathere_guest_dscl -create "$WHOATHERE_USER_RECORD" Password '*' || return 70
  fi
  WHOATHERE_GROUP_USERS=$(plutil -extract users json -o - "$WHOATHERE_GROUP_PLIST" 2>/dev/null || printf '[]')
  if ! printf '%s' "$WHOATHERE_GROUP_USERS" | grep -q "\"$WHOATHERE_ACCOUNT_NAME\""; then
    whoathere_guest_dscl -merge "$WHOATHERE_GROUP_RECORD" GroupMembership "$WHOATHERE_ACCOUNT_NAME" || return 70
    WHOATHERE_GROUP_USERS=$(plutil -extract users json -o - "$WHOATHERE_GROUP_PLIST" 2>/dev/null || printf '[]')
  fi

  WHOATHERE_HIDDEN=$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" IsHidden)
  if [ -z "$WHOATHERE_HIDDEN" ]; then
    WHOATHERE_HIDDEN=$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" is_hidden)
  fi
  WHOATHERE_AUTHORITY=$(plutil -extract authentication_authority json -o - "$WHOATHERE_USER_PLIST" 2>/dev/null || printf '[]')
  WHOATHERE_PASSWORD=$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" passwd)
  WHOATHERE_GROUP_GUID=$(whoathere_plist_first_value "$WHOATHERE_GROUP_PLIST" generateduid)
  if [ "$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" name)" != "$WHOATHERE_ACCOUNT_NAME" ] \
    || [ "$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" uid)" != "$WHOATHERE_ACCOUNT_UID" ] \
    || [ "$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" gid)" != "$WHOATHERE_ACCOUNT_GID" ] \
    || [ "$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" home)" != /var/empty ] \
    || [ "$(whoathere_plist_first_value "$WHOATHERE_USER_PLIST" shell)" != /usr/bin/false ] \
    || [ "$WHOATHERE_HIDDEN" != 1 ] \
    || [ "$WHOATHERE_PASSWORD" != '*' ] \
    || [ "$(whoathere_plist_first_value "$WHOATHERE_GROUP_PLIST" name)" != "$WHOATHERE_ACCOUNT_NAME" ] \
    || [ "$(whoathere_plist_first_value "$WHOATHERE_GROUP_PLIST" gid)" != "$WHOATHERE_ACCOUNT_GID" ] \
    || [ -z "$WHOATHERE_GROUP_GUID" ] \
    || ! printf '%s' "$WHOATHERE_GROUP_USERS" | grep -q "\"$WHOATHERE_ACCOUNT_NAME\"" \
    || ! printf '%s' "$WHOATHERE_AUTHORITY" | grep -q 'DisabledUser'; then
    echo "reason_code=artifact_supervisor_package_account_verification_failed" >&2
    return 70
  fi

  for WHOATHERE_OTHER_GROUP_PLIST in "$WHOATHERE_GROUPS_DIR"/*.plist; do
    [ -f "$WHOATHERE_OTHER_GROUP_PLIST" ] || continue
    [ "$WHOATHERE_OTHER_GROUP_PLIST" = "$WHOATHERE_GROUP_PLIST" ] && continue
    WHOATHERE_OTHER_GROUP_USERS=$(plutil -extract users json -o - "$WHOATHERE_OTHER_GROUP_PLIST" 2>/dev/null || printf '[]')
    WHOATHERE_OTHER_GROUP_NESTED=$(plutil -extract nestedgroups json -o - "$WHOATHERE_OTHER_GROUP_PLIST" 2>/dev/null || printf '[]')
    if printf '%s' "$WHOATHERE_OTHER_GROUP_USERS" | grep -q "\"$WHOATHERE_ACCOUNT_NAME\"" \
      || printf '%s' "$WHOATHERE_OTHER_GROUP_NESTED" | grep -q "\"$WHOATHERE_GROUP_GUID\""; then
      case "$WHOATHERE_OTHER_GROUP_PLIST" in
        "$WHOATHERE_GROUPS_DIR/admin.plist"|"$WHOATHERE_GROUPS_DIR/wheel.plist")
          echo "reason_code=artifact_supervisor_package_account_privileged" >&2
          ;;
        *)
          echo "reason_code=artifact_supervisor_package_account_supplementary_group" >&2
          ;;
      esac
      return 70
    fi
  done

  for WHOATHERE_ACCOUNT_PLIST in "$WHOATHERE_USER_PLIST" "$WHOATHERE_GROUP_PLIST"; do
    WHOATHERE_RECORD_UID=$(stat -f '%u' "$WHOATHERE_ACCOUNT_PLIST")
    WHOATHERE_RECORD_MODE=$(stat -f '%Lp' "$WHOATHERE_ACCOUNT_PLIST")
    case "$WHOATHERE_RECORD_MODE" in
      ?[2367]?|??[2367]) WHOATHERE_RECORD_MODE_UNSAFE=1 ;;
      *) WHOATHERE_RECORD_MODE_UNSAFE=0 ;;
    esac
    if [ "$WHOATHERE_RECORD_UID" -ne "$WHOATHERE_ACCOUNT_RECORD_OWNER" ] \
      || [ "$WHOATHERE_RECORD_MODE_UNSAFE" -ne 0 ]; then
      echo "reason_code=artifact_supervisor_package_account_record_unsafe" >&2
      return 70
    fi
  done
}
