#!/bin/sh
set -eu

SSH_HOST=""
SSH_CONFIG=""
REMOTE_ROOT="~/whoathere-actual-malware-lab"
STATE_DIR="~/.whoathere/scaleway-actual-malware-validation"
WHOATHERE_BIN="whoathere"
EXECUTION_PATH="legacy_workspace_non_claim_bearing"
DETONATION_CONFIG=""
DETONATION_CONFIG_SHA256=""
BUNDLE=""
BUNDLE_SHA256=""
STAGE_BUNDLE=""

usage() {
  code=${1:-64}
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-scaleway-host-preflight.sh \
    --ssh-host <host-alias-or-user@host> \
    [--ssh-config ~/.ssh/config] \
    [--remote-root ~/whoathere-actual-malware-lab] \
    [--state-dir ~/.whoathere/scaleway-actual-malware-validation] \
    [--whoathere-bin whoathere] \
    [--execution-path legacy_workspace_non_claim_bearing|exact_artifact_diagnostic] \
    [--detonation-config <absolute-remote-json> \
     --detonation-config-sha256 sha256:<digest>] \
    [--bundle .whoathere/corpus-lab/scaleway-staging/<case>/stage-*.tar.gz] \
    [--bundle-sha256 sha256:<digest>] \
    [--stage-bundle]

Runs remote Scaleway host preflight for actual-malware evaluation.
If --stage-bundle is supplied, copies and extracts the staging tarball into the remote lab root.
This script does not unpack MalwareBazaar ZIPs and does not execute malware.
Exact-artifact mode validates the measured detonation adapter configuration with a
guaranteed-missing artifact instead of requiring the legacy macOS VM health/doctor checks.
EOF
  exit "$code"
}

safe_remote_value() {
  value=$1
  name=$2
  case "$value" in
    *"'"*|*";"*|*"&"*|*"|"*|*"\\"*|*"\`"*|*'$('*|*"<"*|*">"*|*" "*)
      echo "invalid_${name}=$value" >&2
      exit 64
      ;;
  esac
}

validate_bundle_tar() {
  python3 -B - "$BUNDLE" "$BUNDLE_SHA256" <<'PY'
import hashlib
import pathlib
import posixpath
import re
import stat
import sys
import tarfile

bundle = pathlib.Path(sys.argv[1])
expected_hash = sys.argv[2]
if not re.fullmatch(r"sha256:[0-9a-f]{64}", expected_hash):
    raise SystemExit("bundle_sha256_invalid")
hasher = hashlib.sha256()
with bundle.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        hasher.update(chunk)
actual_hash = "sha256:" + hasher.hexdigest()
if actual_hash != expected_hash:
    raise SystemExit(f"local_bundle_sha256_mismatch expected={expected_hash} actual={actual_hash}")
if stat.S_IMODE(bundle.stat().st_mode) & 0o077:
    raise SystemExit("local_bundle_permissions_not_private")
with tarfile.open(bundle, "r:gz") as tar:
    members = tar.getmembers()
    if not members:
        raise SystemExit("bundle_tar_empty")
    top = None
    for member in members:
        name = member.name
        normalized = posixpath.normpath(name)
        parts = normalized.split("/")
        if name.startswith("/") or normalized.startswith("../") or "/../" in normalized or "" in parts:
            raise SystemExit(f"unsafe_tar_path={name}")
        if member.issym() or member.islnk():
            raise SystemExit(f"unsafe_tar_link={name}")
        if not (member.isfile() or member.isdir()):
            raise SystemExit(f"unsupported_tar_member={name}")
        if member.mode & 0o077:
            raise SystemExit(f"tar_member_permissions_not_private={name}")
        if top is None:
            top = parts[0]
        elif parts[0] != top:
            raise SystemExit(f"multiple_tar_roots={top},{parts[0]}")
    if not re.fullmatch(r"stage-[0-9]{8}T[0-9]{6}Z", top or ""):
        raise SystemExit(f"unexpected_tar_root={top}")
    print(top)
PY
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ssh-host)
      [ "$#" -ge 2 ] || usage
      SSH_HOST=$2
      shift 2
      ;;
    --ssh-config)
      [ "$#" -ge 2 ] || usage
      SSH_CONFIG=$2
      shift 2
      ;;
    --remote-root)
      [ "$#" -ge 2 ] || usage
      REMOTE_ROOT=$2
      shift 2
      ;;
    --state-dir)
      [ "$#" -ge 2 ] || usage
      STATE_DIR=$2
      shift 2
      ;;
    --whoathere-bin)
      [ "$#" -ge 2 ] || usage
      WHOATHERE_BIN=$2
      shift 2
      ;;
    --execution-path)
      [ "$#" -ge 2 ] || usage
      EXECUTION_PATH=$2
      shift 2
      ;;
    --detonation-config)
      [ "$#" -ge 2 ] || usage
      DETONATION_CONFIG=$2
      shift 2
      ;;
    --detonation-config-sha256)
      [ "$#" -ge 2 ] || usage
      DETONATION_CONFIG_SHA256=$2
      shift 2
      ;;
    --bundle)
      [ "$#" -ge 2 ] || usage
      BUNDLE=$2
      shift 2
      ;;
    --bundle-sha256)
      [ "$#" -ge 2 ] || usage
      BUNDLE_SHA256=$2
      shift 2
      ;;
    --stage-bundle)
      STAGE_BUNDLE=1
      shift
      ;;
    -h|--help)
      usage 0
      ;;
    *)
      usage
      ;;
  esac
done

[ -n "$SSH_HOST" ] || usage
case "$EXECUTION_PATH" in
  legacy_workspace_non_claim_bearing)
    if [ -n "$DETONATION_CONFIG$DETONATION_CONFIG_SHA256" ]; then
      echo "legacy_preflight_rejects_exact_artifact_options" >&2
      exit 64
    fi
    ;;
  exact_artifact_diagnostic)
    [ -n "$DETONATION_CONFIG" ] || usage
    [ -n "$DETONATION_CONFIG_SHA256" ] || usage
    case "$DETONATION_CONFIG" in
      /*) ;;
      *) echo "detonation_config_must_be_absolute" >&2; exit 64 ;;
    esac
    case "$DETONATION_CONFIG_SHA256" in
      sha256:????????????????????????????????????????????????????????????????) ;;
      *) echo "detonation_config_sha256_invalid" >&2; exit 64 ;;
    esac
    case "${DETONATION_CONFIG_SHA256#sha256:}" in
      *[!0-9a-f]*) echo "detonation_config_sha256_invalid" >&2; exit 64 ;;
    esac
    ;;
  *) echo "invalid_execution_path=$EXECUTION_PATH" >&2; exit 64 ;;
esac
safe_remote_value "$REMOTE_ROOT" "remote_root"
safe_remote_value "$STATE_DIR" "state_dir"
safe_remote_value "$WHOATHERE_BIN" "whoathere_bin"
safe_remote_value "$EXECUTION_PATH" "execution_path"
[ -z "$DETONATION_CONFIG" ] || safe_remote_value "$DETONATION_CONFIG" "detonation_config"
[ -z "$DETONATION_CONFIG_SHA256" ] || safe_remote_value "$DETONATION_CONFIG_SHA256" "detonation_config_sha256"

if [ -n "$STAGE_BUNDLE" ]; then
  [ -n "$BUNDLE" ] || usage
  [ -n "$BUNDLE_SHA256" ] || usage
  [ -f "$BUNDLE" ] || {
    echo "missing_bundle=$BUNDLE" >&2
    exit 64
  }
fi

ssh_run() {
  command="umask 077; $1"
  if [ -n "$SSH_CONFIG" ]; then
    ssh -F "$SSH_CONFIG" "$SSH_HOST" "$command"
  else
    ssh "$SSH_HOST" "$command"
  fi
}

scp_to_remote() {
  src=$1
  dst=$2
  if [ -n "$SSH_CONFIG" ]; then
    scp -F "$SSH_CONFIG" "$src" "$SSH_HOST:$dst"
  else
    scp "$src" "$SSH_HOST:$dst"
  fi
}

run_remote_capture() {
  name=$1
  command=$2
  output="$REMOTE_ROOT/evidence/preflight/$name.out"
  stderr="$REMOTE_ROOT/evidence/preflight/$name.stderr"
  status_file="$REMOTE_ROOT/evidence/preflight/$name.status"
  remote_command="( $command ) >$output 2>$stderr; rc=\$?; printf \"%s\" \"\$rc\" >$status_file; exit \"\$rc\""
  if ssh_run "$remote_command"; then
    return 0
  fi
  status=$?
  return "$status"
}

ssh_run "umask 077; mkdir -p $REMOTE_ROOT/incoming $REMOTE_ROOT/staged $REMOTE_ROOT/evidence/preflight $REMOTE_ROOT/quarantine; chmod 700 $REMOTE_ROOT $REMOTE_ROOT/incoming $REMOTE_ROOT/staged $REMOTE_ROOT/evidence $REMOTE_ROOT/evidence/preflight $REMOTE_ROOT/quarantine"

if [ -n "$STAGE_BUNDLE" ]; then
  bundle_top=$(validate_bundle_tar)
  safe_remote_value "$bundle_top" "bundle_top"
  remote_bundle="$REMOTE_ROOT/incoming/scaleway-staging-bundle.tar.gz"
  remote_stage_dir="$REMOTE_ROOT/staged/$bundle_top"
  scp_to_remote "$BUNDLE" "$remote_bundle"
  if [ -f "$BUNDLE.manifest.json" ]; then
    scp_to_remote "$BUNDLE.manifest.json" "$remote_bundle.manifest.json"
  fi
  ssh_run "chmod 600 $remote_bundle; test ! -e $remote_bundle.manifest.json || chmod 600 $remote_bundle.manifest.json"
  ssh_run "printf '%s  scaleway-staging-bundle.tar.gz\n' '$BUNDLE_SHA256' >$remote_bundle.sha256"
  remote_hash=$(ssh_run "shasum -a 256 $remote_bundle | awk '{print \"sha256:\" \$1}'")
  if [ "$remote_hash" != "$BUNDLE_SHA256" ]; then
    echo "remote_bundle_sha256_mismatch expected=$BUNDLE_SHA256 actual=$remote_hash" >&2
    exit 65
  fi
  ssh_run "test ! -e $remote_stage_dir"
  ssh_run "tar -tzf $remote_bundle >$REMOTE_ROOT/evidence/preflight/staging-bundle-list.txt"
  ssh_run "tar -xzf $remote_bundle -C $REMOTE_ROOT/staged"
  ssh_run "chmod -R go-rwx $remote_stage_dir"
  ssh_run "python3 -c 'import json,pathlib,sys; d=pathlib.Path(\"$remote_stage_dir\"); p=d/\"metadata/staging-manifest.json\"; a=d/\"metadata/custody-review-approval.json\"; m=json.loads(p.read_text()); approval=json.loads(a.read_text()); count=m.get(\"sample_count\"); samples=m.get(\"samples\"); approved=approval.get(\"samples\"); manifest_hashes={row.get(\"sample_sha256\") for row in samples} if isinstance(samples,list) else set(); approval_hashes={row.get(\"sample_sha256\") for row in approved} if isinstance(approved,list) else set(); ok=(m.get(\"no_unpack_during_staging\") is True and m.get(\"sync_back_allowed\") is False and m.get(\"live_c2_allowed\") is False and m.get(\"second_stage_live_fetch_allowed\") is False and isinstance(count,int) and not isinstance(count,bool) and count > 0 and isinstance(samples,list) and len(samples) == count and len(manifest_hashes) == count and isinstance(approved,list) and len(approved) == count and len(approval_hashes) == count and manifest_hashes == approval_hashes and approval.get(\"scope\",{}).get(\"sample_count\") == count); print(json.dumps({\"staging_manifest\": str(p), \"valid\": ok, \"sample_count\": count, \"approval_sample_count\": len(approved) if isinstance(approved,list) else None})); sys.exit(0 if ok else 1)' >$REMOTE_ROOT/evidence/preflight/staging-manifest-check.json"
fi

overall=0
run_remote_capture host "date -u && sw_vers && uname -a && id && df -h $REMOTE_ROOT" || overall=1
run_remote_capture whoathere_path "command -v $WHOATHERE_BIN && $WHOATHERE_BIN --version" || overall=1
if [ "$EXECUTION_PATH" = "exact_artifact_diagnostic" ]; then
  readiness_probe="$REMOTE_ROOT/evidence/preflight/exact-artifact-readiness-probe-missing.whl"
  ssh_run "test ! -e $readiness_probe"
  run_remote_capture detonation_config_readiness "python3 -c 'import hashlib,pathlib,stat,sys; p=pathlib.Path(sys.argv[1]); m=p.lstat(); actual=\"sha256:\"+hashlib.sha256(p.read_bytes()).hexdigest(); ok=stat.S_ISREG(m.st_mode) and not p.is_symlink() and m.st_size>0 and actual==sys.argv[2]; sys.exit(0 if ok else 1)' $DETONATION_CONFIG $DETONATION_CONFIG_SHA256" || true
  run_remote_capture exact_artifact_readiness "$WHOATHERE_BIN artifact inspect $readiness_probe --ecosystem pypi --state-dir $STATE_DIR --detonation --detonation-config $DETONATION_CONFIG" || true
  run_remote_capture exact_artifact_readiness_validation "python3 -c 'import json,pathlib,sys; root=pathlib.Path(sys.argv[1]); report=json.loads((root/\"exact_artifact_readiness.out\").read_text()); status=(root/\"exact_artifact_readiness.status\").read_text(); ok=(status==\"64\" and report.get(\"schema_version\")==\"whoathere.exact_artifact_inspection.v1\" and report.get(\"status\")==\"error\" and report.get(\"exit_code\")==64 and report.get(\"reason_codes\")==[\"exact_artifact_path_unreadable\"] and report.get(\"admission_authority\") is False and report.get(\"observed_clean\") is False and report.get(\"sync_back_enabled\") is False); print(json.dumps({\"valid\":ok,\"expected_terminal_reason\":\"exact_artifact_path_unreadable\",\"artifact_executed\":False,\"vm_execution_requested\":False},sort_keys=True)); sys.exit(0 if ok else 1)' $REMOTE_ROOT/evidence/preflight" || true
else
  run_remote_capture doctor "$WHOATHERE_BIN doctor --json --state-dir $STATE_DIR" || overall=1
  run_remote_capture vm_status "$WHOATHERE_BIN vm status --json --state-dir $STATE_DIR" || true
  run_remote_capture vm_health "$WHOATHERE_BIN vm health --state-dir $STATE_DIR" || overall=1
fi
run_remote_capture scanners_list "$WHOATHERE_BIN scanners list --json" || overall=1
run_remote_capture red_team_gate "$WHOATHERE_BIN vm red-team-gate --json" || overall=1
run_remote_capture host_firewall "(/sbin/pfctl -s info; /sbin/pfctl -sr) 2>&1 || true" || true
run_remote_capture network_snapshot "netstat -rn && scutil --dns" || true

overall=0
if [ "$EXECUTION_PATH" = "exact_artifact_diagnostic" ]; then
  required_statuses="host whoathere_path detonation_config_readiness exact_artifact_readiness_validation scanners_list red_team_gate"
else
  required_statuses="host whoathere_path doctor vm_health scanners_list red_team_gate"
fi
for required_status in $required_statuses; do
  remote_status=$(ssh_run "cat $REMOTE_ROOT/evidence/preflight/$required_status.status 2>/dev/null || printf missing")
  if [ "$remote_status" != "0" ]; then
    overall=1
  fi
done

if [ "$EXECUTION_PATH" = "exact_artifact_diagnostic" ]; then
  exact_artifact_readiness_json=$(printf '{"detonation_config_path":"%s","detonation_config_sha256":"%s","probe_validation_path":"%s/evidence/preflight/exact_artifact_readiness_validation.out","expected_terminal_reason":"exact_artifact_path_unreadable","artifact_executed":false,"vm_execution_requested":false}' "$DETONATION_CONFIG" "$DETONATION_CONFIG_SHA256" "$REMOTE_ROOT")
else
  exact_artifact_readiness_json=null
fi

ssh_run "cat >$REMOTE_ROOT/evidence/preflight/actual-malware-preflight-summary.json <<EOF
{
  \"schema\": \"whoathere.actual_malware.scaleway_preflight_summary.v1\",
  \"remote_root\": \"$REMOTE_ROOT\",
  \"state_dir\": \"$STATE_DIR\",
  \"whoathere_bin\": \"$WHOATHERE_BIN\",
  \"execution_path\": \"$EXECUTION_PATH\",
  \"exact_artifact_readiness\": $exact_artifact_readiness_json,
  \"staged_bundle\": \"$STAGE_BUNDLE\",
  \"ready_for_sample_workspace_preparation\": $([ "$overall" -eq 0 ] && echo true || echo false),
  \"notes\": [
    \"This preflight does not unpack MalwareBazaar ZIPs and does not execute malware.\",
    \"Cloud firewall, provider approval, sinkhole endpoints, and evidence storage must still be verified by the operator.\",
    \"Do not run malware samples with --sync-back.\"
  ]
}
EOF"

echo "remote_preflight_evidence=$REMOTE_ROOT/evidence/preflight"
exit "$overall"
