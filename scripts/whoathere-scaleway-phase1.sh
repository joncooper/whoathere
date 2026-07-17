#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)

SSH_HOST=""
SSH_CONFIG=""
REMOTE_ROOT="/Users/m1/whoathere-actual-malware-lab"
STAGE_DIR=""
STATE_DIR="/Users/m1/.whoathere/macos-vm-validation-ff1bb24"
WHOATHERE_BIN="/Users/m1/.whoathere/bin/whoathere"
EXECUTION_PATH="legacy_workspace_non_claim_bearing"
DETONATION_CONFIG=""
DETONATION_CONFIG_SHA256=""
EXECUTION_TOOLS_BIN=""
SECURITY_LAB_OWNER=""
EVALUATION_OWNER=""
PROVIDER_APPROVAL_REF=""
LEGAL_PROVIDER_APPROVAL_REF=""
SINKHOLE_REFERENCE=""
CLOUD_FIREWALL_ASSERTED=""
SINKHOLE_ASSERTED=""
PHASE="all"
RUN_TIMEOUT_SECONDS="600"
REPREPARE_BENIGN=""

usage() {
  code=${1:-64}
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-scaleway-phase1.sh \
    --ssh-host <host-alias-or-user@host> \
    [--ssh-config <path>] \
    [--remote-root /Users/m1/whoathere-actual-malware-lab] \
    [--stage-dir /Users/m1/whoathere-actual-malware-lab/staged/stage-...] \
    [--state-dir /Users/m1/.whoathere/macos-vm-validation-ff1bb24] \
    [--whoathere-bin /Users/m1/.whoathere/bin/whoathere] \
    [--execution-path legacy_workspace_non_claim_bearing|exact_artifact_diagnostic] \
    [--detonation-config <absolute-remote-json> \
     --detonation-config-sha256 sha256:<digest>] \
    [--execution-tools-bin <absolute-remote-directory-containing-zig>] \
    --security-lab-owner <ref> \
    --evaluation-owner <ref> \
    [--provider-approval-ref <ref>] \
    [--legal-provider-approval-ref <ref>] \
    [--cloud-firewall-default-deny-asserted] \
    [--sinkhole-ready-asserted --sinkhole-reference <ref>] \
    [--phase lock|guardrails|prepare-benign|run-benign|all] \
    [--reprepare-benign]

Copies the phase-1 remote harness to the disposable Scaleway Mac and runs it.
The harness never unpacks MalwareBazaar ZIPs and never executes malware.
Exact-artifact mode is limited to lock/guardrails and validates the measured detonation adapter
configuration with a guaranteed-missing artifact. Legacy mode keeps the existing VM-health check.
EOF
  exit "$code"
}

safe_remote_value() {
  value=$1
  name=$2
  case "$value" in
    *[!A-Za-z0-9_./:@%+=,-]*)
      echo "invalid_${name}=$value" >&2
      exit 64
      ;;
  esac
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
    --stage-dir)
      [ "$#" -ge 2 ] || usage
      STAGE_DIR=$2
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
    --execution-tools-bin)
      [ "$#" -ge 2 ] || usage
      EXECUTION_TOOLS_BIN=$2
      shift 2
      ;;
    --security-lab-owner)
      [ "$#" -ge 2 ] || usage
      SECURITY_LAB_OWNER=$2
      shift 2
      ;;
    --evaluation-owner)
      [ "$#" -ge 2 ] || usage
      EVALUATION_OWNER=$2
      shift 2
      ;;
    --provider-approval-ref)
      [ "$#" -ge 2 ] || usage
      PROVIDER_APPROVAL_REF=$2
      shift 2
      ;;
    --legal-provider-approval-ref)
      [ "$#" -ge 2 ] || usage
      LEGAL_PROVIDER_APPROVAL_REF=$2
      shift 2
      ;;
    --sinkhole-reference)
      [ "$#" -ge 2 ] || usage
      SINKHOLE_REFERENCE=$2
      shift 2
      ;;
    --cloud-firewall-default-deny-asserted)
      CLOUD_FIREWALL_ASSERTED=1
      shift
      ;;
    --sinkhole-ready-asserted)
      SINKHOLE_ASSERTED=1
      shift
      ;;
    --phase)
      [ "$#" -ge 2 ] || usage
      PHASE=$2
      shift 2
      ;;
    --run-timeout-seconds)
      [ "$#" -ge 2 ] || usage
      RUN_TIMEOUT_SECONDS=$2
      shift 2
      ;;
    --reprepare-benign)
      REPREPARE_BENIGN=1
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
[ -n "$SECURITY_LAB_OWNER" ] || usage
[ -n "$EVALUATION_OWNER" ] || usage

case "$PHASE" in
  lock|guardrails|prepare-benign|run-benign|all) ;;
  *) echo "invalid_phase=$PHASE" >&2; exit 64 ;;
esac

case "$EXECUTION_PATH" in
  legacy_workspace_non_claim_bearing)
    if [ -n "$DETONATION_CONFIG$DETONATION_CONFIG_SHA256$EXECUTION_TOOLS_BIN" ]; then
      echo "legacy_phase1_rejects_exact_artifact_options" >&2
      exit 64
    fi
    ;;
  exact_artifact_diagnostic)
    [ "$PHASE" = "lock" ] || [ "$PHASE" = "guardrails" ] || {
      echo "exact_artifact_phase1_supports_lock_or_guardrails_only" >&2
      exit 64
    }
    [ -n "$DETONATION_CONFIG" ] || usage
    [ -n "$DETONATION_CONFIG_SHA256" ] || usage
    [ -n "$EXECUTION_TOOLS_BIN" ] || usage
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
[ -z "$EXECUTION_TOOLS_BIN" ] || safe_remote_value "$EXECUTION_TOOLS_BIN" "execution_tools_bin"
[ -z "$STAGE_DIR" ] || safe_remote_value "$STAGE_DIR" "stage_dir"
safe_remote_value "$SECURITY_LAB_OWNER" "security_lab_owner"
safe_remote_value "$EVALUATION_OWNER" "evaluation_owner"
[ -z "$PROVIDER_APPROVAL_REF" ] || safe_remote_value "$PROVIDER_APPROVAL_REF" "provider_approval_ref"
[ -z "$LEGAL_PROVIDER_APPROVAL_REF" ] || safe_remote_value "$LEGAL_PROVIDER_APPROVAL_REF" "legal_provider_approval_ref"
[ -z "$SINKHOLE_REFERENCE" ] || safe_remote_value "$SINKHOLE_REFERENCE" "sinkhole_reference"

ssh_run() {
  if [ -n "$SSH_CONFIG" ]; then
    ssh -F "$SSH_CONFIG" "$SSH_HOST" "$1"
  else
    ssh "$SSH_HOST" "$1"
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

remote_tools="$REMOTE_ROOT/tools"
remote_evaluator="$remote_tools/whoathere-actual-malware-evaluation.py"
remote_phase1="$remote_tools/whoathere-scaleway-phase1-remote.py"
remote_scanner_bin="$remote_tools/scanners/bin"

if [ -n "$EXECUTION_TOOLS_BIN" ]; then
  case "$EXECUTION_TOOLS_BIN" in
    /*) ;;
    *) echo "execution_tools_bin_must_be_absolute" >&2; exit 64 ;;
  esac
  case "$EXECUTION_TOOLS_BIN" in
    *:*) echo "execution_tools_bin_must_not_contain_colon" >&2; exit 64 ;;
  esac
  ssh_run "test -d $EXECUTION_TOOLS_BIN && test ! -L $EXECUTION_TOOLS_BIN && test -f $EXECUTION_TOOLS_BIN/zig && test ! -L $EXECUTION_TOOLS_BIN/zig && test -x $EXECUTION_TOOLS_BIN/zig"
fi

ssh_run "mkdir -p $remote_tools $remote_scanner_bin $REMOTE_ROOT/evidence/phase1 $REMOTE_ROOT/workspaces/benign"
ssh_run "chmod u+w $remote_evaluator $remote_phase1 2>/dev/null || true"
scp_to_remote "$REPO_ROOT/scripts/whoathere-actual-malware-evaluation.py" "$remote_evaluator"
scp_to_remote "$REPO_ROOT/scripts/whoathere-scaleway-phase1-remote.py" "$remote_phase1"
ssh_run "chmod 700 $remote_tools && chmod 500 $remote_evaluator $remote_phase1"

remote_path_prefix=$remote_scanner_bin
[ -z "$EXECUTION_TOOLS_BIN" ] || remote_path_prefix="$EXECUTION_TOOLS_BIN:$remote_path_prefix"
remote_command="WHOATHERE_SCANNER_CACHE_DIR=$remote_tools/scanners PATH=$remote_path_prefix:\$PATH /usr/bin/python3 $remote_phase1 --remote-root $REMOTE_ROOT --state-dir $STATE_DIR --whoathere-bin $WHOATHERE_BIN --evaluator-script $remote_evaluator --execution-path $EXECUTION_PATH --security-lab-owner $SECURITY_LAB_OWNER --evaluation-owner $EVALUATION_OWNER --phase $PHASE --run-timeout-seconds $RUN_TIMEOUT_SECONDS"
[ -z "$DETONATION_CONFIG" ] || remote_command="$remote_command --detonation-config $DETONATION_CONFIG --detonation-config-sha256 $DETONATION_CONFIG_SHA256"
[ -z "$STAGE_DIR" ] || remote_command="$remote_command --stage-dir $STAGE_DIR"
[ -z "$PROVIDER_APPROVAL_REF" ] || remote_command="$remote_command --provider-approval-ref $PROVIDER_APPROVAL_REF"
[ -z "$LEGAL_PROVIDER_APPROVAL_REF" ] || remote_command="$remote_command --legal-provider-approval-ref $LEGAL_PROVIDER_APPROVAL_REF"
[ -z "$SINKHOLE_REFERENCE" ] || remote_command="$remote_command --sinkhole-reference $SINKHOLE_REFERENCE"
[ -z "$CLOUD_FIREWALL_ASSERTED" ] || remote_command="$remote_command --cloud-firewall-default-deny-asserted"
[ -z "$SINKHOLE_ASSERTED" ] || remote_command="$remote_command --sinkhole-ready-asserted"
[ -z "$REPREPARE_BENIGN" ] || remote_command="$remote_command --reprepare-benign"

ssh_run "$remote_command"
