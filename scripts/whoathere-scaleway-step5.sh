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
EXECUTION_PATH=""
SAMPLE_ID="mb-npm-serverless-env-helpers-1.0.1"
RUN_ID=""
PROVIDER_APPROVAL_REF=""
LEGAL_PROVIDER_APPROVAL_REF=""
SINKHOLE_REFERENCE=""
LULU_REFERENCE=""
CLOUD_FIREWALL_ASSERTED=""
SINKHOLE_ASSERTED=""
EGRESS_DENY_ASSERTED=""
LULU_ASSERTED=""
LIVE_APPROVED=""
FORCE=""
DETONATION_CONFIG=""
DETONATION_CONFIG_SHA256=""
CODEX_CLIENT_PATH=""
CODEX_CLIENT_SHA256=""
CODEX_MODEL=""
CODEX_AUTH_HOME=""
CODEX_TIMEOUT_SECONDS="300"
PRODUCT_RUN_TIMEOUT_SECONDS="840"
RESTRICTED_SOURCE_APPROVED=""
RESTRICTED_SOURCE_APPROVAL_REF=""
RESTRICTED_BEHAVIOR_APPROVED=""
RESTRICTED_BEHAVIOR_APPROVAL_REF=""
CLEARANCE_CONSUMPTION_RECORD=""
CLEARANCE_CONSUMPTION_RECORD_SHA256=""

usage() {
  code=${1:-64}
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-scaleway-step5.sh \
    --ssh-host <host-alias-or-user@host> \
    [--ssh-config <path>] \
    [--remote-root /Users/m1/whoathere-actual-malware-lab] \
    [--stage-dir /Users/m1/whoathere-actual-malware-lab/staged/stage-...] \
    [--state-dir /Users/m1/.whoathere/macos-vm-validation-ff1bb24] \
    [--whoathere-bin /Users/m1/.whoathere/bin/whoathere] \
    --execution-path <exact_artifact_diagnostic|legacy_workspace_non_claim_bearing> \
    [--sample-id mb-npm-serverless-env-helpers-1.0.1] \
    [--run-id run-YYYYMMDDTHHMMSSZ] \
    --provider-approval-ref <ref> \
    --legal-provider-approval-ref <ref> \
    --cloud-firewall-default-deny-asserted \
    (--sinkhole-ready-asserted --sinkhole-reference <ref> | --egress-deny-asserted) \
    --lulu-enabled-asserted [--lulu-reference <ref>] \
    --live-malware-execution-approved

Exact-artifact options:
    --detonation-config <absolute-remote-json> --detonation-config-sha256 sha256:<digest> \
    --codex-client-path <absolute-remote-native-binary> --codex-client-sha256 sha256:<digest> \
    --codex-model <model> --codex-auth-home <absolute-dedicated-home> \
    [--restricted-source-hosted-review-approved --restricted-source-review-approval-ref <ref>] \
    --restricted-behavior-hosted-review-approved --restricted-behavior-review-approval-ref <ref> \
    --clearance-consumption-record <absolute-remote-json> \
    --clearance-consumption-record-sha256 sha256:<digest>

The exact-artifact path also requires a measured detonation config and Codex client, a dedicated
Codex auth home, sinkhole telemetry, and explicit approval for hosted review of restricted behavior
telemetry. Restricted source review is optional and is enabled only by its approval flag/ref pair.

Runs exactly one approved primary malware sample through WhoaThere's VM-backed no-sync path.
This script copies tooling to the disposable Scaleway Mac, then all malware unpack/execution happens remotely.
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
    --ssh-host) [ "$#" -ge 2 ] || usage; SSH_HOST=$2; shift 2 ;;
    --ssh-config) [ "$#" -ge 2 ] || usage; SSH_CONFIG=$2; shift 2 ;;
    --remote-root) [ "$#" -ge 2 ] || usage; REMOTE_ROOT=$2; shift 2 ;;
    --stage-dir) [ "$#" -ge 2 ] || usage; STAGE_DIR=$2; shift 2 ;;
    --state-dir) [ "$#" -ge 2 ] || usage; STATE_DIR=$2; shift 2 ;;
    --whoathere-bin) [ "$#" -ge 2 ] || usage; WHOATHERE_BIN=$2; shift 2 ;;
    --execution-path) [ "$#" -ge 2 ] || usage; EXECUTION_PATH=$2; shift 2 ;;
    --sample-id) [ "$#" -ge 2 ] || usage; SAMPLE_ID=$2; shift 2 ;;
    --run-id) [ "$#" -ge 2 ] || usage; RUN_ID=$2; shift 2 ;;
    --provider-approval-ref) [ "$#" -ge 2 ] || usage; PROVIDER_APPROVAL_REF=$2; shift 2 ;;
    --legal-provider-approval-ref) [ "$#" -ge 2 ] || usage; LEGAL_PROVIDER_APPROVAL_REF=$2; shift 2 ;;
    --sinkhole-reference) [ "$#" -ge 2 ] || usage; SINKHOLE_REFERENCE=$2; shift 2 ;;
    --lulu-reference) [ "$#" -ge 2 ] || usage; LULU_REFERENCE=$2; shift 2 ;;
    --cloud-firewall-default-deny-asserted) CLOUD_FIREWALL_ASSERTED=1; shift ;;
    --sinkhole-ready-asserted) SINKHOLE_ASSERTED=1; shift ;;
    --egress-deny-asserted) EGRESS_DENY_ASSERTED=1; shift ;;
    --lulu-enabled-asserted) LULU_ASSERTED=1; shift ;;
    --live-malware-execution-approved) LIVE_APPROVED=1; shift ;;
    --detonation-config) [ "$#" -ge 2 ] || usage; DETONATION_CONFIG=$2; shift 2 ;;
    --detonation-config-sha256) [ "$#" -ge 2 ] || usage; DETONATION_CONFIG_SHA256=$2; shift 2 ;;
    --codex-client-path) [ "$#" -ge 2 ] || usage; CODEX_CLIENT_PATH=$2; shift 2 ;;
    --codex-client-sha256) [ "$#" -ge 2 ] || usage; CODEX_CLIENT_SHA256=$2; shift 2 ;;
    --codex-model) [ "$#" -ge 2 ] || usage; CODEX_MODEL=$2; shift 2 ;;
    --codex-auth-home) [ "$#" -ge 2 ] || usage; CODEX_AUTH_HOME=$2; shift 2 ;;
    --codex-timeout-seconds) [ "$#" -ge 2 ] || usage; CODEX_TIMEOUT_SECONDS=$2; shift 2 ;;
    --product-run-timeout-seconds) [ "$#" -ge 2 ] || usage; PRODUCT_RUN_TIMEOUT_SECONDS=$2; shift 2 ;;
    --restricted-source-hosted-review-approved) RESTRICTED_SOURCE_APPROVED=1; shift ;;
    --restricted-source-review-approval-ref) [ "$#" -ge 2 ] || usage; RESTRICTED_SOURCE_APPROVAL_REF=$2; shift 2 ;;
    --restricted-behavior-hosted-review-approved) RESTRICTED_BEHAVIOR_APPROVED=1; shift ;;
    --restricted-behavior-review-approval-ref) [ "$#" -ge 2 ] || usage; RESTRICTED_BEHAVIOR_APPROVAL_REF=$2; shift 2 ;;
    --clearance-consumption-record) [ "$#" -ge 2 ] || usage; CLEARANCE_CONSUMPTION_RECORD=$2; shift 2 ;;
    --clearance-consumption-record-sha256) [ "$#" -ge 2 ] || usage; CLEARANCE_CONSUMPTION_RECORD_SHA256=$2; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage 0 ;;
    *) usage ;;
  esac
done

[ -n "$SSH_HOST" ] || usage
[ -n "$EXECUTION_PATH" ] || usage
[ -n "$PROVIDER_APPROVAL_REF" ] || usage
[ -n "$LEGAL_PROVIDER_APPROVAL_REF" ] || usage
[ -n "$CLOUD_FIREWALL_ASSERTED" ] || usage
[ -n "$LULU_ASSERTED" ] || usage
[ -n "$LIVE_APPROVED" ] || usage
if [ -z "$SINKHOLE_ASSERTED" ] && [ -z "$EGRESS_DENY_ASSERTED" ]; then
  usage
fi
if [ -n "$SINKHOLE_ASSERTED" ] && [ -z "$SINKHOLE_REFERENCE" ]; then
  usage
fi
if [ -n "$RESTRICTED_SOURCE_APPROVED" ] && [ -z "$RESTRICTED_SOURCE_APPROVAL_REF" ]; then
  echo "restricted_source_review_approval_flag_and_ref_must_match" >&2
  exit 64
fi
if [ -z "$RESTRICTED_SOURCE_APPROVED" ] && [ -n "$RESTRICTED_SOURCE_APPROVAL_REF" ]; then
  echo "restricted_source_review_approval_flag_and_ref_must_match" >&2
  exit 64
fi
case "$EXECUTION_PATH" in
  exact_artifact_diagnostic)
    [ -n "$SINKHOLE_ASSERTED" ] || usage
    [ -n "$DETONATION_CONFIG" ] || usage
    [ -n "$DETONATION_CONFIG_SHA256" ] || usage
    [ -n "$CODEX_CLIENT_PATH" ] || usage
    [ -n "$CODEX_CLIENT_SHA256" ] || usage
    [ -n "$CODEX_MODEL" ] || usage
    [ -n "$CODEX_AUTH_HOME" ] || usage
    [ -n "$RESTRICTED_BEHAVIOR_APPROVED" ] || usage
    [ -n "$RESTRICTED_BEHAVIOR_APPROVAL_REF" ] || usage
    [ -n "$CLEARANCE_CONSUMPTION_RECORD" ] || usage
    [ -n "$CLEARANCE_CONSUMPTION_RECORD_SHA256" ] || usage
    ;;
  legacy_workspace_non_claim_bearing) ;;
  *) usage ;;
esac

safe_remote_value "$REMOTE_ROOT" "remote_root"
safe_remote_value "$STATE_DIR" "state_dir"
safe_remote_value "$WHOATHERE_BIN" "whoathere_bin"
safe_remote_value "$EXECUTION_PATH" "execution_path"
safe_remote_value "$SAMPLE_ID" "sample_id"
[ -z "$RUN_ID" ] || safe_remote_value "$RUN_ID" "run_id"
[ -z "$STAGE_DIR" ] || safe_remote_value "$STAGE_DIR" "stage_dir"
safe_remote_value "$PROVIDER_APPROVAL_REF" "provider_approval_ref"
safe_remote_value "$LEGAL_PROVIDER_APPROVAL_REF" "legal_provider_approval_ref"
[ -z "$SINKHOLE_REFERENCE" ] || safe_remote_value "$SINKHOLE_REFERENCE" "sinkhole_reference"
[ -z "$LULU_REFERENCE" ] || safe_remote_value "$LULU_REFERENCE" "lulu_reference"
[ -z "$DETONATION_CONFIG" ] || safe_remote_value "$DETONATION_CONFIG" "detonation_config"
[ -z "$DETONATION_CONFIG_SHA256" ] || safe_remote_value "$DETONATION_CONFIG_SHA256" "detonation_config_sha256"
[ -z "$CODEX_CLIENT_PATH" ] || safe_remote_value "$CODEX_CLIENT_PATH" "codex_client_path"
[ -z "$CODEX_CLIENT_SHA256" ] || safe_remote_value "$CODEX_CLIENT_SHA256" "codex_client_sha256"
[ -z "$CODEX_MODEL" ] || safe_remote_value "$CODEX_MODEL" "codex_model"
[ -z "$CODEX_AUTH_HOME" ] || safe_remote_value "$CODEX_AUTH_HOME" "codex_auth_home"
safe_remote_value "$CODEX_TIMEOUT_SECONDS" "codex_timeout_seconds"
safe_remote_value "$PRODUCT_RUN_TIMEOUT_SECONDS" "product_run_timeout_seconds"
[ -z "$RESTRICTED_SOURCE_APPROVAL_REF" ] || safe_remote_value "$RESTRICTED_SOURCE_APPROVAL_REF" "restricted_source_approval_ref"
[ -z "$RESTRICTED_BEHAVIOR_APPROVAL_REF" ] || safe_remote_value "$RESTRICTED_BEHAVIOR_APPROVAL_REF" "restricted_behavior_approval_ref"
[ -z "$CLEARANCE_CONSUMPTION_RECORD" ] || safe_remote_value "$CLEARANCE_CONSUMPTION_RECORD" "clearance_consumption_record"
[ -z "$CLEARANCE_CONSUMPTION_RECORD_SHA256" ] || safe_remote_value "$CLEARANCE_CONSUMPTION_RECORD_SHA256" "clearance_consumption_record_sha256"

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
remote_step5="$remote_tools/whoathere-scaleway-step5-remote.py"
remote_scanner_bin="$remote_tools/scanners/bin"

ssh_run "mkdir -p $remote_tools $REMOTE_ROOT/evidence/step5 $REMOTE_ROOT/workspaces/malware"
ssh_run "chmod u+w $remote_evaluator $remote_step5 2>/dev/null || true"
scp_to_remote "$REPO_ROOT/scripts/whoathere-actual-malware-evaluation.py" "$remote_evaluator"
scp_to_remote "$REPO_ROOT/scripts/whoathere-scaleway-step5-remote.py" "$remote_step5"
ssh_run "chmod 700 $remote_tools && chmod 500 $remote_evaluator $remote_step5"

remote_command="WHOATHERE_SCANNER_CACHE_DIR=$remote_tools/scanners PATH=$remote_scanner_bin:\$PATH python3 $remote_step5 --remote-root $REMOTE_ROOT --state-dir $STATE_DIR --whoathere-bin $WHOATHERE_BIN --evaluator-script $remote_evaluator --execution-path $EXECUTION_PATH --sample-id $SAMPLE_ID --provider-approval-ref $PROVIDER_APPROVAL_REF --legal-provider-approval-ref $LEGAL_PROVIDER_APPROVAL_REF --cloud-firewall-default-deny-asserted --lulu-enabled-asserted --live-malware-execution-approved"
[ -z "$STAGE_DIR" ] || remote_command="$remote_command --stage-dir $STAGE_DIR"
[ -z "$RUN_ID" ] || remote_command="$remote_command --run-id $RUN_ID"
[ -z "$SINKHOLE_ASSERTED" ] || remote_command="$remote_command --sinkhole-ready-asserted --sinkhole-reference $SINKHOLE_REFERENCE"
[ -z "$EGRESS_DENY_ASSERTED" ] || remote_command="$remote_command --egress-deny-asserted"
[ -z "$LULU_REFERENCE" ] || remote_command="$remote_command --lulu-reference $LULU_REFERENCE"
[ -z "$FORCE" ] || remote_command="$remote_command --force"
if [ "$EXECUTION_PATH" = "exact_artifact_diagnostic" ]; then
  remote_command="$remote_command --detonation-config $DETONATION_CONFIG --detonation-config-sha256 $DETONATION_CONFIG_SHA256 --codex-client-path $CODEX_CLIENT_PATH --codex-client-sha256 $CODEX_CLIENT_SHA256 --codex-model $CODEX_MODEL --codex-auth-home $CODEX_AUTH_HOME --codex-timeout-seconds $CODEX_TIMEOUT_SECONDS --product-run-timeout-seconds $PRODUCT_RUN_TIMEOUT_SECONDS --restricted-behavior-hosted-review-approved --restricted-behavior-review-approval-ref $RESTRICTED_BEHAVIOR_APPROVAL_REF --clearance-consumption-record $CLEARANCE_CONSUMPTION_RECORD --clearance-consumption-record-sha256 $CLEARANCE_CONSUMPTION_RECORD_SHA256"
  if [ -n "$RESTRICTED_SOURCE_APPROVED" ]; then
    remote_command="$remote_command --restricted-source-hosted-review-approved --restricted-source-review-approval-ref $RESTRICTED_SOURCE_APPROVAL_REF"
  fi
fi

ssh_run "$remote_command"
