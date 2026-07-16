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
CAMPAIGN_ID="whoathere-actual-malware-2026-07-01"
SLICE_ID=""
SAMPLE_ARGS=""
LIMIT=""
MAX_SAMPLES_PER_CLEARANCE="1"
CLEARANCE_RECORD=""
PROVIDER_APPROVAL_REF=""
LEGAL_PROVIDER_APPROVAL_REF=""
SINKHOLE_REFERENCE=""
LULU_REFERENCE=""
CLOUD_FIREWALL_ASSERTED=""
SINKHOLE_ASSERTED=""
EGRESS_DENY_ASSERTED=""
LULU_ASSERTED=""
LIVE_APPROVED=""
INCLUDE_EXISTING=""
INCLUDE_STANDALONE_STEP5=""
FINALIZE_FAILED_SCORE=""
EVALUATION_MANIFEST=""
VERIFIED_EVIDENCE_REGISTRY=""
VERIFIED_EVIDENCE_PUBLIC_KEY=""
VERIFIED_EVIDENCE_SIGNATURE=""
EXPECTED_EVALUATION_MANIFEST_SHA256=""
EXPECTED_VERIFIER_PUBLIC_KEY_SHA256=""
LEGACY_SCORE_MAINTENANCE=""
LEGACY_SCORE_ACKNOWLEDGED=""
PHASE="score"
CLEARANCE_ID=""
CLEARANCE_METHOD="host_rebuild_or_lab_runbook_clearance"
CLEARANCE_REVIEWER="operator-asserted"
HOST_FIREWALL_ASSERTED=""
PREVIOUS_CONTAMINATION_RESOLVED=""
HOST_REBUILT_OR_CLEARED=""
VM_REBUILT_OR_PRUNED=""

usage() {
  code=${1:-64}
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-scaleway-steps6-8.sh \
    --ssh-host <host-alias-or-user@host> \
    [--ssh-config <path>] \
    [--remote-root /Users/m1/whoathere-actual-malware-lab] \
    [--stage-dir /Users/m1/whoathere-actual-malware-lab/staged/stage-...] \
    [--state-dir /Users/m1/.whoathere/macos-vm-validation-ff1bb24] \
    [--whoathere-bin /Users/m1/.whoathere/bin/whoathere] \
    [--campaign-id whoathere-actual-malware-2026-07-01] \
    [--phase clearance|slice|score|finalize|all] \
    [--sample-id <sample-id>]... \
    [--limit <n>] \
    [--max-samples-per-clearance 1] \
    [--clearance-record /Users/m1/whoathere-actual-malware-lab/evidence/clearance/<record>.json] \
    [--clearance-reviewer <safe-ref>] \
    [--include-standalone-step5-results] \
    [--evaluation-manifest <remote EvaluationManifestV2 path>] \
    [--verified-evidence-registry <remote independently generated registry path>] \
    [--verified-evidence-public-key <remote pinned Ed25519 public-key path>] \
    [--verified-evidence-signature <remote detached raw signature path>] \
    [--expected-evaluation-manifest-sha256 sha256:<operator-frozen-digest>] \
    [--expected-verifier-public-key-sha256 sha256:<operator-frozen-digest>] \
    [--legacy-non-claim-bearing-score-maintenance \
      --acknowledge-non-claim-bearing-legacy-score] \
    [--finalize-failed-score] \
    --provider-approval-ref <ref> \
    --legal-provider-approval-ref <ref> \
    --cloud-firewall-default-deny-asserted \
    --host-firewall-default-deny-asserted \
    (--sinkhole-ready-asserted --sinkhole-reference <ref> | --egress-deny-asserted) \
    --lulu-enabled-asserted [--lulu-reference <ref>] \
    [--live-malware-execution-approved for slice/all]

For --phase clearance, the remote harness runs non-malware preflight checks and writes a clearance
record. For --phase slice, it requires a post-contamination clearance record and defaults to one
live malware sample per clearance. Claim-bearing --phase score requires a frozen v2 manifest plus
an independently generated, signed verified-evidence registry. The legacy maintenance mode is
non-claim-bearing and cannot be finalized. --phase all is intentionally unsupported because the
registry must be produced independently after the slice. --phase score and --phase finalize do not
execute malware.
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

require_sha256() {
  value=$1
  name=$2
  digest=${value#sha256:}
  if [ "$digest" = "$value" ] || [ "${#digest}" -ne 64 ]; then
    echo "invalid_${name}" >&2
    exit 64
  fi
  case "$digest" in
    *[!0-9a-f]*)
      echo "invalid_${name}" >&2
      exit 64
      ;;
  esac
}

append_sample_arg() {
  value=$1
  safe_remote_value "$value" "sample_id"
  SAMPLE_ARGS="$SAMPLE_ARGS --sample-id $value"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --ssh-host) [ "$#" -ge 2 ] || usage; SSH_HOST=$2; shift 2 ;;
    --ssh-config) [ "$#" -ge 2 ] || usage; SSH_CONFIG=$2; shift 2 ;;
    --remote-root) [ "$#" -ge 2 ] || usage; REMOTE_ROOT=$2; shift 2 ;;
    --stage-dir) [ "$#" -ge 2 ] || usage; STAGE_DIR=$2; shift 2 ;;
    --state-dir) [ "$#" -ge 2 ] || usage; STATE_DIR=$2; shift 2 ;;
    --whoathere-bin) [ "$#" -ge 2 ] || usage; WHOATHERE_BIN=$2; shift 2 ;;
    --campaign-id) [ "$#" -ge 2 ] || usage; CAMPAIGN_ID=$2; shift 2 ;;
    --clearance-id) [ "$#" -ge 2 ] || usage; CLEARANCE_ID=$2; shift 2 ;;
    --clearance-method) [ "$#" -ge 2 ] || usage; CLEARANCE_METHOD=$2; shift 2 ;;
    --clearance-reviewer) [ "$#" -ge 2 ] || usage; CLEARANCE_REVIEWER=$2; shift 2 ;;
    --slice-id) [ "$#" -ge 2 ] || usage; SLICE_ID=$2; shift 2 ;;
    --sample-id) [ "$#" -ge 2 ] || usage; append_sample_arg "$2"; shift 2 ;;
    --limit) [ "$#" -ge 2 ] || usage; LIMIT=$2; shift 2 ;;
    --max-samples-per-clearance) [ "$#" -ge 2 ] || usage; MAX_SAMPLES_PER_CLEARANCE=$2; shift 2 ;;
    --clearance-record) [ "$#" -ge 2 ] || usage; CLEARANCE_RECORD=$2; shift 2 ;;
    --evaluation-manifest) [ "$#" -ge 2 ] || usage; EVALUATION_MANIFEST=$2; shift 2 ;;
    --verified-evidence-registry) [ "$#" -ge 2 ] || usage; VERIFIED_EVIDENCE_REGISTRY=$2; shift 2 ;;
    --verified-evidence-public-key) [ "$#" -ge 2 ] || usage; VERIFIED_EVIDENCE_PUBLIC_KEY=$2; shift 2 ;;
    --verified-evidence-signature) [ "$#" -ge 2 ] || usage; VERIFIED_EVIDENCE_SIGNATURE=$2; shift 2 ;;
    --expected-evaluation-manifest-sha256) [ "$#" -ge 2 ] || usage; EXPECTED_EVALUATION_MANIFEST_SHA256=$2; shift 2 ;;
    --expected-verifier-public-key-sha256) [ "$#" -ge 2 ] || usage; EXPECTED_VERIFIER_PUBLIC_KEY_SHA256=$2; shift 2 ;;
    --provider-approval-ref) [ "$#" -ge 2 ] || usage; PROVIDER_APPROVAL_REF=$2; shift 2 ;;
    --legal-provider-approval-ref) [ "$#" -ge 2 ] || usage; LEGAL_PROVIDER_APPROVAL_REF=$2; shift 2 ;;
    --sinkhole-reference) [ "$#" -ge 2 ] || usage; SINKHOLE_REFERENCE=$2; shift 2 ;;
    --lulu-reference) [ "$#" -ge 2 ] || usage; LULU_REFERENCE=$2; shift 2 ;;
    --phase) [ "$#" -ge 2 ] || usage; PHASE=$2; shift 2 ;;
    --cloud-firewall-default-deny-asserted) CLOUD_FIREWALL_ASSERTED=1; shift ;;
    --host-firewall-default-deny-asserted) HOST_FIREWALL_ASSERTED=1; shift ;;
    --previous-contamination-resolved-asserted) PREVIOUS_CONTAMINATION_RESOLVED=1; shift ;;
    --host-rebuilt-or-cleared-asserted) HOST_REBUILT_OR_CLEARED=1; shift ;;
    --vm-state-rebuilt-or-pruned-asserted) VM_REBUILT_OR_PRUNED=1; shift ;;
    --sinkhole-ready-asserted) SINKHOLE_ASSERTED=1; shift ;;
    --egress-deny-asserted) EGRESS_DENY_ASSERTED=1; shift ;;
    --lulu-enabled-asserted) LULU_ASSERTED=1; shift ;;
    --live-malware-execution-approved) LIVE_APPROVED=1; shift ;;
    --include-existing-samples) INCLUDE_EXISTING=1; shift ;;
    --include-standalone-step5-results) INCLUDE_STANDALONE_STEP5=1; shift ;;
    --finalize-failed-score) FINALIZE_FAILED_SCORE=1; shift ;;
    --legacy-non-claim-bearing-score-maintenance) LEGACY_SCORE_MAINTENANCE=1; shift ;;
    --acknowledge-non-claim-bearing-legacy-score) LEGACY_SCORE_ACKNOWLEDGED=1; shift ;;
    -h|--help) usage 0 ;;
    *) usage ;;
  esac
done

[ -n "$SSH_HOST" ] || usage
case "$PHASE" in clearance|slice|score|finalize|all) ;; *) usage ;; esac
if [ "$PHASE" = "all" ]; then
  echo "phase_all_incompatible_with_post_run_independent_evidence_verification_use_separate_phases" >&2
  exit 64
fi

if [ "$PHASE" = "score" ]; then
  if [ -n "$LEGACY_SCORE_MAINTENANCE" ]; then
    if [ -z "$LEGACY_SCORE_ACKNOWLEDGED" ]; then
      echo "legacy_score_maintenance_requires_explicit_non_claim_bearing_acknowledgement" >&2
      exit 64
    fi
  else
    if [ -z "$VERIFIED_EVIDENCE_REGISTRY" ]; then
      echo "verified_evidence_registry_not_generated" >&2
      exit 64
    fi
    [ -n "$EVALUATION_MANIFEST" ] || { echo "evaluation_manifest_v2_required" >&2; exit 64; }
    [ -n "$VERIFIED_EVIDENCE_PUBLIC_KEY" ] || { echo "verified_evidence_public_key_required" >&2; exit 64; }
    [ -n "$VERIFIED_EVIDENCE_SIGNATURE" ] || { echo "verified_evidence_signature_required" >&2; exit 64; }
    [ -n "$EXPECTED_EVALUATION_MANIFEST_SHA256" ] || { echo "expected_evaluation_manifest_sha256_required" >&2; exit 64; }
    [ -n "$EXPECTED_VERIFIER_PUBLIC_KEY_SHA256" ] || { echo "expected_verifier_public_key_sha256_required" >&2; exit 64; }
  fi
fi
if [ "$PHASE" = "finalize" ]; then
  [ -n "$EXPECTED_EVALUATION_MANIFEST_SHA256" ] || { echo "expected_evaluation_manifest_sha256_required_for_finalize" >&2; exit 64; }
  [ -n "$EXPECTED_VERIFIER_PUBLIC_KEY_SHA256" ] || { echo "expected_verifier_public_key_sha256_required_for_finalize" >&2; exit 64; }
fi
if [ -n "$LEGACY_SCORE_ACKNOWLEDGED" ] && [ -z "$LEGACY_SCORE_MAINTENANCE" ]; then
  echo "legacy_score_acknowledgement_requires_legacy_maintenance_mode" >&2
  exit 64
fi
[ -z "$EXPECTED_EVALUATION_MANIFEST_SHA256" ] || require_sha256 "$EXPECTED_EVALUATION_MANIFEST_SHA256" "expected_evaluation_manifest_sha256"
[ -z "$EXPECTED_VERIFIER_PUBLIC_KEY_SHA256" ] || require_sha256 "$EXPECTED_VERIFIER_PUBLIC_KEY_SHA256" "expected_verifier_public_key_sha256"

if [ "$PHASE" = "clearance" ] || [ "$PHASE" = "slice" ] || [ "$PHASE" = "all" ]; then
  [ -n "$PROVIDER_APPROVAL_REF" ] || usage
  [ -n "$LEGAL_PROVIDER_APPROVAL_REF" ] || usage
  [ -n "$CLOUD_FIREWALL_ASSERTED" ] || usage
  [ -n "$HOST_FIREWALL_ASSERTED" ] || usage
  [ -n "$LULU_ASSERTED" ] || usage
  if [ -z "$SINKHOLE_ASSERTED" ] && [ -z "$EGRESS_DENY_ASSERTED" ]; then
    usage
  fi
  if [ -n "$SINKHOLE_ASSERTED" ] && [ -z "$SINKHOLE_REFERENCE" ]; then
    usage
  fi
fi
if [ "$PHASE" = "slice" ]; then
  [ -n "$LIVE_APPROVED" ] || usage
  [ -n "$CLEARANCE_RECORD" ] || usage
fi
if [ "$PHASE" = "all" ]; then
  [ -n "$LIVE_APPROVED" ] || usage
fi
if [ "$PHASE" = "clearance" ]; then
  [ -n "$PREVIOUS_CONTAMINATION_RESOLVED" ] || usage
  [ -n "$HOST_REBUILT_OR_CLEARED" ] || usage
  [ -n "$VM_REBUILT_OR_PRUNED" ] || usage
fi
if [ "$PHASE" = "all" ]; then
  [ -n "$PREVIOUS_CONTAMINATION_RESOLVED" ] || usage
  [ -n "$HOST_REBUILT_OR_CLEARED" ] || usage
  [ -n "$VM_REBUILT_OR_PRUNED" ] || usage
fi

safe_remote_value "$REMOTE_ROOT" "remote_root"
safe_remote_value "$STATE_DIR" "state_dir"
safe_remote_value "$WHOATHERE_BIN" "whoathere_bin"
safe_remote_value "$CAMPAIGN_ID" "campaign_id"
safe_remote_value "$CLEARANCE_METHOD" "clearance_method"
safe_remote_value "$CLEARANCE_REVIEWER" "clearance_reviewer"
safe_remote_value "$MAX_SAMPLES_PER_CLEARANCE" "max_samples_per_clearance"
[ -z "$STAGE_DIR" ] || safe_remote_value "$STAGE_DIR" "stage_dir"
[ -z "$CLEARANCE_ID" ] || safe_remote_value "$CLEARANCE_ID" "clearance_id"
[ -z "$SLICE_ID" ] || safe_remote_value "$SLICE_ID" "slice_id"
[ -z "$LIMIT" ] || safe_remote_value "$LIMIT" "limit"
[ -z "$CLEARANCE_RECORD" ] || safe_remote_value "$CLEARANCE_RECORD" "clearance_record"
[ -z "$EVALUATION_MANIFEST" ] || safe_remote_value "$EVALUATION_MANIFEST" "evaluation_manifest"
[ -z "$VERIFIED_EVIDENCE_REGISTRY" ] || safe_remote_value "$VERIFIED_EVIDENCE_REGISTRY" "verified_evidence_registry"
[ -z "$VERIFIED_EVIDENCE_PUBLIC_KEY" ] || safe_remote_value "$VERIFIED_EVIDENCE_PUBLIC_KEY" "verified_evidence_public_key"
[ -z "$VERIFIED_EVIDENCE_SIGNATURE" ] || safe_remote_value "$VERIFIED_EVIDENCE_SIGNATURE" "verified_evidence_signature"
[ -z "$EXPECTED_EVALUATION_MANIFEST_SHA256" ] || safe_remote_value "$EXPECTED_EVALUATION_MANIFEST_SHA256" "expected_evaluation_manifest_sha256"
[ -z "$EXPECTED_VERIFIER_PUBLIC_KEY_SHA256" ] || safe_remote_value "$EXPECTED_VERIFIER_PUBLIC_KEY_SHA256" "expected_verifier_public_key_sha256"
[ -z "$PROVIDER_APPROVAL_REF" ] || safe_remote_value "$PROVIDER_APPROVAL_REF" "provider_approval_ref"
[ -z "$LEGAL_PROVIDER_APPROVAL_REF" ] || safe_remote_value "$LEGAL_PROVIDER_APPROVAL_REF" "legal_provider_approval_ref"
[ -z "$SINKHOLE_REFERENCE" ] || safe_remote_value "$SINKHOLE_REFERENCE" "sinkhole_reference"
[ -z "$LULU_REFERENCE" ] || safe_remote_value "$LULU_REFERENCE" "lulu_reference"

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
remote_steps68="$remote_tools/whoathere-scaleway-steps6-8-remote.py"
remote_scanner_bin="$remote_tools/scanners/bin"

ssh_run "mkdir -p $remote_tools $REMOTE_ROOT/evidence/step6 $REMOTE_ROOT/evidence/step7 $REMOTE_ROOT/evidence/step8"
ssh_run "chmod u+w $remote_evaluator $remote_step5 $remote_steps68 2>/dev/null || true"
scp_to_remote "$REPO_ROOT/scripts/whoathere-actual-malware-evaluation.py" "$remote_evaluator"
scp_to_remote "$REPO_ROOT/scripts/whoathere-scaleway-step5-remote.py" "$remote_step5"
scp_to_remote "$REPO_ROOT/scripts/whoathere-scaleway-steps6-8-remote.py" "$remote_steps68"
ssh_run "chmod 700 $remote_tools && chmod 500 $remote_evaluator $remote_step5 $remote_steps68"

remote_command="WHOATHERE_SCANNER_CACHE_DIR=$remote_tools/scanners PATH=$remote_scanner_bin:\$PATH python3 $remote_steps68 --phase $PHASE --remote-root $REMOTE_ROOT --state-dir $STATE_DIR --whoathere-bin $WHOATHERE_BIN --evaluator-script $remote_evaluator --step5-script $remote_step5 --campaign-id $CAMPAIGN_ID --clearance-method $CLEARANCE_METHOD --clearance-reviewer $CLEARANCE_REVIEWER --max-samples-per-clearance $MAX_SAMPLES_PER_CLEARANCE"
[ -z "$STAGE_DIR" ] || remote_command="$remote_command --stage-dir $STAGE_DIR"
[ -z "$CLEARANCE_ID" ] || remote_command="$remote_command --clearance-id $CLEARANCE_ID"
[ -z "$SLICE_ID" ] || remote_command="$remote_command --slice-id $SLICE_ID"
[ -z "$LIMIT" ] || remote_command="$remote_command --limit $LIMIT"
[ -z "$CLEARANCE_RECORD" ] || remote_command="$remote_command --clearance-record $CLEARANCE_RECORD"
[ -z "$EVALUATION_MANIFEST" ] || remote_command="$remote_command --evaluation-manifest $EVALUATION_MANIFEST"
[ -z "$VERIFIED_EVIDENCE_REGISTRY" ] || remote_command="$remote_command --verified-evidence-registry $VERIFIED_EVIDENCE_REGISTRY"
[ -z "$VERIFIED_EVIDENCE_PUBLIC_KEY" ] || remote_command="$remote_command --verified-evidence-public-key $VERIFIED_EVIDENCE_PUBLIC_KEY"
[ -z "$VERIFIED_EVIDENCE_SIGNATURE" ] || remote_command="$remote_command --verified-evidence-signature $VERIFIED_EVIDENCE_SIGNATURE"
[ -z "$EXPECTED_EVALUATION_MANIFEST_SHA256" ] || remote_command="$remote_command --expected-evaluation-manifest-sha256 $EXPECTED_EVALUATION_MANIFEST_SHA256"
[ -z "$EXPECTED_VERIFIER_PUBLIC_KEY_SHA256" ] || remote_command="$remote_command --expected-verifier-public-key-sha256 $EXPECTED_VERIFIER_PUBLIC_KEY_SHA256"
[ -z "$SAMPLE_ARGS" ] || remote_command="$remote_command $SAMPLE_ARGS"
[ -z "$PROVIDER_APPROVAL_REF" ] || remote_command="$remote_command --provider-approval-ref $PROVIDER_APPROVAL_REF"
[ -z "$LEGAL_PROVIDER_APPROVAL_REF" ] || remote_command="$remote_command --legal-provider-approval-ref $LEGAL_PROVIDER_APPROVAL_REF"
[ -z "$CLOUD_FIREWALL_ASSERTED" ] || remote_command="$remote_command --cloud-firewall-default-deny-asserted"
[ -z "$HOST_FIREWALL_ASSERTED" ] || remote_command="$remote_command --host-firewall-default-deny-asserted"
[ -z "$PREVIOUS_CONTAMINATION_RESOLVED" ] || remote_command="$remote_command --previous-contamination-resolved-asserted"
[ -z "$HOST_REBUILT_OR_CLEARED" ] || remote_command="$remote_command --host-rebuilt-or-cleared-asserted"
[ -z "$VM_REBUILT_OR_PRUNED" ] || remote_command="$remote_command --vm-state-rebuilt-or-pruned-asserted"
[ -z "$SINKHOLE_ASSERTED" ] || remote_command="$remote_command --sinkhole-ready-asserted --sinkhole-reference $SINKHOLE_REFERENCE"
[ -z "$EGRESS_DENY_ASSERTED" ] || remote_command="$remote_command --egress-deny-asserted"
[ -z "$LULU_ASSERTED" ] || remote_command="$remote_command --lulu-enabled-asserted"
[ -z "$LULU_REFERENCE" ] || remote_command="$remote_command --lulu-reference $LULU_REFERENCE"
[ -z "$LIVE_APPROVED" ] || remote_command="$remote_command --live-malware-execution-approved"
[ -z "$INCLUDE_EXISTING" ] || remote_command="$remote_command --include-existing-samples"
[ -z "$INCLUDE_STANDALONE_STEP5" ] || remote_command="$remote_command --include-standalone-step5-results"
[ -z "$FINALIZE_FAILED_SCORE" ] || remote_command="$remote_command --finalize-failed-score"
[ -z "$LEGACY_SCORE_MAINTENANCE" ] || remote_command="$remote_command --legacy-non-claim-bearing-score-maintenance"
[ -z "$LEGACY_SCORE_ACKNOWLEDGED" ] || remote_command="$remote_command --acknowledge-non-claim-bearing-legacy-score"

ssh_run "$remote_command"
