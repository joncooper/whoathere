#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
CASE_ID="whoathere-actual-malware-2026-07-01"
QUARANTINE_ROOT="$REPO_ROOT/.whoathere/corpus-lab/quarantine"
OUT_ROOT="$REPO_ROOT/.whoathere/corpus-lab/scaleway-staging"
SECURITY_LAB_OWNER=""
EVALUATION_OWNER=""
LEGAL_PROVIDER_APPROVAL_REF=""
FORCE=""

usage() {
  code=${1:-64}
  cat >&2 <<'EOF'
usage:
  scripts/whoathere-build-scaleway-staging-bundle.sh \
    --security-lab-owner <name-or-approval-ref> \
    --evaluation-owner <name-or-approval-ref> \
    --legal-provider-approval-ref <approval-ref> \
    [--case-id whoathere-actual-malware-2026-07-01] \
    [--quarantine-root .whoathere/corpus-lab/quarantine] \
    [--out-root .whoathere/corpus-lab/scaleway-staging] \
    [--force]

Builds a restricted staging bundle for the disposable Scaleway Mac.
The bundle contains MalwareBazaar password-protected ZIPs, custody records, approval metadata,
a generated corpus manifest, and a remote README. It does not unpack or execute malware.
EOF
  exit "$code"
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --case-id)
      [ "$#" -ge 2 ] || usage
      CASE_ID=$2
      shift 2
      ;;
    --quarantine-root)
      [ "$#" -ge 2 ] || usage
      QUARANTINE_ROOT=$2
      shift 2
      ;;
    --out-root)
      [ "$#" -ge 2 ] || usage
      OUT_ROOT=$2
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
    --legal-provider-approval-ref)
      [ "$#" -ge 2 ] || usage
      LEGAL_PROVIDER_APPROVAL_REF=$2
      shift 2
      ;;
    --force)
      FORCE=1
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

[ -n "$SECURITY_LAB_OWNER" ] || usage
[ -n "$EVALUATION_OWNER" ] || usage
[ -n "$LEGAL_PROVIDER_APPROVAL_REF" ] || usage

python3 -B - "$REPO_ROOT" "$CASE_ID" "$QUARANTINE_ROOT" "$OUT_ROOT" "$SECURITY_LAB_OWNER" "$EVALUATION_OWNER" "$LEGAL_PROVIDER_APPROVAL_REF" "$FORCE" <<'PY'
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

repo_root = Path(sys.argv[1]).resolve()
case_id = sys.argv[2]
quarantine_root = Path(sys.argv[3]).expanduser()
out_root = Path(sys.argv[4]).expanduser()
security_lab_owner = sys.argv[5]
evaluation_owner = sys.argv[6]
legal_provider_approval_ref = sys.argv[7]
force = bool(sys.argv[8])

if not all(part and part.replace("-", "").replace("_", "").replace(".", "").isalnum() for part in [case_id]):
    raise SystemExit(f"invalid_case_id={case_id}")

fixture_path = repo_root / "docs/product-build-run/actual-malware-malwarebazaar-fixture.jsonl.sample"
case_root = quarantine_root / case_id / "malwarebazaar"
approval_path = case_root / "custody-review-approval.json"
summary_path = case_root / "bulk-acquisition-summary.json"
results_path = case_root / "bulk-acquisition-results.jsonl"
validator = repo_root / "scripts/whoathere-actual-malware-evaluation.py"

for required in (fixture_path, approval_path, summary_path, results_path, validator):
    if not required.is_file():
        raise SystemExit(f"missing_required_file={required}")

def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()

def copy_file(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)

def read_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))

approval = read_json(approval_path)
summary = read_json(summary_path)
if approval.get("schema") != "whoathere.actual_malware.custody_review_approval.v1":
    raise SystemExit("approval_schema_invalid")
if approval.get("review_decision") != "approved_for_corpus_promotion_and_controlled_staging":
    raise SystemExit("approval_decision_not_controlled_staging")
if summary.get("status_counts") != {"acquired": 20}:
    raise SystemExit(f"summary_status_counts_invalid={summary.get('status_counts')}")
scope = approval.get("scope", {})
expected_scope_hashes = {
    "fixture_sha256": fixture_path,
    "bulk_summary_sha256": summary_path,
    "bulk_results_sha256": results_path,
}
for key, path in expected_scope_hashes.items():
    if scope.get(key) != sha256_file(path):
        raise SystemExit(f"approval_scope_hash_mismatch={key}")
if scope.get("sample_count") != len(approval.get("samples", [])):
    raise SystemExit("approval_scope_sample_count_mismatch")

timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
stage_root = out_root / case_id / f"stage-{timestamp}"
if stage_root.exists():
    if not force:
        raise SystemExit(f"stage_root_exists={stage_root}")
    shutil.rmtree(stage_root)
metadata_dir = stage_root / "metadata"
samples_dir = stage_root / "samples" / "malwarebazaar"
metadata_dir.mkdir(parents=True)
samples_dir.mkdir(parents=True)

copy_file(fixture_path, metadata_dir / "actual-malware-malwarebazaar-fixture.jsonl.sample")
copy_file(approval_path, metadata_dir / "custody-review-approval.json")
copy_file(summary_path, metadata_dir / "bulk-acquisition-summary.json")
copy_file(results_path, metadata_dir / "bulk-acquisition-results.jsonl")

fixture_by_sha: dict[str, dict] = {}
with fixture_path.open(encoding="utf-8") as handle:
    for line in handle:
        stripped = line.strip()
        if stripped:
            row = json.loads(stripped)
            fixture_by_sha[row["sha256"]] = row

corpus_rows: list[dict] = []
supporting_payload_rows: list[dict] = []
copied_samples: list[dict] = []
for sample in sorted(approval.get("samples", []), key=lambda item: item["sample_sha256"]):
    digest = sample["sample_sha256"].removeprefix("sha256:")
    source_dir = case_root / digest
    archive = source_dir / f"{digest}.malwarebazaar.zip"
    sidecar = source_dir / f"{digest}.malwarebazaar.zip.sha256"
    custody = source_dir / "custody.json"
    for required in (archive, sidecar, custody):
        if not required.is_file():
            raise SystemExit(f"missing_sample_file={required}")
    sidecar_hash = sidecar.read_text(encoding="utf-8").split()[0]
    actual_archive_hash = sha256_file(archive)
    if sidecar_hash != actual_archive_hash:
        raise SystemExit(f"archive_sidecar_hash_mismatch={digest}")
    if sample.get("archive_sha256") != actual_archive_hash:
        raise SystemExit(f"approval_archive_hash_mismatch={digest}")
    if sample.get("custody_sha256") != sha256_file(custody):
        raise SystemExit(f"approval_custody_hash_mismatch={digest}")
    dest_dir = samples_dir / digest

    custody_data = read_json(custody)
    custody_expected = {
        "source": "malwarebazaar",
        "source_reference": f"malwarebazaar:sha256:{digest}",
        "sample_sha256": f"sha256:{digest}",
        "malwarebazaar_confirmed_sample_sha256": f"sha256:{digest}",
        "download_archive_sha256": actual_archive_hash,
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
    }
    for key, expected in custody_expected.items():
        if custody_data.get(key) != expected:
            raise SystemExit(f"custody_{key}_mismatch={digest}")
    if custody_data.get("download_archive_size_bytes") != archive.stat().st_size:
        raise SystemExit(f"custody_archive_size_mismatch={digest}")
    mb_data = custody_data.get("malwarebazaar_info", {}).get("data", [])
    if not mb_data or not isinstance(mb_data[0], dict):
        raise SystemExit(f"malwarebazaar_info_missing={digest}")
    mb_info = mb_data[0]
    fixture_row = fixture_by_sha.get(digest) or custody_data.get("malwarebazaar_fixture_row", {})
    artifact_size = int(mb_info.get("file_size") or 0)
    if artifact_size <= 0:
        raise SystemExit(f"artifact_size_missing={digest}")
    copy_file(archive, dest_dir / archive.name)
    copy_file(sidecar, dest_dir / sidecar.name)
    copy_file(custody, dest_dir / custody.name)
    acquired_at = custody_data.get("created_at_utc")
    first_seen = str(fixture_row.get("first_seen_utc") or mb_info.get("first_seen") or "")
    disclosure_date = first_seen[:10] if len(first_seen) >= 10 else acquired_at[:10]
    artifact_role = fixture_row["role"]
    execution_eligible_initial_package_run = artifact_role == "package_artifact"
    corpus_row = {
            "schema_version": "whoathere.actual_malware.corpus.v1",
            "sample_id": fixture_row["sample_id"],
            "sample_kind": "malware",
            "ecosystem": fixture_row["ecosystem"],
            "package_name": fixture_row["package_name"],
            "package_version": fixture_row["package_version"],
            "artifact_filename": fixture_row["file_name"],
            "artifact_sha256": f"sha256:{digest}",
            "artifact_size_bytes": artifact_size,
            "artifact_role": artifact_role,
            "execution_eligible_initial_package_run": execution_eligible_initial_package_run,
            "execution_notes": (
                "primary package artifact"
                if execution_eligible_initial_package_run
                else "supporting payload only; do not include in package-install run matrix without a separate replay plan"
            ),
            "source_type": "malware_repository",
            "source_reference": f"malwarebazaar:sha256:{digest}",
            "disclosure_date": disclosure_date,
            "expected_result": "malicious",
            "trigger_phases": fixture_row["trigger_phases"],
            "behavior_labels": fixture_row["behavior_labels"],
            "network_policy": "sinkhole_only",
            "live_c2_allowed": False,
            "second_stage_live_fetch_allowed": False,
            "sync_back_allowed": False,
            "acquisition": {
                "case_id": case_id,
                "allowed_test_purpose": custody_data["allowed_test_purpose"],
                "acquired_at_utc": acquired_at,
                "collector": custody_data["collector"],
                "reviewer": approval["reviewer"],
                "authorization": legal_provider_approval_ref,
                "custody_store": f"scaleway_staging_bundle:{case_id}",
                "retention_rule": custody_data["retention_rule"],
                "source_confidence": "high",
            },
            "approvals": {
                "two_person_approval": True,
                "legal_provider_approval": True,
                "security_lab_owner": security_lab_owner,
                "whoathere_evaluation_owner": evaluation_owner,
            },
        }
    corpus_rows.append(corpus_row)
    if not execution_eligible_initial_package_run:
        supporting_payload_rows.append(corpus_row)
    copied_samples.append(
        {
            "sample_sha256": f"sha256:{digest}",
            "sample_id": fixture_row["sample_id"],
            "role": artifact_role,
            "execution_eligible_initial_package_run": execution_eligible_initial_package_run,
            "archive_path": str((dest_dir / archive.name).relative_to(stage_root)),
            "archive_sha256": sha256_file(dest_dir / archive.name),
            "custody_path": str((dest_dir / custody.name).relative_to(stage_root)),
            "custody_sha256": sha256_file(dest_dir / custody.name),
        }
    )

corpus_path = metadata_dir / "corpus_manifest.jsonl"
with corpus_path.open("w", encoding="utf-8") as handle:
    for row in sorted(corpus_rows, key=lambda item: item["sample_id"]):
        handle.write(json.dumps(row, sort_keys=True) + "\n")

run_matrix_path = metadata_dir / "run_matrix.todo.csv"
with (metadata_dir / "supporting_payloads.jsonl").open("w", encoding="utf-8") as handle:
    for row in sorted(supporting_payload_rows, key=lambda item: item["sample_id"]):
        handle.write(json.dumps(row, sort_keys=True) + "\n")

with run_matrix_path.open("w", encoding="utf-8") as handle:
    handle.write("sample_id,workspace_path,tool,tool_args_json,timeout_seconds,network_policy,mode\n")
    for row in sorted(corpus_rows, key=lambda item: item["sample_id"]):
        if not row["execution_eligible_initial_package_run"]:
            continue
        tool = "npm" if row["ecosystem"] == "npm" else "pip"
        tool_args = "[\"install\"]" if tool == "npm" else "[\"install\", \".\"]"
        handle.write(
            f"{row['sample_id']},TODO_PREPARE_DISPOSABLE_WORKSPACE/{row['sample_id']},{tool},"
            f"\"{tool_args.replace(chr(34), chr(34) + chr(34))}\",600,sinkhole_only,intake\n"
        )

remote_readme = metadata_dir / "REMOTE_README.md"
remote_readme.write_text(
    f"""# WhoaThere Actual Malware Scaleway Staging Bundle

Case: `{case_id}`

This bundle contains MalwareBazaar password-protected ZIP archives and custody metadata only.
Do not unzip, install, import, execute, or sync back sample contents during staging or preflight.

Expected remote flow:

1. Extract this tarball into a restricted lab directory on the disposable Scaleway Mac.
2. Validate `metadata/staging-manifest.json` and `metadata/corpus_manifest.jsonl`.
3. Run WhoaThere preflight before preparing any sample workspace.
4. Use `metadata/run_matrix.todo.csv` only for primary package artifacts.
5. Treat `metadata/supporting_payloads.jsonl` as replay-only or lineage evidence until a separate
   replay plan exists.
6. Prepare one sample workspace at a time inside the controlled lab workflow.
7. Execute only through WhoaThere's VM-backed path with sinkhole-only networking and no sync-back.

MalwareBazaar ZIP password: `infected`.
""",
    encoding="utf-8",
)

validation_report = metadata_dir / "corpus-validation.json"
completed = subprocess.run(
    [sys.executable, str(validator), "validate-corpus", "--corpus", str(corpus_path), "--report", str(validation_report)],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    check=False,
)
(metadata_dir / "corpus-validation.stdout").write_text(completed.stdout, encoding="utf-8")
(metadata_dir / "corpus-validation.stderr").write_text(completed.stderr, encoding="utf-8")
if completed.returncode != 0:
    raise SystemExit(f"corpus_validation_failed={completed.returncode}")

file_entries = []
for path in sorted(item for item in stage_root.rglob("*") if item.is_file()):
    if path.name == "staging-manifest.json":
        continue
    file_entries.append(
        {
            "path": path.relative_to(stage_root).as_posix(),
            "size": path.stat().st_size,
            "sha256": sha256_file(path),
        }
    )

manifest = {
    "schema": "whoathere.actual_malware.scaleway_staging_manifest.v1",
    "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "case_id": case_id,
    "source_quarantine_root": str(case_root),
    "stage_root": str(stage_root),
    "security_lab_owner": security_lab_owner,
    "whoathere_evaluation_owner": evaluation_owner,
    "legal_provider_approval_ref": legal_provider_approval_ref,
    "malwarebazaar_zip_password": "infected",
    "no_unpack_during_staging": True,
    "live_c2_allowed": False,
    "second_stage_live_fetch_allowed": False,
    "sync_back_allowed": False,
    "host_execution_authorized_by_bundle": False,
    "sample_count": len(copied_samples),
    "samples": copied_samples,
    "files": file_entries,
    "bundle_contents_sha256": "sha256:" + hashlib.sha256(
        json.dumps(file_entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest(),
}
(metadata_dir / "staging-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")

bundle_path = out_root / case_id / f"{stage_root.name}.tar.gz"
bundle_path.parent.mkdir(parents=True, exist_ok=True)
if bundle_path.exists() and not force:
    raise SystemExit(f"bundle_exists={bundle_path}")
with tarfile.open(bundle_path, "w:gz") as tar:
    tar.add(stage_root, arcname=stage_root.name, recursive=True)

bundle_record = {
    "schema": "whoathere.actual_malware.scaleway_staging_bundle.v1",
    "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z"),
    "case_id": case_id,
    "stage_root": str(stage_root),
    "bundle_path": str(bundle_path),
    "bundle_sha256": sha256_file(bundle_path),
    "bundle_size_bytes": bundle_path.stat().st_size,
    "manifest_path": str(metadata_dir / "staging-manifest.json"),
    "manifest_sha256": sha256_file(metadata_dir / "staging-manifest.json"),
    "corpus_manifest_path": str(corpus_path),
    "corpus_manifest_sha256": sha256_file(corpus_path),
    "sample_count": len(copied_samples),
}
bundle_record_path = bundle_path.with_name(bundle_path.name + ".manifest.json")
bundle_record_path.write_text(json.dumps(bundle_record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(bundle_path.with_name(bundle_path.name + ".sha256")).write_text(
    f"{bundle_record['bundle_sha256']}  {bundle_path.name}\n",
    encoding="utf-8",
)

print(json.dumps(bundle_record, indent=2, sort_keys=True))
PY
