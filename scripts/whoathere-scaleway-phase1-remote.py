#!/usr/bin/env python3
"""Remote phase-1 harness for WhoaThere actual-malware evaluation.

This script is intended to run on the disposable Scaleway Mac. It locks the staged corpus state,
checks the remote guardrails that are observable from the host, prepares a benign control workspace,
and runs that benign control through WhoaThere's VM-backed path with sync-back disabled.

It never unpacks MalwareBazaar ZIPs and has no command that runs a malware sample.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_PREFIX = "whoathere.actual_malware.scaleway_phase1"
BENIGN_SAMPLE_ID = "benign-npm-postinstall-001"


class Phase1Error(Exception):
    pass


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def run_capture(argv: list[str], out_path: Path, timeout_seconds: int = 120) -> dict[str, Any]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    started = now_utc()
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        stdout = completed.stdout
        stderr = completed.stderr
        exit_code = completed.returncode
        timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = exc.stderr if isinstance(exc.stderr, str) else ""
        exit_code = 124
        timed_out = True
    out_path.write_text(stdout, encoding="utf-8")
    stderr_path = out_path.with_suffix(out_path.suffix + ".stderr")
    stderr_path.write_text(stderr, encoding="utf-8")
    return {
        "argv": argv,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "started_at_utc": started,
        "finished_at_utc": now_utc(),
        "output_path": str(out_path),
        "stderr_path": str(stderr_path),
    }


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved_path = path.expanduser().resolve()
    resolved_root = root.expanduser().resolve()
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise Phase1Error(f"{label}_outside_remote_root:{resolved_path}")
    return resolved_path


def latest_stage(remote_root: Path) -> Path:
    staged_root = remote_root / "staged"
    candidates = sorted(
        (item for item in staged_root.iterdir() if item.is_dir() and re.fullmatch(r"stage-\d{8}T\d{6}Z", item.name)),
        key=lambda item: item.name,
    )
    if not candidates:
        raise Phase1Error(f"no_stage_dirs_found:{staged_root}")
    return candidates[-1]


def workspace_hash(workspace: Path) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    for path in sorted(item for item in workspace.rglob("*") if item.is_file()):
        files.append(
            {
                "path": path.relative_to(workspace).as_posix(),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    digest_input = json.dumps(files, sort_keys=True, separators=(",", ":"))
    return {
        "schema": f"{SCHEMA_PREFIX}.workspace_hash.v1",
        "workspace": str(workspace),
        "file_count": len(files),
        "total_bytes": sum(item["size"] for item in files),
        "sha256": sha256_text(digest_input),
        "files": files,
    }


def phase_paths(remote_root: Path) -> dict[str, Path]:
    evidence_dir = remote_root / "evidence" / "phase1"
    return {
        "evidence_dir": evidence_dir,
        "state_lock": evidence_dir / "state-lock.json",
        "guardrails": evidence_dir / "guardrails-status.json",
        "benign_workspace": remote_root / "workspaces" / "benign" / BENIGN_SAMPLE_ID,
        "benign_corpus": evidence_dir / "benign-control-corpus.jsonl",
        "benign_manifest": evidence_dir / "benign-control-workspace.json",
        "benign_run_dir": evidence_dir / "benign-dry-run",
    }


def load_stage(stage_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]]]:
    manifest_path = stage_dir / "metadata" / "staging-manifest.json"
    corpus_path = stage_dir / "metadata" / "corpus_manifest.jsonl"
    supporting_path = stage_dir / "metadata" / "supporting_payloads.jsonl"
    if not manifest_path.is_file():
        raise Phase1Error(f"missing_staging_manifest:{manifest_path}")
    if not corpus_path.is_file():
        raise Phase1Error(f"missing_corpus_manifest:{corpus_path}")
    manifest = read_json(manifest_path)
    corpus = read_jsonl(corpus_path)
    supporting = read_jsonl(supporting_path) if supporting_path.is_file() else []
    return manifest, corpus, supporting


def check_stage_invariants(stage_dir: Path) -> dict[str, Any]:
    manifest, corpus, supporting = load_stage(stage_dir)
    samples_dir = stage_dir / "samples" / "malwarebazaar"
    sample_dirs = sorted(item for item in samples_dir.iterdir() if item.is_dir()) if samples_dir.is_dir() else []
    archive_paths = sorted(samples_dir.glob("*/*.malwarebazaar.zip")) if samples_dir.is_dir() else []
    custody_paths = sorted(samples_dir.glob("*/custody.json")) if samples_dir.is_dir() else []
    sidecar_paths = sorted(samples_dir.glob("*/*.malwarebazaar.zip.sha256")) if samples_dir.is_dir() else []
    allowed_names = {".malwarebazaar.zip", ".malwarebazaar.zip.sha256", "custody.json"}
    unexpected_files: list[str] = []
    archive_hash_mismatches: list[str] = []
    for path in sorted(item for item in samples_dir.rglob("*") if item.is_file()) if samples_dir.is_dir() else []:
        if path.name == "custody.json" or path.name.endswith(".malwarebazaar.zip") or path.name.endswith(".malwarebazaar.zip.sha256"):
            continue
        unexpected_files.append(str(path.relative_to(stage_dir)))
    for archive in archive_paths:
        sidecar = archive.with_name(archive.name + ".sha256")
        if not sidecar.is_file():
            archive_hash_mismatches.append(f"missing_sidecar:{archive.relative_to(stage_dir)}")
            continue
        expected = sidecar.read_text(encoding="utf-8").split()[0]
        actual = sha256_file(archive)
        if expected != actual:
            archive_hash_mismatches.append(f"sha256_mismatch:{archive.relative_to(stage_dir)}")
    primary = [row for row in corpus if row.get("execution_eligible_initial_package_run") is True]
    invariant_failures: list[str] = []
    expected_count = manifest.get("sample_count")
    if manifest.get("no_unpack_during_staging") is not True:
        invariant_failures.append("manifest_no_unpack_during_staging_not_true")
    for key in ("sync_back_allowed", "live_c2_allowed", "second_stage_live_fetch_allowed", "host_execution_authorized_by_bundle"):
        if manifest.get(key) is not False:
            invariant_failures.append(f"manifest_{key}_not_false")
    if expected_count != len(archive_paths):
        invariant_failures.append(f"archive_count_mismatch:{expected_count}!={len(archive_paths)}")
    if expected_count != len(custody_paths):
        invariant_failures.append(f"custody_count_mismatch:{expected_count}!={len(custody_paths)}")
    if expected_count != len(sidecar_paths):
        invariant_failures.append(f"sidecar_count_mismatch:{expected_count}!={len(sidecar_paths)}")
    if unexpected_files:
        invariant_failures.append("unexpected_sample_files_present")
    if archive_hash_mismatches:
        invariant_failures.append("archive_hash_mismatches_present")
    return {
        "stage_dir": str(stage_dir),
        "manifest_path": str(stage_dir / "metadata" / "staging-manifest.json"),
        "manifest_sha256": sha256_file(stage_dir / "metadata" / "staging-manifest.json"),
        "corpus_path": str(stage_dir / "metadata" / "corpus_manifest.jsonl"),
        "corpus_sha256": sha256_file(stage_dir / "metadata" / "corpus_manifest.jsonl"),
        "run_matrix_path": str(stage_dir / "metadata" / "run_matrix.todo.csv"),
        "run_matrix_sha256": sha256_file(stage_dir / "metadata" / "run_matrix.todo.csv"),
        "sample_count": len(corpus),
        "primary_package_artifact_count": len(primary),
        "supporting_payload_count": len(supporting),
        "sample_directory_count": len(sample_dirs),
        "malwarebazaar_archive_count": len(archive_paths),
        "custody_record_count": len(custody_paths),
        "sidecar_count": len(sidecar_paths),
        "unexpected_sample_files": unexpected_files,
        "archive_hash_mismatches": archive_hash_mismatches,
        "invariant_failures": invariant_failures,
        "valid": not invariant_failures,
    }


def lock_state(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    paths = phase_paths(remote_root)
    stage_check = check_stage_invariants(stage_dir)
    preflight_path = remote_root / "evidence" / "preflight" / "actual-malware-preflight-summary.json"
    preflight = read_json(preflight_path) if preflight_path.is_file() else {}
    state_lock = {
        "schema": f"{SCHEMA_PREFIX}.state_lock.v1",
        "created_at_utc": now_utc(),
        "remote_root": str(remote_root),
        "stage": stage_check,
        "preflight_summary_path": str(preflight_path),
        "preflight_summary_sha256": sha256_file(preflight_path) if preflight_path.is_file() else None,
        "preflight_ready_for_sample_workspace_preparation": preflight.get("ready_for_sample_workspace_preparation") is True,
        "provider_approval_ref": args.provider_approval_ref,
        "legal_provider_approval_ref": args.legal_provider_approval_ref,
        "security_lab_owner": args.security_lab_owner,
        "evaluation_owner": args.evaluation_owner,
        "live_malware_execution_authorized_by_phase1": False,
        "malware_unpacked_by_phase1": False,
        "malware_executed_by_phase1": False,
        "sync_back_allowed_by_phase1": False,
        "valid": stage_check["valid"] and preflight.get("ready_for_sample_workspace_preparation") is True,
    }
    write_json(paths["state_lock"], state_lock)
    return state_lock


def guardrails(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    paths = phase_paths(remote_root)
    if not paths["state_lock"].is_file():
        lock_state(remote_root, stage_dir, args)
    state_lock = read_json(paths["state_lock"])
    command_dir = paths["evidence_dir"] / "guardrail-commands"
    whoathere_bin = str(args.whoathere_bin)
    commands = {
        "vm_health": run_capture([whoathere_bin, "vm", "health", "--state-dir", str(args.state_dir)], command_dir / "vm-health.out", args.timeout_seconds),
        "red_team_gate": run_capture([whoathere_bin, "vm", "red-team-gate", "--json"], command_dir / "red-team-gate.json", args.timeout_seconds),
        "scanners_list": run_capture([whoathere_bin, "scanners", "list", "--json"], command_dir / "scanners-list.json", args.timeout_seconds),
    }
    pf_info = shutil.which("pfctl")
    if pf_info:
        commands["pf_info"] = run_capture([pf_info, "-s", "info"], command_dir / "pf-info.out", args.timeout_seconds)
        commands["pf_rules"] = run_capture([pf_info, "-sr"], command_dir / "pf-rules.out", args.timeout_seconds)
    preflight_pf_info = remote_root / "evidence" / "preflight" / "host-firewall-sudo-info.out"
    preflight_pf_rules = remote_root / "evidence" / "preflight" / "host-firewall-sudo-rules.out"
    preflight_pf_enabled = False
    if preflight_pf_info.is_file():
        preflight_pf_enabled = "Status: Enabled" in preflight_pf_info.read_text(encoding="utf-8", errors="replace")
    external_assertions = {
        "provider_approval_on_file": bool(args.provider_approval_ref),
        "legal_provider_approval_on_file": bool(args.legal_provider_approval_ref),
        "cloud_firewall_default_deny_asserted": args.cloud_firewall_default_deny_asserted,
        "sinkhole_ready_asserted": args.sinkhole_ready_asserted,
        "sinkhole_reference": args.sinkhole_reference,
    }
    command_ok = all(record["exit_code"] == 0 for name, record in commands.items() if name in {"vm_health", "red_team_gate", "scanners_list"})
    pf_observed = commands.get("pf_info", {}).get("exit_code") == 0 or preflight_pf_enabled
    ready_for_benign = state_lock.get("valid") is True and command_ok
    ready_for_live = (
        ready_for_benign
        and pf_observed
        and args.cloud_firewall_default_deny_asserted
        and args.sinkhole_ready_asserted
        and bool(args.provider_approval_ref)
        and bool(args.legal_provider_approval_ref)
    )
    status = {
        "schema": f"{SCHEMA_PREFIX}.guardrails_status.v1",
        "created_at_utc": now_utc(),
        "remote_root": str(remote_root),
        "stage_dir": str(stage_dir),
        "state_lock_path": str(paths["state_lock"]),
        "state_lock_sha256": sha256_file(paths["state_lock"]),
        "commands": commands,
        "external_assertions": external_assertions,
        "host_pf_observed": pf_observed,
        "host_pf_preflight_evidence": {
            "info_path": str(preflight_pf_info),
            "info_sha256": sha256_file(preflight_pf_info) if preflight_pf_info.is_file() else None,
            "rules_path": str(preflight_pf_rules),
            "rules_sha256": sha256_file(preflight_pf_rules) if preflight_pf_rules.is_file() else None,
            "status_enabled_observed": preflight_pf_enabled,
        },
        "malware_unpacked": False,
        "malware_executed": False,
        "sync_back_allowed": False,
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "ready_for_benign_dry_run": ready_for_benign,
        "ready_for_live_malware_rehearsal": ready_for_live,
        "live_malware_rehearsal_blockers": [] if ready_for_live else [
            reason for reason, blocked in [
                ("state_lock_or_vm_guardrails_not_ready", not ready_for_benign),
                ("host_pf_not_observed", not pf_observed),
                ("cloud_firewall_default_deny_not_asserted", not args.cloud_firewall_default_deny_asserted),
                ("sinkhole_ready_not_asserted", not args.sinkhole_ready_asserted),
                ("provider_or_legal_approval_reference_missing", not (args.provider_approval_ref and args.legal_provider_approval_ref)),
            ] if blocked
        ],
    }
    write_json(paths["guardrails"], status)
    return status


def prepare_benign(remote_root: Path, args: argparse.Namespace) -> dict[str, Any]:
    paths = phase_paths(remote_root)
    workspace = paths["benign_workspace"]
    if workspace.exists():
        shutil.rmtree(workspace)
    workspace.mkdir(parents=True)
    package_json = {
        "name": "whoathere-benign-postinstall-control",
        "version": "1.0.0",
        "private": True,
        "description": "Benign local control for WhoaThere actual-malware evaluation phase 1.",
        "scripts": {
            "postinstall": "node postinstall.js"
        },
        "dependencies": {},
        "devDependencies": {},
    }
    (workspace / "package.json").write_text(json.dumps(package_json, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    (workspace / "postinstall.js").write_text(
        """const fs = require('fs');
const path = require('path');
const out = path.join(process.cwd(), 'postinstall-ran.txt');
fs.writeFileSync(out, 'benign postinstall control executed in guest workspace\\n', { encoding: 'utf8' });
console.log('whoathere benign postinstall control complete');
""",
        encoding="utf-8",
    )
    identity = workspace_hash(workspace)
    row = {
        "schema_version": "whoathere.actual_malware.corpus.v1",
        "sample_id": BENIGN_SAMPLE_ID,
        "sample_kind": "benign_control",
        "ecosystem": "npm",
        "package_name": package_json["name"],
        "package_version": package_json["version"],
        "artifact_filename": f"{BENIGN_SAMPLE_ID}.workspace",
        "artifact_sha256": identity["sha256"],
        "artifact_size_bytes": identity["total_bytes"],
        "source_type": "lab_benign_fixture",
        "source_reference": f"local_scaleway_workspace:{workspace}",
        "disclosure_date": now_utc()[:10],
        "acquisition": {
            "case_id": args.case_id,
            "allowed_test_purpose": "whoathere benign phase-1 dry run",
            "acquired_at_utc": now_utc(),
            "collector": "scaleway-phase1-remote-harness",
            "reviewer": args.evaluation_owner,
            "authorization": "benign_lab_fixture_no_malware",
            "custody_store": f"scaleway_remote_workspace:{workspace}",
            "retention_rule": "retain_sanitized_phase1_evidence",
            "source_confidence": "high",
        },
        "approvals": {
            "legal_provider_approval": True,
            "security_lab_owner": args.security_lab_owner,
            "whoathere_evaluation_owner": args.evaluation_owner,
            "two_person_approval": True,
        },
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "trigger_phases": ["npm_lifecycle"],
        "behavior_labels": ["benign_postinstall"],
        "expected_result": "benign",
        "notes": "Remote benign control generated by phase-1 harness; not malware.",
    }
    paths["benign_corpus"].write_text(json.dumps(row, sort_keys=True) + "\n", encoding="utf-8")
    manifest = {
        "schema": f"{SCHEMA_PREFIX}.benign_control_workspace.v1",
        "created_at_utc": now_utc(),
        "sample_id": BENIGN_SAMPLE_ID,
        "workspace": str(workspace),
        "corpus_path": str(paths["benign_corpus"]),
        "workspace_identity": identity,
        "malware_unpacked": False,
        "malware_executed": False,
        "sync_back_allowed": False,
    }
    write_json(paths["benign_manifest"], manifest)
    return manifest


def assert_no_unsafe_result(result_path: Path) -> dict[str, Any]:
    result = read_json(result_path)
    summary = result.get("summary", {})
    failures: list[str] = []
    workflow_failures: list[str] = []
    if result.get("sync_back_requested") is not False:
        failures.append("sync_back_requested_not_false")
    for key in ("host_execution_enabled", "sync_back_enabled", "sync_back_applied"):
        if summary.get(key) is not False:
            failures.append(f"{key}_not_false")
    if result.get("redaction_leaks"):
        failures.append("redaction_leaks_present")
    if not summary.get("verdicts"):
        workflow_failures.append("verdicts_missing")
    for name, record in sorted(result.get("commands", {}).items()):
        if not isinstance(record, dict):
            workflow_failures.append(f"{name}_record_missing")
            continue
        if record.get("timed_out") is True:
            workflow_failures.append(f"{name}_timed_out")
        exit_code = record.get("exit_code")
        benign_manual_review = (
            result.get("expected_result") == "benign"
            and name == "package_risk_assess"
            and exit_code in {20, 22}
            and "manual_review" in summary.get("verdicts", [])
        )
        if exit_code != 0 and not benign_manual_review:
            workflow_failures.append(f"{name}_exit_code_{record.get('exit_code')}")
    result["phase1_safety_failures"] = failures
    result["phase1_workflow_failures"] = workflow_failures
    result["phase1_safety_passed"] = not failures
    result["phase1_workflow_passed"] = not workflow_failures
    return result


def run_benign(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    paths = phase_paths(remote_root)
    if not paths["guardrails"].is_file():
        guardrails(remote_root, stage_dir, args)
    guardrail_status = read_json(paths["guardrails"])
    if guardrail_status.get("ready_for_benign_dry_run") is not True:
        raise Phase1Error(f"guardrails_not_ready_for_benign_dry_run:{paths['guardrails']}")
    if not paths["benign_manifest"].is_file() or args.reprepare_benign:
        prepare_benign(remote_root, args)
    paths["benign_run_dir"].mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(args.evaluator_script),
        "run-sample",
        "--corpus",
        str(paths["benign_corpus"]),
        "--sample-id",
        BENIGN_SAMPLE_ID,
        "--workspace",
        str(paths["benign_workspace"]),
        "--state-dir",
        str(args.state_dir),
        "--whoathere-bin",
        str(args.whoathere_bin),
        "--out-dir",
        str(paths["benign_run_dir"]),
        "--tool",
        "npm",
        "--tool-args-json",
        '["install"]',
        "--mode",
        "intake",
        "--timeout-seconds",
        str(args.run_timeout_seconds),
        "--execute-approved",
    ]
    record = run_capture(command, paths["benign_run_dir"] / "phase1-run-sample.stdout", args.run_timeout_seconds + 60)
    result_path = paths["benign_run_dir"] / "run_result.json"
    if not result_path.is_file():
        raise Phase1Error(f"benign_run_result_missing:{result_path}")
    result = assert_no_unsafe_result(result_path)
    result["phase1_command_record"] = record
    write_json(paths["benign_run_dir"] / "phase1-benign-dry-run-summary.json", result)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-root", type=Path, required=True)
    parser.add_argument("--stage-dir", type=Path)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--whoathere-bin", type=Path, required=True)
    parser.add_argument("--evaluator-script", type=Path, required=True)
    parser.add_argument("--case-id", default="whoathere-actual-malware-2026-07-01")
    parser.add_argument("--security-lab-owner", required=True)
    parser.add_argument("--evaluation-owner", required=True)
    parser.add_argument("--provider-approval-ref", default="")
    parser.add_argument("--legal-provider-approval-ref", default="")
    parser.add_argument("--sinkhole-reference", default="")
    parser.add_argument("--cloud-firewall-default-deny-asserted", action="store_true")
    parser.add_argument("--sinkhole-ready-asserted", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--run-timeout-seconds", type=int, default=600)
    parser.add_argument("--reprepare-benign", action="store_true")
    parser.add_argument(
        "--phase",
        choices=["lock", "guardrails", "prepare-benign", "run-benign", "all"],
        default="all",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        remote_root = args.remote_root.expanduser().resolve()
        if not remote_root.is_dir():
            raise Phase1Error(f"remote_root_missing:{remote_root}")
        stage_dir = args.stage_dir.expanduser().resolve() if args.stage_dir else latest_stage(remote_root)
        require_under(stage_dir, remote_root, "stage_dir")
        require_under(args.state_dir, Path(args.state_dir).expanduser().resolve().parent, "state_dir")
        if not args.evaluator_script.is_file():
            raise Phase1Error(f"missing_evaluator_script:{args.evaluator_script}")

        results: dict[str, Any] = {
            "schema": f"{SCHEMA_PREFIX}.run.v1",
            "created_at_utc": now_utc(),
            "phase": args.phase,
            "remote_root": str(remote_root),
            "stage_dir": str(stage_dir),
        }
        if args.phase in {"lock", "all"}:
            results["state_lock"] = lock_state(remote_root, stage_dir, args)
        if args.phase in {"guardrails", "all"}:
            results["guardrails"] = guardrails(remote_root, stage_dir, args)
        if args.phase in {"prepare-benign", "all"}:
            results["benign_workspace"] = prepare_benign(remote_root, args)
        if args.phase in {"run-benign", "all"}:
            results["benign_dry_run"] = run_benign(remote_root, stage_dir, args)
        print(json.dumps(results, indent=2, sort_keys=True))
        if "benign_dry_run" in results and (
            not results["benign_dry_run"].get("phase1_safety_passed")
            or not results["benign_dry_run"].get("phase1_workflow_passed")
        ):
            return 20
        return 0
    except Phase1Error as exc:
        print(f"phase1_error={exc}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
