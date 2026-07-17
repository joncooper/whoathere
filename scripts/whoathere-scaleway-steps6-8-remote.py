#!/usr/bin/env python3
"""Remote Steps 6-8 harness for the WhoaThere actual-malware evaluation.

Runs only on the disposable Scaleway Mac. The harness orchestrates campaign slices, scoring, and
final evidence sealing while preserving the Step 5 safety invariant: every malware artifact is
prepared and executed only through the remote VM-backed no-sync path.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCHEMA_PREFIX = "whoathere.actual_malware.scaleway_steps6_8"
EVALUATION_MANIFEST_V2_SCHEMA = "whoathere.actual_malware.evaluation_manifest.v2"
VERIFIED_EVIDENCE_REGISTRY_V1_SCHEMA = "whoathere.actual_malware.verified_evidence_registry.v1"
RUN_RESULT_V1_SCHEMA = "whoathere.actual_malware.run_result.v1"
RUN_RESULT_V2_SCHEMA = "whoathere.actual_malware.run_result.v2"
SCORE_REPORT_V1_SCHEMA = "whoathere.actual_malware.score_report.v1"
SCORE_REPORT_V2_SCHEMA = "whoathere.actual_malware.score_report.v2"
SCORER_V2_ID = "whoathere-actual-malware-evaluation.py:score-results-v2"
LEGACY_EXECUTION_PATH = "legacy_workspace_non_claim_bearing"
EXACT_ARTIFACT_EXECUTION_PATH = "exact_artifact_diagnostic"
EXACT_ARTIFACT_READINESS_REASON = "exact_artifact_path_unreadable"
EXACT_ARTIFACT_CLEARANCE_PREFLIGHT_SCHEMA = (
    f"{SCHEMA_PREFIX}.exact_artifact_clearance_preflight.v1"
)


class Step68Error(Exception):
    pass


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(dt.timezone.utc)
    except ValueError:
        return None


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def sha256_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def regular_non_symlink(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    return path.is_file() and not path.is_symlink() and metadata.st_size > 0


def directory_non_symlink(path: Path) -> bool:
    try:
        path.lstat()
    except OSError:
        return False
    return path.is_dir() and not path.is_symlink()


def require_json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = read_json(path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Step68Error(f"{label}_invalid_json:{path}") from exc
    if not isinstance(value, dict):
        raise Step68Error(f"{label}_must_be_object:{path}")
    return value


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved_path = path.expanduser().resolve()
    resolved_root = root.expanduser().resolve()
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise Step68Error(f"{label}_outside_remote_root:{resolved_path}")
    return resolved_path


def ensure_directory_under(path: Path, root: Path, label: str) -> Path:
    resolved_path = require_under(path, root, label)
    resolved_path.mkdir(parents=True, exist_ok=True)
    if not resolved_path.is_dir():
        raise Step68Error(f"{label}_not_directory:{resolved_path}")
    return resolved_path


def invalidate_canonical_claim_outputs(remote_root: Path, campaign_id: str) -> None:
    paths = (
        remote_root / "evidence" / "step7" / campaign_id / "step7-score-summary.json",
        remote_root / "evidence" / "step8" / campaign_id / "step8-final-summary.json",
        remote_root / "evidence" / "step8" / campaign_id / "evidence-bundle-manifest.json",
    )
    for index, path in enumerate(paths):
        resolved_path = require_under(path, remote_root, f"canonical_claim_output_{index}")
        if resolved_path.exists() and not resolved_path.is_file():
            raise Step68Error(f"canonical_claim_output_not_file:{resolved_path}")
        resolved_path.unlink(missing_ok=True)


def require_safe_segment(value: str, label: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,160}", value):
        raise Step68Error(f"{label}_invalid:{value}")
    if value in {".", ".."}:
        raise Step68Error(f"{label}_invalid:{value}")
    return value


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def load_stage(stage_dir: Path) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    corpus_path = stage_dir / "metadata" / "corpus_manifest.jsonl"
    matrix_path = stage_dir / "metadata" / "run_matrix.todo.csv"
    if not corpus_path.is_file():
        raise Step68Error(f"missing_corpus_manifest:{corpus_path}")
    if not matrix_path.is_file():
        raise Step68Error(f"missing_run_matrix:{matrix_path}")
    with matrix_path.open(newline="", encoding="utf-8") as handle:
        matrix = list(csv.DictReader(handle))
    return read_jsonl(corpus_path), matrix


def latest_stage(remote_root: Path) -> Path:
    staged_root = remote_root / "staged"
    candidates = sorted(item for item in staged_root.iterdir() if item.is_dir() and item.name.startswith("stage-"))
    if not candidates:
        raise Step68Error(f"no_stage_dirs_found:{staged_root}")
    return candidates[-1]


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


def existing_successful_live_runs(remote_root: Path) -> list[dict[str, Any]]:
    runs: list[dict[str, Any]] = []
    for summary_path in sorted((remote_root / "evidence" / "step5").glob("*/*/step5-summary.json")):
        try:
            step5_summary = read_json(summary_path)
        except Exception:
            continue
        result_path: Path | None = None
        declared_result_path = step5_summary.get("result_path")
        if isinstance(declared_result_path, str):
            candidate = require_under(Path(declared_result_path), remote_root, "prior_step5_result")
            if candidate.is_file():
                result_path = candidate
        if result_path is None:
            for candidate in (
                summary_path.parent / "whoathere-run" / "diagnostic_result.json",
                summary_path.parent / "whoathere-run" / "run_result.json",
            ):
                if candidate.is_file():
                    result_path = candidate
                    break
        try:
            result = read_json(result_path) if result_path is not None else {}
        except Exception:
            result = {}
        evidence_failures: list[str] = []
        if result_path is None:
            evidence_failures.append("step5_result_missing")
        if not step5_summary.get("host_contamination_status"):
            evidence_failures.append("host_contamination_status_missing")
        if not step5_summary.get("vm_state_status"):
            evidence_failures.append("vm_state_status_missing")
        runs.append(
            {
                "sample_id": result.get("sample_id") or step5_summary.get("sample_id"),
                "result_path": str(result_path) if result_path is not None else None,
                "result_sha256": sha256_file(result_path) if result_path is not None else None,
                "run_dir": str(summary_path.parent),
                "created_at_utc": result.get("created_at_utc") or step5_summary.get("created_at_utc"),
                "verdict_class": result.get("verdict_class"),
                "execution_path": step5_summary.get("execution_path"),
                "safety_passed": step5_summary.get("safety_passed"),
                "host_contamination_status": step5_summary.get("host_contamination_status"),
                "vm_state_status": step5_summary.get("vm_state_status"),
                "evidence_failures": evidence_failures,
                "evidence_complete": not evidence_failures,
            }
        )
    return runs


def latest_contamination(runs: list[dict[str, Any]]) -> dict[str, Any] | None:
    contaminated = [
        run
        for run in runs
        if str(run.get("host_contamination_status", "")).startswith("contaminated")
        or str(run.get("vm_state_status", "")).startswith("suspend_requested")
    ]
    if not contaminated:
        return None
    return max(contaminated, key=lambda item: parse_utc(str(item.get("created_at_utc"))) or dt.datetime.min.replace(tzinfo=dt.timezone.utc))


def validate_exact_artifact_config(args: argparse.Namespace, context: str) -> None:
    if args.detonation_config is None or not args.detonation_config_sha256:
        raise Step68Error(f"{context}_exact_artifact_detonation_config_required")
    if not args.detonation_config.is_absolute() or not regular_non_symlink(args.detonation_config):
        raise Step68Error("detonation_config_must_be_absolute_regular_non_symlink")
    if not valid_sha256(args.detonation_config_sha256):
        raise Step68Error("detonation_config_sha256_invalid")
    if sha256_file(args.detonation_config) != args.detonation_config_sha256:
        raise Step68Error("detonation_config_sha256_mismatch")


def validate_clearance_execution_args(args: argparse.Namespace) -> None:
    if args.execution_path is None:
        args.execution_path = LEGACY_EXECUTION_PATH
    if args.execution_path == LEGACY_EXECUTION_PATH:
        if args.detonation_config is not None or args.detonation_config_sha256:
            raise Step68Error("legacy_clearance_rejects_exact_artifact_options")
        return
    if args.execution_path != EXACT_ARTIFACT_EXECUTION_PATH:
        raise Step68Error(f"unsupported_clearance_execution_path:{args.execution_path}")
    validate_exact_artifact_config(args, "clearance")


def exact_artifact_clearance_preflight(
    remote_root: Path,
    args: argparse.Namespace,
    out_path: Path,
) -> tuple[dict[str, Any], dict[str, Any]]:
    started = now_utc()
    guardrails_path = remote_root / "evidence" / "phase1" / "guardrails-status.json"
    failures: list[str] = []
    guardrails: dict[str, Any] = {}
    if not regular_non_symlink(guardrails_path):
        failures.append("phase1_guardrails_missing")
    else:
        try:
            guardrails = require_json_object(guardrails_path, "phase1_guardrails")
        except Step68Error:
            failures.append("phase1_guardrails_invalid")
    readiness = guardrails.get("exact_artifact_readiness")
    readiness_bound = (
        guardrails.get("execution_path") == EXACT_ARTIFACT_EXECUTION_PATH
        and guardrails.get("ready_for_exact_artifact_diagnostic") is True
        and isinstance(readiness, dict)
        and readiness.get("valid") is True
        and readiness.get("execution_path") == EXACT_ARTIFACT_EXECUTION_PATH
        and readiness.get("detonation_config_path") == str(args.detonation_config)
        and readiness.get("detonation_config_sha256") == args.detonation_config_sha256
        and readiness.get("expected_terminal_reason") == EXACT_ARTIFACT_READINESS_REASON
        and readiness.get("artifact_executed") is False
        and readiness.get("vm_execution_requested") is False
    )
    if not readiness_bound:
        failures.append("phase1_exact_artifact_readiness_not_bound")
    preflight = {
        "schema": EXACT_ARTIFACT_CLEARANCE_PREFLIGHT_SCHEMA,
        "created_at_utc": now_utc(),
        "execution_path": EXACT_ARTIFACT_EXECUTION_PATH,
        "ready_for_live_malware": not failures,
        "ready_for_exact_artifact_diagnostic": not failures,
        "detonation_config_path": str(args.detonation_config),
        "detonation_config_sha256": args.detonation_config_sha256,
        "phase1_guardrails_path": str(guardrails_path),
        "phase1_guardrails_sha256": (
            sha256_file(guardrails_path) if regular_non_symlink(guardrails_path) else None
        ),
        "phase1_exact_artifact_readiness": readiness if isinstance(readiness, dict) else None,
        "expected_terminal_reason": EXACT_ARTIFACT_READINESS_REASON,
        "artifact_executed": False,
        "vm_execution_requested": False,
        "failures": failures,
    }
    write_json(out_path, preflight)
    record = {
        "operation": "consume_phase1_exact_artifact_readiness",
        "executed_subprocess": False,
        "exit_code": 0 if not failures else 20,
        "timed_out": False,
        "started_at_utc": started,
        "finished_at_utc": now_utc(),
        "output_path": str(out_path),
        "stderr_path": None,
    }
    return preflight, record


def validate_clearance(remote_root: Path, args: argparse.Namespace, runs: list[dict[str, Any]]) -> dict[str, Any]:
    if args.phase not in {"slice", "all"}:
        return {"required": False, "valid": True}
    if not args.clearance_record:
        raise Step68Error("step6_requires_post_contamination_clearance_record")
    clearance_path = require_under(args.clearance_record, remote_root, "clearance_record")
    if not clearance_path.is_file():
        raise Step68Error(f"clearance_record_missing:{clearance_path}")
    clearance = read_json(clearance_path)
    failures: list[str] = []
    if clearance.get("schema") != "whoathere.actual_malware.scaleway_clearance.v1":
        failures.append("schema_invalid")
    if not parse_utc(clearance.get("created_at_utc")):
        failures.append("created_at_utc_invalid")
    required_true = [
        "ready_for_live_malware",
        "previous_contamination_resolved",
        "host_rebuilt_or_cleared",
        "vm_state_rebuilt_or_pruned",
        "no_live_malware_execution_since_clearance",
        "cloud_firewall_default_deny_verified",
        "host_firewall_default_deny_verified",
        "lulu_secondary_control_enabled",
    ]
    failures.extend([key for key in required_true if clearance.get(key) is not True])
    if not (clearance.get("sinkhole_ready_verified") is True or clearance.get("egress_deny_verified") is True):
        failures.append("sinkhole_or_egress_deny_not_verified")
    if clearance.get("sinkhole_ready_verified") is True and not clearance.get("sinkhole_reference"):
        failures.append("sinkhole_reference_missing")
    if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
        if clearance.get("sinkhole_ready_verified") is not True:
            failures.append("exact_artifact_clearance_sinkhole_not_verified")
        if clearance.get("sinkhole_reference") != args.sinkhole_reference:
            failures.append("exact_artifact_clearance_sinkhole_reference_mismatch")
        if clearance.get("execution_path") != EXACT_ARTIFACT_EXECUTION_PATH:
            failures.append("exact_artifact_clearance_execution_path_mismatch")
        if clearance.get("detonation_config_path") != str(args.detonation_config):
            failures.append("exact_artifact_clearance_detonation_config_path_mismatch")
        if clearance.get("detonation_config_sha256") != args.detonation_config_sha256:
            failures.append("exact_artifact_clearance_detonation_config_sha256_mismatch")
    for key in ("provider_approval_ref", "legal_provider_approval_ref", "clearance_method", "reviewer"):
        if not isinstance(clearance.get(key), str) or not clearance.get(key):
            failures.append(f"{key}_missing")
    if clearance.get("remote_root") not in {None, str(remote_root)}:
        failures.append("remote_root_mismatch")
    if clearance.get("state_dir") not in {None, str(args.state_dir)}:
        failures.append("state_dir_mismatch")
    preflight = clearance.get("preflight")
    if not isinstance(preflight, dict):
        failures.append("preflight_missing")
    else:
        preflight_path_raw = preflight.get("path")
        preflight_sha = preflight.get("sha256")
        if not isinstance(preflight_path_raw, str):
            failures.append("preflight_path_missing")
        else:
            preflight_path = require_under(Path(preflight_path_raw), remote_root, "clearance_preflight")
            if not preflight_path.is_file():
                failures.append("preflight_file_missing")
            elif preflight_sha != sha256_file(preflight_path):
                failures.append("preflight_sha256_mismatch")
            elif args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
                try:
                    preflight_data = require_json_object(preflight_path, "clearance_preflight")
                except Step68Error:
                    failures.append("exact_artifact_clearance_preflight_invalid")
                else:
                    if preflight_data.get("schema") != EXACT_ARTIFACT_CLEARANCE_PREFLIGHT_SCHEMA:
                        failures.append("exact_artifact_clearance_preflight_schema_invalid")
                    if preflight_data.get("ready_for_exact_artifact_diagnostic") is not True:
                        failures.append("exact_artifact_clearance_preflight_not_ready")
                    if preflight_data.get("detonation_config_path") != str(args.detonation_config):
                        failures.append("exact_artifact_clearance_preflight_config_path_mismatch")
                    if preflight_data.get("detonation_config_sha256") != args.detonation_config_sha256:
                        failures.append("exact_artifact_clearance_preflight_config_sha256_mismatch")
                    if preflight_data.get("artifact_executed") is not False:
                        failures.append("exact_artifact_clearance_preflight_artifact_execution_invalid")
                    if preflight_data.get("vm_execution_requested") is not False:
                        failures.append("exact_artifact_clearance_preflight_vm_execution_invalid")
    incomplete_runs = [run for run in runs if not run.get("evidence_complete")]
    if incomplete_runs:
        failures.append("prior_live_run_evidence_incomplete")
    latest = latest_contamination(runs)
    clearance_at = parse_utc(clearance.get("created_at_utc"))
    latest_at = parse_utc(str(latest.get("created_at_utc"))) if latest else None
    if latest_at and (clearance_at is None or clearance_at <= latest_at):
        failures.append("clearance_not_newer_than_latest_contamination")
    record = {
        "required": True,
        "valid": not failures,
        "path": str(clearance_path),
        "sha256": sha256_file(clearance_path),
        "clearance_created_at_utc": clearance.get("created_at_utc"),
        "latest_contamination": latest,
        "incomplete_prior_live_runs": incomplete_runs,
        "failures": failures,
    }
    if failures:
        raise Step68Error(f"clearance_invalid:{','.join(failures)}")
    return record


def reserve_clearance_consumption(
    remote_root: Path,
    clearance_record: dict[str, Any],
    selected: list[dict[str, Any]],
    args: argparse.Namespace,
) -> dict[str, Any]:
    clearance_sha = clearance_record["sha256"]
    digest = hashlib.sha256(clearance_sha.encode("utf-8")).hexdigest()
    consumption_dir = remote_root / "evidence" / "clearance-consumption"
    consumption_dir.mkdir(parents=True, exist_ok=True)
    consumption_path = consumption_dir / f"{digest}.json"
    record = {
        "schema": f"{SCHEMA_PREFIX}.clearance_consumption.v1",
        "created_at_utc": now_utc(),
        "clearance_path": clearance_record["path"],
        "clearance_sha256": clearance_sha,
        "campaign_id": args.campaign_id,
        "sample_ids": [item["sample"]["sample_id"] for item in selected],
        "max_samples_per_clearance": args.max_samples_per_clearance,
        "status": "reserved_before_live_execution",
    }
    try:
        with consumption_path.open("x", encoding="utf-8") as handle:
            handle.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    except FileExistsError as exc:
        raise Step68Error(f"clearance_already_consumed:{consumption_path}") from exc
    record["path"] = str(consumption_path)
    record["sha256"] = sha256_file(consumption_path)
    return record


def build_clearance_record(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    clearance_id = args.clearance_id or dt.datetime.now(dt.timezone.utc).strftime("clearance-%Y%m%dT%H%M%SZ")
    require_safe_segment(clearance_id, "clearance_id")
    clearance_dir = remote_root / "evidence" / "clearance" / clearance_id
    clearance_dir.mkdir(parents=True, exist_ok=False)
    runs = existing_successful_live_runs(remote_root)
    latest = latest_contamination(runs)
    preflight_path = clearance_dir / "preflight.json"
    if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
        preflight, preflight_record = exact_artifact_clearance_preflight(
            remote_root,
            args,
            preflight_path,
        )
        direct_commands = {
            "red_team_gate": run_capture(
                [str(args.whoathere_bin), "vm", "red-team-gate", "--json"],
                clearance_dir / "red-team-gate.json",
                args.timeout_seconds,
            ),
            "scanners_list": run_capture(
                [str(args.whoathere_bin), "scanners", "list", "--json"],
                clearance_dir / "scanners-list.json",
                args.timeout_seconds,
            ),
        }
    else:
        command = [
            sys.executable,
            str(args.evaluator_script),
            "preflight-lab",
            "--whoathere-bin",
            str(args.whoathere_bin),
            "--state-dir",
            str(args.state_dir),
            "--out",
            str(preflight_path),
            "--timeout-seconds",
            str(args.timeout_seconds),
        ]
        preflight_record = run_capture(
            command,
            clearance_dir / "preflight-lab.stdout",
            args.timeout_seconds + 60,
        )
        preflight = read_json(preflight_path) if preflight_path.is_file() else {}
        direct_commands = {
            "vm_health": run_capture(
                [str(args.whoathere_bin), "vm", "health", "--state-dir", str(args.state_dir)],
                clearance_dir / "vm-health.out",
                args.timeout_seconds,
            ),
            "red_team_gate": run_capture(
                [str(args.whoathere_bin), "vm", "red-team-gate", "--json"],
                clearance_dir / "red-team-gate.json",
                args.timeout_seconds,
            ),
            "scanners_list": run_capture(
                [str(args.whoathere_bin), "scanners", "list", "--json"],
                clearance_dir / "scanners-list.json",
                args.timeout_seconds,
            ),
        }
    blockers: list[str] = []
    required_assertions = [
        ("previous_contamination_resolved", args.previous_contamination_resolved_asserted),
        ("host_rebuilt_or_cleared", args.host_rebuilt_or_cleared_asserted),
        ("vm_state_rebuilt_or_pruned", args.vm_state_rebuilt_or_pruned_asserted),
        ("cloud_firewall_default_deny_verified", args.cloud_firewall_default_deny_asserted),
        ("host_firewall_default_deny_verified", args.host_firewall_default_deny_asserted),
        ("lulu_secondary_control_enabled", args.lulu_enabled_asserted),
    ]
    for name, asserted in required_assertions:
        if not asserted:
            blockers.append(f"{name}_not_asserted")
    if not (args.sinkhole_ready_asserted or args.egress_deny_asserted):
        blockers.append("sinkhole_ready_or_egress_deny_not_asserted")
    if args.sinkhole_ready_asserted and not args.sinkhole_reference:
        blockers.append("sinkhole_reference_missing")
    if not args.provider_approval_ref or not args.legal_provider_approval_ref:
        blockers.append("provider_or_legal_approval_missing")
    if preflight_record["exit_code"] != 0:
        blockers.append("preflight_lab_failed")
    if preflight.get("ready_for_live_malware") is not True:
        blockers.append("preflight_not_ready_for_live_malware")
    if any(record["exit_code"] != 0 for record in direct_commands.values()):
        blockers.append("direct_guardrail_command_failed")
    record = {
        "schema": "whoathere.actual_malware.scaleway_clearance.v1",
        "created_at_utc": now_utc(),
        "clearance_id": clearance_id,
        "remote_root": str(remote_root),
        "stage_dir": str(stage_dir),
        "state_dir": str(args.state_dir),
        "execution_path": args.execution_path,
        "detonation_config_path": (
            str(args.detonation_config)
            if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH
            else None
        ),
        "detonation_config_sha256": (
            args.detonation_config_sha256
            if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH
            else None
        ),
        "clearance_method": args.clearance_method,
        "ready_for_live_malware": not blockers,
        "previous_contamination_resolved": args.previous_contamination_resolved_asserted,
        "host_rebuilt_or_cleared": args.host_rebuilt_or_cleared_asserted,
        "vm_state_rebuilt_or_pruned": args.vm_state_rebuilt_or_pruned_asserted,
        "no_live_malware_execution_since_clearance": True,
        "cloud_firewall_default_deny_verified": args.cloud_firewall_default_deny_asserted,
        "host_firewall_default_deny_verified": args.host_firewall_default_deny_asserted,
        "lulu_secondary_control_enabled": args.lulu_enabled_asserted,
        "sinkhole_ready_verified": args.sinkhole_ready_asserted,
        "egress_deny_verified": args.egress_deny_asserted,
        "sinkhole_reference": args.sinkhole_reference,
        "provider_approval_ref": args.provider_approval_ref,
        "legal_provider_approval_ref": args.legal_provider_approval_ref,
        "reviewer": args.clearance_reviewer,
        "latest_contamination": latest,
        "preflight": {
            "path": str(preflight_path),
            "sha256": sha256_file(preflight_path) if preflight_path.is_file() else None,
            "command": preflight_record,
        },
        "direct_commands": direct_commands,
        "blockers": blockers,
        "notes": [
            "This clearance phase does not unpack MalwareBazaar ZIPs and does not execute malware.",
            (
                "Exact-artifact clearance consumes the digest-bound Phase 1 adapter readiness and does not require legacy VM health."
                if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH
                else "Legacy clearance retains the existing doctor and VM-health preflight."
            ),
            "Step 6 still requires an explicit live-malware execution approval at slice time.",
        ],
    }
    record_path = clearance_dir / "clearance-record.json"
    write_json(record_path, record)
    record["path"] = str(record_path)
    record["sha256"] = sha256_file(record_path)
    print(json.dumps(record, indent=2, sort_keys=True))
    return record


def eligible_matrix_samples(stage_dir: Path, requested: list[str], include_existing: bool, remote_root: Path) -> list[dict[str, Any]]:
    corpus, matrix = load_stage(stage_dir)
    by_id = {row["sample_id"]: row for row in corpus}
    matrix_by_id = {row["sample_id"]: row for row in matrix}
    existing = {str(run.get("sample_id")) for run in existing_successful_live_runs(remote_root)}
    if requested:
        sample_ids = requested
    else:
        sample_ids = [row["sample_id"] for row in matrix]
    selected: list[dict[str, Any]] = []
    for sample_id in sample_ids:
        require_safe_segment(sample_id, "sample_id")
        sample = by_id.get(sample_id)
        matrix_row = matrix_by_id.get(sample_id)
        if sample is None:
            raise Step68Error(f"unknown_sample_id:{sample_id}")
        if matrix_row is None:
            raise Step68Error(f"sample_not_in_primary_run_matrix:{sample_id}")
        if sample.get("sample_kind") != "malware":
            raise Step68Error(f"step6_sample_must_be_malware:{sample_id}")
        if sample.get("execution_eligible_initial_package_run") is not True:
            raise Step68Error(f"sample_not_initial_package_run_eligible:{sample_id}")
        if sample_id in existing and not include_existing:
            continue
        selected.append({"sample": sample, "matrix_row": matrix_row})
    return selected


def validate_slice_execution_args(args: argparse.Namespace) -> None:
    if args.execution_path == LEGACY_EXECUTION_PATH:
        if (
            args.detonation_config is not None
            or args.detonation_config_sha256
            or args.restricted_source_hosted_review_approved
            or args.restricted_behavior_hosted_review_approved
            or args.split_local_behavior_finalization
        ):
            raise Step68Error("legacy_execution_path_rejects_exact_artifact_options")
        return
    if args.execution_path != EXACT_ARTIFACT_EXECUTION_PATH:
        raise Step68Error("slice_requires_explicit_execution_path")
    if args.max_samples_per_clearance != 1:
        raise Step68Error("exact_artifact_diagnostic_requires_one_sample_per_clearance")
    if len(args.sample_id) != 1:
        raise Step68Error("exact_artifact_diagnostic_requires_one_explicit_sample_id")
    source_review_approved = args.restricted_source_hosted_review_approved
    source_review_ref_present = bool(args.restricted_source_review_approval_ref)
    if source_review_approved != source_review_ref_present:
        raise Step68Error("restricted_source_review_approval_flag_and_ref_must_match")
    split_local = args.split_local_behavior_finalization
    required = [
        ("detonation_config", args.detonation_config),
        ("detonation_config_sha256", args.detonation_config_sha256),
        ("restricted_behavior_hosted_review_approved", args.restricted_behavior_hosted_review_approved),
        ("restricted_behavior_review_approval_ref", args.restricted_behavior_review_approval_ref),
    ]
    if split_local:
        forbidden = [
            label
            for label, value in (
                ("codex_client_path", args.codex_client_path),
                ("codex_client_sha256", args.codex_client_sha256),
                ("codex_model", args.codex_model),
                ("codex_auth_home", args.codex_auth_home),
                ("restricted_source_hosted_review_approved", source_review_approved),
                ("restricted_source_review_approval_ref", args.restricted_source_review_approval_ref),
            )
            if value not in {None, "", False}
        ]
        if forbidden:
            raise Step68Error(
                "split_local_behavior_finalization_rejects_remote_codex_and_source_review_inputs:"
                + ",".join(forbidden)
            )
    else:
        required.extend(
            [
                ("codex_client_path", args.codex_client_path),
                ("codex_client_sha256", args.codex_client_sha256),
                ("codex_model", args.codex_model),
                ("codex_auth_home", args.codex_auth_home),
            ]
        )
    missing = [label for label, value in required if value in {None, "", False}]
    if missing:
        raise Step68Error(f"exact_artifact_missing_required_options:{','.join(missing)}")
    if (
        source_review_approved
        and args.restricted_source_review_approval_ref
        == args.restricted_behavior_review_approval_ref
    ):
        raise Step68Error("restricted_source_and_behavior_review_approval_refs_must_be_distinct")
    if not args.sinkhole_ready_asserted:
        raise Step68Error("exact_artifact_behavior_observation_requires_sinkhole_ready")
    if not valid_sha256(args.detonation_config_sha256):
        raise Step68Error("detonation_config_sha256_invalid")
    if not split_local and not valid_sha256(args.codex_client_sha256):
        raise Step68Error("codex_client_sha256_invalid")
    if not args.detonation_config.is_absolute() or not regular_non_symlink(args.detonation_config):
        raise Step68Error("detonation_config_must_be_absolute_regular_non_symlink")
    if sha256_file(args.detonation_config) != args.detonation_config_sha256:
        raise Step68Error("detonation_config_sha256_mismatch")
    if not split_local:
        if not args.codex_client_path.is_absolute() or not regular_non_symlink(args.codex_client_path):
            raise Step68Error("codex_client_must_be_absolute_regular_non_symlink")
        if not os.access(args.codex_client_path, os.X_OK):
            raise Step68Error("codex_client_not_executable")
        if sha256_file(args.codex_client_path) != args.codex_client_sha256:
            raise Step68Error("codex_client_sha256_mismatch")
        if not args.codex_auth_home.is_absolute() or not directory_non_symlink(args.codex_auth_home):
            raise Step68Error("codex_auth_home_must_be_absolute_directory_non_symlink")
        if not 1 <= args.codex_timeout_seconds <= 600:
            raise Step68Error("codex_timeout_seconds_out_of_range")
        if args.run_timeout_seconds <= args.codex_timeout_seconds + args.timeout_seconds + 30:
            raise Step68Error("run_timeout_too_short_for_codex_plus_post_run_sealing")
    elif args.run_timeout_seconds <= args.timeout_seconds + 30:
        raise Step68Error("run_timeout_too_short_for_detonation_plus_post_run_sealing")


def sanitize_exact_step5_run_record(
    record: dict[str, Any],
    args: argparse.Namespace,
    sample_id: str,
) -> dict[str, Any]:
    return {
        key: record.get(key)
        for key in (
            "exit_code",
            "timed_out",
            "started_at_utc",
            "finished_at_utc",
            "output_path",
            "stderr_path",
        )
    } | {
        "command_identity": {
            "operation": "step5_exact_artifact_diagnostic",
            "sample_id": sample_id,
            "detonation_config_sha256": args.detonation_config_sha256,
            "behavior_observation_mode": (
                "split_local_pending" if args.split_local_behavior_finalization else "remote_codex"
            ),
            "codex_client_sha256": (
                None if args.split_local_behavior_finalization else args.codex_client_sha256
            ),
            "codex_model": None if args.split_local_behavior_finalization else args.codex_model,
            "ai_source_review": (
                False
                if args.split_local_behavior_finalization
                else args.restricted_source_hosted_review_approved
            ),
            "ai_behavior_observation": not args.split_local_behavior_finalization,
            "source_review_approval_ref_sha256": (
                sha256_text(args.restricted_source_review_approval_ref)
                if args.restricted_source_hosted_review_approved
                and not args.split_local_behavior_finalization
                else None
            ),
            "behavior_review_approval_ref_sha256": sha256_text(args.restricted_behavior_review_approval_ref),
            "codex_auth_home_path_retained": False,
            "raw_argv_retained": False,
        }
    }


def run_campaign_slice(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    require_safe_segment(args.campaign_id, "campaign_id")
    validate_slice_execution_args(args)
    runs_before = existing_successful_live_runs(remote_root)
    clearance = validate_clearance(remote_root, args, runs_before)
    selected = eligible_matrix_samples(stage_dir, args.sample_id, args.include_existing_samples, remote_root)
    if args.limit is not None:
        selected = selected[: args.limit]
    if not selected:
        raise Step68Error("no_step6_samples_selected")
    if len(selected) > args.max_samples_per_clearance:
        raise Step68Error(f"selected_sample_count_exceeds_clearance_limit:{len(selected)}>{args.max_samples_per_clearance}")
    invalidate_canonical_claim_outputs(remote_root, args.campaign_id)
    clearance_consumption = reserve_clearance_consumption(remote_root, clearance, selected, args)

    slice_id = args.slice_id or dt.datetime.now(dt.timezone.utc).strftime("slice-%Y%m%dT%H%M%SZ")
    require_safe_segment(slice_id, "slice_id")
    slice_dir = remote_root / "evidence" / "step6" / args.campaign_id / slice_id
    slice_dir.mkdir(parents=True, exist_ok=True)

    sample_runs: list[dict[str, Any]] = []
    for item in selected:
        sample_id = item["sample"]["sample_id"]
        run_id = f"{slice_id}-{sample_id}"
        require_safe_segment(run_id, "run_id")
        command = [
            sys.executable,
            str(args.step5_script),
            "--remote-root",
            str(remote_root),
            "--stage-dir",
            str(stage_dir),
            "--state-dir",
            str(args.state_dir),
            "--whoathere-bin",
            str(args.whoathere_bin),
            "--evaluator-script",
            str(args.evaluator_script),
            "--execution-path",
            args.execution_path,
            "--sample-id",
            sample_id,
            "--run-id",
            run_id,
            "--provider-approval-ref",
            args.provider_approval_ref,
            "--legal-provider-approval-ref",
            args.legal_provider_approval_ref,
            "--cloud-firewall-default-deny-asserted",
            "--lulu-enabled-asserted",
            "--live-malware-execution-approved",
            "--timeout-seconds",
            str(args.timeout_seconds),
        ]
        if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
            command.extend(
                [
                    "--detonation-config",
                    str(args.detonation_config),
                    "--detonation-config-sha256",
                    args.detonation_config_sha256,
                    "--product-run-timeout-seconds",
                    str(args.run_timeout_seconds - args.timeout_seconds - 30),
                    "--restricted-behavior-hosted-review-approved",
                    "--restricted-behavior-review-approval-ref",
                    args.restricted_behavior_review_approval_ref,
                    "--clearance-consumption-record",
                    clearance_consumption["path"],
                    "--clearance-consumption-record-sha256",
                    clearance_consumption["sha256"],
                ]
            )
            if args.split_local_behavior_finalization:
                command.append("--split-local-behavior-finalization")
            else:
                command.extend(
                    [
                        "--codex-client-path",
                        str(args.codex_client_path),
                        "--codex-client-sha256",
                        args.codex_client_sha256,
                        "--codex-model",
                        args.codex_model,
                        "--codex-auth-home",
                        str(args.codex_auth_home),
                        "--codex-timeout-seconds",
                        str(args.codex_timeout_seconds),
                    ]
                )
                if args.restricted_source_hosted_review_approved:
                    command.extend(
                        [
                            "--restricted-source-hosted-review-approved",
                            "--restricted-source-review-approval-ref",
                            args.restricted_source_review_approval_ref,
                        ]
                    )
        if args.sinkhole_ready_asserted:
            command.extend(["--sinkhole-ready-asserted", "--sinkhole-reference", args.sinkhole_reference])
        if args.egress_deny_asserted:
            command.append("--egress-deny-asserted")
        if args.lulu_reference:
            command.extend(["--lulu-reference", args.lulu_reference])
        run_record = run_capture(command, slice_dir / f"{sample_id}.step5.stdout", args.run_timeout_seconds)
        if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
            run_record = sanitize_exact_step5_run_record(run_record, args, sample_id)
        summary_path = remote_root / "evidence" / "step5" / sample_id / run_id / "step5-summary.json"
        summary = read_json(summary_path) if summary_path.is_file() else {}
        declared_result_path = summary.get("result_path")
        if isinstance(declared_result_path, str):
            result_path = require_under(Path(declared_result_path), remote_root, "step6_result")
        elif args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
            result_path = remote_root / "evidence" / "step5" / sample_id / run_id / "whoathere-run" / "diagnostic_result.json"
        else:
            result_path = remote_root / "evidence" / "step5" / sample_id / run_id / "whoathere-run" / "run_result.json"
        result = read_json(result_path) if result_path.is_file() else {}
        sample_runs.append(
            {
                "sample_id": sample_id,
                "run_id": run_id,
                "command": run_record,
                "result_path": str(result_path),
                "result_sha256": sha256_file(result_path) if result_path.is_file() else None,
                "summary_path": str(summary_path),
                "summary_sha256": sha256_file(summary_path) if summary_path.is_file() else None,
                "verdict_class": result.get("verdict_class"),
                "execution_path": args.execution_path,
                "claim_bearing": False,
                "diagnostic_completed": summary.get("diagnostic_completed"),
                "diagnostic_detection_observed": summary.get("diagnostic_detection_observed"),
                "behavior_observation_mode": summary.get("behavior_observation_mode"),
                "pending_local_behavior_finalization": summary.get(
                    "pending_local_behavior_finalization"
                ),
                "codex_behavior_detected": summary.get("codex_behavior_detected"),
                "codex_observed_detonation_gate_passed": summary.get(
                    "codex_observed_detonation_gate_passed"
                ),
                "physical_detonation_evidence_completed": summary.get(
                    "physical_detonation_evidence_completed"
                ),
                "physical_safety_proven": summary.get("physical_safety_proven"),
                "safety_passed": summary.get("safety_passed"),
                "safety_failures": summary.get("safety_failures"),
            }
        )
        if run_record["exit_code"] != 0:
            break

    unsafe = [
        run
        for run in sample_runs
        if run.get("safety_passed") is not True or run.get("verdict_class") == "unsafe_allow"
    ]
    incomplete = [
        run
        for run in sample_runs
        if run["command"]["exit_code"] != 0 or run.get("diagnostic_completed") is not True
    ]
    diagnostic_misses = [
        run
        for run in sample_runs
        if run.get("diagnostic_completed") is True
        and run.get("diagnostic_detection_observed") is not True
        and run.get("pending_local_behavior_finalization") is not True
    ]
    pending_local_runs = [
        run
        for run in sample_runs
        if run.get("pending_local_behavior_finalization") is True
    ]
    split_pending_completed = (
        args.split_local_behavior_finalization
        and len(pending_local_runs) == len(sample_runs)
        and not incomplete
        and not unsafe
    )
    slice_summary = {
        "schema": f"{SCHEMA_PREFIX}.campaign_slice.v1",
        "created_at_utc": now_utc(),
        "campaign_id": args.campaign_id,
        "slice_id": slice_id,
        "execution_path": args.execution_path,
        "claim_bearing": False,
        "scorable": False,
        "finalizable": False,
        "stage_dir": str(stage_dir),
        "clearance": clearance,
        "clearance_consumption": clearance_consumption,
        "network_policy": "sinkhole_only" if args.sinkhole_ready_asserted else "egress_denied_no_live_c2",
        "claim_boundary": (
            "sinkhole telemetry expected"
            if args.sinkhole_ready_asserted
            else "egress denied; network behavior may be fail-closed rather than sinkhole-observed"
        ),
        "sample_runs": sample_runs,
        "safety_passed": not unsafe,
        "diagnostic_completed": not incomplete,
        "diagnostic_detection_observed": (
            not args.split_local_behavior_finalization
            and not incomplete
            and not diagnostic_misses
        ),
        "diagnostic_gate_passed": (
            not args.split_local_behavior_finalization
            and not unsafe
            and not incomplete
            and not diagnostic_misses
        ),
        "behavior_observation_mode": (
            "split_local_pending" if args.split_local_behavior_finalization else "remote_codex"
        ),
        "pending_local_behavior_finalization": split_pending_completed,
        "physical_pending_gate_passed": split_pending_completed,
        "stop_required_before_next_live_sample": True,
        "host_contamination_status": "contaminated_rebuild_or_clear_before_next_live_run",
        "vm_state_status": "suspend_requested_rebuild_or_prune_before_next_live_run",
        "unsafe_or_failed_runs": unsafe,
        "incomplete_runs": incomplete,
        "diagnostic_misses": diagnostic_misses,
        "pending_local_runs": pending_local_runs,
    }
    write_json(slice_dir / "step6-slice-summary.json", slice_summary)
    print(json.dumps(slice_summary, indent=2, sort_keys=True))
    return slice_summary


def collect_results(
    remote_root: Path,
    campaign_id: str,
    expected_schema: str,
    include_standalone: bool = False,
) -> list[dict[str, Any]]:
    result_references: list[dict[str, Any]] = []
    for slice_summary_path in sorted((remote_root / "evidence" / "step6" / campaign_id).glob("*/step6-slice-summary.json")):
        try:
            slice_summary = read_json(slice_summary_path)
        except Exception:
            raise Step68Error(f"campaign_slice_summary_invalid_json:{slice_summary_path}")
        if not isinstance(slice_summary, dict) or not isinstance(slice_summary.get("sample_runs"), list):
            raise Step68Error(f"campaign_slice_summary_invalid:{slice_summary_path}")
        for sample_run in slice_summary["sample_runs"]:
            if not isinstance(sample_run, dict) or not isinstance(sample_run.get("result_path"), str):
                raise Step68Error(f"campaign_result_reference_invalid:{slice_summary_path}")
            if not isinstance(sample_run.get("sample_id"), str) or not sample_run["sample_id"]:
                raise Step68Error(f"campaign_result_sample_id_missing:{slice_summary_path}")
            result_sha256 = sample_run.get("result_sha256")
            if not valid_sha256(result_sha256):
                raise Step68Error(f"campaign_result_sha256_missing:{slice_summary_path}")
            result_references.append(
                {
                    "path": require_under(Path(sample_run["result_path"]), remote_root, "campaign_result"),
                    "sha256": result_sha256,
                    "sample_id": sample_run.get("sample_id"),
                    "reference_path": str(slice_summary_path),
                }
            )
    if include_standalone:
        result_references.extend(
            {
                "path": require_under(path, remote_root, "standalone_result"),
                "sha256": None,
                "sample_id": None,
                "reference_path": None,
            }
            for path in sorted((remote_root / "evidence" / "step5").glob("*/*/whoathere-run/run_result.json"))
        )
    deduped: dict[str, dict[str, Any]] = {}
    for reference in result_references:
        path = Path(reference["path"])
        resolved = str(path.resolve())
        prior = deduped.get(resolved)
        if prior is None:
            deduped[resolved] = reference
            continue
        for key in ("sha256", "sample_id"):
            if prior.get(key) is not None and reference.get(key) is not None and prior.get(key) != reference.get(key):
                raise Step68Error(f"campaign_result_reference_conflict:{path}:{key}")
            if prior.get(key) is None and reference.get(key) is not None:
                prior[key] = reference[key]
    results: list[dict[str, Any]] = []
    for reference in deduped.values():
        path = Path(reference["path"])
        if not path.is_file():
            raise Step68Error(f"campaign_result_missing:{path}")
        if path.name != "run_result.json" or path.parent.name != "whoathere-run":
            raise Step68Error(f"campaign_result_path_shape_invalid:{path}")
        require_under(path.parents[1], remote_root, "campaign_result_evidence_dir")
        expected_sha256 = reference.get("sha256")
        actual_sha256 = sha256_file(path)
        if expected_sha256 is not None and expected_sha256 != actual_sha256:
            raise Step68Error(f"campaign_result_sha256_mismatch:{path}")
        result = require_json_object(path, "campaign_result")
        if reference.get("sample_id") is not None and result.get("sample_id") != reference["sample_id"]:
            raise Step68Error(f"campaign_result_sample_id_mismatch:{path}")
        if result.get("schema") != expected_schema:
            if expected_schema == RUN_RESULT_V2_SCHEMA:
                raise Step68Error(f"run_result_v2_not_generated:{path}")
            raise Step68Error(f"legacy_run_result_v1_required:{path}")
        summary_path = path.parents[1] / "step5-summary.json"
        step5_summary = read_json(summary_path) if summary_path.is_file() else {}
        if expected_schema == RUN_RESULT_V1_SCHEMA:
            for key in ("live_c2_allowed", "second_stage_live_fetch_allowed", "sync_back_allowed"):
                if key not in result and key in step5_summary:
                    result[key] = step5_summary[key]
        result["_source_result_path"] = str(path)
        result["_source_result_sha256"] = actual_sha256
        results.append(result)
    if not results:
        raise Step68Error("no_run_results_found_for_scoring")
    return results


def resolve_v2_score_inputs(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    if args.verified_evidence_registry is None:
        raise Step68Error("verified_evidence_registry_not_generated")
    registry_path = require_under(
        args.verified_evidence_registry,
        remote_root,
        "verified_evidence_registry",
    )
    if not registry_path.is_file():
        raise Step68Error(f"verified_evidence_registry_not_generated:{registry_path}")
    if args.evaluation_manifest is None:
        raise Step68Error("evaluation_manifest_v2_required")
    manifest_path = require_under(args.evaluation_manifest, remote_root, "evaluation_manifest")
    if not manifest_path.is_file():
        raise Step68Error(f"evaluation_manifest_v2_missing:{manifest_path}")
    if args.verified_evidence_public_key is None:
        raise Step68Error("verified_evidence_public_key_required")
    public_key_path = require_under(
        args.verified_evidence_public_key,
        remote_root,
        "verified_evidence_public_key",
    )
    if not public_key_path.is_file():
        raise Step68Error(f"verified_evidence_public_key_missing:{public_key_path}")
    if args.verified_evidence_signature is None:
        raise Step68Error("verified_evidence_signature_required")
    signature_path = require_under(
        args.verified_evidence_signature,
        remote_root,
        "verified_evidence_signature",
    )
    if not signature_path.is_file():
        raise Step68Error(f"verified_evidence_signature_missing:{signature_path}")
    if signature_path.stat().st_size != 64:
        raise Step68Error("verified_evidence_signature_size_invalid")
    if args.expected_evaluation_manifest_sha256 is None:
        raise Step68Error("expected_evaluation_manifest_sha256_required")
    if not valid_sha256(args.expected_evaluation_manifest_sha256):
        raise Step68Error("expected_evaluation_manifest_sha256_invalid")
    if args.expected_verifier_public_key_sha256 is None:
        raise Step68Error("expected_verifier_public_key_sha256_required")
    if not valid_sha256(args.expected_verifier_public_key_sha256):
        raise Step68Error("expected_verifier_public_key_sha256_invalid")

    manifest = require_json_object(manifest_path, "evaluation_manifest_v2")
    if manifest.get("schema") != EVALUATION_MANIFEST_V2_SCHEMA:
        raise Step68Error("evaluation_manifest_v2_schema_invalid")
    registry = require_json_object(registry_path, "verified_evidence_registry")
    if registry.get("schema") != VERIFIED_EVIDENCE_REGISTRY_V1_SCHEMA:
        raise Step68Error("verified_evidence_registry_schema_invalid")

    corpus_path = require_under(
        stage_dir / "metadata" / "corpus_manifest.jsonl",
        remote_root,
        "stage_corpus_manifest",
    )
    if not corpus_path.is_file():
        raise Step68Error(f"missing_corpus_manifest:{corpus_path}")
    digests = {
        "corpus_sha256": sha256_file(corpus_path),
        "evaluation_manifest_sha256": sha256_file(manifest_path),
        "verified_evidence_registry_sha256": sha256_file(registry_path),
        "verified_evidence_public_key_sha256": sha256_file(public_key_path),
        "verified_evidence_signature_sha256": sha256_file(signature_path),
    }
    if digests["evaluation_manifest_sha256"] != args.expected_evaluation_manifest_sha256:
        raise Step68Error("operator_evaluation_manifest_sha256_pin_mismatch")
    if digests["verified_evidence_public_key_sha256"] != args.expected_verifier_public_key_sha256:
        raise Step68Error("operator_verifier_public_key_sha256_pin_mismatch")
    if manifest.get("corpus_sha256") != digests["corpus_sha256"]:
        raise Step68Error("evaluation_manifest_corpus_sha256_mismatch")
    if registry.get("evaluation_manifest_sha256") != digests["evaluation_manifest_sha256"]:
        raise Step68Error("verified_evidence_registry_evaluation_manifest_sha256_mismatch")
    if registry.get("corpus_sha256") != digests["corpus_sha256"]:
        raise Step68Error("verified_evidence_registry_corpus_sha256_mismatch")
    if registry.get("evaluation_id") != manifest.get("evaluation_id"):
        raise Step68Error("verified_evidence_registry_evaluation_id_mismatch")
    if registry.get("identities") != manifest.get("identities"):
        raise Step68Error("verified_evidence_registry_identities_manifest_mismatch")
    expected_registry = manifest.get("verified_evidence_registry")
    if not isinstance(expected_registry, dict):
        raise Step68Error("evaluation_manifest_verified_evidence_registry_missing")
    for key in ("registry_id", "verifier_id", "verifier_public_key_sha256"):
        if registry.get(key) != expected_registry.get(key):
            raise Step68Error(f"verified_evidence_registry_{key}_manifest_mismatch")
    pinned_key_digest = expected_registry.get("verifier_public_key_sha256")
    if not valid_sha256(pinned_key_digest):
        raise Step68Error("evaluation_manifest_verifier_public_key_sha256_invalid")
    if pinned_key_digest != digests["verified_evidence_public_key_sha256"]:
        raise Step68Error("verified_evidence_public_key_sha256_mismatch")

    return {
        "evaluation_id": manifest.get("evaluation_id"),
        "corpus_path": corpus_path,
        "evaluation_manifest_path": manifest_path,
        "verified_evidence_registry_path": registry_path,
        "verified_evidence_public_key_path": public_key_path,
        "verified_evidence_signature_path": signature_path,
        "operator_expected_evaluation_manifest_sha256": args.expected_evaluation_manifest_sha256,
        "operator_expected_verifier_public_key_sha256": args.expected_verifier_public_key_sha256,
        "digests": digests,
    }


def validate_v2_score_report_binding(report: dict[str, Any], score_inputs: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    expected = {
        "schema": SCORE_REPORT_V2_SCHEMA,
        "scorer_id": SCORER_V2_ID,
        "evaluation_id": score_inputs["evaluation_id"],
        **score_inputs["digests"],
    }
    for key, value in expected.items():
        if report.get(key) != value:
            failures.append(f"score_report_{key}_mismatch")
    return failures


def run_evidence_dir_from_result_path(path: Path) -> Path:
    return path.parents[1]


def audit_completed_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    audited: list[dict[str, Any]] = []
    failures: list[str] = []
    for result in results:
        result_path = Path(str(result.get("_source_result_path", "")))
        evidence_dir = run_evidence_dir_from_result_path(result_path) if result_path.name else Path(".")
        summary_path = evidence_dir / "step5-summary.json"
        live_gate_path = evidence_dir / "live-gate.json"
        seal_path = evidence_dir / "step5-evidence-seal.json"
        summary = read_json(summary_path) if summary_path.is_file() else {}
        live_gate = read_json(live_gate_path) if live_gate_path.is_file() else {}
        seal = read_json(seal_path) if seal_path.is_file() else {}
        item_failures: list[str] = []
        if result.get("schema") == RUN_RESULT_V2_SCHEMA:
            safety = result.get("safety") if isinstance(result.get("safety"), dict) else {}
            for key in (
                "host_package_execution_applied",
                "sync_back_applied",
                "live_c2_contacted",
                "live_second_stage_fetched",
                "restricted_material_leak",
            ):
                if safety.get(key) is not False:
                    item_failures.append(f"{key}_not_false")
            if safety.get("teardown_verified") is not True:
                item_failures.append("teardown_verified_not_true")
            if safety.get("network_policy") != "sinkhole_only":
                item_failures.append("network_policy_not_sinkhole_only")
        else:
            result_summary = result.get("summary", {})
            for key, value in [
                ("host_execution_enabled", result_summary.get("host_execution_enabled")),
                ("sync_back_enabled", result_summary.get("sync_back_enabled")),
                ("sync_back_applied", result_summary.get("sync_back_applied")),
                ("live_c2_allowed", result.get("live_c2_allowed", summary.get("live_c2_allowed"))),
                (
                    "second_stage_live_fetch_allowed",
                    result.get("second_stage_live_fetch_allowed", summary.get("second_stage_live_fetch_allowed")),
                ),
                ("sync_back_allowed", result.get("sync_back_allowed", summary.get("sync_back_allowed"))),
            ]:
                if value is not False:
                    item_failures.append(f"{key}_not_false")
            if result.get("redaction_leaks"):
                item_failures.append("redaction_leaks_present")
        if summary.get("safety_passed") is not True:
            item_failures.append("step5_summary_safety_not_true")
        if live_gate.get("ready_for_single_malware_rehearsal") is not True:
            item_failures.append("live_gate_not_ready")
        if live_gate.get("live_c2_allowed") is not False:
            item_failures.append("live_gate_live_c2_not_false")
        if live_gate.get("second_stage_live_fetch_allowed") is not False:
            item_failures.append("live_gate_second_stage_fetch_not_false")
        if live_gate.get("sync_back_allowed") is not False:
            item_failures.append("live_gate_sync_back_not_false")
        if not seal_path.is_file():
            item_failures.append("per_run_seal_missing")
        else:
            if seal.get("schema") != "whoathere.actual_malware.evidence_bundle_manifest.v1":
                item_failures.append("per_run_seal_schema_invalid")
            raw_seal_root = seal.get("evidence_dir")
            if not isinstance(raw_seal_root, str) or Path(raw_seal_root).resolve() != evidence_dir.resolve():
                item_failures.append("per_run_seal_evidence_dir_mismatch")
            sealed_file_records = seal.get("files")
            sealed_files: dict[str, str] = {}
            sealed_total_bytes = 0
            seal_file_records_valid = isinstance(sealed_file_records, list)
            if not seal_file_records_valid:
                item_failures.append("per_run_seal_files_invalid")
                sealed_file_records = []
            for index, item in enumerate(sealed_file_records):
                if not isinstance(item, dict):
                    item_failures.append(f"per_run_seal_file_record_invalid_{index}")
                    seal_file_records_valid = False
                    continue
                relative_path = item.get("path")
                expected_digest = item.get("sha256")
                expected_size = item.get("size")
                if (
                    not isinstance(relative_path, str)
                    or not relative_path
                    or Path(relative_path).is_absolute()
                    or not valid_sha256(expected_digest)
                    or not isinstance(expected_size, int)
                    or isinstance(expected_size, bool)
                    or expected_size < 0
                ):
                    item_failures.append(f"per_run_seal_file_record_invalid_{index}")
                    seal_file_records_valid = False
                    continue
                if relative_path in sealed_files:
                    item_failures.append(f"per_run_seal_duplicate_path:{relative_path}")
                    seal_file_records_valid = False
                    continue
                try:
                    sealed_path = require_under(
                        evidence_dir / relative_path,
                        evidence_dir,
                        "per_run_sealed_file",
                    )
                except Step68Error:
                    item_failures.append(f"per_run_seal_path_outside_evidence:{relative_path}")
                    seal_file_records_valid = False
                    continue
                if sealed_path.is_symlink() or not sealed_path.is_file():
                    item_failures.append(f"per_run_sealed_file_missing_or_nonregular:{relative_path}")
                    seal_file_records_valid = False
                    continue
                actual_size = sealed_path.stat().st_size
                actual_digest = sha256_file(sealed_path)
                if actual_size != expected_size:
                    item_failures.append(f"per_run_sealed_file_size_mismatch:{relative_path}")
                if actual_digest != expected_digest:
                    item_failures.append(f"per_run_sealed_file_sha256_mismatch:{relative_path}")
                sealed_files[relative_path] = expected_digest
                sealed_total_bytes += expected_size
            if seal_file_records_valid:
                expected_bundle_digest = sha256_text(
                    json.dumps(sealed_file_records, sort_keys=True, separators=(",", ":"))
                )
                if seal.get("bundle_sha256") != expected_bundle_digest:
                    item_failures.append("per_run_seal_bundle_sha256_mismatch")
                if seal.get("file_count") != len(sealed_file_records):
                    item_failures.append("per_run_seal_file_count_mismatch")
                if seal.get("total_bytes") != sealed_total_bytes:
                    item_failures.append("per_run_seal_total_bytes_mismatch")
            critical_paths = {
                "step5-summary.json": summary_path,
                "live-gate.json": live_gate_path,
            }
            try:
                result_relative = result_path.resolve().relative_to(evidence_dir.resolve()).as_posix()
            except ValueError:
                item_failures.append("result_path_outside_per_run_evidence")
            else:
                critical_paths[result_relative] = result_path
            for relative_path, critical_path in critical_paths.items():
                if not critical_path.is_file():
                    item_failures.append(f"per_run_critical_file_missing:{relative_path}")
                elif sealed_files.get(relative_path) != sha256_file(critical_path):
                    item_failures.append(f"per_run_critical_file_not_currently_sealed:{relative_path}")
        seal_created_at = parse_utc(seal.get("created_at_utc"))
        summary_created_at = parse_utc(summary.get("created_at_utc"))
        if seal_created_at and summary_created_at and seal_created_at < summary_created_at:
            item_failures.append("per_run_seal_older_than_summary")
        if item_failures:
            failures.append(f"{result.get('sample_id')}:{','.join(item_failures)}")
        audited.append(
            {
                "sample_id": result.get("sample_id"),
                "profile_id": result.get("profile_id"),
                "result_path": str(result_path),
                "result_sha256": result.get("_source_result_sha256"),
                "summary_path": str(summary_path),
                "live_gate_path": str(live_gate_path),
                "seal_path": str(seal_path),
                "network_policy": live_gate.get("network_policy", result.get("network_policy")),
                "claim_boundary": live_gate.get("claim_boundary"),
                "failures": item_failures,
            }
        )
    return {
        "schema": f"{SCHEMA_PREFIX}.result_safety_audit.v1",
        "created_at_utc": now_utc(),
        "valid": not failures,
        "failures": failures,
        "results": audited,
    }


def score_campaign(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    require_safe_segment(args.campaign_id, "campaign_id")
    legacy_mode = args.legacy_non_claim_bearing_score_maintenance
    if not legacy_mode:
        invalidate_canonical_claim_outputs(remote_root, args.campaign_id)
    if legacy_mode:
        if not args.acknowledge_non_claim_bearing_legacy_score:
            raise Step68Error("legacy_score_maintenance_requires_explicit_non_claim_bearing_acknowledgement")
        score_inputs = None
        score_dir = remote_root / "evidence" / "step7-legacy-maintenance" / args.campaign_id
        expected_result_schema = RUN_RESULT_V1_SCHEMA
    else:
        score_inputs = resolve_v2_score_inputs(remote_root, stage_dir, args)
        score_dir = remote_root / "evidence" / "step7" / args.campaign_id
        expected_result_schema = RUN_RESULT_V2_SCHEMA
    results = collect_results(
        remote_root,
        args.campaign_id,
        expected_result_schema,
        args.include_standalone_step5_results,
    )
    score_dir = ensure_directory_under(score_dir, remote_root, "score_dir")
    results_jsonl = score_dir / "run_result.jsonl"
    with results_jsonl.open("w", encoding="utf-8") as handle:
        for result in results:
            clean = {key: value for key, value in result.items() if not key.startswith("_")}
            handle.write(json.dumps(clean, sort_keys=True) + "\n")
    report_json = score_dir / "score-report.json"
    report_md = score_dir / "score-report.md"
    report_json.unlink(missing_ok=True)
    report_md.unlink(missing_ok=True)
    safety_audit = audit_completed_results(results)
    safety_audit_path = score_dir / "result-safety-audit.json"
    write_json(safety_audit_path, safety_audit)
    if legacy_mode:
        command = [
            sys.executable,
            str(args.evaluator_script),
            "score-results-v1-legacy",
            "--acknowledge-non-claim-bearing-legacy-score",
            "--corpus",
            str(stage_dir / "metadata" / "corpus_manifest.jsonl"),
            "--results",
            str(results_jsonl),
            "--report-json",
            str(report_json),
            "--report-md",
            str(report_md),
        ]
    else:
        assert score_inputs is not None
        command = [
            sys.executable,
            str(args.evaluator_script),
            "score-results",
            "--corpus",
            str(score_inputs["corpus_path"]),
            "--results",
            str(results_jsonl),
            "--evaluation-manifest",
            str(score_inputs["evaluation_manifest_path"]),
            "--verified-evidence-registry",
            str(score_inputs["verified_evidence_registry_path"]),
            "--verified-evidence-public-key",
            str(score_inputs["verified_evidence_public_key_path"]),
            "--verified-evidence-signature",
            str(score_inputs["verified_evidence_signature_path"]),
            "--report-json",
            str(report_json),
            "--report-md",
            str(report_md),
        ]
    score_record = run_capture(command, score_dir / "score-results.stdout", args.timeout_seconds)
    report_load_failure: str | None = None
    if report_json.is_file():
        try:
            report = require_json_object(report_json, "score_report")
        except Step68Error as exc:
            report = {}
            report_load_failure = str(exc)
    else:
        report = {}
        report_load_failure = "score_report_not_generated"
    if legacy_mode:
        report_binding_failures = []
        if report.get("schema") != SCORE_REPORT_V1_SCHEMA:
            report_binding_failures.append("score_report_schema_mismatch")
        if report.get("claim_bearing") is not False:
            report_binding_failures.append("legacy_score_report_claim_bearing_not_false")
        if report.get("legacy_compatibility_only") is not True:
            report_binding_failures.append("legacy_score_report_compatibility_marker_missing")
    else:
        assert score_inputs is not None
        report_binding_failures = validate_v2_score_report_binding(report, score_inputs)
    if report_load_failure:
        report_binding_failures.append(report_load_failure)
    score_report_passed = (
        report.get("passed") is True
        and score_record.get("exit_code") == 0
        and not report_binding_failures
    )
    campaign_gate_passed = score_report_passed and safety_audit["valid"]
    input_bindings = None
    if score_inputs is not None:
        input_bindings = {
            "evaluation_id": score_inputs["evaluation_id"],
            "corpus": str(score_inputs["corpus_path"]),
            "evaluation_manifest": str(score_inputs["evaluation_manifest_path"]),
            "verified_evidence_registry": str(score_inputs["verified_evidence_registry_path"]),
            "verified_evidence_public_key": str(score_inputs["verified_evidence_public_key_path"]),
            "verified_evidence_signature": str(score_inputs["verified_evidence_signature_path"]),
            **score_inputs["digests"],
        }
    score_summary = {
        "schema": (
            f"{SCHEMA_PREFIX}.legacy_score_summary.v1"
            if legacy_mode
            else f"{SCHEMA_PREFIX}.score_summary.v2"
        ),
        "created_at_utc": now_utc(),
        "campaign_id": args.campaign_id,
        "scoring_mode": (
            "legacy_v1_non_claim_bearing_maintenance"
            if legacy_mode
            else "evaluation_manifest_v2_signed_verified_evidence"
        ),
        "score_protocol": "legacy_v1_maintenance" if legacy_mode else "mandatory_v2",
        "legacy_compatibility_only": legacy_mode,
        "claim_bearing": not legacy_mode,
        "finalizable": not legacy_mode,
        "result_count": len(results),
        "required_result_schema": expected_result_schema,
        "results_jsonl": str(results_jsonl),
        "results_jsonl_sha256": sha256_file(results_jsonl),
        "score_report_json": str(report_json),
        "score_report_json_sha256": sha256_file(report_json) if report_json.is_file() else None,
        "score_report_md": str(report_md),
        "score_report_md_sha256": sha256_file(report_md) if report_md.is_file() else None,
        "result_safety_audit": str(safety_audit_path),
        "result_safety_audit_sha256": sha256_file(safety_audit_path),
        "score_command": score_record,
        "evaluator_script": str(args.evaluator_script.expanduser().resolve()),
        "evaluator_script_sha256": sha256_file(args.evaluator_script.expanduser().resolve()),
        "operator_trust_anchors": (
            None
            if legacy_mode
            else {
                "expected_evaluation_manifest_sha256": score_inputs[
                    "operator_expected_evaluation_manifest_sha256"
                ],
                "expected_verifier_public_key_sha256": score_inputs[
                    "operator_expected_verifier_public_key_sha256"
                ],
            }
        ),
        "score_report": report,
        "score_report_binding_valid": not report_binding_failures,
        "score_report_binding_failures": report_binding_failures,
        "score_input_bindings": input_bindings,
        "safety_audit_valid": safety_audit["valid"],
        "score_report_passed": score_report_passed,
        "campaign_gate_passed": campaign_gate_passed,
        "score_passed": campaign_gate_passed,
        "claim_boundary": (
            "Legacy V1 producer verdict maintenance only. This output is non-claim-bearing, uses no exact "
            "sample/profile denominator, and cannot be finalized."
            if legacy_mode
            else "Claim-bearing score uses the frozen EvaluationManifestV2 denominator, exact RunResultV2 "
            "rows, and the independently produced Ed25519-signed verified-evidence registry."
        ),
    }
    summary_name = "step7-legacy-maintenance-summary.json" if legacy_mode else "step7-score-summary.json"
    write_json(score_dir / summary_name, score_summary)
    print(json.dumps(score_summary, indent=2, sort_keys=True))
    return score_summary


def forbidden_evidence_files(evidence_root: Path) -> list[str]:
    forbidden_names = (
        ".malwarebazaar.zip",
        ".tgz",
        ".tar.gz",
        ".whl",
        ".pyz",
        ".macho",
    )
    forbidden_parts = {
        "samples",
        "workspaces",
        "raw-malwarebazaar-extract",
        "artifact-extract",
    }
    findings: list[str] = []
    for path in sorted(item for item in evidence_root.rglob("*") if item.is_file()):
        rel = path.relative_to(evidence_root).as_posix()
        parts = set(Path(rel).parts)
        if parts & forbidden_parts:
            findings.append(rel)
            continue
        if any(rel.endswith(name) for name in forbidden_names):
            findings.append(rel)
    return findings


def validate_finalizable_v2_score_summary(
    score_summary: dict[str, Any],
    remote_root: Path,
    stage_dir: Path,
    campaign_id: str,
    evaluator_script: Path,
    expected_evaluation_manifest_sha256: str | None,
    expected_verifier_public_key_sha256: str | None,
) -> dict[str, Any]:
    if (
        score_summary.get("schema") != f"{SCHEMA_PREFIX}.score_summary.v2"
        or score_summary.get("score_protocol") != "mandatory_v2"
        or score_summary.get("scoring_mode") != "evaluation_manifest_v2_signed_verified_evidence"
        or score_summary.get("claim_bearing") is not True
        or score_summary.get("finalizable") is not True
        or score_summary.get("legacy_compatibility_only") is not False
    ):
        raise Step68Error("step7_score_not_claim_bearing")
    if score_summary.get("campaign_id") != campaign_id:
        raise Step68Error("step7_score_campaign_id_mismatch")
    if score_summary.get("required_result_schema") != RUN_RESULT_V2_SCHEMA:
        raise Step68Error("step7_score_run_result_v2_required")
    resolved_evaluator = evaluator_script.expanduser().resolve()
    if not resolved_evaluator.is_file():
        raise Step68Error(f"step7_evaluator_script_missing:{resolved_evaluator}")
    if score_summary.get("evaluator_script") != str(resolved_evaluator):
        raise Step68Error("step7_evaluator_script_path_mismatch")
    if score_summary.get("evaluator_script_sha256") != sha256_file(resolved_evaluator):
        raise Step68Error("step7_evaluator_script_sha256_mismatch")
    if score_summary.get("score_report_binding_valid") is not True or score_summary.get(
        "score_report_binding_failures"
    ) != []:
        raise Step68Error("step7_score_report_binding_not_valid")

    bindings = score_summary.get("score_input_bindings")
    if not isinstance(bindings, dict):
        raise Step68Error("step7_score_input_bindings_missing")
    if expected_evaluation_manifest_sha256 is None:
        raise Step68Error("expected_evaluation_manifest_sha256_required_for_finalize")
    if not valid_sha256(expected_evaluation_manifest_sha256):
        raise Step68Error("expected_evaluation_manifest_sha256_invalid_for_finalize")
    if expected_verifier_public_key_sha256 is None:
        raise Step68Error("expected_verifier_public_key_sha256_required_for_finalize")
    if not valid_sha256(expected_verifier_public_key_sha256):
        raise Step68Error("expected_verifier_public_key_sha256_invalid_for_finalize")
    if bindings.get("evaluation_manifest_sha256") != expected_evaluation_manifest_sha256:
        raise Step68Error("operator_evaluation_manifest_sha256_pin_mismatch_for_finalize")
    if bindings.get("verified_evidence_public_key_sha256") != expected_verifier_public_key_sha256:
        raise Step68Error("operator_verifier_public_key_sha256_pin_mismatch_for_finalize")
    if score_summary.get("operator_trust_anchors") != {
        "expected_evaluation_manifest_sha256": expected_evaluation_manifest_sha256,
        "expected_verifier_public_key_sha256": expected_verifier_public_key_sha256,
    }:
        raise Step68Error("step7_operator_trust_anchors_mismatch")
    path_digest_pairs = {
        "corpus": "corpus_sha256",
        "evaluation_manifest": "evaluation_manifest_sha256",
        "verified_evidence_registry": "verified_evidence_registry_sha256",
        "verified_evidence_public_key": "verified_evidence_public_key_sha256",
        "verified_evidence_signature": "verified_evidence_signature_sha256",
    }
    bound_paths: dict[str, Path] = {}
    for path_key, digest_key in path_digest_pairs.items():
        raw_path = bindings.get(path_key)
        expected_digest = bindings.get(digest_key)
        if not isinstance(raw_path, str):
            raise Step68Error(f"step7_score_input_{path_key}_path_missing")
        if not valid_sha256(expected_digest):
            raise Step68Error(f"step7_score_input_{digest_key}_invalid")
        path = require_under(Path(raw_path), remote_root, f"step7_score_input_{path_key}")
        if not path.is_file():
            raise Step68Error(f"step7_score_input_{path_key}_missing:{path}")
        if sha256_file(path) != expected_digest:
            raise Step68Error(f"step7_score_input_{path_key}_sha256_mismatch")
        bound_paths[path_key] = path
    expected_stage_corpus = (stage_dir / "metadata" / "corpus_manifest.jsonl").resolve()
    if bound_paths["corpus"].resolve() != expected_stage_corpus:
        raise Step68Error("step7_score_input_corpus_path_stage_mismatch")
    if bound_paths["verified_evidence_signature"].stat().st_size != 64:
        raise Step68Error("step7_verified_evidence_signature_size_invalid")
    manifest = require_json_object(bound_paths["evaluation_manifest"], "step7_evaluation_manifest")
    registry = require_json_object(bound_paths["verified_evidence_registry"], "step7_verified_evidence_registry")
    if manifest.get("schema") != EVALUATION_MANIFEST_V2_SCHEMA:
        raise Step68Error("step7_evaluation_manifest_schema_invalid")
    if registry.get("schema") != VERIFIED_EVIDENCE_REGISTRY_V1_SCHEMA:
        raise Step68Error("step7_verified_evidence_registry_schema_invalid")
    if manifest.get("corpus_sha256") != bindings.get("corpus_sha256"):
        raise Step68Error("step7_evaluation_manifest_corpus_sha256_mismatch")
    if registry.get("evaluation_manifest_sha256") != bindings.get("evaluation_manifest_sha256"):
        raise Step68Error("step7_registry_evaluation_manifest_sha256_mismatch")
    if registry.get("corpus_sha256") != bindings.get("corpus_sha256"):
        raise Step68Error("step7_registry_corpus_sha256_mismatch")
    if bindings.get("evaluation_id") != manifest.get("evaluation_id") or registry.get(
        "evaluation_id"
    ) != manifest.get("evaluation_id"):
        raise Step68Error("step7_score_evaluation_id_mismatch")

    results_path_raw = score_summary.get("results_jsonl")
    if not isinstance(results_path_raw, str):
        raise Step68Error("step7_results_jsonl_path_missing")
    results_path = require_under(Path(results_path_raw), remote_root, "step7_results_jsonl")
    if not results_path.is_file():
        raise Step68Error(f"step7_results_jsonl_missing:{results_path}")
    if score_summary.get("results_jsonl_sha256") != sha256_file(results_path):
        raise Step68Error("step7_results_jsonl_sha256_mismatch")

    report_path_raw = score_summary.get("score_report_json")
    if not isinstance(report_path_raw, str):
        raise Step68Error("step7_score_report_path_missing")
    report_path = require_under(Path(report_path_raw), remote_root, "step7_score_report")
    if not report_path.is_file():
        raise Step68Error(f"step7_score_report_missing:{report_path}")
    if score_summary.get("score_report_json_sha256") != sha256_file(report_path):
        raise Step68Error("step7_score_report_sha256_mismatch")
    report = require_json_object(report_path, "step7_score_report")
    score_inputs = {
        "evaluation_id": bindings.get("evaluation_id"),
        "digests": {digest_key: bindings.get(digest_key) for digest_key in path_digest_pairs.values()},
    }
    report_binding_failures = validate_v2_score_report_binding(report, score_inputs)
    if report_binding_failures:
        raise Step68Error(f"step7_score_report_binding_mismatch:{','.join(report_binding_failures)}")
    if score_summary.get("score_report") != report:
        raise Step68Error("step7_embedded_score_report_mismatch")
    return {
        "report": report,
        "results_path": results_path,
        "bound_paths": bound_paths,
        "evaluator_script": resolved_evaluator,
        "evaluator_script_sha256": score_summary.get("evaluator_script_sha256"),
        "results_sha256": score_summary.get("results_jsonl_sha256"),
    }


def validate_current_audited_results(
    safety_audit: dict[str, Any],
    results_path: Path,
    remote_root: Path,
    campaign_id: str,
) -> None:
    if safety_audit.get("schema") != f"{SCHEMA_PREFIX}.result_safety_audit.v1":
        raise Step68Error("step7_safety_audit_schema_invalid")
    audited_rows = safety_audit.get("results")
    if not isinstance(audited_rows, list):
        raise Step68Error("step7_safety_audit_results_invalid")
    try:
        snapshot_rows = read_jsonl(results_path)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Step68Error("step7_results_jsonl_invalid") from exc
    snapshot_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for row in snapshot_rows:
        if not isinstance(row, dict):
            raise Step68Error("step7_results_jsonl_row_invalid")
        key = (str(row.get("sample_id")), str(row.get("profile_id")))
        if key in snapshot_by_key:
            raise Step68Error(f"step7_results_jsonl_duplicate_sample_profile:{key[0]}:{key[1]}")
        snapshot_by_key[key] = row
    campaign_results = collect_results(
        remote_root,
        campaign_id,
        RUN_RESULT_V2_SCHEMA,
        include_standalone=False,
    )
    campaign_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for result in campaign_results:
        clean = {key: value for key, value in result.items() if not key.startswith("_")}
        key = (str(clean.get("sample_id")), str(clean.get("profile_id")))
        if key in campaign_by_key:
            raise Step68Error(f"current_campaign_duplicate_sample_profile:{key[0]}:{key[1]}")
        campaign_by_key[key] = clean
    if campaign_by_key != snapshot_by_key:
        raise Step68Error("step7_results_no_longer_match_current_campaign_references")
    if len(audited_rows) != len(snapshot_rows):
        raise Step68Error("step7_safety_audit_result_count_mismatch")

    current_results: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, str]] = set()
    for index, audited in enumerate(audited_rows):
        if not isinstance(audited, dict):
            raise Step68Error(f"step7_safety_audit_result_invalid:{index}")
        raw_path = audited.get("result_path")
        expected_digest = audited.get("result_sha256")
        if not isinstance(raw_path, str) or not valid_sha256(expected_digest):
            raise Step68Error(f"step7_safety_audit_result_binding_invalid:{index}")
        result_path = require_under(Path(raw_path), remote_root, "step7_audited_result")
        if not result_path.is_file():
            raise Step68Error(f"step7_audited_result_missing:{result_path}")
        actual_digest = sha256_file(result_path)
        if actual_digest != expected_digest:
            raise Step68Error(f"step7_audited_result_sha256_mismatch:{result_path}")
        result = require_json_object(result_path, "step7_audited_result")
        if result.get("schema") != RUN_RESULT_V2_SCHEMA:
            raise Step68Error(f"step7_audited_result_v2_required:{result_path}")
        key = (str(result.get("sample_id")), str(result.get("profile_id")))
        if key in seen_keys:
            raise Step68Error(f"step7_safety_audit_duplicate_sample_profile:{key[0]}:{key[1]}")
        seen_keys.add(key)
        if audited.get("sample_id") != key[0] or audited.get("profile_id") != key[1]:
            raise Step68Error(f"step7_safety_audit_sample_profile_mismatch:{result_path}")
        if snapshot_by_key.get(key) != result:
            raise Step68Error(f"step7_audited_result_snapshot_mismatch:{result_path}")
        result["_source_result_path"] = str(result_path)
        result["_source_result_sha256"] = actual_digest
        current_results.append(result)
    current_audit = audit_completed_results(current_results)
    if current_audit.get("valid") is not True:
        raise Step68Error("step7_safety_audit_no_longer_valid")


def snapshot_v2_claim_inputs(validated_score: dict[str, Any], final_dir: Path) -> dict[str, Any]:
    bound_paths = validated_score["bound_paths"]
    source_records = {
        "corpus": (
            bound_paths["corpus"],
            "corpus-manifest.jsonl",
            validated_score["report"].get("corpus_sha256"),
        ),
        "evaluation_manifest": (
            bound_paths["evaluation_manifest"],
            "evaluation-manifest.json",
            validated_score["report"].get("evaluation_manifest_sha256"),
        ),
        "verified_evidence_registry": (
            bound_paths["verified_evidence_registry"],
            "verified-evidence-registry.json",
            validated_score["report"].get("verified_evidence_registry_sha256"),
        ),
        "verified_evidence_public_key": (
            bound_paths["verified_evidence_public_key"],
            "verifier-public-key.pem",
            validated_score["report"].get("verified_evidence_public_key_sha256"),
        ),
        "verified_evidence_signature": (
            bound_paths["verified_evidence_signature"],
            "verified-evidence-registry.sig",
            validated_score["report"].get("verified_evidence_signature_sha256"),
        ),
        "results": (
            validated_score["results_path"],
            "run-results.jsonl",
            validated_score["results_sha256"],
        ),
        "evaluator_script": (
            validated_score["evaluator_script"],
            "mandatory-v2-scorer.py",
            validated_score["evaluator_script_sha256"],
        ),
    }
    snapshot_dir = Path(tempfile.mkdtemp(prefix="claim-inputs-", dir=final_dir))
    if snapshot_dir.is_symlink() or not stat.S_ISDIR(snapshot_dir.lstat().st_mode):
        raise Step68Error("step8_claim_inputs_fresh_directory_invalid")
    if snapshot_dir.resolve().parent != final_dir.resolve():
        raise Step68Error("step8_claim_inputs_fresh_directory_outside_final_dir")
    snapshots: dict[str, dict[str, Any]] = {}
    for key, (source_path, filename, expected_digest) in source_records.items():
        if not valid_sha256(expected_digest):
            raise Step68Error(f"step8_claim_input_{key}_expected_digest_invalid")
        if source_path.is_symlink() or not stat.S_ISREG(source_path.lstat().st_mode):
            raise Step68Error(f"step8_claim_input_{key}_source_not_regular")
        snapshot_path = snapshot_dir / filename
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            destination_fd = os.open(snapshot_path, flags, 0o600)
        except OSError as exc:
            raise Step68Error(f"step8_claim_input_{key}_exclusive_create_failed") from exc
        try:
            with source_path.open("rb") as source, os.fdopen(destination_fd, "wb") as destination:
                shutil.copyfileobj(source, destination)
        except Exception:
            snapshot_path.unlink(missing_ok=True)
            raise
        if snapshot_path.is_symlink() or not stat.S_ISREG(snapshot_path.lstat().st_mode):
            raise Step68Error(f"step8_claim_input_{key}_snapshot_not_regular")
        if snapshot_path.resolve().parent != snapshot_dir.resolve():
            raise Step68Error(f"step8_claim_input_{key}_snapshot_outside_fresh_directory")
        actual_digest = sha256_file(snapshot_path)
        if actual_digest != expected_digest:
            raise Step68Error(f"step8_claim_input_{key}_snapshot_sha256_mismatch")
        snapshots[key] = {
            "path": snapshot_path,
            "sha256": actual_digest,
        }
    return {
        "directory": snapshot_dir,
        "inputs": snapshots,
    }


def revalidate_v2_score(
    validated_score: dict[str, Any],
    final_dir: Path,
    timeout_seconds: int,
) -> dict[str, Any]:
    report_path = final_dir / "score-revalidation-report.json"
    report_path.unlink(missing_ok=True)
    bound_paths = validated_score["bound_paths"]
    command = [
        sys.executable,
        str(validated_score["evaluator_script"]),
        "score-results",
        "--corpus",
        str(bound_paths["corpus"]),
        "--results",
        str(validated_score["results_path"]),
        "--evaluation-manifest",
        str(bound_paths["evaluation_manifest"]),
        "--verified-evidence-registry",
        str(bound_paths["verified_evidence_registry"]),
        "--verified-evidence-public-key",
        str(bound_paths["verified_evidence_public_key"]),
        "--verified-evidence-signature",
        str(bound_paths["verified_evidence_signature"]),
        "--report-json",
        str(report_path),
    ]
    command_record = run_capture(
        command,
        final_dir / "score-revalidation.stdout",
        timeout_seconds,
    )
    if command_record.get("timed_out") is True or command_record.get("exit_code") not in {0, 20}:
        report_path.unlink(missing_ok=True)
        raise Step68Error("step8_v2_score_revalidation_command_failed")
    if not report_path.is_file():
        raise Step68Error("step8_v2_score_revalidation_report_missing")
    report = require_json_object(report_path, "step8_v2_score_revalidation_report")
    original_report = validated_score["report"]
    score_inputs = {
        "evaluation_id": original_report.get("evaluation_id"),
        "digests": {
            "corpus_sha256": original_report.get("corpus_sha256"),
            "evaluation_manifest_sha256": original_report.get("evaluation_manifest_sha256"),
            "verified_evidence_registry_sha256": original_report.get("verified_evidence_registry_sha256"),
            "verified_evidence_public_key_sha256": original_report.get("verified_evidence_public_key_sha256"),
            "verified_evidence_signature_sha256": original_report.get("verified_evidence_signature_sha256"),
        },
    }
    binding_failures = validate_v2_score_report_binding(report, score_inputs)
    if binding_failures:
        raise Step68Error(f"step8_v2_score_revalidation_binding_mismatch:{','.join(binding_failures)}")
    comparable_report = {key: value for key, value in report.items() if key != "created_at_utc"}
    comparable_original = {key: value for key, value in original_report.items() if key != "created_at_utc"}
    if comparable_report != comparable_original:
        raise Step68Error("step8_v2_score_revalidation_report_mismatch")
    expected_exit_code = 0 if report.get("passed") is True else 20
    if command_record.get("exit_code") != expected_exit_code:
        raise Step68Error("step8_v2_score_revalidation_exit_status_mismatch")
    quality_gates = report.get("quality_gates")
    foundational_quality_gates = (
        "manifest_valid",
        "verified_evidence_signature_valid",
        "verified_evidence_registry_valid",
        "results_valid",
        "exact_sample_profile_denominator",
        "no_zero_row_cohorts",
    )
    if (
        not isinstance(quality_gates, dict)
        or any(quality_gates.get(key) is not True for key in foundational_quality_gates)
        or report.get("validation_errors") != []
    ):
        raise Step68Error("step8_v2_score_revalidation_not_authentic")
    return {
        "report_path": str(report_path),
        "report_sha256": sha256_file(report_path),
        "report": report,
        "command": command_record,
    }


def finalize_bundle(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    require_safe_segment(args.campaign_id, "campaign_id")
    final_dir = ensure_directory_under(
        remote_root / "evidence" / "step8" / args.campaign_id,
        remote_root,
        "step8_final_dir",
    )
    seal_path = final_dir / "evidence-bundle-manifest.json"
    final_summary_path = final_dir / "step8-final-summary.json"
    claim_derivation_path = final_dir / "claim-derivation-input.json"
    # A finalization attempt invalidates stale canonical Step 8 outputs before doing any checks.
    # Command/audit diagnostics may remain, but neither is a final bundle.
    seal_path.unlink(missing_ok=True)
    final_summary_path.unlink(missing_ok=True)
    claim_derivation_path.unlink(missing_ok=True)
    score_summary_path = require_under(
        remote_root / "evidence" / "step7" / args.campaign_id / "step7-score-summary.json",
        remote_root,
        "step7_score_summary",
    )
    if not score_summary_path.is_file():
        raise Step68Error(f"missing_step7_score_summary:{score_summary_path}")
    score_summary = require_json_object(score_summary_path, "step7_score_summary")
    validated_score = validate_finalizable_v2_score_summary(
        score_summary,
        remote_root,
        stage_dir,
        args.campaign_id,
        args.evaluator_script,
        args.expected_evaluation_manifest_sha256,
        args.expected_verifier_public_key_sha256,
    )
    score_report = validated_score["report"]
    expected_score_hash = score_summary.get("result_safety_audit_sha256")
    safety_audit_path_raw = score_summary.get("result_safety_audit")
    if not isinstance(safety_audit_path_raw, str):
        raise Step68Error("step7_safety_audit_path_missing")
    safety_audit_path = require_under(Path(safety_audit_path_raw), remote_root, "step7_safety_audit")
    if not safety_audit_path.is_file():
        raise Step68Error(f"step7_safety_audit_missing:{safety_audit_path}")
    if expected_score_hash != sha256_file(safety_audit_path):
        raise Step68Error("step7_safety_audit_sha256_mismatch")
    safety_audit = require_json_object(safety_audit_path, "step7_safety_audit")
    if safety_audit.get("valid") is not True:
        raise Step68Error("step7_safety_audit_not_valid")
    if score_summary.get("safety_audit_valid") is not True:
        raise Step68Error("step7_safety_audit_not_valid")
    validate_current_audited_results(
        safety_audit,
        validated_score["results_path"],
        remote_root,
        args.campaign_id,
    )
    claim_input_snapshot = snapshot_v2_claim_inputs(validated_score, final_dir)
    snapshot_validated_score = dict(validated_score)
    snapshot_validated_score["bound_paths"] = {
        key: claim_input_snapshot["inputs"][key]["path"]
        for key in (
            "corpus",
            "evaluation_manifest",
            "verified_evidence_registry",
            "verified_evidence_public_key",
            "verified_evidence_signature",
        )
    }
    snapshot_validated_score["results_path"] = claim_input_snapshot["inputs"]["results"]["path"]
    snapshot_validated_score["evaluator_script"] = claim_input_snapshot["inputs"]["evaluator_script"]["path"]
    score_revalidation = revalidate_v2_score(
        snapshot_validated_score,
        final_dir,
        args.timeout_seconds,
    )
    score_report = score_revalidation["report"]
    score_command_exit = score_summary.get("score_command", {}).get("exit_code")
    score_report_passed = score_report.get("passed") is True
    expected_score_command_exit = 0 if score_report_passed else 20
    if score_command_exit != expected_score_command_exit:
        raise Step68Error("step7_score_command_exit_mismatch")
    if score_summary.get("score_report_passed") != score_report_passed:
        raise Step68Error("step7_score_report_passed_summary_mismatch")
    campaign_gate_passed = score_report_passed and safety_audit.get("valid") is True
    if score_summary.get("campaign_gate_passed") != campaign_gate_passed:
        raise Step68Error("step7_campaign_gate_passed_summary_mismatch")
    if score_summary.get("score_passed") != campaign_gate_passed:
        raise Step68Error("step7_score_passed_summary_mismatch")
    if not campaign_gate_passed and not args.finalize_failed_score:
        if score_command_exit != 0:
            raise Step68Error("step7_score_command_failed")
        raise Step68Error("step7_score_report_not_passed")
    claim_derivation = {
        "schema": f"{SCHEMA_PREFIX}.claim_derivation_input.v1",
        "created_at_utc": now_utc(),
        "campaign_id": args.campaign_id,
        "derived_campaign_gate_passed": campaign_gate_passed,
        "failed_score_evidence_bundle_requested": not campaign_gate_passed,
        "score_revalidation_report": score_revalidation["report_path"],
        "score_revalidation_report_sha256": score_revalidation["report_sha256"],
        "claim_input_snapshot": {
            key: {"path": str(value["path"]), "sha256": value["sha256"]}
            for key, value in claim_input_snapshot["inputs"].items()
        },
        "evaluation_manifest": str(claim_input_snapshot["inputs"]["evaluation_manifest"]["path"]),
        "evaluation_manifest_sha256": score_report.get("evaluation_manifest_sha256"),
        "verified_evidence_registry": str(claim_input_snapshot["inputs"]["verified_evidence_registry"]["path"]),
        "verified_evidence_registry_sha256": score_report.get("verified_evidence_registry_sha256"),
        "verified_evidence_public_key": str(claim_input_snapshot["inputs"]["verified_evidence_public_key"]["path"]),
        "verified_evidence_public_key_sha256": score_report.get("verified_evidence_public_key_sha256"),
        "verified_evidence_signature": str(claim_input_snapshot["inputs"]["verified_evidence_signature"]["path"]),
        "verified_evidence_signature_sha256": score_report.get("verified_evidence_signature_sha256"),
        "run_results": str(claim_input_snapshot["inputs"]["results"]["path"]),
        "run_results_sha256": claim_input_snapshot["inputs"]["results"]["sha256"],
        "mandatory_v2_scorer": str(claim_input_snapshot["inputs"]["evaluator_script"]["path"]),
        "mandatory_v2_scorer_sha256": claim_input_snapshot["inputs"]["evaluator_script"]["sha256"],
        "operator_expected_evaluation_manifest_sha256": args.expected_evaluation_manifest_sha256,
        "operator_expected_verifier_public_key_sha256": args.expected_verifier_public_key_sha256,
        "authoritative_finalization_record": "not_generated",
        "independent_finalization_signature": "not_generated",
        "claim_authority": "none_derive_by_rerunning_mandatory_v2",
        "claim_boundary": (
            "This sealed record indexes the inputs and the locally rederived gate. It does not authorize a "
            "claim. A consumer must rerun the pinned mandatory-v2 scorer and verify the signed registry."
        ),
    }
    write_json(claim_derivation_path, claim_derivation)
    forbidden_files = forbidden_evidence_files(remote_root / "evidence")
    if forbidden_files:
        raise Step68Error(f"forbidden_restricted_material_in_evidence:{','.join(forbidden_files[:20])}")
    evidence_symlinks = sorted(
        path.relative_to(remote_root / "evidence").as_posix()
        for path in (remote_root / "evidence").rglob("*")
        if path.is_symlink()
    )
    if evidence_symlinks:
        raise Step68Error(f"symlink_in_evidence:{','.join(evidence_symlinks[:20])}")
    command = [
        sys.executable,
        str(validated_score["evaluator_script"]),
        "seal-evidence",
        "--evidence-dir",
        str(remote_root / "evidence"),
        "--out",
        str(seal_path),
    ]
    seal_record = run_capture(command, final_dir / "seal-evidence.stdout", args.timeout_seconds)
    if seal_record.get("timed_out") is True or seal_record.get("exit_code") != 0 or not seal_path.is_file():
        seal_path.unlink(missing_ok=True)
        final_summary_path.unlink(missing_ok=True)
        raise Step68Error("step8_evidence_seal_failed")
    seal_manifest = require_json_object(seal_path, "step8_evidence_bundle_manifest")
    if seal_manifest.get("schema") != "whoathere.actual_malware.evidence_bundle_manifest.v1":
        seal_path.unlink(missing_ok=True)
        raise Step68Error("step8_evidence_bundle_manifest_schema_invalid")
    if seal_manifest.get("evidence_dir") != str(remote_root / "evidence"):
        seal_path.unlink(missing_ok=True)
        raise Step68Error("step8_evidence_bundle_manifest_root_mismatch")
    if not valid_sha256(seal_manifest.get("bundle_sha256")):
        seal_path.unlink(missing_ok=True)
        raise Step68Error("step8_evidence_bundle_manifest_digest_invalid")
    sealed_files = {
        item.get("path"): item.get("sha256")
        for item in seal_manifest.get("files", [])
        if isinstance(item, dict)
    }
    claim_derivation_rel = claim_derivation_path.relative_to(remote_root / "evidence").as_posix()
    if sealed_files.get(claim_derivation_rel) != sha256_file(claim_derivation_path):
        seal_path.unlink(missing_ok=True)
        raise Step68Error("step8_claim_derivation_input_not_sealed")
    revalidation_path = Path(score_revalidation["report_path"])
    revalidation_rel = revalidation_path.relative_to(remote_root / "evidence").as_posix()
    if sealed_files.get(revalidation_rel) != score_revalidation["report_sha256"]:
        seal_path.unlink(missing_ok=True)
        raise Step68Error("step8_score_revalidation_report_not_sealed")
    for key, snapshot in claim_input_snapshot["inputs"].items():
        snapshot_rel = snapshot["path"].relative_to(remote_root / "evidence").as_posix()
        if sealed_files.get(snapshot_rel) != snapshot["sha256"]:
            seal_path.unlink(missing_ok=True)
            raise Step68Error(f"step8_claim_input_{key}_not_sealed")
    seal_manifest_sha256 = sha256_file(seal_path)
    final_summary = {
        "schema": f"{SCHEMA_PREFIX}.final_bundle.v2",
        "created_at_utc": now_utc(),
        "campaign_id": args.campaign_id,
        "stage_dir": str(stage_dir),
        "stage_corpus_sha256": sha256_file(stage_dir / "metadata" / "corpus_manifest.jsonl"),
        "evidence_root": str(remote_root / "evidence"),
        "evidence_bundle_manifest": str(seal_path),
        "evidence_bundle_manifest_sha256": seal_manifest_sha256,
        "evidence_bundle_sha256": seal_manifest.get("bundle_sha256"),
        "seal_command": seal_record,
        "claim_derivation_input": str(claim_derivation_path),
        "claim_derivation_input_sha256": sha256_file(claim_derivation_path),
        "score_revalidation_report": score_revalidation["report_path"],
        "score_revalidation_report_sha256": score_revalidation["report_sha256"],
        "score_summary_path": str(score_summary_path),
        "score_summary_sha256": sha256_file(score_summary_path),
        "authoritative_finalization_record": "not_generated",
        "independent_finalization_signature": "not_generated",
        "claim_authority": "none_post_seal_index_is_non_authoritative",
        "required_claim_verification": (
            "Rerun the pinned mandatory-v2 scorer over the indexed manifest, RunResultV2 rows, signed "
            "registry, pinned public key, and detached signature. Reject added claim booleans in this index."
        ),
        "forbidden_material_check": {
            "checked_root": str(remote_root / "evidence"),
            "forbidden_file_count": len(forbidden_files),
            "forbidden_files": forbidden_files,
        },
        "restricted_evidence_boundary": (
            "This final summary binds the sanitized evidence manifest written immediately before it. "
            "The final summary is intentionally not a member of that manifest, avoiding a self-reference. "
            "Raw samples, unpacked workspaces, VM disks, and unrestricted packet captures remain restricted."
        ),
    }
    write_json(final_summary_path, final_summary)
    returned_summary = dict(final_summary)
    returned_summary["final_summary_path"] = str(final_summary_path)
    returned_summary["final_summary_sha256"] = sha256_file(final_summary_path)
    print(json.dumps(returned_summary, indent=2, sort_keys=True))
    return returned_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-root", type=Path, required=True)
    parser.add_argument("--stage-dir", type=Path)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--whoathere-bin", type=Path, required=True)
    parser.add_argument("--evaluator-script", type=Path, required=True)
    parser.add_argument("--step5-script", type=Path, required=True)
    parser.add_argument(
        "--execution-path",
        choices=[LEGACY_EXECUTION_PATH, EXACT_ARTIFACT_EXECUTION_PATH],
    )
    parser.add_argument("--campaign-id", default="whoathere-actual-malware-2026-07-01")
    parser.add_argument("--clearance-id")
    parser.add_argument("--clearance-method", default="host_rebuild_or_lab_runbook_clearance")
    parser.add_argument("--clearance-reviewer", default="operator-asserted")
    parser.add_argument("--slice-id")
    parser.add_argument("--sample-id", action="append", default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--max-samples-per-clearance", type=int, default=1)
    parser.add_argument("--include-existing-samples", action="store_true")
    parser.add_argument("--include-standalone-step5-results", action="store_true")
    parser.add_argument("--evaluation-manifest", type=Path)
    parser.add_argument("--verified-evidence-registry", type=Path)
    parser.add_argument("--verified-evidence-public-key", type=Path)
    parser.add_argument("--verified-evidence-signature", type=Path)
    parser.add_argument("--expected-evaluation-manifest-sha256")
    parser.add_argument("--expected-verifier-public-key-sha256")
    parser.add_argument("--legacy-non-claim-bearing-score-maintenance", action="store_true")
    parser.add_argument("--acknowledge-non-claim-bearing-legacy-score", action="store_true")
    parser.add_argument("--clearance-record", type=Path)
    parser.add_argument("--provider-approval-ref", default="")
    parser.add_argument("--legal-provider-approval-ref", default="")
    parser.add_argument("--cloud-firewall-default-deny-asserted", action="store_true")
    parser.add_argument("--host-firewall-default-deny-asserted", action="store_true")
    parser.add_argument("--previous-contamination-resolved-asserted", action="store_true")
    parser.add_argument("--host-rebuilt-or-cleared-asserted", action="store_true")
    parser.add_argument("--vm-state-rebuilt-or-pruned-asserted", action="store_true")
    parser.add_argument("--sinkhole-ready-asserted", action="store_true")
    parser.add_argument("--egress-deny-asserted", action="store_true")
    parser.add_argument("--sinkhole-reference", default="")
    parser.add_argument("--lulu-enabled-asserted", action="store_true")
    parser.add_argument("--lulu-reference", default="")
    parser.add_argument("--live-malware-execution-approved", action="store_true")
    parser.add_argument("--detonation-config", type=Path)
    parser.add_argument("--detonation-config-sha256")
    parser.add_argument("--codex-client-path", type=Path)
    parser.add_argument("--codex-client-sha256")
    parser.add_argument("--codex-model")
    parser.add_argument("--codex-auth-home", type=Path)
    parser.add_argument("--codex-timeout-seconds", type=int, default=300)
    parser.add_argument("--restricted-source-hosted-review-approved", action="store_true")
    parser.add_argument("--restricted-source-review-approval-ref", default="")
    parser.add_argument("--restricted-behavior-hosted-review-approved", action="store_true")
    parser.add_argument("--restricted-behavior-review-approval-ref", default="")
    parser.add_argument("--split-local-behavior-finalization", action="store_true")
    parser.add_argument("--finalize-failed-score", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--run-timeout-seconds", type=int, default=900)
    parser.add_argument("--phase", choices=["clearance", "slice", "score", "finalize", "all"], default="score")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.phase == "all":
            raise Step68Error(
                "phase_all_incompatible_with_post_run_independent_evidence_verification_use_separate_phases"
            )
        if args.legacy_non_claim_bearing_score_maintenance and args.phase != "score":
            raise Step68Error("legacy_score_maintenance_only_supported_for_score_phase")
        if args.acknowledge_non_claim_bearing_legacy_score and not args.legacy_non_claim_bearing_score_maintenance:
            raise Step68Error("legacy_score_acknowledgement_requires_legacy_maintenance_mode")
        if args.legacy_non_claim_bearing_score_maintenance and any(
            value is not None
            for value in (
                args.evaluation_manifest,
                args.verified_evidence_registry,
                args.verified_evidence_public_key,
                args.verified_evidence_signature,
                args.expected_evaluation_manifest_sha256,
                args.expected_verifier_public_key_sha256,
            )
        ):
            raise Step68Error("legacy_score_maintenance_rejects_v2_evidence_inputs")
        if (
            args.phase == "score"
            and not args.legacy_non_claim_bearing_score_maintenance
            and args.include_standalone_step5_results
        ):
            raise Step68Error("claim_bearing_v2_score_rejects_standalone_step5_results")
        if args.limit is not None and args.limit <= 0:
            raise Step68Error("limit_must_be_positive")
        if args.max_samples_per_clearance <= 0:
            raise Step68Error("max_samples_per_clearance_must_be_positive")
        if args.phase in {"clearance", "all"}:
            validate_clearance_execution_args(args)
        if args.phase in {"slice", "all"}:
            validate_slice_execution_args(args)
        if args.phase in {"clearance", "slice", "all"}:
            missing = [
                name
                for name, value in [
                    ("provider_approval_ref", args.provider_approval_ref),
                    ("legal_provider_approval_ref", args.legal_provider_approval_ref),
                    ("cloud_firewall_default_deny_asserted", args.cloud_firewall_default_deny_asserted),
                    ("host_firewall_default_deny_asserted", args.host_firewall_default_deny_asserted),
                    ("lulu_enabled_asserted", args.lulu_enabled_asserted),
                ]
                if not value
            ]
            if args.phase in {"slice", "all"} and not args.live_malware_execution_approved:
                missing.append("live_malware_execution_approved")
            if missing:
                raise Step68Error(f"{args.phase}_missing_required_assertions:{','.join(missing)}")
            if not (args.sinkhole_ready_asserted or args.egress_deny_asserted):
                raise Step68Error(f"{args.phase}_requires_sinkhole_ready_or_egress_deny_assertion")
            if args.sinkhole_ready_asserted and not args.sinkhole_reference:
                raise Step68Error("sinkhole_reference_required_when_sinkhole_ready_asserted")
        remote_root = args.remote_root.expanduser().resolve()
        if not remote_root.is_dir():
            raise Step68Error(f"remote_root_missing:{remote_root}")
        stage_dir = args.stage_dir.expanduser().resolve() if args.stage_dir else latest_stage(remote_root)
        require_under(stage_dir, remote_root, "stage_dir")
        if not args.evaluator_script.is_file():
            raise Step68Error(f"missing_evaluator_script:{args.evaluator_script}")
        if not args.step5_script.is_file():
            raise Step68Error(f"missing_step5_script:{args.step5_script}")

        result: dict[str, Any] = {
            "schema": f"{SCHEMA_PREFIX}.run.v1",
            "created_at_utc": now_utc(),
            "phase": args.phase,
            "campaign_id": args.campaign_id,
        }
        if args.phase in {"clearance", "all"}:
            result["clearance"] = build_clearance_record(remote_root, stage_dir, args)
            if result["clearance"].get("ready_for_live_malware") is not True:
                return 20
            if args.phase == "all" and args.clearance_record is None:
                args.clearance_record = Path(result["clearance"]["path"])
        if args.phase in {"slice", "all"}:
            result["slice"] = run_campaign_slice(remote_root, stage_dir, args)
            if result["slice"].get("safety_passed") is not True:
                write_json(remote_root / "evidence" / "step6" / args.campaign_id / "last-run-failed.json", result)
                return 20
            if (
                args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH
                and (
                    result["slice"].get("physical_pending_gate_passed") is not True
                    if args.split_local_behavior_finalization
                    else result["slice"].get("diagnostic_gate_passed") is not True
                )
            ):
                write_json(remote_root / "evidence" / "step6" / args.campaign_id / "last-run-failed.json", result)
                return 20
        if args.phase in {"score", "all"}:
            result["score"] = score_campaign(remote_root, stage_dir, args)
            if result["score"].get("score_passed") is not True:
                return 20
        if args.phase in {"finalize", "all"}:
            result["final"] = finalize_bundle(remote_root, stage_dir, args)
        return 0
    except Step68Error as exc:
        print(f"steps6_8_error={exc}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
