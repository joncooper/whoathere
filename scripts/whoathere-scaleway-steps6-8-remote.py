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
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


SCHEMA_PREFIX = "whoathere.actual_malware.scaleway_steps6_8"


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


def require_under(path: Path, root: Path, label: str) -> Path:
    resolved_path = path.expanduser().resolve()
    resolved_root = root.expanduser().resolve()
    if resolved_path != resolved_root and resolved_root not in resolved_path.parents:
        raise Step68Error(f"{label}_outside_remote_root:{resolved_path}")
    return resolved_path


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
    for result_path in sorted((remote_root / "evidence" / "step5").glob("*/*/whoathere-run/run_result.json")):
        try:
            result = read_json(result_path)
        except Exception:
            continue
        summary_path = result_path.parents[1] / "step5-summary.json"
        step5_summary = read_json(summary_path) if summary_path.is_file() else {}
        evidence_failures: list[str] = []
        if not summary_path.is_file():
            evidence_failures.append("step5_summary_missing")
        if not step5_summary.get("host_contamination_status"):
            evidence_failures.append("host_contamination_status_missing")
        if not step5_summary.get("vm_state_status"):
            evidence_failures.append("vm_state_status_missing")
        runs.append(
            {
                "sample_id": result.get("sample_id"),
                "result_path": str(result_path),
                "result_sha256": sha256_file(result_path),
                "run_dir": str(result_path.parents[1]),
                "created_at_utc": result.get("created_at_utc") or step5_summary.get("created_at_utc"),
                "verdict_class": result.get("verdict_class"),
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
    command = [
        sys.executable,
        str(args.evaluator_script),
        "preflight-lab",
        "--whoathere-bin",
        str(args.whoathere_bin),
        "--state-dir",
        str(args.state_dir),
        "--out",
        str(clearance_dir / "preflight.json"),
        "--timeout-seconds",
        str(args.timeout_seconds),
    ]
    preflight_record = run_capture(command, clearance_dir / "preflight-lab.stdout", args.timeout_seconds + 60)
    preflight = read_json(clearance_dir / "preflight.json") if (clearance_dir / "preflight.json").is_file() else {}
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
            "path": str(clearance_dir / "preflight.json"),
            "sha256": sha256_file(clearance_dir / "preflight.json") if (clearance_dir / "preflight.json").is_file() else None,
            "command": preflight_record,
        },
        "direct_commands": direct_commands,
        "blockers": blockers,
        "notes": [
            "This clearance phase does not unpack MalwareBazaar ZIPs and does not execute malware.",
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


def run_campaign_slice(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    require_safe_segment(args.campaign_id, "campaign_id")
    runs_before = existing_successful_live_runs(remote_root)
    clearance = validate_clearance(remote_root, args, runs_before)
    selected = eligible_matrix_samples(stage_dir, args.sample_id, args.include_existing_samples, remote_root)
    if args.limit is not None:
        selected = selected[: args.limit]
    if not selected:
        raise Step68Error("no_step6_samples_selected")
    if len(selected) > args.max_samples_per_clearance:
        raise Step68Error(f"selected_sample_count_exceeds_clearance_limit:{len(selected)}>{args.max_samples_per_clearance}")
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
        if args.sinkhole_ready_asserted:
            command.extend(["--sinkhole-ready-asserted", "--sinkhole-reference", args.sinkhole_reference])
        if args.egress_deny_asserted:
            command.append("--egress-deny-asserted")
        if args.lulu_reference:
            command.extend(["--lulu-reference", args.lulu_reference])
        run_record = run_capture(command, slice_dir / f"{sample_id}.step5.stdout", args.run_timeout_seconds)
        result_path = remote_root / "evidence" / "step5" / sample_id / run_id / "whoathere-run" / "run_result.json"
        summary_path = remote_root / "evidence" / "step5" / sample_id / run_id / "step5-summary.json"
        result = read_json(result_path) if result_path.is_file() else {}
        summary = read_json(summary_path) if summary_path.is_file() else {}
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
                "safety_passed": summary.get("safety_passed"),
                "safety_failures": summary.get("safety_failures"),
            }
        )
        if run_record["exit_code"] != 0:
            break

    unsafe = [
        run
        for run in sample_runs
        if run["command"]["exit_code"] != 0 or run.get("safety_passed") is not True or run.get("verdict_class") in {"miss", "unsafe_allow"}
    ]
    slice_summary = {
        "schema": f"{SCHEMA_PREFIX}.campaign_slice.v1",
        "created_at_utc": now_utc(),
        "campaign_id": args.campaign_id,
        "slice_id": slice_id,
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
        "stop_required_before_next_live_sample": True,
        "host_contamination_status": "contaminated_rebuild_or_clear_before_next_live_run",
        "vm_state_status": "suspend_requested_rebuild_or_prune_before_next_live_run",
        "unsafe_or_failed_runs": unsafe,
    }
    write_json(slice_dir / "step6-slice-summary.json", slice_summary)
    print(json.dumps(slice_summary, indent=2, sort_keys=True))
    return slice_summary


def collect_results(remote_root: Path, campaign_id: str, include_standalone: bool = False) -> list[dict[str, Any]]:
    result_paths: list[Path] = []
    for slice_summary_path in sorted((remote_root / "evidence" / "step6" / campaign_id).glob("*/step6-slice-summary.json")):
        try:
            slice_summary = read_json(slice_summary_path)
        except Exception:
            continue
        for sample_run in slice_summary.get("sample_runs", []):
            if not isinstance(sample_run, dict) or not isinstance(sample_run.get("result_path"), str):
                continue
            result_paths.append(require_under(Path(sample_run["result_path"]), remote_root, "campaign_result"))
    if include_standalone:
        result_paths.extend(sorted((remote_root / "evidence" / "step5").glob("*/*/whoathere-run/run_result.json")))
    deduped: list[Path] = []
    seen: set[str] = set()
    for path in result_paths:
        resolved = str(path.resolve())
        if resolved not in seen:
            seen.add(resolved)
            deduped.append(path)
    results: list[dict[str, Any]] = []
    for path in deduped:
        try:
            result = read_json(path)
        except Exception:
            continue
        summary_path = path.parents[1] / "step5-summary.json"
        step5_summary = read_json(summary_path) if summary_path.is_file() else {}
        for key in ("live_c2_allowed", "second_stage_live_fetch_allowed", "sync_back_allowed"):
            if key not in result and key in step5_summary:
                result[key] = step5_summary[key]
        result["_source_result_path"] = str(path)
        result["_source_result_sha256"] = sha256_file(path)
        results.append(result)
    if not results:
        raise Step68Error("no_run_results_found_for_scoring")
    return results


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
        elif seal.get("bundle_sha256") is None:
            item_failures.append("per_run_seal_bundle_hash_missing")
        elif summary_path.is_file():
            sealed_files = {
                item.get("path"): item.get("sha256")
                for item in seal.get("files", [])
                if isinstance(item, dict)
            }
            if sealed_files.get("step5-summary.json") != sha256_file(summary_path):
                item_failures.append("per_run_seal_summary_hash_stale")
        seal_created_at = parse_utc(seal.get("created_at_utc"))
        summary_created_at = parse_utc(summary.get("created_at_utc"))
        if seal_created_at and summary_created_at and seal_created_at < summary_created_at:
            item_failures.append("per_run_seal_older_than_summary")
        if item_failures:
            failures.append(f"{result.get('sample_id')}:{','.join(item_failures)}")
        audited.append(
            {
                "sample_id": result.get("sample_id"),
                "result_path": str(result_path),
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
    score_dir = remote_root / "evidence" / "step7" / args.campaign_id
    score_dir.mkdir(parents=True, exist_ok=True)
    results = collect_results(remote_root, args.campaign_id, args.include_standalone_step5_results)
    results_jsonl = score_dir / "run_result.jsonl"
    with results_jsonl.open("w", encoding="utf-8") as handle:
        for result in results:
            clean = {key: value for key, value in result.items() if not key.startswith("_")}
            handle.write(json.dumps(clean, sort_keys=True) + "\n")
    report_json = score_dir / "score-report.json"
    report_md = score_dir / "score-report.md"
    safety_audit = audit_completed_results(results)
    safety_audit_path = score_dir / "result-safety-audit.json"
    write_json(safety_audit_path, safety_audit)
    command = [
        sys.executable,
        str(args.evaluator_script),
        "score-results",
        "--corpus",
        str(stage_dir / "metadata" / "corpus_manifest.jsonl"),
        "--results",
        str(results_jsonl),
        "--report-json",
        str(report_json),
        "--report-md",
        str(report_md),
    ]
    score_record = run_capture(command, score_dir / "score-results.stdout", args.timeout_seconds)
    report = read_json(report_json) if report_json.is_file() else {}
    score_summary = {
        "schema": f"{SCHEMA_PREFIX}.score_summary.v1",
        "created_at_utc": now_utc(),
        "campaign_id": args.campaign_id,
        "result_count": len(results),
        "results_jsonl": str(results_jsonl),
        "results_jsonl_sha256": sha256_file(results_jsonl),
        "score_report_json": str(report_json),
        "score_report_json_sha256": sha256_file(report_json) if report_json.is_file() else None,
        "score_report_md": str(report_md),
        "score_report_md_sha256": sha256_file(report_md) if report_md.is_file() else None,
        "result_safety_audit": str(safety_audit_path),
        "result_safety_audit_sha256": sha256_file(safety_audit_path),
        "score_command": score_record,
        "score_report": report,
        "safety_audit_valid": safety_audit["valid"],
        "score_passed": report.get("passed") is True and score_record.get("exit_code") == 0,
        "claim_boundary": "Score includes completed run_result.json files only; missing campaign samples are not counted.",
    }
    write_json(score_dir / "step7-score-summary.json", score_summary)
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


def finalize_bundle(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    require_safe_segment(args.campaign_id, "campaign_id")
    final_dir = remote_root / "evidence" / "step8" / args.campaign_id
    final_dir.mkdir(parents=True, exist_ok=True)
    forbidden_files = forbidden_evidence_files(remote_root / "evidence")
    if forbidden_files:
        raise Step68Error(f"forbidden_restricted_material_in_evidence:{','.join(forbidden_files[:20])}")
    score_summary_path = remote_root / "evidence" / "step7" / args.campaign_id / "step7-score-summary.json"
    if not score_summary_path.is_file():
        raise Step68Error(f"missing_step7_score_summary:{score_summary_path}")
    score_summary = read_json(score_summary_path)
    expected_score_hash = score_summary.get("result_safety_audit_sha256")
    safety_audit_path_raw = score_summary.get("result_safety_audit")
    if not isinstance(safety_audit_path_raw, str):
        raise Step68Error("step7_safety_audit_path_missing")
    safety_audit_path = require_under(Path(safety_audit_path_raw), remote_root, "step7_safety_audit")
    if not safety_audit_path.is_file():
        raise Step68Error(f"step7_safety_audit_missing:{safety_audit_path}")
    if expected_score_hash != sha256_file(safety_audit_path):
        raise Step68Error("step7_safety_audit_sha256_mismatch")
    safety_audit = read_json(safety_audit_path)
    if safety_audit.get("valid") is not True:
        raise Step68Error("step7_safety_audit_not_valid")
    if score_summary.get("safety_audit_valid") is not True:
        raise Step68Error("step7_safety_audit_not_valid")
    score_command_exit = score_summary.get("score_command", {}).get("exit_code")
    score_report_passed = score_summary.get("score_report", {}).get("passed") is True
    score_gate_passed = score_command_exit == 0 and score_report_passed
    if not score_gate_passed and not args.finalize_failed_score:
        if score_command_exit != 0:
            raise Step68Error("step7_score_command_failed")
        raise Step68Error("step7_score_report_not_passed")
    seal_path = final_dir / "evidence-bundle-manifest.json"
    final_summary = {
        "schema": f"{SCHEMA_PREFIX}.final_bundle.v1",
        "created_at_utc": now_utc(),
        "campaign_id": args.campaign_id,
        "stage_dir": str(stage_dir),
        "stage_corpus_sha256": sha256_file(stage_dir / "metadata" / "corpus_manifest.jsonl"),
        "evidence_root": str(remote_root / "evidence"),
        "evidence_bundle_manifest": str(seal_path),
        "score_summary_path": str(score_summary_path),
        "score_summary_sha256": sha256_file(score_summary_path),
        "score_summary": score_summary,
        "score_gate_passed": score_gate_passed,
        "finalized_failed_score": not score_gate_passed,
        "forbidden_material_check": {
            "checked_root": str(remote_root / "evidence"),
            "forbidden_file_count": len(forbidden_files),
            "forbidden_files": forbidden_files,
        },
        "restricted_evidence_boundary": (
            "This final bundle is a sanitized evidence manifest. Raw samples, unpacked workspaces, "
            "VM disks, and unrestricted packet captures remain restricted evidence outside the normal bundle."
        ),
    }
    final_summary_path = final_dir / "step8-final-summary.json"
    write_json(final_summary_path, final_summary)
    command = [
        sys.executable,
        str(args.evaluator_script),
        "seal-evidence",
        "--evidence-dir",
        str(remote_root / "evidence"),
        "--out",
        str(seal_path),
    ]
    seal_record = run_capture(command, final_dir / "seal-evidence.stdout", args.timeout_seconds)
    returned_summary = dict(final_summary)
    returned_summary["final_summary_path"] = str(final_summary_path)
    returned_summary["final_summary_sha256"] = sha256_file(final_summary_path)
    returned_summary["evidence_bundle_manifest_sha256"] = sha256_file(seal_path) if seal_path.is_file() else None
    returned_summary["seal_command"] = seal_record
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
    parser.add_argument("--finalize-failed-score", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    parser.add_argument("--run-timeout-seconds", type=int, default=900)
    parser.add_argument("--phase", choices=["clearance", "slice", "score", "finalize", "all"], default="score")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        if args.limit is not None and args.limit <= 0:
            raise Step68Error("limit_must_be_positive")
        if args.max_samples_per_clearance <= 0:
            raise Step68Error("max_samples_per_clearance_must_be_positive")
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
        if args.phase in {"score", "all"}:
            result["score"] = score_campaign(remote_root, stage_dir, args)
        if args.phase in {"finalize", "all"}:
            result["final"] = finalize_bundle(remote_root, stage_dir, args)
        return 0
    except Step68Error as exc:
        print(f"steps6_8_error={exc}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
