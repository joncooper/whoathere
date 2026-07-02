#!/usr/bin/env python3
"""Remote Step 5 single-malware rehearsal harness for WhoaThere.

Runs only on the disposable Scaleway Mac. It verifies live-run guardrail assertions, prepares one
approved MalwareBazaar package artifact into a remote lab workspace, executes it only through
WhoaThere's VM-backed no-sync path, suspends the VM, and seals sanitized evidence.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
import posixpath
import shutil
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any


SCHEMA_PREFIX = "whoathere.actual_malware.scaleway_step5"
MB_ZIP_PASSWORD = b"infected"


class Step5Error(Exception):
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
        raise Step5Error(f"{label}_outside_remote_root:{resolved_path}")
    return resolved_path


def safe_member_path(name: str) -> str:
    normalized = posixpath.normpath(name)
    parts = normalized.split("/")
    if name.startswith("/") or normalized.startswith("../") or "/../" in normalized or "" in parts:
        raise Step5Error(f"unsafe_archive_member_path:{name}")
    if normalized in {".", ".."}:
        raise Step5Error(f"unsafe_archive_member_path:{name}")
    return normalized


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


def latest_stage(remote_root: Path) -> Path:
    staged_root = remote_root / "staged"
    candidates = sorted(item for item in staged_root.iterdir() if item.is_dir() and item.name.startswith("stage-"))
    if not candidates:
        raise Step5Error(f"no_stage_dirs_found:{staged_root}")
    return candidates[-1]


def load_stage(stage_dir: Path) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, str]]]:
    manifest_path = stage_dir / "metadata" / "staging-manifest.json"
    corpus_path = stage_dir / "metadata" / "corpus_manifest.jsonl"
    matrix_path = stage_dir / "metadata" / "run_matrix.todo.csv"
    if not manifest_path.is_file():
        raise Step5Error(f"missing_staging_manifest:{manifest_path}")
    if not corpus_path.is_file():
        raise Step5Error(f"missing_corpus_manifest:{corpus_path}")
    if not matrix_path.is_file():
        raise Step5Error(f"missing_run_matrix:{matrix_path}")
    with matrix_path.open(newline="", encoding="utf-8") as handle:
        matrix = list(csv.DictReader(handle))
    return read_json(manifest_path), read_jsonl(corpus_path), matrix


def sample_and_matrix(stage_dir: Path, sample_id: str) -> tuple[dict[str, Any], dict[str, str]]:
    _, corpus, matrix = load_stage(stage_dir)
    sample = next((row for row in corpus if row.get("sample_id") == sample_id), None)
    if sample is None:
        raise Step5Error(f"unknown_sample_id:{sample_id}")
    matrix_row = next((row for row in matrix if row.get("sample_id") == sample_id), None)
    if matrix_row is None:
        raise Step5Error(f"sample_not_in_primary_run_matrix:{sample_id}")
    return sample, matrix_row


def validate_sample_for_step5(sample: dict[str, Any]) -> None:
    if sample.get("sample_kind") != "malware":
        raise Step5Error("step5_sample_must_be_malware")
    if sample.get("expected_result") != "malicious":
        raise Step5Error("step5_sample_expected_result_must_be_malicious")
    if sample.get("execution_eligible_initial_package_run") is not True:
        raise Step5Error("sample_not_execution_eligible_initial_package_run")
    for key in ("live_c2_allowed", "second_stage_live_fetch_allowed", "sync_back_allowed"):
        if sample.get(key) is not False:
            raise Step5Error(f"sample_{key}_must_be_false")
    if sample.get("network_policy") != "sinkhole_only":
        raise Step5Error("sample_network_policy_must_be_sinkhole_only")
    approvals = sample.get("approvals", {})
    if approvals.get("two_person_approval") is not True or approvals.get("legal_provider_approval") is not True:
        raise Step5Error("sample_approval_fields_not_ready")


def step5_paths(remote_root: Path, sample_id: str, run_id: str) -> dict[str, Path]:
    evidence_dir = remote_root / "evidence" / "step5" / sample_id / run_id
    workspace_root = remote_root / "workspaces" / "malware" / sample_id / run_id
    return {
        "evidence_dir": evidence_dir,
        "workspace_root": workspace_root,
        "raw_extract": workspace_root / "raw-malwarebazaar-extract",
        "artifact_extract": workspace_root / "artifact-extract",
        "prepared_manifest": evidence_dir / "prepared-workspace.json",
        "live_gate": evidence_dir / "live-gate.json",
        "run_dir": evidence_dir / "whoathere-run",
        "summary": evidence_dir / "step5-summary.json",
        "seal": evidence_dir / "step5-evidence-seal.json",
    }


def archive_paths(stage_dir: Path, sample: dict[str, Any]) -> tuple[Path, Path, Path]:
    digest = sample["artifact_sha256"].removeprefix("sha256:")
    sample_dir = stage_dir / "samples" / "malwarebazaar" / digest
    archive = sample_dir / f"{digest}.malwarebazaar.zip"
    sidecar = sample_dir / f"{digest}.malwarebazaar.zip.sha256"
    custody = sample_dir / "custody.json"
    for required in (archive, sidecar, custody):
        if not required.is_file():
            raise Step5Error(f"missing_sample_file:{required}")
    expected_archive_hash = sidecar.read_text(encoding="utf-8").split()[0]
    actual_archive_hash = sha256_file(archive)
    if expected_archive_hash != actual_archive_hash:
        raise Step5Error("archive_sidecar_hash_mismatch")
    custody_data = read_json(custody)
    if custody_data.get("sample_sha256") != sample["artifact_sha256"]:
        raise Step5Error("custody_sample_sha256_mismatch")
    if custody_data.get("download_archive_sha256") != actual_archive_hash:
        raise Step5Error("custody_archive_sha256_mismatch")
    for key in ("live_c2_allowed", "second_stage_live_fetch_allowed", "sync_back_allowed"):
        if custody_data.get(key) is not False:
            raise Step5Error(f"custody_{key}_must_be_false")
    return archive, sidecar, custody


def safe_extract_zip(zip_path: Path, out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[Path] = []
    with zipfile.ZipFile(zip_path) as archive:
        planned: list[str] = []
        for info in archive.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise Step5Error(f"zip_symlink_refused:{info.filename}")
            normalized = safe_member_path(info.filename)
            target = out_dir / normalized
            require_under(target, out_dir, "zip_member")
            if info.is_dir():
                continue
            planned.append(normalized)
    if len(planned) != 1:
        raise Step5Error(f"zip_expected_one_file_got_{len(planned)}")
    bsdtar = shutil.which("bsdtar")
    unzip = shutil.which("unzip")
    if bsdtar is not None:
        completed = subprocess.run(
            [bsdtar, "--passphrase", MB_ZIP_PASSWORD.decode("ascii"), "-xf", str(zip_path), "-C", str(out_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    elif unzip is not None:
        completed = subprocess.run(
            [unzip, "-P", MB_ZIP_PASSWORD.decode("ascii"), "-qq", str(zip_path), "-d", str(out_dir)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    else:
        raise Step5Error("system_zip_extractor_missing")
    if completed.returncode != 0:
        raise Step5Error(f"system_zip_extract_failed:{completed.returncode}:{completed.stderr[:200]}")
    for root, dirs, files in os.walk(out_dir):
        for name in dirs + files:
            path = Path(root) / name
            if path.is_symlink():
                raise Step5Error(f"zip_extracted_symlink_refused:{path}")
    extracted = [out_dir / planned[0]]
    if not extracted[0].is_file():
        raise Step5Error(f"zip_planned_member_missing_after_extract:{planned[0]}")
    return extracted


def safe_extract_tar(tar_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with tarfile.open(tar_path, "r:*") as archive:
        for member in archive.getmembers():
            if posixpath.normpath(member.name) == ".":
                continue
            normalized = safe_member_path(member.name)
            target = out_dir / normalized
            require_under(target, out_dir, "tar_member")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise Step5Error(f"tar_unsupported_member_refused:{member.name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                raise Step5Error(f"tar_member_read_failed:{member.name}")
            with source, target.open("xb") as dest:
                shutil.copyfileobj(source, dest)


def safe_extract_wheel(wheel_path: Path, out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(wheel_path) as archive:
        for info in archive.infolist():
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise Step5Error(f"wheel_symlink_refused:{info.filename}")
            normalized = safe_member_path(info.filename)
            target = out_dir / normalized
            require_under(target, out_dir, "wheel_member")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("xb") as dest:
                shutil.copyfileobj(source, dest)


def prepare_sample(remote_root: Path, stage_dir: Path, sample_id: str, run_id: str, force: bool) -> dict[str, Any]:
    sample, matrix_row = sample_and_matrix(stage_dir, sample_id)
    validate_sample_for_step5(sample)
    paths = step5_paths(remote_root, sample_id, run_id)
    if paths["workspace_root"].exists():
        if not force:
            raise Step5Error(f"workspace_root_exists:{paths['workspace_root']}")
        shutil.rmtree(paths["workspace_root"])
    paths["workspace_root"].mkdir(parents=True)
    paths["evidence_dir"].mkdir(parents=True, exist_ok=True)

    archive, sidecar, custody = archive_paths(stage_dir, sample)
    extracted = safe_extract_zip(archive, paths["raw_extract"])
    artifact = extracted[0]
    artifact_hash = sha256_file(artifact)
    if artifact_hash != sample["artifact_sha256"]:
        raise Step5Error(f"artifact_sha256_mismatch expected={sample['artifact_sha256']} actual={artifact_hash}")

    artifact_name = sample["artifact_filename"]
    if sample["ecosystem"] == "npm" and artifact_name.endswith(".tgz"):
        safe_extract_tar(artifact, paths["artifact_extract"])
        candidate = paths["artifact_extract"] / "package"
        workspace = candidate if (candidate / "package.json").is_file() else paths["artifact_extract"]
        tool = "npm"
        tool_args_json = matrix_row["tool_args_json"]
    elif sample["ecosystem"] == "pypi" and artifact_name.endswith((".tar.gz", ".tgz", ".zip", ".whl")):
        if artifact_name.endswith(".whl"):
            safe_extract_wheel(artifact, paths["artifact_extract"])
        elif artifact_name.endswith(".zip"):
            safe_extract_zip(artifact, paths["artifact_extract"])
        else:
            safe_extract_tar(artifact, paths["artifact_extract"])
        workspace = paths["artifact_extract"]
        tool = matrix_row["tool"]
        tool_args_json = matrix_row["tool_args_json"]
    else:
        raise Step5Error(f"unsupported_step5_artifact:{sample['ecosystem']}:{artifact_name}")

    require_under(workspace, paths["workspace_root"], "prepared_workspace")
    if not workspace.is_dir():
        raise Step5Error(f"prepared_workspace_missing:{workspace}")
    identity = workspace_hash(workspace)
    manifest = {
        "schema": f"{SCHEMA_PREFIX}.prepared_workspace.v1",
        "created_at_utc": now_utc(),
        "sample_id": sample_id,
        "run_id": run_id,
        "sample": {
            "ecosystem": sample["ecosystem"],
            "package_name": sample["package_name"],
            "package_version": sample["package_version"],
            "artifact_filename": sample["artifact_filename"],
            "artifact_sha256": sample["artifact_sha256"],
            "behavior_labels": sample.get("behavior_labels", []),
            "trigger_phases": sample.get("trigger_phases", []),
        },
        "source_archive": {
            "path": str(archive),
            "sha256": sha256_file(archive),
            "sidecar_path": str(sidecar),
            "custody_path": str(custody),
            "custody_sha256": sha256_file(custody),
        },
        "extracted_artifact": {
            "path": str(artifact),
            "sha256": artifact_hash,
            "size": artifact.stat().st_size,
        },
        "workspace": str(workspace),
        "workspace_identity": identity,
        "tool": tool,
        "tool_args_json": tool_args_json,
        "mode": matrix_row["mode"],
        "timeout_seconds": int(matrix_row["timeout_seconds"]),
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "host_malware_bytes_unpacked": True,
        "local_developer_host_touched": False,
        "restricted_workspace_root": str(paths["workspace_root"]),
    }
    write_json(paths["prepared_manifest"], manifest)
    return manifest


def verify_live_gate(remote_root: Path, stage_dir: Path, args: argparse.Namespace, sample_id: str, run_id: str) -> dict[str, Any]:
    paths = step5_paths(remote_root, sample_id, run_id)
    phase1_state = remote_root / "evidence" / "phase1" / "state-lock.json"
    phase1_guardrails = remote_root / "evidence" / "phase1" / "guardrails-status.json"
    if not phase1_state.is_file():
        raise Step5Error(f"missing_phase1_state_lock:{phase1_state}")
    if not phase1_guardrails.is_file():
        raise Step5Error(f"missing_phase1_guardrails:{phase1_guardrails}")
    state_lock = read_json(phase1_state)
    guardrails = read_json(phase1_guardrails)
    sample, _ = sample_and_matrix(stage_dir, sample_id)
    validate_sample_for_step5(sample)

    command_dir = paths["evidence_dir"] / "live-gate-commands"
    whoathere_bin = str(args.whoathere_bin)
    commands = {
        "vm_health": run_capture([whoathere_bin, "vm", "health", "--state-dir", str(args.state_dir)], command_dir / "vm-health.out", args.timeout_seconds),
        "red_team_gate": run_capture([whoathere_bin, "vm", "red-team-gate", "--json"], command_dir / "red-team-gate.json", args.timeout_seconds),
        "scanners_list": run_capture([whoathere_bin, "scanners", "list", "--json"], command_dir / "scanners-list.json", args.timeout_seconds),
    }
    network_control_ready = args.sinkhole_ready_asserted or args.egress_deny_asserted
    blockers = []
    if state_lock.get("valid") is not True:
        blockers.append("phase1_state_lock_not_valid")
    if guardrails.get("ready_for_benign_dry_run") is not True:
        blockers.append("phase1_benign_guardrail_not_ready")
    if guardrails.get("host_pf_observed") is not True:
        blockers.append("host_pf_not_observed")
    if not args.cloud_firewall_default_deny_asserted:
        blockers.append("cloud_firewall_default_deny_not_asserted")
    if not network_control_ready:
        blockers.append("sinkhole_or_egress_deny_not_asserted")
    if not args.live_malware_execution_approved:
        blockers.append("live_malware_execution_not_approved")
    if not args.lulu_enabled_asserted:
        blockers.append("lulu_secondary_control_not_asserted")
    if not all(record["exit_code"] == 0 for record in commands.values()):
        blockers.append("live_gate_command_failed")
    gate = {
        "schema": f"{SCHEMA_PREFIX}.live_gate.v1",
        "created_at_utc": now_utc(),
        "sample_id": sample_id,
        "run_id": run_id,
        "phase1_state_lock_path": str(phase1_state),
        "phase1_state_lock_sha256": sha256_file(phase1_state),
        "phase1_guardrails_path": str(phase1_guardrails),
        "phase1_guardrails_sha256": sha256_file(phase1_guardrails),
        "commands": commands,
        "external_assertions": {
            "provider_approval_ref": args.provider_approval_ref,
            "legal_provider_approval_ref": args.legal_provider_approval_ref,
            "cloud_firewall_default_deny_asserted": args.cloud_firewall_default_deny_asserted,
            "sinkhole_ready_asserted": args.sinkhole_ready_asserted,
            "egress_deny_asserted": args.egress_deny_asserted,
            "sinkhole_reference": args.sinkhole_reference,
            "lulu_enabled_asserted": args.lulu_enabled_asserted,
            "lulu_reference": args.lulu_reference,
            "live_malware_execution_approved": args.live_malware_execution_approved,
        },
        "network_policy": "sinkhole_only" if args.sinkhole_ready_asserted else "egress_denied_no_live_c2",
        "claim_boundary": (
            "sinkhole telemetry expected"
            if args.sinkhole_ready_asserted
            else "egress denied; network behavior may be fail-closed rather than sinkhole-observed"
        ),
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "ready_for_single_malware_rehearsal": not blockers,
        "blockers": blockers,
    }
    write_json(paths["live_gate"], gate)
    if blockers:
        raise Step5Error(f"live_gate_not_ready:{','.join(blockers)}")
    return gate


def assert_no_unsafe_result(result: dict[str, Any]) -> list[str]:
    failures: list[str] = []
    summary = result.get("summary", {})
    if result.get("sync_back_requested") is not False:
        failures.append("sync_back_requested_not_false")
    for key in ("host_execution_enabled", "sync_back_enabled", "sync_back_applied"):
        if summary.get(key) is not False:
            failures.append(f"{key}_not_false")
    if result.get("redaction_leaks"):
        failures.append("redaction_leaks_present")
    return failures


def run_step5(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    sample_id = args.sample_id
    run_id = args.run_id or dt.datetime.now(dt.timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    paths = step5_paths(remote_root, sample_id, run_id)
    paths["evidence_dir"].mkdir(parents=True, exist_ok=True)
    live_gate = verify_live_gate(remote_root, stage_dir, args, sample_id, run_id)
    prepared = prepare_sample(remote_root, stage_dir, sample_id, run_id, args.force)
    paths["run_dir"].mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        str(args.evaluator_script),
        "run-sample",
        "--corpus",
        str(stage_dir / "metadata" / "corpus_manifest.jsonl"),
        "--sample-id",
        sample_id,
        "--workspace",
        prepared["workspace"],
        "--state-dir",
        str(args.state_dir),
        "--whoathere-bin",
        str(args.whoathere_bin),
        "--out-dir",
        str(paths["run_dir"]),
        "--tool",
        prepared["tool"],
        "--tool-args-json",
        prepared["tool_args_json"],
        "--mode",
        prepared["mode"],
        "--timeout-seconds",
        str(prepared["timeout_seconds"]),
        "--execute-approved",
    ]
    run_record = run_capture(command, paths["run_dir"] / "step5-run-sample.stdout", prepared["timeout_seconds"] + 120)
    result_path = paths["run_dir"] / "run_result.json"
    result = read_json(result_path) if result_path.is_file() else {}
    safety_failures = assert_no_unsafe_result(result) if result else ["run_result_missing"]
    suspend_record = run_capture(
        [str(args.whoathere_bin), "vm", "suspend", "--state-dir", str(args.state_dir), "--execute"],
        paths["evidence_dir"] / "post-run-vm-suspend.out",
        args.timeout_seconds,
    )
    summary = {
        "schema": f"{SCHEMA_PREFIX}.summary.v1",
        "created_at_utc": now_utc(),
        "sample_id": sample_id,
        "run_id": run_id,
        "live_gate": live_gate,
        "prepared_manifest_path": str(paths["prepared_manifest"]),
        "prepared_manifest_sha256": sha256_file(paths["prepared_manifest"]),
        "run_record": run_record,
        "result_path": str(result_path),
        "result_sha256": sha256_file(result_path) if result_path.is_file() else None,
        "verdict_class": result.get("verdict_class"),
        "summary": result.get("summary", {}),
        "safety_failures": safety_failures,
        "safety_passed": not safety_failures,
        "sync_back_allowed": False,
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "host_contamination_status": "contaminated_rebuild_or_clear_before_next_live_run",
        "vm_state_status": "suspend_requested_rebuild_or_prune_before_next_live_run",
        "post_run_vm_suspend": suspend_record,
    }
    write_json(paths["summary"], summary)
    seal_record = run_capture(
        [
            sys.executable,
            str(args.evaluator_script),
            "seal-evidence",
            "--evidence-dir",
            str(paths["evidence_dir"]),
            "--out",
            str(paths["seal"]),
        ],
        paths["evidence_dir"] / "seal-evidence.stdout",
        args.timeout_seconds,
    )
    returned_summary = dict(summary)
    if paths["seal"].is_file():
        returned_summary["evidence_seal_path"] = str(paths["seal"])
        returned_summary["evidence_seal_sha256"] = sha256_file(paths["seal"])
    returned_summary["seal_record"] = seal_record
    return returned_summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-root", type=Path, required=True)
    parser.add_argument("--stage-dir", type=Path)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--whoathere-bin", type=Path, required=True)
    parser.add_argument("--evaluator-script", type=Path, required=True)
    parser.add_argument("--sample-id", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--provider-approval-ref", required=True)
    parser.add_argument("--legal-provider-approval-ref", required=True)
    parser.add_argument("--cloud-firewall-default-deny-asserted", action="store_true")
    parser.add_argument("--sinkhole-ready-asserted", action="store_true")
    parser.add_argument("--egress-deny-asserted", action="store_true")
    parser.add_argument("--sinkhole-reference", default="")
    parser.add_argument("--lulu-enabled-asserted", action="store_true")
    parser.add_argument("--lulu-reference", default="")
    parser.add_argument("--live-malware-execution-approved", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        remote_root = args.remote_root.expanduser().resolve()
        if not remote_root.is_dir():
            raise Step5Error(f"remote_root_missing:{remote_root}")
        stage_dir = args.stage_dir.expanduser().resolve() if args.stage_dir else latest_stage(remote_root)
        require_under(stage_dir, remote_root, "stage_dir")
        if not args.evaluator_script.is_file():
            raise Step5Error(f"missing_evaluator_script:{args.evaluator_script}")
        result = run_step5(remote_root, stage_dir, args)
        print(json.dumps(result, indent=2, sort_keys=True))
        if not result.get("safety_passed"):
            return 20
        return 0
    except Step5Error as exc:
        print(f"step5_error={exc}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
