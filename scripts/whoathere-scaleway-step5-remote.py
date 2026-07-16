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
LEGACY_EXECUTION_PATH = "legacy_workspace_non_claim_bearing"
EXACT_ARTIFACT_EXECUTION_PATH = "exact_artifact_diagnostic"
EXACT_ARTIFACT_REPORT_SCHEMA = "whoathere.exact_artifact_inspection.v1"
EXACT_ARTIFACT_DIAGNOSTIC_SCHEMA = "whoathere.actual_malware.exact_artifact_diagnostic_result.v1"
PHYSICAL_DETONATION_PROVIDERS = {
    "linux_vz_exact_npm_v1",
    "linux_vz_exact_wheel_v1",
    "linux_vz_exact_sdist_v1",
}
CODEX_BEHAVIOR_PROVIDER = "codex-subscription-behavior-observer-v1"


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


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 71 and value.startswith("sha256:") and all(
        character in "0123456789abcdef" for character in value[7:]
    )


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


def run_capture_restricted(
    argv: list[str],
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
    command_identity: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    """Run a command while retaining raw output only in the restricted workspace.

    Exact-artifact inspection can invoke a hosted reviewer. Even though the product contract emits
    bounded JSON, malformed output and provider diagnostics are not eligible for the sanitized
    evidence directory. The public record therefore contains only measurements and timestamps.
    """

    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
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
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")
    return (
        {
            "command_identity": command_identity,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "started_at_utc": started,
            "finished_at_utc": now_utc(),
            "stdout_sha256": sha256_file(stdout_path),
            "stdout_bytes": stdout_path.stat().st_size,
            "stderr_sha256": sha256_file(stderr_path),
            "stderr_bytes": stderr_path.stat().st_size,
            "raw_output_retained_in_restricted_workspace": True,
            "raw_argv_retained_in_sanitized_evidence": False,
        },
        stdout,
    )


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
        "exact_artifact": workspace_root / "exact-artifact",
        "restricted_command_output": workspace_root / "restricted-command-output",
        "prepared_manifest": evidence_dir / "prepared-workspace.json",
        "live_gate": evidence_dir / "live-gate.json",
        "run_dir": evidence_dir / "whoathere-run",
        "exact_artifact_report": evidence_dir / "whoathere-run" / "exact-artifact-inspection-sanitized.json",
        "diagnostic_result": evidence_dir / "whoathere-run" / "diagnostic_result.json",
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


def prepare_legacy_workspace_sample(
    remote_root: Path,
    stage_dir: Path,
    sample_id: str,
    run_id: str,
    force: bool,
) -> dict[str, Any]:
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
        "execution_path": LEGACY_EXECUTION_PATH,
        "claim_bearing": False,
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


def prepare_exact_artifact_sample(
    remote_root: Path,
    stage_dir: Path,
    sample_id: str,
    run_id: str,
    force: bool,
) -> dict[str, Any]:
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
    extracted_artifact = extracted[0]
    artifact_hash = sha256_file(extracted_artifact)
    if artifact_hash != sample["artifact_sha256"]:
        raise Step5Error(
            f"artifact_sha256_mismatch expected={sample['artifact_sha256']} actual={artifact_hash}"
        )

    artifact_name = sample.get("artifact_filename")
    if not isinstance(artifact_name, str) or not artifact_name or Path(artifact_name).name != artifact_name:
        raise Step5Error("exact_artifact_filename_not_safe_basename")
    supported = (
        sample.get("ecosystem") == "npm" and artifact_name.endswith((".tgz", ".tar.gz"))
    ) or (
        sample.get("ecosystem") == "pypi"
        and artifact_name.endswith((".whl", ".tar.gz", ".tgz", ".zip"))
    )
    if not supported:
        raise Step5Error(f"unsupported_exact_artifact:{sample.get('ecosystem')}:{artifact_name}")
    paths["exact_artifact"].mkdir(parents=True)
    artifact = paths["exact_artifact"] / artifact_name
    require_under(artifact, paths["workspace_root"], "exact_artifact")
    extracted_artifact.replace(artifact)
    if sha256_file(artifact) != sample["artifact_sha256"]:
        raise Step5Error("exact_artifact_sha256_changed_after_materialization")

    manifest = {
        "schema": f"{SCHEMA_PREFIX}.prepared_exact_artifact.v1",
        "created_at_utc": now_utc(),
        "execution_path": EXACT_ARTIFACT_EXECUTION_PATH,
        "claim_bearing": False,
        "sample_id": sample_id,
        "run_id": run_id,
        "sample": {
            "ecosystem": sample["ecosystem"],
            "package_name": sample["package_name"],
            "package_version": sample["package_version"],
            "artifact_filename": artifact_name,
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
        "exact_artifact": {
            "path": str(artifact),
            "sha256": artifact_hash,
            "size": artifact.stat().st_size,
        },
        "mode": matrix_row["mode"],
        "timeout_seconds": int(matrix_row["timeout_seconds"]),
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "outer_custody_zip_unpacked_on_cloud_mac": True,
        "package_artifact_unpacked_by_harness": False,
        "local_developer_host_touched": False,
        "restricted_workspace_root": str(paths["workspace_root"]),
    }
    write_json(paths["prepared_manifest"], manifest)
    return manifest


def prepare_sample(
    remote_root: Path,
    stage_dir: Path,
    sample_id: str,
    run_id: str,
    force: bool,
    execution_path: str,
) -> dict[str, Any]:
    if execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
        return prepare_exact_artifact_sample(remote_root, stage_dir, sample_id, run_id, force)
    if execution_path == LEGACY_EXECUTION_PATH:
        return prepare_legacy_workspace_sample(remote_root, stage_dir, sample_id, run_id, force)
    raise Step5Error(f"unsupported_execution_path:{execution_path}")


def validate_execution_path_args(args: argparse.Namespace, remote_root: Path) -> dict[str, Any]:
    if args.execution_path == LEGACY_EXECUTION_PATH:
        exact_values = (
            args.detonation_config,
            args.detonation_config_sha256,
            args.codex_client_path,
            args.codex_client_sha256,
            args.codex_model,
            args.codex_auth_home,
            args.restricted_source_review_approval_ref,
            args.restricted_behavior_review_approval_ref,
            args.clearance_consumption_record,
            args.clearance_consumption_record_sha256,
        )
        if (
            args.restricted_source_hosted_review_approved
            or args.restricted_behavior_hosted_review_approved
            or args.split_local_behavior_finalization
        ):
            raise Step5Error("legacy_execution_path_rejects_hosted_restricted_review_approvals")
        if any(value not in {None, ""} for value in exact_values):
            raise Step5Error("legacy_execution_path_rejects_exact_artifact_options")
        return {
            "execution_path": LEGACY_EXECUTION_PATH,
            "claim_bearing": False,
            "description": "legacy loose-workspace evaluator; retained for maintenance only",
        }

    if args.execution_path != EXACT_ARTIFACT_EXECUTION_PATH:
        raise Step5Error(f"unsupported_execution_path:{args.execution_path}")
    source_review_approved = args.restricted_source_hosted_review_approved
    source_review_ref_present = bool(args.restricted_source_review_approval_ref)
    if source_review_approved != source_review_ref_present:
        raise Step5Error("restricted_source_review_approval_flag_and_ref_must_match")
    split_local = args.split_local_behavior_finalization
    missing: list[str] = []
    required = [
        ("detonation_config", args.detonation_config),
        ("detonation_config_sha256", args.detonation_config_sha256),
        ("restricted_behavior_hosted_review_approved", args.restricted_behavior_hosted_review_approved),
        ("restricted_behavior_review_approval_ref", args.restricted_behavior_review_approval_ref),
        ("clearance_consumption_record", args.clearance_consumption_record),
        ("clearance_consumption_record_sha256", args.clearance_consumption_record_sha256),
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
            raise Step5Error(
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
    for label, value in required:
        if value in {None, "", False}:
            missing.append(label)
    if missing:
        raise Step5Error(f"exact_artifact_missing_required_options:{','.join(missing)}")
    if (
        source_review_approved
        and args.restricted_source_review_approval_ref
        == args.restricted_behavior_review_approval_ref
    ):
        raise Step5Error("restricted_source_and_behavior_review_approval_refs_must_be_distinct")
    if not args.sinkhole_ready_asserted:
        raise Step5Error("exact_artifact_behavior_observation_requires_sinkhole_ready")
    if not valid_sha256(args.detonation_config_sha256):
        raise Step5Error("detonation_config_sha256_invalid")
    if not split_local and not valid_sha256(args.codex_client_sha256):
        raise Step5Error("codex_client_sha256_invalid")
    if not valid_sha256(args.clearance_consumption_record_sha256):
        raise Step5Error("clearance_consumption_record_sha256_invalid")
    if not split_local:
        if not 1 <= args.codex_timeout_seconds <= 600:
            raise Step5Error("codex_timeout_seconds_out_of_range")
        if args.product_run_timeout_seconds <= args.codex_timeout_seconds:
            raise Step5Error("product_run_timeout_must_exceed_codex_timeout")

    detonation_config = args.detonation_config
    codex_client = args.codex_client_path
    codex_auth_home = args.codex_auth_home
    if not detonation_config.is_absolute() or not regular_non_symlink(detonation_config):
        raise Step5Error("detonation_config_must_be_absolute_regular_non_symlink")
    if sha256_file(detonation_config) != args.detonation_config_sha256:
        raise Step5Error("detonation_config_sha256_mismatch")
    if not split_local:
        if not codex_client.is_absolute() or not regular_non_symlink(codex_client):
            raise Step5Error("codex_client_must_be_absolute_regular_non_symlink")
        if not os.access(codex_client, os.X_OK):
            raise Step5Error("codex_client_not_executable")
        if sha256_file(codex_client) != args.codex_client_sha256:
            raise Step5Error("codex_client_sha256_mismatch")
        if not codex_auth_home.is_absolute() or not directory_non_symlink(codex_auth_home):
            raise Step5Error("codex_auth_home_must_be_absolute_directory_non_symlink")
    clearance_consumption_path = require_under(
        args.clearance_consumption_record,
        remote_root,
        "clearance_consumption_record",
    )
    if not regular_non_symlink(clearance_consumption_path):
        raise Step5Error("clearance_consumption_record_missing")
    if sha256_file(clearance_consumption_path) != args.clearance_consumption_record_sha256:
        raise Step5Error("clearance_consumption_record_sha256_mismatch")
    clearance_consumption = read_json(clearance_consumption_path)
    if (
        clearance_consumption.get("schema")
        != "whoathere.actual_malware.scaleway_steps6_8.clearance_consumption.v1"
        or clearance_consumption.get("sample_ids") != [args.sample_id]
        or clearance_consumption.get("max_samples_per_clearance") != 1
        or clearance_consumption.get("status") != "reserved_before_live_execution"
    ):
        raise Step5Error("clearance_consumption_record_invalid_for_exact_sample")

    return {
        "execution_path": EXACT_ARTIFACT_EXECUTION_PATH,
        "claim_bearing": False,
        "behavior_observation_mode": (
            "split_local_pending" if split_local else "remote_codex"
        ),
        "detonation": {
            "config_sha256": args.detonation_config_sha256,
            "config_path_retained": False,
        },
        "codex": (
            {
                "provider": "codex",
                "remote_invocation": False,
                "status": "pending_local_behavior_finalization",
                "auth_material_transferred_to_remote": False,
            }
            if split_local
            else {
                "provider": "codex",
                "remote_invocation": True,
                "client_sha256": args.codex_client_sha256,
                "model": args.codex_model,
                "auth_mode": "saved_subscription_auth_dedicated_home",
                "auth_home_path_retained": False,
                "timeout_seconds": args.codex_timeout_seconds,
            }
        ),
        "restricted_hosted_review_approvals": {
            "source": {
                "approved": source_review_approved,
                "approval_ref": (
                    args.restricted_source_review_approval_ref
                    if source_review_approved
                    else None
                ),
            },
            "behavior_telemetry": {
                "approved": True,
                "approval_ref": args.restricted_behavior_review_approval_ref,
            },
        },
        "clearance_consumption": {
            "sha256": args.clearance_consumption_record_sha256,
            "sample_count": 1,
        },
    }


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
        "execution_path": args.execution_path,
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
            "restricted_source_hosted_review_approved": args.restricted_source_hosted_review_approved,
            "restricted_source_review_approval_ref": (
                args.restricted_source_review_approval_ref
                if args.restricted_source_hosted_review_approved
                else None
            ),
            "restricted_behavior_hosted_review_approved": args.restricted_behavior_hosted_review_approved,
            "restricted_behavior_review_approval_ref": args.restricted_behavior_review_approval_ref,
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


def normal_not_requested_stage(
    stage: Any,
    stage_name: str,
    reason_code: str,
    expected_artifact_sha256: str,
    expected_manifest_sha256: str,
) -> bool:
    return (
        isinstance(stage, dict)
        and stage.get("stage") == stage_name
        and stage.get("status") == "not_requested"
        and stage.get("artifact_sha256") == expected_artifact_sha256
        and stage.get("manifest_sha256") == expected_manifest_sha256
        and stage.get("provider") is None
        and stage.get("request_sha256") is None
        and stage.get("result_sha256") is None
        and stage.get("observation_count") == 0
        and stage.get("reason_codes") == [reason_code]
    )


def validate_exact_artifact_report(
    report: dict[str, Any],
    process_exit_code: int,
    expected_artifact_sha256: str,
    behavior_observation_mode: str = "remote_codex",
) -> dict[str, Any]:
    failures: list[str] = []
    if report.get("schema_version") != EXACT_ARTIFACT_REPORT_SCHEMA:
        failures.append("exact_artifact_report_schema_invalid")
    if report.get("exit_code") != process_exit_code:
        failures.append("exact_artifact_report_exit_code_mismatch")
    expected_outcomes = {
        20: ("findings", "malicious"),
        22: (None, None),
    }
    if process_exit_code not in expected_outcomes:
        failures.append(f"exact_artifact_product_exit_unsupported:{process_exit_code}")
    elif process_exit_code == 20:
        if report.get("status") != "findings" or report.get("verdict") != "malicious":
            failures.append("exact_artifact_detection_exit_report_disagreement")
    elif report.get("status") not in {"inconclusive", "unsupported"} or report.get("verdict") not in {
        "inconclusive",
        "unsupported",
    }:
        failures.append("exact_artifact_inconclusive_exit_report_disagreement")
    identity = report.get("identity")
    expected_manifest_sha256 = (
        identity.get("manifest_sha256") if isinstance(identity, dict) else None
    )
    if (
        not isinstance(identity, dict)
        or identity.get("artifact_sha256") != expected_artifact_sha256
        or not valid_sha256(expected_manifest_sha256)
    ):
        failures.append("exact_artifact_report_identity_mismatch")
    if report.get("admission_authority") is not False:
        failures.append("exact_artifact_report_admission_authority_not_false")
    if report.get("observed_clean") is not False:
        failures.append("exact_artifact_report_observed_clean_not_false")
    if report.get("sync_back_enabled") is not False:
        failures.append("exact_artifact_report_sync_back_enabled_not_false")

    observations = report.get("observations")
    if not isinstance(observations, list):
        failures.append("exact_artifact_report_observations_not_array")
        observations = []
    elif any(
        not isinstance(observation, dict)
        or observation.get("artifact_sha256") != expected_artifact_sha256
        for observation in observations
    ):
        failures.append("exact_artifact_observation_identity_mismatch")
    eligible_count = sum(
        1
        for observation in observations
        if isinstance(observation, dict) and observation.get("behavior_detection_eligible") is True
    )
    if report.get("behavior_detection_count") != eligible_count:
        failures.append("exact_artifact_behavior_detection_count_mismatch")
    codex_source_finding_count = sum(
        1 for observation in observations if isinstance(observation, dict) and observation.get("source") == "ai_source_review"
    )
    codex_behavior_finding_count = sum(
        1 for observation in observations if isinstance(observation, dict) and observation.get("source") == "ai_behavioral"
    )
    codex_behavior_detection_count = sum(
        1
        for observation in observations
        if isinstance(observation, dict)
        and observation.get("source") == "ai_behavioral"
        and observation.get("behavior_detection_eligible") is True
    )
    if behavior_observation_mode == "split_local_pending":
        stages = report.get("stages") if isinstance(report.get("stages"), list) else []
        ai_review_stages = [
            stage for stage in stages if isinstance(stage, dict) and stage.get("stage") == "ai_review"
        ]
        behavior_stages = [
            stage
            for stage in stages
            if isinstance(stage, dict) and stage.get("stage") == "behavior_observation"
        ]
        normal_placeholders = (
            len(ai_review_stages) == 1
            and normal_not_requested_stage(
                ai_review_stages[0],
                "ai_review",
                "exact_artifact_ai_not_requested",
                expected_artifact_sha256,
                expected_manifest_sha256,
            )
            and len(behavior_stages) == 1
            and normal_not_requested_stage(
                behavior_stages[0],
                "behavior_observation",
                "exact_artifact_behavior_observation_not_requested",
                expected_artifact_sha256,
                expected_manifest_sha256,
            )
        )
        if codex_source_finding_count or codex_behavior_finding_count or not normal_placeholders:
            failures.append("split_local_remote_ai_evidence_present")
    return {
        "valid": not failures,
        "failures": failures,
        "finding_observed": not failures and process_exit_code == 20,
        "behavior_detection_count": eligible_count,
        "codex_source_finding_count": codex_source_finding_count,
        "codex_behavior_finding_count": codex_behavior_finding_count,
        "codex_behavior_detection_count": codex_behavior_detection_count,
        "codex_behavior_detected": codex_behavior_detection_count > 0,
    }


def assess_codex_observed_physical_detonation(
    report: dict[str, Any],
    expected_artifact_sha256: str,
    behavior_observation_mode: str = "remote_codex",
) -> dict[str, Any]:
    stages = report.get("stages") if isinstance(report.get("stages"), list) else []
    identity = report.get("identity") if isinstance(report.get("identity"), dict) else {}
    expected_manifest_sha256 = identity.get("manifest_sha256")
    scenario_plan = report.get("scenario_plan") if isinstance(report.get("scenario_plan"), dict) else {}
    intents = scenario_plan.get("intents") if isinstance(scenario_plan.get("intents"), list) else []
    expected_action_count = len(intents)
    failures: list[str] = []

    detonation_stages = [
        stage for stage in stages if isinstance(stage, dict) and stage.get("stage") == "detonation"
    ]
    detonation_reasons: list[str] = []
    projected_bundle_count = 0
    projected_behavior_bundles: list[dict[str, str]] = []
    physical_evidence_completed = False
    if len(detonation_stages) != 1:
        failures.append("physical_detonation_stage_missing_or_duplicate")
    else:
        detonation = detonation_stages[0]
        detonation_reasons = (
            detonation.get("reason_codes") if isinstance(detonation.get("reason_codes"), list) else []
        )
        projected_bundle_count = sum(
            1
            for reason in detonation_reasons
            if isinstance(reason, str) and reason.endswith("_behavior_bundle_projected")
        )
        projected_actions = {
            reason.removesuffix("_behavior_bundle_projected")
            for reason in detonation_reasons
            if isinstance(reason, str) and reason.endswith("_behavior_bundle_projected")
        }
        digest_by_action: dict[str, str] = {}
        malformed_bundle_digest = False
        for reason in detonation_reasons:
            if not isinstance(reason, str) or "_behavior_bundle_sha256:" not in reason:
                continue
            action, separator, digest = reason.partition("_behavior_bundle_sha256:")
            if (
                not separator
                or not action
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
                or action in digest_by_action
            ):
                malformed_bundle_digest = True
                continue
            digest_by_action[action] = "sha256:" + digest
        event_actions = {
            reason.partition("_behavior_event_count:")[0]
            for reason in detonation_reasons
            if isinstance(reason, str) and "_behavior_event_count:" in reason
        }
        projected_behavior_bundles = [
            {"action_id": action, "bundle_sha256": digest_by_action[action]}
            for action in sorted(digest_by_action)
        ]
        bindings_valid = (
            detonation.get("artifact_sha256") == expected_artifact_sha256
            and valid_sha256(expected_manifest_sha256)
            and detonation.get("manifest_sha256") == expected_manifest_sha256
            and valid_sha256(detonation.get("request_sha256"))
            and valid_sha256(detonation.get("result_sha256"))
            and detonation.get("observation_count") == 0
        )
        receipt_projection_complete = (
            expected_action_count > 0
            and projected_bundle_count == expected_action_count
            and len(digest_by_action) == expected_action_count
            and len(event_actions) == expected_action_count
            and not malformed_bundle_digest
            and projected_actions == set(digest_by_action) == event_actions
            and any(
                isinstance(reason, str) and reason.endswith("_evidence_captured_pending_analysis")
                for reason in detonation_reasons
            )
            and any(
                isinstance(reason, str) and reason.endswith("_evidence_output_preserved")
                for reason in detonation_reasons
            )
            and not any(
                isinstance(reason, str) and reason.endswith("_evidence_incomplete")
                for reason in detonation_reasons
            )
        )
        physical_evidence_completed = (
            detonation.get("provider") in PHYSICAL_DETONATION_PROVIDERS
            and detonation.get("status") in {"complete", "incomplete"}
            and bindings_valid
            and receipt_projection_complete
        )
        if detonation.get("provider") not in PHYSICAL_DETONATION_PROVIDERS:
            failures.append("physical_detonation_provider_not_qualified")
        if not bindings_valid:
            failures.append("physical_detonation_stage_binding_invalid")
        if not receipt_projection_complete:
            failures.append("physical_detonation_receipt_projection_incomplete")
        if malformed_bundle_digest:
            failures.append("physical_detonation_behavior_bundle_digest_invalid")
        if detonation.get("status") not in {"complete", "incomplete"}:
            failures.append("physical_detonation_stage_not_terminal")

    behavioral_observations = [
        observation
        for observation in report.get("observations", [])
        if isinstance(observation, dict) and observation.get("source") == "ai_behavioral"
    ] if isinstance(report.get("observations"), list) else []
    eligible_behavioral_observations = [
        observation
        for observation in behavioral_observations
        if observation.get("behavior_detection_eligible") is True
    ]
    all_behavior_stages = [
        stage
        for stage in stages
        if isinstance(stage, dict) and stage.get("stage") == "behavior_observation"
    ]
    behavior_not_requested_stages = [
        stage for stage in all_behavior_stages if stage.get("status") == "not_requested"
    ]
    behavior_stages = [
        stage for stage in all_behavior_stages if stage.get("status") != "not_requested"
    ]
    behavior_stage_bindings_valid = bool(behavior_stages) and all(
        stage.get("provider") == CODEX_BEHAVIOR_PROVIDER
        and stage.get("artifact_sha256") == expected_artifact_sha256
        and valid_sha256(stage.get("request_sha256"))
        and valid_sha256(stage.get("result_sha256"))
        and stage.get("status")
        in {"complete", "findings", "findings_with_incomplete_coverage", "incomplete"}
        and isinstance(stage.get("observation_count"), int)
        and stage.get("observation_count") >= 0
        for stage in behavior_stages
    )
    behavior_stage_observation_count = sum(
        int(stage.get("observation_count", 0)) for stage in behavior_stages if isinstance(stage, dict)
    )
    behavior_stage_positive = any(
        stage.get("status") in {"findings", "findings_with_incomplete_coverage"}
        and int(stage.get("observation_count", 0)) > 0
        for stage in behavior_stages
        if isinstance(stage, dict)
    )
    codex_behavior_stage_proven = (
        projected_bundle_count > 0
        and len(behavior_stages) == projected_bundle_count
        and behavior_stage_bindings_valid
        and behavior_stage_observation_count == len(behavioral_observations)
        and behavior_stage_positive
        and bool(eligible_behavioral_observations)
    )
    if behavior_observation_mode == "remote_codex":
        if not eligible_behavioral_observations:
            failures.append("eligible_codex_behavioral_observation_missing")
        if not codex_behavior_stage_proven:
            failures.append("codex_behavior_observation_stage_not_proven")
    elif behavior_observation_mode == "split_local_pending":
        placeholder_valid = (
            len(behavior_not_requested_stages) == 1
            and normal_not_requested_stage(
                behavior_not_requested_stages[0],
                "behavior_observation",
                "exact_artifact_behavior_observation_not_requested",
                expected_artifact_sha256,
                expected_manifest_sha256,
            )
        )
        if behavior_stages or behavioral_observations or not placeholder_valid:
            failures.append("split_local_remote_behavior_observation_present")
    else:
        failures.append("behavior_observation_mode_invalid")

    physical_safety_proven = physical_evidence_completed
    codex_observed_detonation_gate_passed = physical_evidence_completed and codex_behavior_stage_proven
    return {
        "physical_detonation_evidence_completed": physical_evidence_completed,
        "physical_safety_proven": physical_safety_proven,
        "expected_action_count": expected_action_count,
        "projected_behavior_bundle_count": projected_bundle_count,
        "projected_behavior_bundles": projected_behavior_bundles,
        "behavior_observation_mode": behavior_observation_mode,
        "pending_local_behavior_finalization": (
            behavior_observation_mode == "split_local_pending" and physical_evidence_completed
        ),
        "codex_behavior_stage_proven": codex_behavior_stage_proven,
        "eligible_codex_behavioral_observation_count": len(eligible_behavioral_observations),
        "codex_observed_detonation_gate_passed": codex_observed_detonation_gate_passed,
        "failures": failures,
    }


def sanitized_reason_codes(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value
        if isinstance(item, str)
        and 0 < len(item) <= 160
        and all(
            character.isascii()
            and (character.islower() or character.isdigit() or character in "_-.:")
            for character in item
        )
    ][:128]


def safe_report_scalar(value: Any, maximum_length: int = 256) -> str | int | bool | None:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, str) and len(value) <= maximum_length and "\n" not in value and "\r" not in value:
        return value
    return None


def sanitize_exact_artifact_report(report: dict[str, Any]) -> dict[str, Any]:
    """Project the trusted report schema without copying source, telemetry, or unknown fields."""

    identity = report.get("identity") if isinstance(report.get("identity"), dict) else {}
    scenario_plan = report.get("scenario_plan") if isinstance(report.get("scenario_plan"), dict) else {}
    stages: list[dict[str, Any]] = []
    for stage in report.get("stages", []) if isinstance(report.get("stages"), list) else []:
        if not isinstance(stage, dict):
            continue
        stages.append(
            {
                key: safe_report_scalar(stage.get(key))
                for key in (
                    "stage",
                    "status",
                    "artifact_sha256",
                    "manifest_sha256",
                    "request_sha256",
                    "result_sha256",
                    "provider",
                    "observation_count",
                )
            }
            | {"reason_codes": sanitized_reason_codes(stage.get("reason_codes"))}
        )
    observations: list[dict[str, Any]] = []
    for observation in report.get("observations", []) if isinstance(report.get("observations"), list) else []:
        if not isinstance(observation, dict):
            continue
        observations.append(
            {
                key: safe_report_scalar(observation.get(key))
                for key in (
                    "schema_version",
                    "source",
                    "threat_class",
                    "confidence",
                    "artifact_sha256",
                    "manifest_sha256",
                    "coverage",
                    "behavior_detection_eligible",
                    "observation_sha256",
                )
            }
            | {"coverage_gap_codes": sanitized_reason_codes(observation.get("coverage_gap_codes"))}
        )
    return {
        "schema_version": safe_report_scalar(report.get("schema_version")),
        "status": safe_report_scalar(report.get("status")),
        "verdict": safe_report_scalar(report.get("verdict")),
        "exit_code": safe_report_scalar(report.get("exit_code")),
        "identity": {
            key: safe_report_scalar(identity.get(key))
            for key in (
                "artifact_sha256",
                "envelope_sha256",
                "manifest_sha256",
                "byte_length",
                "ecosystem",
                "artifact_format",
                "source_type",
                "acquisition_method",
            )
        },
        "stages": stages,
        "scenario_plan": {
            key: safe_report_scalar(scenario_plan.get(key))
            for key in (
                "schema_version",
                "artifact_sha256",
                "manifest_sha256",
                "status",
                "plan_sha256",
                "runtime_binding_required",
                "runtime_binding_status",
                "executable",
            )
        }
        | {
            "intent_count": len(scenario_plan.get("intents", []))
            if isinstance(scenario_plan.get("intents"), list)
            else 0,
            "reason_codes": sanitized_reason_codes(scenario_plan.get("reason_codes")),
        },
        "observations": observations,
        "behavior_detection_count": safe_report_scalar(report.get("behavior_detection_count")),
        "admission_authority": safe_report_scalar(report.get("admission_authority")),
        "observed_clean": safe_report_scalar(report.get("observed_clean")),
        "sync_back_enabled": safe_report_scalar(report.get("sync_back_enabled")),
        "reason_codes": sanitized_reason_codes(report.get("reason_codes")),
        "sanitized_projection": True,
        "raw_source_or_telemetry_included": False,
    }


def run_legacy_workspace(
    stage_dir: Path,
    args: argparse.Namespace,
    prepared: dict[str, Any],
    paths: dict[str, Path],
) -> dict[str, Any]:
    command = [
        sys.executable,
        str(args.evaluator_script),
        "run-sample",
        "--corpus",
        str(stage_dir / "metadata" / "corpus_manifest.jsonl"),
        "--sample-id",
        args.sample_id,
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
    return {
        "execution_path": LEGACY_EXECUTION_PATH,
        "claim_bearing": False,
        "scorable": False,
        "finalizable": False,
        "run_record": run_record,
        "result_path": str(result_path),
        "result_sha256": sha256_file(result_path) if result_path.is_file() else None,
        "verdict_class": result.get("verdict_class"),
        "producer_summary": result.get("summary", {}),
        "diagnostic_completed": run_record["exit_code"] == 0 and bool(result),
        "diagnostic_detection_observed": result.get("verdict_class") not in {None, "miss", "unsafe_allow"},
        "safety_failures": safety_failures,
        "safety_passed": not safety_failures,
        "vm_state_status": "suspend_requested_rebuild_or_prune_before_next_live_run",
        "post_run_vm_suspend": suspend_record,
    }


def run_exact_artifact(
    args: argparse.Namespace,
    prepared: dict[str, Any],
    paths: dict[str, Path],
    execution_config: dict[str, Any],
) -> dict[str, Any]:
    artifact = Path(prepared["exact_artifact"]["path"])
    split_local = args.split_local_behavior_finalization
    behavior_observation_mode = "split_local_pending" if split_local else "remote_codex"
    command = [
        str(args.whoathere_bin),
        "artifact",
        "inspect",
        str(artifact),
        "--ecosystem",
        prepared["sample"]["ecosystem"],
        "--state-dir",
        str(args.state_dir),
        "--detonation",
        "--detonation-config",
        str(args.detonation_config),
    ]
    if not split_local:
        command.extend(
            [
                "--behavior-observe",
                "--approve-hosted-behavior-review",
                "--ai-provider",
                "codex",
                "--ai-client-path",
                str(args.codex_client_path),
                "--ai-client-sha256",
                args.codex_client_sha256,
                "--ai-model",
                args.codex_model,
                "--ai-auth-home",
                str(args.codex_auth_home),
                "--ai-timeout-seconds",
                str(args.codex_timeout_seconds),
            ]
        )
        if args.restricted_source_hosted_review_approved:
            command.extend(["--ai-review", "--approve-hosted-source-review"])
    command_identity = {
        "operation": "whoathere_artifact_inspect_exact_artifact",
        "artifact_sha256": prepared["exact_artifact"]["sha256"],
        "ecosystem": prepared["sample"]["ecosystem"],
        "detonation": True,
        "detonation_config_sha256": args.detonation_config_sha256,
        "behavior_observation_mode": behavior_observation_mode,
        "ai_source_review": False if split_local else args.restricted_source_hosted_review_approved,
        "ai_behavior_observation": not split_local,
        "ai_provider": None if split_local else "codex",
        "ai_client_sha256": None if split_local else args.codex_client_sha256,
        "ai_model": None if split_local else args.codex_model,
        "ai_auth_mode": None if split_local else "saved_subscription_auth_dedicated_home",
        "ai_timeout_seconds": None if split_local else args.codex_timeout_seconds,
        "source_review_approval_ref": (
            args.restricted_source_review_approval_ref
            if args.restricted_source_hosted_review_approved and not split_local
            else None
        ),
        "behavior_review_approval_ref": args.restricted_behavior_review_approval_ref,
        "sync_back_option_present": False,
    }
    run_record, raw_stdout = run_capture_restricted(
        command,
        paths["restricted_command_output"] / "exact-artifact-inspection.stdout",
        paths["restricted_command_output"] / "exact-artifact-inspection.stderr",
        args.product_run_timeout_seconds,
        command_identity,
    )
    try:
        parsed = json.loads(raw_stdout)
    except (json.JSONDecodeError, UnicodeDecodeError):
        parsed = None
    report = parsed if isinstance(parsed, dict) else {}
    validation = validate_exact_artifact_report(
        report,
        run_record["exit_code"],
        prepared["exact_artifact"]["sha256"],
        behavior_observation_mode,
    )
    if run_record["timed_out"]:
        validation["failures"].append("exact_artifact_product_timed_out")
        validation["valid"] = False
        validation["finding_observed"] = False
    if validation["valid"]:
        write_json(paths["exact_artifact_report"], sanitize_exact_artifact_report(report))
    physical_assessment = assess_codex_observed_physical_detonation(
        report,
        prepared["exact_artifact"]["sha256"],
        behavior_observation_mode,
    )
    diagnostic_completed = (
        validation["valid"]
        and run_record["exit_code"] in {20, 22}
        and (not split_local or physical_assessment["physical_detonation_evidence_completed"])
    )
    product_finding_observed = (
        diagnostic_completed and run_record["exit_code"] == 20 and not split_local
    )
    codex_observed_detonation = (
        product_finding_observed
        and physical_assessment["codex_observed_detonation_gate_passed"]
    )
    safety_failures = [
        failure
        for failure in validation["failures"]
        if failure
        in {
            "exact_artifact_report_admission_authority_not_false",
            "exact_artifact_report_observed_clean_not_false",
            "exact_artifact_report_sync_back_enabled_not_false",
        }
    ]
    if not physical_assessment["physical_safety_proven"]:
        safety_failures.append("physical_detonation_safety_not_proven")
    pending_local_behavior_finalization = (
        split_local and diagnostic_completed and not safety_failures
    )
    result = {
        "schema": EXACT_ARTIFACT_DIAGNOSTIC_SCHEMA,
        "created_at_utc": now_utc(),
        "sample_id": prepared["sample_id"],
        "run_id": prepared["run_id"],
        "execution_path": EXACT_ARTIFACT_EXECUTION_PATH,
        "claim_bearing": False,
        "scorable": False,
        "finalizable": False,
        "behavior_observation_mode": behavior_observation_mode,
        "pending_local_behavior_finalization": pending_local_behavior_finalization,
        "artifact": {
            "ecosystem": prepared["sample"]["ecosystem"],
            "filename": prepared["sample"]["artifact_filename"],
            "sha256": prepared["exact_artifact"]["sha256"],
            "size": prepared["exact_artifact"]["size"],
        },
        "execution_config": execution_config,
        "product": {
            "report_path": str(paths["exact_artifact_report"]) if paths["exact_artifact_report"].is_file() else None,
            "report_sha256": sha256_file(paths["exact_artifact_report"])
            if paths["exact_artifact_report"].is_file()
            else None,
            "raw_report_sha256": run_record["stdout_sha256"],
            "raw_report_retained_in_restricted_workspace": True,
            "exit_code": run_record["exit_code"],
            "status": report.get("status"),
            "verdict": report.get("verdict"),
            "report_validation": validation,
        },
        "diagnostic_completed": diagnostic_completed,
        "product_finding_observed": product_finding_observed,
        "diagnostic_detection_observed": codex_observed_detonation,
        "codex_observed_detonation_gate_passed": codex_observed_detonation,
        "physical_detonation": physical_assessment,
        "verdict_class": (
            "diagnostic_pending_local_behavior_finalization"
            if pending_local_behavior_finalization
            else "diagnostic_incomplete"
            if split_local
            else ("diagnostic_detection" if codex_observed_detonation else "diagnostic_miss")
        ),
        "behavior_detection_count": 0 if split_local else validation["behavior_detection_count"],
        "codex_source_finding_count": 0 if split_local else validation["codex_source_finding_count"],
        "codex_behavior_finding_count": 0 if split_local else validation["codex_behavior_finding_count"],
        "codex_behavior_detection_count": 0 if split_local else validation["codex_behavior_detection_count"],
        "codex_behavior_detected": False if split_local else validation["codex_behavior_detected"],
        "safety": {
            "network_policy": "sinkhole_only",
            "sync_back_allowed": False,
            "live_c2_allowed": False,
            "live_second_stage_fetch_allowed": False,
            "product_sync_back_enabled": report.get("sync_back_enabled"),
            "product_admission_authority": report.get("admission_authority"),
        },
        "safety_failures": safety_failures,
        "safety_passed": not safety_failures,
        "run_record": run_record,
    }
    write_json(paths["diagnostic_result"], result)
    return {
        "execution_path": EXACT_ARTIFACT_EXECUTION_PATH,
        "claim_bearing": False,
        "scorable": False,
        "finalizable": False,
        "behavior_observation_mode": behavior_observation_mode,
        "pending_local_behavior_finalization": pending_local_behavior_finalization,
        "run_record": run_record,
        "result_path": str(paths["diagnostic_result"]),
        "result_sha256": sha256_file(paths["diagnostic_result"]),
        "product_report_path": result["product"]["report_path"],
        "product_report_sha256": result["product"]["report_sha256"],
        "verdict_class": result["verdict_class"],
        "diagnostic_completed": diagnostic_completed,
        "product_finding_observed": product_finding_observed,
        "diagnostic_detection_observed": codex_observed_detonation,
        "codex_observed_detonation_gate_passed": codex_observed_detonation,
        "physical_detonation_evidence_completed": physical_assessment[
            "physical_detonation_evidence_completed"
        ],
        "physical_safety_proven": physical_assessment["physical_safety_proven"],
        "codex_behavior_detected": False if split_local else validation["codex_behavior_detected"],
        "safety_failures": safety_failures,
        "safety_passed": not safety_failures,
        "vm_state_status": "exact_artifact_product_detonation_adapter_completed_or_reported_incomplete",
        "post_run_vm_suspend": None,
    }


def run_step5(remote_root: Path, stage_dir: Path, args: argparse.Namespace) -> dict[str, Any]:
    sample_id = args.sample_id
    run_id = args.run_id or dt.datetime.now(dt.timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    paths = step5_paths(remote_root, sample_id, run_id)
    paths["evidence_dir"].mkdir(parents=True, exist_ok=True)
    execution_config = validate_execution_path_args(args, remote_root)
    live_gate = verify_live_gate(remote_root, stage_dir, args, sample_id, run_id)
    prepared = prepare_sample(remote_root, stage_dir, sample_id, run_id, args.force, args.execution_path)
    paths["run_dir"].mkdir(parents=True, exist_ok=True)
    if args.execution_path == EXACT_ARTIFACT_EXECUTION_PATH:
        execution = run_exact_artifact(args, prepared, paths, execution_config)
    else:
        execution = run_legacy_workspace(stage_dir, args, prepared, paths)
    summary = {
        "schema": f"{SCHEMA_PREFIX}.summary.v2",
        "created_at_utc": now_utc(),
        "sample_id": sample_id,
        "run_id": run_id,
        "execution_path": args.execution_path,
        "claim_bearing": False,
        "scorable": False,
        "finalizable": False,
        "live_gate": live_gate,
        "prepared_manifest_path": str(paths["prepared_manifest"]),
        "prepared_manifest_sha256": sha256_file(paths["prepared_manifest"]),
        **execution,
        "sync_back_allowed": False,
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "host_contamination_status": "contaminated_rebuild_or_clear_before_next_live_run",
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
    parser.add_argument(
        "--execution-path",
        choices=[LEGACY_EXECUTION_PATH, EXACT_ARTIFACT_EXECUTION_PATH],
        required=True,
    )
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
    parser.add_argument("--detonation-config", type=Path)
    parser.add_argument("--detonation-config-sha256")
    parser.add_argument("--codex-client-path", type=Path)
    parser.add_argument("--codex-client-sha256")
    parser.add_argument("--codex-model")
    parser.add_argument("--codex-auth-home", type=Path)
    parser.add_argument("--codex-timeout-seconds", type=int, default=300)
    parser.add_argument("--product-run-timeout-seconds", type=int, default=840)
    parser.add_argument("--restricted-source-hosted-review-approved", action="store_true")
    parser.add_argument("--restricted-source-review-approval-ref", default="")
    parser.add_argument("--restricted-behavior-hosted-review-approved", action="store_true")
    parser.add_argument("--restricted-behavior-review-approval-ref", default="")
    parser.add_argument("--split-local-behavior-finalization", action="store_true")
    parser.add_argument("--clearance-consumption-record", type=Path)
    parser.add_argument("--clearance-consumption-record-sha256")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--timeout-seconds", type=int, default=120)
    return parser


def step5_exit_code(result: dict[str, Any], execution_path: str) -> int:
    if result.get("safety_passed") is not True:
        return 20
    if result.get("diagnostic_completed") is not True:
        return 70
    if result.get("pending_local_behavior_finalization") is True:
        return 0
    if (
        execution_path == EXACT_ARTIFACT_EXECUTION_PATH
        and result.get("codex_observed_detonation_gate_passed") is not True
    ):
        return 20
    return 0


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
        return step5_exit_code(result, args.execution_path)
    except Step5Error as exc:
        print(f"step5_error={exc}", file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
