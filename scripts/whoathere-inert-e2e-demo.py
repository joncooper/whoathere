#!/usr/bin/env python3
"""Run the bounded two-host P07 inert static/VM/Codex demonstration.

The cloud Mac executes only the exact inert artifact in disposable Linux VZ guests. Only a
strictly sanitized report, typed behavior bundles, and a bounded safety projection cross back to
the local Mac. Subscription-backed Codex observes those typed bundles locally and has no
containment, evidence-authentication, admission, or clean authority.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
from typing import Any, Callable


INPUT_SCHEMA = "whoathere.inert_e2e_demo_input.v1"
REMOTE_SCHEMA = "whoathere.inert_e2e_remote_result.v1"
EXPORT_SCHEMA = "whoathere.split_behavior_export.v1"
REPORT_SCHEMA = "whoathere.exact_artifact_inspection.v1"
BUNDLE_SCHEMA = "whoathere.behavior_analysis_bundle.v1"
OBSERVER_SCHEMA = "whoathere.behavior_observe.v1"
DIAGNOSTIC_SCHEMA = "whoathere.two_host_behavior_diagnostic.v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_JSON_BYTES = 32 * 1024 * 1024
PROFILES = ("ci_false", "ci_true")
ACTION_BY_PROFILE = {"ci_false": "vm_ci_false", "ci_true": "vm_ci_true"}
INVARIANTS = (
    "host_package_executions",
    "sync_backs",
    "unsafe_allows",
    "restricted_material_leaks",
    "live_c2_contacts",
    "live_second_stage_fetches",
)
REMOTE_RESULT_KEYS = {
    "schema_version",
    "status",
    "input_sha256",
    "artifact_sha256",
    "manifest_sha256",
    "scenario_plan_sha256",
    "detonation_result_sha256",
    "sanitized_report_sha256",
    "export_manifest_sha256",
    "files",
    "profiles",
    "invariants",
    "raw_evidence_included",
    "artifact_bytes_included",
    "package_source_included",
    "remote_ai_invoked",
    "admission_authority",
    "observed_clean",
}
REMOTE_PROFILE_KEYS = {
    "profile",
    "execution_result_sha256",
    "bundle_sha256",
    "root_receipt_sha256",
    "host_receipt_sha256",
    "vm_started",
    "vm_stopped",
    "clone_destroyed",
    "image_identity_stable",
    "public_network_route_present",
    "sync_back",
    "authoritative_verdict_permitted",
    "evidence_coverage_complete",
}
REMOTE_FILE_KEYS = {"role", "path", "sha256", "byte_length"}
EXPORT_MANIFEST_KEYS = {
    "schema_version",
    "created_at_utc",
    "artifact_sha256",
    "manifest_sha256",
    "detonation_provider",
    "sanitized_report_sha256",
    "bundle_count",
    "bundle_set_sha256",
    "files",
    "raw_evidence_included",
    "artifact_bytes_included",
    "package_source_included",
}
EXPORT_REPORT_FILE_KEYS = {"role", "path", "sha256", "byte_length"}
EXPORT_BUNDLE_FILE_KEYS = {
    "role",
    "action_key",
    "bundle_sha256",
    "path",
    "sha256",
    "byte_length",
}
SAFE_TOKEN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$")
SAFE_EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:\-]{0,159}$")
SAFE_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,4094}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class DemoError(Exception):
    def __init__(self, reason_code: str, exit_code: int = 22):
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.exit_code = exit_code


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


Runner = Callable[[list[str], bytes | None, int], CommandResult]


def require(condition: bool, reason_code: str, exit_code: int = 22) -> None:
    if not condition:
        raise DemoError(reason_code, exit_code)


def sha256_bytes(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def serde_event_sha256(value: dict[str, Any]) -> str:
    return sha256_bytes(
        json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    )


def exact_keys(value: Any, keys: set[str], reason_code: str) -> dict[str, Any]:
    require(isinstance(value, dict) and set(value) == keys, reason_code, 64)
    return value


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and SHA256.fullmatch(value) is not None


def digest_value(value: Any, reason_code: str) -> str:
    require(valid_sha256(value), reason_code, 64)
    return value


def safe_token(value: Any, reason_code: str) -> str:
    require(isinstance(value, str) and SAFE_TOKEN.fullmatch(value) is not None, reason_code, 64)
    return value


def absolute_path(value: Any, reason_code: str) -> Path:
    require(
        isinstance(value, str)
        and value.startswith("/")
        and "\x00" not in value
        and "\n" not in value
        and "\r" not in value
        and len(value.encode()) <= 4096,
        reason_code,
        64,
    )
    return Path(value)


def remote_path(value: Any, reason_code: str) -> PurePosixPath:
    require(isinstance(value, str) and SAFE_REMOTE_PATH.fullmatch(value) is not None, reason_code, 64)
    path = PurePosixPath(value)
    require(".." not in path.parts and "//" not in value, reason_code, 64)
    return path


def under_remote(path: PurePosixPath, root: PurePosixPath, reason_code: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise DemoError(reason_code, 64) from error


def read_regular(path: Path, max_bytes: int, reason_code: str) -> bytes:
    try:
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and 0 < metadata.st_size <= max_bytes,
            reason_code,
            64,
        )
        return path.read_bytes()
    except OSError as error:
        raise DemoError(reason_code, 64) from error


def parse_json(content: bytes, reason_code: str) -> dict[str, Any]:
    try:
        value = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DemoError(reason_code, 64) from error
    require(isinstance(value, dict), reason_code, 64)
    return value


def private_regular(path: Path, reason_code: str) -> None:
    content = read_regular(path, MAX_INPUT_BYTES, reason_code)
    del content
    mode = stat.S_IMODE(path.stat().st_mode)
    require(mode & 0o077 == 0, reason_code, 64)


def private_directory(path: Path, reason_code: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise DemoError(reason_code, 64) from error
    require(
        stat.S_ISDIR(metadata.st_mode)
        and not path.is_symlink()
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0,
        reason_code,
        64,
    )


def validate_file_binding(value: Any, reason_code: str) -> dict[str, Any]:
    binding = exact_keys(value, {"path", "sha256"}, reason_code)
    absolute_path(binding["path"], reason_code)
    digest_value(binding["sha256"], reason_code)
    return binding


def validate_input(value: dict[str, Any]) -> dict[str, Any]:
    plan = exact_keys(
        value,
        {"schema_version", "demo", "preflight", "remote", "local", "policy"},
        "p07_input_shape_invalid",
    )
    require(plan["schema_version"] == INPUT_SCHEMA, "p07_input_schema_invalid", 64)

    demo = exact_keys(
        plan["demo"],
        {
            "demo_id",
            "artifact_filename",
            "artifact_byte_length",
            "artifact_sha256",
            "required_profiles",
        },
        "p07_demo_shape_invalid",
    )
    safe_token(demo["demo_id"], "p07_demo_id_invalid")
    safe_token(demo["artifact_filename"], "p07_artifact_filename_invalid")
    require(
        isinstance(demo["artifact_byte_length"], int)
        and not isinstance(demo["artifact_byte_length"], bool)
        and 0 < demo["artifact_byte_length"] <= 16 * 1024 * 1024,
        "p07_artifact_length_invalid",
        64,
    )
    digest_value(demo["artifact_sha256"], "p07_artifact_digest_invalid")
    require(demo["required_profiles"] == list(PROFILES), "p07_profile_set_invalid", 64)

    preflight = exact_keys(
        plan["preflight"],
        {
            "command",
            "input",
            "expected_campaign_id",
            "expected_profile_id",
        },
        "p07_preflight_shape_invalid",
    )
    validate_file_binding(preflight["command"], "p07_preflight_command_invalid")
    validate_file_binding(preflight["input"], "p07_preflight_input_invalid")
    safe_token(preflight["expected_campaign_id"], "p07_preflight_campaign_invalid")
    safe_token(preflight["expected_profile_id"], "p07_preflight_profile_invalid")

    remote = exact_keys(
        plan["remote"],
        {
            "host_alias",
            "workspace_root",
            "python_path",
            "artifact",
            "whoathere",
            "detonation_config",
            "detonation_output_root",
            "run_root",
            "report_sanitizer",
            "bundle_exporter",
            "timeout_seconds",
        },
        "p07_remote_shape_invalid",
    )
    safe_token(remote["host_alias"], "p07_remote_host_alias_invalid")
    root = remote_path(remote["workspace_root"], "p07_remote_root_invalid")
    require(str(root) != "/", "p07_remote_root_invalid", 64)
    python_path = remote_path(remote["python_path"], "p07_remote_python_invalid")
    require(str(python_path) == "/usr/bin/python3", "p07_remote_python_invalid", 64)
    for label in ("artifact", "whoathere", "detonation_config", "report_sanitizer", "bundle_exporter"):
        binding = validate_file_binding(remote[label], f"p07_remote_{label}_invalid")
        bound_path = remote_path(binding["path"], f"p07_remote_{label}_invalid")
        under_remote(bound_path, root, f"p07_remote_{label}_outside_root")
    require(
        PurePosixPath(remote["artifact"]["path"]).name == demo["artifact_filename"],
        "p07_remote_artifact_filename_mismatch",
        64,
    )
    detonation_root = remote_path(
        remote["detonation_output_root"], "p07_remote_detonation_root_invalid"
    )
    run_root = remote_path(remote["run_root"], "p07_remote_run_root_invalid")
    under_remote(detonation_root, root, "p07_remote_detonation_root_outside_workspace")
    under_remote(run_root, root, "p07_remote_run_root_outside_workspace")
    require(detonation_root != run_root, "p07_remote_output_roots_aliased", 64)
    require(
        isinstance(remote["timeout_seconds"], int)
        and not isinstance(remote["timeout_seconds"], bool)
        and 60 <= remote["timeout_seconds"] <= 900,
        "p07_remote_timeout_invalid",
        64,
    )

    local = exact_keys(
        plan["local"],
        {
            "whoathere",
            "codex_client",
            "model",
            "auth_home",
            "timeout_seconds",
            "output_root",
            "two_host_diagnostic",
        },
        "p07_local_shape_invalid",
    )
    for label in ("whoathere", "codex_client", "two_host_diagnostic"):
        validate_file_binding(local[label], f"p07_local_{label}_invalid")
    safe_token(local["model"], "p07_local_model_invalid")
    absolute_path(local["auth_home"], "p07_local_auth_home_invalid")
    absolute_path(local["output_root"], "p07_local_output_root_invalid")
    require(
        isinstance(local["timeout_seconds"], int)
        and not isinstance(local["timeout_seconds"], bool)
        and 60 <= local["timeout_seconds"] <= 600,
        "p07_local_timeout_invalid",
        64,
    )

    policy = exact_keys(
        plan["policy"],
        {
            "planned_material",
            "hosted_behavior_review_approved",
            "remote_ai_permitted",
            "raw_export_permitted",
            "sync_back_permitted",
            "admission_authority",
            "sinkhole_destination",
        },
        "p07_policy_shape_invalid",
    )
    require(
        policy
        == {
            "planned_material": "inert_only",
            "hosted_behavior_review_approved": True,
            "remote_ai_permitted": False,
            "raw_export_permitted": False,
            "sync_back_permitted": False,
            "admission_authority": False,
            "sinkhole_destination": "local_loopback",
        },
        "p07_policy_invalid",
        64,
    )
    return plan


def load_plan(input_path: Path, expected_digest: str) -> tuple[dict[str, Any], bytes]:
    require(input_path.is_absolute(), "p07_input_path_not_absolute", 64)
    digest_value(expected_digest, "p07_input_digest_invalid")
    private_regular(input_path, "p07_input_not_private")
    content = read_regular(input_path, MAX_INPUT_BYTES, "p07_input_unavailable")
    require(sha256_bytes(content) == expected_digest, "p07_input_digest_mismatch", 64)
    return validate_input(parse_json(content, "p07_input_json_invalid")), content


def verify_local_prerequisites(
    plan: dict[str, Any], ssh_config: Path, *, require_fresh_output: bool = True
) -> None:
    require(ssh_config.is_absolute(), "p07_ssh_config_not_absolute", 64)
    private_regular(ssh_config, "p07_ssh_config_invalid")
    for binding in (
        plan["preflight"]["command"],
        plan["preflight"]["input"],
        plan["local"]["whoathere"],
        plan["local"]["codex_client"],
        plan["local"]["two_host_diagnostic"],
    ):
        path = Path(binding["path"])
        try:
            metadata = path.lstat()
        except OSError as error:
            raise DemoError("p07_local_bound_file_unavailable", 64) from error
        require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and 0 < metadata.st_size <= 512 * 1024 * 1024,
            "p07_local_bound_file_unavailable",
            64,
        )
        require(sha256_file(path) == binding["sha256"], "p07_local_bound_file_mismatch", 64)
    require(
        sha256_file(Path(plan["preflight"]["input"]["path"]))
        == plan["preflight"]["input"]["sha256"],
        "p07_preflight_input_digest_mismatch",
        64,
    )
    private_regular(
        Path(plan["preflight"]["input"]["path"]),
        "p07_preflight_input_not_private",
    )
    p06_input = parse_json(
        read_regular(
            Path(plan["preflight"]["input"]["path"]),
            MAX_INPUT_BYTES,
            "p07_preflight_input_invalid",
        ),
        "p07_preflight_input_invalid",
    )
    p06_ssh = p06_input.get("ssh")
    p06_binding = p06_input.get("run_binding")
    p06_files = p06_binding.get("files") if isinstance(p06_binding, dict) else None
    require(
        isinstance(p06_ssh, dict)
        and p06_ssh.get("host_alias") == plan["remote"]["host_alias"]
        and isinstance(p06_binding, dict)
        and p06_binding.get("campaign_id") == plan["preflight"]["expected_campaign_id"]
        and p06_binding.get("profile_id") == plan["preflight"]["expected_profile_id"]
        and isinstance(p06_files, list),
        "p07_preflight_plan_binding_mismatch",
        64,
    )
    p06_by_label = {
        item.get("label"): item for item in p06_files if isinstance(item, dict)
    }
    expected_p06_files = {
        "whoathere_bin": plan["remote"]["whoathere"],
        "detonation_config": plan["remote"]["detonation_config"],
        "sanitizer": plan["remote"]["bundle_exporter"],
    }
    require(
        all(
            isinstance(p06_by_label.get(label), dict)
            and p06_by_label[label].get("path") == expected["path"]
            and p06_by_label[label].get("sha256") == expected["sha256"]
            for label, expected in expected_p06_files.items()
        ),
        "p07_preflight_plan_binding_mismatch",
        64,
    )
    private_directory(Path(plan["local"]["auth_home"]), "p07_local_auth_home_invalid")
    output_root = Path(plan["local"]["output_root"])
    private_directory(output_root.parent, "p07_local_output_parent_invalid")
    if require_fresh_output:
        require(
            not output_root.exists() and not output_root.is_symlink(),
            "p07_local_output_not_fresh",
            64,
        )
    else:
        private_directory(output_root, "p07_local_output_invalid")


def default_runner(argv: list[str], input_bytes: bytes | None, timeout: int) -> CommandResult:
    try:
        completed = subprocess.run(
            argv,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)
    except subprocess.TimeoutExpired as error:
        return CommandResult(
            124,
            error.stdout if isinstance(error.stdout, bytes) else b"",
            error.stderr if isinstance(error.stderr, bytes) else b"",
            True,
        )


def bounded_result(
    result: CommandResult,
    allowed_codes: set[int],
    reason_code: str,
    *,
    allow_stderr: bool = False,
) -> bytes:
    require(
        not result.timed_out
        and result.returncode in allowed_codes
        and len(result.stdout) <= MAX_JSON_BYTES
        and len(result.stderr) <= MAX_JSON_BYTES
        and (allow_stderr or not result.stderr),
        reason_code,
    )
    return result.stdout


def run_preflight(plan: dict[str, Any], ssh_config: Path, runner: Runner) -> dict[str, Any]:
    preflight = plan["preflight"]
    result = runner(
        [
            preflight["command"]["path"],
            "--input",
            preflight["input"]["path"],
            "--input-sha256",
            preflight["input"]["sha256"],
            "--ssh-config",
            str(ssh_config),
            "--json",
        ],
        None,
        45,
    )
    content = bounded_result(result, {0}, "p07_preflight_not_ready")
    value = parse_json(content, "p07_preflight_result_invalid")
    bindings = value.get("bindings")
    identities = bindings.get("identity_sha256s") if isinstance(bindings, dict) else None
    require(
        value.get("schema_version") == "whoathere.cloud_lab_preflight_result.v1"
        and value.get("status") == "ready"
        and value.get("exit_code") == 0
        and value.get("input_sha256") == preflight["input"]["sha256"]
        and isinstance(bindings, dict)
        and bindings.get("campaign_id") == preflight["expected_campaign_id"]
        and bindings.get("profile_id") == preflight["expected_profile_id"]
        and isinstance(identities, dict)
        and identities.get("whoathere_bin") == plan["remote"]["whoathere"]["sha256"]
        and identities.get("detonation_config")
        == plan["remote"]["detonation_config"]["sha256"]
        and identities.get("sanitizer") == plan["remote"]["bundle_exporter"]["sha256"]
        and value.get("artifact_opened") is False
        and value.get("package_executed") is False
        and value.get("vm_started") is False
        and value.get("remote_state_mutated") is False
        and value.get("clearance_consumed") is False,
        "p07_preflight_binding_invalid",
    )
    return value


REMOTE_SOURCE = r'''
import base64, hashlib, json, os, pathlib, runpy, stat, subprocess

REMOTE_SCHEMA = "whoathere.inert_e2e_remote_result.v1"
payload = json.loads(base64.b64decode("__PAYLOAD_B64__").decode("utf-8"))

class Failure(Exception):
    pass

def need(condition, code):
    if not condition:
        raise Failure(code)

def digest_bytes(content):
    return "sha256:" + hashlib.sha256(content).hexdigest()

def digest_file(path):
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def regular_file(binding):
    path = pathlib.Path(binding["path"])
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and not path.is_symlink() and meta.st_size > 0, "remote_bound_file_invalid")
    need(digest_file(path) == binding["sha256"], "remote_bound_file_digest_mismatch")
    return path

def read_json(path, code, maximum=33554432):
    meta = path.lstat()
    need(stat.S_ISREG(meta.st_mode) and not path.is_symlink() and 0 < meta.st_size <= maximum, code)
    value = json.loads(path.read_text(encoding="utf-8"))
    need(isinstance(value, dict), code)
    return value

def event_hash(event):
    return digest_bytes(json.dumps(event, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

def safe_error(code):
    print(json.dumps({"schema_version": REMOTE_SCHEMA, "status": "error", "reason_code": code}, sort_keys=True, separators=(",", ":")))

try:
    os.umask(0o077)
    demo = payload["demo"]
    remote = payload["remote"]
    artifact = regular_file(remote["artifact"])
    whoathere = regular_file(remote["whoathere"])
    config_path = regular_file(remote["detonation_config"])
    sanitizer_path = regular_file(remote["report_sanitizer"])
    exporter_path = regular_file(remote["bundle_exporter"])
    need(digest_file(artifact) == demo["artifact_sha256"] and artifact.stat().st_size == demo["artifact_byte_length"], "remote_artifact_identity_mismatch")

    config = read_json(config_path, "remote_config_invalid")
    need(config.get("dependency_closure_path") is None, "remote_config_closure_not_null")
    need(config.get("output_root") == remote["detonation_output_root"], "remote_config_output_root_mismatch")
    detonation_root = pathlib.Path(remote["detonation_output_root"])
    run_root = pathlib.Path(remote["run_root"])
    need(not detonation_root.exists() and not run_root.exists(), "remote_output_not_fresh")
    run_root.mkdir(mode=0o700)
    state_root = run_root / "state"
    state_root.mkdir(mode=0o700)

    completed = subprocess.run(
        [str(whoathere), "artifact", "inspect", str(artifact), "--ecosystem", "npm", "--state-dir", str(state_root), "--detonation", "--detonation-config", str(config_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=remote["timeout_seconds"],
        check=False,
    )
    (run_root / "artifact-inspect.stderr").write_bytes(completed.stderr)
    need(completed.returncode in (20, 22) and 0 < len(completed.stdout) <= 33554432, "remote_inspection_failed")
    report = json.loads(completed.stdout.decode("utf-8"))
    need(isinstance(report, dict) and report.get("schema_version") == "whoathere.exact_artifact_inspection.v1", "remote_report_invalid")
    raw_report_path = run_root / "artifact-inspect.json"
    raw_report_path.write_bytes(completed.stdout)
    raw_report_path.chmod(0o600)

    sanitizer = runpy.run_path(str(sanitizer_path))
    sanitized = sanitizer["sanitize_exact_artifact_report"](report)
    sanitized_raw = (json.dumps(sanitized, indent=2, sort_keys=True) + "\n").encode("utf-8")
    sanitized_path = run_root / "sanitized-report.json"
    sanitized_path.write_bytes(sanitized_raw)
    sanitized_path.chmod(0o600)

    exporter = runpy.run_path(str(exporter_path))
    export_dir = run_root / "export"
    export_result = exporter["export_bundle_set"](sanitized_path, detonation_root, export_dir)
    need(export_result.get("status") == "exported" and export_result.get("bundle_count") == 2, "remote_export_incomplete")
    manifest_path = export_dir / "export-manifest.json"
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw.decode("utf-8"))
    need(manifest.get("raw_evidence_included") is False and manifest.get("artifact_bytes_included") is False and manifest.get("package_source_included") is False, "remote_export_policy_invalid")

    identity = sanitized.get("identity")
    need(isinstance(identity, dict) and identity.get("artifact_sha256") == demo["artifact_sha256"], "remote_report_artifact_mismatch")
    need(sanitized.get("admission_authority") is False and sanitized.get("observed_clean") is False and sanitized.get("sync_back_enabled") is False, "remote_report_authority_invalid")
    stages = [row for row in sanitized.get("stages", []) if isinstance(row, dict) and row.get("stage") == "detonation"]
    need(len(stages) == 1 and stages[0].get("provider") == "linux_vz_exact_npm_v1", "remote_detonation_stage_invalid")
    scenario = sanitized.get("scenario_plan")
    need(isinstance(scenario, dict) and isinstance(scenario.get("plan_sha256"), str), "remote_scenario_invalid")

    manifest_files = manifest.get("files")
    need(isinstance(manifest_files, list) and len(manifest_files) == 3, "remote_export_file_set_invalid")
    bundle_files = {}
    for item in manifest_files:
        need(isinstance(item, dict), "remote_export_file_set_invalid")
        if item.get("role") == "behavior_bundle":
            action = item.get("action_key")
            need(action in ("vm_ci_false", "vm_ci_true") and action not in bundle_files, "remote_bundle_action_invalid")
            bundle_files[action] = item
    need(set(bundle_files) == {"vm_ci_false", "vm_ci_true"}, "remote_bundle_set_invalid")

    execution_paths = list(detonation_root.rglob("execution-run.json"))
    need(len(execution_paths) == 2, "remote_execution_result_count_invalid")
    executions = {}
    for path in execution_paths:
        profile = "ci_true" if "ci_true" in path.parts else "ci_false" if "ci_false" in path.parts else None
        need(profile is not None and profile not in executions, "remote_execution_profile_invalid")
        executions[profile] = (path, read_json(path, "remote_execution_result_invalid"))
    need(set(executions) == {"ci_false", "ci_true"}, "remote_execution_profile_set_invalid")

    profiles = []
    all_network_local = True
    second_stage_seen = False
    for profile in ("ci_false", "ci_true"):
        action = "vm_" + profile
        item = bundle_files[action]
        relative = pathlib.PurePosixPath(item["path"])
        need(".." not in relative.parts and not relative.is_absolute(), "remote_bundle_path_invalid")
        bundle_path = export_dir.joinpath(*relative.parts)
        bundle_raw = bundle_path.read_bytes()
        need(digest_bytes(bundle_raw) == item["sha256"] == item["bundle_sha256"], "remote_bundle_digest_mismatch")
        bundle = json.loads(bundle_raw.decode("utf-8"))
        need(bundle.get("schema_version") == "whoathere.behavior_analysis_bundle.v1" and bundle.get("artifact_sha256") == demo["artifact_sha256"], "remote_bundle_invalid")
        execution_path, execution = executions[profile]
        execution_raw = execution_path.read_bytes()
        need(execution.get("artifact_sha256") == demo["artifact_sha256"], "remote_execution_artifact_mismatch")
        need(execution.get("vm_started") is True and execution.get("vm_stopped") is True and execution.get("clone_destroyed") is True and execution.get("image_identity_stable") is True, "remote_teardown_invalid")
        need(execution.get("public_network_route_present") is False and execution.get("sync_back") is False and execution.get("authoritative_verdict_permitted") is False, "remote_safety_state_invalid")
        need(execution.get("package_execution") is True and execution.get("package_process_succeeded") is True, "remote_package_execution_invalid")
        need(execution.get("root_receipt_sha256") == bundle.get("root_receipt_sha256"), "remote_root_receipt_mismatch")
        need(bundle.get("host_receipt_sha256") == digest_bytes(execution_raw), "remote_host_receipt_mismatch")
        events = bundle.get("events")
        need(isinstance(events, list), "remote_bundle_events_invalid")
        for event in events:
            signal = event.get("signal") if isinstance(event, dict) else None
            need(isinstance(signal, dict), "remote_bundle_events_invalid")
            if signal.get("kind") == "network":
                all_network_local = all_network_local and signal.get("destination") in ("local_sinkhole", "unavailable")
                second_stage_seen = second_stage_seen or signal.get("action") == "receive_executable"
            if signal.get("kind") == "process":
                second_stage_seen = second_stage_seen or signal.get("action") == "executable_payload_launch"
        profiles.append({
            "profile": profile,
            "execution_result_sha256": digest_bytes(execution_raw),
            "bundle_sha256": item["bundle_sha256"],
            "root_receipt_sha256": bundle["root_receipt_sha256"],
            "host_receipt_sha256": bundle["host_receipt_sha256"],
            "vm_started": True,
            "vm_stopped": True,
            "clone_destroyed": True,
            "image_identity_stable": True,
            "public_network_route_present": False,
            "sync_back": False,
            "authoritative_verdict_permitted": False,
            "evidence_coverage_complete": all(row.get("state") == "complete" for row in bundle.get("coverage", [])),
        })
    need(all_network_local and not second_stage_seen, "remote_live_network_or_second_stage_seen")

    files = []
    for item in manifest_files:
        files.append({"role": item["role"], "path": item["path"], "sha256": item["sha256"], "byte_length": item["byte_length"]})
    result = {
        "schema_version": REMOTE_SCHEMA,
        "status": "complete",
        "input_sha256": payload["input_sha256"],
        "artifact_sha256": demo["artifact_sha256"],
        "manifest_sha256": identity["manifest_sha256"],
        "scenario_plan_sha256": scenario["plan_sha256"],
        "detonation_result_sha256": stages[0]["result_sha256"],
        "sanitized_report_sha256": manifest["sanitized_report_sha256"],
        "export_manifest_sha256": digest_bytes(manifest_raw),
        "files": files,
        "profiles": profiles,
        "invariants": {
            "host_package_executions": 0,
            "sync_backs": 0,
            "unsafe_allows": 0,
            "restricted_material_leaks": 0,
            "live_c2_contacts": 0,
            "live_second_stage_fetches": 0,
        },
        "raw_evidence_included": False,
        "artifact_bytes_included": False,
        "package_source_included": False,
        "remote_ai_invoked": False,
        "admission_authority": False,
        "observed_clean": False,
    }
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
except Failure as error:
    safe_error(str(error))
    raise SystemExit(65)
except Exception:
    safe_error("remote_demo_internal_error")
    raise SystemExit(65)
'''


def build_remote_source(plan: dict[str, Any], input_sha256: str) -> bytes:
    digest_value(input_sha256, "p07_input_digest_invalid")
    payload = {
        "input_sha256": input_sha256,
        "demo": plan["demo"],
        "remote": plan["remote"],
    }
    encoded = base64.b64encode(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    return REMOTE_SOURCE.replace("__PAYLOAD_B64__", encoded).encode("utf-8")


def run_remote(
    plan: dict[str, Any], input_sha256: str, ssh_config: Path, runner: Runner
) -> dict[str, Any]:
    remote = plan["remote"]
    result = runner(
        [
            "/usr/bin/ssh",
            "-F",
            str(ssh_config),
            "-o",
            "BatchMode=yes",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RequestTTY=no",
            "-o",
            "ConnectTimeout=10",
            "-T",
            remote["host_alias"],
            remote["python_path"],
            "-",
        ],
        build_remote_source(plan, input_sha256),
        remote["timeout_seconds"] + 60,
    )
    content = bounded_result(result, {0}, "p07_remote_demo_failed")
    value = parse_json(content, "p07_remote_result_invalid")
    validate_remote_result(plan, input_sha256, value)
    return value


def validate_remote_result(
    plan: dict[str, Any], expected_input_sha256: str, value: dict[str, Any]
) -> None:
    exact_keys(value, REMOTE_RESULT_KEYS, "p07_remote_result_shape_invalid")
    require(
        value.get("schema_version") == REMOTE_SCHEMA
        and value.get("status") == "complete"
        and value.get("input_sha256") == expected_input_sha256
        and value.get("artifact_sha256") == plan["demo"]["artifact_sha256"]
        and valid_sha256(value.get("manifest_sha256"))
        and valid_sha256(value.get("scenario_plan_sha256"))
        and valid_sha256(value.get("detonation_result_sha256"))
        and valid_sha256(value.get("sanitized_report_sha256"))
        and valid_sha256(value.get("export_manifest_sha256"))
        and value.get("raw_evidence_included") is False
        and value.get("artifact_bytes_included") is False
        and value.get("package_source_included") is False
        and value.get("remote_ai_invoked") is False
        and value.get("admission_authority") is False
        and value.get("observed_clean") is False,
        "p07_remote_result_binding_invalid",
    )
    invariants = value.get("invariants")
    require(
        isinstance(invariants, dict)
        and set(invariants) == set(INVARIANTS)
        and all(invariants[name] == 0 and not isinstance(invariants[name], bool) for name in INVARIANTS),
        "p07_remote_invariants_invalid",
    )
    profiles = value.get("profiles")
    require(isinstance(profiles, list) and len(profiles) == 2, "p07_remote_profile_count_invalid")
    by_profile = {row.get("profile"): row for row in profiles if isinstance(row, dict)}
    require(set(by_profile) == set(PROFILES), "p07_remote_profile_set_invalid")
    for profile in PROFILES:
        row = by_profile[profile]
        exact_keys(row, REMOTE_PROFILE_KEYS, "p07_remote_profile_shape_invalid")
        require(
            all(valid_sha256(row.get(key)) for key in ("execution_result_sha256", "bundle_sha256", "root_receipt_sha256", "host_receipt_sha256"))
            and row.get("execution_result_sha256") == row.get("host_receipt_sha256")
            and row.get("vm_started") is True
            and row.get("vm_stopped") is True
            and row.get("clone_destroyed") is True
            and row.get("image_identity_stable") is True
            and row.get("public_network_route_present") is False
            and row.get("sync_back") is False
            and row.get("authoritative_verdict_permitted") is False
            and isinstance(row.get("evidence_coverage_complete"), bool),
            "p07_remote_profile_safety_invalid",
        )
    files = value.get("files")
    require(isinstance(files, list) and len(files) == 3, "p07_remote_file_set_invalid")
    require(
        all(isinstance(item, dict) for item in files),
        "p07_remote_file_set_invalid",
    )
    for item in files:
        exact_keys(item, REMOTE_FILE_KEYS, "p07_remote_file_shape_invalid")
    paths = {item.get("path") for item in files if isinstance(item, dict)}
    require(
        paths
        == {
            "sanitized-exact-artifact-report.json",
            "bundles/vm_ci_false/behavior-bundle.json",
            "bundles/vm_ci_true/behavior-bundle.json",
        }
        and all(
            valid_sha256(item.get("sha256"))
            and isinstance(item.get("byte_length"), int)
            and not isinstance(item.get("byte_length"), bool)
            and 0 < item["byte_length"] <= MAX_JSON_BYTES
            for item in files
        ),
        "p07_remote_file_set_invalid",
    )
    by_path = {item["path"]: item for item in files}
    require(
        by_path["sanitized-exact-artifact-report.json"]["role"]
        == "sanitized_exact_artifact_report"
        and by_path["bundles/vm_ci_false/behavior-bundle.json"]["role"]
        == "behavior_bundle"
        and by_path["bundles/vm_ci_true/behavior-bundle.json"]["role"]
        == "behavior_bundle",
        "p07_remote_file_role_invalid",
    )


def write_new_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
    path.chmod(0o600)


def copy_sanitized_export(
    plan: dict[str, Any], ssh_config: Path, remote_result: dict[str, Any], runner: Runner
) -> Path:
    output_root = Path(plan["local"]["output_root"])
    output_root.mkdir(mode=0o700)
    write_new_private(
        output_root / "remote-result.json",
        (json.dumps(remote_result, indent=2, sort_keys=True) + "\n").encode(),
    )
    export_root = output_root / "export"
    export_root.mkdir(mode=0o700)
    remote_export = PurePosixPath(plan["remote"]["run_root"]) / "export"
    remote_files = list(remote_result["files"]) + [
        {
            "path": "export-manifest.json",
            "sha256": remote_result["export_manifest_sha256"],
            "byte_length": None,
        }
    ]
    for item in remote_files:
        relative = PurePosixPath(item["path"])
        require(not relative.is_absolute() and ".." not in relative.parts, "p07_transfer_path_invalid")
        destination = export_root.joinpath(*relative.parts)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in destination.parents:
            directory.chmod(0o700)
            if directory == export_root:
                break
        result = runner(
            [
                "/usr/bin/scp",
                "-F",
                str(ssh_config),
                f"{plan['remote']['host_alias']}:{remote_export.joinpath(*relative.parts)}",
                str(destination),
            ],
            None,
            30,
        )
        bounded_result(result, {0}, "p07_sanitized_transfer_failed")
        destination.chmod(0o600)
        content = read_regular(destination, MAX_JSON_BYTES, "p07_transferred_file_invalid")
        require(sha256_bytes(content) == item["sha256"], "p07_transferred_file_digest_mismatch")
        if item["byte_length"] is not None:
            require(len(content) == item["byte_length"], "p07_transferred_file_length_mismatch")
    return export_root


def validate_export(
    plan: dict[str, Any], export_root: Path, remote_result: dict[str, Any]
) -> tuple[Path, dict[str, Path], dict[str, dict[str, Any]]]:
    private_directory(export_root, "p07_export_root_invalid")
    private_directory(export_root / "bundles", "p07_export_bundle_root_invalid")
    for action in ACTION_BY_PROFILE.values():
        private_directory(
            export_root / "bundles" / action,
            "p07_export_bundle_directory_invalid",
        )
    manifest_path = export_root / "export-manifest.json"
    manifest_raw = read_regular(manifest_path, MAX_JSON_BYTES, "p07_export_manifest_invalid")
    require(
        sha256_bytes(manifest_raw) == remote_result["export_manifest_sha256"],
        "p07_export_manifest_digest_mismatch",
    )
    manifest = parse_json(manifest_raw, "p07_export_manifest_invalid")
    exact_keys(manifest, EXPORT_MANIFEST_KEYS, "p07_export_manifest_shape_invalid")
    require(
        manifest.get("schema_version") == EXPORT_SCHEMA
        and manifest.get("artifact_sha256") == plan["demo"]["artifact_sha256"]
        and manifest.get("manifest_sha256") == remote_result["manifest_sha256"]
        and manifest.get("bundle_count") == 2
        and manifest.get("detonation_provider") == "linux_vz_exact_npm_v1"
        and valid_sha256(manifest.get("bundle_set_sha256"))
        and manifest.get("raw_evidence_included") is False
        and manifest.get("artifact_bytes_included") is False
        and manifest.get("package_source_included") is False,
        "p07_export_manifest_binding_invalid",
    )
    manifest_files = manifest.get("files")
    require(
        isinstance(manifest_files, list) and len(manifest_files) == 3,
        "p07_export_manifest_file_set_invalid",
    )
    manifest_by_path: dict[str, dict[str, Any]] = {}
    bundle_bindings: list[dict[str, Any]] = []
    for item in manifest_files:
        require(isinstance(item, dict), "p07_export_manifest_file_set_invalid")
        role = item.get("role")
        if role == "sanitized_exact_artifact_report":
            exact_keys(item, EXPORT_REPORT_FILE_KEYS, "p07_export_manifest_file_shape_invalid")
        elif role == "behavior_bundle":
            exact_keys(item, EXPORT_BUNDLE_FILE_KEYS, "p07_export_manifest_file_shape_invalid")
            action = item.get("action_key")
            require(
                action in ACTION_BY_PROFILE.values()
                and item.get("bundle_sha256") == item.get("sha256"),
                "p07_export_manifest_bundle_binding_invalid",
            )
            expected_path = f"bundles/{action}/behavior-bundle.json"
            require(
                item.get("path") == expected_path,
                "p07_export_manifest_bundle_binding_invalid",
            )
            bundle_bindings.append(
                {
                    "action_key": action,
                    "bundle_sha256": item["bundle_sha256"],
                    "path": item.get("path"),
                    "byte_length": item.get("byte_length"),
                }
            )
        else:
            raise DemoError("p07_export_manifest_file_role_invalid", 64)
        path = item.get("path")
        require(
            isinstance(path, str) and path not in manifest_by_path,
            "p07_export_manifest_file_set_invalid",
        )
        manifest_by_path[path] = item
    expected_paths = {
        "sanitized-exact-artifact-report.json",
        "bundles/vm_ci_false/behavior-bundle.json",
        "bundles/vm_ci_true/behavior-bundle.json",
    }
    require(
        set(manifest_by_path) == expected_paths
        and len(bundle_bindings) == 2
        and canonical_sha256(sorted(bundle_bindings, key=lambda item: item["action_key"]))
        == manifest["bundle_set_sha256"],
        "p07_export_manifest_file_set_invalid",
    )
    remote_files = {item["path"]: item for item in remote_result["files"]}
    require(
        all(
            remote_files[path]["role"] == item["role"]
            and remote_files[path]["sha256"] == item["sha256"]
            and remote_files[path]["byte_length"] == item["byte_length"]
            for path, item in manifest_by_path.items()
        ),
        "p07_export_manifest_remote_binding_invalid",
    )
    report_path = export_root / "sanitized-exact-artifact-report.json"
    report_raw = read_regular(report_path, MAX_JSON_BYTES, "p07_sanitized_report_invalid")
    require(
        sha256_bytes(report_raw) == remote_result["sanitized_report_sha256"] == manifest.get("sanitized_report_sha256"),
        "p07_sanitized_report_digest_mismatch",
    )
    report_file = manifest_by_path["sanitized-exact-artifact-report.json"]
    require(
        report_file["sha256"] == sha256_bytes(report_raw)
        and report_file["byte_length"] == len(report_raw),
        "p07_sanitized_report_file_binding_invalid",
    )
    report = parse_json(report_raw, "p07_sanitized_report_invalid")
    identity = report.get("identity")
    scenario = report.get("scenario_plan")
    detonation_stages = [
        stage
        for stage in report.get("stages", [])
        if isinstance(stage, dict) and stage.get("stage") == "detonation"
    ]
    require(
        report.get("schema_version") == REPORT_SCHEMA
        and isinstance(identity, dict)
        and identity.get("artifact_sha256") == plan["demo"]["artifact_sha256"]
        and identity.get("manifest_sha256") == remote_result["manifest_sha256"]
        and report.get("admission_authority") is False
        and report.get("observed_clean") is False
        and report.get("sync_back_enabled") is False
        and report.get("sanitized_projection") is True
        and report.get("raw_source_or_telemetry_included") is False,
        "p07_sanitized_report_binding_invalid",
    )
    require(
        isinstance(scenario, dict)
        and scenario.get("artifact_sha256") == plan["demo"]["artifact_sha256"]
        and scenario.get("manifest_sha256") == remote_result["manifest_sha256"]
        and scenario.get("plan_sha256") == remote_result["scenario_plan_sha256"]
        and len(detonation_stages) == 1
        and detonation_stages[0].get("provider") == "linux_vz_exact_npm_v1"
        and detonation_stages[0].get("artifact_sha256")
        == plan["demo"]["artifact_sha256"]
        and detonation_stages[0].get("manifest_sha256")
        == remote_result["manifest_sha256"]
        and detonation_stages[0].get("result_sha256")
        == remote_result["detonation_result_sha256"],
        "p07_sanitized_report_execution_binding_invalid",
    )
    bundle_paths: dict[str, Path] = {}
    bundles: dict[str, dict[str, Any]] = {}
    safety = {row["profile"]: row for row in remote_result["profiles"]}
    for profile in PROFILES:
        path = export_root / "bundles" / ACTION_BY_PROFILE[profile] / "behavior-bundle.json"
        raw = read_regular(path, MAX_JSON_BYTES, "p07_bundle_invalid")
        bundle = parse_json(raw, "p07_bundle_invalid")
        manifest_file = manifest_by_path[
            f"bundles/{ACTION_BY_PROFILE[profile]}/behavior-bundle.json"
        ]
        require(
            bundle.get("schema_version") == BUNDLE_SCHEMA
            and bundle.get("artifact_sha256") == plan["demo"]["artifact_sha256"]
            and bundle.get("manifest_sha256") == remote_result["manifest_sha256"]
            and sha256_bytes(raw) == safety[profile]["bundle_sha256"]
            and sha256_bytes(raw) == manifest_file["sha256"]
            and sha256_bytes(raw) == manifest_file["bundle_sha256"]
            and len(raw) == manifest_file["byte_length"]
            and bundle.get("root_receipt_sha256") == safety[profile]["root_receipt_sha256"]
            and bundle.get("host_receipt_sha256") == safety[profile]["host_receipt_sha256"],
            "p07_bundle_binding_invalid",
        )
        require(
            safety[profile]["evidence_coverage_complete"]
            == all(
                isinstance(row, dict) and row.get("state") == "complete"
                for row in bundle.get("coverage", [])
            )
            and all(
                isinstance(event, dict)
                and event.get("source_receipt_sha256")
                == safety[profile]["root_receipt_sha256"]
                for event in bundle.get("events", [])
            ),
            "p07_bundle_receipt_or_coverage_binding_invalid",
        )
        validate_profile_evidence(profile, bundle)
        bundle_paths[profile] = path
        bundles[profile] = bundle
    return report_path, bundle_paths, bundles


def typed_citations(bundle: dict[str, Any], selector: Callable[[dict[str, Any]], bool]) -> list[str]:
    citations: list[str] = []
    for event in bundle.get("events", []):
        if isinstance(event, dict) and selector(event.get("signal", {})):
            event_id = event.get("event_id")
            require(
                isinstance(event_id, str) and SAFE_EVENT_ID.fullmatch(event_id),
                "p07_event_id_invalid",
            )
            citations.append(f"{event_id}@{serde_event_sha256(event)}")
    return citations


def validate_profile_evidence(profile: str, bundle: dict[str, Any]) -> None:
    lifecycle = typed_citations(
        bundle,
        lambda signal: signal.get("kind") == "process"
        and signal.get("action") == "package_trigger"
        and signal.get("trigger") == "npm_lifecycle",
    )
    require(lifecycle, "p07_lifecycle_evidence_missing")
    coverage = bundle.get("coverage")
    require(
        isinstance(coverage, list)
        and any(isinstance(row, dict) and row.get("state") == "incomplete" for row in coverage),
        "p07_incomplete_coverage_not_preserved",
    )
    if profile != "ci_true":
        return
    canary = typed_citations(
        bundle,
        lambda signal: (
            signal.get("kind") == "filesystem"
            and signal.get("operation") == "read"
            and signal.get("target") == "credential_file"
        )
        or (
            signal.get("kind") == "canary"
            and signal.get("action") == "read"
            and signal.get("canary") == "npm_token"
        ),
    )
    connects = typed_citations(
        bundle,
        lambda signal: signal.get("kind") == "network"
        and signal.get("action") == "connect"
        and signal.get("destination") == "local_sinkhole",
    )
    require(canary, "p07_canary_evidence_missing")
    require(connects, "p07_sinkhole_evidence_missing")


def run_observers(
    plan: dict[str, Any], bundle_paths: dict[str, Path], runner: Runner
) -> dict[str, Path]:
    local = plan["local"]
    output_root = Path(local["output_root"])
    observer_root = output_root / "observer-results-final"
    observer_root.mkdir(mode=0o700)
    paths: dict[str, Path] = {}
    for profile in PROFILES:
        bundle_path = bundle_paths[profile]
        bundle_digest = sha256_file(bundle_path)
        state_root = output_root / "observer-state-final" / profile
        result = runner(
            [
                local["whoathere"]["path"],
                "behavior",
                "observe",
                str(bundle_path),
                "--bundle-sha256",
                bundle_digest,
                "--ai-provider",
                "codex",
                "--ai-client-path",
                local["codex_client"]["path"],
                "--ai-client-sha256",
                local["codex_client"]["sha256"],
                "--ai-model",
                local["model"],
                "--ai-auth-home",
                local["auth_home"],
                "--approve-hosted-behavior-review",
                "--state-dir",
                str(state_root),
                "--ai-timeout-seconds",
                str(local["timeout_seconds"]),
            ],
            None,
            local["timeout_seconds"] * 6 + 60,
        )
        content = bounded_result(result, {0, 20, 22}, "p07_codex_observer_failed")
        value = parse_json(content, "p07_codex_observer_result_invalid")
        require(
            value.get("schema_version") == OBSERVER_SCHEMA
            and value.get("provider") == "codex"
            and value.get("artifact_sha256") == plan["demo"]["artifact_sha256"]
            and value.get("bundle_sha256") == bundle_digest
            and value.get("observe_only") is True
            and value.get("admission_authority") is False
            and value.get("observed_clean") is False,
            "p07_codex_observer_binding_invalid",
        )
        path = observer_root / f"{profile}.json"
        write_new_private(path, content)
        paths[profile] = path
    return paths


def run_diagnostic(
    plan: dict[str, Any], report_path: Path, export_root: Path, observers: dict[str, Path], runner: Runner
) -> dict[str, Any]:
    script = plan["local"]["two_host_diagnostic"]["path"]
    argv = [
        sys.executable,
        script,
        "--remote-report",
        str(report_path),
        "--bundle-dir",
        str(export_root / "bundles"),
    ]
    for profile in PROFILES:
        argv.extend(["--observer-result", str(observers[profile])])
    result = runner(argv, None, 30)
    content = bounded_result(result, {20}, "p07_reconciliation_failed")
    value = parse_json(content, "p07_reconciliation_invalid")
    rows = value.get("bundles")
    require(
        value.get("schema_version") == DIAGNOSTIC_SCHEMA
        and value.get("verdict") == "diagnostic_detection"
        and value.get("diagnostic_only") is True
        and value.get("claim_bearing") is False
        and value.get("reconciliation_complete") is True
        and value.get("exact_artifact_sha256") == plan["demo"]["artifact_sha256"]
        and value.get("admission_authority") is False
        and value.get("observed_clean") is False
        and isinstance(rows, list)
        and len(rows) == 2,
        "p07_reconciliation_binding_invalid",
    )
    actions = {row.get("action_key"): row for row in rows if isinstance(row, dict)}
    require(set(actions) == set(ACTION_BY_PROFILE.values()), "p07_reconciliation_profile_set_invalid")
    eligible_finding_count = 0
    for profile in PROFILES:
        row = actions[ACTION_BY_PROFILE[profile]]
        findings = row.get("behavior_specific_findings")
        require(
            row.get("bundle_sha256") == sha256_file(
                export_root / "bundles" / ACTION_BY_PROFILE[profile] / "behavior-bundle.json"
            )
            and row.get("observer_result_sha256") == sha256_file(observers[profile])
            and isinstance(findings, list),
            "p07_reconciliation_finding_set_invalid",
        )
        eligible_finding_count += len(findings)
        for finding in findings:
            evidence = finding.get("evidence") if isinstance(finding, dict) else None
            require(
                isinstance(finding.get("kind"), str)
                and valid_sha256(finding.get("finding_sha256"))
                and isinstance(evidence, list)
                and bool(evidence)
                and all(
                    isinstance(ref, dict)
                    and isinstance(ref.get("event_id"), str)
                    and valid_sha256(ref.get("event_sha256"))
                    for ref in evidence
                ),
                "p07_reconciliation_citation_invalid",
            )
    require(eligible_finding_count > 0, "p07_reconciliation_finding_missing")
    write_new_private(
        Path(plan["local"]["output_root"]) / "reconciliation.json",
        content,
    )
    return value


def load_observer_findings(
    plan: dict[str, Any],
    observers: dict[str, Path],
    bundles: dict[str, dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    projected: dict[str, list[dict[str, Any]]] = {}
    for profile in PROFILES:
        raw = read_regular(observers[profile], MAX_JSON_BYTES, "p07_observer_result_invalid")
        value = parse_json(raw, "p07_observer_result_invalid")
        bundle = bundles[profile]
        bundle_sha256 = sha256_file(
            Path(plan["local"]["output_root"])
            / "export"
            / "bundles"
            / ACTION_BY_PROFILE[profile]
            / "behavior-bundle.json"
        )
        panel = value.get("panel")
        correlation = panel.get("correlation_report") if isinstance(panel, dict) else None
        require(
            value.get("schema_version") == OBSERVER_SCHEMA
            and value.get("bundle_sha256") == bundle_sha256
            and value.get("observe_only") is True
            and value.get("admission_authority") is False
            and value.get("observed_clean") is False
            and isinstance(correlation, dict)
            and correlation.get("bundle_sha256") == bundle_sha256
            and correlation.get("positive_preservation_verified") is True,
            "p07_observer_correlation_invalid",
        )
        events = {
            event.get("event_id"): serde_event_sha256(event)
            for event in bundle.get("events", [])
            if isinstance(event, dict) and isinstance(event.get("event_id"), str)
        }
        findings = correlation.get("findings")
        require(isinstance(findings, list) and findings, "p07_observer_finding_missing")
        rows: list[dict[str, Any]] = []
        for finding in findings:
            evidence = finding.get("evidence") if isinstance(finding, dict) else None
            require(
                isinstance(finding.get("kind"), str)
                and SAFE_EVENT_ID.fullmatch(finding["kind"]) is not None
                and valid_sha256(finding.get("finding_sha256"))
                and isinstance(evidence, list)
                and evidence,
                "p07_observer_finding_invalid",
            )
            citations: list[dict[str, str]] = []
            for reference in evidence:
                event_id = reference.get("event_id") if isinstance(reference, dict) else None
                require(
                    isinstance(event_id, str)
                    and reference.get("event_sha256") == events.get(event_id),
                    "p07_observer_citation_invalid",
                )
                citations.append(
                    {"event_id": event_id, "event_sha256": reference["event_sha256"]}
                )
            rows.append(
                {
                    "kind": finding["kind"],
                    "finding_sha256": finding["finding_sha256"],
                    "evidence": citations,
                }
            )
        projected[profile] = rows
    return projected


def render_transcript(
    plan: dict[str, Any],
    remote_result: dict[str, Any],
    bundles: dict[str, dict[str, Any]],
    diagnostic: dict[str, Any],
    observer_findings: dict[str, list[dict[str, Any]]],
    *,
    execution_mode: str,
    resume_binding_sha256: str | None = None,
) -> str:
    require(
        execution_mode in {"fresh_end_to_end", "resumed_local_from_preserved_export"},
        "p07_transcript_execution_mode_invalid",
    )
    require(
        (execution_mode == "fresh_end_to_end" and resume_binding_sha256 is None)
        or (
            execution_mode == "resumed_local_from_preserved_export"
            and valid_sha256(resume_binding_sha256)
        ),
        "p07_transcript_resume_binding_invalid",
    )
    rows = {row["action_key"]: row for row in diagnostic["bundles"]}
    safety = {row["profile"]: row for row in remote_result["profiles"]}
    lines = [
        "BLOCK - suspicious package capability and behavior observed in disposable VM",
        "P07 inert end-to-end demonstration: complete (diagnostic only; not a malware benchmark)",
        (
            "Execution mode: fresh end-to-end invocation"
            if execution_mode == "fresh_end_to_end"
            else "Execution mode: resumed local completion from preserved sanitized export"
        ),
        *(
            [f"Resume binding: {resume_binding_sha256}"]
            if resume_binding_sha256 is not None
            else []
        ),
        f"Artifact: {remote_result['artifact_sha256']}",
        f"Manifest: {remote_result['manifest_sha256']}",
        f"Scenario plan: {remote_result['scenario_plan_sha256']}",
        f"Detonation result: {remote_result['detonation_result_sha256']}",
        "Profiles:",
    ]
    for profile in PROFILES:
        bundle = bundles[profile]
        row = rows[ACTION_BY_PROFILE[profile]]
        proof = safety[profile]
        lifecycle = typed_citations(
            bundle,
            lambda signal: signal.get("kind") == "process"
            and signal.get("action") == "package_trigger"
            and signal.get("trigger") == "npm_lifecycle",
        )
        canary = typed_citations(
            bundle,
            lambda signal: (
                signal.get("kind") == "filesystem"
                and signal.get("operation") == "read"
                and signal.get("target") == "credential_file"
            )
            or (
                signal.get("kind") == "canary"
                and signal.get("action") == "read"
                and signal.get("canary") == "npm_token"
            ),
        )
        network = typed_citations(
            bundle,
            lambda signal: signal.get("kind") == "network"
            and signal.get("action") in {"connect", "send"}
            and signal.get("destination") == "local_sinkhole",
        )
        lines.extend(
            [
                f"- CI={'true' if profile == 'ci_true' else 'false'}",
                f"  Bundle: {proof['bundle_sha256']}",
                f"  Observer result: {row['observer_result_sha256']}",
                f"  Execution result: {proof['execution_result_sha256']}",
                f"  Root receipt: {proof['root_receipt_sha256']}",
                f"  Host receipt: {proof['host_receipt_sha256']}",
                f"  Lifecycle evidence: {', '.join(lifecycle)}",
                "  Protected fake-canary access: " + (", ".join(canary) if canary else "not observed"),
                "  Local-sinkhole network intent: " + (", ".join(network) if network else "not observed"),
                "  Codex findings:",
            ]
        )
        for finding in observer_findings[profile]:
            citations = ", ".join(
                f"{reference['event_id']}@{reference['event_sha256']}"
                for reference in finding["evidence"]
            )
            lines.append(f"    - {finding['kind']} [{citations}]")
        lines.append("  Coverage: incomplete; never interpreted as clean")
    lines.extend(
        [
            "Safety invariants (receipt-bound):",
            *[f"- {name.replace('_', ' ')}: 0" for name in INVARIANTS],
            "Package-written fixture markers: supporting-only; never used as authenticated findings",
            "Authority: Codex is observe-only; this result cannot install, contain, admit, allow, sync back, or declare clean",
        ]
    )
    transcript = "\n".join(lines) + "\n"
    require("/Users/" not in transcript and "127.0.0.1" not in transcript, "p07_transcript_private_path_leak")
    require("whoathere_fake_" not in transcript and "ALLOW" not in transcript, "p07_transcript_unsafe_content")
    return transcript


def run_demo(
    input_path: Path,
    input_sha256: str,
    ssh_config: Path,
    *,
    runner: Runner = default_runner,
) -> str:
    plan, _ = load_plan(input_path, input_sha256)
    verify_local_prerequisites(plan, ssh_config)
    run_preflight(plan, ssh_config, runner)
    remote_result = run_remote(plan, input_sha256, ssh_config, runner)
    export_root = copy_sanitized_export(plan, ssh_config, remote_result, runner)
    report_path, bundle_paths, bundles = validate_export(plan, export_root, remote_result)
    observers = run_observers(plan, bundle_paths, runner)
    diagnostic = run_diagnostic(plan, report_path, export_root, observers, runner)
    observer_findings = load_observer_findings(plan, observers, bundles)
    transcript = render_transcript(
        plan,
        remote_result,
        bundles,
        diagnostic,
        observer_findings,
        execution_mode="fresh_end_to_end",
    )
    write_new_private(Path(plan["local"]["output_root"]) / "transcript.txt", transcript.encode())
    return transcript


def resume_sanitized_local(
    input_path: Path,
    input_sha256: str,
    ssh_config: Path,
    *,
    runner: Runner = default_runner,
) -> str:
    """Finish only the local observe/reconcile stages after a preserved remote success."""

    plan, _ = load_plan(input_path, input_sha256)
    verify_local_prerequisites(plan, ssh_config, require_fresh_output=False)
    output_root = Path(plan["local"]["output_root"])
    require(
        not any(
            (output_root / name).exists()
            for name in (
                "observer-results-final",
                "observer-state-final",
                "reconciliation.json",
                "transcript.txt",
            )
        ),
        "p07_local_resume_not_fresh",
        64,
    )
    remote_result_raw = read_regular(
        output_root / "remote-result.json",
        MAX_JSON_BYTES,
        "p07_remote_result_invalid",
    )
    remote_result = parse_json(remote_result_raw, "p07_remote_result_invalid")
    validate_remote_result(plan, input_sha256, remote_result)
    export_root = output_root / "export"
    report_path, bundle_paths, bundles = validate_export(plan, export_root, remote_result)
    observers = run_observers(plan, bundle_paths, runner)
    diagnostic = run_diagnostic(plan, report_path, export_root, observers, runner)
    observer_findings = load_observer_findings(plan, observers, bundles)
    resume_binding_sha256 = canonical_sha256(
        {
            "input_sha256": input_sha256,
            "remote_result_sha256": sha256_bytes(remote_result_raw),
            "export_manifest_sha256": remote_result["export_manifest_sha256"],
        }
    )
    transcript = render_transcript(
        plan,
        remote_result,
        bundles,
        diagnostic,
        observer_findings,
        execution_mode="resumed_local_from_preserved_export",
        resume_binding_sha256=resume_binding_sha256,
    )
    write_new_private(output_root / "transcript.txt", transcript.encode())
    return transcript


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--ssh-config", required=True, type=Path)
    parser.add_argument("--resume-sanitized-local", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        function = resume_sanitized_local if args.resume_sanitized_local else run_demo
        transcript = function(
            args.input.expanduser(), args.input_sha256, args.ssh_config.expanduser()
        )
    except DemoError as error:
        print(f"P07 ERROR {error.reason_code}")
        return error.exit_code
    print(transcript, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
