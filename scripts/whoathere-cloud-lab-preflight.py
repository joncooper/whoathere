#!/usr/bin/env python3
"""Return one actionable readiness result for an exact WhoaThere cloud-lab plan."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


INPUT_SCHEMA = "whoathere.cloud_lab_preflight_input.v1"
PROBE_SCHEMA = "whoathere.cloud_lab_preflight_probe.v1"
RESULT_SCHEMA = "whoathere.cloud_lab_preflight_result.v1"
MAX_INPUT_BYTES = 64 * 1024
MAX_COMMAND_OUTPUT_BYTES = 256 * 1024
FILE_LABELS = (
    "whoathere_bin",
    "vm_helper",
    "runtime_record",
    "detonation_config",
    "policy",
    "sanitizer",
)
STORAGE_LABELS = ("custody_root", "evidence_root", "sanitized_root", "clone_root")
SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:@%+=,-]{0,159}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
GIT_COMMIT = re.compile(r"[0-9a-f]{40}")


class InputError(Exception):
    pass


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


Runner = Callable[[list[str], bytes | None, int], CommandResult]


@dataclass(frozen=True)
class PreflightResult:
    status: str
    exit_code: int
    input_sha256: str
    attempt: int
    blocker_code: str | None
    detail: str | None
    action: str | None
    bindings: dict[str, Any]

    def as_json(self) -> dict[str, Any]:
        return {
            "schema_version": RESULT_SCHEMA,
            "status": self.status,
            "exit_code": self.exit_code,
            "input_sha256": self.input_sha256,
            "attempt": self.attempt,
            "blocker": (
                None
                if self.blocker_code is None
                else {
                    "code": self.blocker_code,
                    "detail": self.detail,
                    "action": self.action,
                }
            ),
            "bindings": self.bindings,
            "artifact_opened": False,
            "package_executed": False,
            "vm_started": False,
            "remote_state_mutated": False,
            "clearance_consumed": False,
        }


def exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise InputError(f"{label}_shape_invalid")
    return value


def safe_token(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if value == "" and allow_empty:
        return value
    if not isinstance(value, str) or SAFE_TOKEN.fullmatch(value) is None:
        raise InputError(f"{label}_invalid")
    return value


def digest_value(value: Any, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise InputError(f"{label}_invalid")
    return value


def absolute_path(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or len(value) > 1024
        or "\x00" in value
        or any(part in {"", ".", ".."} for part in value.split("/")[1:])
    ):
        raise InputError(f"{label}_invalid")
    return value


def parse_json_strict(content: bytes, label: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise InputError(f"{label}_duplicate_field")
            result[key] = value
        return result

    try:
        return json.loads(content.decode("utf-8"), object_pairs_hook=pairs)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InputError(f"{label}_json_invalid") from exc


def read_exact_file(path: Path, expected_sha256: str) -> tuple[bytes, str]:
    if not path.is_absolute():
        raise InputError("input_path_not_absolute")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InputError("input_unreadable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0:
            raise InputError("input_not_regular_nonempty")
        if metadata.st_size > MAX_INPUT_BYTES:
            raise InputError("input_too_large")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise InputError("input_permissions_not_private")
        content = b""
        while len(content) < metadata.st_size:
            chunk = os.read(descriptor, metadata.st_size - len(content))
            if not chunk:
                raise InputError("input_changed_during_read")
            content += chunk
        if os.read(descriptor, 1):
            raise InputError("input_changed_during_read")
        after = os.fstat(descriptor)
        if (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise InputError("input_changed_during_read")
    finally:
        os.close(descriptor)
    actual = "sha256:" + hashlib.sha256(content).hexdigest()
    if actual != digest_value(expected_sha256, "input_sha256"):
        raise InputError("input_sha256_mismatch")
    return content, actual


def validate_input(value: Any) -> dict[str, Any]:
    plan = exact_keys(
        value,
        {
            "schema_version",
            "attempt",
            "ssh",
            "authorization",
            "provider",
            "run_binding",
            "host_controls",
            "storage",
            "clearance",
        },
        "input",
    )
    if (
        plan["schema_version"] != INPUT_SCHEMA
        or type(plan["attempt"]) is not int
        or plan["attempt"] not in {0, 1}
    ):
        raise InputError("input_version_or_attempt_invalid")
    ssh = exact_keys(
        plan["ssh"],
        {"host_alias", "expected_hostname", "expected_user", "source_route_reference"},
        "ssh",
    )
    for key in ssh:
        safe_token(ssh[key], f"ssh_{key}")
    authorization = exact_keys(
        plan["authorization"],
        {
            "provider_approval_reference",
            "legal_approval_reference",
            "operator_authorization_reference",
            "planned_material",
        },
        "authorization",
    )
    for key in (
        "provider_approval_reference",
        "legal_approval_reference",
        "operator_authorization_reference",
    ):
        if not isinstance(authorization[key], str) or len(authorization[key]) > 160:
            raise InputError(f"authorization_{key}_invalid")
        if authorization[key] and SAFE_TOKEN.fullmatch(authorization[key]) is None:
            raise InputError(f"authorization_{key}_invalid")
    if authorization["planned_material"] not in {"inert_only", "restricted_malware"}:
        raise InputError("authorization_planned_material_invalid")
    provider = exact_keys(
        plan["provider"],
        {"name", "firewall_posture", "firewall_reference"},
        "provider",
    )
    safe_token(provider["name"], "provider_name")
    if provider["firewall_posture"] not in {
        "cloud_default_deny",
        "provider_unavailable_host_pf",
    }:
        raise InputError("provider_firewall_posture_invalid")
    if not isinstance(provider["firewall_reference"], str) or len(
        provider["firewall_reference"]
    ) > 160:
        raise InputError("provider_firewall_reference_invalid")
    if provider["firewall_reference"] and SAFE_TOKEN.fullmatch(
        provider["firewall_reference"]
    ) is None:
        raise InputError("provider_firewall_reference_invalid")

    binding = exact_keys(
        plan["run_binding"],
        {"checkout_path", "git_commit", "campaign_id", "profile_id", "files"},
        "run_binding",
    )
    absolute_path(binding["checkout_path"], "run_binding_checkout_path")
    if not isinstance(binding["git_commit"], str) or GIT_COMMIT.fullmatch(
        binding["git_commit"]
    ) is None:
        raise InputError("run_binding_git_commit_invalid")
    safe_token(binding["campaign_id"], "run_binding_campaign_id")
    safe_token(binding["profile_id"], "run_binding_profile_id")
    if not isinstance(binding["files"], list) or len(binding["files"]) != len(FILE_LABELS):
        raise InputError("run_binding_files_invalid")
    binding_paths: list[str] = []
    for expected_label, item in zip(FILE_LABELS, binding["files"]):
        row = exact_keys(item, {"label", "path", "sha256"}, "run_binding_file")
        if row["label"] != expected_label:
            raise InputError("run_binding_file_order_invalid")
        binding_paths.append(
            absolute_path(row["path"], f"run_binding_{expected_label}_path")
        )
        digest_value(row["sha256"], f"run_binding_{expected_label}_sha256")
    if len(set(binding_paths)) != len(FILE_LABELS):
        raise InputError("run_binding_file_paths_not_distinct")

    controls = exact_keys(
        plan["host_controls"],
        {"pf_info", "pf_rules", "lulu_evidence", "max_age_seconds", "sinkhole"},
        "host_controls",
    )
    if (
        not isinstance(controls["max_age_seconds"], int)
        or isinstance(controls["max_age_seconds"], bool)
        or not 60 <= controls["max_age_seconds"] <= 86400
    ):
        raise InputError("host_controls_max_age_invalid")
    for label in ("pf_info", "pf_rules", "lulu_evidence"):
        item = exact_keys(controls[label], {"path", "sha256"}, f"host_controls_{label}")
        absolute_path(item["path"], f"host_controls_{label}_path")
        digest_value(item["sha256"], f"host_controls_{label}_sha256")
    sinkhole = exact_keys(
        controls["sinkhole"], {"host", "port", "reference"}, "host_controls_sinkhole"
    )
    if sinkhole["host"] not in {"127.0.0.1", "::1"}:
        raise InputError("host_controls_sinkhole_not_loopback")
    if (
        not isinstance(sinkhole["port"], int)
        or isinstance(sinkhole["port"], bool)
        or not 1 <= sinkhole["port"] <= 65535
    ):
        raise InputError("host_controls_sinkhole_port_invalid")
    safe_token(sinkhole["reference"], "host_controls_sinkhole_reference")

    storage = exact_keys(plan["storage"], set(STORAGE_LABELS), "storage")
    for label in STORAGE_LABELS:
        absolute_path(storage[label], f"storage_{label}")
    if len(set(storage.values())) != len(STORAGE_LABELS):
        raise InputError("storage_paths_not_distinct")

    clearance = exact_keys(
        plan["clearance"],
        {"mode", "path", "sha256", "latest_contamination_at_utc"},
        "clearance",
    )
    if authorization["planned_material"] == "inert_only":
        if clearance != {
            "mode": "not_required_inert",
            "path": None,
            "sha256": None,
            "latest_contamination_at_utc": None,
        }:
            raise InputError("inert_clearance_posture_invalid")
    else:
        if clearance["mode"] != "required_restricted":
            raise InputError("restricted_clearance_required")
        absolute_path(clearance["path"], "clearance_path")
        digest_value(clearance["sha256"], "clearance_sha256")
        if not isinstance(clearance["latest_contamination_at_utc"], str):
            raise InputError("clearance_latest_contamination_invalid")
    return plan


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
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout if isinstance(exc.stdout, bytes) else b""
        stderr = exc.stderr if isinstance(exc.stderr, bytes) else b""
        return CommandResult(124, stdout, stderr, True)


REMOTE_PROBE_SOURCE = r'''
import base64, datetime as dt, getpass, hashlib, json, os, pathlib, re, socket, stat, subprocess

plan = json.loads(base64.b64decode("__PLAN_B64__").decode("utf-8"))

def sha(path):
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()

def file_state(item):
    path = pathlib.Path(item["path"])
    try:
        meta = path.lstat()
        regular = stat.S_ISREG(meta.st_mode) and not path.is_symlink() and meta.st_size > 0
    except OSError:
        return {"regular": False, "sha256": None}
    return {"regular": regular, "sha256": sha(path) if regular else None}

def boot_epoch():
    try:
        result = subprocess.run(
            ["/usr/sbin/sysctl", "-n", "kern.boottime"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=3,
            check=False,
        )
        match = re.search(r"sec = ([0-9]+)", result.stdout)
        return float(match.group(1)) if result.returncode == 0 and match else None
    except Exception:
        return None

booted_at = boot_epoch()

def fresh_file(item, max_age):
    path = pathlib.Path(item["path"])
    state = file_state(item)
    try:
        observed_mtime = path.stat().st_mtime
        age = max(0.0, dt.datetime.now(dt.timezone.utc).timestamp() - observed_mtime)
    except OSError:
        observed_mtime = 0
        age = max_age + 1
    state["fresh"] = (
        state["regular"]
        and age <= max_age
        and booted_at is not None
        and observed_mtime >= booted_at
    )
    return state

def storage_state(value):
    path = pathlib.Path(value)
    try:
        meta = path.lstat()
        directory = stat.S_ISDIR(meta.st_mode) and not path.is_symlink()
        return {
            "directory": directory,
            "private": directory and stat.S_IMODE(meta.st_mode) & 0o077 == 0,
            "writable": directory and os.access(path, os.W_OK | os.X_OK),
        }
    except OSError:
        return {"directory": False, "private": False, "writable": False}

max_age = plan["host_controls"]["max_age_seconds"]
pf_info = fresh_file(plan["host_controls"]["pf_info"], max_age)
pf_rules = fresh_file(plan["host_controls"]["pf_rules"], max_age)
info_text = ""
rules_text = ""
if pf_info["regular"]:
    info_text = pathlib.Path(plan["host_controls"]["pf_info"]["path"]).read_text(errors="replace")
if pf_rules["regular"]:
    rules_text = pathlib.Path(plan["host_controls"]["pf_rules"]["path"]).read_text(errors="replace")
blanket = inbound = outbound = False
for line in rules_text.splitlines():
    tokens = line.lower().split()
    if not tokens or tokens[0] != "block" or "all" not in tokens:
        continue
    if "in" in tokens:
        inbound = True
    elif "out" in tokens:
        outbound = True
    else:
        blanket = True

lulu = fresh_file(plan["host_controls"]["lulu_evidence"], max_age)
lulu_enabled = lulu_filtering = False
if lulu["regular"]:
    try:
        value = json.loads(pathlib.Path(plan["host_controls"]["lulu_evidence"]["path"]).read_text())
        lulu_enabled = value.get("enabled") is True
        lulu_filtering = value.get("filtering") is True
    except Exception:
        pass

sinkhole_listening = False
try:
    with socket.create_connection(
        (plan["host_controls"]["sinkhole"]["host"], plan["host_controls"]["sinkhole"]["port"]),
        timeout=1.0,
    ):
        sinkhole_listening = True
except OSError:
    pass

identities = {item["label"]: file_state(item) for item in plan["run_binding"]["files"]}

def command_output(argv):
    try:
        result = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3, check=False)
        return result.returncode, result.stdout.strip()
    except Exception:
        return 127, ""

git_code, git_commit = command_output(["/usr/bin/git", "-C", plan["run_binding"]["checkout_path"], "rev-parse", "HEAD"])
hv_code, hv_value = command_output(["/usr/sbin/sysctl", "-n", "kern.hv_support"])
gui_code, gui_value = command_output(["/usr/bin/pgrep", "-x", "WindowServer"])
stale_count = 0
for name in ("whoathere-linux-vz-package-execution", "whoathere-linux-vz-package-runtime"):
    code, output = command_output(["/usr/bin/pgrep", "-x", name])
    if code == 0:
        stale_count += len([line for line in output.splitlines() if line.strip()])

storage = {label: storage_state(plan["storage"][label]) for label in ("custody_root", "evidence_root", "sanitized_root", "clone_root")}
clone_count = None
if storage["clone_root"]["directory"]:
    try:
        clone_count = sum(1 for _ in os.scandir(plan["storage"]["clone_root"]))
    except OSError:
        clone_count = None

clearance_plan = plan["clearance"]
clearance = {"required": clearance_plan["mode"] == "required_restricted", "valid": True, "fresh": True, "consumed": False, "sha256": None}
if clearance["required"]:
    state = file_state({"path": clearance_plan["path"]})
    clearance["sha256"] = state["sha256"]
    clearance["valid"] = state["regular"] and state["sha256"] == clearance_plan["sha256"]
    clearance["fresh"] = False
    if clearance["valid"]:
        try:
            value = json.loads(pathlib.Path(clearance_plan["path"]).read_text())
            created = dt.datetime.fromisoformat(value.get("created_at_utc", "").replace("Z", "+00:00"))
            latest = dt.datetime.fromisoformat(clearance_plan["latest_contamination_at_utc"].replace("Z", "+00:00"))
            core_true = (
                "ready_for_live_malware",
                "previous_contamination_resolved",
                "host_rebuilt_or_cleared",
                "vm_state_rebuilt_or_pruned",
                "no_live_malware_execution_since_clearance",
                "host_firewall_default_deny_verified",
                "lulu_secondary_control_enabled",
            )
            clearance["valid"] = (
                value.get("schema") == "whoathere.actual_malware.scaleway_clearance.v1"
                and all(value.get(key) is True for key in core_true)
            )
            clearance["fresh"] = clearance["valid"] and created > latest
        except Exception:
            clearance["valid"] = False
    marker_name = hashlib.sha256(clearance_plan["sha256"].encode("utf-8")).hexdigest() + ".json"
    marker_path = pathlib.Path(plan["storage"]["evidence_root"]) / "clearance-consumption" / marker_name
    try:
        marker_path.lstat()
        clearance["consumed"] = True
    except FileNotFoundError:
        clearance["consumed"] = False
    except OSError:
        clearance["consumed"] = True

host_name = socket.gethostname()
host_id = "sha256:" + hashlib.sha256((host_name + "\x00" + getpass.getuser()).encode()).hexdigest()
result = {
    "schema_version": "whoathere.cloud_lab_preflight_probe.v1",
    "host": {"hostname": host_name, "user": getpass.getuser(), "ssh_session": bool(os.environ.get("SSH_CONNECTION")), "host_id_sha256": host_id},
    "platform": {
        "vz_framework": pathlib.Path("/System/Library/Frameworks/Virtualization.framework").is_dir(),
        "hypervisor_supported": hv_code == 0 and hv_value == "1",
        "gui_session_present": gui_code == 0 and bool(gui_value),
    },
    "identities": {"git_commit": git_commit if git_code == 0 else None, "files": identities},
    "controls": {
        "pf_info_sha256": pf_info["sha256"], "pf_rules_sha256": pf_rules["sha256"],
        "pf_fresh": pf_info["fresh"] and pf_rules["fresh"], "pf_enabled": "Status: Enabled" in info_text,
        "pf_default_deny": blanket or (inbound and outbound), "lulu_sha256": lulu["sha256"],
        "lulu_fresh": lulu["fresh"], "lulu_enabled": lulu_enabled, "lulu_filtering": lulu_filtering,
        "sinkhole_listening": sinkhole_listening,
    },
    "storage": storage,
    "stale_state": {"process_count": stale_count, "clone_count": clone_count},
    "clearance": clearance,
    "safety": {"artifact_opened": False, "package_executed": False, "vm_started": False, "remote_state_mutated": False, "clearance_consumed": False},
}
print(json.dumps(result, sort_keys=True, separators=(",", ":")))
'''


def build_remote_source(plan_bytes: bytes) -> bytes:
    encoded = base64.b64encode(plan_bytes).decode("ascii")
    return REMOTE_PROBE_SOURCE.replace("__PLAN_B64__", encoded).encode("utf-8")


def parse_ssh_config(content: bytes) -> dict[str, str]:
    if len(content) > MAX_COMMAND_OUTPUT_BYTES:
        raise InputError("ssh_config_output_too_large")
    result: dict[str, str] = {}
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputError("ssh_config_output_invalid") from exc
    for line in text.splitlines():
        key, separator, value = line.partition(" ")
        if separator and key in {"hostname", "user"} and key not in result:
            result[key] = value.strip()
    if not result.get("hostname") or not result.get("user"):
        raise InputError("ssh_config_output_invalid")
    return result


def parse_probe(content: bytes) -> dict[str, Any]:
    if not content or len(content) > MAX_COMMAND_OUTPUT_BYTES:
        raise InputError("probe_output_size_invalid")
    value = parse_json_strict(content, "probe")
    probe = exact_keys(
        value,
        {
            "schema_version",
            "host",
            "platform",
            "identities",
            "controls",
            "storage",
            "stale_state",
            "clearance",
            "safety",
        },
        "probe",
    )
    if probe["schema_version"] != PROBE_SCHEMA:
        raise InputError("probe_schema_invalid")
    host = exact_keys(
        probe["host"],
        {"hostname", "user", "ssh_session", "host_id_sha256"},
        "probe_host",
    )
    if not isinstance(host["hostname"], str) or not isinstance(host["user"], str):
        raise InputError("probe_host_identity_invalid")
    if type(host["ssh_session"]) is not bool:
        raise InputError("probe_host_session_invalid")
    digest_value(host["host_id_sha256"], "probe_host_id_sha256")
    platform = exact_keys(
        probe["platform"],
        {"vz_framework", "hypervisor_supported", "gui_session_present"},
        "probe_platform",
    )
    if any(type(platform[key]) is not bool for key in platform):
        raise InputError("probe_platform_value_invalid")
    identities = exact_keys(probe["identities"], {"git_commit", "files"}, "probe_identities")
    if identities["git_commit"] is not None and (
        not isinstance(identities["git_commit"], str)
        or GIT_COMMIT.fullmatch(identities["git_commit"]) is None
    ):
        raise InputError("probe_git_commit_invalid")
    if not isinstance(identities["files"], dict) or set(identities["files"]) != set(FILE_LABELS):
        raise InputError("probe_identity_files_invalid")
    for label in FILE_LABELS:
        identity = exact_keys(
            identities["files"][label], {"regular", "sha256"}, "probe_identity_file"
        )
        if type(identity["regular"]) is not bool:
            raise InputError("probe_identity_regular_invalid")
        if identity["sha256"] is not None:
            digest_value(identity["sha256"], "probe_identity_sha256")
    controls = exact_keys(
        probe["controls"],
        {
            "pf_info_sha256",
            "pf_rules_sha256",
            "pf_fresh",
            "pf_enabled",
            "pf_default_deny",
            "lulu_sha256",
            "lulu_fresh",
            "lulu_enabled",
            "lulu_filtering",
            "sinkhole_listening",
        },
        "probe_controls",
    )
    for key in ("pf_info_sha256", "pf_rules_sha256", "lulu_sha256"):
        if controls[key] is not None:
            digest_value(controls[key], f"probe_controls_{key}")
    for key in (
        "pf_fresh",
        "pf_enabled",
        "pf_default_deny",
        "lulu_fresh",
        "lulu_enabled",
        "lulu_filtering",
        "sinkhole_listening",
    ):
        if type(controls[key]) is not bool:
            raise InputError(f"probe_controls_{key}_invalid")
    storage = exact_keys(probe["storage"], set(STORAGE_LABELS), "probe_storage")
    for label in STORAGE_LABELS:
        item = exact_keys(
            storage[label], {"directory", "private", "writable"}, "probe_storage_item"
        )
        if any(type(item[key]) is not bool for key in item):
            raise InputError("probe_storage_value_invalid")
    stale = exact_keys(
        probe["stale_state"], {"process_count", "clone_count"}, "probe_stale_state"
    )
    for key in stale:
        if stale[key] is not None and (
            not isinstance(stale[key], int)
            or isinstance(stale[key], bool)
            or stale[key] < 0
        ):
            raise InputError("probe_stale_state_value_invalid")
    clearance = exact_keys(
        probe["clearance"],
        {"required", "valid", "fresh", "consumed", "sha256"},
        "probe_clearance",
    )
    for key in ("required", "valid", "fresh", "consumed"):
        if type(clearance[key]) is not bool:
            raise InputError(f"probe_clearance_{key}_invalid")
    if clearance["sha256"] is not None:
        digest_value(clearance["sha256"], "probe_clearance_sha256")
    safety = exact_keys(
        probe["safety"],
        {"artifact_opened", "package_executed", "vm_started", "remote_state_mutated", "clearance_consumed"},
        "probe_safety",
    )
    if any(type(value) is not bool or value is not False for value in safety.values()):
        raise InputError("probe_safety_posture_invalid")
    return probe


ACTIONS = {
    "AUTHORIZATION_INVALID": "Record fresh provider, legal, and operator authorization references, then rerun.",
    "PROVIDER_FIREWALL_INVALID": "Restore the approved provider firewall posture and attach its current reference, then rerun.",
    "SSH_ROUTE_INVALID": "Restore the approved SSH route and host binding, then rerun.",
    "HOST_IDENTITY_INVALID": "Restore the approved cloud Mac identity or approve and bind the replacement host, then rerun.",
    "IDENTITY_MISMATCH": "Restage the approved code/runtime/policy bundle and issue a new exact input; do not bless the observed digest.",
    "PF_INVALID": "Capture fresh privileged PF evidence with PF enabled and the approved default-deny rules, then rerun.",
    "LULU_INVALID": "Enable LuLu filtering in the logged-in GUI session and attach fresh health evidence, then rerun.",
    "SINKHOLE_INVALID": "Start the approved loopback sinkhole at the pinned address and port, then rerun.",
    "VZ_INVALID": "Restore Apple Virtualization, hypervisor, and logged-in GUI prerequisites, then rerun.",
    "STORAGE_INVALID": "Restore private writable custody, evidence, and sanitized-export directories, then rerun.",
    "STALE_STATE": "Run the approved cleanup procedure so no helper process or disposable clone remains, then rerun.",
    "CLEARANCE_INVALID": "Issue fresh unconsumed clearance bound to this campaign after resolving prior contamination, then rerun.",
}


def blocked(plan: dict[str, Any], digest: str, code: str, detail: str) -> PreflightResult:
    action = (
        "PARK P06; record this blocker and do not start P07."
        if plan["attempt"] == 1
        else ACTIONS[code]
    )
    return PreflightResult(
        "blocked",
        20,
        digest,
        plan["attempt"],
        code,
        detail,
        action,
        {
            "campaign_id": plan["run_binding"]["campaign_id"],
            "profile_id": plan["run_binding"]["profile_id"],
            "git_commit": plan["run_binding"]["git_commit"],
        },
    )


def evaluate_probe(plan: dict[str, Any], digest: str, probe: dict[str, Any]) -> PreflightResult:
    host = probe["host"]
    expected_host_id = "sha256:" + hashlib.sha256(
        (host["hostname"] + "\x00" + host["user"]).encode("utf-8")
    ).hexdigest()
    if (
        host["hostname"] != plan["ssh"]["expected_hostname"]
        or host["user"] != plan["ssh"]["expected_user"]
        or host["ssh_session"] is not True
        or host["host_id_sha256"] != expected_host_id
    ):
        return blocked(plan, digest, "HOST_IDENTITY_INVALID", "remote host identity did not match")
    identities = probe["identities"]
    if identities["git_commit"] != plan["run_binding"]["git_commit"]:
        return blocked(plan, digest, "IDENTITY_MISMATCH", "checkout identity did not match")
    expected_files = {item["label"]: item for item in plan["run_binding"]["files"]}
    for label in FILE_LABELS:
        observed = identities["files"][label]
        if observed["regular"] is not True or observed["sha256"] != expected_files[label]["sha256"]:
            return blocked(plan, digest, "IDENTITY_MISMATCH", f"{label} identity did not match")
    controls = probe["controls"]
    if (
        controls["pf_info_sha256"] != plan["host_controls"]["pf_info"]["sha256"]
        or controls["pf_rules_sha256"] != plan["host_controls"]["pf_rules"]["sha256"]
        or controls["pf_fresh"] is not True
        or controls["pf_enabled"] is not True
        or controls["pf_default_deny"] is not True
    ):
        return blocked(plan, digest, "PF_INVALID", "host PF evidence was stale, mismatched, or not default-deny")
    if (
        controls["lulu_sha256"] != plan["host_controls"]["lulu_evidence"]["sha256"]
        or controls["lulu_fresh"] is not True
        or controls["lulu_enabled"] is not True
        or controls["lulu_filtering"] is not True
    ):
        return blocked(plan, digest, "LULU_INVALID", "LuLu evidence was stale, mismatched, or not filtering")
    if controls["sinkhole_listening"] is not True:
        return blocked(plan, digest, "SINKHOLE_INVALID", "approved loopback sinkhole was unavailable")
    platform = probe["platform"]
    if not all(platform.get(key) is True for key in ("vz_framework", "hypervisor_supported", "gui_session_present")):
        return blocked(plan, digest, "VZ_INVALID", "Apple Virtualization or GUI prerequisite was unavailable")
    for label in STORAGE_LABELS:
        item = probe["storage"][label]
        if item["directory"] is not True or item["private"] is not True or item["writable"] is not True:
            return blocked(plan, digest, "STORAGE_INVALID", f"{label} was not private and writable")
    stale = probe["stale_state"]
    if stale["process_count"] != 0 or stale["clone_count"] != 0:
        return blocked(plan, digest, "STALE_STATE", "stale helper process or disposable clone remained")
    clearance = probe["clearance"]
    clearance_required = plan["clearance"]["mode"] == "required_restricted"
    if clearance["required"] is not clearance_required:
        return blocked(plan, digest, "CLEARANCE_INVALID", "clearance applicability did not match the plan")
    if clearance_required:
        if (
            clearance["sha256"] != plan["clearance"]["sha256"]
            or clearance["valid"] is not True
            or clearance["fresh"] is not True
            or clearance["consumed"] is not False
        ):
            return blocked(plan, digest, "CLEARANCE_INVALID", "restricted-material clearance was invalid or stale")
    elif clearance != {
        "required": False,
        "valid": True,
        "fresh": True,
        "consumed": False,
        "sha256": None,
    }:
        return blocked(plan, digest, "CLEARANCE_INVALID", "inert clearance posture was contradictory")
    bindings = {
        "campaign_id": plan["run_binding"]["campaign_id"],
        "profile_id": plan["run_binding"]["profile_id"],
        "git_commit": plan["run_binding"]["git_commit"],
        "host_id_sha256": host["host_id_sha256"],
        "identity_sha256s": {label: identities["files"][label]["sha256"] for label in FILE_LABELS},
    }
    return PreflightResult("ready", 0, digest, plan["attempt"], None, None, None, bindings)


def run_preflight(
    input_path: Path,
    input_sha256: str,
    ssh_config: Path | None,
    *,
    runner: Runner = default_runner,
    ssh_binary: str = "/usr/bin/ssh",
) -> PreflightResult:
    content, actual_sha256 = read_exact_file(input_path, input_sha256)
    plan = validate_input(parse_json_strict(content, "input"))
    authorization = plan["authorization"]
    if not all(
        authorization[key]
        for key in (
            "provider_approval_reference",
            "legal_approval_reference",
            "operator_authorization_reference",
        )
    ):
        return blocked(plan, actual_sha256, "AUTHORIZATION_INVALID", "required authorization reference was missing")
    if not plan["provider"]["firewall_reference"]:
        return blocked(plan, actual_sha256, "PROVIDER_FIREWALL_INVALID", "provider firewall reference was missing")

    base = [ssh_binary]
    if ssh_config is not None:
        if not ssh_config.is_absolute() or not ssh_config.is_file() or ssh_config.is_symlink():
            return blocked(plan, actual_sha256, "SSH_ROUTE_INVALID", "SSH configuration was unavailable")
        base.extend(["-F", str(ssh_config)])
    options = [
        "-o",
        "BatchMode=yes",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "PermitLocalCommand=no",
        "-o",
        "RequestTTY=no",
    ]
    config_result = runner(base + options + ["-G", plan["ssh"]["host_alias"]], None, 10)
    if (
        config_result.returncode != 0
        or config_result.timed_out
        or config_result.stderr and len(config_result.stderr) > MAX_COMMAND_OUTPUT_BYTES
    ):
        return blocked(plan, actual_sha256, "SSH_ROUTE_INVALID", "SSH route resolution failed")
    try:
        resolved = parse_ssh_config(config_result.stdout)
    except InputError:
        return blocked(plan, actual_sha256, "SSH_ROUTE_INVALID", "SSH route resolution was invalid")
    if resolved["user"] != plan["ssh"]["expected_user"]:
        return blocked(plan, actual_sha256, "SSH_ROUTE_INVALID", "SSH route resolved the wrong user")

    probe_result = runner(
        base
        + options
        + [
            "-o",
            "ConnectTimeout=10",
            "-T",
            plan["ssh"]["host_alias"],
            "/usr/bin/python3",
            "-",
        ],
        build_remote_source(content),
        30,
    )
    if (
        probe_result.returncode != 0
        or probe_result.timed_out
        or probe_result.stderr
        or len(probe_result.stdout) > MAX_COMMAND_OUTPUT_BYTES
    ):
        return blocked(plan, actual_sha256, "SSH_ROUTE_INVALID", "read-only SSH probe failed")
    try:
        probe = parse_probe(probe_result.stdout)
    except InputError:
        return blocked(plan, actual_sha256, "SSH_ROUTE_INVALID", "read-only SSH probe output was invalid")
    return evaluate_probe(plan, actual_sha256, probe)


def render_human(result: PreflightResult) -> str:
    if result.status == "ready":
        return (
            f"READY P06 input={result.input_sha256} "
            f"campaign={result.bindings['campaign_id']} "
            f"host={result.bindings['host_id_sha256']} "
            f"profile={result.bindings['profile_id']}\n"
            "No artifact was opened, no package executed, no VM started, and no remote state changed."
        )
    if result.status == "error":
        return (
            f"ERROR {result.blocker_code}: {result.detail}\n"
            f"ACTION: {result.action}\n"
            "No artifact was opened, no package executed, no VM started, and no remote state changed."
        )
    return (
        f"BLOCKED {result.blocker_code}: {result.detail}\n"
        f"ACTION: {result.action}\n"
        "No artifact was opened, no package executed, no VM started, and no remote state changed."
    )


def error_result(reason: str) -> PreflightResult:
    return PreflightResult(
        "error",
        64,
        "sha256:unavailable",
        0,
        "INPUT_INVALID",
        reason,
        "Correct the closed input and detached digest, then rerun.",
        {},
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--ssh-config", type=Path)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    try:
        result = run_preflight(args.input, args.input_sha256, args.ssh_config)
    except InputError as exc:
        result = error_result(str(exc))
    if args.json:
        print(json.dumps(result.as_json(), sort_keys=True, separators=(",", ":")))
    else:
        print(render_human(result))
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
