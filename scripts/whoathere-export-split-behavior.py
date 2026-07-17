#!/usr/bin/env python3
"""Export only report-bound behavior bundles from a restricted detonation output tree.

The input report must already be the sanitized exact-artifact projection emitted by the remote
Step 5 harness. This script never reads package artifacts, raw sensor evidence, packet captures, or
other detonation files. It reads only that report and regular files named ``behavior-bundle.json``.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
from typing import Any


EXPORT_SCHEMA = "whoathere.split_behavior_export.v1"
RESULT_SCHEMA = "whoathere.split_behavior_export_result.v1"
REPORT_SCHEMA = "whoathere.exact_artifact_inspection.v1"
BUNDLE_SCHEMA = "whoathere.behavior_analysis_bundle.v1"
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_BUNDLES = 128
MAX_EVENTS = 50_000
REPORT_KEYS = {
    "schema_version",
    "status",
    "verdict",
    "exit_code",
    "identity",
    "stages",
    "scenario_plan",
    "observations",
    "behavior_detection_count",
    "admission_authority",
    "observed_clean",
    "sync_back_enabled",
    "reason_codes",
    "sanitized_projection",
    "raw_source_or_telemetry_included",
}
REPORT_IDENTITY_KEYS = {
    "artifact_sha256",
    "envelope_sha256",
    "manifest_sha256",
    "byte_length",
    "ecosystem",
    "artifact_format",
    "source_type",
    "acquisition_method",
}
REPORT_STAGE_KEYS = {
    "stage",
    "status",
    "artifact_sha256",
    "manifest_sha256",
    "request_sha256",
    "result_sha256",
    "provider",
    "observation_count",
    "reason_codes",
}
REPORT_SCENARIO_KEYS = {
    "schema_version",
    "artifact_sha256",
    "manifest_sha256",
    "status",
    "plan_sha256",
    "runtime_binding_required",
    "runtime_binding_status",
    "executable",
    "intent_count",
    "reason_codes",
}
REPORT_OBSERVATION_KEYS = {
    "schema_version",
    "source",
    "threat_class",
    "confidence",
    "artifact_sha256",
    "manifest_sha256",
    "coverage",
    "behavior_detection_eligible",
    "observation_sha256",
    "finding_kind",
    "coverage_gap_codes",
}
REPORT_FINDING_KIND_KEYS = {"source", "kind"}
BUNDLE_KEYS = {
    "schema_version",
    "artifact_sha256",
    "manifest_sha256",
    "scenario_id",
    "scenario_sha256",
    "run_id",
    "root_receipt_sha256",
    "host_receipt_sha256",
    "coverage",
    "events",
}
MODALITIES = {"process", "filesystem", "canary", "network", "scenario"}
PHYSICAL_PROVIDERS = {
    "linux_vz_exact_npm_v1": re.compile(r"^vm_ci_(false|true)$"),
    "linux_vz_exact_wheel_v1": re.compile(r"^vm_wheel_action_([0-9]+)$"),
    "linux_vz_exact_sdist_v1": re.compile(r"^vm_sdist_action_([0-9]+)$"),
}
BUNDLE_REASON = re.compile(r"^([a-z0-9_]+)_behavior_bundle_sha256:([0-9a-f]{64})$")


class ExportError(Exception):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def require(condition: bool, reason_code: str) -> None:
    if not condition:
        raise ExportError(reason_code)


def valid_sha256(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def exact_keys(value: dict[str, Any], expected: set[str], reason_code: str) -> None:
    require(set(value) == expected, reason_code)


def safe_report_scalar(value: Any) -> bool:
    return (
        value is None
        or isinstance(value, bool)
        or (isinstance(value, int) and not isinstance(value, bool))
        or (
            isinstance(value, str)
            and len(value) <= 256
            and "\n" not in value
            and "\r" not in value
        )
    )


def validate_reason_codes(value: Any, reason_code: str) -> None:
    require(isinstance(value, list) and len(value) <= 128, reason_code)
    require(
        all(
            isinstance(item, str)
            and 0 < len(item) <= 160
            and all(
                character.isascii()
                and (character.islower() or character.isdigit() or character in "_-.:")
                for character in item
            )
            for item in value
        ),
        reason_code,
    )


def validate_sanitized_report_shape(report: dict[str, Any]) -> None:
    reason = "split_behavior_export_report_not_sanitized"
    exact_keys(report, REPORT_KEYS, reason)
    identity = report.get("identity")
    stages = report.get("stages")
    scenario = report.get("scenario_plan")
    observations = report.get("observations")
    require(
        isinstance(identity, dict)
        and isinstance(stages, list)
        and isinstance(scenario, dict)
        and isinstance(observations, list),
        reason,
    )
    exact_keys(identity, REPORT_IDENTITY_KEYS, reason)
    exact_keys(scenario, REPORT_SCENARIO_KEYS, reason)
    require(all(safe_report_scalar(value) for value in identity.values()), reason)
    require(
        all(safe_report_scalar(value) for key, value in report.items() if key not in {
            "identity", "stages", "scenario_plan", "observations", "reason_codes"
        }),
        reason,
    )
    require(
        all(safe_report_scalar(value) for key, value in scenario.items() if key != "reason_codes"),
        reason,
    )
    validate_reason_codes(report.get("reason_codes"), reason)
    validate_reason_codes(scenario.get("reason_codes"), reason)
    for stage in stages:
        require(isinstance(stage, dict), reason)
        exact_keys(stage, REPORT_STAGE_KEYS, reason)
        require(
            all(safe_report_scalar(value) for key, value in stage.items() if key != "reason_codes"),
            reason,
        )
        validate_reason_codes(stage.get("reason_codes"), reason)
    for observation in observations:
        require(isinstance(observation, dict), reason)
        exact_keys(observation, REPORT_OBSERVATION_KEYS, reason)
        finding_kind = observation.get("finding_kind")
        require(isinstance(finding_kind, dict), reason)
        exact_keys(finding_kind, REPORT_FINDING_KIND_KEYS, reason)
        require(all(safe_report_scalar(value) for value in finding_kind.values()), reason)
        require(
            all(
                safe_report_scalar(value)
                for key, value in observation.items()
                if key not in {"coverage_gap_codes", "finding_kind"}
            ),
            reason,
        )
        validate_reason_codes(observation.get("coverage_gap_codes"), reason)


def project_sanitized_report(report: dict[str, Any]) -> bytes:
    """Rebuild only fields emitted by the remote sanitized-report projector."""

    identity = report["identity"]
    scenario = report["scenario_plan"]
    projected = {
        "schema_version": report["schema_version"],
        "status": report["status"],
        "verdict": report["verdict"],
        "exit_code": report["exit_code"],
        "identity": {key: identity[key] for key in REPORT_IDENTITY_KEYS},
        "stages": [
            {key: stage[key] for key in REPORT_STAGE_KEYS}
            for stage in report["stages"]
        ],
        "scenario_plan": {key: scenario[key] for key in REPORT_SCENARIO_KEYS},
        "observations": [
            {
                key: (
                    {
                        finding_key: observation["finding_kind"][finding_key]
                        for finding_key in REPORT_FINDING_KIND_KEYS
                    }
                    if key == "finding_kind"
                    else observation[key]
                )
                for key in REPORT_OBSERVATION_KEYS
            }
            for observation in report["observations"]
        ],
        "behavior_detection_count": report["behavior_detection_count"],
        "admission_authority": report["admission_authority"],
        "observed_clean": report["observed_clean"],
        "sync_back_enabled": report["sync_back_enabled"],
        "reason_codes": list(report["reason_codes"]),
        "sanitized_projection": report["sanitized_projection"],
        "raw_source_or_telemetry_included": report["raw_source_or_telemetry_included"],
    }
    return (json.dumps(projected, indent=2, sort_keys=True) + "\n").encode("utf-8")


def read_regular_json(path: Path, reason_prefix: str) -> tuple[bytes, dict[str, Any]]:
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            require(
                stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= MAX_JSON_BYTES,
                f"{reason_prefix}_unavailable",
            )
            raw = handle.read(MAX_JSON_BYTES + 1)
            require(
                len(raw) == metadata.st_size and len(raw) <= MAX_JSON_BYTES,
                f"{reason_prefix}_unavailable",
            )
        value = json.loads(raw.decode("utf-8"))
    except ExportError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExportError(f"{reason_prefix}_unavailable") from error
    require(isinstance(value, dict), f"{reason_prefix}_invalid")
    return raw, value


def validate_report(path: Path) -> tuple[bytes, dict[str, Any]]:
    _, report = read_regular_json(path, "split_behavior_export_report")
    validate_sanitized_report_shape(report)
    require(report.get("schema_version") == REPORT_SCHEMA, "split_behavior_export_report_invalid")
    require(
        report.get("sanitized_projection") is True
        and report.get("raw_source_or_telemetry_included") is False,
        "split_behavior_export_report_not_sanitized",
    )
    require(
        report.get("admission_authority") is False
        and report.get("observed_clean") is False
        and report.get("sync_back_enabled") is False,
        "split_behavior_export_report_safety_invalid",
    )
    identity = report.get("identity")
    require(isinstance(identity, dict), "split_behavior_export_report_identity_invalid")
    artifact_sha256 = identity.get("artifact_sha256")
    manifest_sha256 = identity.get("manifest_sha256")
    require(
        valid_sha256(artifact_sha256) and valid_sha256(manifest_sha256),
        "split_behavior_export_report_identity_invalid",
    )

    stages = [
        stage
        for stage in report.get("stages", [])
        if isinstance(stage, dict) and stage.get("stage") == "detonation"
    ]
    require(len(stages) == 1, "split_behavior_export_detonation_stage_invalid")
    detonation = stages[0]
    provider = detonation.get("provider")
    action_pattern = PHYSICAL_PROVIDERS.get(provider)
    require(action_pattern is not None, "split_behavior_export_detonation_provider_invalid")
    require(
        detonation.get("artifact_sha256") == artifact_sha256
        and detonation.get("manifest_sha256") == manifest_sha256,
        "split_behavior_export_detonation_binding_invalid",
    )

    declared: dict[str, str] = {}
    seen_digests: set[str] = set()
    reason_codes = detonation.get("reason_codes")
    require(isinstance(reason_codes, list), "split_behavior_export_detonation_stage_invalid")
    for reason in reason_codes:
        match = BUNDLE_REASON.fullmatch(reason) if isinstance(reason, str) else None
        if match is None:
            continue
        action, hexadecimal = match.groups()
        digest = "sha256:" + hexadecimal
        require(
            action_pattern.fullmatch(action) is not None,
            "split_behavior_export_action_invalid",
        )
        require(
            action not in declared and digest not in seen_digests,
            "split_behavior_export_report_bundle_duplicate",
        )
        declared[action] = digest
        seen_digests.add(digest)
    require(0 < len(declared) <= MAX_BUNDLES, "split_behavior_export_declared_bundle_count_invalid")

    scenario_plan = report.get("scenario_plan")
    require(isinstance(scenario_plan, dict), "split_behavior_export_scenario_plan_invalid")
    intent_count = scenario_plan.get("intent_count")
    require(
        isinstance(intent_count, int)
        and not isinstance(intent_count, bool)
        and intent_count == len(declared),
        "split_behavior_export_declared_bundle_count_invalid",
    )
    require(
        scenario_plan.get("artifact_sha256") == artifact_sha256
        and scenario_plan.get("manifest_sha256") == manifest_sha256,
        "split_behavior_export_scenario_plan_invalid",
    )
    return project_sanitized_report(report), {
        "artifact_sha256": artifact_sha256,
        "manifest_sha256": manifest_sha256,
        "provider": provider,
        "declared": declared,
    }


def collect_behavior_bundle_paths(root: Path) -> list[Path]:
    try:
        metadata = root.lstat()
    except OSError as error:
        raise ExportError("split_behavior_export_output_root_unavailable") from error
    require(
        stat.S_ISDIR(metadata.st_mode) and not root.is_symlink(),
        "split_behavior_export_output_root_unavailable",
    )
    paths: list[Path] = []
    for directory, child_directories, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in child_directories:
            require(
                not (directory_path / name).is_symlink(),
                "split_behavior_export_symlink_rejected",
            )
        if "behavior-bundle.json" not in filenames:
            continue
        candidate = directory_path / "behavior-bundle.json"
        require(not candidate.is_symlink(), "split_behavior_export_symlink_rejected")
        paths.append(candidate)
        require(
            len(paths) <= MAX_BUNDLES * 8,
            "split_behavior_export_candidate_count_exceeded",
        )
    return sorted(paths)


def bundle_identity(value: dict[str, Any]) -> tuple[Any, Any]:
    return value.get("artifact_sha256"), value.get("manifest_sha256")


def valid_identifier(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 160
        and all(
            character.isascii() and (character.isalnum() or character in "-_./:")
            for character in value
        )
    )


def valid_code(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 0 < len(value.encode("utf-8")) <= 160
        and all(
            character.isascii()
            and (character.islower() or character.isdigit() or character == "_")
            for character in value
        )
    )


def validate_signal(signal: Any) -> None:
    reason = "split_behavior_export_bundle_invalid"
    require(isinstance(signal, dict), reason)
    kind = signal.get("kind")
    if kind == "process":
        exact_keys(signal, {"kind", "action", "trigger"}, reason)
        action = signal.get("action")
        trigger = signal.get("trigger")
        require(
            action in {
                "package_trigger",
                "ordinary_child",
                "shell_spawn",
                "dynamic_loader",
                "background_process",
                "executable_payload_launch",
            },
            reason,
        )
        require(
            (
                action == "package_trigger"
                and trigger
                in {
                    "npm_lifecycle",
                    "npm_bin",
                    "npm_import",
                    "wheel_pth",
                    "wheel_import",
                    "wheel_entry_point",
                    "sdist_build_backend",
                    "sdist_setup_py",
                    "sdist_import",
                }
            )
            or (action != "package_trigger" and trigger is None),
            reason,
        )
    elif kind == "filesystem":
        exact_keys(signal, {"kind", "operation", "target"}, reason)
        require(signal.get("operation") in {"read", "write", "delete", "rename"}, reason)
        require(
            signal.get("target")
            in {
                "ordinary_workspace",
                "sensitive_file",
                "credential_file",
                "persistence_location",
                "repository_metadata",
                "workflow_definition",
                "package_metadata",
                "executable_payload",
                "package_self",
            },
            reason,
        )
    elif kind == "canary":
        exact_keys(signal, {"kind", "action", "canary"}, reason)
        require(
            signal.get("action")
            in {"read", "copied_to_process", "sent_to_network", "used_for_publish"},
            reason,
        )
        require(
            signal.get("canary")
            in {
                "npm_token",
                "pypi_token",
                "github_token",
                "cloud_credential",
                "ssh_key",
                "sensitive_file",
            },
            reason,
        )
    elif kind == "network":
        exact_keys(signal, {"kind", "action", "destination"}, reason)
        require(
            signal.get("action")
            in {
                "dns_lookup",
                "connect",
                "send",
                "receive_executable",
                "metadata_request",
                "package_publish",
            },
            reason,
        )
        require(
            signal.get("destination")
            in {
                "unavailable",
                "local_sinkhole",
                "external_internet",
                "cloud_metadata",
                "public_code_host",
                "package_registry",
                "dead_drop_service",
            },
            reason,
        )
    elif kind == "scenario":
        exact_keys(signal, {"kind", "action", "gate"}, reason)
        action = signal.get("action")
        gate = signal.get("gate")
        require(
            action
            in {
                "ordinary_control",
                "environment_gate_observed",
                "delayed_execution_observed",
                "obfuscated_payload_decoded",
                "self_propagation_attempt",
                "dependency_indirection_observed",
                "import_time_tampering_observed",
            },
            reason,
        )
        require(
            (
                action == "environment_gate_observed"
                and gate
                in {"ci", "platform", "locale", "username", "hostname", "secret_presence", "time"}
            )
            or (action != "environment_gate_observed" and gate is None),
            reason,
        )
    else:
        raise ExportError(reason)


def validate_bundle_shape(value: dict[str, Any]) -> None:
    reason = "split_behavior_export_bundle_invalid"
    exact_keys(value, BUNDLE_KEYS, reason)
    require(valid_sha256(value.get("root_receipt_sha256")), reason)
    require(valid_sha256(value.get("host_receipt_sha256")), reason)
    require(
        valid_identifier(value.get("scenario_id")) and valid_identifier(value.get("run_id")),
        reason,
    )
    coverage = value.get("coverage")
    events = value.get("events")
    require(isinstance(coverage, list) and len(coverage) == len(MODALITIES), reason)
    require(isinstance(events, list) and len(events) <= MAX_EVENTS, reason)
    seen_modalities: set[str] = set()
    for row in coverage:
        require(isinstance(row, dict), reason)
        exact_keys(row, {"modality", "state", "limitation_codes"}, reason)
        modality = row.get("modality")
        state = row.get("state")
        codes = row.get("limitation_codes")
        require(modality in MODALITIES and modality not in seen_modalities, reason)
        require(isinstance(codes, list) and len(codes) <= 64, reason)
        require(
            all(valid_code(code) for code in codes) and len(codes) == len(set(codes)),
            reason,
        )
        require(
            (state == "complete" and not codes) or (state == "incomplete" and bool(codes)),
            reason,
        )
        seen_modalities.add(modality)
    require(seen_modalities == MODALITIES, reason)
    previous_sequence = -1
    event_ids: set[str] = set()
    for event in events:
        require(isinstance(event, dict), reason)
        exact_keys(
            event,
            {"sequence", "event_id", "source_receipt_sha256", "signal", "untrusted_detail"},
            reason,
        )
        sequence = event.get("sequence")
        event_id = event.get("event_id")
        detail = event.get("untrusted_detail")
        require(
            isinstance(sequence, int)
            and not isinstance(sequence, bool)
            and sequence >= 0
            and sequence <= (2**64 - 1)
            and sequence > previous_sequence,
            reason,
        )
        require(valid_identifier(event_id) and event_id not in event_ids, reason)
        require(valid_sha256(event.get("source_receipt_sha256")), reason)
        # The current authenticated projector emits no free-form detail. Keep the
        # split export typed-only so package content or raw telemetry cannot ride
        # through this otherwise untrusted field.
        require(detail is None, reason)
        validate_signal(event.get("signal"))
        previous_sequence = sequence
        event_ids.add(event_id)


def project_bundle(value: dict[str, Any]) -> bytes:
    """Rebuild the strict Rust bundle wire schema without copying unknown fields."""

    projected_events: list[dict[str, Any]] = []
    for event in value["events"]:
        signal = event["signal"]
        kind = signal["kind"]
        if kind == "process":
            projected_signal = {
                "kind": kind,
                "action": signal["action"],
                "trigger": signal["trigger"],
            }
        elif kind == "filesystem":
            projected_signal = {
                "kind": kind,
                "operation": signal["operation"],
                "target": signal["target"],
            }
        elif kind == "canary":
            projected_signal = {
                "kind": kind,
                "action": signal["action"],
                "canary": signal["canary"],
            }
        elif kind == "network":
            projected_signal = {
                "kind": kind,
                "action": signal["action"],
                "destination": signal["destination"],
            }
        else:
            projected_signal = {
                "kind": kind,
                "action": signal["action"],
                "gate": signal["gate"],
            }
        projected_events.append(
            {
                "sequence": event["sequence"],
                "event_id": event["event_id"],
                "source_receipt_sha256": event["source_receipt_sha256"],
                "signal": projected_signal,
                "untrusted_detail": event["untrusted_detail"],
            }
        )
    projected = {
        "schema_version": value["schema_version"],
        "artifact_sha256": value["artifact_sha256"],
        "manifest_sha256": value["manifest_sha256"],
        "scenario_id": value["scenario_id"],
        "scenario_sha256": value["scenario_sha256"],
        "run_id": value["run_id"],
        "root_receipt_sha256": value["root_receipt_sha256"],
        "host_receipt_sha256": value["host_receipt_sha256"],
        "coverage": [
            {
                "modality": row["modality"],
                "state": row["state"],
                "limitation_codes": list(row["limitation_codes"]),
            }
            for row in value["coverage"]
        ],
        "events": projected_events,
    }
    return json.dumps(projected, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def validate_matching_bundle(
    value: dict[str, Any], expected_artifact: str, expected_manifest: str
) -> None:
    validate_bundle_shape(value)
    require(value.get("schema_version") == BUNDLE_SCHEMA, "split_behavior_export_bundle_invalid")
    require(
        bundle_identity(value) == (expected_artifact, expected_manifest),
        "split_behavior_export_bundle_binding_mismatch",
    )
    require(
        isinstance(value.get("scenario_id"), str)
        and bool(value["scenario_id"])
        and valid_sha256(value.get("scenario_sha256"))
        and isinstance(value.get("run_id"), str)
        and bool(value["run_id"])
        and isinstance(value.get("coverage"), list)
        and isinstance(value.get("events"), list),
        "split_behavior_export_bundle_invalid",
    )


def locate_declared_bundles(root: Path, report: dict[str, Any]) -> dict[str, tuple[Path, bytes]]:
    declared_by_digest = {digest: action for action, digest in report["declared"].items()}
    matched: dict[str, tuple[Path, bytes]] = {}
    same_identity_extras: list[Path] = []
    for path in collect_behavior_bundle_paths(root):
        try:
            raw, value = read_regular_json(path, "split_behavior_export_bundle")
        except ExportError:
            # An unreadable unrelated historical bundle is outside this report's export set. If it
            # replaced a declared bundle, the exact declared digest will be missing below.
            continue
        digest = sha256_bytes(raw)
        action = declared_by_digest.get(digest)
        same_identity = bundle_identity(value) == (
            report["artifact_sha256"],
            report["manifest_sha256"],
        )
        if action is None:
            if same_identity:
                same_identity_extras.append(path)
            continue
        validate_matching_bundle(value, report["artifact_sha256"], report["manifest_sha256"])
        projected_raw = project_bundle(value)
        require(
            sha256_bytes(projected_raw) == digest,
            "split_behavior_export_bundle_noncanonical",
        )
        require(action not in matched, "split_behavior_export_bundle_duplicate")
        matched[action] = (path, projected_raw)

    require(
        not same_identity_extras,
        "split_behavior_export_bundle_digest_mismatch",
    )
    missing = set(report["declared"]) - set(matched)
    require(not missing, "split_behavior_export_bundle_missing")
    require(
        set(matched) == set(report["declared"]),
        "split_behavior_export_bundle_set_mismatch",
    )
    return matched


def write_new_private(path: Path, content: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
    path.chmod(0o600)


def export_bundle_set(report_path: Path, output_root: Path, export_dir: Path) -> dict[str, Any]:
    report_raw, report = validate_report(report_path)
    matched = locate_declared_bundles(output_root, report)
    require(not export_dir.exists(), "split_behavior_export_directory_not_fresh")
    parent = export_dir.parent
    require(parent.is_dir() and not parent.is_symlink(), "split_behavior_export_parent_unavailable")

    export_dir.mkdir(mode=0o700)
    try:
        report_relative = Path("sanitized-exact-artifact-report.json")
        write_new_private(export_dir / report_relative, report_raw)
        files: list[dict[str, Any]] = [
            {
                "role": "sanitized_exact_artifact_report",
                "path": report_relative.as_posix(),
                "sha256": sha256_bytes(report_raw),
                "byte_length": len(report_raw),
            }
        ]
        bundle_bindings: list[dict[str, Any]] = []
        for action in sorted(matched):
            _, raw = matched[action]
            relative = Path("bundles") / action / "behavior-bundle.json"
            write_new_private(export_dir / relative, raw)
            digest = sha256_bytes(raw)
            binding = {
                "action_key": action,
                "bundle_sha256": digest,
                "path": relative.as_posix(),
                "byte_length": len(raw),
            }
            bundle_bindings.append(binding)
            files.append({"role": "behavior_bundle", **binding, "sha256": digest})

        manifest = {
            "schema_version": EXPORT_SCHEMA,
            "created_at_utc": dt.datetime.now(dt.timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "artifact_sha256": report["artifact_sha256"],
            "manifest_sha256": report["manifest_sha256"],
            "detonation_provider": report["provider"],
            "sanitized_report_sha256": sha256_bytes(report_raw),
            "bundle_count": len(bundle_bindings),
            "bundle_set_sha256": canonical_sha256(bundle_bindings),
            "files": files,
            "raw_evidence_included": False,
            "artifact_bytes_included": False,
            "package_source_included": False,
        }
        manifest_raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        manifest_path = export_dir / "export-manifest.json"
        write_new_private(manifest_path, manifest_raw)
        for directory, child_directories, filenames in os.walk(export_dir):
            Path(directory).chmod(0o700)
            for name in child_directories:
                (Path(directory) / name).chmod(0o700)
            for name in filenames:
                (Path(directory) / name).chmod(0o600)
        return {
            "schema_version": RESULT_SCHEMA,
            "status": "exported",
            "export_directory": str(export_dir),
            "manifest_path": str(manifest_path),
            "manifest_sha256": sha256_bytes(manifest_raw),
            "artifact_sha256": report["artifact_sha256"],
            "bundle_count": len(bundle_bindings),
            "raw_evidence_included": False,
            "artifact_bytes_included": False,
        }
    except Exception:
        shutil.rmtree(export_dir, ignore_errors=True)
        raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sanitized-report", type=Path, required=True)
    parser.add_argument("--detonation-output-root", type=Path, required=True)
    parser.add_argument("--export-dir", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    os.umask(0o077)
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = export_bundle_set(
            args.sanitized_report.expanduser(),
            args.detonation_output_root.expanduser(),
            args.export_dir.expanduser(),
        )
    except ExportError as error:
        print(f"split_behavior_export_error={error.reason_code}", file=sys.stderr)
        return 65
    except OSError:
        print("split_behavior_export_error=split_behavior_export_io_failed", file=sys.stderr)
        return 74
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
