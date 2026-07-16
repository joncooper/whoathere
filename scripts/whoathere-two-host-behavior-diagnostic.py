#!/usr/bin/env python3
"""Join remote VZ behavior bundles to local ``whoathere behavior observe`` results.

This bridge is intentionally diagnostic-only. It does not execute artifacts, invoke Codex, grant
admission, or interpret missing evidence as clean. The Rust producer remains responsible for full
schema validation; this script only rechecks the cross-host bindings needed for the split workflow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path
from typing import Any


SCHEMA = "whoathere.two_host_behavior_diagnostic.v1"
EXACT_REPORT_SCHEMA = "whoathere.exact_artifact_inspection.v1"
BUNDLE_SCHEMA = "whoathere.behavior_analysis_bundle.v1"
OBSERVER_SCHEMA = "whoathere.behavior_observe.v1"
PHYSICAL_PROVIDERS = {
    "linux_vz_exact_npm_v1": ("npm", re.compile(r"^vm_ci_(false|true)$")),
    "linux_vz_exact_wheel_v1": ("pypi", re.compile(r"^vm_wheel_action_(\d+)$")),
    "linux_vz_exact_sdist_v1": ("pypi", re.compile(r"^vm_sdist_action_(\d+)$")),
}
BUNDLE_REASON = re.compile(r"^([a-z0-9_]+)_behavior_bundle_sha256:([0-9a-f]{64})$")
DETECTION_ELIGIBLE = {
    "second_stage_handoff",
    "sensitive_file_access",
    "credential_access",
    "canary_access",
    "canary_use",
    "credential_exfiltration",
    "metadata_access",
    "exfiltration",
    "second_stage_download",
    "persistence_modification",
    "destructive_file_action",
    "self_deletion",
    "repository_mutation",
    "workflow_mutation",
    "package_mutation",
    "package_publish_attempt",
    "self_propagation",
    "obfuscation_or_packing",
    "import_time_tampering",
}
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_INPUTS = 128


class DiagnosticError(Exception):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


def require(condition: bool, reason_code: str) -> None:
    if not condition:
        raise DiagnosticError(reason_code)


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def json_sha256(value: Any) -> str:
    """A measured JSON-content binding owned by this diagnostic, not a producer receipt."""

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def serde_sha256(value: Any) -> str:
    """Reproduce event hashes from compact Rust struct JSON already present in a bundle."""

    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(encoded)


def valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def read_json(path: Path, reason_prefix: str) -> tuple[bytes, dict[str, Any]]:
    try:
        metadata = path.lstat()
        require(
            stat.S_ISREG(metadata.st_mode)
            and not path.is_symlink()
            and 0 < metadata.st_size <= MAX_FILE_BYTES,
            f"{reason_prefix}_unavailable",
        )
        raw = path.read_bytes()
        value = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError(f"{reason_prefix}_unavailable") from error
    require(isinstance(value, dict), f"{reason_prefix}_invalid")
    return raw, value


def collect_named_bundles(root: Path) -> list[Path]:
    try:
        metadata = root.lstat()
    except OSError as error:
        raise DiagnosticError("two_host_behavior_bundle_directory_unavailable") from error
    require(
        stat.S_ISDIR(metadata.st_mode) and not root.is_symlink(),
        "two_host_behavior_bundle_directory_unavailable",
    )
    paths: list[Path] = []
    for directory, child_directories, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        require(
            not any((directory_path / name).is_symlink() for name in child_directories),
            "two_host_behavior_bundle_symlink_rejected",
        )
        if "behavior-bundle.json" in filenames:
            candidate = directory_path / "behavior-bundle.json"
            require(not candidate.is_symlink(), "two_host_behavior_bundle_symlink_rejected")
            paths.append(candidate)
    require(0 < len(paths) <= MAX_INPUTS, "two_host_behavior_bundle_count_invalid")
    return sorted(paths)


def collect_observer_results(
    directory: Path | None, explicit_paths: list[Path]
) -> list[Path]:
    paths = list(explicit_paths)
    if directory is not None:
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise DiagnosticError("two_host_behavior_observer_directory_unavailable") from error
        require(
            stat.S_ISDIR(metadata.st_mode) and not directory.is_symlink(),
            "two_host_behavior_observer_directory_unavailable",
        )
        paths.extend(sorted(directory.rglob("*.json")))
    require(0 < len(paths) <= MAX_INPUTS, "two_host_behavior_observer_count_invalid")
    return paths


def action_intent_sha256(
    provider: str, action_key: str, intents: list[dict[str, Any]]
) -> str | None:
    match = PHYSICAL_PROVIDERS[provider][1].fullmatch(action_key)
    require(match is not None, "two_host_remote_action_key_invalid")
    if provider == "linux_vz_exact_npm_v1":
        profile = f"ci_{match.group(1)}"
        candidates = [intent for intent in intents if profile in json.dumps(intent.get("kind"))]
        require(len(candidates) == 1, "two_host_remote_action_binding_invalid")
        return candidates[0].get("intent_sha256")
    index = int(match.group(1))
    require(index < len(intents), "two_host_remote_action_binding_invalid")
    return intents[index].get("intent_sha256")


def validate_remote_report(path: Path) -> dict[str, Any]:
    raw, report = read_json(path, "two_host_remote_report")
    require(report.get("schema_version") == EXACT_REPORT_SCHEMA, "two_host_remote_report_invalid")
    identity = report.get("identity")
    require(isinstance(identity, dict), "two_host_remote_identity_invalid")
    artifact = identity.get("artifact_sha256")
    manifest = identity.get("manifest_sha256")
    require(valid_sha256(artifact) and valid_sha256(manifest), "two_host_remote_identity_invalid")
    require(
        report.get("admission_authority") is False
        and report.get("observed_clean") is False
        and report.get("sync_back_enabled") is False,
        "two_host_remote_safety_contract_invalid",
    )
    stages = [stage for stage in report.get("stages", []) if stage.get("stage") == "detonation"]
    require(len(stages) == 1, "two_host_remote_detonation_stage_invalid")
    detonation = stages[0]
    provider = detonation.get("provider")
    require(provider in PHYSICAL_PROVIDERS, "two_host_remote_detonation_provider_invalid")
    require(
        identity.get("ecosystem") == PHYSICAL_PROVIDERS[provider][0]
        and detonation.get("artifact_sha256") == artifact
        and detonation.get("manifest_sha256") == manifest,
        "two_host_remote_detonation_binding_invalid",
    )
    plan = report.get("scenario_plan")
    intents = plan.get("intents") if isinstance(plan, dict) else None
    require(
        isinstance(intents, list)
        and plan.get("artifact_sha256") == artifact
        and plan.get("manifest_sha256") == manifest,
        "two_host_remote_scenario_plan_invalid",
    )
    declared: dict[str, str] = {}
    seen_digests: set[str] = set()
    for reason in detonation.get("reason_codes", []):
        match = BUNDLE_REASON.fullmatch(reason) if isinstance(reason, str) else None
        if match is None:
            continue
        action_key, hexadecimal = match.groups()
        digest = "sha256:" + hexadecimal
        require(
            action_key not in declared and digest not in seen_digests,
            "two_host_remote_behavior_bundle_duplicate",
        )
        declared[action_key] = digest
        seen_digests.add(digest)
    require(declared, "two_host_remote_behavior_bundle_missing")
    intent_bindings = {
        action: action_intent_sha256(provider, action, intents) for action in declared
    }
    require(
        all(valid_sha256(digest) for digest in intent_bindings.values()),
        "two_host_remote_action_binding_invalid",
    )
    return {
        "artifact_sha256": artifact,
        "manifest_sha256": manifest,
        "report_sha256": sha256_bytes(raw),
        "provider": provider,
        "detonation_status": detonation.get("status"),
        "declared": declared,
        "intent_bindings": intent_bindings,
        "safety": {
            "admission_authority": False,
            "observed_clean": False,
            "sync_back_enabled": False,
        },
    }


def validate_bundle(path: Path, remote: dict[str, Any]) -> dict[str, Any]:
    raw, bundle = read_json(path, "two_host_behavior_bundle")
    digest = sha256_bytes(raw)
    require(bundle.get("schema_version") == BUNDLE_SCHEMA, "two_host_behavior_bundle_invalid")
    require(
        bundle.get("artifact_sha256") == remote["artifact_sha256"]
        and bundle.get("manifest_sha256") == remote["manifest_sha256"],
        "two_host_behavior_bundle_artifact_mismatch",
    )
    require(
        isinstance(bundle.get("scenario_id"), str)
        and valid_sha256(bundle.get("scenario_sha256"))
        and isinstance(bundle.get("run_id"), str),
        "two_host_behavior_bundle_identity_invalid",
    )
    events = bundle.get("events")
    require(isinstance(events, list), "two_host_behavior_bundle_events_invalid")
    event_sha256s: dict[str, str] = {}
    for event in events:
        require(isinstance(event, dict), "two_host_behavior_bundle_events_invalid")
        event_id = event.get("event_id")
        require(
            isinstance(event_id, str) and event_id not in event_sha256s,
            "two_host_behavior_bundle_events_invalid",
        )
        event_sha256s[event_id] = serde_sha256(event)
    coverage = bundle.get("coverage")
    coverage_complete = isinstance(coverage, list) and all(
        isinstance(row, dict) and row.get("state") == "complete" for row in coverage
    )
    return {
        "bundle_sha256": digest,
        "scenario_id": bundle["scenario_id"],
        "scenario_sha256": bundle["scenario_sha256"],
        "run_id": bundle["run_id"],
        "event_count": len(events),
        "event_sha256s": event_sha256s,
        "evidence_coverage_complete": coverage_complete,
    }


def validate_finding(finding: Any, bundle: dict[str, Any]) -> dict[str, Any]:
    require(isinstance(finding, dict), "two_host_behavior_finding_invalid")
    kind = finding.get("kind")
    evidence = finding.get("evidence")
    require(
        isinstance(kind, str)
        and valid_sha256(finding.get("finding_sha256"))
        and isinstance(evidence, list)
        and evidence,
        "two_host_behavior_finding_invalid",
    )
    for reference in evidence:
        require(isinstance(reference, dict), "two_host_behavior_finding_evidence_invalid")
        event_id = reference.get("event_id")
        require(
            isinstance(event_id, str)
            and reference.get("event_sha256") == bundle["event_sha256s"].get(event_id),
            "two_host_behavior_finding_evidence_mismatch",
        )
    return finding


def validate_observer(path: Path, bundle: dict[str, Any], artifact: str) -> dict[str, Any]:
    raw, result = read_json(path, "two_host_behavior_observer_result")
    require(
        result.get("schema_version") == OBSERVER_SCHEMA
        and result.get("provider") == "codex"
        and result.get("artifact_sha256") == artifact
        and result.get("bundle_sha256") == bundle["bundle_sha256"]
        and result.get("observe_only") is True
        and result.get("admission_authority") is False
        and result.get("observed_clean") is False,
        "two_host_behavior_observer_binding_invalid",
    )
    panel = result.get("panel")
    require(
        isinstance(panel, dict)
        and panel.get("bundle_sha256") == bundle["bundle_sha256"]
        and panel.get("admission_authority") is False
        and panel.get("observed_clean") is False,
        "two_host_behavior_panel_binding_invalid",
    )
    receipt_bindings: list[dict[str, str]] = []
    for observation in panel.get("observations", []):
        receipt = observation.get("receipt") if isinstance(observation, dict) else None
        require(
            isinstance(receipt, dict)
            and receipt.get("provider") == "codex"
            and receipt.get("bundle_sha256") == bundle["bundle_sha256"]
            and receipt.get("selected_role") == observation.get("selected_role"),
            "two_host_behavior_provider_receipt_mismatch",
        )
        receipt_bindings.append(
            {
                "selected_role": receipt["selected_role"],
                "measured_receipt_json_sha256": json_sha256(receipt),
                "provider_output_sha256": receipt.get("provider_output_sha256"),
            }
        )
    correlation = panel.get("correlation_report")
    findings: list[dict[str, Any]] = []
    correlation_sha256 = None
    specialist_sha256s: list[str] = []
    if correlation is not None:
        require(
            isinstance(correlation, dict)
            and correlation.get("bundle_sha256") == bundle["bundle_sha256"]
            and correlation.get("positive_preservation_verified") is True,
            "two_host_behavior_correlation_binding_invalid",
        )
        findings = [validate_finding(finding, bundle) for finding in correlation.get("findings", [])]
        specialist_sha256s = correlation.get("specialist_report_sha256s", [])
        require(
            isinstance(specialist_sha256s, list)
            and all(valid_sha256(digest) for digest in specialist_sha256s),
            "two_host_behavior_specialist_binding_invalid",
        )
        correlation_sha256 = json_sha256(correlation)
    eligible = [finding for finding in findings if finding.get("kind") in DETECTION_ELIGIBLE]
    status = result.get("status")
    if eligible:
        require(
            status == "behavior_detected"
            and result.get("exit_code") == 20
            and correlation.get("conclusion") == "behavior_detected",
            "two_host_behavior_observer_status_invalid",
        )
    else:
        require(
            status in {"behavior_observed", "inconclusive"},
            "two_host_behavior_observer_status_invalid",
        )
    return {
        "bundle_sha256": bundle["bundle_sha256"],
        "result_sha256": sha256_bytes(raw),
        "status": status,
        "provider_receipts": sorted(
            receipt_bindings, key=lambda value: value["selected_role"]
        ),
        "specialist_report_sha256s": specialist_sha256s,
        "measured_correlation_json_sha256": correlation_sha256,
        "findings": eligible,
    }


def minimal_inconclusive(reason_code: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA,
        "verdict": "inconclusive",
        "exit_code": 22,
        "diagnostic_only": True,
        "claim_bearing": False,
        "reconciliation_complete": False,
        "exact_artifact_sha256": None,
        "remote_report_sha256": None,
        "input_binding_sha256": None,
        "safety": None,
        "bundles": [],
        "behavior_specific_findings": [],
        "admission_authority": False,
        "observed_clean": False,
        "reason_codes": sorted(
            {
                reason_code,
                "two_host_behavior_diagnostic_non_claim_bearing",
                "two_host_behavior_never_authorizes_admission",
            }
        ),
    }


def build_diagnostic(
    report_path: Path,
    bundle_root: Path,
    observer_directory: Path | None,
    explicit_observers: list[Path],
) -> dict[str, Any]:
    remote = validate_remote_report(report_path)
    errors: set[str] = set()
    bundles: dict[str, dict[str, Any]] = {}
    for path in collect_named_bundles(bundle_root):
        try:
            bundle = validate_bundle(path, remote)
            require(
                bundle["bundle_sha256"] not in bundles,
                "two_host_behavior_bundle_duplicate",
            )
            bundles[bundle["bundle_sha256"]] = bundle
        except DiagnosticError as error:
            errors.add(error.reason_code)
    declared = set(remote["declared"].values())
    if declared - set(bundles):
        errors.add("two_host_behavior_bundle_missing")
    if set(bundles) - declared:
        errors.add("two_host_behavior_bundle_extra")

    observers: dict[str, dict[str, Any]] = {}
    try:
        observer_paths = collect_observer_results(observer_directory, explicit_observers)
    except DiagnosticError as error:
        errors.add(error.reason_code)
        observer_paths = []
    seen_paths: set[Path] = set()
    for path in observer_paths:
        try:
            resolved = path.resolve(strict=True)
            require(
                resolved not in seen_paths,
                "two_host_behavior_observer_path_duplicate",
            )
            seen_paths.add(resolved)
            _, preview = read_json(path, "two_host_behavior_observer_result")
            bundle_sha256 = preview.get("bundle_sha256")
            require(
                bundle_sha256 in bundles and bundle_sha256 not in observers,
                "two_host_behavior_observer_bundle_invalid",
            )
            observers[bundle_sha256] = validate_observer(
                path, bundles[bundle_sha256], remote["artifact_sha256"]
            )
        except (OSError, DiagnosticError) as error:
            errors.add(
                error.reason_code
                if isinstance(error, DiagnosticError)
                else "two_host_behavior_observer_unavailable"
            )
    if declared - set(observers):
        errors.add("two_host_behavior_observer_missing")
    if set(observers) - declared:
        errors.add("two_host_behavior_observer_extra")

    action_by_digest = {digest: action for action, digest in remote["declared"].items()}
    rows: list[dict[str, Any]] = []
    preserved: list[dict[str, Any]] = []
    for action, digest in remote["declared"].items():
        bundle = bundles.get(digest)
        if bundle is None:
            continue
        observer = observers.get(digest)
        findings = observer["findings"] if observer else []
        row = {
            "action_key": action,
            "scenario_intent_sha256": remote["intent_bindings"][action],
            "bundle_sha256": digest,
            "scenario_id": bundle["scenario_id"],
            "scenario_sha256": bundle["scenario_sha256"],
            "run_id": bundle["run_id"],
            "event_count": bundle["event_count"],
            "evidence_coverage_complete": bundle["evidence_coverage_complete"],
            "observer_result_sha256": observer["result_sha256"] if observer else None,
            "observer_status": observer["status"] if observer else None,
            "provider_receipts": observer["provider_receipts"] if observer else [],
            "specialist_report_sha256s": (
                observer["specialist_report_sha256s"] if observer else []
            ),
            "measured_correlation_json_sha256": (
                observer["measured_correlation_json_sha256"] if observer else None
            ),
            "behavior_specific_findings": findings,
        }
        rows.append(row)
        preserved.extend(
            {"action_key": action_by_digest[digest], "bundle_sha256": digest, "finding": finding}
            for finding in findings
        )

    complete = not errors
    verdict = "diagnostic_detection" if complete and preserved else "inconclusive"
    reason_codes = {
        "two_host_behavior_diagnostic_non_claim_bearing",
        "two_host_behavior_never_authorizes_admission",
        *errors,
    }
    reason_codes.add(
        "two_host_behavior_specific_finding_preserved"
        if verdict == "diagnostic_detection"
        else "two_host_behavior_no_complete_detection_result"
    )
    binding = {
        "artifact_sha256": remote["artifact_sha256"],
        "remote_report_sha256": remote["report_sha256"],
        "bundles": [
            [row["bundle_sha256"], row["observer_result_sha256"]] for row in rows
        ],
    }
    return {
        "schema_version": SCHEMA,
        "verdict": verdict,
        "exit_code": 20 if verdict == "diagnostic_detection" else 22,
        "diagnostic_only": True,
        "claim_bearing": False,
        "reconciliation_complete": complete,
        "exact_artifact_sha256": remote["artifact_sha256"],
        "manifest_sha256": remote["manifest_sha256"],
        "remote_report_sha256": remote["report_sha256"],
        "detonation_provider": remote["provider"],
        "detonation_status": remote["detonation_status"],
        "input_binding_sha256": json_sha256(binding),
        "safety": remote["safety"],
        "bundles": rows,
        "behavior_specific_findings": preserved,
        "admission_authority": False,
        "observed_clean": False,
        "reason_codes": sorted(reason_codes),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-report", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--observer-result-dir", type=Path)
    parser.add_argument("--observer-result", action="append", default=[], type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        result = build_diagnostic(
            args.remote_report,
            args.bundle_dir,
            args.observer_result_dir,
            args.observer_result,
        )
    except DiagnosticError as error:
        result = minimal_inconclusive(error.reason_code)
    print(json.dumps(result, indent=2, sort_keys=True))
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
