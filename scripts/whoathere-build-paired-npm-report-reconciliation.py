#!/usr/bin/env python3
"""Build the self-contained, prose-free P05 npm report reconciliation envelope.

This assembler reads only sanitized report, typed-bundle, Codex-result, and reconciliation JSON.
The Rust product boundary independently validates the resulting envelope before rendering it.
"""

from __future__ import annotations

import argparse
import json
import runpy
import stat
import sys
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
BRIDGE = runpy.run_path(str(SCRIPT_DIR / "whoathere-two-host-behavior-diagnostic.py"))
SCHEMA = "whoathere.paired_npm_report_reconciliation.v1"
PROFILE_BY_ACTION = {"vm_ci_false": "ci_false", "vm_ci_true": "ci_true"}

DiagnosticError = BRIDGE["DiagnosticError"]
build_diagnostic = BRIDGE["build_diagnostic"]
collect_named_bundles = BRIDGE["collect_named_bundles"]
read_json = BRIDGE["read_json"]
sha256_bytes = BRIDGE["sha256_bytes"]
validate_remote_report = BRIDGE["validate_remote_report"]


def require(condition: bool, reason_code: str) -> None:
    if not condition:
        raise DiagnosticError(reason_code)


def normalized_finding(finding: Any) -> dict[str, Any]:
    require(isinstance(finding, dict), "paired_npm_envelope_finding_invalid")
    evidence = finding.get("evidence")
    require(isinstance(evidence, list) and evidence, "paired_npm_envelope_finding_invalid")
    projected_evidence = []
    for reference in evidence:
        require(isinstance(reference, dict), "paired_npm_envelope_finding_invalid")
        projected_evidence.append(
            {
                "event_id": reference.get("event_id"),
                "event_sha256": reference.get("event_sha256"),
            }
        )
    projected_evidence.sort(key=lambda value: (value["event_id"], value["event_sha256"]))
    return {
        "kind": finding.get("kind"),
        "threat_class": finding.get("threat_class"),
        "confidence": finding.get("confidence"),
        "evidence": projected_evidence,
        "finding_sha256": finding.get("finding_sha256"),
    }


def build_envelope(args: argparse.Namespace) -> dict[str, Any]:
    report_raw, _ = read_json(args.remote_report, "paired_npm_envelope_report")
    export_raw, export = read_json(args.export_manifest, "paired_npm_envelope_export")
    reconciliation_raw, source_reconciliation = read_json(
        args.source_reconciliation, "paired_npm_envelope_source_reconciliation"
    )
    diagnostic = build_diagnostic(
        args.remote_report,
        args.bundle_dir,
        None,
        args.observer_result,
    )
    require(
        source_reconciliation == diagnostic,
        "paired_npm_envelope_source_reconciliation_mismatch",
    )
    require(
        diagnostic.get("schema_version") == "whoathere.two_host_behavior_diagnostic.v1"
        and diagnostic.get("reconciliation_complete") is True
        and diagnostic.get("diagnostic_only") is True
        and diagnostic.get("claim_bearing") is False
        and diagnostic.get("admission_authority") is False
        and diagnostic.get("observed_clean") is False,
        "paired_npm_envelope_source_reconciliation_invalid",
    )
    remote = validate_remote_report(args.remote_report)
    require(
        export.get("schema_version") == "whoathere.split_behavior_export.v1"
        and export.get("artifact_sha256") == remote["artifact_sha256"]
        and export.get("manifest_sha256") == remote["manifest_sha256"]
        and export.get("sanitized_report_sha256") == sha256_bytes(report_raw)
        and export.get("bundle_count") == 2
        and export.get("raw_evidence_included") is False
        and export.get("artifact_bytes_included") is False
        and export.get("package_source_included") is False,
        "paired_npm_envelope_export_invalid",
    )

    bundles: dict[str, dict[str, Any]] = {}
    for path in collect_named_bundles(args.bundle_dir):
        raw, bundle = read_json(path, "paired_npm_envelope_bundle")
        digest = sha256_bytes(raw)
        require(digest not in bundles, "paired_npm_envelope_bundle_duplicate")
        bundles[digest] = bundle

    observers: dict[str, tuple[str, dict[str, Any]]] = {}
    for path in args.observer_result:
        raw, observer = read_json(path, "paired_npm_envelope_observer")
        bundle_sha256 = observer.get("bundle_sha256")
        require(
            isinstance(bundle_sha256, str) and bundle_sha256 not in observers,
            "paired_npm_envelope_observer_duplicate",
        )
        observers[bundle_sha256] = (sha256_bytes(raw), observer)

    source_rows = {
        row.get("action_key"): row
        for row in diagnostic.get("bundles", [])
        if isinstance(row, dict)
    }
    require(
        set(source_rows) == set(PROFILE_BY_ACTION),
        "paired_npm_envelope_profile_set_invalid",
    )
    profiles = []
    for action_key in ["vm_ci_false", "vm_ci_true"]:
        source = source_rows[action_key]
        bundle_sha256 = source.get("bundle_sha256")
        bundle = bundles.get(bundle_sha256)
        observer_pair = observers.get(bundle_sha256)
        require(
            isinstance(bundle, dict) and observer_pair is not None,
            "paired_npm_envelope_profile_input_missing",
        )
        observer_sha256, observer = observer_pair
        require(
            observer_sha256 == source.get("observer_result_sha256"),
            "paired_npm_envelope_observer_identity_mismatch",
        )
        panel = observer.get("panel")
        correlation = panel.get("correlation_report") if isinstance(panel, dict) else None
        require(
            isinstance(correlation, dict),
            "paired_npm_envelope_correlation_missing",
        )
        findings = [normalized_finding(value) for value in correlation.get("findings", [])]
        findings.sort(key=lambda value: value["kind"])
        profiles.append(
            {
                "profile": PROFILE_BY_ACTION[action_key],
                "action_key": action_key,
                "bundle_sha256": bundle_sha256,
                "observer_result_sha256": observer_sha256,
                "event_count": source.get("event_count"),
                "evidence_coverage_complete": source.get("evidence_coverage_complete"),
                "behavior_bundle": bundle,
                "codex": {
                    "schema_version": observer.get("schema_version"),
                    "status": observer.get("status"),
                    "provider": observer.get("provider"),
                    "artifact_sha256": observer.get("artifact_sha256"),
                    "bundle_sha256": observer.get("bundle_sha256"),
                    "panel_schema_version": panel.get("schema_version"),
                    "panel_outcome": panel.get("outcome"),
                    "panel_reason_code": panel.get("reason_code"),
                    "provider_receipts": source.get("provider_receipts"),
                    "specialist_report_sha256s": source.get("specialist_report_sha256s"),
                    "measured_correlation_json_sha256": source.get(
                        "measured_correlation_json_sha256"
                    ),
                    "correlation_conclusion": correlation.get("conclusion"),
                    "missing_roles": correlation.get("missing_roles"),
                    "coverage_gap_codes": correlation.get("coverage_gap_codes"),
                    "positive_preservation_verified": correlation.get(
                        "positive_preservation_verified"
                    ),
                    "role_failure_count": len(panel.get("role_failures", [])),
                    "findings": findings,
                    "observe_only": observer.get("observe_only"),
                    "admission_authority": observer.get("admission_authority"),
                    "observed_clean": observer.get("observed_clean"),
                },
            }
        )

    return {
        "schema_version": SCHEMA,
        "artifact_sha256": diagnostic["exact_artifact_sha256"],
        "manifest_sha256": diagnostic["manifest_sha256"],
        "report_sha256": sha256_bytes(report_raw),
        "export_manifest_sha256": sha256_bytes(export_raw),
        "source_reconciliation_schema_version": diagnostic["schema_version"],
        "source_reconciliation_sha256": sha256_bytes(reconciliation_raw),
        "source_reconciliation_input_binding_sha256": diagnostic[
            "input_binding_sha256"
        ],
        "scenario_plan_sha256": diagnostic["scenario_plan_sha256"],
        "scenario_intent_count": diagnostic["scenario_intent_count"],
        "detonation_provider": diagnostic["detonation_provider"],
        "detonation_status": diagnostic["detonation_status"],
        "profiles": profiles,
        "reconciliation_complete": True,
        "diagnostic_only": True,
        "claim_bearing": False,
        "sanitized_projection": True,
        "raw_source_or_telemetry_included": False,
        "admission_authority": False,
        "observed_clean": False,
        "sync_back_enabled": False,
    }


def write_new_private(path: Path, content: bytes) -> None:
    parent = path.parent
    metadata = parent.lstat()
    require(
        stat.S_ISDIR(metadata.st_mode) and not parent.is_symlink(),
        "paired_npm_envelope_output_parent_invalid",
    )
    with path.open("xb") as handle:
        handle.write(content)
        handle.flush()
    path.chmod(0o600)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--remote-report", required=True, type=Path)
    parser.add_argument("--export-manifest", required=True, type=Path)
    parser.add_argument("--source-reconciliation", required=True, type=Path)
    parser.add_argument("--bundle-dir", required=True, type=Path)
    parser.add_argument("--observer-result", action="append", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        require(
            len(args.observer_result) == 2,
            "paired_npm_envelope_observer_count_invalid",
        )
        envelope = build_envelope(args)
        content = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")
        write_new_private(args.output, content)
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA,
                    "status": "complete",
                    "output_sha256": sha256_bytes(content),
                    "profile_count": len(envelope["profiles"]),
                    "raw_source_or_telemetry_included": False,
                    "admission_authority": False,
                },
                sort_keys=True,
            )
        )
        return 0
    except (DiagnosticError, OSError) as error:
        reason = error.reason_code if isinstance(error, DiagnosticError) else "paired_npm_envelope_output_failed"
        print(
            json.dumps(
                {
                    "schema_version": SCHEMA,
                    "status": "error",
                    "reason_code": reason,
                    "admission_authority": False,
                },
                sort_keys=True,
            )
        )
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
