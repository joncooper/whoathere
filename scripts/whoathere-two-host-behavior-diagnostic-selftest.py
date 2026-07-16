#!/usr/bin/env python3
"""Hermetic happy-path and fail-closed checks for the two-host bridge."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


SCRIPT = Path(__file__).with_name("whoathere-two-host-behavior-diagnostic.py")


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def compact_digest(value: Any) -> str:
    return digest(json.dumps(value, separators=(",", ":")).encode())


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")


def make_bundle(artifact: str, manifest: str, run_id: str = "wheel-run-0") -> tuple[dict[str, Any], bytes]:
    event = {
        "sequence": 1,
        "event_id": "file-1-protected-canary-read-0",
        "source_receipt_sha256": digest(b"root-file-receipt"),
        "signal": {"kind": "canary", "action": "read", "canary": "pypi_token"},
        "untrusted_detail": None,
    }
    bundle = {
        "schema_version": "whoathere.behavior_analysis_bundle.v1",
        "artifact_sha256": artifact,
        "manifest_sha256": manifest,
        "scenario_id": "wheel.install_exact.v1",
        "scenario_sha256": digest(b"wheel-scenario"),
        "run_id": run_id,
        "root_receipt_sha256": digest(b"root-receipt"),
        "host_receipt_sha256": digest(b"host-receipt"),
        "coverage": [
            {"modality": name, "state": "incomplete", "limitation_codes": ["fixture"]}
            for name in ["process", "filesystem", "canary", "network", "scenario"]
        ],
        "events": [event],
    }
    return bundle, json.dumps(bundle, separators=(",", ":")).encode()


def make_report(artifact: str, manifest: str, bundle_sha256: str) -> dict[str, Any]:
    return {
        "schema_version": "whoathere.exact_artifact_inspection.v1",
        "identity": {
            "artifact_sha256": artifact,
            "manifest_sha256": manifest,
            "ecosystem": "pypi",
        },
        "stages": [
            {
                "stage": "detonation",
                "status": "incomplete",
                "provider": "linux_vz_exact_wheel_v1",
                "artifact_sha256": artifact,
                "manifest_sha256": manifest,
                "reason_codes": [
                    "vm_wheel_action_0_behavior_bundle_sha256:"
                    + bundle_sha256.removeprefix("sha256:")
                ],
            }
        ],
        "scenario_plan": {
            "artifact_sha256": artifact,
            "manifest_sha256": manifest,
            "plan_sha256": digest(b"scenario-plan"),
            "intent_count": 1,
        },
        "admission_authority": False,
        "observed_clean": False,
        "sync_back_enabled": False,
        "sanitized_projection": True,
        "raw_source_or_telemetry_included": False,
    }


def make_observer(bundle: dict[str, Any], bundle_sha256: str, positive: bool) -> dict[str, Any]:
    event = bundle["events"][0]
    evidence = [{"event_id": event["event_id"], "event_sha256": compact_digest(event)}]
    finding = {
        "kind": "canary_access",
        "finding_sha256": digest(b"canary-finding"),
        "evidence": evidence,
    }
    findings = [finding] if positive else []
    correlation = {
        "bundle_sha256": bundle_sha256,
        "conclusion": "behavior_detected" if positive else "uncertain",
        "findings": findings,
        "specialist_report_sha256s": [digest(b"specialist")],
        "positive_preservation_verified": True,
    }
    role = "credential_and_canary"
    receipt = {
        "provider": "codex",
        "bundle_sha256": bundle_sha256,
        "selected_role": role,
        "provider_output_sha256": digest(b"provider-output"),
    }
    return {
        "schema_version": "whoathere.behavior_observe.v1",
        "status": "behavior_detected" if positive else "inconclusive",
        "exit_code": 20 if positive else 22,
        "provider": "codex",
        "artifact_sha256": bundle["artifact_sha256"],
        "bundle_sha256": bundle_sha256,
        "observe_only": True,
        "admission_authority": False,
        "observed_clean": False,
        "panel": {
            "bundle_sha256": bundle_sha256,
            "observations": [{"selected_role": role, "receipt": receipt}],
            "correlation_report": correlation,
            "admission_authority": False,
            "observed_clean": False,
        },
    }


def run(report: Path, bundles: Path, observers: Path) -> tuple[int, dict[str, Any]]:
    completed = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--remote-report",
            str(report),
            "--bundle-dir",
            str(bundles),
            "--observer-result-dir",
            str(observers),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert not completed.stderr, completed.stderr
    return completed.returncode, json.loads(completed.stdout)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whoathere-two-host-selftest-") as temporary:
        root = Path(temporary)
        bundles = root / "bundles"
        observers = root / "observers"
        bundles.mkdir()
        observers.mkdir()
        artifact = digest(b"artifact")
        manifest = digest(b"manifest")
        bundle, bundle_raw = make_bundle(artifact, manifest)
        bundle_sha256 = digest(bundle_raw)
        (bundles / "behavior-bundle.json").write_bytes(bundle_raw)
        report_path = root / "report.json"
        result_path = observers / "result.json"
        write_json(report_path, make_report(artifact, manifest, bundle_sha256))

        write_json(result_path, make_observer(bundle, bundle_sha256, positive=True))
        code, result = run(report_path, bundles, observers)
        assert code == 20 and result["verdict"] == "diagnostic_detection", result
        assert result["reconciliation_complete"] is True, result
        assert result["scenario_plan_sha256"] == digest(b"scenario-plan"), result
        assert result["scenario_intent_count"] == 1, result
        assert "scenario_intent_sha256" not in result["bundles"][0], result
        assert result["behavior_specific_findings"][0]["finding"]["kind"] == "canary_access"
        assert result["admission_authority"] is False and result["observed_clean"] is False

        unsafe_projection = make_report(artifact, manifest, bundle_sha256)
        unsafe_projection["raw_source_or_telemetry_included"] = True
        write_json(report_path, unsafe_projection)
        code, result = run(report_path, bundles, observers)
        assert code == 22 and result["reconciliation_complete"] is False, result
        assert "two_host_remote_sanitized_projection_invalid" in result["reason_codes"]
        write_json(report_path, make_report(artifact, manifest, bundle_sha256))

        write_json(result_path, make_observer(bundle, bundle_sha256, positive=False))
        code, result = run(report_path, bundles, observers)
        assert code == 22 and result["verdict"] == "inconclusive", result
        assert result["reconciliation_complete"] is True and not result["behavior_specific_findings"]

        result_path.unlink()
        code, result = run(report_path, bundles, observers)
        assert code == 22 and result["reconciliation_complete"] is False, result
        assert "two_host_behavior_observer_missing" in result["reason_codes"]

        write_json(result_path, make_observer(bundle, bundle_sha256, positive=True))
        _, extra_raw = make_bundle(artifact, manifest, "wheel-run-extra")
        extra_path = bundles / "extra" / "behavior-bundle.json"
        extra_path.parent.mkdir()
        extra_path.write_bytes(extra_raw)
        code, result = run(report_path, bundles, observers)
        assert code == 22 and result["reconciliation_complete"] is False, result
        assert result["behavior_specific_findings"], result  # A mismatch cannot erase a valid positive.
        assert "two_host_behavior_bundle_extra" in result["reason_codes"]

        extra_path.unlink()
        tampered = make_observer(bundle, bundle_sha256, positive=True)
        tampered["panel"]["observations"][0]["receipt"]["bundle_sha256"] = digest(b"wrong")
        write_json(result_path, tampered)
        code, result = run(report_path, bundles, observers)
        assert code == 22 and result["reconciliation_complete"] is False, result
        assert "two_host_behavior_provider_receipt_mismatch" in result["reason_codes"]

    print("two-host behavior diagnostic selftest: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
