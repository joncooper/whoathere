#!/usr/bin/env python3
"""Hermetic success and failure tests for the split behavior exporter."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import stat
import subprocess
import tempfile


SCRIPT = Path(__file__).with_name("whoathere-export-split-behavior.py")
ARTIFACT = "sha256:" + "1" * 64
MANIFEST = "sha256:" + "2" * 64


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def bundle(index: int) -> bytes:
    value = {
        "schema_version": "whoathere.behavior_analysis_bundle.v1",
        "artifact_sha256": ARTIFACT,
        "manifest_sha256": MANIFEST,
        "scenario_id": f"wheel-import-{index}",
        "scenario_sha256": "sha256:" + str(index + 3) * 64,
        "run_id": f"run-{index}",
        "root_receipt_sha256": "sha256:" + str(index + 5) * 64,
        "host_receipt_sha256": "sha256:" + str(index + 7) * 64,
        "coverage": [
            {"modality": modality, "state": "complete", "limitation_codes": []}
            for modality in ("process", "filesystem", "canary", "network", "scenario")
        ],
        "events": [],
    }
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def static_evidence(range_kind: str) -> dict[str, object]:
    if range_kind == "lines":
        range_value = {
            "kind": "lines",
            "start_line": 7,
            "end_line": 7,
            "start_byte": 32,
            "end_byte": 47,
        }
    elif range_kind == "bytes":
        range_value = {"kind": "bytes", "start_byte": 32, "end_byte": 47}
    else:
        raise ValueError(range_kind)
    return {
        "source": "deterministic_static",
        "source_receipt_sha256": "sha256:" + "b" * 64,
        "evidence_sha256": "sha256:" + "d" * 64,
        "package_source_included": False,
        "selected_bytes_included": False,
        "location": {
            "file_id": "sha256:" + "e" * 64,
            "file_sha256": "sha256:" + "f" * 64,
            "kind": "file",
            "range": range_value,
            "selected_bytes_sha256": "sha256:" + "0" * 64,
        },
    }


def report(
    bundle_digests: list[str],
    *,
    static_positive: bool = False,
    non_static_positive: bool = False,
    static_range_kind: str = "lines",
) -> bytes:
    reasons = [
        f"vm_wheel_action_{index}_behavior_bundle_sha256:{value.removeprefix('sha256:')}"
        for index, value in enumerate(bundle_digests)
    ]
    observations: list[dict[str, object]] = []
    if static_positive:
        observations.append(
            {
                "schema_version": "whoathere.exact_artifact_observation.v1",
                "source": "deterministic_static",
                "threat_class": "second_stage_native_or_wasm_handoff",
                "finding_kind": {
                    "source": "deterministic_static",
                    "kind": "download_execute_capability",
                },
                "confidence": "high",
                "artifact_sha256": ARTIFACT,
                "manifest_sha256": MANIFEST,
                "coverage": "complete",
                "behavior_detection_eligible": True,
                "observation_sha256": digest(b"static-download-execute"),
                "evidence": static_evidence(static_range_kind),
                "coverage_gap_codes": [],
            }
        )
    if non_static_positive:
        observations.append(
            {
                "schema_version": "whoathere.exact_artifact_observation.v1",
                "source": "codex_behavioral",
                "threat_class": "credential_and_sensitive_file_discovery",
                "finding_kind": {
                    "source": "codex_behavioral",
                    "kind": "credential_access",
                },
                "confidence": "high",
                "artifact_sha256": ARTIFACT,
                "manifest_sha256": MANIFEST,
                "coverage": "complete",
                "behavior_detection_eligible": True,
                "observation_sha256": digest(b"codex-credential-access"),
                "evidence": None,
                "coverage_gap_codes": [],
            }
        )
    value = {
        "schema_version": "whoathere.exact_artifact_inspection.v1",
        "status": "blocked",
        "verdict": "incomplete",
        "exit_code": 65,
        "identity": {
            "artifact_sha256": ARTIFACT,
            "envelope_sha256": "sha256:" + "9" * 64,
            "manifest_sha256": MANIFEST,
            "byte_length": 123,
            "ecosystem": "pypi",
            "artifact_format": "wheel",
            "source_type": "local_file",
            "acquisition_method": "exact_artifact",
        },
        "stages": [
            {
                "stage": "detonation",
                "status": "completed",
                "provider": "linux_vz_exact_wheel_v1",
                "artifact_sha256": ARTIFACT,
                "manifest_sha256": MANIFEST,
                "request_sha256": "sha256:" + "a" * 64,
                "result_sha256": "sha256:" + "b" * 64,
                "observation_count": 0,
                "reason_codes": reasons,
            }
        ],
        "scenario_plan": {
            "schema_version": "whoathere.scenario_plan.v1",
            "artifact_sha256": ARTIFACT,
            "manifest_sha256": MANIFEST,
            "status": "compiled",
            "plan_sha256": "sha256:" + "c" * 64,
            "runtime_binding_required": True,
            "runtime_binding_status": "verified",
            "executable": "whoathere",
            "intent_count": len(bundle_digests),
            "reason_codes": [],
        },
        "observations": observations,
        "behavior_detection_count": len(observations),
        "admission_authority": False,
        "observed_clean": False,
        "sync_back_enabled": False,
        "reason_codes": [],
        "sanitized_projection": True,
        "raw_source_or_telemetry_included": False,
    }
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_inputs(root: Path) -> tuple[Path, Path, list[bytes]]:
    output = root / "detonation-output"
    output.mkdir()
    bundles = [bundle(0), bundle(1)]
    for index, raw in enumerate(bundles):
        path = output / f"run/action-{index:04}/evidence/behavior-bundle.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(raw)
    report_path = root / "sanitized-report.json"
    report_path.write_bytes(
        report([digest(raw) for raw in bundles], static_positive=True)
    )
    return report_path, output, bundles


def run(report_path: Path, output: Path, export: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(SCRIPT),
            "--sanitized-report",
            str(report_path),
            "--detonation-output-root",
            str(output),
            "--export-dir",
            str(export),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require_rejected(result: subprocess.CompletedProcess[str], reason: str) -> None:
    assert result.returncode != 0, result.stdout
    assert f"split_behavior_export_error={reason}" in result.stderr, result.stderr


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whoathere-split-behavior-export-selftest-") as temp:
        root = Path(temp)
        report_path, output, bundles = write_inputs(root)
        bundle_digests = [digest(raw) for raw in bundles]

        exported = root / "export-success"
        success = run(report_path, output, exported)
        assert success.returncode == 0, success.stderr
        result = json.loads(success.stdout)
        assert result["bundle_count"] == 2, result
        manifest = json.loads((exported / "export-manifest.json").read_text(encoding="utf-8"))
        assert manifest["raw_evidence_included"] is False, manifest
        assert manifest["artifact_bytes_included"] is False, manifest
        exported_report = json.loads(
            (exported / "sanitized-exact-artifact-report.json").read_text(
                encoding="utf-8"
            )
        )
        assert exported_report["observations"][0]["finding_kind"] == {
            "source": "deterministic_static",
            "kind": "download_execute_capability",
        }, exported_report
        exported_evidence = exported_report["observations"][0]["evidence"]
        assert set(exported_evidence) == {
            "source",
            "source_receipt_sha256",
            "evidence_sha256",
            "package_source_included",
            "selected_bytes_included",
            "location",
        }, exported_evidence
        assert (
            exported_evidence["package_source_included"] is False
        ), exported_evidence
        assert (
            exported_evidence["selected_bytes_included"] is False
        ), exported_evidence
        assert exported_evidence["location"]["kind"] == "file", exported_evidence
        assert exported_evidence["location"]["range"] == {
            "kind": "lines",
            "start_line": 7,
            "end_line": 7,
            "start_byte": 32,
            "end_byte": 47,
        }, exported_evidence
        assert "selected_bytes" not in exported_evidence["location"], exported_evidence
        for file_entry in manifest["files"]:
            copied = (exported / file_entry["path"]).read_bytes()
            assert file_entry["sha256"] == digest(copied), file_entry
            assert file_entry["byte_length"] == len(copied), file_entry
        assert {
            path.relative_to(exported).as_posix()
            for path in exported.rglob("*")
            if path.is_file()
        } == {
            "sanitized-exact-artifact-report.json",
            "bundles/vm_wheel_action_0/behavior-bundle.json",
            "bundles/vm_wheel_action_1/behavior-bundle.json",
            "export-manifest.json",
        }
        for path in (exported, *exported.rglob("*")):
            mode = stat.S_IMODE(path.stat().st_mode)
            assert mode == (0o700 if path.is_dir() else 0o600), (path, oct(mode))

        mixed_report_path = root / "mixed-observations-report.json"
        mixed_report_path.write_bytes(
            report(
                bundle_digests,
                static_positive=True,
                non_static_positive=True,
            )
        )
        mixed_export = root / "export-mixed-observations"
        mixed_success = run(mixed_report_path, output, mixed_export)
        assert mixed_success.returncode == 0, mixed_success.stderr
        mixed_exported_report = json.loads(
            (mixed_export / "sanitized-exact-artifact-report.json").read_text(
                encoding="utf-8"
            )
        )
        assert mixed_exported_report["observations"][1]["source"] == "codex_behavioral"
        assert mixed_exported_report["observations"][1]["evidence"] is None

        byte_report_path = root / "byte-range-report.json"
        byte_report_path.write_bytes(
            report(
                bundle_digests,
                static_positive=True,
                static_range_kind="bytes",
            )
        )
        byte_export = root / "export-byte-range"
        byte_success = run(byte_report_path, output, byte_export)
        assert byte_success.returncode == 0, byte_success.stderr
        byte_exported_report = json.loads(
            (byte_export / "sanitized-exact-artifact-report.json").read_text(
                encoding="utf-8"
            )
        )
        assert byte_exported_report["observations"][0]["evidence"]["location"][
            "range"
        ] == {"kind": "bytes", "start_byte": 32, "end_byte": 47}

        missing_root = root / "missing-output"
        missing_root.mkdir()
        path = missing_root / "action/evidence/behavior-bundle.json"
        path.parent.mkdir(parents=True)
        path.write_bytes(bundles[0])
        require_rejected(
            run(report_path, missing_root, root / "export-missing"),
            "split_behavior_export_bundle_missing",
        )

        duplicate_root = root / "duplicate-output"
        duplicate_root.mkdir()
        for name in ("first", "second"):
            path = duplicate_root / name / "behavior-bundle.json"
            path.parent.mkdir()
            path.write_bytes(bundles[0])
        other = duplicate_root / "other/behavior-bundle.json"
        other.parent.mkdir()
        other.write_bytes(bundles[1])
        require_rejected(
            run(report_path, duplicate_root, root / "export-duplicate"),
            "split_behavior_export_bundle_duplicate",
        )

        mismatch_report = root / "mismatch-report.json"
        mismatch_report.write_bytes(report([digest(bundles[0]), "sha256:" + "f" * 64]))
        require_rejected(
            run(mismatch_report, output, root / "export-mismatch"),
            "split_behavior_export_bundle_digest_mismatch",
        )

        unknown_root = root / "unknown-field-output"
        unknown_root.mkdir()
        invalid_bundle = json.loads(bundles[0])
        invalid_bundle["raw_artifact_bytes"] = "forbidden"
        invalid_raw = json.dumps(invalid_bundle, separators=(",", ":")).encode("utf-8")
        invalid_path = unknown_root / "action/behavior-bundle.json"
        invalid_path.parent.mkdir()
        invalid_path.write_bytes(invalid_raw)
        unknown_report = root / "unknown-field-report.json"
        unknown_report.write_bytes(report([digest(invalid_raw)]))
        require_rejected(
            run(unknown_report, unknown_root, root / "export-unknown-field"),
            "split_behavior_export_bundle_invalid",
        )

        detail_root = root / "untrusted-detail-output"
        detail_root.mkdir()
        detail_bundle = json.loads(bundles[0])
        detail_bundle["events"] = [
            {
                "sequence": 1,
                "event_id": "event-1",
                "source_receipt_sha256": "sha256:" + "d" * 64,
                "signal": {
                    "kind": "filesystem",
                    "operation": "read",
                    "target": "credential_file",
                },
                "untrusted_detail": "forbidden raw detail",
            }
        ]
        detail_raw = json.dumps(detail_bundle, separators=(",", ":")).encode("utf-8")
        detail_path = detail_root / "action/behavior-bundle.json"
        detail_path.parent.mkdir()
        detail_path.write_bytes(detail_raw)
        detail_report = root / "untrusted-detail-report.json"
        detail_report.write_bytes(report([digest(detail_raw)]))
        require_rejected(
            run(detail_report, detail_root, root / "export-untrusted-detail"),
            "split_behavior_export_bundle_invalid",
        )

        invalid_report_value = json.loads(report_path.read_bytes())
        invalid_report_value["raw_telemetry"] = "forbidden"
        invalid_report = root / "unknown-report-field.json"
        invalid_report.write_text(json.dumps(invalid_report_value), encoding="utf-8")
        require_rejected(
            run(invalid_report, output, root / "export-unknown-report-field"),
            "split_behavior_export_report_not_sanitized",
        )

        raw_evidence_value = json.loads(report_path.read_bytes())
        raw_evidence_value["observations"][0]["evidence"]["location"][
            "selected_bytes"
        ] = "forbidden package content"
        raw_evidence_report = root / "raw-evidence-report.json"
        raw_evidence_report.write_text(json.dumps(raw_evidence_value), encoding="utf-8")
        require_rejected(
            run(raw_evidence_report, output, root / "export-raw-evidence"),
            "split_behavior_export_report_not_sanitized",
        )

        source_included_value = json.loads(report_path.read_bytes())
        source_included_value["observations"][0]["evidence"][
            "package_source_included"
        ] = True
        source_included_report = root / "source-included-report.json"
        source_included_report.write_text(
            json.dumps(source_included_value), encoding="utf-8"
        )
        require_rejected(
            run(source_included_report, output, root / "export-source-included"),
            "split_behavior_export_report_not_sanitized",
        )

        non_file_location_value = json.loads(report_path.read_bytes())
        non_file_location_value["observations"][0]["evidence"]["location"][
            "kind"
        ] = "file_range"
        non_file_location_report = root / "non-file-location-report.json"
        non_file_location_report.write_text(
            json.dumps(non_file_location_value), encoding="utf-8"
        )
        require_rejected(
            run(non_file_location_report, output, root / "export-non-file-location"),
            "split_behavior_export_report_not_sanitized",
        )

        non_static_evidence_value = json.loads(mixed_report_path.read_bytes())
        non_static_evidence_value["observations"][1]["evidence"] = static_evidence(
            "lines"
        )
        non_static_evidence_report = root / "non-static-evidence-report.json"
        non_static_evidence_report.write_text(
            json.dumps(non_static_evidence_value), encoding="utf-8"
        )
        require_rejected(
            run(
                non_static_evidence_report,
                output,
                root / "export-non-static-evidence",
            ),
            "split_behavior_export_report_not_sanitized",
        )

        invalid_byte_order_value = json.loads(byte_report_path.read_bytes())
        invalid_byte_order_value["observations"][0]["evidence"]["location"][
            "range"
        ]["start_byte"] = 48
        invalid_byte_order_report = root / "invalid-byte-order-report.json"
        invalid_byte_order_report.write_text(
            json.dumps(invalid_byte_order_value), encoding="utf-8"
        )
        require_rejected(
            run(
                invalid_byte_order_report,
                output,
                root / "export-invalid-byte-order",
            ),
            "split_behavior_export_report_not_sanitized",
        )

        byte_extra_key_value = json.loads(byte_report_path.read_bytes())
        byte_extra_key_value["observations"][0]["evidence"]["location"]["range"][
            "start_line"
        ] = 7
        byte_extra_key_report = root / "byte-extra-key-report.json"
        byte_extra_key_report.write_text(
            json.dumps(byte_extra_key_value), encoding="utf-8"
        )
        require_rejected(
            run(byte_extra_key_report, output, root / "export-byte-extra-key"),
            "split_behavior_export_report_not_sanitized",
        )

    print("whoathere_split_behavior_export_selftest=pass")
    print("success_missing_duplicate_mismatch=covered")
    print("private_sanitized_export_only=verified")
    print("unknown_raw_fields=rejected")
    print("typed_static_and_null_non_static_evidence=verified")
    print("line_and_byte_evidence_ranges=verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
