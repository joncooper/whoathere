#!/usr/bin/env python3
"""Measure, invoke, and sign the narrow deterministic static-projection path.

The assembler invokes the absolute, manifest-pinned static verifier itself against the exact
artifact digest frozen in EvaluationManifestV2. It captures canonical verifier stdout directly,
copies only its exact ten-field DownloadExecuteCapability projections into a signed
verified_projection_bundle.v1, and invokes the current RunResultV2 publisher. It has no package
execution, networking, AI, verdict, observed-clean, release, or admission authority.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER_PATH = ROOT / "scripts" / "whoathere-run-result-v2-publisher.py"

RUN_INPUT_SCHEMA = "whoathere.static_projection_bundle_run_fact_inputs.v1"
PROJECTION_SCHEMA_DESCRIPTOR = "whoathere.static_download_execute_projection_schema.v1"
STATIC_METADATA_SCHEMA = "whoathere.static_download_execute_projection_metadata.v1"
STATIC_SOURCE_RECEIPT_SCHEMA = "whoathere.artifact_static_analysis.v1"
STATIC_PROJECTION_KIND = "static_download_execute_capability"
STATIC_METADATA_CLAIM_BOUNDARY = (
    "Verified deterministic capability only; no runtime-attempt, observed-clean, release, or "
    "admission authority."
)
PUBLISHER_CLAIM_BOUNDARY = (
    "Independent evidence projections only; no verdict, observed-clean, release, or admission authority."
)
STATIC_EVIDENCE_BINDING = "static_verifier_source_receipt"

PROJECTION_FIELDS = [
    "kind",
    "artifact_sha256",
    "artifact_manifest_sha256",
    "exact_observation_sha256",
    "finding_evidence_sha256",
    "file_id",
    "file_sha256",
    "range",
    "selected_bytes_sha256",
    "source_receipt_sha256",
]
PROJECTION_FIELD_SET = set(PROJECTION_FIELDS)
STATIC_METADATA_KEYS = {
    "schema",
    "verification_status",
    "claim_boundary",
    "verification_summary",
    "source_receipt_sha256",
    "projections",
    "projection_count",
    "admission_authority",
    "observed_clean",
}
STATIC_SUMMARY_KEYS = {
    "source_receipt_schema",
    "verification_method",
    "artifact_sha256",
    "artifact_manifest_sha256",
    "ecosystem",
    "artifact_format",
    "deterministic_analysis_sha256",
    "deterministic_analysis_status",
    "deterministic_reason_codes",
    "exact_observations",
    "package_execution_applied",
    "network_access_applied",
    "ai_applied",
    "vm_applied",
    "admission_authority",
    "observed_clean",
}
EXACT_OBSERVATION_KEYS = {
    "schema_version",
    "source",
    "threat_class",
    "finding_kind",
    "confidence",
    "artifact_sha256",
    "manifest_sha256",
    "evidence",
    "coverage",
    "coverage_gap_codes",
    "behavior_detection_eligible",
    "observation_sha256",
}
RUN_INPUT_KEYS = {
    "schema",
    "created_at_utc",
    "verified_at_utc",
    "run_id",
    "completion_state",
    "completion_gap_codes",
    "coverage",
    "safety",
}
SAFE_SAFETY = {
    "network_policy": "sinkhole_only",
    "host_package_execution_applied": False,
    "sync_back_applied": False,
    "live_c2_contacted": False,
    "live_second_stage_fetched": False,
    "restricted_material_leak": False,
    "teardown_verified": True,
}
EXPECTED_SCHEMA_DESCRIPTOR = {
    "schema": PROJECTION_SCHEMA_DESCRIPTOR,
    "metadata_schema": STATIC_METADATA_SCHEMA,
    "projection_kind": STATIC_PROJECTION_KIND,
    "projection_fields": PROJECTION_FIELDS,
    "range_variants": [
        {"kind": "bytes", "fields": ["kind", "start_byte", "end_byte"]},
        {
            "kind": "lines",
            "fields": ["kind", "start_line", "end_line", "start_byte", "end_byte"],
        },
    ],
}

MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_SCHEMA_BYTES = 1024 * 1024
MAX_RUN_INPUT_BYTES = 1024 * 1024
MAX_STATIC_METADATA_BYTES = 64 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024


class AssemblerError(Exception):
    """A stable fail-closed assembler error."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise AssemblerError(reason)


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"{name}_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - installation failure only.
        raise AssemblerError(f"{name}_module_unavailable") from exc
    return module


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def pretty_json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def exact_keys(value: Any, expected: set[str], reason: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{reason}_not_object")
    require(set(value) == expected, f"{reason}_keys_invalid")
    return value


def canonical_utc_seconds(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 20:
        return False
    punctuation = {4: "-", 7: "-", 10: "T", 13: ":", 16: ":", 19: "Z"}
    return all(
        character == punctuation[index] if index in punctuation else character.isdigit()
        for index, character in enumerate(value)
    )


def parse_utc(value: Any, reason: str, publisher: ModuleType) -> Any:
    try:
        return publisher.parse_utc(value, reason)
    except publisher.PublisherError as exc:
        raise AssemblerError(str(exc)) from exc


def regular_non_symlink(path: Path, reason: str) -> os.stat_result:
    require(path.is_absolute(), f"{reason}_path_not_absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AssemblerError(f"{reason}_unavailable") from exc
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), f"{reason}_not_regular")
    require(metadata.st_size > 0, f"{reason}_empty")
    return metadata


def write_exclusive(path: Path, payload: bytes) -> None:
    require(path.is_absolute(), "output_path_not_absolute")
    require(path.parent.is_dir(), "output_parent_missing")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise AssemblerError("output_create_failed") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def write_output_set(outputs: list[tuple[Path, bytes]]) -> None:
    paths = [path for path, _ in outputs]
    require(len(paths) == len(set(paths)), "output_paths_must_differ")
    require(all(not path.exists() for path in paths), "output_already_exists")
    written: list[Path] = []
    try:
        for path, payload in outputs:
            write_exclusive(path, payload)
            written.append(path)
    except Exception:
        for path in reversed(written):
            try:
                path.unlink()
            except OSError:
                pass
        raise


def load_canonical_json(
    *,
    path: Path,
    maximum_bytes: int,
    reason: str,
    publisher: ModuleType,
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = publisher.read_regular(path, maximum_bytes, reason)
        value = publisher.load_json_bytes(raw, reason)
    except publisher.PublisherError as exc:
        raise AssemblerError(str(exc)) from exc
    require(isinstance(value, dict), f"{reason}_not_object")
    require(publisher.canonical_json_bytes(value) == raw, f"{reason}_not_canonical")
    return value, raw


def validate_projection_schema(path: Path, publisher: ModuleType) -> str:
    value, raw = load_canonical_json(
        path=path,
        maximum_bytes=MAX_SCHEMA_BYTES,
        reason="projection_schema",
        publisher=publisher,
    )
    require(value == EXPECTED_SCHEMA_DESCRIPTOR, "projection_schema_descriptor_invalid")
    return sha256_bytes(raw)


def load_run_inputs(path: Path, publisher: ModuleType) -> dict[str, Any]:
    value, _ = load_canonical_json(
        path=path,
        maximum_bytes=MAX_RUN_INPUT_BYTES,
        reason="run_fact_inputs",
        publisher=publisher,
    )
    exact_keys(value, RUN_INPUT_KEYS, "run_fact_inputs")
    require(value.get("schema") == RUN_INPUT_SCHEMA, "run_fact_inputs_schema_invalid")
    require(publisher.valid_identifier(value.get("run_id")), "run_fact_inputs_run_id_invalid")
    require(
        value.get("completion_state") in {"complete", "incomplete"},
        "run_fact_inputs_completion_state_invalid",
    )
    gaps = value.get("completion_gap_codes")
    require(
        isinstance(gaps, list)
        and gaps == sorted(set(gaps))
        and all(item in publisher.ALLOWED_COMPLETION_GAPS for item in gaps),
        "run_fact_inputs_completion_gaps_invalid",
    )
    exact_keys(value.get("safety"), publisher.SAFETY_KEYS, "run_fact_inputs_safety")
    require(value["safety"] == SAFE_SAFETY, "run_fact_inputs_safety_not_conservative")
    require(isinstance(value.get("coverage"), list) and value["coverage"], "run_fact_inputs_coverage_invalid")
    return value


def validate_artifact(path: Path) -> None:
    regular_non_symlink(path, "exact_artifact")


def invoke_static_verifier(
    *,
    verifier_raw: bytes,
    artifact_path: Path,
    ecosystem: str,
    acquired_at_utc: str,
    expected_artifact_sha256: str,
    timeout_seconds: int,
    publisher: ModuleType,
) -> tuple[dict[str, Any], bytes]:
    require(canonical_utc_seconds(acquired_at_utc), "artifact_acquired_at_invalid")
    with tempfile.TemporaryDirectory(prefix="whoathere-static-projection-invoke-") as raw_tmp:
        temporary = Path(raw_tmp)
        measured_verifier = temporary / "whoathere-static-projection"
        measured_verifier.write_bytes(verifier_raw)
        measured_verifier.chmod(0o500)
        environment = {
            "HOME": str(temporary),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(temporary),
        }
        try:
            process = subprocess.run(
                [
                    str(measured_verifier),
                    "--artifact",
                    str(artifact_path),
                    "--ecosystem",
                    ecosystem,
                    "--acquired-at",
                    acquired_at_utc,
                    "--expected-artifact-sha256",
                    expected_artifact_sha256,
                ],
                cwd=temporary,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise AssemblerError("static_verifier_timeout") from exc
        except OSError as exc:
            raise AssemblerError("static_verifier_invoke_failed") from exc
    require(process.returncode == 0, f"static_verifier_failed_exit_{process.returncode}")
    require(not process.stderr, "static_verifier_success_stderr_not_empty")
    require(0 < len(process.stdout) <= MAX_STATIC_METADATA_BYTES, "static_verifier_stdout_size_invalid")
    try:
        metadata = publisher.load_json_bytes(process.stdout, "static_verifier_metadata")
    except publisher.PublisherError as exc:
        raise AssemblerError(str(exc)) from exc
    require(isinstance(metadata, dict), "static_verifier_metadata_not_object")
    require(
        publisher.canonical_json_bytes(metadata) == process.stdout,
        "static_verifier_metadata_not_canonical",
    )
    return metadata, process.stdout


def validate_static_metadata(
    *,
    metadata: dict[str, Any],
    slot: dict[str, Any],
    publisher: ModuleType,
) -> tuple[list[dict[str, Any]], str, str]:
    exact_keys(metadata, STATIC_METADATA_KEYS, "static_verifier_metadata")
    require(metadata.get("schema") == STATIC_METADATA_SCHEMA, "static_verifier_metadata_schema_invalid")
    require(metadata.get("verification_status") == "verified", "static_verifier_status_invalid")
    require(metadata.get("claim_boundary") == STATIC_METADATA_CLAIM_BOUNDARY, "static_verifier_claim_boundary_invalid")
    require(metadata.get("admission_authority") is False, "static_verifier_admission_authority_invalid")
    require(metadata.get("observed_clean") is False, "static_verifier_observed_clean_invalid")

    summary = exact_keys(metadata.get("verification_summary"), STATIC_SUMMARY_KEYS, "static_verification_summary")
    require(summary.get("source_receipt_schema") == STATIC_SOURCE_RECEIPT_SCHEMA, "static_source_receipt_schema_invalid")
    require(
        summary.get("verification_method") == "exact_archive_reopen_normalize_redetect_v1",
        "static_verification_method_invalid",
    )
    require(summary.get("artifact_sha256") == slot.get("artifact_sha256"), "static_metadata_artifact_sha256_slot_mismatch")
    require(summary.get("ecosystem") == slot.get("ecosystem"), "static_metadata_ecosystem_slot_mismatch")
    require(publisher.valid_sha256(summary.get("artifact_manifest_sha256")), "static_metadata_manifest_sha256_invalid")
    source_receipt_sha256 = metadata.get("source_receipt_sha256")
    require(publisher.valid_sha256(source_receipt_sha256), "static_source_receipt_sha256_invalid")
    require(
        source_receipt_sha256 == summary.get("deterministic_analysis_sha256"),
        "static_source_receipt_analysis_mismatch",
    )
    for key in (
        "package_execution_applied",
        "network_access_applied",
        "ai_applied",
        "vm_applied",
        "admission_authority",
        "observed_clean",
    ):
        require(summary.get(key) is False, f"static_verification_summary_{key}_invalid")
    expected_formats = {
        "npm": {"npm_tar_gzip"},
        "pypi": {"wheel_zip", "sdist_tar_gzip", "sdist_zip"},
    }
    require(
        summary.get("artifact_format") in expected_formats.get(str(slot.get("ecosystem")), set()),
        "static_metadata_artifact_format_invalid",
    )
    analysis_status = summary.get("deterministic_analysis_status")
    require(
        analysis_status in {"findings", "findings_with_incomplete_coverage"},
        "static_metadata_analysis_status_invalid",
    )
    deterministic_state = "complete" if analysis_status == "findings" else "incomplete"
    reasons = summary.get("deterministic_reason_codes")
    require(
        isinstance(reasons, list)
        and reasons == sorted(set(reasons))
        and all(isinstance(reason, str) and reason for reason in reasons),
        "static_metadata_reason_codes_invalid",
    )

    projections = metadata.get("projections")
    count = metadata.get("projection_count")
    require(
        isinstance(projections, list)
        and projections
        and isinstance(count, int)
        and not isinstance(count, bool)
        and count == len(projections),
        "static_projection_count_invalid",
    )
    exact_observations = summary.get("exact_observations")
    require(
        isinstance(exact_observations, list) and len(exact_observations) == len(projections),
        "static_exact_observation_count_mismatch",
    )
    observations_by_sha256: dict[str, dict[str, Any]] = {}
    for observation in exact_observations:
        exact_keys(observation, EXACT_OBSERVATION_KEYS, "static_exact_observation")
        observation_sha256 = observation.get("observation_sha256")
        require(
            publisher.valid_sha256(observation_sha256)
            and str(observation_sha256) not in observations_by_sha256,
            "static_exact_observation_identity_invalid",
        )
        require(
            observation.get("schema_version") == "whoathere.exact_artifact_observation.v1"
            and observation.get("source") == "deterministic_static"
            and observation.get("threat_class") == "second_stage_native_or_wasm_handoff"
            and observation.get("finding_kind")
            == {"source": "deterministic_static", "kind": "download_execute_capability"}
            and observation.get("confidence") in {"moderate", "high"}
            and observation.get("artifact_sha256") == slot.get("artifact_sha256")
            and observation.get("manifest_sha256") == summary.get("artifact_manifest_sha256")
            and observation.get("behavior_detection_eligible") is True,
            "static_exact_observation_policy_invalid",
        )
        expected_observation_coverage = "complete" if deterministic_state == "complete" else "incomplete"
        expected_gap_codes = [] if deterministic_state == "complete" else ["deterministic_analysis_coverage_incomplete"]
        require(
            observation.get("coverage") == expected_observation_coverage
            and observation.get("coverage_gap_codes") == expected_gap_codes,
            "static_exact_observation_coverage_invalid",
        )
        observations_by_sha256[str(observation_sha256)] = observation
    require(
        list(observations_by_sha256) == sorted(observations_by_sha256),
        "static_exact_observations_not_sorted",
    )

    copied_projections: list[dict[str, Any]] = []
    projected_observation_ids: list[str] = []
    for projection in projections:
        exact_keys(projection, PROJECTION_FIELD_SET, "static_projection")
        require(projection.get("kind") == STATIC_PROJECTION_KIND, "static_projection_kind_invalid")
        require(projection.get("artifact_sha256") == slot.get("artifact_sha256"), "static_projection_artifact_mismatch")
        require(
            projection.get("artifact_manifest_sha256") == summary.get("artifact_manifest_sha256"),
            "static_projection_manifest_mismatch",
        )
        require(
            projection.get("source_receipt_sha256") == source_receipt_sha256,
            "static_projection_source_receipt_mismatch",
        )
        for key in (
            "exact_observation_sha256",
            "finding_evidence_sha256",
            "file_id",
            "file_sha256",
            "selected_bytes_sha256",
        ):
            require(publisher.valid_sha256(projection.get(key)), f"static_projection_{key}_invalid")
        try:
            publisher.validate_range(projection.get("range"))
        except publisher.PublisherError as exc:
            raise AssemblerError(str(exc)) from exc
        observation = observations_by_sha256.get(str(projection.get("exact_observation_sha256")))
        require(observation is not None, "static_projection_observation_unbound")
        evidence = exact_keys(
            observation.get("evidence"),
            {"source", "evidence_sha256", "location"},
            "static_observation_evidence",
        )
        location = exact_keys(
            evidence.get("location"),
            {"kind", "file_id", "file_sha256", "range", "selected_bytes_sha256"},
            "static_observation_location",
        )
        require(
            evidence.get("source") == "deterministic_static"
            and evidence.get("evidence_sha256") == projection.get("finding_evidence_sha256")
            and location
            == {
                "kind": "file",
                "file_id": projection.get("file_id"),
                "file_sha256": projection.get("file_sha256"),
                "range": projection.get("range"),
                "selected_bytes_sha256": projection.get("selected_bytes_sha256"),
            },
            "static_projection_observation_citation_mismatch",
        )
        projected_observation_ids.append(str(projection["exact_observation_sha256"]))
        copied_projections.append(copy.deepcopy(projection))
    require(projected_observation_ids == sorted(projected_observation_ids), "static_projections_not_sorted")
    require(
        set(projected_observation_ids) == set(observations_by_sha256),
        "static_projection_observation_set_mismatch",
    )
    try:
        publisher.project_observations(
            copied_projections,
            artifact_sha256=str(slot["artifact_sha256"]),
            coverage_modalities={"deterministic"},
        )
    except publisher.PublisherError as exc:
        raise AssemblerError(str(exc)) from exc
    return copied_projections, str(source_receipt_sha256), deterministic_state


def build_coverage_and_completion(
    *,
    run_inputs: dict[str, Any],
    slot: dict[str, Any],
    source_receipt_sha256: str,
    deterministic_state: str,
    publisher: ModuleType,
) -> tuple[list[dict[str, Any]], str, list[str]]:
    required_modalities = set(slot.get("required_modalities", []))
    expected_modalities = required_modalities | {"deterministic"}
    input_rows = run_inputs["coverage"]
    by_modality: dict[str, dict[str, Any]] = {}
    output_rows: list[dict[str, Any]] = []
    for row in input_rows:
        require(isinstance(row, dict), "run_fact_inputs_coverage_row_invalid")
        modality = row.get("modality")
        require(
            modality in publisher.ALLOWED_MODALITIES and str(modality) not in by_modality,
            "run_fact_inputs_coverage_modality_invalid",
        )
        state = row.get("state")
        require(state in publisher.ALLOWED_COVERAGE_STATES, "run_fact_inputs_coverage_state_invalid")
        if modality == "deterministic":
            exact_keys(row, {"modality", "state", "evidence_binding"}, "run_fact_inputs_static_coverage")
            require(row.get("evidence_binding") == STATIC_EVIDENCE_BINDING, "run_fact_inputs_static_binding_invalid")
            require(state == deterministic_state, "run_fact_inputs_static_state_mismatch")
            output = {
                "modality": "deterministic",
                "state": state,
                "evidence_sha256": source_receipt_sha256,
            }
        else:
            exact_keys(row, {"modality", "state", "evidence_sha256"}, "run_fact_inputs_other_coverage")
            require(state != "complete", "run_fact_inputs_unverified_modality_cannot_be_complete")
            require(publisher.valid_sha256(row.get("evidence_sha256")), "run_fact_inputs_coverage_digest_invalid")
            output = dict(row)
        by_modality[str(modality)] = output
        output_rows.append(output)
    require(set(by_modality) == expected_modalities, "run_fact_inputs_coverage_denominator_mismatch")
    output_rows = sorted(output_rows, key=lambda row: row["modality"])
    try:
        coverage = publisher.validate_coverage(output_rows, required_modalities)
    except publisher.PublisherError as exc:
        raise AssemblerError(str(exc)) from exc

    completion_state = str(run_inputs["completion_state"])
    gaps = list(run_inputs["completion_gap_codes"])
    if completion_state == "complete":
        require(not gaps, "run_fact_inputs_complete_has_gaps")
        require(
            expected_modalities == {"deterministic"} and deterministic_state == "complete",
            "run_fact_inputs_complete_not_proven",
        )
    else:
        require(bool(gaps), "run_fact_inputs_incomplete_requires_gap")
    for row in coverage:
        if row["state"] == "complete":
            continue
        modality = row["modality"]
        if row["state"] == "infrastructure_error":
            require("infrastructure_error" in gaps, "run_fact_inputs_infrastructure_gap_missing")
        elif row["state"] == "unsupported":
            require(
                "independent_verifier_unsupported_event" in gaps,
                "run_fact_inputs_unsupported_gap_missing",
            )
        elif modality == "deterministic":
            require("deterministic_coverage_incomplete" in gaps, "run_fact_inputs_static_gap_missing")
        elif modality == "dynamic":
            require("dynamic_coverage_incomplete" in gaps, "run_fact_inputs_dynamic_gap_missing")
        else:
            require(
                "independent_verifier_coverage_incomplete" in gaps,
                "run_fact_inputs_independent_gap_missing",
            )
    return coverage, completion_state, gaps


def sign_payload(
    *,
    payload: bytes,
    private_key_raw: bytes,
    public_key_raw: bytes,
    publisher: ModuleType,
) -> bytes:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl_missing")
    with tempfile.TemporaryDirectory(prefix="whoathere-static-bundle-sign-") as raw_tmp:
        temporary = Path(raw_tmp)
        payload_path = temporary / "payload.json"
        private_path = temporary / "private.pem"
        signature_path = temporary / "payload.sig"
        payload_path.write_bytes(payload)
        private_path.write_bytes(private_key_raw)
        private_path.chmod(0o600)
        signed = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_path),
                "-in",
                str(payload_path),
                "-out",
                str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(signed.returncode == 0, "bundle_signing_failed")
        signature = signature_path.read_bytes()
    try:
        publisher.verify_signature(payload, public_key_raw, signature)
    except publisher.PublisherError as exc:
        raise AssemblerError("bundle_signing_key_mismatch") from exc
    return signature


def invoke_and_verify_publisher(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    sample_id: str,
    profile_id: str,
    bundle_raw: bytes,
    signature_raw: bytes,
    public_key_raw: bytes,
    publisher: ModuleType,
) -> bytes:
    with tempfile.TemporaryDirectory(prefix="whoathere-static-bundle-publish-") as raw_tmp:
        temporary = Path(raw_tmp)
        bundle_path = temporary / "bundle.json"
        signature_path = temporary / "bundle.sig"
        public_key_path = temporary / "public.pem"
        result_path = temporary / "run-result.json"
        bundle_path.write_bytes(bundle_raw)
        signature_path.write_bytes(signature_raw)
        public_key_path.write_bytes(public_key_raw)
        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(PUBLISHER_PATH),
                "--evaluation-manifest",
                str(manifest_path),
                "--expected-evaluation-manifest-sha256",
                expected_manifest_sha256,
                "--sample-id",
                sample_id,
                "--profile-id",
                profile_id,
                "--verified-projection-bundle",
                str(bundle_path),
                "--verified-projection-signature",
                str(signature_path),
                "--verifier-public-key",
                str(public_key_path),
                "--out",
                str(result_path),
            ],
            cwd=temporary,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(process.returncode == 0, "run_result_publisher_failed")
        try:
            result_raw = publisher.read_regular(result_path, MAX_STATIC_METADATA_BYTES, "run_result")
            supplied = publisher.load_json_bytes(result_raw, "run_result")
            recomputed = publisher.publish(
                manifest_path=manifest_path,
                expected_manifest_sha256=expected_manifest_sha256,
                sample_id=sample_id,
                profile_id=profile_id,
                bundle_path=bundle_path,
                signature_path=signature_path,
                public_key_path=public_key_path,
            )
        except publisher.PublisherError as exc:
            raise AssemblerError(str(exc)) from exc
    require(isinstance(supplied, dict), "run_result_not_object")
    require(result_raw == pretty_json_bytes(supplied), "run_result_not_publisher_serialization")
    require(supplied == recomputed, "run_result_publisher_recompute_mismatch")
    return result_raw


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--evaluation-manifest", type=Path, required=True)
    result.add_argument("--expected-evaluation-manifest-sha256", required=True)
    result.add_argument("--sample-id", required=True)
    result.add_argument("--profile-id", required=True)
    result.add_argument("--artifact", type=Path, required=True)
    result.add_argument("--artifact-acquired-at", required=True)
    result.add_argument("--verifier-id", required=True)
    result.add_argument("--verifier-executable", type=Path, required=True)
    result.add_argument("--projection-schema", type=Path, required=True)
    result.add_argument("--verifier-public-key", type=Path, required=True)
    result.add_argument("--verifier-signing-private-key", type=Path, required=True)
    result.add_argument("--run-fact-inputs", type=Path, required=True)
    result.add_argument("--verifier-timeout-seconds", type=int, default=120)
    result.add_argument("--out-static-verifier-metadata", type=Path, required=True)
    result.add_argument("--out-bundle", type=Path, required=True)
    result.add_argument("--out-signature", type=Path, required=True)
    result.add_argument("--out-run-result", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        publisher = load_module("whoathere_run_result_v2_publisher", PUBLISHER_PATH)
        manifest_path = args.evaluation_manifest.expanduser().absolute()
        artifact_path = args.artifact.expanduser().absolute()
        verifier_path = args.verifier_executable.expanduser().absolute()
        schema_path = args.projection_schema.expanduser().absolute()
        public_key_path = args.verifier_public_key.expanduser().absolute()
        private_key_path = args.verifier_signing_private_key.expanduser().absolute()
        run_inputs_path = args.run_fact_inputs.expanduser().absolute()
        output_paths = [
            args.out_static_verifier_metadata.expanduser().absolute(),
            args.out_bundle.expanduser().absolute(),
            args.out_signature.expanduser().absolute(),
            args.out_run_result.expanduser().absolute(),
        ]
        require(
            1 <= args.verifier_timeout_seconds <= 600,
            "verifier_timeout_seconds_invalid",
        )
        require(len(output_paths) == len(set(output_paths)), "output_paths_must_differ")
        require(all(not path.exists() for path in output_paths), "output_already_exists")

        try:
            manifest_raw = publisher.read_regular(
                manifest_path, publisher.MAX_MANIFEST_BYTES, "evaluation_manifest"
            )
            require(
                publisher.sha256_bytes(manifest_raw)
                == args.expected_evaluation_manifest_sha256,
                "evaluation_manifest_digest_mismatch",
            )
            manifest = publisher.load_json_bytes(manifest_raw, "evaluation_manifest")
            require(isinstance(manifest, dict), "evaluation_manifest_not_object")
            slot = publisher.selected_run_slot(manifest, args.sample_id, args.profile_id)
            public_key_raw = publisher.read_regular(
                public_key_path, publisher.MAX_KEY_BYTES, "verifier_public_key"
            )
            private_key_raw = publisher.read_regular(
                private_key_path, MAX_PRIVATE_KEY_BYTES, "verifier_signing_private_key"
            )
            verifier_raw = publisher.read_regular(
                verifier_path, MAX_EXECUTABLE_BYTES, "verifier_executable"
            )
        except publisher.PublisherError as exc:
            raise AssemblerError(str(exc)) from exc
        verifier_metadata = regular_non_symlink(verifier_path, "verifier_executable")
        require(verifier_metadata.st_mode & 0o111 != 0, "verifier_executable_not_executable")
        validate_artifact(artifact_path)

        expected_registry = manifest.get("verified_evidence_registry")
        require(isinstance(expected_registry, dict), "manifest_verified_registry_invalid")
        require(args.verifier_id == expected_registry.get("verifier_id"), "verifier_id_pin_mismatch")
        require(
            sha256_bytes(verifier_raw) == expected_registry.get("verifier_executable_sha256"),
            "verifier_executable_sha256_pin_mismatch",
        )
        schema_sha256 = validate_projection_schema(schema_path, publisher)
        require(
            schema_sha256 == expected_registry.get("projection_schema_sha256"),
            "projection_schema_sha256_pin_mismatch",
        )
        public_key_sha256 = sha256_bytes(public_key_raw)
        require(
            public_key_sha256 == expected_registry.get("verifier_public_key_sha256"),
            "verifier_public_key_sha256_pin_mismatch",
        )

        run_inputs = load_run_inputs(run_inputs_path, publisher)
        starts_at = parse_utc(
            manifest["evaluation_window"]["starts_at_utc"], "evaluation_window_start_invalid", publisher
        )
        ends_at = parse_utc(
            manifest["evaluation_window"]["ends_at_utc"], "evaluation_window_end_invalid", publisher
        )
        created_at = parse_utc(
            run_inputs["created_at_utc"], "run_fact_created_at_invalid", publisher
        )
        verified_at = parse_utc(
            run_inputs["verified_at_utc"], "run_fact_verified_at_invalid", publisher
        )
        acquired_at = parse_utc(
            args.artifact_acquired_at, "artifact_acquired_at_invalid", publisher
        )
        require(acquired_at <= created_at, "artifact_acquired_after_run_creation")
        require(
            starts_at <= created_at <= verified_at <= ends_at,
            "run_fact_timestamp_order_invalid",
        )

        static_metadata, static_metadata_raw = invoke_static_verifier(
            verifier_raw=verifier_raw,
            artifact_path=artifact_path,
            ecosystem=str(slot["ecosystem"]),
            acquired_at_utc=args.artifact_acquired_at,
            expected_artifact_sha256=str(slot["artifact_sha256"]),
            timeout_seconds=args.verifier_timeout_seconds,
            publisher=publisher,
        )
        projections, source_receipt_sha256, deterministic_state = validate_static_metadata(
            metadata=static_metadata,
            slot=slot,
            publisher=publisher,
        )
        coverage, completion_state, completion_gaps = build_coverage_and_completion(
            run_inputs=run_inputs,
            slot=slot,
            source_receipt_sha256=source_receipt_sha256,
            deterministic_state=deterministic_state,
            publisher=publisher,
        )

        bundle = {
            "schema": publisher.BUNDLE_SCHEMA,
            "verified_at_utc": run_inputs["verified_at_utc"],
            "verifier_id": args.verifier_id,
            "verifier_executable_sha256": sha256_bytes(verifier_raw),
            "projection_schema_sha256": schema_sha256,
            "verifier_public_key_sha256": public_key_sha256,
            "verification_status": "verified",
            "run_fact": {
                "created_at_utc": run_inputs["created_at_utc"],
                "run_id": run_inputs["run_id"],
                "evaluation_id": manifest["evaluation_id"],
                "evaluation_manifest_sha256": args.expected_evaluation_manifest_sha256,
                "corpus_sha256": manifest["corpus_sha256"],
                "sample_id": args.sample_id,
                "profile_id": args.profile_id,
                "artifact_sha256": slot["artifact_sha256"],
                "execution_profile_sha256": slot["execution_profile_sha256"],
                "verifier_executable_sha256": sha256_bytes(verifier_raw),
                "projection_schema_sha256": schema_sha256,
                "ecosystem": slot["ecosystem"],
                "identities": manifest["identities"],
                "completion_state": completion_state,
                "completion_gap_codes": completion_gaps,
                "coverage": coverage,
                "safety": copy.deepcopy(run_inputs["safety"]),
            },
            "projections": projections,
            "claim_boundary": PUBLISHER_CLAIM_BOUNDARY,
        }
        bundle_raw = publisher.canonical_json_bytes(bundle)
        bundle_signature = sign_payload(
            payload=bundle_raw,
            private_key_raw=private_key_raw,
            public_key_raw=public_key_raw,
            publisher=publisher,
        )
        run_result_raw = invoke_and_verify_publisher(
            manifest_path=manifest_path,
            expected_manifest_sha256=args.expected_evaluation_manifest_sha256,
            sample_id=args.sample_id,
            profile_id=args.profile_id,
            bundle_raw=bundle_raw,
            signature_raw=bundle_signature,
            public_key_raw=public_key_raw,
            publisher=publisher,
        )
        write_output_set(
            list(
                zip(
                    output_paths,
                    [static_metadata_raw, bundle_raw, bundle_signature, run_result_raw],
                    strict=True,
                )
            )
        )
    except (AssemblerError, KeyError) as exc:
        reason = str(exc) if isinstance(exc, AssemblerError) else "required_binding_missing"
        print(reason, file=sys.stderr)
        return 20
    print(
        json.dumps(
            {
                "bundle_sha256": sha256_bytes(bundle_raw),
                "run_result_sha256": sha256_bytes(run_result_raw),
                "static_verifier_metadata_sha256": sha256_bytes(static_metadata_raw),
                "status": "signed_static_projection_bundle_published",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
