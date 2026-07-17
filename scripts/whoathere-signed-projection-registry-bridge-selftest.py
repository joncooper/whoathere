#!/usr/bin/env python3
"""Hermetic end-to-end tests for the signed projection registry bridge.

The fixture is synthetic metadata only. It does not contain, inspect, install, or execute package
content and does not use a network or lab host.
"""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "scripts" / "whoathere-run-result-v2-publisher.py"
BRIDGE = ROOT / "scripts" / "whoathere-signed-projection-registry-bridge.py"
EVALUATOR = ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"

EXECUTION_PROFILE_SHA256 = "sha256:" + "8" * 64
VERIFIER_EXECUTABLE_SHA256 = "sha256:" + "6" * 64
PROJECTION_SCHEMA_SHA256 = "sha256:" + "7" * 64
CLAIM_BOUNDARY = (
    "Independent evidence projections only; no verdict, observed-clean, release, or admission authority."
)
RUN_SPECS = [
    ("synthetic-static-wheel-a", "wheel-static-v1", "a"),
    ("synthetic-static-wheel-b", "wheel-static-v1", "b"),
    ("synthetic-static-sdist-c", "sdist-static-v1", "c"),
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def pretty(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(pretty(value))


def key_pair(root: Path, name: str = "verifier") -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl is required")
    private = root / f"{name}-private.pem"
    public = root / f"{name}-public.pem"
    subprocess.run(
        [openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    subprocess.run(
        [openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )
    return private, public


def sign(private: Path, payload: Path, signature: Path) -> None:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl is required")
    subprocess.run(
        [
            openssl,
            "pkeyutl",
            "-sign",
            "-rawin",
            "-inkey",
            str(private),
            "-in",
            str(payload),
            "-out",
            str(signature),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=True,
    )


def corpus_row(sample_id: str, digest_char: str) -> dict[str, Any]:
    is_sdist = "sdist" in sample_id
    return {
        "schema_version": "whoathere.actual_malware.corpus.v1",
        "sample_id": sample_id,
        "sample_kind": "malware",
        "ecosystem": "pypi",
        "package_name": sample_id,
        "package_version": "1.0.0",
        "artifact_filename": sample_id + (".tar.gz" if is_sdist else ".whl"),
        "artifact_sha256": "sha256:" + digest_char * 64,
        "artifact_size_bytes": 64,
        "source_type": "lab_benign_fixture",
        "source_reference": "synthetic:signed-projection-bridge",
        "disclosure_date": "2026-07-01",
        "expected_result": "malicious",
        "trigger_phases": ["pypi_pep517" if is_sdist else "python_import"],
        "behavior_labels": ["second_stage_fetch"],
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "acquisition": {
            "case_id": "synthetic-bridge-selftest",
            "allowed_test_purpose": "hermetic registry bridge selftest",
            "acquired_at_utc": "2026-07-01T00:00:00Z",
            "collector": "selftest",
            "reviewer": "selftest",
            "authorization": "synthetic-only",
            "custody_store": "temporary-directory",
            "retention_rule": "destroy-on-close",
            "source_confidence": "synthetic",
        },
        "approvals": {
            "two_person_approval": True,
            "legal_provider_approval": True,
            "security_lab_owner": "selftest",
            "whoathere_evaluation_owner": "selftest",
        },
    }


def manifest(corpus_path: Path, public_key: Path) -> dict[str, Any]:
    return {
        "schema": "whoathere.actual_malware.evaluation_manifest.v2",
        "evaluation_id": "synthetic-static-bridge",
        "evaluation_class": "known_regression",
        "created_at_utc": "2026-07-14T23:59:00Z",
        "corpus_sha256": digest(corpus_path.read_bytes()),
        "identities": {
            "runtime_sha256": "sha256:" + "1" * 64,
            "prompt_set_sha256": "sha256:" + "2" * 64,
            "observation_schema_sha256": "sha256:" + "3" * 64,
            "provider_adapter_sha256": "sha256:" + "4" * 64,
            "policy_sha256": "sha256:" + "5" * 64,
            "scorer_id": "whoathere-actual-malware-evaluation.py:score-results-v2",
        },
        "verified_evidence_registry": {
            "registry_id": "synthetic-static-registry",
            "verifier_id": "synthetic-static-verifier",
            "verifier_public_key_sha256": digest(public_key.read_bytes()),
            "verifier_executable_sha256": VERIFIER_EXECUTABLE_SHA256,
            "projection_schema_sha256": PROJECTION_SCHEMA_SHA256,
        },
        "evaluation_window": {
            "starts_at_utc": "2026-07-15T00:00:00Z",
            "ends_at_utc": "2026-07-15T01:00:00Z",
            "maximum_result_to_registry_seconds": 600,
        },
        "thresholds": {
            "malicious_behavior_detection_rate_min": 1.0,
            "benign_false_malicious_rate_max": 0.0,
            "benign_friction_rate_max": 0.0,
            "required_run_completion_rate_min": 1.0,
            "safety_pass_rate_min": 1.0,
        },
        "cohorts": [
            {
                "cohort_id": "synthetic-malicious",
                "expected_result": "malicious",
                "description": "synthetic static bridge regression",
            }
        ],
        "required_runs": [
            {
                "sample_id": sample_id,
                "profile_id": profile_id,
                "cohort_id": "synthetic-malicious",
                "family_id": "synthetic-static-family-" + digest_char,
                "campaign_id": "synthetic-static-campaign-" + digest_char,
                "artifact_sha256": "sha256:" + digest_char * 64,
                "execution_profile_sha256": EXECUTION_PROFILE_SHA256,
                "ecosystem": "pypi",
                "expected_result": "malicious",
                "required_behavior_labels": ["second_stage_fetch"],
                "required_modalities": ["deterministic"],
                "require_complete": True,
            }
            for sample_id, profile_id, digest_char in RUN_SPECS
        ],
    }


def static_projection(index: int, artifact_sha256: str, seed: int) -> dict[str, Any]:
    offset = index * 100
    digest_characters = "def0123456789abc"
    digest_character = digest_characters[(seed * 3 + index) % len(digest_characters)]
    source_character = digest_characters[(seed * 3 + index + 1) % len(digest_characters)]
    return {
        "kind": "static_download_execute_capability",
        "artifact_sha256": artifact_sha256,
        "artifact_manifest_sha256": "sha256:" + digest_character * 64,
        "exact_observation_sha256": "sha256:" + source_character * 64,
        "finding_evidence_sha256": "sha256:" + digest_characters[(seed + 4 + index) % 16] * 64,
        "file_id": "sha256:" + digest_characters[(seed + 6 + index) % 16] * 64,
        "file_sha256": "sha256:" + digest_characters[(seed + 8 + index) % 16] * 64,
        "range": {"kind": "bytes", "start_byte": 100 + offset, "end_byte": 180 + offset},
        "selected_bytes_sha256": "sha256:" + digest_characters[(seed + 10 + index) % 16] * 64,
        "source_receipt_sha256": "sha256:" + digest_characters[(seed + 12 + index) % 16] * 64,
    }


def bundle(
    manifest_value: dict[str, Any],
    manifest_sha256: str,
    sample_id: str,
    profile_id: str,
    artifact_sha256: str,
    run_index: int,
) -> dict[str, Any]:
    registry = manifest_value["verified_evidence_registry"]
    return {
        "schema": "whoathere.actual_malware.verified_projection_bundle.v1",
        "verified_at_utc": "2026-07-15T00:02:00Z",
        "verifier_id": registry["verifier_id"],
        "verifier_executable_sha256": registry["verifier_executable_sha256"],
        "projection_schema_sha256": registry["projection_schema_sha256"],
        "verifier_public_key_sha256": registry["verifier_public_key_sha256"],
        "verification_status": "verified",
        "run_fact": {
            "created_at_utc": "2026-07-15T00:01:00Z",
            "run_id": "run-" + sample_id,
            "evaluation_id": manifest_value["evaluation_id"],
            "evaluation_manifest_sha256": manifest_sha256,
            "corpus_sha256": manifest_value["corpus_sha256"],
            "sample_id": sample_id,
            "profile_id": profile_id,
            "artifact_sha256": artifact_sha256,
            "execution_profile_sha256": EXECUTION_PROFILE_SHA256,
            "verifier_executable_sha256": registry["verifier_executable_sha256"],
            "projection_schema_sha256": registry["projection_schema_sha256"],
            "ecosystem": "pypi",
            "identities": copy.deepcopy(manifest_value["identities"]),
            "completion_state": "complete",
            "completion_gap_codes": [],
            "coverage": [
                {
                    "modality": "deterministic",
                    "state": "complete",
                    "evidence_sha256": "sha256:" + "b" * 64,
                }
            ],
            "safety": {
                "network_policy": "sinkhole_only",
                "host_package_execution_applied": False,
                "sync_back_applied": False,
                "live_c2_contacted": False,
                "live_second_stage_fetched": False,
                "restricted_material_leak": False,
                "teardown_verified": True,
            },
        },
        "projections": [
            static_projection(0, artifact_sha256, run_index),
            static_projection(1, artifact_sha256, run_index),
        ],
        "claim_boundary": CLAIM_BOUNDARY,
    }


def publish(
    *,
    directory: Path,
    manifest_path: Path,
    manifest_sha256: str,
    bundle_path: Path,
    bundle_signature: Path,
    public_key: Path,
    sample_id: str,
    profile_id: str,
    output_name: str = "run-result.json",
) -> tuple[subprocess.CompletedProcess[str], Path]:
    output = directory / output_name
    process = subprocess.run(
        [
            "python3",
            "-B",
            str(PUBLISHER),
            "--evaluation-manifest",
            str(manifest_path),
            "--expected-evaluation-manifest-sha256",
            manifest_sha256,
            "--sample-id",
            sample_id,
            "--profile-id",
            profile_id,
            "--verified-projection-bundle",
            str(bundle_path),
            "--verified-projection-signature",
            str(bundle_signature),
            "--verifier-public-key",
            str(public_key),
            "--out",
            str(output),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return process, output


def bridge(
    *,
    directory: Path,
    manifest_path: Path,
    manifest_sha256: str,
    run_index_path: Path,
    public_key: Path,
    private_key: Path,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    registry = directory / "verified-evidence-registry.json"
    signature = directory / "verified-evidence-registry.sig"
    process = subprocess.run(
        [
            "python3",
            "-B",
            str(BRIDGE),
            "--evaluation-manifest",
            str(manifest_path),
            "--expected-evaluation-manifest-sha256",
            manifest_sha256,
            "--run-index",
            str(run_index_path),
            "--verifier-public-key",
            str(public_key),
            "--registry-signing-private-key",
            str(private_key),
            "--out-registry",
            str(registry),
            "--out-signature",
            str(signature),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return process, registry, signature


def score(
    *,
    corpus_path: Path,
    manifest_path: Path,
    run_results: list[Path],
    registry: Path,
    public_key: Path,
    registry_signature: Path,
    directory: Path,
) -> subprocess.CompletedProcess[str]:
    results_jsonl = directory / "run-results.jsonl"
    results_jsonl.write_text(
        "".join(
            json.dumps(json.loads(path.read_text(encoding="utf-8")), sort_keys=True) + "\n"
            for path in run_results
        ),
        encoding="utf-8",
    )
    return subprocess.run(
        [
            "python3",
            "-B",
            str(EVALUATOR),
            "score-results",
            "--corpus",
            str(corpus_path),
            "--results",
            str(results_jsonl),
            "--evaluation-manifest",
            str(manifest_path),
            "--verified-evidence-registry",
            str(registry),
            "--verified-evidence-public-key",
            str(public_key),
            "--verified-evidence-signature",
            str(registry_signature),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def case_directory(root: Path, name: str) -> Path:
    directory = root / name
    directory.mkdir()
    return directory


def write_run_index(
    path: Path,
    manifest_sha256: str,
    entries: list[dict[str, str]],
) -> Path:
    path.write_bytes(
        canonical(
            {
                "schema": "whoathere.actual_malware.signed_projection_run_index.v1",
                "evaluation_manifest_sha256": manifest_sha256,
                "runs": entries,
            }
        )
    )
    return path


def main() -> int:
    checks = 0
    with tempfile.TemporaryDirectory(prefix="whoathere-signed-projection-bridge-selftest-") as raw_tmp:
        root = Path(raw_tmp)
        private_key, public_key = key_pair(root)
        corpus_path = root / "corpus.jsonl"
        corpus_path.write_text(
            "".join(
                json.dumps(corpus_row(sample_id, digest_char), sort_keys=True) + "\n"
                for sample_id, _, digest_char in RUN_SPECS
            ),
            encoding="utf-8",
        )
        manifest_value = manifest(corpus_path, public_key)
        manifest_path = root / "evaluation-manifest.json"
        write_json(manifest_path, manifest_value)
        manifest_sha256 = digest(manifest_path.read_bytes())
        entries: list[dict[str, str]] = []
        run_results: list[Path] = []
        bundle_values: list[dict[str, Any]] = []
        bundle_paths: list[Path] = []
        bundle_signatures: list[Path] = []
        for run_index, (sample_id, profile_id, digest_char) in enumerate(RUN_SPECS):
            run_directory = case_directory(root, f"source-run-{run_index}")
            bundle_value = bundle(
                manifest_value,
                manifest_sha256,
                sample_id,
                profile_id,
                "sha256:" + digest_char * 64,
                run_index,
            )
            bundle_path = run_directory / "verified-projection-bundle.json"
            bundle_path.write_bytes(canonical(bundle_value))
            bundle_signature = run_directory / "verified-projection-bundle.sig"
            sign(private_key, bundle_path, bundle_signature)
            publisher_process, run_result = publish(
                directory=run_directory,
                manifest_path=manifest_path,
                manifest_sha256=manifest_sha256,
                bundle_path=bundle_path,
                bundle_signature=bundle_signature,
                public_key=public_key,
                sample_id=sample_id,
                profile_id=profile_id,
            )
            require(publisher_process.returncode == 0, publisher_process.stderr)
            bundle_values.append(bundle_value)
            bundle_paths.append(bundle_path)
            bundle_signatures.append(bundle_signature)
            run_results.append(run_result)
            entries.append(
                {
                    "sample_id": sample_id,
                    "profile_id": profile_id,
                    "verified_projection_bundle": str(bundle_path),
                    "verified_projection_signature": str(bundle_signature),
                    "run_result": str(run_result),
                }
            )
        checks += 1

        happy_dir = case_directory(root, "happy")
        happy_index = write_run_index(happy_dir / "run-index.json", manifest_sha256, entries)
        bridge_process, registry_path, registry_signature = bridge(
            directory=happy_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=happy_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(bridge_process.returncode == 0, bridge_process.stderr)
        checks += 1

        registry = json.loads(registry_path.read_text(encoding="utf-8"))
        results = [json.loads(path.read_text(encoding="utf-8")) for path in run_results]
        bundle_sha256_by_run = {
            (sample_id, profile_id): digest(bundle_paths[index].read_bytes())
            for index, (sample_id, profile_id, _) in enumerate(RUN_SPECS)
        }
        require(registry["schema"] == "whoathere.actual_malware.verified_evidence_registry.v1", str(registry))
        require(len(registry["run_fact_records"]) == 3, str(registry["run_fact_records"]))
        require(len(registry["records"]) == 6, str(registry["records"]))
        require(
            {
                (row["sample_id"], row["profile_id"], row["projection_sha256"])
                for row in registry["records"]
            }
            == {
                (result["sample_id"], result["profile_id"], observation["projection_sha256"])
                for result in results
                for observation in result["observations"]
            },
            "registry/result projection set drifted",
        )
        require(
            all(
                row["verification_receipt_sha256"]
                == bundle_sha256_by_run[(row["sample_id"], row["profile_id"])]
                for row in registry["records"]
            ),
            "evidence verification receipt is not the bundle digest",
        )
        require(
            all(
                row["verification_receipt_sha256"]
                == bundle_sha256_by_run[(row["sample_id"], row["profile_id"])]
                for row in registry["run_fact_records"]
            ),
            "run-fact verification receipt is not the bundle digest",
        )
        require(
            all(
                row["execution_profile_sha256"] == EXECUTION_PROFILE_SHA256
                and row["verifier_executable_sha256"] == VERIFIER_EXECUTABLE_SHA256
                and row["projection_schema_sha256"] == PROJECTION_SCHEMA_SHA256
                for row in registry["records"] + registry["run_fact_records"]
            ),
            "current identity pins were not projected",
        )
        checks += 1

        scorer_process = score(
            corpus_path=corpus_path,
            manifest_path=manifest_path,
            run_results=run_results,
            registry=registry_path,
            public_key=public_key,
            registry_signature=registry_signature,
            directory=happy_dir,
        )
        require(scorer_process.returncode == 0, scorer_process.stdout + scorer_process.stderr)
        score_report = json.loads(scorer_process.stdout)
        require(score_report["passed"] is True and score_report["validation_errors"] == [], str(score_report))
        require(score_report["rates"]["malicious_behavior_detection"] == 1.0, str(score_report))
        checks += 1

        tampered_bundle_dir = case_directory(root, "tampered-bundle")
        tampered_bundle_value = copy.deepcopy(bundle_values[0])
        tampered_bundle_value["projections"][0]["exact_observation_sha256"] = "sha256:" + "f" * 64
        tampered_bundle_path = tampered_bundle_dir / "bundle.json"
        tampered_bundle_path.write_bytes(canonical(tampered_bundle_value))
        tampered_entries = copy.deepcopy(entries)
        tampered_entries[0]["verified_projection_bundle"] = str(tampered_bundle_path)
        tampered_index = write_run_index(
            tampered_bundle_dir / "run-index.json", manifest_sha256, tampered_entries
        )
        tampered_process, _, _ = bridge(
            directory=tampered_bundle_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=tampered_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            tampered_process.returncode == 20 and "projection_signature_invalid" in tampered_process.stderr,
            tampered_process.stderr,
        )
        checks += 1

        result_drift_dir = case_directory(root, "result-drift")
        drifted_result = copy.deepcopy(results[0])
        drifted_result["admission"]["manual_review_required"] = False
        drifted_result_path = result_drift_dir / "run-result.json"
        drifted_result_path.write_bytes(pretty(drifted_result))
        drift_entries = copy.deepcopy(entries)
        drift_entries[0]["run_result"] = str(drifted_result_path)
        drift_index = write_run_index(
            result_drift_dir / "run-index.json", manifest_sha256, drift_entries
        )
        drift_process, _, _ = bridge(
            directory=result_drift_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=drift_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            drift_process.returncode == 20 and "run_result_publisher_recompute_mismatch" in drift_process.stderr,
            drift_process.stderr,
        )
        checks += 1

        pin_drift_dir = case_directory(root, "pin-drift")
        pin_drift_manifest = copy.deepcopy(manifest_value)
        pin_drift_manifest["verified_evidence_registry"]["projection_schema_sha256"] = "sha256:" + "9" * 64
        pin_drift_manifest_path = pin_drift_dir / "evaluation-manifest.json"
        write_json(pin_drift_manifest_path, pin_drift_manifest)
        pin_drift_manifest_sha256 = digest(pin_drift_manifest_path.read_bytes())
        pin_drift_index = write_run_index(
            pin_drift_dir / "run-index.json", pin_drift_manifest_sha256, entries
        )
        pin_process, _, _ = bridge(
            directory=pin_drift_dir,
            manifest_path=pin_drift_manifest_path,
            manifest_sha256=pin_drift_manifest_sha256,
            run_index_path=pin_drift_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            pin_process.returncode == 20 and "projection_schema_sha256_pin_mismatch" in pin_process.stderr,
            pin_process.stderr,
        )
        checks += 1

        typed_dir = case_directory(root, "typed-event-default-closed")
        typed_bundle = copy.deepcopy(bundle_values[0])
        typed_bundle["run_fact"]["coverage"].append(
            {"modality": "dynamic", "state": "complete", "evidence_sha256": "sha256:" + "c" * 64}
        )
        typed_bundle["projections"] = [
            {
                "kind": "typed_event",
                "event_id": "synthetic-env-read",
                "modality": "dynamic",
                "evidence_type": "environment_credential_read",
                "event_sha256": "sha256:" + "d" * 64,
                "source_receipt_sha256": "sha256:" + "e" * 64,
            }
        ]
        typed_bundle_path = typed_dir / "bundle.json"
        typed_bundle_path.write_bytes(canonical(typed_bundle))
        typed_bundle_signature = typed_dir / "bundle.sig"
        sign(private_key, typed_bundle_path, typed_bundle_signature)
        typed_publisher, typed_result = publish(
            directory=typed_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            bundle_path=typed_bundle_path,
            bundle_signature=typed_bundle_signature,
            public_key=public_key,
            sample_id=RUN_SPECS[0][0],
            profile_id=RUN_SPECS[0][1],
            output_name="typed-run-result.json",
        )
        require(typed_publisher.returncode == 0, typed_publisher.stderr)
        typed_bridge_dir = case_directory(typed_dir, "bridge")
        typed_entries = copy.deepcopy(entries)
        typed_entries[0]["verified_projection_bundle"] = str(typed_bundle_path)
        typed_entries[0]["verified_projection_signature"] = str(typed_bundle_signature)
        typed_entries[0]["run_result"] = str(typed_result)
        typed_index = write_run_index(
            typed_bridge_dir / "run-index.json", manifest_sha256, typed_entries
        )
        typed_process, _, _ = bridge(
            directory=typed_bridge_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=typed_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            typed_process.returncode == 20 and "static_projection_kind_required" in typed_process.stderr,
            typed_process.stderr,
        )
        checks += 1

        wrong_key_dir = case_directory(root, "wrong-registry-key")
        wrong_private, _ = key_pair(wrong_key_dir, "wrong")
        wrong_key_process, _, _ = bridge(
            directory=wrong_key_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=happy_index,
            public_key=public_key,
            private_key=wrong_private,
        )
        require(
            wrong_key_process.returncode == 20 and "registry_signing_key_mismatch" in wrong_key_process.stderr,
            wrong_key_process.stderr,
        )
        checks += 1

        tampered_registry_dir = case_directory(root, "tampered-registry")
        tampered_registry = copy.deepcopy(registry)
        tampered_registry["records"][0]["evidence_sha256"] = "sha256:" + "0" * 64
        tampered_registry_path = tampered_registry_dir / "registry.json"
        tampered_registry_path.write_bytes(pretty(tampered_registry))
        copied_signature = tampered_registry_dir / "registry.sig"
        copied_signature.write_bytes(registry_signature.read_bytes())
        tampered_score = score(
            corpus_path=corpus_path,
            manifest_path=manifest_path,
            run_results=run_results,
            registry=tampered_registry_path,
            public_key=public_key,
            registry_signature=copied_signature,
            directory=tampered_registry_dir,
        )
        require(tampered_score.returncode == 20, tampered_score.stdout + tampered_score.stderr)
        tampered_report = json.loads(tampered_score.stdout)
        require(
            "verified_evidence_registry_signature_invalid" in tampered_report["validation_errors"],
            str(tampered_report["validation_errors"]),
        )
        checks += 1

        missing_dir = case_directory(root, "missing-run")
        missing_index = write_run_index(
            missing_dir / "run-index.json", manifest_sha256, entries[:-1]
        )
        missing_process, _, _ = bridge(
            directory=missing_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=missing_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            missing_process.returncode == 20 and "run_index_missing_manifest_run" in missing_process.stderr,
            missing_process.stderr,
        )
        checks += 1

        duplicate_dir = case_directory(root, "duplicate-run")
        duplicate_index = write_run_index(
            duplicate_dir / "run-index.json", manifest_sha256, entries + [copy.deepcopy(entries[0])]
        )
        duplicate_process, _, _ = bridge(
            directory=duplicate_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=duplicate_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            duplicate_process.returncode == 20 and "run_index_duplicate_run" in duplicate_process.stderr,
            duplicate_process.stderr,
        )
        checks += 1

        unknown_dir = case_directory(root, "unknown-run")
        unknown_entry = copy.deepcopy(entries[0])
        unknown_entry["sample_id"] = "synthetic-unknown-wheel"
        unknown_index = write_run_index(
            unknown_dir / "run-index.json", manifest_sha256, entries + [unknown_entry]
        )
        unknown_process, _, _ = bridge(
            directory=unknown_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index_path=unknown_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            unknown_process.returncode == 20 and "run_index_unknown_run" in unknown_process.stderr,
            unknown_process.stderr,
        )
        checks += 1

    print(f"signed projection registry bridge self-test passed ({checks} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
