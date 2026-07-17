#!/usr/bin/env python3
"""Hermetic adversarial tests for the signed-projection RunResultV2 publisher."""

from __future__ import annotations

import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "scripts" / "whoathere-run-result-v2-publisher.py"
CLAIM_BOUNDARY = (
    "Independent evidence projections only; no verdict, observed-clean, release, or admission authority."
)
PROFILE_SHA256 = "sha256:" + "8" * 64
ARTIFACT_SHA256 = "sha256:" + "a" * 64
VERIFIER_EXECUTABLE_SHA256 = "sha256:" + "7" * 64
PROJECTION_SCHEMA_SHA256 = "sha256:" + "9" * 64


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def key_pair(root: Path) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl is required")
    private = root / "verifier-private.pem"
    public = root / "verifier-public.pem"
    subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True)
    subprocess.run([openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True)
    return private, public


def manifest(public_key: Path) -> dict[str, Any]:
    identities = {
        "runtime_sha256": "sha256:" + "1" * 64,
        "prompt_set_sha256": "sha256:" + "2" * 64,
        "observation_schema_sha256": "sha256:" + "3" * 64,
        "provider_adapter_sha256": "sha256:" + "4" * 64,
        "policy_sha256": "sha256:" + "5" * 64,
        "scorer_id": "whoathere-actual-malware-evaluation.py:score-results-v2",
    }
    return {
        "schema": "whoathere.actual_malware.evaluation_manifest.v2",
        "evaluation_id": "four-miss-fixture",
        "evaluation_class": "known_regression",
        "created_at_utc": "2026-07-14T23:59:00Z",
        "corpus_sha256": "sha256:" + "6" * 64,
        "identities": identities,
        "verified_evidence_registry": {
            "registry_id": "fixture-registry",
            "verifier_id": "fixture-independent-verifier",
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
                "cohort_id": "four-misses",
                "expected_result": "malicious",
                "description": "synthetic known-miss publisher fixture",
            }
        ],
        "required_runs": [
            {
                "sample_id": "mb-telnyx-fixture-wheel",
                "profile_id": "wheel-trigger-matrix-v1",
                "cohort_id": "four-misses",
                "family_id": "telnyx-fixture",
                "campaign_id": "fixture-campaign",
                "artifact_sha256": ARTIFACT_SHA256,
                "execution_profile_sha256": PROFILE_SHA256,
                "ecosystem": "pypi",
                "expected_result": "malicious",
                "required_behavior_labels": ["second_stage_fetch"],
                "required_modalities": ["deterministic", "dynamic"],
                "require_complete": True,
            }
        ],
    }


def projection_bundle(manifest_value: dict[str, Any], manifest_sha256: str) -> dict[str, Any]:
    return {
        "schema": "whoathere.actual_malware.verified_projection_bundle.v1",
        "verified_at_utc": "2026-07-15T00:02:00Z",
        "verifier_id": "fixture-independent-verifier",
        "verifier_executable_sha256": VERIFIER_EXECUTABLE_SHA256,
        "projection_schema_sha256": PROJECTION_SCHEMA_SHA256,
        "verifier_public_key_sha256": manifest_value["verified_evidence_registry"][
            "verifier_public_key_sha256"
        ],
        "verification_status": "verified",
        "run_fact": {
            "created_at_utc": "2026-07-15T00:01:00Z",
            "run_id": "run-telnyx-fixture",
            "evaluation_id": manifest_value["evaluation_id"],
            "evaluation_manifest_sha256": manifest_sha256,
            "corpus_sha256": manifest_value["corpus_sha256"],
            "sample_id": "mb-telnyx-fixture-wheel",
            "profile_id": "wheel-trigger-matrix-v1",
            "artifact_sha256": ARTIFACT_SHA256,
            "execution_profile_sha256": PROFILE_SHA256,
            "verifier_executable_sha256": VERIFIER_EXECUTABLE_SHA256,
            "projection_schema_sha256": PROJECTION_SCHEMA_SHA256,
            "ecosystem": "pypi",
            "identities": copy.deepcopy(manifest_value["identities"]),
            "completion_state": "incomplete",
            "completion_gap_codes": ["dynamic_coverage_incomplete"],
            "coverage": [
                {
                    "modality": "deterministic",
                    "state": "complete",
                    "evidence_sha256": "sha256:" + "b" * 64,
                },
                {
                    "modality": "dynamic",
                    "state": "incomplete",
                    "evidence_sha256": "sha256:" + "c" * 64,
                },
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
            {
                "kind": "static_download_execute_capability",
                "artifact_sha256": ARTIFACT_SHA256,
                "artifact_manifest_sha256": "sha256:" + "d" * 64,
                "exact_observation_sha256": "sha256:" + "e" * 64,
                "finding_evidence_sha256": "sha256:" + "f" * 64,
                "file_id": "sha256:" + "0" * 64,
                "file_sha256": "sha256:" + "1" * 64,
                "range": {"kind": "bytes", "start_byte": 100, "end_byte": 240},
                "selected_bytes_sha256": "sha256:" + "2" * 64,
                "source_receipt_sha256": "sha256:" + "3" * 64,
            },
            {
                "kind": "typed_event",
                "event_id": "event-env-read-1",
                "modality": "dynamic",
                "evidence_type": "environment_credential_read",
                "event_sha256": "sha256:" + "4" * 64,
                "source_receipt_sha256": "sha256:" + "5" * 64,
            },
        ],
        "claim_boundary": CLAIM_BOUNDARY,
    }


def sign(private: Path, bundle_path: Path, signature_path: Path) -> None:
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
            str(bundle_path),
            "-out",
            str(signature_path),
        ],
        check=True,
    )


def run_case(
    root: Path,
    name: str,
    manifest_path: Path,
    manifest_sha256: str,
    private: Path,
    base_bundle: dict[str, Any],
    public: Path,
    mutate: Callable[[dict[str, Any]], None] | None = None,
    forge_signature: bool = False,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    directory = root / name
    directory.mkdir()
    bundle = copy.deepcopy(base_bundle)
    if mutate is not None:
        mutate(bundle)
    bundle_path = directory / "bundle.json"
    signature_path = directory / "bundle.sig"
    output_path = directory / "run-result.json"
    bundle_path.write_bytes(canonical(bundle))
    sign(private, bundle_path, signature_path)
    if forge_signature:
        raw = bytearray(signature_path.read_bytes())
        raw[0] ^= 0x01
        signature_path.write_bytes(bytes(raw))
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
            "mb-telnyx-fixture-wheel",
            "--profile-id",
            "wheel-trigger-matrix-v1",
            "--verified-projection-bundle",
            str(bundle_path),
            "--verified-projection-signature",
            str(signature_path),
            "--verifier-public-key",
            str(public),
            "--out",
            str(output_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return process, output_path


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whoathere-run-result-publisher-selftest-") as raw_tmp:
        root = Path(raw_tmp)
        private, public = key_pair(root)
        manifest_value = manifest(public)
        manifest_path = root / "evaluation-manifest.json"
        write_json(manifest_path, manifest_value)
        manifest_sha256 = digest(manifest_path.read_bytes())
        base_bundle = projection_bundle(manifest_value, manifest_sha256)

        happy, happy_out = run_case(
            root, "happy", manifest_path, manifest_sha256, private, base_bundle, public
        )
        require(happy.returncode == 0, happy.stderr)
        result = json.loads(happy_out.read_text(encoding="utf-8"))
        require(result["schema"] == "whoathere.actual_malware.run_result.v2", str(result))
        require(result["execution_profile_sha256"] == PROFILE_SHA256, str(result))
        require(result["verifier_executable_sha256"] == VERIFIER_EXECUTABLE_SHA256, str(result))
        require(result["projection_schema_sha256"] == PROJECTION_SCHEMA_SHA256, str(result))
        require(result["completion_state"] == "incomplete", str(result))
        require(result["completion_reason_codes"] == ["dynamic_coverage_incomplete"], str(result))
        require(
            result["admission"]
            == {"artifact_release_applied": False, "manual_review_required": True},
            str(result),
        )
        by_type = {row["evidence_type"]: row for row in result["observations"]}
        require(by_type["download_execute_capability"]["behavior_label"] == "second_stage_fetch", str(result))
        require(by_type["environment_credential_read"]["behavior_label"] == "credential_env_access", str(result))
        require(
            by_type["download_execute_capability"]["projection_sha256"]
            == digest(canonical(base_bundle["projections"][0])),
            str(result),
        )
        require(
            by_type["environment_credential_read"]["projection_sha256"]
            == digest(canonical(base_bundle["projections"][1])),
            str(result),
        )
        for observation in result["observations"]:
            require(
                observation["observation_id"]
                == "observation-" + observation["projection_sha256"].removeprefix("sha256:"),
                str(observation),
            )

        loose, _ = run_case(
            root,
            "loose-reason",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value.__setitem__("reason_codes", ["known_bad_package"]),
        )
        require(loose.returncode == 20 and "verified_projection_bundle_keys_invalid" in loose.stderr, loose.stderr)

        unverified, _ = run_case(
            root,
            "unverified",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value.__setitem__("verification_status", "producer_claimed"),
        )
        require(
            unverified.returncode == 20 and "projection_verification_status_invalid" in unverified.stderr,
            unverified.stderr,
        )

        label_injection, _ = run_case(
            root,
            "label-injection",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value["projections"][1].__setitem__("behavior_label", "https_exfil"),
        )
        require(
            label_injection.returncode == 20 and "typed_event_projection_keys_invalid" in label_injection.stderr,
            label_injection.stderr,
        )

        unmapped, _ = run_case(
            root,
            "unmapped",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value["projections"][1].__setitem__("evidence_type", "package_name_known_bad"),
        )
        require(
            unmapped.returncode == 20 and "typed_event_evidence_type_unmapped" in unmapped.stderr,
            unmapped.stderr,
        )

        profile_mismatch, _ = run_case(
            root,
            "profile-mismatch",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value["run_fact"].__setitem__(
                "execution_profile_sha256", "sha256:" + "9" * 64
            ),
        )
        require(
            profile_mismatch.returncode == 20
            and "verified_run_fact_execution_profile_sha256_mismatch" in profile_mismatch.stderr,
            profile_mismatch.stderr,
        )

        invalid_citation, _ = run_case(
            root,
            "invalid-static-citation",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value["projections"][0].__setitem__(
                "range", {"kind": "bytes", "start_byte": 240, "end_byte": 100}
            ),
        )
        require(
            invalid_citation.returncode == 20 and "static_citation_range_invalid" in invalid_citation.stderr,
            invalid_citation.stderr,
        )

        for evidence_type in (
            "environment_credential_read",
            "ci_gate_activation",
            "https_exfiltration_attempt",
            "second_stage_fetch_attempt",
        ):
            runtime_static, _ = run_case(
                root,
                f"runtime-static-{evidence_type}",
                manifest_path,
                manifest_sha256,
                private,
                base_bundle,
                public,
                lambda value, evidence_type=evidence_type: value["projections"][1].update(
                    {"modality": "deterministic", "evidence_type": evidence_type}
                ),
            )
            require(
                runtime_static.returncode == 20
                and "typed_event_modality_invalid" in runtime_static.stderr,
                runtime_static.stderr,
            )

        duplicate_source_event, _ = run_case(
            root,
            "duplicate-source-event-relabeled",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value["projections"].append(
                {
                    **copy.deepcopy(value["projections"][1]),
                    "evidence_type": "ci_gate_activation",
                }
            ),
        )
        require(
            duplicate_source_event.returncode == 20
            and "typed_event_source_identity_duplicate" in duplicate_source_event.stderr,
            duplicate_source_event.stderr,
        )

        conflicting_source_event, _ = run_case(
            root,
            "duplicate-source-event-conflicting-digest",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value["projections"].append(
                {
                    **copy.deepcopy(value["projections"][1]),
                    "event_sha256": "sha256:" + "6" * 64,
                }
            ),
        )
        require(
            conflicting_source_event.returncode == 20
            and "typed_event_source_identity_duplicate" in conflicting_source_event.stderr,
            conflicting_source_event.stderr,
        )

        verifier_substitution, _ = run_case(
            root,
            "verifier-executable-substitution",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value.__setitem__("verifier_executable_sha256", "sha256:" + "0" * 64),
        )
        require(
            verifier_substitution.returncode == 20
            and "projection_verifier_executable_digest_mismatch" in verifier_substitution.stderr,
            verifier_substitution.stderr,
        )

        schema_substitution, _ = run_case(
            root,
            "projection-schema-substitution",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            lambda value: value.__setitem__("projection_schema_sha256", "sha256:" + "0" * 64),
        )
        require(
            schema_substitution.returncode == 20
            and "projection_schema_digest_mismatch" in schema_substitution.stderr,
            schema_substitution.stderr,
        )

        forged, _ = run_case(
            root,
            "forged-signature",
            manifest_path,
            manifest_sha256,
            private,
            base_bundle,
            public,
            forge_signature=True,
        )
        require(forged.returncode == 20 and "projection_signature_invalid" in forged.stderr, forged.stderr)

        print(
            json.dumps(
                {
                    "schema": "whoathere.run_result_v2_publisher_selftest.v1",
                    "valid": True,
                    "tests": [
                        "signed_projection_publishes_manual_review_only",
                        "incomplete_run_fact_is_preserved",
                        "static_download_execute_maps_narrowly",
                        "observation_id_binds_canonical_projection_digest",
                        "behavior_labels_are_derived",
                        "loose_reason_fields_rejected",
                        "unverified_bundle_rejected",
                        "producer_behavior_label_rejected",
                        "unmapped_evidence_type_rejected",
                        "execution_profile_digest_mismatch_rejected",
                        "invalid_static_citation_rejected",
                        "runtime_evidence_is_dynamic_only",
                        "duplicate_source_event_relabel_rejected",
                        "duplicate_source_event_conflicting_digest_rejected",
                        "verifier_executable_substitution_rejected",
                        "projection_schema_substitution_rejected",
                        "forged_signature_rejected",
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
