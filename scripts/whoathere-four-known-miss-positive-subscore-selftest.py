#!/usr/bin/env python3
"""Hermetic end-to-end proof for the R02 four-known-miss positive subscore.

The test uses synthetic JSON metadata and ephemeral Ed25519 keys. It contains no package bytes,
does not access a network or lab host, and does not execute package, VM, or AI code.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = (
    ROOT
    / "docs"
    / "product-build-run"
    / "four-known-miss-positive-subscore-contract.v2.json"
)
COMPLETE_PROFILE = (
    ROOT / "docs" / "product-build-run" / "four-known-miss-campaign-profile.v1.json"
)
COMPILER = ROOT / "scripts" / "whoathere-compile-four-known-miss-positive-subscore.py"
PUBLISHER = ROOT / "scripts" / "whoathere-run-result-v2-publisher.py"
BRIDGE = ROOT / "scripts" / "whoathere-signed-projection-registry-bridge.py"
SUBSCORE = ROOT / "scripts" / "whoathere-score-four-known-miss-positive-subscore.py"
BRIDGE_SELFTEST = ROOT / "scripts" / "whoathere-signed-projection-registry-bridge-selftest.py"

SCORER_ID = "whoathere-actual-malware-evaluation.py:score-results-v2"
VERIFIER_EXECUTABLE_SHA256 = "sha256:" + "6" * 64
PROJECTION_SCHEMA_SHA256 = "sha256:" + "7" * 64
CLAIM_BOUNDARY = (
    "Independent evidence projections only; no verdict, observed-clean, release, or admission authority."
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"{name} unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def pretty(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def corpus_row(contract_row: dict[str, Any]) -> dict[str, Any]:
    sample_id = str(contract_row["sample_id"])
    artifact_form = str(contract_row["artifact_form"])
    if artifact_form == "npm_tgz":
        filename = sample_id + ".tgz"
        trigger = "npm_lifecycle"
    elif artifact_form == "wheel":
        filename = sample_id + ".whl"
        trigger = "python_import"
    else:
        filename = sample_id + ".tar.gz"
        trigger = "pypi_pep517"
    return {
        "schema_version": "whoathere.actual_malware.corpus.v1",
        "sample_id": sample_id,
        "sample_kind": "malware",
        "ecosystem": contract_row["ecosystem"],
        "package_name": "synthetic-" + sample_id,
        "package_version": "0.0.0-r02",
        "artifact_filename": filename,
        "artifact_sha256": contract_row["artifact_sha256"],
        "artifact_size_bytes": 64,
        "source_type": "lab_benign_fixture",
        "source_reference": "synthetic:r02-positive-subscore",
        "disclosure_date": "2026-07-01",
        "expected_result": "malicious",
        "trigger_phases": [trigger],
        "behavior_labels": list(contract_row["required_behavior_labels"]),
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "acquisition": {
            "case_id": "synthetic-r02-positive-subscore",
            "allowed_test_purpose": "hermetic R02 metadata proof",
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


def compile_manifest(
    *, directory: Path, corpus: Path, public_key: Path
) -> tuple[subprocess.CompletedProcess[str], Path]:
    output = directory / "evaluation-manifest.json"
    process = subprocess.run(
        [
            str(COMPILER),
            "--complete-run-profile",
            str(COMPLETE_PROFILE),
            "--corpus",
            str(corpus),
            "--output",
            str(output),
            "--evaluation-id",
            "synthetic-r02-four-positive",
            "--created-at-utc",
            "2026-07-14T23:59:00Z",
            "--starts-at-utc",
            "2026-07-15T00:00:00Z",
            "--ends-at-utc",
            "2026-07-15T01:00:00Z",
            "--maximum-result-to-registry-seconds",
            "600",
            "--runtime-sha256",
            "sha256:" + "1" * 64,
            "--prompt-set-sha256",
            "sha256:" + "2" * 64,
            "--observation-schema-sha256",
            "sha256:" + "3" * 64,
            "--provider-adapter-sha256",
            "sha256:" + "4" * 64,
            "--policy-sha256",
            "sha256:" + "5" * 64,
            "--scorer-id",
            SCORER_ID,
            "--registry-id",
            "synthetic-r02-registry",
            "--verifier-id",
            "synthetic-r02-independent-verifier",
            "--verifier-public-key-sha256",
            sha256_bytes(public_key.read_bytes()),
            "--verifier-executable-sha256",
            VERIFIER_EXECUTABLE_SHA256,
            "--projection-schema-sha256",
            PROJECTION_SCHEMA_SHA256,
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return process, output


def typed_projection(
    *, event_id: str, evidence_type: str, seed: str
) -> dict[str, Any]:
    return {
        "kind": "typed_event",
        "event_id": event_id,
        "modality": "dynamic",
        "evidence_type": evidence_type,
        "event_sha256": "sha256:" + seed * 64,
        "source_receipt_sha256": "sha256:" + ("f" if seed != "f" else "e") * 64,
    }


def static_projection(
    artifact_sha256: str,
    seed: int,
    *,
    kind: str = "static_download_execute_capability",
) -> dict[str, Any]:
    characters = "89abcdef01234567"
    return {
        "kind": kind,
        "artifact_sha256": artifact_sha256,
        "artifact_manifest_sha256": "sha256:" + characters[seed % 16] * 64,
        "exact_observation_sha256": "sha256:" + characters[(seed + 1) % 16] * 64,
        "finding_evidence_sha256": "sha256:" + characters[(seed + 2) % 16] * 64,
        "file_id": "sha256:" + characters[(seed + 3) % 16] * 64,
        "file_sha256": "sha256:" + characters[(seed + 4) % 16] * 64,
        "range": {"kind": "bytes", "start_byte": 100 + seed, "end_byte": 180 + seed},
        "selected_bytes_sha256": "sha256:" + characters[(seed + 5) % 16] * 64,
        "source_receipt_sha256": "sha256:" + characters[(seed + 6) % 16] * 64,
    }


def bundle(
    *, manifest: dict[str, Any], manifest_sha256: str, slot: dict[str, Any], index: int
) -> dict[str, Any]:
    modality = slot["required_modalities"][0]
    static_kind = (
        "static_sensitive_file_exfiltration_capability"
        if slot["profile_id"] == "npm-exact-archive-static-capability-positive-v1"
        else "static_download_execute_capability"
    )
    projections = [
        static_projection(
            str(slot["artifact_sha256"]),
            index + 1,
            kind=static_kind,
        )
    ]
    registry = manifest["verified_evidence_registry"]
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
            "run_id": "synthetic-run-" + str(index),
            "evaluation_id": manifest["evaluation_id"],
            "evaluation_manifest_sha256": manifest_sha256,
            "corpus_sha256": manifest["corpus_sha256"],
            "sample_id": slot["sample_id"],
            "profile_id": slot["profile_id"],
            "artifact_sha256": slot["artifact_sha256"],
            "execution_profile_sha256": slot["execution_profile_sha256"],
            "verifier_executable_sha256": registry["verifier_executable_sha256"],
            "projection_schema_sha256": registry["projection_schema_sha256"],
            "ecosystem": slot["ecosystem"],
            "identities": copy.deepcopy(manifest["identities"]),
            "completion_state": "incomplete",
            "completion_gap_codes": ["independent_verifier_coverage_incomplete"],
            "coverage": [
                {
                    "modality": modality,
                    "state": "incomplete",
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
        "projections": projections,
        "claim_boundary": CLAIM_BOUNDARY,
    }


def publish_bundle(
    *, helper: ModuleType, directory: Path, manifest_path: Path, manifest_sha256: str,
    public_key: Path, private_key: Path, bundle_value: dict[str, Any], slot: dict[str, Any],
) -> tuple[Path, Path, Path]:
    bundle_path = directory / "verified-projection-bundle.json"
    bundle_path.write_bytes(canonical(bundle_value))
    signature = directory / "verified-projection-bundle.sig"
    helper.sign(private_key, bundle_path, signature)
    process, result = helper.publish(
        directory=directory,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        bundle_path=bundle_path,
        bundle_signature=signature,
        public_key=public_key,
        sample_id=slot["sample_id"],
        profile_id=slot["profile_id"],
    )
    require(process.returncode == 0, process.stderr)
    return bundle_path, signature, result


def write_results(path: Path, results: list[Path]) -> None:
    path.write_text(
        "".join(
            json.dumps(json.loads(result.read_text(encoding="utf-8")), sort_keys=True) + "\n"
            for result in results
        ),
        encoding="utf-8",
    )


def run_subscore(
    *, corpus: Path, results: Path, manifest: Path, registry: Path,
    public_key: Path, signature: Path,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(SUBSCORE),
            "--complete-run-profile",
            str(COMPLETE_PROFILE),
            "--corpus",
            str(corpus),
            "--results",
            str(results),
            "--evaluation-manifest",
            str(manifest),
            "--verified-evidence-registry",
            str(registry),
            "--verified-evidence-public-key",
            str(public_key),
            "--verified-evidence-signature",
            str(signature),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def bridge_campaign(
    *, helper: ModuleType, directory: Path, manifest_path: Path, manifest_sha256: str,
    entries: list[dict[str, str]], public_key: Path, private_key: Path,
) -> tuple[subprocess.CompletedProcess[str], Path, Path]:
    run_index = helper.write_run_index(directory / "run-index.json", manifest_sha256, entries)
    return helper.bridge(
        directory=directory,
        manifest_path=manifest_path,
        manifest_sha256=manifest_sha256,
        run_index_path=run_index,
        public_key=public_key,
        private_key=private_key,
    )


def main() -> int:
    checks: list[str] = []
    helper = load_module("whoathere_bridge_selftest_helpers", BRIDGE_SELFTEST)
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix="whoathere-r02-positive-subscore-") as raw_tmp:
        root = Path(raw_tmp)
        private_key, public_key = helper.key_pair(root)
        corpus = root / "corpus.jsonl"
        corpus.write_text(
            "".join(json.dumps(corpus_row(row), sort_keys=True) + "\n" for row in contract["rows"]),
            encoding="utf-8",
        )
        compile_process, manifest_path = compile_manifest(
            directory=root,
            corpus=corpus,
            public_key=public_key,
        )
        require(compile_process.returncode == 0, compile_process.stderr)
        compile_report = json.loads(compile_process.stdout)
        require(compile_report["required_run_count"] == 4, str(compile_report))
        require(
            compile_report["contract_sha256"]
            == "sha256:3269f8525e60012c075c951664083e559583a849f476d035922000d653da8359",
            str(compile_report),
        )
        checks.append("exact_contract_compiles")

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest_sha256 = sha256_bytes(manifest_path.read_bytes())
        bundle_values: list[dict[str, Any]] = []
        bundle_paths: list[Path] = []
        bundle_signatures: list[Path] = []
        run_results: list[Path] = []
        entries: list[dict[str, str]] = []
        for index, slot in enumerate(manifest["required_runs"]):
            directory = root / f"run-{index}"
            directory.mkdir()
            bundle_value = bundle(
                manifest=manifest,
                manifest_sha256=manifest_sha256,
                slot=slot,
                index=index,
            )
            bundle_path, bundle_signature, run_result = publish_bundle(
                helper=helper,
                directory=directory,
                manifest_path=manifest_path,
                manifest_sha256=manifest_sha256,
                public_key=public_key,
                private_key=private_key,
                bundle_value=bundle_value,
                slot=slot,
            )
            bundle_values.append(bundle_value)
            bundle_paths.append(bundle_path)
            bundle_signatures.append(bundle_signature)
            run_results.append(run_result)
            entries.append(
                {
                    "sample_id": slot["sample_id"],
                    "profile_id": slot["profile_id"],
                    "verified_projection_bundle": str(bundle_path),
                    "verified_projection_signature": str(bundle_signature),
                    "run_result": str(run_result),
                }
            )
        checks.append("four_signed_incomplete_results_publish")

        happy = root / "happy"
        happy.mkdir()
        bridge_process, registry, registry_signature = bridge_campaign(
            helper=helper,
            directory=happy,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(bridge_process.returncode == 0, bridge_process.stderr)
        results = happy / "results.jsonl"
        write_results(results, run_results)
        score_process = run_subscore(
            corpus=corpus,
            results=results,
            manifest=manifest_path,
            registry=registry,
            public_key=public_key,
            signature=registry_signature,
        )
        require(score_process.returncode == 0, score_process.stderr)
        report = json.loads(score_process.stdout)
        require(report["detection_subscore"] == {
            "behavior_positive_count": 4,
            "required_count": 4,
            "denominator": 4,
            "rate": 1.0,
            "passed": True,
        }, str(report["detection_subscore"]))
        require(report["safety"]["pass_count"] == 4 and report["safety"]["passed"] is True, str(report["safety"]))
        require(
            report["completion_quality"]["complete_count"] == 0
            and report["completion_quality"]["rate"] == 0.0
            and report["completion_quality"]["passed"] is False,
            str(report["completion_quality"]),
        )
        require(report["overall_passed"] is False, str(report))
        require(
            report["authority"] == {
                "observed_clean_eligible_count": 0,
                "artifact_release_applied_count": 0,
                "manual_review_required_count": 4,
                "sync_back_applied_count": 0,
                "observed_clean_authorized": False,
                "admission_authorized": False,
                "release_authorized": False,
                "sync_back_authorized": False,
            },
            str(report["authority"]),
        )
        require(report["underlying_v2_report"]["passed"] is False, str(report))
        checks.append("happy_path_is_4_of_4_safe_incomplete_and_overall_false")

        omission = root / "omission"
        omission.mkdir()
        omitted, _, _ = bridge_campaign(
            helper=helper,
            directory=omission,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=entries[:-1],
            public_key=public_key,
            private_key=private_key,
        )
        require(omitted.returncode == 20 and "run_index_missing_manifest_run" in omitted.stderr, omitted.stderr)
        checks.append("row_omission_fails")

        duplication = root / "duplication"
        duplication.mkdir()
        duplicated, _, _ = bridge_campaign(
            helper=helper,
            directory=duplication,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=entries + [copy.deepcopy(entries[0])],
            public_key=public_key,
            private_key=private_key,
        )
        require(duplicated.returncode == 20 and "run_index_duplicate_run" in duplicated.stderr, duplicated.stderr)
        checks.append("row_duplication_fails")

        profile = root / "profile-substitution"
        profile.mkdir()
        profile_entries = copy.deepcopy(entries)
        profile_entries[0]["profile_id"] = "substituted-positive-profile"
        profile_process, _, _ = bridge_campaign(
            helper=helper,
            directory=profile,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=profile_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            profile_process.returncode == 20
            and "run_index_missing_manifest_run" in profile_process.stderr,
            profile_process.stderr,
        )
        checks.append("profile_substitution_fails")

        signature_case = root / "bundle-signature-tamper"
        signature_case.mkdir()
        tampered_bundle = signature_case / "bundle.json"
        tampered_bundle_value = copy.deepcopy(bundle_values[0])
        tampered_bundle_value["run_fact"]["run_id"] = "synthetic-signature-tamper"
        tampered_bundle.write_bytes(canonical(tampered_bundle_value))
        signature_entries = copy.deepcopy(entries)
        signature_entries[0]["verified_projection_bundle"] = str(tampered_bundle)
        signature_process, _, _ = bridge_campaign(
            helper=helper,
            directory=signature_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=signature_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            signature_process.returncode == 20
            and "projection_signature_invalid" in signature_process.stderr,
            signature_process.stderr,
        )
        checks.append("bundle_signature_tamper_fails")

        projection_case = root / "projection-change"
        projection_case.mkdir()
        changed_projection_bundle = copy.deepcopy(bundle_values[0])
        changed_projection_bundle["projections"][0]["selected_bytes_sha256"] = (
            "sha256:" + "c" * 64
        )
        changed_path = projection_case / "bundle.json"
        changed_path.write_bytes(canonical(changed_projection_bundle))
        changed_signature = projection_case / "bundle.sig"
        helper.sign(private_key, changed_path, changed_signature)
        projection_entries = copy.deepcopy(entries)
        projection_entries[0]["verified_projection_bundle"] = str(changed_path)
        projection_entries[0]["verified_projection_signature"] = str(changed_signature)
        projection_process, _, _ = bridge_campaign(
            helper=helper,
            directory=projection_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=projection_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            projection_process.returncode == 20
            and "run_result_publisher_recompute_mismatch" in projection_process.stderr,
            projection_process.stderr,
        )
        checks.append("signed_projection_change_with_stale_result_fails")

        identity_case = root / "identity-change"
        identity_case.mkdir()
        changed_identity_bundle = copy.deepcopy(bundle_values[0])
        changed_identity_bundle["verifier_executable_sha256"] = "sha256:" + "9" * 64
        identity_path = identity_case / "bundle.json"
        identity_path.write_bytes(canonical(changed_identity_bundle))
        identity_signature = identity_case / "bundle.sig"
        helper.sign(private_key, identity_path, identity_signature)
        identity_entries = copy.deepcopy(entries)
        identity_entries[0]["verified_projection_bundle"] = str(identity_path)
        identity_entries[0]["verified_projection_signature"] = str(identity_signature)
        identity_process, _, _ = bridge_campaign(
            helper=helper,
            directory=identity_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=identity_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(identity_process.returncode == 20 and "verifier_executable_sha256_pin_mismatch" in identity_process.stderr, identity_process.stderr)
        checks.append("verifier_identity_change_fails")

        artifact_case = root / "artifact-substitution"
        artifact_case.mkdir()
        changed_artifact_bundle = copy.deepcopy(bundle_values[0])
        changed_artifact_bundle["run_fact"]["artifact_sha256"] = manifest["required_runs"][1]["artifact_sha256"]
        artifact_path = artifact_case / "bundle.json"
        artifact_path.write_bytes(canonical(changed_artifact_bundle))
        artifact_signature = artifact_case / "bundle.sig"
        helper.sign(private_key, artifact_path, artifact_signature)
        artifact_entries = copy.deepcopy(entries)
        artifact_entries[0]["verified_projection_bundle"] = str(artifact_path)
        artifact_entries[0]["verified_projection_signature"] = str(artifact_signature)
        artifact_process, _, _ = bridge_campaign(
            helper=helper,
            directory=artifact_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=artifact_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(artifact_process.returncode == 20 and "verified_run_fact_artifact_sha256_mismatch" in artifact_process.stderr, artifact_process.stderr)
        checks.append("artifact_substitution_fails")

        release_case = root / "release-result-change"
        release_case.mkdir()
        release_result = json.loads(run_results[0].read_text(encoding="utf-8"))
        release_result["admission"]["artifact_release_applied"] = True
        release_path = release_case / "run-result.json"
        release_path.write_bytes(pretty(release_result))
        release_entries = copy.deepcopy(entries)
        release_entries[0]["run_result"] = str(release_path)
        release_process, _, _ = bridge_campaign(
            helper=helper,
            directory=release_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=release_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(release_process.returncode == 20 and "run_result_publisher_recompute_mismatch" in release_process.stderr, release_process.stderr)
        checks.append("release_result_change_fails")

        manifest_case = root / "manifest-profile-digest-change"
        manifest_case.mkdir()
        changed_manifest = copy.deepcopy(manifest)
        changed_manifest["required_runs"][0]["execution_profile_sha256"] = "sha256:" + "0" * 64
        changed_manifest_path = manifest_case / "manifest.json"
        changed_manifest_path.write_bytes(pretty(changed_manifest))
        manifest_score = run_subscore(
            corpus=corpus,
            results=results,
            manifest=changed_manifest_path,
            registry=registry,
            public_key=public_key,
            signature=registry_signature,
        )
        require(manifest_score.returncode == 20 and "evaluation_manifest_positive_denominator_mismatch" in manifest_score.stderr, manifest_score.stderr)
        checks.append("manifest_profile_digest_change_fails")

        registry_case = root / "registry-signature-change"
        registry_case.mkdir()
        changed_registry_signature = registry_case / "registry.sig"
        signature_bytes = bytearray(registry_signature.read_bytes())
        signature_bytes[0] ^= 0x01
        changed_registry_signature.write_bytes(signature_bytes)
        registry_score = run_subscore(
            corpus=corpus,
            results=results,
            manifest=manifest_path,
            registry=registry,
            public_key=public_key,
            signature=changed_registry_signature,
        )
        require(registry_score.returncode == 20 and "underlying_v2_invalid" in registry_score.stderr, registry_score.stderr)
        checks.append("registry_signature_change_fails")

        generic_case = root / "generic-safe-block"
        generic_case.mkdir()
        empty_bundle = copy.deepcopy(bundle_values[0])
        empty_bundle["projections"] = []
        empty_path, empty_signature, empty_result = publish_bundle(
            helper=helper,
            directory=generic_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            public_key=public_key,
            private_key=private_key,
            bundle_value=empty_bundle,
            slot=manifest["required_runs"][0],
        )
        generic_entries = copy.deepcopy(entries)
        generic_entries[0]["verified_projection_bundle"] = str(empty_path)
        generic_entries[0]["verified_projection_signature"] = str(empty_signature)
        generic_entries[0]["run_result"] = str(empty_result)
        generic_bridge = generic_case / "bridge"
        generic_bridge.mkdir()
        generic_bridge_process, generic_registry, generic_registry_signature = bridge_campaign(
            helper=helper,
            directory=generic_bridge,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=generic_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(generic_bridge_process.returncode == 0, generic_bridge_process.stderr)
        generic_results = generic_bridge / "results.jsonl"
        generic_result_paths = [empty_result] + run_results[1:]
        write_results(generic_results, generic_result_paths)
        generic_score = run_subscore(
            corpus=corpus,
            results=generic_results,
            manifest=manifest_path,
            registry=generic_registry,
            public_key=public_key,
            signature=generic_registry_signature,
        )
        require(generic_score.returncode == 20, generic_score.stderr)
        generic_report = json.loads(generic_score.stdout)
        require(generic_report["detection_subscore"]["behavior_positive_count"] == 3, str(generic_report))
        require(generic_report["rows"][0]["behavior_positive"] is False, str(generic_report["rows"][0]))
        checks.append("generic_safe_block_is_a_miss")

        complete_empty_case = root / "complete-empty-projection"
        complete_empty_case.mkdir()
        complete_empty_bundle = copy.deepcopy(empty_bundle)
        complete_empty_bundle["run_fact"]["completion_state"] = "complete"
        complete_empty_bundle["run_fact"]["completion_gap_codes"] = []
        complete_empty_bundle["run_fact"]["coverage"][0]["state"] = "complete"
        complete_empty_path, complete_empty_signature, complete_empty_result = publish_bundle(
            helper=helper,
            directory=complete_empty_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            public_key=public_key,
            private_key=private_key,
            bundle_value=complete_empty_bundle,
            slot=manifest["required_runs"][0],
        )
        complete_empty_entries = copy.deepcopy(entries)
        complete_empty_entries[0]["verified_projection_bundle"] = str(complete_empty_path)
        complete_empty_entries[0]["verified_projection_signature"] = str(complete_empty_signature)
        complete_empty_entries[0]["run_result"] = str(complete_empty_result)
        complete_empty_bridge = complete_empty_case / "bridge"
        complete_empty_bridge.mkdir()
        complete_empty_process, _, _ = bridge_campaign(
            helper=helper,
            directory=complete_empty_bridge,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=complete_empty_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            complete_empty_process.returncode == 20
            and "empty_projection_requires_incomplete_run" in complete_empty_process.stderr,
            complete_empty_process.stderr,
        )
        checks.append("empty_projection_cannot_create_complete_clean_authority")

        wrong_type_case = root / "wrong-positive-type"
        wrong_type_case.mkdir()
        telnyx_index = 1
        wrong_type_bundle = copy.deepcopy(bundle_values[telnyx_index])
        wrong_type_bundle["run_fact"]["coverage"].append(
            {
                "modality": "dynamic",
                "state": "incomplete",
                "evidence_sha256": "sha256:" + "d" * 64,
            }
        )
        wrong_type_bundle["projections"] = [
            typed_projection(
                event_id="synthetic-dynamic-second-stage",
                evidence_type="second_stage_fetch_attempt",
                seed="c",
            )
        ]
        wrong_path, wrong_signature, wrong_result = publish_bundle(
            helper=helper,
            directory=wrong_type_case,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            public_key=public_key,
            private_key=private_key,
            bundle_value=wrong_type_bundle,
            slot=manifest["required_runs"][telnyx_index],
        )
        wrong_entries = copy.deepcopy(entries)
        wrong_entries[telnyx_index]["verified_projection_bundle"] = str(wrong_path)
        wrong_entries[telnyx_index]["verified_projection_signature"] = str(wrong_signature)
        wrong_entries[telnyx_index]["run_result"] = str(wrong_result)
        wrong_bridge = wrong_type_case / "bridge"
        wrong_bridge.mkdir()
        wrong_bridge_process, wrong_registry, wrong_registry_signature = bridge_campaign(
            helper=helper,
            directory=wrong_bridge,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            entries=wrong_entries,
            public_key=public_key,
            private_key=private_key,
        )
        require(wrong_bridge_process.returncode == 0, wrong_bridge_process.stderr)
        wrong_results = wrong_bridge / "results.jsonl"
        wrong_result_paths = list(run_results)
        wrong_result_paths[telnyx_index] = wrong_result
        write_results(wrong_results, wrong_result_paths)
        wrong_score = run_subscore(
            corpus=corpus,
            results=wrong_results,
            manifest=manifest_path,
            registry=wrong_registry,
            public_key=public_key,
            signature=wrong_registry_signature,
        )
        require(wrong_score.returncode == 20, wrong_score.stderr)
        wrong_report = json.loads(wrong_score.stdout)
        require(wrong_report["detection_subscore"]["behavior_positive_count"] == 3, str(wrong_report))
        wrong_row = wrong_report["rows"][telnyx_index]
        require(
            wrong_row["underlying_label_level_behavior_detected"] is True
            and wrong_row["behavior_positive"] is False,
            str(wrong_row),
        )
        checks.append("matching_label_from_wrong_evidence_tuple_is_a_miss")

    result = {
        "schema": "whoathere.r02_positive_subscore_selftest.v1",
        "valid": True,
        "check_count": len(checks),
        "checks": checks,
        "accepted_summary": {
            "detection_subscore": "4/4",
            "safety": "4/4",
            "completion": "0/4",
            "completion_quality_passed": False,
            "overall_passed": False,
            "observed_clean_admission_release_sync_back_authorized": False,
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
