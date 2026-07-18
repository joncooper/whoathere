#!/usr/bin/env python3
"""Hermetic tests for the fail-closed verified-evidence registry producer.

All evidence is inert synthetic JSON. The fixture verifier is deliberately test-only: it exercises
the closed subprocess protocol but is not a substitute for the missing production Rust receipt and
event verifier.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
PRODUCER = REPO_ROOT / "scripts" / "whoathere-verified-evidence-registry.py"
SCORER_ID = "whoathere-actual-malware-evaluation.py:score-results-v2"
CREATED_AT = "2026-07-15T00:03:00Z"


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def canonical(value: Any, *, newline: bool = False) -> bytes:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return payload + (b"\n" if newline else b"")


def write_json(path: Path, value: Any) -> None:
    path.write_bytes(json.dumps(value, indent=2, sort_keys=True).encode() + b"\n")


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_bytes(b"".join(canonical(row, newline=True) for row in rows))


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def generate_key_pair(private_key: Path, public_key: Path) -> None:
    generated = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private_key)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert_true(generated.returncode == 0, "synthetic private-key generation failed")
    private_key.chmod(0o600)
    derived = subprocess.run(
        ["openssl", "pkey", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    assert_true(derived.returncode == 0, "synthetic public-key derivation failed")


def corpus_row() -> dict[str, Any]:
    return {
        "schema_version": "whoathere.actual_malware.corpus.v1",
        "sample_id": "synthetic-malicious",
        "sample_kind": "malware",
        "ecosystem": "npm",
        "package_name": "synthetic-malicious",
        "package_version": "1.0.0",
        "artifact_filename": "synthetic-malicious.tgz",
        "artifact_sha256": "sha256:" + "a" * 64,
        "artifact_size_bytes": 64,
        "source_type": "lab_benign_fixture",
        "source_reference": "synthetic:selftest",
        "disclosure_date": "2026-07-01",
        "expected_result": "malicious",
        "trigger_phases": ["npm_lifecycle"],
        "behavior_labels": ["credential_env_access"],
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "acquisition": {
            "case_id": "synthetic-selftest",
            "allowed_test_purpose": "hermetic registry producer selftest",
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
        "evaluation_id": "synthetic-registry-evaluation",
        "created_at_utc": "2026-07-14T23:59:00Z",
        "corpus_sha256": sha256_file(corpus_path),
        "identities": {
            "runtime_sha256": "sha256:" + "b" * 64,
            "prompt_set_sha256": "sha256:" + "c" * 64,
            "observation_schema_sha256": "sha256:" + "d" * 64,
            "provider_adapter_sha256": "sha256:" + "e" * 64,
            "policy_sha256": "sha256:" + "f" * 64,
            "scorer_id": SCORER_ID,
        },
        "verified_evidence_registry": {
            "registry_id": "synthetic-registry",
            "verifier_id": "synthetic-fixture-verifier",
            "verifier_public_key_sha256": sha256_file(public_key),
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
                "cohort_id": "synthetic-malicious-cohort",
                "expected_result": "malicious",
                "description": "Inert synthetic registry-producer fixture.",
            }
        ],
        "required_runs": [
            {
                "sample_id": "synthetic-malicious",
                "profile_id": "npm-ci-false",
                "cohort_id": "synthetic-malicious-cohort",
                "family_id": "synthetic-family",
                "campaign_id": "synthetic-campaign",
                "artifact_sha256": "sha256:" + "a" * 64,
                "ecosystem": "npm",
                "expected_result": "malicious",
                "required_behavior_labels": ["credential_env_access"],
                "required_modalities": ["dynamic"],
                "require_complete": True,
            }
        ],
    }


def result(manifest_path: Path, corpus_path: Path, event_path: Path) -> dict[str, Any]:
    return {
        "schema": "whoathere.actual_malware.run_result.v2",
        "created_at_utc": "2026-07-15T00:01:00Z",
        "run_id": "synthetic-run",
        "evaluation_id": "synthetic-registry-evaluation",
        "evaluation_manifest_sha256": sha256_file(manifest_path),
        "corpus_sha256": sha256_file(corpus_path),
        "sample_id": "synthetic-malicious",
        "profile_id": "npm-ci-false",
        "artifact_sha256": "sha256:" + "a" * 64,
        "ecosystem": "npm",
        "identities": {
            "runtime_sha256": "sha256:" + "b" * 64,
            "prompt_set_sha256": "sha256:" + "c" * 64,
            "observation_schema_sha256": "sha256:" + "d" * 64,
            "provider_adapter_sha256": "sha256:" + "e" * 64,
            "policy_sha256": "sha256:" + "f" * 64,
            "scorer_id": SCORER_ID,
        },
        "completion_state": "complete",
        "completion_reason_codes": [],
        "coverage": [
            {
                "modality": "dynamic",
                "state": "complete",
                "evidence_sha256": "sha256:" + "1" * 64,
            }
        ],
        "observations": [
            {
                "observation_id": "credential-read-1",
                "modality": "dynamic",
                "evidence_type": "environment_credential_read",
                "behavior_label": "credential_env_access",
                "evidence_ref": "receipt:synthetic-root#credential-read-1",
                "evidence_sha256": sha256_file(event_path),
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
        "admission": {
            "artifact_release_applied": False,
            "manual_review_required": True,
        },
    }


FIXTURE_VERIFIER = r'''#!/usr/bin/env python3
import argparse, hashlib, json, os
from pathlib import Path

def digest(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

parser = argparse.ArgumentParser()
parser.add_argument("--request", type=Path, required=True)
parser.add_argument("--response", type=Path, required=True)
args = parser.parse_args()
request_bytes = args.request.read_bytes()
request = json.loads(request_bytes)
assert canonical(request) == request_bytes
sources = {}
verified_sources = []
for source in request["sources"]:
    payload = Path(source["path"]).read_bytes()
    assert len(payload) == source["byte_length"]
    assert digest(payload) == source["sha256"]
    sources[source["source_id"]] = source
    verified_sources.append({
        "source_id": source["source_id"],
        "role": source["role"],
        "byte_length": source["byte_length"],
        "sha256": source["sha256"],
        "authentication": source["required_authentication"],
        "verification_status": "verified",
    })
observations = {row["observation_id"]: row for row in request["run_result"]["observations"]}
mappings = {row["observation_id"]: row for row in request["observation_sources"]}
verified_observations = []
for observation_id, observation in sorted(observations.items()):
    mapping = mappings[observation_id]
    receipt = sources[mapping["source_receipt_id"]]
    verified_observations.append({
        "observation_id": observation_id,
        "observed_at_utc": request["run_result"]["created_at_utc"],
        "modality": observation["modality"],
        "evidence_type": observation["evidence_type"],
        "behavior_label": observation["behavior_label"],
        "evidence_ref": observation["evidence_ref"],
        "evidence_sha256": observation["evidence_sha256"],
        "event_source_id": mapping["event_source_id"],
        "source_receipt_id": mapping["source_receipt_id"],
        "source_receipt_sha256": receipt["sha256"],
        "authentication": "typed_event_derived_from_verified_receipt",
    })
run_receipt = sources[request["run_fact_source_receipt_id"]]
response = {
    "schema": "whoathere.actual_malware.evidence_verifier_response.v1",
    "verifier_id": request["verifier_id"],
    "verifier_executable_sha256": request["verifier_executable_sha256"],
    "request_sha256": digest(request_bytes),
    "sample_id": request["sample_id"],
    "profile_id": request["profile_id"],
    "artifact_sha256": request["artifact_sha256"],
    "verified_at_utc": "2026-07-15T00:02:00Z",
    "verification_status": "verified",
    "sources": sorted(verified_sources, key=lambda row: row["source_id"]),
    "run_fact": {
        "observed_at_utc": request["run_result"]["created_at_utc"],
        "run_fact_projection_sha256": request["run_fact_projection_sha256"],
        "source_receipt_id": request["run_fact_source_receipt_id"],
        "source_receipt_sha256": run_receipt["sha256"],
        "authentication": "verified_from_signed_receipts",
    },
    "observations": verified_observations,
    "claim_boundary": "Receipt signatures, expected bindings, event digests, and run facts verified; no verdict or admission authority.",
}
descriptor = os.open(args.response, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
try:
    os.write(descriptor, canonical(response))
    os.fsync(descriptor)
finally:
    os.close(descriptor)
'''


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.evidence = root / "evidence"
        self.evidence.mkdir(parents=True)
        self.private_key = root / "operator-private.pem"
        self.public_key = self.evidence / "operator-public.pem"
        generate_key_pair(self.private_key, self.public_key)
        self.verifier = root / "synthetic-fixture-verifier.py"
        self.verifier.write_text(
            FIXTURE_VERIFIER.replace("#!/usr/bin/env python3", f"#!{sys.executable}"),
            encoding="utf-8",
        )
        self.verifier.chmod(0o700)
        self.corpus = self.evidence / "corpus.jsonl"
        write_jsonl(self.corpus, [corpus_row()])
        self.manifest = self.evidence / "manifest.json"
        write_json(self.manifest, manifest(self.corpus, self.public_key))
        self.sources: dict[str, tuple[str, Path]] = {}
        for source_id, role, filename, payload in [
            ("root-receipt", "guest_root_receipt", "root-receipt.json", b'{"synthetic":"root"}'),
            ("host-evidence", "host_composite_evidence", "host-evidence.json", b'{"synthetic":"host-evidence"}'),
            ("host-receipt", "host_composite_receipt", "host-receipt.json", b'{"synthetic":"host-receipt"}'),
            ("guest-key", "guest_evidence_public_key", "guest.pub", b"synthetic-guest-key"),
            ("host-key", "host_evidence_public_key", "host.pub", b"synthetic-host-key"),
            ("bindings", "expected_bindings", "bindings.json", b'{"synthetic":"bindings"}'),
            ("credential-event", "typed_event", "credential-event.json", b'{"synthetic":"credential-read"}'),
        ]:
            path = self.evidence / filename
            path.write_bytes(payload)
            self.sources[source_id] = (role, path)
        self.results = self.evidence / "results.jsonl"
        self.row = result(self.manifest, self.corpus, self.sources["credential-event"][1])
        write_jsonl(self.results, [self.row])
        self.index = self.evidence / "verification-index.json"
        self.write_index()
        self.registry = self.evidence / "registry.json"
        self.signature = self.evidence / "registry.sig"

    def index_value(self) -> dict[str, Any]:
        return {
            "schema": "whoathere.actual_malware.evidence_verification_index.v1",
            "evaluation_id": "synthetic-registry-evaluation",
            "evaluation_manifest_sha256": sha256_file(self.manifest),
            "corpus_sha256": sha256_file(self.corpus),
            "results_sha256": sha256_file(self.results),
            "verifier_id": "synthetic-fixture-verifier",
            "verifier_protocol": "whoathere-independent-receipt-event-verifier-v1",
            "verifier_executable_sha256": sha256_file(self.verifier),
            "runs": [
                {
                    "sample_id": "synthetic-malicious",
                    "profile_id": "npm-ci-false",
                    "artifact_sha256": "sha256:" + "a" * 64,
                    "run_fact_source_receipt_id": "host-receipt",
                    "sources": [
                        {
                            "source_id": source_id,
                            "role": role,
                            "relative_path": path.relative_to(self.evidence).as_posix(),
                            "byte_length": path.stat().st_size,
                            "sha256": sha256_file(path),
                        }
                        for source_id, (role, path) in sorted(self.sources.items())
                    ],
                    "observation_sources": [
                        {
                            "observation_id": "credential-read-1",
                            "event_source_id": "credential-event",
                            "source_receipt_id": "root-receipt",
                        }
                    ],
                }
            ],
        }

    def write_index(self, mutate: Callable[[dict[str, Any]], None] | None = None) -> None:
        value = self.index_value()
        if mutate:
            mutate(value)
        write_json(self.index, value)

    def produce_args(self, *, include_verifier: bool = True) -> list[str]:
        arguments = [
            sys.executable,
            str(PRODUCER),
            "produce",
            "--corpus",
            str(self.corpus),
            "--evaluation-manifest",
            str(self.manifest),
            "--results",
            str(self.results),
            "--verification-index",
            str(self.index),
            "--evidence-root",
            str(self.evidence),
            "--expected-verifier-command-sha256",
            sha256_file(self.verifier),
            "--private-key",
            str(self.private_key),
            "--public-key",
            str(self.public_key),
            "--expected-evaluation-manifest-sha256",
            sha256_file(self.manifest),
            "--expected-verifier-public-key-sha256",
            sha256_file(self.public_key),
            "--registry-out",
            str(self.registry),
            "--signature-out",
            str(self.signature),
            "--created-at-utc",
            CREATED_AT,
        ]
        if include_verifier:
            arguments.extend(["--verifier-command", str(self.verifier)])
        return arguments

    def run_produce(self, *, include_verifier: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.produce_args(include_verifier=include_verifier),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

    def run_verify(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(PRODUCER),
                "verify-only",
                "--corpus",
                str(self.corpus),
                "--evaluation-manifest",
                str(self.manifest),
                "--results",
                str(self.results),
                "--registry",
                str(self.registry),
                "--public-key",
                str(self.public_key),
                "--signature",
                str(self.signature),
                "--expected-evaluation-manifest-sha256",
                sha256_file(self.manifest),
                "--expected-verifier-public-key-sha256",
                sha256_file(self.public_key),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )


def reason(process: subprocess.CompletedProcess[str]) -> str:
    try:
        return str(json.loads(process.stderr)["reason_code"])
    except (json.JSONDecodeError, KeyError) as exc:
        raise AssertionError(f"invalid diagnostic: {process.stderr}") from exc


def new_fixture(root: Path, name: str) -> Fixture:
    case = root / name
    case.mkdir()
    return Fixture(case)


def main() -> int:
    if shutil.which("openssl") is None:
        print("openssl is required for registry-producer selftests", file=sys.stderr)
        return 77
    tests: list[str] = []
    with tempfile.TemporaryDirectory(prefix="whoathere-registry-selftest-") as raw_root:
        root = Path(raw_root)

        success = new_fixture(root, "success")
        produced = success.run_produce()
        assert_true(produced.returncode == 0, produced.stderr)
        report = json.loads(produced.stdout)
        assert_true(report["status"] == "generated_and_verified", produced.stdout)
        assert_true(success.signature.stat().st_size == 64, "signature is not raw Ed25519")
        verified = success.run_verify()
        assert_true(verified.returncode == 0, verified.stderr)
        assert_true(json.loads(verified.stdout)["status"] == "verified", verified.stdout)
        tests.extend(["produce_and_self_verify", "raw_ed25519_signature", "verify_only"])

        unavailable = new_fixture(root, "missing-verifier")
        missing = unavailable.run_produce(include_verifier=False)
        assert_true(missing.returncode == 64, missing.stderr)
        assert_true(reason(missing) == "independent_receipt_event_verifier_unavailable", missing.stderr)
        assert_true(not unavailable.registry.exists() and not unavailable.signature.exists(), "outputs generated")
        tests.append("missing_verifier_is_not_generated")

        manifest_substitution = new_fixture(root, "manifest-substitution")
        arguments = manifest_substitution.produce_args()
        pin_index = arguments.index("--expected-evaluation-manifest-sha256") + 1
        arguments[pin_index] = "sha256:" + "0" * 64
        substituted = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert_true(reason(substituted) == "evaluation_manifest_out_of_band_digest_mismatch", substituted.stderr)
        tests.append("manifest_substitution_rejected")

        verifier_substitution = new_fixture(root, "verifier-substitution")
        arguments = verifier_substitution.produce_args()
        pin_index = arguments.index("--expected-verifier-command-sha256") + 1
        arguments[pin_index] = "sha256:" + "0" * 64
        substituted = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert_true(reason(substituted) == "independent_verifier_out_of_band_digest_mismatch", substituted.stderr)
        tests.append("verifier_substitution_rejected")

        source_tamper = new_fixture(root, "source-tamper")
        source_tamper.sources["credential-event"][1].write_bytes(b"tampered")
        tampered = source_tamper.run_produce()
        assert_true(reason(tampered) in {"evidence_source_byte_length_mismatch", "evidence_source_size_invalid"}, tampered.stderr)
        tests.append("source_tamper_rejected")

        duplicate = new_fixture(root, "duplicate-result")
        write_jsonl(duplicate.results, [duplicate.row, duplicate.row])
        duplicate.write_index()
        duplicated = duplicate.run_produce()
        assert_true(reason(duplicated) == "result_run_id_missing_or_duplicate", duplicated.stderr)
        tests.append("duplicate_result_rejected")

        missing_result = new_fixture(root, "missing-result")
        missing_result.results.write_text("# intentionally empty\n", encoding="utf-8")
        missing_result.write_index()
        absent = missing_result.run_produce()
        assert_true(reason(absent) == "manifest_denominator_result_missing", absent.stderr)
        tests.append("missing_result_rejected")

        duplicate_index = new_fixture(root, "duplicate-index")
        duplicate_index.write_index(lambda value: value["runs"].append(copy.deepcopy(value["runs"][0])))
        duplicated = duplicate_index.run_produce()
        assert_true(reason(duplicated) == "verification_index_run_duplicate", duplicated.stderr)
        tests.append("duplicate_index_run_rejected")

        missing_mapping = new_fixture(root, "missing-mapping")
        missing_mapping.write_index(lambda value: value["runs"][0].update({"observation_sources": []}))
        absent = missing_mapping.run_produce()
        assert_true(reason(absent) == "verification_index_observation_denominator_mismatch", absent.stderr)
        tests.append("missing_observation_mapping_rejected")

        source_symlink = new_fixture(root, "source-symlink")
        event = source_symlink.sources["credential-event"][1]
        replacement = source_symlink.evidence / "replacement-event.json"
        replacement.write_bytes(event.read_bytes())
        event.unlink()
        event.symlink_to(replacement.name)
        symlinked = source_symlink.run_produce()
        assert_true(reason(symlinked) == "evidence_source_symlink_forbidden", symlinked.stderr)
        tests.append("evidence_symlink_rejected")

        key_symlink = new_fixture(root, "key-symlink")
        real_private = key_symlink.private_key
        linked_private = key_symlink.root / "linked-private.pem"
        linked_private.symlink_to(real_private.name)
        arguments = key_symlink.produce_args()
        arguments[arguments.index("--private-key") + 1] = str(linked_private)
        symlinked = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert_true(reason(symlinked) == "registry_private_key_symlink_forbidden", symlinked.stderr)
        tests.append("private_key_symlink_rejected")

        key_location = new_fixture(root, "key-location")
        in_tree = key_location.evidence / "private.pem"
        shutil.copyfile(key_location.private_key, in_tree)
        in_tree.chmod(0o600)
        arguments = key_location.produce_args()
        arguments[arguments.index("--private-key") + 1] = str(in_tree)
        misplaced = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert_true(reason(misplaced) == "registry_private_key_under_evidence_root_forbidden", misplaced.stderr)
        tests.append("private_key_under_evidence_tree_rejected")

        key_mismatch = new_fixture(root, "key-mismatch")
        other_private = key_mismatch.root / "other-private.pem"
        other_public = key_mismatch.root / "other-public.pem"
        generate_key_pair(other_private, other_public)
        arguments = key_mismatch.produce_args()
        arguments[arguments.index("--private-key") + 1] = str(other_private)
        mismatch = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert_true(reason(mismatch) == "registry_private_public_key_mismatch", mismatch.stderr)
        tests.append("private_public_key_mismatch_rejected")

        registry_tamper = new_fixture(root, "registry-tamper")
        assert_true(registry_tamper.run_produce().returncode == 0, "baseline generation failed")
        registry_tamper.registry.write_bytes(registry_tamper.registry.read_bytes() + b" ")
        tampered = registry_tamper.run_verify()
        assert_true(reason(tampered) == "verified_registry_signature_invalid", tampered.stderr)
        tests.append("signed_registry_tamper_rejected")

        exclusive = new_fixture(root, "exclusive-output")
        assert_true(exclusive.run_produce().returncode == 0, "baseline generation failed")
        registry_digest = sha256_file(exclusive.registry)
        signature_digest = sha256_file(exclusive.signature)
        repeated = exclusive.run_produce()
        assert_true(reason(repeated) == "registry_output_already_exists", repeated.stderr)
        assert_true(sha256_file(exclusive.registry) == registry_digest, "registry overwritten")
        assert_true(sha256_file(exclusive.signature) == signature_digest, "signature overwritten")
        tests.append("exclusive_outputs_not_overwritten")

    print(json.dumps({"status": "ok", "test_count": len(tests), "tests": tests}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
