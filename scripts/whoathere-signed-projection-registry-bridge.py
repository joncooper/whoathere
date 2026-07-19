#!/usr/bin/env python3
"""Bridge signed independent projection bundles into the mandatory V2 evidence registry.

This is deliberately a narrow, fail-closed bridge. A canonical run index must name exactly one
signed bundle and one publisher-emitted result for every manifest run. Each bundle must contain one
or more publisher-supported independently verified projections, or an explicitly empty projection
set for a signed no-finding run. The bridge reuses the RunResultV2 publisher as the policy authority,
independently checks every bundle signature and frozen identity pin, requires every supplied
RunResultV2 to be byte-for-byte publisher serialization and semantically identical to a fresh
publisher result, and then derives the current evaluator registry records. It never inspects or
executes package bytes and never grants release authority.

The resulting registry is signed with the same Ed25519 identity frozen in EvaluationManifestV2.
The bridge therefore needs access to that verifier identity's signing key; it neither creates nor
persists a key.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PUBLISHER_PATH = ROOT / "scripts" / "whoathere-run-result-v2-publisher.py"
EVALUATOR_PATH = ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"

REGISTRY_SCHEMA = "whoathere.actual_malware.verified_evidence_registry.v1"
RUN_INDEX_SCHEMA = "whoathere.actual_malware.signed_projection_run_index.v1"
SUPPORTED_PROJECTION_KINDS = {
    "static_download_execute_capability",
    "static_sensitive_file_exfiltration_capability",
    "typed_event",
}
STATIC_PROJECTION_EVIDENCE_TYPES = {
    "static_download_execute_capability": "download_execute_capability",
    "static_sensitive_file_exfiltration_capability": "sensitive_file_exfiltration_capability",
}
MAX_RUN_INDEX_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 64 * 1024 * 1024
MAX_PRIVATE_KEY_BYTES = 64 * 1024


class BridgeError(Exception):
    """A stable fail-closed bridge error."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise BridgeError(reason)


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"{name}_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - only installation/import failures reach this.
        raise BridgeError(f"{name}_module_unavailable") from exc
    return module


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def publisher_json_bytes(value: Any) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"


def write_exclusive(path: Path, payload: bytes) -> None:
    require(path.is_absolute(), "output_path_not_absolute")
    require(path.parent.is_dir(), "output_parent_missing")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BridgeError("output_create_failed") from exc
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


def sign_registry(
    *,
    registry_bytes: bytes,
    private_key_bytes: bytes,
    public_key_bytes: bytes,
    publisher: ModuleType,
) -> bytes:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl_missing")
    with tempfile.TemporaryDirectory(prefix="whoathere-signed-registry-bridge-") as raw_tmp:
        temporary = Path(raw_tmp)
        private_path = temporary / "registry-private.pem"
        registry_path = temporary / "registry.json"
        signature_path = temporary / "registry.sig"
        private_path.write_bytes(private_key_bytes)
        private_path.chmod(0o600)
        registry_path.write_bytes(registry_bytes)
        signed = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_path),
                "-in",
                str(registry_path),
                "-out",
                str(signature_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(signed.returncode == 0, "registry_signing_failed")
        try:
            signature = signature_path.read_bytes()
        except OSError as exc:
            raise BridgeError("registry_signature_unavailable") from exc
    try:
        publisher.verify_signature(registry_bytes, public_key_bytes, signature)
    except publisher.PublisherError as exc:
        raise BridgeError("registry_signing_key_mismatch") from exc
    return signature


def run_fact_record(
    *,
    result: dict[str, Any],
    bundle: dict[str, Any],
    bundle_sha256: str,
    evaluator: ModuleType,
) -> dict[str, Any]:
    projection_sha256 = evaluator.run_fact_projection_sha256(result)
    record_binding = (
        str(result["sample_id"])
        + "\0"
        + str(result["profile_id"])
        + "\0"
        + projection_sha256
    ).encode("utf-8")
    return {
        "record_id": "run-fact-" + hashlib.sha256(record_binding).hexdigest()[:48],
        "sample_id": result["sample_id"],
        "profile_id": result["profile_id"],
        "artifact_sha256": result["artifact_sha256"],
        "execution_profile_sha256": result["execution_profile_sha256"],
        "verifier_executable_sha256": result["verifier_executable_sha256"],
        "projection_schema_sha256": result["projection_schema_sha256"],
        "observed_at_utc": result["created_at_utc"],
        "verified_at_utc": bundle["verified_at_utc"],
        "run_fact_projection_sha256": projection_sha256,
        "source_receipt_sha256": bundle_sha256,
        "verification_receipt_sha256": bundle_sha256,
        "verification_method": bundle["verifier_id"],
        "verification_status": "verified",
    }


def evidence_records(
    *,
    result: dict[str, Any],
    bundle: dict[str, Any],
    bundle_sha256: str,
    publisher: ModuleType,
) -> list[dict[str, Any]]:
    projections = bundle.get("projections")
    require(isinstance(projections, list), "projection_array_required")
    if not projections:
        run_fact = bundle.get("run_fact")
        require(
            isinstance(run_fact, dict) and run_fact.get("completion_state") != "complete",
            "empty_projection_requires_incomplete_run",
        )
    by_projection_sha256: dict[str, dict[str, Any]] = {}
    for projection in projections:
        projection_kind = projection.get("kind") if isinstance(projection, dict) else None
        require(
            isinstance(projection, dict)
            and isinstance(projection_kind, str)
            and projection_kind in SUPPORTED_PROJECTION_KINDS,
            "projection_kind_unsupported",
        )
        projection_sha256 = publisher.sha256_bytes(publisher.canonical_json_bytes(projection))
        require(projection_sha256 not in by_projection_sha256, "projection_digest_duplicate")
        by_projection_sha256[projection_sha256] = projection

    observations = result.get("observations")
    require(
        isinstance(observations, list) and len(observations) == len(projections),
        "projection_observation_count_mismatch",
    )
    records: list[dict[str, Any]] = []
    observed_projection_sha256: set[str] = set()
    for observation in observations:
        require(isinstance(observation, dict), "projection_observation_invalid")
        projection_sha256 = observation.get("projection_sha256")
        projection = by_projection_sha256.get(str(projection_sha256))
        require(projection is not None, "projection_observation_unbound")
        projection_kind = projection.get("kind")
        if isinstance(projection_kind, str) and projection_kind in STATIC_PROJECTION_EVIDENCE_TYPES:
            expected_modality = "deterministic"
            expected_evidence_type = STATIC_PROJECTION_EVIDENCE_TYPES[projection_kind]
            expected_evidence_sha256 = projection.get("exact_observation_sha256")
        elif projection_kind == "typed_event":
            expected_modality = projection.get("modality")
            expected_evidence_type = projection.get("evidence_type")
            expected_evidence_sha256 = projection.get("event_sha256")
        else:  # Guard the closed catalogue even if the caller changes above.
            raise BridgeError("projection_kind_unsupported")
        expected_behavior_label = publisher.EVIDENCE_TYPE_TO_BEHAVIOR_LABEL.get(
            str(expected_evidence_type)
        )
        require(expected_behavior_label is not None, "projection_evidence_type_unmapped")
        require(
            observation.get("modality") == expected_modality
            and observation.get("evidence_type") == expected_evidence_type
            and observation.get("behavior_label") == expected_behavior_label
            and observation.get("evidence_sha256") == expected_evidence_sha256,
            "projection_observation_policy_mismatch",
        )
        require(str(projection_sha256) not in observed_projection_sha256, "projection_observation_duplicate")
        observed_projection_sha256.add(str(projection_sha256))
        record_binding = (
            str(result["sample_id"])
            + "\0"
            + str(result["profile_id"])
            + "\0"
            + str(projection_sha256)
        ).encode("utf-8")
        records.append(
            {
                "record_id": "evidence-" + hashlib.sha256(record_binding).hexdigest(),
                "sample_id": result["sample_id"],
                "profile_id": result["profile_id"],
                "artifact_sha256": result["artifact_sha256"],
                "execution_profile_sha256": result["execution_profile_sha256"],
                "verifier_executable_sha256": result["verifier_executable_sha256"],
                "projection_schema_sha256": result["projection_schema_sha256"],
                "observed_at_utc": result["created_at_utc"],
                "verified_at_utc": bundle["verified_at_utc"],
                "modality": observation["modality"],
                "evidence_type": observation["evidence_type"],
                "behavior_label": observation["behavior_label"],
                "observation_id": observation["observation_id"],
                "evidence_ref": observation["evidence_ref"],
                "evidence_sha256": observation["evidence_sha256"],
                "projection_sha256": observation["projection_sha256"],
                "source_receipt_sha256": projection["source_receipt_sha256"],
                "verification_receipt_sha256": bundle_sha256,
                "verification_method": bundle["verifier_id"],
                "verification_status": "verified",
            }
        )
    require(
        observed_projection_sha256 == set(by_projection_sha256),
        "projection_observation_set_mismatch",
    )
    return sorted(records, key=lambda row: row["record_id"])


def load_run_index(
    *,
    run_index_path: Path,
    expected_manifest_sha256: str,
    publisher: ModuleType,
) -> list[dict[str, Any]]:
    try:
        raw = publisher.read_regular(
            run_index_path, MAX_RUN_INDEX_BYTES, "signed_projection_run_index"
        )
        require(
            publisher.valid_sha256(expected_manifest_sha256),
            "expected_manifest_sha256_invalid",
        )
        value = publisher.load_json_bytes(raw, "signed_projection_run_index")
        require(isinstance(value, dict), "signed_projection_run_index_not_object")
        require(
            publisher.canonical_json_bytes(value) == raw,
            "signed_projection_run_index_not_canonical",
        )
        require(
            set(value) == {"schema", "evaluation_manifest_sha256", "runs"},
            "signed_projection_run_index_keys_invalid",
        )
        require(value.get("schema") == RUN_INDEX_SCHEMA, "signed_projection_run_index_schema_invalid")
        require(
            value.get("evaluation_manifest_sha256") == expected_manifest_sha256,
            "signed_projection_run_index_manifest_digest_mismatch",
        )
        runs = value.get("runs")
        require(isinstance(runs, list) and runs, "signed_projection_run_index_runs_invalid")
        entries: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        expected_keys = {
            "sample_id",
            "profile_id",
            "verified_projection_bundle",
            "verified_projection_signature",
            "run_result",
        }
        for entry in runs:
            require(isinstance(entry, dict) and set(entry) == expected_keys, "run_index_entry_keys_invalid")
            sample_id = entry.get("sample_id")
            profile_id = entry.get("profile_id")
            require(
                publisher.valid_identifier(sample_id) and publisher.valid_identifier(profile_id),
                "run_index_entry_identity_invalid",
            )
            run_key = (str(sample_id), str(profile_id))
            require(run_key not in seen, "run_index_duplicate_run")
            seen.add(run_key)
            normalized = dict(entry)
            for key in (
                "verified_projection_bundle",
                "verified_projection_signature",
                "run_result",
            ):
                path_value = entry.get(key)
                require(
                    isinstance(path_value, str) and 1 <= len(path_value) <= 4096,
                    f"run_index_{key}_path_invalid",
                )
                path = Path(path_value)
                require(path.is_absolute(), f"run_index_{key}_path_not_absolute")
                normalized[key] = path
            entries.append(normalized)
        return entries
    except BridgeError:
        raise
    except publisher.PublisherError as exc:
        raise BridgeError(str(exc)) from exc


def verify_indexed_run(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    manifest: dict[str, Any],
    slot: dict[str, Any],
    entry: dict[str, Any],
    public_key_path: Path,
    public_key_raw: bytes,
    publisher: ModuleType,
) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    sample_id = str(entry["sample_id"])
    profile_id = str(entry["profile_id"])
    bundle_path = entry["verified_projection_bundle"]
    bundle_signature_path = entry["verified_projection_signature"]
    run_result_path = entry["run_result"]
    try:
        bundle_signature_raw = publisher.read_regular(
            bundle_signature_path, publisher.MAX_SIGNATURE_BYTES, "projection_signature"
        )
        bundle_raw = publisher.read_regular(
            bundle_path, publisher.MAX_BUNDLE_BYTES, "verified_projection_bundle"
        )
        bundle = publisher.load_json_bytes(bundle_raw, "verified_projection_bundle")
        require(isinstance(bundle, dict), "verified_projection_bundle_not_object")
        require(
            publisher.canonical_json_bytes(bundle) == bundle_raw,
            "verified_projection_bundle_not_canonical",
        )

        expected_registry = manifest.get("verified_evidence_registry")
        require(isinstance(expected_registry, dict), "manifest_verified_registry_invalid")
        publisher.verify_signature(bundle_raw, public_key_raw, bundle_signature_raw)
        for key in (
            "verifier_id",
            "verifier_executable_sha256",
            "projection_schema_sha256",
            "verifier_public_key_sha256",
        ):
            require(bundle.get(key) == expected_registry.get(key), f"{key}_pin_mismatch")
        run_fact = bundle.get("run_fact")
        require(isinstance(run_fact, dict), "verified_run_fact_not_object")
        require(
            run_fact.get("execution_profile_sha256") == slot.get("execution_profile_sha256"),
            "execution_profile_sha256_pin_mismatch",
        )
        require(
            run_fact.get("verifier_executable_sha256")
            == expected_registry.get("verifier_executable_sha256"),
            "run_fact_verifier_executable_sha256_pin_mismatch",
        )
        require(
            run_fact.get("projection_schema_sha256")
            == expected_registry.get("projection_schema_sha256"),
            "run_fact_projection_schema_sha256_pin_mismatch",
        )

        recomputed_result = publisher.publish(
            manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest_sha256,
            sample_id=sample_id,
            profile_id=profile_id,
            bundle_path=bundle_path,
            signature_path=bundle_signature_path,
            public_key_path=public_key_path,
        )
        run_result_raw = publisher.read_regular(run_result_path, MAX_RESULT_BYTES, "run_result")
        supplied_result = publisher.load_json_bytes(run_result_raw, "run_result")
        require(isinstance(supplied_result, dict), "run_result_not_object")
        require(
            run_result_raw == publisher_json_bytes(supplied_result),
            "run_result_not_publisher_serialization",
        )
        require(supplied_result == recomputed_result, "run_result_publisher_recompute_mismatch")
        return supplied_result, bundle, bundle_raw
    except BridgeError:
        raise
    except publisher.PublisherError as exc:
        raise BridgeError(str(exc)) from exc


def derive_registry(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    run_index_path: Path,
    public_key_path: Path,
    publisher: ModuleType,
    evaluator: ModuleType,
) -> tuple[dict[str, Any], bytes, dict[tuple[str, str], str]]:
    entries = load_run_index(
        run_index_path=run_index_path,
        expected_manifest_sha256=expected_manifest_sha256,
        publisher=publisher,
    )
    try:
        manifest_raw = publisher.read_regular(
            manifest_path, publisher.MAX_MANIFEST_BYTES, "evaluation_manifest"
        )
        require(
            publisher.sha256_bytes(manifest_raw) == expected_manifest_sha256,
            "evaluation_manifest_digest_mismatch",
        )
        manifest = publisher.load_json_bytes(manifest_raw, "evaluation_manifest")
        require(isinstance(manifest, dict), "evaluation_manifest_not_object")
        required_runs = manifest.get("required_runs")
        require(isinstance(required_runs, list) and required_runs, "manifest_required_runs_invalid")
        required_runs_by_key: dict[tuple[str, str], dict[str, Any]] = {}
        for slot in required_runs:
            require(isinstance(slot, dict), "manifest_run_slot_invalid")
            run_key = (str(slot.get("sample_id")), str(slot.get("profile_id")))
            require(run_key not in required_runs_by_key, "manifest_run_slot_not_unique")
            required_runs_by_key[run_key] = slot
        entries_by_key = {
            (str(entry["sample_id"]), str(entry["profile_id"])): entry for entry in entries
        }
        missing = set(required_runs_by_key) - set(entries_by_key)
        unknown = set(entries_by_key) - set(required_runs_by_key)
        require(not missing, "run_index_missing_manifest_run")
        require(not unknown, "run_index_unknown_run")
        require(len(entries) == len(required_runs_by_key), "run_index_denominator_mismatch")

        public_key_raw = publisher.read_regular(
            public_key_path, publisher.MAX_KEY_BYTES, "verifier_public_key"
        )
        expected_registry = manifest.get("verified_evidence_registry")
        require(isinstance(expected_registry, dict), "manifest_verified_registry_invalid")
        require(
            publisher.sha256_bytes(public_key_raw)
            == expected_registry.get("verifier_public_key_sha256"),
            "verifier_public_key_digest_mismatch",
        )
    except BridgeError:
        raise
    except publisher.PublisherError as exc:
        raise BridgeError(str(exc)) from exc

    verified_runs: list[tuple[dict[str, Any], dict[str, Any], bytes]] = []
    bundle_sha256_by_run: dict[tuple[str, str], str] = {}
    for run_key in sorted(required_runs_by_key):
        result, bundle, bundle_raw = verify_indexed_run(
            manifest_path=manifest_path,
            expected_manifest_sha256=expected_manifest_sha256,
            manifest=manifest,
            slot=required_runs_by_key[run_key],
            entry=entries_by_key[run_key],
            public_key_path=public_key_path,
            public_key_raw=public_key_raw,
            publisher=publisher,
        )
        verified_runs.append((result, bundle, bundle_raw))
        bundle_sha256_by_run[run_key] = sha256_bytes(bundle_raw)

    registry_created_at = max(
        (bundle["verified_at_utc"] for _, bundle, _ in verified_runs),
        key=lambda value: publisher.parse_utc(value, "projection_verified_at_invalid"),
    )
    run_fact_records: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    results_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    for result, bundle, bundle_raw in verified_runs:
        run_key = (str(result["sample_id"]), str(result["profile_id"]))
        bundle_sha256 = sha256_bytes(bundle_raw)
        results_by_key[run_key] = result
        run_fact_records.append(
            run_fact_record(
                result=result,
                bundle=bundle,
                bundle_sha256=bundle_sha256,
                evaluator=evaluator,
            )
        )
        records.extend(
            evidence_records(
                result=result,
                bundle=bundle,
                bundle_sha256=bundle_sha256,
                publisher=publisher,
            )
        )

    registry = {
        "schema": REGISTRY_SCHEMA,
        "registry_id": expected_registry["registry_id"],
        "created_at_utc": registry_created_at,
        "evaluation_id": manifest["evaluation_id"],
        "evaluation_manifest_sha256": expected_manifest_sha256,
        "corpus_sha256": manifest["corpus_sha256"],
        "identities": manifest["identities"],
        "verifier_id": expected_registry["verifier_id"],
        "verifier_public_key_sha256": expected_registry["verifier_public_key_sha256"],
        "verifier_executable_sha256": expected_registry["verifier_executable_sha256"],
        "projection_schema_sha256": expected_registry["projection_schema_sha256"],
        "run_fact_records": sorted(
            run_fact_records, key=lambda row: (row["sample_id"], row["profile_id"])
        ),
        "records": sorted(records, key=lambda row: row["record_id"]),
    }

    registry_errors, verified_records, verified_run_facts, registry_created_at = (
        evaluator.validate_verified_evidence_registry_v1(
            registry,
            manifest,
            expected_manifest_sha256,
            manifest["corpus_sha256"],
            required_runs_by_key,
        )
    )
    if registry_errors:
        raise BridgeError("derived_registry_invalid:" + str(registry_errors[0]))
    for run_key in sorted(required_runs_by_key):
        result_errors, _ = evaluator.validate_run_result_v2(
            results_by_key[run_key],
            required_runs_by_key[run_key],
            manifest,
            expected_manifest_sha256,
            manifest["corpus_sha256"],
            verified_records,
            verified_run_facts,
            registry_created_at,
        )
        if result_errors:
            raise BridgeError(
                f"derived_registry_result_invalid:{run_key[0]}:{run_key[1]}:{result_errors[0]}"
            )
    return registry, public_key_raw, bundle_sha256_by_run


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--evaluation-manifest", type=Path, required=True)
    result.add_argument("--expected-evaluation-manifest-sha256", required=True)
    result.add_argument("--run-index", type=Path, required=True)
    result.add_argument("--verifier-public-key", type=Path, required=True)
    result.add_argument("--registry-signing-private-key", type=Path, required=True)
    result.add_argument("--out-registry", type=Path, required=True)
    result.add_argument("--out-signature", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    publisher = load_module("whoathere_run_result_v2_publisher", PUBLISHER_PATH)
    evaluator = load_module("whoathere_actual_malware_evaluation", EVALUATOR_PATH)
    try:
        manifest_path = args.evaluation_manifest.expanduser().absolute()
        run_index_path = args.run_index.expanduser().absolute()
        public_key_path = args.verifier_public_key.expanduser().absolute()
        private_key_path = args.registry_signing_private_key.expanduser().absolute()
        out_registry = args.out_registry.expanduser().absolute()
        out_signature = args.out_signature.expanduser().absolute()
        require(out_registry != out_signature, "output_paths_must_differ")
        require(not out_registry.exists() and not out_signature.exists(), "output_already_exists")

        registry, public_key_raw, bundle_sha256_by_run = derive_registry(
            manifest_path=manifest_path,
            expected_manifest_sha256=args.expected_evaluation_manifest_sha256,
            run_index_path=run_index_path,
            public_key_path=public_key_path,
            publisher=publisher,
            evaluator=evaluator,
        )
        try:
            private_key_raw = publisher.read_regular(
                private_key_path, MAX_PRIVATE_KEY_BYTES, "registry_signing_private_key"
            )
        except publisher.PublisherError as exc:
            raise BridgeError(str(exc)) from exc
        registry_raw = publisher_json_bytes(registry)
        registry_signature = sign_registry(
            registry_bytes=registry_raw,
            private_key_bytes=private_key_raw,
            public_key_bytes=public_key_raw,
            publisher=publisher,
        )
        write_exclusive(out_registry, registry_raw)
        try:
            write_exclusive(out_signature, registry_signature)
        except Exception:
            try:
                out_registry.unlink()
            except OSError:
                pass
            raise
    except BridgeError as exc:
        print(exc, file=sys.stderr)
        return 20
    print(
        json.dumps(
            {
                "bundle_sha256_by_run": {
                    f"{sample_id}:{profile_id}": bundle_sha256
                    for (sample_id, profile_id), bundle_sha256 in sorted(
                        bundle_sha256_by_run.items()
                    )
                },
                "out_registry": str(args.out_registry),
                "out_signature": str(args.out_signature),
                "status": "verified_registry_published",
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
