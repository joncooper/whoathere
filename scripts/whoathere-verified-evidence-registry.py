#!/usr/bin/env python3
"""Produce or independently verify an EvaluationManifestV2 evidence registry.

This command never executes package code and never generates cryptographic keys. Production
requires an operator-pinned receipt/event verifier implementing the closed protocol below. The
registry is not generated when that verifier, any source binding, or any cryptographic operation
is unavailable.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
EVALUATOR_PATH = REPO_ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"

INDEX_SCHEMA = "whoathere.actual_malware.evidence_verification_index.v1"
REQUEST_SCHEMA = "whoathere.actual_malware.evidence_verifier_request.v1"
RESPONSE_SCHEMA = "whoathere.actual_malware.evidence_verifier_response.v1"
REGISTRY_SCHEMA = "whoathere.actual_malware.verified_evidence_registry.v1"
RUN_FACT_SCHEMA = "whoathere.actual_malware.run_fact_projection.v1"
VERIFIER_PROTOCOL = "whoathere-independent-receipt-event-verifier-v1"

MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_CORPUS_BYTES = 32 * 1024 * 1024
MAX_RESULTS_BYTES = 32 * 1024 * 1024
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_VERIFIER_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_KEY_BYTES = 1024 * 1024

SOURCE_AUTHENTICATION = {
    "guest_root_receipt": "ed25519_signature_and_expected_bindings",
    "host_composite_receipt": "ed25519_signature_and_expected_bindings",
    "modality_receipt": "cryptographic_signature_and_expected_bindings",
    "run_fact_receipt": "cryptographic_signature_and_expected_bindings",
    "host_composite_evidence": "receipt_digest_binding",
    "process_evidence": "signed_receipt_digest_binding",
    "file_evidence": "signed_receipt_digest_binding",
    "network_evidence": "signed_receipt_digest_binding",
    "typed_event": "signed_receipt_event_binding",
    "guest_evidence_public_key": "public_key_used",
    "host_evidence_public_key": "public_key_used",
    "modality_public_key": "public_key_used",
    "expected_bindings": "expected_bindings_consumed",
}
SIGNED_RECEIPT_ROLES = {
    "guest_root_receipt",
    "host_composite_receipt",
    "modality_receipt",
    "run_fact_receipt",
}
DYNAMIC_REQUIRED_ROLES = {
    "guest_root_receipt",
    "host_composite_evidence",
    "host_composite_receipt",
    "guest_evidence_public_key",
    "host_evidence_public_key",
    "expected_bindings",
}
REQUIRED_RESPONSE_KEYS = {
    "schema",
    "verifier_id",
    "verifier_executable_sha256",
    "request_sha256",
    "sample_id",
    "profile_id",
    "artifact_sha256",
    "verified_at_utc",
    "verification_status",
    "sources",
    "run_fact",
    "observations",
    "claim_boundary",
}


class RegistryError(Exception):
    """A fail-closed registry production or verification error."""

    def __init__(self, reason_code: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code
        self.context = context or {}


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def valid_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def valid_identifier(value: Any) -> bool:
    if not isinstance(value, str) or not 1 <= len(value) <= 128:
        return False
    return value[0].isalnum() and all(character.isalnum() or character in "_.:-" for character in value)


def canonical_json_bytes(value: Any, *, newline: bool = False) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return encoded + (b"\n" if newline else b"")


def parse_utc(value: Any, reason: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise RegistryError(reason)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise RegistryError(reason) from exc
    if parsed.tzinfo is None:
        raise RegistryError(reason)
    return parsed.astimezone(dt.timezone.utc)


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def reject_symlink(path: Path, reason: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as exc:
        raise RegistryError(reason) from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise RegistryError(reason)


def read_regular_file(path: Path, maximum_bytes: int, reason_prefix: str) -> bytes:
    reject_symlink(path, f"{reason_prefix}_symlink_forbidden")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise RegistryError(f"{reason_prefix}_open_failed") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RegistryError(f"{reason_prefix}_not_regular_file")
        if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
            raise RegistryError(f"{reason_prefix}_size_invalid")
        chunks: list[bytes] = []
        remaining = metadata.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RegistryError(f"{reason_prefix}_short_read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RegistryError(f"{reason_prefix}_changed_during_read")
        after = os.fstat(descriptor)
        if (metadata.st_dev, metadata.st_ino, metadata.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise RegistryError(f"{reason_prefix}_changed_during_read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def load_json_bytes(payload: bytes, reason: str) -> Any:
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RegistryError(reason) from exc


def load_json_file(path: Path, maximum_bytes: int, reason_prefix: str) -> tuple[Any, bytes]:
    payload = read_regular_file(path, maximum_bytes, reason_prefix)
    return load_json_bytes(payload, f"{reason_prefix}_json_invalid"), payload


def load_jsonl_bytes(payload: bytes, reason_prefix: str) -> list[dict[str, Any]]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RegistryError(f"{reason_prefix}_utf8_invalid") from exc
    rows: list[dict[str, Any]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        try:
            row = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise RegistryError(
                f"{reason_prefix}_json_invalid", context={"line": line_number}
            ) from exc
        if not isinstance(row, dict):
            raise RegistryError(f"{reason_prefix}_row_not_object", context={"line": line_number})
        rows.append(row)
    return rows


def require_exact_keys(value: Any, keys: set[str], reason_prefix: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RegistryError(f"{reason_prefix}_not_object")
    actual = set(value)
    if actual != keys:
        raise RegistryError(
            f"{reason_prefix}_fields_invalid",
            context={"missing_field_count": len(keys - actual), "extra_field_count": len(actual - keys)},
        )
    return value


def load_evaluator() -> Any:
    spec = importlib.util.spec_from_file_location("whoathere_actual_malware_evaluation", EVALUATOR_PATH)
    if spec is None or spec.loader is None:
        raise RegistryError("evaluation_contract_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_corpus_rows(evaluator: Any, rows: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    by_id: dict[str, dict[str, Any]] = {}
    errors: list[str] = []
    for index, row in enumerate(rows):
        row_errors = evaluator.validate_corpus_row(row)
        errors.extend(f"row_{index + 1}:{error}" for error in row_errors)
        sample_id = row.get("sample_id")
        if isinstance(sample_id, str):
            if sample_id in by_id:
                errors.append(f"duplicate_sample_id:{sample_id}")
            else:
                by_id[sample_id] = row
    if not rows:
        errors.append("corpus_empty")
    if errors:
        raise RegistryError("corpus_validation_failed", context={"error_count": len(errors)})
    return by_id


def validate_campaign_inputs(
    *,
    corpus_bytes: bytes,
    manifest: Any,
    manifest_bytes: bytes,
    results_bytes: bytes,
    expected_manifest_sha256: str,
) -> tuple[Any, dict[str, dict[str, Any]], dict[tuple[str, str], dict[str, Any]], list[dict[str, Any]]]:
    evaluator = load_evaluator()
    manifest_sha256 = sha256_bytes(manifest_bytes)
    corpus_sha256 = sha256_bytes(corpus_bytes)
    if manifest_sha256 != expected_manifest_sha256:
        raise RegistryError("evaluation_manifest_out_of_band_digest_mismatch")
    corpus_rows = load_jsonl_bytes(corpus_bytes, "corpus")
    corpus = validate_corpus_rows(evaluator, corpus_rows)
    errors, required_runs, _ = evaluator.validate_evaluation_manifest_v2(
        manifest,
        corpus,
        corpus_sha256,
    )
    if errors:
        raise RegistryError("evaluation_manifest_validation_failed", context={"error_count": len(errors)})
    results = load_jsonl_bytes(results_bytes, "results")
    rows_by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    run_ids: set[str] = set()
    for row in results:
        key = (row.get("sample_id"), row.get("profile_id"))
        if not all(isinstance(item, str) for item in key):
            raise RegistryError("result_sample_profile_invalid")
        rows_by_key.setdefault((str(key[0]), str(key[1])), []).append(row)
        run_id = row.get("run_id")
        if not isinstance(run_id, str) or run_id in run_ids:
            raise RegistryError("result_run_id_missing_or_duplicate")
        run_ids.add(run_id)
    expected = set(required_runs)
    actual = set(rows_by_key)
    if expected - actual:
        raise RegistryError("manifest_denominator_result_missing", context={"missing_count": len(expected - actual)})
    if actual - expected:
        raise RegistryError("manifest_denominator_result_unknown", context={"unknown_count": len(actual - expected)})
    if any(len(rows_by_key[key]) != 1 for key in expected):
        raise RegistryError("manifest_denominator_result_duplicate")
    if len(results) != len(expected):
        raise RegistryError("manifest_denominator_result_count_mismatch")
    ordered = [rows_by_key[key][0] for key in sorted(expected)]
    for row in ordered:
        if row.get("evaluation_id") != manifest.get("evaluation_id"):
            raise RegistryError("result_evaluation_id_mismatch")
        if row.get("evaluation_manifest_sha256") != manifest_sha256:
            raise RegistryError("result_manifest_digest_mismatch")
        if row.get("corpus_sha256") != corpus_sha256:
            raise RegistryError("result_corpus_digest_mismatch")
        required = required_runs[(str(row["sample_id"]), str(row["profile_id"]))]
        for key in ("artifact_sha256", "ecosystem"):
            if row.get(key) != required.get(key):
                raise RegistryError(f"result_{key}_mismatch")
    return evaluator, corpus, required_runs, ordered


def run_fact_projection_sha256(result: dict[str, Any]) -> str:
    coverage = result.get("coverage")
    sorted_coverage = (
        sorted(coverage, key=lambda item: str(item.get("modality")))
        if isinstance(coverage, list) and all(isinstance(item, dict) for item in coverage)
        else coverage
    )
    projection = {
        "schema": RUN_FACT_SCHEMA,
        "run_result_schema": result.get("schema"),
        "created_at_utc": result.get("created_at_utc"),
        "run_id": result.get("run_id"),
        "evaluation_id": result.get("evaluation_id"),
        "evaluation_manifest_sha256": result.get("evaluation_manifest_sha256"),
        "corpus_sha256": result.get("corpus_sha256"),
        "sample_id": result.get("sample_id"),
        "profile_id": result.get("profile_id"),
        "artifact_sha256": result.get("artifact_sha256"),
        "ecosystem": result.get("ecosystem"),
        "identities": result.get("identities"),
        "completion_state": result.get("completion_state"),
        "completion_reason_codes": result.get("completion_reason_codes"),
        "coverage": sorted_coverage,
        "safety": result.get("safety"),
        "admission": result.get("admission"),
    }
    return sha256_bytes(canonical_json_bytes(projection))


def safe_relative_source(root: Path, relative: Any, source_id: str) -> Path:
    if not isinstance(relative, str) or not relative or len(relative) > 1024:
        raise RegistryError("evidence_source_relative_path_invalid", context={"source_id": source_id})
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise RegistryError("evidence_source_relative_path_invalid", context={"source_id": source_id})
    current = root
    for part in pure.parts:
        current = current / part
        reject_symlink(current, "evidence_source_symlink_forbidden")
    try:
        current.relative_to(root)
    except ValueError as exc:
        raise RegistryError("evidence_source_outside_evidence_root") from exc
    return current


def validate_and_measure_index(
    *,
    index: Any,
    evidence_root: Path,
    manifest: dict[str, Any],
    manifest_sha256: str,
    corpus_sha256: str,
    results_sha256: str,
    required_runs: dict[tuple[str, str], dict[str, Any]],
    results: list[dict[str, Any]],
    verifier_id: str,
    verifier_sha256: str,
) -> dict[tuple[str, str], dict[str, Any]]:
    require_exact_keys(
        index,
        {
            "schema",
            "evaluation_id",
            "evaluation_manifest_sha256",
            "corpus_sha256",
            "results_sha256",
            "verifier_id",
            "verifier_protocol",
            "verifier_executable_sha256",
            "runs",
        },
        "verification_index",
    )
    expected_top = {
        "schema": INDEX_SCHEMA,
        "evaluation_id": manifest.get("evaluation_id"),
        "evaluation_manifest_sha256": manifest_sha256,
        "corpus_sha256": corpus_sha256,
        "results_sha256": results_sha256,
        "verifier_id": verifier_id,
        "verifier_protocol": VERIFIER_PROTOCOL,
        "verifier_executable_sha256": verifier_sha256,
    }
    for key, expected in expected_top.items():
        if index.get(key) != expected:
            raise RegistryError(f"verification_index_{key}_mismatch")
    run_rows = index.get("runs")
    if not isinstance(run_rows, list):
        raise RegistryError("verification_index_runs_not_array")
    index_by_key: dict[tuple[str, str], dict[str, Any]] = {}
    result_by_key = {(row["sample_id"], row["profile_id"]): row for row in results}
    for run_index, run in enumerate(run_rows):
        require_exact_keys(
            run,
            {
                "sample_id",
                "profile_id",
                "artifact_sha256",
                "run_fact_source_receipt_id",
                "sources",
                "observation_sources",
            },
            "verification_index_run",
        )
        key = (run.get("sample_id"), run.get("profile_id"))
        if not all(isinstance(item, str) for item in key):
            raise RegistryError("verification_index_run_key_invalid", context={"run_index": run_index})
        normalized_key = (str(key[0]), str(key[1]))
        if normalized_key in index_by_key:
            raise RegistryError("verification_index_run_duplicate")
        required = required_runs.get(normalized_key)
        result = result_by_key.get(normalized_key)
        if required is None or result is None:
            raise RegistryError("verification_index_run_unknown")
        if run.get("artifact_sha256") != required.get("artifact_sha256"):
            raise RegistryError("verification_index_artifact_sha256_mismatch")
        sources = run.get("sources")
        if not isinstance(sources, list) or not sources:
            raise RegistryError("verification_index_sources_empty")
        source_by_id: dict[str, dict[str, Any]] = {}
        roles: set[str] = set()
        for source in sources:
            require_exact_keys(
                source,
                {"source_id", "role", "relative_path", "byte_length", "sha256"},
                "verification_index_source",
            )
            source_id = source.get("source_id")
            role = source.get("role")
            if not valid_identifier(source_id) or source_id in source_by_id:
                raise RegistryError("verification_index_source_id_invalid_or_duplicate")
            if role not in SOURCE_AUTHENTICATION:
                raise RegistryError("verification_index_source_role_invalid", context={"source_id": source_id})
            byte_length = source.get("byte_length")
            if not isinstance(byte_length, int) or isinstance(byte_length, bool) or not 0 < byte_length <= MAX_SOURCE_BYTES:
                raise RegistryError("verification_index_source_byte_length_invalid", context={"source_id": source_id})
            if not valid_sha256(source.get("sha256")):
                raise RegistryError("verification_index_source_sha256_invalid", context={"source_id": source_id})
            path = safe_relative_source(evidence_root, source.get("relative_path"), str(source_id))
            payload = read_regular_file(path, min(MAX_SOURCE_BYTES, byte_length), "evidence_source")
            if len(payload) != byte_length:
                raise RegistryError("evidence_source_byte_length_mismatch", context={"source_id": source_id})
            if sha256_bytes(payload) != source["sha256"]:
                raise RegistryError("evidence_source_sha256_mismatch", context={"source_id": source_id})
            measured = dict(source)
            measured["absolute_path"] = str(path)
            measured["authentication"] = SOURCE_AUTHENTICATION[str(role)]
            source_by_id[str(source_id)] = measured
            roles.add(str(role))
        observations = result.get("observations")
        if not isinstance(observations, list):
            raise RegistryError("result_observations_not_array")
        observation_by_id: dict[str, dict[str, Any]] = {}
        for observation in observations:
            if not isinstance(observation, dict) or not valid_identifier(observation.get("observation_id")):
                raise RegistryError("result_observation_id_invalid")
            observation_id = str(observation["observation_id"])
            if observation_id in observation_by_id:
                raise RegistryError("result_observation_id_duplicate")
            observation_by_id[observation_id] = observation
        mappings = run.get("observation_sources")
        if not isinstance(mappings, list):
            raise RegistryError("verification_index_observation_sources_not_array")
        mapping_by_observation: dict[str, dict[str, Any]] = {}
        for mapping in mappings:
            require_exact_keys(
                mapping,
                {"observation_id", "event_source_id", "source_receipt_id"},
                "verification_index_observation_source",
            )
            observation_id = mapping.get("observation_id")
            if not isinstance(observation_id, str) or observation_id in mapping_by_observation:
                raise RegistryError("verification_index_observation_mapping_duplicate_or_invalid")
            observation = observation_by_id.get(observation_id)
            event = source_by_id.get(str(mapping.get("event_source_id")))
            receipt = source_by_id.get(str(mapping.get("source_receipt_id")))
            if observation is None:
                raise RegistryError("verification_index_observation_mapping_unknown")
            if event is None or event.get("role") != "typed_event":
                raise RegistryError("verification_index_observation_event_source_invalid")
            if receipt is None or receipt.get("role") not in SIGNED_RECEIPT_ROLES:
                raise RegistryError("verification_index_observation_receipt_source_invalid")
            if event.get("sha256") != observation.get("evidence_sha256"):
                raise RegistryError("verification_index_observation_event_digest_mismatch")
            mapping_by_observation[observation_id] = mapping
        if set(mapping_by_observation) != set(observation_by_id):
            raise RegistryError(
                "verification_index_observation_denominator_mismatch",
                context={
                    "missing_count": len(set(observation_by_id) - set(mapping_by_observation)),
                    "unknown_count": len(set(mapping_by_observation) - set(observation_by_id)),
                },
            )
        run_fact_receipt_id = run.get("run_fact_source_receipt_id")
        run_fact_receipt = source_by_id.get(str(run_fact_receipt_id))
        if run_fact_receipt is None or run_fact_receipt.get("role") not in SIGNED_RECEIPT_ROLES:
            raise RegistryError("verification_index_run_fact_receipt_invalid")
        required_modalities = set(required.get("required_modalities", []))
        has_dynamic = "dynamic" in required_modalities or any(
            observation.get("modality") == "dynamic" for observation in observations
        )
        if has_dynamic:
            missing_roles = DYNAMIC_REQUIRED_ROLES - roles
            if missing_roles:
                raise RegistryError(
                    "independent_dynamic_receipt_verification_inputs_missing",
                    context={"missing_role_count": len(missing_roles)},
                )
            if run_fact_receipt.get("role") != "host_composite_receipt":
                raise RegistryError("dynamic_run_fact_requires_host_composite_receipt")
        index_by_key[normalized_key] = {
            "source_by_id": source_by_id,
            "mapping_by_observation": mapping_by_observation,
            "run_fact_source_receipt_id": run_fact_receipt_id,
        }
    expected_keys = set(required_runs)
    actual_keys = set(index_by_key)
    if expected_keys - actual_keys:
        raise RegistryError("manifest_denominator_verification_index_missing")
    if actual_keys - expected_keys:
        raise RegistryError("manifest_denominator_verification_index_unknown")
    if len(run_rows) != len(expected_keys):
        raise RegistryError("manifest_denominator_verification_index_count_mismatch")
    return index_by_key


def verifier_request(
    *,
    manifest: dict[str, Any],
    manifest_sha256: str,
    corpus_sha256: str,
    result: dict[str, Any],
    required_run: dict[str, Any],
    run_index: dict[str, Any],
    verifier_id: str,
    verifier_sha256: str,
) -> dict[str, Any]:
    sources = []
    for source_id, source in sorted(run_index["source_by_id"].items()):
        sources.append(
            {
                "source_id": source_id,
                "role": source["role"],
                "path": source["absolute_path"],
                "byte_length": source["byte_length"],
                "sha256": source["sha256"],
                "required_authentication": source["authentication"],
            }
        )
    mappings = [
        dict(mapping)
        for _, mapping in sorted(run_index["mapping_by_observation"].items())
    ]
    return {
        "schema": REQUEST_SCHEMA,
        "verifier_protocol": VERIFIER_PROTOCOL,
        "verifier_id": verifier_id,
        "verifier_executable_sha256": verifier_sha256,
        "evaluation_id": manifest["evaluation_id"],
        "evaluation_manifest_sha256": manifest_sha256,
        "corpus_sha256": corpus_sha256,
        "identities": manifest["identities"],
        "sample_id": result["sample_id"],
        "profile_id": result["profile_id"],
        "artifact_sha256": result["artifact_sha256"],
        "required_modalities": sorted(required_run.get("required_modalities", [])),
        "run_fact_projection_sha256": run_fact_projection_sha256(result),
        "run_result": result,
        "run_fact_source_receipt_id": run_index["run_fact_source_receipt_id"],
        "sources": sources,
        "observation_sources": mappings,
        "claim_boundary": (
            "Corpus labels, expected results, family names, package reputation, and producer verdicts "
            "are intentionally absent. The verifier must derive each typed observation from the exact "
            "event and cryptographically verified receipt chain."
        ),
    }


def run_verifier(
    *,
    verifier_bytes: bytes,
    request: dict[str, Any],
    timeout_seconds: int,
) -> tuple[dict[str, Any], bytes]:
    request_bytes = canonical_json_bytes(request)
    with tempfile.TemporaryDirectory(prefix="whoathere-registry-verifier-") as raw_tmp:
        temporary = Path(raw_tmp)
        request_path = temporary / "request.json"
        response_path = temporary / "response.json"
        verifier_path = temporary / "verifier"
        verifier_descriptor = os.open(
            verifier_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o500,
        )
        try:
            os.write(verifier_descriptor, verifier_bytes)
            os.fsync(verifier_descriptor)
        finally:
            os.close(verifier_descriptor)
        descriptor = os.open(request_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, request_bytes)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        environment = {
            "HOME": str(temporary / "empty-home"),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
            "TMPDIR": str(temporary),
            "TZ": "UTC",
        }
        (temporary / "empty-home").mkdir(mode=0o700)
        try:
            process = subprocess.Popen(
                [str(verifier_path), "--request", str(request_path), "--response", str(response_path)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=environment,
                start_new_session=True,
            )
            try:
                stdout, stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired as exc:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise RegistryError("independent_verifier_timeout") from exc
        except OSError as exc:
            raise RegistryError("independent_verifier_execution_failed") from exc
        if process.returncode != 0:
            raise RegistryError(
                "independent_verifier_rejected_evidence",
                context={
                    "exit_code": process.returncode,
                    "stdout_sha256": sha256_bytes(stdout),
                    "stderr_sha256": sha256_bytes(stderr),
                },
            )
        if stdout or stderr:
            raise RegistryError(
                "independent_verifier_output_channel_not_empty",
                context={
                    "stdout_sha256": sha256_bytes(stdout),
                    "stderr_sha256": sha256_bytes(stderr),
                },
            )
        response_bytes = read_regular_file(
            response_path,
            MAX_VERIFIER_RESPONSE_BYTES,
            "independent_verifier_response",
        )
        response = load_json_bytes(response_bytes, "independent_verifier_response_json_invalid")
        if canonical_json_bytes(response) != response_bytes:
            raise RegistryError("independent_verifier_response_noncanonical")
        return response, response_bytes


def validate_verifier_response(
    *,
    response: Any,
    response_bytes: bytes,
    request: dict[str, Any],
    result: dict[str, Any],
    run_index: dict[str, Any],
    verifier_id: str,
    verifier_sha256: str,
    manifest: dict[str, Any],
    registry_created_at: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    response = require_exact_keys(response, REQUIRED_RESPONSE_KEYS, "independent_verifier_response")
    expected = {
        "schema": RESPONSE_SCHEMA,
        "verifier_id": verifier_id,
        "verifier_executable_sha256": verifier_sha256,
        "request_sha256": sha256_bytes(canonical_json_bytes(request)),
        "sample_id": result["sample_id"],
        "profile_id": result["profile_id"],
        "artifact_sha256": result["artifact_sha256"],
        "verification_status": "verified",
    }
    for key, value in expected.items():
        if response.get(key) != value:
            raise RegistryError(f"independent_verifier_response_{key}_mismatch")
    claim_boundary = response.get("claim_boundary")
    if claim_boundary != (
        "Receipt signatures, expected bindings, event digests, and run facts verified; no verdict or admission authority."
    ):
        raise RegistryError("independent_verifier_response_claim_boundary_invalid")
    verified_at = parse_utc(response.get("verified_at_utc"), "independent_verifier_verified_at_invalid")
    created_at = parse_utc(registry_created_at, "registry_created_at_invalid")
    starts_at = parse_utc(manifest["evaluation_window"]["starts_at_utc"], "evaluation_window_start_invalid")
    ends_at = parse_utc(manifest["evaluation_window"]["ends_at_utc"], "evaluation_window_end_invalid")
    if not starts_at <= verified_at <= created_at <= ends_at:
        raise RegistryError("independent_verifier_timestamp_outside_registry_window")

    expected_sources = run_index["source_by_id"]
    response_sources = response.get("sources")
    if not isinstance(response_sources, list):
        raise RegistryError("independent_verifier_sources_not_array")
    by_id: dict[str, dict[str, Any]] = {}
    source_keys = {
        "source_id",
        "role",
        "byte_length",
        "sha256",
        "authentication",
        "verification_status",
    }
    for source in response_sources:
        require_exact_keys(source, source_keys, "independent_verifier_source")
        source_id = source.get("source_id")
        if not isinstance(source_id, str) or source_id in by_id:
            raise RegistryError("independent_verifier_source_duplicate_or_invalid")
        expected_source = expected_sources.get(source_id)
        if expected_source is None:
            raise RegistryError("independent_verifier_source_unknown")
        expected_projection = {
            "source_id": source_id,
            "role": expected_source["role"],
            "byte_length": expected_source["byte_length"],
            "sha256": expected_source["sha256"],
            "authentication": expected_source["authentication"],
            "verification_status": "verified",
        }
        if source != expected_projection:
            raise RegistryError("independent_verifier_source_binding_mismatch")
        by_id[source_id] = source
    if set(by_id) != set(expected_sources):
        raise RegistryError("independent_verifier_source_denominator_mismatch")

    run_fact = require_exact_keys(
        response.get("run_fact"),
        {
            "observed_at_utc",
            "run_fact_projection_sha256",
            "source_receipt_id",
            "source_receipt_sha256",
            "authentication",
        },
        "independent_verifier_run_fact",
    )
    run_fact_source_id = run_index["run_fact_source_receipt_id"]
    run_fact_source = expected_sources[run_fact_source_id]
    if run_fact != {
        "observed_at_utc": result.get("created_at_utc"),
        "run_fact_projection_sha256": run_fact_projection_sha256(result),
        "source_receipt_id": run_fact_source_id,
        "source_receipt_sha256": run_fact_source["sha256"],
        "authentication": "verified_from_signed_receipts",
    }:
        raise RegistryError("independent_verifier_run_fact_binding_mismatch")
    parse_utc(run_fact["observed_at_utc"], "independent_verifier_run_fact_observed_at_invalid")

    observations = result.get("observations", [])
    observation_by_id = {row["observation_id"]: row for row in observations}
    response_observations = response.get("observations")
    if not isinstance(response_observations, list):
        raise RegistryError("independent_verifier_observations_not_array")
    response_by_id: dict[str, dict[str, Any]] = {}
    observation_keys = {
        "observation_id",
        "observed_at_utc",
        "modality",
        "evidence_type",
        "behavior_label",
        "evidence_ref",
        "evidence_sha256",
        "event_source_id",
        "source_receipt_id",
        "source_receipt_sha256",
        "authentication",
    }
    for verified in response_observations:
        require_exact_keys(verified, observation_keys, "independent_verifier_observation")
        observation_id = verified.get("observation_id")
        if not isinstance(observation_id, str) or observation_id in response_by_id:
            raise RegistryError("independent_verifier_observation_duplicate_or_invalid")
        observation = observation_by_id.get(observation_id)
        mapping = run_index["mapping_by_observation"].get(observation_id)
        if observation is None or mapping is None:
            raise RegistryError("independent_verifier_observation_unknown")
        receipt = expected_sources[mapping["source_receipt_id"]]
        expected_observation = {
            "observation_id": observation_id,
            "observed_at_utc": verified.get("observed_at_utc"),
            "modality": observation.get("modality"),
            "evidence_type": observation.get("evidence_type"),
            "behavior_label": observation.get("behavior_label"),
            "evidence_ref": observation.get("evidence_ref"),
            "evidence_sha256": observation.get("evidence_sha256"),
            "event_source_id": mapping["event_source_id"],
            "source_receipt_id": mapping["source_receipt_id"],
            "source_receipt_sha256": receipt["sha256"],
            "authentication": "typed_event_derived_from_verified_receipt",
        }
        if verified != expected_observation:
            raise RegistryError("independent_verifier_observation_binding_mismatch")
        observed_at = parse_utc(verified["observed_at_utc"], "independent_verifier_observation_time_invalid")
        result_at = parse_utc(result.get("created_at_utc"), "result_created_at_invalid")
        if not starts_at <= observed_at <= result_at <= verified_at:
            raise RegistryError("independent_verifier_observation_timestamp_order_invalid")
        response_by_id[observation_id] = verified
    if set(response_by_id) != set(observation_by_id):
        raise RegistryError("independent_verifier_observation_denominator_mismatch")

    verification_receipt_sha256 = sha256_bytes(response_bytes)
    run_record = {
        "record_id": record_id("run-fact", result["sample_id"], result["profile_id"]),
        "sample_id": result["sample_id"],
        "profile_id": result["profile_id"],
        "artifact_sha256": result["artifact_sha256"],
        "observed_at_utc": run_fact["observed_at_utc"],
        "verified_at_utc": response["verified_at_utc"],
        "run_fact_projection_sha256": run_fact["run_fact_projection_sha256"],
        "source_receipt_sha256": run_fact["source_receipt_sha256"],
        "verification_receipt_sha256": verification_receipt_sha256,
        "verification_method": verifier_id,
        "verification_status": "verified",
    }
    evidence_records: list[dict[str, Any]] = []
    for observation_id, verified in sorted(response_by_id.items()):
        if verified["behavior_label"] is None:
            continue
        evidence_records.append(
            {
                "record_id": record_id(
                    "evidence",
                    result["sample_id"],
                    result["profile_id"],
                    observation_id,
                    verified["evidence_sha256"],
                ),
                "sample_id": result["sample_id"],
                "profile_id": result["profile_id"],
                "artifact_sha256": result["artifact_sha256"],
                "observed_at_utc": verified["observed_at_utc"],
                "verified_at_utc": response["verified_at_utc"],
                "modality": verified["modality"],
                "evidence_type": verified["evidence_type"],
                "behavior_label": verified["behavior_label"],
                "evidence_ref": verified["evidence_ref"],
                "evidence_sha256": verified["evidence_sha256"],
                "source_receipt_sha256": verified["source_receipt_sha256"],
                "verification_receipt_sha256": verification_receipt_sha256,
                "verification_method": verifier_id,
                "verification_status": "verified",
            }
        )
    return run_record, evidence_records


def record_id(prefix: str, *values: str) -> str:
    digest = hashlib.sha256("\0".join(values).encode("utf-8")).hexdigest()[:32]
    return f"{prefix}-{digest}"


def measure_regular_executable(path: Path, expected_sha256: str) -> tuple[str, bytes]:
    if not path.is_absolute():
        raise RegistryError("independent_verifier_path_must_be_absolute")
    payload = read_regular_file(path, 512 * 1024 * 1024, "independent_verifier_executable")
    metadata = path.stat()
    if metadata.st_mode & 0o111 == 0:
        raise RegistryError("independent_verifier_not_executable")
    measured = sha256_bytes(payload)
    if measured != expected_sha256:
        raise RegistryError("independent_verifier_out_of_band_digest_mismatch")
    return measured, payload


def check_private_key(path: Path, evidence_root: Path) -> None:
    if not path.is_absolute():
        raise RegistryError("registry_private_key_path_must_be_absolute")
    reject_symlink(path, "registry_private_key_symlink_forbidden")
    metadata = path.stat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size <= 0 or metadata.st_size > MAX_KEY_BYTES:
        raise RegistryError("registry_private_key_file_invalid")
    if metadata.st_uid != os.getuid():
        raise RegistryError("registry_private_key_owner_invalid")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise RegistryError("registry_private_key_permissions_too_broad")
    try:
        path.resolve(strict=True).relative_to(evidence_root.resolve(strict=True))
    except ValueError:
        return
    raise RegistryError("registry_private_key_under_evidence_root_forbidden")


def openssl_path() -> str:
    executable = shutil.which("openssl")
    if executable is None:
        raise RegistryError("openssl_unavailable")
    return executable


def public_key_der(openssl: str, path: Path, *, private: bool) -> bytes:
    arguments = [openssl, "pkey", "-in", str(path), "-pubout", "-outform", "DER"]
    if not private:
        arguments.insert(2, "-pubin")
    result = subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0 or not result.stdout:
        raise RegistryError("ed25519_public_key_derivation_failed")
    return result.stdout


def verify_key_pair(
    *,
    private_key: Path,
    public_key: Path,
    evidence_root: Path,
    expected_public_key_sha256: str,
) -> tuple[str, str]:
    check_private_key(private_key, evidence_root)
    public_bytes = read_regular_file(public_key, MAX_KEY_BYTES, "registry_public_key")
    public_digest = sha256_bytes(public_bytes)
    if public_digest != expected_public_key_sha256:
        raise RegistryError("registry_public_key_out_of_band_digest_mismatch")
    openssl = openssl_path()
    inspection = subprocess.run(
        [openssl, "pkey", "-pubin", "-in", str(public_key), "-text_pub", "-noout"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if inspection.returncode != 0 or b"ED25519" not in inspection.stdout.upper():
        raise RegistryError("registry_public_key_not_ed25519")
    private_der = public_key_der(openssl, private_key, private=True)
    public_der = public_key_der(openssl, public_key, private=False)
    if private_der != public_der:
        raise RegistryError("registry_private_public_key_mismatch")
    return openssl, public_digest


def sign_registry(openssl: str, private_key: Path, registry_bytes: bytes) -> bytes:
    with tempfile.TemporaryDirectory(prefix="whoathere-registry-sign-") as raw_tmp:
        temporary = Path(raw_tmp)
        input_path = temporary / "registry.json"
        signature_path = temporary / "registry.sig"
        descriptor = os.open(input_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(descriptor, registry_bytes)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        result = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(private_key),
                "-in",
                str(input_path),
                "-out",
                str(signature_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if result.returncode != 0 or result.stdout:
            raise RegistryError("registry_ed25519_signing_failed")
        signature = read_regular_file(signature_path, 64, "registry_signature")
    if len(signature) != 64:
        raise RegistryError("registry_signature_not_raw_ed25519")
    return signature


def prepare_output(path: Path, payload: bytes, mode: int) -> Path:
    if path.exists() or path.is_symlink():
        raise RegistryError("registry_output_already_exists")
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise RegistryError("registry_output_write_failed")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return temporary


def publish_outputs(outputs: list[tuple[Path, bytes, int]]) -> None:
    prepared: list[tuple[Path, Path]] = []
    published: list[Path] = []
    try:
        for destination, payload, mode in outputs:
            prepared.append((prepare_output(destination, payload, mode), destination))
        for temporary, destination in prepared:
            try:
                os.link(temporary, destination)
            except FileExistsError as exc:
                raise RegistryError("registry_output_already_exists") from exc
            published.append(destination)
        for directory in sorted({destination.parent for _, destination in prepared}, key=str):
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except Exception:
        for destination in published:
            try:
                destination.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        for temporary, _ in prepared:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def verify_registry_bundle(
    *,
    corpus_path: Path,
    manifest_path: Path,
    results_path: Path,
    registry_path: Path,
    public_key_path: Path,
    signature_path: Path,
    expected_manifest_sha256: str,
    expected_public_key_sha256: str,
) -> dict[str, Any]:
    manifest, manifest_bytes = load_json_file(manifest_path, MAX_MANIFEST_BYTES, "evaluation_manifest")
    corpus_bytes = read_regular_file(corpus_path, MAX_CORPUS_BYTES, "corpus")
    results_bytes = read_regular_file(results_path, MAX_RESULTS_BYTES, "results")
    evaluator, _, required_runs, results = validate_campaign_inputs(
        corpus_bytes=corpus_bytes,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        results_bytes=results_bytes,
        expected_manifest_sha256=expected_manifest_sha256,
    )
    public_key_bytes = read_regular_file(public_key_path, MAX_KEY_BYTES, "registry_public_key")
    if sha256_bytes(public_key_bytes) != expected_public_key_sha256:
        raise RegistryError("registry_public_key_out_of_band_digest_mismatch")
    registry, registry_bytes = load_json_file(registry_path, MAX_RESULTS_BYTES, "verified_registry")
    signature_bytes = read_regular_file(signature_path, 64, "verified_registry_signature")
    signature_errors = evaluator.verify_ed25519_registry_signature(
        registry_bytes,
        public_key_bytes,
        signature_bytes,
        expected_public_key_sha256,
    )
    if signature_errors:
        raise RegistryError("verified_registry_signature_invalid", context={"error_count": len(signature_errors)})
    manifest_sha256 = sha256_bytes(manifest_bytes)
    corpus_sha256 = sha256_bytes(corpus_bytes)
    registry_errors, records, run_facts, registry_created_at = evaluator.validate_verified_evidence_registry_v1(
        registry,
        manifest,
        manifest_sha256,
        corpus_sha256,
        required_runs,
    )
    if registry_errors:
        raise RegistryError("verified_registry_contract_invalid", context={"error_count": len(registry_errors)})
    result_by_key = {(row["sample_id"], row["profile_id"]): row for row in results}
    result_errors: list[str] = []
    for key in sorted(required_runs):
        errors, _ = evaluator.validate_run_result_v2(
            result_by_key[key],
            required_runs[key],
            manifest,
            manifest_sha256,
            corpus_sha256,
            records,
            run_facts,
            registry_created_at,
        )
        result_errors.extend(errors)
    if result_errors:
        raise RegistryError("verified_registry_result_binding_invalid", context={"error_count": len(result_errors)})
    return {
        "schema": "whoathere.actual_malware.verified_evidence_registry.digest_report.v1",
        "status": "verified",
        "evaluation_manifest_sha256": manifest_sha256,
        "corpus_sha256": corpus_sha256,
        "results_sha256": sha256_bytes(results_bytes),
        "verifier_public_key_sha256": sha256_bytes(public_key_bytes),
        "verified_evidence_registry_sha256": sha256_bytes(registry_bytes),
        "verified_evidence_signature_sha256": sha256_bytes(signature_bytes),
        "required_run_count": len(required_runs),
        "verified_run_fact_count": len(run_facts),
        "verified_behavior_record_count": len(records),
        "claim_boundary": (
            "This verifies exact bindings and authentication only. Detection and safety claims require "
            "the separately pinned EvaluationManifestV2 scorer."
        ),
    }


def command_produce(args: argparse.Namespace) -> dict[str, Any]:
    if args.verifier_command is None:
        raise RegistryError(
            "independent_receipt_event_verifier_unavailable",
            context={"required_verifier_protocol": VERIFIER_PROTOCOL},
        )
    if not valid_sha256(args.expected_evaluation_manifest_sha256):
        raise RegistryError("expected_evaluation_manifest_sha256_invalid")
    if not valid_sha256(args.expected_verifier_public_key_sha256):
        raise RegistryError("expected_verifier_public_key_sha256_invalid")
    if not valid_sha256(args.expected_verifier_command_sha256):
        raise RegistryError("expected_verifier_command_sha256_invalid")
    evidence_root = args.evidence_root
    reject_symlink(evidence_root, "evidence_root_symlink_forbidden")
    if not evidence_root.is_dir():
        raise RegistryError("evidence_root_not_directory")
    verifier_sha256, verifier_bytes = measure_regular_executable(
        args.verifier_command,
        args.expected_verifier_command_sha256,
    )
    manifest, manifest_bytes = load_json_file(
        args.evaluation_manifest,
        MAX_MANIFEST_BYTES,
        "evaluation_manifest",
    )
    corpus_bytes = read_regular_file(args.corpus, MAX_CORPUS_BYTES, "corpus")
    results_bytes = read_regular_file(args.results, MAX_RESULTS_BYTES, "results")
    evaluator, _, required_runs, results = validate_campaign_inputs(
        corpus_bytes=corpus_bytes,
        manifest=manifest,
        manifest_bytes=manifest_bytes,
        results_bytes=results_bytes,
        expected_manifest_sha256=args.expected_evaluation_manifest_sha256,
    )
    del evaluator
    manifest_sha256 = sha256_bytes(manifest_bytes)
    corpus_sha256 = sha256_bytes(corpus_bytes)
    results_sha256 = sha256_bytes(results_bytes)
    expected_registry = manifest.get("verified_evidence_registry")
    if not isinstance(expected_registry, dict):
        raise RegistryError("evaluation_manifest_verified_registry_missing")
    verifier_id = expected_registry.get("verifier_id")
    if not valid_identifier(verifier_id):
        raise RegistryError("evaluation_manifest_verifier_id_invalid")
    if expected_registry.get("verifier_public_key_sha256") != args.expected_verifier_public_key_sha256:
        raise RegistryError("evaluation_manifest_public_key_out_of_band_digest_mismatch")
    index, index_bytes = load_json_file(args.verification_index, MAX_INDEX_BYTES, "verification_index")
    index_by_key = validate_and_measure_index(
        index=index,
        evidence_root=evidence_root,
        manifest=manifest,
        manifest_sha256=manifest_sha256,
        corpus_sha256=corpus_sha256,
        results_sha256=results_sha256,
        required_runs=required_runs,
        results=results,
        verifier_id=str(verifier_id),
        verifier_sha256=verifier_sha256,
    )
    openssl, public_key_sha256 = verify_key_pair(
        private_key=args.private_key,
        public_key=args.public_key,
        evidence_root=evidence_root,
        expected_public_key_sha256=args.expected_verifier_public_key_sha256,
    )
    created_at = args.created_at_utc or utc_now()
    created_time = parse_utc(created_at, "registry_created_at_invalid")
    starts_at = parse_utc(manifest["evaluation_window"]["starts_at_utc"], "evaluation_window_start_invalid")
    ends_at = parse_utc(manifest["evaluation_window"]["ends_at_utc"], "evaluation_window_end_invalid")
    if not starts_at <= created_time <= ends_at:
        raise RegistryError("registry_created_at_outside_evaluation_window")
    run_fact_records: list[dict[str, Any]] = []
    evidence_records: list[dict[str, Any]] = []
    for result in results:
        key = (result["sample_id"], result["profile_id"])
        request = verifier_request(
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            corpus_sha256=corpus_sha256,
            result=result,
            required_run=required_runs[key],
            run_index=index_by_key[key],
            verifier_id=str(verifier_id),
            verifier_sha256=verifier_sha256,
        )
        response, response_bytes = run_verifier(
            verifier_bytes=verifier_bytes,
            request=request,
            timeout_seconds=args.verifier_timeout_seconds,
        )
        run_record, records = validate_verifier_response(
            response=response,
            response_bytes=response_bytes,
            request=request,
            result=result,
            run_index=index_by_key[key],
            verifier_id=str(verifier_id),
            verifier_sha256=verifier_sha256,
            manifest=manifest,
            registry_created_at=created_at,
        )
        run_fact_records.append(run_record)
        evidence_records.extend(records)
    registry = {
        "schema": REGISTRY_SCHEMA,
        "registry_id": expected_registry["registry_id"],
        "created_at_utc": created_at,
        "evaluation_id": manifest["evaluation_id"],
        "evaluation_manifest_sha256": manifest_sha256,
        "corpus_sha256": corpus_sha256,
        "identities": manifest["identities"],
        "verifier_id": verifier_id,
        "verifier_public_key_sha256": public_key_sha256,
        "run_fact_records": sorted(
            run_fact_records,
            key=lambda row: (row["sample_id"], row["profile_id"]),
        ),
        "records": sorted(
            evidence_records,
            key=lambda row: (
                row["sample_id"],
                row["profile_id"],
                row["modality"],
                row["evidence_type"],
                row["evidence_ref"],
            ),
        ),
    }
    registry_bytes = canonical_json_bytes(registry, newline=True)
    signature = sign_registry(openssl, args.private_key, registry_bytes)
    with tempfile.TemporaryDirectory(prefix="whoathere-registry-prepublish-") as raw_tmp:
        temporary = Path(raw_tmp)
        temporary_registry = temporary / "registry.json"
        temporary_signature = temporary / "registry.sig"
        temporary_registry.write_bytes(registry_bytes)
        temporary_signature.write_bytes(signature)
        report = verify_registry_bundle(
            corpus_path=args.corpus,
            manifest_path=args.evaluation_manifest,
            results_path=args.results,
            registry_path=temporary_registry,
            public_key_path=args.public_key,
            signature_path=temporary_signature,
            expected_manifest_sha256=args.expected_evaluation_manifest_sha256,
            expected_public_key_sha256=args.expected_verifier_public_key_sha256,
        )
    publish_outputs(
        [
            (args.registry_out, registry_bytes, 0o600),
            (args.signature_out, signature, 0o600),
        ]
    )
    report.update(
        {
            "status": "generated_and_verified",
            "verification_index_sha256": sha256_bytes(index_bytes),
            "verifier_executable_sha256": verifier_sha256,
        }
    )
    return report


def command_verify_only(args: argparse.Namespace) -> dict[str, Any]:
    if not valid_sha256(args.expected_evaluation_manifest_sha256):
        raise RegistryError("expected_evaluation_manifest_sha256_invalid")
    if not valid_sha256(args.expected_verifier_public_key_sha256):
        raise RegistryError("expected_verifier_public_key_sha256_invalid")
    return verify_registry_bundle(
        corpus_path=args.corpus,
        manifest_path=args.evaluation_manifest,
        results_path=args.results,
        registry_path=args.registry,
        public_key_path=args.public_key,
        signature_path=args.signature,
        expected_manifest_sha256=args.expected_evaluation_manifest_sha256,
        expected_public_key_sha256=args.expected_verifier_public_key_sha256,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    produce = subparsers.add_parser("produce")
    produce.add_argument("--corpus", type=Path, required=True)
    produce.add_argument("--evaluation-manifest", type=Path, required=True)
    produce.add_argument("--results", type=Path, required=True)
    produce.add_argument("--verification-index", type=Path, required=True)
    produce.add_argument("--evidence-root", type=Path, required=True)
    produce.add_argument("--verifier-command", type=Path)
    produce.add_argument("--expected-verifier-command-sha256", required=True)
    produce.add_argument("--private-key", type=Path, required=True)
    produce.add_argument("--public-key", type=Path, required=True)
    produce.add_argument("--expected-evaluation-manifest-sha256", required=True)
    produce.add_argument("--expected-verifier-public-key-sha256", required=True)
    produce.add_argument("--registry-out", type=Path, required=True)
    produce.add_argument("--signature-out", type=Path, required=True)
    produce.add_argument("--created-at-utc")
    produce.add_argument("--verifier-timeout-seconds", type=int, default=60)
    produce.set_defaults(func=command_produce)

    verify = subparsers.add_parser("verify-only")
    verify.add_argument("--corpus", type=Path, required=True)
    verify.add_argument("--evaluation-manifest", type=Path, required=True)
    verify.add_argument("--results", type=Path, required=True)
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--signature", type=Path, required=True)
    verify.add_argument("--expected-evaluation-manifest-sha256", required=True)
    verify.add_argument("--expected-verifier-public-key-sha256", required=True)
    verify.set_defaults(func=command_verify_only)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if getattr(args, "verifier_timeout_seconds", 1) <= 0:
            raise RegistryError("verifier_timeout_seconds_invalid")
        report = args.func(args)
    except RegistryError as exc:
        diagnostic = {
            "schema": "whoathere.actual_malware.verified_evidence_registry.status.v1",
            "status": "not_generated" if args.command == "produce" else "verification_failed",
            "reason_code": exc.reason_code,
            **exc.context,
        }
        print(json.dumps(diagnostic, sort_keys=True), file=sys.stderr)
        return 64
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
