#!/usr/bin/env python3
"""Publish a fail-closed RunResultV2 from a signed independent projection bundle.

This command does not inspect package bytes. It accepts only evidence projections authenticated by
the verifier key frozen in EvaluationManifestV2, derives behavior labels itself, and never grants
release or clean authority.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


MANIFEST_SCHEMA = "whoathere.actual_malware.evaluation_manifest.v2"
BUNDLE_SCHEMA = "whoathere.actual_malware.verified_projection_bundle.v1"
RUN_RESULT_SCHEMA = "whoathere.actual_malware.run_result.v2"
CLAIM_BOUNDARY = (
    "Independent evidence projections only; no verdict, observed-clean, release, or admission authority."
)
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_SIGNATURE_BYTES = 1024

EVIDENCE_TYPE_TO_BEHAVIOR_LABEL = {
    "environment_credential_read": "credential_env_access",
    "https_exfiltration_attempt": "https_exfil",
    "download_execute_capability": "second_stage_fetch",
    "sensitive_file_exfiltration_capability": "sensitive_file_exfiltration",
    "second_stage_fetch_attempt": "second_stage_fetch",
    "ci_gate_activation": "ci_gated_activation",
}
TYPED_EVENT_EVIDENCE_TYPES = {
    "environment_credential_read",
    "https_exfiltration_attempt",
    "second_stage_fetch_attempt",
    "ci_gate_activation",
}
EVIDENCE_TYPE_ALLOWED_MODALITIES = {
    "environment_credential_read": {"dynamic"},
    "https_exfiltration_attempt": {"dynamic"},
    "download_execute_capability": {"deterministic"},
    "sensitive_file_exfiltration_capability": {"deterministic"},
    "second_stage_fetch_attempt": {"dynamic"},
    "ci_gate_activation": {"dynamic"},
}
STATIC_PROJECTION_POLICIES = {
    "static_download_execute_capability": (
        "download_execute_capability",
        "static_download_execute_projection",
    ),
    "static_sensitive_file_exfiltration_capability": (
        "sensitive_file_exfiltration_capability",
        "static_sensitive_file_exfiltration_projection",
    ),
}
ALLOWED_MODALITIES = {"deterministic", "scanner", "claude", "codex", "dynamic", "fused"}
ALLOWED_COVERAGE_STATES = {"complete", "incomplete", "unsupported", "infrastructure_error"}
ALLOWED_COMPLETION_GAPS = {
    "deterministic_coverage_incomplete",
    "dynamic_coverage_incomplete",
    "process_coverage_incomplete",
    "file_coverage_incomplete",
    "canary_coverage_incomplete",
    "network_coverage_incomplete",
    "scenario_coverage_incomplete",
    "independent_verifier_coverage_incomplete",
    "independent_verifier_unsupported_event",
    "infrastructure_error",
}
SAFETY_KEYS = {
    "network_policy",
    "host_package_execution_applied",
    "sync_back_applied",
    "live_c2_contacted",
    "live_second_stage_fetched",
    "restricted_material_leak",
    "teardown_verified",
}
RUN_FACT_KEYS = {
    "created_at_utc",
    "run_id",
    "evaluation_id",
    "evaluation_manifest_sha256",
    "corpus_sha256",
    "sample_id",
    "profile_id",
    "artifact_sha256",
    "execution_profile_sha256",
    "verifier_executable_sha256",
    "projection_schema_sha256",
    "ecosystem",
    "identities",
    "completion_state",
    "completion_gap_codes",
    "coverage",
    "safety",
}
BUNDLE_KEYS = {
    "schema",
    "verified_at_utc",
    "verifier_id",
    "verifier_executable_sha256",
    "projection_schema_sha256",
    "verifier_public_key_sha256",
    "verification_status",
    "run_fact",
    "projections",
    "claim_boundary",
}


class PublisherError(Exception):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise PublisherError(reason)


def object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise PublisherError("json_duplicate_key")
        value[key] = item
    return value


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


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
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 128
        and value[0].isalnum()
        and all(character.isalnum() or character in "_.:-" for character in value)
    )


def exact_keys(value: Any, expected: set[str], reason: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{reason}_not_object")
    actual = set(value)
    require(actual == expected, f"{reason}_keys_invalid")
    return value


def read_regular(path: Path, maximum: int, reason: str) -> bytes:
    require(path.is_absolute(), f"{reason}_path_not_absolute")
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise PublisherError(f"{reason}_unavailable") from exc
    require(stat.S_ISREG(metadata.st_mode) and not path.is_symlink(), f"{reason}_not_regular")
    require(0 < metadata.st_size <= maximum, f"{reason}_size_invalid")
    try:
        value = path.read_bytes()
    except OSError as exc:
        raise PublisherError(f"{reason}_unreadable") from exc
    require(len(value) == metadata.st_size, f"{reason}_size_changed")
    return value


def load_json_bytes(raw: bytes, reason: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=object_without_duplicates)
    except PublisherError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PublisherError(f"{reason}_invalid_json") from exc


def parse_utc(value: Any, reason: str) -> dt.datetime:
    require(isinstance(value, str) and value.endswith("Z"), reason)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise PublisherError(reason) from exc
    require(parsed.tzinfo is not None, reason)
    return parsed.astimezone(dt.timezone.utc)


def verify_signature(bundle_raw: bytes, public_key_raw: bytes, signature_raw: bytes) -> None:
    require(len(signature_raw) == 64, "projection_signature_size_invalid")
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl_missing")
    import tempfile

    with tempfile.TemporaryDirectory(prefix="whoathere-run-result-publisher-") as raw_tmp:
        temporary = Path(raw_tmp)
        bundle_path = temporary / "bundle.json"
        key_path = temporary / "public-key.pem"
        signature_path = temporary / "bundle.sig"
        bundle_path.write_bytes(bundle_raw)
        key_path.write_bytes(public_key_raw)
        signature_path.write_bytes(signature_raw)
        inspect = subprocess.run(
            [openssl, "pkey", "-pubin", "-in", str(key_path), "-text_pub", "-noout"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(inspect.returncode == 0 and b"ED25519" in inspect.stdout.upper(), "verifier_key_not_ed25519")
        verified = subprocess.run(
            [
                openssl,
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                str(key_path),
                "-sigfile",
                str(signature_path),
                "-in",
                str(bundle_path),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(verified.returncode == 0, "projection_signature_invalid")


def selected_run_slot(manifest: dict[str, Any], sample_id: str, profile_id: str) -> dict[str, Any]:
    require(manifest.get("schema") == MANIFEST_SCHEMA, "evaluation_manifest_schema_invalid")
    require(valid_identifier(manifest.get("evaluation_id")), "evaluation_id_invalid")
    require(valid_sha256(manifest.get("corpus_sha256")), "corpus_sha256_invalid")
    require(isinstance(manifest.get("identities"), dict), "manifest_identities_invalid")
    require(
        all(EVIDENCE_TYPE_ALLOWED_MODALITIES.get(key) for key in EVIDENCE_TYPE_TO_BEHAVIOR_LABEL),
        "evidence_type_modality_policy_missing",
    )
    require(
        all(
            modalities <= ALLOWED_MODALITIES
            for modalities in EVIDENCE_TYPE_ALLOWED_MODALITIES.values()
        ),
        "evidence_type_modality_policy_invalid",
    )
    registry = manifest.get("verified_evidence_registry")
    require(isinstance(registry, dict), "manifest_verified_registry_invalid")
    require(valid_identifier(registry.get("verifier_id")), "manifest_verifier_id_invalid")
    require(valid_sha256(registry.get("verifier_public_key_sha256")), "manifest_verifier_key_digest_invalid")
    require(
        valid_sha256(registry.get("verifier_executable_sha256")),
        "manifest_verifier_executable_digest_invalid",
    )
    require(
        valid_sha256(registry.get("projection_schema_sha256")),
        "manifest_projection_schema_digest_invalid",
    )
    window = manifest.get("evaluation_window")
    require(isinstance(window, dict), "evaluation_window_invalid")
    starts_at = parse_utc(window.get("starts_at_utc"), "evaluation_window_start_invalid")
    ends_at = parse_utc(window.get("ends_at_utc"), "evaluation_window_end_invalid")
    require(starts_at < ends_at, "evaluation_window_order_invalid")
    required_runs = manifest.get("required_runs")
    require(isinstance(required_runs, list), "manifest_required_runs_invalid")
    matches = [
        row
        for row in required_runs
        if isinstance(row, dict) and row.get("sample_id") == sample_id and row.get("profile_id") == profile_id
    ]
    require(len(matches) == 1, "manifest_run_slot_not_unique")
    slot = matches[0]
    for key in ("artifact_sha256", "execution_profile_sha256"):
        require(valid_sha256(slot.get(key)), f"manifest_run_slot_{key}_invalid")
    require(slot.get("ecosystem") in {"npm", "pypi"}, "manifest_run_slot_ecosystem_invalid")
    modalities = slot.get("required_modalities")
    require(
        isinstance(modalities, list)
        and modalities
        and len(modalities) == len(set(modalities))
        and all(item in ALLOWED_MODALITIES for item in modalities),
        "manifest_run_slot_modalities_invalid",
    )
    return slot


def validate_coverage(value: Any, required_modalities: set[str]) -> list[dict[str, Any]]:
    require(isinstance(value, list) and value, "projection_coverage_invalid")
    by_modality: dict[str, dict[str, Any]] = {}
    for row in value:
        row = exact_keys(row, {"modality", "state", "evidence_sha256"}, "projection_coverage_row")
        modality = row.get("modality")
        require(modality in ALLOWED_MODALITIES and modality not in by_modality, "projection_coverage_modality_invalid")
        require(row.get("state") in ALLOWED_COVERAGE_STATES, "projection_coverage_state_invalid")
        require(valid_sha256(row.get("evidence_sha256")), "projection_coverage_digest_invalid")
        by_modality[str(modality)] = dict(row)
    require(required_modalities <= set(by_modality), "projection_required_modality_missing")
    return [by_modality[key] for key in sorted(by_modality)]


def validate_safety(value: Any) -> dict[str, Any]:
    safety = exact_keys(value, SAFETY_KEYS, "projection_safety")
    require(safety.get("network_policy") == "sinkhole_only", "projection_network_policy_invalid")
    for key in SAFETY_KEYS - {"network_policy"}:
        require(isinstance(safety.get(key), bool), f"projection_safety_{key}_invalid")
    return dict(safety)


def validate_range(value: Any) -> str:
    require(isinstance(value, dict), "static_citation_range_invalid")
    kind = value.get("kind")
    if kind == "bytes":
        exact_keys(value, {"kind", "start_byte", "end_byte"}, "static_citation_range")
        start = value.get("start_byte")
        end = value.get("end_byte")
        require(
            isinstance(start, int)
            and not isinstance(start, bool)
            and isinstance(end, int)
            and not isinstance(end, bool)
            and 0 <= start < end,
            "static_citation_range_invalid",
        )
        return f"bytes:{start}:{end}"
    if kind == "lines":
        exact_keys(
            value,
            {"kind", "start_line", "end_line", "start_byte", "end_byte"},
            "static_citation_range",
        )
        start_line = value.get("start_line")
        end_line = value.get("end_line")
        start = value.get("start_byte")
        end = value.get("end_byte")
        require(
            all(isinstance(item, int) and not isinstance(item, bool) for item in (start_line, end_line, start, end))
            and 1 <= start_line <= end_line
            and 0 <= start < end,
            "static_citation_range_invalid",
        )
        return f"lines:{start_line}:{end_line}:{start}:{end}"
    raise PublisherError("static_citation_range_invalid")


def observation_id(projection: dict[str, Any]) -> str:
    return "observation-" + hashlib.sha256(canonical_json_bytes(projection)).hexdigest()


def project_observations(
    value: Any,
    *,
    artifact_sha256: str,
    coverage_modalities: set[str],
) -> list[dict[str, Any]]:
    require(isinstance(value, list), "verified_projections_invalid")
    observations: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_source_events: set[tuple[str, str]] = set()
    seen_static_sources: set[tuple[str, str]] = set()
    for projection in value:
        require(isinstance(projection, dict), "verified_projection_not_object")
        kind = projection.get("kind")
        if kind == "typed_event":
            projection = exact_keys(
                projection,
                {"kind", "event_id", "modality", "evidence_type", "event_sha256", "source_receipt_sha256"},
                "typed_event_projection",
            )
            require(valid_identifier(projection.get("event_id")), "typed_event_id_invalid")
            modality = projection.get("modality")
            evidence_type = projection.get("evidence_type")
            require(evidence_type in TYPED_EVENT_EVIDENCE_TYPES, "typed_event_evidence_type_unmapped")
            allowed_modalities = EVIDENCE_TYPE_ALLOWED_MODALITIES.get(str(evidence_type))
            require(bool(allowed_modalities), "evidence_type_modality_policy_missing")
            require(
                modality in allowed_modalities and modality in coverage_modalities,
                "typed_event_modality_invalid",
            )
            require(valid_sha256(projection.get("event_sha256")), "typed_event_digest_invalid")
            require(valid_sha256(projection.get("source_receipt_sha256")), "typed_event_receipt_digest_invalid")
            source_event = (
                str(projection["source_receipt_sha256"]),
                str(projection["event_id"]),
            )
            require(source_event not in seen_source_events, "typed_event_source_identity_duplicate")
            seen_source_events.add(source_event)
            identifier = observation_id(projection)
            evidence_ref = (
                f"signed-event:{projection['event_id']}#"
                f"{str(projection['source_receipt_sha256']).removeprefix('sha256:')}"
            )
            evidence_sha256 = projection["event_sha256"]
        elif isinstance(kind, str) and kind in STATIC_PROJECTION_POLICIES:
            evidence_type, projection_context = STATIC_PROJECTION_POLICIES[kind]
            projection = exact_keys(
                projection,
                {
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
                },
                projection_context,
            )
            require(projection.get("artifact_sha256") == artifact_sha256, "static_projection_artifact_mismatch")
            for key in (
                "artifact_manifest_sha256",
                "exact_observation_sha256",
                "finding_evidence_sha256",
                "file_id",
                "file_sha256",
                "selected_bytes_sha256",
                "source_receipt_sha256",
            ):
                require(valid_sha256(projection.get(key)), f"static_projection_{key}_invalid")
            require("deterministic" in coverage_modalities, "static_projection_coverage_missing")
            range_ref = validate_range(projection.get("range"))
            static_source = (
                str(projection["source_receipt_sha256"]),
                str(projection["exact_observation_sha256"]),
            )
            require(static_source not in seen_static_sources, "static_projection_source_identity_duplicate")
            seen_static_sources.add(static_source)
            identifier = observation_id(projection)
            modality = "deterministic"
            require(
                modality in EVIDENCE_TYPE_ALLOWED_MODALITIES[evidence_type],
                "static_projection_modality_policy_invalid",
            )
            evidence_ref = (
                "verified-static:"
                f"{str(projection['artifact_manifest_sha256']).removeprefix('sha256:')}#"
                f"{str(projection['file_id']).removeprefix('sha256:')}:{range_ref}@"
                f"{str(projection['source_receipt_sha256']).removeprefix('sha256:')}"
            )
            evidence_sha256 = projection["exact_observation_sha256"]
        else:
            raise PublisherError("verified_projection_kind_unmapped")
        require(identifier not in seen_ids, "verified_projection_duplicate")
        seen_ids.add(identifier)
        projection_sha256 = sha256_bytes(canonical_json_bytes(projection))
        observations.append(
            {
                "observation_id": identifier,
                "modality": modality,
                "evidence_type": evidence_type,
                "behavior_label": EVIDENCE_TYPE_TO_BEHAVIOR_LABEL[evidence_type],
                "evidence_ref": evidence_ref,
                "evidence_sha256": evidence_sha256,
                "projection_sha256": projection_sha256,
            }
        )
    return sorted(observations, key=lambda item: item["observation_id"])


def publish(
    *,
    manifest_path: Path,
    expected_manifest_sha256: str,
    sample_id: str,
    profile_id: str,
    bundle_path: Path,
    signature_path: Path,
    public_key_path: Path,
) -> dict[str, Any]:
    require(valid_sha256(expected_manifest_sha256), "expected_manifest_sha256_invalid")
    require(valid_identifier(sample_id), "sample_id_invalid")
    require(valid_identifier(profile_id), "profile_id_invalid")
    manifest_raw = read_regular(manifest_path, MAX_MANIFEST_BYTES, "evaluation_manifest")
    require(sha256_bytes(manifest_raw) == expected_manifest_sha256, "evaluation_manifest_digest_mismatch")
    manifest = load_json_bytes(manifest_raw, "evaluation_manifest")
    require(isinstance(manifest, dict), "evaluation_manifest_not_object")
    slot = selected_run_slot(manifest, sample_id, profile_id)

    public_key_raw = read_regular(public_key_path, MAX_KEY_BYTES, "verifier_public_key")
    signature_raw = read_regular(signature_path, MAX_SIGNATURE_BYTES, "projection_signature")
    registry = manifest["verified_evidence_registry"]
    public_key_sha256 = sha256_bytes(public_key_raw)
    require(public_key_sha256 == registry["verifier_public_key_sha256"], "verifier_public_key_digest_mismatch")

    bundle_raw = read_regular(bundle_path, MAX_BUNDLE_BYTES, "verified_projection_bundle")
    bundle = load_json_bytes(bundle_raw, "verified_projection_bundle")
    require(canonical_json_bytes(bundle) == bundle_raw, "verified_projection_bundle_not_canonical")
    verify_signature(bundle_raw, public_key_raw, signature_raw)
    bundle = exact_keys(bundle, BUNDLE_KEYS, "verified_projection_bundle")
    require(bundle.get("schema") == BUNDLE_SCHEMA, "verified_projection_bundle_schema_invalid")
    require(bundle.get("verification_status") == "verified", "projection_verification_status_invalid")
    require(bundle.get("claim_boundary") == CLAIM_BOUNDARY, "projection_claim_boundary_invalid")
    require(bundle.get("verifier_id") == registry["verifier_id"], "projection_verifier_id_mismatch")
    require(
        bundle.get("verifier_executable_sha256") == registry["verifier_executable_sha256"],
        "projection_verifier_executable_digest_mismatch",
    )
    require(
        bundle.get("projection_schema_sha256") == registry["projection_schema_sha256"],
        "projection_schema_digest_mismatch",
    )
    require(bundle.get("verifier_public_key_sha256") == public_key_sha256, "projection_verifier_key_digest_mismatch")
    verified_at = parse_utc(bundle.get("verified_at_utc"), "projection_verified_at_invalid")

    run_fact = exact_keys(bundle.get("run_fact"), RUN_FACT_KEYS, "verified_run_fact")
    expected_bindings = {
        "evaluation_id": manifest["evaluation_id"],
        "evaluation_manifest_sha256": expected_manifest_sha256,
        "corpus_sha256": manifest["corpus_sha256"],
        "sample_id": sample_id,
        "profile_id": profile_id,
        "artifact_sha256": slot["artifact_sha256"],
        "execution_profile_sha256": slot["execution_profile_sha256"],
        "verifier_executable_sha256": registry["verifier_executable_sha256"],
        "projection_schema_sha256": registry["projection_schema_sha256"],
        "ecosystem": slot["ecosystem"],
        "identities": manifest["identities"],
    }
    for key, expected in expected_bindings.items():
        require(run_fact.get(key) == expected, f"verified_run_fact_{key}_mismatch")
    require(valid_identifier(run_fact.get("run_id")), "verified_run_fact_run_id_invalid")
    created_at = parse_utc(run_fact.get("created_at_utc"), "verified_run_fact_created_at_invalid")
    starts_at = parse_utc(manifest["evaluation_window"]["starts_at_utc"], "evaluation_window_start_invalid")
    ends_at = parse_utc(manifest["evaluation_window"]["ends_at_utc"], "evaluation_window_end_invalid")
    require(starts_at <= created_at <= verified_at <= ends_at, "verified_projection_timestamp_order_invalid")

    completion_state = run_fact.get("completion_state")
    require(completion_state in ALLOWED_COVERAGE_STATES, "verified_run_fact_completion_state_invalid")
    gaps = run_fact.get("completion_gap_codes")
    require(
        isinstance(gaps, list)
        and len(gaps) == len(set(gaps))
        and all(item in ALLOWED_COMPLETION_GAPS for item in gaps),
        "verified_run_fact_completion_gaps_invalid",
    )
    require(
        (completion_state == "complete" and not gaps) or (completion_state != "complete" and bool(gaps)),
        "verified_run_fact_completion_gap_state_mismatch",
    )
    required_modalities = set(slot["required_modalities"])
    coverage = validate_coverage(run_fact.get("coverage"), required_modalities)
    if completion_state == "complete":
        require(
            all(row["state"] == "complete" for row in coverage if row["modality"] in required_modalities),
            "verified_complete_run_has_incomplete_required_modality",
        )
    safety = validate_safety(run_fact.get("safety"))
    observations = project_observations(
        bundle.get("projections"),
        artifact_sha256=slot["artifact_sha256"],
        coverage_modalities={row["modality"] for row in coverage},
    )

    return {
        "schema": RUN_RESULT_SCHEMA,
        "created_at_utc": run_fact["created_at_utc"],
        "run_id": run_fact["run_id"],
        "evaluation_id": run_fact["evaluation_id"],
        "evaluation_manifest_sha256": run_fact["evaluation_manifest_sha256"],
        "corpus_sha256": run_fact["corpus_sha256"],
        "sample_id": run_fact["sample_id"],
        "profile_id": run_fact["profile_id"],
        "artifact_sha256": run_fact["artifact_sha256"],
        "execution_profile_sha256": run_fact["execution_profile_sha256"],
        "verifier_executable_sha256": run_fact["verifier_executable_sha256"],
        "projection_schema_sha256": run_fact["projection_schema_sha256"],
        "ecosystem": run_fact["ecosystem"],
        "identities": run_fact["identities"],
        "completion_state": completion_state,
        "completion_reason_codes": sorted(gaps),
        "coverage": coverage,
        "observations": observations,
        "safety": safety,
        "admission": {
            "artifact_release_applied": False,
            "manual_review_required": True,
        },
    }


def write_new(path: Path, value: dict[str, Any]) -> None:
    require(path.is_absolute(), "output_path_not_absolute")
    require(path.parent.is_dir(), "output_parent_missing")
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise PublisherError("output_create_failed") from exc
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--evaluation-manifest", type=Path, required=True)
    result.add_argument("--expected-evaluation-manifest-sha256", required=True)
    result.add_argument("--sample-id", required=True)
    result.add_argument("--profile-id", required=True)
    result.add_argument("--verified-projection-bundle", type=Path, required=True)
    result.add_argument("--verified-projection-signature", type=Path, required=True)
    result.add_argument("--verifier-public-key", type=Path, required=True)
    result.add_argument("--out", type=Path, required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        result = publish(
            manifest_path=args.evaluation_manifest.expanduser().absolute(),
            expected_manifest_sha256=args.expected_evaluation_manifest_sha256,
            sample_id=args.sample_id,
            profile_id=args.profile_id,
            bundle_path=args.verified_projection_bundle.expanduser().absolute(),
            signature_path=args.verified_projection_signature.expanduser().absolute(),
            public_key_path=args.verifier_public_key.expanduser().absolute(),
        )
        write_new(args.out.expanduser().absolute(), result)
    except PublisherError as exc:
        print(exc, file=sys.stderr)
        return 20
    print(json.dumps({"status": "published_manual_review_only", "out": str(args.out)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
