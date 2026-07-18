#!/usr/bin/env python3
"""Fail-closed metadata validator for the four-known-miss positive subscore contract.

This command reads JSON metadata only. It does not read package artifacts, collect evidence,
contact a lab host, start a VM, invoke hosted AI, or execute package code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any


CONTRACT_SCHEMA = "whoathere.four_known_miss_positive_subscore_contract.v1"
CONTRACT_ID = "four-prior-misses-positive-only-v1"
CONTRACT_CANONICALIZATION = "utf8-json-sort-keys-compact-no-nan-v1"
CONTRACT_SHA256 = "sha256:a47b8288c14c6c1eafb3976415fdc16a24ce0b85f06f4cf2c687ee50509ee053"
SOURCE_PROFILE_SCHEMA = "whoathere.known_miss_campaign_profile.v1"
SOURCE_PROFILE_ID = "four-prior-misses-v1"
SOURCE_PROFILE_SHA256 = "sha256:f8e45c1ccb191a1e621f474fb93151c6feca9b86fc4082948259019ed6e85179"
REPORT_SCHEMA = "whoathere.four_known_miss_positive_subscore_contract_validation.v1"

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

EXPECTED_TOP_LEVEL_FIELDS = {
    "schema",
    "contract_id",
    "contract_purpose",
    "canonicalization",
    "source_complete_run_profile_binding",
    "positive_profiles",
    "rows",
    "detection_policy",
    "claim_and_coverage_policy",
    "safety_policy",
    "evaluation_window_policy",
    "thresholds",
    "identity_policy",
}

EXPECTED_IDENTITY_FIELDS = [
    "contract_sha256",
    "artifact_profile_denominator_sha256",
    "source_revision",
    "runtime_sha256",
    "sensor_sha256",
    "verifier_executable_sha256",
    "verifier_public_key_sha256",
    "projection_schema_sha256",
    "prompt_set_sha256",
    "model_identity",
    "provider_adapter_sha256",
    "policy_sha256",
    "compiler_sha256",
    "publisher_sha256",
    "scorer_sha256",
    "scorer_id",
]

EXPECTED_ROWS: tuple[dict[str, str], ...] = (
    {
        "row_id": "mb-npm-sbx-45.0.2-positive",
        "sample_id": "mb-npm-sbx-45.0.2",
        "artifact_sha256": "sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933",
        "ecosystem": "npm",
        "artifact_form": "npm_tgz",
        "positive_profile_id": "npm-exact-lifecycle-ci-matrix-positive-v1",
        "source_complete_run_profile_id": "npm-exact-lifecycle-ci-matrix-v1",
        "source_complete_run_profile_sha256": "sha256:3f30cf9b63d205fc063108ff86765de30e7b83de83c924c2284a5a59b1d727ba",
        "behavior_label": "credential_env_access",
        "modality": "dynamic",
        "evidence_type": "environment_credential_read",
    },
    {
        "row_id": "mb-telnyx-4.87.1-wheel-positive",
        "sample_id": "mb-telnyx-4.87.1-wheel",
        "artifact_sha256": "sha256:7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9",
        "ecosystem": "pypi",
        "artifact_form": "wheel",
        "positive_profile_id": "pypi-exact-archive-static-capability-positive-v1",
        "source_complete_run_profile_id": "wheel-exact-complete-trigger-matrix-v1",
        "source_complete_run_profile_sha256": "sha256:9da59e60f1554b30b0fe4859ea9dd09712483d82f8472db789519212eb9c34d8",
        "behavior_label": "second_stage_fetch",
        "modality": "deterministic",
        "evidence_type": "download_execute_capability",
    },
    {
        "row_id": "mb-telnyx-4.87.2-wheel-positive",
        "sample_id": "mb-telnyx-4.87.2-wheel",
        "artifact_sha256": "sha256:cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3",
        "ecosystem": "pypi",
        "artifact_form": "wheel",
        "positive_profile_id": "pypi-exact-archive-static-capability-positive-v1",
        "source_complete_run_profile_id": "wheel-exact-complete-trigger-matrix-v1",
        "source_complete_run_profile_sha256": "sha256:d8c0689e15ca579b22f3754063d24b8db15e3e1ddc6f7ecc002356168e24338e",
        "behavior_label": "second_stage_fetch",
        "modality": "deterministic",
        "evidence_type": "download_execute_capability",
    },
    {
        "row_id": "mb-telnyx-4.87.2-sdist-positive",
        "sample_id": "mb-telnyx-4.87.2-sdist",
        "artifact_sha256": "sha256:a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5",
        "ecosystem": "pypi",
        "artifact_form": "sdist",
        "positive_profile_id": "pypi-exact-archive-static-capability-positive-v1",
        "source_complete_run_profile_id": "sdist-exact-build-derived-wheel-matrix-v1",
        "source_complete_run_profile_sha256": "sha256:3b4dfb4a33cc2b139b29c975430b44122a51370ecc87cfd95e9edffa814f4910",
        "behavior_label": "second_stage_fetch",
        "modality": "deterministic",
        "evidence_type": "download_execute_capability",
    },
)


class ValidationError(Exception):
    """The contract is not the reviewed R01 contract."""


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError("canonical_json_invalid") from exc


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def load_json(path: Path, label: str) -> Any:
    if not path.is_file():
        raise ValidationError(f"{label}_not_regular_file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{label}_invalid_json") from exc


def require_object(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(reason)
    return value


def require_exact_fields(value: dict[str, Any], expected: set[str], prefix: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise ValidationError(f"{prefix}_missing_fields:{','.join(missing)}")
    if unknown:
        raise ValidationError(f"{prefix}_unknown_fields:{','.join(unknown)}")


def validate_source_profile(path: Path, contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    source = require_object(load_json(path, "source_profile"), "source_profile_must_be_object")
    if sha256_file(path) != SOURCE_PROFILE_SHA256:
        raise ValidationError("source_profile_sha256_mismatch")
    if source.get("schema") != SOURCE_PROFILE_SCHEMA:
        raise ValidationError("source_profile_schema_mismatch")
    if source.get("campaign_profile_id") != SOURCE_PROFILE_ID:
        raise ValidationError("source_profile_id_mismatch")

    binding = require_object(
        contract.get("source_complete_run_profile_binding"),
        "source_complete_run_profile_binding_must_be_object",
    )
    if binding != {
        "campaign_profile_id": SOURCE_PROFILE_ID,
        "profile_file_sha256": SOURCE_PROFILE_SHA256,
    }:
        raise ValidationError("source_complete_run_profile_binding_mismatch")

    profiles = source.get("artifact_profiles")
    if not isinstance(profiles, list) or len(profiles) != 4:
        raise ValidationError("source_profile_requires_exactly_four_rows")
    by_sample: dict[str, dict[str, Any]] = {}
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("sample_id"), str):
            raise ValidationError("source_profile_row_invalid")
        sample_id = profile["sample_id"]
        if sample_id in by_sample:
            raise ValidationError(f"source_profile_duplicate_sample_id:{sample_id}")
        by_sample[sample_id] = profile
    return by_sample


def validate_positive_profiles(contract: dict[str, Any]) -> dict[str, dict[str, Any]]:
    profiles = contract.get("positive_profiles")
    if not isinstance(profiles, list) or len(profiles) != 2:
        raise ValidationError("positive_profiles_requires_exactly_two_profiles")
    by_id: dict[str, dict[str, Any]] = {}
    for profile in profiles:
        if not isinstance(profile, dict) or not isinstance(profile.get("profile_id"), str):
            raise ValidationError("positive_profile_invalid")
        profile_id = profile["profile_id"]
        if profile_id in by_id:
            raise ValidationError(f"positive_profile_duplicate:{profile_id}")
        evidence = profile.get("permitted_positive_evidence")
        if not isinstance(evidence, list) or len(evidence) != 1 or not isinstance(evidence[0], dict):
            raise ValidationError(f"positive_profile_evidence_invalid:{profile_id}")
        by_id[profile_id] = profile
    return by_id


def validate_rows(
    contract: dict[str, Any],
    source_by_sample: dict[str, dict[str, Any]],
    positive_profiles: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    rows = contract.get("rows")
    if not isinstance(rows, list) or len(rows) != 4:
        raise ValidationError("contract_requires_exactly_four_rows")
    if len({row.get("row_id") for row in rows if isinstance(row, dict)}) != 4:
        raise ValidationError("row_ids_must_be_unique")
    if len({row.get("sample_id") for row in rows if isinstance(row, dict)}) != 4:
        raise ValidationError("sample_ids_must_be_unique")
    if len({row.get("artifact_sha256") for row in rows if isinstance(row, dict)}) != 4:
        raise ValidationError("artifact_sha256_values_must_be_unique")

    summaries: list[dict[str, Any]] = []
    for index, (raw_row, expected) in enumerate(zip(rows, EXPECTED_ROWS, strict=True)):
        if not isinstance(raw_row, dict):
            raise ValidationError(f"rows[{index}]_must_be_object")
        if raw_row.get("expected_result") != "malicious":
            raise ValidationError(f"rows[{index}]_expected_result_must_be_malicious")
        for field in (
            "row_id",
            "sample_id",
            "artifact_sha256",
            "ecosystem",
            "artifact_form",
            "positive_profile_id",
            "source_complete_run_profile_id",
            "source_complete_run_profile_sha256",
        ):
            if raw_row.get(field) != expected[field]:
                raise ValidationError(f"rows[{index}]_{field}_sealed_value_mismatch")
        if raw_row.get("required_behavior_labels") != [expected["behavior_label"]]:
            raise ValidationError(f"rows[{index}]_required_behavior_labels_mismatch")
        if not SHA256_RE.fullmatch(str(raw_row.get("artifact_sha256", ""))):
            raise ValidationError(f"rows[{index}]_artifact_sha256_invalid")

        source = source_by_sample.get(expected["sample_id"])
        if source is None:
            raise ValidationError(f"rows[{index}]_source_sample_missing")
        execution_profile = source.get("execution_profile")
        if not isinstance(execution_profile, dict):
            raise ValidationError(f"rows[{index}]_source_execution_profile_invalid")
        source_values = {
            "artifact_sha256": source.get("artifact_sha256"),
            "ecosystem": source.get("ecosystem"),
            "artifact_form": execution_profile.get("artifact_kind"),
            "source_complete_run_profile_id": execution_profile.get("profile_id"),
            "source_complete_run_profile_sha256": source.get("execution_profile_sha256"),
        }
        for field, value in source_values.items():
            if raw_row.get(field) != value:
                raise ValidationError(f"rows[{index}]_{field}_source_profile_mismatch")

        positive_profile = positive_profiles.get(expected["positive_profile_id"])
        if positive_profile is None:
            raise ValidationError(f"rows[{index}]_positive_profile_missing")
        if expected["artifact_form"] not in positive_profile.get("artifact_forms", []):
            raise ValidationError(f"rows[{index}]_artifact_form_not_permitted")
        evidence = positive_profile["permitted_positive_evidence"][0]
        expected_evidence = {
            "behavior_label": expected["behavior_label"],
            "evidence_type": expected["evidence_type"],
            "modality": expected["modality"],
        }
        if evidence != expected_evidence:
            raise ValidationError(f"rows[{index}]_permitted_positive_evidence_mismatch")
        summaries.append(
            {
                "row_id": expected["row_id"],
                "sample_id": expected["sample_id"],
                "artifact_form": expected["artifact_form"],
                "positive_profile_id": expected["positive_profile_id"],
                "behavior_label": expected["behavior_label"],
                "modality": expected["modality"],
                "evidence_type": expected["evidence_type"],
            }
        )
    return summaries


def validate_contract(contract_path: Path, source_profile_path: Path) -> dict[str, Any]:
    contract = require_object(load_json(contract_path, "contract"), "contract_must_be_object")
    require_exact_fields(contract, EXPECTED_TOP_LEVEL_FIELDS, "contract")
    if contract.get("schema") != CONTRACT_SCHEMA:
        raise ValidationError("contract_schema_mismatch")
    if contract.get("contract_id") != CONTRACT_ID:
        raise ValidationError("contract_id_mismatch")
    if contract.get("contract_purpose") != "behavior_positive_detection_subscore_only":
        raise ValidationError("contract_purpose_mismatch")
    if contract.get("canonicalization") != CONTRACT_CANONICALIZATION:
        raise ValidationError("contract_canonicalization_mismatch")

    source_by_sample = validate_source_profile(source_profile_path, contract)
    positive_profiles = validate_positive_profiles(contract)
    row_summaries = validate_rows(contract, source_by_sample, positive_profiles)

    identity_policy = require_object(
        contract.get("identity_policy"), "identity_policy_must_be_object"
    )
    if identity_policy.get("required_identity_fields") != EXPECTED_IDENTITY_FIELDS:
        raise ValidationError("required_identity_fields_mismatch")

    contract_sha256 = sha256_bytes(canonical_json_bytes(contract))
    if contract_sha256 != CONTRACT_SHA256:
        raise ValidationError("contract_semantic_sha256_mismatch")
    denominator = {
        "positive_profiles": contract["positive_profiles"],
        "rows": contract["rows"],
    }
    denominator_sha256 = sha256_bytes(canonical_json_bytes(denominator))
    modalities = sorted({row["modality"] for row in row_summaries})
    return {
        "schema": REPORT_SCHEMA,
        "valid": True,
        "metadata_only": True,
        "contract_id": CONTRACT_ID,
        "contract_sha256": contract_sha256,
        "artifact_profile_denominator_sha256": denominator_sha256,
        "source_complete_run_profile_sha256": SOURCE_PROFILE_SHA256,
        "row_count": len(row_summaries),
        "required_behavior_positive_count": 4,
        "permitted_positive_modalities": modalities,
        "required_identity_fields": EXPECTED_IDENTITY_FIELDS,
        "rows": row_summaries,
        "claim_boundary": {
            "positive_only": True,
            "completion_quality_or_overall_pass": False,
            "observed_clean_admission_or_release": False,
            "full_corpus_baseline": False,
        },
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--contract", type=Path, required=True)
    parser.add_argument("--complete-run-profile", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = validate_contract(args.contract, args.complete_run_profile)
    except ValidationError as exc:
        print(f"validation_error={exc}", file=sys.stderr)
        return 64
    except FileNotFoundError as exc:
        print(f"validation_error=missing_file:{exc}", file=sys.stderr)
        return 64
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
