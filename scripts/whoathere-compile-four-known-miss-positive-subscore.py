#!/usr/bin/env python3
"""Compile the frozen four-known-miss positive contract into an EvaluationManifestV2 carrier.

This command is metadata-only. It validates tracked contracts and corpus metadata, but never reads
package artifacts, evidence, credentials, or lab state and never invokes a package, VM, network, or
AI provider. Final executable and provider identities are intentionally frozen by R02b, not here.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_VALIDATOR_PATH = (
    ROOT / "scripts" / "whoathere-validate-four-known-miss-positive-subscore-contract.py"
)
EVALUATOR_PATH = ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"
DEFAULT_CONTRACT = (
    ROOT
    / "docs"
    / "product-build-run"
    / "four-known-miss-positive-subscore-contract.v2.json"
)
DEFAULT_COMPLETE_PROFILE = (
    ROOT / "docs" / "product-build-run" / "four-known-miss-campaign-profile.v1.json"
)

MANIFEST_SCHEMA = "whoathere.actual_malware.evaluation_manifest.v2"
MANIFEST_CARRIER_CLASS = "known_regression"
SCORER_ID = "whoathere-actual-malware-evaluation.py:score-results-v2"
COHORT_ID = "four-prior-misses-positive-only"
COHORT_DESCRIPTION = (
    "R01 positive-only four-prior-miss subscore; exact permitted evidence "
    "is enforced by the dedicated subscore summary."
)
COMPILE_REPORT_SCHEMA = "whoathere.four_known_miss_positive_subscore_compile_report.v1"
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class CompileError(Exception):
    """A stable fail-closed metadata compilation error."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise CompileError(reason)


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"{name}_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - only local installation failures reach this.
        raise CompileError(f"{name}_module_unavailable") from exc
    return module


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
        raise CompileError("canonical_json_invalid") from exc


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_json(path: Path, reason: str) -> Any:
    require(path.is_file(), f"{reason}_not_regular_file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CompileError(f"{reason}_invalid_json") from exc


def parse_utc(value: Any, reason: str) -> dt.datetime:
    require(isinstance(value, str) and value.endswith("Z"), reason)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise CompileError(reason) from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), reason)
    return parsed


def require_identifier(value: Any, reason: str) -> str:
    require(isinstance(value, str) and IDENTIFIER_RE.fullmatch(value) is not None, reason)
    return value


def require_sha256(value: Any, reason: str) -> str:
    require(isinstance(value, str) and SHA256_RE.fullmatch(value) is not None, reason)
    return value


def read_corpus(
    path: Path, evaluator: ModuleType
) -> tuple[dict[str, dict[str, Any]], str]:
    try:
        rows = evaluator.read_jsonl(path)
        corpus_sha256 = evaluator.sha256_file(path)
    except Exception as exc:
        raise CompileError("corpus_unreadable") from exc
    require(rows, "corpus_empty")
    by_sample: dict[str, dict[str, Any]] = {}
    seen_artifacts: set[str] = set()
    for row in rows:
        errors = evaluator.validate_corpus_row(row)
        if errors:
            raise CompileError(f"corpus_invalid:{errors[0]}")
        sample_id = str(row["sample_id"])
        artifact_sha256 = str(row["artifact_sha256"])
        require(sample_id not in by_sample, f"corpus_duplicate_sample_id:{sample_id}")
        require(
            artifact_sha256 not in seen_artifacts,
            f"corpus_duplicate_artifact_sha256:{artifact_sha256}",
        )
        by_sample[sample_id] = row
        seen_artifacts.add(artifact_sha256)
    return by_sample, corpus_sha256


def validate_contract_and_source(
    contract_path: Path,
    complete_profile_path: Path,
    validator: ModuleType,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    try:
        report = validator.validate_contract(contract_path, complete_profile_path)
    except Exception as exc:
        raise CompileError(f"positive_subscore_contract_invalid:{exc}") from exc
    contract = load_json(contract_path, "positive_subscore_contract")
    complete_profile = load_json(complete_profile_path, "complete_run_profile")
    require(isinstance(contract, dict), "positive_subscore_contract_not_object")
    require(isinstance(complete_profile, dict), "complete_run_profile_not_object")
    return contract, complete_profile, report


def build_required_runs(
    contract: dict[str, Any],
    complete_profile: dict[str, Any],
    corpus_by_sample: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    positive_profiles_raw = contract.get("positive_profiles")
    rows = contract.get("rows")
    source_profiles_raw = complete_profile.get("artifact_profiles")
    require(isinstance(positive_profiles_raw, list), "positive_profiles_invalid")
    require(isinstance(rows, list) and len(rows) == 4, "positive_rows_invalid")
    require(isinstance(source_profiles_raw, list), "complete_profile_rows_invalid")
    positive_profiles = {
        str(profile.get("profile_id")): profile
        for profile in positive_profiles_raw
        if isinstance(profile, dict)
    }
    source_profiles = {
        str(profile.get("sample_id")): profile
        for profile in source_profiles_raw
        if isinstance(profile, dict)
    }
    require(len(positive_profiles) == len(positive_profiles_raw), "positive_profile_ids_invalid")
    require(len(source_profiles) == len(source_profiles_raw), "source_profile_ids_invalid")

    profile_sha256_by_id = {
        profile_id: sha256_bytes(canonical_json_bytes(profile))
        for profile_id, profile in positive_profiles.items()
    }
    required_runs: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        require(isinstance(row, dict), f"rows[{index}]_invalid")
        sample_id = str(row.get("sample_id"))
        positive_profile_id = str(row.get("positive_profile_id"))
        positive_profile = positive_profiles.get(positive_profile_id)
        source_profile = source_profiles.get(sample_id)
        corpus_row = corpus_by_sample.get(sample_id)
        require(positive_profile is not None, f"rows[{index}]_positive_profile_missing")
        require(source_profile is not None, f"rows[{index}]_source_profile_missing")
        require(corpus_row is not None, f"corpus_missing_required_sample:{sample_id}")
        require(
            corpus_row.get("artifact_sha256") == row.get("artifact_sha256"),
            f"corpus_artifact_sha256_mismatch:{sample_id}",
        )
        require(
            corpus_row.get("ecosystem") == row.get("ecosystem"),
            f"corpus_ecosystem_mismatch:{sample_id}",
        )
        require(
            corpus_row.get("sample_kind") == "malware"
            and corpus_row.get("expected_result") == "malicious",
            f"corpus_expected_malicious_mismatch:{sample_id}",
        )
        required_labels = row.get("required_behavior_labels")
        require(
            isinstance(required_labels, list)
            and len(required_labels) == 1
            and required_labels[0] in corpus_row.get("behavior_labels", []),
            f"corpus_required_behavior_label_mismatch:{sample_id}",
        )
        permitted_evidence = positive_profile.get("permitted_positive_evidence")
        require(
            isinstance(permitted_evidence, list)
            and len(permitted_evidence) == 1
            and isinstance(permitted_evidence[0], dict),
            f"positive_profile_evidence_invalid:{positive_profile_id}",
        )
        evidence = permitted_evidence[0]
        require(
            evidence.get("behavior_label") == required_labels[0],
            f"positive_profile_behavior_label_mismatch:{sample_id}",
        )
        modality = evidence.get("modality")
        require(
            modality in {"deterministic", "dynamic"},
            f"positive_profile_modality_invalid:{sample_id}",
        )
        required_runs.append(
            {
                "sample_id": sample_id,
                "profile_id": positive_profile_id,
                "cohort_id": COHORT_ID,
                "family_id": source_profile["family_id"],
                "campaign_id": source_profile["campaign_id"],
                "artifact_sha256": row["artifact_sha256"],
                "execution_profile_sha256": profile_sha256_by_id[positive_profile_id],
                "ecosystem": row["ecosystem"],
                "expected_result": "malicious",
                "required_behavior_labels": list(required_labels),
                "required_modalities": [modality],
                "require_complete": True,
            }
        )
    require(
        len(required_runs) == 4
        and len({(row["sample_id"], row["profile_id"]) for row in required_runs}) == 4,
        "compiled_denominator_not_exactly_four_unique_rows",
    )
    return required_runs, profile_sha256_by_id


def build_manifest(
    args: argparse.Namespace,
    contract: dict[str, Any],
    complete_profile: dict[str, Any],
    corpus_by_sample: dict[str, dict[str, Any]],
    corpus_sha256: str,
) -> tuple[dict[str, Any], dict[str, str]]:
    created_at = parse_utc(args.created_at_utc, "created_at_utc_invalid")
    starts_at = parse_utc(args.starts_at_utc, "starts_at_utc_invalid")
    ends_at = parse_utc(args.ends_at_utc, "ends_at_utc_invalid")
    require(created_at <= starts_at < ends_at, "evaluation_window_order_invalid")
    upper_bound = contract["evaluation_window_policy"][
        "maximum_result_to_registry_seconds_upper_bound"
    ]
    require(
        isinstance(args.maximum_result_to_registry_seconds, int)
        and 0 < args.maximum_result_to_registry_seconds <= upper_bound,
        "maximum_result_to_registry_seconds_invalid",
    )
    for name in ("evaluation_id", "registry_id", "verifier_id", "scorer_id"):
        require_identifier(getattr(args, name), f"{name}_invalid")
    require(args.scorer_id == SCORER_ID, "scorer_id_not_pinned")
    digest_names = (
        "runtime_sha256",
        "prompt_set_sha256",
        "observation_schema_sha256",
        "provider_adapter_sha256",
        "policy_sha256",
        "verifier_public_key_sha256",
        "verifier_executable_sha256",
        "projection_schema_sha256",
    )
    for name in digest_names:
        require_sha256(getattr(args, name), f"{name}_invalid")
    required_runs, profile_sha256_by_id = build_required_runs(
        contract,
        complete_profile,
        corpus_by_sample,
    )
    thresholds = contract["thresholds"]
    manifest = {
        "schema": MANIFEST_SCHEMA,
        "evaluation_id": args.evaluation_id,
        "evaluation_class": MANIFEST_CARRIER_CLASS,
        "created_at_utc": args.created_at_utc,
        "corpus_sha256": corpus_sha256,
        "identities": {
            "runtime_sha256": args.runtime_sha256,
            "prompt_set_sha256": args.prompt_set_sha256,
            "observation_schema_sha256": args.observation_schema_sha256,
            "provider_adapter_sha256": args.provider_adapter_sha256,
            "policy_sha256": args.policy_sha256,
            "scorer_id": args.scorer_id,
        },
        "verified_evidence_registry": {
            "registry_id": args.registry_id,
            "verifier_id": args.verifier_id,
            "verifier_public_key_sha256": args.verifier_public_key_sha256,
            "verifier_executable_sha256": args.verifier_executable_sha256,
            "projection_schema_sha256": args.projection_schema_sha256,
        },
        "evaluation_window": {
            "starts_at_utc": args.starts_at_utc,
            "ends_at_utc": args.ends_at_utc,
            "maximum_result_to_registry_seconds": args.maximum_result_to_registry_seconds,
        },
        "thresholds": {
            "malicious_behavior_detection_rate_min": thresholds[
                "behavior_positive_rate_min"
            ],
            "benign_false_malicious_rate_max": 0.0,
            "benign_friction_rate_max": 0.0,
            "required_run_completion_rate_min": thresholds[
                "required_run_completion_rate_min"
            ],
            "safety_pass_rate_min": thresholds["safety_pass_rate_min"],
        },
        "cohorts": [
            {
                "cohort_id": COHORT_ID,
                "expected_result": "malicious",
                "description": COHORT_DESCRIPTION,
            }
        ],
        "required_runs": required_runs,
    }
    return manifest, profile_sha256_by_id


def validate_manifest_against_contract(
    manifest: Any,
    contract: dict[str, Any],
    complete_profile: dict[str, Any],
    corpus_by_sample: dict[str, dict[str, Any]],
    corpus_sha256: str,
) -> dict[str, str]:
    require(isinstance(manifest, dict), "evaluation_manifest_not_object")
    require(manifest.get("schema") == MANIFEST_SCHEMA, "evaluation_manifest_schema_mismatch")
    require(
        manifest.get("evaluation_class") == MANIFEST_CARRIER_CLASS,
        "evaluation_manifest_carrier_class_mismatch",
    )
    require(manifest.get("corpus_sha256") == corpus_sha256, "evaluation_manifest_corpus_mismatch")
    expected_runs, profile_sha256_by_id = build_required_runs(
        contract,
        complete_profile,
        corpus_by_sample,
    )
    require(
        manifest.get("required_runs") == expected_runs,
        "evaluation_manifest_positive_denominator_mismatch",
    )
    expected_cohorts = [
        {
            "cohort_id": COHORT_ID,
            "expected_result": "malicious",
            "description": COHORT_DESCRIPTION,
        }
    ]
    require(manifest.get("cohorts") == expected_cohorts, "evaluation_manifest_cohort_mismatch")
    thresholds = contract["thresholds"]
    expected_thresholds = {
        "malicious_behavior_detection_rate_min": thresholds[
            "behavior_positive_rate_min"
        ],
        "benign_false_malicious_rate_max": 0.0,
        "benign_friction_rate_max": 0.0,
        "required_run_completion_rate_min": thresholds[
            "required_run_completion_rate_min"
        ],
        "safety_pass_rate_min": thresholds["safety_pass_rate_min"],
    }
    require(
        manifest.get("thresholds") == expected_thresholds,
        "evaluation_manifest_thresholds_mismatch",
    )
    window = manifest.get("evaluation_window")
    require(isinstance(window, dict), "evaluation_manifest_window_invalid")
    maximum_skew = window.get("maximum_result_to_registry_seconds")
    upper_bound = contract["evaluation_window_policy"][
        "maximum_result_to_registry_seconds_upper_bound"
    ]
    require(
        isinstance(maximum_skew, int)
        and not isinstance(maximum_skew, bool)
        and 0 < maximum_skew <= upper_bound,
        "evaluation_manifest_window_skew_invalid",
    )
    return profile_sha256_by_id


def validate_compiled_manifest(
    manifest: dict[str, Any],
    corpus_by_sample: dict[str, dict[str, Any]],
    corpus_sha256: str,
    evaluator: ModuleType,
) -> None:
    errors, _, _ = evaluator.validate_evaluation_manifest_v2(
        manifest,
        corpus_by_sample,
        corpus_sha256,
    )
    if errors:
        raise CompileError(f"compiled_manifest_invalid:{errors[0]}")


def write_new_private_json(path: Path, value: Any) -> None:
    require(path.is_absolute(), "output_path_not_absolute")
    require(path.parent.is_dir(), "output_parent_not_directory")
    payload = json.dumps(
        value,
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise CompileError("output_create_failed") from exc
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


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    result.add_argument("--complete-run-profile", type=Path, default=DEFAULT_COMPLETE_PROFILE)
    result.add_argument("--corpus", type=Path, required=True)
    result.add_argument("--output", type=Path, required=True)
    result.add_argument("--evaluation-id", required=True)
    result.add_argument("--created-at-utc", required=True)
    result.add_argument("--starts-at-utc", required=True)
    result.add_argument("--ends-at-utc", required=True)
    result.add_argument("--maximum-result-to-registry-seconds", type=int, required=True)
    result.add_argument("--runtime-sha256", required=True)
    result.add_argument("--prompt-set-sha256", required=True)
    result.add_argument("--observation-schema-sha256", required=True)
    result.add_argument("--provider-adapter-sha256", required=True)
    result.add_argument("--policy-sha256", required=True)
    result.add_argument("--scorer-id", required=True)
    result.add_argument("--registry-id", required=True)
    result.add_argument("--verifier-id", required=True)
    result.add_argument("--verifier-public-key-sha256", required=True)
    result.add_argument("--verifier-executable-sha256", required=True)
    result.add_argument("--projection-schema-sha256", required=True)
    return result


def compile_manifest(args: argparse.Namespace) -> tuple[dict[str, Any], dict[str, Any]]:
    validator = load_module("whoathere_r01_contract_validator", CONTRACT_VALIDATOR_PATH)
    evaluator = load_module("whoathere_actual_malware_evaluation", EVALUATOR_PATH)
    contract, complete_profile, contract_report = validate_contract_and_source(
        args.contract,
        args.complete_run_profile,
        validator,
    )
    corpus_by_sample, corpus_sha256 = read_corpus(args.corpus, evaluator)
    manifest, profile_sha256_by_id = build_manifest(
        args,
        contract,
        complete_profile,
        corpus_by_sample,
        corpus_sha256,
    )
    validate_manifest_against_contract(
        manifest,
        contract,
        complete_profile,
        corpus_by_sample,
        corpus_sha256,
    )
    validate_compiled_manifest(manifest, corpus_by_sample, corpus_sha256, evaluator)
    report = {
        "schema": COMPILE_REPORT_SCHEMA,
        "status": "compiled_metadata_only",
        "contract_id": contract["contract_id"],
        "contract_sha256": contract_report["contract_sha256"],
        "artifact_profile_denominator_sha256": contract_report[
            "artifact_profile_denominator_sha256"
        ],
        "corpus_sha256": corpus_sha256,
        "required_run_count": len(manifest["required_runs"]),
        "positive_profile_sha256_by_id": profile_sha256_by_id,
        "identity_posture": "synthetic_or_provisional_until_r02b",
        "output": str(args.output),
    }
    return manifest, report


def main() -> int:
    args = parser().parse_args()
    args.contract = args.contract.expanduser().absolute()
    args.complete_run_profile = args.complete_run_profile.expanduser().absolute()
    args.corpus = args.corpus.expanduser().absolute()
    args.output = args.output.expanduser().absolute()
    try:
        manifest, report = compile_manifest(args)
        write_new_private_json(args.output, manifest)
    except CompileError as exc:
        print(f"error:{exc}", file=sys.stderr)
        return 20
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
