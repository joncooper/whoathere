#!/usr/bin/env python3
"""Score the frozen four-known-miss positive-only contract over mandatory V2 evidence.

The mandatory V2 scorer authenticates the manifest, results, run facts, evidence registry, and
signatures. This narrow summary then enforces the stricter R01 per-row evidence tuple instead of
allowing a matching behavior label from an unapproved modality or evidence type to satisfy the
positive subscore.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
COMPILER_PATH = ROOT / "scripts" / "whoathere-compile-four-known-miss-positive-subscore.py"
CONTRACT_VALIDATOR_PATH = (
    ROOT / "scripts" / "whoathere-validate-four-known-miss-positive-subscore-contract.py"
)
EVALUATOR_PATH = ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"
DEFAULT_CONTRACT = (
    ROOT
    / "docs"
    / "product-build-run"
    / "four-known-miss-positive-subscore-contract.v1.json"
)
DEFAULT_COMPLETE_PROFILE = (
    ROOT / "docs" / "product-build-run" / "four-known-miss-campaign-profile.v1.json"
)
REPORT_SCHEMA = "whoathere.four_known_miss_positive_subscore_report.v1"


class SubscoreError(Exception):
    """A stable fail-closed positive-subscore error."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SubscoreError(reason)


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"{name}_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - only local installation failures reach this.
        raise SubscoreError(f"{name}_module_unavailable") from exc
    return module


def exact_result_rows(
    results_path: Path,
    expected_keys: set[tuple[str, str]],
    evaluator: ModuleType,
) -> dict[tuple[str, str], dict[str, Any]]:
    try:
        rows = evaluator.read_jsonl(results_path)
    except Exception as exc:
        raise SubscoreError("run_results_unreadable") from exc
    by_key: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in rows:
        key = (str(row.get("sample_id")), str(row.get("profile_id")))
        by_key.setdefault(key, []).append(row)
    require(set(by_key) == expected_keys, "run_results_denominator_mismatch")
    require(
        all(len(group) == 1 for group in by_key.values()),
        "run_results_duplicate_sample_profile",
    )
    return {key: group[0] for key, group in by_key.items()}


def rate(numerator: int, denominator: int) -> float:
    require(denominator > 0, "subscore_denominator_zero")
    return numerator / denominator


def score_positive_subscore(args: argparse.Namespace) -> dict[str, Any]:
    compiler = load_module("whoathere_positive_subscore_compiler", COMPILER_PATH)
    validator = load_module("whoathere_r01_contract_validator", CONTRACT_VALIDATOR_PATH)
    evaluator = load_module("whoathere_actual_malware_evaluation", EVALUATOR_PATH)
    try:
        contract, complete_profile, contract_report = compiler.validate_contract_and_source(
            args.contract,
            args.complete_run_profile,
            validator,
        )
        corpus_by_sample, corpus_sha256 = compiler.read_corpus(args.corpus, evaluator)
        manifest = compiler.load_json(args.evaluation_manifest, "evaluation_manifest")
        profile_sha256_by_id = compiler.validate_manifest_against_contract(
            manifest,
            contract,
            complete_profile,
            corpus_by_sample,
            corpus_sha256,
        )
        underlying = evaluator.score_results_v2(
            corpus_path=args.corpus,
            results_path=args.results,
            manifest_path=args.evaluation_manifest,
            verified_evidence_registry_path=args.verified_evidence_registry,
            verified_evidence_public_key_path=args.verified_evidence_public_key,
            verified_evidence_signature_path=args.verified_evidence_signature,
        )
    except SubscoreError:
        raise
    except Exception as exc:
        raise SubscoreError(f"mandatory_v2_scoring_failed:{exc}") from exc
    validation_errors = underlying.get("validation_errors")
    require(isinstance(validation_errors, list), "underlying_validation_errors_invalid")
    if validation_errors:
        raise SubscoreError(f"underlying_v2_invalid:{validation_errors[0]}")
    require(underlying.get("valid_result_count") == 4, "underlying_valid_result_count_mismatch")

    positive_profiles = {
        str(profile["profile_id"]): profile for profile in contract["positive_profiles"]
    }
    contract_rows = contract["rows"]
    expected_keys = {
        (str(row["sample_id"]), str(row["positive_profile_id"])) for row in contract_rows
    }
    raw_results = exact_result_rows(args.results, expected_keys, evaluator)
    base_summaries = {
        (str(row["sample_id"]), str(row["profile_id"])): row
        for row in underlying.get("results", [])
        if isinstance(row, dict)
    }
    require(set(base_summaries) == expected_keys, "underlying_result_summary_denominator_mismatch")

    row_reports: list[dict[str, Any]] = []
    for contract_row in contract_rows:
        key = (
            str(contract_row["sample_id"]),
            str(contract_row["positive_profile_id"]),
        )
        result = raw_results[key]
        base_summary = base_summaries[key]
        profile = positive_profiles[key[1]]
        permitted = profile["permitted_positive_evidence"][0]
        observations = result.get("observations")
        require(isinstance(observations, list), f"result_observations_invalid:{key[0]}")
        exact_matches = [
            observation
            for observation in observations
            if isinstance(observation, dict)
            and observation.get("modality") == permitted["modality"]
            and observation.get("evidence_type") == permitted["evidence_type"]
            and observation.get("behavior_label") == permitted["behavior_label"]
        ]
        row_reports.append(
            {
                "row_id": contract_row["row_id"],
                "sample_id": key[0],
                "profile_id": key[1],
                "artifact_sha256": contract_row["artifact_sha256"],
                "execution_profile_sha256": profile_sha256_by_id[key[1]],
                "permitted_positive": dict(permitted),
                "exact_positive_observation_ids": sorted(
                    str(observation["observation_id"]) for observation in exact_matches
                ),
                "exact_positive_projection_sha256": sorted(
                    str(observation["projection_sha256"]) for observation in exact_matches
                ),
                "behavior_positive": bool(exact_matches),
                "underlying_label_level_behavior_detected": base_summary.get(
                    "behavior_detected"
                ),
                "complete": base_summary.get("complete"),
                "safety_passed": base_summary.get("safety_passed"),
                "observed_clean_eligible": base_summary.get("observed_clean_eligible"),
                "artifact_release_applied": base_summary.get("artifact_release_applied"),
                "manual_review_required": base_summary.get("manual_review_required"),
                "derived_verdict_class": base_summary.get("derived_verdict_class"),
            }
        )

    denominator = int(contract["thresholds"]["required_row_count"])
    required_positive_count = int(
        contract["thresholds"]["required_behavior_positive_count"]
    )
    behavior_positive_count = sum(1 for row in row_reports if row["behavior_positive"])
    safety_pass_count = sum(1 for row in row_reports if row["safety_passed"] is True)
    complete_count = sum(1 for row in row_reports if row["complete"] is True)
    observed_clean_count = sum(
        1 for row in row_reports if row["observed_clean_eligible"] is True
    )
    release_applied_count = sum(
        1 for row in row_reports if row["artifact_release_applied"] is True
    )
    manual_review_count = sum(
        1 for row in row_reports if row["manual_review_required"] is True
    )
    sync_back_applied_count = sum(
        1
        for result in raw_results.values()
        if isinstance(result.get("safety"), dict)
        and result["safety"].get("sync_back_applied") is True
    )

    detection_rate = rate(behavior_positive_count, denominator)
    safety_rate = rate(safety_pass_count, denominator)
    completion_rate = rate(complete_count, denominator)
    detection_passed = (
        behavior_positive_count >= required_positive_count
        and detection_rate >= float(contract["thresholds"]["behavior_positive_rate_min"])
    )
    safety_passed = (
        safety_rate >= float(contract["thresholds"]["safety_pass_rate_min"])
        and all(underlying.get("safety_gates", {}).values())
    )
    completion_quality_passed = all(underlying.get("quality_gates", {}).values())
    contract_claims = contract["claim_and_coverage_policy"]
    authority = {
        "observed_clean_eligible_count": observed_clean_count,
        "artifact_release_applied_count": release_applied_count,
        "manual_review_required_count": manual_review_count,
        "sync_back_applied_count": sync_back_applied_count,
        "observed_clean_authorized": bool(contract_claims["observed_clean_authorized"]),
        "admission_authorized": bool(contract_claims["admission_authorized"]),
        "release_authorized": bool(contract_claims["release_authorized"]),
        "sync_back_authorized": bool(contract_claims["sync_back_authorized"]),
    }
    authority_clear = (
        observed_clean_count == 0
        and release_applied_count == 0
        and sync_back_applied_count == 0
        and not any(
            authority[key]
            for key in (
                "observed_clean_authorized",
                "admission_authorized",
                "release_authorized",
                "sync_back_authorized",
            )
        )
    )
    overall_passed = bool(underlying.get("passed")) and detection_passed
    report = {
        "schema": REPORT_SCHEMA,
        "status": (
            "behavior_positive_subscore_passed"
            if detection_passed and safety_passed and authority_clear
            else "behavior_positive_subscore_failed"
        ),
        "contract_id": contract["contract_id"],
        "contract_sha256": contract_report["contract_sha256"],
        "artifact_profile_denominator_sha256": contract_report[
            "artifact_profile_denominator_sha256"
        ],
        "evaluation_manifest_sha256": underlying["evaluation_manifest_sha256"],
        "detection_subscore": {
            "behavior_positive_count": behavior_positive_count,
            "required_count": required_positive_count,
            "denominator": denominator,
            "rate": detection_rate,
            "passed": detection_passed,
        },
        "safety": {
            "pass_count": safety_pass_count,
            "denominator": denominator,
            "rate": safety_rate,
            "passed": safety_passed,
            "underlying_gates": underlying["safety_gates"],
        },
        "completion_quality": {
            "complete_count": complete_count,
            "denominator": denominator,
            "rate": completion_rate,
            "passed": completion_quality_passed,
            "underlying_gates": underlying["quality_gates"],
        },
        "authority": authority,
        "overall_passed": overall_passed,
        "rows": row_reports,
        "underlying_v2_report": underlying,
        "claim_boundary": (
            "Positive-only exact-evidence subscore. Incomplete coverage may preserve a verified "
            "positive but cannot authorize observed-clean, admission, release, sync-back, or an "
            "overall evaluation pass."
        ),
    }
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--contract", type=Path, default=DEFAULT_CONTRACT)
    result.add_argument("--complete-run-profile", type=Path, default=DEFAULT_COMPLETE_PROFILE)
    result.add_argument("--corpus", type=Path, required=True)
    result.add_argument("--results", type=Path, required=True)
    result.add_argument("--evaluation-manifest", type=Path, required=True)
    result.add_argument("--verified-evidence-registry", type=Path, required=True)
    result.add_argument("--verified-evidence-public-key", type=Path, required=True)
    result.add_argument("--verified-evidence-signature", type=Path, required=True)
    result.add_argument("--report-json", type=Path)
    return result


def main() -> int:
    args = parser().parse_args()
    for name in (
        "contract",
        "complete_run_profile",
        "corpus",
        "results",
        "evaluation_manifest",
        "verified_evidence_registry",
        "verified_evidence_public_key",
        "verified_evidence_signature",
    ):
        setattr(args, name, getattr(args, name).expanduser().absolute())
    if args.report_json is not None:
        args.report_json = args.report_json.expanduser().absolute()
    try:
        report = score_positive_subscore(args)
        if args.report_json is not None:
            compiler = load_module("whoathere_positive_subscore_compiler_writer", COMPILER_PATH)
            compiler.write_new_private_json(args.report_json, report)
    except SubscoreError as exc:
        print(f"error:{exc}", file=sys.stderr)
        return 20
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "behavior_positive_subscore_passed" else 20


if __name__ == "__main__":
    raise SystemExit(main())
