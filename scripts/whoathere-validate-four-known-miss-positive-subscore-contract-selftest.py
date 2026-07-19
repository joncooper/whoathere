#!/usr/bin/env python3
"""Hermetic version and mutation tests for the positive-subscore contract validator."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "whoathere-validate-four-known-miss-positive-subscore-contract.py"
CONTRACT_V1 = (
    REPO_ROOT
    / "docs"
    / "product-build-run"
    / "four-known-miss-positive-subscore-contract.v1.json"
)
CONTRACT_V2 = (
    REPO_ROOT
    / "docs"
    / "product-build-run"
    / "four-known-miss-positive-subscore-contract.v2.json"
)
SOURCE_PROFILE = (
    REPO_ROOT / "docs" / "product-build-run" / "four-known-miss-campaign-profile.v1.json"
)
EXPECTED_IDENTITIES = {
    "v1": {
        "path": CONTRACT_V1,
        "schema": "whoathere.four_known_miss_positive_subscore_contract.v1",
        "contract_id": "four-prior-misses-positive-only-v1",
        "contract_sha256": "sha256:a47b8288c14c6c1eafb3976415fdc16a24ce0b85f06f4cf2c687ee50509ee053",
        "denominator_sha256": "sha256:bdd99ff7ba8634dbcec7f98f442962a7c371437f9d0d3bcc9fd940f8af285c96",
        "modalities": ["deterministic", "dynamic"],
    },
    "v2": {
        "path": CONTRACT_V2,
        "schema": "whoathere.four_known_miss_positive_subscore_contract.v2",
        "contract_id": "four-prior-misses-positive-only-v2",
        "contract_sha256": "sha256:3269f8525e60012c075c951664083e559583a849f476d035922000d653da8359",
        "denominator_sha256": "sha256:489be1dfe2513a29c8a4019d2303ebf377e93be33c4fe50bb7d34816d65dc792",
        "modalities": ["deterministic"],
    },
}


def invoke(contract_path: Path, source_profile_path: Path = SOURCE_PROFILE) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(VALIDATOR),
            "--contract",
            str(contract_path),
            "--complete-run-profile",
            str(source_profile_path),
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )


def require_rejected(name: str, contract: dict[str, Any], directory: Path) -> None:
    path = directory / f"{name}.json"
    write_json(path, contract)
    completed = invoke(path)
    if completed.returncode != 64 or "validation_error=" not in completed.stderr:
        raise AssertionError(
            f"{name}: expected fail-closed exit 64; "
            f"got {completed.returncode}; stdout={completed.stdout!r}; stderr={completed.stderr!r}"
        )


def main() -> int:
    for version_name, expected in EXPECTED_IDENTITIES.items():
        canonical = invoke(expected["path"])
        if canonical.returncode != 0:
            raise AssertionError(
                f"canonical {version_name} contract rejected: {canonical.stderr}"
            )
        report = json.loads(canonical.stdout)
        if report.get("valid") is not True or report.get("row_count") != 4:
            raise AssertionError(
                f"canonical {version_name} validation report did not contain four valid rows"
            )
        if report.get("required_behavior_positive_count") != 4:
            raise AssertionError(
                f"canonical {version_name} validation report did not retain the 4/4 threshold"
            )
        if report.get("contract_schema") != expected["schema"]:
            raise AssertionError(f"canonical {version_name} schema changed")
        if report.get("contract_id") != expected["contract_id"]:
            raise AssertionError(f"canonical {version_name} id changed")
        if report.get("contract_sha256") != expected["contract_sha256"]:
            raise AssertionError(f"canonical {version_name} contract digest changed")
        if (
            report.get("artifact_profile_denominator_sha256")
            != expected["denominator_sha256"]
        ):
            raise AssertionError(f"canonical {version_name} denominator digest changed")
        if report.get("permitted_positive_modalities") != expected["modalities"]:
            raise AssertionError(f"canonical {version_name} modalities changed")
        if report.get("claim_boundary") != {
            "completion_quality_or_overall_pass": False,
            "full_corpus_baseline": False,
            "observed_clean_admission_or_release": False,
            "positive_only": True,
        }:
            raise AssertionError(f"canonical {version_name} claim boundary changed")

    base = json.loads(CONTRACT_V2.read_text(encoding="utf-8"))

    mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        (
            "schema_substitution",
            lambda value: value.__setitem__(
                "schema", "whoathere.four_known_miss_positive_subscore_contract.v1"
            ),
        ),
        (
            "contract_id_substitution",
            lambda value: value.__setitem__(
                "contract_id", "four-prior-misses-positive-only-v1"
            ),
        ),
        ("unknown_top_level_field", lambda value: value.__setitem__("future", True)),
        ("missing_thresholds", lambda value: value.pop("thresholds")),
        ("row_omission", lambda value: value["rows"].pop()),
        ("row_duplication", lambda value: value["rows"].__setitem__(3, copy.deepcopy(value["rows"][0]))),
        ("row_reordering", lambda value: value["rows"].reverse()),
        (
            "artifact_substitution",
            lambda value: value["rows"][0].__setitem__("artifact_sha256", "sha256:" + "0" * 64),
        ),
        ("artifact_form_substitution", lambda value: value["rows"][1].__setitem__("artifact_form", "sdist")),
        (
            "positive_profile_substitution",
            lambda value: value["rows"][0].__setitem__(
                "positive_profile_id", "pypi-exact-archive-static-capability-positive-v1"
            ),
        ),
        (
            "complete_profile_substitution",
            lambda value: value["rows"][0].__setitem__(
                "source_complete_run_profile_id", "wheel-exact-complete-trigger-matrix-v1"
            ),
        ),
        (
            "behavior_label_widening",
            lambda value: value["rows"][0]["required_behavior_labels"].append("https_exfil"),
        ),
        (
            "evidence_type_substitution",
            lambda value: value["positive_profiles"][0]["permitted_positive_evidence"][0].__setitem__(
                "evidence_type", "local_sinkhole_network_intent"
            ),
        ),
        (
            "modality_substitution",
            lambda value: value["positive_profiles"][1]["permitted_positive_evidence"][0].__setitem__(
                "modality", "codex"
            ),
        ),
        (
            "positive_evidence_widening",
            lambda value: value["positive_profiles"][1]["permitted_positive_evidence"].append(
                {
                    "behavior_label": "https_exfil",
                    "evidence_type": "https_exfiltration_attempt",
                    "modality": "dynamic",
                }
            ),
        ),
        (
            "generic_block_relaxation",
            lambda value: value["detection_policy"].__setitem__(
                "generic_safe_block_counts_as_detection", True
            ),
        ),
        (
            "clean_claim_relaxation",
            lambda value: value["claim_and_coverage_policy"].__setitem__(
                "observed_clean_authorized", True
            ),
        ),
        (
            "safety_invariant_omission",
            lambda value: value["safety_policy"]["required_zero_invariants"].pop(),
        ),
        (
            "window_policy_relaxation",
            lambda value: value["evaluation_window_policy"].__setitem__(
                "maximum_result_to_registry_seconds_upper_bound", 601
            ),
        ),
        (
            "threshold_relaxation",
            lambda value: value["thresholds"].__setitem__("required_behavior_positive_count", 3),
        ),
        (
            "identity_field_omission",
            lambda value: value["identity_policy"]["required_identity_fields"].remove(
                "sensor_sha256"
            ),
        ),
        (
            "identity_field_widening",
            lambda value: value["identity_policy"]["required_identity_fields"].append(
                "unreviewed_identity"
            ),
        ),
    ]

    with tempfile.TemporaryDirectory(prefix="whoathere-r01-contract-selftest-") as temp:
        directory = Path(temp)
        for name, mutate in mutations:
            candidate = copy.deepcopy(base)
            mutate(candidate)
            require_rejected(name, candidate, directory)

        source = json.loads(SOURCE_PROFILE.read_text(encoding="utf-8"))
        source["campaign_profile_id"] = "substituted-profile"
        tampered_source = directory / "tampered-source-profile.json"
        write_json(tampered_source, source)
        source_result = invoke(CONTRACT_V2, tampered_source)
        if source_result.returncode != 64 or "validation_error=" not in source_result.stderr:
            raise AssertionError("source complete-run profile substitution did not fail closed")

    print(
        "R02b positive-subscore contract selftest passed "
        f"({len(mutations) + len(EXPECTED_IDENTITIES) + 1} cases)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
