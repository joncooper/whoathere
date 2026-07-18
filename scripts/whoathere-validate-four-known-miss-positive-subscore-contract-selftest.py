#!/usr/bin/env python3
"""Hermetic mutation tests for the R01 positive-subscore contract validator."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "scripts" / "whoathere-validate-four-known-miss-positive-subscore-contract.py"
CONTRACT = (
    REPO_ROOT
    / "docs"
    / "product-build-run"
    / "four-known-miss-positive-subscore-contract.v1.json"
)
SOURCE_PROFILE = (
    REPO_ROOT / "docs" / "product-build-run" / "four-known-miss-campaign-profile.v1.json"
)
EXPECTED_CONTRACT_SHA256 = (
    "sha256:a47b8288c14c6c1eafb3976415fdc16a24ce0b85f06f4cf2c687ee50509ee053"
)
EXPECTED_DENOMINATOR_SHA256 = (
    "sha256:bdd99ff7ba8634dbcec7f98f442962a7c371437f9d0d3bcc9fd940f8af285c96"
)


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
    base = json.loads(CONTRACT.read_text(encoding="utf-8"))
    canonical = invoke(CONTRACT)
    if canonical.returncode != 0:
        raise AssertionError(f"canonical contract rejected: {canonical.stderr}")
    report = json.loads(canonical.stdout)
    if report.get("valid") is not True or report.get("row_count") != 4:
        raise AssertionError("canonical validation report did not contain four valid rows")
    if report.get("required_behavior_positive_count") != 4:
        raise AssertionError("canonical validation report did not retain the 4/4 threshold")
    if report.get("contract_sha256") != EXPECTED_CONTRACT_SHA256:
        raise AssertionError("canonical contract digest changed")
    if report.get("artifact_profile_denominator_sha256") != EXPECTED_DENOMINATOR_SHA256:
        raise AssertionError("canonical denominator digest changed")
    if report.get("permitted_positive_modalities") != ["deterministic", "dynamic"]:
        raise AssertionError("canonical modalities changed")
    if report.get("claim_boundary") != {
        "completion_quality_or_overall_pass": False,
        "full_corpus_baseline": False,
        "observed_clean_admission_or_release": False,
        "positive_only": True,
    }:
        raise AssertionError("canonical claim boundary changed")

    mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
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
        source_result = invoke(CONTRACT, tampered_source)
        if source_result.returncode != 64 or "validation_error=" not in source_result.stderr:
            raise AssertionError("source complete-run profile substitution did not fail closed")

    print(f"R01 positive-subscore contract selftest passed ({len(mutations) + 2} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
