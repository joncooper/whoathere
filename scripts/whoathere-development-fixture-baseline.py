#!/usr/bin/env python3
"""Run canonical fixtures and frozen public controls as a development baseline.

This development runner measures the current exact-artifact static path only.
It deliberately does not request AI review, detonation, or admission. Sealed
expectations are used by this runner for scoring and are never passed to the
WhoaThere process.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "whoathere/tests/fixtures/threat-taxonomy-v1"
BUILDER_PATH = FIXTURE_ROOT / "build_fixtures.py"
EXPECTATIONS_PATH = FIXTURE_ROOT / "sealed/expectations-v2.json"
EXPECTATIONS_SHA_PATH = FIXTURE_ROOT / "sealed/expectations-v2.json.sha256"
BASELINE_MANIFEST_PATH = (
    ROOT / "whoathere/tests/fixtures/development-baseline-manifest-v1.json"
)
DEFAULT_PUBLIC_CONTROLS_DIR = ROOT / ".whoathere/benign-neighbors-20260716"
ACQUIRED_AT = "2026-07-15T00:00:00Z"
BASELINE_LABEL = "non_claim_bearing_development_baseline"
REPORT_SCHEMA = "whoathere.exact_artifact_inspection.v1"
SUMMARY_SCHEMA = "whoathere.development_fixture_baseline.v2"
BASELINE_MANIFEST_SCHEMA = "whoathere.development_baseline_manifest.v1"
EXPECTED_METRIC_KEYS = {
    "canonical_active_behavior_positive_count",
    "canonical_active_review_count",
    "canonical_active_total",
    "canonical_benign_false_malicious_count",
    "canonical_benign_total",
    "public_benign_false_malicious_count",
    "public_benign_total",
}
SUPPORTED_PUBLIC_FORMS = {
    "npm_tgz": ("npm", ".tgz"),
    "pypi_sdist_tar_gzip": ("pypi", ".tar.gz"),
    "pypi_wheel": ("pypi", ".whl"),
}


class BaselineFailure(RuntimeError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise BaselineFailure(reason)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"


def prepare_output_root(path: Path) -> Path:
    path = path.resolve()
    if path.exists():
        require(path.is_dir(), "output_path_not_directory")
        require(not any(path.iterdir()), "output_directory_not_empty")
    else:
        path.mkdir(parents=True)
    return path


def load_expectations() -> list[dict[str, Any]]:
    data = EXPECTATIONS_PATH.read_bytes()
    seal = EXPECTATIONS_SHA_PATH.read_text(encoding="utf-8").split()
    require(len(seal) == 2, "expectations_seal_format_invalid")
    require(seal[1] == EXPECTATIONS_PATH.name, "expectations_seal_name_invalid")
    require(hashlib.sha256(data).hexdigest() == seal[0], "expectations_seal_digest_mismatch")
    document = json.loads(data)
    require(
        document.get("schema_version") == "whoathere.canonical_fixture_expectations.v2",
        "expectations_schema_invalid",
    )
    require(
        document.get("scanner_input_policy")
        == "exact_artifact_only_expectations_sidecar_forbidden",
        "expectations_scanner_policy_invalid",
    )
    cases = document.get("cases")
    require(isinstance(cases, list) and len(cases) == 6, "expectations_case_count_invalid")

    sample_ids: set[str] = set()
    filenames: set[str] = set()
    validated: list[dict[str, Any]] = []
    for case in cases:
        require(isinstance(case, dict), "expectations_case_invalid")
        sample_id = case.get("sample_id")
        filename = case.get("artifact_filename")
        ecosystem = case.get("ecosystem")
        expected_result = case.get("expected_result")
        digest = case.get("artifact_sha256")
        require(
            isinstance(sample_id, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*", sample_id) is not None
            and sample_id not in sample_ids,
            "expectations_sample_id_invalid_or_duplicate",
        )
        require(
            isinstance(filename, str)
            and Path(filename).name == filename
            and filename not in filenames,
            "expectations_artifact_filename_invalid_or_duplicate",
        )
        require(ecosystem in {"npm", "pypi"}, "expectations_ecosystem_invalid")
        require(expected_result in {"malicious", "benign"}, "expectations_result_invalid")
        require(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "expectations_artifact_digest_invalid",
        )
        sample_ids.add(sample_id)
        filenames.add(filename)
        validated.append(
            {
                **case,
                "cohort": (
                    "canonical_active"
                    if expected_result == "malicious"
                    else "canonical_benign"
                ),
                "form": case.get("artifact_kind"),
            }
        )

    require(
        sum(case["expected_result"] == "malicious" for case in validated) == 3,
        "expectations_active_case_count_invalid",
    )
    require(
        sum(case["expected_result"] == "benign" for case in validated) == 3,
        "expectations_benign_case_count_invalid",
    )
    return sorted(validated, key=lambda case: str(case["sample_id"]))


def load_baseline_manifest(
    path: Path,
) -> tuple[list[dict[str, Any]], dict[str, int], str]:
    require(path.is_file() and not path.is_symlink(), "baseline_manifest_unavailable")
    data = path.read_bytes()
    document = json.loads(data)
    require(isinstance(document, dict), "baseline_manifest_invalid")
    require(
        document.get("schema_version") == BASELINE_MANIFEST_SCHEMA,
        "baseline_manifest_schema_invalid",
    )
    expected_metrics = document.get("expected_metrics")
    require(
        isinstance(expected_metrics, dict)
        and set(expected_metrics) == EXPECTED_METRIC_KEYS,
        "baseline_expected_metrics_invalid",
    )
    require(
        all(
            isinstance(value, int) and not isinstance(value, bool) and value >= 0
            for value in expected_metrics.values()
        ),
        "baseline_expected_metric_value_invalid",
    )

    controls = document.get("public_benign_controls")
    require(
        isinstance(controls, list) and len(controls) == 5,
        "public_control_count_invalid",
    )
    sample_ids: set[str] = set()
    filenames: set[str] = set()
    coordinate_forms: set[tuple[str, str]] = set()
    validated: list[dict[str, Any]] = []
    for control in controls:
        require(isinstance(control, dict), "public_control_invalid")
        sample_id = control.get("sample_id")
        filename = control.get("artifact_filename")
        digest = control.get("artifact_sha256")
        coordinate = control.get("coordinate")
        ecosystem = control.get("ecosystem")
        form = control.get("form")
        require(
            isinstance(sample_id, str)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]*", sample_id) is not None
            and sample_id not in sample_ids,
            "public_control_id_invalid_or_duplicate",
        )
        require(
            isinstance(filename, str)
            and Path(filename).name == filename
            and filename not in filenames,
            "public_control_filename_invalid_or_duplicate",
        )
        require(
            isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest) is not None,
            "public_control_digest_invalid",
        )
        require(
            isinstance(coordinate, str)
            and re.fullmatch(
                r"(?:npm|pypi):[a-z0-9][a-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9._+-]*",
                coordinate,
            )
            is not None,
            "public_control_coordinate_invalid",
        )
        require(
            isinstance(form, str) and form in SUPPORTED_PUBLIC_FORMS,
            "public_control_form_unsupported",
        )
        expected_ecosystem, suffix = SUPPORTED_PUBLIC_FORMS[form]
        require(
            ecosystem == expected_ecosystem and filename.endswith(suffix),
            "public_control_form_mismatch",
        )
        require(
            coordinate.startswith(f"{ecosystem}:")
            and (coordinate, form) not in coordinate_forms,
            "public_control_coordinate_form_invalid_or_duplicate",
        )
        sample_ids.add(sample_id)
        filenames.add(filename)
        coordinate_forms.add((coordinate, form))
        validated.append(
            {
                **control,
                "cohort": "public_benign",
                "expected_result": "benign",
            }
        )
    return (
        sorted(validated, key=lambda control: str(control["sample_id"])),
        {key: int(expected_metrics[key]) for key in sorted(expected_metrics)},
        "sha256:" + hashlib.sha256(data).hexdigest(),
    )


def build_fixtures(output_dir: Path) -> Path:
    fixture_dir = output_dir / "fixtures"
    completed = subprocess.run(
        [sys.executable, str(BUILDER_PATH), "--out-dir", str(fixture_dir)],
        cwd=output_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(completed.returncode == 0, "fixture_builder_failed")
    try:
        build_report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BaselineFailure("fixture_builder_output_invalid") from error
    require(
        build_report.get("schema_version") == "whoathere.inert_fixture_build.v1",
        "fixture_builder_schema_invalid",
    )
    return fixture_dir


def verify_artifacts(
    fixture_dir: Path,
    cases: list[dict[str, Any]],
    *,
    unavailable_reason: str,
    mismatch_reason: str,
) -> None:
    require(fixture_dir.is_dir(), unavailable_reason)
    for case in cases:
        artifact = fixture_dir / str(case["artifact_filename"])
        require(
            artifact.is_file() and not artifact.is_symlink(),
            f"{unavailable_reason}:{case['sample_id']}",
        )
        require(
            sha256_file(artifact) == case["artifact_sha256"],
            f"{mismatch_reason}:{case['sample_id']}",
        )


def normalized_report_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    if value.startswith("sha256:"):
        value = value.removeprefix("sha256:")
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        return None
    return value


def inspect_case(
    *,
    whoathere_bin: Path,
    output_dir: Path,
    fixture_dir: Path,
    case: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    sample_id = str(case["sample_id"])
    artifact = fixture_dir / str(case["artifact_filename"])
    state_dir = output_dir / "state" / f"{index:02d}-{sample_id}"
    state_dir.mkdir(parents=True)
    command = [
        str(whoathere_bin),
        "artifact",
        "inspect",
        str(artifact),
        "--ecosystem",
        str(case["ecosystem"]),
        "--state-dir",
        str(state_dir),
        "--acquired-at",
        ACQUIRED_AT,
    ]
    completed = subprocess.run(
        command,
        cwd=output_dir,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise BaselineFailure(f"inspection_output_invalid_json:{sample_id}") from error
    require(isinstance(report, dict), f"inspection_report_invalid:{sample_id}")
    require(report.get("schema_version") == REPORT_SCHEMA, f"inspection_schema_invalid:{sample_id}")
    report_exit = report.get("exit_code")
    require(
        isinstance(report_exit, int) and not isinstance(report_exit, bool),
        f"inspection_exit_code_invalid:{sample_id}",
    )
    require(
        report_exit == completed.returncode,
        f"inspection_process_report_exit_mismatch:{sample_id}",
    )
    require(report_exit in {20, 22}, f"inspection_unexpected_exit_code:{sample_id}")
    identity = report.get("identity")
    require(isinstance(identity, dict), f"inspection_identity_missing:{sample_id}")
    require(
        normalized_report_digest(identity.get("artifact_sha256")) == case["artifact_sha256"],
        f"inspection_artifact_digest_mismatch:{sample_id}",
    )
    status = report.get("status")
    verdict = report.get("verdict")
    require(status in {"findings", "inconclusive", "unsupported"}, f"inspection_status_invalid:{sample_id}")
    require(verdict in {"malicious", "inconclusive", "unsupported"}, f"inspection_verdict_invalid:{sample_id}")
    require(
        (report_exit == 20 and status == "findings" and verdict == "malicious")
        or (
            report_exit == 22
            and status in {"inconclusive", "unsupported"}
            and verdict == status
        ),
        f"inspection_disposition_exit_mismatch:{sample_id}",
    )
    behavior_count = report.get("behavior_detection_count")
    require(
        isinstance(behavior_count, int)
        and not isinstance(behavior_count, bool)
        and behavior_count >= 0,
        f"inspection_behavior_count_invalid:{sample_id}",
    )
    require(
        (verdict == "malicious") == (behavior_count > 0),
        f"inspection_behavior_disposition_mismatch:{sample_id}",
    )

    reports_dir = output_dir / "reports"
    reports_dir.mkdir(exist_ok=True)
    report_name = f"{sample_id}.json"
    report_bytes = canonical_json(report).encode("utf-8")
    (reports_dir / report_name).write_bytes(report_bytes)
    return {
        "admission_authority": report.get("admission_authority"),
        "artifact_filename": case["artifact_filename"],
        "artifact_sha256": case["artifact_sha256"],
        "behavior_detection_count": behavior_count,
        "cohort": case["cohort"],
        "coordinate": case.get("coordinate"),
        "ecosystem": case["ecosystem"],
        "expected_result": case["expected_result"],
        "form": case.get("form"),
        "observed_clean": report.get("observed_clean"),
        "process_exit_code": completed.returncode,
        "report_path": f"reports/{report_name}",
        "report_sha256": "sha256:" + hashlib.sha256(report_bytes).hexdigest(),
        "sample_id": sample_id,
        "status": status,
        "sync_back_enabled": report.get("sync_back_enabled"),
        "verdict": verdict,
    }


def metric_case(case: dict[str, Any]) -> dict[str, Any]:
    return {
        "process_exit_code": case["process_exit_code"],
        "sample_id": case["sample_id"],
        "status": case["status"],
        "verdict": case["verdict"],
    }


def summarize(
    cases: list[dict[str, Any]],
    expected_metrics: dict[str, int],
    baseline_manifest_sha256: str,
) -> dict[str, Any]:
    active = [case for case in cases if case["cohort"] == "canonical_active"]
    canonical_benign = [
        case for case in cases if case["cohort"] == "canonical_benign"
    ]
    public_benign = [case for case in cases if case["cohort"] == "public_benign"]
    benign = canonical_benign + public_benign
    active_behavior_positives = [
        case for case in active if case["behavior_detection_count"] > 0
    ]
    active_misses = [
        case for case in active if case["behavior_detection_count"] == 0
    ]
    active_reviews = [
        case
        for case in active
        if case["process_exit_code"] == 22
        and case["verdict"] in {"inconclusive", "unsupported"}
    ]
    canonical_benign_false_malicious = [
        case for case in canonical_benign if case["verdict"] == "malicious"
    ]
    public_benign_false_malicious = [
        case for case in public_benign if case["verdict"] == "malicious"
    ]
    benign_false_malicious = (
        canonical_benign_false_malicious + public_benign_false_malicious
    )
    benign_friction = [
        case for case in benign if case["verdict"] in {"inconclusive", "unsupported"}
    ]
    admission_violations = [
        str(case["sample_id"]) for case in cases if case["admission_authority"] is not False
    ]
    observed_clean_violations = [
        str(case["sample_id"]) for case in cases if case["observed_clean"] is not False
    ]
    sync_back_violations = [
        str(case["sample_id"]) for case in cases if case["sync_back_enabled"] is not False
    ]
    safety_passed = not (
        admission_violations or observed_clean_violations or sync_back_violations
    )
    metrics = {
        "active_behavior_positive_count": len(active_behavior_positives),
        "active_malicious_count": len(active_behavior_positives),
        "active_miss_count": len(active_misses),
        "active_misses": [metric_case(case) for case in active_misses],
        "active_review_count": len(active_reviews),
        "active_total": len(active),
        "benign_false_malicious": [
            metric_case(case) for case in benign_false_malicious
        ],
        "benign_false_malicious_count": len(benign_false_malicious),
        "benign_friction": [metric_case(case) for case in benign_friction],
        "benign_friction_count": len(benign_friction),
        "benign_total": len(benign),
        "canonical_benign_false_malicious_count": len(
            canonical_benign_false_malicious
        ),
        "canonical_benign_total": len(canonical_benign),
        "public_benign_false_malicious_count": len(public_benign_false_malicious),
        "public_benign_total": len(public_benign),
    }
    observed_expected_metrics = {
        "canonical_active_behavior_positive_count": len(active_behavior_positives),
        "canonical_active_review_count": len(active_reviews),
        "canonical_active_total": len(active),
        "canonical_benign_false_malicious_count": len(
            canonical_benign_false_malicious
        ),
        "canonical_benign_total": len(canonical_benign),
        "public_benign_false_malicious_count": len(public_benign_false_malicious),
        "public_benign_total": len(public_benign),
    }
    metric_mismatches = [
        {
            "expected": expected_metrics[key],
            "metric": key,
            "observed": observed_expected_metrics[key],
        }
        for key in sorted(expected_metrics)
        if expected_metrics[key] != observed_expected_metrics[key]
    ]
    return {
        "acquired_at": ACQUIRED_AT,
        "baseline_kind": BASELINE_LABEL,
        "baseline_manifest_sha256": baseline_manifest_sha256,
        "cases": cases,
        "claim_bearing": False,
        "configuration": {
            "ai_review_requested": False,
            "detonation_requested": False,
            "expectations_passed_to_whoathere": False,
            "exact_local_artifacts": True,
        },
        "expected_metrics": expected_metrics,
        "metric_gate": {
            "mismatches": metric_mismatches,
            "passed": not metric_mismatches,
        },
        "metrics": metrics,
        "safety": {
            "admission_authority_violations": admission_violations,
            "observed_clean_violations": observed_clean_violations,
            "passed": safety_passed,
            "sync_back_violations": sync_back_violations,
        },
        "schema_version": SUMMARY_SCHEMA,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--whoathere-bin", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--fixture-dir",
        type=Path,
        help="Use a prebuilt canonical fixture directory instead of rebuilding it.",
    )
    parser.add_argument(
        "--baseline-manifest",
        type=Path,
        default=BASELINE_MANIFEST_PATH,
        help="Frozen expected metrics and public-control identities.",
    )
    parser.add_argument(
        "--public-controls-dir",
        type=Path,
        default=DEFAULT_PUBLIC_CONTROLS_DIR,
        help="Directory containing the exact public controls (their bytes remain untracked).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    whoathere_bin = args.whoathere_bin.resolve()
    require(
        whoathere_bin.is_file() and os.access(whoathere_bin, os.X_OK),
        "whoathere_binary_unavailable_or_not_executable",
    )
    output_dir = prepare_output_root(args.output_dir)
    canonical_cases = load_expectations()
    public_cases, expected_metrics, baseline_manifest_sha256 = load_baseline_manifest(
        args.baseline_manifest.resolve()
    )
    fixture_dir = args.fixture_dir.resolve() if args.fixture_dir else build_fixtures(output_dir)
    verify_artifacts(
        fixture_dir,
        canonical_cases,
        unavailable_reason="fixture_artifact_unavailable",
        mismatch_reason="fixture_artifact_digest_mismatch",
    )
    public_controls_dir = args.public_controls_dir.resolve()
    verify_artifacts(
        public_controls_dir,
        public_cases,
        unavailable_reason="public_control_artifact_unavailable",
        mismatch_reason="public_control_artifact_digest_mismatch",
    )

    canonical_results = [
        inspect_case(
            whoathere_bin=whoathere_bin,
            output_dir=output_dir,
            fixture_dir=fixture_dir,
            case=case,
            index=index,
        )
        for index, case in enumerate(canonical_cases, start=1)
    ]
    public_results = [
        inspect_case(
            whoathere_bin=whoathere_bin,
            output_dir=output_dir,
            fixture_dir=public_controls_dir,
            case=case,
            index=index,
        )
        for index, case in enumerate(public_cases, start=len(canonical_cases) + 1)
    ]
    summary = summarize(
        canonical_results + public_results,
        expected_metrics,
        baseline_manifest_sha256,
    )
    encoded = canonical_json(summary)
    (output_dir / "summary.json").write_text(encoded, encoding="utf-8")
    sys.stdout.write(encoded)
    return 0 if summary["safety"]["passed"] and summary["metric_gate"]["passed"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BaselineFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"whoathere_development_fixture_baseline=failed reason={error}", file=sys.stderr)
        raise SystemExit(1) from error
