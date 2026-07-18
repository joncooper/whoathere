#!/usr/bin/env python3
"""Self-test the frozen, non-claim-bearing development baseline runner."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/whoathere-development-fixture-baseline.py"
TRACKED_MANIFEST = ROOT / "whoathere/tests/fixtures/development-baseline-manifest-v1.json"


class SelftestFailure(RuntimeError):
    pass


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise SelftestFailure(reason)


FAKE_CLI = r'''#!/usr/bin/env python3
import hashlib
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
if len(args) != 9 or args[:2] != ["artifact", "inspect"]:
    raise SystemExit(64)
artifact = Path(args[2])
digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
name = artifact.name
status, verdict, exit_code, behavior_count = "inconclusive", "inconclusive", 22, 0
unsafe = os.environ.get("WHOATHERE_BASELINE_SELFTEST_UNSAFE") == name
exit_mismatch = os.environ.get("WHOATHERE_BASELINE_SELFTEST_EXIT_MISMATCH") == name
report = {
    "schema_version": "whoathere.exact_artifact_inspection.v1",
    "status": status,
    "verdict": verdict,
    "exit_code": exit_code + (1 if exit_mismatch else 0),
    "identity": {"artifact_sha256": "sha256:" + digest},
    "behavior_detection_count": behavior_count,
    "admission_authority": False,
    "observed_clean": unsafe,
    "sync_back_enabled": False,
}
invocations = Path(os.environ["WHOATHERE_BASELINE_SELFTEST_INVOCATIONS"])
with invocations.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args, separators=(",", ":")) + "\n")
print(json.dumps(report, sort_keys=True))
raise SystemExit(exit_code)
'''


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def prepare_public_controls(temp: Path) -> tuple[Path, Path, dict[str, object]]:
    manifest = json.loads(TRACKED_MANIFEST.read_text(encoding="utf-8"))
    require(
        manifest.get("schema_version") == "whoathere.development_baseline_manifest.v1",
        "tracked_manifest_schema_invalid",
    )
    controls = manifest.get("public_benign_controls")
    require(isinstance(controls, list) and len(controls) == 5, "tracked_controls_invalid")
    controls_dir = temp / "public-controls"
    controls_dir.mkdir()
    for control in controls:
        require(isinstance(control, dict), "tracked_control_invalid")
        payload = f"inert public control: {control['sample_id']}\n".encode()
        (controls_dir / str(control["artifact_filename"])).write_bytes(payload)
        control["artifact_sha256"] = hashlib.sha256(payload).hexdigest()
    manifest_path = temp / "baseline-manifest.json"
    write_json(manifest_path, manifest)
    return manifest_path, controls_dir, manifest


def run_runner(
    fake_cli: Path,
    output_dir: Path,
    invocations: Path,
    manifest_path: Path,
    public_controls_dir: Path,
    *,
    fixture_dir: Path | None = None,
    unsafe_filename: str | None = None,
    mismatch_filename: str | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        sys.executable,
        str(RUNNER),
        "--whoathere-bin",
        str(fake_cli),
        "--output-dir",
        str(output_dir),
        "--baseline-manifest",
        str(manifest_path),
        "--public-controls-dir",
        str(public_controls_dir),
    ]
    if fixture_dir is not None:
        command.extend(["--fixture-dir", str(fixture_dir)])
    env = dict(os.environ)
    env["WHOATHERE_BASELINE_SELFTEST_INVOCATIONS"] = str(invocations)
    if unsafe_filename is not None:
        env["WHOATHERE_BASELINE_SELFTEST_UNSAFE"] = unsafe_filename
    if mismatch_filename is not None:
        env["WHOATHERE_BASELINE_SELFTEST_EXIT_MISMATCH"] = mismatch_filename
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def require_manifest_rejected(
    *,
    fake_cli: Path,
    temp: Path,
    invocations: Path,
    controls_dir: Path,
    manifest: dict[str, object],
    label: str,
    reason: str,
) -> None:
    manifest_path = temp / f"{label}-manifest.json"
    write_json(manifest_path, manifest)
    completed = run_runner(
        fake_cli,
        temp / f"{label}-output",
        invocations,
        manifest_path,
        controls_dir,
    )
    require(completed.returncode != 0, f"{label}_manifest_accepted")
    require(reason in completed.stderr, f"{label}_rejection_reason_missing:{completed.stderr}")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whoathere-development-baseline-selftest-") as raw:
        temp = Path(raw)
        fake_cli = temp / "whoathere-fake"
        fake_cli.write_text(FAKE_CLI, encoding="utf-8")
        fake_cli.chmod(0o755)
        invocations = temp / "invocations.jsonl"
        manifest_path, controls_dir, manifest = prepare_public_controls(temp)

        first_output = temp / "first"
        first = run_runner(
            fake_cli,
            first_output,
            invocations,
            manifest_path,
            controls_dir,
        )
        require(first.returncode == 0, f"frozen_baseline_failed:{first.stderr}")
        summary = json.loads(first.stdout)
        require(
            summary.get("baseline_kind") == "non_claim_bearing_development_baseline",
            "baseline_label_invalid",
        )
        require(summary.get("claim_bearing") is False, "claim_boundary_invalid")
        require(summary.get("metric_gate", {}).get("passed") is True, "metric_gate_failed")
        metrics = summary.get("metrics", {})
        require(metrics.get("active_total") == 3, "active_total_invalid")
        require(metrics.get("active_behavior_positive_count") == 0, "active_positive_invalid")
        require(metrics.get("active_miss_count") == 3, "active_miss_count_invalid")
        require(metrics.get("active_review_count") == 3, "active_review_count_invalid")
        require(metrics.get("canonical_benign_total") == 3, "canonical_benign_total_invalid")
        require(
            metrics.get("canonical_benign_false_malicious_count") == 0,
            "canonical_benign_false_count_invalid",
        )
        require(metrics.get("public_benign_total") == 5, "public_benign_total_invalid")
        require(
            metrics.get("public_benign_false_malicious_count") == 0,
            "public_benign_false_count_invalid",
        )
        require(summary.get("safety", {}).get("passed") is True, "safe_baseline_not_safe")
        require(
            (first_output / "summary.json").read_text(encoding="utf-8") == first.stdout,
            "summary_not_canonical_or_bound",
        )
        require(len(list((first_output / "reports").glob("*.json"))) == 11, "report_count_invalid")
        for case in summary["cases"]:
            report_bytes = (first_output / case["report_path"]).read_bytes()
            require(
                case["report_sha256"] == "sha256:" + hashlib.sha256(report_bytes).hexdigest(),
                f"report_digest_binding_invalid:{case['sample_id']}",
            )

        calls = [json.loads(line) for line in invocations.read_text(encoding="utf-8").splitlines()]
        require(len(calls) == 11, "invocation_count_invalid")
        state_dirs: set[str] = set()
        for call in calls:
            require(call[:2] == ["artifact", "inspect"], "exact_artifact_command_missing")
            require(
                "--acquired-at" in call and "2026-07-15T00:00:00Z" in call,
                "fixed_acquired_at_missing",
            )
            require("--state-dir" in call, "state_dir_missing")
            state_dirs.add(call[call.index("--state-dir") + 1])
            joined = " ".join(call).lower()
            require("expectations" not in joined and "sealed" not in joined, "expectations_passed_to_scanner")
            require("--ai-review" not in call and "--detonation" not in call, "optional_analysis_unexpected")
        require(len(state_dirs) == 11, "state_directories_not_unique")

        fixture_dir = first_output / "fixtures"
        unsafe = run_runner(
            fake_cli,
            temp / "unsafe",
            invocations,
            manifest_path,
            controls_dir,
            fixture_dir=fixture_dir,
            unsafe_filename="whoathere-fixture-npm-ci-neighbor-1.0.0.tgz",
        )
        require(unsafe.returncode != 0, "observed_clean_violation_not_rejected")
        require(json.loads(unsafe.stdout)["safety"]["passed"] is False, "unsafe_marked_safe")

        mismatch = run_runner(
            fake_cli,
            temp / "exit-mismatch",
            invocations,
            manifest_path,
            controls_dir,
            fixture_dir=fixture_dir,
            mismatch_filename="whoathere_fixture_wheel_canary-1.0.0-py3-none-any.whl",
        )
        require(mismatch.returncode != 0, "process_report_exit_mismatch_not_rejected")
        require(
            "inspection_process_report_exit_mismatch:fixture-wheel-canary-v1" in mismatch.stderr,
            "process_report_exit_mismatch_reason_missing",
        )

        changed_metric_manifest = copy.deepcopy(manifest)
        changed_metric_manifest["expected_metrics"][
            "canonical_active_behavior_positive_count"
        ] = 1
        changed_metric_path = temp / "changed-metric-manifest.json"
        write_json(changed_metric_path, changed_metric_manifest)
        changed_metric = run_runner(
            fake_cli,
            temp / "changed-metric",
            invocations,
            changed_metric_path,
            controls_dir,
            fixture_dir=fixture_dir,
        )
        require(changed_metric.returncode != 0, "changed_expected_metric_did_not_fail")
        changed_summary = json.loads(changed_metric.stdout)
        require(changed_summary["metric_gate"]["passed"] is False, "metric_mismatch_hidden")
        require(
            changed_summary["metric_gate"]["mismatches"]
            == [
                {
                    "expected": 1,
                    "metric": "canonical_active_behavior_positive_count",
                    "observed": 0,
                }
            ],
            "metric_mismatch_not_exact",
        )

        duplicate = copy.deepcopy(manifest)
        duplicate["public_benign_controls"][1]["sample_id"] = duplicate[
            "public_benign_controls"
        ][0]["sample_id"]
        require_manifest_rejected(
            fake_cli=fake_cli,
            temp=temp,
            invocations=invocations,
            controls_dir=controls_dir,
            manifest=duplicate,
            label="duplicate-id",
            reason="public_control_id_invalid_or_duplicate",
        )

        unsupported = copy.deepcopy(manifest)
        unsupported["public_benign_controls"][0]["form"] = "npm_zip"
        require_manifest_rejected(
            fake_cli=fake_cli,
            temp=temp,
            invocations=invocations,
            controls_dir=controls_dir,
            manifest=unsupported,
            label="unsupported-form",
            reason="public_control_form_unsupported",
        )

        malformed = copy.deepcopy(manifest)
        malformed["public_benign_controls"][0]["artifact_sha256"] = "not-a-sha256"
        require_manifest_rejected(
            fake_cli=fake_cli,
            temp=temp,
            invocations=invocations,
            controls_dir=controls_dir,
            manifest=malformed,
            label="malformed-hash",
            reason="public_control_digest_invalid",
        )

        first_control = manifest["public_benign_controls"][0]
        tampered_path = controls_dir / first_control["artifact_filename"]
        tampered_path.write_bytes(tampered_path.read_bytes() + b"tampered\n")
        changed_bytes = run_runner(
            fake_cli,
            temp / "changed-bytes",
            invocations,
            manifest_path,
            controls_dir,
            fixture_dir=fixture_dir,
        )
        require(changed_bytes.returncode != 0, "changed_public_control_bytes_accepted")
        require(
            f"public_control_artifact_digest_mismatch:{first_control['sample_id']}"
            in changed_bytes.stderr,
            "changed_public_control_reason_missing",
        )

    print("whoathere_development_fixture_baseline_selftest=ok cases=11 public_controls=5")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SelftestFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"whoathere_development_fixture_baseline_selftest=failed reason={error}", file=sys.stderr)
        raise SystemExit(1) from error
