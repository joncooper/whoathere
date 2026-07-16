#!/usr/bin/env python3
"""Self-test the non-claim-bearing canonical fixture baseline runner."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts/whoathere-development-fixture-baseline.py"


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
active = "canary" in name
if active and "npm" in name:
    status, verdict, exit_code, behavior_count = "findings", "malicious", 20, 1
elif active:
    status, verdict, exit_code, behavior_count = "inconclusive", "inconclusive", 22, 0
elif "wheel" in name:
    status, verdict, exit_code, behavior_count = "findings", "malicious", 20, 1
elif "sdist" in name:
    status, verdict, exit_code, behavior_count = "unsupported", "unsupported", 22, 0
else:
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


def run_runner(
    fake_cli: Path,
    output_dir: Path,
    invocations: Path,
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


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whoathere-development-baseline-selftest-") as raw:
        temp = Path(raw)
        fake_cli = temp / "whoathere-fake"
        fake_cli.write_text(FAKE_CLI, encoding="utf-8")
        fake_cli.chmod(0o755)
        invocations = temp / "invocations.jsonl"

        first_output = temp / "first"
        first = run_runner(fake_cli, first_output, invocations)
        require(first.returncode == 0, f"development_metrics_must_not_fail_harness:{first.stderr}")
        summary = json.loads(first.stdout)
        require(
            summary.get("baseline_kind") == "non_claim_bearing_development_baseline",
            "baseline_label_invalid",
        )
        require(summary.get("claim_bearing") is False, "claim_boundary_invalid")
        metrics = summary.get("metrics", {})
        require(metrics.get("active_total") == 3, "active_total_invalid")
        require(metrics.get("active_malicious_count") == 1, "active_malicious_count_invalid")
        require(metrics.get("active_miss_count") == 2, "active_miss_count_invalid")
        require(metrics.get("benign_total") == 3, "benign_total_invalid")
        require(metrics.get("benign_false_malicious_count") == 1, "benign_false_count_invalid")
        require(metrics.get("benign_friction_count") == 2, "benign_friction_count_invalid")
        require(summary.get("safety", {}).get("passed") is True, "safe_baseline_not_safe")
        require((first_output / "summary.json").read_text(encoding="utf-8") == first.stdout, "summary_not_canonical_or_bound")
        require(len(list((first_output / "reports").glob("*.json"))) == 6, "per_case_report_count_invalid")
        for case in summary["cases"]:
            report_bytes = (first_output / case["report_path"]).read_bytes()
            require(
                case["report_sha256"] == "sha256:" + hashlib.sha256(report_bytes).hexdigest(),
                f"report_digest_binding_invalid:{case['sample_id']}",
            )

        calls = [json.loads(line) for line in invocations.read_text(encoding="utf-8").splitlines()]
        require(len(calls) == 6, "invocation_count_invalid")
        state_dirs: set[str] = set()
        for call in calls:
            require(call[:2] == ["artifact", "inspect"], "exact_artifact_command_missing")
            require("--acquired-at" in call and "2026-07-15T00:00:00Z" in call, "fixed_acquired_at_missing")
            require("--state-dir" in call, "state_dir_missing")
            state_dirs.add(call[call.index("--state-dir") + 1])
            joined = " ".join(call).lower()
            require("expectations" not in joined and "sealed" not in joined, "expectations_passed_to_scanner")
            require("--ai-review" not in call and "--detonation" not in call, "optional_analysis_unexpected")
        require(len(state_dirs) == 6, "state_directories_not_unique")

        fixture_dir = first_output / "fixtures"
        unsafe_output = temp / "unsafe"
        unsafe = run_runner(
            fake_cli,
            unsafe_output,
            invocations,
            fixture_dir=fixture_dir,
            unsafe_filename="whoathere-fixture-npm-ci-neighbor-1.0.0.tgz",
        )
        require(unsafe.returncode != 0, "observed_clean_violation_not_rejected")
        unsafe_summary = json.loads(unsafe.stdout)
        require(unsafe_summary["safety"]["passed"] is False, "unsafe_summary_marked_safe")
        require(
            unsafe_summary["safety"]["observed_clean_violations"]
            == ["fixture-npm-ci-neighbor-v1"],
            "observed_clean_violation_not_reported",
        )

        mismatch_output = temp / "mismatch"
        mismatch = run_runner(
            fake_cli,
            mismatch_output,
            invocations,
            fixture_dir=fixture_dir,
            mismatch_filename="whoathere_fixture_wheel_canary-1.0.0-py3-none-any.whl",
        )
        require(mismatch.returncode != 0, "process_report_exit_mismatch_not_rejected")
        require(
            "inspection_process_report_exit_mismatch:fixture-wheel-canary-v1" in mismatch.stderr,
            "process_report_exit_mismatch_reason_missing",
        )

    print("whoathere_development_fixture_baseline_selftest=ok cases=6")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SelftestFailure, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"whoathere_development_fixture_baseline_selftest=failed reason={error}", file=sys.stderr)
        raise SystemExit(1) from error
