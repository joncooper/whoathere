#!/usr/bin/env python3
"""Focused synthetic self-test for Step 5 exact-artifact preparation-only mode."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import zipfile


ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "scripts" / "whoathere-scaleway-step5.sh"


def sha256_file(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def require(condition: bool, message: object) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whoathere-step5-prepare-only-") as temporary:
        root = Path(temporary).resolve()
        remote_root = root / "remote-lab"
        stage = remote_root / "staged" / "stage-20260717T000000Z"
        metadata = stage / "metadata"
        metadata.mkdir(parents=True)
        artifact_name = "synthetic_fixture-1.0-py3-none-any.whl"
        artifact_bytes = b"synthetic inert wheel fixture; never execute\n"
        artifact_sha256 = "sha256:" + hashlib.sha256(artifact_bytes).hexdigest()
        sample_id = "synthetic-pypi-prepare-only"
        sample = {
            "sample_id": sample_id,
            "sample_kind": "malware",
            "expected_result": "malicious",
            "execution_eligible_initial_package_run": True,
            "ecosystem": "pypi",
            "package_name": "synthetic-fixture",
            "package_version": "1.0",
            "artifact_filename": artifact_name,
            "artifact_sha256": artifact_sha256,
            "network_policy": "sinkhole_only",
            "live_c2_allowed": False,
            "second_stage_live_fetch_allowed": False,
            "sync_back_allowed": False,
            "approvals": {"two_person_approval": True, "legal_provider_approval": True},
        }
        (metadata / "corpus_manifest.jsonl").write_text(
            json.dumps(sample, sort_keys=True) + "\n", encoding="utf-8"
        )
        (metadata / "run_matrix.todo.csv").write_text(
            'sample_id,workspace,tool,tool_args_json,timeout_seconds,network_policy,mode\n'
            f'{sample_id},TODO,pip,"[""install""]",60,sinkhole_only,intake\n',
            encoding="utf-8",
        )
        write_json(metadata / "staging-manifest.json", {"schema": "synthetic-stage.v1"})

        digest = artifact_sha256.removeprefix("sha256:")
        sample_dir = stage / "samples" / "malwarebazaar" / digest
        sample_dir.mkdir(parents=True)
        archive = sample_dir / f"{digest}.malwarebazaar.zip"
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_STORED) as outer:
            outer.writestr(artifact_name, artifact_bytes)
        archive_sha256 = sha256_file(archive)
        (sample_dir / f"{digest}.malwarebazaar.zip.sha256").write_text(
            f"{archive_sha256}  {archive.name}\n", encoding="utf-8"
        )
        write_json(
            sample_dir / "custody.json",
            {
                "sample_sha256": artifact_sha256,
                "download_archive_sha256": archive_sha256,
                "live_c2_allowed": False,
                "second_stage_live_fetch_allowed": False,
                "sync_back_allowed": False,
            },
        )

        state_lock = {
            "schema": "whoathere.actual_malware.scaleway_phase1.state_lock.v1",
            "valid": True,
            "remote_root": str(remote_root),
            "provider_approval_ref": "synthetic-provider",
            "legal_provider_approval_ref": "synthetic-legal",
            "execution_binding": {
                "execution_path": "exact_artifact_diagnostic",
                "valid": True,
            },
            "stage": {
                "stage_dir": str(stage),
                "manifest_sha256": sha256_file(metadata / "staging-manifest.json"),
                "corpus_sha256": sha256_file(metadata / "corpus_manifest.jsonl"),
                "run_matrix_sha256": sha256_file(metadata / "run_matrix.todo.csv"),
            },
        }
        write_json(remote_root / "evidence" / "phase1" / "state-lock.json", state_lock)

        fake_bin = root / "fake-bin"
        fake_bin.mkdir()
        invocation_log = root / "whoathere-invocations.log"
        invocation_log.write_text("", encoding="utf-8")
        fake_whoathere = fake_bin / "whoathere"
        fake_whoathere.write_text(
            f"#!/bin/sh\nprintf '%s\\n' \"$*\" >>'{invocation_log}'\nexit 99\n",
            encoding="utf-8",
        )
        fake_whoathere.chmod(0o700)
        (fake_bin / "ssh").write_text(
            "#!/bin/sh\nset -eu\n[ \"${1:-}\" != -F ] || shift 2\nshift\nexec /bin/sh -c \"$1\"\n",
            encoding="utf-8",
        )
        (fake_bin / "scp").write_text(
            "#!/bin/sh\nset -eu\n[ \"${1:-}\" != -F ] || shift 2\nsrc=$1\ndst=${2#*:}\ncp \"$src\" \"$dst\"\n",
            encoding="utf-8",
        )
        for command in (fake_bin / "ssh", fake_bin / "scp"):
            command.chmod(0o700)

        run_id = "run-prepare-only-selftest"
        command = [
            str(WRAPPER),
            "--ssh-host", "synthetic-host",
            "--remote-root", str(remote_root),
            "--stage-dir", str(stage),
            "--state-dir", str(root / "unused-state"),
            "--whoathere-bin", str(fake_whoathere),
            "--execution-path", "exact_artifact_diagnostic",
            "--prepare-only",
            "--sample-id", sample_id,
            "--run-id", run_id,
            "--provider-approval-ref", "synthetic-provider",
            "--legal-provider-approval-ref", "synthetic-legal",
        ]
        environment = dict(os.environ)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        completed = subprocess.run(
            command, cwd=ROOT, env=environment, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        require(completed.returncode == 0, completed.stderr)
        summary = json.loads(completed.stdout)
        evidence = remote_root / "evidence" / "step5" / sample_id / run_id
        receipt = json.loads((evidence / "prepared-only-result.json").read_text(encoding="utf-8"))
        prepared = json.loads((evidence / "prepared-workspace.json").read_text(encoding="utf-8"))
        seal = json.loads((evidence / "step5-evidence-seal.json").read_text(encoding="utf-8"))
        require(summary["prepare_only"] is True and summary["evidence_sealed"] is True, summary)
        require(receipt["preparation_completed"] is True, receipt)
        require(receipt["physical_safety_claimed"] is False, receipt)
        require(receipt["whoathere_invoked"] is False and receipt["vm_invoked"] is False, receipt)
        require(receipt["ai_invoked"] is False and receipt["clearance_consumed"] is False, receipt)
        require(invocation_log.read_text(encoding="utf-8") == "", "whoathere_was_invoked")
        require(not (evidence / "whoathere-run").exists(), "whoathere_run_dir_created")
        require(sha256_file(Path(prepared["exact_artifact"]["path"])) == artifact_sha256, prepared)
        sealed_names = {item["path"] for item in seal["files"]}
        require(
            {"live-gate.json", "prepared-workspace.json", "prepared-only-result.json", "step5-summary.json"}
            <= sealed_names,
            seal,
        )

        rejected = subprocess.run(
            command + ["--live-malware-execution-approved"], cwd=ROOT, env=environment,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        require(rejected.returncode == 64, rejected)
        require("prepare_only_rejects_live_malware_execution_approval" in rejected.stderr, rejected.stderr)

        invalid_schema = json.loads(json.dumps(state_lock))
        invalid_schema["schema"] = "whoathere.actual_malware.scaleway_phase1.state_lock.v0"
        invalid_lock = json.loads(json.dumps(state_lock))
        invalid_lock["valid"] = False
        wrong_root = json.loads(json.dumps(state_lock))
        wrong_root["remote_root"] = str(root / "different-remote-root")
        wrong_execution_path = json.loads(json.dumps(state_lock))
        wrong_execution_path["execution_binding"]["execution_path"] = (
            "legacy_workspace_non_claim_bearing"
        )
        rejection_cases = (
            (
                "invalid-schema",
                invalid_schema,
                None,
                None,
                "phase1_state_lock_schema_invalid",
            ),
            (
                "invalid-lock",
                invalid_lock,
                None,
                None,
                "phase1_state_lock_not_valid",
            ),
            (
                "wrong-root",
                wrong_root,
                None,
                None,
                "phase1_state_lock_remote_root_mismatch",
            ),
            (
                "wrong-execution-path",
                wrong_execution_path,
                None,
                None,
                "phase1_exact_artifact_execution_binding_not_valid",
            ),
            (
                "wrong-provider-approval",
                state_lock,
                "--provider-approval-ref",
                "different-provider-approval",
                "phase1_provider_approval_ref_mismatch",
            ),
            (
                "wrong-legal-approval",
                state_lock,
                "--legal-provider-approval-ref",
                "different-legal-approval",
                "phase1_legal_provider_approval_ref_mismatch",
            ),
        )
        for suffix, lock_value, changed_option, changed_value, expected_reason in rejection_cases:
            write_json(remote_root / "evidence" / "phase1" / "state-lock.json", lock_value)
            rejected_command = list(command)
            rejected_command[rejected_command.index("--run-id") + 1] = (
                f"run-prepare-only-{suffix}"
            )
            if changed_option is not None:
                rejected_command[rejected_command.index(changed_option) + 1] = changed_value
            rejected_run = subprocess.run(
                rejected_command, cwd=ROOT, env=environment,
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            require(rejected_run.returncode == 64, rejected_run)
            require(expected_reason in rejected_run.stderr, rejected_run.stderr)

    print("whoathere_scaleway_step5_prepare_only_selftest=pass")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
