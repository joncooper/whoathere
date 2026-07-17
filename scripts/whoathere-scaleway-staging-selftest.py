#!/usr/bin/env python3
"""Synthetic self-test for approval-selected Scaleway custody staging."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile


REPO_ROOT = Path(__file__).resolve().parent.parent
BUILDER = REPO_ROOT / "scripts/whoathere-build-scaleway-staging-bundle.sh"
PREFLIGHT = REPO_ROOT / "scripts/whoathere-scaleway-host-preflight.sh"
PHASE1 = REPO_ROOT / "scripts/whoathere-scaleway-phase1.sh"
STEP5_REMOTE = REPO_ROOT / "scripts/whoathere-scaleway-step5-remote.py"
FIXTURE = REPO_ROOT / "docs/product-build-run/actual-malware-malwarebazaar-fixture.jsonl.sample"
CASE_ID = "whoathere-actual-malware-2026-07-01"
APPROVED_DIGESTS = {
    "7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9",
    "cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def fixture_rows() -> list[dict]:
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines() if line.strip()]


def create_synthetic_custody(root: Path, rows: list[dict]) -> list[dict]:
    approval_samples = []
    for fixture_row in rows:
        digest = fixture_row["sha256"]
        if digest not in APPROVED_DIGESTS:
            continue
        sample_dir = root / digest
        sample_dir.mkdir(parents=True)
        archive = sample_dir / f"{digest}.malwarebazaar.zip"
        archive.write_bytes(b"synthetic-custody-placeholder:" + digest.encode("ascii"))
        archive_sha256 = sha256_file(archive)
        sidecar = sample_dir / f"{digest}.malwarebazaar.zip.sha256"
        sidecar.write_text(f"{archive_sha256}  {archive.name}\n", encoding="utf-8")
        custody = sample_dir / "custody.json"
        write_json(
            custody,
            {
                "schema": "whoathere.actual_malware.malwarebazaar_custody.v1",
                "source": "malwarebazaar",
                "source_reference": f"malwarebazaar:sha256:{digest}",
                "sample_sha256": f"sha256:{digest}",
                "malwarebazaar_confirmed_sample_sha256": f"sha256:{digest}",
                "download_archive_sha256": archive_sha256,
                "download_archive_size_bytes": archive.stat().st_size,
                "created_at_utc": "2026-07-16T00:00:00Z",
                "allowed_test_purpose": "synthetic staging self-test",
                "collector": "synthetic-collector",
                "retention_rule": "destroy_after_selftest",
                "live_c2_allowed": False,
                "second_stage_live_fetch_allowed": False,
                "sync_back_allowed": False,
                "malwarebazaar_fixture_row": fixture_row,
                "malwarebazaar_info": {
                    "data": [
                        {
                            "file_size": 4096,
                            "first_seen": fixture_row["first_seen_utc"],
                        }
                    ]
                },
            },
        )
        approval_samples.append(
            {
                "sample_sha256": f"sha256:{digest}",
                "archive_sha256": archive_sha256,
                "custody_sha256": sha256_file(custody),
            }
        )
    require(len(approval_samples) == 2, "fixture_missing_approved_telnyx_rows")
    return approval_samples


def create_fake_remote_tools(bin_dir: Path) -> Path:
    bin_dir.mkdir(parents=True)
    ssh = bin_dir / "ssh"
    ssh.write_text(
        """#!/bin/sh
set -eu
if [ "${1:-}" = "-F" ]; then shift 2; fi
shift
exec /bin/sh -c "$1"
""",
        encoding="utf-8",
    )
    scp = bin_dir / "scp"
    scp.write_text(
        """#!/bin/sh
set -eu
if [ "${1:-}" = "-F" ]; then shift 2; fi
src=$1
dst=${2#*:}
cp "$src" "$dst"
""",
        encoding="utf-8",
    )
    whoathere = bin_dir / "whoathere"
    whoathere.write_text(
        """#!/bin/sh
set -eu
test -z "${WHOATHERE_SELFTEST_INVOCATIONS:-}" || printf '%s\n' "$*" >>"$WHOATHERE_SELFTEST_INVOCATIONS"
case "${1:-}" in
  --version) printf '%s\n' 'whoathere synthetic-selftest' ;;
  doctor)
    test -z "${WHOATHERE_SELFTEST_LEGACY_VM_UNREADY:-}" || exit 70
    printf '%s\n' '{}'
    ;;
  scanners) printf '%s\n' '{}' ;;
  vm)
    if [ "${2:-}" = "health" ] && [ -n "${WHOATHERE_SELFTEST_LEGACY_VM_UNREADY:-}" ]; then
      exit 70
    fi
    printf '%s\n' '{}'
    ;;
  artifact)
    test "${2:-}" = "inspect" || exit 64
    if [ -n "${WHOATHERE_SELFTEST_EXPECTED_ZIG:-}" ]; then
      test "$(command -v zig)" = "$WHOATHERE_SELFTEST_EXPECTED_ZIG"
    fi
    shift 2
    config=""
    while [ "$#" -gt 0 ]; do
      if [ "$1" = "--detonation-config" ]; then
        config=$2
        shift 2
      else
        shift
      fi
    done
    test -n "$config" && test -f "$config" || {
      printf '%s\n' '{"admission_authority":false,"exit_code":64,"observed_clean":false,"reason_codes":["linux_vz_exact_wheel_input_invalid"],"schema_version":"whoathere.exact_artifact_inspection.v1","status":"error","sync_back_enabled":false}'
      exit 64
    }
    printf '%s\n' '{"admission_authority":false,"exit_code":64,"observed_clean":false,"reason_codes":["exact_artifact_path_unreadable"],"schema_version":"whoathere.exact_artifact_inspection.v1","status":"error","sync_back_enabled":false}'
    exit 64
    ;;
  *) exit 64 ;;
esac
""",
        encoding="utf-8",
    )
    for path in (ssh, scp, whoathere):
        path.chmod(0o700)
    return whoathere


def assert_private_tree(root: Path) -> None:
    for path in (root, *root.rglob("*")):
        mode = stat.S_IMODE(path.stat().st_mode)
        require(mode & 0o077 == 0, f"path_not_private={path}:{oct(mode)}")


def load_module(path: Path, name: str) -> object:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"module_load_failed={path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> int:
    rows = fixture_rows()
    with tempfile.TemporaryDirectory(prefix="whoathere-scaleway-staging-selftest-") as temp:
        temp_root = Path(temp)
        quarantine = temp_root / "quarantine"
        case_root = quarantine / CASE_ID / "malwarebazaar"
        case_root.mkdir(parents=True)
        approval_samples = create_synthetic_custody(case_root, rows)

        results = []
        for index, row in enumerate(rows):
            results.append(
                {
                    "sample_id": row["sample_id"],
                    "sample_sha256": f"sha256:{row['sha256']}",
                    "status": "acquired" if index == 0 else "skipped_existing",
                }
            )
        results_path = case_root / "bulk-acquisition-results.jsonl"
        results_path.write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in results),
            encoding="utf-8",
        )
        summary_path = case_root / "bulk-acquisition-summary.json"
        write_json(
            summary_path,
            {
                "schema": "whoathere.actual_malware.malwarebazaar_bulk_acquisition.v1",
                "case_id": CASE_ID,
                "fixture_sha256": sha256_file(FIXTURE),
                "requested_count": 20,
                "fixture_row_count": 20,
                "status_counts": {"acquired": 1, "skipped_existing": 19},
                "results": results,
            },
        )

        approval = temp_root / "additive-two-telnyx-approval.json"
        write_json(
            approval,
            {
                "schema": "whoathere.actual_malware.custody_review_approval.v1",
                "review_decision": "approved_for_corpus_promotion_and_controlled_staging",
                "reviewer": "synthetic-reviewer",
                "scope": {
                    "fixture_sha256": sha256_file(FIXTURE),
                    "bulk_summary_sha256": sha256_file(summary_path),
                    "bulk_results_sha256": sha256_file(results_path),
                    "sample_count": 2,
                },
                "samples": approval_samples,
            },
        )

        out_root = temp_root / "staging"
        build = subprocess.run(
            [
                str(BUILDER),
                "--case-id",
                CASE_ID,
                "--quarantine-root",
                str(quarantine),
                "--out-root",
                str(out_root),
                "--custody-review-approval",
                str(approval),
                "--security-lab-owner",
                "synthetic-security-owner",
                "--evaluation-owner",
                "synthetic-evaluation-owner",
                "--legal-provider-approval-ref",
                "synthetic-provider-approval",
            ],
            cwd=REPO_ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(build.returncode == 0, f"builder_failed={build.stderr}")
        bundle_record = json.loads(build.stdout)
        require(bundle_record["sample_count"] == 2, "bundle_sample_count_not_approval_selected")
        bundle = Path(bundle_record["bundle_path"])
        stage_root = Path(bundle_record["stage_root"])
        manifest = json.loads((stage_root / "metadata/staging-manifest.json").read_text(encoding="utf-8"))
        staged_digests = {row["sample_sha256"].removeprefix("sha256:") for row in manifest["samples"]}
        require(staged_digests == APPROVED_DIGESTS, f"staged_digest_mismatch={staged_digests}")
        require(len(list((stage_root / "samples/malwarebazaar").iterdir())) == 2, "unapproved_sample_staged")
        assert_private_tree(case_root)
        assert_private_tree(stage_root)
        require(stat.S_IMODE(approval.stat().st_mode) == 0o600, "external_approval_not_private")
        require(stat.S_IMODE(bundle.stat().st_mode) == 0o600, "bundle_not_private")
        with tarfile.open(bundle, "r:gz") as archive:
            require(all(member.mode & 0o077 == 0 for member in archive.getmembers()), "tar_member_not_private")

        fake_bin = temp_root / "fake-bin"
        fake_whoathere = create_fake_remote_tools(fake_bin)
        remote_root = temp_root / "remote-lab"
        preflight_command = [
            str(PREFLIGHT),
            "--ssh-host",
            "synthetic-host",
            "--remote-root",
            str(remote_root),
            "--state-dir",
            str(temp_root / "synthetic-state"),
            "--whoathere-bin",
            str(fake_whoathere),
            "--bundle",
            str(bundle),
            "--bundle-sha256",
            bundle_record["bundle_sha256"],
            "--stage-bundle",
        ]
        environment = dict(os.environ)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"

        bundle.chmod(0o644)
        rejected = subprocess.run(
            preflight_command,
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(rejected.returncode != 0, "public_bundle_was_not_rejected")
        require("local_bundle_permissions_not_private" in rejected.stderr, rejected.stderr)
        bundle.chmod(0o600)

        preflight = subprocess.run(
            preflight_command,
            cwd=REPO_ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(preflight.returncode == 0, f"preflight_failed={preflight.stderr}")
        manifest_check = json.loads(
            (remote_root / "evidence/preflight/staging-manifest-check.json").read_text(encoding="utf-8")
        )
        require(manifest_check["valid"] is True, manifest_check)
        require(manifest_check["sample_count"] == 2, manifest_check)
        require(manifest_check["approval_sample_count"] == 2, manifest_check)
        assert_private_tree(remote_root)

        detonation_config = temp_root / "exact-wheel-detonation-config.json"
        write_json(detonation_config, {"artifact_kind": "pypi_wheel", "selftest": True})
        detonation_config.chmod(0o600)
        detonation_config_sha256 = sha256_file(detonation_config)
        invocation_log = temp_root / "whoathere-invocations.log"
        invocation_log.write_text("", encoding="utf-8")
        legacy_phase1_environment = dict(environment)
        legacy_phase1_environment["WHOATHERE_SELFTEST_INVOCATIONS"] = str(invocation_log)
        legacy_phase1 = subprocess.run(
            [
                str(PHASE1),
                "--ssh-host",
                "synthetic-host",
                "--remote-root",
                str(remote_root),
                "--stage-dir",
                str(Path(manifest_check["staging_manifest"]).parent.parent),
                "--state-dir",
                str(temp_root / "synthetic-state"),
                "--whoathere-bin",
                str(fake_whoathere),
                "--security-lab-owner",
                "synthetic-security-owner",
                "--evaluation-owner",
                "synthetic-evaluation-owner",
                "--phase",
                "guardrails",
            ],
            cwd=REPO_ROOT,
            env=legacy_phase1_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(legacy_phase1.returncode == 0, f"legacy_phase1_failed={legacy_phase1.stderr}")
        legacy_guardrails = json.loads(legacy_phase1.stdout)["guardrails"]
        require(legacy_guardrails["ready_for_benign_dry_run"] is True, legacy_guardrails)
        require("vm_health" in legacy_guardrails["commands"], legacy_guardrails["commands"])
        legacy_invocations = invocation_log.read_text(encoding="utf-8").splitlines()
        require(any(line.startswith("scanners list ") for line in legacy_invocations), legacy_invocations)

        invocation_log.write_text("", encoding="utf-8")
        exact_environment = dict(environment)
        exact_environment["WHOATHERE_SELFTEST_LEGACY_VM_UNREADY"] = "1"
        exact_environment["WHOATHERE_SELFTEST_INVOCATIONS"] = str(invocation_log)
        exact_preflight_command = [
            str(PREFLIGHT),
            "--ssh-host",
            "synthetic-host",
            "--remote-root",
            str(remote_root),
            "--state-dir",
            str(temp_root / "synthetic-state"),
            "--whoathere-bin",
            str(fake_whoathere),
            "--execution-path",
            "exact_artifact_diagnostic",
            "--detonation-config",
            str(detonation_config),
            "--detonation-config-sha256",
            detonation_config_sha256,
        ]
        exact_preflight = subprocess.run(
            exact_preflight_command,
            cwd=REPO_ROOT,
            env=exact_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(exact_preflight.returncode == 0, f"exact_preflight_failed={exact_preflight.stderr}")
        exact_preflight_summary = json.loads(
            (remote_root / "evidence/preflight/actual-malware-preflight-summary.json").read_text(
                encoding="utf-8"
            )
        )
        require(
            exact_preflight_summary["execution_path"] == "exact_artifact_diagnostic"
            and exact_preflight_summary["ready_for_sample_workspace_preparation"] is True,
            exact_preflight_summary,
        )
        require(
            exact_preflight_summary["exact_artifact_readiness"]["detonation_config_sha256"]
            == detonation_config_sha256,
            exact_preflight_summary,
        )
        exact_invocations = invocation_log.read_text(encoding="utf-8").splitlines()
        require(any(line.startswith("artifact inspect ") for line in exact_invocations), exact_invocations)
        require(not any(line.startswith("doctor ") for line in exact_invocations), exact_invocations)
        require(not any(line.startswith("vm health ") for line in exact_invocations), exact_invocations)

        remote_stage_dir = Path(manifest_check["staging_manifest"]).parent.parent
        sudo_pf_info = remote_root / "evidence/preflight/host-firewall-sudo-info.out"
        sudo_pf_info.write_text("Status: Enabled\n", encoding="utf-8")
        sudo_pf_info.chmod(0o600)
        execution_tools_bin = temp_root / "execution-tools-bin"
        execution_tools_bin.mkdir(mode=0o700)
        fake_zig = execution_tools_bin / "zig"
        fake_zig.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_zig.chmod(0o500)
        exact_environment["WHOATHERE_SELFTEST_EXPECTED_ZIG"] = str(fake_zig)
        phase1_common = [
            str(PHASE1),
            "--ssh-host",
            "synthetic-host",
            "--remote-root",
            str(remote_root),
            "--stage-dir",
            str(remote_stage_dir),
            "--state-dir",
            str(temp_root / "synthetic-state"),
            "--whoathere-bin",
            str(fake_whoathere),
            "--execution-path",
            "exact_artifact_diagnostic",
            "--detonation-config",
            str(detonation_config),
            "--detonation-config-sha256",
            detonation_config_sha256,
            "--execution-tools-bin",
            str(execution_tools_bin),
            "--security-lab-owner",
            "synthetic-security-owner",
            "--evaluation-owner",
            "synthetic-evaluation-owner",
            "--provider-approval-ref",
            "synthetic-provider-approval",
            "--legal-provider-approval-ref",
            "synthetic-legal-approval",
            "--cloud-firewall-default-deny-asserted",
            "--sinkhole-ready-asserted",
            "--sinkhole-reference",
            "synthetic-sinkhole",
            "--phase",
            "guardrails",
        ]
        phase1_lock = list(phase1_common)
        phase1_lock[-1] = "lock"
        locked = subprocess.run(
            phase1_lock,
            cwd=REPO_ROOT,
            env=exact_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(locked.returncode == 0, f"exact_phase1_lock_failed={locked.stderr}")
        locked_state = json.loads(locked.stdout)["state_lock"]
        require(locked_state["valid"] is True, locked_state)
        require(
            locked_state["execution_binding"]["detonation_config_sha256"]
            == detonation_config_sha256,
            locked_state,
        )

        alternate_config = temp_root / "alternate-exact-wheel-detonation-config.json"
        write_json(alternate_config, {"artifact_kind": "pypi_wheel", "selftest": "alternate"})
        alternate_config.chmod(0o600)
        mismatched_lock_args = list(phase1_common)
        mismatched_lock_args[
            mismatched_lock_args.index("--detonation-config") + 1
        ] = str(alternate_config)
        mismatched_lock_args[
            mismatched_lock_args.index("--detonation-config-sha256") + 1
        ] = sha256_file(alternate_config)
        mismatched_lock = subprocess.run(
            mismatched_lock_args,
            cwd=REPO_ROOT,
            env=exact_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(mismatched_lock.returncode == 64, mismatched_lock.stderr)
        require(
            "state_lock_execution_or_stage_binding_mismatch" in mismatched_lock.stderr,
            mismatched_lock.stderr,
        )

        bad_phase1 = list(phase1_common)
        bad_phase1[bad_phase1.index("--detonation-config-sha256") + 1] = "sha256:" + "0" * 64
        rejected_phase1 = subprocess.run(
            bad_phase1,
            cwd=REPO_ROOT,
            env=exact_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(rejected_phase1.returncode == 64, rejected_phase1.stderr)
        require("detonation_config_sha256_mismatch" in rejected_phase1.stderr, rejected_phase1.stderr)

        invocation_log.write_text("", encoding="utf-8")
        phase1 = subprocess.run(
            phase1_common,
            cwd=REPO_ROOT,
            env=exact_environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        require(phase1.returncode == 0, f"exact_phase1_failed={phase1.stderr}")
        phase1_result = json.loads(phase1.stdout)
        exact_guardrails = phase1_result["guardrails"]
        require(exact_guardrails["ready_for_exact_artifact_diagnostic"] is True, exact_guardrails)
        require(exact_guardrails["ready_for_benign_dry_run"] is False, exact_guardrails)
        require(exact_guardrails["ready_for_live_malware_rehearsal"] is True, exact_guardrails)
        require(exact_guardrails["exact_artifact_readiness"]["valid"] is True, exact_guardrails)
        require("vm_health" not in exact_guardrails["commands"], exact_guardrails["commands"])
        phase1_invocations = invocation_log.read_text(encoding="utf-8").splitlines()
        require(not any(line.startswith("scanners list ") for line in phase1_invocations), phase1_invocations)

        step5_module = load_module(STEP5_REMOTE, "whoathere_step5_readiness_selftest")
        corpus_rows = [
            json.loads(line)
            for line in (remote_stage_dir / "metadata/corpus_manifest.jsonl").read_text(
                encoding="utf-8"
            ).splitlines()
            if line.strip()
        ]
        sample_id = corpus_rows[0]["sample_id"]
        live_gate_args = argparse.Namespace(
            whoathere_bin=fake_whoathere,
            state_dir=temp_root / "synthetic-state",
            timeout_seconds=30,
            execution_path="exact_artifact_diagnostic",
            detonation_config=detonation_config,
            detonation_config_sha256=detonation_config_sha256,
            sinkhole_ready_asserted=True,
            egress_deny_asserted=False,
            cloud_firewall_default_deny_asserted=True,
            live_malware_execution_approved=True,
            lulu_enabled_asserted=True,
            lulu_reference="synthetic-lulu",
            sinkhole_reference="synthetic-sinkhole",
            provider_approval_ref="synthetic-provider-approval",
            legal_provider_approval_ref="synthetic-legal-approval",
            restricted_source_hosted_review_approved=False,
            restricted_source_review_approval_ref="",
            restricted_behavior_hosted_review_approved=True,
            restricted_behavior_review_approval_ref="synthetic-behavior-approval",
        )
        invocation_log.write_text("", encoding="utf-8")
        live_gate = step5_module.verify_live_gate(
            remote_root,
            remote_stage_dir,
            live_gate_args,
            sample_id,
            "synthetic-exact-live-gate",
        )
        require(live_gate["ready_for_single_malware_rehearsal"] is True, live_gate)
        require("vm_health" not in live_gate["commands"], live_gate["commands"])
        require(
            live_gate["phase1_execution_readiness"]["detonation_config_sha256"]
            == detonation_config_sha256,
            live_gate,
        )
        step5_invocations = invocation_log.read_text(encoding="utf-8").splitlines()
        require(not any(line.startswith("vm health ") for line in step5_invocations), step5_invocations)
        require(not any(line.startswith("scanners list ") for line in step5_invocations), step5_invocations)

    print("whoathere_scaleway_staging_selftest=pass")
    print("approved_sample_count=2")
    print("mixed_acquisition_statuses=accepted")
    print("approval_selected_preflight_count=accepted")
    print("private_custody_and_staging_modes=enforced")
    print("exact_artifact_config_readiness=verified_without_vm_execution")
    print("exact_artifact_live_gate=consumes_phase1_readiness")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
