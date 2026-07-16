#!/usr/bin/env python3
"""Synthetic self-test for approval-selected Scaleway custody staging."""

from __future__ import annotations

import hashlib
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
case "${1:-}" in
  --version) printf '%s\n' 'whoathere synthetic-selftest' ;;
  doctor|scanners) printf '%s\n' '{}' ;;
  vm) printf '%s\n' '{}' ;;
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

    print("whoathere_scaleway_staging_selftest=pass")
    print("approved_sample_count=2")
    print("mixed_acquisition_statuses=accepted")
    print("approval_selected_preflight_count=accepted")
    print("private_custody_and_staging_modes=enforced")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
