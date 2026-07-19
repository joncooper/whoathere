#!/usr/bin/env python3
"""Hermetic happy-path and tamper checks for the metadata-only R02b freeze tool."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "scripts" / "whoathere-freeze-four-known-miss-positive-subscore.py"
CONTRACT = ROOT / "docs" / "product-build-run" / "four-known-miss-positive-subscore-contract.v2.json"
COMPLETE_PROFILE = ROOT / "docs" / "product-build-run" / "four-known-miss-campaign-profile.v1.json"
SCHEMA_SET = ROOT / "scripts" / "whoathere-static-projection-schema-set-v1.json"
EVALUATOR = ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"{name} unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def corpus_row(contract_row: dict[str, Any]) -> dict[str, Any]:
    artifact_form = str(contract_row["artifact_form"])
    trigger = {
        "npm_tgz": "npm_lifecycle",
        "wheel": "python_import",
        "sdist": "pypi_pep517",
    }[artifact_form]
    suffix = {"npm_tgz": ".tgz", "wheel": ".whl", "sdist": ".tar.gz"}[artifact_form]
    sample_id = str(contract_row["sample_id"])
    return {
        "schema_version": "whoathere.actual_malware.corpus.v1",
        "sample_id": sample_id,
        "sample_kind": "malware",
        "ecosystem": contract_row["ecosystem"],
        "package_name": "synthetic-" + sample_id,
        "package_version": "0.0.0-r02b",
        "artifact_filename": sample_id + suffix,
        "artifact_sha256": contract_row["artifact_sha256"],
        "artifact_size_bytes": 64,
        "source_type": "lab_benign_fixture",
        "source_reference": "synthetic:r02b-freeze-selftest",
        "disclosure_date": "2026-07-01",
        "expected_result": "malicious",
        "trigger_phases": [trigger],
        "behavior_labels": list(contract_row["required_behavior_labels"]),
        "network_policy": "sinkhole_only",
        "live_c2_allowed": False,
        "second_stage_live_fetch_allowed": False,
        "sync_back_allowed": False,
        "acquisition": {
            "case_id": "synthetic-r02b-freeze",
            "allowed_test_purpose": "hermetic metadata freeze selftest",
            "acquired_at_utc": "2026-07-01T00:00:00Z",
            "collector": "selftest",
            "reviewer": "selftest",
            "authorization": "synthetic-only",
            "custody_store": "temporary-directory",
            "retention_rule": "destroy-on-close",
            "source_confidence": "synthetic",
        },
        "approvals": {
            "two_person_approval": True,
            "legal_provider_approval": True,
            "security_lab_owner": "selftest",
            "whoathere_evaluation_owner": "selftest",
        },
    }


def key_pair(directory: Path, stem: str) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl required")
    private = directory / f"{stem}-private.pem"
    public = directory / f"{stem}-public.pem"
    subprocess.run([openssl, "genpkey", "-algorithm", "ED25519", "-out", str(private)], check=True)
    subprocess.run(
        [openssl, "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True
    )
    return private, public


def write_corpus(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_bytes(b"".join(canonical(row) + b"\n" for row in rows))


def base_command(
    *, corpus: Path, verifier: Path, public_key: Path, schema: Path, revision: str,
    outputs: tuple[Path, Path, Path], verify: bool = False,
) -> list[str]:
    command = [
        str(TOOL),
        "--contract", str(CONTRACT),
        "--complete-run-profile", str(COMPLETE_PROFILE),
        "--corpus", str(corpus),
        "--verifier-executable", str(verifier),
        "--verifier-public-key", str(public_key),
        "--projection-schema", str(schema),
        "--source-revision", revision,
        "--created-at-utc", "2026-07-20T00:00:00Z",
        "--starts-at-utc", "2026-07-20T00:00:01Z",
        "--ends-at-utc", "2026-07-20T01:00:00Z",
        "--maximum-result-to-registry-seconds", "600",
        "--collection-lock-out", str(outputs[0]),
        "--evaluation-manifest-out", str(outputs[1]),
        "--freeze-receipt-out", str(outputs[2]),
    ]
    if verify:
        command.append("--verify-existing")
    return command


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)


def fresh_outputs(root: Path, stem: str) -> tuple[Path, Path, Path]:
    return (
        root / f"{stem}-lock.json",
        root / f"{stem}-manifest.json",
        root / f"{stem}-receipt.json",
    )


def require_failure(process: subprocess.CompletedProcess[str], token: str) -> None:
    require(process.returncode == 20, f"expected failure: {process.stdout} {process.stderr}")
    require(token in process.stderr, f"missing {token}: {process.stderr}")


def main() -> int:
    contract = json.loads(CONTRACT.read_text(encoding="utf-8"))
    rows = [corpus_row(row) for row in contract["rows"]]
    rows[0]["behavior_labels"].append("https_exfil")
    rows[1]["behavior_labels"].append("process_spawn")
    revision_process = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
    )
    revision = revision_process.stdout.strip()
    with tempfile.TemporaryDirectory(prefix="whoathere-r02b-freeze-selftest-") as raw_root:
        root = Path(raw_root)
        corpus = root / "corpus.jsonl"
        write_corpus(corpus, rows)
        verifier = root / "static-verifier"
        verifier.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        verifier.chmod(0o755)
        _, public_key = key_pair(root, "primary")
        _, second_public_key = key_pair(root, "second")
        schema = root / "projection-schema-set.json"
        schema.write_bytes(SCHEMA_SET.read_bytes())
        outputs = fresh_outputs(root, "happy")
        command = base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs,
        )
        happy = run(command)
        require(happy.returncode == 0, happy.stderr)
        for output in outputs:
            require(output.is_file(), f"missing output {output}")
            require(stat.S_IMODE(output.stat().st_mode) == 0o600, "output mode is not 0600")
            value = json.loads(output.read_text(encoding="utf-8"))
            require(output.read_bytes() == canonical(value), f"output is not canonical: {output}")

        lock = json.loads(outputs[0].read_text(encoding="utf-8"))
        manifest = json.loads(outputs[1].read_text(encoding="utf-8"))
        receipt = json.loads(outputs[2].read_text(encoding="utf-8"))
        require(lock["status"] == "frozen_metadata_only", "lock posture")
        require(lock["identities"]["runtime_sha256"] == "not_used", "runtime posture")
        require(lock["identities"]["sensor_sha256"] == "not_used", "sensor posture")
        require(lock["identities"]["model_identity"] == "not_used", "model posture")
        require(lock["identities"]["prompt_set_sha256"] == "not_used", "prompt posture")
        require(lock["identities"]["provider_adapter_sha256"] == "not_used", "provider posture")
        require(manifest["identities"]["policy_sha256"] == digest(outputs[0].read_bytes()), "lock binding")
        require(receipt["collection_lock_sha256"] == digest(outputs[0].read_bytes()), "receipt lock")
        require(
            receipt["evaluation_manifest_sha256"] == digest(outputs[1].read_bytes()),
            "receipt manifest",
        )
        require(len(manifest["required_runs"]) == 4, "manifest denominator")
        require(
            {(row["sample_id"], row["profile_id"]) for row in manifest["required_runs"]}
            == {(row["sample_id"], row["positive_profile_id"]) for row in contract["rows"]},
            "manifest exact slots",
        )
        evaluator = load_module("whoathere_r02b_selftest_evaluator", EVALUATOR)
        corpus_by_sample = {row["sample_id"]: row for row in rows}
        errors, _, _ = evaluator.validate_evaluation_manifest_v2(
            manifest, corpus_by_sample, digest(corpus.read_bytes())
        )
        require(errors == [], str(errors))

        verified = run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs, verify=True,
        ))
        require(verified.returncode == 0, verified.stderr)

        original_key = public_key.read_bytes()
        public_key.write_bytes(second_public_key.read_bytes())
        require_failure(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs, verify=True,
        )), "frozen_output_mismatch")
        public_key.write_bytes(original_key)

        original_tool = verifier.read_bytes()
        verifier.write_bytes(original_tool + b"# changed\n")
        require_failure(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs, verify=True,
        )), "frozen_output_mismatch")
        verifier.write_bytes(original_tool)
        verifier.chmod(0o755)

        original_schema = schema.read_bytes()
        changed_schema = copy.deepcopy(json.loads(original_schema))
        changed_schema["policies"][0]["behavior_label"] = "filesystem_scan"
        schema.write_bytes(canonical(changed_schema))
        require_failure(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs, verify=True,
        )), "projection_schema_set_invalid")
        schema.write_bytes(original_schema)

        original_corpus = corpus.read_bytes()
        changed_rows = copy.deepcopy(rows)
        changed_rows[0]["package_name"] = "changed-after-freeze"
        write_corpus(corpus, changed_rows)
        require_failure(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs, verify=True,
        )), "frozen_output_mismatch")
        corpus.write_bytes(original_corpus)

        original_manifest = outputs[1].read_bytes()
        outputs[1].write_bytes(original_manifest + b" ")
        require_failure(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs, verify=True,
        )), "frozen_output_mismatch")
        outputs[1].write_bytes(original_manifest)

        wrong_revision_outputs = fresh_outputs(root, "wrong-revision")
        require_failure(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision="0" * 40, outputs=wrong_revision_outputs,
        )), "source_revision_mismatch")
        require(not any(path.exists() for path in wrong_revision_outputs), "revision failure wrote output")

        bad_time_outputs = fresh_outputs(root, "bad-time")
        bad_time_command = base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=bad_time_outputs,
        )
        bad_time_command[bad_time_command.index("--created-at-utc") + 1] = "2026-07-20T00:00:02Z"
        require_failure(run(bad_time_command), "evaluation_window_order_invalid")
        require(not any(path.exists() for path in bad_time_outputs), "time failure wrote output")

        occupied_outputs = fresh_outputs(root, "occupied")
        occupied_outputs[0].write_text("occupied", encoding="utf-8")
        require_failure(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=occupied_outputs,
        )), "output_already_exists")
        require(not occupied_outputs[1].exists() and not occupied_outputs[2].exists(), "partial output")

        for output in outputs:
            output.chmod(0o644)
        require(run(base_command(
            corpus=corpus, verifier=verifier, public_key=public_key,
            schema=schema, revision=revision, outputs=outputs, verify=True,
        )).returncode == 0, "tracked 0644 outputs did not verify")

        freeze_module = load_module("whoathere_r02b_freeze_tool", TOOL)
        parent_process = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD^"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True,
        )
        freeze_module.validate_source_revision(parent_process.stdout.strip(), True)

    print("whoathere R02b metadata freeze self-test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
