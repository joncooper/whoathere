#!/usr/bin/env python3
"""Self-test the metadata-only four-known-miss evaluation compiler."""

from __future__ import annotations

import copy
import hashlib
import json
import runpy
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
COMPILER = REPOSITORY_ROOT / "scripts" / "whoathere-compile-four-known-miss-evaluation.py"
PROFILE_SPEC = (
    REPOSITORY_ROOT
    / "docs"
    / "product-build-run"
    / "four-known-miss-campaign-profile.v1.json"
)
SCORER_ID = "whoathere-actual-malware-evaluation.py:score-results-v2"
EVALUATOR = REPOSITORY_ROOT / "scripts" / "whoathere-actual-malware-evaluation.py"


def digest_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_corpus(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
        encoding="utf-8",
    )


def corpus_rows(profile_spec: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for profile in profile_spec["artifact_profiles"]:
        rows.append(
            {
                "schema_version": "whoathere.actual_malware.corpus.v1",
                "sample_id": profile["sample_id"],
                "sample_kind": "malware",
                "ecosystem": profile["ecosystem"],
                "artifact_sha256": profile["artifact_sha256"],
                "behavior_labels": list(profile["sealed_expected_behavior_labels"]),
                "expected_result": "malicious",
                "network_policy": "sinkhole_only",
                "live_c2_allowed": False,
                "second_stage_live_fetch_allowed": False,
                "sync_back_allowed": False,
            }
        )
    rows.append(
        {
            "schema_version": "whoathere.actual_malware.corpus.v1",
            "sample_id": "unrelated-benign-control",
            "sample_kind": "benign_control",
            "ecosystem": "npm",
            "artifact_sha256": "sha256:" + "e" * 64,
            "behavior_labels": ["benign_postinstall"],
            "expected_result": "benign",
            "network_policy": "sinkhole_only",
            "live_c2_allowed": False,
            "second_stage_live_fetch_allowed": False,
            "sync_back_allowed": False,
        }
    )
    return rows


def compile_command(corpus: Path, output: Path, profile_spec: Path = PROFILE_SPEC) -> list[str]:
    return [
        sys.executable,
        str(COMPILER),
        "--profile-spec",
        str(profile_spec),
        "--corpus",
        str(corpus),
        "--output",
        str(output),
        "--evaluation-id",
        "four-known-miss-selftest",
        "--created-at-utc",
        "2026-07-19T23:59:00Z",
        "--starts-at-utc",
        "2026-07-20T00:00:00Z",
        "--ends-at-utc",
        "2026-07-20T01:00:00Z",
        "--maximum-result-to-registry-seconds",
        "600",
        "--runtime-sha256",
        "sha256:" + "1" * 64,
        "--prompt-set-sha256",
        "sha256:" + "2" * 64,
        "--observation-schema-sha256",
        "sha256:" + "3" * 64,
        "--provider-adapter-sha256",
        "sha256:" + "4" * 64,
        "--policy-sha256",
        "sha256:" + "5" * 64,
        "--scorer-id",
        SCORER_ID,
        "--registry-id",
        "four-known-miss-registry",
        "--verifier-id",
        "four-known-miss-verifier",
        "--verifier-public-key-sha256",
        "sha256:" + "6" * 64,
        "--verifier-executable-sha256",
        "sha256:" + "7" * 64,
        "--projection-schema-sha256",
        "sha256:" + "8" * 64,
    ]


def run_compile(
    corpus: Path,
    output: Path,
    profile_spec: Path = PROFILE_SPEC,
    *,
    command_mutator: Any = None,
) -> subprocess.CompletedProcess[str]:
    command = compile_command(corpus, output, profile_spec)
    if command_mutator is not None:
        command_mutator(command)
    return subprocess.run(command, text=True, capture_output=True, check=False)


def assert_failure(result: subprocess.CompletedProcess[str], token: str, output: Path) -> None:
    assert result.returncode == 20, (result.returncode, result.stdout, result.stderr)
    assert token in result.stderr, result.stderr
    assert not output.exists(), output


def replace_argument(command: list[str], name: str, value: str) -> None:
    command[command.index(name) + 1] = value


def main() -> int:
    tracked_spec = json.loads(PROFILE_SPEC.read_text(encoding="utf-8"))
    assert len(tracked_spec["artifact_profiles"]) == 4
    expected_host_policy = {
        "host_scope": "approved_remote_cloud_mac_lab_only",
        "local_developer_mac_permitted": False,
        "action_time_authorization_required": True,
        "verified_host_binding_required": True,
    }
    assert all(
        profile["execution_profile"]["execution_host_policy"] == expected_host_policy
        for profile in tracked_spec["artifact_profiles"]
    )
    assert tracked_spec["artifact_profiles"][0]["execution_profile"]["matrix"][0][
        "environment"
    ] == {"set": {}, "unset": ["CI"]}
    sdist_readiness = tracked_spec["artifact_profiles"][3]["execution_profile"][
        "implementation_readiness"
    ]
    assert sdist_readiness["state"] == "blocked"
    assert sdist_readiness["authoritative_campaign_run_permitted"] is False

    with tempfile.TemporaryDirectory(prefix="whoathere-known-miss-compiler-") as raw_root:
        root = Path(raw_root)
        rows = corpus_rows(tracked_spec)
        corpus = root / "corpus.jsonl"
        write_corpus(corpus, rows)

        output = root / "evaluation.json"
        result = run_compile(corpus, output)
        assert_failure(
            result,
            "campaign_profile_not_authoritative_ready:mb-telnyx-4.87.2-sdist",
            output,
        )

        # Exercise the future ready-state manifest builder in memory without bypassing the CLI's
        # current refusal to mint a claim-bearing file from a blocked campaign profile.
        compiler = runpy.run_path(str(COMPILER))
        validated_profiles = compiler["validate_profile_spec"](PROFILE_SPEC)
        parsed_rows, corpus_sha256 = compiler["read_corpus"](corpus)
        compiler["validate_corpus_bindings"](parsed_rows, validated_profiles)
        arguments = compiler["build_argument_parser"]().parse_args(
            compile_command(corpus, root / "never-written.json")[2:]
        )
        manifest = compiler["build_manifest"](
            arguments, validated_profiles, corpus_sha256
        )
        assert manifest["schema"] == "whoathere.actual_malware.evaluation_manifest.v2"
        assert manifest["evaluation_class"] == "known_regression"
        assert manifest["corpus_sha256"] == digest_bytes(corpus.read_bytes())
        assert manifest["thresholds"]["malicious_behavior_detection_rate_min"] == 1.0
        assert len(manifest["required_runs"]) == 4
        assert len(
            {(run["sample_id"], run["profile_id"]) for run in manifest["required_runs"]}
        ) == 4
        by_sample = {run["sample_id"]: run for run in manifest["required_runs"]}
        for profile in tracked_spec["artifact_profiles"]:
            run = by_sample[profile["sample_id"]]
            assert run["artifact_sha256"] == profile["artifact_sha256"]
            assert run["execution_profile_sha256"] == profile["execution_profile_sha256"]
            assert run["required_behavior_labels"] == profile[
                "sealed_expected_behavior_labels"
            ]
            assert run["required_modalities"] == ["deterministic", "codex", "dynamic"]
            assert run["require_complete"] is True
        assert manifest["identities"] == {
            "runtime_sha256": "sha256:" + "1" * 64,
            "prompt_set_sha256": "sha256:" + "2" * 64,
            "observation_schema_sha256": "sha256:" + "3" * 64,
            "provider_adapter_sha256": "sha256:" + "4" * 64,
            "policy_sha256": "sha256:" + "5" * 64,
            "scorer_id": SCORER_ID,
        }
        assert manifest["verified_evidence_registry"] == {
            "registry_id": "four-known-miss-registry",
            "verifier_id": "four-known-miss-verifier",
            "verifier_public_key_sha256": "sha256:" + "6" * 64,
            "verifier_executable_sha256": "sha256:" + "7" * 64,
            "projection_schema_sha256": "sha256:" + "8" * 64,
        }
        evaluator = runpy.run_path(str(EVALUATOR))
        manifest_errors, _, _ = evaluator["validate_evaluation_manifest_v2"](
            manifest,
            {row["sample_id"]: row for row in rows},
            manifest["corpus_sha256"],
        )
        assert manifest_errors == [], manifest_errors

        missing_corpus = root / "missing-corpus.jsonl"
        write_corpus(missing_corpus, rows[:-2] + rows[-1:])
        missing_output = root / "missing-output.json"
        assert_failure(
            run_compile(missing_corpus, missing_output),
            "corpus_missing_required_sample:mb-telnyx-4.87.2-sdist",
            missing_output,
        )

        duplicate_corpus = root / "duplicate-corpus.jsonl"
        write_corpus(duplicate_corpus, rows + [copy.deepcopy(rows[0])])
        duplicate_output = root / "duplicate-output.json"
        assert_failure(
            run_compile(duplicate_corpus, duplicate_output),
            "corpus_duplicate_sample_id:mb-npm-sbx-45.0.2",
            duplicate_output,
        )

        for field, replacement, token in (
            ("artifact_sha256", "sha256:" + "a" * 64, "corpus_artifact_sha256_mismatch"),
            ("ecosystem", "pypi", "corpus_ecosystem_mismatch"),
            ("behavior_labels", ["filesystem_scan"], "corpus_behavior_labels_mismatch"),
        ):
            mutated_rows = copy.deepcopy(rows)
            mutated_rows[0][field] = replacement
            mutated_corpus = root / f"mutated-{field}.jsonl"
            mutated_output = root / f"mutated-{field}-output.json"
            write_corpus(mutated_corpus, mutated_rows)
            assert_failure(run_compile(mutated_corpus, mutated_output), token, mutated_output)

        missing_spec_value = copy.deepcopy(tracked_spec)
        missing_spec_value["artifact_profiles"] = missing_spec_value["artifact_profiles"][:-1]
        missing_spec = root / "missing-profile.json"
        write_json(missing_spec, missing_spec_value)
        missing_spec_output = root / "missing-spec-output.json"
        assert_failure(
            run_compile(corpus, missing_spec_output, missing_spec),
            "profile_spec_requires_exactly_four_artifact_profiles",
            missing_spec_output,
        )

        duplicate_spec_value = copy.deepcopy(tracked_spec)
        duplicate_spec_value["artifact_profiles"][3] = copy.deepcopy(
            duplicate_spec_value["artifact_profiles"][0]
        )
        duplicate_spec = root / "duplicate-profile.json"
        write_json(duplicate_spec, duplicate_spec_value)
        duplicate_spec_output = root / "duplicate-spec-output.json"
        assert_failure(
            run_compile(corpus, duplicate_spec_output, duplicate_spec),
            "profile_spec_duplicate_sample_id:mb-npm-sbx-45.0.2",
            duplicate_spec_output,
        )

        tampered_profile = copy.deepcopy(tracked_spec)
        tampered_profile["artifact_profiles"][0]["execution_profile"]["matrix"][0][
            "registry_fallback"
        ] = True
        tampered_spec = root / "tampered-profile.json"
        write_json(tampered_spec, tampered_profile)
        tampered_output = root / "tampered-output.json"
        assert_failure(
            run_compile(corpus, tampered_output, tampered_spec),
            "execution_profile_sha256_content_mismatch",
            tampered_output,
        )

        local_host_profile = copy.deepcopy(tracked_spec)
        local_host_profile["artifact_profiles"][0]["execution_profile"][
            "execution_host_policy"
        ]["local_developer_mac_permitted"] = True
        local_host_spec = root / "local-host-profile.json"
        local_host_output = root / "local-host-output.json"
        write_json(local_host_spec, local_host_profile)
        assert_failure(
            run_compile(corpus, local_host_output, local_host_spec),
            "execution_profile_host_policy_invalid",
            local_host_output,
        )

        # Even when a modified corpus and modified profile agree with one another, corpus labels
        # cannot define the gate: the independent compiler pin rejects the profile change.
        inferred_profile = copy.deepcopy(tracked_spec)
        inferred_profile["artifact_profiles"][0]["sealed_expected_behavior_labels"] = [
            "filesystem_scan"
        ]
        inferred_rows = copy.deepcopy(rows)
        inferred_rows[0]["behavior_labels"] = ["filesystem_scan"]
        inferred_spec_path = root / "corpus-inferred-profile.json"
        inferred_corpus_path = root / "corpus-inferred.jsonl"
        inferred_output = root / "corpus-inferred-output.json"
        write_json(inferred_spec_path, inferred_profile)
        write_corpus(inferred_corpus_path, inferred_rows)
        assert_failure(
            run_compile(inferred_corpus_path, inferred_output, inferred_spec_path),
            "sealed_expected_behavior_labels_mismatch",
            inferred_output,
        )

        invalid_digest_output = root / "invalid-digest-output.json"
        assert_failure(
            run_compile(
                corpus,
                invalid_digest_output,
                command_mutator=lambda command: replace_argument(
                    command, "--runtime-sha256", "sha256:not-a-digest"
                ),
            ),
            "runtime_sha256_invalid",
            invalid_digest_output,
        )

        wrong_scorer_output = root / "wrong-scorer-output.json"
        assert_failure(
            run_compile(
                corpus,
                wrong_scorer_output,
                command_mutator=lambda command: replace_argument(
                    command, "--scorer-id", "some-other-scorer"
                ),
            ),
            "scorer_id_not_pinned",
            wrong_scorer_output,
        )

        late_created_output = root / "late-created-output.json"
        assert_failure(
            run_compile(
                corpus,
                late_created_output,
                command_mutator=lambda command: replace_argument(
                    command, "--created-at-utc", "2026-07-20T00:00:01Z"
                ),
            ),
            "created_at_after_evaluation_window_start",
            late_created_output,
        )

    print("whoathere four-known-miss evaluation compiler self-test: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
