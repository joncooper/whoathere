#!/usr/bin/env python3
"""Validate and, only when fully ready, compile the four-known-miss profile.

This command is metadata-only. It reads a tracked profile specification and a lab corpus
manifest and validates their exact bindings. It creates a new EvaluationManifestV2 only when every
frozen execution profile permits an authoritative campaign. It never opens artifact paths, unpacks
packages, invokes a package manager, connects to a lab host, or executes package code.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any


PROFILE_SCHEMA = "whoathere.known_miss_campaign_profile.v1"
PROFILE_ID = "four-prior-misses-v1"
PROFILE_CANONICALIZATION = "utf8-json-sort-keys-compact-no-nan-v1"
EXECUTION_PROFILE_SCHEMA = "whoathere.aggregate_execution_profile.v1"
CORPUS_SCHEMA = "whoathere.actual_malware.corpus.v1"
EVALUATION_MANIFEST_SCHEMA = "whoathere.actual_malware.evaluation_manifest.v2"
EVALUATION_CLASS = "known_regression"
COHORT_ID = "four-prior-misses"
SCORER_ID = "whoathere-actual-malware-evaluation.py:score-results-v2"

SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]*$")

ALLOWED_ECOSYSTEMS = {"npm", "pypi"}
ALLOWED_MODALITIES = {"deterministic", "scanner", "claude", "codex", "dynamic", "fused"}
EXPECTED_EXECUTION_HOST_POLICY = {
    "host_scope": "approved_remote_cloud_mac_lab_only",
    "local_developer_mac_permitted": False,
    "action_time_authorization_required": True,
    "verified_host_binding_required": True,
}

# These constants pin the tracked declaration independently of the lab corpus. In particular,
# behavior_labels in the corpus are only a consistency check: they cannot select or widen the
# labels written to required_runs. Updating this campaign intentionally requires changing both
# the reviewed profile specification and these independent compiler pins.
EXPECTED_ARTIFACTS: tuple[dict[str, Any], ...] = (
    {
        "sample_id": "mb-npm-sbx-45.0.2",
        "artifact_sha256": "sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933",
        "ecosystem": "npm",
        "family_id": "sbx-ci-credential-harvester",
        "campaign_id": "npm-supply-chain-2026-04",
        "sealed_expected_behavior_labels": (
            "ci_gated_activation",
            "credential_env_access",
            "https_exfil",
        ),
        "required_modalities": ("deterministic", "codex", "dynamic"),
        "profile_id": "npm-exact-lifecycle-ci-matrix-v1",
        "execution_profile_sha256": "sha256:3f30cf9b63d205fc063108ff86765de30e7b83de83c924c2284a5a59b1d727ba",
    },
    {
        "sample_id": "mb-telnyx-4.87.1-wheel",
        "artifact_sha256": "sha256:7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9",
        "ecosystem": "pypi",
        "family_id": "telnyx-compromised-release",
        "campaign_id": "teampcp-telnyx-2026",
        "sealed_expected_behavior_labels": (
            "credential_env_access",
            "https_exfil",
            "second_stage_fetch",
        ),
        "required_modalities": ("deterministic", "codex", "dynamic"),
        "profile_id": "wheel-exact-complete-trigger-matrix-v1",
        "execution_profile_sha256": "sha256:9da59e60f1554b30b0fe4859ea9dd09712483d82f8472db789519212eb9c34d8",
    },
    {
        "sample_id": "mb-telnyx-4.87.2-wheel",
        "artifact_sha256": "sha256:cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3",
        "ecosystem": "pypi",
        "family_id": "telnyx-compromised-release",
        "campaign_id": "teampcp-telnyx-2026",
        "sealed_expected_behavior_labels": (
            "credential_env_access",
            "https_exfil",
            "second_stage_fetch",
        ),
        "required_modalities": ("deterministic", "codex", "dynamic"),
        "profile_id": "wheel-exact-complete-trigger-matrix-v1",
        "execution_profile_sha256": "sha256:d8c0689e15ca579b22f3754063d24b8db15e3e1ddc6f7ecc002356168e24338e",
    },
    {
        "sample_id": "mb-telnyx-4.87.2-sdist",
        "artifact_sha256": "sha256:a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5",
        "ecosystem": "pypi",
        "family_id": "telnyx-compromised-release",
        "campaign_id": "teampcp-telnyx-2026",
        "sealed_expected_behavior_labels": (
            "credential_env_access",
            "https_exfil",
            "second_stage_fetch",
        ),
        "required_modalities": ("deterministic", "codex", "dynamic"),
        "profile_id": "sdist-exact-build-derived-wheel-matrix-v1",
        "execution_profile_sha256": "sha256:3b4dfb4a33cc2b139b29c975430b44122a51370ecc87cfd95e9edffa814f4910",
    },
)


class ValidationError(Exception):
    """A fail-closed metadata validation error."""


def canonical_json_bytes(value: Any) -> bytes:
    """Return the campaign's documented canonical JSON representation."""

    try:
        rendered = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("canonical_json_invalid") from exc
    return rendered.encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(chunk)
    return "sha256:" + hasher.hexdigest()


def require_object(value: Any, reason: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(reason)
    return value


def require_exact_keys(value: dict[str, Any], expected: set[str], prefix: str) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing:
        raise ValidationError(f"{prefix}_missing_fields:{','.join(missing)}")
    if unknown:
        raise ValidationError(f"{prefix}_unknown_fields:{','.join(unknown)}")


def require_identifier(value: Any, reason: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) > 128
        or IDENTIFIER_RE.fullmatch(value) is None
    ):
        raise ValidationError(reason)
    return value


def require_sha256(value: Any, reason: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise ValidationError(reason)
    return value


def parse_utc(value: Any, reason: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError(reason)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValidationError(reason) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise ValidationError(reason)
    return parsed


def load_json(path: Path, reason: str) -> Any:
    if not path.is_file():
        raise ValidationError(f"{reason}_not_regular_file")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"{reason}_invalid_json") from exc


def validate_profile_spec(path: Path) -> list[dict[str, Any]]:
    root = require_object(load_json(path, "profile_spec"), "profile_spec_must_be_object")
    require_exact_keys(
        root,
        {"schema", "campaign_profile_id", "canonicalization", "artifact_profiles"},
        "profile_spec",
    )
    if root["schema"] != PROFILE_SCHEMA:
        raise ValidationError("profile_spec_schema_mismatch")
    if root["campaign_profile_id"] != PROFILE_ID:
        raise ValidationError("profile_spec_campaign_profile_id_mismatch")
    if root["canonicalization"] != PROFILE_CANONICALIZATION:
        raise ValidationError("profile_spec_canonicalization_mismatch")

    profiles = root["artifact_profiles"]
    if not isinstance(profiles, list) or len(profiles) != len(EXPECTED_ARTIFACTS):
        raise ValidationError("profile_spec_requires_exactly_four_artifact_profiles")

    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_digests: set[str] = set()
    expected_keys = {
        "sample_id",
        "artifact_sha256",
        "ecosystem",
        "family_id",
        "campaign_id",
        "sealed_expected_behavior_labels",
        "required_modalities",
        "execution_profile",
        "execution_profile_sha256",
    }
    for index, (raw_profile, expected) in enumerate(zip(profiles, EXPECTED_ARTIFACTS, strict=True)):
        prefix = f"artifact_profiles[{index}]"
        profile = require_object(raw_profile, f"{prefix}_must_be_object")
        require_exact_keys(profile, expected_keys, prefix)

        sample_id = require_identifier(profile["sample_id"], f"{prefix}_sample_id_invalid")
        artifact_sha256 = require_sha256(
            profile["artifact_sha256"], f"{prefix}_artifact_sha256_invalid"
        )
        if sample_id in seen_ids:
            raise ValidationError(f"profile_spec_duplicate_sample_id:{sample_id}")
        if artifact_sha256 in seen_digests:
            raise ValidationError(f"profile_spec_duplicate_artifact_sha256:{artifact_sha256}")
        seen_ids.add(sample_id)
        seen_digests.add(artifact_sha256)

        for field in ("sample_id", "artifact_sha256", "ecosystem", "family_id", "campaign_id"):
            if profile[field] != expected[field]:
                raise ValidationError(f"{prefix}_{field}_sealed_value_mismatch")
        if profile["ecosystem"] not in ALLOWED_ECOSYSTEMS:
            raise ValidationError(f"{prefix}_ecosystem_invalid")
        require_identifier(profile["family_id"], f"{prefix}_family_id_invalid")
        require_identifier(profile["campaign_id"], f"{prefix}_campaign_id_invalid")

        labels = profile["sealed_expected_behavior_labels"]
        if not isinstance(labels, list) or tuple(labels) != expected["sealed_expected_behavior_labels"]:
            raise ValidationError(f"{prefix}_sealed_expected_behavior_labels_mismatch")
        if len(labels) != len(set(labels)):
            raise ValidationError(f"{prefix}_sealed_expected_behavior_labels_duplicate")

        modalities = profile["required_modalities"]
        if not isinstance(modalities, list) or tuple(modalities) != expected["required_modalities"]:
            raise ValidationError(f"{prefix}_required_modalities_mismatch")
        if any(modality not in ALLOWED_MODALITIES for modality in modalities):
            raise ValidationError(f"{prefix}_required_modalities_invalid")

        execution_profile = require_object(
            profile["execution_profile"], f"{prefix}_execution_profile_must_be_object"
        )
        if execution_profile.get("schema") != EXECUTION_PROFILE_SCHEMA:
            raise ValidationError(f"{prefix}_execution_profile_schema_mismatch")
        if execution_profile.get("profile_id") != expected["profile_id"]:
            raise ValidationError(f"{prefix}_execution_profile_id_mismatch")
        require_identifier(
            execution_profile.get("profile_id"), f"{prefix}_execution_profile_id_invalid"
        )
        expected_binding = {
            "sample_id": sample_id,
            "artifact_sha256": artifact_sha256,
        }
        if execution_profile.get("artifact_binding") != expected_binding:
            raise ValidationError(f"{prefix}_execution_profile_artifact_binding_mismatch")
        if not isinstance(execution_profile.get("matrix"), list) or not execution_profile["matrix"]:
            raise ValidationError(f"{prefix}_execution_profile_matrix_missing")
        if execution_profile.get("network_policy") != "sinkhole_only":
            raise ValidationError(f"{prefix}_execution_profile_network_policy_invalid")
        if execution_profile.get("execution_host_policy") != EXPECTED_EXECUTION_HOST_POLICY:
            raise ValidationError(f"{prefix}_execution_profile_host_policy_invalid")
        for false_field in ("sync_back", "live_c2", "live_second_stage_fetch"):
            if execution_profile.get(false_field) is not False:
                raise ValidationError(f"{prefix}_execution_profile_{false_field}_must_be_false")
        if execution_profile.get("fresh_disposable_guest_per_expanded_action") is not True:
            raise ValidationError(f"{prefix}_execution_profile_fresh_guest_required")

        declared_profile_sha256 = require_sha256(
            profile["execution_profile_sha256"],
            f"{prefix}_execution_profile_sha256_invalid",
        )
        calculated_profile_sha256 = sha256_bytes(canonical_json_bytes(execution_profile))
        if declared_profile_sha256 != calculated_profile_sha256:
            raise ValidationError(f"{prefix}_execution_profile_sha256_content_mismatch")
        if declared_profile_sha256 != expected["execution_profile_sha256"]:
            raise ValidationError(f"{prefix}_execution_profile_sha256_sealed_value_mismatch")

        validated.append(profile)

    return validated


def read_corpus(path: Path) -> tuple[list[dict[str, Any]], str]:
    if not path.is_file():
        raise ValidationError("corpus_not_regular_file")
    rows: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    seen_artifact_digests: set[str] = set()
    try:
        with path.open(encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                try:
                    row = json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValidationError(f"corpus_line_{line_number}_invalid_json") from exc
                if not isinstance(row, dict):
                    raise ValidationError(f"corpus_line_{line_number}_must_be_object")
                if row.get("schema_version") != CORPUS_SCHEMA:
                    raise ValidationError(f"corpus_line_{line_number}_schema_mismatch")
                sample_id = require_identifier(
                    row.get("sample_id"), f"corpus_line_{line_number}_sample_id_invalid"
                )
                artifact_sha256 = require_sha256(
                    row.get("artifact_sha256"),
                    f"corpus_line_{line_number}_artifact_sha256_invalid",
                )
                if sample_id in seen_ids:
                    raise ValidationError(f"corpus_duplicate_sample_id:{sample_id}")
                if artifact_sha256 in seen_artifact_digests:
                    raise ValidationError(f"corpus_duplicate_artifact_sha256:{artifact_sha256}")
                seen_ids.add(sample_id)
                seen_artifact_digests.add(artifact_sha256)
                if row.get("ecosystem") not in ALLOWED_ECOSYSTEMS:
                    raise ValidationError(f"corpus_line_{line_number}_ecosystem_invalid")
                labels = row.get("behavior_labels")
                if (
                    not isinstance(labels, list)
                    or any(not isinstance(label, str) or not label for label in labels)
                    or len(labels) != len(set(labels))
                ):
                    raise ValidationError(f"corpus_line_{line_number}_behavior_labels_invalid")
                rows.append(row)
    except (OSError, UnicodeDecodeError) as exc:
        raise ValidationError("corpus_unreadable") from exc
    if not rows:
        raise ValidationError("corpus_empty")
    return rows, sha256_file(path)


def validate_corpus_bindings(
    rows: list[dict[str, Any]], profiles: list[dict[str, Any]]
) -> None:
    rows_by_id = {row["sample_id"]: row for row in rows}
    for profile in profiles:
        sample_id = profile["sample_id"]
        row = rows_by_id.get(sample_id)
        if row is None:
            raise ValidationError(f"corpus_missing_required_sample:{sample_id}")
        if row.get("artifact_sha256") != profile["artifact_sha256"]:
            raise ValidationError(f"corpus_artifact_sha256_mismatch:{sample_id}")
        if row.get("ecosystem") != profile["ecosystem"]:
            raise ValidationError(f"corpus_ecosystem_mismatch:{sample_id}")
        corpus_labels = row.get("behavior_labels", [])
        sealed_labels = profile["sealed_expected_behavior_labels"]
        if sorted(corpus_labels) != sorted(sealed_labels):
            raise ValidationError(f"corpus_behavior_labels_mismatch:{sample_id}")
        if row.get("sample_kind") != "malware" or row.get("expected_result") != "malicious":
            raise ValidationError(f"corpus_expected_malicious_mismatch:{sample_id}")
        if row.get("network_policy") != "sinkhole_only":
            raise ValidationError(f"corpus_network_policy_mismatch:{sample_id}")
        for field in ("live_c2_allowed", "second_stage_live_fetch_allowed", "sync_back_allowed"):
            if row.get(field) is not False:
                raise ValidationError(f"corpus_{field}_must_be_false:{sample_id}")


def require_authoritative_campaign_readiness(
    profiles: list[dict[str, Any]],
) -> None:
    """Refuse to mint a claim-bearing manifest while any frozen lane is blocked."""

    blocked: list[str] = []
    for profile in profiles:
        readiness = profile["execution_profile"].get("implementation_readiness")
        if readiness is None:
            continue
        if not isinstance(readiness, dict):
            blocked.append(str(profile["sample_id"]))
            continue
        if (
            readiness.get("state") != "ready"
            or readiness.get("authoritative_campaign_run_permitted") is not True
        ):
            blocked.append(str(profile["sample_id"]))
    if blocked:
        raise ValidationError(
            "campaign_profile_not_authoritative_ready:" + ",".join(sorted(blocked))
        )


def build_manifest(
    args: argparse.Namespace,
    profiles: list[dict[str, Any]],
    corpus_sha256: str,
) -> dict[str, Any]:
    created_at = parse_utc(args.created_at_utc, "created_at_utc_invalid")
    starts_at = parse_utc(args.starts_at_utc, "starts_at_utc_invalid")
    ends_at = parse_utc(args.ends_at_utc, "ends_at_utc_invalid")
    if starts_at >= ends_at:
        raise ValidationError("evaluation_window_order_invalid")
    if created_at > starts_at:
        raise ValidationError("created_at_after_evaluation_window_start")
    if args.maximum_result_to_registry_seconds <= 0:
        raise ValidationError("maximum_result_to_registry_seconds_invalid")

    require_identifier(args.evaluation_id, "evaluation_id_invalid")
    require_identifier(args.registry_id, "registry_id_invalid")
    require_identifier(args.verifier_id, "verifier_id_invalid")
    require_identifier(args.scorer_id, "scorer_id_invalid")
    if args.scorer_id != SCORER_ID:
        raise ValidationError("scorer_id_not_pinned")
    for name in (
        "runtime_sha256",
        "prompt_set_sha256",
        "observation_schema_sha256",
        "provider_adapter_sha256",
        "policy_sha256",
        "verifier_public_key_sha256",
        "verifier_executable_sha256",
        "projection_schema_sha256",
    ):
        require_sha256(getattr(args, name), f"{name}_invalid")

    required_runs = []
    for profile in profiles:
        execution_profile = profile["execution_profile"]
        required_runs.append(
            {
                "sample_id": profile["sample_id"],
                "profile_id": execution_profile["profile_id"],
                "execution_profile_sha256": profile["execution_profile_sha256"],
                "cohort_id": COHORT_ID,
                "family_id": profile["family_id"],
                "campaign_id": profile["campaign_id"],
                "artifact_sha256": profile["artifact_sha256"],
                "ecosystem": profile["ecosystem"],
                "expected_result": "malicious",
                # This is intentionally copied from the independently pinned profile, never from
                # the corpus row. Corpus labels cannot create a detection or widen the gate.
                "required_behavior_labels": list(profile["sealed_expected_behavior_labels"]),
                "required_modalities": list(profile["required_modalities"]),
                "require_complete": True,
            }
        )

    if len(required_runs) != 4 or len(
        {(run["sample_id"], run["profile_id"]) for run in required_runs}
    ) != 4:
        raise ValidationError("compiled_required_runs_not_exactly_four_unique_pairs")

    return {
        "schema": EVALUATION_MANIFEST_SCHEMA,
        "evaluation_id": args.evaluation_id,
        "evaluation_class": EVALUATION_CLASS,
        "created_at_utc": args.created_at_utc,
        "corpus_sha256": corpus_sha256,
        "identities": {
            "runtime_sha256": args.runtime_sha256,
            "prompt_set_sha256": args.prompt_set_sha256,
            "observation_schema_sha256": args.observation_schema_sha256,
            "provider_adapter_sha256": args.provider_adapter_sha256,
            "policy_sha256": args.policy_sha256,
            "scorer_id": args.scorer_id,
        },
        "verified_evidence_registry": {
            "registry_id": args.registry_id,
            "verifier_id": args.verifier_id,
            "verifier_public_key_sha256": args.verifier_public_key_sha256,
            "verifier_executable_sha256": args.verifier_executable_sha256,
            "projection_schema_sha256": args.projection_schema_sha256,
        },
        "evaluation_window": {
            "starts_at_utc": args.starts_at_utc,
            "ends_at_utc": args.ends_at_utc,
            "maximum_result_to_registry_seconds": args.maximum_result_to_registry_seconds,
        },
        "thresholds": {
            "malicious_behavior_detection_rate_min": 1.0,
            "benign_false_malicious_rate_max": 0.0,
            "benign_friction_rate_max": 0.0,
            "required_run_completion_rate_min": 1.0,
            "safety_pass_rate_min": 1.0,
        },
        "cohorts": [
            {
                "cohort_id": COHORT_ID,
                "expected_result": "malicious",
                "description": (
                    "Frozen behavior-specific regression cohort for the four prior misses; "
                    "corpus labels alone never satisfy detection."
                ),
            }
        ],
        "required_runs": required_runs,
    }


def write_new_private_json(path: Path, value: Any) -> None:
    if not path.parent.is_dir():
        raise ValidationError("output_parent_not_directory")
    payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False) + "\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise ValidationError("output_already_exists") from exc
    except OSError as exc:
        raise ValidationError("output_create_failed") from exc
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def build_argument_parser() -> argparse.ArgumentParser:
    repository_root = Path(__file__).resolve().parents[1]
    default_spec = (
        repository_root
        / "docs"
        / "product-build-run"
        / "four-known-miss-campaign-profile.v1.json"
    )
    parser = argparse.ArgumentParser(
        description=(
            "Validate the frozen four-known-miss profile against a lab corpus manifest and "
            "create an exact EvaluationManifestV2 only when every lane is ready. Metadata only; "
            "never opens package artifacts."
        )
    )
    parser.add_argument("--profile-spec", type=Path, default=default_spec)
    parser.add_argument("--corpus", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--evaluation-id", required=True)
    parser.add_argument("--created-at-utc", required=True)
    parser.add_argument("--starts-at-utc", required=True)
    parser.add_argument("--ends-at-utc", required=True)
    parser.add_argument("--maximum-result-to-registry-seconds", type=int, required=True)
    parser.add_argument("--runtime-sha256", required=True)
    parser.add_argument("--prompt-set-sha256", required=True)
    parser.add_argument("--observation-schema-sha256", required=True)
    parser.add_argument("--provider-adapter-sha256", required=True)
    parser.add_argument("--policy-sha256", required=True)
    parser.add_argument("--scorer-id", required=True)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--verifier-id", required=True)
    parser.add_argument("--verifier-public-key-sha256", required=True)
    parser.add_argument("--verifier-executable-sha256", required=True)
    parser.add_argument("--projection-schema-sha256", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)
    try:
        profiles = validate_profile_spec(args.profile_spec)
        rows, corpus_sha256 = read_corpus(args.corpus)
        validate_corpus_bindings(rows, profiles)
        manifest = build_manifest(args, profiles, corpus_sha256)
        require_authoritative_campaign_readiness(profiles)
        write_new_private_json(args.output, manifest)
    except ValidationError as exc:
        print(f"error:{exc}", file=sys.stderr)
        return 20
    print(
        json.dumps(
            {
                "schema": "whoathere.known_miss_manifest_compile_report.v1",
                "status": "compiled",
                "profile_spec_sha256": sha256_file(args.profile_spec),
                "corpus_sha256": corpus_sha256,
                "required_run_count": 4,
                "declared_profile_readiness": {
                    profile["sample_id"]: profile["execution_profile"].get(
                        "implementation_readiness", {"state": "ready"}
                    )
                    for profile in profiles
                },
                "output": str(args.output),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
