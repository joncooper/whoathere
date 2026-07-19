#!/usr/bin/env python3
"""Freeze or verify the metadata-only R02b four-known-miss collection campaign.

This command reads only the reviewed contract, campaign profile, corpus metadata, executable and
schema bytes, and an Ed25519 public key. It does not read package artifacts or private keys and it
does not invoke a package, VM, network client, or AI provider.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
VALIDATOR_PATH = SCRIPTS / "whoathere-validate-four-known-miss-positive-subscore-contract.py"
COMPILER_PATH = SCRIPTS / "whoathere-compile-four-known-miss-positive-subscore.py"
EVALUATOR_PATH = SCRIPTS / "whoathere-actual-malware-evaluation.py"
PUBLISHER_PATH = SCRIPTS / "whoathere-run-result-v2-publisher.py"
ASSEMBLER_PATH = SCRIPTS / "whoathere-static-projection-bundle-assembler.py"
BRIDGE_PATH = SCRIPTS / "whoathere-signed-projection-registry-bridge.py"
FREEZE_TOOL_PATH = Path(__file__).resolve()

LOCK_SCHEMA = "whoathere.four_known_miss_positive_subscore_collection_lock.v1"
RECEIPT_SCHEMA = "whoathere.four_known_miss_positive_subscore_freeze_receipt.v1"
CONTRACT_SCHEMA = "whoathere.four_known_miss_positive_subscore_contract.v2"
CONTRACT_ID = "four-prior-misses-positive-only-v2"
FREEZE_ID = "four-prior-misses-positive-only-v2-r02b"
EVALUATION_ID = "four-prior-misses-positive-only-v2-r02b"
REGISTRY_ID = "four-prior-misses-positive-registry-v2"
VERIFIER_ID = "whoathere-static-projection-v1"
SCORER_ID = "whoathere-actual-malware-evaluation.py:score-results-v2"
NOT_USED = "not_used"
MAX_METADATA_BYTES = 64 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
REVISION_RE = re.compile(r"^[0-9a-f]{40}$")

EXPECTED_ROWS = (
    (
        "mb-npm-sbx-45.0.2",
        "sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933",
        "npm-exact-archive-static-capability-positive-v1",
        "sensitive_file_exfiltration",
        "sensitive_file_exfiltration_capability",
        "deterministic",
    ),
    (
        "mb-telnyx-4.87.1-wheel",
        "sha256:7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9",
        "pypi-exact-archive-static-capability-positive-v1",
        "second_stage_fetch",
        "download_execute_capability",
        "deterministic",
    ),
    (
        "mb-telnyx-4.87.2-wheel",
        "sha256:cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3",
        "pypi-exact-archive-static-capability-positive-v1",
        "second_stage_fetch",
        "download_execute_capability",
        "deterministic",
    ),
    (
        "mb-telnyx-4.87.2-sdist",
        "sha256:a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5",
        "pypi-exact-archive-static-capability-positive-v1",
        "second_stage_fetch",
        "download_execute_capability",
        "deterministic",
    ),
)

PROJECTION_FIELDS = [
    "kind",
    "artifact_sha256",
    "artifact_manifest_sha256",
    "exact_observation_sha256",
    "finding_evidence_sha256",
    "file_id",
    "file_sha256",
    "range",
    "selected_bytes_sha256",
    "source_receipt_sha256",
]
EXPECTED_SCHEMA_SET = {
    "schema": "whoathere.static_projection_schema_set.v1",
    "policies": [
        {
            "behavior_label": "second_stage_fetch",
            "evidence_type": "download_execute_capability",
            "finding_kind": "download_execute_capability",
            "metadata_schema": "whoathere.static_download_execute_projection_metadata.v1",
            "projection_kind": "static_download_execute_capability",
            "projection_schema": "whoathere.static_download_execute_projection_schema.v1",
            "threat_class": "second_stage_native_or_wasm_handoff",
        },
        {
            "behavior_label": "sensitive_file_exfiltration",
            "evidence_type": "sensitive_file_exfiltration_capability",
            "finding_kind": "sensitive_file_exfiltration_capability",
            "metadata_schema": "whoathere.static_sensitive_file_exfiltration_projection_metadata.v1",
            "projection_kind": "static_sensitive_file_exfiltration_capability",
            "projection_schema": "whoathere.static_sensitive_file_exfiltration_projection_schema.v1",
            "threat_class": "network_and_exfiltration",
        },
    ],
    "projection_fields": PROJECTION_FIELDS,
    "range_variants": [
        {"fields": ["kind", "start_byte", "end_byte"], "kind": "bytes"},
        {
            "fields": ["kind", "start_line", "end_line", "start_byte", "end_byte"],
            "kind": "lines",
        },
    ],
}


class FreezeError(Exception):
    """A stable fail-closed metadata freeze error."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise FreezeError(reason)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FreezeError(f"json_duplicate_key:{key}")
        result[key] = value
    return result


def canonical_json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise FreezeError("canonical_json_invalid") from exc


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def read_regular(path: Path, maximum_bytes: int, reason: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FreezeError(f"{reason}_unreadable") from exc
    require(stat.S_ISREG(metadata.st_mode), f"{reason}_not_regular_file")
    require(metadata.st_size <= maximum_bytes, f"{reason}_too_large")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise FreezeError(f"{reason}_unreadable") from exc


def load_json_raw(raw: bytes, reason: str) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicate_keys)
    except FreezeError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FreezeError(f"{reason}_invalid_json") from exc


def load_module(name: str, path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"{name}_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise FreezeError(f"{name}_module_unavailable") from exc
    return module


def parse_utc(value: Any, reason: str) -> dt.datetime:
    require(isinstance(value, str) and value.endswith("Z"), reason)
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise FreezeError(reason) from exc
    require(parsed.tzinfo is not None and parsed.utcoffset() == dt.timedelta(0), reason)
    return parsed


def git_head() -> str:
    process = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    require(process.returncode == 0, "source_revision_git_unavailable")
    revision = process.stdout.strip()
    require(REVISION_RE.fullmatch(revision) is not None, "source_revision_git_invalid")
    return revision


def validate_source_revision(revision: str, verify_existing: bool) -> None:
    head = git_head()
    if not verify_existing:
        require(revision == head, "source_revision_mismatch")
        return
    process = subprocess.run(
        ["git", "-C", str(ROOT), "merge-base", "--is-ancestor", revision, head],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(process.returncode == 0, "source_revision_not_current_or_ancestor")


def validate_ed25519_public_key(path: Path, raw: bytes) -> None:
    openssl = shutil.which("openssl")
    require(openssl is not None, "openssl_missing")
    process = subprocess.run(
        [openssl, "pkey", "-pubin", "-in", str(path), "-text_pub", "-noout"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(
        process.returncode == 0 and b"ED25519" in process.stdout.upper(),
        "verifier_public_key_not_ed25519",
    )
    require(b"PRIVATE KEY" not in raw, "verifier_public_key_contains_private_key")


def unused_sha256(component: str) -> str:
    return sha256_bytes(canonical_json_bytes({"component": component, "status": NOT_USED}))


def require_output_paths(paths: list[Path], *, must_exist: bool) -> None:
    require(len(set(paths)) == len(paths), "output_paths_not_distinct")
    for path in paths:
        require(path.is_absolute(), "output_path_not_absolute")
        require(path.parent.is_dir(), "output_parent_not_directory")
        if must_exist:
            raw = read_regular(path, MAX_METADATA_BYTES, "frozen_output")
            del raw
            mode = stat.S_IMODE(path.stat().st_mode)
            require(mode in {0o600, 0o644}, "frozen_output_mode_invalid")
        else:
            require(not path.exists() and not path.is_symlink(), "output_already_exists")


def validate_exact_contract_rows(
    contract: dict[str, Any], corpus_by_sample: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    rows = contract.get("rows")
    profiles = contract.get("positive_profiles")
    require(isinstance(rows, list) and len(rows) == 4, "contract_rows_not_exactly_four")
    require(isinstance(profiles, list), "contract_profiles_invalid")
    profile_by_id = {
        str(profile.get("profile_id")): profile for profile in profiles if isinstance(profile, dict)
    }
    require(len(profile_by_id) == len(profiles), "contract_profile_ids_invalid")
    require(len(corpus_by_sample) == 4, "corpus_rows_not_exactly_four")

    summaries: list[dict[str, Any]] = []
    actual_tuples: list[tuple[str, str, str, str, str, str]] = []
    for index, row in enumerate(rows):
        require(isinstance(row, dict), f"contract_rows[{index}]_invalid")
        profile_id = str(row.get("positive_profile_id"))
        profile = profile_by_id.get(profile_id)
        require(profile is not None, f"contract_rows[{index}]_profile_missing")
        evidence_rows = profile.get("permitted_positive_evidence")
        require(
            isinstance(evidence_rows, list)
            and len(evidence_rows) == 1
            and isinstance(evidence_rows[0], dict),
            f"contract_rows[{index}]_evidence_invalid",
        )
        evidence = evidence_rows[0]
        labels = row.get("required_behavior_labels")
        require(isinstance(labels, list) and len(labels) == 1, f"contract_rows[{index}]_labels_invalid")
        sample_id = str(row.get("sample_id"))
        corpus_row = corpus_by_sample.get(sample_id)
        require(corpus_row is not None, f"corpus_missing_required_sample:{sample_id}")
        corpus_labels = corpus_row.get("behavior_labels")
        require(
            isinstance(corpus_labels, list) and labels[0] in corpus_labels,
            f"corpus_required_behavior_label_missing:{sample_id}",
        )
        actual_tuples.append(
            (
                sample_id,
                str(row.get("artifact_sha256")),
                profile_id,
                str(labels[0]),
                str(evidence.get("evidence_type")),
                str(evidence.get("modality")),
            )
        )
        summaries.append(
            {
                "row_id": row.get("row_id"),
                "sample_id": sample_id,
                "artifact_sha256": row.get("artifact_sha256"),
                "ecosystem": row.get("ecosystem"),
                "artifact_form": row.get("artifact_form"),
                "positive_profile_id": profile_id,
                "behavior_label": labels[0],
                "evidence_type": evidence.get("evidence_type"),
                "modality": evidence.get("modality"),
            }
        )
    require(tuple(actual_tuples) == EXPECTED_ROWS, "contract_exact_rows_or_labels_mismatch")
    require(set(corpus_by_sample) == {row[0] for row in EXPECTED_ROWS}, "corpus_sample_set_mismatch")
    return summaries


def build_documents(args: argparse.Namespace) -> tuple[bytes, bytes, bytes, dict[str, Any]]:
    require(args.contract.is_absolute(), "contract_path_not_absolute")
    require(args.complete_run_profile.is_absolute(), "complete_run_profile_path_not_absolute")
    require(args.corpus.is_absolute(), "corpus_path_not_absolute")
    require(args.verifier_executable.is_absolute(), "verifier_executable_path_not_absolute")
    require(args.verifier_public_key.is_absolute(), "verifier_public_key_path_not_absolute")
    require(args.projection_schema.is_absolute(), "projection_schema_path_not_absolute")
    require(REVISION_RE.fullmatch(args.source_revision or "") is not None, "source_revision_invalid")
    validate_source_revision(args.source_revision, args.verify_existing)

    created_at = parse_utc(args.created_at_utc, "created_at_utc_invalid")
    starts_at = parse_utc(args.starts_at_utc, "starts_at_utc_invalid")
    ends_at = parse_utc(args.ends_at_utc, "ends_at_utc_invalid")
    require(created_at <= starts_at < ends_at, "evaluation_window_order_invalid")
    require(
        isinstance(args.maximum_result_to_registry_seconds, int)
        and not isinstance(args.maximum_result_to_registry_seconds, bool)
        and args.maximum_result_to_registry_seconds > 0,
        "maximum_result_to_registry_seconds_invalid",
    )

    validator = load_module("whoathere_r02b_contract_validator", VALIDATOR_PATH)
    compiler = load_module("whoathere_r02b_manifest_compiler", COMPILER_PATH)
    evaluator = load_module("whoathere_r02b_evaluator", EVALUATOR_PATH)
    try:
        contract, complete_profile, contract_report = compiler.validate_contract_and_source(
            args.contract, args.complete_run_profile, validator
        )
    except Exception as exc:
        raise FreezeError(f"positive_subscore_contract_invalid:{exc}") from exc
    require(contract.get("schema") == CONTRACT_SCHEMA, "contract_v2_required")
    require(contract.get("contract_id") == CONTRACT_ID, "contract_v2_id_required")
    upper_bound = contract.get("evaluation_window_policy", {}).get(
        "maximum_result_to_registry_seconds_upper_bound"
    )
    require(
        isinstance(upper_bound, int)
        and args.maximum_result_to_registry_seconds <= upper_bound,
        "maximum_result_to_registry_seconds_exceeds_contract",
    )
    corpus_by_sample, corpus_sha256 = compiler.read_corpus(args.corpus, evaluator)
    required_rows = validate_exact_contract_rows(contract, corpus_by_sample)

    verifier_raw = read_regular(args.verifier_executable, MAX_EXECUTABLE_BYTES, "verifier_executable")
    require(os.access(args.verifier_executable, os.X_OK), "verifier_executable_not_executable")
    public_key_raw = read_regular(args.verifier_public_key, MAX_METADATA_BYTES, "verifier_public_key")
    validate_ed25519_public_key(args.verifier_public_key, public_key_raw)
    projection_schema_raw = read_regular(
        args.projection_schema, MAX_METADATA_BYTES, "projection_schema"
    )
    projection_schema = load_json_raw(projection_schema_raw, "projection_schema")
    require(projection_schema == EXPECTED_SCHEMA_SET, "projection_schema_set_invalid")
    require(
        projection_schema_raw
        in {canonical_json_bytes(projection_schema), canonical_json_bytes(projection_schema) + b"\n"},
        "projection_schema_set_not_canonical",
    )

    tool_paths = {
        "validator_sha256": VALIDATOR_PATH,
        "compiler_sha256": COMPILER_PATH,
        "publisher_sha256": PUBLISHER_PATH,
        "scorer_sha256": EVALUATOR_PATH,
        "assembler_sha256": ASSEMBLER_PATH,
        "bridge_sha256": BRIDGE_PATH,
        "freeze_tool_sha256": FREEZE_TOOL_PATH,
    }
    tool_digests = {
        name: sha256_bytes(read_regular(path, MAX_EXECUTABLE_BYTES, name.removesuffix("_sha256")))
        for name, path in tool_paths.items()
    }
    contract_raw = read_regular(args.contract, MAX_METADATA_BYTES, "contract")
    projection_schema_sha256 = sha256_bytes(projection_schema_raw)
    identities = {
        "contract_sha256": contract_report["contract_sha256"],
        "artifact_profile_denominator_sha256": contract_report[
            "artifact_profile_denominator_sha256"
        ],
        "source_revision": args.source_revision,
        "runtime_sha256": NOT_USED,
        "sensor_sha256": NOT_USED,
        "verifier_executable_sha256": sha256_bytes(verifier_raw),
        "verifier_public_key_sha256": sha256_bytes(public_key_raw),
        "projection_schema_sha256": projection_schema_sha256,
        "prompt_set_sha256": NOT_USED,
        "model_identity": NOT_USED,
        "provider_adapter_sha256": NOT_USED,
        # The external collection-policy identity is the reviewed semantic v2 contract. The
        # EvaluationManifestV2 policy identity below is separately the raw lock digest.
        "policy_sha256": contract_report["contract_sha256"],
        "scorer_id": SCORER_ID,
        **tool_digests,
    }
    required_identity_fields = contract.get("identity_policy", {}).get("required_identity_fields")
    require(isinstance(required_identity_fields, list), "contract_required_identity_fields_invalid")
    require(
        set(required_identity_fields) <= set(identities),
        "collection_lock_required_identity_missing",
    )
    lock = {
        "schema": LOCK_SCHEMA,
        "freeze_id": FREEZE_ID,
        "status": "frozen_metadata_only",
        "created_at_utc": args.created_at_utc,
        "contract_id": CONTRACT_ID,
        "contract_file_sha256": sha256_bytes(contract_raw),
        "corpus_sha256": corpus_sha256,
        "evaluation_window": {
            "starts_at_utc": args.starts_at_utc,
            "ends_at_utc": args.ends_at_utc,
            "maximum_result_to_registry_seconds": args.maximum_result_to_registry_seconds,
        },
        "required_rows": required_rows,
        "identities": identities,
        "manifest_identity_posture": {
            "runtime_sha256": unused_sha256("runtime"),
            "prompt_set_sha256": unused_sha256("prompt_set"),
            "observation_schema_sha256": unused_sha256("observation_schema"),
            "provider_adapter_sha256": unused_sha256("provider_adapter"),
            "policy_binding": "raw_collection_lock_sha256",
            "scorer_id": SCORER_ID,
        },
        "claim_boundary": {
            "metadata_only": True,
            "package_artifact_read": False,
            "package_execution": False,
            "vm_network_or_ai": False,
            "admission_release_or_observed_clean": False,
        },
    }
    lock_raw = canonical_json_bytes(lock)
    lock_sha256 = sha256_bytes(lock_raw)

    compiler_args = argparse.Namespace(
        created_at_utc=args.created_at_utc,
        starts_at_utc=args.starts_at_utc,
        ends_at_utc=args.ends_at_utc,
        maximum_result_to_registry_seconds=args.maximum_result_to_registry_seconds,
        evaluation_id=EVALUATION_ID,
        registry_id=REGISTRY_ID,
        verifier_id=VERIFIER_ID,
        scorer_id=SCORER_ID,
        runtime_sha256=unused_sha256("runtime"),
        prompt_set_sha256=unused_sha256("prompt_set"),
        observation_schema_sha256=unused_sha256("observation_schema"),
        provider_adapter_sha256=unused_sha256("provider_adapter"),
        policy_sha256=lock_sha256,
        verifier_public_key_sha256=identities["verifier_public_key_sha256"],
        verifier_executable_sha256=identities["verifier_executable_sha256"],
        projection_schema_sha256=projection_schema_sha256,
    )
    manifest, _ = compiler.build_manifest(
        compiler_args, contract, complete_profile, corpus_by_sample, corpus_sha256
    )
    compiler.validate_manifest_against_contract(
        manifest, contract, complete_profile, corpus_by_sample, corpus_sha256
    )
    compiler.validate_compiled_manifest(manifest, corpus_by_sample, corpus_sha256, evaluator)
    require(
        manifest.get("identities", {}).get("policy_sha256") == lock_sha256,
        "manifest_policy_lock_binding_invalid",
    )
    manifest_raw = canonical_json_bytes(manifest)
    manifest_sha256 = sha256_bytes(manifest_raw)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "freeze_id": FREEZE_ID,
        "status": "frozen_metadata_only",
        "created_at_utc": args.created_at_utc,
        "source_revision": args.source_revision,
        "collection_lock_sha256": lock_sha256,
        "evaluation_manifest_sha256": manifest_sha256,
        "contract_sha256": contract_report["contract_sha256"],
        "artifact_profile_denominator_sha256": contract_report[
            "artifact_profile_denominator_sha256"
        ],
        "corpus_sha256": corpus_sha256,
        "claim_boundary": "Metadata identities only; no package bytes, execution, VM, network, AI, admission, release, or observed-clean authority.",
    }
    receipt_raw = canonical_json_bytes(receipt)
    report = {
        "status": "verified" if args.verify_existing else "frozen",
        "freeze_id": FREEZE_ID,
        "collection_lock_sha256": lock_sha256,
        "evaluation_manifest_sha256": manifest_sha256,
        "corpus_sha256": corpus_sha256,
        "required_run_count": 4,
        "metadata_only": True,
    }
    return lock_raw, manifest_raw, receipt_raw, report


def write_exclusive(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise FreezeError("output_create_failed") from exc
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def freeze_or_verify(args: argparse.Namespace) -> dict[str, Any]:
    output_paths = [args.collection_lock_out, args.evaluation_manifest_out, args.freeze_receipt_out]
    require_output_paths(output_paths, must_exist=args.verify_existing)
    lock_raw, manifest_raw, receipt_raw, report = build_documents(args)
    expected = list(zip(output_paths, (lock_raw, manifest_raw, receipt_raw), strict=True))
    if args.verify_existing:
        for path, raw in expected:
            require(
                read_regular(path, MAX_METADATA_BYTES, "frozen_output") == raw,
                f"frozen_output_mismatch:{path.name}",
            )
        return report

    created: list[Path] = []
    try:
        for path, raw in expected:
            write_exclusive(path, raw)
            created.append(path)
        for path, raw in expected:
            require(path.read_bytes() == raw, f"frozen_output_write_mismatch:{path.name}")
            require(stat.S_IMODE(path.stat().st_mode) == 0o600, "frozen_output_mode_invalid")
    except Exception:
        for path in created:
            try:
                path.unlink()
            except OSError:
                pass
        raise
    return report


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--contract", type=Path, required=True)
    result.add_argument("--complete-run-profile", type=Path, required=True)
    result.add_argument("--corpus", type=Path, required=True)
    result.add_argument("--verifier-executable", type=Path, required=True)
    result.add_argument("--verifier-public-key", type=Path, required=True)
    result.add_argument("--projection-schema", type=Path, required=True)
    result.add_argument("--source-revision", required=True)
    result.add_argument("--created-at-utc", required=True)
    result.add_argument("--starts-at-utc", required=True)
    result.add_argument("--ends-at-utc", required=True)
    result.add_argument("--maximum-result-to-registry-seconds", type=int, default=600)
    result.add_argument("--collection-lock-out", type=Path, required=True)
    result.add_argument("--evaluation-manifest-out", type=Path, required=True)
    result.add_argument("--freeze-receipt-out", type=Path, required=True)
    result.add_argument(
        "--verify-existing",
        action="store_true",
        help="Recompute every identity and require byte-exact safe-mode existing outputs.",
    )
    return result


def main() -> int:
    args = parser().parse_args()
    for name in (
        "contract",
        "complete_run_profile",
        "corpus",
        "verifier_executable",
        "verifier_public_key",
        "projection_schema",
    ):
        path = getattr(args, name).expanduser()
        setattr(args, name, path if path.is_absolute() else path.absolute())
    # Outputs intentionally are not normalized: accepting a relative output would make a freeze
    # depend on the caller's ambient working directory.
    for name in ("collection_lock_out", "evaluation_manifest_out", "freeze_receipt_out"):
        setattr(args, name, getattr(args, name).expanduser())
    try:
        report = freeze_or_verify(args)
    except FreezeError as exc:
        print(f"error:{exc}", file=sys.stderr)
        return 20
    except Exception as exc:
        print(f"error:freeze_internal_error:{type(exc).__name__}", file=sys.stderr)
        return 20
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
