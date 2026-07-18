#!/usr/bin/env python3
"""Focused fake-runner tests for the P07 inert end-to-end operator command."""

from __future__ import annotations

import copy
import contextlib
import hashlib
import io
import json
from pathlib import Path
import runpy
import stat
import sys
import tempfile
import types
from typing import Any


SCRIPT = Path(__file__).with_name("whoathere-inert-e2e-demo.py")
MODULE = runpy.run_path(str(SCRIPT))
CommandResult = MODULE["CommandResult"]
DemoError = MODULE["DemoError"]
run_demo = MODULE["run_demo"]
resume_sanitized_local = MODULE["resume_sanitized_local"]
validate_remote_result = MODULE["validate_remote_result"]
validate_export = MODULE["validate_export"]
build_remote_source = MODULE["build_remote_source"]
event_sha256 = MODULE["serde_event_sha256"]
sha256_bytes = MODULE["sha256_bytes"]
canonical_sha256 = MODULE["canonical_sha256"]
INPUT_SCHEMA = MODULE["INPUT_SCHEMA"]
REMOTE_SCHEMA = MODULE["REMOTE_SCHEMA"]


def digest(character: str) -> str:
    return "sha256:" + character * 64


def canonical(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=False)


def private_file(path: Path, content: bytes) -> dict[str, str]:
    path.write_bytes(content)
    path.chmod(0o600)
    return {"path": str(path), "sha256": sha256_bytes(content)}


def event(sequence: int, event_id: str, signal: dict[str, Any]) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "event_id": event_id,
        "source_receipt_sha256": digest("9"),
        "signal": signal,
        "untrusted_detail": None,
    }


def bundle(profile: str, artifact: str, manifest: str) -> dict[str, Any]:
    root_receipt = digest("5" if profile == "ci_false" else "6")
    events = [
        event(
            1,
            f"process/{profile}/lifecycle",
            {"kind": "process", "action": "package_trigger", "trigger": "npm_lifecycle"},
        )
    ]
    if profile == "ci_true":
        events.extend(
            [
                event(
                    2,
                    "file/ci_true/canary",
                    {"kind": "filesystem", "operation": "read", "target": "credential_file"},
                ),
                event(
                    3,
                    "network/ci_true/connect",
                    {"kind": "network", "action": "connect", "destination": "local_sinkhole"},
                ),
            ]
        )
    for item in events:
        item["source_receipt_sha256"] = root_receipt
    return {
        "schema_version": "whoathere.behavior_analysis_bundle.v1",
        "artifact_sha256": artifact,
        "manifest_sha256": manifest,
        "scenario_id": f"npm_{profile}",
        "scenario_sha256": digest("3" if profile == "ci_false" else "4"),
        "run_id": f"run_{profile}",
        "root_receipt_sha256": root_receipt,
        # The behavior projector defines the host receipt identity as the exact
        # execution-run.json digest.
        "host_receipt_sha256": digest("e" if profile == "ci_false" else "f"),
        "coverage": [
            {
                "modality": name,
                "state": "incomplete",
                "limitation_codes": ["inert_demo_partial_coverage"],
            }
            for name in ("process", "filesystem", "canary", "network", "scenario")
        ],
        "events": events,
    }


def make_fixture(root: Path) -> dict[str, Any]:
    private = root / "private"
    private_dir(private)
    auth_home = private / "auth"
    private_dir(auth_home)
    artifact = digest("a")
    manifest = digest("b")

    remote_whoathere = {"path": "/remote/p07/whoathere", "sha256": digest("1")}
    remote_config = {"path": "/remote/p07/config.json", "sha256": digest("2")}
    remote_exporter = {"path": "/remote/p07/exporter.py", "sha256": digest("4")}

    preflight_command = private_file(private / "preflight", b"preflight-v1")
    preflight_input = private_file(
        private / "preflight-input.json",
        canonical(
            {
                "ssh": {"host_alias": "p07-test"},
                "run_binding": {
                    "campaign_id": "p07-selftest",
                    "profile_id": "npm-ci-paired",
                    "files": [
                        {"label": "whoathere_bin", **remote_whoathere},
                        {"label": "detonation_config", **remote_config},
                        {"label": "sanitizer", **remote_exporter},
                    ],
                },
            }
        ),
    )
    local_whoathere = private_file(private / "whoathere", b"whoathere-v1")
    codex = private_file(private / "codex", b"codex-v1")
    diagnostic_script = private_file(private / "diagnostic.py", b"diagnostic-v1")
    ssh_config = private / "ssh-config"
    private_file(ssh_config, b"Host test\n  HostName example.invalid\n")

    report = {
        "schema_version": "whoathere.exact_artifact_inspection.v1",
        "identity": {"artifact_sha256": artifact, "manifest_sha256": manifest},
        "stages": [
            {
                "stage": "detonation",
                "provider": "linux_vz_exact_npm_v1",
                "artifact_sha256": artifact,
                "manifest_sha256": manifest,
                "result_sha256": digest("2"),
            }
        ],
        "scenario_plan": {
            "artifact_sha256": artifact,
            "manifest_sha256": manifest,
            "plan_sha256": digest("1"),
        },
        "admission_authority": False,
        "observed_clean": False,
        "sync_back_enabled": False,
        "sanitized_projection": True,
        "raw_source_or_telemetry_included": False,
    }
    report_raw = canonical(report)
    bundles = {profile: bundle(profile, artifact, manifest) for profile in ("ci_false", "ci_true")}
    bundle_raw = {profile: canonical(value) for profile, value in bundles.items()}
    bundle_sha = {profile: sha256_bytes(value) for profile, value in bundle_raw.items()}

    bundle_bindings = [
        {
            "action_key": f"vm_{profile}",
            "bundle_sha256": bundle_sha[profile],
            "path": f"bundles/vm_{profile}/behavior-bundle.json",
            "byte_length": len(bundle_raw[profile]),
        }
        for profile in ("ci_false", "ci_true")
    ]
    manifest_value = {
        "schema_version": "whoathere.split_behavior_export.v1",
        "created_at_utc": "2026-07-18T00:00:00Z",
        "artifact_sha256": artifact,
        "manifest_sha256": manifest,
        "detonation_provider": "linux_vz_exact_npm_v1",
        "bundle_count": 2,
        "bundle_set_sha256": canonical_sha256(bundle_bindings),
        "sanitized_report_sha256": sha256_bytes(report_raw),
        "raw_evidence_included": False,
        "artifact_bytes_included": False,
        "package_source_included": False,
        "files": [
            {
                "role": "sanitized_exact_artifact_report",
                "path": "sanitized-exact-artifact-report.json",
                "sha256": sha256_bytes(report_raw),
                "byte_length": len(report_raw),
            },
            *[
                {
                    "role": "behavior_bundle",
                    **binding,
                    "sha256": bundle_sha[profile],
                }
                for profile, binding in zip(
                    ("ci_false", "ci_true"), bundle_bindings, strict=True
                )
            ],
        ],
    }
    manifest_raw = canonical(manifest_value)
    export_files = {
        "export-manifest.json": manifest_raw,
        "sanitized-exact-artifact-report.json": report_raw,
        "bundles/vm_ci_false/behavior-bundle.json": bundle_raw["ci_false"],
        "bundles/vm_ci_true/behavior-bundle.json": bundle_raw["ci_true"],
    }

    observer_values: dict[str, dict[str, Any]] = {}
    observer_raw: dict[str, bytes] = {}
    findings: dict[str, dict[str, Any]] = {}
    for profile in ("ci_false", "ci_true"):
        parsed_bundle = json.loads(bundle_raw[profile].decode("utf-8"))
        cited_event = parsed_bundle["events"][0 if profile == "ci_false" else 1]
        finding = {
            "kind": "sensitive_file_access" if profile == "ci_true" else "credential_access",
            "threat_class": "credential_and_sensitive_file_discovery",
            "confidence": "high",
            "evidence": [
                {
                    "event_id": cited_event["event_id"],
                    "event_sha256": event_sha256(cited_event),
                }
            ],
            "finding_sha256": digest("c" if profile == "ci_false" else "d"),
        }
        findings[profile] = finding
        observer = {
            "schema_version": "whoathere.behavior_observe.v1",
            "provider": "codex",
            "artifact_sha256": artifact,
            "bundle_sha256": bundle_sha[profile],
            "status": "behavior_detected",
            "observe_only": True,
            "admission_authority": False,
            "observed_clean": False,
            "panel": {
                "bundle_sha256": bundle_sha[profile],
                "correlation_report": {
                    "bundle_sha256": bundle_sha[profile],
                    "positive_preservation_verified": True,
                    "findings": [finding],
                },
            },
        }
        observer_values[profile] = observer
        observer_raw[profile] = canonical(observer)

    remote_result = {
        "schema_version": REMOTE_SCHEMA,
        "status": "complete",
        "input_sha256": digest("0"),
        "artifact_sha256": artifact,
        "manifest_sha256": manifest,
        "scenario_plan_sha256": digest("1"),
        "detonation_result_sha256": digest("2"),
        "sanitized_report_sha256": sha256_bytes(report_raw),
        "export_manifest_sha256": sha256_bytes(manifest_raw),
        "files": [
            {
                "role": "sanitized_exact_artifact_report",
                "path": "sanitized-exact-artifact-report.json",
                "sha256": sha256_bytes(report_raw),
                "byte_length": len(report_raw),
            },
            *[
                {
                    "role": "behavior_bundle",
                    "path": f"bundles/vm_{profile}/behavior-bundle.json",
                    "sha256": bundle_sha[profile],
                    "byte_length": len(bundle_raw[profile]),
                }
                for profile in ("ci_false", "ci_true")
            ],
        ],
        "profiles": [
            {
                "profile": profile,
                "execution_result_sha256": bundles[profile]["host_receipt_sha256"],
                "bundle_sha256": bundle_sha[profile],
                "root_receipt_sha256": bundles[profile]["root_receipt_sha256"],
                "host_receipt_sha256": bundles[profile]["host_receipt_sha256"],
                "vm_started": True,
                "vm_stopped": True,
                "clone_destroyed": True,
                "image_identity_stable": True,
                "public_network_route_present": False,
                "sync_back": False,
                "authoritative_verdict_permitted": False,
                "evidence_coverage_complete": False,
            }
            for profile in ("ci_false", "ci_true")
        ],
        "invariants": {
            "host_package_executions": 0,
            "sync_backs": 0,
            "unsafe_allows": 0,
            "restricted_material_leaks": 0,
            "live_c2_contacts": 0,
            "live_second_stage_fetches": 0,
        },
        "raw_evidence_included": False,
        "artifact_bytes_included": False,
        "package_source_included": False,
        "remote_ai_invoked": False,
        "admission_authority": False,
        "observed_clean": False,
    }

    diagnostic = {
        "schema_version": "whoathere.two_host_behavior_diagnostic.v1",
        "verdict": "diagnostic_detection",
        "exit_code": 20,
        "diagnostic_only": True,
        "claim_bearing": False,
        "reconciliation_complete": True,
        "exact_artifact_sha256": artifact,
        "admission_authority": False,
        "observed_clean": False,
        "bundles": [
            {
                "action_key": f"vm_{profile}",
                "bundle_sha256": bundle_sha[profile],
                "observer_result_sha256": sha256_bytes(observer_raw[profile]),
                "behavior_specific_findings": [findings[profile]],
            }
            for profile in ("ci_false", "ci_true")
        ],
    }

    plan = {
        "schema_version": INPUT_SCHEMA,
        "demo": {
            "demo_id": "p07-selftest",
            "artifact_filename": "whoathere-fixture-npm-ci-canary-1.0.0.tgz",
            "artifact_byte_length": 1311,
            "artifact_sha256": artifact,
            "required_profiles": ["ci_false", "ci_true"],
        },
        "preflight": {
            "command": preflight_command,
            "input": preflight_input,
            "expected_campaign_id": "p07-selftest",
            "expected_profile_id": "npm-ci-paired",
        },
        "remote": {
            "host_alias": "p07-test",
            "workspace_root": "/remote/p07",
            "python_path": "/usr/bin/python3",
            "artifact": {
                "path": "/remote/p07/whoathere-fixture-npm-ci-canary-1.0.0.tgz",
                "sha256": artifact,
            },
            "whoathere": remote_whoathere,
            "detonation_config": remote_config,
            "detonation_output_root": "/remote/p07/detonation",
            "run_root": "/remote/p07/run",
            "report_sanitizer": {"path": "/remote/p07/sanitizer.py", "sha256": digest("3")},
            "bundle_exporter": remote_exporter,
            "timeout_seconds": 180,
        },
        "local": {
            "whoathere": local_whoathere,
            "codex_client": codex,
            "model": "gpt-5.6-sol",
            "auth_home": str(auth_home),
            "timeout_seconds": 60,
            "output_root": str(private / "output"),
            "two_host_diagnostic": diagnostic_script,
        },
        "policy": {
            "planned_material": "inert_only",
            "hosted_behavior_review_approved": True,
            "remote_ai_permitted": False,
            "raw_export_permitted": False,
            "sync_back_permitted": False,
            "admission_authority": False,
            "sinkhole_destination": "local_loopback",
        },
    }
    plan_raw = canonical(plan)
    remote_result["input_sha256"] = sha256_bytes(plan_raw)
    plan_path = private / "plan.json"
    private_file(plan_path, plan_raw)
    return {
        "plan": plan,
        "plan_path": plan_path,
        "plan_sha256": sha256_bytes(plan_raw),
        "ssh_config": ssh_config,
        "remote_result": remote_result,
        "export_files": export_files,
        "observer_raw": observer_raw,
        "diagnostic": diagnostic,
    }


class FakeRunner:
    def __init__(self, fixture: dict[str, Any], mode: str = "complete"):
        self.fixture = fixture
        self.mode = mode
        self.calls: list[tuple[list[str], bytes | None]] = []

    def __call__(self, argv: list[str], input_bytes: bytes | None, timeout: int):
        del timeout
        self.calls.append((list(argv), input_bytes))
        plan = self.fixture["plan"]
        if argv[0] == plan["preflight"]["command"]["path"]:
            if self.mode == "preflight_blocked":
                return CommandResult(20, b'{"status":"blocked"}\n', b"")
            value = {
                "schema_version": "whoathere.cloud_lab_preflight_result.v1",
                "status": "ready",
                "exit_code": 0,
                "input_sha256": plan["preflight"]["input"]["sha256"],
                "bindings": {
                    "campaign_id": plan["preflight"]["expected_campaign_id"],
                    "profile_id": plan["preflight"]["expected_profile_id"],
                    "identity_sha256s": {
                        "whoathere_bin": plan["remote"]["whoathere"]["sha256"],
                        "detonation_config": plan["remote"]["detonation_config"]["sha256"],
                        "sanitizer": plan["remote"]["bundle_exporter"]["sha256"],
                    },
                },
                "artifact_opened": False,
                "package_executed": False,
                "vm_started": False,
                "remote_state_mutated": False,
                "clearance_consumed": False,
            }
            return CommandResult(0, canonical(value), b"")
        if argv[0] == "/usr/bin/ssh":
            return CommandResult(0, canonical(self.fixture["remote_result"]), b"")
        if argv[0] == "/usr/bin/scp":
            source = argv[-2]
            destination = Path(argv[-1])
            relative = source.split("/export/", 1)[1]
            destination.write_bytes(self.fixture["export_files"][relative])
            return CommandResult(0, b"", b"")
        if argv[0] == plan["local"]["whoathere"]["path"]:
            profile = "ci_true" if "vm_ci_true" in argv[3] else "ci_false"
            return CommandResult(20, self.fixture["observer_raw"][profile], b"")
        if "--remote-report" in argv:
            value = copy.deepcopy(self.fixture["diagnostic"])
            if self.mode == "citation_missing":
                value["bundles"][0]["behavior_specific_findings"][0]["evidence"] = []
            if self.mode == "observer_digest_mismatch":
                value["bundles"][0]["observer_result_sha256"] = digest("0")
            return CommandResult(20, canonical(value), b"")
        raise AssertionError(f"unexpected command: {argv}")


def expect_error(function, reason: str) -> None:
    try:
        function()
    except DemoError as error:
        assert error.reason_code == reason, (error.reason_code, reason)
    else:
        raise AssertionError(f"expected {reason}")


def test_complete_run() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        runner = FakeRunner(fixture)
        transcript = run_demo(
            fixture["plan_path"],
            fixture["plan_sha256"],
            fixture["ssh_config"],
            runner=runner,
        )
        assert transcript.startswith("BLOCK - suspicious package capability")
        assert "CI=false" in transcript and "CI=true" in transcript
        assert "host package executions: 0" in transcript
        assert "Package-written fixture markers: supporting-only" in transcript
        assert "Execution mode: fresh end-to-end invocation" in transcript
        assert "Resume binding:" not in transcript
        assert "/remote/" not in transcript and str(root) not in transcript
        assert "127.0.0.1" not in transcript and "whoathere_fake_" not in transcript
        assert (Path(fixture["plan"]["local"]["output_root"]) / "transcript.txt").is_file()

        ssh_calls = [call for call in runner.calls if call[0][0] == "/usr/bin/ssh"]
        scp_calls = [call for call in runner.calls if call[0][0] == "/usr/bin/scp"]
        observer_calls = [
            call
            for call in runner.calls
            if call[0][0] == fixture["plan"]["local"]["whoathere"]["path"]
        ]
        assert len(ssh_calls) == 1 and len(scp_calls) == 4 and len(observer_calls) == 2
        assert all("/export/" in call[0][-2] and "*" not in call[0][-2] for call in scp_calls)
        remote_source = ssh_calls[0][1]
        assert remote_source is not None
        assert fixture["plan"]["local"]["auth_home"].encode() not in remote_source
        assert fixture["plan"]["local"]["codex_client"]["path"].encode() not in remote_source


def test_preflight_stops_execution() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        runner = FakeRunner(fixture, "preflight_blocked")
        expect_error(
            lambda: run_demo(
                fixture["plan_path"],
                fixture["plan_sha256"],
                fixture["ssh_config"],
                runner=runner,
            ),
            "p07_preflight_not_ready",
        )
        assert not any(call[0][0] == "/usr/bin/ssh" for call in runner.calls)


def test_digest_mismatch_stops_before_runner() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        Path(fixture["plan"]["local"]["codex_client"]["path"]).write_bytes(b"substituted")
        runner = FakeRunner(fixture)
        expect_error(
            lambda: run_demo(
                fixture["plan_path"],
                fixture["plan_sha256"],
                fixture["ssh_config"],
                runner=runner,
            ),
            "p07_local_bound_file_mismatch",
        )
        assert not runner.calls


def test_public_plan_mode_stops_before_runner() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        fixture["plan_path"].chmod(0o644)
        runner = FakeRunner(fixture)
        expect_error(
            lambda: run_demo(
                fixture["plan_path"],
                fixture["plan_sha256"],
                fixture["ssh_config"],
                runner=runner,
            ),
            "p07_input_not_private",
        )
        assert not runner.calls


def test_preflight_plan_join_mismatch_stops_before_runner() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        plan = copy.deepcopy(fixture["plan"])
        plan["remote"]["detonation_config"]["sha256"] = digest("0")
        content = canonical(plan)
        fixture["plan_path"].write_bytes(content)
        fixture["plan_path"].chmod(0o600)
        runner = FakeRunner(fixture)
        expect_error(
            lambda: run_demo(
                fixture["plan_path"],
                sha256_bytes(content),
                fixture["ssh_config"],
                runner=runner,
            ),
            "p07_preflight_plan_binding_mismatch",
        )
        assert not runner.calls


def test_remote_cardinality_and_safety_fail_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        missing_profile = copy.deepcopy(fixture["remote_result"])
        missing_profile["profiles"].pop()
        expect_error(
            lambda: validate_remote_result(
                fixture["plan"], fixture["plan_sha256"], missing_profile
            ),
            "p07_remote_profile_count_invalid",
        )
        missing_bundle = copy.deepcopy(fixture["remote_result"])
        missing_bundle["files"].pop()
        expect_error(
            lambda: validate_remote_result(
                fixture["plan"], fixture["plan_sha256"], missing_bundle
            ),
            "p07_remote_file_set_invalid",
        )
        unsafe = copy.deepcopy(fixture["remote_result"])
        unsafe["invariants"]["sync_backs"] = 1
        expect_error(
            lambda: validate_remote_result(
                fixture["plan"], fixture["plan_sha256"], unsafe
            ),
            "p07_remote_invariants_invalid",
        )


def stage_preserved_export(fixture: dict[str, Any]) -> Path:
    output_root = Path(fixture["plan"]["local"]["output_root"])
    output_root.mkdir(mode=0o700)
    (output_root / "remote-result.json").write_bytes(canonical(fixture["remote_result"]))
    (output_root / "remote-result.json").chmod(0o600)
    export_root = output_root / "export"
    export_root.mkdir(mode=0o700)
    for relative, raw in fixture["export_files"].items():
        path = export_root / relative
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in path.parents:
            directory.chmod(0o700)
            if directory == export_root:
                break
        path.write_bytes(raw)
        path.chmod(0o600)
    return export_root


def replace_fixture_bundle(
    fixture: dict[str, Any], profile: str, mutate: Any
) -> None:
    relative = f"bundles/vm_{profile}/behavior-bundle.json"
    value = json.loads(fixture["export_files"][relative].decode("utf-8"))
    mutate(value)
    raw = canonical(value)
    bundle_digest = sha256_bytes(raw)
    fixture["export_files"][relative] = raw

    manifest = json.loads(
        fixture["export_files"]["export-manifest.json"].decode("utf-8")
    )
    for item in manifest["files"]:
        if item["path"] == relative:
            item["sha256"] = bundle_digest
            item["bundle_sha256"] = bundle_digest
            item["byte_length"] = len(raw)
    bundle_bindings = [
        {
            "action_key": item["action_key"],
            "bundle_sha256": item["bundle_sha256"],
            "path": item["path"],
            "byte_length": item["byte_length"],
        }
        for item in manifest["files"]
        if item["role"] == "behavior_bundle"
    ]
    manifest["bundle_set_sha256"] = canonical_sha256(
        sorted(bundle_bindings, key=lambda item: item["action_key"])
    )
    manifest_raw = canonical(manifest)
    fixture["export_files"]["export-manifest.json"] = manifest_raw
    fixture["remote_result"]["export_manifest_sha256"] = sha256_bytes(manifest_raw)
    for item in fixture["remote_result"]["files"]:
        if item["path"] == relative:
            item["sha256"] = bundle_digest
            item["byte_length"] = len(raw)
    for item in fixture["remote_result"]["profiles"]:
        if item["profile"] == profile:
            item["bundle_sha256"] = bundle_digest


def test_resume_is_visible_and_digest_bound() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        stage_preserved_export(fixture)
        transcript = resume_sanitized_local(
            fixture["plan_path"],
            fixture["plan_sha256"],
            fixture["ssh_config"],
            runner=FakeRunner(fixture),
        )
        assert "Execution mode: resumed local completion from preserved sanitized export" in transcript
        assert "Resume binding: sha256:" in transcript


def test_preserved_projection_tampering_fails_closed() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        export_root = stage_preserved_export(fixture)

        unknown_result = copy.deepcopy(fixture["remote_result"])
        unknown_result["private_path"] = "/private/should-not-cross"
        expect_error(
            lambda: validate_remote_result(
                fixture["plan"], fixture["plan_sha256"], unknown_result
            ),
            "p07_remote_result_shape_invalid",
        )

        unknown_profile = copy.deepcopy(fixture["remote_result"])
        unknown_profile["profiles"][0]["private_path"] = "/private/should-not-cross"
        expect_error(
            lambda: validate_remote_result(
                fixture["plan"], fixture["plan_sha256"], unknown_profile
            ),
            "p07_remote_profile_shape_invalid",
        )

        unknown_file = copy.deepcopy(fixture["remote_result"])
        unknown_file["files"][0]["private_path"] = "/private/should-not-cross"
        expect_error(
            lambda: validate_remote_result(
                fixture["plan"], fixture["plan_sha256"], unknown_file
            ),
            "p07_remote_file_shape_invalid",
        )

        forged_scenario = copy.deepcopy(fixture["remote_result"])
        forged_scenario["scenario_plan_sha256"] = digest("0")
        validate_remote_result(fixture["plan"], fixture["plan_sha256"], forged_scenario)
        expect_error(
            lambda: validate_export(fixture["plan"], export_root, forged_scenario),
            "p07_sanitized_report_execution_binding_invalid",
        )

        forged_detonation = copy.deepcopy(fixture["remote_result"])
        forged_detonation["detonation_result_sha256"] = digest("0")
        validate_remote_result(fixture["plan"], fixture["plan_sha256"], forged_detonation)
        expect_error(
            lambda: validate_export(fixture["plan"], export_root, forged_detonation),
            "p07_sanitized_report_execution_binding_invalid",
        )

        forged_execution = copy.deepcopy(fixture["remote_result"])
        forged_execution["profiles"][0]["execution_result_sha256"] = digest("0")
        forged_execution["profiles"][0]["host_receipt_sha256"] = digest("0")
        validate_remote_result(fixture["plan"], fixture["plan_sha256"], forged_execution)
        expect_error(
            lambda: validate_export(fixture["plan"], export_root, forged_execution),
            "p07_bundle_binding_invalid",
        )

    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        replace_fixture_bundle(
            fixture,
            "ci_false",
            lambda value: value["events"][0].update(
                source_receipt_sha256=digest("0")
            ),
        )
        export_root = stage_preserved_export(fixture)
        validate_remote_result(
            fixture["plan"], fixture["plan_sha256"], fixture["remote_result"]
        )
        expect_error(
            lambda: validate_export(
                fixture["plan"], export_root, fixture["remote_result"]
            ),
            "p07_bundle_receipt_or_coverage_binding_invalid",
        )

    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        fixture["remote_result"]["profiles"][0]["evidence_coverage_complete"] = True
        export_root = stage_preserved_export(fixture)
        validate_remote_result(
            fixture["plan"], fixture["plan_sha256"], fixture["remote_result"]
        )
        expect_error(
            lambda: validate_export(
                fixture["plan"], export_root, fixture["remote_result"]
            ),
            "p07_bundle_receipt_or_coverage_binding_invalid",
        )


class StopAtWhoathere(Exception):
    pass


def execute_remote_source_to_first_subprocess(plan: dict[str, Any]) -> int:
    calls: list[list[str]] = []
    fake_subprocess = types.ModuleType("subprocess")
    fake_subprocess.PIPE = object()

    def fake_run(argv: list[str], **_: Any) -> None:
        calls.append(list(argv))
        raise StopAtWhoathere

    fake_subprocess.run = fake_run
    original = sys.modules.get("subprocess")
    sys.modules["subprocess"] = fake_subprocess
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                exec(build_remote_source(plan, digest("a")), {"__name__": "__main__"})
            except SystemExit:
                pass
    finally:
        if original is None:
            del sys.modules["subprocess"]
        else:
            sys.modules["subprocess"] = original
    return len(calls)


def make_remote_preexecution_plan(root: Path) -> dict[str, Any]:
    remote_root = root / "remote"
    remote_root.mkdir(mode=0o700)
    artifact = private_file(remote_root / "artifact.tgz", b"inert-artifact")
    whoathere = private_file(remote_root / "whoathere", b"bound-whoathere")
    sanitizer = private_file(remote_root / "sanitizer.py", b"sanitizer = True\n")
    exporter = private_file(remote_root / "exporter.py", b"exporter = True\n")
    detonation_root = remote_root / "detonation"
    run_root = remote_root / "run"
    config_raw = canonical(
        {"dependency_closure_path": None, "output_root": str(detonation_root)}
    )
    config = private_file(remote_root / "config.json", config_raw)
    return {
        "demo": {
            "artifact_sha256": artifact["sha256"],
            "artifact_byte_length": len(b"inert-artifact"),
        },
        "remote": {
            "artifact": artifact,
            "whoathere": whoathere,
            "detonation_config": config,
            "report_sanitizer": sanitizer,
            "bundle_exporter": exporter,
            "detonation_output_root": str(detonation_root),
            "run_root": str(run_root),
            "timeout_seconds": 10,
        },
    }


def test_remote_preexecution_boundaries_precede_whoathere() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-remote-source-") as temporary:
        baseline_root = Path(temporary) / "baseline"
        baseline_root.mkdir(mode=0o700)
        baseline = make_remote_preexecution_plan(baseline_root)
        assert execute_remote_source_to_first_subprocess(baseline) == 1

    mutations = (
        ("artifact", lambda plan, root: plan["remote"]["artifact"].update(sha256=digest("0"))),
        ("whoathere", lambda plan, root: plan["remote"]["whoathere"].update(sha256=digest("0"))),
        ("config", lambda plan, root: plan["remote"]["detonation_config"].update(sha256=digest("0"))),
        ("sanitizer", lambda plan, root: plan["remote"]["report_sanitizer"].update(sha256=digest("0"))),
        ("exporter", lambda plan, root: plan["remote"]["bundle_exporter"].update(sha256=digest("0"))),
        (
            "stale_detonation",
            lambda plan, root: Path(plan["remote"]["detonation_output_root"]).mkdir(),
        ),
        ("stale_run", lambda plan, root: Path(plan["remote"]["run_root"]).mkdir()),
    )
    for name, mutate in mutations:
        with tempfile.TemporaryDirectory(prefix=f"whoathere-p07-{name}-") as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            plan = make_remote_preexecution_plan(root)
            mutate(plan, root)
            assert execute_remote_source_to_first_subprocess(plan) == 0, name

    with tempfile.TemporaryDirectory(prefix="whoathere-p07-config-output-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        plan = make_remote_preexecution_plan(root)
        config_path = Path(plan["remote"]["detonation_config"]["path"])
        config_raw = canonical(
            {"dependency_closure_path": None, "output_root": str(root / "wrong")}
        )
        config_path.write_bytes(config_raw)
        plan["remote"]["detonation_config"]["sha256"] = sha256_bytes(config_raw)
        assert execute_remote_source_to_first_subprocess(plan) == 0


def test_missing_citation_fails() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        runner = FakeRunner(fixture, "citation_missing")
        expect_error(
            lambda: run_demo(
                fixture["plan_path"],
                fixture["plan_sha256"],
                fixture["ssh_config"],
                runner=runner,
            ),
            "p07_reconciliation_citation_invalid",
        )


def test_observer_result_digest_substitution_fails() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        runner = FakeRunner(fixture, "observer_digest_mismatch")
        expect_error(
            lambda: run_demo(
                fixture["plan_path"],
                fixture["plan_sha256"],
                fixture["ssh_config"],
                runner=runner,
            ),
            "p07_reconciliation_finding_set_invalid",
        )


def test_cross_plan_preserved_export_replay_fails_before_runner() -> None:
    with tempfile.TemporaryDirectory(prefix="whoathere-p07-selftest-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        fixture = make_fixture(root)
        stage_preserved_export(fixture)

        changed_plan = copy.deepcopy(fixture["plan"])
        changed_plan["remote"]["detonation_config"]["sha256"] = digest("0")
        p06_path = Path(changed_plan["preflight"]["input"]["path"])
        p06_input = json.loads(p06_path.read_text(encoding="utf-8"))
        for item in p06_input["run_binding"]["files"]:
            if item["label"] == "detonation_config":
                item["sha256"] = digest("0")
        p06_raw = canonical(p06_input)
        p06_path.write_bytes(p06_raw)
        p06_path.chmod(0o600)
        changed_plan["preflight"]["input"]["sha256"] = sha256_bytes(p06_raw)
        changed_raw = canonical(changed_plan)
        fixture["plan_path"].write_bytes(changed_raw)
        fixture["plan_path"].chmod(0o600)

        runner = FakeRunner(fixture)
        expect_error(
            lambda: resume_sanitized_local(
                fixture["plan_path"],
                sha256_bytes(changed_raw),
                fixture["ssh_config"],
                runner=runner,
            ),
            "p07_remote_result_binding_invalid",
        )
        assert not runner.calls


def main() -> int:
    tests = [
        test_complete_run,
        test_preflight_stops_execution,
        test_digest_mismatch_stops_before_runner,
        test_public_plan_mode_stops_before_runner,
        test_preflight_plan_join_mismatch_stops_before_runner,
        test_remote_cardinality_and_safety_fail_closed,
        test_resume_is_visible_and_digest_bound,
        test_preserved_projection_tampering_fails_closed,
        test_remote_preexecution_boundaries_precede_whoathere,
        test_missing_citation_fails,
        test_observer_result_digest_substitution_fails,
        test_cross_plan_preserved_export_replay_fails_before_runner,
    ]
    for test in tests:
        test()
    print(f"P07 inert end-to-end self-test: PASS ({len(tests)} cases)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
