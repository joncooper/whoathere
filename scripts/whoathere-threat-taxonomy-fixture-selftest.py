#!/usr/bin/env python3
"""Self-test the deterministic, inert threat-taxonomy package fixtures."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path
from types import ModuleType
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "whoathere/tests/fixtures/threat-taxonomy-v1"
BUILDER_PATH = FIXTURE_ROOT / "build_fixtures.py"
EXPECTATIONS_PATH = FIXTURE_ROOT / "sealed/expectations-v2.json"
EXPECTATIONS_SHA_PATH = FIXTURE_ROOT / "sealed/expectations-v2.json.sha256"
FAKE_CANARY = "WHOATHERE_FAKE_CANARY_V1:fixture-only-value"

THREAT_CLASSES = {
    "credential_and_sensitive_file_discovery",
    "network_and_exfiltration",
    "second_stage_native_or_wasm_handoff",
    "process_execution_and_dynamic_loading",
    "obfuscation_and_packing",
    "environment_and_time_gating",
    "persistence_destruction_and_self_deletion",
    "repository_package_and_self_propagation",
    "dependency_indirection",
    "import_time_tampering",
}
TRIGGERS = {
    "npm_lifecycle",
    "npm_bin",
    "npm_import",
    "wheel_pth",
    "wheel_import",
    "wheel_entry_point",
    "sdist_build_backend",
    "sdist_setup_py",
    "sdist_import",
}
EVALUATOR_BEHAVIOR_LABELS = {
    "credential_env_access",
    "filesystem_scan",
    "ssh_git_cloud_token_access",
    "npm_token_access",
    "pypi_token_access",
    "dns_exfil",
    "https_exfil",
    "metadata_service_access",
    "second_stage_fetch",
    "process_spawn",
    "persistence",
    "self_deletion",
    "github_actions_modification",
    "ci_gated_activation",
    "delayed_activation",
    "platform_gating",
    "native_binary_payload",
    "dependency_confusion",
    "direct_source",
    "self_propagation",
    "obfuscation",
}
MODALITIES = {"deterministic", "scanner", "claude", "codex", "dynamic", "fused"}
EVIDENCE_MODALITIES = {"process", "filesystem", "canary", "network", "scenario"}


class SelftestFailure(RuntimeError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SelftestFailure(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_builder() -> ModuleType:
    spec = importlib.util.spec_from_file_location("whoathere_threat_fixture_builder", BUILDER_PATH)
    require(spec is not None and spec.loader is not None, "fixture_builder_import_spec_missing")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_expectations() -> dict[str, Any]:
    data = EXPECTATIONS_PATH.read_bytes()
    seal_parts = EXPECTATIONS_SHA_PATH.read_text(encoding="utf-8").split()
    require(len(seal_parts) == 2, "expectations_seal_format_invalid")
    require(seal_parts[1] == EXPECTATIONS_PATH.name, "expectations_seal_basename_invalid")
    require(seal_parts[0] == sha256(data), "expectations_seal_digest_mismatch")
    expectations = json.loads(data)
    require(
        expectations.get("schema_version") == "whoathere.canonical_fixture_expectations.v2",
        "expectations_schema_invalid",
    )
    require(
        expectations.get("scanner_input_policy")
        == "exact_artifact_only_expectations_sidecar_forbidden",
        "expectations_scanner_policy_invalid",
    )
    return expectations


def validate_expectations(expectations: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cases = expectations.get("cases")
    require(isinstance(cases, list) and len(cases) == 6, "expectations_case_count_invalid")
    by_filename: dict[str, dict[str, Any]] = {}
    sample_ids: set[str] = set()
    for case in cases:
        require(isinstance(case, dict), "expectations_case_invalid")
        filename = case.get("artifact_filename")
        sample_id = case.get("sample_id")
        require(isinstance(filename, str) and Path(filename).name == filename, "artifact_filename_invalid")
        require(isinstance(sample_id, str) and sample_id not in sample_ids, "sample_id_invalid_or_duplicate")
        require(filename not in by_filename, "artifact_filename_duplicate")
        sample_ids.add(sample_id)
        by_filename[filename] = case
        digest = case.get("artifact_sha256")
        require(isinstance(digest, str) and len(digest) == 64, "artifact_digest_invalid")
        require(case.get("expected_result") in {"malicious", "benign"}, "expected_result_invalid")
        threat_classes = case.get("threat_classes")
        triggers = case.get("trigger_labels")
        require(isinstance(threat_classes, list) and set(threat_classes) <= THREAT_CLASSES, "threat_class_invalid")
        require(isinstance(triggers, list) and set(triggers) <= TRIGGERS, "trigger_label_invalid")
        profiles = case.get("profiles")
        require(isinstance(profiles, list) and profiles, "profiles_missing")
        profile_ids: set[str] = set()
        for profile in profiles:
            require(isinstance(profile, dict), "profile_invalid")
            profile_id = profile.get("profile_id")
            require(isinstance(profile_id, str) and profile_id not in profile_ids, "profile_id_invalid_or_duplicate")
            profile_ids.add(profile_id)
            require(profile.get("trigger_label") in TRIGGERS, "profile_trigger_invalid")
            labels = profile.get("required_behavior_labels")
            require(isinstance(labels, list) and set(labels) <= EVALUATOR_BEHAVIOR_LABELS, "behavior_label_invalid")
            modalities = profile.get("required_modalities")
            require(isinstance(modalities, list) and set(modalities) <= MODALITIES, "required_modality_invalid")
            evidence_modalities = profile.get("required_evidence_modalities")
            require(
                isinstance(evidence_modalities, list)
                and set(evidence_modalities) <= EVIDENCE_MODALITIES,
                "required_evidence_modality_invalid",
            )
            require(profile.get("require_complete") is True, "profile_must_require_complete")
            observations = profile.get("expected_observation_kinds")
            require(
                isinstance(observations, list)
                and set(observations) <= {"local_sinkhole_network_intent"},
                "expected_observation_kind_invalid",
            )
            if case["expected_result"] == "benign":
                require(not labels, "benign_profile_has_required_malicious_behavior")
        neighbor = case.get("matched_neighbor_sample_id")
        require(isinstance(neighbor, str), "matched_neighbor_missing")
    for case in cases:
        neighbor_id = case["matched_neighbor_sample_id"]
        require(neighbor_id in sample_ids, "matched_neighbor_unknown")
        neighbor = next(item for item in cases if item["sample_id"] == neighbor_id)
        require(neighbor["expected_result"] != case["expected_result"], "matched_neighbor_same_expected_result")
        require(neighbor["ecosystem"] == case["ecosystem"], "matched_neighbor_ecosystem_mismatch")
        require(neighbor["artifact_kind"] == case["artifact_kind"], "matched_neighbor_artifact_kind_mismatch")
    return by_filename


def archive_members(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
    else:
        with tarfile.open(path, "r:gz") as archive:
            names = archive.getnames()
    for name in names:
        candidate = Path(name)
        require(not candidate.is_absolute(), f"archive_absolute_path:{path.name}:{name}")
        require(".." not in candidate.parts, f"archive_parent_traversal:{path.name}:{name}")
        require("expectations" not in name.lower(), f"sealed_expectations_leaked_into_artifact:{path.name}")
        require("sealed/" not in name.lower(), f"sealed_directory_leaked_into_artifact:{path.name}")
    return names


def validate_npm_physical_fixture_contract(path: Path, *, active: bool) -> None:
    with tarfile.open(path, "r:gz") as archive:
        source_file = archive.extractfile("package/postinstall.js")
        require(source_file is not None, f"npm_postinstall_missing:{path.name}")
        source = source_file.read().decode("utf-8")
    if active:
        require(
            'process.env.HOME === "/run/whoathere/home"' in source,
            "npm_physical_fixture_home_binding_missing",
        )
        require(
            "/run/whoathere/home/.whoathere-canaries/npm-token" in source,
            "npm_physical_fixture_canary_binding_missing",
        )
        require(
            'resolved.startsWith("/run/whoathere/work/npm/")' in source,
            "npm_physical_fixture_output_binding_missing",
        )
        require(
            "whoathere_fake_npm_token_v1_" in source,
            "npm_physical_fixture_canary_sentinel_missing",
        )
    else:
        require(
            "const runtimeFixture = false;" in source,
            "npm_benign_neighbor_must_not_auto_arm",
        )


def minimal_environment(root: Path, *, armed: bool, ci: str = "true", fake_path: Path | None = None) -> dict[str, str]:
    home = root / "home"
    temp = root / "tmp"
    output = root / "markers"
    npm_cache = root / "npm-cache"
    for directory in (home, temp, output, npm_cache):
        directory.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "TMPDIR": str(temp),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "CI": ci,
        "WHOATHERE_FIXTURE_ARMED": "1" if armed else "0",
        "WHOATHERE_FIXTURE_OUTPUT_DIR": str(output),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "NPM_CONFIG_USERCONFIG": os.devnull,
        "NPM_CONFIG_CACHE": str(npm_cache),
        "NPM_CONFIG_OFFLINE": "true",
        "NPM_CONFIG_AUDIT": "false",
        "NPM_CONFIG_FUND": "false",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false",
    }
    if fake_path is not None:
        env["WHOATHERE_FAKE_CREDENTIAL_PATH"] = str(fake_path)
    return env


def run(command: list[str], *, cwd: Path, env: dict[str, str], timeout: int = 90) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0:
        raise SelftestFailure(
            f"command_failed:{result.returncode}:{' '.join(command)}\nstdout={result.stdout}\nstderr={result.stderr}"
        )
    return result


def read_marker(
    path: Path,
    expected_trigger: str,
    expected_canary_touched: bool,
    *,
    expected_network_intent: str = "local_sinkhole_udp",
) -> dict[str, Any]:
    require(path.is_file(), f"marker_missing:{path.name}")
    raw = path.read_bytes()
    require(FAKE_CANARY.encode() not in raw, f"fake_canary_leaked:{path.name}")
    marker = json.loads(raw)
    require(marker.get("trigger") == expected_trigger, f"marker_trigger_invalid:{path.name}")
    require(marker.get("canary_touched") is expected_canary_touched, f"marker_canary_state_invalid:{path.name}")
    require(
        marker.get("network_intent") == expected_network_intent,
        f"marker_network_intent_invalid:{path.name}",
    )
    require(marker.get("destination") == "127.0.0.1:48739", f"marker_destination_invalid:{path.name}")
    return marker


def run_npm_case(artifact: Path, root: Path, *, active: bool, ci: str, fake_path: Path | None) -> None:
    consumer = root / "consumer"
    consumer.mkdir(parents=True)
    (consumer / "package.json").write_text(
        json.dumps({"name": "whoathere-fixture-consumer", "version": "1.0.0", "private": True}) + "\n",
        encoding="utf-8",
    )
    env = minimal_environment(root, armed=True, ci=ci, fake_path=fake_path)
    run(
        [
            "npm",
            "install",
            "--offline",
            "--ignore-scripts=false",
            "--no-audit",
            "--no-fund",
            "--package-lock=false",
            str(artifact),
        ],
        cwd=consumer,
        env=env,
    )
    marker_name = "npm_lifecycle_ci_true.json" if ci == "true" else "npm_lifecycle_ci_false.json"
    read_marker(
        root / "markers" / marker_name,
        marker_name.removesuffix(".json"),
        active and ci == "true",
        expected_network_intent="local_sinkhole_tcp",
    )


def extract_wheel(artifact: Path, destination: Path) -> Path:
    destination.mkdir(parents=True)
    with zipfile.ZipFile(artifact) as archive:
        for member in archive.infolist():
            candidate = Path(member.filename)
            require(not candidate.is_absolute() and ".." not in candidate.parts, "wheel_member_path_invalid")
            require(not member.is_dir(), "wheel_directory_member_refused")
            target = destination.joinpath(*candidate.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.read(member))
    return destination


def exercise_wheel(artifact: Path, root: Path, *, active: bool, distribution: str, fake_path: Path | None) -> None:
    root.mkdir(parents=True, exist_ok=True)
    site_dir = extract_wheel(artifact, root / "site")
    env = minimal_environment(root, armed=True, fake_path=fake_path)
    run(
        [sys.executable, "-S", "-c", "import site,sys; site.addsitedir(sys.argv[1])", str(site_dir)],
        cwd=root,
        env=env,
    )
    read_marker(root / "markers/wheel_pth.json", "wheel_pth", active)
    run(
        [
            sys.executable,
            "-S",
            "-c",
            f"import sys; sys.path.insert(0, sys.argv[1]); import {distribution}",
            str(site_dir),
        ],
        cwd=root,
        env=env,
    )
    read_marker(root / "markers/wheel_import.json", "wheel_import", active)
    entry_points = site_dir / f"{distribution}-1.0.0.dist-info/entry_points.txt"
    require(
        entry_points.read_text(encoding="utf-8").strip()
        == f"[console_scripts]\n{distribution.replace('_', '-')} = {distribution}_cli:main",
        "console_entry_metadata_invalid",
    )
    run(
        [
            sys.executable,
            "-S",
            "-c",
            f"import sys; sys.path.insert(0, sys.argv[1]); from {distribution}_cli import main; raise SystemExit(main())",
            str(site_dir),
        ],
        cwd=root,
        env=env,
    )
    read_marker(root / "markers/wheel_entry_point.json", "wheel_entry_point", active)


def extract_sdist(artifact: Path, destination: Path) -> Path:
    destination.mkdir(parents=True)
    with tarfile.open(artifact, "r:gz") as archive:
        members = archive.getmembers()
        roots: set[str] = set()
        for member in members:
            candidate = Path(member.name)
            require(not candidate.is_absolute() and ".." not in candidate.parts, "sdist_member_path_invalid")
            require(member.isfile(), "sdist_non_file_member_refused")
            roots.add(candidate.parts[0])
            data = archive.extractfile(member)
            require(data is not None, "sdist_member_unreadable")
            target = destination.joinpath(*candidate.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data.read())
    require(len(roots) == 1, "sdist_root_count_invalid")
    return destination / next(iter(roots))


def exercise_sdist(artifact: Path, root: Path, *, active: bool, distribution: str, fake_path: Path | None) -> None:
    project = extract_sdist(artifact, root / "source")
    wheels = root / "wheels"
    wheels.mkdir()
    env = minimal_environment(root, armed=True, fake_path=fake_path)
    run(
        [
            sys.executable,
            "-S",
            "-c",
            (
                "import sys; sys.path.insert(0, sys.argv[1]); "
                "import fixture_backend; print(fixture_backend.build_wheel(sys.argv[2]))"
            ),
            str(project / "backend"),
            str(wheels),
        ],
        cwd=root,
        env=env,
        timeout=120,
    )
    read_marker(root / "markers/sdist_build_backend.json", "sdist_build_backend", active)
    derived = sorted(wheels.glob("*.whl"))
    require(len(derived) == 1, "sdist_derived_wheel_count_invalid")
    runtime_root = root / "derived-runtime"
    runtime_root.mkdir()
    exercise_wheel(derived[0], runtime_root, active=active, distribution=distribution, fake_path=fake_path)


def main() -> int:
    builder = load_builder()
    expectations = load_expectations()
    expected_by_filename = validate_expectations(expectations)
    with tempfile.TemporaryDirectory(prefix="whoathere-fixture-selftest-") as temporary:
        temp = Path(temporary)
        build_a = temp / "build-a"
        build_b = temp / "build-b"
        first = builder.build_all(build_a)
        second = builder.build_all(build_b)
        require(first == second, "fixture_build_metadata_not_deterministic")
        require({item["filename"] for item in first} == set(expected_by_filename), "fixture_artifact_set_mismatch")
        for item in first:
            filename = str(item["filename"])
            artifact_a = build_a / filename
            artifact_b = build_b / filename
            require(artifact_a.read_bytes() == artifact_b.read_bytes(), f"fixture_bytes_not_deterministic:{filename}")
            require(item["sha256"] == expected_by_filename[filename]["artifact_sha256"], f"sealed_digest_mismatch:{filename}")
            archive_members(artifact_a)
            if filename.startswith("whoathere-fixture-npm-ci-"):
                validate_npm_physical_fixture_contract(
                    artifact_a,
                    active="-canary-" in filename,
                )

        fake_root = temp / "whoathere-fixture-fake-canary"
        fake_root.mkdir()
        fake_path = fake_root / "whoathere-fake-credential.txt"
        fake_path.write_text(FAKE_CANARY + "\n", encoding="utf-8")

        run_npm_case(
            build_a / "whoathere-fixture-npm-ci-canary-1.0.0.tgz",
            temp / "whoathere-fixture-npm-canary-ci-false",
            active=True,
            ci="false",
            fake_path=None,
        )
        run_npm_case(
            build_a / "whoathere-fixture-npm-ci-canary-1.0.0.tgz",
            temp / "whoathere-fixture-npm-canary-ci-true",
            active=True,
            ci="true",
            fake_path=fake_path,
        )
        run_npm_case(
            build_a / "whoathere-fixture-npm-ci-neighbor-1.0.0.tgz",
            temp / "whoathere-fixture-npm-neighbor-ci-true",
            active=False,
            ci="true",
            fake_path=None,
        )

        exercise_wheel(
            build_a / "whoathere_fixture_wheel_canary-1.0.0-py3-none-any.whl",
            temp / "whoathere-fixture-wheel-canary",
            active=True,
            distribution="whoathere_fixture_wheel_canary",
            fake_path=fake_path,
        )
        exercise_wheel(
            build_a / "whoathere_fixture_wheel_neighbor-1.0.0-py3-none-any.whl",
            temp / "whoathere-fixture-wheel-neighbor",
            active=False,
            distribution="whoathere_fixture_wheel_neighbor",
            fake_path=None,
        )

        exercise_sdist(
            build_a / "whoathere_fixture_sdist_canary-1.0.0.tar.gz",
            temp / "whoathere-fixture-sdist-canary",
            active=True,
            distribution="whoathere_fixture_sdist_canary",
            fake_path=fake_path,
        )
        exercise_sdist(
            build_a / "whoathere_fixture_sdist_neighbor-1.0.0.tar.gz",
            temp / "whoathere-fixture-sdist-neighbor",
            active=False,
            distribution="whoathere_fixture_sdist_neighbor",
            fake_path=None,
        )

        for path in temp.rglob("*.json"):
            require(FAKE_CANARY.encode() not in path.read_bytes(), f"fake_canary_leaked_to_json:{path.name}")
    print("whoathere_threat_taxonomy_fixture_selftest=ok artifacts=6 active=3 benign_neighbors=3")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (SelftestFailure, OSError, subprocess.SubprocessError, ValueError, KeyError) as error:
        print(f"whoathere_threat_taxonomy_fixture_selftest=failed reason={error}", file=sys.stderr)
        raise SystemExit(1) from error
