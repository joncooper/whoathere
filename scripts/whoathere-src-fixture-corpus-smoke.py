#!/usr/bin/env python3
"""Run WhoaThere local beta checks against the generated ~/src dependency corpus."""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


ROOT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_CORPUS = ROOT_DIR / "docs/product-build-run/src-dependency-fixtures.json"
DEFAULT_REPORT_DIR = ROOT_DIR / "docs/product-build-run"
CLI = ROOT_DIR / "whoathere/target/debug/whoathere"
OLD_PUBLISHED_AT = 1_700_000_000
DEFAULT_TIMEOUT = 120
SENSITIVE_PATTERNS = [
    re.compile("/" + "Users/"),
    re.compile("WHOATHERE_" + "CANARY_TOKEN_VALUE"),
    re.compile("npm_" + "secret_token_value"),
    re.compile("openai_" + "secret_token_value"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
    re.compile(r"://[^\"<> ]+@"),
]


@dataclass
class CommandResult:
    name: str
    command: list[str]
    exit_code: int
    elapsed_seconds: float
    stdout_path: Path
    stderr_path: Path
    json_data: dict[str, Any] | None = None
    parse_error: str | None = None


@dataclass
class FixtureCase:
    name: str
    ecosystem: str
    slice_name: str
    workspace: Path
    expected: str
    package_names: list[str]


@dataclass
class CaseResult:
    case: FixtureCase
    command: str
    exit_code: int
    verdict: str
    package_count: int
    reason_codes: list[str]
    scanner_clean: bool | None
    output_path: Path
    failures: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    repeat_verdict: str | None = None
    repeat_reason_codes: list[str] | None = None


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate fixture projects from the ~/src dependency corpus and run WhoaThere checks.",
    )
    parser.add_argument("--offline", action="store_true", help="Run offline parser/classification cases.")
    parser.add_argument("--online-public", action="store_true", help="Run public scanner/metadata cases.")
    parser.add_argument("--include-vm", action="store_true", help="Run selected VM detonation cases when VM is ready.")
    parser.add_argument("--require-vm", action="store_true", help="Fail if --include-vm is set but VM is not ready.")
    parser.add_argument("--fixture-json", type=Path, default=DEFAULT_CORPUS)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--vm-state-dir", type=Path)
    parser.add_argument("--report-dir", type=Path, default=DEFAULT_REPORT_DIR)
    parser.add_argument("--cleanup-work-dir", action="store_true", help="Delete the temp work dir after writing reports.")
    parser.add_argument("--scanner-timeout-seconds", type=int, default=180)
    parser.add_argument("--detonate-timeout-seconds", type=int, default=900)
    parser.add_argument("--offline-node-direct", type=int, default=50)
    parser.add_argument("--offline-python-direct", type=int, default=50)
    parser.add_argument("--offline-node-locked", type=int, default=200)
    parser.add_argument("--offline-python-locked", type=int, default=200)
    parser.add_argument("--determinism-recheck", action=argparse.BooleanOptionalAction, default=True)
    args = parser.parse_args()
    if not args.offline and not args.online_public and not args.include_vm:
        args.offline = True
    if args.require_vm and not args.include_vm:
        parser.error("--require-vm requires --include-vm")
    return args


def safe_name(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "-", name).strip("-")[:80] or "fixture"


def active_count(fixture: dict[str, Any]) -> int:
    return int(fixture.get("source_class_counts", {}).get("active", 0))


def top_fixtures(
    fixtures: list[dict[str, Any]],
    ecosystem: str,
    source: str,
    limit: int,
    active_only: bool = True,
) -> list[dict[str, Any]]:
    rows = [
        item
        for item in fixtures
        if item.get("ecosystem") == ecosystem
        and item.get("source") == source
        and (not active_only or active_count(item) > 0)
    ]
    rows.sort(
        key=lambda item: (
            active_count(item),
            int(item.get("occurrence_count", 0)),
            str(item.get("name", "")),
        ),
        reverse=True,
    )
    return rows[:limit]


def find_fixture(fixtures: list[dict[str, Any]], ecosystem: str, name: str) -> dict[str, Any] | None:
    lowered = name.lower()
    for fixture in fixtures:
        if fixture.get("ecosystem") == ecosystem and str(fixture.get("name", "")).lower() == lowered:
            return fixture
    return None


def node_spec(fixture: dict[str, Any]) -> str:
    for spec in fixture.get("specs", []):
        if usable_node_spec(str(spec)):
            return str(spec)
    for version in fixture.get("versions", []):
        if str(version):
            return str(version)
    return "*"


def usable_node_spec(spec: str) -> bool:
    if not spec or spec in {"<url>", "<vcs>", "<path>", "<redacted>"}:
        return False
    bad_prefixes = ("http:", "https:", "git+", "file:", "link:", "workspace:")
    return not spec.startswith(bad_prefixes)


def python_requirement(fixture: dict[str, Any], allow_range: bool = True) -> str:
    name = str(fixture.get("name", "")).strip()
    for spec in fixture.get("specs", []):
        spec = str(spec).strip()
        if usable_python_spec(spec, allow_range=allow_range):
            if spec.startswith(("==", ">=", "<=", "~=", "!=", ">", "<")):
                return f"{name}{spec}"
            if re.match(r"^[0-9][A-Za-z0-9_.!*+-]*$", spec):
                return f"{name}=={spec}"
            if allow_range and spec in {"*", ""}:
                return name
    for version in fixture.get("versions", []):
        version = str(version).strip()
        if re.match(r"^[0-9][A-Za-z0-9_.!+-]*$", version):
            return f"{name}=={version} # whoathere-published-at={OLD_PUBLISHED_AT}"
    return name


def usable_python_spec(spec: str, allow_range: bool) -> bool:
    if not spec or spec in {"<url>", "<vcs>", "<path>", "<redacted>"}:
        return False
    if any(marker in spec for marker in ("://", "git+", "file:", "../", "./")):
        return False
    if not allow_range and not (spec.startswith("==") or re.match(r"^[0-9]", spec)):
        return False
    return True


def locked_version(fixture: dict[str, Any], fallback: str = "1.0.0") -> str:
    versions = [str(v) for v in fixture.get("versions", []) if str(v)]
    if versions:
        return sorted(versions)[-1]
    for spec in fixture.get("specs", []):
        spec = str(spec)
        if re.match(r"^[0-9][A-Za-z0-9_.!+-]*$", spec):
            return spec
        if spec.startswith("=="):
            return spec[2:]
    return fallback


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def write_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def write_node_project(path: Path, name: str, dependencies: dict[str, str], extra: dict[str, Any] | None = None) -> None:
    ensure_clean_dir(path)
    package: dict[str, Any] = {
        "name": safe_name(name),
        "version": "1.0.0",
        "private": True,
        "whoatherePublishedAtUnixSeconds": OLD_PUBLISHED_AT,
        "dependencies": dependencies,
    }
    if extra:
        package.update(extra)
    write_json(path / "package.json", package)


def write_node_lock_project(path: Path, name: str, fixtures: list[dict[str, Any]]) -> None:
    ensure_clean_dir(path)
    root_name = safe_name(name)
    package = {
        "name": root_name,
        "version": "1.0.0",
        "private": True,
        "whoatherePublishedAtUnixSeconds": OLD_PUBLISHED_AT,
        "dependencies": {str(f["name"]): locked_version(f) for f in fixtures[:50]},
    }
    packages: dict[str, Any] = {
        "": {
            "name": root_name,
            "version": "1.0.0",
            "dependencies": package["dependencies"],
        }
    }
    for fixture in fixtures:
        pkg = str(fixture["name"])
        version = locked_version(fixture)
        packages[f"node_modules/{pkg}"] = {
            "version": version,
            "resolved": "https://registry.npmjs.org/whoathere-fixture/-/whoathere-fixture.tgz",
            "integrity": "sha512-whoathere-fixture",
        }
    lock = {
        "name": root_name,
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": packages,
    }
    write_json(path / "package.json", package)
    write_json(path / "package-lock.json", lock)


def write_requirements_project(path: Path, lines: list[str]) -> None:
    ensure_clean_dir(path)
    (path / "requirements.txt").write_text("\n".join(lines) + "\n")


def write_uv_lock_project(path: Path, fixtures: list[dict[str, Any]]) -> None:
    ensure_clean_dir(path)
    lines = []
    for fixture in fixtures:
        name = str(fixture["name"])
        version = locked_version(fixture)
        lines.extend(
            [
                "[[package]]",
                f'name = "{name}"',
                f'version = "{version}"',
                'source = { registry = "https://pypi.org/simple" }',
                "",
            ]
        )
    (path / "uv.lock").write_text("\n".join(lines))


def build_cases(fixtures: list[dict[str, Any]], work_dir: Path, args: argparse.Namespace) -> dict[str, list[FixtureCase]]:
    cases: dict[str, list[FixtureCase]] = defaultdict(list)
    generated = work_dir / "generated-fixtures"

    node_declared = top_fixtures(fixtures, "node", "declared", args.offline_node_direct)
    node_deps = {str(f["name"]): node_spec(f) for f in node_declared}
    node_path = generated / "active-direct-node"
    write_node_project(node_path, "whoathere-active-direct-node", node_deps)
    cases["offline"].append(
        FixtureCase("active-direct-node", "npm", "active-direct-small", node_path, "conservative", list(node_deps))
    )

    py_declared = top_fixtures(fixtures, "python", "declared", args.offline_python_direct)
    py_lines = [python_requirement(f) for f in py_declared]
    py_path = generated / "active-direct-python"
    write_requirements_project(py_path, py_lines)
    cases["offline"].append(
        FixtureCase("active-direct-python", "pypi", "active-direct-small", py_path, "conservative", [str(f["name"]) for f in py_declared])
    )

    node_locked = top_fixtures(fixtures, "node", "locked", args.offline_node_locked)
    node_lock_path = generated / "active-locked-node"
    write_node_lock_project(node_lock_path, "whoathere-active-locked-node", node_locked)
    cases["offline"].append(
        FixtureCase("active-locked-node", "npm", "active-locked-small", node_lock_path, "conservative", [str(f["name"]) for f in node_locked])
    )

    py_locked = top_fixtures(fixtures, "python", "locked", args.offline_python_locked)
    py_lock_path = generated / "active-locked-python"
    write_uv_lock_project(py_lock_path, py_locked)
    cases["offline"].append(
        FixtureCase("active-locked-python", "uv", "active-locked-small", py_lock_path, "conservative", [str(f["name"]) for f in py_locked])
    )

    workflow_node_names = [
        "typescript",
        "vite",
        "eslint",
        "react",
        "react-dom",
        "@types/node",
        "tailwindcss",
        "postcss",
    ]
    workflow_node = {
        name: node_spec(find_fixture(fixtures, "node", name) or {"name": name, "specs": ["*"], "versions": []})
        for name in workflow_node_names
    }
    workflow_node_path = generated / "workflow-friction-node"
    write_node_project(workflow_node_path, "whoathere-workflow-friction-node", workflow_node)
    cases["offline"].append(
        FixtureCase("workflow-friction-node", "npm", "workflow-friction", workflow_node_path, "conservative", workflow_node_names)
    )

    workflow_py_names = ["pytest", "hatchling", "setuptools", "wheel", "requests", "httpx", "fastapi"]
    workflow_py_fixtures = [
        find_fixture(fixtures, "python", name) or {"name": name, "specs": [], "versions": ["1.0.0"]}
        for name in workflow_py_names
    ]
    workflow_py_path = generated / "workflow-friction-python"
    write_requirements_project(workflow_py_path, [python_requirement(f) for f in workflow_py_fixtures])
    cases["offline"].append(
        FixtureCase("workflow-friction-python", "pypi", "workflow-friction", workflow_py_path, "conservative", workflow_py_names)
    )

    hard_node_path = generated / "hard-classes-node"
    hard_node_deps = {
        "fsevents": "2.3.3",
        "@esbuild/darwin-arm64": "0.25.0",
        "node-gyp": "^10.0.0",
    }
    write_node_project(
        hard_node_path,
        "whoathere-hard-classes-node",
        hard_node_deps,
        {"gypfile": True, "scripts": {"install": "node-gyp rebuild"}},
    )
    (hard_node_path / "binding.gyp").write_text('{"targets":[{"target_name":"fixture","sources":["fixture.cc"]}]}\n')
    cases["offline"].append(
        FixtureCase("hard-classes-node", "npm", "hard-classes", hard_node_path, "hard_class", list(hard_node_deps))
    )

    hard_py_path = generated / "hard-classes-python"
    hard_py_lines = [
        "numpy==1.26.4 # whoathere-published-at=1700000000",
        "pandas==2.2.2 # whoathere-published-at=1700000000",
        "pyarrow==16.1.0 # whoathere-published-at=1700000000",
        "torch==2.3.1 # whoathere-published-at=1700000000",
        "pillow==10.3.0 # whoathere-published-at=1700000000",
        "duckdb==1.0.0 # whoathere-published-at=1700000000",
    ]
    write_requirements_project(hard_py_path, hard_py_lines)
    (hard_py_path / "native_marker.so").write_text("whoathere fixture native marker\n")
    cases["offline"].append(
        FixtureCase("hard-classes-python", "pypi", "hard-classes", hard_py_path, "hard_class", ["numpy", "pandas", "pyarrow", "torch", "pillow", "duckdb"])
    )

    range_node_path = generated / "range-unpinned-node"
    range_node = {
        "react": "*",
        "typescript": "^5.0.0",
        "vite": "^5.0.0",
        "eslint": ">=8.0.0",
    }
    write_node_project(range_node_path, "whoathere-range-unpinned-node", range_node)
    cases["offline"].append(
        FixtureCase("range-unpinned-node", "npm", "range-unpinned", range_node_path, "range_unpinned", list(range_node))
    )

    range_py_path = generated / "range-unpinned-python"
    write_requirements_project(range_py_path, ["requests>=2.0", "pytest", "httpx~=0.27"])
    cases["offline"].append(
        FixtureCase("range-unpinned-python", "pypi", "range-unpinned", range_py_path, "range_unpinned", ["requests", "pytest", "httpx"])
    )

    online_node_path = generated / "online-public-node"
    online_node = {"typescript": "5.7.2", "react": "19.0.0", "semver": "7.7.1"}
    write_node_project(online_node_path, "whoathere-online-public-node", online_node)
    cases["online"].append(
        FixtureCase("online-public-node", "npm", "online-public", online_node_path, "scanner_public", list(online_node))
    )

    online_py_path = generated / "online-public-python"
    write_requirements_project(
        online_py_path,
        [
            "requests==2.31.0 # whoathere-published-at=1700000000",
            "urllib3==2.2.2 # whoathere-published-at=1700000000",
            "idna==3.7 # whoathere-published-at=1700000000",
        ],
    )
    cases["online"].append(
        FixtureCase("online-public-python", "pypi", "online-public", online_py_path, "scanner_public", ["requests", "urllib3", "idna"])
    )

    cases["vm"].extend(cases["online"][:])
    return cases


def run_command(
    name: str,
    command: list[str],
    output_dir: Path,
    timeout: int = DEFAULT_TIMEOUT,
    cwd: Path = ROOT_DIR,
    env: dict[str, str] | None = None,
) -> CommandResult:
    output_dir.mkdir(parents=True, exist_ok=True)
    label = safe_name(name)
    stdout_path = output_dir / f"{label}.stdout"
    stderr_path = output_dir / f"{label}.stderr"
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            cwd=str(cwd),
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired as exc:
        exit_code = 124
        stdout = exc.stdout if isinstance(exc.stdout, str) else ""
        stderr = (exc.stderr if isinstance(exc.stderr, str) else "") + f"\ncommand timed out after {timeout}s\n"
    elapsed = time.monotonic() - started
    stdout_path.write_text(stdout)
    stderr_path.write_text(stderr)
    data = None
    parse_error = None
    stripped = stdout.strip()
    if stripped.startswith("{"):
        try:
            data = json.loads(stripped)
        except json.JSONDecodeError as exc:
            parse_error = str(exc)
    return CommandResult(name, command, exit_code, elapsed, stdout_path, stderr_path, data, parse_error)


def display_command(command: list[str]) -> str:
    result = []
    for part in command:
        if str(part) == str(CLI):
            result.append("whoathere")
        elif str(part).startswith(str(ROOT_DIR)):
            result.append(str(part).replace(str(ROOT_DIR), "$REPO"))
        else:
            result.append(str(part))
    return " ".join(result)


def output_has_sensitive_material(result: CommandResult) -> list[str]:
    text = result.stdout_path.read_text(errors="replace") + "\n" + result.stderr_path.read_text(errors="replace")
    findings = []
    for pattern in SENSITIVE_PATTERNS:
        if pattern.search(text):
            findings.append(f"sensitive_output_pattern:{pattern.pattern}")
    return findings


def run_package_risk(
    case: FixtureCase,
    state_dir: Path,
    output_dir: Path,
    scanner_receipt: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT,
) -> CaseResult:
    command = [
        str(CLI),
        "package-risk",
        "assess",
        "--workspace",
        str(case.workspace),
        "--ecosystem",
        case.ecosystem,
        "--state-dir",
        str(state_dir),
        "--json",
    ]
    if scanner_receipt:
        command.extend(["--scanner-receipt", str(scanner_receipt)])
    result = run_command(f"package-risk-{case.name}", command, output_dir, timeout=timeout)
    failures = output_has_sensitive_material(result)
    warnings: list[str] = []
    data = result.json_data or {}
    if result.parse_error:
        failures.append("package_risk_output_not_json")
    verdict = str(data.get("overall_verdict", "unknown"))
    package_count = int(data.get("package_count", 0) or 0)
    reason_codes = [str(item) for item in data.get("reason_codes", [])]
    scanner_evidence = data.get("scanner_evidence", {}) if isinstance(data.get("scanner_evidence"), dict) else {}
    scanner_clean = scanner_evidence.get("scanner_clean")
    host_effect = str(data.get("host_effect", ""))
    if "no_package_code_executed" not in host_effect:
        failures.append("package_risk_host_effect_missing_no_package_code_executed")
    if verdict == "auto_sync_candidate" and not scanner_receipt:
        failures.append("auto_sync_candidate_without_scanner_receipt")
    if verdict == "auto_sync_candidate" and scanner_clean is False:
        failures.append("auto_sync_candidate_with_unclean_scanner")
    if case.expected in {"hard_class", "range_unpinned"} and verdict == "auto_sync_candidate":
        failures.append(f"{case.expected}_unexpected_auto_sync_candidate")
    if package_count == 0:
        failures.append("package_risk_found_zero_packages")
    if not reason_codes and verdict != "auto_sync_candidate":
        warnings.append("non_allow_verdict_without_reason_codes")
    if "reputation_metadata_missing" in reason_codes:
        warnings.append("reputation_metadata_missing")
    return CaseResult(
        case=case,
        command=display_command(command),
        exit_code=result.exit_code,
        verdict=verdict,
        package_count=package_count,
        reason_codes=reason_codes,
        scanner_clean=scanner_clean if isinstance(scanner_clean, bool) else None,
        output_path=result.stdout_path,
        failures=failures,
        warnings=warnings,
    )


def run_scanners(
    case: FixtureCase,
    state_dir: Path,
    output_dir: Path,
    timeout: int,
) -> tuple[CommandResult, Path | None, list[str]]:
    scanner_ecosystem = "pypi" if case.ecosystem == "uv" else case.ecosystem
    command = [
        str(CLI),
        "scanners",
        "run",
        "--workspace",
        str(case.workspace),
        "--ecosystem",
        scanner_ecosystem,
        "--state-dir",
        str(state_dir),
        "--timeout-seconds",
        str(timeout),
        "--execute",
        "--json",
    ]
    result = run_command(f"scanners-{case.name}", command, output_dir, timeout=timeout + 20)
    failures = output_has_sensitive_material(result)
    data = result.json_data or {}
    scanner_clean = data.get("scanner_clean")
    if result.parse_error:
        failures.append("scanner_output_not_json")
    if scanner_clean is False and result.exit_code == 0:
        failures.append("scanner_unclean_returned_success")
    receipt_path = None
    raw_receipt = data.get("receipt_path")
    if isinstance(raw_receipt, str) and raw_receipt:
        receipt_path = Path(raw_receipt)
    elif isinstance(data.get("scanner_receipt_auth"), dict):
        receipt_path = result.stdout_path
    return result, receipt_path, failures


def derived_scanner_status(data: dict[str, Any]) -> str:
    status = data.get("status")
    if isinstance(status, str) and status:
        return status
    records = data.get("records", [])
    if not isinstance(records, list):
        records = []
    record_statuses = {str(record.get("status", "unknown")) for record in records if isinstance(record, dict)}
    if not record_statuses:
        return "unknown"
    if any(status in record_statuses for status in {"findings", "error", "timed_out"}):
        return "+".join(sorted(status for status in record_statuses if status in {"findings", "error", "timed_out"}))
    if record_statuses <= {"passed", "not_applicable"}:
        return "passed"
    return "+".join(sorted(record_statuses))


def run_vm_detonate(
    case: FixtureCase,
    state_dir: Path | None,
    output_dir: Path,
    timeout: int,
) -> tuple[CommandResult, list[str]]:
    if case.ecosystem == "npm":
        manager = "npm"
        args = ["install"]
    else:
        manager = "pip"
        args = ["install", "-r", "requirements.txt"]
    command = [
        str(CLI),
        "vm",
        "detonate",
        "--workspace",
        str(case.workspace),
        "--execute",
        "--json",
    ]
    if state_dir is not None:
        command.extend(["--state-dir", str(state_dir)])
    command.extend([manager, "--", *args])
    result = run_command(f"vm-detonate-{case.name}", command, output_dir, timeout=timeout)
    failures = output_has_sensitive_material(result)
    data = result.json_data or {}
    if result.parse_error:
        failures.append("vm_detonate_output_not_json")
    if data.get("sync_back_attempted") is True or data.get("sync_back_enabled") is True:
        failures.append("vm_detonate_unexpected_sync_back")
    return result, failures


def repeat_check(result: CaseResult, state_dir: Path, output_dir: Path) -> None:
    repeated = run_package_risk(
        result.case,
        state_dir=state_dir,
        output_dir=output_dir,
        scanner_receipt=None,
    )
    result.repeat_verdict = repeated.verdict
    result.repeat_reason_codes = repeated.reason_codes
    if result.verdict != repeated.verdict:
        result.failures.append("determinism_verdict_changed")
    if sorted(result.reason_codes) != sorted(repeated.reason_codes):
        result.failures.append("determinism_reason_codes_changed")
    result.failures.extend(f"repeat:{failure}" for failure in repeated.failures)


def summarize_cases(results: list[CaseResult]) -> dict[str, Any]:
    verdict_counts = Counter(result.verdict for result in results)
    reason_counts: Counter[str] = Counter()
    warning_counts: Counter[str] = Counter()
    failure_counts: Counter[str] = Counter()
    packages_seen = 0
    for result in results:
        packages_seen += result.package_count
        reason_counts.update(result.reason_codes)
        warning_counts.update(result.warnings)
        failure_counts.update(result.failures)
    return {
        "case_count": len(results),
        "packages_seen": packages_seen,
        "verdict_counts": dict(sorted(verdict_counts.items())),
        "top_reason_codes": reason_counts.most_common(20),
        "warning_counts": dict(sorted(warning_counts.items())),
        "failure_counts": dict(sorted(failure_counts.items())),
    }


def report_case_table(results: list[CaseResult]) -> str:
    lines = [
        "| Case | Slice | Ecosystem | Verdict | Packages | Exit | Failures | Warnings |",
        "| --- | --- | --- | --- | ---: | ---: | --- | --- |",
    ]
    for result in results:
        failures = ", ".join(result.failures) if result.failures else ""
        warnings = ", ".join(result.warnings) if result.warnings else ""
        lines.append(
            f"| `{result.case.name}` | `{result.case.slice_name}` | `{result.case.ecosystem}` | "
            f"`{result.verdict}` | {result.package_count} | {result.exit_code} | "
            f"{failures or '-'} | {warnings or '-'} |"
        )
    return "\n".join(lines)


def write_reports(
    args: argparse.Namespace,
    work_dir: Path,
    preflight: list[CommandResult],
    offline_results: list[CaseResult],
    online_results: list[CaseResult],
    scanner_results: list[dict[str, Any]],
    vm_results: list[dict[str, Any]],
    global_failures: list[str],
    generated_cases: dict[str, list[FixtureCase]],
) -> tuple[Path, Path]:
    args.report_dir.mkdir(parents=True, exist_ok=True)
    report_json = args.report_dir / "src-fixture-corpus-latest.json"
    report_md = args.report_dir / "src-fixture-corpus-latest.md"
    report_json_label = (
        str(report_json.relative_to(ROOT_DIR)) if report_json.is_relative_to(ROOT_DIR) else str(report_json)
    )
    all_case_results = offline_results + online_results
    summary = {
        "schema_version": "whoathere.src_fixture_corpus_smoke_report.v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "mode": {
            "offline": bool(args.offline),
            "online_public": bool(args.online_public),
            "include_vm": bool(args.include_vm),
        },
        "fixture_json": str(args.fixture_json.relative_to(ROOT_DIR) if args.fixture_json.is_relative_to(ROOT_DIR) else args.fixture_json),
        "work_dir": str(work_dir),
        "state_dir": str(args.state_dir),
        "case_summary": summarize_cases(all_case_results),
        "offline_summary": summarize_cases(offline_results),
        "online_summary": summarize_cases(online_results),
        "scanner_summary": summarize_scanner_results(scanner_results),
        "vm_summary": summarize_vm_results(vm_results),
        "global_failures": global_failures,
        "case_results": [
            {
                "case": result.case.name,
                "slice": result.case.slice_name,
                "ecosystem": result.case.ecosystem,
                "expected": result.case.expected,
                "exit_code": result.exit_code,
                "verdict": result.verdict,
                "package_count": result.package_count,
                "scanner_clean": result.scanner_clean,
                "reason_codes": result.reason_codes,
                "failures": result.failures,
                "warnings": result.warnings,
                "output_path": str(result.output_path),
            }
            for result in all_case_results
        ],
        "scanner_results": scanner_results,
        "vm_results": vm_results,
        "generated_case_counts": {key: len(value) for key, value in generated_cases.items()},
    }
    write_json(report_json, summary)

    failure_count = len(global_failures) + sum(len(result.failures) for result in all_case_results)
    failure_count += sum(len(item.get("failures", [])) for item in scanner_results)
    failure_count += sum(len(item.get("failures", [])) for item in vm_results)
    lines = [
        "# WhoaThere Source Fixture Corpus Smoke Report",
        "",
        f"- Generated at: `{summary['generated_at']}`",
        f"- Mode: offline=`{args.offline}`, online_public=`{args.online_public}`, include_vm=`{args.include_vm}`",
        f"- Work dir: `{work_dir}`",
        f"- State dir: `{args.state_dir}`",
        f"- Total case failures: `{failure_count}`",
        "",
        "## Summary",
        "",
        f"- Cases run: `{summary['case_summary']['case_count']}`",
        f"- Package inputs observed: `{summary['case_summary']['packages_seen']}`",
        f"- Verdict counts: `{summary['case_summary']['verdict_counts']}`",
        f"- Scanner records: `{summary['scanner_summary']['record_count']}`",
        f"- VM records: `{summary['vm_summary']['record_count']}`",
        "",
        "## Offline Package-Risk Cases",
        "",
        report_case_table(offline_results) if offline_results else "_Not run._",
        "",
        "## Online Public Cases",
        "",
        report_case_table(online_results) if online_results else "_Not run._",
        "",
        "## Scanner Results",
        "",
        scanner_table(scanner_results),
        "",
        "## VM Results",
        "",
        vm_table(vm_results),
        "",
        "## Top Reason Codes",
        "",
    ]
    for reason, count in summary["case_summary"]["top_reason_codes"]:
        lines.append(f"- `{reason}`: `{count}`")
    if not summary["case_summary"]["top_reason_codes"]:
        lines.append("- None")
    lines.extend(
        [
            "",
            "## Failures And Warnings",
            "",
        ]
    )
    if global_failures:
        for failure in global_failures:
            lines.append(f"- Global failure: `{failure}`")
    for result in all_case_results:
        for failure in result.failures:
            lines.append(f"- `{result.case.name}` failure: `{failure}`")
    for item in scanner_results:
        for failure in item.get("failures", []):
            lines.append(f"- `{item['case']}` scanner failure: `{failure}`")
    for item in vm_results:
        for failure in item.get("failures", []):
            lines.append(f"- `{item['case']}` VM failure: `{failure}`")
    warnings = []
    for result in all_case_results:
        warnings.extend((result.case.name, warning) for warning in result.warnings)
    if warnings:
        for case_name, warning in warnings[:50]:
            lines.append(f"- `{case_name}` warning: `{warning}`")
    if not global_failures and not any(r.failures for r in all_case_results) and not any(i.get("failures") for i in scanner_results) and not any(i.get("failures") for i in vm_results):
        lines.append("- No harness safety failures detected.")
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `manual_review` is expected for many beta cases when scanner, VM, reputation, or last-known-good evidence is incomplete.",
            "- Hard classes should remain `manual_review` or `deny`; an `auto_sync_candidate` hard-class result is a test failure.",
            "- `reputation_metadata_missing` means this run did not prove registry/repository reputation is productized for that case.",
            "- Scanner and VM failures are not allow signals; they should keep the result conservative.",
            "",
            "## Raw Outputs",
            "",
            f"- Machine-readable report: `{report_json_label}`",
            f"- Command outputs: `{work_dir / 'outputs'}`",
            f"- Generated fixture projects: `{work_dir / 'generated-fixtures'}`",
            "",
        ]
    )
    report_md.write_text("\n".join(lines))
    return report_json, report_md


def summarize_scanner_results(records: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(record.get("status", "unknown")) for record in records)
    clean_counts = Counter(str(record.get("scanner_clean", "unknown")) for record in records)
    failure_counts: Counter[str] = Counter()
    for record in records:
        failure_counts.update(record.get("failures", []))
    return {
        "record_count": len(records),
        "status_counts": dict(sorted(status_counts.items())),
        "scanner_clean_counts": dict(sorted(clean_counts.items())),
        "failure_counts": dict(sorted(failure_counts.items())),
    }


def summarize_vm_results(records: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = Counter(str(record.get("status", "unknown")) for record in records)
    failure_counts: Counter[str] = Counter()
    for record in records:
        failure_counts.update(record.get("failures", []))
    return {
        "record_count": len(records),
        "status_counts": dict(sorted(status_counts.items())),
        "failure_counts": dict(sorted(failure_counts.items())),
    }


def scanner_table(records: list[dict[str, Any]]) -> str:
    if not records:
        return "_Not run._"
    lines = [
        "| Case | Exit | Status | Scanner Clean | Failures |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for record in records:
        failures = ", ".join(record.get("failures", [])) or "-"
        lines.append(
            f"| `{record['case']}` | {record['exit_code']} | `{record.get('status', 'unknown')}` | "
            f"`{record.get('scanner_clean', 'unknown')}` | {failures} |"
        )
    return "\n".join(lines)


def vm_table(records: list[dict[str, Any]]) -> str:
    if not records:
        return "_Not run._"
    lines = [
        "| Case | Exit | Status | Verdict | Failures |",
        "| --- | ---: | --- | --- | --- |",
    ]
    for record in records:
        failures = ", ".join(record.get("failures", [])) or "-"
        lines.append(
            f"| `{record['case']}` | {record['exit_code']} | `{record.get('status', 'unknown')}` | "
            f"`{record.get('verdict', 'unknown')}` | {failures} |"
        )
    return "\n".join(lines)


def bootstrap_scanners(work_dir: Path, timeout: int) -> CommandResult:
    return run_command(
        "bootstrap-scanners",
        [str(ROOT_DIR / "scripts/whoathere-bootstrap-scanners.sh")],
        work_dir / "outputs/preflight",
        timeout=timeout,
    )


def main() -> int:
    args = parse_args()
    temp_root = None
    if args.work_dir is None:
        temp_root = Path(tempfile.mkdtemp(prefix="whoathere-src-fixture-corpus."))
        args.work_dir = temp_root
    else:
        args.work_dir = args.work_dir.resolve()
        args.work_dir.mkdir(parents=True, exist_ok=True)
    if args.state_dir is None:
        args.state_dir = args.work_dir / "state"
    args.state_dir.mkdir(parents=True, exist_ok=True)

    global_failures: list[str] = []
    preflight: list[CommandResult] = []
    offline_results: list[CaseResult] = []
    online_results: list[CaseResult] = []
    scanner_results: list[dict[str, Any]] = []
    vm_results: list[dict[str, Any]] = []

    try:
        corpus = json.loads(args.fixture_json.read_text())
        fixtures = corpus.get("fixtures", [])
        if not isinstance(fixtures, list) or not fixtures:
            raise ValueError("fixture corpus has no fixtures")

        preflight_dir = args.work_dir / "outputs/preflight"
        build = run_command(
            "cargo-build",
            ["cargo", "build", "--manifest-path", str(ROOT_DIR / "whoathere/Cargo.toml"), "-p", "whoathere-cli", "--bin", "whoathere"],
            preflight_dir,
            timeout=300,
        )
        preflight.append(build)
        if build.exit_code != 0:
            global_failures.append("cargo_build_failed")
        for name, command in [
            ("doctor", [str(CLI), "doctor", "--json", "--state-dir", str(args.state_dir)]),
            ("scanners-list", [str(CLI), "scanners", "list", "--json"]),
            ("vm-status", [str(CLI), "vm", "status", "--json"]),
        ]:
            result = run_command(name, command, preflight_dir)
            preflight.append(result)
            if result.parse_error:
                global_failures.append(f"{name}_output_not_json")

        cases = build_cases(fixtures, args.work_dir, args)

        if args.offline:
            offline_dir = args.work_dir / "outputs/offline"
            for case in cases["offline"]:
                result = run_package_risk(case, args.state_dir, offline_dir)
                if args.determinism_recheck:
                    repeat_check(result, args.state_dir, args.work_dir / "outputs/offline-repeat")
                offline_results.append(result)

        if args.online_public:
            bootstrap = bootstrap_scanners(args.work_dir, timeout=max(300, args.scanner_timeout_seconds))
            preflight.append(bootstrap)
            if bootstrap.exit_code != 0:
                global_failures.append("scanner_bootstrap_failed_or_partial")
            online_dir = args.work_dir / "outputs/online"
            for case in cases["online"]:
                scanner_result, receipt_path, scanner_failures = run_scanners(
                    case,
                    args.state_dir,
                    online_dir,
                    timeout=args.scanner_timeout_seconds,
                )
                scanner_data = scanner_result.json_data or {}
                scanner_status = derived_scanner_status(scanner_data)
                scanner_results.append(
                    {
                        "case": case.name,
                        "exit_code": scanner_result.exit_code,
                        "status": scanner_status,
                        "scanner_clean": scanner_data.get("scanner_clean", "unknown"),
                        "reason_codes": scanner_data.get("reason_codes", []),
                        "receipt_path": str(receipt_path) if receipt_path else None,
                        "failures": scanner_failures,
                        "output_path": str(scanner_result.stdout_path),
                    }
                )
                package_result = run_package_risk(
                    case,
                    args.state_dir,
                    online_dir,
                    scanner_receipt=receipt_path,
                    timeout=DEFAULT_TIMEOUT,
                )
                if scanner_data.get("scanner_clean") is not True and package_result.verdict == "auto_sync_candidate":
                    package_result.failures.append("online_auto_sync_candidate_without_clean_scanner")
                online_results.append(package_result)

        if args.include_vm:
            vm_state = args.vm_state_dir
            vm_status_cmd = [str(CLI), "vm", "status", "--json"]
            if vm_state:
                vm_status_cmd.extend(["--state-dir", str(vm_state)])
            vm_status = run_command("vm-status-for-detonation", vm_status_cmd, args.work_dir / "outputs/vm")
            preflight.append(vm_status)
            vm_ready = bool((vm_status.json_data or {}).get("ready"))
            if not vm_ready:
                vm_results.append(
                    {
                        "case": "vm-preflight",
                        "exit_code": vm_status.exit_code,
                        "status": "skipped_not_ready",
                        "verdict": "not_run",
                        "reason_codes": (vm_status.json_data or {}).get("reason_codes", []),
                        "failures": ["vm_not_ready"] if args.require_vm else [],
                        "output_path": str(vm_status.stdout_path),
                    }
                )
                if args.require_vm:
                    global_failures.append("vm_required_but_not_ready")
            else:
                for case in cases["vm"]:
                    vm_result, vm_failures = run_vm_detonate(
                        case,
                        state_dir=vm_state,
                        output_dir=args.work_dir / "outputs/vm",
                        timeout=args.detonate_timeout_seconds,
                    )
                    vm_data = vm_result.json_data or {}
                    vm_results.append(
                        {
                            "case": case.name,
                            "exit_code": vm_result.exit_code,
                            "status": vm_data.get("status", "unknown"),
                            "verdict": vm_data.get("verdict", vm_data.get("overall_verdict", "unknown")),
                            "reason_codes": vm_data.get("reason_codes", []),
                            "failures": vm_failures,
                            "output_path": str(vm_result.stdout_path),
                        }
                    )

        report_json, report_md = write_reports(
            args,
            args.work_dir,
            preflight,
            offline_results,
            online_results,
            scanner_results,
            vm_results,
            global_failures,
            cases,
        )
        total_failures = len(global_failures)
        total_failures += sum(len(result.failures) for result in offline_results + online_results)
        total_failures += sum(len(item.get("failures", [])) for item in scanner_results)
        total_failures += sum(len(item.get("failures", [])) for item in vm_results)
        print(f"src_fixture_corpus_report={report_md}")
        print(f"src_fixture_corpus_report_json={report_json}")
        print(f"src_fixture_corpus_work_dir={args.work_dir}")
        print(f"src_fixture_corpus_failures={total_failures}")
        if total_failures:
            return 20
        return 0
    finally:
        if temp_root is not None and args.cleanup_work_dir:
            shutil.rmtree(temp_root, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
