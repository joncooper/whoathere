#!/usr/bin/env python3
"""Collect deduped Python and Node dependency fixtures from ~/src.

The output is intentionally metadata-only: package names, specs/versions, manifest-relative paths,
and coarse source classes. It does not copy project source, lockfile contents, credentials, or
absolute host paths into the fixture list.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 fallback is intentionally absent.
    tomllib = None  # type: ignore[assignment]


DEFAULT_ROOT = Path.home() / "src"
DEFAULT_JSON = (
    Path(__file__).resolve().parents[1]
    / "docs"
    / "product-build-run"
    / "src-dependency-fixtures.json"
)
DEFAULT_MD = DEFAULT_JSON.with_suffix(".md")

MANIFEST_NAMES = {"package.json", "package-lock.json", "pyproject.toml", "requirements.txt", "uv.lock"}
EXCLUDED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".tox",
    ".eggs",
    "site-packages",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".uv-cache",
    ".pdm-build",
    ".next",
    ".turbo",
    ".parcel-cache",
    "target",
    "dist",
    "build",
}
NODE_DEP_FIELDS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
    "bundleDependencies",
    "bundledDependencies",
)
PY_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9_.-]*)")
EGG_RE = re.compile(r"[#&]egg=([A-Za-z0-9_.-]+)")
NODE_NAME_RE = re.compile(r"^(?:@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)$")


def relpath(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def source_class(relative_path: str) -> str:
    parts = relative_path.split("/")
    joined = f"/{relative_path}/"
    if parts and parts[0] == "archive":
        return "archive"
    if "/.agents/" in joined or "/templates/" in joined:
        return "template"
    if "/.claude/worktrees/" in joined:
        return "worktree"
    if "/vendor/" in joined or "/third_party/" in joined or "/.lake/" in joined:
        return "vendored"
    if "/ref/" in joined or "/reference-implementations/" in joined:
        return "reference"
    return "active"


def normalize_node_name(name: str) -> str:
    return name.strip().lower()


def normalize_python_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def strip_inline_comment(value: str) -> str:
    return value.split(" #", 1)[0].strip()


def sanitize_spec(spec: str | None) -> str | None:
    if spec is None:
        return None
    value = strip_inline_comment(str(spec)).strip()
    if not value:
        return None
    lower = value.lower()
    if "://" in lower or lower.startswith(("git+", "hg+", "svn+", "bzr+")):
        return "<url-or-vcs-spec>"
    if lower.startswith(("github:", "gitlab:", "bitbucket:")):
        return "<hosted-vcs-spec>"
    if lower.startswith(("file:", "link:", "portal:")) or value.startswith(("/", "./", "../", "~")):
        return "<path-spec>"
    value = re.sub(r"(?i)(token|password|passwd|secret|api[_-]?key)=([^&\\s]+)", r"\1=<redacted>", value)
    if len(value) > 160:
        return value[:157] + "..."
    return value


def walk_manifests(root: Path) -> list[Path]:
    manifests: list[Path] = []
    for current, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIR_NAMES]
        for filename in files:
            if filename in MANIFEST_NAMES:
                manifests.append(Path(current) / filename)
    return sorted(manifests)


def load_json(path: Path) -> Any | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_toml(path: Path) -> dict[str, Any] | None:
    if tomllib is None:
        return None
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def add_fixture(
    fixtures: dict[tuple[str, str, str], dict[str, Any]],
    *,
    ecosystem: str,
    source: str,
    name: str,
    manifest: Path,
    root: Path,
    manifest_kind: str,
    group: str,
    spec: str | None = None,
    version: str | None = None,
    project_name: str | None = None,
) -> None:
    if not name:
        return
    normalized = normalize_node_name(name) if ecosystem == "node" else normalize_python_name(name)
    if ecosystem == "node" and not NODE_NAME_RE.match(normalized):
        return
    key = (ecosystem, source, normalized)
    relative_manifest = relpath(manifest, root)
    entry = fixtures.setdefault(
        key,
        {
            "ecosystem": ecosystem,
            "source": source,
            "name": normalized,
            "specs": [],
            "versions": [],
            "occurrence_count": 0,
            "source_class_counts": {},
            "groups": {},
            "sample_occurrences": [],
        },
    )
    entry["occurrence_count"] += 1
    sanitized_spec = sanitize_spec(spec)
    if sanitized_spec and sanitized_spec not in entry["specs"]:
        entry["specs"].append(sanitized_spec)
    if version and version not in entry["versions"]:
        entry["versions"].append(version)
    class_name = source_class(relative_manifest)
    entry["source_class_counts"][class_name] = entry["source_class_counts"].get(class_name, 0) + 1
    entry["groups"][group] = entry["groups"].get(group, 0) + 1
    if len(entry["sample_occurrences"]) < 12:
        occurrence = {
            "manifest": relative_manifest,
            "manifest_kind": manifest_kind,
            "group": group,
            "source_class": class_name,
        }
        if project_name:
            occurrence["project_name"] = project_name
        if sanitized_spec:
            occurrence["spec"] = sanitized_spec
        if version:
            occurrence["version"] = version
        entry["sample_occurrences"].append(occurrence)


def parse_package_json(path: Path, root: Path, fixtures: dict[tuple[str, str, str], dict[str, Any]]) -> None:
    data = load_json(path)
    if not isinstance(data, dict):
        return
    project_name = data.get("name") if isinstance(data.get("name"), str) else None
    for field in NODE_DEP_FIELDS:
        deps = data.get(field)
        if isinstance(deps, dict):
            for name, spec in deps.items():
                if isinstance(name, str):
                    add_fixture(
                        fixtures,
                        ecosystem="node",
                        source="declared",
                        name=name,
                        manifest=path,
                        root=root,
                        manifest_kind="package.json",
                        group=field,
                        spec=str(spec) if spec is not None else None,
                        project_name=project_name,
                    )
        elif isinstance(deps, list):
            for name in deps:
                if isinstance(name, str):
                    add_fixture(
                        fixtures,
                        ecosystem="node",
                        source="declared",
                        name=name,
                        manifest=path,
                        root=root,
                        manifest_kind="package.json",
                        group=field,
                        project_name=project_name,
                    )


def package_name_from_lock_path(lock_path: str) -> str | None:
    parts = lock_path.split("/")
    try:
        idx = len(parts) - 1 - list(reversed(parts)).index("node_modules")
    except ValueError:
        return None
    tail = parts[idx + 1 :]
    if not tail:
        return None
    if tail[0].startswith("@") and len(tail) >= 2:
        return f"{tail[0]}/{tail[1]}"
    return tail[0]


def parse_lock_deps_tree(
    deps: dict[str, Any],
    path: Path,
    root: Path,
    fixtures: dict[tuple[str, str, str], dict[str, Any]],
) -> None:
    for name, meta in deps.items():
        if isinstance(name, str):
            version = meta.get("version") if isinstance(meta, dict) and isinstance(meta.get("version"), str) else None
            add_fixture(
                fixtures,
                ecosystem="node",
                source="locked",
                name=name,
                manifest=path,
                root=root,
                manifest_kind="package-lock.json",
                group="dependencies",
                version=version,
            )
        if isinstance(meta, dict) and isinstance(meta.get("dependencies"), dict):
            parse_lock_deps_tree(meta["dependencies"], path, root, fixtures)


def parse_package_lock(path: Path, root: Path, fixtures: dict[tuple[str, str, str], dict[str, Any]]) -> None:
    data = load_json(path)
    if not isinstance(data, dict):
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for lock_path, meta in packages.items():
            if not isinstance(lock_path, str) or lock_path == "":
                continue
            name = package_name_from_lock_path(lock_path)
            if not name:
                continue
            version = meta.get("version") if isinstance(meta, dict) and isinstance(meta.get("version"), str) else None
            add_fixture(
                fixtures,
                ecosystem="node",
                source="locked",
                name=name,
                manifest=path,
                root=root,
                manifest_kind="package-lock.json",
                group="packages",
                version=version,
            )
    deps = data.get("dependencies")
    if isinstance(deps, dict):
        parse_lock_deps_tree(deps, path, root, fixtures)


def parse_requirement_line(line: str) -> tuple[str | None, str | None, str]:
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None, None, "blank_or_comment"
    if raw.startswith(("-r ", "--requirement ", "-c ", "--constraint ")):
        return None, raw, "include_or_constraint"
    if raw.startswith(("--index-url", "--extra-index-url", "--find-links", "--trusted-host", "--pre", "--only-binary", "--no-binary")):
        return None, raw, "installer_option"
    editable = raw.startswith("-e ") or raw.startswith("--editable ")
    if editable:
        match = EGG_RE.search(raw)
        if match:
            return match.group(1), "<url-or-vcs-spec>", "editable"
        return None, "<url-or-vcs-spec>", "editable_unknown_name"
    without_comment = strip_inline_comment(raw)
    if " @ " in without_comment:
        name = without_comment.split(" @ ", 1)[0].strip()
        return name or None, "<url-or-vcs-spec>", "direct_url"
    match = PY_NAME_RE.match(without_comment)
    if match:
        return match.group(1), without_comment, "requirement"
    return None, without_comment, "unknown"


def add_python_req_string(
    req: Any,
    path: Path,
    root: Path,
    fixtures: dict[tuple[str, str, str], dict[str, Any]],
    manifest_kind: str,
    group: str,
    project_name: str | None = None,
) -> None:
    if not isinstance(req, str):
        return
    name, spec, kind = parse_requirement_line(req)
    if name:
        add_fixture(
            fixtures,
            ecosystem="python",
            source="declared",
            name=name,
            manifest=path,
            root=root,
            manifest_kind=manifest_kind,
            group=f"{group}:{kind}",
            spec=spec,
            project_name=project_name,
        )


def parse_requirements(path: Path, root: Path, fixtures: dict[tuple[str, str, str], dict[str, Any]]) -> None:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError:
        lines = path.read_text(errors="ignore").splitlines()
    for line in lines:
        add_python_req_string(line, path, root, fixtures, "requirements.txt", "requirements")


def parse_poetry_dependencies(
    deps: Any,
    path: Path,
    root: Path,
    fixtures: dict[tuple[str, str, str], dict[str, Any]],
    group: str,
    project_name: str | None,
) -> None:
    if not isinstance(deps, dict):
        return
    for name, spec in deps.items():
        if not isinstance(name, str) or name.lower() == "python":
            continue
        spec_text = json.dumps(spec, sort_keys=True) if isinstance(spec, (dict, list)) else str(spec)
        add_fixture(
            fixtures,
            ecosystem="python",
            source="declared",
            name=name,
            manifest=path,
            root=root,
            manifest_kind="pyproject.toml",
            group=group,
            spec=spec_text,
            project_name=project_name,
        )


def parse_pyproject(path: Path, root: Path, fixtures: dict[tuple[str, str, str], dict[str, Any]]) -> None:
    data = load_toml(path)
    if not isinstance(data, dict):
        return
    project = data.get("project") if isinstance(data.get("project"), dict) else {}
    project_name = project.get("name") if isinstance(project.get("name"), str) else None
    for req in project.get("dependencies", []) if isinstance(project.get("dependencies"), list) else []:
        add_python_req_string(req, path, root, fixtures, "pyproject.toml", "project.dependencies", project_name)
    optional = project.get("optional-dependencies")
    if isinstance(optional, dict):
        for group, deps in optional.items():
            if isinstance(deps, list):
                for req in deps:
                    add_python_req_string(req, path, root, fixtures, "pyproject.toml", f"project.optional-dependencies.{group}", project_name)
    build_system = data.get("build-system")
    if isinstance(build_system, dict) and isinstance(build_system.get("requires"), list):
        for req in build_system["requires"]:
            add_python_req_string(req, path, root, fixtures, "pyproject.toml", "build-system.requires", project_name)
    dependency_groups = data.get("dependency-groups")
    if isinstance(dependency_groups, dict):
        for group, deps in dependency_groups.items():
            if isinstance(deps, list):
                for req in deps:
                    add_python_req_string(req, path, root, fixtures, "pyproject.toml", f"dependency-groups.{group}", project_name)
    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) and isinstance(tool.get("poetry"), dict) else {}
    parse_poetry_dependencies(poetry.get("dependencies"), path, root, fixtures, "tool.poetry.dependencies", project_name)
    parse_poetry_dependencies(poetry.get("dev-dependencies"), path, root, fixtures, "tool.poetry.dev-dependencies", project_name)
    poetry_groups = poetry.get("group")
    if isinstance(poetry_groups, dict):
        for group, meta in poetry_groups.items():
            if isinstance(meta, dict):
                parse_poetry_dependencies(meta.get("dependencies"), path, root, fixtures, f"tool.poetry.group.{group}.dependencies", project_name)


def parse_uv_lock(path: Path, root: Path, fixtures: dict[tuple[str, str, str], dict[str, Any]]) -> None:
    data = load_toml(path)
    if not isinstance(data, dict):
        return
    packages = data.get("package")
    if not isinstance(packages, list):
        return
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("name"), str):
            continue
        version = package.get("version") if isinstance(package.get("version"), str) else None
        add_fixture(
            fixtures,
            ecosystem="python",
            source="locked",
            name=package["name"],
            manifest=path,
            root=root,
            manifest_kind="uv.lock",
            group="package",
            version=version,
        )


def collect(root: Path) -> dict[str, Any]:
    fixtures: dict[tuple[str, str, str], dict[str, Any]] = {}
    manifests = walk_manifests(root)
    manifest_counts = Counter(path.name for path in manifests)
    source_class_counts = Counter(source_class(relpath(path, root)) for path in manifests)
    for path in manifests:
        if path.name == "package.json":
            parse_package_json(path, root, fixtures)
        elif path.name == "package-lock.json":
            parse_package_lock(path, root, fixtures)
        elif path.name == "requirements.txt":
            parse_requirements(path, root, fixtures)
        elif path.name == "pyproject.toml":
            parse_pyproject(path, root, fixtures)
        elif path.name == "uv.lock":
            parse_uv_lock(path, root, fixtures)
    fixture_list = sorted(fixtures.values(), key=lambda item: (item["ecosystem"], item["source"], item["name"]))
    for fixture in fixture_list:
        fixture["specs"] = sorted(fixture["specs"])
        fixture["versions"] = sorted(fixture["versions"])
        fixture["source_class_counts"] = dict(sorted(fixture["source_class_counts"].items()))
        fixture["groups"] = dict(sorted(fixture["groups"].items()))
    counts_by_kind = Counter((item["ecosystem"], item["source"]) for item in fixture_list)
    return {
        "schema_version": "whoathere.src_dependency_fixtures.v1",
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "root_label": "~/src",
        "root": "~/" + relpath(root, Path.home()),
        "excluded_dir_names": sorted(EXCLUDED_DIR_NAMES),
        "manifest_counts": dict(sorted(manifest_counts.items())),
        "manifest_source_class_counts": dict(sorted(source_class_counts.items())),
        "fixture_counts": {f"{ecosystem}.{source}": count for (ecosystem, source), count in sorted(counts_by_kind.items())},
        "total_unique_fixtures": len(fixture_list),
        "fixtures": fixture_list,
    }


def markdown_summary(data: dict[str, Any]) -> str:
    fixtures = data["fixtures"]
    top = sorted(fixtures, key=lambda item: (-item["occurrence_count"], item["ecosystem"], item["source"], item["name"]))[:40]
    active = [item for item in fixtures if item["source_class_counts"].get("active")]
    active_top = sorted(active, key=lambda item: (-item["source_class_counts"].get("active", 0), item["ecosystem"], item["source"], item["name"]))[:40]
    lines = [
        "# Source Dependency Fixture List",
        "",
        "Generated from `~/src/**` for WhoaThere beta compatibility testing.",
        "",
        "This file contains dependency metadata only. It does not include project source, lockfile",
        "contents, credentials, canaries, or absolute host paths.",
        "",
        "## Summary",
        "",
        f"- Generated at: `{data['generated_at']}`",
        f"- Root: `{data['root_label']}`",
        f"- Manifests scanned: `{sum(data['manifest_counts'].values())}`",
        f"- Unique deduped fixtures: `{data['total_unique_fixtures']}`",
        "",
        "### Manifest Counts",
        "",
    ]
    for name, count in data["manifest_counts"].items():
        lines.append(f"- `{name}`: `{count}`")
    lines.extend(["", "### Fixture Counts", ""])
    for name, count in data["fixture_counts"].items():
        lines.append(f"- `{name}`: `{count}`")
    lines.extend(["", "### Source Class Counts", ""])
    for name, count in data["manifest_source_class_counts"].items():
        lines.append(f"- `{name}`: `{count}`")
    lines.extend(["", "## Top Fixtures By Occurrence", ""])
    lines.append("| Ecosystem | Source | Package | Occurrences | Versions | Specs |")
    lines.append("| --- | --- | --- | ---: | --- | --- |")
    for item in top:
        versions = ", ".join(item["versions"][:8])
        specs = ", ".join(item["specs"][:4])
        lines.append(f"| {item['ecosystem']} | {item['source']} | `{item['name']}` | {item['occurrence_count']} | `{versions}` | `{specs}` |")
    lines.extend(["", "## Top Active-Project Fixtures", ""])
    lines.append("| Ecosystem | Source | Package | Active Occurrences | Total Occurrences |")
    lines.append("| --- | --- | --- | ---: | ---: |")
    for item in active_top:
        lines.append(
            f"| {item['ecosystem']} | {item['source']} | `{item['name']}` | "
            f"{item['source_class_counts'].get('active', 0)} | {item['occurrence_count']} |"
        )
    lines.extend(
        [
            "",
            "## How To Use This",
            "",
            "- Use `node.locked` and `python.locked` as a broad compatibility corpus for package-risk",
            "  classification, scanner normalization, and allow/manual-review reason quality.",
            "- Use `node.declared` and `python.declared` to build small direct-dependency install",
            "  projects for VM detonation trials.",
            "- Start with `source_class_counts.active`; use `archive`, `template`, `vendored`, and",
            "  `reference` entries for breadth after the active-project pass is stable.",
            "- Do not install this whole list on the host. Use generated throwaway projects and run",
            "  installs through WhoaThere's VM path.",
            "",
            "Full deduped fixture metadata is in `src-dependency-fixtures.json`.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(DEFAULT_ROOT))
    parser.add_argument("--json-out", default=str(DEFAULT_JSON))
    parser.add_argument("--md-out", default=str(DEFAULT_MD))
    args = parser.parse_args()
    root = Path(args.root).expanduser().resolve()
    json_out = Path(args.json_out).expanduser().resolve()
    md_out = Path(args.md_out).expanduser().resolve()
    if not root.is_dir():
        print(f"root_not_found={root}", file=sys.stderr)
        return 64
    data = collect(root)
    json_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md_out.write_text(markdown_summary(data), encoding="utf-8")
    print(f"dependency_fixture_json={json_out}")
    print(f"dependency_fixture_markdown={md_out}")
    print(f"total_unique_fixtures={data['total_unique_fixtures']}")
    for name, count in data["fixture_counts"].items():
        print(f"fixture_count_{name}={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
