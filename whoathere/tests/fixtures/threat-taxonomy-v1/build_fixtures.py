#!/usr/bin/env python3
"""Build deterministic, inert package artifacts for behavior-evaluation tests.

This builder deliberately emits package artifacts only. Ground-truth labels live
in the sibling sealed/ directory and must never be copied into scanner inputs.
The active fixtures can read only an explicitly armed fake-canary file and send
only a constant marker to a fixed loopback sinkhole.
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Iterable


VERSION = "1.0.0"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
FILE_MODE = 0o644
EXEC_MODE = 0o755


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def deterministic_tar_gz(entries: dict[str, tuple[bytes, int]]) -> bytes:
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(entries):
            data, mode = entries[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = mode
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(data))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", compresslevel=9, mtime=0, fileobj=compressed) as stream:
        stream.write(tar_buffer.getvalue())
    return compressed.getvalue()


def wheel_record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
    return "sha256=" + digest.decode("ascii")


def deterministic_wheel(
    distribution: str,
    version: str,
    files: dict[str, tuple[bytes, int]],
    entry_point: str,
) -> bytes:
    dist_info = f"{distribution}-{version}.dist-info"
    members = dict(files)
    members[f"{dist_info}/METADATA"] = (
        (
            "Metadata-Version: 2.3\n"
            f"Name: {distribution.replace('_', '-')}\n"
            f"Version: {version}\n"
            "Summary: Inert WhoaThere canonical behavior fixture\n"
            "Requires-Python: >=3.9\n"
        ).encode(),
        FILE_MODE,
    )
    members[f"{dist_info}/WHEEL"] = (
        b"Wheel-Version: 1.0\nGenerator: whoathere-inert-fixture-builder-v1\n"
        b"Root-Is-Purelib: true\nTag: py3-none-any\n",
        FILE_MODE,
    )
    members[f"{dist_info}/entry_points.txt"] = (entry_point.encode(), FILE_MODE)

    record_path = f"{dist_info}/RECORD"
    record_lines = [
        f"{name},{wheel_record_hash(data)},{len(data)}"
        for name, (data, _mode) in sorted(members.items())
    ]
    record_lines.append(f"{record_path},,")
    members[record_path] = (("\n".join(record_lines) + "\n").encode(), FILE_MODE)

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name in sorted(members):
            data, mode = members[name]
            info = zipfile.ZipInfo(name, ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return output.getvalue()


def node_probe_source(active: bool) -> bytes:
    if active:
        probe_body = r'''
  const credentialPath = runtimeFixture
    ? path.resolve("/run/whoathere/home/.whoathere-canaries/npm-token")
    : path.resolve(process.env.WHOATHERE_FAKE_CREDENTIAL_PATH || "");
  if (runtimeFixture) {
    if (credentialPath !== "/run/whoathere/home/.whoathere-canaries/npm-token") {
      throw new Error("fixture_runtime_canary_path_refused");
    }
  } else if (path.basename(credentialPath) !== "whoathere-fake-credential.txt" ||
             !credentialPath.split(path.sep).some((part) => part.startsWith("whoathere-fixture-"))) {
      throw new Error("fixture_fake_credential_path_refused");
  }
  const fakeCredential = fs.readFileSync(credentialPath, "utf8");
  const expectedSentinel = runtimeFixture
    ? "whoathere_fake_npm_token_v1_"
    : "WHOATHERE_FAKE_CANARY_V1:";
  if (!fakeCredential.startsWith(expectedSentinel)) {
    throw new Error("fixture_fake_credential_sentinel_missing");
  }
  writeMarker(outputDir, "npm_lifecycle_ci_true", true);
'''
        runtime_fixture_expression = (
            'process.env.WHOATHERE_FIXTURE_ARMED === undefined && '
            'process.env.HOME === "/run/whoathere/home"'
        )
    else:
        probe_body = r'''
  const publicData = fs.readFileSync(path.join(__dirname, "fixture-public.txt"), "utf8");
  if (publicData.trim() !== "whoathere inert public fixture data") {
    throw new Error("fixture_public_data_invalid");
  }
  writeMarker(outputDir, "npm_lifecycle_ci_true", false);
'''
        runtime_fixture_expression = "false"
    source = rf'''"use strict";
const fs = require("fs");
const path = require("path");
const net = require("net");

function outputDirectory(runtimeFixture) {{
  if (runtimeFixture) {{
    const resolved = path.resolve(process.cwd(), ".whoathere-fixture-output");
    if (!resolved.startsWith("/run/whoathere/work/npm/")) {{
      throw new Error("fixture_runtime_output_path_refused");
    }}
    fs.mkdirSync(resolved, {{ recursive: true }});
    return resolved;
  }}
  const raw = process.env.WHOATHERE_FIXTURE_OUTPUT_DIR || "";
  const resolved = path.resolve(raw);
  if (!resolved.split(path.sep).some((part) => part.startsWith("whoathere-fixture-"))) {{
    throw new Error("fixture_output_path_refused");
  }}
  fs.mkdirSync(resolved, {{ recursive: true }});
  return resolved;
}}

function writeMarker(directory, trigger, canaryTouched) {{
  const marker = {{
    schema_version: "whoathere.inert_fixture_marker.v1",
    trigger,
    canary_touched: canaryTouched,
    network_intent: "local_sinkhole_tcp",
    destination: "127.0.0.1:48739"
  }};
  fs.writeFileSync(path.join(directory, `${{trigger}}.json`), JSON.stringify(marker) + "\n", {{ mode: 0o600 }});
}}

const runtimeFixture = {runtime_fixture_expression};
const fixtureArmed = process.env.WHOATHERE_FIXTURE_ARMED === "1" || runtimeFixture;
if (fixtureArmed) {{
  const outputDir = outputDirectory(runtimeFixture);
  if (process.env.CI !== "true") {{
    writeMarker(outputDir, "npm_lifecycle_ci_false", false);
  }} else {{
{probe_body}
    const socket = net.createConnection({{ host: "127.0.0.1", port: 48739 }});
    socket.once("connect", () => socket.end(Buffer.from("WHOATHERE_INERT_SINKHOLE_INTENT_V1")));
    socket.once("error", () => socket.destroy());
  }}
}}
'''
    return source.encode()


def npm_artifact(active: bool) -> tuple[str, bytes]:
    suffix = "canary" if active else "neighbor"
    name = f"whoathere-fixture-npm-ci-{suffix}"
    package = {
        "name": name,
        "version": VERSION,
        "description": "Inert WhoaThere canonical behavior fixture",
        "license": "UNLICENSED",
        "scripts": {"postinstall": "node postinstall.js"},
    }
    entries = {
        "package/package.json": (canonical_json(package), FILE_MODE),
        "package/postinstall.js": (node_probe_source(active), FILE_MODE),
        "package/fixture-public.txt": (b"whoathere inert public fixture data\n", FILE_MODE),
    }
    filename = f"{name}-{VERSION}.tgz"
    return filename, deterministic_tar_gz(entries)


def python_probe_source(active: bool, public_filename: str) -> bytes:
    if active:
        probe_body = r'''
    credential_path = Path(os.environ.get("WHOATHERE_FAKE_CREDENTIAL_PATH", "")).resolve()
    if (
        credential_path.name != "whoathere-fake-credential.txt"
        or not any(part.startswith("whoathere-fixture-") for part in credential_path.parts)
    ):
        raise RuntimeError("fixture_fake_credential_path_refused")
    fake_credential = credential_path.read_text(encoding="utf-8")
    if not fake_credential.startswith("WHOATHERE_FAKE_CANARY_V1:"):
        raise RuntimeError("fixture_fake_credential_sentinel_missing")
    canary_touched = True
'''
    else:
        probe_body = rf'''
    public_data = Path(__file__).with_name("{public_filename}").read_text(encoding="utf-8")
    if public_data.strip() != "whoathere inert public fixture data":
        raise RuntimeError("fixture_public_data_invalid")
    canary_touched = False
'''
    return f'''"""Shared inert probe; cannot read arbitrary credentials or reach a public route."""
from __future__ import annotations

import json
import os
import socket
from pathlib import Path


def probe(trigger: str) -> None:
    if os.environ.get("WHOATHERE_FIXTURE_ARMED") != "1":
        return
    output_dir = Path(os.environ.get("WHOATHERE_FIXTURE_OUTPUT_DIR", "")).resolve()
    if not any(part.startswith("whoathere-fixture-") for part in output_dir.parts):
        raise RuntimeError("fixture_output_path_refused")
    output_dir.mkdir(parents=True, exist_ok=True)
{probe_body}
    marker = {{
        "schema_version": "whoathere.inert_fixture_marker.v1",
        "trigger": trigger,
        "canary_touched": canary_touched,
        "network_intent": "local_sinkhole_udp",
        "destination": "127.0.0.1:48739",
    }}
    (output_dir / f"{{trigger}}.json").write_text(
        json.dumps(marker, sort_keys=True) + "\\n", encoding="utf-8"
    )
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sinkhole:
            sinkhole.sendto(b"WHOATHERE_INERT_SINKHOLE_INTENT_V1", ("127.0.0.1", 48739))
    except OSError:
        # A no-network sandbox is a successful containment outcome. The file
        # marker and syscall attempt still establish the typed sinkhole intent.
        pass
'''.encode()


def wheel_payload(distribution: str, active: bool) -> tuple[dict[str, tuple[bytes, int]], str]:
    module = distribution
    helper = f"{distribution}_probe"
    pth_module = f"{distribution}_pth"
    cli_module = f"{distribution}_cli"
    public_filename = f"{distribution}_public.txt"
    files: dict[str, tuple[bytes, int]] = {
        f"{helper}.py": (python_probe_source(active, public_filename), FILE_MODE),
        f"{public_filename}": (b"whoathere inert public fixture data\n", FILE_MODE),
        f"{pth_module}.py": (
            f"from {helper} import probe\nprobe('wheel_pth')\n".encode(),
            FILE_MODE,
        ),
        f"{distribution}.pth": (f"import {pth_module}\n".encode(), FILE_MODE),
        f"{module}/__init__.py": (
            f"from {helper} import probe\nprobe('wheel_import')\nVALUE = 'inert'\n".encode(),
            FILE_MODE,
        ),
        f"{cli_module}.py": (
            (
                f"from {helper} import probe\n\n"
                "def main():\n"
                "    probe('wheel_entry_point')\n"
                "    return 0\n"
            ).encode(),
            FILE_MODE,
        ),
    }
    entry_point = f"[console_scripts]\n{distribution.replace('_', '-')} = {cli_module}:main\n"
    return files, entry_point


def wheel_artifact(active: bool) -> tuple[str, bytes]:
    suffix = "canary" if active else "neighbor"
    distribution = f"whoathere_fixture_wheel_{suffix}"
    files, entry_point = wheel_payload(distribution, active)
    filename = f"{distribution}-{VERSION}-py3-none-any.whl"
    return filename, deterministic_wheel(distribution, VERSION, files, entry_point)


def sdist_backend_source(distribution: str, active: bool) -> bytes:
    payload_files, entry_point = wheel_payload(distribution, active)
    encoded_payload = {
        name: {"data": base64.b64encode(data).decode("ascii"), "mode": mode}
        for name, (data, mode) in sorted(payload_files.items())
    }
    embedded = json.dumps(encoded_payload, sort_keys=True, separators=(",", ":"))
    return f'''"""Minimal deterministic PEP 517 backend for an inert WhoaThere fixture."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import zipfile
from pathlib import Path

from fixture_build_probe import probe

VERSION = "{VERSION}"
DIST = "{distribution}"
PAYLOAD = json.loads({embedded!r})
ENTRY_POINT = {entry_point!r}
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)


def _record_hash(data):
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    del config_settings, metadata_directory
    probe("sdist_build_backend")
    dist_info = f"{{DIST}}-{{VERSION}}.dist-info"
    members = {{name: (base64.b64decode(item["data"]), item["mode"]) for name, item in PAYLOAD.items()}}
    members[f"{{dist_info}}/METADATA"] = (
        f"Metadata-Version: 2.3\\nName: {{DIST.replace('_', '-')}}\\nVersion: {{VERSION}}\\n"
        "Summary: Inert WhoaThere canonical sdist fixture\\nRequires-Python: >=3.9\\n".encode(),
        0o644,
    )
    members[f"{{dist_info}}/WHEEL"] = (
        b"Wheel-Version: 1.0\\nGenerator: whoathere-inert-pep517-backend-v1\\n"
        b"Root-Is-Purelib: true\\nTag: py3-none-any\\n",
        0o644,
    )
    members[f"{{dist_info}}/entry_points.txt"] = (ENTRY_POINT.encode(), 0o644)
    record_path = f"{{dist_info}}/RECORD"
    record = [f"{{name}},{{_record_hash(data)}},{{len(data)}}" for name, (data, _mode) in sorted(members.items())]
    record.append(f"{{record_path}},,")
    members[record_path] = (("\\n".join(record) + "\\n").encode(), 0o644)
    filename = f"{{DIST}}-{{VERSION}}-py3-none-any.whl"
    destination = Path(wheel_directory) / filename
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(destination, "w") as archive:
        for name in sorted(members):
            data, mode = members[name]
            info = zipfile.ZipInfo(name, ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (mode & 0xFFFF) << 16
            archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return filename


def get_requires_for_build_wheel(config_settings=None):
    del config_settings
    return []
'''.encode()


def sdist_artifact(active: bool) -> tuple[str, bytes]:
    suffix = "canary" if active else "neighbor"
    distribution = f"whoathere_fixture_sdist_{suffix}"
    root = f"{distribution}-{VERSION}"
    build_probe = python_probe_source(active, "fixture-public.txt")
    pyproject = (
        "[build-system]\n"
        "requires = []\n"
        "build-backend = \"fixture_backend\"\n"
        "backend-path = [\"backend\"]\n\n"
        "[project]\n"
        f"name = \"{distribution.replace('_', '-')}\"\n"
        f"version = \"{VERSION}\"\n"
        "description = \"Inert WhoaThere canonical behavior fixture\"\n"
        "requires-python = \">=3.9\"\n"
    ).encode()
    pkg_info = (
        "Metadata-Version: 2.3\n"
        f"Name: {distribution.replace('_', '-')}\n"
        f"Version: {VERSION}\n"
        "Summary: Inert WhoaThere canonical behavior fixture\n"
    ).encode()
    entries = {
        f"{root}/PKG-INFO": (pkg_info, FILE_MODE),
        f"{root}/pyproject.toml": (pyproject, FILE_MODE),
        f"{root}/backend/fixture_backend.py": (sdist_backend_source(distribution, active), FILE_MODE),
        f"{root}/backend/fixture_build_probe.py": (build_probe, FILE_MODE),
        f"{root}/backend/fixture-public.txt": (b"whoathere inert public fixture data\n", FILE_MODE),
        f"{root}/src/{distribution}/__init__.py": (b"VALUE = 'inert source tree'\n", FILE_MODE),
    }
    filename = f"{distribution}-{VERSION}.tar.gz"
    return filename, deterministic_tar_gz(entries)


def fixture_artifacts() -> Iterable[tuple[str, bytes]]:
    for factory in (npm_artifact, wheel_artifact, sdist_artifact):
        yield factory(True)
        yield factory(False)


def build_all(out_dir: Path) -> list[dict[str, object]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    expected_names: set[str] = set()
    results: list[dict[str, object]] = []
    for filename, data in fixture_artifacts():
        expected_names.add(filename)
        destination = out_dir / filename
        destination.write_bytes(data)
        results.append(
            {
                "filename": filename,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        )
    unexpected = sorted(path.name for path in out_dir.iterdir() if path.is_file() and path.name not in expected_names)
    if unexpected:
        raise RuntimeError(f"artifact_output_contains_unexpected_files:{','.join(unexpected)}")
    return sorted(results, key=lambda item: str(item["filename"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    results = build_all(args.out_dir.resolve())
    print(json.dumps({"schema_version": "whoathere.inert_fixture_build.v1", "artifacts": results}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
