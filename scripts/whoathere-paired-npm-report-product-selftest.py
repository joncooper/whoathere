#!/usr/bin/env python3
"""Exercise the real P05 paired npm report and fail-closed mutation controls."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def json_bytes(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("utf-8")


def run(
    cli: Path,
    report: Path,
    report_sha256: str,
    reconciliation: Path,
    reconciliation_sha256: str,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(cli),
            "report",
            "render",
            str(report),
            "--report-sha256",
            report_sha256,
            "--reconciliation",
            str(reconciliation),
            "--reconciliation-sha256",
            reconciliation_sha256,
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def mutate_citation(value: dict[str, Any]) -> None:
    finding = value["profiles"][0]["codex"]["findings"][0]
    finding["evidence"][0]["event_sha256"] = digest(b"forged-event")
    identity = [finding["kind"], finding["evidence"]]
    finding["finding_sha256"] = digest(
        json.dumps(identity, separators=(",", ":")).encode("utf-8")
    )


def promote_network_finding(value: dict[str, Any]) -> None:
    finding = value["profiles"][0]["codex"]["findings"][2]
    finding["kind"] = "exfiltration"
    finding["threat_class"] = "network_and_exfiltration"
    identity = [finding["kind"], finding["evidence"]]
    finding["finding_sha256"] = digest(
        json.dumps(identity, separators=(",", ":")).encode("utf-8")
    )


def omit_credential_citation(value: dict[str, Any]) -> None:
    finding = value["profiles"][0]["codex"]["findings"][0]
    finding["evidence"].pop()
    identity = [finding["kind"], finding["evidence"]]
    finding["finding_sha256"] = digest(
        json.dumps(identity, separators=(",", ":")).encode("utf-8")
    )


def rebind_observer_identity(value: dict[str, Any]) -> None:
    value["profiles"][0]["observer_result_sha256"] = digest(b"other-observer")
    binding = {
        "artifact_sha256": value["artifact_sha256"],
        "bundles": [
            [profile["bundle_sha256"], profile["observer_result_sha256"]]
            for profile in value["profiles"]
        ],
        "remote_report_sha256": value["report_sha256"],
        "scenario_plan_sha256": value["scenario_plan_sha256"],
    }
    value["source_reconciliation_input_binding_sha256"] = digest(
        json.dumps(binding, separators=(",", ":")).encode("utf-8")
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--report-sha256", required=True)
    parser.add_argument("--reconciliation", required=True, type=Path)
    parser.add_argument("--reconciliation-sha256", required=True)
    args = parser.parse_args()

    baseline = run(
        args.cli,
        args.report,
        args.report_sha256,
        args.reconciliation,
        args.reconciliation_sha256,
    )
    assert baseline.returncode == 20, baseline.stdout
    assert not baseline.stderr, baseline.stderr
    required = [
        "BLOCK - malicious capability found in package",
        "CI=false diagnostic VM/Codex evidence",
        "CI=true diagnostic VM/Codex evidence",
        "73 typed events",
        "2 npm lifecycle executions; 6 credential-file reads",
        "10 local-sinkhole connects; 10 local-sinkhole sends",
        "connect/send intent does not establish payload or credential exfiltration",
        "all citations resolved",
        "Coverage: incomplete",
        "sanitized diagnostic, unauthenticated",
        "did not create, erase, or downgrade the static result",
    ]
    assert all(fragment in baseline.stdout for fragment in required), baseline.stdout

    source = json.loads(args.reconciliation.read_text(encoding="utf-8"))
    mutations: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
        ("unknown-field", lambda value: value.__setitem__("unexpected", True)),
        ("unsupported-version", lambda value: value.__setitem__("schema_version", "v2")),
        ("artifact-mismatch", lambda value: value.__setitem__("artifact_sha256", digest(b"other"))),
        ("missing-profile", lambda value: value["profiles"].pop()),
        ("duplicate-profile", lambda value: value["profiles"].append(copy.deepcopy(value["profiles"][0]))),
        ("swapped-profile", lambda value: value["profiles"].reverse()),
        ("authority", lambda value: value.__setitem__("admission_authority", True)),
        ("observed-clean", lambda value: value.__setitem__("observed_clean", True)),
        ("claim-bearing", lambda value: value.__setitem__("claim_bearing", True)),
        ("input-binding", lambda value: value.__setitem__("source_reconciliation_input_binding_sha256", digest(b"other"))),
        ("source-reconciliation-identity", lambda value: value.__setitem__("source_reconciliation_sha256", digest(b"other"))),
        ("observer-identity-rebinding", rebind_observer_identity),
        ("citation-forgery", mutate_citation),
        ("citation-omission", omit_credential_citation),
        ("exfiltration-promotion", promote_network_finding),
        (
            "untrusted-detail",
            lambda value: value["profiles"][0]["behavior_bundle"]["events"][0].__setitem__(
                "untrusted_detail", "not allowed"
            ),
        ),
        (
            "coverage-upgrade",
            lambda value: value["profiles"][0]["behavior_bundle"]["coverage"][0].update(
                {"state": "complete", "limitation_codes": []}
            ),
        ),
    ]

    with tempfile.TemporaryDirectory(prefix="whoathere-p05-product-") as temporary:
        root = Path(temporary)
        for name, mutation in mutations:
            value = copy.deepcopy(source)
            mutation(value)
            content = json_bytes(value)
            path = root / f"{name}.json"
            path.write_bytes(content)
            completed = run(
                args.cli,
                args.report,
                args.report_sha256,
                path,
                digest(content),
            )
            assert completed.returncode == 64, (name, completed.stdout)
            assert not completed.stderr, (name, completed.stderr)
            assert "BLOCK" not in completed.stdout, (name, completed.stdout)
            assert "ALLOW" not in completed.stdout, (name, completed.stdout)
            assert str(path) not in completed.stdout, (name, completed.stdout)

        mismatch = run(
            args.cli,
            args.report,
            args.report_sha256,
            args.reconciliation,
            digest(b"wrong-envelope"),
        )
        assert mismatch.returncode == 64, mismatch.stdout
        assert "BLOCK" not in mismatch.stdout and "ALLOW" not in mismatch.stdout

    print(
        f"paired npm product selftest: ok (baseline + {len(mutations) + 1} fail-closed controls)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
