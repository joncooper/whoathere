#!/usr/bin/env python3
"""Focused production-path checks for the P06 cloud-lab preflight."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable


SCRIPT = Path(__file__).with_name("whoathere-cloud-lab-preflight.py")
SPEC = importlib.util.spec_from_file_location("whoathere_cloud_lab_preflight", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load preflight module")
PREFLIGHT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PREFLIGHT
SPEC.loader.exec_module(PREFLIGHT)


SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
GIT_COMMIT = "d" * 40


def base_plan() -> dict[str, Any]:
    files = []
    for index, label in enumerate(PREFLIGHT.FILE_LABELS):
        files.append(
            {
                "label": label,
                "path": f"/opt/whoathere/p06/{label}",
                "sha256": "sha256:" + f"{index + 1:x}" * 64,
            }
        )
    return {
        "schema_version": PREFLIGHT.INPUT_SCHEMA,
        "attempt": 0,
        "ssh": {
            "host_alias": "whoathere-cloud-mac",
            "expected_hostname": "cloud-mac",
            "expected_user": "m1",
            "source_route_reference": "route-approved-20260718",
        },
        "authorization": {
            "provider_approval_reference": "provider-approved-20260718",
            "legal_approval_reference": "legal-approved-20260718",
            "operator_authorization_reference": "operator-approved-20260718",
            "planned_material": "inert_only",
        },
        "provider": {
            "name": "scaleway",
            "firewall_posture": "provider_unavailable_host_pf",
            "firewall_reference": "provider-posture-20260718",
        },
        "run_binding": {
            "checkout_path": "/opt/whoathere/checkout",
            "git_commit": GIT_COMMIT,
            "campaign_id": "p07-inert-demo",
            "profile_id": "npm-ci-paired",
            "files": files,
        },
        "host_controls": {
            "pf_info": {"path": "/opt/whoathere/control/pf-info", "sha256": SHA_A},
            "pf_rules": {"path": "/opt/whoathere/control/pf-rules", "sha256": SHA_B},
            "lulu_evidence": {"path": "/opt/whoathere/control/lulu.json", "sha256": SHA_C},
            "max_age_seconds": 3600,
            "sinkhole": {
                "host": "127.0.0.1",
                "port": 48739,
                "reference": "sinkhole-approved-20260718",
            },
        },
        "storage": {
            "custody_root": "/opt/whoathere/custody",
            "evidence_root": "/opt/whoathere/evidence",
            "sanitized_root": "/opt/whoathere/sanitized",
            "clone_root": "/opt/whoathere/clones",
        },
        "clearance": {
            "mode": "not_required_inert",
            "path": None,
            "sha256": None,
            "latest_contamination_at_utc": None,
        },
    }


def base_probe(plan: dict[str, Any]) -> dict[str, Any]:
    host_id = "sha256:" + hashlib.sha256(
        (
            plan["ssh"]["expected_hostname"]
            + "\x00"
            + plan["ssh"]["expected_user"]
        ).encode()
    ).hexdigest()
    return {
        "schema_version": PREFLIGHT.PROBE_SCHEMA,
        "host": {
            "hostname": plan["ssh"]["expected_hostname"],
            "user": plan["ssh"]["expected_user"],
            "ssh_session": True,
            "host_id_sha256": host_id,
        },
        "platform": {
            "vz_framework": True,
            "hypervisor_supported": True,
            "gui_session_present": True,
        },
        "identities": {
            "git_commit": plan["run_binding"]["git_commit"],
            "files": {
                item["label"]: {"regular": True, "sha256": item["sha256"]}
                for item in plan["run_binding"]["files"]
            },
        },
        "controls": {
            "pf_info_sha256": plan["host_controls"]["pf_info"]["sha256"],
            "pf_rules_sha256": plan["host_controls"]["pf_rules"]["sha256"],
            "pf_fresh": True,
            "pf_enabled": True,
            "pf_default_deny": True,
            "lulu_sha256": plan["host_controls"]["lulu_evidence"]["sha256"],
            "lulu_fresh": True,
            "lulu_enabled": True,
            "lulu_filtering": True,
            "sinkhole_listening": True,
        },
        "storage": {
            label: {"directory": True, "private": True, "writable": True}
            for label in PREFLIGHT.STORAGE_LABELS
        },
        "stale_state": {"process_count": 0, "clone_count": 0},
        "clearance": {
            "required": False,
            "valid": True,
            "fresh": True,
            "consumed": False,
            "sha256": None,
        },
        "safety": {
            "artifact_opened": False,
            "package_executed": False,
            "vm_started": False,
            "remote_state_mutated": False,
            "clearance_consumed": False,
        },
    }


class FakeRunner:
    def __init__(self, probe: dict[str, Any], *, route_ok: bool = True) -> None:
        self.probe = probe
        self.route_ok = route_ok
        self.calls: list[tuple[list[str], bytes | None, int]] = []

    def __call__(
        self, argv: list[str], input_bytes: bytes | None, timeout: int
    ) -> Any:
        self.calls.append((list(argv), input_bytes, timeout))
        if "-G" in argv:
            if not self.route_ok:
                return PREFLIGHT.CommandResult(255, b"", b"route failed")
            return PREFLIGHT.CommandResult(
                0,
                b"hostname 203.0.113.10\nuser m1\n",
                b"",
            )
        return PREFLIGHT.CommandResult(
            0,
            json.dumps(self.probe, sort_keys=True, separators=(",", ":")).encode(),
            b"",
        )


def encoded(plan: dict[str, Any]) -> bytes:
    return json.dumps(plan, sort_keys=True, separators=(",", ":")).encode()


def digest(content: bytes) -> str:
    return "sha256:" + hashlib.sha256(content).hexdigest()


def invoke(
    root: Path,
    plan: dict[str, Any],
    probe: dict[str, Any] | None = None,
    *,
    runner: FakeRunner | None = None,
    name: str = "plan.json",
) -> tuple[Any, FakeRunner]:
    content = encoded(plan)
    path = root / name
    path.write_bytes(content)
    path.chmod(0o600)
    selected = runner or FakeRunner(probe or base_probe(plan))
    result = PREFLIGHT.run_preflight(
        path,
        digest(content),
        None,
        runner=selected,
        ssh_binary="/usr/bin/ssh",
    )
    return result, selected


def assert_block(
    root: Path,
    expected: str,
    mutate: Callable[[dict[str, Any], dict[str, Any]], None],
    *,
    name: str,
) -> None:
    plan = base_plan()
    probe = base_probe(plan)
    mutate(plan, probe)
    result, _ = invoke(root, plan, probe, name=name)
    assert result.status == "blocked", (expected, result)
    assert result.exit_code == 20
    assert result.blocker_code == expected, (expected, result.blocker_code)
    rendered = PREFLIGHT.render_human(result)
    assert rendered.count("ACTION:") == 1
    assert "ALLOW" not in rendered


def expect_input_error(action: Callable[[], Any], expected: str) -> None:
    try:
        action()
    except PREFLIGHT.InputError as exc:
        assert str(exc) == expected, (expected, str(exc))
    else:
        raise AssertionError(f"expected InputError: {expected}")


def snapshot(root: Path) -> dict[str, tuple[int, str]]:
    result: dict[str, tuple[int, str]] = {}
    for path in sorted(root.iterdir()):
        if path.is_file() and not path.is_symlink():
            result[path.name] = (
                stat.S_IMODE(path.stat().st_mode),
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )
    return result


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="whoathere-p06-selftest-") as value:
        root = Path(value)

        # The exact production path reaches READY without mutating its local input.
        plan = base_plan()
        probe = base_probe(plan)
        content = encoded(plan)
        ready_path = root / "ready.json"
        ready_path.write_bytes(content)
        ready_path.chmod(0o600)
        before = snapshot(root)
        runner = FakeRunner(probe)
        ready = PREFLIGHT.run_preflight(
            ready_path,
            digest(content),
            None,
            runner=runner,
            ssh_binary="/usr/bin/ssh",
        )
        assert ready.status == "ready" and ready.exit_code == 0
        assert snapshot(root) == before
        assert len(runner.calls) == 2
        assert "-G" in runner.calls[0][0] and runner.calls[0][1] is None
        assert runner.calls[1][0][-2:] == ["/usr/bin/python3", "-"]
        assert runner.calls[1][1] is not None
        command_text = " ".join(" ".join(call[0]) for call in runner.calls)
        for forbidden in ("scp", "sudo", "mkdir", "artifact", "scanner", "vm start"):
            assert forbidden not in command_text.lower(), forbidden
        ready_json = ready.as_json()
        for flag in (
            "artifact_opened",
            "package_executed",
            "vm_started",
            "remote_state_mutated",
            "clearance_consumed",
        ):
            assert ready_json[flag] is False
        assert PREFLIGHT.render_human(ready).count("ACTION:") == 0

        # Pre-SSH gates do not invoke the route or probe.
        missing_auth = base_plan()
        missing_auth["authorization"]["operator_authorization_reference"] = ""
        auth_runner = FakeRunner(base_probe(missing_auth))
        auth_result, _ = invoke(
            root, missing_auth, runner=auth_runner, name="missing-auth.json"
        )
        assert auth_result.blocker_code == "AUTHORIZATION_INVALID"
        assert not auth_runner.calls

        missing_provider = base_plan()
        missing_provider["provider"]["firewall_reference"] = ""
        provider_runner = FakeRunner(base_probe(missing_provider))
        provider_result, _ = invoke(
            root,
            missing_provider,
            runner=provider_runner,
            name="missing-provider.json",
        )
        assert provider_result.blocker_code == "PROVIDER_FIREWALL_INVALID"
        assert not provider_runner.calls

        route_plan = base_plan()
        route_runner = FakeRunner(base_probe(route_plan), route_ok=False)
        route_result, _ = invoke(
            root, route_plan, runner=route_runner, name="bad-route.json"
        )
        assert route_result.blocker_code == "SSH_ROUTE_INVALID"
        assert len(route_runner.calls) == 1

        # Each remote readiness family yields one stable blocker.
        assert_block(
            root,
            "HOST_IDENTITY_INVALID",
            lambda _p, q: q["host"].__setitem__("hostname", "replacement-mac"),
            name="host.json",
        )
        assert_block(
            root,
            "HOST_IDENTITY_INVALID",
            lambda _p, q: q["host"].__setitem__(
                "host_id_sha256", "sha256:" + "0" * 64
            ),
            name="host-id.json",
        )
        assert_block(
            root,
            "IDENTITY_MISMATCH",
            lambda _p, q: q["identities"].__setitem__("git_commit", "f" * 40),
            name="identity.json",
        )
        assert_block(
            root,
            "PF_INVALID",
            lambda _p, q: q["controls"].__setitem__("pf_default_deny", False),
            name="pf.json",
        )
        assert_block(
            root,
            "LULU_INVALID",
            lambda _p, q: q["controls"].__setitem__("lulu_filtering", False),
            name="lulu.json",
        )
        assert_block(
            root,
            "SINKHOLE_INVALID",
            lambda _p, q: q["controls"].__setitem__("sinkhole_listening", False),
            name="sinkhole.json",
        )
        assert_block(
            root,
            "VZ_INVALID",
            lambda _p, q: q["platform"].__setitem__("hypervisor_supported", False),
            name="vz.json",
        )
        assert_block(
            root,
            "STORAGE_INVALID",
            lambda _p, q: q["storage"]["clone_root"].__setitem__("writable", False),
            name="storage.json",
        )
        assert_block(
            root,
            "STALE_STATE",
            lambda _p, q: q["stale_state"].__setitem__("clone_count", 1),
            name="stale.json",
        )

        restricted = base_plan()
        restricted["authorization"]["planned_material"] = "restricted_malware"
        restricted["clearance"] = {
            "mode": "required_restricted",
            "path": "/opt/whoathere/clearance.json",
            "sha256": SHA_A,
            "latest_contamination_at_utc": "2026-07-18T12:00:00Z",
        }
        restricted_probe = base_probe(restricted)
        restricted_probe["clearance"] = {
            "required": True,
            "valid": True,
            "fresh": True,
            "consumed": True,
            "sha256": SHA_A,
        }
        restricted_result, _ = invoke(
            root, restricted, restricted_probe, name="clearance.json"
        )
        assert restricted_result.blocker_code == "CLEARANCE_INVALID"

        restricted_ready_probe = base_probe(restricted)
        restricted_ready_probe["clearance"] = {
            "required": True,
            "valid": True,
            "fresh": True,
            "consumed": False,
            "sha256": SHA_A,
        }
        restricted_ready, _ = invoke(
            root,
            restricted,
            restricted_ready_probe,
            name="clearance-ready.json",
        )
        assert restricted_ready.status == "ready"
        assert "clearance-consumption" in PREFLIGHT.REMOTE_PROBE_SOURCE
        assert "marker_path.lstat()" in PREFLIGHT.REMOTE_PROBE_SOURCE
        assert "except FileNotFoundError" in PREFLIGHT.REMOTE_PROBE_SOURCE

        omitted_clearance_probe = base_probe(restricted)
        omitted_clearance_result, _ = invoke(
            root,
            restricted,
            omitted_clearance_probe,
            name="clearance-applicability.json",
        )
        assert omitted_clearance_result.blocker_code == "CLEARANCE_INVALID"

        inert_clearance = base_plan()
        inert_clearance_probe = base_probe(inert_clearance)
        inert_clearance_probe["clearance"]["valid"] = False
        inert_clearance_result, _ = invoke(
            root,
            inert_clearance,
            inert_clearance_probe,
            name="inert-clearance-contradiction.json",
        )
        assert inert_clearance_result.blocker_code == "CLEARANCE_INVALID"

        # Precedence is independent of how many later facts also fail.
        combined = base_plan()
        combined_probe = base_probe(combined)
        combined_probe["host"]["user"] = "wrong-user"
        combined_probe["identities"]["git_commit"] = "f" * 40
        combined_probe["controls"]["pf_enabled"] = False
        combined_result, _ = invoke(
            root, combined, combined_probe, name="combined.json"
        )
        assert combined_result.blocker_code == "HOST_IDENTITY_INVALID"

        # A second failed attempt parks instead of inviting another repair loop.
        parked = base_plan()
        parked["attempt"] = 1
        parked_probe = base_probe(parked)
        parked_probe["controls"]["lulu_enabled"] = False
        parked_result, _ = invoke(root, parked, parked_probe, name="parked.json")
        assert parked_result.blocker_code == "LULU_INVALID"
        assert parked_result.action == "PARK P06; record this blocker and do not start P07."

        # Closed/digest-bound/private input failures occur before remote execution.
        unknown = base_plan()
        unknown["unexpected"] = True
        unknown_content = encoded(unknown)
        unknown_path = root / "unknown.json"
        unknown_path.write_bytes(unknown_content)
        unknown_path.chmod(0o600)
        no_calls = FakeRunner(base_probe(base_plan()))
        expect_input_error(
            lambda: PREFLIGHT.run_preflight(
                unknown_path,
                digest(unknown_content),
                None,
                runner=no_calls,
            ),
            "input_shape_invalid",
        )
        assert not no_calls.calls

        expect_input_error(
            lambda: PREFLIGHT.run_preflight(
                ready_path, "sha256:" + "0" * 64, None, runner=no_calls
            ),
            "input_sha256_mismatch",
        )
        assert not no_calls.calls

        aliased = base_plan()
        first_file = aliased["run_binding"]["files"][0]
        for item in aliased["run_binding"]["files"][1:]:
            item["path"] = first_file["path"]
            item["sha256"] = first_file["sha256"]
        aliased_content = encoded(aliased)
        aliased_path = root / "aliased-identities.json"
        aliased_path.write_bytes(aliased_content)
        aliased_path.chmod(0o600)
        expect_input_error(
            lambda: PREFLIGHT.run_preflight(
                aliased_path,
                digest(aliased_content),
                None,
                runner=no_calls,
            ),
            "run_binding_file_paths_not_distinct",
        )
        assert not no_calls.calls

        boolean_attempt = base_plan()
        boolean_attempt["attempt"] = True
        boolean_attempt_content = encoded(boolean_attempt)
        boolean_attempt_path = root / "boolean-attempt.json"
        boolean_attempt_path.write_bytes(boolean_attempt_content)
        boolean_attempt_path.chmod(0o600)
        expect_input_error(
            lambda: PREFLIGHT.run_preflight(
                boolean_attempt_path,
                digest(boolean_attempt_content),
                None,
                runner=no_calls,
            ),
            "input_version_or_attempt_invalid",
        )
        assert not no_calls.calls

        public_path = root / "public.json"
        public_path.write_bytes(encoded(base_plan()))
        public_path.chmod(0o644)
        expect_input_error(
            lambda: PREFLIGHT.run_preflight(
                public_path, digest(public_path.read_bytes()), None, runner=no_calls
            ),
            "input_permissions_not_private",
        )

        symlink_path = root / "symlink.json"
        symlink_path.symlink_to(ready_path)
        expect_input_error(
            lambda: PREFLIGHT.run_preflight(
                symlink_path, digest(content), None, runner=no_calls
            ),
            "input_unreadable",
        )

        unsafe_probe = base_probe(base_plan())
        unsafe_probe["safety"]["vm_started"] = True
        expect_input_error(
            lambda: PREFLIGHT.parse_probe(encoded(unsafe_probe)),
            "probe_safety_posture_invalid",
        )

        falsey_safety_probe = base_probe(base_plan())
        falsey_safety_probe["safety"]["vm_started"] = 0
        expect_input_error(
            lambda: PREFLIGHT.parse_probe(encoded(falsey_safety_probe)),
            "probe_safety_posture_invalid",
        )

        falsey_stale_probe = base_probe(base_plan())
        falsey_stale_probe["stale_state"]["process_count"] = False
        expect_input_error(
            lambda: PREFLIGHT.parse_probe(encoded(falsey_stale_probe)),
            "probe_stale_state_value_invalid",
        )

        missing_path = root / "does-not-exist.json"
        cli = [
            sys.executable,
            "-B",
            str(SCRIPT),
            "--input",
            str(missing_path),
            "--input-sha256",
            "sha256:" + "0" * 64,
        ]
        human_error = subprocess.run(cli, capture_output=True, text=True, check=False)
        assert human_error.returncode == 64
        assert human_error.stdout.startswith("ERROR INPUT_INVALID:")
        assert human_error.stdout.count("ACTION:") == 1
        json_error = subprocess.run(
            cli + ["--json"], capture_output=True, text=True, check=False
        )
        assert json_error.returncode == 64
        parsed_error = json.loads(json_error.stdout)
        assert parsed_error["status"] == "error"
        assert parsed_error["exit_code"] == 64
        assert parsed_error["blocker"]["code"] == "INPUT_INVALID"

    print("P06 cloud-lab preflight self-test: ready path and focused fail-closed controls passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
