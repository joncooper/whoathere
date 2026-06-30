# Phase 2 Advanced Isolation Build Plan

## Objective

Harden endpoint containment for supported Linux and macOS workflows, including process-tree inheritance, egress control, cleanup leases, and compatibility with real npm/PyPI packages.

## Non-Goals

- Production Vault.
- Windows endpoint.
- Full runtime EDR.
- Cloud detonation automation.

## Required Source Artifacts

- `outputs/GOAL-07/phase-2-advanced-isolation-goal.md`
- `outputs/GOAL-09/endpoint-egress-decision-table.md`
- `outputs/GOAL-09/macos-beta-containment-positioning.md`
- `outputs/GOAL-09/phase-gate-scorecard.md`

## Milestones

| Milestone | Work | Exit evidence |
| --- | --- | --- |
| P2-M1 Linux runner design | User/mount/PID/network namespaces, seccomp profile, cgroup limits, Landlock probe. | Design and kernel capability matrix. |
| P2-M2 Cleanup lease model | Per-run lease IDs, tagged temp dirs, janitor, idempotent rollback. | Crash/signal cleanup tests. |
| P2-M3 Endpoint egress enforcement | Direct public registry/index block before execution in CI/high-risk mode. | CT-010 harness. |
| P2-M4 Subprocess inheritance | Correlation ID and policy propagation to child package-manager invocations. | CT-004 tests. |
| P2-M5 macOS GA decision | VM compatibility/perf validation or explicit beta continuation. | macOS report approved by product/security. |
| P2-M6 Real package matrix | Native npm modules, Python sdists/wheels, workspaces, virtualenvs. | Compatibility report. |

## Repo/File Plan

- `whoathere/crates/whoathere-sandbox/src/linux.rs`
- `whoathere/crates/whoathere-sandbox/src/macos.rs`
- `whoathere/crates/whoathere-sandbox/src/cleanup.rs`
- `whoathere/crates/whoathere-sandbox/src/egress.rs`
- `whoathere/tests/compat/`

## Verification Commands

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-sandbox
whoathere doctor --json
whoathere protect npm --dry-run -- ci
whoathere protect pip --dry-run -- install -r requirements.txt
```

## Release Gate Evidence

- CT-004, CT-010, CT-011 pass.
- macOS remains beta unless GA criteria pass.
- Cleanup leaves no VM, namespace, mount, socket, firewall/proxy, credential, or temp state.

## Research Required

- Supported macOS VM file-sharing mechanics for project installs.

## Validation Pending

- Kernel coverage across supported Linux distributions.
- Apple Silicon and Intel VM performance.

## First Implementation Tasks

1. Add backend capability probing.
2. Add cleanup lease model.
3. Add egress decision evaluator.
4. Add compatibility test harness.

