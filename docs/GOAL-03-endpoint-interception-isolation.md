# GOAL-03: Endpoint Interception And Isolation

## Objective

Design the macOS/Linux local engine that intercepts npm and pip workflows without breaking standard tooling, then isolates or controls untrusted install/build scripts.

## Required Interception Strategy

Use transparent PATH shims as the first interception layer for `npm`, `npx`, `pip`, and `pip3`. Preserve argv, stdin, stdout, stderr, signals, working directory, and exit code. Add explicit handling for `python -m pip` through documented shell integration, local policy checks, and later telemetry backstop.

Use package-manager configuration steering for registry/index routing:

- npm: environment/config steering for registry, scoped registry behavior, lockfile `resolved` host rewriting policy, and lifecycle-script visibility.
- pip: `--index-url`, config, environment variables, `--dry-run --report`, and hash-aware Simple API behavior.

Do not use `LD_PRELOAD`, `DYLD_*`, or package-manager forks as primary enforcement mechanisms.

## Required Isolation Tracks

### Linux Track

Evaluate and plan:

- User, mount, PID, IPC, UTS, cgroup, and network namespaces.
- Seccomp filters for syscall reduction.
- Cgroups for CPU, memory, process, and I/O limits.
- Landlock where available for unprivileged filesystem and network restrictions.
- Bubblewrap/runc/rootless-container style runners.
- Docker/container mode for CI and local Linux containers.
- Read-only host binds with writable project/cache/tmp areas.
- Network-deny and network-recording modes.

### macOS Track

Evaluate and plan:

- Lightweight VM isolation as the default strong-control candidate, with Phase 1 labeled beta containment until Phase 2 validation proves GA readiness.
- Endpoint Security for process/file telemetry and partial control.
- Network Extension or pf-based options only if they can be justified operationally.
- Seatbelt/sandbox profile research as a spike, not a dependable product foundation.
- Apple Silicon constraints, filesystem sharing, code signing, notarization, and developer-tool compatibility.

## Required Workflow Plans

- `npm install` and `npm ci`: whole-install sandbox first, later per-package script replay if feasible.
- `npm run`: lifecycle and user-script behavior when the command can invoke dependency code or package-manager subprocesses.
- `npx` and `npm exec`: command intent classification, package fetch routing, execution policy, and break-glass behavior.
- `pip install`: resolver/report step, artifact fetch, wheel preference, sdist build sandbox, install into target environment.
- `pip download`: artifact acquisition policy when packages are fetched but not installed.
- `python -m pip`: detection and steering strategy.
- Private registries, lockfiles, editable installs, git/tarball/direct URL dependencies, workspaces, and global installs.

## Required Endpoint Contracts

The goal output must define:

- Interceptor request shape: observed command, argv, environment redaction, working directory, resolved real binary, parent process, package context when known, and correlation ID.
- Isolation contract: environment variables, DNS behavior, proxy/firewall behavior, subprocess inheritance, mount/filesystem rules, cleanup guarantees, and failure modes.
- Network decision table: DNS versus direct IP, HTTPS CONNECT, localhost, private RFC1918 ranges, Git SSH, Git HTTPS, package registries, telemetry endpoints, and native build tools invoking network calls.
- Event/log schema: timestamp, platform, process tree, command, package name/version when known, endpoint, matched rule, action, and redaction status.
- Report contract: human-readable explanation and machine-readable JSON for CI.

## Operational Requirements

The goal output must state:

- Minimum supported macOS and Linux versions.
- Required privileges, entitlements, helper tools, and installation steps.
- Known unsupported cases and their fail-closed, beta, observe, or approved-warning behavior.
- Cleanup tests proving no lingering VM, network namespace, firewall, proxy, mount, or temporary credential state.
- User-facing remediation for policy denial, sandbox failure, missing privileges, and unavailable Vault.

## Required Deliverables

- `endpoint-architecture.md`: local engine, shim, sandbox, config, and telemetry design.
- `ADR-002-interception-strategy.md`: PATH shims plus config steering decision.
- `ADR-003-linux-isolation.md`: Linux sandbox backend decision.
- `ADR-004-macos-isolation.md`: macOS VM versus Endpoint Security versus sandbox-profile decision.
- `package-manager-compatibility-matrix.md`: npm/pip workflow coverage and known breakage risks.
- `endpoint-contracts.md`: interceptor, isolation, network decision, event, and report schemas.
- `endpoint-operational-plan.md`: OS versions, privileges, cleanup, helper lifecycle, and unsupported cases.
- `endpoint-ux.md`: install, status, diagnostics, prompts, break-glass, and failure messages.

## Acceptance Criteria

- Standard commands still look and feel like native npm and pip commands.
- The plan accounts for command-line flags overriding config steering.
- Linux has a credible strong-isolation path using kernel primitives.
- macOS does not overclaim native sandbox strength; Phase 1 is beta containment, and GA strong isolation is VM-based unless evidence proves another option.
- Unsupported dependency source types fail closed in CI and high-risk contexts.
- Subprocesses inherit the intended isolation boundary on both macOS and Linux.
- DNS, direct IP, private network, localhost, Git SSH/HTTPS, and cached/offline cases are covered by explicit decision tables.
- Cleanup behavior is testable and leaves no persistent enforcement state behind after normal or failed runs.
- Every adversarial endpoint scenario in the acceptance matrix has a planned fixture.

## Exit Gate

Do not start CLI implementation planning until both ADR-003 and ADR-004 define enforceable containment guarantees, known gaps, compatibility test fixtures, subprocess inheritance, and cleanup behavior.

## Suggested Subagents

- Linux sandbox specialist.
- macOS security specialist.
- npm compatibility reviewer.
- Python packaging compatibility reviewer.
