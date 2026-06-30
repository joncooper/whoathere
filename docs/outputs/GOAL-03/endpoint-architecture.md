# Endpoint Architecture

## Summary

The endpoint uses transparent PATH shims plus package-manager configuration steering. The shim preserves native command behavior, classifies the command, evaluates policy, configures registry/index routing, and invokes the real package manager inside the selected isolation backend.

## Components

- PATH shims: `npm`, `npx`, `pip`, `pip3`.
- Shell integration: detects protected project context and handles `python -m pip` by routing through `whoathere protect pip --python-module`.
- Local engine: command classifier, local policy evaluator, config steering, audit emitter.
- Sandbox runner: Linux strong isolation and macOS VM-backed beta containment path.
- Local policy cache: signed policy snapshot with expiry.
- Local audit buffer: append-only local events flushed to Vault when available.

## Command Flow

1. Shim records command, argv, cwd, parent process, platform, and correlation ID.
2. Real package-manager binary is resolved outside the shim directory.
3. Local engine classifies workflow and source risk.
4. Local policy decides allow, warn, deny, manual review, quarantine, or break-glass required.
5. Local engine injects npm/pip registry/index config only for the child process.
6. Sandbox runner starts package-manager process with inherited isolation for subprocesses.
7. Local engine preserves stdout, stderr, signal, and exit code.
8. Audit event is written with redacted evidence.

## `python -m pip`

Protected mode must not silently miss `python -m pip`.

- In project directories initialized by `whoathere init`, shell integration aliases `python -m pip`-style workflows through `whoathere protect pip --python-module`.
- CI templates call `whoathere protect pip -- python -m pip ...`.
- If a protected policy requires enforcement and `python -m pip` is detected only by backstop telemetry, the command is treated as a policy violation and subsequent high-risk operations fail closed until remediated.

## Enforcement Boundaries

Registry/index steering is not a security boundary. The enforcement boundary is the sandbox/network layer plus Vault admission. Command-line flags that override npm/pip config are detected and either rewritten only with explicit explanation or denied in protected modes.
