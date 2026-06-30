# ADR-002: Endpoint Interception Strategy

- Status: accepted
- Date: 2026-06-25

## Context

WhoaThere must protect common npm and pip workflows without requiring developers to fork package managers or learn new install commands.

## Decision

Use PATH shims for `npm`, `npx`, `pip`, and `pip3`, plus package-manager configuration steering and explicit `python -m pip` handling.

Reject `LD_PRELOAD`, `DYLD_*`, TLS MITM, WASM, and package-manager forks as primary enforcement.

## Alternatives Considered

| Alternative | Rejection rationale |
| --- | --- |
| Package-manager fork | High maintenance and ecosystem drift. |
| Shell aliases only | Easy to bypass and shell-specific. |
| `LD_PRELOAD`/`DYLD_*` | Brittle, SIP-sensitive on macOS, bypassable. |
| TLS MITM | Breaks credentials/private registries and expands trust burden. |
| WASM | Cannot run arbitrary native npm/pip install workflows. |

## Security Impact

Shims provide intent capture; sandbox and Vault provide enforcement. Absolute-path package-manager invocation remains a known gap until telemetry backstop is implemented.

## Operational Impact

Shims are reversible with `whoathere shim uninstall`. Real binary discovery is recorded by `whoathere doctor`.

## Compatibility Impact

Native argv, cwd, stdin/stdout/stderr, signal, and exit behavior are preserved. Command-line options that override secure routing are denied in protected modes.

## Cost/Performance Impact

Shim overhead target is under 50 ms before package-manager startup, excluding policy fetch.

## Revisit Trigger

Revisit only if compatibility tests show PATH shims cannot preserve npm/pip semantics for core workflows.

