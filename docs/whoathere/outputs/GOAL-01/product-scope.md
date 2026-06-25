# Product Scope

## MVP Thesis

WhoaThere reduces the blast radius of malicious npm and pip packages by controlling dependency acquisition, install/build script execution, and package admission before untrusted artifacts can execute with developer or CI credentials.

The MVP is a Vault-backed local endpoint and CI flow:

- Local engine intercepts supported npm and pip commands on macOS and Linux.
- Local engine routes package resolution and artifact fetches through WhoaThere Vault where configured.
- Linux endpoint provides strong local isolation for install/build execution.
- macOS endpoint provides compatible interception and a VM-backed beta-containment plan; Endpoint Security is telemetry/backstop, not the primary sandbox.
- Vault enforces scan-before-serve package admission and fail-closed CI behavior.

## Personas

- Developer laptop user: wants normal `npm` and `pip` workflows with clear allow/block explanations.
- CI runner operator: wants deterministic fail-closed package installs with cache performance.
- Security admin: defines namespace, registry, script, egress, break-glass, and admission policies.
- Platform engineer: deploys Vault, integrates CI routing, observes health, and handles rollback.

## Protected Workflows

- `npm install`
- `npm ci`
- `npx` and `npm exec`
- `pip install`
- `pip3`
- `python -m pip`

`npm run` and `pip download` are included as policy-relevant adjacent workflows because they can invoke dependency code or acquire artifacts.

## Explicit Non-Goals

- Full runtime application protection after install.
- Windows endpoint implementation in MVP.
- TLS MITM for arbitrary developer traffic.
- Package-manager forks as primary integration.
- `LD_PRELOAD`, `DYLD_*`, or WASM as primary enforcement.
- General vulnerability management outside package admission and install/build risk.

## First Vertical Slice

The first buildable slice is:

1. Rust CLI and PATH shims classify npm/pip commands.
2. Local policy decides allow, warn, deny, quarantine, manual review, or break-glass required.
3. Linux runs supported installs in a constrained sandbox; macOS runs interception plus VM-isolation spike path.
4. Vault serves npm/PyPI-compatible metadata and artifacts only after admission.
5. Audit events link CLI decision, package coordinates, policy version, and evidence references.

## Done Signal

A reviewer can run through the supported commands and determine:

- What is blocked: known malicious behavior, unsupported high-risk source types in CI, public fallback for internal names, unapproved cache misses, scanner/proxy outage in CI.
- What warns: developer-machine compatibility risks explicitly allowed by policy.
- What is recorded: package coordinates, source, digest, decision, policy, redacted evidence, and correlation IDs.
- What is ignored: full runtime behavior after install unless covered by import-time detonation.
- What is deferred: Windows, IDE plugins, dashboard UI, full runtime containment.
