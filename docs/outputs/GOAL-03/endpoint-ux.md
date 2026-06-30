# Endpoint UX

## Commands

- `whoathere shim install`: install shims and verify real binary paths.
- `whoathere doctor`: report platform support, sandbox capability, Vault reachability, policy freshness, and cleanup status.
- `whoathere protect npm -- <args>`: explicit npm protection wrapper.
- `whoathere protect pip -- <args>`: explicit pip protection wrapper.
- `whoathere policy explain <decision-id>`: show policy and evidence explanation.
- `whoathere break-glass request`: request scoped override.

## macOS Mode Labels

- `macOS beta containment`: VM-backed beta path is active for this workflow.
- `macOS telemetry/interception only`: interception and audit are active, but containment is not.
- `macOS containment unavailable`: containment was required but unavailable; high-risk/CI commands fail closed.

## Message Rules

- Preserve npm/pip output by default.
- WhoaThere messages are prefixed and concise.
- Denies include decision ID, matched policy, package/source, and remediation.
- Warnings require policy permission and include risk reason.
- Break-glass messages include scope and expiry.

## Exit Codes

- `0`: package manager succeeded.
- `10`: policy deny.
- `11`: quarantine/manual review.
- `12`: unsupported workflow.
- `20`: sandbox failure.
- `30`: Vault unavailable.
- `31`: scanner/detonator unavailable.
- `40`: break-glass required/expired.
- `70`: internal error.

Package-manager failures preserve package-manager exit codes. WhoaThere-specific exit codes are used only when WhoaThere enforcement, policy, sandbox, Vault, or break-glass state determines the result.
