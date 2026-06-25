# Product Build Run Pass 2: Security Invariants

## Scope

Reviewed implementation slices against global safety gates:

- No public fallback.
- No unapproved artifact serving.
- No actual malware execution.
- No raw secret persistence.
- CI/high-risk fail-closed behavior.
- macOS beta containment label integrity.

## Findings

| Slice | Finding | Risk |
| --- | --- | --- |
| CLI scan command | Unsupported manifest kind was checked after attempting file read. | Invalid commands could be used as path probes. |
| Audit | Audit record shape existed but did not persist JSONL or prove redaction at write boundary. | Evidence trail could leak secrets or be absent. |
| Vault admission | Promotion needed tests proving incomplete evidence does not create a servable generation. | Cold-miss or scanner outage might later fail open. |
| Fixtures | Fixture files needed compile-time scan coverage without execution. | Tests could accidentally evolve into package execution. |

## Improvements Made

- Moved unsupported manifest-kind rejection before filesystem reads.
- Added redacted JSONL audit writer and tests.
- Added incomplete-evidence fail-closed admission test.
- Added fixture-backed static scanner tests using `include_str!`; no package manager or interpreter is invoked.

## Validation

- `cargo test --manifest-path whoathere/Cargo.toml` passed with 36 tests.
- CLI scan command has a unit test for unsupported kind fail-closed behavior.
- Detector fixture tests use inert local metadata only.
