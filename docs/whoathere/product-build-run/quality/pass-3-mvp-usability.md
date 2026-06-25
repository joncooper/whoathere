# Product Build Run Pass 3: MVP Usability

## Scope

Reviewed whether a developer can exercise the MVP safely from the CLI.

## Findings

| Slice | Finding | Risk |
| --- | --- | --- |
| Evidence profiles | Profiles were library-only after initial implementation. | User could not inspect what the Vault would require. |
| Vault admission | Admission promotion was library-only. | User could not demo fail-closed versus promoted behavior. |
| Shim manifest | Dry-run output lacked concrete shim rows before improvement. | User could not see the interception plan. |

## Improvements Made

- Added `whoathere evidence profiles`.
- Added `whoathere vault simulate` for incomplete-evidence fail-closed behavior.
- Added `whoathere vault simulate --complete` for in-memory approved promotion behavior.
- Enhanced `whoathere shim install --dry-run` to include the shim manifest.

## Validation

- CLI tests cover evidence profile listing and Vault simulation.
- Planned manual smoke checks:
  - `cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence profiles`
  - `cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault simulate`
  - `cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault simulate --complete`
