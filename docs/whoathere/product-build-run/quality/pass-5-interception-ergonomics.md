# Product Build Run Pass 5: Interception Ergonomics

## Scope

Reviewed whether the local interception artifacts would preserve normal developer workflows.

## Finding

The initial shim materialization plan included `python` and `python3` as default shims so `python -m pip install` could be intercepted. That would catch the desired workflow, but it would also intercept ordinary Python execution and likely break developer tooling.

## Improvement Made

- Default materialized shims are limited to `npm`, `npx`, `pip`, and `pip3`.
- `python` and `python3` remain supported by command classification, are listed as optional in the dry-run manifest, and require explicit `shim install --include-python --dest <sandbox-dir>` opt-in before materialization.
- Actual shim materialization writes only to an explicit destination directory and never edits PATH or shell profiles.

## Validation

- Unit tests cover explicit destination parsing, default shim materialization, and opt-in python/python3 shim materialization.
- README documents the optional Python shim tradeoff.
- Smoke checks confirmed `shim install --dry-run --include-python` shows both default and optional shim rows and opt-in materialization writes six shims under a sandbox temp directory.
