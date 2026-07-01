# Source Dependency Fixture Test Plan

## Purpose

Use the deduped `~/src` dependency corpus to test WhoaThere against packages and dependency shapes
that resemble normal local work, before moving to real malware samples.

Input corpus:

- `docs/product-build-run/src-dependency-fixtures.json`
- `docs/product-build-run/src-dependency-fixtures.md`

The corpus is metadata-only. It should drive generated throwaway projects and package-risk/scanner
tests; it should not cause dependencies to install directly on the host.

## Recommended Slices

1. Active direct dependencies:
   - `source_class_counts.active > 0`
   - `source in {"declared"}`
   - Start with the top 50 Node and top 50 Python packages by active occurrence.

2. Active locked transitive dependencies:
   - `source_class_counts.active > 0`
   - `source in {"locked"}`
   - Start with the top 200 Node and top 200 Python packages by active occurrence.

3. Hard package classes:
   - Node examples: `fsevents`, `esbuild` platform packages, packages with native install tools.
   - Python examples: `numpy`, `pandas`, `pyarrow`, `torch`, packages likely to use native wheels.
   - Expected beta behavior: manual review or fail closed, not auto-sync.

4. Workflow friction packages:
   - Common dev dependencies such as `typescript`, `vite`, `eslint`, `pytest`, `hatchling`,
     `setuptools`, `wheel`.
   - Expected behavior: clear explanations, stable manual-review reasons when evidence is missing,
     and no host execution.

5. Breadth pass:
   - Include `archive`, `template`, `reference`, `vendored`, and `worktree` source classes only
     after the active-project pass is stable.

## Test Workflow

1. Parser and classification pass:
   - Generate throwaway npm, pip, and uv projects from fixture slices.
   - Run `whoathere package-risk assess --json`.
   - Verify every dependency receives a deterministic allow/manual-review/deny reason.
   - Verify native, binary, direct/VCS/editable, and unknown package classes stay conservative.

2. Scanner pass:
   - Run external scanners only on generated throwaway fixtures or public/open projects.
   - Keep private-project networked scanner runs opt-in because they may disclose dependency
     metadata to external services.
   - Verify scanner failures become `scanner_clean=false` or unavailable/error reason codes, never
     unsafe allow decisions.

3. VM pass:
   - Do not install the whole corpus.
   - Select a small package slice and run supported workflows inside the macOS VM.
   - For the current beta, expect many public-resolution cases to fail closed because the release is
     local-first and conservative.
   - Verify clean local packages can run inside the VM and only approved outputs sync back.

4. False-positive review:
   - Record packages that are common and low-risk but still generate noisy manual-review reasons.
   - Tune wording and grouping before relaxing any policy.
   - Do not weaken hard-class behavior for native/binary/direct/VCS/editable dependencies.

5. Malware overlay later:
   - Reuse common package names and API shapes from this corpus to build non-destructive malicious
     fixtures with mock canaries.
   - Test install-time, build-time, import-time, CLI-entry, API-compatible, delayed-CI, and
     macOS-specific activation patterns.

## Exit Criteria For This Corpus

- WhoaThere can process generated fixture projects without host package execution.
- JSON output is deterministic, redacted, and understandable.
- Common packages do not produce confusing or contradictory reason codes.
- Hard package classes remain manual-review or deny by default.
- Scanner outages or network restrictions never authorize execution or sync-back.
