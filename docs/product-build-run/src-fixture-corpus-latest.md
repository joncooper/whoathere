# WhoaThere Source Fixture Corpus Smoke Report

- Generated at: `2026-07-01T12:00:30Z`
- Mode: offline=`True`, online_public=`True`, include_vm=`False`
- Work dir: `/var/folders/7_/j0p6z0qj5x13kcwpxz7ls90w0000gn/T/whoathere-src-fixture-corpus._zq1hs1d`
- State dir: `/var/folders/7_/j0p6z0qj5x13kcwpxz7ls90w0000gn/T/whoathere-src-fixture-corpus._zq1hs1d/state`
- Total case failures: `0`

## Summary

- Cases run: `12`
- Package inputs observed: `543`
- Verdict counts: `{'manual_review': 12}`
- Scanner records: `2`
- VM records: `0`

## Offline Package-Risk Cases

| Case | Slice | Ecosystem | Verdict | Packages | Exit | Failures | Warnings |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| `active-direct-node` | `active-direct-small` | `npm` | `manual_review` | 51 | 22 | - | reputation_metadata_missing |
| `active-direct-python` | `active-direct-small` | `pypi` | `manual_review` | 50 | 22 | - | reputation_metadata_missing |
| `active-locked-node` | `active-locked-small` | `npm` | `manual_review` | 201 | 22 | - | reputation_metadata_missing |
| `active-locked-python` | `active-locked-small` | `uv` | `manual_review` | 200 | 22 | - | reputation_metadata_missing |
| `workflow-friction-node` | `workflow-friction` | `npm` | `manual_review` | 9 | 22 | - | reputation_metadata_missing |
| `workflow-friction-python` | `workflow-friction` | `pypi` | `manual_review` | 7 | 22 | - | reputation_metadata_missing |
| `hard-classes-node` | `hard-classes` | `npm` | `manual_review` | 4 | 22 | - | reputation_metadata_missing |
| `hard-classes-python` | `hard-classes` | `pypi` | `manual_review` | 6 | 22 | - | reputation_metadata_missing |
| `range-unpinned-node` | `range-unpinned` | `npm` | `manual_review` | 5 | 22 | - | reputation_metadata_missing |
| `range-unpinned-python` | `range-unpinned` | `pypi` | `manual_review` | 3 | 22 | - | reputation_metadata_missing |

## Online Public Cases

| Case | Slice | Ecosystem | Verdict | Packages | Exit | Failures | Warnings |
| --- | --- | --- | --- | ---: | ---: | --- | --- |
| `online-public-node` | `online-public` | `npm` | `manual_review` | 4 | 22 | - | reputation_metadata_missing |
| `online-public-python` | `online-public` | `pypi` | `manual_review` | 3 | 22 | - | reputation_metadata_missing |

## Scanner Results

| Case | Exit | Status | Scanner Clean | Failures |
| --- | ---: | --- | --- | --- |
| `online-public-node` | 0 | `passed` | `True` | - |
| `online-public-python` | 20 | `error+findings` | `False` | - |

## VM Results

_Not run._

## Top Reason Codes

- `artifact_review_not_requested`: `12`
- `reputation_metadata_missing`: `12`
- `package_risk_no_static_high_risk_indicator`: `11`
- `baseline_absent_requires_review`: `10`
- `package_publish_time_missing`: `10`
- `scanner_receipt_not_requested`: `10`
- `unpinned_no_last_known_good`: `7`
- `baseline_absent_pinned_clean_candidate`: `6`
- `scanner_receipt_workspace_bound`: `2`
- `network_capability_observed`: `1`
- `npm_lockfile_dependency_record`: `1`
- `npm_lockfile_resolved_url_present`: `1`
- `python_lockfile_dependency_record`: `1`
- `python_lockfile_registry_source_record`: `1`
- `native_extension_marker`: `1`
- `native_extension_requires_manual_review`: `1`
- `npm_lifecycle_script_install`: `1`
- `scanner_receipt_clean_advisory`: `1`
- `scanner_receipt_core_records_clean`: `1`
- `scanner_grype_not_clean`: `1`

## Failures And Warnings

- `active-direct-node` warning: `reputation_metadata_missing`
- `active-direct-python` warning: `reputation_metadata_missing`
- `active-locked-node` warning: `reputation_metadata_missing`
- `active-locked-python` warning: `reputation_metadata_missing`
- `workflow-friction-node` warning: `reputation_metadata_missing`
- `workflow-friction-python` warning: `reputation_metadata_missing`
- `hard-classes-node` warning: `reputation_metadata_missing`
- `hard-classes-python` warning: `reputation_metadata_missing`
- `range-unpinned-node` warning: `reputation_metadata_missing`
- `range-unpinned-python` warning: `reputation_metadata_missing`
- `online-public-node` warning: `reputation_metadata_missing`
- `online-public-python` warning: `reputation_metadata_missing`
- No harness safety failures detected.

## Interpretation

- `manual_review` is expected for many beta cases when scanner, VM, reputation, or last-known-good evidence is incomplete.
- Hard classes should remain `manual_review` or `deny`; an `auto_sync_candidate` hard-class result is a test failure.
- `reputation_metadata_missing` means this run did not prove registry/repository reputation is productized for that case.
- Scanner and VM failures are not allow signals; they should keep the result conservative.

## Raw Outputs

- Machine-readable report: `docs/product-build-run/src-fixture-corpus-latest.json`
- Command outputs: `/var/folders/7_/j0p6z0qj5x13kcwpxz7ls90w0000gn/T/whoathere-src-fixture-corpus._zq1hs1d/outputs`
- Generated fixture projects: `/var/folders/7_/j0p6z0qj5x13kcwpxz7ls90w0000gn/T/whoathere-src-fixture-corpus._zq1hs1d/generated-fixtures`
