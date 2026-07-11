# Artifact-Native sdist Build-Closure Materialization Checkpoint

Date: 2026-07-11

Status: an inert guest API can now turn the authenticated closure payload into exact, validated,
package-manager-named wheel files; the production supervisor still does not call it or execute code

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Build-Closure Staging Checkpoint](artifact-native-sdist-build-closure-staging-checkpoint-2026-07-11.md)
- [Python Wheel Binary Distribution Format](https://packaging.python.org/en/latest/specifications/binary-distribution-format/)

## Outcome

The typed sdist build-closure manifest now binds an `artifact_filename` and `artifact_format` for
every exact dependency artifact. Version 1 accepts only wheels and rejects:

- path separators, traversal, non-ASCII names, and names longer than 255 bytes;
- a distribution or version prefix that does not match the typed package identity;
- missing or malformed Python, ABI, or platform tags;
- an optional build tag that does not begin with a digit;
- non-wheel extensions or unknown artifact formats; and
- duplicate materialization filenames, even when the records otherwise differ.

Rust produces and validates this schema. The Swift host parser independently applies the same
closed-key, filename, format, ordering, and uniqueness rules before VM or launch authority use.
The filename contract follows the wheel specification’s
`{distribution}-{version}(-{build tag})?-{python tag}-{abi tag}-{platform tag}.whl` shape while
remaining deliberately ASCII-only for this first execution slice.

## Inert guest materialization

After exact target and closure staging, `StagedMacosSdistGuestV1::materialize_build_closure` can:

1. prove the held closure-payload descriptor still names the same supervisor-owned, single-link,
   read-only file at its expected path;
2. create a new supervisor-owned `build-closure/` directory with mode `0700`;
3. split the held payload at the manifest’s exact declared byte boundaries;
4. create each wheel with create-new, no-follow, close-on-exec behavior;
5. sync it, change it to mode `0444`, reopen it without following links, and compare descriptor and
   pathname device/inode identity; and
6. independently rehash every materialized wheel and compare its exact digest and length to the
   authenticated manifest.

The returned typed observation contains the materialization-directory device and inode plus each
wheel’s validated filename, SHA-256, byte length, device, and inode. The implementation keeps the
file descriptors open until cleanup, records every pathname immediately after creation, and makes
partial-failure cleanup retryable.

Cleanup detects closure-payload replacement and materialized-wheel replacement. It removes the
materialized files and directory before the original closure payload, manifest, target sdist, and
scenario directory. A mismatch or incomplete removal returns a cleanup failure instead of
silently claiming disposal.

## Production claim boundary

This is intentionally not wired into `whoathere-sdist-supervisor`. The currently signed production
receipt remains truthful with:

- `package_execution_enabled=false`;
- `sync_back_enabled=false`; and
- `build_closure_materialized=false`.

The mode-`0700` directory also keeps the wheels unavailable to the package UID. A later step must
introduce a separate, explicit execution authority and a protected handoff to the unprivileged
build environment before the package manager can consume them. No public dependency fallback is
introduced.

## Verification

Inert tests prove:

- Rust and Swift reject traversal, backslashes, identity/version rebinding, malformed tags,
  unknown formats, and duplicate filenames;
- exact concatenated closure bytes become the expected wheel filenames and per-file byte strings;
- directory and file modes, link counts, lengths, hashes, devices, and inodes match;
- repeated materialization is rejected;
- replacement of the staged payload fails before materialization;
- replacement of a materialized wheel makes cleanup fail closed and permits a safe retry; and
- successful cleanup leaves the staging root empty.

Verification commands completed successfully:

```sh
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-detonation
cargo test --manifest-path whoathere/Cargo.toml -p whoathere-macos-vm
cargo clippy --manifest-path whoathere/Cargo.toml -p whoathere-detonation -p whoathere-macos-vm --all-targets -- -D warnings
swift test
```

The Rust macOS VM suite passed 22 sdist backend tests, and the Swift helper suite passed 85 tests.
No VM, package manager, build backend, public resolver, restricted sample, or malware was used.

## Next gate

The next local-code slice is a separately authorized, unprivileged build runner with:

- a protected, read-only closure handoff;
- `--no-index` and exact fixed-closure enforcement;
- fresh virtual-environment creation and teardown;
- explicit PEP 517 versus legacy setup behavior;
- independently trustworthy process, file, credential, listener, and network telemetry; and
- signed evidence that distinguishes materialization, execution, derived-wheel production, and
  cleanup.

A live VZ qualification still requires an independently confirmed Mac and a newly provisioned,
measured stopped base. Real-malware execution remains separately gated and unauthorized.
