# Artifact-Native Linux VZ Root Materialization Checkpoint

Date: 2026-07-13

Status: exact package bytes, normalized sdist source, and fixed sdist build closures now have
fail-closed root-supervised materialization primitives; they are not yet connected to a process
launcher and no package has executed

## Outcome

The future Linux VZ package supervisor can now construct all package-controlled filesystem inputs
from already bound data without accepting a caller path or unpacking an archive through a package
tool. Three distinct custody operations are implemented:

1. stage the exact npm tarball, wheel, or sdist under its process-plan basename;
2. normalize and safely materialize an sdist's one expected package root; and
3. stage every exact wheel in an sdist's fixed build closure.

All creation is relative to an already opened run-root directory descriptor. Creation uses
non-following, exclusive `mkdirat`/`openat` operations; verification compares the held descriptor
with a non-following directory-relative lookup. The materializers do not resolve a caller-supplied
filesystem path and do not invoke a package manager, runtime, shell, or package-controlled code.

This is library-level construction and verification only. The existing execution runner still
runs as UID/GID 65534 and remains false-authority. The root-only materializers are deliberately not
inserted into that unprivileged runner; a separate protected supervisor must own them when launch
and cgroup enforcement are implemented.

## Exact artifact custody

The canonical execution program and fixed process plan now preserve both the exact artifact
SHA-256 and byte length. The materializer derives the only accepted input basename from the unique
`MaterializeExactArtifact` action and requires the source descriptor to be:

- a regular file owned by the supervisor UID/GID;
- mode `0444` with one link;
- exactly the plan-bound byte length; and
- an exact match for the plan-bound SHA-256.

The destination is created as a new `input` directory and a new basename with `O_EXCL`,
`O_NOFOLLOW`, and `O_CLOEXEC`. The file is copied, synced, sealed to `0444`, rehashed, and checked
for the same device, inode, length, mode, link count, name mapping, and digest. The directory is then
sealed to `0555`. Prelaunch and post-run checks repeat the name-to-inode and digest verification
through the held descriptors. Cleanup first verifies the exact object, temporarily restores owner
write permission to the sealed directory, removes it descriptor-relatively, and syncs the parent.

The run root itself must be supervisor-owned, must not be group- or other-writable, and must be
traversable by the fixed package identity. A pre-existing `input` namespace, wrong bytes, wrong
length, unsafe source metadata, invalid plan, or replaced name fails closed.

## Safe normalized sdist source

`whoathere-artifact` now exposes a non-writing prepared-extraction object for exact sdist tar-gzip
and ZIP bytes. It reuses the strict archive readers and their existing traversal, link, device,
duplicate, case-fold, Unicode, prefix-collision, member-count, member-size, expanded-size,
compression-ratio, path-depth, and trailing-data checks. It additionally requires the exact
compiler-bound archive root and emits only normalized paths relative to that root.

The prepared manifest binds:

- archive form and canonical archive root;
- expanded byte length;
- every synthesized or explicit directory;
- every regular file's relative path, byte length, SHA-256, and package mode; and
- one canonical extraction-manifest SHA-256.

Member bytes are private, omitted from serialization, and redacted from `Debug`. They are moved
from the bounded archive reader into the prepared plan instead of cloned, avoiding a second full
expanded-archive buffer at peak memory.

The Linux VZ sdist materializer obtains those bytes only from the already rehashed exact-artifact
handle. It creates `/run/whoathere/source` descriptor-relatively and independently validates every
relative component before creating a member. Directories start at `0700`; files start at `0600`
and retain only a normalized executable bit (`0600` or `0700`). Every file is synced and checked
against its prepared digest, length, type, mode, owner, link count, and name-to-inode mapping.

Before ownership changes, the materializer enumerates the complete constructed tree and requires it
to equal the prepared member set exactly. It then transfers files and deepest directories to the
fixed package UID/GID, transfers the source root last, and repeats complete-tree verification. The
prelaunch check rejects an unexpected member or any changed expected member. This ownership change
is intentional: sdist build backends may write build output into the normalized source tree after
launch. The source tree therefore lives only inside the disposable no-sync VM clone and is not a
host copy-back candidate.

## Exact build-closure custody

The fixed process plan previously named closure wheels in pip arguments but did not carry each
wheel's complete identity. `ValidateExactBuildClosure` now binds the validated declaration-set
digest and the full canonical `SdistBuildClosureV1`: closure digest, ordered filenames, formats,
artifact digests, and byte lengths. Plan derivation rejects an invalid or empty closure and rejects
a declaration digest that does not match the closure.

The closure materializer consumes one supervisor-owned, mode-`0444`, single-link descriptor whose
length equals the checked sum of the plan-bound artifacts. It divides the payload only according to
the plan's ordered lengths, rehashes each segment, rejects wrong or trailing bytes, and creates one
flat `closure` directory containing only exclusive non-following files with the exact validated
wheel basenames. Files are root-owned `0444`; the directory is root-owned `0555`. The unprivileged
package process can read the wheels but cannot replace or add them.

The staged observation binds the process-plan digest, build-requirements digest, closure digest,
aggregate payload digest, artifact count, payload length, and closure directory device/inode.
Prelaunch and post-run checks reverify every held file and name mapping. Cleanup is retry-safe across
partial unlink progress and never removes a file whose mapping or content no longer matches.

## Verification

Local verification used only Rust source and deterministic inert fixtures:

- `whoathere-artifact`: 16 unit tests and 5 integration tests passed;
- `whoathere-macos-vm`: 124 library tests passed;
- execution-runner native tests: 2 passed;
- warnings-denied Clippy for both affected crates passed;
- formatting and `git diff --check` passed; and
- the repository-wide Rust test suite passed in full.

The first repository-wide attempt failed only because the workspace sandbox denied four inert fake
Ollama tests permission to bind localhost. The identical full command passed with local loopback
binding available. No package input or execution was involved in that exception.

Focused tests cover exact rehash and cleanup, wrong bytes, occupied namespaces, wrong sdist roots,
normalized-root removal, synthesized parent directories, executable-bit normalization, unexpected
post-materialization members, full closure identity in the process plan, wrong closure payloads,
read-only package inputs, stable device/inode mappings, and redaction of member contents.

The process-plan wire changed to bind artifact length and full closure identity. The previously
recorded release-runner hash is therefore not reused for this source state. A clean reproducible
Linux/aarch64 runner and runtime-image rebuild belongs to the later launcher/runtime checkpoint
after these primitives are integrated; no new runtime identity is claimed here.

## Malware handling boundary

Real malware runs only on the approved cloud Mac under the restricted lab workflow, inside a fresh
disposable Linux VZ clone. This checkpoint did not access the cloud Mac and did not download,
transfer, inspect, unpack, or execute a real sample. It did not run any package locally, start a VM,
use Docker for detonation, enable sync-back, contact live C2, or fetch a second stage.

## Claim boundary and next gate

This checkpoint closes filesystem-input construction as a source-level primitive. It does not
qualify an execution-capable runtime, prove that npm/pip/build triggers run physically, add signed
dynamic evidence, or improve the current 7/11 malicious-package detection result.

The next engineering gate is a protected root supervisor that:

1. creates the fixed writable work/cache/home/tmp/derived namespaces;
2. remeasures every pinned runtime executable and measured process input immediately before launch;
3. launches only the canonical process-plan actions under UID/GID 65534 in the scenario cgroup;
4. applies per-stage deadlines and bounded stdout/stderr capture;
5. validates the one derived wheel and typed console-entry-point substitutions;
6. terminates and reaps every descendant before post-run input rehash and VM teardown; and
7. binds materialization, process, protected telemetry, and teardown observations into signed
   evidence.

Only after that implementation passes local inert tests should a rebuilt execution runtime run
physical inert npm, wheel, and nested-sdist qualification cases on the approved cloud Mac. Real
malware and benign-corpus regression remain later, separate gates.
