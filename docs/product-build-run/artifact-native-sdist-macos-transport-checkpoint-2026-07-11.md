# Artifact-Native sdist Mac Transport Checkpoint

Date: 2026-07-11

Status: inert exact sdist bytes compile into a distinct closed Mac run spec, round-trip through a
bounded challenge-bound binary channel, and stage read-only under a held inode; guest
authentication, signed receipts, VM launch, build execution, pip, package code, and malware remain
out of scope for this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Scenario Compiler Checkpoint](artifact-native-sdist-scenario-compiler-checkpoint-2026-07-11.md)
- [Artifact-Native Wheel Mac Run-Spec Checkpoint](artifact-native-wheel-mac-run-spec-checkpoint-2026-07-10.md)

## Outcome

`whoathere-macos-vm` now has an sdist-specific Mac boundary rather than treating an sdist as a
wheel or generic npm artifact. It adds three layers:

1. a canonical `whoathere.macos_sdist_run_spec.v1` that nests the validated sdist scenario template;
2. a distinct bounded host and guest binary submission protocol for the exact sdist bytes; and
3. guest staging that exclusively creates, syncs, freezes, holds, rehashes, and removes the inert
   sdist without opening or executing the archive.

The protocol has sdist-specific schema names, execution-binding domain separators, host magic, and
guest magic. Wheel and npm run-spec or transport domains are rejected rather than accepted through
a generic decoder.

## Mac run-spec binding

Every sdist Mac run spec binds:

- the full canonical sdist scenario template and template digest;
- exact original sdist digest and byte length;
- fixed offline build-closure digest;
- scenario identity and typed scenario kind;
- base disk and auxiliary-storage identities;
- hardware model and machine identifier;
- CPU and memory configuration;
- provisioning receipt, helper, guest supervisor, guest authentication key, runner configuration,
  and clone implementation digests;
- measured Python executable and pip CLI versions and digests;
- a dedicated non-root package UID/GID and fixed package username;
- APFS clone with no copy fallback;
- zero network devices;
- one boot and one scenario followed by clone destruction; and
- the sdist-only guest protocol identity and digest.

Compilation and decoding both revalidate the nested template and require its Python and pip
measurements to match the backend identity. The closure digest is repeated at the run-spec boundary
and must equal the digest inside the validated template. Unknown, noncanonical, cross-schema,
runtime-mismatched, closure-mutated, or policy-mutated run specs fail closed.

## Exact binary transport

The host submission frame carries a fixed binary prefix followed by one canonical header and the
exact sdist bytes. The prefix and header bind:

- protocol magic, version, and frame type;
- bounded header and artifact lengths;
- raw artifact SHA-256;
- full canonical Mac run spec and its digest;
- fixed build-closure digest;
- challenge-binding digest;
- execution-binding digest derived from the challenge and run spec; and
- the fixed artifact transport ceiling.

The full-frame decoder rejects wrong magic, unsupported versions or frame types, malformed or
noncanonical headers, challenge rebinding, run-spec substitution, closure substitution, exact-byte
mutation, truncation, and trailing data.

The guest decoder uses a separate sdist guest magic and streams the body into a caller-owned sink
while hashing, so it does not buffer a second artifact-sized copy. It accepts only exact EOF after
the declared body. The host, wheel guest, and npm guest transport domains are rejected.

## Non-executing guest staging

The first staging implementation:

- requires an absolute existing supervisor-owned staging root that is not group- or world-writable;
- creates a random per-scenario directory with exclusive mode `0700` semantics;
- creates `artifact.sdist` with `create_new`, `O_NOFOLLOW`, and `O_CLOEXEC`;
- streams only the bounded sdist guest submission into that file;
- syncs the content, checks owner/type/link-count/length, and changes the file to mode `0444`;
- reopens read-only with `O_NOFOLLOW`, checks descriptor and path device/inode agreement, and holds
  that descriptor;
- rehashes the held file before and after the future execution window;
- detects same-byte path replacement through device/inode binding; and
- removes both the file and per-scenario directory, including best-effort cleanup on failure/drop.

No staging API executes the archive, imports Python, invokes a backend, invokes pip, provides a
sync-back option, or returns guest-produced material to the host.

## Verification

| Gate | Result |
| --- | --- |
| sdist Mac backend/transport/staging integration tests | 7 passed, 0 failed |
| `whoathere-macos-vm` tests | 53 passed, 0 failed |
| `whoathere-detonation` tests | 18 passed, 0 failed |
| Workspace Clippy with warnings denied | passed |
| Rust formatting | passed |

The focused tests generate only inert nested-root tar/gzip bytes. They prove all four typed sdist
scenario kinds nest in the distinct Mac run spec, exact bytes and backend measurements rebind the
run-spec digest, runtime mismatch fails, canonical wire tampering fails, host binary round-trip is
challenge-bound, guest streaming is fragmented-read tolerant, cross-domain frames fail, staging is
read-only and single-link, pre/post rehashes preserve the held inode, bad transport leaves no staged
artifact, and path replacement is detected before any future launch.

No public network, registry, cloud Mac, VM, guest process, PEP 517 backend, setup script, pip
process, Python import, package code, restricted sample, or malware was used.

## Claim boundary and next gate

This checkpoint does not yet establish an authenticated host-to-guest session. A caller-supplied
challenge digest is cryptographically bound into the frame, but no fresh authority record, measured
guest signature, signed staging receipt, or complete control-frame session exists for sdists yet.
It also transports only the target sdist; the exact build-closure artifacts are identity-bound but
not transported or installed.

The next slice is therefore:

1. add an sdist-specific fresh challenge and measured Ed25519 guest response;
2. add a signed staging receipt binding the challenge, run spec, exact sdist, closure digest, held
   device/inode, prelaunch rehash, and explicit no-execution/no-sync posture;
3. compose the ordered control session and prove cleanup on every binding failure; and
4. only then design the separate bounded channel for the exact build-closure artifacts.

Actual PEP 517 or legacy execution remains closed until those layers and a root-owned fixed runner
are proven. The live wheel qualification also remains gated on trusted confirmation of the cloud
Mac's changed SSH host identity; host-key verification has not been weakened.
