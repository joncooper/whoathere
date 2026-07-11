# Artifact-Native sdist Launch-Authority Issuer Checkpoint

Date: 2026-07-11

Status: the host can persist an unpredictable, expiring sdist launch authority bound to the exact
artifact, run spec, fixed build closure, and submission header; helper-side atomic consumption and
VM launch are not implemented in this checkpoint

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Authenticated Session Checkpoint](artifact-native-sdist-authenticated-session-checkpoint-2026-07-11.md)

## Outcome

`whoathere-macos-vm` now issues a distinct `whoathere.sdist_run_authority.v1` record before an
sdist launch can be prepared. Each issuance draws independent 256-bit randomness for the authority
identifier and challenge binding, derives the submission execution binding from that challenge and
the exact Mac run spec, constructs the closed sdist submission header, and durably publishes one
pending record.

The authority record binds:

- exact original sdist digest;
- exact Mac run-spec digest;
- fixed build-closure digest;
- unpredictable challenge-binding digest;
- unpredictable sdist-specific authority identifier;
- issue time; and
- expiry time.

The maximum lifetime is 15 minutes. Zero issue time, zero lifetime, overflow, and longer lifetimes
fail before authority creation.

## Protected persistence

The issuer requires an absolute existing state directory owned by the current helper identity and
not group- or world-writable. It opens all directories with `O_DIRECTORY`, `O_NOFOLLOW`, and
`O_CLOEXEC`; creates sdist-only `sdist-authorities/pending` and `consumed` children at exact mode
`0700`; and creates each authority record with `openat`, `O_EXCL`, `O_NOFOLLOW`, `O_CLOEXEC`, and
mode `0600`.

Before returning, it:

- writes canonical JSON;
- syncs the authority file;
- verifies regular-file type, owner, single link, exact mode, and exact length;
- syncs the pending and authority-root directories; and
- returns the exact record SHA-256 and pending path.

Authority identifier collision with either pending or consumed state fails or retries with fresh
randomness. Existing authority files are never overwritten.

## Verification

The sdist Mac integration suite now has 13 passing tests. The authority test proves:

- two issuances for the same run spec have distinct authority IDs and challenge bindings;
- the returned header challenge binding equals the persisted record;
- artifact, run-spec, and closure identities match exactly;
- issue and expiry times are retained exactly;
- persisted bytes match the returned record digest;
- authority files are mode `0600`;
- excessive lifetime fails closed; and
- a group/world-writable state root is rejected.

All inputs are inert generated sdist bytes. No VM, guest process, build backend, pip, package code,
network, restricted sample, or malware was used.

## Claim boundary and next gate

This is an issuer, not yet a complete single-use authority system. A helper must still atomically
rename the exact pending record into the consumed directory and validate expiry, challenge, header,
artifact, run-spec, and closure bindings before it authenticates the guest or accepts any artifact
bytes. Until that consumption path is implemented and tested, the authenticated session remains
nonce-bearing and signature-bound but does not claim replay prevention.

After atomic consumption, the next data-plane boundary is a separate manifest and transport for
every exact build-closure artifact. The target-sdist frame will not be generalized into an
unbounded dependency bundle.
