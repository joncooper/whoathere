# Artifact-Native sdist Single-Use Authority Checkpoint

Date: 2026-07-11

Status: the Mac sdist authority primitive now performs an atomic, burn-first pending-to-consumed
transition and can derive the exact guest challenge only after successful consumption; production
Swift/VZ helper integration, build-closure transport, VM launch, and package execution remain open

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Artifact-Native sdist Authenticated Session Checkpoint](artifact-native-sdist-authenticated-session-checkpoint-2026-07-11.md)
- [Artifact-Native sdist Launch-Authority Issuer Checkpoint](artifact-native-sdist-launch-authority-issuer-checkpoint-2026-07-11.md)

## Outcome

The sdist launch-authority module now has a helper-facing consumption request and a consumed
authority observation. On macOS, consumption atomically renames the exact authority record from the
protected pending directory into the protected consumed directory with `renameatx_np` and
`RENAME_EXCL`. The move happens before expiry, digest, record, or binding validation.

This ordering is intentional: an expired, mutated, or incorrectly bound attempt burns its authority
and cannot be corrected and retried. Two concurrent consumers cannot both win.

## Burn-first validation sequence

After the atomic move, the consumer:

1. syncs the pending, consumed, and authority-root directories;
2. opens the consumed record with `O_NOFOLLOW` and `O_CLOEXEC`;
3. requires a regular, helper-owned, single-link `0600` file under the fixed record-size ceiling;
4. reads the exact stored bytes and verifies the expected record SHA-256;
5. parses a closed authority schema and requires canonical JSON;
6. validates the sdist authority identifier and canonical decimal time fields;
7. requires a positive lifetime no longer than 15 minutes;
8. accepts time only in the half-open interval `issued_at <= now < expires_at`;
9. requires exact agreement among the persisted record and submission header for challenge
   binding, run-spec digest, artifact digest, and build-closure digest; and
10. returns the immutable consumed record, digest, path, and consumption time.

If the record is already consumed, missing, expired, noncanonical, mutated, or rebound, the API
returns a specific fail-closed error. No path moves a consumed authority back to pending.

## Consume-then-authorize composition

The helper-facing `consume_and_authorize_macos_sdist_guest_session_v1` API first completes the
burn-first operation. Only after success does it construct an sdist authentication challenge from:

- the consumed submission execution binding;
- exact run-spec digest;
- exact build-closure digest;
- caller-provided fresh guest nonce;
- disposable-clone binding; and
- measured guest authentication public-key digest from the bound backend identity.

The resulting authorized-session object retains the consumed authority, exact submission header,
and exact challenge as one typed value. This gives the future production helper an API that does not
need to reconstruct or separately trust those bindings.

The lower-level challenge constructor remains available to protocol tests and library callers, so
production enforcement still depends on wiring the actual helper lifecycle exclusively through the
consume-then-authorize entrypoint.

## Verification

The sdist Mac integration suite now has 18 passing tests. New coverage proves:

- successful consumption removes pending state and creates consumed state;
- sequential replay returns `authority_unavailable`;
- exact expiry time is rejected and burned;
- a header with a different random challenge binding is rejected and burned;
- an on-disk one-byte mutation is rejected and burned;
- two concurrent consumers produce exactly one success and one unavailable result;
- the consumed record retains exact artifact, run-spec, closure, digest, and time identity; and
- consume-then-authorize derives the exact execution, run-spec, closure, clone, and measured-key
  challenge fields, while a second authorization attempt fails as replay.

All inputs are inert generated sdist bytes. No VM, guest process, package manager, build backend,
network, restricted sample, or malware was used.

## Claim boundary and next gate

This checkpoint proves the Rust/macOS authority primitive. It does not prove that the packaged Mac
helper invokes it before opening a VZ channel, that helper measurements include this code, or that a
real guest launch rejects replay. The next slice is to add an sdist helper lifecycle that accepts
only a prepared authority request, consumes it before guest authentication or artifact reads, and
uses the resulting authorized-session object to compose the existing control and binary frames.

Only after that helper lifecycle is tested should work proceed to a separately bounded manifest and
transport for exact build-closure artifacts.
