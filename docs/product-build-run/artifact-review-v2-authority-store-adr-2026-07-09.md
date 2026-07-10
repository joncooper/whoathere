# Artifact Review v2 Replay And Lineage Authority ADR

Date: 2026-07-09

Status: sealed bounded MemoryOnly contract and pure transitions implemented; crash-consistent and
protected backends not implemented; the `AN-506` protected-evidence gate remains open

## Context

This ADR refines the authenticated-evidence work in the
[canonical artifact-native execution plan](artifact-native-detection-execution-plan.md), especially
`AN-506` evidence authentication and `AN-507` guest-compromise testing. It also answers the
[artifact-native threat-model addendum](artifact-native-threat-model-addendum.md) row for evidence
replay, tampering, truncation, and store replacement. That row requires canonical bounded evidence,
authenticated provenance, tamper-evident or append-only state, and rejection of stale or duplicate
job identities.

The current
[Artifact Review v2 local runtime checkpoint](artifact-review-v2-local-runtime-checkpoint-2026-07-09.md)
is deliberately unauthenticated and cannot authorize allow or sync-back. The authentication crate
now exposes a sealed bounded MemoryOnly authority. It creates a CSPRNG authority identity, reserves
`(trust_domain, evidence_id)` as `Pending` at challenge issue, rejects conflicting issue before
execution, atomically advances an accepted reservation and artifact lineage, and retains the exact
union of positive finding identities. Its pure `BTreeMap` transitions clone on success and leave
state unchanged on every error.

This is the first implementation slice of this ADR, not its protected-authority conclusion. Memory
state does not survive restart, its receipts contain no canonical state digest, and a user-owned
state file could not protect itself from another process running as the same macOS user.

This decision covers Artifact Review v2's restrictive advisory evidence. It does not grant AI
output allow authority, qualify VM telemetry, or replace the later signed `VerdictEnvelope`.

## Decision

We will separate the logical authority state machine from its persistence and protection backend.
All backends use the same bounded canonical state and pure transitions, but their receipts state
their actual durability and rollback posture. Only a protected Mac authority can satisfy the
`AN-506` protected-evidence gate.

The supported postures are:

| Posture | Intended use | Honest guarantee | Explicit limitation |
| --- | --- | --- | --- |
| `MemoryOnly` | Unit tests and deterministic transition checks | Sealed bounded one-process challenge, issue-time evidence reservation, generation, and lineage transitions with explicit receipts | No restart, cross-process, receipt-recovery, state-digest, or rollback guarantee; not a production authority |
| `CrashConsistentUserFile` | Development and crash/retry qualification | Bounded cross-process serialization, immutable state generations, file and directory durability, restart-safe idempotency | A same-user process can replace or roll back the lock, head, and state; the protected-evidence gate remains open |
| `ProtectedMacAuthority` | Required Mac-local authority | Root-owned or code-identity-restricted launchd/XPC boundary; protected signing key and anchor; unprivileged provider/package processes cannot mutate authority state | Does not resist root, host administration, or whole-machine snapshot rollback unless separately anchored |
| `RemoteConditionalAuthority` | Future Cloudflare/AWS and stronger rollback scope | Server-side conditional commit over the authority generation and state digest; local disk rollback cannot reset remote state | Adds network availability, latency, service identity, and operational dependencies; KMS alone is not a state store |

Implementation order and status:

1. **Complete:** sealed bounded MemoryOnly store contract and pure transition engine.
2. **Pending:** clearly labeled user-file crash-consistency backend and canonical persisted state.
3. **Pending:** protected Mac authority with protected key custody, clock, and head anchor.

The user-file backend will be useful qualification machinery but will not be the default trusted
authority.

## Security Invariants

1. Signature and evidence reconstruction succeed before an acceptance transition is requested.
2. The authenticated wrapper is constructed only after an owned authority backend returns a commit
   receipt whose durability and rollback-protection posture are explicit. A MemoryOnly receipt
   proves only the in-process commit sequence; only a protected durable commit can close `AN-506`.
3. Evidence identity is reserved across the entire trust domain at challenge issue, using
   `(trust_domain, evidence_id)`. Issuer or signing-key rotation cannot reset the reservation.
4. The challenge, runtime-seam digest, aggregate manifest, and signed statement bind a CSPRNG
   authority id. A persisted backend must retain that identity as its canonical `store_id` or
   `authority_epoch`; silently initializing a replacement authority cannot preserve continuity.
5. A challenge is single-use. An exact response-loss retry is idempotent; any changed evidence
   digest, cumulative-positive set, challenge binding, or evidence-id binding is replay or
   equivocation.
6. Artifact lineage is keyed by `(trust_domain, canonical_artifact_lineage_scope)`. Acceptance is a
   compare-and-swap against the exact predecessor evidence digest.
7. Positive finding identities are monotonic. A successor claims exactly the set union of its
   predecessor's cumulative positives and its current positives. A later clean result cannot erase
   an earlier positive. Clearing a false positive requires a separate signed adjudication design.
8. Missing, corrupt, over-capacity, noncanonical, stale, replaced, or durability-uncertain state
   fails closed. No backend falls back to an empty or in-memory store.
9. Authority state contains only bounded identities, digests, transition metadata, and public key
   references. It contains no signing seed, provider output, restricted capture, package bytes,
   credential, or canary.

## Canonical State And Pure Transitions

The state wire is a versioned RFC 8785/JCS JSON object with decimal integers represented as strings,
explicit present/absent states, sorted arrays, and no unknown fields, JSON numbers, or `null`. The
decoder reads a size-limited byte slice, rejects duplicate logical keys and noncanonical bytes, and
reconstructs domain types through their validating constructors.

The logical state contains:

- a random canonical `store_id`/`authority_epoch`, monotonically increasing generation, and prior
  state digest;
- challenge records with exact canonical binding digests and expiry;
- trust-domain-wide evidence reservations in `Pending`, `Accepted`, or `ExpiredUnaccepted` state;
- accepted evidence digest, current and cumulative positive finding identities, and acceptance
  generation; and
- lineage head and cumulative positive finding identities for each trust-domain/artifact scope.

Initial hard ceilings are:

| Resource | Maximum |
| --- | ---: |
| Canonical state bytes | 16 MiB |
| Active challenge records | 4,096 |
| Evidence reservations/tombstones | 16,384 |
| Artifact lineages | 4,096 |
| Positive finding identities per lineage | 4,096 |
| Positive finding references across the store | 65,536 |
| Unreferenced immutable generation objects before maintenance fails closed | 16 |

Code may lower these limits but may not raise them from untrusted configuration. Capacity is checked
before mutation. Reaching a limit returns a typed capacity error and preserves the prior generation;
it never prunes replay or lineage history implicitly.

The state engine exposes pure `apply_issue`, `apply_accept`, and explicit maintenance transitions.
Each takes one validated state value and returns either a complete next state plus outcome or an
error without side effects. The persistence backend owns locking, load/validation, commit, and
recovery around those transitions.

At issue:

1. The authority stamps trusted issuance and expiry time and validates the binding and predecessor.
2. It looks up `(trust_domain, evidence_id)` before generating or returning a challenge.
3. An exact canonical binding retry returns the existing pending challenge.
4. A different binding, an accepted reservation, or an expired tombstone for that evidence ID is
   replay/equivocation; evidence IDs are not silently reused.
5. A new CSPRNG-derived challenge and pending reservation are committed together before issue
   returns.

At acceptance:

1. The sealed verifier passes a private capability representing a signature-verified, fully
   reconstructed statement. Public callers cannot construct this capability or implement an
   always-accepting store.
2. Under the backend transaction, the authority reloads state and rechecks challenge identity,
   freshness, reservation, evidence identity, predecessor, and cumulative-positive union.
3. Challenge consumption, evidence acceptance, and lineage advancement occur in one generation.
4. The same challenge, evidence digest, and cumulative set returns `IdempotentRetry`. Any difference
   returns replay/equivocation. A competing successor from the same predecessor returns lineage
   conflict.

The store interface remains sealed to this crate. `MemoryOnly` is test-only or carries an explicit
ephemeral receipt. An authenticated result carries an opaque authority commit receipt containing
store ID, generation, state digest, acceptance outcome, durability posture, and rollback-protection
posture. No boolean supplied by a caller substitutes for that receipt.

## Crash-Consistent macOS File Protocol

The user-file backend uses one dedicated absolute root, owner-only permissions, a pinned directory
file descriptor, a stable kernel lock, immutable content-addressed state generations, and a small
head record:

```text
<root>/                                  0700
  store.lock                             0600; stable inode; never deleted
  head.v2                                0400; file-only authority pointer
  states/
    state-<generation>-<sha256>          0400; immutable canonical state
    .incoming-<random>                   0600; create-new staging only
```

Root, lock, head, staging, and state files are opened relative to the pinned directory with
`O_NOFOLLOW | O_CLOEXEC`; directories also use `O_DIRECTORY`. The backend validates expected owner,
exact mode, regular-file type, link count, device/inode identity, and local filesystem support.
State length is checked before allocation, reading is limited to `MAX + 1`, and the opened inode is
restated and rehashed after reading.

`store.lock` uses `flock(LOCK_EX | LOCK_NB)` with a monotonic bounded retry deadline. It is never
removed because a process crash releases the kernel lock. Time-based stale-lock deletion is not
used: deleting a lock pathname while a holder still owns the old inode can create two authorities.
The backend rechecks that the lock pathname still names the locked inode before publishing.

One commit performs these steps while holding the lock:

1. Load the head or protected anchor and the exact immutable generation it names. Verify store ID,
   generation, byte digest, canonical encoding, bounds, and all cross-index invariants.
2. Apply one pure transition and serialize the complete next generation.
3. Create a random create-new staging file in `states/`, write all bytes, call `sync_all`, set mode
   `0400`, and call `sync_all` again.
4. On macOS call `fcntl(F_FULLFSYNC)` on the state file. Strict mode treats an unavailable full sync
   as backend unavailability rather than silently weakening the receipt.
5. Rehash and restat the staging descriptor, then publish it without replacement as
   `state-<generation>-<sha256>`. Remove the staging name, sync the `states` directory, and verify
   the published object is a single-link regular file with the expected bytes.
6. For `CrashConsistentUserFile`, write a create-new temporary head naming the new store ID,
   generation, object name, and digest; sync and `F_FULLFSYNC` it; atomically rename it over
   `head.v2`; then sync the root directory. The head replacement is the commit point.
7. For a protected Keychain or remote anchor, conditionally update the anchor only after the
   immutable state object and directory are durable. That successful anchor update is the commit
   point.
8. Return the authority receipt only after the commit point and its required durability calls.

Unique immutable generation objects avoid overwriting the predecessor before a new head commits.
A crash before head/anchor commit leaves the old generation authoritative and the new object
unreferenced. A crash after commit leaves the new generation authoritative. A crash after durable
commit but before the response is handled yields an exact idempotent retry. Startup may remove only
validated unreferenced staging/generation objects under the hard orphan cap.

Recovery never chooses an older generation because the current object is missing or corrupt. A
missing head/anchor, a head-object mismatch, an unexpected generation, or a noncanonical state is a
hard failure requiring an explicit recovery workflow. Initialization and open-existing are distinct
operations; open-existing never creates an empty authority.

## Protected Mac Authority And Key Custody

The provider runtime is currently a caller-authorized, unsandboxed same-user executable. POSIX
`0700` and `0600` modes therefore do not protect a user-file authority from that actor. The Mac gate
requires a narrow launchd/XPC authority with one of these reviewed protection arrangements:

- root-owned authority state and signing material, with the service accepting only bounded
  digest/transition requests from an authenticated WhoaThere client identity; or
- a code-signed XPC authority whose signing key and current-head anchor are held in a
  code-identity/access-group-restricted, this-device-only Keychain item.

The authority does not execute provider or package code and does not receive unrestricted package
output. It owns challenge issuance, trusted time, signing-key use, state commit, and audit-safe
receipts. The Ed25519 seed never appears in the user-file store, child environment, inherited file
descriptors, runtime directory, debug output, or audit record. Verification keys and key lifecycle
metadata remain separately resolvable public control-plane state.

A Keychain current-head item can detect rollback of user-owned state only when the untrusted process
cannot read, replace, or delete that item. It is not a hardware monotonic counter and does not defend
against root, host administration, a restored whole-machine snapshot, or rollback of both disk and
Keychain. A root-owned file authority similarly protects against the unprivileged package/provider
actor but not root or disk-image rollback. If those actors enter scope, the authority head must move
to a remote transactional service using conditional generation/digest updates. A remote KMS can
protect the signing key but does not by itself provide monotonic replay state.

## Verification Matrix

| Area | Required tests |
| --- | --- |
| Pure transitions | New issue, exact issue retry, conflicting issue, first acceptance, exact acceptance retry, changed-body equivocation, same-ID/different-challenge rejection, expiry, and state immutability on every error |
| Trust-domain identity | Issuer/key rotation cannot reuse an evidence ID or reset lineage; separate trust domains remain isolated; copied state with the wrong authority epoch fails |
| Lineage | Exact predecessor succeeds; stale and competing successors fail; ancestor positives remain; duplicate/current positives form a set; dropping a positive fails; positive and global-cap saturation fails before mutation |
| Decoder and bounds | `MAX + 1` bytes, malformed UTF-8/JSON, duplicate/unknown fields, JSON numbers or `null`, noncanonical ordering, invalid decimal strings, duplicate logical keys, inconsistent indexes, missing lineage heads, invalid digests, excessive records, and excessive total positive references |
| Filesystem identity | Symlinked root/head/state/lock, hard-linked state, special files, wrong owner/mode/link count, replaced root or lock inode, temporary collision, changed inode during read, digest mismatch, and unsupported/nonlocal filesystem |
| Multiprocess locking | At least 16 independent processes race one exact acceptance: one `Accepted`, the rest `IdempotentRetry`; a different digest is equivocation; killing the lock holder permits later acquisition without deleting the lock |
| Commit fault injection | Process exit before staging, during write, before/after file sync, before/after `F_FULLFSYNC`, before/after immutable publication, before/after directory sync, before/after head/anchor commit, and after commit before response; reopen observes only the complete old or complete new state |
| Restart and retry | Issued challenge survives restart; committed acceptance remains idempotent; uncommitted acceptance can be retried once; lineage and positives survive; no recovery path falls back to empty or prior state |
| Rollback and replacement | Restoring an old file-only head plus matching state demonstrates the documented `NoneSameUserCanRollback` limitation; the same restore is rejected by the protected anchor; missing or deleted protected anchor fails closed |
| Key custody and leakage | Unauthorized same-user/provider client cannot invoke signing or anchor mutation; key seed is absent from state, environment, file descriptors, diagnostics, and audit output; revoked, wrong-role, wrong-purpose, wrong-epoch, and expired keys fail |

## Cloud Mac Qualification Gate

After deterministic unit and subprocess tests pass locally, the disposable cloud Mac may be used for
an inert-only durability campaign. No package installation, real provider, network call, or malware
sample is required or authorized for this gate.

The campaign must run on a documented supported local filesystem and include:

1. the multiprocess issue/accept race and lock-holder kill cases;
2. the full injected process-exit matrix around state, directory, and head/anchor commit points;
3. controlled reboots after immutable-state full sync, around head/anchor commit, and after the API
   reports success;
4. same-user attempts to replace root, lock, head, state, and prior generations;
5. protected-authority client-identity and Keychain/root ownership denial tests; and
6. restoration of a prior valid state snapshot, which must fail under the protected posture.

The Mac gate passes only when every reopen yields the complete old or complete new generation, no
transition is accepted twice, equivocation never becomes idempotency, cumulative positives never
decrease, success is never reported before durable commit, and protected rollback/replacement is
rejected or fails closed. Results must state the exact filesystem, macOS version, authority posture,
and residual root/snapshot boundary.

## Consequences And Open Gate

The design adds serialization, full-file generation writes, an exclusive local transaction, and a
protected service or remote dependency. Those costs are acceptable for the low-volume Mac-local
Artifact Review authority and can be measured before choosing a database-backed cloud
implementation. Immutable generations make crash reasoning and external anchoring simpler than an
unanchored mutable database, while the pure transition engine remains backend-neutral.

`CrashConsistentUserFile` may land as a development backend and may claim bounded crash-consistent
replay and lineage behavior among cooperative processes. It may not claim same-user store integrity,
tamper-proof lineage, or completion of the `AN-506` protected-evidence gate.

The `AN-506` protected-evidence gate remains open until `ProtectedMacAuthority` exists, the signing
key and head anchor are outside the provider/package actor's authority, the cloud-Mac qualification
gate passes, and the authenticated result carries the durable protected-authority receipt. Remote
conditional state is deferred until the local contract and conformance suite are stable.
