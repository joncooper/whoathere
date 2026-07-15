# Authenticated package root-evidence transport checkpoint

Date: 2026-07-15

Status: verified code-and-protocol checkpoint; physical guest-service custody and package execution
remain open

## Result

The Linux VZ package boundary now has a distinct authenticated result path for the canonical root
process, file, and network evidence produced by the protected collector. It does not reuse the
older correlation/payload-set decoder and it cannot represent this result as complete, clean,
verdict-authorizing, or sync-back-eligible.

The concrete collector now returns its already validated canonical root evidence instead of
discarding it with an `InvalidState` error solely because host-frame, DNS, HTTP, and global file
coverage remain incomplete. The protected service constructs exact package root-evidence claims,
uses the one-use execution-bound signing authority, and sends four separately bounded frames:

1. canonical root process evidence;
2. canonical root file evidence;
3. canonical root network evidence;
4. the Ed25519 root-evidence receipt.

A finish-v4 acknowledgement binds every payload digest and length to the exact authority request,
execution grant, measured guest key, sensor session, action, cgroup, launch contract, process plan,
terminal state, health state, and receipt lifetime. Its policy fields are fixed to:

- `evidence_kind: authenticated_root_incomplete`;
- `evidence_complete: false`;
- `host_composition_required: true`;
- `authoritative_verdict_permitted: false`;
- `sync_back: false`;
- no public network route.

## Independent consumer checks

The root-runner observer now requires the original authority request, the same consumed grant
observation, and the measured guest public key before opening the protected channel. On finish it:

- enforces exact frame kind, order, sequence, length, and digest limits;
- requires the finish-v4 incomplete/non-authorizing policy;
- strictly decodes each canonical root evidence schema against the active sensor challenge,
  launch contract, cgroup, leader, parent, process plan, and supervisor terminal;
- independently reconstructs the complete receipt claims from those typed objects;
- verifies the receipt with the grant-qualified Ed25519 public key and signed lifetime;
- rejects legacy/root variant substitution, evidence rebinding, noncanonical bytes, stale receipts,
  false clean upgrades, verdict authority, public routing, and sync-back.

Only after those checks does the process supervisor accept an
`AuthenticatedRootIncomplete` observation. Its schema-v2 evidence and the execution transcript use
generic, variant-tagged authentication/evidence-set fields rather than pretending the root receipt
is a legacy process correlation. The execution transcript remains globally unauthenticated and
verdict-ineligible until the independently verified host-frame/lifecycle composition is attached.

## Key custody and one-use behavior

The protected service receives the previously constructed
`LinuxVzPackageRootEvidenceSigningAuthorityV1`; it does not receive a second caller-selected request
or grant. The authority supplies its exact source bindings internally and burns the action before
claims validation or signing. The signing key remains private and redacted, and no key or seed
getter was added.

This closes the in-process ownership shape but does not yet prove that the measured physical guest
service binary is the sole process that receives the seed. The service entry point remains
crate-private and is not yet launched by the package runtime image.

## Verification

Completed locally:

- macOS `whoathere-macos-vm` library tests: 231 passed;
- Linux/aarch64-musl guest-target compilation, including tests: passed;
- full Rust workspace tests and documentation tests: passed;
- native workspace and Linux/aarch64-musl target Clippy with warnings denied: passed;
- Rust formatting and diff whitespace checks: passed;
- macOS VM Swift helper: 218 passed;
- finish-v4 tests cover the distinct receipt frame, canonical acknowledgement, clean/verdict/sync
  rejection, legacy-variant substitution, and digest rebinding;
- the existing receipt suite continues to cover wrong keys, mutations, time bounds, execution
  rebinding, one-use authority issuance, action replay, and rebound-then-retry rejection;
- the final restricted-material scan found only documented canary terminology, and `.whoathere/`
  plus `.env` remain ignored and untracked.

## Claim boundary

This checkpoint does not claim:

- a physical package-runtime VM run through this transport;
- measured guest signer custody;
- host-frame, DNS, HTTP(S), IPv6, TCP, GSO, retransmission, or broad network completion;
- global file coverage;
- host lifecycle/destruction composition attached to the process transcript;
- an authoritative clean or malicious verdict;
- any sync-back authority;
- improved malicious-package detection coverage.

No VM, package, or malware was run for this checkpoint. The July 1 actual-malware result therefore
remains 7 of 11 behavior detections (63.6%); containment remained successful, while the detection
gate remains open.

## Next gate

Wire the measured guest service process and runtime image to construct and exclusively own the
one-use signing authority, then perform one inert npm/wheel/sdist qualification on the approved
cloud Mac. The Mac host must independently verify the guest receipt, attach bounded host-frame and
lifecycle evidence, preserve incomplete coverage, destroy the clone, and keep verdict and sync-back
closed. Real-malware execution still requires the separate restricted-lab approval gate.
