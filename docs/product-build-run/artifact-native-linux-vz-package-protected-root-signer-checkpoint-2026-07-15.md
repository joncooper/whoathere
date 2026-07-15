# Linux VZ Package Protected Root-Signer Checkpoint

Date: 2026-07-15

Status: shared one-use execution-request state and a grant-bound protected root-receipt signing
authority are implemented and tested; physical root-service custody, receipt transport, and inert
package qualification remain open

## Result

The verified package execution-grant observation now owns the one-use execution-request burn. An
authorizer borrows that observation instead of taking ownership and maintaining a private Boolean.
Creating two authorizer wrappers therefore cannot derive two execution requests: the first valid or
invalid attempt atomically burns the single state shared by the retained grant observation.

That same retained observation can now be used by later evidence composition without reconstructing,
cloning, or recovering an execution capability. Root-receipt construction and independent Mac host
composition both reject a grant until its exact execution request has actually been consumed.

A new `LinuxVzPackageRootEvidenceSigningAuthorityV1` models the protected guest signer boundary. It
accepts only:

- the exact package-authority request;
- its verified and consumed one-use execution-grant observation;
- proof that the execution request was consumed; and
- an Ed25519 signing seed whose public-key digest is the guest evidence-key identity already carried
  by that grant.

The seed is held in zeroizing storage, converted to the protected signing key, and immediately
zeroized. The authority exposes no key or seed accessor. Its debug representation contains only the
authority-request digest, grant digest, and burned-action count. The grant also atomically burns the
single signer-authority issuance before key validation, so a wrong-key attempt cannot be repaired by
constructing another authority over the same execution.

## Fail-closed receipt production

For every nonzero process action, the signer burns the action index before validating the proposed
claims. A malformed or rebound attempt cannot be corrected and re-signed for the same action. The
signer independently requires the receipt claims to match the retained request and grant across:

- artifact kind, digest, and byte length;
- authority-request and execution-grant digests and grant time bounds;
- runtime qualification, rootfs, manifest, and package-runner identities;
- typed scenario plan, template, kind, policy, dependency closure, and runtime profile;
- telemetry backend and request, grant, attempt, and clone challenges; and
- the grant-qualified guest evidence public key.

The existing strict claims validation still binds the protected sensor identity, launch contract,
process plan, action/cgroup identity, terminal state, canonical process/file/network evidence,
coverage gaps, and validity window. Receipt signing cannot upgrade current evidence: host
composition remains required, authoritative verdicts remain forbidden, and sync-back remains
structurally absent.

## Verification

Focused tests prove that:

- multiple authorizer wrappers share one irreversible request burn;
- a signing authority cannot be created before request consumption;
- the guest signing key must match the key measured into the consumed grant;
- a wrong-key attempt spends the one signer-authority issuance and a second constructor is rejected;
- a valid protected receipt independently verifies under the measured public key;
- a repeated action is rejected;
- an artifact-rebound signing attempt burns the action before rejection and a corrected retry is
  rejected; and
- host composition rejects an otherwise valid source set until the grant's request burn is visible.

The final qualification run passed:

- all 228 `whoathere-macos-vm` Rust library tests;
- the full Rust workspace test and documentation-test suite;
- workspace Clippy across all targets with warnings denied;
- Rust formatting checks; and
- all 218 Swift helper tests.

No VM, package, or malware executed for this checkpoint. No raw malware, packet capture, VM disk,
private host path, canary, signing seed, or credential was added to tracked files.

## Remaining gate

This checkpoint establishes the protected authority primitive but does not claim that a measured
root-service process owns it yet. AN-506 remains open until the physical path:

1. supplies the exact request, consumed grant, measured signer key, process plan, and launch contract
   to the protected root service without exposing them as package-controlled inputs;
2. constructs and signs claims only after process, file, and guest-network collectors finish;
3. transports the bounded receipt and honestly incomplete canonical evidence to the Mac instead of
   routing it through the older complete-legacy-payload decoder;
4. composes and independently verifies the guest and host receipts after VM stop, stable image
   remeasurement, and clone destruction;
5. runs inert npm, exact-wheel, and nested-sdist qualification with no route, share, or sync-back;
6. broadens network observation and measures benign controls; and
7. only then requests separate approval for the restricted eleven-sample regression.

The July actual-malware score remains 7/11. This checkpoint improves evidence authority and replay
resistance; it does not detect another sample or support a broader product claim.
