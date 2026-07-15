# Linux VZ Package Authenticated Host-Composition Checkpoint

Date: 2026-07-15

Status: independent Mac verification and a fail-closed host-composition protocol are implemented
and tested; guest signer/root-service integration and physical inert-package qualification remain
open

## Result

WhoaThere now has an independently implemented Mac verifier for the protected guest's package
root-evidence receipt. The verifier uses Foundation canonical JSON and CryptoKit Ed25519 rather
than the Rust receipt implementation or its private claims type. It requires host-supplied expected
bindings for the exact authority, consumed grant, scenario/runtime identities, action/cgroup,
terminal, counts, coverage, and canonical process/file/network payload bytes.

The Mac can also construct and sign a distinct host-composite evidence object after it has verified
the guest receipt. That object binds the selected UDP host-frame correlation to the terminated guest
channel, stopped VM, stable post-run image identity, destroyed disposable clone, serial-log digest,
and sorted digest-only references to restricted raw evidence.

Neither signature is a verdict. The guest receipt still requires host composition. The current host
composite records only the selected transmitted UDP correlation and therefore says
`inconclusive_incomplete_coverage`, `broad_host_network_coverage_complete: false`,
`composite_evidence_complete: false`, `authoritative_verdict_permitted: false`, and
`sync_back_policy: structurally_absent`.

## Independent guest-receipt verification

The Swift verifier for `whoathere.linux_vz_package_root_evidence_receipt.v2`:

- accepts only the exact top-level and claims key sets and exact canonical bytes;
- independently hashes each canonical process, file, and network payload and binds its byte length;
- binds every dynamic digest and numeric field through typed field enums rather than accepting
  guest-selected expected values;
- checks the exact terminal/wait-status relationship, one action/cgroup, distinct PIDs, monotonic
  interval, heartbeat and event counts, grant interval, and receipt freshness;
- requires complete connect/`sendto` and cgroup-egress collection with zero reported loss while
  preserving the declared global file and broad-network gaps;
- requires UID/GID 65534, no raw arguments/paths/addresses, no public route, no truncation, no
  verdict authority, no VM-destruction claim, and no sync-back;
- derives the expected guest-key digest from the host-supplied public key and verifies the
  domain-separated Ed25519 signature with CryptoKit; and
- returns a typed verified value that still exposes host composition as mandatory and verdict and
  sync-back authority as false.

A deterministic Rust signer fixture and Swift verifier share these stable public values:

- unsigned claims: `sha256:9c24aa8dd83ad562f72415d1c110bff61548412b2f18aedf75e182cc39d776f9`;
- signed receipt: `sha256:dc91df448364fa0d8ddb2fb60d4f7c89027f3326d7ae9136a70bebaedc6d8a22`.

The fixture contains inert synthetic canonical payloads only. It is a wire/signature interoperability
test, not a package or behavioral-detection result.

## Host-composite boundary

`whoathere.linux_vz_package_host_composite_evidence.v1` accepts only an already verified guest
receipt, the independently decoded selected-UDP host evidence, and a closed Mac lifecycle object.
It rebinds:

- artifact, package-authority request, consumed execution grant, clone, exact runtime rootfs,
  runtime manifest, execution runner, and distinct guest/host evidence keys;
- exact guest receipt and process/file/network evidence digests;
- exact host-network evidence, frame, and normalized egress-correlation digests;
- a six-step host order from verified guest receipt through drained host frame, guest-channel
  termination, VM stop, stable image remeasurement, and clone destruction after stop; and
- a serial-log digest and one or more sorted unique restricted-evidence reference digests, never a
  host path or raw evidence bytes.

The host receipt uses a separate domain and key, zeroizes the supplied signing seed, binds the
entire canonical composite evidence object, and has a maximum ten-minute validity interval. Wrong
keys, stale receipts, forged signatures, rebound root receipts, incomplete lifecycle state, and
noncanonical bytes fail closed.

## Verification

The following checks passed locally:

- 223 `whoathere-macos-vm` Rust library tests;
- Rust formatting;
- `whoathere-macos-vm` Clippy across all targets with warnings denied;
- 218 Swift helper tests; and
- whitespace/error checks on the working diff.

New negative tests cover payload rebinding, wrong guest and host keys, premature/expired evidence,
noncanonical bytes, signature mutation, signed sync-back elevation, invented verdict fields,
coverage overclaims, missing VM stop, rebound root receipt bytes, and stale host receipts.

No VM, package, or malware executed for this checkpoint. No raw malware, packet capture, VM disk,
private host path, canary, or credential was added to tracked files.

## Remaining gate

This checkpoint closes the independent Mac parser/verifier and the first host-composite protocol
shape. AN-506 still requires:

1. carry the exact authority request, consumed grant observation, and measured guest-key identity
   into a protected signer after the root process/file/network collectors finish;
2. emit the guest receipt over an authenticated, bounded channel without exposing the signing seed
   to the untrusted package supervisor;
3. replace or bridge the older complete-legacy-payload assumption in the execution supervisor so
   incomplete root evidence reaches host composition without being mistaken for clean evidence;
4. source the expected host evidence key from the authenticated runtime qualification rather than
   an ad hoc caller value, and independently verify the host-composite receipt in Rust;
5. physically populate and verify both receipts with inert npm, exact wheel, and nested-sdist
   scenarios while preserving no route, no share, no sync-back, stop-before-destroy, and exact image
   identity; and
6. broaden network coverage, run benign controls, and only then request separate approval for the
   restricted eleven-sample malware regression.

The July actual-malware score remains 7/11. These authentication contracts improve evidence
trustworthiness; they do not by themselves detect another sample or justify a broader product
claim.
