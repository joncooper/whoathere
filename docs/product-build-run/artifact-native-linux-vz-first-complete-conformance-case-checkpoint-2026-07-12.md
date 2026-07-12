# Artifact-Native Linux VZ First Complete Conformance-Case Checkpoint

Date: 2026-07-12

Status: one physical Apple-silicon Mac completed the trusted inert `fork_exec_exit` case with
separately signed guest process evidence and host packet/lifecycle evidence; independent Swift and
Rust implementations verified the complete case, but the backend remains `candidate_unqualified`
with 37 of 38 physical cases still pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Live Guest-Receipt Checkpoint](artifact-native-linux-vz-live-guest-receipt-checkpoint-2026-07-12.md)
- [Complete-Matrix Qualification Checkpoint](artifact-native-linux-vz-complete-matrix-qualification-checkpoint-2026-07-11.md)

## Outcome

The physical harness now retains two distinct authenticated views of one fresh challenge:

- the root-only guest signer derives process claims from the ordered cgroup-bound
  `fork`, `exec`, and `exit` payload and signs the guest receipt; and
- a separately keyed host signer derives packet and lifecycle claims from canonical host
  observations and signs the host receipt only after the guest channel terminates and the VM stops.

The host evidence payload contains a fixed six-event sequence: VM start, guest-channel connect,
guest-channel termination, packet-sensor completion, VM stop, and destruction of the diskless
ephemeral execution instance. It also binds two sensor heartbeats, zero dropped or truncated
frames, zero raw or externally forwarded frames, a healthy packet sensor ending in
`drained_would_block`, no storage devices, no external route, no package execution, and no
sync-back.

Swift verified each receipt against independently derived claims and then verified their shared
challenge, run spec, backend, terminal state, sensor health, teardown, and no-authority posture.
Only after that complete-case check passed did the harness create the three receipt/evidence files.
A separate Rust executable retrieved the raw inert serial evidence and canonical host payload,
decoded both independently, rederived both claim sets, verified both Ed25519 signatures, and
accepted the complete case.

The final physical run bound these exact values:

| Binding or observation | Value |
| --- | --- |
| Backend identity | `sha256:ac91294dffe34a2e953a77e9032004406611b6960cf4029b0dd36a9e51bacba8` |
| Signed host helper and packet sensor | `sha256:0ab67695259601cbffad0ba4dc5e643dabbf784ab83fa50a30173af54ade7f4a` |
| Guest evidence public key | `sha256:bd7f25d9b75f79d398cb73cd4b3dc1a4ce05941598e89b854151a595859c9432` |
| Host evidence public key | `sha256:2747cb61dcb2a6a24dfcd7ec41a4e984195c553ea8a7378935f68a2e6b984d70` |
| Challenge | `sha256:e4533c94b02e3ee3be5069f512db9296c7fdf3379ec397e4afeba731b876bb87` |
| Run spec | `sha256:7d72ee7225059e3149fb6fced17f8a185e91e29f6d2eff9687f5705bfd609db5` |
| Guest process evidence | `sha256:54fc54298d28037d3b3e19eb3829a4cb802bd47e70fa86c286a2ba17f15a3edf` |
| Guest receipt | `sha256:03e8abd2a72a56dc9710122e3e0729a1bed1463bd0f980e063d106177142f108` |
| Host evidence payload | `sha256:bd2049bd510ac327823ae3358fc4a7ae33f099641a8466d4a6ce707d32e36669` |
| Host receipt | `sha256:e2a8c968efac563959d8e6f90dd2662042ffd293ea1824f05edfcd19a2d5654d` |
| Inert serial evidence | `sha256:1bcfadacceb6699207c7c89abf5d57db38b3d884a22c93d199928b45d84fe33c` |
| Complete conformance case verified | `true` |
| Raw/external frame count | `0` / `0` |
| VM stopped / diskless instance destroyed | `true` / `true` |
| Package execution / external route / sync-back | `false` / `false` / `false` |
| Execution authority | `false` |

The harness creates serial, guest-receipt, host-evidence, and host-receipt files atomically with
owner-only mode `0600`. The successful final run confirmed that mode for all four files. An earlier
successful draft run exposed that the serial file inherited mode `0644` inside an otherwise
owner-only run directory; the final helper hardened that path and the complete case was rerun under
the new helper identity rather than carrying the weaker draft result forward.

## Key custody and trust boundary

The host signing key was freshly generated on the physical Mac in an owner-only directory. Its
seed remained mode `0600` on that Mac and was not retrieved or printed; only the public key was
copied into the local ignored evidence area and measured into the backend identity. Transient seed
bytes read by the helper are zeroized after signing.

This is a software-held key, not Secure Enclave protection or hardware attestation. The Mac
operator can access it, just as the host can extract the image-provisioned guest seed from the
initramfs. The two signatures establish domain separation, exact-byte binding, and tamper detection
within the controlled lab workflow; they do not prove safety against a malicious host operator.

For this diskless backend, `clone_destroyed` means the stopped one-boot execution instance has no
root disk or storage device to retain. It is not evidence of deleting a filesystem clone. Future
disk-backed backends must produce a real clone-deletion observation rather than reusing this
derivation.

## Validation

The final exact helper was rebuilt, ad-hoc signed with the virtualization entitlement, measured into
the new backend identity, and verified by the independent Swift identity decoder before the fresh
challenge was created. After the physical run, the independent Rust complete-case verifier
reproduced every digest in the table above.

The following repository gates passed:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
swift test --package-path whoathere/helpers/macos-vm-helper
scripts/whoathere-package-risk-smoke.sh
scripts/whoathere-scanner-integration-smoke.sh
scripts/whoathere-real-world-attack-harness.sh
scripts/whoathere-actual-malware-harness-selftest.py
```

The Swift helper passed all 105 tests. Both clean signed-image builds passed the independent signed
image verifier and were recursively byte-identical. The closed fixture-contract verifier again
produced exactly 38 unique description-only cases and the pinned static ARM64 descriptor digest.
The malware harness command above was its nonexecuting self-test only; no restricted sample was
opened or run.

## Qualification boundary and next gate

This is one physical complete case, not backend qualification and not package detection. It covers
only the ordinary `fork_exec_exit` terminal. It does not test nonzero network traffic, packet drops
or overflow, sensor death, channel interruption, timeout teardown, file behavior, DNS/HTTP intent,
listener cleanup, or the other 37 closed cases. A zero-frame run proves the sink saw no frame for
this inert fixture; it does not qualify packet capture for traffic or fault conditions.

No npm, PyPI, unknown, restricted, or malware package code ran. No execution-authority issuer was
added. The next gate is to implement the remaining protected guest and host observation channels,
then run each of the other 37 trusted inert cases on fresh challenge and execution-instance
bindings. Only the complete 38-case aggregate may construct the distinct qualified backend type.
