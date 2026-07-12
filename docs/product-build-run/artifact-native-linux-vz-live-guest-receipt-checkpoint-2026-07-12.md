# Artifact-Native Linux VZ Live Guest-Receipt Checkpoint

Date: 2026-07-12

Status: a physical Apple-silicon Mac completed the trusted inert `fork_exec_exit` case through a
bounded host-to-guest virtio-vsock challenge channel and returned a root-signed guest receipt that
independent Swift and Rust implementations verified against the exact unqualified backend identity;
host lifecycle signing, a complete conformance case, and backend qualification remain pending

Canonical references:

- [Artifact-Native Detection Execution Plan](artifact-native-detection-execution-plan.md)
- [Measured Backend-Identity Checkpoint](artifact-native-linux-vz-measured-backend-identity-checkpoint-2026-07-11.md)
- [Ordered Process-Evidence Checkpoint](artifact-native-linux-vz-ordered-process-evidence-checkpoint-2026-07-11.md)

## Outcome

The guest now contains a statically linked ARM64 Linux signer/supervisor at a root-only path and a
32-byte Ed25519 seed at a root-owned mode-`0600` path. A canonical second initramfs overlay also
contains only the three exact virtio-vsock modules extracted from the pinned Alpine ISO modloop.
There is still no root disk, shared directory, external route, package authority, or sync-back path.

The signer listens once on virtio-vsock port 40551 and only accepts the host CID. Its request frame
contains exactly one canonical run spec and one canonical challenge, with fixed byte limits, exact
length checks, trailing-byte rejection, socket timeouts, and no command or path field. Before the
fixture starts, the signer validates the complete run context and hashes:

- its running executable through the kernel-provided `/proc/self/exe` handle;
- the protected process sensor through a no-follow file descriptor;
- the inert fixture through a no-follow file descriptor; and
- the challenge public-key binding derived from the root-only seed.

Only the existing process sensor then runs the known inert fixture as UID/GID 65534. The resulting
canonical fork/exec/exit payload is parsed inside the VM, converted into the existing guest claims,
and signed. The receipt returns over one bounded response frame. The host independently derives the
expected claims from serial evidence rather than trusting claims supplied in the response.

The successful physical run reported:

| Binding or observation | Value |
| --- | --- |
| Backend identity | `sha256:a059e03b4d47d2741e16bcedef77503392e0cd7082b8c8cfcf031d65e30c3f60` |
| Signed host helper | `sha256:e648e88169baf7e4eb94514164875f2bf521d2634528695aa01889e0dff637f1` |
| Challenge | `sha256:6bd9e7ecf8c64cc709501646a8a70e04fc2c751d2e992c01adc1cdef2415e2c7` |
| Run spec | `sha256:eb71d69f8ee8b514f035bbdb2a092043116056087fff3991e13cefd02b2e7ca3` |
| Process evidence | `sha256:7d5cfa3b7c2e3b3a56155215a40ed4d74a8c7e7953f4f467b0092c19a6c55aec` |
| Guest receipt | `sha256:5ef3e26c53ad882758fc211d061473e77063836b0bf442d5a8924c6404110a9a` |
| Ordered process events | `3` (`fork`, `exec`, `exit`) |
| Package principal | UID/GID `65534` |
| Host raw frames | `0` |
| VM stopped | `true` |
| Image identity stable | `true` |
| Package execution | `false` |
| External route | `false` |
| Sync-back | `false` |
| Execution authority | `false` |

Swift validated the request, embedded identity, challenge, serial-derived claims, Ed25519 signature,
image stability, exact serial markers, zero raw frames, and stopped VM before retaining the receipt.
A separate Rust executable then retrieved the raw serial and receipt bytes, independently decoded
the same run spec, identity, challenge, and process evidence, and reproduced every digest above.

## Reproducibility and fail-closed behavior

Two clean final signed-image builds made with the same protected seed were recursively byte-for-byte
identical. Both passed the signed-image verifier and its nested base-image verifier. The physical run
used the same exact signer and signed initramfs bytes:

- guest signer:
  `sha256:b259c5ec8ee0aaf7de4e1fc543affc77690fb7cc168134679b3df7df22f447c4`;
- signed initramfs:
  `sha256:77f80fd7adfae8dc1ee45bc2be986291a481d1fc0f6df2ec217178722b843ef3`;
- kernel BTF:
  `sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb`.

Two earlier physical attempts failed closed and produced no receipt. The first exposed a host parser
bug: the ready marker arrived with console CRLF line endings, while the initial poll searched for LF
bytes. The fix uses the existing exact-line normalizer and adds explicit VM teardown to every
post-start error path. The second request reached the signer, which correctly rejected the generic
`O_NOFOLLOW` open of Linux's protected `/proc/self/exe` link before starting the fixture. The final
implementation uses a dedicated current-executable measurement path while retaining no-follow opens
for ordinary sensor and fixture paths.

## Claim boundary and next gate

This is cryptographic proof that the entity holding the image-provisioned guest seed signed claims
bound to the exact one-use challenge, run spec, backend identity, and serial-observed payload. The
mode-`0600` guest path prevents the UID/GID 65534 fixture from reading the seed, but it is not hardware
attestation: the Mac host that supplies the initramfs can extract its contents, and the protected
local source seed still exists outside the image. Do not describe this checkpoint as protection from
a malicious host or as an independently attested VM identity.

The backend remains `candidate_unqualified`. No host lifecycle receipt was signed, no complete
guest-plus-host conformance case was verified, and none of the other 37 conformance cases ran. No npm,
PyPI, unknown, or malware package code ran. The next gate is a separately signed host packet/lifecycle
receipt for this same challenge, followed by verification of the first complete conformance case.
