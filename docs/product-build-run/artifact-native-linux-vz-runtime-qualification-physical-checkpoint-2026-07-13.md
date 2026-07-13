# Artifact-Native Linux VZ Runtime-Qualification Physical Checkpoint

Date: 2026-07-13

Status: the pinned package runtime passed one inert physical qualification on the approved cloud
Mac; both signed receipts independently verify, and package execution authority remains unavailable

## Outcome

The exact candidate runtime booted in one disposable Linux VZ VM on the approved cloud Mac and ran
only the fixed false-authority probe through the already-qualified protected process sensor. The
successful run proved all of the following:

- the guest remeasured the exact 1 GiB runtime block device and fixed ext filesystem identity;
- the runtime mounted read-only with `nodev,nosuid`;
- the measured runner executed only the `fork_exec_exit` false-authority alias as UID/GID 65534;
- the protected sensor emitted the exact eight required capability/terminal markers and one
  canonical `fork`/`exec`/`exit` evidence payload;
- the guest signed a request-, clone-, image-, runtime-, and evidence-bound receipt;
- the no-forwarding raw-frame sinkhole observed zero frames and zero drops;
- the guest channel terminated, the VM stopped, and the writable clone was destroyed after stop;
- the host signed a separate exact-lifecycle receipt; and
- execution authority, package execution, external routing, and sync-back remained false.

The launcher accepted no package artifact, package-manager command, generic argument vector,
execution grant, or sync-back destination. This gate did not run npm, pip, a wheel, an sdist, a
package lifecycle, or malware.

## Qualified inputs

The physical run bound these exact identities:

- qualified telemetry backend: `sha256:fed9ddb696432fa40ce20959b366235f5b7c1b06fd1dedb413ded4f5916734b1`;
- backend identity: `sha256:f610a600fd2654cff2ec8979c0e4e27b1ccdd3aededcc5d4c2bde5eefc5b8c71`;
- kernel: `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd`;
- base signed initramfs: `sha256:925f150d3faa7f036245391ce2c80a2f5524c13f77eea68de8a6a80c423f3b12`;
- protected guest signer: `sha256:71a68545f1edafa5fd85ad1785bc538327a2e4b67deb09d93c3038b39b8487f3`;
- protected process sensor: `sha256:d1edfce7fdba9bccdc1cbc313d469bcc52c8eb1a070732b571cccaa44ce7b3da`;
- qualification manifest: `sha256:74dd24aae8f023826b30c76ecc9ad8f192037f1b4b9497f2e8c70a2320aac86c`;
- complete Rust source closure: `sha256:ea72ffa2c6192d3db3e6c4ba96ba58f379869177ed378fc2b5fe1a748ab8779c`;
- qualification initramfs: `sha256:7cc5eaf5019e7bb33815ec79088aefdf4a154e6f229c17397b87e22b9a5dbd3d`;
- qualification agent: `sha256:1eb8fbb393ed2b373e6fa32f411150a91e32150fc6f044e302a05e8ac993ca93`;
- candidate runtime rootfs: `sha256:0114f1508ca2214787af2befc64641801f26904d7d6771cbb8cd9a746d7029ae`;
- candidate runtime manifest: `sha256:bcfa7106cd4a604af531b7c3320625a4434009a692bbde01c953ef61e2fb23a5`;
- candidate package runner: `sha256:96c9ab2127e11029c1b23259afcbd7dfab984ab3ae4528555f0a8b34dc48d658`;
- guest public key: `sha256:bd7f25d9b75f79d398cb73cd4b3dc1a4ce05941598e89b854151a595859c9432`; and
- host public key: `sha256:6ff50fffbdda2e7fbb9357b7b61cbf94ad9acfe328b4363dda3eca558b58222f`.

Two fresh local builds of the final qualification image were byte-identical. Both independently
passed the image verifier before transfer. The manifest, initramfs, and agent were rehashed on the
cloud Mac before the successful run and matched the local bytes exactly.

## Authenticated run evidence

The successful physical run produced these sanitized identities:

- qualification request: `sha256:eec2ebf4beb002906c1fc690f53e049686238b1899eb9bd9d2ac30d4d719403f`;
- unique clone binding: `sha256:d84181183e9bcaa0f72841bee1031f025d5e9715b57b647a8f8725f4ef0ae823`;
- guest receipt: `sha256:92d78ab471d748a831e393f27d623a57fb68f8083a13184fe74686feb42ff027`;
- host lifecycle evidence: `sha256:fa65491d6b075b81e7c6c285f29d224a9234d7befc19b12b4c42d01c5d54e6f6`; and
- host lifecycle receipt: `sha256:597bff3c02055ace29dba00b062b46cc40a723f39368be982e09ed2c068d8467`.

The independent Rust guest-receipt verifier accepted the request, rootfs, process evidence, guest
key, and signature. The separate Rust host-receipt verifier reconstructed the exact six lifecycle
events and accepted the request frame, response frame, evidence, host key, and signature. Both
verifiers passed first on the cloud Mac and then again against the inert copied-back evidence.
Neither verifier can grant execution or sync-back authority.

The final serial record ended in the exact receipt-success and qualification-success markers. The
runtime run directory was empty afterward, independently confirming clone destruction. The host
signing seed remained on the cloud Mac and was neither printed nor copied back.

## Fail-closed findings during the gate

The physical gate exposed two integration defects without crossing a safety boundary:

1. The first launcher binary lacked the required macOS virtualization entitlement. VZ rejected the
   configuration before starting a VM. The launcher returned a structured false-authority failure
   and cleaned the pre-VM clone. The replacement was ad-hoc signed through the repository's existing
   entitlement workflow with only `com.apple.security.virtualization`.
2. The first booting guest builds treated the protected sensor's fixed capability lines as an
   invalid evidence prefix. They emitted no receipt, powered off, and left no clone. The agent now
   requires the exact ordered eight-line sensor marker sequence and passes only the final canonical
   process-evidence line into receipt construction. It does not accept arbitrary prefixes or scan
   forward to a convenient payload.

These failures are useful qualification evidence: host and guest both failed closed, issued no
authority, and cleaned their disposable state. The corrected image was rebuilt twice and reverified
before the successful physical run.

## Claim boundary

The package runtime is now qualified for this exact inert false-authority probe on the measured
local Linux VZ backend. This does not qualify arbitrary package execution, prove npm/PyPI malware
detection, lower false-positive estimates, or create a production enforcement claim. No one-use
package execution grant exists yet.

Real malware remains restricted to the approved cloud Mac. No real sample was downloaded,
inspected, unpacked, transferred, or executed during this qualification work.

## Next gate

Bind the already-designed one-use execution grants to this qualified runtime, implement the first
inert npm tarball, wheel, and nested-sdist scenarios, and require the same authenticated process,
file, network, teardown, and clone-destruction evidence before any result is accepted. Keep
sync-back structurally absent. Only after the inert ecosystem matrix and benign controls pass should
the restricted eleven-sample regression gate run on the approved cloud Mac.
