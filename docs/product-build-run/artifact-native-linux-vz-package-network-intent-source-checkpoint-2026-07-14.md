# Artifact-Native Linux VZ Package Network-Intent Source Checkpoint

Date: 2026-07-14

Status: protected guest IPv4/IPv6 syscall-intent capture and an inert physical cloud-Mac
qualification are complete; canonical root network evidence, transmitted-frame correlation, and
package release remain unavailable

## Outcome

WhoaThere's protected package-process source now captures socket-address intent for the closed
`connect` and `sendto` syscall shapes. The BPF producer reads only exact `sockaddr_in` and
`sockaddr_in6` lengths, the decoder normalizes those bytes to address family, port, and address, and
the cgroup-correlated process stream carries that normalized target alongside the enter/exit pair.
Pointer arguments remain zero in the correlated stream and canonical process evidence.

A fresh diskless inert qualification on the approved cloud Mac proved one IPv4 TCP connect intent
and one IPv6 UDP send intent in the same continuously drained process stream as credential, exec,
mmap, and terminal observations. Both network syscalls failed before transmission because the guest
has neither an external route nor an IPv6 address. The independent host raw-frame sink saw zero
frames. Strict schema-v11 evidence was accepted only after all 18 source events, 10 correlated
observations, zero-loss state, process/file payloads, VM stop, and image identities matched exactly.

This closes only the protected network-intent **source** subgate. The root service does not yet emit
a canonical network-evidence payload, exact targets are not present in the canonical root process
payload, and the process/file/network streams do not yet cross one protected transport or join one
authenticated composite envelope. Arm and release therefore remain fail closed. The July malicious
package score remains **7/11 (63.6%)**.

## Producer and correlation boundary

For syscall-enter records, the BPF producer now:

- branches only for the selected AArch64 `connect` and `sendto` syscall numbers;
- obtains the socket-address pointer and declared length from the tracepoint context without
  storing the pointer in the emitted event;
- reads the two-byte family first with `bpf_probe_read_user`;
- accepts only `AF_INET` with exactly 16 bytes or `AF_INET6` with exactly 28 bytes;
- rereads exactly that bounded socket-address shape into the protected ring record; and
- records family and exact data length for strict userspace validation.

The full ring record is initialized before use. If the user-memory read fails, the family is
unsupported, or the length is wrong, the producer discards the already-reserved ring record and
increments the protected drop counter. It does not submit partial network detail. This discard was
added after local generated-program review caught an unreleased-reservation path before the physical
run.

The decoder independently requires:

- syscall-enter kind and `connect` or `sendto` identity;
- family bytes equal to the event family;
- exact family-specific length;
- nonzero network-byte-order port;
- declared syscall length equal to the captured length; and
- no truncation flag.

It copies only the family-specific address bytes into a fixed normalized target, hides the address
from `Debug`, and zeroizes both the source event's argument/data buffers and the normalized address
when their owners are dropped. The process correlator binds the target to the same cgroup, PID,
TGID, enter/exit sequence, timestamps, CPUs, arguments, and result as the syscall pair. Any detail
that cannot be normalized is unconsumed detail and fails the stream.

The existing canonical root process payload includes the `connect` and `sendto` syscall identities,
redacted argument-vector commitments, results, sequences, timestamps, process identity, and CPUs.
It deliberately does **not** yet serialize the target. The inert qualification transcript exposes
only the closed destination class, family, port, and syscall result; it does not serialize raw IP
addresses. A dedicated canonical root network schema must replace that test-only outer summary.

## Physical qualification

No package and no malware sample ran. The final run used a purpose-built unprivileged static inert
fixture in one fresh diskless Linux VZ guest. The VM had two vCPUs, no root disk, no directory
share, one host raw-frame sinkhole with no external route, and no sync-back path.

The fixture performed, in order:

1. the previously qualified credential drop, exec, three measured mmap pairs, and file mutation;
2. TCP `connect` to IPv4 documentation address `192.0.2.9` on port `443`;
3. one-byte UDP `sendto` to IPv6 documentation address `2001:db8::9` on port `53`; and
4. normal exit.

The pinned topology returned exact results:

- IPv4 connect: `-ENETUNREACH` (`-101`), because there is no route; and
- IPv6 send: `-EADDRNOTAVAIL` (`-99`), because the deliberately unconfigured guest has no IPv6
  source address.

Both are pre-transmission terminals. The host raw-frame count remained zero, so this run proves
protected guest intent plus independent absence of emitted frames. It does not prove host-side
correlation of a transmitted packet; that requires a later controlled sinkhole case whose exact
frame is captured and joined to guest intent.

The final strict verifier exited `0` with `status: "ok"` and `evidence_valid: true`. It proved:

- 18 contiguous process source events and 10 correlated observations;
- exact `connect_enter`, `connect_exit`, `sendto_enter`, and `sendto_exit` placement before the
  terminal event;
- two normalized network intents with the exact family, port, address, result, cgroup, process,
  sequence, timestamp, and CPU bindings;
- 70 active process-drain polls, three nonempty polls, and maximum batch size seven;
- zero BPF drops and zero discarded userspace records;
- a 6,304-byte canonical root process payload with SHA-256
  `37c8631a4ce53fd6ad130f596a410e34d191837d232038ec434f7475a4baf95b`;
- the existing five-mark file collector still produced 12 source events, 11 permission responses,
  one exact workspace change, and zero overflow;
- a 6,372-byte canonical root file payload with SHA-256
  `65ae64132674bb9540995806812ad50c792b9a6ef9025a249b9e9af4dcf31792`;
- the injected source-limit fault still signaled after 1,200 microseconds, killed its fault cgroup,
  and reaped the second inert fixture with exact `SIGKILL` status;
- 4,682 bytes of canonical outer schema-v11 evidence with SHA-256
  `194aea13fc067f785109a33d36b047539283089f6d0ca53e33ceaed9d4aec40c`;
- zero host raw frames, stable kernel/initramfs identities, and a stopped VM before acceptance; and
- `package_execution: false`, `malware_execution: false`, and `sync_back: false`.

The retained sanitized serial transcript is 5,530 bytes with SHA-256
`0f09ed251811ab10c9a743164884240e1716e85ac69dd34d73d8b7a050c26ecf`.

Two preceding attempts failed closed and did not produce accepted evidence. The first exposed only
fixture exit code `85`; the second added a sanitized result/errno diagnostic and identified Linux
`EADDRNOTAVAIL` for the intentionally unaddressed IPv6 socket. The contract was then bound to that
exact pinned-topology result. Both rejected runs still had zero host frames, no package or malware
execution, no sync-back, and a stopped VM.

Exact final inputs were:

| Component | Bytes | SHA-256 |
| --- | ---: | --- |
| Source commit | — | `28bfef0de51d611cabe17653056f0ad5e30f963a` |
| Pinned Linux kernel | 36,110,336 | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | 12,472,222 | `9e6519ef2034469a1fbb298f4a1fb7653576eb7287600b1d9b0c75c6a2d0ae45` |
| Guest init | 2,205 | `8e4b7a709ae061f88cedaf45db55b3a9f7e94730aa4a966ed3bb5029ec12c709` |
| Static network/process/file probe | 1,484,064 | `1b89e242c2a2adaab49c82ffad44466720dce5ce90cc450c7b192a0249aedd8f` |
| Static inert fixture | 381,712 | `c916471f9928b9e204c41d5d8e87ab39501dd1270b921a76418ddd693e590e54` |
| Canonical overlay CPIO | 1,868,800 | `0404ba93eed747885bf8a894c9591eb47c0dbd8ec68ec4d323c3651e3e20574a` |
| Deterministic gzip overlay | 919,775 | `8dc1dd4a44d1dde27468ee9b28e6111537f039744d5ae29388e56c8935abe868` |
| Combined qualification initramfs | 13,391,997 | `b66633bc97d6d819b91a110a0c552fa50018173caa561aae9d5262f66f26823e` |
| Strict entitled Mac verifier | 2,864,928 | `c9fb99e2ed626236d11213cb439d030e6c660fc79995afcd4ba2a00717fb1f54` |

The verifier passed strict code-signature validation and carried the macOS virtualization
entitlement.

## Validation

- Focused protected sensor Rust tests: 43 passed.
- `whoathere-macos-vm` Rust library suite after the final binding: 204 passed.
- Swift helper suite after the final binding: 200 passed.
- Native package-wide Clippy with warnings denied after the final binding: passed.
- Linux/aarch64-musl package-wide Clippy with warnings denied after the final binding: passed.
- Static aarch64-musl release probe and fixture build through `cargo zigbuild`: passed.
- Strict code-signature and virtualization-entitlement verification: passed.
- Exact inert physical qualification, including process/file continuity and injected fault behavior:
  passed.
- Rust formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| BPF producer | `4a4695c0981b946fe5a1386349a147beba75ed0235f14cc6cf5ba43954114561` |
| Kernel-event decoder and normalized target | `1676fa5ef2f1d9491219acb44034041d4c32b85db91f16d44ca3c7ea2749781c` |
| Process-stream correlation | `72f4c0830d13a57f0d787673bfda989711954f3fa09d0ad501db8bf991a7814a` |
| Inert physical qualification probe | `9fd8b56fcea3f45abe46b7f70c6f4f003d3ee7fc8075766a4982e3b59c4318e1` |
| Inert fixture | `90321c7c47796123d6795ad4169009d4eac03b2e08cd76811ccb7091c26bf3d0` |
| Strict Swift schema-v11 evidence decoder | `b099a5bb93eb560ef181df4ed20c71cb0e71431e19f8983ad87043adbe875378` |
| Strict Mac physical verifier entrypoint | `58dd6a59cf8357085f4b957acb942b7570c918dbad4a232a0b240385e35c1225` |

## Claim boundary and next step

This checkpoint proves that the protected guest process source can observe, normalize, correlate,
and strictly qualify two closed IP socket-intent shapes while the independent host confirms no
frame escaped the pre-transmission failures. It does not prove a canonical root network payload,
DNS intent, HTTP(S) observation, exact host/guest correlation for transmitted frames, arbitrary
npm/PyPI safety, low false positives, or improved malicious-sample detection.

The next implementation slice is a canonical root network-evidence payload that classifies and
tokenizes targets without serializing raw addresses, binds every intent to the process source and
sensor health, and joins controlled transmitted cases to exact host raw-frame evidence. That
payload must then cross the protected control protocol and join process and file evidence under one
authenticated composite envelope before runtime qualification or admission can consume it.
