# Artifact-Native Linux VZ Channel-Interruption Checkpoint

Date: 2026-07-12

Status: `channel_interruption` plus the twenty-eight earlier physical cases pass on one exact
measured backend identity; the backend remains `candidate_unqualified` with 9 of 38 cases pending

## Outcome

The seventh teardown-stress gate proves fail-closed handling when the host interrupts the guest
evidence channel. After the guest signer accepts the measured host connection, the host transmits
only the valid 16-byte frame header from the exact 5,165-byte challenge-bound request and half-closes
its write side. The guest reads EOF, rejects the declared-but-missing run-spec and challenge bodies
with the exact transport-length error, and exits before it can decode a run spec or launch a fixture.

The guest emits zero response bytes, no sensor or package-behavior evidence, and no guest receipt.
The signed host evidence binds the full request size, exact transmitted prefix, zero response,
terminated channel, healthy zero-frame packet sensor, natural VM stop, and destruction of the
diskless instance. Swift and Rust reject wrong or partial interruption fields, request-size
rebinding, response bytes, wrong prefix lengths, guest-receipt substitution, contradictory serial
markers, and interruption fields on ordinary cases.

| Binding or observation | Final channel-interruption case |
| --- | --- |
| Backend identity | `sha256:3536d0fd7d779d1ab804c99db9eb4cee9caecf46c6344ac3682087723ea7b311` |
| Entitled signed host helper | `sha256:287b9d136d020ded488a1e64900b319d3f8612660348a0c7779113f1c9e789fd` |
| Linux kernel | `sha256:8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Signed initramfs | `sha256:f811659aa67554f42678ee1abcf85f46b4b0034a6d5ff396bcf5309648582ad0` |
| Guest signer | `sha256:2de86caeeefc46f5a9b2ee2cad43307c4e378c8e6cef0461e0513f0105b1b759` |
| Protected sensor | `sha256:0fa373c6050059ef74c5da9f0b1f9ff3acb1ed05a1a61a02aa77f7747c23fa98` |
| Signed-image manifest | `sha256:96d5d6cd77e2c25556046361f25207fc048533da33de87cd8e3bd4d0a035f97f` |
| Challenge | `sha256:b412a78fe94c9c7ed45913482e34b9b17cbb805e7f27692a84edf96836373393` |
| Run spec | `sha256:e4b8c363175c85924cc90c2399acc47f4399d3741a3f2919f0415135653001a6` |
| Request frame | 5,165 bytes; `sha256:128374fde97b860e1fb5dea08837c19710907f95af12766ed37092ba02279a8d` |
| Host lifecycle evidence | `sha256:6d055a9c4f9f9ae940b9089cceffd8330b9e8bae646570ab325d68345500fe2e` |
| Host receipt | `sha256:4bd79f85b9c31b5ff6cb21494a056905f42dcb71ed7300336444132897ba8b07` |
| Sanitized serial | `sha256:f81fb31e732fd2fcd8c1c1c02a437f5367d134db6dc0c98616173782a062ea82` |
| Interruption | `host_write_half_close_after_request_header` |
| Transmitted prefix / guest response | `16` / `0` bytes |
| Guest receipt / guest evidence | absent / absent |
| Host terminal | `infrastructure_error_with_teardown` |
| VM stopped / clone destroyed | `true` / `true` |
| Execution authority / package execution / sync-back | `false` / `false` / `false` |

The signed guest image is byte-identical to the independently reproduced and verified image from
the background-listener checkpoint; only the host helper and therefore backend identity changed.
All 29 implemented cases then ran physically on this identity. All 87 downloaded request inputs
matched locally and every signed complete case passed the independent Rust verifier using pinned
guest and remote-host public keys. The restricted, gitignored sanitized 29-case archive contains
231 files and has SHA-256
`f8132eccb32232bf6200564e81e1b2622824455560c3c41beb900a6cce16dacd`.

## Boundary and next gate

This remains telemetry qualification, not package detection. No npm, PyPI, unknown, restricted, or
malware package code ran. The backend cannot issue package-execution authority. The next closed gate
is `vm_stop`.
