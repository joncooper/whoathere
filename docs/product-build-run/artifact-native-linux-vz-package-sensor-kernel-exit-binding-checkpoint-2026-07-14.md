# Artifact-Native Linux VZ Package-Sensor Kernel-Exit Checkpoint

Date: 2026-07-14

Status: BTF-bound raw kernel exit status physically qualified with an inert fixture on the approved
cloud Mac

## Outcome

The package-process sensor can now obtain the leader's raw Linux wait status independently from the
kernel and carry it through the fail-closed event decoder and process correlator. The final strict
inert run required the kernel-derived value to equal the protected probe's separate `waitpid`
result exactly.

The pinned kernel's ordinary `sched_process_exit` tracepoint does not publish an `exit_code` field.
The implementation therefore does not synthesize a value from the supervisor result or treat a
safe block as behavior evidence. Instead it:

1. reads and hashes the bounded runtime `/sys/kernel/btf/vmlinux` bytes;
2. strictly resolves the exact signed 32-bit `task_struct.exit_code` member;
3. loads a `BPF_PROG_TYPE_RAW_TRACEPOINT` program;
4. attaches it to `sched_process_exit` with `BPF_RAW_TRACEPOINT_OPEN`;
5. reads the field with `bpf_probe_read_kernel` only after the package-cgroup filter matches; and
6. emits the raw wait status in version two of the fixed 192-byte kernel-event record.

The final runtime BTF identity resolves `task_struct.exit_code` at byte offset `1964`. The guest
evidence and strict Mac verifier independently bind that exact digest and offset, the raw-tracepoint
attachment, the BTF field source, kernel wait status `0`, and `waitpid` wait status `0`. The existing
14-event credential/exec/loader-mmap/exit stream remained contiguous, with zero producer drops and
zero decoder discards.

This closes the kernel-exit primitive and its inert proof. It does **not** instantiate the
production root collector or reconcile this source with the real package supervisor yet. The July
malicious-package score remains **7/11 (63.6%)**.

## Safety boundary

No package or malware sample ran. The only executed guest payload was the previously qualified,
purpose-built inert fixture. The final run used a fresh disposable Linux VZ guest on the approved
cloud Mac with:

- no external route;
- no root disk or directory share;
- zero host raw frames;
- package execution reported false;
- malware execution reported false;
- sync-back reported false; and
- a stopped VM before the host verifier accepted the result.

Real malware remains restricted to the approved cloud Mac and may run only inside a fresh
disposable Linux VZ guest under the separate lab workflow. It must never run in this workspace, in
Docker, or on either Mac host.

## Fail-closed design

### Runtime BTF parser

The new parser accepts only bounded BTF v1 data and rejects malformed headers, string/type-section
overflow, unsupported member encodings, missing or duplicate `task_struct.exit_code` members,
bitfields, non-byte-aligned members, and types that do not resolve through the allowed qualifier or
typedef chain to a signed 32-bit integer. The BTF input is limited to 8 MiB and 262,144 types.

The producer retains both the BTF SHA-256 and the resolved byte offset. A changed kernel layout is
therefore explicit evidence, not an implicit host assumption.

### Raw tracepoint program

The exit program is separate from the four perf-tracepoint programs used for `fork`, `exec`,
`sys_enter`, and `sys_exit`. It filters on the held package cgroup before reading the task, uses the
raw tracepoint task pointer, and treats a failed kernel read or failed ring reservation as protected
loss. The event record is fully zero-initialized before its typed fields are populated.

The version-two exit record must contain exactly one result-present flag and one valid raw Linux
wait status. The decoder rejects legacy version-one records, missing results, negative or
out-of-range values, stopped/continued states, signals outside the supported kernel range, and
noncanonical high bits. Non-exit lifecycle records and syscall-enter records cannot carry this
field.

### Correlation and host evidence

The per-thread correlator retains the kernel wait status on the terminal lifecycle observation and
rejects a process finish while a selected syscall is pending. The inert probe requires the final
source event and final correlated lifecycle observation to carry the exact same raw status returned
by `waitpid`.

Canonical guest evidence schema v3 adds:

- `exit_attachment = raw_tracepoint:sched_process_exit`;
- `exit_status_source = runtime_btf:task_struct.exit_code`;
- `runtime_btf_sha256`;
- `task_exit_code_byte_offset`;
- `kernel_exit_wait_status`; and
- `waitpid_wait_status`.

The Mac verifier takes the expected fixture digest, runtime BTF digest, and task-field offset as
separate command-line expectations. It accepts only exact canonical JSON, exact keys and values,
equal wait statuses, the previous 14-event/loss contract, the no-execution safety markers, a stable
kernel/initramfs identity, zero raw frames, and a stopped VM.

## Physical qualification

The final exact-offset run exited `0` with canonical `status: "ok"`. It bound:

- runtime BTF SHA-256
  `d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb`;
- `task_struct.exit_code` byte offset `1964`;
- raw kernel wait status `0`;
- independent `waitpid` wait status `0`;
- source sequence `1..14`;
- cgroup ID `21`;
- zero dropped and discarded records;
- zero host raw frames; and
- a fully stopped disposable VM.

The canonical guest payload was 1,531 bytes. The final sanitized serial transcript was 2,379 bytes
with SHA-256
`54051a3807516e26148f65fe99e47fc92acf7de5d8ba8a8be154e6b56024d718`.

Exact final inputs were:

| Component | SHA-256 |
| --- | --- |
| Pinned Linux kernel | `8b216f74e7f89def4604adf69e2345437363aff4819101bb1551c9e83cd35cdd` |
| Base initramfs | `fc1aad923040d23bea79f62bef4a8e2481162e89a5c42245903df1a85134a527` |
| Guest init | `6f468789962fc6c7c49e4b6d38845597954b70c38a1b687258ac077b7657e9af` |
| Final static inert probe | `f79623a569207b44cbe93c8c7fc7d8b674a755f9083fee8d701178f079881554` |
| Previously qualified inert fixture | `c660520c04d3221694022f5546facf84a338982783d4d81ded75a7ae5165c0e6` |
| Canonical overlay CPIO | `1dd2d77141adfcdfa32af914e32741bb4387f9f7f96bb91516a3dc8259ec60d4` |
| Deterministic gzip overlay | `a3b55105f3495b3c9d7635dd3ebf72d2fd4fc5f75a4700b162de6b615c5d2811` |
| Combined qualification initramfs | `b39a7fb01842e0214c1a8ee0ba64687580f51df7bdd817b3690612248fe0bf8c` |
| Strict exact-offset Mac verifier | `07aa7bd21216200131e8cf7675e985f6be925455d20b435e0a3c843b1eadefea` |

The overlay CPIO was 1,027,584 bytes, its deterministic gzip was 536,497 bytes, the combined
initramfs was 10,685,456 bytes, and the final static probe was 653,328 bytes.

## Falsification and correction history

Three failed-closed runs materially improved the result:

1. The first implementation required an `exit_code` field in the ordinary tracepoint format. The
   pinned kernel proved that assumption false and stopped before fixture execution. This led to the
   raw-tracepoint plus runtime-BTF design.
2. A locally rebuilt static fixture produced only eight events because it had no runtime-loader
   `mmap` calls. A subsequent dynamic rebuild produced ten events. Both were correctly rejected by
   the existing exact 14-event contract.
3. Reusing the exact previously qualified fixture restored the same three loader `mmap` pairs and
   allowed the kernel-exit change to be evaluated without changing the test input.

None of these runs used package or malware code. No failed run was relabeled as a detection or a
successful qualification.

## Validation

- Package-sensor Rust library suite: 184 passed.
- Complete Rust workspace test suite, including local fake-server loopback cases: passed.
- Swift helper suite: 200 passed.
- Native package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Linux/aarch64-musl package-wide `cargo clippy --all-targets -- -D warnings`: passed.
- Static aarch64-musl release probe build through `cargo zigbuild`: passed.
- Release Mac verifier build, ad-hoc virtualization-entitlement signing, and strict signature
  verification: passed.
- Exact-offset physical inert qualification: passed.
- Formatting and `git diff --check`: passed.

Key tracked source identities are:

| Source | SHA-256 |
| --- | --- |
| Runtime BTF parser | `60d86e948e772d1233fdf9edd66a4f8338b636fd89f1f0ca766d3aaf75932f7d` |
| BPF producer and raw-exit program | `b76839c1c1519a3852419b9d744033b772ebabf2876f0bec9bfbfa0257d0a41b` |
| Kernel event decoder | `7dc487a7a7569d78b7346f0d6229a1e6055f31d0ab66162695f1e83c1d4e543f` |
| Per-thread process correlator | `a8dd16ae004735382e2236d1ea1b4e64016dcf05e60df4355e325f9e4d676364` |
| Inert qualification probe | `c4bf0a678efdc68f862e3ff45a46f4fcb95f3bf1b0476c0d005932e5ead6430d` |
| Strict Swift evidence decoder | `9a2effcf3d4a5b4c647aef1f31d95a56e7c8833efa46d224df570bcdd13ab1a6` |
| Strict Mac verifier | `f86c88700e524898592492824414a644fda6379c9b3ccf253426f58c57f32ca5` |
| Swift decoder tests | `0b15801500bda9b8a53d6547fe6dceb21662f0608bbc42f874a6427e579a779d` |
| Cargo lock | `0635890ecb3d8b03c683983b3799e2a8fd6aa6252eb914b6e0cc227804f85b93` |

## Remaining integration gaps

The next highest-leverage slice is still the production root collector. It must own this BPF
producer and ring-buffer consumer, feed the fail-closed correlator, derive typed process evidence,
and require the supervisor completion and kernel wait status to agree. Either missing source,
status disagreement, loss, or unfinished syscall pairing must make coverage incomplete.

After that, the protected service still needs fanotify/file collection and a post-run filesystem
diff, physical `connect`/`sendto` qualification and host-frame correlation, a signed
`EvidenceEnvelope`, complete runtime integration, inert npm/wheel/sdist scenarios, benign controls,
known-malware regression, and held-out gates. Known-malware regression remains cloud-Mac-only in
fresh disposable Linux VZ guests.
