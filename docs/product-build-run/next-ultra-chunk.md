# Next Ultra Chunk: P06 Cloud-Lab Ready/Not-Ready Preflight

Status: complete. P05 is complete and pushed at `da2f9a7`; P06 is accepted locally and must be
pushed before P07 starts.

Updated: 2026-07-18

## Immutable execution contract

- Branch: `codex/p06-cloud-lab-preflight`, based on accepted P05 commit `da2f9a7`.
- Budget: 1-2 hours of focused implementation, excluding independent verification.
- One read-only Ultra input audit and one final independent Ultra verification are allowed.
- The input audit found that no existing command satisfies P06: the older preflight can report
  ready while leaving operator checks unresolved, while the staging/clearance harnesses mutate
  remote state or depend on prior restricted-corpus state.
- Implement one thin Python operator command and one focused self-test. Do not add a Rust CLI
  subsystem, new VM protocol, new evidence signer, or general remote-execution framework.
- At two focused implementation hours, push a safe WIP reproduction and stop rather than expanding
  scope.

Primary metric: one command returns either green `READY` or exactly one precedence-ranked
`BLOCKED` result with one concrete operator action, before any artifact access or VM start.

## Accepted result

- The final production command returned `READY` on the approved cloud Mac for exact inert campaign
  `p07-inert-npm-demo-20260718` and profile `npm-ci-paired`.
- The exact input digest was
  `sha256:5fe0ae9496f4d7eaf16c365cf83005ca243b80f9505b8aee15f8de76e1e96309`.
- The preflight implementation digest was
  `sha256:04bec519c44102c369f3bea5d45b645688b1622dde0004904633e2b946e86007`.
- The result recorded `artifact_opened=false`, `package_executed=false`, `vm_started=false`,
  `remote_state_mutated=false`, and `clearance_consumed=false`.
- The focused production-path self-test passed. Independent Ultra verification returned GO after
  its route/output mutations and all discovered must-fix regressions failed closed.
- No raw or restricted artifact was opened, no package code executed, and no VM started during P06.

## User-facing command

```text
scripts/whoathere-cloud-lab-preflight.py \
  --input <cloud-lab-preflight-input.json> \
  --input-sha256 sha256:<exact-input-digest> \
  [--ssh-config <local-ssh-config>] \
  [--json]
```

Exit codes:

- `0`: `READY`;
- `20`: valid plan, one operational blocker; and
- `64`: malformed, mismatched, unsafe, or unsupported input.

Human output contains one status headline and, when blocked, exactly one `ACTION:` line. JSON output
contains the same single blocker/action plus safe identity bindings and explicit non-execution
flags.

## Closed input contract

Schema: `whoathere.cloud_lab_preflight_input.v1`.

The exact top-level sections are:

1. `ssh`: safe host alias, expected remote hostname and user, and a non-secret source-route
   reference.
2. `authorization`: provider, legal, and operator authorization references plus
   `planned_material`, either `inert_only` or `restricted_malware`.
3. `provider`: provider name, exactly one firewall posture (`cloud_default_deny` or
   `provider_unavailable_host_pf`), and its evidence reference.
4. `run_binding`: exact remote checkout path and Git commit, campaign ID, profile ID, and six
   ordered remote file identities: `whoathere_bin`, `vm_helper`, `runtime_record`,
   `detonation_config`, `policy`, and `sanitizer`.
5. `host_controls`: exact fresh PF-info, PF-rules, and LuLu-evidence file paths/digests; loopback-only
   sinkhole host/port/reference; and the maximum evidence age.
6. `storage`: exact custody, evidence, sanitized-export, and ephemeral-clone directory paths.
7. `clearance`: `not_required_inert` with no path/digest, or `required_restricted` with an exact
   clearance path/digest and latest-contamination timestamp.

All objects are closed. Digests are canonical lowercase SHA-256 values; IDs/references are bounded
safe tokens; paths are absolute remote paths. The plan contains no sample, package, artifact,
archive, workspace, credential, canary, or secret path/value.

## Probe boundary

After local exact-digest/schema validation and authorization checks, the command performs only:

1. local `ssh -G` resolution for the intended host alias; and
2. exactly one noninteractive SSH invocation of `/usr/bin/python3 -`, sending a fixed read-only
   probe over stdin and receiving one bounded JSON object on stdout.

The remote probe may:

- compare remote hostname/user and confirm an SSH session;
- hash the six allowlisted identity files;
- read the exact PF/LuLu control evidence files and verify freshness;
- verify PF enabled/default-deny and LuLu enabled/filtering posture;
- connect only to the configured loopback sinkhole;
- check Apple Virtualization framework availability;
- `stat` custody/evidence/sanitized/clone roots without listing custody contents;
- check fixed WhoaThere helper/process names and require the ephemeral-clone root to be empty; and
- for restricted material only, open and validate the exact clearance record.

It may not upload or create files, make directories, alter permissions, invoke `sudo`, stage a
bundle, list/open artifact custody contents, inspect a package, run scanners, call WhoaThere,
start/stop a VM, consume clearance, contact a non-loopback destination, or write evidence remotely.

## Blocker precedence

The command exposes only the first failed condition in this fixed order:

1. invalid input/detached digest (`ERROR`, no SSH);
2. missing authorization or provider-firewall posture (`BLOCKED`, no SSH);
3. SSH configuration/route or bounded probe failure;
4. remote hostname/user/session mismatch;
5. code, helper, runtime, configuration, policy, or sanitizer identity mismatch, in that order;
6. stale/invalid PF evidence or PF not enabled/default-deny;
7. stale/invalid LuLu evidence or LuLu not enabled/filtering;
8. loopback sinkhole unavailable;
9. Apple Virtualization unavailable;
10. custody/evidence/sanitized storage missing, unsafe, or unusable;
11. stale WhoaThere process or nonempty ephemeral-clone root; and
12. required clearance missing, mismatched, stale, consumed, or not ready.

Each blocker has one stable reason code and one bounded action sentence. Other failed conditions are
not listed in human output; the operator fixes the named blocker and reruns.

## Frozen acceptance criteria

1. A complete synthetic plan through a fake SSH route produces `READY`, exit 0, exact bindings, and
   `artifact_opened=false`, `package_executed=false`, `vm_started=false`,
   `remote_state_mutated=false`, and `clearance_consumed=false`.
2. Missing authorization blocks before either SSH invocation.
3. Exactly one `ssh -G` and one read-only remote probe occur on the ready path; no `scp`, remote
   write, WhoaThere command, scanner, package, or VM command occurs.
4. Every required code/runtime/policy identity matches its exact digest or the first mismatch is the
   sole blocker.
5. PF, LuLu, sinkhole, VZ, storage, stale process/clone, and clearance checks follow the fixed
   precedence and yield one actionable result.
6. `inert_only` requires explicit not-applicable custody/clearance posture; `restricted_malware`
   requires a fresh exact clearance and authorization references. Neither mode accesses artifacts.
7. Unknown, missing, duplicate, unsafe path, non-loopback sinkhole, malformed digest, symlink,
   oversized, truncated, trailing-data, route/probe spoof, extra-output, timeout, and identity
   substitution inputs fail conservatively without echoing untrusted values or paths.
8. JSON and human modes agree on status, exit, blocker, bindings, and non-execution flags.
9. The command never reports general malware readiness; it is bound to one exact
   host/code/runtime/policy/campaign/profile plan.
10. No credentials, IP addresses, private SSH configuration, raw control output, restricted paths,
    or ignored lab files enter git.

## Required checks

- Focused ready-path self-test using temporary inert files, a loopback sinkhole, and fake SSH.
- One-at-a-time blocker tests for pre-SSH authorization, route, identity, PF, LuLu, sinkhole,
  storage, stale clone, and restricted-clearance failures.
- Closed-schema/digest/path/output/timeout mutation tests.
- Shell/Python compilation checks and `git diff --check`.
- Existing Scaleway staging/phase-1 self-test only if P06 changes a shared existing helper; otherwise
  P06 must not broaden into that harness.
- Independent Ultra verification before commit or push.
- One actual approved cloud-Mac run may return `READY` or one exact blocker. It must use an inert-only
  plan, perform no repair beyond one bounded operator action, and never access a package or start a
  VM.

## Stop and parking rule

Park P06 if the host cannot provide fresh PF or LuLu evidence without mutation, SSH cannot run the
single read-only probe, or the exact P07 runtime/helper/config identities are not yet available.
Record the first blocker and smallest operator action. Do not weaken a required check, fall back to
assertion-only readiness, touch the restricted corpus, or begin P07.
