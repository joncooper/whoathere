# P06 Cloud-Lab Preflight Product Report

Status: accepted on 2026-07-18.

## Outcome

WhoaThere now has one read-only operator command that answers a narrow question before cloud-lab
work begins: is this exact host, code/runtime/policy bundle, campaign, and profile ready, or what is
the single next action?

```text
scripts/whoathere-cloud-lab-preflight.py \
  --input <private-exact-plan.json> \
  --input-sha256 sha256:<exact-plan-digest> \
  [--ssh-config <private-ssh-config>] \
  [--json]
```

The outcomes are deliberately small:

- exit `0`: `READY` for that exact plan;
- exit `20`: one precedence-ranked `BLOCKED` result and one `ACTION:`; or
- exit `64`: malformed, mismatched, unsafe, or unsupported input reported as `ERROR`.

It does not report general malware readiness and does not authorize execution.

## Production proof

The final implementation was run against the approved cloud Mac with an inert-only P07 plan. It
returned `READY` and bound:

- input digest
  `sha256:5fe0ae9496f4d7eaf16c365cf83005ca243b80f9505b8aee15f8de76e1e96309`;
- preflight implementation digest
  `sha256:04bec519c44102c369f3bea5d45b645688b1622dde0004904633e2b946e86007`;
- the exact remote Git commit, six ordered code/runtime/policy identities, campaign, profile, and a
  privacy-safe host identity digest; and
- `artifact_opened=false`, `package_executed=false`, `vm_started=false`,
  `remote_state_mutated=false`, and `clearance_consumed=false`.

The private input, SSH configuration, control records, and complete result remain ignored under
`.whoathere/`. No IP address, credential, private path, raw control output, artifact byte, or
restricted telemetry is tracked here.

## What the command checks

The command first validates a private, closed, exact-digest input. It then performs local SSH route
resolution and exactly one fixed, noninteractive read-only probe. The probe verifies, as applicable:

- remote host/user/session identity;
- exact Git, CLI, helper, runtime-record, detonation-config, policy, and sanitizer identities;
- reboot-current PF and LuLu evidence, default-deny posture, and the approved loopback sinkhole;
- Apple Virtualization, hypervisor, and logged-in GUI prerequisites;
- private writable custody/evidence/export/clone storage;
- absence of stale WhoaThere helpers or disposable clones; and
- exact restricted clearance, freshness, and the existing exclusive consumption marker.

It never invokes WhoaThere, a scanner, a package manager, `sudo`, or a VM. It does not upload,
stage, create, remove, or modify remote files, and it never lists or opens artifact custody.

## Verification

The focused production-path self-test covers the ready path, pre-SSH blockers, fixed precedence,
attempt-one parking, human/JSON consistency, strict input/probe types, identity substitution,
clearance applicability, and conservative non-execution flags.

Independent Ultra verification returned GO after:

- a 13-case route, output, input, identity, path, and sinkhole mutation pass failed closed;
- five targeted regressions for discovered contract defects failed closed;
- static inspection confirmed the fixed remote probe contains no remote write or mutation calls;
  and
- Python compilation, the focused self-test, and `git diff --check` passed.

The review materially improved the production boundary: it corrected restricted-clearance
applicability and consumption, falsey type confusion, forged host identities, aliased runtime
roles, boolean attempt values, error rendering, and evidence surviving a reboot.

## Claim boundary and next step

P06 proves plan-specific operability and safety before execution. It does not improve the finalized
July 7/11 malware baseline, certify a package as clean, or grant restricted-material access.

P07 subsequently used a freshly rebound green plan to run a wholly inert package through one
documented static-analysis, disposable-VM, telemetry, Codex-observer, and human-report command. See
the [P07 product report](inert-end-to-end-demo-product-report.md).
