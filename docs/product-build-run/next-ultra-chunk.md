# Next Ultra Chunk: P07 One-Command Inert End-to-End Demo

Status: complete. P06 is complete and pushed at `fa6fc4c`; the final P07 implementation passed one
fresh uninterrupted default invocation on 2026-07-18. R01 is next but remains outside the current
P04-P07 goal.

Updated: 2026-07-18

## Immutable execution contract

- Branch: `codex/p07-inert-end-to-end-demo`, based on accepted P06 commit `fa6fc4c`.
- Budget: 2-4 hours of focused implementation, excluding one independent final verification.
- The read-only Ultra input audit is complete. It selected a thin two-host orchestration script
  around existing production commands; no new Rust, VM protocol, evaluator, evidence signer,
  profile subsystem, or remote-execution framework is permitted.
- Use the already-qualified Linux VZ runtime and helper. Only a fresh no-closure detonation
  configuration and fresh output locations may be staged on the approved cloud Mac.
- At four focused implementation hours, preserve the exact blocker and stop rather than expanding
  the architecture.

Primary metric: one local command performs preflight, exact-artifact static inspection, both fresh
npm VM profiles, sanitized export, local subscription-backed Codex observation, cross-host
reconciliation, and a concise human result.

P07 proves a usable end-to-end product path. It does not change the finalized July experimental
baseline of 7/11 and is not a claim-bearing evaluation result.

## Accepted result

- The final bounded operator command composes P06, exact-artifact inspection, both npm CI profiles,
  strict sanitized export, local subscription-backed Codex observation, cross-host reconciliation,
  and the final human transcript. Focused hermetic tests exercise that default path.
- Exact artifact digest:
  `sha256:6d487f71d980a0ab8dc4aab303f99f9576e3d335d7cef3ab88463e87e41168ff`.
- `CI=false` produced 20 typed events and one Codex lifecycle finding with an exact event-hash
  citation.
- `CI=true` produced 24 typed events, including three authenticated fake-token canary reads and a
  local-sinkhole connection. Codex cited lifecycle, canary access, and the outbound connection.
- Both VM/profile rows bind execution-result, root-receipt, host-receipt, bundle, and observer
  identities. Both VMs stopped, both clones were destroyed, images remained stable, no public route
  or sync-back existed, and all six canonical safety-invariant counts were zero.
- Coverage remained incomplete; the result was `BLOCK`, diagnostic-only, observe-only, and never
  clean, admitted, installed, or allowed.
- The focused fake-runner suite covers preflight-before-execution, digest substitution, transfer
  allowlisting, profile/bundle cardinality, safety proof, citation integrity, and transcript
  redaction.
- The first physical attempt preserved evidence but stopped at a stale remote exporter that did not
  understand the sanitizer's typed static citation. One bounded repair staged the already-tested
  current exporter and refreshed P06. The next remote run completed both VM profiles and the strict
  export, then exposed two wrapper-only assumptions—requiring a post-connect send event and
  rejecting the observer's valid exit 0. After those corrections, local observation,
  reconciliation, and transcript generation completed through the earlier resume path. The final
  explicit producer-plan-bound resume and remaining digest joins were implemented afterward.
- A new final invocation then ran the default command from fresh P06-bound remote and local roots.
  It completed preflight, both VM profiles, export, both Codex observations, reconciliation, and
  transcript generation in one process with `Execution mode: fresh end-to-end invocation`.

The final command is therefore physically accepted. The earlier resumed attempt remains recorded as
qualification history rather than being substituted for the final result.

## Canonical inert artifact

Use the tracked deterministic fixture builder to produce exactly:

```text
whoathere-fixture-npm-ci-canary-1.0.0.tgz
sha256:6d487f71d980a0ab8dc4aab303f99f9576e3d335d7cef3ab88463e87e41168ff
```

The artifact has no dependencies and no publication authority. Its postinstall lifecycle code:

- records an inert package-written marker in both CI profiles;
- only under `CI=true`, reads the runtime's seeded fake npm-token file;
- only under `CI=true`, connects to `127.0.0.1:48739` and sends a constant inert marker;
- never sends canary bytes, reaches a public destination, fetches a second stage, or writes outside
  the disposable guest workspace.

Package-written markers are supporting-only. They cannot establish a behavior detection, evidence
authenticity, safety, or clean status.

## User-facing command

```text
scripts/whoathere-inert-e2e-demo.py \
  --input <absolute-private-p07-plan.json> \
  --input-sha256 sha256:<exact-plan-digest> \
  --ssh-config <absolute-private-ssh-config>
```

The command returns success only when the complete demo and all bindings validate. Its displayed
package action is `BLOCK` or `REVIEW`; operational success never means `ALLOW`, clean, admitted, or
safe to install.

## Closed private plan

Schema: `whoathere.inert_e2e_demo_input.v1`. Unknown fields are rejected.

The plan binds:

1. `demo`: one bounded demo ID, the exact artifact filename, byte length, and SHA-256.
2. `preflight`: the P06 implementation, exact private P06 input, detached input digest, and expected
   campaign/profile identity.
3. `remote`: SSH alias plus exact absolute paths and SHA-256 identities for the staged artifact,
   WhoaThere binary, no-closure detonation configuration, sanitizer, fresh state/output/export
   roots, and approved remote Python interpreter.
4. `local`: exact WhoaThere binary and native Codex client identities, exact model, dedicated
   subscription-authenticated auth home, timeout, and a fresh ignored output root.
5. `policy`: both required profiles, loopback sinkhole destination, hosted-behavior-review approval,
   no raw export, no remote AI/auth, no sync-back, and no admission authority.

The plan contains no password, private key, canary value, API key, raw telemetry, or restricted
artifact path. Input and SSH files remain ignored and mode-private.

## Existing stages to compose

The wrapper performs only this sequence:

1. Run `whoathere-cloud-lab-preflight.py` and require fresh `READY` for the exact no-closure config.
2. Over the pinned SSH route, re-hash the staged inert artifact and bound executables/configuration,
   require all fresh output paths to be absent, then run the existing remote production command:

   ```text
   whoathere artifact inspect <exact-inert.tgz> \
     --ecosystem npm \
     --state-dir <fresh-private-state> \
     --detonation \
     --detonation-config <exact-no-closure-config.json>
   ```

3. Reuse `sanitize_exact_artifact_report()` from the existing Step 5 harness, then run
   `whoathere-export-split-behavior.py` remotely.
4. Transfer only the sanitized report, export manifest, two typed behavior bundles, and a bounded
   safety projection. Artifact bytes, source, raw receipts, raw streams, packet captures, logs,
   canary values, Codex credentials, and private remote paths do not cross hosts.
5. Run local `whoathere behavior observe` once for each exact bundle with the saved subscription,
   native Codex client, exact client digest, exact model, empty private work state, hosted review
   explicitly approved, and no web or tools.
6. Run `whoathere-two-host-behavior-diagnostic.py` to recheck artifact, manifest, scenario, bundle,
   observer, finding, and event-citation continuity.
7. Render one concise transcript from the validated diagnostic and safety projection.

No Codex binary or authentication material is installed or copied to the cloud Mac.

## Safety proof and transcript contract

The remote projection is allowlisted and bounded. For both `CI=false` and `CI=true`, it binds the
exact execution result, behavior bundle, root receipt, and host-composite receipt and reports:

- VM started and stopped;
- clone destroyed;
- image identity stable;
- public route absent;
- sync-back false;
- authoritative verdict false;
- package execution occurred only through the Linux VZ guest provider; and
- coverage limitations remain explicit.

The final transcript contains:

- `BLOCK` or `REVIEW`, never `ALLOW` or clean;
- exact artifact, manifest, scenario-plan, detonation-result, bundle, observer-result, root-receipt,
  and host-receipt digests;
- distinct `CI=false` and `CI=true` rows;
- authenticated lifecycle evidence in both profiles;
- protected fake-canary-file access and local-sinkhole connection intent, with send activity shown
  when observed;
- Codex findings with exact event-ID and event-hash citations;
- package-written marker evidence labeled supporting-only;
- incomplete coverage and no installation, containment, admission, or sync-back authority; and
- the canonical invariant counts: zero host package executions, sync-backs, unsafe allows,
  restricted-material leaks, live-C2 contacts, and live second-stage fetches, with receipt refs.

Because the artifact is wholly inert and contains no restricted material, the restricted-material
count is zero by construction as well as by export policy. A public route is absent, so the fixed
loopback sinkhole cannot become live C2.

## Frozen acceptance criteria

1. One documented local command completes the existing finite npm CI-paired workflow.
2. P06 failure, plan mismatch, artifact/config/tool digest mismatch, or non-fresh output prevents
   artifact execution.
3. Exactly two fresh VM profiles and two report-bound bundles validate; missing, duplicate, extra,
   or mismatched profiles/bundles fail.
4. Exact artifact and manifest identities remain continuous through static analysis, scenario,
   detonation, bundles, Codex results, reconciliation, and transcript.
5. Typed lifecycle evidence appears in both profiles. Protected canary-file access plus local
   sinkhole connection intent appears in `CI=true`; send activity is displayed when observed.
6. Every displayed Codex citation resolves to an exact verified event ID and event SHA-256. Codex
   cannot change containment, evidence authenticity, admission, or the safety result.
7. Both VMs stop, both clones are destroyed, both image identities remain stable, no public route
   or sync-back exists, and all canonical invariant counts are zero with receipt references.
8. The package-written marker remains explicitly supporting-only. Incomplete coverage without a
   validated positive produces `REVIEW`; incomplete coverage never produces clean or allow.
9. Only the strict sanitized export and bounded safety projection cross from cloud to local. No
   artifact/source bytes, raw telemetry, raw receipts, logs, canary values, private paths, or remote
   Codex/auth invocation occur.
10. The final transcript contains no secret, canary value, IP address, SSH detail, private path, or
    untrusted package prose and is suitable for README/portfolio publication.

## Required checks

- Focused fake-runner self-test for orchestration, fail-before-execution, digest continuity,
  profile cardinality, safe transfer allowlist, citation validation, safety proof, and transcript
  redaction.
- Existing fixture-builder/sealed-digest check.
- Existing exporter, two-host diagnostic, and behavior-observer focused tests.
- Python compilation, `git diff --check`, and secret/private-path scan.
- One physical run on the approved cloud Mac using only the canonical inert fixture.
- One independent Ultra verification after the physical transcript is sanitized.

## Stop and parking rule

After one bounded operational repair, park P07 and record the exact blocker if:

- refreshed P06 is not green;
- the canonical fixture cannot bind the no-closure config;
- either VM lacks teardown or safety proof;
- lifecycle or required CI=true sinkhole/canary evidence is absent;
- the sanitized export cannot reconcile exactly;
- local Codex authentication/model readiness fails twice; or
- success would require a new sensor, runtime, evaluator, P05 renderer, profile subsystem, or remote
  execution framework.

Once the physical transcript passes, stop. P07's job is the working demo; R01-R06 are the next
claim-bearing work.
