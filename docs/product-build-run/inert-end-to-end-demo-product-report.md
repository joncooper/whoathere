# P07 Inert End-to-End Product Demonstration

Status: accepted diagnostic product result
Date: 2026-07-18
Scope: canonical inert npm artifact; no restricted malware

## Outcome

WhoaThere now has one bounded operator command that composes the working product spine:

```text
exact artifact
  → deterministic analysis
  → two fresh Linux VZ profiles
  → typed behavior evidence
  → sanitized cross-host export
  → local subscription-backed Codex observation
  → exact citation reconciliation
  → human BLOCK/REVIEW report
```

The accepted final invocation completed in one uninterrupted default command and produced `BLOCK -
suspicious package capability and behavior observed in disposable VM`. It ran P06, both fresh VM
profiles, strict export, local Codex observation, reconciliation, and transcript generation without
using the resume or repair path. It is a diagnostic result, not a malware benchmark, clean verdict,
or installation decision.

## User command

```sh
scripts/whoathere-inert-e2e-demo.py \
  --input /private/path/p07-demo-plan.json \
  --input-sha256 sha256:<exact-plan-digest> \
  --ssh-config /private/path/ssh-config
```

The private closed plan binds the exact P06 input, SSH alias, artifact, cloud binary and
configuration, sanitizer/exporter, local WhoaThere and native Codex clients, subscription model,
auth home, and fresh output roots. It contains no password, private key, canary value, API key, or
raw telemetry.

## Exact result

| Binding | Value |
| --- | --- |
| Artifact | `sha256:6d487f71d980a0ab8dc4aab303f99f9576e3d335d7cef3ab88463e87e41168ff` |
| P07 input | `sha256:4449d0e1d9c1cfdca19e4fcfed737ca39587f4fde54ea2ae443710bb2403dd21` |
| Manifest | `sha256:7c0fe228c14e7d3be6b3cdaffe43c975a619c59fbd77d1443229737fb9c2d65b` |
| Scenario plan | `sha256:3714e86d74c7163e12a938b913f91c1a82ebcb1c7868d1106683878f83ea3be4` |
| Detonation result | `sha256:d77c06a967ec5ce064e4a334fe054f689e781ec543180fea289632abb621b269` |
| Remote result | `sha256:ccab53f136f2e6b6b5b140a25090b9e9330e495abff46900a3ec6b1a5d715a59` |
| Reconciliation | `sha256:5efdc742ed88ce4b11834e2d8235be4c5c2ae2395d4a1ad43cef55f6d0370f3b` |
| Transcript | `sha256:53113f027cd9c6a3f72faadd438c3d6838a6dc4cba34f16300502788430c77fb` |
| Artifact form | deterministic no-dependency npm tarball |
| Profiles | `CI=false`, `CI=true` |
| Result | `BLOCK`; diagnostic only; incomplete coverage |

### Profile evidence

| Profile | Typed events | Observed behavior | Codex result |
| --- | ---: | --- | --- |
| `CI=false` | 20 | npm lifecycle trigger | lifecycle-trigger execution, cited to the exact typed event |
| `CI=true` | 24 | npm lifecycle trigger, three protected fake-token canary reads, local-sinkhole connection | lifecycle trigger, canary access, and outbound connection, each cited to exact typed events |

The reconciler retained `CI=false` as `behavior_observed` with no detection-eligible behavioral
finding and `CI=true` as `behavior_detected` with one eligible canary-access finding. P07 is a
product demonstration, so these rows are not scored as a benchmark.

`CI=false` bundle:
`sha256:99417c366392a623891df2ebf35d7659ddb4ed432ab9166dd22ea91f97a650a8`.

`CI=true` bundle:
`sha256:430970d53af26ed1fd511a1b8afc89ad5bb509594e1f84263dd27d87ed7c226d`.

The package-written fixture marker remains supporting-only. It did not authenticate evidence or
drive the result. Network evidence establishes local connection intent, not payload contents or
credential exfiltration.

## Trust split

- The cloud Mac received the sealed inert artifact and executed it only inside fresh Linux VZ
  guests.
- The local Mac received only the strict sanitized report, two typed bundles, and a bounded safety
  projection.
- Raw receipts, raw event streams, packet captures, logs, package source, artifact bytes, canary
  values, and private remote paths did not cross to the local Mac.
- The cloud Mac received no Codex executable, subscription authentication, API key, or prompt.
- Codex was observe-only. Deterministic collectors and receipt checks remained authoritative for
  evidence and containment.

## Safety result

Both profiles recorded VM start and stop, clone destruction, stable image identity, absent public
route, absent sync-back, and no authoritative verdict permission. Each profile binds its execution
result to root and host-composite receipt digests.

The split export carries receipt references, not the underlying signature material. The cloud-side
projector verified the exact execution inputs before exporting those references, but the local
snapshot remains diagnostic rather than independently producer-authenticated or claim-bearing.

| Canonical invariant | Count |
| --- | ---: |
| Host package executions | 0 |
| Sync-backs | 0 |
| Unsafe allows | 0 |
| Restricted-material leaks | 0 |
| Live-C2 contacts | 0 |
| Live second-stage fetches | 0 |

The restricted-material count is zero by construction: this demonstration used only a tracked,
deterministically generated inert fixture.

## Sanitized transcript summary

```text
BLOCK - suspicious package capability and behavior observed in disposable VM
P07 inert end-to-end demonstration: complete (diagnostic only; not a malware benchmark)
Execution mode: fresh end-to-end invocation

CI=false
  typed events: 20
  lifecycle: observed and receipt-bound
  protected fake-canary access: not observed
  local-sinkhole network intent: not observed
  Codex: lifecycle_trigger_execution with exact event-hash citation

CI=true
  typed events: 24
  lifecycle: observed and receipt-bound
  protected fake-canary access: three authenticated open/read events
  local-sinkhole network intent: one typed connection event
  Codex: lifecycle_trigger_execution, outbound_connection, and canary_access,
         each with exact event-hash citations

Coverage: incomplete; never interpreted as clean
Safety: six canonical invariant counts are zero with receipt references
Package-written fixture markers: supporting-only
Authority: Codex is observe-only; no install, containment, admission, allow, sync-back, or clean authority
```

## Qualification notes

The orchestration failed closed during qualification and exposed two narrow integration
assumptions:

1. The initially staged exporter predated the sanitizer's typed static citation field. The already
   tested current exporter was staged, rebound through P06, and used with fresh output paths.
2. The first wrapper expected both connect and post-connect send events and scorer-style process
   exits from the observer. The actual evidence honestly contained a local connection but no send,
   while the observe-only CLI correctly returned exit 0. The wrapper now preserves exactly what was
   observed and leaves behavior eligibility to the existing verifier.

The first remote VM/export success was retained after these failures, and that historical attempt
finished through the earlier resume path. The final implementation now identifies resume mode,
binds the remote result to the exact P07 input, and rejects extra fields or substitutions in
scenario, detonation, execution-result, receipt, observer, bundle, or file identities. After those
changes passed the hermetic suite, a new fresh default invocation physically exercised the final
path without using resume and produced the accepted result above.

No raw evidence format, VM runtime, sensor, containment control, evaluator, or admission policy was
weakened to complete P07.

## Claim boundary and next step

P07 demonstrates that the product stages work coherently end to end and physically qualifies the
bounded operator command. It does **not** change the finalized July restricted-malware baseline of
7/11, establish a claim-bearing 4/4 result for the previous misses, measure benign friction, or
show broad malware coverage.

R01 subsequently froze the separate positive-only four-miss subscore contract, and R02 proved its
4/4 detection, 0/4 completion, and overall-false semantics through the signed metadata path. Both
were synthetic or metadata-only. R02b is next: freeze the exact final tool and evaluation identities
before any restricted row is collected.
