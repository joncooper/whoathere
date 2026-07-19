# Next Ultra Chunk: R03 Restricted-Lab Preflight Refresh

Status: ready after R02b. Do not begin R03 automatically.

Updated: 2026-07-19

## Accepted R02b result

R02b produced one immutable metadata-only collection identity for the four previous misses:

- active contract: `four-known-miss-positive-subscore-contract.v2.json`;
- source revision: `29c7a9bc7f4fd79478fa0ef7192e9f509be05e45`;
- exact four-row corpus:
  `sha256:e848f51878c8fe89ece0876a4ae7c07a88416a36decb29a3354725f49ea06819`;
- exact verifier executable:
  `sha256:d51431a2e08f74fb008988d8e8e24cca8e43873b06ae530e4d9e9cc834a2de33`;
- verifier public key:
  `sha256:85500877dd142794fd7beea871e0eaffb67ec0a4ec07670246ae5403d5036197`;
- combined projection schema:
  `sha256:2785f493cd0ddf4ad3f99124344c40180e7d9c1f4fbf4c182c27fe547f5c377a`;
- collection lock:
  `sha256:32f96202ca0a6d524c291c339e5aba35cd5acdc92b11f465b4caed5a47e6d928`;
- EvaluationManifestV2:
  `sha256:53db45466a91cbaeab6db51039cd515e292291a84f6056b3638f508e39f0dee2`;
- collection window: `2026-07-19T02:00:00Z` through `2026-08-18T23:59:59Z`;
- result-to-registry maximum: 600 seconds.

Contract v1 remains historical and byte-identical. Contract v2 explicitly permits deterministic
`sensitive_file_exfiltration_capability -> sensitive_file_exfiltration` for npm and deterministic
`download_execute_capability -> second_stage_fetch` for all three Telnyx rows. One combined schema
identity supports both closed projection kinds.

The current synthetic proof remains detection `4/4`, safety `4/4`, completion `0/4`, and
`overall_passed=false`. R02b collected no package or evidence bytes and ran no package, VM,
network, cloud, or AI workload. Real publication therefore remains `0/4`, and the finalized July
experimental baseline remains `7/11`.

## R03 frozen user outcome

A single read-only preflight returns `READY` for the exact R02b identity on the approved cloud Mac,
or `BLOCKED` with one concrete operator action, before any retained artifact is opened.

Primary metric: one current preflight result binds the cloud host, route, legal/provider posture,
containment controls, restricted custody, R02b source revision, exact verifier/key/schema/corpus,
and EvaluationManifestV2.

Budget: 1-2 focused hours. Stop before R04.

## Inputs

- The tracked R02b lock, manifest, receipt, corpus metadata, combined schema, and public key.
- The ignored exact verifier and campaign private key created by R02b.
- The existing P06 read-only cloud-lab preflight command and approved SSH configuration.
- Fresh explicit user authorization for the restricted lab check.

No R02b-bound tool, policy, contract, corpus, key, verifier, schema, or collection-window change is
allowed. A required change invalidates the freeze and returns to a new R02b version.

## Acceptance

1. The tracked freeze re-verifies byte-for-byte from the current branch.
2. The local ignored verifier and key match the frozen executable and public-key digests.
3. The read-only cloud preflight binds the exact R02b manifest and reports either:
   - `READY`, with all required route, host, firewall, LuLu, sinkhole, VZ, storage, custody,
     clearance, stale-state, and identity checks green; or
   - `BLOCKED`, with one precedence-ranked reason and one concrete operator action.
4. No retained package is opened, copied, unpacked, inspected, or executed.
5. No VM starts, no cloud state mutates, no clearance is consumed, and no hosted AI runs.
6. The branch is documented, committed, pushed, and work stops before R04.

## Forest check and stop rule

At 60 minutes or after two materially different failures, ask whether the exact preflight moved
toward `READY`. Do not add a new sensor, VM protocol, evaluator feature, provider integration, or
general cloud abstraction. If blocked at two hours, push the exact reproduction and smallest
operator action, then return control to the user.
