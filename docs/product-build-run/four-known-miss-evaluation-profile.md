# Four-known-miss evaluation profiles

There are now three deliberately separate artifacts:

- [`four-known-miss-campaign-profile.v1.json`](./four-known-miss-campaign-profile.v1.json) remains
  the original complete-run profile. It requires deterministic, Codex, and dynamic coverage and
  still refuses authoritative compilation while the complete sdist execution path is blocked.
- [`four-known-miss-positive-subscore-contract.v1.json`](./four-known-miss-positive-subscore-contract.v1.json)
  is the historical R01 positive-only contract. Its npm row remains dynamic
  `environment_credential_read -> credential_env_access`; R02b did not reinterpret it.
- [`four-known-miss-positive-subscore-contract.v2.json`](./four-known-miss-positive-subscore-contract.v2.json)
  is the active collection contract. It explicitly uses deterministic
  `sensitive_file_exfiltration_capability -> sensitive_file_exfiltration` for npm and deterministic
  `download_execute_capability -> second_stage_fetch` for each Telnyx row.

Both positive-only versions freeze exactly four behavior-positive rows without pretending that
incomplete coverage can pass completion/quality, overall evaluation, clean, admission, or release
gates. Neither counts a corpus label, package identity, hash, advisory, reputation signal, generic
safe block, producer claim, or AI-authored label by itself.

Validate the frozen semantic contract locally with:

```sh
scripts/whoathere-validate-four-known-miss-positive-subscore-contract.py \
  --contract docs/product-build-run/four-known-miss-positive-subscore-contract.v2.json \
  --complete-run-profile docs/product-build-run/four-known-miss-campaign-profile.v1.json
```

The active v2 semantic contract SHA-256 is
`sha256:3269f8525e60012c075c951664083e559583a849f476d035922000d653da8359`; its artifact/profile
denominator SHA-256 is
`sha256:489be1dfe2513a29c8a4019d2303ebf377e93be33c4fe50bb7d34816d65dc792`.
Historical v1 remains byte-identical and valid.

## R02b immutable collection freeze

R02b completed the metadata-only freeze before restricted collection:

- source revision: `29c7a9bc7f4fd79478fa0ef7192e9f509be05e45`;
- exact four-row corpus: `sha256:e848f51878c8fe89ece0876a4ae7c07a88416a36decb29a3354725f49ea06819`;
- combined npm/PyPI projection schema: `sha256:2785f493cd0ddf4ad3f99124344c40180e7d9c1f4fbf4c182c27fe547f5c377a`;
- exact arm64 verifier executable: `sha256:d51431a2e08f74fb008988d8e8e24cca8e43873b06ae530e4d9e9cc834a2de33`;
- verifier public key: `sha256:85500877dd142794fd7beea871e0eaffb67ec0a4ec07670246ae5403d5036197`;
- collection lock: `sha256:32f96202ca0a6d524c291c339e5aba35cd5acdc92b11f465b4caed5a47e6d928`;
- EvaluationManifestV2: `sha256:53db45466a91cbaeab6db51039cd515e292291a84f6056b3638f508e39f0dee2`;
- inclusive collection window: `2026-07-19T02:00:00Z` through `2026-08-18T23:59:59Z`;
- result-to-registry maximum: 600 seconds.

The tracked [collection lock](./four-known-miss-positive-subscore-collection-lock.v1.json),
[manifest](./four-known-miss-positive-subscore-evaluation-manifest.v2.json),
[freeze receipt](./four-known-miss-positive-subscore-freeze-receipt.v1.json), and
[public key](./four-known-miss-positive-subscore-verifier-public-key.v1.pem) contain no package
bytes, private key, source excerpts, telemetry, credentials, or host-private paths. The durable
private key and exact verifier copy remain under ignored local campaign state. Any bound tool or
policy change invalidates the freeze.

No real row was collected by R02b. The claim-bearing positive subscore remains **0/4**, and the
finalized July experimental baseline remains **7/11**. R03 is the next bounded step.

## R02 synthetic publication proof

R02 connects the frozen contract to the production metadata path without reading a package or
evidence file:

```sh
scripts/whoathere-four-known-miss-positive-subscore-selftest.py
```

The hermetic command creates only temporary synthetic corpus metadata, incomplete verified
projection bundles, and ephemeral Ed25519 keys. It exercises the dedicated positive-subscore
compiler, RunResultV2 publisher, generalized signed-registry bridge, mandatory V2 scorer, and the
contract-specific summary. Its accepted result is:

| Gate | Synthetic result |
| --- | --- |
| Exact behavior-positive detection | 4/4, pass |
| Safety | 4/4, pass |
| Completion | 0/4, fail |
| Completion/quality | fail |
| Overall evaluation | `false` |
| Observed-clean/admission/release/sync-back authority | all `false` |

The summary is stricter than label matching: it requires the exact active-contract
`(modality, evidence_type, behavior_label)` tuple. A signed dynamic
`second_stage_fetch_attempt -> second_stage_fetch` therefore cannot satisfy a Telnyx row that
permits only deterministic `download_execute_capability -> second_stage_fetch`. A signed
incomplete no-finding row also remains a miss. The bridge permits an empty projection set only for
an incomplete run, so this path does not create complete clean authority.

Sixteen integration checks cover the happy path plus row omission/duplication, profile and artifact
substitution, bundle and registry signatures, projection and identity drift, profile-digest drift,
result-authored release, generic blocks, and wrong evidence tuples. Existing publisher, bridge,
evaluator, complete-run compiler, and R01 contract suites remain green.

This is still synthetic evaluator readiness. No R04/R05 evidence row has been collected, so the
claim-bearing positive subscore remains **0/4** and the finalized July experimental result remains
**7/11**. R02b is complete; R03 refreshes the restricted-lab preflight against the frozen identity.

## Complete-run profile

This profile freezes the next detection-bearing campaign around the four artifacts that the July
1 run missed. It is a metadata-only planning and evaluation contract. Compiling it does not open,
unpack, inspect, or execute a package and does not contact the cloud Mac.

The tracked source of truth is
[`four-known-miss-campaign-profile.v1.json`](./four-known-miss-campaign-profile.v1.json). It has
exactly four artifact-level rows:

| Artifact | Aggregate execution profile |
| --- | --- |
| `mb-npm-sbx-45.0.2` | Exact tarball installed from an in-guest local artifact with `CI` absent, then with `CI=true` |
| `mb-telnyx-4.87.1-wheel` | Exact wheel install, every validated `.pth`, import root, and console entry point |
| `mb-telnyx-4.87.2-wheel` | Exact wheel install, every validated `.pth`, import root, and console entry point |
| `mb-telnyx-4.87.2-sdist` | Exact-metadata-selected sdist build lane followed by the complete derived-wheel trigger matrix |

Each aggregate profile has a deterministic SHA-256 over UTF-8 JSON rendered with sorted keys,
compact separators, and no non-finite numbers. The profile includes the exact sample and artifact
digest binding, disposable-guest policy, approved-remote-cloud-Mac-only host policy, sinkhole-only
network posture, no-sync and no-live-fetch rules, and the complete action selectors. The resulting
evaluation denominator is four, not the number of actions expanded within each aggregate profile.

These four known-malware profiles never authorize execution on the developer's local Mac. Every
profile requires a separately approved remote cloud-Mac lab host, fresh action-time authorization,
and verified evidence binding the run to that host. A producer must not claim an execution-profile
digest unless those host facts are verified; compiling the metadata does not itself authorize or
perform a run.

## Honest current readiness

The npm and wheel profiles describe paths the current exact-artifact runners can exercise. The
sdist profile is intentionally marked `blocked`: exact artifact metadata must select one of PEP
517 or legacy `setup.py`, and the selected path must support the complete derived-wheel `.pth`,
import-root, and console-entry-point fan-out. PEP 517 and `setup.py` are alternatives chosen by
exact metadata, not two unconditional builds.

The blocked state is part of the sdist execution-profile digest. The compiler validates the target
denominator but refuses to create an EvaluationManifestV2 while any profile has
`authoritative_campaign_run_permitted=false`. When the missing sdist support lands, the reviewed
profile, its digest, and the compiler pin must change together before an authoritative campaign
can start.

The required coverage modalities are `deterministic`, `codex`, and `dynamic`. Deterministic is
required because the current exact-artifact Telnyx behavior finding is static. Codex is required
so the campaign proves the observe-only AI path, and dynamic is required so the disposable-VM
evidence path cannot be omitted. `fused` is not required until that modality is produced and
verified end to end.

## Compiling a lab manifest

`whoathere-compile-four-known-miss-evaluation.py` validates the frozen declaration against the
real restricted corpus manifest at lab time. It fails closed for a missing or duplicate required
sample, duplicate artifact digest, digest mismatch, ecosystem mismatch, behavior-label mismatch,
changed profile description, unsafe corpus policy, malformed identity, or invalid evaluation
window. Extra corpus rows are allowed so the four-row gate can be compiled from the full corpus.

All mutable campaign identities are explicit inputs:

```sh
scripts/whoathere-compile-four-known-miss-evaluation.py \
  --corpus /restricted/path/corpus.jsonl \
  --output /restricted/path/four-known-miss-evaluation.json \
  --evaluation-id four-known-miss-YYYYMMDD \
  --created-at-utc YYYY-MM-DDTHH:MM:SSZ \
  --starts-at-utc YYYY-MM-DDTHH:MM:SSZ \
  --ends-at-utc YYYY-MM-DDTHH:MM:SSZ \
  --maximum-result-to-registry-seconds 600 \
  --runtime-sha256 sha256:... \
  --prompt-set-sha256 sha256:... \
  --observation-schema-sha256 sha256:... \
  --provider-adapter-sha256 sha256:... \
  --policy-sha256 sha256:... \
  --scorer-id whoathere-actual-malware-evaluation.py:score-results-v2 \
  --registry-id verified-evidence-registry-id \
  --verifier-id independent-verifier-id \
  --verifier-public-key-sha256 sha256:... \
  --verifier-executable-sha256 sha256:... \
  --projection-schema-sha256 sha256:...
```

Today this command exits fail-closed without creating the output because the sdist profile remains
blocked. Once every profile is reviewed as ready, the output path must not already exist and the
compiler will create exactly one mode-`0600` EvaluationManifestV2 containing four unique
`required_runs`, each with its deterministic `execution_profile_sha256`. It copies required
behavior labels from the independently pinned profile, never from the corpus. Corpus labels are
only a consistency check and cannot themselves satisfy detection; the scorer still requires
allowlisted, verified behavior evidence from a required modality.

Run the local metadata-only regression with:

```sh
scripts/whoathere-compile-four-known-miss-evaluation-selftest.py
```

This self-test uses synthetic corpus rows in a temporary directory. It does not use raw malware,
the cloud Mac, a VM, a package manager, or network access.
