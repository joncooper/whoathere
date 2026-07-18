# Next Ultra Chunk: R02 Synthetic 4/4 Positive-Subscore Path

Status: complete. R01 is accepted and pushed at `405182d`. R02 is independently accepted on its
dedicated branch. R02b is ready but has not begun and must be a separate bounded chunk.

Updated: 2026-07-18

## Accepted result

- One hermetic command exercises the exact-contract compiler, publisher, mixed-projection signed
  registry bridge, mandatory V2 scorer, and strict positive-subscore summary.
- Detection subscore: `4/4`, rate `1.0`, pass.
- Safety: `4/4`, rate `1.0`, pass.
- Completion: `0/4`, rate `0.0`; completion/quality fails.
- Underlying and summarized `overall_passed` are both `false`.
- Observed-clean, admission, release, and sync-back authority are all `false`.
- A generic safe block and a matching label from the wrong evidence tuple each score `3/4`.
- Empty projection sets are accepted only for incomplete runs and cannot create complete-clean
  authority.
- Sixteen focused integration checks plus the existing publisher, bridge, evaluator, complete-run
  compiler, and R01 contract suites pass.
- Independent final verification returned `GO`.
- No package, evidence, cloud host, VM, hosted AI, malware, credential, or private data was
  accessed.
- This proves synthetic evaluator readiness only. Real-evidence publication remains `0/4`, and the
  finalized July experimental baseline remains `7/11`.

## Frozen user outcome

One hermetic metadata-only command proves that the exact frozen four-row contract can produce a
valid **4/4 behavior-positive detection subscore** while safety passes, completion/quality fails,
and overall evaluation remains false.

Primary metric: the production compiler, publisher, signed-registry bridge, mandatory V2 scorer,
and positive-subscore summary agree on detection `4/4`, safety `4/4`, completion `0/4`, and
`overall_passed=false`.

## Inputs and branch

- Branch: `codex/r02-synthetic-four-of-four-subscore`, based on accepted R01 commit `405182d`.
- Contract:
  `docs/product-build-run/four-known-miss-positive-subscore-contract.v1.json`, canonical SHA-256
  `sha256:a47b8288c14c6c1eafb3976415fdc16a24ce0b85f06f4cf2c687ee50509ee053`.
- Artifact/profile denominator SHA-256:
  `sha256:bdd99ff7ba8634dbcec7f98f442962a7c371437f9d0d3bcc9fd940f8af285c96`.
- Existing complete-run profile remains unchanged and is used only to validate lineage.
- The synthetic corpus contains metadata rows with the frozen sample IDs and artifact digests. It
  contains no package bytes or restricted evidence.
- Synthetic executable, key, provider, and policy identities prove binding behavior only. Final
  values and the expanded R01 identity set are frozen in R02b, not R02.

## Bounded implementation

R02 may change only:

1. A dedicated positive-subscore compiler that validates R01 and emits the exact four positive
   profile rows in an EvaluationManifestV2 carrier.
2. The existing signed-projection registry bridge, narrowly generalized from static-only to both
   publisher-supported kinds needed here:
   - `typed_event`; and
   - `static_download_execute_capability`.
3. A dedicated positive-subscore summary layered on the mandatory V2 scorer. It must count only
   the exact `(modality, evidence_type, behavior_label)` tuple permitted by R01, not a matching
   behavior label from another modality or evidence type.
4. Focused hermetic integration and regression tests.

The bridge may accept a signed empty projection set so a generic fail-closed block can be proven to
remain a detection miss. It still requires one authenticated run-fact record for every manifest
row and exhaustive equality between signed projections, publisher-derived observations, registry
records, and results.

No evaluator identity expansion, final manifest freeze, sensor, runtime, VM, AI, cloud, package,
or malware work is permitted. Those belong to R02b or later chunks.

## Frozen synthetic rows

| Row | Signed positive | Coverage |
| --- | --- | --- |
| npm `sbx` | dynamic `environment_credential_read -> credential_env_access` | incomplete |
| Telnyx wheel 4.87.1 | deterministic `download_execute_capability -> second_stage_fetch` | incomplete |
| Telnyx wheel 4.87.2 | deterministic `download_execute_capability -> second_stage_fetch` | incomplete |
| Telnyx sdist 4.87.2 | deterministic `download_execute_capability -> second_stage_fetch` | incomplete |

Every row has zero safety violations, verified teardown, manual review required, and no artifact
release. Synthetic signatures use ephemeral Ed25519 keys created inside a temporary directory.

## Acceptance

1. The compiler validates the exact R01 contract and emits four unique positive profile rows with
   exact artifact, form, profile, label, modality, threshold, window, and corpus bindings.
2. Publisher and bridge accept one dynamic npm bundle plus three static Telnyx bundles, derive the
   exhaustive signed registry, and reject unknown projection kinds.
3. The dedicated scorer summary reports:
   - detection numerator/denominator `4/4`, rate `1.0`, pass;
   - safety `4/4`, rate `1.0`, pass;
   - completion `0/4`, rate `0.0`, fail;
   - `overall_passed=false`; and
   - observed-clean, admission, release, and sync-back authority all false.
4. A valid signed incomplete row with no projections is a miss. A validly signed dynamic
   `second_stage_fetch_attempt` cannot satisfy a Telnyx row that permits only deterministic
   `download_execute_capability`.
5. Omission, duplication, artifact/result substitution, bundle or registry signature changes,
   profile/profile-digest drift, projection omission/addition/duplication/change, and manifest,
   result, registry, verifier, schema, or policy identity drift fail closed.
6. Attempted result-authored release/admission changes fail publisher recomputation or scoring.
7. The existing complete-run compiler, publisher, bridge, and evaluator hermetic suites remain
   green.
8. The branch is independently reviewed, committed, and pushed. Work stops before R02b.

## Stop rule

At four focused hours, preserve the one exact missing bridge and stop. Do not widen this chunk into
complete clean-admission verification, final identity design, or evidence collection.
