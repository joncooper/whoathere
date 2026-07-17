# Four-known-miss evaluation profile

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
