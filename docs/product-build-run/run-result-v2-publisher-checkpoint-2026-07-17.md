# RunResultV2 Publisher Checkpoint

Date: 2026-07-17

Status: a narrow fail-closed publisher exists for signed independent projections; a production
multi-action verifier still does not emit this bundle, so the known-malware score remains 7/11.

## What this closes

`scripts/whoathere-run-result-v2-publisher.py` converts one frozen EvaluationManifestV2 run slot
and one detached-signature-verified projection bundle into a strict RunResultV2. It does not read,
unpack, or execute a package.

The publisher:

- pins the manifest digest out of band;
- selects exactly one `(sample_id, profile_id)` slot;
- requires the signed run fact to match the evaluation, corpus, artifact, ecosystem, identities,
  and `execution_profile_sha256` frozen in that slot;
- verifies the bundle with the Ed25519 verifier key pinned by the manifest;
- requires the bundle and run fact to carry the manifest-frozen verifier-executable and projection-
  schema digests;
- preserves complete, incomplete, unsupported, and infrastructure-error states exactly;
- accepts only allowlisted typed completion gaps and rejects free-form reason fields;
- derives behavior labels from a closed evidence-type mapping instead of accepting labels from the
  producer or bundle;
- always emits `artifact_release_applied: false` and `manual_review_required: true`; and
- has no verdict, observed-clean, release, or admission authority.

The first mapping is deliberately narrow. A signed projection for an independently verified exact
artifact `DownloadExecuteCapability` must carry the artifact and normalized-manifest digests, exact
observation and finding-evidence digests, file id and digest, byte or line range, selected-byte
digest, and source-receipt digest. Only that citation-complete projection maps to the static
`download_execute_capability` evidence type and the sealed `second_stage_fetch` behavior class. It
does not claim that a runtime fetch was attempted. The `second_stage_fetch_attempt` evidence type
remains reserved for verified dynamic evidence, and a generic deterministic typed event cannot use
it as a shortcut. The publisher hashes the complete canonical projection, binds that digest to the
derived observation id, and the scorer requires the same binding in the signed evidence registry.
This makes a plausible-looking citation insufficient unless the pinned verifier authenticated the
same complete projection.

The generic typed-event lane currently accepts only independently signed **dynamic** projections
for the four known-miss classes:

- `environment_credential_read` -> `credential_env_access`;
- `ci_gate_activation` -> `ci_gated_activation`;
- `https_exfiltration_attempt` -> `https_exfil`; and
- `second_stage_fetch_attempt` -> `second_stage_fetch` for verified runtime events.

These four publisher runtime types are dynamic-only. More broadly, every behavior-bearing evidence
type mapped by the scorer has an explicit, default-closed modality policy: runtime reads, requests,
attempts, spawns, writes, executions, and gates are dynamic-only; obfuscated-code structure is
limited to static-analysis modalities; and download/execute capability is deterministic-only. A
mapped type without a policy invalidates the evaluation. Reusing one source event under another
evidence type—or supplying a conflicting digest for the same receipt and event id—is rejected.

Package names, hashes-as-reputation, corpus labels, advisories, producer verdicts, free-form reason
strings, and hosted source-review labels are not inputs to this mapping.

Run the hermetic test with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/whoathere-run-result-v2-publisher-selftest.py
```

The self-test uses synthetic metadata and a temporary Ed25519 key. It covers the successful
manual-review-only path plus signature forgery, unverified status, label injection, unmapped
evidence, profile substitution, loose reason fields, incomplete preservation, invalid static
citations, runtime-as-static substitution, duplicate source-event relabeling, verifier/schema
substitution, and attempts to bypass the citation-complete static mapping.

## What remains open

This publisher is the consumer-side bridge, not the independent verifier. The current one-action
native proof derives one file observation, but no production executable yet authenticates the
complete multi-action process, file, canary, and network receipt graph and emits the signed
projection-bundle schema used here. The scorer's end-to-end claim path remains blocked until the
verified-evidence registry is derived from—and cryptographically binds—the exact same signed bundle
consumed by this bridge. A separately assembled registry, even if well formed and signed, does not
close that provenance link. Until that exact-bundle path exists, this bridge is manual-review-only:
diagnostic static or VM findings cannot create a claim-bearing 4/4 or 11/11 result.

The timestamp model also remains explicitly open. RunResultV2 currently copies the signed run-fact
`created_at_utc`; it is the run-fact time, not a publication timestamp. No report should describe it
as publication time. A future schema revision should distinguish observed, verified, and published
timestamps rather than changing the meaning of this existing field in place.
