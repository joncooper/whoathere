# Paired npm VM/Codex Product Report

Date: 2026-07-18

Status: P05 product diagnostic; sanitized, digest-bound, and unauthenticated

## Outcome

WhoaThere's saved-report command now presents the previous npm miss as one understandable
multimodal report:

- deterministic static analysis remains the sole source of the `BLOCK` decision;
- disposable-VM evidence is displayed separately for `CI=false` and `CI=true`;
- observe-only Codex findings retain their exact typed-event citations;
- local-sinkhole connect/send intent is supporting activity, not payload exfiltration; and
- incomplete coverage and the absence of admission authority remain prominent.

The production render exits 20 with:

```text
BLOCK - malicious capability found in package
```

P05 does not execute the package, invoke Codex, or contact the cloud Mac. It validates and presents
the already-produced sanitized diagnostic evidence.

## Exact bindings

| Item | SHA-256 |
| --- | --- |
| Artifact | `sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933` |
| Manifest | `sha256:14da51ba0162c2658057202df1e94d71b7a89d5f2a813464830b3eadd06f7f37` |
| Static report | `sha256:bc09a308462940012d9060b54a46ff7568ee94d04a5ccb2d10a3faeca1a5e452` |
| Paired reconciliation envelope | `sha256:ac521c940607aea152461bcfbcd74fe55769e58f9a36e1fd7480b8a88c7252b5` |
| Export manifest | `sha256:12686a54572505ab36eabd45690919de83cdf13becaf58364c7ced56d4fe0f57` |
| Source reconciliation | `sha256:e01f4bd4844756bdd5b07a2d3dd111be9283561fad319d3d3be2af7ff852a5c7` |
| Source input binding | `sha256:bb44a2843b20486d56a8f473d74f283da96187d1d26cdecdc89f233e8c7782f6` |

## Paired observations

| Profile | Typed events | npm lifecycle | Credential-file reads | Sinkhole connects | Sinkhole sends | Coverage |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| `CI=false` | 73 | 2 | 6 | 10 | 10 | incomplete in all five modalities |
| `CI=true` | 73 | 2 | 6 | 10 | 10 | incomplete in all five modalities |

Codex produced four high-confidence, structurally cited findings in each profile:

- npm lifecycle execution;
- credential access;
- outbound connection intent; and
- network send intent.

The product recomputes each finding identity and resolves every citation against the matching
strict `BehaviorAnalysisBundleV1` event. It does not use model explanations or reason strings to
derive the displayed facts.

## Fail-closed controls

The focused product self-test passed the baseline plus 18 fail-closed controls. It rejected:

- detached-digest mismatch;
- unknown or unsupported schema content;
- artifact mismatch;
- missing, duplicated, or reordered profiles;
- authority, observed-clean, and claim-bearing mutations;
- source-binding mismatch;
- source-reconciliation identity substitution;
- coherent Codex observer-identity rebinding;
- a coherently rehashed cross-profile citation forgery;
- a coherently rehashed citation omission that retained the claimed Codex-result identity;
- an attempted network-to-exfiltration promotion;
- non-null untrusted event detail; and
- an attempted coverage upgrade.

Each failure exited 64 without rendering `BLOCK` or `ALLOW` and without echoing a local input path.
The original P03 complete-report and P04 sanitized-static paths remain backward compatible when no
reconciliation is supplied.

Independent Ultra verification initially reproduced coherent citation omission and source/observer
identity substitution. The accepted implementation now pins the complete frozen source contract
and normalized Codex projection before revalidating every typed event and citation. The verifier
reran all three attacks, observed exit 64 for each, and returned GO.

## Claim boundary

The envelope contains sanitized typed events and prose-free Codex projections, but not the signed
root/host receipt bytes, verification keys, or provider output needed for producer authentication.
Its exact digest therefore proves integrity only under caller-provided custody.

This is a useful product diagnostic, not a new evaluation score. It does not establish successful
credential exfiltration, meaningful CI-gated divergence, complete telemetry, observed-clean,
installation authority, admission, sync-back, R06 completion, or an 11/11 known-regression result.
The finalized July experimental baseline remains 7/11.
