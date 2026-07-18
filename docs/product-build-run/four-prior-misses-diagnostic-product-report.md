# Four Prior Misses: Diagnostic Product Report

**Result:** diagnostic **4/4**. The finalized July restricted-malware experimental baseline remains
**7/11**.

WhoaThere's production saved-report command rendered four unique, exact-digest-bound sanitized
projections as:

> `BLOCK - malicious capability found in package`

Each result was independently derived from typed deterministic-static findings under the current
behavior allowlist. Historical sample names, expected labels, corpus membership, advisories, and
hash reputation were not verdict inputs.

## Exact inputs and results

| Historical cohort label | Form | Artifact SHA-256 | Sanitized-report SHA-256 | Result |
| --- | --- | --- | --- | --- |
| Telnyx 4.87.1 | PyPI wheel | `sha256:7321caa303fe96ded0492c747d2f353c4f7d17185656fe292ab0a59e2bd0b8d9` | `sha256:b662269261553d071426807107cb226072a24c03491acccd32b4091b44cf5f43` | `BLOCK`, exit 20 |
| Telnyx 4.87.2 | PyPI wheel | `sha256:cd08115806662469bbedec4b03f8427b97c8a4b3bc1442dc18b72b4e19395fe3` | `sha256:11770b7fd13aa752019447e59d287eb3c12caed4ddf5b68663d69dbc41646fd8` | `BLOCK`, exit 20 |
| Telnyx 4.87.2 | PyPI tar.gz sdist | `sha256:a9235c0eb74a8e92e5a0150e055ee9dcdc6252a07785b6677a9ca831157833a5` | `sha256:3c784119fef8532848d2906a1cd476ef2dc9006d83b09ab7e37bc04dde92601c` | `BLOCK`, exit 20 |
| npm sbx 45.0.2 | npm tar.gz | `sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933` | `sha256:bc09a308462940012d9060b54a46ff7568ee94d04a5ccb2d10a3faeca1a5e452` | `BLOCK`, exit 20 |

The cohort labels identify the historical inputs for readers. They did not create or strengthen a
finding.

## Behavior-specific evidence

### PyPI wheel `7321caa...b8d9`

- `download_execute_capability` — evidence `sha256:2309e35f585d7df6e7c9e99330ae228de7d32ba3dc538c3561ba9344dd7724bf`;
  file SHA-256 `sha256:23b1ec58649170650110ecad96e5a9490d98146e105226a16d898fbe108139e5`;
  line 7782, bytes 349905-349920.
- `environment_to_process_capability` — evidence `sha256:c55e900bbce4484cf03a176cc9f8890f001bed4ce34c19b915e796b24585004d`;
  the same digest-bound file range.
- Material gaps: dependency closure and trigger-graph coverage are incomplete; AI review,
  detonation, and behavior observation were not requested for this static projection.

### PyPI wheel `cd081158...5fe3`

- `download_execute_capability` — evidence `sha256:6d67576208f76b51f605bb5769ca36041e0a5a5272a2c7f68e53d8631ece8d89`;
  file SHA-256 `sha256:ab4c4aebb52027bf3d2f6b2dcef593a1a2cff415774ea4711f7d6e0aa1451d4e`;
  line 7782, bytes 349905-349920.
- `environment_to_process_capability` — evidence `sha256:f81d7c9a569a79aa4809116b3d7cc9f60624ff9f8f8752aad74b9381141d179a`;
  the same digest-bound file range.
- Material gaps: dependency closure and trigger-graph coverage are incomplete; AI review,
  detonation, and behavior observation were not requested for this static projection.

### PyPI sdist `a9235c0e...33a5`

- `download_execute_capability` — evidence `sha256:d3ce3cfa0a804d3d5316a4c0def3f6a1ee7b88663f1004411d97153b66e0bbb0`;
  file SHA-256 `sha256:ab4c4aebb52027bf3d2f6b2dcef593a1a2cff415774ea4711f7d6e0aa1451d4e`;
  line 7782, bytes 349905-349920.
- `environment_to_process_capability` — evidence `sha256:7db1eafdc53d810d1fffdef120ec3597237caef311896f250ae6f6f9867b1fdc`;
  the same digest-bound file range.
- The older producer projection also records generic environment-exfiltration capability. Current
  product policy treats that finding as context, not as a blocking finding.
- Material gaps: build and dependency closure, derived-wheel probing, executable-member analysis,
  and trigger-graph coverage are incomplete; AI review, detonation, and behavior observation were
  not requested for this static projection.

### npm tarball `0b8e586c...8933`

- `environment_to_process_capability` — two typed findings; representative evidence
  `sha256:49840166ff867f80beaef6e2a3d053224ff0da7e6c103f569464d86260d5b492`;
  file SHA-256 `sha256:bda1cd943a6b3537d002f0338c35082fa606a0a648038e17c78cc27ef1b8f1d3`;
  line 9, bytes 335-359.
- `sensitive_file_exfiltration_capability` — evidence
  `sha256:470f0e74882c479daf20f3a3acb8f7322b72cc70d356eb43094bf459f602ab79`;
  the same file SHA-256, line 83, bytes 4293-4298.
- `sensitive_path_access` — two typed findings; representative evidence
  `sha256:866dd4a50117f906bb7f3a156a63a2ba7ae5b280da66490e581dd85688513a54`;
  the same file SHA-256, line 80, bytes 3816-3822.
- Material gaps: dependency closure, unresolved trigger targets, and deterministic trigger-graph
  coverage remain incomplete. The retained projection notes paired VM bundles but contains no
  dynamic observations; P05 will present that evidence through a separate validated boundary.

## Validation and claim boundary

For every input, WhoaThere verified the exact report-file digest, closed projection field sets,
artifact and manifest bindings, stage and scenario-summary bindings, deterministic source receipt,
observation digest and evidence range, coverage, historical producer consistency, and false
authority flags. It then re-derived blocking eligibility, count, disposition, verdict, and exit
code under current product policy.

The projections deliberately omit package source, selected bytes, scenario intents, and raw
telemetry. The renderer did not reopen package artifacts or re-resolve citations. Report-digest
matching provides integrity, not producer authentication.

This is a **diagnostic 4/4** result for the four prior misses. It is not the R06 signed detection
subscore, not a new 11-sample campaign, not an 11/11 result, and not evidence of broad malware
coverage. Coverage remains incomplete, and the reports grant no clean, installation, admission,
release, sync-back, or publication authority. The finalized July experimental baseline remains
**7/11**.
