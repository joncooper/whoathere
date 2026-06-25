# Pass 2 Rubric: Security Invariants And Gate Preservation

| Criterion | Weight | Passing standard |
| --- | ---: | --- |
| Fail-closed preservation | 25 | Plans block CI/high-risk ambiguity and unknown artifacts. |
| Promotion safety | 20 | Production promotion remains tied to active servable generation and evidence profiles. |
| Break-glass safety | 15 | Break-glass cannot promote unknown/unscanned code or enable public fallback. |
| Privacy boundary | 15 | Plans preserve no source/secrets/full env/full payload persistence. |
| Research gates | 15 | Allow-verdict, control-plane, Cloudflare, secure update, and macOS GA gates remain visible. |
| Ops security blockers | 10 | Secure update/SLO/incident gates are release blockers. |

Automatic fail: public fallback, unapproved serving, unaudited break-glass, raw secret/source persistence, or implementation of gated production promotion.

Pass threshold: 95/100.

