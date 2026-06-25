# Acceptance Test Matrix

Every downstream planning goal must map its tests back to this matrix. The matrix is intentionally adversarial; passing it is the minimum evidence that the generated plans preserve WhoaThere's security intent.

GOAL-09 `outputs/GOAL-09/primary-owner-test-matrix.md` is the authoritative source for single-accountable ownership, harness location, and phase contributors.

## Adversarial Package Tests

| ID | Scenario | Required Result |
| --- | --- | --- |
| AT-001 | npm package runs `postinstall` and reads `~/.npmrc`, `~/.ssh`, cloud env vars, then attempts HTTPS exfiltration. | Install is blocked or sandboxed; secret reads and network attempt are recorded in redacted evidence. |
| AT-002 | npm package uses `prepare` or `prepublish` to fetch and execute remote code. | Fetch/execute is blocked or quarantined; lifecycle script is visible in decision explanation. |
| AT-003 | Python package uses PEP 517 build backend to execute malicious code during sdist build. | Build occurs only in sandbox; filesystem and network attempts are blocked or recorded. |
| AT-004 | Python package is clean at install but malicious on first import. | Import-time detonation detects or quarantines before approval. |
| AT-005 | Package attempts DNS TXT, DoH, and encoded URL exfiltration. | DNS/HTTPS attempts are blocked or recorded; package is denied or quarantined. |
| AT-006 | Package behaves benignly on macOS but maliciously on Linux CI. | Detonation matrix includes Linux CI context and flags the Linux payload. |
| AT-007 | Native extension reads local credentials or opens network connection during build/import. | Native behavior is sandboxed and denied or quarantined with evidence. |
| AT-008 | Payload activates only with `CI=true`, after sleep, or on specific hostname/user. | Detonation or static analysis surfaces the condition and payload. |
| AT-009 | Maintainer-takeover simulation adds new lifecycle script and obfuscated code in patch release. | Release is quarantined or sent to manual review with diff/anomaly evidence. |
| AT-010 | Public package shadows internal package name with higher version. | Resolver selects private package or fails closed; no public fallback occurs. |

## Package-Manager Compatibility Tests

| ID | Scenario | Required Result |
| --- | --- | --- |
| CT-001 | `npm install` with package-lock integrity and default registry replacement. | Vault preserves integrity and registry semantics. |
| CT-002 | `npm ci` with existing lockfile and lifecycle scripts. | Install remains deterministic; policy decisions are explainable. |
| CT-003 | `npx` or `npm exec` fetches and runs a transient package. | Execution intent is classified and policy-gated. |
| CT-004 | `npm run` invokes dependency scripts or package-manager subprocesses. | Subprocesses inherit isolation and audit correlation. |
| CT-005 | npm alias, optional dependency, peer dependency, workspace, and scoped registry cases. | Supported cases behave natively; unsupported cases fail closed by policy. |
| CT-006 | `pip install -r requirements.txt` with hashes, markers, and extras. | Hash and marker semantics are preserved. |
| CT-007 | `python -m pip install` bypasses direct shim invocation. | Plan either intercepts, detects, or clearly fails closed in protected modes. |
| CT-008 | pip sdist build, wheel install, editable install, and direct URL reference. | Supported behavior is defined; unsupported high-risk behavior fails closed. |
| CT-009 | Private registry/index plus public fallback. | Dependency confusion rules are enforced. |
| CT-010 | Subprocess tries direct IP, localhost, RFC1918, DNS, Git SSH, and Git HTTPS egress. | Behavior matches explicit endpoint network decision table. |
| CT-011 | Endpoint run fails midway. | Cleanup test proves no lingering VM, namespace, proxy, firewall, mount, temp credential, or helper state. |

## Outage And Policy Tests

| ID | Scenario | Required Result |
| --- | --- | --- |
| OT-001 | Vault proxy unavailable during CI install. | Install fails closed unless scoped break-glass is active. |
| OT-002 | Scanner unavailable on cache miss. | Package is not promoted; install blocks or returns deterministic policy failure. |
| OT-003 | Detonator queue backlog exceeds SLO. | Alert fires; admission behavior follows policy. |
| OT-004 | Policy service unavailable on endpoint. | Cached policy rules are used only if valid; otherwise protected high-risk installs fail closed. |
| OT-005 | Break-glass approval expires mid-workflow. | New decisions fail closed; audit log records expiration. |
| OT-006 | CAS object is tampered with or hash check fails. | Artifact is denied/quarantined; no response serves corrupted content. |
| OT-007 | Partial deploy or rollback occurs while package is pending admission. | Clients receive deterministic failure or previous approved state; no unscanned package is served. |
| OT-008 | Provider token is stale, replayed, or unauthorized. | Request is rejected, redacted audit event is emitted, and no secret appears in logs. |

## Performance And Scale Tests

| ID | Scenario | Required Result |
| --- | --- | --- |
| PT-001 | 1,000 concurrent CI jobs request warm npm and pip artifacts. | Warm-cache path meets defined latency/error SLO. |
| PT-002 | Large npm tarball and Python wheel stream through Vault. | Streaming avoids full in-memory buffering and preserves hash/integrity. |
| PT-003 | Large cold miss triggers fetch, scan, detonation, and promotion. | Cold-miss latency is measured and admission state is deterministic. |
| PT-004 | Hot metadata fanout for large dependency tree. | Metadata cache and DB plan handles resolver request patterns. |

## Privacy And Audit Tests

| ID | Scenario | Required Result |
| --- | --- | --- |
| PA-001 | Malicious fixture attempts to expose secrets in logs. | Evidence is redacted; raw secrets are not stored. |
| PA-002 | Admin reviews deny decision. | Audit trail links decision, policy version, package digest, and evidence summary. |
| PA-003 | Customer requests data inventory. | Privacy data map identifies collected fields, purpose, retention, and deletion/export behavior. |
