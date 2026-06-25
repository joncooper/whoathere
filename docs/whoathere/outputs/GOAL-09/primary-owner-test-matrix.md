# Primary-Owner Test Matrix

This matrix turns multi-phase traceability into single-accountable ownership. Contributor phases may provide fixtures, backends, or infrastructure, but the primary owner is responsible for the test definition, harness, pass/fail assertion, and release gate evidence.

| Test ID | Primary owner | Contributors | Harness location to define | Required assertion |
| --- | --- | --- | --- | --- |
| AT-001 npm postinstall exfil | Phase 1 Endpoint | Phase 4 Detection | `tests/fixtures/npm/postinstall-exfil` | Linux local containment blocks or records controlled egress; macOS beta labels containment state. |
| AT-002 npm prepare remote fetch | Phase 1 Endpoint | Phase 4 Detection | `tests/fixtures/npm/prepare-remote-fetch` | Unsupported remote fetch is denied or routed through policy; CI fails closed. |
| AT-003 PEP 517 malicious backend | Phase 1 Endpoint | Phase 4 Detection | `tests/fixtures/pypi/pep517-backend` | Build backend executes only inside supported containment/evidence boundary. |
| AT-004 Python import-time payload | Phase 4 Detection | Phase 3 Vault | `tests/fixtures/pypi/import-time-payload` | Import-time payload is exercised before allow verdict where policy requires import detonation. |
| AT-005 DNS/DoH/HTTPS exfil | Phase 4 Detection | Phase 2 Endpoint | `tests/fixtures/network/exfil` | DNS, DoH, HTTPS, direct IP, and Git egress decisions match endpoint/Vault network policy. |
| AT-006 platform split payload | Phase 2 Endpoint | Phase 4 Detection | `tests/fixtures/platform-split` | Linux CI and macOS contexts are both represented or explicitly marked unsupported/fail-closed. |
| AT-007 native extension abuse | Phase 2 Endpoint | Phase 4 Detection | `tests/fixtures/native-extension` | Native build/import cannot access denied files or network paths outside policy. |
| AT-008 delayed CI activation | Phase 4 Detection | Phase 3 Vault | `tests/fixtures/ci-delayed-activation` | CI/environment/sleep/hostname evasions are detonated or routed to manual review. |
| AT-009 maintainer takeover diff | Phase 4 Detection | Phase 3 Vault | `tests/fixtures/version-diff` | Reputation/version-diff signal affects verdict or manual review. |
| AT-010 dependency confusion | Phase 3 Vault | Phase 1 Endpoint | `tests/fixtures/dependency-confusion` | Internal namespace packages never resolve to public source unless explicit approved mapping exists. |
| CT-001 npm lockfile/integrity registry | Phase 3 Vault | Phase 1 Endpoint | `tests/compat/npm/lockfile-integrity` | Lockfile integrity and resolved registry are preserved through Vault. |
| CT-002 npm ci deterministic | Phase 1 Endpoint | Phase 3 Vault | `tests/compat/npm/ci` | `npm ci` deterministic behavior is preserved locally and under Vault route. |
| CT-003 npx/npm exec transient package | Phase 1 Endpoint | Policy/control plane | `tests/compat/npm/exec` | Transient package execution is high-risk and requires allow verdict or scoped break-glass in CI. |
| CT-004 npm run subprocess inheritance | Phase 2 Endpoint | Phase 1 Endpoint | `tests/compat/npm/run-subprocess` | Child processes inherit containment, egress policy, and correlation ID. |
| CT-005 npm aliases/optional/peer/workspaces | Phase 3 Vault | Phase 1 Endpoint | `tests/compat/npm/resolution` | Resolution preserves package-manager semantics and source policy. |
| CT-006 pip requirements hashes/markers/extras | Phase 3 Vault | Phase 1 Endpoint | `tests/compat/pip/requirements` | Hashes, markers, extras, constraints, and index precedence are preserved or fail closed. |
| CT-007 python -m pip | Phase 1 Endpoint | Phase 2 Endpoint | `tests/compat/pip/python-module` | `python -m pip`, venv Python, absolute Python, and nested invocation paths are protected or fail closed in protected contexts. |
| CT-008 pip sdist/wheel/editable/direct URL | Phase 3 Vault | Phase 1 Endpoint | `tests/compat/pip/source-types` | Source type policy is explicit; unsupported high-risk cases fail closed in CI. |
| CT-009 private index plus public fallback | Phase 3 Vault | Policy/control plane | `tests/compat/source-priority` | Public fallback cannot satisfy internal namespace unless policy explicitly allows it. |
| CT-010 endpoint egress matrix | Phase 2 Endpoint | Phase 4 Detection | `tests/compat/network/egress-matrix` | Direct IP, localhost, RFC1918, metadata IP, DNS, Git SSH/HTTPS match decision table. |
| CT-011 cleanup after failure | Phase 2 Endpoint | Ops | `tests/compat/cleanup` | No lingering VM, namespace, proxy, firewall, mount, temp credential, socket, or helper state. |
| OT-001 Vault unavailable | Phase 3 Vault | CI/Platform | `tests/outage/vault-unavailable` | CI fails closed; developer mode only uses approved digest-bound stale artifacts where policy permits. |
| OT-002 scanner unavailable | Phase 3 Vault | Phase 4 Detection | `tests/outage/scanner-unavailable` | No unknown artifact promotion; return pending/manual_review/503 by policy. |
| OT-003 detonator backlog | Phase 3 Vault | Phase 4 Detection | `tests/outage/detonator-backlog` | Admission remains deterministic; backlog alerts fire; no fail-open. |
| OT-004 policy unavailable | Phase 1 Endpoint | Phase 3 Vault | `tests/outage/policy-unavailable` | CI/high-risk fails closed; developer warning only for valid cached digest-bound decisions. |
| OT-005 break-glass expiry | Policy/control plane | Phase 1/3 | `tests/outage/break-glass-expiry` | Expired or revoked break-glass cannot authorize install, fetch, or serve. |
| OT-006 CAS tamper | Phase 3 Vault | Security | `tests/outage/cas-tamper` | Digest mismatch blocks serving and triggers audit/incident signal. |
| OT-007 partial deploy/rollback | Phase 3 Vault | Ops | `tests/outage/rollback` | Rollback serves last known approved generation or fails closed. |
| OT-008 provider token stale/replay | Phase 3 Vault | Ops/Security | `tests/outage/provider-auth` | Unauthorized/replayed/stale provider credentials cannot fetch or promote. |
| PT-001 1,000 concurrent CI warm cache | Phase 3 Vault | Platform | `tests/perf/warm-cache-1000` | Meets p95/p99/error budget defined in Phase 3 benchmark contract. |
| PT-002 large artifact streaming | Phase 3 Vault | Platform | `tests/perf/large-artifact` | First-byte, range-read, checksum, and memory ceilings pass. |
| PT-003 cold miss admission | Phase 3 Vault | Phase 4 Detection | `tests/perf/cold-miss` | Fetch/scan/detonate/promote path is measured and deterministic; no partial allow. |
| PT-004 metadata fanout | Phase 3 Vault | Platform | `tests/perf/metadata-fanout` | Metadata p95/p99 and cache-hit behavior meet benchmark contract. |
| PA-001 local redaction | Phase 1 Endpoint | Phase 4 Detection | `tests/privacy/local-redaction` | Secrets in env, args, DNS names, URL paths, filenames, and logs are redacted or field-dropped. |
| PA-002 audit decision trace | Phase 3 Vault | Policy/Detection | `tests/privacy/audit-trace` | Every allow/deny/quarantine/manual-review/break-glass has full trace without sensitive payloads. |
| PA-003 privacy export/delete | Phase 3 Control Plane | Ops/Privacy | `tests/privacy/export-delete` | Inventory, export, deletion, retention, and legal-hold exceptions are testable. |
