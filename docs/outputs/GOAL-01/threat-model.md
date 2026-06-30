# Threat Model

## Assets

- Developer credentials: npm/PyPI tokens, SSH keys, cloud environment variables, Git credentials.
- CI credentials and signing tokens.
- Source tree integrity and dependency lockfiles.
- Vault CAS, metadata, policy, audit logs, and evidence bundles.
- Internal package namespaces and private registry contents.
- Build availability and package-cache performance.

## Trust Boundaries

- Developer shell to WhoaThere shim.
- Local engine to real package manager.
- Local sandbox to host filesystem and network.
- Developer/CI network to Vault.
- Vault serving plane to fetch/detonation planes.
- Quarantine CAS to promoted serving namespace.
- Policy/admin control plane to enforcement points.

## Adversary Capabilities

- Publishes malicious npm or PyPI package.
- Takes over a maintainer account and publishes a malicious patch release.
- Uses typo-squatting or dependency confusion.
- Uses lifecycle scripts, PEP 517 build hooks, native extensions, platform selectors, import-time payloads, or delayed activation.
- Attempts DNS/HTTPS exfiltration, direct IP egress, Git dependency bypass, or lockfile manipulation.
- Knows WhoaThere exists and detects sandbox/CI/dev environments.

## Abuse Cases And Mitigations

| Abuse case | Mitigation | Tests |
| --- | --- | --- |
| npm lifecycle script steals credentials | PATH shim, policy-gated script execution, sandbox, Vault admission, redacted evidence | AT-001, AT-002 |
| Python build backend executes malicious code | sdist build sandbox, PEP 517 detection, detonation | AT-003 |
| Import-time payload fetches remote code | import-time detonation before allow verdict | AT-004 |
| DNS or HTTPS exfiltration | network-deny/recording mode, DNS logging, deny by default in detonation | AT-005 |
| Platform-specific payload hides from laptop | detonation matrix includes Linux CI and macOS contexts | AT-006 |
| Native extension abuses build/import | native binary detection and sandboxed build/import | AT-007 |
| Delayed or CI-gated activation | CI env simulation, delay detection, static guard review | AT-008 |
| Maintainer takeover | version-diff and maintainer/release anomaly signals | AT-009 |
| Dependency confusion | internal namespace rules and private-registry precedence | AT-010, CT-009 |
| Package-manager edge case bypass | compatibility matrix and fail-closed unsupported high-risk sources | CT-001 through CT-011 |
| Outage forces insecure fallback | fail-closed policy and break-glass audit | OT-001 through OT-008 |

## Residual Risk

- A package may contain malicious logic that only activates in a production application runtime not represented in MVP detonation. This is explicitly outside MVP runtime scope.
- macOS endpoint isolation is weaker than Linux unless VM-backed isolation is selected and implemented.
- Dynamic analysis cannot prove benign behavior; it only raises confidence and catches targeted evasion scenarios.

## Required Review Conclusion

The MVP is acceptable only if install-time, build-time, import-time, namespace, source-routing, and outage risks are each assigned to a concrete control and test owner.

