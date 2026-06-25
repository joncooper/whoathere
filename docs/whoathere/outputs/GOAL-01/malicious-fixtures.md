# Malicious Fixture Requirements

## Fixture Set

| Fixture | Behavior | Expected result | Tests |
| --- | --- | --- | --- |
| `npm-postinstall-exfil` | Reads token-like files/env vars, attempts HTTPS and DNS exfil in `postinstall`. | Block or sandbox; redacted evidence records attempts. | AT-001, AT-005 |
| `npm-prepare-fetch-exec` | Uses `prepare` to download and execute remote JS. | Quarantine or deny before approval. | AT-002 |
| `py-pep517-build-exec` | PEP 517 backend executes code during sdist build. | Build isolated; filesystem/network attempts blocked or recorded. | AT-003 |
| `py-import-payload` | Clean install, malicious `import` downloads payload. | Import-time detonation denies/quarantines. | AT-004 |
| `platform-split-payload` | Benign on macOS, malicious on Linux CI. | Linux CI detonation catches behavior. | AT-006 |
| `native-extension-probe` | `.node`/`.so`/`.dylib`/`.pyd` probes credentials/network. | Native build/import isolated and denied/quarantined. | AT-007 |
| `delayed-ci-payload` | Activates only with `CI=true`, hostname guard, or sleep. | Static/dynamic analysis surfaces trigger. | AT-008 |
| `maintainer-takeover-diff` | Known-good version followed by patch adding script/obfuscation. | Manual review or quarantine. | AT-009 |
| `dependency-confusion-public` | Public package shadows internal name. | Private wins or fail closed. | AT-010, CT-009 |
| `source-bypass-cases` | Git SSH, Git HTTPS, tarball URL, direct reference, editable install. | Supported cases policy-gated; high-risk CI unsupported cases fail closed. | CT-005, CT-008, CT-010 |

## Fixture Rules

- Fixtures must be synthetic and safe; exfiltration endpoints are local test listeners or blackholed domains.
- Secrets used in tests are fake canaries.
- Each fixture must emit enough behavior for evidence capture without damaging the host.
- Each fixture must have npm/pip lockfile and no-lockfile variants where applicable.

