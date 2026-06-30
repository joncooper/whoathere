# Detonation Matrix

| Ecosystem | Artifact | Environment | Actions |
| --- | --- | --- | --- |
| npm | tarball | Linux CI `CI=true` | install lifecycle scripts, require/import entrypoints, no-network and recorded-egress modes. |
| npm | tarball | macOS developer | install lifecycle scripts and require/import smoke where platform-compatible. |
| npm | native extension | Linux + macOS contexts | build/import with filesystem and egress monitoring. |
| PyPI | wheel | Linux CI | install and import smoke. |
| PyPI | wheel | macOS developer | install and import smoke where tags match. |
| PyPI | sdist | Linux CI | PEP 517 build, wheel install, import smoke. |
| PyPI | native extension | Linux + macOS contexts | build/import with filesystem and egress monitoring. |

## Evasion Simulation

- `CI=true`
- Changed hostname/user.
- Sleep acceleration or timeout detection.
- Network disabled and recorded-egress modes.
- Direct IP, DNS TXT, DoH, HTTPS, Git SSH/HTTPS attempts.

## Platform Rule

Do not approve a package solely from the current developer platform. Approval must cover the target platform set requested by policy.

