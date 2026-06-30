# Scanner Signal Inventory

## Static Signals

- npm lifecycle scripts: `preinstall`, `install`, `postinstall`, `prepare`, `prepublish`.
- Python build hooks: `setup.py`, PEP 517 backend, `pyproject.toml`.
- Suspicious shell, curl, wget, PowerShell, encoded commands.
- Native binaries and extension markers: `.node`, `.so`, `.dylib`, `.pyd`.
- Obfuscation, packed JS, dynamic eval, base64 payloads.
- Suspicious URLs, IP literals, DNS/DoH endpoints.

## Provenance/Reputation Signals

- New maintainer or ownership change.
- Newly added lifecycle/build script.
- Patch/minor release with high diff risk.
- Missing or changed provenance.
- Newly published package or typo-squat similarity.
- Known malware/vulnerability feeds.

## Dynamic Signals

- Process tree.
- Filesystem reads/writes outside allowed paths.
- DNS/HTTPS egress attempts.
- Environment variable access patterns where feasible.
- CI/hostname/user/time guards.
- Import-time network or process activity.

## Verdict Explanation

Every signal contributes reason codes. Opaque scores alone are not sufficient for deny/manual-review decisions.

