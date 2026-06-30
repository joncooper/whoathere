# Not-Now List

| Item | Reason | Revisit trigger | Owner | Blocks phase? |
| --- | --- | --- | --- | --- |
| Windows endpoint | User set later expansion; macOS/Linux first. | Phase 2 endpoint stable. | Endpoint team | no |
| Full runtime app protection | MVP scope is install/build/import-time. | Design partners require runtime controls. | Product/security | no |
| TLS MITM primary enforcement | Breaks trust/auth and increases liability. | None unless customer explicitly requests separate product. | Architecture | no |
| `LD_PRELOAD`/`DYLD_*` primary enforcement | Bypassable and brittle. | None for primary enforcement. | Endpoint | no |
| Package-manager forks | High maintenance/ecosystem drift. | Shims/config cannot preserve core semantics. | Endpoint | no |
| WASM primary sandbox | Cannot run arbitrary native/npm/pip workflows. | Future package ecosystem supports WASI-native installs. | Architecture | no |
| Non-npm/pip ecosystems | MVP focus. | npm/pip MVP stable and customer demand exists. | Product | no |
| Cloudflare-only Vault | Higher MVP risk for private detonation. | Workers VPC/Containers mature and pass benchmarks. | Vault | no |
| SaaS dashboard polish | Planning focuses CLI/Vault/control APIs. | Phase 3 admin workflows need UX. | Product | no |

