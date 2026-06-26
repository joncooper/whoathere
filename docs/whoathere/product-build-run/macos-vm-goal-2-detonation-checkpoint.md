# WhoaThere macOS VM Goal 2 Detonation Checkpoint

Date: 2026-06-26

## Final Goal 2 Standard Used

Goal 2 is considered usable only when WhoaThere can run supported npm, pip, or uv fixture workflows inside the Apple Silicon macOS guest VM, with no host package execution and no host sync-back. The runner must use sanitized inputs, fake canaries, bounded execution, structured evidence, conservative verdicts, and fail-closed behavior when VM health, guest tooling, workflow support, or job results are missing.

This goal does not claim universal malware detection, safe arbitrary native execution, enterprise package admission, public registry mirroring, runtime application protection, or safe sync-back to the host project.

## What Is Implemented

- `whoathere vm detonate` CLI contract with dry-run planning, `--execute`, `--workspace`, `--state-dir`, `--helper`, `--fixture`, `--timeout-seconds`, and `--json`.
- Host-side detonation planning that records `sync_back_enabled=false`, `host_package_execution_enabled=false`, `high_risk_package_execution_enabled=false`, command class, timeout, fake canary classes, and a sanitized mirror scan.
- Sanitized mirror scanning that counts allowed manifest/lock/build inputs and excludes obvious secrets such as `.env`, `.npmrc`, `.pypirc`, `.ssh`, `.aws`, `.kube`, `.git-credentials`, and private-key paths. Traversal and symlink escapes are blocked.
- Swift helper `detonate` command that requires `--execute`, a live VM runtime, valid host and guest health proofs, a supported tool, a supported command class, and a fixture name before submitting a job.
- Runtime job-file to vsock bridge. The helper writes a bounded job request into WhoaThere-managed state; the live runtime forwards it over the existing guest vsock session; the guest agent returns a sanitized one-line JSON result.
- Guest agent v0.2.0 keeps the readiness connection open after health proof and accepts allowlisted fixture jobs only.
- Guest-side fake canaries for npm, PyPI, GitHub, cloud, Kubernetes, Vault, `.env`-style, and AI-tool credentials.
- Guest-side fixture runner for fixed npm and Python recipes. It detects canary access, mock network/exfil markers, timeouts, command failure, manual-review classes, and missing toolchains without returning raw canary values.
- Guest readiness proof now reports toolchain availability for npm, python3, pip, and uv.

## Current Live Validation State

Local compile/unit validation passes, and dry-run plus fail-closed helper behavior is validated.

Live VM detonation is not yet proven because the validation VM still needs the updated guest agent re-provisioned into the disk image. Non-interactive sudo failed with `sudo: a password is required`.

Run this before live detonation validation:

```sh
sudo /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/scripts/provision-guest-readiness.sh /Users/jdc/.whoathere/macos-vm-validation
```

Then run:

```sh
/Users/jdc/src/whoathere/whoathere/target/debug/whoathere vm start --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --execute
/Users/jdc/src/whoathere/whoathere/target/debug/whoathere vm health --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper
/Users/jdc/src/whoathere/whoathere/target/debug/whoathere vm detonate --state-dir /Users/jdc/.whoathere/macos-vm-validation --helper /Users/jdc/src/whoathere/whoathere/helpers/macos-vm-helper/.build/arm64-apple-macosx/debug/whoathere-macos-vm-helper --fixture clean_npm_lifecycle --timeout-seconds 120 --execute npm -- ci
```

## Attack-Pattern Matrix

| Attack pattern | Recent anchor | Goal 2 posture | Evidence or fixture |
| --- | --- | --- | --- |
| npm maintainer/account compromise publishing a poisoned trusted package | Axios/plain-crypto-js compromise, March 2026 | Detonate or manual-review; no host execution | `npm_postinstall_canary_exfil`, `npm_prepare_remote_fetch`; lifecycle script markers and network/canary evidence |
| npm lifecycle script installs second-stage malware | Axios/plain-crypto-js postinstall RAT | Deny when canary/network markers appear; otherwise record lifecycle execution | npm fixture recipes run `npm install` in guest and inspect canary/network markers |
| Self-propagating credential theft across npm/GitHub/CI | Shai-Hulud and Mini Shai-Hulud campaigns | Deny if canary access or mock egress is observed; no real secrets available to guest | fake npm/GitHub/cloud canaries, `npm_postinstall_canary_exfil`, `delayed_ci_canary` |
| PyPI import-time payload | mistralai PyPI 2.4.6 import-time downloader reports | Detect during `python_import_probe` fixture when pip/python available | `pypi_import_time_canary` / `python_import_time_canary` |
| Python setup.py / PEP 517 build abuse | Ongoing PyPI malicious build/install patterns | Deny on canary access; fail closed on tooling failure | `pypi_setup_py_canary`, `pypi_pep517_canary` |
| `.pth` startup hook | Durable PyPI persistence/evasion class | Manual-review in current guest runner; full startup-hook execution deferred | `python_pth_startup_hook` classification fixture |
| Typosquatting / slopsquatting | 2026 LLM hallucinated package-name research | Not solved by VM alone; source identity and policy should deny/manual-review | dependency-confusion/source-policy remains Phase 1/2; Goal 2 records unsupported package class |
| Dependency confusion | Durable npm/PyPI attack class | Block before detonation through source/package identity gates | existing Phase 1 package identity tests |
| Native extensions and binary wheels | Durable Python/npm native payload class | Manual-review or deny by default | `native_extension_canary`, `binary_wheel_native_marker` |
| Direct URL, VCS, editable dependencies | Durable source substitution class | Deny/manual-review by default | `direct_git_tarball_canary`, `direct_url_vcs_editable` |
| DNS/HTTPS exfiltration | Shai-Hulud-style credential theft and C2 patterns | Detect mock egress markers now; robust packet/DNS capture deferred | `dns_tunneling_canary`, `https_exfil_canary` |
| Platform-specific darwin payload | Axios cross-platform RAT class | Detect when lifecycle fixture runs in macOS guest | `npm_darwin_only_payload` |
| Delayed `CI=true` activation | CI-targeted supply-chain malware | Detect in fixture environment with `CI=true` | `delayed_ci_canary` |
| API-compatible malicious behavior after normal import/constructor call | Recent concern for packages that preserve API shape | Partially supported through import/fixture probes; general runtime behavior remains deferred | `api_compatible_canary_theft` manual-review fixture, future targeted probes |

## Fixture Coverage

| Fixture | Current support | Expected verdict |
| --- | --- | --- |
| `clean_npm_lifecycle` | Guest recipe, requires npm in guest | `allow_observed_clean` if command succeeds |
| `clean_pip_package` | Guest recipe, requires python3 and pip in guest | `allow_observed_clean` if command succeeds |
| `npm_postinstall_canary_exfil` | Guest recipe | `deny_malicious_behavior` |
| `npm_prepare_remote_fetch` | Guest recipe | `deny_malicious_behavior` |
| `npm_darwin_only_payload` | Guest recipe | `deny_malicious_behavior` |
| `delayed_ci_canary` | Guest recipe | `deny_malicious_behavior` |
| `dns_tunneling_canary` | Guest recipe with mock marker | `deny_malicious_behavior` |
| `https_exfil_canary` | Guest recipe with mock marker | `deny_malicious_behavior` |
| `pypi_pep517_canary` | Guest recipe, approximates build-time abuse | `deny_malicious_behavior` |
| `pypi_setup_py_canary` | Guest recipe | `deny_malicious_behavior` |
| `pypi_import_time_canary` | Guest recipe | `deny_malicious_behavior` |
| `native_extension_canary` | Classification-only | `manual_review_risky_class` |
| `binary_wheel_native_marker` | Classification-only | `manual_review_risky_class` |
| `direct_git_tarball_canary` | Classification-only | `manual_review_risky_class` or deny |
| `direct_url_vcs_editable` | Classification-only | `manual_review_risky_class` or deny |
| `uv_unpinned_dependency` | Classification-only | manual review / last-known-good handling deferred |
| `npm_bin_token_theft` | Classification-only | manual review |
| `npm_transitive_malicious_dependency` | Classification-only | manual review |
| `python_pth_startup_hook` | Classification-only | manual review |
| `api_compatible_canary_theft` | Classification-only | manual review |

## Validation Results

Passed:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo clippy --manifest-path whoathere/Cargo.toml --all-targets -- -D warnings
cargo fmt --manifest-path whoathere/Cargo.toml --all -- --check
swift test
cc -O2 -Wall -Wextra -target arm64-apple-macos13 -o /tmp/whoathere-guest-ready-test whoathere/helpers/macos-vm-helper/guest-agent/whoathere-guest-ready.c
```

Focused checks performed:

- `whoathere vm detonate ... npm -- ci` dry-run reports no sync-back, no host package execution, fake canary categories, command class, and sanitized mirror counts.
- `whoathere vm detonate --execute ...` against a stopped validation VM fails closed with `runtime_process_not_running`.
- `sudo -n provision-guest-readiness.sh ...` correctly did not proceed without cached sudo credentials.

Pending:

- Re-provision updated guest agent into validation VM.
- Start VM and prove guest readiness with v0.2.0 agent and toolchain readiness.
- Run clean npm or pip fixture inside VM and receive `allow_observed_clean`.
- Run malicious npm and Python fixtures inside VM and receive deny/manual-review/fail-closed verdicts based on guest evidence.
- Verify no lingering VM runtime or mounted disk remains after live validation.

## Known Limitations

- Project mirror transfer into the guest is not implemented yet. Goal 2 currently supports fixture/local recipes first, not arbitrary project dependency resolution.
- Network evidence is marker-based inside controlled fixtures. Full DNS/HTTPS observation without TLS MITM is deferred.
- uv execution is not implemented in the guest runner; uv fixtures fail closed or manual-review until a guest uv toolchain and recipe are available.
- Native/binary/direct/VCS/editable classes are not executed; they remain manual-review or deny by default.
- The guest runner uses fixed internal fixture recipes and does not expose arbitrary shell execution over the host protocol.

## Sources Used

- Axios/plain-crypto-js compromise reporting: https://www.tomshardware.com/tech-industry/cyber-security/axios-npm-package-compromised-in-supply-chain-attack-that-deployed-a-cross-platform-rat
- Mini Shai-Hulud npm campaign reporting: https://www.techradar.com/pro/security/mini-shai-halud-hackers-publish-over-600-compromised-npm-packages-developers-warned-to-be-on-their-guard
- Mini Shai-Hulud / TanStack / Mistral / PyPI reporting: https://www.tomshardware.com/tech-industry/cyber-security/compromised-mistral-ai-and-tanstack-packages-may-have-exposed-github-cloud-and-ci-cd-credentials-in-mini-shai-hulud-malware-infection-supply-chain-campaign-spreads-across-npm-and-ai-developer-ecosystems-like-wildfire
- Shai-Hulud resurgence reporting: https://www.itpro.com/security/cyber-attacks/shai-hulud-malware-is-back-with-a-vengeance-and-hit-more-than-19-000-github-repositories-so-far-heres-what-developers-need-to-know
- Dynamic-analysis research gap: https://arxiv.org/abs/2505.13804
- PyPI detection research: https://arxiv.org/abs/2606.19063
- Slopsquatting / package hallucination attack-surface research: https://arxiv.org/abs/2605.17062

