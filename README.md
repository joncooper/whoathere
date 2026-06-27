# WhoaThere Timer

A compact macOS menu bar timer for consulting hours.

## WhoaThere Supply Chain Planning

The supply-chain security product planning artifacts live in `docs/whoathere/`.
Start with `docs/whoathere/README.md`; it contains the generated goal packs for turning the WhoaThere meta-plan into build-ready implementation plans.

## WhoaThere Supply Chain Prototype

The current Rust prototype lives in `whoathere/`. It is still local-dev only for endpoint execution: protected install/build/import execution, public registry fetches, OS sandbox enforcement, durable Vault storage, and full production Vault deployment remain gated. Phase 3 adds a bounded Vault data-plane prototype and AWS-first deployment skeleton, not a complete production service. Phase 4 adds typed, fixture-safe dynamic behavior evidence and admin workflow contracts, not arbitrary malware execution.

Useful local checks:

```sh
cargo test --manifest-path whoathere/Cargo.toml
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- doctor
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- doctor --json --state-dir "$HOME/.whoathere/macos-vm-validation" --helper /absolute/path/to/whoathere-macos-vm-helper
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- endpoint setup --shim-dir /tmp/whoathere-shims --workspace "$PWD" --vault-origin http://127.0.0.1:4873 --replay-store /tmp/whoathere-replay-store.txt
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --json --require-ready
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --json --require-ready --scope current
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence providers --scope linux
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence challenge --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-fixture --json --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873 --profile complete
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-admission --json --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873 --profile complete
scripts/whoathere-build-linux-active-probe-image.sh
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-docker --json --execute --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-docker --json --execute --admit --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- evidence linux-active-probe-docker --json --execute --admit --replay-store /tmp/whoathere-replay-store.txt --subject launch-sha256-smoke --context-hash sha256:smoke-context --vault-host 127.0.0.1:4873
scripts/whoathere-linux-active-probe-internal-vault-smoke.sh
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- launch provider-check --execute --workspace whoathere/tests/fixtures/source-clean --vault-origin http://127.0.0.1:4873 --egress-enforced --containment-available npm -- ci
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-compat/npm/fixture
cargo run --manifest-path whoathere/Cargo.toml -p whoathere-cli -- vault dev-http GET /v1/registry-compat/pypi/simple/fixture/
scripts/whoathere-linux-active-probe-docker-smoke.sh
scripts/whoathere-linux-active-probe-docker-admission-smoke.sh
scripts/whoathere-linux-active-probe-admission-smoke.sh
scripts/whoathere-linux-active-probe-fixture-smoke.sh
scripts/whoathere-provider-challenge-smoke.sh
scripts/whoathere-provider-smoke.sh
scripts/whoathere-compat-smoke.sh
scripts/whoathere-endpoint-smoke.sh
```

The local-dev Vault compatibility paths serve only deterministic safe fixture archives after exact promoted-cache lookup. They are not a production package registry.
Vault `/healthz` is liveness only. Vault `/readyz` is fail-closed for protected traffic until real production dependencies are verified.
`evidence providers --json --require-ready` is intentionally fail-closed until real OS containment and Vault-only egress providers can actively verify enforcement; its current posture fields are diagnostics only.
Linux provider diagnostics now include a `provider_active_probe` receipt contract. Current read-only evidence reports the receipt as missing/unsatisfied; future Linux providers must satisfy that challenge-bound receipt before proof verification can be enabled.
`evidence linux-active-probe-fixture` validates deterministic complete/incomplete/overpermissive receipt profiles for the Linux active-probe contract, but always reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
`evidence linux-active-probe-admission` validates that an active-probe receipt is bound to a replay-guard-issued, single-use challenge before it is admissible; accepted admission still reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
`evidence linux-active-probe-docker --execute` runs the local `whoathere/linux-active-probe:local` probe image as non-root user `65532:65532` with `--network none`, no-new-privileges, dropped capabilities, and resource limits, then validates the emitted receipt. With `--docker-network <name>`, it refuses to attach unless Docker reports the network as internal. With `--admit`, it issues a replay-guard-owned challenge, consumes the real Docker receipt through admission, and still remains fail-closed without proof minting or execution authorization. With `--admit --replay-store <path>` or `WHOATHERE_REPLAY_STORE=<path>`, challenge issue/consume state is persisted in the local file-backed replay store using nonce digests rather than raw nonces. The env default is applied only in admission mode. It records UID/GID maps and nested-userns attempt results, remains fail-closed, and always reports `authorization=false`, `proof_minted=false`, and `execution_allowed=false`.
`evidence challenge --subject <id> --context-hash <hash> --vault-host <host>` evaluates an explicit provider challenge against one local provider and remains fail-closed until same-subject containment and Vault-only egress proofs are implemented. JSON challenge output includes the exact sorted `probe_destinations` manifest that a real active-probe executor must attempt.
`launch provider-check` builds the same launch plan as `launch plan`, evaluates the generated proof challenge against the current local provider skeleton, appends `launch_provider_check_*` diagnostics, and remains fail-closed without package execution or OS/network mutation.
Materialized PATH shims call `whoathere protect --execute <tool> -- "$@"`; use `WHOATHERE_WORKSPACE`, `WHOATHERE_VAULT_ORIGIN`, `WHOATHERE_POLICY`, `WHOATHERE_AUDIT_PATH`, and `WHOATHERE_REPLAY_STORE` to provide environment defaults without editing the shim files.
`launch plan` emits `provider_challenge_command=...` whenever it creates a proof challenge, making the generated launch subject/context/Vault host directly testable with `evidence challenge`.
`endpoint setup` prints the shim install command, shell exports including optional `WHOATHERE_REPLAY_STORE`, and current-provider readiness gate; it is diagnostic-only and exits fail-closed until real provider verification exists.
`scripts/whoathere-provider-challenge-smoke.sh` checks the explicit provider challenge JSON contract and expected fail-closed challenge attempt reasons.
`scripts/whoathere-build-linux-active-probe-image.sh` builds the local probe image from the already-present BuildKit base with `--pull=false` and a constrained Docker build context.
`scripts/whoathere-linux-active-probe-admission-smoke.sh` checks replay-owned receipt admission: a complete issued receipt is accepted for admission only, while replayed, unknown, mutated, and incomplete receipts fail closed without proof minting or execution authorization.
`scripts/whoathere-linux-active-probe-docker-smoke.sh` builds and checks the Docker active-probe executor against the local WhoaThere probe image without image pulls or public network access; current output proves the non-root container user, image contract, seccomp, cgroup, no-new-privileges, and no-network denial, but still fails closed on user namespace and Vault allowance gaps.
`scripts/whoathere-linux-active-probe-docker-admission-smoke.sh` checks replay-owned admission against real Docker active-probe output: no-network, `WHOATHERE_REPLAY_STORE` durable replay-store, replayed, and internal-Vault receipt paths all fail closed without proof minting or execution authorization.
`scripts/whoathere-linux-active-probe-internal-vault-smoke.sh` creates a Docker internal network, starts an inert Vault fixture on that network, proves configured-Vault reachability inside the internal network, denies every non-Vault challenge destination by internal-network boundary, and still fails closed without proof minting or launch authorization. The CLI refuses custom Docker networks unless Docker reports them as internal.
`scripts/whoathere-linux-active-probe-fixture-smoke.sh` checks complete, incomplete, and overpermissive Linux active-probe fixture profiles without OS/network mutation or proof minting.
`scripts/whoathere-provider-smoke.sh` checks current-host provider readiness diagnostics, including fail-closed status and no active/package/OS/network/public-probe side effects.
`scripts/whoathere-endpoint-smoke.sh` chains endpoint setup, shim materialization, PATH resolution, and expected-denied `npm ci` plus `pip install` interception in a temp workspace without allowing package-manager execution.

## Run

```sh
swift build
open -n "dist/WhoaThere Timer.app"
```

For development, `swift run whoathere-timer` also works. The app runs as an accessory app, so it appears in the menu bar without a Dock icon.

## Behavior

- Clicking the menu bar item opens a small anchored panel attached to the status item.
- The menu bar item is a quiet `TC` marker while idle. While active, it shows the live elapsed interval.
- The panel focuses on a one-line note, the next timer action, and compact `Today` / `Week` billing progress.
- Focus settings, recent entries, and discard are hidden behind `Details`.
- Stopping an active interval saves it locally in `UserDefaults` for the current user.
