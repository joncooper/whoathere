# WhoaThere Phase 2 Isolation Checkpoint

## Scope

Phase 2 hardens local isolation and proof-provider support on top of the completed Phase 1 CLI MVP. It does not deploy Vault, fetch public packages, or run dynamic detonation.

The Phase 2 priority order remains:

1. macOS endpoint behavior first.
2. Linux endpoint and CI behavior second.
3. Windows deferred.

## Implemented Phase 2 Support

Phase 2 now provides an explicit provider control model:

- `diagnostic_only`: read-only evidence or insufficient/off-host prerequisites. This never verifies proofs.
- `partial`: required local primitives are visible, but proof verification is not enabled. This never verifies proofs.
- `beta`: macOS VM/egress/telemetry primitives are visible, but the provider remains beta and proof verification is not enabled. This never verifies proofs.
- `verified`: reserved for a future provider that independently verifies containment and Vault-only egress for the exact challenge. Phase 2 does not report current local providers as verified.

macOS local MVP support:

- Read-only detection for Hypervisor.framework, Virtualization.framework, EndpointSecurity.framework, NetworkExtension.framework, `sandbox-exec`, and `pfctl`.
- A macOS verification plan that requires VM boundary, workspace mount policy, generated package-manager config, packet-filter or NetworkExtension default-deny, EndpointSecurity or audit telemetry, and configured-Vault-only egress.
- Explicit beta labeling when the macOS primitive set is present.
- No package execution, OS mutation, network mutation, proof minting, or launch authorization from macOS diagnostics.

Linux local MVP support:

- Read-only readiness detection for `/proc/self/status`, user/network namespaces, cgroup state, no-new-privileges, seccomp mode, unprivileged user namespaces, Landlock availability, namespace tools, and packet-filter tools.
- A Linux verification plan that requires subject/context binding, user namespace, network namespace, no-new-privileges, seccomp, cgroup scope, Landlock accounting, and configured-Vault-only default-deny egress.
- A challenge-bound active-probe receipt contract with replay-owned admission, required negative network probes, and rejection for missing, mutated, overpermissive, stale, or replayed evidence.
- Docker active-probe diagnostics for local Linux-like execution remain receipt evidence only; they do not mint trusted launch proofs.

## Security Posture

High-risk npm/pip install execution remains fail closed. A launch can proceed toward runtime materialization only if containment and egress proofs are both verified, fresh, same-subject, same-provider-session, same context hash, same configured Vault host, and matched to the generated challenge.

Operator assertions, registry/index steering, read-only provider diagnostics, beta macOS primitives, Linux active-probe receipts, and test-only providers are not accepted as production proof for high-risk package-manager execution.

## Exit Criteria Evidence

| Exit criterion | Evidence |
| --- | --- |
| macOS isolation strategy is implemented to the strongest practical local MVP level and clearly labeled with remaining limits | `MacosContainmentReadiness`, `macos_verification_plan_from_readiness`, macOS provider diagnostics, and this checkpoint document the VM-first beta strategy and fail-closed limits. |
| Linux isolation/proof provider path is implemented to the strongest practical local MVP level and clearly labeled with remaining limits | `LinuxContainmentReadiness`, Linux active-probe receipts/admission, Docker active-probe diagnostics, and this checkpoint document the namespace/seccomp/cgroup/Landlock/packet-filter path and fail-closed limits. |
| Provider readiness distinguishes diagnostics, beta/partial controls, and verified controls | `ProviderControlLevel` is rendered in text and JSON provider diagnostics and in verification-plan JSON. |
| High-risk npm/pip execution remains fail-closed unless both containment and Vault-only egress are verified | Launch and protect tests continue to block high-risk npm/pip execution when proofs are missing, operator-asserted, stale, mismatched, or diagnostic-only. |
| Proofs are bound to subject, context hash, configured Vault host, provider identity, freshness window, and challenge/replay controls | Provider challenges, replay guards, challenge-authority consume binding, active-probe admission, and launch proof checks cover these bindings. |
| Tests cover success and failure paths for macOS and Linux provider readiness, proof validation, stale proof rejection, wrong subject/context/Vault rejection, and operator-assertion rejection | Focused sandbox, launch, and CLI tests cover readiness control levels, challenge validation, active-probe success/failure, stale/wrong proof blocking, and operator assertion rejection. |
| Phase 2 docs state what is implemented, what is not, and what remains for Phase 3 | This checkpoint lists implemented Phase 2 support and deferred Phase 3 work. |

## Not Implemented In Phase 2

- A production-grade macOS VM helper that actually runs npm/pip install/build/import paths.
- Production macOS packet-filter or NetworkExtension rule installation.
- Production EndpointSecurity authorization/telemetry integration.
- A production Linux namespace/seccomp/cgroup/Landlock runner that executes package managers.
- A production Linux packet-filter install/verification path.
- Mapping real provider receipts into trusted launch proofs outside test-support.
- Any Windows support.

## Deferred To Phase 3

- Production Vault deployment.
- Authenticated tenant-aware package proxy.
- Durable package cache, metadata store, queue/workflow orchestration, and production audit sink.
- Real upstream npm/PyPI fetch path.
- Coordination between Vault-issued challenges, production audit, and endpoint provider proof submission.

## Deferred To Phase 4

- Dynamic detonation workers.
- Behavior analysis automation.
- Admin workflows beyond local-dev audit and diagnostics.
