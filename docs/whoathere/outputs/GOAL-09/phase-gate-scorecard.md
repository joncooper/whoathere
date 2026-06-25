# Phase-Gate Scorecard

Each phase gate is executable only when every row has named evidence, a validation environment, a threshold, an approver, and a fail-safe action.

## Global Ship/No-Ship Invariants

| Gate | Owner | Evidence | Environment | Pass threshold | Approver | Fail-safe |
| --- | --- | --- | --- | --- | --- | --- |
| No public fallback | Endpoint + Vault | Egress test logs, registry config audit, CI route proof. | Developer laptop, Linux CI, AWS VPC. | No supported protected workflow reaches public npm/PyPI directly unless explicit policy source allows it through Vault admission. | Security owner. | Block release. |
| No unapproved artifact serving | Vault | CAS/verdict consistency test, tamper test, rollback test. | AWS staging. | Unknown, scanner-failed, detonator-failed, and digest-mismatched artifacts never return 200. | Security owner + Vault owner. | Freeze promotion. |
| No unaudited break-glass | Policy | Audit trace for request, approval, use, expiry, revoke. | Local + Vault staging. | Every use has actor, scope, reason, expiry, decision, and evidence refs. | Security admin owner. | Disable break-glass. |
| Privacy boundary | Ops + Detection | Redaction fixture and data inventory. | Local + Vault staging. | No raw secrets, source trees, full env dumps, full payloads, or arbitrary filesystem snapshots are persisted. | Privacy owner. | Drop/quarantine event fields, block evidence persistence if uncertain. |

## Phase 1 Gate: MVP Local CLI

| Gate | Owner | Evidence | Environment | Pass threshold | Approver | Fail-safe |
| --- | --- | --- | --- | --- | --- | --- |
| CLI/shim workflow coverage | Endpoint | CT-002, CT-003, CT-006, CT-007 local harness. | macOS beta, Linux, Linux container. | Supported commands produce deterministic allow/deny/warn/break-glass-required with audit ID. | Endpoint owner. | Mark unsupported workflow fail-closed in CI/high-risk mode. |
| Linux basic containment | Endpoint | AT-001 through AT-003 local malicious fixtures. | Linux x86_64 and Linux container. | Secrets are denied/redacted; unauthorized egress blocked or captured by local controlled egress path. | Security owner. | No Phase 1 Linux release. |
| macOS beta containment | Endpoint + macOS platform | Beta containment report. | macOS Intel and Apple Silicon. | VM-backed path either contains the fixture or the CLI labels mode as beta-limited and blocks high-risk/CI claims. | Endpoint owner + Product. | Ship macOS as telemetry/interception-only or block distribution. |
| Protected-context bypass guard | Endpoint + CI | Shim bypass tests for absolute npm/pip/python and direct public registry route. | Linux CI and protected workspace. | CI/high-risk paths cannot reach public sources without Vault/policy route. | Security owner. | Fail closed; no bypass warn-only mode. |
| Secure update readiness | Ops | Secure update ADR and signed test release. | Release staging. | Key custody, manifest expiry, rollback protection, revocation, and emergency channel are specified. | Ops owner + Security owner. | No external endpoint distribution. |

## Phase 2 Gate: Advanced Isolation

| Gate | Owner | Evidence | Environment | Pass threshold | Approver | Fail-safe |
| --- | --- | --- | --- | --- | --- | --- |
| Linux hardening | Endpoint | Namespace/seccomp/cgroup/Landlock matrix. | Supported Linux kernels and Docker. | Every supported kernel gets strong, reported, or fail-closed degraded mode. | Endpoint owner. | Unsupported platform blocks high-risk mode. |
| macOS GA containment decision | Endpoint + Product | VM compatibility/performance benchmark and UX report. | macOS Intel and Apple Silicon. | File ownership, symlinks, native artifacts, package caches, and subprocesses work under containment with defined limits. | Product + Security owner. | Remain beta; no GA containment claim. |
| Endpoint network decision table | Endpoint + Security | CT-010 harness. | macOS beta/GA candidate, Linux. | Every network target class has an explicit allow/block/record decision by workflow phase. | Security owner. | Block high-risk workflows. |
| Cleanup leases and janitor | Endpoint | CT-011 failure/signal/crash/sleep tests. | macOS and Linux. | No lingering VM, namespace, mount, socket, firewall/proxy, credential, or temp state after timeout/restart. | Endpoint owner. | Disable affected backend. |

## Phase 3 Gate: Enterprise Vault

| Gate | Owner | Evidence | Environment | Pass threshold | Approver | Fail-safe |
| --- | --- | --- | --- | --- | --- | --- |
| Minimum allow verdict | Vault + Detection | Allow-verdict research output and test fixtures. | AWS staging. | Every artifact type has mandatory evidence, failure behavior, and platform/source coverage before promotion. | Security owner + Detection owner. | Unknown or partial evidence returns pending/manual_review/deny, never allow. |
| Atomic promotion | Vault | CAS/verdict/alias transaction tests and rollback drills. | AWS staging. | No client-observable state can serve an allow verdict without matching promoted CAS and metadata generation. | Vault owner. | Freeze promotion and serve last known good approved generation only. |
| Cold-miss production path | Vault + Detection | PT-003 and OT-002/OT-003 results. | AWS staging and canary. | Cold miss may promote only through minimum allow verdict; scanner/detonator outage never promotes. | Security owner. | Return deterministic 503/pending/manual_review. |
| Fail-closed CI routing | Vault + CI | OT-001 through OT-008. | AWS VPC + CI runners. | CI has no public fallback and fails closed on Vault/policy/scanner ambiguity. | Platform owner. | Disable CI route. |
| Minimum control plane | Product + Vault + Policy | Control-plane research output and API/UX plan. | Staging. | Policy, break-glass, manual review, audit search/export, privacy export/delete, notifications, and admin auth are operable. | Product + Security owner. | No enterprise production launch. |

## Phase 4 Gate: Advanced Detonation

| Gate | Owner | Evidence | Environment | Pass threshold | Approver | Fail-safe |
| --- | --- | --- | --- | --- | --- | --- |
| Full fixture suite | Detection | AT-001 through AT-009. | Linux detonation, selective macOS VM detonation. | Malicious behavior is detected, denied, quarantined, or routed to manual review by artifact-specific policy. | Detection owner + Security owner. | Do not expand allow coverage. |
| Manual review binding | Policy + Detection | Review workflow tests. | Vault staging. | Decisions bind to digest, ecosystem, source, metadata context, policy version, evidence set, approver, and expiry. | Security owner. | Manual review cannot create allow. |
| Incident drills | Ops | Drill reports. | Staging. | Malicious package, false positive, outage, policy misconfiguration, and key compromise drills pass SEV/runbook criteria. | Ops owner. | Block GA/enterprise expansion. |

