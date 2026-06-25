use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use whoathere_core::{ContainmentBackend, ContainmentStrength, ExecutionMode};
use whoathere_hash::sha256_digest;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxPlan {
    pub backend: ContainmentBackend,
    pub strength: ContainmentStrength,
    pub label: &'static str,
    pub high_risk_allowed: bool,
}

pub trait SandboxBackend {
    fn plan(&self, mode: ExecutionMode) -> SandboxPlan;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicy {
    BlockAll,
    AllowVaultOnly,
    RecordedDetonation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressDecision {
    pub allowed: bool,
    pub reason_code: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderControlLevel {
    DiagnosticOnly,
    Partial,
    Beta,
    Verified,
}

impl ProviderControlLevel {
    pub fn label(self) -> &'static str {
        match self {
            ProviderControlLevel::DiagnosticOnly => "diagnostic_only",
            ProviderControlLevel::Partial => "partial",
            ProviderControlLevel::Beta => "beta",
            ProviderControlLevel::Verified => "verified",
        }
    }
}

pub fn evaluate_egress(policy: EgressPolicy, destination_host: &str) -> EgressDecision {
    match policy {
        EgressPolicy::BlockAll => EgressDecision {
            allowed: false,
            reason_code: "egress_block_all",
        },
        EgressPolicy::AllowVaultOnly => {
            let allowed =
                destination_host == "vault.local" || destination_host.ends_with(".vault.local");
            EgressDecision {
                allowed,
                reason_code: if allowed {
                    "egress_vault_allowed"
                } else {
                    "egress_public_registry_denied"
                },
            }
        }
        EgressPolicy::RecordedDetonation => EgressDecision {
            allowed: true,
            reason_code: "egress_recorded_detonation",
        },
    }
}

pub fn evaluate_configured_vault_egress(
    destination_host: &str,
    configured_vault_host: &str,
) -> EgressDecision {
    let allowed = !configured_vault_host.is_empty() && destination_host == configured_vault_host;
    EgressDecision {
        allowed,
        reason_code: if allowed {
            "egress_configured_vault_allowed"
        } else {
            "egress_non_configured_destination_denied"
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStatus {
    Missing,
    OperatorAsserted,
    Verified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofTrust {
    None,
    OperatorAssertion,
    TrustedLocalProvider,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofMechanism {
    None,
    OperatorAssertion,
    LinuxNamespace,
    MacosVmBeta,
    LinuxPacketFilter,
    MacosPacketFilter,
    TestOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EgressPolicyScope {
    Unknown,
    DefaultDenyExceptConfiguredVault,
}

pub fn mandatory_vault_only_probe_destinations() -> &'static [&'static str] {
    &[
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "github.com",
        "169.254.169.254",
        "127.0.0.1:9000",
        "10.0.0.1",
        "172.16.0.1",
        "192.168.0.1",
        "[::1]:9000",
        "fd00::1",
        "fe80::1",
        "1.1.1.1:53",
        "8.8.8.8:53",
    ]
}

pub fn vault_only_probe_destinations(configured_vault_host: &str) -> Vec<String> {
    let mut probe_destinations = Vec::new();
    if !configured_vault_host.is_empty() {
        probe_destinations.push(configured_vault_host.to_string());
    }
    probe_destinations.extend(
        mandatory_vault_only_probe_destinations()
            .iter()
            .map(|destination| (*destination).to_string()),
    );
    probe_destinations.sort();
    probe_destinations.dedup();
    probe_destinations
}

pub const DEFAULT_PROVIDER_CHALLENGE_TTL_SECONDS: u64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofSubject {
    pub launch_id: String,
}

impl ProofSubject {
    pub fn unbound() -> Self {
        Self {
            launch_id: "unbound".to_string(),
        }
    }

    pub fn for_launch(launch_id: impl Into<String>) -> Self {
        Self {
            launch_id: launch_id.into(),
        }
    }

    pub fn is_bound(&self) -> bool {
        !self.launch_id.is_empty() && self.launch_id != "unbound"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofProvenance {
    pub provider_id: String,
    pub provider_version: String,
    pub platform: String,
    pub mechanism: ProofMechanism,
    pub trust: ProofTrust,
    pub verified_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub context_hash: String,
    pub rule_generation_id: String,
    pub evidence: Vec<String>,
}

impl ProofProvenance {
    pub fn missing() -> Self {
        Self {
            provider_id: "none".to_string(),
            provider_version: "none".to_string(),
            platform: current_platform_label().to_string(),
            mechanism: ProofMechanism::None,
            trust: ProofTrust::None,
            verified_at_unix_seconds: 0,
            expires_at_unix_seconds: 0,
            context_hash: "none".to_string(),
            rule_generation_id: "none".to_string(),
            evidence: Vec::new(),
        }
    }

    pub fn operator_asserted(provider_id: impl Into<String>) -> Self {
        Self {
            provider_id: provider_id.into(),
            provider_version: "operator".to_string(),
            platform: current_platform_label().to_string(),
            mechanism: ProofMechanism::OperatorAssertion,
            trust: ProofTrust::OperatorAssertion,
            verified_at_unix_seconds: 0,
            expires_at_unix_seconds: 0,
            context_hash: "operator-asserted".to_string(),
            rule_generation_id: "operator-asserted".to_string(),
            evidence: Vec::new(),
        }
    }

    pub fn trusted_local_provider(provider_id: impl Into<String>, evidence: &[&str]) -> Self {
        Self::trusted_local_provider_with_mechanism(
            provider_id,
            "test",
            ProofMechanism::TestOnly,
            evidence,
        )
    }

    pub fn trusted_local_provider_for_context(
        provider_id: impl Into<String>,
        evidence: &[&str],
        context_hash: impl Into<String>,
        rule_generation_id: impl Into<String>,
    ) -> Self {
        Self::trusted_local_provider_for_context_with_mechanism(
            provider_id,
            "test",
            ProofMechanism::TestOnly,
            evidence,
            context_hash,
            rule_generation_id,
        )
    }

    pub fn trusted_local_provider_with_mechanism(
        provider_id: impl Into<String>,
        provider_version: impl Into<String>,
        mechanism: ProofMechanism,
        evidence: &[&str],
    ) -> Self {
        Self::trusted_local_provider_for_context_with_mechanism(
            provider_id,
            provider_version,
            mechanism,
            evidence,
            "test-context",
            "test-generation",
        )
    }

    pub fn trusted_local_provider_for_context_with_mechanism(
        provider_id: impl Into<String>,
        provider_version: impl Into<String>,
        mechanism: ProofMechanism,
        evidence: &[&str],
        context_hash: impl Into<String>,
        rule_generation_id: impl Into<String>,
    ) -> Self {
        Self {
            provider_id: provider_id.into(),
            provider_version: provider_version.into(),
            platform: current_platform_label().to_string(),
            mechanism,
            trust: ProofTrust::TrustedLocalProvider,
            verified_at_unix_seconds: 1,
            expires_at_unix_seconds: u64::MAX,
            context_hash: context_hash.into(),
            rule_generation_id: rule_generation_id.into(),
            evidence: evidence.iter().map(|item| (*item).to_string()).collect(),
        }
    }

    pub fn trusted_for_launch(&self) -> bool {
        self.trust == ProofTrust::TrustedLocalProvider
            && !self.provider_id.is_empty()
            && !self.evidence.is_empty()
    }

    pub fn fresh_at(&self, validation_time_unix_seconds: u64) -> bool {
        self.verified_at_unix_seconds <= validation_time_unix_seconds
            && validation_time_unix_seconds < self.expires_at_unix_seconds
    }
}

fn current_platform_label() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        "unknown"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainmentProof {
    status: ProofStatus,
    subject: ProofSubject,
    backend: ContainmentBackend,
    strength: ContainmentStrength,
    mode: ExecutionMode,
    high_risk_allowed: bool,
    provenance: ProofProvenance,
    reason_code: &'static str,
}

impl ContainmentProof {
    pub fn missing(mode: ExecutionMode) -> Self {
        Self {
            status: ProofStatus::Missing,
            subject: ProofSubject::unbound(),
            backend: ContainmentBackend::None,
            strength: ContainmentStrength::FailedClosed,
            mode,
            high_risk_allowed: false,
            provenance: ProofProvenance::missing(),
            reason_code: "containment_proof_missing",
        }
    }

    pub fn operator_asserted(mode: ExecutionMode, backend: ContainmentBackend) -> Self {
        Self {
            status: ProofStatus::OperatorAsserted,
            subject: ProofSubject::unbound(),
            backend,
            strength: ContainmentStrength::FailedClosed,
            mode,
            high_risk_allowed: false,
            provenance: ProofProvenance::operator_asserted("cli-operator-assertion"),
            reason_code: "containment_operator_assertion_not_verified",
        }
    }

    pub fn unavailable_by_provider(
        mode: ExecutionMode,
        subject: ProofSubject,
        provenance: ProofProvenance,
        reason_code: &'static str,
    ) -> Self {
        Self {
            status: ProofStatus::Missing,
            subject,
            backend: ContainmentBackend::None,
            strength: ContainmentStrength::FailedClosed,
            mode,
            high_risk_allowed: false,
            provenance,
            reason_code,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn verified_by_provider(
        subject: ProofSubject,
        plan: SandboxPlan,
        mode: ExecutionMode,
        provenance: ProofProvenance,
    ) -> Self {
        let trusted = provenance.trusted_for_launch() && subject.is_bound();
        let high_risk_allowed = plan.high_risk_allowed
            && plan.strength != ContainmentStrength::FailedClosed
            && plan.backend != ContainmentBackend::None
            && trusted;
        Self {
            status: if high_risk_allowed {
                ProofStatus::Verified
            } else {
                ProofStatus::Missing
            },
            subject,
            backend: plan.backend,
            strength: plan.strength,
            mode,
            high_risk_allowed,
            provenance,
            reason_code: if high_risk_allowed {
                "containment_verified"
            } else if !trusted {
                "containment_provider_not_trusted"
            } else {
                "containment_verified_but_high_risk_not_allowed"
            },
        }
    }

    pub fn permits_high_risk(&self) -> bool {
        self.status == ProofStatus::Verified && self.high_risk_allowed
    }

    pub fn fresh_at(&self, validation_time_unix_seconds: u64) -> bool {
        self.provenance.fresh_at(validation_time_unix_seconds)
    }

    pub fn status(&self) -> ProofStatus {
        self.status
    }

    pub fn subject(&self) -> &ProofSubject {
        &self.subject
    }

    pub fn backend(&self) -> ContainmentBackend {
        self.backend
    }

    pub fn strength(&self) -> ContainmentStrength {
        self.strength
    }

    pub fn provenance(&self) -> &ProofProvenance {
        &self.provenance
    }

    pub fn reason_code(&self) -> &'static str {
        self.reason_code
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressCheck {
    pub destination_host: String,
    pub allowed: bool,
    pub reason_code: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressProof {
    status: ProofStatus,
    subject: ProofSubject,
    policy_scope: EgressPolicyScope,
    configured_vault_host: String,
    checks: Vec<EgressCheck>,
    provenance: ProofProvenance,
    reason_code: &'static str,
}

impl EgressProof {
    pub fn missing() -> Self {
        Self {
            status: ProofStatus::Missing,
            subject: ProofSubject::unbound(),
            policy_scope: EgressPolicyScope::Unknown,
            configured_vault_host: String::new(),
            checks: Vec::new(),
            provenance: ProofProvenance::missing(),
            reason_code: "egress_proof_missing",
        }
    }

    pub fn operator_asserted(configured_vault_host: impl Into<String>) -> Self {
        Self {
            status: ProofStatus::OperatorAsserted,
            subject: ProofSubject::unbound(),
            policy_scope: EgressPolicyScope::Unknown,
            configured_vault_host: configured_vault_host.into(),
            checks: Vec::new(),
            provenance: ProofProvenance::operator_asserted("cli-operator-assertion"),
            reason_code: "egress_operator_assertion_not_verified",
        }
    }

    pub fn unavailable_by_provider(
        configured_vault_host: impl Into<String>,
        subject: ProofSubject,
        provenance: ProofProvenance,
        reason_code: &'static str,
    ) -> Self {
        Self {
            status: ProofStatus::Missing,
            subject,
            policy_scope: EgressPolicyScope::Unknown,
            configured_vault_host: configured_vault_host.into(),
            checks: Vec::new(),
            provenance,
            reason_code,
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn verified_vault_only_by_provider(
        subject: ProofSubject,
        provenance: ProofProvenance,
        policy_scope: EgressPolicyScope,
        configured_vault_host: impl Into<String>,
        destinations: &[&str],
    ) -> Self {
        let configured_vault_host = configured_vault_host.into();
        let trusted = provenance.trusted_for_launch()
            && subject.is_bound()
            && policy_scope == EgressPolicyScope::DefaultDenyExceptConfiguredVault;
        let default_deny_attested = provenance
            .evidence
            .iter()
            .any(|signal| signal == "egress.default_deny_except_configured_vault.attested=true");
        let checks = destinations
            .iter()
            .map(|destination| {
                let decision =
                    evaluate_configured_vault_egress(destination, &configured_vault_host);
                EgressCheck {
                    destination_host: (*destination).to_string(),
                    allowed: decision.allowed,
                    reason_code: decision.reason_code,
                }
            })
            .collect::<Vec<_>>();
        let vault_allowed = checks
            .iter()
            .any(|check| check.destination_host == configured_vault_host && check.allowed);
        let non_vault_denied = checks
            .iter()
            .filter(|check| check.destination_host != configured_vault_host)
            .all(|check| !check.allowed);
        let mandatory_denials_present =
            mandatory_vault_only_probe_destinations()
                .iter()
                .all(|mandatory| {
                    checks
                        .iter()
                        .any(|check| check.destination_host == *mandatory && !check.allowed)
                });
        Self {
            status: if trusted
                && default_deny_attested
                && vault_allowed
                && non_vault_denied
                && mandatory_denials_present
            {
                ProofStatus::Verified
            } else {
                ProofStatus::Missing
            },
            subject,
            policy_scope,
            configured_vault_host,
            checks,
            provenance,
            reason_code: if trusted
                && default_deny_attested
                && vault_allowed
                && non_vault_denied
                && mandatory_denials_present
            {
                "egress_vault_only_verified"
            } else if !trusted {
                "egress_provider_not_trusted"
            } else if !default_deny_attested {
                "egress_default_deny_rule_not_attested"
            } else {
                "egress_vault_only_not_verified"
            },
        }
    }

    pub fn permits_only_configured_vault(&self) -> bool {
        self.status == ProofStatus::Verified
            && self.policy_scope == EgressPolicyScope::DefaultDenyExceptConfiguredVault
            && self.reason_code == "egress_vault_only_verified"
    }

    pub fn fresh_at(&self, validation_time_unix_seconds: u64) -> bool {
        self.provenance.fresh_at(validation_time_unix_seconds)
    }

    pub fn status(&self) -> ProofStatus {
        self.status
    }

    pub fn subject(&self) -> &ProofSubject {
        &self.subject
    }

    pub fn policy_scope(&self) -> EgressPolicyScope {
        self.policy_scope
    }

    pub fn configured_vault_host(&self) -> &str {
        &self.configured_vault_host
    }

    pub fn checks(&self) -> &[EgressCheck] {
        &self.checks
    }

    pub fn provenance(&self) -> &ProofProvenance {
        &self.provenance
    }

    pub fn reason_code(&self) -> &'static str {
        self.reason_code
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderVerificationChallenge {
    pub challenge_id: String,
    pub challenge_nonce: String,
    pub subject: ProofSubject,
    pub context_hash: String,
    pub configured_vault_host: String,
    pub probe_destinations: Vec<String>,
    pub validation_time_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

impl ProviderVerificationChallenge {
    pub fn new(
        subject: ProofSubject,
        context_hash: impl Into<String>,
        configured_vault_host: impl Into<String>,
        validation_time_unix_seconds: u64,
    ) -> Self {
        let context_hash = context_hash.into();
        let configured_vault_host = configured_vault_host.into();
        let nonce_basis = format!(
            "compat-nonce;subject={};context_hash={};configured_vault_host={};validation_time={}",
            subject.launch_id, context_hash, configured_vault_host, validation_time_unix_seconds
        );
        let challenge_nonce = format!("proof-nonce-{}", sha256_digest(nonce_basis.as_bytes()));
        Self::new_with_nonce(
            subject,
            context_hash,
            configured_vault_host,
            validation_time_unix_seconds,
            challenge_nonce,
            validation_time_unix_seconds.saturating_add(DEFAULT_PROVIDER_CHALLENGE_TTL_SECONDS),
        )
    }

    pub fn new_with_nonce(
        subject: ProofSubject,
        context_hash: impl Into<String>,
        configured_vault_host: impl Into<String>,
        validation_time_unix_seconds: u64,
        challenge_nonce: impl Into<String>,
        expires_at_unix_seconds: u64,
    ) -> Self {
        let context_hash = context_hash.into();
        let configured_vault_host = configured_vault_host.into();
        let challenge_nonce = challenge_nonce.into();
        let probe_destinations = vault_only_probe_destinations(&configured_vault_host);
        let challenge_basis = format!(
            "subject={};context_hash={};configured_vault_host={};validation_time={};expires_at={};nonce={};probes={}",
            subject.launch_id,
            context_hash,
            configured_vault_host,
            validation_time_unix_seconds,
            expires_at_unix_seconds,
            challenge_nonce,
            probe_destinations.join(",")
        );
        let challenge_id = format!(
            "proof-challenge-{}",
            sha256_digest(challenge_basis.as_bytes())
        );
        Self {
            challenge_id,
            challenge_nonce,
            subject,
            context_hash,
            configured_vault_host,
            probe_destinations,
            validation_time_unix_seconds,
            expires_at_unix_seconds,
        }
    }

    pub fn reason_codes(&self) -> Vec<&'static str> {
        let mut reasons = Vec::new();
        if !self.subject.is_bound() {
            reasons.push("provider_challenge_subject_unbound");
        }
        if self.context_hash.is_empty() || self.context_hash == "none" {
            reasons.push("provider_challenge_context_hash_missing");
        }
        if self.configured_vault_host.is_empty() {
            reasons.push("provider_challenge_vault_host_missing");
        }
        if self.challenge_nonce.is_empty() {
            reasons.push("provider_challenge_nonce_missing");
        }
        if self.expires_at_unix_seconds <= self.validation_time_unix_seconds {
            reasons.push("provider_challenge_expiry_invalid");
        }
        if !self
            .probe_destinations
            .iter()
            .any(|destination| destination == &self.configured_vault_host)
        {
            reasons.push("provider_challenge_vault_probe_missing");
        }
        if mandatory_vault_only_probe_destinations()
            .iter()
            .any(|mandatory| {
                !self
                    .probe_destinations
                    .iter()
                    .any(|probe| probe == mandatory)
            })
        {
            reasons.push("provider_challenge_mandatory_probe_missing");
        }
        reasons
    }

    pub fn reason_codes_at(&self, now_unix_seconds: u64) -> Vec<&'static str> {
        let mut reasons = self.reason_codes();
        if now_unix_seconds < self.validation_time_unix_seconds {
            reasons.push("provider_challenge_not_yet_valid");
        }
        if now_unix_seconds >= self.expires_at_unix_seconds {
            reasons.push("provider_challenge_expired");
        }
        reasons.sort();
        reasons.dedup();
        reasons
    }

    pub fn valid(&self) -> bool {
        self.reason_codes().is_empty()
    }

    pub fn valid_at(&self, now_unix_seconds: u64) -> bool {
        self.reason_codes_at(now_unix_seconds).is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderChallengeUseStatus {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChallengeUseDecision {
    pub challenge_id: String,
    pub status: ProviderChallengeUseStatus,
    pub reason_codes: Vec<String>,
}

impl ProviderChallengeUseDecision {
    pub fn accepted(&self) -> bool {
        self.status == ProviderChallengeUseStatus::Accepted
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProviderChallengeReplayRecord {
    subject: ProofSubject,
    context_hash: String,
    configured_vault_host: String,
    probe_destinations: Vec<String>,
    challenge_nonce_digest: String,
    validation_time_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    consumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChallengeReplaySnapshot {
    pub challenge_id: String,
    pub subject: ProofSubject,
    pub context_hash: String,
    pub configured_vault_host: String,
    pub probe_destinations: Vec<String>,
    pub challenge_nonce_digest: String,
    pub validation_time_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub consumed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChallengeReplayGuard {
    ttl_seconds: u64,
    next_sequence: u64,
    issued: BTreeMap<String, ProviderChallengeReplayRecord>,
}

impl Default for ProviderChallengeReplayGuard {
    fn default() -> Self {
        Self::new(DEFAULT_PROVIDER_CHALLENGE_TTL_SECONDS)
    }
}

impl ProviderChallengeReplayGuard {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            next_sequence: 0,
            issued: BTreeMap::new(),
        }
    }

    pub fn issue(
        &mut self,
        subject: ProofSubject,
        context_hash: impl Into<String>,
        configured_vault_host: impl Into<String>,
        now_unix_seconds: u64,
    ) -> ProviderVerificationChallenge {
        let context_hash = context_hash.into();
        let configured_vault_host = configured_vault_host.into();
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let nonce_basis = format!(
            "sequence={sequence};subject={};context_hash={};configured_vault_host={};issued_at={now_unix_seconds}",
            subject.launch_id, context_hash, configured_vault_host
        );
        let challenge_nonce = format!("proof-nonce-{}", sha256_digest(nonce_basis.as_bytes()));
        let challenge = ProviderVerificationChallenge::new_with_nonce(
            subject,
            context_hash,
            configured_vault_host,
            now_unix_seconds,
            challenge_nonce,
            now_unix_seconds.saturating_add(self.ttl_seconds),
        );
        self.issued.insert(
            challenge.challenge_id.clone(),
            ProviderChallengeReplayRecord {
                subject: challenge.subject.clone(),
                context_hash: challenge.context_hash.clone(),
                configured_vault_host: challenge.configured_vault_host.clone(),
                probe_destinations: challenge.probe_destinations.clone(),
                challenge_nonce_digest: provider_challenge_nonce_digest(&challenge.challenge_nonce),
                validation_time_unix_seconds: challenge.validation_time_unix_seconds,
                expires_at_unix_seconds: challenge.expires_at_unix_seconds,
                consumed: false,
            },
        );
        challenge
    }

    pub fn consume(
        &mut self,
        challenge: &ProviderVerificationChallenge,
        now_unix_seconds: u64,
    ) -> ProviderChallengeUseDecision {
        let mut reason_codes = challenge
            .reason_codes_at(now_unix_seconds)
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();

        match self.issued.get_mut(&challenge.challenge_id) {
            Some(record) => {
                if record.consumed {
                    reason_codes.push("provider_challenge_replayed".to_string());
                }
                if record.subject != challenge.subject {
                    reason_codes.push("provider_challenge_subject_mutated".to_string());
                }
                if record.context_hash != challenge.context_hash {
                    reason_codes.push("provider_challenge_context_mutated".to_string());
                }
                if record.configured_vault_host != challenge.configured_vault_host {
                    reason_codes.push("provider_challenge_vault_mutated".to_string());
                }
                if record.probe_destinations != challenge.probe_destinations {
                    reason_codes.push("provider_challenge_probe_set_mutated".to_string());
                }
                if record.challenge_nonce_digest
                    != provider_challenge_nonce_digest(&challenge.challenge_nonce)
                {
                    reason_codes.push("provider_challenge_nonce_mismatch".to_string());
                }
                if record.validation_time_unix_seconds != challenge.validation_time_unix_seconds {
                    reason_codes.push("provider_challenge_validation_time_mutated".to_string());
                }
                if record.expires_at_unix_seconds != challenge.expires_at_unix_seconds {
                    reason_codes.push("provider_challenge_expiry_mutated".to_string());
                }
                reason_codes.sort();
                reason_codes.dedup();
                if reason_codes.is_empty() {
                    record.consumed = true;
                    ProviderChallengeUseDecision {
                        challenge_id: challenge.challenge_id.clone(),
                        status: ProviderChallengeUseStatus::Accepted,
                        reason_codes,
                    }
                } else {
                    ProviderChallengeUseDecision {
                        challenge_id: challenge.challenge_id.clone(),
                        status: ProviderChallengeUseStatus::Rejected,
                        reason_codes,
                    }
                }
            }
            None => {
                reason_codes.push("provider_challenge_not_issued".to_string());
                reason_codes.sort();
                reason_codes.dedup();
                ProviderChallengeUseDecision {
                    challenge_id: challenge.challenge_id.clone(),
                    status: ProviderChallengeUseStatus::Rejected,
                    reason_codes,
                }
            }
        }
    }

    pub fn prune_expired(&mut self, now_unix_seconds: u64) -> usize {
        let before = self.issued.len();
        self.issued
            .retain(|_, record| now_unix_seconds < record.expires_at_unix_seconds);
        before.saturating_sub(self.issued.len())
    }

    pub fn snapshots(&self) -> Vec<ProviderChallengeReplaySnapshot> {
        self.issued
            .iter()
            .map(|(challenge_id, record)| ProviderChallengeReplaySnapshot {
                challenge_id: challenge_id.clone(),
                subject: record.subject.clone(),
                context_hash: record.context_hash.clone(),
                configured_vault_host: record.configured_vault_host.clone(),
                probe_destinations: record.probe_destinations.clone(),
                challenge_nonce_digest: record.challenge_nonce_digest.clone(),
                validation_time_unix_seconds: record.validation_time_unix_seconds,
                expires_at_unix_seconds: record.expires_at_unix_seconds,
                consumed: record.consumed,
            })
            .collect()
    }

    pub fn restore(
        ttl_seconds: u64,
        next_sequence: u64,
        snapshots: impl IntoIterator<Item = ProviderChallengeReplaySnapshot>,
    ) -> Self {
        let mut issued = BTreeMap::new();
        for snapshot in snapshots {
            issued.insert(
                snapshot.challenge_id,
                ProviderChallengeReplayRecord {
                    subject: snapshot.subject,
                    context_hash: snapshot.context_hash,
                    configured_vault_host: snapshot.configured_vault_host,
                    probe_destinations: snapshot.probe_destinations,
                    challenge_nonce_digest: snapshot.challenge_nonce_digest,
                    validation_time_unix_seconds: snapshot.validation_time_unix_seconds,
                    expires_at_unix_seconds: snapshot.expires_at_unix_seconds,
                    consumed: snapshot.consumed,
                },
            );
        }
        Self {
            ttl_seconds,
            next_sequence,
            issued,
        }
    }
}

fn provider_challenge_nonce_digest(challenge_nonce: &str) -> String {
    sha256_digest(challenge_nonce.as_bytes())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChallengeReplayFileStore {
    path: PathBuf,
    ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderChallengeReplayFileStoreOperationOutcome {
    pub stale_lock_recovered: bool,
}

impl ProviderChallengeReplayFileStore {
    pub fn new(path: impl Into<PathBuf>, ttl_seconds: u64) -> Self {
        Self {
            path: path.into(),
            ttl_seconds,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn issue(
        &self,
        subject: ProofSubject,
        context_hash: impl Into<String>,
        configured_vault_host: impl Into<String>,
        now_unix_seconds: u64,
    ) -> std::io::Result<ProviderVerificationChallenge> {
        self.issue_with_outcome(
            subject,
            context_hash,
            configured_vault_host,
            now_unix_seconds,
        )
        .map(|(challenge, _outcome)| challenge)
    }

    pub fn issue_with_outcome(
        &self,
        subject: ProofSubject,
        context_hash: impl Into<String>,
        configured_vault_host: impl Into<String>,
        now_unix_seconds: u64,
    ) -> std::io::Result<(
        ProviderVerificationChallenge,
        ProviderChallengeReplayFileStoreOperationOutcome,
    )> {
        let lock = self.acquire_lock(now_unix_seconds)?;
        let outcome = lock.outcome();
        let mut guard = self.read_guard_locked()?;
        guard.prune_expired(now_unix_seconds);
        let challenge = guard.issue(
            subject,
            context_hash,
            configured_vault_host,
            now_unix_seconds,
        );
        self.write_guard_locked(&guard)?;
        Ok((challenge, outcome))
    }

    pub fn consume(
        &self,
        challenge: &ProviderVerificationChallenge,
        now_unix_seconds: u64,
    ) -> std::io::Result<ProviderChallengeUseDecision> {
        self.consume_with_outcome(challenge, now_unix_seconds)
            .map(|(decision, _outcome)| decision)
    }

    pub fn consume_with_outcome(
        &self,
        challenge: &ProviderVerificationChallenge,
        now_unix_seconds: u64,
    ) -> std::io::Result<(
        ProviderChallengeUseDecision,
        ProviderChallengeReplayFileStoreOperationOutcome,
    )> {
        let lock = self.acquire_lock(now_unix_seconds)?;
        let outcome = lock.outcome();
        let mut guard = self.read_guard_locked()?;
        let decision = guard.consume(challenge, now_unix_seconds);
        self.write_guard_locked(&guard)?;
        Ok((decision, outcome))
    }

    pub fn prune_expired(&self, now_unix_seconds: u64) -> std::io::Result<usize> {
        let _lock = self.acquire_lock(now_unix_seconds)?;
        let mut guard = self.read_guard_locked()?;
        let pruned = guard.prune_expired(now_unix_seconds);
        self.write_guard_locked(&guard)?;
        Ok(pruned)
    }

    pub fn snapshots(&self) -> std::io::Result<Vec<ProviderChallengeReplaySnapshot>> {
        let _lock = self.acquire_lock(current_unix_seconds())?;
        Ok(self.read_guard_locked()?.snapshots())
    }

    fn acquire_lock(
        &self,
        now_unix_seconds: u64,
    ) -> std::io::Result<ProviderChallengeReplayFileLock> {
        ProviderChallengeReplayFileLock::acquire(
            provider_challenge_lock_path(&self.path),
            now_unix_seconds,
            self.ttl_seconds.max(1),
        )
    }

    fn read_guard_locked(&self) -> std::io::Result<ProviderChallengeReplayGuard> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => provider_challenge_store_decode(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(ProviderChallengeReplayGuard::new(self.ttl_seconds))
            }
            Err(error) => Err(error),
        }
    }

    fn write_guard_locked(&self, guard: &ProviderChallengeReplayGuard) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = provider_challenge_tmp_path(&self.path);
        let bytes = provider_challenge_store_encode(guard);
        write_private_file_new(&tmp_path, bytes.as_bytes())?;
        fs::rename(&tmp_path, &self.path)?;
        set_private_file_permissions(&self.path)?;
        Ok(())
    }
}

struct ProviderChallengeReplayFileLock {
    path: PathBuf,
    stale_lock_recovered: bool,
}

impl ProviderChallengeReplayFileLock {
    fn acquire(
        path: PathBuf,
        now_unix_seconds: u64,
        stale_after_seconds: u64,
    ) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut stale_lock_recovered = false;
        for _ in 0..50 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    if let Err(error) =
                        write_provider_challenge_lock_file(&mut file, now_unix_seconds)
                    {
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    if let Err(error) = set_private_file_permissions(&path) {
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self {
                        path,
                        stale_lock_recovered,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if provider_challenge_lock_is_stale(
                        &path,
                        now_unix_seconds,
                        stale_after_seconds,
                    )? {
                        match fs::remove_file(&path) {
                            Ok(()) => {
                                stale_lock_recovered = true;
                                continue;
                            }
                            Err(remove_error)
                                if remove_error.kind() == std::io::ErrorKind::NotFound =>
                            {
                                stale_lock_recovered = true;
                                continue;
                            }
                            Err(remove_error) => return Err(remove_error),
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "provider challenge replay store lock busy",
        ))
    }

    fn outcome(&self) -> ProviderChallengeReplayFileStoreOperationOutcome {
        ProviderChallengeReplayFileStoreOperationOutcome {
            stale_lock_recovered: self.stale_lock_recovered,
        }
    }
}

const PROVIDER_CHALLENGE_LOCK_SCHEMA: &str = "whoathere.provider_challenge_replay_lock.v1";

fn write_provider_challenge_lock_file(
    file: &mut std::fs::File,
    now_unix_seconds: u64,
) -> std::io::Result<()> {
    use std::io::Write;

    writeln!(file, "{PROVIDER_CHALLENGE_LOCK_SCHEMA}")?;
    writeln!(file, "created_at_unix_seconds={now_unix_seconds}")?;
    writeln!(file, "pid={}", std::process::id())?;
    file.flush()
}

fn provider_challenge_lock_is_stale(
    path: &Path,
    now_unix_seconds: u64,
    stale_after_seconds: u64,
) -> std::io::Result<bool> {
    match fs::read_to_string(path) {
        Ok(contents) => match provider_challenge_lock_created_at(&contents) {
            Some(created_at) => {
                Ok(now_unix_seconds.saturating_sub(created_at) > stale_after_seconds)
            }
            None => provider_challenge_lock_metadata_is_stale(path, stale_after_seconds),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn provider_challenge_lock_metadata_is_stale(
    path: &Path,
    stale_after_seconds: u64,
) -> std::io::Result<bool> {
    let modified = fs::metadata(path)?.modified()?;
    match std::time::SystemTime::now().duration_since(modified) {
        Ok(age) => Ok(age.as_secs() > stale_after_seconds),
        Err(_) => Ok(false),
    }
}

fn provider_challenge_lock_created_at(contents: &str) -> Option<u64> {
    let mut lines = contents.lines();
    if lines.next()? != PROVIDER_CHALLENGE_LOCK_SCHEMA {
        return None;
    }
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key == "created_at_unix_seconds" {
            return value.parse::<u64>().ok();
        }
    }
    None
}

impl Drop for ProviderChallengeReplayFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn provider_challenge_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn provider_challenge_tmp_path(path: &Path) -> PathBuf {
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    PathBuf::from(tmp_path)
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn write_private_file_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    set_private_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

const PROVIDER_CHALLENGE_STORE_SCHEMA: &str = "whoathere.provider_challenge_replay_store.v1";

fn provider_challenge_store_encode(guard: &ProviderChallengeReplayGuard) -> String {
    let mut lines = vec![
        PROVIDER_CHALLENGE_STORE_SCHEMA.to_string(),
        format!("ttl_seconds={}", guard.ttl_seconds),
        format!("next_sequence={}", guard.next_sequence),
    ];
    for snapshot in guard.snapshots() {
        lines.push(format!(
            "record challenge_id={} subject={} context_hash={} configured_vault_host={} probe_destinations={} challenge_nonce_digest={} validation_time_unix_seconds={} expires_at_unix_seconds={} consumed={}",
            hex_encode(snapshot.challenge_id.as_bytes()),
            hex_encode(snapshot.subject.launch_id.as_bytes()),
            hex_encode(snapshot.context_hash.as_bytes()),
            hex_encode(snapshot.configured_vault_host.as_bytes()),
            snapshot
                .probe_destinations
                .iter()
                .map(|probe| hex_encode(probe.as_bytes()))
                .collect::<Vec<_>>()
                .join(","),
            hex_encode(snapshot.challenge_nonce_digest.as_bytes()),
            snapshot.validation_time_unix_seconds,
            snapshot.expires_at_unix_seconds,
            snapshot.consumed
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn provider_challenge_store_decode(
    contents: &str,
) -> std::io::Result<ProviderChallengeReplayGuard> {
    let mut lines = contents.lines();
    if lines.next() != Some(PROVIDER_CHALLENGE_STORE_SCHEMA) {
        return Err(invalid_provider_challenge_store("schema"));
    }
    let ttl_seconds = parse_store_u64(lines.next(), "ttl_seconds")?;
    let next_sequence = parse_store_u64(lines.next(), "next_sequence")?;
    let mut snapshots = Vec::new();
    let mut challenge_ids = BTreeSet::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some(fields) = line.strip_prefix("record ") else {
            return Err(invalid_provider_challenge_store("record_prefix"));
        };
        let snapshot = provider_challenge_snapshot_decode(fields)?;
        if !challenge_ids.insert(snapshot.challenge_id.clone()) {
            return Err(invalid_provider_challenge_store("duplicate_challenge_id"));
        }
        snapshots.push(snapshot);
    }
    Ok(ProviderChallengeReplayGuard::restore(
        ttl_seconds,
        next_sequence,
        snapshots,
    ))
}

fn parse_store_u64(line: Option<&str>, key: &str) -> std::io::Result<u64> {
    let Some(line) = line else {
        return Err(invalid_provider_challenge_store(key));
    };
    let Some(value) = line.strip_prefix(&format!("{key}=")) else {
        return Err(invalid_provider_challenge_store(key));
    };
    value
        .parse::<u64>()
        .map_err(|_| invalid_provider_challenge_store(key))
}

fn provider_challenge_snapshot_decode(
    fields: &str,
) -> std::io::Result<ProviderChallengeReplaySnapshot> {
    let mut map = BTreeMap::new();
    for field in fields.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            return Err(invalid_provider_challenge_store("record_field"));
        };
        if map.insert(key, value).is_some() {
            return Err(invalid_provider_challenge_store("duplicate_field"));
        }
    }
    let challenge_id = hex_decode_string(required_store_field(&map, "challenge_id")?)?;
    let subject =
        ProofSubject::for_launch(hex_decode_string(required_store_field(&map, "subject")?)?);
    let context_hash = hex_decode_string(required_store_field(&map, "context_hash")?)?;
    let configured_vault_host =
        hex_decode_string(required_store_field(&map, "configured_vault_host")?)?;
    let probe_destinations = required_store_field(&map, "probe_destinations")?
        .split(',')
        .filter(|encoded| !encoded.is_empty())
        .map(hex_decode_string)
        .collect::<std::io::Result<Vec<_>>>()?;
    let challenge_nonce_digest =
        hex_decode_string(required_store_field(&map, "challenge_nonce_digest")?)?;
    let validation_time_unix_seconds = parse_record_u64(&map, "validation_time_unix_seconds")?;
    let expires_at_unix_seconds = parse_record_u64(&map, "expires_at_unix_seconds")?;
    let consumed = match required_store_field(&map, "consumed")? {
        "true" => true,
        "false" => false,
        _ => return Err(invalid_provider_challenge_store("consumed")),
    };
    Ok(ProviderChallengeReplaySnapshot {
        challenge_id,
        subject,
        context_hash,
        configured_vault_host,
        probe_destinations,
        challenge_nonce_digest,
        validation_time_unix_seconds,
        expires_at_unix_seconds,
        consumed,
    })
}

fn required_store_field<'a>(map: &'a BTreeMap<&str, &str>, key: &str) -> std::io::Result<&'a str> {
    map.get(key)
        .copied()
        .ok_or_else(|| invalid_provider_challenge_store(key))
}

fn parse_record_u64(map: &BTreeMap<&str, &str>, key: &str) -> std::io::Result<u64> {
    required_store_field(map, key)?
        .parse::<u64>()
        .map_err(|_| invalid_provider_challenge_store(key))
}

fn invalid_provider_challenge_store(field: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("invalid provider challenge replay store: {field}"),
    )
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(hex_digit(byte >> 4));
        encoded.push(hex_digit(byte & 0x0f));
    }
    encoded
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble is always 0..=15"),
    }
}

fn hex_decode_string(value: &str) -> std::io::Result<String> {
    let bytes = hex_decode(value)?;
    String::from_utf8(bytes).map_err(|_| invalid_provider_challenge_store("utf8"))
}

fn hex_decode(value: &str) -> std::io::Result<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid_provider_challenge_store("hex_length"));
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let high = hex_value(chunk[0])?;
        let low = hex_value(chunk[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn hex_value(value: u8) -> std::io::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid_provider_challenge_store("hex")),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChallengeAttempt {
    pub challenge_id: String,
    pub provider_id: String,
    pub subject: ProofSubject,
    pub context_hash: String,
    pub configured_vault_host: String,
    pub probe_destination_count: usize,
    pub containment_status: ProofStatus,
    pub egress_status: ProofStatus,
    pub challenge_satisfied: bool,
    pub reason_codes: Vec<String>,
}

impl ProviderChallengeAttempt {
    pub fn from_proofs(
        challenge: &ProviderVerificationChallenge,
        containment: &ContainmentProof,
        egress: &EgressProof,
    ) -> Self {
        let mut reason_codes = challenge
            .reason_codes()
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        if !containment.permits_high_risk() {
            reason_codes.push(containment.reason_code().to_string());
        }
        if !egress.permits_only_configured_vault() {
            reason_codes.push(egress.reason_code().to_string());
        }
        if containment.subject() != &challenge.subject {
            reason_codes.push("provider_challenge_containment_subject_mismatch".to_string());
        }
        if egress.subject() != &challenge.subject {
            reason_codes.push("provider_challenge_egress_subject_mismatch".to_string());
        }
        if containment.provenance().context_hash != challenge.context_hash {
            reason_codes.push("provider_challenge_containment_context_mismatch".to_string());
        }
        if egress.provenance().context_hash != challenge.context_hash {
            reason_codes.push("provider_challenge_egress_context_mismatch".to_string());
        }
        if egress.configured_vault_host() != challenge.configured_vault_host {
            reason_codes.push("provider_challenge_egress_vault_mismatch".to_string());
        }
        if containment.provenance().provider_id != egress.provenance().provider_id {
            reason_codes.push("provider_challenge_provider_id_mismatch".to_string());
        }
        if containment.provenance().platform != egress.provenance().platform {
            reason_codes.push("provider_challenge_provider_platform_mismatch".to_string());
        }
        if containment.provenance().rule_generation_id != egress.provenance().rule_generation_id {
            reason_codes.push("provider_challenge_rule_generation_mismatch".to_string());
        }
        for probe in &challenge.probe_destinations {
            match egress
                .checks()
                .iter()
                .find(|check| check.destination_host == *probe)
            {
                Some(check) if *probe == challenge.configured_vault_host && !check.allowed => {
                    reason_codes.push("provider_challenge_vault_probe_denied".to_string());
                }
                Some(check) if *probe != challenge.configured_vault_host && check.allowed => {
                    reason_codes.push("provider_challenge_non_vault_probe_allowed".to_string());
                }
                Some(_) => {}
                None => reason_codes.push("provider_challenge_egress_probe_missing".to_string()),
            }
        }
        if !containment.fresh_at(challenge.validation_time_unix_seconds)
            || !egress.fresh_at(challenge.validation_time_unix_seconds)
        {
            reason_codes.push("provider_challenge_proof_not_fresh".to_string());
        }
        reason_codes.sort();
        reason_codes.dedup();
        Self {
            challenge_id: challenge.challenge_id.clone(),
            provider_id: containment.provenance().provider_id.clone(),
            subject: challenge.subject.clone(),
            context_hash: challenge.context_hash.clone(),
            configured_vault_host: challenge.configured_vault_host.clone(),
            probe_destination_count: challenge.probe_destinations.len(),
            containment_status: containment.status(),
            egress_status: egress.status(),
            challenge_satisfied: reason_codes.is_empty(),
            reason_codes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderChallengeProofs {
    pub containment: ContainmentProof,
    pub egress: EgressProof,
}

#[cfg(any(test, feature = "test-support"))]
pub mod test_support {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TestOnlyProofProvider {
        subject: ProofSubject,
        configured_vault_host: String,
        context_hash: String,
    }

    impl TestOnlyProofProvider {
        pub fn new(launch_id: impl Into<String>, configured_vault_host: impl Into<String>) -> Self {
            Self::new_for_context(launch_id, configured_vault_host, "test-context")
        }

        pub fn new_for_context(
            launch_id: impl Into<String>,
            configured_vault_host: impl Into<String>,
            context_hash: impl Into<String>,
        ) -> Self {
            Self {
                subject: ProofSubject::for_launch(launch_id),
                configured_vault_host: configured_vault_host.into(),
                context_hash: context_hash.into(),
            }
        }

        pub fn subject(&self) -> ProofSubject {
            self.subject.clone()
        }

        fn provenance_for_context(&self, context_hash: impl Into<String>) -> ProofProvenance {
            ProofProvenance::trusted_local_provider_for_context(
                "sandbox-test-only-provider",
                &[
                    "test-only-provider-harness",
                    "egress.default_deny_except_configured_vault.attested=true",
                ],
                context_hash,
                "test-generation",
            )
        }
    }

    impl ProofProvider for TestOnlyProofProvider {
        fn provenance(&self) -> ProofProvenance {
            self.provenance_for_context(self.context_hash.clone())
        }

        fn prove_containment(&self, mode: ExecutionMode) -> ContainmentProof {
            ContainmentProof::verified_by_provider(
                self.subject.clone(),
                SandboxPlan {
                    backend: ContainmentBackend::LinuxNamespace,
                    strength: ContainmentStrength::Strong,
                    label: "test-only provider containment",
                    high_risk_allowed: true,
                },
                mode,
                self.provenance(),
            )
        }

        fn prove_containment_for_challenge(
            &self,
            challenge: &ProviderVerificationChallenge,
            mode: ExecutionMode,
        ) -> ContainmentProof {
            ContainmentProof::verified_by_provider(
                challenge.subject.clone(),
                SandboxPlan {
                    backend: ContainmentBackend::LinuxNamespace,
                    strength: ContainmentStrength::Strong,
                    label: "test-only provider challenge containment",
                    high_risk_allowed: true,
                },
                mode,
                self.provenance_for_context(challenge.context_hash.clone()),
            )
        }

        fn prove_egress(
            &self,
            subject: ProofSubject,
            configured_vault_host: &str,
            probe_destinations: &[&str],
        ) -> EgressProof {
            let mut destinations = vault_only_probe_destinations(configured_vault_host);
            destinations.extend(
                probe_destinations
                    .iter()
                    .map(|destination| (*destination).to_string()),
            );
            destinations.sort();
            destinations.dedup();
            let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
            EgressProof::verified_vault_only_by_provider(
                subject,
                self.provenance(),
                EgressPolicyScope::DefaultDenyExceptConfiguredVault,
                configured_vault_host,
                &destination_refs,
            )
        }

        fn prove_egress_for_challenge(
            &self,
            challenge: &ProviderVerificationChallenge,
        ) -> EgressProof {
            let destination_refs = challenge
                .probe_destinations
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            EgressProof::verified_vault_only_by_provider(
                challenge.subject.clone(),
                self.provenance_for_context(challenge.context_hash.clone()),
                EgressPolicyScope::DefaultDenyExceptConfiguredVault,
                &challenge.configured_vault_host,
                &destination_refs,
            )
        }
    }

    pub fn verified_containment(subject: &str) -> ContainmentProof {
        verified_containment_for_context(subject, "test-context")
    }

    pub fn verified_containment_for_context(subject: &str, context_hash: &str) -> ContainmentProof {
        verified_containment_for_context_and_rule(subject, context_hash, "test-generation")
    }

    pub fn verified_containment_for_context_and_rule(
        subject: &str,
        context_hash: &str,
        rule_generation_id: &str,
    ) -> ContainmentProof {
        ContainmentProof::verified_by_provider(
            ProofSubject::for_launch(subject),
            SandboxPlan {
                backend: ContainmentBackend::LinuxNamespace,
                strength: ContainmentStrength::Strong,
                label: "test-only verified containment",
                high_risk_allowed: true,
            },
            ExecutionMode::CiFailClosed,
            ProofProvenance::trusted_local_provider_for_context(
                "sandbox-test-only-provider",
                &["test-only-containment"],
                context_hash,
                rule_generation_id,
            ),
        )
    }

    pub fn expired_containment(subject: &str) -> ContainmentProof {
        expired_containment_for_context(subject, "test-context")
    }

    pub fn expired_containment_for_context(subject: &str, context_hash: &str) -> ContainmentProof {
        ContainmentProof::verified_by_provider(
            ProofSubject::for_launch(subject),
            SandboxPlan {
                backend: ContainmentBackend::LinuxNamespace,
                strength: ContainmentStrength::Strong,
                label: "test-only expired containment",
                high_risk_allowed: true,
            },
            ExecutionMode::CiFailClosed,
            expired_provenance("test-only-expired-containment", context_hash),
        )
    }

    pub fn verified_egress(subject: &str, configured_vault_host: &str) -> EgressProof {
        verified_egress_for_context(subject, configured_vault_host, "test-context")
    }

    pub fn verified_egress_for_context(
        subject: &str,
        configured_vault_host: &str,
        context_hash: &str,
    ) -> EgressProof {
        verified_egress_for_context_and_rule(
            subject,
            configured_vault_host,
            context_hash,
            "test-generation",
        )
    }

    pub fn verified_egress_for_context_and_rule(
        subject: &str,
        configured_vault_host: &str,
        context_hash: &str,
        rule_generation_id: &str,
    ) -> EgressProof {
        let destinations = vault_only_probe_destinations(configured_vault_host);
        let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
        EgressProof::verified_vault_only_by_provider(
            ProofSubject::for_launch(subject),
            ProofProvenance::trusted_local_provider_for_context(
                "sandbox-test-only-provider",
                &[
                    "test-only-egress",
                    "egress.default_deny_except_configured_vault.attested=true",
                ],
                context_hash,
                rule_generation_id,
            ),
            EgressPolicyScope::DefaultDenyExceptConfiguredVault,
            configured_vault_host,
            &destination_refs,
        )
    }

    pub fn expired_egress(subject: &str, configured_vault_host: &str) -> EgressProof {
        expired_egress_for_context(subject, configured_vault_host, "test-context")
    }

    pub fn expired_egress_for_context(
        subject: &str,
        configured_vault_host: &str,
        context_hash: &str,
    ) -> EgressProof {
        let destinations = vault_only_probe_destinations(configured_vault_host);
        let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
        EgressProof::verified_vault_only_by_provider(
            ProofSubject::for_launch(subject),
            expired_provenance("test-only-expired-egress", context_hash),
            EgressPolicyScope::DefaultDenyExceptConfiguredVault,
            configured_vault_host,
            &destination_refs,
        )
    }

    fn expired_provenance(evidence: &'static str, context_hash: &str) -> ProofProvenance {
        let mut provenance = ProofProvenance::trusted_local_provider_for_context(
            "sandbox-test-only-provider",
            &[
                evidence,
                "egress.default_deny_except_configured_vault.attested=true",
            ],
            context_hash,
            "test-generation",
        );
        provenance.verified_at_unix_seconds = 1;
        provenance.expires_at_unix_seconds = 2;
        provenance
    }
}

pub trait ProofProvider {
    fn provenance(&self) -> ProofProvenance;

    fn prove_containment(&self, mode: ExecutionMode) -> ContainmentProof;

    fn prove_egress(
        &self,
        subject: ProofSubject,
        configured_vault_host: &str,
        probe_destinations: &[&str],
    ) -> EgressProof;

    fn prove_containment_for_challenge(
        &self,
        _challenge: &ProviderVerificationChallenge,
        mode: ExecutionMode,
    ) -> ContainmentProof {
        self.prove_containment(mode)
    }

    fn prove_egress_for_challenge(&self, challenge: &ProviderVerificationChallenge) -> EgressProof {
        let probe_destinations = challenge
            .probe_destinations
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>();
        self.prove_egress(
            challenge.subject.clone(),
            &challenge.configured_vault_host,
            &probe_destinations,
        )
    }

    fn prove_challenge(
        &self,
        challenge: &ProviderVerificationChallenge,
        mode: ExecutionMode,
    ) -> ProviderChallengeProofs {
        ProviderChallengeProofs {
            containment: self.prove_containment_for_challenge(challenge, mode),
            egress: self.prove_egress_for_challenge(challenge),
        }
    }

    fn evaluate_challenge(
        &self,
        challenge: &ProviderVerificationChallenge,
        mode: ExecutionMode,
    ) -> ProviderChallengeAttempt {
        let proofs = self.prove_challenge(challenge, mode);
        ProviderChallengeAttempt::from_proofs(challenge, &proofs.containment, &proofs.egress)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderPlatform {
    Linux,
    Macos,
}

impl LocalProviderPlatform {
    fn label(self) -> &'static str {
        match self {
            LocalProviderPlatform::Linux => "linux",
            LocalProviderPlatform::Macos => "macos",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxContainmentReadiness {
    pub control_level: ProviderControlLevel,
    pub target_matches_host: Option<bool>,
    pub proc_status_available: bool,
    pub user_namespace_observed: bool,
    pub net_namespace_observed: bool,
    pub cgroup_available: bool,
    pub no_new_privs: Option<bool>,
    pub seccomp_mode: Option<u8>,
    pub unprivileged_userns_clone: Option<bool>,
    pub landlock_abi_version: Option<u32>,
    pub namespace_creation_tool_available: bool,
    pub packet_filter_tool_available: bool,
    pub required_primitives_present: bool,
    pub proof_verification_enabled: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosContainmentReadiness {
    pub control_level: ProviderControlLevel,
    pub target_matches_host: Option<bool>,
    pub hypervisor_framework_available: bool,
    pub virtualization_framework_available: bool,
    pub endpointsecurity_framework_available: bool,
    pub network_extension_framework_available: bool,
    pub sandbox_exec_available: bool,
    pub pfctl_available: bool,
    pub vm_isolation_primitives_present: bool,
    pub egress_control_primitives_present: bool,
    pub telemetry_primitives_present: bool,
    pub required_primitives_present: bool,
    pub beta_containment: bool,
    pub proof_verification_enabled: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalVerificationPlan {
    pub platform: &'static str,
    pub enforcement_strategy: &'static str,
    pub control_level: ProviderControlLevel,
    pub prerequisites_present: bool,
    pub proof_verification_enabled: bool,
    pub can_verify_now: bool,
    pub required_checks: Vec<String>,
    pub blocking_reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProviderEvidencePosture {
    pub schema_version: Option<String>,
    pub status: Option<String>,
    pub verdict: Option<String>,
    pub target_platform: Option<String>,
    pub host_platform: Option<String>,
    pub target_matches_host: Option<bool>,
    pub active_verification_enabled: Option<bool>,
    pub package_execution_attempted: Option<bool>,
    pub os_mutation_attempted: Option<bool>,
    pub network_mutation_attempted: Option<bool>,
    pub public_network_probe_attempted: Option<bool>,
}

pub const LINUX_ACTIVE_PROBE_SCHEMA_VERSION: &str = "linux_active_probe.v1";
pub const LINUX_ACTIVE_PROBE_COMPLETE_STATUS: &str = "active_probe_complete";
pub const LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE: &str = "provider_namespace_only";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxActiveProbeFixtureProfile {
    Complete,
    Incomplete,
    Overpermissive,
}

impl LinuxActiveProbeFixtureProfile {
    pub fn label(self) -> &'static str {
        match self {
            LinuxActiveProbeFixtureProfile::Complete => "complete",
            LinuxActiveProbeFixtureProfile::Incomplete => "incomplete",
            LinuxActiveProbeFixtureProfile::Overpermissive => "overpermissive",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxActiveProbeReceipt {
    pub schema_version: Option<String>,
    pub status: Option<String>,
    pub target_matches_host: Option<bool>,
    pub challenge_id: Option<String>,
    pub subject: Option<String>,
    pub context_hash: Option<String>,
    pub configured_vault_host: Option<String>,
    pub user_namespace_isolated: Option<bool>,
    pub user_namespace_uid: Option<String>,
    pub user_namespace_gid: Option<String>,
    pub user_namespace_uid_map: Option<String>,
    pub user_namespace_gid_map: Option<String>,
    pub nested_user_namespace_attempt: Option<String>,
    pub nested_user_namespace_created: Option<bool>,
    pub nested_user_namespace_uid_map: Option<String>,
    pub nested_user_namespace_gid_map: Option<String>,
    pub network_namespace_isolated: Option<bool>,
    pub no_new_privs: Option<bool>,
    pub seccomp_filter_enforced: Option<bool>,
    pub cgroup_scoped: Option<bool>,
    pub default_deny_except_configured_vault: Option<bool>,
    pub package_execution_attempted: Option<bool>,
    pub os_mutation_scope: Option<String>,
    pub network_mutation_scope: Option<String>,
    pub public_network_probe_attempted: Option<bool>,
    pub allowed_destinations: Vec<String>,
    pub denied_destinations: Vec<String>,
    pub missing_probe_destinations: Vec<String>,
    pub allowed_non_vault_destinations: Vec<String>,
    pub satisfied: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxActiveProbeAdmission {
    pub challenge_id: String,
    pub replay_decision: ProviderChallengeUseDecision,
    pub receipt: LinuxActiveProbeReceipt,
    pub accepted: bool,
    pub reason_codes: Vec<String>,
}

pub fn admit_linux_active_probe_receipt(
    guard: &mut ProviderChallengeReplayGuard,
    challenge: &ProviderVerificationChallenge,
    evidence: &[String],
    now_unix_seconds: u64,
) -> LinuxActiveProbeAdmission {
    let replay_decision = guard.consume(challenge, now_unix_seconds);
    admit_linux_active_probe_receipt_with_replay_decision(replay_decision, challenge, evidence)
}

pub fn admit_linux_active_probe_receipt_with_replay_decision(
    replay_decision: ProviderChallengeUseDecision,
    challenge: &ProviderVerificationChallenge,
    evidence: &[String],
) -> LinuxActiveProbeAdmission {
    let receipt = linux_active_probe_receipt_from_evidence(challenge, evidence);
    let mut reason_codes = replay_decision.reason_codes.clone();
    if !receipt.satisfied {
        reason_codes.extend(receipt.reason_codes.iter().cloned());
    }
    reason_codes.sort();
    reason_codes.dedup();
    let accepted = replay_decision.accepted() && receipt.satisfied && reason_codes.is_empty();
    LinuxActiveProbeAdmission {
        challenge_id: challenge.challenge_id.clone(),
        replay_decision,
        receipt,
        accepted,
        reason_codes,
    }
}

pub fn collect_local_provider_evidence(platform: LocalProviderPlatform) -> Vec<String> {
    match platform {
        LocalProviderPlatform::Linux => collect_linux_provider_evidence(),
        LocalProviderPlatform::Macos => collect_macos_provider_evidence(),
    }
}

pub fn local_provider_evidence_posture_from_evidence(
    evidence: &[String],
) -> LocalProviderEvidencePosture {
    LocalProviderEvidencePosture {
        schema_version: evidence_value(evidence, "provider_evidence_schema=").map(str::to_string),
        status: evidence_value(evidence, "provider_status=").map(str::to_string),
        verdict: evidence_value(evidence, "provider_verdict=").map(str::to_string),
        target_platform: evidence_value(evidence, "provider_target_platform=").map(str::to_string),
        host_platform: evidence_value(evidence, "provider_host_platform=").map(str::to_string),
        target_matches_host: evidence_value(evidence, "provider_target_matches_host=")
            .and_then(parse_bool_flag),
        active_verification_enabled: evidence_value(
            evidence,
            "provider_active_verification.enabled=",
        )
        .and_then(parse_bool_flag),
        package_execution_attempted: evidence_value(
            evidence,
            "provider_package_execution_attempted=",
        )
        .and_then(parse_bool_flag),
        os_mutation_attempted: evidence_value(evidence, "provider_os_mutation_attempted=")
            .and_then(parse_bool_flag),
        network_mutation_attempted: evidence_value(
            evidence,
            "provider_network_mutation_attempted=",
        )
        .and_then(parse_bool_flag),
        public_network_probe_attempted: evidence_value(
            evidence,
            "provider_public_network_probe_attempted=",
        )
        .and_then(parse_bool_flag),
    }
}

pub fn linux_active_probe_receipt_from_evidence(
    challenge: &ProviderVerificationChallenge,
    evidence: &[String],
) -> LinuxActiveProbeReceipt {
    let schema_version = evidence_value(evidence, "provider_evidence_schema=").map(str::to_string);
    let status = evidence_value(evidence, "provider_status=").map(str::to_string);
    let target_matches_host =
        evidence_value(evidence, "provider_target_matches_host=").and_then(parse_bool_flag);
    let challenge_id = evidence_value(evidence, "provider_challenge_id=").map(str::to_string);
    let subject = evidence_value(evidence, "provider_challenge_subject=").map(str::to_string);
    let context_hash =
        evidence_value(evidence, "provider_challenge_context_hash=").map(str::to_string);
    let configured_vault_host =
        evidence_value(evidence, "provider_challenge_configured_vault_host=").map(str::to_string);
    let user_namespace_isolated =
        evidence_value(evidence, "linux.active_probe.user_namespace.isolated=")
            .and_then(parse_bool_flag);
    let user_namespace_uid =
        evidence_value(evidence, "linux.active_probe.user_namespace.uid=").map(str::to_string);
    let user_namespace_gid =
        evidence_value(evidence, "linux.active_probe.user_namespace.gid=").map(str::to_string);
    let user_namespace_uid_map =
        evidence_value(evidence, "linux.active_probe.user_namespace.uid_map=").map(str::to_string);
    let user_namespace_gid_map =
        evidence_value(evidence, "linux.active_probe.user_namespace.gid_map=").map(str::to_string);
    let nested_user_namespace_attempt = evidence_value(
        evidence,
        "linux.active_probe.user_namespace.nested_attempt=",
    )
    .map(str::to_string);
    let nested_user_namespace_created = evidence_value(
        evidence,
        "linux.active_probe.user_namespace.nested_created=",
    )
    .and_then(parse_bool_flag);
    let nested_user_namespace_uid_map = evidence_value(
        evidence,
        "linux.active_probe.user_namespace.nested_uid_map=",
    )
    .map(str::to_string);
    let nested_user_namespace_gid_map = evidence_value(
        evidence,
        "linux.active_probe.user_namespace.nested_gid_map=",
    )
    .map(str::to_string);
    let network_namespace_isolated =
        evidence_value(evidence, "linux.active_probe.network_namespace.isolated=")
            .and_then(parse_bool_flag);
    let no_new_privs =
        evidence_value(evidence, "linux.active_probe.no_new_privs=").and_then(parse_bool_flag);
    let seccomp_filter_enforced =
        evidence_value(evidence, "linux.active_probe.seccomp_filter.enforced=")
            .and_then(parse_bool_flag);
    let cgroup_scoped =
        evidence_value(evidence, "linux.active_probe.cgroup.scoped=").and_then(parse_bool_flag);
    let default_deny_except_configured_vault = evidence_value(
        evidence,
        "linux.active_probe.egress.default_deny_except_configured_vault=",
    )
    .and_then(parse_bool_flag);
    let package_execution_attempted =
        evidence_value(evidence, "provider_package_execution_attempted=").and_then(parse_bool_flag);
    let os_mutation_scope =
        evidence_value(evidence, "linux.active_probe.os_mutation_scope=").map(str::to_string);
    let network_mutation_scope =
        evidence_value(evidence, "linux.active_probe.network_mutation_scope=").map(str::to_string);
    let public_network_probe_attempted =
        evidence_value(evidence, "provider_public_network_probe_attempted=")
            .and_then(parse_bool_flag);
    let allowed_destinations =
        sorted_evidence_values(evidence, "linux.active_probe.egress.allowed=");
    let denied_destinations = sorted_evidence_values(evidence, "linux.active_probe.egress.denied=");
    let allowed_set = allowed_destinations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    let denied_set = denied_destinations
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();

    let mut reason_codes = Vec::new();
    if schema_version.as_deref() != Some(LINUX_ACTIVE_PROBE_SCHEMA_VERSION) {
        reason_codes.push("linux_active_probe_receipt_missing".to_string());
        if schema_version.is_some() {
            reason_codes.push("linux_active_probe_schema_invalid".to_string());
        }
    }
    if status.as_deref() != Some(LINUX_ACTIVE_PROBE_COMPLETE_STATUS) {
        reason_codes.push("linux_active_probe_not_complete".to_string());
    }
    if target_matches_host != Some(true) {
        reason_codes.push("linux_active_probe_target_not_current_host".to_string());
    }
    if challenge_id.as_deref() != Some(challenge.challenge_id.as_str()) {
        reason_codes.push("linux_active_probe_challenge_id_mismatch".to_string());
    }
    if subject.as_deref() != Some(challenge.subject.launch_id.as_str()) {
        reason_codes.push("linux_active_probe_subject_mismatch".to_string());
    }
    if context_hash.as_deref() != Some(challenge.context_hash.as_str()) {
        reason_codes.push("linux_active_probe_context_mismatch".to_string());
    }
    if configured_vault_host.as_deref() != Some(challenge.configured_vault_host.as_str()) {
        reason_codes.push("linux_active_probe_vault_mismatch".to_string());
    }
    if user_namespace_isolated != Some(true) {
        reason_codes.push("linux_active_probe_user_namespace_not_isolated".to_string());
    }
    if network_namespace_isolated != Some(true) {
        reason_codes.push("linux_active_probe_network_namespace_not_isolated".to_string());
    }
    if no_new_privs != Some(true) {
        reason_codes.push("linux_active_probe_no_new_privs_not_enforced".to_string());
    }
    if seccomp_filter_enforced != Some(true) {
        reason_codes.push("linux_active_probe_seccomp_not_enforced".to_string());
    }
    if cgroup_scoped != Some(true) {
        reason_codes.push("linux_active_probe_cgroup_not_scoped".to_string());
    }
    if default_deny_except_configured_vault != Some(true) {
        reason_codes.push("linux_active_probe_default_deny_not_attested".to_string());
    }
    if package_execution_attempted != Some(false) {
        reason_codes.push("linux_active_probe_package_execution_attempted".to_string());
    }
    if os_mutation_scope.as_deref() != Some(LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE) {
        reason_codes.push("linux_active_probe_os_mutation_scope_invalid".to_string());
    }
    if network_mutation_scope.as_deref() != Some(LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE) {
        reason_codes.push("linux_active_probe_network_mutation_scope_invalid".to_string());
    }
    if public_network_probe_attempted != Some(false) {
        reason_codes.push("linux_active_probe_public_network_probe_attempted".to_string());
    }

    let vault_host = challenge.configured_vault_host.as_str();
    if denied_set.contains(vault_host) {
        reason_codes.push("linux_active_probe_vault_probe_denied".to_string());
    }
    if !allowed_set.contains(vault_host) {
        reason_codes.push("linux_active_probe_vault_probe_missing".to_string());
    }

    let mut missing_probe_destinations = Vec::new();
    let mut allowed_non_vault_destinations = Vec::new();
    for probe in &challenge.probe_destinations {
        if probe == vault_host {
            continue;
        }
        if allowed_set.contains(probe.as_str()) {
            allowed_non_vault_destinations.push(probe.clone());
        }
        if !denied_set.contains(probe.as_str()) {
            missing_probe_destinations.push(probe.clone());
        }
    }
    if !allowed_non_vault_destinations.is_empty() {
        reason_codes.push("linux_active_probe_non_vault_probe_allowed".to_string());
    }
    if !missing_probe_destinations.is_empty() {
        reason_codes.push("linux_active_probe_denied_probe_missing".to_string());
    }

    reason_codes.sort();
    reason_codes.dedup();
    LinuxActiveProbeReceipt {
        schema_version,
        status,
        target_matches_host,
        challenge_id,
        subject,
        context_hash,
        configured_vault_host,
        user_namespace_isolated,
        user_namespace_uid,
        user_namespace_gid,
        user_namespace_uid_map,
        user_namespace_gid_map,
        nested_user_namespace_attempt,
        nested_user_namespace_created,
        nested_user_namespace_uid_map,
        nested_user_namespace_gid_map,
        network_namespace_isolated,
        no_new_privs,
        seccomp_filter_enforced,
        cgroup_scoped,
        default_deny_except_configured_vault,
        package_execution_attempted,
        os_mutation_scope,
        network_mutation_scope,
        public_network_probe_attempted,
        allowed_destinations,
        denied_destinations,
        missing_probe_destinations,
        allowed_non_vault_destinations,
        satisfied: reason_codes.is_empty(),
        reason_codes,
    }
}

pub fn linux_active_probe_fixture_evidence(
    challenge: &ProviderVerificationChallenge,
    profile: LinuxActiveProbeFixtureProfile,
) -> Vec<String> {
    let mut evidence = vec![
        format!("provider_evidence_schema={LINUX_ACTIVE_PROBE_SCHEMA_VERSION}"),
        format!(
            "provider_status={}",
            match profile {
                LinuxActiveProbeFixtureProfile::Incomplete => "active_probe_incomplete",
                LinuxActiveProbeFixtureProfile::Complete
                | LinuxActiveProbeFixtureProfile::Overpermissive => {
                    LINUX_ACTIVE_PROBE_COMPLETE_STATUS
                }
            }
        ),
        "provider_target_matches_host=true".to_string(),
        format!("provider_challenge_id={}", challenge.challenge_id),
        format!("provider_challenge_subject={}", challenge.subject.launch_id),
        format!("provider_challenge_context_hash={}", challenge.context_hash),
        format!(
            "provider_challenge_configured_vault_host={}",
            challenge.configured_vault_host
        ),
        "provider_package_execution_attempted=false".to_string(),
        "provider_public_network_probe_attempted=false".to_string(),
    ];

    if profile != LinuxActiveProbeFixtureProfile::Incomplete {
        evidence.extend([
            "linux.active_probe.user_namespace.isolated=true".to_string(),
            "linux.active_probe.network_namespace.isolated=true".to_string(),
            "linux.active_probe.no_new_privs=true".to_string(),
            "linux.active_probe.seccomp_filter.enforced=true".to_string(),
            "linux.active_probe.cgroup.scoped=true".to_string(),
            "linux.active_probe.egress.default_deny_except_configured_vault=true".to_string(),
            format!("linux.active_probe.os_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"),
            format!(
                "linux.active_probe.network_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"
            ),
        ]);
    }

    for probe in &challenge.probe_destinations {
        let allowed = probe == &challenge.configured_vault_host
            || (profile == LinuxActiveProbeFixtureProfile::Overpermissive
                && probe == "registry.npmjs.org");
        if allowed {
            evidence.push(format!("linux.active_probe.egress.allowed={probe}"));
        } else if profile != LinuxActiveProbeFixtureProfile::Incomplete {
            evidence.push(format!("linux.active_probe.egress.denied={probe}"));
        }
    }

    evidence
}

pub fn linux_verification_plan_from_readiness(
    readiness: &LinuxContainmentReadiness,
) -> LocalVerificationPlan {
    LocalVerificationPlan {
        platform: "linux",
        enforcement_strategy: "namespace_seccomp_cgroup_landlock_packet_filter",
        control_level: readiness.control_level,
        prerequisites_present: readiness.required_primitives_present,
        proof_verification_enabled: readiness.proof_verification_enabled,
        can_verify_now: readiness.required_primitives_present
            && readiness.proof_verification_enabled,
        required_checks: string_list(&[
            "bind_launch_subject_context_hash",
            "verify_user_namespace",
            "verify_network_namespace",
            "verify_no_new_privs",
            "verify_seccomp_filter",
            "verify_cgroup_scope",
            "verify_landlock_or_record_unavailable",
            "verify_default_deny_except_configured_vault",
        ]),
        blocking_reason_codes: readiness.reason_codes.clone(),
    }
}

pub fn macos_verification_plan_from_readiness(
    readiness: &MacosContainmentReadiness,
) -> LocalVerificationPlan {
    LocalVerificationPlan {
        platform: "macos",
        enforcement_strategy: "virtualization_vm_packet_filter_endpoint_telemetry",
        control_level: readiness.control_level,
        prerequisites_present: readiness.required_primitives_present,
        proof_verification_enabled: readiness.proof_verification_enabled,
        can_verify_now: readiness.required_primitives_present
            && readiness.proof_verification_enabled,
        required_checks: string_list(&[
            "bind_launch_subject_context_hash",
            "verify_virtualization_vm_boundary",
            "verify_workspace_mount_policy",
            "verify_generated_package_manager_config",
            "verify_packet_filter_or_network_extension_default_deny",
            "verify_endpointsecurity_or_audit_telemetry",
            "verify_default_deny_except_configured_vault",
        ]),
        blocking_reason_codes: readiness.reason_codes.clone(),
    }
}

pub fn linux_containment_readiness_from_evidence(evidence: &[String]) -> LinuxContainmentReadiness {
    let target_matches_host =
        evidence_value(evidence, "provider_target_matches_host=").and_then(parse_bool_flag);
    let proc_status_available = evidence_has_exact(evidence, "linux.proc_self_status.present=true");
    let user_namespace_observed =
        evidence_has_exact(evidence, "linux.proc_self_ns_user.present=true");
    let net_namespace_observed =
        evidence_has_exact(evidence, "linux.proc_self_ns_net.present=true");
    let cgroup_available = evidence_has_exact(evidence, "linux.cgroup_self.present=true");
    let no_new_privs = evidence_value(evidence, "linux.no_new_privs=").and_then(parse_bool_flag);
    let seccomp_mode =
        evidence_value(evidence, "linux.seccomp_mode=").and_then(|value| value.parse::<u8>().ok());
    let unprivileged_userns_clone =
        evidence_value(evidence, "linux.unprivileged_userns_clone=").and_then(parse_bool_flag);
    let landlock_abi_version = evidence_value(evidence, "linux.landlock_abi_version=")
        .and_then(|value| value.parse::<u32>().ok());
    let namespace_creation_tool_available =
        evidence_has_exact(evidence, "linux.unshare.present=true")
            || evidence_has_exact(evidence, "linux.bubblewrap.present=true");
    let packet_filter_tool_available = evidence_has_exact(evidence, "linux.nft.present=true")
        || evidence_has_exact(evidence, "linux.iptables.present=true");

    let mut reason_codes = Vec::new();
    if target_matches_host != Some(true) {
        reason_codes.push("linux_provider_target_not_current_host".to_string());
    }
    if !proc_status_available {
        reason_codes.push("linux_proc_status_unavailable".to_string());
    }
    if !user_namespace_observed {
        reason_codes.push("linux_user_namespace_unobserved".to_string());
    }
    if !net_namespace_observed {
        reason_codes.push("linux_net_namespace_unobserved".to_string());
    }
    if !cgroup_available {
        reason_codes.push("linux_cgroup_unobserved".to_string());
    }
    if no_new_privs != Some(true) {
        reason_codes.push("linux_no_new_privs_not_observed".to_string());
    }
    if seccomp_mode.unwrap_or(0) == 0 {
        reason_codes.push("linux_seccomp_not_observed".to_string());
    }
    if unprivileged_userns_clone != Some(true) {
        reason_codes.push("linux_unprivileged_userns_clone_not_enabled".to_string());
    }
    if landlock_abi_version.is_none() {
        reason_codes.push("linux_landlock_abi_unavailable".to_string());
    }
    if !namespace_creation_tool_available {
        reason_codes.push("linux_namespace_creation_tool_unavailable".to_string());
    }
    if !packet_filter_tool_available {
        reason_codes.push("linux_packet_filter_tool_unavailable".to_string());
    }
    reason_codes.push("linux_proof_verification_not_implemented".to_string());

    let required_primitives_present = target_matches_host == Some(true)
        && proc_status_available
        && user_namespace_observed
        && net_namespace_observed
        && cgroup_available
        && no_new_privs == Some(true)
        && seccomp_mode.unwrap_or(0) > 0
        && unprivileged_userns_clone == Some(true)
        && namespace_creation_tool_available
        && packet_filter_tool_available;

    let proof_verification_enabled = false;
    let control_level = if required_primitives_present && proof_verification_enabled {
        ProviderControlLevel::Verified
    } else if required_primitives_present {
        ProviderControlLevel::Partial
    } else {
        ProviderControlLevel::DiagnosticOnly
    };

    LinuxContainmentReadiness {
        control_level,
        target_matches_host,
        proc_status_available,
        user_namespace_observed,
        net_namespace_observed,
        cgroup_available,
        no_new_privs,
        seccomp_mode,
        unprivileged_userns_clone,
        landlock_abi_version,
        namespace_creation_tool_available,
        packet_filter_tool_available,
        required_primitives_present,
        proof_verification_enabled,
        reason_codes,
    }
}

pub fn macos_containment_readiness_from_evidence(evidence: &[String]) -> MacosContainmentReadiness {
    let target_matches_host =
        evidence_value(evidence, "provider_target_matches_host=").and_then(parse_bool_flag);
    let hypervisor_framework_available =
        evidence_has_exact(evidence, "macos.hypervisor_framework.present=true");
    let virtualization_framework_available =
        evidence_has_exact(evidence, "macos.virtualization_framework.present=true");
    let endpointsecurity_framework_available =
        evidence_has_exact(evidence, "macos.endpointsecurity_framework.present=true");
    let network_extension_framework_available =
        evidence_has_exact(evidence, "macos.network_extension_framework.present=true");
    let sandbox_exec_available = evidence_has_exact(evidence, "macos.sandbox_exec.present=true");
    let pfctl_available = evidence_has_exact(evidence, "macos.pfctl.present=true");

    let vm_isolation_primitives_present =
        hypervisor_framework_available && virtualization_framework_available;
    let egress_control_primitives_present =
        network_extension_framework_available || pfctl_available;
    let telemetry_primitives_present = endpointsecurity_framework_available;
    let required_primitives_present = target_matches_host == Some(true)
        && vm_isolation_primitives_present
        && egress_control_primitives_present
        && telemetry_primitives_present;

    let mut reason_codes = Vec::new();
    if target_matches_host != Some(true) {
        reason_codes.push("macos_provider_target_not_current_host".to_string());
    }
    if !hypervisor_framework_available {
        reason_codes.push("macos_hypervisor_framework_unavailable".to_string());
    }
    if !virtualization_framework_available {
        reason_codes.push("macos_virtualization_framework_unavailable".to_string());
    }
    if !endpointsecurity_framework_available {
        reason_codes.push("macos_endpointsecurity_framework_unavailable".to_string());
    }
    if !network_extension_framework_available && !pfctl_available {
        reason_codes.push("macos_egress_control_unavailable".to_string());
    }
    if !sandbox_exec_available {
        reason_codes.push("macos_sandbox_exec_unavailable".to_string());
    }
    reason_codes.push("macos_vm_containment_beta".to_string());
    reason_codes.push("macos_proof_verification_not_implemented".to_string());

    let proof_verification_enabled = false;
    let control_level = if required_primitives_present && proof_verification_enabled {
        ProviderControlLevel::Verified
    } else if required_primitives_present {
        ProviderControlLevel::Beta
    } else if target_matches_host == Some(true)
        && (vm_isolation_primitives_present
            || egress_control_primitives_present
            || telemetry_primitives_present)
    {
        ProviderControlLevel::Partial
    } else {
        ProviderControlLevel::DiagnosticOnly
    };

    MacosContainmentReadiness {
        control_level,
        target_matches_host,
        hypervisor_framework_available,
        virtualization_framework_available,
        endpointsecurity_framework_available,
        network_extension_framework_available,
        sandbox_exec_available,
        pfctl_available,
        vm_isolation_primitives_present,
        egress_control_primitives_present,
        telemetry_primitives_present,
        required_primitives_present,
        beta_containment: true,
        proof_verification_enabled,
        reason_codes,
    }
}

fn string_list(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn collect_linux_provider_evidence() -> Vec<String> {
    let mut evidence = local_provider_evidence_prelude(LocalProviderPlatform::Linux);
    evidence.extend(path_presence_signal(
        "linux.proc_self_status.present",
        "/proc/self/status",
    ));
    if let Ok(status) = fs::read_to_string("/proc/self/status") {
        evidence.extend(proc_status_value(
            &status,
            "NoNewPrivs",
            "linux.no_new_privs",
        ));
        evidence.extend(proc_status_value(&status, "Seccomp", "linux.seccomp_mode"));
    }
    evidence.extend(read_link_signal(
        "linux.proc_self_ns_user",
        "/proc/self/ns/user",
    ));
    evidence.extend(read_link_signal(
        "linux.proc_init_ns_user",
        "/proc/1/ns/user",
    ));
    evidence.extend(read_link_signal(
        "linux.proc_self_ns_net",
        "/proc/self/ns/net",
    ));
    evidence.extend(read_link_signal("linux.proc_init_ns_net", "/proc/1/ns/net"));
    evidence.extend(read_trimmed_file_signal(
        "linux.unprivileged_userns_clone",
        "/proc/sys/kernel/unprivileged_userns_clone",
    ));
    evidence.extend(path_presence_signal(
        "linux.cgroup_self.present",
        "/proc/self/cgroup",
    ));
    evidence.extend(read_trimmed_file_signal(
        "linux.landlock_abi_version",
        "/proc/sys/kernel/landlock/abi_version",
    ));
    evidence.extend(path_presence_any_signal(
        "linux.unshare.present",
        &["/usr/bin/unshare", "/bin/unshare"],
    ));
    evidence.extend(path_presence_any_signal(
        "linux.bubblewrap.present",
        &["/usr/bin/bwrap", "/bin/bwrap"],
    ));
    evidence.extend(path_presence_any_signal(
        "linux.newuidmap.present",
        &["/usr/bin/newuidmap", "/bin/newuidmap"],
    ));
    evidence.extend(path_presence_any_signal(
        "linux.newgidmap.present",
        &["/usr/bin/newgidmap", "/bin/newgidmap"],
    ));
    evidence.extend(path_presence_any_signal(
        "linux.nft.present",
        &["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"],
    ));
    evidence.extend(path_presence_any_signal(
        "linux.iptables.present",
        &[
            "/usr/sbin/iptables",
            "/sbin/iptables",
            "/usr/bin/iptables",
            "/bin/iptables",
        ],
    ));
    evidence
}

fn collect_macos_provider_evidence() -> Vec<String> {
    let mut evidence = local_provider_evidence_prelude(LocalProviderPlatform::Macos);
    evidence.extend(path_presence_signal(
        "macos.hypervisor_framework.present",
        "/System/Library/Frameworks/Hypervisor.framework",
    ));
    evidence.extend(path_presence_signal(
        "macos.virtualization_framework.present",
        "/System/Library/Frameworks/Virtualization.framework",
    ));
    evidence.extend(path_presence_signal(
        "macos.endpointsecurity_framework.present",
        "/System/Library/Frameworks/EndpointSecurity.framework",
    ));
    evidence.extend(path_presence_signal(
        "macos.network_extension_framework.present",
        "/System/Library/Frameworks/NetworkExtension.framework",
    ));
    evidence.extend(path_presence_signal(
        "macos.sandbox_exec.present",
        "/usr/bin/sandbox-exec",
    ));
    evidence.extend(path_presence_signal("macos.pfctl.present", "/sbin/pfctl"));
    evidence
}

fn local_provider_evidence_prelude(platform: LocalProviderPlatform) -> Vec<String> {
    let target = platform.label();
    let host = current_platform_label();
    vec![
        "provider_evidence_schema=local_provider_readiness.v1".to_string(),
        "provider_status=read_only_probe".to_string(),
        "provider_verdict=not_verified".to_string(),
        format!("provider_host_platform={host}"),
        format!("provider_target_platform={target}"),
        format!("provider_target_matches_host={}", host == target),
        format!("platform_target={target}"),
        "provider_active_verification.enabled=false".to_string(),
        "provider_package_execution_attempted=false".to_string(),
        "provider_os_mutation_attempted=false".to_string(),
        "provider_network_mutation_attempted=false".to_string(),
        "provider_public_network_probe_attempted=false".to_string(),
    ]
}

fn path_presence_signal(key: &str, path: impl AsRef<Path>) -> Vec<String> {
    vec![format!("{key}={}", path.as_ref().exists())]
}

fn path_presence_any_signal(key: &str, paths: &[&str]) -> Vec<String> {
    let present_path = paths.iter().find(|path| Path::new(path).exists());
    let mut signals = vec![format!("{key}={}", present_path.is_some())];
    if let Some(path) = present_path {
        signals.push(format!("{key}.path={path}"));
    }
    signals
}

fn read_link_signal(key: &str, path: impl AsRef<Path>) -> Vec<String> {
    match fs::read_link(path.as_ref()) {
        Ok(target) => vec![
            format!("{key}.present=true"),
            format!("{key}.target={}", target.display()),
        ],
        Err(_) => vec![format!("{key}.present=false")],
    }
}

fn read_trimmed_file_signal(key: &str, path: impl AsRef<Path>) -> Vec<String> {
    match fs::read_to_string(path.as_ref()) {
        Ok(value) => vec![format!("{key}={}", value.trim())],
        Err(_) => vec![format!("{key}=unavailable")],
    }
}

fn proc_status_value(status: &str, source_key: &str, output_key: &str) -> Vec<String> {
    status
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| *key == source_key)
                .map(|(_, value)| format!("{output_key}={}", value.trim()))
        })
        .into_iter()
        .collect()
}

fn evidence_has_exact(evidence: &[String], expected: &str) -> bool {
    evidence.iter().any(|signal| signal == expected)
}

fn evidence_value<'a>(evidence: &'a [String], prefix: &str) -> Option<&'a str> {
    evidence
        .iter()
        .find_map(|signal| signal.strip_prefix(prefix))
}

fn sorted_evidence_values(evidence: &[String], prefix: &str) -> Vec<String> {
    let mut values = evidence
        .iter()
        .filter_map(|signal| signal.strip_prefix(prefix))
        .map(str::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values.dedup();
    values
}

fn parse_bool_flag(value: &str) -> Option<bool> {
    match value {
        "1" | "true" => Some(true),
        "0" | "false" => Some(false),
        _ => None,
    }
}

pub struct FailClosedProofProvider {
    pub provider_id: &'static str,
}

impl ProofProvider for FailClosedProofProvider {
    fn provenance(&self) -> ProofProvenance {
        ProofProvenance {
            provider_id: self.provider_id.to_string(),
            provider_version: "unimplemented".to_string(),
            platform: current_platform_label().to_string(),
            mechanism: ProofMechanism::None,
            trust: ProofTrust::None,
            verified_at_unix_seconds: 0,
            expires_at_unix_seconds: 0,
            context_hash: "unimplemented".to_string(),
            rule_generation_id: "unimplemented".to_string(),
            evidence: Vec::new(),
        }
    }

    fn prove_containment(&self, mode: ExecutionMode) -> ContainmentProof {
        ContainmentProof::unavailable_by_provider(
            mode,
            ProofSubject::unbound(),
            self.provenance(),
            "containment_provider_unimplemented",
        )
    }

    fn prove_egress(
        &self,
        subject: ProofSubject,
        configured_vault_host: &str,
        _probe_destinations: &[&str],
    ) -> EgressProof {
        EgressProof::unavailable_by_provider(
            configured_vault_host,
            subject,
            self.provenance(),
            "egress_provider_unimplemented",
        )
    }

    fn prove_containment_for_challenge(
        &self,
        challenge: &ProviderVerificationChallenge,
        mode: ExecutionMode,
    ) -> ContainmentProof {
        ContainmentProof::unavailable_by_provider(
            mode,
            challenge.subject.clone(),
            fail_closed_challenge_provenance(self.provider_id, challenge),
            "containment_provider_unimplemented",
        )
    }

    fn prove_egress_for_challenge(&self, challenge: &ProviderVerificationChallenge) -> EgressProof {
        EgressProof::unavailable_by_provider(
            &challenge.configured_vault_host,
            challenge.subject.clone(),
            fail_closed_challenge_provenance(self.provider_id, challenge),
            "egress_provider_unimplemented",
        )
    }
}

pub struct LinuxLocalProofProvider;

impl ProofProvider for LinuxLocalProofProvider {
    fn provenance(&self) -> ProofProvenance {
        unavailable_provider_provenance_with_evidence(
            "linux-local-proof-provider",
            "linux",
            ProofMechanism::None,
            collect_local_provider_evidence(LocalProviderPlatform::Linux),
        )
    }

    fn prove_containment(&self, mode: ExecutionMode) -> ContainmentProof {
        ContainmentProof::unavailable_by_provider(
            mode,
            ProofSubject::unbound(),
            unavailable_provider_provenance_with_evidence(
                "linux-local-proof-provider",
                "linux",
                ProofMechanism::LinuxNamespace,
                collect_local_provider_evidence(LocalProviderPlatform::Linux),
            ),
            "linux_containment_provider_unimplemented",
        )
    }

    fn prove_egress(
        &self,
        subject: ProofSubject,
        configured_vault_host: &str,
        _probe_destinations: &[&str],
    ) -> EgressProof {
        EgressProof::unavailable_by_provider(
            configured_vault_host,
            subject,
            unavailable_provider_provenance_with_evidence(
                "linux-local-proof-provider",
                "linux",
                ProofMechanism::LinuxPacketFilter,
                collect_local_provider_evidence(LocalProviderPlatform::Linux),
            ),
            "linux_egress_provider_unimplemented",
        )
    }

    fn prove_containment_for_challenge(
        &self,
        challenge: &ProviderVerificationChallenge,
        mode: ExecutionMode,
    ) -> ContainmentProof {
        ContainmentProof::unavailable_by_provider(
            mode,
            challenge.subject.clone(),
            unavailable_provider_provenance_for_challenge(
                "linux-local-proof-provider",
                "linux",
                ProofMechanism::LinuxNamespace,
                LocalProviderPlatform::Linux,
                challenge,
            ),
            "linux_containment_provider_unimplemented",
        )
    }

    fn prove_egress_for_challenge(&self, challenge: &ProviderVerificationChallenge) -> EgressProof {
        EgressProof::unavailable_by_provider(
            &challenge.configured_vault_host,
            challenge.subject.clone(),
            unavailable_provider_provenance_for_challenge(
                "linux-local-proof-provider",
                "linux",
                ProofMechanism::LinuxPacketFilter,
                LocalProviderPlatform::Linux,
                challenge,
            ),
            "linux_egress_provider_unimplemented",
        )
    }
}

pub struct MacosLocalProofProvider;

impl ProofProvider for MacosLocalProofProvider {
    fn provenance(&self) -> ProofProvenance {
        unavailable_provider_provenance_with_evidence(
            "macos-local-proof-provider",
            "macos",
            ProofMechanism::None,
            collect_local_provider_evidence(LocalProviderPlatform::Macos),
        )
    }

    fn prove_containment(&self, mode: ExecutionMode) -> ContainmentProof {
        ContainmentProof::unavailable_by_provider(
            mode,
            ProofSubject::unbound(),
            unavailable_provider_provenance_with_evidence(
                "macos-local-proof-provider",
                "macos",
                ProofMechanism::MacosVmBeta,
                collect_local_provider_evidence(LocalProviderPlatform::Macos),
            ),
            "macos_containment_provider_unimplemented",
        )
    }

    fn prove_egress(
        &self,
        subject: ProofSubject,
        configured_vault_host: &str,
        _probe_destinations: &[&str],
    ) -> EgressProof {
        EgressProof::unavailable_by_provider(
            configured_vault_host,
            subject,
            unavailable_provider_provenance_with_evidence(
                "macos-local-proof-provider",
                "macos",
                ProofMechanism::MacosPacketFilter,
                collect_local_provider_evidence(LocalProviderPlatform::Macos),
            ),
            "macos_egress_provider_unimplemented",
        )
    }

    fn prove_containment_for_challenge(
        &self,
        challenge: &ProviderVerificationChallenge,
        mode: ExecutionMode,
    ) -> ContainmentProof {
        ContainmentProof::unavailable_by_provider(
            mode,
            challenge.subject.clone(),
            unavailable_provider_provenance_for_challenge(
                "macos-local-proof-provider",
                "macos",
                ProofMechanism::MacosVmBeta,
                LocalProviderPlatform::Macos,
                challenge,
            ),
            "macos_containment_provider_unimplemented",
        )
    }

    fn prove_egress_for_challenge(&self, challenge: &ProviderVerificationChallenge) -> EgressProof {
        EgressProof::unavailable_by_provider(
            &challenge.configured_vault_host,
            challenge.subject.clone(),
            unavailable_provider_provenance_for_challenge(
                "macos-local-proof-provider",
                "macos",
                ProofMechanism::MacosPacketFilter,
                LocalProviderPlatform::Macos,
                challenge,
            ),
            "macos_egress_provider_unimplemented",
        )
    }
}

fn fail_closed_challenge_provenance(
    provider_id: impl Into<String>,
    challenge: &ProviderVerificationChallenge,
) -> ProofProvenance {
    ProofProvenance {
        provider_id: provider_id.into(),
        provider_version: "unimplemented".to_string(),
        platform: current_platform_label().to_string(),
        mechanism: ProofMechanism::None,
        trust: ProofTrust::None,
        verified_at_unix_seconds: 0,
        expires_at_unix_seconds: 0,
        context_hash: challenge.context_hash.clone(),
        rule_generation_id: "unimplemented".to_string(),
        evidence: provider_challenge_evidence(challenge),
    }
}

fn unavailable_provider_provenance_for_challenge(
    provider_id: impl Into<String>,
    platform: impl Into<String>,
    mechanism: ProofMechanism,
    local_platform: LocalProviderPlatform,
    challenge: &ProviderVerificationChallenge,
) -> ProofProvenance {
    let mut evidence = collect_local_provider_evidence(local_platform);
    evidence.extend(provider_challenge_evidence(challenge));
    let mut provenance =
        unavailable_provider_provenance_with_evidence(provider_id, platform, mechanism, evidence);
    provenance.context_hash = challenge.context_hash.clone();
    provenance
}

fn provider_challenge_evidence(challenge: &ProviderVerificationChallenge) -> Vec<String> {
    vec![
        format!("provider_challenge_id={}", challenge.challenge_id),
        format!("provider_challenge_subject={}", challenge.subject.launch_id),
        format!("provider_challenge_context_hash={}", challenge.context_hash),
        format!(
            "provider_challenge_configured_vault_host={}",
            challenge.configured_vault_host
        ),
        format!(
            "provider_challenge_probe_count={}",
            challenge.probe_destinations.len()
        ),
        format!(
            "provider_challenge_expires_at={}",
            challenge.expires_at_unix_seconds
        ),
        format!(
            "provider_challenge_nonce_present={}",
            !challenge.challenge_nonce.is_empty()
        ),
    ]
}

fn unavailable_provider_provenance_with_evidence(
    provider_id: impl Into<String>,
    platform: impl Into<String>,
    mechanism: ProofMechanism,
    evidence: Vec<String>,
) -> ProofProvenance {
    ProofProvenance {
        provider_id: provider_id.into(),
        provider_version: "skeleton".to_string(),
        platform: platform.into(),
        mechanism,
        trust: ProofTrust::None,
        verified_at_unix_seconds: 0,
        expires_at_unix_seconds: 0,
        context_hash: "unverified".to_string(),
        rule_generation_id: "unverified".to_string(),
        evidence,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupLease {
    pub lease_id: String,
    pub owned_paths: Vec<String>,
    pub released: bool,
}

impl CleanupLease {
    pub fn new(lease_id: impl Into<String>) -> Self {
        Self {
            lease_id: lease_id.into(),
            owned_paths: Vec::new(),
            released: false,
        }
    }

    pub fn track_path(&mut self, path: impl Into<String>) {
        if !self.released {
            self.owned_paths.push(path.into());
        }
    }

    pub fn release(&mut self) -> Vec<String> {
        self.released = true;
        std::mem::take(&mut self.owned_paths)
    }
}

pub struct UnsupportedBackend;

impl SandboxBackend for UnsupportedBackend {
    fn plan(&self, mode: ExecutionMode) -> SandboxPlan {
        SandboxPlan {
            backend: ContainmentBackend::None,
            strength: ContainmentStrength::FailedClosed,
            label: match mode {
                ExecutionMode::Observe => "observe only",
                _ => "containment unavailable",
            },
            high_risk_allowed: false,
        }
    }
}

pub struct MacosBetaBackend {
    pub available: bool,
}

impl SandboxBackend for MacosBetaBackend {
    fn plan(&self, mode: ExecutionMode) -> SandboxPlan {
        if self.available {
            SandboxPlan {
                backend: ContainmentBackend::MacosVmBeta,
                strength: ContainmentStrength::Beta,
                label: "macOS beta containment",
                high_risk_allowed: matches!(mode, ExecutionMode::BetaContainment),
            }
        } else {
            UnsupportedBackend.plan(mode)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_provider_challenge_evidence(
        provenance: &ProofProvenance,
        challenge: &ProviderVerificationChallenge,
    ) {
        assert!(provenance
            .evidence
            .contains(&format!("provider_challenge_id={}", challenge.challenge_id)));
        assert!(provenance.evidence.contains(&format!(
            "provider_challenge_subject={}",
            challenge.subject.launch_id
        )));
        assert!(provenance.evidence.contains(&format!(
            "provider_challenge_context_hash={}",
            challenge.context_hash
        )));
        assert!(provenance.evidence.contains(&format!(
            "provider_challenge_configured_vault_host={}",
            challenge.configured_vault_host
        )));
        assert!(provenance.evidence.contains(&format!(
            "provider_challenge_probe_count={}",
            challenge.probe_destinations.len()
        )));
        assert!(provenance.evidence.contains(&format!(
            "provider_challenge_expires_at={}",
            challenge.expires_at_unix_seconds
        )));
        assert!(provenance.evidence.contains(&format!(
            "provider_challenge_nonce_present={}",
            !challenge.challenge_nonce.is_empty()
        )));
    }

    fn assert_read_only_provider_posture(evidence: &[String], target: &str) {
        let posture = local_provider_evidence_posture_from_evidence(evidence);
        assert_eq!(
            posture.schema_version.as_deref(),
            Some("local_provider_readiness.v1")
        );
        assert_eq!(posture.status.as_deref(), Some("read_only_probe"));
        assert_eq!(posture.verdict.as_deref(), Some("not_verified"));
        assert_eq!(posture.target_platform.as_deref(), Some(target));
        assert_eq!(
            posture.host_platform.as_deref(),
            Some(current_platform_label())
        );
        assert_eq!(
            posture.target_matches_host,
            Some(current_platform_label() == target)
        );
        assert_eq!(posture.active_verification_enabled, Some(false));
        assert_eq!(posture.package_execution_attempted, Some(false));
        assert_eq!(posture.os_mutation_attempted, Some(false));
        assert_eq!(posture.network_mutation_attempted, Some(false));
        assert_eq!(posture.public_network_probe_attempted, Some(false));
    }

    #[test]
    fn unsupported_backend_fails_closed() {
        let plan = UnsupportedBackend.plan(ExecutionMode::CiFailClosed);
        assert_eq!(plan.strength, ContainmentStrength::FailedClosed);
        assert!(!plan.high_risk_allowed);
    }

    #[test]
    fn macos_beta_backend_is_labeled_beta() {
        let plan = MacosBetaBackend { available: true }.plan(ExecutionMode::BetaContainment);
        assert_eq!(plan.label, "macOS beta containment");
        assert_eq!(plan.strength, ContainmentStrength::Beta);
    }

    #[test]
    fn egress_vault_only_blocks_public_registry() {
        let public = evaluate_egress(EgressPolicy::AllowVaultOnly, "registry.npmjs.org");
        assert!(!public.allowed);
        assert_eq!(public.reason_code, "egress_public_registry_denied");

        let vault = evaluate_egress(EgressPolicy::AllowVaultOnly, "vault.local");
        assert!(vault.allowed);
    }

    #[test]
    fn egress_vault_only_does_not_allow_arbitrary_loopback() {
        let loopback = evaluate_egress(EgressPolicy::AllowVaultOnly, "127.0.0.1");
        assert!(!loopback.allowed);
        assert_eq!(loopback.reason_code, "egress_public_registry_denied");
    }

    #[test]
    fn configured_vault_egress_requires_exact_host() {
        let allowed = evaluate_configured_vault_egress("127.0.0.1:4873", "127.0.0.1:4873");
        assert!(allowed.allowed);

        let denied = evaluate_configured_vault_egress("127.0.0.1:9000", "127.0.0.1:4873");
        assert!(!denied.allowed);
        assert_eq!(
            denied.reason_code,
            "egress_non_configured_destination_denied"
        );
    }

    #[test]
    fn vault_only_probe_destinations_cover_private_ipv6_dns_and_deduplicate() {
        let probes = vault_only_probe_destinations("127.0.0.1:4873");
        assert_eq!(
            probes.len(),
            mandatory_vault_only_probe_destinations().len() + 1
        );
        for expected in [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.0.1",
            "[::1]:9000",
            "fd00::1",
            "fe80::1",
            "1.1.1.1:53",
            "8.8.8.8:53",
        ] {
            assert!(probes.contains(&expected.to_string()));
        }

        let deduplicated = vault_only_probe_destinations("127.0.0.1:9000");
        assert_eq!(
            deduplicated.len(),
            mandatory_vault_only_probe_destinations().len()
        );
        assert_eq!(
            deduplicated
                .iter()
                .filter(|destination| *destination == "127.0.0.1:9000")
                .count(),
            1
        );
    }

    #[test]
    fn provider_challenge_binds_subject_context_vault_and_required_probes() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:abc123",
            "127.0.0.1:4873",
            1,
        );
        assert!(challenge.valid());
        assert!(challenge
            .challenge_id
            .starts_with("proof-challenge-sha256:"));
        assert!(challenge.challenge_nonce.starts_with("proof-nonce-sha256:"));
        assert_eq!(challenge.validation_time_unix_seconds, 1);
        assert_eq!(
            challenge.expires_at_unix_seconds,
            1 + DEFAULT_PROVIDER_CHALLENGE_TTL_SECONDS
        );
        assert!(challenge.valid_at(1));
        assert!(challenge
            .probe_destinations
            .contains(&"127.0.0.1:4873".to_string()));
        for mandatory in mandatory_vault_only_probe_destinations() {
            assert!(challenge
                .probe_destinations
                .contains(&(*mandatory).to_string()));
        }

        let invalid = ProviderVerificationChallenge::new(ProofSubject::unbound(), "none", "", 1);
        assert!(!invalid.valid());
        assert!(invalid
            .reason_codes()
            .contains(&"provider_challenge_subject_unbound"));
        assert!(invalid
            .reason_codes()
            .contains(&"provider_challenge_context_hash_missing"));
        assert!(invalid
            .reason_codes()
            .contains(&"provider_challenge_vault_host_missing"));

        let invalid_nonce = ProviderVerificationChallenge::new_with_nonce(
            ProofSubject::for_launch("launch-1"),
            "sha256:abc123",
            "127.0.0.1:4873",
            1,
            "",
            1,
        );
        assert!(!invalid_nonce.valid());
        assert!(invalid_nonce
            .reason_codes()
            .contains(&"provider_challenge_nonce_missing"));
        assert!(invalid_nonce
            .reason_codes()
            .contains(&"provider_challenge_expiry_invalid"));
    }

    #[test]
    fn provider_challenge_replay_guard_issues_unique_single_use_challenges() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        let first = guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let second = guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        assert_ne!(first.challenge_id, second.challenge_id);
        assert_ne!(first.challenge_nonce, second.challenge_nonce);
        assert_eq!(first.expires_at_unix_seconds, 160);

        let accepted = guard.consume(&first, 100);
        assert!(accepted.accepted());
        assert!(accepted.reason_codes.is_empty());

        let replay = guard.consume(&first, 101);
        assert!(!replay.accepted());
        assert_eq!(replay.status, ProviderChallengeUseStatus::Rejected);
        assert!(replay
            .reason_codes
            .contains(&"provider_challenge_replayed".to_string()));

        let second_accepted = guard.consume(&second, 159);
        assert!(second_accepted.accepted());
    }

    #[test]
    fn provider_challenge_replay_guard_snapshots_restore_without_raw_nonce() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        let challenge = guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );

        let snapshots = guard.snapshots();
        assert_eq!(snapshots.len(), 1);
        let snapshot = &snapshots[0];
        assert_eq!(snapshot.challenge_id, challenge.challenge_id);
        assert_ne!(snapshot.challenge_nonce_digest, challenge.challenge_nonce);
        assert_eq!(
            snapshot.challenge_nonce_digest,
            provider_challenge_nonce_digest(&challenge.challenge_nonce)
        );
        assert!(!snapshot.consumed);

        let mut restored = ProviderChallengeReplayGuard::restore(60, 1, snapshots);
        let accepted = restored.consume(&challenge, 100);
        assert!(accepted.accepted());

        let replay = restored.consume(&challenge, 101);
        assert!(!replay.accepted());
        assert!(replay
            .reason_codes
            .contains(&"provider_challenge_replayed".to_string()));

        let consumed_snapshots = restored.snapshots();
        assert_eq!(consumed_snapshots.len(), 1);
        assert!(consumed_snapshots[0].consumed);
    }

    #[test]
    fn provider_challenge_replay_guard_restored_snapshot_rejects_mutated_nonce() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        let mut challenge = guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let snapshots = guard.snapshots();
        challenge.challenge_nonce = "proof-nonce-sha256:mutated".to_string();

        let mut restored = ProviderChallengeReplayGuard::restore(60, 1, snapshots);
        let rejected = restored.consume(&challenge, 100);
        assert!(!rejected.accepted());
        assert!(rejected
            .reason_codes
            .contains(&"provider_challenge_nonce_mismatch".to_string()));
    }

    #[test]
    fn provider_challenge_file_store_persists_single_use_without_raw_nonce() {
        let root = unique_test_dir("provider-challenge-file-store");
        let path = root.join("replay-store.txt");
        let store = ProviderChallengeReplayFileStore::new(&path, 60);
        let challenge = store
            .issue(
                ProofSubject::for_launch("launch-1"),
                "sha256:context",
                "127.0.0.1:4873",
                100,
            )
            .expect("issue challenge");

        let store_contents = fs::read_to_string(store.path()).expect("read store");
        assert!(store_contents.contains(PROVIDER_CHALLENGE_STORE_SCHEMA));
        assert!(store_contents.contains("challenge_nonce_digest="));
        assert!(!store_contents.contains(&challenge.challenge_nonce));
        assert!(!provider_challenge_lock_path(store.path()).exists());

        let accepted = ProviderChallengeReplayFileStore::new(&path, 60)
            .consume(&challenge, 100)
            .expect("consume challenge");
        assert!(accepted.accepted());

        let replayed = ProviderChallengeReplayFileStore::new(&path, 60)
            .consume(&challenge, 101)
            .expect("replay challenge");
        assert!(!replayed.accepted());
        assert!(replayed
            .reason_codes
            .contains(&"provider_challenge_replayed".to_string()));

        let snapshots = store.snapshots().expect("read snapshots");
        assert_eq!(snapshots.len(), 1);
        assert!(snapshots[0].consumed);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(store.path())
                .expect("metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn provider_challenge_file_store_rejects_corrupt_state_without_mutation() {
        let root = unique_test_dir("provider-challenge-file-store-corrupt");
        fs::create_dir_all(&root).expect("create root");
        let path = root.join("replay-store.txt");
        fs::write(&path, "not a replay store\n").expect("write corrupt store");
        set_private_file_permissions(&path).expect("private corrupt store");

        let store = ProviderChallengeReplayFileStore::new(&path, 60);
        let error = store
            .issue(
                ProofSubject::for_launch("launch-1"),
                "sha256:context",
                "127.0.0.1:4873",
                100,
            )
            .expect_err("corrupt store must fail closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(
            fs::read_to_string(&path).expect("corrupt store remains"),
            "not a replay store\n"
        );
        assert!(!provider_challenge_lock_path(&path).exists());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn provider_challenge_file_store_recovers_stale_lock() {
        let root = unique_test_dir("provider-challenge-file-store-stale-lock");
        fs::create_dir_all(&root).expect("create root");
        let path = root.join("replay-store.txt");
        let lock_path = provider_challenge_lock_path(&path);
        fs::write(
            &lock_path,
            format!("{PROVIDER_CHALLENGE_LOCK_SCHEMA}\ncreated_at_unix_seconds=1\npid=999999\n"),
        )
        .expect("write stale lock");
        set_private_file_permissions(&lock_path).expect("private stale lock");

        assert!(provider_challenge_lock_is_stale(&lock_path, 100, 60).expect("stale check"));
        assert!(!provider_challenge_lock_is_stale(&lock_path, 30, 60).expect("fresh check"));

        let store = ProviderChallengeReplayFileStore::new(&path, 60);
        let (challenge, outcome) = store
            .issue_with_outcome(
                ProofSubject::for_launch("launch-1"),
                "sha256:context",
                "127.0.0.1:4873",
                100,
            )
            .expect("stale lock recovered");
        assert!(challenge.valid_at(100));
        assert!(outcome.stale_lock_recovered);
        assert!(!lock_path.exists());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn provider_challenge_file_store_concurrent_issue_consume_is_single_use() {
        let root = unique_test_dir("provider-challenge-file-store-concurrent");
        let path = root.join("replay-store.txt");
        let worker_count = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(worker_count));
        let mut handles = Vec::new();
        for worker in 0..worker_count {
            let path = path.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let store = ProviderChallengeReplayFileStore::new(&path, 60);
                barrier.wait();
                let challenge = store
                    .issue(
                        ProofSubject::for_launch(format!("launch-{worker}")),
                        format!("sha256:context-{worker}"),
                        "127.0.0.1:4873",
                        100,
                    )
                    .expect("issue challenge");
                let accepted = ProviderChallengeReplayFileStore::new(&path, 60)
                    .consume(&challenge, 100)
                    .expect("consume challenge");
                assert!(accepted.accepted());
                challenge.challenge_id
            }));
        }

        let mut challenge_ids = BTreeSet::new();
        for handle in handles {
            let challenge_id = handle.join().expect("worker completed");
            assert!(challenge_ids.insert(challenge_id));
        }

        let snapshots = ProviderChallengeReplayFileStore::new(&path, 60)
            .snapshots()
            .expect("snapshots");
        assert_eq!(snapshots.len(), worker_count);
        assert!(snapshots.iter().all(|snapshot| snapshot.consumed));
        assert!(!provider_challenge_lock_path(&path).exists());

        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn provider_challenge_store_rejects_duplicate_record_fields() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let contents = provider_challenge_store_encode(&guard);
        let tampered = contents.replace(" subject=", " challenge_id=ff subject=");

        let error =
            provider_challenge_store_decode(&tampered).expect_err("duplicate field rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("duplicate_field"));
    }

    #[test]
    fn provider_challenge_store_rejects_duplicate_challenge_ids() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let contents = provider_challenge_store_encode(&guard);
        let record = contents
            .lines()
            .find(|line| line.starts_with("record "))
            .expect("encoded record")
            .to_string();
        let tampered = format!("{}{}\n", contents, record);

        let error =
            provider_challenge_store_decode(&tampered).expect_err("duplicate challenge rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("duplicate_challenge_id"));
    }

    #[test]
    fn linux_active_probe_admission_requires_replay_owned_satisfying_receipt() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        let challenge = guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let evidence = linux_active_probe_fixture_evidence(
            &challenge,
            LinuxActiveProbeFixtureProfile::Complete,
        );
        let admission = admit_linux_active_probe_receipt(&mut guard, &challenge, &evidence, 100);
        assert!(admission.accepted);
        assert!(admission.reason_codes.is_empty());
        assert!(admission.replay_decision.accepted());
        assert!(admission.receipt.satisfied);

        let replay = admit_linux_active_probe_receipt(&mut guard, &challenge, &evidence, 101);
        assert!(!replay.accepted);
        assert!(replay
            .reason_codes
            .contains(&"provider_challenge_replayed".to_string()));
    }

    #[test]
    fn linux_active_probe_admission_rejects_unknown_and_invalid_receipts() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        let issued = guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let invalid_evidence = linux_active_probe_fixture_evidence(
            &issued,
            LinuxActiveProbeFixtureProfile::Incomplete,
        );
        let invalid = admit_linux_active_probe_receipt(&mut guard, &issued, &invalid_evidence, 100);
        assert!(!invalid.accepted);
        assert!(invalid.replay_decision.accepted());
        assert!(!invalid.receipt.satisfied);
        assert!(invalid
            .reason_codes
            .contains(&"linux_active_probe_not_complete".to_string()));

        let unknown = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-unknown"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let unknown_evidence =
            linux_active_probe_fixture_evidence(&unknown, LinuxActiveProbeFixtureProfile::Complete);
        let unknown_admission =
            admit_linux_active_probe_receipt(&mut guard, &unknown, &unknown_evidence, 100);
        assert!(!unknown_admission.accepted);
        assert!(unknown_admission.receipt.satisfied);
        assert!(unknown_admission
            .reason_codes
            .contains(&"provider_challenge_not_issued".to_string()));
    }

    #[test]
    fn provider_challenge_replay_guard_rejects_unknown_expired_and_mutated_challenges() {
        let mut guard = ProviderChallengeReplayGuard::new(60);
        let issued = guard.issue(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let unknown = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            100,
        );
        let unknown_decision = guard.consume(&unknown, 100);
        assert!(!unknown_decision.accepted());
        assert!(unknown_decision
            .reason_codes
            .contains(&"provider_challenge_not_issued".to_string()));

        let expired = guard.consume(&issued, 160);
        assert!(!expired.accepted());
        assert!(expired
            .reason_codes
            .contains(&"provider_challenge_expired".to_string()));

        let mut mutated = issued.clone();
        mutated.context_hash = "sha256:other-context".to_string();
        mutated.challenge_nonce = "proof-nonce-sha256:mutated".to_string();
        let mutated_decision = guard.consume(&mutated, 100);
        assert!(!mutated_decision.accepted());
        assert!(mutated_decision
            .reason_codes
            .contains(&"provider_challenge_context_mutated".to_string()));
        assert!(mutated_decision
            .reason_codes
            .contains(&"provider_challenge_nonce_mismatch".to_string()));

        assert_eq!(guard.prune_expired(159), 0);
        assert_eq!(guard.prune_expired(160), 1);
    }

    #[test]
    fn test_only_provider_satisfies_matching_challenge() {
        let provider = test_support::TestOnlyProofProvider::new_for_context(
            "launch-1",
            "127.0.0.1:4873",
            "sha256:context",
        );
        let challenge = ProviderVerificationChallenge::new(
            provider.subject(),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        let attempt = provider.evaluate_challenge(&challenge, ExecutionMode::CiFailClosed);
        assert!(attempt.challenge_satisfied);
        assert!(attempt.reason_codes.is_empty());
        assert_eq!(attempt.containment_status, ProofStatus::Verified);
        assert_eq!(attempt.egress_status, ProofStatus::Verified);
        assert_eq!(
            attempt.probe_destination_count,
            challenge.probe_destinations.len()
        );
    }

    #[test]
    fn test_only_provider_uses_challenge_subject_and_context() {
        let provider = test_support::TestOnlyProofProvider::new_for_context(
            "stale-launch",
            "127.0.0.1:4873",
            "sha256:stale-context",
        );
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-from-challenge"),
            "sha256:challenge-context",
            "127.0.0.1:4873",
            1,
        );
        let proofs = provider.prove_challenge(&challenge, ExecutionMode::CiFailClosed);
        assert_eq!(proofs.containment.subject(), &challenge.subject);
        assert_eq!(proofs.egress.subject(), &challenge.subject);
        assert_eq!(
            proofs.containment.provenance().context_hash,
            challenge.context_hash
        );
        assert_eq!(
            proofs.egress.provenance().context_hash,
            challenge.context_hash
        );

        let attempt =
            ProviderChallengeAttempt::from_proofs(&challenge, &proofs.containment, &proofs.egress);
        assert!(attempt.challenge_satisfied);
        assert!(attempt.reason_codes.is_empty());
    }

    #[test]
    fn provider_challenge_requires_all_requested_probes_and_same_provider() {
        let mut challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        challenge
            .probe_destinations
            .push("extra.registry.example".to_string());
        let containment = ContainmentProof::verified_by_provider(
            challenge.subject.clone(),
            SandboxPlan {
                backend: ContainmentBackend::LinuxNamespace,
                strength: ContainmentStrength::Strong,
                label: "linux containment",
                high_risk_allowed: true,
            },
            ExecutionMode::CiFailClosed,
            ProofProvenance::trusted_local_provider_for_context(
                "containment-provider",
                &["namespace-probed"],
                "sha256:context",
                "rule-generation",
            ),
        );
        let destinations = vault_only_probe_destinations("127.0.0.1:4873");
        let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
        let egress = EgressProof::verified_vault_only_by_provider(
            challenge.subject.clone(),
            ProofProvenance::trusted_local_provider_for_context(
                "egress-provider",
                &[
                    "packet-filter-probed",
                    "egress.default_deny_except_configured_vault.attested=true",
                ],
                "sha256:context",
                "rule-generation",
            ),
            EgressPolicyScope::DefaultDenyExceptConfiguredVault,
            "127.0.0.1:4873",
            &destination_refs,
        );
        let attempt = ProviderChallengeAttempt::from_proofs(&challenge, &containment, &egress);
        assert!(!attempt.challenge_satisfied);
        assert!(attempt
            .reason_codes
            .contains(&"provider_challenge_egress_probe_missing".to_string()));
        assert!(attempt
            .reason_codes
            .contains(&"provider_challenge_provider_id_mismatch".to_string()));
        assert!(!attempt
            .reason_codes
            .contains(&"provider_challenge_rule_generation_mismatch".to_string()));
    }

    #[test]
    fn linux_active_probe_receipt_satisfies_matching_challenge_contract() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        let mut evidence = vec![
            format!("provider_evidence_schema={LINUX_ACTIVE_PROBE_SCHEMA_VERSION}"),
            format!("provider_status={LINUX_ACTIVE_PROBE_COMPLETE_STATUS}"),
            "provider_target_matches_host=true".to_string(),
            format!("provider_challenge_id={}", challenge.challenge_id),
            format!("provider_challenge_subject={}", challenge.subject.launch_id),
            format!("provider_challenge_context_hash={}", challenge.context_hash),
            format!(
                "provider_challenge_configured_vault_host={}",
                challenge.configured_vault_host
            ),
            "linux.active_probe.user_namespace.isolated=true".to_string(),
            "linux.active_probe.network_namespace.isolated=true".to_string(),
            "linux.active_probe.no_new_privs=true".to_string(),
            "linux.active_probe.seccomp_filter.enforced=true".to_string(),
            "linux.active_probe.cgroup.scoped=true".to_string(),
            "linux.active_probe.egress.default_deny_except_configured_vault=true".to_string(),
            "provider_package_execution_attempted=false".to_string(),
            format!(
                "linux.active_probe.os_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"
            ),
            format!(
                "linux.active_probe.network_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"
            ),
            "provider_public_network_probe_attempted=false".to_string(),
        ];
        for probe in &challenge.probe_destinations {
            if probe == &challenge.configured_vault_host {
                evidence.push(format!("linux.active_probe.egress.allowed={probe}"));
            } else {
                evidence.push(format!("linux.active_probe.egress.denied={probe}"));
            }
        }

        let receipt = linux_active_probe_receipt_from_evidence(&challenge, &evidence);
        assert!(receipt.satisfied);
        assert!(receipt.reason_codes.is_empty());
        assert_eq!(
            receipt.allowed_destinations,
            vec![challenge.configured_vault_host.clone()]
        );
        assert_eq!(
            receipt.denied_destinations.len(),
            challenge.probe_destinations.len() - 1
        );
        assert!(receipt.missing_probe_destinations.is_empty());
        assert!(receipt.allowed_non_vault_destinations.is_empty());
    }

    #[test]
    fn linux_active_probe_receipt_rejects_missing_mutated_and_overpermissive_evidence() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        let evidence = vec![
            format!("provider_evidence_schema={LINUX_ACTIVE_PROBE_SCHEMA_VERSION}"),
            format!("provider_status={LINUX_ACTIVE_PROBE_COMPLETE_STATUS}"),
            "provider_target_matches_host=true".to_string(),
            format!("provider_challenge_id={}", challenge.challenge_id),
            format!("provider_challenge_subject={}", challenge.subject.launch_id),
            "provider_challenge_context_hash=sha256:other-context".to_string(),
            format!(
                "provider_challenge_configured_vault_host={}",
                challenge.configured_vault_host
            ),
            "linux.active_probe.user_namespace.isolated=true".to_string(),
            "linux.active_probe.network_namespace.isolated=true".to_string(),
            "linux.active_probe.no_new_privs=true".to_string(),
            "linux.active_probe.seccomp_filter.enforced=true".to_string(),
            "linux.active_probe.cgroup.scoped=true".to_string(),
            "linux.active_probe.egress.default_deny_except_configured_vault=false".to_string(),
            "provider_package_execution_attempted=false".to_string(),
            format!(
                "linux.active_probe.os_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"
            ),
            format!(
                "linux.active_probe.network_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"
            ),
            "provider_public_network_probe_attempted=true".to_string(),
            format!(
                "linux.active_probe.egress.allowed={}",
                challenge.configured_vault_host
            ),
            "linux.active_probe.egress.allowed=registry.npmjs.org".to_string(),
        ];

        let receipt = linux_active_probe_receipt_from_evidence(&challenge, &evidence);
        assert!(!receipt.satisfied);
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_context_mismatch".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_default_deny_not_attested".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_public_network_probe_attempted".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_non_vault_probe_allowed".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_denied_probe_missing".to_string()));
        assert_eq!(
            receipt.allowed_non_vault_destinations,
            vec!["registry.npmjs.org".to_string()]
        );
        assert!(!receipt.missing_probe_destinations.is_empty());
    }

    #[test]
    fn linux_active_probe_fixture_profiles_validate_contract_boundaries() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );

        let complete_evidence = linux_active_probe_fixture_evidence(
            &challenge,
            LinuxActiveProbeFixtureProfile::Complete,
        );
        let complete = linux_active_probe_receipt_from_evidence(&challenge, &complete_evidence);
        assert!(complete.satisfied);
        assert!(complete.reason_codes.is_empty());

        let incomplete_evidence = linux_active_probe_fixture_evidence(
            &challenge,
            LinuxActiveProbeFixtureProfile::Incomplete,
        );
        let incomplete = linux_active_probe_receipt_from_evidence(&challenge, &incomplete_evidence);
        assert!(!incomplete.satisfied);
        assert!(incomplete
            .reason_codes
            .contains(&"linux_active_probe_not_complete".to_string()));
        assert!(incomplete
            .reason_codes
            .contains(&"linux_active_probe_denied_probe_missing".to_string()));

        let overpermissive_evidence = linux_active_probe_fixture_evidence(
            &challenge,
            LinuxActiveProbeFixtureProfile::Overpermissive,
        );
        let overpermissive =
            linux_active_probe_receipt_from_evidence(&challenge, &overpermissive_evidence);
        assert!(!overpermissive.satisfied);
        assert!(overpermissive
            .reason_codes
            .contains(&"linux_active_probe_non_vault_probe_allowed".to_string()));
        assert_eq!(
            overpermissive.allowed_non_vault_destinations,
            vec!["registry.npmjs.org".to_string()]
        );
    }

    #[test]
    fn provider_challenge_reports_rule_generation_mismatch() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        let containment = ContainmentProof::verified_by_provider(
            challenge.subject.clone(),
            SandboxPlan {
                backend: ContainmentBackend::LinuxNamespace,
                strength: ContainmentStrength::Strong,
                label: "linux containment",
                high_risk_allowed: true,
            },
            ExecutionMode::CiFailClosed,
            ProofProvenance::trusted_local_provider_for_context(
                "sandbox-test-only-provider",
                &["namespace-probed"],
                "sha256:context",
                "containment-generation",
            ),
        );
        let destinations = vault_only_probe_destinations("127.0.0.1:4873");
        let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
        let egress = EgressProof::verified_vault_only_by_provider(
            challenge.subject.clone(),
            ProofProvenance::trusted_local_provider_for_context(
                "sandbox-test-only-provider",
                &[
                    "packet-filter-probed",
                    "egress.default_deny_except_configured_vault.attested=true",
                ],
                "sha256:context",
                "egress-generation",
            ),
            EgressPolicyScope::DefaultDenyExceptConfiguredVault,
            "127.0.0.1:4873",
            &destination_refs,
        );
        let attempt = ProviderChallengeAttempt::from_proofs(&challenge, &containment, &egress);
        assert!(!attempt.challenge_satisfied);
        assert!(attempt
            .reason_codes
            .contains(&"provider_challenge_rule_generation_mismatch".to_string()));
        assert!(!attempt
            .reason_codes
            .contains(&"provider_challenge_provider_id_mismatch".to_string()));
    }

    #[test]
    fn linux_local_provider_challenge_attempt_records_challenge_and_fails_closed() {
        let provider = LinuxLocalProofProvider;
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        let proofs = provider.prove_challenge(&challenge, ExecutionMode::CiFailClosed);
        let attempt =
            ProviderChallengeAttempt::from_proofs(&challenge, &proofs.containment, &proofs.egress);
        assert!(!attempt.challenge_satisfied);
        assert_eq!(attempt.containment_status, ProofStatus::Missing);
        assert_eq!(attempt.egress_status, ProofStatus::Missing);
        assert_eq!(proofs.containment.subject(), &challenge.subject);
        assert_eq!(proofs.egress.subject(), &challenge.subject);
        assert_eq!(
            proofs.containment.provenance().context_hash,
            challenge.context_hash
        );
        assert_eq!(
            proofs.egress.provenance().context_hash,
            challenge.context_hash
        );
        assert_provider_challenge_evidence(proofs.containment.provenance(), &challenge);
        assert_provider_challenge_evidence(proofs.egress.provenance(), &challenge);
        assert!(attempt
            .reason_codes
            .contains(&"linux_containment_provider_unimplemented".to_string()));
        assert!(attempt
            .reason_codes
            .contains(&"linux_egress_provider_unimplemented".to_string()));
        assert!(attempt
            .reason_codes
            .contains(&"provider_challenge_egress_probe_missing".to_string()));
        assert!(attempt
            .reason_codes
            .contains(&"provider_challenge_proof_not_fresh".to_string()));
        assert!(!attempt
            .reason_codes
            .contains(&"provider_challenge_containment_subject_mismatch".to_string()));
        assert!(!attempt
            .reason_codes
            .contains(&"provider_challenge_containment_context_mismatch".to_string()));
    }

    #[test]
    fn macos_local_provider_challenge_attempt_records_challenge_and_fails_closed() {
        let provider = MacosLocalProofProvider;
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        let proofs = provider.prove_challenge(&challenge, ExecutionMode::BetaContainment);
        let attempt =
            ProviderChallengeAttempt::from_proofs(&challenge, &proofs.containment, &proofs.egress);
        assert!(!attempt.challenge_satisfied);
        assert_eq!(attempt.containment_status, ProofStatus::Missing);
        assert_eq!(attempt.egress_status, ProofStatus::Missing);
        assert_eq!(proofs.containment.subject(), &challenge.subject);
        assert_eq!(proofs.egress.subject(), &challenge.subject);
        assert_eq!(
            proofs.containment.provenance().context_hash,
            challenge.context_hash
        );
        assert_eq!(
            proofs.egress.provenance().context_hash,
            challenge.context_hash
        );
        assert_provider_challenge_evidence(proofs.containment.provenance(), &challenge);
        assert_provider_challenge_evidence(proofs.egress.provenance(), &challenge);
        assert!(attempt
            .reason_codes
            .contains(&"macos_containment_provider_unimplemented".to_string()));
        assert!(attempt
            .reason_codes
            .contains(&"macos_egress_provider_unimplemented".to_string()));
        assert!(attempt
            .reason_codes
            .contains(&"provider_challenge_egress_probe_missing".to_string()));
        assert!(attempt
            .reason_codes
            .contains(&"provider_challenge_proof_not_fresh".to_string()));
    }

    #[test]
    fn operator_asserted_proofs_do_not_permit_high_risk() {
        let containment = ContainmentProof::operator_asserted(
            ExecutionMode::CiFailClosed,
            ContainmentBackend::LinuxNamespace,
        );
        let egress = EgressProof::operator_asserted("127.0.0.1:4873");
        assert!(!containment.permits_high_risk());
        assert!(!egress.permits_only_configured_vault());
    }

    #[test]
    fn verified_containment_requires_mode_strength_and_allowance() {
        let proof = ContainmentProof::verified_by_provider(
            ProofSubject::for_launch("launch-1"),
            SandboxPlan {
                backend: ContainmentBackend::MacosVmBeta,
                strength: ContainmentStrength::Beta,
                label: "macOS beta containment",
                high_risk_allowed: true,
            },
            ExecutionMode::BetaContainment,
            ProofProvenance::trusted_local_provider(
                "sandbox-unit-test-provider",
                &["vm-helper-probed"],
            ),
        );
        assert!(proof.permits_high_risk());
        assert_eq!(proof.reason_code, "containment_verified");
    }

    #[test]
    fn trusted_provider_requires_evidence() {
        let provenance = ProofProvenance::trusted_local_provider("empty-evidence-provider", &[]);
        let proof = ContainmentProof::verified_by_provider(
            ProofSubject::for_launch("launch-1"),
            SandboxPlan {
                backend: ContainmentBackend::LinuxNamespace,
                strength: ContainmentStrength::Strong,
                label: "linux containment",
                high_risk_allowed: true,
            },
            ExecutionMode::CiFailClosed,
            provenance,
        );
        assert!(!proof.permits_high_risk());
        assert_eq!(proof.reason_code, "containment_provider_not_trusted");
    }

    #[test]
    fn test_only_provider_harness_verifies_same_subject_proofs() {
        let provider = test_support::TestOnlyProofProvider::new("launch-1", "127.0.0.1:4873");
        let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
        let egress =
            provider.prove_egress(provider.subject(), "127.0.0.1:4873", &["127.0.0.1:4873"]);
        assert!(containment.permits_high_risk());
        assert!(egress.permits_only_configured_vault());
        assert_eq!(containment.subject(), egress.subject());
        assert!(egress
            .checks()
            .iter()
            .any(|check| check.destination_host == "registry.npmjs.org" && !check.allowed));
        assert_eq!(containment.provenance().mechanism, ProofMechanism::TestOnly);
    }

    #[test]
    fn unbound_subject_cannot_verify_containment() {
        let proof = ContainmentProof::verified_by_provider(
            ProofSubject::unbound(),
            SandboxPlan {
                backend: ContainmentBackend::LinuxNamespace,
                strength: ContainmentStrength::Strong,
                label: "linux containment",
                high_risk_allowed: true,
            },
            ExecutionMode::CiFailClosed,
            ProofProvenance::trusted_local_provider(
                "sandbox-unit-test-provider",
                &["namespace-probed"],
            ),
        );
        assert!(!proof.permits_high_risk());
        assert_eq!(proof.reason_code, "containment_provider_not_trusted");
    }

    #[test]
    fn verified_egress_requires_exact_vault_and_denies_public_hosts() {
        let destinations = vault_only_probe_destinations("127.0.0.1:4873");
        let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
        let proof = EgressProof::verified_vault_only_by_provider(
            ProofSubject::for_launch("launch-1"),
            ProofProvenance::trusted_local_provider(
                "sandbox-unit-test-provider",
                &[
                    "packet-filter-probed",
                    "egress.default_deny_except_configured_vault.attested=true",
                ],
            ),
            EgressPolicyScope::DefaultDenyExceptConfiguredVault,
            "127.0.0.1:4873",
            &destination_refs,
        );
        assert!(proof.permits_only_configured_vault());
        assert!(proof
            .checks
            .iter()
            .any(|check| check.destination_host == "registry.npmjs.org" && !check.allowed));
        assert!(proof
            .checks
            .iter()
            .any(|check| check.destination_host == "10.0.0.1" && !check.allowed));
        assert!(proof
            .checks
            .iter()
            .any(|check| check.destination_host == "fd00::1" && !check.allowed));
        assert!(proof
            .checks
            .iter()
            .any(|check| check.destination_host == "8.8.8.8:53" && !check.allowed));
    }

    #[test]
    fn egress_proof_requires_mandatory_negative_checks() {
        let proof = EgressProof::verified_vault_only_by_provider(
            ProofSubject::for_launch("launch-1"),
            ProofProvenance::trusted_local_provider(
                "sandbox-unit-test-provider",
                &[
                    "packet-filter-probed",
                    "egress.default_deny_except_configured_vault.attested=true",
                ],
            ),
            EgressPolicyScope::DefaultDenyExceptConfiguredVault,
            "127.0.0.1:4873",
            &["127.0.0.1:4873"],
        );
        assert!(!proof.permits_only_configured_vault());
        assert_eq!(proof.reason_code, "egress_vault_only_not_verified");
    }

    #[test]
    fn egress_proof_requires_default_deny_rule_attestation() {
        let destinations = vault_only_probe_destinations("127.0.0.1:4873");
        let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
        let proof = EgressProof::verified_vault_only_by_provider(
            ProofSubject::for_launch("launch-1"),
            ProofProvenance::trusted_local_provider(
                "sandbox-unit-test-provider",
                &["packet-filter-probed"],
            ),
            EgressPolicyScope::DefaultDenyExceptConfiguredVault,
            "127.0.0.1:4873",
            &destination_refs,
        );
        assert!(!proof.permits_only_configured_vault());
        assert_eq!(proof.reason_code, "egress_default_deny_rule_not_attested");
    }

    #[test]
    fn egress_proof_requires_default_deny_scope() {
        let destinations = vault_only_probe_destinations("127.0.0.1:4873");
        let destination_refs = destinations.iter().map(String::as_str).collect::<Vec<_>>();
        let proof = EgressProof::verified_vault_only_by_provider(
            ProofSubject::for_launch("launch-1"),
            ProofProvenance::trusted_local_provider(
                "sandbox-unit-test-provider",
                &[
                    "packet-filter-probed",
                    "egress.default_deny_except_configured_vault.attested=true",
                ],
            ),
            EgressPolicyScope::Unknown,
            "127.0.0.1:4873",
            &destination_refs,
        );
        assert!(!proof.permits_only_configured_vault());
        assert_eq!(proof.reason_code, "egress_provider_not_trusted");
    }

    #[test]
    fn fail_closed_provider_never_verifies_proofs() {
        let provider = FailClosedProofProvider {
            provider_id: "linux-provider-unimplemented",
        };
        let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
        let egress = provider.prove_egress(
            ProofSubject::for_launch("launch-1"),
            "127.0.0.1:4873",
            &["127.0.0.1:4873"],
        );
        assert!(!containment.permits_high_risk());
        assert!(!egress.permits_only_configured_vault());
        assert_eq!(
            containment.reason_code,
            "containment_provider_unimplemented"
        );
        assert_eq!(egress.reason_code, "egress_provider_unimplemented");
    }

    #[test]
    fn linux_local_provider_skeleton_fails_closed() {
        let provider = LinuxLocalProofProvider;
        let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
        let egress = provider.prove_egress(
            ProofSubject::for_launch("launch-1"),
            "127.0.0.1:4873",
            &["127.0.0.1:4873"],
        );
        assert_eq!(containment.status(), ProofStatus::Missing);
        assert_eq!(
            containment.reason_code(),
            "linux_containment_provider_unimplemented"
        );
        assert_eq!(
            containment.provenance().mechanism,
            ProofMechanism::LinuxNamespace
        );
        assert!(containment
            .provenance()
            .evidence
            .contains(&"provider_status=read_only_probe".to_string()));
        assert_read_only_provider_posture(&containment.provenance().evidence, "linux");
        assert_read_only_provider_posture(&egress.provenance().evidence, "linux");
        assert!(containment
            .provenance()
            .evidence
            .contains(&"platform_target=linux".to_string()));
        assert!(containment
            .provenance()
            .evidence
            .iter()
            .any(|signal| signal.starts_with("linux.proc_self_status.present=")));
        assert!(!containment.permits_high_risk());
        assert_eq!(egress.status(), ProofStatus::Missing);
        assert_eq!(egress.reason_code(), "linux_egress_provider_unimplemented");
        assert_eq!(
            egress.provenance().mechanism,
            ProofMechanism::LinuxPacketFilter
        );
        assert!(!egress.permits_only_configured_vault());
    }

    #[test]
    fn linux_readiness_parses_required_primitives_without_enabling_proofs() {
        let evidence = vec![
            "provider_target_matches_host=true".to_string(),
            "linux.proc_self_status.present=true".to_string(),
            "linux.proc_self_ns_user.present=true".to_string(),
            "linux.proc_self_ns_net.present=true".to_string(),
            "linux.cgroup_self.present=true".to_string(),
            "linux.no_new_privs=1".to_string(),
            "linux.seccomp_mode=2".to_string(),
            "linux.unprivileged_userns_clone=1".to_string(),
            "linux.landlock_abi_version=5".to_string(),
            "linux.unshare.present=true".to_string(),
            "linux.nft.present=true".to_string(),
        ];
        let readiness = linux_containment_readiness_from_evidence(&evidence);
        assert_eq!(readiness.target_matches_host, Some(true));
        assert_eq!(readiness.control_level, ProviderControlLevel::Partial);
        assert!(readiness.required_primitives_present);
        assert!(!readiness.proof_verification_enabled);
        assert_eq!(readiness.no_new_privs, Some(true));
        assert_eq!(readiness.seccomp_mode, Some(2));
        assert_eq!(readiness.landlock_abi_version, Some(5));
        assert!(readiness.namespace_creation_tool_available);
        assert!(readiness.packet_filter_tool_available);
        assert!(readiness
            .reason_codes
            .contains(&"linux_proof_verification_not_implemented".to_string()));
    }

    #[test]
    fn linux_verification_plan_does_not_verify_from_readiness_alone() {
        let evidence = vec![
            "provider_target_matches_host=true".to_string(),
            "linux.proc_self_status.present=true".to_string(),
            "linux.proc_self_ns_user.present=true".to_string(),
            "linux.proc_self_ns_net.present=true".to_string(),
            "linux.cgroup_self.present=true".to_string(),
            "linux.no_new_privs=1".to_string(),
            "linux.seccomp_mode=2".to_string(),
            "linux.unprivileged_userns_clone=1".to_string(),
            "linux.landlock_abi_version=5".to_string(),
            "linux.bubblewrap.present=true".to_string(),
            "linux.iptables.present=true".to_string(),
        ];
        let readiness = linux_containment_readiness_from_evidence(&evidence);
        let plan = linux_verification_plan_from_readiness(&readiness);
        assert_eq!(plan.platform, "linux");
        assert_eq!(plan.control_level, ProviderControlLevel::Partial);
        assert!(plan.prerequisites_present);
        assert!(!plan.proof_verification_enabled);
        assert!(!plan.can_verify_now);
        assert!(plan
            .required_checks
            .contains(&"verify_seccomp_filter".to_string()));
        assert!(plan
            .blocking_reason_codes
            .contains(&"linux_proof_verification_not_implemented".to_string()));
    }

    #[test]
    fn linux_readiness_requires_current_host_and_nonexecuted_tooling_signals() {
        let off_host_evidence = vec![
            "provider_target_matches_host=false".to_string(),
            "linux.proc_self_status.present=true".to_string(),
            "linux.proc_self_ns_user.present=true".to_string(),
            "linux.proc_self_ns_net.present=true".to_string(),
            "linux.cgroup_self.present=true".to_string(),
            "linux.no_new_privs=1".to_string(),
            "linux.seccomp_mode=2".to_string(),
            "linux.unprivileged_userns_clone=1".to_string(),
            "linux.landlock_abi_version=5".to_string(),
            "linux.unshare.present=true".to_string(),
            "linux.nft.present=true".to_string(),
        ];
        let off_host = linux_containment_readiness_from_evidence(&off_host_evidence);
        assert_eq!(off_host.control_level, ProviderControlLevel::DiagnosticOnly);
        assert!(!off_host.required_primitives_present);
        assert!(off_host
            .reason_codes
            .contains(&"linux_provider_target_not_current_host".to_string()));

        let missing_tool_evidence = vec![
            "provider_target_matches_host=true".to_string(),
            "linux.proc_self_status.present=true".to_string(),
            "linux.proc_self_ns_user.present=true".to_string(),
            "linux.proc_self_ns_net.present=true".to_string(),
            "linux.cgroup_self.present=true".to_string(),
            "linux.no_new_privs=1".to_string(),
            "linux.seccomp_mode=2".to_string(),
            "linux.unprivileged_userns_clone=1".to_string(),
            "linux.landlock_abi_version=5".to_string(),
        ];
        let missing_tool = linux_containment_readiness_from_evidence(&missing_tool_evidence);
        assert_eq!(
            missing_tool.control_level,
            ProviderControlLevel::DiagnosticOnly
        );
        assert!(!missing_tool.required_primitives_present);
        assert!(missing_tool
            .reason_codes
            .contains(&"linux_namespace_creation_tool_unavailable".to_string()));
        assert!(missing_tool
            .reason_codes
            .contains(&"linux_packet_filter_tool_unavailable".to_string()));
    }

    #[test]
    fn linux_readiness_reports_missing_primitives_from_provider_evidence() {
        let provider = LinuxLocalProofProvider;
        let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
        let readiness =
            linux_containment_readiness_from_evidence(&containment.provenance().evidence);
        assert!(!readiness.proof_verification_enabled);
        assert!(!readiness.required_primitives_present);
        assert!(readiness
            .reason_codes
            .contains(&"linux_proof_verification_not_implemented".to_string()));
    }

    #[test]
    fn macos_readiness_parses_vm_and_egress_primitives_without_enabling_proofs() {
        let evidence = vec![
            "provider_target_matches_host=true".to_string(),
            "macos.hypervisor_framework.present=true".to_string(),
            "macos.virtualization_framework.present=true".to_string(),
            "macos.endpointsecurity_framework.present=true".to_string(),
            "macos.network_extension_framework.present=true".to_string(),
            "macos.sandbox_exec.present=true".to_string(),
            "macos.pfctl.present=true".to_string(),
        ];
        let readiness = macos_containment_readiness_from_evidence(&evidence);
        assert_eq!(readiness.target_matches_host, Some(true));
        assert_eq!(readiness.control_level, ProviderControlLevel::Beta);
        assert!(readiness.required_primitives_present);
        assert!(readiness.vm_isolation_primitives_present);
        assert!(readiness.egress_control_primitives_present);
        assert!(readiness.telemetry_primitives_present);
        assert!(readiness.beta_containment);
        assert!(!readiness.proof_verification_enabled);
        assert!(readiness
            .reason_codes
            .contains(&"macos_vm_containment_beta".to_string()));
        assert!(readiness
            .reason_codes
            .contains(&"macos_proof_verification_not_implemented".to_string()));
    }

    #[test]
    fn macos_verification_plan_does_not_verify_from_readiness_alone() {
        let evidence = vec![
            "provider_target_matches_host=true".to_string(),
            "macos.hypervisor_framework.present=true".to_string(),
            "macos.virtualization_framework.present=true".to_string(),
            "macos.endpointsecurity_framework.present=true".to_string(),
            "macos.network_extension_framework.present=true".to_string(),
            "macos.sandbox_exec.present=true".to_string(),
            "macos.pfctl.present=true".to_string(),
        ];
        let readiness = macos_containment_readiness_from_evidence(&evidence);
        let plan = macos_verification_plan_from_readiness(&readiness);
        assert_eq!(plan.platform, "macos");
        assert_eq!(plan.control_level, ProviderControlLevel::Beta);
        assert!(plan.prerequisites_present);
        assert!(!plan.proof_verification_enabled);
        assert!(!plan.can_verify_now);
        assert!(plan
            .required_checks
            .contains(&"verify_virtualization_vm_boundary".to_string()));
        assert!(plan
            .blocking_reason_codes
            .contains(&"macos_vm_containment_beta".to_string()));
        assert!(plan
            .blocking_reason_codes
            .contains(&"macos_proof_verification_not_implemented".to_string()));
    }

    #[test]
    fn macos_readiness_requires_current_host_even_when_frameworks_exist() {
        let evidence = vec![
            "provider_target_matches_host=false".to_string(),
            "macos.hypervisor_framework.present=true".to_string(),
            "macos.virtualization_framework.present=true".to_string(),
            "macos.endpointsecurity_framework.present=true".to_string(),
            "macos.network_extension_framework.present=true".to_string(),
            "macos.sandbox_exec.present=true".to_string(),
            "macos.pfctl.present=true".to_string(),
        ];
        let readiness = macos_containment_readiness_from_evidence(&evidence);
        assert_eq!(
            readiness.control_level,
            ProviderControlLevel::DiagnosticOnly
        );
        assert!(!readiness.required_primitives_present);
        assert!(readiness
            .reason_codes
            .contains(&"macos_provider_target_not_current_host".to_string()));
    }

    #[test]
    fn macos_readiness_reports_beta_and_missing_verification_from_provider_evidence() {
        let provider = MacosLocalProofProvider;
        let containment = provider.prove_containment(ExecutionMode::BetaContainment);
        let readiness =
            macos_containment_readiness_from_evidence(&containment.provenance().evidence);
        assert!(readiness.beta_containment);
        assert!(!readiness.proof_verification_enabled);
        assert!(readiness
            .reason_codes
            .contains(&"macos_vm_containment_beta".to_string()));
        assert!(readiness
            .reason_codes
            .contains(&"macos_proof_verification_not_implemented".to_string()));
    }

    #[test]
    fn macos_local_provider_skeleton_fails_closed() {
        let provider = MacosLocalProofProvider;
        let containment = provider.prove_containment(ExecutionMode::BetaContainment);
        let egress = provider.prove_egress(
            ProofSubject::for_launch("launch-1"),
            "127.0.0.1:4873",
            &["127.0.0.1:4873"],
        );
        assert_eq!(containment.status(), ProofStatus::Missing);
        assert_eq!(
            containment.reason_code(),
            "macos_containment_provider_unimplemented"
        );
        assert_eq!(
            containment.provenance().mechanism,
            ProofMechanism::MacosVmBeta
        );
        assert!(containment
            .provenance()
            .evidence
            .contains(&"provider_status=read_only_probe".to_string()));
        assert_read_only_provider_posture(&containment.provenance().evidence, "macos");
        assert_read_only_provider_posture(&egress.provenance().evidence, "macos");
        assert!(containment
            .provenance()
            .evidence
            .contains(&"platform_target=macos".to_string()));
        assert!(containment
            .provenance()
            .evidence
            .iter()
            .any(|signal| signal.starts_with("macos.hypervisor_framework.present=")));
        assert!(!containment.permits_high_risk());
        assert_eq!(egress.status(), ProofStatus::Missing);
        assert_eq!(egress.reason_code(), "macos_egress_provider_unimplemented");
        assert_eq!(
            egress.provenance().mechanism,
            ProofMechanism::MacosPacketFilter
        );
        assert!(!egress.permits_only_configured_vault());
    }

    #[test]
    fn cleanup_lease_releases_tracked_paths_once() {
        let mut lease = CleanupLease::new("lease-1");
        lease.track_path("/tmp/whoathere-lease-1");
        let first = lease.release();
        let second = lease.release();
        assert_eq!(first, vec!["/tmp/whoathere-lease-1".to_string()]);
        assert!(second.is_empty());
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("whoathere-{label}-{}-{nanos}", std::process::id()))
    }
}
