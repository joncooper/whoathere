use crate::{
    valid_identity_component_v2, ArtifactReviewAuthErrorV2, ArtifactReviewKeyIdentityV2,
    MAX_ARTIFACT_REVIEW_POSITIVE_FINDING_IDS_V2, MAX_JCS_SAFE_INTEGER_V2,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::Mutex;
use whoathere_artifact::Sha256Digest;
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};

pub const ARTIFACT_REVIEW_CHALLENGE_SCHEMA_V2: &str =
    "whoathere.artifact_review_evidence_challenge.v2";
pub const ARTIFACT_REVIEW_CHALLENGE_CANONICALIZATION_V2: &str = "rfc8785.jcs.no_numbers.v1";
pub const MAX_ARTIFACT_REVIEW_CHALLENGE_TTL_SECONDS_V2: u64 = 15 * 60;
pub const MAX_ARTIFACT_REVIEW_CHALLENGE_WORK_ITEMS_V2: u32 = 512;
pub const MAX_ARTIFACT_REVIEW_ACTIVE_CHALLENGES_V2: usize = 4_096;
pub const MAX_ARTIFACT_REVIEW_EVIDENCE_RESERVATIONS_V2: usize = 16_384;
pub const MAX_ARTIFACT_REVIEW_LINEAGES_V2: usize = 4_096;
pub const MAX_ARTIFACT_REVIEW_TOTAL_POSITIVE_FINDING_REFERENCES_V2: usize = 65_536;

const CHALLENGE_ID_DOMAIN_V2: &[u8] = b"whoathere.artifact_review_evidence.challenge_id\0v2\0";
const AUTHORITY_ID_PREFIX_V2: &str = "arv2-authority-csprng256:";
const LINEAGE_SCOPE_DOMAIN_V2: &[u8] =
    b"whoathere.artifact_review_evidence.artifact_lineage_scope\0v2\0";

/// Random identity of one challenge authority lifetime. The value is created
/// only by the authority constructor and cannot be supplied by a caller.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ArtifactReviewChallengeAuthorityIdV2(String);

impl fmt::Debug for ArtifactReviewChallengeAuthorityIdV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ArtifactReviewChallengeAuthorityIdV2")
            .field(&self.0)
            .finish()
    }
}

impl ArtifactReviewChallengeAuthorityIdV2 {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn generate() -> Result<Self, ArtifactReviewAuthErrorV2> {
        let mut random = [0_u8; 32];
        getrandom::fill(&mut random).map_err(|_| ArtifactReviewAuthErrorV2::EntropyUnavailable)?;
        let mut value = String::with_capacity(AUTHORITY_ID_PREFIX_V2.len() + 64);
        value.push_str(AUTHORITY_ID_PREFIX_V2);
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
        }
        let authority_id = Self(value);
        if !authority_id.is_valid() {
            return Err(ArtifactReviewAuthErrorV2::EntropyUnavailable);
        }
        Ok(authority_id)
    }

    fn is_valid(&self) -> bool {
        valid_prefixed_lower_hex_256_v2(&self.0, AUTHORITY_ID_PREFIX_V2)
    }
}

/// Returns the only lineage scope accepted for repeated evidence about one
/// exact artifact. Trust domain remains a separate store key so issuer/key
/// rotation cannot reset positive findings within that domain.
pub fn canonical_artifact_review_lineage_scope_v2(
    subject: &ArtifactReviewSubjectBindingV2,
) -> Result<String, ArtifactReviewAuthErrorV2> {
    subject.validate()?;
    let mut input = Vec::with_capacity(
        LINEAGE_SCOPE_DOMAIN_V2.len() + subject.artifact_sha256().as_str().len(),
    );
    input.extend_from_slice(LINEAGE_SCOPE_DOMAIN_V2);
    input.extend_from_slice(subject.artifact_sha256().as_str().as_bytes());
    let digest = Sha256Digest::from_bytes(&input);
    Ok(format!(
        "arv2-lineage-sha256:{}",
        digest
            .as_str()
            .strip_prefix("sha256:")
            .expect("constructed SHA-256 digest has prefix")
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewSubjectBindingV2 {
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    cas_object_key: String,
}

impl ArtifactReviewSubjectBindingV2 {
    pub fn from_subject(
        subject: &ArtifactEvidenceSubjectV2,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        subject
            .validate_identity()
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidChallenge)?;
        let binding = Self {
            artifact_sha256: Sha256Digest::parse(subject.artifact_sha256())
                .map_err(|_| ArtifactReviewAuthErrorV2::InvalidChallenge)?,
            envelope_sha256: Sha256Digest::parse(subject.envelope_sha256())
                .map_err(|_| ArtifactReviewAuthErrorV2::InvalidChallenge)?,
            manifest_sha256: Sha256Digest::parse(subject.manifest_sha256())
                .map_err(|_| ArtifactReviewAuthErrorV2::InvalidChallenge)?,
            cas_object_key: subject.cas_object_key().to_string(),
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ArtifactReviewAuthErrorV2> {
        let expected = canonical_cas_object_key_for_artifact(self.artifact_sha256.as_str())
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidChallenge)?;
        if self.cas_object_key != expected {
            return Err(ArtifactReviewAuthErrorV2::InvalidChallenge);
        }
        Ok(())
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn envelope_sha256(&self) -> &Sha256Digest {
        &self.envelope_sha256
    }

    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub fn cas_object_key(&self) -> &str {
        &self.cas_object_key
    }
}

#[derive(Debug, Clone)]
pub struct ArtifactReviewChallengeDraftV2 {
    pub evidence_id: String,
    pub run_id: String,
    pub subject: ArtifactReviewSubjectBindingV2,
    pub policy_sha256: Sha256Digest,
    pub request_sha256: Sha256Digest,
    pub expected_work_set_sha256: Sha256Digest,
    pub expected_work_item_count: u32,
    pub key_identity: ArtifactReviewKeyIdentityV2,
    pub lineage_scope: String,
    pub predecessor_evidence_sha256: ExplicitDigestStateV2,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplicitDigestStateV2 {
    Absent,
    Present(Sha256Digest),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewChallengeBindingV2 {
    evidence_id: String,
    run_id: String,
    subject: ArtifactReviewSubjectBindingV2,
    policy_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    expected_work_set_sha256: Sha256Digest,
    expected_work_item_count: u32,
    key_identity: ArtifactReviewKeyIdentityV2,
    lineage_scope: String,
    predecessor_evidence_sha256: ExplicitDigestStateV2,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl ArtifactReviewChallengeBindingV2 {
    pub fn new(draft: ArtifactReviewChallengeDraftV2) -> Result<Self, ArtifactReviewAuthErrorV2> {
        let binding = Self {
            evidence_id: draft.evidence_id,
            run_id: draft.run_id,
            subject: draft.subject,
            policy_sha256: draft.policy_sha256,
            request_sha256: draft.request_sha256,
            expected_work_set_sha256: draft.expected_work_set_sha256,
            expected_work_item_count: draft.expected_work_item_count,
            key_identity: draft.key_identity,
            lineage_scope: draft.lineage_scope,
            predecessor_evidence_sha256: draft.predecessor_evidence_sha256,
            issued_at_unix_seconds: draft.issued_at_unix_seconds,
            expires_at_unix_seconds: draft.expires_at_unix_seconds,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn validate(&self) -> Result<(), ArtifactReviewAuthErrorV2> {
        self.subject.validate()?;
        self.key_identity.validate()?;
        let expected_lineage_scope = canonical_artifact_review_lineage_scope_v2(&self.subject)?;
        if !valid_identity_component_v2(&self.evidence_id)
            || !valid_identity_component_v2(&self.run_id)
            || !valid_identity_component_v2(&self.lineage_scope)
            || self.lineage_scope != expected_lineage_scope
            || self.expected_work_item_count == 0
            || self.expected_work_item_count > MAX_ARTIFACT_REVIEW_CHALLENGE_WORK_ITEMS_V2
            || self.issued_at_unix_seconds >= self.expires_at_unix_seconds
            || self.expires_at_unix_seconds > MAX_JCS_SAFE_INTEGER_V2
            || self.expires_at_unix_seconds - self.issued_at_unix_seconds
                > MAX_ARTIFACT_REVIEW_CHALLENGE_TTL_SECONDS_V2
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidChallenge);
        }
        Ok(())
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn subject(&self) -> &ArtifactReviewSubjectBindingV2 {
        &self.subject
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn expected_work_set_sha256(&self) -> &Sha256Digest {
        &self.expected_work_set_sha256
    }

    pub fn expected_work_item_count(&self) -> u32 {
        self.expected_work_item_count
    }

    pub fn key_identity(&self) -> &ArtifactReviewKeyIdentityV2 {
        &self.key_identity
    }

    pub fn lineage_scope(&self) -> &str {
        &self.lineage_scope
    }

    pub fn predecessor_evidence_sha256(&self) -> &ExplicitDigestStateV2 {
        &self.predecessor_evidence_sha256
    }

    pub fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    pub fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    fn canonical_json_for_authority_v2(
        &self,
        authority_id: &ArtifactReviewChallengeAuthorityIdV2,
    ) -> Result<Vec<u8>, ArtifactReviewAuthErrorV2> {
        self.validate()?;
        if !authority_id.is_valid() {
            return Err(ArtifactReviewAuthErrorV2::InvalidChallenge);
        }
        let predecessor = match &self.predecessor_evidence_sha256 {
            ExplicitDigestStateV2::Absent => ExplicitDigestWireV2::Absent,
            ExplicitDigestStateV2::Present(digest) => ExplicitDigestWireV2::Present {
                sha256: digest.as_str(),
            },
        };
        let wire = ChallengeBindingWireV2 {
            schema_version: ARTIFACT_REVIEW_CHALLENGE_SCHEMA_V2,
            canonicalization: ARTIFACT_REVIEW_CHALLENGE_CANONICALIZATION_V2,
            authority_id: authority_id.as_str(),
            evidence_id: &self.evidence_id,
            run_id: &self.run_id,
            artifact_sha256: self.subject.artifact_sha256.as_str(),
            envelope_sha256: self.subject.envelope_sha256.as_str(),
            manifest_sha256: self.subject.manifest_sha256.as_str(),
            cas_object_key: &self.subject.cas_object_key,
            policy_sha256: self.policy_sha256.as_str(),
            request_sha256: self.request_sha256.as_str(),
            expected_work_set_sha256: self.expected_work_set_sha256.as_str(),
            expected_work_item_count: self.expected_work_item_count.to_string(),
            trust_domain: self.key_identity.trust_domain(),
            issuer_id: self.key_identity.issuer_id(),
            producer_role: "host_control_plane",
            evidence_purpose: "restrictive_advisory_only",
            algorithm: self.key_identity.algorithm(),
            key_id: self.key_identity.key_id(),
            key_epoch: self.key_identity.key_epoch().to_string(),
            lineage_scope: &self.lineage_scope,
            predecessor_evidence_sha256: predecessor,
            issued_at_unix_seconds: self.issued_at_unix_seconds.to_string(),
            expires_at_unix_seconds: self.expires_at_unix_seconds.to_string(),
        };
        serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| ArtifactReviewAuthErrorV2::Serialization)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ChallengeBindingWireV2<'a> {
    schema_version: &'a str,
    canonicalization: &'a str,
    authority_id: &'a str,
    evidence_id: &'a str,
    run_id: &'a str,
    artifact_sha256: &'a str,
    envelope_sha256: &'a str,
    manifest_sha256: &'a str,
    cas_object_key: &'a str,
    policy_sha256: &'a str,
    request_sha256: &'a str,
    expected_work_set_sha256: &'a str,
    expected_work_item_count: String,
    trust_domain: &'a str,
    issuer_id: &'a str,
    producer_role: &'a str,
    evidence_purpose: &'a str,
    algorithm: &'a str,
    key_id: &'a str,
    key_epoch: String,
    lineage_scope: &'a str,
    predecessor_evidence_sha256: ExplicitDigestWireV2<'a>,
    issued_at_unix_seconds: String,
    expires_at_unix_seconds: String,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ExplicitDigestWireV2<'a> {
    Absent,
    Present { sha256: &'a str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewChallengeV2 {
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    challenge_id: String,
    binding: ArtifactReviewChallengeBindingV2,
}

impl ArtifactReviewChallengeV2 {
    pub fn authority_id(&self) -> &ArtifactReviewChallengeAuthorityIdV2 {
        &self.authority_id
    }

    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub fn binding(&self) -> &ArtifactReviewChallengeBindingV2 {
        &self.binding
    }

    pub fn canonical_binding_sha256_v2(&self) -> Result<Sha256Digest, ArtifactReviewAuthErrorV2> {
        self.validate()?;
        Ok(Sha256Digest::from_bytes(
            &self
                .binding
                .canonical_json_for_authority_v2(&self.authority_id)?,
        ))
    }

    pub fn validate(&self) -> Result<(), ArtifactReviewAuthErrorV2> {
        self.binding.validate()?;
        if !self.authority_id.is_valid() || !valid_challenge_id_v2(&self.challenge_id) {
            return Err(ArtifactReviewAuthErrorV2::InvalidChallenge);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewChallengeAcceptanceV2 {
    Accepted,
    IdempotentRetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewChallengeIssueOutcomeV2 {
    Issued,
    IdempotentRetry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewAuthorityDurabilityV2 {
    MemoryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewAuthorityProtectionV2 {
    NoRestartOrRollbackProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewChallengeIssueCommitReceiptV2 {
    challenge: ArtifactReviewChallengeV2,
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    generation: u64,
    outcome: ArtifactReviewChallengeIssueOutcomeV2,
    durability: ArtifactReviewAuthorityDurabilityV2,
    protection: ArtifactReviewAuthorityProtectionV2,
}

impl ArtifactReviewChallengeIssueCommitReceiptV2 {
    pub fn challenge(&self) -> &ArtifactReviewChallengeV2 {
        &self.challenge
    }

    pub fn into_challenge(self) -> ArtifactReviewChallengeV2 {
        self.challenge
    }

    pub fn authority_id(&self) -> &ArtifactReviewChallengeAuthorityIdV2 {
        &self.authority_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn outcome(&self) -> ArtifactReviewChallengeIssueOutcomeV2 {
        self.outcome
    }

    pub fn durability(&self) -> ArtifactReviewAuthorityDurabilityV2 {
        self.durability
    }

    pub fn protection(&self) -> ArtifactReviewAuthorityProtectionV2 {
        self.protection
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewChallengeAcceptanceCommitReceiptV2 {
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    generation: u64,
    outcome: ArtifactReviewChallengeAcceptanceV2,
    durability: ArtifactReviewAuthorityDurabilityV2,
    protection: ArtifactReviewAuthorityProtectionV2,
}

impl ArtifactReviewChallengeAcceptanceCommitReceiptV2 {
    pub fn authority_id(&self) -> &ArtifactReviewChallengeAuthorityIdV2 {
        &self.authority_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn outcome(&self) -> ArtifactReviewChallengeAcceptanceV2 {
        self.outcome
    }

    pub fn durability(&self) -> ArtifactReviewAuthorityDurabilityV2 {
        self.durability
    }

    pub fn protection(&self) -> ArtifactReviewAuthorityProtectionV2 {
        self.protection
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LineageStateV2 {
    head_evidence_sha256: Sha256Digest,
    cumulative_positive_finding_ids: BTreeSet<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EvidenceReservationV2 {
    Pending {
        challenge: ArtifactReviewChallengeV2,
    },
    Accepted {
        challenge: ArtifactReviewChallengeV2,
        evidence_sha256: Sha256Digest,
        current_positive_finding_ids: Vec<Sha256Digest>,
        cumulative_positive_finding_ids: Vec<Sha256Digest>,
    },
}

impl EvidenceReservationV2 {
    fn challenge(&self) -> &ArtifactReviewChallengeV2 {
        match self {
            Self::Pending { challenge } | Self::Accepted { challenge, .. } => challenge,
        }
    }

    fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct ChallengeAuthorityStateV2 {
    generation: u64,
    reservations: BTreeMap<(String, String), EvidenceReservationV2>,
    lineages: BTreeMap<(String, String), LineageStateV2>,
    total_positive_finding_references: usize,
}

#[derive(Debug, Clone, Copy)]
struct ChallengeAuthorityLimitsV2 {
    active_challenges: usize,
    reservations: usize,
    lineages: usize,
    total_positive_finding_references: usize,
}

impl ChallengeAuthorityLimitsV2 {
    const PRODUCTION: Self = Self {
        active_challenges: MAX_ARTIFACT_REVIEW_ACTIVE_CHALLENGES_V2,
        reservations: MAX_ARTIFACT_REVIEW_EVIDENCE_RESERVATIONS_V2,
        lineages: MAX_ARTIFACT_REVIEW_LINEAGES_V2,
        total_positive_finding_references: MAX_ARTIFACT_REVIEW_TOTAL_POSITIVE_FINDING_REFERENCES_V2,
    };
}

enum ArtifactReviewChallengeAuthorityBackendV2 {
    MemoryOnly {
        state: Mutex<ChallengeAuthorityStateV2>,
        limits: ChallengeAuthorityLimitsV2,
    },
}

/// Sealed challenge authority façade. This slice intentionally exposes only a
/// memory-only backend and makes its lack of restart/rollback protection
/// explicit in every commit receipt.
pub struct ArtifactReviewChallengeAuthorityV2 {
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    backend: ArtifactReviewChallengeAuthorityBackendV2,
}

impl fmt::Debug for ArtifactReviewChallengeAuthorityV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactReviewChallengeAuthorityV2")
            .field("authority_id", &self.authority_id)
            .field(
                "durability",
                &ArtifactReviewAuthorityDurabilityV2::MemoryOnly,
            )
            .field(
                "protection",
                &ArtifactReviewAuthorityProtectionV2::NoRestartOrRollbackProtection,
            )
            .finish_non_exhaustive()
    }
}

impl ArtifactReviewChallengeAuthorityV2 {
    pub fn new_memory_only() -> Result<Self, ArtifactReviewAuthErrorV2> {
        Self::new_memory_only_with_limits(ChallengeAuthorityLimitsV2::PRODUCTION)
    }

    fn new_memory_only_with_limits(
        limits: ChallengeAuthorityLimitsV2,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        if limits.active_challenges == 0
            || limits.reservations == 0
            || limits.lineages == 0
            || limits.total_positive_finding_references == 0
            || limits.active_challenges > MAX_ARTIFACT_REVIEW_ACTIVE_CHALLENGES_V2
            || limits.reservations > MAX_ARTIFACT_REVIEW_EVIDENCE_RESERVATIONS_V2
            || limits.lineages > MAX_ARTIFACT_REVIEW_LINEAGES_V2
            || limits.total_positive_finding_references
                > MAX_ARTIFACT_REVIEW_TOTAL_POSITIVE_FINDING_REFERENCES_V2
        {
            return Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded);
        }
        Ok(Self {
            authority_id: ArtifactReviewChallengeAuthorityIdV2::generate()?,
            backend: ArtifactReviewChallengeAuthorityBackendV2::MemoryOnly {
                state: Mutex::new(ChallengeAuthorityStateV2::default()),
                limits,
            },
        })
    }

    pub fn authority_id(&self) -> &ArtifactReviewChallengeAuthorityIdV2 {
        &self.authority_id
    }

    pub fn issue(
        &self,
        binding: ArtifactReviewChallengeBindingV2,
    ) -> Result<ArtifactReviewChallengeIssueCommitReceiptV2, ArtifactReviewAuthErrorV2> {
        let ArtifactReviewChallengeAuthorityBackendV2::MemoryOnly { state, limits } = &self.backend;
        let mut current = state
            .lock()
            .map_err(|_| ArtifactReviewAuthErrorV2::StateUnavailable)?;
        if let Some(commit) =
            issue_transition_v2(&current, &self.authority_id, &binding, None, *limits)?
        {
            return Ok(commit.receipt);
        }
        for _ in 0..4 {
            let mut nonce = [0_u8; 32];
            getrandom::fill(&mut nonce)
                .map_err(|_| ArtifactReviewAuthErrorV2::EntropyUnavailable)?;
            match issue_transition_v2(&current, &self.authority_id, &binding, Some(nonce), *limits)
            {
                Ok(Some(commit)) => {
                    *current = commit.next_state;
                    return Ok(commit.receipt);
                }
                Err(ArtifactReviewAuthErrorV2::DuplicateChallenge) => continue,
                Ok(None) => unreachable!("entropy was supplied for a new challenge"),
                Err(error) => return Err(error),
            }
        }
        Err(ArtifactReviewAuthErrorV2::DuplicateChallenge)
    }

    pub(crate) fn ensure_owns_challenge(
        &self,
        challenge: &ArtifactReviewChallengeV2,
    ) -> Result<(), ArtifactReviewAuthErrorV2> {
        challenge.validate()?;
        if challenge.authority_id() != &self.authority_id {
            return Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
        }
        Ok(())
    }

    pub(crate) fn accept_verified_evidence_with_findings(
        &self,
        challenge: &ArtifactReviewChallengeV2,
        evidence_sha256: Sha256Digest,
        current_positive_finding_ids: &[Sha256Digest],
        claimed_cumulative_positive_finding_ids: &[Sha256Digest],
        now_unix_seconds: u64,
    ) -> Result<ArtifactReviewChallengeAcceptanceCommitReceiptV2, ArtifactReviewAuthErrorV2> {
        let ArtifactReviewChallengeAuthorityBackendV2::MemoryOnly { state, limits } = &self.backend;
        let mut current = state
            .lock()
            .map_err(|_| ArtifactReviewAuthErrorV2::StateUnavailable)?;
        let commit = acceptance_transition_v2(
            &current,
            &self.authority_id,
            challenge,
            evidence_sha256,
            current_positive_finding_ids,
            claimed_cumulative_positive_finding_ids,
            now_unix_seconds,
            *limits,
        )?;
        if commit.receipt.outcome == ArtifactReviewChallengeAcceptanceV2::Accepted {
            *current = commit.next_state;
        }
        Ok(commit.receipt)
    }

    pub fn current_lineage_head(
        &self,
        trust_domain: &str,
        lineage_scope: &str,
    ) -> Result<Option<Sha256Digest>, ArtifactReviewAuthErrorV2> {
        let ArtifactReviewChallengeAuthorityBackendV2::MemoryOnly { state, .. } = &self.backend;
        let state = state
            .lock()
            .map_err(|_| ArtifactReviewAuthErrorV2::StateUnavailable)?;
        Ok(state
            .lineages
            .get(&(trust_domain.to_string(), lineage_scope.to_string()))
            .map(|lineage| lineage.head_evidence_sha256.clone()))
    }

    pub fn cumulative_positive_finding_ids(
        &self,
        trust_domain: &str,
        lineage_scope: &str,
    ) -> Result<Vec<Sha256Digest>, ArtifactReviewAuthErrorV2> {
        let ArtifactReviewChallengeAuthorityBackendV2::MemoryOnly { state, .. } = &self.backend;
        let state = state
            .lock()
            .map_err(|_| ArtifactReviewAuthErrorV2::StateUnavailable)?;
        Ok(state
            .lineages
            .get(&(trust_domain.to_string(), lineage_scope.to_string()))
            .map(|lineage| {
                lineage
                    .cumulative_positive_finding_ids
                    .iter()
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    #[cfg(test)]
    fn state_snapshot_for_tests(
        &self,
    ) -> Result<ChallengeAuthorityStateV2, ArtifactReviewAuthErrorV2> {
        let ArtifactReviewChallengeAuthorityBackendV2::MemoryOnly { state, .. } = &self.backend;
        state
            .lock()
            .map_err(|_| ArtifactReviewAuthErrorV2::StateUnavailable)
            .map(|state| state.clone())
    }
}

struct IssueTransitionCommitV2 {
    next_state: ChallengeAuthorityStateV2,
    receipt: ArtifactReviewChallengeIssueCommitReceiptV2,
}

fn issue_transition_v2(
    state: &ChallengeAuthorityStateV2,
    authority_id: &ArtifactReviewChallengeAuthorityIdV2,
    binding: &ArtifactReviewChallengeBindingV2,
    nonce: Option<[u8; 32]>,
    limits: ChallengeAuthorityLimitsV2,
) -> Result<Option<IssueTransitionCommitV2>, ArtifactReviewAuthErrorV2> {
    binding.validate()?;
    if !authority_id.is_valid() {
        return Err(ArtifactReviewAuthErrorV2::InvalidChallenge);
    }
    let reservation_key = (
        binding.key_identity().trust_domain().to_string(),
        binding.evidence_id().to_string(),
    );
    if let Some(reservation) = state.reservations.get(&reservation_key) {
        return match reservation {
            EvidenceReservationV2::Pending { challenge } if challenge.binding() == binding => {
                Ok(Some(IssueTransitionCommitV2 {
                    next_state: state.clone(),
                    receipt: issue_receipt_v2(
                        challenge.clone(),
                        state.generation,
                        ArtifactReviewChallengeIssueOutcomeV2::IdempotentRetry,
                    ),
                }))
            }
            EvidenceReservationV2::Pending { .. } | EvidenceReservationV2::Accepted { .. } => {
                Err(ArtifactReviewAuthErrorV2::ReplayOrEquivocation)
            }
        };
    }
    let Some(nonce) = nonce else {
        return Ok(None);
    };
    let active_challenges = state
        .reservations
        .values()
        .filter(|reservation| reservation.is_pending())
        .count();
    if active_challenges >= limits.active_challenges
        || state.reservations.len() >= limits.reservations
    {
        return Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded);
    }
    let challenge = challenge_from_nonce_v2(authority_id, binding.clone(), nonce)?;
    if state
        .reservations
        .values()
        .any(|reservation| reservation.challenge().challenge_id() == challenge.challenge_id())
    {
        return Err(ArtifactReviewAuthErrorV2::DuplicateChallenge);
    }
    let next_generation = next_authority_generation_v2(state.generation)?;
    let mut next_state = state.clone();
    next_state.generation = next_generation;
    next_state.reservations.insert(
        reservation_key,
        EvidenceReservationV2::Pending {
            challenge: challenge.clone(),
        },
    );
    Ok(Some(IssueTransitionCommitV2 {
        next_state,
        receipt: issue_receipt_v2(
            challenge,
            next_generation,
            ArtifactReviewChallengeIssueOutcomeV2::Issued,
        ),
    }))
}

fn issue_receipt_v2(
    challenge: ArtifactReviewChallengeV2,
    generation: u64,
    outcome: ArtifactReviewChallengeIssueOutcomeV2,
) -> ArtifactReviewChallengeIssueCommitReceiptV2 {
    ArtifactReviewChallengeIssueCommitReceiptV2 {
        authority_id: challenge.authority_id().clone(),
        challenge,
        generation,
        outcome,
        durability: ArtifactReviewAuthorityDurabilityV2::MemoryOnly,
        protection: ArtifactReviewAuthorityProtectionV2::NoRestartOrRollbackProtection,
    }
}

struct AcceptanceTransitionCommitV2 {
    next_state: ChallengeAuthorityStateV2,
    receipt: ArtifactReviewChallengeAcceptanceCommitReceiptV2,
}

#[allow(clippy::too_many_arguments)]
fn acceptance_transition_v2(
    state: &ChallengeAuthorityStateV2,
    authority_id: &ArtifactReviewChallengeAuthorityIdV2,
    challenge: &ArtifactReviewChallengeV2,
    evidence_sha256: Sha256Digest,
    current_positive_finding_ids: &[Sha256Digest],
    claimed_cumulative_positive_finding_ids: &[Sha256Digest],
    now_unix_seconds: u64,
    limits: ChallengeAuthorityLimitsV2,
) -> Result<AcceptanceTransitionCommitV2, ArtifactReviewAuthErrorV2> {
    challenge.validate()?;
    if challenge.authority_id() != authority_id {
        return Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
    }
    let reservation_key = (
        challenge
            .binding()
            .key_identity()
            .trust_domain()
            .to_string(),
        challenge.binding().evidence_id().to_string(),
    );
    let reservation = state
        .reservations
        .get(&reservation_key)
        .ok_or(ArtifactReviewAuthErrorV2::UnknownChallenge)?;
    if reservation.challenge() != challenge {
        return Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
    }
    if let EvidenceReservationV2::Accepted {
        evidence_sha256: accepted_evidence_sha256,
        current_positive_finding_ids: accepted_current,
        cumulative_positive_finding_ids: accepted_cumulative,
        ..
    } = reservation
    {
        return if accepted_evidence_sha256 == &evidence_sha256
            && accepted_current == current_positive_finding_ids
            && accepted_cumulative == claimed_cumulative_positive_finding_ids
        {
            Ok(AcceptanceTransitionCommitV2 {
                next_state: state.clone(),
                receipt: acceptance_receipt_v2(
                    authority_id.clone(),
                    state.generation,
                    ArtifactReviewChallengeAcceptanceV2::IdempotentRetry,
                ),
            })
        } else {
            Err(ArtifactReviewAuthErrorV2::ReplayOrEquivocation)
        };
    }
    if current_positive_finding_ids.len() > MAX_ARTIFACT_REVIEW_POSITIVE_FINDING_IDS_V2
        || claimed_cumulative_positive_finding_ids.len()
            > MAX_ARTIFACT_REVIEW_POSITIVE_FINDING_IDS_V2
    {
        return Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded);
    }
    if !strictly_sorted_unique_digests_v2(current_positive_finding_ids)
        || !strictly_sorted_unique_digests_v2(claimed_cumulative_positive_finding_ids)
    {
        return Err(ArtifactReviewAuthErrorV2::InvalidStatement);
    }
    if now_unix_seconds < challenge.binding().issued_at_unix_seconds() {
        return Err(ArtifactReviewAuthErrorV2::ChallengeNotYetActive);
    }
    if now_unix_seconds >= challenge.binding().expires_at_unix_seconds() {
        return Err(ArtifactReviewAuthErrorV2::ChallengeExpired);
    }

    let lineage_key = (
        challenge
            .binding()
            .key_identity()
            .trust_domain()
            .to_string(),
        challenge.binding().lineage_scope().to_string(),
    );
    let current_lineage = state.lineages.get(&lineage_key);
    let lineage_matches = match challenge.binding().predecessor_evidence_sha256() {
        ExplicitDigestStateV2::Absent => current_lineage.is_none(),
        ExplicitDigestStateV2::Present(expected) => {
            current_lineage.is_some_and(|lineage| &lineage.head_evidence_sha256 == expected)
        }
    };
    if !lineage_matches {
        return Err(ArtifactReviewAuthErrorV2::LineageConflict);
    }
    let mut expected_cumulative = current_lineage
        .map(|lineage| lineage.cumulative_positive_finding_ids.clone())
        .unwrap_or_default();
    expected_cumulative.extend(current_positive_finding_ids.iter().cloned());
    if expected_cumulative
        .iter()
        .ne(claimed_cumulative_positive_finding_ids)
    {
        return Err(ArtifactReviewAuthErrorV2::LineageConflict);
    }
    if expected_cumulative.len() > MAX_ARTIFACT_REVIEW_POSITIVE_FINDING_IDS_V2 {
        return Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded);
    }
    if current_lineage.is_none() && state.lineages.len() >= limits.lineages {
        return Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded);
    }
    let old_reference_count = current_lineage
        .map(|lineage| lineage.cumulative_positive_finding_ids.len())
        .unwrap_or(0);
    let prospective_reference_count = state
        .total_positive_finding_references
        .checked_sub(old_reference_count)
        .and_then(|value| value.checked_add(expected_cumulative.len()))
        .and_then(|value| value.checked_add(current_positive_finding_ids.len()))
        .and_then(|value| value.checked_add(claimed_cumulative_positive_finding_ids.len()))
        .ok_or(ArtifactReviewAuthErrorV2::StoreCapacityExceeded)?;
    if prospective_reference_count > limits.total_positive_finding_references {
        return Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded);
    }
    let next_generation = next_authority_generation_v2(state.generation)?;
    let mut next_state = state.clone();
    next_state.generation = next_generation;
    next_state.total_positive_finding_references = prospective_reference_count;
    next_state.reservations.insert(
        reservation_key,
        EvidenceReservationV2::Accepted {
            challenge: challenge.clone(),
            evidence_sha256: evidence_sha256.clone(),
            current_positive_finding_ids: current_positive_finding_ids.to_vec(),
            cumulative_positive_finding_ids: claimed_cumulative_positive_finding_ids.to_vec(),
        },
    );
    next_state.lineages.insert(
        lineage_key,
        LineageStateV2 {
            head_evidence_sha256: evidence_sha256,
            cumulative_positive_finding_ids: expected_cumulative,
        },
    );
    Ok(AcceptanceTransitionCommitV2 {
        next_state,
        receipt: acceptance_receipt_v2(
            authority_id.clone(),
            next_generation,
            ArtifactReviewChallengeAcceptanceV2::Accepted,
        ),
    })
}

fn acceptance_receipt_v2(
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    generation: u64,
    outcome: ArtifactReviewChallengeAcceptanceV2,
) -> ArtifactReviewChallengeAcceptanceCommitReceiptV2 {
    ArtifactReviewChallengeAcceptanceCommitReceiptV2 {
        authority_id,
        generation,
        outcome,
        durability: ArtifactReviewAuthorityDurabilityV2::MemoryOnly,
        protection: ArtifactReviewAuthorityProtectionV2::NoRestartOrRollbackProtection,
    }
}

fn next_authority_generation_v2(generation: u64) -> Result<u64, ArtifactReviewAuthErrorV2> {
    if generation >= MAX_JCS_SAFE_INTEGER_V2 {
        return Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded);
    }
    Ok(generation + 1)
}

fn challenge_from_nonce_v2(
    authority_id: &ArtifactReviewChallengeAuthorityIdV2,
    binding: ArtifactReviewChallengeBindingV2,
    nonce: [u8; 32],
) -> Result<ArtifactReviewChallengeV2, ArtifactReviewAuthErrorV2> {
    let binding_bytes = binding.canonical_json_for_authority_v2(authority_id)?;
    let authority_bytes = authority_id.as_str().as_bytes();
    let mut input = Vec::with_capacity(
        CHALLENGE_ID_DOMAIN_V2.len()
            + 8
            + authority_bytes.len()
            + nonce.len()
            + 8
            + binding_bytes.len(),
    );
    input.extend_from_slice(CHALLENGE_ID_DOMAIN_V2);
    input.extend_from_slice(&(authority_bytes.len() as u64).to_be_bytes());
    input.extend_from_slice(authority_bytes);
    input.extend_from_slice(&nonce);
    input.extend_from_slice(&(binding_bytes.len() as u64).to_be_bytes());
    input.extend_from_slice(&binding_bytes);
    let digest = Sha256Digest::from_bytes(&input);
    let challenge = ArtifactReviewChallengeV2 {
        authority_id: authority_id.clone(),
        challenge_id: format!(
            "arv2-challenge-sha256:{}",
            digest
                .as_str()
                .strip_prefix("sha256:")
                .expect("constructed SHA-256 digest has prefix")
        ),
        binding,
    };
    challenge.validate()?;
    Ok(challenge)
}

fn strictly_sorted_unique_digests_v2(values: &[Sha256Digest]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn valid_challenge_id_v2(value: &str) -> bool {
    valid_prefixed_lower_hex_256_v2(value, "arv2-challenge-sha256:")
}

fn valid_prefixed_lower_hex_256_v2(value: &str, prefix: &str) -> bool {
    let Some(hex) = value.strip_prefix(prefix) else {
        return false;
    };
    hex.len() == 64
        && hex
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ArtifactReviewKeyIdentityV2;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use whoathere_evidence::v2::{
        canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2,
    };

    #[derive(Debug)]
    struct TestAuthorityV2(ArtifactReviewChallengeAuthorityV2);

    impl TestAuthorityV2 {
        fn new() -> Self {
            Self(
                ArtifactReviewChallengeAuthorityV2::new_memory_only()
                    .expect("memory-only authority"),
            )
        }

        fn issue(
            &self,
            binding: ArtifactReviewChallengeBindingV2,
        ) -> Result<ArtifactReviewChallengeV2, ArtifactReviewAuthErrorV2> {
            self.0
                .issue(binding)
                .map(|receipt| receipt.into_challenge())
        }

        fn accept_verified_evidence_with_findings(
            &self,
            challenge: &ArtifactReviewChallengeV2,
            evidence_sha256: Sha256Digest,
            current: &[Sha256Digest],
            cumulative: &[Sha256Digest],
            now: u64,
        ) -> Result<ArtifactReviewChallengeAcceptanceV2, ArtifactReviewAuthErrorV2> {
            self.0
                .accept_verified_evidence_with_findings(
                    challenge,
                    evidence_sha256,
                    current,
                    cumulative,
                    now,
                )
                .map(|receipt| receipt.outcome())
        }

        fn current_lineage_head(
            &self,
            trust_domain: &str,
            lineage_scope: &str,
        ) -> Result<Option<Sha256Digest>, ArtifactReviewAuthErrorV2> {
            self.0.current_lineage_head(trust_domain, lineage_scope)
        }

        fn cumulative_positive_finding_ids(
            &self,
            trust_domain: &str,
            lineage_scope: &str,
        ) -> Result<Vec<Sha256Digest>, ArtifactReviewAuthErrorV2> {
            self.0
                .cumulative_positive_finding_ids(trust_domain, lineage_scope)
        }
    }

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn subject() -> ArtifactReviewSubjectBindingV2 {
        subject_with_label("challenge-test")
    }

    fn subject_with_label(label: &str) -> ArtifactReviewSubjectBindingV2 {
        let artifact = digest(&format!("{label}-artifact"));
        let subject = ArtifactEvidenceSubjectV2::new(
            artifact.as_str(),
            digest(&format!("{label}-envelope")).as_str(),
            digest(&format!("{label}-manifest")).as_str(),
            canonical_cas_object_key_for_artifact(artifact.as_str()).expect("CAS key"),
        )
        .expect("subject");
        ArtifactReviewSubjectBindingV2::from_subject(&subject).expect("binding")
    }

    fn key_identity() -> ArtifactReviewKeyIdentityV2 {
        ArtifactReviewKeyIdentityV2::new_host_control_plane(
            "challenge-test-domain",
            "challenge-test-issuer",
            "challenge-test-key",
            1,
        )
        .expect("key identity")
    }

    fn rotated_key_identity() -> ArtifactReviewKeyIdentityV2 {
        ArtifactReviewKeyIdentityV2::new_host_control_plane(
            "challenge-test-domain",
            "challenge-test-rotated-issuer",
            "challenge-test-rotated-key",
            2,
        )
        .expect("rotated key identity")
    }

    fn binding(
        evidence_id: &str,
        run_id: &str,
        predecessor: ExplicitDigestStateV2,
    ) -> ArtifactReviewChallengeBindingV2 {
        binding_with_key_identity(evidence_id, run_id, predecessor, key_identity())
    }

    fn binding_with_key_identity(
        evidence_id: &str,
        run_id: &str,
        predecessor: ExplicitDigestStateV2,
        key_identity: ArtifactReviewKeyIdentityV2,
    ) -> ArtifactReviewChallengeBindingV2 {
        binding_with_subject_and_key_identity(
            evidence_id,
            run_id,
            predecessor,
            subject(),
            key_identity,
        )
    }

    fn binding_with_subject_and_key_identity(
        evidence_id: &str,
        run_id: &str,
        predecessor: ExplicitDigestStateV2,
        subject: ArtifactReviewSubjectBindingV2,
        key_identity: ArtifactReviewKeyIdentityV2,
    ) -> ArtifactReviewChallengeBindingV2 {
        let lineage_scope =
            canonical_artifact_review_lineage_scope_v2(&subject).expect("lineage scope");
        ArtifactReviewChallengeBindingV2::new(ArtifactReviewChallengeDraftV2 {
            evidence_id: evidence_id.to_string(),
            run_id: run_id.to_string(),
            subject,
            policy_sha256: digest("challenge-test-policy"),
            request_sha256: digest("challenge-test-request"),
            expected_work_set_sha256: digest("challenge-test-work-set"),
            expected_work_item_count: 3,
            key_identity,
            lineage_scope,
            predecessor_evidence_sha256: predecessor,
            issued_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 1_300,
        })
        .expect("challenge binding")
    }

    fn limits(
        active_challenges: usize,
        reservations: usize,
        lineages: usize,
        total_positive_finding_references: usize,
    ) -> ChallengeAuthorityLimitsV2 {
        ChallengeAuthorityLimitsV2 {
            active_challenges,
            reservations,
            lineages,
            total_positive_finding_references,
        }
    }

    #[test]
    fn exact_issue_retry_reuses_challenge_generation_and_explicit_memory_posture() {
        let authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
        let issue_binding = binding(
            "evidence-issue-retry",
            "run-issue-retry",
            ExplicitDigestStateV2::Absent,
        );
        let first = authority
            .issue(issue_binding.clone())
            .expect("first issue commit");
        assert_eq!(
            first.outcome(),
            ArtifactReviewChallengeIssueOutcomeV2::Issued
        );
        assert_eq!(first.generation(), 1);
        assert_eq!(first.authority_id(), authority.authority_id());
        assert_eq!(first.challenge().authority_id(), authority.authority_id());
        assert_eq!(
            first.durability(),
            ArtifactReviewAuthorityDurabilityV2::MemoryOnly
        );
        assert_eq!(
            first.protection(),
            ArtifactReviewAuthorityProtectionV2::NoRestartOrRollbackProtection
        );
        assert!(valid_prefixed_lower_hex_256_v2(
            authority.authority_id().as_str(),
            AUTHORITY_ID_PREFIX_V2
        ));
        let retry = authority
            .issue(issue_binding.clone())
            .expect("exact issue retry commit");
        assert_eq!(
            retry.outcome(),
            ArtifactReviewChallengeIssueOutcomeV2::IdempotentRetry
        );
        assert_eq!(retry.generation(), 1);
        assert_eq!(retry.challenge(), first.challenge());

        let other_authority =
            ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("other authority");
        let other = other_authority
            .issue(issue_binding)
            .expect("other authority issue");
        assert_ne!(
            other.challenge().challenge_id(),
            first.challenge().challenge_id()
        );
        assert_ne!(
            other
                .challenge()
                .canonical_binding_sha256_v2()
                .expect("other challenge binding digest"),
            first
                .challenge()
                .canonical_binding_sha256_v2()
                .expect("first challenge binding digest")
        );

        let before_conflict = authority.state_snapshot_for_tests().expect("snapshot");
        assert_eq!(
            authority.issue(binding(
                "evidence-issue-retry",
                "run-changed-before-execution",
                ExplicitDigestStateV2::Absent,
            )),
            Err(ArtifactReviewAuthErrorV2::ReplayOrEquivocation)
        );
        assert_eq!(
            authority.state_snapshot_for_tests().expect("snapshot"),
            before_conflict
        );
    }

    #[test]
    fn generation_cannot_cross_the_canonical_jcs_integer_boundary() {
        let authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
        let state = ChallengeAuthorityStateV2 {
            generation: MAX_JCS_SAFE_INTEGER_V2,
            ..ChallengeAuthorityStateV2::default()
        };
        let unchanged = state.clone();
        assert!(matches!(
            issue_transition_v2(
                &state,
                authority.authority_id(),
                &binding(
                    "evidence-generation-boundary",
                    "run-generation-boundary",
                    ExplicitDigestStateV2::Absent,
                ),
                Some([29_u8; 32]),
                ChallengeAuthorityLimitsV2::PRODUCTION,
            ),
            Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded)
        ));
        assert_eq!(state, unchanged);
    }

    #[test]
    fn authority_substitution_fails_before_acceptance_without_mutation() {
        let authority_a =
            ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority A");
        let authority_b =
            ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority B");
        let issue = authority_a
            .issue(binding(
                "evidence-authority-a",
                "run-authority-a",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("A issue");
        let challenge = issue.challenge().clone();
        let a_before = authority_a.state_snapshot_for_tests().expect("A snapshot");
        let b_before = authority_b.state_snapshot_for_tests().expect("B snapshot");
        assert_eq!(
            authority_b.accept_verified_evidence_with_findings(
                &challenge,
                digest("authority-a-evidence"),
                &[],
                &[],
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch)
        );
        assert_eq!(
            authority_a.state_snapshot_for_tests().expect("A snapshot"),
            a_before
        );
        assert_eq!(
            authority_b.state_snapshot_for_tests().expect("B snapshot"),
            b_before
        );
        let accepted = authority_a
            .accept_verified_evidence_with_findings(
                &challenge,
                digest("authority-a-evidence"),
                &[],
                &[],
                1_004,
            )
            .expect("A acceptance");
        assert_eq!(
            accepted.outcome(),
            ArtifactReviewChallengeAcceptanceV2::Accepted
        );
        assert_eq!(accepted.generation(), 2);
        assert_eq!(accepted.authority_id(), authority_a.authority_id());
    }

    #[test]
    fn reduced_limits_fail_closed_without_mutating_candidate_state() {
        let active_limited =
            ArtifactReviewChallengeAuthorityV2::new_memory_only_with_limits(limits(1, 4, 4, 16))
                .expect("active-limited authority");
        active_limited
            .issue(binding(
                "evidence-active-one",
                "run-active-one",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("first active challenge");
        let before_active_error = active_limited
            .state_snapshot_for_tests()
            .expect("active snapshot");
        assert_eq!(
            active_limited.issue(binding(
                "evidence-active-two",
                "run-active-two",
                ExplicitDigestStateV2::Absent,
            )),
            Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded)
        );
        assert_eq!(
            active_limited
                .state_snapshot_for_tests()
                .expect("active snapshot"),
            before_active_error
        );

        let reservation_limited =
            ArtifactReviewChallengeAuthorityV2::new_memory_only_with_limits(limits(2, 1, 2, 8))
                .expect("reservation-limited authority");
        let first = reservation_limited
            .issue(binding(
                "evidence-reservation-one",
                "run-reservation-one",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("reservation issue")
            .into_challenge();
        reservation_limited
            .accept_verified_evidence_with_findings(
                &first,
                digest("reservation-evidence-one"),
                &[],
                &[],
                1_004,
            )
            .expect("reservation acceptance");
        let before_reservation_error = reservation_limited
            .state_snapshot_for_tests()
            .expect("reservation snapshot");
        assert_eq!(
            reservation_limited.issue(binding_with_subject_and_key_identity(
                "evidence-reservation-two",
                "run-reservation-two",
                ExplicitDigestStateV2::Absent,
                subject_with_label("reservation-two"),
                key_identity(),
            )),
            Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded)
        );
        assert_eq!(
            reservation_limited
                .state_snapshot_for_tests()
                .expect("reservation snapshot"),
            before_reservation_error
        );

        let lineage_limited =
            ArtifactReviewChallengeAuthorityV2::new_memory_only_with_limits(limits(2, 4, 1, 8))
                .expect("lineage-limited authority");
        let first = lineage_limited
            .issue(binding(
                "evidence-lineage-one",
                "run-lineage-one",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("first lineage issue")
            .into_challenge();
        lineage_limited
            .accept_verified_evidence_with_findings(
                &first,
                digest("lineage-evidence-one"),
                &[],
                &[],
                1_004,
            )
            .expect("first lineage acceptance");
        let second = lineage_limited
            .issue(binding_with_subject_and_key_identity(
                "evidence-lineage-two",
                "run-lineage-two",
                ExplicitDigestStateV2::Absent,
                subject_with_label("lineage-two"),
                key_identity(),
            ))
            .expect("second lineage issue")
            .into_challenge();
        let before_lineage_error = lineage_limited
            .state_snapshot_for_tests()
            .expect("lineage snapshot");
        assert_eq!(
            lineage_limited.accept_verified_evidence_with_findings(
                &second,
                digest("lineage-evidence-two"),
                &[],
                &[],
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded)
        );
        assert_eq!(
            lineage_limited
                .state_snapshot_for_tests()
                .expect("lineage snapshot"),
            before_lineage_error
        );

        // One accepted positive is stored three times: current and cumulative
        // on its reservation, plus cumulative on the lineage. A successor with
        // no new positives still needs another retained cumulative reference.
        let references_limited =
            ArtifactReviewChallengeAuthorityV2::new_memory_only_with_limits(limits(2, 4, 2, 3))
                .expect("reference-limited authority");
        let first = references_limited
            .issue(binding(
                "evidence-reference-one",
                "run-reference-one",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("reference issue")
            .into_challenge();
        let retained = digest("retained-reference");
        let first_evidence = digest("reference-evidence-one");
        references_limited
            .accept_verified_evidence_with_findings(
                &first,
                first_evidence.clone(),
                std::slice::from_ref(&retained),
                std::slice::from_ref(&retained),
                1_004,
            )
            .expect("reference acceptance");
        assert_eq!(
            references_limited
                .state_snapshot_for_tests()
                .expect("reference snapshot")
                .total_positive_finding_references,
            3
        );
        let successor = references_limited
            .issue(binding(
                "evidence-reference-two",
                "run-reference-two",
                ExplicitDigestStateV2::Present(first_evidence),
            ))
            .expect("reference successor issue")
            .into_challenge();
        let before_reference_error = references_limited
            .state_snapshot_for_tests()
            .expect("reference snapshot");
        assert_eq!(
            references_limited.accept_verified_evidence_with_findings(
                &successor,
                digest("reference-evidence-two"),
                &[],
                std::slice::from_ref(&retained),
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::StoreCapacityExceeded)
        );
        assert_eq!(
            references_limited
                .state_snapshot_for_tests()
                .expect("reference snapshot"),
            before_reference_error
        );
    }

    #[test]
    fn concurrent_same_evidence_acceptance_has_one_winner_and_equivocation_fails() {
        let store = Arc::new(TestAuthorityV2::new());
        let challenge = store
            .issue(binding(
                "evidence-race",
                "run-race",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("issue");
        let evidence = digest("accepted-evidence");
        let barrier = Arc::new(Barrier::new(16));
        let workers = (0..16)
            .map(|_| {
                let store = Arc::clone(&store);
                let challenge = challenge.clone();
                let evidence = evidence.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.0.accept_verified_evidence_with_findings(
                        &challenge,
                        evidence,
                        &[],
                        &[],
                        1_004,
                    )
                })
            })
            .collect::<Vec<_>>();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker"))
            .collect::<Result<Vec<_>, _>>()
            .expect("same evidence is accepted or idempotent");
        assert_eq!(
            outcomes
                .iter()
                .filter(|receipt| {
                    receipt.outcome() == ArtifactReviewChallengeAcceptanceV2::Accepted
                })
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|receipt| {
                    receipt.outcome() == ArtifactReviewChallengeAcceptanceV2::IdempotentRetry
                })
                .count(),
            15
        );
        assert!(outcomes.iter().all(|receipt| {
            receipt.generation() == 2
                && receipt.durability() == ArtifactReviewAuthorityDurabilityV2::MemoryOnly
                && receipt.protection()
                    == ArtifactReviewAuthorityProtectionV2::NoRestartOrRollbackProtection
        }));
        assert_eq!(
            store.0.accept_verified_evidence_with_findings(
                &challenge,
                digest("different-evidence"),
                &[],
                &[],
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::ReplayOrEquivocation)
        );
    }

    #[test]
    fn exact_lineage_cas_rejects_stale_predecessor() {
        let store = TestAuthorityV2::new();
        let first = store
            .issue(binding(
                "evidence-first",
                "run-first",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("first challenge");
        let first_digest = digest("first-evidence");
        assert_eq!(
            store
                .accept_verified_evidence_with_findings(
                    &first,
                    first_digest.clone(),
                    &[],
                    &[],
                    1_004,
                )
                .expect("first acceptance"),
            ArtifactReviewChallengeAcceptanceV2::Accepted
        );
        let stale = store
            .issue(binding(
                "evidence-stale",
                "run-stale",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("stale challenge");
        assert_eq!(
            store.accept_verified_evidence_with_findings(
                &stale,
                digest("stale-evidence"),
                &[],
                &[],
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::LineageConflict)
        );
        let successor = store
            .issue(binding(
                "evidence-successor",
                "run-successor",
                ExplicitDigestStateV2::Present(first_digest),
            ))
            .expect("successor challenge");
        let successor_digest = digest("successor-evidence");
        assert_eq!(
            store
                .accept_verified_evidence_with_findings(
                    &successor,
                    successor_digest.clone(),
                    &[],
                    &[],
                    1_004,
                )
                .expect("successor acceptance"),
            ArtifactReviewChallengeAcceptanceV2::Accepted
        );
        let scope = canonical_artifact_review_lineage_scope_v2(&subject()).expect("scope");
        assert_eq!(
            store
                .current_lineage_head("challenge-test-domain", &scope)
                .expect("head"),
            Some(successor_digest)
        );
    }

    #[test]
    fn lineage_retains_ancestor_findings_and_reserves_evidence_identity() {
        let store = TestAuthorityV2::new();
        let first = store
            .issue(binding(
                "evidence-positive",
                "run-positive-1",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("first challenge");
        let first_digest = digest("positive-evidence-1");
        let finding_a = digest("finding-a");
        store
            .accept_verified_evidence_with_findings(
                &first,
                first_digest.clone(),
                std::slice::from_ref(&finding_a),
                std::slice::from_ref(&finding_a),
                1_004,
            )
            .expect("first positive");

        let dropping = store
            .issue(binding(
                "evidence-drop",
                "run-positive-2",
                ExplicitDigestStateV2::Present(first_digest.clone()),
            ))
            .expect("drop challenge");
        let finding_b = digest("finding-b");
        assert_eq!(
            store.accept_verified_evidence_with_findings(
                &dropping,
                digest("positive-evidence-2"),
                std::slice::from_ref(&finding_b),
                std::slice::from_ref(&finding_b),
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::LineageConflict)
        );

        let successor = store
            .issue(binding(
                "evidence-positive-2",
                "run-positive-3",
                ExplicitDigestStateV2::Present(first_digest),
            ))
            .expect("successor");
        let mut cumulative = vec![finding_a, finding_b.clone()];
        cumulative.sort();
        let second_digest = digest("positive-evidence-2");
        store
            .accept_verified_evidence_with_findings(
                &successor,
                second_digest.clone(),
                std::slice::from_ref(&finding_b),
                &cumulative,
                1_004,
            )
            .expect("exact union");

        assert_eq!(
            store.issue(binding(
                "evidence-positive-2",
                "run-positive-4",
                ExplicitDigestStateV2::Present(second_digest),
            )),
            Err(ArtifactReviewAuthErrorV2::ReplayOrEquivocation)
        );
    }

    #[test]
    fn issuer_rotation_cannot_reset_evidence_identity_or_lineage_findings() {
        let store = TestAuthorityV2::new();
        let first = store
            .issue(binding(
                "evidence-rotation-stable",
                "run-before-rotation",
                ExplicitDigestStateV2::Absent,
            ))
            .expect("first challenge");
        let first_digest = digest("evidence-before-rotation");
        let retained_finding = digest("finding-before-rotation");
        store
            .accept_verified_evidence_with_findings(
                &first,
                first_digest.clone(),
                std::slice::from_ref(&retained_finding),
                std::slice::from_ref(&retained_finding),
                1_004,
            )
            .expect("first acceptance");

        assert_eq!(
            store.issue(binding_with_key_identity(
                "evidence-rotation-stable",
                "run-reused-after-rotation",
                ExplicitDigestStateV2::Present(first_digest.clone()),
                rotated_key_identity(),
            )),
            Err(ArtifactReviewAuthErrorV2::ReplayOrEquivocation)
        );

        let successor = store
            .issue(binding_with_key_identity(
                "evidence-rotation-successor",
                "run-successor-after-rotation",
                ExplicitDigestStateV2::Present(first_digest),
                rotated_key_identity(),
            ))
            .expect("rotated successor challenge");
        store
            .accept_verified_evidence_with_findings(
                &successor,
                digest("evidence-after-rotation"),
                &[],
                std::slice::from_ref(&retained_finding),
                1_004,
            )
            .expect("rotation preserves lineage while permitting a fresh evidence ID");
        let lineage_scope = canonical_artifact_review_lineage_scope_v2(&subject()).expect("scope");
        assert_eq!(
            store
                .cumulative_positive_finding_ids("challenge-test-domain", &lineage_scope)
                .expect("cumulative findings"),
            vec![retained_finding]
        );
    }

    #[test]
    fn arbitrary_lineage_scope_is_rejected() {
        let subject = subject();
        let result = ArtifactReviewChallengeBindingV2::new(ArtifactReviewChallengeDraftV2 {
            evidence_id: "evidence-arbitrary-scope".to_string(),
            run_id: "run-arbitrary-scope".to_string(),
            subject,
            policy_sha256: digest("challenge-test-policy"),
            request_sha256: digest("challenge-test-request"),
            expected_work_set_sha256: digest("challenge-test-work-set"),
            expected_work_item_count: 3,
            key_identity: key_identity(),
            lineage_scope: "caller-chosen-reset-scope".to_string(),
            predecessor_evidence_sha256: ExplicitDigestStateV2::Absent,
            issued_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 1_300,
        });
        assert_eq!(result, Err(ArtifactReviewAuthErrorV2::InvalidChallenge));
    }
}
