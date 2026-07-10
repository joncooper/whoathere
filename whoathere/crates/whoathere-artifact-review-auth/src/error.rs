use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewAuthErrorV2 {
    InvalidIdentity,
    InvalidKey,
    DuplicateKey,
    UnknownKey,
    WrongKeyRole,
    WrongKeyPurpose,
    KeyNotYetActive,
    KeyExpired,
    KeyRevoked,
    EntropyUnavailable,
    InvalidChallenge,
    DuplicateChallenge,
    UnknownChallenge,
    ChallengeBindingMismatch,
    ChallengeNotYetActive,
    ChallengeExpired,
    ReplayOrEquivocation,
    LineageConflict,
    InvalidStatement,
    ContextBindingMismatch,
    InvalidRuntimeEvidence,
    NormalizationFailed,
    AggregateManifestMismatch,
    NormalizedResultMismatch,
    StatementLimitExceeded,
    NonCanonicalStatement,
    InvalidSignature,
    SignatureVerificationFailed,
    FreshnessInvalid,
    Serialization,
    StateUnavailable,
    StoreCapacityExceeded,
}

impl ArtifactReviewAuthErrorV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidIdentity => "artifact_review_auth_identity_invalid",
            Self::InvalidKey => "artifact_review_auth_key_invalid",
            Self::DuplicateKey => "artifact_review_auth_key_duplicate",
            Self::UnknownKey => "artifact_review_auth_key_unknown",
            Self::WrongKeyRole => "artifact_review_auth_key_role_mismatch",
            Self::WrongKeyPurpose => "artifact_review_auth_key_purpose_mismatch",
            Self::KeyNotYetActive => "artifact_review_auth_key_not_yet_active",
            Self::KeyExpired => "artifact_review_auth_key_expired",
            Self::KeyRevoked => "artifact_review_auth_key_revoked",
            Self::EntropyUnavailable => "artifact_review_auth_entropy_unavailable",
            Self::InvalidChallenge => "artifact_review_auth_challenge_invalid",
            Self::DuplicateChallenge => "artifact_review_auth_challenge_duplicate",
            Self::UnknownChallenge => "artifact_review_auth_challenge_unknown",
            Self::ChallengeBindingMismatch => "artifact_review_auth_challenge_binding_mismatch",
            Self::ChallengeNotYetActive => "artifact_review_auth_challenge_not_yet_active",
            Self::ChallengeExpired => "artifact_review_auth_challenge_expired",
            Self::ReplayOrEquivocation => "artifact_review_auth_replay_or_equivocation",
            Self::LineageConflict => "artifact_review_auth_lineage_conflict",
            Self::InvalidStatement => "artifact_review_auth_statement_invalid",
            Self::ContextBindingMismatch => "artifact_review_auth_context_binding_mismatch",
            Self::InvalidRuntimeEvidence => "artifact_review_auth_runtime_evidence_invalid",
            Self::NormalizationFailed => "artifact_review_auth_normalization_failed",
            Self::AggregateManifestMismatch => "artifact_review_auth_aggregate_manifest_mismatch",
            Self::NormalizedResultMismatch => "artifact_review_auth_normalized_result_mismatch",
            Self::StatementLimitExceeded => "artifact_review_auth_statement_limit_exceeded",
            Self::NonCanonicalStatement => "artifact_review_auth_statement_not_canonical",
            Self::InvalidSignature => "artifact_review_auth_signature_invalid",
            Self::SignatureVerificationFailed => {
                "artifact_review_auth_signature_verification_failed"
            }
            Self::FreshnessInvalid => "artifact_review_auth_freshness_invalid",
            Self::Serialization => "artifact_review_auth_serialization_failed",
            Self::StateUnavailable => "artifact_review_auth_state_unavailable",
            Self::StoreCapacityExceeded => "artifact_review_auth_store_capacity_exceeded",
        }
    }
}

impl fmt::Display for ArtifactReviewAuthErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ArtifactReviewAuthErrorV2 {}
