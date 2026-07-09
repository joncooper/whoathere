//! Artifact-native evidence identity contracts.
//!
//! These types intentionally project only the identity needed to bind evidence
//! to an already validated artifact manifest.  This crate does not parse
//! artifacts and therefore does not need to depend on the parser-heavy artifact
//! crate.

use std::collections::{HashMap, HashSet};

/// The only evidence-envelope schema accepted by this module.
pub const EVIDENCE_ENVELOPE_SCHEMA_V2: &str = "whoathere.evidence.v2";

const SHA256_PREFIX: &str = "sha256:";
const CAS_PREFIX: &str = "blobs/sha256/";
const MAX_IDENTITY_COMPONENT_LEN: usize = 256;
const MAX_EVIDENCE_JOBS: usize = 128;
const MAX_REPLAY_IDENTITIES: usize = 4_096;
const MAX_LIMITATIONS: usize = 128;

/// The exact content-addressed artifact and normalized-manifest identity under review.
///
/// The digest strings are deliberately retained as a small wire projection.
/// Call [`ArtifactEvidenceSubjectV2::new`] when constructing bound values and
/// always call [`EvidenceEnvelopeV2::validate_structure`] after decoding an
/// envelope. Construction validates identities but does not authenticate their
/// provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactEvidenceSubjectV2 {
    artifact_sha256: String,
    envelope_sha256: String,
    manifest_sha256: String,
    cas_object_key: String,
}

impl ArtifactEvidenceSubjectV2 {
    /// Constructs a subject only when both digests are canonical and the CAS
    /// object key is the canonical digest-derived key for the original artifact.
    pub fn new(
        artifact_sha256: impl Into<String>,
        envelope_sha256: impl Into<String>,
        manifest_sha256: impl Into<String>,
        cas_object_key: impl Into<String>,
    ) -> Result<Self, EvidenceValidationErrorV2> {
        let subject = Self {
            artifact_sha256: artifact_sha256.into(),
            envelope_sha256: envelope_sha256.into(),
            manifest_sha256: manifest_sha256.into(),
            cas_object_key: cas_object_key.into(),
        };
        subject.validate_identity()?;
        Ok(subject)
    }

    /// Validates the canonical digest forms and the digest-derived CAS key.
    pub fn validate_identity(&self) -> Result<(), EvidenceValidationErrorV2> {
        validate_artifact_digest(&self.artifact_sha256)?;
        validate_envelope_digest(&self.envelope_sha256)?;
        validate_manifest_digest(&self.manifest_sha256)?;
        validate_cas_key(&self.cas_object_key)?;

        let expected_key = canonical_cas_object_key_for_artifact(&self.artifact_sha256)?;
        if self.cas_object_key != expected_key {
            return Err(EvidenceValidationErrorV2::CasObjectKeyDigestMismatch);
        }
        Ok(())
    }

    pub fn artifact_sha256(&self) -> &str {
        &self.artifact_sha256
    }

    pub fn envelope_sha256(&self) -> &str {
        &self.envelope_sha256
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.manifest_sha256
    }

    pub fn cas_object_key(&self) -> &str {
        &self.cas_object_key
    }
}

/// Returns the one canonical digest-derived CAS key for an artifact digest.
pub fn canonical_cas_object_key_for_artifact(
    artifact_sha256: &str,
) -> Result<String, EvidenceValidationErrorV2> {
    validate_artifact_digest(artifact_sha256)?;
    let digest = artifact_sha256
        .strip_prefix(SHA256_PREFIX)
        .expect("validated SHA-256 digest has the prefix");
    Ok(format!("{CAS_PREFIX}{digest}"))
}

/// Identity of deterministic, scanner, or AI analysis that produced a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalyzerIdentityV2 {
    pub analyzer_id: String,
    pub analyzer_version: String,
    pub analyzer_sha256: String,
}

/// Identity of the typed scenario whose execution produced a result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioIdentityV2 {
    pub scenario_id: String,
    pub scenario_sha256: String,
}

/// A result is produced by exactly one applicable identity class.  The enum
/// prevents a caller from ambiguously supplying both analyzer and scenario
/// identities or neither after validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceProducerIdentityV2 {
    Analyzer(AnalyzerIdentityV2),
    Scenario(ScenarioIdentityV2),
}

impl EvidenceProducerIdentityV2 {
    fn validate_identity(&self) -> Result<(), EvidenceValidationErrorV2> {
        match self {
            Self::Analyzer(identity) => {
                if identity.analyzer_id.is_empty()
                    || identity.analyzer_version.is_empty()
                    || identity.analyzer_sha256.is_empty()
                {
                    return Err(EvidenceValidationErrorV2::MissingProducerIdentity);
                }
                if !valid_identity_component(&identity.analyzer_id)
                    || !valid_identity_component(&identity.analyzer_version)
                {
                    return Err(EvidenceValidationErrorV2::InvalidProducerIdentity);
                }
                if !valid_sha256_digest(&identity.analyzer_sha256) {
                    return Err(EvidenceValidationErrorV2::InvalidProducerDigest);
                }
            }
            Self::Scenario(identity) => {
                if identity.scenario_id.is_empty() || identity.scenario_sha256.is_empty() {
                    return Err(EvidenceValidationErrorV2::MissingProducerIdentity);
                }
                if !valid_identity_component(&identity.scenario_id) {
                    return Err(EvidenceValidationErrorV2::InvalidProducerIdentity);
                }
                if !valid_sha256_digest(&identity.scenario_sha256) {
                    return Err(EvidenceValidationErrorV2::InvalidProducerDigest);
                }
            }
        }
        Ok(())
    }
}

/// Whether the producer completed the evidence-producing operation itself.
/// Package exit status is evidence payload, not this state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceJobCompletionV2 {
    Completed,
    Failed,
    TimedOut,
    Skipped,
}

/// Explicit coverage state for a job or aggregate envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceCompletenessV2 {
    Complete,
    Incomplete,
}

/// A bounded, machine-readable limitation.  The optional evidence digest can
/// refer to a restricted diagnostic without carrying untrusted diagnostic text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceLimitationV2 {
    pub code: String,
    pub evidence_sha256: Option<String>,
}

/// Limitations are represented separately from a completeness assertion so a
/// producer cannot hide a known gap behind a `Complete` enum value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceLimitationStateV2 {
    None,
    Present(Vec<EvidenceLimitationV2>),
}

/// Coverage and known-limitations state shared by jobs and envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceCoverageV2 {
    pub completeness: EvidenceCompletenessV2,
    pub limitations: EvidenceLimitationStateV2,
}

impl EvidenceCoverageV2 {
    pub fn complete() -> Self {
        Self {
            completeness: EvidenceCompletenessV2::Complete,
            limitations: EvidenceLimitationStateV2::None,
        }
    }

    fn validate_complete(&self) -> Result<(), EvidenceValidationErrorV2> {
        if self.completeness != EvidenceCompletenessV2::Complete {
            return Err(EvidenceValidationErrorV2::IncompleteCoverage);
        }
        match &self.limitations {
            EvidenceLimitationStateV2::None => Ok(()),
            EvidenceLimitationStateV2::Present(_) => {
                Err(EvidenceValidationErrorV2::CoverageHasLimitations)
            }
        }
    }

    fn validate_structure(&self) -> Result<(), EvidenceValidationErrorV2> {
        if let EvidenceLimitationStateV2::Present(limitations) = &self.limitations {
            if limitations.is_empty() || limitations.len() > MAX_LIMITATIONS {
                return Err(EvidenceValidationErrorV2::InvalidLimitations);
            }
            for limitation in limitations {
                if !valid_identity_component(&limitation.code)
                    || limitation
                        .evidence_sha256
                        .as_deref()
                        .is_some_and(|digest| !valid_sha256_digest(digest))
                {
                    return Err(EvidenceValidationErrorV2::InvalidLimitations);
                }
            }
        }
        Ok(())
    }
}

/// One artifact-bound evidence result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobResultV2 {
    pub job_id: String,
    pub evidence_id: String,
    pub run_id: String,
    pub job_spec_sha256: String,
    pub produced_at_unix_seconds: u64,
    pub subject: ArtifactEvidenceSubjectV2,
    pub policy_sha256: String,
    pub producer: EvidenceProducerIdentityV2,
    pub completion: EvidenceJobCompletionV2,
    pub coverage: EvidenceCoverageV2,
    pub result_sha256: String,
}

/// Artifact-native evidence envelope.  Every contained job repeats the exact
/// subject and policy binding so cross-artifact splicing fails validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceEnvelopeV2 {
    pub schema_version: String,
    pub evidence_id: String,
    pub run_id: String,
    pub run_started_at_unix_seconds: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub subject: ArtifactEvidenceSubjectV2,
    pub policy_sha256: String,
    pub coverage: EvidenceCoverageV2,
    pub jobs: Vec<EvidenceJobResultV2>,
}

impl EvidenceEnvelopeV2 {
    /// Consumes an untrusted envelope and validates only its structure and
    /// trusted-context bindings. This does not authenticate the producer or
    /// prove that claimed coverage occurred.
    ///
    /// Callers must authenticate canonical bytes before using even restrictive
    /// claims, then atomically reserve the evidence id in their replay store.
    pub fn validate_structure(
        self,
        context: &EvidenceValidationContextV2,
    ) -> Result<StructurallyValidatedEvidenceV2, EvidenceValidationErrorV2> {
        self.validate_structure_ref(context)?;
        Ok(StructurallyValidatedEvidenceV2 { envelope: self })
    }

    fn validate_structure_ref(
        &self,
        context: &EvidenceValidationContextV2,
    ) -> Result<(), EvidenceValidationErrorV2> {
        if self.schema_version != EVIDENCE_ENVELOPE_SCHEMA_V2 {
            return Err(EvidenceValidationErrorV2::UnsupportedSchema);
        }

        validate_context(context)?;
        validate_envelope_identity(self, context)?;

        self.subject.validate_identity()?;
        context.expected_subject.validate_identity()?;
        validate_subject_binding(&self.subject, &context.expected_subject)?;

        validate_policy_digest(&self.policy_sha256)?;
        validate_policy_digest(&context.expected_policy_sha256)?;
        if self.policy_sha256 != context.expected_policy_sha256 {
            return Err(EvidenceValidationErrorV2::PolicyBindingMismatch);
        }

        self.coverage.validate_structure()?;
        if self.jobs.is_empty() {
            return Err(EvidenceValidationErrorV2::MissingRequiredJob);
        }
        if self.jobs.len() > MAX_EVIDENCE_JOBS {
            return Err(EvidenceValidationErrorV2::TooManyJobs);
        }

        let mut seen_job_ids = HashSet::with_capacity(self.jobs.len());
        let expected_jobs = context
            .expected_jobs
            .iter()
            .map(|expected| (expected.job_id.as_str(), expected))
            .collect::<HashMap<_, _>>();
        for job in &self.jobs {
            if !valid_identity_component(&job.job_id) {
                return Err(if job.job_id.is_empty() {
                    EvidenceValidationErrorV2::MissingJobId
                } else {
                    EvidenceValidationErrorV2::InvalidJobId
                });
            }
            if !seen_job_ids.insert(job.job_id.as_str()) {
                return Err(EvidenceValidationErrorV2::DuplicateJobId);
            }

            let Some(expected_job) = expected_jobs.get(job.job_id.as_str()) else {
                return Err(EvidenceValidationErrorV2::UnexpectedJob);
            };

            if job.evidence_id != self.evidence_id || job.run_id != self.run_id {
                return Err(EvidenceValidationErrorV2::JobRunBindingMismatch);
            }
            validate_job_spec_digest(&job.job_spec_sha256)?;
            if job.job_spec_sha256 != expected_job.job_spec_sha256 {
                return Err(EvidenceValidationErrorV2::JobSpecBindingMismatch);
            }
            if job.produced_at_unix_seconds < self.run_started_at_unix_seconds
                || job.produced_at_unix_seconds > self.issued_at_unix_seconds
                || job.produced_at_unix_seconds > context.now_unix_seconds
            {
                return Err(EvidenceValidationErrorV2::JobTimestampInvalid);
            }

            job.subject.validate_identity()?;
            validate_subject_binding(&job.subject, &self.subject)?;

            validate_policy_digest(&job.policy_sha256)?;
            if job.policy_sha256 != self.policy_sha256 {
                return Err(EvidenceValidationErrorV2::PolicyBindingMismatch);
            }

            job.producer.validate_identity()?;
            if job.producer != expected_job.producer {
                return Err(EvidenceValidationErrorV2::ProducerIdentityMismatch);
            }

            job.coverage.validate_structure()?;

            if job.result_sha256.is_empty() {
                return Err(EvidenceValidationErrorV2::MissingResultDigest);
            }
            if !valid_sha256_digest(&job.result_sha256) {
                return Err(EvidenceValidationErrorV2::InvalidResultDigest);
            }
        }

        if context
            .expected_jobs
            .iter()
            .any(|expected| !self.jobs.iter().any(|job| job.job_id == expected.job_id))
        {
            return Err(EvidenceValidationErrorV2::MissingRequiredJob);
        }

        Ok(())
    }
}

/// A structurally valid but explicitly unauthenticated evidence envelope.
///
/// This type is not admission authority. It exists so callers cannot mutate the
/// validated instance without leaving the wrapper type.
#[derive(Debug, PartialEq, Eq)]
pub struct StructurallyValidatedEvidenceV2 {
    envelope: EvidenceEnvelopeV2,
}

impl StructurallyValidatedEvidenceV2 {
    pub fn evidence_id(&self) -> &str {
        &self.envelope.evidence_id
    }

    pub fn subject(&self) -> &ArtifactEvidenceSubjectV2 {
        &self.envelope.subject
    }

    pub fn jobs(&self) -> &[EvidenceJobResultV2] {
        &self.envelope.jobs
    }

    pub const fn is_authenticated(&self) -> bool {
        false
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }

    /// Separately checks whether every expected producer completed with full,
    /// limitation-free coverage while preserving the wrapper on failure.
    pub fn check_complete(&self) -> Result<(), EvidenceValidationErrorV2> {
        self.envelope.coverage.validate_complete()?;
        for job in &self.envelope.jobs {
            if job.completion != EvidenceJobCompletionV2::Completed {
                return Err(EvidenceValidationErrorV2::JobNotCompleted);
            }
            job.coverage.validate_complete()?;
        }
        Ok(())
    }

    pub fn into_complete(self) -> Result<CompleteStructuralEvidenceV2, EvidenceValidationErrorV2> {
        self.check_complete()?;
        Ok(CompleteStructuralEvidenceV2 {
            envelope: self.envelope,
        })
    }

    pub fn run_id(&self) -> &str {
        &self.envelope.run_id
    }

    pub fn policy_sha256(&self) -> &str {
        &self.envelope.policy_sha256
    }

    pub fn coverage(&self) -> &EvidenceCoverageV2 {
        &self.envelope.coverage
    }
}

/// Structurally complete, still unauthenticated evidence.
#[derive(Debug, PartialEq, Eq)]
pub struct CompleteStructuralEvidenceV2 {
    envelope: EvidenceEnvelopeV2,
}

impl CompleteStructuralEvidenceV2 {
    pub fn evidence_id(&self) -> &str {
        &self.envelope.evidence_id
    }

    pub const fn is_authenticated(&self) -> bool {
        false
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

/// The producer identity expected for one unique job id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobExpectationV2 {
    pub job_id: String,
    pub job_spec_sha256: String,
    pub producer: EvidenceProducerIdentityV2,
}

/// Trusted verifier inputs.  These values originate from the control plane,
/// not from the evidence envelope being checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceValidationContextV2 {
    pub expected_evidence_id: String,
    pub expected_run_id: String,
    pub expected_subject: ArtifactEvidenceSubjectV2,
    pub expected_policy_sha256: String,
    pub expected_jobs: Vec<EvidenceJobExpectationV2>,
    pub now_unix_seconds: u64,
    pub maximum_age_seconds: u64,
    pub previously_accepted_evidence_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceValidationErrorV2 {
    UnsupportedSchema,
    MissingEvidenceId,
    InvalidEvidenceId,
    EvidenceIdMismatch,
    MissingRunId,
    InvalidRunId,
    RunIdMismatch,
    ReplayedIdentity,
    InvalidFreshnessWindow,
    EvidenceFromFuture,
    StaleEvidence,
    MissingArtifactDigest,
    InvalidArtifactDigest,
    MissingManifestDigest,
    InvalidManifestDigest,
    MissingEnvelopeDigest,
    InvalidEnvelopeDigest,
    MissingCasObjectKey,
    InvalidCasObjectKey,
    CasObjectKeyDigestMismatch,
    ArtifactBindingMismatch,
    ManifestBindingMismatch,
    EnvelopeBindingMismatch,
    CasObjectKeyBindingMismatch,
    MissingPolicyDigest,
    InvalidPolicyDigest,
    PolicyBindingMismatch,
    MissingProducerIdentity,
    InvalidProducerIdentity,
    InvalidProducerDigest,
    ProducerIdentityMismatch,
    MissingJobSpecDigest,
    InvalidJobSpecDigest,
    JobSpecBindingMismatch,
    JobRunBindingMismatch,
    JobTimestampInvalid,
    MissingJobId,
    InvalidJobId,
    DuplicateJobId,
    DuplicateExpectedJobId,
    MissingRequiredJob,
    UnexpectedJob,
    TooManyJobs,
    TooManyReplayIdentities,
    JobNotCompleted,
    IncompleteCoverage,
    CoverageHasLimitations,
    MissingResultDigest,
    InvalidResultDigest,
    InvalidLimitations,
}

impl EvidenceValidationErrorV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedSchema => "evidence_v2_schema_unsupported",
            Self::MissingEvidenceId => "evidence_v2_id_missing",
            Self::InvalidEvidenceId => "evidence_v2_id_invalid",
            Self::EvidenceIdMismatch => "evidence_v2_id_mismatch",
            Self::MissingRunId => "evidence_v2_run_id_missing",
            Self::InvalidRunId => "evidence_v2_run_id_invalid",
            Self::RunIdMismatch => "evidence_v2_run_id_mismatch",
            Self::ReplayedIdentity => "evidence_v2_identity_replayed",
            Self::InvalidFreshnessWindow => "evidence_v2_freshness_window_invalid",
            Self::EvidenceFromFuture => "evidence_v2_created_in_future",
            Self::StaleEvidence => "evidence_v2_stale",
            Self::MissingArtifactDigest => "evidence_v2_artifact_digest_missing",
            Self::InvalidArtifactDigest => "evidence_v2_artifact_digest_invalid",
            Self::MissingManifestDigest => "evidence_v2_manifest_digest_missing",
            Self::InvalidManifestDigest => "evidence_v2_manifest_digest_invalid",
            Self::MissingEnvelopeDigest => "evidence_v2_envelope_digest_missing",
            Self::InvalidEnvelopeDigest => "evidence_v2_envelope_digest_invalid",
            Self::MissingCasObjectKey => "evidence_v2_cas_object_key_missing",
            Self::InvalidCasObjectKey => "evidence_v2_cas_object_key_invalid",
            Self::CasObjectKeyDigestMismatch => "evidence_v2_cas_object_key_digest_mismatch",
            Self::ArtifactBindingMismatch => "evidence_v2_artifact_binding_mismatch",
            Self::ManifestBindingMismatch => "evidence_v2_manifest_binding_mismatch",
            Self::EnvelopeBindingMismatch => "evidence_v2_envelope_binding_mismatch",
            Self::CasObjectKeyBindingMismatch => "evidence_v2_cas_object_key_binding_mismatch",
            Self::MissingPolicyDigest => "evidence_v2_policy_digest_missing",
            Self::InvalidPolicyDigest => "evidence_v2_policy_digest_invalid",
            Self::PolicyBindingMismatch => "evidence_v2_policy_binding_mismatch",
            Self::MissingProducerIdentity => "evidence_v2_producer_identity_missing",
            Self::InvalidProducerIdentity => "evidence_v2_producer_identity_invalid",
            Self::InvalidProducerDigest => "evidence_v2_producer_digest_invalid",
            Self::ProducerIdentityMismatch => "evidence_v2_producer_identity_mismatch",
            Self::MissingJobSpecDigest => "evidence_v2_job_spec_digest_missing",
            Self::InvalidJobSpecDigest => "evidence_v2_job_spec_digest_invalid",
            Self::JobSpecBindingMismatch => "evidence_v2_job_spec_binding_mismatch",
            Self::JobRunBindingMismatch => "evidence_v2_job_run_binding_mismatch",
            Self::JobTimestampInvalid => "evidence_v2_job_timestamp_invalid",
            Self::MissingJobId => "evidence_v2_job_id_missing",
            Self::InvalidJobId => "evidence_v2_job_id_invalid",
            Self::DuplicateJobId => "evidence_v2_job_id_duplicate",
            Self::DuplicateExpectedJobId => "evidence_v2_expected_job_id_duplicate",
            Self::MissingRequiredJob => "evidence_v2_required_job_missing",
            Self::UnexpectedJob => "evidence_v2_job_unexpected",
            Self::TooManyJobs => "evidence_v2_job_count_exceeded",
            Self::TooManyReplayIdentities => "evidence_v2_replay_identity_count_exceeded",
            Self::JobNotCompleted => "evidence_v2_job_not_completed",
            Self::IncompleteCoverage => "evidence_v2_coverage_incomplete",
            Self::CoverageHasLimitations => "evidence_v2_coverage_limited",
            Self::MissingResultDigest => "evidence_v2_result_digest_missing",
            Self::InvalidResultDigest => "evidence_v2_result_digest_invalid",
            Self::InvalidLimitations => "evidence_v2_limitations_invalid",
        }
    }
}

fn validate_context(
    context: &EvidenceValidationContextV2,
) -> Result<(), EvidenceValidationErrorV2> {
    if context.expected_evidence_id.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingEvidenceId);
    }
    if !valid_identity_component(&context.expected_evidence_id) {
        return Err(EvidenceValidationErrorV2::InvalidEvidenceId);
    }
    if context.expected_run_id.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingRunId);
    }
    if !valid_identity_component(&context.expected_run_id) {
        return Err(EvidenceValidationErrorV2::InvalidRunId);
    }
    if context.maximum_age_seconds == 0 {
        return Err(EvidenceValidationErrorV2::InvalidFreshnessWindow);
    }
    if context.expected_jobs.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingRequiredJob);
    }
    if context.expected_jobs.len() > MAX_EVIDENCE_JOBS {
        return Err(EvidenceValidationErrorV2::TooManyJobs);
    }
    if context.previously_accepted_evidence_ids.len() > MAX_REPLAY_IDENTITIES {
        return Err(EvidenceValidationErrorV2::TooManyReplayIdentities);
    }

    let mut seen_expected_ids = HashSet::with_capacity(context.expected_jobs.len());
    for expected in &context.expected_jobs {
        if !valid_identity_component(&expected.job_id) {
            return Err(if expected.job_id.is_empty() {
                EvidenceValidationErrorV2::MissingJobId
            } else {
                EvidenceValidationErrorV2::InvalidJobId
            });
        }
        if !seen_expected_ids.insert(expected.job_id.as_str()) {
            return Err(EvidenceValidationErrorV2::DuplicateExpectedJobId);
        }
        validate_job_spec_digest(&expected.job_spec_sha256)?;
        expected.producer.validate_identity()?;
    }
    Ok(())
}

fn validate_envelope_identity(
    envelope: &EvidenceEnvelopeV2,
    context: &EvidenceValidationContextV2,
) -> Result<(), EvidenceValidationErrorV2> {
    if envelope.evidence_id.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingEvidenceId);
    }
    if !valid_identity_component(&envelope.evidence_id) {
        return Err(EvidenceValidationErrorV2::InvalidEvidenceId);
    }
    if envelope.evidence_id != context.expected_evidence_id {
        return Err(EvidenceValidationErrorV2::EvidenceIdMismatch);
    }
    if context
        .previously_accepted_evidence_ids
        .iter()
        .any(|id| id == &envelope.evidence_id)
    {
        return Err(EvidenceValidationErrorV2::ReplayedIdentity);
    }

    if envelope.run_id.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingRunId);
    }
    if !valid_identity_component(&envelope.run_id) {
        return Err(EvidenceValidationErrorV2::InvalidRunId);
    }
    if envelope.run_id != context.expected_run_id {
        return Err(EvidenceValidationErrorV2::RunIdMismatch);
    }

    if envelope.run_started_at_unix_seconds == 0
        || envelope.issued_at_unix_seconds < envelope.run_started_at_unix_seconds
        || envelope.expires_at_unix_seconds <= envelope.issued_at_unix_seconds
    {
        return Err(EvidenceValidationErrorV2::InvalidFreshnessWindow);
    }
    if envelope.issued_at_unix_seconds > context.now_unix_seconds {
        return Err(EvidenceValidationErrorV2::EvidenceFromFuture);
    }
    if context.now_unix_seconds >= envelope.expires_at_unix_seconds
        || context
            .now_unix_seconds
            .saturating_sub(envelope.issued_at_unix_seconds)
            > context.maximum_age_seconds
    {
        return Err(EvidenceValidationErrorV2::StaleEvidence);
    }
    Ok(())
}

fn validate_subject_binding(
    actual: &ArtifactEvidenceSubjectV2,
    expected: &ArtifactEvidenceSubjectV2,
) -> Result<(), EvidenceValidationErrorV2> {
    if actual.artifact_sha256 != expected.artifact_sha256 {
        return Err(EvidenceValidationErrorV2::ArtifactBindingMismatch);
    }
    if actual.envelope_sha256 != expected.envelope_sha256 {
        return Err(EvidenceValidationErrorV2::EnvelopeBindingMismatch);
    }
    if actual.manifest_sha256 != expected.manifest_sha256 {
        return Err(EvidenceValidationErrorV2::ManifestBindingMismatch);
    }
    if actual.cas_object_key != expected.cas_object_key {
        return Err(EvidenceValidationErrorV2::CasObjectKeyBindingMismatch);
    }
    Ok(())
}

fn validate_artifact_digest(value: &str) -> Result<(), EvidenceValidationErrorV2> {
    if value.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingArtifactDigest);
    }
    if !valid_sha256_digest(value) {
        return Err(EvidenceValidationErrorV2::InvalidArtifactDigest);
    }
    Ok(())
}

fn validate_manifest_digest(value: &str) -> Result<(), EvidenceValidationErrorV2> {
    if value.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingManifestDigest);
    }
    if !valid_sha256_digest(value) {
        return Err(EvidenceValidationErrorV2::InvalidManifestDigest);
    }
    Ok(())
}

fn validate_envelope_digest(value: &str) -> Result<(), EvidenceValidationErrorV2> {
    if value.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingEnvelopeDigest);
    }
    if !valid_sha256_digest(value) {
        return Err(EvidenceValidationErrorV2::InvalidEnvelopeDigest);
    }
    Ok(())
}

fn validate_policy_digest(value: &str) -> Result<(), EvidenceValidationErrorV2> {
    if value.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingPolicyDigest);
    }
    if !valid_sha256_digest(value) {
        return Err(EvidenceValidationErrorV2::InvalidPolicyDigest);
    }
    Ok(())
}

fn validate_job_spec_digest(value: &str) -> Result<(), EvidenceValidationErrorV2> {
    if value.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingJobSpecDigest);
    }
    if !valid_sha256_digest(value) {
        return Err(EvidenceValidationErrorV2::InvalidJobSpecDigest);
    }
    Ok(())
}

fn validate_cas_key(value: &str) -> Result<(), EvidenceValidationErrorV2> {
    if value.is_empty() {
        return Err(EvidenceValidationErrorV2::MissingCasObjectKey);
    }
    let Some(digest) = value.strip_prefix(CAS_PREFIX) else {
        return Err(EvidenceValidationErrorV2::InvalidCasObjectKey);
    };
    if !valid_sha256_hex(digest) {
        return Err(EvidenceValidationErrorV2::InvalidCasObjectKey);
    }
    Ok(())
}

fn valid_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix(SHA256_PREFIX)
        .is_some_and(valid_sha256_hex)
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_identity_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_IDENTITY_COMPONENT_LEN
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'+')
        })
        && value != "."
        && value != ".."
}
