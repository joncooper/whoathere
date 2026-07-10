use crate::{
    valid_identity_component_v2, ArtifactReviewAuthErrorV2, ArtifactReviewChallengeAuthorityIdV2,
    ArtifactReviewChallengeV2, ArtifactReviewKeyIdentityV2, ArtifactReviewKeyRegistryV2,
    ArtifactReviewSigningKeyV2, ArtifactReviewSubjectBindingV2, ExplicitDigestStateV2,
    MAX_JCS_SAFE_INTEGER_V2,
};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_artifact_review_runtime::LocalProviderEvidenceExecutionBindingV2;

pub const ARTIFACT_REVIEW_EVIDENCE_STATEMENT_SCHEMA_V2: &str =
    "whoathere.artifact_review_evidence_statement.v2";
pub const ARTIFACT_REVIEW_EVIDENCE_CANONICALIZATION_V2: &str = "rfc8785.jcs.no_numbers.v1";
pub const ARTIFACT_REVIEW_EVIDENCE_SIGNATURE_PROFILE_V2: &str = "ed25519.direct.expected_body.v1";
pub const MAX_ARTIFACT_REVIEW_EVIDENCE_STATEMENT_BYTES_V2: usize = 256 * 1024;
pub const MAX_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_BYTES_V2: u64 = 4 * 1024 * 1024;
pub const MAX_ARTIFACT_REVIEW_NORMALIZED_RESULT_BYTES_V2: u64 = 1024 * 1024;
pub const MAX_ARTIFACT_REVIEW_EVIDENCE_TTL_SECONDS_V2: u64 = 5 * 60;
pub const MAX_ARTIFACT_REVIEW_EVIDENCE_LIMITATIONS_V2: usize = 128;
pub const MAX_ARTIFACT_REVIEW_POSITIVE_FINDING_IDS_V2: usize = 4_096;

const SIGNATURE_DOMAIN_V2: &[u8] = b"whoathere.artifact_review_evidence.signature\0";
const SIGNATURE_LAYOUT_VERSION_V2: u16 = 2;
const SIGNATURE_BYTES_V2: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactReviewEvidenceCompletenessV2 {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone)]
pub struct ArtifactReviewEvidenceStatementDraftV2 {
    pub challenge: ArtifactReviewChallengeV2,
    pub challenge_binding_sha256: Sha256Digest,
    pub runtime_execution_binding_sha256: Sha256Digest,
    pub run_started_at_unix_seconds: u64,
    pub run_finished_at_unix_seconds: u64,
    pub evidence_issued_at_unix_seconds: u64,
    pub evidence_expires_at_unix_seconds: u64,
    pub deterministic_analysis_sha256: Sha256Digest,
    pub coverage_manifest_sha256: Sha256Digest,
    pub provider_adapter_sha256: Sha256Digest,
    pub model_content_sha256: Sha256Digest,
    pub prompt_template_sha256: Sha256Digest,
    pub model_output_schema_sha256: Sha256Digest,
    pub adapter_result_schema_sha256: Sha256Digest,
    pub declared_control_plane_build_sha256: Sha256Digest,
    pub runtime_contract_sha256: Sha256Digest,
    pub normalizer_contract_sha256: Sha256Digest,
    pub aggregate_manifest_sha256: Sha256Digest,
    pub aggregate_manifest_byte_len: u64,
    pub normalized_result_sha256: Sha256Digest,
    pub normalized_result_byte_len: u64,
    pub execution_claims_sha256: Sha256Digest,
    pub current_positive_finding_ids: Vec<Sha256Digest>,
    pub cumulative_positive_finding_ids: Vec<Sha256Digest>,
    pub completeness: ArtifactReviewEvidenceCompletenessV2,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewEvidenceStatementV2 {
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    challenge_id: String,
    challenge_binding_sha256: Sha256Digest,
    runtime_execution_binding_sha256: Sha256Digest,
    key_identity: ArtifactReviewKeyIdentityV2,
    evidence_id: String,
    run_id: String,
    subject: ArtifactReviewSubjectBindingV2,
    policy_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    expected_work_set_sha256: Sha256Digest,
    expected_work_item_count: u32,
    lineage_scope: String,
    predecessor_evidence_sha256: ExplicitDigestStateV2,
    challenge_issued_at_unix_seconds: u64,
    challenge_expires_at_unix_seconds: u64,
    run_started_at_unix_seconds: u64,
    run_finished_at_unix_seconds: u64,
    evidence_issued_at_unix_seconds: u64,
    evidence_expires_at_unix_seconds: u64,
    deterministic_analysis_sha256: Sha256Digest,
    coverage_manifest_sha256: Sha256Digest,
    provider_adapter_sha256: Sha256Digest,
    model_content_sha256: Sha256Digest,
    prompt_template_sha256: Sha256Digest,
    model_output_schema_sha256: Sha256Digest,
    adapter_result_schema_sha256: Sha256Digest,
    declared_control_plane_build_sha256: Sha256Digest,
    runtime_contract_sha256: Sha256Digest,
    normalizer_contract_sha256: Sha256Digest,
    aggregate_manifest_sha256: Sha256Digest,
    aggregate_manifest_byte_len: u64,
    normalized_result_sha256: Sha256Digest,
    normalized_result_byte_len: u64,
    execution_claims_sha256: Sha256Digest,
    current_positive_finding_ids: Vec<Sha256Digest>,
    cumulative_positive_finding_ids: Vec<Sha256Digest>,
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: Vec<String>,
}

impl ArtifactReviewEvidenceStatementV2 {
    pub fn new(
        draft: ArtifactReviewEvidenceStatementDraftV2,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        draft.challenge.validate()?;
        if draft.challenge_binding_sha256 != draft.challenge.canonical_binding_sha256_v2()? {
            return Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
        }
        let binding = draft.challenge.binding();
        let statement = Self {
            authority_id: draft.challenge.authority_id().clone(),
            challenge_id: draft.challenge.challenge_id().to_string(),
            challenge_binding_sha256: draft.challenge_binding_sha256,
            runtime_execution_binding_sha256: draft.runtime_execution_binding_sha256,
            key_identity: binding.key_identity().clone(),
            evidence_id: binding.evidence_id().to_string(),
            run_id: binding.run_id().to_string(),
            subject: binding.subject().clone(),
            policy_sha256: binding.policy_sha256().clone(),
            request_sha256: binding.request_sha256().clone(),
            expected_work_set_sha256: binding.expected_work_set_sha256().clone(),
            expected_work_item_count: binding.expected_work_item_count(),
            lineage_scope: binding.lineage_scope().to_string(),
            predecessor_evidence_sha256: binding.predecessor_evidence_sha256().clone(),
            challenge_issued_at_unix_seconds: binding.issued_at_unix_seconds(),
            challenge_expires_at_unix_seconds: binding.expires_at_unix_seconds(),
            run_started_at_unix_seconds: draft.run_started_at_unix_seconds,
            run_finished_at_unix_seconds: draft.run_finished_at_unix_seconds,
            evidence_issued_at_unix_seconds: draft.evidence_issued_at_unix_seconds,
            evidence_expires_at_unix_seconds: draft.evidence_expires_at_unix_seconds,
            deterministic_analysis_sha256: draft.deterministic_analysis_sha256,
            coverage_manifest_sha256: draft.coverage_manifest_sha256,
            provider_adapter_sha256: draft.provider_adapter_sha256,
            model_content_sha256: draft.model_content_sha256,
            prompt_template_sha256: draft.prompt_template_sha256,
            model_output_schema_sha256: draft.model_output_schema_sha256,
            adapter_result_schema_sha256: draft.adapter_result_schema_sha256,
            declared_control_plane_build_sha256: draft.declared_control_plane_build_sha256,
            runtime_contract_sha256: draft.runtime_contract_sha256,
            normalizer_contract_sha256: draft.normalizer_contract_sha256,
            aggregate_manifest_sha256: draft.aggregate_manifest_sha256,
            aggregate_manifest_byte_len: draft.aggregate_manifest_byte_len,
            normalized_result_sha256: draft.normalized_result_sha256,
            normalized_result_byte_len: draft.normalized_result_byte_len,
            execution_claims_sha256: draft.execution_claims_sha256,
            current_positive_finding_ids: draft.current_positive_finding_ids,
            cumulative_positive_finding_ids: draft.cumulative_positive_finding_ids,
            completeness: draft.completeness,
            limitations: draft.limitations,
        };
        statement.validate()?;
        Ok(statement)
    }

    pub fn validate(&self) -> Result<(), ArtifactReviewAuthErrorV2> {
        self.subject.validate()?;
        self.key_identity.validate()?;
        let runtime_binding = LocalProviderEvidenceExecutionBindingV2::new(
            self.challenge_id.clone(),
            self.evidence_id.clone(),
            self.run_id.clone(),
            self.challenge_binding_sha256.clone(),
        )
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidStatement)?;
        let expected_runtime_binding_sha256 =
            crate::local_provider_evidence_execution_binding_sha256_v2(
                &self.authority_id,
                &runtime_binding,
            )?;
        if !valid_identity_component_v2(&self.evidence_id)
            || !valid_identity_component_v2(&self.run_id)
            || !valid_identity_component_v2(&self.lineage_scope)
            || self.expected_work_item_count == 0
            || self.aggregate_manifest_byte_len == 0
            || self.aggregate_manifest_byte_len > MAX_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_BYTES_V2
            || self.normalized_result_byte_len == 0
            || self.normalized_result_byte_len > MAX_ARTIFACT_REVIEW_NORMALIZED_RESULT_BYTES_V2
            || self.challenge_issued_at_unix_seconds > self.run_started_at_unix_seconds
            || self.run_started_at_unix_seconds > self.run_finished_at_unix_seconds
            || self.run_finished_at_unix_seconds > self.evidence_issued_at_unix_seconds
            || self.evidence_issued_at_unix_seconds >= self.evidence_expires_at_unix_seconds
            || self.evidence_expires_at_unix_seconds > self.challenge_expires_at_unix_seconds
            || self.evidence_expires_at_unix_seconds > MAX_JCS_SAFE_INTEGER_V2
            || self.evidence_expires_at_unix_seconds - self.evidence_issued_at_unix_seconds
                > MAX_ARTIFACT_REVIEW_EVIDENCE_TTL_SECONDS_V2
            || self.limitations.len() > MAX_ARTIFACT_REVIEW_EVIDENCE_LIMITATIONS_V2
            || self.current_positive_finding_ids.len() > MAX_ARTIFACT_REVIEW_POSITIVE_FINDING_IDS_V2
            || self.cumulative_positive_finding_ids.len()
                > MAX_ARTIFACT_REVIEW_POSITIVE_FINDING_IDS_V2
            || (self.completeness == ArtifactReviewEvidenceCompletenessV2::Complete
                && !self.limitations.is_empty())
            || (self.completeness == ArtifactReviewEvidenceCompletenessV2::Incomplete
                && self.limitations.is_empty())
            || self.runtime_execution_binding_sha256 != expected_runtime_binding_sha256
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidStatement);
        }
        if self
            .limitations
            .iter()
            .any(|limitation| !valid_identity_component_v2(limitation))
            || !strictly_sorted_unique_v2(&self.current_positive_finding_ids)
            || !strictly_sorted_unique_v2(&self.cumulative_positive_finding_ids)
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidStatement);
        }
        let cumulative = self
            .cumulative_positive_finding_ids
            .iter()
            .collect::<HashSet<_>>();
        if self
            .current_positive_finding_ids
            .iter()
            .any(|finding| !cumulative.contains(finding))
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidStatement);
        }
        Ok(())
    }

    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub fn authority_id(&self) -> &ArtifactReviewChallengeAuthorityIdV2 {
        &self.authority_id
    }

    pub fn challenge_binding_sha256(&self) -> &Sha256Digest {
        &self.challenge_binding_sha256
    }

    pub fn runtime_execution_binding_sha256(&self) -> &Sha256Digest {
        &self.runtime_execution_binding_sha256
    }

    pub fn key_identity(&self) -> &ArtifactReviewKeyIdentityV2 {
        &self.key_identity
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn run_started_at_unix_seconds(&self) -> u64 {
        self.run_started_at_unix_seconds
    }

    pub fn run_finished_at_unix_seconds(&self) -> u64 {
        self.run_finished_at_unix_seconds
    }

    pub fn evidence_issued_at_unix_seconds(&self) -> u64 {
        self.evidence_issued_at_unix_seconds
    }

    pub fn evidence_expires_at_unix_seconds(&self) -> u64 {
        self.evidence_expires_at_unix_seconds
    }

    pub fn subject(&self) -> &ArtifactReviewSubjectBindingV2 {
        &self.subject
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn aggregate_manifest_sha256(&self) -> &Sha256Digest {
        &self.aggregate_manifest_sha256
    }

    pub fn normalized_result_sha256(&self) -> &Sha256Digest {
        &self.normalized_result_sha256
    }

    pub fn current_positive_finding_ids(&self) -> &[Sha256Digest] {
        &self.current_positive_finding_ids
    }

    pub fn cumulative_positive_finding_ids(&self) -> &[Sha256Digest] {
        &self.cumulative_positive_finding_ids
    }

    pub fn completeness(&self) -> ArtifactReviewEvidenceCompletenessV2 {
        self.completeness
    }

    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    pub fn canonical_json_v2(&self) -> Result<Vec<u8>, ArtifactReviewAuthErrorV2> {
        self.validate()?;
        let predecessor = match &self.predecessor_evidence_sha256 {
            ExplicitDigestStateV2::Absent => ExplicitDigestWireV2::Absent,
            ExplicitDigestStateV2::Present(digest) => ExplicitDigestWireV2::Present {
                sha256: digest.as_str(),
            },
        };
        let wire = EvidenceStatementWireV2 {
            schema_version: ARTIFACT_REVIEW_EVIDENCE_STATEMENT_SCHEMA_V2,
            canonicalization: ARTIFACT_REVIEW_EVIDENCE_CANONICALIZATION_V2,
            signature_profile: ARTIFACT_REVIEW_EVIDENCE_SIGNATURE_PROFILE_V2,
            authority_id: self.authority_id.as_str(),
            trust_domain: self.key_identity.trust_domain(),
            issuer_id: self.key_identity.issuer_id(),
            producer_role: "host_control_plane",
            evidence_purpose: "restrictive_advisory_only",
            algorithm: self.key_identity.algorithm(),
            key_id: self.key_identity.key_id(),
            key_epoch: self.key_identity.key_epoch().to_string(),
            challenge_id: &self.challenge_id,
            challenge_binding_sha256: self.challenge_binding_sha256.as_str(),
            runtime_execution_binding_sha256: self.runtime_execution_binding_sha256.as_str(),
            evidence_id: &self.evidence_id,
            run_id: &self.run_id,
            artifact_sha256: self.subject.artifact_sha256().as_str(),
            envelope_sha256: self.subject.envelope_sha256().as_str(),
            manifest_sha256: self.subject.manifest_sha256().as_str(),
            cas_object_key: self.subject.cas_object_key(),
            policy_sha256: self.policy_sha256.as_str(),
            request_sha256: self.request_sha256.as_str(),
            expected_work_set_sha256: self.expected_work_set_sha256.as_str(),
            expected_work_item_count: self.expected_work_item_count.to_string(),
            lineage_scope: &self.lineage_scope,
            predecessor_evidence_sha256: predecessor,
            challenge_issued_at_unix_seconds: self.challenge_issued_at_unix_seconds.to_string(),
            challenge_expires_at_unix_seconds: self.challenge_expires_at_unix_seconds.to_string(),
            run_started_at_unix_seconds: self.run_started_at_unix_seconds.to_string(),
            run_finished_at_unix_seconds: self.run_finished_at_unix_seconds.to_string(),
            evidence_issued_at_unix_seconds: self.evidence_issued_at_unix_seconds.to_string(),
            evidence_expires_at_unix_seconds: self.evidence_expires_at_unix_seconds.to_string(),
            deterministic_analysis_sha256: self.deterministic_analysis_sha256.as_str(),
            coverage_manifest_sha256: self.coverage_manifest_sha256.as_str(),
            provider_adapter_sha256: self.provider_adapter_sha256.as_str(),
            model_content_sha256: self.model_content_sha256.as_str(),
            prompt_template_sha256: self.prompt_template_sha256.as_str(),
            model_output_schema_sha256: self.model_output_schema_sha256.as_str(),
            adapter_result_schema_sha256: self.adapter_result_schema_sha256.as_str(),
            declared_control_plane_build_sha256: self.declared_control_plane_build_sha256.as_str(),
            runtime_contract_sha256: self.runtime_contract_sha256.as_str(),
            normalizer_contract_sha256: self.normalizer_contract_sha256.as_str(),
            aggregate_manifest_sha256: self.aggregate_manifest_sha256.as_str(),
            aggregate_manifest_byte_len: self.aggregate_manifest_byte_len.to_string(),
            normalized_result_sha256: self.normalized_result_sha256.as_str(),
            normalized_result_byte_len: self.normalized_result_byte_len.to_string(),
            execution_claims_sha256: self.execution_claims_sha256.as_str(),
            current_positive_finding_ids: digest_strings_v2(&self.current_positive_finding_ids),
            cumulative_positive_finding_ids: digest_strings_v2(
                &self.cumulative_positive_finding_ids,
            ),
            completeness: self.completeness,
            limitations: &self.limitations,
        };
        let body = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| ArtifactReviewAuthErrorV2::Serialization)?;
        if body.len() > MAX_ARTIFACT_REVIEW_EVIDENCE_STATEMENT_BYTES_V2 {
            return Err(ArtifactReviewAuthErrorV2::StatementLimitExceeded);
        }
        Ok(body)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EvidenceStatementWireV2<'a> {
    schema_version: &'a str,
    canonicalization: &'a str,
    signature_profile: &'a str,
    authority_id: &'a str,
    trust_domain: &'a str,
    issuer_id: &'a str,
    producer_role: &'a str,
    evidence_purpose: &'a str,
    algorithm: &'a str,
    key_id: &'a str,
    key_epoch: String,
    challenge_id: &'a str,
    challenge_binding_sha256: &'a str,
    runtime_execution_binding_sha256: &'a str,
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
    lineage_scope: &'a str,
    predecessor_evidence_sha256: ExplicitDigestWireV2<'a>,
    challenge_issued_at_unix_seconds: String,
    challenge_expires_at_unix_seconds: String,
    run_started_at_unix_seconds: String,
    run_finished_at_unix_seconds: String,
    evidence_issued_at_unix_seconds: String,
    evidence_expires_at_unix_seconds: String,
    deterministic_analysis_sha256: &'a str,
    coverage_manifest_sha256: &'a str,
    provider_adapter_sha256: &'a str,
    model_content_sha256: &'a str,
    prompt_template_sha256: &'a str,
    model_output_schema_sha256: &'a str,
    adapter_result_schema_sha256: &'a str,
    declared_control_plane_build_sha256: &'a str,
    runtime_contract_sha256: &'a str,
    normalizer_contract_sha256: &'a str,
    aggregate_manifest_sha256: &'a str,
    aggregate_manifest_byte_len: String,
    normalized_result_sha256: &'a str,
    normalized_result_byte_len: String,
    execution_claims_sha256: &'a str,
    current_positive_finding_ids: Vec<&'a str>,
    cumulative_positive_finding_ids: Vec<&'a str>,
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: &'a [String],
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ExplicitDigestWireV2<'a> {
    Absent,
    Present { sha256: &'a str },
}

pub struct SignedArtifactReviewStatementV2 {
    transport_bytes: Vec<u8>,
}

impl fmt::Debug for SignedArtifactReviewStatementV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedArtifactReviewStatementV2")
            .field(
                "transport_sha256",
                &Sha256Digest::from_bytes(&self.transport_bytes),
            )
            .field("transport_byte_len", &self.transport_bytes.len())
            .field("canonical_statement", &"<redacted>")
            .field("signature", &"<redacted>")
            .finish()
    }
}

impl SignedArtifactReviewStatementV2 {
    pub fn from_transport_bytes(
        transport_bytes: Vec<u8>,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        decode_signed_transport_v2(&transport_bytes)?;
        Ok(Self { transport_bytes })
    }

    pub fn transport_bytes(&self) -> &[u8] {
        &self.transport_bytes
    }

    pub fn evidence_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&self.transport_bytes)
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

pub(crate) fn sign_artifact_review_statement_v2(
    statement: &ArtifactReviewEvidenceStatementV2,
    signer: &ArtifactReviewSigningKeyV2,
) -> Result<SignedArtifactReviewStatementV2, ArtifactReviewAuthErrorV2> {
    statement.validate()?;
    if statement.key_identity() != signer.identity() {
        return Err(ArtifactReviewAuthErrorV2::UnknownKey);
    }
    signer.validate_for_evidence(
        statement.evidence_issued_at_unix_seconds,
        statement.evidence_expires_at_unix_seconds,
    )?;
    let body = statement.canonical_json_v2()?;
    let mut signed_prefix = signature_input_prefix_v2(&body)?;
    let signature = signer.sign(&signed_prefix);
    signed_prefix.extend_from_slice(&signature);
    SignedArtifactReviewStatementV2::from_transport_bytes(signed_prefix)
}

pub(crate) struct SignatureVerifiedArtifactReviewStatementV2 {
    statement: ArtifactReviewEvidenceStatementV2,
    evidence_sha256: Sha256Digest,
}

impl fmt::Debug for SignatureVerifiedArtifactReviewStatementV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignatureVerifiedArtifactReviewStatementV2")
            .field("evidence_sha256", &self.evidence_sha256)
            .field("evidence_id", &self.statement.evidence_id)
            .field("run_id", &self.statement.run_id)
            .field("completeness", &self.statement.completeness)
            .finish()
    }
}

impl SignatureVerifiedArtifactReviewStatementV2 {
    pub fn statement(&self) -> &ArtifactReviewEvidenceStatementV2 {
        &self.statement
    }

    pub fn evidence_sha256(&self) -> &Sha256Digest {
        &self.evidence_sha256
    }
}

/// Verifies a statement against an independently constructed expected value.
/// No untrusted JSON is parsed: the canonical body must be byte-identical to
/// the verifier-owned projection before the authenticated wrapper is created.
pub(crate) fn verify_artifact_review_statement_signature_v2(
    signed: &SignedArtifactReviewStatementV2,
    expected: ArtifactReviewEvidenceStatementV2,
    registry: &ArtifactReviewKeyRegistryV2,
    now_unix_seconds: u64,
) -> Result<SignatureVerifiedArtifactReviewStatementV2, ArtifactReviewAuthErrorV2> {
    expected.validate()?;
    let decoded = decode_signed_transport_v2(signed.transport_bytes())?;
    let record = registry.resolve(expected.key_identity())?;
    record.validate_for_evidence(
        expected.evidence_issued_at_unix_seconds,
        expected.evidence_expires_at_unix_seconds,
        now_unix_seconds,
    )?;
    if now_unix_seconds < expected.evidence_issued_at_unix_seconds
        || now_unix_seconds >= expected.evidence_expires_at_unix_seconds
    {
        return Err(ArtifactReviewAuthErrorV2::FreshnessInvalid);
    }
    record.verify_strict(decoded.signature_input, decoded.signature)?;
    let expected_body = expected.canonical_json_v2()?;
    if decoded.body != expected_body {
        return Err(ArtifactReviewAuthErrorV2::InvalidStatement);
    }
    Ok(SignatureVerifiedArtifactReviewStatementV2 {
        statement: expected,
        evidence_sha256: signed.evidence_sha256(),
    })
}

struct DecodedSignedTransportV2<'a> {
    signature_input: &'a [u8],
    body: &'a [u8],
    signature: &'a [u8; SIGNATURE_BYTES_V2],
}

fn signature_input_prefix_v2(body: &[u8]) -> Result<Vec<u8>, ArtifactReviewAuthErrorV2> {
    if body.is_empty() || body.len() > MAX_ARTIFACT_REVIEW_EVIDENCE_STATEMENT_BYTES_V2 {
        return Err(ArtifactReviewAuthErrorV2::StatementLimitExceeded);
    }
    let body_len =
        u32::try_from(body.len()).map_err(|_| ArtifactReviewAuthErrorV2::StatementLimitExceeded)?;
    let mut bytes = Vec::with_capacity(SIGNATURE_DOMAIN_V2.len() + 2 + 4 + body.len());
    bytes.extend_from_slice(SIGNATURE_DOMAIN_V2);
    bytes.extend_from_slice(&SIGNATURE_LAYOUT_VERSION_V2.to_be_bytes());
    bytes.extend_from_slice(&body_len.to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}

fn decode_signed_transport_v2(
    transport: &[u8],
) -> Result<DecodedSignedTransportV2<'_>, ArtifactReviewAuthErrorV2> {
    let header_len = SIGNATURE_DOMAIN_V2.len() + 2 + 4;
    if transport.len() < header_len + 1 + SIGNATURE_BYTES_V2
        || !transport.starts_with(SIGNATURE_DOMAIN_V2)
    {
        return Err(ArtifactReviewAuthErrorV2::InvalidSignature);
    }
    let version_start = SIGNATURE_DOMAIN_V2.len();
    let version = u16::from_be_bytes(
        transport[version_start..version_start + 2]
            .try_into()
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidSignature)?,
    );
    if version != SIGNATURE_LAYOUT_VERSION_V2 {
        return Err(ArtifactReviewAuthErrorV2::InvalidSignature);
    }
    let length_start = version_start + 2;
    let body_len = u32::from_be_bytes(
        transport[length_start..length_start + 4]
            .try_into()
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidSignature)?,
    ) as usize;
    if body_len == 0 || body_len > MAX_ARTIFACT_REVIEW_EVIDENCE_STATEMENT_BYTES_V2 {
        return Err(ArtifactReviewAuthErrorV2::StatementLimitExceeded);
    }
    let body_end = header_len
        .checked_add(body_len)
        .ok_or(ArtifactReviewAuthErrorV2::StatementLimitExceeded)?;
    let expected_len = body_end
        .checked_add(SIGNATURE_BYTES_V2)
        .ok_or(ArtifactReviewAuthErrorV2::StatementLimitExceeded)?;
    if transport.len() != expected_len {
        return Err(ArtifactReviewAuthErrorV2::InvalidSignature);
    }
    let signature = transport[body_end..]
        .try_into()
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidSignature)?;
    Ok(DecodedSignedTransportV2 {
        signature_input: &transport[..body_end],
        body: &transport[header_len..body_end],
        signature,
    })
}

fn strictly_sorted_unique_v2(values: &[Sha256Digest]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn digest_strings_v2(values: &[Sha256Digest]) -> Vec<&str> {
    values.iter().map(Sha256Digest::as_str).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        canonical_artifact_review_lineage_scope_v2, ArtifactReviewChallengeAuthorityV2,
        ArtifactReviewChallengeBindingV2, ArtifactReviewChallengeDraftV2,
        ArtifactReviewKeyIdentityV2, ArtifactReviewVerificationKeyRecordV2,
    };
    use whoathere_evidence::v2::{
        canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2,
    };

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn subject() -> ArtifactReviewSubjectBindingV2 {
        let artifact = digest("wire-test-artifact");
        let subject = ArtifactEvidenceSubjectV2::new(
            artifact.as_str(),
            digest("wire-test-envelope").as_str(),
            digest("wire-test-manifest").as_str(),
            canonical_cas_object_key_for_artifact(artifact.as_str()).expect("CAS key"),
        )
        .expect("subject");
        ArtifactReviewSubjectBindingV2::from_subject(&subject).expect("binding")
    }

    fn key_identity() -> ArtifactReviewKeyIdentityV2 {
        ArtifactReviewKeyIdentityV2::new_host_control_plane(
            "wire-test-domain",
            "wire-test-issuer",
            "wire-test-key",
            1,
        )
        .expect("identity")
    }

    fn signer() -> ArtifactReviewSigningKeyV2 {
        let mut seed = [7_u8; 32];
        let signer =
            ArtifactReviewSigningKeyV2::from_seed(key_identity(), &mut seed, 900, 2_000, None)
                .expect("signer");
        assert_eq!(seed, [0_u8; 32]);
        signer
    }

    fn statement(normalized_label: &str) -> ArtifactReviewEvidenceStatementV2 {
        let subject = subject();
        let lineage_scope = canonical_artifact_review_lineage_scope_v2(&subject).expect("lineage");
        let binding = ArtifactReviewChallengeBindingV2::new(ArtifactReviewChallengeDraftV2 {
            evidence_id: "wire-test-evidence".to_string(),
            run_id: "wire-test-run".to_string(),
            subject,
            policy_sha256: digest("wire-test-policy"),
            request_sha256: digest("wire-test-request"),
            expected_work_set_sha256: digest("wire-test-work-set"),
            expected_work_item_count: 3,
            key_identity: key_identity(),
            lineage_scope,
            predecessor_evidence_sha256: ExplicitDigestStateV2::Absent,
            issued_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 1_300,
        })
        .expect("challenge binding");
        let challenge = ArtifactReviewChallengeAuthorityV2::new_memory_only()
            .expect("authority")
            .issue(binding)
            .expect("challenge issue")
            .into_challenge();
        let challenge_binding_sha256 = challenge
            .canonical_binding_sha256_v2()
            .expect("challenge binding digest");
        let runtime_binding = LocalProviderEvidenceExecutionBindingV2::new(
            challenge.challenge_id(),
            challenge.binding().evidence_id(),
            challenge.binding().run_id(),
            challenge_binding_sha256.clone(),
        )
        .expect("runtime binding");
        let runtime_execution_binding_sha256 =
            crate::local_provider_evidence_execution_binding_sha256_v2(
                challenge.authority_id(),
                &runtime_binding,
            )
            .expect("runtime binding digest");
        let positive = digest("wire-test-positive");
        ArtifactReviewEvidenceStatementV2::new(ArtifactReviewEvidenceStatementDraftV2 {
            challenge,
            challenge_binding_sha256,
            runtime_execution_binding_sha256,
            run_started_at_unix_seconds: 1_001,
            run_finished_at_unix_seconds: 1_002,
            evidence_issued_at_unix_seconds: 1_003,
            evidence_expires_at_unix_seconds: 1_200,
            deterministic_analysis_sha256: digest("wire-test-analysis"),
            coverage_manifest_sha256: digest("wire-test-coverage"),
            provider_adapter_sha256: digest("wire-test-provider"),
            model_content_sha256: digest("wire-test-model"),
            prompt_template_sha256: digest("wire-test-prompt"),
            model_output_schema_sha256: digest("wire-test-model-schema"),
            adapter_result_schema_sha256: digest("wire-test-adapter-schema"),
            declared_control_plane_build_sha256: digest("wire-test-declared-build"),
            runtime_contract_sha256: digest("wire-test-runtime-contract"),
            normalizer_contract_sha256: digest("wire-test-normalizer-contract"),
            aggregate_manifest_sha256: digest("wire-test-aggregate"),
            aggregate_manifest_byte_len: 4_096,
            normalized_result_sha256: digest(normalized_label),
            normalized_result_byte_len: 1_024,
            execution_claims_sha256: digest("wire-test-claims"),
            current_positive_finding_ids: vec![positive.clone()],
            cumulative_positive_finding_ids: vec![positive],
            completeness: ArtifactReviewEvidenceCompletenessV2::Incomplete,
            limitations: vec!["wire_test_limitation".to_string()],
        })
        .expect("statement")
    }

    #[test]
    fn canonical_profile_has_no_numbers_or_nulls_and_strict_signature_verifies() {
        let statement = statement("wire-test-normalized");
        let body = statement.canonical_json_v2().expect("body");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("JSON");
        fn assert_profile(value: &serde_json::Value) {
            match value {
                serde_json::Value::Null | serde_json::Value::Number(_) => {
                    panic!("signed profile forbids null and number tokens")
                }
                serde_json::Value::Array(values) => values.iter().for_each(assert_profile),
                serde_json::Value::Object(fields) => fields.values().for_each(assert_profile),
                serde_json::Value::Bool(_) | serde_json::Value::String(_) => {}
            }
        }
        assert_profile(&value);
        assert_eq!(
            serde_json_canonicalizer::to_vec(&value).expect("canonical"),
            body
        );

        let signer = signer();
        let registry =
            ArtifactReviewKeyRegistryV2::new([signer.verification_record()]).expect("registry");
        let signed = sign_artifact_review_statement_v2(&statement, &signer).expect("sign");
        let verified = verify_artifact_review_statement_signature_v2(
            &signed,
            statement.clone(),
            &registry,
            1_004,
        )
        .expect("verify");
        assert_eq!(verified.statement(), &statement);
        assert_eq!(verified.evidence_sha256(), &signed.evidence_sha256());
    }

    #[test]
    fn tampering_wrong_expected_body_and_revocation_fail_closed() {
        let expected = statement("wire-test-normalized-a");
        let signer = signer();
        let record = signer.verification_record();
        let registry = ArtifactReviewKeyRegistryV2::new([record.clone()]).expect("registry");
        let signed = sign_artifact_review_statement_v2(&expected, &signer).expect("sign");

        let mut tampered = signed.transport_bytes().to_vec();
        *tampered.last_mut().expect("signature") ^= 1;
        let tampered =
            SignedArtifactReviewStatementV2::from_transport_bytes(tampered).expect("wire shape");
        assert!(matches!(
            verify_artifact_review_statement_signature_v2(
                &tampered,
                expected.clone(),
                &registry,
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::SignatureVerificationFailed)
        ));
        assert!(matches!(
            verify_artifact_review_statement_signature_v2(
                &signed,
                statement("wire-test-normalized-b"),
                &registry,
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::InvalidStatement)
        ));

        let revoked = ArtifactReviewVerificationKeyRecordV2::new(
            record.identity().clone(),
            record.verifying_key_bytes(),
            record.active_from_unix_seconds(),
            record.active_until_unix_seconds(),
            Some(1_004),
        )
        .expect("revoked record");
        let revoked_registry = ArtifactReviewKeyRegistryV2::new([revoked]).expect("registry");
        assert!(matches!(
            verify_artifact_review_statement_signature_v2(
                &signed,
                expected,
                &revoked_registry,
                1_004,
            ),
            Err(ArtifactReviewAuthErrorV2::KeyRevoked)
        ));
    }
}
