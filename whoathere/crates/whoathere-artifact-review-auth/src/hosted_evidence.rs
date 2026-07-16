//! Authenticated aggregation for subscription-backed hosted Artifact Review.
//!
//! The host signer authenticates only locally observed adapter receipts and the
//! deterministic normalization of their captured model outputs. It does not
//! attest provider internals, hosted model contents, billing truth, or package
//! safety, and this evidence can never authorize admission.

use crate::aggregate::{cumulative_findings_for_statement_v2, trusted_system_unix_seconds_v2};
use crate::wire::{
    sign_artifact_review_statement_v2, verify_artifact_review_statement_signature_v2,
    SignatureVerifiedArtifactReviewStatementV2,
};
use crate::{
    ArtifactReviewAuthErrorV2, ArtifactReviewChallengeAcceptanceCommitReceiptV2,
    ArtifactReviewChallengeAcceptanceV2, ArtifactReviewChallengeAuthorityIdV2,
    ArtifactReviewChallengeAuthorityV2, ArtifactReviewEvidenceCompletenessV2,
    ArtifactReviewEvidenceModelIdentityPostureV2, ArtifactReviewEvidenceRunContextV2,
    ArtifactReviewEvidenceStatementDraftV2, ArtifactReviewEvidenceStatementV2,
    ArtifactReviewKeyRegistryV2, ArtifactReviewSigningKeyV2, SignedArtifactReviewStatementV2,
    MAX_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_BYTES_V2, MAX_ARTIFACT_REVIEW_EVIDENCE_TTL_SECONDS_V2,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::{NormalizedArtifact, Sha256Digest};
use whoathere_artifact_review_runtime::{
    hosted_cli_provider_identity_v2, hosted_expected_work_set_sha256_v3,
    recompute_verified_hosted_runtime_batch_sha256_v3,
    recompute_verified_hosted_runtime_row_sha256_v3,
    validate_verified_hosted_runtime_batch_against_request_v3, ArtifactAiAuthenticationModeV2,
    ArtifactAiAvailableInferenceControlsV2, ArtifactAiControlPostureV2,
    ArtifactAiExecutionStatusV2, ArtifactAiObservedModelV2, ArtifactAiProviderKindV2,
    ArtifactAiProviderTransportV2, HostedRuntimeBatchBindingInputV3, HostedRuntimeChallengeV3,
    HostedRuntimeRowBindingInputV3, HostedRuntimeRowFailureV3, VerifiedHostedRuntimeBatchV3,
    VerifiedHostedRuntimeRowStateV3, ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V2,
    CLAUDE_SUBSCRIPTION_ADAPTER_VERSION_V2, CODEX_SUBSCRIPTION_ADAPTER_VERSION_V2,
    VERIFIED_HOSTED_RUNTIME_BATCH_SCHEMA_V3, VERIFIED_HOSTED_RUNTIME_ROW_SCHEMA_V3,
};
use whoathere_detector::{
    normalize_artifact_review_provider_outputs_v2, ArtifactReviewAdapterNormalizationV2,
    ArtifactReviewChannelIsolationV2, ArtifactReviewCoverageCompletenessV2,
    ArtifactReviewModelIdentityPostureV2, ArtifactReviewPrivacyPostureV2,
    ArtifactReviewProviderOutputV2, ArtifactReviewRequestV2, ArtifactReviewVerdictV2,
    ArtifactReviewWorkItemNormalizationStatusV2, ArtifactReviewWorkItemStatusV2,
    ArtifactStaticAnalysis,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const HOSTED_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_SCHEMA_V2: &str =
    "whoathere.artifact_review_hosted_authenticated_aggregate_manifest.v3";
pub const HOSTED_ARTIFACT_REVIEW_RECEIPT_PROJECTION_V3: &str =
    "whoathere.hosted_receipt.decimal_strings.tagged_absence.v3";
pub const HOSTED_ARTIFACT_REVIEW_RUNTIME_CONTRACT_ID_V2: &str =
    "whoathere.hosted_artifact_review_runtime_contract.v3";
pub const HOSTED_ARTIFACT_REVIEW_EXECUTION_BINDING_SCHEMA_V2: &str =
    "whoathere.hosted_artifact_review_execution_binding.v3";
pub const HOSTED_ARTIFACT_REVIEW_EVIDENCE_BOUND_EXECUTION_SEAM_V2: &str =
    "whoathere.hosted_provider_prechallenged_sealed_runtime_batch.v3";

/// Imported receipt/output material is useful for diagnostics, but it did not
/// cross the runtime-owned pre-challenged execution seam. There is
/// intentionally no conversion from this type to `VerifiedHostedRuntimeBatchV3`
/// and no signing API accepts it.
pub struct UnauthenticatedImportedHostedInvocationV3 {
    provider_output: ArtifactReviewProviderOutputV2,
    receipt_canonical_json: Vec<u8>,
}

impl fmt::Debug for UnauthenticatedImportedHostedInvocationV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnauthenticatedImportedHostedInvocationV3")
            .field("work_item_id", self.provider_output.work_item_id())
            .field(
                "provider_output_sha256",
                &self.provider_output.captured_output_sha256(),
            )
            .field(
                "receipt_sha256",
                &Sha256Digest::from_bytes(&self.receipt_canonical_json),
            )
            .field("provider_output", &"<redacted>")
            .field("receipt", &"<redacted>")
            .finish()
    }
}

impl UnauthenticatedImportedHostedInvocationV3 {
    pub fn from_imported_parts(
        provider_output: ArtifactReviewProviderOutputV2,
        receipt_canonical_json: Vec<u8>,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        if receipt_canonical_json.is_empty()
            || receipt_canonical_json.len()
                > MAX_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_BYTES_V2 as usize
        {
            return Err(ArtifactReviewAuthErrorV2::StatementLimitExceeded);
        }
        Ok(Self {
            provider_output,
            receipt_canonical_json,
        })
    }

    pub const fn is_authenticated(&self) -> bool {
        false
    }

    pub const fn can_be_signed(&self) -> bool {
        false
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HostedProviderEvidenceExecutionBindingV2 {
    challenge_id: String,
    evidence_id: String,
    run_id: String,
    challenge_binding_sha256: Sha256Digest,
}

/// Converts an issued authentication challenge into the opaque, single-use
/// runtime token. The token is consumed by the hosted runtime before any
/// provider process starts; it cannot be attached to imported evidence later.
pub fn hosted_runtime_challenge_v3(
    context: &ArtifactReviewEvidenceRunContextV2,
    request: &ArtifactReviewRequestV2,
) -> Result<HostedRuntimeChallengeV3, ArtifactReviewAuthErrorV2> {
    let challenge = context.challenge();
    let binding = challenge.binding();
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let expected_work_set_sha256 = hosted_expected_work_set_sha256_v3(request)
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    if binding.request_sha256() != &request_sha256
        || binding.expected_work_set_sha256() != &expected_work_set_sha256
        || usize::try_from(binding.expected_work_item_count()).ok()
            != Some(request.work_items().len())
    {
        return Err(ArtifactReviewAuthErrorV2::ContextBindingMismatch);
    }
    HostedRuntimeChallengeV3::new(
        challenge.authority_id().as_str(),
        challenge.challenge_id(),
        binding.evidence_id(),
        binding.run_id(),
        challenge.canonical_binding_sha256_v2()?,
        request_sha256,
        expected_work_set_sha256,
        binding.expected_work_item_count(),
        binding.issued_at_unix_seconds(),
        binding.expires_at_unix_seconds(),
    )
    .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)
}

pub fn hosted_provider_evidence_execution_binding_sha256_v2(
    authority_id: &ArtifactReviewChallengeAuthorityIdV2,
    challenge_id: &str,
    evidence_id: &str,
    run_id: &str,
    challenge_binding_sha256: &Sha256Digest,
) -> Result<Sha256Digest, ArtifactReviewAuthErrorV2> {
    let wire = HostedExecutionBindingWireV2 {
        schema_version: HOSTED_ARTIFACT_REVIEW_EXECUTION_BINDING_SCHEMA_V2,
        evidence_binding_seam: HOSTED_ARTIFACT_REVIEW_EVIDENCE_BOUND_EXECUTION_SEAM_V2,
        authority_id: authority_id.as_str(),
        challenge_id,
        evidence_id,
        run_id,
        challenge_binding_sha256: challenge_binding_sha256.as_str(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactReviewAuthErrorV2::Serialization)?;
    Ok(Sha256Digest::from_bytes(&bytes))
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostedExecutionBindingWireV2<'a> {
    schema_version: &'a str,
    evidence_binding_seam: &'a str,
    authority_id: &'a str,
    challenge_id: &'a str,
    evidence_id: &'a str,
    run_id: &'a str,
    challenge_binding_sha256: &'a str,
}

pub fn hosted_artifact_review_runtime_contract_sha256_v2() -> Sha256Digest {
    Sha256Digest::from_bytes(
        format!(
            "{HOSTED_ARTIFACT_REVIEW_RUNTIME_CONTRACT_ID_V2}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V2,
            CLAUDE_SUBSCRIPTION_ADAPTER_VERSION_V2,
            CODEX_SUBSCRIPTION_ADAPTER_VERSION_V2,
            VERIFIED_HOSTED_RUNTIME_BATCH_SCHEMA_V3,
            VERIFIED_HOSTED_RUNTIME_ROW_SCHEMA_V3,
            HOSTED_ARTIFACT_REVIEW_EXECUTION_BINDING_SCHEMA_V2,
            HOSTED_ARTIFACT_REVIEW_EVIDENCE_BOUND_EXECUTION_SEAM_V2,
            HOSTED_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_SCHEMA_V2,
            HOSTED_ARTIFACT_REVIEW_RECEIPT_PROJECTION_V3,
        )
        .as_bytes(),
    )
}

struct RestrictedHostedRuntimeRowMaterialV3 {
    work_item_id: Sha256Digest,
    state: VerifiedHostedRuntimeRowStateV3,
    failure_reason: Option<HostedRuntimeRowFailureV3>,
    output_channel_isolation: ArtifactReviewChannelIsolationV2,
    output_no_truncation_verified: bool,
    provider_output_bytes: Vec<u8>,
    receipt_canonical_json: Vec<u8>,
    row_sha256: Sha256Digest,
}

pub struct RestrictedHostedArtifactReviewEvidenceMaterialV2 {
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    binding: HostedProviderEvidenceExecutionBindingV2,
    request_sha256: Sha256Digest,
    expected_work_set_sha256: Sha256Digest,
    expected_work_item_count: u32,
    expected_work_item_ids: Vec<Sha256Digest>,
    provider: ArtifactAiProviderKindV2,
    model_identity_sha256: Sha256Digest,
    model_identity_posture: ArtifactReviewModelIdentityPostureV2,
    runtime_challenge_issued_at_unix_seconds: u64,
    runtime_challenge_expires_at_unix_seconds: u64,
    runtime_started_at_unix_millis: u64,
    runtime_finished_at_unix_millis: u64,
    runtime_coverage_complete: bool,
    runtime_batch_sha256: Sha256Digest,
    run_started_at_unix_seconds: u64,
    run_finished_at_unix_seconds: u64,
    evidence_issued_at_unix_seconds: u64,
    evidence_expires_at_unix_seconds: u64,
    provider_outputs: Vec<ArtifactReviewProviderOutputV2>,
    runtime_rows: Vec<RestrictedHostedRuntimeRowMaterialV3>,
    aggregate_manifest: Vec<u8>,
    normalized_result: Vec<u8>,
}

impl fmt::Debug for RestrictedHostedArtifactReviewEvidenceMaterialV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedHostedArtifactReviewEvidenceMaterialV2")
            .field("authority_id", &self.authority_id)
            .field("binding", &self.binding)
            .field("runtime_batch_sha256", &self.runtime_batch_sha256)
            .field("invocation_count", &self.provider_outputs.len())
            .field(
                "aggregate_manifest_sha256",
                &Sha256Digest::from_bytes(&self.aggregate_manifest),
            )
            .field(
                "normalized_result_sha256",
                &Sha256Digest::from_bytes(&self.normalized_result),
            )
            .field("invocations", &"<restricted>")
            .field("normalized_result", &"<redacted>")
            .finish()
    }
}

impl RestrictedHostedArtifactReviewEvidenceMaterialV2 {
    pub fn aggregate_manifest_bytes(&self) -> &[u8] {
        &self.aggregate_manifest
    }
}

pub struct SignedHostedArtifactReviewEvidencePackageV2 {
    signed_statement: SignedArtifactReviewStatementV2,
    restricted_material: RestrictedHostedArtifactReviewEvidenceMaterialV2,
}

impl fmt::Debug for SignedHostedArtifactReviewEvidencePackageV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedHostedArtifactReviewEvidencePackageV2")
            .field("signed_statement", &self.signed_statement)
            .field("restricted_material", &self.restricted_material)
            .finish()
    }
}

impl SignedHostedArtifactReviewEvidencePackageV2 {
    pub fn signed_statement(&self) -> &SignedArtifactReviewStatementV2 {
        &self.signed_statement
    }

    pub fn into_parts(
        self,
    ) -> (
        SignedArtifactReviewStatementV2,
        RestrictedHostedArtifactReviewEvidenceMaterialV2,
    ) {
        (self.signed_statement, self.restricted_material)
    }

    pub fn from_parts(
        signed_statement: SignedArtifactReviewStatementV2,
        restricted_material: RestrictedHostedArtifactReviewEvidenceMaterialV2,
    ) -> Self {
        Self {
            signed_statement,
            restricted_material,
        }
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

pub struct AuthenticatedHostedArtifactReviewEvidenceV2 {
    authenticated_statement: SignatureVerifiedArtifactReviewStatementV2,
    normalization: ArtifactReviewAdapterNormalizationV2,
    acceptance_commit_receipt: ArtifactReviewChallengeAcceptanceCommitReceiptV2,
}

impl fmt::Debug for AuthenticatedHostedArtifactReviewEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedHostedArtifactReviewEvidenceV2")
            .field("authenticated_statement", &self.authenticated_statement)
            .field("normalization", &self.normalization)
            .field("acceptance_commit_receipt", &self.acceptance_commit_receipt)
            .finish()
    }
}

impl AuthenticatedHostedArtifactReviewEvidenceV2 {
    pub fn evidence_sha256(&self) -> &Sha256Digest {
        self.authenticated_statement.evidence_sha256()
    }

    pub fn statement(&self) -> &ArtifactReviewEvidenceStatementV2 {
        self.authenticated_statement.statement()
    }

    pub fn result(&self) -> &whoathere_detector::StructurallyValidatedArtifactReviewResultV2 {
        self.normalization.structurally_validated_result()
    }

    pub fn acceptance(&self) -> ArtifactReviewChallengeAcceptanceV2 {
        self.acceptance_commit_receipt.outcome()
    }

    pub fn acceptance_commit_receipt(&self) -> &ArtifactReviewChallengeAcceptanceCommitReceiptV2 {
        &self.acceptance_commit_receipt
    }

    /// Hosted model contents and provider internals remain opaque, so hosted
    /// evidence is deliberately never represented as complete.
    pub const fn is_complete(&self) -> bool {
        false
    }

    pub const fn is_authenticated(&self) -> bool {
        true
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub fn sign_hosted_provider_artifact_review_evidence_v2(
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    context: &ArtifactReviewEvidenceRunContextV2,
    verified_runtime_batch: VerifiedHostedRuntimeBatchV3,
    signer: &ArtifactReviewSigningKeyV2,
    challenge_authority: &ArtifactReviewChallengeAuthorityV2,
) -> Result<SignedHostedArtifactReviewEvidencePackageV2, ArtifactReviewAuthErrorV2> {
    context.validate_bindings(subject, artifact, analysis, request)?;
    challenge_authority.ensure_owns_challenge(context.challenge())?;
    let issued_at = trusted_system_unix_seconds_v2()?;
    let expires_at = issued_at
        .checked_add(context.evidence_ttl_seconds())
        .ok_or(ArtifactReviewAuthErrorV2::FreshnessInvalid)?;
    let mut material = material_from_verified_hosted_runtime_batch_v3(
        context,
        request,
        verified_runtime_batch,
        issued_at,
        expires_at,
    )?;
    validate_hosted_material_context_v2(context, &material)?;
    let reconstructed =
        reconstruct_hosted_evidence_v2(subject, artifact, analysis, request, &material)?;
    material.aggregate_manifest = reconstructed.aggregate_manifest.clone();
    material.normalized_result = reconstructed
        .normalization
        .adapter_normalized_output()
        .to_vec();
    let cumulative = cumulative_findings_for_statement_v2(
        context,
        &reconstructed.current_positive_finding_ids,
        challenge_authority,
    )?;
    let statement =
        build_hosted_statement_v2(request, context, &material, &reconstructed, cumulative)?;
    let signed_statement = sign_artifact_review_statement_v2(&statement, signer)?;
    Ok(SignedHostedArtifactReviewEvidencePackageV2 {
        signed_statement,
        restricted_material: material,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_and_accept_hosted_provider_artifact_review_evidence_v2(
    package: SignedHostedArtifactReviewEvidencePackageV2,
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    context: &ArtifactReviewEvidenceRunContextV2,
    registry: &ArtifactReviewKeyRegistryV2,
    challenge_authority: &ArtifactReviewChallengeAuthorityV2,
) -> Result<AuthenticatedHostedArtifactReviewEvidenceV2, ArtifactReviewAuthErrorV2> {
    context.validate_bindings(subject, artifact, analysis, request)?;
    challenge_authority.ensure_owns_challenge(context.challenge())?;
    let SignedHostedArtifactReviewEvidencePackageV2 {
        signed_statement,
        restricted_material,
    } = package;
    validate_hosted_material_context_v2(context, &restricted_material)?;
    let reconstructed =
        reconstruct_hosted_evidence_v2(subject, artifact, analysis, request, &restricted_material)?;
    if restricted_material.aggregate_manifest != reconstructed.aggregate_manifest {
        return Err(ArtifactReviewAuthErrorV2::AggregateManifestMismatch);
    }
    if restricted_material.normalized_result
        != reconstructed.normalization.adapter_normalized_output()
    {
        return Err(ArtifactReviewAuthErrorV2::NormalizedResultMismatch);
    }
    let cumulative = cumulative_findings_for_statement_v2(
        context,
        &reconstructed.current_positive_finding_ids,
        challenge_authority,
    )?;
    let expected_statement = build_hosted_statement_v2(
        request,
        context,
        &restricted_material,
        &reconstructed,
        cumulative,
    )?;
    let verification_now = trusted_system_unix_seconds_v2()?;
    let authenticated_statement = verify_artifact_review_statement_signature_v2(
        &signed_statement,
        expected_statement,
        registry,
        verification_now,
    )?;
    let acceptance_commit_receipt = challenge_authority.accept_verified_evidence_with_findings(
        context.challenge(),
        signed_statement.evidence_sha256(),
        authenticated_statement
            .statement()
            .current_positive_finding_ids(),
        authenticated_statement
            .statement()
            .cumulative_positive_finding_ids(),
        verification_now,
    )?;
    Ok(AuthenticatedHostedArtifactReviewEvidenceV2 {
        authenticated_statement,
        normalization: reconstructed.normalization,
        acceptance_commit_receipt,
    })
}

fn material_from_verified_hosted_runtime_batch_v3(
    context: &ArtifactReviewEvidenceRunContextV2,
    request: &ArtifactReviewRequestV2,
    verified_runtime_batch: VerifiedHostedRuntimeBatchV3,
    evidence_issued_at_unix_seconds: u64,
    evidence_expires_at_unix_seconds: u64,
) -> Result<RestrictedHostedArtifactReviewEvidenceMaterialV2, ArtifactReviewAuthErrorV2> {
    if evidence_expires_at_unix_seconds <= evidence_issued_at_unix_seconds
        || evidence_expires_at_unix_seconds - evidence_issued_at_unix_seconds
            > MAX_ARTIFACT_REVIEW_EVIDENCE_TTL_SECONDS_V2
    {
        return Err(ArtifactReviewAuthErrorV2::FreshnessInvalid);
    }
    validate_verified_hosted_runtime_batch_against_request_v3(&verified_runtime_batch, request)
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    let challenge = context.challenge();
    let challenge_binding = challenge.binding();
    let expected_challenge_binding_sha256 = challenge.canonical_binding_sha256_v2()?;
    if verified_runtime_batch.authority_id() != challenge.authority_id().as_str()
        || verified_runtime_batch.challenge_id() != challenge.challenge_id()
        || verified_runtime_batch.evidence_id() != challenge_binding.evidence_id()
        || verified_runtime_batch.run_id() != challenge_binding.run_id()
        || verified_runtime_batch.challenge_binding_sha256() != &expected_challenge_binding_sha256
        || verified_runtime_batch.request_sha256() != challenge_binding.request_sha256()
        || verified_runtime_batch.expected_work_set_sha256()
            != challenge_binding.expected_work_set_sha256()
        || verified_runtime_batch.expected_work_item_count()
            != challenge_binding.expected_work_item_count()
        || verified_runtime_batch.issued_at_unix_seconds()
            != challenge_binding.issued_at_unix_seconds()
        || verified_runtime_batch.expires_at_unix_seconds()
            != challenge_binding.expires_at_unix_seconds()
    {
        return Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
    }
    let request_sha256 = verified_runtime_batch.request_sha256().clone();
    let expected_work_set_sha256 = verified_runtime_batch.expected_work_set_sha256().clone();
    let expected_work_item_count = verified_runtime_batch.expected_work_item_count();
    let expected_work_item_ids = verified_runtime_batch.expected_work_item_ids().to_vec();
    let provider = verified_runtime_batch.provider();
    let model_identity_sha256 = verified_runtime_batch.model_identity_sha256().clone();
    let model_identity_posture = verified_runtime_batch.model_identity_posture().clone();
    let runtime_challenge_issued_at_unix_seconds = verified_runtime_batch.issued_at_unix_seconds();
    let runtime_challenge_expires_at_unix_seconds =
        verified_runtime_batch.expires_at_unix_seconds();
    let runtime_started_at_unix_millis = verified_runtime_batch.started_at_unix_millis();
    let runtime_finished_at_unix_millis = verified_runtime_batch.finished_at_unix_millis();
    let runtime_coverage_complete = verified_runtime_batch.coverage_complete();
    let runtime_batch_sha256 = verified_runtime_batch.runtime_batch_sha256().clone();
    let mut provider_outputs = Vec::with_capacity(verified_runtime_batch.rows().len());
    let mut runtime_rows = Vec::with_capacity(verified_runtime_batch.rows().len());
    for row in verified_runtime_batch.into_rows() {
        let work_item_id = row.work_item_id().clone();
        let state = row.state();
        let failure_reason = row.failure_reason();
        let output_channel_isolation = row.output_channel_isolation();
        let output_no_truncation_verified = row.output_no_truncation_verified();
        let row_sha256 = row.row_sha256().clone();
        let (provider_output, _receipt, provider_output_bytes, receipt_canonical_json) =
            row.into_parts();
        provider_outputs.push(provider_output);
        runtime_rows.push(RestrictedHostedRuntimeRowMaterialV3 {
            work_item_id,
            state,
            failure_reason,
            output_channel_isolation,
            output_no_truncation_verified,
            provider_output_bytes,
            receipt_canonical_json,
            row_sha256,
        });
    }
    let run_started_at_unix_seconds = runtime_started_at_unix_millis / 1_000;
    let run_finished_at_unix_seconds = runtime_finished_at_unix_millis / 1_000;
    Ok(RestrictedHostedArtifactReviewEvidenceMaterialV2 {
        authority_id: challenge.authority_id().clone(),
        binding: HostedProviderEvidenceExecutionBindingV2 {
            challenge_id: challenge.challenge_id().to_string(),
            evidence_id: challenge_binding.evidence_id().to_string(),
            run_id: challenge_binding.run_id().to_string(),
            challenge_binding_sha256: expected_challenge_binding_sha256,
        },
        request_sha256,
        expected_work_set_sha256,
        expected_work_item_count,
        expected_work_item_ids,
        provider,
        model_identity_sha256,
        model_identity_posture,
        runtime_challenge_issued_at_unix_seconds,
        runtime_challenge_expires_at_unix_seconds,
        runtime_started_at_unix_millis,
        runtime_finished_at_unix_millis,
        runtime_coverage_complete,
        runtime_batch_sha256,
        run_started_at_unix_seconds,
        run_finished_at_unix_seconds,
        evidence_issued_at_unix_seconds,
        evidence_expires_at_unix_seconds,
        provider_outputs,
        runtime_rows,
        aggregate_manifest: Vec::new(),
        normalized_result: Vec::new(),
    })
}

fn validate_hosted_material_context_v2(
    context: &ArtifactReviewEvidenceRunContextV2,
    material: &RestrictedHostedArtifactReviewEvidenceMaterialV2,
) -> Result<(), ArtifactReviewAuthErrorV2> {
    let challenge = context.challenge();
    let binding = challenge.binding();
    let expected_challenge_binding_sha256 = challenge.canonical_binding_sha256_v2()?;
    if material.authority_id != *challenge.authority_id()
        || material.binding.challenge_id != challenge.challenge_id()
        || material.binding.evidence_id != binding.evidence_id()
        || material.binding.run_id != binding.run_id()
        || material.binding.challenge_binding_sha256 != expected_challenge_binding_sha256
        || material.request_sha256 != *binding.request_sha256()
        || material.expected_work_set_sha256 != *binding.expected_work_set_sha256()
        || material.expected_work_item_count != binding.expected_work_item_count()
        || material.runtime_challenge_issued_at_unix_seconds != binding.issued_at_unix_seconds()
        || material.runtime_challenge_expires_at_unix_seconds != binding.expires_at_unix_seconds()
    {
        return Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
    }
    let runtime_challenge_start_millis = material
        .runtime_challenge_issued_at_unix_seconds
        .checked_mul(1_000)
        .ok_or(ArtifactReviewAuthErrorV2::FreshnessInvalid)?;
    let runtime_challenge_finish_millis_exclusive = material
        .runtime_challenge_expires_at_unix_seconds
        .checked_mul(1_000)
        .ok_or(ArtifactReviewAuthErrorV2::FreshnessInvalid)?;
    if material.runtime_started_at_unix_millis < runtime_challenge_start_millis
        || material.runtime_started_at_unix_millis > material.runtime_finished_at_unix_millis
        || material.runtime_finished_at_unix_millis >= runtime_challenge_finish_millis_exclusive
        || material.run_started_at_unix_seconds != material.runtime_started_at_unix_millis / 1_000
        || material.run_finished_at_unix_seconds != material.runtime_finished_at_unix_millis / 1_000
        || binding.issued_at_unix_seconds() > material.run_started_at_unix_seconds
        || material.run_started_at_unix_seconds > material.run_finished_at_unix_seconds
        || material.run_finished_at_unix_seconds > material.evidence_issued_at_unix_seconds
        || material.evidence_issued_at_unix_seconds >= material.evidence_expires_at_unix_seconds
        || material.evidence_expires_at_unix_seconds > binding.expires_at_unix_seconds()
        || material.evidence_expires_at_unix_seconds - material.evidence_issued_at_unix_seconds
            != context.evidence_ttl_seconds()
    {
        return Err(ArtifactReviewAuthErrorV2::FreshnessInvalid);
    }
    Ok(())
}

struct ReconstructedHostedEvidenceV2 {
    normalization: ArtifactReviewAdapterNormalizationV2,
    aggregate_manifest: Vec<u8>,
    current_positive_finding_ids: Vec<Sha256Digest>,
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: Vec<String>,
}

fn validate_restricted_hosted_runtime_batch_v3(
    request: &ArtifactReviewRequestV2,
    material: &RestrictedHostedArtifactReviewEvidenceMaterialV2,
) -> Result<(), ArtifactReviewAuthErrorV2> {
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let expected_work_set_sha256 = hosted_expected_work_set_sha256_v3(request)
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    let expected_work_item_ids = request
        .work_items()
        .iter()
        .map(|item| item.work_item_id().clone())
        .collect::<Vec<_>>();
    if material.request_sha256 != request_sha256
        || material.expected_work_set_sha256 != expected_work_set_sha256
        || usize::try_from(material.expected_work_item_count).ok()
            != Some(request.work_items().len())
        || material.expected_work_item_ids != expected_work_item_ids
        || hosted_cli_provider_identity_v2(material.provider) != *request.provider()
        || material.model_identity_sha256 != request.model().identity_sha256()
        || &material.model_identity_posture != request.model().identity_posture()
        || material.provider_outputs.len() != material.runtime_rows.len()
        || material.provider_outputs.is_empty()
        || material.runtime_coverage_complete
            != (request.coverage().completeness() == ArtifactReviewCoverageCompletenessV2::Complete
                && material.runtime_rows.iter().all(|row| {
                    row.state == VerifiedHostedRuntimeRowStateV3::Complete
                        && row.failure_reason.is_none()
                }))
    {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }

    let mut row_sha256s = Vec::with_capacity(material.runtime_rows.len());
    for ((expected_work_item_id, output), row) in expected_work_item_ids
        .iter()
        .zip(&material.provider_outputs)
        .zip(&material.runtime_rows)
    {
        if output.work_item_id() != expected_work_item_id
            || row.work_item_id != *expected_work_item_id
            || output.captured_output_sha256()
                != Sha256Digest::from_bytes(&row.provider_output_bytes)
            || output.captured_output_len() != row.provider_output_bytes.len()
            || row.output_channel_isolation
                != match material.provider {
                    ArtifactAiProviderKindV2::Claude => {
                        ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted
                    }
                    ArtifactAiProviderKindV2::Codex => {
                        ArtifactReviewChannelIsolationV2::CollapsedPrompt
                    }
                }
            || (output.status() == ArtifactReviewWorkItemStatusV2::Completed
                && !row.output_no_truncation_verified)
            || (output.status() == ArtifactReviewWorkItemStatusV2::Truncated
                && row.output_no_truncation_verified)
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        let recomputed =
            recompute_verified_hosted_runtime_row_sha256_v3(&HostedRuntimeRowBindingInputV3 {
                work_item_id: &row.work_item_id,
                state: row.state,
                failure_reason: row.failure_reason,
                output_status: output.status(),
                output_channel_isolation: row.output_channel_isolation,
                output_no_truncation_verified: row.output_no_truncation_verified,
                provider_output_bytes: &row.provider_output_bytes,
                receipt_canonical_json: &row.receipt_canonical_json,
            })
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
        if recomputed != row.row_sha256 {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        row_sha256s.push(recomputed);
    }

    let recomputed_batch =
        recompute_verified_hosted_runtime_batch_sha256_v3(&HostedRuntimeBatchBindingInputV3 {
            authority_id: material.authority_id.as_str(),
            challenge_id: &material.binding.challenge_id,
            evidence_id: &material.binding.evidence_id,
            run_id: &material.binding.run_id,
            challenge_binding_sha256: &material.binding.challenge_binding_sha256,
            request_sha256: &material.request_sha256,
            expected_work_set_sha256: &material.expected_work_set_sha256,
            expected_work_item_count: material.expected_work_item_count,
            expected_work_item_ids: &material.expected_work_item_ids,
            provider: material.provider,
            model_identity_sha256: &material.model_identity_sha256,
            model_identity_posture: &material.model_identity_posture,
            issued_at_unix_seconds: material.runtime_challenge_issued_at_unix_seconds,
            expires_at_unix_seconds: material.runtime_challenge_expires_at_unix_seconds,
            started_at_unix_millis: material.runtime_started_at_unix_millis,
            finished_at_unix_millis: material.runtime_finished_at_unix_millis,
            coverage_complete: material.runtime_coverage_complete,
            row_sha256s: &row_sha256s,
        })
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    if recomputed_batch != material.runtime_batch_sha256 {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }
    Ok(())
}

fn reconstruct_hosted_evidence_v2(
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    material: &RestrictedHostedArtifactReviewEvidenceMaterialV2,
) -> Result<ReconstructedHostedEvidenceV2, ArtifactReviewAuthErrorV2> {
    request
        .validate(subject, artifact, analysis)
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    validate_restricted_hosted_runtime_batch_v3(request, material)?;
    if request.privacy_posture() != ArtifactReviewPrivacyPostureV2::ApprovedHosted
        || !matches!(
            request.model().identity_posture(),
            ArtifactReviewModelIdentityPostureV2::ProviderHostedOpaqueVersion
        )
        || material.provider_outputs.len() != request.work_items().len()
        || material.runtime_rows.len() != request.work_items().len()
    {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }

    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let expected = request
        .work_items()
        .iter()
        .map(|item| (item.work_item_id().clone(), item))
        .collect::<BTreeMap<_, _>>();
    let mut observed = BTreeSet::new();
    let mut receipt_wires = Vec::with_capacity(material.provider_outputs.len());
    for (output, runtime_row) in material.provider_outputs.iter().zip(&material.runtime_rows) {
        if output.work_item_id() != &runtime_row.work_item_id
            || !observed.insert(output.work_item_id().clone())
            || !expected.contains_key(output.work_item_id())
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        let receipt = decode_hosted_receipt_v2(&runtime_row.receipt_canonical_json)?;
        validate_hosted_receipt_v2(
            request,
            artifact,
            &request_sha256,
            output,
            &receipt,
            material.run_started_at_unix_seconds,
            material.run_finished_at_unix_seconds,
        )?;
        if !hosted_runtime_row_claim_is_coherent_v3(runtime_row, output, &receipt) {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        let receipt_projection =
            hosted_receipt_no_numbers_projection_v3(&runtime_row.receipt_canonical_json)?;
        receipt_wires.push(HostedInvocationManifestWireV2 {
            runtime_row_sha256: runtime_row.row_sha256.clone(),
            runtime_row_state: hosted_runtime_row_state_wire_v3(runtime_row.state).to_string(),
            runtime_failure_reason: hosted_runtime_row_failure_wire_v3(runtime_row.failure_reason)
                .to_string(),
            receipt_sha256: Sha256Digest::from_bytes(&runtime_row.receipt_canonical_json),
            receipt_byte_len: runtime_row.receipt_canonical_json.len().to_string(),
            receipt_projection,
            validated_receipt: receipt,
            normalized_provider_output_status: work_item_status_wire_v2(output.status())
                .to_string(),
            normalized_provider_output_sha256: output.captured_output_sha256(),
            normalized_provider_output_byte_len: output.captured_output_len().to_string(),
        });
    }
    if observed != expected.keys().cloned().collect::<BTreeSet<_>>() {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }
    receipt_wires.sort_by(|left, right| {
        left.validated_receipt
            .work_item_id
            .cmp(&right.validated_receipt.work_item_id)
    });

    let normalization = normalize_artifact_review_provider_outputs_v2(
        subject,
        artifact,
        analysis,
        request,
        &material.provider_outputs,
    )
    .map_err(|_| ArtifactReviewAuthErrorV2::NormalizationFailed)?;
    for invocation in &receipt_wires {
        if invocation.validated_receipt.status != ArtifactAiExecutionStatusV2::Completed {
            let output = material
                .provider_outputs
                .iter()
                .find(|output| output.work_item_id() == &invocation.validated_receipt.work_item_id)
                .ok_or(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
            if output.status() == ArtifactReviewWorkItemStatusV2::Completed
                && !normalization
                    .structurally_validated_result()
                    .findings()
                    .iter()
                    .any(|finding| {
                        finding.work_item_id() == &invocation.validated_receipt.work_item_id
                    })
            {
                return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
            }
        }
    }
    let mut current_positive_finding_ids = BTreeSet::new();
    for finding in normalization.structurally_validated_result().findings() {
        if finding.behavior_gate_eligible() {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        current_positive_finding_ids.insert(finding.finding_id_sha256().clone());
    }
    let current_positive_finding_ids = current_positive_finding_ids.into_iter().collect::<Vec<_>>();
    let limitations = derive_hosted_limitations_v2(request, &receipt_wires, &normalization);
    // Opaque hosted model content and provider execution make this incomplete
    // even when every planned work item produced a syntactically valid result.
    let completeness = ArtifactReviewEvidenceCompletenessV2::Incomplete;
    let aggregate_manifest = build_hosted_aggregate_manifest_v2(
        request,
        material,
        &receipt_wires,
        &normalization,
        &current_positive_finding_ids,
        completeness,
        &limitations,
    )?;
    Ok(ReconstructedHostedEvidenceV2 {
        normalization,
        aggregate_manifest,
        current_positive_finding_ids,
        completeness,
        limitations,
    })
}

fn validate_hosted_receipt_v2(
    request: &ArtifactReviewRequestV2,
    artifact: &NormalizedArtifact,
    request_sha256: &Sha256Digest,
    output: &ArtifactReviewProviderOutputV2,
    receipt: &HostedProviderReceiptWireV2,
    run_started_at_unix_seconds: u64,
    run_finished_at_unix_seconds: u64,
) -> Result<(), ArtifactReviewAuthErrorV2> {
    let expected_provider = hosted_cli_provider_identity_v2(receipt.provider);
    let expected_transport = match receipt.provider {
        ArtifactAiProviderKindV2::Claude => ArtifactAiProviderTransportV2::ClaudeCodePrintCliV1,
        ArtifactAiProviderKindV2::Codex => ArtifactAiProviderTransportV2::CodexExecCliV1,
    };
    let expected_auth = match receipt.provider {
        ArtifactAiProviderKindV2::Claude => ArtifactAiAuthenticationModeV2::ClaudeSubscription,
        ArtifactAiProviderKindV2::Codex => ArtifactAiAuthenticationModeV2::ChatGptSubscription,
    };
    let expected_read_only_sandbox = match receipt.provider {
        ArtifactAiProviderKindV2::Claude => ArtifactAiControlPostureV2::NotEstablished,
        ArtifactAiProviderKindV2::Codex => {
            ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        }
    };
    let invocation_sha256 = request
        .invocation_sha256(output.work_item_id())
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    let invocation = request
        .invocation(artifact, output.work_item_id())
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    let provider_input = invocation
        .canonical_provider_input_json_v2()
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    let output_sha256 = output.captured_output_sha256();
    let output_byte_len = output.captured_output_len() as u64;
    let observed_model_matches = match &receipt.observed_model {
        ArtifactAiObservedModelV2::Unavailable => true,
        ArtifactAiObservedModelV2::Present { model_id } => model_id == &receipt.requested_model,
    };
    let observed_elapsed_millis = receipt
        .finished_at_unix_millis
        .checked_sub(receipt.started_at_unix_millis)
        .ok_or(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    let run_start_millis = run_started_at_unix_seconds
        .checked_mul(1_000)
        .ok_or(ArtifactReviewAuthErrorV2::FreshnessInvalid)?;
    let run_finish_millis_exclusive = run_finished_at_unix_seconds
        .checked_add(1)
        .and_then(|value| value.checked_mul(1_000))
        .ok_or(ArtifactReviewAuthErrorV2::FreshnessInvalid)?;
    if receipt.schema_version != ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V2
        || request.provider() != &expected_provider
        || receipt.transport != expected_transport
        || receipt.authentication_mode != expected_auth
        || receipt.client_version.is_empty()
        || receipt.client_version.len() > 512
        || receipt.request_sha256 != *request_sha256
        || receipt.work_item_id != *output.work_item_id()
        || receipt.invocation_sha256 != invocation_sha256
        || receipt.provider_adapter_sha256 != request.provider().adapter_sha256
        || receipt.model_identity_sha256 != request.model().identity_sha256()
        || &receipt.model_identity_posture != request.model().identity_posture()
        || receipt.requested_model != request.model().model_id
        || receipt.prompt_template_sha256 != request.prompt().template_sha256
        || receipt.model_output_schema_sha256 != *request.model_output_schema_sha256()
        || receipt.provider_input_sha256 != Sha256Digest::from_bytes(&provider_input)
        || receipt.provider_input_byte_len != provider_input.len() as u64
        || receipt.trusted_instruction_sha256
            != Sha256Digest::from_bytes(
                whoathere_detector::artifact_review_system_prompt_v2().as_bytes(),
            )
        || !hosted_receipt_output_row_is_coherent_v3(
            receipt,
            output,
            &output_sha256,
            output_byte_len,
        )
        || !observed_model_matches
        || receipt.started_at_unix_millis < run_start_millis
        || receipt.started_at_unix_millis > receipt.finished_at_unix_millis
        || receipt.finished_at_unix_millis >= run_finish_millis_exclusive
        || receipt.elapsed_millis != observed_elapsed_millis
        || receipt.available_inference_controls.requested_model_control
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt
            .available_inference_controls
            .strict_output_schema_control
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt.available_inference_controls.tools_disabled_control
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt
            .available_inference_controls
            .web_search_disabled_control
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt
            .available_inference_controls
            .session_persistence_disabled_control
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt
            .available_inference_controls
            .user_customizations_disabled_control
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt
            .available_inference_controls
            .read_only_sandbox_control
            != expected_read_only_sandbox
        || receipt.available_inference_controls.memory_disabled_control
            != ArtifactAiControlPostureV2::NotEstablished
        || !receipt.strict_output_schema_requested
        || !receipt.api_key_environment_stripped
        || !receipt.empty_working_directory_before_verified
        || !receipt.empty_working_directory_after_verified
        || receipt.authentication_home_isolation_posture != ArtifactAiControlPostureV2::HostVerified
        || receipt.empty_working_directory_posture != ArtifactAiControlPostureV2::HostVerified
        || receipt.customizations_disabled_posture
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt.model_tools_disabled_posture
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt.model_web_access_disabled_posture
            != ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
        || receipt.host_filesystem_isolation_posture != ArtifactAiControlPostureV2::NotEstablished
        || receipt.provider_control_plane_isolation_posture
            != ArtifactAiControlPostureV2::ProviderHostedOpaque
        || receipt.detached_descendant_containment_posture
            != ArtifactAiControlPostureV2::NotEstablished
        || receipt.package_artifact_path_exposed
        || receipt.package_code_executed
        || !receipt.process_group_cleanup_verified
        || !receipt.run_directory_cleanup_verified
        || receipt.client_executable_posture != ArtifactAiControlPostureV2::HostVerified
        || (receipt.status == ArtifactAiExecutionStatusV2::Completed
            && (!receipt.stdin_write_complete
                || !receipt.stdout_eof_verified
                || !receipt.stderr_eof_verified
                || receipt.pipe_drain_timed_out))
        || (receipt.status == ArtifactAiExecutionStatusV2::OutputCaptureIncomplete
            && receipt.stdin_write_complete
            && receipt.stdout_eof_verified
            && receipt.stderr_eof_verified
            && !receipt.pipe_drain_timed_out)
    {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }
    Ok(())
}

fn hosted_receipt_output_row_is_coherent_v3(
    receipt: &HostedProviderReceiptWireV2,
    output: &ArtifactReviewProviderOutputV2,
    output_sha256: &Sha256Digest,
    output_byte_len: u64,
) -> bool {
    let status_can_be_authenticated_incomplete = matches!(
        receipt.status,
        ArtifactAiExecutionStatusV2::ClientNonZeroExit
            | ArtifactAiExecutionStatusV2::TimedOut
            | ArtifactAiExecutionStatusV2::Cancelled
            | ArtifactAiExecutionStatusV2::StdoutLimitExceeded
            | ArtifactAiExecutionStatusV2::StderrLimitExceeded
            | ArtifactAiExecutionStatusV2::OutputCaptureIncomplete
            | ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid
    );
    if receipt.status != ArtifactAiExecutionStatusV2::Completed
        && !status_can_be_authenticated_incomplete
    {
        return false;
    }
    let model_output_binding = match (
        receipt.model_output_sha256.as_ref(),
        receipt.model_output_byte_len,
    ) {
        (Some(model_output_sha256), Some(model_output_byte_len)) => {
            Some((model_output_sha256, model_output_byte_len))
        }
        (None, None) => None,
        _ => return false,
    };
    match output.status() {
        ArtifactReviewWorkItemStatusV2::Completed => {
            model_output_binding.is_some_and(|(model_output_sha256, model_output_byte_len)| {
                output_byte_len > 0
                    && model_output_sha256 == output_sha256
                    && model_output_byte_len == output_byte_len
            })
        }
        ArtifactReviewWorkItemStatusV2::Truncated => {
            output_byte_len == 0
                && receipt.status == ArtifactAiExecutionStatusV2::StdoutLimitExceeded
        }
        ArtifactReviewWorkItemStatusV2::Failed => {
            output_byte_len == 0
                && status_can_be_authenticated_incomplete
                && receipt.status != ArtifactAiExecutionStatusV2::StdoutLimitExceeded
        }
    }
}

fn hosted_runtime_row_claim_is_coherent_v3(
    runtime_row: &RestrictedHostedRuntimeRowMaterialV3,
    output: &ArtifactReviewProviderOutputV2,
    receipt: &HostedProviderReceiptWireV2,
) -> bool {
    let expected_failure_reason = match receipt.status {
        ArtifactAiExecutionStatusV2::Completed => None,
        ArtifactAiExecutionStatusV2::ClientNonZeroExit => {
            Some(HostedRuntimeRowFailureV3::ClientNonZeroExit)
        }
        ArtifactAiExecutionStatusV2::TimedOut => Some(HostedRuntimeRowFailureV3::TimedOut),
        ArtifactAiExecutionStatusV2::Cancelled => Some(HostedRuntimeRowFailureV3::Cancelled),
        ArtifactAiExecutionStatusV2::StdoutLimitExceeded => {
            Some(HostedRuntimeRowFailureV3::StdoutLimitExceeded)
        }
        ArtifactAiExecutionStatusV2::StderrLimitExceeded => {
            Some(HostedRuntimeRowFailureV3::StderrLimitExceeded)
        }
        ArtifactAiExecutionStatusV2::OutputCaptureIncomplete => {
            Some(HostedRuntimeRowFailureV3::OutputCaptureIncomplete)
        }
        ArtifactAiExecutionStatusV2::ProcessCleanupFailed => {
            Some(HostedRuntimeRowFailureV3::ProcessCleanupFailed)
        }
        ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid => {
            Some(HostedRuntimeRowFailureV3::OutputEnvelopeInvalid)
        }
        ArtifactAiExecutionStatusV2::ClientIdentityChanged => {
            Some(HostedRuntimeRowFailureV3::ClientIdentityChanged)
        }
        ArtifactAiExecutionStatusV2::IsolationCheckFailed => {
            Some(HostedRuntimeRowFailureV3::IsolationCheckFailed)
        }
        ArtifactAiExecutionStatusV2::AuthenticationContinuityFailed => {
            Some(HostedRuntimeRowFailureV3::AuthenticationContinuityFailed)
        }
        ArtifactAiExecutionStatusV2::ObservedModelMismatch => {
            Some(HostedRuntimeRowFailureV3::ObservedModelMismatch)
        }
        ArtifactAiExecutionStatusV2::PostExecutionVerificationFailed => {
            Some(HostedRuntimeRowFailureV3::PostExecutionVerificationFailed)
        }
    };
    if runtime_row.failure_reason != expected_failure_reason {
        return false;
    }
    matches!(
        (runtime_row.state, output.status(), receipt.status),
        (
            VerifiedHostedRuntimeRowStateV3::Complete,
            ArtifactReviewWorkItemStatusV2::Completed,
            ArtifactAiExecutionStatusV2::Completed
        ) | (
            VerifiedHostedRuntimeRowStateV3::IncompletePositive,
            ArtifactReviewWorkItemStatusV2::Completed,
            ArtifactAiExecutionStatusV2::ClientNonZeroExit
                | ArtifactAiExecutionStatusV2::TimedOut
                | ArtifactAiExecutionStatusV2::Cancelled
                | ArtifactAiExecutionStatusV2::StderrLimitExceeded
                | ArtifactAiExecutionStatusV2::OutputCaptureIncomplete
                | ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid
        ) | (
            VerifiedHostedRuntimeRowStateV3::Truncated,
            ArtifactReviewWorkItemStatusV2::Truncated,
            ArtifactAiExecutionStatusV2::StdoutLimitExceeded
        ) | (
            VerifiedHostedRuntimeRowStateV3::Failed,
            ArtifactReviewWorkItemStatusV2::Failed,
            ArtifactAiExecutionStatusV2::ClientNonZeroExit
                | ArtifactAiExecutionStatusV2::TimedOut
                | ArtifactAiExecutionStatusV2::Cancelled
                | ArtifactAiExecutionStatusV2::StderrLimitExceeded
                | ArtifactAiExecutionStatusV2::OutputCaptureIncomplete
                | ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid
        )
    )
}

fn derive_hosted_limitations_v2(
    request: &ArtifactReviewRequestV2,
    receipts: &[HostedInvocationManifestWireV2],
    normalization: &ArtifactReviewAdapterNormalizationV2,
) -> Vec<String> {
    let mut limitations = BTreeSet::from([
        "artifact_review_ai_findings_not_behavior_gate_eligible".to_string(),
        "control_plane_build_identity_not_independently_measured".to_string(),
        "host_signer_attests_adapter_observations_only".to_string(),
        "hosted_provider_auth_mode_host_observed_not_provider_attested".to_string(),
        "hosted_provider_control_plane_network_not_detonation_traffic".to_string(),
        "hosted_provider_internal_execution_not_attested".to_string(),
        "hosted_provider_model_content_not_measured".to_string(),
        "normalizer_identity_is_contract_digest_not_binary_measurement".to_string(),
        "runtime_identity_is_contract_digest_not_binary_measurement".to_string(),
    ]);
    if request.coverage().completeness() != ArtifactReviewCoverageCompletenessV2::Complete
        || !request.coverage().limitations().is_empty()
    {
        limitations.insert("artifact_review_coverage_incomplete".to_string());
    }
    for invocation in receipts {
        if invocation.validated_receipt.status != ArtifactAiExecutionStatusV2::Completed {
            limitations.insert(
                hosted_execution_status_limitation_v3(invocation.validated_receipt.status)
                    .to_string(),
            );
        }
        if invocation
            .validated_receipt
            .post_auth_observation_sha256
            .is_none()
        {
            limitations.insert("hosted_provider_post_auth_observation_unavailable".to_string());
        }
        match &invocation.validated_receipt.observed_model {
            ArtifactAiObservedModelV2::Unavailable => {
                limitations.insert("hosted_provider_observed_model_unavailable".to_string());
            }
            ArtifactAiObservedModelV2::Present { model_id }
                if model_id != &invocation.validated_receipt.requested_model =>
            {
                limitations.insert("hosted_provider_observed_model_mismatch".to_string());
            }
            ArtifactAiObservedModelV2::Present { .. } => {}
        }
        if invocation
            .validated_receipt
            .available_inference_controls
            .seed_control_exposed
            || invocation
                .validated_receipt
                .available_inference_controls
                .temperature_control_exposed
            || invocation
                .validated_receipt
                .available_inference_controls
                .top_p_control_exposed
        {
            // Availability is recorded, but a hosted model remains opaque.
        } else {
            limitations.insert("hosted_provider_inference_controls_partial".to_string());
        }
    }
    if !normalization.missing_work_item_ids().is_empty() {
        limitations.insert("artifact_review_normalizer_missing_work_items".to_string());
    }
    for outcome in normalization.outcomes() {
        if outcome.status() != ArtifactReviewWorkItemNormalizationStatusV2::Normalized {
            limitations.insert(outcome.status().reason_code().to_string());
        }
        for reason in outcome.rejection_reasons() {
            limitations.insert(reason.reason_code().to_string());
        }
    }
    if normalization
        .structurally_validated_result()
        .findings()
        .is_empty()
    {
        limitations.insert("hosted_ai_no_finding_has_no_admission_authority".to_string());
    }
    limitations.into_iter().collect()
}

fn build_hosted_statement_v2(
    request: &ArtifactReviewRequestV2,
    context: &ArtifactReviewEvidenceRunContextV2,
    material: &RestrictedHostedArtifactReviewEvidenceMaterialV2,
    reconstructed: &ReconstructedHostedEvidenceV2,
    cumulative_positive_finding_ids: Vec<Sha256Digest>,
) -> Result<ArtifactReviewEvidenceStatementV2, ArtifactReviewAuthErrorV2> {
    let normalized = reconstructed.normalization.adapter_normalized_output();
    ArtifactReviewEvidenceStatementV2::new(ArtifactReviewEvidenceStatementDraftV2 {
        challenge: context.challenge().clone(),
        challenge_binding_sha256: material.binding.challenge_binding_sha256.clone(),
        runtime_execution_binding_sha256: hosted_provider_evidence_execution_binding_sha256_v2(
            &material.authority_id,
            &material.binding.challenge_id,
            &material.binding.evidence_id,
            &material.binding.run_id,
            &material.binding.challenge_binding_sha256,
        )?,
        run_started_at_unix_seconds: material.run_started_at_unix_seconds,
        run_finished_at_unix_seconds: material.run_finished_at_unix_seconds,
        evidence_issued_at_unix_seconds: material.evidence_issued_at_unix_seconds,
        evidence_expires_at_unix_seconds: material.evidence_expires_at_unix_seconds,
        deterministic_analysis_sha256: request.deterministic_analysis_sha256().clone(),
        coverage_manifest_sha256: request.coverage_manifest_sha256().clone(),
        provider_adapter_sha256: request.provider().adapter_sha256.clone(),
        model_identity_sha256: request.model().identity_sha256(),
        model_identity_posture:
            ArtifactReviewEvidenceModelIdentityPostureV2::ProviderHostedOpaqueVersion,
        prompt_template_sha256: request.prompt().template_sha256.clone(),
        model_output_schema_sha256: request.model_output_schema_sha256().clone(),
        adapter_result_schema_sha256: request.adapter_result_schema_sha256().clone(),
        declared_control_plane_build_sha256: context.declared_control_plane_build_sha256().clone(),
        runtime_contract_sha256: hosted_artifact_review_runtime_contract_sha256_v2(),
        normalizer_contract_sha256: crate::local_artifact_review_normalizer_contract_sha256_v2(),
        aggregate_manifest_sha256: Sha256Digest::from_bytes(&reconstructed.aggregate_manifest),
        aggregate_manifest_byte_len: reconstructed.aggregate_manifest.len() as u64,
        normalized_result_sha256: Sha256Digest::from_bytes(normalized),
        normalized_result_byte_len: normalized.len() as u64,
        execution_claims_sha256: reconstructed
            .normalization
            .execution_report()
            .execution_claims_sha256()
            .clone(),
        current_positive_finding_ids: reconstructed.current_positive_finding_ids.clone(),
        cumulative_positive_finding_ids,
        completeness: reconstructed.completeness,
        limitations: reconstructed.limitations.clone(),
    })
}

fn build_hosted_aggregate_manifest_v2(
    request: &ArtifactReviewRequestV2,
    material: &RestrictedHostedArtifactReviewEvidenceMaterialV2,
    receipts: &[HostedInvocationManifestWireV2],
    normalization: &ArtifactReviewAdapterNormalizationV2,
    current_positive_finding_ids: &[Sha256Digest],
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: &[String],
) -> Result<Vec<u8>, ArtifactReviewAuthErrorV2> {
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let runtime_execution_binding_sha256 = hosted_provider_evidence_execution_binding_sha256_v2(
        &material.authority_id,
        &material.binding.challenge_id,
        &material.binding.evidence_id,
        &material.binding.run_id,
        &material.binding.challenge_binding_sha256,
    )?;
    let normalization_outcomes = normalization
        .outcomes()
        .iter()
        .map(|outcome| HostedNormalizationOutcomeWireV2 {
            work_item_id: outcome.work_item_id().clone(),
            provider_output_capture_sha256: outcome.provider_output_capture_sha256().clone(),
            provider_output_capture_byte_len: outcome
                .provider_output_capture_byte_len()
                .to_string(),
            status: outcome.status().reason_code().to_string(),
            declared_finding_count: outcome.declared_finding_count().to_string(),
            structurally_valid_finding_count: outcome
                .structurally_valid_finding_count()
                .to_string(),
            retained_finding_count: outcome.retained_finding_count().to_string(),
            deduplicated_finding_count: outcome.deduplicated_finding_count().to_string(),
            rejected_finding_count: outcome.rejected_finding_count().to_string(),
            rejection_reasons: outcome
                .rejection_reasons()
                .iter()
                .map(|reason| reason.reason_code().to_string())
                .collect(),
        })
        .collect();
    let finding_references = normalization
        .structurally_validated_result()
        .findings()
        .iter()
        .map(|finding| HostedFindingReferenceWireV2 {
            finding_id_sha256: finding.finding_id_sha256().clone(),
            evidence_provenance_sha256: finding.evidence_sha256().clone(),
            behavior_gate_eligible: finding.behavior_gate_eligible(),
        })
        .collect();
    let wire = HostedAggregateManifestWireV2 {
        schema_version: HOSTED_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_SCHEMA_V2.to_string(),
        canonicalization: crate::ARTIFACT_REVIEW_EVIDENCE_CANONICALIZATION_V2.to_string(),
        hosted_receipt_projection: HOSTED_ARTIFACT_REVIEW_RECEIPT_PROJECTION_V3.to_string(),
        signer_attestation_scope: "host_observed_adapter_evidence_only".to_string(),
        admission_authority: "none".to_string(),
        authority_id: material.authority_id.as_str().to_string(),
        challenge_id: material.binding.challenge_id.clone(),
        evidence_id: material.binding.evidence_id.clone(),
        run_id: material.binding.run_id.clone(),
        challenge_binding_sha256: material.binding.challenge_binding_sha256.clone(),
        runtime_execution_binding_sha256,
        runtime_batch_schema: VERIFIED_HOSTED_RUNTIME_BATCH_SCHEMA_V3.to_string(),
        runtime_row_schema: VERIFIED_HOSTED_RUNTIME_ROW_SCHEMA_V3.to_string(),
        runtime_batch_sha256: material.runtime_batch_sha256.clone(),
        runtime_expected_work_set_sha256: material.expected_work_set_sha256.clone(),
        runtime_expected_work_item_count: material.expected_work_item_count.to_string(),
        runtime_expected_work_item_ids: material.expected_work_item_ids.clone(),
        runtime_provider: hosted_provider_kind_wire_v3(material.provider).to_string(),
        runtime_model_identity_sha256: material.model_identity_sha256.clone(),
        runtime_model_identity_posture: model_identity_posture_wire_v3(
            &material.model_identity_posture,
        )
        .to_string(),
        runtime_challenge_issued_at_unix_seconds: material
            .runtime_challenge_issued_at_unix_seconds
            .to_string(),
        runtime_challenge_expires_at_unix_seconds: material
            .runtime_challenge_expires_at_unix_seconds
            .to_string(),
        runtime_started_at_unix_millis: material.runtime_started_at_unix_millis.to_string(),
        runtime_finished_at_unix_millis: material.runtime_finished_at_unix_millis.to_string(),
        runtime_coverage_complete: material.runtime_coverage_complete,
        run_started_at_unix_seconds: material.run_started_at_unix_seconds.to_string(),
        run_finished_at_unix_seconds: material.run_finished_at_unix_seconds.to_string(),
        evidence_issued_at_unix_seconds: material.evidence_issued_at_unix_seconds.to_string(),
        evidence_expires_at_unix_seconds: material.evidence_expires_at_unix_seconds.to_string(),
        request_sha256,
        expected_work_item_ids: request
            .work_items()
            .iter()
            .map(|item| item.work_item_id().clone())
            .collect(),
        deterministic_analysis_sha256: request.deterministic_analysis_sha256().clone(),
        coverage_manifest_sha256: request.coverage_manifest_sha256().clone(),
        coverage_completeness: match request.coverage().completeness() {
            ArtifactReviewCoverageCompletenessV2::Complete => "complete",
            ArtifactReviewCoverageCompletenessV2::Incomplete => "incomplete",
        }
        .to_string(),
        provider_adapter_sha256: request.provider().adapter_sha256.clone(),
        model_identity_sha256: request.model().identity_sha256(),
        model_identity_posture: model_identity_posture_wire_v3(request.model().identity_posture())
            .to_string(),
        prompt_template_sha256: request.prompt().template_sha256.clone(),
        model_output_schema_sha256: request.model_output_schema_sha256().clone(),
        adapter_result_schema_sha256: request.adapter_result_schema_sha256().clone(),
        receipts: receipts.to_vec(),
        normalization_outcomes,
        missing_work_item_ids: normalization.missing_work_item_ids().to_vec(),
        normalized_result_sha256: Sha256Digest::from_bytes(
            normalization.adapter_normalized_output(),
        ),
        normalized_result_byte_len: normalization.adapter_normalized_output().len().to_string(),
        execution_claims_sha256: normalization
            .execution_report()
            .execution_claims_sha256()
            .clone(),
        verdict: verdict_wire_v2(normalization.structurally_validated_result().verdict())
            .to_string(),
        finding_references,
        current_positive_finding_ids: current_positive_finding_ids.to_vec(),
        completeness,
        limitations: limitations.to_vec(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactReviewAuthErrorV2::Serialization)?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_BYTES_V2 {
        return Err(ArtifactReviewAuthErrorV2::StatementLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostedProviderReceiptWireV2 {
    schema_version: String,
    provider: ArtifactAiProviderKindV2,
    transport: ArtifactAiProviderTransportV2,
    authentication_mode: ArtifactAiAuthenticationModeV2,
    client_version: String,
    client_executable_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    work_item_id: Sha256Digest,
    invocation_sha256: Sha256Digest,
    provider_adapter_sha256: Sha256Digest,
    model_identity_sha256: Sha256Digest,
    model_identity_posture: ArtifactReviewModelIdentityPostureV2,
    requested_model: String,
    observed_model: ArtifactAiObservedModelV2,
    prompt_template_sha256: Sha256Digest,
    model_output_schema_sha256: Sha256Digest,
    provider_input_sha256: Sha256Digest,
    provider_input_byte_len: u64,
    effective_arguments_sha256: Sha256Digest,
    effective_environment_sha256: Sha256Digest,
    trusted_instruction_sha256: Sha256Digest,
    pre_auth_observation_sha256: Sha256Digest,
    post_auth_observation_sha256: Option<Sha256Digest>,
    raw_stdout_sha256: Sha256Digest,
    raw_stdout_byte_len: u64,
    raw_stderr_sha256: Sha256Digest,
    raw_stderr_byte_len: u64,
    model_output_sha256: Option<Sha256Digest>,
    model_output_byte_len: Option<u64>,
    started_at_unix_millis: u64,
    finished_at_unix_millis: u64,
    elapsed_millis: u64,
    status: ArtifactAiExecutionStatusV2,
    available_inference_controls: ArtifactAiAvailableInferenceControlsV2,
    strict_output_schema_requested: bool,
    api_key_environment_stripped: bool,
    empty_working_directory_before_verified: bool,
    empty_working_directory_after_verified: bool,
    authentication_home_isolation_posture: ArtifactAiControlPostureV2,
    empty_working_directory_posture: ArtifactAiControlPostureV2,
    customizations_disabled_posture: ArtifactAiControlPostureV2,
    model_tools_disabled_posture: ArtifactAiControlPostureV2,
    model_web_access_disabled_posture: ArtifactAiControlPostureV2,
    host_filesystem_isolation_posture: ArtifactAiControlPostureV2,
    provider_control_plane_isolation_posture: ArtifactAiControlPostureV2,
    detached_descendant_containment_posture: ArtifactAiControlPostureV2,
    package_artifact_path_exposed: bool,
    package_code_executed: bool,
    stdin_write_complete: bool,
    stdout_eof_verified: bool,
    stderr_eof_verified: bool,
    pipe_drain_timed_out: bool,
    process_group_cleanup_verified: bool,
    run_directory_cleanup_verified: bool,
    client_executable_posture: ArtifactAiControlPostureV2,
}

fn decode_hosted_receipt_v2(
    receipt_canonical_json: &[u8],
) -> Result<HostedProviderReceiptWireV2, ArtifactReviewAuthErrorV2> {
    let mut deserializer = serde_json::Deserializer::from_slice(receipt_canonical_json);
    let decoded = HostedProviderReceiptWireV2::deserialize(&mut deserializer)
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    deserializer
        .end()
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    Ok(decoded)
}

fn hosted_receipt_no_numbers_projection_v3(
    canonical_receipt: &[u8],
) -> Result<serde_json::Value, ArtifactReviewAuthErrorV2> {
    let value: serde_json::Value = serde_json::from_slice(canonical_receipt)
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
    project_json_without_numbers_or_nulls_v3(value)
}

fn project_json_without_numbers_or_nulls_v3(
    value: serde_json::Value,
) -> Result<serde_json::Value, ArtifactReviewAuthErrorV2> {
    match value {
        serde_json::Value::Null => Ok(serde_json::json!({"state": "absent"})),
        serde_json::Value::Bool(_) | serde_json::Value::String(_) => Ok(value),
        serde_json::Value::Number(number) => {
            if !number.is_u64() && !number.is_i64() {
                return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
            }
            Ok(serde_json::Value::String(number.to_string()))
        }
        serde_json::Value::Array(values) => values
            .into_iter()
            .map(project_json_without_numbers_or_nulls_v3)
            .collect::<Result<Vec<_>, _>>()
            .map(serde_json::Value::Array),
        serde_json::Value::Object(entries) => entries
            .into_iter()
            .map(|(key, value)| {
                project_json_without_numbers_or_nulls_v3(value).map(|value| (key, value))
            })
            .collect::<Result<serde_json::Map<_, _>, _>>()
            .map(serde_json::Value::Object),
    }
}

#[derive(Clone, Serialize)]
#[serde(deny_unknown_fields)]
struct HostedInvocationManifestWireV2 {
    runtime_row_sha256: Sha256Digest,
    runtime_row_state: String,
    runtime_failure_reason: String,
    receipt_sha256: Sha256Digest,
    receipt_byte_len: String,
    receipt_projection: serde_json::Value,
    #[serde(skip)]
    validated_receipt: HostedProviderReceiptWireV2,
    normalized_provider_output_status: String,
    normalized_provider_output_sha256: Sha256Digest,
    normalized_provider_output_byte_len: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostedAggregateManifestWireV2 {
    schema_version: String,
    canonicalization: String,
    hosted_receipt_projection: String,
    signer_attestation_scope: String,
    admission_authority: String,
    authority_id: String,
    challenge_id: String,
    evidence_id: String,
    run_id: String,
    challenge_binding_sha256: Sha256Digest,
    runtime_execution_binding_sha256: Sha256Digest,
    runtime_batch_schema: String,
    runtime_row_schema: String,
    runtime_batch_sha256: Sha256Digest,
    runtime_expected_work_set_sha256: Sha256Digest,
    runtime_expected_work_item_count: String,
    runtime_expected_work_item_ids: Vec<Sha256Digest>,
    runtime_provider: String,
    runtime_model_identity_sha256: Sha256Digest,
    runtime_model_identity_posture: String,
    runtime_challenge_issued_at_unix_seconds: String,
    runtime_challenge_expires_at_unix_seconds: String,
    runtime_started_at_unix_millis: String,
    runtime_finished_at_unix_millis: String,
    runtime_coverage_complete: bool,
    run_started_at_unix_seconds: String,
    run_finished_at_unix_seconds: String,
    evidence_issued_at_unix_seconds: String,
    evidence_expires_at_unix_seconds: String,
    request_sha256: Sha256Digest,
    expected_work_item_ids: Vec<Sha256Digest>,
    deterministic_analysis_sha256: Sha256Digest,
    coverage_manifest_sha256: Sha256Digest,
    coverage_completeness: String,
    provider_adapter_sha256: Sha256Digest,
    model_identity_sha256: Sha256Digest,
    model_identity_posture: String,
    prompt_template_sha256: Sha256Digest,
    model_output_schema_sha256: Sha256Digest,
    adapter_result_schema_sha256: Sha256Digest,
    receipts: Vec<HostedInvocationManifestWireV2>,
    normalization_outcomes: Vec<HostedNormalizationOutcomeWireV2>,
    missing_work_item_ids: Vec<Sha256Digest>,
    normalized_result_sha256: Sha256Digest,
    normalized_result_byte_len: String,
    execution_claims_sha256: Sha256Digest,
    verdict: String,
    finding_references: Vec<HostedFindingReferenceWireV2>,
    current_positive_finding_ids: Vec<Sha256Digest>,
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: Vec<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostedNormalizationOutcomeWireV2 {
    work_item_id: Sha256Digest,
    provider_output_capture_sha256: Sha256Digest,
    provider_output_capture_byte_len: String,
    status: String,
    declared_finding_count: String,
    structurally_valid_finding_count: String,
    retained_finding_count: String,
    deduplicated_finding_count: String,
    rejected_finding_count: String,
    rejection_reasons: Vec<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostedFindingReferenceWireV2 {
    finding_id_sha256: Sha256Digest,
    evidence_provenance_sha256: Sha256Digest,
    behavior_gate_eligible: bool,
}

fn work_item_status_wire_v2(status: ArtifactReviewWorkItemStatusV2) -> &'static str {
    match status {
        ArtifactReviewWorkItemStatusV2::Completed => "completed",
        ArtifactReviewWorkItemStatusV2::Failed => "failed",
        ArtifactReviewWorkItemStatusV2::Truncated => "truncated",
    }
}

fn hosted_provider_kind_wire_v3(provider: ArtifactAiProviderKindV2) -> &'static str {
    match provider {
        ArtifactAiProviderKindV2::Claude => "claude",
        ArtifactAiProviderKindV2::Codex => "codex",
    }
}

fn model_identity_posture_wire_v3(posture: &ArtifactReviewModelIdentityPostureV2) -> &'static str {
    match posture {
        ArtifactReviewModelIdentityPostureV2::MeasuredLocalContent { .. } => {
            "measured_local_content"
        }
        ArtifactReviewModelIdentityPostureV2::ProviderHostedOpaqueVersion => {
            "provider_hosted_opaque_version"
        }
    }
}

fn hosted_runtime_row_state_wire_v3(state: VerifiedHostedRuntimeRowStateV3) -> &'static str {
    match state {
        VerifiedHostedRuntimeRowStateV3::Complete => "complete",
        VerifiedHostedRuntimeRowStateV3::IncompletePositive => "incomplete_positive",
        VerifiedHostedRuntimeRowStateV3::Truncated => "truncated",
        VerifiedHostedRuntimeRowStateV3::Failed => "failed",
    }
}

fn hosted_runtime_row_failure_wire_v3(failure: Option<HostedRuntimeRowFailureV3>) -> &'static str {
    match failure {
        None => "none",
        Some(HostedRuntimeRowFailureV3::ClientNonZeroExit) => "client_non_zero_exit",
        Some(HostedRuntimeRowFailureV3::TimedOut) => "timed_out",
        Some(HostedRuntimeRowFailureV3::Cancelled) => "cancelled",
        Some(HostedRuntimeRowFailureV3::StdoutLimitExceeded) => "stdout_limit_exceeded",
        Some(HostedRuntimeRowFailureV3::StderrLimitExceeded) => "stderr_limit_exceeded",
        Some(HostedRuntimeRowFailureV3::OutputCaptureIncomplete) => "output_capture_incomplete",
        Some(HostedRuntimeRowFailureV3::ProcessCleanupFailed) => "process_cleanup_failed",
        Some(HostedRuntimeRowFailureV3::OutputEnvelopeInvalid) => "output_envelope_invalid",
        Some(HostedRuntimeRowFailureV3::ClientIdentityChanged) => "client_identity_changed",
        Some(HostedRuntimeRowFailureV3::IsolationCheckFailed) => "isolation_check_failed",
        Some(HostedRuntimeRowFailureV3::AuthenticationContinuityFailed) => {
            "authentication_continuity_failed"
        }
        Some(HostedRuntimeRowFailureV3::ObservedModelMismatch) => "observed_model_mismatch",
        Some(HostedRuntimeRowFailureV3::PostExecutionVerificationFailed) => {
            "post_execution_verification_failed"
        }
        Some(HostedRuntimeRowFailureV3::InternalOutputStateMismatch) => {
            "internal_output_state_mismatch"
        }
    }
}

fn hosted_execution_status_limitation_v3(status: ArtifactAiExecutionStatusV2) -> &'static str {
    match status {
        ArtifactAiExecutionStatusV2::Completed => "hosted_provider_execution_completed",
        ArtifactAiExecutionStatusV2::ClientNonZeroExit => {
            "hosted_provider_execution_client_non_zero_exit"
        }
        ArtifactAiExecutionStatusV2::TimedOut => "hosted_provider_execution_timed_out",
        ArtifactAiExecutionStatusV2::Cancelled => "hosted_provider_execution_cancelled",
        ArtifactAiExecutionStatusV2::StdoutLimitExceeded => {
            "hosted_provider_execution_stdout_limit_exceeded"
        }
        ArtifactAiExecutionStatusV2::StderrLimitExceeded => {
            "hosted_provider_execution_stderr_limit_exceeded"
        }
        ArtifactAiExecutionStatusV2::OutputCaptureIncomplete => {
            "hosted_provider_execution_output_capture_incomplete"
        }
        ArtifactAiExecutionStatusV2::ProcessCleanupFailed => {
            "hosted_provider_execution_process_cleanup_failed"
        }
        ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid => {
            "hosted_provider_execution_output_envelope_invalid"
        }
        ArtifactAiExecutionStatusV2::ClientIdentityChanged => {
            "hosted_provider_execution_client_identity_changed"
        }
        ArtifactAiExecutionStatusV2::IsolationCheckFailed => {
            "hosted_provider_execution_isolation_check_failed"
        }
        ArtifactAiExecutionStatusV2::AuthenticationContinuityFailed => {
            "hosted_provider_execution_authentication_continuity_failed"
        }
        ArtifactAiExecutionStatusV2::ObservedModelMismatch => {
            "hosted_provider_execution_observed_model_mismatch"
        }
        ArtifactAiExecutionStatusV2::PostExecutionVerificationFailed => {
            "hosted_provider_execution_post_execution_verification_failed"
        }
    }
}

fn verdict_wire_v2(verdict: ArtifactReviewVerdictV2) -> &'static str {
    match verdict {
        ArtifactReviewVerdictV2::NoFinding => "no_finding",
        ArtifactReviewVerdictV2::Suspicious => "suspicious",
        ArtifactReviewVerdictV2::Uncertain => "uncertain",
    }
}
