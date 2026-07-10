use crate::wire::{
    sign_artifact_review_statement_v2, verify_artifact_review_statement_signature_v2,
    SignatureVerifiedArtifactReviewStatementV2,
};
use crate::{
    ArtifactReviewAuthErrorV2, ArtifactReviewChallengeAcceptanceCommitReceiptV2,
    ArtifactReviewChallengeAcceptanceV2, ArtifactReviewChallengeAuthorityIdV2,
    ArtifactReviewChallengeAuthorityV2, ArtifactReviewChallengeV2,
    ArtifactReviewEvidenceCompletenessV2, ArtifactReviewEvidenceStatementDraftV2,
    ArtifactReviewEvidenceStatementV2, ArtifactReviewKeyRegistryV2, ArtifactReviewSigningKeyV2,
    SignedArtifactReviewStatementV2, MAX_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_BYTES_V2,
    MAX_ARTIFACT_REVIEW_EVIDENCE_TTL_SECONDS_V2, MAX_JCS_SAFE_INTEGER_V2,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};
use whoathere_artifact::{NormalizedArtifact, Sha256Digest};
use whoathere_artifact_review_ollama::{
    parse_ollama_terminal_frame_v1, verify_ollama_terminal_frame_v1, OLLAMA_ADAPTER_VERSION_V1,
    OLLAMA_TERMINAL_FRAME_SCHEMA_V1,
};
use whoathere_artifact_review_runtime::{
    EvidenceBoundLocalProviderRunV2, LocalProviderEvidenceExecutionBindingV2,
    LocalProviderExecutableIdentityPostureV2, LocalProviderHostIsolationV2,
    LocalProviderInvocationObservationV2, LocalProviderInvocationRecordV2,
    LocalProviderModelIdentityPostureV2, LocalProviderNetworkIsolationV2,
    LocalProviderResourceIsolationV2, LocalProviderRunTerminalStateV2, LocalProviderRuntimeErrorV2,
    LocalProviderTerminalPhaseV2, LocalProviderTerminationReasonV2, LocalProviderWorkPartitionV2,
    INERT_PROVIDER_ADAPTER_VERSION_V2, MAX_LOCAL_PROVIDER_TOTAL_INPUT_BYTES_V2,
    MAX_LOCAL_PROVIDER_TOTAL_STDERR_BYTES_V2,
};
use whoathere_detector::{
    artifact_review_adapter_result_schema_sha256_v2, artifact_review_model_output_schema_sha256_v2,
    decode_and_validate_artifact_review_provider_input_v2,
    normalize_artifact_review_provider_outputs_v2, ArtifactReviewAdapterNormalizationV2,
    ArtifactReviewChannelIsolationV2, ArtifactReviewCoverageCompletenessV2,
    ArtifactReviewPrivacyPostureV2, ArtifactReviewProviderOutputV2, ArtifactReviewRequestV2,
    ArtifactReviewVerdictV2, ArtifactReviewWorkItemNormalizationStatusV2,
    ArtifactReviewWorkItemStatusV2, ArtifactStaticAnalysis,
    StructurallyValidatedArtifactReviewResultV2, ARTIFACT_REVIEW_ADAPTER_RESULT_SCHEMA_ID_V2,
    ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_ID_V2, ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2,
    ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2, ARTIFACT_REVIEW_RESULT_SCHEMA_V2,
    MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2, MAX_ARTIFACT_REVIEW_RESULT_BYTES_V2,
    MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const ARTIFACT_REVIEW_AGGREGATE_MANIFEST_SCHEMA_V2: &str =
    "whoathere.artifact_review_authenticated_aggregate_manifest.v3";
pub const ARTIFACT_REVIEW_EXPECTED_WORK_SET_SCHEMA_V2: &str =
    "whoathere.artifact_review_expected_work_set.v2";
pub const LOCAL_ARTIFACT_REVIEW_NORMALIZER_CONTRACT_ID_V2: &str =
    "whoathere.artifact_review_normalizer_contract.v2";
pub const LOCAL_PROVIDER_RUNTIME_CONTRACT_ID_V2: &str =
    "whoathere.macos_local_provider_runtime_contract.v3";
pub const ARTIFACT_REVIEW_RUNTIME_EXECUTION_BINDING_SCHEMA_V2: &str =
    "whoathere.artifact_review_runtime_execution_binding.v2";
pub const LOCAL_PROVIDER_EVIDENCE_BOUND_EXECUTION_SEAM_V2: &str =
    "whoathere.local_provider_evidence_bound_host_timed_execution.v2";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewEvidenceRunContextV2 {
    challenge: ArtifactReviewChallengeV2,
    declared_control_plane_build_sha256: Sha256Digest,
    evidence_ttl_seconds: u64,
}

impl ArtifactReviewEvidenceRunContextV2 {
    pub fn new(
        challenge: ArtifactReviewChallengeV2,
        declared_control_plane_build_sha256: Sha256Digest,
        evidence_ttl_seconds: u64,
    ) -> Result<Self, ArtifactReviewAuthErrorV2> {
        challenge.validate()?;
        if evidence_ttl_seconds == 0
            || evidence_ttl_seconds > MAX_ARTIFACT_REVIEW_EVIDENCE_TTL_SECONDS_V2
        {
            return Err(ArtifactReviewAuthErrorV2::FreshnessInvalid);
        }
        Ok(Self {
            challenge,
            declared_control_plane_build_sha256,
            evidence_ttl_seconds,
        })
    }

    pub fn challenge(&self) -> &ArtifactReviewChallengeV2 {
        &self.challenge
    }

    pub fn declared_control_plane_build_sha256(&self) -> &Sha256Digest {
        &self.declared_control_plane_build_sha256
    }

    pub fn evidence_ttl_seconds(&self) -> u64 {
        self.evidence_ttl_seconds
    }

    fn validate_bindings(
        &self,
        subject: &ArtifactEvidenceSubjectV2,
        artifact: &NormalizedArtifact,
        analysis: &ArtifactStaticAnalysis,
        request: &ArtifactReviewRequestV2,
    ) -> Result<(), ArtifactReviewAuthErrorV2> {
        request
            .validate(subject, artifact, analysis)
            .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
        let subject_binding = crate::ArtifactReviewSubjectBindingV2::from_subject(subject)?;
        let request_sha256 = request
            .request_sha256()
            .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
        let work_set_sha256 = artifact_review_expected_work_set_sha256_v2(request)?;
        let binding = self.challenge.binding();
        if binding.subject() != &subject_binding
            || binding.policy_sha256() != request.policy_sha256()
            || binding.request_sha256() != &request_sha256
            || binding.expected_work_set_sha256() != &work_set_sha256
            || usize::try_from(binding.expected_work_item_count()).ok()
                != Some(request.work_items().len())
        {
            return Err(ArtifactReviewAuthErrorV2::ContextBindingMismatch);
        }
        Ok(())
    }

    fn validate_execution_binding_and_times(
        &self,
        authority_id: &ArtifactReviewChallengeAuthorityIdV2,
        execution_binding: &LocalProviderEvidenceExecutionBindingV2,
        run_started_at_unix_seconds: u64,
        run_finished_at_unix_seconds: u64,
        evidence_issued_at_unix_seconds: u64,
        evidence_expires_at_unix_seconds: u64,
    ) -> Result<(), ArtifactReviewAuthErrorV2> {
        let challenge_binding = self.challenge.binding();
        let expected_challenge_binding_sha256 = self.challenge.canonical_binding_sha256_v2()?;
        if authority_id != self.challenge.authority_id()
            || execution_binding.challenge_id() != self.challenge.challenge_id()
            || execution_binding.evidence_id() != challenge_binding.evidence_id()
            || execution_binding.run_id() != challenge_binding.run_id()
            || execution_binding.challenge_binding_sha256() != &expected_challenge_binding_sha256
        {
            return Err(ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
        }
        if challenge_binding.issued_at_unix_seconds() > run_started_at_unix_seconds
            || run_started_at_unix_seconds > run_finished_at_unix_seconds
            || run_finished_at_unix_seconds > evidence_issued_at_unix_seconds
            || evidence_issued_at_unix_seconds >= evidence_expires_at_unix_seconds
            || evidence_expires_at_unix_seconds > challenge_binding.expires_at_unix_seconds()
            || evidence_expires_at_unix_seconds > MAX_JCS_SAFE_INTEGER_V2
            || evidence_expires_at_unix_seconds - evidence_issued_at_unix_seconds
                != self.evidence_ttl_seconds
        {
            return Err(ArtifactReviewAuthErrorV2::FreshnessInvalid);
        }
        Ok(())
    }
}

pub fn local_provider_evidence_execution_binding_sha256_v2(
    authority_id: &ArtifactReviewChallengeAuthorityIdV2,
    binding: &LocalProviderEvidenceExecutionBindingV2,
) -> Result<Sha256Digest, ArtifactReviewAuthErrorV2> {
    let wire = RuntimeExecutionBindingWireV2 {
        schema_version: ARTIFACT_REVIEW_RUNTIME_EXECUTION_BINDING_SCHEMA_V2,
        authority_id: authority_id.as_str(),
        challenge_id: binding.challenge_id(),
        evidence_id: binding.evidence_id(),
        run_id: binding.run_id(),
        challenge_binding_sha256: binding.challenge_binding_sha256().as_str(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactReviewAuthErrorV2::Serialization)?;
    Ok(Sha256Digest::from_bytes(&bytes))
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct RuntimeExecutionBindingWireV2<'a> {
    schema_version: &'a str,
    authority_id: &'a str,
    challenge_id: &'a str,
    evidence_id: &'a str,
    run_id: &'a str,
    challenge_binding_sha256: &'a str,
}

fn trusted_evidence_times_v2(
    context: &ArtifactReviewEvidenceRunContextV2,
    bound_run: &EvidenceBoundLocalProviderRunV2,
) -> Result<(u64, u64), ArtifactReviewAuthErrorV2> {
    let issued_at = trusted_system_unix_seconds_v2()?;
    let expires_at = issued_at
        .checked_add(context.evidence_ttl_seconds)
        .ok_or(ArtifactReviewAuthErrorV2::FreshnessInvalid)?;
    context.validate_execution_binding_and_times(
        context.challenge().authority_id(),
        bound_run.binding(),
        bound_run.started_at_unix_seconds(),
        bound_run.finished_at_unix_seconds(),
        issued_at,
        expires_at,
    )?;
    Ok((issued_at, expires_at))
}

fn trusted_system_unix_seconds_v2() -> Result<u64, ArtifactReviewAuthErrorV2> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ArtifactReviewAuthErrorV2::FreshnessInvalid)?
        .as_secs();
    if now == 0 || now > MAX_JCS_SAFE_INTEGER_V2 {
        return Err(ArtifactReviewAuthErrorV2::FreshnessInvalid);
    }
    Ok(now)
}

pub fn artifact_review_expected_work_set_sha256_v2(
    request: &ArtifactReviewRequestV2,
) -> Result<Sha256Digest, ArtifactReviewAuthErrorV2> {
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let wire = ExpectedWorkSetWireV2 {
        schema_version: ARTIFACT_REVIEW_EXPECTED_WORK_SET_SCHEMA_V2,
        request_sha256: request_sha256.as_str(),
        work_item_ids: request
            .work_items()
            .iter()
            .map(|item| item.work_item_id().as_str())
            .collect(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactReviewAuthErrorV2::Serialization)?;
    Ok(Sha256Digest::from_bytes(&bytes))
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExpectedWorkSetWireV2<'a> {
    schema_version: &'a str,
    request_sha256: &'a str,
    work_item_ids: Vec<&'a str>,
}

pub fn local_artifact_review_normalizer_contract_sha256_v2() -> Sha256Digest {
    Sha256Digest::from_bytes(
        format!(
            "{LOCAL_ARTIFACT_REVIEW_NORMALIZER_CONTRACT_ID_V2}\0{}\0{}\0{}\0{}\0{}\0{}",
            ARTIFACT_REVIEW_RESULT_SCHEMA_V2,
            artifact_review_model_output_schema_sha256_v2(),
            artifact_review_adapter_result_schema_sha256_v2(),
            MAX_ARTIFACT_REVIEW_RESULT_BYTES_V2,
            MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2,
            ARTIFACT_REVIEW_ADAPTER_RESULT_SCHEMA_ID_V2,
        )
        .as_bytes(),
    )
}

pub fn local_provider_runtime_contract_sha256_v2() -> Sha256Digest {
    Sha256Digest::from_bytes(
        format!(
            "{LOCAL_PROVIDER_RUNTIME_CONTRACT_ID_V2}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
            INERT_PROVIDER_ADAPTER_VERSION_V2,
            OLLAMA_ADAPTER_VERSION_V1,
            OLLAMA_TERMINAL_FRAME_SCHEMA_V1,
            MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2,
            MAX_LOCAL_PROVIDER_TOTAL_INPUT_BYTES_V2,
            MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2,
            MAX_LOCAL_PROVIDER_TOTAL_STDERR_BYTES_V2,
            ARTIFACT_REVIEW_RUNTIME_EXECUTION_BINDING_SCHEMA_V2,
            LOCAL_PROVIDER_EVIDENCE_BOUND_EXECUTION_SEAM_V2,
        )
        .as_bytes(),
    )
}

struct OwnedRestrictedCaptureV2 {
    work_item_id: Sha256Digest,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl fmt::Debug for OwnedRestrictedCaptureV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OwnedRestrictedCaptureV2")
            .field("work_item_id", &self.work_item_id)
            .field("stdout_sha256", &Sha256Digest::from_bytes(&self.stdout))
            .field("stdout_byte_len", &self.stdout.len())
            .field("stderr_sha256", &Sha256Digest::from_bytes(&self.stderr))
            .field("stderr_byte_len", &self.stderr.len())
            .field("stdout", &"<restricted>")
            .field("stderr", &"<restricted>")
            .finish()
    }
}

pub struct RestrictedArtifactReviewEvidenceMaterialV2 {
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    execution_binding: LocalProviderEvidenceExecutionBindingV2,
    run_started_at_unix_seconds: u64,
    run_finished_at_unix_seconds: u64,
    evidence_issued_at_unix_seconds: u64,
    evidence_expires_at_unix_seconds: u64,
    invocation_records: Vec<LocalProviderInvocationRecordV2>,
    captures: Vec<OwnedRestrictedCaptureV2>,
    work_partition: LocalProviderWorkPartitionV2,
    terminal_state: LocalProviderRunTerminalStateV2,
    aggregate_manifest: Vec<u8>,
    normalized_result: Vec<u8>,
}

impl fmt::Debug for RestrictedArtifactReviewEvidenceMaterialV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestrictedArtifactReviewEvidenceMaterialV2")
            .field("authority_id", &self.authority_id)
            .field("execution_binding", &self.execution_binding)
            .field(
                "run_started_at_unix_seconds",
                &self.run_started_at_unix_seconds,
            )
            .field(
                "run_finished_at_unix_seconds",
                &self.run_finished_at_unix_seconds,
            )
            .field(
                "evidence_issued_at_unix_seconds",
                &self.evidence_issued_at_unix_seconds,
            )
            .field(
                "evidence_expires_at_unix_seconds",
                &self.evidence_expires_at_unix_seconds,
            )
            .field("invocation_record_count", &self.invocation_records.len())
            .field("capture_count", &self.captures.len())
            .field("work_partition", &self.work_partition)
            .field("terminal_state", &self.terminal_state)
            .field(
                "aggregate_manifest_sha256",
                &Sha256Digest::from_bytes(&self.aggregate_manifest),
            )
            .field(
                "aggregate_manifest_byte_len",
                &self.aggregate_manifest.len(),
            )
            .field(
                "normalized_result_sha256",
                &Sha256Digest::from_bytes(&self.normalized_result),
            )
            .field("normalized_result_byte_len", &self.normalized_result.len())
            .field("capture_bytes", &"<restricted>")
            .field("normalized_result", &"<redacted>")
            .finish()
    }
}

impl RestrictedArtifactReviewEvidenceMaterialV2 {
    pub fn authority_id(&self) -> &ArtifactReviewChallengeAuthorityIdV2 {
        &self.authority_id
    }

    pub fn aggregate_manifest_bytes(&self) -> &[u8] {
        &self.aggregate_manifest
    }
}

pub struct SignedArtifactReviewEvidencePackageV2 {
    signed_statement: SignedArtifactReviewStatementV2,
    restricted_material: RestrictedArtifactReviewEvidenceMaterialV2,
}

impl fmt::Debug for SignedArtifactReviewEvidencePackageV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedArtifactReviewEvidencePackageV2")
            .field("signed_statement", &self.signed_statement)
            .field("restricted_material", &self.restricted_material)
            .finish()
    }
}

impl SignedArtifactReviewEvidencePackageV2 {
    pub fn signed_statement(&self) -> &SignedArtifactReviewStatementV2 {
        &self.signed_statement
    }

    pub fn into_parts(
        self,
    ) -> (
        SignedArtifactReviewStatementV2,
        RestrictedArtifactReviewEvidenceMaterialV2,
    ) {
        (self.signed_statement, self.restricted_material)
    }

    pub fn from_parts(
        signed_statement: SignedArtifactReviewStatementV2,
        restricted_material: RestrictedArtifactReviewEvidenceMaterialV2,
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

#[allow(clippy::too_many_arguments)]
/// Signs only a run whose evidence identity was fixed before execution.
///
/// ```compile_fail
/// use whoathere_artifact_review_auth::sign_local_provider_artifact_review_evidence_v2;
/// use whoathere_artifact_review_runtime::LocalProviderRunV2;
/// fn old_unbound_run_cannot_sign(run: LocalProviderRunV2) {
///     let _ = sign_local_provider_artifact_review_evidence_v2(
///         todo!(), todo!(), todo!(), todo!(), todo!(), run, todo!(), todo!(),
///     );
/// }
/// ```
pub fn sign_local_provider_artifact_review_evidence_v2(
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    context: &ArtifactReviewEvidenceRunContextV2,
    run: EvidenceBoundLocalProviderRunV2,
    signer: &ArtifactReviewSigningKeyV2,
    challenge_authority: &ArtifactReviewChallengeAuthorityV2,
) -> Result<SignedArtifactReviewEvidencePackageV2, ArtifactReviewAuthErrorV2> {
    context.validate_bindings(subject, artifact, analysis, request)?;
    challenge_authority.ensure_owns_challenge(context.challenge())?;
    if signer.identity() != context.challenge.binding().key_identity() {
        return Err(ArtifactReviewAuthErrorV2::UnknownKey);
    }
    let (evidence_issued_at_unix_seconds, evidence_expires_at_unix_seconds) =
        trusted_evidence_times_v2(context, &run)?;
    let mut material = material_from_run_v2(
        run,
        context.challenge().authority_id().clone(),
        evidence_issued_at_unix_seconds,
        evidence_expires_at_unix_seconds,
    )?;
    let reconstructed =
        reconstruct_local_evidence_v2(subject, artifact, analysis, request, &material)?;
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
    let statement = build_statement_v2(request, context, &material, &reconstructed, cumulative)?;
    let signed_statement = sign_artifact_review_statement_v2(&statement, signer)?;
    Ok(SignedArtifactReviewEvidencePackageV2 {
        signed_statement,
        restricted_material: material,
    })
}

pub struct AuthenticatedArtifactReviewEvidenceV2 {
    authenticated_statement: SignatureVerifiedArtifactReviewStatementV2,
    normalization: ArtifactReviewAdapterNormalizationV2,
    acceptance_commit_receipt: ArtifactReviewChallengeAcceptanceCommitReceiptV2,
}

impl fmt::Debug for AuthenticatedArtifactReviewEvidenceV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedArtifactReviewEvidenceV2")
            .field("authenticated_statement", &self.authenticated_statement)
            .field("normalization", &self.normalization)
            .field("acceptance_commit_receipt", &self.acceptance_commit_receipt)
            .finish()
    }
}

impl AuthenticatedArtifactReviewEvidenceV2 {
    pub fn evidence_sha256(&self) -> &Sha256Digest {
        self.authenticated_statement.evidence_sha256()
    }

    pub fn statement(&self) -> &ArtifactReviewEvidenceStatementV2 {
        self.authenticated_statement.statement()
    }

    pub fn result(&self) -> &StructurallyValidatedArtifactReviewResultV2 {
        self.normalization.structurally_validated_result()
    }

    pub fn acceptance(&self) -> ArtifactReviewChallengeAcceptanceV2 {
        self.acceptance_commit_receipt.outcome()
    }

    pub fn acceptance_commit_receipt(&self) -> &ArtifactReviewChallengeAcceptanceCommitReceiptV2 {
        &self.acceptance_commit_receipt
    }

    pub fn is_complete(&self) -> bool {
        self.statement().completeness() == ArtifactReviewEvidenceCompletenessV2::Complete
    }

    pub const fn is_authenticated(&self) -> bool {
        true
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub fn verify_and_accept_local_provider_artifact_review_evidence_v2(
    package: SignedArtifactReviewEvidencePackageV2,
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    context: &ArtifactReviewEvidenceRunContextV2,
    registry: &ArtifactReviewKeyRegistryV2,
    challenge_authority: &ArtifactReviewChallengeAuthorityV2,
) -> Result<AuthenticatedArtifactReviewEvidenceV2, ArtifactReviewAuthErrorV2> {
    context.validate_bindings(subject, artifact, analysis, request)?;
    challenge_authority.ensure_owns_challenge(context.challenge())?;
    let SignedArtifactReviewEvidencePackageV2 {
        signed_statement,
        restricted_material,
    } = package;
    let reconstructed =
        reconstruct_local_evidence_v2(subject, artifact, analysis, request, &restricted_material)?;
    context.validate_execution_binding_and_times(
        &restricted_material.authority_id,
        &restricted_material.execution_binding,
        restricted_material.run_started_at_unix_seconds,
        restricted_material.run_finished_at_unix_seconds,
        restricted_material.evidence_issued_at_unix_seconds,
        restricted_material.evidence_expires_at_unix_seconds,
    )?;
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
    let expected_statement = build_statement_v2(
        request,
        context,
        &restricted_material,
        &reconstructed,
        cumulative,
    )?;
    let verification_now_unix_seconds = trusted_system_unix_seconds_v2()?;
    let authenticated_statement = verify_artifact_review_statement_signature_v2(
        &signed_statement,
        expected_statement,
        registry,
        verification_now_unix_seconds,
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
        verification_now_unix_seconds,
    )?;
    Ok(AuthenticatedArtifactReviewEvidenceV2 {
        authenticated_statement,
        normalization: reconstructed.normalization,
        acceptance_commit_receipt,
    })
}

fn material_from_run_v2(
    bound_run: EvidenceBoundLocalProviderRunV2,
    authority_id: ArtifactReviewChallengeAuthorityIdV2,
    evidence_issued_at_unix_seconds: u64,
    evidence_expires_at_unix_seconds: u64,
) -> Result<RestrictedArtifactReviewEvidenceMaterialV2, ArtifactReviewAuthErrorV2> {
    let (execution_binding, run_started_at_unix_seconds, run_finished_at_unix_seconds, run) =
        bound_run.into_parts();
    let (outputs, records, captures, work_partition, terminal_state) =
        run.into_evidence_parts().into_parts();
    if outputs.len() != records.len() || records.len() != captures.len() {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }
    for ((output, record), capture) in outputs.iter().zip(&records).zip(&captures) {
        if output.work_item_id() != record.work_item_id()
            || output.work_item_id() != capture.work_item_id()
            || output.status() != record.provider_output_status()
            || output.captured_output_sha256() != *record.stdout_capture_sha256()
            || output.captured_output_len() as u64 != record.stdout_capture_byte_len()
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
    }
    let captures = captures
        .into_iter()
        .map(|capture| {
            capture.consume(|view| OwnedRestrictedCaptureV2 {
                work_item_id: view.work_item_id().clone(),
                stdout: view.stdout_bytes().to_vec(),
                stderr: view.stderr_bytes().to_vec(),
            })
        })
        .collect();
    Ok(RestrictedArtifactReviewEvidenceMaterialV2 {
        authority_id,
        execution_binding,
        run_started_at_unix_seconds,
        run_finished_at_unix_seconds,
        evidence_issued_at_unix_seconds,
        evidence_expires_at_unix_seconds,
        invocation_records: records,
        captures,
        work_partition,
        terminal_state,
        aggregate_manifest: Vec::new(),
        normalized_result: Vec::new(),
    })
}

struct ReconstructedLocalEvidenceV2 {
    normalization: ArtifactReviewAdapterNormalizationV2,
    aggregate_manifest: Vec<u8>,
    current_positive_finding_ids: Vec<Sha256Digest>,
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: Vec<String>,
}

fn reconstruct_local_evidence_v2(
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    material: &RestrictedArtifactReviewEvidenceMaterialV2,
) -> Result<ReconstructedLocalEvidenceV2, ArtifactReviewAuthErrorV2> {
    request
        .validate(subject, artifact, analysis)
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let expected_work_item_ids = request
        .work_items()
        .iter()
        .map(|item| item.work_item_id().clone())
        .collect::<Vec<_>>();
    if material.work_partition.expected_work_item_ids() != expected_work_item_ids
        || material.work_partition.recorded_work_item_ids().len()
            != material.invocation_records.len()
        || material.invocation_records.len() != material.captures.len()
    {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }

    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let mut outputs = Vec::with_capacity(material.invocation_records.len());
    let mut total_stdout = 0usize;
    let mut total_stderr = 0usize;
    for ((record, capture), expected_recorded_id) in material
        .invocation_records
        .iter()
        .zip(&material.captures)
        .zip(material.work_partition.recorded_work_item_ids())
    {
        if record.work_item_id() != expected_recorded_id
            || capture.work_item_id != *expected_recorded_id
            || record.request_sha256() != &request_sha256
            || record.provider_adapter_sha256() != &request.provider().adapter_sha256
            || record.model_content_sha256() != &request.model().model_content_sha256
            || record.invocation_sha256()
                != &request
                    .invocation_sha256(expected_recorded_id)
                    .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        let invocation = request
            .invocation(artifact, expected_recorded_id)
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
        let provider_input = invocation
            .canonical_provider_input_json_v2()
            .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
        if provider_input.len() as u64 != record.provider_input_byte_len()
            || Sha256Digest::from_bytes(&provider_input) != *record.provider_input_sha256()
            || capture.stdout.len() as u64 != record.stdout_capture_byte_len()
            || Sha256Digest::from_bytes(&capture.stdout) != *record.stdout_capture_sha256()
            || capture.stderr.len() as u64 != record.stderr_capture_byte_len()
            || Sha256Digest::from_bytes(&capture.stderr) != *record.stderr_capture_sha256()
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        match record.provider_observation() {
            None => {
                if record.channel_isolation()
                    == ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted
                    || record.model_identity_posture()
                        == LocalProviderModelIdentityPostureV2::ServerReportedManifestDigestMatchedPinnedExpectedValueServerNotAttested
                {
                    return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
                }
            }
            Some(LocalProviderInvocationObservationV2::OllamaLoopbackV1(observation)) => {
                let decoded = decode_and_validate_artifact_review_provider_input_v2(&provider_input)
                    .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
                let parsed = parse_ollama_terminal_frame_v1(&capture.stderr)
                    .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
                let verified = verify_ollama_terminal_frame_v1(parsed, &decoded, &capture.stdout)
                    .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
                if &verified != observation
                    || record.termination_reason() != LocalProviderTerminationReasonV2::Completed
                    || record.channel_isolation()
                        != ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted
                    || record.network_isolation()
                        != LocalProviderNetworkIsolationV2::LiteralLoopbackAdapterTransportServerEgressNotEnforced
                    || record.model_identity_posture()
                        != LocalProviderModelIdentityPostureV2::ServerReportedManifestDigestMatchedPinnedExpectedValueServerNotAttested
                    || record.resource_isolation()
                        != LocalProviderResourceIsolationV2::AdapterWallClockStreamCapsServerResourcesNotEnforced
                {
                    return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
                }
            }
        }
        total_stdout = total_stdout
            .checked_add(capture.stdout.len())
            .ok_or(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
        total_stderr = total_stderr
            .checked_add(capture.stderr.len())
            .ok_or(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;

        let expected_status = expected_status_for_termination_v2(record.termination_reason());
        if record.provider_output_status() != expected_status || !eof_claims_are_coherent_v2(record)
        {
            return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
        }
        let output = match expected_status {
            ArtifactReviewWorkItemStatusV2::Completed => {
                ArtifactReviewProviderOutputV2::new_complete(
                    expected_recorded_id.clone(),
                    capture.stdout.clone(),
                    record.channel_isolation(),
                )
            }
            ArtifactReviewWorkItemStatusV2::Truncated => {
                ArtifactReviewProviderOutputV2::new_truncated_capture(
                    expected_recorded_id.clone(),
                    capture.stdout.clone(),
                    record.channel_isolation(),
                )
            }
            ArtifactReviewWorkItemStatusV2::Failed => {
                ArtifactReviewProviderOutputV2::new_failed_capture(
                    expected_recorded_id.clone(),
                    capture.stdout.clone(),
                    record.channel_isolation(),
                    record.stdout_eof_verified(),
                )
            }
        }
        .map_err(|_| ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence)?;
        outputs.push(output);
    }
    if total_stdout > MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2
        || total_stderr > MAX_LOCAL_PROVIDER_TOTAL_STDERR_BYTES_V2
    {
        return Err(ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }

    let normalization = normalize_artifact_review_provider_outputs_v2(
        subject, artifact, analysis, request, &outputs,
    )
    .map_err(|_| ArtifactReviewAuthErrorV2::NormalizationFailed)?;
    let current_positive_finding_ids = normalization
        .structurally_validated_result()
        .findings()
        .iter()
        .map(|finding| finding.evidence_sha256().clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let limitations = derive_limitations_v2(request, material, &normalization);
    let completeness = if limitations.is_empty() {
        ArtifactReviewEvidenceCompletenessV2::Complete
    } else {
        ArtifactReviewEvidenceCompletenessV2::Incomplete
    };
    let aggregate_manifest = build_aggregate_manifest_v2(
        request,
        material,
        &normalization,
        &current_positive_finding_ids,
        completeness,
        &limitations,
    )?;
    Ok(ReconstructedLocalEvidenceV2 {
        normalization,
        aggregate_manifest,
        current_positive_finding_ids,
        completeness,
        limitations,
    })
}

fn expected_status_for_termination_v2(
    termination: LocalProviderTerminationReasonV2,
) -> ArtifactReviewWorkItemStatusV2 {
    match termination {
        LocalProviderTerminationReasonV2::Completed => ArtifactReviewWorkItemStatusV2::Completed,
        LocalProviderTerminationReasonV2::StdoutLimitExceeded => {
            ArtifactReviewWorkItemStatusV2::Truncated
        }
        LocalProviderTerminationReasonV2::NonZeroExit
        | LocalProviderTerminationReasonV2::StderrLimitExceeded
        | LocalProviderTerminationReasonV2::PerCallTimeout
        | LocalProviderTerminationReasonV2::GlobalTimeout
        | LocalProviderTerminationReasonV2::Cancelled
        | LocalProviderTerminationReasonV2::InputWriteFailed
        | LocalProviderTerminationReasonV2::OutputReadFailed
        | LocalProviderTerminationReasonV2::ProtocolHandshakeFailed
        | LocalProviderTerminationReasonV2::LingeringProcessGroup => {
            ArtifactReviewWorkItemStatusV2::Failed
        }
    }
}

fn eof_claims_are_coherent_v2(record: &LocalProviderInvocationRecordV2) -> bool {
    match record.termination_reason() {
        LocalProviderTerminationReasonV2::Completed
        | LocalProviderTerminationReasonV2::NonZeroExit => {
            record.stdout_eof_verified() && record.stderr_eof_verified()
        }
        LocalProviderTerminationReasonV2::StdoutLimitExceeded => !record.stdout_eof_verified(),
        LocalProviderTerminationReasonV2::StderrLimitExceeded => !record.stderr_eof_verified(),
        LocalProviderTerminationReasonV2::PerCallTimeout
        | LocalProviderTerminationReasonV2::GlobalTimeout
        | LocalProviderTerminationReasonV2::Cancelled
        | LocalProviderTerminationReasonV2::InputWriteFailed
        | LocalProviderTerminationReasonV2::OutputReadFailed
        | LocalProviderTerminationReasonV2::ProtocolHandshakeFailed
        | LocalProviderTerminationReasonV2::LingeringProcessGroup => true,
    }
}

fn derive_limitations_v2(
    request: &ArtifactReviewRequestV2,
    material: &RestrictedArtifactReviewEvidenceMaterialV2,
    normalization: &ArtifactReviewAdapterNormalizationV2,
) -> Vec<String> {
    let mut limitations = BTreeSet::new();
    limitations.insert("control_plane_build_identity_not_independently_measured".to_string());
    limitations.insert("runtime_identity_is_contract_digest_not_binary_measurement".to_string());
    limitations.insert("normalizer_identity_is_contract_digest_not_binary_measurement".to_string());
    if request.coverage().completeness() != ArtifactReviewCoverageCompletenessV2::Complete
        || !request.coverage().limitations().is_empty()
    {
        limitations.insert("artifact_review_coverage_incomplete".to_string());
    }
    if !material
        .work_partition
        .attempted_without_capture_work_item_ids()
        .is_empty()
    {
        limitations.insert("local_provider_attempted_without_capture".to_string());
    }
    if !material
        .work_partition
        .unattempted_work_item_ids()
        .is_empty()
    {
        limitations.insert("local_provider_work_unattempted".to_string());
    }
    if let Some(error) = material.terminal_state.terminal_error() {
        limitations.insert(error.reason_code().to_string());
    }
    if let Some(error) = material.terminal_state.secondary_cleanup_error() {
        limitations.insert(error.reason_code().to_string());
    }
    if !material.terminal_state.run_directory_cleanup_verified() {
        limitations.insert("local_provider_run_directory_cleanup_not_verified".to_string());
    }
    for record in &material.invocation_records {
        if record.termination_reason() != LocalProviderTerminationReasonV2::Completed {
            limitations.insert(format!(
                "local_provider_{}",
                termination_reason_wire_v2(record.termination_reason())
            ));
        }
        if !record.stdout_eof_verified() {
            limitations.insert("local_provider_stdout_eof_not_verified".to_string());
        }
        if !record.stderr_eof_verified() {
            limitations.insert("local_provider_stderr_eof_not_verified".to_string());
        }
        if !record.process_group_cleanup_verified() {
            limitations.insert("local_provider_process_group_cleanup_not_verified".to_string());
        }
        if !record.descendant_containment_verified() {
            limitations.insert("local_provider_descendant_containment_not_verified".to_string());
        }
        if record.channel_isolation() == ArtifactReviewChannelIsolationV2::CollapsedPrompt {
            limitations.insert("local_provider_prompt_channels_collapsed".to_string());
        }
        match record.network_isolation() {
            LocalProviderNetworkIsolationV2::NotEnforcedCallerAuthorizedExecutable => {
                limitations.insert("local_provider_network_isolation_not_enforced".to_string());
            }
            LocalProviderNetworkIsolationV2::LiteralLoopbackAdapterTransportServerEgressNotEnforced => {
                limitations.insert("ollama_adapter_transport_observed_loopback_only".to_string());
                limitations.insert("ollama_server_egress_not_enforced".to_string());
                limitations.insert("ollama_server_peer_process_not_attested".to_string());
                limitations.insert("ollama_local_only_privacy_not_verified".to_string());
            }
        }
        match record.host_isolation() {
            LocalProviderHostIsolationV2::NotSandboxedCallerAuthorizedExecutable => {
                limitations.insert("local_provider_host_isolation_not_enforced".to_string());
            }
        }
        match record.model_identity_posture() {
            LocalProviderModelIdentityPostureV2::SyntheticBehaviorLabelBoundToVerifiedAdapterBytes => {
                limitations.insert("local_provider_model_identity_synthetic".to_string());
            }
            LocalProviderModelIdentityPostureV2::ServerReportedManifestDigestMatchedPinnedExpectedValueServerNotAttested => {
                limitations.insert("ollama_server_executable_not_measured".to_string());
                limitations.insert("ollama_model_manifest_digest_server_reported".to_string());
                limitations.insert("ollama_model_weight_closure_not_independently_measured".to_string());
                limitations.insert("ollama_server_role_semantics_not_attested".to_string());
            }
            LocalProviderModelIdentityPostureV2::UnavailableOrUnverified => {
                limitations.insert("local_provider_model_identity_unverified".to_string());
            }
        }
        match record.resource_isolation() {
            LocalProviderResourceIsolationV2::WallClockStreamCapsAndDescriptorClosureOnly => {
                limitations.insert("local_provider_resource_isolation_partial".to_string());
            }
            LocalProviderResourceIsolationV2::AdapterWallClockStreamCapsServerResourcesNotEnforced => {
                limitations.insert("ollama_adapter_resource_isolation_partial".to_string());
                limitations.insert("ollama_server_resource_isolation_not_enforced".to_string());
                limitations.insert("ollama_server_side_cancellation_not_verified".to_string());
            }
        }
        match record.executable_identity_posture() {
            LocalProviderExecutableIdentityPostureV2::DigestVerifiedPrivateStagedPathSameUserRaceNotExcluded => {
                limitations.insert("local_provider_executable_same_user_race_not_excluded".to_string());
            }
        }
    }
    if !normalization.missing_work_item_ids().is_empty() {
        limitations.insert("artifact_review_normalizer_missing_work_items".to_string());
    }
    for outcome in normalization.outcomes() {
        if outcome.status() != ArtifactReviewWorkItemNormalizationStatusV2::Normalized {
            limitations.insert(outcome.status().reason_code().to_string());
        }
    }
    limitations.into_iter().collect()
}

fn cumulative_findings_for_statement_v2(
    context: &ArtifactReviewEvidenceRunContextV2,
    current: &[Sha256Digest],
    authority: &ArtifactReviewChallengeAuthorityV2,
) -> Result<Vec<Sha256Digest>, ArtifactReviewAuthErrorV2> {
    let binding = context.challenge.binding();
    let mut cumulative = authority
        .cumulative_positive_finding_ids(
            binding.key_identity().trust_domain(),
            binding.lineage_scope(),
        )?
        .into_iter()
        .collect::<BTreeSet<_>>();
    cumulative.extend(current.iter().cloned());
    Ok(cumulative.into_iter().collect())
}

fn build_statement_v2(
    request: &ArtifactReviewRequestV2,
    context: &ArtifactReviewEvidenceRunContextV2,
    material: &RestrictedArtifactReviewEvidenceMaterialV2,
    reconstructed: &ReconstructedLocalEvidenceV2,
    cumulative_positive_finding_ids: Vec<Sha256Digest>,
) -> Result<ArtifactReviewEvidenceStatementV2, ArtifactReviewAuthErrorV2> {
    let normalized = reconstructed.normalization.adapter_normalized_output();
    ArtifactReviewEvidenceStatementV2::new(ArtifactReviewEvidenceStatementDraftV2 {
        challenge: context.challenge.clone(),
        challenge_binding_sha256: material
            .execution_binding
            .challenge_binding_sha256()
            .clone(),
        runtime_execution_binding_sha256: local_provider_evidence_execution_binding_sha256_v2(
            &material.authority_id,
            &material.execution_binding,
        )?,
        run_started_at_unix_seconds: material.run_started_at_unix_seconds,
        run_finished_at_unix_seconds: material.run_finished_at_unix_seconds,
        evidence_issued_at_unix_seconds: material.evidence_issued_at_unix_seconds,
        evidence_expires_at_unix_seconds: material.evidence_expires_at_unix_seconds,
        deterministic_analysis_sha256: request.deterministic_analysis_sha256().clone(),
        coverage_manifest_sha256: request.coverage_manifest_sha256().clone(),
        provider_adapter_sha256: request.provider().adapter_sha256.clone(),
        model_content_sha256: request.model().model_content_sha256.clone(),
        prompt_template_sha256: request.prompt().template_sha256.clone(),
        model_output_schema_sha256: request.model_output_schema_sha256().clone(),
        adapter_result_schema_sha256: request.adapter_result_schema_sha256().clone(),
        declared_control_plane_build_sha256: context.declared_control_plane_build_sha256.clone(),
        runtime_contract_sha256: local_provider_runtime_contract_sha256_v2(),
        normalizer_contract_sha256: local_artifact_review_normalizer_contract_sha256_v2(),
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

fn build_aggregate_manifest_v2(
    request: &ArtifactReviewRequestV2,
    material: &RestrictedArtifactReviewEvidenceMaterialV2,
    normalization: &ArtifactReviewAdapterNormalizationV2,
    current_positive_finding_ids: &[Sha256Digest],
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: &[String],
) -> Result<Vec<u8>, ArtifactReviewAuthErrorV2> {
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewAuthErrorV2::ContextBindingMismatch)?;
    let invocations = material
        .invocation_records
        .iter()
        .map(invocation_manifest_wire_v2)
        .collect();
    let outcomes = normalization
        .outcomes()
        .iter()
        .map(|outcome| NormalizationOutcomeWireV2 {
            work_item_id: outcome.work_item_id().as_str().to_string(),
            provider_output_capture_sha256: outcome
                .provider_output_capture_sha256()
                .as_str()
                .to_string(),
            provider_output_capture_byte_len: outcome
                .provider_output_capture_byte_len()
                .to_string(),
            status: outcome.status().reason_code().to_string(),
        })
        .collect();
    let terminal = &material.terminal_state;
    let runtime_execution_binding_sha256 = local_provider_evidence_execution_binding_sha256_v2(
        &material.authority_id,
        &material.execution_binding,
    )?;
    let wire = AggregateManifestWireV2 {
        schema_version: ARTIFACT_REVIEW_AGGREGATE_MANIFEST_SCHEMA_V2.to_string(),
        canonicalization: crate::ARTIFACT_REVIEW_EVIDENCE_CANONICALIZATION_V2.to_string(),
        authority_id: material.authority_id.as_str().to_string(),
        challenge_id: material.execution_binding.challenge_id().to_string(),
        evidence_id: material.execution_binding.evidence_id().to_string(),
        run_id: material.execution_binding.run_id().to_string(),
        challenge_binding_sha256: material
            .execution_binding
            .challenge_binding_sha256()
            .as_str()
            .to_string(),
        runtime_execution_binding_sha256: runtime_execution_binding_sha256.as_str().to_string(),
        run_started_at_unix_seconds: material.run_started_at_unix_seconds.to_string(),
        run_finished_at_unix_seconds: material.run_finished_at_unix_seconds.to_string(),
        evidence_issued_at_unix_seconds: material.evidence_issued_at_unix_seconds.to_string(),
        evidence_expires_at_unix_seconds: material.evidence_expires_at_unix_seconds.to_string(),
        request_sha256: request_sha256.as_str().to_string(),
        provider_id: request.provider().adapter_id.clone(),
        provider_version: request.provider().adapter_version.clone(),
        model_id: request.model().model_id.clone(),
        model_version: request.model().model_version.clone(),
        prompt_template_id: request.prompt().template_id.clone(),
        prompt_template_version: request.prompt().template_version.clone(),
        model_output_schema_id: ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_ID_V2.to_string(),
        adapter_result_schema_id: ARTIFACT_REVIEW_ADAPTER_RESULT_SCHEMA_ID_V2.to_string(),
        prompt_template_contract_id: ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2.to_string(),
        prompt_template_contract_version: ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2.to_string(),
        privacy_posture: privacy_posture_wire_v2(request.privacy_posture()).to_string(),
        inference_seed: request.inference().seed.to_string(),
        inference_temperature_milli: request.inference().temperature_milli.to_string(),
        inference_top_p_milli: request.inference().top_p_milli.to_string(),
        inference_context_tokens: request.inference().context_tokens.to_string(),
        inference_max_output_tokens: request.inference().max_output_tokens.to_string(),
        expected_work_item_ids: digest_strings_owned_v2(
            material.work_partition.expected_work_item_ids(),
        ),
        recorded_work_item_ids: digest_strings_owned_v2(
            material.work_partition.recorded_work_item_ids(),
        ),
        attempted_without_capture_work_item_ids: digest_strings_owned_v2(
            material
                .work_partition
                .attempted_without_capture_work_item_ids(),
        ),
        unattempted_work_item_ids: digest_strings_owned_v2(
            material.work_partition.unattempted_work_item_ids(),
        ),
        invocations,
        terminal_error: runtime_error_state_wire_v2(terminal.terminal_error()),
        terminal_phase: terminal_phase_state_wire_v2(terminal.terminal_phase()),
        terminal_error_work_item_id: digest_state_wire_v2(terminal.terminal_error_work_item_id()),
        run_directory_cleanup_verified: terminal.run_directory_cleanup_verified(),
        secondary_cleanup_error: runtime_error_state_wire_v2(terminal.secondary_cleanup_error()),
        normalization_outcomes: outcomes,
        missing_work_item_ids: digest_strings_owned_v2(normalization.missing_work_item_ids()),
        normalized_result_sha256: Sha256Digest::from_bytes(
            normalization.adapter_normalized_output(),
        )
        .as_str()
        .to_string(),
        normalized_result_byte_len: normalization.adapter_normalized_output().len().to_string(),
        execution_claims_sha256: normalization
            .execution_report()
            .execution_claims_sha256()
            .as_str()
            .to_string(),
        verdict: verdict_wire_v2(normalization.structurally_validated_result().verdict())
            .to_string(),
        current_positive_finding_ids: digest_strings_owned_v2(current_positive_finding_ids),
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

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AggregateManifestWireV2 {
    schema_version: String,
    canonicalization: String,
    authority_id: String,
    challenge_id: String,
    evidence_id: String,
    run_id: String,
    challenge_binding_sha256: String,
    runtime_execution_binding_sha256: String,
    run_started_at_unix_seconds: String,
    run_finished_at_unix_seconds: String,
    evidence_issued_at_unix_seconds: String,
    evidence_expires_at_unix_seconds: String,
    request_sha256: String,
    provider_id: String,
    provider_version: String,
    model_id: String,
    model_version: String,
    prompt_template_id: String,
    prompt_template_version: String,
    model_output_schema_id: String,
    adapter_result_schema_id: String,
    prompt_template_contract_id: String,
    prompt_template_contract_version: String,
    privacy_posture: String,
    inference_seed: String,
    inference_temperature_milli: String,
    inference_top_p_milli: String,
    inference_context_tokens: String,
    inference_max_output_tokens: String,
    expected_work_item_ids: Vec<String>,
    recorded_work_item_ids: Vec<String>,
    attempted_without_capture_work_item_ids: Vec<String>,
    unattempted_work_item_ids: Vec<String>,
    invocations: Vec<InvocationManifestWireV2>,
    terminal_error: ExplicitStringStateWireV2,
    terminal_phase: ExplicitStringStateWireV2,
    terminal_error_work_item_id: ExplicitStringStateWireV2,
    run_directory_cleanup_verified: bool,
    secondary_cleanup_error: ExplicitStringStateWireV2,
    normalization_outcomes: Vec<NormalizationOutcomeWireV2>,
    missing_work_item_ids: Vec<String>,
    normalized_result_sha256: String,
    normalized_result_byte_len: String,
    execution_claims_sha256: String,
    verdict: String,
    current_positive_finding_ids: Vec<String>,
    completeness: ArtifactReviewEvidenceCompletenessV2,
    limitations: Vec<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct InvocationManifestWireV2 {
    work_item_id: String,
    request_sha256: String,
    invocation_sha256: String,
    provider_adapter_sha256: String,
    model_content_sha256: String,
    provider_input_sha256: String,
    provider_input_byte_len: String,
    stdout_capture_sha256: String,
    stdout_capture_byte_len: String,
    stderr_capture_sha256: String,
    stderr_capture_byte_len: String,
    provider_output_status: String,
    termination_reason: String,
    exit_code: ExplicitStringStateWireV2,
    channel_isolation: String,
    stdout_eof_verified: bool,
    stderr_eof_verified: bool,
    process_group_cleanup_verified: bool,
    descendant_containment_verified: bool,
    kill_escalated: bool,
    network_isolation: String,
    host_isolation: String,
    model_identity_posture: String,
    resource_isolation: String,
    executable_identity_posture: String,
    provider_observation: ProviderObservationWireV2,
    elapsed_millis: String,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum ProviderObservationWireV2 {
    Absent,
    OllamaLoopbackV1(Box<OllamaObservationManifestWireV2>),
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct OllamaObservationManifestWireV2 {
    schema_version: String,
    adapter_id: String,
    adapter_version: String,
    outcome: String,
    work_item_id: String,
    invocation_sha256: String,
    provider_input_sha256: String,
    endpoint: String,
    server_version: String,
    requested_model: String,
    response_model: String,
    expected_model_content_sha256: String,
    pre_model_content_sha256: String,
    post_model_content_sha256: String,
    system_message_sha256: String,
    user_message_sha256: String,
    role_mapping_contract_sha256: String,
    api_request_sha256: String,
    raw_api_response_sha256: String,
    model_output_sha256: String,
    model_output_byte_len: String,
    prompt_eval_count: String,
    eval_count: String,
    done_reason: String,
    seed: String,
    temperature_milli: String,
    top_p_milli: String,
    context_tokens: String,
    max_output_tokens: String,
    observed_transport: String,
    model_identity_posture: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct NormalizationOutcomeWireV2 {
    work_item_id: String,
    provider_output_capture_sha256: String,
    provider_output_capture_byte_len: String,
    status: String,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum ExplicitStringStateWireV2 {
    Absent,
    Present { value: String },
}

fn invocation_manifest_wire_v2(
    record: &LocalProviderInvocationRecordV2,
) -> InvocationManifestWireV2 {
    InvocationManifestWireV2 {
        work_item_id: record.work_item_id().as_str().to_string(),
        request_sha256: record.request_sha256().as_str().to_string(),
        invocation_sha256: record.invocation_sha256().as_str().to_string(),
        provider_adapter_sha256: record.provider_adapter_sha256().as_str().to_string(),
        model_content_sha256: record.model_content_sha256().as_str().to_string(),
        provider_input_sha256: record.provider_input_sha256().as_str().to_string(),
        provider_input_byte_len: record.provider_input_byte_len().to_string(),
        stdout_capture_sha256: record.stdout_capture_sha256().as_str().to_string(),
        stdout_capture_byte_len: record.stdout_capture_byte_len().to_string(),
        stderr_capture_sha256: record.stderr_capture_sha256().as_str().to_string(),
        stderr_capture_byte_len: record.stderr_capture_byte_len().to_string(),
        provider_output_status: work_item_status_wire_v2(record.provider_output_status())
            .to_string(),
        termination_reason: termination_reason_wire_v2(record.termination_reason()).to_string(),
        exit_code: record
            .exit_code()
            .map_or(ExplicitStringStateWireV2::Absent, |value| {
                ExplicitStringStateWireV2::Present {
                    value: value.to_string(),
                }
            }),
        channel_isolation: channel_isolation_wire_v2(record.channel_isolation()).to_string(),
        stdout_eof_verified: record.stdout_eof_verified(),
        stderr_eof_verified: record.stderr_eof_verified(),
        process_group_cleanup_verified: record.process_group_cleanup_verified(),
        descendant_containment_verified: record.descendant_containment_verified(),
        kill_escalated: record.kill_escalated(),
        network_isolation: network_isolation_wire_v2(record.network_isolation()).to_string(),
        host_isolation: host_isolation_wire_v2(record.host_isolation()).to_string(),
        model_identity_posture: model_identity_posture_wire_v2(record.model_identity_posture())
            .to_string(),
        resource_isolation: resource_isolation_wire_v2(record.resource_isolation()).to_string(),
        executable_identity_posture: executable_identity_posture_wire_v2(
            record.executable_identity_posture(),
        )
        .to_string(),
        provider_observation: provider_observation_wire_v2(record.provider_observation()),
        elapsed_millis: record.elapsed_millis().to_string(),
    }
}

fn provider_observation_wire_v2(
    observation: Option<&LocalProviderInvocationObservationV2>,
) -> ProviderObservationWireV2 {
    match observation {
        None => ProviderObservationWireV2::Absent,
        Some(LocalProviderInvocationObservationV2::OllamaLoopbackV1(observation)) => {
            let frame = observation.terminal_frame();
            ProviderObservationWireV2::OllamaLoopbackV1(Box::new(OllamaObservationManifestWireV2 {
                schema_version: frame.schema_version.clone(),
                adapter_id: frame.adapter_id.clone(),
                adapter_version: frame.adapter_version.clone(),
                outcome: "completed".to_string(),
                work_item_id: frame.work_item_id.as_str().to_string(),
                invocation_sha256: frame.invocation_sha256.as_str().to_string(),
                provider_input_sha256: frame.provider_input_sha256.as_str().to_string(),
                endpoint: frame.endpoint.clone(),
                server_version: frame.server_version.clone(),
                requested_model: frame.requested_model.clone(),
                response_model: frame.response_model.clone(),
                expected_model_content_sha256: frame
                    .expected_model_content_sha256
                    .as_str()
                    .to_string(),
                pre_model_content_sha256: frame.pre_model_content_sha256.as_str().to_string(),
                post_model_content_sha256: frame.post_model_content_sha256.as_str().to_string(),
                system_message_sha256: frame.system_message_sha256.as_str().to_string(),
                user_message_sha256: frame.user_message_sha256.as_str().to_string(),
                role_mapping_contract_sha256: frame
                    .role_mapping_contract_sha256
                    .as_str()
                    .to_string(),
                api_request_sha256: frame.api_request_sha256.as_str().to_string(),
                raw_api_response_sha256: frame.raw_api_response_sha256.as_str().to_string(),
                model_output_sha256: frame.model_output_sha256.as_str().to_string(),
                model_output_byte_len: frame.model_output_byte_len.to_string(),
                prompt_eval_count: frame.prompt_eval_count.to_string(),
                eval_count: frame.eval_count.to_string(),
                done_reason: frame.done_reason.clone(),
                seed: frame.seed.to_string(),
                temperature_milli: frame.temperature_milli.to_string(),
                top_p_milli: frame.top_p_milli.to_string(),
                context_tokens: frame.context_tokens.to_string(),
                max_output_tokens: frame.max_output_tokens.to_string(),
                observed_transport: frame.observed_transport.clone(),
                model_identity_posture: frame.model_identity_posture.clone(),
            }))
        }
    }
}

fn runtime_error_state_wire_v2(
    error: Option<LocalProviderRuntimeErrorV2>,
) -> ExplicitStringStateWireV2 {
    error.map_or(ExplicitStringStateWireV2::Absent, |error| {
        ExplicitStringStateWireV2::Present {
            value: error.reason_code().to_string(),
        }
    })
}

fn terminal_phase_state_wire_v2(
    phase: Option<LocalProviderTerminalPhaseV2>,
) -> ExplicitStringStateWireV2 {
    phase.map_or(ExplicitStringStateWireV2::Absent, |phase| {
        ExplicitStringStateWireV2::Present {
            value: match phase {
                LocalProviderTerminalPhaseV2::Preflight => "preflight",
                LocalProviderTerminalPhaseV2::RunSetup => "run_setup",
                LocalProviderTerminalPhaseV2::Invocation => "invocation",
                LocalProviderTerminalPhaseV2::RunDirectoryCleanup => "run_directory_cleanup",
            }
            .to_string(),
        }
    })
}

fn digest_state_wire_v2(digest: Option<&Sha256Digest>) -> ExplicitStringStateWireV2 {
    digest.map_or(ExplicitStringStateWireV2::Absent, |digest| {
        ExplicitStringStateWireV2::Present {
            value: digest.as_str().to_string(),
        }
    })
}

fn digest_strings_owned_v2(values: &[Sha256Digest]) -> Vec<String> {
    values
        .iter()
        .map(|digest| digest.as_str().to_string())
        .collect()
}

fn work_item_status_wire_v2(status: ArtifactReviewWorkItemStatusV2) -> &'static str {
    match status {
        ArtifactReviewWorkItemStatusV2::Completed => "completed",
        ArtifactReviewWorkItemStatusV2::Truncated => "truncated",
        ArtifactReviewWorkItemStatusV2::Failed => "failed",
    }
}

fn termination_reason_wire_v2(reason: LocalProviderTerminationReasonV2) -> &'static str {
    match reason {
        LocalProviderTerminationReasonV2::Completed => "completed",
        LocalProviderTerminationReasonV2::NonZeroExit => "non_zero_exit",
        LocalProviderTerminationReasonV2::StdoutLimitExceeded => "stdout_limit_exceeded",
        LocalProviderTerminationReasonV2::StderrLimitExceeded => "stderr_limit_exceeded",
        LocalProviderTerminationReasonV2::PerCallTimeout => "per_call_timeout",
        LocalProviderTerminationReasonV2::GlobalTimeout => "global_timeout",
        LocalProviderTerminationReasonV2::Cancelled => "cancelled",
        LocalProviderTerminationReasonV2::InputWriteFailed => "input_write_failed",
        LocalProviderTerminationReasonV2::OutputReadFailed => "output_read_failed",
        LocalProviderTerminationReasonV2::ProtocolHandshakeFailed => "protocol_handshake_failed",
        LocalProviderTerminationReasonV2::LingeringProcessGroup => "lingering_process_group",
    }
}

fn channel_isolation_wire_v2(channel: ArtifactReviewChannelIsolationV2) -> &'static str {
    match channel {
        ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted => {
            "separate_trusted_and_untrusted"
        }
        ArtifactReviewChannelIsolationV2::CollapsedPrompt => "collapsed_prompt",
    }
}

fn network_isolation_wire_v2(value: LocalProviderNetworkIsolationV2) -> &'static str {
    match value {
        LocalProviderNetworkIsolationV2::NotEnforcedCallerAuthorizedExecutable => {
            "not_enforced_caller_authorized_executable"
        }
        LocalProviderNetworkIsolationV2::LiteralLoopbackAdapterTransportServerEgressNotEnforced => {
            "literal_loopback_adapter_transport_server_egress_not_enforced"
        }
    }
}

fn host_isolation_wire_v2(value: LocalProviderHostIsolationV2) -> &'static str {
    match value {
        LocalProviderHostIsolationV2::NotSandboxedCallerAuthorizedExecutable => {
            "not_sandboxed_caller_authorized_executable"
        }
    }
}

fn model_identity_posture_wire_v2(value: LocalProviderModelIdentityPostureV2) -> &'static str {
    match value {
        LocalProviderModelIdentityPostureV2::SyntheticBehaviorLabelBoundToVerifiedAdapterBytes => {
            "synthetic_behavior_label_bound_to_verified_adapter_bytes"
        }
        LocalProviderModelIdentityPostureV2::ServerReportedManifestDigestMatchedPinnedExpectedValueServerNotAttested => {
            "server_reported_manifest_digest_matched_pinned_expected_value_server_not_attested"
        }
        LocalProviderModelIdentityPostureV2::UnavailableOrUnverified => {
            "unavailable_or_unverified"
        }
    }
}

fn resource_isolation_wire_v2(value: LocalProviderResourceIsolationV2) -> &'static str {
    match value {
        LocalProviderResourceIsolationV2::WallClockStreamCapsAndDescriptorClosureOnly => {
            "wall_clock_stream_caps_and_descriptor_closure_only"
        }
        LocalProviderResourceIsolationV2::AdapterWallClockStreamCapsServerResourcesNotEnforced => {
            "adapter_wall_clock_stream_caps_server_resources_not_enforced"
        }
    }
}

fn executable_identity_posture_wire_v2(
    value: LocalProviderExecutableIdentityPostureV2,
) -> &'static str {
    match value {
        LocalProviderExecutableIdentityPostureV2::DigestVerifiedPrivateStagedPathSameUserRaceNotExcluded => {
            "digest_verified_private_staged_path_same_user_race_not_excluded"
        }
    }
}

fn privacy_posture_wire_v2(value: ArtifactReviewPrivacyPostureV2) -> &'static str {
    match value {
        ArtifactReviewPrivacyPostureV2::LocalOnly => "local_only",
        ArtifactReviewPrivacyPostureV2::ApprovedHosted => "approved_hosted",
    }
}

fn verdict_wire_v2(value: ArtifactReviewVerdictV2) -> &'static str {
    match value {
        ArtifactReviewVerdictV2::Suspicious => "suspicious",
        ArtifactReviewVerdictV2::NoFinding => "no_finding",
        ArtifactReviewVerdictV2::Uncertain => "uncertain",
    }
}
