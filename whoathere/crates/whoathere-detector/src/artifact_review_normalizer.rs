//! Deterministic normalization of untrusted per-work-item model output.
//!
//! This module does not invoke a provider. It turns the small model-facing
//! schema into the exact adapter-result schema using trusted artifact bytes.

use crate::{
    artifact_review_finding_evidence_sha256_v2,
    decode_and_structurally_validate_artifact_review_result_v2, ArtifactReviewChannelIsolationV2,
    ArtifactReviewContextKindV2, ArtifactReviewExecutionReportV2, ArtifactReviewFindingCategoryV2,
    ArtifactReviewFindingEvidenceInputV2, ArtifactReviewFindingSeverityV2, ArtifactReviewRequestV2,
    ArtifactReviewVerdictV2, ArtifactReviewWorkItemStatusV2, ArtifactStaticAnalysis,
    StructurallyValidatedArtifactReviewResultV2, ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2,
    ARTIFACT_REVIEW_RESULT_SCHEMA_V2, MAX_ARTIFACT_REVIEW_EXPLANATION_CHARS_V2,
    MAX_ARTIFACT_REVIEW_FINDINGS_V2, MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2,
    MAX_ARTIFACT_REVIEW_RESULT_BYTES_V2, MAX_ARTIFACT_REVIEW_WORK_ITEMS_V2,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use whoathere_artifact::{NormalizedArtifact, Sha256Digest};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewProviderOutputErrorV2 {
    OutputLimitExceeded,
}

impl ArtifactReviewProviderOutputErrorV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::OutputLimitExceeded => {
                "artifact_review_v2_provider_output_capture_limit_exceeded"
            }
        }
    }
}

pub struct ArtifactReviewProviderOutputV2 {
    work_item_id: Sha256Digest,
    captured_output: Vec<u8>,
    status: ArtifactReviewWorkItemStatusV2,
    channel_isolation: ArtifactReviewChannelIsolationV2,
    no_truncation_verified: bool,
}

impl fmt::Debug for ArtifactReviewProviderOutputV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactReviewProviderOutputV2")
            .field("work_item_id", &self.work_item_id)
            .field(
                "provider_output_capture_sha256",
                &self.captured_output_sha256(),
            )
            .field(
                "provider_output_capture_byte_len",
                &self.captured_output.len(),
            )
            .field("status", &self.status)
            .field("channel_isolation", &self.channel_isolation)
            .field("no_truncation_verified", &self.no_truncation_verified)
            .field("provider_output_capture", &"<redacted>")
            .finish()
    }
}

impl ArtifactReviewProviderOutputV2 {
    pub fn new_complete(
        work_item_id: Sha256Digest,
        captured_output: Vec<u8>,
        channel_isolation: ArtifactReviewChannelIsolationV2,
    ) -> Result<Self, ArtifactReviewProviderOutputErrorV2> {
        Self::new_capture(
            work_item_id,
            captured_output,
            ArtifactReviewWorkItemStatusV2::Completed,
            channel_isolation,
            true,
        )
    }

    pub fn new_truncated_capture(
        work_item_id: Sha256Digest,
        captured_prefix: Vec<u8>,
        channel_isolation: ArtifactReviewChannelIsolationV2,
    ) -> Result<Self, ArtifactReviewProviderOutputErrorV2> {
        Self::new_capture(
            work_item_id,
            captured_prefix,
            ArtifactReviewWorkItemStatusV2::Truncated,
            channel_isolation,
            false,
        )
    }

    pub fn new_failed_capture(
        work_item_id: Sha256Digest,
        captured_output: Vec<u8>,
        channel_isolation: ArtifactReviewChannelIsolationV2,
        no_truncation_verified: bool,
    ) -> Result<Self, ArtifactReviewProviderOutputErrorV2> {
        Self::new_capture(
            work_item_id,
            captured_output,
            ArtifactReviewWorkItemStatusV2::Failed,
            channel_isolation,
            no_truncation_verified,
        )
    }

    fn new_capture(
        work_item_id: Sha256Digest,
        captured_output: Vec<u8>,
        status: ArtifactReviewWorkItemStatusV2,
        channel_isolation: ArtifactReviewChannelIsolationV2,
        no_truncation_verified: bool,
    ) -> Result<Self, ArtifactReviewProviderOutputErrorV2> {
        if captured_output.len() > MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2 {
            return Err(ArtifactReviewProviderOutputErrorV2::OutputLimitExceeded);
        }
        Ok(Self {
            work_item_id,
            captured_output,
            status,
            channel_isolation,
            no_truncation_verified,
        })
    }

    pub fn work_item_id(&self) -> &Sha256Digest {
        &self.work_item_id
    }

    pub fn captured_output_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&self.captured_output)
    }

    pub fn captured_output_len(&self) -> usize {
        self.captured_output.len()
    }

    pub fn status(&self) -> ArtifactReviewWorkItemStatusV2 {
        self.status
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewWorkItemNormalizationStatusV2 {
    Normalized,
    ProviderFailed,
    Truncated,
    OutputLimitExceeded,
    InvalidModelOutputWire,
    ModelOutputBindingMismatch,
    TooManyFindings,
    AggregateFindingLimitExceeded,
    InvalidFindingReference,
    InvalidFindingEvidence,
}

impl ArtifactReviewWorkItemNormalizationStatusV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Normalized => "artifact_review_v2_work_item_normalized",
            Self::ProviderFailed => "artifact_review_v2_work_item_provider_failed",
            Self::Truncated => "artifact_review_v2_work_item_truncated",
            Self::OutputLimitExceeded => "artifact_review_v2_work_item_output_limit_exceeded",
            Self::InvalidModelOutputWire => "artifact_review_v2_work_item_model_output_invalid",
            Self::ModelOutputBindingMismatch => {
                "artifact_review_v2_work_item_model_output_binding_mismatch"
            }
            Self::TooManyFindings => "artifact_review_v2_work_item_finding_limit_exceeded",
            Self::AggregateFindingLimitExceeded => {
                "artifact_review_v2_work_item_aggregate_finding_limit_exceeded"
            }
            Self::InvalidFindingReference => {
                "artifact_review_v2_work_item_finding_reference_invalid"
            }
            Self::InvalidFindingEvidence => "artifact_review_v2_work_item_finding_evidence_invalid",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReviewWorkItemNormalizationOutcomeV2 {
    work_item_id: Sha256Digest,
    provider_output_capture_sha256: Sha256Digest,
    provider_output_capture_byte_len: u64,
    status: ArtifactReviewWorkItemNormalizationStatusV2,
}

impl ArtifactReviewWorkItemNormalizationOutcomeV2 {
    pub fn work_item_id(&self) -> &Sha256Digest {
        &self.work_item_id
    }

    pub fn provider_output_capture_sha256(&self) -> &Sha256Digest {
        &self.provider_output_capture_sha256
    }

    pub fn provider_output_capture_byte_len(&self) -> u64 {
        self.provider_output_capture_byte_len
    }

    pub fn status(&self) -> ArtifactReviewWorkItemNormalizationStatusV2 {
        self.status
    }
}

pub struct ArtifactReviewAdapterNormalizationV2 {
    adapter_normalized_output: Vec<u8>,
    execution_report: ArtifactReviewExecutionReportV2,
    structurally_validated_result: StructurallyValidatedArtifactReviewResultV2,
    outcomes: Vec<ArtifactReviewWorkItemNormalizationOutcomeV2>,
    missing_work_item_ids: Vec<Sha256Digest>,
}

impl fmt::Debug for ArtifactReviewAdapterNormalizationV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactReviewAdapterNormalizationV2")
            .field(
                "adapter_normalized_output_sha256",
                &Sha256Digest::from_bytes(&self.adapter_normalized_output),
            )
            .field(
                "adapter_normalized_output_len",
                &self.adapter_normalized_output.len(),
            )
            .field(
                "work_item_claim_count",
                &self.execution_report.work_item_claims().len(),
            )
            .field("outcome_count", &self.outcomes.len())
            .field("missing_work_item_count", &self.missing_work_item_ids.len())
            .field("adapter_normalized_output", &"<redacted>")
            .finish()
    }
}

impl ArtifactReviewAdapterNormalizationV2 {
    /// Exact adapter-result JSON. It contains bounded untrusted explanations
    /// and must be sanitized before display.
    pub fn adapter_normalized_output(&self) -> &[u8] {
        &self.adapter_normalized_output
    }

    pub fn execution_report(&self) -> &ArtifactReviewExecutionReportV2 {
        &self.execution_report
    }

    pub fn structurally_validated_result(&self) -> &StructurallyValidatedArtifactReviewResultV2 {
        &self.structurally_validated_result
    }

    pub fn outcomes(&self) -> &[ArtifactReviewWorkItemNormalizationOutcomeV2] {
        &self.outcomes
    }

    pub fn missing_work_item_ids(&self) -> &[Sha256Digest] {
        &self.missing_work_item_ids
    }

    pub fn into_parts(
        self,
    ) -> (
        Vec<u8>,
        ArtifactReviewExecutionReportV2,
        StructurallyValidatedArtifactReviewResultV2,
        Vec<ArtifactReviewWorkItemNormalizationOutcomeV2>,
        Vec<Sha256Digest>,
    ) {
        (
            self.adapter_normalized_output,
            self.execution_report,
            self.structurally_validated_result,
            self.outcomes,
            self.missing_work_item_ids,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelOutputWireV2 {
    schema_version: String,
    work_item_id: Sha256Digest,
    invocation_sha256: Sha256Digest,
    verdict: ArtifactReviewVerdictV2,
    findings: Vec<ModelFindingWireV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModelFindingWireV2 {
    category: ArtifactReviewFindingCategoryV2,
    severity: ArtifactReviewFindingSeverityV2,
    context_id: Sha256Digest,
    context_kind: ArtifactReviewContextKindV2,
    chunk_relative_start_byte: u64,
    chunk_relative_end_byte: u64,
    explanation: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct AdapterResultWireV2 {
    schema_version: String,
    artifact_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    coverage_manifest_sha256: Sha256Digest,
    provider_adapter_sha256: Sha256Digest,
    model_content_sha256: Sha256Digest,
    prompt_template_sha256: Sha256Digest,
    model_output_schema_sha256: Sha256Digest,
    adapter_result_schema_sha256: Sha256Digest,
    verdict: ArtifactReviewVerdictV2,
    findings: Vec<AdapterFindingWireV2>,
}

#[derive(Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AdapterFindingWireV2 {
    category: ArtifactReviewFindingCategoryV2,
    severity: ArtifactReviewFindingSeverityV2,
    work_item_id: Sha256Digest,
    file_id: Sha256Digest,
    file_sha256: Sha256Digest,
    chunk_id: Sha256Digest,
    context_id: Sha256Digest,
    context_kind: ArtifactReviewContextKindV2,
    start_byte: u64,
    end_byte: u64,
    start_line: u64,
    end_line: u64,
    selected_sha256: Sha256Digest,
    evidence_sha256: Sha256Digest,
    explanation: String,
}

pub fn normalize_artifact_review_provider_outputs_v2(
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    outputs: &[ArtifactReviewProviderOutputV2],
) -> Result<ArtifactReviewAdapterNormalizationV2, ArtifactReviewNormalizationErrorV2> {
    request
        .validate(subject, artifact, analysis)
        .map_err(|_| ArtifactReviewNormalizationErrorV2::InvalidRequest)?;
    if outputs.len() > request.work_items().len()
        || outputs.len() > MAX_ARTIFACT_REVIEW_WORK_ITEMS_V2
    {
        return Err(ArtifactReviewNormalizationErrorV2::TooManyProviderOutputs);
    }

    let mut seen_work_items = HashSet::with_capacity(outputs.len());
    for output in outputs {
        if !seen_work_items.insert(output.work_item_id.clone()) {
            return Err(ArtifactReviewNormalizationErrorV2::DuplicateWorkItemOutput);
        }
    }

    let work_items = request
        .work_items()
        .iter()
        .map(|item| (item.work_item_id(), item))
        .collect::<HashMap<_, _>>();
    let missing_work_item_ids = request
        .work_items()
        .iter()
        .filter(|item| !seen_work_items.contains(item.work_item_id()))
        .map(|item| item.work_item_id().clone())
        .collect::<Vec<_>>();
    let coverage_files = request
        .coverage()
        .files()
        .iter()
        .map(|file| (file.file_id(), file))
        .collect::<HashMap<_, _>>();
    let claim_builder = request
        .execution_claim_builder()
        .map_err(|_| ArtifactReviewNormalizationErrorV2::InvalidRequest)?;
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactReviewNormalizationErrorV2::InvalidRequest)?;

    let mut ordered_outputs = outputs.iter().collect::<Vec<_>>();
    ordered_outputs.sort_by(|left, right| left.work_item_id.cmp(&right.work_item_id));
    let mut claims = Vec::with_capacity(ordered_outputs.len());
    let mut outcomes = Vec::with_capacity(ordered_outputs.len());
    let mut findings_by_evidence = BTreeMap::<Sha256Digest, AdapterFindingWireV2>::new();
    let mut normalized_provider_output_bytes = 0usize;

    for output in ordered_outputs {
        let work_item = work_items
            .get(&output.work_item_id)
            .copied()
            .ok_or(ArtifactReviewNormalizationErrorV2::UnknownWorkItem)?;
        let expected_invocation_sha256 = request
            .invocation_sha256(&output.work_item_id)
            .map_err(|_| ArtifactReviewNormalizationErrorV2::InvalidRequest)?;
        let provider_output_capture_sha256 = output.captured_output_sha256();
        let provider_output_capture_byte_len = u64::try_from(output.captured_output.len())
            .map_err(|_| ArtifactReviewNormalizationErrorV2::Serialization)?;
        let output_fits_budget = output.captured_output.len()
            <= MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2
            && normalized_provider_output_bytes
                .checked_add(output.captured_output.len())
                .is_some_and(|total| total <= MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2);
        if output_fits_budget {
            normalized_provider_output_bytes += output.captured_output.len();
        }
        let (mut claim_status, claim_no_truncation, mut outcome_status, mut normalized_findings) =
            if !output_fits_budget {
                (
                    ArtifactReviewWorkItemStatusV2::Failed,
                    output.no_truncation_verified,
                    ArtifactReviewWorkItemNormalizationStatusV2::OutputLimitExceeded,
                    Vec::new(),
                )
            } else if output.status == ArtifactReviewWorkItemStatusV2::Truncated
                || (output.status == ArtifactReviewWorkItemStatusV2::Completed
                    && !output.no_truncation_verified)
            {
                (
                    ArtifactReviewWorkItemStatusV2::Truncated,
                    false,
                    ArtifactReviewWorkItemNormalizationStatusV2::Truncated,
                    Vec::new(),
                )
            } else if output.status == ArtifactReviewWorkItemStatusV2::Failed {
                (
                    ArtifactReviewWorkItemStatusV2::Failed,
                    output.no_truncation_verified,
                    ArtifactReviewWorkItemNormalizationStatusV2::ProviderFailed,
                    Vec::new(),
                )
            } else {
                match normalize_completed_work_item_output(
                    output,
                    work_item,
                    &coverage_files,
                    artifact,
                    &request_sha256,
                    &expected_invocation_sha256,
                ) {
                    Ok(findings) => (
                        ArtifactReviewWorkItemStatusV2::Completed,
                        true,
                        ArtifactReviewWorkItemNormalizationStatusV2::Normalized,
                        findings,
                    ),
                    Err(status) => (
                        ArtifactReviewWorkItemStatusV2::Failed,
                        true,
                        status,
                        Vec::new(),
                    ),
                }
            };
        let mut new_finding_ids = HashSet::new();
        for finding in &normalized_findings {
            if let Some(existing) = findings_by_evidence.get(&finding.evidence_sha256) {
                if existing != finding {
                    return Err(ArtifactReviewNormalizationErrorV2::FindingDigestCollision);
                }
            } else {
                new_finding_ids.insert(finding.evidence_sha256.clone());
            }
        }
        if findings_by_evidence
            .len()
            .checked_add(new_finding_ids.len())
            .is_none_or(|count| count > MAX_ARTIFACT_REVIEW_FINDINGS_V2)
        {
            claim_status = ArtifactReviewWorkItemStatusV2::Failed;
            outcome_status =
                ArtifactReviewWorkItemNormalizationStatusV2::AggregateFindingLimitExceeded;
            normalized_findings.clear();
        }
        claims.push(
            claim_builder
                .from_adapter_claims(
                    output.work_item_id.clone(),
                    provider_output_capture_sha256.clone(),
                    provider_output_capture_byte_len,
                    claim_status,
                    output.channel_isolation,
                    claim_no_truncation,
                )
                .map_err(|_| ArtifactReviewNormalizationErrorV2::InvalidExecutionClaim)?,
        );
        outcomes.push(ArtifactReviewWorkItemNormalizationOutcomeV2 {
            work_item_id: output.work_item_id.clone(),
            provider_output_capture_sha256,
            provider_output_capture_byte_len,
            status: outcome_status,
        });
        for finding in normalized_findings {
            if !findings_by_evidence.contains_key(&finding.evidence_sha256) {
                findings_by_evidence.insert(finding.evidence_sha256.clone(), finding);
            }
        }
    }

    let findings = findings_by_evidence.into_values().collect::<Vec<_>>();
    let verdict = if findings.is_empty() {
        ArtifactReviewVerdictV2::Uncertain
    } else {
        ArtifactReviewVerdictV2::Suspicious
    };
    let wire = AdapterResultWireV2 {
        schema_version: ARTIFACT_REVIEW_RESULT_SCHEMA_V2.to_string(),
        artifact_sha256: request.artifact_sha256().clone(),
        manifest_sha256: request.manifest_sha256().clone(),
        request_sha256,
        coverage_manifest_sha256: request.coverage_manifest_sha256().clone(),
        provider_adapter_sha256: request.provider().adapter_sha256.clone(),
        model_content_sha256: request.model().model_content_sha256.clone(),
        prompt_template_sha256: request.prompt().template_sha256.clone(),
        model_output_schema_sha256: request.model_output_schema_sha256().clone(),
        adapter_result_schema_sha256: request.adapter_result_schema_sha256().clone(),
        verdict,
        findings,
    };
    let adapter_normalized_output =
        serde_json::to_vec(&wire).map_err(|_| ArtifactReviewNormalizationErrorV2::Serialization)?;
    if adapter_normalized_output.len() > MAX_ARTIFACT_REVIEW_RESULT_BYTES_V2 {
        return Err(ArtifactReviewNormalizationErrorV2::AdapterResultLimitExceeded);
    }
    let execution_report = ArtifactReviewExecutionReportV2::from_adapter_claims(
        request,
        claims,
        &adapter_normalized_output,
    )
    .map_err(|_| ArtifactReviewNormalizationErrorV2::InvalidExecutionReport)?;
    let structurally_validated_result = decode_and_structurally_validate_artifact_review_result_v2(
        &adapter_normalized_output,
        request,
        artifact,
        analysis,
        &execution_report,
    )
    .map_err(|_| ArtifactReviewNormalizationErrorV2::StructuralSelfCheckFailed)?;
    Ok(ArtifactReviewAdapterNormalizationV2 {
        adapter_normalized_output,
        execution_report,
        structurally_validated_result,
        outcomes,
        missing_work_item_ids,
    })
}

fn normalize_completed_work_item_output(
    output: &ArtifactReviewProviderOutputV2,
    work_item: &crate::ArtifactReviewWorkItemV2,
    coverage_files: &HashMap<&Sha256Digest, &crate::ArtifactReviewFileCoverageV2>,
    artifact: &NormalizedArtifact,
    request_sha256: &Sha256Digest,
    expected_invocation_sha256: &Sha256Digest,
) -> Result<Vec<AdapterFindingWireV2>, ArtifactReviewWorkItemNormalizationStatusV2> {
    if output.captured_output.is_empty() || std::str::from_utf8(&output.captured_output).is_err() {
        return Err(ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&output.captured_output);
    let wire = ModelOutputWireV2::deserialize(&mut deserializer)
        .map_err(|_| ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire)?;
    deserializer
        .end()
        .map_err(|_| ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire)?;
    if wire.schema_version != ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2
        || wire.work_item_id != output.work_item_id
        || &wire.invocation_sha256 != expected_invocation_sha256
    {
        return Err(ArtifactReviewWorkItemNormalizationStatusV2::ModelOutputBindingMismatch);
    }
    if wire.findings.len() > MAX_ARTIFACT_REVIEW_FINDINGS_V2 {
        return Err(ArtifactReviewWorkItemNormalizationStatusV2::TooManyFindings);
    }
    // The declaration is intentionally advisory. Exact resolved findings win
    // asymmetrically; an unsupported suspicion without a range contributes no
    // finding and can never become a clean result.
    let _declared_verdict = wire.verdict;

    let file_coverage = coverage_files
        .get(work_item.file_id())
        .copied()
        .ok_or(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingReference)?;
    let chunk = file_coverage
        .chunks()
        .iter()
        .find(|chunk| chunk.chunk_id() == work_item.chunk_id())
        .ok_or(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingReference)?;
    let file = artifact
        .file(work_item.file_id())
        .ok_or(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingReference)?;
    let chunk_len = chunk
        .end_byte()
        .checked_sub(chunk.start_byte())
        .ok_or(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;

    let mut findings = Vec::with_capacity(wire.findings.len());
    for model_finding in wire.findings {
        if !context_is_allowed(
            file_coverage.contexts(),
            &model_finding.context_id,
            model_finding.context_kind,
        ) {
            return Err(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingReference);
        }
        if model_finding.chunk_relative_start_byte >= model_finding.chunk_relative_end_byte
            || model_finding.chunk_relative_end_byte > chunk_len
            || model_finding.explanation.is_empty()
            || model_finding.explanation.chars().count() > MAX_ARTIFACT_REVIEW_EXPLANATION_CHARS_V2
            || model_finding.explanation.chars().any(char::is_control)
        {
            return Err(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence);
        }
        let start_byte = chunk
            .start_byte()
            .checked_add(model_finding.chunk_relative_start_byte)
            .ok_or(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;
        let end_byte = chunk
            .start_byte()
            .checked_add(model_finding.chunk_relative_end_byte)
            .ok_or(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;
        let start = usize::try_from(start_byte)
            .map_err(|_| ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;
        let end = usize::try_from(end_byte)
            .map_err(|_| ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;
        if !is_utf8_char_boundary(file.bytes(), start) || !is_utf8_char_boundary(file.bytes(), end)
        {
            return Err(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence);
        }
        let selected = file
            .bytes()
            .get(start..end)
            .ok_or(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;
        let selected_sha256 = Sha256Digest::from_bytes(selected);
        let start_line =
            line_number_within_chunk(file.bytes(), chunk.start_byte(), chunk.start_line(), start)
                .map_err(|_| ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;
        let end_line = line_number_within_chunk(
            file.bytes(),
            chunk.start_byte(),
            chunk.start_line(),
            end.saturating_sub(1),
        )
        .map_err(|_| ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence)?;
        let evidence_sha256 =
            artifact_review_finding_evidence_sha256_v2(ArtifactReviewFindingEvidenceInputV2 {
                request_sha256,
                work_item_id: &output.work_item_id,
                category: model_finding.category,
                severity: model_finding.severity,
                file_id: work_item.file_id(),
                chunk_id: work_item.chunk_id(),
                context_id: &model_finding.context_id,
                context_kind: model_finding.context_kind,
                start_byte,
                end_byte,
                start_line,
                end_line,
                selected_sha256: &selected_sha256,
                explanation: &model_finding.explanation,
            });
        findings.push(AdapterFindingWireV2 {
            category: model_finding.category,
            severity: model_finding.severity,
            work_item_id: output.work_item_id.clone(),
            file_id: work_item.file_id().clone(),
            file_sha256: file.sha256.clone(),
            chunk_id: work_item.chunk_id().clone(),
            context_id: model_finding.context_id,
            context_kind: model_finding.context_kind,
            start_byte,
            end_byte,
            start_line,
            end_line,
            selected_sha256,
            evidence_sha256,
            explanation: model_finding.explanation,
        });
    }
    Ok(findings)
}

fn context_is_allowed(
    contexts: &[crate::ArtifactReviewContextReferenceV2],
    context_id: &Sha256Digest,
    context_kind: ArtifactReviewContextKindV2,
) -> bool {
    contexts
        .binary_search_by(|context| {
            context
                .context_id()
                .cmp(context_id)
                .then_with(|| context.kind().cmp(&context_kind))
        })
        .is_ok()
}

fn is_utf8_char_boundary(bytes: &[u8], index: usize) -> bool {
    index == bytes.len()
        || bytes
            .get(index)
            .is_some_and(|byte| byte & 0b1100_0000 != 0b1000_0000)
}

fn line_number_within_chunk(
    bytes: &[u8],
    chunk_start_byte: u64,
    chunk_start_line: u64,
    offset: usize,
) -> Result<u64, ArtifactReviewNormalizationErrorV2> {
    let chunk_start = usize::try_from(chunk_start_byte)
        .map_err(|_| ArtifactReviewNormalizationErrorV2::InvalidFindingEvidence)?;
    let prefix = bytes
        .get(chunk_start..offset)
        .ok_or(ArtifactReviewNormalizationErrorV2::InvalidFindingEvidence)?;
    Ok(
        chunk_start_line
            .saturating_add(prefix.iter().filter(|byte| **byte == b'\n').count() as u64),
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactReviewNormalizationErrorV2 {
    InvalidRequest,
    TooManyProviderOutputs,
    DuplicateWorkItemOutput,
    UnknownWorkItem,
    InvalidFindingEvidence,
    FindingDigestCollision,
    InvalidExecutionClaim,
    Serialization,
    AdapterResultLimitExceeded,
    InvalidExecutionReport,
    StructuralSelfCheckFailed,
}

impl ArtifactReviewNormalizationErrorV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "artifact_review_v2_normalizer_request_invalid",
            Self::TooManyProviderOutputs => {
                "artifact_review_v2_normalizer_provider_output_count_exceeded"
            }
            Self::DuplicateWorkItemOutput => {
                "artifact_review_v2_normalizer_duplicate_work_item_output"
            }
            Self::UnknownWorkItem => "artifact_review_v2_normalizer_work_item_unknown",
            Self::InvalidFindingEvidence => {
                "artifact_review_v2_normalizer_finding_evidence_invalid"
            }
            Self::FindingDigestCollision => {
                "artifact_review_v2_normalizer_finding_digest_collision"
            }
            Self::InvalidExecutionClaim => "artifact_review_v2_normalizer_execution_claim_invalid",
            Self::Serialization => "artifact_review_v2_normalizer_serialization_failed",
            Self::AdapterResultLimitExceeded => {
                "artifact_review_v2_normalizer_adapter_result_limit_exceeded"
            }
            Self::InvalidExecutionReport => {
                "artifact_review_v2_normalizer_execution_report_invalid"
            }
            Self::StructuralSelfCheckFailed => {
                "artifact_review_v2_normalizer_structural_self_check_failed"
            }
        }
    }
}
