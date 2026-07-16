//! Deterministic normalization of untrusted per-work-item model output.
//!
//! This module does not invoke a provider. It turns the small model-facing
//! schema into the exact adapter-result schema using trusted artifact bytes.

use crate::{
    artifact_review_finding_evidence_sha256_v2, artifact_review_finding_identity_sha256_v2,
    decode_and_structurally_validate_artifact_review_result_v2, ArtifactReviewChannelIsolationV2,
    ArtifactReviewContextKindV2, ArtifactReviewExecutionReportV2, ArtifactReviewFindingCategoryV2,
    ArtifactReviewFindingEvidenceInputV2, ArtifactReviewFindingIdentityInputV2,
    ArtifactReviewFindingSeverityV2, ArtifactReviewRequestV2, ArtifactReviewThreatClassV2,
    ArtifactReviewVerdictV2, ArtifactReviewWorkItemStatusV2, ArtifactStaticAnalysis,
    StructurallyValidatedArtifactReviewResultV2, ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2,
    ARTIFACT_REVIEW_RESULT_SCHEMA_V2, MAX_ARTIFACT_REVIEW_EXPLANATION_CHARS_V2,
    MAX_ARTIFACT_REVIEW_FINDINGS_V2, MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2,
    MAX_ARTIFACT_REVIEW_RESULT_BYTES_V2, MAX_ARTIFACT_REVIEW_WORK_ITEMS_V2,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ArtifactReviewWorkItemNormalizationStatusV2 {
    Normalized,
    /// One or more valid positives were retained, but this work item's
    /// provider or finding coverage was not complete.
    PartiallyNormalized,
    ProviderFailed,
    Truncated,
    OutputLimitExceeded,
    InvalidModelOutputWire,
    ModelOutputBindingMismatch,
    TooManyFindings,
    AggregateFindingLimitExceeded,
    InvalidFindingWire,
    InvalidFindingReference,
    InvalidFindingEvidence,
}

impl ArtifactReviewWorkItemNormalizationStatusV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Normalized => "artifact_review_v2_work_item_normalized",
            Self::PartiallyNormalized => "artifact_review_v2_work_item_partially_normalized",
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
            Self::InvalidFindingWire => "artifact_review_v2_work_item_finding_wire_invalid",
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
    declared_finding_count: u64,
    structurally_valid_finding_count: u64,
    retained_finding_count: u64,
    deduplicated_finding_count: u64,
    rejected_finding_count: u64,
    rejection_reasons: Vec<ArtifactReviewWorkItemNormalizationStatusV2>,
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

    pub fn declared_finding_count(&self) -> u64 {
        self.declared_finding_count
    }

    pub fn structurally_valid_finding_count(&self) -> u64 {
        self.structurally_valid_finding_count
    }

    pub fn retained_finding_count(&self) -> u64 {
        self.retained_finding_count
    }

    pub fn deduplicated_finding_count(&self) -> u64 {
        self.deduplicated_finding_count
    }

    pub fn rejected_finding_count(&self) -> u64 {
        self.rejected_finding_count
    }

    /// Exact, sorted fail-closed reasons that made this work-item coverage
    /// incomplete. Structural duplicates are counted separately and are not a
    /// coverage failure.
    pub fn rejection_reasons(&self) -> &[ArtifactReviewWorkItemNormalizationStatusV2] {
        &self.rejection_reasons
    }

    pub fn coverage_complete(&self) -> bool {
        self.rejection_reasons.is_empty()
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

    pub fn coverage_complete(&self) -> bool {
        self.missing_work_item_ids.is_empty()
            && self
                .outcomes
                .iter()
                .all(ArtifactReviewWorkItemNormalizationOutcomeV2::coverage_complete)
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
struct ModelOutputEnvelopeWireV2 {
    schema_version: String,
    work_item_id: Sha256Digest,
    invocation_sha256: Sha256Digest,
    verdict: ArtifactReviewVerdictV2,
    findings: Vec<serde_json::Value>,
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
    model_identity_sha256: Sha256Digest,
    prompt_template_sha256: Sha256Digest,
    model_output_schema_sha256: Sha256Digest,
    adapter_result_schema_sha256: Sha256Digest,
    verdict: ArtifactReviewVerdictV2,
    findings: Vec<AdapterFindingWireV2>,
}

#[derive(Clone, Serialize, PartialEq, Eq)]
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
    finding_id_sha256: Sha256Digest,
    evidence_sha256: Sha256Digest,
    behavior_gate_eligible: bool,
    explanation: String,
}

#[derive(Clone)]
struct NormalizedFindingCandidateV2 {
    wire: AdapterFindingWireV2,
    source_work_item_id: Sha256Digest,
    model_finding_index: usize,
}

struct FindingCandidateGroupV2 {
    threat_class: ArtifactReviewThreatClassV2,
    representative: NormalizedFindingCandidateV2,
    canonical_lane_work_item_id: Sha256Digest,
    canonical_lane_finding_index: usize,
    occurrences: Vec<NormalizedFindingCandidateV2>,
}

struct WorkItemParseResultV2 {
    declared_finding_count: usize,
    candidates: Vec<NormalizedFindingCandidateV2>,
    rejected_finding_count: usize,
    rejection_reasons: Vec<ArtifactReviewWorkItemNormalizationStatusV2>,
}

struct WorkItemOutcomeBuilderV2 {
    work_item_id: Sha256Digest,
    provider_output_capture_sha256: Sha256Digest,
    provider_output_capture_byte_len: u64,
    declared_finding_count: usize,
    structurally_valid_finding_count: usize,
    retained_finding_count: usize,
    deduplicated_finding_count: usize,
    rejected_finding_count: usize,
    rejection_reasons: Vec<ArtifactReviewWorkItemNormalizationStatusV2>,
}

impl WorkItemOutcomeBuilderV2 {
    fn push_rejection_reason(&mut self, reason: ArtifactReviewWorkItemNormalizationStatusV2) {
        if reason != ArtifactReviewWorkItemNormalizationStatusV2::Normalized
            && reason != ArtifactReviewWorkItemNormalizationStatusV2::PartiallyNormalized
            && !self.rejection_reasons.contains(&reason)
        {
            self.rejection_reasons.push(reason);
        }
    }

    fn finish(
        mut self,
    ) -> Result<ArtifactReviewWorkItemNormalizationOutcomeV2, ArtifactReviewNormalizationErrorV2>
    {
        self.rejection_reasons.sort_unstable();
        self.rejection_reasons.dedup();
        let status = if self.rejection_reasons.is_empty() {
            ArtifactReviewWorkItemNormalizationStatusV2::Normalized
        } else if self.retained_finding_count > 0 || self.deduplicated_finding_count > 0 {
            ArtifactReviewWorkItemNormalizationStatusV2::PartiallyNormalized
        } else {
            self.rejection_reasons[0]
        };
        Ok(ArtifactReviewWorkItemNormalizationOutcomeV2 {
            work_item_id: self.work_item_id,
            provider_output_capture_sha256: self.provider_output_capture_sha256,
            provider_output_capture_byte_len: self.provider_output_capture_byte_len,
            status,
            declared_finding_count: u64::try_from(self.declared_finding_count)
                .map_err(|_| ArtifactReviewNormalizationErrorV2::Serialization)?,
            structurally_valid_finding_count: u64::try_from(self.structurally_valid_finding_count)
                .map_err(|_| ArtifactReviewNormalizationErrorV2::Serialization)?,
            retained_finding_count: u64::try_from(self.retained_finding_count)
                .map_err(|_| ArtifactReviewNormalizationErrorV2::Serialization)?,
            deduplicated_finding_count: u64::try_from(self.deduplicated_finding_count)
                .map_err(|_| ArtifactReviewNormalizationErrorV2::Serialization)?,
            rejected_finding_count: u64::try_from(self.rejected_finding_count)
                .map_err(|_| ArtifactReviewNormalizationErrorV2::Serialization)?,
            rejection_reasons: self.rejection_reasons,
        })
    }
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
    let mut outcome_builders = BTreeMap::<Sha256Digest, WorkItemOutcomeBuilderV2>::new();
    let mut finding_candidates = Vec::<NormalizedFindingCandidateV2>::new();
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
        let claim_status = if output.status == ArtifactReviewWorkItemStatusV2::Completed
            && !output.no_truncation_verified
        {
            ArtifactReviewWorkItemStatusV2::Truncated
        } else {
            output.status
        };
        let claim_no_truncation = claim_status != ArtifactReviewWorkItemStatusV2::Truncated
            && output.no_truncation_verified;
        let mut outcome_builder = WorkItemOutcomeBuilderV2 {
            work_item_id: output.work_item_id.clone(),
            provider_output_capture_sha256: provider_output_capture_sha256.clone(),
            provider_output_capture_byte_len,
            declared_finding_count: 0,
            structurally_valid_finding_count: 0,
            retained_finding_count: 0,
            deduplicated_finding_count: 0,
            rejected_finding_count: 0,
            rejection_reasons: Vec::new(),
        };
        match claim_status {
            ArtifactReviewWorkItemStatusV2::Completed => {}
            ArtifactReviewWorkItemStatusV2::Failed => outcome_builder
                .push_rejection_reason(ArtifactReviewWorkItemNormalizationStatusV2::ProviderFailed),
            ArtifactReviewWorkItemStatusV2::Truncated => outcome_builder
                .push_rejection_reason(ArtifactReviewWorkItemNormalizationStatusV2::Truncated),
        }
        if !output.no_truncation_verified
            && claim_status != ArtifactReviewWorkItemStatusV2::Truncated
        {
            outcome_builder
                .push_rejection_reason(ArtifactReviewWorkItemNormalizationStatusV2::Truncated);
        }
        if !output_fits_budget {
            outcome_builder.push_rejection_reason(
                ArtifactReviewWorkItemNormalizationStatusV2::OutputLimitExceeded,
            );
        } else {
            let parsed = normalize_work_item_output(
                output,
                work_item,
                &coverage_files,
                artifact,
                request.artifact_sha256(),
                &request_sha256,
                &expected_invocation_sha256,
            );
            outcome_builder.declared_finding_count = parsed.declared_finding_count;
            outcome_builder.structurally_valid_finding_count = parsed.candidates.len();
            outcome_builder.rejected_finding_count = parsed.rejected_finding_count;
            for reason in parsed.rejection_reasons {
                outcome_builder.push_rejection_reason(reason);
            }
            finding_candidates.extend(parsed.candidates);
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
        outcome_builders.insert(output.work_item_id.clone(), outcome_builder);
    }

    let finding_groups = group_finding_candidates(finding_candidates)?;
    let selected_finding_ids = fairly_select_finding_groups(&finding_groups);
    let mut findings = Vec::with_capacity(selected_finding_ids.len());
    for (finding_id, group) in finding_groups {
        if selected_finding_ids.contains(&finding_id) {
            let representative_source = (
                group.representative.source_work_item_id.clone(),
                group.representative.model_finding_index,
                group.representative.wire.evidence_sha256.clone(),
            );
            for occurrence in &group.occurrences {
                let occurrence_source = (
                    occurrence.source_work_item_id.clone(),
                    occurrence.model_finding_index,
                    occurrence.wire.evidence_sha256.clone(),
                );
                let builder = outcome_builders
                    .get_mut(&occurrence.source_work_item_id)
                    .ok_or(ArtifactReviewNormalizationErrorV2::UnknownWorkItem)?;
                if occurrence_source == representative_source {
                    builder.retained_finding_count += 1;
                } else {
                    builder.deduplicated_finding_count += 1;
                }
            }
            findings.push(group.representative.wire);
        } else {
            for occurrence in group.occurrences {
                let builder = outcome_builders
                    .get_mut(&occurrence.source_work_item_id)
                    .ok_or(ArtifactReviewNormalizationErrorV2::UnknownWorkItem)?;
                builder.rejected_finding_count += 1;
                builder.push_rejection_reason(
                    ArtifactReviewWorkItemNormalizationStatusV2::AggregateFindingLimitExceeded,
                );
            }
        }
    }
    findings.sort_by(|left, right| {
        left.finding_id_sha256
            .cmp(&right.finding_id_sha256)
            .then_with(|| left.evidence_sha256.cmp(&right.evidence_sha256))
    });
    let outcomes = outcome_builders
        .into_values()
        .map(WorkItemOutcomeBuilderV2::finish)
        .collect::<Result<Vec<_>, _>>()?;
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
        model_identity_sha256: request.model().identity_sha256(),
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

fn normalize_work_item_output(
    output: &ArtifactReviewProviderOutputV2,
    work_item: &crate::ArtifactReviewWorkItemV2,
    coverage_files: &HashMap<&Sha256Digest, &crate::ArtifactReviewFileCoverageV2>,
    artifact: &NormalizedArtifact,
    artifact_sha256: &Sha256Digest,
    request_sha256: &Sha256Digest,
    expected_invocation_sha256: &Sha256Digest,
) -> WorkItemParseResultV2 {
    let mut result = WorkItemParseResultV2 {
        declared_finding_count: 0,
        candidates: Vec::new(),
        rejected_finding_count: 0,
        rejection_reasons: Vec::new(),
    };
    if output.captured_output.is_empty() || std::str::from_utf8(&output.captured_output).is_err() {
        result
            .rejection_reasons
            .push(ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire);
        return result;
    }
    let mut deserializer = serde_json::Deserializer::from_slice(&output.captured_output);
    let wire = match ModelOutputEnvelopeWireV2::deserialize(&mut deserializer) {
        Ok(wire) if deserializer.end().is_ok() => wire,
        _ => {
            result
                .rejection_reasons
                .push(ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire);
            return result;
        }
    };
    if wire.schema_version != ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2
        || wire.work_item_id != output.work_item_id
        || &wire.invocation_sha256 != expected_invocation_sha256
    {
        result
            .rejection_reasons
            .push(ArtifactReviewWorkItemNormalizationStatusV2::ModelOutputBindingMismatch);
        return result;
    }
    result.declared_finding_count = wire.findings.len();
    if wire.findings.len() > MAX_ARTIFACT_REVIEW_FINDINGS_V2 {
        result
            .rejection_reasons
            .push(ArtifactReviewWorkItemNormalizationStatusV2::TooManyFindings);
    }
    // The declaration is intentionally advisory. Exact resolved findings win
    // asymmetrically; an unsupported suspicion without a range contributes no
    // finding and can never become a clean result.
    let _declared_verdict = wire.verdict;

    for (model_finding_index, finding_value) in wire.findings.into_iter().enumerate() {
        let model_finding = match serde_json::from_value::<ModelFindingWireV2>(finding_value) {
            Ok(finding) => finding,
            Err(_) => {
                result.rejected_finding_count += 1;
                if !result
                    .rejection_reasons
                    .contains(&ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingWire)
                {
                    result
                        .rejection_reasons
                        .push(ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingWire);
                }
                continue;
            }
        };
        match normalize_model_finding(
            output,
            work_item,
            coverage_files,
            artifact,
            artifact_sha256,
            request_sha256,
            model_finding_index,
            model_finding,
        ) {
            Ok(candidate) => result.candidates.push(candidate),
            Err(reason) => {
                result.rejected_finding_count += 1;
                if !result.rejection_reasons.contains(&reason) {
                    result.rejection_reasons.push(reason);
                }
            }
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn normalize_model_finding(
    output: &ArtifactReviewProviderOutputV2,
    work_item: &crate::ArtifactReviewWorkItemV2,
    coverage_files: &HashMap<&Sha256Digest, &crate::ArtifactReviewFileCoverageV2>,
    artifact: &NormalizedArtifact,
    artifact_sha256: &Sha256Digest,
    request_sha256: &Sha256Digest,
    model_finding_index: usize,
    model_finding: ModelFindingWireV2,
) -> Result<NormalizedFindingCandidateV2, ArtifactReviewWorkItemNormalizationStatusV2> {
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
    if !is_utf8_char_boundary(file.bytes(), start) || !is_utf8_char_boundary(file.bytes(), end) {
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
    let finding_id_sha256 =
        artifact_review_finding_identity_sha256_v2(ArtifactReviewFindingIdentityInputV2 {
            artifact_sha256,
            category: model_finding.category,
            file_id: work_item.file_id(),
            file_sha256: &file.sha256,
            context_id: &model_finding.context_id,
            context_kind: model_finding.context_kind,
            start_byte,
            end_byte,
            selected_sha256: &selected_sha256,
        });
    Ok(NormalizedFindingCandidateV2 {
        source_work_item_id: output.work_item_id.clone(),
        model_finding_index,
        wire: AdapterFindingWireV2 {
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
            finding_id_sha256,
            evidence_sha256,
            behavior_gate_eligible: false,
            explanation: model_finding.explanation,
        },
    })
}

fn group_finding_candidates(
    candidates: Vec<NormalizedFindingCandidateV2>,
) -> Result<BTreeMap<Sha256Digest, FindingCandidateGroupV2>, ArtifactReviewNormalizationErrorV2> {
    let mut groups = BTreeMap::<Sha256Digest, FindingCandidateGroupV2>::new();
    for candidate in candidates {
        let finding_id = candidate.wire.finding_id_sha256.clone();
        if let Some(group) = groups.get_mut(&finding_id) {
            if group.threat_class != candidate.wire.category.threat_class()
                || !same_structural_finding(&group.representative.wire, &candidate.wire)
            {
                return Err(ArtifactReviewNormalizationErrorV2::FindingDigestCollision);
            }
            let lane = (
                candidate.source_work_item_id.clone(),
                candidate.model_finding_index,
            );
            let current_lane = (
                group.canonical_lane_work_item_id.clone(),
                group.canonical_lane_finding_index,
            );
            if lane < current_lane {
                group.canonical_lane_work_item_id = lane.0;
                group.canonical_lane_finding_index = lane.1;
            }
            if candidate_is_better_representative(&candidate, &group.representative) {
                group.representative = candidate.clone();
            }
            group.occurrences.push(candidate);
        } else {
            groups.insert(
                finding_id.clone(),
                FindingCandidateGroupV2 {
                    threat_class: candidate.wire.category.threat_class(),
                    representative: candidate.clone(),
                    canonical_lane_work_item_id: candidate.source_work_item_id.clone(),
                    canonical_lane_finding_index: candidate.model_finding_index,
                    occurrences: vec![candidate],
                },
            );
        }
    }
    Ok(groups)
}

fn same_structural_finding(left: &AdapterFindingWireV2, right: &AdapterFindingWireV2) -> bool {
    left.category == right.category
        && left.file_id == right.file_id
        && left.file_sha256 == right.file_sha256
        && left.context_id == right.context_id
        && left.context_kind == right.context_kind
        && left.start_byte == right.start_byte
        && left.end_byte == right.end_byte
        && left.selected_sha256 == right.selected_sha256
}

fn candidate_is_better_representative(
    candidate: &NormalizedFindingCandidateV2,
    current: &NormalizedFindingCandidateV2,
) -> bool {
    finding_severity_rank(candidate.wire.severity)
        .cmp(&finding_severity_rank(current.wire.severity))
        .then_with(|| {
            current
                .wire
                .evidence_sha256
                .cmp(&candidate.wire.evidence_sha256)
        })
        .then_with(|| {
            current
                .source_work_item_id
                .cmp(&candidate.source_work_item_id)
        })
        .then_with(|| {
            current
                .model_finding_index
                .cmp(&candidate.model_finding_index)
        })
        .is_gt()
}

fn finding_severity_rank(severity: ArtifactReviewFindingSeverityV2) -> u8 {
    match severity {
        ArtifactReviewFindingSeverityV2::Low => 0,
        ArtifactReviewFindingSeverityV2::Medium => 1,
        ArtifactReviewFindingSeverityV2::High => 2,
        ArtifactReviewFindingSeverityV2::Critical => 3,
    }
}

struct FairClassQueuesV2 {
    lane_ids: Vec<Sha256Digest>,
    queues: BTreeMap<Sha256Digest, VecDeque<Sha256Digest>>,
    next_lane: usize,
}

fn fairly_select_finding_groups(
    groups: &BTreeMap<Sha256Digest, FindingCandidateGroupV2>,
) -> HashSet<Sha256Digest> {
    if groups.len() <= MAX_ARTIFACT_REVIEW_FINDINGS_V2 {
        return groups.keys().cloned().collect();
    }
    let mut class_queues = BTreeMap::<ArtifactReviewThreatClassV2, FairClassQueuesV2>::new();
    for (finding_id, group) in groups {
        let class = class_queues
            .entry(group.threat_class)
            .or_insert_with(|| FairClassQueuesV2 {
                lane_ids: Vec::new(),
                queues: BTreeMap::new(),
                next_lane: 0,
            });
        class
            .queues
            .entry(group.canonical_lane_work_item_id.clone())
            .or_default()
            .push_back(finding_id.clone());
    }
    for class in class_queues.values_mut() {
        class.lane_ids = class.queues.keys().cloned().collect();
    }

    let mut selected = HashSet::with_capacity(MAX_ARTIFACT_REVIEW_FINDINGS_V2);
    while selected.len() < MAX_ARTIFACT_REVIEW_FINDINGS_V2 {
        let mut made_progress = false;
        for class in class_queues.values_mut() {
            if selected.len() == MAX_ARTIFACT_REVIEW_FINDINGS_V2 {
                break;
            }
            let lane_count = class.lane_ids.len();
            if lane_count == 0 {
                continue;
            }
            for _ in 0..lane_count {
                let lane_index = class.next_lane % lane_count;
                class.next_lane = (class.next_lane + 1) % lane_count;
                let lane_id = &class.lane_ids[lane_index];
                if let Some(finding_id) =
                    class.queues.get_mut(lane_id).and_then(VecDeque::pop_front)
                {
                    selected.insert(finding_id);
                    made_progress = true;
                    break;
                }
            }
        }
        if !made_progress {
            break;
        }
    }
    selected
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
