//! Offline, exact-byte projection of selected deterministic capability findings.
//!
//! This module is intentionally narrow. It reopens, normalizes, and analyzes an
//! npm or PyPI archive directly through the artifact and detector contracts, then emits
//! only citation-complete projections from a closed capability allowlist. It has
//! no package execution, networking, AI, VM, admission, or observed-clean path.

use crate::exact_artifact::{
    checked_filename, declared_format_for, manifest_requires_external_resolution,
    read_exact_artifact,
};
use crate::{
    ExactArtifactEvidenceReferenceV1, ExactArtifactFindingKindV1,
    ExactArtifactObservationConfidenceV1, ExactArtifactObservationCoverageV1,
    ExactArtifactObservationSourceV1, ExactArtifactObservationV1, ExactArtifactStageStatusV1,
    ExactArtifactThreatClassV1,
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::Path;
use whoathere_artifact::{
    detect_artifact_format, normalize_artifact, AcquisitionMethod, ArtifactEnvelope,
    ArtifactEnvelopeInput, ArtifactFormat, ArtifactSourceType, Ecosystem, NormalizationLimits,
    Sha256Digest,
};
use whoathere_detector::{
    analyze_normalized_artifact, ArtifactAnalysisCompleteness, ArtifactAnalysisOutcome,
    ArtifactFindingCategory, EvidenceRange, FindingConfidence, FindingLocation, FindingSpecificity,
};

pub const STATIC_PROJECTION_METADATA_SCHEMA_V1: &str =
    "whoathere.static_download_execute_projection_metadata.v1";
pub const STATIC_SENSITIVE_FILE_EXFILTRATION_PROJECTION_METADATA_SCHEMA_V1: &str =
    "whoathere.static_sensitive_file_exfiltration_projection_metadata.v1";
pub const STATIC_PROJECTION_SOURCE_RECEIPT_SCHEMA_V1: &str =
    whoathere_detector::ARTIFACT_STATIC_ANALYSIS_SCHEMA_VERSION;
pub const STATIC_PROJECTION_KIND_V1: &str = "static_download_execute_capability";
pub const STATIC_SENSITIVE_FILE_EXFILTRATION_PROJECTION_KIND_V1: &str =
    "static_sensitive_file_exfiltration_capability";
pub const STATIC_PROJECTION_CLAIM_BOUNDARY_V1: &str =
    "Verified deterministic capability only; no runtime-attempt, observed-clean, release, or admission authority.";

const EXIT_INCONCLUSIVE: i32 = 22;
const EXIT_DATA_ERROR: i32 = 65;
const EXIT_INTERNAL_ERROR: i32 = 70;

/// Closed set of deterministic findings this verifier is allowed to publish.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticProjectionKindV1 {
    DownloadExecuteCapability,
    SensitiveFileExfiltrationCapability,
}

impl StaticProjectionKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DownloadExecuteCapability => STATIC_PROJECTION_KIND_V1,
            Self::SensitiveFileExfiltrationCapability => {
                STATIC_SENSITIVE_FILE_EXFILTRATION_PROJECTION_KIND_V1
            }
        }
    }

    pub const fn metadata_schema(self) -> &'static str {
        match self {
            Self::DownloadExecuteCapability => STATIC_PROJECTION_METADATA_SCHEMA_V1,
            Self::SensitiveFileExfiltrationCapability => {
                STATIC_SENSITIVE_FILE_EXFILTRATION_PROJECTION_METADATA_SCHEMA_V1
            }
        }
    }

    const fn finding_category(self) -> ArtifactFindingCategory {
        match self {
            Self::DownloadExecuteCapability => ArtifactFindingCategory::DownloadExecuteCapability,
            Self::SensitiveFileExfiltrationCapability => {
                ArtifactFindingCategory::SensitiveFileExfiltrationCapability
            }
        }
    }

    const fn threat_class(self) -> ExactArtifactThreatClassV1 {
        match self {
            Self::DownloadExecuteCapability => {
                ExactArtifactThreatClassV1::SecondStageNativeOrWasmHandoff
            }
            Self::SensitiveFileExfiltrationCapability => {
                ExactArtifactThreatClassV1::NetworkAndExfiltration
            }
        }
    }

    const fn envelope_policy_version(self) -> &'static str {
        match self {
            Self::DownloadExecuteCapability => "static-download-execute-projection-v1",
            Self::SensitiveFileExfiltrationCapability => {
                "static-sensitive-file-exfiltration-projection-v1"
            }
        }
    }

    const fn not_found_reason_code(self) -> &'static str {
        match self {
            Self::DownloadExecuteCapability => {
                "static_projection_download_execute_capability_not_found"
            }
            Self::SensitiveFileExfiltrationCapability => {
                "static_projection_sensitive_file_exfiltration_capability_not_found"
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StaticProjectionRequestV1<'a> {
    pub artifact_path: &'a Path,
    pub ecosystem: Ecosystem,
    pub acquired_at: &'a str,
    pub expected_artifact_sha256: &'a Sha256Digest,
    pub normalization_limits: NormalizationLimits,
}

/// The exact ten-field projection accepted by the RunResultV2 publisher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticDownloadExecuteCapabilityProjectionV1 {
    pub kind: &'static str,
    pub artifact_sha256: Sha256Digest,
    pub artifact_manifest_sha256: Sha256Digest,
    pub exact_observation_sha256: Sha256Digest,
    pub finding_evidence_sha256: Sha256Digest,
    pub file_id: Sha256Digest,
    pub file_sha256: Sha256Digest,
    pub range: EvidenceRange,
    pub selected_bytes_sha256: Sha256Digest,
    pub source_receipt_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeterministicStaticVerificationSummaryV1 {
    pub source_receipt_schema: &'static str,
    pub verification_method: &'static str,
    pub artifact_sha256: Sha256Digest,
    pub artifact_manifest_sha256: Sha256Digest,
    pub ecosystem: Ecosystem,
    pub artifact_format: ArtifactFormat,
    pub deterministic_analysis_sha256: Sha256Digest,
    pub deterministic_analysis_status: ExactArtifactStageStatusV1,
    pub deterministic_reason_codes: Vec<String>,
    pub exact_observations: Vec<ExactArtifactObservationV1>,
    pub package_execution_applied: bool,
    pub network_access_applied: bool,
    pub ai_applied: bool,
    pub vm_applied: bool,
    pub admission_authority: bool,
    pub observed_clean: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticProjectionMetadataV1 {
    pub schema: &'static str,
    pub verification_status: &'static str,
    pub claim_boundary: &'static str,
    pub verification_summary: DeterministicStaticVerificationSummaryV1,
    pub source_receipt_sha256: Sha256Digest,
    pub projections: Vec<StaticDownloadExecuteCapabilityProjectionV1>,
    pub projection_count: usize,
    pub admission_authority: bool,
    pub observed_clean: bool,
}

impl StaticProjectionMetadataV1 {
    /// Sorted-key, compact UTF-8 JSON with one trailing LF, matching the
    /// publisher's canonical JSON convention.
    pub fn canonical_json_bytes(&self) -> Result<Vec<u8>, StaticProjectionErrorV1> {
        canonical_json_bytes(self, self.schema)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticProjectionErrorV1 {
    reason_code: &'static str,
    exit_code: i32,
    metadata_schema: &'static str,
}

impl StaticProjectionErrorV1 {
    const fn inconclusive(
        projection_kind: StaticProjectionKindV1,
        reason_code: &'static str,
    ) -> Self {
        Self {
            reason_code,
            exit_code: EXIT_INCONCLUSIVE,
            metadata_schema: projection_kind.metadata_schema(),
        }
    }

    const fn data(projection_kind: StaticProjectionKindV1, reason_code: &'static str) -> Self {
        Self {
            reason_code,
            exit_code: EXIT_DATA_ERROR,
            metadata_schema: projection_kind.metadata_schema(),
        }
    }

    const fn internal(projection_kind: StaticProjectionKindV1, reason_code: &'static str) -> Self {
        Self {
            reason_code,
            exit_code: EXIT_INTERNAL_ERROR,
            metadata_schema: projection_kind.metadata_schema(),
        }
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn canonical_json_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(
            &serde_json::json!({
                "schema": self.metadata_schema,
                "verification_status": "failed",
                "reason_codes": [self.reason_code],
                "exit_code": self.exit_code,
                "admission_authority": false,
                "observed_clean": false,
            }),
            self.metadata_schema,
        )
        .unwrap_or_else(|_| format!(
            "{{\"admission_authority\":false,\"exit_code\":70,\"observed_clean\":false,\"reason_codes\":[\"static_projection_error_serialization_failed\"],\"schema\":\"{}\",\"verification_status\":\"failed\"}}\n",
            self.metadata_schema
        ).into_bytes())
    }
}

impl std::fmt::Display for StaticProjectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for StaticProjectionErrorV1 {}

/// Reopen and independently analyze one exact package archive, emitting only
/// publisher-compatible, citation-complete download/execute projections.
pub fn verify_static_download_execute_projections_v1(
    request: StaticProjectionRequestV1<'_>,
) -> Result<StaticProjectionMetadataV1, StaticProjectionErrorV1> {
    verify_static_projections_v1(request, StaticProjectionKindV1::DownloadExecuteCapability)
}

/// Reopen and independently analyze one exact package archive, emitting only
/// publisher-compatible, citation-complete sensitive-file/exfiltration
/// capability projections.
pub fn verify_static_sensitive_file_exfiltration_projections_v1(
    request: StaticProjectionRequestV1<'_>,
) -> Result<StaticProjectionMetadataV1, StaticProjectionErrorV1> {
    verify_static_projections_v1(
        request,
        StaticProjectionKindV1::SensitiveFileExfiltrationCapability,
    )
}

/// Reopen and independently analyze one exact package archive using one closed
/// projection policy.
pub fn verify_static_projections_v1(
    request: StaticProjectionRequestV1<'_>,
    projection_kind: StaticProjectionKindV1,
) -> Result<StaticProjectionMetadataV1, StaticProjectionErrorV1> {
    if !request.artifact_path.is_absolute() {
        return Err(StaticProjectionErrorV1::data(
            projection_kind,
            "static_projection_artifact_path_not_absolute",
        ));
    }
    let filename = checked_filename(request.artifact_path).map_err(|_| {
        StaticProjectionErrorV1::data(projection_kind, "static_projection_filename_invalid")
    })?;
    let bytes =
        read_exact_artifact(request.artifact_path, request.normalization_limits).map_err(|_| {
            StaticProjectionErrorV1::data(projection_kind, "static_projection_artifact_unreadable")
        })?;
    let artifact_sha256 = Sha256Digest::from_bytes(&bytes);
    if &artifact_sha256 != request.expected_artifact_sha256 {
        return Err(StaticProjectionErrorV1::data(
            projection_kind,
            "static_projection_expected_artifact_digest_mismatch",
        ));
    }
    let detected_format =
        detect_artifact_format(request.ecosystem, &filename, &bytes).map_err(|_| {
            StaticProjectionErrorV1::data(
                projection_kind,
                "static_projection_artifact_format_invalid",
            )
        })?;
    let declared_format = declared_format_for(request.ecosystem, &filename).ok_or_else(|| {
        StaticProjectionErrorV1::data(
            projection_kind,
            "static_projection_declared_format_unsupported",
        )
    })?;
    if detected_format != declared_format {
        return Err(StaticProjectionErrorV1::data(
            projection_kind,
            "static_projection_declared_format_mismatch",
        ));
    }
    let mut envelope_input = ArtifactEnvelopeInput {
        ecosystem: request.ecosystem,
        package_name: None,
        package_version: None,
        source_coordinate: format!("local-file:{artifact_sha256}"),
        source_type: ArtifactSourceType::LocalFile,
        acquired_at: request.acquired_at.to_string(),
        acquisition_method: AcquisitionMethod::LocalFileImport,
        original_filename: filename,
        declared_format: Some(declared_format),
        custody_reference: format!("independent-static-verifier:{artifact_sha256}"),
        resolver_metadata_sha256: None,
        registry_metadata_sha256: None,
        policy_version: projection_kind.envelope_policy_version().to_string(),
        requires_external_dependency_resolution: false,
    };
    let mut envelope =
        ArtifactEnvelope::from_original_bytes(envelope_input.clone(), &bytes, detected_format);
    envelope.validate().map_err(|_| {
        StaticProjectionErrorV1::data(projection_kind, "static_projection_envelope_invalid")
    })?;
    let mut normalized = normalize_artifact(&envelope, &bytes, request.normalization_limits)
        .map_err(|_| {
            StaticProjectionErrorV1::data(projection_kind, "static_projection_normalization_failed")
        })?;
    let closure_required = manifest_requires_external_resolution(&normalized.manifest);
    if closure_required {
        envelope_input.requires_external_dependency_resolution = true;
        envelope = ArtifactEnvelope::from_original_bytes(envelope_input, &bytes, detected_format);
        envelope.validate().map_err(|_| {
            StaticProjectionErrorV1::data(projection_kind, "static_projection_envelope_invalid")
        })?;
        normalized =
            normalize_artifact(&envelope, &bytes, request.normalization_limits).map_err(|_| {
                StaticProjectionErrorV1::data(
                    projection_kind,
                    "static_projection_normalization_failed",
                )
            })?;
    }
    normalized.validate().map_err(|_| {
        StaticProjectionErrorV1::data(
            projection_kind,
            "static_projection_normalized_artifact_invalid",
        )
    })?;
    if normalized.manifest.artifact_sha256 != artifact_sha256
        || normalized.manifest.magic_detected_format != detected_format
    {
        return Err(StaticProjectionErrorV1::internal(
            projection_kind,
            "static_projection_normalized_artifact_binding_invalid",
        ));
    }
    let analysis = analyze_normalized_artifact(&normalized).map_err(|_| {
        StaticProjectionErrorV1::data(projection_kind, "static_projection_analysis_failed")
    })?;
    analysis.validate(&normalized).map_err(|_| {
        StaticProjectionErrorV1::data(projection_kind, "static_projection_analysis_invalid")
    })?;
    let deterministic_analysis_sha256 = analysis.analysis_sha256().map_err(|_| {
        StaticProjectionErrorV1::internal(
            projection_kind,
            "static_projection_analysis_digest_failed",
        )
    })?;
    let manifest_sha256 = normalized.manifest.manifest_sha256.clone();
    let (coverage, coverage_gap_codes) = match analysis.coverage.completeness {
        ArtifactAnalysisCompleteness::Complete => {
            (ExactArtifactObservationCoverageV1::Complete, Vec::new())
        }
        ArtifactAnalysisCompleteness::Incomplete => (
            ExactArtifactObservationCoverageV1::Incomplete,
            vec!["deterministic_analysis_coverage_incomplete".to_string()],
        ),
    };

    let mut exact_observations = Vec::new();
    for finding in analysis
        .findings
        .iter()
        .filter(|finding| finding.category == projection_kind.finding_category())
    {
        if finding.specificity != FindingSpecificity::PackageSpecific
            || finding.artifact_sha256 != artifact_sha256
            || finding.manifest_sha256 != manifest_sha256
        {
            return Err(StaticProjectionErrorV1::internal(
                projection_kind,
                "static_projection_finding_binding_invalid",
            ));
        }
        let observation = ExactArtifactObservationV1::new(
            ExactArtifactObservationSourceV1::DeterministicStatic,
            projection_kind.threat_class(),
            ExactArtifactFindingKindV1::DeterministicStatic(projection_kind.finding_category()),
            match finding.confidence {
                FindingConfidence::Moderate => ExactArtifactObservationConfidenceV1::Moderate,
                FindingConfidence::High => ExactArtifactObservationConfidenceV1::High,
            },
            artifact_sha256.clone(),
            manifest_sha256.clone(),
            ExactArtifactEvidenceReferenceV1::DeterministicStatic {
                evidence_sha256: finding.evidence_digest.clone(),
                location: finding.location.clone(),
            },
            coverage,
            coverage_gap_codes.clone(),
            true,
        )
        .map_err(|_| {
            StaticProjectionErrorV1::internal(
                projection_kind,
                "static_projection_exact_observation_digest_invalid",
            )
        })?;
        match &observation.evidence {
            ExactArtifactEvidenceReferenceV1::DeterministicStatic {
                location: FindingLocation::File { .. },
                ..
            } => exact_observations.push(observation),
            ExactArtifactEvidenceReferenceV1::DeterministicStatic {
                location: FindingLocation::None { .. },
                ..
            }
            | ExactArtifactEvidenceReferenceV1::AiSourceReview { .. }
            | ExactArtifactEvidenceReferenceV1::AiBehavioral { .. } => {
                return Err(StaticProjectionErrorV1::internal(
                    projection_kind,
                    "static_projection_citation_not_file_bound",
                ));
            }
        }
    }
    exact_observations
        .sort_by(|left, right| left.observation_sha256.cmp(&right.observation_sha256));
    if exact_observations.is_empty() {
        return Err(StaticProjectionErrorV1::inconclusive(
            projection_kind,
            projection_kind.not_found_reason_code(),
        ));
    }

    let deterministic_analysis_status = match analysis.outcome {
        ArtifactAnalysisOutcome::Findings => ExactArtifactStageStatusV1::Findings,
        ArtifactAnalysisOutcome::FindingsWithIncompleteCoverage => {
            ExactArtifactStageStatusV1::FindingsWithIncompleteCoverage
        }
        ArtifactAnalysisOutcome::BoundedNoFinding => ExactArtifactStageStatusV1::Complete,
        ArtifactAnalysisOutcome::IncompleteNoFinding => ExactArtifactStageStatusV1::Incomplete,
    };
    let mut deterministic_reason_codes = analysis.coverage.limitations.clone();
    if analysis.coverage.completeness == ArtifactAnalysisCompleteness::Incomplete {
        deterministic_reason_codes
            .push("exact_artifact_deterministic_coverage_incomplete".to_string());
    }
    deterministic_reason_codes.push("exact_artifact_deterministic_findings".to_string());
    deterministic_reason_codes.sort();
    deterministic_reason_codes.dedup();
    let verification_summary = DeterministicStaticVerificationSummaryV1 {
        source_receipt_schema: STATIC_PROJECTION_SOURCE_RECEIPT_SCHEMA_V1,
        verification_method: "exact_archive_reopen_normalize_redetect_v1",
        artifact_sha256: artifact_sha256.clone(),
        artifact_manifest_sha256: manifest_sha256.clone(),
        ecosystem: request.ecosystem,
        artifact_format: detected_format,
        deterministic_analysis_sha256: deterministic_analysis_sha256.clone(),
        deterministic_analysis_status,
        deterministic_reason_codes,
        exact_observations,
        package_execution_applied: false,
        network_access_applied: false,
        ai_applied: false,
        vm_applied: false,
        admission_authority: false,
        observed_clean: false,
    };
    // The complete, freshly recomputed ArtifactStaticAnalysis is the source
    // receipt. This is exactly the deterministic-stage result digest already
    // emitted by the product spine; the summary above is not a substitute
    // preimage and is deliberately not hashed as the source receipt.
    let source_receipt_sha256 = deterministic_analysis_sha256;

    let mut projections = Vec::with_capacity(verification_summary.exact_observations.len());
    for observation in &verification_summary.exact_observations {
        let ExactArtifactEvidenceReferenceV1::DeterministicStatic {
            evidence_sha256,
            location:
                FindingLocation::File {
                    file_id,
                    file_sha256,
                    range,
                    selected_bytes_sha256,
                },
        } = &observation.evidence
        else {
            return Err(StaticProjectionErrorV1::internal(
                projection_kind,
                "static_projection_citation_not_file_bound",
            ));
        };
        projections.push(StaticDownloadExecuteCapabilityProjectionV1 {
            kind: projection_kind.as_str(),
            artifact_sha256: artifact_sha256.clone(),
            artifact_manifest_sha256: manifest_sha256.clone(),
            exact_observation_sha256: observation.observation_sha256.clone(),
            finding_evidence_sha256: evidence_sha256.clone(),
            file_id: file_id.clone(),
            file_sha256: file_sha256.clone(),
            range: range.clone(),
            selected_bytes_sha256: selected_bytes_sha256.clone(),
            source_receipt_sha256: source_receipt_sha256.clone(),
        });
    }
    projections.sort_by(|left, right| {
        left.exact_observation_sha256
            .cmp(&right.exact_observation_sha256)
    });

    Ok(StaticProjectionMetadataV1 {
        schema: projection_kind.metadata_schema(),
        verification_status: "verified",
        claim_boundary: STATIC_PROJECTION_CLAIM_BOUNDARY_V1,
        verification_summary,
        source_receipt_sha256,
        projection_count: projections.len(),
        projections,
        admission_authority: false,
        observed_clean: false,
    })
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    metadata_schema: &'static str,
) -> Result<Vec<u8>, StaticProjectionErrorV1> {
    let serialization_error = || StaticProjectionErrorV1 {
        reason_code: "static_projection_serialization_failed",
        exit_code: EXIT_INTERNAL_ERROR,
        metadata_schema,
    };
    let value = serde_json::to_value(value).map_err(|_| serialization_error())?;
    let mut bytes =
        serde_json::to_vec(&sorted_json_value(value)).map_err(|_| serialization_error())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sorted_json_value(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sorted_json_value).collect()),
        Value::Object(values) => {
            let ordered = values
                .into_iter()
                .map(|(key, value)| (key, sorted_json_value(value)))
                .collect::<BTreeMap<_, _>>();
            let mut result = Map::new();
            for (key, value) in ordered {
                result.insert(key, value);
            }
            Value::Object(result)
        }
        scalar => scalar,
    }
}
