//! One exact-artifact product spine.
//!
//! This module deliberately stops short of authorization. It binds quarantine,
//! normalization, deterministic analysis, and typed scenario intent to one
//! original artifact digest. Optional AI and detonation implementations must be
//! attached explicitly and must return evidence bound to a product-computed
//! request covering provider, artifact, envelope, manifest, deterministic
//! analysis, and scenario-plan identities.

use crate::{prepare_quarantined_artifact, PreparedArtifact};
use serde::{Deserialize, Serialize};
use std::fs::{Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use whoathere_artifact::{
    AcquisitionMethod, ArtifactEnvelopeInput, ArtifactFormat, ArtifactSourceType, Ecosystem,
    NormalizationCompleteness, NormalizationLimits, Sha256Digest,
};
use whoathere_cache::{PersistentQuarantineCas, VerifiedArtifactLease};
use whoathere_detector::{
    ArtifactAnalysisCompleteness, ArtifactAnalysisOutcome, ArtifactFindingCategory,
    ArtifactReviewFindingCategoryV2, ArtifactReviewThreatClassV2, ArtifactStaticAnalysis,
    BehaviorAnalysisBundleV1, BehaviorEvidenceReferenceV1, BehaviorFindingKindV1,
    BehaviorThreatClassV1, FindingConfidence, FindingLocation, FindingSpecificity,
};
use whoathere_detonation::{
    expected_sdist_scenario_kinds_v1, expected_wheel_scenario_kinds_v1, ArtifactScenarioKindV1,
    NpmEnvironmentProfileV1, SdistScenarioKindV1, WheelScenarioKindV1,
};

pub const EXACT_ARTIFACT_INSPECTION_SCHEMA_V1: &str = "whoathere.exact_artifact_inspection.v1";
pub const EXACT_ARTIFACT_SCENARIO_INTENT_SCHEMA_V1: &str =
    "whoathere.exact_artifact_scenario_intent.v1";
pub const EXACT_ARTIFACT_SCENARIO_PLAN_SCHEMA_V1: &str =
    "whoathere.exact_artifact_scenario_plan.v1";
pub const EXACT_ARTIFACT_ADAPTER_REQUEST_SCHEMA_V1: &str =
    "whoathere.exact_artifact_adapter_request.v1";
pub const EXACT_ARTIFACT_OPTIONAL_RESULT_SCHEMA_V1: &str =
    "whoathere.exact_artifact_optional_result.v1";
pub const EXACT_ARTIFACT_OBSERVATION_SCHEMA_V1: &str = "whoathere.exact_artifact_observation.v1";
pub const MAX_EXACT_ARTIFACT_OPTIONAL_RESULT_BYTES_V1: usize = 256 * 1024;
const MAX_EXACT_ARTIFACT_OBSERVATIONS_V1: usize = 4_096;
const MAX_EXACT_ARTIFACT_BEHAVIOR_BUNDLES_V1: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactObservationSourceV1 {
    DeterministicStatic,
    AiSourceReview,
    AiBehavioral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactObservationConfidenceV1 {
    Moderate,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactObservationCoverageV1 {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactThreatClassV1 {
    CredentialAndSensitiveFileDiscovery,
    NetworkAndExfiltration,
    SecondStageNativeOrWasmHandoff,
    ProcessExecutionAndDynamicLoading,
    ObfuscationAndPacking,
    EnvironmentAndTimeGating,
    PersistenceDestructionAndSelfDeletion,
    RepositoryPackageAndSelfPropagation,
    DependencyIndirection,
    ImportTimeTampering,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "source",
    content = "kind",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ExactArtifactFindingKindV1 {
    DeterministicStatic(ArtifactFindingCategory),
    AiSourceReview(ArtifactReviewFindingCategoryV2),
    AiBehavioral(BehaviorFindingKindV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExactArtifactEvidenceReferenceV1 {
    DeterministicStatic {
        evidence_sha256: Sha256Digest,
        location: FindingLocation,
    },
    AiSourceReview {
        finding_id_sha256: Sha256Digest,
        evidence_sha256: Sha256Digest,
        file_id: Sha256Digest,
        file_sha256: Sha256Digest,
        start_byte: u64,
        end_byte: u64,
        start_line: u64,
        end_line: u64,
        selected_sha256: Sha256Digest,
    },
    AiBehavioral {
        bundle_sha256: Sha256Digest,
        finding_sha256: Sha256Digest,
        events: Vec<BehaviorEvidenceReferenceV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactObservationV1 {
    pub schema_version: String,
    pub source: ExactArtifactObservationSourceV1,
    pub threat_class: ExactArtifactThreatClassV1,
    pub finding_kind: ExactArtifactFindingKindV1,
    pub confidence: ExactArtifactObservationConfidenceV1,
    pub artifact_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub evidence: ExactArtifactEvidenceReferenceV1,
    pub coverage: ExactArtifactObservationCoverageV1,
    pub coverage_gap_codes: Vec<String>,
    pub behavior_detection_eligible: bool,
    pub observation_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExactArtifactObservationDigestWireV1<'a> {
    schema_version: &'static str,
    source: ExactArtifactObservationSourceV1,
    threat_class: ExactArtifactThreatClassV1,
    finding_kind: &'a ExactArtifactFindingKindV1,
    confidence: ExactArtifactObservationConfidenceV1,
    artifact_sha256: &'a Sha256Digest,
    manifest_sha256: &'a Sha256Digest,
    evidence: &'a ExactArtifactEvidenceReferenceV1,
    coverage: ExactArtifactObservationCoverageV1,
    coverage_gap_codes: &'a [String],
    behavior_detection_eligible: bool,
}

impl ExactArtifactObservationV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        source: ExactArtifactObservationSourceV1,
        threat_class: ExactArtifactThreatClassV1,
        finding_kind: ExactArtifactFindingKindV1,
        confidence: ExactArtifactObservationConfidenceV1,
        artifact_sha256: Sha256Digest,
        manifest_sha256: Sha256Digest,
        evidence: ExactArtifactEvidenceReferenceV1,
        coverage: ExactArtifactObservationCoverageV1,
        coverage_gap_codes: Vec<String>,
        behavior_detection_eligible: bool,
    ) -> Result<Self, OptionalAdapterErrorV1> {
        let coverage_gap_codes = sorted_unique(coverage_gap_codes);
        let wire = ExactArtifactObservationDigestWireV1 {
            schema_version: EXACT_ARTIFACT_OBSERVATION_SCHEMA_V1,
            source,
            threat_class,
            finding_kind: &finding_kind,
            confidence,
            artifact_sha256: &artifact_sha256,
            manifest_sha256: &manifest_sha256,
            evidence: &evidence,
            coverage,
            coverage_gap_codes: &coverage_gap_codes,
            behavior_detection_eligible,
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| {
            OptionalAdapterErrorV1::new("exact_artifact_observation_serialization_failed")
        })?;
        let observation = Self {
            schema_version: EXACT_ARTIFACT_OBSERVATION_SCHEMA_V1.to_string(),
            source,
            threat_class,
            finding_kind,
            confidence,
            artifact_sha256,
            manifest_sha256,
            evidence,
            coverage,
            coverage_gap_codes,
            behavior_detection_eligible,
            observation_sha256: Sha256Digest::from_bytes(&bytes),
        };
        observation.validate()?;
        Ok(observation)
    }

    fn validate(&self) -> Result<(), OptionalAdapterErrorV1> {
        let source_matches = matches!(
            (&self.source, &self.finding_kind, &self.evidence),
            (
                ExactArtifactObservationSourceV1::DeterministicStatic,
                ExactArtifactFindingKindV1::DeterministicStatic(_),
                ExactArtifactEvidenceReferenceV1::DeterministicStatic { .. }
            ) | (
                ExactArtifactObservationSourceV1::AiSourceReview,
                ExactArtifactFindingKindV1::AiSourceReview(_),
                ExactArtifactEvidenceReferenceV1::AiSourceReview { .. }
            ) | (
                ExactArtifactObservationSourceV1::AiBehavioral,
                ExactArtifactFindingKindV1::AiBehavioral(_),
                ExactArtifactEvidenceReferenceV1::AiBehavioral { .. }
            )
        );
        let threat_class_matches = match &self.finding_kind {
            ExactArtifactFindingKindV1::DeterministicStatic(category) => {
                self.threat_class == deterministic_threat_class_v1(*category)
            }
            ExactArtifactFindingKindV1::AiSourceReview(category) => {
                self.threat_class == review_threat_class_v1((*category).threat_class())
            }
            ExactArtifactFindingKindV1::AiBehavioral(kind) => {
                self.threat_class == behavior_threat_class_v1((*kind).threat_class())
            }
        };
        let eligibility_valid = match &self.finding_kind {
            ExactArtifactFindingKindV1::AiSourceReview(_) => !self.behavior_detection_eligible,
            ExactArtifactFindingKindV1::AiBehavioral(kind) => {
                self.behavior_detection_eligible == behavior_finding_detection_eligible_v1(*kind)
            }
            ExactArtifactFindingKindV1::DeterministicStatic(_) => true,
        };
        let coverage_valid = match self.coverage {
            ExactArtifactObservationCoverageV1::Complete => self.coverage_gap_codes.is_empty(),
            ExactArtifactObservationCoverageV1::Incomplete => !self.coverage_gap_codes.is_empty(),
        };
        let codes_valid = self.coverage_gap_codes.len() <= 128
            && self.coverage_gap_codes == sorted_unique(self.coverage_gap_codes.clone())
            && self
                .coverage_gap_codes
                .iter()
                .all(|code| valid_reason_code(code));
        let evidence_valid = match &self.evidence {
            ExactArtifactEvidenceReferenceV1::DeterministicStatic { .. } => true,
            ExactArtifactEvidenceReferenceV1::AiSourceReview {
                start_byte,
                end_byte,
                start_line,
                end_line,
                ..
            } => start_byte < end_byte && *start_line > 0 && start_line <= end_line,
            ExactArtifactEvidenceReferenceV1::AiBehavioral { events, .. } => {
                !events.is_empty()
                    && events.len() <= 128
                    && events.windows(2).all(|pair| pair[0] < pair[1])
            }
        };
        let wire = ExactArtifactObservationDigestWireV1 {
            schema_version: EXACT_ARTIFACT_OBSERVATION_SCHEMA_V1,
            source: self.source,
            threat_class: self.threat_class,
            finding_kind: &self.finding_kind,
            confidence: self.confidence,
            artifact_sha256: &self.artifact_sha256,
            manifest_sha256: &self.manifest_sha256,
            evidence: &self.evidence,
            coverage: self.coverage,
            coverage_gap_codes: &self.coverage_gap_codes,
            behavior_detection_eligible: self.behavior_detection_eligible,
        };
        let digest_valid = serde_json::to_vec(&wire)
            .map(|bytes| Sha256Digest::from_bytes(&bytes) == self.observation_sha256)
            .unwrap_or(false);
        if self.schema_version != EXACT_ARTIFACT_OBSERVATION_SCHEMA_V1
            || !source_matches
            || !threat_class_matches
            || !eligibility_valid
            || !coverage_valid
            || !codes_valid
            || !evidence_valid
            || !digest_valid
        {
            return Err(OptionalAdapterErrorV1::new(
                "exact_artifact_observation_invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactDispositionV1 {
    Findings,
    Inconclusive,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactVerdictV1 {
    Malicious,
    Inconclusive,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactStageStatusV1 {
    Complete,
    Findings,
    FindingsWithIncompleteCoverage,
    Incomplete,
    Unsupported,
    NotRequested,
    Unavailable,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactStageReportV1 {
    pub stage: String,
    pub status: ExactArtifactStageStatusV1,
    pub artifact_sha256: Option<String>,
    pub manifest_sha256: Option<String>,
    pub request_sha256: Option<String>,
    pub result_sha256: Option<String>,
    pub provider: Option<String>,
    pub observation_count: usize,
    pub reason_codes: Vec<String>,
}

impl ExactArtifactStageReportV1 {
    fn bound(
        stage: &str,
        status: ExactArtifactStageStatusV1,
        prepared: &PreparedArtifact,
        result_sha256: Option<String>,
        reason_codes: Vec<String>,
    ) -> Self {
        Self {
            stage: stage.to_string(),
            status,
            artifact_sha256: Some(prepared.evidence_subject().artifact_sha256().to_string()),
            manifest_sha256: Some(prepared.evidence_subject().manifest_sha256().to_string()),
            request_sha256: None,
            result_sha256,
            provider: None,
            observation_count: 0,
            reason_codes: sorted_unique(reason_codes),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "ecosystem", content = "scenario", rename_all = "snake_case")]
pub enum ExactArtifactScenarioKindV1 {
    Npm(ArtifactScenarioKindV1),
    Wheel(WheelScenarioKindV1),
    Sdist(SdistScenarioKindV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactScenarioIntentV1 {
    pub schema_version: String,
    pub artifact_sha256: String,
    pub manifest_sha256: String,
    pub kind: ExactArtifactScenarioKindV1,
    pub intent_sha256: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioIntentDigestWireV1<'a> {
    schema_version: &'static str,
    artifact_sha256: &'a str,
    manifest_sha256: &'a str,
    kind: &'a ExactArtifactScenarioKindV1,
}

impl ExactArtifactScenarioIntentV1 {
    fn new(
        artifact_sha256: &str,
        manifest_sha256: &str,
        kind: ExactArtifactScenarioKindV1,
    ) -> Result<Self, ExactArtifactInspectionErrorV1> {
        let digest_wire = ScenarioIntentDigestWireV1 {
            schema_version: EXACT_ARTIFACT_SCENARIO_INTENT_SCHEMA_V1,
            artifact_sha256,
            manifest_sha256,
            kind: &kind,
        };
        let bytes = serde_json::to_vec(&digest_wire).map_err(|_| {
            ExactArtifactInspectionErrorV1::internal(
                "exact_artifact_scenario_intent_serialization_failed",
            )
        })?;
        Ok(Self {
            schema_version: EXACT_ARTIFACT_SCENARIO_INTENT_SCHEMA_V1.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            manifest_sha256: manifest_sha256.to_string(),
            kind,
            intent_sha256: Sha256Digest::from_bytes(&bytes).to_string(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactScenarioPlanV1 {
    pub schema_version: String,
    pub artifact_sha256: String,
    pub manifest_sha256: String,
    pub status: ExactArtifactStageStatusV1,
    pub intents: Vec<ExactArtifactScenarioIntentV1>,
    pub plan_sha256: String,
    pub runtime_binding_required: bool,
    pub runtime_binding_status: String,
    pub executable: bool,
    pub reason_codes: Vec<String>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ScenarioPlanDigestWireV1<'a> {
    schema_version: &'static str,
    artifact_sha256: &'a str,
    manifest_sha256: &'a str,
    status: ExactArtifactStageStatusV1,
    intents: &'a [ExactArtifactScenarioIntentV1],
    runtime_binding_required: bool,
    runtime_binding_status: &'a str,
    executable: bool,
    reason_codes: &'a [String],
}

impl ExactArtifactScenarioPlanV1 {
    fn new(
        prepared: &PreparedArtifact,
        status: ExactArtifactStageStatusV1,
        kinds: Vec<ExactArtifactScenarioKindV1>,
        reason_codes: Vec<String>,
    ) -> Result<Self, ExactArtifactInspectionErrorV1> {
        let artifact_sha256 = prepared.evidence_subject().artifact_sha256();
        let manifest_sha256 = prepared.evidence_subject().manifest_sha256();
        let mut intents = Vec::with_capacity(kinds.len());
        for kind in kinds {
            intents.push(ExactArtifactScenarioIntentV1::new(
                artifact_sha256,
                manifest_sha256,
                kind,
            )?);
        }
        let reason_codes = sorted_unique(reason_codes);
        let wire = ScenarioPlanDigestWireV1 {
            schema_version: EXACT_ARTIFACT_SCENARIO_PLAN_SCHEMA_V1,
            artifact_sha256,
            manifest_sha256,
            status,
            intents: &intents,
            runtime_binding_required: true,
            runtime_binding_status: "not_bound",
            executable: false,
            reason_codes: &reason_codes,
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| {
            ExactArtifactInspectionErrorV1::internal(
                "exact_artifact_scenario_plan_serialization_failed",
            )
        })?;
        Ok(Self {
            schema_version: EXACT_ARTIFACT_SCENARIO_PLAN_SCHEMA_V1.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            manifest_sha256: manifest_sha256.to_string(),
            status,
            intents,
            plan_sha256: Sha256Digest::from_bytes(&bytes).to_string(),
            runtime_binding_required: true,
            runtime_binding_status: "not_bound".to_string(),
            executable: false,
            reason_codes,
        })
    }

    fn with_verified_runtime_binding(mut self) -> Result<Self, ExactArtifactInspectionErrorV1> {
        self.runtime_binding_status = "verified".to_string();
        self.executable = true;
        self.reason_codes
            .retain(|code| code != "exact_artifact_runtime_binding_not_supplied");
        self.reason_codes = sorted_unique(self.reason_codes);
        let wire = ScenarioPlanDigestWireV1 {
            schema_version: EXACT_ARTIFACT_SCENARIO_PLAN_SCHEMA_V1,
            artifact_sha256: &self.artifact_sha256,
            manifest_sha256: &self.manifest_sha256,
            status: self.status,
            intents: &self.intents,
            runtime_binding_required: self.runtime_binding_required,
            runtime_binding_status: &self.runtime_binding_status,
            executable: self.executable,
            reason_codes: &self.reason_codes,
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| {
            ExactArtifactInspectionErrorV1::internal(
                "exact_artifact_scenario_plan_serialization_failed",
            )
        })?;
        self.plan_sha256 = Sha256Digest::from_bytes(&bytes).to_string();
        Ok(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundOptionalEvidenceOutcomeV1 {
    Findings,
    FindingsWithIncompleteCoverage,
    BoundedNoFinding,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactOptionalResultV1 {
    pub schema_version: String,
    pub request_sha256: String,
    pub outcome: BoundOptionalEvidenceOutcomeV1,
    pub observations: Vec<ExactArtifactObservationV1>,
    pub behavior_bundle_sha256s: Vec<Sha256Digest>,
    pub reason_codes: Vec<String>,
}

impl ExactArtifactOptionalResultV1 {
    pub fn new(
        request_sha256: String,
        outcome: BoundOptionalEvidenceOutcomeV1,
        reason_codes: Vec<String>,
    ) -> Result<Self, OptionalAdapterErrorV1> {
        let result = Self {
            schema_version: EXACT_ARTIFACT_OPTIONAL_RESULT_SCHEMA_V1.to_string(),
            request_sha256,
            outcome,
            observations: Vec::new(),
            behavior_bundle_sha256s: Vec::new(),
            reason_codes: sorted_unique(reason_codes),
        };
        result.validate()?;
        Ok(result)
    }

    pub fn with_evidence(
        request_sha256: String,
        outcome: BoundOptionalEvidenceOutcomeV1,
        reason_codes: Vec<String>,
        mut observations: Vec<ExactArtifactObservationV1>,
        mut behavior_bundle_sha256s: Vec<Sha256Digest>,
    ) -> Result<Self, OptionalAdapterErrorV1> {
        observations.sort_by(|left, right| left.observation_sha256.cmp(&right.observation_sha256));
        behavior_bundle_sha256s.sort();
        let result = Self {
            schema_version: EXACT_ARTIFACT_OPTIONAL_RESULT_SCHEMA_V1.to_string(),
            request_sha256,
            outcome,
            observations,
            behavior_bundle_sha256s,
            reason_codes: sorted_unique(reason_codes),
        };
        result.validate()?;
        Ok(result)
    }

    pub fn to_canonical_json_bytes(&self) -> Result<Vec<u8>, OptionalAdapterErrorV1> {
        self.validate()?;
        serde_json::to_vec(self).map_err(|_| {
            OptionalAdapterErrorV1::new("exact_artifact_optional_result_serialization_failed")
        })
    }

    fn validate(&self) -> Result<(), OptionalAdapterErrorV1> {
        if self.schema_version != EXACT_ARTIFACT_OPTIONAL_RESULT_SCHEMA_V1
            || Sha256Digest::parse(self.request_sha256.clone()).is_err()
            || self.reason_codes.is_empty()
            || self.reason_codes.len() > 128
            || self.observations.len() > MAX_EXACT_ARTIFACT_OBSERVATIONS_V1
            || self.behavior_bundle_sha256s.len() > MAX_EXACT_ARTIFACT_BEHAVIOR_BUNDLES_V1
            || self
                .observations
                .iter()
                .any(|observation| observation.validate().is_err())
            || self
                .observations
                .windows(2)
                .any(|pair| pair[0].observation_sha256 >= pair[1].observation_sha256)
            || self
                .behavior_bundle_sha256s
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.reason_codes != sorted_unique(self.reason_codes.clone())
            || self
                .reason_codes
                .iter()
                .any(|code| !valid_reason_code(code))
            || (matches!(
                self.outcome,
                BoundOptionalEvidenceOutcomeV1::Findings
                    | BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage
            ) && self.observations.is_empty())
            || (!self.observations.is_empty()
                && !matches!(
                    self.outcome,
                    BoundOptionalEvidenceOutcomeV1::Findings
                        | BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage
                ))
        {
            return Err(OptionalAdapterErrorV1::new(
                "exact_artifact_optional_result_invalid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactAdapterRequestV1 {
    pub schema_version: String,
    pub stage: String,
    pub provider: String,
    pub artifact_sha256: String,
    pub envelope_sha256: String,
    pub manifest_sha256: String,
    pub scenario_plan_sha256: String,
    pub deterministic_analysis_sha256: Option<String>,
    pub behavior_bundle_sha256: Option<String>,
    pub request_sha256: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExactArtifactAdapterRequestDigestWireV1<'a> {
    schema_version: &'static str,
    stage: &'a str,
    provider: &'a str,
    artifact_sha256: &'a str,
    envelope_sha256: &'a str,
    manifest_sha256: &'a str,
    scenario_plan_sha256: &'a str,
    deterministic_analysis_sha256: Option<&'a str>,
    behavior_bundle_sha256: Option<&'a str>,
}

impl ExactArtifactAdapterRequestV1 {
    fn new(
        stage: &'static str,
        provider: &str,
        prepared: &PreparedArtifact,
        scenarios: &ExactArtifactScenarioPlanV1,
        deterministic_analysis_sha256: Option<&str>,
        behavior_bundle_sha256: Option<&str>,
    ) -> Result<Self, ExactArtifactInspectionErrorV1> {
        if provider.is_empty()
            || provider.len() > 128
            || !provider.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
        {
            return Err(ExactArtifactInspectionErrorV1::internal(
                "exact_artifact_adapter_provider_invalid",
            ));
        }
        let artifact_sha256 = prepared.evidence_subject().artifact_sha256();
        let envelope_sha256 = prepared.evidence_subject().envelope_sha256();
        let manifest_sha256 = prepared.evidence_subject().manifest_sha256();
        let wire = ExactArtifactAdapterRequestDigestWireV1 {
            schema_version: EXACT_ARTIFACT_ADAPTER_REQUEST_SCHEMA_V1,
            stage,
            provider,
            artifact_sha256,
            envelope_sha256,
            manifest_sha256,
            scenario_plan_sha256: &scenarios.plan_sha256,
            deterministic_analysis_sha256,
            behavior_bundle_sha256,
        };
        let bytes = serde_json::to_vec(&wire).map_err(|_| {
            ExactArtifactInspectionErrorV1::internal(
                "exact_artifact_adapter_request_serialization_failed",
            )
        })?;
        Ok(Self {
            schema_version: EXACT_ARTIFACT_ADAPTER_REQUEST_SCHEMA_V1.to_string(),
            stage: stage.to_string(),
            provider: provider.to_string(),
            artifact_sha256: artifact_sha256.to_string(),
            envelope_sha256: envelope_sha256.to_string(),
            manifest_sha256: manifest_sha256.to_string(),
            scenario_plan_sha256: scenarios.plan_sha256.clone(),
            deterministic_analysis_sha256: deterministic_analysis_sha256.map(ToString::to_string),
            behavior_bundle_sha256: behavior_bundle_sha256.map(ToString::to_string),
            request_sha256: Sha256Digest::from_bytes(&bytes).to_string(),
        })
    }
}

/// The minimum response accepted from an optional AI or detonation adapter.
///
/// The product computes the request digest before invocation, requires the
/// adapter to echo it, canonicalizes the typed result locally, and computes the
/// retained result digest itself. A `BoundedNoFinding` result remains analysis
/// evidence and never grants admission authority here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundOptionalEvidenceV1 {
    pub canonical_result_bytes: Vec<u8>,
    pub behavior_bundles: Vec<BehaviorAnalysisBundleV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalAdapterErrorV1 {
    reason_code: &'static str,
}

impl OptionalAdapterErrorV1 {
    pub const fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }
}

/// Capability boundary for hosted or local AI analysis.
///
/// Implementations receive normalized bytes, not a package workspace path.
pub trait ExactArtifactAiAdapterV1 {
    fn provider_id(&self) -> &str;
    fn readiness_reason(&self) -> Option<&'static str>;
    fn analyze(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        prepared: &PreparedArtifact,
        deterministic: &ArtifactStaticAnalysis,
        scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1>;
}

/// Observe-only analysis of a validated behavioral bundle returned by a
/// detonation adapter. Implementations cannot alter execution or admission.
pub trait ExactArtifactBehaviorObserverV1 {
    fn provider_id(&self) -> &str;
    fn readiness_reason(&self) -> Option<&'static str>;
    fn observe_behavior(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        bundle: &BehaviorAnalysisBundleV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1>;
}

/// Capability boundary for a contained execution backend.
///
/// Implementations must re-open the supplied `PreparedArtifact` through its
/// verified transport source before execution. The product spine never treats
/// backend availability as execution evidence.
pub trait ExactArtifactDetonationAdapterV1 {
    fn provider_id(&self) -> &str;
    fn readiness_reason(&self) -> Option<&'static str>;
    /// Returns true only when this adapter can bind and execute the supplied
    /// scenario plan with its currently configured runtime. A plan may remain
    /// incomplete when execution can collect useful evidence but cannot close
    /// every declared coverage gap.
    fn supports_runtime_binding(
        &self,
        _prepared: &PreparedArtifact,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> bool {
        false
    }
    fn detonate(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        artifact: &VerifiedArtifactLease,
        prepared: &PreparedArtifact,
        scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactArtifactInspectionRequestV1<'a> {
    pub artifact_path: &'a Path,
    pub quarantine_root: &'a Path,
    pub ecosystem: Option<Ecosystem>,
    pub acquired_at: &'a str,
    pub ai_requested: bool,
    pub ai_provider: Option<&'a str>,
    pub behavior_observation_requested: bool,
    pub detonation_requested: bool,
    pub normalization_limits: NormalizationLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactIdentityV1 {
    pub artifact_sha256: String,
    pub envelope_sha256: String,
    pub manifest_sha256: String,
    pub cas_object_key: String,
    pub byte_length: u64,
    pub ecosystem: Ecosystem,
    pub artifact_format: ArtifactFormat,
    pub source_type: ArtifactSourceType,
    pub acquisition_method: AcquisitionMethod,
    pub source_coordinate: String,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ExactArtifactInspectionReportV1 {
    pub schema_version: String,
    pub status: ExactArtifactDispositionV1,
    pub verdict: ExactArtifactVerdictV1,
    pub exit_code: i32,
    pub identity: ExactArtifactIdentityV1,
    pub stages: Vec<ExactArtifactStageReportV1>,
    pub scenario_plan: ExactArtifactScenarioPlanV1,
    pub observations: Vec<ExactArtifactObservationV1>,
    pub behavior_detection_count: usize,
    pub admission_authority: bool,
    pub observed_clean: bool,
    pub sync_back_enabled: bool,
    pub reason_codes: Vec<String>,
}

impl ExactArtifactInspectionReportV1 {
    pub fn to_pretty_json(&self) -> Result<String, ExactArtifactInspectionErrorV1> {
        serde_json::to_string_pretty(self).map_err(|_| {
            ExactArtifactInspectionErrorV1::internal("exact_artifact_report_serialization_failed")
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactArtifactInspectionErrorV1 {
    reason_code: &'static str,
    exit_code: i32,
}

impl ExactArtifactInspectionErrorV1 {
    pub const fn invalid_request(reason_code: &'static str) -> Self {
        Self {
            reason_code,
            exit_code: 64,
        }
    }

    fn misuse(reason_code: &'static str) -> Self {
        Self {
            reason_code,
            exit_code: 64,
        }
    }

    fn inconclusive(reason_code: &'static str) -> Self {
        Self {
            reason_code,
            exit_code: 22,
        }
    }

    fn internal(reason_code: &'static str) -> Self {
        Self {
            reason_code,
            exit_code: 70,
        }
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub const fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn to_pretty_json(&self) -> String {
        serde_json::json!({
            "schema_version": EXACT_ARTIFACT_INSPECTION_SCHEMA_V1,
            "status": "error",
            "exit_code": self.exit_code,
            "admission_authority": false,
            "observed_clean": false,
            "sync_back_enabled": false,
            "reason_codes": [self.reason_code],
        })
        .to_string()
    }
}

impl std::fmt::Display for ExactArtifactInspectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for ExactArtifactInspectionErrorV1 {}

pub fn inspect_exact_artifact_v1(
    request: ExactArtifactInspectionRequestV1<'_>,
    ai_adapter: Option<&dyn ExactArtifactAiAdapterV1>,
    detonation_adapter: Option<&dyn ExactArtifactDetonationAdapterV1>,
) -> Result<ExactArtifactInspectionReportV1, ExactArtifactInspectionErrorV1> {
    inspect_exact_artifact_with_behavior_v1(request, ai_adapter, detonation_adapter, None)
}

pub fn inspect_exact_artifact_with_behavior_v1(
    request: ExactArtifactInspectionRequestV1<'_>,
    ai_adapter: Option<&dyn ExactArtifactAiAdapterV1>,
    detonation_adapter: Option<&dyn ExactArtifactDetonationAdapterV1>,
    behavior_observer: Option<&dyn ExactArtifactBehaviorObserverV1>,
) -> Result<ExactArtifactInspectionReportV1, ExactArtifactInspectionErrorV1> {
    let filename = checked_filename(request.artifact_path)?;
    let ecosystem = match request.ecosystem {
        Some(value) => value,
        None => infer_ecosystem(&filename)?,
    };
    let bytes = read_exact_artifact(request.artifact_path, request.normalization_limits)?;
    let artifact_sha256 = Sha256Digest::from_bytes(&bytes);
    let cas = PersistentQuarantineCas::create(
        request.quarantine_root,
        request.normalization_limits.max_original_bytes,
    )
    .map_err(|_| {
        ExactArtifactInspectionErrorV1::internal("exact_artifact_quarantine_unavailable")
    })?;
    let quarantined = cas
        .quarantine_bytes(artifact_sha256.as_str(), &bytes)
        .map_err(|_| {
            ExactArtifactInspectionErrorV1::internal("exact_artifact_quarantine_failed")
        })?;
    let declared_format = declared_format_for(ecosystem, &filename);
    let mut envelope_input = ArtifactEnvelopeInput {
        ecosystem,
        package_name: None,
        package_version: None,
        source_coordinate: format!("local-file:{}", artifact_sha256.as_str()),
        source_type: ArtifactSourceType::LocalFile,
        acquired_at: request.acquired_at.to_string(),
        acquisition_method: AcquisitionMethod::LocalFileImport,
        original_filename: filename,
        declared_format,
        custody_reference: "caller-path-is-not-trusted".to_string(),
        resolver_metadata_sha256: None,
        registry_metadata_sha256: None,
        policy_version: "exact-artifact-inspection-v1".to_string(),
        requires_external_dependency_resolution: false,
    };
    let mut prepared = prepare_quarantined_artifact(
        &cas,
        &quarantined,
        envelope_input.clone(),
        request.normalization_limits,
    )
    .map_err(|_| {
        ExactArtifactInspectionErrorV1::inconclusive("exact_artifact_preparation_failed")
    })?;
    // A local custody import has no trusted resolver record declaring whether
    // an offline closure is required. The first bounded parse inventories that
    // fact from exact bytes; if needed, rebuild only the acquisition envelope
    // and normalize the same verified CAS object again with the discovered
    // declaration. This prevents a guessed `false` from degrading otherwise
    // complete package normalization.
    let discovered_external_resolution =
        manifest_requires_external_resolution(&prepared.normalized().manifest);
    if discovered_external_resolution != envelope_input.requires_external_dependency_resolution {
        envelope_input.requires_external_dependency_resolution = discovered_external_resolution;
        prepared = prepare_quarantined_artifact(
            &cas,
            &quarantined,
            envelope_input,
            request.normalization_limits,
        )
        .map_err(|_| {
            ExactArtifactInspectionErrorV1::inconclusive("exact_artifact_preparation_failed")
        })?;
    }
    let deterministic = prepared.analyze_deterministically().map_err(|_| {
        ExactArtifactInspectionErrorV1::inconclusive("exact_artifact_deterministic_analysis_failed")
    })?;
    let mut scenario_plan = compile_scenario_intents(&prepared)?;
    if request.detonation_requested {
        if let Some(adapter) = detonation_adapter {
            if scenario_plan_runtime_binding_candidate_v1(&prepared, &scenario_plan)
                && adapter.readiness_reason().is_none()
                && adapter.supports_runtime_binding(&prepared, &scenario_plan)
            {
                scenario_plan = scenario_plan.with_verified_runtime_binding()?;
            }
        }
    }

    let mut observations = deterministic_observations_v1(&deterministic)?;
    let mut deterministic_report = deterministic_stage(&prepared, &deterministic)?;
    deterministic_report.observation_count = observations.len();
    let mut stages = vec![
        ExactArtifactStageReportV1::bound(
            "quarantine",
            ExactArtifactStageStatusV1::Complete,
            &prepared,
            None,
            vec!["exact_artifact_quarantined_and_reverified".to_string()],
        ),
        normalization_stage(&prepared),
        deterministic_report,
        ExactArtifactStageReportV1::bound(
            "scenario_compilation",
            scenario_plan.status,
            &prepared,
            Some(scenario_plan.plan_sha256.clone()),
            scenario_plan.reason_codes.clone(),
        ),
    ];
    let ai_outcome = run_ai_stage(
        request.ai_requested,
        request.ai_provider,
        ai_adapter,
        &prepared,
        &deterministic,
        &scenario_plan,
    );
    observations.extend(ai_outcome.observations);
    stages.push(ai_outcome.report);
    let detonation_outcome = run_detonation_stage(
        request.detonation_requested,
        detonation_adapter,
        &cas,
        &prepared,
        &deterministic,
        &scenario_plan,
    );
    observations.extend(detonation_outcome.observations);
    let behavior_bundles = detonation_outcome.behavior_bundles;
    stages.push(detonation_outcome.report);
    let behavior_outcomes = run_behavior_observation_stages(
        request.behavior_observation_requested && request.detonation_requested,
        behavior_observer,
        &prepared,
        &deterministic,
        &scenario_plan,
        behavior_bundles,
    );
    for outcome in behavior_outcomes {
        observations.extend(outcome.observations);
        stages.push(outcome.report);
    }
    observations.sort_by(|left, right| left.observation_sha256.cmp(&right.observation_sha256));
    observations.dedup_by(|left, right| left.observation_sha256 == right.observation_sha256);

    let has_findings = observations
        .iter()
        .any(observation_supports_malicious_verdict_v1);
    let unsupported = scenario_plan.status == ExactArtifactStageStatusV1::Unsupported;
    let disposition = if has_findings {
        ExactArtifactDispositionV1::Findings
    } else if unsupported {
        ExactArtifactDispositionV1::Unsupported
    } else {
        ExactArtifactDispositionV1::Inconclusive
    };
    let exit_code = match disposition {
        ExactArtifactDispositionV1::Findings => 20,
        ExactArtifactDispositionV1::Inconclusive | ExactArtifactDispositionV1::Unsupported => 22,
    };
    let verdict = match disposition {
        ExactArtifactDispositionV1::Findings => ExactArtifactVerdictV1::Malicious,
        ExactArtifactDispositionV1::Inconclusive => ExactArtifactVerdictV1::Inconclusive,
        ExactArtifactDispositionV1::Unsupported => ExactArtifactVerdictV1::Unsupported,
    };
    let behavior_detection_count = observations
        .iter()
        .filter(|observation| observation.behavior_detection_eligible)
        .count();
    let mut reason_codes = stages
        .iter()
        .flat_map(|stage| stage.reason_codes.iter().cloned())
        .collect::<Vec<_>>();
    reason_codes.push("exact_artifact_spine_has_no_admission_authority".to_string());
    reason_codes.push("exact_artifact_missing_evidence_never_observed_clean".to_string());
    reason_codes.push("exact_artifact_legacy_workspace_review_not_used".to_string());
    if !observations.is_empty() {
        reason_codes.push("exact_artifact_typed_observations_preserved".to_string());
    }
    if observations
        .iter()
        .any(|observation| observation.source == ExactArtifactObservationSourceV1::AiSourceReview)
    {
        reason_codes.push("exact_artifact_ai_source_review_requires_corroboration".to_string());
    }
    let identity = prepared
        .normalized()
        .manifest
        .identity
        .as_ref()
        .map(|identity| (identity.display_name.clone(), identity.version.clone()));
    let envelope_sha256 = prepared.envelope().envelope_sha256().map_err(|_| {
        ExactArtifactInspectionErrorV1::internal("exact_artifact_envelope_digest_failed")
    })?;
    Ok(ExactArtifactInspectionReportV1 {
        schema_version: EXACT_ARTIFACT_INSPECTION_SCHEMA_V1.to_string(),
        status: disposition,
        verdict,
        exit_code,
        identity: ExactArtifactIdentityV1 {
            artifact_sha256: prepared.evidence_subject().artifact_sha256().to_string(),
            envelope_sha256: envelope_sha256.to_string(),
            manifest_sha256: prepared.evidence_subject().manifest_sha256().to_string(),
            cas_object_key: prepared.evidence_subject().cas_object_key().to_string(),
            byte_length: prepared.envelope().original_byte_length,
            ecosystem,
            artifact_format: prepared.envelope().magic_detected_format,
            source_type: prepared.envelope().source_type,
            acquisition_method: prepared.envelope().acquisition_method,
            source_coordinate: prepared.envelope().source_coordinate.clone(),
            package_name: identity.as_ref().map(|value| value.0.clone()),
            package_version: identity.map(|value| value.1),
        },
        stages,
        scenario_plan,
        observations,
        behavior_detection_count,
        admission_authority: false,
        observed_clean: false,
        sync_back_enabled: false,
        reason_codes: sorted_unique(reason_codes),
    })
}

pub(crate) fn manifest_requires_external_resolution(
    manifest: &whoathere_artifact::ArtifactManifest,
) -> bool {
    if let Some(npm) = &manifest.metadata.npm {
        return npm.requires_offline_closure;
    }
    if let Some(wheel) = &manifest.metadata.wheel {
        return !wheel.requires_dist.is_empty();
    }
    if let Some(sdist) = &manifest.metadata.sdist {
        return !sdist.build_requires.is_empty()
            || !sdist.requires_dist.is_empty()
            || sdist.dynamic_build_requirements_possible;
    }
    false
}

pub(crate) fn checked_filename(path: &Path) -> Result<String, ExactArtifactInspectionErrorV1> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ExactArtifactInspectionErrorV1::misuse("exact_artifact_filename_invalid"))?;
    Ok(filename.to_string())
}

pub(crate) fn read_exact_artifact(
    path: &Path,
    limits: NormalizationLimits,
) -> Result<Vec<u8>, ExactArtifactInspectionErrorV1> {
    // The caller path is untrusted. Open it once with no symlink traversal and
    // nonblocking semantics (so a path swap to a FIFO cannot hang admission),
    // then perform every identity and content check through that one fd.
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(map_artifact_open_error)?;
    let before = file
        .metadata()
        .map_err(|_| ExactArtifactInspectionErrorV1::misuse("exact_artifact_path_unreadable"))?;
    if !before.file_type().is_file() {
        return Err(ExactArtifactInspectionErrorV1::misuse(
            "exact_artifact_path_not_regular_file",
        ));
    }
    if before.len() == 0 || before.len() > limits.max_original_bytes {
        return Err(ExactArtifactInspectionErrorV1::misuse(
            "exact_artifact_size_out_of_bounds",
        ));
    }
    let expected_len = usize::try_from(before.len())
        .map_err(|_| ExactArtifactInspectionErrorV1::misuse("exact_artifact_size_out_of_bounds"))?;
    let mut bytes = vec![0_u8; expected_len];
    if let Err(error) = file.read_exact(&mut bytes) {
        return Err(if error.kind() == ErrorKind::UnexpectedEof {
            ExactArtifactInspectionErrorV1::inconclusive("exact_artifact_file_identity_changed")
        } else {
            ExactArtifactInspectionErrorV1::misuse("exact_artifact_path_unreadable")
        });
    }
    let mut unexpected_byte = [0_u8; 1];
    if file
        .read(&mut unexpected_byte)
        .map_err(|_| ExactArtifactInspectionErrorV1::misuse("exact_artifact_path_unreadable"))?
        != 0
    {
        return Err(ExactArtifactInspectionErrorV1::inconclusive(
            "exact_artifact_file_identity_changed",
        ));
    }
    let after = file.metadata().map_err(|_| {
        ExactArtifactInspectionErrorV1::inconclusive("exact_artifact_file_identity_changed")
    })?;
    if !same_open_file_identity(&before, &after) {
        return Err(ExactArtifactInspectionErrorV1::inconclusive(
            "exact_artifact_file_identity_changed",
        ));
    }
    Ok(bytes)
}

fn map_artifact_open_error(error: std::io::Error) -> ExactArtifactInspectionErrorV1 {
    if error.raw_os_error() == Some(libc::ELOOP) {
        ExactArtifactInspectionErrorV1::misuse("exact_artifact_path_not_regular_file")
    } else {
        ExactArtifactInspectionErrorV1::misuse("exact_artifact_path_unreadable")
    }
}

fn same_open_file_identity(before: &Metadata, after: &Metadata) -> bool {
    before.file_type().is_file()
        && after.file_type().is_file()
        && before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

fn infer_ecosystem(filename: &str) -> Result<Ecosystem, ExactArtifactInspectionErrorV1> {
    let filename = filename.to_ascii_lowercase();
    if filename.ends_with(".whl") || filename.ends_with(".zip") || filename.ends_with(".tar.gz") {
        Ok(Ecosystem::Pypi)
    } else if filename.ends_with(".tgz") {
        Ok(Ecosystem::Npm)
    } else {
        Err(ExactArtifactInspectionErrorV1::misuse(
            "exact_artifact_ecosystem_required",
        ))
    }
}

/// Formats a non-negative Unix timestamp as the canonical UTC-seconds form
/// required by the artifact envelope contract.
pub fn canonical_utc_timestamp_from_unix_seconds_v1(
    unix_seconds: u64,
) -> Result<String, ExactArtifactInspectionErrorV1> {
    let days = i64::try_from(unix_seconds / 86_400).map_err(|_| {
        ExactArtifactInspectionErrorV1::internal("exact_artifact_timestamp_out_of_range")
    })?;
    let seconds_of_day = unix_seconds % 86_400;
    let (year, month, day) = civil_date_from_unix_days(days).ok_or_else(|| {
        ExactArtifactInspectionErrorV1::internal("exact_artifact_timestamp_out_of_range")
    })?;
    if !(0..=9_999).contains(&year) {
        return Err(ExactArtifactInspectionErrorV1::internal(
            "exact_artifact_timestamp_out_of_range",
        ));
    }
    let hour = seconds_of_day / 3_600;
    let minute = (seconds_of_day % 3_600) / 60;
    let second = seconds_of_day % 60;
    Ok(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

fn civil_date_from_unix_days(days: i64) -> Option<(i64, u64, u64)> {
    let z = days.checked_add(719_468)?;
    let era = if z >= 0 { z } else { z.checked_sub(146_096)? } / 146_097;
    let day_of_era = z.checked_sub(era.checked_mul(146_097)?)?;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era.checked_add(era.checked_mul(400)?)?;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    Some((year, u64::try_from(month).ok()?, u64::try_from(day).ok()?))
}

pub(crate) fn declared_format_for(ecosystem: Ecosystem, filename: &str) -> Option<ArtifactFormat> {
    let filename = filename.to_ascii_lowercase();
    match ecosystem {
        Ecosystem::Npm if filename.ends_with(".tgz") || filename.ends_with(".tar.gz") => {
            Some(ArtifactFormat::NpmTarGzip)
        }
        Ecosystem::Pypi if filename.ends_with(".whl") => Some(ArtifactFormat::WheelZip),
        Ecosystem::Pypi if filename.ends_with(".tar.gz") || filename.ends_with(".tgz") => {
            Some(ArtifactFormat::SdistTarGzip)
        }
        Ecosystem::Pypi if filename.ends_with(".zip") => Some(ArtifactFormat::SdistZip),
        _ => None,
    }
}

fn normalization_stage(prepared: &PreparedArtifact) -> ExactArtifactStageReportV1 {
    let (status, reason) = match prepared.normalized().manifest.normalization_completeness {
        NormalizationCompleteness::Complete => (
            ExactArtifactStageStatusV1::Complete,
            "exact_artifact_normalization_complete",
        ),
        NormalizationCompleteness::Incomplete => (
            ExactArtifactStageStatusV1::Incomplete,
            "exact_artifact_normalization_incomplete",
        ),
        NormalizationCompleteness::Rejected => (
            ExactArtifactStageStatusV1::Unsupported,
            "exact_artifact_normalization_rejected",
        ),
    };
    ExactArtifactStageReportV1::bound(
        "normalization",
        status,
        prepared,
        Some(prepared.evidence_subject().manifest_sha256().to_string()),
        vec![reason.to_string()],
    )
}

fn deterministic_observations_v1(
    analysis: &ArtifactStaticAnalysis,
) -> Result<Vec<ExactArtifactObservationV1>, ExactArtifactInspectionErrorV1> {
    let (coverage, coverage_gap_codes) = match analysis.coverage.completeness {
        ArtifactAnalysisCompleteness::Complete => {
            (ExactArtifactObservationCoverageV1::Complete, Vec::new())
        }
        ArtifactAnalysisCompleteness::Incomplete => (
            ExactArtifactObservationCoverageV1::Incomplete,
            vec!["deterministic_analysis_coverage_incomplete".to_string()],
        ),
    };
    let mut observations = analysis
        .findings
        .iter()
        .map(|finding| {
            ExactArtifactObservationV1::new(
                ExactArtifactObservationSourceV1::DeterministicStatic,
                deterministic_threat_class_v1(finding.category),
                ExactArtifactFindingKindV1::DeterministicStatic(finding.category),
                match finding.confidence {
                    FindingConfidence::Moderate => ExactArtifactObservationConfidenceV1::Moderate,
                    FindingConfidence::High => ExactArtifactObservationConfidenceV1::High,
                },
                finding.artifact_sha256.clone(),
                finding.manifest_sha256.clone(),
                ExactArtifactEvidenceReferenceV1::DeterministicStatic {
                    evidence_sha256: finding.evidence_digest.clone(),
                    location: finding.location.clone(),
                },
                coverage,
                coverage_gap_codes.clone(),
                finding.specificity == FindingSpecificity::PackageSpecific
                    && deterministic_finding_detection_eligible_v1(finding.category),
            )
            .map_err(|_| {
                ExactArtifactInspectionErrorV1::internal(
                    "exact_artifact_deterministic_observation_invalid",
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    observations.sort_by(|left, right| left.observation_sha256.cmp(&right.observation_sha256));
    Ok(observations)
}

fn deterministic_threat_class_v1(category: ArtifactFindingCategory) -> ExactArtifactThreatClassV1 {
    match category {
        ArtifactFindingCategory::EnvironmentAccess => {
            ExactArtifactThreatClassV1::EnvironmentAndTimeGating
        }
        ArtifactFindingCategory::CredentialAccess
        | ArtifactFindingCategory::SensitivePathAccess => {
            ExactArtifactThreatClassV1::CredentialAndSensitiveFileDiscovery
        }
        ArtifactFindingCategory::NetworkCapability
        | ArtifactFindingCategory::EnvironmentExfiltrationCapability
        | ArtifactFindingCategory::CredentialExfiltrationCapability
        | ArtifactFindingCategory::SensitiveFileExfiltrationCapability
        | ArtifactFindingCategory::HttpsSensitiveExfiltrationCapability => {
            ExactArtifactThreatClassV1::NetworkAndExfiltration
        }
        ArtifactFindingCategory::DownloadExecuteCapability => {
            ExactArtifactThreatClassV1::SecondStageNativeOrWasmHandoff
        }
        ArtifactFindingCategory::ProcessExecution
        | ArtifactFindingCategory::EnvironmentToProcessCapability => {
            ExactArtifactThreatClassV1::ProcessExecutionAndDynamicLoading
        }
    }
}

pub(crate) fn review_threat_class_v1(
    threat_class: ArtifactReviewThreatClassV2,
) -> ExactArtifactThreatClassV1 {
    match threat_class {
        ArtifactReviewThreatClassV2::CredentialAndSensitiveFileDiscovery => {
            ExactArtifactThreatClassV1::CredentialAndSensitiveFileDiscovery
        }
        ArtifactReviewThreatClassV2::NetworkExfiltrationAndMetadataAccess => {
            ExactArtifactThreatClassV1::NetworkAndExfiltration
        }
        ArtifactReviewThreatClassV2::SecondStageNativeOrWasmHandoff => {
            ExactArtifactThreatClassV1::SecondStageNativeOrWasmHandoff
        }
        ArtifactReviewThreatClassV2::ProcessShellOrDynamicLoading => {
            ExactArtifactThreatClassV1::ProcessExecutionAndDynamicLoading
        }
        ArtifactReviewThreatClassV2::ObfuscationPackingOrStringConstruction => {
            ExactArtifactThreatClassV1::ObfuscationAndPacking
        }
        ArtifactReviewThreatClassV2::EnvironmentOrDelayedGating => {
            ExactArtifactThreatClassV1::EnvironmentAndTimeGating
        }
        ArtifactReviewThreatClassV2::PersistenceDestructionOrSelfDeletion => {
            ExactArtifactThreatClassV1::PersistenceDestructionAndSelfDeletion
        }
        ArtifactReviewThreatClassV2::RepositoryWorkflowPublicationOrPropagation => {
            ExactArtifactThreatClassV1::RepositoryPackageAndSelfPropagation
        }
        ArtifactReviewThreatClassV2::DependencyIndirectionConfusionOrTransitiveCompromise => {
            ExactArtifactThreatClassV1::DependencyIndirection
        }
        ArtifactReviewThreatClassV2::ImportOrUseTimeTampering => {
            ExactArtifactThreatClassV1::ImportTimeTampering
        }
    }
}

pub(crate) fn behavior_threat_class_v1(
    threat_class: BehaviorThreatClassV1,
) -> ExactArtifactThreatClassV1 {
    match threat_class {
        BehaviorThreatClassV1::CredentialAndSensitiveFileDiscovery => {
            ExactArtifactThreatClassV1::CredentialAndSensitiveFileDiscovery
        }
        BehaviorThreatClassV1::NetworkAndExfiltration => {
            ExactArtifactThreatClassV1::NetworkAndExfiltration
        }
        BehaviorThreatClassV1::SecondStageNativeOrWasmHandoff => {
            ExactArtifactThreatClassV1::SecondStageNativeOrWasmHandoff
        }
        BehaviorThreatClassV1::ProcessExecutionAndDynamicLoading => {
            ExactArtifactThreatClassV1::ProcessExecutionAndDynamicLoading
        }
        BehaviorThreatClassV1::ObfuscationAndPacking => {
            ExactArtifactThreatClassV1::ObfuscationAndPacking
        }
        BehaviorThreatClassV1::EnvironmentAndTimeGating => {
            ExactArtifactThreatClassV1::EnvironmentAndTimeGating
        }
        BehaviorThreatClassV1::PersistenceDestructionAndSelfDeletion => {
            ExactArtifactThreatClassV1::PersistenceDestructionAndSelfDeletion
        }
        BehaviorThreatClassV1::RepositoryPackageAndSelfPropagation => {
            ExactArtifactThreatClassV1::RepositoryPackageAndSelfPropagation
        }
        BehaviorThreatClassV1::DependencyIndirection => {
            ExactArtifactThreatClassV1::DependencyIndirection
        }
        BehaviorThreatClassV1::ImportTimeTampering => {
            ExactArtifactThreatClassV1::ImportTimeTampering
        }
    }
}

fn deterministic_finding_detection_eligible_v1(category: ArtifactFindingCategory) -> bool {
    matches!(
        category,
        ArtifactFindingCategory::CredentialAccess
            | ArtifactFindingCategory::SensitivePathAccess
            | ArtifactFindingCategory::CredentialExfiltrationCapability
            | ArtifactFindingCategory::SensitiveFileExfiltrationCapability
            | ArtifactFindingCategory::HttpsSensitiveExfiltrationCapability
            | ArtifactFindingCategory::DownloadExecuteCapability
            | ArtifactFindingCategory::EnvironmentToProcessCapability
    )
}

pub fn behavior_finding_detection_eligible_v1(kind: BehaviorFindingKindV1) -> bool {
    matches!(
        kind,
        BehaviorFindingKindV1::SecondStageHandoff
            | BehaviorFindingKindV1::SensitiveFileAccess
            | BehaviorFindingKindV1::CredentialAccess
            | BehaviorFindingKindV1::CanaryAccess
            | BehaviorFindingKindV1::CanaryUse
            | BehaviorFindingKindV1::CredentialExfiltration
            | BehaviorFindingKindV1::MetadataAccess
            | BehaviorFindingKindV1::Exfiltration
            | BehaviorFindingKindV1::SecondStageDownload
            | BehaviorFindingKindV1::PersistenceModification
            | BehaviorFindingKindV1::DestructiveFileAction
            | BehaviorFindingKindV1::SelfDeletion
            | BehaviorFindingKindV1::RepositoryMutation
            | BehaviorFindingKindV1::WorkflowMutation
            | BehaviorFindingKindV1::PackageMutation
            | BehaviorFindingKindV1::PackagePublishAttempt
            | BehaviorFindingKindV1::SelfPropagation
            | BehaviorFindingKindV1::ObfuscationOrPacking
            | BehaviorFindingKindV1::ImportTimeTampering
    )
}

fn observation_supports_malicious_verdict_v1(observation: &ExactArtifactObservationV1) -> bool {
    match &observation.finding_kind {
        ExactArtifactFindingKindV1::DeterministicStatic(_)
        | ExactArtifactFindingKindV1::AiBehavioral(_) => observation.behavior_detection_eligible,
        ExactArtifactFindingKindV1::AiSourceReview(_) => false,
    }
}

fn deterministic_stage(
    prepared: &PreparedArtifact,
    deterministic: &ArtifactStaticAnalysis,
) -> Result<ExactArtifactStageReportV1, ExactArtifactInspectionErrorV1> {
    let status = match deterministic.outcome {
        ArtifactAnalysisOutcome::Findings => ExactArtifactStageStatusV1::Findings,
        ArtifactAnalysisOutcome::FindingsWithIncompleteCoverage => {
            ExactArtifactStageStatusV1::FindingsWithIncompleteCoverage
        }
        ArtifactAnalysisOutcome::BoundedNoFinding => ExactArtifactStageStatusV1::Complete,
        ArtifactAnalysisOutcome::IncompleteNoFinding => ExactArtifactStageStatusV1::Incomplete,
    };
    let mut reasons = deterministic.coverage.limitations.clone();
    if deterministic.coverage.completeness == ArtifactAnalysisCompleteness::Incomplete {
        reasons.push("exact_artifact_deterministic_coverage_incomplete".to_string());
    }
    if deterministic.findings.is_empty() {
        reasons.push("exact_artifact_deterministic_no_finding".to_string());
    } else {
        reasons.push("exact_artifact_deterministic_findings".to_string());
    }
    let result_sha256 = deterministic.analysis_sha256().map_err(|_| {
        ExactArtifactInspectionErrorV1::internal("exact_artifact_analysis_digest_failed")
    })?;
    Ok(ExactArtifactStageReportV1::bound(
        "deterministic_analysis",
        status,
        prepared,
        Some(result_sha256.to_string()),
        reasons,
    ))
}

fn compile_scenario_intents(
    prepared: &PreparedArtifact,
) -> Result<ExactArtifactScenarioPlanV1, ExactArtifactInspectionErrorV1> {
    let manifest = &prepared.normalized().manifest;
    if manifest.normalization_completeness != NormalizationCompleteness::Complete {
        return ExactArtifactScenarioPlanV1::new(
            prepared,
            ExactArtifactStageStatusV1::Unsupported,
            Vec::new(),
            vec!["exact_artifact_scenario_requires_complete_normalization".to_string()],
        );
    }
    let mut reasons = Vec::new();
    let kinds = match manifest.magic_detected_format {
        ArtifactFormat::NpmTarGzip => {
            let Some(npm) = &manifest.metadata.npm else {
                return ExactArtifactScenarioPlanV1::new(
                    prepared,
                    ExactArtifactStageStatusV1::Unsupported,
                    Vec::new(),
                    vec!["exact_artifact_npm_metadata_missing".to_string()],
                );
            };
            if prepared.envelope().requires_external_dependency_resolution
                || npm.requires_offline_closure
            {
                reasons.push("exact_artifact_dependency_closure_required".to_string());
            }
            if npm.implicit_node_gyp_rebuild || !manifest.native_binary_file_ids.is_empty() {
                reasons.push("exact_artifact_native_runtime_unqualified".to_string());
            }
            if npm
                .lifecycle_scripts
                .keys()
                .any(|hook| !matches!(hook.as_str(), "preinstall" | "install" | "postinstall"))
            {
                reasons.push("exact_artifact_npm_lifecycle_hook_unqualified".to_string());
            }
            let kinds = vec![
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiFalse,
                }),
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiTrue,
                }),
            ];
            if npm.main_target.is_some() || !npm.export_targets.is_empty() {
                reasons.push(
                    "exact_artifact_npm_main_or_export_probe_runtime_not_qualified".to_string(),
                );
            }
            if !npm.bin_targets.is_empty() {
                reasons.push("exact_artifact_npm_bin_probe_runtime_not_qualified".to_string());
            }
            kinds
        }
        ArtifactFormat::WheelZip => {
            let expected = expected_wheel_scenario_kinds_v1(manifest).map_err(|error| {
                ExactArtifactInspectionErrorV1::inconclusive(error.reason_code())
            })?;
            let Some(wheel) = &manifest.metadata.wheel else {
                return ExactArtifactScenarioPlanV1::new(
                    prepared,
                    ExactArtifactStageStatusV1::Unsupported,
                    Vec::new(),
                    vec!["exact_artifact_wheel_metadata_missing".to_string()],
                );
            };
            if prepared.envelope().requires_external_dependency_resolution
                || !wheel.requires_dist.is_empty()
            {
                reasons.push("exact_artifact_dependency_closure_required".to_string());
            }
            if !wheel.native_tags.is_empty() || !manifest.native_binary_file_ids.is_empty() {
                reasons.push("exact_artifact_native_runtime_unqualified".to_string());
            }
            if !wheel.script_file_ids.is_empty() {
                reasons.push("exact_artifact_wheel_script_unqualified".to_string());
            }
            expected
                .into_iter()
                .map(ExactArtifactScenarioKindV1::Wheel)
                .collect()
        }
        ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip => {
            let Some(sdist) = &manifest.metadata.sdist else {
                return ExactArtifactScenarioPlanV1::new(
                    prepared,
                    ExactArtifactStageStatusV1::Unsupported,
                    Vec::new(),
                    vec!["exact_artifact_sdist_metadata_missing".to_string()],
                );
            };
            let expected = expected_sdist_scenario_kinds_v1(manifest).map_err(|error| {
                ExactArtifactInspectionErrorV1::inconclusive(error.reason_code())
            })?;
            if prepared.envelope().requires_external_dependency_resolution
                || !sdist.build_requires.is_empty()
                || sdist.dynamic_build_requirements_possible
            {
                reasons.push("exact_artifact_sdist_build_closure_required".to_string());
            }
            if sdist.dynamic_build_requirements_possible {
                reasons
                    .push("exact_artifact_sdist_dynamic_build_requirements_possible".to_string());
            }
            if !sdist.requires_dist.is_empty() {
                reasons.push("exact_artifact_dependency_closure_required".to_string());
            }
            if !manifest.native_binary_file_ids.is_empty() {
                reasons.push("exact_artifact_native_runtime_unqualified".to_string());
            }
            // Source-tree package roots are discovery hints, not authority for
            // the complete post-build probe matrix. The existing PEP 517 VM
            // sequence can still build, inspect, install, and exercise those
            // bounded hints to collect evidence. Keep the plan incomplete until
            // an authenticated derived-wheel manifest seals the exact wheel
            // digest and enumerates its complete `.pth`, import, and entry-point
            // trigger matrix.
            reasons.push("exact_artifact_derived_wheel_probe_manifest_required".to_string());
            if sdist.build_backend.is_some() {
                expected
                    .into_iter()
                    .map(ExactArtifactScenarioKindV1::Sdist)
                    .collect()
            } else {
                expected
                    .into_iter()
                    .filter(|kind| {
                        matches!(
                            kind,
                            SdistScenarioKindV1::BuildExactSdist { .. }
                                | SdistScenarioKindV1::InspectDerivedWheel
                        )
                    })
                    .map(ExactArtifactScenarioKindV1::Sdist)
                    .collect()
            }
        }
        ArtifactFormat::Unknown => {
            return ExactArtifactScenarioPlanV1::new(
                prepared,
                ExactArtifactStageStatusV1::Unsupported,
                Vec::new(),
                vec!["exact_artifact_format_unsupported".to_string()],
            )
        }
    };
    let status = if reasons.is_empty() {
        ExactArtifactStageStatusV1::Complete
    } else {
        ExactArtifactStageStatusV1::Incomplete
    };
    reasons.push("exact_artifact_runtime_binding_not_supplied".to_string());
    ExactArtifactScenarioPlanV1::new(prepared, status, kinds, reasons)
}

fn scenario_plan_runtime_binding_candidate_v1(
    prepared: &PreparedArtifact,
    scenarios: &ExactArtifactScenarioPlanV1,
) -> bool {
    if scenarios.status == ExactArtifactStageStatusV1::Complete {
        return true;
    }
    if scenarios.status != ExactArtifactStageStatusV1::Incomplete {
        return false;
    }
    match prepared.normalized().manifest.magic_detected_format {
        ArtifactFormat::WheelZip => {
            let expected = match expected_wheel_scenario_kinds_v1(&prepared.normalized().manifest) {
                Ok(expected) => expected,
                Err(_) => return false,
            };
            let actual = scenarios
                .intents
                .iter()
                .map(|intent| match &intent.kind {
                    ExactArtifactScenarioKindV1::Wheel(kind) => Some(kind.clone()),
                    ExactArtifactScenarioKindV1::Npm(_) | ExactArtifactScenarioKindV1::Sdist(_) => {
                        None
                    }
                })
                .collect::<Option<Vec<_>>>();
            actual.is_some_and(|actual| actual == expected)
        }
        ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip => {
            let expected = match expected_sdist_scenario_kinds_v1(&prepared.normalized().manifest) {
                Ok(expected) => expected,
                Err(_) => return false,
            };
            let actual = scenarios
                .intents
                .iter()
                .map(|intent| match &intent.kind {
                    ExactArtifactScenarioKindV1::Sdist(kind) => Some(kind.clone()),
                    ExactArtifactScenarioKindV1::Npm(_) | ExactArtifactScenarioKindV1::Wheel(_) => {
                        None
                    }
                })
                .collect::<Option<Vec<_>>>();
            actual.is_some_and(|actual| actual == expected)
        }
        ArtifactFormat::NpmTarGzip => {
            if prepared.normalized().manifest.metadata.npm.is_none() {
                return false;
            }
            let expected = vec![
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiFalse,
                }),
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiTrue,
                }),
            ];
            let actual = scenarios
                .intents
                .iter()
                .map(|intent| intent.kind.clone())
                .collect::<Vec<_>>();
            actual == expected
        }
        ArtifactFormat::Unknown => false,
    }
}

struct OptionalStageOutcomeV1 {
    report: ExactArtifactStageReportV1,
    observations: Vec<ExactArtifactObservationV1>,
    behavior_bundles: Vec<BehaviorAnalysisBundleV1>,
}

impl OptionalStageOutcomeV1 {
    fn report_only(report: ExactArtifactStageReportV1) -> Self {
        Self {
            report,
            observations: Vec::new(),
            behavior_bundles: Vec::new(),
        }
    }
}

fn run_ai_stage(
    requested: bool,
    requested_provider: Option<&str>,
    adapter: Option<&dyn ExactArtifactAiAdapterV1>,
    prepared: &PreparedArtifact,
    deterministic: &ArtifactStaticAnalysis,
    scenarios: &ExactArtifactScenarioPlanV1,
) -> OptionalStageOutcomeV1 {
    if !requested {
        return OptionalStageOutcomeV1::report_only(ExactArtifactStageReportV1::bound(
            "ai_review",
            ExactArtifactStageStatusV1::NotRequested,
            prepared,
            None,
            vec!["exact_artifact_ai_not_requested".to_string()],
        ));
    }
    let Some(adapter) = adapter else {
        let mut report = ExactArtifactStageReportV1::bound(
            "ai_review",
            ExactArtifactStageStatusV1::Unavailable,
            prepared,
            None,
            vec!["exact_artifact_ai_adapter_not_attached".to_string()],
        );
        report.provider = requested_provider.map(ToString::to_string);
        return OptionalStageOutcomeV1::report_only(report);
    };
    if requested_provider.is_some_and(|provider| provider != adapter.provider_id()) {
        let mut report = ExactArtifactStageReportV1::bound(
            "ai_review",
            ExactArtifactStageStatusV1::Unavailable,
            prepared,
            None,
            vec!["exact_artifact_ai_provider_mismatch".to_string()],
        );
        report.provider = requested_provider.map(ToString::to_string);
        return OptionalStageOutcomeV1::report_only(report);
    }
    if let Some(reason) = adapter.readiness_reason() {
        let mut report = ExactArtifactStageReportV1::bound(
            "ai_review",
            ExactArtifactStageStatusV1::Unavailable,
            prepared,
            None,
            vec![reason.to_string()],
        );
        report.provider = Some(adapter.provider_id().to_string());
        return OptionalStageOutcomeV1::report_only(report);
    }
    let deterministic_analysis_sha256 = match deterministic.analysis_sha256() {
        Ok(value) => value,
        Err(_) => {
            let mut report = ExactArtifactStageReportV1::bound(
                "ai_review",
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec!["exact_artifact_analysis_digest_failed".to_string()],
            );
            report.provider = Some(adapter.provider_id().to_string());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    let adapter_request = match ExactArtifactAdapterRequestV1::new(
        "ai_review",
        adapter.provider_id(),
        prepared,
        scenarios,
        Some(deterministic_analysis_sha256.as_str()),
        None,
    ) {
        Ok(value) => value,
        Err(error) => {
            let mut report = ExactArtifactStageReportV1::bound(
                "ai_review",
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec![error.reason_code().to_string()],
            );
            report.provider = Some(adapter.provider_id().to_string());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    optional_evidence_stage(
        "ai_review",
        adapter.provider_id(),
        prepared,
        &adapter_request,
        adapter.analyze(&adapter_request, prepared, deterministic, scenarios),
        "exact_artifact_ai_adapter_failed",
        None,
    )
}

fn run_detonation_stage(
    requested: bool,
    adapter: Option<&dyn ExactArtifactDetonationAdapterV1>,
    cas: &PersistentQuarantineCas,
    prepared: &PreparedArtifact,
    deterministic: &ArtifactStaticAnalysis,
    scenarios: &ExactArtifactScenarioPlanV1,
) -> OptionalStageOutcomeV1 {
    if !requested {
        return OptionalStageOutcomeV1::report_only(ExactArtifactStageReportV1::bound(
            "detonation",
            ExactArtifactStageStatusV1::NotRequested,
            prepared,
            None,
            vec!["exact_artifact_detonation_not_requested".to_string()],
        ));
    }
    let Some(adapter) = adapter else {
        return OptionalStageOutcomeV1::report_only(ExactArtifactStageReportV1::bound(
            "detonation",
            ExactArtifactStageStatusV1::Unavailable,
            prepared,
            None,
            vec!["exact_artifact_detonation_adapter_not_attached".to_string()],
        ));
    };
    if !matches!(
        scenarios.status,
        ExactArtifactStageStatusV1::Complete | ExactArtifactStageStatusV1::Incomplete
    ) || !scenarios.executable
        || scenarios.runtime_binding_status != "verified"
    {
        let mut report = ExactArtifactStageReportV1::bound(
            "detonation",
            ExactArtifactStageStatusV1::Incomplete,
            prepared,
            None,
            vec![
                "exact_artifact_scenario_plan_not_executable".to_string(),
                "exact_artifact_runtime_binding_not_verified".to_string(),
            ],
        );
        report.provider = Some(adapter.provider_id().to_string());
        return OptionalStageOutcomeV1::report_only(report);
    }
    if let Some(reason) = adapter.readiness_reason() {
        let mut report = ExactArtifactStageReportV1::bound(
            "detonation",
            ExactArtifactStageStatusV1::Unavailable,
            prepared,
            None,
            vec![reason.to_string()],
        );
        report.provider = Some(adapter.provider_id().to_string());
        return OptionalStageOutcomeV1::report_only(report);
    }
    let lease = match prepared.verified_transport_source(cas) {
        Ok(lease) => lease,
        Err(_) => {
            let mut report = ExactArtifactStageReportV1::bound(
                "detonation",
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec!["exact_artifact_transport_reverification_failed".to_string()],
            );
            report.provider = Some(adapter.provider_id().to_string());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    let deterministic_analysis_sha256 = match deterministic.analysis_sha256() {
        Ok(value) => value,
        Err(_) => {
            let mut report = ExactArtifactStageReportV1::bound(
                "detonation",
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec!["exact_artifact_analysis_digest_failed".to_string()],
            );
            report.provider = Some(adapter.provider_id().to_string());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    let adapter_request = match ExactArtifactAdapterRequestV1::new(
        "detonation",
        adapter.provider_id(),
        prepared,
        scenarios,
        Some(deterministic_analysis_sha256.as_str()),
        None,
    ) {
        Ok(value) => value,
        Err(error) => {
            let mut report = ExactArtifactStageReportV1::bound(
                "detonation",
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec![error.reason_code().to_string()],
            );
            report.provider = Some(adapter.provider_id().to_string());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    optional_evidence_stage(
        "detonation",
        adapter.provider_id(),
        prepared,
        &adapter_request,
        adapter.detonate(&adapter_request, &lease, prepared, scenarios),
        "exact_artifact_detonation_adapter_failed",
        None,
    )
}

fn run_behavior_observation_stages(
    requested: bool,
    observer: Option<&dyn ExactArtifactBehaviorObserverV1>,
    prepared: &PreparedArtifact,
    deterministic: &ArtifactStaticAnalysis,
    scenarios: &ExactArtifactScenarioPlanV1,
    mut bundles: Vec<BehaviorAnalysisBundleV1>,
) -> Vec<OptionalStageOutcomeV1> {
    if !requested {
        return vec![OptionalStageOutcomeV1::report_only(
            ExactArtifactStageReportV1::bound(
                "behavior_observation",
                ExactArtifactStageStatusV1::NotRequested,
                prepared,
                None,
                vec!["exact_artifact_behavior_observation_not_requested".to_string()],
            ),
        )];
    }
    let Some(observer) = observer else {
        return vec![OptionalStageOutcomeV1::report_only(
            ExactArtifactStageReportV1::bound(
                "behavior_observation",
                ExactArtifactStageStatusV1::Unavailable,
                prepared,
                None,
                vec!["exact_artifact_behavior_observer_not_attached".to_string()],
            ),
        )];
    };
    if let Some(reason) = observer.readiness_reason() {
        let mut report = ExactArtifactStageReportV1::bound(
            "behavior_observation",
            ExactArtifactStageStatusV1::Unavailable,
            prepared,
            None,
            vec![reason.to_string()],
        );
        report.provider = Some(observer.provider_id().to_string());
        return vec![OptionalStageOutcomeV1::report_only(report)];
    }
    if bundles.is_empty() {
        let mut report = ExactArtifactStageReportV1::bound(
            "behavior_observation",
            ExactArtifactStageStatusV1::Incomplete,
            prepared,
            None,
            vec!["exact_artifact_behavior_bundle_unavailable".to_string()],
        );
        report.provider = Some(observer.provider_id().to_string());
        return vec![OptionalStageOutcomeV1::report_only(report)];
    }
    let deterministic_analysis_sha256 = match deterministic.analysis_sha256() {
        Ok(value) => value,
        Err(_) => {
            let mut report = ExactArtifactStageReportV1::bound(
                "behavior_observation",
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec!["exact_artifact_analysis_digest_failed".to_string()],
            );
            report.provider = Some(observer.provider_id().to_string());
            return vec![OptionalStageOutcomeV1::report_only(report)];
        }
    };
    bundles.sort_by_key(BehaviorAnalysisBundleV1::bundle_sha256);
    bundles
        .into_iter()
        .map(|bundle| {
            let bundle_sha256 = bundle.bundle_sha256();
            let adapter_request = match ExactArtifactAdapterRequestV1::new(
                "behavior_observation",
                observer.provider_id(),
                prepared,
                scenarios,
                Some(deterministic_analysis_sha256.as_str()),
                Some(bundle_sha256.as_str()),
            ) {
                Ok(value) => value,
                Err(error) => {
                    let mut report = ExactArtifactStageReportV1::bound(
                        "behavior_observation",
                        ExactArtifactStageStatusV1::Error,
                        prepared,
                        None,
                        vec![error.reason_code().to_string()],
                    );
                    report.provider = Some(observer.provider_id().to_string());
                    return OptionalStageOutcomeV1::report_only(report);
                }
            };
            optional_evidence_stage(
                "behavior_observation",
                observer.provider_id(),
                prepared,
                &adapter_request,
                observer.observe_behavior(&adapter_request, &bundle),
                "exact_artifact_behavior_observer_failed",
                Some(&bundle),
            )
        })
        .collect()
}

fn optional_evidence_stage(
    stage: &str,
    provider: &str,
    prepared: &PreparedArtifact,
    request: &ExactArtifactAdapterRequestV1,
    result: Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1>,
    fallback_reason: &'static str,
    expected_behavior_bundle: Option<&BehaviorAnalysisBundleV1>,
) -> OptionalStageOutcomeV1 {
    let result = match result {
        Ok(result) => result,
        Err(error) => {
            let reason = if error.reason_code().is_empty() {
                fallback_reason
            } else {
                error.reason_code()
            };
            let mut report = ExactArtifactStageReportV1::bound(
                stage,
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec![reason.to_string()],
            );
            report.provider = Some(provider.to_string());
            report.request_sha256 = Some(request.request_sha256.clone());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    if result.canonical_result_bytes.is_empty()
        || result.canonical_result_bytes.len() > MAX_EXACT_ARTIFACT_OPTIONAL_RESULT_BYTES_V1
    {
        let mut report = ExactArtifactStageReportV1::bound(
            stage,
            ExactArtifactStageStatusV1::Error,
            prepared,
            None,
            vec!["exact_artifact_optional_result_size_invalid".to_string()],
        );
        report.provider = Some(provider.to_string());
        report.request_sha256 = Some(request.request_sha256.clone());
        return OptionalStageOutcomeV1::report_only(report);
    }
    let canonical_result = match serde_json::from_slice::<ExactArtifactOptionalResultV1>(
        &result.canonical_result_bytes,
    ) {
        Ok(value) if value.validate().is_ok() => value,
        _ => {
            let mut report = ExactArtifactStageReportV1::bound(
                stage,
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec!["exact_artifact_optional_result_invalid".to_string()],
            );
            report.provider = Some(provider.to_string());
            report.request_sha256 = Some(request.request_sha256.clone());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    let reencoded = match canonical_result.to_canonical_json_bytes() {
        Ok(value) => value,
        Err(_) => {
            let mut report = ExactArtifactStageReportV1::bound(
                stage,
                ExactArtifactStageStatusV1::Error,
                prepared,
                None,
                vec!["exact_artifact_optional_result_invalid".to_string()],
            );
            report.provider = Some(provider.to_string());
            report.request_sha256 = Some(request.request_sha256.clone());
            return OptionalStageOutcomeV1::report_only(report);
        }
    };
    if reencoded != result.canonical_result_bytes {
        let mut report = ExactArtifactStageReportV1::bound(
            stage,
            ExactArtifactStageStatusV1::Error,
            prepared,
            None,
            vec!["exact_artifact_optional_result_not_canonical".to_string()],
        );
        report.provider = Some(provider.to_string());
        report.request_sha256 = Some(request.request_sha256.clone());
        return OptionalStageOutcomeV1::report_only(report);
    }
    if canonical_result.request_sha256 != request.request_sha256 {
        let mut report = ExactArtifactStageReportV1::bound(
            stage,
            ExactArtifactStageStatusV1::Error,
            prepared,
            None,
            vec!["exact_artifact_optional_evidence_request_binding_invalid".to_string()],
        );
        report.provider = Some(provider.to_string());
        report.request_sha256 = Some(request.request_sha256.clone());
        return OptionalStageOutcomeV1::report_only(report);
    }
    let mut bundle_sha256s = result
        .behavior_bundles
        .iter()
        .map(BehaviorAnalysisBundleV1::bundle_sha256)
        .collect::<Vec<_>>();
    bundle_sha256s.sort();
    if bundle_sha256s != canonical_result.behavior_bundle_sha256s
        || result.behavior_bundles.len() > MAX_EXACT_ARTIFACT_BEHAVIOR_BUNDLES_V1
        || result.behavior_bundles.iter().any(|bundle| {
            bundle.artifact_sha256().as_str() != request.artifact_sha256
                || bundle.manifest_sha256().as_str() != request.manifest_sha256
                || serde_json::to_vec(bundle)
                    .ok()
                    .and_then(|bytes| {
                        whoathere_detector::decode_and_validate_behavior_analysis_bundle_v1(&bytes)
                            .ok()
                    })
                    .is_none()
        })
    {
        return optional_stage_error(
            stage,
            provider,
            prepared,
            request,
            "exact_artifact_behavior_bundle_binding_invalid",
        );
    }
    if canonical_result.observations.iter().any(|observation| {
        observation.artifact_sha256.as_str() != request.artifact_sha256
            || observation.manifest_sha256.as_str() != request.manifest_sha256
    }) {
        return optional_stage_error(
            stage,
            provider,
            prepared,
            request,
            "exact_artifact_observation_binding_invalid",
        );
    }
    if canonical_result.observations.iter().any(|observation| {
        !observation_evidence_resolves_v1(prepared, expected_behavior_bundle, observation)
    }) {
        return optional_stage_error(
            stage,
            provider,
            prepared,
            request,
            "exact_artifact_observation_evidence_invalid",
        );
    }
    let stage_shape_valid = match stage {
        "ai_review" => {
            result.behavior_bundles.is_empty()
                && canonical_result.observations.iter().all(|observation| {
                    observation.source == ExactArtifactObservationSourceV1::AiSourceReview
                        && !observation.behavior_detection_eligible
                })
        }
        "detonation" => canonical_result.observations.is_empty(),
        "behavior_observation" => {
            result.behavior_bundles.is_empty()
                && request
                    .behavior_bundle_sha256
                    .as_deref()
                    .is_some_and(|expected| {
                        canonical_result.observations.iter().all(|observation| {
                            observation.source == ExactArtifactObservationSourceV1::AiBehavioral
                                && matches!(
                                    &observation.finding_kind,
                                    ExactArtifactFindingKindV1::AiBehavioral(kind)
                                        if observation.behavior_detection_eligible
                                            == behavior_finding_detection_eligible_v1(*kind)
                                )
                                && matches!(
                                    &observation.evidence,
                                    ExactArtifactEvidenceReferenceV1::AiBehavioral {
                                        bundle_sha256,
                                        ..
                                    } if bundle_sha256.as_str() == expected
                                )
                        })
                    })
        }
        _ => false,
    };
    if !stage_shape_valid {
        return optional_stage_error(
            stage,
            provider,
            prepared,
            request,
            "exact_artifact_optional_evidence_stage_shape_invalid",
        );
    }
    let result_sha256 = Sha256Digest::from_bytes(&reencoded).to_string();
    let status = match canonical_result.outcome {
        BoundOptionalEvidenceOutcomeV1::Findings => ExactArtifactStageStatusV1::Findings,
        BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage => {
            ExactArtifactStageStatusV1::FindingsWithIncompleteCoverage
        }
        BoundOptionalEvidenceOutcomeV1::BoundedNoFinding => ExactArtifactStageStatusV1::Complete,
        BoundOptionalEvidenceOutcomeV1::Incomplete => ExactArtifactStageStatusV1::Incomplete,
    };
    let mut report = ExactArtifactStageReportV1::bound(
        stage,
        status,
        prepared,
        Some(result_sha256),
        canonical_result.reason_codes,
    );
    report.provider = Some(provider.to_string());
    report.request_sha256 = Some(request.request_sha256.clone());
    report.observation_count = canonical_result.observations.len();
    OptionalStageOutcomeV1 {
        report,
        observations: canonical_result.observations,
        behavior_bundles: result.behavior_bundles,
    }
}

fn observation_evidence_resolves_v1(
    prepared: &PreparedArtifact,
    expected_behavior_bundle: Option<&BehaviorAnalysisBundleV1>,
    observation: &ExactArtifactObservationV1,
) -> bool {
    match &observation.evidence {
        ExactArtifactEvidenceReferenceV1::DeterministicStatic { .. } => {
            observation.source == ExactArtifactObservationSourceV1::DeterministicStatic
        }
        ExactArtifactEvidenceReferenceV1::AiSourceReview {
            file_id,
            file_sha256,
            start_byte,
            end_byte,
            selected_sha256,
            ..
        } => {
            let Some(file) = prepared.normalized().file(file_id) else {
                return false;
            };
            let Ok(start) = usize::try_from(*start_byte) else {
                return false;
            };
            let Ok(end) = usize::try_from(*end_byte) else {
                return false;
            };
            file.sha256 == *file_sha256
                && start < end
                && end <= file.bytes().len()
                && Sha256Digest::from_bytes(&file.bytes()[start..end]) == *selected_sha256
        }
        ExactArtifactEvidenceReferenceV1::AiBehavioral {
            bundle_sha256,
            finding_sha256,
            events,
        } => {
            let Some(bundle) = expected_behavior_bundle else {
                return false;
            };
            let ExactArtifactFindingKindV1::AiBehavioral(kind) = &observation.finding_kind else {
                return false;
            };
            let expected_finding_sha256 = serde_json::to_vec(&(*kind, events))
                .map(|identity| Sha256Digest::from_bytes(&identity));
            bundle.bundle_sha256() == *bundle_sha256
                && expected_finding_sha256.is_ok_and(|expected| expected == *finding_sha256)
                && events.iter().all(|reference| {
                    bundle
                        .event(reference.event_id())
                        .is_some_and(|event| event.event_sha256() == *reference.event_sha256())
                })
        }
    }
}

fn optional_stage_error(
    stage: &str,
    provider: &str,
    prepared: &PreparedArtifact,
    request: &ExactArtifactAdapterRequestV1,
    reason: &str,
) -> OptionalStageOutcomeV1 {
    let mut report = ExactArtifactStageReportV1::bound(
        stage,
        ExactArtifactStageStatusV1::Error,
        prepared,
        None,
        vec![reason.to_string()],
    );
    report.provider = Some(provider.to_string());
    report.request_sha256 = Some(request.request_sha256.clone());
    OptionalStageOutcomeV1::report_only(report)
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
    values
}

fn valid_reason_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 128
        && code.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'_' | b'-' | b'.' | b':')
        })
}
