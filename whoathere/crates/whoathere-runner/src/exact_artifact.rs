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
    ArtifactAnalysisCompleteness, ArtifactAnalysisOutcome, ArtifactStaticAnalysis,
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
pub const MAX_EXACT_ARTIFACT_OPTIONAL_RESULT_BYTES_V1: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExactArtifactDispositionV1 {
    Findings,
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
            || self.reason_codes != sorted_unique(self.reason_codes.clone())
            || self.reason_codes.iter().any(|code| {
                code.len() > 128
                    || !code.bytes().all(|byte| {
                        byte.is_ascii_lowercase()
                            || byte.is_ascii_digit()
                            || matches!(byte, b'_' | b'-' | b'.' | b':')
                    })
            })
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
}

impl ExactArtifactAdapterRequestV1 {
    fn new(
        stage: &'static str,
        provider: &str,
        prepared: &PreparedArtifact,
        scenarios: &ExactArtifactScenarioPlanV1,
        deterministic_analysis_sha256: Option<&str>,
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

/// Capability boundary for a contained execution backend.
///
/// Implementations must re-open the supplied `PreparedArtifact` through its
/// verified transport source before execution. The product spine never treats
/// backend availability as execution evidence.
pub trait ExactArtifactDetonationAdapterV1 {
    fn provider_id(&self) -> &str;
    fn readiness_reason(&self) -> Option<&'static str>;
    /// Returns true only when this adapter can bind and execute the supplied
    /// complete scenario plan with its currently configured runtime.
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
    pub exit_code: i32,
    pub identity: ExactArtifactIdentityV1,
    pub stages: Vec<ExactArtifactStageReportV1>,
    pub scenario_plan: ExactArtifactScenarioPlanV1,
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
            if scenario_plan.status == ExactArtifactStageStatusV1::Complete
                && adapter.readiness_reason().is_none()
                && adapter.supports_runtime_binding(&prepared, &scenario_plan)
            {
                scenario_plan = scenario_plan.with_verified_runtime_binding()?;
            }
        }
    }

    let mut stages = vec![
        ExactArtifactStageReportV1::bound(
            "quarantine",
            ExactArtifactStageStatusV1::Complete,
            &prepared,
            None,
            vec!["exact_artifact_quarantined_and_reverified".to_string()],
        ),
        normalization_stage(&prepared),
        deterministic_stage(&prepared, &deterministic)?,
        ExactArtifactStageReportV1::bound(
            "scenario_compilation",
            scenario_plan.status,
            &prepared,
            Some(scenario_plan.plan_sha256.clone()),
            scenario_plan.reason_codes.clone(),
        ),
    ];
    stages.push(run_ai_stage(
        request.ai_requested,
        request.ai_provider,
        ai_adapter,
        &prepared,
        &deterministic,
        &scenario_plan,
    ));
    stages.push(run_detonation_stage(
        request.detonation_requested,
        detonation_adapter,
        &cas,
        &prepared,
        &deterministic,
        &scenario_plan,
    ));

    let has_findings = stages.iter().any(|stage| {
        matches!(
            stage.status,
            ExactArtifactStageStatusV1::Findings
                | ExactArtifactStageStatusV1::FindingsWithIncompleteCoverage
        )
    });
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
    let mut reason_codes = stages
        .iter()
        .flat_map(|stage| stage.reason_codes.iter().cloned())
        .collect::<Vec<_>>();
    reason_codes.push("exact_artifact_spine_has_no_admission_authority".to_string());
    reason_codes.push("exact_artifact_missing_evidence_never_observed_clean".to_string());
    reason_codes.push("exact_artifact_legacy_workspace_review_not_used".to_string());
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
        admission_authority: false,
        observed_clean: false,
        sync_back_enabled: false,
        reason_codes: sorted_unique(reason_codes),
    })
}

fn manifest_requires_external_resolution(manifest: &whoathere_artifact::ArtifactManifest) -> bool {
    if let Some(npm) = &manifest.metadata.npm {
        return npm.requires_offline_closure || !npm.dependency_declarations.is_empty();
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

fn checked_filename(path: &Path) -> Result<String, ExactArtifactInspectionErrorV1> {
    let filename = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| ExactArtifactInspectionErrorV1::misuse("exact_artifact_filename_invalid"))?;
    Ok(filename.to_string())
}

fn read_exact_artifact(
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

fn declared_format_for(ecosystem: Ecosystem, filename: &str) -> Option<ArtifactFormat> {
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
                || !npm.dependency_declarations.is_empty()
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
            let mut kinds = vec![
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiFalse,
                }),
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiTrue,
                }),
            ];
            if npm.main_target.is_some() || !npm.export_targets.is_empty() {
                kinds.push(ExactArtifactScenarioKindV1::Npm(
                    ArtifactScenarioKindV1::NpmMainOrExportProbe,
                ));
            }
            if !npm.bin_targets.is_empty() {
                kinds.push(ExactArtifactScenarioKindV1::Npm(
                    ArtifactScenarioKindV1::NpmBinProbe,
                ));
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
            // the post-build probe matrix. Until an authenticated derived-wheel
            // manifest seals the exact wheel digest and enumerates its `.pth`,
            // import, and entry-point triggers, authorize only build and derived
            // artifact inspection intent.
            reasons.push("exact_artifact_derived_wheel_probe_manifest_required".to_string());
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

fn run_ai_stage(
    requested: bool,
    requested_provider: Option<&str>,
    adapter: Option<&dyn ExactArtifactAiAdapterV1>,
    prepared: &PreparedArtifact,
    deterministic: &ArtifactStaticAnalysis,
    scenarios: &ExactArtifactScenarioPlanV1,
) -> ExactArtifactStageReportV1 {
    if !requested {
        return ExactArtifactStageReportV1::bound(
            "ai_review",
            ExactArtifactStageStatusV1::NotRequested,
            prepared,
            None,
            vec!["exact_artifact_ai_not_requested".to_string()],
        );
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
        return report;
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
        return report;
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
        return report;
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
            return report;
        }
    };
    let adapter_request = match ExactArtifactAdapterRequestV1::new(
        "ai_review",
        adapter.provider_id(),
        prepared,
        scenarios,
        Some(deterministic_analysis_sha256.as_str()),
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
            return report;
        }
    };
    optional_evidence_stage(
        "ai_review",
        adapter.provider_id(),
        prepared,
        &adapter_request,
        adapter.analyze(&adapter_request, prepared, deterministic, scenarios),
        "exact_artifact_ai_adapter_failed",
    )
}

fn run_detonation_stage(
    requested: bool,
    adapter: Option<&dyn ExactArtifactDetonationAdapterV1>,
    cas: &PersistentQuarantineCas,
    prepared: &PreparedArtifact,
    deterministic: &ArtifactStaticAnalysis,
    scenarios: &ExactArtifactScenarioPlanV1,
) -> ExactArtifactStageReportV1 {
    if !requested {
        return ExactArtifactStageReportV1::bound(
            "detonation",
            ExactArtifactStageStatusV1::NotRequested,
            prepared,
            None,
            vec!["exact_artifact_detonation_not_requested".to_string()],
        );
    }
    let Some(adapter) = adapter else {
        return ExactArtifactStageReportV1::bound(
            "detonation",
            ExactArtifactStageStatusV1::Unavailable,
            prepared,
            None,
            vec!["exact_artifact_detonation_adapter_not_attached".to_string()],
        );
    };
    if scenarios.status != ExactArtifactStageStatusV1::Complete
        || !scenarios.executable
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
        return report;
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
        return report;
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
            return report;
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
            return report;
        }
    };
    let adapter_request = match ExactArtifactAdapterRequestV1::new(
        "detonation",
        adapter.provider_id(),
        prepared,
        scenarios,
        Some(deterministic_analysis_sha256.as_str()),
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
            return report;
        }
    };
    optional_evidence_stage(
        "detonation",
        adapter.provider_id(),
        prepared,
        &adapter_request,
        adapter.detonate(&adapter_request, &lease, prepared, scenarios),
        "exact_artifact_detonation_adapter_failed",
    )
}

fn optional_evidence_stage(
    stage: &str,
    provider: &str,
    prepared: &PreparedArtifact,
    request: &ExactArtifactAdapterRequestV1,
    result: Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1>,
    fallback_reason: &'static str,
) -> ExactArtifactStageReportV1 {
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
            return report;
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
        return report;
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
            return report;
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
            return report;
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
        return report;
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
        return report;
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
    report
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.retain(|value| !value.is_empty());
    values.sort();
    values.dedup();
    values
}
