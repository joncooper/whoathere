//! Strict presentation boundary for the P05 paired npm VM/Codex diagnostic.
//!
//! The envelope contains sanitized typed behavior bundles and a prose-free
//! projection of Codex findings. It is presentation evidence only: it neither
//! authenticates the upstream producer nor contributes admission authority.

use crate::{
    ExactArtifactInspectionReportV1, ExactArtifactStageStatusV1,
    RetainedExactArtifactReportPostureV1, ValidatedRetainedExactArtifactReportV1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use whoathere_artifact::Sha256Digest;
use whoathere_detector::{
    decode_and_validate_behavior_analysis_bundle_v1, BehaviorAnalysisBundleV1,
    BehaviorCoverageStateV1, BehaviorEvidenceModalityV1, BehaviorEvidenceReferenceV1,
    BehaviorEvidenceSignalV1, BehaviorFindingConfidenceV1, BehaviorFindingKindV1,
    BehaviorThreatClassV1, FileOperationV1, FileTargetClassV1, NetworkActionV1,
    NetworkDestinationClassV1, PackageTriggerV1, ProcessActionV1, SpecialistRoleV1,
};

pub const PAIRED_NPM_REPORT_RECONCILIATION_SCHEMA_V1: &str =
    "whoathere.paired_npm_report_reconciliation.v1";

const SOURCE_RECONCILIATION_SCHEMA_V1: &str = "whoathere.two_host_behavior_diagnostic.v1";
const BEHAVIOR_OBSERVE_SCHEMA_V1: &str = "whoathere.behavior_observe.v1";
const BEHAVIOR_CODEX_PANEL_SCHEMA_V1: &str = "whoathere.behavior_codex_panel.v1";
const DETONATION_PROVIDER_V1: &str = "linux_vz_exact_npm_v1";
const MAX_RECONCILIATION_BYTES: usize = 8 * 1024 * 1024;

// P05 is deliberately a presentation boundary for one frozen diagnostic, not a
// general evidence-ingestion protocol. These identities prevent a caller from
// changing a source identity or normalized Codex projection and merely supplying
// the recomputed detached envelope digest.
const FROZEN_P05_ARTIFACT_SHA256: &str =
    "sha256:0b8e586c7a91fce4fac8296a069c1c5e673046261958e9ba519e6b6e3b458933";
const FROZEN_P05_MANIFEST_SHA256: &str =
    "sha256:14da51ba0162c2658057202df1e94d71b7a89d5f2a813464830b3eadd06f7f37";
const FROZEN_P05_REPORT_SHA256: &str =
    "sha256:bc09a308462940012d9060b54a46ff7568ee94d04a5ccb2d10a3faeca1a5e452";
const FROZEN_P05_EXPORT_MANIFEST_SHA256: &str =
    "sha256:12686a54572505ab36eabd45690919de83cdf13becaf58364c7ced56d4fe0f57";
const FROZEN_P05_SOURCE_RECONCILIATION_SHA256: &str =
    "sha256:e01f4bd4844756bdd5b07a2d3dd111be9283561fad319d3d3be2af7ff852a5c7";
const FROZEN_P05_SOURCE_INPUT_BINDING_SHA256: &str =
    "sha256:bb44a2843b20486d56a8f473d74f283da96187d1d26cdecdc89f233e8c7782f6";
const FROZEN_P05_SCENARIO_PLAN_SHA256: &str =
    "sha256:4beb163692fa5d6e19822e91dea11b3cf217fe11341f2708221b93459b9c81ca";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairedNpmProfileV1 {
    CiFalse,
    CiTrue,
}

impl PairedNpmProfileV1 {
    pub const ALL: [Self; 2] = [Self::CiFalse, Self::CiTrue];

    pub const fn label(self) -> &'static str {
        match self {
            Self::CiFalse => "CI=false",
            Self::CiTrue => "CI=true",
        }
    }

    const fn action_key(self) -> &'static str {
        match self {
            Self::CiFalse => "vm_ci_false",
            Self::CiTrue => "vm_ci_true",
        }
    }

    const fn scenario_id(self) -> &'static str {
        match self {
            Self::CiFalse => "linux-vz-inert-execution-gate-scenario-ci-false-v1",
            Self::CiTrue => "linux-vz-inert-execution-gate-scenario-ci-true-v1",
        }
    }

    const fn run_id(self) -> &'static str {
        match self {
            Self::CiFalse => "linux-vz-inert-execution-gate-run-ci-false-v1",
            Self::CiTrue => "linux-vz-inert-execution-gate-run-ci-true-v1",
        }
    }

    const fn frozen_bundle_sha256(self) -> &'static str {
        match self {
            Self::CiFalse => {
                "sha256:01c28b2fe0ed53aea0a1886056223e11ffc02f6b528f25fa69ee4cb632d840e8"
            }
            Self::CiTrue => {
                "sha256:245f5553dfc4e0e2c4f8029cfdefa12a53452fc922252b3838f06535236f7a81"
            }
        }
    }

    const fn frozen_observer_result_sha256(self) -> &'static str {
        match self {
            Self::CiFalse => {
                "sha256:410ee27561e37c00c0c48ce2a04046de4e53c88f33928bc63f55085ad95c522f"
            }
            Self::CiTrue => {
                "sha256:4ca1d74a169fc71b3c9bc1a3e8f9924a1e69594d7b712aecbc9df363edf0a4cf"
            }
        }
    }

    const fn frozen_codex_projection_sha256(self) -> &'static str {
        match self {
            Self::CiFalse => {
                "sha256:6c75c012c4d3318b0b24322ecb86b781717ac7ea183016bdb901ed90081dbbf2"
            }
            Self::CiTrue => {
                "sha256:8665b50bbd152c324b1302db95ac7f0e2ed906d57ae035bee1dcf0b4fc572612"
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedNpmReportReconciliationWireV1 {
    schema_version: String,
    artifact_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    report_sha256: Sha256Digest,
    export_manifest_sha256: Sha256Digest,
    source_reconciliation_schema_version: String,
    source_reconciliation_sha256: Sha256Digest,
    source_reconciliation_input_binding_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_intent_count: usize,
    detonation_provider: String,
    detonation_status: String,
    profiles: Vec<PairedNpmProfileWireV1>,
    reconciliation_complete: bool,
    diagnostic_only: bool,
    claim_bearing: bool,
    sanitized_projection: bool,
    raw_source_or_telemetry_included: bool,
    admission_authority: bool,
    observed_clean: bool,
    sync_back_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedNpmProfileWireV1 {
    profile: PairedNpmProfileV1,
    action_key: String,
    bundle_sha256: Sha256Digest,
    observer_result_sha256: Sha256Digest,
    event_count: usize,
    evidence_coverage_complete: bool,
    behavior_bundle: BehaviorAnalysisBundleV1,
    codex: PairedNpmCodexProjectionWireV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedNpmCodexProjectionWireV1 {
    schema_version: String,
    status: String,
    provider: String,
    artifact_sha256: Sha256Digest,
    bundle_sha256: Sha256Digest,
    panel_schema_version: String,
    panel_outcome: String,
    panel_reason_code: String,
    provider_receipts: Vec<PairedNpmProviderReceiptIdentityWireV1>,
    specialist_report_sha256s: Vec<Sha256Digest>,
    measured_correlation_json_sha256: Sha256Digest,
    correlation_conclusion: String,
    missing_roles: Vec<SpecialistRoleV1>,
    coverage_gap_codes: Vec<String>,
    positive_preservation_verified: bool,
    role_failure_count: usize,
    findings: Vec<PairedNpmCodexFindingWireV1>,
    observe_only: bool,
    admission_authority: bool,
    observed_clean: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedNpmProviderReceiptIdentityWireV1 {
    selected_role: SpecialistRoleV1,
    measured_receipt_json_sha256: Sha256Digest,
    provider_output_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedNpmCodexFindingWireV1 {
    kind: BehaviorFindingKindV1,
    threat_class: BehaviorThreatClassV1,
    confidence: BehaviorFindingConfidenceV1,
    evidence: Vec<BehaviorEvidenceReferenceV1>,
    finding_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SourceReconciliationInputBindingV1<'a> {
    artifact_sha256: &'a Sha256Digest,
    bundles: Vec<[&'a Sha256Digest; 2]>,
    remote_report_sha256: &'a Sha256Digest,
    scenario_plan_sha256: &'a Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedNpmCoverageSummaryV1 {
    modality: BehaviorEvidenceModalityV1,
    limitation_codes: Vec<String>,
}

impl PairedNpmCoverageSummaryV1 {
    pub const fn modality(&self) -> BehaviorEvidenceModalityV1 {
        self.modality
    }

    pub fn limitation_codes(&self) -> &[String] {
        &self.limitation_codes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedNpmCodexFindingSummaryV1 {
    kind: BehaviorFindingKindV1,
    confidence: BehaviorFindingConfidenceV1,
    finding_sha256: Sha256Digest,
    evidence: Vec<BehaviorEvidenceReferenceV1>,
}

impl PairedNpmCodexFindingSummaryV1 {
    pub const fn kind(&self) -> BehaviorFindingKindV1 {
        self.kind
    }

    pub const fn confidence(&self) -> BehaviorFindingConfidenceV1 {
        self.confidence
    }

    pub fn finding_sha256(&self) -> &Sha256Digest {
        &self.finding_sha256
    }

    pub fn evidence(&self) -> &[BehaviorEvidenceReferenceV1] {
        &self.evidence
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPairedNpmProfileV1 {
    profile: PairedNpmProfileV1,
    bundle_sha256: Sha256Digest,
    observer_result_sha256: Sha256Digest,
    scenario_id: String,
    run_id: String,
    event_count: usize,
    lifecycle_event_count: usize,
    credential_read_event_count: usize,
    connect_event_count: usize,
    send_event_count: usize,
    coverage: Vec<PairedNpmCoverageSummaryV1>,
    codex_findings: Vec<PairedNpmCodexFindingSummaryV1>,
}

impl ValidatedPairedNpmProfileV1 {
    pub const fn profile(&self) -> PairedNpmProfileV1 {
        self.profile
    }

    pub fn bundle_sha256(&self) -> &Sha256Digest {
        &self.bundle_sha256
    }

    pub fn observer_result_sha256(&self) -> &Sha256Digest {
        &self.observer_result_sha256
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub const fn event_count(&self) -> usize {
        self.event_count
    }

    pub const fn lifecycle_event_count(&self) -> usize {
        self.lifecycle_event_count
    }

    pub const fn credential_read_event_count(&self) -> usize {
        self.credential_read_event_count
    }

    pub const fn connect_event_count(&self) -> usize {
        self.connect_event_count
    }

    pub const fn send_event_count(&self) -> usize {
        self.send_event_count
    }

    pub fn coverage(&self) -> &[PairedNpmCoverageSummaryV1] {
        &self.coverage
    }

    pub fn codex_findings(&self) -> &[PairedNpmCodexFindingSummaryV1] {
        &self.codex_findings
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedPairedNpmReportReconciliationV1 {
    envelope_sha256: Sha256Digest,
    export_manifest_sha256: Sha256Digest,
    source_reconciliation_sha256: Sha256Digest,
    source_reconciliation_input_binding_sha256: Sha256Digest,
    profiles: Vec<ValidatedPairedNpmProfileV1>,
}

impl ValidatedPairedNpmReportReconciliationV1 {
    pub fn envelope_sha256(&self) -> &Sha256Digest {
        &self.envelope_sha256
    }

    pub fn export_manifest_sha256(&self) -> &Sha256Digest {
        &self.export_manifest_sha256
    }

    pub fn source_reconciliation_sha256(&self) -> &Sha256Digest {
        &self.source_reconciliation_sha256
    }

    pub fn source_reconciliation_input_binding_sha256(&self) -> &Sha256Digest {
        &self.source_reconciliation_input_binding_sha256
    }

    pub fn profiles(&self) -> &[ValidatedPairedNpmProfileV1] {
        &self.profiles
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }

    pub const fn observed_clean(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairedNpmReportReconciliationErrorV1 {
    reason_code: &'static str,
}

impl PairedNpmReportReconciliationErrorV1 {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    pub const fn exit_code(&self) -> i32 {
        64
    }
}

impl std::fmt::Display for PairedNpmReportReconciliationErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for PairedNpmReportReconciliationErrorV1 {}

pub fn read_and_validate_paired_npm_report_reconciliation_v1(
    path: &Path,
    expected_envelope_sha256: &str,
    retained: &ValidatedRetainedExactArtifactReportV1,
    report_sha256: &str,
) -> Result<ValidatedPairedNpmReportReconciliationV1, PairedNpmReportReconciliationErrorV1> {
    let bytes = read_reconciliation_file(path)?;
    decode_and_validate_paired_npm_report_reconciliation_v1(
        &bytes,
        expected_envelope_sha256,
        retained,
        report_sha256,
    )
}

pub fn decode_and_validate_paired_npm_report_reconciliation_v1(
    bytes: &[u8],
    expected_envelope_sha256: &str,
    retained: &ValidatedRetainedExactArtifactReportV1,
    report_sha256: &str,
) -> Result<ValidatedPairedNpmReportReconciliationV1, PairedNpmReportReconciliationErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_RECONCILIATION_BYTES {
        return Err(PairedNpmReportReconciliationErrorV1::new(
            "paired_npm_reconciliation_size_out_of_bounds",
        ));
    }
    let expected = Sha256Digest::parse(expected_envelope_sha256.to_string()).map_err(|_| {
        PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_sha256_invalid")
    })?;
    let envelope_sha256 = Sha256Digest::from_bytes(bytes);
    if envelope_sha256 != expected {
        return Err(PairedNpmReportReconciliationErrorV1::new(
            "paired_npm_reconciliation_sha256_mismatch",
        ));
    }
    let report_sha256 = Sha256Digest::parse(report_sha256.to_string()).map_err(|_| {
        PairedNpmReportReconciliationErrorV1::new(
            "paired_npm_reconciliation_report_binding_invalid",
        )
    })?;
    let wire: PairedNpmReportReconciliationWireV1 =
        serde_json::from_slice(bytes).map_err(|_| {
            PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_json_invalid")
        })?;
    validate_frozen_p05_contract(&wire)?;
    validate_wire(wire, envelope_sha256, retained, report_sha256)
}

fn validate_frozen_p05_contract(
    wire: &PairedNpmReportReconciliationWireV1,
) -> Result<(), PairedNpmReportReconciliationErrorV1> {
    let invalid =
        || PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_semantics_invalid");
    if wire.artifact_sha256.as_str() != FROZEN_P05_ARTIFACT_SHA256
        || wire.manifest_sha256.as_str() != FROZEN_P05_MANIFEST_SHA256
        || wire.report_sha256.as_str() != FROZEN_P05_REPORT_SHA256
        || wire.export_manifest_sha256.as_str() != FROZEN_P05_EXPORT_MANIFEST_SHA256
        || wire.source_reconciliation_sha256.as_str() != FROZEN_P05_SOURCE_RECONCILIATION_SHA256
        || wire.source_reconciliation_input_binding_sha256.as_str()
            != FROZEN_P05_SOURCE_INPUT_BINDING_SHA256
        || wire.scenario_plan_sha256.as_str() != FROZEN_P05_SCENARIO_PLAN_SHA256
        || wire.profiles.len() != PairedNpmProfileV1::ALL.len()
    {
        return Err(invalid());
    }

    for (expected_profile, profile) in PairedNpmProfileV1::ALL.iter().copied().zip(&wire.profiles) {
        let projection_sha256 =
            Sha256Digest::from_bytes(&serde_json::to_vec(&profile.codex).map_err(|_| invalid())?);
        if profile.profile != expected_profile
            || profile.bundle_sha256.as_str() != expected_profile.frozen_bundle_sha256()
            || profile.observer_result_sha256.as_str()
                != expected_profile.frozen_observer_result_sha256()
            || projection_sha256.as_str() != expected_profile.frozen_codex_projection_sha256()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_wire(
    wire: PairedNpmReportReconciliationWireV1,
    envelope_sha256: Sha256Digest,
    retained: &ValidatedRetainedExactArtifactReportV1,
    report_sha256: Sha256Digest,
) -> Result<ValidatedPairedNpmReportReconciliationV1, PairedNpmReportReconciliationErrorV1> {
    validate_wire_against_report(
        wire,
        envelope_sha256,
        retained.report(),
        retained.posture(),
        report_sha256,
    )
}

fn validate_wire_against_report(
    wire: PairedNpmReportReconciliationWireV1,
    envelope_sha256: Sha256Digest,
    report: &ExactArtifactInspectionReportV1,
    posture: RetainedExactArtifactReportPostureV1,
    report_sha256: Sha256Digest,
) -> Result<ValidatedPairedNpmReportReconciliationV1, PairedNpmReportReconciliationErrorV1> {
    let invalid =
        || PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_semantics_invalid");
    if wire.schema_version != PAIRED_NPM_REPORT_RECONCILIATION_SCHEMA_V1 {
        return Err(PairedNpmReportReconciliationErrorV1::new(
            "paired_npm_reconciliation_schema_unsupported",
        ));
    }
    if posture != RetainedExactArtifactReportPostureV1::SanitizedProjectionV1
        || wire.artifact_sha256.as_str() != report.identity.artifact_sha256
        || wire.manifest_sha256.as_str() != report.identity.manifest_sha256
        || wire.report_sha256 != report_sha256
        || wire.source_reconciliation_schema_version != SOURCE_RECONCILIATION_SCHEMA_V1
        || wire.scenario_plan_sha256.as_str() != report.scenario_plan.plan_sha256
        || wire.scenario_intent_count != 2
        || wire.detonation_provider != DETONATION_PROVIDER_V1
        || wire.detonation_status != "incomplete"
        || wire.profiles.len() != PairedNpmProfileV1::ALL.len()
        || !wire.reconciliation_complete
        || !wire.diagnostic_only
        || wire.claim_bearing
        || !wire.sanitized_projection
        || wire.raw_source_or_telemetry_included
        || wire.admission_authority
        || wire.observed_clean
        || wire.sync_back_enabled
        || !report_matches_detonation(report, &wire)
    {
        return Err(invalid());
    }

    let mut validated_profiles = Vec::with_capacity(wire.profiles.len());
    let mut bundle_identities = BTreeSet::new();
    let mut observer_identities = BTreeSet::new();
    let mut run_ids = BTreeSet::new();
    let mut receipt_identities = BTreeSet::new();
    for (expected_profile, profile) in PairedNpmProfileV1::ALL
        .iter()
        .copied()
        .zip(wire.profiles.iter())
    {
        if profile.profile != expected_profile
            || !bundle_identities.insert(profile.bundle_sha256.clone())
            || !observer_identities.insert(profile.observer_result_sha256.clone())
        {
            return Err(invalid());
        }
        let validated = validate_profile(
            profile,
            &wire.artifact_sha256,
            &wire.manifest_sha256,
            &mut run_ids,
            &mut receipt_identities,
        )?;
        validated_profiles.push(validated);
    }

    let binding = SourceReconciliationInputBindingV1 {
        artifact_sha256: &wire.artifact_sha256,
        bundles: wire
            .profiles
            .iter()
            .map(|profile| [&profile.bundle_sha256, &profile.observer_result_sha256])
            .collect(),
        remote_report_sha256: &wire.report_sha256,
        scenario_plan_sha256: &wire.scenario_plan_sha256,
    };
    let binding_sha256 =
        Sha256Digest::from_bytes(&serde_json::to_vec(&binding).map_err(|_| invalid())?);
    if binding_sha256 != wire.source_reconciliation_input_binding_sha256 {
        return Err(invalid());
    }

    Ok(ValidatedPairedNpmReportReconciliationV1 {
        envelope_sha256,
        export_manifest_sha256: wire.export_manifest_sha256,
        source_reconciliation_sha256: wire.source_reconciliation_sha256,
        source_reconciliation_input_binding_sha256: binding_sha256,
        profiles: validated_profiles,
    })
}

fn report_matches_detonation(
    report: &ExactArtifactInspectionReportV1,
    wire: &PairedNpmReportReconciliationWireV1,
) -> bool {
    let mut stages = report
        .stages
        .iter()
        .filter(|stage| stage.stage == "detonation");
    let Some(stage) = stages.next() else {
        return false;
    };
    stages.next().is_none()
        && stage.status == ExactArtifactStageStatusV1::Incomplete
        && stage.provider.as_deref() == Some(wire.detonation_provider.as_str())
        && stage.artifact_sha256.as_deref() == Some(wire.artifact_sha256.as_str())
        && stage.manifest_sha256.as_deref() == Some(wire.manifest_sha256.as_str())
        && wire.profiles.iter().all(|profile| {
            let digest_reason = format!(
                "{}_behavior_bundle_sha256:{}",
                profile.action_key,
                profile.bundle_sha256.as_str().trim_start_matches("sha256:")
            );
            let count_reason = format!(
                "{}_behavior_event_count:{}",
                profile.action_key, profile.event_count
            );
            stage
                .reason_codes
                .iter()
                .any(|reason| reason == &digest_reason)
                && stage
                    .reason_codes
                    .iter()
                    .any(|reason| reason == &count_reason)
        })
}

fn validate_profile(
    profile: &PairedNpmProfileWireV1,
    artifact_sha256: &Sha256Digest,
    manifest_sha256: &Sha256Digest,
    run_ids: &mut BTreeSet<String>,
    receipt_identities: &mut BTreeSet<Sha256Digest>,
) -> Result<ValidatedPairedNpmProfileV1, PairedNpmReportReconciliationErrorV1> {
    let invalid =
        || PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_semantics_invalid");
    let bundle_bytes = serde_json::to_vec(&profile.behavior_bundle).map_err(|_| invalid())?;
    let bundle =
        decode_and_validate_behavior_analysis_bundle_v1(&bundle_bytes).map_err(|_| invalid())?;
    if profile.action_key != profile.profile.action_key()
        || profile.bundle_sha256 != bundle.bundle_sha256()
        || bundle.artifact_sha256() != artifact_sha256
        || bundle.manifest_sha256() != manifest_sha256
        || bundle.scenario_id() != profile.profile.scenario_id()
        || bundle.run_id() != profile.profile.run_id()
        || !run_ids.insert(bundle.run_id().to_string())
        || !receipt_identities.insert(bundle.root_receipt_sha256().clone())
        || !receipt_identities.insert(bundle.host_receipt_sha256().clone())
        || profile.event_count != bundle.events().len()
        || profile.evidence_coverage_complete
        || bundle.is_complete()
        || bundle
            .events()
            .iter()
            .any(|event| event.untrusted_detail().is_some())
        || bundle
            .events()
            .iter()
            .any(|event| event.source_receipt_sha256() != bundle.root_receipt_sha256())
    {
        return Err(invalid());
    }
    let coverage = bundle
        .coverage()
        .iter()
        .map(|item| {
            if item.state() != BehaviorCoverageStateV1::Incomplete
                || item.limitation_codes().is_empty()
            {
                return Err(invalid());
            }
            Ok(PairedNpmCoverageSummaryV1 {
                modality: item.modality(),
                limitation_codes: item.limitation_codes().to_vec(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut lifecycle_event_count = 0;
    let mut credential_read_event_count = 0;
    let mut connect_event_count = 0;
    let mut send_event_count = 0;
    for event in bundle.events() {
        match event.signal() {
            BehaviorEvidenceSignalV1::Process {
                action: ProcessActionV1::PackageTrigger,
                trigger: Some(PackageTriggerV1::NpmLifecycle),
            } => lifecycle_event_count += 1,
            BehaviorEvidenceSignalV1::Filesystem {
                operation: FileOperationV1::Read,
                target: FileTargetClassV1::CredentialFile,
            } => credential_read_event_count += 1,
            BehaviorEvidenceSignalV1::Network {
                action: NetworkActionV1::Connect,
                destination: NetworkDestinationClassV1::LocalSinkhole,
            } => connect_event_count += 1,
            BehaviorEvidenceSignalV1::Network {
                action: NetworkActionV1::Send,
                destination: NetworkDestinationClassV1::LocalSinkhole,
            } => send_event_count += 1,
            _ => {}
        }
    }
    if lifecycle_event_count == 0
        || credential_read_event_count == 0
        || connect_event_count == 0
        || send_event_count == 0
    {
        return Err(invalid());
    }
    let codex_findings = validate_codex_projection(
        &profile.codex,
        &bundle,
        &profile.bundle_sha256,
        &profile.observer_result_sha256,
        artifact_sha256,
    )?;
    Ok(ValidatedPairedNpmProfileV1 {
        profile: profile.profile,
        bundle_sha256: profile.bundle_sha256.clone(),
        observer_result_sha256: profile.observer_result_sha256.clone(),
        scenario_id: bundle.scenario_id().to_string(),
        run_id: bundle.run_id().to_string(),
        event_count: profile.event_count,
        lifecycle_event_count,
        credential_read_event_count,
        connect_event_count,
        send_event_count,
        coverage,
        codex_findings,
    })
}

fn validate_codex_projection(
    codex: &PairedNpmCodexProjectionWireV1,
    bundle: &BehaviorAnalysisBundleV1,
    bundle_sha256: &Sha256Digest,
    _observer_result_sha256: &Sha256Digest,
    artifact_sha256: &Sha256Digest,
) -> Result<Vec<PairedNpmCodexFindingSummaryV1>, PairedNpmReportReconciliationErrorV1> {
    let invalid =
        || PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_semantics_invalid");
    if codex.schema_version != BEHAVIOR_OBSERVE_SCHEMA_V1
        || codex.status != "behavior_detected"
        || codex.provider != "codex"
        || &codex.artifact_sha256 != artifact_sha256
        || &codex.bundle_sha256 != bundle_sha256
        || codex.panel_schema_version != BEHAVIOR_CODEX_PANEL_SCHEMA_V1
        || codex.panel_outcome != "positive"
        || codex.panel_reason_code != "behavior_codex_panel_positive"
        || codex.correlation_conclusion != "behavior_detected"
        || codex.missing_roles != [SpecialistRoleV1::EvasionAndPropagation]
        || codex.coverage_gap_codes.is_empty()
        || !strictly_sorted_unique(&codex.coverage_gap_codes)
        || !codex.positive_preservation_verified
        || codex.role_failure_count != 0
        || !codex.observe_only
        || codex.admission_authority
        || codex.observed_clean
        || codex.provider_receipts.len() != 4
        || codex.specialist_report_sha256s.len() != 4
        || codex.findings.len() != 4
    {
        return Err(invalid());
    }
    let expected_roles = [
        SpecialistRoleV1::CredentialAndCanary,
        SpecialistRoleV1::Filesystem,
        SpecialistRoleV1::Network,
        SpecialistRoleV1::ProcessAndTrigger,
    ];
    let mut receipt_sha256s = BTreeSet::new();
    let mut provider_output_sha256s = BTreeSet::new();
    for (expected_role, receipt) in expected_roles.iter().zip(&codex.provider_receipts) {
        if receipt.selected_role != *expected_role
            || !receipt_sha256s.insert(receipt.measured_receipt_json_sha256.clone())
            || !provider_output_sha256s.insert(receipt.provider_output_sha256.clone())
        {
            return Err(invalid());
        }
    }
    if !strictly_sorted_unique(&codex.specialist_report_sha256s) {
        return Err(invalid());
    }

    let expected_kinds = [
        BehaviorFindingKindV1::CredentialAccess,
        BehaviorFindingKindV1::LifecycleTriggerExecution,
        BehaviorFindingKindV1::NetworkSend,
        BehaviorFindingKindV1::OutboundConnection,
    ];
    let mut findings = Vec::with_capacity(codex.findings.len());
    for (expected_kind, finding) in expected_kinds.iter().zip(&codex.findings) {
        if finding.kind != *expected_kind
            || finding.threat_class != finding.kind.threat_class()
            || finding.confidence != BehaviorFindingConfidenceV1::High
            || finding.evidence.is_empty()
            || !strictly_sorted_unique(&finding.evidence)
            || !finding.evidence.iter().all(|reference| {
                bundle.event(reference.event_id()).is_some_and(|event| {
                    event.event_sha256() == *reference.event_sha256()
                        && event_supports_finding(event.signal(), finding.kind)
                })
            })
        {
            return Err(invalid());
        }
        let identity =
            serde_json::to_vec(&(finding.kind, &finding.evidence)).map_err(|_| invalid())?;
        if finding.finding_sha256 != Sha256Digest::from_bytes(&identity) {
            return Err(invalid());
        }
        findings.push(PairedNpmCodexFindingSummaryV1 {
            kind: finding.kind,
            confidence: finding.confidence,
            finding_sha256: finding.finding_sha256.clone(),
            evidence: finding.evidence.clone(),
        });
    }
    Ok(findings)
}

fn event_supports_finding(signal: &BehaviorEvidenceSignalV1, kind: BehaviorFindingKindV1) -> bool {
    matches!(
        (kind, signal),
        (
            BehaviorFindingKindV1::CredentialAccess,
            BehaviorEvidenceSignalV1::Filesystem {
                operation: FileOperationV1::Read,
                target: FileTargetClassV1::CredentialFile,
            }
        ) | (
            BehaviorFindingKindV1::LifecycleTriggerExecution,
            BehaviorEvidenceSignalV1::Process {
                action: ProcessActionV1::PackageTrigger,
                trigger: Some(PackageTriggerV1::NpmLifecycle),
            }
        ) | (
            BehaviorFindingKindV1::NetworkSend,
            BehaviorEvidenceSignalV1::Network {
                action: NetworkActionV1::Send,
                destination: NetworkDestinationClassV1::LocalSinkhole,
            }
        ) | (
            BehaviorFindingKindV1::OutboundConnection,
            BehaviorEvidenceSignalV1::Network {
                action: NetworkActionV1::Connect,
                destination: NetworkDestinationClassV1::LocalSinkhole,
            }
        )
    )
}

fn strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn read_reconciliation_file(path: &Path) -> Result<Vec<u8>, PairedNpmReportReconciliationErrorV1> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| {
            if error.raw_os_error() == Some(libc::ELOOP) {
                PairedNpmReportReconciliationErrorV1::new(
                    "paired_npm_reconciliation_path_not_regular_file",
                )
            } else {
                PairedNpmReportReconciliationErrorV1::new(
                    "paired_npm_reconciliation_path_unreadable",
                )
            }
        })?;
    let before = file.metadata().map_err(|_| {
        PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_path_unreadable")
    })?;
    if !before.file_type().is_file()
        || before.len() == 0
        || before.len() > u64::try_from(MAX_RECONCILIATION_BYTES).unwrap_or(u64::MAX)
    {
        return Err(PairedNpmReportReconciliationErrorV1::new(
            "paired_npm_reconciliation_size_out_of_bounds",
        ));
    }
    let expected_len = usize::try_from(before.len()).map_err(|_| {
        PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_size_out_of_bounds")
    })?;
    let mut bytes = vec![0_u8; expected_len];
    if let Err(error) = file.read_exact(&mut bytes) {
        return Err(PairedNpmReportReconciliationErrorV1::new(
            if error.kind() == ErrorKind::UnexpectedEof {
                "paired_npm_reconciliation_file_identity_changed"
            } else {
                "paired_npm_reconciliation_path_unreadable"
            },
        ));
    }
    let mut unexpected = [0_u8; 1];
    if file.read(&mut unexpected).map_err(|_| {
        PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_path_unreadable")
    })? != 0
    {
        return Err(PairedNpmReportReconciliationErrorV1::new(
            "paired_npm_reconciliation_file_identity_changed",
        ));
    }
    let after = file.metadata().map_err(|_| {
        PairedNpmReportReconciliationErrorV1::new("paired_npm_reconciliation_file_identity_changed")
    })?;
    if !same_open_file_identity(&before, &after) {
        return Err(PairedNpmReportReconciliationErrorV1::new(
            "paired_npm_reconciliation_file_identity_changed",
        ));
    }
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ExactArtifactDispositionV1, ExactArtifactIdentityV1, ExactArtifactScenarioPlanV1,
        ExactArtifactStageReportV1, ExactArtifactVerdictV1,
    };
    use whoathere_artifact::{AcquisitionMethod, ArtifactFormat, ArtifactSourceType, Ecosystem};
    use whoathere_detector::{
        BehaviorAnalysisBundleInputV1, BehaviorEvidenceCoverageV1, BehaviorEvidenceEventV1,
    };

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn bundle(profile: PairedNpmProfileV1) -> BehaviorAnalysisBundleV1 {
        let root = digest(&format!("{}-root", profile.label()));
        let events = vec![
            BehaviorEvidenceEventV1::new(
                1,
                format!("{}-lifecycle", profile.action_key()),
                root.clone(),
                BehaviorEvidenceSignalV1::Process {
                    action: ProcessActionV1::PackageTrigger,
                    trigger: Some(PackageTriggerV1::NpmLifecycle),
                },
                None,
            )
            .unwrap(),
            BehaviorEvidenceEventV1::new(
                2,
                format!("{}-credential", profile.action_key()),
                root.clone(),
                BehaviorEvidenceSignalV1::Filesystem {
                    operation: FileOperationV1::Read,
                    target: FileTargetClassV1::CredentialFile,
                },
                None,
            )
            .unwrap(),
            BehaviorEvidenceEventV1::new(
                3,
                format!("{}-connect", profile.action_key()),
                root.clone(),
                BehaviorEvidenceSignalV1::Network {
                    action: NetworkActionV1::Connect,
                    destination: NetworkDestinationClassV1::LocalSinkhole,
                },
                None,
            )
            .unwrap(),
            BehaviorEvidenceEventV1::new(
                4,
                format!("{}-send", profile.action_key()),
                root.clone(),
                BehaviorEvidenceSignalV1::Network {
                    action: NetworkActionV1::Send,
                    destination: NetworkDestinationClassV1::LocalSinkhole,
                },
                None,
            )
            .unwrap(),
        ];
        let coverage = BehaviorEvidenceModalityV1::ALL
            .iter()
            .map(|modality| {
                BehaviorEvidenceCoverageV1::incomplete(
                    *modality,
                    vec![format!("{}_coverage_incomplete", profile.action_key())],
                )
                .unwrap()
            })
            .collect();
        BehaviorAnalysisBundleV1::new(
            BehaviorAnalysisBundleInputV1 {
                artifact_sha256: digest("artifact"),
                manifest_sha256: digest("manifest"),
                scenario_id: profile.scenario_id().to_string(),
                scenario_sha256: digest("scenario"),
                run_id: profile.run_id().to_string(),
                root_receipt_sha256: root,
                host_receipt_sha256: digest(&format!("{}-host", profile.label())),
            },
            coverage,
            events,
        )
        .unwrap()
    }

    fn finding(
        bundle: &BehaviorAnalysisBundleV1,
        kind: BehaviorFindingKindV1,
        event_index: usize,
    ) -> PairedNpmCodexFindingWireV1 {
        let evidence = vec![BehaviorEvidenceReferenceV1::for_event(
            &bundle.events()[event_index],
        )];
        let identity = serde_json::to_vec(&(kind, &evidence)).unwrap();
        PairedNpmCodexFindingWireV1 {
            kind,
            threat_class: kind.threat_class(),
            confidence: BehaviorFindingConfidenceV1::High,
            evidence,
            finding_sha256: Sha256Digest::from_bytes(&identity),
        }
    }

    fn profile(profile: PairedNpmProfileV1) -> PairedNpmProfileWireV1 {
        let behavior_bundle = bundle(profile);
        let mut specialist_report_sha256s = (0..4)
            .map(|index| digest(&format!("{}-specialist-{index}", profile.label())))
            .collect::<Vec<_>>();
        specialist_report_sha256s.sort();
        let provider_receipts = [
            SpecialistRoleV1::CredentialAndCanary,
            SpecialistRoleV1::Filesystem,
            SpecialistRoleV1::Network,
            SpecialistRoleV1::ProcessAndTrigger,
        ]
        .iter()
        .enumerate()
        .map(|(index, role)| PairedNpmProviderReceiptIdentityWireV1 {
            selected_role: *role,
            measured_receipt_json_sha256: digest(&format!("{}-receipt-{index}", profile.label())),
            provider_output_sha256: digest(&format!("{}-output-{index}", profile.label())),
        })
        .collect();
        let findings = vec![
            finding(&behavior_bundle, BehaviorFindingKindV1::CredentialAccess, 1),
            finding(
                &behavior_bundle,
                BehaviorFindingKindV1::LifecycleTriggerExecution,
                0,
            ),
            finding(&behavior_bundle, BehaviorFindingKindV1::NetworkSend, 3),
            finding(
                &behavior_bundle,
                BehaviorFindingKindV1::OutboundConnection,
                2,
            ),
        ];
        PairedNpmProfileWireV1 {
            profile,
            action_key: profile.action_key().to_string(),
            bundle_sha256: behavior_bundle.bundle_sha256(),
            observer_result_sha256: digest(&format!("{}-observer", profile.label())),
            event_count: behavior_bundle.events().len(),
            evidence_coverage_complete: false,
            behavior_bundle,
            codex: PairedNpmCodexProjectionWireV1 {
                schema_version: BEHAVIOR_OBSERVE_SCHEMA_V1.to_string(),
                status: "behavior_detected".to_string(),
                provider: "codex".to_string(),
                artifact_sha256: digest("artifact"),
                bundle_sha256: Sha256Digest::from_bytes(b"placeholder"),
                panel_schema_version: BEHAVIOR_CODEX_PANEL_SCHEMA_V1.to_string(),
                panel_outcome: "positive".to_string(),
                panel_reason_code: "behavior_codex_panel_positive".to_string(),
                provider_receipts,
                specialist_report_sha256s,
                measured_correlation_json_sha256: digest(&format!(
                    "{}-correlation",
                    profile.label()
                )),
                correlation_conclusion: "behavior_detected".to_string(),
                missing_roles: vec![SpecialistRoleV1::EvasionAndPropagation],
                coverage_gap_codes: vec!["missing_specialist_evasion_and_propagation".to_string()],
                positive_preservation_verified: true,
                role_failure_count: 0,
                findings,
                observe_only: true,
                admission_authority: false,
                observed_clean: false,
            },
        }
        .tap_mut(|value| value.codex.bundle_sha256 = value.bundle_sha256.clone())
    }

    trait TapMut: Sized {
        fn tap_mut(mut self, update: impl FnOnce(&mut Self)) -> Self {
            update(&mut self);
            self
        }
    }

    impl<T> TapMut for T {}

    fn wire() -> PairedNpmReportReconciliationWireV1 {
        let profiles = PairedNpmProfileV1::ALL
            .iter()
            .copied()
            .map(profile)
            .collect::<Vec<_>>();
        let mut wire = PairedNpmReportReconciliationWireV1 {
            schema_version: PAIRED_NPM_REPORT_RECONCILIATION_SCHEMA_V1.to_string(),
            artifact_sha256: digest("artifact"),
            manifest_sha256: digest("manifest"),
            report_sha256: digest("report"),
            export_manifest_sha256: digest("export"),
            source_reconciliation_schema_version: SOURCE_RECONCILIATION_SCHEMA_V1.to_string(),
            source_reconciliation_sha256: digest("reconciliation"),
            source_reconciliation_input_binding_sha256: digest("placeholder"),
            scenario_plan_sha256: digest("plan"),
            scenario_intent_count: 2,
            detonation_provider: DETONATION_PROVIDER_V1.to_string(),
            detonation_status: "incomplete".to_string(),
            profiles,
            reconciliation_complete: true,
            diagnostic_only: true,
            claim_bearing: false,
            sanitized_projection: true,
            raw_source_or_telemetry_included: false,
            admission_authority: false,
            observed_clean: false,
            sync_back_enabled: false,
        };
        let binding = SourceReconciliationInputBindingV1 {
            artifact_sha256: &wire.artifact_sha256,
            bundles: wire
                .profiles
                .iter()
                .map(|value| [&value.bundle_sha256, &value.observer_result_sha256])
                .collect(),
            remote_report_sha256: &wire.report_sha256,
            scenario_plan_sha256: &wire.scenario_plan_sha256,
        };
        wire.source_reconciliation_input_binding_sha256 =
            Sha256Digest::from_bytes(&serde_json::to_vec(&binding).unwrap());
        wire
    }

    fn report(wire: &PairedNpmReportReconciliationWireV1) -> ExactArtifactInspectionReportV1 {
        let reason_codes = wire
            .profiles
            .iter()
            .flat_map(|profile| {
                [
                    format!(
                        "{}_behavior_bundle_sha256:{}",
                        profile.action_key,
                        profile.bundle_sha256.as_str().trim_start_matches("sha256:")
                    ),
                    format!(
                        "{}_behavior_event_count:{}",
                        profile.action_key, profile.event_count
                    ),
                ]
            })
            .collect();
        ExactArtifactInspectionReportV1 {
            schema_version: "whoathere.exact_artifact_inspection.v1".to_string(),
            status: ExactArtifactDispositionV1::Findings,
            verdict: ExactArtifactVerdictV1::Malicious,
            exit_code: 20,
            identity: ExactArtifactIdentityV1 {
                artifact_sha256: wire.artifact_sha256.to_string(),
                envelope_sha256: digest("artifact-envelope").to_string(),
                manifest_sha256: wire.manifest_sha256.to_string(),
                cas_object_key: "blobs/sha256/test".to_string(),
                byte_length: 1,
                ecosystem: Ecosystem::Npm,
                artifact_format: ArtifactFormat::NpmTarGzip,
                source_type: ArtifactSourceType::LocalFile,
                acquisition_method: AcquisitionMethod::LocalFileImport,
                source_coordinate: "local-file:test".to_string(),
                package_name: None,
                package_version: None,
            },
            stages: vec![ExactArtifactStageReportV1 {
                stage: "detonation".to_string(),
                status: ExactArtifactStageStatusV1::Incomplete,
                artifact_sha256: Some(wire.artifact_sha256.to_string()),
                manifest_sha256: Some(wire.manifest_sha256.to_string()),
                request_sha256: Some(digest("request").to_string()),
                result_sha256: Some(digest("result").to_string()),
                provider: Some(DETONATION_PROVIDER_V1.to_string()),
                observation_count: 0,
                reason_codes,
            }],
            scenario_plan: ExactArtifactScenarioPlanV1 {
                schema_version: "whoathere.exact_artifact_scenario_plan.v1".to_string(),
                artifact_sha256: wire.artifact_sha256.to_string(),
                manifest_sha256: wire.manifest_sha256.to_string(),
                status: ExactArtifactStageStatusV1::Incomplete,
                intents: vec![],
                plan_sha256: wire.scenario_plan_sha256.to_string(),
                runtime_binding_required: true,
                runtime_binding_status: "verified".to_string(),
                executable: true,
                reason_codes: vec!["fixture_incomplete".to_string()],
            },
            observations: vec![],
            behavior_detection_count: 0,
            admission_authority: false,
            observed_clean: false,
            sync_back_enabled: false,
            reason_codes: vec!["fixture_incomplete".to_string()],
        }
    }

    fn validate(
        wire: PairedNpmReportReconciliationWireV1,
    ) -> Result<ValidatedPairedNpmReportReconciliationV1, PairedNpmReportReconciliationErrorV1>
    {
        let report = report(&wire);
        let report_sha256 = wire.report_sha256.clone();
        validate_wire_against_report(
            wire,
            digest("envelope"),
            &report,
            RetainedExactArtifactReportPostureV1::SanitizedProjectionV1,
            report_sha256,
        )
    }

    #[test]
    fn paired_npm_reconciliation_validates_both_profiles_and_typed_citations() {
        let validated = validate(wire()).unwrap();
        assert_eq!(validated.profiles().len(), 2);
        for profile in validated.profiles() {
            assert_eq!(profile.lifecycle_event_count(), 1);
            assert_eq!(profile.credential_read_event_count(), 1);
            assert_eq!(profile.connect_event_count(), 1);
            assert_eq!(profile.send_event_count(), 1);
            assert_eq!(profile.codex_findings().len(), 4);
            assert_eq!(profile.coverage().len(), 5);
        }
        assert!(!validated.can_authorize_allow());
        assert!(!validated.observed_clean());
    }

    #[test]
    fn paired_npm_reconciliation_rejects_profile_citation_binding_and_authority_mutations() {
        let mut missing = wire();
        missing.profiles.pop();
        assert!(validate(missing).is_err());

        let mut swapped = wire();
        swapped.profiles.swap(0, 1);
        assert!(validate(swapped).is_err());

        let mut forged = wire();
        let cross_profile_reference =
            BehaviorEvidenceReferenceV1::for_event(&forged.profiles[1].behavior_bundle.events()[1]);
        let finding = &mut forged.profiles[0].codex.findings[0];
        finding.evidence[0] = cross_profile_reference;
        finding.finding_sha256 = Sha256Digest::from_bytes(
            &serde_json::to_vec(&(finding.kind, &finding.evidence)).unwrap(),
        );
        assert!(validate(forged).is_err());

        let mut promoted = wire();
        let finding = &mut promoted.profiles[0].codex.findings[2];
        finding.kind = BehaviorFindingKindV1::Exfiltration;
        finding.threat_class = finding.kind.threat_class();
        finding.finding_sha256 = Sha256Digest::from_bytes(
            &serde_json::to_vec(&(finding.kind, &finding.evidence)).unwrap(),
        );
        assert!(validate(promoted).is_err());

        let mut unsafe_wire = wire();
        unsafe_wire.admission_authority = true;
        assert!(validate(unsafe_wire).is_err());

        let mut rebound = wire();
        rebound.source_reconciliation_input_binding_sha256 = digest("forged-binding");
        assert!(validate(rebound).is_err());
    }

    #[test]
    fn paired_npm_reconciliation_schema_is_closed_and_coverage_cannot_be_upgraded() {
        let mut unknown = serde_json::to_value(wire()).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PairedNpmReportReconciliationWireV1>(unknown).is_err());

        let mut complete = serde_json::to_value(wire()).unwrap();
        complete["profiles"][0]["behavior_bundle"]["coverage"][0]["state"] =
            serde_json::json!("complete");
        complete["profiles"][0]["behavior_bundle"]["coverage"][0]["limitation_codes"] =
            serde_json::json!([]);
        let mutated: PairedNpmReportReconciliationWireV1 =
            serde_json::from_value(complete).unwrap();
        assert!(validate(mutated).is_err());
    }
}
