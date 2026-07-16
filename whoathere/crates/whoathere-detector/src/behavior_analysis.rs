//! Observe-only behavioral analysis over already verified execution evidence.
//!
//! This module does not collect telemetry, execute package code, authorize a
//! rerun, or make an admission decision. It projects signed evidence into a
//! bounded typed bundle, validates specialist output against exact event
//! references, and deterministically fuses reports without allowing a
//! correlator to erase a structurally valid positive finding.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const BEHAVIOR_ANALYSIS_BUNDLE_SCHEMA_V1: &str = "whoathere.behavior_analysis_bundle.v1";
pub const SPECIALIST_REPORT_SCHEMA_V1: &str = "whoathere.specialist_report.v1";
pub const CORRELATION_REPORT_SCHEMA_V1: &str = "whoathere.correlation_report.v1";

const MAX_EVENTS: usize = 50_000;
const MAX_BUNDLE_WIRE_BYTES: usize = 16 * 1024 * 1024;
const MAX_UNTRUSTED_DETAIL_BYTES: usize = 4_096;
const MAX_SPECIALIST_OUTPUT_BYTES: usize = 512 * 1024;
const MAX_FINDINGS_PER_REPORT: usize = 128;
const MAX_REFERENCES_PER_FINDING: usize = 32;
const MAX_COVERAGE_GAPS: usize = 64;
const MAX_REPORTS: usize = 20;
const MAX_PROBE_REQUESTS: usize = 2;
const MAX_IDENTIFIER_BYTES: usize = 160;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorEvidenceModalityV1 {
    Process,
    Filesystem,
    Canary,
    Network,
    Scenario,
}

impl BehaviorEvidenceModalityV1 {
    pub const ALL: [Self; 5] = [
        Self::Process,
        Self::Filesystem,
        Self::Canary,
        Self::Network,
        Self::Scenario,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorCoverageStateV1 {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorEvidenceCoverageV1 {
    modality: BehaviorEvidenceModalityV1,
    state: BehaviorCoverageStateV1,
    limitation_codes: Vec<String>,
}

impl BehaviorEvidenceCoverageV1 {
    pub fn complete(modality: BehaviorEvidenceModalityV1) -> Self {
        Self {
            modality,
            state: BehaviorCoverageStateV1::Complete,
            limitation_codes: Vec::new(),
        }
    }

    pub fn incomplete(
        modality: BehaviorEvidenceModalityV1,
        limitation_codes: Vec<String>,
    ) -> Result<Self, BehaviorAnalysisErrorV1> {
        let coverage = Self {
            modality,
            state: BehaviorCoverageStateV1::Incomplete,
            limitation_codes,
        };
        coverage.validate()?;
        Ok(coverage)
    }

    pub fn modality(&self) -> BehaviorEvidenceModalityV1 {
        self.modality
    }

    pub fn state(&self) -> BehaviorCoverageStateV1 {
        self.state
    }

    pub fn limitation_codes(&self) -> &[String] {
        &self.limitation_codes
    }

    fn validate(&self) -> Result<(), BehaviorAnalysisErrorV1> {
        validate_codes(&self.limitation_codes, MAX_COVERAGE_GAPS)?;
        match (self.state, self.limitation_codes.is_empty()) {
            (BehaviorCoverageStateV1::Complete, true)
            | (BehaviorCoverageStateV1::Incomplete, false) => Ok(()),
            _ => Err(BehaviorAnalysisErrorV1::InvalidCoverage),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageTriggerV1 {
    NpmLifecycle,
    NpmBin,
    NpmImport,
    WheelPth,
    WheelImport,
    WheelEntryPoint,
    SdistBuildBackend,
    SdistSetupPy,
    SdistImport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessActionV1 {
    PackageTrigger,
    OrdinaryChild,
    ShellSpawn,
    DynamicLoader,
    BackgroundProcess,
    ExecutablePayloadLaunch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperationV1 {
    Read,
    Write,
    Delete,
    Rename,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileTargetClassV1 {
    OrdinaryWorkspace,
    SensitiveFile,
    CredentialFile,
    PersistenceLocation,
    RepositoryMetadata,
    WorkflowDefinition,
    PackageMetadata,
    ExecutablePayload,
    PackageSelf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryClassV1 {
    NpmToken,
    PypiToken,
    GithubToken,
    CloudCredential,
    SshKey,
    SensitiveFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryActionV1 {
    Read,
    CopiedToProcess,
    SentToNetwork,
    UsedForPublish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkActionV1 {
    DnsLookup,
    Connect,
    Send,
    ReceiveExecutable,
    MetadataRequest,
    PackagePublish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkDestinationClassV1 {
    LocalSinkhole,
    ExternalInternet,
    CloudMetadata,
    PublicCodeHost,
    PackageRegistry,
    DeadDropService,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentGateV1 {
    Ci,
    Platform,
    Locale,
    Username,
    Hostname,
    SecretPresence,
    Time,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioActionV1 {
    OrdinaryControl,
    EnvironmentGateObserved,
    DelayedExecutionObserved,
    ObfuscatedPayloadDecoded,
    SelfPropagationAttempt,
    DependencyIndirectionObserved,
    ImportTimeTamperingObserved,
}

/// A typed projection of one event from verified evidence. Free-form detail is
/// explicitly untrusted and is never inspected by deterministic fusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BehaviorEvidenceSignalV1 {
    Process {
        action: ProcessActionV1,
        trigger: Option<PackageTriggerV1>,
    },
    Filesystem {
        operation: FileOperationV1,
        target: FileTargetClassV1,
    },
    Canary {
        action: CanaryActionV1,
        canary: CanaryClassV1,
    },
    Network {
        action: NetworkActionV1,
        destination: NetworkDestinationClassV1,
    },
    Scenario {
        action: ScenarioActionV1,
        gate: Option<EnvironmentGateV1>,
    },
}

impl BehaviorEvidenceSignalV1 {
    pub const fn modality(&self) -> BehaviorEvidenceModalityV1 {
        match self {
            Self::Process { .. } => BehaviorEvidenceModalityV1::Process,
            Self::Filesystem { .. } => BehaviorEvidenceModalityV1::Filesystem,
            Self::Canary { .. } => BehaviorEvidenceModalityV1::Canary,
            Self::Network { .. } => BehaviorEvidenceModalityV1::Network,
            Self::Scenario { .. } => BehaviorEvidenceModalityV1::Scenario,
        }
    }

    fn validate(&self) -> Result<(), BehaviorAnalysisErrorV1> {
        match self {
            Self::Process {
                action: ProcessActionV1::PackageTrigger,
                trigger: Some(_),
            }
            | Self::Process {
                action:
                    ProcessActionV1::OrdinaryChild
                    | ProcessActionV1::ShellSpawn
                    | ProcessActionV1::DynamicLoader
                    | ProcessActionV1::BackgroundProcess
                    | ProcessActionV1::ExecutablePayloadLaunch,
                trigger: None,
            }
            | Self::Scenario {
                action: ScenarioActionV1::EnvironmentGateObserved,
                gate: Some(_),
            }
            | Self::Scenario {
                action:
                    ScenarioActionV1::OrdinaryControl
                    | ScenarioActionV1::DelayedExecutionObserved
                    | ScenarioActionV1::ObfuscatedPayloadDecoded
                    | ScenarioActionV1::SelfPropagationAttempt
                    | ScenarioActionV1::DependencyIndirectionObserved
                    | ScenarioActionV1::ImportTimeTamperingObserved,
                gate: None,
            }
            | Self::Filesystem { .. }
            | Self::Canary { .. }
            | Self::Network { .. } => Ok(()),
            _ => Err(BehaviorAnalysisErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorEvidenceEventV1 {
    sequence: u64,
    event_id: String,
    source_receipt_sha256: Sha256Digest,
    signal: BehaviorEvidenceSignalV1,
    untrusted_detail: Option<String>,
}

impl BehaviorEvidenceEventV1 {
    pub fn new(
        sequence: u64,
        event_id: impl Into<String>,
        source_receipt_sha256: Sha256Digest,
        signal: BehaviorEvidenceSignalV1,
        untrusted_detail: Option<String>,
    ) -> Result<Self, BehaviorAnalysisErrorV1> {
        let event = Self {
            sequence,
            event_id: event_id.into(),
            source_receipt_sha256,
            signal,
            untrusted_detail,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn source_receipt_sha256(&self) -> &Sha256Digest {
        &self.source_receipt_sha256
    }

    pub fn signal(&self) -> &BehaviorEvidenceSignalV1 {
        &self.signal
    }

    pub fn untrusted_detail(&self) -> Option<&str> {
        self.untrusted_detail.as_deref()
    }

    pub fn event_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&serde_json::to_vec(self).expect("typed event serializes"))
    }

    fn validate(&self) -> Result<(), BehaviorAnalysisErrorV1> {
        validate_identifier(&self.event_id)?;
        self.signal.validate()?;
        if self.untrusted_detail.as_ref().is_some_and(|detail| {
            detail.len() > MAX_UNTRUSTED_DETAIL_BYTES || detail.contains('\0')
        }) {
            return Err(BehaviorAnalysisErrorV1::InvalidUntrustedText);
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct BehaviorAnalysisBundleInputV1 {
    pub artifact_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub scenario_id: String,
    pub scenario_sha256: Sha256Digest,
    pub run_id: String,
    pub root_receipt_sha256: Sha256Digest,
    pub host_receipt_sha256: Sha256Digest,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorAnalysisBundleV1 {
    schema_version: String,
    artifact_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    scenario_id: String,
    scenario_sha256: Sha256Digest,
    run_id: String,
    root_receipt_sha256: Sha256Digest,
    host_receipt_sha256: Sha256Digest,
    coverage: Vec<BehaviorEvidenceCoverageV1>,
    events: Vec<BehaviorEvidenceEventV1>,
}

pub type BehaviorAnalysisBundle = BehaviorAnalysisBundleV1;

impl fmt::Debug for BehaviorAnalysisBundleV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BehaviorAnalysisBundleV1")
            .field("artifact_sha256", &self.artifact_sha256)
            .field("scenario_id", &self.scenario_id)
            .field("run_id", &self.run_id)
            .field("coverage", &self.coverage)
            .field("event_count", &self.events.len())
            .field("event_detail", &"<redacted>")
            .finish()
    }
}

impl BehaviorAnalysisBundleV1 {
    pub fn new(
        input: BehaviorAnalysisBundleInputV1,
        mut coverage: Vec<BehaviorEvidenceCoverageV1>,
        mut events: Vec<BehaviorEvidenceEventV1>,
    ) -> Result<Self, BehaviorAnalysisErrorV1> {
        validate_identifier(&input.scenario_id)?;
        validate_identifier(&input.run_id)?;
        if events.len() > MAX_EVENTS {
            return Err(BehaviorAnalysisErrorV1::LimitExceeded);
        }
        coverage.sort_by_key(|item| item.modality);
        events.sort_by_key(|event| event.sequence);
        let bundle = Self {
            schema_version: BEHAVIOR_ANALYSIS_BUNDLE_SCHEMA_V1.to_string(),
            artifact_sha256: input.artifact_sha256,
            manifest_sha256: input.manifest_sha256,
            scenario_id: input.scenario_id,
            scenario_sha256: input.scenario_sha256,
            run_id: input.run_id,
            root_receipt_sha256: input.root_receipt_sha256,
            host_receipt_sha256: input.host_receipt_sha256,
            coverage,
            events,
        };
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn coverage(&self) -> &[BehaviorEvidenceCoverageV1] {
        &self.coverage
    }

    pub fn events(&self) -> &[BehaviorEvidenceEventV1] {
        &self.events
    }

    pub fn bundle_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&serde_json::to_vec(self).expect("typed bundle serializes"))
    }

    pub fn is_complete(&self) -> bool {
        self.coverage
            .iter()
            .all(|coverage| coverage.state == BehaviorCoverageStateV1::Complete)
    }

    pub fn event(&self, event_id: &str) -> Option<&BehaviorEvidenceEventV1> {
        self.events.iter().find(|event| event.event_id == event_id)
    }

    fn coverage_for(&self, modality: BehaviorEvidenceModalityV1) -> &BehaviorEvidenceCoverageV1 {
        self.coverage
            .iter()
            .find(|coverage| coverage.modality == modality)
            .expect("bundle validation requires every modality")
    }

    fn validate(&self) -> Result<(), BehaviorAnalysisErrorV1> {
        if self.schema_version != BEHAVIOR_ANALYSIS_BUNDLE_SCHEMA_V1
            || self.coverage.len() != BehaviorEvidenceModalityV1::ALL.len()
        {
            return Err(BehaviorAnalysisErrorV1::InvalidBundle);
        }
        let mut seen_modalities = BTreeSet::new();
        for coverage in &self.coverage {
            coverage.validate()?;
            if !seen_modalities.insert(coverage.modality) {
                return Err(BehaviorAnalysisErrorV1::DuplicateCoverage);
            }
        }
        if BehaviorEvidenceModalityV1::ALL
            .iter()
            .any(|modality| !seen_modalities.contains(modality))
        {
            return Err(BehaviorAnalysisErrorV1::InvalidCoverage);
        }

        let mut previous_sequence = None;
        let mut event_ids = BTreeSet::new();
        for event in &self.events {
            event.validate()?;
            if previous_sequence.is_some_and(|previous| event.sequence <= previous)
                || !event_ids.insert(event.event_id.as_str())
            {
                return Err(BehaviorAnalysisErrorV1::DuplicateEvent);
            }
            previous_sequence = Some(event.sequence);
        }
        Ok(())
    }
}

/// Loads a projected behavior bundle at the observe-only AI boundary.
///
/// The decoder revalidates every event, coverage row, receipt binding, and
/// ordering invariant before any hosted provider can receive the bundle.
pub fn decode_and_validate_behavior_analysis_bundle_v1(
    bytes: &[u8],
) -> Result<BehaviorAnalysisBundleV1, BehaviorAnalysisErrorV1> {
    if bytes.is_empty()
        || bytes.len() > MAX_BUNDLE_WIRE_BYTES
        || std::str::from_utf8(bytes).is_err()
    {
        return Err(BehaviorAnalysisErrorV1::InvalidBundle);
    }
    let bundle: BehaviorAnalysisBundleV1 =
        serde_json::from_slice(bytes).map_err(|_| BehaviorAnalysisErrorV1::InvalidBundle)?;
    bundle.validate()?;
    Ok(bundle)
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BehaviorEvidenceReferenceV1 {
    event_id: String,
    event_sha256: Sha256Digest,
}

impl BehaviorEvidenceReferenceV1 {
    pub fn for_event(event: &BehaviorEvidenceEventV1) -> Self {
        Self {
            event_id: event.event_id.clone(),
            event_sha256: event.event_sha256(),
        }
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn event_sha256(&self) -> &Sha256Digest {
        &self.event_sha256
    }

    fn validate_for_bundle(
        &self,
        bundle: &BehaviorAnalysisBundleV1,
    ) -> Result<(), BehaviorAnalysisErrorV1> {
        let event = bundle
            .event(&self.event_id)
            .ok_or(BehaviorAnalysisErrorV1::InvalidEvidenceReference)?;
        if event.event_sha256() != self.event_sha256 {
            return Err(BehaviorAnalysisErrorV1::InvalidEvidenceReference);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialistRoleV1 {
    ProcessAndTrigger,
    Filesystem,
    CredentialAndCanary,
    Network,
    EvasionAndPropagation,
}

impl SpecialistRoleV1 {
    pub const ALL: [Self; 5] = [
        Self::ProcessAndTrigger,
        Self::Filesystem,
        Self::CredentialAndCanary,
        Self::Network,
        Self::EvasionAndPropagation,
    ];

    fn required_modalities(self) -> &'static [BehaviorEvidenceModalityV1] {
        match self {
            Self::ProcessAndTrigger => &[
                BehaviorEvidenceModalityV1::Process,
                BehaviorEvidenceModalityV1::Scenario,
            ],
            Self::Filesystem => &[BehaviorEvidenceModalityV1::Filesystem],
            Self::CredentialAndCanary => &[
                BehaviorEvidenceModalityV1::Process,
                BehaviorEvidenceModalityV1::Filesystem,
                BehaviorEvidenceModalityV1::Canary,
            ],
            Self::Network => &[BehaviorEvidenceModalityV1::Network],
            Self::EvasionAndPropagation => &[
                BehaviorEvidenceModalityV1::Process,
                BehaviorEvidenceModalityV1::Filesystem,
                BehaviorEvidenceModalityV1::Network,
                BehaviorEvidenceModalityV1::Scenario,
            ],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorThreatClassV1 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorFindingKindV1 {
    LifecycleTriggerExecution,
    ShellExecution,
    DynamicLoading,
    Daemonization,
    SecondStageHandoff,
    SensitiveFileAccess,
    CredentialAccess,
    CanaryAccess,
    CanaryUse,
    CredentialExfiltration,
    DnsLookup,
    OutboundConnection,
    NetworkSend,
    MetadataAccess,
    Exfiltration,
    SecondStageDownload,
    PersistenceModification,
    DestructiveFileAction,
    SelfDeletion,
    RepositoryMutation,
    WorkflowMutation,
    PackageMutation,
    PackagePublishAttempt,
    SelfPropagation,
    ObfuscationOrPacking,
    EnvironmentGate,
    DelayedExecution,
    DependencyIndirection,
    ImportTimeTampering,
}

impl BehaviorFindingKindV1 {
    pub const fn threat_class(self) -> BehaviorThreatClassV1 {
        use BehaviorFindingKindV1 as Finding;
        match self {
            Finding::SensitiveFileAccess
            | Finding::CredentialAccess
            | Finding::CanaryAccess
            | Finding::CanaryUse => BehaviorThreatClassV1::CredentialAndSensitiveFileDiscovery,
            Finding::DnsLookup
            | Finding::OutboundConnection
            | Finding::NetworkSend
            | Finding::MetadataAccess
            | Finding::Exfiltration
            | Finding::CredentialExfiltration => BehaviorThreatClassV1::NetworkAndExfiltration,
            Finding::SecondStageHandoff | Finding::SecondStageDownload => {
                BehaviorThreatClassV1::SecondStageNativeOrWasmHandoff
            }
            Finding::LifecycleTriggerExecution
            | Finding::ShellExecution
            | Finding::DynamicLoading
            | Finding::Daemonization => BehaviorThreatClassV1::ProcessExecutionAndDynamicLoading,
            Finding::ObfuscationOrPacking => BehaviorThreatClassV1::ObfuscationAndPacking,
            Finding::EnvironmentGate | Finding::DelayedExecution => {
                BehaviorThreatClassV1::EnvironmentAndTimeGating
            }
            Finding::PersistenceModification
            | Finding::DestructiveFileAction
            | Finding::SelfDeletion => BehaviorThreatClassV1::PersistenceDestructionAndSelfDeletion,
            Finding::RepositoryMutation
            | Finding::WorkflowMutation
            | Finding::PackageMutation
            | Finding::PackagePublishAttempt
            | Finding::SelfPropagation => {
                BehaviorThreatClassV1::RepositoryPackageAndSelfPropagation
            }
            Finding::DependencyIndirection => BehaviorThreatClassV1::DependencyIndirection,
            Finding::ImportTimeTampering => BehaviorThreatClassV1::ImportTimeTampering,
        }
    }

    fn allowed_for(self, role: SpecialistRoleV1) -> bool {
        use BehaviorFindingKindV1 as Finding;
        match role {
            SpecialistRoleV1::ProcessAndTrigger => matches!(
                self,
                Finding::LifecycleTriggerExecution
                    | Finding::ShellExecution
                    | Finding::DynamicLoading
                    | Finding::Daemonization
                    | Finding::SecondStageHandoff
            ),
            SpecialistRoleV1::Filesystem => matches!(
                self,
                Finding::SensitiveFileAccess
                    | Finding::CredentialAccess
                    | Finding::PersistenceModification
                    | Finding::DestructiveFileAction
                    | Finding::SelfDeletion
                    | Finding::RepositoryMutation
                    | Finding::WorkflowMutation
                    | Finding::PackageMutation
            ),
            SpecialistRoleV1::CredentialAndCanary => matches!(
                self,
                Finding::CredentialAccess
                    | Finding::CanaryAccess
                    | Finding::CanaryUse
                    | Finding::CredentialExfiltration
            ),
            SpecialistRoleV1::Network => matches!(
                self,
                Finding::DnsLookup
                    | Finding::OutboundConnection
                    | Finding::NetworkSend
                    | Finding::MetadataAccess
                    | Finding::Exfiltration
                    | Finding::CredentialExfiltration
                    | Finding::SecondStageDownload
                    | Finding::PackagePublishAttempt
            ),
            SpecialistRoleV1::EvasionAndPropagation => matches!(
                self,
                Finding::ObfuscationOrPacking
                    | Finding::EnvironmentGate
                    | Finding::DelayedExecution
                    | Finding::SelfPropagation
                    | Finding::RepositoryMutation
                    | Finding::WorkflowMutation
                    | Finding::PackageMutation
                    | Finding::PackagePublishAttempt
                    | Finding::DependencyIndirection
                    | Finding::ImportTimeTampering
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorFindingConfidenceV1 {
    Moderate,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecialistConclusionV1 {
    Positive,
    NoFinding,
    Uncertain,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SpecialistReportWireV1 {
    schema_version: String,
    bundle_sha256: Sha256Digest,
    producer_id: String,
    producer_receipt_sha256: Sha256Digest,
    role: SpecialistRoleV1,
    conclusion: SpecialistConclusionV1,
    coverage_gap_codes: Vec<String>,
    findings: Vec<BehaviorFindingWireV1>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct BehaviorFindingWireV1 {
    kind: BehaviorFindingKindV1,
    confidence: BehaviorFindingConfidenceV1,
    evidence: Vec<BehaviorEvidenceReferenceV1>,
    explanation: String,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct StructurallyValidatedBehaviorFindingV1 {
    kind: BehaviorFindingKindV1,
    threat_class: BehaviorThreatClassV1,
    confidence: BehaviorFindingConfidenceV1,
    evidence: Vec<BehaviorEvidenceReferenceV1>,
    finding_sha256: Sha256Digest,
    explanation: String,
}

impl fmt::Debug for StructurallyValidatedBehaviorFindingV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StructurallyValidatedBehaviorFindingV1")
            .field("kind", &self.kind)
            .field("threat_class", &self.threat_class)
            .field("confidence", &self.confidence)
            .field("evidence", &self.evidence)
            .field("finding_sha256", &self.finding_sha256)
            .field("explanation", &"<redacted>")
            .finish()
    }
}

impl StructurallyValidatedBehaviorFindingV1 {
    pub fn kind(&self) -> BehaviorFindingKindV1 {
        self.kind
    }

    pub fn threat_class(&self) -> BehaviorThreatClassV1 {
        self.threat_class
    }

    pub fn confidence(&self) -> BehaviorFindingConfidenceV1 {
        self.confidence
    }

    pub fn evidence(&self) -> &[BehaviorEvidenceReferenceV1] {
        &self.evidence
    }

    pub fn finding_sha256(&self) -> &Sha256Digest {
        &self.finding_sha256
    }

    /// Bounded model text; never an authority-bearing reason code.
    pub fn explanation(&self) -> &str {
        &self.explanation
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct SpecialistReportV1 {
    schema_version: String,
    bundle_sha256: Sha256Digest,
    producer_id: String,
    producer_receipt_sha256: Sha256Digest,
    role: SpecialistRoleV1,
    conclusion: SpecialistConclusionV1,
    coverage_gap_codes: Vec<String>,
    findings: Vec<StructurallyValidatedBehaviorFindingV1>,
}

pub type SpecialistReport = SpecialistReportV1;

impl fmt::Debug for SpecialistReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpecialistReportV1")
            .field("producer_id", &self.producer_id)
            .field("role", &self.role)
            .field("conclusion", &self.conclusion)
            .field("coverage_gap_codes", &self.coverage_gap_codes)
            .field("finding_count", &self.findings.len())
            .field("model_text", &"<redacted>")
            .finish()
    }
}

impl SpecialistReportV1 {
    pub fn producer_id(&self) -> &str {
        &self.producer_id
    }

    pub fn role(&self) -> SpecialistRoleV1 {
        self.role
    }

    pub fn conclusion(&self) -> SpecialistConclusionV1 {
        self.conclusion
    }

    pub fn coverage_gap_codes(&self) -> &[String] {
        &self.coverage_gap_codes
    }

    pub fn findings(&self) -> &[StructurallyValidatedBehaviorFindingV1] {
        &self.findings
    }

    pub const fn is_observe_only(&self) -> bool {
        true
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }

    pub fn report_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&serde_json::to_vec(self).expect("typed report serializes"))
    }
}

pub fn decode_and_validate_specialist_report_v1(
    bytes: &[u8],
    bundle: &BehaviorAnalysisBundleV1,
) -> Result<SpecialistReportV1, BehaviorAnalysisErrorV1> {
    if bytes.is_empty()
        || bytes.len() > MAX_SPECIALIST_OUTPUT_BYTES
        || std::str::from_utf8(bytes).is_err()
    {
        return Err(BehaviorAnalysisErrorV1::InvalidSpecialistWire);
    }
    let wire: SpecialistReportWireV1 = serde_json::from_slice(bytes)
        .map_err(|_| BehaviorAnalysisErrorV1::InvalidSpecialistWire)?;
    if wire.schema_version != SPECIALIST_REPORT_SCHEMA_V1
        || wire.bundle_sha256 != bundle.bundle_sha256()
    {
        return Err(BehaviorAnalysisErrorV1::BindingMismatch);
    }
    validate_identifier(&wire.producer_id)?;
    validate_codes(&wire.coverage_gap_codes, MAX_COVERAGE_GAPS)?;
    if wire.findings.len() > MAX_FINDINGS_PER_REPORT {
        return Err(BehaviorAnalysisErrorV1::LimitExceeded);
    }

    let mut findings = Vec::with_capacity(wire.findings.len());
    let mut finding_ids = BTreeSet::new();
    for finding in wire.findings {
        if !finding.kind.allowed_for(wire.role)
            || finding.evidence.is_empty()
            || finding.evidence.len() > MAX_REFERENCES_PER_FINDING
            || finding.explanation.is_empty()
            || finding.explanation.len() > MAX_UNTRUSTED_DETAIL_BYTES
            || finding.explanation.contains('\0')
        {
            return Err(BehaviorAnalysisErrorV1::InvalidFinding);
        }
        let mut evidence = finding.evidence;
        evidence.sort();
        let mut references = BTreeSet::new();
        for reference in &evidence {
            reference.validate_for_bundle(bundle)?;
            if !references.insert(reference.clone()) {
                return Err(BehaviorAnalysisErrorV1::DuplicateEvidenceReference);
            }
        }
        if !finding_has_typed_support(bundle, finding.kind, &evidence) {
            return Err(BehaviorAnalysisErrorV1::InvalidFindingEvidence);
        }
        let identity_bytes = serde_json::to_vec(&(finding.kind, &evidence))
            .map_err(|_| BehaviorAnalysisErrorV1::InvalidFinding)?;
        let finding_sha256 = Sha256Digest::from_bytes(&identity_bytes);
        if !finding_ids.insert(finding_sha256.clone()) {
            return Err(BehaviorAnalysisErrorV1::DuplicateFinding);
        }
        findings.push(StructurallyValidatedBehaviorFindingV1 {
            kind: finding.kind,
            threat_class: finding.kind.threat_class(),
            confidence: finding.confidence,
            evidence,
            finding_sha256,
            explanation: finding.explanation,
        });
    }

    let relevant_coverage_complete =
        wire.role.required_modalities().iter().all(|modality| {
            bundle.coverage_for(*modality).state == BehaviorCoverageStateV1::Complete
        });
    let derived_conclusion = if !findings.is_empty() {
        SpecialistConclusionV1::Positive
    } else if relevant_coverage_complete && wire.coverage_gap_codes.is_empty() {
        SpecialistConclusionV1::NoFinding
    } else {
        SpecialistConclusionV1::Uncertain
    };
    if wire.conclusion != derived_conclusion {
        return Err(BehaviorAnalysisErrorV1::InvalidConclusion);
    }

    Ok(SpecialistReportV1 {
        schema_version: SPECIALIST_REPORT_SCHEMA_V1.to_string(),
        bundle_sha256: wire.bundle_sha256,
        producer_id: wire.producer_id,
        producer_receipt_sha256: wire.producer_receipt_sha256,
        role: wire.role,
        conclusion: derived_conclusion,
        coverage_gap_codes: wire.coverage_gap_codes,
        findings,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FixedEnvironmentProfileV1 {
    DeveloperLinuxEnUs,
    DeveloperLinuxNonEnglish,
    CiLinuxEnUs,
    CiLinuxNonEnglish,
    FixedMorningUtc,
    FixedEveningUtc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationExtensionV1 {
    ThirtySeconds,
    SixtySeconds,
    OneHundredTwentySeconds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSinkholeServiceV1 {
    Dns,
    Http,
    Https,
    CloudMetadata,
    PackageRegistry,
}

/// Closed, declarative rerun catalogue. There is intentionally no free-form
/// command, URL, credential, host path, or execution method in this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeActionV1 {
    SetCi { enabled: bool },
    SetCanaryToken { present: bool },
    SetEnvironmentProfile { profile: FixedEnvironmentProfileV1 },
    InvokeKnownTrigger { trigger: PackageTriggerV1 },
    ExtendObservationWindow { extension: ObservationExtensionV1 },
    EnableLocalSinkhole { service: LocalSinkholeServiceV1 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProbeRequestV1 {
    bundle_sha256: Sha256Digest,
    original_run_id: String,
    rationale_code: String,
    supporting_evidence: Vec<BehaviorEvidenceReferenceV1>,
    action: ProbeActionV1,
    fresh_vm_required: bool,
    request_sha256: Sha256Digest,
}

impl ProbeRequestV1 {
    pub fn new(
        bundle: &BehaviorAnalysisBundleV1,
        rationale_code: impl Into<String>,
        mut supporting_evidence: Vec<BehaviorEvidenceReferenceV1>,
        action: ProbeActionV1,
    ) -> Result<Self, BehaviorAnalysisErrorV1> {
        let rationale_code = rationale_code.into();
        validate_code(&rationale_code)?;
        if supporting_evidence.is_empty() || supporting_evidence.len() > MAX_REFERENCES_PER_FINDING
        {
            return Err(BehaviorAnalysisErrorV1::InvalidProbeRequest);
        }
        supporting_evidence.sort();
        let mut seen = BTreeSet::new();
        for reference in &supporting_evidence {
            reference.validate_for_bundle(bundle)?;
            if !seen.insert(reference.clone()) {
                return Err(BehaviorAnalysisErrorV1::DuplicateEvidenceReference);
            }
        }
        let bundle_sha256 = bundle.bundle_sha256();
        let identity = serde_json::to_vec(&(
            &bundle_sha256,
            bundle.run_id(),
            &rationale_code,
            &supporting_evidence,
            &action,
            true,
        ))
        .map_err(|_| BehaviorAnalysisErrorV1::InvalidProbeRequest)?;
        Ok(Self {
            bundle_sha256,
            original_run_id: bundle.run_id().to_string(),
            rationale_code,
            supporting_evidence,
            action,
            fresh_vm_required: true,
            request_sha256: Sha256Digest::from_bytes(&identity),
        })
    }

    pub fn action(&self) -> &ProbeActionV1 {
        &self.action
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub const fn fresh_vm_required(&self) -> bool {
        self.fresh_vm_required
    }

    pub const fn is_execution_authority(&self) -> bool {
        false
    }

    fn validate_for_bundle(
        &self,
        bundle: &BehaviorAnalysisBundleV1,
    ) -> Result<(), BehaviorAnalysisErrorV1> {
        if self.bundle_sha256 != bundle.bundle_sha256()
            || self.original_run_id != bundle.run_id()
            || !self.fresh_vm_required
        {
            return Err(BehaviorAnalysisErrorV1::BindingMismatch);
        }
        for reference in &self.supporting_evidence {
            reference.validate_for_bundle(bundle)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationConclusionV1 {
    BehaviorDetected,
    NoFinding,
    Uncertain,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct CorrelationReportV1 {
    schema_version: String,
    bundle_sha256: Sha256Digest,
    conclusion: CorrelationConclusionV1,
    findings: Vec<StructurallyValidatedBehaviorFindingV1>,
    specialist_report_sha256s: Vec<Sha256Digest>,
    missing_roles: Vec<SpecialistRoleV1>,
    disagreement_roles: Vec<SpecialistRoleV1>,
    coverage_gap_codes: Vec<String>,
    probe_requests: Vec<ProbeRequestV1>,
    positive_preservation_verified: bool,
}

pub type CorrelationReport = CorrelationReportV1;

impl fmt::Debug for CorrelationReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CorrelationReportV1")
            .field("conclusion", &self.conclusion)
            .field("finding_count", &self.findings.len())
            .field("missing_roles", &self.missing_roles)
            .field("disagreement_roles", &self.disagreement_roles)
            .field("coverage_gap_codes", &self.coverage_gap_codes)
            .field("probe_request_count", &self.probe_requests.len())
            .finish()
    }
}

impl CorrelationReportV1 {
    pub fn conclusion(&self) -> CorrelationConclusionV1 {
        self.conclusion
    }

    pub fn findings(&self) -> &[StructurallyValidatedBehaviorFindingV1] {
        &self.findings
    }

    pub fn missing_roles(&self) -> &[SpecialistRoleV1] {
        &self.missing_roles
    }

    pub fn disagreement_roles(&self) -> &[SpecialistRoleV1] {
        &self.disagreement_roles
    }

    pub fn coverage_gap_codes(&self) -> &[String] {
        &self.coverage_gap_codes
    }

    pub fn probe_requests(&self) -> &[ProbeRequestV1] {
        &self.probe_requests
    }

    pub const fn positive_preservation_verified(&self) -> bool {
        self.positive_preservation_verified
    }

    pub const fn is_observe_only(&self) -> bool {
        true
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

/// Deterministically fuses structurally validated specialist reports. The
/// union of all positive findings is authoritative for this correlation step;
/// a model is never asked which positives to retain.
pub fn fuse_specialist_reports_v1(
    bundle: &BehaviorAnalysisBundleV1,
    reports: &[SpecialistReportV1],
    probe_requests: Vec<ProbeRequestV1>,
) -> Result<CorrelationReportV1, BehaviorAnalysisErrorV1> {
    if reports.len() > MAX_REPORTS || probe_requests.len() > MAX_PROBE_REQUESTS {
        return Err(BehaviorAnalysisErrorV1::LimitExceeded);
    }
    let bundle_sha256 = bundle.bundle_sha256();
    let mut report_identities = BTreeSet::new();
    let mut conclusions_by_role: BTreeMap<SpecialistRoleV1, BTreeSet<u8>> = BTreeMap::new();
    let mut findings_by_id = BTreeMap::new();
    let mut report_sha256s = Vec::with_capacity(reports.len());
    let mut gap_codes = BTreeSet::new();

    for report in reports {
        if report.bundle_sha256 != bundle_sha256
            || !report_identities.insert((report.role, report.producer_id.as_str()))
        {
            return Err(BehaviorAnalysisErrorV1::BindingMismatch);
        }
        let conclusion_code = match report.conclusion {
            SpecialistConclusionV1::Positive => 1,
            SpecialistConclusionV1::NoFinding => 2,
            SpecialistConclusionV1::Uncertain => 3,
        };
        conclusions_by_role
            .entry(report.role)
            .or_default()
            .insert(conclusion_code);
        for code in &report.coverage_gap_codes {
            gap_codes.insert(code.clone());
        }
        for finding in &report.findings {
            findings_by_id
                .entry(finding.finding_sha256.clone())
                .and_modify(|existing: &mut StructurallyValidatedBehaviorFindingV1| {
                    if finding.confidence > existing.confidence
                        || (finding.confidence == existing.confidence
                            && finding.explanation < existing.explanation)
                    {
                        *existing = finding.clone();
                    }
                })
                .or_insert_with(|| finding.clone());
        }
        report_sha256s.push(report.report_sha256());
    }

    let missing_roles = SpecialistRoleV1::ALL
        .iter()
        .copied()
        .filter(|role| !conclusions_by_role.contains_key(role))
        .collect::<Vec<_>>();
    let disagreement_roles = conclusions_by_role
        .iter()
        .filter_map(|(role, conclusions)| (conclusions.len() > 1).then_some(*role))
        .collect::<Vec<_>>();

    for coverage in &bundle.coverage {
        if coverage.state == BehaviorCoverageStateV1::Incomplete {
            for code in &coverage.limitation_codes {
                gap_codes.insert(code.clone());
            }
        }
    }
    for role in &missing_roles {
        gap_codes.insert(format!(
            "missing_specialist_{}",
            specialist_role_code(*role)
        ));
    }
    for role in &disagreement_roles {
        gap_codes.insert(format!(
            "specialist_disagreement_{}",
            specialist_role_code(*role)
        ));
    }

    let mut seen_probes = BTreeSet::new();
    for request in &probe_requests {
        request.validate_for_bundle(bundle)?;
        if !seen_probes.insert(request.request_sha256.clone()) {
            return Err(BehaviorAnalysisErrorV1::DuplicateProbeRequest);
        }
    }

    let findings = findings_by_id.into_values().collect::<Vec<_>>();
    let any_uncertain = reports
        .iter()
        .any(|report| report.conclusion == SpecialistConclusionV1::Uncertain);
    let conclusion = if !findings.is_empty() {
        CorrelationConclusionV1::BehaviorDetected
    } else if !missing_roles.is_empty()
        || !disagreement_roles.is_empty()
        || any_uncertain
        || !bundle.is_complete()
        || !gap_codes.is_empty()
        || !probe_requests.is_empty()
    {
        CorrelationConclusionV1::Uncertain
    } else {
        CorrelationConclusionV1::NoFinding
    };

    report_sha256s.sort();
    Ok(CorrelationReportV1 {
        schema_version: CORRELATION_REPORT_SCHEMA_V1.to_string(),
        bundle_sha256,
        conclusion,
        findings,
        specialist_report_sha256s: report_sha256s,
        missing_roles,
        disagreement_roles,
        coverage_gap_codes: gap_codes.into_iter().collect(),
        probe_requests,
        positive_preservation_verified: true,
    })
}

fn specialist_role_code(role: SpecialistRoleV1) -> &'static str {
    match role {
        SpecialistRoleV1::ProcessAndTrigger => "process_and_trigger",
        SpecialistRoleV1::Filesystem => "filesystem",
        SpecialistRoleV1::CredentialAndCanary => "credential_and_canary",
        SpecialistRoleV1::Network => "network",
        SpecialistRoleV1::EvasionAndPropagation => "evasion_and_propagation",
    }
}

fn finding_has_typed_support(
    bundle: &BehaviorAnalysisBundleV1,
    kind: BehaviorFindingKindV1,
    evidence: &[BehaviorEvidenceReferenceV1],
) -> bool {
    let signals = evidence
        .iter()
        .filter_map(|reference| bundle.event(reference.event_id()))
        .map(BehaviorEvidenceEventV1::signal)
        .collect::<Vec<_>>();
    let any =
        |predicate: fn(&BehaviorEvidenceSignalV1) -> bool| signals.iter().copied().any(predicate);
    use BehaviorEvidenceSignalV1 as Signal;
    use BehaviorFindingKindV1 as Finding;
    match kind {
        Finding::LifecycleTriggerExecution => any(|signal| {
            matches!(
                signal,
                Signal::Process {
                    action: ProcessActionV1::PackageTrigger,
                    trigger: Some(_)
                }
            )
        }),
        Finding::ShellExecution => any(|signal| {
            matches!(
                signal,
                Signal::Process {
                    action: ProcessActionV1::ShellSpawn,
                    ..
                }
            )
        }),
        Finding::DynamicLoading => any(|signal| {
            matches!(
                signal,
                Signal::Process {
                    action: ProcessActionV1::DynamicLoader,
                    ..
                }
            )
        }),
        Finding::Daemonization => any(|signal| {
            matches!(
                signal,
                Signal::Process {
                    action: ProcessActionV1::BackgroundProcess,
                    ..
                }
            )
        }),
        Finding::SecondStageHandoff => any(|signal| {
            matches!(
                signal,
                Signal::Process {
                    action: ProcessActionV1::ExecutablePayloadLaunch,
                    ..
                }
            )
        }),
        Finding::SensitiveFileAccess => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Read,
                    target: FileTargetClassV1::SensitiveFile
                }
            )
        }),
        Finding::CredentialAccess => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Read,
                    target: FileTargetClassV1::CredentialFile
                } | Signal::Canary {
                    action: CanaryActionV1::Read,
                    ..
                }
            )
        }),
        Finding::CanaryAccess => any(|signal| {
            matches!(
                signal,
                Signal::Canary {
                    action: CanaryActionV1::Read,
                    ..
                }
            )
        }),
        Finding::CanaryUse => any(|signal| {
            matches!(
                signal,
                Signal::Canary {
                    action: CanaryActionV1::CopiedToProcess | CanaryActionV1::UsedForPublish,
                    ..
                }
            )
        }),
        Finding::CredentialExfiltration => {
            let canary_sent = any(|signal| {
                matches!(
                    signal,
                    Signal::Canary {
                        action: CanaryActionV1::SentToNetwork,
                        ..
                    }
                )
            });
            let network_send = any(|signal| {
                matches!(
                    signal,
                    Signal::Network {
                        action: NetworkActionV1::Send,
                        ..
                    }
                )
            });
            canary_sent && network_send
        }
        Finding::DnsLookup => any(|signal| {
            matches!(
                signal,
                Signal::Network {
                    action: NetworkActionV1::DnsLookup,
                    ..
                }
            )
        }),
        Finding::OutboundConnection => any(|signal| {
            matches!(
                signal,
                Signal::Network {
                    action: NetworkActionV1::Connect,
                    ..
                }
            )
        }),
        Finding::NetworkSend => any(|signal| {
            matches!(
                signal,
                Signal::Network {
                    action: NetworkActionV1::Send,
                    ..
                }
            )
        }),
        Finding::MetadataAccess => any(|signal| {
            matches!(
                signal,
                Signal::Network {
                    action: NetworkActionV1::MetadataRequest,
                    destination: NetworkDestinationClassV1::CloudMetadata
                }
            )
        }),
        Finding::Exfiltration => {
            let canary_sent = any(|signal| {
                matches!(
                    signal,
                    Signal::Canary {
                        action: CanaryActionV1::SentToNetwork,
                        ..
                    }
                )
            });
            let network_send = any(|signal| {
                matches!(
                    signal,
                    Signal::Network {
                        action: NetworkActionV1::Send,
                        ..
                    }
                )
            });
            canary_sent && network_send
        }
        Finding::SecondStageDownload => any(|signal| {
            matches!(
                signal,
                Signal::Network {
                    action: NetworkActionV1::ReceiveExecutable,
                    ..
                }
            )
        }),
        Finding::PersistenceModification => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Write | FileOperationV1::Rename,
                    target: FileTargetClassV1::PersistenceLocation
                }
            )
        }),
        Finding::DestructiveFileAction => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Delete,
                    target: FileTargetClassV1::SensitiveFile
                        | FileTargetClassV1::CredentialFile
                        | FileTargetClassV1::RepositoryMetadata
                        | FileTargetClassV1::WorkflowDefinition
                        | FileTargetClassV1::PackageMetadata
                }
            )
        }),
        Finding::SelfDeletion => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Delete,
                    target: FileTargetClassV1::PackageSelf
                }
            )
        }),
        Finding::RepositoryMutation => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Write
                        | FileOperationV1::Delete
                        | FileOperationV1::Rename,
                    target: FileTargetClassV1::RepositoryMetadata
                }
            )
        }),
        Finding::WorkflowMutation => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Write
                        | FileOperationV1::Delete
                        | FileOperationV1::Rename,
                    target: FileTargetClassV1::WorkflowDefinition
                }
            )
        }),
        Finding::PackageMutation => any(|signal| {
            matches!(
                signal,
                Signal::Filesystem {
                    operation: FileOperationV1::Write
                        | FileOperationV1::Delete
                        | FileOperationV1::Rename,
                    target: FileTargetClassV1::PackageMetadata
                }
            )
        }),
        Finding::PackagePublishAttempt => any(|signal| {
            matches!(
                signal,
                Signal::Network {
                    action: NetworkActionV1::PackagePublish,
                    destination: NetworkDestinationClassV1::PackageRegistry
                } | Signal::Canary {
                    action: CanaryActionV1::UsedForPublish,
                    ..
                }
            )
        }),
        Finding::SelfPropagation => any(|signal| {
            matches!(
                signal,
                Signal::Scenario {
                    action: ScenarioActionV1::SelfPropagationAttempt,
                    ..
                }
            )
        }),
        Finding::ObfuscationOrPacking => any(|signal| {
            matches!(
                signal,
                Signal::Scenario {
                    action: ScenarioActionV1::ObfuscatedPayloadDecoded,
                    ..
                }
            )
        }),
        Finding::EnvironmentGate => any(|signal| {
            matches!(
                signal,
                Signal::Scenario {
                    action: ScenarioActionV1::EnvironmentGateObserved,
                    gate: Some(_)
                }
            )
        }),
        Finding::DelayedExecution => any(|signal| {
            matches!(
                signal,
                Signal::Scenario {
                    action: ScenarioActionV1::DelayedExecutionObserved,
                    ..
                }
            )
        }),
        Finding::DependencyIndirection => any(|signal| {
            matches!(
                signal,
                Signal::Scenario {
                    action: ScenarioActionV1::DependencyIndirectionObserved,
                    ..
                }
            )
        }),
        Finding::ImportTimeTampering => any(|signal| {
            matches!(
                signal,
                Signal::Scenario {
                    action: ScenarioActionV1::ImportTimeTamperingObserved,
                    ..
                }
            )
        }),
    }
}

fn validate_identifier(value: &str) -> Result<(), BehaviorAnalysisErrorV1> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
    {
        return Err(BehaviorAnalysisErrorV1::InvalidIdentifier);
    }
    Ok(())
}

fn validate_code(value: &str) -> Result<(), BehaviorAnalysisErrorV1> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(BehaviorAnalysisErrorV1::InvalidReasonCode);
    }
    Ok(())
}

fn validate_codes(values: &[String], limit: usize) -> Result<(), BehaviorAnalysisErrorV1> {
    if values.len() > limit {
        return Err(BehaviorAnalysisErrorV1::LimitExceeded);
    }
    let mut seen = BTreeSet::new();
    for value in values {
        validate_code(value)?;
        if !seen.insert(value.as_str()) {
            return Err(BehaviorAnalysisErrorV1::DuplicateReasonCode);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorAnalysisErrorV1 {
    InvalidBundle,
    InvalidCoverage,
    DuplicateCoverage,
    InvalidEvent,
    DuplicateEvent,
    InvalidIdentifier,
    InvalidReasonCode,
    DuplicateReasonCode,
    InvalidUntrustedText,
    InvalidSpecialistWire,
    BindingMismatch,
    InvalidFinding,
    InvalidFindingEvidence,
    InvalidEvidenceReference,
    DuplicateEvidenceReference,
    DuplicateFinding,
    InvalidConclusion,
    InvalidProbeRequest,
    DuplicateProbeRequest,
    LimitExceeded,
}

impl BehaviorAnalysisErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidBundle => "behavior_analysis_bundle_invalid",
            Self::InvalidCoverage => "behavior_analysis_coverage_invalid",
            Self::DuplicateCoverage => "behavior_analysis_coverage_duplicate",
            Self::InvalidEvent => "behavior_analysis_event_invalid",
            Self::DuplicateEvent => "behavior_analysis_event_duplicate",
            Self::InvalidIdentifier => "behavior_analysis_identifier_invalid",
            Self::InvalidReasonCode => "behavior_analysis_reason_code_invalid",
            Self::DuplicateReasonCode => "behavior_analysis_reason_code_duplicate",
            Self::InvalidUntrustedText => "behavior_analysis_untrusted_text_invalid",
            Self::InvalidSpecialistWire => "behavior_analysis_specialist_wire_invalid",
            Self::BindingMismatch => "behavior_analysis_binding_mismatch",
            Self::InvalidFinding => "behavior_analysis_finding_invalid",
            Self::InvalidFindingEvidence => "behavior_analysis_finding_evidence_invalid",
            Self::InvalidEvidenceReference => "behavior_analysis_evidence_reference_invalid",
            Self::DuplicateEvidenceReference => "behavior_analysis_evidence_reference_duplicate",
            Self::DuplicateFinding => "behavior_analysis_finding_duplicate",
            Self::InvalidConclusion => "behavior_analysis_conclusion_invalid",
            Self::InvalidProbeRequest => "behavior_analysis_probe_request_invalid",
            Self::DuplicateProbeRequest => "behavior_analysis_probe_request_duplicate",
            Self::LimitExceeded => "behavior_analysis_limit_exceeded",
        }
    }
}

impl fmt::Display for BehaviorAnalysisErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for BehaviorAnalysisErrorV1 {}
