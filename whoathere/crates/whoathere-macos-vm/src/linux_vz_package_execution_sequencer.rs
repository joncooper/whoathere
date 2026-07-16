use crate::LinuxVzPackageObservedProcessEvidenceV1;
#[cfg(target_os = "linux")]
use crate::LinuxVzPackageProcessTerminalV1;
#[cfg(target_os = "linux")]
use crate::{
    create_fresh_linux_vz_package_workspace_v1, derive_linux_vz_package_process_launch_contract_v1,
    materialize_linux_vz_package_artifact_v1, materialize_linux_vz_package_build_closure_v1,
    materialize_linux_vz_package_sdist_source_v1, measure_and_seal_linux_vz_package_process_v1,
    supervise_linux_vz_package_process_v1, validate_linux_vz_package_console_target_v1,
    validate_single_linux_vz_package_derived_wheel_v1,
    LinuxVzPackageArtifactMaterializationObservationV1,
    LinuxVzPackageClosureMaterializationObservationV1, LinuxVzPackageConsoleTargetObservationV1,
    LinuxVzPackageDerivedWheelObservationV1, LinuxVzPackageExecutionAttemptAuthorityV1,
    LinuxVzPackageMaterializationPolicyV1, LinuxVzPackageProtectedProcessObserverV1,
    LinuxVzPackageScenarioClockV1, LinuxVzPackageSdistMaterializationObservationV1,
    LinuxVzPackageWorkspaceObservationV1, MaterializedLinuxVzPackageArtifactV1,
    MaterializedLinuxVzPackageBuildClosureV1, MaterializedLinuxVzPackageSdistSourceV1,
    StructurallyValidatedMacosLinuxVzPackageExecutionRequestV1,
    ValidatedLinuxVzPackageDerivedWheelV1, ValidatedLinuxVzPackageDynamicProcessBindingsV1,
};
#[cfg(any(target_os = "linux", test))]
use crate::{
    MacosLinuxVzPackageExecutionActionV1, MacosLinuxVzPackageExecutionProcessPlanV1,
    MacosLinuxVzPackageInternalActionV1, MacosLinuxVzPackageProcessArgumentV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::File;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_execution_sequence_transcript.v1";
pub const LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_execution_sequence_transcript.v2";
pub const MAX_LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_BYTES_V1: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageExecutionSequencerErrorV1 {
    InvalidPlan,
    InvalidInputs,
    AuthorityInvalid,
    WorkspaceFailed,
    MaterializationFailed,
    InternalValidationFailed,
    LaunchContractFailed,
    ProcessMeasurementFailed,
    ProcessSupervisionFailed,
    CleanupFailed,
    Serialization,
    LimitExceeded,
}

impl LinuxVzPackageExecutionSequencerErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidPlan => "linux_vz_package_execution_sequence_plan_invalid",
            Self::InvalidInputs => "linux_vz_package_execution_sequence_inputs_invalid",
            Self::AuthorityInvalid => "linux_vz_package_execution_sequence_authority_invalid",
            Self::WorkspaceFailed => "linux_vz_package_execution_sequence_workspace_failed",
            Self::MaterializationFailed => {
                "linux_vz_package_execution_sequence_materialization_failed"
            }
            Self::InternalValidationFailed => {
                "linux_vz_package_execution_sequence_internal_validation_failed"
            }
            Self::LaunchContractFailed => {
                "linux_vz_package_execution_sequence_launch_contract_failed"
            }
            Self::ProcessMeasurementFailed => {
                "linux_vz_package_execution_sequence_process_measurement_failed"
            }
            Self::ProcessSupervisionFailed => {
                "linux_vz_package_execution_sequence_process_supervision_failed"
            }
            Self::CleanupFailed => "linux_vz_package_execution_sequence_cleanup_failed",
            Self::Serialization => "linux_vz_package_execution_sequence_serialization_failed",
            Self::LimitExceeded => "linux_vz_package_execution_sequence_limit_exceeded",
        }
    }
}

impl fmt::Display for LinuxVzPackageExecutionSequencerErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageExecutionSequencerErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzPackageExecutionSequenceTerminalV1 {
    Complete,
    ProcessFailed,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactMaterializationSummaryWireV1<'a> {
    artifact_sha256: &'a Sha256Digest,
    artifact_byte_length: String,
    input_basename: &'a str,
    input_directory_device: String,
    input_directory_inode: String,
    device: String,
    inode: String,
    staged: bool,
    final_postrun_rehash: bool,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SdistMaterializationSummaryWireV1<'a> {
    extraction_manifest_sha256: &'a Sha256Digest,
    artifact_format: whoathere_artifact::ArtifactFormat,
    canonical_archive_root: &'a str,
    member_count: String,
    expanded_byte_length: String,
    source_device: String,
    source_inode: String,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ClosureMaterializationSummaryWireV1<'a> {
    build_requires_sha256: &'a Sha256Digest,
    closure_sha256: &'a Sha256Digest,
    payload_sha256: &'a Sha256Digest,
    artifact_count: String,
    payload_byte_length: String,
    closure_device: String,
    closure_inode: String,
    staged: bool,
    final_postrun_rehash: bool,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ProcessSummaryWireV1<'a> {
    action_index: String,
    stage_name: &'a str,
    supervisor_evidence_sha256: &'a Sha256Digest,
    protected_sensor_evidence_kind: crate::LinuxVzPackageProtectedSensorEvidenceKindV1,
    protected_sensor_authentication_sha256: &'a Sha256Digest,
    protected_sensor_evidence_set_sha256: &'a Sha256Digest,
    sensor_session_challenge_sha256: &'a Sha256Digest,
    process_sensor_evidence_sha256: &'a Sha256Digest,
    file_sensor_evidence_sha256: &'a Sha256Digest,
    network_sensor_evidence_sha256: &'a Sha256Digest,
    protected_sensor_authenticated: bool,
    terminal: LinuxVzPackageProcessTerminalV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    termination_signal: Option<String>,
    deadline_reached: bool,
    descendant_teardown_complete: bool,
    coverage_complete: bool,
    host_composition_required: bool,
    authoritative_verdict_permitted: bool,
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionSequenceTranscriptWireV1<'a> {
    schema_version: &'static str,
    execution_request_sha256: &'a Sha256Digest,
    execution_grant_sha256: &'a Sha256Digest,
    attempt_binding_sha256: &'a Sha256Digest,
    process_plan_sha256: &'a Sha256Digest,
    artifact_sha256: &'a Sha256Digest,
    workspace_initial_observation_sha256: &'a Sha256Digest,
    workspace_final_observation_sha256: &'a Sha256Digest,
    artifact: ArtifactMaterializationSummaryWireV1<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sdist: Option<SdistMaterializationSummaryWireV1<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_closure: Option<ClosureMaterializationSummaryWireV1<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived_wheel_observation_sha256: Option<&'a Sha256Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    derived_wheel_manifest_sha256: Option<&'a Sha256Digest>,
    console_target_observation_sha256: Vec<&'a Sha256Digest>,
    processes: Vec<ProcessSummaryWireV1<'a>>,
    completed_action_count: String,
    total_action_count: String,
    terminal: LinuxVzPackageExecutionSequenceTerminalV1,
    trigger_sequence_complete: bool,
    execution_attempt_consumed: bool,
    workspace_cleanup_complete: bool,
    authenticated: bool,
    verdict_eligible: bool,
    public_network_route_present: bool,
    sync_back: bool,
}

pub struct LinuxVzPackageExecutionSequenceTranscriptV1 {
    canonical_json: Vec<u8>,
    transcript_sha256: Sha256Digest,
    execution_request_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    terminal: LinuxVzPackageExecutionSequenceTerminalV1,
    completed_action_count: usize,
    total_action_count: usize,
    processes: Vec<LinuxVzPackageObservedProcessEvidenceV1>,
}

impl fmt::Debug for LinuxVzPackageExecutionSequenceTranscriptV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageExecutionSequenceTranscriptV1")
            .field("transcript_sha256", &self.transcript_sha256)
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("terminal", &self.terminal)
            .field("completed_action_count", &self.completed_action_count)
            .field("total_action_count", &self.total_action_count)
            .field("process_count", &self.processes.len())
            .finish()
    }
}

impl LinuxVzPackageExecutionSequenceTranscriptV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn transcript_sha256(&self) -> &Sha256Digest {
        &self.transcript_sha256
    }

    pub fn execution_request_sha256(&self) -> &Sha256Digest {
        &self.execution_request_sha256
    }

    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn attempt_binding_sha256(&self) -> &Sha256Digest {
        &self.attempt_binding_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub const fn terminal(&self) -> LinuxVzPackageExecutionSequenceTerminalV1 {
        self.terminal
    }

    pub const fn completed_action_count(&self) -> usize {
        self.completed_action_count
    }

    pub const fn total_action_count(&self) -> usize {
        self.total_action_count
    }

    pub fn processes(&self) -> &[LinuxVzPackageObservedProcessEvidenceV1] {
        &self.processes
    }

    pub const fn trigger_sequence_complete(&self) -> bool {
        matches!(
            self.terminal,
            LinuxVzPackageExecutionSequenceTerminalV1::Complete
        )
    }

    pub const fn authenticated(&self) -> bool {
        false
    }

    pub const fn verdict_eligible(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SequenceRequirementsV1 {
    build_closure_required: bool,
    derived_wheel_required: bool,
    process_count: usize,
}

#[cfg(any(target_os = "linux", test))]
fn sequence_requirements_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
) -> Result<SequenceRequirementsV1, LinuxVzPackageExecutionSequencerErrorV1> {
    if process_plan.actions().len() < 2
        || process_plan.package_execution_authority_permitted()
        || process_plan.sync_back_permitted()
        || !matches!(
            process_plan.actions().first(),
            Some(MacosLinuxVzPackageExecutionActionV1::Internal {
                action: MacosLinuxVzPackageInternalActionV1::MaterializeExactArtifact { .. }
            })
        )
    {
        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
    }
    let mut materialize_count = 0_usize;
    let mut source_count = 0_usize;
    let mut closure_count = 0_usize;
    let mut closure_payload_count = 0_usize;
    let mut derived_count = 0_usize;
    let mut inspect_count = 0_usize;
    let mut process_count = 0_usize;
    let mut sdist_build_process_count = 0_usize;
    let mut source_ready = false;
    let mut closure_ready = false;
    let mut sdist_build_completed = false;
    let mut derived_ready = false;
    for action in process_plan.actions() {
        match action {
            MacosLinuxVzPackageExecutionActionV1::Internal { action } => match action {
                MacosLinuxVzPackageInternalActionV1::MaterializeExactArtifact { .. } => {
                    materialize_count += 1;
                }
                MacosLinuxVzPackageInternalActionV1::SafelyExtractExactSdist { .. } => {
                    source_count += 1;
                    source_ready = true;
                }
                MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                    build_requires_sha256,
                    build_closure,
                } => {
                    if !source_ready
                        || build_closure.validate().is_err()
                        || build_requires_sha256 != build_closure.declaration_set_sha256()
                    {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    closure_count += 1;
                    if !build_closure.artifacts().is_empty() {
                        closure_payload_count += 1;
                    }
                    closure_ready = true;
                }
                MacosLinuxVzPackageInternalActionV1::ValidateSingleDerivedWheel => {
                    if !source_ready || !closure_ready || !sdist_build_completed {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    derived_count += 1;
                    derived_ready = true;
                }
                MacosLinuxVzPackageInternalActionV1::InspectDerivedWheelMetadata => {
                    if !derived_ready {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    inspect_count += 1;
                }
                MacosLinuxVzPackageInternalActionV1::ValidateConsoleEntryPointTarget { .. } => {}
            },
            MacosLinuxVzPackageExecutionActionV1::Process { process } => {
                if process.stage_name() == "python_build_exact_sdist" {
                    if !source_ready || !closure_ready || sdist_build_completed {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    sdist_build_process_count += 1;
                    sdist_build_completed = true;
                }
                if process.arguments().iter().any(|argument| {
                    matches!(
                        argument,
                        MacosLinuxVzPackageProcessArgumentV1::ValidatedDerivedWheelPath
                    )
                }) && !derived_ready
                {
                    return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                }
                process_count += 1;
            }
        }
    }
    if materialize_count != 1
        || source_count > 1
        || closure_count > 1
        || closure_payload_count > 1
        || derived_count > 1
        || inspect_count > 1
        || process_count == 0
        || (source_count == 0 && (closure_count != 0 || derived_count != 0 || inspect_count != 0))
        || (source_count == 0 && sdist_build_process_count != 0)
        || (source_count == 1
            && (closure_count != 1 || sdist_build_process_count != 1 || derived_count != 1))
    {
        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
    }
    Ok(SequenceRequirementsV1 {
        build_closure_required: closure_payload_count == 1,
        derived_wheel_required: derived_count == 1,
        process_count,
    })
}

#[cfg(target_os = "linux")]
pub fn execute_linux_vz_package_sequence_v1(
    request: StructurallyValidatedMacosLinuxVzPackageExecutionRequestV1,
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    exact_artifact_source: &mut File,
    mut exact_build_closure_payload_source: Option<&mut File>,
    observer: &mut dyn LinuxVzPackageProtectedProcessObserverV1,
) -> Result<LinuxVzPackageExecutionSequenceTranscriptV1, LinuxVzPackageExecutionSequencerErrorV1> {
    let requirements = sequence_requirements_v1(process_plan)?;
    if requirements.build_closure_required != exact_build_closure_payload_source.is_some() {
        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidInputs);
    }
    let execution_request_sha256 = request.request_sha256().clone();
    let execution_grant_sha256 = request.execution_grant_sha256().clone();
    let attempt_binding_sha256 = request.attempt_binding_sha256().clone();
    let mut authority =
        LinuxVzPackageExecutionAttemptAuthorityV1::from_validated_request_v1(request, process_plan)
            .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::AuthorityInvalid)?;
    let policy = LinuxVzPackageMaterializationPolicyV1::for_root_supervisor_v1()
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::AuthorityInvalid)?;
    let (mut workspace, workspace_initial) =
        create_fresh_linux_vz_package_workspace_v1(process_plan, &policy)
            .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed)?;
    workspace
        .seed_guest_file_canaries_v1(&attempt_binding_sha256)
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed)?;
    let scenario_clock = LinuxVzPackageScenarioClockV1::start_v1(process_plan)
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::AuthorityInvalid)?;

    let mut artifact: Option<MaterializedLinuxVzPackageArtifactV1> = None;
    let mut artifact_staged: Option<LinuxVzPackageArtifactMaterializationObservationV1> = None;
    let mut sdist_source: Option<MaterializedLinuxVzPackageSdistSourceV1> = None;
    let mut sdist_observation: Option<LinuxVzPackageSdistMaterializationObservationV1> = None;
    let mut build_closure: Option<MaterializedLinuxVzPackageBuildClosureV1> = None;
    let mut build_closure_staged: Option<LinuxVzPackageClosureMaterializationObservationV1> = None;
    let mut derived_wheel: Option<ValidatedLinuxVzPackageDerivedWheelV1> = None;
    let mut derived_wheel_observation: Option<LinuxVzPackageDerivedWheelObservationV1> = None;
    let mut console_targets: Vec<LinuxVzPackageConsoleTargetObservationV1> = Vec::new();
    let mut processes: Vec<LinuxVzPackageObservedProcessEvidenceV1> =
        Vec::with_capacity(requirements.process_count);
    let mut completed_action_count = 0_usize;
    let mut terminal = LinuxVzPackageExecutionSequenceTerminalV1::Complete;

    for (action_index, action) in process_plan.actions().iter().enumerate() {
        match action {
            MacosLinuxVzPackageExecutionActionV1::Internal { action } => match action {
                MacosLinuxVzPackageInternalActionV1::MaterializeExactArtifact { .. } => {
                    if action_index != 0 || artifact.is_some() {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    let (materialized, observation) = materialize_linux_vz_package_artifact_v1(
                        workspace.run_root().map_err(|_| {
                            LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed
                        })?,
                        exact_artifact_source,
                        process_plan,
                        &policy,
                    )
                    .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed)?;
                    artifact = Some(materialized);
                    artifact_staged = Some(observation);
                }
                MacosLinuxVzPackageInternalActionV1::SafelyExtractExactSdist { .. } => {
                    if sdist_source.is_some() {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    let (materialized, observation) = materialize_linux_vz_package_sdist_source_v1(
                        workspace.run_root().map_err(|_| {
                            LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed
                        })?,
                        artifact
                            .as_mut()
                            .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?,
                        process_plan,
                        &policy,
                    )
                    .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed)?;
                    sdist_source = Some(materialized);
                    sdist_observation = Some(observation);
                }
                MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                    build_requires_sha256,
                    build_closure: declared_closure,
                } => {
                    if build_closure.is_some() {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    if declared_closure.validate().is_err()
                        || build_requires_sha256 != declared_closure.declaration_set_sha256()
                    {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    if declared_closure.artifacts().is_empty() {
                        if exact_build_closure_payload_source.is_some() {
                            return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidInputs);
                        }
                        completed_action_count = action_index + 1;
                        continue;
                    }
                    let payload = exact_build_closure_payload_source
                        .take()
                        .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidInputs)?;
                    let (materialized, observation) =
                        materialize_linux_vz_package_build_closure_v1(
                            workspace.run_root().map_err(|_| {
                                LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed
                            })?,
                            payload,
                            process_plan,
                            &policy,
                        )
                        .map_err(|_| {
                            LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed
                        })?;
                    build_closure = Some(materialized);
                    build_closure_staged = Some(observation);
                }
                MacosLinuxVzPackageInternalActionV1::ValidateSingleDerivedWheel => {
                    if derived_wheel.is_some() {
                        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
                    }
                    let (mut validated, initial_observation) =
                        validate_single_linux_vz_package_derived_wheel_v1(
                            &mut workspace,
                            process_plan,
                            &policy,
                        )
                        .map_err(|_| {
                            LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed
                        })?;
                    let verified_observation = validated.verify_prelaunch().map_err(|_| {
                        LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed
                    })?;
                    if verified_observation.observation_sha256()
                        != initial_observation.observation_sha256()
                    {
                        return Err(
                            LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed,
                        );
                    }
                    derived_wheel_observation = Some(initial_observation);
                    derived_wheel = Some(validated);
                }
                MacosLinuxVzPackageInternalActionV1::InspectDerivedWheelMetadata => {
                    let validated = derived_wheel
                        .as_mut()
                        .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?;
                    let observation = validated.verify_prelaunch().map_err(|_| {
                        LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed
                    })?;
                    if derived_wheel_observation
                        .as_ref()
                        .map(|value| value.observation_sha256())
                        != Some(observation.observation_sha256())
                    {
                        return Err(
                            LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed,
                        );
                    }
                }
                MacosLinuxVzPackageInternalActionV1::ValidateConsoleEntryPointTarget { .. } => {
                    console_targets.push(
                        validate_linux_vz_package_console_target_v1(process_plan, action_index)
                            .map_err(|_| {
                                LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed
                            })?,
                    );
                }
            },
            MacosLinuxVzPackageExecutionActionV1::Process { process } => {
                workspace
                    .verify_prelaunch()
                    .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed)?;
                artifact
                    .as_mut()
                    .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?
                    .verify_prelaunch()
                    .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed)?;
                if let Some(value) = build_closure.as_mut() {
                    value.verify_prelaunch().map_err(|_| {
                        LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed
                    })?;
                }
                let uses_derived = process.arguments().iter().any(|argument| {
                    matches!(
                        argument,
                        MacosLinuxVzPackageProcessArgumentV1::ValidatedDerivedWheelPath
                    )
                });
                let bindings = if uses_derived {
                    derived_wheel
                        .as_ref()
                        .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?
                        .process_bindings_v1()
                } else {
                    ValidatedLinuxVzPackageDynamicProcessBindingsV1::none()
                };
                if let Some(value) = derived_wheel.as_mut() {
                    value.verify_prelaunch().map_err(|_| {
                        LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed
                    })?;
                }
                let contract = derive_linux_vz_package_process_launch_contract_v1(
                    process_plan,
                    action_index,
                    &bindings,
                )
                .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::LaunchContractFailed)?;
                let mut measured = measure_and_seal_linux_vz_package_process_v1(&contract)
                    .map_err(|_| {
                        LinuxVzPackageExecutionSequencerErrorV1::ProcessMeasurementFailed
                    })?;
                let observed = supervise_linux_vz_package_process_v1(
                    &contract,
                    &mut measured,
                    &scenario_clock,
                    &mut authority,
                    observer,
                )
                .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::ProcessSupervisionFailed)?;
                workspace
                    .verify_postrun()
                    .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed)?;
                artifact
                    .as_mut()
                    .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?
                    .verify_postrun()
                    .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed)?;
                if let Some(value) = build_closure.as_mut() {
                    value.verify_postrun().map_err(|_| {
                        LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed
                    })?;
                }
                if let Some(value) = derived_wheel.as_mut() {
                    value.verify_postrun().map_err(|_| {
                        LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed
                    })?;
                }
                let supervisor = observed.supervisor();
                let process_succeeded = supervisor.terminal()
                    == LinuxVzPackageProcessTerminalV1::Exited
                    && supervisor.exit_status() == Some(0)
                    && !supervisor.deadline_reached();
                processes.push(observed);
                if !process_succeeded {
                    terminal = LinuxVzPackageExecutionSequenceTerminalV1::ProcessFailed;
                    completed_action_count = action_index + 1;
                    break;
                }
            }
        }
        completed_action_count = action_index + 1;
    }

    if completed_action_count == 0 {
        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
    }
    if terminal == LinuxVzPackageExecutionSequenceTerminalV1::Complete
        && (requirements.derived_wheel_required != derived_wheel.is_some()
            || exact_build_closure_payload_source.is_some()
            || completed_action_count != process_plan.actions().len())
    {
        return Err(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan);
    }
    let artifact_final = artifact
        .as_mut()
        .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?
        .verify_postrun()
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed)?;
    let closure_final = build_closure
        .as_mut()
        .map(|value| value.verify_postrun())
        .transpose()
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::MaterializationFailed)?;
    if let Some(value) = derived_wheel.as_mut() {
        value
            .verify_postrun()
            .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::InternalValidationFailed)?;
    }
    let workspace_final = workspace
        .verify_postrun()
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::WorkspaceFailed)?;

    let staged = artifact_staged
        .as_ref()
        .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?;
    let wire = build_transcript_wire_v1(
        &execution_request_sha256,
        &execution_grant_sha256,
        &attempt_binding_sha256,
        process_plan,
        &workspace_initial,
        &workspace_final,
        staged,
        &artifact_final,
        sdist_observation.as_ref(),
        build_closure_staged.as_ref(),
        closure_final.as_ref(),
        derived_wheel_observation.as_ref(),
        &console_targets,
        &processes,
        completed_action_count,
        terminal,
    );
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_BYTES_V1
    {
        return Err(LinuxVzPackageExecutionSequencerErrorV1::LimitExceeded);
    }

    derived_wheel.take();
    sdist_source.take();
    if let Some(value) = build_closure.as_mut() {
        value
            .cleanup()
            .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::CleanupFailed)?;
    }
    artifact
        .as_mut()
        .ok_or(LinuxVzPackageExecutionSequencerErrorV1::InvalidPlan)?
        .cleanup()
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::CleanupFailed)?;
    workspace
        .cleanup()
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::CleanupFailed)?;
    observer
        .complete_sequence_v1()
        .map_err(|_| LinuxVzPackageExecutionSequencerErrorV1::ProcessSupervisionFailed)?;

    Ok(LinuxVzPackageExecutionSequenceTranscriptV1 {
        transcript_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        execution_request_sha256,
        execution_grant_sha256,
        attempt_binding_sha256,
        process_plan_sha256: process_plan.process_plan_sha256().clone(),
        artifact_sha256: process_plan.artifact_sha256().clone(),
        terminal,
        completed_action_count,
        total_action_count: process_plan.actions().len(),
        processes,
    })
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn build_transcript_wire_v1<'a>(
    execution_request_sha256: &'a Sha256Digest,
    execution_grant_sha256: &'a Sha256Digest,
    attempt_binding_sha256: &'a Sha256Digest,
    process_plan: &'a MacosLinuxVzPackageExecutionProcessPlanV1,
    workspace_initial: &'a LinuxVzPackageWorkspaceObservationV1,
    workspace_final: &'a LinuxVzPackageWorkspaceObservationV1,
    artifact_staged: &'a LinuxVzPackageArtifactMaterializationObservationV1,
    artifact_final: &'a LinuxVzPackageArtifactMaterializationObservationV1,
    sdist: Option<&'a LinuxVzPackageSdistMaterializationObservationV1>,
    closure_staged: Option<&'a LinuxVzPackageClosureMaterializationObservationV1>,
    closure_final: Option<&'a LinuxVzPackageClosureMaterializationObservationV1>,
    derived_wheel: Option<&'a LinuxVzPackageDerivedWheelObservationV1>,
    console_targets: &'a [LinuxVzPackageConsoleTargetObservationV1],
    processes: &'a [LinuxVzPackageObservedProcessEvidenceV1],
    completed_action_count: usize,
    terminal: LinuxVzPackageExecutionSequenceTerminalV1,
) -> ExecutionSequenceTranscriptWireV1<'a> {
    ExecutionSequenceTranscriptWireV1 {
        schema_version: LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_SCHEMA_V2,
        execution_request_sha256,
        execution_grant_sha256,
        attempt_binding_sha256,
        process_plan_sha256: process_plan.process_plan_sha256(),
        artifact_sha256: process_plan.artifact_sha256(),
        workspace_initial_observation_sha256: workspace_initial.observation_sha256(),
        workspace_final_observation_sha256: workspace_final.observation_sha256(),
        artifact: ArtifactMaterializationSummaryWireV1 {
            artifact_sha256: artifact_staged.artifact_sha256(),
            artifact_byte_length: artifact_staged.artifact_byte_length().to_string(),
            input_basename: artifact_staged.input_basename(),
            input_directory_device: artifact_staged.input_directory_device().to_string(),
            input_directory_inode: artifact_staged.input_directory_inode().to_string(),
            device: artifact_staged.device().to_string(),
            inode: artifact_staged.inode().to_string(),
            staged: true,
            final_postrun_rehash: artifact_final.artifact_sha256()
                == artifact_staged.artifact_sha256()
                && artifact_final.device() == artifact_staged.device()
                && artifact_final.inode() == artifact_staged.inode(),
        },
        sdist: sdist.map(|value| SdistMaterializationSummaryWireV1 {
            extraction_manifest_sha256: value.extraction_manifest_sha256(),
            artifact_format: value.artifact_format(),
            canonical_archive_root: value.canonical_archive_root(),
            member_count: value.member_count().to_string(),
            expanded_byte_length: value.expanded_byte_length().to_string(),
            source_device: value.source_device().to_string(),
            source_inode: value.source_inode().to_string(),
        }),
        build_closure: closure_staged
            .zip(closure_final)
            .map(
                |(staged, final_value)| ClosureMaterializationSummaryWireV1 {
                    build_requires_sha256: staged.build_requires_sha256(),
                    closure_sha256: staged.closure_sha256(),
                    payload_sha256: staged.payload_sha256(),
                    artifact_count: staged.artifact_count().to_string(),
                    payload_byte_length: staged.payload_byte_length().to_string(),
                    closure_device: staged.closure_device().to_string(),
                    closure_inode: staged.closure_inode().to_string(),
                    staged: true,
                    final_postrun_rehash: final_value.closure_sha256() == staged.closure_sha256()
                        && final_value.payload_sha256() == staged.payload_sha256()
                        && final_value.closure_device() == staged.closure_device()
                        && final_value.closure_inode() == staged.closure_inode(),
                },
            ),
        derived_wheel_observation_sha256: derived_wheel.map(|value| value.observation_sha256()),
        derived_wheel_manifest_sha256: derived_wheel
            .map(|value| value.normalized_manifest_sha256()),
        console_target_observation_sha256: console_targets
            .iter()
            .map(|value| value.observation_sha256())
            .collect(),
        processes: processes
            .iter()
            .map(|value| ProcessSummaryWireV1 {
                action_index: value.supervisor().action_index().to_string(),
                stage_name: value.supervisor().stage_name(),
                supervisor_evidence_sha256: value.supervisor().evidence_sha256(),
                protected_sensor_evidence_kind: value.supervisor().protected_sensor_evidence_kind(),
                protected_sensor_authentication_sha256: value
                    .supervisor()
                    .protected_sensor_authentication_sha256(),
                protected_sensor_evidence_set_sha256: value
                    .supervisor()
                    .protected_sensor_evidence_set_sha256(),
                sensor_session_challenge_sha256: value
                    .supervisor()
                    .sensor_session_challenge_sha256(),
                process_sensor_evidence_sha256: value.supervisor().process_sensor_evidence_sha256(),
                file_sensor_evidence_sha256: value.supervisor().file_sensor_evidence_sha256(),
                network_sensor_evidence_sha256: value.supervisor().network_sensor_evidence_sha256(),
                protected_sensor_authenticated: value.supervisor().protected_sensor_authenticated(),
                terminal: value.supervisor().terminal(),
                exit_status: value
                    .supervisor()
                    .exit_status()
                    .map(|value| value.to_string()),
                termination_signal: value
                    .supervisor()
                    .termination_signal()
                    .map(|value| value.to_string()),
                deadline_reached: value.supervisor().deadline_reached(),
                descendant_teardown_complete: value.supervisor().descendant_teardown_complete(),
                coverage_complete: value.coverage_complete(),
                host_composition_required: value.host_composition_required(),
                authoritative_verdict_permitted: value.authoritative_verdict_permitted(),
            })
            .collect(),
        completed_action_count: completed_action_count.to_string(),
        total_action_count: process_plan.actions().len().to_string(),
        terminal,
        trigger_sequence_complete: matches!(
            terminal,
            LinuxVzPackageExecutionSequenceTerminalV1::Complete
        ),
        execution_attempt_consumed: true,
        workspace_cleanup_complete: true,
        authenticated: false,
        verdict_eligible: false,
        public_network_route_present: false,
        sync_back: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        MacosLinuxVzNpmLifecyclePolicyV1, MacosLinuxVzPackageDependencyPolicyV1,
        MacosLinuxVzPackageExecutionStageV1, MacosLinuxVzPackageRuntimeExecutablesV1,
        MacosLinuxVzSdistBuildRecipeV1,
    };
    use whoathere_artifact::ArtifactFormat;
    use whoathere_detonation::{
        NpmEnvironmentProfileV1, SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1,
        SdistBuildClosureV1, SdistBuildModeV1,
    };

    fn npm_plan_v1() -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::NodeNpm {
                node_version: "24.4.0".to_string(),
                node_executable_sha256: Sha256Digest::from_bytes(b"inert node"),
                npm_version: "11.4.2".to_string(),
                npm_cli_sha256: Sha256Digest::from_bytes(b"inert npm cli"),
            },
            "npm_install_exact_local_tarball",
            vec![
                MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
                    environment: NpmEnvironmentProfileV1::CiTrue,
                    input_basename: "package.tgz".to_string(),
                    dependency_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::OfflineExactDependencyFree,
                    lifecycle_policy:
                        MacosLinuxVzNpmLifecyclePolicyV1::PackageManifestInstallHooksOnly,
                },
            ],
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("npm plan")
    }

    fn python_runtime_v1() -> MacosLinuxVzPackageRuntimeExecutablesV1 {
        MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
            python_version: "3.14.0".to_string(),
            python_executable_sha256: Sha256Digest::from_bytes(b"inert python"),
            pip_version: "25.1".to_string(),
            pip_cli_sha256: Sha256Digest::from_bytes(b"inert pip"),
        }
    }

    fn sdist_plan_v1() -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let closure = SdistBuildClosureV1::new(
            &["setuptools==75.0.0".to_string()],
            vec![SdistBuildClosureArtifactV1::new(
                "setuptools",
                "75.0.0",
                "setuptools-75.0.0-py3-none-any.whl",
                SdistBuildClosureArtifactFormatV1::Wheel,
                Sha256Digest::from_bytes(b"inert setuptools wheel"),
                1024,
            )
            .expect("closure artifact")],
        )
        .expect("closure");
        let build = MacosLinuxVzSdistBuildRecipeV1::new_for_execution_program_test_v1(
            ArtifactFormat::SdistTarGzip,
            "fixture-pkg-1.0.0".to_string(),
            SdistBuildModeV1::Pep517,
            Some("setuptools.build_meta".to_string()),
            Vec::new(),
            closure.declaration_set_sha256().clone(),
            closure.clone(),
        );
        let program = test_macos_linux_vz_package_execution_program_v1(
            python_runtime_v1(),
            "sdist_build_install_then_import_root",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
                    input_basename: "package.tar.gz".to_string(),
                    artifact_format: ArtifactFormat::SdistTarGzip,
                    expected_archive_root: "fixture-pkg-1.0.0".to_string(),
                },
                MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshSdistBuildVirtualEnvironment,
                MacosLinuxVzPackageExecutionStageV1::PythonInstallExactSdistBuildClosure {
                    build_requires_sha256: closure.declaration_set_sha256().clone(),
                    build_closure: closure,
                    resolver_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::NoIndexFixedClosureOnly,
                },
                MacosLinuxVzPackageExecutionStageV1::PythonBuildExactSdist { build },
                MacosLinuxVzPackageExecutionStageV1::PythonValidateSingleDerivedWheel,
                MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshDerivedWheelInstallVirtualEnvironment,
                MacosLinuxVzPackageExecutionStageV1::PythonPipInstallDerivedWheel {
                    resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexNoDependencies,
                },
                MacosLinuxVzPackageExecutionStageV1::PythonImportDerivedWheelRootProbe {
                    module: "fixture_pkg".to_string(),
                },
            ],
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("sdist plan")
    }

    #[test]
    fn npm_sequence_requires_one_materialization_and_one_process_without_closure() {
        let requirements = sequence_requirements_v1(&npm_plan_v1()).expect("requirements");
        assert!(!requirements.build_closure_required);
        assert!(!requirements.derived_wheel_required);
        assert_eq!(requirements.process_count, 1);
    }

    #[test]
    fn sdist_sequence_requires_source_closure_build_and_derived_wheel_in_order() {
        let requirements = sequence_requirements_v1(&sdist_plan_v1()).expect("requirements");
        assert!(requirements.build_closure_required);
        assert!(requirements.derived_wheel_required);
        assert_eq!(requirements.process_count, 6);
    }

    #[test]
    fn unsigned_sequence_transcripts_are_never_verdict_evidence() {
        assert_eq!(
            LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_SCHEMA_V1,
            "whoathere.linux_vz_package_execution_sequence_transcript.v1"
        );
        assert_ne!(
            LinuxVzPackageExecutionSequenceTerminalV1::Complete,
            LinuxVzPackageExecutionSequenceTerminalV1::ProcessFailed
        );
    }
}
