#[cfg(target_os = "linux")]
use crate::{
    connect_linux_vz_package_root_sensor_observer_v1, execute_linux_vz_package_sequence_v1,
    run_linux_vz_package_root_sensor_service_v1, split_linux_vz_package_root_coordinator_v1,
    LinuxVzPackageObservedProtectedSensorEvidenceV1, LinuxVzPackageRootCoordinatorBranchV1,
    LinuxVzPackageRootEvidenceSigningAuthorityV1, LinuxVzPackageRootRunnerBranchV1,
    LinuxVzPackageRootSensorServiceBranchV1, QualifiedMacosLinuxVzTelemetryBackendV1,
};
use crate::{
    derive_macos_linux_vz_package_execution_process_plan_v1,
    derive_macos_linux_vz_package_execution_program_v1,
    structurally_decode_macos_linux_vz_package_execution_request_v1,
    LinuxVzPackageExecutionSequenceTerminalV1, LinuxVzPackageSensorControlErrorV1,
    MacosLinuxVzPackageAuthorityRequestV1, MacosLinuxVzPackageExecutionGrantObservationV1,
    MacosLinuxVzPackageExecutionProcessPlanV1, MacosLinuxVzPackageExecutionRequestAuthorizerV1,
    MacosLinuxVzPackageExecutionRequestV1,
};
#[cfg(any(target_os = "linux", test))]
use crate::{
    MAX_LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_BYTES_V1,
    MAX_LINUX_VZ_PACKAGE_PROCESS_SUPERVISOR_EVIDENCE_BYTES_V1,
    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
    MAX_LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_BYTES_V1,
};
#[cfg(target_os = "linux")]
use serde::{Deserialize, Serialize};
#[cfg(any(target_os = "linux", test))]
use sha2::Digest;
use std::fmt;
use std::fs::File;
#[cfg(any(target_os = "linux", test))]
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_ROOT_RUNTIME_RESULT_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_root_runtime_result.v1";
pub const MAX_LINUX_VZ_PACKAGE_ROOT_RUNTIME_RESULT_BYTES_V1: usize = 256 * 1024 * 1024;

#[cfg(any(target_os = "linux", test))]
const RESULT_FRAME_MAGIC_V1: &[u8; 8] = b"WTPKRR01";
#[cfg(any(target_os = "linux", test))]
const RESULT_FRAME_VERSION_V1: u16 = 1;
#[cfg(any(target_os = "linux", test))]
const RESULT_FRAME_HEADER_BYTES_V1: usize = 56;
#[cfg(any(target_os = "linux", test))]
const MAX_RESULT_EVIDENCE_FRAME_BYTES_V1: usize =
    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1;
#[cfg(any(target_os = "linux", test))]
const MAX_RESULT_SUMMARY_BYTES_V1: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const INPUT_HANDOFF_MAGIC_V1: &[u8; 8] = b"WTPKIN01";
#[cfg(target_os = "linux")]
const INPUT_HANDOFF_BYTES_V1: usize = 16;
#[cfg(target_os = "linux")]
const INPUT_HANDOFF_ACK_V1: &[u8; 8] = b"WTPKIA01";
#[cfg(target_os = "linux")]
const RUNNER_FAILURE_EXIT_V1: i32 = 78;

#[cfg(any(target_os = "linux", test))]
fn build_closure_payload_required_v1(
    actions: &[crate::MacosLinuxVzPackageExecutionActionV1],
) -> bool {
    actions.iter().any(|action| {
        matches!(
            action,
            crate::MacosLinuxVzPackageExecutionActionV1::Internal {
                action: crate::MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                    build_closure,
                    ..
                }
            }
            | crate::MacosLinuxVzPackageExecutionActionV1::Internal {
                action:
                    crate::MacosLinuxVzPackageInternalActionV1::ValidateExactNpmDependencyClosure {
                        dependency_closure: build_closure,
                        ..
                    }
            } if !build_closure.artifacts().is_empty()
        )
    })
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxVzPackageRootRunnerFailureStageV1 {
    CustodyBoundary,
    InputHandoffReceive,
    InputHandoffAck,
    ObserverConnect,
    RequestDecode,
    SequenceExecution,
    ResultWrite,
}

#[cfg(any(target_os = "linux", test))]
impl LinuxVzPackageRootRunnerFailureStageV1 {
    const fn as_str(self) -> &'static str {
        match self {
            Self::CustodyBoundary => "custody_boundary",
            Self::InputHandoffReceive => "input_handoff_receive",
            Self::InputHandoffAck => "input_handoff_ack",
            Self::ObserverConnect => "observer_connect",
            Self::RequestDecode => "request_decode",
            Self::SequenceExecution => "sequence_execution",
            Self::ResultWrite => "result_write",
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LinuxVzPackageRootRunnerFailureV1 {
    stage: LinuxVzPackageRootRunnerFailureStageV1,
    reason: &'static str,
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootRunnerFailureV1 {
    const fn new(stage: LinuxVzPackageRootRunnerFailureStageV1, reason: &'static str) -> Self {
        Self { stage, reason }
    }
}

#[cfg(any(target_os = "linux", test))]
fn write_root_runner_failure_diagnostic_v1(
    writer: &mut impl Write,
    stage: LinuxVzPackageRootRunnerFailureStageV1,
    reason: &'static str,
) -> std::io::Result<()> {
    writeln!(
        writer,
        "WHOATHERE_PACKAGE_ROOT_RUNNER_FAILED stage={} reason={reason}",
        stage.as_str()
    )?;
    writer.flush()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootRuntimeErrorV1 {
    UnsupportedPlatform,
    RequestPreparationFailed,
    ProcessPlanInvalid,
    InputDescriptorInvalid,
    ResultChannelFailed,
    CoordinatorFailed,
    CustodyBoundaryInvalid,
    SigningAuthorityFailed,
    InputHandoffFailed,
    SensorServiceFailed(LinuxVzPackageSensorControlErrorV1),
    SensorObserverFailed,
    SequenceFailed,
    ResultInvalid,
    RunnerFailed,
    LimitExceeded,
    Serialization,
}

impl LinuxVzPackageRootRuntimeErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "linux_vz_package_root_runtime_platform_unsupported",
            Self::RequestPreparationFailed => {
                "linux_vz_package_root_runtime_request_preparation_failed"
            }
            Self::ProcessPlanInvalid => "linux_vz_package_root_runtime_process_plan_invalid",
            Self::InputDescriptorInvalid => {
                "linux_vz_package_root_runtime_input_descriptor_invalid"
            }
            Self::ResultChannelFailed => "linux_vz_package_root_runtime_result_channel_failed",
            Self::CoordinatorFailed => "linux_vz_package_root_runtime_coordinator_failed",
            Self::CustodyBoundaryInvalid => {
                "linux_vz_package_root_runtime_custody_boundary_invalid"
            }
            Self::SigningAuthorityFailed => {
                "linux_vz_package_root_runtime_signing_authority_failed"
            }
            Self::InputHandoffFailed => "linux_vz_package_root_runtime_input_handoff_failed",
            Self::SensorServiceFailed(error) => error.reason_code(),
            Self::SensorObserverFailed => "linux_vz_package_root_runtime_sensor_observer_failed",
            Self::SequenceFailed => "linux_vz_package_root_runtime_sequence_failed",
            Self::ResultInvalid => "linux_vz_package_root_runtime_result_invalid",
            Self::RunnerFailed => "linux_vz_package_root_runtime_runner_failed",
            Self::LimitExceeded => "linux_vz_package_root_runtime_limit_exceeded",
            Self::Serialization => "linux_vz_package_root_runtime_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootRuntimeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootRuntimeErrorV1 {}

/// Exact one-attempt execution state prepared before the root coordinator forks.
///
/// Construction burns the verified grant's only execution-request derivation before validating
/// any supplied artifact or scenario bytes. The closed request, execution program, and fixed
/// process plan are all derived while the coordinator is still single-threaded. This value is
/// deliberately non-clonable.
pub struct PreparedLinuxVzPackageRootRuntimeExecutionV1<'execution> {
    authority_request: &'execution MacosLinuxVzPackageAuthorityRequestV1,
    grant: &'execution MacosLinuxVzPackageExecutionGrantObservationV1,
    execution_request: MacosLinuxVzPackageExecutionRequestV1,
    process_plan: MacosLinuxVzPackageExecutionProcessPlanV1,
}

impl fmt::Debug for PreparedLinuxVzPackageRootRuntimeExecutionV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedLinuxVzPackageRootRuntimeExecutionV1")
            .field(
                "package_authority_request_sha256",
                &self.authority_request.request_sha256(),
            )
            .field(
                "execution_grant_sha256",
                &self.grant.execution_grant_sha256(),
            )
            .field(
                "execution_request_sha256",
                &self.execution_request.request_sha256(),
            )
            .field(
                "process_plan_sha256",
                &self.process_plan.process_plan_sha256(),
            )
            .field("sync_back", &false)
            .finish()
    }
}

impl PreparedLinuxVzPackageRootRuntimeExecutionV1<'_> {
    pub fn execution_request_sha256(&self) -> &Sha256Digest {
        self.execution_request.request_sha256()
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        self.process_plan.process_plan_sha256()
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub fn prepare_linux_vz_package_root_runtime_execution_v1<'execution>(
    authority_request: &'execution MacosLinuxVzPackageAuthorityRequestV1,
    grant: &'execution MacosLinuxVzPackageExecutionGrantObservationV1,
    artifact_bytes: &[u8],
    scenario_plan_bytes: &[u8],
    scenario_template_bytes: &[u8],
) -> Result<
    PreparedLinuxVzPackageRootRuntimeExecutionV1<'execution>,
    LinuxVzPackageRootRuntimeErrorV1,
> {
    let authorizer = MacosLinuxVzPackageExecutionRequestAuthorizerV1::new(grant)
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::RequestPreparationFailed)?;
    let execution_request = authorizer
        .build_and_consume(
            authority_request,
            artifact_bytes,
            scenario_plan_bytes,
            scenario_template_bytes,
        )
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::RequestPreparationFailed)?;
    let structurally_validated = structurally_decode_macos_linux_vz_package_execution_request_v1(
        execution_request.canonical_json_v1(),
    )
    .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::RequestPreparationFailed)?;
    let program = derive_macos_linux_vz_package_execution_program_v1(&structurally_validated)
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ProcessPlanInvalid)?;
    let process_plan = derive_macos_linux_vz_package_execution_process_plan_v1(&program)
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ProcessPlanInvalid)?;
    if process_plan.process_plan_sha256() == execution_request.request_sha256()
        || process_plan.artifact_sha256() != execution_request.artifact_sha256()
        || !grant.execution_request_consumed()
        || authority_request.sync_back_permitted()
        || grant.sync_back_permitted()
        || execution_request.sync_back_permitted()
        || process_plan.sync_back_permitted()
    {
        return Err(LinuxVzPackageRootRuntimeErrorV1::ProcessPlanInvalid);
    }
    Ok(PreparedLinuxVzPackageRootRuntimeExecutionV1 {
        authority_request,
        grant,
        execution_request,
        process_plan,
    })
}

pub struct LinuxVzPackageRootRuntimeActionEvidenceV1 {
    action_index: usize,
    supervisor_evidence: Vec<u8>,
    root_evidence_receipt: Vec<u8>,
    process_evidence: Vec<u8>,
    file_evidence: Vec<u8>,
    network_evidence: Vec<u8>,
}

impl fmt::Debug for LinuxVzPackageRootRuntimeActionEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootRuntimeActionEvidenceV1")
            .field("action_index", &self.action_index)
            .field(
                "supervisor_evidence_sha256",
                &Sha256Digest::from_bytes(&self.supervisor_evidence),
            )
            .field(
                "root_evidence_receipt_sha256",
                &Sha256Digest::from_bytes(&self.root_evidence_receipt),
            )
            .field(
                "process_evidence_sha256",
                &Sha256Digest::from_bytes(&self.process_evidence),
            )
            .field(
                "file_evidence_sha256",
                &Sha256Digest::from_bytes(&self.file_evidence),
            )
            .field(
                "network_evidence_sha256",
                &Sha256Digest::from_bytes(&self.network_evidence),
            )
            .finish()
    }
}

impl LinuxVzPackageRootRuntimeActionEvidenceV1 {
    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    pub fn supervisor_evidence_v1(&self) -> &[u8] {
        &self.supervisor_evidence
    }

    pub fn root_evidence_receipt_v1(&self) -> &[u8] {
        &self.root_evidence_receipt
    }

    pub fn process_evidence_v1(&self) -> &[u8] {
        &self.process_evidence
    }

    pub fn file_evidence_v1(&self) -> &[u8] {
        &self.file_evidence
    }

    pub fn network_evidence_v1(&self) -> &[u8] {
        &self.network_evidence
    }
}

pub struct LinuxVzPackageRootRuntimeResultV1 {
    transcript: Vec<u8>,
    transcript_sha256: Sha256Digest,
    summary: Vec<u8>,
    action_evidence: Vec<LinuxVzPackageRootRuntimeActionEvidenceV1>,
    terminal: LinuxVzPackageExecutionSequenceTerminalV1,
}

impl fmt::Debug for LinuxVzPackageRootRuntimeResultV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootRuntimeResultV1")
            .field("transcript_sha256", &self.transcript_sha256)
            .field("action_evidence_count", &self.action_evidence.len())
            .field("terminal", &self.terminal)
            .field("root_evidence_authenticated", &true)
            .field("host_composition_required", &true)
            .field("verdict_eligible", &false)
            .field("sync_back", &false)
            .finish()
    }
}

impl LinuxVzPackageRootRuntimeResultV1 {
    pub fn transcript_v1(&self) -> &[u8] {
        &self.transcript
    }

    pub fn transcript_sha256(&self) -> &Sha256Digest {
        &self.transcript_sha256
    }

    pub fn summary_v1(&self) -> &[u8] {
        &self.summary
    }

    pub fn action_evidence(&self) -> &[LinuxVzPackageRootRuntimeActionEvidenceV1] {
        &self.action_evidence
    }

    pub const fn terminal(&self) -> LinuxVzPackageExecutionSequenceTerminalV1 {
        self.terminal
    }

    pub const fn root_evidence_authenticated(&self) -> bool {
        true
    }

    pub const fn host_composition_required(&self) -> bool {
        true
    }

    pub const fn authoritative_verdict_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

/// Writes the bounded transcript and every authenticated root evidence component to an external
/// evidence channel using the same digest-framed protocol verified between the runner and service.
/// This is evidence egress only; the framing carries no artifact bytes and no sync-back authority.
#[cfg(target_os = "linux")]
pub fn write_linux_vz_package_root_runtime_result_v1(
    writer: &mut dyn Write,
    result: &LinuxVzPackageRootRuntimeResultV1,
) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
    write_result_frame_v1(
        writer,
        RuntimeResultFrameKindV1::Transcript,
        0,
        &result.transcript,
    )?;
    for action in &result.action_evidence {
        for (kind, payload) in [
            (
                RuntimeResultFrameKindV1::Supervisor,
                action.supervisor_evidence.as_slice(),
            ),
            (
                RuntimeResultFrameKindV1::RootReceipt,
                action.root_evidence_receipt.as_slice(),
            ),
            (
                RuntimeResultFrameKindV1::Process,
                action.process_evidence.as_slice(),
            ),
            (
                RuntimeResultFrameKindV1::File,
                action.file_evidence.as_slice(),
            ),
            (
                RuntimeResultFrameKindV1::Network,
                action.network_evidence.as_slice(),
            ),
        ] {
            write_result_frame_v1(writer, kind, action.action_index, payload)?;
        }
    }
    write_result_frame_v1(
        writer,
        RuntimeResultFrameKindV1::Complete,
        0,
        &result.summary,
    )?;
    writer
        .flush()
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultChannelFailed)
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum RuntimeResultFrameKindV1 {
    Transcript = 1,
    Supervisor = 2,
    RootReceipt = 3,
    Process = 4,
    File = 5,
    Network = 6,
    Complete = 7,
    Error = 8,
}

#[cfg(any(target_os = "linux", test))]
impl RuntimeResultFrameKindV1 {
    fn from_u16_v1(value: u16) -> Result<Self, LinuxVzPackageRootRuntimeErrorV1> {
        match value {
            1 => Ok(Self::Transcript),
            2 => Ok(Self::Supervisor),
            3 => Ok(Self::RootReceipt),
            4 => Ok(Self::Process),
            5 => Ok(Self::File),
            6 => Ok(Self::Network),
            7 => Ok(Self::Complete),
            8 => Ok(Self::Error),
            _ => Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid),
        }
    }

    const fn maximum_payload_bytes_v1(self) -> usize {
        match self {
            Self::Transcript => MAX_LINUX_VZ_PACKAGE_EXECUTION_SEQUENCE_TRANSCRIPT_BYTES_V1,
            Self::Supervisor => MAX_LINUX_VZ_PACKAGE_PROCESS_SUPERVISOR_EVIDENCE_BYTES_V1,
            Self::RootReceipt => MAX_LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_BYTES_V1,
            Self::Process | Self::File | Self::Network => MAX_RESULT_EVIDENCE_FRAME_BYTES_V1,
            Self::Complete | Self::Error => MAX_RESULT_SUMMARY_BYTES_V1,
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct RuntimeResultSummaryWireV1 {
    schema_version: String,
    execution_request_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    transcript_sha256: Sha256Digest,
    terminal: LinuxVzPackageExecutionSequenceTerminalV1,
    process_action_indexes: Vec<String>,
    process_action_count: String,
    result_frame_count: String,
    root_evidence_authenticated: bool,
    host_composition_required: bool,
    authoritative_verdict_permitted: bool,
    public_network_route_present: bool,
    package_execution: bool,
    sync_back: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, PartialEq, Eq)]
struct RuntimeResultFrameV1 {
    kind: RuntimeResultFrameKindV1,
    action_index: usize,
    payload: Vec<u8>,
}

#[cfg(any(target_os = "linux", test))]
fn write_result_frame_v1(
    writer: &mut dyn Write,
    kind: RuntimeResultFrameKindV1,
    action_index: usize,
    payload: &[u8],
) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
    if payload.is_empty() || payload.len() > kind.maximum_payload_bytes_v1() {
        return Err(LinuxVzPackageRootRuntimeErrorV1::LimitExceeded);
    }
    let action_index =
        u32::try_from(action_index).map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
    let payload_length = u64::try_from(payload.len())
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
    let digest = sha2::Sha256::digest(payload);
    let mut header = [0_u8; RESULT_FRAME_HEADER_BYTES_V1];
    header[..8].copy_from_slice(RESULT_FRAME_MAGIC_V1);
    header[8..10].copy_from_slice(&RESULT_FRAME_VERSION_V1.to_be_bytes());
    header[10..12].copy_from_slice(&(kind as u16).to_be_bytes());
    header[12..16].copy_from_slice(&action_index.to_be_bytes());
    header[16..24].copy_from_slice(&payload_length.to_be_bytes());
    header[24..56].copy_from_slice(&digest);
    writer
        .write_all(&header)
        .and_then(|()| writer.write_all(payload))
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultChannelFailed)
}

#[cfg(any(target_os = "linux", test))]
fn read_result_frame_v1(
    reader: &mut dyn Read,
    aggregate_bytes: &mut usize,
) -> Result<RuntimeResultFrameV1, LinuxVzPackageRootRuntimeErrorV1> {
    let mut header = [0_u8; RESULT_FRAME_HEADER_BYTES_V1];
    reader
        .read_exact(&mut header)
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultChannelFailed)?;
    if &header[..8] != RESULT_FRAME_MAGIC_V1
        || u16::from_be_bytes([header[8], header[9]]) != RESULT_FRAME_VERSION_V1
    {
        return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
    }
    let kind = RuntimeResultFrameKindV1::from_u16_v1(u16::from_be_bytes([header[10], header[11]]))?;
    let action_index = usize::try_from(u32::from_be_bytes(
        header[12..16]
            .try_into()
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultInvalid)?,
    ))
    .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
    let payload_length = usize::try_from(u64::from_be_bytes(
        header[16..24]
            .try_into()
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultInvalid)?,
    ))
    .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
    if payload_length == 0 || payload_length > kind.maximum_payload_bytes_v1() {
        return Err(LinuxVzPackageRootRuntimeErrorV1::LimitExceeded);
    }
    *aggregate_bytes = aggregate_bytes
        .checked_add(RESULT_FRAME_HEADER_BYTES_V1)
        .and_then(|value| value.checked_add(payload_length))
        .ok_or(LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
    if *aggregate_bytes > MAX_LINUX_VZ_PACKAGE_ROOT_RUNTIME_RESULT_BYTES_V1 {
        return Err(LinuxVzPackageRootRuntimeErrorV1::LimitExceeded);
    }
    let mut payload = vec![0_u8; payload_length];
    reader
        .read_exact(&mut payload)
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultChannelFailed)?;
    if sha2::Sha256::digest(&payload).as_slice() != &header[24..56] {
        return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
    }
    Ok(RuntimeResultFrameV1 {
        kind,
        action_index,
        payload,
    })
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
pub fn run_linux_vz_package_root_runtime_execution_v1(
    prepared: PreparedLinuxVzPackageRootRuntimeExecutionV1<'_>,
    signing_seed_fd: OwnedFd,
    backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    guest_evidence_verifying_key: [u8; 32],
    artifact_source: File,
    build_closure_source: Option<File>,
) -> Result<LinuxVzPackageRootRuntimeResultV1, LinuxVzPackageRootRuntimeErrorV1> {
    linux::run_v1(
        prepared,
        signing_seed_fd,
        backend,
        guest_evidence_verifying_key,
        artifact_source,
        build_closure_source,
    )
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
pub fn run_linux_vz_package_root_runtime_execution_v1(
    _prepared: PreparedLinuxVzPackageRootRuntimeExecutionV1<'_>,
    _signing_seed_fd: OwnedFd,
    _backend: &crate::QualifiedMacosLinuxVzTelemetryBackendV1,
    _guest_evidence_verifying_key: [u8; 32],
    _artifact_source: File,
    _build_closure_source: Option<File>,
) -> Result<LinuxVzPackageRootRuntimeResultV1, LinuxVzPackageRootRuntimeErrorV1> {
    Err(LinuxVzPackageRootRuntimeErrorV1::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::mem::{size_of, zeroed, MaybeUninit};

    struct RunnerInputsV1 {
        artifact: File,
        build_closure: Option<File>,
        result_writer: File,
    }

    pub(super) fn run_v1(
        prepared: PreparedLinuxVzPackageRootRuntimeExecutionV1<'_>,
        signing_seed_fd: OwnedFd,
        backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
        guest_evidence_verifying_key: [u8; 32],
        artifact_source: File,
        build_closure_source: Option<File>,
    ) -> Result<LinuxVzPackageRootRuntimeResultV1, LinuxVzPackageRootRuntimeErrorV1> {
        validate_execution_inputs_v1(
            &prepared.process_plan,
            &artifact_source,
            build_closure_source.as_ref(),
        )?;
        let (result_reader, result_writer) = pipe_v1()?;
        match split_linux_vz_package_root_coordinator_v1(signing_seed_fd)
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::CoordinatorFailed)?
        {
            LinuxVzPackageRootCoordinatorBranchV1::SensorService(branch) => run_service_v1(
                branch,
                prepared,
                backend,
                artifact_source,
                build_closure_source,
                result_reader,
                result_writer,
            ),
            LinuxVzPackageRootCoordinatorBranchV1::RootRunner(branch) => {
                run_runner_and_exit_v1(branch, prepared, backend, guest_evidence_verifying_key)
            }
        }
    }

    fn run_service_v1(
        branch: LinuxVzPackageRootSensorServiceBranchV1,
        prepared: PreparedLinuxVzPackageRootRuntimeExecutionV1<'_>,
        backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
        artifact_source: File,
        build_closure_source: Option<File>,
        result_reader: OwnedFd,
        result_writer: OwnedFd,
    ) -> Result<LinuxVzPackageRootRuntimeResultV1, LinuxVzPackageRootRuntimeErrorV1> {
        let runner_pid = branch.runner_pid();
        if !valid_custody_boundary_v1(&branch) {
            terminate_and_reap_v1(runner_pid);
            return Err(LinuxVzPackageRootRuntimeErrorV1::CustodyBoundaryInvalid);
        }
        let (control_fd, signing_seed) = branch.into_control_and_signing_seed_v1();
        let signing_seed = signing_seed
            .read_once_v1()
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::SigningAuthorityFailed)?;
        let authority = LinuxVzPackageRootEvidenceSigningAuthorityV1::from_consumed_execution_v1(
            prepared.authority_request,
            prepared.grant,
            signing_seed,
        )
        .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::SigningAuthorityFailed)?;
        let mut control = UnixStream::from(control_fd);
        let handoff = send_runner_inputs_v1(
            &mut control,
            &artifact_source,
            build_closure_source.as_ref(),
            result_writer.as_raw_fd(),
        );
        drop(result_writer);
        if handoff.is_err() || read_handoff_ack_v1(&mut control).is_err() {
            terminate_and_reap_v1(runner_pid);
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        let control_fd = control.into();
        if let Err(error) =
            run_linux_vz_package_root_sensor_service_v1(control_fd, runner_pid, authority, backend)
        {
            terminate_and_reap_v1(runner_pid);
            return Err(LinuxVzPackageRootRuntimeErrorV1::SensorServiceFailed(error));
        }
        let mut result_reader = File::from(result_reader);
        let result = read_execution_result_v1(&mut result_reader, &prepared);
        let runner_status = wait_runner_v1(runner_pid);
        match (result, runner_status) {
            (Ok(result), Ok(())) => Ok(result),
            (Err(error), _) => Err(error),
            (_, Err(error)) => Err(error),
        }
    }

    fn run_runner_and_exit_v1(
        branch: LinuxVzPackageRootRunnerBranchV1,
        prepared: PreparedLinuxVzPackageRootRuntimeExecutionV1<'_>,
        backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
        guest_evidence_verifying_key: [u8; 32],
    ) -> ! {
        let exit_code = match run_runner_v1(branch, prepared, backend, guest_evidence_verifying_key)
        {
            Ok(()) => 0,
            Err(failure) => {
                let _ = write_root_runner_failure_diagnostic_v1(
                    &mut std::io::stderr().lock(),
                    failure.stage,
                    failure.reason,
                );
                RUNNER_FAILURE_EXIT_V1
            }
        };
        unsafe { libc::_exit(exit_code) }
    }

    fn run_runner_v1(
        branch: LinuxVzPackageRootRunnerBranchV1,
        prepared: PreparedLinuxVzPackageRootRuntimeExecutionV1<'_>,
        backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
        guest_evidence_verifying_key: [u8; 32],
    ) -> Result<(), LinuxVzPackageRootRunnerFailureV1> {
        if !branch.signing_seed_descriptor_closed()
            || branch.ptrace_capability_present()
            || branch.dumpable()
            || !branch.no_new_privileges()
        {
            return Err(LinuxVzPackageRootRunnerFailureV1::new(
                LinuxVzPackageRootRunnerFailureStageV1::CustodyBoundary,
                LinuxVzPackageRootRuntimeErrorV1::CustodyBoundaryInvalid.reason_code(),
            ));
        }
        let mut control = UnixStream::from(branch.into_control_fd_v1());
        let mut inputs = receive_runner_inputs_v1(&mut control).map_err(|error| {
            LinuxVzPackageRootRunnerFailureV1::new(
                LinuxVzPackageRootRunnerFailureStageV1::InputHandoffReceive,
                error.reason_code(),
            )
        })?;
        control.write_all(INPUT_HANDOFF_ACK_V1).map_err(|_| {
            LinuxVzPackageRootRunnerFailureV1::new(
                LinuxVzPackageRootRunnerFailureStageV1::InputHandoffAck,
                LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed.reason_code(),
            )
        })?;
        let control_fd = control.into();
        let mut observer = connect_linux_vz_package_root_sensor_observer_v1(
            control_fd,
            backend,
            prepared.authority_request,
            prepared.grant,
            guest_evidence_verifying_key,
        )
        .map_err(|error| {
            LinuxVzPackageRootRunnerFailureV1::new(
                LinuxVzPackageRootRunnerFailureStageV1::ObserverConnect,
                error.reason_code(),
            )
        })?;
        let request = structurally_decode_macos_linux_vz_package_execution_request_v1(
            prepared.execution_request.canonical_json_v1(),
        )
        .map_err(|error| {
            LinuxVzPackageRootRunnerFailureV1::new(
                LinuxVzPackageRootRunnerFailureStageV1::RequestDecode,
                error.reason_code(),
            )
        })?;
        let closure = inputs.build_closure.as_mut();
        let transcript = execute_linux_vz_package_sequence_v1(
            request,
            &prepared.process_plan,
            &mut inputs.artifact,
            closure,
            &mut observer,
        )
        .map_err(|error| {
            LinuxVzPackageRootRunnerFailureV1::new(
                LinuxVzPackageRootRunnerFailureStageV1::SequenceExecution,
                error.reason_code(),
            )
        })?;
        write_execution_result_v1(&mut inputs.result_writer, &transcript).map_err(|error| {
            LinuxVzPackageRootRunnerFailureV1::new(
                LinuxVzPackageRootRunnerFailureStageV1::ResultWrite,
                error.reason_code(),
            )
        })
    }

    fn valid_custody_boundary_v1(branch: &LinuxVzPackageRootSensorServiceBranchV1) -> bool {
        let boundary = branch.runner_custody_boundary();
        branch.runner_hardening_complete()
            && boundary.runner_pid() == branch.runner_pid()
            && boundary.thread_count() == 1
            && boundary.open_descriptor_count() == 4
            && boundary.unexpected_descriptor_count() == 0
            && !boundary.ptrace_capability_present()
            && boundary.root_credentials_verified()
            && boundary.tracer_absent()
            && boundary.no_new_privileges()
            && boundary.ambient_capabilities() == 0
    }

    fn validate_execution_inputs_v1(
        process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
        artifact: &File,
        build_closure: Option<&File>,
    ) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
        validate_read_only_input_v1(artifact)?;
        if let Some(closure) = build_closure {
            validate_read_only_input_v1(closure)?;
        }
        let closure_required = build_closure_payload_required_v1(process_plan.actions());
        if closure_required != build_closure.is_some() {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputDescriptorInvalid);
        }
        Ok(())
    }

    fn validate_read_only_input_v1(file: &File) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
        let descriptor = file.as_raw_fd();
        let access = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        let metadata = file
            .metadata()
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::InputDescriptorInvalid)?;
        if access < 0
            || access & libc::O_ACCMODE != libc::O_RDONLY
            || descriptor_flags < 0
            || descriptor_flags & libc::FD_CLOEXEC == 0
            || !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.mode() & 0o7777 != 0o444
            || metadata.nlink() != 1
            || metadata.len() == 0
        {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputDescriptorInvalid);
        }
        Ok(())
    }

    fn pipe_v1() -> Result<(OwnedFd, OwnedFd), LinuxVzPackageRootRuntimeErrorV1> {
        let mut descriptors = [-1_i32; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(LinuxVzPackageRootRuntimeErrorV1::ResultChannelFailed);
        }
        Ok(unsafe {
            (
                OwnedFd::from_raw_fd(descriptors[0]),
                OwnedFd::from_raw_fd(descriptors[1]),
            )
        })
    }

    fn send_runner_inputs_v1(
        stream: &mut UnixStream,
        artifact: &File,
        build_closure: Option<&File>,
        result_writer: RawFd,
    ) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
        let mut descriptors = vec![artifact.as_raw_fd()];
        if let Some(closure) = build_closure {
            descriptors.push(closure.as_raw_fd());
        }
        descriptors.push(result_writer);
        if !(2..=3).contains(&descriptors.len())
            || descriptors
                .iter()
                .any(|descriptor| *descriptor <= libc::STDERR_FILENO)
        {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        let mut frame = [0_u8; INPUT_HANDOFF_BYTES_V1];
        frame[..8].copy_from_slice(INPUT_HANDOFF_MAGIC_V1);
        frame[8] = u8::try_from(descriptors.len())
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
        frame[9] = u8::from(build_closure.is_some());
        let mut io_vector = libc::iovec {
            iov_base: frame.as_mut_ptr().cast(),
            iov_len: frame.len(),
        };
        let descriptor_bytes = descriptors
            .len()
            .checked_mul(size_of::<RawFd>())
            .ok_or(LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
        let control_length = unsafe { libc::CMSG_SPACE(descriptor_bytes as libc::c_uint) } as usize;
        let mut control = [0 as libc::c_long; 8];
        if control_length > size_of::<[libc::c_long; 8]>() {
            return Err(LinuxVzPackageRootRuntimeErrorV1::LimitExceeded);
        }
        let mut message = unsafe { zeroed::<libc::msghdr>() };
        message.msg_iov = &mut io_vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control_length
            .try_into()
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
        let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if header.is_null() {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        unsafe {
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = (libc::CMSG_LEN(descriptor_bytes as libc::c_uint) as usize)
                .try_into()
                .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
            for (index, descriptor) in descriptors.iter().enumerate() {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    *descriptor,
                );
            }
        }
        let sent = loop {
            let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
            if sent >= 0 {
                break sent as usize;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
            }
        };
        if sent == 0 || sent > frame.len() {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        stream
            .write_all(&frame[sent..])
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed)
    }

    fn receive_runner_inputs_v1(
        stream: &mut UnixStream,
    ) -> Result<RunnerInputsV1, LinuxVzPackageRootRuntimeErrorV1> {
        let mut frame = [0_u8; INPUT_HANDOFF_BYTES_V1];
        let mut io_vector = libc::iovec {
            iov_base: frame.as_mut_ptr().cast(),
            iov_len: frame.len(),
        };
        let mut control = [0 as libc::c_long; 8];
        let mut message = unsafe { zeroed::<libc::msghdr>() };
        message.msg_iov = &mut io_vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of::<[libc::c_long; 8]>()
            .try_into()
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
        let received = loop {
            let received =
                unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
            if received >= 0 {
                break received as usize;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
            }
        };
        if received == 0
            || received > frame.len()
            || message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        let descriptors = collect_descriptors_v1(&message)?;
        if stream.read_exact(&mut frame[received..]).is_err()
            || &frame[..8] != INPUT_HANDOFF_MAGIC_V1
            || frame[10..].iter().any(|byte| *byte != 0)
        {
            close_raw_descriptors_v1(&descriptors);
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        let closure_present = match frame[9] {
            0 => false,
            1 => true,
            _ => {
                close_raw_descriptors_v1(&descriptors);
                return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
            }
        };
        let expected_count = if closure_present { 3 } else { 2 };
        if frame[8] as usize != expected_count || descriptors.len() != expected_count {
            close_raw_descriptors_v1(&descriptors);
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        let mut descriptors = descriptors.into_iter();
        let artifact = unsafe {
            File::from_raw_fd(
                descriptors
                    .next()
                    .ok_or(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed)?,
            )
        };
        let build_closure = if closure_present {
            Some(unsafe {
                File::from_raw_fd(
                    descriptors
                        .next()
                        .ok_or(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed)?,
                )
            })
        } else {
            None
        };
        let result_writer = unsafe {
            File::from_raw_fd(
                descriptors
                    .next()
                    .ok_or(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed)?,
            )
        };
        validate_read_only_input_v1(&artifact)?;
        if let Some(closure) = build_closure.as_ref() {
            validate_read_only_input_v1(closure)?;
        }
        validate_result_writer_v1(&result_writer)?;
        Ok(RunnerInputsV1 {
            artifact,
            build_closure,
            result_writer,
        })
    }

    fn collect_descriptors_v1(
        message: &libc::msghdr,
    ) -> Result<Vec<RawFd>, LinuxVzPackageRootRuntimeErrorV1> {
        let mut descriptors = Vec::new();
        let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
        while !header.is_null() {
            let value = unsafe { &*header };
            let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
            let length = usize::try_from(value.cmsg_len)
                .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)?;
            if value.cmsg_level != libc::SOL_SOCKET
                || value.cmsg_type != libc::SCM_RIGHTS
                || length < minimum
                || !(length - minimum).is_multiple_of(size_of::<RawFd>())
            {
                close_raw_descriptors_v1(&descriptors);
                return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
            }
            let count = (length - minimum) / size_of::<RawFd>();
            for index in 0..count {
                let descriptor = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index))
                };
                let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
                if descriptor <= libc::STDERR_FILENO
                    || descriptors.contains(&descriptor)
                    || flags < 0
                    || flags & libc::FD_CLOEXEC == 0
                {
                    close_raw_descriptors_v1(&descriptors);
                    if descriptor > libc::STDERR_FILENO && !descriptors.contains(&descriptor) {
                        let _ = unsafe { libc::close(descriptor) };
                    }
                    return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
                }
                descriptors.push(descriptor);
            }
            header = unsafe { libc::CMSG_NXTHDR(message, header) };
        }
        if descriptors.is_empty() {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        Ok(descriptors)
    }

    fn close_raw_descriptors_v1(descriptors: &[RawFd]) {
        for descriptor in descriptors {
            let _ = unsafe { libc::close(*descriptor) };
        }
    }

    fn validate_result_writer_v1(writer: &File) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
        let descriptor = writer.as_raw_fd();
        let access = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        let mut metadata = MaybeUninit::<libc::stat>::uninit();
        if access < 0
            || access & libc::O_ACCMODE != libc::O_WRONLY
            || flags < 0
            || flags & libc::FD_CLOEXEC == 0
            || unsafe { libc::fstat(descriptor, metadata.as_mut_ptr()) } != 0
        {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        let metadata = unsafe { metadata.assume_init() };
        if metadata.st_mode & libc::S_IFMT != libc::S_IFIFO
            || metadata.st_uid != 0
            || metadata.st_gid != 0
        {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        Ok(())
    }

    fn read_handoff_ack_v1(
        stream: &mut UnixStream,
    ) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
        let mut acknowledgement = [0_u8; 8];
        stream
            .read_exact(&mut acknowledgement)
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed)?;
        if &acknowledgement != INPUT_HANDOFF_ACK_V1 {
            return Err(LinuxVzPackageRootRuntimeErrorV1::InputHandoffFailed);
        }
        Ok(())
    }

    fn write_execution_result_v1(
        writer: &mut File,
        transcript: &crate::LinuxVzPackageExecutionSequenceTranscriptV1,
    ) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
        write_result_frame_v1(
            writer,
            RuntimeResultFrameKindV1::Transcript,
            0,
            transcript.canonical_json_v1(),
        )?;
        let mut action_indexes = Vec::with_capacity(transcript.processes().len());
        for process in transcript.processes() {
            let action_index = process.supervisor().action_index();
            if action_index == 0
                || action_indexes
                    .last()
                    .is_some_and(|previous| *previous >= action_index)
            {
                return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
            }
            let LinuxVzPackageObservedProtectedSensorEvidenceV1::AuthenticatedRootIncomplete(
                output,
            ) = process.protected_sensor()
            else {
                return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
            };
            if !output.authenticated()
                || output.coverage_complete()
                || !output.host_composition_required()
                || output.authoritative_verdict_permitted()
                || output.sync_back_permitted()
            {
                return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
            }
            for (kind, bytes) in [
                (
                    RuntimeResultFrameKindV1::Supervisor,
                    process.supervisor().canonical_json_v1(),
                ),
                (
                    RuntimeResultFrameKindV1::RootReceipt,
                    output.receipt_bytes_v1(),
                ),
                (
                    RuntimeResultFrameKindV1::Process,
                    output.process().canonical_json_v1(),
                ),
                (
                    RuntimeResultFrameKindV1::File,
                    output.file().canonical_json_v1(),
                ),
                (
                    RuntimeResultFrameKindV1::Network,
                    output.network().canonical_json_v1(),
                ),
            ] {
                write_result_frame_v1(writer, kind, action_index, bytes)?;
            }
            action_indexes.push(action_index);
        }
        let summary = RuntimeResultSummaryWireV1 {
            schema_version: LINUX_VZ_PACKAGE_ROOT_RUNTIME_RESULT_SCHEMA_V1.to_string(),
            execution_request_sha256: transcript.execution_request_sha256().clone(),
            execution_grant_sha256: transcript.execution_grant_sha256().clone(),
            attempt_binding_sha256: transcript.attempt_binding_sha256().clone(),
            process_plan_sha256: transcript.process_plan_sha256().clone(),
            artifact_sha256: transcript.artifact_sha256().clone(),
            transcript_sha256: transcript.transcript_sha256().clone(),
            terminal: transcript.terminal(),
            process_action_indexes: action_indexes.iter().map(ToString::to_string).collect(),
            process_action_count: action_indexes.len().to_string(),
            result_frame_count: (2 + action_indexes.len() * 5).to_string(),
            root_evidence_authenticated: true,
            host_composition_required: true,
            authoritative_verdict_permitted: false,
            public_network_route_present: false,
            package_execution: true,
            sync_back: false,
        };
        let summary = serde_json_canonicalizer::to_vec(&summary)
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::Serialization)?;
        write_result_frame_v1(writer, RuntimeResultFrameKindV1::Complete, 0, &summary)?;
        writer
            .flush()
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultChannelFailed)
    }

    fn read_execution_result_v1(
        reader: &mut File,
        prepared: &PreparedLinuxVzPackageRootRuntimeExecutionV1<'_>,
    ) -> Result<LinuxVzPackageRootRuntimeResultV1, LinuxVzPackageRootRuntimeErrorV1> {
        let mut aggregate = 0_usize;
        let transcript = read_result_frame_v1(reader, &mut aggregate)?;
        if transcript.kind != RuntimeResultFrameKindV1::Transcript || transcript.action_index != 0 {
            return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
        }
        let transcript_sha256 = Sha256Digest::from_bytes(&transcript.payload);
        let mut actions = Vec::new();
        let summary = loop {
            let frame = read_result_frame_v1(reader, &mut aggregate)?;
            match frame.kind {
                RuntimeResultFrameKindV1::Complete if frame.action_index == 0 => {
                    break frame.payload;
                }
                RuntimeResultFrameKindV1::Error => {
                    return Err(LinuxVzPackageRootRuntimeErrorV1::RunnerFailed);
                }
                RuntimeResultFrameKindV1::Supervisor => {
                    if frame.action_index == 0
                        || actions.last().is_some_and(
                            |action: &LinuxVzPackageRootRuntimeActionEvidenceV1| {
                                action.action_index >= frame.action_index
                            },
                        )
                    {
                        return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
                    }
                    let receipt = read_expected_action_frame_v1(
                        reader,
                        &mut aggregate,
                        RuntimeResultFrameKindV1::RootReceipt,
                        frame.action_index,
                    )?;
                    let process = read_expected_action_frame_v1(
                        reader,
                        &mut aggregate,
                        RuntimeResultFrameKindV1::Process,
                        frame.action_index,
                    )?;
                    let file = read_expected_action_frame_v1(
                        reader,
                        &mut aggregate,
                        RuntimeResultFrameKindV1::File,
                        frame.action_index,
                    )?;
                    let network = read_expected_action_frame_v1(
                        reader,
                        &mut aggregate,
                        RuntimeResultFrameKindV1::Network,
                        frame.action_index,
                    )?;
                    actions.push(LinuxVzPackageRootRuntimeActionEvidenceV1 {
                        action_index: frame.action_index,
                        supervisor_evidence: frame.payload,
                        root_evidence_receipt: receipt,
                        process_evidence: process,
                        file_evidence: file,
                        network_evidence: network,
                    });
                }
                _ => return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid),
            }
        };
        let wire: RuntimeResultSummaryWireV1 = serde_json::from_slice(&summary)
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::ResultInvalid)?;
        let canonical = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::Serialization)?;
        let action_indexes = actions
            .iter()
            .map(|action| action.action_index.to_string())
            .collect::<Vec<_>>();
        if canonical != summary
            || wire.schema_version != LINUX_VZ_PACKAGE_ROOT_RUNTIME_RESULT_SCHEMA_V1
            || wire.execution_request_sha256 != *prepared.execution_request.request_sha256()
            || wire.execution_grant_sha256 != *prepared.grant.execution_grant_sha256()
            || wire.attempt_binding_sha256 != *prepared.grant.attempt_binding_sha256()
            || wire.process_plan_sha256 != *prepared.process_plan.process_plan_sha256()
            || wire.artifact_sha256 != *prepared.authority_request.artifact_sha256()
            || wire.transcript_sha256 != transcript_sha256
            || wire.process_action_indexes != action_indexes
            || wire.process_action_count != actions.len().to_string()
            || wire.result_frame_count != (2 + actions.len() * 5).to_string()
            || actions.is_empty()
            || !wire.root_evidence_authenticated
            || !wire.host_composition_required
            || wire.authoritative_verdict_permitted
            || wire.public_network_route_present
            || !wire.package_execution
            || wire.sync_back
        {
            return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
        }
        Ok(LinuxVzPackageRootRuntimeResultV1 {
            transcript: transcript.payload,
            transcript_sha256,
            summary,
            action_evidence: actions,
            terminal: wire.terminal,
        })
    }

    fn read_expected_action_frame_v1(
        reader: &mut File,
        aggregate: &mut usize,
        expected_kind: RuntimeResultFrameKindV1,
        expected_action_index: usize,
    ) -> Result<Vec<u8>, LinuxVzPackageRootRuntimeErrorV1> {
        let frame = read_result_frame_v1(reader, aggregate)?;
        if frame.kind != expected_kind || frame.action_index != expected_action_index {
            return Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid);
        }
        Ok(frame.payload)
    }

    fn wait_runner_v1(runner_pid: u32) -> Result<(), LinuxVzPackageRootRuntimeErrorV1> {
        let runner_pid = libc::pid_t::try_from(runner_pid)
            .map_err(|_| LinuxVzPackageRootRuntimeErrorV1::RunnerFailed)?;
        let mut status = 0_i32;
        loop {
            let result = unsafe { libc::waitpid(runner_pid, &mut status, 0) };
            if result == runner_pid {
                break;
            }
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return Err(LinuxVzPackageRootRuntimeErrorV1::RunnerFailed);
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err(LinuxVzPackageRootRuntimeErrorV1::RunnerFailed);
        }
        Ok(())
    }

    fn terminate_and_reap_v1(runner_pid: u32) {
        let Ok(runner_pid) = libc::pid_t::try_from(runner_pid) else {
            return;
        };
        let _ = unsafe { libc::kill(runner_pid, libc::SIGKILL) };
        let mut status = 0_i32;
        loop {
            let result = unsafe { libc::waitpid(runner_pid, &mut status, 0) };
            if result == runner_pid {
                return;
            }
            if result < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
            {
                continue;
            }
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    #[test]
    fn preparation_burns_one_exact_request_before_the_fork_boundary() {
        let (artifact, plan, template) =
            crate::linux_vz_package_execution_request::test_inert_npm_execution_inputs_v1();
        let request = crate::linux_vz_package_authority_request::test_macos_linux_vz_package_authority_request_from_scenario_v1(
            crate::MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact,
            &plan,
            &template,
            digest("root runtime request challenge"),
            digest("root runtime unique clone"),
        );
        let grant = crate::linux_vz_package_execution_grant::test_macos_linux_vz_package_execution_grant_observation_v1(&request);
        let prepared = prepare_linux_vz_package_root_runtime_execution_v1(
            &request, &grant, &artifact, &plan, &template,
        )
        .expect("prepare exact runtime execution");
        assert!(grant.execution_request_consumed());
        assert_eq!(
            prepared.process_plan_sha256(),
            prepared.process_plan.process_plan_sha256()
        );
        assert!(!prepared.sync_back_permitted());
        assert!(matches!(
            prepare_linux_vz_package_root_runtime_execution_v1(
                &request, &grant, &artifact, &plan, &template,
            ),
            Err(LinuxVzPackageRootRuntimeErrorV1::RequestPreparationFailed)
        ));
    }

    #[test]
    fn empty_sdist_closure_does_not_require_a_payload_descriptor() {
        use whoathere_detonation::{
            SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
        };

        let empty = SdistBuildClosureV1::new(&[], Vec::new()).expect("empty closure");
        let empty_actions = [crate::MacosLinuxVzPackageExecutionActionV1::Internal {
            action: crate::MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                build_requires_sha256: empty.declaration_set_sha256().clone(),
                build_closure: empty,
            },
        }];
        assert!(!build_closure_payload_required_v1(&empty_actions));

        let requirements = ["setuptools==75.0.0".to_string()];
        let populated = SdistBuildClosureV1::new(
            &requirements,
            vec![SdistBuildClosureArtifactV1::new(
                "setuptools",
                "75.0.0",
                "setuptools-75.0.0-py3-none-any.whl",
                SdistBuildClosureArtifactFormatV1::Wheel,
                digest("setuptools wheel"),
                1024,
            )
            .expect("closure artifact")],
        )
        .expect("populated closure");
        let populated_actions = [crate::MacosLinuxVzPackageExecutionActionV1::Internal {
            action: crate::MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                build_requires_sha256: populated.declaration_set_sha256().clone(),
                build_closure: populated,
            },
        }];
        assert!(build_closure_payload_required_v1(&populated_actions));
    }

    #[test]
    fn result_frame_round_trip_rejects_corruption_and_bounds() {
        assert_eq!(
            MAX_RESULT_EVIDENCE_FRAME_BYTES_V1,
            MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1
        );
        let payload = b"authenticated inert result";
        let mut frame = Vec::new();
        write_result_frame_v1(&mut frame, RuntimeResultFrameKindV1::Process, 7, payload)
            .expect("frame");
        let mut aggregate = 0;
        let decoded = read_result_frame_v1(&mut frame.as_slice(), &mut aggregate).expect("decode");
        assert_eq!(decoded.kind, RuntimeResultFrameKindV1::Process);
        assert_eq!(decoded.action_index, 7);
        assert_eq!(decoded.payload, payload);
        assert_eq!(aggregate, RESULT_FRAME_HEADER_BYTES_V1 + payload.len());

        let beyond_legacy_limit = vec![0; 4 * 1024 * 1024 + 1];
        write_result_frame_v1(
            &mut Vec::new(),
            RuntimeResultFrameKindV1::Process,
            8,
            &beyond_legacy_limit,
        )
        .expect("result evidence above the legacy limit");

        frame[24] ^= 1;
        assert_eq!(
            read_result_frame_v1(&mut frame.as_slice(), &mut 0),
            Err(LinuxVzPackageRootRuntimeErrorV1::ResultInvalid)
        );
        assert_eq!(
            write_result_frame_v1(
                &mut Vec::new(),
                RuntimeResultFrameKindV1::Process,
                1,
                &vec![0; MAX_RESULT_EVIDENCE_FRAME_BYTES_V1 + 1],
            ),
            Err(LinuxVzPackageRootRuntimeErrorV1::LimitExceeded)
        );
    }

    #[test]
    fn root_runner_failure_diagnostic_contains_only_fixed_stage_and_reason_codes() {
        let cases = [
            (
                LinuxVzPackageRootRunnerFailureStageV1::CustodyBoundary,
                "custody_boundary",
            ),
            (
                LinuxVzPackageRootRunnerFailureStageV1::InputHandoffReceive,
                "input_handoff_receive",
            ),
            (
                LinuxVzPackageRootRunnerFailureStageV1::InputHandoffAck,
                "input_handoff_ack",
            ),
            (
                LinuxVzPackageRootRunnerFailureStageV1::ObserverConnect,
                "observer_connect",
            ),
            (
                LinuxVzPackageRootRunnerFailureStageV1::RequestDecode,
                "request_decode",
            ),
            (
                LinuxVzPackageRootRunnerFailureStageV1::SequenceExecution,
                "sequence_execution",
            ),
            (
                LinuxVzPackageRootRunnerFailureStageV1::ResultWrite,
                "result_write",
            ),
        ];
        for (stage, expected) in cases {
            let mut diagnostic = Vec::new();
            write_root_runner_failure_diagnostic_v1(
                &mut diagnostic,
                stage,
                LinuxVzPackageRootRuntimeErrorV1::SequenceFailed.reason_code(),
            )
            .expect("write diagnostic");
            assert_eq!(
                String::from_utf8(diagnostic).expect("UTF-8 diagnostic"),
                format!(
                    "WHOATHERE_PACKAGE_ROOT_RUNNER_FAILED stage={expected} reason=linux_vz_package_root_runtime_sequence_failed\n"
                )
            );
        }
    }

    #[test]
    fn runtime_result_is_explicitly_not_a_verdict_or_sync_back_authority() {
        let result = LinuxVzPackageRootRuntimeResultV1 {
            transcript: b"transcript".to_vec(),
            transcript_sha256: Sha256Digest::from_bytes(b"transcript"),
            summary: b"summary".to_vec(),
            action_evidence: Vec::new(),
            terminal: LinuxVzPackageExecutionSequenceTerminalV1::Complete,
        };
        assert!(result.root_evidence_authenticated());
        assert!(result.host_composition_required());
        assert!(!result.authoritative_verdict_permitted());
        assert!(!result.sync_back_permitted());
    }
}
