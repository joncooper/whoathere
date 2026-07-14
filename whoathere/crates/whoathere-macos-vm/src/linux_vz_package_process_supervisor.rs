#[cfg(any(target_os = "linux", test))]
use crate::LinuxVzPackageProcessLaunchContractV1;
#[cfg(target_os = "linux")]
use crate::{
    decode_linux_vz_package_process_sensor_correlation_v1,
    decode_linux_vz_package_protected_sensor_payload_set_v1,
    validate_linux_vz_package_protected_sensor_payloads_v1,
    LinuxVzPackageExpectedProcessSensorCorrelationV1, LinuxVzPackageProcessLaunchIdentityV1,
    MeasuredLinuxVzPackageProcessV1,
};
use crate::{
    LinuxVzPackageProcessMeasurementObservationV1, LinuxVzPackageProcessSensorCorrelationV1,
    LinuxVzPackageProtectedSensorPayloadSetV1, MacosLinuxVzPackageExecutionActionV1,
    MacosLinuxVzPackageExecutionProcessPlanV1,
    StructurallyValidatedMacosLinuxVzPackageExecutionRequestV1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
#[cfg(target_os = "linux")]
use std::os::fd::RawFd;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_PROCESS_SUPERVISOR_EVIDENCE_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_process_supervisor_evidence.v1";
pub const MAX_LINUX_VZ_PACKAGE_PROCESS_SUPERVISOR_EVIDENCE_BYTES_V1: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageProcessSupervisorErrorV1 {
    UnsupportedPlatform,
    PrivilegeBoundary,
    InvalidContract,
    InvalidDeadline,
    ProcessMeasurementFailed,
    CgroupUnavailable,
    CgroupCreateFailed,
    CgroupConfigurationFailed,
    PipeFailed,
    ForkFailed,
    CgroupMembershipFailed,
    ProtectedSensorUnavailable,
    ProtectedSensorCorrelationFailed,
    ProtectedSensorTeardownFailed,
    ChildSetupFailed,
    WaitFailed,
    OutputFailed,
    TeardownFailed,
    PostrunMeasurementFailed,
    Serialization,
    LimitExceeded,
}

impl LinuxVzPackageProcessSupervisorErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "linux_vz_package_process_supervisor_platform_unsupported",
            Self::PrivilegeBoundary => "linux_vz_package_process_supervisor_privilege_invalid",
            Self::InvalidContract => "linux_vz_package_process_supervisor_contract_invalid",
            Self::InvalidDeadline => "linux_vz_package_process_supervisor_deadline_invalid",
            Self::ProcessMeasurementFailed => {
                "linux_vz_package_process_supervisor_measurement_failed"
            }
            Self::CgroupUnavailable => "linux_vz_package_process_supervisor_cgroup_unavailable",
            Self::CgroupCreateFailed => "linux_vz_package_process_supervisor_cgroup_create_failed",
            Self::CgroupConfigurationFailed => {
                "linux_vz_package_process_supervisor_cgroup_configuration_failed"
            }
            Self::PipeFailed => "linux_vz_package_process_supervisor_pipe_failed",
            Self::ForkFailed => "linux_vz_package_process_supervisor_fork_failed",
            Self::CgroupMembershipFailed => {
                "linux_vz_package_process_supervisor_cgroup_membership_failed"
            }
            Self::ProtectedSensorUnavailable => {
                "linux_vz_package_process_supervisor_sensor_unavailable"
            }
            Self::ProtectedSensorCorrelationFailed => {
                "linux_vz_package_process_supervisor_sensor_correlation_failed"
            }
            Self::ProtectedSensorTeardownFailed => {
                "linux_vz_package_process_supervisor_sensor_teardown_failed"
            }
            Self::ChildSetupFailed => "linux_vz_package_process_supervisor_child_setup_failed",
            Self::WaitFailed => "linux_vz_package_process_supervisor_wait_failed",
            Self::OutputFailed => "linux_vz_package_process_supervisor_output_failed",
            Self::TeardownFailed => "linux_vz_package_process_supervisor_teardown_failed",
            Self::PostrunMeasurementFailed => {
                "linux_vz_package_process_supervisor_postrun_measurement_failed"
            }
            Self::Serialization => "linux_vz_package_process_supervisor_serialization_failed",
            Self::LimitExceeded => "linux_vz_package_process_supervisor_limit_exceeded",
        }
    }
}

impl fmt::Display for LinuxVzPackageProcessSupervisorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageProcessSupervisorErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzPackageProcessTerminalV1 {
    Exited,
    Signaled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxVzPackageProcessCompletionV1 {
    process_started_monotonic_nanoseconds: u64,
    process_ended_monotonic_nanoseconds: u64,
    terminal: LinuxVzPackageProcessTerminalV1,
    exit_status: Option<u8>,
    termination_signal: Option<u8>,
}

impl LinuxVzPackageProcessCompletionV1 {
    pub(crate) fn from_parts_v1(
        process_started_monotonic_nanoseconds: u64,
        process_ended_monotonic_nanoseconds: u64,
        terminal: LinuxVzPackageProcessTerminalV1,
        exit_status: Option<u8>,
        termination_signal: Option<u8>,
    ) -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
        if process_started_monotonic_nanoseconds == 0
            || process_ended_monotonic_nanoseconds <= process_started_monotonic_nanoseconds
            || !matches!(
                (terminal, exit_status, termination_signal),
                (LinuxVzPackageProcessTerminalV1::Exited, Some(_), None)
                    | (
                        LinuxVzPackageProcessTerminalV1::Signaled,
                        None,
                        Some(1..=64)
                    )
            )
        {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed);
        }
        Ok(Self {
            process_started_monotonic_nanoseconds,
            process_ended_monotonic_nanoseconds,
            terminal,
            exit_status,
            termination_signal,
        })
    }

    pub const fn process_started_monotonic_nanoseconds(&self) -> u64 {
        self.process_started_monotonic_nanoseconds
    }

    pub const fn process_ended_monotonic_nanoseconds(&self) -> u64 {
        self.process_ended_monotonic_nanoseconds
    }

    pub const fn terminal(&self) -> LinuxVzPackageProcessTerminalV1 {
        self.terminal
    }

    pub const fn exit_status(&self) -> Option<u8> {
        self.exit_status
    }

    pub const fn termination_signal(&self) -> Option<u8> {
        self.termination_signal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageBoundedOutputObservationV1 {
    total_byte_length: String,
    captured_byte_length: String,
    sha256: Sha256Digest,
    truncated: bool,
}

impl LinuxVzPackageBoundedOutputObservationV1 {
    pub fn total_byte_length(&self) -> u64 {
        self.total_byte_length
            .parse()
            .expect("supervisor output length is constructed from u64")
    }

    pub fn captured_byte_length(&self) -> u64 {
        self.captured_byte_length
            .parse()
            .expect("supervisor captured length is constructed from u64")
    }

    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

#[cfg(target_os = "linux")]
#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackageProcessSupervisorEvidenceWireV1<'a> {
    schema_version: &'static str,
    execution_grant_sha256: &'a Sha256Digest,
    attempt_binding_sha256: &'a Sha256Digest,
    launch_contract_sha256: &'a Sha256Digest,
    process_plan_sha256: &'a Sha256Digest,
    action_index: String,
    stage_name: &'a str,
    preexec_measurement_sha256: &'a Sha256Digest,
    postrun_measurement_sha256: &'a Sha256Digest,
    protected_sensor_correlation_sha256: &'a Sha256Digest,
    protected_sensor_payload_set_sha256: &'a Sha256Digest,
    cgroup_name: &'a str,
    cgroup_version: &'static str,
    leader_pid: String,
    package_uid: String,
    package_gid: String,
    no_supplementary_groups: bool,
    no_new_privileges: bool,
    subreaper_enabled: bool,
    terminal: LinuxVzPackageProcessTerminalV1,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    termination_signal: Option<String>,
    started_monotonic_nanoseconds: String,
    ended_monotonic_nanoseconds: String,
    deadline_monotonic_nanoseconds: String,
    deadline_reached: bool,
    term_signal_count: String,
    cgroup_kill_used: bool,
    background_descendants_observed: bool,
    reaped_process_count: String,
    stdout: &'a LinuxVzPackageBoundedOutputObservationV1,
    stderr: &'a LinuxVzPackageBoundedOutputObservationV1,
    child_setup_channel_clean: bool,
    cgroup_empty_after_reap: bool,
    cgroup_removed: bool,
    descendant_teardown_complete: bool,
    public_network_route_present: bool,
    sync_back: bool,
}

pub struct LinuxVzPackageProcessSupervisorEvidenceV1 {
    canonical_json: Vec<u8>,
    evidence_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    stage_name: String,
    preexec_measurement: LinuxVzPackageProcessMeasurementObservationV1,
    postrun_measurement: LinuxVzPackageProcessMeasurementObservationV1,
    protected_sensor_correlation_sha256: Sha256Digest,
    protected_sensor_payload_set_sha256: Sha256Digest,
    cgroup_name: String,
    leader_pid: u32,
    terminal: LinuxVzPackageProcessTerminalV1,
    exit_status: Option<u8>,
    termination_signal: Option<u8>,
    started_monotonic_nanoseconds: u64,
    ended_monotonic_nanoseconds: u64,
    deadline_monotonic_nanoseconds: u64,
    deadline_reached: bool,
    term_signal_count: u32,
    cgroup_kill_used: bool,
    background_descendants_observed: bool,
    reaped_process_count: u32,
    stdout_observation: LinuxVzPackageBoundedOutputObservationV1,
    stderr_observation: LinuxVzPackageBoundedOutputObservationV1,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl fmt::Debug for LinuxVzPackageProcessSupervisorEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageProcessSupervisorEvidenceV1")
            .field("evidence_sha256", &self.evidence_sha256)
            .field("launch_contract_sha256", &self.launch_contract_sha256)
            .field("action_index", &self.action_index)
            .field("stage_name", &self.stage_name)
            .field("leader_pid", &self.leader_pid)
            .field("terminal", &self.terminal)
            .field("deadline_reached", &self.deadline_reached)
            .field(
                "background_descendants_observed",
                &self.background_descendants_observed,
            )
            .field("stdout", &"<bounded-output-redacted>")
            .field("stderr", &"<bounded-output-redacted>")
            .finish()
    }
}

impl LinuxVzPackageProcessSupervisorEvidenceV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn evidence_sha256(&self) -> &Sha256Digest {
        &self.evidence_sha256
    }

    pub fn launch_contract_sha256(&self) -> &Sha256Digest {
        &self.launch_contract_sha256
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

    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    pub fn stage_name(&self) -> &str {
        &self.stage_name
    }

    pub fn preexec_measurement(&self) -> &LinuxVzPackageProcessMeasurementObservationV1 {
        &self.preexec_measurement
    }

    pub fn postrun_measurement(&self) -> &LinuxVzPackageProcessMeasurementObservationV1 {
        &self.postrun_measurement
    }

    pub fn protected_sensor_correlation_sha256(&self) -> &Sha256Digest {
        &self.protected_sensor_correlation_sha256
    }

    pub fn protected_sensor_payload_set_sha256(&self) -> &Sha256Digest {
        &self.protected_sensor_payload_set_sha256
    }

    pub fn cgroup_name(&self) -> &str {
        &self.cgroup_name
    }

    pub const fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    pub const fn terminal(&self) -> LinuxVzPackageProcessTerminalV1 {
        self.terminal
    }

    pub const fn exit_status(&self) -> Option<u8> {
        self.exit_status
    }

    pub const fn termination_signal(&self) -> Option<u8> {
        self.termination_signal
    }

    pub const fn deadline_reached(&self) -> bool {
        self.deadline_reached
    }

    pub const fn started_monotonic_nanoseconds(&self) -> u64 {
        self.started_monotonic_nanoseconds
    }

    pub const fn ended_monotonic_nanoseconds(&self) -> u64 {
        self.ended_monotonic_nanoseconds
    }

    pub const fn deadline_monotonic_nanoseconds(&self) -> u64 {
        self.deadline_monotonic_nanoseconds
    }

    pub const fn term_signal_count(&self) -> u32 {
        self.term_signal_count
    }

    pub const fn cgroup_kill_used(&self) -> bool {
        self.cgroup_kill_used
    }

    pub const fn background_descendants_observed(&self) -> bool {
        self.background_descendants_observed
    }

    pub const fn reaped_process_count(&self) -> u32 {
        self.reaped_process_count
    }

    pub fn stdout_observation(&self) -> &LinuxVzPackageBoundedOutputObservationV1 {
        &self.stdout_observation
    }

    pub fn stderr_observation(&self) -> &LinuxVzPackageBoundedOutputObservationV1 {
        &self.stderr_observation
    }

    pub fn stdout(&self) -> &[u8] {
        &self.stdout
    }

    pub fn stderr(&self) -> &[u8] {
        &self.stderr
    }

    pub const fn descendant_teardown_complete(&self) -> bool {
        true
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub struct LinuxVzPackageObservedProcessEvidenceV1 {
    supervisor: LinuxVzPackageProcessSupervisorEvidenceV1,
    protected_sensor: LinuxVzPackageProcessSensorCorrelationV1,
    protected_sensor_payloads: LinuxVzPackageProtectedSensorPayloadSetV1,
}

impl fmt::Debug for LinuxVzPackageObservedProcessEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageObservedProcessEvidenceV1")
            .field("supervisor", &self.supervisor)
            .field("protected_sensor", &self.protected_sensor)
            .finish()
    }
}

impl LinuxVzPackageObservedProcessEvidenceV1 {
    pub fn supervisor(&self) -> &LinuxVzPackageProcessSupervisorEvidenceV1 {
        &self.supervisor
    }

    pub fn protected_sensor(&self) -> &LinuxVzPackageProcessSensorCorrelationV1 {
        &self.protected_sensor
    }

    pub fn process_sensor_evidence(&self) -> &[u8] {
        self.protected_sensor_payloads.process().canonical_json_v1()
    }

    pub fn file_sensor_evidence(&self) -> &[u8] {
        self.protected_sensor_payloads.file().canonical_json_v1()
    }

    pub fn network_sensor_evidence(&self) -> &[u8] {
        self.protected_sensor_payloads.network().canonical_json_v1()
    }

    pub fn protected_sensor_payloads(&self) -> &LinuxVzPackageProtectedSensorPayloadSetV1 {
        &self.protected_sensor_payloads
    }

    pub const fn coverage_complete(&self) -> bool {
        true
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxVzPackageProtectedSensorOutputV1 {
    pub(crate) correlation: Vec<u8>,
    pub(crate) process_evidence: Vec<u8>,
    pub(crate) file_evidence: Vec<u8>,
    pub(crate) network_evidence: Vec<u8>,
}

/// Crate-sealed process observation boundary.
///
/// A production implementation must own a root-protected sensor channel and make abort idempotent.
/// The process is never released from its blocked child setup until `leader_attached_v1` succeeds.
#[cfg(target_os = "linux")]
pub trait LinuxVzPackageProtectedProcessObserverV1:
    protected_process_observer_seal::Sealed
{
    fn sensor_session_challenge_sha256_v1(&self) -> &Sha256Digest;

    fn arm_v1(
        &mut self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
        cgroup_name: &str,
        cgroup_directory_fd: RawFd,
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1>;

    fn leader_attached_v1(
        &mut self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
        cgroup_name: &str,
        leader_pid: u32,
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1>;

    fn finish_v1(
        &mut self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
        cgroup_name: &str,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<LinuxVzPackageProtectedSensorOutputV1, LinuxVzPackageProcessSupervisorErrorV1>;

    fn abort_v1(&mut self) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1>;
}

#[cfg(target_os = "linux")]
pub(crate) mod protected_process_observer_seal {
    pub trait Sealed {}
}

pub struct LinuxVzPackageScenarioClockV1 {
    process_plan_sha256: Sha256Digest,
    started_monotonic_nanoseconds: u64,
    deadline_monotonic_nanoseconds: u64,
}

impl fmt::Debug for LinuxVzPackageScenarioClockV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageScenarioClockV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field(
                "started_monotonic_nanoseconds",
                &self.started_monotonic_nanoseconds,
            )
            .field(
                "deadline_monotonic_nanoseconds",
                &self.deadline_monotonic_nanoseconds,
            )
            .finish()
    }
}

impl LinuxVzPackageScenarioClockV1 {
    #[cfg(target_os = "linux")]
    pub fn start_v1(
        process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    ) -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
        let started = linux::monotonic_nanoseconds_v1()?;
        let duration = process_plan
            .limits()
            .wall_clock_millis
            .checked_mul(1_000_000)
            .ok_or(LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline)?;
        let deadline = started
            .checked_add(duration)
            .ok_or(LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline)?;
        Ok(Self {
            process_plan_sha256: process_plan.process_plan_sha256().clone(),
            started_monotonic_nanoseconds: started,
            deadline_monotonic_nanoseconds: deadline,
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn start_v1(
        _process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    ) -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
        Err(LinuxVzPackageProcessSupervisorErrorV1::UnsupportedPlatform)
    }

    pub const fn started_monotonic_nanoseconds(&self) -> u64 {
        self.started_monotonic_nanoseconds
    }

    pub const fn deadline_monotonic_nanoseconds(&self) -> u64 {
        self.deadline_monotonic_nanoseconds
    }
}

/// One-scenario authority derived only from a structurally validated request whose signed grant
/// was already burned. Each process action is burned before measurement or launch, including on
/// failure, so an in-guest caller cannot retry a changed executable under the same attempt.
pub struct LinuxVzPackageExecutionAttemptAuthorityV1 {
    process_plan_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    process_action_indexes: BTreeSet<usize>,
    burned_process_action_indexes: BTreeSet<usize>,
}

impl fmt::Debug for LinuxVzPackageExecutionAttemptAuthorityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageExecutionAttemptAuthorityV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("execution_grant_sha256", &self.execution_grant_sha256)
            .field("attempt_binding_sha256", &self.attempt_binding_sha256)
            .field("process_action_count", &self.process_action_indexes.len())
            .field(
                "burned_process_action_count",
                &self.burned_process_action_indexes.len(),
            )
            .finish()
    }
}

impl LinuxVzPackageExecutionAttemptAuthorityV1 {
    pub fn from_validated_request_v1(
        request: StructurallyValidatedMacosLinuxVzPackageExecutionRequestV1,
        process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    ) -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
        if request.package_execution_authority_permitted()
            || request.sync_back_permitted()
            || request.request_sha256() != process_plan.execution_request_sha256()
            || request.artifact_sha256() != process_plan.artifact_sha256()
            || request.artifact_byte_length() != process_plan.artifact_byte_length()
            || request.package_uid() != 65_534
            || request.package_gid() != 65_534
            || process_plan.package_execution_authority_permitted()
            || process_plan.sync_back_permitted()
        {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidContract);
        }
        let process_action_indexes = process_plan
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(index, action)| {
                matches!(action, MacosLinuxVzPackageExecutionActionV1::Process { .. })
                    .then_some(index)
            })
            .collect::<BTreeSet<_>>();
        if process_action_indexes.is_empty() {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidContract);
        }
        Ok(Self {
            process_plan_sha256: process_plan.process_plan_sha256().clone(),
            execution_grant_sha256: request.execution_grant_sha256().clone(),
            attempt_binding_sha256: request.attempt_binding_sha256().clone(),
            process_action_indexes,
            burned_process_action_indexes: BTreeSet::new(),
        })
    }

    #[cfg(any(target_os = "linux", test))]
    fn burn_process_action_v1(
        &mut self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        if contract.process_plan_sha256() != &self.process_plan_sha256
            || !self
                .process_action_indexes
                .contains(&contract.action_index())
            || !self
                .burned_process_action_indexes
                .insert(contract.action_index())
        {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidContract);
        }
        Ok(())
    }

    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn attempt_binding_sha256(&self) -> &Sha256Digest {
        &self.attempt_binding_sha256
    }

    pub fn burned_process_action_count(&self) -> usize {
        self.burned_process_action_indexes.len()
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }

    #[cfg(test)]
    fn for_test_v1(process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1) -> Self {
        let process_action_indexes = process_plan
            .actions()
            .iter()
            .enumerate()
            .filter_map(|(index, action)| {
                matches!(action, MacosLinuxVzPackageExecutionActionV1::Process { .. })
                    .then_some(index)
            })
            .collect();
        Self {
            process_plan_sha256: process_plan.process_plan_sha256().clone(),
            execution_grant_sha256: Sha256Digest::from_bytes(b"inert test execution grant"),
            attempt_binding_sha256: Sha256Digest::from_bytes(b"inert test attempt binding"),
            process_action_indexes,
            burned_process_action_indexes: BTreeSet::new(),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn supervise_linux_vz_package_process_v1(
    contract: &LinuxVzPackageProcessLaunchContractV1,
    measured: &mut MeasuredLinuxVzPackageProcessV1,
    scenario_clock: &LinuxVzPackageScenarioClockV1,
    authority: &mut LinuxVzPackageExecutionAttemptAuthorityV1,
    observer: &mut dyn LinuxVzPackageProtectedProcessObserverV1,
) -> Result<LinuxVzPackageObservedProcessEvidenceV1, LinuxVzPackageProcessSupervisorErrorV1> {
    linux::supervise_v1(contract, measured, scenario_clock, authority, observer)
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::ffi::CString;
    use std::fs::File;
    use std::io::Read;
    use std::mem::{size_of, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::os::unix::fs::MetadataExt;
    use std::ptr;

    const PACKAGE_UID_V1: u32 = 65_534;
    const PACKAGE_GID_V1: u32 = 65_534;
    const CGROUP_ROOT_V1: &str = "/sys/fs/cgroup";
    const CGROUP2_SUPER_MAGIC_V1: i64 = 0x6367_7270;
    const CHILD_SETUP_PDEATHSIG_FAILED_V1: u8 = 1;
    const CHILD_SETUP_SESSION_FAILED_V1: u8 = 2;
    const CHILD_SETUP_DIRECTORY_FAILED_V1: u8 = 3;
    const CHILD_SETUP_RLIMIT_FAILED_V1: u8 = 4;
    const CHILD_SETUP_SYNC_FAILED_V1: u8 = 5;
    const CHILD_SETUP_CREDENTIAL_FAILED_V1: u8 = 6;
    const CHILD_SETUP_PRIVILEGE_FAILED_V1: u8 = 7;
    const CHILD_SETUP_STDIO_FAILED_V1: u8 = 8;
    const CHILD_SETUP_EXEC_FAILED_V1: u8 = 9;

    pub(super) fn monotonic_nanoseconds_v1() -> Result<u64, LinuxVzPackageProcessSupervisorErrorV1>
    {
        let mut value = MaybeUninit::<libc::timespec>::uninit();
        if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline);
        }
        let value = unsafe { value.assume_init() };
        if value.tv_sec < 0 || value.tv_nsec < 0 {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline);
        }
        (value.tv_sec as u64)
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(value.tv_nsec as u64))
            .ok_or(LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline)
    }

    pub(super) fn supervise_v1(
        contract: &LinuxVzPackageProcessLaunchContractV1,
        measured: &mut MeasuredLinuxVzPackageProcessV1,
        scenario_clock: &LinuxVzPackageScenarioClockV1,
        authority: &mut LinuxVzPackageExecutionAttemptAuthorityV1,
        observer: &mut dyn LinuxVzPackageProtectedProcessObserverV1,
    ) -> Result<LinuxVzPackageObservedProcessEvidenceV1, LinuxVzPackageProcessSupervisorErrorV1>
    {
        authority.burn_process_action_v1(contract)?;
        require_supervisor_boundary_v1()?;
        if contract.launch_authority_present()
            || contract.sync_back_permitted()
            || authority.sync_back_permitted()
            || scenario_clock.process_plan_sha256 != *contract.process_plan_sha256()
        {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidContract);
        }
        let now = monotonic_nanoseconds_v1()?;
        if now >= scenario_clock.deadline_monotonic_nanoseconds {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline);
        }
        let preexec_measurement = measured
            .verify_immediate_preexec()
            .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::ProcessMeasurementFailed)?;
        let preexec_measurement_sha256 = canonical_measurement_sha256_v1(&preexec_measurement)?;
        let prepared = PreparedChildInputsV1::new(contract)?;
        let mut cgroup = ProcessCgroupV1::create(contract)?;
        let sensor_session_challenge_sha256 = observer.sensor_session_challenge_sha256_v1().clone();
        if sensor_session_challenge_sha256 == Sha256Digest::from_bytes(&[]) {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorUnavailable);
        }
        observer.arm_v1(contract, &cgroup.name, cgroup.directory.as_raw_fd())?;

        let result = (|| {
            let mut pipes = ProcessPipesV1::create()?;

            let started = monotonic_nanoseconds_v1()?;
            if started >= scenario_clock.deadline_monotonic_nanoseconds {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline);
            }
            let parent_pid = unsafe { libc::getpid() };
            let leader_parent_pid = u32::try_from(parent_pid)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::ForkFailed)?;
            if leader_parent_pid <= 1 {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::ForkFailed);
            }
            let child = unsafe { libc::fork() };
            if child < 0 {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::ForkFailed);
            }
            if child == 0 {
                child_exec_v1(contract, measured, &prepared, &mut pipes, parent_pid);
            }
            let leader_pid = u32::try_from(child)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::ForkFailed)?;
            pipes.parent_after_fork_v1()?;

            if cgroup.add_pid_v1(leader_pid).is_err() {
                let _ = cgroup.kill_all_v1();
                let _ = reap_until_no_children_v1(
                    monotonic_nanoseconds_v1()?.saturating_add(
                        contract.limits().teardown_deadline_milliseconds() * 1_000_000,
                    ),
                    Some(child),
                    None,
                );
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupMembershipFailed);
            }
            if observer
                .leader_attached_v1(contract, &cgroup.name, leader_pid)
                .is_err()
            {
                let _ = cgroup.kill_all_v1();
                let _ = reap_until_no_children_v1(
                    monotonic_nanoseconds_v1()?.saturating_add(
                        contract.limits().teardown_deadline_milliseconds() * 1_000_000,
                    ),
                    Some(child),
                    None,
                );
                return Err(
                    LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorCorrelationFailed,
                );
            }
            if pipes.release_child_v1().is_err() {
                let _ = cgroup.kill_all_v1();
                let _ = reap_until_no_children_v1(
                    monotonic_nanoseconds_v1()?.saturating_add(
                        contract.limits().teardown_deadline_milliseconds() * 1_000_000,
                    ),
                    Some(child),
                    None,
                );
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupMembershipFailed);
            }

            let mut stdout = BoundedOutputV1::new(contract.limits().stdout_capture_bytes())?;
            let mut stderr = BoundedOutputV1::new(contract.limits().stderr_capture_bytes())?;
            let mut leader_status = None;
            let mut reaped_process_count = 0_u32;
            let mut deadline_reached = false;
            let mut background_descendants_observed = false;
            let mut term_signal_count = 0_u32;
            let mut cgroup_kill_used = false;

            loop {
                pipes.drain_outputs_v1(&mut stdout, &mut stderr)?;
                let reaped = reap_available_v1(Some(child), &mut leader_status)?;
                reaped_process_count = reaped_process_count
                    .checked_add(reaped)
                    .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                let populated = cgroup.populated_v1()?;
                let current = monotonic_nanoseconds_v1()?;
                if leader_status.is_some() {
                    if !populated {
                        break;
                    }
                    background_descendants_observed = true;
                    term_signal_count = term_signal_count
                        .checked_add(cgroup.signal_all_v1(libc::SIGTERM)?)
                        .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                    break;
                }
                if current >= scenario_clock.deadline_monotonic_nanoseconds {
                    deadline_reached = true;
                    term_signal_count = term_signal_count
                        .checked_add(cgroup.signal_all_v1(libc::SIGTERM)?)
                        .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                    break;
                }
                pipes.poll_v1(25)?;
            }

            if cgroup.populated_v1()? {
                let term_deadline = monotonic_nanoseconds_v1()?.saturating_add(
                    contract
                        .limits()
                        .term_grace_milliseconds()
                        .saturating_mul(1_000_000),
                );
                while monotonic_nanoseconds_v1()? < term_deadline {
                    pipes.drain_outputs_v1(&mut stdout, &mut stderr)?;
                    let reaped = reap_available_v1(Some(child), &mut leader_status)?;
                    reaped_process_count = reaped_process_count
                        .checked_add(reaped)
                        .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                    if !cgroup.populated_v1()? {
                        break;
                    }
                    pipes.poll_v1(10)?;
                }
            }
            if cgroup.populated_v1()? {
                cgroup.kill_all_v1()?;
                cgroup_kill_used = true;
            }

            let teardown_deadline = monotonic_nanoseconds_v1()?.saturating_add(
                contract
                    .limits()
                    .teardown_deadline_milliseconds()
                    .saturating_mul(1_000_000),
            );
            let (additional_reaped, observed_leader_status) =
                reap_until_no_children_v1(teardown_deadline, Some(child), leader_status)?;
            reaped_process_count = reaped_process_count
                .checked_add(additional_reaped)
                .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
            leader_status = observed_leader_status;
            while cgroup.populated_v1()? && monotonic_nanoseconds_v1()? < teardown_deadline {
                pipes.drain_outputs_v1(&mut stdout, &mut stderr)?;
                let reaped = reap_available_v1(Some(child), &mut leader_status)?;
                reaped_process_count = reaped_process_count
                    .checked_add(reaped)
                    .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                pipes.poll_v1(10)?;
            }
            if cgroup.populated_v1()? {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::TeardownFailed);
            }
            pipes.drain_to_eof_v1(&mut stdout, &mut stderr, teardown_deadline)?;
            let child_setup_clean = pipes.child_setup_clean_v1()?;
            if !child_setup_clean {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::ChildSetupFailed);
            }
            let leader_status =
                leader_status.ok_or(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed)?;
            let (terminal, exit_status, termination_signal) = decode_wait_status_v1(leader_status)?;
            let ended = monotonic_nanoseconds_v1()?;
            let completion = LinuxVzPackageProcessCompletionV1::from_parts_v1(
                started,
                ended,
                terminal,
                exit_status,
                termination_signal,
            )?;
            let launch_identity = LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(contract)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::InvalidContract)?;
            let cgroup_name = cgroup.name.clone();
            let protected_sensor_result = observer
                .finish_v1(contract, &cgroup_name, leader_pid, &completion)
                .and_then(|output| {
                    let correlation = decode_linux_vz_package_process_sensor_correlation_v1(
                        &output.correlation,
                        LinuxVzPackageExpectedProcessSensorCorrelationV1 {
                            sensor_session_challenge_sha256: &sensor_session_challenge_sha256,
                            contract,
                            cgroup_name: &cgroup_name,
                            leader_pid,
                            leader_parent_pid,
                            launch_identity,
                            completion,
                        },
                    )
                    .map_err(|_| {
                        LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorCorrelationFailed
                    })?;
                    validate_linux_vz_package_protected_sensor_payloads_v1(
                        &correlation,
                        &output.process_evidence,
                        &output.file_evidence,
                        &output.network_evidence,
                    )
                    .map_err(|_| {
                        LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorCorrelationFailed
                    })?;
                    let payloads = decode_linux_vz_package_protected_sensor_payload_set_v1(
                        &correlation,
                        &output.process_evidence,
                        &output.file_evidence,
                        &output.network_evidence,
                    )
                    .map_err(|_| {
                        LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorCorrelationFailed
                    })?;
                    Ok((correlation, payloads))
                });
            cgroup.remove_v1()?;
            let (protected_sensor, protected_sensor_payloads) = protected_sensor_result?;
            let postrun_measurement = measured
                .verify_postrun()
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::PostrunMeasurementFailed)?;
            let postrun_measurement_sha256 = canonical_measurement_sha256_v1(&postrun_measurement)?;
            let (stdout_observation, stdout_bytes) = stdout.finish_v1();
            let (stderr_observation, stderr_bytes) = stderr.finish_v1();

            let wire = PackageProcessSupervisorEvidenceWireV1 {
                schema_version: LINUX_VZ_PACKAGE_PROCESS_SUPERVISOR_EVIDENCE_SCHEMA_V1,
                execution_grant_sha256: authority.execution_grant_sha256(),
                attempt_binding_sha256: authority.attempt_binding_sha256(),
                launch_contract_sha256: contract.launch_contract_sha256(),
                process_plan_sha256: contract.process_plan_sha256(),
                action_index: contract.action_index().to_string(),
                stage_name: contract.stage_name(),
                preexec_measurement_sha256: &preexec_measurement_sha256,
                postrun_measurement_sha256: &postrun_measurement_sha256,
                protected_sensor_correlation_sha256: protected_sensor.correlation_sha256(),
                protected_sensor_payload_set_sha256: protected_sensor_payloads.payload_set_sha256(),
                cgroup_name: &cgroup_name,
                cgroup_version: "v2",
                leader_pid: leader_pid.to_string(),
                package_uid: PACKAGE_UID_V1.to_string(),
                package_gid: PACKAGE_GID_V1.to_string(),
                no_supplementary_groups: true,
                no_new_privileges: true,
                subreaper_enabled: true,
                terminal,
                exit_status: exit_status.map(|value| value.to_string()),
                termination_signal: termination_signal.map(|value| value.to_string()),
                started_monotonic_nanoseconds: started.to_string(),
                ended_monotonic_nanoseconds: ended.to_string(),
                deadline_monotonic_nanoseconds: scenario_clock
                    .deadline_monotonic_nanoseconds
                    .to_string(),
                deadline_reached,
                term_signal_count: term_signal_count.to_string(),
                cgroup_kill_used,
                background_descendants_observed,
                reaped_process_count: reaped_process_count.to_string(),
                stdout: &stdout_observation,
                stderr: &stderr_observation,
                child_setup_channel_clean: true,
                cgroup_empty_after_reap: true,
                cgroup_removed: true,
                descendant_teardown_complete: true,
                public_network_route_present: false,
                sync_back: false,
            };
            let canonical_json = serde_json_canonicalizer::to_vec(&wire)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::Serialization)?;
            if canonical_json.is_empty()
                || canonical_json.len() > MAX_LINUX_VZ_PACKAGE_PROCESS_SUPERVISOR_EVIDENCE_BYTES_V1
            {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded);
            }
            let supervisor = LinuxVzPackageProcessSupervisorEvidenceV1 {
                evidence_sha256: Sha256Digest::from_bytes(&canonical_json),
                canonical_json,
                execution_grant_sha256: authority.execution_grant_sha256().clone(),
                attempt_binding_sha256: authority.attempt_binding_sha256().clone(),
                launch_contract_sha256: contract.launch_contract_sha256().clone(),
                process_plan_sha256: contract.process_plan_sha256().clone(),
                action_index: contract.action_index(),
                stage_name: contract.stage_name().to_string(),
                preexec_measurement,
                postrun_measurement,
                protected_sensor_correlation_sha256: protected_sensor.correlation_sha256().clone(),
                protected_sensor_payload_set_sha256: protected_sensor_payloads
                    .payload_set_sha256()
                    .clone(),
                cgroup_name,
                leader_pid,
                terminal,
                exit_status,
                termination_signal,
                started_monotonic_nanoseconds: started,
                ended_monotonic_nanoseconds: ended,
                deadline_monotonic_nanoseconds: scenario_clock.deadline_monotonic_nanoseconds,
                deadline_reached,
                term_signal_count,
                cgroup_kill_used,
                background_descendants_observed,
                reaped_process_count,
                stdout_observation,
                stderr_observation,
                stdout: stdout_bytes,
                stderr: stderr_bytes,
            };
            Ok(LinuxVzPackageObservedProcessEvidenceV1 {
                supervisor,
                protected_sensor,
                protected_sensor_payloads,
            })
        })();
        match result {
            Ok(evidence) => Ok(evidence),
            Err(error) => match observer.abort_v1() {
                Ok(()) => Err(error),
                Err(_) => {
                    Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorTeardownFailed)
                }
            },
        }
    }

    fn require_supervisor_boundary_v1() -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        if unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0
            || unsafe { libc::getegid() } != 0
            || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } != 0
        {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::PrivilegeBoundary);
        }
        Ok(())
    }

    struct PreparedChildInputsV1 {
        argv: Vec<CString>,
        argv_pointers: Vec<*const libc::c_char>,
        environment: Vec<CString>,
        environment_pointers: Vec<*const libc::c_char>,
    }

    impl PreparedChildInputsV1 {
        fn new(
            contract: &LinuxVzPackageProcessLaunchContractV1,
        ) -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
            let argv = contract
                .argv()
                .iter()
                .map(|value| CString::new(value.as_str()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::InvalidContract)?;
            let environment = contract
                .environment()
                .iter()
                .map(|(key, value)| CString::new(format!("{key}={value}")))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::InvalidContract)?;
            let mut argv_pointers = argv.iter().map(|value| value.as_ptr()).collect::<Vec<_>>();
            argv_pointers.push(ptr::null());
            let mut environment_pointers = environment
                .iter()
                .map(|value| value.as_ptr())
                .collect::<Vec<_>>();
            environment_pointers.push(ptr::null());
            Ok(Self {
                argv,
                argv_pointers,
                environment,
                environment_pointers,
            })
        }
    }

    struct ProcessPipesV1 {
        stdout_read: File,
        stdout_write: Option<File>,
        stderr_read: File,
        stderr_write: Option<File>,
        sync_read: Option<File>,
        sync_write: Option<File>,
        setup_read: File,
        setup_write: Option<File>,
        stdout_eof: bool,
        stderr_eof: bool,
    }

    impl ProcessPipesV1 {
        fn create() -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
            let (stdout_read, stdout_write) = pipe_v1()?;
            let (stderr_read, stderr_write) = pipe_v1()?;
            let (sync_read, sync_write) = pipe_v1()?;
            let (setup_read, setup_write) = pipe_v1()?;
            set_nonblocking_v1(stdout_read.as_raw_fd())?;
            set_nonblocking_v1(stderr_read.as_raw_fd())?;
            set_nonblocking_v1(setup_read.as_raw_fd())?;
            Ok(Self {
                stdout_read,
                stdout_write: Some(stdout_write),
                stderr_read,
                stderr_write: Some(stderr_write),
                sync_read: Some(sync_read),
                sync_write: Some(sync_write),
                setup_read,
                setup_write: Some(setup_write),
                stdout_eof: false,
                stderr_eof: false,
            })
        }

        fn parent_after_fork_v1(&mut self) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            self.stdout_write.take();
            self.stderr_write.take();
            self.sync_read.take();
            self.setup_write.take();
            Ok(())
        }

        fn release_child_v1(&mut self) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            let Some(sync_write) = self.sync_write.take() else {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::PipeFailed);
            };
            write_all_fd_v1(sync_write.as_raw_fd(), &[1])
        }

        fn poll_v1(
            &self,
            timeout_milliseconds: i32,
        ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            let mut descriptors = [
                libc::pollfd {
                    fd: self.stdout_read.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.stderr_read.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
                libc::pollfd {
                    fd: self.setup_read.as_raw_fd(),
                    events: libc::POLLIN | libc::POLLHUP,
                    revents: 0,
                },
            ];
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    timeout_milliseconds,
                )
            };
            if result < 0 && last_errno_v1() != libc::EINTR {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::OutputFailed);
            }
            Ok(())
        }

        fn drain_outputs_v1(
            &mut self,
            stdout: &mut BoundedOutputV1,
            stderr: &mut BoundedOutputV1,
        ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            if !self.stdout_eof {
                self.stdout_eof = stdout.drain_fd_v1(self.stdout_read.as_raw_fd())?;
            }
            if !self.stderr_eof {
                self.stderr_eof = stderr.drain_fd_v1(self.stderr_read.as_raw_fd())?;
            }
            Ok(())
        }

        fn drain_to_eof_v1(
            &mut self,
            stdout: &mut BoundedOutputV1,
            stderr: &mut BoundedOutputV1,
            deadline: u64,
        ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            while (!self.stdout_eof || !self.stderr_eof) && monotonic_nanoseconds_v1()? < deadline {
                self.drain_outputs_v1(stdout, stderr)?;
                if !self.stdout_eof || !self.stderr_eof {
                    self.poll_v1(10)?;
                }
            }
            if !self.stdout_eof || !self.stderr_eof {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::OutputFailed);
            }
            Ok(())
        }

        fn child_setup_clean_v1(&mut self) -> Result<bool, LinuxVzPackageProcessSupervisorErrorV1> {
            let mut bytes = Vec::new();
            self.setup_read
                .read_to_end(&mut bytes)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::PipeFailed)?;
            Ok(bytes.is_empty())
        }
    }

    fn child_exec_v1(
        contract: &LinuxVzPackageProcessLaunchContractV1,
        measured: &MeasuredLinuxVzPackageProcessV1,
        prepared: &PreparedChildInputsV1,
        pipes: &mut ProcessPipesV1,
        parent_pid: libc::pid_t,
    ) -> ! {
        let setup_fd = pipes
            .setup_write
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .unwrap_or(-1);
        let fail = |code: u8| -> ! {
            if setup_fd >= 0 {
                let _ = unsafe { libc::write(setup_fd, (&code as *const u8).cast(), 1) };
            }
            unsafe { libc::_exit(126) }
        };
        let _ = unsafe { libc::close(pipes.stdout_read.as_raw_fd()) };
        let _ = unsafe { libc::close(pipes.stderr_read.as_raw_fd()) };
        let _ = unsafe { libc::close(pipes.setup_read.as_raw_fd()) };
        pipes.sync_write.take();
        if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0
            || unsafe { libc::getppid() } != parent_pid
        {
            fail(CHILD_SETUP_PDEATHSIG_FAILED_V1);
        }
        if unsafe { libc::setsid() } < 0 {
            fail(CHILD_SETUP_SESSION_FAILED_V1);
        }
        if unsafe { libc::fchdir(measured.current_directory_fd_v1()) } != 0 {
            fail(CHILD_SETUP_DIRECTORY_FAILED_V1);
        }
        if set_child_limits_v1(contract).is_err() {
            fail(CHILD_SETUP_RLIMIT_FAILED_V1);
        }
        let Some(sync_read) = pipes.sync_read.as_ref() else {
            fail(CHILD_SETUP_SYNC_FAILED_V1);
        };
        let mut token = 0_u8;
        if read_exact_fd_v1(sync_read.as_raw_fd(), std::slice::from_mut(&mut token)).is_err()
            || token != 1
        {
            fail(CHILD_SETUP_SYNC_FAILED_V1);
        }
        pipes.sync_read.take();
        if unsafe { libc::setgroups(0, ptr::null()) } != 0
            || unsafe { libc::setresgid(PACKAGE_GID_V1, PACKAGE_GID_V1, PACKAGE_GID_V1) } != 0
            || unsafe { libc::setresuid(PACKAGE_UID_V1, PACKAGE_UID_V1, PACKAGE_UID_V1) } != 0
        {
            fail(CHILD_SETUP_CREDENTIAL_FAILED_V1);
        }
        if unsafe {
            libc::prctl(
                libc::PR_CAP_AMBIENT,
                libc::PR_CAP_AMBIENT_CLEAR_ALL,
                0,
                0,
                0,
            )
        } != 0
            || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
            || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        {
            fail(CHILD_SETUP_PRIVILEGE_FAILED_V1);
        }
        let null_path = b"/dev/null\0";
        let null_fd =
            unsafe { libc::open(null_path.as_ptr().cast(), libc::O_RDONLY | libc::O_CLOEXEC) };
        let stdout_fd = pipes
            .stdout_write
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .unwrap_or(-1);
        let stderr_fd = pipes
            .stderr_write
            .as_ref()
            .map(AsRawFd::as_raw_fd)
            .unwrap_or(-1);
        if null_fd < 0
            || stdout_fd < 0
            || stderr_fd < 0
            || unsafe { libc::dup2(null_fd, libc::STDIN_FILENO) } < 0
            || unsafe { libc::dup2(stdout_fd, libc::STDOUT_FILENO) } < 0
            || unsafe { libc::dup2(stderr_fd, libc::STDERR_FILENO) } < 0
        {
            fail(CHILD_SETUP_STDIO_FAILED_V1);
        }
        let exec_fd = unsafe { libc::fcntl(measured.executable_fd_v1(), libc::F_DUPFD, 20) };
        if exec_fd < 0 {
            fail(CHILD_SETUP_EXEC_FAILED_V1);
        }
        let empty = b"\0";
        let _keepalive = (&prepared.argv, &prepared.environment);
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                exec_fd,
                empty.as_ptr().cast::<libc::c_char>(),
                prepared.argv_pointers.as_ptr(),
                prepared.environment_pointers.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        fail(CHILD_SETUP_EXEC_FAILED_V1)
    }

    fn set_child_limits_v1(
        contract: &LinuxVzPackageProcessLaunchContractV1,
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        let limits = contract.limits();
        set_rlimit_v1(libc::RLIMIT_CORE, limits.rlimit_core_bytes())?;
        set_rlimit_v1(libc::RLIMIT_CPU, limits.rlimit_cpu_seconds())?;
        set_rlimit_v1(libc::RLIMIT_FSIZE, limits.rlimit_file_size_bytes())?;
        set_rlimit_v1(libc::RLIMIT_AS, limits.rlimit_address_space_bytes())?;
        set_rlimit_v1(libc::RLIMIT_NOFILE, u64::from(limits.rlimit_open_files()))?;
        set_rlimit_v1(libc::RLIMIT_NPROC, u64::from(limits.rlimit_processes()))?;
        Ok(())
    }

    #[cfg(target_env = "gnu")]
    type RlimitResourceV1 = libc::__rlimit_resource_t;
    #[cfg(not(target_env = "gnu"))]
    type RlimitResourceV1 = libc::c_int;

    fn set_rlimit_v1(
        resource: RlimitResourceV1,
        value: u64,
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        let value = libc::rlim_t::try_from(value)
            .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::InvalidContract)?;
        let limit = libc::rlimit {
            rlim_cur: value,
            rlim_max: value,
        };
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::ChildSetupFailed);
        }
        Ok(())
    }

    struct ProcessCgroupV1 {
        root: File,
        directory: File,
        name: String,
        removed: bool,
    }

    impl ProcessCgroupV1 {
        fn create(
            contract: &LinuxVzPackageProcessLaunchContractV1,
        ) -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
            let root_path = CString::new(CGROUP_ROOT_V1).expect("fixed cgroup root");
            let root_fd = unsafe {
                libc::open(
                    root_path.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if root_fd < 0 {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupUnavailable);
            }
            let root = unsafe { File::from_raw_fd(root_fd) };
            let metadata = root
                .metadata()
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::CgroupUnavailable)?;
            let mut statfs = MaybeUninit::<libc::statfs>::uninit();
            if !metadata.file_type().is_dir()
                || metadata.uid() != 0
                || metadata.gid() != 0
                || unsafe { libc::fstatfs(root.as_raw_fd(), statfs.as_mut_ptr()) } != 0
                || unsafe { statfs.assume_init() }.f_type as i64 != CGROUP2_SUPER_MAGIC_V1
            {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupUnavailable);
            }
            let name = format!("whoathere-package-action-{}", contract.action_index());
            let name_c = CString::new(name.as_str())
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::CgroupCreateFailed)?;
            if unsafe { libc::mkdirat(root.as_raw_fd(), name_c.as_ptr(), 0o700) } != 0 {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupCreateFailed);
            }
            let directory_fd = unsafe {
                libc::openat(
                    root.as_raw_fd(),
                    name_c.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if directory_fd < 0 {
                let _ = unsafe {
                    libc::unlinkat(root.as_raw_fd(), name_c.as_ptr(), libc::AT_REMOVEDIR)
                };
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupCreateFailed);
            }
            let directory = unsafe { File::from_raw_fd(directory_fd) };
            let mut value = Self {
                root,
                directory,
                name,
                removed: false,
            };
            value.configure_v1(contract)?;
            Ok(value)
        }

        fn configure_v1(
            &mut self,
            contract: &LinuxVzPackageProcessLaunchContractV1,
        ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            let cgroup_type = self.read_control_v1("cgroup.type", 128)?;
            if cgroup_type != b"domain\n" {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed);
            }
            self.write_control_v1(
                "pids.max",
                contract.limits().cgroup_pids_max().to_string().as_bytes(),
            )?;
            self.write_control_v1(
                "memory.max",
                contract
                    .limits()
                    .cgroup_memory_max_bytes()
                    .to_string()
                    .as_bytes(),
            )?;
            self.write_control_v1(
                "memory.swap.max",
                contract
                    .limits()
                    .cgroup_swap_max_bytes()
                    .to_string()
                    .as_bytes(),
            )?;
            self.write_control_v1("memory.oom.group", b"1")?;
            self.write_control_v1("cpu.max", b"100000 100000")?;
            if self.populated_v1()? {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed);
            }
            Ok(())
        }

        fn add_pid_v1(&mut self, pid: u32) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            self.write_control_v1("cgroup.procs", pid.to_string().as_bytes())?;
            let members = self.read_pids_v1()?;
            if members != [pid] {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupMembershipFailed);
            }
            Ok(())
        }

        fn signal_all_v1(
            &mut self,
            signal: i32,
        ) -> Result<u32, LinuxVzPackageProcessSupervisorErrorV1> {
            let mut total = 0_u32;
            for pid in self.read_pids_v1()? {
                let result = unsafe { libc::kill(pid as libc::pid_t, signal) };
                if result == 0 {
                    total = total
                        .checked_add(1)
                        .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                } else if last_errno_v1() != libc::ESRCH {
                    return Err(LinuxVzPackageProcessSupervisorErrorV1::TeardownFailed);
                }
            }
            Ok(total)
        }

        fn kill_all_v1(&mut self) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            self.write_control_v1("cgroup.kill", b"1")
        }

        fn populated_v1(&self) -> Result<bool, LinuxVzPackageProcessSupervisorErrorV1> {
            let events = self.read_control_v1("cgroup.events", 16 * 1024)?;
            let text = std::str::from_utf8(&events)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed)?;
            let mut populated = None;
            for line in text.lines() {
                if let Some(value) = line.strip_prefix("populated ") {
                    if populated.replace(value == "1").is_some() || (value != "0" && value != "1") {
                        return Err(
                            LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed,
                        );
                    }
                }
            }
            populated.ok_or(LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed)
        }

        fn read_pids_v1(&self) -> Result<Vec<u32>, LinuxVzPackageProcessSupervisorErrorV1> {
            let bytes = self.read_control_v1("cgroup.procs", 1024 * 1024)?;
            let text = std::str::from_utf8(&bytes)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed)?;
            let mut values = Vec::new();
            for line in text.lines() {
                let value = line.parse::<u32>().map_err(|_| {
                    LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed
                })?;
                if value <= 1 || values.contains(&value) {
                    return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed);
                }
                values.push(value);
            }
            Ok(values)
        }

        fn write_control_v1(
            &self,
            name: &str,
            bytes: &[u8],
        ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            let name = CString::new(name)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed)?;
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed);
            }
            let file = unsafe { File::from_raw_fd(fd) };
            write_all_fd_v1(file.as_raw_fd(), bytes)
        }

        fn read_control_v1(
            &self,
            name: &str,
            maximum: usize,
        ) -> Result<Vec<u8>, LinuxVzPackageProcessSupervisorErrorV1> {
            let name = CString::new(name)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed)?;
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if fd < 0 {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed);
            }
            let file = unsafe { File::from_raw_fd(fd) };
            let mut bytes = Vec::new();
            file.take(maximum as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed)?;
            if bytes.len() > maximum {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded);
            }
            Ok(bytes)
        }

        fn remove_v1(&mut self) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
            if self.removed || self.populated_v1()? {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::TeardownFailed);
            }
            let name = CString::new(self.name.as_str())
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::TeardownFailed)?;
            if unsafe { libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) }
                != 0
            {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::TeardownFailed);
            }
            self.removed = true;
            Ok(())
        }
    }

    impl Drop for ProcessCgroupV1 {
        fn drop(&mut self) {
            if self.removed {
                return;
            }
            let _ = self.kill_all_v1();
            let deadline = monotonic_nanoseconds_v1()
                .unwrap_or(0)
                .saturating_add(5_000_000_000);
            loop {
                loop {
                    let mut status = 0_i32;
                    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
                    if pid <= 0 {
                        break;
                    }
                }
                if self.populated_v1().ok() == Some(false) {
                    if let Ok(name) = CString::new(self.name.as_str()) {
                        let _ = unsafe {
                            libc::unlinkat(self.root.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR)
                        };
                    }
                    break;
                }
                if monotonic_nanoseconds_v1().unwrap_or(u64::MAX) >= deadline {
                    break;
                }
                let pause = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 10_000_000,
                };
                let _ = unsafe { libc::nanosleep(&pause, ptr::null_mut()) };
            }
        }
    }

    struct BoundedOutputV1 {
        maximum: u64,
        captured: Vec<u8>,
        total: u64,
        hasher: Sha256,
    }

    impl BoundedOutputV1 {
        fn new(maximum: u64) -> Result<Self, LinuxVzPackageProcessSupervisorErrorV1> {
            let capacity = usize::try_from(maximum)
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
            Ok(Self {
                maximum,
                captured: Vec::with_capacity(capacity.min(64 * 1024)),
                total: 0,
                hasher: Sha256::new(),
            })
        }

        fn drain_fd_v1(
            &mut self,
            fd: RawFd,
        ) -> Result<bool, LinuxVzPackageProcessSupervisorErrorV1> {
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let count = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
                if count > 0 {
                    let count = count as usize;
                    self.total = self
                        .total
                        .checked_add(count as u64)
                        .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                    self.hasher.update(&buffer[..count]);
                    let remaining = self.maximum.saturating_sub(self.captured.len() as u64);
                    let retain = usize::try_from(remaining.min(count as u64))
                        .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                    self.captured.extend_from_slice(&buffer[..retain]);
                    continue;
                }
                if count == 0 {
                    return Ok(true);
                }
                let error = last_errno_v1();
                if error == libc::EINTR {
                    continue;
                }
                if error == libc::EAGAIN || error == libc::EWOULDBLOCK {
                    return Ok(false);
                }
                return Err(LinuxVzPackageProcessSupervisorErrorV1::OutputFailed);
            }
        }

        fn finish_v1(self) -> (LinuxVzPackageBoundedOutputObservationV1, Vec<u8>) {
            let digest = self.hasher.finalize();
            let observation = LinuxVzPackageBoundedOutputObservationV1 {
                total_byte_length: self.total.to_string(),
                captured_byte_length: self.captured.len().to_string(),
                sha256: digest_result_v1(&digest),
                truncated: self.total > self.captured.len() as u64,
            };
            (observation, self.captured)
        }
    }

    fn pipe_v1() -> Result<(File, File), LinuxVzPackageProcessSupervisorErrorV1> {
        let mut descriptors = [-1_i32; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::PipeFailed);
        }
        Ok(unsafe {
            (
                File::from_raw_fd(descriptors[0]),
                File::from_raw_fd(descriptors[1]),
            )
        })
    }

    fn set_nonblocking_v1(fd: RawFd) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } != 0 {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::PipeFailed);
        }
        Ok(())
    }

    fn write_all_fd_v1(
        fd: RawFd,
        bytes: &[u8],
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        let mut offset = 0;
        while offset < bytes.len() {
            let count =
                unsafe { libc::write(fd, bytes[offset..].as_ptr().cast(), bytes.len() - offset) };
            if count > 0 {
                offset += count as usize;
            } else if count < 0 && last_errno_v1() == libc::EINTR {
                continue;
            } else {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::PipeFailed);
            }
        }
        Ok(())
    }

    fn read_exact_fd_v1(
        fd: RawFd,
        bytes: &mut [u8],
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        let mut offset = 0;
        while offset < bytes.len() {
            let count = unsafe {
                libc::read(
                    fd,
                    bytes[offset..].as_mut_ptr().cast(),
                    bytes.len() - offset,
                )
            };
            if count > 0 {
                offset += count as usize;
            } else if count < 0 && last_errno_v1() == libc::EINTR {
                continue;
            } else {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::PipeFailed);
            }
        }
        Ok(())
    }

    fn reap_available_v1(
        leader: Option<libc::pid_t>,
        leader_status: &mut Option<i32>,
    ) -> Result<u32, LinuxVzPackageProcessSupervisorErrorV1> {
        let mut count = 0_u32;
        loop {
            let mut status = 0_i32;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid > 0 {
                count = count
                    .checked_add(1)
                    .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                if leader == Some(pid) && leader_status.replace(status).is_some() {
                    return Err(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed);
                }
                continue;
            }
            if pid == 0 || (pid < 0 && last_errno_v1() == libc::ECHILD) {
                return Ok(count);
            }
            if last_errno_v1() == libc::EINTR {
                continue;
            }
            return Err(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed);
        }
    }

    fn reap_until_no_children_v1(
        deadline: u64,
        leader: Option<libc::pid_t>,
        mut leader_status: Option<i32>,
    ) -> Result<(u32, Option<i32>), LinuxVzPackageProcessSupervisorErrorV1> {
        let mut count = 0_u32;
        loop {
            let mut status = 0_i32;
            let result = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if result < 0 && last_errno_v1() == libc::ECHILD {
                return Ok((count, leader_status));
            }
            if result > 0 {
                count = count
                    .checked_add(1)
                    .ok_or(LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded)?;
                if leader == Some(result) && leader_status.replace(status).is_some() {
                    return Err(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed);
                }
                continue;
            }
            if result < 0 && last_errno_v1() == libc::EINTR {
                continue;
            }
            if result < 0 {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed);
            }
            if monotonic_nanoseconds_v1()? >= deadline {
                return Err(LinuxVzPackageProcessSupervisorErrorV1::TeardownFailed);
            }
            let pause = libc::timespec {
                tv_sec: 0,
                tv_nsec: 10_000_000,
            };
            let _ = unsafe { libc::nanosleep(&pause, ptr::null_mut()) };
        }
    }

    fn decode_wait_status_v1(
        status: i32,
    ) -> Result<
        (LinuxVzPackageProcessTerminalV1, Option<u8>, Option<u8>),
        LinuxVzPackageProcessSupervisorErrorV1,
    > {
        if libc::WIFEXITED(status) {
            let value = u8::try_from(libc::WEXITSTATUS(status))
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::WaitFailed)?;
            Ok((LinuxVzPackageProcessTerminalV1::Exited, Some(value), None))
        } else if libc::WIFSIGNALED(status) {
            let value = u8::try_from(libc::WTERMSIG(status))
                .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::WaitFailed)?;
            Ok((LinuxVzPackageProcessTerminalV1::Signaled, None, Some(value)))
        } else {
            Err(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed)
        }
    }

    fn canonical_measurement_sha256_v1(
        observation: &LinuxVzPackageProcessMeasurementObservationV1,
    ) -> Result<Sha256Digest, LinuxVzPackageProcessSupervisorErrorV1> {
        let canonical = serde_json_canonicalizer::to_vec(observation)
            .map_err(|_| LinuxVzPackageProcessSupervisorErrorV1::Serialization)?;
        Ok(Sha256Digest::from_bytes(&canonical))
    }

    fn digest_result_v1(digest: &[u8]) -> Sha256Digest {
        assert_eq!(digest.len(), 32, "SHA-256 output length");
        let mut value = String::with_capacity(71);
        value.push_str("sha256:");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in digest {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Sha256Digest::parse(value).expect("lowercase SHA-256 digest")
    }

    fn last_errno_v1() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    }

    const _: () = assert!(size_of::<libc::pid_t>() <= size_of::<i32>());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_linux_vz_package_process_launch_contract_v1,
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        MacosLinuxVzNpmLifecyclePolicyV1, MacosLinuxVzPackageDependencyPolicyV1,
        MacosLinuxVzPackageExecutionStageV1, MacosLinuxVzPackageRuntimeExecutablesV1,
        ValidatedLinuxVzPackageDynamicProcessBindingsV1,
    };
    use whoathere_detonation::NpmEnvironmentProfileV1;

    fn test_process_plan_v1() -> MacosLinuxVzPackageExecutionProcessPlanV1 {
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
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("process plan")
    }

    #[test]
    fn supervisor_errors_have_stable_distinct_reason_codes() {
        let values = [
            LinuxVzPackageProcessSupervisorErrorV1::UnsupportedPlatform,
            LinuxVzPackageProcessSupervisorErrorV1::PrivilegeBoundary,
            LinuxVzPackageProcessSupervisorErrorV1::InvalidContract,
            LinuxVzPackageProcessSupervisorErrorV1::InvalidDeadline,
            LinuxVzPackageProcessSupervisorErrorV1::ProcessMeasurementFailed,
            LinuxVzPackageProcessSupervisorErrorV1::CgroupUnavailable,
            LinuxVzPackageProcessSupervisorErrorV1::CgroupCreateFailed,
            LinuxVzPackageProcessSupervisorErrorV1::CgroupConfigurationFailed,
            LinuxVzPackageProcessSupervisorErrorV1::PipeFailed,
            LinuxVzPackageProcessSupervisorErrorV1::ForkFailed,
            LinuxVzPackageProcessSupervisorErrorV1::CgroupMembershipFailed,
            LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorUnavailable,
            LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorCorrelationFailed,
            LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorTeardownFailed,
            LinuxVzPackageProcessSupervisorErrorV1::ChildSetupFailed,
            LinuxVzPackageProcessSupervisorErrorV1::WaitFailed,
            LinuxVzPackageProcessSupervisorErrorV1::OutputFailed,
            LinuxVzPackageProcessSupervisorErrorV1::TeardownFailed,
            LinuxVzPackageProcessSupervisorErrorV1::PostrunMeasurementFailed,
            LinuxVzPackageProcessSupervisorErrorV1::Serialization,
            LinuxVzPackageProcessSupervisorErrorV1::LimitExceeded,
        ];
        let reasons = values
            .iter()
            .map(|value| value.reason_code())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(reasons.len(), values.len());
    }

    #[test]
    fn supervisor_is_platform_closed_on_macos() {
        #[cfg(not(target_os = "linux"))]
        assert_eq!(
            LinuxVzPackageProcessSupervisorErrorV1::UnsupportedPlatform.reason_code(),
            "linux_vz_package_process_supervisor_platform_unsupported"
        );
    }

    #[test]
    fn process_completion_requires_one_exact_wait_terminal() {
        let exited = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            100,
            200,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("exited completion");
        assert_eq!(exited.exit_status(), Some(0));
        assert_eq!(exited.termination_signal(), None);

        let signaled = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            100,
            200,
            LinuxVzPackageProcessTerminalV1::Signaled,
            None,
            Some(9),
        )
        .expect("signaled completion");
        assert_eq!(
            signaled.terminal(),
            LinuxVzPackageProcessTerminalV1::Signaled
        );

        for invalid in [
            LinuxVzPackageProcessCompletionV1::from_parts_v1(
                0,
                200,
                LinuxVzPackageProcessTerminalV1::Exited,
                Some(0),
                None,
            ),
            LinuxVzPackageProcessCompletionV1::from_parts_v1(
                200,
                200,
                LinuxVzPackageProcessTerminalV1::Exited,
                Some(0),
                None,
            ),
            LinuxVzPackageProcessCompletionV1::from_parts_v1(
                100,
                200,
                LinuxVzPackageProcessTerminalV1::Exited,
                None,
                Some(9),
            ),
            LinuxVzPackageProcessCompletionV1::from_parts_v1(
                100,
                200,
                LinuxVzPackageProcessTerminalV1::Signaled,
                None,
                Some(0),
            ),
            LinuxVzPackageProcessCompletionV1::from_parts_v1(
                100,
                200,
                LinuxVzPackageProcessTerminalV1::Signaled,
                None,
                Some(65),
            ),
        ] {
            assert_eq!(
                invalid,
                Err(LinuxVzPackageProcessSupervisorErrorV1::WaitFailed)
            );
        }
    }

    #[test]
    fn one_attempt_authority_burns_process_action_before_launch() {
        let plan = test_process_plan_v1();
        let contract = derive_linux_vz_package_process_launch_contract_v1(
            &plan,
            1,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("launch contract");
        let mut authority = LinuxVzPackageExecutionAttemptAuthorityV1::for_test_v1(&plan);
        assert_eq!(authority.burned_process_action_count(), 0);
        authority
            .burn_process_action_v1(&contract)
            .expect("first burn");
        assert_eq!(authority.burned_process_action_count(), 1);
        assert_eq!(
            authority.burn_process_action_v1(&contract),
            Err(LinuxVzPackageProcessSupervisorErrorV1::InvalidContract)
        );
        assert_eq!(authority.burned_process_action_count(), 1);
        assert!(!authority.sync_back_permitted());
    }
}
