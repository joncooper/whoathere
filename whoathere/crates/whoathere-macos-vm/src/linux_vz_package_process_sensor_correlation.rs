use crate::LinuxVzPackageProcessTerminalV1;
#[cfg(any(target_os = "linux", test))]
use crate::{
    LinuxVzPackageProcessCompletionV1, LinuxVzPackageProcessLaunchContractV1,
    LinuxVzPackageProcessLaunchIdentityV1,
};
#[cfg(any(target_os = "linux", test))]
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_process_sensor_correlation.v1";
pub const LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_process_sensor_correlation.v2";
pub const LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V3: &str =
    "whoathere.linux_vz_package_process_sensor_correlation.v3";
pub const LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V4: &str =
    "whoathere.linux_vz_package_process_sensor_correlation.v4";
pub const MAX_LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_BYTES_V1: usize = 64 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageProcessSensorCorrelationErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    BindingMismatch,
    InvalidHealth,
    InvalidCounts,
    InvalidTiming,
    PayloadDigestMismatch,
}

impl LinuxVzPackageProcessSensorCorrelationErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_process_sensor_correlation_empty",
            Self::LimitExceeded => "linux_vz_package_process_sensor_correlation_limit_exceeded",
            Self::InvalidJson => "linux_vz_package_process_sensor_correlation_json_invalid",
            Self::NonCanonical => "linux_vz_package_process_sensor_correlation_noncanonical",
            Self::BindingMismatch => "linux_vz_package_process_sensor_correlation_binding_mismatch",
            Self::InvalidHealth => "linux_vz_package_process_sensor_correlation_health_invalid",
            Self::InvalidCounts => "linux_vz_package_process_sensor_correlation_counts_invalid",
            Self::InvalidTiming => "linux_vz_package_process_sensor_correlation_timing_invalid",
            Self::PayloadDigestMismatch => {
                "linux_vz_package_process_sensor_payload_digest_mismatch"
            }
        }
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn validate_linux_vz_package_protected_sensor_payloads_v1(
    correlation: &LinuxVzPackageProcessSensorCorrelationV1,
    process_evidence: &[u8],
    file_evidence: &[u8],
    network_evidence: &[u8],
) -> Result<(), LinuxVzPackageProcessSensorCorrelationErrorV1> {
    if process_evidence.is_empty() || file_evidence.is_empty() || network_evidence.is_empty() {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::Empty);
    }
    if process_evidence.len() > MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1
        || file_evidence.len() > MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1
        || network_evidence.len() > MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1
    {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::LimitExceeded);
    }
    if correlation.process_evidence_sha256() != &Sha256Digest::from_bytes(process_evidence)
        || correlation.file_evidence_sha256() != &Sha256Digest::from_bytes(file_evidence)
        || correlation.network_evidence_sha256() != &Sha256Digest::from_bytes(network_evidence)
    {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::PayloadDigestMismatch);
    }
    Ok(())
}

impl fmt::Display for LinuxVzPackageProcessSensorCorrelationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageProcessSensorCorrelationErrorV1 {}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProcessSensorCorrelationWireV4 {
    schema_version: String,
    sensor_session_challenge_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    action_index: String,
    cgroup_name: String,
    cgroup_id: String,
    leader_pid: String,
    leader_parent_pid: String,
    leader_executable_sha256: Sha256Digest,
    leader_argv_sha256: Sha256Digest,
    leader_argv_item_count: String,
    leader_kernel_wait_status: String,
    leader_supervisor_wait_status: String,
    leader_terminal: LinuxVzPackageProcessTerminalV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leader_exit_status: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leader_termination_signal: Option<String>,
    package_uid: String,
    package_gid: String,
    sensor_started_monotonic_nanoseconds: String,
    process_started_monotonic_nanoseconds: String,
    process_ended_monotonic_nanoseconds: String,
    sensor_ended_monotonic_nanoseconds: String,
    event_sequence_start: String,
    event_sequence_end: String,
    event_count: String,
    process_event_count: String,
    file_event_count: String,
    network_event_count: String,
    heartbeat_count: String,
    dropped_event_count: String,
    process_evidence_sha256: Sha256Digest,
    file_evidence_sha256: Sha256Digest,
    network_evidence_sha256: Sha256Digest,
    process_sensor_healthy: bool,
    file_sensor_healthy: bool,
    network_sensor_healthy: bool,
    evidence_truncated: bool,
    leader_correlated_before_release: bool,
    cgroup_empty_after_reap: bool,
    cgroup_present_during_sensor_finalize: bool,
    descendant_teardown_complete: bool,
    sensor_teardown_complete: bool,
    public_network_route_present: bool,
    sync_back: bool,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
pub(crate) struct LinuxVzPackageExpectedProcessSensorCorrelationV1<'a> {
    pub(crate) sensor_session_challenge_sha256: &'a Sha256Digest,
    pub(crate) contract: &'a LinuxVzPackageProcessLaunchContractV1,
    pub(crate) cgroup_name: &'a str,
    pub(crate) leader_pid: u32,
    pub(crate) leader_parent_pid: u32,
    pub(crate) launch_identity: LinuxVzPackageProcessLaunchIdentityV1,
    pub(crate) completion: LinuxVzPackageProcessCompletionV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageProcessSensorCorrelationV1 {
    canonical_json: Vec<u8>,
    correlation_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    action_index: usize,
    cgroup_name: String,
    cgroup_id: u64,
    leader_pid: u32,
    leader_parent_pid: u32,
    leader_executable_sha256: Sha256Digest,
    leader_argv_sha256: Sha256Digest,
    leader_argv_item_count: usize,
    leader_kernel_wait_status: u16,
    leader_supervisor_wait_status: u16,
    leader_terminal: LinuxVzPackageProcessTerminalV1,
    leader_exit_status: Option<u8>,
    leader_termination_signal: Option<u8>,
    sensor_started_monotonic_nanoseconds: u64,
    process_started_monotonic_nanoseconds: u64,
    process_ended_monotonic_nanoseconds: u64,
    sensor_ended_monotonic_nanoseconds: u64,
    event_count: u64,
    process_event_count: u64,
    file_event_count: u64,
    network_event_count: u64,
    heartbeat_count: u64,
    process_evidence_sha256: Sha256Digest,
    file_evidence_sha256: Sha256Digest,
    network_evidence_sha256: Sha256Digest,
}

impl fmt::Debug for LinuxVzPackageProcessSensorCorrelationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageProcessSensorCorrelationV1")
            .field("correlation_sha256", &self.correlation_sha256)
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("launch_contract_sha256", &self.launch_contract_sha256)
            .field("action_index", &self.action_index)
            .field("cgroup_name", &self.cgroup_name)
            .field("cgroup_id", &self.cgroup_id)
            .field("leader_pid", &self.leader_pid)
            .field("leader_parent_pid", &self.leader_parent_pid)
            .field("leader_argv_item_count", &self.leader_argv_item_count)
            .field("leader_kernel_wait_status", &self.leader_kernel_wait_status)
            .field(
                "leader_supervisor_wait_status",
                &self.leader_supervisor_wait_status,
            )
            .field("event_count", &self.event_count)
            .finish()
    }
}

impl LinuxVzPackageProcessSensorCorrelationV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn correlation_sha256(&self) -> &Sha256Digest {
        &self.correlation_sha256
    }

    pub fn sensor_session_challenge_sha256(&self) -> &Sha256Digest {
        &self.sensor_session_challenge_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn launch_contract_sha256(&self) -> &Sha256Digest {
        &self.launch_contract_sha256
    }

    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    pub fn cgroup_name(&self) -> &str {
        &self.cgroup_name
    }

    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    pub const fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    pub const fn leader_parent_pid(&self) -> u32 {
        self.leader_parent_pid
    }

    pub fn leader_executable_sha256(&self) -> &Sha256Digest {
        &self.leader_executable_sha256
    }

    pub fn leader_argv_sha256(&self) -> &Sha256Digest {
        &self.leader_argv_sha256
    }

    pub const fn leader_argv_item_count(&self) -> usize {
        self.leader_argv_item_count
    }

    pub const fn leader_kernel_wait_status(&self) -> u16 {
        self.leader_kernel_wait_status
    }

    pub const fn leader_supervisor_wait_status(&self) -> u16 {
        self.leader_supervisor_wait_status
    }

    pub const fn leader_terminal(&self) -> LinuxVzPackageProcessTerminalV1 {
        self.leader_terminal
    }

    pub const fn leader_exit_status(&self) -> Option<u8> {
        self.leader_exit_status
    }

    pub const fn leader_termination_signal(&self) -> Option<u8> {
        self.leader_termination_signal
    }

    pub const fn sensor_started_monotonic_nanoseconds(&self) -> u64 {
        self.sensor_started_monotonic_nanoseconds
    }

    pub const fn process_started_monotonic_nanoseconds(&self) -> u64 {
        self.process_started_monotonic_nanoseconds
    }

    pub const fn process_ended_monotonic_nanoseconds(&self) -> u64 {
        self.process_ended_monotonic_nanoseconds
    }

    pub const fn sensor_ended_monotonic_nanoseconds(&self) -> u64 {
        self.sensor_ended_monotonic_nanoseconds
    }

    pub const fn event_count(&self) -> u64 {
        self.event_count
    }

    pub const fn process_event_count(&self) -> u64 {
        self.process_event_count
    }

    pub const fn file_event_count(&self) -> u64 {
        self.file_event_count
    }

    pub const fn network_event_count(&self) -> u64 {
        self.network_event_count
    }

    pub const fn heartbeat_count(&self) -> u64 {
        self.heartbeat_count
    }

    pub fn process_evidence_sha256(&self) -> &Sha256Digest {
        &self.process_evidence_sha256
    }

    pub fn file_evidence_sha256(&self) -> &Sha256Digest {
        &self.file_evidence_sha256
    }

    pub fn network_evidence_sha256(&self) -> &Sha256Digest {
        &self.network_evidence_sha256
    }

    pub const fn coverage_complete(&self) -> bool {
        true
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[cfg(any(target_os = "linux", test))]
pub(crate) fn decode_linux_vz_package_process_sensor_correlation_v1(
    bytes: &[u8],
    expected: LinuxVzPackageExpectedProcessSensorCorrelationV1<'_>,
) -> Result<LinuxVzPackageProcessSensorCorrelationV1, LinuxVzPackageProcessSensorCorrelationErrorV1>
{
    if bytes.is_empty() {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_BYTES_V1 {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = PackageProcessSensorCorrelationWireV4::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidJson)?;
    if canonical != bytes {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::NonCanonical);
    }

    let action_index = decimal_usize_v1(&wire.action_index)?;
    let cgroup_id = decimal_u64_v1(&wire.cgroup_id)?;
    let leader_pid = decimal_u32_v1(&wire.leader_pid)?;
    let leader_parent_pid = decimal_u32_v1(&wire.leader_parent_pid)?;
    let leader_argv_item_count = decimal_usize_v1(&wire.leader_argv_item_count)?;
    let leader_kernel_wait_status = decimal_u16_v1(&wire.leader_kernel_wait_status)?;
    let leader_supervisor_wait_status = decimal_u16_v1(&wire.leader_supervisor_wait_status)?;
    let leader_exit_status = optional_u8_v1(wire.leader_exit_status.as_deref(), true)?;
    let leader_termination_signal =
        optional_u8_v1(wire.leader_termination_signal.as_deref(), false)?;
    let package_uid = decimal_u32_v1(&wire.package_uid)?;
    let package_gid = decimal_u32_v1(&wire.package_gid)?;
    let sensor_started = decimal_u64_v1(&wire.sensor_started_monotonic_nanoseconds)?;
    let process_started = decimal_u64_v1(&wire.process_started_monotonic_nanoseconds)?;
    let process_ended = decimal_u64_v1(&wire.process_ended_monotonic_nanoseconds)?;
    let sensor_ended = decimal_u64_v1(&wire.sensor_ended_monotonic_nanoseconds)?;
    let event_sequence_start = decimal_u64_v1(&wire.event_sequence_start)?;
    let event_sequence_end = decimal_u64_v1(&wire.event_sequence_end)?;
    let event_count = decimal_u64_v1(&wire.event_count)?;
    let process_event_count = decimal_u64_v1(&wire.process_event_count)?;
    let file_event_count = decimal_u64_v1(&wire.file_event_count)?;
    let network_event_count = decimal_u64_v1(&wire.network_event_count)?;
    let heartbeat_count = decimal_u64_v1(&wire.heartbeat_count)?;
    let dropped_event_count = decimal_u64_v1(&wire.dropped_event_count)?;
    let expected_cgroup_name = format!(
        "whoathere-package-action-{}",
        expected.contract.action_index()
    );
    if wire.schema_version != LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V4
        || &wire.sensor_session_challenge_sha256 != expected.sensor_session_challenge_sha256
        || &wire.process_plan_sha256 != expected.contract.process_plan_sha256()
        || &wire.launch_contract_sha256 != expected.contract.launch_contract_sha256()
        || action_index != expected.contract.action_index()
        || wire.cgroup_name != expected.cgroup_name
        || wire.cgroup_name != expected_cgroup_name
        || leader_pid != expected.leader_pid
        || leader_parent_pid != expected.leader_parent_pid
        || wire.leader_executable_sha256 != *expected.launch_identity.executable_sha256()
        || wire.leader_argv_sha256 != *expected.launch_identity.argv_sha256()
        || leader_argv_item_count != expected.launch_identity.argv_item_count()
        || leader_supervisor_wait_status != expected.completion.supervisor_wait_status()
        || leader_kernel_wait_status != leader_supervisor_wait_status
        || process_started != expected.completion.process_started_monotonic_nanoseconds()
        || process_ended != expected.completion.process_ended_monotonic_nanoseconds()
        || wire.leader_terminal != expected.completion.terminal()
        || leader_exit_status != expected.completion.exit_status()
        || leader_termination_signal != expected.completion.termination_signal()
        || package_uid != 65_534
        || package_gid != 65_534
        || cgroup_id == 0
        || leader_pid <= 1
        || leader_parent_pid <= 1
        || leader_parent_pid == leader_pid
    {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch);
    }
    if !wire.process_sensor_healthy
        || !wire.file_sensor_healthy
        || !wire.network_sensor_healthy
        || wire.evidence_truncated
        || !wire.leader_correlated_before_release
        || !wire.cgroup_empty_after_reap
        || !wire.cgroup_present_during_sensor_finalize
        || !wire.descendant_teardown_complete
        || !wire.sensor_teardown_complete
        || wire.public_network_route_present
        || wire.sync_back
        || dropped_event_count != 0
        || heartbeat_count < 2
    {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidHealth);
    }
    let summed_event_count = process_event_count
        .checked_add(file_event_count)
        .and_then(|value| value.checked_add(network_event_count))
        .ok_or(LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts)?;
    let empty_digest = Sha256Digest::from_bytes(&[]);
    if process_event_count < 3
        || file_event_count < 1
        || event_count != summed_event_count
        || event_sequence_start != 1
        || event_sequence_end != event_count
        || event_count > 1_000_000
        || wire.process_evidence_sha256 == empty_digest
        || wire.file_evidence_sha256 == empty_digest
        || wire.network_evidence_sha256 == empty_digest
    {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts);
    }
    if sensor_started == 0
        || sensor_started > process_started
        || process_started >= process_ended
        || process_ended > sensor_ended
    {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidTiming);
    }
    Ok(LinuxVzPackageProcessSensorCorrelationV1 {
        correlation_sha256: Sha256Digest::from_bytes(&canonical),
        canonical_json: canonical,
        sensor_session_challenge_sha256: wire.sensor_session_challenge_sha256,
        process_plan_sha256: wire.process_plan_sha256,
        launch_contract_sha256: wire.launch_contract_sha256,
        action_index,
        cgroup_name: wire.cgroup_name,
        cgroup_id,
        leader_pid,
        leader_parent_pid,
        leader_executable_sha256: wire.leader_executable_sha256,
        leader_argv_sha256: wire.leader_argv_sha256,
        leader_argv_item_count,
        leader_kernel_wait_status,
        leader_supervisor_wait_status,
        leader_terminal: wire.leader_terminal,
        leader_exit_status,
        leader_termination_signal,
        sensor_started_monotonic_nanoseconds: sensor_started,
        process_started_monotonic_nanoseconds: process_started,
        process_ended_monotonic_nanoseconds: process_ended,
        sensor_ended_monotonic_nanoseconds: sensor_ended,
        event_count,
        process_event_count,
        file_event_count,
        network_event_count,
        heartbeat_count,
        process_evidence_sha256: wire.process_evidence_sha256,
        file_evidence_sha256: wire.file_evidence_sha256,
        network_evidence_sha256: wire.network_evidence_sha256,
    })
}

#[cfg(any(target_os = "linux", test))]
fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzPackageProcessSensorCorrelationErrorV1> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts)
}

#[cfg(any(target_os = "linux", test))]
fn decimal_u32_v1(value: &str) -> Result<u32, LinuxVzPackageProcessSensorCorrelationErrorV1> {
    let value = decimal_u64_v1(value)?;
    u32::try_from(value).map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts)
}

#[cfg(any(target_os = "linux", test))]
fn decimal_u16_v1(value: &str) -> Result<u16, LinuxVzPackageProcessSensorCorrelationErrorV1> {
    let value = decimal_u64_v1(value)?;
    u16::try_from(value).map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts)
}

#[cfg(any(target_os = "linux", test))]
fn optional_u8_v1(
    value: Option<&str>,
    allow_zero: bool,
) -> Result<Option<u8>, LinuxVzPackageProcessSensorCorrelationErrorV1> {
    value
        .map(|value| {
            let parsed = decimal_u64_v1(value)?;
            let parsed = u8::try_from(parsed)
                .map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch)?;
            if !allow_zero && !(1..=64).contains(&parsed) {
                return Err(LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch);
            }
            Ok(parsed)
        })
        .transpose()
}

#[cfg(any(target_os = "linux", test))]
fn decimal_usize_v1(value: &str) -> Result<usize, LinuxVzPackageProcessSensorCorrelationErrorV1> {
    let value = decimal_u64_v1(value)?;
    usize::try_from(value).map_err(|_| LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts)
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

    fn contract_v1() -> LinuxVzPackageProcessLaunchContractV1 {
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
        let plan = derive_macos_linux_vz_package_execution_process_plan_v1(&program)
            .expect("process plan");
        derive_linux_vz_package_process_launch_contract_v1(
            &plan,
            1,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("launch contract")
    }

    fn payload_v1(
        contract: &LinuxVzPackageProcessLaunchContractV1,
        challenge: &Sha256Digest,
    ) -> Vec<u8> {
        let launch_identity =
            LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(contract).expect("identity");
        let mut value = serde_json::json!({
            "action_index": contract.action_index().to_string(),
            "cgroup_empty_after_reap": true,
            "cgroup_id": "9001",
            "cgroup_name": "whoathere-package-action-1",
            "cgroup_present_during_sensor_finalize": true,
            "descendant_teardown_complete": true,
            "dropped_event_count": "0",
            "event_count": "4",
            "event_sequence_end": "4",
            "event_sequence_start": "1",
            "evidence_truncated": false,
            "file_event_count": "1",
            "file_evidence_sha256": Sha256Digest::from_bytes(b"empty file evidence payload"),
            "file_sensor_healthy": true,
            "heartbeat_count": "2",
            "launch_contract_sha256": contract.launch_contract_sha256(),
            "leader_correlated_before_release": true,
            "leader_exit_status": "0",
            "leader_kernel_wait_status": "0",
            "leader_pid": "42",
            "leader_supervisor_wait_status": "0",
            "leader_terminal": "exited",
            "network_event_count": "0",
            "network_evidence_sha256": Sha256Digest::from_bytes(b"empty network evidence payload"),
            "network_sensor_healthy": true,
            "package_gid": "65534",
            "package_uid": "65534",
            "process_ended_monotonic_nanoseconds": "300",
            "process_event_count": "3",
            "process_evidence_sha256": Sha256Digest::from_bytes(b"exec and exit evidence payload"),
            "process_plan_sha256": contract.process_plan_sha256(),
            "process_sensor_healthy": true,
            "process_started_monotonic_nanoseconds": "200",
            "public_network_route_present": false,
            "schema_version": LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V4,
            "sensor_ended_monotonic_nanoseconds": "400",
            "sensor_session_challenge_sha256": challenge,
            "sensor_started_monotonic_nanoseconds": "100",
            "sensor_teardown_complete": true,
            "sync_back": false
        });
        value["leader_argv_item_count"] =
            serde_json::json!(launch_identity.argv_item_count().to_string());
        value["leader_argv_sha256"] = serde_json::json!(launch_identity.argv_sha256());
        value["leader_executable_sha256"] = serde_json::json!(launch_identity.executable_sha256());
        value["leader_parent_pid"] = serde_json::json!("40");
        serde_json_canonicalizer::to_vec(&value).expect("payload")
    }

    fn expected_v1<'a>(
        contract: &'a LinuxVzPackageProcessLaunchContractV1,
        challenge: &'a Sha256Digest,
    ) -> LinuxVzPackageExpectedProcessSensorCorrelationV1<'a> {
        LinuxVzPackageExpectedProcessSensorCorrelationV1 {
            sensor_session_challenge_sha256: challenge,
            contract,
            cgroup_name: "whoathere-package-action-1",
            leader_pid: 42,
            leader_parent_pid: 40,
            launch_identity: LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(contract)
                .expect("identity"),
            completion: LinuxVzPackageProcessCompletionV1::from_parts_v1(
                200,
                300,
                0,
                LinuxVzPackageProcessTerminalV1::Exited,
                Some(0),
                None,
            )
            .expect("completion"),
        }
    }

    #[test]
    fn complete_cgroup_bound_sensor_correlation_is_accepted() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh sensor session challenge");
        let payload = payload_v1(&contract, &challenge);
        let observed = decode_linux_vz_package_process_sensor_correlation_v1(
            &payload,
            expected_v1(&contract, &challenge),
        )
        .expect("correlation");
        assert_eq!(observed.leader_pid(), 42);
        assert_eq!(observed.leader_parent_pid(), 40);
        let launch_identity =
            LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(&contract).expect("identity");
        assert_eq!(
            observed.leader_executable_sha256(),
            launch_identity.executable_sha256()
        );
        assert_eq!(observed.leader_argv_sha256(), launch_identity.argv_sha256());
        assert_eq!(
            observed.leader_argv_item_count(),
            launch_identity.argv_item_count()
        );
        assert_eq!(
            observed.leader_terminal(),
            LinuxVzPackageProcessTerminalV1::Exited
        );
        assert_eq!(observed.leader_exit_status(), Some(0));
        assert_eq!(observed.leader_termination_signal(), None);
        assert_eq!(observed.leader_supervisor_wait_status(), 0);
        assert_eq!(observed.leader_kernel_wait_status(), 0);
        assert_eq!(observed.cgroup_id(), 9001);
        assert_eq!(observed.process_event_count(), 3);
        assert_eq!(observed.file_event_count(), 1);
        assert!(observed.coverage_complete());
        assert!(!observed.sync_back_permitted());
        assert_eq!(
            observed.correlation_sha256(),
            &Sha256Digest::from_bytes(observed.canonical_json_v1())
        );
    }

    #[test]
    fn core_dump_completion_preserves_exact_kernel_and_supervisor_status() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh signaled sensor session");
        let mut value: serde_json::Value =
            serde_json::from_slice(&payload_v1(&contract, &challenge)).expect("JSON");
        value
            .as_object_mut()
            .expect("correlation object")
            .remove("leader_exit_status");
        value["leader_terminal"] = serde_json::json!("signaled");
        value["leader_termination_signal"] = serde_json::json!("11");
        value["leader_kernel_wait_status"] = serde_json::json!("139");
        value["leader_supervisor_wait_status"] = serde_json::json!("139");
        let payload = serde_json_canonicalizer::to_vec(&value).expect("signaled payload");
        let observed = decode_linux_vz_package_process_sensor_correlation_v1(
            &payload,
            LinuxVzPackageExpectedProcessSensorCorrelationV1 {
                sensor_session_challenge_sha256: &challenge,
                contract: &contract,
                cgroup_name: "whoathere-package-action-1",
                leader_pid: 42,
                leader_parent_pid: 40,
                launch_identity: LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(&contract)
                    .expect("identity"),
                completion: LinuxVzPackageProcessCompletionV1::from_parts_v1(
                    200,
                    300,
                    139,
                    LinuxVzPackageProcessTerminalV1::Signaled,
                    None,
                    Some(11),
                )
                .expect("completion"),
            },
        )
        .expect("signaled correlation");
        assert_eq!(
            observed.leader_terminal(),
            LinuxVzPackageProcessTerminalV1::Signaled
        );
        assert_eq!(observed.leader_exit_status(), None);
        assert_eq!(observed.leader_termination_signal(), Some(11));
        assert_eq!(observed.leader_supervisor_wait_status(), 139);
        assert_eq!(observed.leader_kernel_wait_status(), 139);
    }

    #[test]
    fn missing_health_drop_and_rebinding_fail_closed() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh sensor session challenge");
        for (field, replacement, expected_error) in [
            (
                "process_sensor_healthy",
                serde_json::json!(false),
                LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidHealth,
            ),
            (
                "dropped_event_count",
                serde_json::json!("1"),
                LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidHealth,
            ),
            (
                "leader_pid",
                serde_json::json!("43"),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
            (
                "leader_exit_status",
                serde_json::json!("1"),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
            (
                "leader_supervisor_wait_status",
                serde_json::json!("1792"),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
            (
                "leader_kernel_wait_status",
                serde_json::json!("1792"),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
            (
                "leader_parent_pid",
                serde_json::json!("39"),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
            (
                "leader_argv_item_count",
                serde_json::json!("1"),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
            (
                "leader_executable_sha256",
                serde_json::json!(Sha256Digest::from_bytes(b"rebound executable")),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
            (
                "sensor_session_challenge_sha256",
                serde_json::json!(Sha256Digest::from_bytes(b"stale session")),
                LinuxVzPackageProcessSensorCorrelationErrorV1::BindingMismatch,
            ),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_slice(&payload_v1(&contract, &challenge)).expect("JSON");
            value[field] = replacement;
            let changed = serde_json_canonicalizer::to_vec(&value).expect("changed");
            assert_eq!(
                decode_linux_vz_package_process_sensor_correlation_v1(
                    &changed,
                    expected_v1(&contract, &challenge)
                ),
                Err(expected_error)
            );
        }

        for required_wait_status in ["leader_supervisor_wait_status", "leader_kernel_wait_status"] {
            let mut value: serde_json::Value =
                serde_json::from_slice(&payload_v1(&contract, &challenge)).expect("JSON");
            value
                .as_object_mut()
                .expect("correlation object")
                .remove(required_wait_status);
            let missing = serde_json_canonicalizer::to_vec(&value).expect("missing field");
            assert_eq!(
                decode_linux_vz_package_process_sensor_correlation_v1(
                    &missing,
                    expected_v1(&contract, &challenge)
                ),
                Err(LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidJson)
            );
        }
    }

    #[test]
    fn noncanonical_and_inconsistent_counts_fail_closed() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh sensor session challenge");
        let mut noncanonical = payload_v1(&contract, &challenge);
        noncanonical.push(b'\n');
        assert_eq!(
            decode_linux_vz_package_process_sensor_correlation_v1(
                &noncanonical,
                expected_v1(&contract, &challenge)
            ),
            Err(LinuxVzPackageProcessSensorCorrelationErrorV1::NonCanonical)
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&payload_v1(&contract, &challenge)).expect("JSON");
        value["file_event_count"] = serde_json::json!("2");
        let changed = serde_json_canonicalizer::to_vec(&value).expect("changed");
        assert_eq!(
            decode_linux_vz_package_process_sensor_correlation_v1(
                &changed,
                expected_v1(&contract, &challenge)
            ),
            Err(LinuxVzPackageProcessSensorCorrelationErrorV1::InvalidCounts)
        );
    }

    #[test]
    fn detailed_sensor_payloads_must_match_the_correlated_digests() {
        assert_eq!(
            MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
            16 * 1024 * 1024
        );
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh sensor session challenge");
        let correlation = decode_linux_vz_package_process_sensor_correlation_v1(
            &payload_v1(&contract, &challenge),
            expected_v1(&contract, &challenge),
        )
        .expect("correlation");
        validate_linux_vz_package_protected_sensor_payloads_v1(
            &correlation,
            b"exec and exit evidence payload",
            b"empty file evidence payload",
            b"empty network evidence payload",
        )
        .expect("payload binding");
        assert_eq!(
            validate_linux_vz_package_protected_sensor_payloads_v1(
                &correlation,
                b"mutated process evidence payload",
                b"empty file evidence payload",
                b"empty network evidence payload",
            ),
            Err(LinuxVzPackageProcessSensorCorrelationErrorV1::PayloadDigestMismatch)
        );
    }
}
