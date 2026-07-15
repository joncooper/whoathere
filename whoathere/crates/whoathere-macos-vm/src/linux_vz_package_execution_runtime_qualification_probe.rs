#[cfg(target_os = "linux")]
use crate::{
    LinuxVzPackageRootCoordinatorBranchV1, LinuxVzPackageRootRunnerBranchV1,
    LinuxVzPackageRootSensorServiceBranchV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::time::Duration;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_execution_runtime_qualification_probe.v1";
pub const MAX_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_BYTES_V1: usize = 64 * 1024;

#[cfg(target_os = "linux")]
const CONTROL_TIMEOUT_SECONDS_V1: u64 = 10;
#[cfg(target_os = "linux")]
const RUNNER_PROOF_V1: &[u8] = b"whoathere-execution-runtime-runner-branch-v1\n";
#[cfg(target_os = "linux")]
const SERVICE_SEED_READ_ACK_V1: &[u8] = b"whoathere-execution-runtime-service-seed-read-v1\n";
const CAP_SYS_PTRACE_BIT_V1: u64 = 1_u64 << 19;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRuntimeQualificationProbeWireV1 {
    schema_version: String,
    runtime_sha256: Sha256Digest,
    seed_public_key_sha256: Sha256Digest,
    service_pid: String,
    runner_pid: String,
    runner_thread_count: String,
    runner_open_descriptor_count: String,
    runner_unexpected_descriptor_count: String,
    runner_inheritable_capabilities: String,
    runner_permitted_capabilities: String,
    runner_effective_capabilities: String,
    runner_bounding_capabilities: String,
    runner_ambient_capabilities: String,
    runner_exit_status: String,
    seed_byte_length: String,
    root_credentials_verified: bool,
    tracer_absent: bool,
    no_new_privileges: bool,
    ptrace_capability_present: bool,
    runner_self_dumpable: bool,
    service_dumpable: bool,
    runner_parent_death_signal_sigkill: bool,
    runner_seed_descriptor_closed: bool,
    runner_control_release_bound: bool,
    seed_read_after_runner_boundary_verification: bool,
    seed_pipe_exact_eof: bool,
    fixed_execution_entrypoint_measured: bool,
    coordinator_split_exercised: bool,
    execution_grant_consumed: bool,
    execution_request_consumed: bool,
    execution_authority_issued: bool,
    package_execution: bool,
    sync_back: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1 {
    canonical_json: Vec<u8>,
    evidence_sha256: Sha256Digest,
    wire: ExecutionRuntimeQualificationProbeWireV1,
}

impl fmt::Debug for LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1")
            .field("evidence_sha256", &self.evidence_sha256)
            .field("runtime_sha256", &self.wire.runtime_sha256)
            .field("seed_public_key_sha256", &self.wire.seed_public_key_sha256)
            .field("coordinator_split_exercised", &true)
            .field("package_execution", &false)
            .field("sync_back", &false)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn evidence_sha256(&self) -> &Sha256Digest {
        &self.evidence_sha256
    }

    pub fn runtime_sha256(&self) -> &Sha256Digest {
        &self.wire.runtime_sha256
    }

    pub fn seed_public_key_sha256(&self) -> &Sha256Digest {
        &self.wire.seed_public_key_sha256
    }

    pub fn service_pid(&self) -> u32 {
        self.wire
            .service_pid
            .parse()
            .expect("validated service pid")
    }

    pub fn runner_pid(&self) -> u32 {
        self.wire.runner_pid.parse().expect("validated runner pid")
    }

    pub fn runner_thread_count(&self) -> u32 {
        self.wire
            .runner_thread_count
            .parse()
            .expect("validated runner thread count")
    }

    pub fn runner_open_descriptor_count(&self) -> u32 {
        self.wire
            .runner_open_descriptor_count
            .parse()
            .expect("validated runner descriptor count")
    }

    pub fn runner_inheritable_capabilities(&self) -> u64 {
        u64::from_str_radix(&self.wire.runner_inheritable_capabilities, 16)
            .expect("validated inheritable capabilities")
    }

    pub fn runner_permitted_capabilities(&self) -> u64 {
        u64::from_str_radix(&self.wire.runner_permitted_capabilities, 16)
            .expect("validated permitted capabilities")
    }

    pub fn runner_effective_capabilities(&self) -> u64 {
        u64::from_str_radix(&self.wire.runner_effective_capabilities, 16)
            .expect("validated effective capabilities")
    }

    pub fn runner_bounding_capabilities(&self) -> u64 {
        u64::from_str_radix(&self.wire.runner_bounding_capabilities, 16)
            .expect("validated bounding capabilities")
    }

    pub fn runner_ambient_capabilities(&self) -> u64 {
        u64::from_str_radix(&self.wire.runner_ambient_capabilities, 16)
            .expect("validated ambient capabilities")
    }

    pub const fn coordinator_split_exercised(&self) -> bool {
        true
    }

    pub const fn execution_authority_issued(&self) -> bool {
        false
    }

    pub const fn package_execution_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1 {
    UnsupportedPlatform,
    CoordinatorFailed,
    RunnerBoundaryInvalid,
    ControlFailed,
    SigningSeedInvalid,
    RunnerFailed,
    Empty,
    LimitExceeded,
    InvalidEvidence,
    BindingMismatch,
    NonCanonical,
    Serialization,
}

impl LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => {
                "linux_vz_package_execution_runtime_probe_platform_unsupported"
            }
            Self::CoordinatorFailed => {
                "linux_vz_package_execution_runtime_probe_coordinator_failed"
            }
            Self::RunnerBoundaryInvalid => {
                "linux_vz_package_execution_runtime_probe_runner_boundary_invalid"
            }
            Self::ControlFailed => "linux_vz_package_execution_runtime_probe_control_failed",
            Self::SigningSeedInvalid => {
                "linux_vz_package_execution_runtime_probe_signing_seed_invalid"
            }
            Self::RunnerFailed => "linux_vz_package_execution_runtime_probe_runner_failed",
            Self::Empty => "linux_vz_package_execution_runtime_probe_empty",
            Self::LimitExceeded => "linux_vz_package_execution_runtime_probe_limit_exceeded",
            Self::InvalidEvidence => "linux_vz_package_execution_runtime_probe_evidence_invalid",
            Self::BindingMismatch => "linux_vz_package_execution_runtime_probe_binding_mismatch",
            Self::NonCanonical => "linux_vz_package_execution_runtime_probe_noncanonical",
            Self::Serialization => "linux_vz_package_execution_runtime_probe_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1 {}

/// Exercises the exact coordinator split linked into the execution-capable runtime without
/// consuming a package grant or executing an artifact.
///
/// The root-runner branch never receives the signing seed and terminates with `_exit`; only the
/// isolated service branch can return canonical evidence to the caller.
pub fn run_linux_vz_package_execution_runtime_qualification_probe_v1(
    signing_seed_fd: OwnedFd,
    runtime_sha256: Sha256Digest,
    expected_public_key_sha256: &Sha256Digest,
) -> Result<
    LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1,
    LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1,
> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = signing_seed_fd;
        let _ = runtime_sha256;
        let _ = expected_public_key_sha256;
        Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    {
        match crate::split_linux_vz_package_root_coordinator_v1(signing_seed_fd).map_err(|_| {
            LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::CoordinatorFailed
        })? {
            LinuxVzPackageRootCoordinatorBranchV1::RootRunner(branch) => {
                let exit_code = if run_runner_probe_v1(branch).is_ok() {
                    0
                } else {
                    78
                };
                unsafe { libc::_exit(exit_code) }
            }
            LinuxVzPackageRootCoordinatorBranchV1::SensorService(branch) => {
                run_service_probe_v1(branch, runtime_sha256, expected_public_key_sha256)
            }
        }
    }
}

pub fn decode_linux_vz_package_execution_runtime_qualification_probe_v1(
    bytes: &[u8],
    expected_runtime_sha256: &Sha256Digest,
    expected_public_key_sha256: &Sha256Digest,
) -> Result<
    LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1,
    LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1,
> {
    if bytes.is_empty() {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_BYTES_V1 {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = ExecutionRuntimeQualificationProbeWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::InvalidEvidence)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::InvalidEvidence)?;
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::Serialization)?;
    if canonical_json != bytes {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::NonCanonical);
    }
    validate_probe_wire_v1(&wire, expected_runtime_sha256, expected_public_key_sha256)?;
    Ok(LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1 {
        evidence_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        wire,
    })
}

fn validate_probe_wire_v1(
    wire: &ExecutionRuntimeQualificationProbeWireV1,
    expected_runtime_sha256: &Sha256Digest,
    expected_public_key_sha256: &Sha256Digest,
) -> Result<(), LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    let service_pid = parse_canonical_u32_v1(&wire.service_pid)?;
    let runner_pid = parse_canonical_u32_v1(&wire.runner_pid)?;
    let inheritable = parse_capability_mask_v1(&wire.runner_inheritable_capabilities)?;
    let permitted = parse_capability_mask_v1(&wire.runner_permitted_capabilities)?;
    let effective = parse_capability_mask_v1(&wire.runner_effective_capabilities)?;
    let bounding = parse_capability_mask_v1(&wire.runner_bounding_capabilities)?;
    let ambient = parse_capability_mask_v1(&wire.runner_ambient_capabilities)?;
    if wire.schema_version != LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_SCHEMA_V1
        || wire.runtime_sha256 != *expected_runtime_sha256
        || wire.seed_public_key_sha256 != *expected_public_key_sha256
        || service_pid == runner_pid
        || parse_canonical_u32_v1(&wire.runner_thread_count)? != 1
        || parse_canonical_u32_v1(&wire.runner_open_descriptor_count)? != 4
        || parse_canonical_u32_allow_zero_v1(&wire.runner_unexpected_descriptor_count)? != 0
        || parse_canonical_u32_allow_zero_v1(&wire.runner_exit_status)? != 0
        || parse_canonical_u32_v1(&wire.seed_byte_length)? != 32
        || inheritable & CAP_SYS_PTRACE_BIT_V1 != 0
        || permitted & CAP_SYS_PTRACE_BIT_V1 != 0
        || effective & CAP_SYS_PTRACE_BIT_V1 != 0
        || bounding & CAP_SYS_PTRACE_BIT_V1 != 0
        || ambient != 0
        || !wire.root_credentials_verified
        || !wire.tracer_absent
        || !wire.no_new_privileges
        || wire.ptrace_capability_present
        || wire.runner_self_dumpable
        || wire.service_dumpable
        || !wire.runner_parent_death_signal_sigkill
        || !wire.runner_seed_descriptor_closed
        || !wire.runner_control_release_bound
        || !wire.seed_read_after_runner_boundary_verification
        || !wire.seed_pipe_exact_eof
        || !wire.fixed_execution_entrypoint_measured
        || !wire.coordinator_split_exercised
        || wire.execution_grant_consumed
        || wire.execution_request_consumed
        || wire.execution_authority_issued
        || wire.package_execution
        || wire.sync_back
    {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::BindingMismatch);
    }
    Ok(())
}

fn parse_canonical_u32_v1(
    value: &str,
) -> Result<u32, LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    let parsed = parse_canonical_u32_allow_zero_v1(value)?;
    if parsed == 0 {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::InvalidEvidence);
    }
    Ok(parsed)
}

fn parse_canonical_u32_allow_zero_v1(
    value: &str,
) -> Result<u32, LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    if value.is_empty()
        || value.len() > 10
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::InvalidEvidence);
    }
    value
        .parse::<u32>()
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::InvalidEvidence)
}

fn parse_capability_mask_v1(
    value: &str,
) -> Result<u64, LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::InvalidEvidence);
    }
    u64::from_str_radix(value, 16)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::InvalidEvidence)
}

#[cfg(target_os = "linux")]
fn run_runner_probe_v1(
    branch: LinuxVzPackageRootRunnerBranchV1,
) -> Result<(), LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    if !branch.signing_seed_descriptor_closed()
        || branch.ptrace_capability_present()
        || branch.dumpable()
        || !branch.no_new_privileges()
    {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::RunnerBoundaryInvalid);
    }
    let mut control = control_stream_v1(branch.into_control_fd_v1())?;
    control
        .write_all(RUNNER_PROOF_V1)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed)?;
    control
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed)?;
    let acknowledgement = read_bounded_to_eof_v1(&mut control, 128)?;
    if acknowledgement != SERVICE_SEED_READ_ACK_V1 {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run_service_probe_v1(
    branch: LinuxVzPackageRootSensorServiceBranchV1,
    runtime_sha256: Sha256Digest,
    expected_public_key_sha256: &Sha256Digest,
) -> Result<
    LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1,
    LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1,
> {
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
        || !branch.runner_hardening_complete()
    {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::RunnerBoundaryInvalid);
    }
    let service_pid = branch.service_pid();
    let runner_pid = branch.runner_pid();
    let boundary = *branch.runner_custody_boundary();
    if boundary.runner_pid() != runner_pid
        || boundary.ptrace_capability_present()
        || !boundary.root_credentials_verified()
        || !boundary.tracer_absent()
        || !boundary.no_new_privileges()
        || boundary.thread_count() != 1
        || boundary.open_descriptor_count() != 4
        || boundary.unexpected_descriptor_count() != 0
        || boundary.ambient_capabilities() != 0
    {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::RunnerBoundaryInvalid);
    }
    let (control_fd, signing_seed) = branch.into_control_and_signing_seed_v1();
    let mut control = control_stream_v1(control_fd)?;
    if read_bounded_to_eof_v1(&mut control, 128)? != RUNNER_PROOF_V1 {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed);
    }
    let signing_seed = signing_seed
        .read_once_v1()
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::SigningSeedInvalid)?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&signing_seed);
    if signing_key.verifying_key().is_weak() {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::SigningSeedInvalid);
    }
    let public_key_sha256 = Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes());
    drop(signing_key);
    drop(signing_seed);
    if public_key_sha256 != *expected_public_key_sha256 {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::SigningSeedInvalid);
    }
    control
        .write_all(SERVICE_SEED_READ_ACK_V1)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed)?;
    control
        .shutdown(std::net::Shutdown::Write)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed)?;
    let runner_exit_status = wait_for_runner_v1(runner_pid)?;

    let wire = ExecutionRuntimeQualificationProbeWireV1 {
        schema_version: LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_SCHEMA_V1
            .to_string(),
        runtime_sha256,
        seed_public_key_sha256: public_key_sha256,
        service_pid: service_pid.to_string(),
        runner_pid: runner_pid.to_string(),
        runner_thread_count: boundary.thread_count().to_string(),
        runner_open_descriptor_count: boundary.open_descriptor_count().to_string(),
        runner_unexpected_descriptor_count: boundary.unexpected_descriptor_count().to_string(),
        runner_inheritable_capabilities: format!("{:016x}", boundary.inheritable_capabilities()),
        runner_permitted_capabilities: format!("{:016x}", boundary.permitted_capabilities()),
        runner_effective_capabilities: format!("{:016x}", boundary.effective_capabilities()),
        runner_bounding_capabilities: format!("{:016x}", boundary.bounding_capabilities()),
        runner_ambient_capabilities: format!("{:016x}", boundary.ambient_capabilities()),
        runner_exit_status: runner_exit_status.to_string(),
        seed_byte_length: "32".to_string(),
        root_credentials_verified: boundary.root_credentials_verified(),
        tracer_absent: boundary.tracer_absent(),
        no_new_privileges: boundary.no_new_privileges(),
        ptrace_capability_present: boundary.ptrace_capability_present(),
        runner_self_dumpable: false,
        service_dumpable: false,
        runner_parent_death_signal_sigkill: true,
        runner_seed_descriptor_closed: true,
        runner_control_release_bound: true,
        seed_read_after_runner_boundary_verification: true,
        seed_pipe_exact_eof: true,
        fixed_execution_entrypoint_measured: true,
        coordinator_split_exercised: true,
        execution_grant_consumed: false,
        execution_request_consumed: false,
        execution_authority_issued: false,
        package_execution: false,
        sync_back: false,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len()
            > MAX_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_BYTES_V1
    {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::LimitExceeded);
    }
    validate_probe_wire_v1(&wire, &wire.runtime_sha256, expected_public_key_sha256)?;
    Ok(LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1 {
        evidence_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        wire,
    })
}

#[cfg(target_os = "linux")]
fn control_stream_v1(
    descriptor: OwnedFd,
) -> Result<UnixStream, LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    let stream = UnixStream::from(descriptor);
    let timeout = Some(Duration::from_secs(CONTROL_TIMEOUT_SECONDS_V1));
    stream
        .set_read_timeout(timeout)
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed)?;
    Ok(stream)
}

#[cfg(target_os = "linux")]
fn read_bounded_to_eof_v1(
    stream: &mut UnixStream,
    maximum: usize,
) -> Result<Vec<u8>, LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    let mut bytes = Vec::new();
    stream
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::ControlFailed);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn wait_for_runner_v1(
    runner_pid: u32,
) -> Result<i32, LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1> {
    let runner_pid = libc::pid_t::try_from(runner_pid)
        .map_err(|_| LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::RunnerFailed)?;
    let mut status = 0_i32;
    loop {
        let result = unsafe { libc::waitpid(runner_pid, &mut status, 0) };
        if result == runner_pid {
            break;
        }
        if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
            continue;
        }
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::RunnerFailed);
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::RunnerFailed);
    }
    Ok(libc::WEXITSTATUS(status))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &[u8]) -> Sha256Digest {
        Sha256Digest::from_bytes(label)
    }

    fn valid_wire() -> ExecutionRuntimeQualificationProbeWireV1 {
        ExecutionRuntimeQualificationProbeWireV1 {
            schema_version: LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_SCHEMA_V1
                .to_string(),
            runtime_sha256: digest(b"execution runtime"),
            seed_public_key_sha256: digest(b"guest key"),
            service_pid: "100".to_string(),
            runner_pid: "101".to_string(),
            runner_thread_count: "1".to_string(),
            runner_open_descriptor_count: "4".to_string(),
            runner_unexpected_descriptor_count: "0".to_string(),
            runner_inheritable_capabilities: "0000000000000000".to_string(),
            runner_permitted_capabilities: "000001fffff7ffff".to_string(),
            runner_effective_capabilities: "000001fffff7ffff".to_string(),
            runner_bounding_capabilities: "000001fffff7ffff".to_string(),
            runner_ambient_capabilities: "0000000000000000".to_string(),
            runner_exit_status: "0".to_string(),
            seed_byte_length: "32".to_string(),
            root_credentials_verified: true,
            tracer_absent: true,
            no_new_privileges: true,
            ptrace_capability_present: false,
            runner_self_dumpable: false,
            service_dumpable: false,
            runner_parent_death_signal_sigkill: true,
            runner_seed_descriptor_closed: true,
            runner_control_release_bound: true,
            seed_read_after_runner_boundary_verification: true,
            seed_pipe_exact_eof: true,
            fixed_execution_entrypoint_measured: true,
            coordinator_split_exercised: true,
            execution_grant_consumed: false,
            execution_request_consumed: false,
            execution_authority_issued: false,
            package_execution: false,
            sync_back: false,
        }
    }

    #[test]
    fn strict_probe_decoder_binds_exact_runtime_key_and_custody_boundary() {
        let wire = valid_wire();
        let bytes = serde_json_canonicalizer::to_vec(&wire).unwrap();
        let decoded = decode_linux_vz_package_execution_runtime_qualification_probe_v1(
            &bytes,
            &wire.runtime_sha256,
            &wire.seed_public_key_sha256,
        )
        .unwrap();
        assert_eq!(decoded.canonical_json_v1(), bytes);
        assert!(decoded.coordinator_split_exercised());
        assert!(!decoded.execution_authority_issued());
        assert!(!decoded.package_execution_permitted());
        assert!(!decoded.sync_back_permitted());

        assert_eq!(
            decode_linux_vz_package_execution_runtime_qualification_probe_v1(
                &bytes,
                &digest(b"other runtime"),
                &wire.seed_public_key_sha256,
            ),
            Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::BindingMismatch)
        );
    }

    #[test]
    fn probe_decoder_rejects_authority_capability_and_canonicality_upgrades() {
        for mutate in [
            |wire: &mut ExecutionRuntimeQualificationProbeWireV1| {
                wire.execution_authority_issued = true
            },
            |wire: &mut ExecutionRuntimeQualificationProbeWireV1| wire.package_execution = true,
            |wire: &mut ExecutionRuntimeQualificationProbeWireV1| wire.sync_back = true,
            |wire: &mut ExecutionRuntimeQualificationProbeWireV1| {
                wire.runner_effective_capabilities = "0000000000080000".to_string()
            },
        ] {
            let mut wire = valid_wire();
            mutate(&mut wire);
            let bytes = serde_json_canonicalizer::to_vec(&wire).unwrap();
            assert!(
                decode_linux_vz_package_execution_runtime_qualification_probe_v1(
                    &bytes,
                    &digest(b"execution runtime"),
                    &digest(b"guest key"),
                )
                .is_err()
            );
        }

        let wire = valid_wire();
        let mut value = serde_json::to_value(&wire).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unknown".to_string(), serde_json::Value::Bool(true));
        assert!(
            decode_linux_vz_package_execution_runtime_qualification_probe_v1(
                &serde_json::to_vec_pretty(&value).unwrap(),
                &wire.runtime_sha256,
                &wire.seed_public_key_sha256,
            )
            .is_err()
        );
    }

    #[test]
    fn physical_probe_is_platform_closed_off_linux() {
        #[cfg(not(target_os = "linux"))]
        {
            use std::os::fd::FromRawFd;

            let fd = unsafe { OwnedFd::from_raw_fd(libc::dup(libc::STDIN_FILENO)) };
            assert_eq!(
                run_linux_vz_package_execution_runtime_qualification_probe_v1(
                    fd,
                    digest(b"runtime"),
                    &digest(b"key")
                ),
                Err(LinuxVzPackageExecutionRuntimeQualificationProbeErrorV1::UnsupportedPlatform)
            );
        }
    }
}
