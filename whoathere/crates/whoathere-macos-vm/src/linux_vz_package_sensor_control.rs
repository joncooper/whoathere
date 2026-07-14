#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_file_collector::LinuxVzPackageRootFileCollectorV1;
#[cfg(target_os = "linux")]
use crate::linux_vz_package_sensor_process_collector::LinuxVzPackageRootProcessCollectorV1;
#[cfg(target_os = "linux")]
use crate::{
    encode_linux_vz_package_root_file_evidence_v1,
    encode_linux_vz_package_root_process_evidence_v1, protected_process_observer_seal,
    LinuxVzPackageExpectedRootFileEvidenceV1, LinuxVzPackageExpectedRootProcessEvidenceV1,
    LinuxVzPackageProcessLaunchContractV1, LinuxVzPackageProcessSupervisorErrorV1,
    LinuxVzPackageProtectedProcessObserverV1, LinuxVzPackageProtectedSensorOutputV1,
    LinuxVzPackageRootFileEvidenceV1, LinuxVzPackageRootProcessEvidenceV1,
    MAX_LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_BYTES_V1,
    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
};
use crate::{
    LinuxVzPackageProcessCompletionV1, LinuxVzPackageProcessLaunchIdentityV1,
    LinuxVzPackageProcessTerminalV1, QualifiedMacosLinuxVzTelemetryBackendV1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::mem::{size_of, zeroed, MaybeUninit};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "linux")]
use std::time::Duration;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_PROTOCOL_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_protocol.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_OPEN_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_open.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_OPEN_ACK_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_open_ack.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_arm.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_ACK_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_arm_ack.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_sensor_control_arm.v2";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_ACK_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_sensor_control_arm_ack.v2";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_leader.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_ACK_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_leader_ack.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_sensor_control_leader.v2";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_ACK_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_sensor_control_leader_ack.v2";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_finish.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_ACK_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_finish_ack.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_sensor_control_finish.v2";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_ACK_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_sensor_control_finish_ack.v2";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_SCHEMA_V3: &str =
    "whoathere.linux_vz_package_sensor_control_finish.v3";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_ACK_SCHEMA_V3: &str =
    "whoathere.linux_vz_package_sensor_control_finish_ack.v3";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_ABORT_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_abort.v1";
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_ABORT_ACK_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_sensor_control_abort_ack.v1";

pub const MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_MESSAGE_BYTES_V1: usize = 256 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_EVIDENCE_BYTES_V1: usize = 4 * 1024 * 1024;
pub const LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1: usize = 60;

const CONTROL_MAGIC_V1: &[u8; 8] = b"WTPKSN01";
const CONTROL_VERSION_V1: u16 = 1;
#[cfg(target_os = "linux")]
const CONTROL_TIMEOUT_SECONDS_V1: u64 = 10;
#[cfg(target_os = "linux")]
const CGROUP2_SUPER_MAGIC_V1: i64 = 0x6367_7270;
const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum LinuxVzPackageSensorControlFrameKindV1 {
    OpenSession = 1,
    OpenSessionAck = 2,
    Arm = 3,
    ArmAck = 4,
    LeaderAttached = 5,
    LeaderAttachedAck = 6,
    Finish = 7,
    CorrelationEvidence = 8,
    ProcessEvidence = 9,
    FileEvidence = 10,
    NetworkEvidence = 11,
    FinishAck = 12,
    Abort = 13,
    AbortAck = 14,
}

impl LinuxVzPackageSensorControlFrameKindV1 {
    fn from_u16_v1(value: u16) -> Result<Self, LinuxVzPackageSensorControlErrorV1> {
        match value {
            1 => Ok(Self::OpenSession),
            2 => Ok(Self::OpenSessionAck),
            3 => Ok(Self::Arm),
            4 => Ok(Self::ArmAck),
            5 => Ok(Self::LeaderAttached),
            6 => Ok(Self::LeaderAttachedAck),
            7 => Ok(Self::Finish),
            8 => Ok(Self::CorrelationEvidence),
            9 => Ok(Self::ProcessEvidence),
            10 => Ok(Self::FileEvidence),
            11 => Ok(Self::NetworkEvidence),
            12 => Ok(Self::FinishAck),
            13 => Ok(Self::Abort),
            14 => Ok(Self::AbortAck),
            _ => Err(LinuxVzPackageSensorControlErrorV1::InvalidFrameKind),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageSensorControlErrorV1 {
    Empty,
    LimitExceeded,
    InvalidMagic,
    InvalidVersion,
    InvalidFrameKind,
    InvalidSequence,
    InvalidLength,
    DigestMismatch,
    NonCanonical,
    InvalidPayload,
    InvalidIdentity,
    InvalidPeer,
    InvalidDescriptor,
    InvalidState,
    EntropyUnavailable,
    SensorFault,
    Io,
}

impl LinuxVzPackageSensorControlErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_sensor_control_empty",
            Self::LimitExceeded => "linux_vz_package_sensor_control_limit_exceeded",
            Self::InvalidMagic => "linux_vz_package_sensor_control_magic_invalid",
            Self::InvalidVersion => "linux_vz_package_sensor_control_version_invalid",
            Self::InvalidFrameKind => "linux_vz_package_sensor_control_frame_kind_invalid",
            Self::InvalidSequence => "linux_vz_package_sensor_control_sequence_invalid",
            Self::InvalidLength => "linux_vz_package_sensor_control_length_invalid",
            Self::DigestMismatch => "linux_vz_package_sensor_control_digest_mismatch",
            Self::NonCanonical => "linux_vz_package_sensor_control_noncanonical",
            Self::InvalidPayload => "linux_vz_package_sensor_control_payload_invalid",
            Self::InvalidIdentity => "linux_vz_package_sensor_control_identity_invalid",
            Self::InvalidPeer => "linux_vz_package_sensor_control_peer_invalid",
            Self::InvalidDescriptor => "linux_vz_package_sensor_control_descriptor_invalid",
            Self::InvalidState => "linux_vz_package_sensor_control_state_invalid",
            Self::EntropyUnavailable => "linux_vz_package_sensor_control_entropy_unavailable",
            Self::SensorFault => "linux_vz_package_sensor_control_sensor_fault",
            Self::Io => "linux_vz_package_sensor_control_io_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageSensorControlErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageSensorControlErrorV1 {}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageSensorControlFrameV1 {
    kind: LinuxVzPackageSensorControlFrameKindV1,
    sequence: u64,
    payload_sha256: Sha256Digest,
    payload: Vec<u8>,
}

impl fmt::Debug for LinuxVzPackageSensorControlFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageSensorControlFrameV1")
            .field("kind", &self.kind)
            .field("sequence", &self.sequence)
            .field("payload_sha256", &self.payload_sha256)
            .field("payload_byte_length", &self.payload.len())
            .field("payload", &"<redacted>")
            .finish()
    }
}

impl LinuxVzPackageSensorControlFrameV1 {
    pub const fn kind(&self) -> LinuxVzPackageSensorControlFrameKindV1 {
        self.kind
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootSensorIdentityV1 {
    qualified_telemetry_backend_sha256: Sha256Digest,
    guest_evidence_signer_sha256: Sha256Digest,
    protected_sensor_bundle_sha256: Sha256Digest,
    sensor_configuration_sha256: Sha256Digest,
}

impl LinuxVzPackageRootSensorIdentityV1 {
    pub fn from_qualified_backend_v1(
        backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    ) -> Result<Self, LinuxVzPackageSensorControlErrorV1> {
        let value = Self {
            qualified_telemetry_backend_sha256: backend.qualified_backend_sha256().clone(),
            guest_evidence_signer_sha256: backend.guest_sensor_sha256().clone(),
            protected_sensor_bundle_sha256: backend.guest_bpf_bundle_sha256().clone(),
            sensor_configuration_sha256: backend.guest_sensor_configuration_sha256().clone(),
        };
        value.validate_v1()?;
        Ok(value)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let values = [
            &self.qualified_telemetry_backend_sha256,
            &self.guest_evidence_signer_sha256,
            &self.protected_sensor_bundle_sha256,
            &self.sensor_configuration_sha256,
        ];
        if values.contains(&&empty)
            || values
                .iter()
                .enumerate()
                .any(|(index, digest)| values[..index].contains(digest))
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidIdentity);
        }
        Ok(())
    }

    pub fn qualified_telemetry_backend_sha256(&self) -> &Sha256Digest {
        &self.qualified_telemetry_backend_sha256
    }

    pub fn guest_evidence_signer_sha256(&self) -> &Sha256Digest {
        &self.guest_evidence_signer_sha256
    }

    pub fn protected_sensor_bundle_sha256(&self) -> &Sha256Digest {
        &self.protected_sensor_bundle_sha256
    }

    pub fn sensor_configuration_sha256(&self) -> &Sha256Digest {
        &self.sensor_configuration_sha256
    }

    #[cfg(target_os = "linux")]
    fn from_measured_guest_components_v1(
        qualified_telemetry_backend_sha256: Sha256Digest,
        guest_evidence_signer_sha256: Sha256Digest,
        protected_sensor_bundle_sha256: Sha256Digest,
        sensor_configuration_sha256: Sha256Digest,
    ) -> Result<Self, LinuxVzPackageSensorControlErrorV1> {
        let value = Self {
            qualified_telemetry_backend_sha256,
            guest_evidence_signer_sha256,
            protected_sensor_bundle_sha256,
            sensor_configuration_sha256,
        };
        value.validate_v1()?;
        Ok(value)
    }
}

pub fn encode_linux_vz_package_sensor_control_frame_v1(
    kind: LinuxVzPackageSensorControlFrameKindV1,
    sequence: u64,
    payload: &[u8],
    maximum_payload_bytes: usize,
) -> Result<Vec<u8>, LinuxVzPackageSensorControlErrorV1> {
    if payload.is_empty() {
        return Err(LinuxVzPackageSensorControlErrorV1::Empty);
    }
    if sequence == 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence);
    }
    if maximum_payload_bytes == 0
        || payload.len() > maximum_payload_bytes
        || payload.len() > MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_EVIDENCE_BYTES_V1
    {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    let payload_length = u64::try_from(payload.len())
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
    let raw_digest = Sha256::digest(payload);
    let mut frame = Vec::with_capacity(
        LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1
            .checked_add(payload.len())
            .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?,
    );
    frame.extend_from_slice(CONTROL_MAGIC_V1);
    frame.extend_from_slice(&CONTROL_VERSION_V1.to_be_bytes());
    frame.extend_from_slice(&(kind as u16).to_be_bytes());
    frame.extend_from_slice(&sequence.to_be_bytes());
    frame.extend_from_slice(&payload_length.to_be_bytes());
    frame.extend_from_slice(&raw_digest);
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn decode_linux_vz_package_sensor_control_frame_v1(
    frame: &[u8],
    maximum_payload_bytes: usize,
) -> Result<LinuxVzPackageSensorControlFrameV1, LinuxVzPackageSensorControlErrorV1> {
    if frame.len() < LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidLength);
    }
    if &frame[..8] != CONTROL_MAGIC_V1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidMagic);
    }
    let version = u16::from_be_bytes([frame[8], frame[9]]);
    if version != CONTROL_VERSION_V1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidVersion);
    }
    let kind = LinuxVzPackageSensorControlFrameKindV1::from_u16_v1(u16::from_be_bytes([
        frame[10], frame[11],
    ]))?;
    let sequence = u64::from_be_bytes(
        frame[12..20]
            .try_into()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidLength)?,
    );
    let payload_length = u64::from_be_bytes(
        frame[20..28]
            .try_into()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidLength)?,
    );
    let payload_length = usize::try_from(payload_length)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
    if sequence == 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence);
    }
    if payload_length == 0
        || maximum_payload_bytes == 0
        || payload_length > maximum_payload_bytes
        || payload_length > MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_EVIDENCE_BYTES_V1
    {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    let expected_length = LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1
        .checked_add(payload_length)
        .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
    if frame.len() != expected_length {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidLength);
    }
    let payload = &frame[LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1..];
    if frame[28..60] != Sha256::digest(payload)[..] {
        return Err(LinuxVzPackageSensorControlErrorV1::DigestMismatch);
    }
    Ok(LinuxVzPackageSensorControlFrameV1 {
        kind,
        sequence,
        payload_sha256: Sha256Digest::from_bytes(payload),
        payload: payload.to_vec(),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorSessionBindingWireV1 {
    guest_evidence_signer_sha256: Sha256Digest,
    package_gid: String,
    package_uid: String,
    qualified_telemetry_backend_sha256: Sha256Digest,
    protected_sensor_bundle_sha256: Sha256Digest,
    sensor_configuration_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorOpenRequestWireV1 {
    control_sequence: String,
    operation: String,
    public_network_route_present: bool,
    root_runner_gid: String,
    root_runner_uid: String,
    schema_version: String,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorOpenAckWireV1 {
    control_sequence: String,
    operation: String,
    previous_session_present: bool,
    public_network_route_present: bool,
    schema_version: String,
    sensor_assets_measured: bool,
    sensor_ready: bool,
    service_gid: String,
    service_pid: String,
    service_uid: String,
    session: SensorSessionBindingWireV1,
    signing_material_protected: bool,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorArmRequestWireV2 {
    action_index: String,
    argv_item_count: String,
    argv_sha256: Sha256Digest,
    cgroup_directory_fd_transferred: bool,
    cgroup_name: String,
    control_sequence: String,
    expected_executable_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    operation: String,
    process_plan_sha256: Sha256Digest,
    public_network_route_present: bool,
    schema_version: String,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorArmAckWireV2 {
    action_index: String,
    argv_item_count: String,
    argv_sha256: Sha256Digest,
    bpf_drop_count: String,
    cgroup_directory_fd_received: bool,
    cgroup_id: String,
    cgroup_name: String,
    cgroup_v2_verified: bool,
    control_sequence: String,
    expected_executable_sha256: Sha256Digest,
    file_sensor_armed: bool,
    heartbeat_started: bool,
    launch_contract_sha256: Sha256Digest,
    network_sensor_armed: bool,
    operation: String,
    process_plan_sha256: Sha256Digest,
    process_sensor_armed: bool,
    public_network_route_present: bool,
    schema_version: String,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorLeaderRequestWireV2 {
    action_index: String,
    cgroup_id: String,
    cgroup_name: String,
    control_sequence: String,
    launch_contract_sha256: Sha256Digest,
    leader_pid: String,
    operation: String,
    process_plan_sha256: Sha256Digest,
    public_network_route_present: bool,
    schema_version: String,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorLeaderAckWireV2 {
    action_index: String,
    bpf_drop_count: String,
    cgroup_id: String,
    cgroup_name: String,
    control_sequence: String,
    file_sensor_active: bool,
    heartbeat_count: String,
    launch_contract_sha256: Sha256Digest,
    leader_blocked_before_release: bool,
    leader_parent_pid: String,
    leader_parent_pid_verified: bool,
    leader_pid: String,
    network_sensor_active: bool,
    operation: String,
    process_plan_sha256: Sha256Digest,
    process_sensor_active: bool,
    proc_cgroup_membership_verified: bool,
    public_network_route_present: bool,
    schema_version: String,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorFinishRequestWireV3 {
    action_index: String,
    cgroup_id: String,
    cgroup_name: String,
    control_sequence: String,
    launch_contract_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leader_exit_status: Option<String>,
    leader_pid: String,
    leader_supervisor_wait_status: String,
    leader_terminal: LinuxVzPackageProcessTerminalV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leader_termination_signal: Option<String>,
    operation: String,
    process_ended_monotonic_nanoseconds: String,
    process_plan_sha256: Sha256Digest,
    process_started_monotonic_nanoseconds: String,
    public_network_route_present: bool,
    schema_version: String,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorFinishAckWireV3 {
    action_index: String,
    cgroup_empty_after_reap: bool,
    cgroup_fd_released: bool,
    cgroup_id: String,
    cgroup_name: String,
    cgroup_present_during_sensor_finalize: bool,
    control_sequence: String,
    correlation_byte_length: String,
    correlation_sha256: Sha256Digest,
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    file_evidence_byte_length: String,
    file_evidence_sha256: Sha256Digest,
    file_sensor_healthy: bool,
    heartbeat_count: String,
    launch_contract_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leader_exit_status: Option<String>,
    leader_pid: String,
    leader_supervisor_wait_status: String,
    leader_terminal: LinuxVzPackageProcessTerminalV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leader_termination_signal: Option<String>,
    network_evidence_byte_length: String,
    network_evidence_sha256: Sha256Digest,
    network_sensor_healthy: bool,
    operation: String,
    process_evidence_byte_length: String,
    process_evidence_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    process_sensor_healthy: bool,
    public_network_route_present: bool,
    schema_version: String,
    sensor_teardown_complete: bool,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorAbortRequestWireV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    action_index: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cgroup_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cgroup_name: Option<String>,
    control_sequence: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    launch_contract_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    leader_pid: Option<String>,
    operation: String,
    prior_state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    process_plan_sha256: Option<Sha256Digest>,
    public_network_route_present: bool,
    schema_version: String,
    session: SensorSessionBindingWireV1,
    sync_back: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SensorAbortAckWireV1 {
    abort_evidence_emitted: bool,
    cgroup_fd_released: bool,
    control_sequence: String,
    operation: String,
    public_network_route_present: bool,
    schema_version: String,
    sensor_teardown_complete: bool,
    session: SensorSessionBindingWireV1,
    session_aborted: bool,
    sync_back: bool,
}

fn session_binding_v1(
    identity: &LinuxVzPackageRootSensorIdentityV1,
    challenge: &Sha256Digest,
) -> SensorSessionBindingWireV1 {
    SensorSessionBindingWireV1 {
        guest_evidence_signer_sha256: identity.guest_evidence_signer_sha256().clone(),
        package_gid: PACKAGE_GID_V1.to_string(),
        package_uid: PACKAGE_UID_V1.to_string(),
        qualified_telemetry_backend_sha256: identity.qualified_telemetry_backend_sha256().clone(),
        protected_sensor_bundle_sha256: identity.protected_sensor_bundle_sha256().clone(),
        sensor_configuration_sha256: identity.sensor_configuration_sha256().clone(),
        sensor_session_challenge_sha256: challenge.clone(),
    }
}

fn canonical_bytes_v1<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, LinuxVzPackageSensorControlErrorV1> {
    let bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    if bytes.is_empty() || bytes.len() > MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_MESSAGE_BYTES_V1 {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    Ok(bytes)
}

fn decode_canonical_payload_v1<T>(payload: &[u8]) -> Result<T, LinuxVzPackageSensorControlErrorV1>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_MESSAGE_BYTES_V1 {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let value = T::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    if serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?
        != payload
    {
        return Err(LinuxVzPackageSensorControlErrorV1::NonCanonical);
    }
    Ok(value)
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzPackageSensorControlErrorV1> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)
}

fn optional_u8_v1(
    value: Option<&str>,
    zero_permitted: bool,
) -> Result<Option<u8>, LinuxVzPackageSensorControlErrorV1> {
    value
        .map(|value| {
            let value = decimal_u64_v1(value)?;
            if value > u8::MAX as u64 || (!zero_permitted && !(1..=64).contains(&value)) {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
            }
            Ok(value as u8)
        })
        .transpose()
}

fn process_completion_from_finish_request_v3(
    request: &SensorFinishRequestWireV3,
) -> Result<LinuxVzPackageProcessCompletionV1, LinuxVzPackageSensorControlErrorV1> {
    let started = decimal_u64_v1(&request.process_started_monotonic_nanoseconds)?;
    let ended = decimal_u64_v1(&request.process_ended_monotonic_nanoseconds)?;
    let supervisor_wait_status =
        u16::try_from(decimal_u64_v1(&request.leader_supervisor_wait_status)?)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    let exit_status = optional_u8_v1(request.leader_exit_status.as_deref(), true)?;
    let termination_signal = optional_u8_v1(request.leader_termination_signal.as_deref(), false)?;
    LinuxVzPackageProcessCompletionV1::from_parts_v1(
        started,
        ended,
        supervisor_wait_status,
        request.leader_terminal,
        exit_status,
        termination_signal,
    )
    .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)
}

fn process_launch_identity_from_arm_request_v2(
    request: &SensorArmRequestWireV2,
) -> Result<LinuxVzPackageProcessLaunchIdentityV1, LinuxVzPackageSensorControlErrorV1> {
    let argv_item_count = usize::try_from(decimal_u64_v1(&request.argv_item_count)?)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    LinuxVzPackageProcessLaunchIdentityV1::from_bound_digests_v1(
        request.expected_executable_sha256.clone(),
        request.argv_sha256.clone(),
        argv_item_count,
    )
    .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)
}

fn validate_root_leader_status_v1(
    status: &str,
    expected_parent_pid: u32,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if expected_parent_pid <= 1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
    }
    let root_uids = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .map(|line| line.split_ascii_whitespace().skip(1).collect::<Vec<_>>())
        == Some(vec!["0", "0", "0", "0"]);
    let root_gids = status
        .lines()
        .find(|line| line.starts_with("Gid:"))
        .map(|line| line.split_ascii_whitespace().skip(1).collect::<Vec<_>>())
        == Some(vec!["0", "0", "0", "0"]);
    let parent_pid = status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .map(str::trim)
        .map(decimal_u64_v1)
        .transpose()?
        .and_then(|value| u32::try_from(value).ok());
    if !root_uids || !root_gids || parent_pid != Some(expected_parent_pid) {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootSensorObserverStateV1 {
    Opening,
    SessionOpen,
    Armed,
    LeaderCorrelated,
    Finished,
    Aborted,
    Faulted,
}

#[cfg(target_os = "linux")]
impl RootSensorObserverStateV1 {
    const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Opening => "opening",
            Self::SessionOpen => "session_open",
            Self::Armed => "armed",
            Self::LeaderCorrelated => "leader_correlated",
            Self::Finished => "finished",
            Self::Aborted => "aborted",
            Self::Faulted => "faulted",
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveSensorBindingV1 {
    launch_contract_sha256: Sha256Digest,
    launch_identity: LinuxVzPackageProcessLaunchIdentityV1,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    cgroup_name: String,
    cgroup_id: u64,
    root_runner_pid: u32,
    leader_pid: Option<u32>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootSensorServiceStateV1 {
    AwaitingOpen,
    SessionOpen,
    Armed,
    LeaderCorrelated,
    Finished,
    Aborted,
}

#[cfg(target_os = "linux")]
impl RootSensorServiceStateV1 {
    const fn as_observer_state_v1(self) -> Option<&'static str> {
        match self {
            Self::AwaitingOpen => None,
            Self::SessionOpen => Some("session_open"),
            Self::Armed => Some("armed"),
            Self::LeaderCorrelated => Some("leader_correlated"),
            Self::Finished => Some("finished"),
            Self::Aborted => Some("aborted"),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
struct RootSensorServiceActionContextV1 {
    sensor_session_challenge_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    launch_identity: LinuxVzPackageProcessLaunchIdentityV1,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    cgroup_name: String,
    cgroup_id: u64,
    root_runner_pid: u32,
    leader_pid: Option<u32>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct RootSensorServiceActiveActionV1 {
    context: RootSensorServiceActionContextV1,
    cgroup_directory: OwnedFd,
}

#[cfg(target_os = "linux")]
struct RootSensorServiceCommonRequestV1<'a> {
    session: &'a SensorSessionBindingWireV1,
    schema_version: &'a str,
    expected_schema_version: &'a str,
    operation: &'a str,
    expected_operation: &'a str,
    public_network_route_present: bool,
    sync_back: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
struct RootSensorServiceArmStatusV1 {
    bpf_drop_count: u64,
    file_sensor_armed: bool,
    heartbeat_started: bool,
    network_sensor_armed: bool,
    process_sensor_armed: bool,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
struct RootSensorServiceLeaderStatusV1 {
    bpf_drop_count: u64,
    file_sensor_active: bool,
    heartbeat_count: u64,
    network_sensor_active: bool,
    process_sensor_active: bool,
}

#[cfg(target_os = "linux")]
#[allow(dead_code)]
struct RootSensorServiceFinishStatusV1 {
    output: LinuxVzPackageProtectedSensorOutputV1,
    descendant_teardown_complete: bool,
    dropped_event_count: u64,
    file_sensor_healthy: bool,
    heartbeat_count: u64,
    network_sensor_healthy: bool,
    process_sensor_healthy: bool,
    sensor_teardown_complete: bool,
}

/// Internal boundary between the protected control service and a real event collector.
///
/// This deliberately remains crate-private until the package collector can provide arbitrary
/// event streaming, loss accounting, fanotify enforcement, and signed evidence. A fixture or
/// no-op implementation must never be exposed as a production package sensor.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
trait LinuxVzPackageRootSensorServiceCollectorV1 {
    fn validate_ready_v1(
        &mut self,
        identity: &LinuxVzPackageRootSensorIdentityV1,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1>;

    fn arm_v1(
        &mut self,
        context: &RootSensorServiceActionContextV1,
        cgroup_directory: RawFd,
    ) -> Result<RootSensorServiceArmStatusV1, LinuxVzPackageSensorControlErrorV1>;

    fn leader_attached_v1(
        &mut self,
        context: &RootSensorServiceActionContextV1,
        cgroup_directory: RawFd,
    ) -> Result<RootSensorServiceLeaderStatusV1, LinuxVzPackageSensorControlErrorV1>;

    /// Returns distinct nonblocking, close-on-exec descriptors that become readable or hung up
    /// when their protected collectors fault or exit unexpectedly while an action is active.
    fn fault_signal_fds_v1(&self) -> Result<Vec<RawFd>, LinuxVzPackageSensorControlErrorV1>;

    fn finish_v1(
        &mut self,
        context: &RootSensorServiceActionContextV1,
        cgroup_directory: RawFd,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<RootSensorServiceFinishStatusV1, LinuxVzPackageSensorControlErrorV1>;

    fn abort_v1(
        &mut self,
        context: Option<&RootSensorServiceActionContextV1>,
        cgroup_directory: Option<RawFd>,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1>;
}

#[cfg(target_os = "linux")]
fn valid_fault_signal_fds_v1(descriptors: &[RawFd], control_fd: RawFd) -> bool {
    !descriptors.is_empty()
        && descriptors
            .iter()
            .all(|descriptor| *descriptor >= 0 && *descriptor != control_fd)
        && descriptors
            .iter()
            .enumerate()
            .all(|(index, descriptor)| !descriptors[..index].contains(descriptor))
}

/// Concrete process and file components for the protected root sensor service.
///
/// This adapter deliberately reports the network sensor unavailable. The enclosing service
/// therefore refuses its arm acknowledgement and cannot release a package until an equally
/// concrete protected network component is composed with it.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RootProcessServiceCollectorStateV1 {
    Unvalidated,
    Ready,
    Armed,
    LeaderAttached,
    Finished,
    Aborted,
}

#[cfg(target_os = "linux")]
struct LinuxVzPackageRootProcessServiceCollectorV1 {
    ring_buffer_capacity: usize,
    maximum_source_events: usize,
    state: RootProcessServiceCollectorStateV1,
    process: Option<LinuxVzPackageRootProcessCollectorV1>,
    file: Option<LinuxVzPackageRootFileCollectorV1>,
    completed_process_evidence: Option<LinuxVzPackageRootProcessEvidenceV1>,
    completed_file_evidence: Option<LinuxVzPackageRootFileEvidenceV1>,
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootProcessServiceCollectorV1 {
    #[allow(dead_code)]
    fn new_v1(ring_buffer_capacity: usize, maximum_source_events: usize) -> Self {
        Self {
            ring_buffer_capacity,
            maximum_source_events,
            state: RootProcessServiceCollectorStateV1::Unvalidated,
            process: None,
            file: None,
            completed_process_evidence: None,
            completed_file_evidence: None,
        }
    }
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootSensorServiceCollectorV1 for LinuxVzPackageRootProcessServiceCollectorV1 {
    fn validate_ready_v1(
        &mut self,
        _identity: &LinuxVzPackageRootSensorIdentityV1,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if self.state != RootProcessServiceCollectorStateV1::Unvalidated
            || unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0
            || unsafe { libc::getegid() } != 0
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        self.state = RootProcessServiceCollectorStateV1::Ready;
        Ok(())
    }

    fn arm_v1(
        &mut self,
        context: &RootSensorServiceActionContextV1,
        cgroup_directory: RawFd,
    ) -> Result<RootSensorServiceArmStatusV1, LinuxVzPackageSensorControlErrorV1> {
        if self.state != RootProcessServiceCollectorStateV1::Ready
            || context.leader_pid.is_some()
            || validate_cgroup_directory_descriptor_v1(cgroup_directory)? != context.cgroup_id
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        validate_cgroup_directory_name_v1(cgroup_directory, &context.cgroup_name)?;
        require_exact_cgroup_processes_v1(cgroup_directory, &[])?;
        let mut process = LinuxVzPackageRootProcessCollectorV1::arm_v1(
            context.cgroup_id,
            self.ring_buffer_capacity,
            self.maximum_source_events,
        )
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        process
            .require_healthy_v1()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        let file = match LinuxVzPackageRootFileCollectorV1::arm_v1(
            context.cgroup_id,
            cgroup_directory,
            context.sensor_session_challenge_sha256.clone(),
            self.maximum_source_events,
        ) {
            Ok(file) => file,
            Err(_) => {
                process.abort_v1();
                return Err(LinuxVzPackageSensorControlErrorV1::SensorFault);
            }
        };
        if file.require_healthy_v1().is_err() {
            process.abort_v1();
            return Err(LinuxVzPackageSensorControlErrorV1::SensorFault);
        }
        self.process = Some(process);
        self.file = Some(file);
        self.state = RootProcessServiceCollectorStateV1::Armed;
        Ok(RootSensorServiceArmStatusV1 {
            bpf_drop_count: 0,
            file_sensor_armed: true,
            heartbeat_started: true,
            network_sensor_armed: false,
            process_sensor_armed: true,
        })
    }

    fn leader_attached_v1(
        &mut self,
        context: &RootSensorServiceActionContextV1,
        cgroup_directory: RawFd,
    ) -> Result<RootSensorServiceLeaderStatusV1, LinuxVzPackageSensorControlErrorV1> {
        let leader_pid = context
            .leader_pid
            .filter(|leader_pid| *leader_pid > 1)
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        if self.state != RootProcessServiceCollectorStateV1::Armed
            || validate_cgroup_directory_descriptor_v1(cgroup_directory)? != context.cgroup_id
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        require_exact_cgroup_processes_v1(cgroup_directory, &[leader_pid])?;
        let file = self
            .file
            .as_mut()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        file.leader_attached_before_release_v1(leader_pid)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        file.require_healthy_v1()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        let process = self
            .process
            .as_mut()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        process
            .leader_attached_before_release_v1(leader_pid)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        process
            .require_healthy_v1()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        self.state = RootProcessServiceCollectorStateV1::LeaderAttached;
        Ok(RootSensorServiceLeaderStatusV1 {
            bpf_drop_count: 0,
            file_sensor_active: true,
            heartbeat_count: 1,
            network_sensor_active: false,
            process_sensor_active: true,
        })
    }

    fn fault_signal_fds_v1(&self) -> Result<Vec<RawFd>, LinuxVzPackageSensorControlErrorV1> {
        if !matches!(
            self.state,
            RootProcessServiceCollectorStateV1::Armed
                | RootProcessServiceCollectorStateV1::LeaderAttached
        ) {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let process = self
            .process
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?
            .fault_signal_fd_v1()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        let file = self
            .file
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?
            .fault_signal_fd_v1()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        if process == file {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
        }
        Ok(vec![process, file])
    }

    fn finish_v1(
        &mut self,
        context: &RootSensorServiceActionContextV1,
        cgroup_directory: RawFd,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<RootSensorServiceFinishStatusV1, LinuxVzPackageSensorControlErrorV1> {
        let leader_pid = context
            .leader_pid
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        if self.state != RootProcessServiceCollectorStateV1::LeaderAttached
            || validate_cgroup_directory_descriptor_v1(cgroup_directory)? != context.cgroup_id
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        require_exact_cgroup_processes_v1(cgroup_directory, &[])?;
        let collection = self
            .process
            .as_mut()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?
            .finish_after_empty_cgroup_v1(leader_pid, completion)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        self.process.take();
        let file_collection = self
            .file
            .as_mut()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?
            .finish_after_empty_cgroup_v1(
                leader_pid,
                completion.process_ended_monotonic_nanoseconds(),
            )
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        self.file.take();
        let expected = LinuxVzPackageExpectedRootProcessEvidenceV1::from_action_v1(
            context.sensor_session_challenge_sha256.clone(),
            context.launch_contract_sha256.clone(),
            context.process_plan_sha256.clone(),
            context.action_index,
            context.cgroup_name.clone(),
            context.cgroup_id,
            context.root_runner_pid,
            leader_pid,
            &context.launch_identity,
            completion,
        )
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        let process_evidence =
            encode_linux_vz_package_root_process_evidence_v1(&expected, &collection)
                .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        let file_expected = LinuxVzPackageExpectedRootFileEvidenceV1::from_action_v1(
            context.sensor_session_challenge_sha256.clone(),
            context.launch_contract_sha256.clone(),
            context.process_plan_sha256.clone(),
            context.action_index,
            context.cgroup_name.clone(),
            context.cgroup_id,
            context.root_runner_pid,
            leader_pid,
            completion,
        )
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        let file_evidence =
            encode_linux_vz_package_root_file_evidence_v1(&file_expected, &file_collection)
                .map_err(|_| LinuxVzPackageSensorControlErrorV1::SensorFault)?;
        self.completed_process_evidence = Some(process_evidence);
        self.completed_file_evidence = Some(file_evidence);
        self.state = RootProcessServiceCollectorStateV1::Finished;
        // Process and file evidence alone cannot be represented as complete protected sensor
        // output. The composite adapter must add typed network evidence and global correlation
        // before this service can return a finish status.
        Err(LinuxVzPackageSensorControlErrorV1::InvalidState)
    }

    fn abort_v1(
        &mut self,
        _context: Option<&RootSensorServiceActionContextV1>,
        _cgroup_directory: Option<RawFd>,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if let Some(process) = self.process.as_mut() {
            process.abort_v1();
        }
        if let Some(file) = self.file.as_mut() {
            file.abort_v1();
        }
        self.process.take();
        self.file.take();
        if self.state != RootProcessServiceCollectorStateV1::Finished {
            self.state = RootProcessServiceCollectorStateV1::Aborted;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageRootProcessServiceCollectorV1 {
    fn drop(&mut self) {
        let _ = self.abort_v1(None, None);
    }
}

#[cfg(target_os = "linux")]
struct RootSensorServiceSessionV1<'a> {
    stream: UnixStream,
    identity: LinuxVzPackageRootSensorIdentityV1,
    root_runner_pid: u32,
    session: Option<SensorSessionBindingWireV1>,
    next_control_sequence: u64,
    state: RootSensorServiceStateV1,
    active: Option<RootSensorServiceActiveActionV1>,
    collector: &'a mut dyn LinuxVzPackageRootSensorServiceCollectorV1,
}

#[cfg(target_os = "linux")]
impl Drop for RootSensorServiceSessionV1<'_> {
    fn drop(&mut self) {
        if !matches!(
            self.state,
            RootSensorServiceStateV1::Finished | RootSensorServiceStateV1::Aborted
        ) {
            let _ = self.collector.abort_v1(
                self.active.as_ref().map(|active| &active.context),
                self.active
                    .as_ref()
                    .map(|active| active.cgroup_directory.as_raw_fd()),
            );
            self.active.take();
        }
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

/// Drives one protected root-sensor control session.
///
/// This entry point is intentionally crate-private while the production streaming collector is
/// unfinished. Every exit before a successful finish or abort invokes collector teardown and
/// releases the received cgroup descriptor.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
fn serve_linux_vz_package_root_sensor_control_session_v1(
    control_fd: OwnedFd,
    qualified_telemetry_backend_sha256: Sha256Digest,
    guest_evidence_signer_sha256: Sha256Digest,
    protected_sensor_bundle_sha256: Sha256Digest,
    sensor_configuration_sha256: Sha256Digest,
    collector: &mut dyn LinuxVzPackageRootSensorServiceCollectorV1,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    let identity = LinuxVzPackageRootSensorIdentityV1::from_measured_guest_components_v1(
        qualified_telemetry_backend_sha256,
        guest_evidence_signer_sha256,
        protected_sensor_bundle_sha256,
        sensor_configuration_sha256,
    )?;
    let stream = UnixStream::from(control_fd);
    let root_runner_pid = validate_root_sensor_stream_v1(&stream)?;
    if root_runner_pid <= 1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_SECONDS_V1)))
        .and_then(|()| {
            stream.set_write_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_SECONDS_V1)))
        })
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    if let Err(error) = collector.validate_ready_v1(&identity) {
        let _ = collector.abort_v1(None, None);
        return Err(error);
    }
    RootSensorServiceSessionV1 {
        stream,
        identity,
        root_runner_pid,
        session: None,
        next_control_sequence: 1,
        state: RootSensorServiceStateV1::AwaitingOpen,
        active: None,
        collector,
    }
    .run_v1()
}

#[cfg(target_os = "linux")]
impl RootSensorServiceSessionV1<'_> {
    fn run_v1(&mut self) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        self.open_session_v1()?;
        let (frame, descriptor) = self.receive_request_v1()?;
        match frame.kind() {
            LinuxVzPackageSensorControlFrameKindV1::Abort => {
                self.abort_from_frame_v1(frame, descriptor)?;
                return Ok(());
            }
            LinuxVzPackageSensorControlFrameKindV1::Arm => {
                self.arm_from_frame_v1(frame, descriptor)?;
            }
            _ => return Err(LinuxVzPackageSensorControlErrorV1::InvalidState),
        }

        let (frame, descriptor) = self.receive_request_v1()?;
        match frame.kind() {
            LinuxVzPackageSensorControlFrameKindV1::Abort => {
                self.abort_from_frame_v1(frame, descriptor)?;
                return Ok(());
            }
            LinuxVzPackageSensorControlFrameKindV1::LeaderAttached => {
                self.leader_from_frame_v1(frame, descriptor)?;
            }
            _ => return Err(LinuxVzPackageSensorControlErrorV1::InvalidState),
        }

        let (frame, descriptor) = self.receive_request_or_sensor_fault_v1()?;
        match frame.kind() {
            LinuxVzPackageSensorControlFrameKindV1::Abort => {
                self.abort_from_frame_v1(frame, descriptor)?;
            }
            LinuxVzPackageSensorControlFrameKindV1::Finish => {
                self.finish_from_frame_v1(frame, descriptor)?;
            }
            _ => return Err(LinuxVzPackageSensorControlErrorV1::InvalidState),
        }
        Ok(())
    }

    fn open_session_v1(&mut self) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if self.state != RootSensorServiceStateV1::AwaitingOpen {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let (frame, descriptor) = self.receive_request_v1()?;
        if frame.kind() != LinuxVzPackageSensorControlFrameKindV1::OpenSession
            || descriptor.is_some()
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let request: SensorOpenRequestWireV1 = decode_canonical_payload_v1(frame.payload())?;
        require_control_sequence_v1(&request.control_sequence, frame.sequence())?;
        if request.operation != "open_session"
            || request.public_network_route_present
            || request.root_runner_gid != "0"
            || request.root_runner_uid != "0"
            || request.schema_version != LINUX_VZ_PACKAGE_SENSOR_CONTROL_OPEN_SCHEMA_V1
            || request.sync_back
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        validate_service_session_binding_v1(&self.identity, &request.session)?;
        self.session = Some(request.session.clone());
        let ack_sequence = self.next_control_sequence;
        let ack = SensorOpenAckWireV1 {
            control_sequence: ack_sequence.to_string(),
            operation: "open_session_ack".to_string(),
            previous_session_present: false,
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_OPEN_ACK_SCHEMA_V1.to_string(),
            sensor_assets_measured: true,
            sensor_ready: true,
            service_gid: "0".to_string(),
            service_pid: unsafe { libc::getpid() }.to_string(),
            service_uid: "0".to_string(),
            session: request.session,
            signing_material_protected: true,
            sync_back: false,
        };
        self.send_json_v1(LinuxVzPackageSensorControlFrameKindV1::OpenSessionAck, &ack)?;
        self.state = RootSensorServiceStateV1::SessionOpen;
        Ok(())
    }

    fn arm_from_frame_v1(
        &mut self,
        frame: LinuxVzPackageSensorControlFrameV1,
        descriptor: Option<OwnedFd>,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if self.state != RootSensorServiceStateV1::SessionOpen {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let descriptor = descriptor.ok_or(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor)?;
        let request: SensorArmRequestWireV2 = decode_canonical_payload_v1(frame.payload())?;
        require_control_sequence_v1(&request.control_sequence, frame.sequence())?;
        self.validate_common_action_request_v1(RootSensorServiceCommonRequestV1 {
            session: &request.session,
            schema_version: &request.schema_version,
            expected_schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_SCHEMA_V2,
            operation: &request.operation,
            expected_operation: "arm",
            public_network_route_present: request.public_network_route_present,
            sync_back: request.sync_back,
        })?;
        if !request.cgroup_directory_fd_transferred {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        let action_index = usize::try_from(decimal_u64_v1(&request.action_index)?)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
        if request.cgroup_name != format!("whoathere-package-action-{action_index}") {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        validate_action_digests_v1(
            &request.launch_contract_sha256,
            &request.process_plan_sha256,
        )?;
        let launch_identity = process_launch_identity_from_arm_request_v2(&request)?;
        let cgroup_id = validate_cgroup_directory_descriptor_v1(descriptor.as_raw_fd())?;
        validate_cgroup_directory_name_v1(descriptor.as_raw_fd(), &request.cgroup_name)?;
        require_exact_cgroup_processes_v1(descriptor.as_raw_fd(), &[])?;
        let context = RootSensorServiceActionContextV1 {
            sensor_session_challenge_sha256: self
                .session_v1()?
                .sensor_session_challenge_sha256
                .clone(),
            launch_contract_sha256: request.launch_contract_sha256,
            launch_identity,
            process_plan_sha256: request.process_plan_sha256,
            action_index,
            cgroup_name: request.cgroup_name,
            cgroup_id,
            root_runner_pid: self.root_runner_pid,
            leader_pid: None,
        };
        self.active = Some(RootSensorServiceActiveActionV1 {
            context: context.clone(),
            cgroup_directory: descriptor,
        });
        let active = self
            .active
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        let status = self
            .collector
            .arm_v1(&context, active.cgroup_directory.as_raw_fd())?;
        let fault_signal_fds = self.collector.fault_signal_fds_v1()?;
        if status.bpf_drop_count != 0
            || !valid_fault_signal_fds_v1(&fault_signal_fds, self.stream.as_raw_fd())
            || !status.file_sensor_armed
            || !status.heartbeat_started
            || !status.network_sensor_armed
            || !status.process_sensor_armed
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        let ack_sequence = self.next_control_sequence;
        let ack = SensorArmAckWireV2 {
            action_index: context.action_index.to_string(),
            argv_item_count: context.launch_identity.argv_item_count().to_string(),
            argv_sha256: context.launch_identity.argv_sha256().clone(),
            bpf_drop_count: status.bpf_drop_count.to_string(),
            cgroup_directory_fd_received: true,
            cgroup_id: context.cgroup_id.to_string(),
            cgroup_name: context.cgroup_name,
            cgroup_v2_verified: true,
            control_sequence: ack_sequence.to_string(),
            expected_executable_sha256: context.launch_identity.executable_sha256().clone(),
            file_sensor_armed: status.file_sensor_armed,
            heartbeat_started: status.heartbeat_started,
            launch_contract_sha256: context.launch_contract_sha256,
            network_sensor_armed: status.network_sensor_armed,
            operation: "arm_ack".to_string(),
            process_plan_sha256: context.process_plan_sha256,
            process_sensor_armed: status.process_sensor_armed,
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_ACK_SCHEMA_V2.to_string(),
            session: self.session_v1()?.clone(),
            sync_back: false,
        };
        self.send_json_v1(LinuxVzPackageSensorControlFrameKindV1::ArmAck, &ack)?;
        self.state = RootSensorServiceStateV1::Armed;
        Ok(())
    }

    fn leader_from_frame_v1(
        &mut self,
        frame: LinuxVzPackageSensorControlFrameV1,
        descriptor: Option<OwnedFd>,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if self.state != RootSensorServiceStateV1::Armed || descriptor.is_some() {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let request: SensorLeaderRequestWireV2 = decode_canonical_payload_v1(frame.payload())?;
        require_control_sequence_v1(&request.control_sequence, frame.sequence())?;
        self.validate_common_action_request_v1(RootSensorServiceCommonRequestV1 {
            session: &request.session,
            schema_version: &request.schema_version,
            expected_schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_SCHEMA_V2,
            operation: &request.operation,
            expected_operation: "leader_attached",
            public_network_route_present: request.public_network_route_present,
            sync_back: request.sync_back,
        })?;
        let leader_pid = u32::try_from(decimal_u64_v1(&request.leader_pid)?)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
        if leader_pid <= 1 {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        let active = self
            .active
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        require_action_binding_v1(
            &active.context,
            &request.action_index,
            &request.cgroup_id,
            &request.cgroup_name,
            &request.launch_contract_sha256,
            &request.process_plan_sha256,
        )?;
        require_exact_cgroup_processes_v1(active.cgroup_directory.as_raw_fd(), &[leader_pid])?;
        require_proc_cgroup_membership_v1(
            leader_pid,
            &active.context.cgroup_name,
            active.context.root_runner_pid,
        )?;
        let mut context = active.context.clone();
        context.leader_pid = Some(leader_pid);
        if let Some(active) = self.active.as_mut() {
            active.context.leader_pid = Some(leader_pid);
        }
        let active = self
            .active
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        let status = self
            .collector
            .leader_attached_v1(&context, active.cgroup_directory.as_raw_fd())?;
        let fault_signal_fds = self.collector.fault_signal_fds_v1()?;
        if status.bpf_drop_count != 0
            || !valid_fault_signal_fds_v1(&fault_signal_fds, self.stream.as_raw_fd())
            || status.heartbeat_count < 1
            || !status.file_sensor_active
            || !status.network_sensor_active
            || !status.process_sensor_active
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        let ack_sequence = self.next_control_sequence;
        let ack = SensorLeaderAckWireV2 {
            action_index: context.action_index.to_string(),
            bpf_drop_count: status.bpf_drop_count.to_string(),
            cgroup_id: context.cgroup_id.to_string(),
            cgroup_name: context.cgroup_name,
            control_sequence: ack_sequence.to_string(),
            file_sensor_active: status.file_sensor_active,
            heartbeat_count: status.heartbeat_count.to_string(),
            launch_contract_sha256: context.launch_contract_sha256,
            leader_blocked_before_release: true,
            leader_parent_pid: context.root_runner_pid.to_string(),
            leader_parent_pid_verified: true,
            leader_pid: leader_pid.to_string(),
            network_sensor_active: status.network_sensor_active,
            operation: "leader_attached_ack".to_string(),
            process_plan_sha256: context.process_plan_sha256,
            process_sensor_active: status.process_sensor_active,
            proc_cgroup_membership_verified: true,
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_ACK_SCHEMA_V2.to_string(),
            session: self.session_v1()?.clone(),
            sync_back: false,
        };
        self.send_json_v1(
            LinuxVzPackageSensorControlFrameKindV1::LeaderAttachedAck,
            &ack,
        )?;
        self.state = RootSensorServiceStateV1::LeaderCorrelated;
        Ok(())
    }

    fn finish_from_frame_v1(
        &mut self,
        frame: LinuxVzPackageSensorControlFrameV1,
        descriptor: Option<OwnedFd>,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if self.state != RootSensorServiceStateV1::LeaderCorrelated || descriptor.is_some() {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let request: SensorFinishRequestWireV3 = decode_canonical_payload_v1(frame.payload())?;
        require_control_sequence_v1(&request.control_sequence, frame.sequence())?;
        self.validate_common_action_request_v1(RootSensorServiceCommonRequestV1 {
            session: &request.session,
            schema_version: &request.schema_version,
            expected_schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_SCHEMA_V3,
            operation: &request.operation,
            expected_operation: "finish",
            public_network_route_present: request.public_network_route_present,
            sync_back: request.sync_back,
        })?;
        let leader_pid = u32::try_from(decimal_u64_v1(&request.leader_pid)?)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
        let completion = process_completion_from_finish_request_v3(&request)?;
        if leader_pid <= 1 {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        let active = self
            .active
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        require_action_binding_v1(
            &active.context,
            &request.action_index,
            &request.cgroup_id,
            &request.cgroup_name,
            &request.launch_contract_sha256,
            &request.process_plan_sha256,
        )?;
        if active.context.leader_pid != Some(leader_pid) {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        require_exact_cgroup_processes_v1(active.cgroup_directory.as_raw_fd(), &[])?;
        let context = active.context.clone();
        let status =
            self.collector
                .finish_v1(&context, active.cgroup_directory.as_raw_fd(), &completion)?;
        require_exact_cgroup_processes_v1(active.cgroup_directory.as_raw_fd(), &[])?;
        validate_service_finish_status_v1(&status)?;
        let RootSensorServiceFinishStatusV1 {
            output,
            descendant_teardown_complete,
            dropped_event_count,
            file_sensor_healthy,
            heartbeat_count,
            network_sensor_healthy,
            process_sensor_healthy,
            sensor_teardown_complete,
        } = status;
        let correlation_sha256 = Sha256Digest::from_bytes(&output.correlation);
        let process_evidence_sha256 = Sha256Digest::from_bytes(&output.process_evidence);
        let file_evidence_sha256 = Sha256Digest::from_bytes(&output.file_evidence);
        let network_evidence_sha256 = Sha256Digest::from_bytes(&output.network_evidence);
        let correlation_byte_length = output.correlation.len();
        let process_evidence_byte_length = output.process_evidence.len();
        let file_evidence_byte_length = output.file_evidence.len();
        let network_evidence_byte_length = output.network_evidence.len();
        self.active.take();
        self.send_payload_v1(
            LinuxVzPackageSensorControlFrameKindV1::CorrelationEvidence,
            &output.correlation,
            MAX_LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_BYTES_V1,
        )?;
        self.send_payload_v1(
            LinuxVzPackageSensorControlFrameKindV1::ProcessEvidence,
            &output.process_evidence,
            MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
        )?;
        self.send_payload_v1(
            LinuxVzPackageSensorControlFrameKindV1::FileEvidence,
            &output.file_evidence,
            MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
        )?;
        self.send_payload_v1(
            LinuxVzPackageSensorControlFrameKindV1::NetworkEvidence,
            &output.network_evidence,
            MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
        )?;
        let ack_sequence = self.next_control_sequence;
        let ack = SensorFinishAckWireV3 {
            action_index: context.action_index.to_string(),
            cgroup_empty_after_reap: true,
            cgroup_fd_released: true,
            cgroup_id: context.cgroup_id.to_string(),
            cgroup_name: context.cgroup_name,
            cgroup_present_during_sensor_finalize: true,
            control_sequence: ack_sequence.to_string(),
            correlation_byte_length: correlation_byte_length.to_string(),
            correlation_sha256,
            descendant_teardown_complete,
            dropped_event_count: dropped_event_count.to_string(),
            file_evidence_byte_length: file_evidence_byte_length.to_string(),
            file_evidence_sha256,
            file_sensor_healthy,
            heartbeat_count: heartbeat_count.to_string(),
            launch_contract_sha256: context.launch_contract_sha256,
            leader_exit_status: completion.exit_status().map(|value| value.to_string()),
            leader_pid: leader_pid.to_string(),
            leader_supervisor_wait_status: completion.supervisor_wait_status().to_string(),
            leader_terminal: completion.terminal(),
            leader_termination_signal: completion
                .termination_signal()
                .map(|value| value.to_string()),
            network_evidence_byte_length: network_evidence_byte_length.to_string(),
            network_evidence_sha256,
            network_sensor_healthy,
            operation: "finish_ack".to_string(),
            process_evidence_byte_length: process_evidence_byte_length.to_string(),
            process_evidence_sha256,
            process_plan_sha256: context.process_plan_sha256,
            process_sensor_healthy,
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_ACK_SCHEMA_V3.to_string(),
            sensor_teardown_complete,
            session: self.session_v1()?.clone(),
            sync_back: false,
        };
        self.send_json_v1(LinuxVzPackageSensorControlFrameKindV1::FinishAck, &ack)?;
        self.state = RootSensorServiceStateV1::Finished;
        Ok(())
    }

    fn abort_from_frame_v1(
        &mut self,
        frame: LinuxVzPackageSensorControlFrameV1,
        descriptor: Option<OwnedFd>,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if descriptor.is_some()
            || !matches!(
                self.state,
                RootSensorServiceStateV1::SessionOpen
                    | RootSensorServiceStateV1::Armed
                    | RootSensorServiceStateV1::LeaderCorrelated
            )
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let request: SensorAbortRequestWireV1 = decode_canonical_payload_v1(frame.payload())?;
        require_control_sequence_v1(&request.control_sequence, frame.sequence())?;
        self.validate_common_action_request_v1(RootSensorServiceCommonRequestV1 {
            session: &request.session,
            schema_version: &request.schema_version,
            expected_schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ABORT_SCHEMA_V1,
            operation: &request.operation,
            expected_operation: "abort",
            public_network_route_present: request.public_network_route_present,
            sync_back: request.sync_back,
        })?;
        let expected_prior_state = self
            .state
            .as_observer_state_v1()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        if request.prior_state != expected_prior_state {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        validate_abort_action_binding_v1(self.active.as_ref(), &request)?;
        self.collector.abort_v1(
            self.active.as_ref().map(|active| &active.context),
            self.active
                .as_ref()
                .map(|active| active.cgroup_directory.as_raw_fd()),
        )?;
        self.active.take();
        let ack_sequence = self.next_control_sequence;
        let ack = SensorAbortAckWireV1 {
            abort_evidence_emitted: false,
            cgroup_fd_released: true,
            control_sequence: ack_sequence.to_string(),
            operation: "abort_ack".to_string(),
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ABORT_ACK_SCHEMA_V1.to_string(),
            sensor_teardown_complete: true,
            session: self.session_v1()?.clone(),
            session_aborted: true,
            sync_back: false,
        };
        self.send_json_v1(LinuxVzPackageSensorControlFrameKindV1::AbortAck, &ack)?;
        self.state = RootSensorServiceStateV1::Aborted;
        Ok(())
    }

    fn validate_common_action_request_v1(
        &self,
        request: RootSensorServiceCommonRequestV1<'_>,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if request.session != self.session_v1()?
            || request.schema_version != request.expected_schema_version
            || request.operation != request.expected_operation
            || request.public_network_route_present
            || request.sync_back
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        Ok(())
    }

    fn session_v1(
        &self,
    ) -> Result<&SensorSessionBindingWireV1, LinuxVzPackageSensorControlErrorV1> {
        self.session
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)
    }

    fn receive_request_v1(
        &mut self,
    ) -> Result<
        (LinuxVzPackageSensorControlFrameV1, Option<OwnedFd>),
        LinuxVzPackageSensorControlErrorV1,
    > {
        let (frame, descriptor) = receive_control_frame_with_descriptor_v1(
            &mut self.stream,
            MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_MESSAGE_BYTES_V1,
        )?;
        if frame.sequence() != self.next_control_sequence {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence);
        }
        self.next_control_sequence = self
            .next_control_sequence
            .checked_add(1)
            .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
        Ok((frame, descriptor))
    }

    fn receive_request_or_sensor_fault_v1(
        &mut self,
    ) -> Result<
        (LinuxVzPackageSensorControlFrameV1, Option<OwnedFd>),
        LinuxVzPackageSensorControlErrorV1,
    > {
        if self.state != RootSensorServiceStateV1::LeaderCorrelated {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let fault_signal_fds = self.collector.fault_signal_fds_v1()?;
        if !valid_fault_signal_fds_v1(&fault_signal_fds, self.stream.as_raw_fd()) {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
        }
        let mut descriptors = Vec::with_capacity(fault_signal_fds.len().saturating_add(1));
        descriptors.push(libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        });
        descriptors.extend(fault_signal_fds.iter().map(|descriptor| libc::pollfd {
            fd: *descriptor,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        }));
        loop {
            for descriptor in &mut descriptors {
                descriptor.revents = 0;
            }
            let result = unsafe {
                libc::poll(
                    descriptors.as_mut_ptr(),
                    descriptors.len() as libc::nfds_t,
                    i32::try_from(CONTROL_TIMEOUT_SECONDS_V1 * 1_000)
                        .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?,
                )
            };
            if result == 0 {
                return Err(LinuxVzPackageSensorControlErrorV1::Io);
            }
            if result < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(LinuxVzPackageSensorControlErrorV1::Io);
            }
            if descriptors[1..]
                .iter()
                .any(|descriptor| descriptor.revents != 0)
            {
                return self.handle_sensor_fault_v1();
            }
            if descriptors[0].revents & libc::POLLIN != 0 {
                return self.receive_request_v1();
            }
            if descriptors[0].revents != 0 {
                return Err(LinuxVzPackageSensorControlErrorV1::Io);
            }
        }
    }

    fn handle_sensor_fault_v1<T>(&mut self) -> Result<T, LinuxVzPackageSensorControlErrorV1> {
        if let Some(active) = self.active.as_ref() {
            let _ = kill_cgroup_from_descriptor_v1(active.cgroup_directory.as_raw_fd());
        }
        let _ = self.collector.abort_v1(
            self.active.as_ref().map(|active| &active.context),
            self.active
                .as_ref()
                .map(|active| active.cgroup_directory.as_raw_fd()),
        );
        self.active.take();
        self.state = RootSensorServiceStateV1::Aborted;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        Err(LinuxVzPackageSensorControlErrorV1::SensorFault)
    }

    fn send_json_v1<T: Serialize>(
        &mut self,
        kind: LinuxVzPackageSensorControlFrameKindV1,
        value: &T,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        let payload = canonical_bytes_v1(value)?;
        self.send_payload_v1(
            kind,
            &payload,
            MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_MESSAGE_BYTES_V1,
        )
    }

    fn send_payload_v1(
        &mut self,
        kind: LinuxVzPackageSensorControlFrameKindV1,
        payload: &[u8],
        maximum_payload_bytes: usize,
    ) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        let frame = encode_linux_vz_package_sensor_control_frame_v1(
            kind,
            self.next_control_sequence,
            payload,
            maximum_payload_bytes,
        )?;
        self.stream
            .write_all(&frame)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
        self.next_control_sequence = self
            .next_control_sequence
            .checked_add(1)
            .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
pub struct LinuxVzPackageRootSensorObserverV1 {
    stream: UnixStream,
    identity: LinuxVzPackageRootSensorIdentityV1,
    sensor_session_challenge_sha256: Sha256Digest,
    peer_pid: u32,
    root_runner_pid: u32,
    next_control_sequence: u64,
    state: RootSensorObserverStateV1,
    active: Option<ActiveSensorBindingV1>,
    channel_usable: bool,
}

#[cfg(target_os = "linux")]
impl fmt::Debug for LinuxVzPackageRootSensorObserverV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootSensorObserverV1")
            .field("identity", &self.identity)
            .field(
                "sensor_session_challenge_sha256",
                &self.sensor_session_challenge_sha256,
            )
            .field("peer_pid", &self.peer_pid)
            .field("root_runner_pid", &self.root_runner_pid)
            .field("next_control_sequence", &self.next_control_sequence)
            .field("state", &self.state)
            .field("active", &self.active)
            .field("channel_usable", &self.channel_usable)
            .field("stream", &"<root-only-unix-stream>")
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl protected_process_observer_seal::Sealed for LinuxVzPackageRootSensorObserverV1 {}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageRootSensorObserverV1 {
    fn drop(&mut self) {
        if !matches!(
            self.state,
            RootSensorObserverStateV1::Finished | RootSensorObserverStateV1::Aborted
        ) {
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
        }
    }
}

#[cfg(target_os = "linux")]
pub fn connect_linux_vz_package_root_sensor_observer_v1(
    control_fd: OwnedFd,
    backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
) -> Result<LinuxVzPackageRootSensorObserverV1, LinuxVzPackageSensorControlErrorV1> {
    let identity = LinuxVzPackageRootSensorIdentityV1::from_qualified_backend_v1(backend)?;
    let stream = UnixStream::from(control_fd);
    let peer_pid = validate_root_sensor_stream_v1(&stream)?;
    let root_runner_pid = u32::try_from(unsafe { libc::getpid() })
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPeer)?;
    if root_runner_pid <= 1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }
    stream
        .set_read_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_SECONDS_V1)))
        .and_then(|()| {
            stream.set_write_timeout(Some(Duration::from_secs(CONTROL_TIMEOUT_SECONDS_V1)))
        })
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::EntropyUnavailable)?;
    if challenge == [0_u8; 32] {
        return Err(LinuxVzPackageSensorControlErrorV1::EntropyUnavailable);
    }
    let mut observer = LinuxVzPackageRootSensorObserverV1 {
        stream,
        identity,
        sensor_session_challenge_sha256: Sha256Digest::from_bytes(&challenge),
        peer_pid,
        root_runner_pid,
        next_control_sequence: 1,
        state: RootSensorObserverStateV1::Opening,
        active: None,
        channel_usable: true,
    };
    observer.open_session_v1()?;
    Ok(observer)
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootSensorObserverV1 {
    fn open_session_v1(&mut self) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
        if self.state != RootSensorObserverStateV1::Opening {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let request_sequence = self.next_control_sequence;
        let request = SensorOpenRequestWireV1 {
            control_sequence: request_sequence.to_string(),
            operation: "open_session".to_string(),
            public_network_route_present: false,
            root_runner_gid: "0".to_string(),
            root_runner_uid: "0".to_string(),
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_OPEN_SCHEMA_V1.to_string(),
            session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
            sync_back: false,
        };
        self.send_json_v1(
            LinuxVzPackageSensorControlFrameKindV1::OpenSession,
            &request,
        )?;
        let (ack, ack_sequence): (SensorOpenAckWireV1, u64) =
            self.receive_json_v1(LinuxVzPackageSensorControlFrameKindV1::OpenSessionAck)?;
        let expected = SensorOpenAckWireV1 {
            control_sequence: ack_sequence.to_string(),
            operation: "open_session_ack".to_string(),
            previous_session_present: false,
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_OPEN_ACK_SCHEMA_V1.to_string(),
            sensor_assets_measured: true,
            sensor_ready: true,
            service_gid: "0".to_string(),
            service_pid: self.peer_pid.to_string(),
            service_uid: "0".to_string(),
            session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
            signing_material_protected: true,
            sync_back: false,
        };
        if ack != expected {
            self.state = RootSensorObserverStateV1::Faulted;
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        self.state = RootSensorObserverStateV1::SessionOpen;
        Ok(())
    }

    fn send_json_v1<T: Serialize>(
        &mut self,
        kind: LinuxVzPackageSensorControlFrameKindV1,
        value: &T,
    ) -> Result<u64, LinuxVzPackageSensorControlErrorV1> {
        let payload = canonical_bytes_v1(value)?;
        self.send_payload_v1(kind, &payload, None)
    }

    fn send_json_with_fd_v1<T: Serialize>(
        &mut self,
        kind: LinuxVzPackageSensorControlFrameKindV1,
        value: &T,
        descriptor: RawFd,
    ) -> Result<u64, LinuxVzPackageSensorControlErrorV1> {
        let payload = canonical_bytes_v1(value)?;
        self.send_payload_v1(kind, &payload, Some(descriptor))
    }

    fn send_payload_v1(
        &mut self,
        kind: LinuxVzPackageSensorControlFrameKindV1,
        payload: &[u8],
        descriptor: Option<RawFd>,
    ) -> Result<u64, LinuxVzPackageSensorControlErrorV1> {
        if !self.channel_usable {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let sequence = self.next_control_sequence;
        let frame = encode_linux_vz_package_sensor_control_frame_v1(
            kind,
            sequence,
            payload,
            MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_MESSAGE_BYTES_V1,
        )?;
        let result = match descriptor {
            Some(descriptor) => send_frame_with_descriptor_v1(&mut self.stream, &frame, descriptor),
            None => self
                .stream
                .write_all(&frame)
                .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io),
        };
        if let Err(error) = result {
            self.channel_usable = false;
            return Err(error);
        }
        self.next_control_sequence = self
            .next_control_sequence
            .checked_add(1)
            .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
        Ok(sequence)
    }

    fn receive_json_v1<T>(
        &mut self,
        expected_kind: LinuxVzPackageSensorControlFrameKindV1,
    ) -> Result<(T, u64), LinuxVzPackageSensorControlErrorV1>
    where
        T: for<'de> Deserialize<'de> + Serialize,
    {
        let frame = self.receive_payload_v1(
            expected_kind,
            MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_MESSAGE_BYTES_V1,
        )?;
        let value = decode_canonical_payload_v1(frame.payload())?;
        Ok((value, frame.sequence()))
    }

    fn receive_payload_v1(
        &mut self,
        expected_kind: LinuxVzPackageSensorControlFrameKindV1,
        maximum_payload_bytes: usize,
    ) -> Result<LinuxVzPackageSensorControlFrameV1, LinuxVzPackageSensorControlErrorV1> {
        if !self.channel_usable {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        let sequence = self.next_control_sequence;
        let result = read_control_frame_v1(&mut self.stream, maximum_payload_bytes);
        let frame = match result {
            Ok(frame) => frame,
            Err(error) => {
                self.channel_usable = false;
                return Err(error);
            }
        };
        if frame.kind() != expected_kind || frame.sequence() != sequence {
            self.channel_usable = false;
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence);
        }
        self.next_control_sequence = self
            .next_control_sequence
            .checked_add(1)
            .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
        Ok(frame)
    }

    fn active_binding_v1(
        &self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
        cgroup_name: &str,
    ) -> Result<&ActiveSensorBindingV1, LinuxVzPackageSensorControlErrorV1> {
        let active = self
            .active
            .as_ref()
            .ok_or(LinuxVzPackageSensorControlErrorV1::InvalidState)?;
        if active.launch_contract_sha256 != *contract.launch_contract_sha256()
            || active.launch_identity
                != LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(contract)
                    .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?
            || active.process_plan_sha256 != *contract.process_plan_sha256()
            || active.action_index != contract.action_index()
            || active.cgroup_name != cgroup_name
        {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
        }
        Ok(active)
    }
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageProtectedProcessObserverV1 for LinuxVzPackageRootSensorObserverV1 {
    fn sensor_session_challenge_sha256_v1(&self) -> &Sha256Digest {
        &self.sensor_session_challenge_sha256
    }

    fn arm_v1(
        &mut self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
        cgroup_name: &str,
        cgroup_directory_fd: RawFd,
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        let result = (|| {
            if self.state != RootSensorObserverStateV1::SessionOpen
                || contract.sync_back_permitted()
                || cgroup_name != format!("whoathere-package-action-{}", contract.action_index())
            {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
            }
            let cgroup_id = validate_cgroup_directory_descriptor_v1(cgroup_directory_fd)?;
            let launch_identity = LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(contract)
                .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
            let request_sequence = self.next_control_sequence;
            let request = SensorArmRequestWireV2 {
                action_index: contract.action_index().to_string(),
                argv_item_count: launch_identity.argv_item_count().to_string(),
                argv_sha256: launch_identity.argv_sha256().clone(),
                cgroup_directory_fd_transferred: true,
                cgroup_name: cgroup_name.to_string(),
                control_sequence: request_sequence.to_string(),
                expected_executable_sha256: launch_identity.executable_sha256().clone(),
                launch_contract_sha256: contract.launch_contract_sha256().clone(),
                operation: "arm".to_string(),
                process_plan_sha256: contract.process_plan_sha256().clone(),
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_SCHEMA_V2.to_string(),
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                sync_back: false,
            };
            self.send_json_with_fd_v1(
                LinuxVzPackageSensorControlFrameKindV1::Arm,
                &request,
                cgroup_directory_fd,
            )?;
            let (ack, ack_sequence): (SensorArmAckWireV2, u64) =
                self.receive_json_v1(LinuxVzPackageSensorControlFrameKindV1::ArmAck)?;
            let expected = SensorArmAckWireV2 {
                action_index: contract.action_index().to_string(),
                argv_item_count: launch_identity.argv_item_count().to_string(),
                argv_sha256: launch_identity.argv_sha256().clone(),
                bpf_drop_count: "0".to_string(),
                cgroup_directory_fd_received: true,
                cgroup_id: cgroup_id.to_string(),
                cgroup_name: cgroup_name.to_string(),
                cgroup_v2_verified: true,
                control_sequence: ack_sequence.to_string(),
                expected_executable_sha256: launch_identity.executable_sha256().clone(),
                file_sensor_armed: true,
                heartbeat_started: true,
                launch_contract_sha256: contract.launch_contract_sha256().clone(),
                network_sensor_armed: true,
                operation: "arm_ack".to_string(),
                process_plan_sha256: contract.process_plan_sha256().clone(),
                process_sensor_armed: true,
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_ACK_SCHEMA_V2.to_string(),
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                sync_back: false,
            };
            if ack != expected {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
            }
            Ok(ActiveSensorBindingV1 {
                launch_contract_sha256: contract.launch_contract_sha256().clone(),
                launch_identity,
                process_plan_sha256: contract.process_plan_sha256().clone(),
                action_index: contract.action_index(),
                cgroup_name: cgroup_name.to_string(),
                cgroup_id,
                root_runner_pid: self.root_runner_pid,
                leader_pid: None,
            })
        })();
        match result {
            Ok(active) => {
                self.active = Some(active);
                self.state = RootSensorObserverStateV1::Armed;
                Ok(())
            }
            Err(_) => {
                self.state = RootSensorObserverStateV1::Faulted;
                Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorUnavailable)
            }
        }
    }

    fn leader_attached_v1(
        &mut self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
        cgroup_name: &str,
        leader_pid: u32,
    ) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        let result = (|| {
            if self.state != RootSensorObserverStateV1::Armed || leader_pid <= 1 {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
            }
            let active = self.active_binding_v1(contract, cgroup_name)?.clone();
            if active.leader_pid.is_some() || active.root_runner_pid != self.root_runner_pid {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
            }
            let request_sequence = self.next_control_sequence;
            let request = SensorLeaderRequestWireV2 {
                action_index: active.action_index.to_string(),
                cgroup_id: active.cgroup_id.to_string(),
                cgroup_name: active.cgroup_name.clone(),
                control_sequence: request_sequence.to_string(),
                launch_contract_sha256: active.launch_contract_sha256.clone(),
                leader_pid: leader_pid.to_string(),
                operation: "leader_attached".to_string(),
                process_plan_sha256: active.process_plan_sha256.clone(),
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_SCHEMA_V2.to_string(),
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                sync_back: false,
            };
            self.send_json_v1(
                LinuxVzPackageSensorControlFrameKindV1::LeaderAttached,
                &request,
            )?;
            let (ack, ack_sequence): (SensorLeaderAckWireV2, u64) =
                self.receive_json_v1(LinuxVzPackageSensorControlFrameKindV1::LeaderAttachedAck)?;
            if decimal_u64_v1(&ack.heartbeat_count)? < 1 {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
            }
            let expected = SensorLeaderAckWireV2 {
                action_index: active.action_index.to_string(),
                bpf_drop_count: "0".to_string(),
                cgroup_id: active.cgroup_id.to_string(),
                cgroup_name: active.cgroup_name,
                control_sequence: ack_sequence.to_string(),
                file_sensor_active: true,
                heartbeat_count: ack.heartbeat_count.clone(),
                launch_contract_sha256: active.launch_contract_sha256,
                leader_blocked_before_release: true,
                leader_parent_pid: active.root_runner_pid.to_string(),
                leader_parent_pid_verified: true,
                leader_pid: leader_pid.to_string(),
                network_sensor_active: true,
                operation: "leader_attached_ack".to_string(),
                process_plan_sha256: active.process_plan_sha256,
                process_sensor_active: true,
                proc_cgroup_membership_verified: true,
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_LEADER_ACK_SCHEMA_V2.to_string(),
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                sync_back: false,
            };
            if ack != expected {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                if let Some(active) = self.active.as_mut() {
                    active.leader_pid = Some(leader_pid);
                }
                self.state = RootSensorObserverStateV1::LeaderCorrelated;
                Ok(())
            }
            Err(_) => {
                self.state = RootSensorObserverStateV1::Faulted;
                Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorCorrelationFailed)
            }
        }
    }

    fn require_healthy_v1(&mut self) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        if self.state != RootSensorObserverStateV1::LeaderCorrelated || !self.channel_usable {
            return Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorUnavailable);
        }
        let mut descriptor = libc::pollfd {
            fd: self.stream.as_raw_fd(),
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        loop {
            descriptor.revents = 0;
            let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
            if result == 0 {
                return Ok(());
            }
            if result > 0 {
                self.channel_usable = false;
                self.state = RootSensorObserverStateV1::Faulted;
                return Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorUnavailable);
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                self.channel_usable = false;
                self.state = RootSensorObserverStateV1::Faulted;
                return Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorUnavailable);
            }
        }
    }

    fn finish_v1(
        &mut self,
        contract: &LinuxVzPackageProcessLaunchContractV1,
        cgroup_name: &str,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<LinuxVzPackageProtectedSensorOutputV1, LinuxVzPackageProcessSupervisorErrorV1> {
        let result = (|| {
            if self.state != RootSensorObserverStateV1::LeaderCorrelated || leader_pid <= 1 {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
            }
            LinuxVzPackageProcessCompletionV1::from_parts_v1(
                completion.process_started_monotonic_nanoseconds(),
                completion.process_ended_monotonic_nanoseconds(),
                completion.supervisor_wait_status(),
                completion.terminal(),
                completion.exit_status(),
                completion.termination_signal(),
            )
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
            let active = self.active_binding_v1(contract, cgroup_name)?.clone();
            if active.leader_pid != Some(leader_pid) {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
            }
            let request_sequence = self.next_control_sequence;
            let request = SensorFinishRequestWireV3 {
                action_index: active.action_index.to_string(),
                cgroup_id: active.cgroup_id.to_string(),
                cgroup_name: active.cgroup_name.clone(),
                control_sequence: request_sequence.to_string(),
                launch_contract_sha256: active.launch_contract_sha256.clone(),
                leader_exit_status: completion.exit_status().map(|value| value.to_string()),
                leader_pid: leader_pid.to_string(),
                leader_supervisor_wait_status: completion.supervisor_wait_status().to_string(),
                leader_terminal: completion.terminal(),
                leader_termination_signal: completion
                    .termination_signal()
                    .map(|value| value.to_string()),
                operation: "finish".to_string(),
                process_ended_monotonic_nanoseconds: completion
                    .process_ended_monotonic_nanoseconds()
                    .to_string(),
                process_plan_sha256: active.process_plan_sha256.clone(),
                process_started_monotonic_nanoseconds: completion
                    .process_started_monotonic_nanoseconds()
                    .to_string(),
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_SCHEMA_V3.to_string(),
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                sync_back: false,
            };
            self.send_json_v1(LinuxVzPackageSensorControlFrameKindV1::Finish, &request)?;
            let correlation = self
                .receive_payload_v1(
                    LinuxVzPackageSensorControlFrameKindV1::CorrelationEvidence,
                    MAX_LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_BYTES_V1,
                )?
                .payload;
            let process_evidence = self
                .receive_payload_v1(
                    LinuxVzPackageSensorControlFrameKindV1::ProcessEvidence,
                    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
                )?
                .payload;
            let file_evidence = self
                .receive_payload_v1(
                    LinuxVzPackageSensorControlFrameKindV1::FileEvidence,
                    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
                )?
                .payload;
            let network_evidence = self
                .receive_payload_v1(
                    LinuxVzPackageSensorControlFrameKindV1::NetworkEvidence,
                    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
                )?
                .payload;
            let (ack, ack_sequence): (SensorFinishAckWireV3, u64) =
                self.receive_json_v1(LinuxVzPackageSensorControlFrameKindV1::FinishAck)?;
            if decimal_u64_v1(&ack.heartbeat_count)? < 2
                || decimal_u64_v1(&ack.dropped_event_count)? != 0
            {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
            }
            let expected = SensorFinishAckWireV3 {
                action_index: active.action_index.to_string(),
                cgroup_empty_after_reap: true,
                cgroup_fd_released: true,
                cgroup_id: active.cgroup_id.to_string(),
                cgroup_name: active.cgroup_name,
                cgroup_present_during_sensor_finalize: true,
                control_sequence: ack_sequence.to_string(),
                correlation_byte_length: correlation.len().to_string(),
                correlation_sha256: Sha256Digest::from_bytes(&correlation),
                descendant_teardown_complete: true,
                dropped_event_count: "0".to_string(),
                file_evidence_byte_length: file_evidence.len().to_string(),
                file_evidence_sha256: Sha256Digest::from_bytes(&file_evidence),
                file_sensor_healthy: true,
                heartbeat_count: ack.heartbeat_count.clone(),
                launch_contract_sha256: active.launch_contract_sha256,
                leader_exit_status: completion.exit_status().map(|value| value.to_string()),
                leader_pid: leader_pid.to_string(),
                leader_supervisor_wait_status: completion.supervisor_wait_status().to_string(),
                leader_terminal: completion.terminal(),
                leader_termination_signal: completion
                    .termination_signal()
                    .map(|value| value.to_string()),
                network_evidence_byte_length: network_evidence.len().to_string(),
                network_evidence_sha256: Sha256Digest::from_bytes(&network_evidence),
                network_sensor_healthy: true,
                operation: "finish_ack".to_string(),
                process_evidence_byte_length: process_evidence.len().to_string(),
                process_evidence_sha256: Sha256Digest::from_bytes(&process_evidence),
                process_plan_sha256: active.process_plan_sha256,
                process_sensor_healthy: true,
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_ACK_SCHEMA_V3.to_string(),
                sensor_teardown_complete: true,
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                sync_back: false,
            };
            if ack != expected {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
            }
            Ok(LinuxVzPackageProtectedSensorOutputV1 {
                correlation,
                process_evidence,
                file_evidence,
                network_evidence,
            })
        })();
        match result {
            Ok(output) => {
                self.state = RootSensorObserverStateV1::Finished;
                Ok(output)
            }
            Err(_) => {
                self.state = RootSensorObserverStateV1::Faulted;
                Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorCorrelationFailed)
            }
        }
    }

    fn abort_v1(&mut self) -> Result<(), LinuxVzPackageProcessSupervisorErrorV1> {
        if matches!(
            self.state,
            RootSensorObserverStateV1::Finished | RootSensorObserverStateV1::Aborted
        ) {
            return Ok(());
        }
        if self.state == RootSensorObserverStateV1::Faulted && !self.channel_usable {
            self.active.take();
            self.state = RootSensorObserverStateV1::Aborted;
            let _ = self.stream.shutdown(std::net::Shutdown::Both);
            return Ok(());
        }
        let result = (|| {
            if !self.channel_usable || self.state == RootSensorObserverStateV1::Opening {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
            }
            let prior_state = self.state;
            let active = self.active.clone();
            let request_sequence = self.next_control_sequence;
            let request = SensorAbortRequestWireV1 {
                action_index: active
                    .as_ref()
                    .map(|binding| binding.action_index.to_string()),
                cgroup_id: active.as_ref().map(|binding| binding.cgroup_id.to_string()),
                cgroup_name: active.as_ref().map(|binding| binding.cgroup_name.clone()),
                control_sequence: request_sequence.to_string(),
                launch_contract_sha256: active
                    .as_ref()
                    .map(|binding| binding.launch_contract_sha256.clone()),
                leader_pid: active
                    .as_ref()
                    .and_then(|binding| binding.leader_pid)
                    .map(|pid| pid.to_string()),
                operation: "abort".to_string(),
                prior_state: prior_state.as_str_v1().to_string(),
                process_plan_sha256: active
                    .as_ref()
                    .map(|binding| binding.process_plan_sha256.clone()),
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ABORT_SCHEMA_V1.to_string(),
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                sync_back: false,
            };
            self.send_json_v1(LinuxVzPackageSensorControlFrameKindV1::Abort, &request)?;
            let (ack, ack_sequence): (SensorAbortAckWireV1, u64) =
                self.receive_json_v1(LinuxVzPackageSensorControlFrameKindV1::AbortAck)?;
            let expected = SensorAbortAckWireV1 {
                abort_evidence_emitted: false,
                cgroup_fd_released: true,
                control_sequence: ack_sequence.to_string(),
                operation: "abort_ack".to_string(),
                public_network_route_present: false,
                schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ABORT_ACK_SCHEMA_V1.to_string(),
                sensor_teardown_complete: true,
                session: session_binding_v1(&self.identity, &self.sensor_session_challenge_sha256),
                session_aborted: true,
                sync_back: false,
            };
            if ack != expected {
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
            }
            Ok(())
        })();
        match result {
            Ok(()) => {
                self.active = None;
                self.state = RootSensorObserverStateV1::Aborted;
                Ok(())
            }
            Err(_) => {
                self.state = RootSensorObserverStateV1::Faulted;
                Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorTeardownFailed)
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn require_control_sequence_v1(
    encoded: &str,
    expected: u64,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if decimal_u64_v1(encoded)? != expected {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_service_session_binding_v1(
    identity: &LinuxVzPackageRootSensorIdentityV1,
    session: &SensorSessionBindingWireV1,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    let challenge = &session.sensor_session_challenge_sha256;
    let empty = Sha256Digest::from_bytes(&[]);
    if *challenge == empty
        || challenge == identity.qualified_telemetry_backend_sha256()
        || challenge == identity.guest_evidence_signer_sha256()
        || challenge == identity.protected_sensor_bundle_sha256()
        || challenge == identity.sensor_configuration_sha256()
        || *session != session_binding_v1(identity, challenge)
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidIdentity);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_action_digests_v1(
    launch_contract_sha256: &Sha256Digest,
    process_plan_sha256: &Sha256Digest,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    let empty = Sha256Digest::from_bytes(&[]);
    if *launch_contract_sha256 == empty
        || *process_plan_sha256 == empty
        || launch_contract_sha256 == process_plan_sha256
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_action_binding_v1(
    context: &RootSensorServiceActionContextV1,
    action_index: &str,
    cgroup_id: &str,
    cgroup_name: &str,
    launch_contract_sha256: &Sha256Digest,
    process_plan_sha256: &Sha256Digest,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if action_index != context.action_index.to_string()
        || cgroup_id != context.cgroup_id.to_string()
        || cgroup_name != context.cgroup_name
        || launch_contract_sha256 != &context.launch_contract_sha256
        || process_plan_sha256 != &context.process_plan_sha256
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_abort_action_binding_v1(
    active: Option<&RootSensorServiceActiveActionV1>,
    request: &SensorAbortRequestWireV1,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    let context = active.map(|active| &active.context);
    let expected_action_index = context.map(|context| context.action_index.to_string());
    let expected_cgroup_id = context.map(|context| context.cgroup_id.to_string());
    let expected_cgroup_name = context.map(|context| context.cgroup_name.clone());
    let expected_launch_contract = context.map(|context| context.launch_contract_sha256.clone());
    let expected_leader_pid = context
        .and_then(|context| context.leader_pid)
        .map(|leader_pid| leader_pid.to_string());
    let expected_process_plan = context.map(|context| context.process_plan_sha256.clone());
    if request.action_index != expected_action_index
        || request.cgroup_id != expected_cgroup_id
        || request.cgroup_name != expected_cgroup_name
        || request.launch_contract_sha256 != expected_launch_contract
        || request.leader_pid != expected_leader_pid
        || request.process_plan_sha256 != expected_process_plan
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_service_finish_status_v1(
    status: &RootSensorServiceFinishStatusV1,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if !status.descendant_teardown_complete
        || status.dropped_event_count != 0
        || !status.file_sensor_healthy
        || status.heartbeat_count < 2
        || !status.network_sensor_healthy
        || !status.process_sensor_healthy
        || !status.sensor_teardown_complete
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
    }
    require_service_evidence_payload_v1(
        &status.output.correlation,
        MAX_LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_BYTES_V1,
    )?;
    for payload in [
        &status.output.process_evidence,
        &status.output.file_evidence,
        &status.output.network_evidence,
    ] {
        require_service_evidence_payload_v1(
            payload,
            MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_service_evidence_payload_v1(
    payload: &[u8],
    maximum_payload_bytes: usize,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if payload.is_empty()
        || payload.len() > maximum_payload_bytes
        || payload.len() > MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_EVIDENCE_BYTES_V1
    {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_cgroup_directory_name_v1(
    descriptor: RawFd,
    expected_name: &str,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if expected_name.is_empty()
        || std::fs::read_link(format!("/proc/self/fd/{descriptor}"))
            .ok()
            .and_then(|path| path.file_name().map(|name| name.to_owned()))
            .and_then(|name| name.into_string().ok())
            .as_deref()
            != Some(expected_name)
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn kill_cgroup_from_descriptor_v1(
    descriptor: RawFd,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    let kill_file = unsafe {
        libc::openat(
            descriptor,
            c"cgroup.kill".as_ptr(),
            libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if kill_file < 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let mut file = unsafe { File::from_raw_fd(kill_file) };
    file.write_all(b"1")
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)
}

#[cfg(target_os = "linux")]
fn read_cgroup_processes_v1(
    descriptor: RawFd,
) -> Result<Vec<u32>, LinuxVzPackageSensorControlErrorV1> {
    let process_file = unsafe {
        libc::openat(
            descriptor,
            c"cgroup.procs".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if process_file < 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let mut file = unsafe { File::from_raw_fd(process_file) };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(64 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    if bytes.len() > 64 * 1024 {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    let mut processes = Vec::new();
    for line in value.lines() {
        let process = u32::try_from(decimal_u64_v1(line)?)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
        if process <= 1 || processes.contains(&process) {
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload);
        }
        processes.push(process);
    }
    processes.sort_unstable();
    Ok(processes)
}

#[cfg(target_os = "linux")]
fn require_exact_cgroup_processes_v1(
    descriptor: RawFd,
    expected: &[u32],
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    let mut expected = expected.to_vec();
    expected.sort_unstable();
    if read_cgroup_processes_v1(descriptor)? != expected {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_proc_cgroup_membership_v1(
    leader_pid: u32,
    expected_cgroup_name: &str,
    expected_parent_pid: u32,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if leader_pid <= 1 || expected_parent_pid <= 1 || leader_pid == expected_parent_pid {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
    }
    let cgroup = read_virtual_file_bounded_v1(&format!("/proc/{leader_pid}/cgroup"), 64 * 1024)?;
    let cgroup = std::str::from_utf8(&cgroup)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    let unified_memberships = cgroup
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, ':');
            match (fields.next(), fields.next(), fields.next()) {
                (Some("0"), Some(""), Some(path)) => Some(path),
                _ => None,
            }
        })
        .collect::<Vec<_>>();
    if unified_memberships.len() != 1
        || unified_memberships[0]
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            != Some(expected_cgroup_name)
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidState);
    }

    let status = read_virtual_file_bounded_v1(&format!("/proc/{leader_pid}/status"), 64 * 1024)?;
    let status = std::str::from_utf8(&status)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPayload)?;
    validate_root_leader_status_v1(status, expected_parent_pid)
}

#[cfg(target_os = "linux")]
fn read_virtual_file_bounded_v1(
    path: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, LinuxVzPackageSensorControlErrorV1> {
    if maximum_bytes == 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    let mut file = File::open(path).map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(maximum_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    if bytes.len() > maximum_bytes {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn receive_control_frame_with_descriptor_v1(
    stream: &mut UnixStream,
    maximum_payload_bytes: usize,
) -> Result<(LinuxVzPackageSensorControlFrameV1, Option<OwnedFd>), LinuxVzPackageSensorControlErrorV1>
{
    let mut header = [0_u8; LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1];
    let mut io_vector = libc::iovec {
        iov_base: header.as_mut_ptr().cast(),
        iov_len: header.len(),
    };
    let mut control = [0 as libc::c_long; 8];
    let (received, message) = loop {
        control.fill(0);
        let mut message = unsafe { zeroed::<libc::msghdr>() };
        message.msg_iov = &mut io_vector;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = size_of::<[libc::c_long; 8]>()
            .try_into()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
        let received =
            unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
        if received >= 0 {
            break (received as usize, message);
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(LinuxVzPackageSensorControlErrorV1::Io);
        }
    };
    if received == 0 || received > header.len() {
        return Err(LinuxVzPackageSensorControlErrorV1::Io);
    }
    let (received_descriptors, unknown_control_message) =
        collect_received_descriptors_v1(&message)?;
    let invalid_control = message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0
        || unknown_control_message
        || received_descriptors.len() > 1;
    if invalid_control {
        close_raw_descriptors_v1(&received_descriptors);
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let descriptor = if let Some(descriptor) = received_descriptors.first().copied() {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            close_raw_descriptors_v1(&received_descriptors);
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
        }
        Some(unsafe { OwnedFd::from_raw_fd(descriptor) })
    } else {
        None
    };
    stream
        .read_exact(&mut header[received..])
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    let payload_length = validate_control_header_v1(&header, maximum_payload_bytes)?;
    let total_length = LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1
        .checked_add(payload_length)
        .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
    let mut frame = Vec::with_capacity(total_length);
    frame.extend_from_slice(&header);
    frame.resize(total_length, 0);
    stream
        .read_exact(&mut frame[LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1..])
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    let frame = decode_linux_vz_package_sensor_control_frame_v1(&frame, maximum_payload_bytes)?;
    Ok((frame, descriptor))
}

#[cfg(target_os = "linux")]
fn collect_received_descriptors_v1(
    message: &libc::msghdr,
) -> Result<(Vec<RawFd>, bool), LinuxVzPackageSensorControlErrorV1> {
    let mut descriptors = Vec::new();
    let mut unknown_control_message = false;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let control_header = unsafe { &*header };
        let minimum_length = unsafe { libc::CMSG_LEN(0) } as usize;
        let control_length = usize::try_from(control_header.cmsg_len)
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
        if control_length < minimum_length {
            close_raw_descriptors_v1(&descriptors);
            return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
        }
        if control_header.cmsg_level == libc::SOL_SOCKET
            && control_header.cmsg_type == libc::SCM_RIGHTS
        {
            let payload_length = control_length - minimum_length;
            if payload_length == 0 || !payload_length.is_multiple_of(size_of::<RawFd>()) {
                close_raw_descriptors_v1(&descriptors);
                return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
            }
            let count = payload_length / size_of::<RawFd>();
            for index in 0..count {
                let descriptor = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index))
                };
                if descriptor < 0 || descriptors.contains(&descriptor) {
                    close_raw_descriptors_v1(&descriptors);
                    if descriptor >= 0 && !descriptors.contains(&descriptor) {
                        let _ = unsafe { libc::close(descriptor) };
                    }
                    return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
                }
                descriptors.push(descriptor);
            }
        } else {
            unknown_control_message = true;
        }
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Ok((descriptors, unknown_control_message))
}

#[cfg(target_os = "linux")]
fn close_raw_descriptors_v1(descriptors: &[RawFd]) {
    for descriptor in descriptors {
        let _ = unsafe { libc::close(*descriptor) };
    }
}

#[cfg(target_os = "linux")]
fn validate_root_sensor_stream_v1(
    stream: &UnixStream,
) -> Result<u32, LinuxVzPackageSensorControlErrorV1> {
    let mut real_uid: libc::uid_t = 0;
    let mut effective_uid: libc::uid_t = 0;
    let mut saved_uid: libc::uid_t = 0;
    let mut real_gid: libc::gid_t = 0;
    let mut effective_gid: libc::gid_t = 0;
    let mut saved_gid: libc::gid_t = 0;
    if unsafe { libc::getresuid(&mut real_uid, &mut effective_uid, &mut saved_uid) } != 0
        || unsafe { libc::getresgid(&mut real_gid, &mut effective_gid, &mut saved_gid) } != 0
        || [real_uid, effective_uid, saved_uid] != [0, 0, 0]
        || [real_gid, effective_gid, saved_gid] != [0, 0, 0]
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }

    let descriptor = stream.as_raw_fd();
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK || stat.st_uid != 0 || stat.st_gid != 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }

    let mut socket_type: libc::c_int = 0;
    let mut socket_type_length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut libc::c_int).cast(),
            &mut socket_type_length,
        )
    } != 0
        || socket_type != libc::SOCK_STREAM
        || socket_type_length as usize != size_of::<libc::c_int>()
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }

    let mut socket_domain: libc::c_int = 0;
    let mut socket_domain_length = size_of::<libc::c_int>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_DOMAIN,
            (&mut socket_domain as *mut libc::c_int).cast(),
            &mut socket_domain_length,
        )
    } != 0
        || socket_domain != libc::AF_UNIX
        || socket_domain_length as usize != size_of::<libc::c_int>()
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }

    let mut credentials = MaybeUninit::<libc::ucred>::uninit();
    let mut credentials_length = size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            descriptor,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            credentials.as_mut_ptr().cast(),
            &mut credentials_length,
        )
    } != 0
        || credentials_length as usize != size_of::<libc::ucred>()
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }
    let credentials = unsafe { credentials.assume_init() };
    let current_pid = unsafe { libc::getpid() };
    if credentials.uid != 0
        || credentials.gid != 0
        || credentials.pid <= 1
        || credentials.pid == current_pid
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidPeer);
    }
    u32::try_from(credentials.pid).map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidPeer)
}

#[cfg(target_os = "linux")]
fn validate_cgroup_directory_descriptor_v1(
    descriptor: RawFd,
) -> Result<u64, LinuxVzPackageSensorControlErrorV1> {
    if descriptor < 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0 || descriptor_flags & libc::FD_CLOEXEC == 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_ino == 0
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let mut statfs = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptor, statfs.as_mut_ptr()) } != 0
        || unsafe { statfs.assume_init() }.f_type as i64 != CGROUP2_SUPER_MAGIC_V1
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    Ok(stat.st_ino)
}

#[cfg(target_os = "linux")]
fn send_frame_with_descriptor_v1(
    stream: &mut UnixStream,
    frame: &[u8],
    descriptor: RawFd,
) -> Result<(), LinuxVzPackageSensorControlErrorV1> {
    if frame.is_empty() || unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidDescriptor);
    }
    let mut io_vector = libc::iovec {
        iov_base: frame.as_ptr().cast_mut().cast(),
        iov_len: frame.len(),
    };
    let control_length = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as libc::c_uint) } as usize;
    let mut control = [0 as libc::c_long; 4];
    if control_length > size_of::<[libc::c_long; 4]>() {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    let mut message = unsafe { zeroed::<libc::msghdr>() };
    message.msg_iov = &mut io_vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control_length
        .try_into()
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
    let control_header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if control_header.is_null() {
        return Err(LinuxVzPackageSensorControlErrorV1::Io);
    }
    unsafe {
        (*control_header).cmsg_level = libc::SOL_SOCKET;
        (*control_header).cmsg_type = libc::SCM_RIGHTS;
        (*control_header).cmsg_len = (libc::CMSG_LEN(size_of::<RawFd>() as libc::c_uint) as usize)
            .try_into()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
        std::ptr::write_unaligned(libc::CMSG_DATA(control_header).cast::<RawFd>(), descriptor);
    }
    let sent = loop {
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if sent >= 0 {
            break sent as usize;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(LinuxVzPackageSensorControlErrorV1::Io);
        }
    };
    if sent == 0 || sent > frame.len() {
        return Err(LinuxVzPackageSensorControlErrorV1::Io);
    }
    if sent < frame.len() {
        stream
            .write_all(&frame[sent..])
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_control_frame_v1(
    stream: &mut UnixStream,
    maximum_payload_bytes: usize,
) -> Result<LinuxVzPackageSensorControlFrameV1, LinuxVzPackageSensorControlErrorV1> {
    let mut header = [0_u8; LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1];
    stream
        .read_exact(&mut header)
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    let payload_length = validate_control_header_v1(&header, maximum_payload_bytes)?;
    let total_length = LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1
        .checked_add(payload_length)
        .ok_or(LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
    let mut frame = Vec::with_capacity(total_length);
    frame.extend_from_slice(&header);
    frame.resize(total_length, 0);
    stream
        .read_exact(&mut frame[LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1..])
        .map_err(|_| LinuxVzPackageSensorControlErrorV1::Io)?;
    decode_linux_vz_package_sensor_control_frame_v1(&frame, maximum_payload_bytes)
}

#[cfg(target_os = "linux")]
fn validate_control_header_v1(
    header: &[u8; LINUX_VZ_PACKAGE_SENSOR_CONTROL_HEADER_BYTES_V1],
    maximum_payload_bytes: usize,
) -> Result<usize, LinuxVzPackageSensorControlErrorV1> {
    if &header[..8] != CONTROL_MAGIC_V1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidMagic);
    }
    if u16::from_be_bytes([header[8], header[9]]) != CONTROL_VERSION_V1 {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidVersion);
    }
    LinuxVzPackageSensorControlFrameKindV1::from_u16_v1(u16::from_be_bytes([
        header[10], header[11],
    ]))?;
    if u64::from_be_bytes(
        header[12..20]
            .try_into()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidLength)?,
    ) == 0
    {
        return Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence);
    }
    let payload_length = usize::try_from(u64::from_be_bytes(
        header[20..28]
            .try_into()
            .map_err(|_| LinuxVzPackageSensorControlErrorV1::InvalidLength)?,
    ))
    .map_err(|_| LinuxVzPackageSensorControlErrorV1::LimitExceeded)?;
    if payload_length == 0
        || maximum_payload_bytes == 0
        || payload_length > maximum_payload_bytes
        || payload_length > MAX_LINUX_VZ_PACKAGE_SENSOR_CONTROL_EVIDENCE_BYTES_V1
    {
        return Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded);
    }
    Ok(payload_length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct TestWireV1 {
        alpha: String,
        beta: String,
    }

    #[test]
    fn control_frame_round_trip_is_exact_and_redacted() {
        let payload = br#"{"alpha":"one","beta":"two"}"#;
        let encoded = encode_linux_vz_package_sensor_control_frame_v1(
            LinuxVzPackageSensorControlFrameKindV1::ProcessEvidence,
            17,
            payload,
            1024,
        )
        .expect("frame");
        let decoded =
            decode_linux_vz_package_sensor_control_frame_v1(&encoded, 1024).expect("decoded frame");
        assert_eq!(
            decoded.kind(),
            LinuxVzPackageSensorControlFrameKindV1::ProcessEvidence
        );
        assert_eq!(decoded.sequence(), 17);
        assert_eq!(decoded.payload(), payload);
        assert_eq!(decoded.payload_sha256(), &Sha256Digest::from_bytes(payload));
        let debug = format!("{decoded:?}");
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("alpha"));
    }

    #[test]
    fn control_frame_rejects_header_and_digest_mutations() {
        let payload = b"evidence";
        let frame = encode_linux_vz_package_sensor_control_frame_v1(
            LinuxVzPackageSensorControlFrameKindV1::FileEvidence,
            2,
            payload,
            1024,
        )
        .expect("frame");
        let cases = [
            (0, LinuxVzPackageSensorControlErrorV1::InvalidMagic),
            (9, LinuxVzPackageSensorControlErrorV1::InvalidVersion),
            (11, LinuxVzPackageSensorControlErrorV1::InvalidFrameKind),
            (59, LinuxVzPackageSensorControlErrorV1::DigestMismatch),
        ];
        for (offset, expected) in cases {
            let mut mutated = frame.clone();
            mutated[offset] ^= 0xff;
            assert_eq!(
                decode_linux_vz_package_sensor_control_frame_v1(&mutated, 1024),
                Err(expected)
            );
        }
    }

    #[test]
    fn control_frame_rejects_sequence_length_trailing_and_limits() {
        let payload = b"evidence";
        let frame = encode_linux_vz_package_sensor_control_frame_v1(
            LinuxVzPackageSensorControlFrameKindV1::NetworkEvidence,
            3,
            payload,
            1024,
        )
        .expect("frame");
        let mut zero_sequence = frame.clone();
        zero_sequence[12..20].copy_from_slice(&0_u64.to_be_bytes());
        assert_eq!(
            decode_linux_vz_package_sensor_control_frame_v1(&zero_sequence, 1024),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence)
        );
        let mut wrong_length = frame.clone();
        wrong_length[20..28].copy_from_slice(&99_u64.to_be_bytes());
        assert_eq!(
            decode_linux_vz_package_sensor_control_frame_v1(&wrong_length, 1024),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidLength)
        );
        let mut trailing = frame.clone();
        trailing.push(0);
        assert_eq!(
            decode_linux_vz_package_sensor_control_frame_v1(&trailing, 1024),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidLength)
        );
        assert_eq!(
            decode_linux_vz_package_sensor_control_frame_v1(&frame, payload.len() - 1),
            Err(LinuxVzPackageSensorControlErrorV1::LimitExceeded)
        );
        assert_eq!(
            encode_linux_vz_package_sensor_control_frame_v1(
                LinuxVzPackageSensorControlFrameKindV1::Finish,
                0,
                payload,
                1024,
            ),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidSequence)
        );
    }

    #[test]
    fn canonical_payload_decoder_rejects_reordered_and_trailing_json() {
        let value = TestWireV1 {
            alpha: "one".to_string(),
            beta: "two".to_string(),
        };
        let canonical = canonical_bytes_v1(&value).expect("canonical");
        assert_eq!(
            decode_canonical_payload_v1::<TestWireV1>(&canonical).expect("decode"),
            value
        );
        assert_eq!(
            decode_canonical_payload_v1::<TestWireV1>(br#"{"beta":"two","alpha":"one"}"#,),
            Err(LinuxVzPackageSensorControlErrorV1::NonCanonical)
        );
        assert_eq!(
            decode_canonical_payload_v1::<TestWireV1>(br#"{"alpha":"one","beta":"two"}x"#,),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
        );
    }

    #[test]
    fn decimal_parser_requires_minimal_unsigned_form() {
        assert_eq!(decimal_u64_v1("0"), Ok(0));
        assert_eq!(decimal_u64_v1("42"), Ok(42));
        for invalid in ["", "00", "01", "+1", "-1", "1.0", " 1"] {
            assert_eq!(
                decimal_u64_v1(invalid),
                Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
            );
        }
    }

    #[test]
    fn arm_v2_binds_redacted_launch_identity() {
        let request = SensorArmRequestWireV2 {
            action_index: "1".to_string(),
            argv_item_count: "4".to_string(),
            argv_sha256: Sha256Digest::from_bytes(b"canonical argv"),
            cgroup_directory_fd_transferred: true,
            cgroup_name: "whoathere-package-action-1".to_string(),
            control_sequence: "3".to_string(),
            expected_executable_sha256: Sha256Digest::from_bytes(b"measured executable"),
            launch_contract_sha256: Sha256Digest::from_bytes(b"launch contract"),
            operation: "arm".to_string(),
            process_plan_sha256: Sha256Digest::from_bytes(b"process plan"),
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_ARM_SCHEMA_V2.to_string(),
            session: SensorSessionBindingWireV1 {
                guest_evidence_signer_sha256: Sha256Digest::from_bytes(b"guest signer"),
                package_gid: "65534".to_string(),
                package_uid: "65534".to_string(),
                qualified_telemetry_backend_sha256: Sha256Digest::from_bytes(b"backend"),
                protected_sensor_bundle_sha256: Sha256Digest::from_bytes(b"sensor bundle"),
                sensor_configuration_sha256: Sha256Digest::from_bytes(b"sensor configuration"),
                sensor_session_challenge_sha256: Sha256Digest::from_bytes(b"fresh challenge"),
            },
            sync_back: false,
        };
        let canonical = canonical_bytes_v1(&request).expect("canonical arm request");
        assert!(!String::from_utf8_lossy(&canonical).contains("package.tgz"));
        let decoded: SensorArmRequestWireV2 =
            decode_canonical_payload_v1(&canonical).expect("arm request");
        let identity =
            process_launch_identity_from_arm_request_v2(&decoded).expect("launch identity");
        assert_eq!(identity.argv_item_count(), 4);
        assert_eq!(identity.argv_sha256(), &request.argv_sha256);
        assert_eq!(
            identity.executable_sha256(),
            &request.expected_executable_sha256
        );

        let mut empty_count = request.clone();
        empty_count.argv_item_count = "0".to_string();
        assert_eq!(
            process_launch_identity_from_arm_request_v2(&empty_count),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
        );
        let mut empty_digest = request;
        empty_digest.argv_sha256 = Sha256Digest::from_bytes(&[]);
        assert_eq!(
            process_launch_identity_from_arm_request_v2(&empty_digest),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
        );
    }

    #[test]
    fn root_leader_status_requires_exact_parent_and_root_credentials() {
        let exact = "Name:\tfixture\nPPid:\t40\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n";
        validate_root_leader_status_v1(exact, 40).expect("exact leader status");
        assert_eq!(
            validate_root_leader_status_v1(exact, 39),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidState)
        );
        assert_eq!(
            validate_root_leader_status_v1(
                "Name:\tfixture\nPPid:\t40\nUid:\t65534\t65534\t65534\t65534\nGid:\t0\t0\t0\t0\n",
                40,
            ),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidState)
        );
    }

    #[test]
    fn finish_v3_binds_one_exact_supervisor_wait_status() {
        let session = SensorSessionBindingWireV1 {
            guest_evidence_signer_sha256: Sha256Digest::from_bytes(b"guest signer"),
            package_gid: "65534".to_string(),
            package_uid: "65534".to_string(),
            qualified_telemetry_backend_sha256: Sha256Digest::from_bytes(b"backend"),
            protected_sensor_bundle_sha256: Sha256Digest::from_bytes(b"sensor bundle"),
            sensor_configuration_sha256: Sha256Digest::from_bytes(b"sensor configuration"),
            sensor_session_challenge_sha256: Sha256Digest::from_bytes(b"fresh challenge"),
        };
        let exact = SensorFinishRequestWireV3 {
            action_index: "1".to_string(),
            cgroup_id: "41".to_string(),
            cgroup_name: "whoathere-package-action-1".to_string(),
            control_sequence: "7".to_string(),
            launch_contract_sha256: Sha256Digest::from_bytes(b"launch contract"),
            leader_exit_status: Some("0".to_string()),
            leader_pid: "42".to_string(),
            leader_supervisor_wait_status: "0".to_string(),
            leader_terminal: LinuxVzPackageProcessTerminalV1::Exited,
            leader_termination_signal: None,
            operation: "finish".to_string(),
            process_ended_monotonic_nanoseconds: "300".to_string(),
            process_plan_sha256: Sha256Digest::from_bytes(b"process plan"),
            process_started_monotonic_nanoseconds: "200".to_string(),
            public_network_route_present: false,
            schema_version: LINUX_VZ_PACKAGE_SENSOR_CONTROL_FINISH_SCHEMA_V3.to_string(),
            session,
            sync_back: false,
        };
        let canonical = canonical_bytes_v1(&exact).expect("canonical finish request");
        let decoded: SensorFinishRequestWireV3 =
            decode_canonical_payload_v1(&canonical).expect("finish request");
        let completion =
            process_completion_from_finish_request_v3(&decoded).expect("completion binding");
        assert_eq!(completion.supervisor_wait_status(), 0);
        assert_eq!(
            completion.terminal(),
            LinuxVzPackageProcessTerminalV1::Exited
        );
        assert_eq!(completion.exit_status(), Some(0));
        assert_eq!(completion.termination_signal(), None);

        let mut wrong_terminal = exact.clone();
        wrong_terminal.leader_terminal = LinuxVzPackageProcessTerminalV1::Signaled;
        assert_eq!(
            process_completion_from_finish_request_v3(&wrong_terminal),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
        );
        let mut missing_status = exact.clone();
        missing_status.leader_exit_status = None;
        assert_eq!(
            process_completion_from_finish_request_v3(&missing_status),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
        );
        let mut mismatched_wait_status = exact.clone();
        mismatched_wait_status.leader_supervisor_wait_status = "1792".to_string();
        assert_eq!(
            process_completion_from_finish_request_v3(&mismatched_wait_status),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
        );
        let mut core_dump = exact.clone();
        core_dump.leader_exit_status = None;
        core_dump.leader_supervisor_wait_status = "139".to_string();
        core_dump.leader_terminal = LinuxVzPackageProcessTerminalV1::Signaled;
        core_dump.leader_termination_signal = Some("11".to_string());
        let core_dump =
            process_completion_from_finish_request_v3(&core_dump).expect("core-dump completion");
        assert_eq!(core_dump.supervisor_wait_status(), 139);
        assert_eq!(core_dump.termination_signal(), Some(11));
        let mut invalid_time = exact;
        invalid_time.process_ended_monotonic_nanoseconds = "200".to_string();
        assert_eq!(
            process_completion_from_finish_request_v3(&invalid_time),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidPayload)
        );
    }

    #[test]
    fn sensor_identity_rejects_empty_or_reused_component_digests() {
        let empty = Sha256Digest::from_bytes(&[]);
        let first = Sha256Digest::from_bytes(b"first");
        let second = Sha256Digest::from_bytes(b"second");
        let third = Sha256Digest::from_bytes(b"third");
        let invalid_empty = LinuxVzPackageRootSensorIdentityV1 {
            qualified_telemetry_backend_sha256: empty,
            guest_evidence_signer_sha256: first.clone(),
            protected_sensor_bundle_sha256: second.clone(),
            sensor_configuration_sha256: third.clone(),
        };
        assert_eq!(
            invalid_empty.validate_v1(),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidIdentity)
        );
        let invalid_reuse = LinuxVzPackageRootSensorIdentityV1 {
            qualified_telemetry_backend_sha256: first.clone(),
            guest_evidence_signer_sha256: first,
            protected_sensor_bundle_sha256: second,
            sensor_configuration_sha256: third,
        };
        assert_eq!(
            invalid_reuse.validate_v1(),
            Err(LinuxVzPackageSensorControlErrorV1::InvalidIdentity)
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn descriptor_receiver_preserves_frame_and_sets_close_on_exec() {
        let (mut sender, mut receiver) = UnixStream::pair().expect("socket pair");
        let source = File::open("/dev/null").expect("source descriptor");
        let payload = br#"{"alpha":"one","beta":"two"}"#;
        let encoded = encode_linux_vz_package_sensor_control_frame_v1(
            LinuxVzPackageSensorControlFrameKindV1::Arm,
            3,
            payload,
            1024,
        )
        .expect("frame");
        send_frame_with_descriptor_v1(&mut sender, &encoded, source.as_raw_fd())
            .expect("send frame with descriptor");
        let (decoded, received) =
            receive_control_frame_with_descriptor_v1(&mut receiver, 1024).expect("receive");
        let received = received.expect("received descriptor");
        assert_eq!(decoded.kind(), LinuxVzPackageSensorControlFrameKindV1::Arm);
        assert_eq!(decoded.sequence(), 3);
        assert_eq!(decoded.payload(), payload);
        assert_ne!(received.as_raw_fd(), source.as_raw_fd());
        let flags = unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn observer_health_fails_closed_on_authenticated_channel_teardown() {
        let identity = LinuxVzPackageRootSensorIdentityV1 {
            qualified_telemetry_backend_sha256: Sha256Digest::from_bytes(b"backend"),
            guest_evidence_signer_sha256: Sha256Digest::from_bytes(b"signer"),
            protected_sensor_bundle_sha256: Sha256Digest::from_bytes(b"bundle"),
            sensor_configuration_sha256: Sha256Digest::from_bytes(b"configuration"),
        };
        identity.validate_v1().expect("distinct measured identity");
        let (stream, peer) = UnixStream::pair().expect("protected channel");
        let mut observer = LinuxVzPackageRootSensorObserverV1 {
            stream,
            identity,
            sensor_session_challenge_sha256: Sha256Digest::from_bytes(b"challenge"),
            peer_pid: 2,
            root_runner_pid: 3,
            next_control_sequence: 7,
            state: RootSensorObserverStateV1::LeaderCorrelated,
            active: None,
            channel_usable: true,
        };
        observer.require_healthy_v1().expect("quiet channel");
        drop(peer);
        assert_eq!(
            observer.require_healthy_v1(),
            Err(LinuxVzPackageProcessSupervisorErrorV1::ProtectedSensorUnavailable)
        );
        assert_eq!(observer.state, RootSensorObserverStateV1::Faulted);
        assert!(!observer.channel_usable);
        observer
            .abort_v1()
            .expect("idempotent local fault teardown");
        assert_eq!(observer.state, RootSensorObserverStateV1::Aborted);
    }
}
