use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryGuestObservationClaimsV1,
    MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_BPF_PROGRAM_TYPE_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_bpf_program_type_evidence_payload.v1";
pub const LINUX_VZ_BPF_PROGRAM_TYPE_EVIDENCE_SERIAL_PREFIX_V1: &[u8] =
    b"WHOATHERE_GUEST_BPF_PROGRAM_TYPE_EVIDENCE ";
pub const MAX_LINUX_VZ_BPF_PROGRAM_TYPE_EVIDENCE_PAYLOAD_BYTES_V1: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzBpfProgramTypeEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
}

impl fmt::Display for LinuxVzBpfProgramTypeEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_bpf_program_type_evidence_missing",
            Self::Duplicate => "linux_vz_bpf_program_type_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_bpf_program_type_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_bpf_program_type_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_bpf_program_type_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_bpf_program_type_evidence_schema_invalid",
        })
    }
}

impl std::error::Error for LinuxVzBpfProgramTypeEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzBpfProgramTypeEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    evidence_byte_length: u64,
    package_uid: u32,
    package_gid: u32,
    raw_tracepoint_actor_pid: u32,
    raw_tracepoint_cgroup_id: u64,
    raw_tracepoint_program_id: u32,
    socket_filter_program_id: u32,
}

impl LinuxVzBpfProgramTypeEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn evidence_byte_length(&self) -> u64 {
        self.evidence_byte_length
    }

    pub fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub fn raw_tracepoint_actor_pid(&self) -> u32 {
        self.raw_tracepoint_actor_pid
    }

    pub fn raw_tracepoint_cgroup_id(&self) -> u64 {
        self.raw_tracepoint_cgroup_id
    }

    pub fn raw_tracepoint_program_id(&self) -> u32 {
        self.raw_tracepoint_program_id
    }

    pub fn socket_filter_program_id(&self) -> u32 {
        self.socket_filter_program_id
    }

    pub fn guest_observation_claims_v1(
        &self,
    ) -> Result<LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1>
    {
        LinuxVzTelemetryGuestObservationClaimsV1::new(
            self.payload_sha256.clone(),
            self.evidence_byte_length,
            1,
            2,
            2,
            2,
            0,
            true,
            false,
            true,
            LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BpfProgramTypeEvidenceWireV1 {
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    evidence_truncated: bool,
    fixture_case: String,
    heartbeat_count: String,
    observation_map_type: String,
    package_gid: String,
    package_uid: String,
    raw_tracepoint_actor_pid: String,
    raw_tracepoint_attach_command: String,
    raw_tracepoint_cgroup_id: String,
    raw_tracepoint_name: String,
    raw_tracepoint_observation_count: String,
    raw_tracepoint_program_id: String,
    raw_tracepoint_program_type: String,
    raw_tracepoint_timestamp_ns: String,
    resource_teardown_complete: bool,
    schema_version: String,
    sensor_healthy: bool,
    socket_filter_attach_option: String,
    socket_filter_input_bytes: String,
    socket_filter_output_bytes: String,
    socket_filter_program_id: String,
    socket_filter_program_type: String,
}

pub fn decode_linux_vz_bpf_program_type_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<LinuxVzBpfProgramTypeEvidencePayloadV1, LinuxVzBpfProgramTypeEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) =
            line.strip_prefix(LINUX_VZ_BPF_PROGRAM_TYPE_EVIDENCE_SERIAL_PREFIX_V1)
        else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzBpfProgramTypeEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_bpf_program_type_evidence_payload_v1(
        payload.ok_or(LinuxVzBpfProgramTypeEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_bpf_program_type_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzBpfProgramTypeEvidencePayloadV1, LinuxVzBpfProgramTypeEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_BPF_PROGRAM_TYPE_EVIDENCE_PAYLOAD_BYTES_V1
    {
        return Err(LinuxVzBpfProgramTypeEvidencePayloadErrorV1::LimitExceeded);
    }
    let wire: BpfProgramTypeEvidenceWireV1 = serde_json::from_slice(payload)
        .map_err(|_| LinuxVzBpfProgramTypeEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzBpfProgramTypeEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzBpfProgramTypeEvidencePayloadErrorV1::NonCanonical);
    }
    let package_uid = decimal_u64(&wire.package_uid)?;
    let package_gid = decimal_u64(&wire.package_gid)?;
    let actor_pid = decimal_u64(&wire.raw_tracepoint_actor_pid)?;
    let cgroup_id = decimal_u64(&wire.raw_tracepoint_cgroup_id)?;
    let raw_program_id = decimal_u64(&wire.raw_tracepoint_program_id)?;
    let socket_program_id = decimal_u64(&wire.socket_filter_program_id)?;
    if wire.schema_version != LINUX_VZ_BPF_PROGRAM_TYPE_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.fixture_case != "bpf_program_types"
        || wire.observation_map_type != "BPF_MAP_TYPE_ARRAY"
        || wire.raw_tracepoint_attach_command != "BPF_RAW_TRACEPOINT_OPEN"
        || wire.raw_tracepoint_name != "sys_enter"
        || wire.raw_tracepoint_program_type != "BPF_PROG_TYPE_RAW_TRACEPOINT"
        || wire.socket_filter_attach_option != "SO_ATTACH_BPF"
        || wire.socket_filter_program_type != "BPF_PROG_TYPE_SOCKET_FILTER"
        || decimal_u64(&wire.event_sequence_start)? != 1
        || decimal_u64(&wire.event_sequence_end)? != 2
        || decimal_u64(&wire.event_count)? != 2
        || decimal_u64(&wire.heartbeat_count)? != 2
        || decimal_u64(&wire.dropped_event_count)? != 0
        || decimal_u64(&wire.raw_tracepoint_observation_count)? != 1
        || decimal_u64(&wire.raw_tracepoint_timestamp_ns)? == 0
        || decimal_u64(&wire.socket_filter_input_bytes)? != 8
        || decimal_u64(&wire.socket_filter_output_bytes)? != 4
        || package_uid != 65534
        || package_gid != 65534
        || !(2..=i32::MAX as u64).contains(&actor_pid)
        || cgroup_id == 0
        || !(1..=u32::MAX as u64).contains(&raw_program_id)
        || !(1..=u32::MAX as u64).contains(&socket_program_id)
        || raw_program_id == socket_program_id
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
        || !wire.resource_teardown_complete
    {
        return Err(LinuxVzBpfProgramTypeEvidencePayloadErrorV1::InvalidSchema);
    }
    Ok(LinuxVzBpfProgramTypeEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        evidence_byte_length: payload.len() as u64,
        package_uid: package_uid as u32,
        package_gid: package_gid as u32,
        raw_tracepoint_actor_pid: actor_pid as u32,
        raw_tracepoint_cgroup_id: cgroup_id,
        raw_tracepoint_program_id: raw_program_id as u32,
        socket_filter_program_id: socket_program_id as u32,
    })
}

fn decimal_u64(value: &str) -> Result<u64, LinuxVzBpfProgramTypeEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzBpfProgramTypeEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzBpfProgramTypeEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "descendant_teardown_complete": true,
            "dropped_event_count": "0",
            "event_count": "2",
            "event_sequence_end": "2",
            "event_sequence_start": "1",
            "evidence_truncated": false,
            "fixture_case": "bpf_program_types",
            "heartbeat_count": "2",
            "observation_map_type": "BPF_MAP_TYPE_ARRAY",
            "package_gid": "65534",
            "package_uid": "65534",
            "raw_tracepoint_actor_pid": "411",
            "raw_tracepoint_attach_command": "BPF_RAW_TRACEPOINT_OPEN",
            "raw_tracepoint_cgroup_id": "21",
            "raw_tracepoint_name": "sys_enter",
            "raw_tracepoint_observation_count": "1",
            "raw_tracepoint_program_id": "43",
            "raw_tracepoint_program_type": "BPF_PROG_TYPE_RAW_TRACEPOINT",
            "raw_tracepoint_timestamp_ns": "1000",
            "resource_teardown_complete": true,
            "schema_version": LINUX_VZ_BPF_PROGRAM_TYPE_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "sensor_healthy": true,
            "socket_filter_attach_option": "SO_ATTACH_BPF",
            "socket_filter_input_bytes": "8",
            "socket_filter_output_bytes": "4",
            "socket_filter_program_id": "44",
            "socket_filter_program_type": "BPF_PROG_TYPE_SOCKET_FILTER"
        }))
        .unwrap()
    }

    #[test]
    fn bpf_program_type_evidence_binds_load_attach_trigger_and_teardown() {
        let evidence = decode_linux_vz_bpf_program_type_evidence_payload_v1(&payload()).unwrap();
        assert_eq!(evidence.raw_tracepoint_actor_pid(), 411);
        assert_eq!(evidence.raw_tracepoint_cgroup_id(), 21);
        assert_eq!(evidence.raw_tracepoint_program_id(), 43);
        assert_eq!(evidence.socket_filter_program_id(), 44);
        assert!(evidence.guest_observation_claims_v1().is_ok());

        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["socket_filter_output_bytes"] = serde_json::json!("8");
        let rebound = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            decode_linux_vz_bpf_program_type_evidence_payload_v1(&rebound),
            Err(LinuxVzBpfProgramTypeEvidencePayloadErrorV1::InvalidSchema)
        );
    }
}
