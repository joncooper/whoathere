use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryGuestObservationClaimsV1,
    MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_process_evidence_payload.v1";
pub const LINUX_VZ_PROCESS_EVIDENCE_SERIAL_PREFIX_V1: &[u8] = b"WHOATHERE_GUEST_PROCESS_EVIDENCE ";
pub const MAX_LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzProcessEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzProcessEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Missing => "linux_vz_process_evidence_missing",
            Self::Duplicate => "linux_vz_process_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_process_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_process_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_process_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_process_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_process_evidence_event_invalid",
        };
        formatter.write_str(value)
    }
}

impl std::error::Error for LinuxVzProcessEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzProcessEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    evidence_byte_length: u64,
    event_sequence_start: u64,
    event_sequence_end: u64,
    event_count: u64,
    heartbeat_count: u64,
    dropped_event_count: u64,
    package_uid: u32,
    package_gid: u32,
}

impl LinuxVzProcessEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn evidence_byte_length(&self) -> u64 {
        self.evidence_byte_length
    }

    pub fn event_sequence_start(&self) -> u64 {
        self.event_sequence_start
    }

    pub fn event_sequence_end(&self) -> u64 {
        self.event_sequence_end
    }

    pub fn event_count(&self) -> u64 {
        self.event_count
    }

    pub fn heartbeat_count(&self) -> u64 {
        self.heartbeat_count
    }

    pub fn dropped_event_count(&self) -> u64 {
        self.dropped_event_count
    }

    pub fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub fn guest_observation_claims_v1(
        &self,
    ) -> Result<LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1>
    {
        LinuxVzTelemetryGuestObservationClaimsV1::new(
            self.payload_sha256.clone(),
            self.evidence_byte_length,
            self.event_sequence_start,
            self.event_sequence_end,
            self.event_count,
            self.heartbeat_count,
            self.dropped_event_count,
            true,
            false,
            true,
            LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessEvidenceWireV1 {
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<ProcessEventWireV1>,
    evidence_truncated: bool,
    heartbeat_count: String,
    package_gid: String,
    package_uid: String,
    schema_version: String,
    sensor_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessEventWireV1 {
    actor_pid: String,
    cgroup_id: String,
    kind: String,
    sequence: String,
    subject_pid: String,
    timestamp_ns: String,
}

#[derive(Debug, Clone, Copy)]
struct ValidatedProcessEventV1 {
    actor_pid: u64,
    cgroup_id: u64,
    subject_pid: u64,
    timestamp_ns: u64,
}

pub fn decode_linux_vz_process_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<LinuxVzProcessEvidencePayloadV1, LinuxVzProcessEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) = line.strip_prefix(LINUX_VZ_PROCESS_EVIDENCE_SERIAL_PREFIX_V1) else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzProcessEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_process_evidence_payload_v1(
        payload.ok_or(LinuxVzProcessEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_process_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzProcessEvidencePayloadV1, LinuxVzProcessEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzProcessEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = ProcessEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzProcessEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzProcessEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzProcessEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzProcessEvidencePayloadErrorV1::NonCanonical);
    }

    let event_sequence_start = decimal_u64_v1(&wire.event_sequence_start)?;
    let event_sequence_end = decimal_u64_v1(&wire.event_sequence_end)?;
    let event_count = decimal_u64_v1(&wire.event_count)?;
    let heartbeat_count = decimal_u64_v1(&wire.heartbeat_count)?;
    let dropped_event_count = decimal_u64_v1(&wire.dropped_event_count)?;
    let package_uid = decimal_u64_v1(&wire.package_uid)?;
    let package_gid = decimal_u64_v1(&wire.package_gid)?;
    if wire.schema_version != LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_SCHEMA_V1
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
        || event_sequence_start != 1
        || event_sequence_end != 3
        || event_count != 3
        || heartbeat_count != 2
        || dropped_event_count != 0
        || package_uid != 65534
        || package_gid != 65534
        || wire.events.len() != 3
    {
        return Err(LinuxVzProcessEvidencePayloadErrorV1::InvalidSchema);
    }

    let expected_kinds = ["fork", "exec", "exit"];
    let mut events = Vec::with_capacity(3);
    for (index, event) in wire.events.iter().enumerate() {
        if event.kind != expected_kinds[index]
            || decimal_u64_v1(&event.sequence)? != index as u64 + 1
        {
            return Err(LinuxVzProcessEvidencePayloadErrorV1::InvalidEvent);
        }
        let event = ValidatedProcessEventV1 {
            actor_pid: decimal_u64_v1(&event.actor_pid)?,
            cgroup_id: decimal_u64_v1(&event.cgroup_id)?,
            subject_pid: decimal_u64_v1(&event.subject_pid)?,
            timestamp_ns: decimal_u64_v1(&event.timestamp_ns)?,
        };
        if event.actor_pid == 0 || event.subject_pid == 0 || event.cgroup_id == 0 {
            return Err(LinuxVzProcessEvidencePayloadErrorV1::InvalidEvent);
        }
        events.push(event);
    }
    if events[0].actor_pid == events[0].subject_pid
        || events[1].actor_pid != events[0].subject_pid
        || events[1].subject_pid != events[0].subject_pid
        || events[2].actor_pid != events[0].subject_pid
        || events[2].subject_pid != events[0].subject_pid
        || events[0].cgroup_id != events[1].cgroup_id
        || events[1].cgroup_id != events[2].cgroup_id
        || events[0].timestamp_ns >= events[1].timestamp_ns
        || events[1].timestamp_ns >= events[2].timestamp_ns
    {
        return Err(LinuxVzProcessEvidencePayloadErrorV1::InvalidEvent);
    }

    Ok(LinuxVzProcessEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        evidence_byte_length: payload.len() as u64,
        event_sequence_start,
        event_sequence_end,
        event_count,
        heartbeat_count,
        dropped_event_count,
        package_uid: package_uid as u32,
        package_gid: package_gid as u32,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzProcessEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzProcessEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzProcessEvidencePayloadErrorV1::InvalidSchema)
}
