use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryHostObservationClaimsV1,
    MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_host_evidence_payload.v1";
pub const MAX_LINUX_VZ_HOST_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzHostEvidencePayloadErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzHostEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Empty => "linux_vz_host_evidence_empty",
            Self::LimitExceeded => "linux_vz_host_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_host_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_host_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_host_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_host_evidence_event_invalid",
        };
        formatter.write_str(value)
    }
}

impl std::error::Error for LinuxVzHostEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzHostEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    raw_frame_count: u64,
}

impl LinuxVzHostEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn raw_frame_count(&self) -> u64 {
        self.raw_frame_count
    }

    pub fn host_observation_claims_v1(
        &self,
    ) -> Result<LinuxVzTelemetryHostObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1> {
        LinuxVzTelemetryHostObservationClaimsV1::new(
            self.payload_sha256.clone(),
            self.canonical_json.len() as u64,
            1,
            6,
            6,
            2,
            0,
            true,
            false,
            true,
            true,
            true,
            true,
            0,
            LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEvidenceWireV1 {
    clone_destroyed: bool,
    dropped_frame_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<HostEvidenceEventWireV1>,
    evidence_truncated: bool,
    external_frames_forwarded: String,
    external_route_configured: bool,
    guest_channel_terminated: bool,
    heartbeat_count: String,
    package_execution: bool,
    packet_sensor_healthy: bool,
    packet_sensor_terminal: String,
    raw_frame_count: String,
    root_disk_present: bool,
    schema_version: String,
    storage_device_count: String,
    sync_back: bool,
    vm_started: bool,
    vm_stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEvidenceEventWireV1 {
    kind: String,
    sequence: String,
}

pub fn decode_linux_vz_host_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzHostEvidencePayloadV1, LinuxVzHostEvidencePayloadErrorV1> {
    if payload.is_empty() {
        return Err(LinuxVzHostEvidencePayloadErrorV1::Empty);
    }
    if payload.len() > MAX_LINUX_VZ_HOST_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzHostEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = HostEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzHostEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzHostEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzHostEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzHostEvidencePayloadErrorV1::NonCanonical);
    }
    let raw_frame_count = decimal_u64_v1(&wire.raw_frame_count)?;
    if wire.schema_version != LINUX_VZ_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 6
        || decimal_u64_v1(&wire.event_count)? != 6
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || decimal_u64_v1(&wire.dropped_frame_count)? != 0
        || decimal_u64_v1(&wire.external_frames_forwarded)? != 0
        || raw_frame_count != 0
        || decimal_u64_v1(&wire.storage_device_count)? != 0
        || !wire.packet_sensor_healthy
        || wire.packet_sensor_terminal != "drained_would_block"
        || wire.evidence_truncated
        || !wire.guest_channel_terminated
        || !wire.vm_started
        || !wire.vm_stopped
        || !wire.clone_destroyed
        || wire.root_disk_present
        || wire.external_route_configured
        || wire.package_execution
        || wire.sync_back
        || wire.events.len() != 6
    {
        return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema);
    }
    let expected_kinds = [
        "vm_started",
        "guest_channel_connected",
        "guest_channel_terminated",
        "host_packet_sensor_complete",
        "vm_stopped",
        "ephemeral_clone_destroyed",
    ];
    for (index, event) in wire.events.iter().enumerate() {
        if event.kind != expected_kinds[index]
            || decimal_u64_v1(&event.sequence)? != index as u64 + 1
        {
            return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidEvent);
        }
    }
    Ok(LinuxVzHostEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        raw_frame_count,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzHostEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzHostEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canonical_payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "clone_destroyed": true,
            "dropped_frame_count": "0",
            "event_count": "6",
            "event_sequence_end": "6",
            "event_sequence_start": "1",
            "events": [
                {"kind": "vm_started", "sequence": "1"},
                {"kind": "guest_channel_connected", "sequence": "2"},
                {"kind": "guest_channel_terminated", "sequence": "3"},
                {"kind": "host_packet_sensor_complete", "sequence": "4"},
                {"kind": "vm_stopped", "sequence": "5"},
                {"kind": "ephemeral_clone_destroyed", "sequence": "6"}
            ],
            "evidence_truncated": false,
            "external_frames_forwarded": "0",
            "external_route_configured": false,
            "guest_channel_terminated": true,
            "heartbeat_count": "2",
            "package_execution": false,
            "packet_sensor_healthy": true,
            "packet_sensor_terminal": "drained_would_block",
            "raw_frame_count": "0",
            "root_disk_present": false,
            "schema_version": LINUX_VZ_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "storage_device_count": "0",
            "sync_back": false,
            "vm_started": true,
            "vm_stopped": true
        }))
        .expect("canonical host payload")
    }

    #[test]
    fn exact_inert_host_payload_derives_strict_claims() {
        let bytes = canonical_payload();
        let payload = decode_linux_vz_host_evidence_payload_v1(&bytes).expect("host payload");
        assert_eq!(payload.raw_frame_count(), 0);
        assert_eq!(payload.canonical_json_v1(), bytes);
        let claims = payload.host_observation_claims_v1().expect("host claims");
        assert!(claims.packet_sensor_healthy());
        assert!(claims.vm_started());
        assert!(claims.vm_stopped());
        assert!(claims.clone_destroyed());
    }

    #[test]
    fn host_payload_rejects_noncanonical_and_changed_observation() {
        let mut bytes = canonical_payload();
        bytes.push(b'\n');
        assert_eq!(
            decode_linux_vz_host_evidence_payload_v1(&bytes),
            Err(LinuxVzHostEvidencePayloadErrorV1::NonCanonical)
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical_payload()).expect("host JSON");
        value["raw_frame_count"] = serde_json::json!("1");
        let changed = serde_json_canonicalizer::to_vec(&value).expect("changed host JSON");
        assert_eq!(
            decode_linux_vz_host_evidence_payload_v1(&changed),
            Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema)
        );
    }
}
