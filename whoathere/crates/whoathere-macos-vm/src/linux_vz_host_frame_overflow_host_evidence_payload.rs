use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryHostObservationClaimsV1,
    MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_HOST_FRAME_OVERFLOW_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_host_frame_overflow_host_evidence_payload.v1";
pub const MAX_LINUX_VZ_HOST_FRAME_OVERFLOW_HOST_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "linux_vz_host_frame_overflow_host_evidence_empty",
            Self::LimitExceeded => "linux_vz_host_frame_overflow_host_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_host_frame_overflow_host_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_host_frame_overflow_host_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_host_frame_overflow_host_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_host_frame_overflow_host_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzHostFrameOverflowHostEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    dropped_frame_count: u64,
    observed_frame_count: u64,
    source_port: u16,
}

impl LinuxVzHostFrameOverflowHostEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn dropped_frame_count(&self) -> u64 {
        self.dropped_frame_count
    }

    pub fn observed_frame_count(&self) -> u64 {
        self.observed_frame_count
    }

    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    pub fn host_observation_claims_v1(
        &self,
    ) -> Result<LinuxVzTelemetryHostObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1> {
        LinuxVzTelemetryHostObservationClaimsV1::new(
            self.payload_sha256.clone(),
            self.canonical_json.len() as u64,
            1,
            7,
            7,
            2,
            self.dropped_frame_count,
            true,
            false,
            true,
            true,
            true,
            true,
            0,
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFrameOverflowHostEvidenceWireV1 {
    clone_destroyed: bool,
    dropped_frame_count: String,
    duplicate_frame_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<HostFrameOverflowHostEventWireV1>,
    evidence_truncated: bool,
    external_frames_forwarded: String,
    external_route_configured: bool,
    guest_channel_terminated: bool,
    guest_trigger_frame_count: String,
    heartbeat_count: String,
    host_frame_queue_capacity: String,
    ingress_frame_count: String,
    observed_frame_count: String,
    package_execution: bool,
    packet_sensor_healthy: bool,
    packet_sensor_terminal: String,
    raw_frame_count: String,
    root_disk_present: bool,
    schema_version: String,
    source_port: String,
    storage_device_count: String,
    sync_back: bool,
    unexpected_frame_count: String,
    unique_sequence_count: String,
    vm_started: bool,
    vm_stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFrameOverflowHostEventWireV1 {
    kind: String,
    sequence: String,
}

pub fn decode_linux_vz_host_frame_overflow_host_evidence_payload_v1(
    payload: &[u8],
) -> Result<
    LinuxVzHostFrameOverflowHostEvidencePayloadV1,
    LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1,
> {
    if payload.is_empty() {
        return Err(LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::Empty);
    }
    if payload.len() > MAX_LINUX_VZ_HOST_FRAME_OVERFLOW_HOST_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = HostFrameOverflowHostEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::NonCanonical);
    }
    let dropped = decimal_u64_v1(&wire.dropped_frame_count)?;
    let observed = decimal_u64_v1(&wire.observed_frame_count)?;
    let triggers = decimal_u64_v1(&wire.guest_trigger_frame_count)?;
    let raw = decimal_u64_v1(&wire.raw_frame_count)?;
    if wire.schema_version != LINUX_VZ_HOST_FRAME_OVERFLOW_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 7
        || decimal_u64_v1(&wire.event_count)? != 7
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || triggers != 512
        || decimal_u64_v1(&wire.ingress_frame_count)? != triggers
        || observed != 64
        || dropped != 448
        || observed.checked_add(dropped) != Some(triggers)
        || raw != observed
        || decimal_u64_v1(&wire.unique_sequence_count)? != observed
        || decimal_u64_v1(&wire.duplicate_frame_count)? != 0
        || decimal_u64_v1(&wire.unexpected_frame_count)? != 0
        || decimal_u64_v1(&wire.host_frame_queue_capacity)? != observed
        || decimal_u64_v1(&wire.source_port)? == 0
        || decimal_u64_v1(&wire.source_port)? > u16::MAX as u64
        || decimal_u64_v1(&wire.external_frames_forwarded)? != 0
        || decimal_u64_v1(&wire.storage_device_count)? != 0
        || !wire.packet_sensor_healthy
        || wire.packet_sensor_terminal != "bounded_queue_overflow_accounted"
        || wire.evidence_truncated
        || !wire.guest_channel_terminated
        || !wire.vm_started
        || !wire.vm_stopped
        || !wire.clone_destroyed
        || wire.root_disk_present
        || wire.external_route_configured
        || wire.package_execution
        || wire.sync_back
        || wire.events.len() != 7
    {
        return Err(LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidSchema);
    }
    let expected_kinds = [
        "vm_started",
        "host_frame_queue_bounded",
        "guest_channel_connected",
        "guest_channel_terminated",
        "host_packet_sensor_incomplete",
        "vm_stopped",
        "ephemeral_clone_destroyed",
    ];
    for (index, event) in wire.events.iter().enumerate() {
        if event.kind != expected_kinds[index]
            || decimal_u64_v1(&event.sequence)? != index as u64 + 1
        {
            return Err(LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidEvent);
        }
    }
    Ok(LinuxVzHostFrameOverflowHostEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        dropped_frame_count: dropped,
        observed_frame_count: observed,
        source_port: decimal_u64_v1(&wire.source_port)? as u16,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "clone_destroyed": true,
            "dropped_frame_count": "448",
            "duplicate_frame_count": "0",
            "event_count": "7",
            "event_sequence_end": "7",
            "event_sequence_start": "1",
            "events": [
                {"kind": "vm_started", "sequence": "1"},
                {"kind": "host_frame_queue_bounded", "sequence": "2"},
                {"kind": "guest_channel_connected", "sequence": "3"},
                {"kind": "guest_channel_terminated", "sequence": "4"},
                {"kind": "host_packet_sensor_incomplete", "sequence": "5"},
                {"kind": "vm_stopped", "sequence": "6"},
                {"kind": "ephemeral_clone_destroyed", "sequence": "7"}
            ],
            "evidence_truncated": false,
            "external_frames_forwarded": "0",
            "external_route_configured": false,
            "guest_channel_terminated": true,
            "guest_trigger_frame_count": "512",
            "heartbeat_count": "2",
            "host_frame_queue_capacity": "64",
            "ingress_frame_count": "512",
            "observed_frame_count": "64",
            "package_execution": false,
            "packet_sensor_healthy": true,
            "packet_sensor_terminal": "bounded_queue_overflow_accounted",
            "raw_frame_count": "64",
            "root_disk_present": false,
            "schema_version": LINUX_VZ_HOST_FRAME_OVERFLOW_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "source_port": "49152",
            "storage_device_count": "0",
            "sync_back": false,
            "unexpected_frame_count": "0",
            "unique_sequence_count": "64",
            "vm_started": true,
            "vm_stopped": true
        }))
        .unwrap()
    }

    #[test]
    fn exact_host_gap_derives_incomplete_claims() {
        let evidence =
            decode_linux_vz_host_frame_overflow_host_evidence_payload_v1(&payload()).unwrap();
        assert_eq!(evidence.observed_frame_count(), 64);
        assert_eq!(evidence.dropped_frame_count(), 448);
        let claims = evidence.host_observation_claims_v1().unwrap();
        assert_eq!(claims.dropped_frame_count(), 448);
        assert!(claims.packet_sensor_healthy());
        assert_eq!(
            claims.observed_terminal(),
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap
        );
    }

    #[test]
    fn host_gap_rejects_missing_drop_and_count_rebinding() {
        for (field, value) in [
            ("dropped_frame_count", serde_json::json!("0")),
            ("ingress_frame_count", serde_json::json!("511")),
            ("observed_frame_count", serde_json::json!("63")),
            ("unique_sequence_count", serde_json::json!("63")),
            ("duplicate_frame_count", serde_json::json!("1")),
            ("unexpected_frame_count", serde_json::json!("1")),
            ("host_frame_queue_capacity", serde_json::json!("63")),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
            changed[field] = value;
            let encoded = serde_json_canonicalizer::to_vec(&changed).unwrap();
            assert_eq!(
                decode_linux_vz_host_frame_overflow_host_evidence_payload_v1(&encoded),
                Err(LinuxVzHostFrameOverflowHostEvidencePayloadErrorV1::InvalidSchema)
            );
        }
    }
}
