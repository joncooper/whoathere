use crate::{
    LinuxVzTelemetryConformanceCaseV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_host_frame_overflow_guest_evidence_payload.v1";
pub const LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_SERIAL_PREFIX_V1: &[u8] =
    b"WHOATHERE_GUEST_HOST_FRAME_OVERFLOW_EVIDENCE ";
pub const MAX_LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_host_frame_overflow_guest_evidence_missing",
            Self::Duplicate => "linux_vz_host_frame_overflow_guest_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_host_frame_overflow_guest_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_host_frame_overflow_guest_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_host_frame_overflow_guest_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_host_frame_overflow_guest_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_host_frame_overflow_guest_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzHostFrameOverflowGuestEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    source_port: u16,
    trigger_count: u64,
}

impl LinuxVzHostFrameOverflowGuestEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow
    }

    pub fn package_uid(&self) -> u32 {
        65534
    }

    pub fn package_gid(&self) -> u32 {
        65534
    }

    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    pub fn trigger_count(&self) -> u64 {
        self.trigger_count
    }

    pub fn guest_observation_claims_v1(
        &self,
    ) -> Result<LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1>
    {
        LinuxVzTelemetryGuestObservationClaimsV1::new(
            self.payload_sha256.clone(),
            self.canonical_json.len() as u64,
            1,
            1,
            1,
            2,
            0,
            true,
            false,
            true,
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFrameOverflowGuestEvidenceWireV1 {
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<HostFrameOverflowGuestEventWireV1>,
    evidence_truncated: bool,
    fixture_case: String,
    heartbeat_count: String,
    host_frame_payload_bytes: String,
    host_frame_source_port: String,
    host_frame_transmitted_count: String,
    host_frame_trigger_count: String,
    host_frame_tx_dropped_count: String,
    host_frame_tx_error_count: String,
    package_gid: String,
    package_uid: String,
    schema_version: String,
    sensor_healthy: bool,
    traffic_kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostFrameOverflowGuestEventWireV1 {
    actor_pid: String,
    kind: String,
    sequence: String,
    timestamp_ns: String,
}

pub fn decode_linux_vz_host_frame_overflow_guest_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<
    LinuxVzHostFrameOverflowGuestEvidencePayloadV1,
    LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1,
> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) =
            line.strip_prefix(LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_SERIAL_PREFIX_V1)
        else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_host_frame_overflow_guest_evidence_payload_v1(
        payload.ok_or(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_host_frame_overflow_guest_evidence_payload_v1(
    payload: &[u8],
) -> Result<
    LinuxVzHostFrameOverflowGuestEvidencePayloadV1,
    LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1,
> {
    if payload.is_empty()
        || payload.len() > MAX_LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_BYTES_V1
    {
        return Err(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = HostFrameOverflowGuestEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::NonCanonical);
    }
    let source_port = decimal_u64_v1(&wire.host_frame_source_port)?;
    let trigger_count = decimal_u64_v1(&wire.host_frame_trigger_count)?;
    if wire.schema_version != LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.fixture_case != "host_frame_overflow"
        || wire.traffic_kind != "sequenced_udp_sinkhole_frames"
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 1
        || decimal_u64_v1(&wire.event_count)? != 1
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || decimal_u64_v1(&wire.dropped_event_count)? != 0
        || decimal_u64_v1(&wire.host_frame_payload_bytes)? != 16
        || source_port == 0
        || source_port > u16::MAX as u64
        || trigger_count != 512
        || decimal_u64_v1(&wire.host_frame_transmitted_count)? != trigger_count
        || decimal_u64_v1(&wire.host_frame_tx_dropped_count)? != 0
        || decimal_u64_v1(&wire.host_frame_tx_error_count)? != 0
        || decimal_u64_v1(&wire.package_uid)? != 65534
        || decimal_u64_v1(&wire.package_gid)? != 65534
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
        || wire.events.len() != 1
    {
        return Err(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidSchema);
    }
    let event = &wire.events[0];
    if event.kind != "host_frame_overflow_trigger"
        || decimal_u64_v1(&event.sequence)? != 1
        || decimal_u64_v1(&event.actor_pid)? == 0
        || decimal_u64_v1(&event.timestamp_ns)? == 0
    {
        return Err(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidEvent);
    }
    Ok(LinuxVzHostFrameOverflowGuestEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        source_port: source_port as u16,
        trigger_count,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "descendant_teardown_complete": true,
            "dropped_event_count": "0",
            "event_count": "1",
            "event_sequence_end": "1",
            "event_sequence_start": "1",
            "events": [{
                "actor_pid": "10",
                "kind": "host_frame_overflow_trigger",
                "sequence": "1",
                "timestamp_ns": "100"
            }],
            "evidence_truncated": false,
            "fixture_case": "host_frame_overflow",
            "heartbeat_count": "2",
            "host_frame_payload_bytes": "16",
            "host_frame_source_port": "49152",
            "host_frame_transmitted_count": "512",
            "host_frame_trigger_count": "512",
            "host_frame_tx_dropped_count": "0",
            "host_frame_tx_error_count": "0",
            "package_gid": "65534",
            "package_uid": "65534",
            "schema_version": LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "sensor_healthy": true,
            "traffic_kind": "sequenced_udp_sinkhole_frames"
        }))
        .unwrap()
    }

    #[test]
    fn exact_guest_trigger_derives_incomplete_claims_without_guest_drops() {
        let evidence =
            decode_linux_vz_host_frame_overflow_guest_evidence_payload_v1(&payload()).unwrap();
        assert_eq!(evidence.source_port(), 49152);
        assert_eq!(evidence.trigger_count(), 512);
        let claims = evidence.guest_observation_claims_v1().unwrap();
        assert_eq!(claims.dropped_event_count(), 0);
        assert_eq!(
            claims.observed_terminal(),
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap
        );
    }

    #[test]
    fn guest_trigger_rejects_count_and_tx_rebinding() {
        for (field, value) in [
            ("host_frame_transmitted_count", serde_json::json!("511")),
            ("host_frame_trigger_count", serde_json::json!("511")),
            ("host_frame_tx_dropped_count", serde_json::json!("1")),
            ("host_frame_tx_error_count", serde_json::json!("1")),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
            changed[field] = value;
            let encoded = serde_json_canonicalizer::to_vec(&changed).unwrap();
            assert_eq!(
                decode_linux_vz_host_frame_overflow_guest_evidence_payload_v1(&encoded),
                Err(LinuxVzHostFrameOverflowGuestEvidencePayloadErrorV1::InvalidSchema)
            );
        }
    }
}
