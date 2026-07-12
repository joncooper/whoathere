use crate::{
    LinuxVzTelemetryConformanceCaseV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_DROP_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_drop_evidence_payload.v1";
pub const LINUX_VZ_DROP_EVIDENCE_SERIAL_PREFIX_V1: &[u8] = b"WHOATHERE_GUEST_DROP_EVIDENCE ";
pub const MAX_LINUX_VZ_DROP_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzDropEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzDropEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_drop_evidence_missing",
            Self::Duplicate => "linux_vz_drop_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_drop_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_drop_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_drop_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_drop_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_drop_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzDropEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzDropEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    dropped_event_count: u64,
    package_uid: u32,
    package_gid: u32,
}

impl LinuxVzDropEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure
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
            self.canonical_json.len() as u64,
            1,
            1,
            1,
            2,
            self.dropped_event_count,
            true,
            false,
            true,
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DropEvidenceWireV1 {
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<DropEventWireV1>,
    evidence_truncated: bool,
    fixture_case: String,
    heartbeat_count: String,
    injection_kind: String,
    package_gid: String,
    package_uid: String,
    reservation_attempt_count: String,
    reservation_success_count: String,
    ring_buffer_capacity_bytes: String,
    schema_version: String,
    sensor_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DropEventWireV1 {
    actor_pid: String,
    kind: String,
    sequence: String,
    timestamp_ns: String,
}

pub fn decode_linux_vz_drop_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<LinuxVzDropEvidencePayloadV1, LinuxVzDropEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) = line.strip_prefix(LINUX_VZ_DROP_EVIDENCE_SERIAL_PREFIX_V1) else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzDropEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_drop_evidence_payload_v1(
        payload.ok_or(LinuxVzDropEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_drop_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzDropEvidencePayloadV1, LinuxVzDropEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_DROP_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzDropEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = DropEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzDropEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzDropEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzDropEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzDropEvidencePayloadErrorV1::NonCanonical);
    }
    let dropped = decimal_u64_v1(&wire.dropped_event_count)?;
    let attempts = decimal_u64_v1(&wire.reservation_attempt_count)?;
    let successes = decimal_u64_v1(&wire.reservation_success_count)?;
    if wire.schema_version != LINUX_VZ_DROP_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.fixture_case != "bpf_reservation_failure"
        || wire.injection_kind != "ringbuf_reserve_exhaustion"
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 1
        || decimal_u64_v1(&wire.event_count)? != 1
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || decimal_u64_v1(&wire.ring_buffer_capacity_bytes)? != 4096
        || attempts != 2048
        || dropped == 0
        || successes == 0
        || dropped.checked_add(successes) != Some(attempts)
        || decimal_u64_v1(&wire.package_uid)? != 65534
        || decimal_u64_v1(&wire.package_gid)? != 65534
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
        || wire.events.len() != 1
    {
        return Err(LinuxVzDropEvidencePayloadErrorV1::InvalidSchema);
    }
    let event = &wire.events[0];
    if event.kind != "bpf_reservation_failure"
        || decimal_u64_v1(&event.sequence)? != 1
        || decimal_u64_v1(&event.actor_pid)? == 0
        || decimal_u64_v1(&event.timestamp_ns)? == 0
    {
        return Err(LinuxVzDropEvidencePayloadErrorV1::InvalidEvent);
    }
    Ok(LinuxVzDropEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        dropped_event_count: dropped,
        package_uid: 65534,
        package_gid: 65534,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzDropEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzDropEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzDropEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "descendant_teardown_complete": true,
            "dropped_event_count": "1878",
            "event_count": "1",
            "event_sequence_end": "1",
            "event_sequence_start": "1",
            "events": [{
                "actor_pid": "10",
                "kind": "bpf_reservation_failure",
                "sequence": "1",
                "timestamp_ns": "100"
            }],
            "evidence_truncated": false,
            "fixture_case": "bpf_reservation_failure",
            "heartbeat_count": "2",
            "injection_kind": "ringbuf_reserve_exhaustion",
            "package_gid": "65534",
            "package_uid": "65534",
            "reservation_attempt_count": "2048",
            "reservation_success_count": "170",
            "ring_buffer_capacity_bytes": "4096",
            "schema_version": LINUX_VZ_DROP_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "sensor_healthy": true
        }))
        .unwrap()
    }

    #[test]
    fn exact_bpf_gap_derives_incomplete_claims() {
        let evidence = decode_linux_vz_drop_evidence_payload_v1(&payload()).unwrap();
        assert_eq!(evidence.dropped_event_count(), 1878);
        let claims = evidence.guest_observation_claims_v1().unwrap();
        assert_eq!(claims.dropped_event_count(), 1878);
        assert_eq!(
            claims.observed_terminal(),
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap
        );
    }

    #[test]
    fn drop_evidence_rejects_synthetic_or_unaccounted_counts() {
        for (field, value) in [
            ("dropped_event_count", "0"),
            ("reservation_success_count", "0"),
            ("reservation_attempt_count", "2049"),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
            changed[field] = serde_json::json!(value);
            let encoded = serde_json_canonicalizer::to_vec(&changed).unwrap();
            assert_eq!(
                decode_linux_vz_drop_evidence_payload_v1(&encoded),
                Err(LinuxVzDropEvidencePayloadErrorV1::InvalidSchema)
            );
        }
    }
}
