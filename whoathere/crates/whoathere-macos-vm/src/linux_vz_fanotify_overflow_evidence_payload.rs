use crate::{
    LinuxVzTelemetryConformanceCaseV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_fanotify_overflow_evidence_payload.v1";
pub const LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_SERIAL_PREFIX_V1: &[u8] =
    b"WHOATHERE_GUEST_FANOTIFY_OVERFLOW_EVIDENCE ";
pub const MAX_LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzFanotifyOverflowEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzFanotifyOverflowEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_fanotify_overflow_evidence_missing",
            Self::Duplicate => "linux_vz_fanotify_overflow_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_fanotify_overflow_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_fanotify_overflow_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_fanotify_overflow_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_fanotify_overflow_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_fanotify_overflow_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzFanotifyOverflowEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzFanotifyOverflowEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    dropped_event_count: u64,
}

impl LinuxVzFanotifyOverflowEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow
    }

    pub fn package_uid(&self) -> u32 {
        65534
    }

    pub fn package_gid(&self) -> u32 {
        65534
    }

    pub fn dropped_event_count(&self) -> u64 {
        self.dropped_event_count
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
struct FanotifyOverflowEvidenceWireV1 {
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<FanotifyOverflowEventWireV1>,
    evidence_truncated: bool,
    fanotify_observed_event_count: String,
    fanotify_overflow_marker_count: String,
    fanotify_queue_limit_injected: String,
    fanotify_queue_limit_original: String,
    fanotify_queue_limit_restored: bool,
    fanotify_trigger_count: String,
    fanotify_unique_inode_count: String,
    fixture_case: String,
    heartbeat_count: String,
    injection_kind: String,
    package_gid: String,
    package_uid: String,
    schema_version: String,
    sensor_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FanotifyOverflowEventWireV1 {
    actor_pid: String,
    kind: String,
    sequence: String,
    timestamp_ns: String,
}

pub fn decode_linux_vz_fanotify_overflow_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<LinuxVzFanotifyOverflowEvidencePayloadV1, LinuxVzFanotifyOverflowEvidencePayloadErrorV1>
{
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) =
            line.strip_prefix(LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_SERIAL_PREFIX_V1)
        else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_fanotify_overflow_evidence_payload_v1(
        payload.ok_or(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_fanotify_overflow_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzFanotifyOverflowEvidencePayloadV1, LinuxVzFanotifyOverflowEvidencePayloadErrorV1>
{
    if payload.is_empty()
        || payload.len() > MAX_LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_BYTES_V1
    {
        return Err(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = FanotifyOverflowEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::NonCanonical);
    }
    let dropped = decimal_u64_v1(&wire.dropped_event_count)?;
    let observed = decimal_u64_v1(&wire.fanotify_observed_event_count)?;
    let triggers = decimal_u64_v1(&wire.fanotify_trigger_count)?;
    let injected_limit = decimal_u64_v1(&wire.fanotify_queue_limit_injected)?;
    let original_limit = decimal_u64_v1(&wire.fanotify_queue_limit_original)?;
    if wire.schema_version != LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.fixture_case != "fanotify_queue_overflow"
        || wire.injection_kind != "fanotify_queue_limit_exhaustion"
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 1
        || decimal_u64_v1(&wire.event_count)? != 1
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || injected_limit != 64
        || original_limit < injected_limit
        || triggers != 256
        || decimal_u64_v1(&wire.fanotify_unique_inode_count)? != triggers
        || observed != injected_limit
        || dropped != 192
        || observed.checked_add(dropped) != Some(triggers)
        || decimal_u64_v1(&wire.fanotify_overflow_marker_count)? != 1
        || !wire.fanotify_queue_limit_restored
        || decimal_u64_v1(&wire.package_uid)? != 65534
        || decimal_u64_v1(&wire.package_gid)? != 65534
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
        || wire.events.len() != 1
    {
        return Err(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidSchema);
    }
    let event = &wire.events[0];
    if event.kind != "fanotify_queue_overflow"
        || decimal_u64_v1(&event.sequence)? != 1
        || decimal_u64_v1(&event.actor_pid)? == 0
        || decimal_u64_v1(&event.timestamp_ns)? == 0
    {
        return Err(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidEvent);
    }
    Ok(LinuxVzFanotifyOverflowEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        dropped_event_count: dropped,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzFanotifyOverflowEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "descendant_teardown_complete": true,
            "dropped_event_count": "192",
            "event_count": "1",
            "event_sequence_end": "1",
            "event_sequence_start": "1",
            "events": [{
                "actor_pid": "10",
                "kind": "fanotify_queue_overflow",
                "sequence": "1",
                "timestamp_ns": "100"
            }],
            "evidence_truncated": false,
            "fanotify_observed_event_count": "64",
            "fanotify_overflow_marker_count": "1",
            "fanotify_queue_limit_injected": "64",
            "fanotify_queue_limit_original": "16384",
            "fanotify_queue_limit_restored": true,
            "fanotify_trigger_count": "256",
            "fanotify_unique_inode_count": "256",
            "fixture_case": "fanotify_queue_overflow",
            "heartbeat_count": "2",
            "injection_kind": "fanotify_queue_limit_exhaustion",
            "package_gid": "65534",
            "package_uid": "65534",
            "schema_version": LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "sensor_healthy": true
        }))
        .unwrap()
    }

    #[test]
    fn exact_fanotify_gap_derives_incomplete_claims() {
        let evidence = decode_linux_vz_fanotify_overflow_evidence_payload_v1(&payload()).unwrap();
        assert_eq!(evidence.dropped_event_count(), 192);
        let claims = evidence.guest_observation_claims_v1().unwrap();
        assert_eq!(claims.dropped_event_count(), 192);
        assert_eq!(
            claims.observed_terminal(),
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap
        );
    }

    #[test]
    fn fanotify_gap_rejects_missing_marker_restore_and_count_rebinding() {
        for (field, value) in [
            ("fanotify_overflow_marker_count", serde_json::json!("0")),
            ("fanotify_queue_limit_restored", serde_json::json!(false)),
            ("fanotify_observed_event_count", serde_json::json!("63")),
            ("dropped_event_count", serde_json::json!("191")),
            ("fanotify_unique_inode_count", serde_json::json!("255")),
        ] {
            let mut changed: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
            changed[field] = value;
            let encoded = serde_json_canonicalizer::to_vec(&changed).unwrap();
            assert_eq!(
                decode_linux_vz_fanotify_overflow_evidence_payload_v1(&encoded),
                Err(LinuxVzFanotifyOverflowEvidencePayloadErrorV1::InvalidSchema)
            );
        }
    }
}
