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
    channel_interruption: Option<LinuxVzChannelInterruptionEvidenceV1>,
    vm_stop: Option<LinuxVzVmStopEvidenceV1>,
    guest_sensor_death: Option<LinuxVzGuestSensorDeathEvidenceV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzChannelInterruptionEvidenceV1 {
    request_frame_bytes: u64,
    transmitted_prefix_bytes: u64,
    response_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzVmStopEvidenceV1 {
    request_frame_bytes: u64,
    transmitted_request_bytes: u64,
    response_bytes: u64,
    fixture_active_marker_observed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzGuestSensorDeathEvidenceV1 {
    request_frame_bytes: u64,
    transmitted_request_bytes: u64,
    response_bytes: u64,
    fixture_active_marker_observed: bool,
    signal: u64,
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

    pub fn channel_interruption(&self) -> Option<&LinuxVzChannelInterruptionEvidenceV1> {
        self.channel_interruption.as_ref()
    }

    pub fn vm_stop(&self) -> Option<&LinuxVzVmStopEvidenceV1> {
        self.vm_stop.as_ref()
    }

    pub fn guest_sensor_death(&self) -> Option<&LinuxVzGuestSensorDeathEvidenceV1> {
        self.guest_sensor_death.as_ref()
    }

    pub fn host_observation_claims_v1(
        &self,
    ) -> Result<LinuxVzTelemetryHostObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1> {
        self.host_observation_claims_for_terminal_v1(
            LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
        )
    }

    pub fn host_observation_claims_for_terminal_v1(
        &self,
        observed_terminal: LinuxVzTelemetryConformanceObservedTerminalV1,
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
            observed_terminal,
        )
    }
}

impl LinuxVzChannelInterruptionEvidenceV1 {
    pub fn request_frame_bytes(&self) -> u64 {
        self.request_frame_bytes
    }

    pub fn transmitted_prefix_bytes(&self) -> u64 {
        self.transmitted_prefix_bytes
    }

    pub fn response_bytes(&self) -> u64 {
        self.response_bytes
    }
}

impl LinuxVzVmStopEvidenceV1 {
    pub fn request_frame_bytes(&self) -> u64 {
        self.request_frame_bytes
    }

    pub fn transmitted_request_bytes(&self) -> u64 {
        self.transmitted_request_bytes
    }

    pub fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    pub fn fixture_active_marker_observed(&self) -> bool {
        self.fixture_active_marker_observed
    }
}

impl LinuxVzGuestSensorDeathEvidenceV1 {
    pub fn request_frame_bytes(&self) -> u64 {
        self.request_frame_bytes
    }

    pub fn transmitted_request_bytes(&self) -> u64 {
        self.transmitted_request_bytes
    }

    pub fn response_bytes(&self) -> u64 {
        self.response_bytes
    }

    pub fn fixture_active_marker_observed(&self) -> bool {
        self.fixture_active_marker_observed
    }

    pub fn signal(&self) -> u64 {
        self.signal
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostEvidenceWireV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_interruption_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_request_frame_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_response_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    channel_transmitted_prefix_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vm_stop_fixture_active_marker_observed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vm_stop_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vm_stop_request_frame_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vm_stop_response_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    vm_stop_transmitted_request_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_sensor_death_fixture_active_marker_observed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_sensor_death_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_sensor_death_request_frame_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_sensor_death_response_bytes: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_sensor_death_signal: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    guest_sensor_death_transmitted_request_bytes: Option<String>,
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
    let channel_interruption = match (
        wire.channel_interruption_kind.as_deref(),
        wire.channel_request_frame_bytes.as_deref(),
        wire.channel_response_bytes.as_deref(),
        wire.channel_transmitted_prefix_bytes.as_deref(),
    ) {
        (None, None, None, None) => None,
        (
            Some("host_write_half_close_after_request_header"),
            Some(request_frame_bytes),
            Some(response_bytes),
            Some(transmitted_prefix_bytes),
        ) => {
            let request_frame_bytes = decimal_u64_v1(request_frame_bytes)?;
            let response_bytes = decimal_u64_v1(response_bytes)?;
            let transmitted_prefix_bytes = decimal_u64_v1(transmitted_prefix_bytes)?;
            if request_frame_bytes <= 16 || transmitted_prefix_bytes != 16 || response_bytes != 0 {
                return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema);
            }
            Some(LinuxVzChannelInterruptionEvidenceV1 {
                request_frame_bytes,
                transmitted_prefix_bytes,
                response_bytes,
            })
        }
        _ => return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema),
    };
    let vm_stop = match (
        wire.vm_stop_kind.as_deref(),
        wire.vm_stop_request_frame_bytes.as_deref(),
        wire.vm_stop_transmitted_request_bytes.as_deref(),
        wire.vm_stop_response_bytes.as_deref(),
        wire.vm_stop_fixture_active_marker_observed,
    ) {
        (None, None, None, None, None) => None,
        (
            Some("host_stop_after_guest_fixture_active"),
            Some(request_frame_bytes),
            Some(transmitted_request_bytes),
            Some(response_bytes),
            Some(true),
        ) => {
            let request_frame_bytes = decimal_u64_v1(request_frame_bytes)?;
            let transmitted_request_bytes = decimal_u64_v1(transmitted_request_bytes)?;
            let response_bytes = decimal_u64_v1(response_bytes)?;
            if request_frame_bytes <= 16
                || transmitted_request_bytes != request_frame_bytes
                || response_bytes != 0
            {
                return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema);
            }
            Some(LinuxVzVmStopEvidenceV1 {
                request_frame_bytes,
                transmitted_request_bytes,
                response_bytes,
                fixture_active_marker_observed: true,
            })
        }
        _ => return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema),
    };
    let guest_sensor_death = match (
        wire.guest_sensor_death_kind.as_deref(),
        wire.guest_sensor_death_request_frame_bytes.as_deref(),
        wire.guest_sensor_death_transmitted_request_bytes.as_deref(),
        wire.guest_sensor_death_response_bytes.as_deref(),
        wire.guest_sensor_death_fixture_active_marker_observed,
        wire.guest_sensor_death_signal.as_deref(),
    ) {
        (None, None, None, None, None, None) => None,
        (
            Some("guest_signer_sigkill_after_protected_sensor_ready"),
            Some(request_frame_bytes),
            Some(transmitted_request_bytes),
            Some(response_bytes),
            Some(true),
            Some(signal),
        ) => {
            let request_frame_bytes = decimal_u64_v1(request_frame_bytes)?;
            let transmitted_request_bytes = decimal_u64_v1(transmitted_request_bytes)?;
            let response_bytes = decimal_u64_v1(response_bytes)?;
            let signal = decimal_u64_v1(signal)?;
            if request_frame_bytes <= 16
                || transmitted_request_bytes != request_frame_bytes
                || response_bytes != 0
                || signal != 9
            {
                return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema);
            }
            Some(LinuxVzGuestSensorDeathEvidenceV1 {
                request_frame_bytes,
                transmitted_request_bytes,
                response_bytes,
                fixture_active_marker_observed: true,
                signal,
            })
        }
        _ => return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema),
    };
    if [
        channel_interruption.is_some(),
        vm_stop.is_some(),
        guest_sensor_death.is_some(),
    ]
    .into_iter()
    .filter(|present| *present)
    .count()
        > 1
    {
        return Err(LinuxVzHostEvidencePayloadErrorV1::InvalidSchema);
    }
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
        channel_interruption,
        vm_stop,
        guest_sensor_death,
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

    fn canonical_channel_interruption_payload() -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical_payload()).expect("host JSON");
        value["channel_interruption_kind"] =
            serde_json::json!("host_write_half_close_after_request_header");
        value["channel_request_frame_bytes"] = serde_json::json!("5082");
        value["channel_response_bytes"] = serde_json::json!("0");
        value["channel_transmitted_prefix_bytes"] = serde_json::json!("16");
        serde_json_canonicalizer::to_vec(&value).expect("channel interruption host payload")
    }

    fn canonical_vm_stop_payload() -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical_payload()).expect("host JSON");
        value["vm_stop_fixture_active_marker_observed"] = serde_json::json!(true);
        value["vm_stop_kind"] = serde_json::json!("host_stop_after_guest_fixture_active");
        value["vm_stop_request_frame_bytes"] = serde_json::json!("5082");
        value["vm_stop_response_bytes"] = serde_json::json!("0");
        value["vm_stop_transmitted_request_bytes"] = serde_json::json!("5082");
        serde_json_canonicalizer::to_vec(&value).expect("VM-stop host payload")
    }

    fn canonical_guest_sensor_death_payload() -> Vec<u8> {
        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical_payload()).expect("host JSON");
        value["guest_sensor_death_fixture_active_marker_observed"] = serde_json::json!(true);
        value["guest_sensor_death_kind"] =
            serde_json::json!("guest_signer_sigkill_after_protected_sensor_ready");
        value["guest_sensor_death_request_frame_bytes"] = serde_json::json!("5082");
        value["guest_sensor_death_response_bytes"] = serde_json::json!("0");
        value["guest_sensor_death_signal"] = serde_json::json!("9");
        value["guest_sensor_death_transmitted_request_bytes"] = serde_json::json!("5082");
        serde_json_canonicalizer::to_vec(&value).expect("guest-sensor-death host payload")
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
        assert_eq!(
            claims.observed_terminal(),
            LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete
        );
        let incomplete = payload
            .host_observation_claims_for_terminal_v1(
                LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap,
            )
            .expect("incomplete host claims");
        assert_eq!(
            incomplete.observed_terminal(),
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap
        );
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

    #[test]
    fn channel_interruption_binds_exact_header_prefix_and_zero_response() {
        let payload =
            decode_linux_vz_host_evidence_payload_v1(&canonical_channel_interruption_payload())
                .expect("channel interruption payload");
        let interruption = payload
            .channel_interruption()
            .expect("channel interruption evidence");
        assert_eq!(interruption.request_frame_bytes(), 5082);
        assert_eq!(interruption.transmitted_prefix_bytes(), 16);
        assert_eq!(interruption.response_bytes(), 0);
    }

    #[test]
    fn channel_interruption_rejects_partial_and_rebound_claims() {
        for (field, changed) in [
            ("channel_request_frame_bytes", serde_json::json!("16")),
            ("channel_transmitted_prefix_bytes", serde_json::json!("15")),
            ("channel_response_bytes", serde_json::json!("1")),
            (
                "channel_interruption_kind",
                serde_json::json!("socket_closed"),
            ),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_slice(&canonical_channel_interruption_payload())
                    .expect("channel host JSON");
            value[field] = changed;
            let bytes = serde_json_canonicalizer::to_vec(&value).expect("changed host JSON");
            assert!(decode_linux_vz_host_evidence_payload_v1(&bytes).is_err());
        }
        let mut partial: serde_json::Value =
            serde_json::from_slice(&canonical_payload()).expect("host JSON");
        partial["channel_interruption_kind"] =
            serde_json::json!("host_write_half_close_after_request_header");
        let bytes = serde_json_canonicalizer::to_vec(&partial).expect("partial host JSON");
        assert!(decode_linux_vz_host_evidence_payload_v1(&bytes).is_err());
    }

    #[test]
    fn vm_stop_binds_full_request_zero_response_and_active_fixture() {
        let payload = decode_linux_vz_host_evidence_payload_v1(&canonical_vm_stop_payload())
            .expect("VM-stop payload");
        let vm_stop = payload.vm_stop().expect("VM-stop evidence");
        assert_eq!(vm_stop.request_frame_bytes(), 5082);
        assert_eq!(vm_stop.transmitted_request_bytes(), 5082);
        assert_eq!(vm_stop.response_bytes(), 0);
        assert!(vm_stop.fixture_active_marker_observed());
    }

    #[test]
    fn vm_stop_rejects_partial_rebound_and_channel_coexistence() {
        for (field, changed) in [
            ("vm_stop_request_frame_bytes", serde_json::json!("16")),
            (
                "vm_stop_transmitted_request_bytes",
                serde_json::json!("5081"),
            ),
            ("vm_stop_response_bytes", serde_json::json!("1")),
            (
                "vm_stop_fixture_active_marker_observed",
                serde_json::json!(false),
            ),
            ("vm_stop_kind", serde_json::json!("socket_closed")),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_slice(&canonical_vm_stop_payload()).expect("VM-stop JSON");
            value[field] = changed;
            let bytes = serde_json_canonicalizer::to_vec(&value).expect("changed JSON");
            assert!(decode_linux_vz_host_evidence_payload_v1(&bytes).is_err());
        }
        let mut both: serde_json::Value =
            serde_json::from_slice(&canonical_vm_stop_payload()).expect("VM-stop JSON");
        both["channel_interruption_kind"] =
            serde_json::json!("host_write_half_close_after_request_header");
        both["channel_request_frame_bytes"] = serde_json::json!("5082");
        both["channel_response_bytes"] = serde_json::json!("0");
        both["channel_transmitted_prefix_bytes"] = serde_json::json!("16");
        let bytes = serde_json_canonicalizer::to_vec(&both).expect("coexisting JSON");
        assert!(decode_linux_vz_host_evidence_payload_v1(&bytes).is_err());
    }

    #[test]
    fn guest_sensor_death_binds_full_request_active_fixture_and_sigkill() {
        let payload =
            decode_linux_vz_host_evidence_payload_v1(&canonical_guest_sensor_death_payload())
                .expect("guest-sensor-death payload");
        let death = payload
            .guest_sensor_death()
            .expect("guest-sensor-death evidence");
        assert_eq!(death.request_frame_bytes(), 5082);
        assert_eq!(death.transmitted_request_bytes(), 5082);
        assert_eq!(death.response_bytes(), 0);
        assert!(death.fixture_active_marker_observed());
        assert_eq!(death.signal(), 9);
    }

    #[test]
    fn guest_sensor_death_rejects_partial_rebound_and_other_fault_fields() {
        for (field, changed) in [
            (
                "guest_sensor_death_request_frame_bytes",
                serde_json::json!("16"),
            ),
            (
                "guest_sensor_death_transmitted_request_bytes",
                serde_json::json!("5081"),
            ),
            ("guest_sensor_death_response_bytes", serde_json::json!("1")),
            ("guest_sensor_death_signal", serde_json::json!("15")),
            (
                "guest_sensor_death_fixture_active_marker_observed",
                serde_json::json!(false),
            ),
        ] {
            let mut value: serde_json::Value =
                serde_json::from_slice(&canonical_guest_sensor_death_payload())
                    .expect("guest-sensor-death JSON");
            value[field] = changed;
            let bytes = serde_json_canonicalizer::to_vec(&value).expect("changed JSON");
            assert!(decode_linux_vz_host_evidence_payload_v1(&bytes).is_err());
        }
        let mut both: serde_json::Value =
            serde_json::from_slice(&canonical_guest_sensor_death_payload())
                .expect("guest-sensor-death JSON");
        both["vm_stop_fixture_active_marker_observed"] = serde_json::json!(true);
        both["vm_stop_kind"] = serde_json::json!("host_stop_after_guest_fixture_active");
        both["vm_stop_request_frame_bytes"] = serde_json::json!("5082");
        both["vm_stop_response_bytes"] = serde_json::json!("0");
        both["vm_stop_transmitted_request_bytes"] = serde_json::json!("5082");
        let bytes = serde_json_canonicalizer::to_vec(&both).expect("coexisting JSON");
        assert!(decode_linux_vz_host_evidence_payload_v1(&bytes).is_err());
    }
}
