use crate::{
    LinuxVzTelemetryConformanceCaseV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_network_evidence_payload.v1";
pub const LINUX_VZ_NETWORK_EVIDENCE_SERIAL_PREFIX_V1: &[u8] = b"WHOATHERE_GUEST_NETWORK_EVIDENCE ";
pub const MAX_LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzNetworkEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzNetworkEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_network_evidence_missing",
            Self::Duplicate => "linux_vz_network_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_network_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_network_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_network_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_network_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_network_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzNetworkEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzNetworkEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    package_uid: u32,
    package_gid: u32,
    source_port: u16,
}

impl LinuxVzNetworkEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        self.fixture_case
    }

    pub fn source_port(&self) -> u16 {
        self.source_port
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
            4,
            4,
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
struct NetworkEvidenceWireV1 {
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<NetworkEventWireV1>,
    evidence_truncated: bool,
    fixture_case: String,
    heartbeat_count: String,
    network_action: String,
    network_family: String,
    network_protocol: String,
    network_socket_state: String,
    network_source: String,
    network_source_port: String,
    network_target: String,
    network_target_port: String,
    package_gid: String,
    package_uid: String,
    reaped_process_count: String,
    schema_version: String,
    sensor_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkEventWireV1 {
    actor_pid: String,
    cgroup_id: String,
    kind: String,
    sequence: String,
    subject_pid: String,
    timestamp_ns: String,
}

pub fn decode_linux_vz_network_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<LinuxVzNetworkEvidencePayloadV1, LinuxVzNetworkEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) = line.strip_prefix(LINUX_VZ_NETWORK_EVIDENCE_SERIAL_PREFIX_V1) else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzNetworkEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_network_evidence_payload_v1(
        payload.ok_or(LinuxVzNetworkEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_network_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzNetworkEvidencePayloadV1, LinuxVzNetworkEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzNetworkEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = NetworkEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzNetworkEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzNetworkEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzNetworkEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzNetworkEvidencePayloadErrorV1::NonCanonical);
    }
    let source_port = decimal_u64_v1(&wire.network_source_port)?;
    let fixture_case = match wire.fixture_case.as_str() {
        "ipv4_connect"
            if wire.network_family == "ipv4"
                && wire.network_source == "192.0.2.2"
                && wire.network_target == "192.0.2.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::Ipv4Connect
        }
        "ipv6_connect"
            if wire.network_family == "ipv6"
                && wire.network_source == "2001:db8::2"
                && wire.network_target == "2001:db8::1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
        }
        "udp_send"
            if wire.network_family == "ipv4"
                && wire.network_source == "192.0.2.2"
                && wire.network_target == "192.0.2.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::UdpSend
        }
        "loopback_connect"
            if wire.network_family == "ipv4"
                && wire.network_source == "127.0.0.1"
                && wire.network_target == "127.0.0.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::LoopbackConnect
        }
        _ => return Err(LinuxVzNetworkEvidencePayloadErrorV1::InvalidSchema),
    };
    let (expected_action, expected_protocol, expected_socket_state, expected_event_kind) =
        if fixture_case == LinuxVzTelemetryConformanceCaseV1::UdpSend {
            ("udp_send", "udp", "unconnected_bound", "sendto")
        } else if fixture_case == LinuxVzTelemetryConformanceCaseV1::LoopbackConnect {
            ("tcp_connect", "tcp", "established", "connect")
        } else {
            ("tcp_connect", "tcp", "syn_sent", "connect")
        };
    let expected_target_port = if fixture_case == LinuxVzTelemetryConformanceCaseV1::LoopbackConnect
    {
        40_552
    } else {
        443
    };
    if wire.schema_version != LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.network_action != expected_action
        || wire.network_protocol != expected_protocol
        || wire.network_socket_state != expected_socket_state
        || decimal_u64_v1(&wire.network_target_port)? != expected_target_port
        || source_port == 0
        || source_port > u16::MAX as u64
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 4
        || decimal_u64_v1(&wire.event_count)? != 4
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || decimal_u64_v1(&wire.dropped_event_count)? != 0
        || decimal_u64_v1(&wire.package_uid)? != 65534
        || decimal_u64_v1(&wire.package_gid)? != 65534
        || decimal_u64_v1(&wire.reaped_process_count)? != 1
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
        || wire.events.len() != 4
    {
        return Err(LinuxVzNetworkEvidencePayloadErrorV1::InvalidSchema);
    }
    let expected_kinds = ["fork", "exec", expected_event_kind, "exit"];
    let mut child_pid = None;
    let mut cgroup_id = None;
    let mut prior_timestamp = 0;
    for (index, event) in wire.events.iter().enumerate() {
        let actor = decimal_u64_v1(&event.actor_pid)?;
        let subject = decimal_u64_v1(&event.subject_pid)?;
        let cgroup = decimal_u64_v1(&event.cgroup_id)?;
        let timestamp = decimal_u64_v1(&event.timestamp_ns)?;
        if event.kind != expected_kinds[index]
            || decimal_u64_v1(&event.sequence)? != index as u64 + 1
            || actor == 0
            || subject == 0
            || cgroup == 0
            || timestamp <= prior_timestamp
        {
            return Err(LinuxVzNetworkEvidencePayloadErrorV1::InvalidEvent);
        }
        if index == 0 {
            if actor == subject {
                return Err(LinuxVzNetworkEvidencePayloadErrorV1::InvalidEvent);
            }
            child_pid = Some(subject);
            cgroup_id = Some(cgroup);
        } else if actor != child_pid.unwrap()
            || subject != child_pid.unwrap()
            || cgroup != cgroup_id.unwrap()
        {
            return Err(LinuxVzNetworkEvidencePayloadErrorV1::InvalidEvent);
        }
        prior_timestamp = timestamp;
    }
    Ok(LinuxVzNetworkEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        fixture_case,
        package_uid: 65534,
        package_gid: 65534,
        source_port: source_port as u16,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzNetworkEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzNetworkEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzNetworkEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "descendant_teardown_complete": true,
            "dropped_event_count": "0",
            "event_count": "4",
            "event_sequence_end": "4",
            "event_sequence_start": "1",
            "events": [
                {"actor_pid":"10","cgroup_id":"21","kind":"fork","sequence":"1","subject_pid":"11","timestamp_ns":"100"},
                {"actor_pid":"11","cgroup_id":"21","kind":"exec","sequence":"2","subject_pid":"11","timestamp_ns":"200"},
                {"actor_pid":"11","cgroup_id":"21","kind":"connect","sequence":"3","subject_pid":"11","timestamp_ns":"300"},
                {"actor_pid":"11","cgroup_id":"21","kind":"exit","sequence":"4","subject_pid":"11","timestamp_ns":"400"}
            ],
            "evidence_truncated": false,
            "fixture_case": "ipv4_connect",
            "heartbeat_count": "2",
            "network_action": "tcp_connect",
            "network_family": "ipv4",
            "network_protocol": "tcp",
            "network_socket_state": "syn_sent",
            "network_source": "192.0.2.2",
            "network_source_port": "49152",
            "network_target": "192.0.2.1",
            "network_target_port": "443",
            "package_gid": "65534",
            "package_uid": "65534",
            "reaped_process_count": "1",
            "schema_version": LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "sensor_healthy": true
        })).unwrap()
    }

    #[test]
    fn ipv4_payload_binds_exact_sinkhole_tuple() {
        let evidence = decode_linux_vz_network_evidence_payload_v1(&payload()).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::Ipv4Connect
        );
        assert_eq!(evidence.source_port(), 49152);
        assert_eq!(
            evidence
                .guest_observation_claims_v1()
                .unwrap()
                .evidence_payload_sha256(),
            evidence.payload_sha256()
        );
    }

    #[test]
    fn ipv4_payload_rejects_target_rebinding() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["network_target"] = serde_json::json!("169.254.169.254");
        let forged = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            decode_linux_vz_network_evidence_payload_v1(&forged),
            Err(LinuxVzNetworkEvidencePayloadErrorV1::InvalidSchema)
        );
    }

    #[test]
    fn ipv6_payload_binds_exact_documentation_sinkhole() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("ipv6_connect");
        value["network_family"] = serde_json::json!("ipv6");
        value["network_source"] = serde_json::json!("2001:db8::2");
        value["network_target"] = serde_json::json!("2001:db8::1");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
        );
    }

    #[test]
    fn udp_payload_binds_sendto_and_exact_documentation_sinkhole() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("udp_send");
        value["network_action"] = serde_json::json!("udp_send");
        value["network_protocol"] = serde_json::json!("udp");
        value["network_socket_state"] = serde_json::json!("unconnected_bound");
        value["events"][2]["kind"] = serde_json::json!("sendto");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::UdpSend
        );
    }

    #[test]
    fn loopback_payload_binds_established_guest_sinkhole() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("loopback_connect");
        value["network_socket_state"] = serde_json::json!("established");
        value["network_source"] = serde_json::json!("127.0.0.1");
        value["network_target"] = serde_json::json!("127.0.0.1");
        value["network_target_port"] = serde_json::json!("40552");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::LoopbackConnect
        );
    }
}
