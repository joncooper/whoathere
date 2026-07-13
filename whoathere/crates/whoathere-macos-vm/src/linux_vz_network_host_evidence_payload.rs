use crate::{
    LinuxVzTelemetryConformanceCaseV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryHostObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_NETWORK_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_network_host_evidence_payload.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzNetworkHostEvidencePayloadErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzNetworkHostEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "linux_vz_network_host_evidence_empty",
            Self::LimitExceeded => "linux_vz_network_host_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_network_host_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_network_host_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_network_host_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_network_host_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzNetworkHostEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzNetworkHostEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    source_port: u16,
}

impl LinuxVzNetworkHostEvidencePayloadV1 {
    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn source_port(&self) -> u16 {
        self.source_port
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        self.fixture_case
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
struct NetworkHostEvidenceWireV1 {
    bootstrap_frame_count: String,
    clone_destroyed: bool,
    dropped_frame_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<NetworkHostEventWireV1>,
    evidence_truncated: bool,
    external_frames_forwarded: String,
    external_route_configured: bool,
    fixture_case: String,
    frame_kind: String,
    guest_channel_terminated: bool,
    heartbeat_count: String,
    ip_checksum_valid: bool,
    matched_frame_count: String,
    package_execution: bool,
    packet_sensor_healthy: bool,
    packet_sensor_terminal: String,
    raw_frame_count: String,
    root_disk_present: bool,
    schema_version: String,
    source_address: String,
    source_mac: String,
    source_port: String,
    storage_device_count: String,
    sync_back: bool,
    target_address: String,
    target_mac: String,
    target_port: String,
    transport_checksum_valid: bool,
    unexpected_frame_count: String,
    vm_started: bool,
    vm_stopped: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkHostEventWireV1 {
    kind: String,
    sequence: String,
}

pub fn decode_linux_vz_network_host_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzNetworkHostEvidencePayloadV1, LinuxVzNetworkHostEvidencePayloadErrorV1> {
    if payload.is_empty() {
        return Err(LinuxVzNetworkHostEvidencePayloadErrorV1::Empty);
    }
    if payload.len() > crate::MAX_LINUX_VZ_HOST_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzNetworkHostEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = NetworkHostEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzNetworkHostEvidencePayloadErrorV1::NonCanonical);
    }
    let source_port = decimal_u64_v1(&wire.source_port)?;
    let fixture_case = match wire.fixture_case.as_str() {
        "ipv4_connect"
            if wire.frame_kind == "ipv4_tcp_syn"
                && wire.source_address == "192.0.2.2"
                && wire.target_address == "192.0.2.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::Ipv4Connect
        }
        "ipv6_connect"
            if wire.frame_kind == "ipv6_tcp_syn"
                && wire.source_address == "2001:db8::2"
                && wire.target_address == "2001:db8::1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
        }
        "udp_send"
            if wire.frame_kind == "ipv4_udp_datagram"
                && wire.source_address == "192.0.2.2"
                && wire.target_address == "192.0.2.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::UdpSend
        }
        "raw_frame_attachment"
            if wire.frame_kind == "ipv4_udp_raw_frame_attachment"
                && wire.source_address == "192.0.2.2"
                && wire.target_address == "192.0.2.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::RawFrameAttachment
        }
        "private_address_connect"
            if wire.frame_kind == "ipv4_tcp_syn_private"
                && wire.source_address == "10.0.0.2"
                && wire.target_address == "10.0.0.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect
        }
        "link_local_connect"
            if wire.frame_kind == "ipv4_tcp_syn_link_local"
                && wire.source_address == "169.254.100.2"
                && wire.target_address == "169.254.100.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect
        }
        "metadata_address_connect"
            if wire.frame_kind == "ipv4_tcp_syn_metadata"
                && wire.source_address == "169.254.169.253"
                && wire.target_address == "169.254.169.254" =>
        {
            LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect
        }
        "public_address_connect"
            if wire.frame_kind == "ipv4_tcp_syn_public"
                && wire.source_address == "198.51.100.2"
                && wire.target_address == "198.51.100.1" =>
        {
            LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect
        }
        "dns_plaintext"
            if wire.frame_kind == "ipv4_udp_dns_plaintext_query"
                && wire.source_address == "192.0.2.2"
                && wire.target_address == "192.0.2.53" =>
        {
            LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
        }
        "dns_malformed"
            if wire.frame_kind == "ipv4_udp_dns_malformed_truncated_question"
                && wire.source_address == "192.0.2.2"
                && wire.target_address == "192.0.2.53" =>
        {
            LinuxVzTelemetryConformanceCaseV1::DnsMalformed
        }
        "encrypted_dns_connect"
            if wire.frame_kind == "ipv4_tcp_syn_dot_port"
                && wire.source_address == "192.0.2.2"
                && wire.target_address == "192.0.2.53" =>
        {
            LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect
        }
        _ => return Err(LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidSchema),
    };
    if wire.schema_version != LINUX_VZ_NETWORK_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.source_mac != "02:57:48:4f:41:31"
        || wire.target_mac != "02:57:48:4f:41:fe"
        || source_port == 0
        || source_port > u16::MAX as u64
        || decimal_u64_v1(&wire.target_port)?
            != if fixture_case == LinuxVzTelemetryConformanceCaseV1::RawFrameAttachment {
                40_553
            } else if fixture_case == LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect {
                853
            } else if matches!(
                fixture_case,
                LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
                    | LinuxVzTelemetryConformanceCaseV1::DnsMalformed
            ) {
                53
            } else {
                443
            }
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 7
        || decimal_u64_v1(&wire.event_count)? != 7
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || decimal_u64_v1(&wire.bootstrap_frame_count)?
            != if fixture_case == LinuxVzTelemetryConformanceCaseV1::Ipv6Connect {
                1
            } else {
                0
            }
        || decimal_u64_v1(&wire.raw_frame_count)?
            != if fixture_case == LinuxVzTelemetryConformanceCaseV1::Ipv6Connect {
                2
            } else {
                1
            }
        || decimal_u64_v1(&wire.matched_frame_count)? != 1
        || decimal_u64_v1(&wire.unexpected_frame_count)? != 0
        || decimal_u64_v1(&wire.dropped_frame_count)? != 0
        || decimal_u64_v1(&wire.external_frames_forwarded)? != 0
        || decimal_u64_v1(&wire.storage_device_count)? != 0
        || wire.ip_checksum_valid
            != (fixture_case != LinuxVzTelemetryConformanceCaseV1::Ipv6Connect)
        || !wire.transport_checksum_valid
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
        || wire.events.len() != 7
    {
        return Err(LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidSchema);
    }
    let expected = [
        "vm_started",
        "guest_channel_connected",
        "sinkhole_frame_observed",
        "guest_channel_terminated",
        "host_packet_sensor_complete",
        "vm_stopped",
        "ephemeral_clone_destroyed",
    ];
    for (index, event) in wire.events.iter().enumerate() {
        if event.kind != expected[index] || decimal_u64_v1(&event.sequence)? != index as u64 + 1 {
            return Err(LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidEvent);
        }
    }
    Ok(LinuxVzNetworkHostEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        fixture_case,
        source_port: source_port as u16,
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzNetworkHostEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "bootstrap_frame_count": "0",
            "clone_destroyed": true,
            "dropped_frame_count": "0",
            "event_count": "7",
            "event_sequence_end": "7",
            "event_sequence_start": "1",
            "events": [
                {"kind":"vm_started","sequence":"1"},
                {"kind":"guest_channel_connected","sequence":"2"},
                {"kind":"sinkhole_frame_observed","sequence":"3"},
                {"kind":"guest_channel_terminated","sequence":"4"},
                {"kind":"host_packet_sensor_complete","sequence":"5"},
                {"kind":"vm_stopped","sequence":"6"},
                {"kind":"ephemeral_clone_destroyed","sequence":"7"}
            ],
            "evidence_truncated": false,
            "external_frames_forwarded": "0",
            "external_route_configured": false,
            "fixture_case": "ipv4_connect",
            "frame_kind": "ipv4_tcp_syn",
            "guest_channel_terminated": true,
            "heartbeat_count": "2",
            "ip_checksum_valid": true,
            "matched_frame_count": "1",
            "package_execution": false,
            "packet_sensor_healthy": true,
            "packet_sensor_terminal": "drained_would_block",
            "raw_frame_count": "1",
            "root_disk_present": false,
            "schema_version": LINUX_VZ_NETWORK_HOST_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "source_address": "192.0.2.2",
            "source_mac": "02:57:48:4f:41:31",
            "source_port": "49152",
            "storage_device_count": "0",
            "sync_back": false,
            "target_address": "192.0.2.1",
            "target_mac": "02:57:48:4f:41:fe",
            "target_port": "443",
            "transport_checksum_valid": true,
            "unexpected_frame_count": "0",
            "vm_started": true,
            "vm_stopped": true
        }))
        .unwrap()
    }

    #[test]
    fn exact_ipv4_syn_frame_derives_host_claims() {
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&payload()).unwrap();
        assert_eq!(evidence.source_port(), 49152);
        assert_eq!(
            evidence
                .host_observation_claims_v1()
                .unwrap()
                .evidence_payload_sha256(),
            evidence.payload_sha256()
        );
    }

    #[test]
    fn unexpected_frame_fails_closed() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["unexpected_frame_count"] = serde_json::json!("1");
        let forged = serde_json_canonicalizer::to_vec(&value).unwrap();
        assert_eq!(
            decode_linux_vz_network_host_evidence_payload_v1(&forged),
            Err(LinuxVzNetworkHostEvidencePayloadErrorV1::InvalidSchema)
        );
    }

    #[test]
    fn exact_ipv6_syn_frame_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("ipv6_connect");
        value["bootstrap_frame_count"] = serde_json::json!("1");
        value["frame_kind"] = serde_json::json!("ipv6_tcp_syn");
        value["ip_checksum_valid"] = serde_json::json!(false);
        value["source_address"] = serde_json::json!("2001:db8::2");
        value["target_address"] = serde_json::json!("2001:db8::1");
        value["raw_frame_count"] = serde_json::json!("2");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
        );
    }

    #[test]
    fn exact_ipv4_udp_frame_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("udp_send");
        value["frame_kind"] = serde_json::json!("ipv4_udp_datagram");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::UdpSend
        );
    }

    #[test]
    fn exact_raw_frame_attachment_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("raw_frame_attachment");
        value["frame_kind"] = serde_json::json!("ipv4_udp_raw_frame_attachment");
        value["target_port"] = serde_json::json!("40553");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::RawFrameAttachment
        );
    }

    #[test]
    fn exact_private_ipv4_syn_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("private_address_connect");
        value["frame_kind"] = serde_json::json!("ipv4_tcp_syn_private");
        value["source_address"] = serde_json::json!("10.0.0.2");
        value["target_address"] = serde_json::json!("10.0.0.1");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect
        );
    }

    #[test]
    fn exact_link_local_ipv4_syn_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("link_local_connect");
        value["frame_kind"] = serde_json::json!("ipv4_tcp_syn_link_local");
        value["source_address"] = serde_json::json!("169.254.100.2");
        value["target_address"] = serde_json::json!("169.254.100.1");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect
        );
    }

    #[test]
    fn exact_metadata_ipv4_syn_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("metadata_address_connect");
        value["frame_kind"] = serde_json::json!("ipv4_tcp_syn_metadata");
        value["source_address"] = serde_json::json!("169.254.169.253");
        value["target_address"] = serde_json::json!("169.254.169.254");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect
        );
    }

    #[test]
    fn exact_public_ipv4_syn_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("public_address_connect");
        value["frame_kind"] = serde_json::json!("ipv4_tcp_syn_public");
        value["source_address"] = serde_json::json!("198.51.100.2");
        value["target_address"] = serde_json::json!("198.51.100.1");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect
        );
    }

    #[test]
    fn exact_plaintext_dns_query_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("dns_plaintext");
        value["frame_kind"] = serde_json::json!("ipv4_udp_dns_plaintext_query");
        value["target_address"] = serde_json::json!("192.0.2.53");
        value["target_port"] = serde_json::json!("53");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
        );
    }

    #[test]
    fn exact_malformed_dns_query_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("dns_malformed");
        value["frame_kind"] = serde_json::json!("ipv4_udp_dns_malformed_truncated_question");
        value["target_address"] = serde_json::json!("192.0.2.53");
        value["target_port"] = serde_json::json!("53");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::DnsMalformed
        );
    }

    #[test]
    fn exact_encrypted_dns_syn_derives_distinct_case() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).unwrap();
        value["fixture_case"] = serde_json::json!("encrypted_dns_connect");
        value["frame_kind"] = serde_json::json!("ipv4_tcp_syn_dot_port");
        value["target_address"] = serde_json::json!("192.0.2.53");
        value["target_port"] = serde_json::json!("853");
        let encoded = serde_json_canonicalizer::to_vec(&value).unwrap();
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&encoded).unwrap();
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect
        );
    }
}
