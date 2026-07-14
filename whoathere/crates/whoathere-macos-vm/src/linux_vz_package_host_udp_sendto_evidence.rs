use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_host_udp_sendto_evidence.v1";
pub const MAX_LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_BYTES_V1: usize = 64 * 1024;

const UNOBSERVED_CAPABILITIES_V1: [&str; 4] = [
    "ipv6_host_frames",
    "kernel_socket_buffer_drop_accounting",
    "non_udp_sendto_host_frames",
    "retransmission_and_multi_frame_events",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageHostUdpSendtoEvidenceErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidExpectedBinding,
    BindingMismatch,
    IncompleteCollection,
    InvalidCoverage,
    CorrelationMismatch,
    Serialization,
}

impl LinuxVzPackageHostUdpSendtoEvidenceErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_host_udp_sendto_evidence_empty",
            Self::LimitExceeded => "linux_vz_package_host_udp_sendto_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_package_host_udp_sendto_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_package_host_udp_sendto_evidence_noncanonical",
            Self::InvalidExpectedBinding => {
                "linux_vz_package_host_udp_sendto_expected_binding_invalid"
            }
            Self::BindingMismatch => "linux_vz_package_host_udp_sendto_binding_mismatch",
            Self::IncompleteCollection => "linux_vz_package_host_udp_sendto_collection_incomplete",
            Self::InvalidCoverage => "linux_vz_package_host_udp_sendto_coverage_invalid",
            Self::CorrelationMismatch => "linux_vz_package_host_udp_sendto_correlation_mismatch",
            Self::Serialization => "linux_vz_package_host_udp_sendto_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageHostUdpSendtoEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageHostUdpSendtoEvidenceErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageHostDestinationClassV1 {
    Unspecified,
    Loopback,
    Private,
    LinkLocal,
    Metadata,
    Documentation,
    Multicast,
    Broadcast,
    Public,
}

impl LinuxVzPackageHostDestinationClassV1 {
    const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Unspecified => "unspecified",
            Self::Loopback => "loopback",
            Self::Private => "private",
            Self::LinkLocal => "link_local",
            Self::Metadata => "metadata",
            Self::Documentation => "documentation",
            Self::Multicast => "multicast",
            Self::Broadcast => "broadcast",
            Self::Public => "public",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageExpectedHostUdpSendtoV1 {
    root_network_evidence_sha256: Sha256Digest,
    process_evidence_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
    destination_token_sha256: Sha256Digest,
    destination_class: LinuxVzPackageHostDestinationClassV1,
    destination_port: u16,
    enter_source_sequence: u64,
    syscall_result: u64,
}

impl LinuxVzPackageExpectedHostUdpSendtoV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_v1(
        root_network_evidence_sha256: Sha256Digest,
        process_evidence_sha256: Sha256Digest,
        sensor_session_challenge_sha256: Sha256Digest,
        destination_token_sha256: Sha256Digest,
        destination_class: LinuxVzPackageHostDestinationClassV1,
        destination_port: u16,
        enter_source_sequence: u64,
        syscall_result: u64,
    ) -> Result<Self, LinuxVzPackageHostUdpSendtoEvidenceErrorV1> {
        let expected = Self {
            root_network_evidence_sha256,
            process_evidence_sha256,
            sensor_session_challenge_sha256,
            destination_token_sha256,
            destination_class,
            destination_port,
            enter_source_sequence,
            syscall_result,
        };
        expected.validate_v1()?;
        Ok(expected)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageHostUdpSendtoEvidenceErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let digests = [
            &self.root_network_evidence_sha256,
            &self.process_evidence_sha256,
            &self.sensor_session_challenge_sha256,
            &self.destination_token_sha256,
        ];
        if digests.contains(&&empty)
            || digests.iter().collect::<BTreeSet<_>>().len() != digests.len()
            || self.destination_port == 0
            || self.enter_source_sequence == 0
            || self.syscall_result == 0
            || self.syscall_result > u64::from(u16::MAX)
        {
            return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::InvalidExpectedBinding);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageHostUdpSendtoEvidenceV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    root_network_evidence_sha256: Sha256Digest,
    process_evidence_sha256: Sha256Digest,
    destination_token_sha256: Sha256Digest,
    frame_sha256: Sha256Digest,
    source_port: u16,
    destination_port: u16,
    payload_byte_count: u64,
}

impl LinuxVzPackageHostUdpSendtoEvidenceV1 {
    pub fn canonical_json(&self) -> &[u8] {
        &self.canonical_json
    }
    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }
    pub fn root_network_evidence_sha256(&self) -> &Sha256Digest {
        &self.root_network_evidence_sha256
    }
    pub fn process_evidence_sha256(&self) -> &Sha256Digest {
        &self.process_evidence_sha256
    }
    pub fn destination_token_sha256(&self) -> &Sha256Digest {
        &self.destination_token_sha256
    }
    pub fn frame_sha256(&self) -> &Sha256Digest {
        &self.frame_sha256
    }
    pub const fn source_port(&self) -> u16 {
        self.source_port
    }
    pub const fn destination_port(&self) -> u16 {
        self.destination_port
    }
    pub const fn payload_byte_count(&self) -> u64 {
        self.payload_byte_count
    }
    pub const fn selected_correlation_complete(&self) -> bool {
        true
    }
    pub const fn broad_host_frame_coverage_complete(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostUdpSendtoEvidenceWireV1 {
    binding: HostUdpSendtoBindingWireV1,
    collector: HostUdpSendtoCollectorWireV1,
    coverage: HostUdpSendtoCoverageWireV1,
    event: HostUdpSendtoEventWireV1,
    schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostUdpSendtoBindingWireV1 {
    process_evidence_sha256: Sha256Digest,
    root_network_evidence_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostUdpSendtoCollectorWireV1 {
    dropped_frame_count: String,
    healthy: bool,
    ingress_frame_count: String,
    retained_frame_count: String,
    terminal: String,
    truncated_frame_count: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostUdpSendtoCoverageWireV1 {
    broad_host_frame_coverage_complete: bool,
    correlated_transmitted_event_count: String,
    raw_addresses_serialized: bool,
    raw_frame_bytes_serialized: bool,
    selected_udp_sendto_correlation_complete: bool,
    unobserved_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostUdpSendtoEventWireV1 {
    destination_class: String,
    destination_port: String,
    destination_token_sha256: Sha256Digest,
    enter_source_sequence: String,
    event_kind: String,
    frame_sha256: Sha256Digest,
    source_port: String,
    syscall_result: String,
    transport: String,
    transport_payload_byte_count: String,
}

pub fn decode_linux_vz_package_host_udp_sendto_evidence_v1(
    bytes: &[u8],
    expected: &LinuxVzPackageExpectedHostUdpSendtoV1,
) -> Result<LinuxVzPackageHostUdpSendtoEvidenceV1, LinuxVzPackageHostUdpSendtoEvidenceErrorV1> {
    expected.validate_v1()?;
    if bytes.is_empty() {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_BYTES_V1 {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::LimitExceeded);
    }
    let wire: HostUdpSendtoEvidenceWireV1 = serde_json::from_slice(bytes)
        .map_err(|_| LinuxVzPackageHostUdpSendtoEvidenceErrorV1::InvalidJson)?;
    if canonical_json_v1(&wire)?.as_slice() != bytes {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::NonCanonical);
    }
    if wire.schema_version != LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V1
        || wire.binding
            != (HostUdpSendtoBindingWireV1 {
                process_evidence_sha256: expected.process_evidence_sha256.clone(),
                root_network_evidence_sha256: expected.root_network_evidence_sha256.clone(),
                sensor_session_challenge_sha256: expected.sensor_session_challenge_sha256.clone(),
            })
    {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::BindingMismatch);
    }
    if wire.collector
        != (HostUdpSendtoCollectorWireV1 {
            dropped_frame_count: "0".to_string(),
            healthy: true,
            ingress_frame_count: "1".to_string(),
            retained_frame_count: "1".to_string(),
            terminal: "drained_after_stop".to_string(),
            truncated_frame_count: "0".to_string(),
        })
    {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::IncompleteCollection);
    }
    if wire.coverage
        != (HostUdpSendtoCoverageWireV1 {
            broad_host_frame_coverage_complete: false,
            correlated_transmitted_event_count: "1".to_string(),
            raw_addresses_serialized: false,
            raw_frame_bytes_serialized: false,
            selected_udp_sendto_correlation_complete: true,
            unobserved_capabilities: UNOBSERVED_CAPABILITIES_V1
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        })
    {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::InvalidCoverage);
    }
    let source_port = parse_u16_v1(&wire.event.source_port)?;
    let destination_port = parse_u16_v1(&wire.event.destination_port)?;
    let enter_source_sequence = parse_u64_v1(&wire.event.enter_source_sequence)?;
    let syscall_result = parse_u64_v1(&wire.event.syscall_result)?;
    let payload_byte_count = parse_u64_v1(&wire.event.transport_payload_byte_count)?;
    let binding_digests = [
        &expected.root_network_evidence_sha256,
        &expected.process_evidence_sha256,
        &expected.sensor_session_challenge_sha256,
        &expected.destination_token_sha256,
    ];
    if wire.event.destination_class != expected.destination_class.as_str_v1()
        || destination_port != expected.destination_port
        || wire.event.destination_token_sha256 != expected.destination_token_sha256
        || enter_source_sequence != expected.enter_source_sequence
        || wire.event.event_kind != "sendto"
        || binding_digests.contains(&&wire.event.frame_sha256)
        || syscall_result != expected.syscall_result
        || payload_byte_count != expected.syscall_result
        || wire.event.transport != "udp"
    {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::CorrelationMismatch);
    }
    Ok(LinuxVzPackageHostUdpSendtoEvidenceV1 {
        canonical_json: bytes.to_vec(),
        payload_sha256: Sha256Digest::from_bytes(bytes),
        root_network_evidence_sha256: expected.root_network_evidence_sha256.clone(),
        process_evidence_sha256: expected.process_evidence_sha256.clone(),
        destination_token_sha256: expected.destination_token_sha256.clone(),
        frame_sha256: wire.event.frame_sha256,
        source_port,
        destination_port,
        payload_byte_count,
    })
}

fn parse_u64_v1(value: &str) -> Result<u64, LinuxVzPackageHostUdpSendtoEvidenceErrorV1> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| LinuxVzPackageHostUdpSendtoEvidenceErrorV1::CorrelationMismatch)?;
    if parsed.to_string() != value {
        return Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::CorrelationMismatch);
    }
    Ok(parsed)
}

fn parse_u16_v1(value: &str) -> Result<u16, LinuxVzPackageHostUdpSendtoEvidenceErrorV1> {
    let parsed = parse_u64_v1(value)?;
    u16::try_from(parsed)
        .ok()
        .filter(|value| *value > 0)
        .ok_or(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::CorrelationMismatch)
}

fn canonical_json_v1<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, LinuxVzPackageHostUdpSendtoEvidenceErrorV1> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|_| LinuxVzPackageHostUdpSendtoEvidenceErrorV1::Serialization)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected_v1() -> LinuxVzPackageExpectedHostUdpSendtoV1 {
        LinuxVzPackageExpectedHostUdpSendtoV1::new_v1(
            Sha256Digest::from_bytes(b"network"),
            Sha256Digest::from_bytes(b"process"),
            Sha256Digest::parse(
                "sha256:0a6d2053eb627f5f1ed55c993237d3bd832dc1b72f4084c40c9a224e83d6c965",
            )
            .expect("challenge"),
            Sha256Digest::parse(
                "sha256:3ef258ec5ef33c871db55bb52239931372585c08ad3fbafda224bc498ad0ed7b",
            )
            .expect("token"),
            LinuxVzPackageHostDestinationClassV1::Documentation,
            40_553,
            16,
            16,
        )
        .expect("expected")
    }

    fn exact_wire_v1() -> HostUdpSendtoEvidenceWireV1 {
        let expected = expected_v1();
        HostUdpSendtoEvidenceWireV1 {
            binding: HostUdpSendtoBindingWireV1 {
                process_evidence_sha256: expected.process_evidence_sha256.clone(),
                root_network_evidence_sha256: expected.root_network_evidence_sha256.clone(),
                sensor_session_challenge_sha256: expected.sensor_session_challenge_sha256.clone(),
            },
            collector: HostUdpSendtoCollectorWireV1 {
                dropped_frame_count: "0".to_string(),
                healthy: true,
                ingress_frame_count: "1".to_string(),
                retained_frame_count: "1".to_string(),
                terminal: "drained_after_stop".to_string(),
                truncated_frame_count: "0".to_string(),
            },
            coverage: HostUdpSendtoCoverageWireV1 {
                broad_host_frame_coverage_complete: false,
                correlated_transmitted_event_count: "1".to_string(),
                raw_addresses_serialized: false,
                raw_frame_bytes_serialized: false,
                selected_udp_sendto_correlation_complete: true,
                unobserved_capabilities: UNOBSERVED_CAPABILITIES_V1
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            },
            event: HostUdpSendtoEventWireV1 {
                destination_class: "documentation".to_string(),
                destination_port: "40553".to_string(),
                destination_token_sha256: expected.destination_token_sha256.clone(),
                enter_source_sequence: "16".to_string(),
                event_kind: "sendto".to_string(),
                frame_sha256: Sha256Digest::parse(
                    "sha256:68a91108eb3257418ef82965c5c5ba6d2b5aa8aaded43647c25aad1be43caf1e",
                )
                .expect("frame"),
                source_port: "49152".to_string(),
                syscall_result: "16".to_string(),
                transport: "udp".to_string(),
                transport_payload_byte_count: "16".to_string(),
            },
            schema_version: LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V1.to_string(),
        }
    }

    #[test]
    fn exact_selected_udp_sendto_evidence_decodes_without_broad_overclaim() {
        let expected = expected_v1();
        let canonical = canonical_json_v1(&exact_wire_v1()).expect("canonical");
        let evidence = decode_linux_vz_package_host_udp_sendto_evidence_v1(&canonical, &expected)
            .expect("decode");
        assert_eq!(evidence.canonical_json(), canonical);
        assert_eq!(
            evidence.payload_sha256().as_str(),
            "sha256:9ce0d72ff3ceaf553b65168fe59983dc4093c392fa61ec1db3f916055640b818"
        );
        assert_eq!(evidence.source_port(), 49_152);
        assert_eq!(evidence.destination_port(), 40_553);
        assert_eq!(evidence.payload_byte_count(), 16);
        assert!(evidence.selected_correlation_complete());
        assert!(!evidence.broad_host_frame_coverage_complete());
        let text = String::from_utf8(canonical).expect("utf8");
        assert!(!text.contains("192.0.2.1"));
        assert!(!text.contains("WHOATHERE_RAW_V1"));
    }

    #[test]
    fn selected_udp_sendto_evidence_rejects_rebinding_loss_and_overclaim() {
        let expected = expected_v1();
        let exact = exact_wire_v1();
        let mut rebound = exact.clone();
        rebound.binding.root_network_evidence_sha256 = Sha256Digest::from_bytes(b"rebound");
        assert_eq!(
            decode_linux_vz_package_host_udp_sendto_evidence_v1(
                &canonical_json_v1(&rebound).expect("rebound"),
                &expected,
            ),
            Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::BindingMismatch)
        );
        let mut dropped = exact.clone();
        dropped.collector.dropped_frame_count = "1".to_string();
        assert_eq!(
            decode_linux_vz_package_host_udp_sendto_evidence_v1(
                &canonical_json_v1(&dropped).expect("dropped"),
                &expected,
            ),
            Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::IncompleteCollection)
        );
        let mut overclaimed = exact.clone();
        overclaimed.coverage.broad_host_frame_coverage_complete = true;
        assert_eq!(
            decode_linux_vz_package_host_udp_sendto_evidence_v1(
                &canonical_json_v1(&overclaimed).expect("overclaimed"),
                &expected,
            ),
            Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::InvalidCoverage)
        );
        let mut mismatched = exact;
        mismatched.event.destination_port = "53".to_string();
        assert_eq!(
            decode_linux_vz_package_host_udp_sendto_evidence_v1(
                &canonical_json_v1(&mismatched).expect("mismatched"),
                &expected,
            ),
            Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::CorrelationMismatch)
        );
    }

    #[test]
    fn selected_udp_sendto_evidence_rejects_oversize_noncanonical_and_unknown_wire() {
        let expected = expected_v1();
        assert_eq!(
            decode_linux_vz_package_host_udp_sendto_evidence_v1(
                &vec![b' '; MAX_LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_BYTES_V1 + 1],
                &expected,
            ),
            Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::LimitExceeded)
        );

        let wire = exact_wire_v1();
        let pretty = serde_json::to_vec_pretty(&wire).expect("pretty");
        assert_eq!(
            decode_linux_vz_package_host_udp_sendto_evidence_v1(&pretty, &expected),
            Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::NonCanonical)
        );

        let mut value = serde_json::to_value(wire).expect("value");
        value
            .as_object_mut()
            .expect("object")
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        let unknown = serde_json_canonicalizer::to_vec(&value).expect("unknown");
        assert_eq!(
            decode_linux_vz_package_host_udp_sendto_evidence_v1(&unknown, &expected),
            Err(LinuxVzPackageHostUdpSendtoEvidenceErrorV1::InvalidJson)
        );
    }
}
