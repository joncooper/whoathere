#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::linux_vz_package_sensor_egress_stream::{
    LinuxVzPackageEgressDecisionV1, LinuxVzPackageEgressEventV1,
    LinuxVzPackageEgressNetworkProtocolV1,
};
use crate::linux_vz_package_sensor_event_stream::{
    LinuxVzPackageNetworkAddressFamilyV1, LinuxVzPackageNetworkTargetV1,
    LinuxVzPackageSelectedSyscallV1,
};
use crate::linux_vz_package_sensor_process_collector::LinuxVzPackageRootProcessCollectionV1;
use crate::linux_vz_package_sensor_process_stream::LinuxVzPackageCorrelatedProcessObservationV1;
use crate::{
    LinuxVzPackageProcessCompletionV1, LinuxVzPackageProcessTerminalV1,
    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use whoathere_artifact::Sha256Digest;
use zeroize::Zeroize;

pub const LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_root_network_evidence.v1";
pub const LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_root_network_evidence.v2";

const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;
const MAX_ROOT_NETWORK_EVENTS_V1: usize = 4_096;
const SENDTO_DESTINATION_DETAIL_UNAVAILABLE_V1: &str = "sendto_destination_detail_unavailable";
const UNOBSERVED_CAPABILITIES_V1: [&str; 4] = [
    "dns_intent",
    "guest_intent_syscalls_beyond_connect_sendto",
    "host_frame_correlation",
    "http_observation",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootNetworkEvidenceErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidExpectedBinding,
    BindingMismatch,
    InvalidCoverage,
    InvalidEvent,
    Serialization,
}

impl LinuxVzPackageRootNetworkEvidenceErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_root_network_evidence_empty",
            Self::LimitExceeded => "linux_vz_package_root_network_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_package_root_network_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_package_root_network_evidence_noncanonical",
            Self::InvalidExpectedBinding => {
                "linux_vz_package_root_network_evidence_expected_binding_invalid"
            }
            Self::BindingMismatch => "linux_vz_package_root_network_evidence_binding_mismatch",
            Self::InvalidCoverage => "linux_vz_package_root_network_evidence_coverage_invalid",
            Self::InvalidEvent => "linux_vz_package_root_network_evidence_event_invalid",
            Self::Serialization => "linux_vz_package_root_network_evidence_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootNetworkEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootNetworkEvidenceErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageExpectedRootNetworkEvidenceV1 {
    sensor_session_challenge_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    process_evidence_sha256: Sha256Digest,
    action_index: usize,
    cgroup_name: String,
    cgroup_id: u64,
    root_runner_pid: u32,
    leader_pid: u32,
    completion: LinuxVzPackageProcessCompletionV1,
}

impl LinuxVzPackageExpectedRootNetworkEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_action_v1(
        sensor_session_challenge_sha256: Sha256Digest,
        launch_contract_sha256: Sha256Digest,
        process_plan_sha256: Sha256Digest,
        process_evidence_sha256: Sha256Digest,
        action_index: usize,
        cgroup_name: String,
        cgroup_id: u64,
        root_runner_pid: u32,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<Self, LinuxVzPackageRootNetworkEvidenceErrorV1> {
        let expected = Self {
            sensor_session_challenge_sha256,
            launch_contract_sha256,
            process_plan_sha256,
            process_evidence_sha256,
            action_index,
            cgroup_name,
            cgroup_id,
            root_runner_pid,
            leader_pid,
            completion: *completion,
        };
        expected.validate_v1()?;
        Ok(expected)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageRootNetworkEvidenceErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let digests = [
            &self.sensor_session_challenge_sha256,
            &self.launch_contract_sha256,
            &self.process_plan_sha256,
            &self.process_evidence_sha256,
        ];
        if digests.contains(&&empty)
            || digests
                .iter()
                .enumerate()
                .any(|(index, digest)| digests[..index].contains(digest))
            || self.cgroup_name.is_empty()
            || self.cgroup_name.len() > 128
            || !self
                .cgroup_name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
            || self.cgroup_name != format!("whoathere-package-action-{}", self.action_index)
            || self.cgroup_id == 0
            || self.root_runner_pid <= 1
            || self.leader_pid <= 1
            || self.root_runner_pid == self.leader_pid
            || self.completion.process_started_monotonic_nanoseconds() == 0
            || self.completion.process_ended_monotonic_nanoseconds()
                <= self.completion.process_started_monotonic_nanoseconds()
        {
            return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidExpectedBinding);
        }
        Ok(())
    }

    pub fn sensor_session_challenge_sha256(&self) -> &Sha256Digest {
        &self.sensor_session_challenge_sha256
    }

    pub fn process_evidence_sha256(&self) -> &Sha256Digest {
        &self.process_evidence_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootNetworkEventKindV1 {
    Connect,
    Sendto,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootNetworkTargetStatusV1 {
    Observed,
    Unavailable,
}

impl LinuxVzPackageRootNetworkTargetStatusV1 {
    const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Unavailable => "unavailable",
        }
    }

    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageRootNetworkEvidenceErrorV1> {
        match value {
            "observed" => Ok(Self::Observed),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent),
        }
    }
}

impl LinuxVzPackageRootNetworkEventKindV1 {
    const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Sendto => "sendto",
        }
    }

    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageRootNetworkEvidenceErrorV1> {
        match value {
            "connect" => Ok(Self::Connect),
            "sendto" => Ok(Self::Sendto),
            _ => Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootNetworkAddressFamilyV1 {
    Ipv4,
    Ipv6,
}

impl LinuxVzPackageRootNetworkAddressFamilyV1 {
    const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageRootNetworkEvidenceErrorV1> {
        match value {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootNetworkDestinationClassV1 {
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

impl LinuxVzPackageRootNetworkDestinationClassV1 {
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

    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageRootNetworkEvidenceErrorV1> {
        match value {
            "unspecified" => Ok(Self::Unspecified),
            "loopback" => Ok(Self::Loopback),
            "private" => Ok(Self::Private),
            "link_local" => Ok(Self::LinkLocal),
            "metadata" => Ok(Self::Metadata),
            "documentation" => Ok(Self::Documentation),
            "multicast" => Ok(Self::Multicast),
            "broadcast" => Ok(Self::Broadcast),
            "public" => Ok(Self::Public),
            _ => Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootNetworkEventV1 {
    kind: LinuxVzPackageRootNetworkEventKindV1,
    target_status: LinuxVzPackageRootNetworkTargetStatusV1,
    address_family: Option<LinuxVzPackageRootNetworkAddressFamilyV1>,
    destination_class: Option<LinuxVzPackageRootNetworkDestinationClassV1>,
    destination_port: Option<u16>,
    destination_token_sha256: Option<Sha256Digest>,
    target_unavailable_reason: Option<String>,
    enter_source_sequence: u64,
    exit_source_sequence: u64,
    enter_timestamp_monotonic_nanoseconds: u64,
    exit_timestamp_monotonic_nanoseconds: u64,
    cgroup_id: u64,
    pid: u32,
    tgid: u32,
    syscall_result: i64,
    enter_cpu: u32,
    exit_cpu: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootNetworkEgressDecisionV1 {
    Allow,
    Block,
}

impl LinuxVzPackageRootNetworkEgressDecisionV1 {
    const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Block => "block",
        }
    }

    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageRootNetworkEvidenceErrorV1> {
        match value {
            "allow" => Ok(Self::Allow),
            "block" => Ok(Self::Block),
            _ => Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootNetworkEgressProtocolV1 {
    Ipv4,
    Ipv6,
    Unsupported,
}

impl LinuxVzPackageRootNetworkEgressProtocolV1 {
    const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Unsupported => "unsupported",
        }
    }

    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageRootNetworkEvidenceErrorV1> {
        match value {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            "unsupported" => Ok(Self::Unsupported),
            _ => Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootNetworkEgressObservationV1 {
    decision: LinuxVzPackageRootNetworkEgressDecisionV1,
    protocol: LinuxVzPackageRootNetworkEgressProtocolV1,
    cgroup_id: u64,
    timestamp_monotonic_nanoseconds: u64,
    packet_length: u32,
    wire_length: u32,
    raw_skb_protocol: u32,
    ingress_interface_index: u32,
    egress_interface_index: u32,
    gso_segment_count: u32,
    gso_segment_size: u32,
    packet_prefix_byte_length: usize,
    packet_prefix_sha256: Sha256Digest,
    packet_correlation_sha256: Option<Sha256Digest>,
    prefix_truncated: bool,
    wire_gso_metadata_available: bool,
    source_sequence: u64,
    cpu: u32,
}

impl LinuxVzPackageRootNetworkEgressObservationV1 {
    pub const fn decision(&self) -> LinuxVzPackageRootNetworkEgressDecisionV1 {
        self.decision
    }

    pub const fn protocol(&self) -> LinuxVzPackageRootNetworkEgressProtocolV1 {
        self.protocol
    }

    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    pub const fn timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.timestamp_monotonic_nanoseconds
    }

    pub const fn packet_length(&self) -> u32 {
        self.packet_length
    }

    pub const fn wire_length(&self) -> u32 {
        self.wire_length
    }

    pub const fn raw_skb_protocol(&self) -> u32 {
        self.raw_skb_protocol
    }

    pub const fn ingress_interface_index(&self) -> u32 {
        self.ingress_interface_index
    }

    pub const fn egress_interface_index(&self) -> u32 {
        self.egress_interface_index
    }

    pub const fn gso_segment_count(&self) -> u32 {
        self.gso_segment_count
    }

    pub const fn gso_segment_size(&self) -> u32 {
        self.gso_segment_size
    }

    pub const fn packet_prefix_byte_length(&self) -> usize {
        self.packet_prefix_byte_length
    }

    pub fn packet_prefix_sha256(&self) -> &Sha256Digest {
        &self.packet_prefix_sha256
    }

    pub fn packet_correlation_sha256(&self) -> Option<&Sha256Digest> {
        self.packet_correlation_sha256.as_ref()
    }

    pub const fn prefix_truncated(&self) -> bool {
        self.prefix_truncated
    }

    pub const fn wire_gso_metadata_available(&self) -> bool {
        self.wire_gso_metadata_available
    }

    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    pub const fn cpu(&self) -> u32 {
        self.cpu
    }
}

impl LinuxVzPackageRootNetworkEventV1 {
    pub const fn kind(&self) -> LinuxVzPackageRootNetworkEventKindV1 {
        self.kind
    }

    pub const fn target_status(&self) -> LinuxVzPackageRootNetworkTargetStatusV1 {
        self.target_status
    }

    pub const fn address_family(&self) -> Option<LinuxVzPackageRootNetworkAddressFamilyV1> {
        self.address_family
    }

    pub const fn destination_class(&self) -> Option<LinuxVzPackageRootNetworkDestinationClassV1> {
        self.destination_class
    }

    pub const fn destination_port(&self) -> Option<u16> {
        self.destination_port
    }

    pub fn destination_token_sha256(&self) -> Option<&Sha256Digest> {
        self.destination_token_sha256.as_ref()
    }

    pub fn target_unavailable_reason(&self) -> Option<&str> {
        self.target_unavailable_reason.as_deref()
    }

    pub const fn enter_source_sequence(&self) -> u64 {
        self.enter_source_sequence
    }

    pub const fn exit_source_sequence(&self) -> u64 {
        self.exit_source_sequence
    }

    pub const fn syscall_result(&self) -> i64 {
        self.syscall_result
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootNetworkEvidenceV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    process_evidence_sha256: Sha256Digest,
    process_source_event_count: u64,
    process_observation_count: usize,
    connect_sendto_intent_coverage_complete: bool,
    egress_packet_coverage_complete: bool,
    egress_dropped_event_count: u64,
    egress_discarded_record_count: u64,
    guest_intent_coverage_complete: bool,
    host_frame_correlation_complete: bool,
    dns_intent_coverage_complete: bool,
    http_observation_complete: bool,
    composite_network_coverage_complete: bool,
    raw_addresses_serialized: bool,
    target_detail_complete: bool,
    events: Vec<LinuxVzPackageRootNetworkEventV1>,
    egress_observations: Vec<LinuxVzPackageRootNetworkEgressObservationV1>,
    unobserved_capabilities: Vec<String>,
}

impl fmt::Debug for LinuxVzPackageRootNetworkEvidenceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootNetworkEvidenceV1")
            .field("payload_sha256", &self.payload_sha256)
            .field("process_evidence_sha256", &self.process_evidence_sha256)
            .field(
                "process_source_event_count",
                &self.process_source_event_count,
            )
            .field("process_observation_count", &self.process_observation_count)
            .field("event_count", &self.events.len())
            .field("egress_event_count", &self.egress_observations.len())
            .field(
                "connect_sendto_intent_coverage_complete",
                &self.connect_sendto_intent_coverage_complete,
            )
            .field(
                "guest_intent_coverage_complete",
                &self.guest_intent_coverage_complete,
            )
            .field(
                "composite_network_coverage_complete",
                &self.composite_network_coverage_complete,
            )
            .field("raw_addresses_serialized", &self.raw_addresses_serialized)
            .field("target_detail_complete", &self.target_detail_complete)
            .finish()
    }
}

impl LinuxVzPackageRootNetworkEvidenceV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn process_evidence_sha256(&self) -> &Sha256Digest {
        &self.process_evidence_sha256
    }

    pub const fn process_source_event_count(&self) -> u64 {
        self.process_source_event_count
    }

    pub const fn process_observation_count(&self) -> usize {
        self.process_observation_count
    }

    pub const fn connect_sendto_intent_coverage_complete(&self) -> bool {
        self.connect_sendto_intent_coverage_complete
    }

    pub const fn egress_packet_coverage_complete(&self) -> bool {
        self.egress_packet_coverage_complete
    }

    pub const fn egress_dropped_event_count(&self) -> u64 {
        self.egress_dropped_event_count
    }

    pub const fn egress_discarded_record_count(&self) -> u64 {
        self.egress_discarded_record_count
    }

    pub const fn guest_intent_coverage_complete(&self) -> bool {
        self.guest_intent_coverage_complete
    }

    pub const fn host_frame_correlation_complete(&self) -> bool {
        self.host_frame_correlation_complete
    }

    pub const fn dns_intent_coverage_complete(&self) -> bool {
        self.dns_intent_coverage_complete
    }

    pub const fn http_observation_complete(&self) -> bool {
        self.http_observation_complete
    }

    pub const fn composite_network_coverage_complete(&self) -> bool {
        self.composite_network_coverage_complete
    }

    pub const fn raw_addresses_serialized(&self) -> bool {
        self.raw_addresses_serialized
    }

    pub const fn target_detail_complete(&self) -> bool {
        self.target_detail_complete
    }

    pub fn events(&self) -> &[LinuxVzPackageRootNetworkEventV1] {
        &self.events
    }

    pub fn egress_observations(&self) -> &[LinuxVzPackageRootNetworkEgressObservationV1] {
        &self.egress_observations
    }

    pub fn unobserved_capabilities(&self) -> &[String] {
        &self.unobserved_capabilities
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootNetworkEvidenceWireV1 {
    binding: RootNetworkBindingWireV1,
    coverage: RootNetworkCoverageWireV1,
    egress_observations: Vec<RootNetworkEgressObservationWireV1>,
    events: Vec<RootNetworkEventWireV1>,
    process_observation_count: String,
    process_source_event_count: String,
    schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootNetworkBindingWireV1 {
    action_index: String,
    cgroup_id: String,
    cgroup_name: String,
    exit_status: Option<String>,
    launch_contract_sha256: Sha256Digest,
    leader_pid: String,
    package_gid: String,
    package_uid: String,
    process_ended_monotonic_nanoseconds: String,
    process_evidence_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    process_started_monotonic_nanoseconds: String,
    process_terminal: String,
    root_runner_pid: String,
    sensor_session_challenge_sha256: Sha256Digest,
    supervisor_wait_status: String,
    termination_signal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootNetworkCoverageWireV1 {
    composite_network_coverage_complete: bool,
    connect_sendto_intent_coverage_complete: bool,
    discarded_record_count: String,
    dns_intent_coverage_complete: bool,
    dropped_event_count: String,
    egress_discarded_record_count: String,
    egress_dropped_event_count: String,
    egress_event_count: String,
    egress_packet_coverage_complete: bool,
    evidence_truncated: bool,
    guest_intent_coverage_complete: bool,
    host_frame_correlation_complete: bool,
    http_observation_complete: bool,
    network_event_count: String,
    process_sensor_healthy: bool,
    raw_addresses_serialized: bool,
    target_detail_complete: bool,
    unobserved_capabilities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootNetworkEgressObservationWireV1 {
    cgroup_id: String,
    cpu: String,
    decision: String,
    egress_interface_index: String,
    gso_segment_count: String,
    gso_segment_size: String,
    ingress_interface_index: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    packet_correlation_sha256: Option<Sha256Digest>,
    packet_length: String,
    packet_prefix_byte_length: String,
    packet_prefix_sha256: Sha256Digest,
    prefix_truncated: bool,
    protocol: String,
    raw_skb_protocol: String,
    source_sequence: String,
    timestamp_monotonic_nanoseconds: String,
    wire_gso_metadata_available: bool,
    wire_length: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootNetworkEventWireV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address_family: Option<String>,
    cgroup_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination_class: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination_port: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    destination_token_sha256: Option<Sha256Digest>,
    enter_cpu: String,
    enter_source_sequence: String,
    enter_timestamp_monotonic_nanoseconds: String,
    event_kind: String,
    exit_cpu: String,
    exit_source_sequence: String,
    exit_timestamp_monotonic_nanoseconds: String,
    pid: String,
    syscall_result: String,
    target_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_unavailable_reason: Option<String>,
    tgid: String,
}

pub(crate) fn encode_linux_vz_package_root_network_evidence_v1(
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
    collection: &LinuxVzPackageRootProcessCollectionV1,
) -> Result<LinuxVzPackageRootNetworkEvidenceV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    expected.validate_v1()?;
    let stream = collection.stream_v1();
    let leader_exit_monotonic_nanoseconds = collection.leader_exit_monotonic_nanoseconds_v1();
    if collection.leader_pid_v1() != expected.leader_pid
        || collection.leader_supervisor_wait_status_v1()
            != expected.completion.supervisor_wait_status()
        || leader_exit_monotonic_nanoseconds
            <= expected.completion.process_started_monotonic_nanoseconds()
        || leader_exit_monotonic_nanoseconds
            > expected.completion.process_ended_monotonic_nanoseconds()
        || stream.expected_cgroup_id_v1() != expected.cgroup_id
        || !collection.coverage_complete_v1()
        || !collection.egress_coverage_complete_v1()
        || !stream.coverage_complete_v1()
        || collection.dropped_event_count_v1() != 0
        || collection.discarded_record_count_v1() != 0
        || collection.egress_dropped_event_count_v1() != 0
        || collection.egress_discarded_record_count_v1() != 0
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::BindingMismatch);
    }

    let events = stream
        .observations_v1()
        .iter()
        .filter_map(|observation| {
            let LinuxVzPackageCorrelatedProcessObservationV1::Syscall(event) = observation else {
                return None;
            };
            let kind = match event.syscall_v1() {
                LinuxVzPackageSelectedSyscallV1::Connect => {
                    LinuxVzPackageRootNetworkEventKindV1::Connect
                }
                LinuxVzPackageSelectedSyscallV1::Sendto => {
                    LinuxVzPackageRootNetworkEventKindV1::Sendto
                }
                _ => {
                    return if event.network_target_v1().is_some() {
                        Some(Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent))
                    } else {
                        None
                    };
                }
            };
            Some(network_event_wire_v1(expected, event, kind))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if events.len() > MAX_ROOT_NETWORK_EVENTS_V1 {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::LimitExceeded);
    }
    let target_detail_complete = events.iter().all(|event| {
        event.target_status == LinuxVzPackageRootNetworkTargetStatusV1::Observed.as_str_v1()
    });
    let egress_observations = collection
        .egress_events_v1()
        .iter()
        .map(|event| egress_observation_wire_v1(expected, event))
        .collect::<Result<Vec<_>, _>>()?;
    if egress_observations.len() > MAX_ROOT_NETWORK_EVENTS_V1
        || events.len().saturating_add(egress_observations.len()) > MAX_ROOT_NETWORK_EVENTS_V1
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::LimitExceeded);
    }

    let wire = RootNetworkEvidenceWireV1 {
        binding: binding_wire_v1(expected),
        coverage: RootNetworkCoverageWireV1 {
            composite_network_coverage_complete: false,
            connect_sendto_intent_coverage_complete: true,
            discarded_record_count: collection.discarded_record_count_v1().to_string(),
            dns_intent_coverage_complete: false,
            dropped_event_count: collection.dropped_event_count_v1().to_string(),
            egress_discarded_record_count: collection
                .egress_discarded_record_count_v1()
                .to_string(),
            egress_dropped_event_count: collection.egress_dropped_event_count_v1().to_string(),
            egress_event_count: egress_observations.len().to_string(),
            egress_packet_coverage_complete: true,
            evidence_truncated: false,
            guest_intent_coverage_complete: false,
            host_frame_correlation_complete: false,
            http_observation_complete: false,
            network_event_count: events.len().to_string(),
            process_sensor_healthy: true,
            raw_addresses_serialized: false,
            target_detail_complete,
            unobserved_capabilities: unobserved_capabilities_v1(target_detail_complete),
        },
        egress_observations,
        events,
        process_observation_count: stream.observations_v1().len().to_string(),
        process_source_event_count: stream.source_event_count_v1().to_string(),
        schema_version: LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V2.to_string(),
    };
    let canonical_json = canonical_json_v1(&wire)?;
    decode_linux_vz_package_root_network_evidence_v1(&canonical_json, expected)
}

pub fn decode_linux_vz_package_root_network_evidence_v1(
    bytes: &[u8],
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
) -> Result<LinuxVzPackageRootNetworkEvidenceV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    expected.validate_v1()?;
    if bytes.is_empty() {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::LimitExceeded);
    }
    let wire: RootNetworkEvidenceWireV1 = serde_json::from_slice(bytes)
        .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidJson)?;
    if canonical_json_v1(&wire)?.as_slice() != bytes {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::NonCanonical);
    }
    if wire.schema_version != LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V2
        || wire.binding != binding_wire_v1(expected)
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::BindingMismatch);
    }
    let process_source_event_count = parse_u64_v1(&wire.process_source_event_count)?;
    let process_observation_count = parse_usize_v1(&wire.process_observation_count)?;
    let process_source_event_count_usize = usize::try_from(process_source_event_count)
        .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage)?;
    let target_detail_complete = wire.events.iter().all(|event| {
        event.target_status == LinuxVzPackageRootNetworkTargetStatusV1::Observed.as_str_v1()
    });
    if process_source_event_count == 0
        || process_observation_count == 0
        || process_observation_count > process_source_event_count_usize
        || wire.events.len() > process_observation_count
        || wire.events.len() > MAX_ROOT_NETWORK_EVENTS_V1
        || wire.egress_observations.len() > MAX_ROOT_NETWORK_EVENTS_V1
        || wire
            .events
            .len()
            .saturating_add(wire.egress_observations.len())
            > MAX_ROOT_NETWORK_EVENTS_V1
        || wire.coverage
            != (RootNetworkCoverageWireV1 {
                composite_network_coverage_complete: false,
                connect_sendto_intent_coverage_complete: true,
                discarded_record_count: "0".to_string(),
                dns_intent_coverage_complete: false,
                dropped_event_count: "0".to_string(),
                egress_discarded_record_count: "0".to_string(),
                egress_dropped_event_count: "0".to_string(),
                egress_event_count: wire.egress_observations.len().to_string(),
                egress_packet_coverage_complete: true,
                evidence_truncated: false,
                guest_intent_coverage_complete: false,
                host_frame_correlation_complete: false,
                http_observation_complete: false,
                network_event_count: wire.events.len().to_string(),
                process_sensor_healthy: true,
                raw_addresses_serialized: false,
                target_detail_complete,
                unobserved_capabilities: unobserved_capabilities_v1(target_detail_complete),
            })
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage);
    }

    let mut prior_exit_sequence = 0_u64;
    let mut prior_exit_timestamp = 0_u64;
    let mut tokens = BTreeSet::new();
    let events = wire
        .events
        .iter()
        .map(|event| {
            let decoded = decode_event_wire_v1(event, expected, process_source_event_count)?;
            if decoded.enter_source_sequence <= prior_exit_sequence
                || decoded.enter_timestamp_monotonic_nanoseconds <= prior_exit_timestamp
                || decoded
                    .destination_token_sha256
                    .as_ref()
                    .is_some_and(|token| !tokens.insert(token.clone()))
            {
                return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
            }
            prior_exit_sequence = decoded.exit_source_sequence;
            prior_exit_timestamp = decoded.exit_timestamp_monotonic_nanoseconds;
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut prior_egress_sequence = 0_u64;
    let mut prior_egress_timestamp = 0_u64;
    let mut correlation_digests = BTreeSet::new();
    let egress_observations = wire
        .egress_observations
        .iter()
        .map(|observation| {
            let decoded = decode_egress_observation_wire_v1(observation, expected)?;
            if decoded.source_sequence != prior_egress_sequence + 1
                || decoded.timestamp_monotonic_nanoseconds <= prior_egress_timestamp
                || decoded
                    .packet_correlation_sha256
                    .as_ref()
                    .is_some_and(|digest| !correlation_digests.insert(digest.clone()))
            {
                return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
            }
            prior_egress_sequence = decoded.source_sequence;
            prior_egress_timestamp = decoded.timestamp_monotonic_nanoseconds;
            Ok(decoded)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(LinuxVzPackageRootNetworkEvidenceV1 {
        canonical_json: bytes.to_vec(),
        payload_sha256: Sha256Digest::from_bytes(bytes),
        process_evidence_sha256: expected.process_evidence_sha256.clone(),
        process_source_event_count,
        process_observation_count,
        connect_sendto_intent_coverage_complete: true,
        egress_packet_coverage_complete: true,
        egress_dropped_event_count: 0,
        egress_discarded_record_count: 0,
        guest_intent_coverage_complete: false,
        host_frame_correlation_complete: false,
        dns_intent_coverage_complete: false,
        http_observation_complete: false,
        composite_network_coverage_complete: false,
        raw_addresses_serialized: false,
        target_detail_complete,
        events,
        egress_observations,
        unobserved_capabilities: unobserved_capabilities_v1(target_detail_complete),
    })
}

fn egress_observation_wire_v1(
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
    event: &LinuxVzPackageEgressEventV1,
) -> Result<RootNetworkEgressObservationWireV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    if event.cgroup_id_v1() != expected.cgroup_id
        || event.timestamp_nanoseconds_v1()
            < expected.completion.process_started_monotonic_nanoseconds()
        || event.timestamp_nanoseconds_v1()
            > expected.completion.process_ended_monotonic_nanoseconds()
        || event.source_sequence_v1() == 0
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
    }
    let decision = match event.decision_v1() {
        LinuxVzPackageEgressDecisionV1::Allow => LinuxVzPackageRootNetworkEgressDecisionV1::Allow,
        LinuxVzPackageEgressDecisionV1::Block => LinuxVzPackageRootNetworkEgressDecisionV1::Block,
    };
    let protocol = match event.protocol_v1() {
        LinuxVzPackageEgressNetworkProtocolV1::Ipv4 => {
            LinuxVzPackageRootNetworkEgressProtocolV1::Ipv4
        }
        LinuxVzPackageEgressNetworkProtocolV1::Ipv6 => {
            LinuxVzPackageRootNetworkEgressProtocolV1::Ipv6
        }
        LinuxVzPackageEgressNetworkProtocolV1::Unsupported => {
            LinuxVzPackageRootNetworkEgressProtocolV1::Unsupported
        }
    };
    let packet_correlation_sha256 = if decision == LinuxVzPackageRootNetworkEgressDecisionV1::Allow
        && !event.prefix_truncated_v1()
    {
        Some(
            event
                .packet_correlation_sha256_v1()
                .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?,
        )
    } else {
        None
    };
    Ok(RootNetworkEgressObservationWireV1 {
        cgroup_id: event.cgroup_id_v1().to_string(),
        cpu: event.cpu_v1().to_string(),
        decision: decision.as_str_v1().to_string(),
        egress_interface_index: event.egress_interface_index_v1().to_string(),
        gso_segment_count: event.gso_segment_count_v1().to_string(),
        gso_segment_size: event.gso_segment_size_v1().to_string(),
        ingress_interface_index: event.ingress_interface_index_v1().to_string(),
        packet_correlation_sha256,
        packet_length: event.packet_length_v1().to_string(),
        packet_prefix_byte_length: event.packet_prefix_v1().len().to_string(),
        packet_prefix_sha256: event.packet_prefix_sha256_v1(),
        prefix_truncated: event.prefix_truncated_v1(),
        protocol: protocol.as_str_v1().to_string(),
        raw_skb_protocol: event.raw_skb_protocol_v1().to_string(),
        source_sequence: event.source_sequence_v1().to_string(),
        timestamp_monotonic_nanoseconds: event.timestamp_nanoseconds_v1().to_string(),
        wire_gso_metadata_available: event.wire_gso_metadata_available_v1(),
        wire_length: event.wire_length_v1().to_string(),
    })
}

fn decode_egress_observation_wire_v1(
    wire: &RootNetworkEgressObservationWireV1,
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
) -> Result<LinuxVzPackageRootNetworkEgressObservationV1, LinuxVzPackageRootNetworkEvidenceErrorV1>
{
    let decision = LinuxVzPackageRootNetworkEgressDecisionV1::parse_v1(&wire.decision)?;
    let protocol = LinuxVzPackageRootNetworkEgressProtocolV1::parse_v1(&wire.protocol)?;
    let cgroup_id = parse_u64_v1(&wire.cgroup_id)?;
    let timestamp_monotonic_nanoseconds = parse_u64_v1(&wire.timestamp_monotonic_nanoseconds)?;
    let packet_length = parse_u32_v1(&wire.packet_length)?;
    let wire_length = parse_u32_v1(&wire.wire_length)?;
    let raw_skb_protocol = parse_u32_v1(&wire.raw_skb_protocol)?;
    let ingress_interface_index = parse_u32_v1(&wire.ingress_interface_index)?;
    let egress_interface_index = parse_u32_v1(&wire.egress_interface_index)?;
    let gso_segment_count = parse_u32_v1(&wire.gso_segment_count)?;
    let gso_segment_size = parse_u32_v1(&wire.gso_segment_size)?;
    let packet_prefix_byte_length = parse_usize_v1(&wire.packet_prefix_byte_length)?;
    let source_sequence = parse_u64_v1(&wire.source_sequence)?;
    let cpu = parse_u32_v1(&wire.cpu)?;
    let packet_length_usize = usize::try_from(packet_length)
        .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?;
    let expected_prefix_length = packet_length_usize.min(160);
    let protocol_matches_raw = match protocol {
        LinuxVzPackageRootNetworkEgressProtocolV1::Ipv4 => raw_skb_protocol == 8,
        LinuxVzPackageRootNetworkEgressProtocolV1::Ipv6 => raw_skb_protocol == 56_710,
        LinuxVzPackageRootNetworkEgressProtocolV1::Unsupported => {
            !matches!(raw_skb_protocol, 8 | 56_710)
        }
    };
    let digest_is_bound = |digest: &Sha256Digest| {
        digest == expected.sensor_session_challenge_sha256()
            || digest == &expected.launch_contract_sha256
            || digest == &expected.process_plan_sha256
            || digest == expected.process_evidence_sha256()
            || digest == &Sha256Digest::from_bytes(&[])
    };
    if cgroup_id != expected.cgroup_id
        || timestamp_monotonic_nanoseconds
            < expected.completion.process_started_monotonic_nanoseconds()
        || timestamp_monotonic_nanoseconds
            > expected.completion.process_ended_monotonic_nanoseconds()
        || packet_length == 0
        || packet_prefix_byte_length != expected_prefix_length
        || wire.prefix_truncated != (packet_prefix_byte_length < packet_length_usize)
        || !protocol_matches_raw
        || wire.wire_gso_metadata_available
        || wire_length != 0
        || gso_segment_count != 0
        || gso_segment_size != 0
        || source_sequence == 0
        || digest_is_bound(&wire.packet_prefix_sha256)
        || match decision {
            LinuxVzPackageRootNetworkEgressDecisionV1::Allow => {
                protocol == LinuxVzPackageRootNetworkEgressProtocolV1::Unsupported
                    || wire.prefix_truncated
                    || match wire.packet_correlation_sha256.as_ref() {
                        Some(digest) => {
                            digest_is_bound(digest) || digest == &wire.packet_prefix_sha256
                        }
                        None => true,
                    }
            }
            LinuxVzPackageRootNetworkEgressDecisionV1::Block => {
                protocol != LinuxVzPackageRootNetworkEgressProtocolV1::Unsupported
                    || wire.packet_correlation_sha256.is_some()
            }
        }
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
    }
    Ok(LinuxVzPackageRootNetworkEgressObservationV1 {
        decision,
        protocol,
        cgroup_id,
        timestamp_monotonic_nanoseconds,
        packet_length,
        wire_length,
        raw_skb_protocol,
        ingress_interface_index,
        egress_interface_index,
        gso_segment_count,
        gso_segment_size,
        packet_prefix_byte_length,
        packet_prefix_sha256: wire.packet_prefix_sha256.clone(),
        packet_correlation_sha256: wire.packet_correlation_sha256.clone(),
        prefix_truncated: wire.prefix_truncated,
        wire_gso_metadata_available: false,
        source_sequence,
        cpu,
    })
}

fn network_event_wire_v1(
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
    event: &crate::linux_vz_package_sensor_process_stream::LinuxVzPackageCorrelatedSyscallV1,
    kind: LinuxVzPackageRootNetworkEventKindV1,
) -> Result<RootNetworkEventWireV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    if event.cgroup_id_v1() != expected.cgroup_id
        || event.pid_v1() <= 1
        || event.tgid_v1() <= 1
        || event.enter_source_sequence_v1() == 0
        || event.exit_source_sequence_v1() != event.enter_source_sequence_v1() + 1
        || event.enter_timestamp_nanoseconds_v1()
            < expected.completion.process_started_monotonic_nanoseconds()
        || event.exit_timestamp_nanoseconds_v1() <= event.enter_timestamp_nanoseconds_v1()
        || event.exit_timestamp_nanoseconds_v1()
            > expected.completion.process_ended_monotonic_nanoseconds()
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
    }
    let (
        target_status,
        address_family,
        destination_class,
        destination_port,
        destination_token_sha256,
        target_unavailable_reason,
    ) = match event.network_target_v1() {
        Some(target) => {
            let (family, destination_class) = classify_network_target_v1(target)?;
            let destination_token_sha256 = network_target_token_v1(
                &expected.sensor_session_challenge_sha256,
                kind,
                family,
                target.port_v1(),
                event.enter_source_sequence_v1(),
                target.address_v1(),
            )?;
            (
                LinuxVzPackageRootNetworkTargetStatusV1::Observed,
                Some(family.as_str_v1().to_string()),
                Some(destination_class.as_str_v1().to_string()),
                Some(target.port_v1().to_string()),
                Some(destination_token_sha256),
                None,
            )
        }
        None if kind == LinuxVzPackageRootNetworkEventKindV1::Sendto
            && event.arguments_v1()[5] == 0 =>
        {
            (
                LinuxVzPackageRootNetworkTargetStatusV1::Unavailable,
                None,
                None,
                None,
                None,
                Some(SENDTO_DESTINATION_DETAIL_UNAVAILABLE_V1.to_string()),
            )
        }
        None => return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent),
    };
    Ok(RootNetworkEventWireV1 {
        address_family,
        cgroup_id: event.cgroup_id_v1().to_string(),
        destination_class,
        destination_port,
        destination_token_sha256,
        enter_cpu: event.enter_cpu_v1().to_string(),
        enter_source_sequence: event.enter_source_sequence_v1().to_string(),
        enter_timestamp_monotonic_nanoseconds: event.enter_timestamp_nanoseconds_v1().to_string(),
        event_kind: kind.as_str_v1().to_string(),
        exit_cpu: event.exit_cpu_v1().to_string(),
        exit_source_sequence: event.exit_source_sequence_v1().to_string(),
        exit_timestamp_monotonic_nanoseconds: event.exit_timestamp_nanoseconds_v1().to_string(),
        pid: event.pid_v1().to_string(),
        syscall_result: event.result_v1().to_string(),
        target_status: target_status.as_str_v1().to_string(),
        target_unavailable_reason,
        tgid: event.tgid_v1().to_string(),
    })
}

fn decode_event_wire_v1(
    wire: &RootNetworkEventWireV1,
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
    process_source_event_count: u64,
) -> Result<LinuxVzPackageRootNetworkEventV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    let kind = LinuxVzPackageRootNetworkEventKindV1::parse_v1(&wire.event_kind)?;
    let target_status = LinuxVzPackageRootNetworkTargetStatusV1::parse_v1(&wire.target_status)?;
    let enter_source_sequence = parse_u64_v1(&wire.enter_source_sequence)?;
    let exit_source_sequence = parse_u64_v1(&wire.exit_source_sequence)?;
    let enter_timestamp_monotonic_nanoseconds =
        parse_u64_v1(&wire.enter_timestamp_monotonic_nanoseconds)?;
    let exit_timestamp_monotonic_nanoseconds =
        parse_u64_v1(&wire.exit_timestamp_monotonic_nanoseconds)?;
    let cgroup_id = parse_u64_v1(&wire.cgroup_id)?;
    let pid = parse_u32_v1(&wire.pid)?;
    let tgid = parse_u32_v1(&wire.tgid)?;
    let syscall_result = parse_i64_v1(&wire.syscall_result)?;
    let enter_cpu = parse_u32_v1(&wire.enter_cpu)?;
    let exit_cpu = parse_u32_v1(&wire.exit_cpu)?;
    if enter_source_sequence == 0
        || exit_source_sequence != enter_source_sequence + 1
        || exit_source_sequence > process_source_event_count
        || enter_timestamp_monotonic_nanoseconds
            < expected.completion.process_started_monotonic_nanoseconds()
        || exit_timestamp_monotonic_nanoseconds <= enter_timestamp_monotonic_nanoseconds
        || exit_timestamp_monotonic_nanoseconds
            > expected.completion.process_ended_monotonic_nanoseconds()
        || cgroup_id != expected.cgroup_id
        || pid <= 1
        || tgid <= 1
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
    }
    let (address_family, destination_class, destination_port, destination_token_sha256) =
        match target_status {
            LinuxVzPackageRootNetworkTargetStatusV1::Observed => {
                if wire.target_unavailable_reason.is_some() {
                    return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
                }
                let address_family = LinuxVzPackageRootNetworkAddressFamilyV1::parse_v1(
                    wire.address_family
                        .as_deref()
                        .ok_or(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?,
                )?;
                let destination_class = LinuxVzPackageRootNetworkDestinationClassV1::parse_v1(
                    wire.destination_class
                        .as_deref()
                        .ok_or(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?,
                )?;
                let destination_port = parse_u16_v1(
                    wire.destination_port
                        .as_deref()
                        .ok_or(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?,
                )?;
                let destination_token_sha256 = wire
                    .destination_token_sha256
                    .as_ref()
                    .ok_or(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?;
                if destination_port == 0
                    || (address_family == LinuxVzPackageRootNetworkAddressFamilyV1::Ipv6
                        && destination_class
                            == LinuxVzPackageRootNetworkDestinationClassV1::Broadcast)
                    || destination_token_sha256 == &Sha256Digest::from_bytes(&[])
                    || destination_token_sha256 == expected.sensor_session_challenge_sha256()
                    || destination_token_sha256 == &expected.launch_contract_sha256
                    || destination_token_sha256 == &expected.process_plan_sha256
                    || destination_token_sha256 == expected.process_evidence_sha256()
                {
                    return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
                }
                (
                    Some(address_family),
                    Some(destination_class),
                    Some(destination_port),
                    Some(destination_token_sha256.clone()),
                )
            }
            LinuxVzPackageRootNetworkTargetStatusV1::Unavailable => {
                if kind != LinuxVzPackageRootNetworkEventKindV1::Sendto
                    || wire.address_family.is_some()
                    || wire.destination_class.is_some()
                    || wire.destination_port.is_some()
                    || wire.destination_token_sha256.is_some()
                    || wire.target_unavailable_reason.as_deref()
                        != Some(SENDTO_DESTINATION_DETAIL_UNAVAILABLE_V1)
                {
                    return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
                }
                (None, None, None, None)
            }
        };
    Ok(LinuxVzPackageRootNetworkEventV1 {
        kind,
        target_status,
        address_family,
        destination_class,
        destination_port,
        destination_token_sha256,
        target_unavailable_reason: wire.target_unavailable_reason.clone(),
        enter_source_sequence,
        exit_source_sequence,
        enter_timestamp_monotonic_nanoseconds,
        exit_timestamp_monotonic_nanoseconds,
        cgroup_id,
        pid,
        tgid,
        syscall_result,
        enter_cpu,
        exit_cpu,
    })
}

fn binding_wire_v1(
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
) -> RootNetworkBindingWireV1 {
    RootNetworkBindingWireV1 {
        action_index: expected.action_index.to_string(),
        cgroup_id: expected.cgroup_id.to_string(),
        cgroup_name: expected.cgroup_name.clone(),
        exit_status: expected
            .completion
            .exit_status()
            .map(|value| value.to_string()),
        launch_contract_sha256: expected.launch_contract_sha256.clone(),
        leader_pid: expected.leader_pid.to_string(),
        package_gid: PACKAGE_GID_V1.to_string(),
        package_uid: PACKAGE_UID_V1.to_string(),
        process_ended_monotonic_nanoseconds: expected
            .completion
            .process_ended_monotonic_nanoseconds()
            .to_string(),
        process_evidence_sha256: expected.process_evidence_sha256.clone(),
        process_plan_sha256: expected.process_plan_sha256.clone(),
        process_started_monotonic_nanoseconds: expected
            .completion
            .process_started_monotonic_nanoseconds()
            .to_string(),
        process_terminal: match expected.completion.terminal() {
            LinuxVzPackageProcessTerminalV1::Exited => "exited",
            LinuxVzPackageProcessTerminalV1::Signaled => "signaled",
        }
        .to_string(),
        root_runner_pid: expected.root_runner_pid.to_string(),
        sensor_session_challenge_sha256: expected.sensor_session_challenge_sha256.clone(),
        supervisor_wait_status: expected.completion.supervisor_wait_status().to_string(),
        termination_signal: expected
            .completion
            .termination_signal()
            .map(|value| value.to_string()),
    }
}

fn classify_network_target_v1(
    target: &LinuxVzPackageNetworkTargetV1,
) -> Result<
    (
        LinuxVzPackageRootNetworkAddressFamilyV1,
        LinuxVzPackageRootNetworkDestinationClassV1,
    ),
    LinuxVzPackageRootNetworkEvidenceErrorV1,
> {
    let family = match target.family_v1() {
        LinuxVzPackageNetworkAddressFamilyV1::Ipv4 => {
            LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4
        }
        LinuxVzPackageNetworkAddressFamilyV1::Ipv6 => {
            LinuxVzPackageRootNetworkAddressFamilyV1::Ipv6
        }
    };
    let class = classify_network_address_v1(family, target.address_v1())?;
    Ok((family, class))
}

fn classify_network_address_v1(
    family: LinuxVzPackageRootNetworkAddressFamilyV1,
    raw_address: &[u8],
) -> Result<LinuxVzPackageRootNetworkDestinationClassV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    match family {
        LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4 => {
            let octets: [u8; 4] = raw_address
                .try_into()
                .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?;
            let address = Ipv4Addr::from(octets);
            Ok(if address.is_unspecified() {
                LinuxVzPackageRootNetworkDestinationClassV1::Unspecified
            } else if address.is_loopback() {
                LinuxVzPackageRootNetworkDestinationClassV1::Loopback
            } else if octets == [169, 254, 169, 254] {
                LinuxVzPackageRootNetworkDestinationClassV1::Metadata
            } else if address.is_private() {
                LinuxVzPackageRootNetworkDestinationClassV1::Private
            } else if address.is_link_local() {
                LinuxVzPackageRootNetworkDestinationClassV1::LinkLocal
            } else if matches!(
                octets,
                [192, 0, 2, _] | [198, 51, 100, _] | [203, 0, 113, _]
            ) {
                LinuxVzPackageRootNetworkDestinationClassV1::Documentation
            } else if address.is_multicast() {
                LinuxVzPackageRootNetworkDestinationClassV1::Multicast
            } else if address.is_broadcast() {
                LinuxVzPackageRootNetworkDestinationClassV1::Broadcast
            } else {
                LinuxVzPackageRootNetworkDestinationClassV1::Public
            })
        }
        LinuxVzPackageRootNetworkAddressFamilyV1::Ipv6 => {
            let octets: [u8; 16] = raw_address
                .try_into()
                .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?;
            let address = Ipv6Addr::from(octets);
            Ok(if address.is_unspecified() {
                LinuxVzPackageRootNetworkDestinationClassV1::Unspecified
            } else if address.is_loopback() {
                LinuxVzPackageRootNetworkDestinationClassV1::Loopback
            } else if address.is_unique_local() {
                LinuxVzPackageRootNetworkDestinationClassV1::Private
            } else if address.is_unicast_link_local() {
                LinuxVzPackageRootNetworkDestinationClassV1::LinkLocal
            } else if octets[..4] == [0x20, 0x01, 0x0d, 0xb8] {
                LinuxVzPackageRootNetworkDestinationClassV1::Documentation
            } else if address.is_multicast() {
                LinuxVzPackageRootNetworkDestinationClassV1::Multicast
            } else {
                LinuxVzPackageRootNetworkDestinationClassV1::Public
            })
        }
    }
}

fn network_target_token_v1(
    challenge: &Sha256Digest,
    kind: LinuxVzPackageRootNetworkEventKindV1,
    family: LinuxVzPackageRootNetworkAddressFamilyV1,
    port: u16,
    enter_source_sequence: u64,
    address: &[u8],
) -> Result<Sha256Digest, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    if port == 0
        || enter_source_sequence == 0
        || !matches!(address.len(), 4 | 16)
        || (family == LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4 && address.len() != 4)
        || (family == LinuxVzPackageRootNetworkAddressFamilyV1::Ipv6 && address.len() != 16)
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
    }
    let mut input = Vec::with_capacity(challenge.as_str().len() + address.len() + 96);
    input.extend_from_slice(b"whoathere.linux_vz_package_root_network_target_token.v1\0");
    input.extend_from_slice(challenge.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(kind.as_str_v1().as_bytes());
    input.push(0);
    input.extend_from_slice(family.as_str_v1().as_bytes());
    input.push(0);
    input.extend_from_slice(&port.to_be_bytes());
    input.extend_from_slice(&enter_source_sequence.to_be_bytes());
    input.extend_from_slice(address);
    let digest = Sha256Digest::from_bytes(&input);
    input.zeroize();
    Ok(digest)
}

fn unobserved_capabilities_v1(target_detail_complete: bool) -> Vec<String> {
    let mut capabilities = UNOBSERVED_CAPABILITIES_V1
        .iter()
        .map(|value| (*value).to_string())
        .collect::<Vec<_>>();
    if !target_detail_complete {
        capabilities.push(SENDTO_DESTINATION_DETAIL_UNAVAILABLE_V1.to_string());
    }
    capabilities.sort_unstable();
    capabilities
}

fn canonical_json_v1<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::Serialization)
}

fn parse_u64_v1(value: &str) -> Result<u64, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    value
        .parse::<u64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
}

fn parse_usize_v1(value: &str) -> Result<usize, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    let parsed = parse_u64_v1(value)?;
    usize::try_from(parsed).map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
}

fn parse_u32_v1(value: &str) -> Result<u32, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    let parsed = parse_u64_v1(value)?;
    u32::try_from(parsed).map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
}

fn parse_u16_v1(value: &str) -> Result<u16, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    let parsed = parse_u64_v1(value)?;
    u16::try_from(parsed).map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
}

fn parse_i64_v1(value: &str) -> Result<i64, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    value
        .parse::<i64>()
        .ok()
        .filter(|parsed| parsed.to_string() == value)
        .ok_or(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_vz_package_sensor_event_stream::{
        decode_linux_vz_package_kernel_event_v1, LinuxVzPackageKernelEventKindV1,
        LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1,
    };
    use crate::linux_vz_package_sensor_process_stream::LinuxVzPackageProcessEventCorrelatorV1;

    const TEST_CGROUP_ID_V1: u64 = 77;
    const TEST_ROOT_RUNNER_PID_V1: u32 = 50;
    const TEST_LEADER_PID_V1: u32 = 51;

    fn kernel_event_v1(
        kind: LinuxVzPackageKernelEventKindV1,
        sequence: u64,
        timestamp: u64,
        syscall: Option<LinuxVzPackageSelectedSyscallV1>,
        arguments: [u64; 6],
        result: Option<i64>,
        network_detail: Option<&[u8]>,
    ) -> crate::linux_vz_package_sensor_event_stream::LinuxVzPackageKernelEventV1 {
        let mut bytes = [0_u8; LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1];
        bytes[0..4].copy_from_slice(b"WTKE");
        bytes[4..6].copy_from_slice(&2_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&(kind as u16).to_le_bytes());
        if result.is_some() {
            bytes[8..12].copy_from_slice(&(1_u32 << 1).to_le_bytes());
        }
        bytes[12..16].copy_from_slice(
            &u32::try_from(LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1)
                .expect("event bytes")
                .to_le_bytes(),
        );
        bytes[16..24].copy_from_slice(&TEST_CGROUP_ID_V1.to_le_bytes());
        bytes[24..32].copy_from_slice(&timestamp.to_le_bytes());
        bytes[32..36].copy_from_slice(&TEST_LEADER_PID_V1.to_le_bytes());
        bytes[36..40].copy_from_slice(&TEST_LEADER_PID_V1.to_le_bytes());
        bytes[44..48].copy_from_slice(&TEST_LEADER_PID_V1.to_le_bytes());
        bytes[48..52].copy_from_slice(&(syscall.map_or(0, |value| value as u32)).to_le_bytes());
        bytes[56..64].copy_from_slice(&result.unwrap_or_default().to_le_bytes());
        for (index, argument) in arguments.iter().enumerate() {
            bytes[64 + index * 8..72 + index * 8].copy_from_slice(&argument.to_le_bytes());
        }
        if let Some(detail) = network_detail {
            bytes[52..54].copy_from_slice(&2_u16.to_le_bytes());
            bytes[54..56].copy_from_slice(
                &u16::try_from(detail.len())
                    .expect("network detail length")
                    .to_le_bytes(),
            );
            bytes[112..112 + detail.len()].copy_from_slice(detail);
        }
        bytes[184..188].copy_from_slice(&1_u32.to_le_bytes());
        decode_linux_vz_package_kernel_event_v1(&bytes, TEST_CGROUP_ID_V1, sequence)
            .expect("kernel event")
    }

    fn completion_v1() -> LinuxVzPackageProcessCompletionV1 {
        LinuxVzPackageProcessCompletionV1::from_parts_v1(
            100,
            1_000,
            0,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("completion")
    }

    fn expected_v1() -> LinuxVzPackageExpectedRootNetworkEvidenceV1 {
        LinuxVzPackageExpectedRootNetworkEvidenceV1::from_action_v1(
            Sha256Digest::from_bytes(b"network-challenge"),
            Sha256Digest::from_bytes(b"launch"),
            Sha256Digest::from_bytes(b"plan"),
            Sha256Digest::from_bytes(b"process-evidence"),
            2,
            "whoathere-package-action-2".to_string(),
            TEST_CGROUP_ID_V1,
            TEST_ROOT_RUNNER_PID_V1,
            TEST_LEADER_PID_V1,
            &completion_v1(),
        )
        .expect("expected")
    }

    fn collection_v1() -> LinuxVzPackageRootProcessCollectionV1 {
        let completion = completion_v1();
        let mut correlator = LinuxVzPackageProcessEventCorrelatorV1::new_v1(TEST_CGROUP_ID_V1, 8)
            .expect("correlator");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                1,
                200,
                None,
                [0; 6],
                None,
                None,
            ))
            .expect("exec");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                2,
                300,
                Some(LinuxVzPackageSelectedSyscallV1::Connect),
                [7, 0, 16, 0, 0, 0],
                None,
                Some(&[2, 0, 1, 187, 192, 0, 2, 9, 0, 0, 0, 0, 0, 0, 0, 0]),
            ))
            .expect("connect enter");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::SyscallExit,
                3,
                400,
                Some(LinuxVzPackageSelectedSyscallV1::Connect),
                [0; 6],
                Some(-101),
                None,
            ))
            .expect("connect exit");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                4,
                900,
                None,
                [0; 6],
                Some(0),
                None,
            ))
            .expect("exit");
        let stream = correlator.finish_v1(0, 0, 4).expect("stream");
        LinuxVzPackageRootProcessCollectionV1::from_test_stream_v1(
            stream,
            TEST_LEADER_PID_V1,
            &completion,
        )
        .expect("collection")
    }

    fn targetless_sendto_collection_v1(
        destination_length: u64,
    ) -> LinuxVzPackageRootProcessCollectionV1 {
        let completion = completion_v1();
        let mut correlator = LinuxVzPackageProcessEventCorrelatorV1::new_v1(TEST_CGROUP_ID_V1, 8)
            .expect("correlator");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                1,
                200,
                None,
                [0; 6],
                None,
                None,
            ))
            .expect("exec");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                2,
                300,
                Some(LinuxVzPackageSelectedSyscallV1::Sendto),
                [7, 0, 16, 0, 0, destination_length],
                None,
                None,
            ))
            .expect("sendto enter");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::SyscallExit,
                3,
                400,
                Some(LinuxVzPackageSelectedSyscallV1::Sendto),
                [0; 6],
                Some(16),
                None,
            ))
            .expect("sendto exit");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                4,
                900,
                None,
                [0; 6],
                Some(0),
                None,
            ))
            .expect("exit");
        let stream = correlator.finish_v1(0, 0, 4).expect("stream");
        LinuxVzPackageRootProcessCollectionV1::from_test_stream_v1(
            stream,
            TEST_LEADER_PID_V1,
            &completion,
        )
        .expect("collection")
    }

    fn exact_wire_v1() -> RootNetworkEvidenceWireV1 {
        let expected = expected_v1();
        let family = LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4;
        let token = network_target_token_v1(
            expected.sensor_session_challenge_sha256(),
            LinuxVzPackageRootNetworkEventKindV1::Connect,
            family,
            443,
            14,
            &[192, 0, 2, 9],
        )
        .expect("token");
        RootNetworkEvidenceWireV1 {
            binding: binding_wire_v1(&expected),
            coverage: RootNetworkCoverageWireV1 {
                composite_network_coverage_complete: false,
                connect_sendto_intent_coverage_complete: true,
                discarded_record_count: "0".to_string(),
                dns_intent_coverage_complete: false,
                dropped_event_count: "0".to_string(),
                egress_discarded_record_count: "0".to_string(),
                egress_dropped_event_count: "0".to_string(),
                egress_event_count: "1".to_string(),
                egress_packet_coverage_complete: true,
                evidence_truncated: false,
                guest_intent_coverage_complete: false,
                host_frame_correlation_complete: false,
                http_observation_complete: false,
                network_event_count: "1".to_string(),
                process_sensor_healthy: true,
                raw_addresses_serialized: false,
                target_detail_complete: true,
                unobserved_capabilities: unobserved_capabilities_v1(true),
            },
            egress_observations: vec![RootNetworkEgressObservationWireV1 {
                cgroup_id: TEST_CGROUP_ID_V1.to_string(),
                cpu: "1".to_string(),
                decision: "allow".to_string(),
                egress_interface_index: "2".to_string(),
                gso_segment_count: "0".to_string(),
                gso_segment_size: "0".to_string(),
                ingress_interface_index: "0".to_string(),
                packet_correlation_sha256: Some(Sha256Digest::from_bytes(
                    b"normalized egress packet",
                )),
                packet_length: "44".to_string(),
                packet_prefix_byte_length: "44".to_string(),
                packet_prefix_sha256: Sha256Digest::from_bytes(b"raw egress packet prefix"),
                prefix_truncated: false,
                protocol: "ipv4".to_string(),
                raw_skb_protocol: "8".to_string(),
                source_sequence: "1".to_string(),
                timestamp_monotonic_nanoseconds: "700".to_string(),
                wire_gso_metadata_available: false,
                wire_length: "0".to_string(),
            }],
            events: vec![RootNetworkEventWireV1 {
                address_family: Some("ipv4".to_string()),
                cgroup_id: "77".to_string(),
                destination_class: Some("documentation".to_string()),
                destination_port: Some("443".to_string()),
                destination_token_sha256: Some(token),
                enter_cpu: "1".to_string(),
                enter_source_sequence: "14".to_string(),
                enter_timestamp_monotonic_nanoseconds: "500".to_string(),
                event_kind: "connect".to_string(),
                exit_cpu: "1".to_string(),
                exit_source_sequence: "15".to_string(),
                exit_timestamp_monotonic_nanoseconds: "600".to_string(),
                pid: "51".to_string(),
                syscall_result: "-101".to_string(),
                target_status: "observed".to_string(),
                target_unavailable_reason: None,
                tgid: "51".to_string(),
            }],
            process_observation_count: "10".to_string(),
            process_source_event_count: "18".to_string(),
            schema_version: LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V2.to_string(),
        }
    }

    #[test]
    fn canonical_network_payload_is_strict_redacted_and_gap_explicit() {
        let expected = expected_v1();
        let bytes = canonical_json_v1(&exact_wire_v1()).expect("canonical");
        let evidence =
            decode_linux_vz_package_root_network_evidence_v1(&bytes, &expected).expect("decode");
        assert_eq!(evidence.events().len(), 1);
        assert!(evidence.connect_sendto_intent_coverage_complete());
        assert!(evidence.egress_packet_coverage_complete());
        assert_eq!(evidence.egress_dropped_event_count(), 0);
        assert_eq!(evidence.egress_discarded_record_count(), 0);
        assert_eq!(evidence.egress_observations().len(), 1);
        assert_eq!(
            evidence.egress_observations()[0].decision(),
            LinuxVzPackageRootNetworkEgressDecisionV1::Allow
        );
        assert_eq!(
            evidence.egress_observations()[0].protocol(),
            LinuxVzPackageRootNetworkEgressProtocolV1::Ipv4
        );
        assert!(!evidence.egress_observations()[0].wire_gso_metadata_available());
        assert!(!evidence.guest_intent_coverage_complete());
        assert!(!evidence.host_frame_correlation_complete());
        assert!(!evidence.composite_network_coverage_complete());
        assert!(!evidence.raw_addresses_serialized());
        assert!(evidence.target_detail_complete());
        assert_eq!(
            evidence.events()[0].destination_class(),
            Some(LinuxVzPackageRootNetworkDestinationClassV1::Documentation)
        );
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(!text.contains("192.0.2.9"));
        assert!(!text.contains("2001:db8"));
    }

    #[test]
    fn encoder_preserves_targetless_sendto_and_marks_target_detail_incomplete() {
        let expected = expected_v1();
        let evidence = encode_linux_vz_package_root_network_evidence_v1(
            &expected,
            &targetless_sendto_collection_v1(0),
        )
        .expect("encode targetless sendto");

        assert!(evidence.connect_sendto_intent_coverage_complete());
        assert!(!evidence.target_detail_complete());
        assert_eq!(evidence.events().len(), 1);
        let event = &evidence.events()[0];
        assert_eq!(event.kind(), LinuxVzPackageRootNetworkEventKindV1::Sendto);
        assert_eq!(
            event.target_status(),
            LinuxVzPackageRootNetworkTargetStatusV1::Unavailable
        );
        assert_eq!(event.address_family(), None);
        assert_eq!(event.destination_class(), None);
        assert_eq!(event.destination_port(), None);
        assert_eq!(event.destination_token_sha256(), None);
        assert_eq!(
            event.target_unavailable_reason(),
            Some(SENDTO_DESTINATION_DETAIL_UNAVAILABLE_V1)
        );
        assert_eq!(event.syscall_result(), 16);
        assert!(evidence
            .unobserved_capabilities()
            .windows(2)
            .all(|pair| pair[0] < pair[1]));
        assert!(evidence
            .unobserved_capabilities()
            .iter()
            .any(|capability| capability == SENDTO_DESTINATION_DETAIL_UNAVAILABLE_V1));

        let wire: RootNetworkEvidenceWireV1 =
            serde_json::from_slice(evidence.canonical_json_v1()).expect("canonical wire");
        let event = &wire.events[0];
        assert_eq!(event.target_status, "unavailable");
        assert_eq!(
            event.target_unavailable_reason.as_deref(),
            Some(SENDTO_DESTINATION_DETAIL_UNAVAILABLE_V1)
        );
        assert!(event.address_family.is_none());
        assert!(event.destination_class.is_none());
        assert!(event.destination_port.is_none());
        assert!(event.destination_token_sha256.is_none());
    }

    #[test]
    fn targetless_sendto_requires_zero_destination_length() {
        assert_eq!(
            encode_linux_vz_package_root_network_evidence_v1(
                &expected_v1(),
                &targetless_sendto_collection_v1(16),
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );
    }

    #[test]
    fn unavailable_target_union_and_coverage_are_strict() {
        let expected = expected_v1();
        let evidence = encode_linux_vz_package_root_network_evidence_v1(
            &expected,
            &targetless_sendto_collection_v1(0),
        )
        .expect("encode targetless sendto");
        let wire: RootNetworkEvidenceWireV1 =
            serde_json::from_slice(evidence.canonical_json_v1()).expect("canonical wire");

        let mut with_observed_field = wire.events[0].clone();
        with_observed_field.address_family = Some("ipv4".to_string());
        assert_eq!(
            decode_event_wire_v1(&with_observed_field, &expected, 4),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );

        let mut unavailable_connect = wire.events[0].clone();
        unavailable_connect.event_kind = "connect".to_string();
        assert_eq!(
            decode_event_wire_v1(&unavailable_connect, &expected, 4),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );

        let mut observed_without_fields = wire.events[0].clone();
        observed_without_fields.target_status = "observed".to_string();
        observed_without_fields.target_unavailable_reason = None;
        assert_eq!(
            decode_event_wire_v1(&observed_without_fields, &expected, 4),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );

        let mut upgraded_coverage = wire;
        upgraded_coverage.coverage.target_detail_complete = true;
        upgraded_coverage.coverage.unobserved_capabilities = unobserved_capabilities_v1(true);
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&upgraded_coverage).expect("upgraded coverage"),
                &expected,
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage)
        );
    }

    #[test]
    fn encoder_accepts_kernel_exit_before_supervisor_completion_but_not_after_it() {
        let expected = expected_v1();
        let collection = collection_v1();
        let evidence = encode_linux_vz_package_root_network_evidence_v1(&expected, &collection)
            .expect("encode physical completion shape");
        assert_eq!(evidence.events().len(), 1);
        assert_eq!(evidence.events()[0].enter_source_sequence(), 2);
        assert_eq!(evidence.events()[0].exit_source_sequence(), 3);

        let ended_before_kernel_exit = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            100,
            800,
            0,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("mismatched completion");
        let mismatched = LinuxVzPackageExpectedRootNetworkEvidenceV1::from_action_v1(
            Sha256Digest::from_bytes(b"network-challenge"),
            Sha256Digest::from_bytes(b"launch"),
            Sha256Digest::from_bytes(b"plan"),
            Sha256Digest::from_bytes(b"process-evidence"),
            2,
            "whoathere-package-action-2".to_string(),
            TEST_CGROUP_ID_V1,
            TEST_ROOT_RUNNER_PID_V1,
            TEST_LEADER_PID_V1,
            &ended_before_kernel_exit,
        )
        .expect("expected mismatch");
        assert_eq!(
            encode_linux_vz_package_root_network_evidence_v1(&mismatched, &collection),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::BindingMismatch)
        );
    }

    #[test]
    fn network_payload_rejects_unknown_noncanonical_binding_and_coverage_upgrades() {
        let expected = expected_v1();
        let exact = exact_wire_v1();
        let mut value = serde_json::to_value(&exact).expect("value");
        value
            .as_object_mut()
            .expect("object")
            .insert("unknown".to_string(), serde_json::Value::Bool(true));
        let unknown = canonical_json_v1(&value).expect("unknown");
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(&unknown, &expected),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidJson)
        );

        let canonical = canonical_json_v1(&exact).expect("canonical");
        let pretty = serde_json::to_vec_pretty(&exact).expect("pretty");
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(&pretty, &expected),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::NonCanonical)
        );

        let mut rebound = exact.clone();
        rebound.binding.cgroup_id = "78".to_string();
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&rebound).expect("rebound"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::BindingMismatch)
        );

        let mut overclaimed = exact.clone();
        overclaimed.coverage.guest_intent_coverage_complete = true;
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&overclaimed).expect("overclaimed"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage)
        );

        let mut downgraded = exact.clone();
        downgraded.coverage.connect_sendto_intent_coverage_complete = false;
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&downgraded).expect("downgraded"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage)
        );

        let mut upgraded = exact;
        upgraded.coverage.host_frame_correlation_complete = true;
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&upgraded).expect("upgraded"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage)
        );

        let mut missing_egress_coverage = exact_wire_v1();
        missing_egress_coverage
            .coverage
            .egress_packet_coverage_complete = false;
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&missing_egress_coverage).expect("missing egress coverage"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage)
        );

        let mut forged_wire_metadata = exact_wire_v1();
        forged_wire_metadata.egress_observations[0].wire_gso_metadata_available = true;
        forged_wire_metadata.egress_observations[0].wire_length = "44".to_string();
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&forged_wire_metadata).expect("forged wire metadata"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );

        let mut rebound_egress = exact_wire_v1();
        rebound_egress.egress_observations[0].cgroup_id = "78".to_string();
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&rebound_egress).expect("rebound egress"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );

        let mut mislabeled_protocol = exact_wire_v1();
        mislabeled_protocol.egress_observations[0].protocol = "unsupported".to_string();
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&mislabeled_protocol).expect("mislabeled protocol"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );

        let mut duplicate_packet_digest = exact_wire_v1();
        duplicate_packet_digest.egress_observations[0].packet_correlation_sha256 = Some(
            duplicate_packet_digest.egress_observations[0]
                .packet_prefix_sha256
                .clone(),
        );
        assert_eq!(
            decode_linux_vz_package_root_network_evidence_v1(
                &canonical_json_v1(&duplicate_packet_digest).expect("duplicate packet digest"),
                &expected
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );
        assert!(!canonical.is_empty());
    }

    #[test]
    fn destination_tokens_are_challenge_family_port_sequence_and_address_bound() {
        let challenge = Sha256Digest::from_bytes(b"challenge");
        let exact = network_target_token_v1(
            &challenge,
            LinuxVzPackageRootNetworkEventKindV1::Connect,
            LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4,
            443,
            14,
            &[192, 0, 2, 9],
        )
        .expect("exact");
        let variants = [
            network_target_token_v1(
                &Sha256Digest::from_bytes(b"other"),
                LinuxVzPackageRootNetworkEventKindV1::Connect,
                LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4,
                443,
                14,
                &[192, 0, 2, 9],
            )
            .expect("challenge"),
            network_target_token_v1(
                &challenge,
                LinuxVzPackageRootNetworkEventKindV1::Sendto,
                LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4,
                443,
                14,
                &[192, 0, 2, 9],
            )
            .expect("kind"),
            network_target_token_v1(
                &challenge,
                LinuxVzPackageRootNetworkEventKindV1::Connect,
                LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4,
                53,
                14,
                &[192, 0, 2, 9],
            )
            .expect("port"),
            network_target_token_v1(
                &challenge,
                LinuxVzPackageRootNetworkEventKindV1::Connect,
                LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4,
                443,
                16,
                &[192, 0, 2, 9],
            )
            .expect("sequence"),
            network_target_token_v1(
                &challenge,
                LinuxVzPackageRootNetworkEventKindV1::Connect,
                LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4,
                443,
                14,
                &[192, 0, 2, 10],
            )
            .expect("address"),
        ];
        assert!(variants.iter().all(|value| value != &exact));
        assert_eq!(
            variants.iter().collect::<BTreeSet<_>>().len(),
            variants.len()
        );
    }

    #[test]
    fn host_ipv4_frame_parser_token_golden_matches_swift() {
        let challenge = Sha256Digest::parse(
            "sha256:0a6d2053eb627f5f1ed55c993237d3bd832dc1b72f4084c40c9a224e83d6c965",
        )
        .expect("challenge");
        let token = network_target_token_v1(
            &challenge,
            LinuxVzPackageRootNetworkEventKindV1::Sendto,
            LinuxVzPackageRootNetworkAddressFamilyV1::Ipv4,
            40_553,
            16,
            &[192, 0, 2, 1],
        )
        .expect("token");
        assert_eq!(
            token.as_str(),
            "sha256:3ef258ec5ef33c871db55bb52239931372585c08ad3fbafda224bc498ad0ed7b"
        );
    }

    #[test]
    fn destination_classification_covers_every_serialized_class() {
        use LinuxVzPackageRootNetworkAddressFamilyV1::{Ipv4, Ipv6};
        use LinuxVzPackageRootNetworkDestinationClassV1::{
            Broadcast, Documentation, LinkLocal, Loopback, Metadata, Multicast, Private, Public,
            Unspecified,
        };

        let ipv4_cases: [([u8; 4], LinuxVzPackageRootNetworkDestinationClassV1); 9] = [
            ([0, 0, 0, 0], Unspecified),
            ([127, 0, 0, 1], Loopback),
            ([169, 254, 169, 254], Metadata),
            ([10, 0, 0, 1], Private),
            ([169, 254, 1, 1], LinkLocal),
            ([192, 0, 2, 9], Documentation),
            ([224, 0, 0, 1], Multicast),
            ([255, 255, 255, 255], Broadcast),
            ([8, 8, 8, 8], Public),
        ];
        for (address, expected) in ipv4_cases {
            assert_eq!(
                classify_network_address_v1(Ipv4, &address).expect("classify IPv4"),
                expected
            );
        }

        let ipv6_cases: [([u8; 16], LinuxVzPackageRootNetworkDestinationClassV1); 7] = [
            ([0; 16], Unspecified),
            ([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], Loopback),
            ([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], Private),
            (
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                LinkLocal,
            ),
            (
                [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9],
                Documentation,
            ),
            (
                [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                Multicast,
            ),
            (
                [
                    0x26, 0x06, 0x47, 0, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11, 0x11,
                ],
                Public,
            ),
        ];
        for (address, expected) in ipv6_cases {
            assert_eq!(
                classify_network_address_v1(Ipv6, &address).expect("classify IPv6"),
                expected
            );
        }

        assert_eq!(
            classify_network_address_v1(Ipv4, &[127, 0, 0]),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );
        assert_eq!(
            classify_network_address_v1(Ipv6, &[0; 15]),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)
        );
    }

    #[test]
    fn reason_codes_and_expected_binding_are_stable() {
        assert_eq!(
            LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage.reason_code(),
            "linux_vz_package_root_network_evidence_coverage_invalid"
        );
        let completion = completion_v1();
        assert_eq!(
            LinuxVzPackageExpectedRootNetworkEvidenceV1::from_action_v1(
                Sha256Digest::from_bytes(b"same"),
                Sha256Digest::from_bytes(b"same"),
                Sha256Digest::from_bytes(b"plan"),
                Sha256Digest::from_bytes(b"process"),
                0,
                "whoathere-package-action-0".to_string(),
                1,
                50,
                51,
                &completion,
            ),
            Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidExpectedBinding)
        );
    }
}
