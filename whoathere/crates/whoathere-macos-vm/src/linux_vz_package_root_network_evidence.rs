#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

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

const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;
const MAX_ROOT_NETWORK_EVENTS_V1: usize = 4_096;
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
    address_family: LinuxVzPackageRootNetworkAddressFamilyV1,
    destination_class: LinuxVzPackageRootNetworkDestinationClassV1,
    destination_port: u16,
    destination_token_sha256: Sha256Digest,
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

impl LinuxVzPackageRootNetworkEventV1 {
    pub const fn kind(&self) -> LinuxVzPackageRootNetworkEventKindV1 {
        self.kind
    }

    pub const fn address_family(&self) -> LinuxVzPackageRootNetworkAddressFamilyV1 {
        self.address_family
    }

    pub const fn destination_class(&self) -> LinuxVzPackageRootNetworkDestinationClassV1 {
        self.destination_class
    }

    pub const fn destination_port(&self) -> u16 {
        self.destination_port
    }

    pub fn destination_token_sha256(&self) -> &Sha256Digest {
        &self.destination_token_sha256
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
    guest_intent_coverage_complete: bool,
    host_frame_correlation_complete: bool,
    dns_intent_coverage_complete: bool,
    http_observation_complete: bool,
    composite_network_coverage_complete: bool,
    raw_addresses_serialized: bool,
    events: Vec<LinuxVzPackageRootNetworkEventV1>,
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

    pub fn events(&self) -> &[LinuxVzPackageRootNetworkEventV1] {
        &self.events
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
struct RootNetworkEventWireV1 {
    address_family: String,
    cgroup_id: String,
    destination_class: String,
    destination_port: String,
    destination_token_sha256: Sha256Digest,
    enter_cpu: String,
    enter_source_sequence: String,
    enter_timestamp_monotonic_nanoseconds: String,
    event_kind: String,
    exit_cpu: String,
    exit_source_sequence: String,
    exit_timestamp_monotonic_nanoseconds: String,
    pid: String,
    syscall_result: String,
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
        || !stream.coverage_complete_v1()
        || collection.dropped_event_count_v1() != 0
        || collection.discarded_record_count_v1() != 0
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

    let wire = RootNetworkEvidenceWireV1 {
        binding: binding_wire_v1(expected),
        coverage: RootNetworkCoverageWireV1 {
            composite_network_coverage_complete: false,
            connect_sendto_intent_coverage_complete: true,
            discarded_record_count: collection.discarded_record_count_v1().to_string(),
            dns_intent_coverage_complete: false,
            dropped_event_count: collection.dropped_event_count_v1().to_string(),
            evidence_truncated: false,
            guest_intent_coverage_complete: false,
            host_frame_correlation_complete: false,
            http_observation_complete: false,
            network_event_count: events.len().to_string(),
            process_sensor_healthy: true,
            raw_addresses_serialized: false,
            target_detail_complete: true,
            unobserved_capabilities: UNOBSERVED_CAPABILITIES_V1
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
        },
        events,
        process_observation_count: stream.observations_v1().len().to_string(),
        process_source_event_count: stream.source_event_count_v1().to_string(),
        schema_version: LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V1.to_string(),
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
    if wire.schema_version != LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V1
        || wire.binding != binding_wire_v1(expected)
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::BindingMismatch);
    }
    let process_source_event_count = parse_u64_v1(&wire.process_source_event_count)?;
    let process_observation_count = parse_usize_v1(&wire.process_observation_count)?;
    let process_source_event_count_usize = usize::try_from(process_source_event_count)
        .map_err(|_| LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidCoverage)?;
    if process_source_event_count == 0
        || process_observation_count == 0
        || process_observation_count > process_source_event_count_usize
        || wire.events.len() > process_observation_count
        || wire.events.len() > MAX_ROOT_NETWORK_EVENTS_V1
        || wire.coverage
            != (RootNetworkCoverageWireV1 {
                composite_network_coverage_complete: false,
                connect_sendto_intent_coverage_complete: true,
                discarded_record_count: "0".to_string(),
                dns_intent_coverage_complete: false,
                dropped_event_count: "0".to_string(),
                evidence_truncated: false,
                guest_intent_coverage_complete: false,
                host_frame_correlation_complete: false,
                http_observation_complete: false,
                network_event_count: wire.events.len().to_string(),
                process_sensor_healthy: true,
                raw_addresses_serialized: false,
                target_detail_complete: true,
                unobserved_capabilities: UNOBSERVED_CAPABILITIES_V1
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
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
                || !tokens.insert(decoded.destination_token_sha256.clone())
            {
                return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
            }
            prior_exit_sequence = decoded.exit_source_sequence;
            prior_exit_timestamp = decoded.exit_timestamp_monotonic_nanoseconds;
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
        guest_intent_coverage_complete: false,
        host_frame_correlation_complete: false,
        dns_intent_coverage_complete: false,
        http_observation_complete: false,
        composite_network_coverage_complete: false,
        raw_addresses_serialized: false,
        events,
        unobserved_capabilities: UNOBSERVED_CAPABILITIES_V1
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
    })
}

fn network_event_wire_v1(
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
    event: &crate::linux_vz_package_sensor_process_stream::LinuxVzPackageCorrelatedSyscallV1,
    kind: LinuxVzPackageRootNetworkEventKindV1,
) -> Result<RootNetworkEventWireV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    let target = event
        .network_target_v1()
        .ok_or(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent)?;
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
    let (family, destination_class) = classify_network_target_v1(target)?;
    let destination_token_sha256 = network_target_token_v1(
        &expected.sensor_session_challenge_sha256,
        kind,
        family,
        target.port_v1(),
        event.enter_source_sequence_v1(),
        target.address_v1(),
    )?;
    Ok(RootNetworkEventWireV1 {
        address_family: family.as_str_v1().to_string(),
        cgroup_id: event.cgroup_id_v1().to_string(),
        destination_class: destination_class.as_str_v1().to_string(),
        destination_port: target.port_v1().to_string(),
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
        tgid: event.tgid_v1().to_string(),
    })
}

fn decode_event_wire_v1(
    wire: &RootNetworkEventWireV1,
    expected: &LinuxVzPackageExpectedRootNetworkEvidenceV1,
    process_source_event_count: u64,
) -> Result<LinuxVzPackageRootNetworkEventV1, LinuxVzPackageRootNetworkEvidenceErrorV1> {
    let kind = LinuxVzPackageRootNetworkEventKindV1::parse_v1(&wire.event_kind)?;
    let address_family = LinuxVzPackageRootNetworkAddressFamilyV1::parse_v1(&wire.address_family)?;
    let destination_class =
        LinuxVzPackageRootNetworkDestinationClassV1::parse_v1(&wire.destination_class)?;
    if address_family == LinuxVzPackageRootNetworkAddressFamilyV1::Ipv6
        && destination_class == LinuxVzPackageRootNetworkDestinationClassV1::Broadcast
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
    }
    let destination_port = parse_u16_v1(&wire.destination_port)?;
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
    if destination_port == 0
        || enter_source_sequence == 0
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
        || wire.destination_token_sha256 == Sha256Digest::from_bytes(&[])
        || wire.destination_token_sha256 == expected.sensor_session_challenge_sha256
        || wire.destination_token_sha256 == expected.launch_contract_sha256
        || wire.destination_token_sha256 == expected.process_plan_sha256
        || wire.destination_token_sha256 == expected.process_evidence_sha256
    {
        return Err(LinuxVzPackageRootNetworkEvidenceErrorV1::InvalidEvent);
    }
    Ok(LinuxVzPackageRootNetworkEventV1 {
        kind,
        address_family,
        destination_class,
        destination_port,
        destination_token_sha256: wire.destination_token_sha256.clone(),
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
                evidence_truncated: false,
                guest_intent_coverage_complete: false,
                host_frame_correlation_complete: false,
                http_observation_complete: false,
                network_event_count: "1".to_string(),
                process_sensor_healthy: true,
                raw_addresses_serialized: false,
                target_detail_complete: true,
                unobserved_capabilities: UNOBSERVED_CAPABILITIES_V1
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            },
            events: vec![RootNetworkEventWireV1 {
                address_family: "ipv4".to_string(),
                cgroup_id: "77".to_string(),
                destination_class: "documentation".to_string(),
                destination_port: "443".to_string(),
                destination_token_sha256: token,
                enter_cpu: "1".to_string(),
                enter_source_sequence: "14".to_string(),
                enter_timestamp_monotonic_nanoseconds: "500".to_string(),
                event_kind: "connect".to_string(),
                exit_cpu: "1".to_string(),
                exit_source_sequence: "15".to_string(),
                exit_timestamp_monotonic_nanoseconds: "600".to_string(),
                pid: "51".to_string(),
                syscall_result: "-101".to_string(),
                tgid: "51".to_string(),
            }],
            process_observation_count: "10".to_string(),
            process_source_event_count: "18".to_string(),
            schema_version: LINUX_VZ_PACKAGE_ROOT_NETWORK_EVIDENCE_SCHEMA_V1.to_string(),
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
        assert!(!evidence.guest_intent_coverage_complete());
        assert!(!evidence.host_frame_correlation_complete());
        assert!(!evidence.composite_network_coverage_complete());
        assert!(!evidence.raw_addresses_serialized());
        assert_eq!(
            evidence.events()[0].destination_class(),
            LinuxVzPackageRootNetworkDestinationClassV1::Documentation
        );
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(!text.contains("192.0.2.9"));
        assert!(!text.contains("2001:db8"));
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
