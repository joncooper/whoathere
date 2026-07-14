#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]

use crate::{
    LinuxVzPackageProcessSensorCorrelationV1,
    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_PROCESS_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_process_evidence_payload.v1";
pub const LINUX_VZ_PACKAGE_FILE_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_file_evidence_payload.v1";
pub const LINUX_VZ_PACKAGE_NETWORK_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_network_evidence_payload.v1";
pub const LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_SET_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_protected_sensor_payload_set.v1";
pub const MAX_LINUX_VZ_PACKAGE_SENSOR_EVENT_COUNT_V1: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageSensorPayloadErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    BindingMismatch,
    InvalidCoverage,
    InvalidEvent,
    IncompleteProcessLifecycle,
    IncompleteFileDiff,
    GlobalSequenceInvalid,
    Serialization,
}

impl LinuxVzPackageSensorPayloadErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_sensor_payload_empty",
            Self::LimitExceeded => "linux_vz_package_sensor_payload_limit_exceeded",
            Self::InvalidJson => "linux_vz_package_sensor_payload_json_invalid",
            Self::NonCanonical => "linux_vz_package_sensor_payload_noncanonical",
            Self::BindingMismatch => "linux_vz_package_sensor_payload_binding_mismatch",
            Self::InvalidCoverage => "linux_vz_package_sensor_payload_coverage_invalid",
            Self::InvalidEvent => "linux_vz_package_sensor_payload_event_invalid",
            Self::IncompleteProcessLifecycle => {
                "linux_vz_package_process_payload_lifecycle_incomplete"
            }
            Self::IncompleteFileDiff => "linux_vz_package_file_payload_diff_incomplete",
            Self::GlobalSequenceInvalid => {
                "linux_vz_package_sensor_payload_global_sequence_invalid"
            }
            Self::Serialization => "linux_vz_package_sensor_payload_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageSensorPayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageSensorPayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageSensorBindingWireV1 {
    action_index: String,
    cgroup_id: String,
    cgroup_name: String,
    launch_contract_sha256: Sha256Digest,
    leader_pid: String,
    package_gid: String,
    package_uid: String,
    process_plan_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageSensorCoverageWireV1 {
    dropped_event_count: String,
    event_count: String,
    evidence_truncated: bool,
    heartbeat_count: String,
    sensor_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProcessEvidenceWireV1 {
    binding: PackageSensorBindingWireV1,
    coverage: PackageSensorCoverageWireV1,
    descendant_teardown_complete: bool,
    events: Vec<PackageProcessEventWireV1>,
    raw_argv_captured: bool,
    schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageProcessEventWireV1 {
    actor_pid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argv_item_count: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    argv_sha256: Option<Sha256Digest>,
    cgroup_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    executable_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exit_status: Option<String>,
    kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    library_sha256: Option<Sha256Digest>,
    parent_pid: String,
    sequence: String,
    subject_pid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    supplementary_group_count: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_gid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    target_uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    termination_signal: Option<String>,
    timestamp_monotonic_nanoseconds: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageFileEvidenceWireV1 {
    binding: PackageSensorBindingWireV1,
    coverage: PackageSensorCoverageWireV1,
    events: Vec<PackageFileEventWireV1>,
    filesystem_diff_complete: bool,
    raw_paths_captured: bool,
    schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageFileEventWireV1 {
    access_outcome: String,
    actor_pid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    byte_count: Option<String>,
    cgroup_id: String,
    kind: String,
    path_class: String,
    path_token_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secondary_path_token_sha256: Option<Sha256Digest>,
    sequence: String,
    timestamp_monotonic_nanoseconds: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageNetworkEvidenceWireV1 {
    binding: PackageSensorBindingWireV1,
    controlled_sinkhole_only: bool,
    coverage: PackageSensorCoverageWireV1,
    events: Vec<PackageNetworkEventWireV1>,
    public_network_route_present: bool,
    raw_addresses_captured: bool,
    raw_dns_names_captured: bool,
    raw_http_hosts_captured: bool,
    schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageNetworkEventWireV1 {
    actor_pid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    byte_count: Option<String>,
    cgroup_id: String,
    destination_class: String,
    destination_sha256: Sha256Digest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_label_count: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_name_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_query_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dns_wire_length: Option<String>,
    family: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_host_sha256: Option<Sha256Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    http_method_class: Option<String>,
    kind: String,
    outcome: String,
    port: String,
    protocol: String,
    sequence: String,
    timestamp_monotonic_nanoseconds: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageProcessEventKindV1 {
    Fork,
    Exec,
    Exit,
    CredentialChange,
    Reparent,
    Setsid,
    DynamicLibraryLoad,
    Signal,
}

impl LinuxVzPackageProcessEventKindV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "fork" => Ok(Self::Fork),
            "exec" => Ok(Self::Exec),
            "exit" => Ok(Self::Exit),
            "credential_change" => Ok(Self::CredentialChange),
            "reparent" => Ok(Self::Reparent),
            "setsid" => Ok(Self::Setsid),
            "dynamic_library_load" => Ok(Self::DynamicLibraryLoad),
            "signal" => Ok(Self::Signal),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageFileEventKindV1 {
    Open,
    Read,
    Write,
    Rename,
    Delete,
    Mmap,
    PersistenceWrite,
    CanaryRead,
    SensitiveRead,
    FilesystemDiff,
}

impl LinuxVzPackageFileEventKindV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "open" => Ok(Self::Open),
            "read" => Ok(Self::Read),
            "write" => Ok(Self::Write),
            "rename" => Ok(Self::Rename),
            "delete" => Ok(Self::Delete),
            "mmap" => Ok(Self::Mmap),
            "persistence_write" => Ok(Self::PersistenceWrite),
            "canary_read" => Ok(Self::CanaryRead),
            "sensitive_read" => Ok(Self::SensitiveRead),
            "filesystem_diff" => Ok(Self::FilesystemDiff),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageFilePathClassV1 {
    Workspace,
    PackageCache,
    Runtime,
    ProtectedCanary,
    ProtectedSensor,
    SensitiveCredential,
    SensitiveSsh,
    PersistenceStartup,
    Other,
}

impl LinuxVzPackageFilePathClassV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "workspace" => Ok(Self::Workspace),
            "package_cache" => Ok(Self::PackageCache),
            "runtime" => Ok(Self::Runtime),
            "protected_canary" => Ok(Self::ProtectedCanary),
            "protected_sensor" => Ok(Self::ProtectedSensor),
            "sensitive_credential" => Ok(Self::SensitiveCredential),
            "sensitive_ssh" => Ok(Self::SensitiveSsh),
            "persistence_startup" => Ok(Self::PersistenceStartup),
            "other" => Ok(Self::Other),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageFileAccessOutcomeV1 {
    Allowed,
    Denied,
    Observed,
    ChangeDetected,
    NoChange,
}

impl LinuxVzPackageFileAccessOutcomeV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "allowed" => Ok(Self::Allowed),
            "denied" => Ok(Self::Denied),
            "observed" => Ok(Self::Observed),
            "change_detected" => Ok(Self::ChangeDetected),
            "no_change" => Ok(Self::NoChange),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageNetworkEventKindV1 {
    DnsQuery,
    Connect,
    Send,
    HttpRequest,
    Listen,
}

impl LinuxVzPackageNetworkEventKindV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "dns_query" => Ok(Self::DnsQuery),
            "connect" => Ok(Self::Connect),
            "send" => Ok(Self::Send),
            "http_request" => Ok(Self::HttpRequest),
            "listen" => Ok(Self::Listen),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageNetworkDestinationClassV1 {
    Loopback,
    Private,
    LinkLocal,
    Metadata,
    Public,
    ControlledDns,
    ControlledSinkhole,
}

impl LinuxVzPackageNetworkDestinationClassV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "loopback" => Ok(Self::Loopback),
            "private" => Ok(Self::Private),
            "link_local" => Ok(Self::LinkLocal),
            "metadata" => Ok(Self::Metadata),
            "public" => Ok(Self::Public),
            "controlled_dns" => Ok(Self::ControlledDns),
            "controlled_sinkhole" => Ok(Self::ControlledSinkhole),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageNetworkOutcomeV1 {
    Blocked,
    Sinkholed,
    LoopbackObserved,
    ListenerObserved,
}

impl LinuxVzPackageNetworkOutcomeV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "blocked" => Ok(Self::Blocked),
            "sinkholed" => Ok(Self::Sinkholed),
            "loopback_observed" => Ok(Self::LoopbackObserved),
            "listener_observed" => Ok(Self::ListenerObserved),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageNetworkProtocolV1 {
    Tcp,
    Udp,
}

impl LinuxVzPackageNetworkProtocolV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageNetworkFamilyV1 {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageDnsQueryTypeV1 {
    A,
    Aaaa,
    Txt,
    Mx,
    Cname,
    Other,
}

impl LinuxVzPackageDnsQueryTypeV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "a" => Ok(Self::A),
            "aaaa" => Ok(Self::Aaaa),
            "txt" => Ok(Self::Txt),
            "mx" => Ok(Self::Mx),
            "cname" => Ok(Self::Cname),
            "other" => Ok(Self::Other),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageHttpMethodClassV1 {
    Get,
    Post,
    Put,
    Delete,
    Other,
}

impl LinuxVzPackageHttpMethodClassV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "get" => Ok(Self::Get),
            "post" => Ok(Self::Post),
            "put" => Ok(Self::Put),
            "delete" => Ok(Self::Delete),
            "other" => Ok(Self::Other),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

impl LinuxVzPackageNetworkFamilyV1 {
    fn parse_v1(value: &str) -> Result<Self, LinuxVzPackageSensorPayloadErrorV1> {
        match value {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageProcessEventV1 {
    kind: LinuxVzPackageProcessEventKindV1,
    sequence: u64,
    timestamp_monotonic_nanoseconds: u64,
    actor_pid: u32,
    subject_pid: u32,
    parent_pid: u32,
    executable_sha256: Option<Sha256Digest>,
    argv_sha256: Option<Sha256Digest>,
    argv_item_count: Option<u64>,
    library_sha256: Option<Sha256Digest>,
    exit_status: Option<u8>,
    termination_signal: Option<u8>,
    target_uid: Option<u32>,
    target_gid: Option<u32>,
    supplementary_group_count: Option<u32>,
}

impl LinuxVzPackageProcessEventV1 {
    pub const fn kind(&self) -> LinuxVzPackageProcessEventKindV1 {
        self.kind
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.timestamp_monotonic_nanoseconds
    }

    pub const fn actor_pid(&self) -> u32 {
        self.actor_pid
    }

    pub const fn subject_pid(&self) -> u32 {
        self.subject_pid
    }

    pub const fn parent_pid(&self) -> u32 {
        self.parent_pid
    }

    pub fn executable_sha256(&self) -> Option<&Sha256Digest> {
        self.executable_sha256.as_ref()
    }

    pub fn argv_sha256(&self) -> Option<&Sha256Digest> {
        self.argv_sha256.as_ref()
    }

    pub const fn argv_item_count(&self) -> Option<u64> {
        self.argv_item_count
    }

    pub fn library_sha256(&self) -> Option<&Sha256Digest> {
        self.library_sha256.as_ref()
    }

    pub const fn exit_status(&self) -> Option<u8> {
        self.exit_status
    }

    pub const fn termination_signal(&self) -> Option<u8> {
        self.termination_signal
    }

    pub const fn target_uid(&self) -> Option<u32> {
        self.target_uid
    }

    pub const fn target_gid(&self) -> Option<u32> {
        self.target_gid
    }

    pub const fn supplementary_group_count(&self) -> Option<u32> {
        self.supplementary_group_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageFileEventV1 {
    kind: LinuxVzPackageFileEventKindV1,
    path_class: LinuxVzPackageFilePathClassV1,
    outcome: LinuxVzPackageFileAccessOutcomeV1,
    sequence: u64,
    timestamp_monotonic_nanoseconds: u64,
    actor_pid: u32,
    path_token_sha256: Sha256Digest,
    secondary_path_token_sha256: Option<Sha256Digest>,
    byte_count: Option<u64>,
}

impl LinuxVzPackageFileEventV1 {
    pub const fn kind(&self) -> LinuxVzPackageFileEventKindV1 {
        self.kind
    }

    pub const fn path_class(&self) -> LinuxVzPackageFilePathClassV1 {
        self.path_class
    }

    pub const fn outcome(&self) -> LinuxVzPackageFileAccessOutcomeV1 {
        self.outcome
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.timestamp_monotonic_nanoseconds
    }

    pub const fn actor_pid(&self) -> u32 {
        self.actor_pid
    }

    pub fn path_token_sha256(&self) -> &Sha256Digest {
        &self.path_token_sha256
    }

    pub fn secondary_path_token_sha256(&self) -> Option<&Sha256Digest> {
        self.secondary_path_token_sha256.as_ref()
    }

    pub const fn byte_count(&self) -> Option<u64> {
        self.byte_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageNetworkEventV1 {
    kind: LinuxVzPackageNetworkEventKindV1,
    destination_class: LinuxVzPackageNetworkDestinationClassV1,
    outcome: LinuxVzPackageNetworkOutcomeV1,
    family: LinuxVzPackageNetworkFamilyV1,
    protocol: LinuxVzPackageNetworkProtocolV1,
    sequence: u64,
    timestamp_monotonic_nanoseconds: u64,
    actor_pid: u32,
    destination_sha256: Sha256Digest,
    port: u16,
    byte_count: Option<u64>,
    dns_name_sha256: Option<Sha256Digest>,
    dns_query_type: Option<LinuxVzPackageDnsQueryTypeV1>,
    dns_label_count: Option<u16>,
    dns_wire_length: Option<u16>,
    http_host_sha256: Option<Sha256Digest>,
    http_method_class: Option<LinuxVzPackageHttpMethodClassV1>,
}

impl LinuxVzPackageNetworkEventV1 {
    pub const fn kind(&self) -> LinuxVzPackageNetworkEventKindV1 {
        self.kind
    }

    pub const fn destination_class(&self) -> LinuxVzPackageNetworkDestinationClassV1 {
        self.destination_class
    }

    pub const fn outcome(&self) -> LinuxVzPackageNetworkOutcomeV1 {
        self.outcome
    }

    pub const fn family(&self) -> LinuxVzPackageNetworkFamilyV1 {
        self.family
    }

    pub const fn protocol(&self) -> LinuxVzPackageNetworkProtocolV1 {
        self.protocol
    }

    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.timestamp_monotonic_nanoseconds
    }

    pub const fn actor_pid(&self) -> u32 {
        self.actor_pid
    }

    pub fn destination_sha256(&self) -> &Sha256Digest {
        &self.destination_sha256
    }

    pub const fn port(&self) -> u16 {
        self.port
    }

    pub const fn byte_count(&self) -> Option<u64> {
        self.byte_count
    }

    pub fn dns_name_sha256(&self) -> Option<&Sha256Digest> {
        self.dns_name_sha256.as_ref()
    }

    pub const fn dns_query_type(&self) -> Option<LinuxVzPackageDnsQueryTypeV1> {
        self.dns_query_type
    }

    pub const fn dns_label_count(&self) -> Option<u16> {
        self.dns_label_count
    }

    pub const fn dns_wire_length(&self) -> Option<u16> {
        self.dns_wire_length
    }

    pub fn http_host_sha256(&self) -> Option<&Sha256Digest> {
        self.http_host_sha256.as_ref()
    }

    pub const fn http_method_class(&self) -> Option<LinuxVzPackageHttpMethodClassV1> {
        self.http_method_class
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageProcessEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    events: Vec<LinuxVzPackageProcessEventV1>,
}

impl LinuxVzPackageProcessEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn events(&self) -> &[LinuxVzPackageProcessEventV1] {
        &self.events
    }

    pub const fn coverage_complete(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageFileEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    events: Vec<LinuxVzPackageFileEventV1>,
}

impl LinuxVzPackageFileEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn events(&self) -> &[LinuxVzPackageFileEventV1] {
        &self.events
    }

    pub const fn filesystem_diff_complete(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageNetworkEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    events: Vec<LinuxVzPackageNetworkEventV1>,
}

impl LinuxVzPackageNetworkEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn events(&self) -> &[LinuxVzPackageNetworkEventV1] {
        &self.events
    }

    pub const fn public_network_route_present(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageProtectedSensorPayloadSetV1 {
    payload_set_sha256: Sha256Digest,
    process: LinuxVzPackageProcessEvidencePayloadV1,
    file: LinuxVzPackageFileEvidencePayloadV1,
    network: LinuxVzPackageNetworkEvidencePayloadV1,
}

impl LinuxVzPackageProtectedSensorPayloadSetV1 {
    pub fn payload_set_sha256(&self) -> &Sha256Digest {
        &self.payload_set_sha256
    }

    pub fn process(&self) -> &LinuxVzPackageProcessEvidencePayloadV1 {
        &self.process
    }

    pub fn file(&self) -> &LinuxVzPackageFileEvidencePayloadV1 {
        &self.file
    }

    pub fn network(&self) -> &LinuxVzPackageNetworkEvidencePayloadV1 {
        &self.network
    }

    pub const fn coverage_complete(&self) -> bool {
        true
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackageProtectedSensorPayloadSetDigestWireV1<'a> {
    schema_version: &'static str,
    correlation_sha256: &'a Sha256Digest,
    process_evidence_sha256: &'a Sha256Digest,
    file_evidence_sha256: &'a Sha256Digest,
    network_evidence_sha256: &'a Sha256Digest,
    global_sequence_complete: bool,
    coverage_complete: bool,
    public_network_route_present: bool,
    sync_back: bool,
}

pub(crate) fn decode_linux_vz_package_protected_sensor_payload_set_v1(
    correlation: &LinuxVzPackageProcessSensorCorrelationV1,
    process_bytes: &[u8],
    file_bytes: &[u8],
    network_bytes: &[u8],
) -> Result<LinuxVzPackageProtectedSensorPayloadSetV1, LinuxVzPackageSensorPayloadErrorV1> {
    let process = decode_process_payload_v1(correlation, process_bytes)?;
    let file = decode_file_payload_v1(correlation, file_bytes)?;
    let network = decode_network_payload_v1(correlation, network_bytes)?;

    let leader_exit_sequence = process
        .events
        .iter()
        .find(|event| {
            event.kind == LinuxVzPackageProcessEventKindV1::Exit
                && event.subject_pid == correlation.leader_pid()
        })
        .map(|event| event.sequence)
        .ok_or(LinuxVzPackageSensorPayloadErrorV1::IncompleteProcessLifecycle)?;
    let filesystem_diff_sequence = file
        .events
        .iter()
        .find(|event| event.kind == LinuxVzPackageFileEventKindV1::FilesystemDiff)
        .map(|event| event.sequence)
        .ok_or(LinuxVzPackageSensorPayloadErrorV1::IncompleteFileDiff)?;
    if filesystem_diff_sequence <= leader_exit_sequence {
        return Err(LinuxVzPackageSensorPayloadErrorV1::IncompleteFileDiff);
    }

    let mut global_events = Vec::with_capacity(
        process
            .events
            .len()
            .checked_add(file.events.len())
            .and_then(|value| value.checked_add(network.events.len()))
            .ok_or(LinuxVzPackageSensorPayloadErrorV1::LimitExceeded)?,
    );
    global_events.extend(
        process
            .events
            .iter()
            .map(|event| (event.sequence, event.timestamp_monotonic_nanoseconds)),
    );
    global_events.extend(
        file.events
            .iter()
            .map(|event| (event.sequence, event.timestamp_monotonic_nanoseconds)),
    );
    global_events.extend(
        network
            .events
            .iter()
            .map(|event| (event.sequence, event.timestamp_monotonic_nanoseconds)),
    );
    global_events.sort_unstable_by_key(|(sequence, _)| *sequence);
    if global_events.len() != correlation.event_count() as usize
        || global_events.len() > MAX_LINUX_VZ_PACKAGE_SENSOR_EVENT_COUNT_V1
    {
        return Err(LinuxVzPackageSensorPayloadErrorV1::GlobalSequenceInvalid);
    }
    let mut last_timestamp = 0;
    for (index, (sequence, timestamp)) in global_events.iter().enumerate() {
        if *sequence != index as u64 + 1
            || *timestamp <= last_timestamp
            || *timestamp < correlation.process_started_monotonic_nanoseconds()
            || *timestamp > correlation.sensor_ended_monotonic_nanoseconds()
        {
            return Err(LinuxVzPackageSensorPayloadErrorV1::GlobalSequenceInvalid);
        }
        last_timestamp = *timestamp;
    }

    let digest_wire = PackageProtectedSensorPayloadSetDigestWireV1 {
        schema_version: LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_SET_SCHEMA_V1,
        correlation_sha256: correlation.correlation_sha256(),
        process_evidence_sha256: process.payload_sha256(),
        file_evidence_sha256: file.payload_sha256(),
        network_evidence_sha256: network.payload_sha256(),
        global_sequence_complete: true,
        coverage_complete: true,
        public_network_route_present: false,
        sync_back: false,
    };
    let digest_bytes = serde_json_canonicalizer::to_vec(&digest_wire)
        .map_err(|_| LinuxVzPackageSensorPayloadErrorV1::Serialization)?;
    Ok(LinuxVzPackageProtectedSensorPayloadSetV1 {
        payload_set_sha256: Sha256Digest::from_bytes(&digest_bytes),
        process,
        file,
        network,
    })
}

fn decode_process_payload_v1(
    correlation: &LinuxVzPackageProcessSensorCorrelationV1,
    bytes: &[u8],
) -> Result<LinuxVzPackageProcessEvidencePayloadV1, LinuxVzPackageSensorPayloadErrorV1> {
    let (wire, canonical) = decode_canonical_v1::<PackageProcessEvidenceWireV1>(bytes)?;
    validate_binding_v1(&wire.binding, correlation)?;
    let event_count = validate_coverage_v1(&wire.coverage, correlation)?;
    if wire.schema_version != LINUX_VZ_PACKAGE_PROCESS_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.raw_argv_captured
        || !wire.descendant_teardown_complete
        || event_count != correlation.process_event_count()
        || event_count < 3
        || wire.events.len() != event_count as usize
    {
        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidCoverage);
    }

    let mut events = Vec::with_capacity(wire.events.len());
    let mut last_sequence = 0;
    let mut last_timestamp = 0;
    let mut leader_fork_sequence = None;
    let mut leader_exec_sequence = None;
    let mut leader_exit_sequence = None;
    for event in wire.events {
        let kind = LinuxVzPackageProcessEventKindV1::parse_v1(&event.kind)?;
        let sequence = decimal_u64_v1(&event.sequence)?;
        let timestamp = decimal_u64_v1(&event.timestamp_monotonic_nanoseconds)?;
        let cgroup_id = decimal_u64_v1(&event.cgroup_id)?;
        let actor_pid = decimal_u32_v1(&event.actor_pid)?;
        let subject_pid = decimal_u32_v1(&event.subject_pid)?;
        let parent_pid = decimal_u32_v1(&event.parent_pid)?;
        let argv_item_count = optional_decimal_u64_v1(event.argv_item_count.as_deref())?;
        let exit_status = optional_u8_v1(event.exit_status.as_deref(), true)?;
        let termination_signal = optional_u8_v1(event.termination_signal.as_deref(), false)?;
        let target_uid = optional_decimal_u64_v1(event.target_uid.as_deref())?;
        let target_gid = optional_decimal_u64_v1(event.target_gid.as_deref())?;
        let supplementary_group_count =
            optional_decimal_u64_v1(event.supplementary_group_count.as_deref())?;
        if sequence <= last_sequence
            || timestamp <= last_timestamp
            || timestamp < correlation.process_started_monotonic_nanoseconds()
            || timestamp > correlation.process_ended_monotonic_nanoseconds()
            || cgroup_id != correlation.cgroup_id()
            || actor_pid <= 1
            || subject_pid <= 1
            || parent_pid <= 1
        {
            return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
        }
        require_nonempty_optional_digest_v1(event.executable_sha256.as_ref())?;
        require_nonempty_optional_digest_v1(event.argv_sha256.as_ref())?;
        require_nonempty_optional_digest_v1(event.library_sha256.as_ref())?;

        let valid_kind = match kind {
            LinuxVzPackageProcessEventKindV1::Fork => {
                actor_pid == parent_pid
                    && actor_pid != subject_pid
                    && no_process_details_v1(
                        &event,
                        argv_item_count,
                        exit_status,
                        termination_signal,
                        target_uid,
                        target_gid,
                        supplementary_group_count,
                    )
            }
            LinuxVzPackageProcessEventKindV1::Exec => {
                actor_pid == subject_pid
                    && event.executable_sha256.is_some()
                    && event.argv_sha256.is_some()
                    && matches!(argv_item_count, Some(1..=4096))
                    && event.library_sha256.is_none()
                    && exit_status.is_none()
                    && termination_signal.is_none()
                    && target_uid.is_none()
                    && target_gid.is_none()
                    && supplementary_group_count.is_none()
            }
            LinuxVzPackageProcessEventKindV1::Exit => {
                actor_pid == subject_pid
                    && event.executable_sha256.is_none()
                    && event.argv_sha256.is_none()
                    && argv_item_count.is_none()
                    && event.library_sha256.is_none()
                    && exit_status.is_some() != termination_signal.is_some()
                    && target_uid.is_none()
                    && target_gid.is_none()
                    && supplementary_group_count.is_none()
            }
            LinuxVzPackageProcessEventKindV1::CredentialChange => {
                actor_pid == subject_pid
                    && event.executable_sha256.is_none()
                    && event.argv_sha256.is_none()
                    && argv_item_count.is_none()
                    && event.library_sha256.is_none()
                    && exit_status.is_none()
                    && termination_signal.is_none()
                    && matches!(target_uid, Some(value) if value <= u32::MAX as u64)
                    && matches!(target_gid, Some(value) if value <= u32::MAX as u64)
                    && matches!(supplementary_group_count, Some(0..=1024))
            }
            LinuxVzPackageProcessEventKindV1::DynamicLibraryLoad => {
                actor_pid == subject_pid
                    && event.library_sha256.is_some()
                    && event.executable_sha256.is_none()
                    && event.argv_sha256.is_none()
                    && argv_item_count.is_none()
                    && exit_status.is_none()
                    && termination_signal.is_none()
                    && target_uid.is_none()
                    && target_gid.is_none()
                    && supplementary_group_count.is_none()
            }
            LinuxVzPackageProcessEventKindV1::Signal => {
                event.executable_sha256.is_none()
                    && event.argv_sha256.is_none()
                    && argv_item_count.is_none()
                    && event.library_sha256.is_none()
                    && exit_status.is_none()
                    && termination_signal.is_some()
                    && target_uid.is_none()
                    && target_gid.is_none()
                    && supplementary_group_count.is_none()
            }
            LinuxVzPackageProcessEventKindV1::Reparent
            | LinuxVzPackageProcessEventKindV1::Setsid => no_process_details_v1(
                &event,
                argv_item_count,
                exit_status,
                termination_signal,
                target_uid,
                target_gid,
                supplementary_group_count,
            ),
        };
        if !valid_kind {
            return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
        }
        if subject_pid == correlation.leader_pid() {
            match kind {
                LinuxVzPackageProcessEventKindV1::Fork => {
                    if leader_fork_sequence.replace(sequence).is_some() {
                        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
                    }
                }
                LinuxVzPackageProcessEventKindV1::Exec => {
                    if leader_exec_sequence.replace(sequence).is_some() {
                        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
                    }
                }
                LinuxVzPackageProcessEventKindV1::Exit => {
                    if exit_status != correlation.leader_exit_status()
                        || termination_signal != correlation.leader_termination_signal()
                    {
                        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
                    }
                    if leader_exit_sequence.replace(sequence).is_some() {
                        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
                    }
                }
                _ => {}
            }
        }
        last_sequence = sequence;
        last_timestamp = timestamp;
        events.push(LinuxVzPackageProcessEventV1 {
            kind,
            sequence,
            timestamp_monotonic_nanoseconds: timestamp,
            actor_pid,
            subject_pid,
            parent_pid,
            executable_sha256: event.executable_sha256,
            argv_sha256: event.argv_sha256,
            argv_item_count,
            library_sha256: event.library_sha256,
            exit_status,
            termination_signal,
            target_uid: target_uid.map(|value| value as u32),
            target_gid: target_gid.map(|value| value as u32),
            supplementary_group_count: supplementary_group_count.map(|value| value as u32),
        });
    }
    if !matches!(
        (leader_fork_sequence, leader_exec_sequence, leader_exit_sequence),
        (Some(fork), Some(exec), Some(exit)) if fork < exec && exec < exit
    ) {
        return Err(LinuxVzPackageSensorPayloadErrorV1::IncompleteProcessLifecycle);
    }
    Ok(LinuxVzPackageProcessEvidencePayloadV1 {
        payload_sha256: Sha256Digest::from_bytes(&canonical),
        canonical_json: canonical,
        events,
    })
}

fn decode_file_payload_v1(
    correlation: &LinuxVzPackageProcessSensorCorrelationV1,
    bytes: &[u8],
) -> Result<LinuxVzPackageFileEvidencePayloadV1, LinuxVzPackageSensorPayloadErrorV1> {
    let (wire, canonical) = decode_canonical_v1::<PackageFileEvidenceWireV1>(bytes)?;
    validate_binding_v1(&wire.binding, correlation)?;
    let event_count = validate_coverage_v1(&wire.coverage, correlation)?;
    if wire.schema_version != LINUX_VZ_PACKAGE_FILE_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.raw_paths_captured
        || !wire.filesystem_diff_complete
        || event_count != correlation.file_event_count()
        || event_count == 0
        || wire.events.len() != event_count as usize
    {
        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidCoverage);
    }

    let mut events = Vec::with_capacity(wire.events.len());
    let mut last_sequence = 0;
    let mut last_timestamp = 0;
    let mut filesystem_diff_count = 0_u32;
    for event in wire.events {
        let kind = LinuxVzPackageFileEventKindV1::parse_v1(&event.kind)?;
        let path_class = LinuxVzPackageFilePathClassV1::parse_v1(&event.path_class)?;
        let outcome = LinuxVzPackageFileAccessOutcomeV1::parse_v1(&event.access_outcome)?;
        let sequence = decimal_u64_v1(&event.sequence)?;
        let timestamp = decimal_u64_v1(&event.timestamp_monotonic_nanoseconds)?;
        let cgroup_id = decimal_u64_v1(&event.cgroup_id)?;
        let actor_pid = decimal_u32_v1(&event.actor_pid)?;
        let byte_count = optional_decimal_u64_v1(event.byte_count.as_deref())?;
        if sequence <= last_sequence
            || timestamp <= last_timestamp
            || timestamp < correlation.process_started_monotonic_nanoseconds()
            || timestamp > correlation.sensor_ended_monotonic_nanoseconds()
            || (kind != LinuxVzPackageFileEventKindV1::FilesystemDiff
                && timestamp > correlation.process_ended_monotonic_nanoseconds())
            || cgroup_id != correlation.cgroup_id()
            || actor_pid <= 1
            || event.path_token_sha256 == Sha256Digest::from_bytes(&[])
        {
            return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
        }
        require_nonempty_optional_digest_v1(event.secondary_path_token_sha256.as_ref())?;
        let valid_kind = match kind {
            LinuxVzPackageFileEventKindV1::Rename => {
                event.secondary_path_token_sha256.is_some()
                    && matches!(
                        outcome,
                        LinuxVzPackageFileAccessOutcomeV1::Allowed
                            | LinuxVzPackageFileAccessOutcomeV1::Denied
                            | LinuxVzPackageFileAccessOutcomeV1::Observed
                    )
            }
            LinuxVzPackageFileEventKindV1::FilesystemDiff => {
                filesystem_diff_count = filesystem_diff_count.saturating_add(1);
                event.secondary_path_token_sha256.is_none()
                    && path_class == LinuxVzPackageFilePathClassV1::Workspace
                    && timestamp >= correlation.process_ended_monotonic_nanoseconds()
                    && matches!(
                        outcome,
                        LinuxVzPackageFileAccessOutcomeV1::ChangeDetected
                            | LinuxVzPackageFileAccessOutcomeV1::NoChange
                    )
            }
            LinuxVzPackageFileEventKindV1::PersistenceWrite => {
                event.secondary_path_token_sha256.is_none()
                    && path_class == LinuxVzPackageFilePathClassV1::PersistenceStartup
                    && matches!(
                        outcome,
                        LinuxVzPackageFileAccessOutcomeV1::Allowed
                            | LinuxVzPackageFileAccessOutcomeV1::Denied
                            | LinuxVzPackageFileAccessOutcomeV1::Observed
                    )
            }
            LinuxVzPackageFileEventKindV1::CanaryRead => {
                event.secondary_path_token_sha256.is_none()
                    && path_class == LinuxVzPackageFilePathClassV1::ProtectedCanary
                    && matches!(
                        outcome,
                        LinuxVzPackageFileAccessOutcomeV1::Allowed
                            | LinuxVzPackageFileAccessOutcomeV1::Denied
                            | LinuxVzPackageFileAccessOutcomeV1::Observed
                    )
            }
            LinuxVzPackageFileEventKindV1::SensitiveRead => {
                event.secondary_path_token_sha256.is_none()
                    && matches!(
                        path_class,
                        LinuxVzPackageFilePathClassV1::SensitiveCredential
                            | LinuxVzPackageFilePathClassV1::SensitiveSsh
                            | LinuxVzPackageFilePathClassV1::ProtectedSensor
                    )
                    && matches!(
                        outcome,
                        LinuxVzPackageFileAccessOutcomeV1::Allowed
                            | LinuxVzPackageFileAccessOutcomeV1::Denied
                            | LinuxVzPackageFileAccessOutcomeV1::Observed
                    )
            }
            LinuxVzPackageFileEventKindV1::Open
            | LinuxVzPackageFileEventKindV1::Read
            | LinuxVzPackageFileEventKindV1::Write
            | LinuxVzPackageFileEventKindV1::Delete
            | LinuxVzPackageFileEventKindV1::Mmap => {
                event.secondary_path_token_sha256.is_none()
                    && matches!(
                        outcome,
                        LinuxVzPackageFileAccessOutcomeV1::Allowed
                            | LinuxVzPackageFileAccessOutcomeV1::Denied
                            | LinuxVzPackageFileAccessOutcomeV1::Observed
                    )
            }
        };
        if !valid_kind {
            return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
        }
        last_sequence = sequence;
        last_timestamp = timestamp;
        events.push(LinuxVzPackageFileEventV1 {
            kind,
            path_class,
            outcome,
            sequence,
            timestamp_monotonic_nanoseconds: timestamp,
            actor_pid,
            path_token_sha256: event.path_token_sha256,
            secondary_path_token_sha256: event.secondary_path_token_sha256,
            byte_count,
        });
    }
    if filesystem_diff_count != 1 {
        return Err(LinuxVzPackageSensorPayloadErrorV1::IncompleteFileDiff);
    }
    Ok(LinuxVzPackageFileEvidencePayloadV1 {
        payload_sha256: Sha256Digest::from_bytes(&canonical),
        canonical_json: canonical,
        events,
    })
}

fn decode_network_payload_v1(
    correlation: &LinuxVzPackageProcessSensorCorrelationV1,
    bytes: &[u8],
) -> Result<LinuxVzPackageNetworkEvidencePayloadV1, LinuxVzPackageSensorPayloadErrorV1> {
    let (wire, canonical) = decode_canonical_v1::<PackageNetworkEvidenceWireV1>(bytes)?;
    validate_binding_v1(&wire.binding, correlation)?;
    let event_count = validate_coverage_v1(&wire.coverage, correlation)?;
    if wire.schema_version != LINUX_VZ_PACKAGE_NETWORK_EVIDENCE_PAYLOAD_SCHEMA_V1
        || !wire.controlled_sinkhole_only
        || wire.public_network_route_present
        || wire.raw_addresses_captured
        || wire.raw_dns_names_captured
        || wire.raw_http_hosts_captured
        || event_count != correlation.network_event_count()
        || wire.events.len() != event_count as usize
    {
        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidCoverage);
    }

    let mut events = Vec::with_capacity(wire.events.len());
    let mut last_sequence = 0;
    let mut last_timestamp = 0;
    for event in wire.events {
        let kind = LinuxVzPackageNetworkEventKindV1::parse_v1(&event.kind)?;
        let destination_class =
            LinuxVzPackageNetworkDestinationClassV1::parse_v1(&event.destination_class)?;
        let outcome = LinuxVzPackageNetworkOutcomeV1::parse_v1(&event.outcome)?;
        let family = LinuxVzPackageNetworkFamilyV1::parse_v1(&event.family)?;
        let protocol = LinuxVzPackageNetworkProtocolV1::parse_v1(&event.protocol)?;
        let sequence = decimal_u64_v1(&event.sequence)?;
        let timestamp = decimal_u64_v1(&event.timestamp_monotonic_nanoseconds)?;
        let cgroup_id = decimal_u64_v1(&event.cgroup_id)?;
        let actor_pid = decimal_u32_v1(&event.actor_pid)?;
        let port = decimal_u16_v1(&event.port)?;
        let byte_count = optional_decimal_u64_v1(event.byte_count.as_deref())?;
        let dns_label_count = optional_decimal_u64_v1(event.dns_label_count.as_deref())?;
        let dns_wire_length = optional_decimal_u64_v1(event.dns_wire_length.as_deref())?;
        let dns_query_type = event
            .dns_query_type
            .as_deref()
            .map(LinuxVzPackageDnsQueryTypeV1::parse_v1)
            .transpose()?;
        let http_method_class = event
            .http_method_class
            .as_deref()
            .map(LinuxVzPackageHttpMethodClassV1::parse_v1)
            .transpose()?;
        if sequence <= last_sequence
            || timestamp <= last_timestamp
            || timestamp < correlation.process_started_monotonic_nanoseconds()
            || timestamp > correlation.process_ended_monotonic_nanoseconds()
            || cgroup_id != correlation.cgroup_id()
            || actor_pid <= 1
            || port == 0
            || event.destination_sha256 == Sha256Digest::from_bytes(&[])
        {
            return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
        }
        require_nonempty_optional_digest_v1(event.dns_name_sha256.as_ref())?;
        require_nonempty_optional_digest_v1(event.http_host_sha256.as_ref())?;
        let destination_outcome_valid = match destination_class {
            LinuxVzPackageNetworkDestinationClassV1::Loopback => matches!(
                outcome,
                LinuxVzPackageNetworkOutcomeV1::Blocked
                    | LinuxVzPackageNetworkOutcomeV1::Sinkholed
                    | LinuxVzPackageNetworkOutcomeV1::LoopbackObserved
                    | LinuxVzPackageNetworkOutcomeV1::ListenerObserved
            ),
            _ => matches!(
                outcome,
                LinuxVzPackageNetworkOutcomeV1::Blocked | LinuxVzPackageNetworkOutcomeV1::Sinkholed
            ),
        };
        let valid_kind = match kind {
            LinuxVzPackageNetworkEventKindV1::DnsQuery => {
                destination_class == LinuxVzPackageNetworkDestinationClassV1::ControlledDns
                    && port == 53
                    && matches!(
                        protocol,
                        LinuxVzPackageNetworkProtocolV1::Tcp | LinuxVzPackageNetworkProtocolV1::Udp
                    )
                    && event.dns_name_sha256.is_some()
                    && matches!(dns_label_count, Some(1..=127))
                    && matches!(dns_wire_length, Some(12..=4096))
                    && dns_query_type.is_some()
                    && event.http_host_sha256.is_none()
                    && event.http_method_class.is_none()
                    && byte_count == dns_wire_length
                    && byte_count.is_some_and(|value| value > 0 && value <= 65_535)
            }
            LinuxVzPackageNetworkEventKindV1::HttpRequest => {
                protocol == LinuxVzPackageNetworkProtocolV1::Tcp
                    && event.dns_name_sha256.is_none()
                    && event.dns_query_type.is_none()
                    && dns_label_count.is_none()
                    && dns_wire_length.is_none()
                    && event.http_host_sha256.is_some()
                    && http_method_class.is_some()
                    && byte_count.is_some_and(|value| value > 0 && value <= 16 * 1024 * 1024)
            }
            LinuxVzPackageNetworkEventKindV1::Send => {
                no_network_application_details_v1(&event, dns_label_count, dns_wire_length)
                    && byte_count.is_some_and(|value| value > 0 && value <= 16 * 1024 * 1024)
            }
            LinuxVzPackageNetworkEventKindV1::Connect => {
                no_network_application_details_v1(&event, dns_label_count, dns_wire_length)
                    && byte_count.is_none()
                    && outcome != LinuxVzPackageNetworkOutcomeV1::ListenerObserved
            }
            LinuxVzPackageNetworkEventKindV1::Listen => {
                no_network_application_details_v1(&event, dns_label_count, dns_wire_length)
                    && byte_count.is_none()
                    && destination_class == LinuxVzPackageNetworkDestinationClassV1::Loopback
                    && outcome == LinuxVzPackageNetworkOutcomeV1::ListenerObserved
                    && protocol == LinuxVzPackageNetworkProtocolV1::Tcp
            }
        };
        if !destination_outcome_valid || !valid_kind {
            return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
        }
        last_sequence = sequence;
        last_timestamp = timestamp;
        events.push(LinuxVzPackageNetworkEventV1 {
            kind,
            destination_class,
            outcome,
            family,
            protocol,
            sequence,
            timestamp_monotonic_nanoseconds: timestamp,
            actor_pid,
            destination_sha256: event.destination_sha256,
            port,
            byte_count,
            dns_name_sha256: event.dns_name_sha256,
            dns_query_type,
            dns_label_count: dns_label_count.map(|value| value as u16),
            dns_wire_length: dns_wire_length.map(|value| value as u16),
            http_host_sha256: event.http_host_sha256,
            http_method_class,
        });
    }
    Ok(LinuxVzPackageNetworkEvidencePayloadV1 {
        payload_sha256: Sha256Digest::from_bytes(&canonical),
        canonical_json: canonical,
        events,
    })
}

fn decode_canonical_v1<T>(bytes: &[u8]) -> Result<(T, Vec<u8>), LinuxVzPackageSensorPayloadErrorV1>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() {
        return Err(LinuxVzPackageSensorPayloadErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzPackageSensorPayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = T::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageSensorPayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageSensorPayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageSensorPayloadErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(LinuxVzPackageSensorPayloadErrorV1::NonCanonical);
    }
    Ok((wire, canonical))
}

fn validate_binding_v1(
    binding: &PackageSensorBindingWireV1,
    correlation: &LinuxVzPackageProcessSensorCorrelationV1,
) -> Result<(), LinuxVzPackageSensorPayloadErrorV1> {
    if decimal_usize_v1(&binding.action_index)? != correlation.action_index()
        || decimal_u64_v1(&binding.cgroup_id)? != correlation.cgroup_id()
        || binding.cgroup_name != correlation.cgroup_name()
        || binding.launch_contract_sha256 != *correlation.launch_contract_sha256()
        || decimal_u32_v1(&binding.leader_pid)? != correlation.leader_pid()
        || decimal_u32_v1(&binding.package_gid)? != 65_534
        || decimal_u32_v1(&binding.package_uid)? != 65_534
        || binding.process_plan_sha256 != *correlation.process_plan_sha256()
        || binding.sensor_session_challenge_sha256 != *correlation.sensor_session_challenge_sha256()
    {
        return Err(LinuxVzPackageSensorPayloadErrorV1::BindingMismatch);
    }
    Ok(())
}

fn validate_coverage_v1(
    coverage: &PackageSensorCoverageWireV1,
    correlation: &LinuxVzPackageProcessSensorCorrelationV1,
) -> Result<u64, LinuxVzPackageSensorPayloadErrorV1> {
    let event_count = decimal_u64_v1(&coverage.event_count)?;
    if event_count > MAX_LINUX_VZ_PACKAGE_SENSOR_EVENT_COUNT_V1 as u64
        || decimal_u64_v1(&coverage.heartbeat_count)? != correlation.heartbeat_count()
        || decimal_u64_v1(&coverage.dropped_event_count)? != 0
        || !coverage.sensor_healthy
        || coverage.evidence_truncated
    {
        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidCoverage);
    }
    Ok(event_count)
}

fn no_process_details_v1(
    event: &PackageProcessEventWireV1,
    argv_item_count: Option<u64>,
    exit_status: Option<u8>,
    termination_signal: Option<u8>,
    target_uid: Option<u64>,
    target_gid: Option<u64>,
    supplementary_group_count: Option<u64>,
) -> bool {
    event.executable_sha256.is_none()
        && event.argv_sha256.is_none()
        && argv_item_count.is_none()
        && event.library_sha256.is_none()
        && exit_status.is_none()
        && termination_signal.is_none()
        && target_uid.is_none()
        && target_gid.is_none()
        && supplementary_group_count.is_none()
}

fn no_network_application_details_v1(
    event: &PackageNetworkEventWireV1,
    dns_label_count: Option<u64>,
    dns_wire_length: Option<u64>,
) -> bool {
    event.dns_name_sha256.is_none()
        && event.dns_query_type.is_none()
        && dns_label_count.is_none()
        && dns_wire_length.is_none()
        && event.http_host_sha256.is_none()
        && event.http_method_class.is_none()
}

fn require_nonempty_optional_digest_v1(
    value: Option<&Sha256Digest>,
) -> Result<(), LinuxVzPackageSensorPayloadErrorV1> {
    if value.is_some_and(|digest| digest == &Sha256Digest::from_bytes(&[])) {
        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
    }
    Ok(())
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzPackageSensorPayloadErrorV1> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageSensorPayloadErrorV1::InvalidEvent)
}

fn optional_decimal_u64_v1(
    value: Option<&str>,
) -> Result<Option<u64>, LinuxVzPackageSensorPayloadErrorV1> {
    value.map(decimal_u64_v1).transpose()
}

fn decimal_u32_v1(value: &str) -> Result<u32, LinuxVzPackageSensorPayloadErrorV1> {
    let value = decimal_u64_v1(value)?;
    u32::try_from(value).map_err(|_| LinuxVzPackageSensorPayloadErrorV1::InvalidEvent)
}

fn decimal_u16_v1(value: &str) -> Result<u16, LinuxVzPackageSensorPayloadErrorV1> {
    let value = decimal_u64_v1(value)?;
    u16::try_from(value).map_err(|_| LinuxVzPackageSensorPayloadErrorV1::InvalidEvent)
}

fn decimal_usize_v1(value: &str) -> Result<usize, LinuxVzPackageSensorPayloadErrorV1> {
    let value = decimal_u64_v1(value)?;
    usize::try_from(value).map_err(|_| LinuxVzPackageSensorPayloadErrorV1::InvalidEvent)
}

fn optional_u8_v1(
    value: Option<&str>,
    zero_permitted: bool,
) -> Result<Option<u8>, LinuxVzPackageSensorPayloadErrorV1> {
    value
        .map(|value| {
            let value = decimal_u64_v1(value)?;
            if value > u8::MAX as u64 || (!zero_permitted && !(1..=64).contains(&value)) {
                return Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent);
            }
            Ok(value as u8)
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_linux_vz_package_process_sensor_correlation_v1,
        derive_linux_vz_package_process_launch_contract_v1,
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        LinuxVzPackageExpectedProcessSensorCorrelationV1, LinuxVzPackageProcessCompletionV1,
        LinuxVzPackageProcessTerminalV1, MacosLinuxVzNpmLifecyclePolicyV1,
        MacosLinuxVzPackageDependencyPolicyV1, MacosLinuxVzPackageExecutionStageV1,
        MacosLinuxVzPackageRuntimeExecutablesV1, ValidatedLinuxVzPackageDynamicProcessBindingsV1,
        LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V2,
    };
    use serde_json::{json, Value};
    use whoathere_detonation::NpmEnvironmentProfileV1;

    fn contract_v1() -> crate::LinuxVzPackageProcessLaunchContractV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::NodeNpm {
                node_version: "24.4.0".to_string(),
                node_executable_sha256: Sha256Digest::from_bytes(b"inert node"),
                npm_version: "11.4.2".to_string(),
                npm_cli_sha256: Sha256Digest::from_bytes(b"inert npm cli"),
            },
            "npm_install_exact_local_tarball",
            vec![
                MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
                    environment: NpmEnvironmentProfileV1::CiTrue,
                    input_basename: "package.tgz".to_string(),
                    dependency_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::OfflineExactDependencyFree,
                    lifecycle_policy:
                        MacosLinuxVzNpmLifecyclePolicyV1::PackageManifestInstallHooksOnly,
                },
            ],
        );
        let plan = derive_macos_linux_vz_package_execution_process_plan_v1(&program)
            .expect("process plan");
        derive_linux_vz_package_process_launch_contract_v1(
            &plan,
            1,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("launch contract")
    }

    fn binding_v1(
        contract: &crate::LinuxVzPackageProcessLaunchContractV1,
        challenge: &Sha256Digest,
    ) -> Value {
        json!({
            "action_index": contract.action_index().to_string(),
            "cgroup_id": "9001",
            "cgroup_name": "whoathere-package-action-1",
            "launch_contract_sha256": contract.launch_contract_sha256(),
            "leader_pid": "42",
            "package_gid": "65534",
            "package_uid": "65534",
            "process_plan_sha256": contract.process_plan_sha256(),
            "sensor_session_challenge_sha256": challenge,
        })
    }

    fn coverage_v1(event_count: usize) -> Value {
        json!({
            "dropped_event_count": "0",
            "event_count": event_count.to_string(),
            "evidence_truncated": false,
            "heartbeat_count": "2",
            "sensor_healthy": true,
        })
    }

    fn process_payload_value_v1(
        contract: &crate::LinuxVzPackageProcessLaunchContractV1,
        challenge: &Sha256Digest,
        exit_sequence: u64,
    ) -> Value {
        json!({
            "binding": binding_v1(contract, challenge),
            "coverage": coverage_v1(3),
            "descendant_teardown_complete": true,
            "events": [
                {
                    "actor_pid": "100",
                    "cgroup_id": "9001",
                    "kind": "fork",
                    "parent_pid": "100",
                    "sequence": "1",
                    "subject_pid": "42",
                    "timestamp_monotonic_nanoseconds": "210",
                },
                {
                    "actor_pid": "42",
                    "argv_item_count": "3",
                    "argv_sha256": Sha256Digest::from_bytes(b"bounded argv projection"),
                    "cgroup_id": "9001",
                    "executable_sha256": Sha256Digest::from_bytes(b"measured executable"),
                    "kind": "exec",
                    "parent_pid": "100",
                    "sequence": "2",
                    "subject_pid": "42",
                    "timestamp_monotonic_nanoseconds": "220",
                },
                {
                    "actor_pid": "42",
                    "cgroup_id": "9001",
                    "exit_status": "0",
                    "kind": "exit",
                    "parent_pid": "100",
                    "sequence": exit_sequence.to_string(),
                    "subject_pid": "42",
                    "timestamp_monotonic_nanoseconds": "280",
                },
            ],
            "raw_argv_captured": false,
            "schema_version": LINUX_VZ_PACKAGE_PROCESS_EVIDENCE_PAYLOAD_SCHEMA_V1,
        })
    }

    fn file_payload_value_v1(
        contract: &crate::LinuxVzPackageProcessLaunchContractV1,
        challenge: &Sha256Digest,
        sequence: u64,
    ) -> Value {
        json!({
            "binding": binding_v1(contract, challenge),
            "coverage": coverage_v1(1),
            "events": [{
                "access_outcome": "no_change",
                "actor_pid": "42",
                "byte_count": "0",
                "cgroup_id": "9001",
                "kind": "filesystem_diff",
                "path_class": "workspace",
                "path_token_sha256": Sha256Digest::from_bytes(b"scenario-bound workspace token"),
                "sequence": sequence.to_string(),
                "timestamp_monotonic_nanoseconds": "320",
            }],
            "filesystem_diff_complete": true,
            "raw_paths_captured": false,
            "schema_version": LINUX_VZ_PACKAGE_FILE_EVIDENCE_PAYLOAD_SCHEMA_V1,
        })
    }

    fn network_payload_value_v1(
        contract: &crate::LinuxVzPackageProcessLaunchContractV1,
        challenge: &Sha256Digest,
    ) -> Value {
        json!({
            "binding": binding_v1(contract, challenge),
            "controlled_sinkhole_only": true,
            "coverage": coverage_v1(0),
            "events": [],
            "public_network_route_present": false,
            "raw_addresses_captured": false,
            "raw_dns_names_captured": false,
            "raw_http_hosts_captured": false,
            "schema_version": LINUX_VZ_PACKAGE_NETWORK_EVIDENCE_PAYLOAD_SCHEMA_V1,
        })
    }

    fn canonical_v1(value: &Value) -> Vec<u8> {
        serde_json_canonicalizer::to_vec(value).expect("canonical")
    }

    fn correlation_v1(
        contract: &crate::LinuxVzPackageProcessLaunchContractV1,
        challenge: &Sha256Digest,
        process: &[u8],
        file: &[u8],
        network: &[u8],
    ) -> LinuxVzPackageProcessSensorCorrelationV1 {
        correlation_with_counts_v1(contract, challenge, process, file, network, 3, 1, 0, 4)
    }

    #[allow(clippy::too_many_arguments)]
    fn correlation_with_counts_v1(
        contract: &crate::LinuxVzPackageProcessLaunchContractV1,
        challenge: &Sha256Digest,
        process: &[u8],
        file: &[u8],
        network: &[u8],
        process_event_count: u64,
        file_event_count: u64,
        network_event_count: u64,
        event_count: u64,
    ) -> LinuxVzPackageProcessSensorCorrelationV1 {
        let correlation = canonical_v1(&json!({
            "action_index": contract.action_index().to_string(),
            "cgroup_empty_after_reap": true,
            "cgroup_id": "9001",
            "cgroup_name": "whoathere-package-action-1",
            "cgroup_present_during_sensor_finalize": true,
            "descendant_teardown_complete": true,
            "dropped_event_count": "0",
            "event_count": event_count.to_string(),
            "event_sequence_end": event_count.to_string(),
            "event_sequence_start": "1",
            "evidence_truncated": false,
            "file_event_count": file_event_count.to_string(),
            "file_evidence_sha256": Sha256Digest::from_bytes(file),
            "file_sensor_healthy": true,
            "heartbeat_count": "2",
            "launch_contract_sha256": contract.launch_contract_sha256(),
            "leader_correlated_before_release": true,
            "leader_exit_status": "0",
            "leader_pid": "42",
            "leader_terminal": "exited",
            "network_event_count": network_event_count.to_string(),
            "network_evidence_sha256": Sha256Digest::from_bytes(network),
            "network_sensor_healthy": true,
            "package_gid": "65534",
            "package_uid": "65534",
            "process_ended_monotonic_nanoseconds": "300",
            "process_event_count": process_event_count.to_string(),
            "process_evidence_sha256": Sha256Digest::from_bytes(process),
            "process_plan_sha256": contract.process_plan_sha256(),
            "process_sensor_healthy": true,
            "process_started_monotonic_nanoseconds": "200",
            "public_network_route_present": false,
            "schema_version": LINUX_VZ_PACKAGE_PROCESS_SENSOR_CORRELATION_SCHEMA_V2,
            "sensor_ended_monotonic_nanoseconds": "400",
            "sensor_session_challenge_sha256": challenge,
            "sensor_started_monotonic_nanoseconds": "100",
            "sensor_teardown_complete": true,
            "sync_back": false,
        }));
        decode_linux_vz_package_process_sensor_correlation_v1(
            &correlation,
            LinuxVzPackageExpectedProcessSensorCorrelationV1 {
                sensor_session_challenge_sha256: challenge,
                contract,
                cgroup_name: "whoathere-package-action-1",
                leader_pid: 42,
                completion: LinuxVzPackageProcessCompletionV1::from_parts_v1(
                    200,
                    300,
                    LinuxVzPackageProcessTerminalV1::Exited,
                    Some(0),
                    None,
                )
                .expect("completion"),
            },
        )
        .expect("correlation")
    }

    #[test]
    fn exact_bound_payload_set_requires_complete_cross_stream_sequence() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh sensor challenge");
        let process = canonical_v1(&process_payload_value_v1(&contract, &challenge, 3));
        let file = canonical_v1(&file_payload_value_v1(&contract, &challenge, 4));
        let network = canonical_v1(&network_payload_value_v1(&contract, &challenge));
        let correlation = correlation_v1(&contract, &challenge, &process, &file, &network);
        let payloads = decode_linux_vz_package_protected_sensor_payload_set_v1(
            &correlation,
            &process,
            &file,
            &network,
        )
        .expect("payload set");
        assert_eq!(payloads.process().events().len(), 3);
        assert_eq!(payloads.file().events().len(), 1);
        assert!(payloads.network().events().is_empty());
        assert!(payloads.coverage_complete());
        assert!(!payloads.sync_back_permitted());
        assert_ne!(
            payloads.payload_set_sha256(),
            &Sha256Digest::from_bytes(&[])
        );
    }

    #[test]
    fn stale_binding_raw_capture_and_missing_lifecycle_fail_closed() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh sensor challenge");
        let exact_process = process_payload_value_v1(&contract, &challenge, 3);
        let file_value = file_payload_value_v1(&contract, &challenge, 4);
        let network_value = network_payload_value_v1(&contract, &challenge);
        let exact_process_bytes = canonical_v1(&exact_process);
        let file = canonical_v1(&file_value);
        let network = canonical_v1(&network_value);
        let correlation =
            correlation_v1(&contract, &challenge, &exact_process_bytes, &file, &network);

        let mut stale = exact_process.clone();
        stale["binding"]["sensor_session_challenge_sha256"] =
            json!(Sha256Digest::from_bytes(b"stale"));
        assert_eq!(
            decode_process_payload_v1(&correlation, &canonical_v1(&stale)),
            Err(LinuxVzPackageSensorPayloadErrorV1::BindingMismatch)
        );

        let mut raw = exact_process.clone();
        raw["raw_argv_captured"] = json!(true);
        assert_eq!(
            decode_process_payload_v1(&correlation, &canonical_v1(&raw)),
            Err(LinuxVzPackageSensorPayloadErrorV1::InvalidCoverage)
        );

        let mut rebound_exit = exact_process.clone();
        rebound_exit["events"][2]["exit_status"] = json!("1");
        assert_eq!(
            decode_process_payload_v1(&correlation, &canonical_v1(&rebound_exit)),
            Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent)
        );

        let mut no_leader_exit = exact_process;
        no_leader_exit["events"][2]["subject_pid"] = json!("43");
        no_leader_exit["events"][2]["actor_pid"] = json!("43");
        assert_eq!(
            decode_process_payload_v1(&correlation, &canonical_v1(&no_leader_exit)),
            Err(LinuxVzPackageSensorPayloadErrorV1::IncompleteProcessLifecycle)
        );
    }

    #[test]
    fn gapped_global_sequence_and_untrusted_network_posture_fail_closed() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh sensor challenge");
        let process = canonical_v1(&process_payload_value_v1(&contract, &challenge, 3));
        let exact_file = file_payload_value_v1(&contract, &challenge, 4);
        let exact_network = network_payload_value_v1(&contract, &challenge);
        let file = canonical_v1(&exact_file);
        let network = canonical_v1(&exact_network);
        let correlation = correlation_v1(&contract, &challenge, &process, &file, &network);

        let gapped_file = canonical_v1(&file_payload_value_v1(&contract, &challenge, 5));
        assert_eq!(
            decode_linux_vz_package_protected_sensor_payload_set_v1(
                &correlation,
                &process,
                &gapped_file,
                &network,
            ),
            Err(LinuxVzPackageSensorPayloadErrorV1::GlobalSequenceInvalid)
        );

        let early_file = canonical_v1(&file_payload_value_v1(&contract, &challenge, 2));
        assert_eq!(
            decode_linux_vz_package_protected_sensor_payload_set_v1(
                &correlation,
                &process,
                &early_file,
                &network,
            ),
            Err(LinuxVzPackageSensorPayloadErrorV1::IncompleteFileDiff)
        );

        let mut public_route = exact_network;
        public_route["public_network_route_present"] = json!(true);
        assert_eq!(
            decode_network_payload_v1(&correlation, &canonical_v1(&public_route)),
            Err(LinuxVzPackageSensorPayloadErrorV1::InvalidCoverage)
        );

        let mut raw_path = exact_file;
        raw_path["raw_paths_captured"] = json!(true);
        assert_eq!(
            decode_file_payload_v1(&correlation, &canonical_v1(&raw_path)),
            Err(LinuxVzPackageSensorPayloadErrorV1::InvalidCoverage)
        );
    }

    #[test]
    fn dns_txt_intent_is_typed_without_raw_name_or_address_capture() {
        let contract = contract_v1();
        let challenge = Sha256Digest::from_bytes(b"fresh dns sensor challenge");
        let process = canonical_v1(&process_payload_value_v1(&contract, &challenge, 4));
        let file = canonical_v1(&file_payload_value_v1(&contract, &challenge, 5));
        let network_value = json!({
            "binding": binding_v1(&contract, &challenge),
            "controlled_sinkhole_only": true,
            "coverage": coverage_v1(1),
            "events": [{
                "actor_pid": "42",
                "byte_count": "96",
                "cgroup_id": "9001",
                "destination_class": "controlled_dns",
                "destination_sha256": Sha256Digest::from_bytes(b"scenario-bound resolver token"),
                "dns_label_count": "5",
                "dns_name_sha256": Sha256Digest::from_bytes(b"scenario-bound query-name token"),
                "dns_query_type": "txt",
                "dns_wire_length": "96",
                "family": "ipv4",
                "kind": "dns_query",
                "outcome": "sinkholed",
                "port": "53",
                "protocol": "udp",
                "sequence": "3",
                "timestamp_monotonic_nanoseconds": "240",
            }],
            "public_network_route_present": false,
            "raw_addresses_captured": false,
            "raw_dns_names_captured": false,
            "raw_http_hosts_captured": false,
            "schema_version": LINUX_VZ_PACKAGE_NETWORK_EVIDENCE_PAYLOAD_SCHEMA_V1,
        });
        let network = canonical_v1(&network_value);
        let correlation = correlation_with_counts_v1(
            &contract, &challenge, &process, &file, &network, 3, 1, 1, 5,
        );
        let payloads = decode_linux_vz_package_protected_sensor_payload_set_v1(
            &correlation,
            &process,
            &file,
            &network,
        )
        .expect("DNS payload set");
        let event = &payloads.network().events()[0];
        assert_eq!(event.kind(), LinuxVzPackageNetworkEventKindV1::DnsQuery);
        assert_eq!(
            event.destination_class(),
            LinuxVzPackageNetworkDestinationClassV1::ControlledDns
        );
        assert_eq!(event.outcome(), LinuxVzPackageNetworkOutcomeV1::Sinkholed);
        assert!(event.dns_name_sha256().is_some());
        assert_eq!(
            event.dns_query_type(),
            Some(LinuxVzPackageDnsQueryTypeV1::Txt)
        );
        assert_eq!(event.dns_label_count(), Some(5));
        assert_eq!(event.dns_wire_length(), Some(96));

        let mut invalid_query_type = network_value.clone();
        invalid_query_type["events"][0]["dns_query_type"] = json!("raw_unknown_value");
        assert_eq!(
            decode_network_payload_v1(&correlation, &canonical_v1(&invalid_query_type)),
            Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent)
        );

        let mut mismatched_wire_length = network_value;
        mismatched_wire_length["events"][0]["byte_count"] = json!("95");
        assert_eq!(
            decode_network_payload_v1(&correlation, &canonical_v1(&mismatched_wire_length)),
            Err(LinuxVzPackageSensorPayloadErrorV1::InvalidEvent)
        );
    }
}
