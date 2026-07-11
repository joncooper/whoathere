use crate::{
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    MacosLinuxVzTelemetryBackendErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    decode_artifact_protected_telemetry_requirements_v1, ArtifactProtectedTelemetryRequirementsV1,
    ArtifactProtectedTelemetrySensorV1, ArtifactTelemetryNetworkTopologyV1,
    ArtifactTelemetrySyncBackPolicyV1,
};

pub const MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_telemetry_conformance_run_spec.v1";
pub const MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_PROTOCOL_V1: &str =
    "whoathere.linux_vz_telemetry_conformance.v1";
pub const MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformanceFixtureV1 {
    PlatformCapabilities,
    ProcessLineage,
    FileCanary,
    NetworkIntent,
    DropAccounting,
    TeardownStress,
    SensorTamper,
    PackageIsolation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformanceCaseV1 {
    KernelConfigAndBtf,
    CgroupV2,
    FanotifyPermission,
    BpfProgramTypes,
    RawFrameAttachment,
    ForkExecExit,
    Reparenting,
    DoubleForkDaemonization,
    SetsidEscape,
    CredentialChange,
    DynamicLibraryLoad,
    ProtectedOpenReadWriteRenameDelete,
    MmapAccess,
    Ipv4Connect,
    Ipv6Connect,
    UdpSend,
    LoopbackConnect,
    PrivateAddressConnect,
    LinkLocalConnect,
    MetadataAddressConnect,
    PublicAddressConnect,
    DnsPlaintext,
    DnsMalformed,
    EncryptedDnsConnect,
    BpfReservationFailure,
    FanotifyQueueOverflow,
    HostFrameOverflow,
    NormalExit,
    Timeout,
    TermResistance,
    EscapedSession,
    ReparentedChild,
    BackgroundListener,
    ChannelInterruption,
    VmStop,
    GuestSensorDeath,
    HostSensorDeath,
    AllProtectedAssetsDenied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformanceExpectedTerminalV1 {
    ObservationComplete,
    IncompleteOnInjectedGap,
    TimeoutWithTeardown,
    InfrastructureErrorWithTeardown,
    AccessDeniedWithCompleteEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformanceExecutionPostureV1 {
    TrustedInertFixtureOnlyNoPackageCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformancePackageExecutionV1 {
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformanceClonePolicyV1 {
    OneBootOneFixtureDestroyClone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformanceExternalNetworkV1 {
    NoExternalRoute,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxVzTelemetryConformanceLimitsV1 {
    wall_clock_millis: String,
    max_guest_events: String,
    max_host_frames: String,
    max_evidence_bytes: String,
}

impl LinuxVzTelemetryConformanceLimitsV1 {
    fn fixed_v1() -> Self {
        Self {
            wall_clock_millis: "30000".to_string(),
            max_guest_events: "1000000".to_string(),
            max_host_frames: "65536".to_string(),
            max_evidence_bytes: (16 * 1024 * 1024_u64).to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxVzTelemetryConformanceRunSpecWireV1 {
    schema_version: String,
    canonicalization: String,
    conformance_run_id: String,
    evidence_id: String,
    fixture: LinuxVzTelemetryConformanceFixtureV1,
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    fixture_binary_sha256: Sha256Digest,
    expected_terminal: LinuxVzTelemetryConformanceExpectedTerminalV1,
    expected_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    telemetry_requirements: serde_json::Value,
    telemetry_requirements_sha256: Sha256Digest,
    backend_identity: serde_json::Value,
    backend_identity_sha256: Sha256Digest,
    execution_posture: LinuxVzTelemetryConformanceExecutionPostureV1,
    package_execution: LinuxVzTelemetryConformancePackageExecutionV1,
    network_topology: ArtifactTelemetryNetworkTopologyV1,
    external_network: LinuxVzTelemetryConformanceExternalNetworkV1,
    clone_policy: LinuxVzTelemetryConformanceClonePolicyV1,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
    limits: LinuxVzTelemetryConformanceLimitsV1,
    guest_protocol: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzTelemetryConformanceRunSpecV1 {
    canonical_json: Vec<u8>,
    run_spec_sha256: Sha256Digest,
    conformance_run_id: String,
    evidence_id: String,
    fixture: LinuxVzTelemetryConformanceFixtureV1,
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    fixture_binary_sha256: Sha256Digest,
    expected_terminal: LinuxVzTelemetryConformanceExpectedTerminalV1,
    expected_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    telemetry_requirements_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
}

impl fmt::Debug for MacosLinuxVzTelemetryConformanceRunSpecV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzTelemetryConformanceRunSpecV1")
            .field("run_spec_sha256", &self.run_spec_sha256)
            .field("conformance_run_id", &self.conformance_run_id)
            .field("evidence_id", &self.evidence_id)
            .field("fixture", &self.fixture)
            .field("fixture_case", &self.fixture_case)
            .field("fixture_binary_sha256", &self.fixture_binary_sha256)
            .field("expected_terminal", &self.expected_terminal)
            .field("expected_sensors", &self.expected_sensors)
            .field(
                "telemetry_requirements_sha256",
                &self.telemetry_requirements_sha256,
            )
            .field("backend_identity_sha256", &self.backend_identity_sha256)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosLinuxVzTelemetryConformanceRunSpecV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn run_spec_sha256(&self) -> &Sha256Digest {
        &self.run_spec_sha256
    }

    pub fn conformance_run_id(&self) -> &str {
        &self.conformance_run_id
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn fixture(&self) -> LinuxVzTelemetryConformanceFixtureV1 {
        self.fixture
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        self.fixture_case
    }

    pub fn fixture_binary_sha256(&self) -> &Sha256Digest {
        &self.fixture_binary_sha256
    }

    pub fn expected_terminal(&self) -> LinuxVzTelemetryConformanceExpectedTerminalV1 {
        self.expected_terminal
    }

    pub fn expected_sensors(&self) -> &[ArtifactProtectedTelemetrySensorV1] {
        &self.expected_sensors
    }

    pub fn telemetry_requirements_sha256(&self) -> &Sha256Digest {
        &self.telemetry_requirements_sha256
    }

    pub fn backend_identity_sha256(&self) -> &Sha256Digest {
        &self.backend_identity_sha256
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzTelemetryConformanceRunSpecErrorV1 {
    Empty,
    LimitExceeded,
    InvalidSchema,
    InvalidIdentity,
    InvalidFixture,
    RequirementsMismatch,
    Backend(MacosLinuxVzTelemetryBackendErrorV1),
    NonCanonical,
    Serialization,
}

impl MacosLinuxVzTelemetryConformanceRunSpecErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "macos_linux_vz_telemetry_conformance_run_spec_empty",
            Self::LimitExceeded => "macos_linux_vz_telemetry_conformance_run_spec_limit_exceeded",
            Self::InvalidSchema => "macos_linux_vz_telemetry_conformance_run_spec_schema_invalid",
            Self::InvalidIdentity => {
                "macos_linux_vz_telemetry_conformance_run_spec_identity_invalid"
            }
            Self::InvalidFixture => "macos_linux_vz_telemetry_conformance_run_spec_fixture_invalid",
            Self::RequirementsMismatch => {
                "macos_linux_vz_telemetry_conformance_requirements_mismatch"
            }
            Self::Backend(error) => error.reason_code(),
            Self::NonCanonical => "macos_linux_vz_telemetry_conformance_run_spec_noncanonical",
            Self::Serialization => {
                "macos_linux_vz_telemetry_conformance_run_spec_serialization_failed"
            }
        }
    }
}

impl fmt::Display for MacosLinuxVzTelemetryConformanceRunSpecErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzTelemetryConformanceRunSpecErrorV1 {}

pub fn compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
    conformance_run_id: impl Into<String>,
    evidence_id: impl Into<String>,
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    telemetry_requirements: &ArtifactProtectedTelemetryRequirementsV1,
    backend_identity: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<MacosLinuxVzTelemetryConformanceRunSpecV1, MacosLinuxVzTelemetryConformanceRunSpecErrorV1>
{
    let conformance_run_id = conformance_run_id.into();
    let evidence_id = evidence_id.into();
    if !valid_conformance_identity_v1(&conformance_run_id)
        || !valid_conformance_identity_v1(&evidence_id)
    {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidIdentity);
    }
    let requirements_bytes = telemetry_requirements
        .canonical_json_v1()
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::RequirementsMismatch)?;
    let telemetry_requirements_sha256 = Sha256Digest::from_bytes(&requirements_bytes);
    if backend_identity.telemetry_requirements_sha256() != &telemetry_requirements_sha256
        || backend_identity.execution_authority_permitted()
    {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::RequirementsMismatch);
    }
    let backend_bytes = backend_identity
        .canonical_json_v1()
        .map_err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Backend)?;
    let backend_identity_sha256 = Sha256Digest::from_bytes(&backend_bytes);
    let fixture = fixture_for_case_v1(fixture_case);
    let wire = LinuxVzTelemetryConformanceRunSpecWireV1 {
        schema_version: MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_SCHEMA_V1.to_string(),
        canonicalization: "rfc8785.jcs.v1".to_string(),
        conformance_run_id,
        evidence_id,
        fixture,
        fixture_case,
        fixture_binary_sha256: backend_identity.guest_runner_sha256().clone(),
        expected_terminal: expected_terminal_for_case_v1(fixture_case),
        expected_sensors: expected_fixture_sensors_v1(fixture),
        telemetry_requirements: serde_json::from_slice(&requirements_bytes)
            .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Serialization)?,
        telemetry_requirements_sha256,
        backend_identity: serde_json::from_slice(&backend_bytes)
            .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Serialization)?,
        backend_identity_sha256,
        execution_posture:
            LinuxVzTelemetryConformanceExecutionPostureV1::TrustedInertFixtureOnlyNoPackageCode,
        package_execution: LinuxVzTelemetryConformancePackageExecutionV1::Disabled,
        network_topology: ArtifactTelemetryNetworkTopologyV1::HostRawFrameSinkholeNoExternalRoute,
        external_network: LinuxVzTelemetryConformanceExternalNetworkV1::NoExternalRoute,
        clone_policy: LinuxVzTelemetryConformanceClonePolicyV1::OneBootOneFixtureDestroyClone,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
        limits: LinuxVzTelemetryConformanceLimitsV1::fixed_v1(),
        guest_protocol: MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_PROTOCOL_V1.to_string(),
    };
    validate_and_build_run_spec_v1(wire, Some(telemetry_requirements))
}

pub fn decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(
    bytes: &[u8],
) -> Result<MacosLinuxVzTelemetryConformanceRunSpecV1, MacosLinuxVzTelemetryConformanceRunSpecErrorV1>
{
    if bytes.is_empty() {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Empty);
    }
    if bytes.len() > MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = LinuxVzTelemetryConformanceRunSpecWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidSchema)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidSchema)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::NonCanonical);
    }
    validate_and_build_run_spec_v1(wire, None)
}

fn validate_and_build_run_spec_v1(
    wire: LinuxVzTelemetryConformanceRunSpecWireV1,
    expected_requirements: Option<&ArtifactProtectedTelemetryRequirementsV1>,
) -> Result<MacosLinuxVzTelemetryConformanceRunSpecV1, MacosLinuxVzTelemetryConformanceRunSpecErrorV1>
{
    if wire.schema_version != MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_SCHEMA_V1
        || wire.canonicalization != "rfc8785.jcs.v1"
        || wire.execution_posture
            != LinuxVzTelemetryConformanceExecutionPostureV1::TrustedInertFixtureOnlyNoPackageCode
        || wire.package_execution != LinuxVzTelemetryConformancePackageExecutionV1::Disabled
        || wire.network_topology
            != ArtifactTelemetryNetworkTopologyV1::HostRawFrameSinkholeNoExternalRoute
        || wire.external_network != LinuxVzTelemetryConformanceExternalNetworkV1::NoExternalRoute
        || wire.clone_policy
            != LinuxVzTelemetryConformanceClonePolicyV1::OneBootOneFixtureDestroyClone
        || wire.sync_back_policy != ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent
        || wire.limits != LinuxVzTelemetryConformanceLimitsV1::fixed_v1()
        || wire.guest_protocol != MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_PROTOCOL_V1
    {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidSchema);
    }
    if !valid_conformance_identity_v1(&wire.conformance_run_id)
        || !valid_conformance_identity_v1(&wire.evidence_id)
    {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidIdentity);
    }
    if wire.fixture != fixture_for_case_v1(wire.fixture_case)
        || wire.expected_terminal != expected_terminal_for_case_v1(wire.fixture_case)
        || wire.expected_sensors != expected_fixture_sensors_v1(wire.fixture)
    {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidFixture);
    }
    let requirements_bytes = serde_json_canonicalizer::to_vec(&wire.telemetry_requirements)
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Serialization)?;
    let requirements = decode_artifact_protected_telemetry_requirements_v1(&requirements_bytes)
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::RequirementsMismatch)?;
    let requirements_sha256 = Sha256Digest::from_bytes(&requirements_bytes);
    if wire.telemetry_requirements_sha256 != requirements_sha256
        || expected_requirements.is_some_and(|expected| expected != &requirements)
    {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::RequirementsMismatch);
    }
    let backend_bytes = serde_json_canonicalizer::to_vec(&wire.backend_identity)
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Serialization)?;
    let backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &backend_bytes,
        &requirements,
    )
    .map_err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Backend)?;
    let backend_sha256 = Sha256Digest::from_bytes(&backend_bytes);
    if wire.backend_identity_sha256 != backend_sha256
        || wire.fixture_binary_sha256 != *backend.guest_runner_sha256()
        || backend.execution_authority_permitted()
    {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::RequirementsMismatch);
    }
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzTelemetryConformanceRunSpecErrorV1::Serialization)?;
    if canonical_json.len() > MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzTelemetryConformanceRunSpecV1 {
        run_spec_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        conformance_run_id: wire.conformance_run_id,
        evidence_id: wire.evidence_id,
        fixture: wire.fixture,
        fixture_case: wire.fixture_case,
        fixture_binary_sha256: wire.fixture_binary_sha256,
        expected_terminal: wire.expected_terminal,
        expected_sensors: wire.expected_sensors,
        telemetry_requirements_sha256: wire.telemetry_requirements_sha256,
        backend_identity_sha256: wire.backend_identity_sha256,
    })
}

pub const ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1: [LinuxVzTelemetryConformanceCaseV1; 38] = [
    LinuxVzTelemetryConformanceCaseV1::KernelConfigAndBtf,
    LinuxVzTelemetryConformanceCaseV1::CgroupV2,
    LinuxVzTelemetryConformanceCaseV1::FanotifyPermission,
    LinuxVzTelemetryConformanceCaseV1::BpfProgramTypes,
    LinuxVzTelemetryConformanceCaseV1::RawFrameAttachment,
    LinuxVzTelemetryConformanceCaseV1::ForkExecExit,
    LinuxVzTelemetryConformanceCaseV1::Reparenting,
    LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization,
    LinuxVzTelemetryConformanceCaseV1::SetsidEscape,
    LinuxVzTelemetryConformanceCaseV1::CredentialChange,
    LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad,
    LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete,
    LinuxVzTelemetryConformanceCaseV1::MmapAccess,
    LinuxVzTelemetryConformanceCaseV1::Ipv4Connect,
    LinuxVzTelemetryConformanceCaseV1::Ipv6Connect,
    LinuxVzTelemetryConformanceCaseV1::UdpSend,
    LinuxVzTelemetryConformanceCaseV1::LoopbackConnect,
    LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect,
    LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect,
    LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect,
    LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect,
    LinuxVzTelemetryConformanceCaseV1::DnsPlaintext,
    LinuxVzTelemetryConformanceCaseV1::DnsMalformed,
    LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect,
    LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure,
    LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow,
    LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow,
    LinuxVzTelemetryConformanceCaseV1::NormalExit,
    LinuxVzTelemetryConformanceCaseV1::Timeout,
    LinuxVzTelemetryConformanceCaseV1::TermResistance,
    LinuxVzTelemetryConformanceCaseV1::EscapedSession,
    LinuxVzTelemetryConformanceCaseV1::ReparentedChild,
    LinuxVzTelemetryConformanceCaseV1::BackgroundListener,
    LinuxVzTelemetryConformanceCaseV1::ChannelInterruption,
    LinuxVzTelemetryConformanceCaseV1::VmStop,
    LinuxVzTelemetryConformanceCaseV1::GuestSensorDeath,
    LinuxVzTelemetryConformanceCaseV1::HostSensorDeath,
    LinuxVzTelemetryConformanceCaseV1::AllProtectedAssetsDenied,
];

pub const fn fixture_for_case_v1(
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
) -> LinuxVzTelemetryConformanceFixtureV1 {
    use LinuxVzTelemetryConformanceCaseV1 as Case;
    match fixture_case {
        Case::KernelConfigAndBtf
        | Case::CgroupV2
        | Case::FanotifyPermission
        | Case::BpfProgramTypes
        | Case::RawFrameAttachment => LinuxVzTelemetryConformanceFixtureV1::PlatformCapabilities,
        Case::ForkExecExit
        | Case::Reparenting
        | Case::DoubleForkDaemonization
        | Case::SetsidEscape
        | Case::CredentialChange
        | Case::DynamicLibraryLoad => LinuxVzTelemetryConformanceFixtureV1::ProcessLineage,
        Case::ProtectedOpenReadWriteRenameDelete | Case::MmapAccess => {
            LinuxVzTelemetryConformanceFixtureV1::FileCanary
        }
        Case::Ipv4Connect
        | Case::Ipv6Connect
        | Case::UdpSend
        | Case::LoopbackConnect
        | Case::PrivateAddressConnect
        | Case::LinkLocalConnect
        | Case::MetadataAddressConnect
        | Case::PublicAddressConnect
        | Case::DnsPlaintext
        | Case::DnsMalformed
        | Case::EncryptedDnsConnect => LinuxVzTelemetryConformanceFixtureV1::NetworkIntent,
        Case::BpfReservationFailure | Case::FanotifyQueueOverflow | Case::HostFrameOverflow => {
            LinuxVzTelemetryConformanceFixtureV1::DropAccounting
        }
        Case::NormalExit
        | Case::Timeout
        | Case::TermResistance
        | Case::EscapedSession
        | Case::ReparentedChild
        | Case::BackgroundListener
        | Case::ChannelInterruption
        | Case::VmStop => LinuxVzTelemetryConformanceFixtureV1::TeardownStress,
        Case::GuestSensorDeath | Case::HostSensorDeath => {
            LinuxVzTelemetryConformanceFixtureV1::SensorTamper
        }
        Case::AllProtectedAssetsDenied => LinuxVzTelemetryConformanceFixtureV1::PackageIsolation,
    }
}

pub const fn expected_terminal_for_case_v1(
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
) -> LinuxVzTelemetryConformanceExpectedTerminalV1 {
    use LinuxVzTelemetryConformanceCaseV1 as Case;
    match fixture_case {
        Case::BpfReservationFailure | Case::FanotifyQueueOverflow | Case::HostFrameOverflow => {
            LinuxVzTelemetryConformanceExpectedTerminalV1::IncompleteOnInjectedGap
        }
        Case::Timeout
        | Case::TermResistance
        | Case::EscapedSession
        | Case::ReparentedChild
        | Case::BackgroundListener => {
            LinuxVzTelemetryConformanceExpectedTerminalV1::TimeoutWithTeardown
        }
        Case::ChannelInterruption
        | Case::VmStop
        | Case::GuestSensorDeath
        | Case::HostSensorDeath => {
            LinuxVzTelemetryConformanceExpectedTerminalV1::InfrastructureErrorWithTeardown
        }
        Case::AllProtectedAssetsDenied => {
            LinuxVzTelemetryConformanceExpectedTerminalV1::AccessDeniedWithCompleteEvidence
        }
        _ => LinuxVzTelemetryConformanceExpectedTerminalV1::ObservationComplete,
    }
}

fn expected_fixture_sensors_v1(
    fixture: LinuxVzTelemetryConformanceFixtureV1,
) -> Vec<ArtifactProtectedTelemetrySensorV1> {
    use ArtifactProtectedTelemetrySensorV1 as Sensor;
    match fixture {
        LinuxVzTelemetryConformanceFixtureV1::PlatformCapabilities => vec![
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
            Sensor::VmCloneLifecycle,
        ],
        LinuxVzTelemetryConformanceFixtureV1::ProcessLineage => vec![
            Sensor::ProcessForkExecExit,
            Sensor::ProcessCredentials,
            Sensor::DynamicLibraryLoad,
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
        ],
        LinuxVzTelemetryConformanceFixtureV1::FileCanary => vec![
            Sensor::FileOpenReadWrite,
            Sensor::FileMmap,
            Sensor::PersistenceWrites,
            Sensor::FileSystemDiff,
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
        ],
        LinuxVzTelemetryConformanceFixtureV1::NetworkIntent => vec![
            Sensor::GuestNetworkIntent,
            Sensor::HostRawFrames,
            Sensor::DnsSinkhole,
            Sensor::HttpSinkhole,
            Sensor::ProcessListenerDiff,
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
        ],
        LinuxVzTelemetryConformanceFixtureV1::DropAccounting => vec![
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
        ],
        LinuxVzTelemetryConformanceFixtureV1::TeardownStress => vec![
            Sensor::ProcessForkExecExit,
            Sensor::ProcessListenerDiff,
            Sensor::DescendantTeardown,
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
            Sensor::VmCloneLifecycle,
        ],
        LinuxVzTelemetryConformanceFixtureV1::SensorTamper => vec![
            Sensor::ProcessCredentials,
            Sensor::FileOpenReadWrite,
            Sensor::HostRawFrames,
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
            Sensor::VmCloneLifecycle,
        ],
        LinuxVzTelemetryConformanceFixtureV1::PackageIsolation => vec![
            Sensor::ProcessCredentials,
            Sensor::FileOpenReadWrite,
            Sensor::SensorHealthHeartbeat,
            Sensor::DroppedEventAccounting,
            Sensor::VmCloneLifecycle,
        ],
    }
}

fn valid_conformance_identity_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
