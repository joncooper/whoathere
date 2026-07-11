use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_SCHEMA_V1: &str =
    "whoathere.artifact_protected_telemetry_requirements.v1";
pub const MAX_ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactProtectedTelemetrySensorV1 {
    ProcessForkExecExit,
    ProcessCredentials,
    DynamicLibraryLoad,
    FileOpenReadWrite,
    FileMmap,
    PersistenceWrites,
    GuestNetworkIntent,
    HostRawFrames,
    DnsSinkhole,
    HttpSinkhole,
    ProcessListenerDiff,
    FileSystemDiff,
    DescendantTeardown,
    SensorHealthHeartbeat,
    DroppedEventAccounting,
    VmCloneLifecycle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryBackendClassV1 {
    LinuxVzBulk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryNetworkTopologyV1 {
    HostRawFrameSinkholeNoExternalRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryDropPolicyV1 {
    IncompleteOnAnyGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryProcessAttributionV1 {
    CgroupAndKernelLineage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryFileObservationV1 {
    FanotifyPermissionPlusBpfMmap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryEvidenceAuthorityV1 {
    GuestSignedAndHostCorroborated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryPackagePrivilegeV1 {
    DedicatedUidGidNoCapabilities,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetryScenarioReuseV1 {
    OneBootOneScenarioDestroyClone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTelemetrySyncBackPolicyV1 {
    StructurallyAbsent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactProtectedTelemetryRequirementsV1 {
    schema_version: String,
    backend_class: ArtifactTelemetryBackendClassV1,
    required_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    network_topology: ArtifactTelemetryNetworkTopologyV1,
    drop_policy: ArtifactTelemetryDropPolicyV1,
    process_attribution: ArtifactTelemetryProcessAttributionV1,
    file_observation: ArtifactTelemetryFileObservationV1,
    evidence_authority: ArtifactTelemetryEvidenceAuthorityV1,
    package_privilege: ArtifactTelemetryPackagePrivilegeV1,
    scenario_reuse: ArtifactTelemetryScenarioReuseV1,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
    limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactProtectedTelemetryRequirementsErrorV1 {
    Empty,
    LimitExceeded,
    InvalidSchema,
    InvalidPolicy,
    NonCanonical,
    Serialization,
}

impl ArtifactProtectedTelemetryRequirementsErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "artifact_protected_telemetry_requirements_empty",
            Self::LimitExceeded => "artifact_protected_telemetry_requirements_limit_exceeded",
            Self::InvalidSchema => "artifact_protected_telemetry_requirements_schema_invalid",
            Self::InvalidPolicy => "artifact_protected_telemetry_requirements_policy_invalid",
            Self::NonCanonical => "artifact_protected_telemetry_requirements_noncanonical",
            Self::Serialization => "artifact_protected_telemetry_requirements_serialization_failed",
        }
    }
}

impl fmt::Display for ArtifactProtectedTelemetryRequirementsErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ArtifactProtectedTelemetryRequirementsErrorV1 {}

impl ArtifactProtectedTelemetryRequirementsV1 {
    pub fn linux_vz_bulk_v1() -> Self {
        Self {
            schema_version: ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_SCHEMA_V1.to_string(),
            backend_class: ArtifactTelemetryBackendClassV1::LinuxVzBulk,
            required_sensors: required_linux_vz_bulk_sensors_v1(),
            network_topology:
                ArtifactTelemetryNetworkTopologyV1::HostRawFrameSinkholeNoExternalRoute,
            drop_policy: ArtifactTelemetryDropPolicyV1::IncompleteOnAnyGap,
            process_attribution: ArtifactTelemetryProcessAttributionV1::CgroupAndKernelLineage,
            file_observation: ArtifactTelemetryFileObservationV1::FanotifyPermissionPlusBpfMmap,
            evidence_authority:
                ArtifactTelemetryEvidenceAuthorityV1::GuestSignedAndHostCorroborated,
            package_privilege: ArtifactTelemetryPackagePrivilegeV1::DedicatedUidGidNoCapabilities,
            scenario_reuse: ArtifactTelemetryScenarioReuseV1::OneBootOneScenarioDestroyClone,
            sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
            limitations: required_linux_vz_bulk_limitations_v1(),
        }
    }

    pub fn backend_class(&self) -> ArtifactTelemetryBackendClassV1 {
        self.backend_class
    }

    pub fn required_sensors(&self) -> &[ArtifactProtectedTelemetrySensorV1] {
        &self.required_sensors
    }

    pub fn network_topology(&self) -> ArtifactTelemetryNetworkTopologyV1 {
        self.network_topology
    }

    pub fn drop_policy(&self) -> ArtifactTelemetryDropPolicyV1 {
        self.drop_policy
    }

    pub fn sync_back_policy(&self) -> ArtifactTelemetrySyncBackPolicyV1 {
        self.sync_back_policy
    }

    pub fn limitations(&self) -> &[String] {
        &self.limitations
    }

    pub fn canonical_json_v1(
        &self,
    ) -> Result<Vec<u8>, ArtifactProtectedTelemetryRequirementsErrorV1> {
        self.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(self)
            .map_err(|_| ArtifactProtectedTelemetryRequirementsErrorV1::Serialization)?;
        if bytes.len() > MAX_ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_BYTES_V1 {
            return Err(ArtifactProtectedTelemetryRequirementsErrorV1::LimitExceeded);
        }
        Ok(bytes)
    }

    pub fn requirements_sha256_v1(
        &self,
    ) -> Result<Sha256Digest, ArtifactProtectedTelemetryRequirementsErrorV1> {
        Ok(Sha256Digest::from_bytes(&self.canonical_json_v1()?))
    }

    fn validate(&self) -> Result<(), ArtifactProtectedTelemetryRequirementsErrorV1> {
        if self.schema_version != ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_SCHEMA_V1 {
            return Err(ArtifactProtectedTelemetryRequirementsErrorV1::InvalidSchema);
        }
        if self.backend_class != ArtifactTelemetryBackendClassV1::LinuxVzBulk
            || self.required_sensors != required_linux_vz_bulk_sensors_v1()
            || self.network_topology
                != ArtifactTelemetryNetworkTopologyV1::HostRawFrameSinkholeNoExternalRoute
            || self.drop_policy != ArtifactTelemetryDropPolicyV1::IncompleteOnAnyGap
            || self.process_attribution
                != ArtifactTelemetryProcessAttributionV1::CgroupAndKernelLineage
            || self.file_observation
                != ArtifactTelemetryFileObservationV1::FanotifyPermissionPlusBpfMmap
            || self.evidence_authority
                != ArtifactTelemetryEvidenceAuthorityV1::GuestSignedAndHostCorroborated
            || self.package_privilege
                != ArtifactTelemetryPackagePrivilegeV1::DedicatedUidGidNoCapabilities
            || self.scenario_reuse
                != ArtifactTelemetryScenarioReuseV1::OneBootOneScenarioDestroyClone
            || self.sync_back_policy != ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent
            || self.limitations != required_linux_vz_bulk_limitations_v1()
        {
            return Err(ArtifactProtectedTelemetryRequirementsErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}

pub fn decode_artifact_protected_telemetry_requirements_v1(
    bytes: &[u8],
) -> Result<ArtifactProtectedTelemetryRequirementsV1, ArtifactProtectedTelemetryRequirementsErrorV1>
{
    if bytes.is_empty() {
        return Err(ArtifactProtectedTelemetryRequirementsErrorV1::Empty);
    }
    if bytes.len() > MAX_ARTIFACT_PROTECTED_TELEMETRY_REQUIREMENTS_BYTES_V1 {
        return Err(ArtifactProtectedTelemetryRequirementsErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = ArtifactProtectedTelemetryRequirementsV1::deserialize(&mut deserializer)
        .map_err(|_| ArtifactProtectedTelemetryRequirementsErrorV1::InvalidPolicy)?;
    deserializer
        .end()
        .map_err(|_| ArtifactProtectedTelemetryRequirementsErrorV1::InvalidPolicy)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| ArtifactProtectedTelemetryRequirementsErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(ArtifactProtectedTelemetryRequirementsErrorV1::NonCanonical);
    }
    value.validate()?;
    Ok(value)
}

fn required_linux_vz_bulk_sensors_v1() -> Vec<ArtifactProtectedTelemetrySensorV1> {
    use ArtifactProtectedTelemetrySensorV1 as Sensor;
    vec![
        Sensor::ProcessForkExecExit,
        Sensor::ProcessCredentials,
        Sensor::DynamicLibraryLoad,
        Sensor::FileOpenReadWrite,
        Sensor::FileMmap,
        Sensor::PersistenceWrites,
        Sensor::GuestNetworkIntent,
        Sensor::HostRawFrames,
        Sensor::DnsSinkhole,
        Sensor::HttpSinkhole,
        Sensor::ProcessListenerDiff,
        Sensor::FileSystemDiff,
        Sensor::DescendantTeardown,
        Sensor::SensorHealthHeartbeat,
        Sensor::DroppedEventAccounting,
        Sensor::VmCloneLifecycle,
    ]
}

fn required_linux_vz_bulk_limitations_v1() -> Vec<String> {
    vec![
        "encrypted_payload_content_not_decrypted".to_string(),
        "fanotify_mmap_requires_bpf_corroboration".to_string(),
        "guest_kernel_compromise_can_suppress_guest_sensors_host_frames_remain".to_string(),
    ]
}
