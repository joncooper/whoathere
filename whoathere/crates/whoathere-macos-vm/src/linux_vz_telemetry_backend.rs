use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;

pub const MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_telemetry_backend_identity.v1";
pub const MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzTelemetryQualificationStateV1 {
    CandidateUnqualified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzTelemetryBackendErrorV1 {
    Empty,
    LimitExceeded,
    InvalidSchema,
    InvalidIdentity,
    RequirementsMismatch,
    NonCanonical,
    Serialization,
    TelemetryConformanceMissing,
}

impl MacosLinuxVzTelemetryBackendErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "macos_linux_vz_telemetry_backend_empty",
            Self::LimitExceeded => "macos_linux_vz_telemetry_backend_limit_exceeded",
            Self::InvalidSchema => "macos_linux_vz_telemetry_backend_schema_invalid",
            Self::InvalidIdentity => "macos_linux_vz_telemetry_backend_identity_invalid",
            Self::RequirementsMismatch => "macos_linux_vz_telemetry_requirements_mismatch",
            Self::NonCanonical => "macos_linux_vz_telemetry_backend_noncanonical",
            Self::Serialization => "macos_linux_vz_telemetry_backend_serialization_failed",
            Self::TelemetryConformanceMissing => "macos_linux_vz_telemetry_conformance_missing",
        }
    }
}

impl fmt::Display for MacosLinuxVzTelemetryBackendErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzTelemetryBackendErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1 {
    schema_version: String,
    qualification_state: MacosLinuxVzTelemetryQualificationStateV1,
    base_generation_id: String,
    linux_distribution_id: String,
    kernel_release: String,
    kernel_image_sha256: Sha256Digest,
    initramfs_sha256: Sha256Digest,
    root_disk_sha256: Sha256Digest,
    kernel_config_sha256: Sha256Digest,
    btf_sha256: Sha256Digest,
    guest_runner_sha256: Sha256Digest,
    guest_sensor_sha256: Sha256Digest,
    guest_bpf_bundle_sha256: Sha256Digest,
    guest_sensor_configuration_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_helper_sha256: Sha256Digest,
    host_packet_sensor_sha256: Sha256Digest,
    host_packet_sensor_configuration_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    package_uid: String,
    package_gid: String,
}

impl UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_generation_id: impl Into<String>,
        linux_distribution_id: impl Into<String>,
        kernel_release: impl Into<String>,
        kernel_image_sha256: Sha256Digest,
        initramfs_sha256: Sha256Digest,
        root_disk_sha256: Sha256Digest,
        kernel_config_sha256: Sha256Digest,
        btf_sha256: Sha256Digest,
        guest_runner_sha256: Sha256Digest,
        guest_sensor_sha256: Sha256Digest,
        guest_bpf_bundle_sha256: Sha256Digest,
        guest_sensor_configuration_sha256: Sha256Digest,
        guest_evidence_public_key_sha256: Sha256Digest,
        host_helper_sha256: Sha256Digest,
        host_packet_sensor_sha256: Sha256Digest,
        host_packet_sensor_configuration_sha256: Sha256Digest,
        host_evidence_public_key_sha256: Sha256Digest,
        telemetry_requirements: &ArtifactProtectedTelemetryRequirementsV1,
        package_uid: u32,
        package_gid: u32,
    ) -> Result<Self, MacosLinuxVzTelemetryBackendErrorV1> {
        let value = Self {
            schema_version: MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_SCHEMA_V1.to_string(),
            qualification_state: MacosLinuxVzTelemetryQualificationStateV1::CandidateUnqualified,
            base_generation_id: base_generation_id.into(),
            linux_distribution_id: linux_distribution_id.into(),
            kernel_release: kernel_release.into(),
            kernel_image_sha256,
            initramfs_sha256,
            root_disk_sha256,
            kernel_config_sha256,
            btf_sha256,
            guest_runner_sha256,
            guest_sensor_sha256,
            guest_bpf_bundle_sha256,
            guest_sensor_configuration_sha256,
            guest_evidence_public_key_sha256,
            host_helper_sha256,
            host_packet_sensor_sha256,
            host_packet_sensor_configuration_sha256,
            host_evidence_public_key_sha256,
            telemetry_requirements_sha256: telemetry_requirements
                .requirements_sha256_v1()
                .map_err(|_| MacosLinuxVzTelemetryBackendErrorV1::RequirementsMismatch)?,
            package_uid: package_uid.to_string(),
            package_gid: package_gid.to_string(),
        };
        value.validate(Some(telemetry_requirements))?;
        Ok(value)
    }

    pub fn qualification_state(&self) -> MacosLinuxVzTelemetryQualificationStateV1 {
        self.qualification_state
    }

    pub fn base_generation_id(&self) -> &str {
        &self.base_generation_id
    }

    pub fn linux_distribution_id(&self) -> &str {
        &self.linux_distribution_id
    }

    pub fn kernel_release(&self) -> &str {
        &self.kernel_release
    }

    pub fn kernel_image_sha256(&self) -> &Sha256Digest {
        &self.kernel_image_sha256
    }

    pub fn initramfs_sha256(&self) -> &Sha256Digest {
        &self.initramfs_sha256
    }

    pub fn root_disk_sha256(&self) -> &Sha256Digest {
        &self.root_disk_sha256
    }

    pub fn kernel_config_sha256(&self) -> &Sha256Digest {
        &self.kernel_config_sha256
    }

    pub fn kernel_btf_sha256(&self) -> &Sha256Digest {
        &self.btf_sha256
    }

    pub fn guest_runner_sha256(&self) -> &Sha256Digest {
        &self.guest_runner_sha256
    }

    pub fn guest_sensor_sha256(&self) -> &Sha256Digest {
        &self.guest_sensor_sha256
    }

    pub fn guest_bpf_bundle_sha256(&self) -> &Sha256Digest {
        &self.guest_bpf_bundle_sha256
    }

    pub fn telemetry_requirements_sha256(&self) -> &Sha256Digest {
        &self.telemetry_requirements_sha256
    }

    pub fn guest_evidence_public_key_sha256(&self) -> &Sha256Digest {
        &self.guest_evidence_public_key_sha256
    }

    pub fn host_evidence_public_key_sha256(&self) -> &Sha256Digest {
        &self.host_evidence_public_key_sha256
    }

    pub fn package_uid(&self) -> u32 {
        self.package_uid
            .parse()
            .expect("validated Linux VZ package uid")
    }

    pub fn package_gid(&self) -> u32 {
        self.package_gid
            .parse()
            .expect("validated Linux VZ package gid")
    }

    pub const fn execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn require_execution_authority(
        &self,
    ) -> Result<(), MacosLinuxVzTelemetryBackendErrorV1> {
        Err(MacosLinuxVzTelemetryBackendErrorV1::TelemetryConformanceMissing)
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, MacosLinuxVzTelemetryBackendErrorV1> {
        self.validate(None)?;
        let bytes = serde_json_canonicalizer::to_vec(self)
            .map_err(|_| MacosLinuxVzTelemetryBackendErrorV1::Serialization)?;
        if bytes.len() > MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1 {
            return Err(MacosLinuxVzTelemetryBackendErrorV1::LimitExceeded);
        }
        Ok(bytes)
    }

    pub fn identity_sha256_v1(&self) -> Result<Sha256Digest, MacosLinuxVzTelemetryBackendErrorV1> {
        Ok(Sha256Digest::from_bytes(&self.canonical_json_v1()?))
    }

    fn validate(
        &self,
        expected_requirements: Option<&ArtifactProtectedTelemetryRequirementsV1>,
    ) -> Result<(), MacosLinuxVzTelemetryBackendErrorV1> {
        if self.schema_version != MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_SCHEMA_V1 {
            return Err(MacosLinuxVzTelemetryBackendErrorV1::InvalidSchema);
        }
        if self.qualification_state
            != MacosLinuxVzTelemetryQualificationStateV1::CandidateUnqualified
            || !valid_linux_vz_identity_component_v1(&self.base_generation_id)
            || !valid_linux_vz_identity_component_v1(&self.linux_distribution_id)
            || !valid_linux_vz_identity_component_v1(&self.kernel_release)
            || canonical_nonzero_u32_v1(&self.package_uid).is_none()
            || canonical_nonzero_u32_v1(&self.package_gid).is_none()
            || self.package_uid == "0"
            || self.package_gid == "0"
        {
            return Err(MacosLinuxVzTelemetryBackendErrorV1::InvalidIdentity);
        }
        if let Some(requirements) = expected_requirements {
            let expected = requirements
                .requirements_sha256_v1()
                .map_err(|_| MacosLinuxVzTelemetryBackendErrorV1::RequirementsMismatch)?;
            if self.telemetry_requirements_sha256 != expected {
                return Err(MacosLinuxVzTelemetryBackendErrorV1::RequirementsMismatch);
            }
        }
        Ok(())
    }
}

pub fn decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
    bytes: &[u8],
    expected_requirements: &ArtifactProtectedTelemetryRequirementsV1,
) -> Result<UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1, MacosLinuxVzTelemetryBackendErrorV1>
{
    if bytes.is_empty() {
        return Err(MacosLinuxVzTelemetryBackendErrorV1::Empty);
    }
    if bytes.len() > MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryBackendErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzTelemetryBackendErrorV1::InvalidIdentity)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzTelemetryBackendErrorV1::InvalidIdentity)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| MacosLinuxVzTelemetryBackendErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzTelemetryBackendErrorV1::NonCanonical);
    }
    value.validate(Some(expected_requirements))?;
    Ok(value)
}

fn valid_linux_vz_identity_component_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn canonical_nonzero_u32_v1(value: &str) -> Option<u32> {
    if value.is_empty()
        || value.len() > 10
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let parsed = value.parse::<u32>().ok()?;
    (parsed != 0).then_some(parsed)
}
