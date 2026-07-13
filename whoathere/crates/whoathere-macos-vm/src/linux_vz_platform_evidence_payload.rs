use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryGuestObservationClaimsV1,
    MacosLinuxVzTelemetryEvidenceErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PLATFORM_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_platform_evidence_payload.v1";
pub const LINUX_VZ_PLATFORM_EVIDENCE_SERIAL_PREFIX_V1: &[u8] =
    b"WHOATHERE_GUEST_PLATFORM_EVIDENCE ";
pub const MAX_LINUX_VZ_PLATFORM_EVIDENCE_PAYLOAD_BYTES_V1: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPlatformEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
}

impl fmt::Display for LinuxVzPlatformEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_platform_evidence_missing",
            Self::Duplicate => "linux_vz_platform_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_platform_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_platform_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_platform_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_platform_evidence_schema_invalid",
        })
    }
}

impl std::error::Error for LinuxVzPlatformEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPlatformEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    evidence_byte_length: u64,
    btf_byte_length: u64,
    package_uid: u32,
    package_gid: u32,
}

impl LinuxVzPlatformEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn evidence_byte_length(&self) -> u64 {
        self.evidence_byte_length
    }

    pub fn btf_byte_length(&self) -> u64 {
        self.btf_byte_length
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
            self.evidence_byte_length,
            1,
            2,
            2,
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
struct PlatformEvidenceWireV1 {
    btf_byte_length: String,
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    evidence_truncated: bool,
    fixture_case: String,
    heartbeat_count: String,
    kernel_btf_magic: String,
    kernel_btf_sha256: Sha256Digest,
    kernel_config_binding: String,
    kernel_config_sha256: Sha256Digest,
    kernel_release: String,
    package_gid: String,
    package_uid: String,
    schema_version: String,
    sensor_healthy: bool,
}

pub fn build_linux_vz_kernel_config_and_btf_evidence_v1(
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    runtime_kernel_release: &str,
    runtime_btf: &[u8],
) -> Result<LinuxVzPlatformEvidencePayloadV1, LinuxVzPlatformEvidencePayloadErrorV1> {
    if runtime_kernel_release != backend.kernel_release()
        || runtime_btf.len() < 24
        || runtime_btf.len() > 128 * 1024 * 1024
        || runtime_btf[..2] != [0x9f, 0xeb]
        || Sha256Digest::from_bytes(runtime_btf) != *backend.kernel_btf_sha256()
    {
        return Err(LinuxVzPlatformEvidencePayloadErrorV1::InvalidSchema);
    }
    let wire = PlatformEvidenceWireV1 {
        btf_byte_length: runtime_btf.len().to_string(),
        descendant_teardown_complete: true,
        dropped_event_count: "0".into(),
        event_count: "2".into(),
        event_sequence_end: "2".into(),
        event_sequence_start: "1".into(),
        evidence_truncated: false,
        fixture_case: "kernel_config_and_btf".into(),
        heartbeat_count: "2".into(),
        kernel_btf_magic: "9feb".into(),
        kernel_btf_sha256: backend.kernel_btf_sha256().clone(),
        kernel_config_binding: "measured_backend_manifest".into(),
        kernel_config_sha256: backend.kernel_config_sha256().clone(),
        kernel_release: runtime_kernel_release.into(),
        package_gid: backend.package_gid().to_string(),
        package_uid: backend.package_uid().to_string(),
        schema_version: LINUX_VZ_PLATFORM_EVIDENCE_PAYLOAD_SCHEMA_V1.into(),
        sensor_healthy: true,
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPlatformEvidencePayloadErrorV1::InvalidJson)?;
    decode_linux_vz_platform_evidence_payload_v1(&canonical, backend)
}

pub fn decode_linux_vz_platform_evidence_from_serial_v1(
    serial: &[u8],
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<LinuxVzPlatformEvidencePayloadV1, LinuxVzPlatformEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) = line.strip_prefix(LINUX_VZ_PLATFORM_EVIDENCE_SERIAL_PREFIX_V1) else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzPlatformEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_platform_evidence_payload_v1(
        payload.ok_or(LinuxVzPlatformEvidencePayloadErrorV1::Missing)?,
        backend,
    )
}

pub fn decode_linux_vz_platform_evidence_payload_v1(
    payload: &[u8],
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<LinuxVzPlatformEvidencePayloadV1, LinuxVzPlatformEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_PLATFORM_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzPlatformEvidencePayloadErrorV1::LimitExceeded);
    }
    let wire: PlatformEvidenceWireV1 = serde_json::from_slice(payload)
        .map_err(|_| LinuxVzPlatformEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPlatformEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzPlatformEvidencePayloadErrorV1::NonCanonical);
    }
    let btf_byte_length = decimal_u64(&wire.btf_byte_length)?;
    if wire.schema_version != LINUX_VZ_PLATFORM_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.fixture_case != "kernel_config_and_btf"
        || wire.kernel_release != backend.kernel_release()
        || wire.kernel_config_sha256 != *backend.kernel_config_sha256()
        || wire.kernel_config_binding != "measured_backend_manifest"
        || wire.kernel_btf_sha256 != *backend.kernel_btf_sha256()
        || wire.kernel_btf_magic != "9feb"
        || btf_byte_length < 24
        || decimal_u64(&wire.event_sequence_start)? != 1
        || decimal_u64(&wire.event_sequence_end)? != 2
        || decimal_u64(&wire.event_count)? != 2
        || decimal_u64(&wire.heartbeat_count)? != 2
        || decimal_u64(&wire.dropped_event_count)? != 0
        || decimal_u64(&wire.package_uid)? != backend.package_uid() as u64
        || decimal_u64(&wire.package_gid)? != backend.package_gid() as u64
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
    {
        return Err(LinuxVzPlatformEvidencePayloadErrorV1::InvalidSchema);
    }
    Ok(LinuxVzPlatformEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        evidence_byte_length: payload.len() as u64,
        btf_byte_length,
        package_uid: backend.package_uid(),
        package_gid: backend.package_gid(),
    })
}

fn decimal_u64(value: &str) -> Result<u64, LinuxVzPlatformEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPlatformEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPlatformEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;
    use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn backend(btf: &[u8]) -> UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1 {
        let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
        UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
            "base",
            "alpine-aarch64",
            "6.18.35-0-virt",
            digest("kernel"),
            digest("initramfs"),
            digest("root-absence"),
            digest("kernel-config"),
            Sha256Digest::from_bytes(btf),
            digest("runner"),
            digest("signer"),
            digest("sensor"),
            digest("guest-config"),
            digest("guest-key"),
            digest("helper"),
            digest("host-sensor"),
            digest("host-config"),
            digest("host-key"),
            &requirements,
            65534,
            65534,
        )
        .unwrap()
    }

    #[test]
    fn kernel_config_and_btf_evidence_binds_runtime_bytes_to_backend_identity() {
        let mut btf = vec![0_u8; 4096];
        btf[..4].copy_from_slice(&[0x9f, 0xeb, 1, 0]);
        let backend = backend(&btf);
        let payload =
            build_linux_vz_kernel_config_and_btf_evidence_v1(&backend, "6.18.35-0-virt", &btf)
                .unwrap();
        assert_eq!(payload.btf_byte_length(), 4096);
        assert_eq!(payload.package_uid(), 65534);
        assert!(payload.guest_observation_claims_v1().is_ok());

        btf[100] = 1;
        assert_eq!(
            build_linux_vz_kernel_config_and_btf_evidence_v1(&backend, "6.18.35-0-virt", &btf,),
            Err(LinuxVzPlatformEvidencePayloadErrorV1::InvalidSchema)
        );
    }
}
