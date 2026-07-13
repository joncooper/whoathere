use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryGuestObservationClaimsV1,
    MacosLinuxVzTelemetryEvidenceErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_CGROUP_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_cgroup_evidence_payload.v1";
pub const LINUX_VZ_CGROUP_EVIDENCE_SERIAL_PREFIX_V1: &[u8] = b"WHOATHERE_GUEST_CGROUP_EVIDENCE ";
pub const MAX_LINUX_VZ_CGROUP_EVIDENCE_PAYLOAD_BYTES_V1: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzCgroupEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
}

impl fmt::Display for LinuxVzCgroupEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_cgroup_evidence_missing",
            Self::Duplicate => "linux_vz_cgroup_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_cgroup_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_cgroup_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_cgroup_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_cgroup_evidence_schema_invalid",
        })
    }
}

impl std::error::Error for LinuxVzCgroupEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzCgroupEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    evidence_byte_length: u64,
    controllers: Vec<String>,
    membership_pid: u32,
    package_uid: u32,
    package_gid: u32,
}

impl LinuxVzCgroupEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn evidence_byte_length(&self) -> u64 {
        self.evidence_byte_length
    }

    pub fn controllers(&self) -> &[String] {
        &self.controllers
    }

    pub fn membership_pid(&self) -> u32 {
        self.membership_pid
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
            5,
            5,
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
struct CgroupEvidenceWireV1 {
    cgroup2_filesystem_magic: String,
    child_cgroup_created: bool,
    child_cgroup_name: String,
    child_cgroup_removed: bool,
    child_cgroup_type: String,
    child_empty_after_return: bool,
    child_membership_observed: bool,
    child_populated_observed: bool,
    controller_count: String,
    controllers: Vec<String>,
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    evidence_truncated: bool,
    fixture_case: String,
    heartbeat_count: String,
    membership_pid: String,
    membership_process_binding: String,
    mount_path: String,
    mountinfo_filesystem: String,
    package_gid: String,
    package_uid: String,
    schema_version: String,
    sensor_healthy: bool,
}

pub fn build_linux_vz_cgroup_v2_evidence_v1(
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    controllers: &[String],
    membership_pid: u32,
) -> Result<LinuxVzCgroupEvidencePayloadV1, LinuxVzCgroupEvidencePayloadErrorV1> {
    if !valid_controllers(controllers) || membership_pid <= 1 {
        return Err(LinuxVzCgroupEvidencePayloadErrorV1::InvalidSchema);
    }
    let wire = CgroupEvidenceWireV1 {
        cgroup2_filesystem_magic: "63677270".into(),
        child_cgroup_created: true,
        child_cgroup_name: "whoathere-cgroup-v2-probe".into(),
        child_cgroup_removed: true,
        child_cgroup_type: "domain".into(),
        child_empty_after_return: true,
        child_membership_observed: true,
        child_populated_observed: true,
        controller_count: controllers.len().to_string(),
        controllers: controllers.to_vec(),
        descendant_teardown_complete: true,
        dropped_event_count: "0".into(),
        event_count: "5".into(),
        event_sequence_end: "5".into(),
        event_sequence_start: "1".into(),
        evidence_truncated: false,
        fixture_case: "cgroup_v2".into(),
        heartbeat_count: "2".into(),
        membership_pid: membership_pid.to_string(),
        membership_process_binding: "measured_guest_signer_process".into(),
        mount_path: "/sys/fs/cgroup".into(),
        mountinfo_filesystem: "cgroup2".into(),
        package_gid: backend.package_gid().to_string(),
        package_uid: backend.package_uid().to_string(),
        schema_version: LINUX_VZ_CGROUP_EVIDENCE_PAYLOAD_SCHEMA_V1.into(),
        sensor_healthy: true,
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzCgroupEvidencePayloadErrorV1::InvalidJson)?;
    decode_linux_vz_cgroup_evidence_payload_v1(&canonical, backend)
}

pub fn decode_linux_vz_cgroup_evidence_from_serial_v1(
    serial: &[u8],
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<LinuxVzCgroupEvidencePayloadV1, LinuxVzCgroupEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) = line.strip_prefix(LINUX_VZ_CGROUP_EVIDENCE_SERIAL_PREFIX_V1) else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzCgroupEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_cgroup_evidence_payload_v1(
        payload.ok_or(LinuxVzCgroupEvidencePayloadErrorV1::Missing)?,
        backend,
    )
}

pub fn decode_linux_vz_cgroup_evidence_payload_v1(
    payload: &[u8],
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<LinuxVzCgroupEvidencePayloadV1, LinuxVzCgroupEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_CGROUP_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzCgroupEvidencePayloadErrorV1::LimitExceeded);
    }
    let wire: CgroupEvidenceWireV1 = serde_json::from_slice(payload)
        .map_err(|_| LinuxVzCgroupEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzCgroupEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzCgroupEvidencePayloadErrorV1::NonCanonical);
    }
    let membership_pid = decimal_u64(&wire.membership_pid)?;
    if wire.schema_version != LINUX_VZ_CGROUP_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.fixture_case != "cgroup_v2"
        || wire.cgroup2_filesystem_magic != "63677270"
        || wire.mount_path != "/sys/fs/cgroup"
        || wire.mountinfo_filesystem != "cgroup2"
        || wire.child_cgroup_name != "whoathere-cgroup-v2-probe"
        || wire.child_cgroup_type != "domain"
        || !wire.child_cgroup_created
        || !wire.child_membership_observed
        || !wire.child_populated_observed
        || !wire.child_empty_after_return
        || !wire.child_cgroup_removed
        || wire.membership_process_binding != "measured_guest_signer_process"
        || membership_pid <= 1
        || membership_pid > u32::MAX as u64
        || !valid_controllers(&wire.controllers)
        || decimal_u64(&wire.controller_count)? != wire.controllers.len() as u64
        || decimal_u64(&wire.event_sequence_start)? != 1
        || decimal_u64(&wire.event_sequence_end)? != 5
        || decimal_u64(&wire.event_count)? != 5
        || decimal_u64(&wire.heartbeat_count)? != 2
        || decimal_u64(&wire.dropped_event_count)? != 0
        || decimal_u64(&wire.package_uid)? != backend.package_uid() as u64
        || decimal_u64(&wire.package_gid)? != backend.package_gid() as u64
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
    {
        return Err(LinuxVzCgroupEvidencePayloadErrorV1::InvalidSchema);
    }
    Ok(LinuxVzCgroupEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        evidence_byte_length: payload.len() as u64,
        controllers: wire.controllers,
        membership_pid: membership_pid as u32,
        package_uid: backend.package_uid(),
        package_gid: backend.package_gid(),
    })
}

fn valid_controllers(controllers: &[String]) -> bool {
    !controllers.is_empty()
        && controllers.len() <= 64
        && controllers.windows(2).all(|pair| pair[0] < pair[1])
        && controllers.iter().all(|controller| {
            !controller.is_empty()
                && controller.len() <= 64
                && controller
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
        })
}

fn decimal_u64(value: &str) -> Result<u64, LinuxVzCgroupEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzCgroupEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzCgroupEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;
    use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn backend() -> UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1 {
        let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
        UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
            "base",
            "alpine-aarch64",
            "6.18.35-0-virt",
            digest("kernel"),
            digest("initramfs"),
            digest("root-absence"),
            digest("kernel-config"),
            digest("btf"),
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
    fn cgroup_evidence_requires_sorted_controllers_and_runtime_membership() {
        let backend = backend();
        let controllers = vec!["cpu".into(), "memory".into(), "pids".into()];
        let payload = build_linux_vz_cgroup_v2_evidence_v1(&backend, &controllers, 42).unwrap();
        assert_eq!(payload.controllers(), controllers);
        assert_eq!(payload.membership_pid(), 42);
        assert!(payload.guest_observation_claims_v1().is_ok());

        let unsorted = vec!["pids".into(), "cpu".into()];
        assert_eq!(
            build_linux_vz_cgroup_v2_evidence_v1(&backend, &unsorted, 42),
            Err(LinuxVzCgroupEvidencePayloadErrorV1::InvalidSchema)
        );
        assert_eq!(
            build_linux_vz_cgroup_v2_evidence_v1(&backend, &controllers, 1),
            Err(LinuxVzCgroupEvidencePayloadErrorV1::InvalidSchema)
        );
    }
}
