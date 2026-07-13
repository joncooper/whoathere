use crate::{
    LinuxVzTelemetryConformanceCaseV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_FILE_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_file_evidence_payload.v1";
pub const LINUX_VZ_FILE_EVIDENCE_SERIAL_PREFIX_V1: &[u8] = b"WHOATHERE_GUEST_FILE_EVIDENCE ";
pub const MAX_LINUX_VZ_FILE_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzFileEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzFileEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_file_evidence_missing",
            Self::Duplicate => "linux_vz_file_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_file_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_file_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_file_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_file_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_file_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzFileEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzFileEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    package_uid: u32,
    package_gid: u32,
}

impl LinuxVzFileEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        self.fixture_case
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
            self.canonical_json.len() as u64,
            1,
            8,
            8,
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
struct FileEvidenceWireV1 {
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<FileEventWireV1>,
    evidence_truncated: bool,
    fanotify_permission_responses: String,
    file_system_diff_complete: bool,
    fixture_case: String,
    heartbeat_count: String,
    mmap_bpf_correlated: bool,
    package_gid: String,
    package_uid: String,
    persistence_target: String,
    raw_paths_captured: bool,
    schema_version: String,
    sensor_healthy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileEventWireV1 {
    actor_pid: String,
    cgroup_id: String,
    kind: String,
    sequence: String,
    timestamp_ns: String,
}

pub fn decode_linux_vz_file_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<LinuxVzFileEvidencePayloadV1, LinuxVzFileEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) = line.strip_prefix(LINUX_VZ_FILE_EVIDENCE_SERIAL_PREFIX_V1) else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzFileEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_file_evidence_payload_v1(
        payload.ok_or(LinuxVzFileEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_file_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzFileEvidencePayloadV1, LinuxVzFileEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_FILE_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzFileEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = FileEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzFileEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzFileEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzFileEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzFileEvidencePayloadErrorV1::NonCanonical);
    }
    let fixture_case = match wire.fixture_case.as_str() {
        "fanotify_permission" => LinuxVzTelemetryConformanceCaseV1::FanotifyPermission,
        "protected_open_read_write_rename_delete" => {
            LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
        }
        "mmap_access" => LinuxVzTelemetryConformanceCaseV1::MmapAccess,
        _ => return Err(LinuxVzFileEvidencePayloadErrorV1::InvalidSchema),
    };
    let package_uid = decimal_u64(&wire.package_uid)?;
    let package_gid = decimal_u64(&wire.package_gid)?;
    let permission_responses = decimal_u64(&wire.fanotify_permission_responses)?;
    if wire.schema_version != LINUX_VZ_FILE_EVIDENCE_PAYLOAD_SCHEMA_V1
        || decimal_u64(&wire.event_sequence_start)? != 1
        || decimal_u64(&wire.event_sequence_end)? != 8
        || decimal_u64(&wire.event_count)? != 8
        || decimal_u64(&wire.heartbeat_count)? != 2
        || decimal_u64(&wire.dropped_event_count)? != 0
        || permission_responses < 2
        || fixture_case == LinuxVzTelemetryConformanceCaseV1::FanotifyPermission
            && permission_responses != 5
        || package_uid != 65534
        || package_gid != 65534
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || !wire.descendant_teardown_complete
        || !wire.file_system_diff_complete
        || !wire.mmap_bpf_correlated
        || wire.persistence_target != "fake_user_startup"
        || wire.raw_paths_captured
        || wire.events.len() != 8
    {
        return Err(LinuxVzFileEvidencePayloadErrorV1::InvalidSchema);
    }
    let expected_kinds = [
        "file_open",
        "file_read",
        "file_write",
        "file_rename",
        "file_delete",
        "file_mmap",
        "persistence_write",
        "file_system_diff",
    ];
    let mut actor_pid = 0;
    let mut cgroup_id = 0;
    let mut last_timestamp = 0;
    for (index, event) in wire.events.iter().enumerate() {
        let event_actor = decimal_u64(&event.actor_pid)?;
        let event_cgroup = decimal_u64(&event.cgroup_id)?;
        let timestamp = decimal_u64(&event.timestamp_ns)?;
        if event.kind != expected_kinds[index]
            || decimal_u64(&event.sequence)? != index as u64 + 1
            || event_actor == 0
            || event_cgroup == 0
            || timestamp == 0
            || index > 0 && (event_actor != actor_pid || event_cgroup != cgroup_id)
            || timestamp <= last_timestamp
        {
            return Err(LinuxVzFileEvidencePayloadErrorV1::InvalidEvent);
        }
        actor_pid = event_actor;
        cgroup_id = event_cgroup;
        last_timestamp = timestamp;
    }
    Ok(LinuxVzFileEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
        fixture_case,
        package_uid: package_uid as u32,
        package_gid: package_gid as u32,
    })
}

fn decimal_u64(value: &str) -> Result<u64, LinuxVzFileEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzFileEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzFileEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload() -> Vec<u8> {
        let kinds = [
            "file_open",
            "file_read",
            "file_write",
            "file_rename",
            "file_delete",
            "file_mmap",
            "persistence_write",
            "file_system_diff",
        ];
        let events = kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| {
                serde_json::json!({
                    "actor_pid": "411",
                    "cgroup_id": "21",
                    "kind": kind,
                    "sequence": (index + 1).to_string(),
                    "timestamp_ns": (index + 1).to_string()
                })
            })
            .collect::<Vec<_>>();
        serde_json_canonicalizer::to_vec(&serde_json::json!({
            "descendant_teardown_complete": true,
            "dropped_event_count": "0",
            "event_count": "8",
            "event_sequence_end": "8",
            "event_sequence_start": "1",
            "events": events,
            "evidence_truncated": false,
            "fanotify_permission_responses": "2",
            "file_system_diff_complete": true,
            "fixture_case": "protected_open_read_write_rename_delete",
            "heartbeat_count": "2",
            "mmap_bpf_correlated": true,
            "package_gid": "65534",
            "package_uid": "65534",
            "persistence_target": "fake_user_startup",
            "raw_paths_captured": false,
            "schema_version": LINUX_VZ_FILE_EVIDENCE_PAYLOAD_SCHEMA_V1,
            "sensor_healthy": true
        }))
        .expect("file evidence")
    }

    #[test]
    fn file_payload_derives_strict_claims() {
        let evidence = decode_linux_vz_file_evidence_payload_v1(&payload()).expect("payload");
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
        );
        assert_eq!(evidence.package_uid(), 65534);
        let claims = evidence.guest_observation_claims_v1().expect("claims");
        assert_eq!(claims.dropped_event_count(), 0);
    }

    #[test]
    fn file_payload_rejects_sensor_gap_and_reordering() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).expect("JSON");
        value["mmap_bpf_correlated"] = serde_json::json!(false);
        let changed = serde_json_canonicalizer::to_vec(&value).expect("changed");
        assert_eq!(
            decode_linux_vz_file_evidence_payload_v1(&changed),
            Err(LinuxVzFileEvidencePayloadErrorV1::InvalidSchema)
        );
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).expect("JSON");
        value["events"][6]["timestamp_ns"] = serde_json::json!("6");
        let changed = serde_json_canonicalizer::to_vec(&value).expect("changed");
        assert_eq!(
            decode_linux_vz_file_evidence_payload_v1(&changed),
            Err(LinuxVzFileEvidencePayloadErrorV1::InvalidEvent)
        );
    }

    #[test]
    fn fanotify_platform_case_requires_the_same_complete_permission_evidence() {
        let mut value: serde_json::Value = serde_json::from_slice(&payload()).expect("JSON");
        value["fixture_case"] = serde_json::json!("fanotify_permission");
        value["fanotify_permission_responses"] = serde_json::json!("5");
        let canonical = serde_json_canonicalizer::to_vec(&value).expect("canonical");
        let evidence = decode_linux_vz_file_evidence_payload_v1(&canonical).expect("evidence");
        assert_eq!(
            evidence.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::FanotifyPermission
        );
        assert!(evidence.guest_observation_claims_v1().is_ok());

        value["fanotify_permission_responses"] = serde_json::json!("4");
        let incomplete = serde_json_canonicalizer::to_vec(&value).expect("incomplete");
        assert_eq!(
            decode_linux_vz_file_evidence_payload_v1(&incomplete),
            Err(LinuxVzFileEvidencePayloadErrorV1::InvalidSchema)
        );
    }
}
