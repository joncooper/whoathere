use crate::{
    LinuxVzTelemetryConformanceCaseV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_TEARDOWN_EVIDENCE_PAYLOAD_SCHEMA_V1: &str =
    "whoathere.linux_vz_teardown_evidence_payload.v1";
pub const LINUX_VZ_TEARDOWN_EVIDENCE_SERIAL_PREFIX_V1: &[u8] =
    b"WHOATHERE_GUEST_TEARDOWN_EVIDENCE ";
pub const MAX_LINUX_VZ_TEARDOWN_EVIDENCE_PAYLOAD_BYTES_V1: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzTeardownEvidencePayloadErrorV1 {
    Missing,
    Duplicate,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    InvalidEvent,
}

impl fmt::Display for LinuxVzTeardownEvidencePayloadErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "linux_vz_teardown_evidence_missing",
            Self::Duplicate => "linux_vz_teardown_evidence_duplicate",
            Self::LimitExceeded => "linux_vz_teardown_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_teardown_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_teardown_evidence_noncanonical",
            Self::InvalidSchema => "linux_vz_teardown_evidence_schema_invalid",
            Self::InvalidEvent => "linux_vz_teardown_evidence_event_invalid",
        })
    }
}

impl std::error::Error for LinuxVzTeardownEvidencePayloadErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzTeardownEvidencePayloadV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
}

impl LinuxVzTeardownEvidencePayloadV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn fixture_case(&self) -> LinuxVzTelemetryConformanceCaseV1 {
        LinuxVzTelemetryConformanceCaseV1::NormalExit
    }

    pub fn package_uid(&self) -> u32 {
        65534
    }

    pub fn package_gid(&self) -> u32 {
        65534
    }

    pub fn guest_observation_claims_v1(
        &self,
    ) -> Result<LinuxVzTelemetryGuestObservationClaimsV1, MacosLinuxVzTelemetryEvidenceErrorV1>
    {
        LinuxVzTelemetryGuestObservationClaimsV1::new(
            self.payload_sha256.clone(),
            self.canonical_json.len() as u64,
            1,
            3,
            3,
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
struct TeardownEvidenceWireV1 {
    cgroup_empty_after_reap: bool,
    cgroup_removed: bool,
    deadline_limit_ns: String,
    deadline_reached: bool,
    descendant_teardown_complete: bool,
    dropped_event_count: String,
    event_count: String,
    event_sequence_end: String,
    event_sequence_start: String,
    events: Vec<TeardownEventWireV1>,
    evidence_truncated: bool,
    fixture_case: String,
    fixture_exit_status: String,
    heartbeat_count: String,
    kill_signal_count: String,
    package_gid: String,
    package_uid: String,
    reaped_process_count: String,
    schema_version: String,
    sensor_healthy: bool,
    sensor_teardown_complete: bool,
    teardown_trigger: String,
    termination_signal_count: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TeardownEventWireV1 {
    actor_pid: String,
    cgroup_id: String,
    kind: String,
    sequence: String,
    subject_pid: String,
    timestamp_ns: String,
}

pub fn decode_linux_vz_teardown_evidence_from_serial_v1(
    serial: &[u8],
) -> Result<LinuxVzTeardownEvidencePayloadV1, LinuxVzTeardownEvidencePayloadErrorV1> {
    let mut payload = None;
    for raw_line in serial.split(|byte| *byte == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        let Some(candidate) = line.strip_prefix(LINUX_VZ_TEARDOWN_EVIDENCE_SERIAL_PREFIX_V1) else {
            continue;
        };
        if payload.replace(candidate).is_some() {
            return Err(LinuxVzTeardownEvidencePayloadErrorV1::Duplicate);
        }
    }
    decode_linux_vz_teardown_evidence_payload_v1(
        payload.ok_or(LinuxVzTeardownEvidencePayloadErrorV1::Missing)?,
    )
}

pub fn decode_linux_vz_teardown_evidence_payload_v1(
    payload: &[u8],
) -> Result<LinuxVzTeardownEvidencePayloadV1, LinuxVzTeardownEvidencePayloadErrorV1> {
    if payload.is_empty() || payload.len() > MAX_LINUX_VZ_TEARDOWN_EVIDENCE_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzTeardownEvidencePayloadErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(payload);
    let wire = TeardownEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzTeardownEvidencePayloadErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzTeardownEvidencePayloadErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzTeardownEvidencePayloadErrorV1::InvalidJson)?;
    if canonical != payload {
        return Err(LinuxVzTeardownEvidencePayloadErrorV1::NonCanonical);
    }

    if wire.schema_version != LINUX_VZ_TEARDOWN_EVIDENCE_PAYLOAD_SCHEMA_V1
        || wire.fixture_case != "normal_exit"
        || wire.teardown_trigger != "natural_exit"
        || decimal_u64_v1(&wire.deadline_limit_ns)? != 5_000_000_000
        || wire.deadline_reached
        || !wire.descendant_teardown_complete
        || !wire.cgroup_empty_after_reap
        || !wire.cgroup_removed
        || !wire.sensor_teardown_complete
        || !wire.sensor_healthy
        || wire.evidence_truncated
        || decimal_u64_v1(&wire.fixture_exit_status)? != 0
        || decimal_u64_v1(&wire.termination_signal_count)? != 0
        || decimal_u64_v1(&wire.kill_signal_count)? != 0
        || decimal_u64_v1(&wire.reaped_process_count)? != 1
        || decimal_u64_v1(&wire.event_sequence_start)? != 1
        || decimal_u64_v1(&wire.event_sequence_end)? != 3
        || decimal_u64_v1(&wire.event_count)? != 3
        || decimal_u64_v1(&wire.heartbeat_count)? != 2
        || decimal_u64_v1(&wire.dropped_event_count)? != 0
        || decimal_u64_v1(&wire.package_uid)? != 65534
        || decimal_u64_v1(&wire.package_gid)? != 65534
        || wire.events.len() != 3
    {
        return Err(LinuxVzTeardownEvidencePayloadErrorV1::InvalidSchema);
    }

    let mut actor_pids = [0_u64; 3];
    let mut subject_pids = [0_u64; 3];
    let mut cgroup_ids = [0_u64; 3];
    let mut timestamps = [0_u64; 3];
    for (index, event) in wire.events.iter().enumerate() {
        if event.kind != ["fork", "exec", "exit"][index]
            || decimal_u64_v1(&event.sequence)? != (index + 1) as u64
        {
            return Err(LinuxVzTeardownEvidencePayloadErrorV1::InvalidEvent);
        }
        actor_pids[index] = decimal_u64_v1(&event.actor_pid)?;
        subject_pids[index] = decimal_u64_v1(&event.subject_pid)?;
        cgroup_ids[index] = decimal_u64_v1(&event.cgroup_id)?;
        timestamps[index] = decimal_u64_v1(&event.timestamp_ns)?;
    }
    if actor_pids.contains(&0)
        || subject_pids.contains(&0)
        || cgroup_ids.contains(&0)
        || timestamps.contains(&0)
        || actor_pids[0] == subject_pids[0]
        || actor_pids[1] != subject_pids[0]
        || subject_pids[1] != subject_pids[0]
        || actor_pids[2] != subject_pids[0]
        || subject_pids[2] != subject_pids[0]
        || cgroup_ids[1] != cgroup_ids[0]
        || cgroup_ids[2] != cgroup_ids[0]
        || timestamps[0] >= timestamps[1]
        || timestamps[1] >= timestamps[2]
    {
        return Err(LinuxVzTeardownEvidencePayloadErrorV1::InvalidEvent);
    }

    Ok(LinuxVzTeardownEvidencePayloadV1 {
        canonical_json: canonical,
        payload_sha256: Sha256Digest::from_bytes(payload),
    })
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzTeardownEvidencePayloadErrorV1> {
    if value.is_empty()
        || (value != "0" && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzTeardownEvidencePayloadErrorV1::InvalidSchema);
    }
    value
        .parse()
        .map_err(|_| LinuxVzTeardownEvidencePayloadErrorV1::InvalidSchema)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NORMAL_EXIT: &[u8] = br#"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"5000000000","deadline_reached":false,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"42","timestamp_ns":"300"}],"evidence_truncated":false,"fixture_case":"normal_exit","fixture_exit_status":"0","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"natural_exit","termination_signal_count":"0"}"#;

    #[test]
    fn normal_exit_binds_natural_exit_lineage_and_complete_cleanup() {
        let payload = decode_linux_vz_teardown_evidence_payload_v1(NORMAL_EXIT).unwrap();
        assert_eq!(
            payload.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::NormalExit
        );
        assert_eq!(payload.package_uid(), 65534);
        let claims = payload.guest_observation_claims_v1().unwrap();
        assert_eq!(claims.dropped_event_count(), 0);
        assert!(claims.sensor_healthy());
        assert!(claims.descendant_teardown_complete());
    }

    #[test]
    fn normal_exit_rejects_forged_cleanup_signal_and_lineage_claims() {
        for changed in [
            String::from_utf8(NORMAL_EXIT.to_vec())
                .unwrap()
                .replace("\"cgroup_removed\":true", "\"cgroup_removed\":false"),
            String::from_utf8(NORMAL_EXIT.to_vec())
                .unwrap()
                .replace("\"deadline_reached\":false", "\"deadline_reached\":true"),
            String::from_utf8(NORMAL_EXIT.to_vec()).unwrap().replace(
                "\"termination_signal_count\":\"0\"",
                "\"termination_signal_count\":\"1\"",
            ),
            String::from_utf8(NORMAL_EXIT.to_vec())
                .unwrap()
                .replace("\"timestamp_ns\":\"200\"", "\"timestamp_ns\":\"99\""),
        ] {
            assert!(decode_linux_vz_teardown_evidence_payload_v1(changed.as_bytes()).is_err());
        }
    }
}
