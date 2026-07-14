#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]

use crate::linux_vz_package_sensor_event_stream::{
    LinuxVzPackageKernelEventKindV1, LinuxVzPackageSelectedSyscallV1,
};
use crate::linux_vz_package_sensor_process_collector::LinuxVzPackageRootProcessCollectionV1;
use crate::linux_vz_package_sensor_process_stream::LinuxVzPackageCorrelatedProcessObservationV1;
use crate::{
    LinuxVzPackageProcessCompletionV1, LinuxVzPackageProcessLaunchIdentityV1,
    LinuxVzPackageProcessTerminalV1, MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_ROOT_PROCESS_EVIDENCE_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_root_process_evidence.v1";

const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;
const MAX_SOURCE_EVENT_COUNT_V1: u64 = 65_536;
const MAX_DRAIN_BATCH_RECORD_COUNT_V1: u64 = 4_096;
const EXPECTED_TRACEPOINT_NAMES_V1: [&str; 5] = [
    "sched_process_exec",
    "sched_process_exit",
    "sched_process_fork",
    "sys_enter",
    "sys_exit",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootProcessEvidenceErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidExpectedBinding,
    BindingMismatch,
    InvalidRuntimeIdentity,
    InvalidCoverage,
    InvalidObservation,
    IncompleteLeaderLifecycle,
    Serialization,
}

impl LinuxVzPackageRootProcessEvidenceErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_root_process_evidence_empty",
            Self::LimitExceeded => "linux_vz_package_root_process_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_package_root_process_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_package_root_process_evidence_noncanonical",
            Self::InvalidExpectedBinding => {
                "linux_vz_package_root_process_evidence_expected_binding_invalid"
            }
            Self::BindingMismatch => "linux_vz_package_root_process_evidence_binding_mismatch",
            Self::InvalidRuntimeIdentity => {
                "linux_vz_package_root_process_evidence_runtime_identity_invalid"
            }
            Self::InvalidCoverage => "linux_vz_package_root_process_evidence_coverage_invalid",
            Self::InvalidObservation => {
                "linux_vz_package_root_process_evidence_observation_invalid"
            }
            Self::IncompleteLeaderLifecycle => {
                "linux_vz_package_root_process_evidence_leader_lifecycle_incomplete"
            }
            Self::Serialization => "linux_vz_package_root_process_evidence_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootProcessEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootProcessEvidenceErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageExpectedRootProcessEvidenceV1 {
    sensor_session_challenge_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    cgroup_name: String,
    cgroup_id: u64,
    root_runner_pid: u32,
    leader_pid: u32,
    leader_executable_sha256: Sha256Digest,
    leader_argv_sha256: Sha256Digest,
    leader_argv_item_count: usize,
    completion: LinuxVzPackageProcessCompletionV1,
}

impl LinuxVzPackageExpectedRootProcessEvidenceV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_action_v1(
        sensor_session_challenge_sha256: Sha256Digest,
        launch_contract_sha256: Sha256Digest,
        process_plan_sha256: Sha256Digest,
        action_index: usize,
        cgroup_name: String,
        cgroup_id: u64,
        root_runner_pid: u32,
        leader_pid: u32,
        launch_identity: &LinuxVzPackageProcessLaunchIdentityV1,
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<Self, LinuxVzPackageRootProcessEvidenceErrorV1> {
        let expected = Self {
            sensor_session_challenge_sha256,
            launch_contract_sha256,
            process_plan_sha256,
            action_index,
            cgroup_name,
            cgroup_id,
            root_runner_pid,
            leader_pid,
            leader_executable_sha256: launch_identity.executable_sha256().clone(),
            leader_argv_sha256: launch_identity.argv_sha256().clone(),
            leader_argv_item_count: launch_identity.argv_item_count(),
            completion: *completion,
        };
        expected.validate_v1()?;
        Ok(expected)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageRootProcessEvidenceErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let digests = [
            &self.sensor_session_challenge_sha256,
            &self.launch_contract_sha256,
            &self.process_plan_sha256,
            &self.leader_executable_sha256,
            &self.leader_argv_sha256,
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
            || self.leader_argv_item_count == 0
            || self.leader_argv_item_count > 4_096
        {
            return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidExpectedBinding);
        }
        Ok(())
    }

    pub fn sensor_session_challenge_sha256(&self) -> &Sha256Digest {
        &self.sensor_session_challenge_sha256
    }

    pub fn launch_contract_sha256(&self) -> &Sha256Digest {
        &self.launch_contract_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    pub fn cgroup_name(&self) -> &str {
        &self.cgroup_name
    }

    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    pub const fn root_runner_pid(&self) -> u32 {
        self.root_runner_pid
    }

    pub const fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    pub fn completion(&self) -> &LinuxVzPackageProcessCompletionV1 {
        &self.completion
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootProcessLifecycleKindV1 {
    Fork,
    Exec,
    Exit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootProcessSyscallV1 {
    Setgid,
    Setuid,
    Setgroups,
    Connect,
    Sendto,
    Mmap,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootProcessLifecycleObservationV1 {
    kind: LinuxVzPackageRootProcessLifecycleKindV1,
    source_sequence: u64,
    timestamp_monotonic_nanoseconds: u64,
    pid: u32,
    tgid: u32,
    parent_pid: u32,
    subject_pid: u32,
    kernel_wait_status: Option<u16>,
    cpu: u32,
}

impl LinuxVzPackageRootProcessLifecycleObservationV1 {
    pub const fn kind(&self) -> LinuxVzPackageRootProcessLifecycleKindV1 {
        self.kind
    }

    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    pub const fn timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.timestamp_monotonic_nanoseconds
    }

    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub const fn tgid(&self) -> u32 {
        self.tgid
    }

    pub const fn parent_pid(&self) -> u32 {
        self.parent_pid
    }

    pub const fn subject_pid(&self) -> u32 {
        self.subject_pid
    }

    pub const fn kernel_wait_status(&self) -> Option<u16> {
        self.kernel_wait_status
    }

    pub const fn cpu(&self) -> u32 {
        self.cpu
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootProcessSyscallObservationV1 {
    syscall: LinuxVzPackageRootProcessSyscallV1,
    enter_source_sequence: u64,
    exit_source_sequence: u64,
    enter_timestamp_monotonic_nanoseconds: u64,
    exit_timestamp_monotonic_nanoseconds: u64,
    pid: u32,
    tgid: u32,
    argument_vector_sha256: Sha256Digest,
    safe_argument_zero: Option<u64>,
    result: i64,
    enter_cpu: u32,
    exit_cpu: u32,
}

impl LinuxVzPackageRootProcessSyscallObservationV1 {
    pub const fn syscall(&self) -> LinuxVzPackageRootProcessSyscallV1 {
        self.syscall
    }

    pub const fn enter_source_sequence(&self) -> u64 {
        self.enter_source_sequence
    }

    pub const fn exit_source_sequence(&self) -> u64 {
        self.exit_source_sequence
    }

    pub const fn enter_timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.enter_timestamp_monotonic_nanoseconds
    }

    pub const fn exit_timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.exit_timestamp_monotonic_nanoseconds
    }

    pub const fn pid(&self) -> u32 {
        self.pid
    }

    pub const fn tgid(&self) -> u32 {
        self.tgid
    }

    pub fn argument_vector_sha256(&self) -> &Sha256Digest {
        &self.argument_vector_sha256
    }

    pub const fn safe_argument_zero(&self) -> Option<u64> {
        self.safe_argument_zero
    }

    pub const fn result(&self) -> i64 {
        self.result
    }

    pub const fn enter_cpu(&self) -> u32 {
        self.enter_cpu
    }

    pub const fn exit_cpu(&self) -> u32 {
        self.exit_cpu
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxVzPackageRootProcessObservationV1 {
    Lifecycle(LinuxVzPackageRootProcessLifecycleObservationV1),
    Syscall(LinuxVzPackageRootProcessSyscallObservationV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootProcessEvidenceV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    source_event_count: u64,
    observations: Vec<LinuxVzPackageRootProcessObservationV1>,
    runtime_btf_sha256: Sha256Digest,
    task_exit_code_byte_offset: u32,
    tracepoint_format_sha256: BTreeMap<String, Sha256Digest>,
    online_cpus: Vec<u32>,
    attachment_cpu: u32,
    active_drain_poll_count: u64,
    active_nonempty_drain_count: u64,
    source_event_count_before_finish: u64,
    finish_drain_event_count: u64,
    maximum_drain_batch_record_count: u64,
    leader_exec_count: u64,
    leader_first_exec_monotonic_nanoseconds: u64,
    leader_exit_monotonic_nanoseconds: u64,
    leader_kernel_wait_status: u16,
    leader_supervisor_wait_status: u16,
}

impl LinuxVzPackageRootProcessEvidenceV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub const fn source_event_count(&self) -> u64 {
        self.source_event_count
    }

    pub fn observations(&self) -> &[LinuxVzPackageRootProcessObservationV1] {
        &self.observations
    }

    pub fn runtime_btf_sha256(&self) -> &Sha256Digest {
        &self.runtime_btf_sha256
    }

    pub const fn task_exit_code_byte_offset(&self) -> u32 {
        self.task_exit_code_byte_offset
    }

    pub fn tracepoint_format_sha256(&self) -> &BTreeMap<String, Sha256Digest> {
        &self.tracepoint_format_sha256
    }

    pub fn online_cpus(&self) -> &[u32] {
        &self.online_cpus
    }

    pub const fn attachment_cpu(&self) -> u32 {
        self.attachment_cpu
    }

    pub const fn active_drain_poll_count(&self) -> u64 {
        self.active_drain_poll_count
    }

    pub const fn active_nonempty_drain_count(&self) -> u64 {
        self.active_nonempty_drain_count
    }

    pub const fn source_event_count_before_finish(&self) -> u64 {
        self.source_event_count_before_finish
    }

    pub const fn finish_drain_event_count(&self) -> u64 {
        self.finish_drain_event_count
    }

    pub const fn maximum_drain_batch_record_count(&self) -> u64 {
        self.maximum_drain_batch_record_count
    }

    pub const fn leader_exec_count(&self) -> u64 {
        self.leader_exec_count
    }

    pub const fn leader_first_exec_monotonic_nanoseconds(&self) -> u64 {
        self.leader_first_exec_monotonic_nanoseconds
    }

    pub const fn leader_exit_monotonic_nanoseconds(&self) -> u64 {
        self.leader_exit_monotonic_nanoseconds
    }

    pub const fn leader_kernel_wait_status(&self) -> u16 {
        self.leader_kernel_wait_status
    }

    pub const fn leader_supervisor_wait_status(&self) -> u16 {
        self.leader_supervisor_wait_status
    }

    pub const fn coverage_complete(&self) -> bool {
        true
    }

    pub const fn raw_arguments_captured(&self) -> bool {
        false
    }

    pub const fn raw_exec_paths_captured(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootProcessEvidenceWireV1 {
    binding: RootProcessBindingWireV1,
    coverage: RootProcessCoverageWireV1,
    leader: RootProcessLeaderWireV1,
    observations: Vec<RootProcessObservationWireV1>,
    raw_arguments_captured: bool,
    raw_exec_paths_captured: bool,
    runtime_identity: RootProcessRuntimeIdentityWireV1,
    schema_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootProcessBindingWireV1 {
    action_index: String,
    cgroup_id: String,
    cgroup_name: String,
    launch_contract_sha256: Sha256Digest,
    leader_argv_item_count: String,
    leader_argv_sha256: Sha256Digest,
    leader_executable_sha256: Sha256Digest,
    leader_pid: String,
    package_gid: String,
    package_uid: String,
    process_plan_sha256: Sha256Digest,
    root_runner_pid: String,
    sensor_session_challenge_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootProcessCoverageWireV1 {
    active_drain_poll_count: String,
    active_nonempty_drain_count: String,
    continuous_drain: bool,
    coverage_complete: bool,
    discarded_record_count: String,
    dropped_event_count: String,
    evidence_truncated: bool,
    finish_drain_event_count: String,
    maximum_drain_batch_record_count: String,
    observation_count: String,
    process_sensor_healthy: bool,
    source_event_count: String,
    source_event_count_before_finish: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootProcessLeaderWireV1 {
    descendant_teardown_complete: bool,
    exit_status: Option<String>,
    first_exec_monotonic_nanoseconds: String,
    kernel_wait_status: String,
    leader_exec_count: String,
    leader_exit_monotonic_nanoseconds: String,
    process_ended_monotonic_nanoseconds: String,
    process_started_monotonic_nanoseconds: String,
    supervisor_wait_status: String,
    terminal: LinuxVzPackageProcessTerminalV1,
    termination_signal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootProcessRuntimeIdentityWireV1 {
    attachment_cpu: String,
    online_cpus: Vec<String>,
    runtime_btf_sha256: Sha256Digest,
    task_exit_code_byte_offset: String,
    tracepoint_format_sha256: Vec<RootProcessTracepointIdentityWireV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootProcessTracepointIdentityWireV1 {
    name: String,
    sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "observation_kind",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum RootProcessObservationWireV1 {
    Lifecycle {
        cgroup_id: String,
        cpu: String,
        kernel_wait_status: Option<String>,
        lifecycle_kind: String,
        parent_pid: String,
        pid: String,
        source_sequence: String,
        subject_pid: String,
        tgid: String,
        timestamp_monotonic_nanoseconds: String,
    },
    Syscall {
        argument_vector_sha256: Sha256Digest,
        cgroup_id: String,
        enter_cpu: String,
        enter_source_sequence: String,
        enter_timestamp_monotonic_nanoseconds: String,
        exit_cpu: String,
        exit_source_sequence: String,
        exit_timestamp_monotonic_nanoseconds: String,
        pid: String,
        result: String,
        safe_argument_zero: Option<String>,
        syscall: String,
        tgid: String,
    },
}

pub(crate) fn encode_linux_vz_package_root_process_evidence_v1(
    expected: &LinuxVzPackageExpectedRootProcessEvidenceV1,
    collection: &LinuxVzPackageRootProcessCollectionV1,
) -> Result<LinuxVzPackageRootProcessEvidenceV1, LinuxVzPackageRootProcessEvidenceErrorV1> {
    expected.validate_v1()?;
    let stream = collection.stream_v1();
    let observations = stream
        .observations_v1()
        .iter()
        .map(|observation| match observation {
            LinuxVzPackageCorrelatedProcessObservationV1::Lifecycle(event) => {
                RootProcessObservationWireV1::Lifecycle {
                    cgroup_id: event.cgroup_id_v1().to_string(),
                    cpu: event.cpu_v1().to_string(),
                    kernel_wait_status: event
                        .kernel_wait_status_v1()
                        .map(|value| value.to_string()),
                    lifecycle_kind: lifecycle_name_v1(event.kind_v1()).to_string(),
                    parent_pid: event.parent_pid_v1().to_string(),
                    pid: event.pid_v1().to_string(),
                    source_sequence: event.source_sequence_v1().to_string(),
                    subject_pid: event.subject_pid_v1().to_string(),
                    tgid: event.tgid_v1().to_string(),
                    timestamp_monotonic_nanoseconds: event.timestamp_nanoseconds_v1().to_string(),
                }
            }
            LinuxVzPackageCorrelatedProcessObservationV1::Syscall(event) => {
                let syscall = event.syscall_v1();
                RootProcessObservationWireV1::Syscall {
                    argument_vector_sha256: syscall_argument_vector_sha256_v1(
                        syscall,
                        event.arguments_v1(),
                    ),
                    cgroup_id: event.cgroup_id_v1().to_string(),
                    enter_cpu: event.enter_cpu_v1().to_string(),
                    enter_source_sequence: event.enter_source_sequence_v1().to_string(),
                    enter_timestamp_monotonic_nanoseconds: event
                        .enter_timestamp_nanoseconds_v1()
                        .to_string(),
                    exit_cpu: event.exit_cpu_v1().to_string(),
                    exit_source_sequence: event.exit_source_sequence_v1().to_string(),
                    exit_timestamp_monotonic_nanoseconds: event
                        .exit_timestamp_nanoseconds_v1()
                        .to_string(),
                    pid: event.pid_v1().to_string(),
                    result: event.result_v1().to_string(),
                    safe_argument_zero: safe_argument_zero_v1(syscall, event.arguments_v1())
                        .map(|value| value.to_string()),
                    syscall: syscall.name_v1().to_string(),
                    tgid: event.tgid_v1().to_string(),
                }
            }
        })
        .collect::<Vec<_>>();
    let tracepoint_format_sha256 = collection
        .tracepoint_format_sha256_v1()
        .iter()
        .map(|(name, sha256)| RootProcessTracepointIdentityWireV1 {
            name: (*name).to_string(),
            sha256: sha256.clone(),
        })
        .collect();
    let wire = RootProcessEvidenceWireV1 {
        binding: RootProcessBindingWireV1 {
            action_index: expected.action_index.to_string(),
            cgroup_id: expected.cgroup_id.to_string(),
            cgroup_name: expected.cgroup_name.clone(),
            launch_contract_sha256: expected.launch_contract_sha256.clone(),
            leader_argv_item_count: expected.leader_argv_item_count.to_string(),
            leader_argv_sha256: expected.leader_argv_sha256.clone(),
            leader_executable_sha256: expected.leader_executable_sha256.clone(),
            leader_pid: expected.leader_pid.to_string(),
            package_gid: PACKAGE_GID_V1.to_string(),
            package_uid: PACKAGE_UID_V1.to_string(),
            process_plan_sha256: expected.process_plan_sha256.clone(),
            root_runner_pid: expected.root_runner_pid.to_string(),
            sensor_session_challenge_sha256: expected.sensor_session_challenge_sha256.clone(),
        },
        coverage: RootProcessCoverageWireV1 {
            active_drain_poll_count: collection.active_drain_poll_count_v1().to_string(),
            active_nonempty_drain_count: collection.active_nonempty_drain_count_v1().to_string(),
            continuous_drain: collection.continuous_drain_v1(),
            coverage_complete: collection.coverage_complete_v1(),
            discarded_record_count: collection.discarded_record_count_v1().to_string(),
            dropped_event_count: collection.dropped_event_count_v1().to_string(),
            evidence_truncated: false,
            finish_drain_event_count: collection.finish_drain_event_count_v1().to_string(),
            maximum_drain_batch_record_count: collection
                .maximum_drain_batch_record_count_v1()
                .to_string(),
            observation_count: observations.len().to_string(),
            process_sensor_healthy: true,
            source_event_count: stream.source_event_count_v1().to_string(),
            source_event_count_before_finish: collection
                .source_event_count_before_finish_v1()
                .to_string(),
        },
        leader: RootProcessLeaderWireV1 {
            descendant_teardown_complete: true,
            exit_status: expected
                .completion
                .exit_status()
                .map(|value| value.to_string()),
            first_exec_monotonic_nanoseconds: collection
                .leader_first_exec_monotonic_nanoseconds_v1()
                .to_string(),
            kernel_wait_status: collection.leader_kernel_wait_status_v1().to_string(),
            leader_exec_count: collection.leader_exec_count_v1().to_string(),
            leader_exit_monotonic_nanoseconds: collection
                .leader_exit_monotonic_nanoseconds_v1()
                .to_string(),
            process_ended_monotonic_nanoseconds: expected
                .completion
                .process_ended_monotonic_nanoseconds()
                .to_string(),
            process_started_monotonic_nanoseconds: expected
                .completion
                .process_started_monotonic_nanoseconds()
                .to_string(),
            supervisor_wait_status: collection.leader_supervisor_wait_status_v1().to_string(),
            terminal: expected.completion.terminal(),
            termination_signal: expected
                .completion
                .termination_signal()
                .map(|value| value.to_string()),
        },
        observations,
        raw_arguments_captured: false,
        raw_exec_paths_captured: false,
        runtime_identity: RootProcessRuntimeIdentityWireV1 {
            attachment_cpu: collection.attachment_cpu_v1().to_string(),
            online_cpus: collection
                .online_cpus_v1()
                .iter()
                .map(u32::to_string)
                .collect(),
            runtime_btf_sha256: collection.runtime_btf_sha256_v1().clone(),
            task_exit_code_byte_offset: collection.task_exit_code_byte_offset_v1().to_string(),
            tracepoint_format_sha256,
        },
        schema_version: LINUX_VZ_PACKAGE_ROOT_PROCESS_EVIDENCE_SCHEMA_V1.to_string(),
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::Serialization)?;
    decode_linux_vz_package_root_process_evidence_v1(expected, &canonical)
}

pub fn decode_linux_vz_package_root_process_evidence_v1(
    expected: &LinuxVzPackageExpectedRootProcessEvidenceV1,
    bytes: &[u8],
) -> Result<LinuxVzPackageRootProcessEvidenceV1, LinuxVzPackageRootProcessEvidenceErrorV1> {
    expected.validate_v1()?;
    let (wire, canonical) = decode_canonical_v1::<RootProcessEvidenceWireV1>(bytes)?;
    if wire.schema_version != LINUX_VZ_PACKAGE_ROOT_PROCESS_EVIDENCE_SCHEMA_V1
        || wire.raw_arguments_captured
        || wire.raw_exec_paths_captured
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidCoverage);
    }
    validate_binding_v1(&wire.binding, expected)?;
    validate_runtime_identity_v1(&wire.runtime_identity)?;
    let source_event_count = validate_coverage_v1(&wire.coverage, wire.observations.len())?;
    validate_leader_v1(&wire.leader, expected, source_event_count)?;
    let runtime_btf_sha256 = wire.runtime_identity.runtime_btf_sha256.clone();
    let task_exit_code_byte_offset =
        decimal_u32_v1(&wire.runtime_identity.task_exit_code_byte_offset)?;
    let tracepoint_format_sha256 = wire
        .runtime_identity
        .tracepoint_format_sha256
        .iter()
        .map(|identity| (identity.name.clone(), identity.sha256.clone()))
        .collect();
    let online_cpus = wire
        .runtime_identity
        .online_cpus
        .iter()
        .map(|value| decimal_u32_v1(value))
        .collect::<Result<Vec<_>, _>>()?;
    let attachment_cpu = decimal_u32_v1(&wire.runtime_identity.attachment_cpu)?;
    let active_drain_poll_count = decimal_u64_v1(&wire.coverage.active_drain_poll_count)?;
    let active_nonempty_drain_count = decimal_u64_v1(&wire.coverage.active_nonempty_drain_count)?;
    let source_event_count_before_finish =
        decimal_u64_v1(&wire.coverage.source_event_count_before_finish)?;
    let finish_drain_event_count = decimal_u64_v1(&wire.coverage.finish_drain_event_count)?;
    let maximum_drain_batch_record_count =
        decimal_u64_v1(&wire.coverage.maximum_drain_batch_record_count)?;
    let leader_exec_count = decimal_u64_v1(&wire.leader.leader_exec_count)?;
    let leader_first_exec_monotonic_nanoseconds =
        decimal_u64_v1(&wire.leader.first_exec_monotonic_nanoseconds)?;
    let leader_exit_monotonic_nanoseconds =
        decimal_u64_v1(&wire.leader.leader_exit_monotonic_nanoseconds)?;
    let leader_kernel_wait_status = decimal_u16_v1(&wire.leader.kernel_wait_status)?;
    let leader_supervisor_wait_status = decimal_u16_v1(&wire.leader.supervisor_wait_status)?;
    let observations = validate_observations_v1(
        wire.observations,
        expected,
        &wire.leader,
        &online_cpus,
        source_event_count,
    )?;
    Ok(LinuxVzPackageRootProcessEvidenceV1 {
        payload_sha256: Sha256Digest::from_bytes(&canonical),
        canonical_json: canonical,
        source_event_count,
        observations,
        runtime_btf_sha256,
        task_exit_code_byte_offset,
        tracepoint_format_sha256,
        online_cpus,
        attachment_cpu,
        active_drain_poll_count,
        active_nonempty_drain_count,
        source_event_count_before_finish,
        finish_drain_event_count,
        maximum_drain_batch_record_count,
        leader_exec_count,
        leader_first_exec_monotonic_nanoseconds,
        leader_exit_monotonic_nanoseconds,
        leader_kernel_wait_status,
        leader_supervisor_wait_status,
    })
}

fn validate_binding_v1(
    wire: &RootProcessBindingWireV1,
    expected: &LinuxVzPackageExpectedRootProcessEvidenceV1,
) -> Result<(), LinuxVzPackageRootProcessEvidenceErrorV1> {
    if decimal_usize_v1(&wire.action_index)? != expected.action_index
        || decimal_u64_v1(&wire.cgroup_id)? != expected.cgroup_id
        || wire.cgroup_name != expected.cgroup_name
        || wire.launch_contract_sha256 != expected.launch_contract_sha256
        || decimal_usize_v1(&wire.leader_argv_item_count)? != expected.leader_argv_item_count
        || wire.leader_argv_sha256 != expected.leader_argv_sha256
        || wire.leader_executable_sha256 != expected.leader_executable_sha256
        || decimal_u32_v1(&wire.leader_pid)? != expected.leader_pid
        || decimal_u32_v1(&wire.package_gid)? != PACKAGE_GID_V1
        || decimal_u32_v1(&wire.package_uid)? != PACKAGE_UID_V1
        || wire.process_plan_sha256 != expected.process_plan_sha256
        || decimal_u32_v1(&wire.root_runner_pid)? != expected.root_runner_pid
        || wire.sensor_session_challenge_sha256 != expected.sensor_session_challenge_sha256
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::BindingMismatch);
    }
    Ok(())
}

fn validate_runtime_identity_v1(
    wire: &RootProcessRuntimeIdentityWireV1,
) -> Result<(), LinuxVzPackageRootProcessEvidenceErrorV1> {
    let empty = Sha256Digest::from_bytes(&[]);
    let attachment_cpu = decimal_u32_v1(&wire.attachment_cpu)?;
    let task_exit_code_byte_offset = decimal_u32_v1(&wire.task_exit_code_byte_offset)?;
    let online_cpus = wire
        .online_cpus
        .iter()
        .map(|value| decimal_u32_v1(value))
        .collect::<Result<Vec<_>, _>>()?;
    if wire.runtime_btf_sha256 == empty
        || task_exit_code_byte_offset == 0
        || task_exit_code_byte_offset > 4_096
        || online_cpus.is_empty()
        || online_cpus.len() > 4_096
        || !online_cpus.contains(&attachment_cpu)
        || online_cpus.windows(2).any(|pair| pair[0] >= pair[1])
        || wire.tracepoint_format_sha256.len() != EXPECTED_TRACEPOINT_NAMES_V1.len()
        || wire
            .tracepoint_format_sha256
            .iter()
            .map(|identity| identity.sha256.as_str())
            .collect::<BTreeSet<_>>()
            .len()
            != EXPECTED_TRACEPOINT_NAMES_V1.len()
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidRuntimeIdentity);
    }
    for (identity, expected_name) in wire
        .tracepoint_format_sha256
        .iter()
        .zip(EXPECTED_TRACEPOINT_NAMES_V1)
    {
        if identity.name != expected_name || identity.sha256 == empty {
            return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidRuntimeIdentity);
        }
    }
    Ok(())
}

fn validate_coverage_v1(
    wire: &RootProcessCoverageWireV1,
    observation_count: usize,
) -> Result<u64, LinuxVzPackageRootProcessEvidenceErrorV1> {
    let source_event_count = decimal_u64_v1(&wire.source_event_count)?;
    let source_event_count_before_finish = decimal_u64_v1(&wire.source_event_count_before_finish)?;
    let finish_drain_event_count = decimal_u64_v1(&wire.finish_drain_event_count)?;
    let active_drain_poll_count = decimal_u64_v1(&wire.active_drain_poll_count)?;
    let active_nonempty_drain_count = decimal_u64_v1(&wire.active_nonempty_drain_count)?;
    let maximum_drain_batch_record_count = decimal_u64_v1(&wire.maximum_drain_batch_record_count)?;
    if source_event_count == 0
        || source_event_count > MAX_SOURCE_EVENT_COUNT_V1
        || source_event_count_before_finish.checked_add(finish_drain_event_count)
            != Some(source_event_count)
        || decimal_usize_v1(&wire.observation_count)? != observation_count
        || observation_count == 0
        || observation_count as u64 > source_event_count
        || active_nonempty_drain_count > active_drain_poll_count
        || (active_nonempty_drain_count > 0 && source_event_count_before_finish == 0)
        || maximum_drain_batch_record_count == 0
        || maximum_drain_batch_record_count > MAX_DRAIN_BATCH_RECORD_COUNT_V1
        || decimal_u64_v1(&wire.dropped_event_count)? != 0
        || decimal_u64_v1(&wire.discarded_record_count)? != 0
        || !wire.continuous_drain
        || !wire.coverage_complete
        || wire.evidence_truncated
        || !wire.process_sensor_healthy
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidCoverage);
    }
    Ok(source_event_count)
}

fn validate_leader_v1(
    wire: &RootProcessLeaderWireV1,
    expected: &LinuxVzPackageExpectedRootProcessEvidenceV1,
    source_event_count: u64,
) -> Result<(), LinuxVzPackageRootProcessEvidenceErrorV1> {
    let first_exec = decimal_u64_v1(&wire.first_exec_monotonic_nanoseconds)?;
    let exit = decimal_u64_v1(&wire.leader_exit_monotonic_nanoseconds)?;
    let leader_exec_count = decimal_u64_v1(&wire.leader_exec_count)?;
    let completion = &expected.completion;
    if !wire.descendant_teardown_complete
        || leader_exec_count == 0
        || leader_exec_count > source_event_count
        || first_exec < completion.process_started_monotonic_nanoseconds()
        || first_exec >= exit
        || exit > completion.process_ended_monotonic_nanoseconds()
        || decimal_u64_v1(&wire.process_started_monotonic_nanoseconds)?
            != completion.process_started_monotonic_nanoseconds()
        || decimal_u64_v1(&wire.process_ended_monotonic_nanoseconds)?
            != completion.process_ended_monotonic_nanoseconds()
        || decimal_u16_v1(&wire.kernel_wait_status)? != completion.supervisor_wait_status()
        || decimal_u16_v1(&wire.supervisor_wait_status)? != completion.supervisor_wait_status()
        || wire.terminal != completion.terminal()
        || optional_u8_v1(wire.exit_status.as_deref(), true)? != completion.exit_status()
        || optional_u8_v1(wire.termination_signal.as_deref(), false)?
            != completion.termination_signal()
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::IncompleteLeaderLifecycle);
    }
    Ok(())
}

fn validate_observations_v1(
    wires: Vec<RootProcessObservationWireV1>,
    expected: &LinuxVzPackageExpectedRootProcessEvidenceV1,
    leader: &RootProcessLeaderWireV1,
    online_cpus: &[u32],
    source_event_count: u64,
) -> Result<Vec<LinuxVzPackageRootProcessObservationV1>, LinuxVzPackageRootProcessEvidenceErrorV1> {
    let expected_first_exec = decimal_u64_v1(&leader.first_exec_monotonic_nanoseconds)?;
    let expected_exit = decimal_u64_v1(&leader.leader_exit_monotonic_nanoseconds)?;
    let expected_exec_count = decimal_u64_v1(&leader.leader_exec_count)?;
    let expected_wait_status = decimal_u16_v1(&leader.kernel_wait_status)?;
    let mut last_observation_first_source_sequence = 0_u64;
    let mut last_observation_first_timestamp = 0_u64;
    let mut source_events = Vec::with_capacity(source_event_count as usize);
    let mut leader_exec_count = 0_u64;
    let mut leader_first_exec = None;
    let mut leader_exit = None;
    let mut observations = Vec::with_capacity(wires.len());
    for wire in wires {
        match wire {
            RootProcessObservationWireV1::Lifecycle {
                cgroup_id,
                cpu,
                kernel_wait_status,
                lifecycle_kind,
                parent_pid,
                pid,
                source_sequence,
                subject_pid,
                tgid,
                timestamp_monotonic_nanoseconds,
            } => {
                let source_sequence = decimal_u64_v1(&source_sequence)?;
                let timestamp = decimal_u64_v1(&timestamp_monotonic_nanoseconds)?;
                let pid = decimal_u32_v1(&pid)?;
                let tgid = decimal_u32_v1(&tgid)?;
                let parent_pid = decimal_u32_allow_zero_v1(&parent_pid)?;
                let subject_pid = decimal_u32_v1(&subject_pid)?;
                let wait_status = kernel_wait_status
                    .as_deref()
                    .map(decimal_u16_v1)
                    .transpose()?;
                let kind = parse_lifecycle_kind_v1(&lifecycle_kind)?;
                let valid_kind = match kind {
                    LinuxVzPackageRootProcessLifecycleKindV1::Fork => {
                        parent_pid == pid && subject_pid != pid && wait_status.is_none()
                    }
                    LinuxVzPackageRootProcessLifecycleKindV1::Exec => {
                        parent_pid == 0 && subject_pid == pid && wait_status.is_none()
                    }
                    LinuxVzPackageRootProcessLifecycleKindV1::Exit => {
                        parent_pid == 0 && subject_pid == pid && wait_status.is_some()
                    }
                };
                let cpu = decimal_u32_v1(&cpu)?;
                if source_sequence <= last_observation_first_source_sequence
                    || timestamp <= last_observation_first_timestamp
                    || timestamp < expected.completion.process_started_monotonic_nanoseconds()
                    || timestamp > expected.completion.process_ended_monotonic_nanoseconds()
                    || decimal_u64_v1(&cgroup_id)? != expected.cgroup_id
                    || pid <= 1
                    || tgid <= 1
                    || subject_pid <= 1
                    || !online_cpus.contains(&cpu)
                    || !valid_kind
                {
                    return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation);
                }
                if pid == expected.leader_pid
                    && tgid == expected.leader_pid
                    && subject_pid == expected.leader_pid
                {
                    match kind {
                        LinuxVzPackageRootProcessLifecycleKindV1::Exec => {
                            leader_exec_count = leader_exec_count.checked_add(1).ok_or(
                                LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation,
                            )?;
                            leader_first_exec.get_or_insert(timestamp);
                        }
                        LinuxVzPackageRootProcessLifecycleKindV1::Exit => {
                            if leader_exit.replace((timestamp, wait_status)).is_some() {
                                return Err(
                                    LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation,
                                );
                            }
                        }
                        LinuxVzPackageRootProcessLifecycleKindV1::Fork => {}
                    }
                }
                last_observation_first_source_sequence = source_sequence;
                last_observation_first_timestamp = timestamp;
                source_events.push((source_sequence, timestamp));
                observations.push(LinuxVzPackageRootProcessObservationV1::Lifecycle(
                    LinuxVzPackageRootProcessLifecycleObservationV1 {
                        kind,
                        source_sequence,
                        timestamp_monotonic_nanoseconds: timestamp,
                        pid,
                        tgid,
                        parent_pid,
                        subject_pid,
                        kernel_wait_status: wait_status,
                        cpu,
                    },
                ));
            }
            RootProcessObservationWireV1::Syscall {
                argument_vector_sha256,
                cgroup_id,
                enter_cpu,
                enter_source_sequence,
                enter_timestamp_monotonic_nanoseconds,
                exit_cpu,
                exit_source_sequence,
                exit_timestamp_monotonic_nanoseconds,
                pid,
                result,
                safe_argument_zero,
                syscall,
                tgid,
            } => {
                let enter_sequence = decimal_u64_v1(&enter_source_sequence)?;
                let exit_sequence = decimal_u64_v1(&exit_source_sequence)?;
                let enter_timestamp = decimal_u64_v1(&enter_timestamp_monotonic_nanoseconds)?;
                let exit_timestamp = decimal_u64_v1(&exit_timestamp_monotonic_nanoseconds)?;
                let syscall = parse_syscall_v1(&syscall)?;
                let safe_argument_zero = safe_argument_zero
                    .as_deref()
                    .map(decimal_u64_v1)
                    .transpose()?;
                let credential_syscall = matches!(
                    syscall,
                    LinuxVzPackageRootProcessSyscallV1::Setgid
                        | LinuxVzPackageRootProcessSyscallV1::Setuid
                        | LinuxVzPackageRootProcessSyscallV1::Setgroups
                );
                let enter_cpu = decimal_u32_v1(&enter_cpu)?;
                let exit_cpu = decimal_u32_v1(&exit_cpu)?;
                if enter_sequence <= last_observation_first_source_sequence
                    || exit_sequence <= enter_sequence
                    || enter_timestamp <= last_observation_first_timestamp
                    || exit_timestamp <= enter_timestamp
                    || enter_timestamp < expected.completion.process_started_monotonic_nanoseconds()
                    || exit_timestamp > expected.completion.process_ended_monotonic_nanoseconds()
                    || decimal_u64_v1(&cgroup_id)? != expected.cgroup_id
                    || argument_vector_sha256 == Sha256Digest::from_bytes(&[])
                    || credential_syscall != safe_argument_zero.is_some()
                    || !online_cpus.contains(&enter_cpu)
                    || !online_cpus.contains(&exit_cpu)
                {
                    return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation);
                }
                let pid = decimal_u32_v1(&pid)?;
                let tgid = decimal_u32_v1(&tgid)?;
                if pid <= 1 || tgid <= 1 {
                    return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation);
                }
                last_observation_first_source_sequence = enter_sequence;
                last_observation_first_timestamp = enter_timestamp;
                source_events.push((enter_sequence, enter_timestamp));
                source_events.push((exit_sequence, exit_timestamp));
                observations.push(LinuxVzPackageRootProcessObservationV1::Syscall(
                    LinuxVzPackageRootProcessSyscallObservationV1 {
                        syscall,
                        enter_source_sequence: enter_sequence,
                        exit_source_sequence: exit_sequence,
                        enter_timestamp_monotonic_nanoseconds: enter_timestamp,
                        exit_timestamp_monotonic_nanoseconds: exit_timestamp,
                        pid,
                        tgid,
                        argument_vector_sha256,
                        safe_argument_zero,
                        result: decimal_i64_v1(&result)?,
                        enter_cpu,
                        exit_cpu,
                    },
                ));
            }
        }
    }
    source_events.sort_unstable_by_key(|(sequence, _)| *sequence);
    let mut last_source_timestamp = 0_u64;
    let global_sequence_complete = source_events.len() == source_event_count as usize
        && source_events
            .iter()
            .enumerate()
            .all(|(index, (sequence, timestamp))| {
                let valid = *sequence == index as u64 + 1 && *timestamp > last_source_timestamp;
                last_source_timestamp = *timestamp;
                valid
            });
    if !global_sequence_complete
        || leader_exec_count != expected_exec_count
        || leader_first_exec != Some(expected_first_exec)
        || leader_exit != Some((expected_exit, Some(expected_wait_status)))
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::IncompleteLeaderLifecycle);
    }
    Ok(observations)
}

fn lifecycle_name_v1(kind: LinuxVzPackageKernelEventKindV1) -> &'static str {
    match kind {
        LinuxVzPackageKernelEventKindV1::Fork => "fork",
        LinuxVzPackageKernelEventKindV1::Exec => "exec",
        LinuxVzPackageKernelEventKindV1::Exit => "exit",
        LinuxVzPackageKernelEventKindV1::SyscallEnter
        | LinuxVzPackageKernelEventKindV1::SyscallExit => {
            unreachable!("correlated lifecycle observations exclude syscall halves")
        }
    }
}

fn parse_lifecycle_kind_v1(
    value: &str,
) -> Result<LinuxVzPackageRootProcessLifecycleKindV1, LinuxVzPackageRootProcessEvidenceErrorV1> {
    match value {
        "fork" => Ok(LinuxVzPackageRootProcessLifecycleKindV1::Fork),
        "exec" => Ok(LinuxVzPackageRootProcessLifecycleKindV1::Exec),
        "exit" => Ok(LinuxVzPackageRootProcessLifecycleKindV1::Exit),
        _ => Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation),
    }
}

fn parse_syscall_v1(
    value: &str,
) -> Result<LinuxVzPackageRootProcessSyscallV1, LinuxVzPackageRootProcessEvidenceErrorV1> {
    match value {
        "setgid" => Ok(LinuxVzPackageRootProcessSyscallV1::Setgid),
        "setuid" => Ok(LinuxVzPackageRootProcessSyscallV1::Setuid),
        "setgroups" => Ok(LinuxVzPackageRootProcessSyscallV1::Setgroups),
        "connect" => Ok(LinuxVzPackageRootProcessSyscallV1::Connect),
        "sendto" => Ok(LinuxVzPackageRootProcessSyscallV1::Sendto),
        "mmap" => Ok(LinuxVzPackageRootProcessSyscallV1::Mmap),
        _ => Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation),
    }
}

fn safe_argument_zero_v1(
    syscall: LinuxVzPackageSelectedSyscallV1,
    arguments: &[u64; 6],
) -> Option<u64> {
    matches!(
        syscall,
        LinuxVzPackageSelectedSyscallV1::Setgid
            | LinuxVzPackageSelectedSyscallV1::Setuid
            | LinuxVzPackageSelectedSyscallV1::Setgroups
    )
    .then_some(arguments[0])
}

fn syscall_argument_vector_sha256_v1(
    syscall: LinuxVzPackageSelectedSyscallV1,
    arguments: &[u64; 6],
) -> Sha256Digest {
    let mut bytes = Vec::with_capacity(48 + 64);
    bytes.extend_from_slice(b"whoathere.linux_vz_package_syscall_arguments.v1\0");
    bytes.extend_from_slice(&(syscall as u32).to_le_bytes());
    for argument in arguments {
        bytes.extend_from_slice(&argument.to_le_bytes());
    }
    Sha256Digest::from_bytes(&bytes)
}

fn decode_canonical_v1<T>(
    bytes: &[u8],
) -> Result<(T, Vec<u8>), LinuxVzPackageRootProcessEvidenceErrorV1>
where
    T: DeserializeOwned + Serialize,
{
    if bytes.is_empty() {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = T::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::InvalidJson)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::NonCanonical);
    }
    Ok((wire, canonical))
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzPackageRootProcessEvidenceErrorV1> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation)
}

fn decimal_i64_v1(value: &str) -> Result<i64, LinuxVzPackageRootProcessEvidenceErrorV1> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || (digits.len() > 1 && digits.starts_with('0'))
        || value == "-0"
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation)
}

fn decimal_u32_v1(value: &str) -> Result<u32, LinuxVzPackageRootProcessEvidenceErrorV1> {
    let value = decimal_u64_v1(value)?;
    u32::try_from(value).map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation)
}

fn decimal_u32_allow_zero_v1(value: &str) -> Result<u32, LinuxVzPackageRootProcessEvidenceErrorV1> {
    decimal_u32_v1(value)
}

fn decimal_u16_v1(value: &str) -> Result<u16, LinuxVzPackageRootProcessEvidenceErrorV1> {
    let value = decimal_u64_v1(value)?;
    u16::try_from(value).map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation)
}

fn decimal_usize_v1(value: &str) -> Result<usize, LinuxVzPackageRootProcessEvidenceErrorV1> {
    let value = decimal_u64_v1(value)?;
    usize::try_from(value).map_err(|_| LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation)
}

fn optional_u8_v1(
    value: Option<&str>,
    zero_permitted: bool,
) -> Result<Option<u8>, LinuxVzPackageRootProcessEvidenceErrorV1> {
    value
        .map(|value| {
            let value = decimal_u64_v1(value)?;
            if value > u8::MAX as u64 || (!zero_permitted && !(1..=64).contains(&value)) {
                return Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation);
            }
            Ok(value as u8)
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_vz_package_sensor_event_stream::{
        decode_linux_vz_package_kernel_event_v1, LINUX_VZ_PACKAGE_KERNEL_EVENT_BYTES_V1,
    };
    use crate::linux_vz_package_sensor_process_collector::LinuxVzPackageRootProcessCollectionV1;
    use crate::linux_vz_package_sensor_process_stream::LinuxVzPackageProcessEventCorrelatorV1;
    use serde_json::Value;

    const CGROUP_ID_V1: u64 = 71;
    const ROOT_RUNNER_PID_V1: u32 = 400;
    const LEADER_PID_V1: u32 = 401;

    fn kernel_event_v1(
        kind: LinuxVzPackageKernelEventKindV1,
        sequence: u64,
        timestamp: u64,
        syscall: Option<LinuxVzPackageSelectedSyscallV1>,
        arguments: [u64; 6],
        result: Option<i64>,
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
        bytes[16..24].copy_from_slice(&CGROUP_ID_V1.to_le_bytes());
        bytes[24..32].copy_from_slice(&timestamp.to_le_bytes());
        bytes[32..36].copy_from_slice(&LEADER_PID_V1.to_le_bytes());
        bytes[36..40].copy_from_slice(&LEADER_PID_V1.to_le_bytes());
        bytes[44..48].copy_from_slice(&LEADER_PID_V1.to_le_bytes());
        bytes[48..52].copy_from_slice(&(syscall.map_or(0, |value| value as u32)).to_le_bytes());
        bytes[56..64].copy_from_slice(&result.unwrap_or_default().to_le_bytes());
        for (index, argument) in arguments.iter().enumerate() {
            bytes[64 + index * 8..72 + index * 8].copy_from_slice(&argument.to_le_bytes());
        }
        bytes[184..188].copy_from_slice(&1_u32.to_le_bytes());
        decode_linux_vz_package_kernel_event_v1(&bytes, CGROUP_ID_V1, sequence)
            .expect("kernel event")
    }

    fn expected_and_collection_v1() -> (
        LinuxVzPackageExpectedRootProcessEvidenceV1,
        LinuxVzPackageRootProcessCollectionV1,
    ) {
        let completion = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            50,
            500,
            0,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("completion");
        let identity = LinuxVzPackageProcessLaunchIdentityV1::from_bound_digests_v1(
            Sha256Digest::from_bytes(b"executable"),
            Sha256Digest::from_bytes(b"argv"),
            2,
        )
        .expect("identity");
        let expected = LinuxVzPackageExpectedRootProcessEvidenceV1::from_action_v1(
            Sha256Digest::from_bytes(b"session challenge"),
            Sha256Digest::from_bytes(b"launch contract"),
            Sha256Digest::from_bytes(b"process plan"),
            3,
            "whoathere-package-action-3".to_string(),
            CGROUP_ID_V1,
            ROOT_RUNNER_PID_V1,
            LEADER_PID_V1,
            &identity,
            &completion,
        )
        .expect("expected binding");
        let mut correlator =
            LinuxVzPackageProcessEventCorrelatorV1::new_v1(CGROUP_ID_V1, 8).expect("correlator");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::Exec,
                1,
                100,
                None,
                [0; 6],
                None,
            ))
            .expect("exec");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::SyscallEnter,
                2,
                200,
                Some(LinuxVzPackageSelectedSyscallV1::Setuid),
                [u64::from(PACKAGE_UID_V1), 0, 0, 0, 0, 0],
                None,
            ))
            .expect("setuid enter");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::SyscallExit,
                3,
                300,
                Some(LinuxVzPackageSelectedSyscallV1::Setuid),
                [0; 6],
                Some(0),
            ))
            .expect("setuid exit");
        correlator
            .ingest_v1(kernel_event_v1(
                LinuxVzPackageKernelEventKindV1::Exit,
                4,
                400,
                None,
                [0; 6],
                Some(0),
            ))
            .expect("exit");
        let stream = correlator.finish_v1(0, 0, 4).expect("stream");
        let collection = LinuxVzPackageRootProcessCollectionV1::from_test_stream_v1(
            stream,
            LEADER_PID_V1,
            &completion,
        )
        .expect("collection");
        (expected, collection)
    }

    #[test]
    fn reason_codes_are_stable_and_syscall_argument_hashes_are_domain_separated() {
        assert_eq!(
            LinuxVzPackageRootProcessEvidenceErrorV1::BindingMismatch.reason_code(),
            "linux_vz_package_root_process_evidence_binding_mismatch"
        );
        let arguments = [1, 2, 3, 4, 5, 6];
        assert_ne!(
            syscall_argument_vector_sha256_v1(LinuxVzPackageSelectedSyscallV1::Setuid, &arguments),
            syscall_argument_vector_sha256_v1(LinuxVzPackageSelectedSyscallV1::Setgid, &arguments)
        );
    }

    #[test]
    fn strict_decimal_parsers_reject_noncanonical_values() {
        assert_eq!(decimal_u64_v1("0"), Ok(0));
        assert_eq!(decimal_i64_v1("-1"), Ok(-1));
        for value in ["", "01", "+1", " 1"] {
            assert!(decimal_u64_v1(value).is_err());
        }
        for value in ["", "01", "-0", "-01", "+1"] {
            assert!(decimal_i64_v1(value).is_err());
        }
    }

    #[test]
    fn expected_binding_rejects_unsafe_names_and_identity_aliases() {
        let digest = Sha256Digest::from_bytes(b"same");
        let identity = LinuxVzPackageProcessLaunchIdentityV1::from_bound_digests_v1(
            Sha256Digest::from_bytes(b"executable"),
            Sha256Digest::from_bytes(b"argv"),
            2,
        )
        .expect("identity");
        let completion = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            10,
            20,
            0,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("completion");
        assert_eq!(
            LinuxVzPackageExpectedRootProcessEvidenceV1::from_action_v1(
                digest.clone(),
                Sha256Digest::from_bytes(b"contract"),
                Sha256Digest::from_bytes(b"plan"),
                0,
                "../escape".to_string(),
                9,
                10,
                11,
                &identity,
                &completion,
            ),
            Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidExpectedBinding)
        );
        assert_eq!(
            LinuxVzPackageExpectedRootProcessEvidenceV1::from_action_v1(
                digest.clone(),
                digest,
                Sha256Digest::from_bytes(b"plan"),
                0,
                "whoathere-package-action-0".to_string(),
                9,
                10,
                11,
                &identity,
                &completion,
            ),
            Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidExpectedBinding)
        );
    }

    #[test]
    fn exact_collection_round_trips_as_bound_canonical_process_evidence() {
        let (expected, collection) = expected_and_collection_v1();
        let encoded = encode_linux_vz_package_root_process_evidence_v1(&expected, &collection)
            .expect("encoded evidence");
        let decoded = decode_linux_vz_package_root_process_evidence_v1(
            &expected,
            encoded.canonical_json_v1(),
        )
        .expect("decoded evidence");
        assert_eq!(decoded.source_event_count(), 4);
        assert_eq!(decoded.observations().len(), 3);
        assert!(decoded.coverage_complete());
        assert!(!decoded.raw_arguments_captured());
        assert!(!decoded.raw_exec_paths_captured());
        assert_eq!(decoded.payload_sha256(), encoded.payload_sha256());
        assert_eq!(
            decoded.runtime_btf_sha256(),
            collection.runtime_btf_sha256_v1()
        );
        assert_eq!(decoded.task_exit_code_byte_offset(), 96);
        assert_eq!(decoded.tracepoint_format_sha256().len(), 5);
        assert_eq!(decoded.online_cpus(), &[0, 1]);
        assert_eq!(decoded.attachment_cpu(), 1);
        assert_eq!(decoded.leader_exec_count(), 1);
        assert_eq!(decoded.leader_kernel_wait_status(), 0);
        assert_eq!(decoded.leader_supervisor_wait_status(), 0);
        let LinuxVzPackageRootProcessObservationV1::Syscall(syscall) = &decoded.observations()[1]
        else {
            panic!("second observation must be the correlated syscall");
        };
        assert_eq!(
            syscall.syscall(),
            LinuxVzPackageRootProcessSyscallV1::Setuid
        );
        assert_eq!(
            syscall.safe_argument_zero(),
            Some(u64::from(PACKAGE_UID_V1))
        );
        assert_eq!(syscall.result(), 0);
    }

    #[test]
    fn binding_sequence_loss_and_raw_capture_upgrades_fail_closed() {
        let (expected, collection) = expected_and_collection_v1();
        let encoded = encode_linux_vz_package_root_process_evidence_v1(&expected, &collection)
            .expect("encoded evidence");
        let mut wire: Value =
            serde_json::from_slice(encoded.canonical_json_v1()).expect("wire json");

        wire["binding"]["cgroup_id"] = Value::String("72".to_string());
        let changed = serde_json_canonicalizer::to_vec(&wire).expect("canonical changed binding");
        assert_eq!(
            decode_linux_vz_package_root_process_evidence_v1(&expected, &changed),
            Err(LinuxVzPackageRootProcessEvidenceErrorV1::BindingMismatch)
        );

        wire = serde_json::from_slice(encoded.canonical_json_v1()).expect("wire json");
        wire["observations"][1]["enter_source_sequence"] = Value::String("3".to_string());
        let changed = serde_json_canonicalizer::to_vec(&wire).expect("canonical changed sequence");
        assert_eq!(
            decode_linux_vz_package_root_process_evidence_v1(&expected, &changed),
            Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidObservation)
        );

        wire = serde_json::from_slice(encoded.canonical_json_v1()).expect("wire json");
        wire["raw_arguments_captured"] = Value::Bool(true);
        let changed = serde_json_canonicalizer::to_vec(&wire).expect("canonical raw upgrade");
        assert_eq!(
            decode_linux_vz_package_root_process_evidence_v1(&expected, &changed),
            Err(LinuxVzPackageRootProcessEvidenceErrorV1::InvalidCoverage)
        );

        let pretty = serde_json::to_vec_pretty(&wire).expect("pretty json");
        assert_eq!(
            decode_linux_vz_package_root_process_evidence_v1(&expected, &pretty),
            Err(LinuxVzPackageRootProcessEvidenceErrorV1::NonCanonical)
        );
    }

    #[test]
    fn interleaved_thread_pairs_preserve_one_complete_global_source_sequence() {
        let (expected, collection) = expected_and_collection_v1();
        let encoded = encode_linux_vz_package_root_process_evidence_v1(&expected, &collection)
            .expect("encoded evidence");
        let mut wire: Value =
            serde_json::from_slice(encoded.canonical_json_v1()).expect("wire json");
        let mut nested = wire["observations"][1].clone();
        wire["observations"][1]["exit_source_sequence"] = Value::String("5".to_string());
        wire["observations"][1]["exit_timestamp_monotonic_nanoseconds"] =
            Value::String("400".to_string());
        nested["enter_source_sequence"] = Value::String("3".to_string());
        nested["enter_timestamp_monotonic_nanoseconds"] = Value::String("250".to_string());
        nested["exit_source_sequence"] = Value::String("4".to_string());
        nested["exit_timestamp_monotonic_nanoseconds"] = Value::String("300".to_string());
        wire["observations"]
            .as_array_mut()
            .expect("observation array")
            .insert(2, nested);
        wire["observations"][3]["source_sequence"] = Value::String("6".to_string());
        wire["observations"][3]["timestamp_monotonic_nanoseconds"] =
            Value::String("450".to_string());
        wire["coverage"]["source_event_count"] = Value::String("6".to_string());
        wire["coverage"]["source_event_count_before_finish"] = Value::String("6".to_string());
        wire["coverage"]["observation_count"] = Value::String("4".to_string());
        wire["coverage"]["maximum_drain_batch_record_count"] = Value::String("6".to_string());
        wire["leader"]["leader_exit_monotonic_nanoseconds"] = Value::String("450".to_string());
        let changed = serde_json_canonicalizer::to_vec(&wire).expect("interleaved evidence");
        let decoded = decode_linux_vz_package_root_process_evidence_v1(&expected, &changed)
            .expect("interleaved pairs are valid");
        assert_eq!(decoded.source_event_count(), 6);
        assert_eq!(decoded.observations().len(), 4);
    }
}
