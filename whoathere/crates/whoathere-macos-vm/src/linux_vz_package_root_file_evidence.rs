#![cfg_attr(not(any(target_os = "linux", test)), allow(dead_code))]

use crate::linux_vz_package_sensor_file_collector::{
    path_class_name_v1, root_file_path_token_v1, LinuxVzPackageRootFileChangeV1,
    LinuxVzPackageRootFileCollectionV1, LinuxVzPackageRootFilePathNamespaceV1,
    LinuxVzPackageRootFileSnapshotV1, MAX_ROOT_FILE_DIFF_CHANGES_V1,
    MAX_ROOT_FILE_SNAPSHOT_ENTRIES_V1, MAX_ROOT_FILE_SNAPSHOT_REGULAR_BYTES_V1,
    MAX_ROOT_FILE_SOURCE_EVENTS_V1,
};
use crate::{
    LinuxVzPackageFilePathClassV1, LinuxVzPackageProcessCompletionV1,
    MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_ROOT_FILE_EVIDENCE_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_root_file_evidence.v1";

const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;
const REQUIRED_FANOTIFY_MARK_COUNT_V1: u64 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootFileEvidenceErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidExpectedBinding,
    BindingMismatch,
    InvalidCoverage,
    InvalidSnapshot,
    InvalidEvent,
    InvalidChange,
    Serialization,
}

impl LinuxVzPackageRootFileEvidenceErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_root_file_evidence_empty",
            Self::LimitExceeded => "linux_vz_package_root_file_evidence_limit_exceeded",
            Self::InvalidJson => "linux_vz_package_root_file_evidence_json_invalid",
            Self::NonCanonical => "linux_vz_package_root_file_evidence_noncanonical",
            Self::InvalidExpectedBinding => {
                "linux_vz_package_root_file_evidence_expected_binding_invalid"
            }
            Self::BindingMismatch => "linux_vz_package_root_file_evidence_binding_mismatch",
            Self::InvalidCoverage => "linux_vz_package_root_file_evidence_coverage_invalid",
            Self::InvalidSnapshot => "linux_vz_package_root_file_evidence_snapshot_invalid",
            Self::InvalidEvent => "linux_vz_package_root_file_evidence_event_invalid",
            Self::InvalidChange => "linux_vz_package_root_file_evidence_change_invalid",
            Self::Serialization => "linux_vz_package_root_file_evidence_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootFileEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootFileEvidenceErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageExpectedRootFileEvidenceV1 {
    sensor_session_challenge_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    cgroup_name: String,
    cgroup_id: u64,
    root_runner_pid: u32,
    leader_pid: u32,
    completion: LinuxVzPackageProcessCompletionV1,
}

impl LinuxVzPackageExpectedRootFileEvidenceV1 {
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
        completion: &LinuxVzPackageProcessCompletionV1,
    ) -> Result<Self, LinuxVzPackageRootFileEvidenceErrorV1> {
        let expected = Self {
            sensor_session_challenge_sha256,
            launch_contract_sha256,
            process_plan_sha256,
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

    fn validate_v1(&self) -> Result<(), LinuxVzPackageRootFileEvidenceErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let digests = [
            &self.sensor_session_challenge_sha256,
            &self.launch_contract_sha256,
            &self.process_plan_sha256,
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
            return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidExpectedBinding);
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
pub enum LinuxVzPackageRootFileEvidenceEventKindV1 {
    Open,
    Read,
    Write,
    OpenExec,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootFileEvidenceAccessOutcomeV1 {
    Observed,
    Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootFileEvidencePathNamespaceV1 {
    Absolute,
    WorkspaceRelative,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootFileEvidenceChangeKindV1 {
    Created,
    Modified,
    Deleted,
    Renamed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootFileEvidenceEntryKindV1 {
    Directory,
    Regular,
    Symlink,
    Fifo,
    Socket,
    CharacterDevice,
    BlockDevice,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootFileEvidenceEventV1 {
    kind: LinuxVzPackageRootFileEvidenceEventKindV1,
    path_class: LinuxVzPackageFilePathClassV1,
    namespace: LinuxVzPackageRootFileEvidencePathNamespaceV1,
    outcome: LinuxVzPackageRootFileEvidenceAccessOutcomeV1,
    source_sequence: u64,
    timestamp_monotonic_nanoseconds: u64,
    actor_pid: u32,
    cgroup_id: u64,
    path_token_sha256: Sha256Digest,
}

impl LinuxVzPackageRootFileEvidenceEventV1 {
    pub const fn kind(&self) -> LinuxVzPackageRootFileEvidenceEventKindV1 {
        self.kind
    }

    pub const fn path_class(&self) -> LinuxVzPackageFilePathClassV1 {
        self.path_class
    }

    pub const fn namespace(&self) -> LinuxVzPackageRootFileEvidencePathNamespaceV1 {
        self.namespace
    }

    pub const fn outcome(&self) -> LinuxVzPackageRootFileEvidenceAccessOutcomeV1 {
        self.outcome
    }

    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    pub const fn timestamp_monotonic_nanoseconds(&self) -> u64 {
        self.timestamp_monotonic_nanoseconds
    }

    pub const fn actor_pid(&self) -> u32 {
        self.actor_pid
    }

    pub const fn cgroup_id(&self) -> u64 {
        self.cgroup_id
    }

    pub fn path_token_sha256(&self) -> &Sha256Digest {
        &self.path_token_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootFileEvidenceChangeV1 {
    kind: LinuxVzPackageRootFileEvidenceChangeKindV1,
    path_class: LinuxVzPackageFilePathClassV1,
    path_token_sha256: Sha256Digest,
    secondary_path_class: Option<LinuxVzPackageFilePathClassV1>,
    secondary_path_token_sha256: Option<Sha256Digest>,
    prior_entry_kind: Option<LinuxVzPackageRootFileEvidenceEntryKindV1>,
    final_entry_kind: Option<LinuxVzPackageRootFileEvidenceEntryKindV1>,
    content_changed: bool,
    metadata_changed: bool,
    change_record_sha256: Sha256Digest,
}

impl LinuxVzPackageRootFileEvidenceChangeV1 {
    pub const fn kind(&self) -> LinuxVzPackageRootFileEvidenceChangeKindV1 {
        self.kind
    }

    pub const fn path_class(&self) -> LinuxVzPackageFilePathClassV1 {
        self.path_class
    }

    pub fn path_token_sha256(&self) -> &Sha256Digest {
        &self.path_token_sha256
    }

    pub const fn secondary_path_class(&self) -> Option<LinuxVzPackageFilePathClassV1> {
        self.secondary_path_class
    }

    pub fn secondary_path_token_sha256(&self) -> Option<&Sha256Digest> {
        self.secondary_path_token_sha256.as_ref()
    }

    pub const fn prior_entry_kind(&self) -> Option<LinuxVzPackageRootFileEvidenceEntryKindV1> {
        self.prior_entry_kind
    }

    pub const fn final_entry_kind(&self) -> Option<LinuxVzPackageRootFileEvidenceEntryKindV1> {
        self.final_entry_kind
    }

    pub const fn content_changed(&self) -> bool {
        self.content_changed
    }

    pub const fn metadata_changed(&self) -> bool {
        self.metadata_changed
    }

    pub fn change_record_sha256(&self) -> &Sha256Digest {
        &self.change_record_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootFileEvidenceV1 {
    canonical_json: Vec<u8>,
    payload_sha256: Sha256Digest,
    baseline_snapshot_sha256: Sha256Digest,
    final_snapshot_sha256: Sha256Digest,
    workspace_diff_sha256: Sha256Digest,
    events: Vec<LinuxVzPackageRootFileEvidenceEventV1>,
    changes: Vec<LinuxVzPackageRootFileEvidenceChangeV1>,
    diff_completed_monotonic_nanoseconds: u64,
    active_drain_poll_count: u64,
    active_nonempty_drain_count: u64,
    maximum_drain_batch_event_count: u64,
    ignored_non_cgroup_event_count: u64,
    permission_response_count: u64,
    permission_denied_count: u64,
}

impl LinuxVzPackageRootFileEvidenceV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn baseline_snapshot_sha256(&self) -> &Sha256Digest {
        &self.baseline_snapshot_sha256
    }

    pub fn final_snapshot_sha256(&self) -> &Sha256Digest {
        &self.final_snapshot_sha256
    }

    pub fn workspace_diff_sha256(&self) -> &Sha256Digest {
        &self.workspace_diff_sha256
    }

    pub fn events(&self) -> &[LinuxVzPackageRootFileEvidenceEventV1] {
        &self.events
    }

    pub fn changes(&self) -> &[LinuxVzPackageRootFileEvidenceChangeV1] {
        &self.changes
    }

    pub const fn diff_completed_monotonic_nanoseconds(&self) -> u64 {
        self.diff_completed_monotonic_nanoseconds
    }

    pub const fn active_drain_poll_count(&self) -> u64 {
        self.active_drain_poll_count
    }

    pub const fn active_nonempty_drain_count(&self) -> u64 {
        self.active_nonempty_drain_count
    }

    pub const fn maximum_drain_batch_event_count(&self) -> u64 {
        self.maximum_drain_batch_event_count
    }

    pub const fn ignored_non_cgroup_event_count(&self) -> u64 {
        self.ignored_non_cgroup_event_count
    }

    pub const fn permission_response_count(&self) -> u64 {
        self.permission_response_count
    }

    pub const fn permission_denied_count(&self) -> u64 {
        self.permission_denied_count
    }

    pub const fn declared_scope_complete(&self) -> bool {
        true
    }

    pub const fn global_mount_coverage_complete(&self) -> bool {
        false
    }

    pub const fn raw_paths_captured(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFileEvidenceWireV1 {
    binding: RootFileBindingWireV1,
    changes: Vec<RootFileChangeWireV1>,
    coverage: RootFileCoverageWireV1,
    events: Vec<RootFileEventWireV1>,
    raw_paths_captured: bool,
    schema_version: String,
    snapshots: RootFileSnapshotsWireV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFileBindingWireV1 {
    action_index: String,
    cgroup_id: String,
    cgroup_name: String,
    launch_contract_sha256: Sha256Digest,
    leader_pid: String,
    package_gid: String,
    package_uid: String,
    process_ended_monotonic_nanoseconds: String,
    process_plan_sha256: Sha256Digest,
    process_started_monotonic_nanoseconds: String,
    root_runner_pid: String,
    sensor_session_challenge_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFileCoverageWireV1 {
    active_drain_poll_count: String,
    active_nonempty_drain_count: String,
    baseline_entry_count: String,
    baseline_regular_file_bytes_hashed: String,
    change_count: String,
    continuous_drain: bool,
    declared_scope_complete: bool,
    descriptor_relative_workspace_snapshots: bool,
    diff_completed_monotonic_nanoseconds: String,
    evidence_truncated: bool,
    fanotify_event_kinds: Vec<String>,
    fanotify_mark_scope: Vec<String>,
    fanotify_overflow_count: String,
    fanotify_permission_events_enforced: bool,
    fanotify_unobserved_mounts: Vec<String>,
    file_sensor_healthy: bool,
    filesystem_diff_scope: String,
    final_entry_count: String,
    final_regular_file_bytes_hashed: String,
    ignored_non_cgroup_event_count: String,
    global_mount_coverage_complete: bool,
    maximum_drain_batch_event_count: String,
    permission_denied_count: String,
    permission_response_count: String,
    required_fanotify_mark_count: String,
    regular_file_contents_hashed: bool,
    source_event_count: String,
    symlink_targets_hashed: bool,
    workspace_diff_complete: bool,
    workspace_root_identity_stable: bool,
    workspace_snapshot_count: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFileSnapshotsWireV1 {
    baseline_snapshot_sha256: Sha256Digest,
    final_snapshot_sha256: Sha256Digest,
    workspace_diff_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFileEventWireV1 {
    access_outcome: String,
    actor_pid: String,
    cgroup_id: String,
    event_kind: String,
    path_class: String,
    path_namespace: String,
    path_token_sha256: Sha256Digest,
    source_sequence: String,
    timestamp_monotonic_nanoseconds: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootFileChangeWireV1 {
    change_kind: String,
    change_record_sha256: Sha256Digest,
    content_changed: bool,
    final_entry_kind: Option<String>,
    metadata_changed: bool,
    path_class: String,
    path_token_sha256: Sha256Digest,
    prior_entry_kind: Option<String>,
    secondary_path_class: Option<String>,
    secondary_path_token_sha256: Option<Sha256Digest>,
}

pub(crate) fn encode_linux_vz_package_root_file_evidence_v1(
    expected: &LinuxVzPackageExpectedRootFileEvidenceV1,
    collection: &LinuxVzPackageRootFileCollectionV1,
) -> Result<LinuxVzPackageRootFileEvidenceV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    expected.validate_v1()?;
    if collection.cgroup_id_v1() != expected.cgroup_id
        || collection.leader_pid_v1() != expected.leader_pid
        || collection.process_ended_monotonic_nanoseconds_v1()
            != expected.completion.process_ended_monotonic_nanoseconds()
    {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::BindingMismatch);
    }
    let baseline_snapshot_sha256 = snapshot_digest_v1(
        &expected.sensor_session_challenge_sha256,
        collection.baseline_v1(),
    )?;
    let final_snapshot_sha256 = snapshot_digest_v1(
        &expected.sensor_session_challenge_sha256,
        collection.final_snapshot_v1(),
    )?;
    let events = collection
        .events_v1()
        .iter()
        .map(|event| RootFileEventWireV1 {
            access_outcome: event.outcome_v1().as_str_v1().to_string(),
            actor_pid: event.actor_pid_v1().to_string(),
            cgroup_id: event.cgroup_id_v1().to_string(),
            event_kind: event.kind_v1().as_str_v1().to_string(),
            path_class: path_class_name_v1(event.path_class_v1()).to_string(),
            path_namespace: event.namespace_v1().as_str_v1().to_string(),
            path_token_sha256: event.path_token_sha256_v1().clone(),
            source_sequence: event.source_sequence_v1().to_string(),
            timestamp_monotonic_nanoseconds: event.timestamp_monotonic_nanoseconds_v1().to_string(),
        })
        .collect::<Vec<_>>();
    let changes = collection
        .changes_v1()
        .iter()
        .map(|change| change_wire_v1(expected, change))
        .collect::<Result<Vec<_>, _>>()?;
    let workspace_diff_sha256 =
        change_set_digest_v1(&expected.sensor_session_challenge_sha256, &changes)?;
    let wire = RootFileEvidenceWireV1 {
        binding: RootFileBindingWireV1 {
            action_index: expected.action_index.to_string(),
            cgroup_id: expected.cgroup_id.to_string(),
            cgroup_name: expected.cgroup_name.clone(),
            launch_contract_sha256: expected.launch_contract_sha256.clone(),
            leader_pid: expected.leader_pid.to_string(),
            package_gid: PACKAGE_GID_V1.to_string(),
            package_uid: PACKAGE_UID_V1.to_string(),
            process_ended_monotonic_nanoseconds: expected
                .completion
                .process_ended_monotonic_nanoseconds()
                .to_string(),
            process_plan_sha256: expected.process_plan_sha256.clone(),
            process_started_monotonic_nanoseconds: expected
                .completion
                .process_started_monotonic_nanoseconds()
                .to_string(),
            root_runner_pid: expected.root_runner_pid.to_string(),
            sensor_session_challenge_sha256: expected.sensor_session_challenge_sha256.clone(),
        },
        changes,
        coverage: RootFileCoverageWireV1 {
            active_drain_poll_count: collection.active_drain_poll_count_v1().to_string(),
            active_nonempty_drain_count: collection.active_nonempty_drain_count_v1().to_string(),
            baseline_entry_count: collection.baseline_v1().entry_count_v1().to_string(),
            baseline_regular_file_bytes_hashed: collection
                .baseline_v1()
                .regular_file_bytes_hashed_v1()
                .to_string(),
            change_count: collection.changes_v1().len().to_string(),
            continuous_drain: true,
            declared_scope_complete: true,
            descriptor_relative_workspace_snapshots: true,
            diff_completed_monotonic_nanoseconds: collection
                .diff_completed_monotonic_nanoseconds_v1()
                .to_string(),
            evidence_truncated: false,
            fanotify_event_kinds: [
                "access_permission",
                "close_write",
                "open_exec_permission",
                "open_permission",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            fanotify_mark_scope: [
                "dev_mount",
                "root_mount",
                "run_mount",
                "sys_mount",
                "workspace_mount",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            fanotify_overflow_count: collection.fanotify_overflow_count_v1().to_string(),
            fanotify_permission_events_enforced: true,
            fanotify_unobserved_mounts: ["proc_mount"].into_iter().map(str::to_string).collect(),
            file_sensor_healthy: true,
            filesystem_diff_scope: "workspace_mount".to_string(),
            final_entry_count: collection.final_snapshot_v1().entry_count_v1().to_string(),
            final_regular_file_bytes_hashed: collection
                .final_snapshot_v1()
                .regular_file_bytes_hashed_v1()
                .to_string(),
            ignored_non_cgroup_event_count: collection
                .ignored_non_cgroup_event_count_v1()
                .to_string(),
            global_mount_coverage_complete: false,
            maximum_drain_batch_event_count: collection
                .maximum_drain_batch_event_count_v1()
                .to_string(),
            permission_denied_count: collection.permission_denied_count_v1().to_string(),
            permission_response_count: collection.permission_response_count_v1().to_string(),
            required_fanotify_mark_count: collection.required_mark_count_v1().to_string(),
            regular_file_contents_hashed: true,
            source_event_count: collection.events_v1().len().to_string(),
            symlink_targets_hashed: true,
            workspace_diff_complete: true,
            workspace_root_identity_stable: collection.baseline_v1().root_device_v1()
                == collection.final_snapshot_v1().root_device_v1()
                && collection.baseline_v1().root_inode_v1()
                    == collection.final_snapshot_v1().root_inode_v1()
                && collection.baseline_v1().filesystem_magic_v1()
                    == collection.final_snapshot_v1().filesystem_magic_v1(),
            workspace_snapshot_count: "2".to_string(),
        },
        events,
        raw_paths_captured: false,
        schema_version: LINUX_VZ_PACKAGE_ROOT_FILE_EVIDENCE_SCHEMA_V1.to_string(),
        snapshots: RootFileSnapshotsWireV1 {
            baseline_snapshot_sha256,
            final_snapshot_sha256,
            workspace_diff_sha256,
        },
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::Serialization)?;
    decode_linux_vz_package_root_file_evidence_v1(expected, &canonical)
}

pub fn decode_linux_vz_package_root_file_evidence_v1(
    expected: &LinuxVzPackageExpectedRootFileEvidenceV1,
    bytes: &[u8],
) -> Result<LinuxVzPackageRootFileEvidenceV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    expected.validate_v1()?;
    let (wire, canonical) = decode_canonical_v1::<RootFileEvidenceWireV1>(bytes)?;
    if wire.schema_version != LINUX_VZ_PACKAGE_ROOT_FILE_EVIDENCE_SCHEMA_V1
        || wire.raw_paths_captured
    {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage);
    }
    validate_binding_v1(&wire.binding, expected)?;
    let coverage = validate_coverage_v1(
        &wire.coverage,
        wire.events.len(),
        wire.changes.len(),
        expected,
    )?;
    let empty = Sha256Digest::from_bytes(&[]);
    if wire.snapshots.baseline_snapshot_sha256 == empty
        || wire.snapshots.final_snapshot_sha256 == empty
        || wire.snapshots.workspace_diff_sha256 == empty
        || (wire.changes.is_empty()
            && wire.snapshots.baseline_snapshot_sha256 != wire.snapshots.final_snapshot_sha256)
        || (!wire.changes.is_empty()
            && wire.snapshots.baseline_snapshot_sha256 == wire.snapshots.final_snapshot_sha256)
        || change_set_digest_v1(&expected.sensor_session_challenge_sha256, &wire.changes)?
            != wire.snapshots.workspace_diff_sha256
    {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidSnapshot);
    }
    let events = validate_events_v1(wire.events, expected, coverage.diff_completed)?;
    let changes = validate_changes_v1(wire.changes)?;
    Ok(LinuxVzPackageRootFileEvidenceV1 {
        payload_sha256: Sha256Digest::from_bytes(&canonical),
        canonical_json: canonical,
        baseline_snapshot_sha256: wire.snapshots.baseline_snapshot_sha256,
        final_snapshot_sha256: wire.snapshots.final_snapshot_sha256,
        workspace_diff_sha256: wire.snapshots.workspace_diff_sha256,
        events,
        changes,
        diff_completed_monotonic_nanoseconds: coverage.diff_completed,
        active_drain_poll_count: coverage.active_drain_poll_count,
        active_nonempty_drain_count: coverage.active_nonempty_drain_count,
        maximum_drain_batch_event_count: coverage.maximum_drain_batch_event_count,
        ignored_non_cgroup_event_count: coverage.ignored_non_cgroup_event_count,
        permission_response_count: coverage.permission_response_count,
        permission_denied_count: coverage.permission_denied_count,
    })
}

struct ValidatedCoverageV1 {
    diff_completed: u64,
    active_drain_poll_count: u64,
    active_nonempty_drain_count: u64,
    maximum_drain_batch_event_count: u64,
    ignored_non_cgroup_event_count: u64,
    permission_response_count: u64,
    permission_denied_count: u64,
}

fn validate_binding_v1(
    wire: &RootFileBindingWireV1,
    expected: &LinuxVzPackageExpectedRootFileEvidenceV1,
) -> Result<(), LinuxVzPackageRootFileEvidenceErrorV1> {
    if decimal_usize_v1(&wire.action_index)? != expected.action_index
        || decimal_u64_v1(&wire.cgroup_id)? != expected.cgroup_id
        || wire.cgroup_name != expected.cgroup_name
        || wire.launch_contract_sha256 != expected.launch_contract_sha256
        || decimal_u32_v1(&wire.leader_pid)? != expected.leader_pid
        || decimal_u32_v1(&wire.package_gid)? != PACKAGE_GID_V1
        || decimal_u32_v1(&wire.package_uid)? != PACKAGE_UID_V1
        || decimal_u64_v1(&wire.process_ended_monotonic_nanoseconds)?
            != expected.completion.process_ended_monotonic_nanoseconds()
        || wire.process_plan_sha256 != expected.process_plan_sha256
        || decimal_u64_v1(&wire.process_started_monotonic_nanoseconds)?
            != expected.completion.process_started_monotonic_nanoseconds()
        || decimal_u32_v1(&wire.root_runner_pid)? != expected.root_runner_pid
        || wire.sensor_session_challenge_sha256 != expected.sensor_session_challenge_sha256
    {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::BindingMismatch);
    }
    Ok(())
}

fn validate_coverage_v1(
    wire: &RootFileCoverageWireV1,
    event_count: usize,
    change_count: usize,
    expected: &LinuxVzPackageExpectedRootFileEvidenceV1,
) -> Result<ValidatedCoverageV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    let active_drain_poll_count = decimal_u64_v1(&wire.active_drain_poll_count)?;
    let active_nonempty_drain_count = decimal_u64_v1(&wire.active_nonempty_drain_count)?;
    let baseline_entry_count = decimal_usize_v1(&wire.baseline_entry_count)?;
    let baseline_bytes = decimal_u64_v1(&wire.baseline_regular_file_bytes_hashed)?;
    let diff_completed = decimal_u64_v1(&wire.diff_completed_monotonic_nanoseconds)?;
    let final_entry_count = decimal_usize_v1(&wire.final_entry_count)?;
    let final_bytes = decimal_u64_v1(&wire.final_regular_file_bytes_hashed)?;
    let maximum_drain_batch_event_count = decimal_u64_v1(&wire.maximum_drain_batch_event_count)?;
    let ignored_non_cgroup_event_count = decimal_u64_v1(&wire.ignored_non_cgroup_event_count)?;
    let permission_response_count = decimal_u64_v1(&wire.permission_response_count)?;
    let permission_denied_count = decimal_u64_v1(&wire.permission_denied_count)?;
    let event_count_u64 = u64::try_from(event_count)
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage)?;
    if decimal_usize_v1(&wire.source_event_count)? != event_count
        || decimal_usize_v1(&wire.change_count)? != change_count
        || event_count > MAX_ROOT_FILE_SOURCE_EVENTS_V1
        || change_count > MAX_ROOT_FILE_DIFF_CHANGES_V1
        || baseline_entry_count > MAX_ROOT_FILE_SNAPSHOT_ENTRIES_V1
        || final_entry_count > MAX_ROOT_FILE_SNAPSHOT_ENTRIES_V1
        || baseline_bytes > MAX_ROOT_FILE_SNAPSHOT_REGULAR_BYTES_V1
        || final_bytes > MAX_ROOT_FILE_SNAPSHOT_REGULAR_BYTES_V1
        || active_nonempty_drain_count > active_drain_poll_count
        || permission_denied_count > permission_response_count
        || permission_response_count > event_count_u64
        || decimal_u64_v1(&wire.fanotify_overflow_count)? != 0
        || decimal_u64_v1(&wire.required_fanotify_mark_count)? != REQUIRED_FANOTIFY_MARK_COUNT_V1
        || decimal_u64_v1(&wire.workspace_snapshot_count)? != 2
        || diff_completed <= expected.completion.process_ended_monotonic_nanoseconds()
        || !wire.continuous_drain
        || !wire.declared_scope_complete
        || !wire.descriptor_relative_workspace_snapshots
        || wire.evidence_truncated
        || wire.fanotify_event_kinds
            != [
                "access_permission",
                "close_write",
                "open_exec_permission",
                "open_permission",
            ]
        || wire.fanotify_mark_scope
            != [
                "dev_mount",
                "root_mount",
                "run_mount",
                "sys_mount",
                "workspace_mount",
            ]
        || !wire.fanotify_permission_events_enforced
        || wire.fanotify_unobserved_mounts != ["proc_mount"]
        || !wire.file_sensor_healthy
        || wire.filesystem_diff_scope != "workspace_mount"
        || wire.global_mount_coverage_complete
        || !wire.regular_file_contents_hashed
        || !wire.symlink_targets_hashed
        || !wire.workspace_diff_complete
        || !wire.workspace_root_identity_stable
    {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage);
    }
    Ok(ValidatedCoverageV1 {
        diff_completed,
        active_drain_poll_count,
        active_nonempty_drain_count,
        maximum_drain_batch_event_count,
        ignored_non_cgroup_event_count,
        permission_response_count,
        permission_denied_count,
    })
}

fn validate_events_v1(
    wires: Vec<RootFileEventWireV1>,
    expected: &LinuxVzPackageExpectedRootFileEvidenceV1,
    diff_completed: u64,
) -> Result<Vec<LinuxVzPackageRootFileEvidenceEventV1>, LinuxVzPackageRootFileEvidenceErrorV1> {
    let empty = Sha256Digest::from_bytes(&[]);
    let mut prior_timestamp = 0_u64;
    let mut events = Vec::with_capacity(wires.len());
    for (index, wire) in wires.into_iter().enumerate() {
        let source_sequence = decimal_u64_v1(&wire.source_sequence)?;
        let timestamp = decimal_u64_v1(&wire.timestamp_monotonic_nanoseconds)?;
        let kind = parse_event_kind_v1(&wire.event_kind)?;
        let path_class = parse_path_class_v1(&wire.path_class)?;
        let namespace = parse_namespace_v1(&wire.path_namespace)?;
        let outcome = parse_access_outcome_v1(&wire.access_outcome)?;
        let actor_pid = decimal_u32_v1(&wire.actor_pid)?;
        let expected_sequence = u64::try_from(index)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(LinuxVzPackageRootFileEvidenceErrorV1::InvalidEvent)?;
        if source_sequence != expected_sequence
            || timestamp <= prior_timestamp
            || timestamp < expected.completion.process_started_monotonic_nanoseconds()
            || timestamp >= diff_completed
            || actor_pid <= 1
            || decimal_u64_v1(&wire.cgroup_id)? != expected.cgroup_id
            || wire.path_token_sha256 == empty
            || (outcome == LinuxVzPackageRootFileEvidenceAccessOutcomeV1::Denied
                && (path_class != LinuxVzPackageFilePathClassV1::ProtectedSensor
                    || kind == LinuxVzPackageRootFileEvidenceEventKindV1::Write))
        {
            return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidEvent);
        }
        prior_timestamp = timestamp;
        events.push(LinuxVzPackageRootFileEvidenceEventV1 {
            kind,
            path_class,
            namespace,
            outcome,
            source_sequence,
            timestamp_monotonic_nanoseconds: timestamp,
            actor_pid,
            cgroup_id: expected.cgroup_id,
            path_token_sha256: wire.path_token_sha256,
        });
    }
    Ok(events)
}

fn validate_changes_v1(
    wires: Vec<RootFileChangeWireV1>,
) -> Result<Vec<LinuxVzPackageRootFileEvidenceChangeV1>, LinuxVzPackageRootFileEvidenceErrorV1> {
    let empty = Sha256Digest::from_bytes(&[]);
    let mut identities = BTreeSet::new();
    let mut changes = Vec::with_capacity(wires.len());
    for wire in wires {
        let kind = parse_change_kind_v1(&wire.change_kind)?;
        let path_class = parse_path_class_v1(&wire.path_class)?;
        let secondary_path_class = wire
            .secondary_path_class
            .as_deref()
            .map(parse_path_class_v1)
            .transpose()?;
        let prior_entry_kind = wire
            .prior_entry_kind
            .as_deref()
            .map(parse_entry_kind_v1)
            .transpose()?;
        let final_entry_kind = wire
            .final_entry_kind
            .as_deref()
            .map(parse_entry_kind_v1)
            .transpose()?;
        let valid_shape = match kind {
            LinuxVzPackageRootFileEvidenceChangeKindV1::Created => {
                prior_entry_kind.is_none()
                    && final_entry_kind.is_some()
                    && secondary_path_class.is_none()
                    && wire.secondary_path_token_sha256.is_none()
                    && wire.metadata_changed
            }
            LinuxVzPackageRootFileEvidenceChangeKindV1::Modified => {
                prior_entry_kind.is_some()
                    && final_entry_kind.is_some()
                    && secondary_path_class.is_none()
                    && wire.secondary_path_token_sha256.is_none()
                    && (wire.content_changed || wire.metadata_changed)
            }
            LinuxVzPackageRootFileEvidenceChangeKindV1::Deleted => {
                prior_entry_kind.is_some()
                    && final_entry_kind.is_none()
                    && secondary_path_class.is_none()
                    && wire.secondary_path_token_sha256.is_none()
                    && wire.metadata_changed
            }
            LinuxVzPackageRootFileEvidenceChangeKindV1::Renamed => {
                prior_entry_kind.is_some()
                    && final_entry_kind.is_some()
                    && secondary_path_class.is_some()
                    && wire.secondary_path_token_sha256.is_some()
            }
        };
        let identity = (
            wire.change_kind.clone(),
            wire.path_token_sha256.clone(),
            wire.secondary_path_token_sha256.clone(),
        );
        if !valid_shape
            || wire.path_token_sha256 == empty
            || wire.change_record_sha256 == empty
            || wire
                .secondary_path_token_sha256
                .as_ref()
                .is_some_and(|token| token == &empty || token == &wire.path_token_sha256)
            || !identities.insert(identity)
        {
            return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidChange);
        }
        changes.push(LinuxVzPackageRootFileEvidenceChangeV1 {
            kind,
            path_class,
            path_token_sha256: wire.path_token_sha256,
            secondary_path_class,
            secondary_path_token_sha256: wire.secondary_path_token_sha256,
            prior_entry_kind,
            final_entry_kind,
            content_changed: wire.content_changed,
            metadata_changed: wire.metadata_changed,
            change_record_sha256: wire.change_record_sha256,
        });
    }
    Ok(changes)
}

fn change_wire_v1(
    expected: &LinuxVzPackageExpectedRootFileEvidenceV1,
    change: &LinuxVzPackageRootFileChangeV1,
) -> Result<RootFileChangeWireV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    let path_token_sha256 = root_file_path_token_v1(
        &expected.sensor_session_challenge_sha256,
        LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
        change.path_class_v1(),
        change.path_v1(),
    )
    .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidChange)?;
    let secondary_path_token_sha256 =
        match (change.secondary_path_v1(), change.secondary_path_class_v1()) {
            (Some(path), Some(class)) => Some(
                root_file_path_token_v1(
                    &expected.sensor_session_challenge_sha256,
                    LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
                    class,
                    path,
                )
                .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidChange)?,
            ),
            (None, None) => None,
            _ => return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidChange),
        };
    Ok(RootFileChangeWireV1 {
        change_kind: change.kind_v1().as_str_v1().to_string(),
        change_record_sha256: change_record_digest_v1(
            &expected.sensor_session_challenge_sha256,
            change,
            &path_token_sha256,
            secondary_path_token_sha256.as_ref(),
        )?,
        content_changed: change.content_changed_v1(),
        final_entry_kind: change
            .final_entry_kind_v1()
            .map(|kind| kind.as_str_v1().to_string()),
        metadata_changed: change.metadata_changed_v1(),
        path_class: path_class_name_v1(change.path_class_v1()).to_string(),
        path_token_sha256,
        prior_entry_kind: change
            .prior_entry_kind_v1()
            .map(|kind| kind.as_str_v1().to_string()),
        secondary_path_class: change
            .secondary_path_class_v1()
            .map(|class| path_class_name_v1(class).to_string()),
        secondary_path_token_sha256,
    })
}

fn snapshot_digest_v1(
    challenge: &Sha256Digest,
    snapshot: &LinuxVzPackageRootFileSnapshotV1,
) -> Result<Sha256Digest, LinuxVzPackageRootFileEvidenceErrorV1> {
    let mut digest = Sha256::new();
    digest.update(b"whoathere.linux_vz_package_root_file_snapshot_digest.v1\0");
    digest.update(challenge.as_str().as_bytes());
    digest.update([0]);
    digest.update(snapshot.root_device_v1().to_be_bytes());
    digest.update(snapshot.root_inode_v1().to_be_bytes());
    digest.update(snapshot.filesystem_magic_v1().to_be_bytes());
    digest.update(snapshot.regular_file_bytes_hashed_v1().to_be_bytes());
    for entry in snapshot.entries_v1().values() {
        let token = root_file_path_token_v1(
            challenge,
            LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
            entry.path_class_v1(),
            entry.relative_path_v1(),
        )
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidSnapshot)?;
        digest.update(token.as_str().as_bytes());
        digest.update([0]);
        digest.update(path_class_name_v1(entry.path_class_v1()).as_bytes());
        digest.update([0]);
        digest.update(entry.kind_v1().as_str_v1().as_bytes());
        digest.update([0]);
        digest.update(entry.mode_v1().to_be_bytes());
        digest.update(entry.uid_v1().to_be_bytes());
        digest.update(entry.gid_v1().to_be_bytes());
        digest.update(entry.device_v1().to_be_bytes());
        digest.update(entry.inode_v1().to_be_bytes());
        digest.update(entry.link_count_v1().to_be_bytes());
        digest.update(entry.byte_length_v1().to_be_bytes());
        update_optional_digest_v1(&mut digest, entry.content_sha256_v1());
        update_optional_digest_v1(&mut digest, entry.symlink_target_sha256_v1());
        digest.update(entry.fingerprint_sha256_v1().as_str().as_bytes());
        digest.update([0]);
    }
    digest_to_sha256_v1(digest)
}

fn change_record_digest_v1(
    challenge: &Sha256Digest,
    change: &LinuxVzPackageRootFileChangeV1,
    path_token: &Sha256Digest,
    secondary_path_token: Option<&Sha256Digest>,
) -> Result<Sha256Digest, LinuxVzPackageRootFileEvidenceErrorV1> {
    let mut digest = Sha256::new();
    digest.update(b"whoathere.linux_vz_package_root_file_change_record.v1\0");
    digest.update(challenge.as_str().as_bytes());
    digest.update([0]);
    digest.update(change.kind_v1().as_str_v1().as_bytes());
    digest.update([0]);
    digest.update(path_token.as_str().as_bytes());
    digest.update([0]);
    update_optional_digest_v1(&mut digest, secondary_path_token);
    update_optional_digest_v1(&mut digest, change.prior_fingerprint_sha256_v1());
    update_optional_digest_v1(&mut digest, change.final_fingerprint_sha256_v1());
    digest.update([u8::from(change.content_changed_v1())]);
    digest.update([u8::from(change.metadata_changed_v1())]);
    digest_to_sha256_v1(digest)
}

fn change_set_digest_v1(
    challenge: &Sha256Digest,
    changes: &[RootFileChangeWireV1],
) -> Result<Sha256Digest, LinuxVzPackageRootFileEvidenceErrorV1> {
    let canonical = serde_json_canonicalizer::to_vec(&changes)
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::Serialization)?;
    let mut digest = Sha256::new();
    digest.update(b"whoathere.linux_vz_package_root_file_change_set.v1\0");
    digest.update(challenge.as_str().as_bytes());
    digest.update([0]);
    digest.update(canonical);
    digest_to_sha256_v1(digest)
}

fn update_optional_digest_v1(digest: &mut Sha256, value: Option<&Sha256Digest>) {
    match value {
        Some(value) => {
            digest.update([1]);
            digest.update(value.as_str().as_bytes());
        }
        None => digest.update([0]),
    }
    digest.update([0]);
}

fn digest_to_sha256_v1(
    digest: Sha256,
) -> Result<Sha256Digest, LinuxVzPackageRootFileEvidenceErrorV1> {
    let bytes = digest.finalize();
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::Serialization)?;
    }
    Sha256Digest::parse(value).map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::Serialization)
}

fn parse_event_kind_v1(
    value: &str,
) -> Result<LinuxVzPackageRootFileEvidenceEventKindV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    match value {
        "open" => Ok(LinuxVzPackageRootFileEvidenceEventKindV1::Open),
        "read" => Ok(LinuxVzPackageRootFileEvidenceEventKindV1::Read),
        "write" => Ok(LinuxVzPackageRootFileEvidenceEventKindV1::Write),
        "open_exec" => Ok(LinuxVzPackageRootFileEvidenceEventKindV1::OpenExec),
        _ => Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidEvent),
    }
}

fn parse_access_outcome_v1(
    value: &str,
) -> Result<LinuxVzPackageRootFileEvidenceAccessOutcomeV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    match value {
        "observed" => Ok(LinuxVzPackageRootFileEvidenceAccessOutcomeV1::Observed),
        "denied" => Ok(LinuxVzPackageRootFileEvidenceAccessOutcomeV1::Denied),
        _ => Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidEvent),
    }
}

fn parse_namespace_v1(
    value: &str,
) -> Result<LinuxVzPackageRootFileEvidencePathNamespaceV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    match value {
        "absolute" => Ok(LinuxVzPackageRootFileEvidencePathNamespaceV1::Absolute),
        "workspace_relative" => {
            Ok(LinuxVzPackageRootFileEvidencePathNamespaceV1::WorkspaceRelative)
        }
        _ => Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidEvent),
    }
}

fn parse_change_kind_v1(
    value: &str,
) -> Result<LinuxVzPackageRootFileEvidenceChangeKindV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    match value {
        "created" => Ok(LinuxVzPackageRootFileEvidenceChangeKindV1::Created),
        "modified" => Ok(LinuxVzPackageRootFileEvidenceChangeKindV1::Modified),
        "deleted" => Ok(LinuxVzPackageRootFileEvidenceChangeKindV1::Deleted),
        "renamed" => Ok(LinuxVzPackageRootFileEvidenceChangeKindV1::Renamed),
        _ => Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidChange),
    }
}

fn parse_entry_kind_v1(
    value: &str,
) -> Result<LinuxVzPackageRootFileEvidenceEntryKindV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    match value {
        "directory" => Ok(LinuxVzPackageRootFileEvidenceEntryKindV1::Directory),
        "regular" => Ok(LinuxVzPackageRootFileEvidenceEntryKindV1::Regular),
        "symlink" => Ok(LinuxVzPackageRootFileEvidenceEntryKindV1::Symlink),
        "fifo" => Ok(LinuxVzPackageRootFileEvidenceEntryKindV1::Fifo),
        "socket" => Ok(LinuxVzPackageRootFileEvidenceEntryKindV1::Socket),
        "character_device" => Ok(LinuxVzPackageRootFileEvidenceEntryKindV1::CharacterDevice),
        "block_device" => Ok(LinuxVzPackageRootFileEvidenceEntryKindV1::BlockDevice),
        _ => Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidChange),
    }
}

fn parse_path_class_v1(
    value: &str,
) -> Result<LinuxVzPackageFilePathClassV1, LinuxVzPackageRootFileEvidenceErrorV1> {
    match value {
        "workspace" => Ok(LinuxVzPackageFilePathClassV1::Workspace),
        "package_cache" => Ok(LinuxVzPackageFilePathClassV1::PackageCache),
        "runtime" => Ok(LinuxVzPackageFilePathClassV1::Runtime),
        "protected_canary" => Ok(LinuxVzPackageFilePathClassV1::ProtectedCanary),
        "protected_sensor" => Ok(LinuxVzPackageFilePathClassV1::ProtectedSensor),
        "sensitive_credential" => Ok(LinuxVzPackageFilePathClassV1::SensitiveCredential),
        "sensitive_ssh" => Ok(LinuxVzPackageFilePathClassV1::SensitiveSsh),
        "persistence_startup" => Ok(LinuxVzPackageFilePathClassV1::PersistenceStartup),
        "other" => Ok(LinuxVzPackageFilePathClassV1::Other),
        _ => Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidEvent),
    }
}

fn decode_canonical_v1<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<(T, Vec<u8>), LinuxVzPackageRootFileEvidenceErrorV1> {
    if bytes.is_empty() {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_PROTECTED_SENSOR_PAYLOAD_BYTES_V1 {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::LimitExceeded);
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidJson)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::NonCanonical);
    }
    Ok((value, canonical))
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzPackageRootFileEvidenceErrorV1> {
    if value.is_empty()
        || value.len() > 20
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage);
    }
    value
        .parse()
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage)
}

fn decimal_u32_v1(value: &str) -> Result<u32, LinuxVzPackageRootFileEvidenceErrorV1> {
    u32::try_from(decimal_u64_v1(value)?)
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage)
}

fn decimal_usize_v1(value: &str) -> Result<usize, LinuxVzPackageRootFileEvidenceErrorV1> {
    usize::try_from(decimal_u64_v1(value)?)
        .map_err(|_| LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_vz_package_sensor_file_collector::LinuxVzPackageRootFileCollectionV1;
    use crate::LinuxVzPackageProcessTerminalV1;

    fn fixture_v1() -> (
        LinuxVzPackageExpectedRootFileEvidenceV1,
        LinuxVzPackageRootFileCollectionV1,
    ) {
        let challenge = Sha256Digest::from_bytes(b"root file evidence challenge");
        let completion = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            100,
            200,
            0,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("completion");
        let expected = LinuxVzPackageExpectedRootFileEvidenceV1::from_action_v1(
            challenge.clone(),
            Sha256Digest::from_bytes(b"root file launch contract"),
            Sha256Digest::from_bytes(b"root file process plan"),
            3,
            "whoathere-package-action-3".to_string(),
            41,
            42,
            43,
            &completion,
        )
        .expect("expected evidence");
        let collection =
            LinuxVzPackageRootFileCollectionV1::fixture_v1(&challenge, 41, 43, 100, 200);
        (expected, collection)
    }

    #[test]
    fn encoded_evidence_is_canonical_redacted_and_strictly_decodable() {
        let (expected, collection) = fixture_v1();
        let evidence = encode_linux_vz_package_root_file_evidence_v1(&expected, &collection)
            .expect("encoded evidence");
        assert_eq!(evidence.events().len(), 1);
        assert_eq!(evidence.changes().len(), 1);
        assert_eq!(
            evidence.changes()[0].kind(),
            LinuxVzPackageRootFileEvidenceChangeKindV1::Modified
        );
        assert!(evidence.declared_scope_complete());
        assert!(!evidence.global_mount_coverage_complete());
        assert!(!evidence.raw_paths_captured());
        assert_eq!(evidence.permission_response_count(), 1);
        assert_eq!(evidence.permission_denied_count(), 0);
        assert_eq!(
            decode_linux_vz_package_root_file_evidence_v1(&expected, evidence.canonical_json_v1(),)
                .expect("decoded evidence"),
            evidence
        );
        let text = std::str::from_utf8(evidence.canonical_json_v1()).expect("utf8 json");
        assert!(!text.contains("work/package.json"));
        assert!(!text.contains("root file evidence challenge"));
    }

    #[test]
    fn coverage_tampering_unknown_fields_and_noncanonical_json_fail_closed() {
        let (expected, collection) = fixture_v1();
        let evidence = encode_linux_vz_package_root_file_evidence_v1(&expected, &collection)
            .expect("encoded evidence");
        let mut wire: RootFileEvidenceWireV1 =
            serde_json::from_slice(evidence.canonical_json_v1()).expect("wire");
        wire.coverage.fanotify_overflow_count = "1".to_string();
        let overflow = serde_json_canonicalizer::to_vec(&wire).expect("canonical overflow");
        assert_eq!(
            decode_linux_vz_package_root_file_evidence_v1(&expected, &overflow),
            Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage)
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(evidence.canonical_json_v1()).expect("json value");
        value.as_object_mut().expect("object").insert(
            "raw_path".to_string(),
            serde_json::Value::String("/secret".to_string()),
        );
        let unknown = serde_json_canonicalizer::to_vec(&value).expect("canonical unknown");
        assert_eq!(
            decode_linux_vz_package_root_file_evidence_v1(&expected, &unknown),
            Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidJson)
        );

        let pretty: serde_json::Value =
            serde_json::from_slice(evidence.canonical_json_v1()).expect("pretty value");
        let pretty = serde_json::to_vec_pretty(&pretty).expect("pretty json");
        assert_eq!(
            decode_linux_vz_package_root_file_evidence_v1(&expected, &pretty),
            Err(LinuxVzPackageRootFileEvidenceErrorV1::NonCanonical)
        );
    }

    #[test]
    fn reason_codes_and_expected_binding_are_stable() {
        assert_eq!(
            LinuxVzPackageRootFileEvidenceErrorV1::InvalidSnapshot.reason_code(),
            "linux_vz_package_root_file_evidence_snapshot_invalid"
        );
        let completion = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            1,
            2,
            0,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("completion");
        let duplicate = Sha256Digest::from_bytes(b"duplicate");
        assert_eq!(
            LinuxVzPackageExpectedRootFileEvidenceV1::from_action_v1(
                duplicate.clone(),
                duplicate,
                Sha256Digest::from_bytes(b"process plan"),
                0,
                "whoathere-package-action-0".to_string(),
                1,
                2,
                3,
                &completion,
            ),
            Err(LinuxVzPackageRootFileEvidenceErrorV1::InvalidExpectedBinding)
        );
    }
}
