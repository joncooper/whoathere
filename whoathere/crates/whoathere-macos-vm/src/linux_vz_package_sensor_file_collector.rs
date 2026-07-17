#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use crate::LinuxVzPackageFilePathClassV1;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::Sha256Digest;

#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::ffi::{CStr, CString, OsString};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{self, Read};
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStringExt;
#[cfg(target_os = "linux")]
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
#[cfg(target_os = "linux")]
use std::thread::JoinHandle;
#[cfg(target_os = "linux")]
use std::time::Duration;
use zeroize::Zeroize;

pub(crate) const MAX_ROOT_FILE_SNAPSHOT_ENTRIES_V1: usize = 131_072;
pub(crate) const MAX_ROOT_FILE_SNAPSHOT_REGULAR_BYTES_V1: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_ROOT_FILE_DIFF_CHANGES_V1: usize = 131_072;
pub(crate) const MAX_ROOT_FILE_SOURCE_EVENTS_V1: usize = 131_072;
const MAX_ROOT_FILE_PATH_BYTES_V1: usize = 4096;
const MAX_ROOT_FILE_PATH_DEPTH_V1: usize = 64;
#[cfg(target_os = "linux")]
const FANOTIFY_DRAIN_BYTES_V1: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const CONTINUOUS_FILE_DRAIN_INTERVAL_V1: Duration = Duration::from_millis(5);
#[cfg(target_os = "linux")]
const PACKAGE_WORKSPACE_PATH_V1: &[u8] = b"/run/whoathere";
#[cfg(target_os = "linux")]
const PACKAGE_WORKSPACE_PATH_C_V1: &CStr = c"/run/whoathere";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageRootFileCollectorErrorV1 {
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
    PrivilegeBoundary,
    InvalidConfiguration,
    InvalidState,
    OpenFailed,
    WorkspaceInvalid,
    SnapshotFailed,
    SnapshotRace,
    SnapshotLimitExceeded,
    FanotifyUnavailable,
    FanotifyMarkFailed,
    FanotifyReadFailed,
    FanotifyEventInvalid,
    FanotifyResponseFailed,
    FanotifyQueueOverflow,
    ActorCorrelationFailed,
    PreReleaseEvent,
    EventLimitExceeded,
    Worker,
}

impl LinuxVzPackageRootFileCollectorErrorV1 {
    pub(crate) const fn reason_code(self) -> &'static str {
        match self {
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => "linux_vz_package_root_file_platform_unsupported",
            Self::PrivilegeBoundary => "linux_vz_package_root_file_privilege_invalid",
            Self::InvalidConfiguration => "linux_vz_package_root_file_configuration_invalid",
            Self::InvalidState => "linux_vz_package_root_file_state_invalid",
            Self::OpenFailed => "linux_vz_package_root_file_open_failed",
            Self::WorkspaceInvalid => "linux_vz_package_root_file_workspace_invalid",
            Self::SnapshotFailed => "linux_vz_package_root_file_snapshot_failed",
            Self::SnapshotRace => "linux_vz_package_root_file_snapshot_race",
            Self::SnapshotLimitExceeded => "linux_vz_package_root_file_snapshot_limit_exceeded",
            Self::FanotifyUnavailable => "linux_vz_package_root_file_fanotify_unavailable",
            Self::FanotifyMarkFailed => "linux_vz_package_root_file_fanotify_mark_failed",
            Self::FanotifyReadFailed => "linux_vz_package_root_file_fanotify_read_failed",
            Self::FanotifyEventInvalid => "linux_vz_package_root_file_fanotify_event_invalid",
            Self::FanotifyResponseFailed => "linux_vz_package_root_file_fanotify_response_failed",
            Self::FanotifyQueueOverflow => "linux_vz_package_root_file_fanotify_queue_overflow",
            Self::ActorCorrelationFailed => "linux_vz_package_root_file_actor_correlation_failed",
            Self::PreReleaseEvent => "linux_vz_package_root_file_prerelease_event",
            Self::EventLimitExceeded => "linux_vz_package_root_file_event_limit_exceeded",
            Self::Worker => "linux_vz_package_root_file_worker_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootFileCollectorErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootFileCollectorErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LinuxVzPackageRootFileEntryKindV1 {
    Directory,
    Regular,
    Symlink,
    Fifo,
    Socket,
    CharacterDevice,
    BlockDevice,
}

impl LinuxVzPackageRootFileEntryKindV1 {
    pub(crate) const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::Regular => "regular",
            Self::Symlink => "symlink",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::CharacterDevice => "character_device",
            Self::BlockDevice => "block_device",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LinuxVzPackageRootFileChangeKindV1 {
    Created,
    Modified,
    Deleted,
    Renamed,
}

impl LinuxVzPackageRootFileChangeKindV1 {
    pub(crate) const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Created => "created",
            Self::Modified => "modified",
            Self::Deleted => "deleted",
            Self::Renamed => "renamed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageRootFileEventKindV1 {
    Open,
    Read,
    Write,
    OpenExec,
}

impl LinuxVzPackageRootFileEventKindV1 {
    pub(crate) const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Read => "read",
            Self::Write => "write",
            Self::OpenExec => "open_exec",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageRootFileAccessOutcomeV1 {
    Observed,
    Denied,
}

impl LinuxVzPackageRootFileAccessOutcomeV1 {
    pub(crate) const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Observed => "observed",
            Self::Denied => "denied",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinuxVzPackageRootFilePathNamespaceV1 {
    Absolute,
    WorkspaceRelative,
}

impl LinuxVzPackageRootFilePathNamespaceV1 {
    pub(crate) const fn as_str_v1(self) -> &'static str {
        match self {
            Self::Absolute => "absolute",
            Self::WorkspaceRelative => "workspace_relative",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageRootFileSnapshotEntryV1 {
    relative_path: Vec<u8>,
    path_class: LinuxVzPackageFilePathClassV1,
    kind: LinuxVzPackageRootFileEntryKindV1,
    mode: u32,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
    link_count: u64,
    byte_length: u64,
    content_sha256: Option<Sha256Digest>,
    symlink_target_sha256: Option<Sha256Digest>,
    fingerprint_sha256: Sha256Digest,
}

impl fmt::Debug for LinuxVzPackageRootFileSnapshotEntryV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootFileSnapshotEntryV1")
            .field("path", &"<redacted>")
            .field("path_class", &self.path_class)
            .field("kind", &self.kind)
            .field("device", &self.device)
            .field("inode", &self.inode)
            .field("byte_length", &self.byte_length)
            .field("fingerprint_sha256", &self.fingerprint_sha256)
            .finish()
    }
}

impl LinuxVzPackageRootFileSnapshotEntryV1 {
    pub(crate) fn relative_path_v1(&self) -> &[u8] {
        &self.relative_path
    }

    pub(crate) const fn path_class_v1(&self) -> LinuxVzPackageFilePathClassV1 {
        self.path_class
    }

    pub(crate) const fn kind_v1(&self) -> LinuxVzPackageRootFileEntryKindV1 {
        self.kind
    }

    pub(crate) const fn mode_v1(&self) -> u32 {
        self.mode
    }

    pub(crate) const fn uid_v1(&self) -> u32 {
        self.uid
    }

    pub(crate) const fn gid_v1(&self) -> u32 {
        self.gid
    }

    pub(crate) const fn device_v1(&self) -> u64 {
        self.device
    }

    pub(crate) const fn inode_v1(&self) -> u64 {
        self.inode
    }

    pub(crate) const fn link_count_v1(&self) -> u64 {
        self.link_count
    }

    pub(crate) const fn byte_length_v1(&self) -> u64 {
        self.byte_length
    }

    pub(crate) fn content_sha256_v1(&self) -> Option<&Sha256Digest> {
        self.content_sha256.as_ref()
    }

    pub(crate) fn symlink_target_sha256_v1(&self) -> Option<&Sha256Digest> {
        self.symlink_target_sha256.as_ref()
    }

    pub(crate) fn fingerprint_sha256_v1(&self) -> &Sha256Digest {
        &self.fingerprint_sha256
    }

    fn identity_v1(&self) -> (u64, u64, LinuxVzPackageRootFileEntryKindV1) {
        (self.device, self.inode, self.kind)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageRootFileSnapshotEntryV1 {
    fn drop(&mut self) {
        self.relative_path.zeroize();
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageRootFileSnapshotV1 {
    root_device: u64,
    root_inode: u64,
    filesystem_magic: u64,
    entries: BTreeMap<Vec<u8>, LinuxVzPackageRootFileSnapshotEntryV1>,
    regular_file_bytes_hashed: u64,
}

impl fmt::Debug for LinuxVzPackageRootFileSnapshotV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootFileSnapshotV1")
            .field("root_device", &self.root_device)
            .field("root_inode", &self.root_inode)
            .field("filesystem_magic", &self.filesystem_magic)
            .field("entry_count", &self.entries.len())
            .field("regular_file_bytes_hashed", &self.regular_file_bytes_hashed)
            .finish()
    }
}

impl LinuxVzPackageRootFileSnapshotV1 {
    pub(crate) const fn root_device_v1(&self) -> u64 {
        self.root_device
    }

    pub(crate) const fn root_inode_v1(&self) -> u64 {
        self.root_inode
    }

    pub(crate) const fn filesystem_magic_v1(&self) -> u64 {
        self.filesystem_magic
    }

    pub(crate) fn entries_v1(&self) -> &BTreeMap<Vec<u8>, LinuxVzPackageRootFileSnapshotEntryV1> {
        &self.entries
    }

    pub(crate) fn entry_count_v1(&self) -> usize {
        self.entries.len()
    }

    pub(crate) const fn regular_file_bytes_hashed_v1(&self) -> u64 {
        self.regular_file_bytes_hashed
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageRootFileSnapshotV1 {
    fn drop(&mut self) {
        for (mut path, _) in std::mem::take(&mut self.entries) {
            path.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageRootFileChangeV1 {
    kind: LinuxVzPackageRootFileChangeKindV1,
    path: Vec<u8>,
    path_class: LinuxVzPackageFilePathClassV1,
    secondary_path: Option<Vec<u8>>,
    secondary_path_class: Option<LinuxVzPackageFilePathClassV1>,
    prior_entry_kind: Option<LinuxVzPackageRootFileEntryKindV1>,
    final_entry_kind: Option<LinuxVzPackageRootFileEntryKindV1>,
    prior_fingerprint_sha256: Option<Sha256Digest>,
    final_fingerprint_sha256: Option<Sha256Digest>,
    content_changed: bool,
    metadata_changed: bool,
}

impl fmt::Debug for LinuxVzPackageRootFileChangeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootFileChangeV1")
            .field("kind", &self.kind)
            .field("path", &"<redacted>")
            .field("path_class", &self.path_class)
            .field(
                "secondary_path",
                &self.secondary_path.as_ref().map(|_| "<redacted>"),
            )
            .field("content_changed", &self.content_changed)
            .field("metadata_changed", &self.metadata_changed)
            .finish()
    }
}

impl LinuxVzPackageRootFileChangeV1 {
    pub(crate) const fn kind_v1(&self) -> LinuxVzPackageRootFileChangeKindV1 {
        self.kind
    }

    pub(crate) fn path_v1(&self) -> &[u8] {
        &self.path
    }

    pub(crate) const fn path_class_v1(&self) -> LinuxVzPackageFilePathClassV1 {
        self.path_class
    }

    pub(crate) fn secondary_path_v1(&self) -> Option<&[u8]> {
        self.secondary_path.as_deref()
    }

    pub(crate) const fn secondary_path_class_v1(&self) -> Option<LinuxVzPackageFilePathClassV1> {
        self.secondary_path_class
    }

    pub(crate) const fn prior_entry_kind_v1(&self) -> Option<LinuxVzPackageRootFileEntryKindV1> {
        self.prior_entry_kind
    }

    pub(crate) const fn final_entry_kind_v1(&self) -> Option<LinuxVzPackageRootFileEntryKindV1> {
        self.final_entry_kind
    }

    pub(crate) fn prior_fingerprint_sha256_v1(&self) -> Option<&Sha256Digest> {
        self.prior_fingerprint_sha256.as_ref()
    }

    pub(crate) fn final_fingerprint_sha256_v1(&self) -> Option<&Sha256Digest> {
        self.final_fingerprint_sha256.as_ref()
    }

    pub(crate) const fn content_changed_v1(&self) -> bool {
        self.content_changed
    }

    pub(crate) const fn metadata_changed_v1(&self) -> bool {
        self.metadata_changed
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageRootFileChangeV1 {
    fn drop(&mut self) {
        self.path.zeroize();
        if let Some(path) = self.secondary_path.as_mut() {
            path.zeroize();
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageRootFileEventV1 {
    kind: LinuxVzPackageRootFileEventKindV1,
    path_class: LinuxVzPackageFilePathClassV1,
    namespace: LinuxVzPackageRootFilePathNamespaceV1,
    outcome: LinuxVzPackageRootFileAccessOutcomeV1,
    source_sequence: u64,
    timestamp_monotonic_nanoseconds: u64,
    actor_pid: u32,
    cgroup_id: u64,
    path_token_sha256: Sha256Digest,
}

impl fmt::Debug for LinuxVzPackageRootFileEventV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootFileEventV1")
            .field("kind", &self.kind)
            .field("path_class", &self.path_class)
            .field("namespace", &self.namespace)
            .field("outcome", &self.outcome)
            .field("source_sequence", &self.source_sequence)
            .field(
                "timestamp_monotonic_nanoseconds",
                &self.timestamp_monotonic_nanoseconds,
            )
            .field("actor_pid", &self.actor_pid)
            .field("cgroup_id", &self.cgroup_id)
            .field("path_token_sha256", &self.path_token_sha256)
            .finish()
    }
}

impl LinuxVzPackageRootFileEventV1 {
    pub(crate) const fn kind_v1(&self) -> LinuxVzPackageRootFileEventKindV1 {
        self.kind
    }

    pub(crate) const fn path_class_v1(&self) -> LinuxVzPackageFilePathClassV1 {
        self.path_class
    }

    pub(crate) const fn namespace_v1(&self) -> LinuxVzPackageRootFilePathNamespaceV1 {
        self.namespace
    }

    pub(crate) const fn outcome_v1(&self) -> LinuxVzPackageRootFileAccessOutcomeV1 {
        self.outcome
    }

    pub(crate) const fn source_sequence_v1(&self) -> u64 {
        self.source_sequence
    }

    pub(crate) const fn timestamp_monotonic_nanoseconds_v1(&self) -> u64 {
        self.timestamp_monotonic_nanoseconds
    }

    pub(crate) const fn actor_pid_v1(&self) -> u32 {
        self.actor_pid
    }

    pub(crate) const fn cgroup_id_v1(&self) -> u64 {
        self.cgroup_id
    }

    pub(crate) fn path_token_sha256_v1(&self) -> &Sha256Digest {
        &self.path_token_sha256
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct LinuxVzPackageRootFileCollectionV1 {
    cgroup_id: u64,
    leader_pid: u32,
    baseline: LinuxVzPackageRootFileSnapshotV1,
    final_snapshot: LinuxVzPackageRootFileSnapshotV1,
    changes: Vec<LinuxVzPackageRootFileChangeV1>,
    events: Vec<LinuxVzPackageRootFileEventV1>,
    process_ended_monotonic_nanoseconds: u64,
    diff_completed_monotonic_nanoseconds: u64,
    active_drain_poll_count: u64,
    active_nonempty_drain_count: u64,
    maximum_drain_batch_event_count: u64,
    ignored_non_cgroup_event_count: u64,
    permission_response_count: u64,
    permission_denied_count: u64,
    fanotify_overflow_count: u64,
    required_mark_count: u64,
}

impl fmt::Debug for LinuxVzPackageRootFileCollectionV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootFileCollectionV1")
            .field("cgroup_id", &self.cgroup_id)
            .field("leader_pid", &self.leader_pid)
            .field("baseline", &self.baseline)
            .field("final_snapshot", &self.final_snapshot)
            .field("change_count", &self.changes.len())
            .field("event_count", &self.events.len())
            .field(
                "process_ended_monotonic_nanoseconds",
                &self.process_ended_monotonic_nanoseconds,
            )
            .field(
                "diff_completed_monotonic_nanoseconds",
                &self.diff_completed_monotonic_nanoseconds,
            )
            .field("fanotify_overflow_count", &self.fanotify_overflow_count)
            .finish()
    }
}

impl LinuxVzPackageRootFileCollectionV1 {
    pub(crate) const fn cgroup_id_v1(&self) -> u64 {
        self.cgroup_id
    }

    pub(crate) const fn leader_pid_v1(&self) -> u32 {
        self.leader_pid
    }

    pub(crate) fn baseline_v1(&self) -> &LinuxVzPackageRootFileSnapshotV1 {
        &self.baseline
    }

    pub(crate) fn final_snapshot_v1(&self) -> &LinuxVzPackageRootFileSnapshotV1 {
        &self.final_snapshot
    }

    pub(crate) fn changes_v1(&self) -> &[LinuxVzPackageRootFileChangeV1] {
        &self.changes
    }

    pub(crate) fn events_v1(&self) -> &[LinuxVzPackageRootFileEventV1] {
        &self.events
    }

    pub(crate) const fn process_ended_monotonic_nanoseconds_v1(&self) -> u64 {
        self.process_ended_monotonic_nanoseconds
    }

    pub(crate) const fn diff_completed_monotonic_nanoseconds_v1(&self) -> u64 {
        self.diff_completed_monotonic_nanoseconds
    }

    pub(crate) const fn active_drain_poll_count_v1(&self) -> u64 {
        self.active_drain_poll_count
    }

    pub(crate) const fn active_nonempty_drain_count_v1(&self) -> u64 {
        self.active_nonempty_drain_count
    }

    pub(crate) const fn maximum_drain_batch_event_count_v1(&self) -> u64 {
        self.maximum_drain_batch_event_count
    }

    pub(crate) const fn ignored_non_cgroup_event_count_v1(&self) -> u64 {
        self.ignored_non_cgroup_event_count
    }

    pub(crate) const fn permission_response_count_v1(&self) -> u64 {
        self.permission_response_count
    }

    pub(crate) const fn permission_denied_count_v1(&self) -> u64 {
        self.permission_denied_count
    }

    pub(crate) const fn fanotify_overflow_count_v1(&self) -> u64 {
        self.fanotify_overflow_count
    }

    pub(crate) const fn required_mark_count_v1(&self) -> u64 {
        self.required_mark_count
    }

    #[cfg(test)]
    pub(crate) fn fixture_v1(
        challenge: &Sha256Digest,
        cgroup_id: u64,
        leader_pid: u32,
        process_started_monotonic_nanoseconds: u64,
        process_ended_monotonic_nanoseconds: u64,
    ) -> Self {
        let path = b"work/package.json".to_vec();
        let before_content = Sha256Digest::from_bytes(b"{}");
        let after_content = Sha256Digest::from_bytes(b"{ } ");
        let before_fingerprint = Sha256Digest::from_bytes(b"before fixture fingerprint");
        let after_fingerprint = Sha256Digest::from_bytes(b"after fixture fingerprint");
        let before_entry = LinuxVzPackageRootFileSnapshotEntryV1 {
            relative_path: path.clone(),
            path_class: LinuxVzPackageFilePathClassV1::Workspace,
            kind: LinuxVzPackageRootFileEntryKindV1::Regular,
            mode: 0o644,
            uid: 65_534,
            gid: 65_534,
            device: 1,
            inode: 3,
            link_count: 1,
            byte_length: 2,
            content_sha256: Some(before_content),
            symlink_target_sha256: None,
            fingerprint_sha256: before_fingerprint.clone(),
        };
        let after_entry = LinuxVzPackageRootFileSnapshotEntryV1 {
            relative_path: path.clone(),
            path_class: LinuxVzPackageFilePathClassV1::Workspace,
            kind: LinuxVzPackageRootFileEntryKindV1::Regular,
            mode: 0o644,
            uid: 65_534,
            gid: 65_534,
            device: 1,
            inode: 3,
            link_count: 1,
            byte_length: 4,
            content_sha256: Some(after_content),
            symlink_target_sha256: None,
            fingerprint_sha256: after_fingerprint.clone(),
        };
        let baseline = LinuxVzPackageRootFileSnapshotV1 {
            root_device: 1,
            root_inode: 2,
            filesystem_magic: 0x0102_1994,
            entries: BTreeMap::from([(path.clone(), before_entry)]),
            regular_file_bytes_hashed: 2,
        };
        let final_snapshot = LinuxVzPackageRootFileSnapshotV1 {
            root_device: 1,
            root_inode: 2,
            filesystem_magic: 0x0102_1994,
            entries: BTreeMap::from([(path.clone(), after_entry)]),
            regular_file_bytes_hashed: 4,
        };
        let path_token_sha256 = root_file_path_token_v1(
            challenge,
            LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
            LinuxVzPackageFilePathClassV1::Workspace,
            b"work/package.json",
        )
        .expect("fixture path token");
        Self {
            cgroup_id,
            leader_pid,
            baseline,
            final_snapshot,
            changes: vec![LinuxVzPackageRootFileChangeV1 {
                kind: LinuxVzPackageRootFileChangeKindV1::Modified,
                path,
                path_class: LinuxVzPackageFilePathClassV1::Workspace,
                secondary_path: None,
                secondary_path_class: None,
                prior_entry_kind: Some(LinuxVzPackageRootFileEntryKindV1::Regular),
                final_entry_kind: Some(LinuxVzPackageRootFileEntryKindV1::Regular),
                prior_fingerprint_sha256: Some(before_fingerprint),
                final_fingerprint_sha256: Some(after_fingerprint),
                content_changed: true,
                metadata_changed: true,
            }],
            events: vec![LinuxVzPackageRootFileEventV1 {
                kind: LinuxVzPackageRootFileEventKindV1::Open,
                path_class: LinuxVzPackageFilePathClassV1::Workspace,
                namespace: LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
                outcome: LinuxVzPackageRootFileAccessOutcomeV1::Observed,
                source_sequence: 1,
                timestamp_monotonic_nanoseconds: process_started_monotonic_nanoseconds + 1,
                actor_pid: leader_pid,
                cgroup_id,
                path_token_sha256,
            }],
            process_ended_monotonic_nanoseconds,
            diff_completed_monotonic_nanoseconds: process_ended_monotonic_nanoseconds + 1,
            active_drain_poll_count: 1,
            active_nonempty_drain_count: 1,
            maximum_drain_batch_event_count: 1,
            ignored_non_cgroup_event_count: 0,
            permission_response_count: 1,
            permission_denied_count: 0,
            fanotify_overflow_count: 0,
            required_mark_count: REQUIRED_FANOTIFY_MARK_COUNT_FIXTURE_V1,
        }
    }

    #[cfg(test)]
    pub(crate) fn denominator_fixture_v1(
        challenge: &Sha256Digest,
        cgroup_id: u64,
        leader_pid: u32,
        process_started_monotonic_nanoseconds: u64,
        process_ended_monotonic_nanoseconds: u64,
    ) -> Self {
        let mut fixture = Self::fixture_v1(
            challenge,
            cgroup_id,
            leader_pid,
            process_started_monotonic_nanoseconds,
            process_ended_monotonic_nanoseconds,
        );
        let workspace_token = fixture.events[0].path_token_sha256.clone();
        let sensitive_ssh_token = root_file_path_token_v1(
            challenge,
            LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
            LinuxVzPackageFilePathClassV1::SensitiveSsh,
            b"home/.ssh/id_ed25519",
        )
        .expect("fixture sensitive SSH token");
        fixture.events = vec![
            LinuxVzPackageRootFileEventV1 {
                kind: LinuxVzPackageRootFileEventKindV1::Read,
                path_class: LinuxVzPackageFilePathClassV1::SensitiveSsh,
                namespace: LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
                outcome: LinuxVzPackageRootFileAccessOutcomeV1::Observed,
                source_sequence: 1,
                timestamp_monotonic_nanoseconds: process_started_monotonic_nanoseconds + 1,
                actor_pid: leader_pid,
                cgroup_id,
                path_token_sha256: sensitive_ssh_token,
            },
            LinuxVzPackageRootFileEventV1 {
                kind: LinuxVzPackageRootFileEventKindV1::Open,
                path_class: LinuxVzPackageFilePathClassV1::Workspace,
                namespace: LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
                outcome: LinuxVzPackageRootFileAccessOutcomeV1::Observed,
                source_sequence: 2,
                timestamp_monotonic_nanoseconds: process_started_monotonic_nanoseconds + 2,
                actor_pid: leader_pid,
                cgroup_id,
                path_token_sha256: workspace_token.clone(),
            },
        ];
        fixture.maximum_drain_batch_event_count = 2;
        fixture.permission_response_count = 2;
        fixture
    }

    #[cfg(test)]
    pub(crate) fn denominator_fixture_with_unsupported_v1(
        challenge: &Sha256Digest,
        cgroup_id: u64,
        leader_pid: u32,
        process_started_monotonic_nanoseconds: u64,
        process_ended_monotonic_nanoseconds: u64,
    ) -> Self {
        let mut fixture = Self::denominator_fixture_v1(
            challenge,
            cgroup_id,
            leader_pid,
            process_started_monotonic_nanoseconds,
            process_ended_monotonic_nanoseconds,
        );
        let workspace_token = fixture.events[1].path_token_sha256.clone();
        fixture.events.push(LinuxVzPackageRootFileEventV1 {
            kind: LinuxVzPackageRootFileEventKindV1::Write,
            path_class: LinuxVzPackageFilePathClassV1::Workspace,
            namespace: LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
            outcome: LinuxVzPackageRootFileAccessOutcomeV1::Observed,
            source_sequence: 3,
            timestamp_monotonic_nanoseconds: process_started_monotonic_nanoseconds + 3,
            actor_pid: leader_pid,
            cgroup_id,
            path_token_sha256: workspace_token,
        });
        fixture.maximum_drain_batch_event_count = 3;
        fixture
    }
}

#[cfg(test)]
const REQUIRED_FANOTIFY_MARK_COUNT_FIXTURE_V1: u64 = 5;

pub(crate) fn root_file_path_token_v1(
    challenge: &Sha256Digest,
    namespace: LinuxVzPackageRootFilePathNamespaceV1,
    path_class: LinuxVzPackageFilePathClassV1,
    path: &[u8],
) -> Result<Sha256Digest, LinuxVzPackageRootFileCollectorErrorV1> {
    if path.is_empty() || path.len() > MAX_ROOT_FILE_PATH_BYTES_V1 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid);
    }
    let mut input = Vec::with_capacity(challenge.as_str().len() + path.len() + 96);
    input.extend_from_slice(b"whoathere.linux_vz_package_root_file_path_token.v1\0");
    input.extend_from_slice(challenge.as_str().as_bytes());
    input.push(0);
    input.extend_from_slice(namespace.as_str_v1().as_bytes());
    input.push(0);
    input.extend_from_slice(path_class_name_v1(path_class).as_bytes());
    input.push(0);
    input.extend_from_slice(path);
    let digest = Sha256Digest::from_bytes(&input);
    input.zeroize();
    Ok(digest)
}

pub(crate) fn path_class_name_v1(value: LinuxVzPackageFilePathClassV1) -> &'static str {
    match value {
        LinuxVzPackageFilePathClassV1::Workspace => "workspace",
        LinuxVzPackageFilePathClassV1::PackageCache => "package_cache",
        LinuxVzPackageFilePathClassV1::Runtime => "runtime",
        LinuxVzPackageFilePathClassV1::ProtectedCanary => "protected_canary",
        LinuxVzPackageFilePathClassV1::ProtectedSensor => "protected_sensor",
        LinuxVzPackageFilePathClassV1::SensitiveCredential => "sensitive_credential",
        LinuxVzPackageFilePathClassV1::SensitiveSsh => "sensitive_ssh",
        LinuxVzPackageFilePathClassV1::PersistenceStartup => "persistence_startup",
        LinuxVzPackageFilePathClassV1::Other => "other",
    }
}

pub(crate) fn diff_root_file_snapshots_v1(
    baseline: &LinuxVzPackageRootFileSnapshotV1,
    final_snapshot: &LinuxVzPackageRootFileSnapshotV1,
) -> Result<Vec<LinuxVzPackageRootFileChangeV1>, LinuxVzPackageRootFileCollectorErrorV1> {
    if baseline.root_device != final_snapshot.root_device
        || baseline.root_inode != final_snapshot.root_inode
        || baseline.filesystem_magic != final_snapshot.filesystem_magic
    {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::WorkspaceInvalid);
    }
    let mut changes = Vec::new();
    let mut deleted = BTreeSet::new();
    let mut created = BTreeSet::new();
    for (path, prior) in &baseline.entries {
        match final_snapshot.entries.get(path) {
            Some(final_entry) if prior.fingerprint_sha256 != final_entry.fingerprint_sha256 => {
                changes.push(modified_change_v1(path, prior, final_entry));
            }
            Some(_) => {}
            None => {
                deleted.insert(path.clone());
            }
        }
    }
    for path in final_snapshot.entries.keys() {
        if !baseline.entries.contains_key(path) {
            created.insert(path.clone());
        }
    }

    let mut deleted_by_identity: BTreeMap<
        (u64, u64, LinuxVzPackageRootFileEntryKindV1),
        Vec<Vec<u8>>,
    > = BTreeMap::new();
    let mut created_by_identity: BTreeMap<
        (u64, u64, LinuxVzPackageRootFileEntryKindV1),
        Vec<Vec<u8>>,
    > = BTreeMap::new();
    for path in &deleted {
        deleted_by_identity
            .entry(baseline.entries[path].identity_v1())
            .or_default()
            .push(path.clone());
    }
    for path in &created {
        created_by_identity
            .entry(final_snapshot.entries[path].identity_v1())
            .or_default()
            .push(path.clone());
    }
    for (identity, old_paths) in deleted_by_identity {
        let Some(new_paths) = created_by_identity.get(&identity) else {
            continue;
        };
        if old_paths.len() != 1 || new_paths.len() != 1 {
            continue;
        }
        let old_path = &old_paths[0];
        let new_path = &new_paths[0];
        let prior = &baseline.entries[old_path];
        let final_entry = &final_snapshot.entries[new_path];
        changes.push(LinuxVzPackageRootFileChangeV1 {
            kind: LinuxVzPackageRootFileChangeKindV1::Renamed,
            path: new_path.clone(),
            path_class: final_entry.path_class,
            secondary_path: Some(old_path.clone()),
            secondary_path_class: Some(prior.path_class),
            prior_entry_kind: Some(prior.kind),
            final_entry_kind: Some(final_entry.kind),
            prior_fingerprint_sha256: Some(prior.fingerprint_sha256.clone()),
            final_fingerprint_sha256: Some(final_entry.fingerprint_sha256.clone()),
            content_changed: prior.content_sha256 != final_entry.content_sha256
                || prior.symlink_target_sha256 != final_entry.symlink_target_sha256,
            metadata_changed: prior.mode != final_entry.mode
                || prior.uid != final_entry.uid
                || prior.gid != final_entry.gid
                || prior.byte_length != final_entry.byte_length
                || prior.link_count != final_entry.link_count,
        });
        deleted.remove(old_path);
        created.remove(new_path);
    }
    for path in deleted {
        let prior = &baseline.entries[&path];
        changes.push(LinuxVzPackageRootFileChangeV1 {
            kind: LinuxVzPackageRootFileChangeKindV1::Deleted,
            path,
            path_class: prior.path_class,
            secondary_path: None,
            secondary_path_class: None,
            prior_entry_kind: Some(prior.kind),
            final_entry_kind: None,
            prior_fingerprint_sha256: Some(prior.fingerprint_sha256.clone()),
            final_fingerprint_sha256: None,
            content_changed: prior.content_sha256.is_some()
                || prior.symlink_target_sha256.is_some(),
            metadata_changed: true,
        });
    }
    for path in created {
        let final_entry = &final_snapshot.entries[&path];
        changes.push(LinuxVzPackageRootFileChangeV1 {
            kind: LinuxVzPackageRootFileChangeKindV1::Created,
            path,
            path_class: final_entry.path_class,
            secondary_path: None,
            secondary_path_class: None,
            prior_entry_kind: None,
            final_entry_kind: Some(final_entry.kind),
            prior_fingerprint_sha256: None,
            final_fingerprint_sha256: Some(final_entry.fingerprint_sha256.clone()),
            content_changed: final_entry.content_sha256.is_some()
                || final_entry.symlink_target_sha256.is_some(),
            metadata_changed: true,
        });
    }
    if changes.len() > MAX_ROOT_FILE_DIFF_CHANGES_V1 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotLimitExceeded);
    }
    changes.sort_by(|left, right| {
        (left.kind, &left.path, &left.secondary_path).cmp(&(
            right.kind,
            &right.path,
            &right.secondary_path,
        ))
    });
    Ok(changes)
}

fn modified_change_v1(
    path: &[u8],
    prior: &LinuxVzPackageRootFileSnapshotEntryV1,
    final_entry: &LinuxVzPackageRootFileSnapshotEntryV1,
) -> LinuxVzPackageRootFileChangeV1 {
    LinuxVzPackageRootFileChangeV1 {
        kind: LinuxVzPackageRootFileChangeKindV1::Modified,
        path: path.to_vec(),
        path_class: final_entry.path_class,
        secondary_path: None,
        secondary_path_class: None,
        prior_entry_kind: Some(prior.kind),
        final_entry_kind: Some(final_entry.kind),
        prior_fingerprint_sha256: Some(prior.fingerprint_sha256.clone()),
        final_fingerprint_sha256: Some(final_entry.fingerprint_sha256.clone()),
        content_changed: prior.content_sha256 != final_entry.content_sha256
            || prior.symlink_target_sha256 != final_entry.symlink_target_sha256,
        metadata_changed: prior.kind != final_entry.kind
            || prior.mode != final_entry.mode
            || prior.uid != final_entry.uid
            || prior.gid != final_entry.gid
            || prior.device != final_entry.device
            || prior.inode != final_entry.inode
            || prior.link_count != final_entry.link_count
            || prior.byte_length != final_entry.byte_length,
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinuxVzPackageRootFileCollectorStateV1 {
    Armed,
    LeaderAttached,
    Finished,
    Faulted,
    Aborted,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxVzPackageRootFileCollectorV1 {
    state: LinuxVzPackageRootFileCollectorStateV1,
    expected_cgroup_id: u64,
    leader_pid: Option<u32>,
    fault_signal_read: OwnedFd,
    command_sender: Option<SyncSender<LinuxVzPackageRootFileWorkerCommandV1>>,
    worker: Option<JoinHandle<()>>,
}

#[cfg(not(target_os = "linux"))]
#[derive(Debug)]
pub(crate) struct LinuxVzPackageRootFileCollectorV1;

#[cfg(target_os = "linux")]
impl fmt::Debug for LinuxVzPackageRootFileCollectorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootFileCollectorV1")
            .field("state", &self.state)
            .field("expected_cgroup_id", &self.expected_cgroup_id)
            .field("leader_pid", &self.leader_pid)
            .field("worker_present", &self.worker.is_some())
            .finish()
    }
}

#[cfg(target_os = "linux")]
enum LinuxVzPackageRootFileWorkerCommandV1 {
    LeaderAttached {
        leader_pid: u32,
        response: SyncSender<Result<(), LinuxVzPackageRootFileCollectorErrorV1>>,
    },
    Finish {
        leader_pid: u32,
        process_ended_monotonic_nanoseconds: u64,
        response: SyncSender<
            Result<LinuxVzPackageRootFileCollectionV1, LinuxVzPackageRootFileCollectorErrorV1>,
        >,
    },
    Abort,
}

#[cfg(target_os = "linux")]
struct LinuxVzPackageRootFileWorkerReadyV1;

#[cfg(target_os = "linux")]
struct LinuxVzPackageRootFileWorkerV1 {
    expected_cgroup_id: u64,
    challenge: Sha256Digest,
    cgroup_directory: OwnedFd,
    workspace: File,
    fanotify: Option<OwnedFd>,
    fault_signal_write: OwnedFd,
    baseline: LinuxVzPackageRootFileSnapshotV1,
    maximum_source_events: usize,
    leader_pid: Option<u32>,
    tracked_actor_start_times: BTreeMap<u32, u64>,
    events: Vec<LinuxVzPackageRootFileEventV1>,
    fault: Option<LinuxVzPackageRootFileCollectorErrorV1>,
    active_drain_poll_count: u64,
    active_nonempty_drain_count: u64,
    maximum_drain_batch_event_count: u64,
    ignored_non_cgroup_event_count: u64,
    permission_response_count: u64,
    permission_denied_count: u64,
    fanotify_overflow_count: u64,
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootFileCollectorV1 {
    pub(crate) fn arm_v1(
        expected_cgroup_id: u64,
        cgroup_directory: RawFd,
        challenge: Sha256Digest,
        maximum_source_events: usize,
    ) -> Result<Self, LinuxVzPackageRootFileCollectorErrorV1> {
        require_root_v1()?;
        if expected_cgroup_id == 0
            || cgroup_directory < 0
            || challenge == Sha256Digest::from_bytes(&[])
            || maximum_source_events == 0
            || maximum_source_events > MAX_ROOT_FILE_SOURCE_EVENTS_V1
        {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::InvalidConfiguration);
        }
        let cgroup_directory = duplicate_fd_v1(cgroup_directory)?;
        require_cgroup_empty_v1(cgroup_directory.as_raw_fd())?;
        let workspace = open_workspace_v1()?;
        validate_workspace_v1(&workspace)?;
        let baseline = snapshot_workspace_v1(&workspace)?;
        let (fault_signal_read, fault_signal_write) = create_pipe_v1()?;
        let (command_sender, command_receiver) = mpsc::sync_channel(1);
        let (ready_sender, ready_receiver) = mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("whoathere-root-file-sensor-v1".to_string())
            .spawn(move || {
                run_root_file_worker_v1(
                    expected_cgroup_id,
                    challenge,
                    cgroup_directory,
                    workspace,
                    baseline,
                    maximum_source_events,
                    fault_signal_write,
                    ready_sender,
                    command_receiver,
                );
            })
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
        match ready_receiver.recv() {
            Ok(Ok(LinuxVzPackageRootFileWorkerReadyV1)) => Ok(Self {
                state: LinuxVzPackageRootFileCollectorStateV1::Armed,
                expected_cgroup_id,
                leader_pid: None,
                fault_signal_read,
                command_sender: Some(command_sender),
                worker: Some(worker),
            }),
            Ok(Err(error)) => {
                let _ = worker.join();
                Err(error)
            }
            Err(_) => {
                let _ = worker.join();
                Err(LinuxVzPackageRootFileCollectorErrorV1::Worker)
            }
        }
    }

    pub(crate) fn leader_attached_before_release_v1(
        &mut self,
        leader_pid: u32,
    ) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
        if self.state != LinuxVzPackageRootFileCollectorStateV1::Armed
            || self.leader_pid.is_some()
            || leader_pid <= 1
        {
            return self.fault_v1(LinuxVzPackageRootFileCollectorErrorV1::InvalidState);
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        self.sender_v1()?
            .send(LinuxVzPackageRootFileWorkerCommandV1::LeaderAttached {
                leader_pid,
                response: response_sender,
            })
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
        match response_receiver.recv() {
            Ok(Ok(())) => {
                self.leader_pid = Some(leader_pid);
                self.state = LinuxVzPackageRootFileCollectorStateV1::LeaderAttached;
                Ok(())
            }
            Ok(Err(error)) => self.fault_v1(error),
            Err(_) => self.fault_v1(LinuxVzPackageRootFileCollectorErrorV1::Worker),
        }
    }

    pub(crate) fn fault_signal_fd_v1(
        &self,
    ) -> Result<RawFd, LinuxVzPackageRootFileCollectorErrorV1> {
        if !matches!(
            self.state,
            LinuxVzPackageRootFileCollectorStateV1::Armed
                | LinuxVzPackageRootFileCollectorStateV1::LeaderAttached
        ) {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::InvalidState);
        }
        Ok(self.fault_signal_read.as_raw_fd())
    }

    pub(crate) fn require_healthy_v1(&self) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
        let mut poll = libc::pollfd {
            fd: self.fault_signal_fd_v1()?,
            events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
            revents: 0,
        };
        loop {
            let result = unsafe { libc::poll(&mut poll, 1, 0) };
            if result == 0 {
                return Ok(());
            }
            if result > 0 {
                return Err(LinuxVzPackageRootFileCollectorErrorV1::Worker);
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(LinuxVzPackageRootFileCollectorErrorV1::Worker);
            }
        }
    }

    pub(crate) fn finish_after_empty_cgroup_v1(
        &mut self,
        leader_pid: u32,
        process_ended_monotonic_nanoseconds: u64,
    ) -> Result<LinuxVzPackageRootFileCollectionV1, LinuxVzPackageRootFileCollectorErrorV1> {
        if self.state != LinuxVzPackageRootFileCollectorStateV1::LeaderAttached
            || self.leader_pid != Some(leader_pid)
            || process_ended_monotonic_nanoseconds == 0
        {
            return self.fault_v1(LinuxVzPackageRootFileCollectorErrorV1::InvalidState);
        }
        let (response_sender, response_receiver) = mpsc::sync_channel(1);
        self.sender_v1()?
            .send(LinuxVzPackageRootFileWorkerCommandV1::Finish {
                leader_pid,
                process_ended_monotonic_nanoseconds,
                response: response_sender,
            })
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
        self.command_sender.take();
        let result = response_receiver
            .recv()
            .unwrap_or(Err(LinuxVzPackageRootFileCollectorErrorV1::Worker));
        let joined = self
            .worker
            .take()
            .ok_or(LinuxVzPackageRootFileCollectorErrorV1::InvalidState)?
            .join()
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::Worker);
        let result = match (result, joined) {
            (Ok(collection), Ok(())) => Ok(collection),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        };
        self.state = if result.is_ok() {
            LinuxVzPackageRootFileCollectorStateV1::Finished
        } else {
            LinuxVzPackageRootFileCollectorStateV1::Faulted
        };
        result
    }

    pub(crate) fn abort_v1(&mut self) {
        self.shutdown_worker_v1();
        self.leader_pid = None;
        if self.state != LinuxVzPackageRootFileCollectorStateV1::Finished {
            self.state = LinuxVzPackageRootFileCollectorStateV1::Aborted;
        }
    }

    fn sender_v1(
        &self,
    ) -> Result<
        SyncSender<LinuxVzPackageRootFileWorkerCommandV1>,
        LinuxVzPackageRootFileCollectorErrorV1,
    > {
        self.command_sender
            .as_ref()
            .cloned()
            .ok_or(LinuxVzPackageRootFileCollectorErrorV1::InvalidState)
    }

    fn fault_v1<T>(
        &mut self,
        error: LinuxVzPackageRootFileCollectorErrorV1,
    ) -> Result<T, LinuxVzPackageRootFileCollectorErrorV1> {
        self.shutdown_worker_v1();
        self.state = LinuxVzPackageRootFileCollectorStateV1::Faulted;
        Err(error)
    }

    fn shutdown_worker_v1(&mut self) {
        if let Some(sender) = self.command_sender.take() {
            let _ = sender.send(LinuxVzPackageRootFileWorkerCommandV1::Abort);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

#[cfg(not(target_os = "linux"))]
impl LinuxVzPackageRootFileCollectorV1 {
    pub(crate) fn arm_v1(
        _expected_cgroup_id: u64,
        _cgroup_directory: i32,
        _challenge: Sha256Digest,
        _maximum_source_events: usize,
    ) -> Result<Self, LinuxVzPackageRootFileCollectorErrorV1> {
        Err(LinuxVzPackageRootFileCollectorErrorV1::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxVzPackageRootFileCollectorV1 {
    fn drop(&mut self) {
        self.abort_v1();
    }
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_root_file_worker_v1(
    expected_cgroup_id: u64,
    challenge: Sha256Digest,
    cgroup_directory: OwnedFd,
    workspace: File,
    baseline: LinuxVzPackageRootFileSnapshotV1,
    maximum_source_events: usize,
    fault_signal_write: OwnedFd,
    ready_sender: SyncSender<
        Result<LinuxVzPackageRootFileWorkerReadyV1, LinuxVzPackageRootFileCollectorErrorV1>,
    >,
    command_receiver: Receiver<LinuxVzPackageRootFileWorkerCommandV1>,
) {
    let fanotify = match create_fanotify_v1(&workspace) {
        Ok(value) => value,
        Err(error) => {
            let _ = ready_sender.send(Err(error));
            return;
        }
    };
    if ready_sender
        .send(Ok(LinuxVzPackageRootFileWorkerReadyV1))
        .is_err()
    {
        return;
    }
    LinuxVzPackageRootFileWorkerV1 {
        expected_cgroup_id,
        challenge,
        cgroup_directory,
        workspace,
        fanotify: Some(fanotify),
        fault_signal_write,
        baseline,
        maximum_source_events,
        leader_pid: None,
        tracked_actor_start_times: BTreeMap::new(),
        events: Vec::new(),
        fault: None,
        active_drain_poll_count: 0,
        active_nonempty_drain_count: 0,
        maximum_drain_batch_event_count: 0,
        ignored_non_cgroup_event_count: 0,
        permission_response_count: 0,
        permission_denied_count: 0,
        fanotify_overflow_count: 0,
    }
    .run_v1(command_receiver);
}

#[cfg(target_os = "linux")]
impl LinuxVzPackageRootFileWorkerV1 {
    fn run_v1(mut self, command_receiver: Receiver<LinuxVzPackageRootFileWorkerCommandV1>) {
        loop {
            match command_receiver.recv_timeout(CONTINUOUS_FILE_DRAIN_INTERVAL_V1) {
                Ok(LinuxVzPackageRootFileWorkerCommandV1::LeaderAttached {
                    leader_pid,
                    response,
                }) => {
                    let result = self.leader_attached_v1(leader_pid);
                    let _ = response.send(result);
                }
                Ok(LinuxVzPackageRootFileWorkerCommandV1::Finish {
                    leader_pid,
                    process_ended_monotonic_nanoseconds,
                    response,
                }) => {
                    let result = self.finish_v1(leader_pid, process_ended_monotonic_nanoseconds);
                    let _ = response.send(result);
                    return;
                }
                Ok(LinuxVzPackageRootFileWorkerCommandV1::Abort)
                | Err(RecvTimeoutError::Disconnected) => {
                    self.drain_denying_after_fault_v1();
                    return;
                }
                Err(RecvTimeoutError::Timeout) => self.poll_v1(),
            }
        }
    }

    fn leader_attached_v1(
        &mut self,
        leader_pid: u32,
    ) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
        if self.leader_pid.is_some() || leader_pid <= 1 || self.fault.is_some() {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::InvalidState);
        }
        self.drain_v1(false)?;
        if !self.events.is_empty() {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::PreReleaseEvent);
        }
        if !cgroup_contains_pid_v1(self.cgroup_directory.as_raw_fd(), leader_pid)? {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
        }
        let start_time = process_start_time_v1(leader_pid)?;
        self.tracked_actor_start_times
            .insert(leader_pid, start_time);
        self.leader_pid = Some(leader_pid);
        Ok(())
    }

    fn poll_v1(&mut self) {
        if self.leader_pid.is_some() {
            self.active_drain_poll_count = match self.active_drain_poll_count.checked_add(1) {
                Some(value) => value,
                None => {
                    self.record_fault_v1(LinuxVzPackageRootFileCollectorErrorV1::Worker);
                    return;
                }
            };
        }
        match self.drain_v1(self.fault.is_some()) {
            Ok(count) if count > 0 && self.leader_pid.is_some() => {
                self.active_nonempty_drain_count =
                    self.active_nonempty_drain_count.saturating_add(1);
                self.maximum_drain_batch_event_count =
                    self.maximum_drain_batch_event_count.max(count);
            }
            Ok(_) => {}
            Err(error) => self.record_fault_v1(error),
        }
    }

    fn drain_v1(
        &mut self,
        deny_all_permissions: bool,
    ) -> Result<u64, LinuxVzPackageRootFileCollectorErrorV1> {
        let descriptor = self
            .fanotify
            .as_ref()
            .ok_or(LinuxVzPackageRootFileCollectorErrorV1::InvalidState)?
            .as_raw_fd();
        let mut processed = 0_u64;
        loop {
            let mut buffer = vec![0_u8; FANOTIFY_DRAIN_BYTES_V1];
            let length =
                unsafe { libc::read(descriptor, buffer.as_mut_ptr().cast(), buffer.len()) };
            if length < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if error.kind() == io::ErrorKind::WouldBlock {
                    return Ok(processed);
                }
                return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyReadFailed);
            }
            if length == 0 {
                return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyReadFailed);
            }
            let length = usize::try_from(length)
                .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::FanotifyReadFailed)?;
            buffer.truncate(length);
            let batch =
                self.process_fanotify_buffer_v1(descriptor, &buffer, deny_all_permissions)?;
            processed = processed
                .checked_add(batch)
                .ok_or(LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
        }
    }

    fn process_fanotify_buffer_v1(
        &mut self,
        fanotify_descriptor: RawFd,
        buffer: &[u8],
        deny_all_permissions: bool,
    ) -> Result<u64, LinuxVzPackageRootFileCollectorErrorV1> {
        let metadata_size = std::mem::size_of::<libc::fanotify_event_metadata>();
        let mut offset = 0_usize;
        let mut count = 0_u64;
        while offset < buffer.len() {
            if buffer.len() - offset < metadata_size {
                return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid);
            }
            let metadata = unsafe {
                std::ptr::read_unaligned(
                    buffer[offset..]
                        .as_ptr()
                        .cast::<libc::fanotify_event_metadata>(),
                )
            };
            let event_len = usize::try_from(metadata.event_len)
                .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid)?;
            if metadata.vers != libc::FANOTIFY_METADATA_VERSION
                || usize::from(metadata.metadata_len) != metadata_size
                || event_len != metadata_size
            {
                return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid);
            }
            offset += event_len;
            count = count
                .checked_add(1)
                .ok_or(LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
            self.process_fanotify_event_v1(fanotify_descriptor, metadata, deny_all_permissions)?;
        }
        Ok(count)
    }

    fn process_fanotify_event_v1(
        &mut self,
        fanotify_descriptor: RawFd,
        metadata: libc::fanotify_event_metadata,
        deny_all_permissions: bool,
    ) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
        let permission_mask =
            libc::FAN_OPEN_PERM | libc::FAN_ACCESS_PERM | libc::FAN_OPEN_EXEC_PERM;
        let supported_mask = permission_mask | libc::FAN_CLOSE_WRITE | libc::FAN_ONDIR;
        if metadata.mask & libc::FAN_Q_OVERFLOW != 0 {
            self.fanotify_overflow_count = self.fanotify_overflow_count.saturating_add(1);
            return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyQueueOverflow);
        }
        if metadata.fd < 0 {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid);
        }
        let event_file = unsafe { OwnedFd::from_raw_fd(metadata.fd) };
        let is_permission = metadata.mask & permission_mask != 0;
        let mut permission_response = FanotifyPermissionResponseGuardV1::new_v1(
            fanotify_descriptor,
            event_file.as_raw_fd(),
            is_permission,
        );
        if metadata.mask & !supported_mask != 0
            || metadata.mask & (permission_mask | libc::FAN_CLOSE_WRITE) == 0
        {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid);
        }
        let actor_pid = u32::try_from(metadata.pid)
            .ok()
            .filter(|value| *value > 1)
            .ok_or(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid)?;
        let membership = cgroup_contains_pid_v1(self.cgroup_directory.as_raw_fd(), actor_pid)?;
        let tracked_start_time = self.tracked_actor_start_times.get(&actor_pid).copied();
        let actor_is_target = if membership {
            let start_time = process_start_time_v1(actor_pid)?;
            if let Some(expected) = tracked_start_time {
                if expected != start_time {
                    permission_response.respond_v1(false)?;
                    if is_permission {
                        self.permission_response_count =
                            self.permission_response_count.saturating_add(1);
                        self.permission_denied_count =
                            self.permission_denied_count.saturating_add(1);
                    }
                    return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
                }
            } else {
                self.tracked_actor_start_times.insert(actor_pid, start_time);
            }
            true
        } else if tracked_start_time.is_some() {
            match process_start_time_v1(actor_pid) {
                Ok(_) => {
                    permission_response.respond_v1(false)?;
                    if is_permission {
                        self.permission_response_count =
                            self.permission_response_count.saturating_add(1);
                        self.permission_denied_count =
                            self.permission_denied_count.saturating_add(1);
                    }
                    return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
                }
                Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)
                    if !is_permission =>
                {
                    true
                }
                Err(_) => {
                    permission_response.respond_v1(false)?;
                    if is_permission {
                        self.permission_response_count =
                            self.permission_response_count.saturating_add(1);
                        self.permission_denied_count =
                            self.permission_denied_count.saturating_add(1);
                    }
                    return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
                }
            }
        } else {
            false
        };
        if !actor_is_target {
            permission_response.respond_v1(true)?;
            self.ignored_non_cgroup_event_count = self
                .ignored_non_cgroup_event_count
                .checked_add(1)
                .ok_or(LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
            return Ok(());
        }
        if self.leader_pid.is_none() {
            permission_response.respond_v1(false)?;
            if is_permission {
                self.permission_response_count = self.permission_response_count.saturating_add(1);
                self.permission_denied_count = self.permission_denied_count.saturating_add(1);
            }
            return Err(LinuxVzPackageRootFileCollectorErrorV1::PreReleaseEvent);
        }
        let mut raw_path = event_fd_path_v1(event_file.as_raw_fd())?;
        let (namespace, path_class, token_input) = classify_observed_path_v1(&raw_path)?;
        let deny =
            deny_all_permissions || path_class == LinuxVzPackageFilePathClassV1::ProtectedSensor;
        let event_kinds = [
            (libc::FAN_OPEN_PERM, LinuxVzPackageRootFileEventKindV1::Open),
            (
                libc::FAN_ACCESS_PERM,
                LinuxVzPackageRootFileEventKindV1::Read,
            ),
            (
                libc::FAN_OPEN_EXEC_PERM,
                LinuxVzPackageRootFileEventKindV1::OpenExec,
            ),
            (
                libc::FAN_CLOSE_WRITE,
                LinuxVzPackageRootFileEventKindV1::Write,
            ),
        ];
        let added_event_count = event_kinds
            .iter()
            .filter(|(mask, _)| metadata.mask & mask != 0)
            .count();
        if self
            .events
            .len()
            .checked_add(added_event_count)
            .is_none_or(|count| count > self.maximum_source_events)
        {
            raw_path.zeroize();
            return Err(LinuxVzPackageRootFileCollectorErrorV1::EventLimitExceeded);
        }
        permission_response.respond_v1(!deny)?;
        if is_permission {
            self.permission_response_count = self.permission_response_count.saturating_add(1);
            if deny {
                self.permission_denied_count = self.permission_denied_count.saturating_add(1);
            }
        }
        if deny_all_permissions {
            raw_path.zeroize();
            return Ok(());
        }
        let path_token =
            root_file_path_token_v1(&self.challenge, namespace, path_class, token_input);
        raw_path.zeroize();
        let path_token = path_token?;
        let outcome = if is_permission && deny {
            LinuxVzPackageRootFileAccessOutcomeV1::Denied
        } else {
            LinuxVzPackageRootFileAccessOutcomeV1::Observed
        };
        for (mask, kind) in event_kinds {
            if metadata.mask & mask == 0 {
                continue;
            }
            let timestamp = monotonic_nanoseconds_v1()?;
            let timestamp = self
                .events
                .last()
                .map(|event| {
                    event
                        .timestamp_monotonic_nanoseconds
                        .checked_add(1)
                        .map(|minimum| timestamp.max(minimum))
                        .ok_or(LinuxVzPackageRootFileCollectorErrorV1::Worker)
                })
                .transpose()?
                .unwrap_or(timestamp);
            self.events.push(LinuxVzPackageRootFileEventV1 {
                kind,
                path_class,
                namespace,
                outcome,
                source_sequence: self.events.len() as u64 + 1,
                timestamp_monotonic_nanoseconds: timestamp,
                actor_pid,
                cgroup_id: self.expected_cgroup_id,
                path_token_sha256: path_token.clone(),
            });
        }
        Ok(())
    }

    fn finish_v1(
        mut self,
        leader_pid: u32,
        process_ended_monotonic_nanoseconds: u64,
    ) -> Result<LinuxVzPackageRootFileCollectionV1, LinuxVzPackageRootFileCollectorErrorV1> {
        if self.leader_pid != Some(leader_pid) || process_ended_monotonic_nanoseconds == 0 {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::InvalidState);
        }
        if let Some(error) = self.fault {
            self.drain_denying_after_fault_v1();
            return Err(error);
        }
        let drained = self.drain_v1(false)?;
        self.maximum_drain_batch_event_count = self.maximum_drain_batch_event_count.max(drained);
        require_cgroup_empty_v1(self.cgroup_directory.as_raw_fd())?;
        self.fanotify.take();
        let final_snapshot = snapshot_workspace_v1(&self.workspace)?;
        let changes = diff_root_file_snapshots_v1(&self.baseline, &final_snapshot)?;
        let now = monotonic_nanoseconds_v1()?;
        let post_exit_minimum = process_ended_monotonic_nanoseconds
            .checked_add(1)
            .ok_or(LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
        let diff_completed_monotonic_nanoseconds = now.max(post_exit_minimum).max(
            self.events
                .last()
                .map(|event| event.timestamp_monotonic_nanoseconds.saturating_add(1))
                .unwrap_or(1),
        );
        Ok(LinuxVzPackageRootFileCollectionV1 {
            cgroup_id: self.expected_cgroup_id,
            leader_pid,
            baseline: self.baseline,
            final_snapshot,
            changes,
            events: self.events,
            process_ended_monotonic_nanoseconds,
            diff_completed_monotonic_nanoseconds,
            active_drain_poll_count: self.active_drain_poll_count,
            active_nonempty_drain_count: self.active_nonempty_drain_count,
            maximum_drain_batch_event_count: self.maximum_drain_batch_event_count,
            ignored_non_cgroup_event_count: self.ignored_non_cgroup_event_count,
            permission_response_count: self.permission_response_count,
            permission_denied_count: self.permission_denied_count,
            fanotify_overflow_count: self.fanotify_overflow_count,
            required_mark_count: u64::try_from(required_fanotify_marks_v1().len())
                .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::Worker)?
                .saturating_add(1),
        })
    }

    fn record_fault_v1(&mut self, error: LinuxVzPackageRootFileCollectorErrorV1) {
        if self.fault.is_some() {
            return;
        }
        self.fault = Some(error);
        let marker = [1_u8];
        loop {
            let result = unsafe {
                libc::write(
                    self.fault_signal_write.as_raw_fd(),
                    marker.as_ptr().cast(),
                    marker.len(),
                )
            };
            if result == marker.len() as isize {
                return;
            }
            if result < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
    }

    fn drain_denying_after_fault_v1(&mut self) {
        loop {
            match self.drain_v1(true) {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn create_fanotify_v1(workspace: &File) -> Result<OwnedFd, LinuxVzPackageRootFileCollectorErrorV1> {
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_fanotify_init,
            libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
            libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 || descriptor > i32::MAX as libc::c_long {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyUnavailable);
    }
    let fanotify = unsafe { OwnedFd::from_raw_fd(descriptor as RawFd) };
    for path in required_fanotify_marks_v1() {
        add_fanotify_mount_mark_v1(fanotify.as_raw_fd(), libc::AT_FDCWD, path)?;
    }
    add_fanotify_mount_mark_v1(fanotify.as_raw_fd(), workspace.as_raw_fd(), c".")?;
    Ok(fanotify)
}

#[cfg(target_os = "linux")]
fn required_fanotify_marks_v1() -> [&'static CStr; 4] {
    [c"/", c"/sys", c"/dev", c"/run"]
}

#[cfg(target_os = "linux")]
fn add_fanotify_mount_mark_v1(
    fanotify: RawFd,
    directory: RawFd,
    path: &CStr,
) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
    let mask = libc::FAN_OPEN_PERM
        | libc::FAN_ACCESS_PERM
        | libc::FAN_OPEN_EXEC_PERM
        | libc::FAN_CLOSE_WRITE
        | libc::FAN_EVENT_ON_CHILD;
    let result = unsafe {
        libc::syscall(
            libc::SYS_fanotify_mark,
            fanotify,
            libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
            mask,
            directory,
            path.as_ptr(),
        )
    };
    if result != 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyMarkFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn respond_fanotify_v1(
    fanotify: RawFd,
    event_descriptor: RawFd,
    allow: bool,
) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
    let response = libc::fanotify_response {
        fd: event_descriptor,
        response: if allow {
            libc::FAN_ALLOW
        } else {
            libc::FAN_DENY
        },
    };
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (&response as *const libc::fanotify_response).cast::<u8>(),
            std::mem::size_of::<libc::fanotify_response>(),
        )
    };
    let expected_length = isize::try_from(bytes.len())
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::FanotifyResponseFailed)?;
    loop {
        let result = unsafe { libc::write(fanotify, bytes.as_ptr().cast(), bytes.len()) };
        if result == expected_length {
            return Ok(());
        }
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyResponseFailed);
        }
        return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyResponseFailed);
    }
}

#[cfg(target_os = "linux")]
struct FanotifyPermissionResponseGuardV1 {
    fanotify: RawFd,
    event_descriptor: RawFd,
    response_required: bool,
    responded: bool,
}

#[cfg(target_os = "linux")]
impl FanotifyPermissionResponseGuardV1 {
    const fn new_v1(fanotify: RawFd, event_descriptor: RawFd, response_required: bool) -> Self {
        Self {
            fanotify,
            event_descriptor,
            response_required,
            responded: false,
        }
    }

    fn respond_v1(&mut self, allow: bool) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
        if !self.response_required {
            return Ok(());
        }
        if self.responded {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyResponseFailed);
        }
        respond_fanotify_v1(self.fanotify, self.event_descriptor, allow)?;
        self.responded = true;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for FanotifyPermissionResponseGuardV1 {
    fn drop(&mut self) {
        if self.response_required && !self.responded {
            let _ = respond_fanotify_v1(self.fanotify, self.event_descriptor, false);
            self.responded = true;
        }
    }
}

#[cfg(target_os = "linux")]
fn event_fd_path_v1(descriptor: RawFd) -> Result<Vec<u8>, LinuxVzPackageRootFileCollectorErrorV1> {
    let link = CString::new(format!("/proc/self/fd/{descriptor}"))
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid)?;
    let mut path = vec![0_u8; MAX_ROOT_FILE_PATH_BYTES_V1 + 1];
    let length = unsafe { libc::readlink(link.as_ptr(), path.as_mut_ptr().cast(), path.len()) };
    if length <= 0 || usize::try_from(length).ok() == Some(path.len()) {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid);
    }
    path.truncate(
        usize::try_from(length)
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid)?,
    );
    if let Some(value) = path.strip_suffix(b" (deleted)") {
        path = value.to_vec();
    }
    if !path.starts_with(b"/") || path.contains(&0) {
        path.zeroize();
        return Err(LinuxVzPackageRootFileCollectorErrorV1::FanotifyEventInvalid);
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn classify_observed_path_v1(
    absolute_path: &[u8],
) -> Result<
    (
        LinuxVzPackageRootFilePathNamespaceV1,
        LinuxVzPackageFilePathClassV1,
        &[u8],
    ),
    LinuxVzPackageRootFileCollectorErrorV1,
> {
    if absolute_path == PACKAGE_WORKSPACE_PATH_V1 {
        return Ok((
            LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
            LinuxVzPackageFilePathClassV1::Workspace,
            b".",
        ));
    }
    if let Some(relative) = absolute_path
        .strip_prefix(PACKAGE_WORKSPACE_PATH_V1)
        .and_then(|value| value.strip_prefix(b"/"))
    {
        return Ok((
            LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
            classify_workspace_path_v1(relative),
            relative,
        ));
    }
    let path_class = if absolute_path == b"/whoathere/package-runtime-probe"
        || absolute_path == b"/whoathere/process-fixture-child"
    {
        LinuxVzPackageFilePathClassV1::Runtime
    } else if path_prefix_v1(absolute_path, b"/whoathere") {
        LinuxVzPackageFilePathClassV1::ProtectedSensor
    } else if is_ssh_path_v1(absolute_path) {
        LinuxVzPackageFilePathClassV1::SensitiveSsh
    } else if is_persistence_path_v1(absolute_path) {
        LinuxVzPackageFilePathClassV1::PersistenceStartup
    } else if is_sensitive_credential_path_v1(absolute_path) {
        LinuxVzPackageFilePathClassV1::SensitiveCredential
    } else if path_prefix_v1(absolute_path, b"/usr")
        || path_prefix_v1(absolute_path, b"/bin")
        || path_prefix_v1(absolute_path, b"/sbin")
        || path_prefix_v1(absolute_path, b"/lib")
    {
        LinuxVzPackageFilePathClassV1::Runtime
    } else {
        LinuxVzPackageFilePathClassV1::Other
    };
    Ok((
        LinuxVzPackageRootFilePathNamespaceV1::Absolute,
        path_class,
        absolute_path,
    ))
}

fn classify_workspace_path_v1(relative: &[u8]) -> LinuxVzPackageFilePathClassV1 {
    if path_prefix_v1(relative, b"cache") {
        LinuxVzPackageFilePathClassV1::PackageCache
    } else if relative == b"home/.whoathere-canary"
        || path_prefix_v1(relative, b"home/.whoathere-canaries")
    {
        LinuxVzPackageFilePathClassV1::ProtectedCanary
    } else if path_prefix_v1(relative, b"home/.ssh") {
        LinuxVzPackageFilePathClassV1::SensitiveSsh
    } else if relative == b"home/.profile"
        || relative == b"home/.bashrc"
        || relative == b"home/.zshrc"
        || path_prefix_v1(relative, b"home/.config/autostart")
    {
        LinuxVzPackageFilePathClassV1::PersistenceStartup
    } else if relative == b"home/.npmrc"
        || relative == b"home/.pypirc"
        || path_prefix_v1(relative, b"home/.config/pip")
    {
        LinuxVzPackageFilePathClassV1::SensitiveCredential
    } else {
        LinuxVzPackageFilePathClassV1::Workspace
    }
}

fn path_prefix_v1(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|suffix| suffix.starts_with(b"/"))
}

fn is_ssh_path_v1(path: &[u8]) -> bool {
    path_prefix_v1(path, b"/root/.ssh")
        || user_home_relative_path_v1(path)
            .is_some_and(|relative| path_prefix_v1(relative, b".ssh"))
}

fn is_persistence_path_v1(path: &[u8]) -> bool {
    [
        b"/etc/cron".as_slice(),
        b"/etc/crontab".as_slice(),
        b"/etc/init.d".as_slice(),
        b"/etc/profile".as_slice(),
        b"/etc/profile.d".as_slice(),
        b"/etc/rc.local".as_slice(),
        b"/etc/systemd".as_slice(),
        b"/root/.profile".as_slice(),
        b"/root/.bashrc".as_slice(),
        b"/root/.zshrc".as_slice(),
        b"/root/.config/autostart".as_slice(),
        b"/usr/lib/systemd".as_slice(),
        b"/var/spool/cron".as_slice(),
    ]
    .iter()
    .any(|prefix| path_prefix_v1(path, prefix))
        || user_home_relative_path_v1(path).is_some_and(|relative| {
            relative == b".profile"
                || relative == b".bashrc"
                || relative == b".zshrc"
                || path_prefix_v1(relative, b".config/autostart")
        })
}

fn is_sensitive_credential_path_v1(path: &[u8]) -> bool {
    path == b"/etc/shadow"
        || path == b"/etc/gshadow"
        || path == b"/root/.npmrc"
        || path == b"/root/.pypirc"
        || path_prefix_v1(path, b"/root/.config/pip")
        || path_prefix_v1(path, b"/root/.aws")
        || path_prefix_v1(path, b"/root/.config/gcloud")
        || user_home_relative_path_v1(path).is_some_and(|relative| {
            relative == b".npmrc"
                || relative == b".pypirc"
                || path_prefix_v1(relative, b".config/pip")
                || path_prefix_v1(relative, b".aws")
                || path_prefix_v1(relative, b".config/gcloud")
        })
        || proc_environ_path_v1(path)
}

fn user_home_relative_path_v1(path: &[u8]) -> Option<&[u8]> {
    let suffix = path.strip_prefix(b"/home/")?;
    let separator = suffix.iter().position(|byte| *byte == b'/')?;
    if separator == 0 || separator + 1 >= suffix.len() {
        return None;
    }
    Some(&suffix[separator + 1..])
}

fn proc_environ_path_v1(path: &[u8]) -> bool {
    let Some(suffix) = path.strip_prefix(b"/proc/") else {
        return false;
    };
    let Some(pid) = suffix.strip_suffix(b"/environ") else {
        return false;
    };
    !pid.is_empty() && !pid.contains(&b'/') && pid.iter().all(u8::is_ascii_digit)
}

#[cfg(target_os = "linux")]
fn snapshot_workspace_v1(
    workspace: &File,
) -> Result<LinuxVzPackageRootFileSnapshotV1, LinuxVzPackageRootFileCollectorErrorV1> {
    let root_stat = fstat_v1(workspace.as_raw_fd())?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(workspace.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    let filesystem = unsafe { filesystem.assume_init() };
    let mut entries = BTreeMap::new();
    let mut regular_file_bytes_hashed = 0_u64;
    collect_snapshot_directory_v1(
        workspace,
        &[],
        0,
        &mut entries,
        &mut regular_file_bytes_hashed,
    )?;
    Ok(LinuxVzPackageRootFileSnapshotV1 {
        root_device: root_stat.st_dev,
        root_inode: root_stat.st_ino,
        filesystem_magic: filesystem_magic_v1(filesystem.f_type)?,
        entries,
        regular_file_bytes_hashed,
    })
}

#[cfg(target_os = "linux")]
fn collect_snapshot_directory_v1(
    directory: &File,
    prefix: &[u8],
    depth: usize,
    entries: &mut BTreeMap<Vec<u8>, LinuxVzPackageRootFileSnapshotEntryV1>,
    regular_file_bytes_hashed: &mut u64,
) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
    if depth > MAX_ROOT_FILE_PATH_DEPTH_V1 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotLimitExceeded);
    }
    let mut names = list_directory_names_v1(directory)?;
    names.sort();
    for name in names {
        let relative_path = if prefix.is_empty() {
            name.clone()
        } else {
            let mut value = Vec::with_capacity(prefix.len() + name.len() + 1);
            value.extend_from_slice(prefix);
            value.push(b'/');
            value.extend_from_slice(&name);
            value
        };
        if relative_path.is_empty() || relative_path.len() > MAX_ROOT_FILE_PATH_BYTES_V1 {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotLimitExceeded);
        }
        if entries.len() >= MAX_ROOT_FILE_SNAPSHOT_ENTRIES_V1 {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotLimitExceeded);
        }
        let name_c = CString::new(name)
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)?;
        let stat_before = fstatat_nofollow_v1(directory.as_raw_fd(), &name_c)?;
        let kind = entry_kind_v1(stat_before.st_mode)?;
        let (content_sha256, symlink_target_sha256) = match kind {
            LinuxVzPackageRootFileEntryKindV1::Regular => {
                let mut file = open_regular_at_v1(directory.as_raw_fd(), &name_c)?;
                let opened = fstat_v1(file.as_raw_fd())?;
                require_same_stat_identity_v1(&stat_before, &opened)?;
                let byte_length = u64::try_from(stat_before.st_size)
                    .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)?;
                *regular_file_bytes_hashed = regular_file_bytes_hashed
                    .checked_add(byte_length)
                    .ok_or(LinuxVzPackageRootFileCollectorErrorV1::SnapshotLimitExceeded)?;
                if *regular_file_bytes_hashed > MAX_ROOT_FILE_SNAPSHOT_REGULAR_BYTES_V1 {
                    return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotLimitExceeded);
                }
                let digest = digest_reader_v1(&mut file)?;
                let after = fstat_v1(file.as_raw_fd())?;
                require_same_stat_identity_v1(&stat_before, &after)?;
                (Some(digest), None)
            }
            LinuxVzPackageRootFileEntryKindV1::Symlink => {
                let mut target = readlinkat_v1(directory.as_raw_fd(), &name_c)?;
                let after = fstatat_nofollow_v1(directory.as_raw_fd(), &name_c)?;
                require_same_stat_identity_v1(&stat_before, &after)?;
                let digest = Sha256Digest::from_bytes(&target);
                target.zeroize();
                (None, Some(digest))
            }
            _ => (None, None),
        };
        let byte_length = u64::try_from(stat_before.st_size)
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)?;
        let fingerprint_sha256 = snapshot_entry_fingerprint_v1(
            kind,
            stat_before.st_mode & 0o7777,
            stat_before.st_uid,
            stat_before.st_gid,
            stat_before.st_dev,
            stat_before.st_ino,
            u64::from(stat_before.st_nlink),
            byte_length,
            content_sha256.as_ref(),
            symlink_target_sha256.as_ref(),
        );
        let path_class = classify_workspace_path_v1(&relative_path);
        let entry = LinuxVzPackageRootFileSnapshotEntryV1 {
            relative_path: relative_path.clone(),
            path_class,
            kind,
            mode: stat_before.st_mode & 0o7777,
            uid: stat_before.st_uid,
            gid: stat_before.st_gid,
            device: stat_before.st_dev,
            inode: stat_before.st_ino,
            link_count: u64::from(stat_before.st_nlink),
            byte_length,
            content_sha256,
            symlink_target_sha256,
            fingerprint_sha256,
        };
        if entries.insert(relative_path.clone(), entry).is_some() {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
        }
        if kind == LinuxVzPackageRootFileEntryKindV1::Directory {
            let child = open_directory_at_v1(directory.as_raw_fd(), &name_c)?;
            let opened = fstat_v1(child.as_raw_fd())?;
            require_same_stat_identity_v1(&stat_before, &opened)?;
            collect_snapshot_directory_v1(
                &child,
                &relative_path,
                depth + 1,
                entries,
                regular_file_bytes_hashed,
            )?;
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn snapshot_entry_fingerprint_v1(
    kind: LinuxVzPackageRootFileEntryKindV1,
    mode: u32,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
    link_count: u64,
    byte_length: u64,
    content_sha256: Option<&Sha256Digest>,
    symlink_target_sha256: Option<&Sha256Digest>,
) -> Sha256Digest {
    let mut input = Vec::with_capacity(256);
    input.extend_from_slice(b"whoathere.linux_vz_package_root_file_snapshot_entry.v1\0");
    input.extend_from_slice(kind.as_str_v1().as_bytes());
    input.push(0);
    input.extend_from_slice(&mode.to_be_bytes());
    input.extend_from_slice(&uid.to_be_bytes());
    input.extend_from_slice(&gid.to_be_bytes());
    input.extend_from_slice(&device.to_be_bytes());
    input.extend_from_slice(&inode.to_be_bytes());
    input.extend_from_slice(&link_count.to_be_bytes());
    input.extend_from_slice(&byte_length.to_be_bytes());
    if let Some(value) = content_sha256 {
        input.extend_from_slice(value.as_str().as_bytes());
    }
    input.push(0);
    if let Some(value) = symlink_target_sha256 {
        input.extend_from_slice(value.as_str().as_bytes());
    }
    Sha256Digest::from_bytes(&input)
}

#[cfg(target_os = "linux")]
fn digest_reader_v1(
    reader: &mut File,
) -> Result<Sha256Digest, LinuxVzPackageRootFileCollectorErrorV1> {
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let bytes = digest.finalize();
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)?;
    }
    Sha256Digest::parse(value).map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)
}

#[cfg(target_os = "linux")]
fn list_directory_names_v1(
    directory: &File,
) -> Result<Vec<Vec<u8>>, LinuxVzPackageRootFileCollectorErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            c".".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        let _ = unsafe { libc::close(descriptor) };
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            let _ = unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        clear_errno_v1();
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            if errno_v1() != 0 {
                return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if name.is_empty() || name.len() > libc::NAME_MAX as usize {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
        }
        names.push(name.to_vec());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn entry_kind_v1(
    mode: libc::mode_t,
) -> Result<LinuxVzPackageRootFileEntryKindV1, LinuxVzPackageRootFileCollectorErrorV1> {
    match mode & libc::S_IFMT {
        libc::S_IFDIR => Ok(LinuxVzPackageRootFileEntryKindV1::Directory),
        libc::S_IFREG => Ok(LinuxVzPackageRootFileEntryKindV1::Regular),
        libc::S_IFLNK => Ok(LinuxVzPackageRootFileEntryKindV1::Symlink),
        libc::S_IFIFO => Ok(LinuxVzPackageRootFileEntryKindV1::Fifo),
        libc::S_IFSOCK => Ok(LinuxVzPackageRootFileEntryKindV1::Socket),
        libc::S_IFCHR => Ok(LinuxVzPackageRootFileEntryKindV1::CharacterDevice),
        libc::S_IFBLK => Ok(LinuxVzPackageRootFileEntryKindV1::BlockDevice),
        _ => Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed),
    }
}

#[cfg(target_os = "linux")]
fn filesystem_magic_v1<T>(value: T) -> Result<u64, LinuxVzPackageRootFileCollectorErrorV1>
where
    T: TryInto<u64>,
{
    value
        .try_into()
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)
}

#[cfg(target_os = "linux")]
fn open_workspace_v1() -> Result<File, LinuxVzPackageRootFileCollectorErrorV1> {
    let descriptor = unsafe {
        libc::open(
            PACKAGE_WORKSPACE_PATH_C_V1.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::OpenFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn validate_workspace_v1(workspace: &File) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
    let stat = fstat_v1(workspace.as_raw_fd())?;
    let mut filesystem = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(workspace.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::WorkspaceInvalid);
    }
    let filesystem = unsafe { filesystem.assume_init() };
    const TMPFS_MAGIC: i64 = 0x0102_1994;
    if stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || stat.st_uid != 0
        || stat.st_gid != 0
        || stat.st_mode & 0o7777 != 0o755
        || filesystem.f_type as i64 != TMPFS_MAGIC
    {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::WorkspaceInvalid);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_directory_at_v1(
    parent: RawFd,
    name: &CStr,
) -> Result<File, LinuxVzPackageRootFileCollectorErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn open_regular_at_v1(
    parent: RawFd,
    name: &CStr,
) -> Result<File, LinuxVzPackageRootFileCollectorErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

#[cfg(target_os = "linux")]
fn fstat_v1(descriptor: RawFd) -> Result<libc::stat, LinuxVzPackageRootFileCollectorErrorV1> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(descriptor, stat.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    Ok(unsafe { stat.assume_init() })
}

#[cfg(target_os = "linux")]
fn fstatat_nofollow_v1(
    parent: RawFd,
    name: &CStr,
) -> Result<libc::stat, LinuxVzPackageRootFileCollectorErrorV1> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    Ok(unsafe { stat.assume_init() })
}

#[cfg(target_os = "linux")]
fn require_same_stat_identity_v1(
    expected: &libc::stat,
    observed: &libc::stat,
) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
    if expected.st_dev != observed.st_dev
        || expected.st_ino != observed.st_ino
        || expected.st_mode != observed.st_mode
        || expected.st_uid != observed.st_uid
        || expected.st_gid != observed.st_gid
        || expected.st_nlink != observed.st_nlink
        || expected.st_size != observed.st_size
    {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotRace);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn readlinkat_v1(
    parent: RawFd,
    name: &CStr,
) -> Result<Vec<u8>, LinuxVzPackageRootFileCollectorErrorV1> {
    let mut target = vec![0_u8; MAX_ROOT_FILE_PATH_BYTES_V1 + 1];
    let length = unsafe {
        libc::readlinkat(
            parent,
            name.as_ptr(),
            target.as_mut_ptr().cast(),
            target.len(),
        )
    };
    if length < 0 || usize::try_from(length).ok() == Some(target.len()) {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed);
    }
    target.truncate(
        usize::try_from(length)
            .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::SnapshotFailed)?,
    );
    Ok(target)
}

#[cfg(target_os = "linux")]
fn duplicate_fd_v1(descriptor: RawFd) -> Result<OwnedFd, LinuxVzPackageRootFileCollectorErrorV1> {
    let duplicate = unsafe { libc::fcntl(descriptor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::OpenFailed);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

#[cfg(target_os = "linux")]
fn require_cgroup_empty_v1(
    cgroup_directory: RawFd,
) -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
    if read_cgroup_processes_v1(cgroup_directory)?.is_empty() {
        Ok(())
    } else {
        Err(LinuxVzPackageRootFileCollectorErrorV1::InvalidState)
    }
}

#[cfg(target_os = "linux")]
fn cgroup_contains_pid_v1(
    cgroup_directory: RawFd,
    pid: u32,
) -> Result<bool, LinuxVzPackageRootFileCollectorErrorV1> {
    Ok(read_cgroup_processes_v1(cgroup_directory)?.contains(&pid))
}

#[cfg(target_os = "linux")]
fn read_cgroup_processes_v1(
    cgroup_directory: RawFd,
) -> Result<BTreeSet<u32>, LinuxVzPackageRootFileCollectorErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            cgroup_directory,
            c"cgroup.procs".as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
    }
    const MAX_CGROUP_PROCS_BYTES_V1: usize = 1024 * 1024;
    let file = unsafe { File::from_raw_fd(descriptor) };
    let mut bytes = Vec::new();
    let read_limit = u64::try_from(MAX_CGROUP_PROCS_BYTES_V1)
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?
        .saturating_add(1);
    file.take(read_limit)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
    if bytes.len() > MAX_CGROUP_PROCS_BYTES_V1 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
    let mut pids = BTreeSet::new();
    for line in text.lines() {
        if line.is_empty()
            || line.starts_with('0')
            || !line.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
        }
        let pid = line
            .parse::<u32>()
            .ok()
            .filter(|value| *value > 1)
            .ok_or(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
        if !pids.insert(pid) {
            return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
        }
    }
    Ok(pids)
}

#[cfg(target_os = "linux")]
fn process_start_time_v1(pid: u32) -> Result<u64, LinuxVzPackageRootFileCollectorErrorV1> {
    let path = OsString::from_vec(format!("/proc/{pid}/stat").into_bytes());
    let bytes = std::fs::read(path)
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
    if bytes.is_empty() || bytes.len() > 4096 || bytes.contains(&0) {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed);
    }
    let close = bytes
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
    let remainder = bytes
        .get(close + 2..)
        .ok_or(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
    let fields = remainder
        .split(|byte| *byte == b' ')
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    let start_time = fields
        .get(19)
        .ok_or(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
    let text = std::str::from_utf8(start_time)
        .map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)?;
    text.parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(LinuxVzPackageRootFileCollectorErrorV1::ActorCorrelationFailed)
}

#[cfg(target_os = "linux")]
fn monotonic_nanoseconds_v1() -> Result<u64, LinuxVzPackageRootFileCollectorErrorV1> {
    let mut value = std::mem::MaybeUninit::<libc::timespec>::uninit();
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, value.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::Worker);
    }
    let value = unsafe { value.assume_init() };
    let seconds =
        u64::try_from(value.tv_sec).map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
    let nanoseconds =
        u64::try_from(value.tv_nsec).map_err(|_| LinuxVzPackageRootFileCollectorErrorV1::Worker)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .filter(|value| *value > 0)
        .ok_or(LinuxVzPackageRootFileCollectorErrorV1::Worker)
}

#[cfg(target_os = "linux")]
fn require_root_v1() -> Result<(), LinuxVzPackageRootFileCollectorErrorV1> {
    if unsafe { libc::getuid() } == 0
        && unsafe { libc::geteuid() } == 0
        && unsafe { libc::getgid() } == 0
        && unsafe { libc::getegid() } == 0
    {
        Ok(())
    } else {
        Err(LinuxVzPackageRootFileCollectorErrorV1::PrivilegeBoundary)
    }
}

#[cfg(target_os = "linux")]
fn create_pipe_v1() -> Result<(OwnedFd, OwnedFd), LinuxVzPackageRootFileCollectorErrorV1> {
    let mut descriptors = [-1_i32; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(LinuxVzPackageRootFileCollectorErrorV1::Worker);
    }
    Ok((unsafe { OwnedFd::from_raw_fd(descriptors[0]) }, unsafe {
        OwnedFd::from_raw_fd(descriptors[1])
    }))
}

#[cfg(target_os = "linux")]
fn clear_errno_v1() {
    unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "linux")]
fn errno_v1() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn entry(
        path: &[u8],
        class: LinuxVzPackageFilePathClassV1,
        kind: LinuxVzPackageRootFileEntryKindV1,
        device: u64,
        inode: u64,
        content: Option<&[u8]>,
        mode: u32,
        byte_length: u64,
    ) -> LinuxVzPackageRootFileSnapshotEntryV1 {
        let content_sha256 = content.map(Sha256Digest::from_bytes);
        let fingerprint_sha256 = {
            let mut input = Vec::new();
            input.extend_from_slice(kind.as_str_v1().as_bytes());
            input.extend_from_slice(&mode.to_be_bytes());
            input.extend_from_slice(&device.to_be_bytes());
            input.extend_from_slice(&inode.to_be_bytes());
            input.extend_from_slice(&byte_length.to_be_bytes());
            if let Some(value) = &content_sha256 {
                input.extend_from_slice(value.as_str().as_bytes());
            }
            Sha256Digest::from_bytes(&input)
        };
        LinuxVzPackageRootFileSnapshotEntryV1 {
            relative_path: path.to_vec(),
            path_class: class,
            kind,
            mode,
            uid: 65534,
            gid: 65534,
            device,
            inode,
            link_count: 1,
            byte_length,
            content_sha256,
            symlink_target_sha256: None,
            fingerprint_sha256,
        }
    }

    fn snapshot(
        entries: Vec<LinuxVzPackageRootFileSnapshotEntryV1>,
    ) -> LinuxVzPackageRootFileSnapshotV1 {
        LinuxVzPackageRootFileSnapshotV1 {
            root_device: 9,
            root_inode: 10,
            filesystem_magic: 0x0102_1994,
            regular_file_bytes_hashed: entries.iter().map(|entry| entry.byte_length).sum(),
            entries: entries
                .into_iter()
                .map(|entry| (entry.relative_path.clone(), entry))
                .collect(),
        }
    }

    #[test]
    fn diff_detects_content_metadata_create_delete_and_inode_bound_rename() {
        let baseline = snapshot(vec![
            entry(
                b"work/modified",
                LinuxVzPackageFilePathClassV1::Workspace,
                LinuxVzPackageRootFileEntryKindV1::Regular,
                9,
                20,
                Some(b"before"),
                0o600,
                6,
            ),
            entry(
                b"home/.profile",
                LinuxVzPackageFilePathClassV1::PersistenceStartup,
                LinuxVzPackageRootFileEntryKindV1::Regular,
                9,
                21,
                Some(b"profile"),
                0o600,
                7,
            ),
            entry(
                b"work/old-name",
                LinuxVzPackageFilePathClassV1::Workspace,
                LinuxVzPackageRootFileEntryKindV1::Regular,
                9,
                22,
                Some(b"rename"),
                0o600,
                6,
            ),
        ]);
        let final_snapshot = snapshot(vec![
            entry(
                b"work/modified",
                LinuxVzPackageFilePathClassV1::Workspace,
                LinuxVzPackageRootFileEntryKindV1::Regular,
                9,
                20,
                Some(b"after!"),
                0o644,
                6,
            ),
            entry(
                b"work/new-name",
                LinuxVzPackageFilePathClassV1::Workspace,
                LinuxVzPackageRootFileEntryKindV1::Regular,
                9,
                22,
                Some(b"rename"),
                0o600,
                6,
            ),
            entry(
                b"home/.whoathere-canary",
                LinuxVzPackageFilePathClassV1::ProtectedCanary,
                LinuxVzPackageRootFileEntryKindV1::Regular,
                9,
                23,
                Some(b"created"),
                0o600,
                7,
            ),
        ]);
        let changes = diff_root_file_snapshots_v1(&baseline, &final_snapshot).expect("diff");
        assert_eq!(changes.len(), 4);
        assert!(changes.iter().any(|change| {
            change.kind == LinuxVzPackageRootFileChangeKindV1::Modified
                && change.path == b"work/modified"
                && change.content_changed
                && change.metadata_changed
        }));
        assert!(changes.iter().any(|change| {
            change.kind == LinuxVzPackageRootFileChangeKindV1::Deleted
                && change.path == b"home/.profile"
                && change.path_class == LinuxVzPackageFilePathClassV1::PersistenceStartup
        }));
        assert!(changes.iter().any(|change| {
            change.kind == LinuxVzPackageRootFileChangeKindV1::Created
                && change.path == b"home/.whoathere-canary"
                && change.path_class == LinuxVzPackageFilePathClassV1::ProtectedCanary
        }));
        assert!(changes.iter().any(|change| {
            change.kind == LinuxVzPackageRootFileChangeKindV1::Renamed
                && change.path == b"work/new-name"
                && change.secondary_path.as_deref() == Some(b"work/old-name".as_slice())
        }));
    }

    #[test]
    fn diff_rejects_workspace_identity_rebinding() {
        let baseline = snapshot(Vec::new());
        let mut final_snapshot = snapshot(Vec::new());
        final_snapshot.root_inode += 1;
        assert_eq!(
            diff_root_file_snapshots_v1(&baseline, &final_snapshot),
            Err(LinuxVzPackageRootFileCollectorErrorV1::WorkspaceInvalid)
        );
    }

    #[test]
    fn path_tokens_are_challenge_namespace_class_and_path_bound() {
        let challenge = Sha256Digest::from_bytes(b"challenge");
        let base = root_file_path_token_v1(
            &challenge,
            LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
            LinuxVzPackageFilePathClassV1::Workspace,
            b"work/package.json",
        )
        .expect("token");
        let variants = [
            root_file_path_token_v1(
                &Sha256Digest::from_bytes(b"other challenge"),
                LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
                LinuxVzPackageFilePathClassV1::Workspace,
                b"work/package.json",
            )
            .unwrap(),
            root_file_path_token_v1(
                &challenge,
                LinuxVzPackageRootFilePathNamespaceV1::Absolute,
                LinuxVzPackageFilePathClassV1::Workspace,
                b"work/package.json",
            )
            .unwrap(),
            root_file_path_token_v1(
                &challenge,
                LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
                LinuxVzPackageFilePathClassV1::PackageCache,
                b"work/package.json",
            )
            .unwrap(),
            root_file_path_token_v1(
                &challenge,
                LinuxVzPackageRootFilePathNamespaceV1::WorkspaceRelative,
                LinuxVzPackageFilePathClassV1::Workspace,
                b"work/other.json",
            )
            .unwrap(),
        ];
        assert!(variants.iter().all(|value| value != &base));
    }

    #[test]
    fn path_classification_is_closed_and_not_substring_based() {
        assert_eq!(
            classify_workspace_path_v1(b"cache/npm/object"),
            LinuxVzPackageFilePathClassV1::PackageCache
        );
        assert_eq!(
            classify_workspace_path_v1(b"home/.profile"),
            LinuxVzPackageFilePathClassV1::PersistenceStartup
        );
        assert_eq!(
            classify_workspace_path_v1(b"work/fake-home/.profile"),
            LinuxVzPackageFilePathClassV1::Workspace
        );
        assert_eq!(
            classify_workspace_path_v1(b"home/.whoathere-canary"),
            LinuxVzPackageFilePathClassV1::ProtectedCanary
        );
        assert_eq!(
            classify_workspace_path_v1(b"home/.ssh/id_ed25519"),
            LinuxVzPackageFilePathClassV1::SensitiveSsh
        );
        assert!(is_ssh_path_v1(b"/root/.ssh/id_ed25519"));
        assert!(is_ssh_path_v1(b"/home/package/.ssh/id_ed25519"));
        assert!(!is_ssh_path_v1(b"/tmp/fake/.ssh/id_ed25519"));
        assert!(!is_ssh_path_v1(b"/home//.ssh/id_ed25519"));
        assert!(is_persistence_path_v1(
            b"/home/package/.config/autostart/agent.desktop"
        ));
        assert!(!is_persistence_path_v1(b"/tmp/home/package/.profile"));
        assert!(is_sensitive_credential_path_v1(b"/proc/123/environ"));
        assert!(!is_sensitive_credential_path_v1(b"/proc/abc/environ"));
        assert!(!is_sensitive_credential_path_v1(b"/proc/1/task/1/environ"));
    }

    #[test]
    fn reason_codes_are_stable_and_non_linux_constructor_is_closed() {
        assert_eq!(
            LinuxVzPackageRootFileCollectorErrorV1::FanotifyQueueOverflow.reason_code(),
            "linux_vz_package_root_file_fanotify_queue_overflow"
        );
        #[cfg(not(target_os = "linux"))]
        assert!(matches!(
            LinuxVzPackageRootFileCollectorV1::arm_v1(
                1,
                -1,
                Sha256Digest::from_bytes(b"challenge"),
                1,
            ),
            Err(LinuxVzPackageRootFileCollectorErrorV1::UnsupportedPlatform)
        ));
    }
}
