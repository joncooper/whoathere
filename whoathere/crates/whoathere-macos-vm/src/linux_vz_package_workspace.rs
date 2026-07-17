// Darwin exposes several stat mode constants narrower than `u32`, while Linux exposes them as
// `u32`; the explicit conversions keep this descriptor code identical on both targets.
#![allow(clippy::useless_conversion)]

use crate::{LinuxVzPackageMaterializationPolicyV1, MacosLinuxVzPackageExecutionProcessPlanV1};
use serde::Serialize;
use std::ffi::{CStr, CString};
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_WORKSPACE_OBSERVATION_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_workspace_observation.v1";
pub const MAX_LINUX_VZ_PACKAGE_WORKSPACE_OBSERVATION_BYTES_V1: usize = 64 * 1024;
pub const LINUX_VZ_PACKAGE_GUEST_CANARY_SEED_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_guest_canary_seed.v1";

const NPMRC_CANARY_RELATIVE_PATH_V1: &str = "home/.npmrc";
const NPM_TOKEN_CANARY_RELATIVE_PATH_V1: &str = "home/.whoathere-canaries/npm-token";
const PYPI_TOKEN_CANARY_RELATIVE_PATH_V1: &str = "home/.whoathere-canaries/pypi-token";

#[cfg(target_os = "linux")]
const RUN_PARENT_PATH_V1: &str = "/run";
#[cfg(target_os = "linux")]
const RUN_ROOT_NAME_V1: &str = "whoathere";
const RUN_ROOT_PATH_V1: &str = "/run/whoathere";
const TMPFS_SIZE_BYTES_V1: u64 = 1024 * 1024 * 1024;
const TMPFS_INODE_LIMIT_V1: u64 = 131_072;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageWorkspaceErrorV1 {
    UnsupportedPlatform,
    PrivilegeBoundary,
    InvalidProcessPlan,
    ParentUnsafe,
    WorkspaceAlreadyPresent,
    MountFailed,
    WrongFilesystem,
    CreateFailed,
    OwnershipFailed,
    VerificationFailed,
    Serialization,
    LimitExceeded,
    CleanupFailed,
}

impl LinuxVzPackageWorkspaceErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => "linux_vz_package_workspace_platform_unsupported",
            Self::PrivilegeBoundary => "linux_vz_package_workspace_privilege_invalid",
            Self::InvalidProcessPlan => "linux_vz_package_workspace_process_plan_invalid",
            Self::ParentUnsafe => "linux_vz_package_workspace_parent_unsafe",
            Self::WorkspaceAlreadyPresent => "linux_vz_package_workspace_already_present",
            Self::MountFailed => "linux_vz_package_workspace_mount_failed",
            Self::WrongFilesystem => "linux_vz_package_workspace_filesystem_invalid",
            Self::CreateFailed => "linux_vz_package_workspace_create_failed",
            Self::OwnershipFailed => "linux_vz_package_workspace_ownership_failed",
            Self::VerificationFailed => "linux_vz_package_workspace_verification_failed",
            Self::Serialization => "linux_vz_package_workspace_serialization_failed",
            Self::LimitExceeded => "linux_vz_package_workspace_limit_exceeded",
            Self::CleanupFailed => "linux_vz_package_workspace_cleanup_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageWorkspaceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageWorkspaceErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageWorkspaceDirectoryObservationV1 {
    relative_path: String,
    uid: String,
    gid: String,
    mode: String,
    device: String,
    inode: String,
}

impl LinuxVzPackageWorkspaceDirectoryObservationV1 {
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    pub fn uid(&self) -> u32 {
        self.uid.parse().expect("validated workspace uid")
    }

    pub fn gid(&self) -> u32 {
        self.gid.parse().expect("validated workspace gid")
    }

    pub fn mode(&self) -> u32 {
        self.mode.parse().expect("validated workspace mode")
    }

    pub fn device(&self) -> u64 {
        self.device.parse().expect("validated workspace device")
    }

    pub fn inode(&self) -> u64 {
        self.inode.parse().expect("validated workspace inode")
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackageWorkspaceObservationWireV1<'a> {
    schema_version: &'static str,
    process_plan_sha256: &'a Sha256Digest,
    run_root: &'static str,
    filesystem: &'static str,
    tmpfs_size_bytes: String,
    tmpfs_inode_limit: String,
    mount_nodev: bool,
    mount_nosuid: bool,
    mount_executable: bool,
    public_network_route_present: bool,
    directories: &'a [LinuxVzPackageWorkspaceDirectoryObservationV1],
    package_execution: bool,
    sync_back: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageWorkspaceObservationV1 {
    canonical_json: Vec<u8>,
    observation_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    directories: Vec<LinuxVzPackageWorkspaceDirectoryObservationV1>,
}

impl fmt::Debug for LinuxVzPackageWorkspaceObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageWorkspaceObservationV1")
            .field("observation_sha256", &self.observation_sha256)
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("directory_count", &self.directories.len())
            .finish()
    }
}

impl LinuxVzPackageWorkspaceObservationV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn observation_sha256(&self) -> &Sha256Digest {
        &self.observation_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn directories(&self) -> &[LinuxVzPackageWorkspaceDirectoryObservationV1] {
        &self.directories
    }

    pub const fn package_execution_authority_present(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageGuestCanaryFileBindingV1 {
    relative_path: &'static str,
    relative_path_sha256: Sha256Digest,
    content_sha256: Sha256Digest,
    byte_length: usize,
}

impl LinuxVzPackageGuestCanaryFileBindingV1 {
    pub const fn relative_path(&self) -> &'static str {
        self.relative_path
    }

    pub fn relative_path_sha256(&self) -> &Sha256Digest {
        &self.relative_path_sha256
    }

    pub fn content_sha256(&self) -> &Sha256Digest {
        &self.content_sha256
    }

    pub const fn byte_length(&self) -> usize {
        self.byte_length
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageGuestCanarySeedV1 {
    derivation_binding_sha256: Sha256Digest,
    canary_value_sha256: Sha256Digest,
    pypi_canary_value_sha256: Sha256Digest,
    seed_sha256: Sha256Digest,
    files: [LinuxVzPackageGuestCanaryFileBindingV1; 3],
}

impl fmt::Debug for LinuxVzPackageGuestCanarySeedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageGuestCanarySeedV1")
            .field("derivation_binding_sha256", &self.derivation_binding_sha256)
            .field("canary_value_sha256", &self.canary_value_sha256)
            .field("pypi_canary_value_sha256", &self.pypi_canary_value_sha256)
            .field("seed_sha256", &self.seed_sha256)
            .field("file_count", &self.files.len())
            .finish()
    }
}

impl LinuxVzPackageGuestCanarySeedV1 {
    pub fn derivation_binding_sha256(&self) -> &Sha256Digest {
        &self.derivation_binding_sha256
    }

    pub fn canary_value_sha256(&self) -> &Sha256Digest {
        &self.canary_value_sha256
    }

    pub fn pypi_canary_value_sha256(&self) -> &Sha256Digest {
        &self.pypi_canary_value_sha256
    }

    pub fn seed_sha256(&self) -> &Sha256Digest {
        &self.seed_sha256
    }

    pub fn files(&self) -> &[LinuxVzPackageGuestCanaryFileBindingV1] {
        &self.files
    }
}

struct RetainedWorkspaceDirectoryV1 {
    relative_path: &'static str,
    file: File,
    uid: u32,
    gid: u32,
    mode: u32,
    device: u64,
    inode: u64,
}

pub struct MaterializedLinuxVzPackageWorkspaceV1 {
    process_plan_sha256: Sha256Digest,
    policy: LinuxVzPackageMaterializationPolicyV1,
    parent: Option<File>,
    run_root: Option<File>,
    run_root_name: CString,
    directories: Vec<RetainedWorkspaceDirectoryV1>,
    guest_canary_seed: Option<LinuxVzPackageGuestCanarySeedV1>,
    mounted_tmpfs: bool,
    cleaned: bool,
}

impl fmt::Debug for MaterializedLinuxVzPackageWorkspaceV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedLinuxVzPackageWorkspaceV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("mounted_tmpfs", &self.mounted_tmpfs)
            .field("directory_count", &self.directories.len())
            .field("guest_canary_seeded", &self.guest_canary_seed.is_some())
            .field("path", &"<fixed-run-root-redacted>")
            .field("cleaned", &self.cleaned)
            .finish()
    }
}

impl MaterializedLinuxVzPackageWorkspaceV1 {
    pub fn run_root(&self) -> Result<&File, LinuxVzPackageWorkspaceErrorV1> {
        self.run_root
            .as_ref()
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)
    }

    pub fn verify_prelaunch(
        &self,
    ) -> Result<LinuxVzPackageWorkspaceObservationV1, LinuxVzPackageWorkspaceErrorV1> {
        self.verify_v1()
    }

    pub fn verify_postrun(
        &self,
    ) -> Result<LinuxVzPackageWorkspaceObservationV1, LinuxVzPackageWorkspaceErrorV1> {
        self.verify_v1()
    }

    pub fn guest_canary_seed_v1(&self) -> Option<&LinuxVzPackageGuestCanarySeedV1> {
        self.guest_canary_seed.as_ref()
    }

    pub fn seed_guest_file_canaries_v1(
        &mut self,
        derivation_binding_sha256: &Sha256Digest,
    ) -> Result<&LinuxVzPackageGuestCanarySeedV1, LinuxVzPackageWorkspaceErrorV1> {
        if self.guest_canary_seed.is_some() {
            return Err(LinuxVzPackageWorkspaceErrorV1::WorkspaceAlreadyPresent);
        }
        let home = self
            .directories
            .iter()
            .find(|entry| entry.relative_path == "home")
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        let seed = seed_guest_file_canaries_v1(
            &home.file,
            self.policy.package_uid(),
            self.policy.package_gid(),
            derivation_binding_sha256,
        )?;
        self.guest_canary_seed = Some(seed);
        self.guest_canary_seed
            .as_ref()
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)
    }

    pub(crate) fn derived_directory_for_validation_v1(
        &self,
    ) -> Result<&File, LinuxVzPackageWorkspaceErrorV1> {
        self.directories
            .iter()
            .find(|entry| entry.relative_path == "derived")
            .map(|entry| &entry.file)
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)
    }

    pub(crate) fn seal_derived_directory_after_validation_v1(
        &mut self,
    ) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
        let entry = self
            .directories
            .iter_mut()
            .find(|entry| entry.relative_path == "derived")
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        let ownership_changed = unsafe {
            libc::fchown(
                entry.file.as_raw_fd(),
                self.policy.supervisor_uid(),
                self.policy.supervisor_gid(),
            )
        } == 0;
        let mode_changed =
            ownership_changed && unsafe { libc::fchmod(entry.file.as_raw_fd(), 0o555) } == 0;
        if !mode_changed {
            let _ = unsafe {
                libc::fchown(
                    entry.file.as_raw_fd(),
                    self.policy.package_uid(),
                    self.policy.package_gid(),
                )
            };
            let _ = unsafe { libc::fchmod(entry.file.as_raw_fd(), 0o700) };
            return Err(LinuxVzPackageWorkspaceErrorV1::OwnershipFailed);
        }
        entry
            .file
            .sync_all()
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::OwnershipFailed)?;
        entry.uid = self.policy.supervisor_uid();
        entry.gid = self.policy.supervisor_gid();
        entry.mode = 0o555;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn restore_empty_derived_directory_for_test_v1(
        &mut self,
    ) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
        let entry = self
            .directories
            .iter_mut()
            .find(|entry| entry.relative_path == "derived")
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        if unsafe {
            libc::fchown(
                entry.file.as_raw_fd(),
                self.policy.package_uid(),
                self.policy.package_gid(),
            )
        } != 0
            || unsafe { libc::fchmod(entry.file.as_raw_fd(), 0o700) } != 0
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::OwnershipFailed);
        }
        entry.uid = self.policy.package_uid();
        entry.gid = self.policy.package_gid();
        entry.mode = 0o700;
        Ok(())
    }

    pub fn cleanup(&mut self) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
        if self.cleaned {
            return Ok(());
        }
        self.verify_v1()?;
        remove_guest_file_canaries_v1(
            &self
                .directories
                .iter()
                .find(|entry| entry.relative_path == "home")
                .ok_or(LinuxVzPackageWorkspaceErrorV1::CleanupFailed)?
                .file,
        )?;
        self.guest_canary_seed = None;
        self.directories.clear();
        self.run_root.take();
        if self.mounted_tmpfs {
            unmount_fixed_workspace_v1()?;
        } else {
            remove_test_workspace_tree_v1(
                self.parent
                    .as_ref()
                    .ok_or(LinuxVzPackageWorkspaceErrorV1::CleanupFailed)?,
                &self.run_root_name,
            )?;
        }
        let parent = self
            .parent
            .as_ref()
            .ok_or(LinuxVzPackageWorkspaceErrorV1::CleanupFailed)?;
        if unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                self.run_root_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
        }
        parent
            .sync_all()
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CleanupFailed)?;
        self.cleaned = true;
        Ok(())
    }

    fn verify_v1(
        &self,
    ) -> Result<LinuxVzPackageWorkspaceObservationV1, LinuxVzPackageWorkspaceErrorV1> {
        self.policy
            .validate_current_process()
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::PrivilegeBoundary)?;
        let parent = self
            .parent
            .as_ref()
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        let run_root = self
            .run_root
            .as_ref()
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        verify_named_directory_v1(
            parent,
            &self.run_root_name,
            run_root,
            self.policy.supervisor_uid(),
            self.policy.supervisor_gid(),
            0o755,
        )?;
        if self.mounted_tmpfs {
            verify_tmpfs_v1(run_root)?;
        }
        verify_exact_tree_v1(run_root, &self.directories)?;
        let directories = self
            .directories
            .iter()
            .map(|entry| LinuxVzPackageWorkspaceDirectoryObservationV1 {
                relative_path: entry.relative_path.to_string(),
                uid: entry.uid.to_string(),
                gid: entry.gid.to_string(),
                mode: entry.mode.to_string(),
                device: entry.device.to_string(),
                inode: entry.inode.to_string(),
            })
            .collect::<Vec<_>>();
        let wire = PackageWorkspaceObservationWireV1 {
            schema_version: LINUX_VZ_PACKAGE_WORKSPACE_OBSERVATION_SCHEMA_V1,
            process_plan_sha256: &self.process_plan_sha256,
            run_root: RUN_ROOT_PATH_V1,
            filesystem: "tmpfs",
            tmpfs_size_bytes: TMPFS_SIZE_BYTES_V1.to_string(),
            tmpfs_inode_limit: TMPFS_INODE_LIMIT_V1.to_string(),
            mount_nodev: true,
            mount_nosuid: true,
            mount_executable: true,
            public_network_route_present: false,
            directories: &directories,
            package_execution: false,
            sync_back: false,
        };
        let canonical_json = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::Serialization)?;
        if canonical_json.is_empty()
            || canonical_json.len() > MAX_LINUX_VZ_PACKAGE_WORKSPACE_OBSERVATION_BYTES_V1
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::LimitExceeded);
        }
        Ok(LinuxVzPackageWorkspaceObservationV1 {
            observation_sha256: Sha256Digest::from_bytes(&canonical_json),
            canonical_json,
            process_plan_sha256: self.process_plan_sha256.clone(),
            directories,
        })
    }
}

impl Drop for MaterializedLinuxVzPackageWorkspaceV1 {
    fn drop(&mut self) {
        if self.cleanup().is_err() && self.mounted_tmpfs {
            self.directories.clear();
            self.run_root.take();
            let _ = force_detach_fixed_workspace_v1();
            let _ = remove_fixed_workspace_mountpoint_v1();
        }
    }
}

#[cfg(target_os = "linux")]
pub fn create_fresh_linux_vz_package_workspace_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<
    (
        MaterializedLinuxVzPackageWorkspaceV1,
        LinuxVzPackageWorkspaceObservationV1,
    ),
    LinuxVzPackageWorkspaceErrorV1,
> {
    policy
        .validate_current_process()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::PrivilegeBoundary)?;
    if process_plan.package_execution_authority_permitted() || process_plan.sync_back_permitted() {
        return Err(LinuxVzPackageWorkspaceErrorV1::InvalidProcessPlan);
    }
    let parent_path = CString::new(RUN_PARENT_PATH_V1).expect("fixed run parent");
    let parent_fd = unsafe {
        libc::open(
            parent_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if parent_fd < 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::ParentUnsafe);
    }
    let parent = unsafe { File::from_raw_fd(parent_fd) };
    verify_parent_v1(&parent, policy)?;
    let run_root_name = fixed_component_v1(RUN_ROOT_NAME_V1)?;
    require_absent_v1(&parent, &run_root_name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), run_root_name.as_ptr(), 0o700) } != 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CreateFailed);
    }
    parent
        .sync_all()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;
    if let Err(error) = mount_fixed_tmpfs_v1() {
        let _ = unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                run_root_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
        return Err(error);
    }
    match finish_workspace_v1(process_plan, policy, parent, run_root_name, true) {
        Ok(workspace) => Ok(workspace),
        Err(error) => {
            let _ = unmount_fixed_workspace_v1();
            let _ = remove_fixed_workspace_mountpoint_v1();
            Err(error)
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn create_fresh_linux_vz_package_workspace_v1(
    _process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    _policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<
    (
        MaterializedLinuxVzPackageWorkspaceV1,
        LinuxVzPackageWorkspaceObservationV1,
    ),
    LinuxVzPackageWorkspaceErrorV1,
> {
    Err(LinuxVzPackageWorkspaceErrorV1::UnsupportedPlatform)
}

#[cfg(any(target_os = "linux", test))]
fn finish_workspace_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    policy: &LinuxVzPackageMaterializationPolicyV1,
    parent: File,
    run_root_name: CString,
    mounted_tmpfs: bool,
) -> Result<
    (
        MaterializedLinuxVzPackageWorkspaceV1,
        LinuxVzPackageWorkspaceObservationV1,
    ),
    LinuxVzPackageWorkspaceErrorV1,
> {
    let run_root = open_directory_at_v1(parent.as_raw_fd(), &run_root_name)?;
    verify_named_directory_v1(
        &parent,
        &run_root_name,
        &run_root,
        policy.supervisor_uid(),
        policy.supervisor_gid(),
        0o755,
    )?;
    if mounted_tmpfs {
        verify_tmpfs_v1(&run_root)?;
    }
    let directories = create_fixed_tree_v1(&run_root, policy)?;
    verify_initial_tree_empty_v1(&run_root, &directories)?;
    let workspace = MaterializedLinuxVzPackageWorkspaceV1 {
        process_plan_sha256: process_plan.process_plan_sha256().clone(),
        policy: policy.clone(),
        parent: Some(parent),
        run_root: Some(run_root),
        run_root_name,
        directories,
        guest_canary_seed: None,
        mounted_tmpfs,
        cleaned: false,
    };
    let observation = workspace.verify_v1()?;
    Ok((workspace, observation))
}

#[cfg(test)]
pub(crate) fn create_test_linux_vz_package_workspace_at_v1(
    parent: File,
    root_name: &str,
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<MaterializedLinuxVzPackageWorkspaceV1, LinuxVzPackageWorkspaceErrorV1> {
    let root_name = fixed_component_v1(root_name)?;
    require_absent_for_test_v1(&parent, &root_name)?;
    if unsafe { libc::mkdirat(parent.as_raw_fd(), root_name.as_ptr(), 0o755) } != 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CreateFailed);
    }
    finish_workspace_v1(process_plan, policy, parent, root_name, false)
        .map(|(workspace, _)| workspace)
}

#[cfg(any(target_os = "linux", test))]
fn create_fixed_tree_v1(
    run_root: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<Vec<RetainedWorkspaceDirectoryV1>, LinuxVzPackageWorkspaceErrorV1> {
    let specifications = [
        ("cache", None),
        ("cache/npm", Some("cache")),
        ("derived", None),
        ("home", None),
        ("tmp", None),
        ("work", None),
        ("work/npm", Some("work")),
    ];
    let mut retained = Vec::with_capacity(specifications.len());
    for (relative_path, parent_path) in specifications {
        let (parent, name) = if let Some(parent_path) = parent_path {
            let parent = retained
                .iter()
                .find(|entry: &&RetainedWorkspaceDirectoryV1| entry.relative_path == parent_path)
                .ok_or(LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;
            (
                &parent.file,
                fixed_component_v1(relative_path.rsplit('/').next().unwrap())?,
            )
        } else {
            (run_root, fixed_component_v1(relative_path)?)
        };
        if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
            return Err(LinuxVzPackageWorkspaceErrorV1::CreateFailed);
        }
        let directory = open_directory_at_v1(parent.as_raw_fd(), &name)?;
        if unsafe {
            libc::fchown(
                directory.as_raw_fd(),
                policy.package_uid(),
                policy.package_gid(),
            )
        } != 0
            || unsafe { libc::fchmod(directory.as_raw_fd(), 0o700) } != 0
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::OwnershipFailed);
        }
        directory
            .sync_all()
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;
        let metadata = directory
            .metadata()
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        retained.push(RetainedWorkspaceDirectoryV1 {
            relative_path,
            file: directory,
            uid: policy.package_uid(),
            gid: policy.package_gid(),
            mode: 0o700,
            device: metadata.dev(),
            inode: metadata.ino(),
        });
    }
    run_root
        .sync_all()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;
    Ok(retained)
}

fn verify_exact_tree_v1(
    run_root: &File,
    retained: &[RetainedWorkspaceDirectoryV1],
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let root_names = list_directory_names_v1(run_root)?;
    let fixed_names = ["cache", "derived", "home", "tmp", "work"];
    let optional_root_materializations = ["closure", "input", "source"];
    if fixed_names
        .iter()
        .any(|required| !root_names.iter().any(|observed| observed == required))
        || root_names.iter().any(|observed| {
            !fixed_names.contains(&observed.as_str())
                && !optional_root_materializations.contains(&observed.as_str())
        })
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
    }
    for entry in retained {
        let metadata = entry
            .file
            .metadata()
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != entry.uid
            || metadata.gid() != entry.gid
            || metadata.mode() & 0o7777 != entry.mode
            || metadata.dev() != entry.device
            || metadata.ino() != entry.inode
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
        }
        let components = entry.relative_path.split('/').collect::<Vec<_>>();
        let (parent, name) = if components.len() == 1 {
            (run_root, components[0])
        } else {
            let parent = retained
                .iter()
                .find(|candidate| candidate.relative_path == components[0])
                .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
            (&parent.file, components[1])
        };
        let name = fixed_component_v1(name)?;
        let reopened = open_directory_at_v1(parent.as_raw_fd(), &name)?;
        let reopened_metadata = reopened
            .metadata()
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        if reopened_metadata.dev() != entry.device || reopened_metadata.ino() != entry.inode {
            return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
        }
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn verify_initial_tree_empty_v1(
    run_root: &File,
    retained: &[RetainedWorkspaceDirectoryV1],
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    verify_exact_tree_v1(run_root, retained)?;
    for (path, expected) in [("cache", ["npm"].as_slice()), ("work", ["npm"].as_slice())] {
        let directory = retained
            .iter()
            .find(|entry| entry.relative_path == path)
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        if list_directory_names_v1(&directory.file)? != expected {
            return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
        }
    }
    for path in ["cache/npm", "derived", "home", "tmp", "work/npm"] {
        let directory = retained
            .iter()
            .find(|entry| entry.relative_path == path)
            .ok_or(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        if !list_directory_names_v1(&directory.file)?.is_empty() {
            return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_parent_v1(
    parent: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let metadata = parent
        .metadata()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::ParentUnsafe)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != policy.supervisor_uid()
        || metadata.gid() != policy.supervisor_gid()
        || metadata.mode() & 0o022 != 0
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::ParentUnsafe);
    }
    Ok(())
}

fn verify_named_directory_v1(
    parent: &File,
    name: &CString,
    retained: &File,
    expected_uid: u32,
    expected_gid: u32,
    expected_mode: u32,
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let reopened = open_directory_at_v1(parent.as_raw_fd(), name)?;
    let retained_metadata = retained
        .metadata()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
    let reopened_metadata = reopened
        .metadata()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
    if !retained_metadata.file_type().is_dir()
        || retained_metadata.uid() != expected_uid
        || retained_metadata.gid() != expected_gid
        || retained_metadata.mode() & 0o7777 != expected_mode
        || retained_metadata.dev() != reopened_metadata.dev()
        || retained_metadata.ino() != reopened_metadata.ino()
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_absent_v1(parent: &File, name: &CString) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::WorkspaceAlreadyPresent);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() != Some(libc::ENOENT) {
        return Err(LinuxVzPackageWorkspaceErrorV1::ParentUnsafe);
    }
    Ok(())
}

#[cfg(test)]
fn require_absent_for_test_v1(
    parent: &File,
    name: &CString,
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::WorkspaceAlreadyPresent);
    }
    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
        return Err(LinuxVzPackageWorkspaceErrorV1::ParentUnsafe);
    }
    Ok(())
}

fn fixed_component_v1(value: &str) -> Result<CString, LinuxVzPackageWorkspaceErrorV1> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || !value.is_ascii()
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
    }
    CString::new(value).map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)
}

fn open_directory_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<File, LinuxVzPackageWorkspaceErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn seed_guest_file_canaries_v1(
    home: &File,
    package_uid: u32,
    package_gid: u32,
    derivation_binding_sha256: &Sha256Digest,
) -> Result<LinuxVzPackageGuestCanarySeedV1, LinuxVzPackageWorkspaceErrorV1> {
    let token_derivation = format!(
        "{LINUX_VZ_PACKAGE_GUEST_CANARY_SEED_SCHEMA_V1}\0npm-token\0{}",
        derivation_binding_sha256.as_str()
    );
    let token_material_sha256 = Sha256Digest::from_bytes(token_derivation.as_bytes());
    let token = format!(
        "whoathere_fake_npm_token_v1_{}",
        token_material_sha256
            .as_str()
            .strip_prefix("sha256:")
            .expect("sha256 digest prefix")
    );
    let canary_value_sha256 = Sha256Digest::from_bytes(token.as_bytes());
    let npmrc_content = format!("//registry.npmjs.org/:_authToken={token}\n").into_bytes();
    let mut token_file_content = token.into_bytes();
    token_file_content.push(b'\n');

    // Keep both attempt-bound fake ecosystem tokens in one shared honey-directory. The package
    // cannot learn its scenario kind from the seed set, while the typed trigger selects the
    // ecosystem-specific canary class during evidence projection.
    let pypi_token_derivation = format!(
        "{LINUX_VZ_PACKAGE_GUEST_CANARY_SEED_SCHEMA_V1}\0pypi-token\0{}",
        derivation_binding_sha256.as_str()
    );
    let pypi_token_material_sha256 = Sha256Digest::from_bytes(pypi_token_derivation.as_bytes());
    let pypi_token = format!(
        "whoathere_fake_pypi_token_v1_{}",
        pypi_token_material_sha256
            .as_str()
            .strip_prefix("sha256:")
            .expect("sha256 digest prefix")
    );
    let pypi_canary_value_sha256 = Sha256Digest::from_bytes(pypi_token.as_bytes());
    let mut pypi_token_file_content = pypi_token.into_bytes();
    pypi_token_file_content.push(b'\n');

    let npmrc_name = fixed_component_v1(".npmrc")?;
    let canary_directory_name = fixed_component_v1(".whoathere-canaries")?;
    let token_name = fixed_component_v1("npm-token")?;
    let pypi_token_name = fixed_component_v1("pypi-token")?;
    if unsafe { libc::mkdirat(home.as_raw_fd(), canary_directory_name.as_ptr(), 0o700) } != 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CreateFailed);
    }
    let canary_directory = open_directory_at_v1(home.as_raw_fd(), &canary_directory_name)?;
    if unsafe { libc::fchown(canary_directory.as_raw_fd(), package_uid, package_gid) } != 0
        || unsafe { libc::fchmod(canary_directory.as_raw_fd(), 0o700) } != 0
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::OwnershipFailed);
    }

    let npmrc =
        create_private_file_at_v1(home, &npmrc_name, &npmrc_content, package_uid, package_gid)?;
    let token_file = create_private_file_at_v1(
        &canary_directory,
        &token_name,
        &token_file_content,
        package_uid,
        package_gid,
    )?;
    let pypi_token_file = create_private_file_at_v1(
        &canary_directory,
        &pypi_token_name,
        &pypi_token_file_content,
        package_uid,
        package_gid,
    )?;
    canary_directory
        .sync_all()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;
    home.sync_all()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;

    let files = [
        LinuxVzPackageGuestCanaryFileBindingV1 {
            relative_path: NPMRC_CANARY_RELATIVE_PATH_V1,
            relative_path_sha256: Sha256Digest::from_bytes(
                NPMRC_CANARY_RELATIVE_PATH_V1.as_bytes(),
            ),
            content_sha256: Sha256Digest::from_bytes(&npmrc_content),
            byte_length: npmrc_content.len(),
        },
        LinuxVzPackageGuestCanaryFileBindingV1 {
            relative_path: NPM_TOKEN_CANARY_RELATIVE_PATH_V1,
            relative_path_sha256: Sha256Digest::from_bytes(
                NPM_TOKEN_CANARY_RELATIVE_PATH_V1.as_bytes(),
            ),
            content_sha256: Sha256Digest::from_bytes(&token_file_content),
            byte_length: token_file_content.len(),
        },
        LinuxVzPackageGuestCanaryFileBindingV1 {
            relative_path: PYPI_TOKEN_CANARY_RELATIVE_PATH_V1,
            relative_path_sha256: Sha256Digest::from_bytes(
                PYPI_TOKEN_CANARY_RELATIVE_PATH_V1.as_bytes(),
            ),
            content_sha256: Sha256Digest::from_bytes(&pypi_token_file_content),
            byte_length: pypi_token_file_content.len(),
        },
    ];
    verify_private_file_v1(&npmrc, package_uid, package_gid, &files[0])?;
    verify_private_file_v1(&token_file, package_uid, package_gid, &files[1])?;
    verify_private_file_v1(&pypi_token_file, package_uid, package_gid, &files[2])?;

    let seed_binding = format!(
        "{LINUX_VZ_PACKAGE_GUEST_CANARY_SEED_SCHEMA_V1}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}\0{}",
        derivation_binding_sha256.as_str(),
        canary_value_sha256.as_str(),
        pypi_canary_value_sha256.as_str(),
        files[0].relative_path_sha256.as_str(),
        files[0].content_sha256.as_str(),
        files[0].byte_length,
        files[1].relative_path_sha256.as_str(),
        files[1].content_sha256.as_str(),
        files[1].byte_length,
        files[2].relative_path_sha256.as_str(),
        files[2].content_sha256.as_str(),
        files[2].byte_length,
    );
    Ok(LinuxVzPackageGuestCanarySeedV1 {
        derivation_binding_sha256: derivation_binding_sha256.clone(),
        canary_value_sha256,
        pypi_canary_value_sha256,
        seed_sha256: Sha256Digest::from_bytes(seed_binding.as_bytes()),
        files,
    })
}

fn create_private_file_at_v1(
    parent: &File,
    name: &CString,
    content: &[u8],
    package_uid: u32,
    package_gid: u32,
) -> Result<File, LinuxVzPackageWorkspaceErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CreateFailed);
    }
    let mut file = unsafe { File::from_raw_fd(descriptor) };
    if unsafe { libc::fchown(file.as_raw_fd(), package_uid, package_gid) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::OwnershipFailed);
    }
    file.write_all(content)
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;
    file.sync_all()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CreateFailed)?;
    Ok(file)
}

fn verify_private_file_v1(
    file: &File,
    package_uid: u32,
    package_gid: u32,
    binding: &LinuxVzPackageGuestCanaryFileBindingV1,
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let metadata = file
        .metadata()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != package_uid
        || metadata.gid() != package_gid
        || metadata.mode() & 0o7777 != 0o600
        || usize::try_from(metadata.len()).ok() != Some(binding.byte_length)
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
    }
    Ok(())
}

fn remove_guest_file_canaries_v1(home: &File) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let npmrc_name = fixed_component_v1(".npmrc")?;
    unlink_file_if_present_v1(home, &npmrc_name)?;

    let canary_directory_name = fixed_component_v1(".whoathere-canaries")?;
    let canary_directory = match open_directory_at_v1(home.as_raw_fd(), &canary_directory_name) {
        Ok(directory) => Some(directory),
        Err(_) if entry_absent_at_v1(home, &canary_directory_name)? => None,
        Err(_) => return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed),
    };
    if let Some(canary_directory) = canary_directory {
        let token_name = fixed_component_v1("npm-token")?;
        let pypi_token_name = fixed_component_v1("pypi-token")?;
        unlink_file_if_present_v1(&canary_directory, &token_name)?;
        unlink_file_if_present_v1(&canary_directory, &pypi_token_name)?;
        let environment_sensor =
            crate::fixed_linux_vz_package_npm_environment_credential_sensor_binding_v1()
                .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CleanupFailed)?;
        for marker in environment_sensor.markers() {
            let basename = marker
                .marker_relative_path()
                .strip_prefix("home/.whoathere-canaries/")
                .filter(|value| !value.is_empty() && !value.contains('/'))
                .ok_or(LinuxVzPackageWorkspaceErrorV1::CleanupFailed)?;
            let marker_name = fixed_component_v1(basename)?;
            unlink_file_if_present_v1(&canary_directory, &marker_name)?;
        }
        if unsafe {
            libc::unlinkat(
                home.as_raw_fd(),
                canary_directory_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
        }
    }
    home.sync_all()
        .map_err(|_| LinuxVzPackageWorkspaceErrorV1::CleanupFailed)
}

fn unlink_file_if_present_v1(
    parent: &File,
    name: &CString,
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } == 0 {
        return Ok(());
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(())
    } else {
        Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed)
    }
}

fn entry_absent_at_v1(
    parent: &File,
    name: &CString,
) -> Result<bool, LinuxVzPackageWorkspaceErrorV1> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } == 0
    {
        return Ok(false);
    }
    if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
        Ok(true)
    } else {
        Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)
    }
}

fn list_directory_names_v1(
    directory: &File,
) -> Result<Vec<String>, LinuxVzPackageWorkspaceErrorV1> {
    let current = CString::new(".").expect("fixed current-directory component");
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            current.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
    }
    let stream = unsafe { libc::fdopendir(descriptor) };
    if stream.is_null() {
        unsafe {
            libc::close(descriptor);
        }
        return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
    }
    let mut names = Vec::new();
    loop {
        set_errno_v1(0);
        let entry = unsafe { libc::readdir(stream) };
        if entry.is_null() {
            let error = errno_v1();
            unsafe {
                libc::closedir(stream);
            }
            if error != 0 {
                return Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed);
            }
            break;
        }
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        let bytes = name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let value = std::str::from_utf8(bytes)
            .map_err(|_| LinuxVzPackageWorkspaceErrorV1::VerificationFailed)?;
        names.push(value.to_string());
    }
    names.sort();
    Ok(names)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_v1() -> i32 {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn errno_v1() -> i32 {
    unsafe { *libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_errno_v1(value: i32) {
    unsafe {
        *libc::__errno_location() = value;
    }
}

#[cfg(target_os = "macos")]
fn set_errno_v1(value: i32) {
    unsafe {
        *libc::__error() = value;
    }
}

#[cfg(target_os = "linux")]
fn mount_fixed_tmpfs_v1() -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let source = CString::new("whoathere-package-workspace").expect("fixed source");
    let target = CString::new(RUN_ROOT_PATH_V1).expect("fixed target");
    let filesystem = CString::new("tmpfs").expect("fixed filesystem");
    let data = CString::new(format!(
        "size={TMPFS_SIZE_BYTES_V1},nr_inodes={TMPFS_INODE_LIMIT_V1},mode=0755,uid=0,gid=0"
    ))
    .expect("fixed mount data");
    let flags = libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOATIME;
    if unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem.as_ptr(),
            flags,
            data.as_ptr().cast(),
        )
    } != 0
    {
        return Err(LinuxVzPackageWorkspaceErrorV1::MountFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_tmpfs_v1(run_root: &File) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    const TMPFS_MAGIC: u64 = 0x0102_1994;
    let mut stat = MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(run_root.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::WrongFilesystem);
    }
    let stat = unsafe { stat.assume_init() };
    if u64::try_from(stat.f_type).ok() != Some(TMPFS_MAGIC) {
        return Err(LinuxVzPackageWorkspaceErrorV1::WrongFilesystem);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_tmpfs_v1(_run_root: &File) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    Err(LinuxVzPackageWorkspaceErrorV1::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn unmount_fixed_workspace_v1() -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let target = CString::new(RUN_ROOT_PATH_V1).expect("fixed target");
    if unsafe { libc::umount2(target.as_ptr(), 0) } != 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn force_detach_fixed_workspace_v1() -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let target = CString::new(RUN_ROOT_PATH_V1).expect("fixed target");
    if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } != 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn force_detach_fixed_workspace_v1() -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    Err(LinuxVzPackageWorkspaceErrorV1::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn remove_fixed_workspace_mountpoint_v1() -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let parent_path = CString::new(RUN_PARENT_PATH_V1).expect("fixed run parent");
    let parent_fd = unsafe {
        libc::open(
            parent_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if parent_fd < 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
    }
    let parent = unsafe { File::from_raw_fd(parent_fd) };
    let name = fixed_component_v1(RUN_ROOT_NAME_V1)?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), libc::AT_REMOVEDIR) } != 0 {
        return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn remove_fixed_workspace_mountpoint_v1() -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    Err(LinuxVzPackageWorkspaceErrorV1::UnsupportedPlatform)
}

#[cfg(not(target_os = "linux"))]
fn unmount_fixed_workspace_v1() -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    Err(LinuxVzPackageWorkspaceErrorV1::UnsupportedPlatform)
}

fn remove_test_workspace_tree_v1(
    parent: &File,
    root_name: &CString,
) -> Result<(), LinuxVzPackageWorkspaceErrorV1> {
    let root = open_directory_at_v1(parent.as_raw_fd(), root_name)?;
    for (parent_name, child_name) in [("cache", "npm"), ("work", "npm")] {
        let parent_component = fixed_component_v1(parent_name)?;
        let child_component = fixed_component_v1(child_name)?;
        let nested = open_directory_at_v1(root.as_raw_fd(), &parent_component)?;
        if unsafe {
            libc::unlinkat(
                nested.as_raw_fd(),
                child_component.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
        }
    }
    for name in ["cache", "derived", "home", "tmp", "work"] {
        let component = fixed_component_v1(name)?;
        if unsafe { libc::unlinkat(root.as_raw_fd(), component.as_ptr(), libc::AT_REMOVEDIR) } != 0
        {
            return Err(LinuxVzPackageWorkspaceErrorV1::CleanupFailed);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        MacosLinuxVzNpmLifecyclePolicyV1, MacosLinuxVzPackageDependencyPolicyV1,
        MacosLinuxVzPackageExecutionStageV1, MacosLinuxVzPackageRuntimeExecutablesV1,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use whoathere_detonation::NpmEnvironmentProfileV1;

    fn npm_plan() -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::NodeNpm {
                node_version: "24.4.0".to_string(),
                node_executable_sha256: Sha256Digest::from_bytes(b"inert node"),
                npm_version: "11.4.2".to_string(),
                npm_cli_sha256: Sha256Digest::from_bytes(b"inert npm"),
            },
            "npm_install_exact_local_tarball",
            vec![
                MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
                    environment: NpmEnvironmentProfileV1::CiTrue,
                    input_basename: "package.tgz".to_string(),
                    dependency_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::OfflineExactDependencyFree,
                    lifecycle_policy:
                        MacosLinuxVzNpmLifecyclePolicyV1::PackageManifestInstallHooksOnly,
                },
            ],
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("process plan")
    }

    fn unique_test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "whoathere-workspace-test-{}-{}",
            std::process::id(),
            Sha256Digest::from_bytes(format!("{:?}", std::time::SystemTime::now()).as_bytes())
                .as_str()
                .strip_prefix("sha256:")
                .unwrap()
        ))
    }

    #[test]
    fn fixed_workspace_is_exact_owned_and_evidence_bound() {
        let base = unique_test_root();
        std::fs::create_dir(&base).expect("test parent");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .expect("parent mode");
        let parent = File::open(&base).expect("open parent");
        let root_name = fixed_component_v1("scenario").expect("root name");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), root_name.as_ptr(), 0o755) },
            0
        );
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let plan = npm_plan();
        let (mut workspace, observation) =
            finish_workspace_v1(&plan, &policy, parent, root_name, false).expect("workspace");

        assert_eq!(observation.directories().len(), 7);
        assert_eq!(
            observation
                .directories()
                .iter()
                .map(LinuxVzPackageWorkspaceDirectoryObservationV1::relative_path)
                .collect::<Vec<_>>(),
            vec![
                "cache",
                "cache/npm",
                "derived",
                "home",
                "tmp",
                "work",
                "work/npm"
            ]
        );
        assert!(observation.directories().iter().all(|directory| {
            directory.uid() == policy.package_uid()
                && directory.gid() == policy.package_gid()
                && directory.mode() == 0o700
        }));
        assert_eq!(
            observation.observation_sha256(),
            &Sha256Digest::from_bytes(observation.canonical_json_v1())
        );
        assert!(!observation.package_execution_authority_present());
        assert!(!observation.sync_back_permitted());
        assert_eq!(
            workspace
                .verify_prelaunch()
                .expect("verify")
                .observation_sha256(),
            observation.observation_sha256()
        );
        workspace.cleanup().expect("cleanup");
        std::fs::remove_dir(&base).expect("remove test parent");
    }

    #[test]
    fn guest_file_canaries_are_private_fake_and_digest_bound() {
        let base = unique_test_root();
        std::fs::create_dir(&base).expect("test parent");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700))
            .expect("parent mode");
        let parent = File::open(&base).expect("open parent");
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let plan = npm_plan();
        let mut workspace =
            create_test_linux_vz_package_workspace_at_v1(parent, "scenario", &plan, &policy)
                .expect("workspace");
        let binding = Sha256Digest::from_bytes(b"inert canary test attempt");
        let seed = workspace
            .seed_guest_file_canaries_v1(&binding)
            .expect("seed canaries")
            .clone();

        assert_eq!(seed.derivation_binding_sha256(), &binding);
        assert_eq!(seed.files().len(), 3);
        assert_eq!(
            seed.files()
                .iter()
                .map(LinuxVzPackageGuestCanaryFileBindingV1::relative_path)
                .collect::<Vec<_>>(),
            vec![
                NPMRC_CANARY_RELATIVE_PATH_V1,
                NPM_TOKEN_CANARY_RELATIVE_PATH_V1,
                PYPI_TOKEN_CANARY_RELATIVE_PATH_V1
            ]
        );
        let npmrc = std::fs::read(base.join("scenario/home/.npmrc")).expect("read npmrc");
        let token_file = std::fs::read(base.join("scenario/home/.whoathere-canaries/npm-token"))
            .expect("read token canary");
        let pypi_token_file =
            std::fs::read(base.join("scenario/home/.whoathere-canaries/pypi-token"))
                .expect("read pypi token canary");
        assert_eq!(
            Sha256Digest::from_bytes(&npmrc),
            *seed.files()[0].content_sha256()
        );
        assert_eq!(
            Sha256Digest::from_bytes(&token_file),
            *seed.files()[1].content_sha256()
        );
        assert_eq!(
            Sha256Digest::from_bytes(&pypi_token_file),
            *seed.files()[2].content_sha256()
        );
        assert!(npmrc.starts_with(b"//registry.npmjs.org/:_authToken="));
        assert!(npmrc.ends_with(b"\n"));
        assert!(token_file.starts_with(b"whoathere_fake_npm_token_v1_"));
        assert!(token_file.ends_with(b"\n"));
        let token = &token_file[..token_file.len() - 1];
        assert_eq!(Sha256Digest::from_bytes(token), *seed.canary_value_sha256());
        assert!(npmrc.windows(token.len()).any(|window| window == token));
        assert!(pypi_token_file.starts_with(b"whoathere_fake_pypi_token_v1_"));
        assert!(pypi_token_file.ends_with(b"\n"));
        let pypi_token = &pypi_token_file[..pypi_token_file.len() - 1];
        assert_eq!(
            Sha256Digest::from_bytes(pypi_token),
            *seed.pypi_canary_value_sha256()
        );

        for path in [
            base.join("scenario/home/.npmrc"),
            base.join("scenario/home/.whoathere-canaries/npm-token"),
            base.join("scenario/home/.whoathere-canaries/pypi-token"),
        ] {
            let metadata = std::fs::symlink_metadata(path).expect("canary metadata");
            assert!(metadata.file_type().is_file());
            assert_eq!(metadata.mode() & 0o7777, 0o600);
            assert_eq!(metadata.uid(), policy.package_uid());
            assert_eq!(metadata.gid(), policy.package_gid());
        }
        let directory_metadata =
            std::fs::symlink_metadata(base.join("scenario/home/.whoathere-canaries"))
                .expect("canary directory metadata");
        assert!(directory_metadata.file_type().is_dir());
        assert_eq!(directory_metadata.mode() & 0o7777, 0o700);
        assert!(!format!("{seed:?}").contains("whoathere_fake_npm_token"));
        assert!(!format!("{seed:?}").contains("whoathere_fake_pypi_token"));
        assert!(matches!(
            workspace.seed_guest_file_canaries_v1(&binding),
            Err(LinuxVzPackageWorkspaceErrorV1::WorkspaceAlreadyPresent)
        ));

        let environment_sensor =
            crate::fixed_linux_vz_package_npm_environment_credential_sensor_binding_v1()
                .expect("fixed environment sensor");
        for marker in environment_sensor.markers() {
            std::fs::write(
                base.join("scenario").join(marker.marker_relative_path()),
                b"1\n",
            )
            .expect("write inert environment-read marker");
        }

        workspace.cleanup().expect("cleanup");
        std::fs::remove_dir(&base).expect("remove test parent");
    }

    #[test]
    fn guest_file_canary_derivation_is_stable_and_attempt_bound() {
        fn seed_for(binding: &Sha256Digest) -> LinuxVzPackageGuestCanarySeedV1 {
            let base = unique_test_root();
            std::fs::create_dir(&base).expect("test parent");
            let parent = File::open(&base).expect("open parent");
            let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
            let plan = npm_plan();
            let mut workspace =
                create_test_linux_vz_package_workspace_at_v1(parent, "scenario", &plan, &policy)
                    .expect("workspace");
            let seed = workspace
                .seed_guest_file_canaries_v1(binding)
                .expect("seed canaries")
                .clone();
            workspace.cleanup().expect("cleanup");
            std::fs::remove_dir(&base).expect("remove test parent");
            seed
        }

        let first_binding = Sha256Digest::from_bytes(b"inert first attempt");
        let second_binding = Sha256Digest::from_bytes(b"inert second attempt");
        let first = seed_for(&first_binding);
        let repeated = seed_for(&first_binding);
        let second = seed_for(&second_binding);
        assert_eq!(first, repeated);
        assert_ne!(first.seed_sha256(), second.seed_sha256());
        assert_ne!(first.canary_value_sha256(), second.canary_value_sha256());
        assert_ne!(
            first.pypi_canary_value_sha256(),
            second.pypi_canary_value_sha256()
        );
        assert_ne!(
            first.files()[0].content_sha256(),
            second.files()[0].content_sha256()
        );
        assert_ne!(
            first.files()[1].content_sha256(),
            second.files()[1].content_sha256()
        );
        assert_ne!(
            first.files()[2].content_sha256(),
            second.files()[2].content_sha256()
        );
    }

    #[test]
    fn unexpected_workspace_member_fails_closed() {
        let base = unique_test_root();
        std::fs::create_dir(&base).expect("test parent");
        let parent = File::open(&base).expect("open parent");
        let root_name = fixed_component_v1("scenario").expect("root name");
        assert_eq!(
            unsafe { libc::mkdirat(parent.as_raw_fd(), root_name.as_ptr(), 0o755) },
            0
        );
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let plan = npm_plan();
        let (mut workspace, _) =
            finish_workspace_v1(&plan, &policy, parent, root_name, false).expect("workspace");
        std::fs::write(base.join("scenario/unexpected"), b"inert").expect("unexpected member");
        assert!(matches!(
            workspace.verify_prelaunch(),
            Err(LinuxVzPackageWorkspaceErrorV1::VerificationFailed)
        ));
        std::fs::remove_file(base.join("scenario/unexpected")).expect("remove unexpected");
        workspace.cleanup().expect("cleanup");
        std::fs::remove_dir(&base).expect("remove test parent");
    }

    #[test]
    fn production_constructor_is_platform_closed_on_macos() {
        if cfg!(target_os = "linux") {
            return;
        }
        let plan = npm_plan();
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        assert!(matches!(
            create_fresh_linux_vz_package_workspace_v1(&plan, &policy),
            Err(LinuxVzPackageWorkspaceErrorV1::UnsupportedPlatform)
        ));
    }
}
