use crate::{
    MacosLinuxVzPackageExecutionActionV1, MacosLinuxVzPackageExecutionProcessPlanV1,
    MacosLinuxVzPackageInternalActionV1,
};
use sha2::{Digest, Sha256};
use std::ffi::CString;
use std::fmt;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
use whoathere_artifact::Sha256Digest;

const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;
const INPUT_DIRECTORY_NAME_V1: &str = "input";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageMaterializationErrorV1 {
    InvalidPolicy,
    PrivilegeBoundary,
    UnsafeRunRoot,
    InvalidProcessPlan,
    SourceInvalid,
    CreateFailed,
    CopyFailed,
    SyncFailed,
    VerificationFailed,
    CleanupFailed,
}

impl LinuxVzPackageMaterializationErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidPolicy => "linux_vz_package_materialization_policy_invalid",
            Self::PrivilegeBoundary => "linux_vz_package_materialization_privilege_invalid",
            Self::UnsafeRunRoot => "linux_vz_package_materialization_run_root_unsafe",
            Self::InvalidProcessPlan => "linux_vz_package_materialization_process_plan_invalid",
            Self::SourceInvalid => "linux_vz_package_materialization_source_invalid",
            Self::CreateFailed => "linux_vz_package_materialization_create_failed",
            Self::CopyFailed => "linux_vz_package_materialization_copy_failed",
            Self::SyncFailed => "linux_vz_package_materialization_sync_failed",
            Self::VerificationFailed => "linux_vz_package_materialization_verification_failed",
            Self::CleanupFailed => "linux_vz_package_materialization_cleanup_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageMaterializationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageMaterializationErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageMaterializationPolicyV1 {
    supervisor_uid: u32,
    supervisor_gid: u32,
    package_uid: u32,
    package_gid: u32,
}

impl LinuxVzPackageMaterializationPolicyV1 {
    pub fn for_root_supervisor_v1() -> Result<Self, LinuxVzPackageMaterializationErrorV1> {
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
            return Err(LinuxVzPackageMaterializationErrorV1::PrivilegeBoundary);
        }
        Ok(Self {
            supervisor_uid: 0,
            supervisor_gid: 0,
            package_uid: PACKAGE_UID_V1,
            package_gid: PACKAGE_GID_V1,
        })
    }

    #[cfg(test)]
    pub(crate) fn for_current_test_user_v1() -> Self {
        let supervisor_uid = unsafe { libc::geteuid() };
        let supervisor_gid = unsafe { libc::getegid() };
        Self {
            supervisor_uid,
            supervisor_gid,
            package_uid: supervisor_uid,
            package_gid: supervisor_gid,
        }
    }

    pub const fn supervisor_uid(&self) -> u32 {
        self.supervisor_uid
    }

    pub const fn supervisor_gid(&self) -> u32 {
        self.supervisor_gid
    }

    pub const fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub const fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub(crate) fn validate_current_process(
        &self,
    ) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
        if unsafe { libc::geteuid() } != self.supervisor_uid
            || unsafe { libc::getegid() } != self.supervisor_gid
            || self.package_uid == 0
            || self.package_gid == 0
            || (self.supervisor_uid == 0
                && (self.package_uid != PACKAGE_UID_V1 || self.package_gid != PACKAGE_GID_V1))
        {
            return Err(LinuxVzPackageMaterializationErrorV1::PrivilegeBoundary);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageArtifactRehashPhaseV1 {
    Staged,
    Prelaunch,
    Postrun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageArtifactMaterializationObservationV1 {
    phase: LinuxVzPackageArtifactRehashPhaseV1,
    process_plan_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    input_basename: String,
    supervisor_uid: u32,
    supervisor_gid: u32,
    input_directory_device: u64,
    input_directory_inode: u64,
    device: u64,
    inode: u64,
}

impl LinuxVzPackageArtifactMaterializationObservationV1 {
    pub const fn phase(&self) -> LinuxVzPackageArtifactRehashPhaseV1 {
        self.phase
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn input_basename(&self) -> &str {
        &self.input_basename
    }

    pub const fn supervisor_uid(&self) -> u32 {
        self.supervisor_uid
    }

    pub const fn supervisor_gid(&self) -> u32 {
        self.supervisor_gid
    }

    pub const fn input_directory_device(&self) -> u64 {
        self.input_directory_device
    }

    pub const fn input_directory_inode(&self) -> u64 {
        self.input_directory_inode
    }

    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u64 {
        self.inode
    }
}

pub struct MaterializedLinuxVzPackageArtifactV1 {
    run_root: File,
    input_directory: File,
    input_directory_name: CString,
    artifact_file: Option<File>,
    input_basename: CString,
    process_plan_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    supervisor_uid: u32,
    supervisor_gid: u32,
    input_directory_device: u64,
    input_directory_inode: u64,
    device: u64,
    inode: u64,
    cleaned: bool,
}

impl fmt::Debug for MaterializedLinuxVzPackageArtifactV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedLinuxVzPackageArtifactV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("artifact_byte_length", &self.artifact_byte_length)
            .field("input_directory_device", &self.input_directory_device)
            .field("input_directory_inode", &self.input_directory_inode)
            .field("device", &self.device)
            .field("inode", &self.inode)
            .field("path", &"<fixed-run-root-input-path-redacted>")
            .field("cleaned", &self.cleaned)
            .finish()
    }
}

impl MaterializedLinuxVzPackageArtifactV1 {
    pub fn verify_prelaunch(
        &mut self,
    ) -> Result<
        LinuxVzPackageArtifactMaterializationObservationV1,
        LinuxVzPackageMaterializationErrorV1,
    > {
        self.verify(LinuxVzPackageArtifactRehashPhaseV1::Prelaunch)
    }

    pub fn verify_postrun(
        &mut self,
    ) -> Result<
        LinuxVzPackageArtifactMaterializationObservationV1,
        LinuxVzPackageMaterializationErrorV1,
    > {
        self.verify(LinuxVzPackageArtifactRehashPhaseV1::Postrun)
    }

    pub(crate) fn verified_exact_artifact_bytes_for_plan_v1(
        &mut self,
        process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    ) -> Result<Vec<u8>, LinuxVzPackageMaterializationErrorV1> {
        if process_plan.process_plan_sha256() != &self.process_plan_sha256
            || process_plan.artifact_sha256() != &self.artifact_sha256
            || process_plan.artifact_byte_length() != self.artifact_byte_length
        {
            return Err(LinuxVzPackageMaterializationErrorV1::InvalidProcessPlan);
        }
        self.verify(LinuxVzPackageArtifactRehashPhaseV1::Prelaunch)?;
        let capacity = usize::try_from(self.artifact_byte_length)
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        let artifact_file = self
            .artifact_file
            .as_mut()
            .ok_or(LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        artifact_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        let mut bytes = vec![0_u8; capacity];
        artifact_file
            .read_exact(&mut bytes)
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        let mut trailing = [0_u8; 1];
        if artifact_file
            .read(&mut trailing)
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?
            != 0
        {
            return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
        }
        artifact_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        if bytes.len() != capacity || Sha256Digest::from_bytes(&bytes) != self.artifact_sha256 {
            return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
        }
        Ok(bytes)
    }

    pub fn cleanup(&mut self) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
        if self.cleaned {
            return Ok(());
        }
        verify_named_directory_v1(
            &self.run_root,
            &self.input_directory_name,
            &self.input_directory,
            self.supervisor_uid,
            self.supervisor_gid,
            self.input_directory_device,
            self.input_directory_inode,
            0o555,
        )?;
        if let Some(file) = &self.artifact_file {
            verify_named_file_v1(
                &self.input_directory,
                &self.input_basename,
                file,
                self.device,
                self.inode,
                self.artifact_byte_length,
                0o444,
                self.supervisor_uid,
                self.supervisor_gid,
            )?;
        }
        set_file_mode_v1(&self.input_directory, 0o700)
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::CleanupFailed)?;
        if unsafe {
            libc::unlinkat(
                self.input_directory.as_raw_fd(),
                self.input_basename.as_ptr(),
                0,
            )
        } != 0
        {
            return Err(LinuxVzPackageMaterializationErrorV1::CleanupFailed);
        }
        self.artifact_file.take();
        self.input_directory
            .sync_all()
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::CleanupFailed)?;
        if unsafe {
            libc::unlinkat(
                self.run_root.as_raw_fd(),
                self.input_directory_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(LinuxVzPackageMaterializationErrorV1::CleanupFailed);
        }
        self.run_root
            .sync_all()
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::CleanupFailed)?;
        self.cleaned = true;
        Ok(())
    }

    fn verify(
        &mut self,
        phase: LinuxVzPackageArtifactRehashPhaseV1,
    ) -> Result<
        LinuxVzPackageArtifactMaterializationObservationV1,
        LinuxVzPackageMaterializationErrorV1,
    > {
        verify_named_directory_v1(
            &self.run_root,
            &self.input_directory_name,
            &self.input_directory,
            self.supervisor_uid,
            self.supervisor_gid,
            self.input_directory_device,
            self.input_directory_inode,
            0o555,
        )?;
        let artifact_file = self
            .artifact_file
            .as_mut()
            .ok_or(LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        verify_named_file_v1(
            &self.input_directory,
            &self.input_basename,
            artifact_file,
            self.device,
            self.inode,
            self.artifact_byte_length,
            0o444,
            self.supervisor_uid,
            self.supervisor_gid,
        )?;
        let (digest, length) = hash_file_from_start_v1(artifact_file)?;
        if digest != self.artifact_sha256 || length != self.artifact_byte_length {
            return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
        }
        Ok(self.observation(phase))
    }

    fn observation(
        &self,
        phase: LinuxVzPackageArtifactRehashPhaseV1,
    ) -> LinuxVzPackageArtifactMaterializationObservationV1 {
        LinuxVzPackageArtifactMaterializationObservationV1 {
            phase,
            process_plan_sha256: self.process_plan_sha256.clone(),
            artifact_sha256: self.artifact_sha256.clone(),
            artifact_byte_length: self.artifact_byte_length,
            input_basename: self.input_basename.to_string_lossy().into_owned(),
            supervisor_uid: self.supervisor_uid,
            supervisor_gid: self.supervisor_gid,
            input_directory_device: self.input_directory_device,
            input_directory_inode: self.input_directory_inode,
            device: self.device,
            inode: self.inode,
        }
    }
}

impl Drop for MaterializedLinuxVzPackageArtifactV1 {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub fn materialize_linux_vz_package_artifact_v1(
    run_root: &File,
    exact_artifact_source: &mut File,
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<
    (
        MaterializedLinuxVzPackageArtifactV1,
        LinuxVzPackageArtifactMaterializationObservationV1,
    ),
    LinuxVzPackageMaterializationErrorV1,
> {
    policy.validate_current_process()?;
    validate_run_root_v1(run_root, policy)?;
    let input_basename = exact_input_basename_v1(process_plan)?;
    validate_source_v1(
        exact_artifact_source,
        policy,
        process_plan.artifact_byte_length(),
    )?;
    let (source_digest, source_length) = hash_file_from_start_v1(exact_artifact_source)
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::SourceInvalid)?;
    if &source_digest != process_plan.artifact_sha256()
        || source_length != process_plan.artifact_byte_length()
    {
        return Err(LinuxVzPackageMaterializationErrorV1::SourceInvalid);
    }
    let retained_run_root = run_root
        .try_clone()
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::CreateFailed)?;

    let input_name = fixed_component_v1(INPUT_DIRECTORY_NAME_V1)?;
    create_directory_at_v1(run_root.as_raw_fd(), &input_name, 0o700)?;
    let input_directory = match open_directory_at_v1(run_root.as_raw_fd(), &input_name) {
        Ok(directory) => directory,
        Err(error) => {
            let _ = unsafe {
                libc::unlinkat(
                    run_root.as_raw_fd(),
                    input_name.as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
            return Err(error);
        }
    };
    let result = (|| {
        validate_created_directory_v1(&input_directory, policy, 0o700)?;
        let mut artifact_file =
            create_file_at_v1(input_directory.as_raw_fd(), &input_basename, 0o600)?;
        copy_exact_file_v1(
            exact_artifact_source,
            &mut artifact_file,
            process_plan.artifact_byte_length(),
        )?;
        artifact_file
            .sync_all()
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::SyncFailed)?;
        set_file_mode_v1(&artifact_file, 0o444)?;
        artifact_file
            .sync_all()
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::SyncFailed)?;
        let metadata = artifact_file
            .metadata()
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        verify_named_file_v1(
            &input_directory,
            &input_basename,
            &artifact_file,
            metadata.dev(),
            metadata.ino(),
            process_plan.artifact_byte_length(),
            0o444,
            policy.supervisor_uid(),
            policy.supervisor_gid(),
        )?;
        let (digest, length) = hash_file_from_start_v1(&mut artifact_file)?;
        if digest != *process_plan.artifact_sha256()
            || length != process_plan.artifact_byte_length()
        {
            return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
        }
        set_file_mode_v1(&input_directory, 0o555)?;
        input_directory
            .sync_all()
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::SyncFailed)?;
        let input_directory_metadata = input_directory
            .metadata()
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        verify_named_directory_v1(
            run_root,
            &input_name,
            &input_directory,
            policy.supervisor_uid(),
            policy.supervisor_gid(),
            input_directory_metadata.dev(),
            input_directory_metadata.ino(),
            0o555,
        )?;
        Ok((
            artifact_file,
            metadata.dev(),
            metadata.ino(),
            input_directory_metadata.dev(),
            input_directory_metadata.ino(),
        ))
    })();

    match result {
        Ok((artifact_file, device, inode, input_directory_device, input_directory_inode)) => {
            let materialized = MaterializedLinuxVzPackageArtifactV1 {
                run_root: retained_run_root,
                input_directory,
                input_directory_name: input_name,
                artifact_file: Some(artifact_file),
                input_basename,
                process_plan_sha256: process_plan.process_plan_sha256().clone(),
                artifact_sha256: process_plan.artifact_sha256().clone(),
                artifact_byte_length: process_plan.artifact_byte_length(),
                supervisor_uid: policy.supervisor_uid(),
                supervisor_gid: policy.supervisor_gid(),
                input_directory_device,
                input_directory_inode,
                device,
                inode,
                cleaned: false,
            };
            let observation = materialized.observation(LinuxVzPackageArtifactRehashPhaseV1::Staged);
            Ok((materialized, observation))
        }
        Err(error) => {
            best_effort_remove_created_input_v1(
                run_root,
                &input_directory,
                &input_basename,
                &input_name,
            );
            Err(error)
        }
    }
}

fn best_effort_remove_created_input_v1(
    run_root: &File,
    input_directory: &File,
    input_basename: &CString,
    input_name: &CString,
) {
    let _ = unsafe { libc::fchmod(input_directory.as_raw_fd(), 0o700 as libc::mode_t) };
    let _ = unsafe { libc::unlinkat(input_directory.as_raw_fd(), input_basename.as_ptr(), 0) };
    let _ = input_directory.sync_all();
    let _ = unsafe {
        libc::unlinkat(
            run_root.as_raw_fd(),
            input_name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    };
    let _ = run_root.sync_all();
}

fn exact_input_basename_v1(
    plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
) -> Result<CString, LinuxVzPackageMaterializationErrorV1> {
    let mut basenames = plan.actions().iter().filter_map(|action| match action {
        MacosLinuxVzPackageExecutionActionV1::Internal {
            action:
                MacosLinuxVzPackageInternalActionV1::MaterializeExactArtifact { input_basename },
        } => Some(input_basename.as_str()),
        _ => None,
    });
    let basename = basenames
        .next()
        .ok_or(LinuxVzPackageMaterializationErrorV1::InvalidProcessPlan)?;
    if basenames.next().is_some() {
        return Err(LinuxVzPackageMaterializationErrorV1::InvalidProcessPlan);
    }
    fixed_component_v1(basename)
}

fn fixed_component_v1(value: &str) -> Result<CString, LinuxVzPackageMaterializationErrorV1> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.contains('/')
        || value.contains('\\')
        || value.len() > 255
        || !value.is_ascii()
    {
        return Err(LinuxVzPackageMaterializationErrorV1::InvalidProcessPlan);
    }
    CString::new(value).map_err(|_| LinuxVzPackageMaterializationErrorV1::InvalidProcessPlan)
}

fn validate_run_root_v1(
    run_root: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    let metadata = run_root
        .metadata()
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::UnsafeRunRoot)?;
    let package_can_traverse = if policy.package_uid == policy.supervisor_uid {
        metadata.mode() & 0o100 != 0
    } else if policy.package_gid == metadata.gid() {
        metadata.mode() & 0o010 != 0
    } else {
        metadata.mode() & 0o001 != 0
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != policy.supervisor_uid
        || metadata.gid() != policy.supervisor_gid
        || metadata.mode() & 0o022 != 0
        || !package_can_traverse
    {
        return Err(LinuxVzPackageMaterializationErrorV1::UnsafeRunRoot);
    }
    Ok(())
}

fn validate_source_v1(
    source: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
    expected_length: u64,
) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    let metadata = source
        .metadata()
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::SourceInvalid)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != policy.supervisor_uid
        || metadata.gid() != policy.supervisor_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o444
        || metadata.len() != expected_length
    {
        return Err(LinuxVzPackageMaterializationErrorV1::SourceInvalid);
    }
    Ok(())
}

fn create_directory_at_v1(
    parent: RawFd,
    name: &CString,
    mode: u32,
) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    if unsafe { libc::mkdirat(parent, name.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(LinuxVzPackageMaterializationErrorV1::CreateFailed);
    }
    Ok(())
}

fn open_directory_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<File, LinuxVzPackageMaterializationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageMaterializationErrorV1::CreateFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn create_file_at_v1(
    parent: RawFd,
    name: &CString,
    mode: u32,
) -> Result<File, LinuxVzPackageMaterializationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageMaterializationErrorV1::CreateFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_created_directory_v1(
    directory: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
    expected_mode: u32,
) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    let metadata = directory
        .metadata()
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != policy.supervisor_uid
        || metadata.gid() != policy.supervisor_gid
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn set_file_mode_v1(file: &File, mode: u32) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn copy_exact_file_v1(
    source: &mut File,
    destination: &mut File,
    expected_length: u64,
) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::CopyFailed)?;
    let mut remaining = expected_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let limit = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::CopyFailed)?;
        let count = source
            .read(&mut buffer[..limit])
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::CopyFailed)?;
        if count == 0 {
            return Err(LinuxVzPackageMaterializationErrorV1::CopyFailed);
        }
        destination
            .write_all(&buffer[..count])
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::CopyFailed)?;
        remaining -= count as u64;
    }
    let mut trailing = [0_u8; 1];
    if source
        .read(&mut trailing)
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::CopyFailed)?
        != 0
    {
        return Err(LinuxVzPackageMaterializationErrorV1::CopyFailed);
    }
    Ok(())
}

fn hash_file_from_start_v1(
    file: &mut File,
) -> Result<(Sha256Digest, u64), LinuxVzPackageMaterializationErrorV1> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        length = length
            .checked_add(count as u64)
            .ok_or(LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    let raw: [u8; 32] = hasher.finalize().into();
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    }
    let digest = Sha256Digest::parse(value)
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    Ok((digest, length))
}

#[allow(clippy::too_many_arguments, clippy::unnecessary_cast)]
fn verify_named_file_v1(
    directory: &File,
    name: &CString,
    file: &File,
    expected_device: u64,
    expected_inode: u64,
    expected_length: u64,
    expected_mode: u32,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    let descriptor_metadata = file
        .metadata()
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    let mut raw = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            raw.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
    }
    let path_metadata = unsafe { raw.assume_init() };
    let path_mode = path_metadata.st_mode as u32;
    if !descriptor_metadata.file_type().is_file()
        || path_mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
        || descriptor_metadata.dev() != expected_device
        || descriptor_metadata.ino() != expected_inode
        || path_metadata.st_dev as u64 != expected_device
        || path_metadata.st_ino as u64 != expected_inode
        || descriptor_metadata.uid() != expected_uid
        || descriptor_metadata.gid() != expected_gid
        || path_metadata.st_uid != expected_uid
        || path_metadata.st_gid != expected_gid
        || descriptor_metadata.nlink() != 1
        || path_metadata.st_nlink as u64 != 1
        || descriptor_metadata.len() != expected_length
        || path_metadata.st_size < 0
        || path_metadata.st_size as u64 != expected_length
        || descriptor_metadata.mode() & 0o7777 != expected_mode
        || path_mode & 0o7777 != expected_mode
    {
        return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::unnecessary_cast)]
fn verify_named_directory_v1(
    parent: &File,
    name: &CString,
    directory: &File,
    expected_uid: u32,
    expected_gid: u32,
    expected_device: u64,
    expected_inode: u64,
    expected_mode: u32,
) -> Result<(), LinuxVzPackageMaterializationErrorV1> {
    let descriptor_metadata = directory
        .metadata()
        .map_err(|_| LinuxVzPackageMaterializationErrorV1::VerificationFailed)?;
    let mut raw = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            raw.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
    }
    let path_metadata = unsafe { raw.assume_init() };
    let path_mode = path_metadata.st_mode as u32;
    if !descriptor_metadata.file_type().is_dir()
        || path_mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR)
        || descriptor_metadata.dev() != expected_device
        || descriptor_metadata.ino() != expected_inode
        || path_metadata.st_dev as u64 != expected_device
        || path_metadata.st_ino as u64 != expected_inode
        || descriptor_metadata.uid() != expected_uid
        || descriptor_metadata.gid() != expected_gid
        || path_metadata.st_uid != expected_uid
        || path_metadata.st_gid != expected_gid
        || descriptor_metadata.mode() & 0o7777 != expected_mode
        || path_mode & 0o7777 != expected_mode
    {
        return Err(LinuxVzPackageMaterializationErrorV1::VerificationFailed);
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
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use whoathere_detonation::NpmEnvironmentProfileV1;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    const ARTIFACT_BYTES: &[u8] = b"inert test-only artifact";

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn test_root() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "whoathere-linux-vz-materialization-{}-{counter}",
            std::process::id()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).expect("create test run root");
        path
    }

    fn test_plan() -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::NodeNpm {
                node_version: "24.17.0".to_string(),
                node_executable_sha256: digest("node"),
                npm_version: "11.12.1".to_string(),
                npm_cli_sha256: digest("npm"),
            },
            "npm_install_exact_local_tarball",
            vec![
                MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
                    environment: NpmEnvironmentProfileV1::CiFalse,
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

    fn source_file(path: &PathBuf, bytes: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create source");
        file.write_all(bytes).expect("write source");
        file.sync_all().expect("sync source");
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .expect("seal source");
        file.seek(SeekFrom::Start(0)).expect("rewind source");
        file
    }

    #[test]
    fn exact_plan_bound_artifact_is_staged_rehashed_and_cleaned_fd_relatively() {
        let root_path = test_root();
        let source_path = root_path.with_extension("source");
        let run_root = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&root_path)
            .expect("open run root");
        let mut source = source_file(&source_path, ARTIFACT_BYTES);
        let plan = test_plan();
        assert_eq!(
            plan.artifact_sha256(),
            &Sha256Digest::from_bytes(ARTIFACT_BYTES)
        );
        assert_eq!(plan.artifact_byte_length(), ARTIFACT_BYTES.len() as u64);
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();

        let (mut materialized, staged) =
            materialize_linux_vz_package_artifact_v1(&run_root, &mut source, &plan, &policy)
                .expect("materialize exact artifact");
        assert_eq!(staged.phase(), LinuxVzPackageArtifactRehashPhaseV1::Staged);
        assert_eq!(staged.input_basename(), "package.tgz");
        let prelaunch = materialized.verify_prelaunch().expect("prelaunch rehash");
        let postrun = materialized.verify_postrun().expect("postrun rehash");
        assert_eq!(prelaunch.artifact_sha256(), plan.artifact_sha256());
        assert_eq!(prelaunch.device(), postrun.device());
        assert_eq!(prelaunch.inode(), postrun.inode());
        let staged_path = root_path.join("input/package.tgz");
        let metadata = fs::symlink_metadata(&staged_path).expect("staged metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o444);
        assert_eq!(metadata.nlink(), 1);
        assert!(OpenOptions::new().write(true).open(&staged_path).is_err());
        materialized.cleanup().expect("cleanup");
        assert!(!root_path.join("input").exists());

        drop(source);
        drop(run_root);
        fs::remove_file(source_path).expect("remove source");
        fs::remove_dir(root_path).expect("remove root");
    }

    #[test]
    fn wrong_bytes_and_preexisting_input_namespace_fail_before_publication() {
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let plan = test_plan();

        let wrong_root_path = test_root();
        let wrong_source_path = wrong_root_path.with_extension("source");
        let wrong_root = File::open(&wrong_root_path).expect("open wrong root");
        let mut wrong_source = source_file(&wrong_source_path, b"wrong inert bytes payload");
        assert_eq!(
            materialize_linux_vz_package_artifact_v1(
                &wrong_root,
                &mut wrong_source,
                &plan,
                &policy,
            )
            .map(|_| ()),
            Err(LinuxVzPackageMaterializationErrorV1::SourceInvalid)
        );
        assert!(!wrong_root_path.join("input").exists());
        drop(wrong_source);
        drop(wrong_root);
        fs::remove_file(wrong_source_path).expect("remove wrong source");
        fs::remove_dir(wrong_root_path).expect("remove wrong root");

        let occupied_root_path = test_root();
        let occupied_source_path = occupied_root_path.with_extension("source");
        fs::create_dir(occupied_root_path.join("input")).expect("occupy input namespace");
        let occupied_root = File::open(&occupied_root_path).expect("open occupied root");
        let mut occupied_source = source_file(&occupied_source_path, ARTIFACT_BYTES);
        assert_eq!(
            materialize_linux_vz_package_artifact_v1(
                &occupied_root,
                &mut occupied_source,
                &plan,
                &policy,
            )
            .map(|_| ()),
            Err(LinuxVzPackageMaterializationErrorV1::CreateFailed)
        );
        drop(occupied_source);
        drop(occupied_root);
        fs::remove_dir(occupied_root_path.join("input")).expect("remove occupied input");
        fs::remove_file(occupied_source_path).expect("remove occupied source");
        fs::remove_dir(occupied_root_path).expect("remove occupied root");
    }
}
