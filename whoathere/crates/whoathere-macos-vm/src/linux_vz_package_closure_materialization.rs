use crate::{
    LinuxVzPackageMaterializationPolicyV1, MacosLinuxVzPackageExecutionActionV1,
    MacosLinuxVzPackageExecutionProcessPlanV1, MacosLinuxVzPackageInternalActionV1,
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
use whoathere_detonation::{SdistBuildClosureArtifactV1, SdistBuildClosureV1};

const CLOSURE_DIRECTORY_NAME_V1: &str = "closure";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageClosureMaterializationErrorV1 {
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

impl LinuxVzPackageClosureMaterializationErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::PrivilegeBoundary => "linux_vz_package_closure_materialization_privilege_invalid",
            Self::UnsafeRunRoot => "linux_vz_package_closure_materialization_run_root_unsafe",
            Self::InvalidProcessPlan => "linux_vz_package_closure_materialization_plan_invalid",
            Self::SourceInvalid => "linux_vz_package_closure_materialization_source_invalid",
            Self::CreateFailed => "linux_vz_package_closure_materialization_create_failed",
            Self::CopyFailed => "linux_vz_package_closure_materialization_copy_failed",
            Self::SyncFailed => "linux_vz_package_closure_materialization_sync_failed",
            Self::VerificationFailed => {
                "linux_vz_package_closure_materialization_verification_failed"
            }
            Self::CleanupFailed => "linux_vz_package_closure_materialization_cleanup_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageClosureMaterializationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageClosureMaterializationErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageClosureRehashPhaseV1 {
    Staged,
    Prelaunch,
    Postrun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageClosureMaterializationObservationV1 {
    phase: LinuxVzPackageClosureRehashPhaseV1,
    process_plan_sha256: Sha256Digest,
    build_requires_sha256: Sha256Digest,
    closure_sha256: Sha256Digest,
    payload_sha256: Sha256Digest,
    artifact_count: usize,
    payload_byte_length: u64,
    supervisor_uid: u32,
    supervisor_gid: u32,
    closure_device: u64,
    closure_inode: u64,
}

impl LinuxVzPackageClosureMaterializationObservationV1 {
    pub const fn phase(&self) -> LinuxVzPackageClosureRehashPhaseV1 {
        self.phase
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn build_requires_sha256(&self) -> &Sha256Digest {
        &self.build_requires_sha256
    }

    pub fn closure_sha256(&self) -> &Sha256Digest {
        &self.closure_sha256
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub const fn artifact_count(&self) -> usize {
        self.artifact_count
    }

    pub const fn payload_byte_length(&self) -> u64 {
        self.payload_byte_length
    }

    pub const fn supervisor_uid(&self) -> u32 {
        self.supervisor_uid
    }

    pub const fn supervisor_gid(&self) -> u32 {
        self.supervisor_gid
    }

    pub const fn closure_device(&self) -> u64 {
        self.closure_device
    }

    pub const fn closure_inode(&self) -> u64 {
        self.closure_inode
    }
}

struct MaterializedClosureFileV1 {
    name: CString,
    file: File,
    sha256: Sha256Digest,
    byte_length: u64,
    device: u64,
    inode: u64,
}

pub struct MaterializedLinuxVzPackageBuildClosureV1 {
    run_root: File,
    closure_directory: File,
    closure_name: CString,
    files: Vec<MaterializedClosureFileV1>,
    process_plan_sha256: Sha256Digest,
    build_requires_sha256: Sha256Digest,
    closure_sha256: Sha256Digest,
    payload_sha256: Sha256Digest,
    payload_byte_length: u64,
    supervisor_uid: u32,
    supervisor_gid: u32,
    closure_device: u64,
    closure_inode: u64,
    cleaned: bool,
}

impl fmt::Debug for MaterializedLinuxVzPackageBuildClosureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MaterializedLinuxVzPackageBuildClosureV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("closure_sha256", &self.closure_sha256)
            .field("payload_sha256", &self.payload_sha256)
            .field("artifact_count", &self.files.len())
            .field("payload_byte_length", &self.payload_byte_length)
            .field("path", &"<fixed-run-root-closure-path-redacted>")
            .field("artifact_bytes", &"<redacted>")
            .field("cleaned", &self.cleaned)
            .finish()
    }
}

impl MaterializedLinuxVzPackageBuildClosureV1 {
    pub fn verify_prelaunch(
        &mut self,
    ) -> Result<
        LinuxVzPackageClosureMaterializationObservationV1,
        LinuxVzPackageClosureMaterializationErrorV1,
    > {
        self.verify(LinuxVzPackageClosureRehashPhaseV1::Prelaunch)
    }

    pub fn verify_postrun(
        &mut self,
    ) -> Result<
        LinuxVzPackageClosureMaterializationObservationV1,
        LinuxVzPackageClosureMaterializationErrorV1,
    > {
        self.verify(LinuxVzPackageClosureRehashPhaseV1::Postrun)
    }

    pub fn cleanup(&mut self) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
        if self.cleaned {
            return Ok(());
        }
        self.verify_files_v1()?;
        set_mode_v1(&self.closure_directory, 0o700)
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::CleanupFailed)?;
        while let Some(entry) = self.files.pop() {
            if unsafe { libc::unlinkat(self.closure_directory.as_raw_fd(), entry.name.as_ptr(), 0) }
                != 0
            {
                self.files.push(entry);
                return Err(LinuxVzPackageClosureMaterializationErrorV1::CleanupFailed);
            }
        }
        self.closure_directory
            .sync_all()
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::CleanupFailed)?;
        if unsafe {
            libc::unlinkat(
                self.run_root.as_raw_fd(),
                self.closure_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } != 0
        {
            return Err(LinuxVzPackageClosureMaterializationErrorV1::CleanupFailed);
        }
        self.run_root
            .sync_all()
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::CleanupFailed)?;
        self.cleaned = true;
        Ok(())
    }

    fn verify(
        &mut self,
        phase: LinuxVzPackageClosureRehashPhaseV1,
    ) -> Result<
        LinuxVzPackageClosureMaterializationObservationV1,
        LinuxVzPackageClosureMaterializationErrorV1,
    > {
        verify_named_directory_v1(
            &self.run_root,
            &self.closure_name,
            &self.closure_directory,
            self.supervisor_uid,
            self.supervisor_gid,
            self.closure_device,
            self.closure_inode,
            0o555,
        )?;
        self.verify_files_v1()?;
        Ok(self.observation(phase))
    }

    fn verify_files_v1(&mut self) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
        for entry in &mut self.files {
            verify_named_file_v1(
                &self.closure_directory,
                entry,
                self.supervisor_uid,
                self.supervisor_gid,
            )?;
        }
        Ok(())
    }

    fn observation(
        &self,
        phase: LinuxVzPackageClosureRehashPhaseV1,
    ) -> LinuxVzPackageClosureMaterializationObservationV1 {
        LinuxVzPackageClosureMaterializationObservationV1 {
            phase,
            process_plan_sha256: self.process_plan_sha256.clone(),
            build_requires_sha256: self.build_requires_sha256.clone(),
            closure_sha256: self.closure_sha256.clone(),
            payload_sha256: self.payload_sha256.clone(),
            artifact_count: self.files.len(),
            payload_byte_length: self.payload_byte_length,
            supervisor_uid: self.supervisor_uid,
            supervisor_gid: self.supervisor_gid,
            closure_device: self.closure_device,
            closure_inode: self.closure_inode,
        }
    }
}

impl Drop for MaterializedLinuxVzPackageBuildClosureV1 {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub fn materialize_linux_vz_package_build_closure_v1(
    run_root: &File,
    closure_payload_source: &mut File,
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<
    (
        MaterializedLinuxVzPackageBuildClosureV1,
        LinuxVzPackageClosureMaterializationObservationV1,
    ),
    LinuxVzPackageClosureMaterializationErrorV1,
> {
    policy
        .validate_current_process()
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::PrivilegeBoundary)?;
    validate_run_root_v1(run_root, policy)?;
    let (build_requires_sha256, closure) = exact_build_closure_v1(process_plan)?;
    let payload_byte_length = closure
        .artifacts()
        .iter()
        .try_fold(0_u64, |total, artifact| {
            total
                .checked_add(artifact.artifact_byte_length())
                .ok_or(LinuxVzPackageClosureMaterializationErrorV1::InvalidProcessPlan)
        })?;
    validate_source_v1(closure_payload_source, policy, payload_byte_length)?;
    let retained_run_root = run_root
        .try_clone()
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::CreateFailed)?;
    let closure_name = fixed_component_v1(CLOSURE_DIRECTORY_NAME_V1)?;
    create_directory_at_v1(run_root.as_raw_fd(), &closure_name, 0o700)?;
    let closure_directory = match open_directory_at_v1(run_root.as_raw_fd(), &closure_name) {
        Ok(directory) => directory,
        Err(error) => {
            remove_closure_root_v1(run_root, &closure_name);
            return Err(error);
        }
    };

    let result = (|| {
        validate_created_directory_v1(&closure_directory, policy, 0o700)?;
        closure_payload_source
            .seek(SeekFrom::Start(0))
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SourceInvalid)?;
        let mut payload_hasher = Sha256::new();
        let mut files = Vec::with_capacity(closure.artifacts().len());
        for artifact in closure.artifacts() {
            let name = fixed_component_v1(artifact.artifact_filename())?;
            let mut file = create_file_at_v1(closure_directory.as_raw_fd(), &name, 0o600)?;
            let observed_digest = copy_exact_segment_v1(
                closure_payload_source,
                &mut file,
                artifact.artifact_byte_length(),
                &mut payload_hasher,
            )?;
            if &observed_digest != artifact.artifact_sha256() {
                return Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed);
            }
            file.sync_all()
                .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SyncFailed)?;
            set_mode_v1(&file, 0o444)?;
            file.sync_all()
                .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SyncFailed)?;
            let metadata = file
                .metadata()
                .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
            let mut entry = MaterializedClosureFileV1 {
                name,
                file,
                sha256: artifact.artifact_sha256().clone(),
                byte_length: artifact.artifact_byte_length(),
                device: metadata.dev(),
                inode: metadata.ino(),
            };
            verify_named_file_v1(
                &closure_directory,
                &mut entry,
                policy.supervisor_uid(),
                policy.supervisor_gid(),
            )?;
            files.push(entry);
        }
        let mut trailing = [0_u8; 1];
        if closure_payload_source
            .read(&mut trailing)
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SourceInvalid)?
            != 0
        {
            return Err(LinuxVzPackageClosureMaterializationErrorV1::SourceInvalid);
        }
        closure_payload_source
            .seek(SeekFrom::Start(0))
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SourceInvalid)?;
        set_mode_v1(&closure_directory, 0o555)?;
        closure_directory
            .sync_all()
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SyncFailed)?;
        let metadata = closure_directory
            .metadata()
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
        verify_named_directory_v1(
            run_root,
            &closure_name,
            &closure_directory,
            policy.supervisor_uid(),
            policy.supervisor_gid(),
            metadata.dev(),
            metadata.ino(),
            0o555,
        )?;
        run_root
            .sync_all()
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SyncFailed)?;
        Ok((
            files,
            digest_from_hasher_v1(payload_hasher)?,
            metadata.dev(),
            metadata.ino(),
        ))
    })();

    match result {
        Ok((files, payload_sha256, closure_device, closure_inode)) => {
            let materialized = MaterializedLinuxVzPackageBuildClosureV1 {
                run_root: retained_run_root,
                closure_directory,
                closure_name,
                files,
                process_plan_sha256: process_plan.process_plan_sha256().clone(),
                build_requires_sha256,
                closure_sha256: closure.closure_sha256().clone(),
                payload_sha256,
                payload_byte_length,
                supervisor_uid: policy.supervisor_uid(),
                supervisor_gid: policy.supervisor_gid(),
                closure_device,
                closure_inode,
                cleaned: false,
            };
            let observation = materialized.observation(LinuxVzPackageClosureRehashPhaseV1::Staged);
            Ok((materialized, observation))
        }
        Err(error) => {
            best_effort_remove_closure_v1(
                run_root,
                &closure_directory,
                &closure_name,
                closure.artifacts(),
            );
            Err(error)
        }
    }
}

fn exact_build_closure_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
) -> Result<(Sha256Digest, SdistBuildClosureV1), LinuxVzPackageClosureMaterializationErrorV1> {
    let mut actions = process_plan
        .actions()
        .iter()
        .filter_map(|action| match action {
            MacosLinuxVzPackageExecutionActionV1::Internal {
                action:
                    MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                        build_requires_sha256,
                        build_closure,
                    },
            } => Some((build_requires_sha256, build_closure)),
            _ => None,
        });
    let (build_requires_sha256, closure) = actions
        .next()
        .ok_or(LinuxVzPackageClosureMaterializationErrorV1::InvalidProcessPlan)?;
    if actions.next().is_some()
        || closure.artifacts().is_empty()
        || closure.validate().is_err()
        || build_requires_sha256 != closure.declaration_set_sha256()
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::InvalidProcessPlan);
    }
    Ok((build_requires_sha256.clone(), closure.clone()))
}

fn validate_run_root_v1(
    run_root: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
    let metadata = run_root
        .metadata()
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::UnsafeRunRoot)?;
    let package_can_traverse = if policy.package_uid() == policy.supervisor_uid() {
        metadata.mode() & 0o100 != 0
    } else if policy.package_gid() == metadata.gid() {
        metadata.mode() & 0o010 != 0
    } else {
        metadata.mode() & 0o001 != 0
    };
    if !metadata.file_type().is_dir()
        || metadata.uid() != policy.supervisor_uid()
        || metadata.gid() != policy.supervisor_gid()
        || metadata.mode() & 0o022 != 0
        || !package_can_traverse
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::UnsafeRunRoot);
    }
    Ok(())
}

fn validate_source_v1(
    source: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
    expected_length: u64,
) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
    let metadata = source
        .metadata()
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::SourceInvalid)?;
    if expected_length == 0
        || !metadata.file_type().is_file()
        || metadata.uid() != policy.supervisor_uid()
        || metadata.gid() != policy.supervisor_gid()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o444
        || metadata.len() != expected_length
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::SourceInvalid);
    }
    Ok(())
}

fn fixed_component_v1(value: &str) -> Result<CString, LinuxVzPackageClosureMaterializationErrorV1> {
    if value.is_empty()
        || value == "."
        || value == ".."
        || value.len() > 255
        || !value.is_ascii()
        || value.contains('/')
        || value.contains('\\')
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::InvalidProcessPlan);
    }
    CString::new(value).map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::InvalidProcessPlan)
}

fn create_directory_at_v1(
    parent: RawFd,
    name: &CString,
    mode: u32,
) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
    if unsafe { libc::mkdirat(parent, name.as_ptr(), mode as libc::mode_t) } != 0 {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::CreateFailed);
    }
    Ok(())
}

fn open_directory_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<File, LinuxVzPackageClosureMaterializationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::CreateFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn create_file_at_v1(
    parent: RawFd,
    name: &CString,
    mode: u32,
) -> Result<File, LinuxVzPackageClosureMaterializationErrorV1> {
    let descriptor = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            mode as libc::c_uint,
        )
    };
    if descriptor < 0 {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::CreateFailed);
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn validate_created_directory_v1(
    directory: &File,
    policy: &LinuxVzPackageMaterializationPolicyV1,
    expected_mode: u32,
) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
    let metadata = directory
        .metadata()
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != policy.supervisor_uid()
        || metadata.gid() != policy.supervisor_gid()
        || metadata.mode() & 0o7777 != expected_mode
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn set_mode_v1(file: &File, mode: u32) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
    if unsafe { libc::fchmod(file.as_raw_fd(), mode as libc::mode_t) } != 0 {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn copy_exact_segment_v1(
    source: &mut File,
    destination: &mut File,
    byte_length: u64,
    payload_hasher: &mut Sha256,
) -> Result<Sha256Digest, LinuxVzPackageClosureMaterializationErrorV1> {
    let mut remaining = byte_length;
    let mut artifact_hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::CopyFailed)?;
        let count = source
            .read(&mut buffer[..requested])
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::CopyFailed)?;
        if count == 0 {
            return Err(LinuxVzPackageClosureMaterializationErrorV1::CopyFailed);
        }
        destination
            .write_all(&buffer[..count])
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::CopyFailed)?;
        artifact_hasher.update(&buffer[..count]);
        payload_hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    digest_from_hasher_v1(artifact_hasher)
}

fn digest_from_hasher_v1(
    hasher: Sha256,
) -> Result<Sha256Digest, LinuxVzPackageClosureMaterializationErrorV1> {
    let raw: [u8; 32] = hasher.finalize().into();
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
    }
    Sha256Digest::parse(value)
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)
}

fn hash_file_v1(
    file: &mut File,
) -> Result<(Sha256Digest, u64), LinuxVzPackageClosureMaterializationErrorV1> {
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        length = length
            .checked_add(count as u64)
            .ok_or(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
    Ok((digest_from_hasher_v1(hasher)?, length))
}

fn verify_named_file_v1(
    directory: &File,
    entry: &mut MaterializedClosureFileV1,
    expected_uid: u32,
    expected_gid: u32,
) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
    let metadata = entry
        .file
        .metadata()
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
    let raw = stat_at_v1(directory.as_raw_fd(), &entry.name)?;
    let raw_mode = raw.st_mode as u32;
    if !metadata.file_type().is_file()
        || raw_mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFREG)
        || metadata.dev() != entry.device
        || metadata.ino() != entry.inode
        || raw.st_dev as u64 != entry.device
        || raw.st_ino as u64 != entry.inode
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || raw.st_uid != expected_uid
        || raw.st_gid != expected_gid
        || metadata.nlink() != 1
        || raw.st_nlink as u64 != 1
        || metadata.len() != entry.byte_length
        || raw.st_size < 0
        || raw.st_size as u64 != entry.byte_length
        || metadata.mode() & 0o7777 != 0o444
        || raw_mode & 0o7777 != 0o444
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed);
    }
    let (digest, length) = hash_file_v1(&mut entry.file)?;
    if digest != entry.sha256 || length != entry.byte_length {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn verify_named_directory_v1(
    parent: &File,
    name: &CString,
    directory: &File,
    expected_uid: u32,
    expected_gid: u32,
    expected_device: u64,
    expected_inode: u64,
    expected_mode: u32,
) -> Result<(), LinuxVzPackageClosureMaterializationErrorV1> {
    let metadata = directory
        .metadata()
        .map_err(|_| LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)?;
    let raw = stat_at_v1(parent.as_raw_fd(), name)?;
    let raw_mode = raw.st_mode as u32;
    if !metadata.file_type().is_dir()
        || raw_mode & u32::from(libc::S_IFMT) != u32::from(libc::S_IFDIR)
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
        || raw.st_dev as u64 != expected_device
        || raw.st_ino as u64 != expected_inode
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || raw.st_uid != expected_uid
        || raw.st_gid != expected_gid
        || metadata.mode() & 0o7777 != expected_mode
        || raw_mode & 0o7777 != expected_mode
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed);
    }
    Ok(())
}

fn stat_at_v1(
    parent: RawFd,
    name: &CString,
) -> Result<libc::stat, LinuxVzPackageClosureMaterializationErrorV1> {
    let mut raw = MaybeUninit::<libc::stat>::uninit();
    if unsafe {
        libc::fstatat(
            parent,
            name.as_ptr(),
            raw.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed);
    }
    Ok(unsafe { raw.assume_init() })
}

fn best_effort_remove_closure_v1(
    run_root: &File,
    closure_directory: &File,
    closure_name: &CString,
    artifacts: &[SdistBuildClosureArtifactV1],
) {
    let _ = unsafe { libc::fchmod(closure_directory.as_raw_fd(), 0o700 as libc::mode_t) };
    for artifact in artifacts {
        let Ok(name) = fixed_component_v1(artifact.artifact_filename()) else {
            continue;
        };
        let _ = unsafe { libc::unlinkat(closure_directory.as_raw_fd(), name.as_ptr(), 0) };
    }
    let _ = closure_directory.sync_all();
    remove_closure_root_v1(run_root, closure_name);
}

fn remove_closure_root_v1(run_root: &File, closure_name: &CString) {
    let _ = unsafe {
        libc::unlinkat(
            run_root.as_raw_fd(),
            closure_name.as_ptr(),
            libc::AT_REMOVEDIR,
        )
    };
    let _ = run_root.sync_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        MacosLinuxVzPackageDependencyPolicyV1, MacosLinuxVzPackageExecutionStageV1,
        MacosLinuxVzPackageRuntimeExecutablesV1,
    };
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use whoathere_artifact::ArtifactFormat;
    use whoathere_detonation::SdistBuildClosureArtifactFormatV1;

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    const ALPHA_BYTES: &[u8] = b"inert alpha wheel bytes";
    const BETA_BYTES: &[u8] = b"inert beta wheel bytes";

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn closure() -> SdistBuildClosureV1 {
        SdistBuildClosureV1::new(
            &["alpha==1.0.0".to_string(), "beta==2.0.0".to_string()],
            vec![
                SdistBuildClosureArtifactV1::new(
                    "alpha",
                    "1.0.0",
                    "alpha-1.0.0-py3-none-any.whl",
                    SdistBuildClosureArtifactFormatV1::Wheel,
                    Sha256Digest::from_bytes(ALPHA_BYTES),
                    ALPHA_BYTES.len() as u64,
                )
                .expect("alpha closure artifact"),
                SdistBuildClosureArtifactV1::new(
                    "beta",
                    "2.0.0",
                    "beta-2.0.0-py3-none-any.whl",
                    SdistBuildClosureArtifactFormatV1::Wheel,
                    Sha256Digest::from_bytes(BETA_BYTES),
                    BETA_BYTES.len() as u64,
                )
                .expect("beta closure artifact"),
            ],
        )
        .expect("inert build closure")
    }

    fn plan(closure: &SdistBuildClosureV1) -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
                python_version: "3.14.0".to_string(),
                python_executable_sha256: digest("python"),
                pip_version: "25.0".to_string(),
                pip_cli_sha256: digest("pip"),
            },
            "sdist_build_exact",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
                    input_basename: "package.tar.gz".to_string(),
                    artifact_format: ArtifactFormat::SdistTarGzip,
                    expected_archive_root: "fixture-1.0.0".to_string(),
                },
                MacosLinuxVzPackageExecutionStageV1::PythonInstallExactSdistBuildClosure {
                    build_requires_sha256: closure.declaration_set_sha256().clone(),
                    build_closure: closure.clone(),
                    resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexFixedClosureOnly,
                },
            ],
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("process plan")
    }

    fn test_root() -> PathBuf {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "whoathere-linux-vz-closure-materialization-{}-{counter}",
            std::process::id()
        ));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder.create(&path).expect("create test run root");
        path
    }

    fn open_root(path: &Path) -> File {
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .expect("open test run root")
    }

    fn source_file(path: &Path, bytes: &[u8]) -> File {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .expect("create payload source");
        file.write_all(bytes).expect("write payload source");
        file.sync_all().expect("sync payload source");
        file.set_permissions(fs::Permissions::from_mode(0o444))
            .expect("seal payload source");
        file.seek(SeekFrom::Start(0))
            .expect("rewind payload source");
        file
    }

    #[test]
    fn exact_plan_bound_closure_is_staged_rehashed_and_cleaned() {
        let closure = closure();
        let plan = plan(&closure);
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let root_path = test_root();
        let payload_path = root_path.with_extension("payload");
        let run_root = open_root(&root_path);
        let payload = [ALPHA_BYTES, BETA_BYTES].concat();
        let mut source = source_file(&payload_path, &payload);

        let (mut materialized, staged) =
            materialize_linux_vz_package_build_closure_v1(&run_root, &mut source, &plan, &policy)
                .expect("materialize closure");
        assert_eq!(staged.phase(), LinuxVzPackageClosureRehashPhaseV1::Staged);
        assert_eq!(staged.closure_sha256(), closure.closure_sha256());
        assert_eq!(staged.artifact_count(), 2);
        assert_eq!(staged.payload_byte_length(), payload.len() as u64);
        assert_eq!(staged.payload_sha256(), &Sha256Digest::from_bytes(&payload));
        assert_eq!(
            fs::read(root_path.join("closure/alpha-1.0.0-py3-none-any.whl"))
                .expect("read staged alpha"),
            ALPHA_BYTES
        );
        assert!(OpenOptions::new()
            .write(true)
            .open(root_path.join("closure/alpha-1.0.0-py3-none-any.whl"))
            .is_err());
        let prelaunch = materialized.verify_prelaunch().expect("prelaunch rehash");
        let postrun = materialized.verify_postrun().expect("postrun rehash");
        assert_eq!(prelaunch.closure_device(), postrun.closure_device());
        assert_eq!(prelaunch.closure_inode(), postrun.closure_inode());
        assert!(!format!("{materialized:?}").contains("inert alpha"));
        materialized.cleanup().expect("cleanup closure");
        assert!(!root_path.join("closure").exists());

        drop(materialized);
        drop(source);
        drop(run_root);
        fs::remove_file(payload_path).expect("remove payload");
        fs::remove_dir(root_path).expect("remove root");
    }

    #[test]
    fn wrong_closure_payload_fails_before_publication() {
        let closure = closure();
        let plan = plan(&closure);
        let policy = LinuxVzPackageMaterializationPolicyV1::for_current_test_user_v1();
        let root_path = test_root();
        let payload_path = root_path.with_extension("payload");
        let run_root = open_root(&root_path);
        let mut payload = [ALPHA_BYTES, BETA_BYTES].concat();
        payload[0] ^= 1;
        let mut source = source_file(&payload_path, &payload);
        assert!(matches!(
            materialize_linux_vz_package_build_closure_v1(&run_root, &mut source, &plan, &policy,),
            Err(LinuxVzPackageClosureMaterializationErrorV1::VerificationFailed)
        ));
        assert!(!root_path.join("closure").exists());

        drop(source);
        drop(run_root);
        fs::remove_file(payload_path).expect("remove payload");
        fs::remove_dir(root_path).expect("remove root");
    }
}
