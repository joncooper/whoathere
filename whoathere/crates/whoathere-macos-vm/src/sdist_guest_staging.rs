use crate::{
    stream_macos_sdist_guest_submission_v1, MacosSdistGuestSubmissionObservationV1,
    MacosSdistSubmissionErrorV1,
};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use whoathere_artifact::Sha256Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosSdistGuestStagingErrorV1 {
    InvalidPolicy,
    UnsafeRoot,
    EntropyUnavailable,
    CreateFailed,
    Transport(MacosSdistSubmissionErrorV1),
    SyncFailed,
    VerificationFailed,
    CleanupFailed,
}

impl MacosSdistGuestStagingErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidPolicy => "macos_sdist_guest_staging_policy_invalid",
            Self::UnsafeRoot => "macos_sdist_guest_staging_root_unsafe",
            Self::EntropyUnavailable => "macos_sdist_guest_staging_entropy_unavailable",
            Self::CreateFailed => "macos_sdist_guest_staging_create_failed",
            Self::Transport(_) => "macos_sdist_guest_staging_transport_failed",
            Self::SyncFailed => "macos_sdist_guest_staging_sync_failed",
            Self::VerificationFailed => "macos_sdist_guest_staging_verification_failed",
            Self::CleanupFailed => "macos_sdist_guest_staging_cleanup_failed",
        }
    }
}

impl fmt::Display for MacosSdistGuestStagingErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosSdistGuestStagingErrorV1 {}

impl From<MacosSdistSubmissionErrorV1> for MacosSdistGuestStagingErrorV1 {
    fn from(error: MacosSdistSubmissionErrorV1) -> Self {
        Self::Transport(error)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosSdistGuestStagingPolicyV1 {
    staging_root: PathBuf,
    supervisor_uid: u32,
    package_uid: u32,
}

impl MacosSdistGuestStagingPolicyV1 {
    pub fn for_current_supervisor(
        staging_root: PathBuf,
        package_uid: u32,
    ) -> Result<Self, MacosSdistGuestStagingErrorV1> {
        let supervisor_uid = unsafe { libc::geteuid() };
        if staging_root.as_os_str().is_empty()
            || !staging_root.is_absolute()
            || package_uid == 0
            || package_uid == supervisor_uid
        {
            return Err(MacosSdistGuestStagingErrorV1::InvalidPolicy);
        }
        Ok(Self {
            staging_root,
            supervisor_uid,
            package_uid,
        })
    }

    pub fn staging_root(&self) -> &Path {
        &self.staging_root
    }

    pub fn supervisor_uid(&self) -> u32 {
        self.supervisor_uid
    }

    pub fn package_uid(&self) -> u32 {
        self.package_uid
    }

    fn validate_root(&self) -> Result<(), MacosSdistGuestStagingErrorV1> {
        let metadata = fs::symlink_metadata(&self.staging_root)
            .map_err(|_| MacosSdistGuestStagingErrorV1::UnsafeRoot)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != self.supervisor_uid
            || metadata.mode() & 0o022 != 0
        {
            return Err(MacosSdistGuestStagingErrorV1::UnsafeRoot);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdistGuestRehashPhaseV1 {
    Prelaunch,
    Postrun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdistGuestRehashObservationV1 {
    phase: SdistGuestRehashPhaseV1,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    device: u64,
    inode: u64,
}

impl SdistGuestRehashObservationV1 {
    pub fn phase(&self) -> SdistGuestRehashPhaseV1 {
        self.phase
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn inode(&self) -> u64 {
        self.inode
    }
}

pub struct StagedMacosSdistGuestV1 {
    directory: PathBuf,
    artifact_path: PathBuf,
    artifact_file: Option<File>,
    transport: MacosSdistGuestSubmissionObservationV1,
    supervisor_uid: u32,
    device: u64,
    inode: u64,
    cleaned: bool,
}

impl fmt::Debug for StagedMacosSdistGuestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedMacosSdistGuestV1")
            .field("transport", &self.transport)
            .field("device", &self.device)
            .field("inode", &self.inode)
            .field("artifact_path", &"<sdist-staging-path-redacted>")
            .field("cleaned", &self.cleaned)
            .finish()
    }
}

impl StagedMacosSdistGuestV1 {
    pub fn artifact_path(&self) -> &Path {
        &self.artifact_path
    }

    pub fn transport(&self) -> &MacosSdistGuestSubmissionObservationV1 {
        &self.transport
    }

    pub fn verify_prelaunch(
        &mut self,
    ) -> Result<SdistGuestRehashObservationV1, MacosSdistGuestStagingErrorV1> {
        self.verify(SdistGuestRehashPhaseV1::Prelaunch)
    }

    pub fn verify_postrun(
        &mut self,
    ) -> Result<SdistGuestRehashObservationV1, MacosSdistGuestStagingErrorV1> {
        self.verify(SdistGuestRehashPhaseV1::Postrun)
    }

    pub fn cleanup(&mut self) -> Result<(), MacosSdistGuestStagingErrorV1> {
        if self.cleaned {
            return Ok(());
        }
        drop(self.artifact_file.take());
        let mut failed = false;
        if let Err(error) = fs::remove_file(&self.artifact_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                failed = true;
            }
        }
        if let Err(error) = fs::remove_dir(&self.directory) {
            if error.kind() != std::io::ErrorKind::NotFound {
                failed = true;
            }
        }
        if fs::symlink_metadata(&self.directory).is_ok() {
            failed = true;
        }
        if failed {
            return Err(MacosSdistGuestStagingErrorV1::CleanupFailed);
        }
        self.cleaned = true;
        Ok(())
    }

    fn verify(
        &mut self,
        phase: SdistGuestRehashPhaseV1,
    ) -> Result<SdistGuestRehashObservationV1, MacosSdistGuestStagingErrorV1> {
        let artifact_file = self
            .artifact_file
            .as_mut()
            .ok_or(MacosSdistGuestStagingErrorV1::VerificationFailed)?;
        let descriptor_metadata = artifact_file
            .metadata()
            .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
        let path_metadata = fs::symlink_metadata(&self.artifact_path)
            .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
        let expected_length = self.transport.artifact_byte_length();
        if !descriptor_metadata.file_type().is_file()
            || !path_metadata.file_type().is_file()
            || descriptor_metadata.nlink() != 1
            || path_metadata.nlink() != 1
            || descriptor_metadata.uid() != self.supervisor_uid
            || path_metadata.uid() != self.supervisor_uid
            || descriptor_metadata.mode() & 0o777 != 0o444
            || path_metadata.mode() & 0o777 != 0o444
            || descriptor_metadata.len() != expected_length
            || path_metadata.len() != expected_length
            || descriptor_metadata.dev() != self.device
            || path_metadata.dev() != self.device
            || descriptor_metadata.ino() != self.inode
            || path_metadata.ino() != self.inode
        {
            return Err(MacosSdistGuestStagingErrorV1::VerificationFailed);
        }
        artifact_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
        let (digest, length) = hash_sdist_reader_v1(artifact_file)?;
        artifact_file
            .seek(SeekFrom::Start(0))
            .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
        if digest != *self.transport.artifact_sha256() || length != expected_length {
            return Err(MacosSdistGuestStagingErrorV1::VerificationFailed);
        }
        Ok(SdistGuestRehashObservationV1 {
            phase,
            artifact_sha256: digest,
            artifact_byte_length: length,
            device: self.device,
            inode: self.inode,
        })
    }
}

impl Drop for StagedMacosSdistGuestV1 {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

pub fn stage_macos_sdist_guest_submission_v1<R: Read>(
    reader: &mut R,
    policy: &MacosSdistGuestStagingPolicyV1,
) -> Result<StagedMacosSdistGuestV1, MacosSdistGuestStagingErrorV1> {
    policy.validate_root()?;
    let directory = create_sdist_staging_directory_v1(policy)?;
    let artifact_path = directory.join("artifact.sdist");
    let result = stage_sdist_into_directory_v1(reader, policy, &directory, &artifact_path);
    if result.is_err() {
        let _ = fs::remove_file(&artifact_path);
        let _ = fs::remove_dir(&directory);
    }
    result
}

fn create_sdist_staging_directory_v1(
    policy: &MacosSdistGuestStagingPolicyV1,
) -> Result<PathBuf, MacosSdistGuestStagingErrorV1> {
    for _ in 0..8 {
        let mut random = [0_u8; 16];
        getrandom::fill(&mut random)
            .map_err(|_| MacosSdistGuestStagingErrorV1::EntropyUnavailable)?;
        let mut name = String::from("sdist-scenario-");
        for byte in random {
            use std::fmt::Write as _;
            write!(&mut name, "{byte:02x}")
                .map_err(|_| MacosSdistGuestStagingErrorV1::EntropyUnavailable)?;
        }
        let directory = policy.staging_root.join(name);
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&directory) {
            Ok(()) => {
                let metadata = fs::symlink_metadata(&directory)
                    .map_err(|_| MacosSdistGuestStagingErrorV1::CreateFailed)?;
                if !metadata.file_type().is_dir()
                    || metadata.uid() != policy.supervisor_uid
                    || metadata.mode() & 0o777 != 0o700
                {
                    let _ = fs::remove_dir(&directory);
                    return Err(MacosSdistGuestStagingErrorV1::CreateFailed);
                }
                return Ok(directory);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(MacosSdistGuestStagingErrorV1::CreateFailed),
        }
    }
    Err(MacosSdistGuestStagingErrorV1::CreateFailed)
}

fn stage_sdist_into_directory_v1<R: Read>(
    reader: &mut R,
    policy: &MacosSdistGuestStagingPolicyV1,
    directory: &Path,
    artifact_path: &Path,
) -> Result<StagedMacosSdistGuestV1, MacosSdistGuestStagingErrorV1> {
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(artifact_path)
        .map_err(|_| MacosSdistGuestStagingErrorV1::CreateFailed)?;
    let transport = stream_macos_sdist_guest_submission_v1(reader, &mut writer)?;
    writer
        .sync_all()
        .map_err(|_| MacosSdistGuestStagingErrorV1::SyncFailed)?;
    let metadata = writer
        .metadata()
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != policy.supervisor_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() != transport.artifact_byte_length()
    {
        return Err(MacosSdistGuestStagingErrorV1::VerificationFailed);
    }
    writer
        .set_permissions(fs::Permissions::from_mode(0o444))
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    writer
        .sync_all()
        .map_err(|_| MacosSdistGuestStagingErrorV1::SyncFailed)?;
    drop(writer);
    fs::set_permissions(directory, fs::Permissions::from_mode(0o711))
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;

    let mut artifact_file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(artifact_path)
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    let metadata = artifact_file
        .metadata()
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    let path_metadata = fs::symlink_metadata(artifact_path)
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != policy.supervisor_uid
        || path_metadata.uid() != policy.supervisor_uid
        || metadata.nlink() != 1
        || path_metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o444
        || path_metadata.mode() & 0o777 != 0o444
        || metadata.len() != transport.artifact_byte_length()
        || path_metadata.len() != transport.artifact_byte_length()
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err(MacosSdistGuestStagingErrorV1::VerificationFailed);
    }
    let (digest, length) = hash_sdist_reader_v1(&mut artifact_file)?;
    artifact_file
        .seek(SeekFrom::Start(0))
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    if digest != *transport.artifact_sha256() || length != transport.artifact_byte_length() {
        return Err(MacosSdistGuestStagingErrorV1::VerificationFailed);
    }
    Ok(StagedMacosSdistGuestV1 {
        directory: directory.to_path_buf(),
        artifact_path: artifact_path.to_path_buf(),
        artifact_file: Some(artifact_file),
        transport,
        supervisor_uid: policy.supervisor_uid,
        device: metadata.dev(),
        inode: metadata.ino(),
        cleaned: false,
    })
}

fn hash_sdist_reader_v1<R: Read>(
    reader: &mut R,
) -> Result<(Sha256Digest, u64), MacosSdistGuestStagingErrorV1> {
    let mut hasher = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader
            .read(&mut buffer)
            .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        length = length
            .checked_add(count as u64)
            .ok_or(MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    }
    let raw: [u8; 32] = hasher.finalize().into();
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    }
    let digest = Sha256Digest::parse(value)
        .map_err(|_| MacosSdistGuestStagingErrorV1::VerificationFailed)?;
    Ok((digest, length))
}
