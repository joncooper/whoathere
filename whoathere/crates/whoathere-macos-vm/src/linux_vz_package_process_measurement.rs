use crate::LinuxVzPackageProcessLaunchContractV1;
#[cfg(target_os = "linux")]
use crate::LinuxVzPackageResolvedExecutableClassV1;
use serde::Serialize;
#[cfg(target_os = "linux")]
use std::ffi::CString;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::{Read, Seek, SeekFrom};
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
use whoathere_artifact::Sha256Digest;

#[cfg(target_os = "linux")]
const PACKAGE_UID_V1: u32 = 65_534;
#[cfg(target_os = "linux")]
const PACKAGE_GID_V1: u32 = 65_534;
#[cfg(target_os = "linux")]
const MAX_MEASURED_EXECUTABLE_BYTES_V1: u64 = 256 * 1024 * 1024;
#[cfg(target_os = "linux")]
const MAX_MEASURED_INPUT_BYTES_V1: u64 = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageProcessMeasurementErrorV1 {
    UnsupportedPlatform,
    PrivilegeBoundary,
    OpenFailed,
    MetadataInvalid,
    DigestMismatch,
    SealFailed,
    IdentityChanged,
    LimitExceeded,
}

impl LinuxVzPackageProcessMeasurementErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::UnsupportedPlatform => {
                "linux_vz_package_process_measurement_platform_unsupported"
            }
            Self::PrivilegeBoundary => "linux_vz_package_process_measurement_privilege_invalid",
            Self::OpenFailed => "linux_vz_package_process_measurement_open_failed",
            Self::MetadataInvalid => "linux_vz_package_process_measurement_metadata_invalid",
            Self::DigestMismatch => "linux_vz_package_process_measurement_digest_mismatch",
            Self::SealFailed => "linux_vz_package_process_measurement_seal_failed",
            Self::IdentityChanged => "linux_vz_package_process_measurement_identity_changed",
            Self::LimitExceeded => "linux_vz_package_process_measurement_limit_exceeded",
        }
    }
}

impl fmt::Display for LinuxVzPackageProcessMeasurementErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageProcessMeasurementErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzPackageProcessMeasurementPhaseV1 {
    SealedPrelaunch,
    ImmediatePreexec,
    Postrun,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageProcessFileMeasurementV1 {
    absolute_path: String,
    sha256: Sha256Digest,
    byte_length: u64,
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    link_count: u64,
}

impl LinuxVzPackageProcessFileMeasurementV1 {
    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub const fn device(&self) -> u64 {
        self.device
    }

    pub const fn inode(&self) -> u64 {
        self.inode
    }

    pub const fn uid(&self) -> u32 {
        self.uid
    }

    pub const fn gid(&self) -> u32 {
        self.gid
    }

    pub const fn mode(&self) -> u32 {
        self.mode
    }

    pub const fn link_count(&self) -> u64 {
        self.link_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageProcessMeasurementObservationV1 {
    phase: LinuxVzPackageProcessMeasurementPhaseV1,
    launch_contract_sha256: Sha256Digest,
    executable: LinuxVzPackageProcessFileMeasurementV1,
    measured_inputs: Vec<LinuxVzPackageProcessFileMeasurementV1>,
    current_directory_path: String,
    current_directory_device: u64,
    current_directory_inode: u64,
    current_directory_uid: u32,
    current_directory_gid: u32,
    current_directory_mode: u32,
}

impl LinuxVzPackageProcessMeasurementObservationV1 {
    pub const fn phase(&self) -> LinuxVzPackageProcessMeasurementPhaseV1 {
        self.phase
    }

    pub fn launch_contract_sha256(&self) -> &Sha256Digest {
        &self.launch_contract_sha256
    }

    pub fn executable(&self) -> &LinuxVzPackageProcessFileMeasurementV1 {
        &self.executable
    }

    pub fn measured_inputs(&self) -> &[LinuxVzPackageProcessFileMeasurementV1] {
        &self.measured_inputs
    }

    pub fn current_directory_path(&self) -> &str {
        &self.current_directory_path
    }

    pub const fn current_directory_device(&self) -> u64 {
        self.current_directory_device
    }

    pub const fn current_directory_inode(&self) -> u64 {
        self.current_directory_inode
    }

    pub const fn current_directory_uid(&self) -> u32 {
        self.current_directory_uid
    }

    pub const fn current_directory_gid(&self) -> u32 {
        self.current_directory_gid
    }

    pub const fn current_directory_mode(&self) -> u32 {
        self.current_directory_mode
    }
}

pub struct MeasuredLinuxVzPackageProcessV1 {
    contract_sha256: Sha256Digest,
    #[cfg(target_os = "linux")]
    executable_path: String,
    #[cfg(target_os = "linux")]
    expected_executable_sha256: Sha256Digest,
    #[cfg(target_os = "linux")]
    measured_input_paths: Vec<(String, Sha256Digest)>,
    current_directory_path: String,
    executable_measurement: LinuxVzPackageProcessFileMeasurementV1,
    measured_input_measurements: Vec<LinuxVzPackageProcessFileMeasurementV1>,
    current_directory_device: u64,
    current_directory_inode: u64,
    current_directory_uid: u32,
    current_directory_gid: u32,
    current_directory_mode: u32,
    #[cfg(target_os = "linux")]
    filesystem_root: File,
    #[cfg(target_os = "linux")]
    executable: File,
    #[cfg(target_os = "linux")]
    measured_inputs: Vec<File>,
    #[cfg(target_os = "linux")]
    current_directory: File,
}

impl fmt::Debug for MeasuredLinuxVzPackageProcessV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MeasuredLinuxVzPackageProcessV1")
            .field("contract_sha256", &self.contract_sha256)
            .field("executable", &self.executable_measurement)
            .field(
                "measured_input_count",
                &self.measured_input_measurements.len(),
            )
            .field("current_directory", &self.current_directory_path)
            .finish()
    }
}

impl MeasuredLinuxVzPackageProcessV1 {
    pub fn sealed_prelaunch_observation(&self) -> LinuxVzPackageProcessMeasurementObservationV1 {
        self.observation(LinuxVzPackageProcessMeasurementPhaseV1::SealedPrelaunch)
    }

    #[cfg(target_os = "linux")]
    pub fn verify_immediate_preexec(
        &mut self,
    ) -> Result<
        LinuxVzPackageProcessMeasurementObservationV1,
        LinuxVzPackageProcessMeasurementErrorV1,
    > {
        self.verify(LinuxVzPackageProcessMeasurementPhaseV1::ImmediatePreexec)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn verify_immediate_preexec(
        &mut self,
    ) -> Result<
        LinuxVzPackageProcessMeasurementObservationV1,
        LinuxVzPackageProcessMeasurementErrorV1,
    > {
        Err(LinuxVzPackageProcessMeasurementErrorV1::UnsupportedPlatform)
    }

    #[cfg(target_os = "linux")]
    pub fn verify_postrun(
        &mut self,
    ) -> Result<
        LinuxVzPackageProcessMeasurementObservationV1,
        LinuxVzPackageProcessMeasurementErrorV1,
    > {
        self.verify(LinuxVzPackageProcessMeasurementPhaseV1::Postrun)
    }

    #[cfg(not(target_os = "linux"))]
    pub fn verify_postrun(
        &mut self,
    ) -> Result<
        LinuxVzPackageProcessMeasurementObservationV1,
        LinuxVzPackageProcessMeasurementErrorV1,
    > {
        Err(LinuxVzPackageProcessMeasurementErrorV1::UnsupportedPlatform)
    }

    fn observation(
        &self,
        phase: LinuxVzPackageProcessMeasurementPhaseV1,
    ) -> LinuxVzPackageProcessMeasurementObservationV1 {
        LinuxVzPackageProcessMeasurementObservationV1 {
            phase,
            launch_contract_sha256: self.contract_sha256.clone(),
            executable: self.executable_measurement.clone(),
            measured_inputs: self.measured_input_measurements.clone(),
            current_directory_path: self.current_directory_path.clone(),
            current_directory_device: self.current_directory_device,
            current_directory_inode: self.current_directory_inode,
            current_directory_uid: self.current_directory_uid,
            current_directory_gid: self.current_directory_gid,
            current_directory_mode: self.current_directory_mode,
        }
    }

    #[cfg(target_os = "linux")]
    fn verify(
        &mut self,
        phase: LinuxVzPackageProcessMeasurementPhaseV1,
    ) -> Result<
        LinuxVzPackageProcessMeasurementObservationV1,
        LinuxVzPackageProcessMeasurementErrorV1,
    > {
        let executable = reopen_and_measure_v1(
            &self.filesystem_root,
            &self.executable_path,
            true,
            0,
            0,
            &self.expected_executable_sha256,
            MAX_MEASURED_EXECUTABLE_BYTES_V1,
        )?;
        require_same_measurement_v1(&self.executable_measurement, &executable.1)?;
        require_descriptor_identity_v1(&self.executable, &self.executable_measurement)?;

        let mut measured_inputs = Vec::with_capacity(self.measured_input_paths.len());
        for (((path, expected), retained), original) in self
            .measured_input_paths
            .iter()
            .zip(&self.measured_inputs)
            .zip(&self.measured_input_measurements)
        {
            let measured = reopen_and_measure_v1(
                &self.filesystem_root,
                path,
                false,
                0,
                0,
                expected,
                MAX_MEASURED_INPUT_BYTES_V1,
            )?;
            require_same_measurement_v1(original, &measured.1)?;
            require_descriptor_identity_v1(retained, original)?;
            measured_inputs.push(measured.1);
        }

        let current_directory = open_beneath_v1(
            &self.filesystem_root,
            &self.current_directory_path,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )?;
        let directory_metadata = current_directory
            .metadata()
            .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid)?;
        if directory_metadata.dev() != self.current_directory_device
            || directory_metadata.ino() != self.current_directory_inode
            || directory_metadata.uid() != self.current_directory_uid
            || directory_metadata.gid() != self.current_directory_gid
            || directory_metadata.mode() & 0o7777 != self.current_directory_mode
        {
            return Err(LinuxVzPackageProcessMeasurementErrorV1::IdentityChanged);
        }
        let retained_directory_metadata = self
            .current_directory
            .metadata()
            .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid)?;
        if retained_directory_metadata.dev() != self.current_directory_device
            || retained_directory_metadata.ino() != self.current_directory_inode
        {
            return Err(LinuxVzPackageProcessMeasurementErrorV1::IdentityChanged);
        }
        self.executable_measurement = executable.1;
        self.measured_input_measurements = measured_inputs;
        Ok(self.observation(phase))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn executable_fd_v1(&self) -> RawFd {
        self.executable.as_raw_fd()
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn current_directory_fd_v1(&self) -> RawFd {
        self.current_directory.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
pub fn measure_and_seal_linux_vz_package_process_v1(
    contract: &LinuxVzPackageProcessLaunchContractV1,
) -> Result<MeasuredLinuxVzPackageProcessV1, LinuxVzPackageProcessMeasurementErrorV1> {
    require_root_boundary_v1()?;
    let filesystem_root = open_filesystem_root_v1()?;
    if contract.executable_path() == contract.current_directory() {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid);
    }

    if contract.executable_class() != LinuxVzPackageResolvedExecutableClassV1::PinnedRootfsRuntime {
        seal_package_generated_executable_v1(
            &filesystem_root,
            contract.executable_path(),
            contract.expected_executable_sha256(),
        )?;
    }
    let (executable, executable_measurement) = reopen_and_measure_v1(
        &filesystem_root,
        contract.executable_path(),
        true,
        0,
        0,
        contract.expected_executable_sha256(),
        MAX_MEASURED_EXECUTABLE_BYTES_V1,
    )?;

    let mut measured_inputs = Vec::with_capacity(contract.measured_inputs().len());
    let mut measured_input_paths = Vec::with_capacity(contract.measured_inputs().len());
    let mut measured_input_measurements = Vec::with_capacity(contract.measured_inputs().len());
    for input in contract.measured_inputs() {
        let (file, measurement) = reopen_and_measure_v1(
            &filesystem_root,
            input.absolute_path(),
            false,
            0,
            0,
            input.expected_sha256(),
            MAX_MEASURED_INPUT_BYTES_V1,
        )?;
        measured_inputs.push(file);
        measured_input_paths.push((
            input.absolute_path().to_string(),
            input.expected_sha256().clone(),
        ));
        measured_input_measurements.push(measurement);
    }

    let current_directory = open_beneath_v1(
        &filesystem_root,
        contract.current_directory(),
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
    )?;
    let directory_metadata = current_directory
        .metadata()
        .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid)?;
    validate_current_directory_metadata_v1(&directory_metadata)?;

    Ok(MeasuredLinuxVzPackageProcessV1 {
        contract_sha256: contract.launch_contract_sha256().clone(),
        executable_path: contract.executable_path().to_string(),
        expected_executable_sha256: contract.expected_executable_sha256().clone(),
        measured_input_paths,
        current_directory_path: contract.current_directory().to_string(),
        executable_measurement,
        measured_input_measurements,
        current_directory_device: directory_metadata.dev(),
        current_directory_inode: directory_metadata.ino(),
        current_directory_uid: directory_metadata.uid(),
        current_directory_gid: directory_metadata.gid(),
        current_directory_mode: directory_metadata.mode() & 0o7777,
        filesystem_root,
        executable,
        measured_inputs,
        current_directory,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn measure_and_seal_linux_vz_package_process_v1(
    _contract: &LinuxVzPackageProcessLaunchContractV1,
) -> Result<MeasuredLinuxVzPackageProcessV1, LinuxVzPackageProcessMeasurementErrorV1> {
    Err(LinuxVzPackageProcessMeasurementErrorV1::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn require_root_boundary_v1() -> Result<(), LinuxVzPackageProcessMeasurementErrorV1> {
    if unsafe { libc::getuid() } != 0
        || unsafe { libc::geteuid() } != 0
        || unsafe { libc::getgid() } != 0
        || unsafe { libc::getegid() } != 0
    {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::PrivilegeBoundary);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_filesystem_root_v1() -> Result<File, LinuxVzPackageProcessMeasurementErrorV1> {
    let path = CString::new("/").expect("fixed root path");
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::OpenFailed);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct OpenHowV1 {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[cfg(target_os = "linux")]
fn open_beneath_v1(
    filesystem_root: &File,
    absolute_path: &str,
    flags: i32,
) -> Result<File, LinuxVzPackageProcessMeasurementErrorV1> {
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;
    const RESOLVE_BENEATH: u64 = 0x08;
    let relative = absolute_path
        .strip_prefix('/')
        .filter(|value| !value.is_empty())
        .ok_or(LinuxVzPackageProcessMeasurementErrorV1::OpenFailed)?;
    let path =
        CString::new(relative).map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::OpenFailed)?;
    let how = OpenHowV1 {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS | RESOLVE_BENEATH,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            filesystem_root.as_raw_fd(),
            path.as_ptr(),
            &how,
            std::mem::size_of::<OpenHowV1>(),
        )
    };
    if fd < 0 || fd > i32::MAX as libc::c_long {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::OpenFailed);
    }
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

#[cfg(target_os = "linux")]
fn seal_package_generated_executable_v1(
    filesystem_root: &File,
    absolute_path: &str,
    expected_sha256: &Sha256Digest,
) -> Result<(), LinuxVzPackageProcessMeasurementErrorV1> {
    let mut file = open_beneath_v1(
        filesystem_root,
        absolute_path,
        libc::O_RDWR | libc::O_CLOEXEC,
    )?;
    let metadata = file
        .metadata()
        .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != PACKAGE_UID_V1
        || metadata.gid() != PACKAGE_GID_V1
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o100 == 0
        || metadata.len() == 0
        || metadata.len() > MAX_MEASURED_EXECUTABLE_BYTES_V1
    {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid);
    }
    let digest = hash_file_exact_v1(&mut file, metadata.len())?;
    if &digest != expected_sha256 {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch);
    }
    if unsafe { libc::fchown(file.as_raw_fd(), 0, 0) } != 0
        || unsafe { libc::fchmod(file.as_raw_fd(), 0o555) } != 0
        || file.sync_all().is_err()
    {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::SealFailed);
    }
    let sealed = file
        .metadata()
        .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::SealFailed)?;
    if sealed.uid() != 0
        || sealed.gid() != 0
        || sealed.nlink() != 1
        || sealed.mode() & 0o7777 != 0o555
        || sealed.dev() != metadata.dev()
        || sealed.ino() != metadata.ino()
        || sealed.len() != metadata.len()
    {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::SealFailed);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reopen_and_measure_v1(
    filesystem_root: &File,
    absolute_path: &str,
    executable: bool,
    expected_uid: u32,
    expected_gid: u32,
    expected_sha256: &Sha256Digest,
    maximum_bytes: u64,
) -> Result<(File, LinuxVzPackageProcessFileMeasurementV1), LinuxVzPackageProcessMeasurementErrorV1>
{
    let mut file = open_beneath_v1(
        filesystem_root,
        absolute_path,
        libc::O_RDONLY | libc::O_CLOEXEC,
    )?;
    let metadata = file
        .metadata()
        .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid)?;
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.gid() != expected_gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || (executable && metadata.mode() & 0o111 == 0)
        || metadata.len() == 0
        || metadata.len() > maximum_bytes
    {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid);
    }
    let digest = hash_file_exact_v1(&mut file, metadata.len())?;
    if &digest != expected_sha256 {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch);
    }
    Ok((
        file,
        LinuxVzPackageProcessFileMeasurementV1 {
            absolute_path: absolute_path.to_string(),
            sha256: digest,
            byte_length: metadata.len(),
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode() & 0o7777,
            link_count: metadata.nlink(),
        },
    ))
}

#[cfg(target_os = "linux")]
fn hash_file_exact_v1(
    file: &mut File,
    length: u64,
) -> Result<Sha256Digest, LinuxVzPackageProcessMeasurementErrorV1> {
    use sha2::{Digest, Sha256};

    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch)?;
    let mut hasher = Sha256::new();
    let mut remaining = length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::LimitExceeded)?;
        let count = file
            .read(&mut buffer[..requested])
            .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch)?;
        if count == 0 {
            return Err(LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch);
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch)?
        != 0
    {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch)?;
    digest_result_v1(hasher.finalize().as_slice())
}

#[cfg(target_os = "linux")]
fn digest_result_v1(
    digest: &[u8],
) -> Result<Sha256Digest, LinuxVzPackageProcessMeasurementErrorV1> {
    if digest.len() != 32 {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch);
    }
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Sha256Digest::parse(value).map_err(|_| LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch)
}

#[cfg(target_os = "linux")]
fn validate_current_directory_metadata_v1(
    metadata: &std::fs::Metadata,
) -> Result<(), LinuxVzPackageProcessMeasurementErrorV1> {
    let root_owned = metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o022 == 0
        && metadata.mode() & 0o001 != 0;
    let package_owned = metadata.uid() == PACKAGE_UID_V1
        && metadata.gid() == PACKAGE_GID_V1
        && metadata.mode() & 0o077 == 0
        && metadata.mode() & 0o100 != 0;
    if !metadata.file_type().is_dir() || (!root_owned && !package_owned) {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_same_measurement_v1(
    expected: &LinuxVzPackageProcessFileMeasurementV1,
    observed: &LinuxVzPackageProcessFileMeasurementV1,
) -> Result<(), LinuxVzPackageProcessMeasurementErrorV1> {
    if expected != observed {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::IdentityChanged);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_descriptor_identity_v1(
    file: &File,
    expected: &LinuxVzPackageProcessFileMeasurementV1,
) -> Result<(), LinuxVzPackageProcessMeasurementErrorV1> {
    let mut stat = MaybeUninit::<libc::stat>::uninit();
    if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid);
    }
    let stat = unsafe { stat.assume_init() };
    if stat.st_dev != expected.device
        || stat.st_ino != expected.inode
        || stat.st_nlink as u64 != expected.link_count
        || stat.st_uid != expected.uid
        || stat.st_gid != expected.gid
        || stat.st_mode & 0o7777 != expected.mode
        || stat.st_size < 0
        || stat.st_size as u64 != expected.byte_length
    {
        return Err(LinuxVzPackageProcessMeasurementErrorV1::IdentityChanged);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn measurement_errors_have_stable_distinct_reason_codes() {
        let reasons = [
            LinuxVzPackageProcessMeasurementErrorV1::UnsupportedPlatform,
            LinuxVzPackageProcessMeasurementErrorV1::PrivilegeBoundary,
            LinuxVzPackageProcessMeasurementErrorV1::OpenFailed,
            LinuxVzPackageProcessMeasurementErrorV1::MetadataInvalid,
            LinuxVzPackageProcessMeasurementErrorV1::DigestMismatch,
            LinuxVzPackageProcessMeasurementErrorV1::SealFailed,
            LinuxVzPackageProcessMeasurementErrorV1::IdentityChanged,
            LinuxVzPackageProcessMeasurementErrorV1::LimitExceeded,
        ]
        .map(LinuxVzPackageProcessMeasurementErrorV1::reason_code);
        let unique = reasons
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), reasons.len());
    }
}
