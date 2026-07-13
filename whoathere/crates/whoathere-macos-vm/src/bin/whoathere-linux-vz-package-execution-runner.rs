#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt};
#[cfg(target_os = "linux")]
use whoathere_artifact::Sha256Digest;
#[cfg(target_os = "linux")]
use whoathere_macos_vm::{
    structurally_decode_macos_linux_vz_package_execution_request_v1,
    MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_REQUEST_BYTES_V1,
};
#[cfg(target_os = "linux")]
use zeroize::Zeroize;

#[cfg(target_os = "linux")]
const PACKAGE_UID: u32 = 65_534;
#[cfg(target_os = "linux")]
const PACKAGE_GID: u32 = 65_534;
#[cfg(target_os = "linux")]
const REQUEST_FD: RawFd = 3;
#[cfg(target_os = "linux")]
const ARTIFACT_FD: RawFd = 4;

const QUALIFICATION_REPORT: &[u8] =
    b"{\"execution_authority\":false,\"package_execution\":false,\"schema_version\":\"whoathere.linux_vz_package_execution_runner_probe.v1\",\"status\":\"closed_runner_candidate_nonexecuting_probe\",\"sync_back\":false}\n";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RunnerError {
    Usage,
    #[cfg(not(target_os = "linux"))]
    UnsupportedPlatform,
    #[cfg(target_os = "linux")]
    PrivilegeBoundary,
    #[cfg(target_os = "linux")]
    ParentBoundary,
    #[cfg(target_os = "linux")]
    DescriptorBoundary,
    #[cfg(target_os = "linux")]
    RequestInvalid,
    #[cfg(target_os = "linux")]
    ArtifactInvalid,
    Output,
}

impl RunnerError {
    const fn reason_code(self) -> &'static str {
        match self {
            Self::Usage => "package_execution_runner_usage_invalid",
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => "package_execution_runner_platform_unsupported",
            #[cfg(target_os = "linux")]
            Self::PrivilegeBoundary => "package_execution_runner_privilege_boundary_invalid",
            #[cfg(target_os = "linux")]
            Self::ParentBoundary => "package_execution_runner_parent_boundary_invalid",
            #[cfg(target_os = "linux")]
            Self::DescriptorBoundary => "package_execution_runner_descriptor_boundary_invalid",
            #[cfg(target_os = "linux")]
            Self::RequestInvalid => "package_execution_runner_request_invalid",
            #[cfg(target_os = "linux")]
            Self::ArtifactInvalid => "package_execution_runner_artifact_invalid",
            Self::Output => "package_execution_runner_output_failed",
        }
    }

    const fn exit_code(self) -> i32 {
        match self {
            Self::Usage => 64,
            #[cfg(not(target_os = "linux"))]
            Self::UnsupportedPlatform => 69,
            #[cfg(target_os = "linux")]
            Self::PrivilegeBoundary | Self::ParentBoundary | Self::DescriptorBoundary => 77,
            #[cfg(target_os = "linux")]
            Self::RequestInvalid | Self::ArtifactInvalid => 65,
            Self::Output => 74,
        }
    }
}

fn main() {
    let result = run();
    if let Err(error) = result {
        let _ = writeln!(std::io::stderr(), "{}", error.reason_code());
        std::process::exit(error.exit_code());
    }
}

fn run() -> Result<(), RunnerError> {
    let args = std::env::args_os().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err(RunnerError::Usage);
    }
    match args[1].to_str() {
        Some("--qualification-probe") => std::io::stdout()
            .write_all(QUALIFICATION_REPORT)
            .map_err(|_| RunnerError::Output),
        Some("--protected-request-validate") => validate_protected_request(),
        _ => Err(RunnerError::Usage),
    }
}

#[cfg(target_os = "linux")]
fn validate_protected_request() -> Result<(), RunnerError> {
    establish_process_boundary()?;
    let request_file = take_protected_descriptor(REQUEST_FD, DescriptorKind::PipeOrSocket)?;
    let artifact_file = take_protected_descriptor(ARTIFACT_FD, DescriptorKind::RootOwnedArtifact)?;
    close_unexpected_descriptors()?;

    let mut request_bytes = read_bounded_request(request_file)?;
    let request = structurally_decode_macos_linux_vz_package_execution_request_v1(&request_bytes)
        .map_err(|_| RunnerError::RequestInvalid)?;
    let artifact_sha256 = hash_exact_artifact(artifact_file, request.artifact_byte_length())?;
    if &artifact_sha256 != request.artifact_sha256() {
        request_bytes.zeroize();
        return Err(RunnerError::ArtifactInvalid);
    }
    request_bytes.zeroize();

    let report = serde_json_canonicalizer::to_vec(&serde_json::json!({
        "artifact_rehashed": true,
        "execution_authority": false,
        "execution_request_sha256": request.request_sha256(),
        "operation": request.operation().operation_name(),
        "package_execution": false,
        "request_structurally_validated": true,
        "schema_version": "whoathere.linux_vz_package_execution_runner_validation.v1",
        "status": "closed_request_and_artifact_validated_no_execution",
        "sync_back": false,
    }))
    .map_err(|_| RunnerError::Output)?;
    std::io::stdout()
        .write_all(&report)
        .and_then(|_| std::io::stdout().write_all(b"\n"))
        .map_err(|_| RunnerError::Output)
}

#[cfg(not(target_os = "linux"))]
fn validate_protected_request() -> Result<(), RunnerError> {
    Err(RunnerError::UnsupportedPlatform)
}

#[cfg(target_os = "linux")]
fn establish_process_boundary() -> Result<(), RunnerError> {
    if unsafe { libc::getuid() } != PACKAGE_UID || unsafe { libc::getgid() } != PACKAGE_GID {
        return Err(RunnerError::PrivilegeBoundary);
    }
    let mut groups = [0_u32; 2];
    let count = unsafe { libc::getgroups(groups.len() as i32, groups.as_mut_ptr().cast()) };
    if count != 1 || groups[0] != PACKAGE_GID {
        return Err(RunnerError::PrivilegeBoundary);
    }
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0
        || unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
    {
        return Err(RunnerError::PrivilegeBoundary);
    }
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(RunnerError::ParentBoundary);
    }
    let status = std::fs::read_to_string(format!("/proc/{parent}/status"))
        .map_err(|_| RunnerError::ParentBoundary)?;
    if !parent_status_is_root(&status) {
        return Err(RunnerError::ParentBoundary);
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
fn parent_status_is_root(status: &str) -> bool {
    let uid_root = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .is_some_and(|line| numeric_status_values(line).as_deref() == Some(&[0, 0, 0, 0]));
    let gid_root = status
        .lines()
        .find(|line| line.starts_with("Gid:"))
        .is_some_and(|line| numeric_status_values(line).as_deref() == Some(&[0, 0, 0, 0]));
    uid_root && gid_root
}

#[cfg(any(target_os = "linux", test))]
fn numeric_status_values(line: &str) -> Option<Vec<u32>> {
    let values = line
        .split_ascii_whitespace()
        .skip(1)
        .map(str::parse::<u32>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (values.len() == 4).then_some(values)
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DescriptorKind {
    PipeOrSocket,
    RootOwnedArtifact,
}

#[cfg(target_os = "linux")]
fn take_protected_descriptor(fd: RawFd, kind: DescriptorKind) -> Result<File, RunnerError> {
    let access_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if access_flags < 0 || access_flags & libc::O_ACCMODE != libc::O_RDONLY {
        return Err(RunnerError::DescriptorBoundary);
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        return Err(RunnerError::DescriptorBoundary);
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file
        .metadata()
        .map_err(|_| RunnerError::DescriptorBoundary)?;
    let valid = match kind {
        DescriptorKind::PipeOrSocket => {
            metadata.file_type().is_fifo() || metadata.file_type().is_socket()
        }
        DescriptorKind::RootOwnedArtifact => {
            metadata.file_type().is_file()
                && metadata.uid() == 0
                && metadata.gid() == 0
                && metadata.mode() & 0o7777 == 0o444
                && metadata.nlink() == 1
        }
    };
    if !valid {
        return Err(RunnerError::DescriptorBoundary);
    }
    Ok(file)
}

#[cfg(target_os = "linux")]
fn close_unexpected_descriptors() -> Result<(), RunnerError> {
    if unsafe { libc::syscall(libc::SYS_close_range, 5_u32, u32::MAX, 0_u32) } != 0 {
        return Err(RunnerError::DescriptorBoundary);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_bounded_request(file: File) -> Result<Vec<u8>, RunnerError> {
    let mut bytes = Vec::new();
    file.take((MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_REQUEST_BYTES_V1 + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| RunnerError::RequestInvalid)?;
    if bytes.is_empty() || bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_REQUEST_BYTES_V1 {
        bytes.zeroize();
        return Err(RunnerError::RequestInvalid);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
fn hash_exact_artifact(mut file: File, expected_length: u64) -> Result<Sha256Digest, RunnerError> {
    let metadata = file.metadata().map_err(|_| RunnerError::ArtifactInvalid)?;
    if metadata.len() != expected_length {
        return Err(RunnerError::ArtifactInvalid);
    }
    let mut hasher = Sha256::new();
    let mut remaining = expected_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| RunnerError::ArtifactInvalid)?;
        let count = file
            .read(&mut buffer[..requested])
            .map_err(|_| RunnerError::ArtifactInvalid)?;
        if count == 0 {
            return Err(RunnerError::ArtifactInvalid);
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| RunnerError::ArtifactInvalid)?
        != 0
    {
        return Err(RunnerError::ArtifactInvalid);
    }
    let digest = hasher.finalize();
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Sha256Digest::parse(text).map_err(|_| RunnerError::ArtifactInvalid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_parent_status_requires_all_real_effective_saved_and_fs_ids() {
        assert!(parent_status_is_root(
            "Name:\tsensor\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n"
        ));
        assert!(!parent_status_is_root(
            "Name:\tpackage\nUid:\t65534\t65534\t65534\t65534\nGid:\t65534\t65534\t65534\t65534\n"
        ));
        assert!(!parent_status_is_root(
            "Name:\tmixed\nUid:\t0\t0\t1000\t0\nGid:\t0\t0\t0\t0\n"
        ));
        assert!(!parent_status_is_root("Name:\tmissing\nUid:\t0\t0\t0\t0\n"));
    }

    #[test]
    fn probe_is_fixed_false_authority_canonical_report() {
        let value: serde_json::Value =
            serde_json::from_slice(QUALIFICATION_REPORT).expect("probe JSON");
        assert_eq!(value["execution_authority"], false);
        assert_eq!(value["package_execution"], false);
        assert_eq!(value["sync_back"], false);
        let mut expected = serde_json_canonicalizer::to_vec(&value).expect("canonical probe");
        expected.push(b'\n');
        assert_eq!(expected, QUALIFICATION_REPORT);
    }
}
