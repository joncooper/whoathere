#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("whoathere_linux_vz_package_root_coordinator_probe_requires_linux");
    std::process::exit(69);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("WHOATHERE_PACKAGE_ROOT_COORDINATOR_FAILED reason={error}");
        std::process::exit(70);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use ed25519_dalek::SigningKey;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::fs::OpenOptions;
    use std::io::{Read, Write};
    use std::os::fd::{FromRawFd, OwnedFd, RawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::net::UnixStream;
    use std::str::FromStr;
    use std::time::Duration;
    use whoathere_artifact::Sha256Digest;
    use whoathere_macos_vm::{
        split_linux_vz_package_root_coordinator_v1, LinuxVzPackageRootCoordinatorBranchV1,
        LinuxVzPackageRootRunnerBranchV1, LinuxVzPackageRootSensorServiceBranchV1,
    };

    const SCHEMA_VERSION_V1: &str = "whoathere.linux_vz_package_root_coordinator_probe.v1";
    const MAXIMUM_PROBE_BYTES_V1: u64 = 64 * 1024 * 1024;
    const CONTROL_TIMEOUT_SECONDS_V1: u64 = 10;
    const RUNNER_PROOF_V1: &[u8] = b"whoathere-root-runner-branch-v1\n";
    const SERVICE_SEED_READ_ACK_V1: &[u8] = b"whoathere-service-seed-read-v1\n";

    #[derive(Debug)]
    struct OptionsV1 {
        seed_descriptor: RawFd,
        expected_probe_sha256: Sha256Digest,
        expected_public_key_sha256: Sha256Digest,
    }

    #[derive(Debug, Serialize)]
    struct CustodyEvidenceV1<'a> {
        ambient_capabilities: String,
        bounding_capabilities: String,
        effective_capabilities: String,
        inheritable_capabilities: String,
        malware_execution: bool,
        no_new_privileges: bool,
        open_descriptor_count: String,
        package_execution: bool,
        permitted_capabilities: String,
        probe_sha256: &'a Sha256Digest,
        ptrace_capability_present: bool,
        root_credentials_verified: bool,
        runner_control_release_bound: bool,
        runner_exit_status: String,
        runner_parent_death_signal_sigkill: bool,
        runner_pid: String,
        runner_self_dumpable: bool,
        runner_seed_descriptor_closed: bool,
        runner_thread_count: String,
        schema_version: &'static str,
        seed_byte_length: String,
        seed_pipe_exact_eof: bool,
        seed_public_key_sha256: &'a Sha256Digest,
        seed_read_after_runner_boundary_verification: bool,
        service_dumpable: bool,
        service_pid: String,
        sync_back: bool,
        tracer_absent: bool,
        unexpected_descriptor_count: String,
    }

    pub(super) fn run() -> Result<(), Box<dyn std::error::Error>> {
        let options = parse_options_v1()?;
        if unsafe { libc::getuid() } != 0
            || unsafe { libc::geteuid() } != 0
            || unsafe { libc::getgid() } != 0
            || unsafe { libc::getegid() } != 0
        {
            return Err("root_coordinator_probe_not_root".into());
        }
        let probe_sha256 = self_digest_v1()?;
        if probe_sha256 != options.expected_probe_sha256 {
            return Err("root_coordinator_probe_digest_mismatch".into());
        }
        let seed_descriptor = take_seed_descriptor_v1(options.seed_descriptor)?;
        match split_linux_vz_package_root_coordinator_v1(seed_descriptor)? {
            LinuxVzPackageRootCoordinatorBranchV1::RootRunner(branch) => run_runner_v1(branch),
            LinuxVzPackageRootCoordinatorBranchV1::SensorService(branch) => {
                run_service_v1(branch, &probe_sha256, &options.expected_public_key_sha256)
            }
        }
    }

    fn parse_options_v1() -> Result<OptionsV1, Box<dyn std::error::Error>> {
        let arguments = std::env::args().collect::<Vec<_>>();
        if arguments.len() != 7
            || arguments[1] != "--seed-fd"
            || arguments[3] != "--expected-probe-sha256"
            || arguments[5] != "--expected-public-key-sha256"
        {
            return Err("root_coordinator_probe_usage".into());
        }
        let seed_descriptor = arguments[2].parse::<RawFd>()?;
        if seed_descriptor <= libc::STDERR_FILENO || arguments[2] != seed_descriptor.to_string() {
            return Err("root_coordinator_probe_seed_fd_invalid".into());
        }
        Ok(OptionsV1 {
            seed_descriptor,
            expected_probe_sha256: Sha256Digest::from_str(&arguments[4])?,
            expected_public_key_sha256: Sha256Digest::from_str(&arguments[6])?,
        })
    }

    fn take_seed_descriptor_v1(descriptor: RawFd) -> Result<OwnedFd, Box<dyn std::error::Error>> {
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0
        {
            return Err("root_coordinator_probe_seed_fd_unavailable".into());
        }
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    fn run_runner_v1(
        branch: LinuxVzPackageRootRunnerBranchV1,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if !branch.signing_seed_descriptor_closed()
            || branch.ptrace_capability_present()
            || branch.dumpable()
            || !branch.no_new_privileges()
        {
            return Err("root_coordinator_runner_branch_invariant_failed".into());
        }
        let mut control = control_stream_v1(branch.into_control_fd_v1())?;
        control.write_all(RUNNER_PROOF_V1)?;
        control.shutdown(std::net::Shutdown::Write)?;
        let acknowledgement = read_bounded_to_eof_v1(&mut control, 128)?;
        if acknowledgement != SERVICE_SEED_READ_ACK_V1 {
            return Err("root_coordinator_service_ack_invalid".into());
        }
        Ok(())
    }

    fn run_service_v1(
        branch: LinuxVzPackageRootSensorServiceBranchV1,
        probe_sha256: &Sha256Digest,
        expected_public_key_sha256: &Sha256Digest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0
            || !branch.runner_hardening_complete()
        {
            return Err("root_coordinator_service_boundary_invalid".into());
        }
        let service_pid = branch.service_pid();
        let runner_pid = branch.runner_pid();
        let boundary = *branch.runner_custody_boundary();
        if boundary.runner_pid() != runner_pid
            || boundary.ptrace_capability_present()
            || !boundary.root_credentials_verified()
            || !boundary.tracer_absent()
            || !boundary.no_new_privileges()
            || boundary.thread_count() != 1
            || boundary.open_descriptor_count() != 4
            || boundary.unexpected_descriptor_count() != 0
            || boundary.ambient_capabilities() != 0
        {
            return Err("root_coordinator_parent_observation_invalid".into());
        }
        let (control_fd, signing_seed) = branch.into_control_and_signing_seed_v1();
        let mut control = control_stream_v1(control_fd)?;
        let runner_proof = read_bounded_to_eof_v1(&mut control, 128)?;
        if runner_proof != RUNNER_PROOF_V1 {
            return Err("root_coordinator_runner_proof_invalid".into());
        }

        let signing_seed = signing_seed.read_once_v1()?;
        let signing_key = SigningKey::from_bytes(&signing_seed);
        if signing_key.verifying_key().is_weak() {
            return Err("root_coordinator_public_key_weak".into());
        }
        let public_key_sha256 = Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes());
        drop(signing_key);
        drop(signing_seed);
        if public_key_sha256 != *expected_public_key_sha256 {
            return Err("root_coordinator_public_key_mismatch".into());
        }
        control.write_all(SERVICE_SEED_READ_ACK_V1)?;
        control.shutdown(std::net::Shutdown::Write)?;
        let runner_exit_status = wait_for_runner_v1(runner_pid)?;

        let evidence = CustodyEvidenceV1 {
            ambient_capabilities: format!("{:016x}", boundary.ambient_capabilities()),
            bounding_capabilities: format!("{:016x}", boundary.bounding_capabilities()),
            effective_capabilities: format!("{:016x}", boundary.effective_capabilities()),
            inheritable_capabilities: format!("{:016x}", boundary.inheritable_capabilities()),
            malware_execution: false,
            no_new_privileges: boundary.no_new_privileges(),
            open_descriptor_count: boundary.open_descriptor_count().to_string(),
            package_execution: false,
            permitted_capabilities: format!("{:016x}", boundary.permitted_capabilities()),
            probe_sha256,
            ptrace_capability_present: boundary.ptrace_capability_present(),
            root_credentials_verified: boundary.root_credentials_verified(),
            runner_control_release_bound: true,
            runner_exit_status: runner_exit_status.to_string(),
            runner_parent_death_signal_sigkill: true,
            runner_pid: runner_pid.to_string(),
            runner_self_dumpable: false,
            runner_seed_descriptor_closed: true,
            runner_thread_count: boundary.thread_count().to_string(),
            schema_version: SCHEMA_VERSION_V1,
            seed_byte_length: "32".to_string(),
            seed_pipe_exact_eof: true,
            seed_public_key_sha256: &public_key_sha256,
            seed_read_after_runner_boundary_verification: true,
            service_dumpable: false,
            service_pid: service_pid.to_string(),
            sync_back: false,
            tracer_absent: boundary.tracer_absent(),
            unexpected_descriptor_count: boundary.unexpected_descriptor_count().to_string(),
        };
        let canonical = serde_json_canonicalizer::to_vec(&evidence)?;
        let mut stdout = std::io::stdout().lock();
        stdout.write_all(b"WHOATHERE_PACKAGE_ROOT_COORDINATOR_EVIDENCE ")?;
        stdout.write_all(&canonical)?;
        stdout.write_all(b"\n")?;
        stdout.flush()?;
        Ok(())
    }

    fn control_stream_v1(descriptor: OwnedFd) -> Result<UnixStream, Box<dyn std::error::Error>> {
        let stream = UnixStream::from(descriptor);
        let timeout = Some(Duration::from_secs(CONTROL_TIMEOUT_SECONDS_V1));
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        Ok(stream)
    }

    fn read_bounded_to_eof_v1(
        stream: &mut UnixStream,
        maximum: usize,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut bytes = Vec::new();
        stream.take(maximum as u64 + 1).read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > maximum {
            return Err("root_coordinator_control_frame_invalid".into());
        }
        Ok(bytes)
    }

    fn wait_for_runner_v1(runner_pid: u32) -> Result<i32, Box<dyn std::error::Error>> {
        let runner_pid = libc::pid_t::try_from(runner_pid)?;
        let mut status = 0_i32;
        loop {
            let result = unsafe { libc::waitpid(runner_pid, &mut status, 0) };
            if result == runner_pid {
                break;
            }
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err("root_coordinator_runner_wait_failed".into());
        }
        if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
            return Err("root_coordinator_runner_exit_failed".into());
        }
        Ok(libc::WEXITSTATUS(status))
    }

    fn self_digest_v1() -> Result<Sha256Digest, Box<dyn std::error::Error>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.len() == 0
            || metadata.len() > MAXIMUM_PROBE_BYTES_V1
        {
            return Err("root_coordinator_probe_metadata_invalid".into());
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut remaining = metadata.len();
        while remaining > 0 {
            let requested = usize::try_from(remaining.min(buffer.len() as u64))?;
            file.read_exact(&mut buffer[..requested])?;
            hasher.update(&buffer[..requested]);
            remaining -= requested as u64;
        }
        let mut trailing = [0_u8; 1];
        if file.read(&mut trailing)? != 0 {
            return Err("root_coordinator_probe_length_changed".into());
        }
        let digest = hasher.finalize();
        let hexadecimal = digest
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        Sha256Digest::parse(format!("sha256:{hexadecimal}")).map_err(Into::into)
    }
}
