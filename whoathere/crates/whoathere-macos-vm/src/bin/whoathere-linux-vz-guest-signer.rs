#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("whoathere_linux_vz_guest_signer_requires_linux");
    std::process::exit(69);
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = linux::run() {
        eprintln!("WHOATHERE_GUEST_SIGNER_FAILED reason={error}");
        std::process::exit(70);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use serde_json::Value;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Write};
    use std::mem::{size_of, zeroed};
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::Path;
    use std::process::{Command, Stdio};
    use whoathere_artifact::Sha256Digest;
    use whoathere_macos_vm::{
        decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1,
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1,
        decode_linux_vz_drop_evidence_from_serial_v1,
        decode_linux_vz_fanotify_overflow_evidence_from_serial_v1,
        decode_linux_vz_file_evidence_from_serial_v1, decode_linux_vz_guest_signer_request_v1,
        decode_linux_vz_host_frame_overflow_guest_evidence_from_serial_v1,
        decode_linux_vz_network_evidence_from_serial_v1,
        decode_linux_vz_process_evidence_from_serial_v1,
        decode_linux_vz_teardown_evidence_from_serial_v1, encode_linux_vz_guest_signer_response_v1,
        expected_terminal_for_case_v1, sign_macos_linux_vz_telemetry_guest_receipt_v1,
        LinuxVzTelemetryConformanceCaseV1, MAX_LINUX_VZ_DROP_EVIDENCE_PAYLOAD_BYTES_V1,
        MAX_LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_BYTES_V1,
        MAX_LINUX_VZ_FILE_EVIDENCE_PAYLOAD_BYTES_V1,
        MAX_LINUX_VZ_GUEST_SIGNER_REQUEST_FRAME_BYTES_V1,
        MAX_LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_BYTES_V1,
        MAX_LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_BYTES_V1,
        MAX_LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_BYTES_V1,
        MAX_LINUX_VZ_TEARDOWN_EVIDENCE_PAYLOAD_BYTES_V1,
    };
    use zeroize::Zeroize;

    const GUEST_SIGNER_PORT: u32 = 40_551;
    const SEED_PATH: &str = "/whoathere/guest-ed25519.seed";
    const SENSOR_PATH: &str = "/whoathere/process-sensor-probe";
    const FIXTURE_PATH: &str = "/whoathere/process-fixture-child";
    const FIXTURE_BUNDLE_PATH: &str = "/whoathere/process-fixture-bundle.json";
    const DYNAMIC_DRIVER_PATH: &str = "/whoathere/dynamic-library-driver";
    const DYNAMIC_LIBRARY_PATH: &str = "/whoathere/dynamic-fixture-library.so";
    const MAX_EXECUTABLE_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_SENSOR_EVIDENCE_BYTES: usize = {
        let file_or_process = if MAX_LINUX_VZ_FILE_EVIDENCE_PAYLOAD_BYTES_V1
            > MAX_LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_BYTES_V1
        {
            MAX_LINUX_VZ_FILE_EVIDENCE_PAYLOAD_BYTES_V1
        } else {
            MAX_LINUX_VZ_PROCESS_EVIDENCE_PAYLOAD_BYTES_V1
        };
        let including_drop = if MAX_LINUX_VZ_DROP_EVIDENCE_PAYLOAD_BYTES_V1 > file_or_process {
            MAX_LINUX_VZ_DROP_EVIDENCE_PAYLOAD_BYTES_V1
        } else {
            file_or_process
        };
        let including_fanotify =
            if MAX_LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_BYTES_V1 > including_drop {
                MAX_LINUX_VZ_FANOTIFY_OVERFLOW_EVIDENCE_PAYLOAD_BYTES_V1
            } else {
                including_drop
            };
        let including_host_frame =
            if MAX_LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_BYTES_V1 > including_fanotify
            {
                MAX_LINUX_VZ_HOST_FRAME_OVERFLOW_GUEST_EVIDENCE_PAYLOAD_BYTES_V1
            } else {
                including_fanotify
            };
        if MAX_LINUX_VZ_TEARDOWN_EVIDENCE_PAYLOAD_BYTES_V1 > including_host_frame {
            MAX_LINUX_VZ_TEARDOWN_EVIDENCE_PAYLOAD_BYTES_V1
        } else {
            including_host_frame
        }
    };
    const MAX_SENSOR_OUTPUT_BYTES: u64 =
        if MAX_LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_BYTES_V1 > MAX_SENSOR_EVIDENCE_BYTES {
            MAX_LINUX_VZ_NETWORK_EVIDENCE_PAYLOAD_BYTES_V1 as u64 + 32 * 1024
        } else {
            MAX_SENSOR_EVIDENCE_BYTES as u64 + 32 * 1024
        };

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
            return Err("guest_signer_not_root".into());
        }
        let listener = VsockListener::bind_one_shot(GUEST_SIGNER_PORT)?;
        println!("WHOATHERE_GUEST_SIGNER_READY port={GUEST_SIGNER_PORT}");
        let mut stream = listener.accept_host()?;
        let mut request_bytes = Vec::new();
        Read::by_ref(&mut stream)
            .take(MAX_LINUX_VZ_GUEST_SIGNER_REQUEST_FRAME_BYTES_V1 as u64 + 1)
            .read_to_end(&mut request_bytes)?;
        if request_bytes.len() > MAX_LINUX_VZ_GUEST_SIGNER_REQUEST_FRAME_BYTES_V1 {
            return Err("guest_signer_request_limit_exceeded".into());
        }
        let request = decode_linux_vz_guest_signer_request_v1(&request_bytes)?;
        let run_spec = decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(
            request.run_spec(),
        )?;
        if !matches!(
            run_spec.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::ForkExecExit
                | LinuxVzTelemetryConformanceCaseV1::Reparenting
                | LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization
                | LinuxVzTelemetryConformanceCaseV1::SetsidEscape
                | LinuxVzTelemetryConformanceCaseV1::CredentialChange
                | LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad
                | LinuxVzTelemetryConformanceCaseV1::Ipv4Connect
                | LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
                | LinuxVzTelemetryConformanceCaseV1::UdpSend
                | LinuxVzTelemetryConformanceCaseV1::LoopbackConnect
                | LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect
                | LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect
                | LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect
                | LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect
                | LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
                | LinuxVzTelemetryConformanceCaseV1::DnsMalformed
                | LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect
                | LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
                | LinuxVzTelemetryConformanceCaseV1::MmapAccess
                | LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure
                | LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow
                | LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow
                | LinuxVzTelemetryConformanceCaseV1::NormalExit
                | LinuxVzTelemetryConformanceCaseV1::Timeout
                | LinuxVzTelemetryConformanceCaseV1::TermResistance
                | LinuxVzTelemetryConformanceCaseV1::EscapedSession
                | LinuxVzTelemetryConformanceCaseV1::ReparentedChild
                | LinuxVzTelemetryConformanceCaseV1::BackgroundListener
                | LinuxVzTelemetryConformanceCaseV1::VmStop
        ) || run_spec.expected_terminal()
            != expected_terminal_for_case_v1(run_spec.fixture_case())
            || run_spec.package_execution_authority_permitted()
        {
            return Err("guest_signer_run_spec_not_supported_inert_case".into());
        }
        let backend = run_spec.backend_identity();
        let challenge = decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
            request.challenge(),
            &run_spec,
            backend,
        )?;

        require_self_digest(backend.guest_sensor_sha256())?;
        require_digest(SENSOR_PATH, backend.guest_bpf_bundle_sha256())?;
        require_fixture_bundle(backend.guest_runner_sha256())?;

        let fixture_case_argument = match run_spec.fixture_case() {
            LinuxVzTelemetryConformanceCaseV1::ForkExecExit => "fork_exec_exit",
            LinuxVzTelemetryConformanceCaseV1::Reparenting => "reparenting",
            LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization => {
                "double_fork_daemonization"
            }
            LinuxVzTelemetryConformanceCaseV1::SetsidEscape => "setsid_escape",
            LinuxVzTelemetryConformanceCaseV1::CredentialChange => "credential_change",
            LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad => "dynamic_library_load",
            LinuxVzTelemetryConformanceCaseV1::Ipv4Connect => "ipv4_connect",
            LinuxVzTelemetryConformanceCaseV1::Ipv6Connect => "ipv6_connect",
            LinuxVzTelemetryConformanceCaseV1::UdpSend => "udp_send",
            LinuxVzTelemetryConformanceCaseV1::LoopbackConnect => "loopback_connect",
            LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect => "private_address_connect",
            LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect => "link_local_connect",
            LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect => "metadata_address_connect",
            LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect => "public_address_connect",
            LinuxVzTelemetryConformanceCaseV1::DnsPlaintext => "dns_plaintext",
            LinuxVzTelemetryConformanceCaseV1::DnsMalformed => "dns_malformed",
            LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect => "encrypted_dns_connect",
            LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete => {
                "protected_open_read_write_rename_delete"
            }
            LinuxVzTelemetryConformanceCaseV1::MmapAccess => "mmap_access",
            LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure => "bpf_reservation_failure",
            LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow => "fanotify_queue_overflow",
            LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow => "host_frame_overflow",
            LinuxVzTelemetryConformanceCaseV1::NormalExit => "normal_exit",
            LinuxVzTelemetryConformanceCaseV1::Timeout => "timeout",
            LinuxVzTelemetryConformanceCaseV1::TermResistance => "term_resistance",
            LinuxVzTelemetryConformanceCaseV1::EscapedSession => "escaped_session",
            LinuxVzTelemetryConformanceCaseV1::ReparentedChild => "reparented_child",
            LinuxVzTelemetryConformanceCaseV1::BackgroundListener => "background_listener",
            LinuxVzTelemetryConformanceCaseV1::VmStop => "vm_stop",
            _ => return Err("guest_signer_run_spec_not_supported_inert_case".into()),
        };
        let mut child = Command::new(SENSOR_PATH)
            .arg(FIXTURE_PATH)
            .arg(fixture_case_argument)
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut sensor_output = Vec::new();
        child
            .stdout
            .take()
            .ok_or("guest_signer_sensor_stdout_missing")?
            .take(MAX_SENSOR_OUTPUT_BYTES + 1)
            .read_to_end(&mut sensor_output)?;
        let status = child.wait()?;
        std::io::stdout().write_all(&sensor_output)?;
        std::io::stdout().flush()?;
        if !status.success() || sensor_output.len() as u64 > MAX_SENSOR_OUTPUT_BYTES {
            return Err("guest_signer_sensor_failed".into());
        }
        let (package_uid, package_gid, claims) = match run_spec.fixture_case() {
            LinuxVzTelemetryConformanceCaseV1::ForkExecExit
            | LinuxVzTelemetryConformanceCaseV1::Reparenting
            | LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization
            | LinuxVzTelemetryConformanceCaseV1::SetsidEscape
            | LinuxVzTelemetryConformanceCaseV1::CredentialChange
            | LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad => {
                let evidence = decode_linux_vz_process_evidence_from_serial_v1(&sensor_output)?;
                if evidence.fixture_case() != run_spec.fixture_case() {
                    return Err("guest_signer_process_case_mismatch".into());
                }
                (
                    evidence.package_uid(),
                    evidence.package_gid(),
                    evidence.guest_observation_claims_v1()?,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
            | LinuxVzTelemetryConformanceCaseV1::MmapAccess => {
                let evidence = decode_linux_vz_file_evidence_from_serial_v1(&sensor_output)?;
                if evidence.fixture_case() != run_spec.fixture_case() {
                    return Err("guest_signer_file_case_mismatch".into());
                }
                (
                    evidence.package_uid(),
                    evidence.package_gid(),
                    evidence.guest_observation_claims_v1()?,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::Ipv4Connect
            | LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
            | LinuxVzTelemetryConformanceCaseV1::UdpSend
            | LinuxVzTelemetryConformanceCaseV1::LoopbackConnect
            | LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect
            | LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
            | LinuxVzTelemetryConformanceCaseV1::DnsMalformed
            | LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect => {
                let evidence = decode_linux_vz_network_evidence_from_serial_v1(&sensor_output)?;
                if evidence.fixture_case() != run_spec.fixture_case() {
                    return Err("guest_signer_network_case_mismatch".into());
                }
                (
                    evidence.package_uid(),
                    evidence.package_gid(),
                    evidence.guest_observation_claims_v1()?,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure => {
                let evidence = decode_linux_vz_drop_evidence_from_serial_v1(&sensor_output)?;
                if evidence.fixture_case() != run_spec.fixture_case() {
                    return Err("guest_signer_drop_case_mismatch".into());
                }
                (
                    evidence.package_uid(),
                    evidence.package_gid(),
                    evidence.guest_observation_claims_v1()?,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow => {
                let evidence =
                    decode_linux_vz_fanotify_overflow_evidence_from_serial_v1(&sensor_output)?;
                if evidence.fixture_case() != run_spec.fixture_case() {
                    return Err("guest_signer_fanotify_overflow_case_mismatch".into());
                }
                (
                    evidence.package_uid(),
                    evidence.package_gid(),
                    evidence.guest_observation_claims_v1()?,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow => {
                let evidence = decode_linux_vz_host_frame_overflow_guest_evidence_from_serial_v1(
                    &sensor_output,
                )?;
                if evidence.fixture_case() != run_spec.fixture_case() {
                    return Err("guest_signer_host_frame_overflow_case_mismatch".into());
                }
                (
                    evidence.package_uid(),
                    evidence.package_gid(),
                    evidence.guest_observation_claims_v1()?,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::NormalExit
            | LinuxVzTelemetryConformanceCaseV1::Timeout
            | LinuxVzTelemetryConformanceCaseV1::TermResistance
            | LinuxVzTelemetryConformanceCaseV1::EscapedSession
            | LinuxVzTelemetryConformanceCaseV1::ReparentedChild
            | LinuxVzTelemetryConformanceCaseV1::BackgroundListener => {
                let evidence = decode_linux_vz_teardown_evidence_from_serial_v1(&sensor_output)?;
                if evidence.fixture_case() != run_spec.fixture_case() {
                    return Err("guest_signer_teardown_case_mismatch".into());
                }
                (
                    evidence.package_uid(),
                    evidence.package_gid(),
                    evidence.guest_observation_claims_v1()?,
                )
            }
            _ => return Err("guest_signer_run_spec_not_supported_inert_case".into()),
        };
        if package_uid != backend.package_uid() || package_gid != backend.package_gid() {
            return Err("guest_signer_package_identity_mismatch".into());
        }
        let seed = read_root_seed(SEED_PATH)?;
        let receipt = sign_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge, &run_spec, backend, &claims, seed,
        )?;
        let response = encode_linux_vz_guest_signer_response_v1(&receipt)?;
        stream.write_all(&response)?;
        stream.flush()?;
        unsafe {
            libc::shutdown(stream.raw_fd(), libc::SHUT_WR);
        }
        println!(
            "WHOATHERE_GUEST_SIGNER_RECEIPT_OK challenge_sha256={} receipt_sha256={}",
            challenge.challenge_sha256(),
            Sha256Digest::from_bytes(&receipt)
        );
        Ok(())
    }

    fn require_digest(
        path: &str,
        expected: &Sha256Digest,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = read_regular_nofollow(path, MAX_EXECUTABLE_BYTES)?;
        if Sha256Digest::from_bytes(&bytes) != *expected {
            return Err("guest_signer_executable_digest_mismatch".into());
        }
        Ok(())
    }

    fn require_fixture_bundle(expected: &Sha256Digest) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = read_regular_nofollow(FIXTURE_BUNDLE_PATH, 64 * 1024)?;
        if Sha256Digest::from_bytes(&bytes) != *expected {
            return Err("guest_signer_fixture_bundle_digest_mismatch".into());
        }
        let value: Value = serde_json::from_slice(&bytes)?;
        let canonical = serde_json_canonicalizer::to_vec(&value)?;
        if bytes != canonical && bytes != [canonical.as_slice(), b"\n"].concat() {
            return Err("guest_signer_fixture_bundle_noncanonical".into());
        }
        let object = value
            .as_object()
            .ok_or("guest_signer_fixture_bundle_schema")?;
        let expected_keys = [
            "dynamic_fixture_library_sha256",
            "dynamic_library_driver_sha256",
            "process_fixture_child_sha256",
            "schema_version",
        ];
        if object.len() != expected_keys.len()
            || expected_keys.iter().any(|key| !object.contains_key(*key))
            || object.get("schema_version").and_then(Value::as_str)
                != Some("whoathere.linux_vz_process_fixture_bundle.v1")
        {
            return Err("guest_signer_fixture_bundle_schema".into());
        }
        let digest = |key: &str| -> Result<Sha256Digest, Box<dyn std::error::Error>> {
            Ok(Sha256Digest::parse(
                object
                    .get(key)
                    .and_then(Value::as_str)
                    .ok_or("guest_signer_fixture_bundle_digest")?,
            )?)
        };
        require_digest(FIXTURE_PATH, &digest("process_fixture_child_sha256")?)?;
        require_digest(
            DYNAMIC_DRIVER_PATH,
            &digest("dynamic_library_driver_sha256")?,
        )?;
        require_digest(
            DYNAMIC_LIBRARY_PATH,
            &digest("dynamic_fixture_library_sha256")?,
        )?;
        Ok(())
    }

    fn require_self_digest(expected: &Sha256Digest) -> Result<(), Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.len() == 0
            || metadata.len() > MAX_EXECUTABLE_BYTES
        {
            return Err("guest_signer_self_metadata_invalid".into());
        }
        let mut value = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_EXECUTABLE_BYTES + 1)
            .read_to_end(&mut value)?;
        if value.is_empty()
            || value.len() as u64 > MAX_EXECUTABLE_BYTES
            || Sha256Digest::from_bytes(&value) != *expected
        {
            return Err("guest_signer_self_digest_mismatch".into());
        }
        Ok(())
    }

    fn read_root_seed(path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
        let path = Path::new(path);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != 0
            || metadata.gid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o600
            || metadata.len() != 32
        {
            return Err("guest_signer_seed_metadata_invalid".into());
        }
        let mut value = Vec::with_capacity(32);
        file.take(33).read_to_end(&mut value)?;
        if value.len() != 32 {
            value.zeroize();
            return Err("guest_signer_seed_length_invalid".into());
        }
        let mut seed = [0_u8; 32];
        seed.copy_from_slice(&value);
        value.zeroize();
        Ok(seed)
    }

    fn read_regular_nofollow(
        path: &str,
        maximum: u64,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
            return Err("guest_signer_input_metadata_invalid".into());
        }
        let mut value = Vec::with_capacity(metadata.len() as usize);
        file.take(maximum + 1).read_to_end(&mut value)?;
        if value.is_empty() || value.len() as u64 > maximum {
            return Err("guest_signer_input_limit_exceeded".into());
        }
        Ok(value)
    }

    struct VsockListener(RawFd);

    impl VsockListener {
        fn bind_one_shot(port: u32) -> Result<Self, Box<dyn std::error::Error>> {
            let descriptor =
                unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let listener = Self(descriptor);
            let address = libc::sockaddr_vm {
                svm_family: libc::AF_VSOCK as libc::sa_family_t,
                svm_reserved1: 0,
                svm_port: port,
                svm_cid: libc::VMADDR_CID_ANY,
                svm_zero: [0; 4],
            };
            let result = unsafe {
                libc::bind(
                    descriptor,
                    (&address as *const libc::sockaddr_vm).cast(),
                    size_of::<libc::sockaddr_vm>() as libc::socklen_t,
                )
            };
            if result != 0 || unsafe { libc::listen(descriptor, 1) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(listener)
        }

        fn accept_host(&self) -> Result<VsockStream, Box<dyn std::error::Error>> {
            let descriptor = unsafe {
                libc::accept4(
                    self.0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    libc::SOCK_CLOEXEC,
                )
            };
            if descriptor < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            let stream = VsockStream(unsafe { File::from_raw_fd(descriptor) });
            stream.require_host_peer()?;
            stream.set_timeouts()?;
            Ok(stream)
        }
    }

    impl Drop for VsockListener {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }

    struct VsockStream(File);

    impl VsockStream {
        fn raw_fd(&self) -> RawFd {
            use std::os::fd::AsRawFd;
            self.0.as_raw_fd()
        }

        fn require_host_peer(&self) -> Result<(), Box<dyn std::error::Error>> {
            let mut address: libc::sockaddr_vm = unsafe { zeroed() };
            let mut length = size_of::<libc::sockaddr_vm>() as libc::socklen_t;
            let result = unsafe {
                libc::getpeername(
                    self.raw_fd(),
                    (&mut address as *mut libc::sockaddr_vm).cast(),
                    &mut length,
                )
            };
            if result != 0
                || length as usize != size_of::<libc::sockaddr_vm>()
                || address.svm_family != libc::AF_VSOCK as libc::sa_family_t
                || address.svm_cid != libc::VMADDR_CID_HOST
            {
                return Err("guest_signer_peer_not_host".into());
            }
            Ok(())
        }

        fn set_timeouts(&self) -> Result<(), Box<dyn std::error::Error>> {
            let timeout = libc::timeval {
                tv_sec: 15,
                tv_usec: 0,
            };
            for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
                let result = unsafe {
                    libc::setsockopt(
                        self.raw_fd(),
                        libc::SOL_SOCKET,
                        option,
                        (&timeout as *const libc::timeval).cast(),
                        size_of::<libc::timeval>() as libc::socklen_t,
                    )
                };
                if result != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            Ok(())
        }
    }

    impl Read for VsockStream {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            self.0.read(buffer)
        }
    }

    impl Write for VsockStream {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.write(buffer)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            self.0.flush()
        }
    }
}
