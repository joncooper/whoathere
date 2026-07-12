use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    encode_linux_vz_guest_signer_request_v1, LinuxVzTelemetryConformanceCaseV1,
    MacosLinuxVzTelemetryConformanceChallengeV1,
};
use zeroize::Zeroize;

const MAX_IDENTITY_BYTES: u64 = 256 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ conformance request build failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 6 || !arguments[1].starts_with('/') || !arguments[5].starts_with('/') {
        return Err(
            "usage: request-build BACKEND_IDENTITY FIXTURE_CASE CONFORMANCE_RUN_ID EVIDENCE_ID OUTPUT_DIR".into(),
        );
    }
    let fixture_case = match arguments[2].as_str() {
        "fork_exec_exit" => LinuxVzTelemetryConformanceCaseV1::ForkExecExit,
        "reparenting" => LinuxVzTelemetryConformanceCaseV1::Reparenting,
        "double_fork_daemonization" => LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization,
        "setsid_escape" => LinuxVzTelemetryConformanceCaseV1::SetsidEscape,
        "credential_change" => LinuxVzTelemetryConformanceCaseV1::CredentialChange,
        "dynamic_library_load" => LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad,
        "ipv4_connect" => LinuxVzTelemetryConformanceCaseV1::Ipv4Connect,
        "ipv6_connect" => LinuxVzTelemetryConformanceCaseV1::Ipv6Connect,
        "udp_send" => LinuxVzTelemetryConformanceCaseV1::UdpSend,
        "loopback_connect" => LinuxVzTelemetryConformanceCaseV1::LoopbackConnect,
        "private_address_connect" => LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect,
        "link_local_connect" => LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect,
        "metadata_address_connect" => LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect,
        "public_address_connect" => LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect,
        "dns_plaintext" => LinuxVzTelemetryConformanceCaseV1::DnsPlaintext,
        "dns_malformed" => LinuxVzTelemetryConformanceCaseV1::DnsMalformed,
        "encrypted_dns_connect" => LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect,
        "protected_open_read_write_rename_delete" => {
            LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
        }
        "mmap_access" => LinuxVzTelemetryConformanceCaseV1::MmapAccess,
        "bpf_reservation_failure" => LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure,
        "fanotify_queue_overflow" => LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow,
        "host_frame_overflow" => LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow,
        "normal_exit" => LinuxVzTelemetryConformanceCaseV1::NormalExit,
        "timeout" => LinuxVzTelemetryConformanceCaseV1::Timeout,
        "term_resistance" => LinuxVzTelemetryConformanceCaseV1::TermResistance,
        "escaped_session" => LinuxVzTelemetryConformanceCaseV1::EscapedSession,
        "reparented_child" => LinuxVzTelemetryConformanceCaseV1::ReparentedChild,
        _ => return Err("request builder fixture case is not implemented".into()),
    };
    let output_directory = Path::new(&arguments[5]);
    validate_output_directory(output_directory)?;

    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let identity_bytes = read_bounded(&arguments[1], MAX_IDENTITY_BYTES)?;
    let backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &identity_bytes,
        &requirements,
    )?;
    let run_spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        &arguments[3],
        &arguments[4],
        fixture_case,
        &requirements,
        &backend,
    )?;

    let mut nonce = [0_u8; 32];
    let mut clone_random = [0_u8; 32];
    getrandom::fill(&mut nonce)?;
    getrandom::fill(&mut clone_random)?;
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        nonce,
        &run_spec,
        &backend,
        Sha256Digest::from_bytes(&clone_random),
    );
    nonce.zeroize();
    clone_random.zeroize();
    let challenge = challenge?;
    let request_frame = encode_linux_vz_guest_signer_request_v1(
        run_spec.canonical_json_v1(),
        challenge.canonical_json_v1(),
    )?;

    write_new(
        &output_directory.join("run-spec.json"),
        run_spec.canonical_json_v1(),
    )?;
    write_new(
        &output_directory.join("challenge.json"),
        challenge.canonical_json_v1(),
    )?;
    write_new(&output_directory.join("guest-request.bin"), &request_frame)?;
    println!(
        "{{\"backend_identity_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"execution_authority\":false,\"fixture_case\":\"{}\",\"package_execution\":false,\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_conformance_request_build_result.v1\",\"sync_back\":false}}",
        backend.identity_sha256_v1()?,
        challenge.challenge_sha256(),
        arguments[2],
        run_spec.run_spec_sha256(),
    );
    Ok(())
}

fn validate_output_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("unsafe request output directory".into());
    }
    Ok(())
}

fn read_bounded(path: &str, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("input is not a bounded regular non-symlink file".into());
    }
    let mut value = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut value)?;
    if value.is_empty() || value.len() as u64 > maximum {
        return Err("input is not a bounded regular non-symlink file".into());
    }
    Ok(value)
}

fn write_new(path: &Path, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(value)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != value.len() as u64
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err("request output verification failed".into());
    }
    Ok(())
}
