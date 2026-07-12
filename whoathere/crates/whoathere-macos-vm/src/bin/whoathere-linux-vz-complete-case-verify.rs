use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1,
    decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_linux_vz_file_evidence_from_serial_v1, decode_linux_vz_host_evidence_payload_v1,
    decode_linux_vz_process_evidence_from_serial_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    verify_macos_linux_vz_telemetry_conformance_case_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_host_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    MAX_LINUX_VZ_HOST_EVIDENCE_PAYLOAD_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ complete-case verification failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 10 || arguments[1..].iter().any(|value| !value.starts_with('/')) {
        return Err("usage: complete-case-verify RUN_SPEC CHALLENGE BACKEND GUEST_PUBLIC_KEY HOST_PUBLIC_KEY SERIAL GUEST_RECEIPT HOST_EVIDENCE HOST_RECEIPT".into());
    }
    let run_spec_bytes = read_bounded(
        &arguments[1],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1 as u64,
    )?;
    let challenge_bytes = read_bounded(
        &arguments[2],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
    )?;
    let backend_bytes = read_bounded(
        &arguments[3],
        MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1 as u64,
    )?;
    let guest_public_key = exact_key(&arguments[4])?;
    let host_public_key = exact_key(&arguments[5])?;
    let serial = read_bounded(&arguments[6], 1024 * 1024)?;
    let guest_receipt = read_bounded(
        &arguments[7],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
    )?;
    let host_evidence = read_bounded(
        &arguments[8],
        MAX_LINUX_VZ_HOST_EVIDENCE_PAYLOAD_BYTES_V1 as u64,
    )?;
    let host_receipt = read_bounded(
        &arguments[9],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
    )?;
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let run_spec =
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&run_spec_bytes)?;
    let fixture_case = match run_spec.fixture_case() {
        LinuxVzTelemetryConformanceCaseV1::ForkExecExit => "fork_exec_exit",
        LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization => "double_fork_daemonization",
        LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete => {
            "protected_open_read_write_rename_delete"
        }
        LinuxVzTelemetryConformanceCaseV1::MmapAccess => "mmap_access",
        _ => return Err("complete-case verifier does not implement this inert case".into()),
    };
    let backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &backend_bytes,
        &requirements,
    )?;
    let challenge = decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
        &challenge_bytes,
        &run_spec,
        &backend,
    )?;
    let (guest_evidence_payload_sha256, guest_claims) = match run_spec.fixture_case() {
        LinuxVzTelemetryConformanceCaseV1::ForkExecExit
        | LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization => {
            let evidence = decode_linux_vz_process_evidence_from_serial_v1(&serial)?;
            if evidence.fixture_case() != run_spec.fixture_case()
                || evidence.package_uid() != backend.package_uid()
                || evidence.package_gid() != backend.package_gid()
            {
                return Err("guest evidence package identity mismatch".into());
            }
            (
                evidence.payload_sha256().clone(),
                evidence.guest_observation_claims_v1()?,
            )
        }
        LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
        | LinuxVzTelemetryConformanceCaseV1::MmapAccess => {
            let evidence = decode_linux_vz_file_evidence_from_serial_v1(&serial)?;
            if evidence.fixture_case() != run_spec.fixture_case()
                || evidence.package_uid() != backend.package_uid()
                || evidence.package_gid() != backend.package_gid()
            {
                return Err("guest file evidence binding mismatch".into());
            }
            (
                evidence.payload_sha256().clone(),
                evidence.guest_observation_claims_v1()?,
            )
        }
        _ => return Err("complete-case verifier does not implement this inert case".into()),
    };
    let verified_guest = verify_macos_linux_vz_telemetry_guest_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &guest_receipt,
        guest_public_key,
        &guest_claims,
    )?;
    let host_evidence = decode_linux_vz_host_evidence_payload_v1(&host_evidence)?;
    let host_claims = host_evidence.host_observation_claims_v1()?;
    let verified_host = verify_macos_linux_vz_telemetry_host_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &host_receipt,
        host_public_key,
        &host_claims,
    )?;
    let verified_case = verify_macos_linux_vz_telemetry_conformance_case_v1(
        &challenge,
        &run_spec,
        Some(&verified_guest),
        &verified_host,
    )?;
    if verified_case.package_execution_authority_permitted()
        || !verified_case.guest_receipt_present()
    {
        return Err("complete case unexpectedly grants execution authority".into());
    }
    println!(
        "{{\"backend_identity_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"complete_conformance_case_verified\":true,\"execution_authority\":false,\"fixture_case\":\"{}\",\"guest_evidence_payload_sha256\":\"{}\",\"guest_receipt_sha256\":\"{}\",\"host_evidence_payload_sha256\":\"{}\",\"host_receipt_sha256\":\"{}\",\"package_execution\":false,\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_complete_case_verification.v1\",\"sync_back\":false}}",
        backend.identity_sha256_v1()?,
        challenge.challenge_sha256(),
        fixture_case,
        guest_evidence_payload_sha256,
        Sha256Digest::from_bytes(&guest_receipt),
        host_evidence.payload_sha256(),
        Sha256Digest::from_bytes(&host_receipt),
        run_spec.run_spec_sha256(),
    );
    Ok(())
}

fn exact_key(path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    read_bounded(path, 32)?
        .try_into()
        .map_err(|_| "evidence public key must be exactly 32 bytes".into())
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
