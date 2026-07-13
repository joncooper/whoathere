use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1,
    decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_linux_vz_bpf_program_type_evidence_from_serial_v1,
    decode_linux_vz_cgroup_evidence_from_serial_v1, decode_linux_vz_file_evidence_from_serial_v1,
    decode_linux_vz_platform_evidence_from_serial_v1,
    decode_linux_vz_process_evidence_from_serial_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    LinuxVzTelemetryConformanceObservedTerminalV1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ guest receipt verification failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 7 || arguments[1..].iter().any(|value| !value.starts_with('/')) {
        return Err(
            "usage: receipt-verify RUN_SPEC CHALLENGE BACKEND_IDENTITY GUEST_PUBLIC_KEY SERIAL RECEIPT"
                .into(),
        );
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
    let public_key = read_bounded(&arguments[4], 32)?;
    let serial = read_bounded(&arguments[5], 1024 * 1024)?;
    let receipt = read_bounded(
        &arguments[6],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
    )?;
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let run_spec =
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&run_spec_bytes)?;
    let backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &backend_bytes,
        &requirements,
    )?;
    let challenge = decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
        &challenge_bytes,
        &run_spec,
        &backend,
    )?;
    if run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::KernelConfigAndBtf {
        let evidence = decode_linux_vz_platform_evidence_from_serial_v1(&serial, &backend)?;
        let claims = evidence.guest_observation_claims_v1()?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "guest public key must be exactly 32 bytes")?;
        let verified = verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge, &run_spec, &backend, &receipt, public_key, &claims,
        )?;
        println!(
            "{{\"backend_identity_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"execution_authority\":false,\"package_execution\":false,\"platform_evidence_payload_sha256\":\"{}\",\"receipt_sha256\":\"{}\",\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_guest_receipt_verification.v1\",\"status\":\"verified\",\"sync_back\":false}}",
            backend.identity_sha256_v1()?,
            verified.challenge_sha256(),
            evidence.payload_sha256(),
            Sha256Digest::from_bytes(&receipt),
            run_spec.run_spec_sha256(),
        );
        return Ok(());
    }
    if run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::CgroupV2 {
        let evidence = decode_linux_vz_cgroup_evidence_from_serial_v1(&serial, &backend)?;
        let claims = evidence.guest_observation_claims_v1()?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "guest public key must be exactly 32 bytes")?;
        let verified = verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge, &run_spec, &backend, &receipt, public_key, &claims,
        )?;
        println!(
            "{{\"backend_identity_sha256\":\"{}\",\"cgroup_evidence_payload_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"execution_authority\":false,\"package_execution\":false,\"receipt_sha256\":\"{}\",\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_guest_receipt_verification.v1\",\"status\":\"verified\",\"sync_back\":false}}",
            backend.identity_sha256_v1()?,
            evidence.payload_sha256(),
            verified.challenge_sha256(),
            Sha256Digest::from_bytes(&receipt),
            run_spec.run_spec_sha256(),
        );
        return Ok(());
    }
    if run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::BpfProgramTypes {
        let evidence = decode_linux_vz_bpf_program_type_evidence_from_serial_v1(&serial)?;
        if evidence.package_uid() != backend.package_uid()
            || evidence.package_gid() != backend.package_gid()
        {
            return Err("guest BPF program-type evidence binding mismatch".into());
        }
        let claims = evidence.guest_observation_claims_v1()?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "guest public key must be exactly 32 bytes")?;
        let verified = verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge, &run_spec, &backend, &receipt, public_key, &claims,
        )?;
        println!(
            "{{\"backend_identity_sha256\":\"{}\",\"bpf_program_type_evidence_payload_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"execution_authority\":false,\"package_execution\":false,\"receipt_sha256\":\"{}\",\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_guest_receipt_verification.v1\",\"status\":\"verified\",\"sync_back\":false}}",
            backend.identity_sha256_v1()?,
            evidence.payload_sha256(),
            verified.challenge_sha256(),
            Sha256Digest::from_bytes(&receipt),
            run_spec.run_spec_sha256(),
        );
        return Ok(());
    }
    if matches!(
        run_spec.fixture_case(),
        LinuxVzTelemetryConformanceCaseV1::FanotifyPermission
            | LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
            | LinuxVzTelemetryConformanceCaseV1::MmapAccess
    ) {
        let evidence = decode_linux_vz_file_evidence_from_serial_v1(&serial)?;
        if evidence.fixture_case() != run_spec.fixture_case()
            || evidence.package_uid() != backend.package_uid()
            || evidence.package_gid() != backend.package_gid()
        {
            return Err("guest file evidence binding mismatch".into());
        }
        let claims = evidence.guest_observation_claims_v1()?;
        let public_key: [u8; 32] = public_key
            .try_into()
            .map_err(|_| "guest public key must be exactly 32 bytes")?;
        let verified = verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge, &run_spec, &backend, &receipt, public_key, &claims,
        )?;
        println!(
            "{{\"backend_identity_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"execution_authority\":false,\"file_evidence_payload_sha256\":\"{}\",\"package_execution\":false,\"receipt_sha256\":\"{}\",\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_guest_receipt_verification.v1\",\"status\":\"verified\",\"sync_back\":false}}",
            backend.identity_sha256_v1()?,
            verified.challenge_sha256(),
            evidence.payload_sha256(),
            Sha256Digest::from_bytes(&receipt),
            run_spec.run_spec_sha256(),
        );
        return Ok(());
    }
    let evidence = decode_linux_vz_process_evidence_from_serial_v1(&serial)?;
    if evidence.fixture_case() != run_spec.fixture_case()
        || evidence.package_uid() != backend.package_uid()
        || evidence.package_gid() != backend.package_gid()
    {
        return Err("guest process evidence binding mismatch".into());
    }
    let claims = match run_spec.fixture_case() {
        LinuxVzTelemetryConformanceCaseV1::HostSensorDeath => evidence
            .guest_observation_claims_for_terminal_v1(
                LinuxVzTelemetryConformanceObservedTerminalV1::InfrastructureErrorWithTeardown,
            )?,
        LinuxVzTelemetryConformanceCaseV1::AllProtectedAssetsDenied => evidence
            .guest_observation_claims_for_terminal_v1(
                LinuxVzTelemetryConformanceObservedTerminalV1::AccessDeniedWithCompleteEvidence,
            )?,
        _ => evidence.guest_observation_claims_v1()?,
    };
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| "guest public key must be exactly 32 bytes")?;
    let verified = verify_macos_linux_vz_telemetry_guest_receipt_v1(
        &challenge, &run_spec, &backend, &receipt, public_key, &claims,
    )?;
    println!(
        "{{\"backend_identity_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"execution_authority\":false,\"package_execution\":false,\"process_evidence_payload_sha256\":\"{}\",\"receipt_sha256\":\"{}\",\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_guest_receipt_verification.v1\",\"status\":\"verified\",\"sync_back\":false}}",
        backend.identity_sha256_v1()?,
        verified.challenge_sha256(),
        evidence.payload_sha256(),
        Sha256Digest::from_bytes(&receipt),
        run_spec.run_spec_sha256(),
    );
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
