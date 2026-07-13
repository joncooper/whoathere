use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use whoathere_macos_vm::{
    decode_linux_vz_package_runtime_qualification_response_v1,
    decode_linux_vz_process_evidence_payload_v1,
    decode_macos_linux_vz_package_runtime_qualification_request_v1,
    verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1,
    LinuxVzTelemetryConformanceCaseV1, MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
    MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
    MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ runtime qualification receipt verify failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 4 || arguments[1..].iter().any(|value| !value.starts_with('/')) {
        return Err(
            "usage: runtime-qualification-receipt-verify REQUEST_JSON RESPONSE_FRAME GUEST_PUBLIC_KEY".into(),
        );
    }
    let request_bytes = read_bounded(
        Path::new(&arguments[1]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1 as u64,
    )?;
    let response_bytes = read_bounded(
        Path::new(&arguments[2]),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1 as u64,
    )?;
    let guest_public_key = read_bounded(Path::new(&arguments[3]), 32)?;
    let request = decode_macos_linux_vz_package_runtime_qualification_request_v1(&request_bytes)?;
    let response = decode_linux_vz_package_runtime_qualification_response_v1(&response_bytes)?;
    if response.probe_report() != MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1 {
        return Err("runtime qualification probe report mismatch".into());
    }
    let process = decode_linux_vz_process_evidence_payload_v1(response.process_evidence())?;
    if process.fixture_case() != LinuxVzTelemetryConformanceCaseV1::ForkExecExit
        || process.package_uid() != request.package_uid()
        || process.package_gid() != request.package_gid()
    {
        return Err("runtime qualification process evidence binding mismatch".into());
    }
    let claims = MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1::new(
        &request,
        process.guest_observation_claims_v1()?,
        response.probe_report(),
        request.candidate_runtime_rootfs_sha256().clone(),
    )?;
    let guest_public_key: [u8; 32] = guest_public_key
        .try_into()
        .map_err(|_| "runtime qualification guest public key length invalid")?;
    let verified = verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
        &request,
        response.guest_receipt(),
        guest_public_key,
        &claims,
    )?;
    println!(
        "{{\"execution_authority\":false,\"package_execution\":false,\"qualification_request_sha256\":\"{}\",\"receipt_verified\":true,\"rootfs_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_runtime_qualification_receipt_verify_result.v1\",\"sync_back\":false}}",
        verified.qualification_request_sha256(),
        verified.claims().rootfs_block_device_sha256(),
    );
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("runtime qualification verification input invalid".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err("runtime qualification verification input changed while reading".into());
    }
    Ok(bytes)
}
