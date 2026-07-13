use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use whoathere_macos_vm::{
    decode_macos_linux_vz_package_runtime_qualification_request_v1,
    verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1,
    MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1,
    MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ runtime qualification host receipt verify failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 7 || arguments[1..].iter().any(|value| !value.starts_with('/')) {
        return Err(
            "usage: runtime-qualification-host-receipt-verify REQUEST_JSON REQUEST_FRAME RESPONSE_FRAME HOST_EVIDENCE HOST_RECEIPT HOST_PUBLIC_KEY".into(),
        );
    }
    let request_bytes = read_bounded(
        Path::new(&arguments[1]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1 as u64,
    )?;
    let request_frame = read_bounded(
        Path::new(&arguments[2]),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1 as u64,
    )?;
    let response_frame = read_bounded(
        Path::new(&arguments[3]),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1 as u64,
    )?;
    let host_evidence = read_bounded(
        Path::new(&arguments[4]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_BYTES_V1 as u64,
    )?;
    let host_receipt = read_bounded(
        Path::new(&arguments[5]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_BYTES_V1 as u64,
    )?;
    let host_public_key = read_bounded(Path::new(&arguments[6]), 32)?;
    let request = decode_macos_linux_vz_package_runtime_qualification_request_v1(&request_bytes)?;
    let host_public_key: [u8; 32] = host_public_key
        .try_into()
        .map_err(|_| "runtime qualification host public key length invalid")?;
    let verified = verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1(
        &request,
        &request_frame,
        &response_frame,
        &host_evidence,
        &host_receipt,
        host_public_key,
    )?;
    println!(
        "{{\"clone_binding_sha256\":\"{}\",\"execution_authority\":false,\"host_evidence_sha256\":\"{}\",\"host_receipt_verified\":true,\"package_execution\":false,\"qualification_request_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_runtime_qualification_host_receipt_verify_result.v1\",\"sync_back\":false}}",
        verified.clone_binding_sha256(),
        verified.host_evidence_sha256(),
        verified.qualification_request_sha256(),
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
        return Err("runtime qualification host verification input invalid".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err("runtime qualification host verification input changed while reading".into());
    }
    Ok(bytes)
}
