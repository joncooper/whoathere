use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use whoathere_macos_vm::{
    build_macos_linux_vz_package_runtime_qualification_record_v1,
    decode_macos_linux_vz_package_runtime_qualification_request_v1,
    verify_macos_linux_vz_package_runtime_qualification_record_v1,
    MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1,
    MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ runtime qualification record failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 10
        || !matches!(arguments[1].as_str(), "build" | "verify")
        || arguments[2..].iter().any(|value| !value.starts_with('/'))
    {
        return Err(usage().into());
    }
    match arguments[1].as_str() {
        "build" => build(&arguments[2..]),
        "verify" => verify(&arguments[2..]),
        _ => Err(usage().into()),
    }
}

fn build(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let inputs = read_evidence_inputs(&arguments[..7])?;
    let record = build_macos_linux_vz_package_runtime_qualification_record_v1(
        &inputs.request,
        &inputs.request_frame,
        &inputs.response_frame,
        &inputs.host_evidence,
        &inputs.host_receipt,
        inputs.guest_public_key,
        inputs.host_public_key,
    )?;
    write_new(Path::new(&arguments[7]), record.canonical_json_v1())?;
    println!(
        "{{\"execution_authority_issuance_permitted\":false,\"execution_runner_capability\":\"not_qualified\",\"package_execution\":false,\"qualification_record_sha256\":\"{}\",\"qualification_state\":\"fixed_nonexecuting_probe_passed\",\"schema_version\":\"whoathere.linux_vz_runtime_qualification_record_build_result.v1\",\"sync_back\":false}}",
        record.record_sha256(),
    );
    Ok(())
}

fn verify(arguments: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let record_bytes = read_bounded(
        Path::new(&arguments[0]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_BYTES_V1 as u64,
    )?;
    let inputs = read_evidence_inputs(&arguments[1..])?;
    let record = verify_macos_linux_vz_package_runtime_qualification_record_v1(
        &record_bytes,
        &inputs.request,
        &inputs.request_frame,
        &inputs.response_frame,
        &inputs.host_evidence,
        &inputs.host_receipt,
        inputs.guest_public_key,
        inputs.host_public_key,
    )?;
    println!(
        "{{\"evidence_binding_verified\":true,\"execution_authority_issuance_permitted\":false,\"execution_runner_capability\":\"not_qualified\",\"package_execution\":false,\"qualification_record_sha256\":\"{}\",\"qualification_state\":\"fixed_nonexecuting_probe_passed\",\"schema_version\":\"whoathere.linux_vz_runtime_qualification_record_verify_result.v1\",\"sync_back\":false}}",
        record.record_sha256(),
    );
    Ok(())
}

struct EvidenceInputs {
    request: whoathere_macos_vm::MacosLinuxVzPackageRuntimeQualificationRequestV1,
    request_frame: Vec<u8>,
    response_frame: Vec<u8>,
    host_evidence: Vec<u8>,
    host_receipt: Vec<u8>,
    guest_public_key: [u8; 32],
    host_public_key: [u8; 32],
}

fn read_evidence_inputs(
    arguments: &[String],
) -> Result<EvidenceInputs, Box<dyn std::error::Error>> {
    if arguments.len() != 7 {
        return Err(usage().into());
    }
    let request_bytes = read_bounded(
        Path::new(&arguments[0]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1 as u64,
    )?;
    let request_frame = read_bounded(
        Path::new(&arguments[1]),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_FRAME_BYTES_V1 as u64,
    )?;
    let response_frame = read_bounded(
        Path::new(&arguments[2]),
        MAX_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RESPONSE_FRAME_BYTES_V1 as u64,
    )?;
    let host_evidence = read_bounded(
        Path::new(&arguments[3]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_EVIDENCE_BYTES_V1 as u64,
    )?;
    let host_receipt = read_bounded(
        Path::new(&arguments[4]),
        MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_HOST_RECEIPT_BYTES_V1 as u64,
    )?;
    let guest_public_key = exact_key(Path::new(&arguments[5]))?;
    let host_public_key = exact_key(Path::new(&arguments[6]))?;
    Ok(EvidenceInputs {
        request: decode_macos_linux_vz_package_runtime_qualification_request_v1(&request_bytes)?,
        request_frame,
        response_frame,
        host_evidence,
        host_receipt,
        guest_public_key,
        host_public_key,
    })
}

fn exact_key(path: &Path) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    read_bounded(path, 32)?
        .try_into()
        .map_err(|_| "runtime qualification public key length invalid".into())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("runtime qualification record input invalid".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err("runtime qualification record input changed while reading".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn usage() -> &'static str {
    "usage: runtime-qualification-record build REQUEST_JSON REQUEST_FRAME RESPONSE_FRAME HOST_EVIDENCE HOST_RECEIPT GUEST_PUBLIC_KEY HOST_PUBLIC_KEY OUTPUT_RECORD\n       runtime-qualification-record verify RECORD REQUEST_JSON REQUEST_FRAME RESPONSE_FRAME HOST_EVIDENCE HOST_RECEIPT GUEST_PUBLIC_KEY HOST_PUBLIC_KEY"
}
