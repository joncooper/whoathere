use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    build_macos_linux_vz_package_execution_runtime_qualification_record_v1,
    decode_qualified_macos_linux_vz_telemetry_backend_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    verify_macos_linux_vz_package_execution_runtime_qualification_record_v1,
};

fn main() {
    if let Err(reason) = run() {
        eprintln!("WHOATHERE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_FAILED reason={reason}");
        std::process::exit(65);
    }
}

fn run() -> Result<(), &'static str> {
    let arguments = std::env::args().collect::<Vec<_>>();
    match arguments.get(1).map(String::as_str) {
        Some("build") if arguments.len() == 12 => build(&arguments[2..]),
        Some("verify") if arguments.len() == 8 => verify(&arguments[2..]),
        _ => Err("usage_invalid"),
    }
}

fn build(arguments: &[String]) -> Result<(), &'static str> {
    let backend = decode_backend_v1(&arguments[0], &arguments[1])?;
    let runtime_manifest = read_bounded_v1(&arguments[2], 128 * 1024)?;
    let image_manifest = read_bounded_v1(&arguments[3], 128 * 1024)?;
    let host_result = read_bounded_v1(&arguments[4], 128 * 1024)?;
    let probe = read_bounded_v1(&arguments[5], 128 * 1024)?;
    let guest_public_key = read_key_v1(&arguments[6])?;
    let host_seed = read_key_v1(&arguments[7])?;
    let grant_public_key = read_key_v1(&arguments[8])?;
    let record = build_macos_linux_vz_package_execution_runtime_qualification_record_v1(
        &backend,
        &runtime_manifest,
        &image_manifest,
        &host_result,
        &probe,
        guest_public_key,
        host_seed,
        grant_public_key,
    )
    .map_err(|error| error.reason_code())?;
    write_new_private_v1(&arguments[9], record.canonical_json_v1())?;
    println!(
        "{{\"execution_authority_issuance_permitted\":true,\"package_execution_during_qualification\":false,\"qualification_record_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_package_execution_runtime_qualification_record_build_result.v1\",\"sync_back\":false}}",
        record.record_sha256()
    );
    Ok(())
}

fn verify(arguments: &[String]) -> Result<(), &'static str> {
    let backend = decode_backend_v1(&arguments[0], &arguments[1])?;
    let record = read_bounded_v1(
        &arguments[2],
        whoathere_macos_vm::MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1,
    )?;
    let guest_public_key = read_key_v1(&arguments[3])?;
    let host_public_key = read_key_v1(&arguments[4])?;
    let grant_public_key = read_key_v1(&arguments[5])?;
    let qualification = verify_macos_linux_vz_package_execution_runtime_qualification_record_v1(
        &record,
        &backend,
        guest_public_key,
        host_public_key,
        grant_public_key,
    )
    .map_err(|error| error.reason_code())?;
    println!(
        "{{\"execution_authority_issuance_permitted\":true,\"execution_grant_issuer_public_key_sha256\":\"{}\",\"guest_evidence_public_key_sha256\":\"{}\",\"host_evidence_public_key_sha256\":\"{}\",\"package_execution_runner_sha256\":\"{}\",\"qualification_record_sha256\":\"{}\",\"qualified_telemetry_backend_sha256\":\"{}\",\"runtime_manifest_sha256\":\"{}\",\"runtime_rootfs_byte_length\":\"{}\",\"runtime_rootfs_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_package_execution_runtime_qualification_record_verify_result.v1\",\"sync_back\":false}}",
        qualification.execution_grant_issuer_public_key_sha256(),
        qualification.guest_evidence_public_key_sha256(),
        qualification.host_evidence_public_key_sha256(),
        qualification.package_execution_runner_sha256(),
        qualification.qualification_record_sha256(),
        qualification.qualified_telemetry_backend_sha256(),
        qualification.execution_runtime_manifest_sha256(),
        qualification.execution_runtime_rootfs_byte_length(),
        qualification.execution_runtime_rootfs_sha256(),
    );
    Ok(())
}

fn decode_backend_v1(
    identity_path: &str,
    qualification_path: &str,
) -> Result<whoathere_macos_vm::QualifiedMacosLinuxVzTelemetryBackendV1, &'static str> {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let identity = read_bounded_v1(
        identity_path,
        whoathere_macos_vm::MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
    )?;
    let identity =
        decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(&identity, &requirements)
            .map_err(|error| error.reason_code())?;
    let qualification = read_bounded_v1(
        qualification_path,
        whoathere_macos_vm::MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
    )?;
    decode_qualified_macos_linux_vz_telemetry_backend_v1(&qualification, &identity)
        .map_err(|error| error.reason_code())
}

fn read_bounded_v1(path: &str, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "input_metadata_failed")?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err("input_invalid");
    }
    let bytes = fs::read(path).map_err(|_| "input_read_failed")?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err("input_invalid");
    }
    Ok(bytes)
}

fn read_key_v1(path: &str) -> Result<[u8; 32], &'static str> {
    read_bounded_v1(path, 32)?
        .try_into()
        .map_err(|_| "key_length_invalid")
}

fn write_new_private_v1(path: &str, bytes: &[u8]) -> Result<(), &'static str> {
    let path = Path::new(path);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    if path.as_os_str().is_empty() || !parent.is_dir() {
        return Err("output_path_invalid");
    }
    #[cfg(unix)]
    let options = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options
    };
    #[cfg(not(unix))]
    let options = {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        options
    };
    let mut output = options.open(path).map_err(|_| "output_create_failed")?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|_| "output_write_failed")
}
