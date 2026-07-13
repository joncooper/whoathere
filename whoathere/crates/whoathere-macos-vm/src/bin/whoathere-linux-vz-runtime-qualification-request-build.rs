use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    build_macos_linux_vz_package_runtime_qualification_request_v1,
    decode_qualified_macos_linux_vz_telemetry_backend_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    encode_linux_vz_package_runtime_qualification_request_v1,
    MacosLinuxVzCandidatePackageRuntimeV1, MacosLinuxVzPackageRuntimeQualificationImageV1,
};
use zeroize::Zeroize;

const MAX_JSON_BYTES: u64 = 4 * 1024 * 1024;
const MAX_INITRAMFS_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_AGENT_BYTES: u64 = 16 * 1024 * 1024;
const MAX_INIT_BYTES: u64 = 1024 * 1024;
const MAX_MODULE_BUNDLE_BYTES: u64 = 256 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ runtime qualification request build failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 9 || arguments[1..].iter().any(|value| !value.starts_with('/')) {
        return Err(
            "usage: runtime-qualification-request-build QUALIFIED_BACKEND BACKEND_IDENTITY ROOTFS RUNTIME_MANIFEST PACKAGE_RUNNER QUALIFICATION_IMAGE_DIR CLONE_BINDING_JSON OUTPUT_DIR".into(),
        );
    }
    let qualified_backend_path = Path::new(&arguments[1]);
    let backend_identity_path = Path::new(&arguments[2]);
    let rootfs_path = Path::new(&arguments[3]);
    let runtime_manifest_path = Path::new(&arguments[4]);
    let package_runner_path = Path::new(&arguments[5]);
    let qualification_image_directory = Path::new(&arguments[6]);
    let clone_binding_path = Path::new(&arguments[7]);
    let output_directory = Path::new(&arguments[8]);
    validate_output_directory(output_directory)?;

    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend_bytes = read_bounded(backend_identity_path, MAX_JSON_BYTES)?;
    let backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &backend_bytes,
        &requirements,
    )?;
    let qualified_bytes = read_bounded(qualified_backend_path, MAX_JSON_BYTES)?;
    let qualified =
        decode_qualified_macos_linux_vz_telemetry_backend_v1(&qualified_bytes, &backend)?;
    let candidate_runtime = MacosLinuxVzCandidatePackageRuntimeV1::from_exact_files(
        rootfs_path,
        runtime_manifest_path,
        package_runner_path,
    )?;

    let qualification_manifest_path = qualification_image_directory.join("manifest.json");
    let qualification_initramfs_path =
        qualification_image_directory.join("whoathere-runtime-qualification-initramfs-virt");
    let qualification_agent_path =
        qualification_image_directory.join("overlay/whoathere/runtime-qualification-agent");
    let qualification_init_path = qualification_image_directory.join("overlay/init");
    let qualification_module_bundle_path =
        qualification_image_directory.join("overlay/whoathere/runtime-module-bundle.json");
    let qualification_manifest = read_bounded(&qualification_manifest_path, MAX_JSON_BYTES)?;
    let qualification_initramfs = read_bounded(&qualification_initramfs_path, MAX_INITRAMFS_BYTES)?;
    let qualification_agent = read_bounded(&qualification_agent_path, MAX_AGENT_BYTES)?;
    let qualification_init = read_bounded(&qualification_init_path, MAX_INIT_BYTES)?;
    let qualification_module_bundle =
        read_bounded(&qualification_module_bundle_path, MAX_MODULE_BUNDLE_BYTES)?;
    let qualification_image = MacosLinuxVzPackageRuntimeQualificationImageV1::from_exact_bytes(
        &qualification_initramfs,
        &qualification_agent,
        &qualification_init,
        &qualification_module_bundle,
    )?;
    validate_qualification_manifest(
        &qualification_manifest,
        &backend,
        &candidate_runtime,
        &qualification_image,
    )?;

    let clone_binding_bytes = read_bounded(clone_binding_path, 64 * 1024)?;
    let clone_binding_value: Value = serde_json::from_slice(&clone_binding_bytes)?;
    if serde_json_canonicalizer::to_vec(&clone_binding_value)? != clone_binding_bytes {
        return Err("runtime qualification clone binding is not canonical JSON".into());
    }
    let clone_binding_sha256 = Sha256Digest::from_bytes(&clone_binding_bytes);
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge)?;
    if challenge.iter().all(|byte| *byte == 0) {
        return Err("runtime qualification challenge entropy invalid".into());
    }
    let request = build_macos_linux_vz_package_runtime_qualification_request_v1(
        &qualified,
        &backend,
        &candidate_runtime,
        &qualification_image,
        challenge,
        clone_binding_sha256.clone(),
    )?;
    challenge.zeroize();
    let frame =
        encode_linux_vz_package_runtime_qualification_request_v1(request.canonical_json_v1())?;
    write_new(
        &output_directory.join("runtime-qualification-request.json"),
        request.canonical_json_v1(),
    )?;
    write_new(
        &output_directory.join("runtime-qualification-request.bin"),
        &frame,
    )?;
    println!(
        "{{\"clone_binding_sha256\":\"{}\",\"execution_authority\":false,\"package_execution\":false,\"qualification_request_sha256\":\"{}\",\"qualified_telemetry_backend_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_runtime_qualification_request_build_result.v1\",\"sync_back\":false}}",
        clone_binding_sha256,
        request.request_sha256(),
        qualified.qualified_backend_sha256(),
    );
    Ok(())
}

fn validate_qualification_manifest(
    bytes: &[u8],
    backend: &whoathere_macos_vm::UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    runtime: &MacosLinuxVzCandidatePackageRuntimeV1,
    image: &MacosLinuxVzPackageRuntimeQualificationImageV1,
) -> Result<(), Box<dyn std::error::Error>> {
    let value: Value = serde_json::from_slice(bytes)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)?;
    if canonical != bytes && [canonical.as_slice(), b"\n"].concat() != bytes {
        return Err("runtime qualification image manifest is not canonical JSON".into());
    }
    let object = value
        .as_object()
        .ok_or("runtime qualification image manifest is not an object")?;
    let string = |key: &str| object.get(key).and_then(Value::as_str);
    let boolean = |key: &str| object.get(key).and_then(Value::as_bool);
    if string("schema_version")
        != Some("whoathere.linux_vz_package_runtime_qualification_image_manifest.v1")
        || string("image_state") != Some("candidate_unqualified")
        || string("runtime_qualification_operation") != Some("fixed_nonexecuting_probe")
        || string("external_network") != Some("host_raw_frame_sinkhole_no_external_route")
        || boolean("package_execution") != Some(false)
        || string("sync_back_policy") != Some("structurally_absent")
        || string("kernel_image_sha256") != Some(backend.kernel_image_sha256().as_str())
        || string("base_signed_initramfs_sha256") != Some(backend.initramfs_sha256().as_str())
        || string("guest_signer_sha256") != Some(backend.guest_sensor_sha256().as_str())
        || string("process_sensor_probe_sha256") != Some(backend.guest_bpf_bundle_sha256().as_str())
        || string("candidate_runtime_rootfs_sha256") != Some(runtime.rootfs_sha256().as_str())
        || string("candidate_runtime_rootfs_byte_length")
            != Some(runtime.rootfs_byte_length().to_string().as_str())
        || string("candidate_runtime_manifest_sha256")
            != Some(runtime.runtime_manifest_sha256().as_str())
        || string("candidate_package_runner_sha256")
            != Some(runtime.package_runner_sha256().as_str())
        || string("runtime_qualification_initramfs_sha256")
            != Some(image.initramfs_sha256().as_str())
        || string("runtime_qualification_agent_sha256") != Some(image.guest_agent_sha256().as_str())
        || string("runtime_qualification_init_sha256") != Some(image.guest_init_sha256().as_str())
        || string("runtime_qualification_module_bundle_sha256")
            != Some(image.module_bundle_sha256().as_str())
    {
        return Err("runtime qualification image manifest binding mismatch".into());
    }
    Ok(())
}

fn validate_output_directory(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("runtime qualification output directory is not secure mode 0700".into());
    }
    Ok(())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("runtime qualification input file is invalid".into());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err("runtime qualification input changed while reading".into());
    }
    Ok(bytes)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.sync_all()?;
    Ok(())
}
