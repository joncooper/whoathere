use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_wheel_scenarios_v1, expected_wheel_scenario_kinds_v1,
    ArtifactScenarioExecutionIdentityV1, WheelRuntimeProfileV1, WheelScenarioCompilationRequestV1,
    WheelScenarioIdentitySetV1, WheelScenarioPolicyV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    compile_macos_wheel_run_spec_v1, prepare_macos_wheel_launch_v1,
    write_macos_wheel_submission_frame_v1, MacosWheelBackendCapabilitiesV1,
    MacosWheelBackendIdentityV1, MACOS_WHEEL_GUEST_PROTOCOL_V1,
};
use zip::write::SimpleFileOptions;

const RECEIPT_SCHEMA_V1: &str = "whoathere.wheel_supervisor_provisioning.v1";
const LAUNCH_SCHEMA_V1: &str = "whoathere.measured_inert_wheel_launch.v1";
const CLONE_IMPLEMENTATION_ID_V1: &[u8] = b"whoathere.swift.fclonefileat.direct.v1";
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const AUTHORITY_LIFETIME_SECONDS: u64 = 120;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WheelProvisioningReceiptV1 {
    base_generation_id: String,
    clone_implementation_sha256: Sha256Digest,
    cpu_count: String,
    guest_auth_public_key_sha256: Sha256Digest,
    guest_protocol_sha256: Sha256Digest,
    guest_supervisor_sha256: Sha256Digest,
    memory_mib: String,
    package_execution_enabled: bool,
    package_gid: String,
    package_uid: String,
    package_username: String,
    pip_cli_sha256: Sha256Digest,
    pip_version: String,
    python_executable_sha256: Sha256Digest,
    python_version: String,
    runner_configuration_sha256: Sha256Digest,
    schema_version: String,
    sync_back_enabled: bool,
    wheel_vsock_port: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct LaunchManifestV1<'a> {
    artifact_sha256: &'a Sha256Digest,
    authority_id: &'a str,
    authority_record_sha256: &'a Sha256Digest,
    challenge_binding_sha256: &'a Sha256Digest,
    package_execution_enabled: bool,
    run_spec_sha256: &'a Sha256Digest,
    schema_version: &'static str,
    submission_file_name: String,
    sync_back_enabled: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("measured_inert_wheel_launch_failed:{error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_arguments()?;
    let bundle = arguments.state_dir.join("bundle");
    let disk = measure_file(&bundle.join("disk.img"), None)?;
    let auxiliary = measure_file(&bundle.join("auxiliary-storage"), None)?;
    let hardware = measure_file(&bundle.join("hardware-model.bin"), Some(MAX_METADATA_BYTES))?;
    let machine = measure_file(
        &bundle.join("machine-identifier.bin"),
        Some(MAX_METADATA_BYTES),
    )?;
    let receipt_measurement = measure_file(
        &bundle.join("wheel-supervisor-provisioning.json"),
        Some(MAX_METADATA_BYTES),
    )?;
    let public_key = measure_file(&bundle.join("wheel-supervisor-public-key.bin"), Some(32))?;
    let helper = measure_file(&arguments.helper, None)?;
    let receipt = decode_receipt(
        receipt_measurement
            .bytes
            .as_deref()
            .ok_or_else(|| io::Error::other("receipt bytes unavailable"))?,
    )?;
    let public_key_bytes = public_key
        .bytes
        .as_deref()
        .ok_or_else(|| io::Error::other("public key bytes unavailable"))?;
    if public_key_bytes.len() != 32
        || public_key.digest != receipt.guest_auth_public_key_sha256
        || receipt.package_execution_enabled
        || receipt.sync_back_enabled
        || receipt.wheel_vsock_port != "47080"
        || receipt.package_username != "_whoatherepkg"
        || receipt.clone_implementation_sha256
            != Sha256Digest::from_bytes(CLONE_IMPLEMENTATION_ID_V1)
        || receipt.guest_protocol_sha256
            != Sha256Digest::from_bytes(MACOS_WHEEL_GUEST_PROTOCOL_V1.as_bytes())
    {
        return Err(io::Error::other("wheel receipt measurement mismatch").into());
    }

    let package_uid = canonical_nonzero_u32(&receipt.package_uid)?;
    let package_gid = canonical_nonzero_u32(&receipt.package_gid)?;
    let cpu_count = u16::try_from(canonical_nonzero_u32(&receipt.cpu_count)?)
        .map_err(|_| io::Error::other("CPU count invalid"))?;
    let memory_mib = canonical_nonzero_u64(&receipt.memory_mib)?;
    let artifact_bytes = inert_wheel()?;
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("measured-inert-wheel-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:measured-inert-wheel-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-10T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "measured_inert_wheel_fixture-1.0.0-py3-none-any.whl".to_string(),
            declared_format: Some(ArtifactFormat::WheelZip),
            custody_reference: "repository-inert-measured-wheel-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "macos-wheel-measured-inert.v1".to_string(),
            requires_external_dependency_resolution: false,
        },
        &artifact_bytes,
        ArtifactFormat::WheelZip,
    );
    let artifact = normalize_artifact(&envelope, &artifact_bytes, NormalizationLimits::default())?;
    let cas_key = canonical_cas_object_key_for_artifact(artifact.manifest.artifact_sha256.as_str())
        .map_err(|_| io::Error::other("artifact CAS key invalid"))?;
    let subject = ArtifactEvidenceSubjectV2::new(
        artifact.manifest.artifact_sha256.as_str(),
        envelope.envelope_sha256()?.as_str(),
        artifact.manifest.manifest_sha256.as_str(),
        cas_key,
    )
    .map_err(|_| io::Error::other("artifact subject invalid"))?;
    let runtime = WheelRuntimeProfileV1::new(
        "macos-arm64-measured-wheel-inert",
        receipt.python_version.clone(),
        receipt.python_executable_sha256.clone(),
        receipt.pip_version.clone(),
        receipt.pip_cli_sha256.clone(),
    )?;
    let policy =
        WheelScenarioPolicyV1::inert_qualification_only(envelope.original_sha256.clone(), runtime)?;
    let mut identity_map = BTreeMap::new();
    for (index, kind) in expected_wheel_scenario_kinds_v1(&artifact.manifest)?
        .into_iter()
        .enumerate()
    {
        let suffix = index + 1;
        identity_map.insert(
            kind,
            ArtifactScenarioExecutionIdentityV1::new(
                format!("measured-wheel-job-{suffix}"),
                format!("measured-wheel-run-{suffix}"),
                format!("measured-wheel-evidence-{suffix}"),
                format!("measured-wheel-scenario-{suffix}"),
            )?,
        );
    }
    let identities = WheelScenarioIdentitySetV1::new("measured-wheel-plan", identity_map)?;
    let plan = compile_wheel_scenarios_v1(WheelScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &artifact.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })?;
    let template = plan
        .templates()
        .iter()
        .find(|template| {
            matches!(
                template.scenario_kind(),
                whoathere_detonation::WheelScenarioKindV1::InstallExactWheel
            )
        })
        .ok_or_else(|| io::Error::other("install wheel scenario unavailable"))?;
    let backend =
        MacosWheelBackendCapabilitiesV1::inert_first_slice(MacosWheelBackendIdentityV1::new(
            receipt.base_generation_id,
            disk.digest,
            auxiliary.digest,
            hardware.digest,
            machine.digest,
            cpu_count,
            memory_mib,
            receipt_measurement.digest,
            helper.digest,
            receipt.guest_supervisor_sha256,
            receipt.guest_auth_public_key_sha256,
            receipt.runner_configuration_sha256,
            package_uid,
            package_gid,
            receipt.python_version,
            receipt.python_executable_sha256,
            receipt.pip_version,
            receipt.pip_cli_sha256,
            receipt.clone_implementation_sha256,
        )?);
    let run_spec = compile_macos_wheel_run_spec_v1(template, &backend)?;
    let issued_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| io::Error::other("system time invalid"))?
        .as_secs();
    let prepared = prepare_macos_wheel_launch_v1(
        &arguments.state_dir,
        run_spec,
        issued_at,
        AUTHORITY_LIFETIME_SECONDS,
    )?;
    let (header, authority) = prepared.into_parts();

    let mut submission = Vec::new();
    write_macos_wheel_submission_frame_v1(&mut submission, &header, &artifact_bytes)?;
    if let Err(error) = write_new_private_file(&arguments.submission_output, &submission) {
        let _ = fs::remove_file(authority.pending_path());
        return Err(error.into());
    }
    let manifest = LaunchManifestV1 {
        artifact_sha256: authority.record().artifact_sha256(),
        authority_id: authority.record().authority_id(),
        authority_record_sha256: authority.record_sha256(),
        challenge_binding_sha256: authority.record().challenge_binding_sha256(),
        package_execution_enabled: false,
        run_spec_sha256: authority.record().run_spec_sha256(),
        schema_version: LAUNCH_SCHEMA_V1,
        submission_file_name: arguments
            .submission_output
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| io::Error::other("submission output name invalid"))?
            .to_string(),
        sync_back_enabled: false,
    };
    let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest)
        .map_err(|_| io::Error::other("launch manifest serialization failed"))?;
    if let Err(error) = write_new_private_file(&arguments.launch_manifest_output, &manifest_bytes) {
        let _ = fs::remove_file(&arguments.submission_output);
        let _ = fs::remove_file(authority.pending_path());
        return Err(error.into());
    }

    println!("measured_inert_wheel_launch_prepared=true");
    println!("authority_id={}", authority.record().authority_id());
    println!("artifact_sha256={}", authority.record().artifact_sha256());
    println!("run_spec_sha256={}", authority.record().run_spec_sha256());
    println!("package_execution_enabled=false");
    println!("sync_back_enabled=false");
    Ok(())
}

struct ArgumentsV1 {
    state_dir: PathBuf,
    helper: PathBuf,
    submission_output: PathBuf,
    launch_manifest_output: PathBuf,
}

fn parse_arguments() -> Result<ArgumentsV1, io::Error> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut state_dir = None;
    let mut helper = None;
    let mut submission_output = None;
    let mut launch_manifest_output = None;
    while let Some(argument) = arguments.next() {
        if argument == "--state-dir" {
            state_dir = arguments.next().map(PathBuf::from);
        } else if argument == "--helper" {
            helper = arguments.next().map(PathBuf::from);
        } else if argument == "--submission-output" {
            submission_output = arguments.next().map(PathBuf::from);
        } else if argument == "--launch-manifest-output" {
            launch_manifest_output = arguments.next().map(PathBuf::from);
        } else {
            return Err(io::Error::other("unknown argument"));
        }
    }
    let value = ArgumentsV1 {
        state_dir: state_dir.ok_or_else(|| io::Error::other("state directory required"))?,
        helper: helper.ok_or_else(|| io::Error::other("helper required"))?,
        submission_output: submission_output
            .ok_or_else(|| io::Error::other("submission output required"))?,
        launch_manifest_output: launch_manifest_output
            .ok_or_else(|| io::Error::other("launch manifest output required"))?,
    };
    if !value.state_dir.is_absolute()
        || !value.helper.is_absolute()
        || !value.submission_output.is_absolute()
        || !value.launch_manifest_output.is_absolute()
        || value.submission_output == value.launch_manifest_output
    {
        return Err(io::Error::other("distinct absolute paths required"));
    }
    Ok(value)
}

fn decode_receipt(bytes: &[u8]) -> Result<WheelProvisioningReceiptV1, io::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let receipt = WheelProvisioningReceiptV1::deserialize(&mut deserializer)
        .map_err(|_| io::Error::other("wheel receipt invalid"))?;
    deserializer
        .end()
        .map_err(|_| io::Error::other("wheel receipt trailing data"))?;
    let canonical = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| io::Error::other("wheel receipt canonicalization failed"))?;
    if canonical != bytes || receipt.schema_version != RECEIPT_SCHEMA_V1 {
        return Err(io::Error::other("wheel receipt noncanonical"));
    }
    Ok(receipt)
}

struct FileMeasurement {
    digest: Sha256Digest,
    bytes: Option<Vec<u8>>,
}

fn measure_file(path: &Path, capture_limit: Option<u64>) -> Result<FileMeasurement, io::Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let descriptor = file.metadata()?;
    let path_before = fs::symlink_metadata(path)?;
    validate_metadata(&descriptor, capture_limit)?;
    validate_metadata(&path_before, capture_limit)?;
    if descriptor.dev() != path_before.dev() || descriptor.ino() != path_before.ino() {
        return Err(io::Error::other("file identity mismatch"));
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_SH | libc::LOCK_NB) } != 0 {
        return Err(io::Error::other("file lock unavailable"));
    }
    let mut hasher = Sha256::new();
    let mut bytes = capture_limit.map(|_| Vec::with_capacity(descriptor.len() as usize));
    let mut observed = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        observed = observed
            .checked_add(count as u64)
            .ok_or_else(|| io::Error::other("file length overflow"))?;
        if observed > descriptor.len() {
            return Err(io::Error::other("file grew during measurement"));
        }
        hasher.update(&buffer[..count]);
        if let Some(bytes) = bytes.as_mut() {
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
    let descriptor_after = file.metadata()?;
    let path_after = fs::symlink_metadata(path)?;
    if observed != descriptor.len()
        || descriptor.dev() != descriptor_after.dev()
        || descriptor.ino() != descriptor_after.ino()
        || descriptor.len() != descriptor_after.len()
        || descriptor_after.dev() != path_after.dev()
        || descriptor_after.ino() != path_after.ino()
    {
        return Err(io::Error::other("file changed during measurement"));
    }
    let raw: [u8; 32] = hasher.finalize().into();
    Ok(FileMeasurement {
        digest: raw_digest(raw)?,
        bytes,
    })
}

fn validate_metadata(metadata: &fs::Metadata, capture_limit: Option<u64>) -> io::Result<()> {
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() == 0
        || capture_limit.is_some_and(|limit| metadata.len() > limit)
    {
        return Err(io::Error::other("file metadata unsafe"));
    }
    Ok(())
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("output parent unavailable"))?;
    let parent_metadata = fs::symlink_metadata(parent)?;
    if !parent_metadata.file_type().is_dir()
        || parent_metadata.uid() != unsafe { libc::geteuid() }
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::other("output parent unsafe"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != bytes.len() as u64
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err(io::Error::other("output verification failed"));
    }
    let parent_directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)?;
    parent_directory.sync_all()?;
    Ok(())
}

fn raw_digest(raw: [u8; 32]) -> Result<Sha256Digest, io::Error> {
    let mut value = String::from("sha256:");
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").map_err(|_| io::Error::other("digest failed"))?;
    }
    Sha256Digest::parse(value).map_err(|_| io::Error::other("digest invalid"))
}

fn canonical_nonzero_u32(value: &str) -> Result<u32, io::Error> {
    if value.is_empty()
        || value.len() > 10
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(io::Error::other("u32 invalid"));
    }
    let parsed = value
        .parse::<u32>()
        .map_err(|_| io::Error::other("u32 invalid"))?;
    if parsed == 0 {
        return Err(io::Error::other("u32 zero"));
    }
    Ok(parsed)
}

fn canonical_nonzero_u64(value: &str) -> Result<u64, io::Error> {
    if value.is_empty()
        || value.len() > 20
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(io::Error::other("u64 invalid"));
    }
    let parsed = value
        .parse::<u64>()
        .map_err(|_| io::Error::other("u64 invalid"))?;
    if parsed == 0 {
        return Err(io::Error::other("u64 zero"));
    }
    Ok(parsed)
}

fn inert_wheel() -> Result<Vec<u8>, io::Error> {
    const DIST_INFO: &str = "measured_inert_wheel_fixture-1.0.0.dist-info";
    let members = vec![
        (
            format!("{DIST_INFO}/METADATA"),
            b"Metadata-Version: 2.1\nName: measured-inert-wheel-fixture\nVersion: 1.0.0\n\n"
                .to_vec(),
        ),
        (
            format!("{DIST_INFO}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: whoathere-inert\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                .to_vec(),
        ),
        (
            "measured_inert_wheel_fixture/__init__.py".to_string(),
            b"VALUE = 1\n".to_vec(),
        ),
    ];
    let record_path = format!("{DIST_INFO}/RECORD");
    let mut record = String::new();
    for (path, bytes) in &members {
        record.push_str(path);
        record.push(',');
        record.push_str(&wheel_record_hash(bytes));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str(&record_path);
    record.push_str(",,\n");
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in members {
        writer
            .start_file(path, SimpleFileOptions::default())
            .map_err(io::Error::other)?;
        writer.write_all(&bytes)?;
    }
    writer
        .start_file(record_path, SimpleFileOptions::default())
        .map_err(io::Error::other)?;
    writer.write_all(record.as_bytes())?;
    writer
        .finish()
        .map(|cursor| cursor.into_inner())
        .map_err(io::Error::other)
}

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest = Sha256Digest::from_bytes(bytes);
    let digest_hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("digest prefix");
    let digest_bytes = digest_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex UTF-8"), 16).expect("hex byte")
        })
        .collect::<Vec<_>>();
    base64_url_no_pad(&digest_bytes)
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    format!("sha256={output}")
}
