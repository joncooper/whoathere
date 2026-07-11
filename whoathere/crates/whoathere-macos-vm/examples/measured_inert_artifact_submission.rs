use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_artifact_scenarios_v1, ArtifactScenarioCompilationRequestV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioIdentitySetV1, ArtifactScenarioPolicyV1,
    NpmRuntimeProfileV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    compile_macos_artifact_run_spec_v1, write_macos_artifact_submission_frame_v1,
    MacosArtifactBackendCapabilitiesV1, MacosArtifactBackendIdentityV1,
    MacosArtifactSubmissionBindingsV1, MacosArtifactSubmissionHeaderV1,
};

const RECEIPT_SCHEMA_V1: &str = "whoathere.artifact_supervisor_provisioning.v1";
const CLONE_IMPLEMENTATION_ID_V1: &[u8] = b"whoathere.swift.fclonefileat.direct.v1";
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProvisioningReceiptV1 {
    artifact_vsock_port: String,
    base_generation_id: String,
    clone_implementation_sha256: Sha256Digest,
    cpu_count: String,
    guest_auth_public_key_sha256: Sha256Digest,
    guest_supervisor_sha256: Sha256Digest,
    memory_mib: String,
    node_executable_sha256: Sha256Digest,
    node_version: String,
    npm_cli_sha256: Sha256Digest,
    npm_version: String,
    package_execution_enabled: bool,
    package_gid: String,
    package_uid: String,
    package_username: String,
    runner_configuration_sha256: Sha256Digest,
    schema_version: String,
    sync_back_enabled: bool,
}

fn main() {
    if run().is_err() {
        eprintln!("measured_inert_artifact_submission_failed");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let (state_dir, helper) = parse_arguments()?;
    let bundle = state_dir.join("bundle");
    let disk = measure_file(&bundle.join("disk.img"), None)?;
    let auxiliary = measure_file(&bundle.join("auxiliary-storage"), None)?;
    let hardware = measure_file(&bundle.join("hardware-model.bin"), Some(MAX_METADATA_BYTES))?;
    let machine = measure_file(
        &bundle.join("machine-identifier.bin"),
        Some(MAX_METADATA_BYTES),
    )?;
    let receipt_measurement = measure_file(
        &bundle.join("artifact-supervisor-provisioning.json"),
        Some(MAX_METADATA_BYTES),
    )?;
    let public_key = measure_file(&bundle.join("artifact-supervisor-public-key.bin"), Some(32))?;
    let helper = measure_file(&helper, None)?;
    let receipt_bytes = receipt_measurement
        .bytes
        .as_deref()
        .ok_or_else(|| io::Error::other("receipt bytes unavailable"))?;
    let receipt = decode_receipt(receipt_bytes)?;
    let public_key_bytes = public_key
        .bytes
        .as_deref()
        .ok_or_else(|| io::Error::other("public key bytes unavailable"))?;
    if public_key_bytes.len() != 32
        || public_key.digest != receipt.guest_auth_public_key_sha256
        || receipt.package_execution_enabled
        || receipt.sync_back_enabled
        || receipt.artifact_vsock_port != "47079"
        || receipt.package_username != "_whoatherepkg"
        || receipt.clone_implementation_sha256
            != Sha256Digest::from_bytes(CLONE_IMPLEMENTATION_ID_V1)
    {
        return Err(io::Error::other("receipt measurement mismatch").into());
    }

    let package_uid = canonical_nonzero_u32(&receipt.package_uid)?;
    let package_gid = canonical_nonzero_u32(&receipt.package_gid)?;
    let cpu_count = u16::try_from(canonical_nonzero_u32(&receipt.cpu_count)?)
        .map_err(|_| io::Error::other("CPU count invalid"))?;
    let memory_mib = canonical_nonzero_u64(&receipt.memory_mib)?;
    let artifact_bytes = inert_npm_tgz()?;
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("measured-inert-vm-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:measured-inert-vm-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-10T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "measured-inert-vm-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "repository-inert-measured-vm-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "macos-artifact-measured-inert.v1".to_string(),
            requires_external_dependency_resolution: false,
        },
        &artifact_bytes,
        ArtifactFormat::NpmTarGzip,
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
    let runtime = NpmRuntimeProfileV1::new(
        "macos-arm64-measured-inert",
        receipt.node_version.clone(),
        receipt.node_executable_sha256.clone(),
        receipt.npm_version.clone(),
        receipt.npm_cli_sha256.clone(),
    )?;
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        envelope.original_sha256.clone(),
        runtime,
    )?;
    let identities = ArtifactScenarioIdentitySetV1::new(
        "measured-inert-plan",
        ArtifactScenarioExecutionIdentityV1::new(
            "measured-inert-job-false",
            "measured-inert-run-false",
            "measured-inert-evidence-false",
            "measured-inert-scenario-false",
        )?,
        ArtifactScenarioExecutionIdentityV1::new(
            "measured-inert-job-true",
            "measured-inert-run-true",
            "measured-inert-evidence-true",
            "measured-inert-scenario-true",
        )?,
    )?;
    let plan = compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &artifact.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })?;
    let backend =
        MacosArtifactBackendCapabilitiesV1::inert_first_slice(MacosArtifactBackendIdentityV1::new(
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
            receipt.node_version,
            receipt.node_executable_sha256,
            receipt.npm_version,
            receipt.npm_cli_sha256,
            receipt.clone_implementation_sha256,
        )?);
    let run_spec = compile_macos_artifact_run_spec_v1(&plan.templates()[0], &backend)?;
    let mut challenge = [0_u8; 32];
    getrandom::fill(&mut challenge)
        .map_err(|_| io::Error::other("challenge entropy unavailable"))?;
    let bindings = MacosArtifactSubmissionBindingsV1::for_run_spec(
        Sha256Digest::from_bytes(&challenge),
        &run_spec,
    );
    let header = MacosArtifactSubmissionHeaderV1::new(run_spec, bindings)?;
    write_macos_artifact_submission_frame_v1(&mut io::stdout().lock(), &header, &artifact_bytes)?;
    Ok(())
}

fn parse_arguments() -> Result<(PathBuf, PathBuf), io::Error> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut state_dir = None;
    let mut helper = None;
    while let Some(argument) = arguments.next() {
        if argument == "--state-dir" {
            state_dir = arguments.next().map(PathBuf::from);
        } else if argument == "--helper" {
            helper = arguments.next().map(PathBuf::from);
        } else {
            return Err(io::Error::other("unknown argument"));
        }
    }
    let state_dir = state_dir.ok_or_else(|| io::Error::other("state directory required"))?;
    let helper = helper.ok_or_else(|| io::Error::other("helper required"))?;
    if !state_dir.is_absolute() || !helper.is_absolute() {
        return Err(io::Error::other("absolute paths required"));
    }
    Ok((state_dir, helper))
}

fn decode_receipt(bytes: &[u8]) -> Result<ProvisioningReceiptV1, io::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let receipt = ProvisioningReceiptV1::deserialize(&mut deserializer)
        .map_err(|_| io::Error::other("receipt invalid"))?;
    deserializer
        .end()
        .map_err(|_| io::Error::other("receipt trailing data"))?;
    let canonical = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| io::Error::other("receipt canonicalization failed"))?;
    if canonical != bytes || receipt.schema_version != RECEIPT_SCHEMA_V1 {
        return Err(io::Error::other("receipt noncanonical"));
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

use std::os::fd::AsRawFd;

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
    let value = value
        .parse::<u32>()
        .map_err(|_| io::Error::other("u32 invalid"))?;
    if value == 0 {
        return Err(io::Error::other("u32 zero"));
    }
    Ok(value)
}

fn canonical_nonzero_u64(value: &str) -> Result<u64, io::Error> {
    if value.is_empty()
        || value.len() > 20
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(io::Error::other("u64 invalid"));
    }
    let value = value
        .parse::<u64>()
        .map_err(|_| io::Error::other("u64 invalid"))?;
    if value == 0 {
        return Err(io::Error::other("u64 zero"));
    }
    Ok(value)
}

fn inert_npm_tgz() -> Result<Vec<u8>, io::Error> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, bytes) in [
        (
            "package/package.json",
            br#"{"name":"measured-inert-vm-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#
                .as_slice(),
        ),
        ("package/post.js", b"process.exit(0)".as_slice()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive.append_data(&mut header, path, Cursor::new(bytes))?;
    }
    archive.into_inner()?.finish()
}
