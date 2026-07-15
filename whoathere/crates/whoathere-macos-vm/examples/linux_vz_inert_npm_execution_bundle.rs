use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_artifact_scenarios_v1, ArtifactProtectedTelemetryRequirementsV1,
    ArtifactRuntimeTargetV1, ArtifactScenarioCompilationRequestV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioIdentitySetV1, ArtifactScenarioPolicyV1,
    NpmEnvironmentProfileV1, NpmRuntimeProfileV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    build_macos_linux_vz_package_authority_request_v1,
    decode_qualified_macos_linux_vz_telemetry_backend_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    sign_macos_linux_vz_package_execution_grant_v1,
    verify_macos_linux_vz_package_execution_runtime_qualification_record_v1,
    MacosLinuxVzCandidatePackageRuntimeV1, MacosLinuxVzPackageArtifactKindV1,
    MacosLinuxVzPackageExecutionGrantContextV1,
    MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
};
use zeroize::Zeroize;

const GRANT_LIFETIME_SECONDS_V1: u64 = 10 * 60;
const MAXIMUM_INPUT_BYTES_V1: u64 = 16 * 1024 * 1024;

#[derive(Debug)]
struct ArgumentsV1 {
    backend_identity: PathBuf,
    qualified_backend: PathBuf,
    qualification_record: PathBuf,
    guest_public_key: PathBuf,
    host_public_key: PathBuf,
    grant_public_key: PathBuf,
    grant_signing_seed: PathBuf,
    clone_binding: PathBuf,
    output_directory: PathBuf,
}

#[derive(Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeCloneBindingWireV1 {
    schema_version: String,
    base_rootfs_sha256: Sha256Digest,
    clone_file_device: String,
    clone_file_inode: String,
    clone_implementation_sha256: Sha256Digest,
    initial_rootfs_sha256: Sha256Digest,
    run_id: String,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BundleManifestV1<'a> {
    schema_version: &'static str,
    artifact_sha256: &'a Sha256Digest,
    artifact_byte_length: String,
    scenario_plan_sha256: &'a Sha256Digest,
    scenario_template_sha256: &'a Sha256Digest,
    package_authority_request_sha256: &'a Sha256Digest,
    execution_grant_sha256: &'a Sha256Digest,
    execution_runtime_qualification_record_sha256: &'a Sha256Digest,
    qualified_telemetry_backend_sha256: &'a Sha256Digest,
    guest_evidence_public_key_sha256: &'a Sha256Digest,
    host_evidence_public_key_sha256: &'a Sha256Digest,
    execution_grant_issuer_public_key_sha256: &'a Sha256Digest,
    clone_binding_sha256: &'a Sha256Digest,
    issued_at_unix_seconds: String,
    expires_at_unix_seconds: String,
    environment: NpmEnvironmentProfileV1,
    execution_authority_issued: bool,
    attempt_limit: String,
    public_network_route_present: bool,
    sync_back: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere_linux_vz_inert_npm_execution_bundle_failed:{error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = parse_arguments_v1()?;
    validate_empty_private_directory_v1(&arguments.output_directory)?;
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend_identity_bytes = read_regular_bounded_v1(
        &arguments.backend_identity,
        MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1 as u64,
    )?;
    let backend_identity = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &backend_identity_bytes,
        &requirements,
    )?;
    let qualified_backend_bytes = read_regular_bounded_v1(
        &arguments.qualified_backend,
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
    )?;
    let qualified_backend = decode_qualified_macos_linux_vz_telemetry_backend_v1(
        &qualified_backend_bytes,
        &backend_identity,
    )?;
    let qualification_record_bytes = read_regular_bounded_v1(
        &arguments.qualification_record,
        MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1 as u64,
    )?;
    let guest_public_key = read_exact_key_v1(&arguments.guest_public_key)?;
    let host_public_key = read_exact_key_v1(&arguments.host_public_key)?;
    let grant_public_key = read_exact_key_v1(&arguments.grant_public_key)?;
    let mut grant_signing_seed = read_exact_key_v1(&arguments.grant_signing_seed)?;
    let qualification = verify_macos_linux_vz_package_execution_runtime_qualification_record_v1(
        &qualification_record_bytes,
        &qualified_backend,
        guest_public_key,
        host_public_key,
        grant_public_key,
    )?;
    let candidate_runtime =
        MacosLinuxVzCandidatePackageRuntimeV1::from_verified_execution_runtime_qualification_v1(
            &qualification,
        )?;
    let clone_binding_bytes = read_regular_bounded_v1(&arguments.clone_binding, 64 * 1024)?;
    let clone_binding: RuntimeCloneBindingWireV1 = serde_json::from_slice(&clone_binding_bytes)?;
    let canonical_clone_binding = serde_json_canonicalizer::to_vec(&clone_binding)?;
    if canonical_clone_binding != clone_binding_bytes
        || clone_binding.schema_version != "whoathere.linux_vz_package_runtime_clone_binding.v1"
        || clone_binding.base_rootfs_sha256 != *qualification.execution_runtime_rootfs_sha256()
        || clone_binding.initial_rootfs_sha256 != *qualification.execution_runtime_rootfs_sha256()
        || !canonical_nonzero_decimal_v1(&clone_binding.clone_file_device)
        || !canonical_nonzero_decimal_v1(&clone_binding.clone_file_inode)
        || !valid_run_id_v1(&clone_binding.run_id)
    {
        return Err(io::Error::other("runtime clone binding invalid").into());
    }
    let clone_binding_sha256 = Sha256Digest::from_bytes(&clone_binding_bytes);

    let artifact_bytes = inert_npm_tgz_v1()?;
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("whoathere-inert-execution-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:whoathere-inert-execution-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-15T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "whoathere-inert-execution-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "purpose-built-inert-linux-vz-execution-gate-v1".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "linux-vz-inert-execution-gate.v1".to_string(),
            requires_external_dependency_resolution: false,
        },
        &artifact_bytes,
        ArtifactFormat::NpmTarGzip,
    );
    let normalized =
        normalize_artifact(&envelope, &artifact_bytes, NormalizationLimits::default())?;
    let cas_key =
        canonical_cas_object_key_for_artifact(normalized.manifest.artifact_sha256.as_str())
            .map_err(|_| io::Error::other("artifact CAS key invalid"))?;
    let subject = ArtifactEvidenceSubjectV2::new(
        normalized.manifest.artifact_sha256.as_str(),
        envelope.envelope_sha256()?.as_str(),
        normalized.manifest.manifest_sha256.as_str(),
        cas_key,
    )
    .map_err(|_| io::Error::other("artifact evidence subject invalid"))?;
    let runtime = NpmRuntimeProfileV1::new_for_target(
        ArtifactRuntimeTargetV1::LinuxArm64,
        "linux-arm64-node24-npm11-qualified-runtime-v1",
        qualification.node_version(),
        qualification.node_executable_sha256().clone(),
        qualification.npm_version(),
        qualification.npm_cli_sha256().clone(),
    )?;
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        envelope.original_sha256.clone(),
        runtime,
    )?;
    let identities = ArtifactScenarioIdentitySetV1::new(
        "linux-vz-inert-execution-gate-plan-v1",
        ArtifactScenarioExecutionIdentityV1::new(
            "linux-vz-inert-execution-gate-job-ci-false-v1",
            "linux-vz-inert-execution-gate-run-ci-false-v1",
            "linux-vz-inert-execution-gate-evidence-ci-false-v1",
            "linux-vz-inert-execution-gate-scenario-ci-false-v1",
        )?,
        ArtifactScenarioExecutionIdentityV1::new(
            "linux-vz-inert-execution-gate-job-ci-true-v1",
            "linux-vz-inert-execution-gate-run-ci-true-v1",
            "linux-vz-inert-execution-gate-evidence-ci-true-v1",
            "linux-vz-inert-execution-gate-scenario-ci-true-v1",
        )?,
    )?;
    let plan = compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &normalized.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })?;
    let plan_bytes = plan.canonical_json_v1()?;
    let template = plan
        .templates()
        .iter()
        .find(|template| {
            template.scenario_kind().environment() == Some(NpmEnvironmentProfileV1::CiTrue)
        })
        .ok_or_else(|| io::Error::other("CI=true template unavailable"))?;
    let template_bytes = template.canonical_json_v1()?;

    let request_challenge = random_nonzero_v1()?;
    let authority_request = build_macos_linux_vz_package_authority_request_v1(
        &qualified_backend,
        MacosLinuxVzPackageArtifactKindV1::NpmTarball,
        &artifact_bytes,
        &plan_bytes,
        &template_bytes,
        &candidate_runtime,
        request_challenge,
        clone_binding_sha256.clone(),
    )?;
    let issued_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let grant_challenge = random_nonzero_v1()?;
    let attempt_binding = Sha256Digest::from_bytes(&random_nonzero_v1()?);
    let grant_context = MacosLinuxVzPackageExecutionGrantContextV1::new(
        &authority_request,
        &qualification,
        grant_challenge,
        attempt_binding,
        issued_at,
        GRANT_LIFETIME_SECONDS_V1,
    )?;
    let execution_grant =
        sign_macos_linux_vz_package_execution_grant_v1(&grant_context, grant_signing_seed)?;
    grant_signing_seed.zeroize();
    let execution_grant_sha256 = Sha256Digest::from_bytes(execution_grant.as_bytes());
    let expires_at = issued_at + GRANT_LIFETIME_SECONDS_V1;

    write_new_private_v1(
        &arguments.output_directory.join("artifact.tgz"),
        &artifact_bytes,
    )?;
    write_new_private_v1(
        &arguments.output_directory.join("scenario-plan.json"),
        &plan_bytes,
    )?;
    write_new_private_v1(
        &arguments.output_directory.join("scenario-template.json"),
        &template_bytes,
    )?;
    write_new_private_v1(
        &arguments
            .output_directory
            .join("package-authority-request.json"),
        authority_request.canonical_json_v1(),
    )?;
    write_new_private_v1(
        &arguments.output_directory.join("execution-grant.json"),
        execution_grant.as_bytes(),
    )?;
    write_new_private_v1(
        &arguments
            .output_directory
            .join("execution-runtime-qualification-record.json"),
        &qualification_record_bytes,
    )?;
    write_new_private_v1(
        &arguments.output_directory.join("backend-identity.json"),
        &backend_identity_bytes,
    )?;
    write_new_private_v1(
        &arguments.output_directory.join("qualified-backend.json"),
        &qualified_backend_bytes,
    )?;
    write_new_private_v1(
        &arguments
            .output_directory
            .join("runtime-clone-binding.json"),
        &clone_binding_bytes,
    )?;
    write_new_private_v1(
        &arguments
            .output_directory
            .join("guest-ed25519-public-key.bin"),
        &guest_public_key,
    )?;
    write_new_private_v1(
        &arguments
            .output_directory
            .join("host-ed25519-public-key.bin"),
        &host_public_key,
    )?;
    write_new_private_v1(
        &arguments
            .output_directory
            .join("grant-issuer-ed25519-public-key.bin"),
        &grant_public_key,
    )?;
    let manifest = BundleManifestV1 {
        schema_version: "whoathere.linux_vz_inert_npm_execution_bundle.v1",
        artifact_sha256: authority_request.artifact_sha256(),
        artifact_byte_length: authority_request.artifact_byte_length().to_string(),
        scenario_plan_sha256: authority_request.scenario_plan_sha256(),
        scenario_template_sha256: authority_request.scenario_template_sha256(),
        package_authority_request_sha256: authority_request.request_sha256(),
        execution_grant_sha256: &execution_grant_sha256,
        execution_runtime_qualification_record_sha256: qualification.qualification_record_sha256(),
        qualified_telemetry_backend_sha256: qualification.qualified_telemetry_backend_sha256(),
        guest_evidence_public_key_sha256: qualification.guest_evidence_public_key_sha256(),
        host_evidence_public_key_sha256: qualification.host_evidence_public_key_sha256(),
        execution_grant_issuer_public_key_sha256: qualification
            .execution_grant_issuer_public_key_sha256(),
        clone_binding_sha256: &clone_binding_sha256,
        issued_at_unix_seconds: issued_at.to_string(),
        expires_at_unix_seconds: expires_at.to_string(),
        environment: NpmEnvironmentProfileV1::CiTrue,
        execution_authority_issued: true,
        attempt_limit: "1".to_string(),
        public_network_route_present: false,
        sync_back: false,
    };
    let manifest_bytes = serde_json_canonicalizer::to_vec(&manifest)?;
    write_new_private_v1(
        &arguments.output_directory.join("bundle-manifest.json"),
        &manifest_bytes,
    )?;

    println!(
        "{{\"artifact_sha256\":\"{}\",\"execution_authority_issued\":true,\"execution_grant_sha256\":\"{}\",\"execution_runtime_qualification_record_sha256\":\"{}\",\"expires_at_unix_seconds\":\"{}\",\"package_authority_request_sha256\":\"{}\",\"public_network_route_present\":false,\"schema_version\":\"whoathere.linux_vz_inert_npm_execution_bundle_build_result.v1\",\"sync_back\":false}}",
        authority_request.artifact_sha256(),
        execution_grant_sha256,
        qualification.qualification_record_sha256(),
        expires_at,
        authority_request.request_sha256(),
    );
    Ok(())
}

fn parse_arguments_v1() -> Result<ArgumentsV1, io::Error> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut parsed = std::collections::BTreeMap::new();
    while let Some(name) = arguments.next() {
        let name = name
            .into_string()
            .map_err(|_| io::Error::other("argument name invalid"))?;
        let value = arguments
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::other("argument value missing"))?;
        if !matches!(
            name.as_str(),
            "--backend-identity"
                | "--qualified-backend"
                | "--qualification-record"
                | "--guest-public-key"
                | "--host-public-key"
                | "--grant-public-key"
                | "--grant-signing-seed"
                | "--clone-binding"
                | "--output-directory"
        ) || parsed.insert(name, value).is_some()
        {
            return Err(io::Error::other("argument invalid"));
        }
    }
    if parsed.len() != 9 || parsed.values().any(|path| !path.is_absolute()) {
        return Err(io::Error::other("absolute arguments required"));
    }
    let mut take = |name: &str| {
        parsed
            .remove(name)
            .ok_or_else(|| io::Error::other("required argument missing"))
    };
    Ok(ArgumentsV1 {
        backend_identity: take("--backend-identity")?,
        qualified_backend: take("--qualified-backend")?,
        qualification_record: take("--qualification-record")?,
        guest_public_key: take("--guest-public-key")?,
        host_public_key: take("--host-public-key")?,
        grant_public_key: take("--grant-public-key")?,
        grant_signing_seed: take("--grant-signing-seed")?,
        clone_binding: take("--clone-binding")?,
        output_directory: take("--output-directory")?,
    })
}

fn validate_empty_private_directory_v1(path: &Path) -> Result<(), io::Error> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
        || fs::read_dir(path)?.next().is_some()
    {
        return Err(io::Error::other("output directory unsafe"));
    }
    Ok(())
}

fn read_regular_bounded_v1(path: &Path, maximum: u64) -> Result<Vec<u8>, io::Error> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(io::Error::other("input invalid"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(io::Error::other("input changed"));
    }
    Ok(bytes)
}

fn read_exact_key_v1(path: &Path) -> Result<[u8; 32], io::Error> {
    let bytes = read_regular_bounded_v1(path, 32)?;
    bytes
        .try_into()
        .map_err(|_| io::Error::other("key length invalid"))
}

fn write_new_private_v1(path: &Path, bytes: &[u8]) -> Result<(), io::Error> {
    if bytes.is_empty() || bytes.len() as u64 > MAXIMUM_INPUT_BYTES_V1 {
        return Err(io::Error::other("output invalid"));
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn random_nonzero_v1() -> Result<[u8; 32], io::Error> {
    let mut value = [0_u8; 32];
    getrandom::fill(&mut value).map_err(|_| io::Error::other("entropy unavailable"))?;
    if value == [0_u8; 32] {
        return Err(io::Error::other("entropy invalid"));
    }
    Ok(value)
}

fn canonical_nonzero_decimal_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 20
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && value.parse::<u64>().is_ok_and(|parsed| parsed > 0)
}

fn valid_run_id_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn inert_npm_tgz_v1() -> Result<Vec<u8>, io::Error> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, bytes) in [
        (
            "package/package.json",
            br#"{"name":"whoathere-inert-execution-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#
                .as_slice(),
        ),
        (
            "package/post.js",
            br#"require("fs").writeFileSync("whoathere-inert-postinstall-marker","purpose-built-inert-v1\n");"#
                .as_slice(),
        ),
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
