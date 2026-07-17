use serde::Serialize;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use whoathere_artifact::{
    detect_artifact_format, normalize_artifact, AcquisitionMethod, ArtifactEnvelope,
    ArtifactEnvelopeInput, ArtifactFormat, ArtifactManifest, ArtifactSourceType, Ecosystem,
    NormalizationLimits, NormalizedArtifact, Sha256Digest,
};
use whoathere_detonation::{
    compile_artifact_scenarios_with_npm_closure_v1, npm_runtime_dependency_requirements_v1,
    ArtifactProtectedTelemetryRequirementsV1, ArtifactRuntimeTargetV1,
    ArtifactScenarioCompilationRequestV1, ArtifactScenarioExecutionIdentityV1,
    ArtifactScenarioIdentitySetV1, ArtifactScenarioPolicyV1, NpmEnvironmentProfileV1,
    NpmRuntimeProfileV1, SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1,
    SdistBuildClosureV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    build_macos_linux_vz_package_authority_request_v1, decode_macos_sdist_build_closure_frame_v1,
    decode_qualified_macos_linux_vz_telemetry_backend_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    sign_macos_linux_vz_package_execution_grant_v1,
    verify_macos_linux_vz_package_execution_runtime_qualification_record_v1,
    MacosLinuxVzCandidatePackageRuntimeV1, MacosLinuxVzPackageArtifactKindV1,
    MacosLinuxVzPackageExecutionGrantContextV1, MACOS_SDIST_BUILD_CLOSURE_MAGIC_V1,
    MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1,
    MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
    MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1,
    MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1,
};
use zeroize::Zeroize;

const GRANT_LIFETIME_SECONDS_V1: u64 = 10 * 60;
const MAXIMUM_INPUT_BYTES_V1: u64 = 16 * 1024 * 1024;
const MAXIMUM_ARTIFACT_ENVELOPE_BYTES_V1: u64 = 1024 * 1024;

#[derive(Debug)]
struct ArgumentsV1 {
    artifact: PathBuf,
    artifact_envelope: Option<PathBuf>,
    artifact_manifest: Option<PathBuf>,
    build_closure: Option<PathBuf>,
    environment: NpmEnvironmentProfileV1,
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
    dependency_closure_sha256: Option<&'a Sha256Digest>,
    build_closure_payload_present: bool,
    build_closure_payload_sha256: Option<&'a Sha256Digest>,
    build_closure_payload_byte_length: String,
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

    let artifact_bytes = read_regular_bounded_v1(&arguments.artifact, MAXIMUM_INPUT_BYTES_V1)?;
    let bindings = load_artifact_bindings_v1(
        &arguments.artifact,
        arguments.artifact_envelope.as_deref(),
        arguments.artifact_manifest.as_deref(),
        &artifact_bytes,
    )?;
    let envelope = bindings.envelope;
    let normalized = bindings.normalized;
    let (dependency_closure, build_closure_payload) = resolve_npm_dependency_closure_v1(
        arguments.build_closure.as_deref(),
        &normalized.manifest,
    )?;
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
    let plan = compile_artifact_scenarios_with_npm_closure_v1(
        ArtifactScenarioCompilationRequestV1 {
            envelope: &envelope,
            manifest: &normalized.manifest,
            subject: &subject,
            policy: &policy,
            identities: &identities,
        },
        dependency_closure.as_ref(),
    )?;
    let plan_bytes = plan.canonical_json_v1()?;
    let template = plan
        .templates()
        .iter()
        .find(|template| template.scenario_kind().environment() == Some(arguments.environment))
        .ok_or_else(|| io::Error::other("requested environment template unavailable"))?;
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
        &arguments.output_directory.join("artifact.bin"),
        &artifact_bytes,
    )?;
    let build_closure_payload_sha256 = (!build_closure_payload.is_empty())
        .then(|| Sha256Digest::from_bytes(&build_closure_payload));
    if !build_closure_payload.is_empty() {
        write_new_private_v1(
            &arguments.output_directory.join("build-closure.bin"),
            &build_closure_payload,
        )?;
    }
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
        environment: arguments.environment,
        dependency_closure_sha256: dependency_closure
            .as_ref()
            .map(SdistBuildClosureV1::closure_sha256),
        build_closure_payload_present: build_closure_payload_sha256.is_some(),
        build_closure_payload_sha256: build_closure_payload_sha256.as_ref(),
        build_closure_payload_byte_length: build_closure_payload.len().to_string(),
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

fn resolve_npm_dependency_closure_v1(
    frame_path: Option<&Path>,
    manifest: &ArtifactManifest,
) -> Result<(Option<SdistBuildClosureV1>, Vec<u8>), io::Error> {
    let requirements = npm_runtime_dependency_requirements_v1(manifest)
        .map_err(|_| io::Error::other("npm dependency declarations unsupported"))?;
    if requirements.is_empty() {
        if frame_path.is_some() {
            return Err(io::Error::other("npm dependency closure unexpected"));
        }
        return Ok((None, Vec::new()));
    }
    let path = frame_path.ok_or_else(|| io::Error::other("npm dependency closure required"))?;
    let maximum = (MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1
        + MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1) as u64
        + MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1;
    let frame = read_regular_bounded_v1(path, maximum)?;
    let closure = closure_from_frame_manifest_v1(&frame)?;
    let expected = SdistBuildClosureV1::new(&requirements, closure.artifacts().to_vec())
        .map_err(|_| io::Error::other("npm dependency closure declarations mismatch"))?;
    if expected != closure {
        return Err(io::Error::other(
            "npm dependency closure declarations mismatch",
        ));
    }
    let (payload, _) = decode_macos_sdist_build_closure_frame_v1(&frame, &closure)
        .map_err(|_| io::Error::other("npm dependency closure frame invalid"))?;
    validate_exact_npm_closure_artifacts_v1(&closure, &payload)?;
    Ok((Some(closure), payload))
}

fn closure_from_frame_manifest_v1(bytes: &[u8]) -> Result<SdistBuildClosureV1, io::Error> {
    if bytes.len() < MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1
        || &bytes[..8] != MACOS_SDIST_BUILD_CLOSURE_MAGIC_V1
    {
        return Err(io::Error::other("npm dependency closure frame invalid"));
    }
    let manifest_length = u32::from_be_bytes(
        bytes[12..16]
            .try_into()
            .map_err(|_| io::Error::other("npm dependency closure frame invalid"))?,
    ) as usize;
    if manifest_length == 0 || manifest_length > MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1 {
        return Err(io::Error::other("npm dependency closure manifest invalid"));
    }
    let end = MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1
        .checked_add(manifest_length)
        .filter(|end| *end <= bytes.len())
        .ok_or_else(|| io::Error::other("npm dependency closure frame invalid"))?;
    let manifest_bytes = &bytes[MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1..end];
    let closure: SdistBuildClosureV1 = serde_json::from_slice(manifest_bytes)
        .map_err(|_| io::Error::other("npm dependency closure manifest invalid"))?;
    if closure
        .canonical_json_v1()
        .map_err(|_| io::Error::other("npm dependency closure manifest invalid"))?
        != manifest_bytes
    {
        return Err(io::Error::other(
            "npm dependency closure manifest noncanonical",
        ));
    }
    Ok(closure)
}

fn validate_exact_npm_closure_artifacts_v1(
    closure: &SdistBuildClosureV1,
    payload: &[u8],
) -> Result<(), io::Error> {
    if closure.artifacts().is_empty()
        || closure.artifacts().iter().any(|artifact| {
            artifact.artifact_format() != SdistBuildClosureArtifactFormatV1::NpmTarGzip
        })
    {
        return Err(io::Error::other("npm dependency closure artifact invalid"));
    }
    let available = closure
        .artifacts()
        .iter()
        .map(SdistBuildClosureArtifactV1::normalized_name)
        .collect::<std::collections::BTreeSet<_>>();
    let mut offset = 0_usize;
    for descriptor in closure.artifacts() {
        let length = usize::try_from(descriptor.artifact_byte_length())
            .map_err(|_| io::Error::other("npm dependency closure payload invalid"))?;
        let end = offset
            .checked_add(length)
            .filter(|end| *end <= payload.len())
            .ok_or_else(|| io::Error::other("npm dependency closure payload invalid"))?;
        let normalized =
            normalize_exact_npm_closure_artifact_v1(descriptor, &payload[offset..end])?;
        for requirement in npm_runtime_dependency_requirements_v1(&normalized.manifest)
            .map_err(|_| io::Error::other("npm transitive dependency unsupported"))?
        {
            let name = requirement
                .split_ascii_whitespace()
                .next()
                .unwrap_or_default()
                .replace(['_', '.'], "-")
                .to_ascii_lowercase();
            if !available.contains(name.as_str()) {
                return Err(io::Error::other(
                    "npm dependency closure transitive artifact missing",
                ));
            }
        }
        offset = end;
    }
    if offset != payload.len() {
        return Err(io::Error::other("npm dependency closure payload invalid"));
    }
    Ok(())
}

fn normalize_exact_npm_closure_artifact_v1(
    descriptor: &SdistBuildClosureArtifactV1,
    bytes: &[u8],
) -> Result<NormalizedArtifact, io::Error> {
    if detect_artifact_format(Ecosystem::Npm, descriptor.artifact_filename(), bytes)
        .map_err(|_| io::Error::other("npm dependency artifact format invalid"))?
        != ArtifactFormat::NpmTarGzip
    {
        return Err(io::Error::other("npm dependency artifact format invalid"));
    }
    let mut normalized = None;
    for requires_external_dependency_resolution in [false, true] {
        let envelope = ArtifactEnvelope::from_original_bytes(
            ArtifactEnvelopeInput {
                ecosystem: Ecosystem::Npm,
                package_name: Some(descriptor.normalized_name().to_string()),
                package_version: Some(descriptor.version().to_string()),
                source_coordinate: format!("local-file:{}", Sha256Digest::from_bytes(bytes)),
                source_type: ArtifactSourceType::LocalFile,
                acquired_at: "2026-07-15T00:00:00Z".to_string(),
                acquisition_method: AcquisitionMethod::LocalFileImport,
                original_filename: descriptor.artifact_filename().to_string(),
                declared_format: Some(ArtifactFormat::NpmTarGzip),
                custody_reference: "sealed-exact-npm-dependency-closure".to_string(),
                resolver_metadata_sha256: None,
                registry_metadata_sha256: None,
                policy_version: "linux-vz-exact-npm-closure.v1".to_string(),
                requires_external_dependency_resolution,
            },
            bytes,
            ArtifactFormat::NpmTarGzip,
        );
        if let Ok(candidate) = normalize_artifact(&envelope, bytes, NormalizationLimits::default())
        {
            normalized = Some(candidate);
            break;
        }
    }
    let normalized = normalized
        .ok_or_else(|| io::Error::other("npm dependency artifact normalization failed"))?;
    let identity = normalized
        .manifest
        .identity
        .as_ref()
        .ok_or_else(|| io::Error::other("npm dependency artifact identity missing"))?;
    if identity.normalized_name != descriptor.normalized_name()
        || identity.version != descriptor.version()
        || normalized.manifest.magic_detected_format != ArtifactFormat::NpmTarGzip
        || !normalized.manifest.native_binary_file_ids.is_empty()
        || normalized
            .manifest
            .metadata
            .npm
            .as_ref()
            .is_none_or(|npm| npm.implicit_node_gyp_rebuild)
    {
        return Err(io::Error::other("npm dependency artifact binding invalid"));
    }
    Ok(normalized)
}

struct ArtifactBindingsV1 {
    envelope: ArtifactEnvelope,
    normalized: NormalizedArtifact,
}

fn load_artifact_bindings_v1(
    artifact_path: &Path,
    envelope_path: Option<&Path>,
    manifest_path: Option<&Path>,
    artifact_bytes: &[u8],
) -> Result<ArtifactBindingsV1, io::Error> {
    match (envelope_path, manifest_path) {
        (Some(envelope_path), Some(manifest_path)) => {
            let envelope_bytes =
                read_regular_bounded_v1(envelope_path, MAXIMUM_ARTIFACT_ENVELOPE_BYTES_V1)?;
            let manifest_bytes = read_regular_bounded_v1(manifest_path, MAXIMUM_INPUT_BYTES_V1)?;
            validate_outer_artifact_bindings_v1(artifact_bytes, &envelope_bytes, &manifest_bytes)
        }
        (None, None) => {
            let artifact_sha256 = Sha256Digest::from_bytes(artifact_bytes);
            let original_filename = artifact_path
                .file_name()
                .and_then(|value| value.to_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| io::Error::other("artifact filename invalid"))?
                .to_string();
            let envelope = ArtifactEnvelope::from_original_bytes(
                ArtifactEnvelopeInput {
                    ecosystem: Ecosystem::Npm,
                    package_name: None,
                    package_version: None,
                    source_coordinate: format!("local-file:{artifact_sha256}"),
                    source_type: ArtifactSourceType::LocalFile,
                    acquired_at: "2026-07-15T00:00:00Z".to_string(),
                    acquisition_method: AcquisitionMethod::LocalFileImport,
                    original_filename,
                    declared_format: Some(ArtifactFormat::NpmTarGzip),
                    custody_reference: "caller-supplied-local-artifact-path".to_string(),
                    resolver_metadata_sha256: None,
                    registry_metadata_sha256: None,
                    policy_version: "linux-vz-inert-execution-gate.v1".to_string(),
                    // The v1 npm execution compiler still supports only exact,
                    // dependency-free tarballs.
                    requires_external_dependency_resolution: false,
                },
                artifact_bytes,
                ArtifactFormat::NpmTarGzip,
            );
            let normalized =
                normalize_artifact(&envelope, artifact_bytes, NormalizationLimits::default())
                    .map_err(|_| io::Error::other("artifact normalization failed"))?;
            Ok(ArtifactBindingsV1 {
                envelope,
                normalized,
            })
        }
        _ => Err(io::Error::other(
            "artifact envelope and manifest must be supplied together",
        )),
    }
}

fn validate_outer_artifact_bindings_v1(
    artifact_bytes: &[u8],
    envelope_bytes: &[u8],
    manifest_bytes: &[u8],
) -> Result<ArtifactBindingsV1, io::Error> {
    let envelope: ArtifactEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|_| io::Error::other("artifact envelope invalid"))?;
    let canonical_envelope = envelope
        .canonical_json()
        .map_err(|_| io::Error::other("artifact envelope invalid"))?;
    if canonical_envelope != envelope_bytes
        || envelope.ecosystem != Ecosystem::Npm
        || envelope.magic_detected_format != ArtifactFormat::NpmTarGzip
        || !envelope.matches_original_bytes(artifact_bytes)
    {
        return Err(io::Error::other("artifact envelope binding invalid"));
    }
    let detected = detect_artifact_format(
        envelope.ecosystem,
        &envelope.original_filename,
        artifact_bytes,
    )
    .map_err(|_| io::Error::other("artifact format invalid"))?;
    if detected != ArtifactFormat::NpmTarGzip || !envelope.verify_magic_format(detected) {
        return Err(io::Error::other("artifact format binding invalid"));
    }

    let supplied_manifest: ArtifactManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| io::Error::other("artifact manifest invalid"))?;
    let normalized = normalize_artifact(&envelope, artifact_bytes, NormalizationLimits::default())
        .map_err(|_| io::Error::other("artifact normalization failed"))?;
    if supplied_manifest != normalized.manifest {
        return Err(io::Error::other("artifact manifest binding invalid"));
    }
    Ok(ArtifactBindingsV1 {
        envelope,
        normalized,
    })
}

fn parse_arguments_v1() -> Result<ArgumentsV1, io::Error> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut paths = std::collections::BTreeMap::new();
    let mut environment = None;
    while let Some(name) = arguments.next() {
        let name = name
            .into_string()
            .map_err(|_| io::Error::other("argument name invalid"))?;
        let value = arguments
            .next()
            .ok_or_else(|| io::Error::other("argument value missing"))?;
        match name.as_str() {
            "--environment" => {
                let value = value
                    .into_string()
                    .map_err(|_| io::Error::other("environment invalid"))?;
                let parsed = match value.as_str() {
                    "ci_false" => NpmEnvironmentProfileV1::CiFalse,
                    "ci_true" => NpmEnvironmentProfileV1::CiTrue,
                    _ => return Err(io::Error::other("environment invalid")),
                };
                if environment.replace(parsed).is_some() {
                    return Err(io::Error::other("argument invalid"));
                }
            }
            "--artifact"
            | "--artifact-envelope"
            | "--artifact-manifest"
            | "--build-closure"
            | "--backend-identity"
            | "--qualified-backend"
            | "--qualification-record"
            | "--guest-public-key"
            | "--host-public-key"
            | "--grant-public-key"
            | "--grant-signing-seed"
            | "--clone-binding"
            | "--output-directory" => {
                if paths.insert(name, PathBuf::from(value)).is_some() {
                    return Err(io::Error::other("argument invalid"));
                }
            }
            _ => return Err(io::Error::other("argument invalid")),
        }
    }
    if paths.values().any(|path| !path.is_absolute()) {
        return Err(io::Error::other("absolute arguments required"));
    }
    let artifact_envelope = paths.remove("--artifact-envelope");
    let artifact_manifest = paths.remove("--artifact-manifest");
    let build_closure = paths.remove("--build-closure");
    if artifact_envelope.is_some() != artifact_manifest.is_some() {
        return Err(io::Error::other(
            "artifact envelope and manifest must be supplied together",
        ));
    }
    if paths.len() != 10 {
        return Err(io::Error::other("required argument missing"));
    }
    let mut take = |name: &str| {
        paths
            .remove(name)
            .ok_or_else(|| io::Error::other("required argument missing"))
    };
    Ok(ArgumentsV1 {
        artifact: take("--artifact")?,
        artifact_envelope,
        artifact_manifest,
        build_closure,
        environment: environment.ok_or_else(|| io::Error::other("environment required"))?,
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

#[cfg(test)]
mod tests {
    use super::{resolve_npm_dependency_closure_v1, validate_outer_artifact_bindings_v1};
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use whoathere_artifact::{
        normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput,
        ArtifactFormat, ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
    };
    use whoathere_detonation::{
        SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
    };
    use whoathere_macos_vm::encode_macos_sdist_build_closure_frame_v1;

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

    struct TempRoot(std::path::PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "whoathere-npm-closure-bundle-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).expect("create test root");
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn npm_tgz() -> Vec<u8> {
        npm_tgz_with(
            br#"{"name":"outer-bound-fixture","version":"4.2.1","scripts":{"postinstall":"node post.js"}}"#,
            b"process.exit(0)",
        )
    }

    fn npm_tgz_with(package_json: &[u8], program: &[u8]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes) in [
            ("package/package.json", package_json),
            ("package/post.js", program),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, path, Cursor::new(bytes))
                .expect("append inert npm member");
        }
        archive
            .into_inner()
            .expect("finish inert npm tar")
            .finish()
            .expect("finish inert npm gzip")
    }

    fn normalized_npm(
        bytes: &[u8],
        name: &str,
        version: &str,
        filename: &str,
        requires_external_dependency_resolution: bool,
    ) -> whoathere_artifact::NormalizedArtifact {
        let envelope = ArtifactEnvelope::from_original_bytes(
            ArtifactEnvelopeInput {
                ecosystem: Ecosystem::Npm,
                package_name: Some(name.to_string()),
                package_version: Some(version.to_string()),
                source_coordinate: format!("fixture:{name}@{version}"),
                source_type: ArtifactSourceType::LocalFile,
                acquired_at: "2026-07-16T00:00:00Z".to_string(),
                acquisition_method: AcquisitionMethod::LocalInertFixture,
                original_filename: filename.to_string(),
                declared_format: Some(ArtifactFormat::NpmTarGzip),
                custody_reference: "inert-npm-closure-builder-test".to_string(),
                resolver_metadata_sha256: None,
                registry_metadata_sha256: None,
                policy_version: "npm-closure-builder-test.v1".to_string(),
                requires_external_dependency_resolution,
            },
            bytes,
            ArtifactFormat::NpmTarGzip,
        );
        normalize_artifact(&envelope, bytes, NormalizationLimits::default())
            .expect("normalize npm fixture")
    }

    #[test]
    fn supplied_outer_envelope_and_manifest_identities_are_preserved() {
        let artifact_bytes = npm_tgz();
        let resolver_metadata_sha256 = Sha256Digest::from_bytes(b"non-default resolver metadata");
        let registry_metadata_sha256 = Sha256Digest::from_bytes(b"non-default registry metadata");
        let envelope = ArtifactEnvelope::from_original_bytes(
            ArtifactEnvelopeInput {
                ecosystem: Ecosystem::Npm,
                package_name: Some("outer-bound-fixture".to_string()),
                package_version: Some("4.2.1".to_string()),
                source_coordinate: "npm:outer-bound-fixture@4.2.1".to_string(),
                source_type: ArtifactSourceType::Registry,
                acquired_at: "2026-07-16T12:34:56Z".to_string(),
                acquisition_method: AcquisitionMethod::RegistryDownload,
                original_filename: "outer-bound-fixture-4.2.1.tgz".to_string(),
                declared_format: Some(ArtifactFormat::NpmTarGzip),
                custody_reference: "outer-custody:registry-download:77".to_string(),
                resolver_metadata_sha256: Some(resolver_metadata_sha256.clone()),
                registry_metadata_sha256: Some(registry_metadata_sha256.clone()),
                policy_version: "outer-admission-policy.v9".to_string(),
                requires_external_dependency_resolution: false,
            },
            &artifact_bytes,
            ArtifactFormat::NpmTarGzip,
        );
        let normalized =
            normalize_artifact(&envelope, &artifact_bytes, NormalizationLimits::default())
                .expect("normalize outer-bound npm fixture");
        let envelope_bytes = envelope.canonical_json().expect("canonical envelope");
        let manifest_bytes = serde_json::to_vec(&normalized.manifest).expect("serialize manifest");

        let bindings =
            validate_outer_artifact_bindings_v1(&artifact_bytes, &envelope_bytes, &manifest_bytes)
                .expect("validate supplied outer bindings");

        assert_eq!(bindings.envelope, envelope);
        assert_eq!(
            bindings
                .envelope
                .envelope_sha256()
                .expect("envelope digest"),
            envelope
                .envelope_sha256()
                .expect("supplied envelope digest")
        );
        assert_eq!(
            bindings.envelope.resolver_metadata_sha256,
            Some(resolver_metadata_sha256)
        );
        assert_eq!(
            bindings.envelope.registry_metadata_sha256,
            Some(registry_metadata_sha256)
        );
        assert_eq!(bindings.normalized.manifest, normalized.manifest);
    }

    #[test]
    fn exact_npm_dependency_frame_is_verified_and_payload_tamper_is_rejected() {
        let target = npm_tgz_with(
            br#"{"name":"closure-target","version":"1.0.0","scripts":{"postinstall":"node post.js"},"dependencies":{"left-pad":"1.3.0"}}"#,
            b"process.exit(0)",
        );
        let target = normalized_npm(
            &target,
            "closure-target",
            "1.0.0",
            "closure-target-1.0.0.tgz",
            true,
        );
        assert!(resolve_npm_dependency_closure_v1(None, &target.manifest).is_err());
        let dependency = npm_tgz_with(
            br#"{"name":"left-pad","version":"1.3.0","main":"post.js"}"#,
            b"module.exports = (value) => String(value);",
        );
        let closure = SdistBuildClosureV1::new(
            &["left-pad 1.3.0".to_string()],
            vec![SdistBuildClosureArtifactV1::new(
                "left-pad",
                "1.3.0",
                "left-pad-1.3.0.tgz",
                SdistBuildClosureArtifactFormatV1::NpmTarGzip,
                Sha256Digest::from_bytes(&dependency),
                dependency.len() as u64,
            )
            .expect("dependency descriptor")],
        )
        .expect("exact npm dependency closure");
        let frame = encode_macos_sdist_build_closure_frame_v1(&closure, &[dependency.clone()])
            .expect("encode closure frame");
        let root = TempRoot::new();
        let frame_path = root.0.join("dependency-closure.frame");
        std::fs::write(&frame_path, &frame).expect("write closure frame");

        let (resolved, payload) =
            resolve_npm_dependency_closure_v1(Some(&frame_path), &target.manifest)
                .expect("verify closure frame");
        assert_eq!(resolved, Some(closure));
        assert_eq!(payload, dependency);

        let mut tampered = frame;
        let last = tampered.last_mut().expect("framed payload byte");
        *last ^= 0x01;
        let tampered_path = root.0.join("dependency-closure-tampered.frame");
        std::fs::write(&tampered_path, tampered).expect("write tampered frame");
        assert!(
            resolve_npm_dependency_closure_v1(Some(&tampered_path), &target.manifest,).is_err()
        );
    }
}
