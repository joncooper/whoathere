use serde::Serialize;
use std::collections::BTreeMap;
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
    compile_wheel_scenarios_v1, expected_wheel_scenario_kinds_v1,
    ArtifactProtectedTelemetryRequirementsV1, ArtifactRuntimeTargetV1,
    ArtifactScenarioExecutionIdentityV1, WheelRuntimeProfileV1, WheelScenarioCompilationRequestV1,
    WheelScenarioIdentitySetV1, WheelScenarioKindV1, WheelScenarioPolicyV1,
    MAX_ARTIFACT_SCENARIO_BYTES_V1, MAX_EXECUTION_BUNDLE_ACTIONS_V2,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    build_macos_linux_vz_package_authority_request_v1,
    compile_macos_linux_vz_wheel_execution_fanout_v1,
    decode_qualified_macos_linux_vz_telemetry_backend_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    sign_macos_linux_vz_package_execution_grant_v1,
    verify_macos_linux_vz_package_execution_runtime_qualification_record_v1,
    MacosLinuxVzCandidatePackageRuntimeV1, MacosLinuxVzPackageArtifactKindV1,
    MacosLinuxVzPackageExecutionGrantContextV1, MacosLinuxVzWheelExecutionFanoutRequestV1,
    MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
};
use zeroize::Zeroize;

const BUNDLE_SCHEMA_V1: &str = "whoathere.linux_vz_inert_wheel_execution_bundle.v1";
const BUILD_RESULT_SCHEMA_V1: &str =
    "whoathere.linux_vz_inert_wheel_execution_bundle_build_result.v1";
const ARTIFACT_FILE_NAME_V1: &str = "artifact.bin";
const GRANT_LIFETIME_SECONDS_V1: u64 = 10 * 60;
const MAXIMUM_INPUT_BYTES_V1: u64 = MAX_ARTIFACT_SCENARIO_BYTES_V1;
const MAXIMUM_ARTIFACT_ENVELOPE_BYTES_V1: u64 = 1024 * 1024;

#[derive(Debug)]
struct ArgumentsV1 {
    artifact: PathBuf,
    artifact_envelope: Option<PathBuf>,
    artifact_manifest: Option<PathBuf>,
    scenario_index: usize,
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
    artifact_file_name: &'static str,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: &'a Sha256Digest,
    artifact_byte_length: String,
    expected_scenario_count: String,
    scenario_index: String,
    selected_scenario_id: &'a str,
    selected_scenario_kind: &'a WheelScenarioKindV1,
    selected_scenario_kind_sha256: &'a Sha256Digest,
    expected_process_action_count: String,
    wheel_fanout_sha256: &'a Sha256Digest,
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
    execution_authority_issued: bool,
    attempt_limit: String,
    public_network_route_present: bool,
    sync_back: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BuildResultV1<'a> {
    schema_version: &'static str,
    artifact_file_name: &'static str,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: &'a Sha256Digest,
    scenario_index: String,
    selected_scenario_id: &'a str,
    execution_authority_issued: bool,
    execution_grant_sha256: &'a Sha256Digest,
    execution_runtime_qualification_record_sha256: &'a Sha256Digest,
    expires_at_unix_seconds: String,
    package_authority_request_sha256: &'a Sha256Digest,
    public_network_route_present: bool,
    sync_back: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere_linux_vz_inert_wheel_execution_bundle_failed:{error}");
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
    let normalization_limits = NormalizationLimits::default();
    let bindings = load_artifact_bindings_v1(
        &arguments.artifact,
        arguments.artifact_envelope.as_deref(),
        arguments.artifact_manifest.as_deref(),
        &artifact_bytes,
        normalization_limits,
    )?;
    let envelope = bindings.envelope;
    let normalized = bindings.normalized;
    require_supported_pure_wheel_v1(&normalized.manifest)?;

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
    let runtime = WheelRuntimeProfileV1::new_for_target(
        ArtifactRuntimeTargetV1::LinuxArm64,
        "linux-arm64-python314-pip26-qualified-runtime-v1",
        qualification.python_version(),
        qualification.python_executable_sha256().clone(),
        qualification.pip_version(),
        qualification.pip_entrypoint_sha256().clone(),
    )?;
    let policy =
        WheelScenarioPolicyV1::inert_qualification_only(envelope.original_sha256.clone(), runtime)?;
    let scenario_kinds = expected_wheel_scenario_kinds_v1(&normalized.manifest)?;
    let expected_scenario_count = u32::try_from(scenario_kinds.len())
        .map_err(|_| io::Error::other("wheel scenario count invalid"))?;
    if expected_scenario_count == 0
        || expected_scenario_count > MAX_EXECUTION_BUNDLE_ACTIONS_V2
        || arguments.scenario_index >= scenario_kinds.len()
    {
        return Err(io::Error::other("wheel scenario index unavailable").into());
    }
    let identity_map = scenario_kinds
        .iter()
        .cloned()
        .enumerate()
        .map(|(index, kind)| {
            let ordinal = index + 1;
            let identity = ArtifactScenarioExecutionIdentityV1::new(
                format!("linux-vz-inert-wheel-job-{ordinal}-v1"),
                format!("linux-vz-inert-wheel-run-{ordinal}-v1"),
                format!("linux-vz-inert-wheel-evidence-{ordinal}-v1"),
                format!("linux-vz-inert-wheel-scenario-{ordinal}-v1"),
            )?;
            Ok((kind, identity))
        })
        .collect::<Result<BTreeMap<_, _>, whoathere_detonation::ArtifactScenarioCompileErrorV1>>(
        )?;
    let identities = WheelScenarioIdentitySetV1::new(
        "linux-vz-inert-wheel-execution-gate-plan-v1",
        identity_map,
    )?;
    let plan = compile_wheel_scenarios_v1(WheelScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &normalized.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })?;
    let fanout = compile_macos_linux_vz_wheel_execution_fanout_v1(
        MacosLinuxVzWheelExecutionFanoutRequestV1 {
            envelope: &envelope,
            artifact_bytes: &artifact_bytes,
            manifest: &normalized.manifest,
            scenario_plan: &plan,
            expected_scenario_count,
            normalization_limits,
        },
    )?;
    let selected_action = fanout
        .actions()
        .get(arguments.scenario_index)
        .ok_or_else(|| io::Error::other("wheel scenario action unavailable"))?;
    if selected_action.scenario_kind() != &scenario_kinds[arguments.scenario_index]
        || selected_action.action_index() as usize != arguments.scenario_index
        || selected_action.execution_authority_issued()
        || selected_action.public_network_route_present()
        || selected_action.sync_back_permitted()
    {
        return Err(io::Error::other("wheel scenario fanout binding invalid").into());
    }
    let plan_bytes = plan.canonical_json_v1()?;
    let template_bytes = selected_action.scenario_template_canonical_json_v1();

    let request_challenge = random_nonzero_v1()?;
    let authority_request = build_macos_linux_vz_package_authority_request_v1(
        &qualified_backend,
        MacosLinuxVzPackageArtifactKindV1::PypiWheel,
        &artifact_bytes,
        &plan_bytes,
        template_bytes,
        &candidate_runtime,
        request_challenge,
        clone_binding_sha256.clone(),
    )?;
    if authority_request.scenario_id() != selected_action.scenario_id()
        || authority_request.scenario_template_sha256()
            != selected_action.scenario_template_sha256()
    {
        return Err(io::Error::other("wheel authority scenario binding invalid").into());
    }

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
        &arguments.output_directory.join(ARTIFACT_FILE_NAME_V1),
        &artifact_bytes,
    )?;
    write_new_private_v1(
        &arguments.output_directory.join("scenario-plan.json"),
        &plan_bytes,
    )?;
    write_new_private_v1(
        &arguments.output_directory.join("scenario-template.json"),
        template_bytes,
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
        schema_version: BUNDLE_SCHEMA_V1,
        artifact_file_name: ARTIFACT_FILE_NAME_V1,
        artifact_kind: MacosLinuxVzPackageArtifactKindV1::PypiWheel,
        artifact_sha256: authority_request.artifact_sha256(),
        artifact_byte_length: authority_request.artifact_byte_length().to_string(),
        expected_scenario_count: expected_scenario_count.to_string(),
        scenario_index: arguments.scenario_index.to_string(),
        selected_scenario_id: authority_request.scenario_id(),
        selected_scenario_kind: selected_action.scenario_kind(),
        selected_scenario_kind_sha256: authority_request.scenario_kind_sha256(),
        expected_process_action_count: selected_action.expected_process_action_count().to_string(),
        wheel_fanout_sha256: fanout.fanout_sha256(),
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

    let result = BuildResultV1 {
        schema_version: BUILD_RESULT_SCHEMA_V1,
        artifact_file_name: ARTIFACT_FILE_NAME_V1,
        artifact_kind: MacosLinuxVzPackageArtifactKindV1::PypiWheel,
        artifact_sha256: authority_request.artifact_sha256(),
        scenario_index: arguments.scenario_index.to_string(),
        selected_scenario_id: authority_request.scenario_id(),
        execution_authority_issued: true,
        execution_grant_sha256: &execution_grant_sha256,
        execution_runtime_qualification_record_sha256: qualification.qualification_record_sha256(),
        expires_at_unix_seconds: expires_at.to_string(),
        package_authority_request_sha256: authority_request.request_sha256(),
        public_network_route_present: false,
        sync_back: false,
    };
    let result_bytes = serde_json_canonicalizer::to_vec(&result)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&result_bytes)?;
    stdout.write_all(b"\n")?;
    stdout.flush()?;
    Ok(())
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
    normalization_limits: NormalizationLimits,
) -> Result<ArtifactBindingsV1, io::Error> {
    match (envelope_path, manifest_path) {
        (Some(envelope_path), Some(manifest_path)) => {
            let envelope_bytes =
                read_regular_bounded_v1(envelope_path, MAXIMUM_ARTIFACT_ENVELOPE_BYTES_V1)?;
            let manifest_bytes = read_regular_bounded_v1(manifest_path, MAXIMUM_INPUT_BYTES_V1)?;
            validate_outer_artifact_bindings_v1(
                artifact_bytes,
                &envelope_bytes,
                &manifest_bytes,
                normalization_limits,
            )
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
                    ecosystem: Ecosystem::Pypi,
                    package_name: None,
                    package_version: None,
                    source_coordinate: format!("local-file:{artifact_sha256}"),
                    source_type: ArtifactSourceType::LocalFile,
                    acquired_at: "2026-07-15T00:00:00Z".to_string(),
                    acquisition_method: AcquisitionMethod::LocalFileImport,
                    original_filename,
                    declared_format: Some(ArtifactFormat::WheelZip),
                    custody_reference: "caller-supplied-local-wheel-path".to_string(),
                    resolver_metadata_sha256: None,
                    registry_metadata_sha256: None,
                    policy_version: "linux-vz-inert-wheel-execution-gate.v1".to_string(),
                    requires_external_dependency_resolution: false,
                },
                artifact_bytes,
                ArtifactFormat::WheelZip,
            );
            let normalized = normalize_artifact(&envelope, artifact_bytes, normalization_limits)
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
    normalization_limits: NormalizationLimits,
) -> Result<ArtifactBindingsV1, io::Error> {
    let envelope: ArtifactEnvelope = serde_json::from_slice(envelope_bytes)
        .map_err(|_| io::Error::other("artifact envelope invalid"))?;
    let canonical_envelope = envelope
        .canonical_json()
        .map_err(|_| io::Error::other("artifact envelope invalid"))?;
    if canonical_envelope != envelope_bytes
        || envelope.ecosystem != Ecosystem::Pypi
        || envelope.magic_detected_format != ArtifactFormat::WheelZip
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
    if detected != ArtifactFormat::WheelZip || !envelope.verify_magic_format(detected) {
        return Err(io::Error::other("artifact format binding invalid"));
    }

    let supplied_manifest: ArtifactManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|_| io::Error::other("artifact manifest invalid"))?;
    let normalized = normalize_artifact(&envelope, artifact_bytes, normalization_limits)
        .map_err(|_| io::Error::other("artifact normalization failed"))?;
    if supplied_manifest != normalized.manifest {
        return Err(io::Error::other("artifact manifest binding invalid"));
    }
    Ok(ArtifactBindingsV1 {
        envelope,
        normalized,
    })
}

fn require_supported_pure_wheel_v1(
    manifest: &whoathere_artifact::ArtifactManifest,
) -> Result<(), io::Error> {
    if manifest.magic_detected_format != ArtifactFormat::WheelZip {
        return Err(io::Error::other("artifact is not a wheel"));
    }
    let wheel = manifest
        .metadata
        .wheel
        .as_ref()
        .ok_or_else(|| io::Error::other("wheel metadata unavailable"))?;
    if wheel.root_is_purelib != Some(true)
        || wheel.tags.is_empty()
        || wheel.tags.iter().any(|tag| !tag.ends_with("-none-any"))
        || !wheel.native_tags.is_empty()
        || !manifest.native_binary_file_ids.is_empty()
        || !wheel.script_file_ids.is_empty()
    {
        return Err(io::Error::other(
            "wheel requires native execution or an unsupported script surface",
        ));
    }
    Ok(())
}

fn parse_arguments_v1() -> Result<ArgumentsV1, io::Error> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mut paths = BTreeMap::new();
    let mut scenario_index = None;
    while let Some(name) = arguments.next() {
        let name = name
            .into_string()
            .map_err(|_| io::Error::other("argument name invalid"))?;
        let value = arguments
            .next()
            .ok_or_else(|| io::Error::other("argument value missing"))?;
        match name.as_str() {
            "--scenario-index" => {
                let value = value
                    .into_string()
                    .map_err(|_| io::Error::other("scenario index invalid"))?;
                let parsed = parse_scenario_index_v1(&value)?;
                if scenario_index.replace(parsed).is_some() {
                    return Err(io::Error::other("argument invalid"));
                }
            }
            "--artifact"
            | "--artifact-envelope"
            | "--artifact-manifest"
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
        scenario_index: scenario_index
            .ok_or_else(|| io::Error::other("scenario index required"))?,
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

fn parse_scenario_index_v1(value: &str) -> Result<usize, io::Error> {
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(io::Error::other("scenario index invalid"));
    }
    let parsed = value
        .parse::<u32>()
        .map_err(|_| io::Error::other("scenario index invalid"))?;
    if parsed >= MAX_EXECUTION_BUNDLE_ACTIONS_V2 {
        return Err(io::Error::other("scenario index invalid"));
    }
    Ok(parsed as usize)
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
    use super::{parse_scenario_index_v1, validate_outer_artifact_bindings_v1};
    use std::io::{Cursor, Write};
    use whoathere_artifact::{
        normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput,
        ArtifactFormat, ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
    };
    use zip::write::SimpleFileOptions;

    #[test]
    fn scenario_index_is_canonical_and_bounded() {
        assert_eq!(parse_scenario_index_v1("0").expect("zero index"), 0);
        assert_eq!(parse_scenario_index_v1("255").expect("last v2 index"), 255);
        for invalid in ["", "00", "01", "-1", "256", "999999999999999999999"] {
            assert!(parse_scenario_index_v1(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn supplied_outer_envelope_and_manifest_identities_are_preserved() {
        let artifact_bytes = wheel_zip();
        let resolver_metadata_sha256 = Sha256Digest::from_bytes(b"non-default resolver metadata");
        let registry_metadata_sha256 = Sha256Digest::from_bytes(b"non-default registry metadata");
        let envelope = ArtifactEnvelope::from_original_bytes(
            ArtifactEnvelopeInput {
                ecosystem: Ecosystem::Pypi,
                package_name: Some("outer-wheel-fixture".to_string()),
                package_version: Some("4.2.1".to_string()),
                source_coordinate: "pypi:outer-wheel-fixture==4.2.1".to_string(),
                source_type: ArtifactSourceType::Registry,
                acquired_at: "2026-07-16T12:34:56Z".to_string(),
                acquisition_method: AcquisitionMethod::RegistryDownload,
                original_filename: "outer_wheel_fixture-4.2.1-py3-none-any.whl".to_string(),
                declared_format: Some(ArtifactFormat::WheelZip),
                custody_reference: "outer-custody:registry-download:88".to_string(),
                resolver_metadata_sha256: Some(resolver_metadata_sha256.clone()),
                registry_metadata_sha256: Some(registry_metadata_sha256.clone()),
                policy_version: "outer-admission-policy.v9".to_string(),
                requires_external_dependency_resolution: false,
            },
            &artifact_bytes,
            ArtifactFormat::WheelZip,
        );
        let normalization_limits = NormalizationLimits::default();
        let normalized = normalize_artifact(&envelope, &artifact_bytes, normalization_limits)
            .expect("normalize outer-bound wheel fixture");
        let envelope_bytes = envelope.canonical_json().expect("canonical envelope");
        let manifest_bytes = serde_json::to_vec(&normalized.manifest).expect("serialize manifest");

        let bindings = validate_outer_artifact_bindings_v1(
            &artifact_bytes,
            &envelope_bytes,
            &manifest_bytes,
            normalization_limits,
        )
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

    fn wheel_zip() -> Vec<u8> {
        const DIST_INFO: &str = "outer_wheel_fixture-4.2.1.dist-info";
        let members = vec![
            (
                format!("{DIST_INFO}/METADATA"),
                b"Metadata-Version: 2.1\nName: outer-wheel-fixture\nVersion: 4.2.1\n\n"
                    .to_vec(),
            ),
            (
                format!("{DIST_INFO}/WHEEL"),
                b"Wheel-Version: 1.0\nGenerator: whoathere-inert\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
                    .to_vec(),
            ),
            (
                "outer_wheel_fixture/__init__.py".to_string(),
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
                .expect("start inert wheel member");
            writer.write_all(&bytes).expect("write inert wheel member");
        }
        writer
            .start_file(record_path, SimpleFileOptions::default())
            .expect("start inert wheel RECORD");
        writer
            .write_all(record.as_bytes())
            .expect("write inert wheel RECORD");
        writer.finish().expect("finish inert wheel").into_inner()
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
                u8::from_str_radix(std::str::from_utf8(pair).expect("hex utf8"), 16)
                    .expect("hex byte")
            })
            .collect::<Vec<_>>();
        format!("sha256={}", base64_url_no_pad(&digest_bytes))
    }

    fn base64_url_no_pad(bytes: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
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
        output
    }
}
