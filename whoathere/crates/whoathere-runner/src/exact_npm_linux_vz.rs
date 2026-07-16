//! Minimal exact npm artifact bridge to the macOS Linux VZ package helper.
//!
//! The helper remains responsible for VM containment and evidence production.
//! This adapter binds the verified quarantine bytes to two lifecycle runs and
//! returns incomplete evidence until a later analysis stage interprets the
//! retained process, file, canary, and network records.

use crate::{
    project_exact_detonation_behavior_v1, BoundOptionalEvidenceOutcomeV1, BoundOptionalEvidenceV1,
    ExactArtifactAdapterRequestV1, ExactArtifactDetonationAdapterV1, ExactArtifactOptionalResultV1,
    ExactArtifactScenarioKindV1, ExactArtifactScenarioPlanV1, ExactArtifactStageStatusV1,
    ExactDetonationBehaviorProjectionInputV1, OptionalAdapterErrorV1, PreparedArtifact,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use whoathere_artifact::{ArtifactFormat, Sha256Digest};
use whoathere_cache::VerifiedArtifactLease;
use whoathere_detector::BehaviorAnalysisBundleV1;
use whoathere_detonation::{
    decode_and_validate_artifact_scenario_plan_v1,
    decode_and_validate_artifact_scenario_template_v1, ArtifactScenarioKindV1,
    NpmEnvironmentProfileV1, MAX_ARTIFACT_SCENARIO_PLAN_WIRE_BYTES_V1,
    MAX_ARTIFACT_SCENARIO_TEMPLATE_WIRE_BYTES_V1,
};

const PROVIDER_ID: &str = "linux_vz_exact_npm_v1";
const HELPER_RESULT_SCHEMA_V1: &str = "whoathere.linux_vz_package_execution_result.v1";
const MAX_ROOT_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_SENSOR_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HOST_EXECUTION_RUN_BYTES: usize = 1024 * 1024;
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzExactNpmDetonationConfigV1 {
    pub helper_path: PathBuf,
    pub kernel_path: PathBuf,
    pub base_initramfs_path: PathBuf,
    pub runtime_directory: PathBuf,
    pub bundle_builder_path: PathBuf,
    pub image_builder_path: PathBuf,
    pub backend_identity_path: PathBuf,
    pub qualified_backend_path: PathBuf,
    pub qualification_record_path: PathBuf,
    pub guest_public_key_path: PathBuf,
    pub host_public_key_path: PathBuf,
    pub grant_public_key_path: PathBuf,
    pub grant_signing_seed_path: PathBuf,
    pub guest_signing_seed_path: PathBuf,
    pub output_root: PathBuf,
    pub timeout_seconds: u64,
    pub helper_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinuxVzExactNpmDetonationAdapterV1 {
    config: LinuxVzExactNpmDetonationConfigV1,
}

impl LinuxVzExactNpmDetonationAdapterV1 {
    pub fn new(config: LinuxVzExactNpmDetonationConfigV1) -> Result<Self, OptionalAdapterErrorV1> {
        let adapter = Self { config };
        if let Some(reason) = adapter.configuration_reason() {
            return Err(OptionalAdapterErrorV1::new(reason));
        }
        Ok(adapter)
    }

    pub fn config(&self) -> &LinuxVzExactNpmDetonationConfigV1 {
        &self.config
    }

    fn configuration_reason(&self) -> Option<&'static str> {
        if !(30..=600).contains(&self.config.timeout_seconds) {
            return Some("linux_vz_exact_npm_timeout_invalid");
        }
        let file_paths = [
            &self.config.helper_path,
            &self.config.kernel_path,
            &self.config.base_initramfs_path,
            &self.config.bundle_builder_path,
            &self.config.image_builder_path,
            &self.config.backend_identity_path,
            &self.config.qualified_backend_path,
            &self.config.qualification_record_path,
            &self.config.guest_public_key_path,
            &self.config.host_public_key_path,
            &self.config.grant_public_key_path,
            &self.config.grant_signing_seed_path,
            &self.config.guest_signing_seed_path,
        ];
        if file_paths
            .iter()
            .any(|path| !path.is_absolute() || !is_regular_non_symlink(path))
            || !self.config.runtime_directory.is_absolute()
            || !is_directory_non_symlink(&self.config.runtime_directory)
            || !self.config.output_root.is_absolute()
        {
            return Some("linux_vz_exact_npm_input_invalid");
        }
        let helper_mode = match fs::symlink_metadata(&self.config.helper_path) {
            Ok(metadata) => metadata.permissions().mode(),
            Err(_) => return Some("linux_vz_exact_npm_helper_unreadable"),
        };
        if helper_mode & 0o111 == 0 {
            return Some("linux_vz_exact_npm_helper_not_executable");
        }
        if let Some(expected) = &self.config.helper_sha256 {
            if Sha256Digest::parse(expected.clone()).is_err() {
                return Some("linux_vz_exact_npm_helper_digest_invalid");
            }
            let bytes = match fs::read(&self.config.helper_path) {
                Ok(bytes) => bytes,
                Err(_) => return Some("linux_vz_exact_npm_helper_unreadable"),
            };
            if Sha256Digest::from_bytes(&bytes).as_str() != expected {
                return Some("linux_vz_exact_npm_helper_digest_mismatch");
            }
        }
        match fs::symlink_metadata(&self.config.output_root) {
            Ok(metadata)
                if metadata.file_type().is_dir() && metadata.permissions().mode() & 0o077 == 0 => {}
            Ok(_) => return Some("linux_vz_exact_npm_output_root_invalid"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = self.config.output_root.parent() else {
                    return Some("linux_vz_exact_npm_output_root_invalid");
                };
                if !is_directory_non_symlink(parent) {
                    return Some("linux_vz_exact_npm_output_root_invalid");
                }
            }
            Err(_) => return Some("linux_vz_exact_npm_output_root_invalid"),
        }
        None
    }

    fn run_profile(
        &self,
        run_root: &Path,
        environment: &'static str,
        artifact_bytes: &[u8],
        artifact_sha256: &Sha256Digest,
        prepared: &PreparedArtifact,
    ) -> ProfileRun {
        let profile_root = run_root.join(environment);
        let evidence_directory = profile_root.join("evidence");
        if create_private_directory(&profile_root).is_err()
            || create_private_directory(&evidence_directory).is_err()
        {
            return ProfileRun::incomplete(environment, "output_directory_creation_failed");
        }
        let artifact_path = profile_root.join("artifact.tgz");
        if write_new_private_file(&artifact_path, artifact_bytes).is_err() {
            return ProfileRun::incomplete(environment, "artifact_materialization_failed");
        }
        let artifact_envelope_path = profile_root.join("artifact-envelope.json");
        let artifact_manifest_path = profile_root.join("artifact-manifest.json");
        let artifact_envelope_bytes = match prepared.envelope().canonical_json() {
            Ok(bytes) => bytes,
            Err(_) => {
                return ProfileRun::incomplete(environment, "artifact_binding_serialization_failed")
            }
        };
        let artifact_manifest_bytes = match serde_json::to_vec(&prepared.normalized().manifest) {
            Ok(bytes) => bytes,
            Err(_) => {
                return ProfileRun::incomplete(environment, "artifact_binding_serialization_failed")
            }
        };
        if write_new_private_file(&artifact_envelope_path, &artifact_envelope_bytes).is_err()
            || write_new_private_file(&artifact_manifest_path, &artifact_manifest_bytes).is_err()
        {
            return ProfileRun::incomplete(environment, "artifact_binding_materialization_failed");
        }
        let envelope_sha256 = match prepared.envelope().envelope_sha256() {
            Ok(digest) => digest,
            Err(_) => {
                return ProfileRun::incomplete(environment, "artifact_binding_serialization_failed")
            }
        };
        let manifest_sha256 = &prepared.normalized().manifest.manifest_sha256;

        let output = Command::new(&self.config.helper_path)
            .arg("--artifact")
            .arg(&artifact_path)
            .arg("--artifact-envelope")
            .arg(&artifact_envelope_path)
            .arg("--artifact-manifest")
            .arg(&artifact_manifest_path)
            .arg("--artifact-kind")
            .arg("npm_tgz")
            .arg("--environment")
            .arg(environment)
            .arg("--kernel")
            .arg(&self.config.kernel_path)
            .arg("--base-initramfs")
            .arg(&self.config.base_initramfs_path)
            .arg("--runtime-directory")
            .arg(&self.config.runtime_directory)
            .arg("--bundle-builder")
            .arg(&self.config.bundle_builder_path)
            .arg("--image-builder")
            .arg(&self.config.image_builder_path)
            .arg("--backend-identity")
            .arg(&self.config.backend_identity_path)
            .arg("--qualified-backend")
            .arg(&self.config.qualified_backend_path)
            .arg("--qualification-record")
            .arg(&self.config.qualification_record_path)
            .arg("--guest-public-key")
            .arg(&self.config.guest_public_key_path)
            .arg("--host-public-key")
            .arg(&self.config.host_public_key_path)
            .arg("--grant-public-key")
            .arg(&self.config.grant_public_key_path)
            .arg("--grant-signing-seed")
            .arg(&self.config.grant_signing_seed_path)
            .arg("--guest-signing-seed")
            .arg(&self.config.guest_signing_seed_path)
            .arg("--output-directory")
            .arg(&evidence_directory)
            .arg("--timeout-seconds")
            .arg(self.config.timeout_seconds.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output();
        let output = match output {
            Ok(output) => output,
            Err(_) => return ProfileRun::incomplete(environment, "helper_invocation_failed"),
        };
        let parsed = match serde_json::from_slice::<PhysicalHelperResultV1>(&output.stdout) {
            Ok(parsed) => parsed,
            Err(_) => return ProfileRun::incomplete(environment, "helper_output_invalid"),
        };
        let mut limitations = Vec::new();
        if !output.status.success() {
            limitations.push("helper_process_failed");
        }
        if parsed.schema_version != HELPER_RESULT_SCHEMA_V1 {
            limitations.push("helper_schema_invalid");
        }
        if parsed.environment.as_deref() != Some(environment) {
            limitations.push("environment_binding_not_proven");
        }
        if parsed.artifact_sha256.as_deref() != Some(artifact_sha256.as_str()) {
            limitations.push("artifact_binding_not_proven");
        }
        if parsed.public_network_route_present != Some(false) {
            limitations.push("no_public_route_not_proven");
        }
        if parsed.sync_back != Some(false) {
            limitations.push("no_sync_back_not_proven");
        }
        if parsed.authoritative_verdict_permitted != Some(false) {
            limitations.push("no_verdict_authority_not_proven");
        }
        if parsed.vm_started != Some(true)
            || parsed.vm_stopped != Some(true)
            || parsed.clone_destroyed != Some(true)
        {
            limitations.push("vm_teardown_not_proven");
        }
        if parsed.image_identity_stable != Some(true) {
            limitations.push("image_identity_stability_not_proven");
        }
        if parsed.package_execution != Some(true) {
            limitations.push("package_execution_not_proven");
        }
        if !matches!(
            parsed.status.as_str(),
            "package_process_complete_evidence_pending_host_composition"
                | "package_process_failed_evidence_preserved"
                | "guest_incomplete_evidence_preserved"
        ) {
            limitations.push("helper_terminal_not_supported");
        }
        let behavior_projection = project_profile_behavior_v1(
            &evidence_directory,
            environment,
            artifact_sha256,
            &envelope_sha256,
            manifest_sha256,
            artifact_bytes.len(),
        );
        let behavior_bundle = match behavior_projection {
            Ok(projected) => Some(projected),
            Err(reason) => {
                limitations.push(reason);
                None
            }
        };
        ProfileRun {
            environment,
            evidence_captured: limitations.is_empty(),
            limitations,
            behavior_bundle,
        }
    }
}

impl ExactArtifactDetonationAdapterV1 for LinuxVzExactNpmDetonationAdapterV1 {
    fn provider_id(&self) -> &str {
        PROVIDER_ID
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        self.configuration_reason()
    }

    fn supports_runtime_binding(
        &self,
        prepared: &PreparedArtifact,
        scenarios: &ExactArtifactScenarioPlanV1,
    ) -> bool {
        if scenarios.status != ExactArtifactStageStatusV1::Complete
            || scenarios.executable
            || scenarios.runtime_binding_status != "not_bound"
            || prepared.normalized().manifest.magic_detected_format != ArtifactFormat::NpmTarGzip
            || prepared.envelope().requires_external_dependency_resolution
        {
            return false;
        }
        let manifest = &prepared.normalized().manifest;
        let Some(npm) = &manifest.metadata.npm else {
            return false;
        };
        if npm.requires_offline_closure
            || !npm.dependency_declarations.is_empty()
            || npm.implicit_node_gyp_rebuild
            || !manifest.native_binary_file_ids.is_empty()
            || scenarios.intents.len() != 2
            || scenarios.intents.iter().any(|intent| {
                !matches!(
                    intent.kind,
                    ExactArtifactScenarioKindV1::Npm(
                        ArtifactScenarioKindV1::NpmLocalTarballInstall { .. }
                    )
                )
            })
        {
            return false;
        }
        let has_ci_false = scenarios.intents.iter().any(|intent| {
            matches!(
                intent.kind,
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiFalse
                })
            )
        });
        let has_ci_true = scenarios.intents.iter().any(|intent| {
            matches!(
                intent.kind,
                ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: NpmEnvironmentProfileV1::CiTrue
                })
            )
        });
        has_ci_false && has_ci_true
    }

    fn detonate(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        artifact: &VerifiedArtifactLease,
        prepared: &PreparedArtifact,
        scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        let artifact_digest = Sha256Digest::from_bytes(artifact.bytes());
        let artifact_sha256 = artifact_digest.to_string();
        let manifest_digest = match Sha256Digest::parse(request.manifest_sha256.clone()) {
            Ok(digest) => digest,
            Err(_) => {
                return incomplete_result(
                    &request.request_sha256,
                    vec!["vm_manifest_binding_invalid".to_string()],
                )
            }
        };
        let envelope_digest = match Sha256Digest::parse(request.envelope_sha256.clone()) {
            Ok(digest) => digest,
            Err(_) => {
                return incomplete_result(
                    &request.request_sha256,
                    vec!["vm_envelope_binding_invalid".to_string()],
                )
            }
        };
        let prepared_envelope_digest = match prepared.envelope().envelope_sha256() {
            Ok(digest) => digest,
            Err(_) => {
                return incomplete_result(
                    &request.request_sha256,
                    vec!["vm_envelope_binding_invalid".to_string()],
                )
            }
        };
        if self.configuration_reason().is_some()
            || artifact_sha256 != request.artifact_sha256
            || artifact_sha256 != prepared.evidence_subject().artifact_sha256()
            || envelope_digest != prepared_envelope_digest
            || manifest_digest != prepared.normalized().manifest.manifest_sha256
            || scenarios.runtime_binding_status != "verified"
            || !scenarios.executable
            || !self.supports_bound_npm_plan(scenarios)
        {
            return incomplete_result(
                &request.request_sha256,
                vec!["vm_runtime_or_artifact_binding_invalid".to_string()],
            );
        }
        let run_root =
            match create_fresh_run_root(&self.config.output_root, &request.request_sha256) {
                Ok(path) => path,
                Err(_) => {
                    return incomplete_result(
                        &request.request_sha256,
                        vec!["vm_output_directory_creation_failed".to_string()],
                    )
                }
            };
        let runs = [
            self.run_profile(
                &run_root,
                "ci_false",
                artifact.bytes(),
                &artifact_digest,
                prepared,
            ),
            self.run_profile(
                &run_root,
                "ci_true",
                artifact.bytes(),
                &artifact_digest,
                prepared,
            ),
        ];
        let mut reasons = vec![
            "vm_evidence_captured_pending_analysis".to_string(),
            "vm_evidence_output_preserved".to_string(),
        ];
        let mut behavior_bundles = Vec::new();
        for mut run in runs {
            if let Some(bundle) = run.behavior_bundle.take() {
                let digest = bundle.bundle_sha256();
                reasons.push(format!(
                    "vm_{}_behavior_bundle_sha256:{}",
                    run.environment,
                    digest.as_str().trim_start_matches("sha256:")
                ));
                reasons.push(format!("vm_{}_behavior_bundle_projected", run.environment));
                let event_count = bundle.events().len();
                reasons.push(format!(
                    "vm_{}_behavior_event_count:{event_count}",
                    run.environment
                ));
                behavior_bundles.push(bundle);
            }
            if !run.evidence_captured {
                reasons.push(format!("vm_{}_evidence_incomplete", run.environment));
            }
            reasons.extend(
                run.limitations
                    .into_iter()
                    .map(|reason| format!("vm_{}_{}", run.environment, reason)),
            );
        }
        incomplete_result_with_bundles(&request.request_sha256, reasons, behavior_bundles)
    }
}

impl LinuxVzExactNpmDetonationAdapterV1 {
    fn supports_bound_npm_plan(&self, scenarios: &ExactArtifactScenarioPlanV1) -> bool {
        scenarios.status == ExactArtifactStageStatusV1::Complete
            && scenarios.intents.len() == 2
            && scenarios.intents.iter().all(|intent| {
                matches!(
                    intent.kind,
                    ExactArtifactScenarioKindV1::Npm(
                        ArtifactScenarioKindV1::NpmLocalTarballInstall { .. }
                    )
                )
            })
    }
}

#[derive(Debug, Deserialize)]
struct PhysicalHelperResultV1 {
    schema_version: String,
    status: String,
    environment: Option<String>,
    artifact_sha256: Option<String>,
    authoritative_verdict_permitted: Option<bool>,
    public_network_route_present: Option<bool>,
    vm_started: Option<bool>,
    vm_stopped: Option<bool>,
    clone_destroyed: Option<bool>,
    image_identity_stable: Option<bool>,
    package_execution: Option<bool>,
    sync_back: Option<bool>,
}

struct ProfileRun {
    environment: &'static str,
    evidence_captured: bool,
    limitations: Vec<&'static str>,
    behavior_bundle: Option<BehaviorAnalysisBundleV1>,
}

impl ProfileRun {
    fn incomplete(environment: &'static str, reason: &'static str) -> Self {
        Self {
            environment,
            evidence_captured: false,
            limitations: vec![reason],
            behavior_bundle: None,
        }
    }
}

fn project_profile_behavior_v1(
    evidence_directory: &Path,
    environment: &str,
    artifact_sha256: &Sha256Digest,
    envelope_sha256: &Sha256Digest,
    manifest_sha256: &Sha256Digest,
    artifact_byte_length: usize,
) -> Result<BehaviorAnalysisBundleV1, &'static str> {
    let scenario_plan_json = read_bounded_regular_file(
        &evidence_directory.join("execution-bundle/scenario-plan.json"),
        MAX_ARTIFACT_SCENARIO_PLAN_WIRE_BYTES_V1,
    )?;
    let scenario_template_json = read_bounded_regular_file(
        &evidence_directory.join("execution-bundle/scenario-template.json"),
        MAX_ARTIFACT_SCENARIO_TEMPLATE_WIRE_BYTES_V1,
    )?;
    let root_receipt_json = read_bounded_regular_file(
        &evidence_directory.join("action-root-receipt.bin"),
        MAX_ROOT_RECEIPT_BYTES,
    )?;
    let process_evidence_json = read_bounded_regular_file(
        &evidence_directory.join("action-process-evidence.bin"),
        MAX_SENSOR_EVIDENCE_BYTES,
    )?;
    let file_evidence_json = read_bounded_regular_file(
        &evidence_directory.join("action-file-evidence.bin"),
        MAX_SENSOR_EVIDENCE_BYTES,
    )?;
    let network_evidence_json = read_bounded_regular_file(
        &evidence_directory.join("action-network-evidence.bin"),
        MAX_SENSOR_EVIDENCE_BYTES,
    )?;
    let host_execution_run_json = read_bounded_regular_file(
        &evidence_directory.join("execution-run.json"),
        MAX_HOST_EXECUTION_RUN_BYTES,
    )?;

    let plan = decode_and_validate_artifact_scenario_plan_v1(&scenario_plan_json)
        .map_err(|_| "behavior_projection_scenario_plan_invalid")?;
    let template = decode_and_validate_artifact_scenario_template_v1(&scenario_template_json)
        .map_err(|_| "behavior_projection_scenario_template_invalid")?;
    let expected_environment = match environment {
        "ci_false" => NpmEnvironmentProfileV1::CiFalse,
        "ci_true" => NpmEnvironmentProfileV1::CiTrue,
        _ => return Err("behavior_projection_environment_invalid"),
    };
    if plan.artifact_sha256() != artifact_sha256
        || plan.envelope_sha256() != envelope_sha256
        || plan.manifest_sha256() != manifest_sha256
        || template.artifact_sha256() != artifact_sha256
        || template.envelope_sha256() != envelope_sha256
        || template.manifest_sha256() != manifest_sha256
        || template.artifact_byte_length() != artifact_byte_length as u64
        || template.environment() != expected_environment
        || !plan.templates().iter().any(|reference| {
            reference.0 == template.scenario_id()
                && reference.1 == expected_environment
                && reference.2 == *template.template_sha256()
        })
    {
        return Err("behavior_projection_scenario_binding_mismatch");
    }

    let root_value: Value = serde_json::from_slice(&root_receipt_json)
        .map_err(|_| "behavior_projection_root_receipt_invalid")?;
    let claims = root_value
        .get("claims")
        .and_then(Value::as_object)
        .ok_or("behavior_projection_root_receipt_invalid")?;
    let claimed_scenario_sha256 = parse_projection_digest_field(claims, "scenario_plan_sha256")?;
    if &claimed_scenario_sha256 != plan.plan_sha256() {
        return Err("behavior_projection_scenario_binding_mismatch");
    }
    let process_plan_sha256 = parse_projection_digest_field(claims, "process_plan_sha256")?;
    let host_execution_run_sha256 = Sha256Digest::from_bytes(&host_execution_run_json);
    let template_value: Value = serde_json::from_slice(&scenario_template_json)
        .map_err(|_| "behavior_projection_scenario_template_invalid")?;
    let run_id = template_value
        .get("identity")
        .and_then(Value::as_object)
        .and_then(|identity| identity.get("run_id"))
        .and_then(Value::as_str)
        .ok_or("behavior_projection_scenario_template_invalid")?;
    let bundle = project_exact_detonation_behavior_v1(ExactDetonationBehaviorProjectionInputV1 {
        artifact_sha256,
        manifest_sha256,
        scenario_id: template.scenario_id(),
        scenario_sha256: plan.plan_sha256(),
        process_plan_sha256: &process_plan_sha256,
        run_id,
        host_execution_run_sha256: &host_execution_run_sha256,
        root_receipt_json: &root_receipt_json,
        process_evidence_json: &process_evidence_json,
        file_evidence_json: &file_evidence_json,
        network_evidence_json: &network_evidence_json,
        host_execution_run_json: &host_execution_run_json,
    })
    .map_err(|error| error.reason_code())?;
    let bundle_bytes = serde_json::to_vec(&bundle)
        .map_err(|_| "behavior_projection_bundle_serialization_failed")?;
    write_new_private_file(
        &evidence_directory.join("behavior-bundle.json"),
        &bundle_bytes,
    )
    .map_err(|_| "behavior_projection_bundle_write_failed")?;
    Ok(bundle)
}

fn parse_projection_digest_field(
    claims: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Sha256Digest, &'static str> {
    let digest = claims
        .get(field)
        .and_then(Value::as_str)
        .ok_or("behavior_projection_root_receipt_invalid")?;
    Sha256Digest::parse(digest.to_string()).map_err(|_| "behavior_projection_root_receipt_invalid")
}

fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "behavior_projection_evidence_unavailable")?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err("behavior_projection_evidence_unavailable");
    }
    fs::read(path).map_err(|_| "behavior_projection_evidence_unavailable")
}

fn incomplete_result(
    request_sha256: &str,
    reason_codes: Vec<String>,
) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
    incomplete_result_with_bundles(request_sha256, reason_codes, Vec::new())
}

fn incomplete_result_with_bundles(
    request_sha256: &str,
    reason_codes: Vec<String>,
    behavior_bundles: Vec<BehaviorAnalysisBundleV1>,
) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
    let bundle_sha256s = behavior_bundles
        .iter()
        .map(BehaviorAnalysisBundleV1::bundle_sha256)
        .collect();
    let result = ExactArtifactOptionalResultV1::with_evidence(
        request_sha256.to_string(),
        BoundOptionalEvidenceOutcomeV1::Incomplete,
        reason_codes,
        Vec::new(),
        bundle_sha256s,
    )?;
    Ok(BoundOptionalEvidenceV1 {
        canonical_result_bytes: result.to_canonical_json_bytes()?,
        behavior_bundles,
    })
}

fn is_regular_non_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_file())
        .unwrap_or(false)
}

fn is_directory_non_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

fn ensure_private_output_root(path: &Path) -> std::io::Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.file_type().is_dir() && metadata.permissions().mode() & 0o077 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "output root is not private",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(path)
        }
        Err(error) => Err(error),
    }
}

fn create_fresh_run_root(output_root: &Path, request_sha256: &str) -> std::io::Result<PathBuf> {
    ensure_private_output_root(output_root)?;
    let digest_suffix = request_sha256
        .strip_prefix("sha256:")
        .unwrap_or(request_sha256)
        .get(..12)
        .unwrap_or("unbound");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    for _ in 0..8 {
        let sequence = RUN_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let candidate = output_root.join(format!(
            "run-{digest_suffix}-{}-{now}-{sequence}",
            std::process::id()
        ));
        match create_private_directory(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "unable to allocate a fresh run directory",
    ))
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder.create(path)
}

fn write_new_private_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
