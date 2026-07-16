//! Minimal exact pure-Python wheel bridge to the macOS Linux VZ package helper.
//!
//! The helper remains responsible for VM containment and authenticated evidence
//! production. This adapter runs one fresh helper action for every normalized
//! wheel trigger and validates the helper-produced wheel plan and selected
//! template before projecting typed behavior evidence.

use crate::{
    linux_vz_helper_diagnostics::{
        linux_vz_helper_failure_class_v1, MAX_LINUX_VZ_HELPER_RESULT_WIRE_BYTES_V1,
    },
    project_exact_detonation_behavior_v1, BoundOptionalEvidenceOutcomeV1, BoundOptionalEvidenceV1,
    ExactArtifactAdapterRequestV1, ExactArtifactDetonationAdapterV1, ExactArtifactOptionalResultV1,
    ExactArtifactScenarioKindV1, ExactArtifactScenarioPlanV1, ExactArtifactStageStatusV1,
    ExactDetonationBehaviorProjectionInputV1, OptionalAdapterErrorV1, PackageExecutionLeaderV1,
    PreparedArtifact,
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
use whoathere_artifact::{
    detect_artifact_format, normalize_artifact, ArtifactEnvelope, ArtifactFormat, ArtifactManifest,
    Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_cache::VerifiedArtifactLease;
use whoathere_detector::{BehaviorAnalysisBundleV1, PackageTriggerV1};
use whoathere_detonation::{
    decode_and_validate_wheel_scenario_plan_v1, decode_and_validate_wheel_scenario_template_v1,
    expected_wheel_scenario_kinds_v1, ArtifactRuntimeTargetV1, WheelScenarioKindV1,
    MAX_WHEEL_SCENARIO_PLAN_WIRE_BYTES_V1, MAX_WHEEL_SCENARIO_TEMPLATE_WIRE_BYTES_V1,
};

const PROVIDER_ID: &str = "linux_vz_exact_wheel_v1";
const CONFIG_ARTIFACT_KIND: &str = "pypi_wheel";
const HELPER_ARTIFACT_KIND: &str = "wheel";
const HELPER_RESULT_SCHEMA_V1: &str = "whoathere.linux_vz_package_execution_result.v1";
const MAX_ROOT_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_SENSOR_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HOST_EXECUTION_RUN_BYTES: usize = 1024 * 1024;
const MAX_ARTIFACT_ENVELOPE_BYTES: usize = 1024 * 1024;
static RUN_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Inputs for projecting one already-produced exact-wheel helper action.
///
/// This path does not execute the artifact or invoke the VM helper. It
/// re-normalizes the exact wheel, verifies the retained outer bindings, and
/// feeds the existing signed/digest-bound helper evidence into the same
/// behavior projector used by live detonation.
#[derive(Debug, Clone, Copy)]
pub struct OfflineExactWheelBehaviorProjectionRequestV1<'a> {
    pub artifact_path: &'a Path,
    pub artifact_envelope_path: &'a Path,
    pub artifact_manifest_path: &'a Path,
    pub evidence_directory: &'a Path,
    pub scenario_index: usize,
    pub normalization_limits: NormalizationLimits,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfflineExactWheelBehaviorProjectionErrorV1 {
    reason_code: &'static str,
}

impl OfflineExactWheelBehaviorProjectionErrorV1 {
    fn new(reason_code: &'static str) -> Self {
        Self { reason_code }
    }

    pub const fn reason_code(self) -> &'static str {
        self.reason_code
    }
}

impl std::fmt::Display for OfflineExactWheelBehaviorProjectionErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for OfflineExactWheelBehaviorProjectionErrorV1 {}

/// Project a retained exact-wheel helper action without rerunning package code.
///
/// The output remains observe-only. In particular, the existing projector
/// carries the helper's `guest_root_receipt_independently_verified=false` and
/// `host_composition_complete=false` flags into incomplete bundle coverage; it
/// never upgrades missing host composition to clean evidence.
pub fn project_offline_exact_wheel_behavior_v1(
    request: OfflineExactWheelBehaviorProjectionRequestV1<'_>,
) -> Result<BehaviorAnalysisBundleV1, OfflineExactWheelBehaviorProjectionErrorV1> {
    if !is_directory_non_symlink(request.evidence_directory) {
        return Err(OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_evidence_directory_unavailable",
        ));
    }
    let maximum_artifact_bytes =
        usize::try_from(request.normalization_limits.max_original_bytes).unwrap_or(usize::MAX);
    let artifact_bytes = read_offline_projection_file(
        request.artifact_path,
        maximum_artifact_bytes,
        "wheel_behavior_projection_artifact_unavailable",
    )?;
    let envelope_bytes = read_offline_projection_file(
        request.artifact_envelope_path,
        MAX_ARTIFACT_ENVELOPE_BYTES,
        "wheel_behavior_projection_artifact_envelope_unavailable",
    )?;
    let manifest_bytes = read_offline_projection_file(
        request.artifact_manifest_path,
        maximum_artifact_bytes,
        "wheel_behavior_projection_artifact_manifest_unavailable",
    )?;

    let envelope: ArtifactEnvelope = serde_json::from_slice(&envelope_bytes).map_err(|_| {
        OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_envelope_invalid",
        )
    })?;
    let canonical_envelope = envelope.canonical_json().map_err(|_| {
        OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_envelope_invalid",
        )
    })?;
    if canonical_envelope != envelope_bytes
        || envelope.ecosystem != Ecosystem::Pypi
        || envelope.magic_detected_format != ArtifactFormat::WheelZip
        || !envelope.matches_original_bytes(&artifact_bytes)
    {
        return Err(OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_envelope_binding_mismatch",
        ));
    }
    let detected_format = detect_artifact_format(
        envelope.ecosystem,
        &envelope.original_filename,
        &artifact_bytes,
    )
    .map_err(|_| {
        OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_format_invalid",
        )
    })?;
    if detected_format != ArtifactFormat::WheelZip || !envelope.verify_magic_format(detected_format)
    {
        return Err(OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_format_binding_mismatch",
        ));
    }

    let supplied_manifest: ArtifactManifest =
        serde_json::from_slice(&manifest_bytes).map_err(|_| {
            OfflineExactWheelBehaviorProjectionErrorV1::new(
                "wheel_behavior_projection_artifact_manifest_invalid",
            )
        })?;
    let canonical_manifest = serde_json::to_vec(&supplied_manifest).map_err(|_| {
        OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_manifest_invalid",
        )
    })?;
    if canonical_manifest != manifest_bytes {
        return Err(OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_manifest_noncanonical",
        ));
    }
    let normalized = normalize_artifact(&envelope, &artifact_bytes, request.normalization_limits)
        .map_err(|_| {
        OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_normalization_failed",
        )
    })?;
    if supplied_manifest != normalized.manifest {
        return Err(OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_manifest_binding_mismatch",
        ));
    }
    let expected_kinds = expected_wheel_scenario_kinds_v1(&normalized.manifest).map_err(|_| {
        OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_expected_scenarios_invalid",
        )
    })?;
    if request.scenario_index >= expected_kinds.len() {
        return Err(OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_scenario_index_invalid",
        ));
    }

    let artifact_sha256 = Sha256Digest::from_bytes(&artifact_bytes);
    let envelope_sha256 = envelope.envelope_sha256().map_err(|_| {
        OfflineExactWheelBehaviorProjectionErrorV1::new(
            "wheel_behavior_projection_artifact_envelope_invalid",
        )
    })?;
    project_wheel_action_behavior_v1(
        request.evidence_directory,
        request.scenario_index,
        &artifact_sha256,
        &envelope_sha256,
        &normalized.manifest.manifest_sha256,
        artifact_bytes.len(),
        &envelope.original_filename,
        &expected_kinds,
        &normalized.manifest,
    )
    .map_err(OfflineExactWheelBehaviorProjectionErrorV1::new)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzExactWheelDetonationConfigV1 {
    /// Required serialized discriminator. The helper CLI uses the shorter
    /// `wheel` spelling, while retained package contracts use `pypi_wheel`.
    pub artifact_kind: String,
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
pub struct LinuxVzExactWheelDetonationAdapterV1 {
    config: LinuxVzExactWheelDetonationConfigV1,
}

impl LinuxVzExactWheelDetonationAdapterV1 {
    pub fn new(
        config: LinuxVzExactWheelDetonationConfigV1,
    ) -> Result<Self, OptionalAdapterErrorV1> {
        let adapter = Self { config };
        if let Some(reason) = adapter.configuration_reason() {
            return Err(OptionalAdapterErrorV1::new(reason));
        }
        Ok(adapter)
    }

    pub fn config(&self) -> &LinuxVzExactWheelDetonationConfigV1 {
        &self.config
    }

    fn configuration_reason(&self) -> Option<&'static str> {
        if self.config.artifact_kind != CONFIG_ARTIFACT_KIND {
            return Some("linux_vz_exact_wheel_artifact_kind_invalid");
        }
        if !(30..=600).contains(&self.config.timeout_seconds) {
            return Some("linux_vz_exact_wheel_timeout_invalid");
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
            return Some("linux_vz_exact_wheel_input_invalid");
        }
        let helper_mode = match fs::symlink_metadata(&self.config.helper_path) {
            Ok(metadata) => metadata.permissions().mode(),
            Err(_) => return Some("linux_vz_exact_wheel_helper_unreadable"),
        };
        if helper_mode & 0o111 == 0 {
            return Some("linux_vz_exact_wheel_helper_not_executable");
        }
        if let Some(expected) = &self.config.helper_sha256 {
            if Sha256Digest::parse(expected.clone()).is_err() {
                return Some("linux_vz_exact_wheel_helper_digest_invalid");
            }
            let bytes = match fs::read(&self.config.helper_path) {
                Ok(bytes) => bytes,
                Err(_) => return Some("linux_vz_exact_wheel_helper_unreadable"),
            };
            if Sha256Digest::from_bytes(&bytes).as_str() != expected {
                return Some("linux_vz_exact_wheel_helper_digest_mismatch");
            }
        }
        match fs::symlink_metadata(&self.config.output_root) {
            Ok(metadata)
                if metadata.file_type().is_dir() && metadata.permissions().mode() & 0o077 == 0 => {}
            Ok(_) => return Some("linux_vz_exact_wheel_output_root_invalid"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let Some(parent) = self.config.output_root.parent() else {
                    return Some("linux_vz_exact_wheel_output_root_invalid");
                };
                if !is_directory_non_symlink(parent) {
                    return Some("linux_vz_exact_wheel_output_root_invalid");
                }
            }
            Err(_) => return Some("linux_vz_exact_wheel_output_root_invalid"),
        }
        None
    }

    #[allow(clippy::too_many_arguments)]
    fn run_action(
        &self,
        run_root: &Path,
        scenario_index: usize,
        artifact_filename: &str,
        artifact_bytes: &[u8],
        artifact_sha256: &Sha256Digest,
        envelope_sha256: &Sha256Digest,
        manifest_sha256: &Sha256Digest,
        expected_kinds: &[WheelScenarioKindV1],
        prepared: &PreparedArtifact,
    ) -> WheelActionRunV1 {
        let action_root = run_root.join(format!("action-{scenario_index:04}"));
        let evidence_directory = action_root.join("evidence");
        if create_private_directory(&action_root).is_err()
            || create_private_directory(&evidence_directory).is_err()
        {
            return WheelActionRunV1::incomplete(
                scenario_index,
                "output_directory_creation_failed",
            );
        }
        let artifact_path = action_root.join(artifact_filename);
        if write_new_private_file(&artifact_path, artifact_bytes).is_err() {
            return WheelActionRunV1::incomplete(scenario_index, "artifact_materialization_failed");
        }
        let artifact_envelope_path = action_root.join("artifact-envelope.json");
        let artifact_manifest_path = action_root.join("artifact-manifest.json");
        let artifact_envelope_bytes = match prepared.envelope().canonical_json() {
            Ok(bytes) => bytes,
            Err(_) => {
                return WheelActionRunV1::incomplete(
                    scenario_index,
                    "artifact_binding_serialization_failed",
                )
            }
        };
        let artifact_manifest_bytes = match serde_json::to_vec(&prepared.normalized().manifest) {
            Ok(bytes) => bytes,
            Err(_) => {
                return WheelActionRunV1::incomplete(
                    scenario_index,
                    "artifact_binding_serialization_failed",
                )
            }
        };
        if write_new_private_file(&artifact_envelope_path, &artifact_envelope_bytes).is_err()
            || write_new_private_file(&artifact_manifest_path, &artifact_manifest_bytes).is_err()
        {
            return WheelActionRunV1::incomplete(
                scenario_index,
                "artifact_binding_materialization_failed",
            );
        }

        let output = Command::new(&self.config.helper_path)
            .arg("--artifact")
            .arg(&artifact_path)
            .arg("--artifact-envelope")
            .arg(&artifact_envelope_path)
            .arg("--artifact-manifest")
            .arg(&artifact_manifest_path)
            .arg("--artifact-kind")
            .arg(HELPER_ARTIFACT_KIND)
            .arg("--scenario-index")
            .arg(scenario_index.to_string())
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
            Err(_) => {
                return WheelActionRunV1::incomplete(scenario_index, "helper_invocation_failed")
            }
        };
        if output.stdout.len() > MAX_LINUX_VZ_HELPER_RESULT_WIRE_BYTES_V1 {
            return WheelActionRunV1::incomplete(scenario_index, "helper_output_oversize");
        }
        let parsed = match serde_json::from_slice::<PhysicalWheelHelperResultV1>(&output.stdout) {
            Ok(parsed) => parsed,
            Err(_) => return WheelActionRunV1::incomplete(scenario_index, "helper_output_invalid"),
        };
        let mut limitations = Vec::new();
        if !output.status.success() {
            limitations.push("helper_process_failed");
            limitations.push(linux_vz_helper_failure_class_v1(parsed.reason.as_deref()));
        }
        if parsed.schema_version != HELPER_RESULT_SCHEMA_V1 {
            limitations.push("helper_schema_invalid");
        }
        if parsed.artifact_kind.as_deref() != Some(HELPER_ARTIFACT_KIND) {
            limitations.push("artifact_kind_binding_not_proven");
        }
        let expected_scenario_index = scenario_index.to_string();
        if parsed.scenario_index.as_deref() != Some(expected_scenario_index.as_str()) {
            limitations.push("scenario_index_binding_not_proven");
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

        let behavior_projection = project_wheel_action_behavior_v1(
            &evidence_directory,
            scenario_index,
            artifact_sha256,
            envelope_sha256,
            manifest_sha256,
            artifact_bytes.len(),
            artifact_filename,
            expected_kinds,
            &prepared.normalized().manifest,
        );
        let behavior_bundle = match behavior_projection {
            Ok(bundle) => match serde_json::to_vec(&bundle) {
                Err(_) => {
                    limitations.push("wheel_behavior_projection_bundle_serialization_failed");
                    None
                }
                Ok(bundle_bytes)
                    if write_new_private_file(
                        &evidence_directory.join("behavior-bundle.json"),
                        &bundle_bytes,
                    )
                    .is_err() =>
                {
                    limitations.push("wheel_behavior_projection_bundle_write_failed");
                    None
                }
                Ok(_) => Some(bundle),
            },
            Err(reason) => {
                limitations.push(reason);
                None
            }
        };
        WheelActionRunV1 {
            scenario_index,
            evidence_captured: limitations.is_empty(),
            limitations,
            behavior_bundle,
        }
    }
}

impl ExactArtifactDetonationAdapterV1 for LinuxVzExactWheelDetonationAdapterV1 {
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
        matches!(
            scenarios.status,
            ExactArtifactStageStatusV1::Complete | ExactArtifactStageStatusV1::Incomplete
        ) && !scenarios.executable
            && scenarios.runtime_binding_status == "not_bound"
            && supported_wheel_plan_v1(prepared, scenarios)
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
                    vec!["vm_wheel_manifest_binding_invalid".to_string()],
                )
            }
        };
        let envelope_digest = match Sha256Digest::parse(request.envelope_sha256.clone()) {
            Ok(digest) => digest,
            Err(_) => {
                return incomplete_result(
                    &request.request_sha256,
                    vec!["vm_wheel_envelope_binding_invalid".to_string()],
                )
            }
        };
        let prepared_envelope_digest = match prepared.envelope().envelope_sha256() {
            Ok(digest) => digest,
            Err(_) => {
                return incomplete_result(
                    &request.request_sha256,
                    vec!["vm_wheel_envelope_binding_invalid".to_string()],
                )
            }
        };
        if self.configuration_reason().is_some()
            || artifact_sha256 != request.artifact_sha256
            || artifact_sha256 != prepared.evidence_subject().artifact_sha256()
            || envelope_digest != prepared_envelope_digest
            || manifest_digest != prepared.normalized().manifest.manifest_sha256
            || !matches!(
                scenarios.status,
                ExactArtifactStageStatusV1::Complete | ExactArtifactStageStatusV1::Incomplete
            )
            || scenarios.runtime_binding_status != "verified"
            || !scenarios.executable
            || !supported_wheel_plan_v1(prepared, scenarios)
        {
            return incomplete_result(
                &request.request_sha256,
                vec!["vm_wheel_runtime_or_artifact_binding_invalid".to_string()],
            );
        }
        let expected_kinds = match wheel_kinds_from_plan_v1(scenarios) {
            Some(kinds) => kinds,
            None => {
                return incomplete_result(
                    &request.request_sha256,
                    vec!["vm_wheel_scenario_plan_invalid".to_string()],
                )
            }
        };
        let run_root =
            match create_fresh_run_root(&self.config.output_root, &request.request_sha256) {
                Ok(path) => path,
                Err(_) => {
                    return incomplete_result(
                        &request.request_sha256,
                        vec!["vm_wheel_output_directory_creation_failed".to_string()],
                    )
                }
            };
        let artifact_filename = prepared.envelope().original_filename.as_str();
        let runs = expected_kinds
            .iter()
            .enumerate()
            .map(|(scenario_index, _)| {
                self.run_action(
                    &run_root,
                    scenario_index,
                    artifact_filename,
                    artifact.bytes(),
                    &artifact_digest,
                    &envelope_digest,
                    &manifest_digest,
                    &expected_kinds,
                    prepared,
                )
            })
            .collect::<Vec<_>>();

        let mut reasons = vec![
            "vm_wheel_evidence_captured_pending_analysis".to_string(),
            "vm_wheel_evidence_output_preserved".to_string(),
        ];
        if prepared.envelope().requires_external_dependency_resolution {
            reasons.push("vm_wheel_dependency_closure_not_installed".to_string());
        }
        let mut behavior_bundles = Vec::new();
        for run in runs {
            if let Some(bundle) = run.behavior_bundle.as_ref() {
                let digest = bundle.bundle_sha256();
                reasons.push(format!(
                    "vm_wheel_action_{}_behavior_bundle_sha256:{}",
                    run.scenario_index,
                    digest.as_str().trim_start_matches("sha256:")
                ));
                reasons.push(format!(
                    "vm_wheel_action_{}_behavior_bundle_projected",
                    run.scenario_index
                ));
                reasons.push(format!(
                    "vm_wheel_action_{}_behavior_event_count:{}",
                    run.scenario_index,
                    bundle.events().len()
                ));
            }
            if !run.evidence_captured {
                reasons.push(format!(
                    "vm_wheel_action_{}_evidence_incomplete",
                    run.scenario_index
                ));
            }
            reasons.extend(
                run.limitations
                    .into_iter()
                    .map(|reason| format!("vm_wheel_action_{}_{}", run.scenario_index, reason)),
            );
            if let Some(bundle) = run.behavior_bundle {
                behavior_bundles.push(bundle);
            }
        }
        incomplete_result_with_behavior_bundles(&request.request_sha256, reasons, behavior_bundles)
    }
}

fn supported_wheel_plan_v1(
    prepared: &PreparedArtifact,
    scenarios: &ExactArtifactScenarioPlanV1,
) -> bool {
    if prepared.normalized().manifest.magic_detected_format != ArtifactFormat::WheelZip {
        return false;
    }
    let Some(wheel) = prepared.normalized().manifest.metadata.wheel.as_ref() else {
        return false;
    };
    if wheel.root_is_purelib != Some(true)
        || !wheel.native_tags.is_empty()
        || !prepared
            .normalized()
            .manifest
            .native_binary_file_ids
            .is_empty()
        || wheel.tags.iter().any(|tag| !tag.ends_with("-none-any"))
        || !wheel.script_file_ids.is_empty()
    {
        return false;
    }
    let expected = match expected_wheel_scenario_kinds_v1(&prepared.normalized().manifest) {
        Ok(expected) => expected,
        Err(_) => return false,
    };
    wheel_kinds_from_plan_v1(scenarios).is_some_and(|actual| actual == expected)
}

fn wheel_kinds_from_plan_v1(
    scenarios: &ExactArtifactScenarioPlanV1,
) -> Option<Vec<WheelScenarioKindV1>> {
    scenarios
        .intents
        .iter()
        .map(|intent| match &intent.kind {
            ExactArtifactScenarioKindV1::Wheel(kind) => Some(kind.clone()),
            ExactArtifactScenarioKindV1::Npm(_) | ExactArtifactScenarioKindV1::Sdist(_) => None,
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct PhysicalWheelHelperResultV1 {
    schema_version: String,
    status: String,
    reason: Option<String>,
    artifact_kind: Option<String>,
    scenario_index: Option<String>,
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

struct WheelActionRunV1 {
    scenario_index: usize,
    evidence_captured: bool,
    limitations: Vec<&'static str>,
    behavior_bundle: Option<BehaviorAnalysisBundleV1>,
}

impl WheelActionRunV1 {
    fn incomplete(scenario_index: usize, reason: &'static str) -> Self {
        Self {
            scenario_index,
            evidence_captured: false,
            limitations: vec![reason],
            behavior_bundle: None,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn project_wheel_action_behavior_v1(
    evidence_directory: &Path,
    scenario_index: usize,
    artifact_sha256: &Sha256Digest,
    envelope_sha256: &Sha256Digest,
    manifest_sha256: &Sha256Digest,
    artifact_byte_length: usize,
    artifact_filename: &str,
    expected_kinds: &[WheelScenarioKindV1],
    manifest: &ArtifactManifest,
) -> Result<BehaviorAnalysisBundleV1, &'static str> {
    let scenario_plan_json = read_bounded_regular_file(
        &evidence_directory.join("execution-bundle/scenario-plan.json"),
        MAX_WHEEL_SCENARIO_PLAN_WIRE_BYTES_V1,
    )?;
    let scenario_template_json = read_bounded_regular_file(
        &evidence_directory.join("execution-bundle/scenario-template.json"),
        MAX_WHEEL_SCENARIO_TEMPLATE_WIRE_BYTES_V1,
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

    let plan = decode_and_validate_wheel_scenario_plan_v1(&scenario_plan_json)
        .map_err(|_| "wheel_behavior_projection_scenario_plan_invalid")?;
    let template = decode_and_validate_wheel_scenario_template_v1(&scenario_template_json)
        .map_err(|_| "wheel_behavior_projection_scenario_template_invalid")?;
    let expected_kind = expected_kinds
        .get(scenario_index)
        .ok_or("wheel_behavior_projection_scenario_index_invalid")?;
    let selected_reference = plan
        .templates()
        .get(scenario_index)
        .ok_or("wheel_behavior_projection_scenario_index_invalid")?;
    let manifest_identity = manifest
        .identity
        .as_ref()
        .ok_or("wheel_behavior_projection_manifest_identity_invalid")?;
    if plan.artifact_sha256() != artifact_sha256
        || plan.envelope_sha256() != envelope_sha256
        || plan.manifest_sha256() != manifest_sha256
        || plan.policy_sha256() != template.policy_sha256()
        || plan.templates().len() != expected_kinds.len()
        || plan
            .templates()
            .iter()
            .map(|reference| &reference.1)
            .ne(expected_kinds.iter())
        || template.artifact_sha256() != artifact_sha256
        || template.envelope_sha256() != envelope_sha256
        || template.manifest_sha256() != manifest_sha256
        || template.artifact_byte_length() != artifact_byte_length as u64
        || template.artifact_filename() != artifact_filename
        || template.package_normalized_name() != manifest_identity.normalized_name
        || template.package_version() != manifest_identity.version
        || template.runtime_target() != ArtifactRuntimeTargetV1::LinuxArm64
        || template.scenario_id() != selected_reference.0
        || template.scenario_kind() != expected_kind
        || template.scenario_kind() != &selected_reference.1
        || template.template_sha256() != &selected_reference.2
    {
        return Err("wheel_behavior_projection_scenario_binding_mismatch");
    }

    let root_value: Value = serde_json::from_slice(&root_receipt_json)
        .map_err(|_| "wheel_behavior_projection_root_receipt_invalid")?;
    let claims = root_value
        .get("claims")
        .and_then(Value::as_object)
        .ok_or("wheel_behavior_projection_root_receipt_invalid")?;
    let claimed_scenario_sha256 = parse_projection_digest_field(claims, "scenario_plan_sha256")?;
    if &claimed_scenario_sha256 != plan.plan_sha256() {
        return Err("wheel_behavior_projection_scenario_binding_mismatch");
    }
    let process_plan_sha256 = parse_projection_digest_field(claims, "process_plan_sha256")?;
    let host_execution_run_sha256 = Sha256Digest::from_bytes(&host_execution_run_json);
    let template_value: Value = serde_json::from_slice(&scenario_template_json)
        .map_err(|_| "wheel_behavior_projection_scenario_template_invalid")?;
    let run_id = template_value
        .get("identity")
        .and_then(Value::as_object)
        .and_then(|identity| identity.get("run_id"))
        .and_then(Value::as_str)
        .ok_or("wheel_behavior_projection_scenario_template_invalid")?;
    let (package_trigger, package_execution_leader, expected_process_stage_name) =
        match expected_kind {
        WheelScenarioKindV1::InstallExactWheel => (
            None,
            PackageExecutionLeaderV1::Tooling,
            "python_pip_install_exact_wheel",
        ),
        WheelScenarioKindV1::FreshInterpreterPth { .. } => (
            Some(PackageTriggerV1::WheelPth),
            PackageExecutionLeaderV1::PackageCode,
            "python_fresh_interpreter_pth_probe",
        ),
        WheelScenarioKindV1::ImportRoot { .. } => (
            Some(PackageTriggerV1::WheelImport),
            PackageExecutionLeaderV1::PackageCode,
            "python_import_root_probe",
        ),
        WheelScenarioKindV1::ConsoleEntryPoint {
            argument_profile, ..
        } => match argument_profile {
            whoathere_detonation::WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperHelp => (
                Some(PackageTriggerV1::WheelEntryPoint),
                PackageExecutionLeaderV1::PackageCode,
                "python_installed_generated_console_wrapper_help_probe",
            ),
            whoathere_detonation::WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperNoArguments => (
                Some(PackageTriggerV1::WheelEntryPoint),
                PackageExecutionLeaderV1::PackageCode,
                "python_installed_generated_console_wrapper_no_arguments_probe",
            ),
        },
    };
    let bundle = project_exact_detonation_behavior_v1(ExactDetonationBehaviorProjectionInputV1 {
        artifact_sha256,
        manifest_sha256,
        scenario_id: template.scenario_id(),
        package_trigger,
        package_execution_leader,
        expected_process_stage_name,
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
    Ok(bundle)
}

fn parse_projection_digest_field(
    claims: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Sha256Digest, &'static str> {
    let digest = claims
        .get(field)
        .and_then(Value::as_str)
        .ok_or("wheel_behavior_projection_root_receipt_invalid")?;
    Sha256Digest::parse(digest.to_string())
        .map_err(|_| "wheel_behavior_projection_root_receipt_invalid")
}

fn read_bounded_regular_file(path: &Path, maximum: usize) -> Result<Vec<u8>, &'static str> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "wheel_behavior_projection_evidence_unavailable")?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err("wheel_behavior_projection_evidence_unavailable");
    }
    fs::read(path).map_err(|_| "wheel_behavior_projection_evidence_unavailable")
}

fn read_offline_projection_file(
    path: &Path,
    maximum: usize,
    reason_code: &'static str,
) -> Result<Vec<u8>, OfflineExactWheelBehaviorProjectionErrorV1> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| OfflineExactWheelBehaviorProjectionErrorV1::new(reason_code))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum as u64 {
        return Err(OfflineExactWheelBehaviorProjectionErrorV1::new(reason_code));
    }
    fs::read(path).map_err(|_| OfflineExactWheelBehaviorProjectionErrorV1::new(reason_code))
}

fn incomplete_result(
    request_sha256: &str,
    reason_codes: Vec<String>,
) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
    let result = ExactArtifactOptionalResultV1::new(
        request_sha256.to_string(),
        BoundOptionalEvidenceOutcomeV1::Incomplete,
        reason_codes,
    )?;
    Ok(BoundOptionalEvidenceV1 {
        canonical_result_bytes: result.to_canonical_json_bytes()?,
        behavior_bundles: Vec::new(),
    })
}

fn incomplete_result_with_behavior_bundles(
    request_sha256: &str,
    reason_codes: Vec<String>,
    behavior_bundles: Vec<BehaviorAnalysisBundleV1>,
) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
    let behavior_bundle_sha256s = behavior_bundles
        .iter()
        .map(BehaviorAnalysisBundleV1::bundle_sha256)
        .collect();
    let result = ExactArtifactOptionalResultV1::with_evidence(
        request_sha256.to_string(),
        BoundOptionalEvidenceOutcomeV1::Incomplete,
        reason_codes,
        Vec::new(),
        behavior_bundle_sha256s,
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
        "unable to allocate fresh run root",
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
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
