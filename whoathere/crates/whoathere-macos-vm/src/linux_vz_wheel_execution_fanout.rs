//! Host-independent wheel execution fanout.
//!
//! This contract is the bridge between one exact, normalized wheel and the per-scenario Linux VZ
//! authority/grant pipeline. It issues no authority and launches no VM. Instead, it proves that the
//! complete supported trigger matrix is represented by one fresh-VM/fresh-grant intent per typed
//! scenario. Any unsupported or missing surface fails closed before a host can mint a grant.

use crate::{
    expected_macos_linux_vz_wheel_process_action_count_v1,
    validate_macos_linux_vz_typed_package_scenario_binding_v1, MacosLinuxVzPackageArtifactKindV1,
};
use serde::Serialize;
use std::fmt;
use whoathere_artifact::{
    normalize_artifact, ArtifactEnvelope, ArtifactFormat, ArtifactManifest, Ecosystem, MemberType,
    NormalizationCompleteness, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    decode_and_validate_wheel_scenario_plan_v1, decode_and_validate_wheel_scenario_template_v1,
    expected_wheel_scenario_kinds_v1, ArtifactRuntimeTargetV1, ArtifactScenarioCompileErrorV1,
    WheelConsoleArgumentProfileV1, WheelScenarioKindV1, WheelScenarioPlanV1,
    MAX_EXECUTION_BUNDLE_ACTIONS_V2,
};

pub const MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_wheel_execution_fanout.v1";
pub const MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_CANONICALIZATION_V1: &str = "rfc8785.jcs.v1";
pub const MAX_MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_BYTES_V1: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzWheelExecutionFanoutFailureDispositionV1 {
    Inconclusive,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzWheelExecutionFanoutErrorV1 {
    EnvelopeInvalid,
    ExactArtifactInvalid,
    ManifestInvalid,
    ManifestArtifactMismatch,
    NormalizationIncomplete,
    UnsupportedDependencies,
    UnsupportedNativeWheel,
    UnsupportedWheelScript,
    UnsupportedPthInventory,
    MissingPthBinding,
    AmbiguousConsoleSemantics,
    ScenarioPlanInvalid,
    ScenarioCoverageMismatch,
    RuntimeTargetMismatch,
    IdentityMismatch,
    ExpectedScenarioCountMismatch,
    LimitExceeded,
    Serialization,
}

impl MacosLinuxVzWheelExecutionFanoutErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::EnvelopeInvalid => "linux_vz_wheel_fanout_envelope_invalid",
            Self::ExactArtifactInvalid => "linux_vz_wheel_fanout_exact_artifact_invalid",
            Self::ManifestInvalid => "linux_vz_wheel_fanout_manifest_invalid",
            Self::ManifestArtifactMismatch => "linux_vz_wheel_fanout_manifest_artifact_mismatch",
            Self::NormalizationIncomplete => "linux_vz_wheel_fanout_normalization_incomplete",
            Self::UnsupportedDependencies => "linux_vz_wheel_fanout_dependencies_unsupported",
            Self::UnsupportedNativeWheel => "linux_vz_wheel_fanout_native_wheel_unsupported",
            Self::UnsupportedWheelScript => "linux_vz_wheel_fanout_wheel_script_unsupported",
            Self::UnsupportedPthInventory => "linux_vz_wheel_fanout_pth_inventory_manual_review",
            Self::MissingPthBinding => "linux_vz_wheel_fanout_pth_binding_missing",
            Self::AmbiguousConsoleSemantics => "linux_vz_wheel_fanout_console_semantics_ambiguous",
            Self::ScenarioPlanInvalid => "linux_vz_wheel_fanout_scenario_plan_invalid",
            Self::ScenarioCoverageMismatch => "linux_vz_wheel_fanout_scenario_coverage_mismatch",
            Self::RuntimeTargetMismatch => "linux_vz_wheel_fanout_runtime_target_mismatch",
            Self::IdentityMismatch => "linux_vz_wheel_fanout_identity_mismatch",
            Self::ExpectedScenarioCountMismatch => {
                "linux_vz_wheel_fanout_expected_scenario_count_mismatch"
            }
            Self::LimitExceeded => "linux_vz_wheel_fanout_limit_exceeded",
            Self::Serialization => "linux_vz_wheel_fanout_serialization_failed",
        }
    }

    pub const fn disposition(self) -> MacosLinuxVzWheelExecutionFanoutFailureDispositionV1 {
        match self {
            Self::UnsupportedDependencies
            | Self::UnsupportedNativeWheel
            | Self::UnsupportedWheelScript
            | Self::UnsupportedPthInventory
            | Self::AmbiguousConsoleSemantics => {
                MacosLinuxVzWheelExecutionFanoutFailureDispositionV1::ManualReview
            }
            _ => MacosLinuxVzWheelExecutionFanoutFailureDispositionV1::Inconclusive,
        }
    }

    pub const fn establishes_clean_behavior(self) -> bool {
        false
    }
}

impl fmt::Display for MacosLinuxVzWheelExecutionFanoutErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzWheelExecutionFanoutErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzWheelVmIsolationIntentV1 {
    FreshDisposableVmClonePerAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzWheelGrantIntentV1 {
    FreshOneUseGrantPerActionNotYetIssued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzWheelEnvironmentIntentV1 {
    FreshVirtualEnvironmentPerAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzWheelTeardownIntentV1 {
    StopVmDestroyCloneNoSyncBack,
}

/// One scenario-level execution intent. Probe intents are composite: they install the exact wheel
/// in their own fresh virtual environment before activating the selected trigger.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosLinuxVzWheelExecutionActionIntentV1 {
    action_index: u32,
    job_id: String,
    run_id: String,
    evidence_id: String,
    scenario_id: String,
    scenario_kind: WheelScenarioKindV1,
    scenario_template_sha256: Sha256Digest,
    authority_binding_subject_sha256: Sha256Digest,
    expected_process_action_count: u32,
    vm_isolation_intent: MacosLinuxVzWheelVmIsolationIntentV1,
    grant_intent: MacosLinuxVzWheelGrantIntentV1,
    environment_intent: MacosLinuxVzWheelEnvironmentIntentV1,
    teardown_intent: MacosLinuxVzWheelTeardownIntentV1,
    exact_offline_install_required: bool,
    public_network_route_present: bool,
    sync_back_permitted: bool,
    execution_authority_issued: bool,
    #[serde(skip)]
    scenario_template_canonical_json: Vec<u8>,
}

impl fmt::Debug for MacosLinuxVzWheelExecutionActionIntentV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzWheelExecutionActionIntentV1")
            .field("action_index", &self.action_index)
            .field("scenario_id", &self.scenario_id)
            .field("scenario_kind", &self.scenario_kind)
            .field("scenario_template_sha256", &self.scenario_template_sha256)
            .field(
                "authority_binding_subject_sha256",
                &self.authority_binding_subject_sha256,
            )
            .field(
                "expected_process_action_count",
                &self.expected_process_action_count,
            )
            .field("scenario_template_canonical_json", &"<digest-bound>")
            .finish()
    }
}

impl MacosLinuxVzWheelExecutionActionIntentV1 {
    pub const fn action_index(&self) -> u32 {
        self.action_index
    }

    pub fn job_id(&self) -> &str {
        &self.job_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn scenario_kind(&self) -> &WheelScenarioKindV1 {
        &self.scenario_kind
    }

    pub fn scenario_template_sha256(&self) -> &Sha256Digest {
        &self.scenario_template_sha256
    }

    pub fn authority_binding_subject_sha256(&self) -> &Sha256Digest {
        &self.authority_binding_subject_sha256
    }

    pub const fn expected_process_action_count(&self) -> u32 {
        self.expected_process_action_count
    }

    pub fn scenario_template_canonical_json_v1(&self) -> &[u8] {
        &self.scenario_template_canonical_json
    }

    pub const fn vm_isolation_intent(&self) -> MacosLinuxVzWheelVmIsolationIntentV1 {
        self.vm_isolation_intent
    }

    pub const fn grant_intent(&self) -> MacosLinuxVzWheelGrantIntentV1 {
        self.grant_intent
    }

    pub const fn environment_intent(&self) -> MacosLinuxVzWheelEnvironmentIntentV1 {
        self.environment_intent
    }

    pub const fn teardown_intent(&self) -> MacosLinuxVzWheelTeardownIntentV1 {
        self.teardown_intent
    }

    pub const fn exact_offline_install_required(&self) -> bool {
        self.exact_offline_install_required
    }

    pub const fn execution_authority_issued(&self) -> bool {
        self.execution_authority_issued
    }

    pub const fn public_network_route_present(&self) -> bool {
        self.public_network_route_present
    }

    pub const fn sync_back_permitted(&self) -> bool {
        self.sync_back_permitted
    }

    pub const fn establishes_clean_behavior(&self) -> bool {
        false
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WheelActionBindingDigestWireV1<'a> {
    schema_version: &'static str,
    artifact_sha256: &'a Sha256Digest,
    manifest_sha256: &'a Sha256Digest,
    scenario_plan_sha256: &'a Sha256Digest,
    action_index: u32,
    scenario_id: &'a str,
    scenario_kind: &'a WheelScenarioKindV1,
    scenario_template_sha256: &'a Sha256Digest,
    expected_process_action_count: u32,
    vm_isolation_intent: MacosLinuxVzWheelVmIsolationIntentV1,
    grant_intent: MacosLinuxVzWheelGrantIntentV1,
    environment_intent: MacosLinuxVzWheelEnvironmentIntentV1,
    teardown_intent: MacosLinuxVzWheelTeardownIntentV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WheelFanoutDigestWireV1<'a> {
    schema_version: &'static str,
    canonicalization: &'static str,
    artifact_sha256: &'a Sha256Digest,
    artifact_byte_length: u64,
    envelope_sha256: &'a Sha256Digest,
    manifest_sha256: &'a Sha256Digest,
    scenario_plan_id: &'a str,
    scenario_plan_sha256: &'a Sha256Digest,
    scenario_policy_sha256: &'a Sha256Digest,
    runtime_profile_sha256: &'a Sha256Digest,
    expected_scenario_count: u32,
    actions: &'a [MacosLinuxVzWheelExecutionActionIntentV1],
    exact_offline_install_required: bool,
    public_network_route_present: bool,
    sync_back_permitted: bool,
    execution_authority_issued: bool,
    observed_clean_permitted: bool,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WheelFanoutWireV1<'a> {
    schema_version: &'static str,
    canonicalization: &'static str,
    artifact_sha256: &'a Sha256Digest,
    artifact_byte_length: u64,
    envelope_sha256: &'a Sha256Digest,
    manifest_sha256: &'a Sha256Digest,
    scenario_plan_id: &'a str,
    scenario_plan_sha256: &'a Sha256Digest,
    scenario_policy_sha256: &'a Sha256Digest,
    runtime_profile_sha256: &'a Sha256Digest,
    expected_scenario_count: u32,
    actions: &'a [MacosLinuxVzWheelExecutionActionIntentV1],
    exact_offline_install_required: bool,
    public_network_route_present: bool,
    sync_back_permitted: bool,
    execution_authority_issued: bool,
    observed_clean_permitted: bool,
    fanout_sha256: &'a Sha256Digest,
}

pub struct MacosLinuxVzWheelExecutionFanoutRequestV1<'a> {
    pub envelope: &'a ArtifactEnvelope,
    pub artifact_bytes: &'a [u8],
    pub manifest: &'a ArtifactManifest,
    pub scenario_plan: &'a WheelScenarioPlanV1,
    pub expected_scenario_count: u32,
    pub normalization_limits: NormalizationLimits,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzWheelExecutionFanoutV1 {
    canonical_json: Vec<u8>,
    scenario_plan_canonical_json: Vec<u8>,
    fanout_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    scenario_plan_id: String,
    scenario_plan_sha256: Sha256Digest,
    scenario_policy_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    expected_scenario_count: u32,
    actions: Vec<MacosLinuxVzWheelExecutionActionIntentV1>,
}

impl fmt::Debug for MacosLinuxVzWheelExecutionFanoutV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzWheelExecutionFanoutV1")
            .field("fanout_sha256", &self.fanout_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("scenario_plan_sha256", &self.scenario_plan_sha256)
            .field("expected_scenario_count", &self.expected_scenario_count)
            .field("action_count", &self.actions.len())
            .finish()
    }
}

impl MacosLinuxVzWheelExecutionFanoutV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn fanout_sha256(&self) -> &Sha256Digest {
        &self.fanout_sha256
    }

    pub fn scenario_plan_canonical_json_v1(&self) -> &[u8] {
        &self.scenario_plan_canonical_json
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn envelope_sha256(&self) -> &Sha256Digest {
        &self.envelope_sha256
    }

    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub fn scenario_plan_id(&self) -> &str {
        &self.scenario_plan_id
    }

    pub fn scenario_plan_sha256(&self) -> &Sha256Digest {
        &self.scenario_plan_sha256
    }

    pub fn scenario_policy_sha256(&self) -> &Sha256Digest {
        &self.scenario_policy_sha256
    }

    pub fn runtime_profile_sha256(&self) -> &Sha256Digest {
        &self.runtime_profile_sha256
    }

    pub const fn expected_scenario_count(&self) -> u32 {
        self.expected_scenario_count
    }

    pub fn actions(&self) -> &[MacosLinuxVzWheelExecutionActionIntentV1] {
        &self.actions
    }

    pub const fn execution_authority_issued(&self) -> bool {
        false
    }

    pub const fn observed_clean_permitted(&self) -> bool {
        false
    }

    pub const fn public_network_route_present(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn compile_macos_linux_vz_wheel_execution_fanout_v1(
    request: MacosLinuxVzWheelExecutionFanoutRequestV1<'_>,
) -> Result<MacosLinuxVzWheelExecutionFanoutV1, MacosLinuxVzWheelExecutionFanoutErrorV1> {
    validate_exact_wheel_v1(
        request.envelope,
        request.artifact_bytes,
        request.manifest,
        request.normalization_limits,
    )?;
    let expected_kinds =
        expected_wheel_scenario_kinds_v1(request.manifest).map_err(map_scenario_error_v1)?;
    let expected_count = u32::try_from(expected_kinds.len())
        .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::LimitExceeded)?;
    if expected_count == 0
        || expected_count > MAX_EXECUTION_BUNDLE_ACTIONS_V2
        || request.expected_scenario_count != expected_count
    {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ExpectedScenarioCountMismatch);
    }

    let plan_bytes = request
        .scenario_plan
        .canonical_json_v1()
        .map_err(map_scenario_error_v1)?;
    let validated_plan = decode_and_validate_wheel_scenario_plan_v1(&plan_bytes)
        .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::ScenarioPlanInvalid)?;
    let envelope_sha256 = request
        .envelope
        .envelope_sha256()
        .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::EnvelopeInvalid)?;
    if validated_plan.plan_sha256() != request.scenario_plan.plan_sha256()
        || validated_plan.artifact_sha256() != &request.manifest.artifact_sha256
        || validated_plan.envelope_sha256() != &envelope_sha256
        || validated_plan.manifest_sha256() != &request.manifest.manifest_sha256
        || request.scenario_plan.subject().artifact_sha256()
            != request.manifest.artifact_sha256.as_str()
        || request.scenario_plan.subject().manifest_sha256()
            != request.manifest.manifest_sha256.as_str()
        || request.scenario_plan.subject().envelope_sha256() != envelope_sha256.as_str()
        || request.scenario_plan.templates().len() != expected_kinds.len()
        || validated_plan.templates().len() != expected_kinds.len()
    {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::IdentityMismatch);
    }

    let mut runtime_profile_sha256: Option<Sha256Digest> = None;
    let mut actions = Vec::with_capacity(expected_kinds.len());
    for (index, ((template, expected_kind), plan_reference)) in request
        .scenario_plan
        .templates()
        .iter()
        .zip(expected_kinds.iter())
        .zip(validated_plan.templates().iter())
        .enumerate()
    {
        if template.scenario_kind() != expected_kind
            || plan_reference.0 != template.identity().scenario_id()
            || &plan_reference.1 != expected_kind
            || &plan_reference.2 != template.template_sha256()
        {
            return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ScenarioCoverageMismatch);
        }
        require_supported_console_semantics_v1(expected_kind)?;
        let template_bytes = template
            .canonical_json_v1()
            .map_err(map_scenario_error_v1)?;
        let validated_template = decode_and_validate_wheel_scenario_template_v1(&template_bytes)
            .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::ScenarioPlanInvalid)?;
        if validated_template.runtime_target() != ArtifactRuntimeTargetV1::LinuxArm64 {
            return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::RuntimeTargetMismatch);
        }
        validate_macos_linux_vz_typed_package_scenario_binding_v1(
            MacosLinuxVzPackageArtifactKindV1::PypiWheel,
            &plan_bytes,
            &template_bytes,
        )
        .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::IdentityMismatch)?;
        if validated_template.artifact_sha256() != &request.manifest.artifact_sha256
            || validated_template.manifest_sha256() != &request.manifest.manifest_sha256
            || validated_template.artifact_byte_length() != request.artifact_bytes.len() as u64
            || validated_template.policy_sha256() != request.scenario_plan.policy_sha256()
            || validated_template.scenario_id() != template.identity().scenario_id()
            || validated_template.scenario_kind() != expected_kind
            || validated_template.template_sha256() != template.template_sha256()
        {
            return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::IdentityMismatch);
        }
        match runtime_profile_sha256.as_ref() {
            None => {
                runtime_profile_sha256 = Some(validated_template.runtime_profile_sha256().clone())
            }
            Some(expected) if expected == validated_template.runtime_profile_sha256() => {}
            Some(_) => return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::IdentityMismatch),
        }

        let action_index = u32::try_from(index)
            .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::LimitExceeded)?;
        let expected_process_action_count =
            expected_macos_linux_vz_wheel_process_action_count_v1(expected_kind);
        let authority_binding_subject_sha256 = action_binding_sha256_v1(
            &request.manifest.artifact_sha256,
            &request.manifest.manifest_sha256,
            request.scenario_plan.plan_sha256(),
            action_index,
            template.identity().scenario_id(),
            expected_kind,
            template.template_sha256(),
            expected_process_action_count,
        )?;
        actions.push(MacosLinuxVzWheelExecutionActionIntentV1 {
            action_index,
            job_id: template.identity().job_id().to_string(),
            run_id: template.identity().run_id().to_string(),
            evidence_id: template.identity().evidence_id().to_string(),
            scenario_id: template.identity().scenario_id().to_string(),
            scenario_kind: expected_kind.clone(),
            scenario_template_sha256: template.template_sha256().clone(),
            authority_binding_subject_sha256,
            expected_process_action_count,
            vm_isolation_intent:
                MacosLinuxVzWheelVmIsolationIntentV1::FreshDisposableVmClonePerAction,
            grant_intent: MacosLinuxVzWheelGrantIntentV1::FreshOneUseGrantPerActionNotYetIssued,
            environment_intent:
                MacosLinuxVzWheelEnvironmentIntentV1::FreshVirtualEnvironmentPerAction,
            teardown_intent: MacosLinuxVzWheelTeardownIntentV1::StopVmDestroyCloneNoSyncBack,
            exact_offline_install_required: true,
            public_network_route_present: false,
            sync_back_permitted: false,
            execution_authority_issued: false,
            scenario_template_canonical_json: template_bytes,
        });
    }

    let runtime_profile_sha256 = runtime_profile_sha256
        .ok_or(MacosLinuxVzWheelExecutionFanoutErrorV1::ScenarioCoverageMismatch)?;
    let fanout_sha256 = fanout_digest_v1(
        &request,
        &envelope_sha256,
        &runtime_profile_sha256,
        &actions,
    )?;
    let canonical_json = serde_json_canonicalizer::to_vec(&WheelFanoutWireV1 {
        schema_version: MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_SCHEMA_V1,
        canonicalization: MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_CANONICALIZATION_V1,
        artifact_sha256: &request.manifest.artifact_sha256,
        artifact_byte_length: request.artifact_bytes.len() as u64,
        envelope_sha256: &envelope_sha256,
        manifest_sha256: &request.manifest.manifest_sha256,
        scenario_plan_id: request.scenario_plan.plan_id(),
        scenario_plan_sha256: request.scenario_plan.plan_sha256(),
        scenario_policy_sha256: request.scenario_plan.policy_sha256(),
        runtime_profile_sha256: &runtime_profile_sha256,
        expected_scenario_count: request.expected_scenario_count,
        actions: &actions,
        exact_offline_install_required: true,
        public_network_route_present: false,
        sync_back_permitted: false,
        execution_authority_issued: false,
        observed_clean_permitted: false,
        fanout_sha256: &fanout_sha256,
    })
    .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_BYTES_V1
    {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzWheelExecutionFanoutV1 {
        canonical_json,
        scenario_plan_canonical_json: plan_bytes,
        fanout_sha256,
        artifact_sha256: request.manifest.artifact_sha256.clone(),
        artifact_byte_length: request.artifact_bytes.len() as u64,
        envelope_sha256,
        manifest_sha256: request.manifest.manifest_sha256.clone(),
        scenario_plan_id: request.scenario_plan.plan_id().to_string(),
        scenario_plan_sha256: request.scenario_plan.plan_sha256().clone(),
        scenario_policy_sha256: request.scenario_plan.policy_sha256().clone(),
        runtime_profile_sha256,
        expected_scenario_count: request.expected_scenario_count,
        actions,
    })
}

fn validate_exact_wheel_v1(
    envelope: &ArtifactEnvelope,
    artifact_bytes: &[u8],
    manifest: &ArtifactManifest,
    limits: NormalizationLimits,
) -> Result<(), MacosLinuxVzWheelExecutionFanoutErrorV1> {
    envelope
        .validate()
        .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::EnvelopeInvalid)?;
    manifest
        .validate()
        .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::ManifestInvalid)?;
    if artifact_bytes.is_empty()
        || envelope.ecosystem != Ecosystem::Pypi
        || envelope.magic_detected_format != ArtifactFormat::WheelZip
        || envelope.original_byte_length != artifact_bytes.len() as u64
        || envelope.original_sha256 != Sha256Digest::from_bytes(artifact_bytes)
        || manifest.magic_detected_format != ArtifactFormat::WheelZip
        || !(artifact_bytes.starts_with(b"PK\x03\x04")
            || artifact_bytes.starts_with(b"PK\x05\x06")
            || artifact_bytes.starts_with(b"PK\x07\x08"))
        || manifest.artifact_sha256 != Sha256Digest::from_bytes(artifact_bytes)
    {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ExactArtifactInvalid);
    }
    let reparsed = normalize_artifact(envelope, artifact_bytes, limits)
        .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::ManifestArtifactMismatch)?;
    if &reparsed.manifest != manifest {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ManifestArtifactMismatch);
    }
    if manifest
        .issues
        .iter()
        .any(|issue| issue.reason_code == "wheel_pth_inventory_not_site_packages_activation")
    {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedPthInventory);
    }
    if manifest.normalization_completeness != NormalizationCompleteness::Complete {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::NormalizationIncomplete);
    }
    let wheel = manifest
        .metadata
        .wheel
        .as_ref()
        .ok_or(MacosLinuxVzWheelExecutionFanoutErrorV1::ManifestInvalid)?;
    if !wheel.requires_dist.is_empty() {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedDependencies);
    }
    if wheel.root_is_purelib != Some(true)
        || !wheel.native_tags.is_empty()
        || !manifest.native_binary_file_ids.is_empty()
        || wheel.tags.iter().any(|tag| !tag.ends_with("-none-any"))
    {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedNativeWheel);
    }
    if !wheel.script_file_ids.is_empty() {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedWheelScript);
    }
    let mut expected_pth_ids = manifest
        .members
        .iter()
        .filter(|member| {
            member.member_type == MemberType::File
                && wheel_pth_has_site_packages_activation_semantics_v1(
                    &member.normalized_path,
                    wheel.dist_info_directory.as_deref().unwrap_or_default(),
                )
        })
        .map(|member| member.file_id.clone())
        .collect::<Vec<_>>();
    expected_pth_ids.sort();
    if expected_pth_ids != wheel.pth_file_ids {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::MissingPthBinding);
    }
    if wheel.console_entry_points
        != wheel
            .entry_points
            .get("console_scripts")
            .cloned()
            .unwrap_or_default()
        || (!wheel.console_entry_points.is_empty() && wheel.entry_points_file_id.is_none())
    {
        return Err(MacosLinuxVzWheelExecutionFanoutErrorV1::AmbiguousConsoleSemantics);
    }
    Ok(())
}

fn wheel_pth_has_site_packages_activation_semantics_v1(path: &str, dist_info: &str) -> bool {
    if !path.ends_with(".pth") {
        return false;
    }
    if !path.contains('/') {
        return true;
    }
    let Some(distribution_stem) = dist_info.strip_suffix(".dist-info") else {
        return false;
    };
    ["purelib", "platlib"].into_iter().any(|scheme| {
        let prefix = format!("{distribution_stem}.data/{scheme}/");
        path.strip_prefix(&prefix).is_some_and(|installed_path| {
            !installed_path.is_empty() && !installed_path.contains('/')
        })
    })
}

fn require_supported_console_semantics_v1(
    kind: &WheelScenarioKindV1,
) -> Result<(), MacosLinuxVzWheelExecutionFanoutErrorV1> {
    if matches!(
        kind,
        WheelScenarioKindV1::ConsoleEntryPoint {
            argument_profile: WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperHelp
                | WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperNoArguments,
            ..
        }
    ) || !matches!(kind, WheelScenarioKindV1::ConsoleEntryPoint { .. })
    {
        Ok(())
    } else {
        Err(MacosLinuxVzWheelExecutionFanoutErrorV1::AmbiguousConsoleSemantics)
    }
}

#[allow(clippy::too_many_arguments)]
fn action_binding_sha256_v1(
    artifact_sha256: &Sha256Digest,
    manifest_sha256: &Sha256Digest,
    scenario_plan_sha256: &Sha256Digest,
    action_index: u32,
    scenario_id: &str,
    scenario_kind: &WheelScenarioKindV1,
    scenario_template_sha256: &Sha256Digest,
    expected_process_action_count: u32,
) -> Result<Sha256Digest, MacosLinuxVzWheelExecutionFanoutErrorV1> {
    let bytes = serde_json_canonicalizer::to_vec(&WheelActionBindingDigestWireV1 {
        schema_version: "whoathere.macos_linux_vz_wheel_action_binding.v1",
        artifact_sha256,
        manifest_sha256,
        scenario_plan_sha256,
        action_index,
        scenario_id,
        scenario_kind,
        scenario_template_sha256,
        expected_process_action_count,
        vm_isolation_intent: MacosLinuxVzWheelVmIsolationIntentV1::FreshDisposableVmClonePerAction,
        grant_intent: MacosLinuxVzWheelGrantIntentV1::FreshOneUseGrantPerActionNotYetIssued,
        environment_intent: MacosLinuxVzWheelEnvironmentIntentV1::FreshVirtualEnvironmentPerAction,
        teardown_intent: MacosLinuxVzWheelTeardownIntentV1::StopVmDestroyCloneNoSyncBack,
    })
    .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::Serialization)?;
    Ok(Sha256Digest::from_bytes(&bytes))
}

fn fanout_digest_v1(
    request: &MacosLinuxVzWheelExecutionFanoutRequestV1<'_>,
    envelope_sha256: &Sha256Digest,
    runtime_profile_sha256: &Sha256Digest,
    actions: &[MacosLinuxVzWheelExecutionActionIntentV1],
) -> Result<Sha256Digest, MacosLinuxVzWheelExecutionFanoutErrorV1> {
    let bytes = serde_json_canonicalizer::to_vec(&WheelFanoutDigestWireV1 {
        schema_version: MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_SCHEMA_V1,
        canonicalization: MACOS_LINUX_VZ_WHEEL_EXECUTION_FANOUT_CANONICALIZATION_V1,
        artifact_sha256: &request.manifest.artifact_sha256,
        artifact_byte_length: request.artifact_bytes.len() as u64,
        envelope_sha256,
        manifest_sha256: &request.manifest.manifest_sha256,
        scenario_plan_id: request.scenario_plan.plan_id(),
        scenario_plan_sha256: request.scenario_plan.plan_sha256(),
        scenario_policy_sha256: request.scenario_plan.policy_sha256(),
        runtime_profile_sha256,
        expected_scenario_count: request.expected_scenario_count,
        actions,
        exact_offline_install_required: true,
        public_network_route_present: false,
        sync_back_permitted: false,
        execution_authority_issued: false,
        observed_clean_permitted: false,
    })
    .map_err(|_| MacosLinuxVzWheelExecutionFanoutErrorV1::Serialization)?;
    Ok(Sha256Digest::from_bytes(&bytes))
}

fn map_scenario_error_v1(
    error: ArtifactScenarioCompileErrorV1,
) -> MacosLinuxVzWheelExecutionFanoutErrorV1 {
    match error {
        ArtifactScenarioCompileErrorV1::IncompleteNormalization => {
            MacosLinuxVzWheelExecutionFanoutErrorV1::NormalizationIncomplete
        }
        ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure => {
            MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedDependencies
        }
        ArtifactScenarioCompileErrorV1::UnsupportedNativeArtifact => {
            MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedNativeWheel
        }
        ArtifactScenarioCompileErrorV1::UnsupportedWheelScript => {
            MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedWheelScript
        }
        ArtifactScenarioCompileErrorV1::InvalidTriggerSurface => {
            MacosLinuxVzWheelExecutionFanoutErrorV1::AmbiguousConsoleSemantics
        }
        ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded => {
            MacosLinuxVzWheelExecutionFanoutErrorV1::LimitExceeded
        }
        ArtifactScenarioCompileErrorV1::Serialization => {
            MacosLinuxVzWheelExecutionFanoutErrorV1::Serialization
        }
        _ => MacosLinuxVzWheelExecutionFanoutErrorV1::ScenarioPlanInvalid,
    }
}
