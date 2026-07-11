use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use whoathere_artifact::{PackageIdentity, Sha256Digest};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const ARTIFACT_SCENARIO_TEMPLATE_SCHEMA_V1: &str = "whoathere.artifact_scenario_template.v1";
pub const ARTIFACT_SCENARIO_PLAN_SCHEMA_V1: &str = "whoathere.artifact_scenario_plan.v1";
pub const ARTIFACT_SCENARIO_POLICY_SCHEMA_V1: &str = "whoathere.artifact_scenario_policy.v1";
pub const ARTIFACT_SCENARIO_COMPILER_ID_V1: &str =
    "whoathere.dependency_free_npm_scenario_compiler.v1";
pub const ARTIFACT_SCENARIO_CANONICALIZATION_V1: &str = "rfc8785.jcs.v1";
pub const NPM_LOCAL_TARBALL_COMMAND_TEMPLATE_V1: &str =
    "whoathere.npm_local_tarball_install.fixed_argv.v1";
pub const EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1: &str = "whoathere.empty_dependency_closure.v1";
pub const MAX_ARTIFACT_SCENARIO_BYTES_V1: u64 = 64 * 1024 * 1024;
pub const MAX_ARTIFACT_SCENARIO_IDENTIFIER_BYTES_V1: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactScenarioCompileErrorV1 {
    InvalidEnvelope,
    InvalidManifest,
    InvalidSubject,
    SubjectMismatch,
    UnsupportedArtifactFormat,
    IncompleteNormalization,
    UnsupportedDependencyClosure,
    UnsupportedNativeArtifact,
    UnsupportedLifecycleHook,
    UnsupportedWheelScript,
    InvalidTriggerSurface,
    ArtifactLimitExceeded,
    PolicyMismatch,
    InvalidPolicy,
    InvalidIdentifiers,
    InvalidWire,
    Serialization,
}

impl ArtifactScenarioCompileErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidEnvelope => "artifact_scenario_envelope_invalid",
            Self::InvalidManifest => "artifact_scenario_manifest_invalid",
            Self::InvalidSubject => "artifact_scenario_subject_invalid",
            Self::SubjectMismatch => "artifact_scenario_subject_mismatch",
            Self::UnsupportedArtifactFormat => "artifact_scenario_format_unsupported",
            Self::IncompleteNormalization => "artifact_scenario_normalization_incomplete",
            Self::UnsupportedDependencyClosure => {
                "artifact_scenario_dependency_closure_unsupported"
            }
            Self::UnsupportedNativeArtifact => "artifact_scenario_native_artifact_unsupported",
            Self::UnsupportedLifecycleHook => "artifact_scenario_lifecycle_hook_unqualified",
            Self::UnsupportedWheelScript => "artifact_scenario_wheel_script_unsupported",
            Self::InvalidTriggerSurface => "artifact_scenario_trigger_surface_invalid",
            Self::ArtifactLimitExceeded => "artifact_scenario_artifact_limit_exceeded",
            Self::PolicyMismatch => "artifact_scenario_policy_mismatch",
            Self::InvalidPolicy => "artifact_scenario_policy_invalid",
            Self::InvalidIdentifiers => "artifact_scenario_identifiers_invalid",
            Self::InvalidWire => "artifact_scenario_wire_invalid",
            Self::Serialization => "artifact_scenario_serialization_failed",
        }
    }
}

impl fmt::Display for ArtifactScenarioCompileErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ArtifactScenarioCompileErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmEnvironmentProfileV1 {
    CiFalse,
    CiTrue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NpmLifecycleHookV1 {
    Preinstall,
    Install,
    Postinstall,
    Preprepare,
    Prepare,
    Postprepare,
    Prepack,
    Postpack,
    Prepublish,
    PrepublishOnly,
    Publish,
    Postpublish,
    Preversion,
    Version,
    Postversion,
}

impl NpmLifecycleHookV1 {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "preinstall" => Some(Self::Preinstall),
            "install" => Some(Self::Install),
            "postinstall" => Some(Self::Postinstall),
            "preprepare" => Some(Self::Preprepare),
            "prepare" => Some(Self::Prepare),
            "postprepare" => Some(Self::Postprepare),
            "prepack" => Some(Self::Prepack),
            "postpack" => Some(Self::Postpack),
            "prepublish" => Some(Self::Prepublish),
            "prepublishOnly" => Some(Self::PrepublishOnly),
            "publish" => Some(Self::Publish),
            "postpublish" => Some(Self::Postpublish),
            "preversion" => Some(Self::Preversion),
            "version" => Some(Self::Version),
            "postversion" => Some(Self::Postversion),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactScenarioKindV1 {
    NpmLocalTarballInstall {
        environment: NpmEnvironmentProfileV1,
    },
    NpmMainOrExportProbe,
    NpmBinProbe,
}

impl ArtifactScenarioKindV1 {
    pub fn environment(self) -> Option<NpmEnvironmentProfileV1> {
        match self {
            Self::NpmLocalTarballInstall { environment } => Some(environment),
            Self::NpmMainOrExportProbe | Self::NpmBinProbe => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactNetworkPolicyV1 {
    NoNetworkDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCloneDispositionV1 {
    DestroyClone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTransportV1 {
    DigestCheckedBoundedRawBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactPackagePrivilegeV1 {
    DedicatedUnprivilegedUidGid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactScenarioEvidenceClassV1 {
    ArtifactTransport,
    GuestArtifactRehash,
    ProcessCredentials,
    ProcessLifecycle,
    ListenerInventory,
    SensorHealth,
    NoNetworkDevice,
    VmStop,
    ChannelClosure,
    CloneDestruction,
    BuildClosureIdentity,
    DerivedArtifactDigest,
    DerivedArtifactValidation,
    BuildEnvironmentTeardown,
}

pub(crate) fn required_evidence_classes_v1() -> Vec<ArtifactScenarioEvidenceClassV1> {
    vec![
        ArtifactScenarioEvidenceClassV1::ArtifactTransport,
        ArtifactScenarioEvidenceClassV1::GuestArtifactRehash,
        ArtifactScenarioEvidenceClassV1::ProcessCredentials,
        ArtifactScenarioEvidenceClassV1::ProcessLifecycle,
        ArtifactScenarioEvidenceClassV1::ListenerInventory,
        ArtifactScenarioEvidenceClassV1::SensorHealth,
        ArtifactScenarioEvidenceClassV1::NoNetworkDevice,
        ArtifactScenarioEvidenceClassV1::VmStop,
        ArtifactScenarioEvidenceClassV1::ChannelClosure,
        ArtifactScenarioEvidenceClassV1::CloneDestruction,
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DependencyClosureV1 {
    Empty {
        declaration_set_sha256: Sha256Digest,
    },
}

impl DependencyClosureV1 {
    pub fn declaration_set_sha256(&self) -> &Sha256Digest {
        match self {
            Self::Empty {
                declaration_set_sha256,
            } => declaration_set_sha256,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleHookBindingV1 {
    hook: NpmLifecycleHookV1,
    command_sha256: Sha256Digest,
}

impl LifecycleHookBindingV1 {
    pub(crate) fn new(hook: NpmLifecycleHookV1, command_sha256: Sha256Digest) -> Self {
        Self {
            hook,
            command_sha256,
        }
    }

    pub fn hook(&self) -> NpmLifecycleHookV1 {
        self.hook
    }

    pub fn command_sha256(&self) -> &Sha256Digest {
        &self.command_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactScenarioLimitsV1 {
    pub max_artifact_bytes: u64,
    pub wall_clock_millis: u64,
    pub max_stdout_bytes: u64,
    pub max_stderr_bytes: u64,
    pub max_processes: u32,
    pub max_open_files: u32,
    pub max_observed_file_events: u32,
}

impl ArtifactScenarioLimitsV1 {
    pub fn first_slice_defaults() -> Self {
        Self {
            max_artifact_bytes: MAX_ARTIFACT_SCENARIO_BYTES_V1,
            wall_clock_millis: 120_000,
            max_stdout_bytes: 1024 * 1024,
            max_stderr_bytes: 1024 * 1024,
            max_processes: 256,
            max_open_files: 1024,
            max_observed_file_events: 65_536,
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        if self.max_artifact_bytes == 0
            || self.max_artifact_bytes > MAX_ARTIFACT_SCENARIO_BYTES_V1
            || !(1_000..=900_000).contains(&self.wall_clock_millis)
            || self.max_stdout_bytes == 0
            || self.max_stdout_bytes > 16 * 1024 * 1024
            || self.max_stderr_bytes == 0
            || self.max_stderr_bytes > 16 * 1024 * 1024
            || !(1..=4096).contains(&self.max_processes)
            || !(16..=65_536).contains(&self.max_open_files)
            || self.max_observed_file_events == 0
            || self.max_observed_file_events > 1_000_000
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct NpmRuntimeProfileV1 {
    profile_id: String,
    node_version: String,
    node_executable_sha256: Sha256Digest,
    npm_version: String,
    npm_cli_sha256: Sha256Digest,
    command_template_sha256: Sha256Digest,
    profile_sha256: Sha256Digest,
}

impl fmt::Debug for NpmRuntimeProfileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NpmRuntimeProfileV1")
            .field("profile_id", &self.profile_id)
            .field("node_version", &self.node_version)
            .field("node_executable_sha256", &self.node_executable_sha256)
            .field("npm_version", &self.npm_version)
            .field("npm_cli_sha256", &self.npm_cli_sha256)
            .field("command_template_sha256", &self.command_template_sha256)
            .field("profile_sha256", &self.profile_sha256)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct NpmRuntimeProfileDigestWireV1<'a> {
    schema_version: &'static str,
    profile_id: &'a str,
    target_os: &'static str,
    target_arch: &'static str,
    node_version: &'a str,
    node_executable_sha256: &'a Sha256Digest,
    npm_version: &'a str,
    npm_cli_sha256: &'a Sha256Digest,
    command_template_sha256: &'a Sha256Digest,
}

impl NpmRuntimeProfileV1 {
    pub fn new(
        profile_id: impl Into<String>,
        node_version: impl Into<String>,
        node_executable_sha256: Sha256Digest,
        npm_version: impl Into<String>,
        npm_cli_sha256: Sha256Digest,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let profile_id = profile_id.into();
        let node_version = node_version.into();
        let npm_version = npm_version.into();
        if !valid_identity_component_v1(&profile_id)
            || !valid_version_component_v1(&node_version)
            || !valid_version_component_v1(&npm_version)
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        let command_template_sha256 =
            Sha256Digest::from_bytes(NPM_LOCAL_TARBALL_COMMAND_TEMPLATE_V1.as_bytes());
        let bytes = serde_json_canonicalizer::to_vec(&NpmRuntimeProfileDigestWireV1 {
            schema_version: "whoathere.npm_runtime_profile.v1",
            profile_id: &profile_id,
            target_os: "macos",
            target_arch: "arm64",
            node_version: &node_version,
            node_executable_sha256: &node_executable_sha256,
            npm_version: &npm_version,
            npm_cli_sha256: &npm_cli_sha256,
            command_template_sha256: &command_template_sha256,
        })
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
        Ok(Self {
            profile_id,
            node_version,
            node_executable_sha256,
            npm_version,
            npm_cli_sha256,
            command_template_sha256,
            profile_sha256: Sha256Digest::from_bytes(&bytes),
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn node_version(&self) -> &str {
        &self.node_version
    }

    pub fn node_executable_sha256(&self) -> &Sha256Digest {
        &self.node_executable_sha256
    }

    pub fn npm_version(&self) -> &str {
        &self.npm_version
    }

    pub fn npm_cli_sha256(&self) -> &Sha256Digest {
        &self.npm_cli_sha256
    }

    pub fn command_template_sha256(&self) -> &Sha256Digest {
        &self.command_template_sha256
    }

    pub fn profile_sha256(&self) -> &Sha256Digest {
        &self.profile_sha256
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactScenarioPolicyV1 {
    policy_sha256: Sha256Digest,
    allowed_fixture_sha256: Sha256Digest,
    runtime_profile: NpmRuntimeProfileV1,
    qualified_lifecycle_hooks: BTreeSet<NpmLifecycleHookV1>,
    limits: ArtifactScenarioLimitsV1,
}

impl fmt::Debug for ArtifactScenarioPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactScenarioPolicyV1")
            .field("policy_sha256", &self.policy_sha256)
            .field("allowed_fixture_sha256", &self.allowed_fixture_sha256)
            .field("runtime_profile", &self.runtime_profile)
            .field("qualified_lifecycle_hooks", &self.qualified_lifecycle_hooks)
            .field("limits", &self.limits)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ArtifactScenarioPolicyDigestWireV1<'a> {
    schema_version: &'static str,
    compiler_id: &'static str,
    qualification: &'static str,
    allowed_fixture_sha256: &'a Sha256Digest,
    runtime_profile_sha256: &'a Sha256Digest,
    qualified_lifecycle_hooks: &'a BTreeSet<NpmLifecycleHookV1>,
    limits: &'a ArtifactScenarioLimitsV1,
    network_policy: ArtifactNetworkPolicyV1,
    clone_disposition: ArtifactCloneDispositionV1,
    package_privilege: ArtifactPackagePrivilegeV1,
}

impl ArtifactScenarioPolicyV1 {
    pub fn inert_qualification_only(
        allowed_fixture_sha256: Sha256Digest,
        runtime_profile: NpmRuntimeProfileV1,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let qualified_lifecycle_hooks = BTreeSet::from([
            NpmLifecycleHookV1::Preinstall,
            NpmLifecycleHookV1::Install,
            NpmLifecycleHookV1::Postinstall,
        ]);
        let limits = ArtifactScenarioLimitsV1::first_slice_defaults();
        limits.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(&ArtifactScenarioPolicyDigestWireV1 {
            schema_version: ARTIFACT_SCENARIO_POLICY_SCHEMA_V1,
            compiler_id: ARTIFACT_SCENARIO_COMPILER_ID_V1,
            qualification: "inert_qualification_only",
            allowed_fixture_sha256: &allowed_fixture_sha256,
            runtime_profile_sha256: runtime_profile.profile_sha256(),
            qualified_lifecycle_hooks: &qualified_lifecycle_hooks,
            limits: &limits,
            network_policy: ArtifactNetworkPolicyV1::NoNetworkDevice,
            clone_disposition: ArtifactCloneDispositionV1::DestroyClone,
            package_privilege: ArtifactPackagePrivilegeV1::DedicatedUnprivilegedUidGid,
        })
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
        Ok(Self {
            policy_sha256: Sha256Digest::from_bytes(&bytes),
            allowed_fixture_sha256,
            runtime_profile,
            qualified_lifecycle_hooks,
            limits,
        })
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn allowed_fixture_sha256(&self) -> &Sha256Digest {
        &self.allowed_fixture_sha256
    }

    pub fn runtime_profile(&self) -> &NpmRuntimeProfileV1 {
        &self.runtime_profile
    }

    pub fn qualified_lifecycle_hooks(&self) -> &BTreeSet<NpmLifecycleHookV1> {
        &self.qualified_lifecycle_hooks
    }

    pub fn limits(&self) -> &ArtifactScenarioLimitsV1 {
        &self.limits
    }

    pub(crate) fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        self.limits.validate()?;
        if self.qualified_lifecycle_hooks.is_empty()
            || !self.qualified_lifecycle_hooks.iter().all(|hook| {
                matches!(
                    hook,
                    NpmLifecycleHookV1::Preinstall
                        | NpmLifecycleHookV1::Install
                        | NpmLifecycleHookV1::Postinstall
                )
            })
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactScenarioExecutionIdentityV1 {
    job_id: String,
    run_id: String,
    evidence_id: String,
    scenario_id: String,
}

impl ArtifactScenarioExecutionIdentityV1 {
    pub fn new(
        job_id: impl Into<String>,
        run_id: impl Into<String>,
        evidence_id: impl Into<String>,
        scenario_id: impl Into<String>,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let value = Self {
            job_id: job_id.into(),
            run_id: run_id.into(),
            evidence_id: evidence_id.into(),
            scenario_id: scenario_id.into(),
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        if [
            self.job_id.as_str(),
            self.run_id.as_str(),
            self.evidence_id.as_str(),
            self.scenario_id.as_str(),
        ]
        .into_iter()
        .any(|value| !valid_identity_component_v1(value))
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers);
        }
        Ok(())
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
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactScenarioIdentitySetV1 {
    plan_id: String,
    ci_false: ArtifactScenarioExecutionIdentityV1,
    ci_true: ArtifactScenarioExecutionIdentityV1,
}

impl ArtifactScenarioIdentitySetV1 {
    pub fn new(
        plan_id: impl Into<String>,
        ci_false: ArtifactScenarioExecutionIdentityV1,
        ci_true: ArtifactScenarioExecutionIdentityV1,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let value = Self {
            plan_id: plan_id.into(),
            ci_false,
            ci_true,
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        self.ci_false.validate()?;
        self.ci_true.validate()?;
        if !valid_identity_component_v1(&self.plan_id)
            || self.ci_false == self.ci_true
            || self.ci_false.job_id == self.ci_true.job_id
            || self.ci_false.run_id == self.ci_true.run_id
            || self.ci_false.evidence_id == self.ci_true.evidence_id
            || self.ci_false.scenario_id == self.ci_true.scenario_id
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers);
        }
        Ok(())
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub(crate) fn for_environment(
        &self,
        environment: NpmEnvironmentProfileV1,
    ) -> &ArtifactScenarioExecutionIdentityV1 {
        match environment {
            NpmEnvironmentProfileV1::CiFalse => &self.ci_false,
            NpmEnvironmentProfileV1::CiTrue => &self.ci_true,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactScenarioTemplateV1 {
    pub(crate) identity: ArtifactScenarioExecutionIdentityV1,
    pub(crate) subject: ArtifactEvidenceSubjectV2,
    pub(crate) package: PackageIdentity,
    pub(crate) artifact_byte_length: u64,
    pub(crate) policy_sha256: Sha256Digest,
    pub(crate) runtime_profile: NpmRuntimeProfileV1,
    pub(crate) dependency_closure: DependencyClosureV1,
    pub(crate) scenario_kind: ArtifactScenarioKindV1,
    pub(crate) lifecycle_hooks: Vec<LifecycleHookBindingV1>,
    pub(crate) limits: ArtifactScenarioLimitsV1,
    pub(crate) required_evidence: Vec<ArtifactScenarioEvidenceClassV1>,
    pub(crate) template_sha256: Sha256Digest,
}

impl fmt::Debug for ArtifactScenarioTemplateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactScenarioTemplateV1")
            .field("scenario_id", &self.identity.scenario_id)
            .field("artifact_sha256", &self.subject.artifact_sha256())
            .field("scenario_kind", &self.scenario_kind)
            .field("lifecycle_hooks", &self.lifecycle_hooks)
            .field("template_sha256", &self.template_sha256)
            .finish()
    }
}

impl ArtifactScenarioTemplateV1 {
    pub fn identity(&self) -> &ArtifactScenarioExecutionIdentityV1 {
        &self.identity
    }

    pub fn subject(&self) -> &ArtifactEvidenceSubjectV2 {
        &self.subject
    }

    pub fn package(&self) -> &PackageIdentity {
        &self.package
    }

    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn runtime_profile(&self) -> &NpmRuntimeProfileV1 {
        &self.runtime_profile
    }

    pub fn dependency_closure(&self) -> &DependencyClosureV1 {
        &self.dependency_closure
    }

    pub fn scenario_kind(&self) -> ArtifactScenarioKindV1 {
        self.scenario_kind
    }

    pub fn lifecycle_hooks(&self) -> &[LifecycleHookBindingV1] {
        &self.lifecycle_hooks
    }

    pub fn limits(&self) -> &ArtifactScenarioLimitsV1 {
        &self.limits
    }

    pub fn required_evidence(&self) -> &[ArtifactScenarioEvidenceClassV1] {
        &self.required_evidence
    }

    pub fn template_sha256(&self) -> &Sha256Digest {
        &self.template_sha256
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
        crate::wire::canonical_template_json_v1(self)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ArtifactScenarioPlanV1 {
    pub(crate) plan_id: String,
    pub(crate) subject: ArtifactEvidenceSubjectV2,
    pub(crate) policy_sha256: Sha256Digest,
    pub(crate) templates: Vec<ArtifactScenarioTemplateV1>,
    pub(crate) plan_sha256: Sha256Digest,
}

impl fmt::Debug for ArtifactScenarioPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactScenarioPlanV1")
            .field("plan_id", &self.plan_id)
            .field("artifact_sha256", &self.subject.artifact_sha256())
            .field("policy_sha256", &self.policy_sha256)
            .field("template_count", &self.templates.len())
            .field("plan_sha256", &self.plan_sha256)
            .finish()
    }
}

impl ArtifactScenarioPlanV1 {
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn subject(&self) -> &ArtifactEvidenceSubjectV2 {
        &self.subject
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn templates(&self) -> &[ArtifactScenarioTemplateV1] {
        &self.templates
    }

    pub fn plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
        crate::wire::canonical_plan_json_v1(self)
    }
}

pub(crate) fn valid_identity_component_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ARTIFACT_SCENARIO_IDENTIFIER_BYTES_V1
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
}

pub(crate) fn valid_version_component_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}
