use crate::artifact::{
    required_evidence_classes_v1, valid_identity_component_v1, valid_version_component_v1,
    ArtifactCloneDispositionV1, ArtifactNetworkPolicyV1, ArtifactPackagePrivilegeV1,
    ArtifactRuntimeTargetV1, ArtifactScenarioCompileErrorV1, ArtifactScenarioEvidenceClassV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioLimitsV1, ArtifactTransportV1,
    DependencyClosureV1, EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1, MAX_ARTIFACT_SCENARIO_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::{
    ArtifactEnvelope, ArtifactFormat, ArtifactManifest, Ecosystem, NormalizationCompleteness,
    PackageIdentity, Sha256Digest, WheelMetadata,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const WHEEL_SCENARIO_TEMPLATE_SCHEMA_V1: &str = "whoathere.wheel_scenario_template.v1";
pub const WHEEL_SCENARIO_PLAN_SCHEMA_V1: &str = "whoathere.wheel_scenario_plan.v1";
pub const WHEEL_SCENARIO_POLICY_SCHEMA_V1: &str = "whoathere.wheel_scenario_policy.v1";
pub const WHEEL_SCENARIO_COMPILER_ID_V1: &str =
    "whoathere.dependency_free_wheel_scenario_compiler.v1";
pub const WHEEL_SCENARIO_CANONICALIZATION_V1: &str = "rfc8785.jcs.v1";
pub const WHEEL_OFFLINE_PROBE_COMMAND_TEMPLATE_V1: &str =
    "whoathere.python_wheel_offline_probe.fixed_runner.v1";
pub const MAX_WHEEL_SCENARIO_TEMPLATE_WIRE_BYTES_V1: usize = 256 * 1024;
pub const MAX_WHEEL_SCENARIO_PLAN_WIRE_BYTES_V1: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WheelScenarioClassV1 {
    InstallExactWheel,
    FreshInterpreterPth,
    ImportRoot,
    ConsoleEntryPoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WheelConsoleArgumentProfileV1 {
    HelpOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum WheelScenarioKindV1 {
    InstallExactWheel,
    FreshInterpreterPth {
        pth_file_ids: Vec<Sha256Digest>,
    },
    ImportRoot {
        module: String,
    },
    ConsoleEntryPoint {
        command_name: String,
        module: String,
        callable: String,
        target_sha256: Sha256Digest,
        argument_profile: WheelConsoleArgumentProfileV1,
    },
}

impl WheelScenarioKindV1 {
    pub fn scenario_class(&self) -> WheelScenarioClassV1 {
        match self {
            Self::InstallExactWheel => WheelScenarioClassV1::InstallExactWheel,
            Self::FreshInterpreterPth { .. } => WheelScenarioClassV1::FreshInterpreterPth,
            Self::ImportRoot { .. } => WheelScenarioClassV1::ImportRoot,
            Self::ConsoleEntryPoint { .. } => WheelScenarioClassV1::ConsoleEntryPoint,
        }
    }

    fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        match self {
            Self::InstallExactWheel => Ok(()),
            Self::FreshInterpreterPth { pth_file_ids } => {
                if pth_file_ids.is_empty() || pth_file_ids.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
                }
                Ok(())
            }
            Self::ImportRoot { module } => validate_python_target(module),
            Self::ConsoleEntryPoint {
                command_name,
                module,
                callable,
                target_sha256,
                argument_profile: WheelConsoleArgumentProfileV1::HelpOnly,
            } => {
                validate_console_name(command_name)?;
                validate_python_target(module)?;
                validate_python_target(callable)?;
                if target_sha256
                    != &Sha256Digest::from_bytes(format!("{module}:{callable}").as_bytes())
                {
                    return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WheelInstallEnvironmentV1 {
    FreshVirtualEnvironment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WheelResolverPolicyV1 {
    NoIndexNoDependencies,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WheelInterpreterPolicyV1 {
    FreshInterpreterPerProbe,
}

#[derive(Clone, PartialEq, Eq)]
pub struct WheelRuntimeProfileV1 {
    profile_id: String,
    runtime_target: ArtifactRuntimeTargetV1,
    python_version: String,
    python_executable_sha256: Sha256Digest,
    pip_version: String,
    pip_cli_sha256: Sha256Digest,
    command_template_sha256: Sha256Digest,
    profile_sha256: Sha256Digest,
}

impl fmt::Debug for WheelRuntimeProfileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WheelRuntimeProfileV1")
            .field("profile_id", &self.profile_id)
            .field("runtime_target", &self.runtime_target)
            .field("python_version", &self.python_version)
            .field("python_executable_sha256", &self.python_executable_sha256)
            .field("pip_version", &self.pip_version)
            .field("pip_cli_sha256", &self.pip_cli_sha256)
            .field("command_template_sha256", &self.command_template_sha256)
            .field("profile_sha256", &self.profile_sha256)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WheelRuntimeProfileDigestWireV1<'a> {
    schema_version: &'static str,
    profile_id: &'a str,
    target_os: &'static str,
    target_arch: &'static str,
    python_version: &'a str,
    python_executable_sha256: &'a Sha256Digest,
    pip_version: &'a str,
    pip_cli_sha256: &'a Sha256Digest,
    command_template_sha256: &'a Sha256Digest,
}

impl WheelRuntimeProfileV1 {
    pub fn new(
        profile_id: impl Into<String>,
        python_version: impl Into<String>,
        python_executable_sha256: Sha256Digest,
        pip_version: impl Into<String>,
        pip_cli_sha256: Sha256Digest,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        Self::new_for_target(
            ArtifactRuntimeTargetV1::MacosArm64,
            profile_id,
            python_version,
            python_executable_sha256,
            pip_version,
            pip_cli_sha256,
        )
    }

    pub fn new_for_target(
        runtime_target: ArtifactRuntimeTargetV1,
        profile_id: impl Into<String>,
        python_version: impl Into<String>,
        python_executable_sha256: Sha256Digest,
        pip_version: impl Into<String>,
        pip_cli_sha256: Sha256Digest,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let profile_id = profile_id.into();
        let python_version = python_version.into();
        let pip_version = pip_version.into();
        if !valid_identity_component_v1(&profile_id)
            || !valid_version_component_v1(&python_version)
            || !valid_version_component_v1(&pip_version)
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        let command_template_sha256 =
            Sha256Digest::from_bytes(WHEEL_OFFLINE_PROBE_COMMAND_TEMPLATE_V1.as_bytes());
        let bytes = serde_json_canonicalizer::to_vec(&WheelRuntimeProfileDigestWireV1 {
            schema_version: "whoathere.wheel_runtime_profile.v1",
            profile_id: &profile_id,
            target_os: runtime_target.target_os(),
            target_arch: runtime_target.target_arch(),
            python_version: &python_version,
            python_executable_sha256: &python_executable_sha256,
            pip_version: &pip_version,
            pip_cli_sha256: &pip_cli_sha256,
            command_template_sha256: &command_template_sha256,
        })
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
        Ok(Self {
            profile_id,
            runtime_target,
            python_version,
            python_executable_sha256,
            pip_version,
            pip_cli_sha256,
            command_template_sha256,
            profile_sha256: Sha256Digest::from_bytes(&bytes),
        })
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub const fn runtime_target(&self) -> ArtifactRuntimeTargetV1 {
        self.runtime_target
    }

    pub fn python_version(&self) -> &str {
        &self.python_version
    }

    pub fn python_executable_sha256(&self) -> &Sha256Digest {
        &self.python_executable_sha256
    }

    pub fn pip_version(&self) -> &str {
        &self.pip_version
    }

    pub fn pip_cli_sha256(&self) -> &Sha256Digest {
        &self.pip_cli_sha256
    }

    pub fn command_template_sha256(&self) -> &Sha256Digest {
        &self.command_template_sha256
    }

    pub fn profile_sha256(&self) -> &Sha256Digest {
        &self.profile_sha256
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WheelScenarioPolicyV1 {
    policy_sha256: Sha256Digest,
    allowed_fixture_sha256: Sha256Digest,
    runtime_profile: WheelRuntimeProfileV1,
    qualified_scenarios: BTreeSet<WheelScenarioClassV1>,
    limits: ArtifactScenarioLimitsV1,
}

impl fmt::Debug for WheelScenarioPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WheelScenarioPolicyV1")
            .field("policy_sha256", &self.policy_sha256)
            .field("allowed_fixture_sha256", &self.allowed_fixture_sha256)
            .field("runtime_profile", &self.runtime_profile)
            .field("qualified_scenarios", &self.qualified_scenarios)
            .field("limits", &self.limits)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WheelScenarioPolicyDigestWireV1<'a> {
    schema_version: &'static str,
    compiler_id: &'static str,
    qualification: &'static str,
    allowed_fixture_sha256: &'a Sha256Digest,
    runtime_profile_sha256: &'a Sha256Digest,
    qualified_scenarios: &'a BTreeSet<WheelScenarioClassV1>,
    limits: &'a ArtifactScenarioLimitsV1,
    network_policy: ArtifactNetworkPolicyV1,
    clone_disposition: ArtifactCloneDispositionV1,
    package_privilege: ArtifactPackagePrivilegeV1,
}

impl WheelScenarioPolicyV1 {
    pub fn inert_qualification_only(
        allowed_fixture_sha256: Sha256Digest,
        runtime_profile: WheelRuntimeProfileV1,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let qualified_scenarios = BTreeSet::from([
            WheelScenarioClassV1::InstallExactWheel,
            WheelScenarioClassV1::FreshInterpreterPth,
            WheelScenarioClassV1::ImportRoot,
            WheelScenarioClassV1::ConsoleEntryPoint,
        ]);
        let limits = ArtifactScenarioLimitsV1::first_slice_defaults();
        limits.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(&WheelScenarioPolicyDigestWireV1 {
            schema_version: WHEEL_SCENARIO_POLICY_SCHEMA_V1,
            compiler_id: WHEEL_SCENARIO_COMPILER_ID_V1,
            qualification: "inert_qualification_only",
            allowed_fixture_sha256: &allowed_fixture_sha256,
            runtime_profile_sha256: runtime_profile.profile_sha256(),
            qualified_scenarios: &qualified_scenarios,
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
            qualified_scenarios,
            limits,
        })
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn allowed_fixture_sha256(&self) -> &Sha256Digest {
        &self.allowed_fixture_sha256
    }

    pub fn runtime_profile(&self) -> &WheelRuntimeProfileV1 {
        &self.runtime_profile
    }

    pub fn limits(&self) -> &ArtifactScenarioLimitsV1 {
        &self.limits
    }

    fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        self.limits.validate()?;
        let required = BTreeSet::from([
            WheelScenarioClassV1::InstallExactWheel,
            WheelScenarioClassV1::FreshInterpreterPth,
            WheelScenarioClassV1::ImportRoot,
            WheelScenarioClassV1::ConsoleEntryPoint,
        ]);
        if self.qualified_scenarios != required {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WheelScenarioIdentitySetV1 {
    plan_id: String,
    identities: BTreeMap<WheelScenarioKindV1, ArtifactScenarioExecutionIdentityV1>,
}

impl fmt::Debug for WheelScenarioIdentitySetV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WheelScenarioIdentitySetV1")
            .field("plan_id", &self.plan_id)
            .field("scenario_count", &self.identities.len())
            .finish()
    }
}

impl WheelScenarioIdentitySetV1 {
    pub fn new(
        plan_id: impl Into<String>,
        identities: BTreeMap<WheelScenarioKindV1, ArtifactScenarioExecutionIdentityV1>,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let value = Self {
            plan_id: plan_id.into(),
            identities,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        if !valid_identity_component_v1(&self.plan_id) || self.identities.is_empty() {
            return Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers);
        }
        let mut jobs = BTreeSet::new();
        let mut runs = BTreeSet::new();
        let mut evidence = BTreeSet::new();
        let mut scenarios = BTreeSet::new();
        for (kind, identity) in &self.identities {
            kind.validate()?;
            identity.validate()?;
            if !jobs.insert(identity.job_id())
                || !runs.insert(identity.run_id())
                || !evidence.insert(identity.evidence_id())
                || !scenarios.insert(identity.scenario_id())
            {
                return Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers);
            }
        }
        Ok(())
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn scenario_kinds(&self) -> impl Iterator<Item = &WheelScenarioKindV1> {
        self.identities.keys()
    }

    fn identity_for(
        &self,
        kind: &WheelScenarioKindV1,
    ) -> Result<&ArtifactScenarioExecutionIdentityV1, ArtifactScenarioCompileErrorV1> {
        self.identities
            .get(kind)
            .ok_or(ArtifactScenarioCompileErrorV1::InvalidIdentifiers)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WheelScenarioTemplateV1 {
    identity: ArtifactScenarioExecutionIdentityV1,
    subject: ArtifactEvidenceSubjectV2,
    package: PackageIdentity,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    runtime_profile: WheelRuntimeProfileV1,
    dependency_closure: DependencyClosureV1,
    scenario_kind: WheelScenarioKindV1,
    limits: ArtifactScenarioLimitsV1,
    required_evidence: Vec<ArtifactScenarioEvidenceClassV1>,
    template_sha256: Sha256Digest,
}

impl fmt::Debug for WheelScenarioTemplateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WheelScenarioTemplateV1")
            .field("scenario_id", &self.identity.scenario_id())
            .field("artifact_sha256", &self.subject.artifact_sha256())
            .field("scenario_kind", &self.scenario_kind)
            .field("template_sha256", &self.template_sha256)
            .finish()
    }
}

impl WheelScenarioTemplateV1 {
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

    pub fn runtime_profile(&self) -> &WheelRuntimeProfileV1 {
        &self.runtime_profile
    }

    pub fn dependency_closure(&self) -> &DependencyClosureV1 {
        &self.dependency_closure
    }

    pub fn scenario_kind(&self) -> &WheelScenarioKindV1 {
        &self.scenario_kind
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
        canonical_wheel_template_json_v1(self)
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct WheelScenarioPlanV1 {
    plan_id: String,
    subject: ArtifactEvidenceSubjectV2,
    policy_sha256: Sha256Digest,
    templates: Vec<WheelScenarioTemplateV1>,
    plan_sha256: Sha256Digest,
}

impl fmt::Debug for WheelScenarioPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WheelScenarioPlanV1")
            .field("plan_id", &self.plan_id)
            .field("artifact_sha256", &self.subject.artifact_sha256())
            .field("policy_sha256", &self.policy_sha256)
            .field("template_count", &self.templates.len())
            .field("plan_sha256", &self.plan_sha256)
            .finish()
    }
}

impl WheelScenarioPlanV1 {
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn subject(&self) -> &ArtifactEvidenceSubjectV2 {
        &self.subject
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn templates(&self) -> &[WheelScenarioTemplateV1] {
        &self.templates
    }

    pub fn plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
        canonical_wheel_plan_json_v1(self)
    }
}

pub struct WheelScenarioCompilationRequestV1<'a> {
    pub envelope: &'a ArtifactEnvelope,
    pub manifest: &'a ArtifactManifest,
    pub subject: &'a ArtifactEvidenceSubjectV2,
    pub policy: &'a WheelScenarioPolicyV1,
    pub identities: &'a WheelScenarioIdentitySetV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyClosureDigestWireV1<'a> {
    schema_version: &'static str,
    manifest_sha256: &'a Sha256Digest,
    dependency_declarations: [String; 0],
}

pub fn expected_wheel_scenario_kinds_v1(
    manifest: &ArtifactManifest,
) -> Result<Vec<WheelScenarioKindV1>, ArtifactScenarioCompileErrorV1> {
    manifest
        .validate()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    if manifest.magic_detected_format != ArtifactFormat::WheelZip {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedArtifactFormat);
    }
    let wheel = manifest
        .metadata
        .wheel
        .as_ref()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    validated_wheel_scenario_kinds_v1(wheel)
}

pub fn compile_wheel_scenarios_v1(
    request: WheelScenarioCompilationRequestV1<'_>,
) -> Result<WheelScenarioPlanV1, ArtifactScenarioCompileErrorV1> {
    request
        .envelope
        .validate()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidEnvelope)?;
    request
        .manifest
        .validate()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    request
        .subject
        .validate_identity()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidSubject)?;
    request.policy.validate()?;
    request.identities.validate()?;

    let envelope_sha256 = request
        .envelope
        .envelope_sha256()
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if request.subject.artifact_sha256() != request.envelope.original_sha256.as_str()
        || request.subject.artifact_sha256() != request.manifest.artifact_sha256.as_str()
        || request.subject.envelope_sha256() != envelope_sha256.as_str()
        || request.subject.manifest_sha256() != request.manifest.manifest_sha256.as_str()
    {
        return Err(ArtifactScenarioCompileErrorV1::SubjectMismatch);
    }
    if request.envelope.ecosystem != Ecosystem::Pypi
        || request.envelope.magic_detected_format != ArtifactFormat::WheelZip
        || request.manifest.magic_detected_format != ArtifactFormat::WheelZip
    {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedArtifactFormat);
    }
    if request.manifest.normalization_completeness != NormalizationCompleteness::Complete {
        return Err(ArtifactScenarioCompileErrorV1::IncompleteNormalization);
    }
    if request.envelope.original_byte_length > request.policy.limits().max_artifact_bytes {
        return Err(ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded);
    }
    if request.policy.allowed_fixture_sha256() != &request.envelope.original_sha256 {
        return Err(ArtifactScenarioCompileErrorV1::PolicyMismatch);
    }

    let identity = request
        .manifest
        .identity
        .as_ref()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    if identity.ecosystem != Ecosystem::Pypi
        || request
            .envelope
            .package_name
            .as_deref()
            .is_some_and(|name| name != identity.display_name)
        || request
            .envelope
            .package_version
            .as_deref()
            .is_some_and(|version| version != identity.version)
    {
        return Err(ArtifactScenarioCompileErrorV1::SubjectMismatch);
    }
    let wheel = request
        .manifest
        .metadata
        .wheel
        .as_ref()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    validate_wheel_metadata_contract(wheel)?;
    if request.envelope.requires_external_dependency_resolution || !wheel.requires_dist.is_empty() {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
    }
    if !wheel.native_tags.is_empty() || !request.manifest.native_binary_file_ids.is_empty() {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedNativeArtifact);
    }
    if !wheel.script_file_ids.is_empty() {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedWheelScript);
    }

    let kinds = validated_wheel_scenario_kinds_v1(wheel)?;
    if request.identities.identities.len() != kinds.len()
        || request.identities.identities.keys().ne(kinds.iter())
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers);
    }
    if kinds.iter().any(|kind| {
        !request
            .policy
            .qualified_scenarios
            .contains(&kind.scenario_class())
    }) {
        return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
    }

    let closure_bytes = serde_json_canonicalizer::to_vec(&EmptyClosureDigestWireV1 {
        schema_version: EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1,
        manifest_sha256: &request.manifest.manifest_sha256,
        dependency_declarations: [],
    })
    .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    let dependency_closure = DependencyClosureV1::Empty {
        declaration_set_sha256: Sha256Digest::from_bytes(&closure_bytes),
    };

    let mut templates = Vec::with_capacity(kinds.len());
    for kind in kinds {
        let mut template = WheelScenarioTemplateV1 {
            identity: request.identities.identity_for(&kind)?.clone(),
            subject: request.subject.clone(),
            package: identity.clone(),
            artifact_byte_length: request.envelope.original_byte_length,
            policy_sha256: request.policy.policy_sha256().clone(),
            runtime_profile: request.policy.runtime_profile().clone(),
            dependency_closure: dependency_closure.clone(),
            scenario_kind: kind,
            limits: request.policy.limits().clone(),
            required_evidence: required_evidence_classes_v1(),
            template_sha256: Sha256Digest::from_bytes(&[]),
        };
        let canonical = template.canonical_json_v1()?;
        template.template_sha256 = Sha256Digest::from_bytes(&canonical);
        templates.push(template);
    }

    let mut plan = WheelScenarioPlanV1 {
        plan_id: request.identities.plan_id().to_string(),
        subject: request.subject.clone(),
        policy_sha256: request.policy.policy_sha256().clone(),
        templates,
        plan_sha256: Sha256Digest::from_bytes(&[]),
    };
    let canonical = plan.canonical_json_v1()?;
    plan.plan_sha256 = Sha256Digest::from_bytes(&canonical);
    Ok(plan)
}

fn validate_wheel_metadata_contract(
    wheel: &WheelMetadata,
) -> Result<(), ArtifactScenarioCompileErrorV1> {
    let Some(dist_info_directory) = wheel.dist_info_directory.as_deref() else {
        return Err(ArtifactScenarioCompileErrorV1::InvalidManifest);
    };
    let expected_native_tags = wheel
        .tags
        .iter()
        .filter(|tag| !tag.ends_with("-none-any"))
        .cloned()
        .collect::<Vec<_>>();
    let expected_console_entry_points = wheel
        .entry_points
        .get("console_scripts")
        .cloned()
        .unwrap_or_default();
    if dist_info_directory.is_empty()
        || !dist_info_directory.ends_with(".dist-info")
        || dist_info_directory.contains('/')
        || wheel.metadata_file_id.is_none()
        || wheel.wheel_file_id.is_none()
        || wheel.record_file_id.is_none()
        || wheel.wheel_version.as_deref() != Some("1.0")
        || wheel.root_is_purelib.is_none()
        || wheel.tags.is_empty()
        || wheel.native_tags != expected_native_tags
        || wheel.console_entry_points != expected_console_entry_points
        || (!wheel.console_entry_points.is_empty() && wheel.entry_points_file_id.is_none())
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidManifest);
    }
    Ok(())
}

fn validated_wheel_scenario_kinds_v1(
    wheel: &WheelMetadata,
) -> Result<Vec<WheelScenarioKindV1>, ArtifactScenarioCompileErrorV1> {
    validate_wheel_metadata_contract(wheel)?;
    let mut kinds = vec![WheelScenarioKindV1::InstallExactWheel];
    if !wheel.pth_file_ids.is_empty() {
        kinds.push(WheelScenarioKindV1::FreshInterpreterPth {
            pth_file_ids: wheel.pth_file_ids.clone(),
        });
    }
    for module in &wheel.import_roots {
        validate_python_target(module)?;
        kinds.push(WheelScenarioKindV1::ImportRoot {
            module: module.clone(),
        });
    }
    for (command_name, target) in &wheel.console_entry_points {
        validate_console_name(command_name)?;
        let (module, callable) = parse_console_target(target)?;
        kinds.push(WheelScenarioKindV1::ConsoleEntryPoint {
            command_name: command_name.clone(),
            module,
            callable,
            target_sha256: Sha256Digest::from_bytes(target.as_bytes()),
            argument_profile: WheelConsoleArgumentProfileV1::HelpOnly,
        });
    }
    if kinds.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
    }
    Ok(kinds)
}

fn parse_console_target(target: &str) -> Result<(String, String), ArtifactScenarioCompileErrorV1> {
    if target.contains('[') || target.contains(']') || target.chars().any(char::is_whitespace) {
        return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
    }
    let mut parts = target.split(':');
    let module = parts.next().unwrap_or_default();
    let callable = parts.next().unwrap_or_default();
    if parts.next().is_some() {
        return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
    }
    validate_python_target(module)?;
    validate_python_target(callable)?;
    Ok((module.to_string(), callable.to_string()))
}

fn validate_python_target(value: &str) -> Result<(), ArtifactScenarioCompileErrorV1> {
    if value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || value.split('.').any(|component| {
            component.is_empty()
                || !component
                    .bytes()
                    .next()
                    .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
                || !component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
    }
    Ok(())
}

fn validate_console_name(value: &str) -> Result<(), ArtifactScenarioCompileErrorV1> {
    if value.is_empty()
        || value.len() > 128
        || value.starts_with('-')
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
    }
    Ok(())
}

fn valid_package_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && value.chars().all(|character| !character.is_control())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioIdentityWireV1 {
    job_id: String,
    run_id: String,
    evidence_id: String,
    scenario_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectWireV1 {
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    cas_object_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WheelRuntimeProfileWireV1 {
    profile_id: String,
    profile_sha256: Sha256Digest,
    target_os: String,
    target_arch: String,
    python_version: String,
    python_executable_sha256: Sha256Digest,
    pip_version: String,
    pip_cli_sha256: Sha256Digest,
    command_template_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WheelScenarioTemplateWireV1 {
    schema_version: String,
    canonicalization: String,
    compiler_id: String,
    identity: ScenarioIdentityWireV1,
    subject: SubjectWireV1,
    package: PackageIdentity,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    runtime_profile: WheelRuntimeProfileWireV1,
    dependency_closure: DependencyClosureV1,
    scenario_kind: WheelScenarioKindV1,
    install_environment: WheelInstallEnvironmentV1,
    resolver_policy: WheelResolverPolicyV1,
    interpreter_policy: WheelInterpreterPolicyV1,
    target_os: String,
    target_arch: String,
    transport: ArtifactTransportV1,
    network_policy: ArtifactNetworkPolicyV1,
    package_privilege: ArtifactPackagePrivilegeV1,
    clone_disposition: ArtifactCloneDispositionV1,
    limits: ArtifactScenarioLimitsV1,
    required_evidence: Vec<ArtifactScenarioEvidenceClassV1>,
}

impl WheelScenarioTemplateWireV1 {
    fn from_template(template: &WheelScenarioTemplateV1) -> Self {
        let identity = template.identity();
        let subject = template.subject();
        let runtime = template.runtime_profile();
        Self {
            schema_version: WHEEL_SCENARIO_TEMPLATE_SCHEMA_V1.to_string(),
            canonicalization: WHEEL_SCENARIO_CANONICALIZATION_V1.to_string(),
            compiler_id: WHEEL_SCENARIO_COMPILER_ID_V1.to_string(),
            identity: ScenarioIdentityWireV1 {
                job_id: identity.job_id().to_string(),
                run_id: identity.run_id().to_string(),
                evidence_id: identity.evidence_id().to_string(),
                scenario_id: identity.scenario_id().to_string(),
            },
            subject: SubjectWireV1 {
                artifact_sha256: Sha256Digest::parse(subject.artifact_sha256().to_string())
                    .expect("validated artifact digest"),
                envelope_sha256: Sha256Digest::parse(subject.envelope_sha256().to_string())
                    .expect("validated envelope digest"),
                manifest_sha256: Sha256Digest::parse(subject.manifest_sha256().to_string())
                    .expect("validated manifest digest"),
                cas_object_key: subject.cas_object_key().to_string(),
            },
            package: template.package().clone(),
            artifact_byte_length: template.artifact_byte_length(),
            policy_sha256: template.policy_sha256().clone(),
            runtime_profile: WheelRuntimeProfileWireV1 {
                profile_id: runtime.profile_id().to_string(),
                profile_sha256: runtime.profile_sha256().clone(),
                target_os: runtime.runtime_target().target_os().to_string(),
                target_arch: runtime.runtime_target().target_arch().to_string(),
                python_version: runtime.python_version().to_string(),
                python_executable_sha256: runtime.python_executable_sha256().clone(),
                pip_version: runtime.pip_version().to_string(),
                pip_cli_sha256: runtime.pip_cli_sha256().clone(),
                command_template_sha256: runtime.command_template_sha256().clone(),
            },
            dependency_closure: template.dependency_closure().clone(),
            scenario_kind: template.scenario_kind().clone(),
            install_environment: WheelInstallEnvironmentV1::FreshVirtualEnvironment,
            resolver_policy: WheelResolverPolicyV1::NoIndexNoDependencies,
            interpreter_policy: WheelInterpreterPolicyV1::FreshInterpreterPerProbe,
            target_os: runtime.runtime_target().target_os().to_string(),
            target_arch: runtime.runtime_target().target_arch().to_string(),
            transport: ArtifactTransportV1::DigestCheckedBoundedRawBytes,
            network_policy: ArtifactNetworkPolicyV1::NoNetworkDevice,
            package_privilege: ArtifactPackagePrivilegeV1::DedicatedUnprivilegedUidGid,
            clone_disposition: ArtifactCloneDispositionV1::DestroyClone,
            limits: template.limits().clone(),
            required_evidence: template.required_evidence().to_vec(),
        }
    }
}

fn canonical_wheel_template_json_v1(
    template: &WheelScenarioTemplateV1,
) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
    let bytes =
        serde_json_canonicalizer::to_vec(&WheelScenarioTemplateWireV1::from_template(template))
            .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if bytes.len() > MAX_WHEEL_SCENARIO_TEMPLATE_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedWheelScenarioTemplateWireV1 {
    template_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    scenario_id: String,
    scenario_kind: WheelScenarioKindV1,
    runtime_target: ArtifactRuntimeTargetV1,
    runtime_profile_sha256: Sha256Digest,
    python_version: String,
    python_executable_sha256: Sha256Digest,
    pip_version: String,
    pip_cli_sha256: Sha256Digest,
    limits: ArtifactScenarioLimitsV1,
}

impl fmt::Debug for ValidatedWheelScenarioTemplateWireV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedWheelScenarioTemplateWireV1")
            .field("template_sha256", &self.template_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("envelope_sha256", &self.envelope_sha256)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("artifact_byte_length", &self.artifact_byte_length)
            .field("policy_sha256", &self.policy_sha256)
            .field("dependency_closure_sha256", &self.dependency_closure_sha256)
            .field("scenario_id", &self.scenario_id)
            .field("scenario_kind", &self.scenario_kind)
            .field("runtime_target", &self.runtime_target)
            .field("runtime_profile_sha256", &self.runtime_profile_sha256)
            .field("python_version", &self.python_version)
            .field("python_executable_sha256", &self.python_executable_sha256)
            .field("pip_version", &self.pip_version)
            .field("pip_cli_sha256", &self.pip_cli_sha256)
            .finish()
    }
}

impl ValidatedWheelScenarioTemplateWireV1 {
    pub fn template_sha256(&self) -> &Sha256Digest {
        &self.template_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn envelope_sha256(&self) -> &Sha256Digest {
        &self.envelope_sha256
    }

    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn dependency_closure_sha256(&self) -> &Sha256Digest {
        &self.dependency_closure_sha256
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn scenario_kind(&self) -> &WheelScenarioKindV1 {
        &self.scenario_kind
    }

    pub const fn runtime_target(&self) -> ArtifactRuntimeTargetV1 {
        self.runtime_target
    }

    pub fn runtime_profile_sha256(&self) -> &Sha256Digest {
        &self.runtime_profile_sha256
    }

    pub fn python_version(&self) -> &str {
        &self.python_version
    }

    pub fn python_executable_sha256(&self) -> &Sha256Digest {
        &self.python_executable_sha256
    }

    pub fn pip_version(&self) -> &str {
        &self.pip_version
    }

    pub fn pip_cli_sha256(&self) -> &Sha256Digest {
        &self.pip_cli_sha256
    }

    pub fn limits(&self) -> &ArtifactScenarioLimitsV1 {
        &self.limits
    }
}

pub fn decode_and_validate_wheel_scenario_template_v1(
    bytes: &[u8],
) -> Result<ValidatedWheelScenarioTemplateWireV1, ArtifactScenarioCompileErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_WHEEL_SCENARIO_TEMPLATE_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = WheelScenarioTemplateWireV1::deserialize(&mut deserializer)
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    validate_wheel_template_wire_v1(&wire)?;
    let runtime_target = ArtifactRuntimeTargetV1::from_wire(&wire.target_os, &wire.target_arch)
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidWire)?;
    Ok(ValidatedWheelScenarioTemplateWireV1 {
        template_sha256: Sha256Digest::from_bytes(bytes),
        artifact_sha256: wire.subject.artifact_sha256,
        envelope_sha256: wire.subject.envelope_sha256,
        manifest_sha256: wire.subject.manifest_sha256,
        artifact_byte_length: wire.artifact_byte_length,
        policy_sha256: wire.policy_sha256,
        dependency_closure_sha256: wire.dependency_closure.declaration_set_sha256().clone(),
        scenario_id: wire.identity.scenario_id,
        scenario_kind: wire.scenario_kind,
        runtime_target,
        runtime_profile_sha256: wire.runtime_profile.profile_sha256,
        python_version: wire.runtime_profile.python_version,
        python_executable_sha256: wire.runtime_profile.python_executable_sha256,
        pip_version: wire.runtime_profile.pip_version,
        pip_cli_sha256: wire.runtime_profile.pip_cli_sha256,
        limits: wire.limits,
    })
}

fn validate_wheel_template_wire_v1(
    wire: &WheelScenarioTemplateWireV1,
) -> Result<(), ArtifactScenarioCompileErrorV1> {
    let Some(runtime_target) =
        ArtifactRuntimeTargetV1::from_wire(&wire.target_os, &wire.target_arch)
    else {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    };
    if wire.schema_version != WHEEL_SCENARIO_TEMPLATE_SCHEMA_V1
        || wire.canonicalization != WHEEL_SCENARIO_CANONICALIZATION_V1
        || wire.compiler_id != WHEEL_SCENARIO_COMPILER_ID_V1
        || [
            wire.identity.job_id.as_str(),
            wire.identity.run_id.as_str(),
            wire.identity.evidence_id.as_str(),
            wire.identity.scenario_id.as_str(),
        ]
        .into_iter()
        .any(|value| !valid_identity_component_v1(value))
        || wire.artifact_byte_length == 0
        || wire.artifact_byte_length > MAX_ARTIFACT_SCENARIO_BYTES_V1
        || wire.package.ecosystem != Ecosystem::Pypi
        || !valid_package_text(&wire.package.display_name)
        || !valid_package_text(&wire.package.normalized_name)
        || !valid_package_text(&wire.package.version)
        || wire.runtime_profile.target_os != wire.target_os
        || wire.runtime_profile.target_arch != wire.target_arch
        || wire.install_environment != WheelInstallEnvironmentV1::FreshVirtualEnvironment
        || wire.resolver_policy != WheelResolverPolicyV1::NoIndexNoDependencies
        || wire.interpreter_policy != WheelInterpreterPolicyV1::FreshInterpreterPerProbe
        || wire.transport != ArtifactTransportV1::DigestCheckedBoundedRawBytes
        || wire.network_policy != ArtifactNetworkPolicyV1::NoNetworkDevice
        || wire.package_privilege != ArtifactPackagePrivilegeV1::DedicatedUnprivilegedUidGid
        || wire.clone_disposition != ArtifactCloneDispositionV1::DestroyClone
        || wire.required_evidence != required_evidence_classes_v1()
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    ArtifactEvidenceSubjectV2::new(
        wire.subject.artifact_sha256.as_str(),
        wire.subject.envelope_sha256.as_str(),
        wire.subject.manifest_sha256.as_str(),
        &wire.subject.cas_object_key,
    )
    .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    wire.limits
        .validate()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    wire.scenario_kind
        .validate()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;

    let runtime = WheelRuntimeProfileV1::new_for_target(
        runtime_target,
        &wire.runtime_profile.profile_id,
        &wire.runtime_profile.python_version,
        wire.runtime_profile.python_executable_sha256.clone(),
        &wire.runtime_profile.pip_version,
        wire.runtime_profile.pip_cli_sha256.clone(),
    )
    .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    if runtime.profile_sha256() != &wire.runtime_profile.profile_sha256
        || runtime.command_template_sha256() != &wire.runtime_profile.command_template_sha256
        || wire.runtime_profile.command_template_sha256
            != Sha256Digest::from_bytes(WHEEL_OFFLINE_PROBE_COMMAND_TEMPLATE_V1.as_bytes())
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let expected_closure = expected_empty_closure_sha256_v1(&wire.subject.manifest_sha256)?;
    if wire.dependency_closure.declaration_set_sha256() != &expected_closure {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    Ok(())
}

fn expected_empty_closure_sha256_v1(
    manifest_sha256: &Sha256Digest,
) -> Result<Sha256Digest, ArtifactScenarioCompileErrorV1> {
    serde_json_canonicalizer::to_vec(&EmptyClosureDigestWireV1 {
        schema_version: EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1,
        manifest_sha256,
        dependency_declarations: [],
    })
    .map(|bytes| Sha256Digest::from_bytes(&bytes))
    .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WheelTemplateReferenceWireV1 {
    scenario_id: String,
    scenario_kind: WheelScenarioKindV1,
    template_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WheelScenarioPlanWireV1 {
    schema_version: String,
    canonicalization: String,
    compiler_id: String,
    plan_id: String,
    subject: SubjectWireV1,
    policy_sha256: Sha256Digest,
    templates: Vec<WheelTemplateReferenceWireV1>,
}

fn canonical_wheel_plan_json_v1(
    plan: &WheelScenarioPlanV1,
) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
    let subject = plan.subject();
    let wire = WheelScenarioPlanWireV1 {
        schema_version: WHEEL_SCENARIO_PLAN_SCHEMA_V1.to_string(),
        canonicalization: WHEEL_SCENARIO_CANONICALIZATION_V1.to_string(),
        compiler_id: WHEEL_SCENARIO_COMPILER_ID_V1.to_string(),
        plan_id: plan.plan_id().to_string(),
        subject: SubjectWireV1 {
            artifact_sha256: Sha256Digest::parse(subject.artifact_sha256().to_string())
                .expect("validated artifact digest"),
            envelope_sha256: Sha256Digest::parse(subject.envelope_sha256().to_string())
                .expect("validated envelope digest"),
            manifest_sha256: Sha256Digest::parse(subject.manifest_sha256().to_string())
                .expect("validated manifest digest"),
            cas_object_key: subject.cas_object_key().to_string(),
        },
        policy_sha256: plan.policy_sha256().clone(),
        templates: plan
            .templates()
            .iter()
            .map(|template| WheelTemplateReferenceWireV1 {
                scenario_id: template.identity().scenario_id().to_string(),
                scenario_kind: template.scenario_kind().clone(),
                template_sha256: template.template_sha256().clone(),
            })
            .collect(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if bytes.len() > MAX_WHEEL_SCENARIO_PLAN_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedWheelScenarioPlanWireV1 {
    plan_sha256: Sha256Digest,
    plan_id: String,
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    policy_sha256: Sha256Digest,
    templates: Vec<(String, WheelScenarioKindV1, Sha256Digest)>,
}

impl ValidatedWheelScenarioPlanWireV1 {
    pub fn plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
    }

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn envelope_sha256(&self) -> &Sha256Digest {
        &self.envelope_sha256
    }

    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    pub fn templates(&self) -> &[(String, WheelScenarioKindV1, Sha256Digest)] {
        &self.templates
    }
}

pub fn decode_and_validate_wheel_scenario_plan_v1(
    bytes: &[u8],
) -> Result<ValidatedWheelScenarioPlanWireV1, ArtifactScenarioCompileErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_WHEEL_SCENARIO_PLAN_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = WheelScenarioPlanWireV1::deserialize(&mut deserializer)
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if canonical != bytes
        || wire.schema_version != WHEEL_SCENARIO_PLAN_SCHEMA_V1
        || wire.canonicalization != WHEEL_SCENARIO_CANONICALIZATION_V1
        || wire.compiler_id != WHEEL_SCENARIO_COMPILER_ID_V1
        || !valid_identity_component_v1(&wire.plan_id)
        || wire.templates.is_empty()
        || wire.templates.len() > 4096
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    ArtifactEvidenceSubjectV2::new(
        wire.subject.artifact_sha256.as_str(),
        wire.subject.envelope_sha256.as_str(),
        wire.subject.manifest_sha256.as_str(),
        &wire.subject.cas_object_key,
    )
    .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    if !matches!(
        wire.templates
            .first()
            .map(|reference| &reference.scenario_kind),
        Some(WheelScenarioKindV1::InstallExactWheel)
    ) {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let mut scenario_ids = BTreeSet::new();
    let mut template_digests = BTreeSet::new();
    for reference in &wire.templates {
        reference
            .scenario_kind
            .validate()
            .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
        if !valid_identity_component_v1(&reference.scenario_id)
            || !scenario_ids.insert(reference.scenario_id.as_str())
            || !template_digests.insert(&reference.template_sha256)
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
        }
    }
    if wire
        .templates
        .windows(2)
        .any(|pair| pair[0].scenario_kind >= pair[1].scenario_kind)
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    Ok(ValidatedWheelScenarioPlanWireV1 {
        plan_sha256: Sha256Digest::from_bytes(bytes),
        plan_id: wire.plan_id,
        artifact_sha256: wire.subject.artifact_sha256,
        envelope_sha256: wire.subject.envelope_sha256,
        manifest_sha256: wire.subject.manifest_sha256,
        policy_sha256: wire.policy_sha256,
        templates: wire
            .templates
            .into_iter()
            .map(|reference| {
                (
                    reference.scenario_id,
                    reference.scenario_kind,
                    reference.template_sha256,
                )
            })
            .collect(),
    })
}
