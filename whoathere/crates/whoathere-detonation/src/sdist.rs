use crate::artifact::{
    required_evidence_classes_v1, valid_identity_component_v1, valid_version_component_v1,
    ArtifactCloneDispositionV1, ArtifactNetworkPolicyV1, ArtifactPackagePrivilegeV1,
    ArtifactRuntimeTargetV1, ArtifactScenarioCompileErrorV1, ArtifactScenarioEvidenceClassV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioLimitsV1, ArtifactTransportV1,
    MAX_ARTIFACT_SCENARIO_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::{
    ArtifactEnvelope, ArtifactFormat, ArtifactManifest, Ecosystem, NormalizationCompleteness,
    PackageIdentity, SdistMetadata, Sha256Digest,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const SDIST_SCENARIO_TEMPLATE_SCHEMA_V1: &str = "whoathere.sdist_scenario_template.v1";
pub const SDIST_SCENARIO_PLAN_SCHEMA_V1: &str = "whoathere.sdist_scenario_plan.v1";
pub const SDIST_SCENARIO_POLICY_SCHEMA_V1: &str = "whoathere.sdist_scenario_policy.v1";
pub const SDIST_BUILD_CLOSURE_SCHEMA_V1: &str = "whoathere.sdist_build_closure.v1";
pub const SDIST_SCENARIO_COMPILER_ID_V1: &str = "whoathere.sdist_scenario_compiler.v1";
pub const SDIST_SCENARIO_CANONICALIZATION_V1: &str = "rfc8785.jcs.v1";
pub const SDIST_OFFLINE_BUILD_COMMAND_TEMPLATE_V1: &str =
    "whoathere.python_sdist_offline_build.fixed_runner.v1";
pub const MAX_SDIST_SCENARIO_TEMPLATE_WIRE_BYTES_V1: usize = 384 * 1024;
pub const MAX_SDIST_SCENARIO_PLAN_WIRE_BYTES_V1: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistScenarioClassV1 {
    BuildExactSdist,
    InspectDerivedWheel,
    InstallDerivedWheel,
    ImportRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistBuildModeV1 {
    Pep517,
    LegacySetupPy,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SdistScenarioKindV1 {
    BuildExactSdist {
        build_mode: SdistBuildModeV1,
        build_backend: Option<String>,
        backend_paths: Vec<String>,
        build_requires_sha256: Sha256Digest,
    },
    InspectDerivedWheel,
    InstallDerivedWheel,
    ImportRoot {
        module: String,
    },
}

impl SdistScenarioKindV1 {
    pub fn scenario_class(&self) -> SdistScenarioClassV1 {
        match self {
            Self::BuildExactSdist { .. } => SdistScenarioClassV1::BuildExactSdist,
            Self::InspectDerivedWheel => SdistScenarioClassV1::InspectDerivedWheel,
            Self::InstallDerivedWheel => SdistScenarioClassV1::InstallDerivedWheel,
            Self::ImportRoot { .. } => SdistScenarioClassV1::ImportRoot,
        }
    }

    fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        match self {
            Self::BuildExactSdist {
                build_mode,
                build_backend,
                backend_paths,
                ..
            } => {
                if backend_paths.windows(2).any(|pair| pair[0] >= pair[1])
                    || backend_paths.iter().any(|path| !valid_backend_path(path))
                {
                    return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
                }
                match build_mode {
                    SdistBuildModeV1::Pep517 => {
                        if build_backend
                            .as_deref()
                            .is_none_or(|backend| !valid_backend_target(backend))
                        {
                            return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
                        }
                    }
                    SdistBuildModeV1::LegacySetupPy => {
                        if build_backend.is_some() || !backend_paths.is_empty() {
                            return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
                        }
                    }
                }
                Ok(())
            }
            Self::InspectDerivedWheel | Self::InstallDerivedWheel => Ok(()),
            Self::ImportRoot { module } => validate_python_target(module),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistBuildEnvironmentV1 {
    FreshIsolatedVirtualEnvironment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistResolverPolicyV1 {
    NoIndexFixedClosureOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistDynamicBuildRequirementsPolicyV1 {
    DenyOutsideFixedClosure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistDerivedWheelPolicyV1 {
    RehashValidateFreshScenarioNoHostCopy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistInterpreterPolicyV1 {
    FreshInterpreterPerProbe,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdistBuildClosureArtifactV1 {
    normalized_name: String,
    version: String,
    artifact_filename: String,
    artifact_format: SdistBuildClosureArtifactFormatV1,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistBuildClosureArtifactFormatV1 {
    Wheel,
}

impl SdistBuildClosureArtifactV1 {
    pub fn new(
        normalized_name: impl Into<String>,
        version: impl Into<String>,
        artifact_filename: impl Into<String>,
        artifact_format: SdistBuildClosureArtifactFormatV1,
        artifact_sha256: Sha256Digest,
        artifact_byte_length: u64,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        let value = Self {
            normalized_name: normalized_name.into(),
            version: version.into(),
            artifact_filename: artifact_filename.into(),
            artifact_format,
            artifact_sha256,
            artifact_byte_length,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn normalized_name(&self) -> &str {
        &self.normalized_name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn artifact_filename(&self) -> &str {
        &self.artifact_filename
    }

    pub fn artifact_format(&self) -> SdistBuildClosureArtifactFormatV1 {
        self.artifact_format
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        if normalize_build_name(&self.normalized_name).as_deref()
            != Some(self.normalized_name.as_str())
            || !valid_version_component_v1(&self.version)
            || !valid_closure_wheel_filename(
                &self.normalized_name,
                &self.version,
                &self.artifact_filename,
            )
            || self.artifact_byte_length == 0
            || self.artifact_byte_length > MAX_ARTIFACT_SCENARIO_BYTES_V1
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}

fn valid_closure_wheel_filename(normalized_name: &str, version: &str, filename: &str) -> bool {
    if filename.is_empty()
        || filename.len() > 255
        || !filename.is_ascii()
        || filename.contains('/')
        || filename.contains('\\')
        || !filename.ends_with(".whl")
        || !filename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return false;
    }
    let distribution = normalized_name.replace('-', "_");
    let prefix = format!("{distribution}-{version}-");
    let Some(tags) = filename
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(".whl"))
    else {
        return false;
    };
    let tag_count = tags.split('-').count();
    if tag_count != 3 && tag_count != 4 {
        return false;
    }
    let parts = tags.split('-').collect::<Vec<_>>();
    if tag_count == 4
        && (parts[0].is_empty()
            || !parts[0].as_bytes()[0].is_ascii_digit()
            || !parts[0]
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'))
    {
        return false;
    }
    parts[tag_count - 3..].iter().all(|tag| {
        tag.split('.').all(|component| {
            !component.is_empty()
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        })
    })
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdistBuildClosureV1 {
    schema_version: String,
    declaration_set_sha256: Sha256Digest,
    artifacts: Vec<SdistBuildClosureArtifactV1>,
    closure_sha256: Sha256Digest,
}

impl fmt::Debug for SdistBuildClosureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdistBuildClosureV1")
            .field("declaration_set_sha256", &self.declaration_set_sha256)
            .field("artifact_count", &self.artifacts.len())
            .field("closure_sha256", &self.closure_sha256)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BuildRequirementSetWireV1<'a> {
    schema_version: &'static str,
    build_requires: &'a [String],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct BuildClosureDigestWireV1<'a> {
    schema_version: &'static str,
    declaration_set_sha256: &'a Sha256Digest,
    artifacts: &'a [SdistBuildClosureArtifactV1],
    resolver_policy: SdistResolverPolicyV1,
}

impl SdistBuildClosureV1 {
    pub fn new(
        build_requires: &[String],
        artifacts: Vec<SdistBuildClosureArtifactV1>,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        validate_build_requirements(build_requires)?;
        if artifacts.windows(2).any(|pair| pair[0] >= pair[1])
            || closure_artifact_filenames_are_not_unique(&artifacts)
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        for artifact in &artifacts {
            artifact.validate()?;
        }
        let available_names = artifacts
            .iter()
            .map(|artifact| artifact.normalized_name.as_str())
            .collect::<BTreeSet<_>>();
        for requirement in build_requires {
            let required_name = requirement_name(requirement)?;
            if !available_names.contains(required_name.as_str()) {
                return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
            }
        }
        let declaration_set_sha256 = build_requirement_set_sha256(build_requires)?;
        let digest_bytes = serde_json_canonicalizer::to_vec(&BuildClosureDigestWireV1 {
            schema_version: SDIST_BUILD_CLOSURE_SCHEMA_V1,
            declaration_set_sha256: &declaration_set_sha256,
            artifacts: &artifacts,
            resolver_policy: SdistResolverPolicyV1::NoIndexFixedClosureOnly,
        })
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
        Ok(Self {
            schema_version: SDIST_BUILD_CLOSURE_SCHEMA_V1.to_string(),
            declaration_set_sha256,
            artifacts,
            closure_sha256: Sha256Digest::from_bytes(&digest_bytes),
        })
    }

    pub fn declaration_set_sha256(&self) -> &Sha256Digest {
        &self.declaration_set_sha256
    }

    pub fn artifacts(&self) -> &[SdistBuildClosureArtifactV1] {
        &self.artifacts
    }

    pub fn closure_sha256(&self) -> &Sha256Digest {
        &self.closure_sha256
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
        self.validate()?;
        serde_json_canonicalizer::to_vec(self)
            .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)
    }

    fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        if self.schema_version != SDIST_BUILD_CLOSURE_SCHEMA_V1
            || self.artifacts.windows(2).any(|pair| pair[0] >= pair[1])
            || closure_artifact_filenames_are_not_unique(&self.artifacts)
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        for artifact in &self.artifacts {
            artifact.validate()?;
        }
        let bytes = serde_json_canonicalizer::to_vec(&BuildClosureDigestWireV1 {
            schema_version: SDIST_BUILD_CLOSURE_SCHEMA_V1,
            declaration_set_sha256: &self.declaration_set_sha256,
            artifacts: &self.artifacts,
            resolver_policy: SdistResolverPolicyV1::NoIndexFixedClosureOnly,
        })
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
        if self.closure_sha256 != Sha256Digest::from_bytes(&bytes) {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}

fn closure_artifact_filenames_are_not_unique(artifacts: &[SdistBuildClosureArtifactV1]) -> bool {
    let mut filenames = BTreeSet::new();
    artifacts
        .iter()
        .any(|artifact| !filenames.insert(artifact.artifact_filename.as_str()))
}

#[derive(Clone, PartialEq, Eq)]
pub struct SdistRuntimeProfileV1 {
    profile_id: String,
    runtime_target: ArtifactRuntimeTargetV1,
    python_version: String,
    python_executable_sha256: Sha256Digest,
    pip_version: String,
    pip_cli_sha256: Sha256Digest,
    command_template_sha256: Sha256Digest,
    profile_sha256: Sha256Digest,
}

impl fmt::Debug for SdistRuntimeProfileV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdistRuntimeProfileV1")
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
struct SdistRuntimeProfileDigestWireV1<'a> {
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

impl SdistRuntimeProfileV1 {
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
            Sha256Digest::from_bytes(SDIST_OFFLINE_BUILD_COMMAND_TEMPLATE_V1.as_bytes());
        let bytes = serde_json_canonicalizer::to_vec(&SdistRuntimeProfileDigestWireV1 {
            schema_version: "whoathere.sdist_runtime_profile.v1",
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

    pub const fn runtime_target(&self) -> ArtifactRuntimeTargetV1 {
        self.runtime_target
    }

    pub fn profile_sha256(&self) -> &Sha256Digest {
        &self.profile_sha256
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SdistScenarioPolicyV1 {
    policy_sha256: Sha256Digest,
    allowed_fixture_sha256: Sha256Digest,
    runtime_profile: SdistRuntimeProfileV1,
    build_closure: SdistBuildClosureV1,
    qualified_scenarios: BTreeSet<SdistScenarioClassV1>,
    limits: ArtifactScenarioLimitsV1,
}

impl fmt::Debug for SdistScenarioPolicyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdistScenarioPolicyV1")
            .field("policy_sha256", &self.policy_sha256)
            .field("allowed_fixture_sha256", &self.allowed_fixture_sha256)
            .field("runtime_profile", &self.runtime_profile)
            .field("build_closure", &self.build_closure)
            .field("qualified_scenarios", &self.qualified_scenarios)
            .finish()
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SdistPolicyDigestWireV1<'a> {
    schema_version: &'static str,
    compiler_id: &'static str,
    qualification: &'static str,
    allowed_fixture_sha256: &'a Sha256Digest,
    runtime_profile_sha256: &'a Sha256Digest,
    build_closure_sha256: &'a Sha256Digest,
    qualified_scenarios: &'a BTreeSet<SdistScenarioClassV1>,
    limits: &'a ArtifactScenarioLimitsV1,
    network_policy: ArtifactNetworkPolicyV1,
    clone_disposition: ArtifactCloneDispositionV1,
    package_privilege: ArtifactPackagePrivilegeV1,
}

impl SdistScenarioPolicyV1 {
    pub fn inert_qualification_only(
        allowed_fixture_sha256: Sha256Digest,
        runtime_profile: SdistRuntimeProfileV1,
        build_closure: SdistBuildClosureV1,
    ) -> Result<Self, ArtifactScenarioCompileErrorV1> {
        build_closure.validate()?;
        let qualified_scenarios = BTreeSet::from([
            SdistScenarioClassV1::BuildExactSdist,
            SdistScenarioClassV1::InspectDerivedWheel,
            SdistScenarioClassV1::InstallDerivedWheel,
            SdistScenarioClassV1::ImportRoot,
        ]);
        let limits = ArtifactScenarioLimitsV1::first_slice_defaults();
        limits.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(&SdistPolicyDigestWireV1 {
            schema_version: SDIST_SCENARIO_POLICY_SCHEMA_V1,
            compiler_id: SDIST_SCENARIO_COMPILER_ID_V1,
            qualification: "inert_qualification_only",
            allowed_fixture_sha256: &allowed_fixture_sha256,
            runtime_profile_sha256: runtime_profile.profile_sha256(),
            build_closure_sha256: build_closure.closure_sha256(),
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
            build_closure,
            qualified_scenarios,
            limits,
        })
    }

    fn validate(&self) -> Result<(), ArtifactScenarioCompileErrorV1> {
        self.limits.validate()?;
        self.build_closure.validate()?;
        if self.qualified_scenarios
            != BTreeSet::from([
                SdistScenarioClassV1::BuildExactSdist,
                SdistScenarioClassV1::InspectDerivedWheel,
                SdistScenarioClassV1::InstallDerivedWheel,
                SdistScenarioClassV1::ImportRoot,
            ])
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SdistScenarioIdentitySetV1 {
    plan_id: String,
    identities: BTreeMap<SdistScenarioKindV1, ArtifactScenarioExecutionIdentityV1>,
}

impl SdistScenarioIdentitySetV1 {
    pub fn new(
        plan_id: impl Into<String>,
        identities: BTreeMap<SdistScenarioKindV1, ArtifactScenarioExecutionIdentityV1>,
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
        let mut all = [
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
            BTreeSet::new(),
        ];
        for (kind, identity) in &self.identities {
            kind.validate()?;
            identity.validate()?;
            for (set, value) in all.iter_mut().zip([
                identity.job_id(),
                identity.run_id(),
                identity.evidence_id(),
                identity.scenario_id(),
            ]) {
                if !set.insert(value) {
                    return Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers);
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct SdistScenarioTemplateV1 {
    identity: ArtifactScenarioExecutionIdentityV1,
    subject: ArtifactEvidenceSubjectV2,
    package: PackageIdentity,
    canonical_package_root: String,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    runtime_profile: SdistRuntimeProfileV1,
    build_closure: SdistBuildClosureV1,
    scenario_kind: SdistScenarioKindV1,
    limits: ArtifactScenarioLimitsV1,
    required_evidence: Vec<ArtifactScenarioEvidenceClassV1>,
    template_sha256: Sha256Digest,
}

impl fmt::Debug for SdistScenarioTemplateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SdistScenarioTemplateV1")
            .field("scenario_id", &self.identity.scenario_id())
            .field("scenario_kind", &self.scenario_kind)
            .field("template_sha256", &self.template_sha256)
            .finish()
    }
}

impl SdistScenarioTemplateV1 {
    pub fn identity(&self) -> &ArtifactScenarioExecutionIdentityV1 {
        &self.identity
    }
    pub fn subject(&self) -> &ArtifactEvidenceSubjectV2 {
        &self.subject
    }
    pub fn package(&self) -> &PackageIdentity {
        &self.package
    }
    pub fn canonical_package_root(&self) -> &str {
        &self.canonical_package_root
    }
    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }
    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }
    pub fn build_closure(&self) -> &SdistBuildClosureV1 {
        &self.build_closure
    }
    pub fn scenario_kind(&self) -> &SdistScenarioKindV1 {
        &self.scenario_kind
    }
    pub fn template_sha256(&self) -> &Sha256Digest {
        &self.template_sha256
    }
    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
        canonical_sdist_template_json_v1(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdistScenarioPlanV1 {
    plan_id: String,
    subject: ArtifactEvidenceSubjectV2,
    policy_sha256: Sha256Digest,
    templates: Vec<SdistScenarioTemplateV1>,
    plan_sha256: Sha256Digest,
}

impl SdistScenarioPlanV1 {
    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }
    pub fn subject(&self) -> &ArtifactEvidenceSubjectV2 {
        &self.subject
    }
    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }
    pub fn templates(&self) -> &[SdistScenarioTemplateV1] {
        &self.templates
    }
    pub fn plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
    }
    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
        canonical_sdist_plan_json_v1(self)
    }
}

pub struct SdistScenarioCompilationRequestV1<'a> {
    pub envelope: &'a ArtifactEnvelope,
    pub manifest: &'a ArtifactManifest,
    pub subject: &'a ArtifactEvidenceSubjectV2,
    pub policy: &'a SdistScenarioPolicyV1,
    pub identities: &'a SdistScenarioIdentitySetV1,
}

pub fn expected_sdist_scenario_kinds_v1(
    manifest: &ArtifactManifest,
) -> Result<Vec<SdistScenarioKindV1>, ArtifactScenarioCompileErrorV1> {
    manifest
        .validate()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    if !matches!(
        manifest.magic_detected_format,
        ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip
    ) {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedArtifactFormat);
    }
    validated_sdist_scenario_kinds_v1(
        manifest
            .metadata
            .sdist
            .as_ref()
            .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?,
    )
}

pub fn compile_sdist_scenarios_v1(
    request: SdistScenarioCompilationRequestV1<'_>,
) -> Result<SdistScenarioPlanV1, ArtifactScenarioCompileErrorV1> {
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
    let identity = request
        .manifest
        .identity
        .as_ref()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    if request.subject.artifact_sha256() != request.envelope.original_sha256.as_str()
        || request.subject.artifact_sha256() != request.manifest.artifact_sha256.as_str()
        || request.subject.envelope_sha256() != envelope_sha256.as_str()
        || request.subject.manifest_sha256() != request.manifest.manifest_sha256.as_str()
        || request.envelope.ecosystem != Ecosystem::Pypi
        || identity.ecosystem != Ecosystem::Pypi
        || request.manifest.normalization_completeness != NormalizationCompleteness::Complete
        || request.envelope.original_byte_length == 0
        || request.envelope.original_byte_length > MAX_ARTIFACT_SCENARIO_BYTES_V1
        || request.policy.allowed_fixture_sha256 != request.envelope.original_sha256
    {
        return Err(ArtifactScenarioCompileErrorV1::SubjectMismatch);
    }
    if !matches!(
        request.manifest.magic_detected_format,
        ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip
    ) {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedArtifactFormat);
    }
    if !request.manifest.native_binary_file_ids.is_empty() {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedNativeArtifact);
    }
    let sdist = request
        .manifest
        .metadata
        .sdist
        .as_ref()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    validate_sdist_metadata_contract(sdist)?;
    if !sdist.requires_dist.is_empty() {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
    }
    let expected_declarations = build_requirement_set_sha256(&sdist.build_requires)?;
    if request.policy.build_closure.declaration_set_sha256() != &expected_declarations {
        return Err(ArtifactScenarioCompileErrorV1::PolicyMismatch);
    }
    let available = request
        .policy
        .build_closure
        .artifacts()
        .iter()
        .map(|artifact| artifact.normalized_name())
        .collect::<BTreeSet<_>>();
    for requirement in &sdist.build_requires {
        if !available.contains(requirement_name(requirement)?.as_str()) {
            return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
        }
    }

    let kinds = validated_sdist_scenario_kinds_v1(sdist)?;
    if request.identities.identities.len() != kinds.len()
        || request.identities.identities.keys().ne(kinds.iter())
        || kinds.iter().any(|kind| {
            !request
                .policy
                .qualified_scenarios
                .contains(&kind.scenario_class())
        })
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers);
    }
    let required_evidence = required_sdist_evidence_classes_v1();
    let mut templates = Vec::with_capacity(kinds.len());
    for kind in kinds {
        let mut template = SdistScenarioTemplateV1 {
            identity: request
                .identities
                .identities
                .get(&kind)
                .ok_or(ArtifactScenarioCompileErrorV1::InvalidIdentifiers)?
                .clone(),
            subject: request.subject.clone(),
            package: identity.clone(),
            canonical_package_root: request.manifest.canonical_package_root.clone(),
            artifact_byte_length: request.envelope.original_byte_length,
            policy_sha256: request.policy.policy_sha256.clone(),
            runtime_profile: request.policy.runtime_profile.clone(),
            build_closure: request.policy.build_closure.clone(),
            scenario_kind: kind,
            limits: request.policy.limits.clone(),
            required_evidence: required_evidence.clone(),
            template_sha256: Sha256Digest::from_bytes(&[]),
        };
        template.template_sha256 = Sha256Digest::from_bytes(&template.canonical_json_v1()?);
        templates.push(template);
    }
    let mut plan = SdistScenarioPlanV1 {
        plan_id: request.identities.plan_id.clone(),
        subject: request.subject.clone(),
        policy_sha256: request.policy.policy_sha256.clone(),
        templates,
        plan_sha256: Sha256Digest::from_bytes(&[]),
    };
    plan.plan_sha256 = Sha256Digest::from_bytes(&plan.canonical_json_v1()?);
    Ok(plan)
}

fn validate_sdist_metadata_contract(
    sdist: &SdistMetadata,
) -> Result<(), ArtifactScenarioCompileErrorV1> {
    if sdist.pkg_info_file_id.is_none()
        || (sdist.pyproject_file_id.is_none() && sdist.setup_py_file_id.is_none())
        || sdist
            .package_roots
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || sdist
            .package_roots
            .iter()
            .any(|root| module_from_package_root(root).is_err())
        || sdist
            .backend_paths
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        || sdist
            .backend_paths
            .iter()
            .any(|path| !valid_backend_path(path))
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidManifest);
    }
    if let Some(backend) = &sdist.build_backend {
        if sdist.pyproject_file_id.is_none() || !valid_backend_target(backend) {
            return Err(ArtifactScenarioCompileErrorV1::InvalidManifest);
        }
    } else if sdist.setup_py_file_id.is_none() {
        return Err(ArtifactScenarioCompileErrorV1::InvalidManifest);
    }
    validate_build_requirements(&sdist.build_requires)
}

fn validated_sdist_scenario_kinds_v1(
    sdist: &SdistMetadata,
) -> Result<Vec<SdistScenarioKindV1>, ArtifactScenarioCompileErrorV1> {
    validate_sdist_metadata_contract(sdist)?;
    let build_mode = if sdist.build_backend.is_some() {
        SdistBuildModeV1::Pep517
    } else {
        SdistBuildModeV1::LegacySetupPy
    };
    let mut kinds = vec![
        SdistScenarioKindV1::BuildExactSdist {
            build_mode,
            build_backend: sdist.build_backend.clone(),
            backend_paths: sdist.backend_paths.clone(),
            build_requires_sha256: build_requirement_set_sha256(&sdist.build_requires)?,
        },
        SdistScenarioKindV1::InspectDerivedWheel,
        SdistScenarioKindV1::InstallDerivedWheel,
    ];
    for root in &sdist.package_roots {
        kinds.push(SdistScenarioKindV1::ImportRoot {
            module: module_from_package_root(root)?,
        });
    }
    if kinds.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
    }
    Ok(kinds)
}

fn required_sdist_evidence_classes_v1() -> Vec<ArtifactScenarioEvidenceClassV1> {
    let mut values = required_evidence_classes_v1();
    values.extend([
        ArtifactScenarioEvidenceClassV1::BuildClosureIdentity,
        ArtifactScenarioEvidenceClassV1::DerivedArtifactDigest,
        ArtifactScenarioEvidenceClassV1::DerivedArtifactValidation,
        ArtifactScenarioEvidenceClassV1::BuildEnvironmentTeardown,
    ]);
    values
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
struct SdistRuntimeProfileWireV1 {
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
struct SdistScenarioTemplateWireV1 {
    schema_version: String,
    canonicalization: String,
    compiler_id: String,
    identity: ScenarioIdentityWireV1,
    subject: SubjectWireV1,
    package: PackageIdentity,
    canonical_package_root: String,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    runtime_profile: SdistRuntimeProfileWireV1,
    build_closure: SdistBuildClosureV1,
    scenario_kind: SdistScenarioKindV1,
    build_environment: SdistBuildEnvironmentV1,
    resolver_policy: SdistResolverPolicyV1,
    dynamic_build_requirements_policy: SdistDynamicBuildRequirementsPolicyV1,
    derived_wheel_policy: SdistDerivedWheelPolicyV1,
    interpreter_policy: SdistInterpreterPolicyV1,
    target_os: String,
    target_arch: String,
    transport: ArtifactTransportV1,
    network_policy: ArtifactNetworkPolicyV1,
    package_privilege: ArtifactPackagePrivilegeV1,
    clone_disposition: ArtifactCloneDispositionV1,
    limits: ArtifactScenarioLimitsV1,
    required_evidence: Vec<ArtifactScenarioEvidenceClassV1>,
}

impl SdistScenarioTemplateWireV1 {
    fn from_template(template: &SdistScenarioTemplateV1) -> Self {
        let identity = template.identity();
        let subject = template.subject();
        let runtime = &template.runtime_profile;
        Self {
            schema_version: SDIST_SCENARIO_TEMPLATE_SCHEMA_V1.to_string(),
            canonicalization: SDIST_SCENARIO_CANONICALIZATION_V1.to_string(),
            compiler_id: SDIST_SCENARIO_COMPILER_ID_V1.to_string(),
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
            package: template.package.clone(),
            canonical_package_root: template.canonical_package_root.clone(),
            artifact_byte_length: template.artifact_byte_length,
            policy_sha256: template.policy_sha256.clone(),
            runtime_profile: SdistRuntimeProfileWireV1 {
                profile_id: runtime.profile_id.clone(),
                profile_sha256: runtime.profile_sha256.clone(),
                target_os: runtime.runtime_target().target_os().to_string(),
                target_arch: runtime.runtime_target().target_arch().to_string(),
                python_version: runtime.python_version.clone(),
                python_executable_sha256: runtime.python_executable_sha256.clone(),
                pip_version: runtime.pip_version.clone(),
                pip_cli_sha256: runtime.pip_cli_sha256.clone(),
                command_template_sha256: runtime.command_template_sha256.clone(),
            },
            build_closure: template.build_closure.clone(),
            scenario_kind: template.scenario_kind.clone(),
            build_environment: SdistBuildEnvironmentV1::FreshIsolatedVirtualEnvironment,
            resolver_policy: SdistResolverPolicyV1::NoIndexFixedClosureOnly,
            dynamic_build_requirements_policy:
                SdistDynamicBuildRequirementsPolicyV1::DenyOutsideFixedClosure,
            derived_wheel_policy: SdistDerivedWheelPolicyV1::RehashValidateFreshScenarioNoHostCopy,
            interpreter_policy: SdistInterpreterPolicyV1::FreshInterpreterPerProbe,
            target_os: runtime.runtime_target().target_os().to_string(),
            target_arch: runtime.runtime_target().target_arch().to_string(),
            transport: ArtifactTransportV1::DigestCheckedBoundedRawBytes,
            network_policy: ArtifactNetworkPolicyV1::NoNetworkDevice,
            package_privilege: ArtifactPackagePrivilegeV1::DedicatedUnprivilegedUidGid,
            clone_disposition: ArtifactCloneDispositionV1::DestroyClone,
            limits: template.limits.clone(),
            required_evidence: template.required_evidence.clone(),
        }
    }
}

fn canonical_sdist_template_json_v1(
    template: &SdistScenarioTemplateV1,
) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
    let bytes =
        serde_json_canonicalizer::to_vec(&SdistScenarioTemplateWireV1::from_template(template))
            .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if bytes.len() > MAX_SDIST_SCENARIO_TEMPLATE_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSdistScenarioTemplateWireV1 {
    template_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    scenario_id: String,
    scenario_kind: SdistScenarioKindV1,
    runtime_target: ArtifactRuntimeTargetV1,
    runtime_profile_sha256: Sha256Digest,
    python_version: String,
    python_executable_sha256: Sha256Digest,
    pip_version: String,
    pip_cli_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    build_closure: SdistBuildClosureV1,
}

impl ValidatedSdistScenarioTemplateWireV1 {
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
    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }
    pub fn scenario_kind(&self) -> &SdistScenarioKindV1 {
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
    pub fn build_closure_sha256(&self) -> &Sha256Digest {
        &self.build_closure_sha256
    }
    pub fn build_closure(&self) -> &SdistBuildClosureV1 {
        &self.build_closure
    }
}

pub fn decode_and_validate_sdist_scenario_template_v1(
    bytes: &[u8],
) -> Result<ValidatedSdistScenarioTemplateWireV1, ArtifactScenarioCompileErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_SDIST_SCENARIO_TEMPLATE_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = SdistScenarioTemplateWireV1::deserialize(&mut deserializer)
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    if serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?
        != bytes
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    validate_sdist_template_wire_v1(&wire)?;
    let runtime_target = ArtifactRuntimeTargetV1::from_wire(&wire.target_os, &wire.target_arch)
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidWire)?;
    Ok(ValidatedSdistScenarioTemplateWireV1 {
        template_sha256: Sha256Digest::from_bytes(bytes),
        artifact_sha256: wire.subject.artifact_sha256,
        envelope_sha256: wire.subject.envelope_sha256,
        manifest_sha256: wire.subject.manifest_sha256,
        artifact_byte_length: wire.artifact_byte_length,
        policy_sha256: wire.policy_sha256,
        scenario_id: wire.identity.scenario_id,
        scenario_kind: wire.scenario_kind,
        runtime_target,
        runtime_profile_sha256: wire.runtime_profile.profile_sha256,
        python_version: wire.runtime_profile.python_version,
        python_executable_sha256: wire.runtime_profile.python_executable_sha256,
        pip_version: wire.runtime_profile.pip_version,
        pip_cli_sha256: wire.runtime_profile.pip_cli_sha256,
        build_closure_sha256: wire.build_closure.closure_sha256.clone(),
        build_closure: wire.build_closure,
    })
}

fn validate_sdist_template_wire_v1(
    wire: &SdistScenarioTemplateWireV1,
) -> Result<(), ArtifactScenarioCompileErrorV1> {
    let Some(runtime_target) =
        ArtifactRuntimeTargetV1::from_wire(&wire.target_os, &wire.target_arch)
    else {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    };
    if wire.schema_version != SDIST_SCENARIO_TEMPLATE_SCHEMA_V1
        || wire.canonicalization != SDIST_SCENARIO_CANONICALIZATION_V1
        || wire.compiler_id != SDIST_SCENARIO_COMPILER_ID_V1
        || [
            wire.identity.job_id.as_str(),
            wire.identity.run_id.as_str(),
            wire.identity.evidence_id.as_str(),
            wire.identity.scenario_id.as_str(),
        ]
        .into_iter()
        .any(|value| !valid_identity_component_v1(value))
        || !valid_package_root(&wire.canonical_package_root)
        || wire.artifact_byte_length == 0
        || wire.artifact_byte_length > MAX_ARTIFACT_SCENARIO_BYTES_V1
        || wire.package.ecosystem != Ecosystem::Pypi
        || !valid_package_text(&wire.package.display_name)
        || !valid_package_text(&wire.package.normalized_name)
        || !valid_package_text(&wire.package.version)
        || wire.runtime_profile.target_os != wire.target_os
        || wire.runtime_profile.target_arch != wire.target_arch
        || wire.build_environment != SdistBuildEnvironmentV1::FreshIsolatedVirtualEnvironment
        || wire.resolver_policy != SdistResolverPolicyV1::NoIndexFixedClosureOnly
        || wire.dynamic_build_requirements_policy
            != SdistDynamicBuildRequirementsPolicyV1::DenyOutsideFixedClosure
        || wire.derived_wheel_policy
            != SdistDerivedWheelPolicyV1::RehashValidateFreshScenarioNoHostCopy
        || wire.interpreter_policy != SdistInterpreterPolicyV1::FreshInterpreterPerProbe
        || wire.transport != ArtifactTransportV1::DigestCheckedBoundedRawBytes
        || wire.network_policy != ArtifactNetworkPolicyV1::NoNetworkDevice
        || wire.package_privilege != ArtifactPackagePrivilegeV1::DedicatedUnprivilegedUidGid
        || wire.clone_disposition != ArtifactCloneDispositionV1::DestroyClone
        || wire.required_evidence != required_sdist_evidence_classes_v1()
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
    wire.build_closure
        .validate()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let runtime = SdistRuntimeProfileV1::new_for_target(
        runtime_target,
        &wire.runtime_profile.profile_id,
        &wire.runtime_profile.python_version,
        wire.runtime_profile.python_executable_sha256.clone(),
        &wire.runtime_profile.pip_version,
        wire.runtime_profile.pip_cli_sha256.clone(),
    )
    .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    if runtime.profile_sha256 != wire.runtime_profile.profile_sha256
        || runtime.command_template_sha256 != wire.runtime_profile.command_template_sha256
        || wire.runtime_profile.command_template_sha256
            != Sha256Digest::from_bytes(SDIST_OFFLINE_BUILD_COMMAND_TEMPLATE_V1.as_bytes())
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    if let SdistScenarioKindV1::BuildExactSdist {
        build_requires_sha256,
        ..
    } = &wire.scenario_kind
    {
        if build_requires_sha256 != wire.build_closure.declaration_set_sha256() {
            return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdistTemplateReferenceWireV1 {
    scenario_id: String,
    scenario_kind: SdistScenarioKindV1,
    template_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdistScenarioPlanWireV1 {
    schema_version: String,
    canonicalization: String,
    compiler_id: String,
    plan_id: String,
    subject: SubjectWireV1,
    policy_sha256: Sha256Digest,
    templates: Vec<SdistTemplateReferenceWireV1>,
}

fn canonical_sdist_plan_json_v1(
    plan: &SdistScenarioPlanV1,
) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
    let subject = &plan.subject;
    let wire = SdistScenarioPlanWireV1 {
        schema_version: SDIST_SCENARIO_PLAN_SCHEMA_V1.to_string(),
        canonicalization: SDIST_SCENARIO_CANONICALIZATION_V1.to_string(),
        compiler_id: SDIST_SCENARIO_COMPILER_ID_V1.to_string(),
        plan_id: plan.plan_id.clone(),
        subject: SubjectWireV1 {
            artifact_sha256: Sha256Digest::parse(subject.artifact_sha256().to_string())
                .expect("validated artifact digest"),
            envelope_sha256: Sha256Digest::parse(subject.envelope_sha256().to_string())
                .expect("validated envelope digest"),
            manifest_sha256: Sha256Digest::parse(subject.manifest_sha256().to_string())
                .expect("validated manifest digest"),
            cas_object_key: subject.cas_object_key().to_string(),
        },
        policy_sha256: plan.policy_sha256.clone(),
        templates: plan
            .templates
            .iter()
            .map(|template| SdistTemplateReferenceWireV1 {
                scenario_id: template.identity.scenario_id().to_string(),
                scenario_kind: template.scenario_kind.clone(),
                template_sha256: template.template_sha256.clone(),
            })
            .collect(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if bytes.len() > MAX_SDIST_SCENARIO_PLAN_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedSdistScenarioPlanWireV1 {
    plan_sha256: Sha256Digest,
    plan_id: String,
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    policy_sha256: Sha256Digest,
    templates: Vec<(String, SdistScenarioKindV1, Sha256Digest)>,
}

impl ValidatedSdistScenarioPlanWireV1 {
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

    pub fn templates(&self) -> &[(String, SdistScenarioKindV1, Sha256Digest)] {
        &self.templates
    }
}

pub fn decode_and_validate_sdist_scenario_plan_v1(
    bytes: &[u8],
) -> Result<ValidatedSdistScenarioPlanWireV1, ArtifactScenarioCompileErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_SDIST_SCENARIO_PLAN_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = SdistScenarioPlanWireV1::deserialize(&mut deserializer)
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if canonical != bytes
        || wire.schema_version != SDIST_SCENARIO_PLAN_SCHEMA_V1
        || wire.canonicalization != SDIST_SCENARIO_CANONICALIZATION_V1
        || wire.compiler_id != SDIST_SCENARIO_COMPILER_ID_V1
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
        Some(SdistScenarioKindV1::BuildExactSdist { .. })
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
    Ok(ValidatedSdistScenarioPlanWireV1 {
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

fn build_requirement_set_sha256(
    build_requires: &[String],
) -> Result<Sha256Digest, ArtifactScenarioCompileErrorV1> {
    validate_build_requirements(build_requires)?;
    serde_json_canonicalizer::to_vec(&BuildRequirementSetWireV1 {
        schema_version: "whoathere.sdist_build_requirement_set.v1",
        build_requires,
    })
    .map(|bytes| Sha256Digest::from_bytes(&bytes))
    .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)
}

fn validate_build_requirements(
    build_requires: &[String],
) -> Result<(), ArtifactScenarioCompileErrorV1> {
    if build_requires.windows(2).any(|pair| pair[0] >= pair[1])
        || build_requires.iter().any(|requirement| {
            requirement.is_empty()
                || requirement.len() > 512
                || !requirement.is_ascii()
                || requirement.chars().any(char::is_control)
                || requirement.contains('@')
                || requirement.contains(';')
                || requirement_name(requirement).is_err()
        })
    {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
    }
    Ok(())
}

fn requirement_name(requirement: &str) -> Result<String, ArtifactScenarioCompileErrorV1> {
    let name = requirement
        .split(|character: char| {
            character.is_whitespace()
                || matches!(character, '[' | '<' | '>' | '=' | '!' | '~' | '@' | ';')
        })
        .next()
        .unwrap_or_default();
    normalize_build_name(name).ok_or(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure)
}

fn normalize_build_name(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    let mut output = String::new();
    let mut separator = false;
    for byte in value.bytes() {
        if matches!(byte, b'-' | b'_' | b'.') {
            if !separator && !output.is_empty() {
                output.push('-');
            }
            separator = true;
        } else {
            output.push((byte as char).to_ascii_lowercase());
            separator = false;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    (!output.is_empty()).then_some(output)
}

fn module_from_package_root(root: &str) -> Result<String, ArtifactScenarioCompileErrorV1> {
    if root.is_empty() || root.len() > 512 || !root.is_ascii() || root.contains("..") {
        return Err(ArtifactScenarioCompileErrorV1::InvalidTriggerSurface);
    }
    let logical = root.strip_prefix("src/").unwrap_or(root);
    let module = logical.replace('/', ".");
    validate_python_target(&module)?;
    Ok(module)
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

fn valid_backend_target(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 || !value.is_ascii() {
        return false;
    }
    let (module, object) = value
        .split_once(':')
        .map_or((value, None), |(module, object)| (module, Some(object)));
    valid_dotted_python_name(module) && object.is_none_or(valid_dotted_python_name)
}

fn valid_dotted_python_name(value: &str) -> bool {
    value.split('.').all(|component| {
        !component.is_empty()
            && component
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && component
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    })
}

fn valid_backend_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.is_ascii()
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
}

fn valid_package_root(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && !value.contains('/')
        && value != "."
        && value != ".."
}

fn valid_package_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && value.chars().all(|character| !character.is_control())
}
