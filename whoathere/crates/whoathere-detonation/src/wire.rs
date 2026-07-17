use crate::artifact::{
    required_evidence_classes_v1, valid_identity_component_v1, ArtifactCloneDispositionV1,
    ArtifactNetworkPolicyV1, ArtifactPackagePrivilegeV1, ArtifactRuntimeTargetV1,
    ArtifactScenarioCompileErrorV1, ArtifactScenarioEvidenceClassV1, ArtifactScenarioKindV1,
    ArtifactScenarioLimitsV1, ArtifactScenarioPlanV1, ArtifactScenarioTemplateV1,
    ArtifactTransportV1, DependencyClosureV1, LifecycleHookBindingV1, NpmEnvironmentProfileV1,
    NpmLifecycleHookV1, NpmRuntimeProfileV1, ARTIFACT_SCENARIO_CANONICALIZATION_V1,
    ARTIFACT_SCENARIO_COMPILER_ID_V1, ARTIFACT_SCENARIO_PLAN_SCHEMA_V1,
    ARTIFACT_SCENARIO_TEMPLATE_SCHEMA_V1, EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1,
    MAX_ARTIFACT_SCENARIO_BYTES_V1, NPM_LOCAL_TARBALL_COMMAND_TEMPLATE_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use whoathere_artifact::{Ecosystem, PackageIdentity, Sha256Digest};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const MAX_ARTIFACT_SCENARIO_TEMPLATE_WIRE_BYTES_V1: usize = 256 * 1024;
pub const MAX_ARTIFACT_SCENARIO_PLAN_WIRE_BYTES_V1: usize = 32 * 1024;

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
struct RuntimeProfileWireV1 {
    profile_id: String,
    profile_sha256: Sha256Digest,
    target_os: String,
    target_arch: String,
    node_version: String,
    node_executable_sha256: Sha256Digest,
    npm_version: String,
    npm_cli_sha256: Sha256Digest,
    command_template_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactScenarioTemplateWireV1 {
    schema_version: String,
    canonicalization: String,
    compiler_id: String,
    identity: ScenarioIdentityWireV1,
    subject: SubjectWireV1,
    package: PackageIdentity,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    runtime_profile: RuntimeProfileWireV1,
    dependency_closure: DependencyClosureV1,
    scenario_kind: ArtifactScenarioKindV1,
    lifecycle_hooks: Vec<LifecycleHookBindingV1>,
    target_os: String,
    target_arch: String,
    transport: ArtifactTransportV1,
    network_policy: ArtifactNetworkPolicyV1,
    package_privilege: ArtifactPackagePrivilegeV1,
    clone_disposition: ArtifactCloneDispositionV1,
    limits: ArtifactScenarioLimitsV1,
    required_evidence: Vec<ArtifactScenarioEvidenceClassV1>,
}

impl ArtifactScenarioTemplateWireV1 {
    fn from_template(template: &ArtifactScenarioTemplateV1) -> Self {
        let identity = template.identity();
        let subject = template.subject();
        let runtime = template.runtime_profile();
        Self {
            schema_version: ARTIFACT_SCENARIO_TEMPLATE_SCHEMA_V1.to_string(),
            canonicalization: ARTIFACT_SCENARIO_CANONICALIZATION_V1.to_string(),
            compiler_id: ARTIFACT_SCENARIO_COMPILER_ID_V1.to_string(),
            identity: ScenarioIdentityWireV1 {
                job_id: identity.job_id().to_string(),
                run_id: identity.run_id().to_string(),
                evidence_id: identity.evidence_id().to_string(),
                scenario_id: identity.scenario_id().to_string(),
            },
            subject: SubjectWireV1 {
                artifact_sha256: Sha256Digest::parse(subject.artifact_sha256().to_string())
                    .expect("validated evidence subject artifact digest"),
                envelope_sha256: Sha256Digest::parse(subject.envelope_sha256().to_string())
                    .expect("validated evidence subject envelope digest"),
                manifest_sha256: Sha256Digest::parse(subject.manifest_sha256().to_string())
                    .expect("validated evidence subject manifest digest"),
                cas_object_key: subject.cas_object_key().to_string(),
            },
            package: template.package().clone(),
            artifact_byte_length: template.artifact_byte_length(),
            policy_sha256: template.policy_sha256().clone(),
            runtime_profile: RuntimeProfileWireV1 {
                profile_id: runtime.profile_id().to_string(),
                profile_sha256: runtime.profile_sha256().clone(),
                target_os: runtime.runtime_target().target_os().to_string(),
                target_arch: runtime.runtime_target().target_arch().to_string(),
                node_version: runtime.node_version().to_string(),
                node_executable_sha256: runtime.node_executable_sha256().clone(),
                npm_version: runtime.npm_version().to_string(),
                npm_cli_sha256: runtime.npm_cli_sha256().clone(),
                command_template_sha256: runtime.command_template_sha256().clone(),
            },
            dependency_closure: template.dependency_closure().clone(),
            scenario_kind: template.scenario_kind(),
            lifecycle_hooks: template.lifecycle_hooks().to_vec(),
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

pub(crate) fn canonical_template_json_v1(
    template: &ArtifactScenarioTemplateV1,
) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
    let bytes =
        serde_json_canonicalizer::to_vec(&ArtifactScenarioTemplateWireV1::from_template(template))
            .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if bytes.len() > MAX_ARTIFACT_SCENARIO_TEMPLATE_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedArtifactScenarioTemplateWireV1 {
    template_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    artifact_byte_length: u64,
    policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    dependency_closure: DependencyClosureV1,
    scenario_id: String,
    environment: NpmEnvironmentProfileV1,
    runtime_target: ArtifactRuntimeTargetV1,
    runtime_profile_sha256: Sha256Digest,
    node_version: String,
    node_executable_sha256: Sha256Digest,
    npm_version: String,
    npm_cli_sha256: Sha256Digest,
    limits: ArtifactScenarioLimitsV1,
}

impl std::fmt::Debug for ValidatedArtifactScenarioTemplateWireV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ValidatedArtifactScenarioTemplateWireV1")
            .field("template_sha256", &self.template_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("envelope_sha256", &self.envelope_sha256)
            .field("manifest_sha256", &self.manifest_sha256)
            .field("artifact_byte_length", &self.artifact_byte_length)
            .field("policy_sha256", &self.policy_sha256)
            .field("dependency_closure_sha256", &self.dependency_closure_sha256)
            .field("scenario_id", &self.scenario_id)
            .field("environment", &self.environment)
            .field("runtime_target", &self.runtime_target)
            .field("runtime_profile_sha256", &self.runtime_profile_sha256)
            .field("node_version", &self.node_version)
            .field("node_executable_sha256", &self.node_executable_sha256)
            .field("npm_version", &self.npm_version)
            .field("npm_cli_sha256", &self.npm_cli_sha256)
            .finish()
    }
}

impl ValidatedArtifactScenarioTemplateWireV1 {
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

    pub fn dependency_closure(&self) -> &DependencyClosureV1 {
        &self.dependency_closure
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn environment(&self) -> NpmEnvironmentProfileV1 {
        self.environment
    }

    pub const fn runtime_target(&self) -> ArtifactRuntimeTargetV1 {
        self.runtime_target
    }

    pub fn runtime_profile_sha256(&self) -> &Sha256Digest {
        &self.runtime_profile_sha256
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

    pub fn limits(&self) -> &ArtifactScenarioLimitsV1 {
        &self.limits
    }
}

pub fn decode_and_validate_artifact_scenario_template_v1(
    bytes: &[u8],
) -> Result<ValidatedArtifactScenarioTemplateWireV1, ArtifactScenarioCompileErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_SCENARIO_TEMPLATE_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = ArtifactScenarioTemplateWireV1::deserialize(&mut deserializer)
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    validate_template_wire_v1(&wire)?;
    let environment = wire
        .scenario_kind
        .environment()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let runtime_target = ArtifactRuntimeTargetV1::from_wire(&wire.target_os, &wire.target_arch)
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let dependency_closure_sha256 = wire.dependency_closure.closure_sha256().clone();
    Ok(ValidatedArtifactScenarioTemplateWireV1 {
        template_sha256: Sha256Digest::from_bytes(bytes),
        artifact_sha256: wire.subject.artifact_sha256,
        envelope_sha256: wire.subject.envelope_sha256,
        manifest_sha256: wire.subject.manifest_sha256,
        artifact_byte_length: wire.artifact_byte_length,
        policy_sha256: wire.policy_sha256,
        dependency_closure_sha256,
        dependency_closure: wire.dependency_closure,
        scenario_id: wire.identity.scenario_id,
        environment,
        runtime_target,
        runtime_profile_sha256: wire.runtime_profile.profile_sha256,
        node_version: wire.runtime_profile.node_version,
        node_executable_sha256: wire.runtime_profile.node_executable_sha256,
        npm_version: wire.runtime_profile.npm_version,
        npm_cli_sha256: wire.runtime_profile.npm_cli_sha256,
        limits: wire.limits,
    })
}

fn validate_template_wire_v1(
    wire: &ArtifactScenarioTemplateWireV1,
) -> Result<(), ArtifactScenarioCompileErrorV1> {
    let Some(runtime_target) =
        ArtifactRuntimeTargetV1::from_wire(&wire.target_os, &wire.target_arch)
    else {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    };
    if wire.schema_version != ARTIFACT_SCENARIO_TEMPLATE_SCHEMA_V1
        || wire.canonicalization != ARTIFACT_SCENARIO_CANONICALIZATION_V1
        || wire.compiler_id != ARTIFACT_SCENARIO_COMPILER_ID_V1
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
        || wire.package.ecosystem != Ecosystem::Npm
        || !valid_package_text_v1(&wire.package.display_name)
        || !valid_package_text_v1(&wire.package.normalized_name)
        || !valid_package_text_v1(&wire.package.version)
        || wire.runtime_profile.target_os != wire.target_os
        || wire.runtime_profile.target_arch != wire.target_arch
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

    let runtime = NpmRuntimeProfileV1::new_for_target(
        runtime_target,
        &wire.runtime_profile.profile_id,
        &wire.runtime_profile.node_version,
        wire.runtime_profile.node_executable_sha256.clone(),
        &wire.runtime_profile.npm_version,
        wire.runtime_profile.npm_cli_sha256.clone(),
    )
    .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    if runtime.profile_sha256() != &wire.runtime_profile.profile_sha256
        || runtime.command_template_sha256() != &wire.runtime_profile.command_template_sha256
        || wire.runtime_profile.command_template_sha256
            != Sha256Digest::from_bytes(NPM_LOCAL_TARBALL_COMMAND_TEMPLATE_V1.as_bytes())
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }

    match &wire.dependency_closure {
        DependencyClosureV1::Empty {
            declaration_set_sha256,
        } => {
            let expected_closure = expected_empty_closure_sha256_v1(&wire.subject.manifest_sha256)?;
            if declaration_set_sha256 != &expected_closure {
                return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
            }
        }
        DependencyClosureV1::NpmTarballSet { closure } => {
            if closure.validate().is_err()
                || closure.artifacts().is_empty()
                || closure.artifacts().iter().any(|artifact| {
                    artifact.artifact_format()
                        != crate::SdistBuildClosureArtifactFormatV1::NpmTarGzip
                })
            {
                return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
            }
        }
    }
    let mut seen = BTreeSet::new();
    for binding in &wire.lifecycle_hooks {
        if !matches!(
            binding.hook(),
            NpmLifecycleHookV1::Preinstall
                | NpmLifecycleHookV1::Install
                | NpmLifecycleHookV1::Postinstall
        ) || !seen.insert(binding.hook())
        {
            return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
        }
    }
    if wire
        .lifecycle_hooks
        .windows(2)
        .any(|pair| pair[0].hook() >= pair[1].hook())
    {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    Ok(())
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyClosureDigestWireV1<'a> {
    schema_version: &'static str,
    manifest_sha256: &'a Sha256Digest,
    dependency_declarations: [String; 0],
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
struct TemplateReferenceWireV1 {
    scenario_id: String,
    environment: NpmEnvironmentProfileV1,
    template_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactScenarioPlanWireV1 {
    schema_version: String,
    canonicalization: String,
    compiler_id: String,
    plan_id: String,
    subject: SubjectWireV1,
    policy_sha256: Sha256Digest,
    templates: Vec<TemplateReferenceWireV1>,
}

pub(crate) fn canonical_plan_json_v1(
    plan: &ArtifactScenarioPlanV1,
) -> Result<Vec<u8>, ArtifactScenarioCompileErrorV1> {
    let subject = plan.subject();
    let wire = ArtifactScenarioPlanWireV1 {
        schema_version: ARTIFACT_SCENARIO_PLAN_SCHEMA_V1.to_string(),
        canonicalization: ARTIFACT_SCENARIO_CANONICALIZATION_V1.to_string(),
        compiler_id: ARTIFACT_SCENARIO_COMPILER_ID_V1.to_string(),
        plan_id: plan.plan_id().to_string(),
        subject: SubjectWireV1 {
            artifact_sha256: Sha256Digest::parse(subject.artifact_sha256().to_string())
                .expect("validated evidence subject artifact digest"),
            envelope_sha256: Sha256Digest::parse(subject.envelope_sha256().to_string())
                .expect("validated evidence subject envelope digest"),
            manifest_sha256: Sha256Digest::parse(subject.manifest_sha256().to_string())
                .expect("validated evidence subject manifest digest"),
            cas_object_key: subject.cas_object_key().to_string(),
        },
        policy_sha256: plan.policy_sha256().clone(),
        templates: plan
            .templates()
            .iter()
            .map(|template| TemplateReferenceWireV1 {
                scenario_id: template.identity().scenario_id().to_string(),
                environment: template
                    .scenario_kind()
                    .environment()
                    .expect("compiled plan contains only install scenarios"),
                template_sha256: template.template_sha256().clone(),
            })
            .collect(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if bytes.len() > MAX_ARTIFACT_SCENARIO_PLAN_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::ArtifactLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedArtifactScenarioPlanWireV1 {
    plan_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    policy_sha256: Sha256Digest,
    plan_id: String,
    templates: Vec<(String, NpmEnvironmentProfileV1, Sha256Digest)>,
}

impl ValidatedArtifactScenarioPlanWireV1 {
    pub fn plan_sha256(&self) -> &Sha256Digest {
        &self.plan_sha256
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

    pub fn plan_id(&self) -> &str {
        &self.plan_id
    }

    pub fn templates(&self) -> &[(String, NpmEnvironmentProfileV1, Sha256Digest)] {
        &self.templates
    }
}

pub fn decode_and_validate_artifact_scenario_plan_v1(
    bytes: &[u8],
) -> Result<ValidatedArtifactScenarioPlanWireV1, ArtifactScenarioCompileErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_SCENARIO_PLAN_WIRE_BYTES_V1 {
        return Err(ArtifactScenarioCompileErrorV1::InvalidWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = ArtifactScenarioPlanWireV1::deserialize(&mut deserializer)
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| ArtifactScenarioCompileErrorV1::InvalidWire)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    if canonical != bytes
        || wire.schema_version != ARTIFACT_SCENARIO_PLAN_SCHEMA_V1
        || wire.canonicalization != ARTIFACT_SCENARIO_CANONICALIZATION_V1
        || wire.compiler_id != ARTIFACT_SCENARIO_COMPILER_ID_V1
        || !valid_identity_component_v1(&wire.plan_id)
        || wire.templates.len() != 2
        || wire.templates[0].environment != NpmEnvironmentProfileV1::CiFalse
        || wire.templates[1].environment != NpmEnvironmentProfileV1::CiTrue
        || wire.templates[0].scenario_id == wire.templates[1].scenario_id
        || wire.templates[0].template_sha256 == wire.templates[1].template_sha256
        || !wire
            .templates
            .iter()
            .all(|reference| valid_identity_component_v1(&reference.scenario_id))
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
    Ok(ValidatedArtifactScenarioPlanWireV1 {
        plan_sha256: Sha256Digest::from_bytes(bytes),
        artifact_sha256: wire.subject.artifact_sha256,
        envelope_sha256: wire.subject.envelope_sha256,
        manifest_sha256: wire.subject.manifest_sha256,
        policy_sha256: wire.policy_sha256,
        plan_id: wire.plan_id,
        templates: wire
            .templates
            .into_iter()
            .map(|reference| {
                (
                    reference.scenario_id,
                    reference.environment,
                    reference.template_sha256,
                )
            })
            .collect(),
    })
}

fn valid_package_text_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii() && !byte.is_ascii_control())
}
