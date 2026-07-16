use crate::artifact::{
    required_evidence_classes_v1, ArtifactScenarioCompileErrorV1, ArtifactScenarioIdentitySetV1,
    ArtifactScenarioKindV1, ArtifactScenarioPlanV1, ArtifactScenarioPolicyV1,
    ArtifactScenarioTemplateV1, DependencyClosureV1, LifecycleHookBindingV1,
    NpmEnvironmentProfileV1, NpmLifecycleHookV1, EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1,
};
use serde::Serialize;
use whoathere_artifact::{
    ArtifactEnvelope, ArtifactFormat, ArtifactManifest, Ecosystem, NormalizationCompleteness,
    Sha256Digest,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub struct ArtifactScenarioCompilationRequestV1<'a> {
    pub envelope: &'a ArtifactEnvelope,
    pub manifest: &'a ArtifactManifest,
    pub subject: &'a ArtifactEvidenceSubjectV2,
    pub policy: &'a ArtifactScenarioPolicyV1,
    pub identities: &'a ArtifactScenarioIdentitySetV1,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct EmptyClosureDigestWireV1<'a> {
    schema_version: &'static str,
    manifest_sha256: &'a Sha256Digest,
    dependency_declarations: [String; 0],
}

pub fn compile_artifact_scenarios_v1(
    request: ArtifactScenarioCompilationRequestV1<'_>,
) -> Result<ArtifactScenarioPlanV1, ArtifactScenarioCompileErrorV1> {
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
    if request.envelope.ecosystem != Ecosystem::Npm
        || request.envelope.magic_detected_format != ArtifactFormat::NpmTarGzip
        || request.manifest.magic_detected_format != ArtifactFormat::NpmTarGzip
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
    if identity.ecosystem != Ecosystem::Npm
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
    let npm = request
        .manifest
        .metadata
        .npm
        .as_ref()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    if request.envelope.requires_external_dependency_resolution || npm.requires_offline_closure {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
    }
    if npm.implicit_node_gyp_rebuild || !request.manifest.native_binary_file_ids.is_empty() {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedNativeArtifact);
    }

    let mut lifecycle_hooks = Vec::with_capacity(npm.lifecycle_scripts.len());
    for (name, command) in &npm.lifecycle_scripts {
        let hook = NpmLifecycleHookV1::parse(name)
            .ok_or(ArtifactScenarioCompileErrorV1::UnsupportedLifecycleHook)?;
        if !request.policy.qualified_lifecycle_hooks().contains(&hook) {
            return Err(ArtifactScenarioCompileErrorV1::UnsupportedLifecycleHook);
        }
        lifecycle_hooks.push(LifecycleHookBindingV1::new(
            hook,
            Sha256Digest::from_bytes(command.as_bytes()),
        ));
    }
    lifecycle_hooks.sort_by_key(LifecycleHookBindingV1::hook);

    let closure_bytes = serde_json_canonicalizer::to_vec(&EmptyClosureDigestWireV1 {
        schema_version: EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1,
        manifest_sha256: &request.manifest.manifest_sha256,
        dependency_declarations: [],
    })
    .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
    let dependency_closure = DependencyClosureV1::Empty {
        declaration_set_sha256: Sha256Digest::from_bytes(&closure_bytes),
    };

    let mut templates = Vec::with_capacity(2);
    for environment in [
        NpmEnvironmentProfileV1::CiFalse,
        NpmEnvironmentProfileV1::CiTrue,
    ] {
        let mut template = ArtifactScenarioTemplateV1 {
            identity: request.identities.for_environment(environment).clone(),
            subject: request.subject.clone(),
            package: identity.clone(),
            artifact_byte_length: request.envelope.original_byte_length,
            policy_sha256: request.policy.policy_sha256().clone(),
            runtime_profile: request.policy.runtime_profile().clone(),
            dependency_closure: dependency_closure.clone(),
            scenario_kind: ArtifactScenarioKindV1::NpmLocalTarballInstall { environment },
            lifecycle_hooks: lifecycle_hooks.clone(),
            limits: request.policy.limits().clone(),
            required_evidence: required_evidence_classes_v1(),
            template_sha256: Sha256Digest::from_bytes(&[]),
        };
        let canonical = template.canonical_json_v1()?;
        template.template_sha256 = Sha256Digest::from_bytes(&canonical);
        templates.push(template);
    }

    let mut plan = ArtifactScenarioPlanV1 {
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
