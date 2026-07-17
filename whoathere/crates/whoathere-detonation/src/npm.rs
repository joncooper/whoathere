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
    compile_artifact_scenarios_with_npm_closure_v1(request, None)
}

/// Compile the same closed npm lifecycle matrix with an optional exact offline tarball closure.
///
/// The closure is caller-supplied only as already sealed descriptors and is rebound here to the
/// dependency declarations parsed from the exact package artifact. It does not authorize network
/// resolution or a registry/cache fallback.
pub fn compile_artifact_scenarios_with_npm_closure_v1(
    request: ArtifactScenarioCompilationRequestV1<'_>,
    supplied_closure: Option<&crate::SdistBuildClosureV1>,
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
    let npm_requirements = npm_runtime_dependency_requirements_v1(request.manifest)?;
    let dependency_closure = if request.envelope.requires_external_dependency_resolution
        || npm.requires_offline_closure
    {
        let closure =
            supplied_closure.ok_or(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure)?;
        if npm_requirements.is_empty()
            || closure.artifacts().is_empty()
            || closure.artifacts().iter().any(|artifact| {
                artifact.artifact_format() != crate::SdistBuildClosureArtifactFormatV1::NpmTarGzip
            })
        {
            return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
        }
        let expected =
            crate::SdistBuildClosureV1::new(&npm_requirements, closure.artifacts().to_vec())?;
        if &expected != closure {
            return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
        }
        DependencyClosureV1::NpmTarballSet {
            closure: closure.clone(),
        }
    } else {
        if supplied_closure.is_some() || !npm_requirements.is_empty() {
            return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
        }
        let closure_bytes = serde_json_canonicalizer::to_vec(&EmptyClosureDigestWireV1 {
            schema_version: EMPTY_DEPENDENCY_CLOSURE_SCHEMA_V1,
            manifest_sha256: &request.manifest.manifest_sha256,
            dependency_declarations: [],
        })
        .map_err(|_| ArtifactScenarioCompileErrorV1::Serialization)?;
        DependencyClosureV1::Empty {
            declaration_set_sha256: Sha256Digest::from_bytes(&closure_bytes),
        }
    };
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

/// Canonical direct runtime/optional/peer requirements for the first exact npm closure slice.
///
/// Development and bundled dependency declarations do not require an external runtime closure.
/// Scoped names and remote/file specifications are conservatively rejected by the shared closure
/// validator rather than being guessed into paths.
pub fn npm_runtime_dependency_requirements_v1(
    manifest: &ArtifactManifest,
) -> Result<Vec<String>, ArtifactScenarioCompileErrorV1> {
    let npm = manifest
        .metadata
        .npm
        .as_ref()
        .ok_or(ArtifactScenarioCompileErrorV1::InvalidManifest)?;
    let mut requirements = npm
        .dependency_declarations
        .iter()
        .filter(|dependency| {
            matches!(
                dependency.group.as_str(),
                "dependencies" | "optionalDependencies" | "peerDependencies"
            )
        })
        .map(|dependency| format!("{} {}", dependency.name, dependency.requirement))
        .collect::<Vec<_>>();
    requirements.sort();
    requirements.dedup();
    crate::sdist::validate_build_requirements(&requirements)?;
    if npm
        .dependency_declarations
        .iter()
        .filter(|dependency| {
            matches!(
                dependency.group.as_str(),
                "dependencies" | "optionalDependencies" | "peerDependencies"
            )
        })
        .any(|dependency| {
            dependency.name.is_empty()
                || dependency.name.len() > 128
                || !dependency.name.is_ascii()
                || !dependency.name.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'-' | b'_' | b'.')
                })
                || dependency.requirement.is_empty()
                || dependency.requirement.len() > 512
                || !dependency.requirement.is_ascii()
                || dependency.requirement.chars().any(char::is_control)
                || !dependency.requirement.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric()
                        || matches!(
                            byte,
                            b'.' | b'-'
                                | b'_'
                                | b'+'
                                | b'^'
                                | b'~'
                                | b'*'
                                | b'<'
                                | b'>'
                                | b'='
                                | b'|'
                                | b' '
                        )
                })
        })
    {
        return Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure);
    }
    Ok(requirements)
}
