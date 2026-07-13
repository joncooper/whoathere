use crate::{
    validate_macos_linux_vz_typed_package_scenario_binding_v1, MacosLinuxVzPackageArtifactKindV1,
    MacosLinuxVzPackageAuthorityRequestV1, MacosLinuxVzPackageExecutionGrantObservationV1,
    MacosLinuxVzPackageExecutionScopeV1,
};
use serde::Serialize;
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    decode_and_validate_artifact_scenario_template_v1, decode_and_validate_sdist_scenario_plan_v1,
    decode_and_validate_sdist_scenario_template_v1, decode_and_validate_wheel_scenario_plan_v1,
    decode_and_validate_wheel_scenario_template_v1, ArtifactScenarioLimitsV1,
    ArtifactTelemetrySyncBackPolicyV1, NpmEnvironmentProfileV1, SdistBuildModeV1,
    SdistScenarioKindV1, WheelConsoleArgumentProfileV1, WheelScenarioKindV1,
};
use zeroize::Zeroize;

pub const MACOS_LINUX_VZ_PACKAGE_EXECUTION_REQUEST_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_execution_request.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_REQUEST_BYTES_V1: usize = 64 * 1024;

const EXECUTION_REQUEST_AUTHORITY_V1: &str = "protected_guest_agent_after_burned_execution_grant";
const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;

/// The only artifact input representation understood by the execution runner.
///
/// The protected guest agent supplies the already rehashed artifact through a fixed read-only file
/// descriptor. No package-controlled path crosses this wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageExecutionArtifactInputV1 {
    ExactRehashedReadOnlyDescriptor,
}

/// A build recipe derived from the validated sdist plan rather than from runner input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosLinuxVzSdistBuildRecipeV1 {
    build_template_sha256: Sha256Digest,
    build_mode: SdistBuildModeV1,
    build_backend: Option<String>,
    backend_paths: Vec<String>,
    build_requires_sha256: Sha256Digest,
}

impl MacosLinuxVzSdistBuildRecipeV1 {
    pub fn build_template_sha256(&self) -> &Sha256Digest {
        &self.build_template_sha256
    }

    pub const fn build_mode(&self) -> SdistBuildModeV1 {
        self.build_mode
    }

    pub fn build_backend(&self) -> Option<&str> {
        self.build_backend.as_deref()
    }

    pub fn backend_paths(&self) -> &[String] {
        &self.backend_paths
    }

    pub fn build_requires_sha256(&self) -> &Sha256Digest {
        &self.build_requires_sha256
    }
}

/// Closed runner operations compiled from validated package scenario plans.
///
/// Probe operations are deliberately composite. For example, an import-root scenario means
/// install the exact wheel in a fresh virtual environment and then import the validated module.
/// The runner never accepts a free-form executable, argv vector, path, or shell fragment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosLinuxVzPackageExecutionOperationV1 {
    NpmInstallExactLocalTarball {
        environment: NpmEnvironmentProfileV1,
    },
    WheelInstallExact {
        install_template_sha256: Sha256Digest,
    },
    WheelInstallThenFreshInterpreterPth {
        install_template_sha256: Sha256Digest,
        pth_file_ids: Vec<Sha256Digest>,
    },
    WheelInstallThenImportRoot {
        install_template_sha256: Sha256Digest,
        module: String,
    },
    WheelInstallThenConsoleEntryPointHelp {
        install_template_sha256: Sha256Digest,
        command_name: String,
        module: String,
        callable: String,
        target_sha256: Sha256Digest,
    },
    SdistBuildExact {
        build: MacosLinuxVzSdistBuildRecipeV1,
    },
    SdistBuildThenInspectDerivedWheel {
        build: MacosLinuxVzSdistBuildRecipeV1,
    },
    SdistBuildThenInstallDerivedWheel {
        build: MacosLinuxVzSdistBuildRecipeV1,
    },
    SdistBuildInstallThenImportRoot {
        build: MacosLinuxVzSdistBuildRecipeV1,
        module: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct PackageExecutionRequestWireV1 {
    schema_version: String,
    authority: String,
    package_authority_request_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    execution_runtime_qualification_record_sha256: Sha256Digest,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: String,
    scenario_plan_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    scenario_id: String,
    scenario_kind_sha256: Sha256Digest,
    scenario_policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    grant_challenge_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    grant_issued_at_unix_seconds: String,
    grant_expires_at_unix_seconds: String,
    grant_verified_at_unix_seconds: String,
    package_uid: String,
    package_gid: String,
    artifact_input: MacosLinuxVzPackageExecutionArtifactInputV1,
    operation: MacosLinuxVzPackageExecutionOperationV1,
    limits: ArtifactScenarioLimitsV1,
    attempt_limit: String,
    execution_scope: MacosLinuxVzPackageExecutionScopeV1,
    public_network_route_present: bool,
    arbitrary_command_input_present: bool,
    execution_grant_consumed: bool,
    package_execution_permitted: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

pub struct MacosLinuxVzPackageExecutionRequestV1 {
    canonical_json: Vec<u8>,
    request_sha256: Sha256Digest,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    operation: MacosLinuxVzPackageExecutionOperationV1,
    limits: ArtifactScenarioLimitsV1,
}

impl fmt::Debug for MacosLinuxVzPackageExecutionRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionRequestV1")
            .field("request_sha256", &self.request_sha256)
            .field("artifact_kind", &self.artifact_kind)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("scenario_template_sha256", &self.scenario_template_sha256)
            .field("execution_grant_sha256", &self.execution_grant_sha256)
            .field("attempt_binding_sha256", &self.attempt_binding_sha256)
            .field("clone_binding_sha256", &self.clone_binding_sha256)
            .field("operation", &self.operation)
            .field("canonical_json", &"<redacted-and-zeroized-on-drop>")
            .finish()
    }
}

impl Drop for MacosLinuxVzPackageExecutionRequestV1 {
    fn drop(&mut self) {
        self.canonical_json.zeroize();
    }
}

impl MacosLinuxVzPackageExecutionRequestV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub const fn artifact_kind(&self) -> MacosLinuxVzPackageArtifactKindV1 {
        self.artifact_kind
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn scenario_template_sha256(&self) -> &Sha256Digest {
        &self.scenario_template_sha256
    }

    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn attempt_binding_sha256(&self) -> &Sha256Digest {
        &self.attempt_binding_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub fn operation(&self) -> &MacosLinuxVzPackageExecutionOperationV1 {
        &self.operation
    }

    pub fn limits(&self) -> &ArtifactScenarioLimitsV1 {
        &self.limits
    }

    pub const fn package_execution_permitted(&self) -> bool {
        true
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzPackageExecutionRequestErrorV1 {
    GrantInvalid,
    GrantBindingMismatch,
    AuthorityRequestInvalid,
    ArtifactMismatch,
    ScenarioInvalid,
    ScenarioBindingMismatch,
    ClosedOperationInvalid,
    AlreadyConsumed,
    LimitExceeded,
    Serialization,
}

impl MacosLinuxVzPackageExecutionRequestErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::GrantInvalid => "macos_linux_vz_execution_request_grant_invalid",
            Self::GrantBindingMismatch => "macos_linux_vz_execution_request_grant_binding_mismatch",
            Self::AuthorityRequestInvalid => {
                "macos_linux_vz_execution_request_authority_request_invalid"
            }
            Self::ArtifactMismatch => "macos_linux_vz_execution_request_artifact_mismatch",
            Self::ScenarioInvalid => "macos_linux_vz_execution_request_scenario_invalid",
            Self::ScenarioBindingMismatch => {
                "macos_linux_vz_execution_request_scenario_binding_mismatch"
            }
            Self::ClosedOperationInvalid => {
                "macos_linux_vz_execution_request_closed_operation_invalid"
            }
            Self::AlreadyConsumed => "macos_linux_vz_execution_request_already_consumed",
            Self::LimitExceeded => "macos_linux_vz_execution_request_limit_exceeded",
            Self::Serialization => "macos_linux_vz_execution_request_serialization_failed",
        }
    }
}

impl fmt::Display for MacosLinuxVzPackageExecutionRequestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzPackageExecutionRequestErrorV1 {}

/// One-boot protected authority that consumes a verified grant observation before doing any other
/// request validation. Invalid and valid derivation attempts both burn the authority.
pub struct MacosLinuxVzPackageExecutionRequestAuthorizerV1 {
    grant: MacosLinuxVzPackageExecutionGrantObservationV1,
    consumed: AtomicBool,
}

impl fmt::Debug for MacosLinuxVzPackageExecutionRequestAuthorizerV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionRequestAuthorizerV1")
            .field("grant", &self.grant)
            .field("consumed", &self.consumed.load(Ordering::Acquire))
            .finish()
    }
}

impl MacosLinuxVzPackageExecutionRequestAuthorizerV1 {
    pub fn new(
        grant: MacosLinuxVzPackageExecutionGrantObservationV1,
    ) -> Result<Self, MacosLinuxVzPackageExecutionRequestErrorV1> {
        if !grant.consumed()
            || grant.package_execution_scope()
                != MacosLinuxVzPackageExecutionScopeV1::OneTypedScenarioOneAttempt
            || grant.sync_back_permitted()
            || grant.package_uid() != PACKAGE_UID_V1
            || grant.package_gid() != PACKAGE_GID_V1
            || grant.issued_at_unix_seconds() == 0
            || grant.verified_at_unix_seconds() < grant.issued_at_unix_seconds()
            || grant.verified_at_unix_seconds() >= grant.expires_at_unix_seconds()
        {
            return Err(MacosLinuxVzPackageExecutionRequestErrorV1::GrantInvalid);
        }
        Ok(Self {
            grant,
            consumed: AtomicBool::new(false),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn build_and_consume(
        &self,
        authority_request: &MacosLinuxVzPackageAuthorityRequestV1,
        artifact_bytes: &[u8],
        scenario_plan_bytes: &[u8],
        scenario_template_bytes: &[u8],
    ) -> Result<MacosLinuxVzPackageExecutionRequestV1, MacosLinuxVzPackageExecutionRequestErrorV1>
    {
        if self.consumed.swap(true, Ordering::AcqRel) {
            return Err(MacosLinuxVzPackageExecutionRequestErrorV1::AlreadyConsumed);
        }
        build_execution_request_v1(
            &self.grant,
            authority_request,
            artifact_bytes,
            scenario_plan_bytes,
            scenario_template_bytes,
        )
    }

    pub fn consumed(&self) -> bool {
        self.consumed.load(Ordering::Acquire)
    }
}

#[allow(clippy::too_many_arguments)]
fn build_execution_request_v1(
    grant: &MacosLinuxVzPackageExecutionGrantObservationV1,
    authority_request: &MacosLinuxVzPackageAuthorityRequestV1,
    artifact_bytes: &[u8],
    scenario_plan_bytes: &[u8],
    scenario_template_bytes: &[u8],
) -> Result<MacosLinuxVzPackageExecutionRequestV1, MacosLinuxVzPackageExecutionRequestErrorV1> {
    if authority_request.package_execution_authority_permitted()
        || authority_request.sync_back_permitted()
    {
        return Err(MacosLinuxVzPackageExecutionRequestErrorV1::AuthorityRequestInvalid);
    }
    if grant.package_authority_request_sha256() != authority_request.request_sha256()
        || grant.request_challenge_sha256() != authority_request.request_challenge_sha256()
        || grant.clone_binding_sha256() != authority_request.clone_binding_sha256()
    {
        return Err(MacosLinuxVzPackageExecutionRequestErrorV1::GrantBindingMismatch);
    }
    if artifact_bytes.is_empty()
        || Sha256Digest::from_bytes(artifact_bytes) != *authority_request.artifact_sha256()
        || artifact_bytes.len() as u64 != authority_request.artifact_byte_length()
    {
        return Err(MacosLinuxVzPackageExecutionRequestErrorV1::ArtifactMismatch);
    }
    if Sha256Digest::from_bytes(scenario_plan_bytes) != *authority_request.scenario_plan_sha256()
        || Sha256Digest::from_bytes(scenario_template_bytes)
            != *authority_request.scenario_template_sha256()
    {
        return Err(MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioBindingMismatch);
    }

    let binding = validate_macos_linux_vz_typed_package_scenario_binding_v1(
        authority_request.artifact_kind(),
        scenario_plan_bytes,
        scenario_template_bytes,
    )
    .map_err(|_| MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioInvalid)?;
    if binding.artifact_sha256() != authority_request.artifact_sha256()
        || binding.artifact_byte_length() != authority_request.artifact_byte_length()
        || binding.scenario_plan_sha256() != authority_request.scenario_plan_sha256()
        || binding.scenario_template_sha256() != authority_request.scenario_template_sha256()
        || binding.scenario_id() != authority_request.scenario_id()
        || binding.scenario_kind_sha256() != authority_request.scenario_kind_sha256()
        || binding.scenario_policy_sha256() != authority_request.scenario_policy_sha256()
        || binding.dependency_closure_sha256() != authority_request.dependency_closure_sha256()
        || binding.runtime_profile_sha256() != authority_request.runtime_profile_sha256()
    {
        return Err(MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioBindingMismatch);
    }

    let (operation, limits) = operation_and_limits_v1(
        authority_request.artifact_kind(),
        scenario_plan_bytes,
        scenario_template_bytes,
    )?;
    let wire = PackageExecutionRequestWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_EXECUTION_REQUEST_SCHEMA_V1.to_string(),
        authority: EXECUTION_REQUEST_AUTHORITY_V1.to_string(),
        package_authority_request_sha256: authority_request.request_sha256().clone(),
        execution_grant_sha256: grant.execution_grant_sha256().clone(),
        execution_runtime_qualification_record_sha256: grant
            .execution_runtime_qualification_record_sha256()
            .clone(),
        artifact_kind: authority_request.artifact_kind(),
        artifact_sha256: authority_request.artifact_sha256().clone(),
        artifact_byte_length: authority_request.artifact_byte_length().to_string(),
        scenario_plan_sha256: authority_request.scenario_plan_sha256().clone(),
        scenario_template_sha256: authority_request.scenario_template_sha256().clone(),
        scenario_id: authority_request.scenario_id().to_string(),
        scenario_kind_sha256: authority_request.scenario_kind_sha256().clone(),
        scenario_policy_sha256: authority_request.scenario_policy_sha256().clone(),
        dependency_closure_sha256: authority_request.dependency_closure_sha256().clone(),
        runtime_profile_sha256: authority_request.runtime_profile_sha256().clone(),
        request_challenge_sha256: grant.request_challenge_sha256().clone(),
        grant_challenge_sha256: grant.grant_challenge_sha256().clone(),
        attempt_binding_sha256: grant.attempt_binding_sha256().clone(),
        clone_binding_sha256: grant.clone_binding_sha256().clone(),
        grant_issued_at_unix_seconds: grant.issued_at_unix_seconds().to_string(),
        grant_expires_at_unix_seconds: grant.expires_at_unix_seconds().to_string(),
        grant_verified_at_unix_seconds: grant.verified_at_unix_seconds().to_string(),
        package_uid: grant.package_uid().to_string(),
        package_gid: grant.package_gid().to_string(),
        artifact_input:
            MacosLinuxVzPackageExecutionArtifactInputV1::ExactRehashedReadOnlyDescriptor,
        operation: operation.clone(),
        limits: limits.clone(),
        attempt_limit: "1".to_string(),
        execution_scope: MacosLinuxVzPackageExecutionScopeV1::OneTypedScenarioOneAttempt,
        public_network_route_present: false,
        arbitrary_command_input_present: false,
        execution_grant_consumed: true,
        package_execution_permitted: true,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageExecutionRequestErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_REQUEST_BYTES_V1
    {
        return Err(MacosLinuxVzPackageExecutionRequestErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzPackageExecutionRequestV1 {
        request_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        artifact_kind: authority_request.artifact_kind(),
        artifact_sha256: authority_request.artifact_sha256().clone(),
        scenario_template_sha256: authority_request.scenario_template_sha256().clone(),
        execution_grant_sha256: grant.execution_grant_sha256().clone(),
        attempt_binding_sha256: grant.attempt_binding_sha256().clone(),
        clone_binding_sha256: grant.clone_binding_sha256().clone(),
        operation,
        limits,
    })
}

fn operation_and_limits_v1(
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    scenario_plan_bytes: &[u8],
    scenario_template_bytes: &[u8],
) -> Result<
    (
        MacosLinuxVzPackageExecutionOperationV1,
        ArtifactScenarioLimitsV1,
    ),
    MacosLinuxVzPackageExecutionRequestErrorV1,
> {
    match artifact_kind {
        MacosLinuxVzPackageArtifactKindV1::NpmTarball => {
            let template =
                decode_and_validate_artifact_scenario_template_v1(scenario_template_bytes)
                    .map_err(|_| MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioInvalid)?;
            Ok((
                MacosLinuxVzPackageExecutionOperationV1::NpmInstallExactLocalTarball {
                    environment: template.environment(),
                },
                template.limits().clone(),
            ))
        }
        MacosLinuxVzPackageArtifactKindV1::PypiWheel => {
            let plan = decode_and_validate_wheel_scenario_plan_v1(scenario_plan_bytes)
                .map_err(|_| MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioInvalid)?;
            let template = decode_and_validate_wheel_scenario_template_v1(scenario_template_bytes)
                .map_err(|_| MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioInvalid)?;
            let operation = wheel_operation_v1(plan.templates(), template.scenario_kind())?;
            Ok((operation, template.limits().clone()))
        }
        MacosLinuxVzPackageArtifactKindV1::PypiSdist => {
            let plan = decode_and_validate_sdist_scenario_plan_v1(scenario_plan_bytes)
                .map_err(|_| MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioInvalid)?;
            let template = decode_and_validate_sdist_scenario_template_v1(scenario_template_bytes)
                .map_err(|_| MacosLinuxVzPackageExecutionRequestErrorV1::ScenarioInvalid)?;
            let operation = sdist_operation_v1(plan.templates(), template.scenario_kind())?;
            Ok((operation, template.limits().clone()))
        }
    }
}

fn wheel_operation_v1(
    templates: &[(String, WheelScenarioKindV1, Sha256Digest)],
    selected: &WheelScenarioKindV1,
) -> Result<MacosLinuxVzPackageExecutionOperationV1, MacosLinuxVzPackageExecutionRequestErrorV1> {
    let install_template_sha256 = templates
        .iter()
        .find_map(|(_, kind, digest)| {
            matches!(kind, WheelScenarioKindV1::InstallExactWheel).then_some(digest.clone())
        })
        .ok_or(MacosLinuxVzPackageExecutionRequestErrorV1::ClosedOperationInvalid)?;
    let operation = match selected {
        WheelScenarioKindV1::InstallExactWheel => {
            MacosLinuxVzPackageExecutionOperationV1::WheelInstallExact {
                install_template_sha256,
            }
        }
        WheelScenarioKindV1::FreshInterpreterPth { pth_file_ids } => {
            MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenFreshInterpreterPth {
                install_template_sha256,
                pth_file_ids: pth_file_ids.clone(),
            }
        }
        WheelScenarioKindV1::ImportRoot { module } => {
            MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenImportRoot {
                install_template_sha256,
                module: module.clone(),
            }
        }
        WheelScenarioKindV1::ConsoleEntryPoint {
            command_name,
            module,
            callable,
            target_sha256,
            argument_profile: WheelConsoleArgumentProfileV1::HelpOnly,
        } => MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenConsoleEntryPointHelp {
            install_template_sha256,
            command_name: command_name.clone(),
            module: module.clone(),
            callable: callable.clone(),
            target_sha256: target_sha256.clone(),
        },
    };
    Ok(operation)
}

fn sdist_operation_v1(
    templates: &[(String, SdistScenarioKindV1, Sha256Digest)],
    selected: &SdistScenarioKindV1,
) -> Result<MacosLinuxVzPackageExecutionOperationV1, MacosLinuxVzPackageExecutionRequestErrorV1> {
    let build = templates
        .iter()
        .find_map(|(_, kind, digest)| match kind {
            SdistScenarioKindV1::BuildExactSdist {
                build_mode,
                build_backend,
                backend_paths,
                build_requires_sha256,
            } => Some(MacosLinuxVzSdistBuildRecipeV1 {
                build_template_sha256: digest.clone(),
                build_mode: *build_mode,
                build_backend: build_backend.clone(),
                backend_paths: backend_paths.clone(),
                build_requires_sha256: build_requires_sha256.clone(),
            }),
            _ => None,
        })
        .ok_or(MacosLinuxVzPackageExecutionRequestErrorV1::ClosedOperationInvalid)?;
    let operation = match selected {
        SdistScenarioKindV1::BuildExactSdist { .. } => {
            MacosLinuxVzPackageExecutionOperationV1::SdistBuildExact { build }
        }
        SdistScenarioKindV1::InspectDerivedWheel => {
            MacosLinuxVzPackageExecutionOperationV1::SdistBuildThenInspectDerivedWheel { build }
        }
        SdistScenarioKindV1::InstallDerivedWheel => {
            MacosLinuxVzPackageExecutionOperationV1::SdistBuildThenInstallDerivedWheel { build }
        }
        SdistScenarioKindV1::ImportRoot { module } => {
            MacosLinuxVzPackageExecutionOperationV1::SdistBuildInstallThenImportRoot {
                build,
                module: module.clone(),
            }
        }
    };
    Ok(operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;
    use whoathere_artifact::{
        normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput,
        ArtifactFormat, ArtifactSourceType, Ecosystem, NormalizationLimits,
    };
    use whoathere_detonation::{
        compile_artifact_scenarios_v1, ArtifactRuntimeTargetV1,
        ArtifactScenarioCompilationRequestV1, ArtifactScenarioExecutionIdentityV1,
        ArtifactScenarioIdentitySetV1, ArtifactScenarioPolicyV1, NpmRuntimeProfileV1,
    };
    use whoathere_evidence::v2::{
        canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2,
    };

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn inert_npm_execution_inputs() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes) in [
            (
                "package/package.json",
                br#"{"name":"execution-request-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#
                    .as_slice(),
            ),
            ("package/post.js", b"process.exit(0)".as_slice()),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, path, Cursor::new(bytes))
                .expect("append inert npm member");
        }
        let artifact_bytes = archive
            .into_inner()
            .expect("finish inert tar")
            .finish()
            .expect("finish inert gzip");
        let envelope = ArtifactEnvelope::from_original_bytes(
            ArtifactEnvelopeInput {
                ecosystem: Ecosystem::Npm,
                package_name: Some("execution-request-fixture".to_string()),
                package_version: Some("1.0.0".to_string()),
                source_coordinate: "fixture:execution-request-fixture@1.0.0".to_string(),
                source_type: ArtifactSourceType::LocalFile,
                acquired_at: "2026-07-13T00:00:00Z".to_string(),
                acquisition_method: AcquisitionMethod::LocalInertFixture,
                original_filename: "execution-request-fixture-1.0.0.tgz".to_string(),
                declared_format: Some(ArtifactFormat::NpmTarGzip),
                custody_reference: "repository-inert-execution-request-fixture".to_string(),
                resolver_metadata_sha256: None,
                registry_metadata_sha256: None,
                policy_version: "linux-vz-execution-request.v1".to_string(),
                requires_external_dependency_resolution: false,
            },
            &artifact_bytes,
            ArtifactFormat::NpmTarGzip,
        );
        let normalized =
            normalize_artifact(&envelope, &artifact_bytes, NormalizationLimits::default())
                .expect("normalize inert npm fixture");
        let subject = ArtifactEvidenceSubjectV2::new(
            normalized.manifest.artifact_sha256.as_str(),
            envelope
                .envelope_sha256()
                .expect("envelope digest")
                .as_str(),
            normalized.manifest.manifest_sha256.as_str(),
            canonical_cas_object_key_for_artifact(normalized.manifest.artifact_sha256.as_str())
                .expect("CAS key"),
        )
        .expect("evidence subject");
        let runtime = NpmRuntimeProfileV1::new_for_target(
            ArtifactRuntimeTargetV1::LinuxArm64,
            "linux-arm64-node24-npm11-inert",
            "24.17.0",
            digest("measured Linux node"),
            "11.12.1",
            digest("measured Linux npm"),
        )
        .expect("Linux npm runtime");
        let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
            envelope.original_sha256.clone(),
            runtime,
        )
        .expect("Linux npm policy");
        let identities = ArtifactScenarioIdentitySetV1::new(
            "execution-request-plan",
            ArtifactScenarioExecutionIdentityV1::new(
                "execution-request-job-false",
                "execution-request-run-false",
                "execution-request-evidence-false",
                "execution-request-scenario-false",
            )
            .expect("false identity"),
            ArtifactScenarioExecutionIdentityV1::new(
                "execution-request-job-true",
                "execution-request-run-true",
                "execution-request-evidence-true",
                "execution-request-scenario-true",
            )
            .expect("true identity"),
        )
        .expect("identity set");
        let plan = compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
            envelope: &envelope,
            manifest: &normalized.manifest,
            subject: &subject,
            policy: &policy,
            identities: &identities,
        })
        .expect("Linux npm plan");
        let plan_bytes = plan.canonical_json_v1().expect("plan bytes");
        let template_bytes = plan.templates()[1]
            .canonical_json_v1()
            .expect("CI=true template bytes");
        (artifact_bytes, plan_bytes, template_bytes)
    }

    #[test]
    fn wheel_probe_is_compiled_as_install_then_closed_probe() {
        let install_digest = digest("wheel install template");
        let templates = vec![
            (
                "install".to_string(),
                WheelScenarioKindV1::InstallExactWheel,
                install_digest.clone(),
            ),
            (
                "import".to_string(),
                WheelScenarioKindV1::ImportRoot {
                    module: "safe_fixture".to_string(),
                },
                digest("wheel import template"),
            ),
        ];
        let operation = wheel_operation_v1(
            &templates,
            &WheelScenarioKindV1::ImportRoot {
                module: "safe_fixture".to_string(),
            },
        )
        .expect("closed operation");
        assert_eq!(
            operation,
            MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenImportRoot {
                install_template_sha256: install_digest,
                module: "safe_fixture".to_string(),
            }
        );
    }

    #[test]
    fn wheel_probe_without_install_prerequisite_fails_closed() {
        let templates = vec![(
            "import".to_string(),
            WheelScenarioKindV1::ImportRoot {
                module: "safe_fixture".to_string(),
            },
            digest("wheel import template"),
        )];
        assert_eq!(
            wheel_operation_v1(
                &templates,
                &WheelScenarioKindV1::ImportRoot {
                    module: "safe_fixture".to_string(),
                },
            ),
            Err(MacosLinuxVzPackageExecutionRequestErrorV1::ClosedOperationInvalid)
        );
    }

    #[test]
    fn sdist_probe_carries_plan_bound_build_prerequisite() {
        let build_digest = digest("sdist build template");
        let build_requires = digest("sdist build requirements");
        let templates = vec![
            (
                "build".to_string(),
                SdistScenarioKindV1::BuildExactSdist {
                    build_mode: SdistBuildModeV1::Pep517,
                    build_backend: Some("fixture_backend".to_string()),
                    backend_paths: vec!["backend".to_string()],
                    build_requires_sha256: build_requires.clone(),
                },
                build_digest.clone(),
            ),
            (
                "import".to_string(),
                SdistScenarioKindV1::ImportRoot {
                    module: "safe_fixture".to_string(),
                },
                digest("sdist import template"),
            ),
        ];
        let operation = sdist_operation_v1(
            &templates,
            &SdistScenarioKindV1::ImportRoot {
                module: "safe_fixture".to_string(),
            },
        )
        .expect("closed operation");
        let MacosLinuxVzPackageExecutionOperationV1::SdistBuildInstallThenImportRoot {
            build,
            module,
        } = operation
        else {
            panic!("unexpected operation");
        };
        assert_eq!(module, "safe_fixture");
        assert_eq!(build.build_template_sha256(), &build_digest);
        assert_eq!(build.build_requires_sha256(), &build_requires);
        assert_eq!(build.build_backend(), Some("fixture_backend"));
        assert_eq!(build.backend_paths(), &["backend".to_string()]);
    }

    #[test]
    fn operation_wire_has_no_free_form_process_interface() {
        let operation =
            MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenConsoleEntryPointHelp {
                install_template_sha256: digest("install"),
                command_name: "fixture-cli".to_string(),
                module: "fixture.cli".to_string(),
                callable: "main".to_string(),
                target_sha256: Sha256Digest::from_bytes(b"fixture.cli:main"),
            };
        let json = serde_json::to_string(&operation).expect("serialize");
        for forbidden in [
            "argv",
            "shell",
            "executable_path",
            "artifact_path",
            "working_directory",
        ] {
            assert!(
                !json.contains(forbidden),
                "unexpected process interface: {forbidden}"
            );
        }
        assert!(json.contains("wheel_install_then_console_entry_point_help"));
    }

    #[test]
    fn exact_inert_npm_inputs_derive_one_bound_ci_true_request() {
        let (artifact_bytes, plan_bytes, template_bytes) = inert_npm_execution_inputs();
        let authority_request = crate::linux_vz_package_authority_request::test_macos_linux_vz_package_authority_request_from_scenario_v1(
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact_bytes,
            &plan_bytes,
            &template_bytes,
            digest("request challenge"),
            digest("unique disposable clone"),
        );
        let grant = crate::linux_vz_package_execution_grant::test_macos_linux_vz_package_execution_grant_observation_v1(&authority_request);
        let expected_grant_sha256 = grant.execution_grant_sha256().clone();
        let authorizer = MacosLinuxVzPackageExecutionRequestAuthorizerV1::new(grant)
            .expect("request authorizer");
        let request = authorizer
            .build_and_consume(
                &authority_request,
                &artifact_bytes,
                &plan_bytes,
                &template_bytes,
            )
            .expect("bound execution request");
        assert!(authorizer.consumed());
        assert_eq!(request.execution_grant_sha256(), &expected_grant_sha256);
        assert_eq!(
            request.artifact_sha256(),
            &Sha256Digest::from_bytes(&artifact_bytes)
        );
        assert_eq!(
            request.operation(),
            &MacosLinuxVzPackageExecutionOperationV1::NpmInstallExactLocalTarball {
                environment: NpmEnvironmentProfileV1::CiTrue,
            }
        );
        assert!(request.package_execution_permitted());
        assert!(!request.sync_back_permitted());
        let value: serde_json::Value =
            serde_json::from_slice(request.canonical_json_v1()).expect("request JSON");
        assert_eq!(
            value["artifact_input"],
            "exact_rehashed_read_only_descriptor"
        );
        assert_eq!(value["attempt_limit"], "1");
        assert_eq!(value["public_network_route_present"], false);
        assert_eq!(value["arbitrary_command_input_present"], false);
        assert_eq!(value["execution_grant_consumed"], true);
        assert_eq!(value["package_execution_permitted"], true);
        assert_eq!(value["sync_back_policy"], "structurally_absent");
        let text = std::str::from_utf8(request.canonical_json_v1()).expect("request UTF-8");
        for forbidden in ["\"argv\"", "\"shell\"", "\"artifact_path\""] {
            assert!(
                !text.contains(forbidden),
                "unexpected process interface: {forbidden}"
            );
        }
    }
}
