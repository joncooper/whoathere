use crate::{
    MacosLinuxVzPackageArtifactKindV1, MacosLinuxVzPackageExecutionOperationV1,
    MacosLinuxVzSdistBuildRecipeV1, StructurallyValidatedMacosLinuxVzPackageExecutionRequestV1,
};
use serde::Serialize;
use std::fmt;
use whoathere_artifact::{ArtifactFormat, Sha256Digest};
use whoathere_detonation::{
    ArtifactScenarioLimitsV1, ArtifactTelemetrySyncBackPolicyV1, NpmEnvironmentProfileV1,
};

pub const MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROGRAM_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_execution_program.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROGRAM_BYTES_V1: usize = 128 * 1024;

const NPM_INPUT_BASENAME_V1: &str = "package.tgz";
const SDIST_TAR_GZIP_INPUT_BASENAME_V1: &str = "package.tar.gz";
const SDIST_ZIP_INPUT_BASENAME_V1: &str = "package.zip";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageExecutionInputMaterializationV1 {
    RootCreatedReadOnlyNamedFileFromRehashedDescriptor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageExecutionWorkspacePolicyV1 {
    FreshUidGidOwnedTmpfsPerScenario,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageExecutionNetworkPolicyV1 {
    NoPublicRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageDependencyPolicyV1 {
    OfflineExactDependencyFree,
    NoIndexNoDependencies,
    NoIndexFixedClosureOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzNpmLifecyclePolicyV1 {
    PackageManifestInstallHooksOnly,
}

/// Closed package-operation stages derived from a validated request.
///
/// These are semantic runner operations, not caller-supplied process specifications. The future
/// Linux runner owns the only mapping from these variants to measured executables and fixed argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosLinuxVzPackageExecutionStageV1 {
    NpmInstallExactLocalTarball {
        environment: NpmEnvironmentProfileV1,
        input_basename: String,
        dependency_policy: MacosLinuxVzPackageDependencyPolicyV1,
        lifecycle_policy: MacosLinuxVzNpmLifecyclePolicyV1,
    },
    PythonCreateFreshWheelVirtualEnvironment,
    PythonPipInstallExactWheel {
        input_basename: String,
        package_normalized_name: String,
        package_version: String,
        resolver_policy: MacosLinuxVzPackageDependencyPolicyV1,
    },
    PythonFreshInterpreterPthProbe {
        pth_file_ids: Vec<Sha256Digest>,
    },
    PythonImportRootProbe {
        module: String,
    },
    PythonConsoleEntryPointHelpProbe {
        command_name: String,
        module: String,
        callable: String,
        target_sha256: Sha256Digest,
    },
    PythonSafelyExtractExactSdist {
        input_basename: String,
        artifact_format: ArtifactFormat,
    },
    PythonCreateFreshSdistBuildVirtualEnvironment,
    PythonInstallExactSdistBuildClosure {
        build_requires_sha256: Sha256Digest,
        resolver_policy: MacosLinuxVzPackageDependencyPolicyV1,
    },
    PythonBuildExactSdist {
        build: MacosLinuxVzSdistBuildRecipeV1,
    },
    PythonValidateSingleDerivedWheel,
    PythonInspectDerivedWheelMetadata,
    PythonCreateFreshDerivedWheelInstallVirtualEnvironment,
    PythonPipInstallDerivedWheel {
        resolver_policy: MacosLinuxVzPackageDependencyPolicyV1,
    },
    PythonImportDerivedWheelRootProbe {
        module: String,
    },
}

impl MacosLinuxVzPackageExecutionStageV1 {
    pub const fn stage_name(&self) -> &'static str {
        match self {
            Self::NpmInstallExactLocalTarball { .. } => "npm_install_exact_local_tarball",
            Self::PythonCreateFreshWheelVirtualEnvironment => {
                "python_create_fresh_wheel_virtual_environment"
            }
            Self::PythonPipInstallExactWheel { .. } => "python_pip_install_exact_wheel",
            Self::PythonFreshInterpreterPthProbe { .. } => "python_fresh_interpreter_pth_probe",
            Self::PythonImportRootProbe { .. } => "python_import_root_probe",
            Self::PythonConsoleEntryPointHelpProbe { .. } => {
                "python_console_entry_point_help_probe"
            }
            Self::PythonSafelyExtractExactSdist { .. } => "python_safely_extract_exact_sdist",
            Self::PythonCreateFreshSdistBuildVirtualEnvironment => {
                "python_create_fresh_sdist_build_virtual_environment"
            }
            Self::PythonInstallExactSdistBuildClosure { .. } => {
                "python_install_exact_sdist_build_closure"
            }
            Self::PythonBuildExactSdist { .. } => "python_build_exact_sdist",
            Self::PythonValidateSingleDerivedWheel => "python_validate_single_derived_wheel",
            Self::PythonInspectDerivedWheelMetadata => "python_inspect_derived_wheel_metadata",
            Self::PythonCreateFreshDerivedWheelInstallVirtualEnvironment => {
                "python_create_fresh_derived_wheel_install_virtual_environment"
            }
            Self::PythonPipInstallDerivedWheel { .. } => "python_pip_install_derived_wheel",
            Self::PythonImportDerivedWheelRootProbe { .. } => {
                "python_import_derived_wheel_root_probe"
            }
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackageExecutionProgramWireV1<'a> {
    schema_version: &'static str,
    execution_request_sha256: &'a Sha256Digest,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: &'a Sha256Digest,
    scenario_template_sha256: &'a Sha256Digest,
    attempt_binding_sha256: &'a Sha256Digest,
    clone_binding_sha256: &'a Sha256Digest,
    operation: &'a str,
    input_materialization: MacosLinuxVzPackageExecutionInputMaterializationV1,
    workspace_policy: MacosLinuxVzPackageExecutionWorkspacePolicyV1,
    network_policy: MacosLinuxVzPackageExecutionNetworkPolicyV1,
    package_uid: String,
    package_gid: String,
    stages: &'a [MacosLinuxVzPackageExecutionStageV1],
    limits: &'a ArtifactScenarioLimitsV1,
    arbitrary_command_input_present: bool,
    execution_authority: bool,
    package_execution: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageExecutionProgramV1 {
    canonical_json: Vec<u8>,
    program_sha256: Sha256Digest,
    execution_request_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    operation: &'static str,
    stages: Vec<MacosLinuxVzPackageExecutionStageV1>,
    limits: ArtifactScenarioLimitsV1,
}

impl fmt::Debug for MacosLinuxVzPackageExecutionProgramV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionProgramV1")
            .field("program_sha256", &self.program_sha256)
            .field("execution_request_sha256", &self.execution_request_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("operation", &self.operation)
            .field("stage_count", &self.stages.len())
            .finish()
    }
}

impl MacosLinuxVzPackageExecutionProgramV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn program_sha256(&self) -> &Sha256Digest {
        &self.program_sha256
    }

    pub fn execution_request_sha256(&self) -> &Sha256Digest {
        &self.execution_request_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub const fn operation_name(&self) -> &'static str {
        self.operation
    }

    pub fn stages(&self) -> &[MacosLinuxVzPackageExecutionStageV1] {
        &self.stages
    }

    pub fn limits(&self) -> &ArtifactScenarioLimitsV1 {
        &self.limits
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzPackageExecutionProgramErrorV1 {
    InvalidOperation,
    LimitExceeded,
    Serialization,
}

impl MacosLinuxVzPackageExecutionProgramErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidOperation => "macos_linux_vz_execution_program_operation_invalid",
            Self::LimitExceeded => "macos_linux_vz_execution_program_limit_exceeded",
            Self::Serialization => "macos_linux_vz_execution_program_serialization_failed",
        }
    }
}

impl fmt::Display for MacosLinuxVzPackageExecutionProgramErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzPackageExecutionProgramErrorV1 {}

pub fn derive_macos_linux_vz_package_execution_program_v1(
    request: &StructurallyValidatedMacosLinuxVzPackageExecutionRequestV1,
) -> Result<MacosLinuxVzPackageExecutionProgramV1, MacosLinuxVzPackageExecutionProgramErrorV1> {
    if request.package_execution_authority_permitted() || request.sync_back_permitted() {
        return Err(MacosLinuxVzPackageExecutionProgramErrorV1::InvalidOperation);
    }
    let stages = stages_for_operation_v1(request.operation())?;
    if stages.is_empty() {
        return Err(MacosLinuxVzPackageExecutionProgramErrorV1::InvalidOperation);
    }
    let wire = PackageExecutionProgramWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROGRAM_SCHEMA_V1,
        execution_request_sha256: request.request_sha256(),
        artifact_kind: request.artifact_kind(),
        artifact_sha256: request.artifact_sha256(),
        scenario_template_sha256: request.scenario_template_sha256(),
        attempt_binding_sha256: request.attempt_binding_sha256(),
        clone_binding_sha256: request.clone_binding_sha256(),
        operation: request.operation().operation_name(),
        input_materialization:
            MacosLinuxVzPackageExecutionInputMaterializationV1::RootCreatedReadOnlyNamedFileFromRehashedDescriptor,
        workspace_policy:
            MacosLinuxVzPackageExecutionWorkspacePolicyV1::FreshUidGidOwnedTmpfsPerScenario,
        network_policy: MacosLinuxVzPackageExecutionNetworkPolicyV1::NoPublicRoute,
        package_uid: request.package_uid().to_string(),
        package_gid: request.package_gid().to_string(),
        stages: &stages,
        limits: request.limits(),
        arbitrary_command_input_present: false,
        execution_authority: false,
        package_execution: false,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageExecutionProgramErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROGRAM_BYTES_V1
    {
        return Err(MacosLinuxVzPackageExecutionProgramErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzPackageExecutionProgramV1 {
        program_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        execution_request_sha256: request.request_sha256().clone(),
        artifact_sha256: request.artifact_sha256().clone(),
        operation: request.operation().operation_name(),
        stages,
        limits: request.limits().clone(),
    })
}

fn stages_for_operation_v1(
    operation: &MacosLinuxVzPackageExecutionOperationV1,
) -> Result<Vec<MacosLinuxVzPackageExecutionStageV1>, MacosLinuxVzPackageExecutionProgramErrorV1> {
    let stages = match operation {
        MacosLinuxVzPackageExecutionOperationV1::NpmInstallExactLocalTarball { environment } => {
            vec![
                MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
                    environment: *environment,
                    input_basename: NPM_INPUT_BASENAME_V1.to_string(),
                    dependency_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::OfflineExactDependencyFree,
                    lifecycle_policy:
                        MacosLinuxVzNpmLifecyclePolicyV1::PackageManifestInstallHooksOnly,
                },
            ]
        }
        MacosLinuxVzPackageExecutionOperationV1::WheelInstallExact {
            artifact_filename,
            package_normalized_name,
            package_version,
            ..
        } => wheel_stages_v1(
            artifact_filename,
            package_normalized_name,
            package_version,
            None,
        ),
        MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenFreshInterpreterPth {
            artifact_filename,
            package_normalized_name,
            package_version,
            pth_file_ids,
            ..
        } => wheel_stages_v1(
            artifact_filename,
            package_normalized_name,
            package_version,
            Some(
                MacosLinuxVzPackageExecutionStageV1::PythonFreshInterpreterPthProbe {
                    pth_file_ids: pth_file_ids.clone(),
                },
            ),
        ),
        MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenImportRoot {
            artifact_filename,
            package_normalized_name,
            package_version,
            module,
            ..
        } => wheel_stages_v1(
            artifact_filename,
            package_normalized_name,
            package_version,
            Some(MacosLinuxVzPackageExecutionStageV1::PythonImportRootProbe {
                module: module.clone(),
            }),
        ),
        MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenConsoleEntryPointHelp {
            artifact_filename,
            package_normalized_name,
            package_version,
            command_name,
            module,
            callable,
            target_sha256,
            ..
        } => wheel_stages_v1(
            artifact_filename,
            package_normalized_name,
            package_version,
            Some(
                MacosLinuxVzPackageExecutionStageV1::PythonConsoleEntryPointHelpProbe {
                    command_name: command_name.clone(),
                    module: module.clone(),
                    callable: callable.clone(),
                    target_sha256: target_sha256.clone(),
                },
            ),
        ),
        MacosLinuxVzPackageExecutionOperationV1::SdistBuildExact { build } => {
            sdist_stages_v1(build, SdistContinuationV1::BuildOnly)?
        }
        MacosLinuxVzPackageExecutionOperationV1::SdistBuildThenInspectDerivedWheel { build } => {
            sdist_stages_v1(build, SdistContinuationV1::Inspect)?
        }
        MacosLinuxVzPackageExecutionOperationV1::SdistBuildThenInstallDerivedWheel { build } => {
            sdist_stages_v1(build, SdistContinuationV1::Install)?
        }
        MacosLinuxVzPackageExecutionOperationV1::SdistBuildInstallThenImportRoot {
            build,
            module,
        } => sdist_stages_v1(build, SdistContinuationV1::Import(module))?,
    };
    Ok(stages)
}

fn wheel_stages_v1(
    artifact_filename: &str,
    package_normalized_name: &str,
    package_version: &str,
    probe: Option<MacosLinuxVzPackageExecutionStageV1>,
) -> Vec<MacosLinuxVzPackageExecutionStageV1> {
    let mut stages = vec![
        MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshWheelVirtualEnvironment,
        MacosLinuxVzPackageExecutionStageV1::PythonPipInstallExactWheel {
            input_basename: artifact_filename.to_string(),
            package_normalized_name: package_normalized_name.to_string(),
            package_version: package_version.to_string(),
            resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexNoDependencies,
        },
    ];
    stages.extend(probe);
    stages
}

enum SdistContinuationV1<'a> {
    BuildOnly,
    Inspect,
    Install,
    Import(&'a str),
}

fn sdist_stages_v1(
    build: &MacosLinuxVzSdistBuildRecipeV1,
    continuation: SdistContinuationV1<'_>,
) -> Result<Vec<MacosLinuxVzPackageExecutionStageV1>, MacosLinuxVzPackageExecutionProgramErrorV1> {
    let input_basename = match build.artifact_format() {
        ArtifactFormat::SdistTarGzip => SDIST_TAR_GZIP_INPUT_BASENAME_V1,
        ArtifactFormat::SdistZip => SDIST_ZIP_INPUT_BASENAME_V1,
        _ => return Err(MacosLinuxVzPackageExecutionProgramErrorV1::InvalidOperation),
    };
    let mut stages = vec![
        MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
            input_basename: input_basename.to_string(),
            artifact_format: build.artifact_format(),
        },
        MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshSdistBuildVirtualEnvironment,
        MacosLinuxVzPackageExecutionStageV1::PythonInstallExactSdistBuildClosure {
            build_requires_sha256: build.build_requires_sha256().clone(),
            resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexFixedClosureOnly,
        },
        MacosLinuxVzPackageExecutionStageV1::PythonBuildExactSdist {
            build: build.clone(),
        },
        MacosLinuxVzPackageExecutionStageV1::PythonValidateSingleDerivedWheel,
    ];
    match continuation {
        SdistContinuationV1::BuildOnly => {}
        SdistContinuationV1::Inspect => {
            stages.push(MacosLinuxVzPackageExecutionStageV1::PythonInspectDerivedWheelMetadata);
        }
        SdistContinuationV1::Install | SdistContinuationV1::Import(_) => {
            stages.extend([
                MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshDerivedWheelInstallVirtualEnvironment,
                MacosLinuxVzPackageExecutionStageV1::PythonPipInstallDerivedWheel {
                    resolver_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::NoIndexNoDependencies,
                },
            ]);
            if let SdistContinuationV1::Import(module) = continuation {
                stages.push(
                    MacosLinuxVzPackageExecutionStageV1::PythonImportDerivedWheelRootProbe {
                        module: module.to_string(),
                    },
                );
            }
        }
    }
    Ok(stages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use whoathere_detonation::SdistBuildModeV1;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn sdist_build(format: ArtifactFormat) -> MacosLinuxVzSdistBuildRecipeV1 {
        MacosLinuxVzSdistBuildRecipeV1::new_for_execution_program_test_v1(
            digest("build template"),
            format,
            SdistBuildModeV1::Pep517,
            Some("setuptools.build_meta".to_string()),
            Vec::new(),
            digest("build closure"),
        )
    }

    #[test]
    fn npm_and_wheel_programs_have_only_closed_prerequisite_order() {
        let npm = stages_for_operation_v1(
            &MacosLinuxVzPackageExecutionOperationV1::NpmInstallExactLocalTarball {
                environment: NpmEnvironmentProfileV1::CiTrue,
            },
        )
        .expect("npm stages");
        assert_eq!(npm.len(), 1);
        assert_eq!(npm[0].stage_name(), "npm_install_exact_local_tarball");

        let wheel = stages_for_operation_v1(
            &MacosLinuxVzPackageExecutionOperationV1::WheelInstallThenImportRoot {
                install_template_sha256: digest("wheel install"),
                artifact_filename: "fixture_pkg-1.0.0-py3-none-any.whl".to_string(),
                package_normalized_name: "fixture-pkg".to_string(),
                package_version: "1.0.0".to_string(),
                module: "fixture_pkg".to_string(),
            },
        )
        .expect("wheel stages");
        assert_eq!(
            wheel
                .iter()
                .map(|stage| stage.stage_name())
                .collect::<Vec<_>>(),
            [
                "python_create_fresh_wheel_virtual_environment",
                "python_pip_install_exact_wheel",
                "python_import_root_probe",
            ]
        );
    }

    #[test]
    fn sdist_program_always_builds_and_validates_before_inspect_install_or_import() {
        let build = sdist_build(ArtifactFormat::SdistTarGzip);
        let stages = stages_for_operation_v1(
            &MacosLinuxVzPackageExecutionOperationV1::SdistBuildInstallThenImportRoot {
                build,
                module: "fixture_pkg".to_string(),
            },
        )
        .expect("sdist stages");
        assert_eq!(
            stages
                .iter()
                .map(|stage| stage.stage_name())
                .collect::<Vec<_>>(),
            [
                "python_safely_extract_exact_sdist",
                "python_create_fresh_sdist_build_virtual_environment",
                "python_install_exact_sdist_build_closure",
                "python_build_exact_sdist",
                "python_validate_single_derived_wheel",
                "python_create_fresh_derived_wheel_install_virtual_environment",
                "python_pip_install_derived_wheel",
                "python_import_derived_wheel_root_probe",
            ]
        );
    }

    #[test]
    fn unsupported_sdist_archive_form_fails_closed() {
        let build = sdist_build(ArtifactFormat::WheelZip);
        assert_eq!(
            stages_for_operation_v1(&MacosLinuxVzPackageExecutionOperationV1::SdistBuildExact {
                build
            }),
            Err(MacosLinuxVzPackageExecutionProgramErrorV1::InvalidOperation)
        );
    }
}
