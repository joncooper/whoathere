use crate::{
    MacosLinuxVzPackageExecutionProgramV1, MacosLinuxVzPackageExecutionStageV1,
    MacosLinuxVzPackageRuntimeExecutablesV1, MacosLinuxVzSdistBuildRecipeV1,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt;
use whoathere_artifact::{ArtifactFormat, Sha256Digest};
use whoathere_detonation::{NpmEnvironmentProfileV1, SdistBuildModeV1};

pub const MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROCESS_PLAN_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_execution_process_plan.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROCESS_PLAN_BYTES_V1: usize = 256 * 1024;

const NODE_PATH: &str = "/usr/bin/node";
const NPM_CLI_PATH: &str = "/usr/lib/node_modules/npm/bin/npm-cli.js";
const PYTHON_PATH: &str = "/usr/bin/python3.14";
const PIP_CLI_PATH: &str = "/usr/bin/pip3";
const RUN_ROOT: &str = "/run/whoathere";
const NPM_WORK: &str = "/run/whoathere/work/npm";
const WHEEL_VENV: &str = "/run/whoathere/work/wheel-venv";
const SDIST_BUILD_VENV: &str = "/run/whoathere/work/sdist-build-venv";
const SDIST_INSTALL_VENV: &str = "/run/whoathere/work/sdist-install-venv";
const SDIST_SOURCE: &str = "/run/whoathere/source";
const SDIST_DERIVED: &str = "/run/whoathere/derived";

const PYTHON_IMPORT_PROBE: &str = "import importlib,sys;importlib.import_module(sys.argv[1])";
const PYTHON_PTH_PROBE: &str = "pass";
const PYTHON_PEP517_BUILD: &str = "import functools,importlib,sys;backend,out,*paths=sys.argv[1:];sys.path[:0]=paths;module,sep,obj=backend.partition(':');target=importlib.import_module(module);target=functools.reduce(getattr,obj.split('.'),target) if sep else target;name=target.build_wheel(out,config_settings=None,metadata_directory=None);print(name)";
const PYTHON_LEGACY_BUILD: &str = "import runpy,sys;sys.path.insert(0,'/run/whoathere/source');sys.argv=['setup.py','bdist_wheel','--dist-dir','/run/whoathere/derived'];runpy.run_path('/run/whoathere/source/setup.py',run_name='__main__')";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageProcessStdioPolicyV1 {
    NullStdinBoundedCapturedOutput,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageProcessEnvironmentPolicyV1 {
    ClearThenExactMap,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosLinuxVzPackageProcessExecutableV1 {
    PinnedRuntimeFile {
        absolute_path: String,
        expected_sha256: Sha256Digest,
    },
    FreshVirtualEnvironmentPythonCopy {
        absolute_path: String,
        source_python_sha256: Sha256Digest,
    },
    ValidatedDerivedConsoleEntryPoint {
        absolute_path: String,
        validated_target_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosLinuxVzPackageProcessArgumentV1 {
    Literal { value: String },
    ValidatedDerivedWheelPath,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageMeasuredProcessInputRoleV1 {
    NpmCli,
    PipCli,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosLinuxVzPackageMeasuredProcessInputV1 {
    role: MacosLinuxVzPackageMeasuredProcessInputRoleV1,
    absolute_path: String,
    expected_sha256: Sha256Digest,
}

impl MacosLinuxVzPackageMeasuredProcessInputV1 {
    pub fn role(&self) -> MacosLinuxVzPackageMeasuredProcessInputRoleV1 {
        self.role
    }

    pub fn absolute_path(&self) -> &str {
        &self.absolute_path
    }

    pub fn expected_sha256(&self) -> &Sha256Digest {
        &self.expected_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MacosLinuxVzPackageFixedProcessV1 {
    stage_name: String,
    executable: MacosLinuxVzPackageProcessExecutableV1,
    /// Fixed values passed after `argv[0]`; the launcher supplies the verified executable as
    /// `argv[0]` and must not prepend or append caller-controlled values.
    arguments: Vec<MacosLinuxVzPackageProcessArgumentV1>,
    environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1,
    environment: BTreeMap<String, String>,
    current_directory: String,
    measured_inputs: Vec<MacosLinuxVzPackageMeasuredProcessInputV1>,
    stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1,
}

impl MacosLinuxVzPackageFixedProcessV1 {
    pub fn stage_name(&self) -> &str {
        &self.stage_name
    }

    pub fn executable(&self) -> &MacosLinuxVzPackageProcessExecutableV1 {
        &self.executable
    }

    pub fn arguments(&self) -> &[MacosLinuxVzPackageProcessArgumentV1] {
        &self.arguments
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    pub fn current_directory(&self) -> &str {
        &self.current_directory
    }

    pub fn measured_inputs(&self) -> &[MacosLinuxVzPackageMeasuredProcessInputV1] {
        &self.measured_inputs
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosLinuxVzPackageInternalActionV1 {
    MaterializeExactArtifact {
        input_basename: String,
    },
    SafelyExtractExactSdist {
        input_basename: String,
        artifact_format: ArtifactFormat,
        expected_archive_root: String,
        destination: String,
    },
    ValidateExactBuildClosure {
        build_requires_sha256: Sha256Digest,
        build_closure: whoathere_detonation::SdistBuildClosureV1,
    },
    ValidateSingleDerivedWheel,
    InspectDerivedWheelMetadata,
    ValidateDerivedConsoleEntryPoint {
        absolute_path: String,
        module: String,
        callable: String,
        target_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MacosLinuxVzPackageExecutionActionV1 {
    Internal {
        action: MacosLinuxVzPackageInternalActionV1,
    },
    Process {
        process: MacosLinuxVzPackageFixedProcessV1,
    },
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackageExecutionProcessPlanWireV1<'a> {
    schema_version: &'static str,
    execution_program_sha256: &'a Sha256Digest,
    execution_request_sha256: &'a Sha256Digest,
    artifact_sha256: &'a Sha256Digest,
    artifact_byte_length: String,
    operation: &'a str,
    actions: &'a [MacosLinuxVzPackageExecutionActionV1],
    caller_process_input_present: bool,
    environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1,
    stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1,
    public_network_route_present: bool,
    execution_authority: bool,
    package_execution: bool,
    sync_back: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageExecutionProcessPlanV1 {
    canonical_json: Vec<u8>,
    process_plan_sha256: Sha256Digest,
    execution_program_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    actions: Vec<MacosLinuxVzPackageExecutionActionV1>,
}

impl fmt::Debug for MacosLinuxVzPackageExecutionProcessPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionProcessPlanV1")
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("execution_program_sha256", &self.execution_program_sha256)
            .field("action_count", &self.actions.len())
            .finish()
    }
}

impl MacosLinuxVzPackageExecutionProcessPlanV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn execution_program_sha256(&self) -> &Sha256Digest {
        &self.execution_program_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn actions(&self) -> &[MacosLinuxVzPackageExecutionActionV1] {
        &self.actions
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzPackageExecutionProcessPlanErrorV1 {
    RuntimeMismatch,
    InvalidStage,
    InvalidDerivedPath,
    LimitExceeded,
    Serialization,
}

impl MacosLinuxVzPackageExecutionProcessPlanErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::RuntimeMismatch => "macos_linux_vz_process_plan_runtime_mismatch",
            Self::InvalidStage => "macos_linux_vz_process_plan_stage_invalid",
            Self::InvalidDerivedPath => "macos_linux_vz_process_plan_derived_path_invalid",
            Self::LimitExceeded => "macos_linux_vz_process_plan_limit_exceeded",
            Self::Serialization => "macos_linux_vz_process_plan_serialization_failed",
        }
    }
}

impl fmt::Display for MacosLinuxVzPackageExecutionProcessPlanErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzPackageExecutionProcessPlanErrorV1 {}

pub fn derive_macos_linux_vz_package_execution_process_plan_v1(
    program: &MacosLinuxVzPackageExecutionProgramV1,
) -> Result<MacosLinuxVzPackageExecutionProcessPlanV1, MacosLinuxVzPackageExecutionProcessPlanErrorV1>
{
    if program.package_execution_authority_permitted() || program.sync_back_permitted() {
        return Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidStage);
    }
    let input_basename = program
        .stages()
        .iter()
        .find_map(input_basename_v1)
        .ok_or(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidStage)?;
    let mut actions = vec![MacosLinuxVzPackageExecutionActionV1::Internal {
        action: MacosLinuxVzPackageInternalActionV1::MaterializeExactArtifact { input_basename },
    }];
    for stage in program.stages() {
        let mut derived = actions_for_stage_v1(stage, program.runtime_executables())?;
        actions.append(&mut derived);
    }
    if actions.is_empty() {
        return Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidStage);
    }
    let wire = PackageExecutionProcessPlanWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROCESS_PLAN_SCHEMA_V1,
        execution_program_sha256: program.program_sha256(),
        execution_request_sha256: program.execution_request_sha256(),
        artifact_sha256: program.artifact_sha256(),
        artifact_byte_length: program.artifact_byte_length().to_string(),
        operation: program.operation_name(),
        actions: &actions,
        caller_process_input_present: false,
        environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1::ClearThenExactMap,
        stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1::NullStdinBoundedCapturedOutput,
        public_network_route_present: false,
        execution_authority: false,
        package_execution: false,
        sync_back: false,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageExecutionProcessPlanErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_PROCESS_PLAN_BYTES_V1
    {
        return Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzPackageExecutionProcessPlanV1 {
        process_plan_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        execution_program_sha256: program.program_sha256().clone(),
        artifact_sha256: program.artifact_sha256().clone(),
        artifact_byte_length: program.artifact_byte_length(),
        actions,
    })
}

fn input_basename_v1(stage: &MacosLinuxVzPackageExecutionStageV1) -> Option<String> {
    match stage {
        MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
            input_basename, ..
        }
        | MacosLinuxVzPackageExecutionStageV1::PythonPipInstallExactWheel {
            input_basename, ..
        }
        | MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
            input_basename,
            ..
        } => Some(input_basename.clone()),
        _ => None,
    }
}

fn actions_for_stage_v1(
    stage: &MacosLinuxVzPackageExecutionStageV1,
    runtime: &MacosLinuxVzPackageRuntimeExecutablesV1,
) -> Result<Vec<MacosLinuxVzPackageExecutionActionV1>, MacosLinuxVzPackageExecutionProcessPlanErrorV1>
{
    let actions = match stage {
        MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
            environment,
            input_basename,
            ..
        } => vec![process_action(npm_install_process(
            runtime,
            *environment,
            input_basename,
        )?)],
        MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshWheelVirtualEnvironment => {
            vec![process_action(create_venv_process(
                runtime,
                WHEEL_VENV,
                "python_create_fresh_wheel_virtual_environment",
            )?)]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonPipInstallExactWheel {
            input_basename, ..
        } => vec![process_action(pip_install_process(
            runtime,
            WHEEL_VENV,
            vec![literal(format!("{RUN_ROOT}/input/{input_basename}"))],
            "python_pip_install_exact_wheel",
        )?)],
        MacosLinuxVzPackageExecutionStageV1::PythonFreshInterpreterPthProbe { .. } => {
            vec![process_action(venv_python_process(
                runtime,
                WHEEL_VENV,
                "python_fresh_interpreter_pth_probe",
                vec![literal("-I"), literal("-c"), literal(PYTHON_PTH_PROBE)],
                RUN_ROOT,
            )?)]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonImportRootProbe { module } => {
            vec![process_action(venv_python_process(
                runtime,
                WHEEL_VENV,
                "python_import_root_probe",
                vec![
                    literal("-I"),
                    literal("-c"),
                    literal(PYTHON_IMPORT_PROBE),
                    literal(module),
                ],
                RUN_ROOT,
            )?)]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonConsoleEntryPointHelpProbe {
            command_name,
            module,
            callable,
            target_sha256,
            ..
        } => {
            let path = validated_console_path_v1(command_name)?;
            vec![
                MacosLinuxVzPackageExecutionActionV1::Internal {
                    action:
                        MacosLinuxVzPackageInternalActionV1::ValidateDerivedConsoleEntryPoint {
                            absolute_path: path.clone(),
                            module: module.clone(),
                            callable: callable.clone(),
                            target_sha256: target_sha256.clone(),
                        },
                },
                process_action(console_process(path, target_sha256)),
            ]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
            input_basename,
            artifact_format,
            expected_archive_root,
        } => vec![MacosLinuxVzPackageExecutionActionV1::Internal {
            action: MacosLinuxVzPackageInternalActionV1::SafelyExtractExactSdist {
                input_basename: input_basename.clone(),
                artifact_format: *artifact_format,
                expected_archive_root: expected_archive_root.clone(),
                destination: SDIST_SOURCE.to_string(),
            },
        }],
        MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshSdistBuildVirtualEnvironment => {
            vec![process_action(create_venv_process(
                runtime,
                SDIST_BUILD_VENV,
                "python_create_fresh_sdist_build_virtual_environment",
            )?)]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonInstallExactSdistBuildClosure {
            build_requires_sha256,
            build_closure,
            ..
        } => {
            if build_closure.validate().is_err()
                || build_requires_sha256 != build_closure.declaration_set_sha256()
                || build_closure.artifacts().is_empty()
            {
                return Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidStage);
            }
            let mut wheel_arguments = Vec::with_capacity(build_closure.artifacts().len());
            for artifact in build_closure.artifacts() {
                wheel_arguments.push(literal(format!(
                    "{RUN_ROOT}/closure/{}",
                    artifact.artifact_filename()
                )));
            }
            vec![
                MacosLinuxVzPackageExecutionActionV1::Internal {
                    action: MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                        build_requires_sha256: build_requires_sha256.clone(),
                        build_closure: build_closure.clone(),
                    },
                },
                process_action(pip_install_process(
                    runtime,
                    SDIST_BUILD_VENV,
                    wheel_arguments,
                    "python_install_exact_sdist_build_closure",
                )?),
            ]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonBuildExactSdist { build } => {
            vec![process_action(sdist_build_process(runtime, build)?)]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonValidateSingleDerivedWheel => {
            vec![MacosLinuxVzPackageExecutionActionV1::Internal {
                action: MacosLinuxVzPackageInternalActionV1::ValidateSingleDerivedWheel,
            }]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonInspectDerivedWheelMetadata => {
            vec![MacosLinuxVzPackageExecutionActionV1::Internal {
                action: MacosLinuxVzPackageInternalActionV1::InspectDerivedWheelMetadata,
            }]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshDerivedWheelInstallVirtualEnvironment => {
            vec![process_action(create_venv_process(
                runtime,
                SDIST_INSTALL_VENV,
                "python_create_fresh_derived_wheel_install_virtual_environment",
            )?)]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonPipInstallDerivedWheel { .. } => {
            vec![process_action(pip_install_process(
                runtime,
                SDIST_INSTALL_VENV,
                vec![MacosLinuxVzPackageProcessArgumentV1::ValidatedDerivedWheelPath],
                "python_pip_install_derived_wheel",
            )?)]
        }
        MacosLinuxVzPackageExecutionStageV1::PythonImportDerivedWheelRootProbe { module } => {
            vec![process_action(venv_python_process(
                runtime,
                SDIST_INSTALL_VENV,
                "python_import_derived_wheel_root_probe",
                vec![
                    literal("-I"),
                    literal("-c"),
                    literal(PYTHON_IMPORT_PROBE),
                    literal(module),
                ],
                RUN_ROOT,
            )?)]
        }
    };
    Ok(actions)
}

fn process_action(
    process: MacosLinuxVzPackageFixedProcessV1,
) -> MacosLinuxVzPackageExecutionActionV1 {
    MacosLinuxVzPackageExecutionActionV1::Process { process }
}

fn literal(value: impl Into<String>) -> MacosLinuxVzPackageProcessArgumentV1 {
    MacosLinuxVzPackageProcessArgumentV1::Literal {
        value: value.into(),
    }
}

fn common_environment() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("HOME".to_string(), format!("{RUN_ROOT}/home")),
        ("LANG".to_string(), "C".to_string()),
        ("LC_ALL".to_string(), "C".to_string()),
        ("PATH".to_string(), "/usr/bin:/bin".to_string()),
        ("TMPDIR".to_string(), format!("{RUN_ROOT}/tmp")),
    ])
}

fn python_environment() -> BTreeMap<String, String> {
    let mut environment = common_environment();
    environment.extend([
        ("PIP_DISABLE_PIP_VERSION_CHECK".to_string(), "1".to_string()),
        ("PIP_NO_INDEX".to_string(), "1".to_string()),
        ("PIP_NO_INPUT".to_string(), "1".to_string()),
        ("PYTHONDONTWRITEBYTECODE".to_string(), "1".to_string()),
        ("PYTHONNOUSERSITE".to_string(), "1".to_string()),
    ]);
    environment
}

fn npm_install_process(
    runtime: &MacosLinuxVzPackageRuntimeExecutablesV1,
    profile: NpmEnvironmentProfileV1,
    input_basename: &str,
) -> Result<MacosLinuxVzPackageFixedProcessV1, MacosLinuxVzPackageExecutionProcessPlanErrorV1> {
    let MacosLinuxVzPackageRuntimeExecutablesV1::NodeNpm {
        node_executable_sha256,
        npm_cli_sha256,
        ..
    } = runtime
    else {
        return Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::RuntimeMismatch);
    };
    let mut environment = common_environment();
    environment.extend([
        ("npm_config_audit".to_string(), "false".to_string()),
        ("npm_config_fund".to_string(), "false".to_string()),
        ("npm_config_offline".to_string(), "true".to_string()),
        ("npm_config_progress".to_string(), "false".to_string()),
        (
            "npm_config_update_notifier".to_string(),
            "false".to_string(),
        ),
    ]);
    if profile == NpmEnvironmentProfileV1::CiTrue {
        environment.insert("CI".to_string(), "true".to_string());
    }
    Ok(MacosLinuxVzPackageFixedProcessV1 {
        stage_name: "npm_install_exact_local_tarball".to_string(),
        executable: MacosLinuxVzPackageProcessExecutableV1::PinnedRuntimeFile {
            absolute_path: NODE_PATH.to_string(),
            expected_sha256: node_executable_sha256.clone(),
        },
        arguments: [
            NPM_CLI_PATH,
            "install",
            "--offline",
            "--no-audit",
            "--no-fund",
            "--no-update-notifier",
            "--foreground-scripts",
            "--ignore-scripts=false",
            "--package-lock=false",
            "--cache=/run/whoathere/cache/npm",
            "--prefix=/run/whoathere/work/npm",
            "--script-shell=/bin/sh",
        ]
        .into_iter()
        .map(literal)
        .chain([literal(format!("{RUN_ROOT}/input/{input_basename}"))])
        .collect(),
        environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1::ClearThenExactMap,
        environment,
        current_directory: NPM_WORK.to_string(),
        measured_inputs: vec![MacosLinuxVzPackageMeasuredProcessInputV1 {
            role: MacosLinuxVzPackageMeasuredProcessInputRoleV1::NpmCli,
            absolute_path: NPM_CLI_PATH.to_string(),
            expected_sha256: npm_cli_sha256.clone(),
        }],
        stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1::NullStdinBoundedCapturedOutput,
    })
}

fn python_runtime(
    runtime: &MacosLinuxVzPackageRuntimeExecutablesV1,
) -> Result<(&Sha256Digest, &Sha256Digest), MacosLinuxVzPackageExecutionProcessPlanErrorV1> {
    match runtime {
        MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
            python_executable_sha256,
            pip_cli_sha256,
            ..
        } => Ok((python_executable_sha256, pip_cli_sha256)),
        _ => Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::RuntimeMismatch),
    }
}

fn create_venv_process(
    runtime: &MacosLinuxVzPackageRuntimeExecutablesV1,
    venv: &str,
    stage_name: &str,
) -> Result<MacosLinuxVzPackageFixedProcessV1, MacosLinuxVzPackageExecutionProcessPlanErrorV1> {
    let (python_sha256, _) = python_runtime(runtime)?;
    Ok(MacosLinuxVzPackageFixedProcessV1 {
        stage_name: stage_name.to_string(),
        executable: MacosLinuxVzPackageProcessExecutableV1::PinnedRuntimeFile {
            absolute_path: PYTHON_PATH.to_string(),
            expected_sha256: python_sha256.clone(),
        },
        arguments: ["-I", "-m", "venv", "--without-pip", "--copies", venv]
            .into_iter()
            .map(literal)
            .collect(),
        environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1::ClearThenExactMap,
        environment: python_environment(),
        current_directory: RUN_ROOT.to_string(),
        measured_inputs: Vec::new(),
        stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1::NullStdinBoundedCapturedOutput,
    })
}

fn pip_install_process(
    runtime: &MacosLinuxVzPackageRuntimeExecutablesV1,
    venv: &str,
    packages: Vec<MacosLinuxVzPackageProcessArgumentV1>,
    stage_name: &str,
) -> Result<MacosLinuxVzPackageFixedProcessV1, MacosLinuxVzPackageExecutionProcessPlanErrorV1> {
    if packages.is_empty() {
        return Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidStage);
    }
    let (python_sha256, pip_sha256) = python_runtime(runtime)?;
    let mut arguments = [
        "-I",
        PIP_CLI_PATH,
        "--python",
        venv,
        "install",
        "--no-index",
        "--no-deps",
        "--disable-pip-version-check",
        "--no-input",
        "--no-compile",
    ]
    .into_iter()
    .map(literal)
    .collect::<Vec<_>>();
    arguments.extend(packages);
    Ok(MacosLinuxVzPackageFixedProcessV1 {
        stage_name: stage_name.to_string(),
        executable: MacosLinuxVzPackageProcessExecutableV1::PinnedRuntimeFile {
            absolute_path: PYTHON_PATH.to_string(),
            expected_sha256: python_sha256.clone(),
        },
        arguments,
        environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1::ClearThenExactMap,
        environment: python_environment(),
        current_directory: RUN_ROOT.to_string(),
        measured_inputs: vec![MacosLinuxVzPackageMeasuredProcessInputV1 {
            role: MacosLinuxVzPackageMeasuredProcessInputRoleV1::PipCli,
            absolute_path: PIP_CLI_PATH.to_string(),
            expected_sha256: pip_sha256.clone(),
        }],
        stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1::NullStdinBoundedCapturedOutput,
    })
}

fn venv_python_process(
    runtime: &MacosLinuxVzPackageRuntimeExecutablesV1,
    venv: &str,
    stage_name: &str,
    arguments: Vec<MacosLinuxVzPackageProcessArgumentV1>,
    current_directory: &str,
) -> Result<MacosLinuxVzPackageFixedProcessV1, MacosLinuxVzPackageExecutionProcessPlanErrorV1> {
    let (python_sha256, _) = python_runtime(runtime)?;
    let absolute_path = format!("{venv}/bin/python3");
    Ok(MacosLinuxVzPackageFixedProcessV1 {
        stage_name: stage_name.to_string(),
        executable: MacosLinuxVzPackageProcessExecutableV1::FreshVirtualEnvironmentPythonCopy {
            absolute_path,
            source_python_sha256: python_sha256.clone(),
        },
        arguments,
        environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1::ClearThenExactMap,
        environment: python_environment(),
        current_directory: current_directory.to_string(),
        measured_inputs: Vec::new(),
        stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1::NullStdinBoundedCapturedOutput,
    })
}

fn validated_console_path_v1(
    command_name: &str,
) -> Result<String, MacosLinuxVzPackageExecutionProcessPlanErrorV1> {
    if command_name.is_empty()
        || command_name.starts_with('-')
        || !command_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidDerivedPath);
    }
    Ok(format!("{WHEEL_VENV}/bin/{command_name}"))
}

fn console_process(
    path: String,
    target_sha256: &Sha256Digest,
) -> MacosLinuxVzPackageFixedProcessV1 {
    MacosLinuxVzPackageFixedProcessV1 {
        stage_name: "python_console_entry_point_help_probe".to_string(),
        executable: MacosLinuxVzPackageProcessExecutableV1::ValidatedDerivedConsoleEntryPoint {
            absolute_path: path.clone(),
            validated_target_sha256: target_sha256.clone(),
        },
        arguments: vec![literal("--help")],
        environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1::ClearThenExactMap,
        environment: python_environment(),
        current_directory: RUN_ROOT.to_string(),
        measured_inputs: Vec::new(),
        stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1::NullStdinBoundedCapturedOutput,
    }
}

fn sdist_build_process(
    runtime: &MacosLinuxVzPackageRuntimeExecutablesV1,
    build: &MacosLinuxVzSdistBuildRecipeV1,
) -> Result<MacosLinuxVzPackageFixedProcessV1, MacosLinuxVzPackageExecutionProcessPlanErrorV1> {
    let arguments = match build.build_mode() {
        SdistBuildModeV1::Pep517 => {
            let backend = build
                .build_backend()
                .ok_or(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidStage)?;
            let mut arguments = vec![
                literal("-I"),
                literal("-c"),
                literal(PYTHON_PEP517_BUILD),
                literal(backend),
                literal(SDIST_DERIVED),
            ];
            for path in build.backend_paths() {
                arguments.push(literal(format!("{SDIST_SOURCE}/{path}")));
            }
            arguments
        }
        SdistBuildModeV1::LegacySetupPy => {
            vec![literal("-I"), literal("-c"), literal(PYTHON_LEGACY_BUILD)]
        }
    };
    venv_python_process(
        runtime,
        SDIST_BUILD_VENV,
        "python_build_exact_sdist",
        arguments,
        SDIST_SOURCE,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_macos_linux_vz_package_execution_program_v1,
        linux_vz_package_authority_request::test_macos_linux_vz_package_authority_request_from_scenario_v1,
        linux_vz_package_execution_grant::test_macos_linux_vz_package_execution_grant_observation_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        MacosLinuxVzPackageArtifactKindV1, MacosLinuxVzPackageDependencyPolicyV1,
        MacosLinuxVzPackageExecutionRequestAuthorizerV1,
    };
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
        SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
    };
    use whoathere_evidence::v2::{
        canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2,
    };

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn python_runtime() -> MacosLinuxVzPackageRuntimeExecutablesV1 {
        MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
            python_version: "3.14.0".to_string(),
            python_executable_sha256: digest("python executable"),
            pip_version: "25.2".to_string(),
            pip_cli_sha256: digest("pip cli"),
        }
    }

    fn process_at(
        plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
        index: usize,
    ) -> &MacosLinuxVzPackageFixedProcessV1 {
        match &plan.actions()[index] {
            MacosLinuxVzPackageExecutionActionV1::Process { process } => process,
            other => panic!("expected process action at {index}, got {other:?}"),
        }
    }

    fn literal_arguments(process: &MacosLinuxVzPackageFixedProcessV1) -> Vec<&str> {
        process
            .arguments()
            .iter()
            .filter_map(|argument| match argument {
                MacosLinuxVzPackageProcessArgumentV1::Literal { value } => Some(value.as_str()),
                MacosLinuxVzPackageProcessArgumentV1::ValidatedDerivedWheelPath => None,
            })
            .collect()
    }

    fn inert_npm_program(
        environment: NpmEnvironmentProfileV1,
    ) -> MacosLinuxVzPackageExecutionProgramV1 {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        let package_json = br#"{"name":"process-plan-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#;
        for (path, bytes) in [
            ("package/package.json", package_json.as_slice()),
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
                .expect("append fixture");
        }
        let artifact_bytes = archive.into_inner().expect("tar").finish().expect("gzip");
        let envelope = ArtifactEnvelope::from_original_bytes(
            ArtifactEnvelopeInput {
                ecosystem: Ecosystem::Npm,
                package_name: Some("process-plan-fixture".to_string()),
                package_version: Some("1.0.0".to_string()),
                source_coordinate: "fixture:process-plan-fixture@1.0.0".to_string(),
                source_type: ArtifactSourceType::LocalFile,
                acquired_at: "2026-07-13T00:00:00Z".to_string(),
                acquisition_method: AcquisitionMethod::LocalInertFixture,
                original_filename: "process-plan-fixture-1.0.0.tgz".to_string(),
                declared_format: Some(ArtifactFormat::NpmTarGzip),
                custody_reference: "repository-inert-process-plan-fixture".to_string(),
                resolver_metadata_sha256: None,
                registry_metadata_sha256: None,
                policy_version: "linux-vz-process-plan.v1".to_string(),
                requires_external_dependency_resolution: false,
            },
            &artifact_bytes,
            ArtifactFormat::NpmTarGzip,
        );
        let normalized =
            normalize_artifact(&envelope, &artifact_bytes, NormalizationLimits::default())
                .expect("normalize fixture");
        let subject = ArtifactEvidenceSubjectV2::new(
            normalized.manifest.artifact_sha256.as_str(),
            envelope.envelope_sha256().expect("envelope").as_str(),
            normalized.manifest.manifest_sha256.as_str(),
            canonical_cas_object_key_for_artifact(normalized.manifest.artifact_sha256.as_str())
                .expect("CAS key"),
        )
        .expect("subject");
        let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
            envelope.original_sha256.clone(),
            NpmRuntimeProfileV1::new_for_target(
                ArtifactRuntimeTargetV1::LinuxArm64,
                "linux-arm64-node24-npm11-inert",
                "24.17.0",
                digest("node executable"),
                "11.12.1",
                digest("npm cli"),
            )
            .expect("runtime"),
        )
        .expect("policy");
        let identities = ArtifactScenarioIdentitySetV1::new(
            "process-plan",
            ArtifactScenarioExecutionIdentityV1::new(
                "process-plan-job-false",
                "process-plan-run-false",
                "process-plan-evidence-false",
                "process-plan-scenario-false",
            )
            .expect("false identity"),
            ArtifactScenarioExecutionIdentityV1::new(
                "process-plan-job-true",
                "process-plan-run-true",
                "process-plan-evidence-true",
                "process-plan-scenario-true",
            )
            .expect("true identity"),
        )
        .expect("identities");
        let scenario_plan = compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
            envelope: &envelope,
            manifest: &normalized.manifest,
            subject: &subject,
            policy: &policy,
            identities: &identities,
        })
        .expect("scenario plan");
        let scenario_plan_bytes = scenario_plan.canonical_json_v1().expect("plan bytes");
        let template = scenario_plan
            .templates()
            .iter()
            .find(|template| template.scenario_kind().environment() == Some(environment))
            .expect("environment template");
        let template_bytes = template.canonical_json_v1().expect("template bytes");
        let authority = test_macos_linux_vz_package_authority_request_from_scenario_v1(
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact_bytes,
            &scenario_plan_bytes,
            &template_bytes,
            digest("challenge"),
            digest("clone"),
        );
        let grant = test_macos_linux_vz_package_execution_grant_observation_v1(&authority);
        let authorizer =
            MacosLinuxVzPackageExecutionRequestAuthorizerV1::new(grant).expect("authorizer");
        let request = authorizer
            .build_and_consume(
                &authority,
                &artifact_bytes,
                &scenario_plan_bytes,
                &template_bytes,
            )
            .expect("request");
        let decoded = crate::structurally_decode_macos_linux_vz_package_execution_request_v1(
            request.canonical_json_v1(),
        )
        .expect("decoded request");
        derive_macos_linux_vz_package_execution_program_v1(&decoded).expect("program")
    }

    #[test]
    fn npm_process_plan_has_fixed_measured_node_npm_and_ci_profiles() {
        let false_plan = derive_macos_linux_vz_package_execution_process_plan_v1(
            &inert_npm_program(NpmEnvironmentProfileV1::CiFalse),
        )
        .expect("CI false process plan");
        let true_plan = derive_macos_linux_vz_package_execution_process_plan_v1(
            &inert_npm_program(NpmEnvironmentProfileV1::CiTrue),
        )
        .expect("CI true process plan");
        assert_ne!(
            false_plan.process_plan_sha256(),
            true_plan.process_plan_sha256()
        );
        let false_text = std::str::from_utf8(false_plan.canonical_json_v1()).expect("UTF-8");
        let true_text = std::str::from_utf8(true_plan.canonical_json_v1()).expect("UTF-8");
        assert!(false_text.contains("/usr/bin/node"));
        assert!(false_text.contains("/usr/lib/node_modules/npm/bin/npm-cli.js"));
        assert!(false_text.contains("--foreground-scripts"));
        assert!(false_text.contains("--script-shell=/bin/sh"));
        assert!(!false_text.contains("\"CI\""));
        assert!(true_text.contains("\"CI\":\"true\""));
        assert!(!false_text.contains("caller_argv"));
        assert!(!false_plan.package_execution_authority_permitted());
        assert!(!false_plan.sync_back_permitted());
    }

    #[test]
    fn wheel_process_plan_materializes_the_later_stage_basename_and_separates_executable() {
        let wheel_basename = "fixture_pkg-1.0.0-py3-none-any.whl";
        let program = test_macos_linux_vz_package_execution_program_v1(
            python_runtime(),
            "wheel_install_then_import_root",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshWheelVirtualEnvironment,
                MacosLinuxVzPackageExecutionStageV1::PythonPipInstallExactWheel {
                    input_basename: wheel_basename.to_string(),
                    package_normalized_name: "fixture-pkg".to_string(),
                    package_version: "1.0.0".to_string(),
                    resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexNoDependencies,
                },
                MacosLinuxVzPackageExecutionStageV1::PythonImportRootProbe {
                    module: "fixture_pkg".to_string(),
                },
            ],
        );
        let plan = derive_macos_linux_vz_package_execution_process_plan_v1(&program)
            .expect("wheel process plan");

        assert!(matches!(
            &plan.actions()[0],
            MacosLinuxVzPackageExecutionActionV1::Internal {
                action: MacosLinuxVzPackageInternalActionV1::MaterializeExactArtifact {
                    input_basename
                }
            } if input_basename == wheel_basename
        ));
        assert_eq!(
            process_at(&plan, 1).stage_name(),
            "python_create_fresh_wheel_virtual_environment"
        );
        assert_eq!(
            literal_arguments(process_at(&plan, 1)),
            ["-I", "-m", "venv", "--without-pip", "--copies", WHEEL_VENV]
        );
        assert_eq!(
            literal_arguments(process_at(&plan, 2)),
            [
                "-I",
                PIP_CLI_PATH,
                "--python",
                WHEEL_VENV,
                "install",
                "--no-index",
                "--no-deps",
                "--disable-pip-version-check",
                "--no-input",
                "--no-compile",
                "/run/whoathere/input/fixture_pkg-1.0.0-py3-none-any.whl",
            ]
        );
        assert_eq!(
            process_at(&plan, 2).measured_inputs()[0].role(),
            MacosLinuxVzPackageMeasuredProcessInputRoleV1::PipCli
        );
        assert!(!literal_arguments(process_at(&plan, 2)).contains(&PYTHON_PATH));
        assert_eq!(
            process_at(&plan, 3).stage_name(),
            "python_import_root_probe"
        );
    }

    #[test]
    fn console_wrapper_is_validated_against_the_semantic_target_before_execution() {
        let target_sha256 = Sha256Digest::from_bytes(b"fixture_pkg.cli:main");
        let program = test_macos_linux_vz_package_execution_program_v1(
            python_runtime(),
            "wheel_install_then_console_entry_point_help",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshWheelVirtualEnvironment,
                MacosLinuxVzPackageExecutionStageV1::PythonPipInstallExactWheel {
                    input_basename: "fixture_pkg-1.0.0-py3-none-any.whl".to_string(),
                    package_normalized_name: "fixture-pkg".to_string(),
                    package_version: "1.0.0".to_string(),
                    resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexNoDependencies,
                },
                MacosLinuxVzPackageExecutionStageV1::PythonConsoleEntryPointHelpProbe {
                    command_name: "fixture-tool".to_string(),
                    module: "fixture_pkg.cli".to_string(),
                    callable: "main".to_string(),
                    target_sha256: target_sha256.clone(),
                },
            ],
        );
        let plan = derive_macos_linux_vz_package_execution_process_plan_v1(&program)
            .expect("console process plan");

        assert!(matches!(
            &plan.actions()[3],
            MacosLinuxVzPackageExecutionActionV1::Internal {
                action: MacosLinuxVzPackageInternalActionV1::ValidateDerivedConsoleEntryPoint {
                    absolute_path,
                    module,
                    callable,
                    target_sha256: action_target,
                }
            } if absolute_path == "/run/whoathere/work/wheel-venv/bin/fixture-tool"
                && module == "fixture_pkg.cli"
                && callable == "main"
                && action_target == &target_sha256
        ));
        assert!(matches!(
            process_at(&plan, 4).executable(),
            MacosLinuxVzPackageProcessExecutableV1::ValidatedDerivedConsoleEntryPoint {
                absolute_path,
                validated_target_sha256,
            } if absolute_path == "/run/whoathere/work/wheel-venv/bin/fixture-tool"
                && validated_target_sha256 == &target_sha256
        ));
        assert_eq!(literal_arguments(process_at(&plan, 4)), ["--help"]);
    }

    #[test]
    fn sdist_process_plan_binds_normalized_root_closure_and_derived_wheel_slot() {
        let build_closure = SdistBuildClosureV1::new(
            &["setuptools==75.0.0".to_string()],
            vec![SdistBuildClosureArtifactV1::new(
                "setuptools",
                "75.0.0",
                "setuptools-75.0.0-py3-none-any.whl",
                SdistBuildClosureArtifactFormatV1::Wheel,
                digest("setuptools wheel"),
                1024,
            )
            .expect("closure artifact")],
        )
        .expect("build closure");
        let build = MacosLinuxVzSdistBuildRecipeV1::new_for_execution_program_test_v1(
            ArtifactFormat::SdistTarGzip,
            "fixture-pkg-1.0.0".to_string(),
            SdistBuildModeV1::Pep517,
            Some("setuptools.build_meta".to_string()),
            Vec::new(),
            build_closure.declaration_set_sha256().clone(),
            build_closure.clone(),
        );
        let program = test_macos_linux_vz_package_execution_program_v1(
            python_runtime(),
            "sdist_build_install_then_import_root",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
                    input_basename: "package.tar.gz".to_string(),
                    artifact_format: ArtifactFormat::SdistTarGzip,
                    expected_archive_root: "fixture-pkg-1.0.0".to_string(),
                },
                MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshSdistBuildVirtualEnvironment,
                MacosLinuxVzPackageExecutionStageV1::PythonInstallExactSdistBuildClosure {
                    build_requires_sha256: build_closure.declaration_set_sha256().clone(),
                    build_closure: build_closure.clone(),
                    resolver_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::NoIndexFixedClosureOnly,
                },
                MacosLinuxVzPackageExecutionStageV1::PythonBuildExactSdist { build },
                MacosLinuxVzPackageExecutionStageV1::PythonValidateSingleDerivedWheel,
                MacosLinuxVzPackageExecutionStageV1::PythonCreateFreshDerivedWheelInstallVirtualEnvironment,
                MacosLinuxVzPackageExecutionStageV1::PythonPipInstallDerivedWheel {
                    resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexNoDependencies,
                },
                MacosLinuxVzPackageExecutionStageV1::PythonImportDerivedWheelRootProbe {
                    module: "fixture_pkg".to_string(),
                },
            ],
        );
        let plan = derive_macos_linux_vz_package_execution_process_plan_v1(&program)
            .expect("sdist process plan");

        assert_eq!(plan.actions().len(), 10);
        assert!(matches!(
            &plan.actions()[1],
            MacosLinuxVzPackageExecutionActionV1::Internal {
                action: MacosLinuxVzPackageInternalActionV1::SafelyExtractExactSdist {
                    input_basename,
                    artifact_format: ArtifactFormat::SdistTarGzip,
                    expected_archive_root,
                    destination,
                }
            } if input_basename == "package.tar.gz"
                && expected_archive_root == "fixture-pkg-1.0.0"
                && destination == SDIST_SOURCE
        ));
        assert!(matches!(
            &plan.actions()[3],
            MacosLinuxVzPackageExecutionActionV1::Internal {
                action: MacosLinuxVzPackageInternalActionV1::ValidateExactBuildClosure {
                    build_requires_sha256,
                    build_closure: observed_closure,
                }
            } if build_requires_sha256 == build_closure.declaration_set_sha256()
                && observed_closure == &build_closure
        ));
        assert!(literal_arguments(process_at(&plan, 4))
            .contains(&"/run/whoathere/closure/setuptools-75.0.0-py3-none-any.whl"));
        assert_eq!(
            process_at(&plan, 7).stage_name(),
            "python_create_fresh_derived_wheel_install_virtual_environment"
        );
        assert!(matches!(
            process_at(&plan, 8).arguments().last(),
            Some(MacosLinuxVzPackageProcessArgumentV1::ValidatedDerivedWheelPath)
        ));
        assert_eq!(
            process_at(&plan, 9).stage_name(),
            "python_import_derived_wheel_root_probe"
        );

        let mismatched = test_macos_linux_vz_package_execution_program_v1(
            python_runtime(),
            "sdist_build_exact",
            vec![
                MacosLinuxVzPackageExecutionStageV1::PythonSafelyExtractExactSdist {
                    input_basename: "package.tar.gz".to_string(),
                    artifact_format: ArtifactFormat::SdistTarGzip,
                    expected_archive_root: "fixture-pkg-1.0.0".to_string(),
                },
                MacosLinuxVzPackageExecutionStageV1::PythonInstallExactSdistBuildClosure {
                    build_requires_sha256: digest("wrong build requirements"),
                    build_closure,
                    resolver_policy: MacosLinuxVzPackageDependencyPolicyV1::NoIndexFixedClosureOnly,
                },
            ],
        );
        assert!(matches!(
            derive_macos_linux_vz_package_execution_process_plan_v1(&mismatched),
            Err(MacosLinuxVzPackageExecutionProcessPlanErrorV1::InvalidStage)
        ));
    }

    #[test]
    fn fixed_python_code_takes_validated_targets_as_data_not_code() {
        assert!(!PYTHON_IMPORT_PROBE.contains("{}"));
        assert!(PYTHON_IMPORT_PROBE.contains("sys.argv[1]"));
        assert!(PYTHON_PEP517_BUILD.contains("sys.argv[1:]"));
        assert!(!PYTHON_PEP517_BUILD.contains("eval("));
        assert!(!PYTHON_PEP517_BUILD.contains("exec("));
    }
}
