use crate::{
    MacosLinuxVzPackageExecutionActionV1, MacosLinuxVzPackageExecutionProcessPlanV1,
    MacosLinuxVzPackageInternalActionV1,
};
use serde::Serialize;
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_CONSOLE_TARGET_OBSERVATION_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_console_target_observation.v1";
pub const MAX_LINUX_VZ_PACKAGE_CONSOLE_TARGET_OBSERVATION_BYTES_V1: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageConsoleTargetValidationErrorV1 {
    InvalidAction,
    InvalidModule,
    InvalidCallable,
    TargetDigestMismatch,
    Serialization,
    LimitExceeded,
}

impl LinuxVzPackageConsoleTargetValidationErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidAction => "linux_vz_package_console_target_action_invalid",
            Self::InvalidModule => "linux_vz_package_console_target_module_invalid",
            Self::InvalidCallable => "linux_vz_package_console_target_callable_invalid",
            Self::TargetDigestMismatch => "linux_vz_package_console_target_digest_mismatch",
            Self::Serialization => "linux_vz_package_console_target_serialization_failed",
            Self::LimitExceeded => "linux_vz_package_console_target_limit_exceeded",
        }
    }
}

impl fmt::Display for LinuxVzPackageConsoleTargetValidationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageConsoleTargetValidationErrorV1 {}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ConsoleTargetObservationWireV1<'a> {
    schema_version: &'static str,
    process_plan_sha256: &'a Sha256Digest,
    action_index: String,
    module: &'a str,
    callable: &'a str,
    canonical_target: &'a str,
    target_sha256: &'a Sha256Digest,
    target_recomputed: bool,
    wrapper_path_used: bool,
    execution_authority: bool,
    package_execution: bool,
    sync_back: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageConsoleTargetObservationV1 {
    canonical_json: Vec<u8>,
    observation_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    module: String,
    callable: String,
    canonical_target: String,
    target_sha256: Sha256Digest,
}

impl fmt::Debug for LinuxVzPackageConsoleTargetObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageConsoleTargetObservationV1")
            .field("observation_sha256", &self.observation_sha256)
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("action_index", &self.action_index)
            .field("canonical_target", &self.canonical_target)
            .finish()
    }
}

impl LinuxVzPackageConsoleTargetObservationV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn observation_sha256(&self) -> &Sha256Digest {
        &self.observation_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    pub fn module(&self) -> &str {
        &self.module
    }

    pub fn callable(&self) -> &str {
        &self.callable
    }

    pub fn canonical_target(&self) -> &str {
        &self.canonical_target
    }

    pub fn target_sha256(&self) -> &Sha256Digest {
        &self.target_sha256
    }

    pub const fn wrapper_path_used(&self) -> bool {
        false
    }

    pub const fn execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn validate_linux_vz_package_console_target_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    action_index: usize,
) -> Result<LinuxVzPackageConsoleTargetObservationV1, LinuxVzPackageConsoleTargetValidationErrorV1>
{
    let MacosLinuxVzPackageExecutionActionV1::Internal {
        action:
            MacosLinuxVzPackageInternalActionV1::ValidateConsoleEntryPointTarget {
                module,
                callable,
                target_sha256,
            },
    } = process_plan
        .actions()
        .get(action_index)
        .ok_or(LinuxVzPackageConsoleTargetValidationErrorV1::InvalidAction)?
    else {
        return Err(LinuxVzPackageConsoleTargetValidationErrorV1::InvalidAction);
    };
    validate_python_dotted_identifier_v1(module)
        .map_err(|_| LinuxVzPackageConsoleTargetValidationErrorV1::InvalidModule)?;
    validate_python_dotted_identifier_v1(callable)
        .map_err(|_| LinuxVzPackageConsoleTargetValidationErrorV1::InvalidCallable)?;
    let canonical_target = format!("{module}:{callable}");
    if &Sha256Digest::from_bytes(canonical_target.as_bytes()) != target_sha256 {
        return Err(LinuxVzPackageConsoleTargetValidationErrorV1::TargetDigestMismatch);
    }
    let wire = ConsoleTargetObservationWireV1 {
        schema_version: LINUX_VZ_PACKAGE_CONSOLE_TARGET_OBSERVATION_SCHEMA_V1,
        process_plan_sha256: process_plan.process_plan_sha256(),
        action_index: action_index.to_string(),
        module,
        callable,
        canonical_target: &canonical_target,
        target_sha256,
        target_recomputed: true,
        wrapper_path_used: false,
        execution_authority: false,
        package_execution: false,
        sync_back: false,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageConsoleTargetValidationErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_LINUX_VZ_PACKAGE_CONSOLE_TARGET_OBSERVATION_BYTES_V1
    {
        return Err(LinuxVzPackageConsoleTargetValidationErrorV1::LimitExceeded);
    }
    Ok(LinuxVzPackageConsoleTargetObservationV1 {
        observation_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        process_plan_sha256: process_plan.process_plan_sha256().clone(),
        action_index,
        module: module.clone(),
        callable: callable.clone(),
        canonical_target,
        target_sha256: target_sha256.clone(),
    })
}

fn validate_python_dotted_identifier_v1(value: &str) -> Result<(), ()> {
    if value.is_empty()
        || value.len() > 512
        || value
            .split('.')
            .any(|component| !valid_python_identifier_component_v1(component))
    {
        return Err(());
    }
    Ok(())
}

fn valid_python_identifier_component_v1(value: &str) -> bool {
    let mut bytes = value.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    (first == b'_' || first.is_ascii_alphabetic())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::test_macos_linux_vz_package_execution_program_v1,
        MacosLinuxVzPackageDependencyPolicyV1, MacosLinuxVzPackageExecutionStageV1,
        MacosLinuxVzPackageRuntimeExecutablesV1,
    };

    fn console_plan_v1(
        module: &str,
        callable: &str,
        target_sha256: Sha256Digest,
    ) -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::PythonPip {
                python_version: "3.14.0".to_string(),
                python_executable_sha256: Sha256Digest::from_bytes(b"inert python"),
                pip_version: "25.1".to_string(),
                pip_cli_sha256: Sha256Digest::from_bytes(b"inert pip"),
            },
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
                    module: module.to_string(),
                    callable: callable.to_string(),
                    target_sha256,
                },
            ],
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("console plan")
    }

    #[test]
    fn target_is_recomputed_without_trusting_a_generated_wrapper() {
        let target = "fixture_pkg.cli:commands.main";
        let plan = console_plan_v1(
            "fixture_pkg.cli",
            "commands.main",
            Sha256Digest::from_bytes(target.as_bytes()),
        );
        let observation =
            validate_linux_vz_package_console_target_v1(&plan, 3).expect("validated target");
        assert_eq!(observation.canonical_target(), target);
        assert_eq!(observation.action_index(), 3);
        assert!(!observation.wrapper_path_used());
        assert!(!observation.execution_authority_permitted());
        assert!(!observation.sync_back_permitted());
        assert_eq!(
            observation.observation_sha256(),
            &Sha256Digest::from_bytes(observation.canonical_json_v1())
        );
    }

    #[test]
    fn malformed_or_rebound_targets_fail_closed() {
        let valid_digest = Sha256Digest::from_bytes(b"fixture_pkg.cli:main");
        for (module, callable, expected) in [
            (
                "fixture_pkg..cli",
                "main",
                LinuxVzPackageConsoleTargetValidationErrorV1::InvalidModule,
            ),
            (
                "fixture-pkg.cli",
                "main",
                LinuxVzPackageConsoleTargetValidationErrorV1::InvalidModule,
            ),
            (
                "fixture_pkg.cli",
                "main()",
                LinuxVzPackageConsoleTargetValidationErrorV1::InvalidCallable,
            ),
        ] {
            let plan = console_plan_v1(module, callable, valid_digest.clone());
            assert_eq!(
                validate_linux_vz_package_console_target_v1(&plan, 3),
                Err(expected)
            );
        }
        let plan = console_plan_v1(
            "fixture_pkg.cli",
            "main",
            Sha256Digest::from_bytes(b"other"),
        );
        assert_eq!(
            validate_linux_vz_package_console_target_v1(&plan, 3),
            Err(LinuxVzPackageConsoleTargetValidationErrorV1::TargetDigestMismatch)
        );
    }

    #[test]
    fn non_console_actions_cannot_mint_target_observations() {
        let target = Sha256Digest::from_bytes(b"fixture_pkg.cli:main");
        let plan = console_plan_v1("fixture_pkg.cli", "main", target);
        assert_eq!(
            validate_linux_vz_package_console_target_v1(&plan, 2),
            Err(LinuxVzPackageConsoleTargetValidationErrorV1::InvalidAction)
        );
        assert_eq!(
            validate_linux_vz_package_console_target_v1(&plan, 4),
            Err(LinuxVzPackageConsoleTargetValidationErrorV1::InvalidAction)
        );
    }
}
