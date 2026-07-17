use crate::{
    MacosLinuxVzPackageExecutionActionV1, MacosLinuxVzPackageExecutionProcessPlanV1,
    MacosLinuxVzPackageMeasuredProcessInputRoleV1, MacosLinuxVzPackageProcessArgumentV1,
    MacosLinuxVzPackageProcessEnvironmentPolicyV1, MacosLinuxVzPackageProcessExecutableV1,
    MacosLinuxVzPackageProcessStdioPolicyV1,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_PROCESS_LAUNCH_CONTRACT_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_process_launch_contract.v1";
pub const MAX_LINUX_VZ_PACKAGE_PROCESS_LAUNCH_CONTRACT_BYTES_V1: usize = 256 * 1024;

const RUN_ROOT_V1: &str = "/run/whoathere";
const DERIVED_ROOT_V1: &str = "/run/whoathere/derived/";
const MAX_ARGUMENT_COUNT_V1: usize = 256;
const MAX_ARGUMENT_ENVIRONMENT_BYTES_V1: usize = 64 * 1024;
const MAX_ENVIRONMENT_VARIABLE_COUNT_V1: usize = 128;
const TERM_GRACE_MILLISECONDS_V1: u64 = 250;
const TEARDOWN_DEADLINE_MILLISECONDS_V1: u64 = 5_000;
const CGROUP_MEMORY_MAX_BYTES_V1: u64 = 2 * 1024 * 1024 * 1024;
const CGROUP_SWAP_MAX_BYTES_V1: u64 = 0;
const RLIMIT_FILE_SIZE_BYTES_V1: u64 = 512 * 1024 * 1024;
const RLIMIT_ADDRESS_SPACE_BYTES_V1: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageProcessLaunchContractErrorV1 {
    InvalidAction,
    DynamicBindingMissing,
    DynamicBindingUnexpected,
    DynamicBindingInvalid,
    InvalidExecutable,
    InvalidArgument,
    InvalidEnvironment,
    InvalidCurrentDirectory,
    InvalidMeasuredInput,
    InvalidLimits,
    LimitExceeded,
    Serialization,
}

impl LinuxVzPackageProcessLaunchContractErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidAction => "linux_vz_package_process_launch_action_invalid",
            Self::DynamicBindingMissing => {
                "linux_vz_package_process_launch_dynamic_binding_missing"
            }
            Self::DynamicBindingUnexpected => {
                "linux_vz_package_process_launch_dynamic_binding_unexpected"
            }
            Self::DynamicBindingInvalid => {
                "linux_vz_package_process_launch_dynamic_binding_invalid"
            }
            Self::InvalidExecutable => "linux_vz_package_process_launch_executable_invalid",
            Self::InvalidArgument => "linux_vz_package_process_launch_argument_invalid",
            Self::InvalidEnvironment => "linux_vz_package_process_launch_environment_invalid",
            Self::InvalidCurrentDirectory => {
                "linux_vz_package_process_launch_current_directory_invalid"
            }
            Self::InvalidMeasuredInput => "linux_vz_package_process_launch_measured_input_invalid",
            Self::InvalidLimits => "linux_vz_package_process_launch_limits_invalid",
            Self::LimitExceeded => "linux_vz_package_process_launch_contract_limit_exceeded",
            Self::Serialization => "linux_vz_package_process_launch_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageProcessLaunchContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageProcessLaunchContractErrorV1 {}

/// Opaque bindings produced by later validators for package-generated paths.
///
/// The empty value is sufficient for every process whose arguments and executable are already
/// fixed in the process plan. There is deliberately no public constructor for a derived-wheel
/// binding: path discovery alone must never manufacture execution authority.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedLinuxVzPackageDynamicProcessBindingsV1 {
    derived_wheel_path: Option<String>,
    derived_wheel_sha256: Option<Sha256Digest>,
}

impl ValidatedLinuxVzPackageDynamicProcessBindingsV1 {
    pub const fn none() -> Self {
        Self {
            derived_wheel_path: None,
            derived_wheel_sha256: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test_v1(derived_wheel: Option<(&str, Sha256Digest)>) -> Self {
        Self {
            derived_wheel_path: derived_wheel.as_ref().map(|(path, _)| (*path).to_string()),
            derived_wheel_sha256: derived_wheel.map(|(_, digest)| digest),
        }
    }

    pub(crate) fn for_derived_wheel_v1(path: String, sha256: Sha256Digest) -> Self {
        Self {
            derived_wheel_path: Some(path),
            derived_wheel_sha256: Some(sha256),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzPackageResolvedExecutableClassV1 {
    PinnedRootfsRuntime,
    PackageGeneratedVirtualEnvironmentPythonCopy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageResolvedMeasuredInputV1 {
    role: MacosLinuxVzPackageMeasuredProcessInputRoleV1,
    absolute_path: String,
    expected_sha256: Sha256Digest,
}

impl LinuxVzPackageResolvedMeasuredInputV1 {
    pub const fn role(&self) -> MacosLinuxVzPackageMeasuredProcessInputRoleV1 {
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
pub struct LinuxVzPackageProcessLaunchLimitsV1 {
    scenario_wall_clock_milliseconds: String,
    stdout_capture_bytes: String,
    stderr_capture_bytes: String,
    cgroup_pids_max: String,
    cgroup_memory_max_bytes: String,
    cgroup_swap_max_bytes: String,
    rlimit_cpu_seconds: String,
    rlimit_open_files: String,
    rlimit_processes: String,
    rlimit_file_size_bytes: String,
    rlimit_address_space_bytes: String,
    rlimit_core_bytes: String,
    term_grace_milliseconds: String,
    teardown_deadline_milliseconds: String,
}

impl LinuxVzPackageProcessLaunchLimitsV1 {
    pub fn scenario_wall_clock_milliseconds(&self) -> u64 {
        decimal_u64_v1(&self.scenario_wall_clock_milliseconds)
    }

    pub fn stdout_capture_bytes(&self) -> u64 {
        decimal_u64_v1(&self.stdout_capture_bytes)
    }

    pub fn stderr_capture_bytes(&self) -> u64 {
        decimal_u64_v1(&self.stderr_capture_bytes)
    }

    pub fn cgroup_pids_max(&self) -> u32 {
        decimal_u64_v1(&self.cgroup_pids_max) as u32
    }

    pub fn cgroup_memory_max_bytes(&self) -> u64 {
        decimal_u64_v1(&self.cgroup_memory_max_bytes)
    }

    pub fn cgroup_swap_max_bytes(&self) -> u64 {
        decimal_u64_v1(&self.cgroup_swap_max_bytes)
    }

    pub fn rlimit_cpu_seconds(&self) -> u64 {
        decimal_u64_v1(&self.rlimit_cpu_seconds)
    }

    pub fn rlimit_open_files(&self) -> u32 {
        decimal_u64_v1(&self.rlimit_open_files) as u32
    }

    pub fn rlimit_processes(&self) -> u32 {
        decimal_u64_v1(&self.rlimit_processes) as u32
    }

    pub fn rlimit_file_size_bytes(&self) -> u64 {
        decimal_u64_v1(&self.rlimit_file_size_bytes)
    }

    pub fn rlimit_address_space_bytes(&self) -> u64 {
        decimal_u64_v1(&self.rlimit_address_space_bytes)
    }

    pub const fn rlimit_core_bytes(&self) -> u64 {
        0
    }

    pub fn term_grace_milliseconds(&self) -> u64 {
        decimal_u64_v1(&self.term_grace_milliseconds)
    }

    pub fn teardown_deadline_milliseconds(&self) -> u64 {
        decimal_u64_v1(&self.teardown_deadline_milliseconds)
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PackageProcessLaunchContractWireV1<'a> {
    schema_version: &'static str,
    process_plan_sha256: &'a Sha256Digest,
    action_index: String,
    stage_name: &'a str,
    executable_class: LinuxVzPackageResolvedExecutableClassV1,
    executable_path: &'a str,
    expected_executable_sha256: &'a Sha256Digest,
    argv: &'a [String],
    environment_policy: MacosLinuxVzPackageProcessEnvironmentPolicyV1,
    environment: &'a BTreeMap<String, String>,
    current_directory: &'a str,
    measured_inputs: &'a [LinuxVzPackageResolvedMeasuredInputV1],
    stdio_policy: MacosLinuxVzPackageProcessStdioPolicyV1,
    limits: &'a LinuxVzPackageProcessLaunchLimitsV1,
    cgroup_version: &'static str,
    cgroup_scope: &'static str,
    credential_policy: &'static str,
    descendant_policy: &'static str,
    public_network_route_present: bool,
    caller_process_input_present: bool,
    launch_authority_present: bool,
    package_execution: bool,
    sync_back: bool,
}

#[derive(Clone, PartialEq, Eq)]
pub struct LinuxVzPackageProcessLaunchContractV1 {
    canonical_json: Vec<u8>,
    launch_contract_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    stage_name: String,
    executable_class: LinuxVzPackageResolvedExecutableClassV1,
    executable_path: String,
    expected_executable_sha256: Sha256Digest,
    argv: Vec<String>,
    environment: BTreeMap<String, String>,
    current_directory: String,
    measured_inputs: Vec<LinuxVzPackageResolvedMeasuredInputV1>,
    limits: LinuxVzPackageProcessLaunchLimitsV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageProcessLaunchIdentityV1 {
    executable_sha256: Sha256Digest,
    argv_sha256: Sha256Digest,
    argv_item_count: usize,
}

impl LinuxVzPackageProcessLaunchIdentityV1 {
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn from_contract_v1(
        contract: &LinuxVzPackageProcessLaunchContractV1,
    ) -> Result<Self, LinuxVzPackageProcessLaunchContractErrorV1> {
        let argv = serde_json_canonicalizer::to_vec(&contract.argv())
            .map_err(|_| LinuxVzPackageProcessLaunchContractErrorV1::Serialization)?;
        Self::from_bound_digests_v1(
            contract.expected_executable_sha256().clone(),
            Sha256Digest::from_bytes(&argv),
            contract.argv().len(),
        )
    }

    pub(crate) fn from_bound_digests_v1(
        executable_sha256: Sha256Digest,
        argv_sha256: Sha256Digest,
        argv_item_count: usize,
    ) -> Result<Self, LinuxVzPackageProcessLaunchContractErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        if executable_sha256 == empty
            || argv_sha256 == empty
            || argv_item_count == 0
            || argv_item_count > MAX_ARGUMENT_COUNT_V1
        {
            return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidArgument);
        }
        Ok(Self {
            executable_sha256,
            argv_sha256,
            argv_item_count,
        })
    }

    pub fn executable_sha256(&self) -> &Sha256Digest {
        &self.executable_sha256
    }

    pub fn argv_sha256(&self) -> &Sha256Digest {
        &self.argv_sha256
    }

    pub const fn argv_item_count(&self) -> usize {
        self.argv_item_count
    }
}

impl fmt::Debug for LinuxVzPackageProcessLaunchContractV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageProcessLaunchContractV1")
            .field("launch_contract_sha256", &self.launch_contract_sha256)
            .field("process_plan_sha256", &self.process_plan_sha256)
            .field("action_index", &self.action_index)
            .field("stage_name", &self.stage_name)
            .field("executable_path", &self.executable_path)
            .field("argv_count", &self.argv.len())
            .field("environment_count", &self.environment.len())
            .finish()
    }
}

impl LinuxVzPackageProcessLaunchContractV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn launch_contract_sha256(&self) -> &Sha256Digest {
        &self.launch_contract_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    pub fn stage_name(&self) -> &str {
        &self.stage_name
    }

    pub const fn executable_class(&self) -> LinuxVzPackageResolvedExecutableClassV1 {
        self.executable_class
    }

    pub fn executable_path(&self) -> &str {
        &self.executable_path
    }

    pub fn expected_executable_sha256(&self) -> &Sha256Digest {
        &self.expected_executable_sha256
    }

    pub fn argv(&self) -> &[String] {
        &self.argv
    }

    pub fn environment(&self) -> &BTreeMap<String, String> {
        &self.environment
    }

    pub fn current_directory(&self) -> &str {
        &self.current_directory
    }

    pub fn measured_inputs(&self) -> &[LinuxVzPackageResolvedMeasuredInputV1] {
        &self.measured_inputs
    }

    pub fn limits(&self) -> &LinuxVzPackageProcessLaunchLimitsV1 {
        &self.limits
    }

    pub const fn launch_authority_present(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn derive_linux_vz_package_process_launch_contract_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
    action_index: usize,
    bindings: &ValidatedLinuxVzPackageDynamicProcessBindingsV1,
) -> Result<LinuxVzPackageProcessLaunchContractV1, LinuxVzPackageProcessLaunchContractErrorV1> {
    let MacosLinuxVzPackageExecutionActionV1::Process { process } = process_plan
        .actions()
        .get(action_index)
        .ok_or(LinuxVzPackageProcessLaunchContractErrorV1::InvalidAction)?
    else {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidAction);
    };

    let (executable_class, executable_path, expected_executable_sha256) = match process.executable()
    {
        MacosLinuxVzPackageProcessExecutableV1::PinnedRuntimeFile {
            absolute_path,
            expected_sha256,
        } => (
            LinuxVzPackageResolvedExecutableClassV1::PinnedRootfsRuntime,
            absolute_path.clone(),
            expected_sha256.clone(),
        ),
        MacosLinuxVzPackageProcessExecutableV1::FreshVirtualEnvironmentPythonCopy {
            absolute_path,
            source_python_sha256,
        } => (
            LinuxVzPackageResolvedExecutableClassV1::PackageGeneratedVirtualEnvironmentPythonCopy,
            absolute_path.clone(),
            source_python_sha256.clone(),
        ),
    };
    validate_absolute_path_v1(&executable_path, true)
        .map_err(|_| LinuxVzPackageProcessLaunchContractErrorV1::InvalidExecutable)?;

    let mut argv = Vec::with_capacity(process.arguments().len() + 1);
    argv.push(executable_path.clone());
    let mut used_derived_wheel = false;
    let mut resolved_derived_wheel = None;
    for argument in process.arguments() {
        let value = match argument {
            MacosLinuxVzPackageProcessArgumentV1::Literal { value } => value.clone(),
            MacosLinuxVzPackageProcessArgumentV1::ValidatedDerivedWheelPath => {
                if used_derived_wheel {
                    return Err(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingInvalid);
                }
                used_derived_wheel = true;
                let path = bindings
                    .derived_wheel_path
                    .as_deref()
                    .ok_or(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingMissing)?;
                let digest = bindings
                    .derived_wheel_sha256
                    .as_ref()
                    .ok_or(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingMissing)?;
                validate_derived_wheel_path_v1(path)?;
                resolved_derived_wheel = Some((path.to_string(), digest.clone()));
                path.to_string()
            }
        };
        if value.as_bytes().contains(&0) {
            return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidArgument);
        }
        argv.push(value);
    }
    if !used_derived_wheel
        && (bindings.derived_wheel_path.is_some() || bindings.derived_wheel_sha256.is_some())
    {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingUnexpected);
    }
    if bindings.derived_wheel_path.is_some() != bindings.derived_wheel_sha256.is_some() {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingInvalid);
    }
    if argv.is_empty() || argv.len() > MAX_ARGUMENT_COUNT_V1 {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::LimitExceeded);
    }

    if process.environment_policy()
        != MacosLinuxVzPackageProcessEnvironmentPolicyV1::ClearThenExactMap
        || process.environment().is_empty()
        || process.environment().len() > MAX_ENVIRONMENT_VARIABLE_COUNT_V1
    {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidEnvironment);
    }
    for (key, value) in process.environment() {
        if key.is_empty()
            || key.as_bytes().contains(&0)
            || key.contains('=')
            || value.as_bytes().contains(&0)
        {
            return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidEnvironment);
        }
    }
    let argument_environment_bytes = argv
        .iter()
        .map(|value| value.len() + 1)
        .chain(
            process
                .environment()
                .iter()
                .map(|(key, value)| key.len() + value.len() + 2),
        )
        .try_fold(0_usize, usize::checked_add)
        .ok_or(LinuxVzPackageProcessLaunchContractErrorV1::LimitExceeded)?;
    if argument_environment_bytes > MAX_ARGUMENT_ENVIRONMENT_BYTES_V1 {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::LimitExceeded);
    }

    validate_absolute_path_v1(process.current_directory(), false)
        .map_err(|_| LinuxVzPackageProcessLaunchContractErrorV1::InvalidCurrentDirectory)?;
    if !process.current_directory().starts_with(RUN_ROOT_V1) {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidCurrentDirectory);
    }
    if process.stdio_policy()
        != MacosLinuxVzPackageProcessStdioPolicyV1::NullStdinBoundedCapturedOutput
    {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidAction);
    }

    let mut seen_measured_paths = BTreeSet::new();
    let mut measured_inputs = Vec::with_capacity(process.measured_inputs().len());
    for input in process.measured_inputs() {
        validate_absolute_path_v1(input.absolute_path(), true)
            .map_err(|_| LinuxVzPackageProcessLaunchContractErrorV1::InvalidMeasuredInput)?;
        if !seen_measured_paths.insert(input.absolute_path().to_string())
            || input.absolute_path() == executable_path
        {
            return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidMeasuredInput);
        }
        measured_inputs.push(LinuxVzPackageResolvedMeasuredInputV1 {
            role: input.role(),
            absolute_path: input.absolute_path().to_string(),
            expected_sha256: input.expected_sha256().clone(),
        });
    }
    if let Some((absolute_path, expected_sha256)) = resolved_derived_wheel {
        if !seen_measured_paths.insert(absolute_path.clone()) || absolute_path == executable_path {
            return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidMeasuredInput);
        }
        measured_inputs.push(LinuxVzPackageResolvedMeasuredInputV1 {
            role: MacosLinuxVzPackageMeasuredProcessInputRoleV1::DerivedWheel,
            absolute_path,
            expected_sha256,
        });
    }

    let limits = limits_v1(process_plan)?;
    let wire = PackageProcessLaunchContractWireV1 {
        schema_version: LINUX_VZ_PACKAGE_PROCESS_LAUNCH_CONTRACT_SCHEMA_V1,
        process_plan_sha256: process_plan.process_plan_sha256(),
        action_index: action_index.to_string(),
        stage_name: process.stage_name(),
        executable_class,
        executable_path: &executable_path,
        expected_executable_sha256: &expected_executable_sha256,
        argv: &argv,
        environment_policy: process.environment_policy(),
        environment: process.environment(),
        current_directory: process.current_directory(),
        measured_inputs: &measured_inputs,
        stdio_policy: process.stdio_policy(),
        limits: &limits,
        cgroup_version: "v2",
        cgroup_scope: "one_process_action_with_all_descendants",
        credential_policy: "uid_gid_65534_no_supplementary_groups_no_new_privileges",
        descendant_policy: "subreaper_cgroup_kill_reap_empty_remove",
        public_network_route_present: false,
        caller_process_input_present: false,
        launch_authority_present: false,
        package_execution: false,
        sync_back: false,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageProcessLaunchContractErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_LINUX_VZ_PACKAGE_PROCESS_LAUNCH_CONTRACT_BYTES_V1
    {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::LimitExceeded);
    }
    Ok(LinuxVzPackageProcessLaunchContractV1 {
        launch_contract_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        process_plan_sha256: process_plan.process_plan_sha256().clone(),
        action_index,
        stage_name: process.stage_name().to_string(),
        executable_class,
        executable_path,
        expected_executable_sha256,
        argv,
        environment: process.environment().clone(),
        current_directory: process.current_directory().to_string(),
        measured_inputs,
        limits,
    })
}

fn validate_absolute_path_v1(
    value: &str,
    allow_rootfs: bool,
) -> Result<(), LinuxVzPackageProcessLaunchContractErrorV1> {
    if value.is_empty()
        || value.len() > 4_096
        || value.as_bytes().contains(&0)
        || !value.starts_with('/')
        || value.ends_with('/')
        || value.split('/').any(|component| component == "..")
        || (!allow_rootfs && !value.starts_with(RUN_ROOT_V1))
    {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidExecutable);
    }
    Ok(())
}

fn validate_derived_wheel_path_v1(
    value: &str,
) -> Result<(), LinuxVzPackageProcessLaunchContractErrorV1> {
    validate_absolute_path_v1(value, false)
        .map_err(|_| LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingInvalid)?;
    let basename = value
        .strip_prefix(DERIVED_ROOT_V1)
        .ok_or(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingInvalid)?;
    if basename.is_empty()
        || basename.contains('/')
        || !basename.ends_with(".whl")
        || !basename.is_ascii()
        || !basename
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingInvalid);
    }
    Ok(())
}

fn limits_v1(
    process_plan: &MacosLinuxVzPackageExecutionProcessPlanV1,
) -> Result<LinuxVzPackageProcessLaunchLimitsV1, LinuxVzPackageProcessLaunchContractErrorV1> {
    let limits = process_plan.limits();
    limits
        .validate()
        .map_err(|_| LinuxVzPackageProcessLaunchContractErrorV1::InvalidLimits)?;
    let rlimit_cpu_seconds = limits
        .wall_clock_millis
        .checked_add(999)
        .and_then(|value| value.checked_div(1_000))
        .and_then(|value| value.checked_add(1))
        .ok_or(LinuxVzPackageProcessLaunchContractErrorV1::InvalidLimits)?;
    Ok(LinuxVzPackageProcessLaunchLimitsV1 {
        scenario_wall_clock_milliseconds: limits.wall_clock_millis.to_string(),
        stdout_capture_bytes: limits.max_stdout_bytes.to_string(),
        stderr_capture_bytes: limits.max_stderr_bytes.to_string(),
        cgroup_pids_max: limits.max_processes.to_string(),
        cgroup_memory_max_bytes: CGROUP_MEMORY_MAX_BYTES_V1.to_string(),
        cgroup_swap_max_bytes: CGROUP_SWAP_MAX_BYTES_V1.to_string(),
        rlimit_cpu_seconds: rlimit_cpu_seconds.to_string(),
        rlimit_open_files: limits.max_open_files.to_string(),
        rlimit_processes: limits.max_processes.to_string(),
        rlimit_file_size_bytes: RLIMIT_FILE_SIZE_BYTES_V1.to_string(),
        rlimit_address_space_bytes: RLIMIT_ADDRESS_SPACE_BYTES_V1.to_string(),
        rlimit_core_bytes: "0".to_string(),
        term_grace_milliseconds: TERM_GRACE_MILLISECONDS_V1.to_string(),
        teardown_deadline_milliseconds: TEARDOWN_DEADLINE_MILLISECONDS_V1.to_string(),
    })
}

fn decimal_u64_v1(value: &str) -> u64 {
    value
        .parse()
        .expect("launch-contract limits are constructed from validated integers")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        derive_macos_linux_vz_package_execution_process_plan_v1,
        linux_vz_package_execution_program::{
            test_macos_linux_vz_package_execution_program_v1,
            test_macos_linux_vz_package_execution_program_with_npm_closure_v1,
        },
        MacosLinuxVzNpmLifecyclePolicyV1, MacosLinuxVzPackageDependencyPolicyV1,
        MacosLinuxVzPackageExecutionStageV1, MacosLinuxVzPackageRuntimeExecutablesV1,
    };
    use whoathere_detonation::{
        DependencyClosureV1, NpmEnvironmentProfileV1, SdistBuildClosureArtifactFormatV1,
        SdistBuildClosureArtifactV1, SdistBuildClosureV1,
    };

    fn npm_plan(profile: NpmEnvironmentProfileV1) -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let program = test_macos_linux_vz_package_execution_program_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::NodeNpm {
                node_version: "24.4.0".to_string(),
                node_executable_sha256: Sha256Digest::from_bytes(b"inert node"),
                npm_version: "11.4.2".to_string(),
                npm_cli_sha256: Sha256Digest::from_bytes(b"inert npm cli"),
            },
            "npm_install_exact_local_tarball",
            vec![
                MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
                    environment: profile,
                    input_basename: "package.tgz".to_string(),
                    dependency_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::OfflineExactDependencyFree,
                    lifecycle_policy:
                        MacosLinuxVzNpmLifecyclePolicyV1::PackageManifestInstallHooksOnly,
                },
            ],
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("process plan")
    }

    fn npm_closure_plan() -> MacosLinuxVzPackageExecutionProcessPlanV1 {
        let closure = SdistBuildClosureV1::new(
            &["left-pad 1.3.0".to_string()],
            vec![SdistBuildClosureArtifactV1::new(
                "left-pad",
                "1.3.0",
                "left-pad-1.3.0.tgz",
                SdistBuildClosureArtifactFormatV1::NpmTarGzip,
                Sha256Digest::from_bytes(b"inert closure tgz"),
                128,
            )
            .expect("closure descriptor")],
        )
        .expect("closure");
        let program = test_macos_linux_vz_package_execution_program_with_npm_closure_v1(
            MacosLinuxVzPackageRuntimeExecutablesV1::NodeNpm {
                node_version: "24.4.0".to_string(),
                node_executable_sha256: Sha256Digest::from_bytes(b"inert node"),
                npm_version: "11.4.2".to_string(),
                npm_cli_sha256: Sha256Digest::from_bytes(b"inert npm cli"),
            },
            "npm_install_exact_local_tarball",
            vec![
                MacosLinuxVzPackageExecutionStageV1::NpmInstallExactLocalTarball {
                    environment: NpmEnvironmentProfileV1::CiTrue,
                    input_basename: "package.tgz".to_string(),
                    dependency_policy:
                        MacosLinuxVzPackageDependencyPolicyV1::NoIndexFixedClosureOnly,
                    lifecycle_policy:
                        MacosLinuxVzNpmLifecyclePolicyV1::PackageManifestInstallHooksOnly,
                },
            ],
            DependencyClosureV1::NpmTarballSet { closure },
        );
        derive_macos_linux_vz_package_execution_process_plan_v1(&program).expect("process plan")
    }

    #[test]
    fn pinned_npm_launch_contract_is_closed_and_resource_bounded() {
        let plan = npm_plan(NpmEnvironmentProfileV1::CiTrue);
        let contract = derive_linux_vz_package_process_launch_contract_v1(
            &plan,
            1,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("launch contract");

        assert_eq!(contract.action_index(), 1);
        assert_eq!(contract.stage_name(), "npm_install_exact_local_tarball");
        assert_eq!(contract.executable_path(), "/usr/bin/node");
        assert_eq!(contract.argv()[0], "/usr/bin/node");
        assert_eq!(
            contract.argv().last().map(String::as_str),
            Some("/run/whoathere/input/package.tgz")
        );
        assert_eq!(
            contract.environment().get("CI").map(String::as_str),
            Some("true")
        );
        assert_eq!(
            contract
                .environment()
                .get("NODE_OPTIONS")
                .map(String::as_str),
            Some("--require=/run/whoathere/input/npm-environment-credential-read-preload-v1.cjs")
        );
        assert_eq!(contract.measured_inputs().len(), 2);
        assert_eq!(
            contract.measured_inputs()[0].absolute_path(),
            "/usr/lib/node_modules/npm/bin/npm-cli.js"
        );
        assert_eq!(
            contract.measured_inputs()[1].role(),
            MacosLinuxVzPackageMeasuredProcessInputRoleV1::NpmEnvironmentCredentialSensorHook
        );
        assert_eq!(
            contract.measured_inputs()[1].absolute_path(),
            "/run/whoathere/input/npm-environment-credential-read-preload-v1.cjs"
        );
        assert_eq!(
            contract.limits().scenario_wall_clock_milliseconds(),
            120_000
        );
        assert_eq!(contract.limits().stdout_capture_bytes(), 1024 * 1024);
        assert_eq!(contract.limits().stderr_capture_bytes(), 1024 * 1024);
        assert_eq!(contract.limits().cgroup_pids_max(), 256);
        assert_eq!(contract.limits().rlimit_open_files(), 1024);
        assert_eq!(contract.limits().rlimit_core_bytes(), 0);
        assert_eq!(contract.limits().term_grace_milliseconds(), 250);
        assert_eq!(contract.limits().teardown_deadline_milliseconds(), 5_000);
        assert!(!contract.launch_authority_present());
        assert!(!contract.sync_back_permitted());

        let value: serde_json::Value =
            serde_json::from_slice(contract.canonical_json_v1()).expect("canonical JSON");
        assert_eq!(value["caller_process_input_present"], false);
        assert_eq!(value["launch_authority_present"], false);
        assert_eq!(value["package_execution"], false);
        assert_eq!(value["public_network_route_present"], false);
        assert_eq!(value["sync_back"], false);
        assert_eq!(
            contract.launch_contract_sha256(),
            &Sha256Digest::from_bytes(contract.canonical_json_v1())
        );
        let identity =
            LinuxVzPackageProcessLaunchIdentityV1::from_contract_v1(&contract).expect("identity");
        let canonical_argv =
            serde_json_canonicalizer::to_vec(&contract.argv()).expect("canonical argv");
        assert_eq!(
            identity.executable_sha256(),
            contract.expected_executable_sha256()
        );
        assert_eq!(
            identity.argv_sha256(),
            &Sha256Digest::from_bytes(&canonical_argv)
        );
        assert_eq!(identity.argv_item_count(), contract.argv().len());
        assert!(!format!("{identity:?}").contains("package.tgz"));
    }

    #[test]
    fn closure_launch_cannot_execute_or_be_attributed_as_target_lifecycle() {
        let plan = npm_closure_plan();
        let closure = derive_linux_vz_package_process_launch_contract_v1(
            &plan,
            2,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("closure launch contract");
        let target = derive_linux_vz_package_process_launch_contract_v1(
            &plan,
            3,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("target launch contract");

        assert_eq!(
            closure.stage_name(),
            "npm_preinstall_exact_dependency_closure"
        );
        assert!(closure
            .argv()
            .iter()
            .any(|value| value == "--ignore-scripts=true"));
        assert!(closure
            .argv()
            .iter()
            .any(|value| value == "/run/whoathere/closure/left-pad-1.3.0.tgz"));
        assert!(closure
            .argv()
            .iter()
            .all(|value| !value.starts_with("/run/whoathere/input/")));
        for forbidden in [
            "CI",
            "NODE_OPTIONS",
            "NPM_TOKEN",
            "GITHUB_TOKEN",
            "AWS_ACCESS_KEY_ID",
        ] {
            assert!(!closure.environment().contains_key(forbidden));
        }
        assert_eq!(closure.measured_inputs().len(), 1);
        assert_eq!(
            closure.measured_inputs()[0].role(),
            MacosLinuxVzPackageMeasuredProcessInputRoleV1::NpmCli
        );

        assert_eq!(target.stage_name(), "npm_install_exact_local_tarball");
        assert!(target
            .argv()
            .iter()
            .any(|value| value == "--ignore-scripts=false"));
        assert_eq!(
            target.argv().last().map(String::as_str),
            Some("/run/whoathere/input/package.tgz")
        );
        assert!(target
            .argv()
            .iter()
            .all(|value| !value.starts_with("/run/whoathere/closure/")));
        assert!(target.environment().contains_key("NODE_OPTIONS"));
        assert!(target.environment().contains_key("NPM_TOKEN"));
        assert_eq!(target.measured_inputs().len(), 2);
        assert_ne!(closure.stage_name(), target.stage_name());
        assert_ne!(
            closure.launch_contract_sha256(),
            target.launch_contract_sha256()
        );
    }

    #[test]
    fn internal_action_and_unexpected_bindings_fail_closed() {
        let plan = npm_plan(NpmEnvironmentProfileV1::CiFalse);
        assert_eq!(
            derive_linux_vz_package_process_launch_contract_v1(
                &plan,
                0,
                &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
            ),
            Err(LinuxVzPackageProcessLaunchContractErrorV1::InvalidAction)
        );
        assert_eq!(
            derive_linux_vz_package_process_launch_contract_v1(
                &plan,
                1,
                &ValidatedLinuxVzPackageDynamicProcessBindingsV1::for_test_v1(Some((
                    "/run/whoathere/derived/unexpected.whl",
                    Sha256Digest::from_bytes(b"unexpected wheel"),
                )),),
            ),
            Err(LinuxVzPackageProcessLaunchContractErrorV1::DynamicBindingUnexpected)
        );
    }

    #[test]
    fn typed_environment_changes_the_launch_contract() {
        let false_plan = npm_plan(NpmEnvironmentProfileV1::CiFalse);
        let true_plan = npm_plan(NpmEnvironmentProfileV1::CiTrue);
        let false_contract = derive_linux_vz_package_process_launch_contract_v1(
            &false_plan,
            1,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("CI false launch contract");
        let true_contract = derive_linux_vz_package_process_launch_contract_v1(
            &true_plan,
            1,
            &ValidatedLinuxVzPackageDynamicProcessBindingsV1::none(),
        )
        .expect("CI true launch contract");
        let mut false_environment = false_contract.environment().clone();
        let mut true_environment = true_contract.environment().clone();
        assert_eq!(false_environment.remove("CI"), None);
        assert_eq!(true_environment.remove("CI"), Some("true".to_string()));
        assert_eq!(false_environment, true_environment);
        assert!(false_environment
            .get("NPM_TOKEN")
            .is_some_and(|value| value.starts_with("npm_") && value.len() == 40));
        assert!(false_environment
            .get("GITHUB_TOKEN")
            .is_some_and(|value| value.starts_with("ghp_") && value.len() == 40));
        assert!(false_environment
            .get("AWS_ACCESS_KEY_ID")
            .is_some_and(|value| value.starts_with("AKIA") && value.len() == 20));
        assert_ne!(
            false_contract.launch_contract_sha256(),
            true_contract.launch_contract_sha256()
        );
        let raw_canary = false_environment
            .get("NPM_TOKEN")
            .expect("fake npm token canary");
        assert!(!format!("{false_contract:?}").contains(raw_canary));
        assert!(!format!("{true_contract:?}").contains(raw_canary));
    }
}
