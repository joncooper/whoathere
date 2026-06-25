#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionMode {
    Observe,
    BetaContainment,
    Protected,
    CiFailClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutageBehavior {
    Block,
    AllowApprovedStale,
    WarnApprovedStale,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentBackend {
    LinuxNamespace,
    MacosVmBeta,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainmentStrength {
    Strong,
    Beta,
    TelemetryOnly,
    FailedClosed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassSignal {
    None,
    AbsoluteBinary,
    PythonModule,
    NestedPackageManager,
    DirectRegistryEgress,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ecosystem {
    Npm,
    Pypi,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandKind {
    VersionProbe,
    NpmInstall,
    NpmCi,
    NpmExec,
    PipInstall,
    PythonModulePipInstall,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowRisk {
    Low,
    Medium,
    High,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandClassification {
    pub ecosystem: Ecosystem,
    pub kind: CommandKind,
    pub risk: WorkflowRisk,
    pub protected: bool,
    pub reason_codes: Vec<String>,
    pub bypass_signal: BypassSignal,
}

impl CommandClassification {
    pub fn unsupported(reason: impl Into<String>) -> Self {
        Self {
            ecosystem: Ecosystem::Unknown,
            kind: CommandKind::Unknown,
            risk: WorkflowRisk::Unsupported,
            protected: false,
            reason_codes: vec![reason.into()],
            bypass_signal: BypassSignal::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitCode {
    Allow,
    Deny,
    Quarantine,
    ManualReview,
    Misuse,
    InternalError,
}

impl ExitCode {
    pub fn code(self) -> i32 {
        match self {
            ExitCode::Allow => 0,
            ExitCode::Deny => 20,
            ExitCode::Quarantine => 21,
            ExitCode::ManualReview => 22,
            ExitCode::Misuse => 64,
            ExitCode::InternalError => 70,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoaThereConfig {
    pub schema_version: String,
    pub mode: ExecutionMode,
    pub outage_behavior: OutageBehavior,
    pub telemetry_redacted_remote: bool,
    pub vault_url: Option<String>,
}

impl Default for WhoaThereConfig {
    fn default() -> Self {
        Self {
            schema_version: "0.1.0".to_string(),
            mode: ExecutionMode::Protected,
            outage_behavior: OutageBehavior::Block,
            telemetry_redacted_remote: false,
            vault_url: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigError {
    UnknownKey(String),
    InvalidValue { key: String, value: String },
}

pub fn parse_config_kv(input: &str) -> Result<WhoaThereConfig, ConfigError> {
    let mut config = WhoaThereConfig::default();
    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(ConfigError::InvalidValue {
                key: line.to_string(),
                value: String::new(),
            });
        };
        let key = key.trim();
        let value = value.trim();
        match key {
            "schema_version" => {
                if value != "0.1.0" {
                    return Err(ConfigError::InvalidValue {
                        key: key.to_string(),
                        value: value.to_string(),
                    });
                }
                config.schema_version = value.to_string();
            }
            "mode" => {
                config.mode = parse_mode(value).ok_or_else(|| ConfigError::InvalidValue {
                    key: key.to_string(),
                    value: value.to_string(),
                })?
            }
            "outage_behavior" => {
                config.outage_behavior =
                    parse_outage_behavior(value).ok_or_else(|| ConfigError::InvalidValue {
                        key: key.to_string(),
                        value: value.to_string(),
                    })?
            }
            "telemetry_redacted_remote" => {
                config.telemetry_redacted_remote =
                    parse_bool(value).ok_or_else(|| ConfigError::InvalidValue {
                        key: key.to_string(),
                        value: value.to_string(),
                    })?
            }
            "vault.url" | "vault_url" => {
                if value.is_empty() || value.contains(char::is_whitespace) {
                    return Err(ConfigError::InvalidValue {
                        key: key.to_string(),
                        value: value.to_string(),
                    });
                }
                config.vault_url = Some(value.to_string());
            }
            _ => return Err(ConfigError::UnknownKey(key.to_string())),
        }
    }
    Ok(config)
}

fn parse_mode(value: &str) -> Option<ExecutionMode> {
    match value {
        "observe" => Some(ExecutionMode::Observe),
        "beta_containment" => Some(ExecutionMode::BetaContainment),
        "protected" => Some(ExecutionMode::Protected),
        "ci_fail_closed" => Some(ExecutionMode::CiFailClosed),
        _ => None,
    }
}

fn parse_outage_behavior(value: &str) -> Option<OutageBehavior> {
    match value {
        "block" => Some(OutageBehavior::Block),
        "allow_approved_stale" => Some(OutageBehavior::AllowApprovedStale),
        "warn_approved_stale" => Some(OutageBehavior::WarnApprovedStale),
        _ => None,
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageContext {
    pub ecosystem: String,
    pub package: Option<String>,
    pub version_or_range: Option<String>,
    pub source_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointEvent {
    pub schema_version: String,
    pub correlation_id: String,
    pub observed_command: String,
    pub execution_mode: ExecutionMode,
    pub containment_backend: ContainmentBackend,
    pub containment_strength: ContainmentStrength,
    pub bypass_signal: BypassSignal,
}

impl EndpointEvent {
    pub fn new(correlation_id: impl Into<String>, observed_command: impl Into<String>) -> Self {
        Self {
            schema_version: "0.1.0".to_string(),
            correlation_id: correlation_id.into(),
            observed_command: observed_command.into(),
            execution_mode: ExecutionMode::Protected,
            containment_backend: ContainmentBackend::None,
            containment_strength: ContainmentStrength::FailedClosed,
            bypass_signal: BypassSignal::None,
        }
    }
}

pub fn macos_beta_label(backend_available: bool) -> &'static str {
    if backend_available {
        "macOS beta containment"
    } else {
        "macOS telemetry/interception only"
    }
}

pub fn classify_package_command(invoked: &str, args: &[String]) -> CommandClassification {
    let invoked_name = basename(invoked);
    if invoked_name == "npx" {
        if is_readonly_version_probe(args) {
            return version_probe_classification(Ecosystem::Npm);
        }
        return npm_exec_classification("npx_transient_execution");
    }

    if invoked_name == "npm" {
        return classify_npm(args);
    }

    if invoked_name == "pip" || invoked_name == "pip3" {
        return classify_pip(args, CommandKind::PipInstall);
    }

    if (invoked_name == "python" || invoked_name == "python3") && is_python_module_pip(args) {
        let remaining = args.iter().skip(2).cloned().collect::<Vec<_>>();
        return classify_pip(&remaining, CommandKind::PythonModulePipInstall);
    }

    CommandClassification::unsupported("unsupported_tool")
}

fn classify_npm(args: &[String]) -> CommandClassification {
    if is_readonly_version_probe(args) {
        return version_probe_classification(Ecosystem::Npm);
    }

    let first_command = args
        .iter()
        .find(|arg| !arg.starts_with('-'))
        .map(String::as_str);
    let source_override = args.iter().any(|arg| {
        arg == "--registry"
            || arg.starts_with("--registry=")
            || arg == "--ignore-scripts=false"
            || arg == "--foreground-scripts"
            || arg.starts_with("http://")
            || arg.starts_with("https://")
            || arg.starts_with("git+")
            || arg.contains("github:")
    });

    let mut reasons = Vec::new();
    let bypass_signal = if source_override {
        reasons.push("npm_source_or_lifecycle_override".to_string());
        BypassSignal::DirectRegistryEgress
    } else {
        BypassSignal::None
    };

    match first_command {
        Some("ci") => {
            reasons.push("npm_ci_lockfile_install".to_string());
            CommandClassification {
                ecosystem: Ecosystem::Npm,
                kind: CommandKind::NpmCi,
                risk: if source_override {
                    WorkflowRisk::High
                } else {
                    WorkflowRisk::Medium
                },
                protected: !source_override,
                reason_codes: reasons,
                bypass_signal,
            }
        }
        Some("install") | Some("i") | Some("add") => {
            reasons.push("npm_install_lifecycle_capable".to_string());
            CommandClassification {
                ecosystem: Ecosystem::Npm,
                kind: CommandKind::NpmInstall,
                risk: WorkflowRisk::High,
                protected: !source_override,
                reason_codes: reasons,
                bypass_signal,
            }
        }
        Some("exec") | Some("x") => npm_exec_classification("npm_exec_transient_execution"),
        _ => CommandClassification::unsupported("unsupported_npm_workflow"),
    }
}

fn npm_exec_classification(reason: &str) -> CommandClassification {
    CommandClassification {
        ecosystem: Ecosystem::Npm,
        kind: CommandKind::NpmExec,
        risk: WorkflowRisk::High,
        protected: false,
        reason_codes: vec![reason.to_string()],
        bypass_signal: BypassSignal::NestedPackageManager,
    }
}

fn classify_pip(args: &[String], kind: CommandKind) -> CommandClassification {
    if is_readonly_version_probe(args) {
        return version_probe_classification(Ecosystem::Pypi);
    }

    let install = args.iter().any(|arg| arg == "install");
    if !install {
        return CommandClassification::unsupported("unsupported_pip_workflow");
    }

    let source_override = args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "--index-url" | "-i" | "--extra-index-url" | "--find-links" | "-f" | "--no-index"
        ) || arg.starts_with("--index-url=")
            || arg.starts_with("--extra-index-url=")
            || arg.starts_with("--find-links=")
            || arg.starts_with("http://")
            || arg.starts_with("https://")
            || arg.starts_with("git+")
    });

    let mut reasons = vec!["pip_install_build_backend_capable".to_string()];
    if kind == CommandKind::PythonModulePipInstall {
        reasons.push("python_module_pip".to_string());
    }

    CommandClassification {
        ecosystem: Ecosystem::Pypi,
        kind,
        risk: WorkflowRisk::High,
        protected: !source_override,
        reason_codes: if source_override {
            reasons.push("pip_source_override".to_string());
            reasons
        } else {
            reasons
        },
        bypass_signal: if source_override {
            BypassSignal::DirectRegistryEgress
        } else if kind == CommandKind::PythonModulePipInstall {
            BypassSignal::PythonModule
        } else {
            BypassSignal::None
        },
    }
}

fn version_probe_classification(ecosystem: Ecosystem) -> CommandClassification {
    CommandClassification {
        ecosystem,
        kind: CommandKind::VersionProbe,
        risk: WorkflowRisk::Low,
        protected: true,
        reason_codes: vec!["readonly_version_probe".to_string()],
        bypass_signal: BypassSignal::None,
    }
}

fn is_readonly_version_probe(args: &[String]) -> bool {
    matches!(args, [arg] if arg == "--version" || arg == "-v" || arg == "-V")
}

fn is_python_module_pip(args: &[String]) -> bool {
    matches!(
        args,
        [flag, module, command, ..]
            if flag == "-m" && module == "pip" && command == "install"
    )
}

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_blocks_on_outage() {
        let config = WhoaThereConfig::default();
        assert_eq!(config.outage_behavior, OutageBehavior::Block);
        assert_eq!(config.vault_url, None);
    }

    #[test]
    fn parses_vault_url_config() {
        let config =
            parse_config_kv("schema_version=0.1.0\nvault.url=https://vault.example.test\n")
                .expect("config should parse");
        assert_eq!(
            config.vault_url,
            Some("https://vault.example.test".to_string())
        );
    }

    #[test]
    fn endpoint_event_defaults_fail_closed() {
        let event = EndpointEvent::new("c1", "npm install");
        assert_eq!(
            event.containment_strength,
            ContainmentStrength::FailedClosed
        );
    }

    #[test]
    fn macos_label_is_explicit_beta_or_telemetry() {
        assert_eq!(macos_beta_label(true), "macOS beta containment");
        assert_eq!(macos_beta_label(false), "macOS telemetry/interception only");
    }

    #[test]
    fn classifies_npm_ci_as_protected_medium_risk() {
        let args = vec!["ci".to_string()];
        let classification = classify_package_command("npm", &args);
        assert_eq!(classification.ecosystem, Ecosystem::Npm);
        assert_eq!(classification.kind, CommandKind::NpmCi);
        assert_eq!(classification.risk, WorkflowRisk::Medium);
        assert!(classification.protected);
    }

    #[test]
    fn detects_npm_registry_override() {
        let args = vec![
            "install".to_string(),
            "--registry=https://example.test".to_string(),
        ];
        let classification = classify_package_command("npm", &args);
        assert_eq!(
            classification.bypass_signal,
            BypassSignal::DirectRegistryEgress
        );
        assert!(!classification.protected);
    }

    #[test]
    fn detects_npm_direct_url_source() {
        let args = vec![
            "install".to_string(),
            "https://example.test/package.tgz".to_string(),
        ];
        let classification = classify_package_command("npm", &args);
        assert_eq!(
            classification.bypass_signal,
            BypassSignal::DirectRegistryEgress
        );
        assert!(!classification.protected);
    }

    #[test]
    fn classifies_python_module_pip() {
        let args = vec![
            "-m".to_string(),
            "pip".to_string(),
            "install".to_string(),
            "example".to_string(),
        ];
        let classification = classify_package_command("python3", &args);
        assert_eq!(classification.ecosystem, Ecosystem::Pypi);
        assert_eq!(classification.kind, CommandKind::PythonModulePipInstall);
        assert_eq!(classification.bypass_signal, BypassSignal::PythonModule);
    }

    #[test]
    fn exit_codes_are_stable() {
        assert_eq!(ExitCode::Allow.code(), 0);
        assert_eq!(ExitCode::Deny.code(), 20);
        assert_eq!(ExitCode::Misuse.code(), 64);
    }

    #[test]
    fn classifies_version_probe_as_low_risk() {
        let args = vec!["--version".to_string()];
        let classification = classify_package_command("npm", &args);
        assert_eq!(classification.kind, CommandKind::VersionProbe);
        assert_eq!(classification.risk, WorkflowRisk::Low);
        assert!(classification.protected);
    }

    #[test]
    fn parses_local_config_kv() {
        let config = parse_config_kv(
            r#"
            mode=ci_fail_closed
            outage_behavior=block
            telemetry_redacted_remote=true
            "#,
        )
        .expect("config should parse");
        assert_eq!(config.mode, ExecutionMode::CiFailClosed);
        assert_eq!(config.outage_behavior, OutageBehavior::Block);
        assert!(config.telemetry_redacted_remote);
    }

    #[test]
    fn rejects_unknown_config_key() {
        let error = parse_config_kv("collect_secrets=true").unwrap_err();
        assert_eq!(
            error,
            ConfigError::UnknownKey("collect_secrets".to_string())
        );
    }

    #[test]
    fn rejects_unknown_config_schema_version() {
        let error = parse_config_kv("schema_version=9.9.9").unwrap_err();
        assert_eq!(
            error,
            ConfigError::InvalidValue {
                key: "schema_version".to_string(),
                value: "9.9.9".to_string()
            }
        );
    }
}
