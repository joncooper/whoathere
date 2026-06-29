use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

use whoathere_evidence::{EvidenceJobKind, EvidenceJobResult, JobState};
use whoathere_hash::sha256_digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Info,
    Suspicious,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticFinding {
    pub severity: FindingSeverity,
    pub reason_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticScanReport {
    pub findings: Vec<StaticFinding>,
}

impl StaticScanReport {
    pub fn passed(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::High)
    }

    pub fn to_job_result(&self) -> EvidenceJobResult {
        self.to_job_result_for("detector-static-manifest-unbound")
    }

    pub fn to_job_result_for(&self, job_id: &str) -> EvidenceJobResult {
        let state = if self.passed() {
            JobState::Passed
        } else {
            JobState::Failed
        };
        let reason_codes = self
            .findings
            .iter()
            .map(|finding| finding.reason_code.clone())
            .collect::<Vec<_>>();
        EvidenceJobResult {
            job_id: job_id.to_string(),
            job_kind: EvidenceJobKind::StaticManifest,
            state,
            log_digest: static_scan_log_digest(StaticScanDigestInput {
                job_id,
                profile_id: "unbound",
                profile_version: 0,
                artifact_digest: "unbound",
                cache_object_key: "unbound",
                manifest_kind: "unknown",
                state,
                findings: &self.findings,
                reason_codes: &reason_codes,
            }),
            reason_codes,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StaticManifestKind {
    NpmPackageJson,
    PyprojectToml,
}

impl StaticManifestKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NpmPackageJson => "npm-package-json",
            Self::PyprojectToml => "pyproject.toml",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaticManifestJobRequest<'a> {
    pub job_id: &'a str,
    pub profile_id: &'a str,
    pub profile_version: u16,
    pub artifact_digest: &'a str,
    pub cache_object_key: &'a str,
    pub manifest_kind: StaticManifestKind,
    pub manifest_contents: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticManifestJobOutput {
    pub job_id: String,
    pub job_kind: EvidenceJobKind,
    pub state: JobState,
    pub log_digest: String,
    pub summary_schema: String,
    pub sanitized_log_summary: String,
    pub reason_codes: Vec<String>,
    pub execution_enabled: bool,
    pub detonation_attempted: bool,
    pub network_attempted: bool,
    pub raw_log_captured: bool,
    pub audit_event_id: String,
}

pub fn run_static_manifest_job(request: StaticManifestJobRequest<'_>) -> StaticManifestJobOutput {
    let mut report = match request.manifest_kind {
        StaticManifestKind::NpmPackageJson => scan_npm_package_json(request.manifest_contents),
        StaticManifestKind::PyprojectToml => scan_pyproject_toml(request.manifest_contents),
    };
    if request.manifest_contents.trim().is_empty() {
        report.findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "static_manifest_empty".to_string(),
            detail: "static manifest job received empty manifest contents".to_string(),
        });
    }
    let mut reason_codes = report
        .findings
        .iter()
        .map(|finding| finding.reason_code.clone())
        .collect::<Vec<_>>();
    let metadata_valid = validate_static_job_request(&request, &mut reason_codes);
    let state = if report.passed() && metadata_valid {
        JobState::Passed
    } else {
        JobState::Failed
    };
    let summary_schema = STATIC_MANIFEST_SUMMARY_SCHEMA.to_string();
    let sanitized_log_summary = static_scan_log_summary(StaticScanDigestInput {
        job_id: request.job_id,
        profile_id: request.profile_id,
        profile_version: request.profile_version,
        artifact_digest: request.artifact_digest,
        cache_object_key: request.cache_object_key,
        manifest_kind: request.manifest_kind.as_str(),
        state,
        findings: &report.findings,
        reason_codes: &reason_codes,
    });
    let log_digest = sha256_digest(sanitized_log_summary.as_bytes());
    let audit_event_id = format!(
        "audit-static-manifest-{}",
        log_digest
            .strip_prefix("sha256:")
            .unwrap_or_default()
            .chars()
            .take(16)
            .collect::<String>()
    );
    StaticManifestJobOutput {
        job_id: request.job_id.to_string(),
        job_kind: EvidenceJobKind::StaticManifest,
        state,
        log_digest,
        summary_schema,
        sanitized_log_summary,
        reason_codes,
        execution_enabled: false,
        detonation_attempted: false,
        network_attempted: false,
        raw_log_captured: false,
        audit_event_id,
    }
}

pub fn scan_npm_package_json(contents: &str) -> StaticScanReport {
    let mut findings = Vec::new();
    match collect_json_key_paths(contents) {
        Ok(key_paths) => {
            for key_path in key_paths {
                if key_path.len() == 2
                    && key_path[0] == "scripts"
                    && NPM_INSTALL_LIFECYCLE_SCRIPTS.contains(&key_path[1].as_str())
                {
                    findings.push(StaticFinding {
                        severity: FindingSeverity::High,
                        reason_code: format!(
                            "npm_lifecycle_{}",
                            reason_fragment_for_script(&key_path[1])
                        ),
                        detail: format!("package.json declares {} lifecycle script", key_path[1]),
                    });
                }
            }
        }
        Err(_) => findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "npm_package_json_malformed".to_string(),
            detail: "package.json is not valid supported JSON".to_string(),
        }),
    }
    if contents.trim().is_empty() {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "npm_package_json_empty".to_string(),
            detail: "package.json is empty".to_string(),
        });
    }
    if contains_exfil_hint(contents) {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "npm_static_exfil_hint".to_string(),
            detail: "manifest or scripts contain network/credential access indicators".to_string(),
        });
    }
    StaticScanReport { findings }
}

pub fn scan_pyproject_toml(contents: &str) -> StaticScanReport {
    let mut findings = Vec::new();
    if !looks_like_supported_pyproject_toml(contents) {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "pypi_pyproject_malformed".to_string(),
            detail: "pyproject.toml is not valid supported TOML shape".to_string(),
        });
    }
    if contents.contains("build-backend") {
        findings.push(StaticFinding {
            severity: FindingSeverity::Suspicious,
            reason_code: "pypi_pep517_build_backend".to_string(),
            detail: "pyproject.toml declares a PEP 517 build backend".to_string(),
        });
    }
    if contains_exfil_hint(contents) {
        findings.push(StaticFinding {
            severity: FindingSeverity::High,
            reason_code: "pypi_static_exfil_hint".to_string(),
            detail: "build metadata contains network/credential access indicators".to_string(),
        });
    }
    StaticScanReport { findings }
}

const NPM_INSTALL_LIFECYCLE_SCRIPTS: &[&str] = &[
    "preinstall",
    "install",
    "postinstall",
    "prepublish",
    "preprepare",
    "prepare",
    "postprepare",
    "prepack",
    "postpack",
];
const STATIC_MANIFEST_SUMMARY_SCHEMA: &str = "whoathere.static_manifest_job.v1";
pub const EXTERNAL_SCANNER_RUN_SCHEMA: &str = "whoathere.external_scanner_run.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerExecutionRole {
    Core,
    ReportOnly,
}

impl ScannerExecutionRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::ReportOnly => "report_only",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerEcosystem {
    Auto,
    Npm,
    Pypi,
}

impl ScannerEcosystem {
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "auto" => Some(Self::Auto),
            "npm" => Some(Self::Npm),
            "pypi" | "pip" | "python" => Some(Self::Pypi),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Npm => "npm",
            Self::Pypi => "pypi",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerRunStatus {
    Passed,
    Findings,
    Unavailable,
    NotApplicable,
    Error,
    TimedOut,
}

impl ScannerRunStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Passed => "passed",
            Self::Findings => "findings",
            Self::Unavailable => "unavailable",
            Self::NotApplicable => "not_applicable",
            Self::Error => "error",
            Self::TimedOut => "timed_out",
        }
    }

    pub fn scanner_clean(self) -> bool {
        matches!(self, Self::Passed | Self::NotApplicable)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalScannerSpec {
    pub name: &'static str,
    pub role: ScannerExecutionRole,
    pub evidence_role: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalScannerInventoryItem {
    pub spec: ExternalScannerSpec,
    pub available: bool,
    pub display_path: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalScannerCommandPlan {
    pub scanner: String,
    pub role: ScannerExecutionRole,
    pub ecosystem: ScannerEcosystem,
    pub status: ScannerRunStatus,
    pub executable: Option<PathBuf>,
    pub display_path: Option<String>,
    pub argv: Vec<String>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalScannerRunRecord {
    pub schema_version: &'static str,
    pub scanner: String,
    pub role: ScannerExecutionRole,
    pub ecosystem: ScannerEcosystem,
    pub status: ScannerRunStatus,
    pub display_path: Option<String>,
    pub argv: Vec<String>,
    pub exit_code: Option<i32>,
    pub elapsed_ms: u128,
    pub timed_out: bool,
    pub stdout_sha256: Option<String>,
    pub stderr_sha256: Option<String>,
    pub stdout_bytes: usize,
    pub stderr_bytes: usize,
    pub finding_count: u32,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExternalScannerRunSummary {
    pub schema_version: &'static str,
    pub workspace_kind: String,
    pub requested_ecosystem: ScannerEcosystem,
    pub effective_ecosystem: ScannerEcosystem,
    pub execute_requested: bool,
    pub timeout_seconds: u64,
    pub scanner_clean: bool,
    pub core_scanner_count: usize,
    pub core_scanner_runnable_count: usize,
    pub reason_codes: Vec<String>,
    pub records: Vec<ExternalScannerRunRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScannerProcessObservation {
    exit_code: Option<i32>,
    elapsed_ms: u128,
    stdout_sha256: Option<String>,
    stderr_sha256: Option<String>,
    stdout_bytes: usize,
    stderr_bytes: usize,
    timed_out: bool,
    finding_count: u32,
}

impl ScannerProcessObservation {
    fn empty() -> Self {
        Self {
            exit_code: None,
            elapsed_ms: 0,
            stdout_sha256: None,
            stderr_sha256: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            timed_out: false,
            finding_count: 0,
        }
    }

    fn error(elapsed_ms: u128) -> Self {
        Self {
            elapsed_ms,
            ..Self::empty()
        }
    }
}

pub fn external_scanner_specs() -> Vec<ExternalScannerSpec> {
    vec![
        ExternalScannerSpec {
            name: "guarddog",
            role: ScannerExecutionRole::Core,
            evidence_role: "malicious package static indicators",
        },
        ExternalScannerSpec {
            name: "osv-scanner",
            role: ScannerExecutionRole::Core,
            evidence_role: "known vulnerability evidence",
        },
        ExternalScannerSpec {
            name: "pip-audit",
            role: ScannerExecutionRole::Core,
            evidence_role: "Python dependency vulnerability evidence",
        },
        ExternalScannerSpec {
            name: "syft",
            role: ScannerExecutionRole::Core,
            evidence_role: "SBOM evidence",
        },
        ExternalScannerSpec {
            name: "grype",
            role: ScannerExecutionRole::Core,
            evidence_role: "SBOM vulnerability evidence",
        },
        ExternalScannerSpec {
            name: "trivy",
            role: ScannerExecutionRole::ReportOnly,
            evidence_role: "alternate filesystem vulnerability and secret evidence",
        },
        ExternalScannerSpec {
            name: "scorecard",
            role: ScannerExecutionRole::ReportOnly,
            evidence_role: "source repository reputation evidence",
        },
    ]
}

pub fn scanner_inventory() -> Vec<ExternalScannerInventoryItem> {
    external_scanner_specs()
        .into_iter()
        .map(|spec| {
            let executable = resolve_scanner_executable(spec.name);
            let available = executable.is_some();
            let display_path = executable.as_ref().map(|path| display_scanner_path(path));
            let version = executable
                .as_ref()
                .and_then(|path| scanner_version(spec.name, path));
            ExternalScannerInventoryItem {
                spec,
                available,
                display_path,
                version,
            }
        })
        .collect()
}

pub fn scanner_bootstrap_cache_dir() -> PathBuf {
    if let Some(path) = std::env::var_os("WHOATHERE_SCANNER_CACHE_DIR") {
        return PathBuf::from(path);
    }
    std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join(".whoathere")
        .join("scanners")
}

pub fn scanner_bootstrap_receipt_path() -> PathBuf {
    scanner_bootstrap_cache_dir().join("scanner-bootstrap.json")
}

pub fn scanner_bootstrap_receipt_present() -> bool {
    scanner_bootstrap_receipt_path().is_file()
}

pub fn plan_external_scanner_run(
    workspace: &Path,
    requested_ecosystem: ScannerEcosystem,
) -> ExternalScannerRunSummary {
    build_external_scanner_summary(workspace, requested_ecosystem, 120, false)
}

pub fn run_external_scanners(
    workspace: &Path,
    requested_ecosystem: ScannerEcosystem,
    timeout_seconds: u64,
    execute: bool,
) -> ExternalScannerRunSummary {
    build_external_scanner_summary(workspace, requested_ecosystem, timeout_seconds, execute)
}

fn build_external_scanner_summary(
    workspace: &Path,
    requested_ecosystem: ScannerEcosystem,
    timeout_seconds: u64,
    execute: bool,
) -> ExternalScannerRunSummary {
    let effective_ecosystem = effective_scanner_ecosystem(workspace, requested_ecosystem);
    let plans = external_scanner_plans(workspace, effective_ecosystem);
    let core_scanner_count = plans
        .iter()
        .filter(|plan| plan.role == ScannerExecutionRole::Core)
        .count();
    let core_scanner_runnable_count = plans
        .iter()
        .filter(|plan| {
            plan.role == ScannerExecutionRole::Core
                && !matches!(
                    plan.status,
                    ScannerRunStatus::Unavailable | ScannerRunStatus::NotApplicable
                )
        })
        .count();
    let mut records = Vec::new();
    for plan in plans {
        records.push(if execute {
            execute_scanner_plan(plan, timeout_seconds)
        } else {
            dry_run_scanner_record(plan)
        });
    }
    let mut reason_codes = Vec::new();
    if requested_ecosystem == ScannerEcosystem::Auto
        && effective_ecosystem == ScannerEcosystem::Auto
    {
        reason_codes.push("scanner_workspace_ecosystem_unknown".to_string());
    }
    if !execute {
        reason_codes.push("scanner_execution_requires_execute".to_string());
    }
    for record in &records {
        if !record.status.scanner_clean() {
            reason_codes.push(format!("scanner_{}_not_clean", record.scanner));
        }
    }
    reason_codes.sort();
    reason_codes.dedup();
    let scanner_clean = execute
        && records
            .iter()
            .filter(|record| record.role == ScannerExecutionRole::Core)
            .all(|record| record.status.scanner_clean());
    ExternalScannerRunSummary {
        schema_version: EXTERNAL_SCANNER_RUN_SCHEMA,
        workspace_kind: workspace_kind(workspace).to_string(),
        requested_ecosystem,
        effective_ecosystem,
        execute_requested: execute,
        timeout_seconds,
        scanner_clean,
        core_scanner_count,
        core_scanner_runnable_count,
        reason_codes,
        records,
    }
}

fn external_scanner_plans(
    workspace: &Path,
    ecosystem: ScannerEcosystem,
) -> Vec<ExternalScannerCommandPlan> {
    external_scanner_specs()
        .into_iter()
        .map(|spec| plan_external_scanner(workspace, ecosystem, spec))
        .collect()
}

fn plan_external_scanner(
    workspace: &Path,
    ecosystem: ScannerEcosystem,
    spec: ExternalScannerSpec,
) -> ExternalScannerCommandPlan {
    let mut plan = ExternalScannerCommandPlan {
        scanner: spec.name.to_string(),
        role: spec.role,
        ecosystem,
        status: ScannerRunStatus::Passed,
        executable: resolve_scanner_executable(spec.name),
        display_path: None,
        argv: Vec::new(),
        reason_codes: Vec::new(),
    };
    plan.display_path = plan
        .executable
        .as_ref()
        .map(|path| display_scanner_path(path));
    if spec.role == ScannerExecutionRole::ReportOnly {
        plan.status = ScannerRunStatus::NotApplicable;
        plan.reason_codes
            .push("scanner_report_only_not_executed_in_core_goal".to_string());
        return plan;
    }
    if plan.executable.is_none() {
        plan.status = ScannerRunStatus::Unavailable;
        plan.reason_codes.push(format!(
            "scanner_{}_unavailable",
            spec.name.replace('-', "_")
        ));
        return plan;
    }
    match spec.name {
        "guarddog" => plan_guarddog(workspace, ecosystem, &mut plan),
        "osv-scanner" => {
            plan.argv = vec![
                "scan".to_string(),
                "source".to_string(),
                "--recursive".to_string(),
                "--format".to_string(),
                "json".to_string(),
                "--no-resolve".to_string(),
                workspace.display().to_string(),
            ];
        }
        "pip-audit" => plan_pip_audit(workspace, ecosystem, &mut plan),
        "syft" => {
            plan.argv = vec![
                workspace.display().to_string(),
                "-o".to_string(),
                "syft-json".to_string(),
            ];
        }
        "grype" => {
            plan.argv = vec![
                workspace.display().to_string(),
                "-o".to_string(),
                "json".to_string(),
                "--fail-on".to_string(),
                "medium".to_string(),
            ];
        }
        _ => {
            plan.status = ScannerRunStatus::NotApplicable;
            plan.reason_codes
                .push("scanner_adapter_not_executed_in_core_goal".to_string());
        }
    }
    plan
}

fn plan_guarddog(
    workspace: &Path,
    ecosystem: ScannerEcosystem,
    plan: &mut ExternalScannerCommandPlan,
) {
    match ecosystem {
        ScannerEcosystem::Npm => {
            plan.argv = vec![
                "npm".to_string(),
                "scan".to_string(),
                workspace.display().to_string(),
                "--output-format=json".to_string(),
            ];
        }
        ScannerEcosystem::Pypi => {
            plan.argv = vec![
                "pypi".to_string(),
                "scan".to_string(),
                workspace.display().to_string(),
                "--output-format=json".to_string(),
            ];
        }
        ScannerEcosystem::Auto => {
            plan.status = ScannerRunStatus::NotApplicable;
            plan.reason_codes
                .push("guarddog_ecosystem_unknown".to_string());
        }
    }
}

fn plan_pip_audit(
    workspace: &Path,
    ecosystem: ScannerEcosystem,
    plan: &mut ExternalScannerCommandPlan,
) {
    if ecosystem == ScannerEcosystem::Npm {
        plan.status = ScannerRunStatus::NotApplicable;
        plan.reason_codes.push("pip_audit_not_for_npm".to_string());
        return;
    }
    let requirements = find_requirements_files(workspace);
    if requirements.is_empty() {
        plan.status = ScannerRunStatus::NotApplicable;
        plan.reason_codes
            .push("pip_audit_requirements_file_missing".to_string());
        return;
    }
    let mut safe_requirements = Vec::new();
    let mut unsafe_reason = None;
    for path in requirements {
        match requirements_file_is_pinned_and_local_safe(&path) {
            Ok(()) => safe_requirements.push(path),
            Err(reason) => {
                unsafe_reason.get_or_insert(reason);
            }
        };
    }
    if safe_requirements.is_empty() {
        plan.status = ScannerRunStatus::NotApplicable;
        plan.reason_codes
            .push(unsafe_reason.unwrap_or_else(|| "pip_audit_resolution_skipped".to_string()));
        return;
    }
    let first = safe_requirements.remove(0);
    plan.argv = vec![
        "-r".to_string(),
        first.display().to_string(),
        "--format=json".to_string(),
        "--progress-spinner=off".to_string(),
        "--no-deps".to_string(),
    ];
}

fn execute_scanner_plan(
    plan: ExternalScannerCommandPlan,
    timeout_seconds: u64,
) -> ExternalScannerRunRecord {
    if matches!(
        plan.status,
        ScannerRunStatus::Unavailable | ScannerRunStatus::NotApplicable
    ) {
        return record_from_plan(plan, ScannerProcessObservation::empty());
    }
    let Some(executable) = plan.executable.clone() else {
        return record_from_plan(plan, ScannerProcessObservation::empty());
    };
    let start = Instant::now();
    let stdout_path = scanner_temp_path(&completed_safe_name(&plan.scanner), "stdout");
    let stderr_path = scanner_temp_path(&completed_safe_name(&plan.scanner), "stderr");
    let stdout_file = match std::fs::File::create(&stdout_path) {
        Ok(file) => file,
        Err(_) => {
            let mut reason_codes = plan.reason_codes.clone();
            reason_codes.push("scanner_stdout_tempfile_failed".to_string());
            let mut failed = plan;
            failed.status = ScannerRunStatus::Error;
            failed.reason_codes = reason_codes;
            return record_from_plan(
                failed,
                ScannerProcessObservation::error(start.elapsed().as_millis()),
            );
        }
    };
    let stderr_file = match std::fs::File::create(&stderr_path) {
        Ok(file) => file,
        Err(_) => {
            let _ = std::fs::remove_file(&stdout_path);
            let mut reason_codes = plan.reason_codes.clone();
            reason_codes.push("scanner_stderr_tempfile_failed".to_string());
            let mut failed = plan;
            failed.status = ScannerRunStatus::Error;
            failed.reason_codes = reason_codes;
            return record_from_plan(
                failed,
                ScannerProcessObservation::error(start.elapsed().as_millis()),
            );
        }
    };
    let mut command = Command::new(&executable);
    command.args(&plan.argv);
    command.stdout(Stdio::from(stdout_file));
    command.stderr(Stdio::from(stderr_file));
    let spawn_result = command.spawn();
    let Ok(mut child) = spawn_result else {
        let mut reason_codes = plan.reason_codes.clone();
        reason_codes.push("scanner_process_spawn_failed".to_string());
        let mut failed = plan;
        failed.status = ScannerRunStatus::Error;
        failed.reason_codes = reason_codes;
        return record_from_plan(
            failed,
            ScannerProcessObservation::error(start.elapsed().as_millis()),
        );
    };
    let timeout = Duration::from_secs(timeout_seconds.clamp(1, 300));
    let mut timed_out = false;
    let exit_status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if start.elapsed() >= timeout {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                sleep(Duration::from_millis(25));
            }
            Err(_) => break None,
        }
    };
    let stdout = std::fs::read(&stdout_path).unwrap_or_default();
    let stderr = std::fs::read(&stderr_path).unwrap_or_default();
    let _ = std::fs::remove_file(&stdout_path);
    let _ = std::fs::remove_file(&stderr_path);
    let exit_code = exit_status.and_then(|status| status.code());
    let stdout_sha256 = Some(sha256_digest(&stdout));
    let stderr_sha256 = Some(sha256_digest(&stderr));
    let finding_count = estimate_scanner_findings(&stdout, &stderr);
    let mut completed = plan;
    if timed_out {
        completed.status = ScannerRunStatus::TimedOut;
        completed
            .reason_codes
            .push("scanner_process_timed_out".to_string());
    } else if finding_count > 0 {
        completed.status = ScannerRunStatus::Findings;
        completed
            .reason_codes
            .push("scanner_findings_observed".to_string());
    } else if exit_code == Some(0) {
        completed.status = ScannerRunStatus::Passed;
    } else if completed.scanner == "grype" && exit_code.is_some() {
        completed.status = ScannerRunStatus::Findings;
        completed
            .reason_codes
            .push("scanner_grype_fail_on_threshold_triggered".to_string());
    } else {
        completed.status = ScannerRunStatus::Error;
        completed
            .reason_codes
            .push("scanner_process_error".to_string());
    }
    completed.reason_codes.sort();
    completed.reason_codes.dedup();
    record_from_plan(
        completed,
        ScannerProcessObservation {
            exit_code,
            elapsed_ms: start.elapsed().as_millis(),
            stdout_sha256,
            stderr_sha256,
            stdout_bytes: stdout.len(),
            stderr_bytes: stderr.len(),
            timed_out,
            finding_count,
        },
    )
}

fn scanner_temp_path(scanner: &str, stream: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "whoathere-scanner-{}-{}-{}-{}.tmp",
        scanner,
        stream,
        std::process::id(),
        Instant::now().elapsed().as_nanos()
    ))
}

fn completed_safe_name(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect()
}

fn dry_run_scanner_record(plan: ExternalScannerCommandPlan) -> ExternalScannerRunRecord {
    let mut dry = plan;
    if !matches!(
        dry.status,
        ScannerRunStatus::Unavailable | ScannerRunStatus::NotApplicable
    ) {
        dry.reason_codes
            .push("scanner_execution_requires_execute".to_string());
    }
    record_from_plan(dry, ScannerProcessObservation::empty())
}

fn record_from_plan(
    plan: ExternalScannerCommandPlan,
    observation: ScannerProcessObservation,
) -> ExternalScannerRunRecord {
    ExternalScannerRunRecord {
        schema_version: EXTERNAL_SCANNER_RUN_SCHEMA,
        scanner: plan.scanner,
        role: plan.role,
        ecosystem: plan.ecosystem,
        status: plan.status,
        display_path: plan.display_path,
        argv: redact_scanner_argv(&plan.argv),
        exit_code: observation.exit_code,
        elapsed_ms: observation.elapsed_ms,
        timed_out: observation.timed_out,
        stdout_sha256: observation.stdout_sha256,
        stderr_sha256: observation.stderr_sha256,
        stdout_bytes: observation.stdout_bytes,
        stderr_bytes: observation.stderr_bytes,
        finding_count: observation.finding_count,
        reason_codes: plan.reason_codes,
    }
}

fn resolve_scanner_executable(name: &str) -> Option<PathBuf> {
    let cache_candidate = scanner_bootstrap_cache_dir().join("bin").join(name);
    if cache_candidate.is_file() {
        return Some(cache_candidate);
    }
    command_path_on_path(name).or_else(|| match name {
        "guarddog" | "pip-audit" => command_path_on_path("uvx"),
        _ => None,
    })
}

fn command_path_on_path(command: &str) -> Option<PathBuf> {
    let candidate = PathBuf::from(command);
    if candidate.components().count() > 1 && candidate.is_file() {
        return Some(candidate);
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let path = dir.join(command);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn scanner_version(name: &str, executable: &Path) -> Option<String> {
    let mut args = vec!["--version".to_string()];
    if executable.file_name().and_then(|name| name.to_str()) == Some("uvx") {
        args = vec![name.to_string(), "--version".to_string()];
    } else if name == "scorecard" {
        args = vec!["version".to_string()];
    }
    let output = Command::new(executable).args(args).output().ok()?;
    let text = if output.stdout.is_empty() {
        String::from_utf8_lossy(&output.stderr).to_string()
    } else {
        String::from_utf8_lossy(&output.stdout).to_string()
    };
    let single = text
        .lines()
        .find(|line| line.chars().any(|ch| ch.is_ascii_digit()))
        .or_else(|| text.lines().next())?
        .trim();
    if single.is_empty() {
        None
    } else {
        Some(redact_summary_text(single))
    }
}

fn display_scanner_path(path: &Path) -> String {
    let cache_dir = scanner_bootstrap_cache_dir();
    if let Ok(relative) = path.strip_prefix(&cache_dir) {
        return format!("<whoathere-scanner-cache>/{}", relative.display());
    }
    if let Some(file_name) = path.file_name().and_then(|name| name.to_str()) {
        return file_name.to_string();
    }
    "<scanner-path-redacted>".to_string()
}

fn effective_scanner_ecosystem(workspace: &Path, requested: ScannerEcosystem) -> ScannerEcosystem {
    if requested != ScannerEcosystem::Auto {
        return requested;
    }
    if workspace.join("package.json").is_file() {
        return ScannerEcosystem::Npm;
    }
    if workspace.join("pyproject.toml").is_file() || !find_requirements_files(workspace).is_empty()
    {
        return ScannerEcosystem::Pypi;
    }
    ScannerEcosystem::Auto
}

fn workspace_kind(workspace: &Path) -> &'static str {
    if workspace.join("package.json").is_file() {
        "npm_project"
    } else if workspace.join("pyproject.toml").is_file() {
        "python_project"
    } else if !find_requirements_files(workspace).is_empty() {
        "python_requirements"
    } else {
        "unknown"
    }
}

fn find_requirements_files(workspace: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(workspace) else {
        return Vec::new();
    };
    let mut out = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("requirements") && name.ends_with(".txt"))
        })
        .collect::<Vec<_>>();
    out.sort();
    out
}

fn requirements_file_is_pinned_and_local_safe(path: &Path) -> Result<(), String> {
    let contents = std::fs::read_to_string(path)
        .map_err(|_| "pip_audit_requirements_unreadable".to_string())?;
    let mut package_line_seen = false;
    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("-r ")
            || line.starts_with("--requirement")
            || line.starts_with("-c ")
            || line.starts_with("--constraint")
        {
            return Err("pip_audit_nested_requirements_skipped".to_string());
        }
        if line.starts_with("-e ") || line.starts_with("--editable") {
            return Err("pip_audit_editable_requirement_skipped".to_string());
        }
        let lowered = line.to_ascii_lowercase();
        if lowered.contains("://") || lowered.starts_with("git+") {
            return Err("pip_audit_direct_or_vcs_requirement_skipped".to_string());
        }
        if !(line.contains("==")
            && !line.contains(">=")
            && !line.contains("<=")
            && !line.contains("~="))
        {
            return Err("pip_audit_unpinned_requirement_skipped".to_string());
        }
        package_line_seen = true;
    }
    if package_line_seen {
        Ok(())
    } else {
        Err("pip_audit_requirements_empty".to_string())
    }
}

fn estimate_scanner_findings(stdout: &[u8], stderr: &[u8]) -> u32 {
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(stdout).to_ascii_lowercase());
    combined.push_str(&String::from_utf8_lossy(stderr).to_ascii_lowercase());
    if combined.contains("whoathere_fake_finding") {
        return 1;
    }
    let indicators = [
        "\"vulnerabilities\":[{",
        "\"matches\":[{",
        "\"findings\":[{",
        "\"issues\":[{",
        "\"results\":[{",
        "\"malicious\":true",
        "\"severity\":\"high\"",
        "\"severity\":\"critical\"",
    ];
    indicators
        .iter()
        .filter(|indicator| combined.contains(**indicator))
        .count() as u32
}

fn redact_scanner_argv(argv: &[String]) -> Vec<String> {
    argv.iter()
        .map(|value| {
            if Path::new(value).is_absolute()
                || value.contains("/Users/")
                || value.contains("/private/")
                || value.contains("/tmp/")
            {
                "<workspace>".to_string()
            } else {
                redact_summary_text(value)
            }
        })
        .collect()
}

fn redact_summary_text(value: &str) -> String {
    let mut redacted = value.replace('\n', " ");
    if let Some(index) = redacted.find("/Users/") {
        redacted.truncate(index);
        redacted.push_str("<redacted-path>");
    }
    for marker in [
        "NPM_TOKEN",
        "PYPI_TOKEN",
        "TWINE_PASSWORD",
        "AWS_SECRET_ACCESS_KEY",
        "WHOATHERE_CANARY_TOKEN",
    ] {
        redacted = redacted.replace(marker, "<redacted>");
    }
    redacted
}

fn validate_static_job_request(
    request: &StaticManifestJobRequest<'_>,
    reason_codes: &mut Vec<String>,
) -> bool {
    let mut valid = true;
    if request.job_id.is_empty() {
        reason_codes.push("static_manifest_job_id_empty".to_string());
        valid = false;
    }
    if request.profile_id.is_empty() {
        reason_codes.push("static_manifest_profile_id_empty".to_string());
        valid = false;
    }
    if request.profile_version == 0 {
        reason_codes.push("static_manifest_profile_version_zero".to_string());
        valid = false;
    }
    for value in [
        request.job_id,
        request.profile_id,
        request.artifact_digest,
        request.cache_object_key,
    ] {
        if !summary_value_is_safe(value) {
            reason_codes.push("static_manifest_metadata_control_character".to_string());
            valid = false;
            break;
        }
    }
    if !valid_sha256_digest(request.artifact_digest) {
        reason_codes.push("static_manifest_artifact_digest_invalid".to_string());
        valid = false;
    }
    let expected_cache_key = request
        .artifact_digest
        .strip_prefix("sha256:")
        .map(|digest| format!("blobs/sha256/{digest}"));
    if expected_cache_key.as_deref() != Some(request.cache_object_key) {
        reason_codes.push("static_manifest_cache_object_key_mismatch".to_string());
        valid = false;
    }
    valid
}

fn collect_json_key_paths(contents: &str) -> Result<Vec<Vec<String>>, String> {
    let chars = contents.chars().collect::<Vec<_>>();
    let mut parser = JsonKeyPathParser {
        chars: &chars,
        index: 0,
        key_paths: Vec::new(),
    };
    parser.parse_value(&mut Vec::new())?;
    parser.skip_whitespace();
    if parser.index != chars.len() {
        return Err("trailing JSON characters".to_string());
    }
    Ok(parser.key_paths)
}

struct JsonKeyPathParser<'a> {
    chars: &'a [char],
    index: usize,
    key_paths: Vec<Vec<String>>,
}

impl JsonKeyPathParser<'_> {
    fn parse_value(&mut self, path: &mut Vec<String>) -> Result<(), String> {
        self.skip_whitespace();
        match self.peek() {
            Some('{') => self.parse_object(path),
            Some('[') => self.parse_array(path),
            Some('"') => self.parse_string().map(|_| ()),
            Some('t') => self.parse_literal("true"),
            Some('f') => self.parse_literal("false"),
            Some('n') => self.parse_literal("null"),
            Some('-' | '0'..='9') => self.parse_number(),
            _ => Err("unexpected JSON value".to_string()),
        }
    }

    fn parse_object(&mut self, path: &mut Vec<String>) -> Result<(), String> {
        self.expect('{')?;
        self.skip_whitespace();
        if self.consume('}') {
            return Ok(());
        }
        loop {
            self.skip_whitespace();
            let key = self.parse_string()?;
            let mut key_path = path.clone();
            key_path.push(key.clone());
            self.key_paths.push(key_path);
            self.skip_whitespace();
            self.expect(':')?;
            path.push(key);
            self.parse_value(path)?;
            path.pop();
            self.skip_whitespace();
            if self.consume('}') {
                return Ok(());
            }
            self.expect(',')?;
        }
    }

    fn parse_array(&mut self, path: &mut Vec<String>) -> Result<(), String> {
        self.expect('[')?;
        self.skip_whitespace();
        if self.consume(']') {
            return Ok(());
        }
        loop {
            self.parse_value(path)?;
            self.skip_whitespace();
            if self.consume(']') {
                return Ok(());
            }
            self.expect(',')?;
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        self.expect('"')?;
        let mut out = String::new();
        while let Some(ch) = self.peek() {
            self.index += 1;
            match ch {
                '"' => return Ok(out),
                '\\' => {
                    let Some(escaped) = self.peek() else {
                        return Err("unterminated escape sequence".to_string());
                    };
                    self.index += 1;
                    match escaped {
                        '"' | '\\' | '/' => out.push(escaped),
                        'b' => out.push('\u{0008}'),
                        'f' => out.push('\u{000c}'),
                        'n' => out.push('\n'),
                        'r' => out.push('\r'),
                        't' => out.push('\t'),
                        'u' => out.push(self.parse_unicode_escape()?),
                        _ => return Err("invalid escape sequence".to_string()),
                    }
                }
                character if character.is_control() => {
                    return Err("control character in JSON string".to_string());
                }
                _ => out.push(ch),
            }
        }
        Err("unterminated JSON string".to_string())
    }

    fn parse_unicode_escape(&mut self) -> Result<char, String> {
        if self.index + 4 > self.chars.len() {
            return Err("truncated unicode escape".to_string());
        }
        let hex = self.chars[self.index..self.index + 4]
            .iter()
            .collect::<String>();
        self.index += 4;
        let codepoint =
            u32::from_str_radix(&hex, 16).map_err(|_| "invalid unicode escape".to_string())?;
        char::from_u32(codepoint).ok_or_else(|| "invalid unicode codepoint".to_string())
    }

    fn parse_number(&mut self) -> Result<(), String> {
        if self.consume('-') && !self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
            return Err("invalid JSON number".to_string());
        }
        match self.peek() {
            Some('0') => self.index += 1,
            Some('1'..='9') => {
                self.index += 1;
                while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                    self.index += 1;
                }
            }
            _ => return Err("invalid JSON number".to_string()),
        }
        if self.consume('.') {
            if !self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                return Err("invalid JSON number".to_string());
            }
            while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                self.index += 1;
            }
        }
        if self.peek().is_some_and(|ch| matches!(ch, 'e' | 'E')) {
            self.index += 1;
            if self.peek().is_some_and(|ch| matches!(ch, '+' | '-')) {
                self.index += 1;
            }
            if !self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                return Err("invalid JSON number".to_string());
            }
            while self.peek().is_some_and(|ch| ch.is_ascii_digit()) {
                self.index += 1;
            }
        }
        Ok(())
    }

    fn parse_literal(&mut self, literal: &str) -> Result<(), String> {
        for expected in literal.chars() {
            self.expect(expected)?;
        }
        Ok(())
    }

    fn skip_whitespace(&mut self) {
        while self.peek().is_some_and(|ch| ch.is_whitespace()) {
            self.index += 1;
        }
    }

    fn consume(&mut self, expected: char) -> bool {
        if self.peek() == Some(expected) {
            self.index += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, expected: char) -> Result<(), String> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(format!("expected JSON character {expected}"))
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.index).copied()
    }
}

fn reason_fragment_for_script(script: &str) -> String {
    script
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect()
}

fn valid_sha256_digest(value: &str) -> bool {
    let Some((algorithm, digest)) = value.split_once(':') else {
        return false;
    };
    algorithm == "sha256"
        && digest.len() == 64
        && digest
            .chars()
            .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
}

fn summary_value_is_safe(value: &str) -> bool {
    value
        .chars()
        .all(|character| !character.is_control() && character != '\n' && character != '\r')
}

fn safe_summary_value(value: &str) -> String {
    if summary_value_is_safe(value) {
        value.to_string()
    } else {
        "<invalid-summary-value>".to_string()
    }
}

fn looks_like_supported_pyproject_toml(contents: &str) -> bool {
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return false;
    }
    let mut in_multiline_array = false;
    for line in contents.lines() {
        let line = line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if in_multiline_array {
            if !toml_line_has_balanced_quotes(line) {
                return false;
            }
            if line.ends_with(']') {
                in_multiline_array = false;
            }
            continue;
        }
        if line.starts_with('[') {
            if !line.ends_with(']') || line.len() <= 2 || !toml_line_has_balanced_quotes(line) {
                return false;
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return false;
        };
        if !key
            .trim()
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
        {
            return false;
        }
        let value = value.trim();
        if value.is_empty() || !toml_line_has_balanced_quotes(value) {
            return false;
        }
        if value.starts_with('[') && !value.ends_with(']') {
            in_multiline_array = true;
        }
    }
    !in_multiline_array
}

fn toml_line_has_balanced_quotes(line: &str) -> bool {
    let mut escaped = false;
    let mut in_string = false;
    for character in line.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match character {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            _ => {}
        }
    }
    !in_string && !escaped
}

fn contains_exfil_hint(contents: &str) -> bool {
    let lowered = contents.to_ascii_lowercase();
    lowered.contains("process.env")
        || lowered.contains("authorization")
        || lowered.contains("token")
        || lowered.contains("api_key")
        || lowered.contains("curl ")
        || lowered.contains("fetch(")
        || lowered.contains("https://")
        || lowered.contains("http://")
}

struct StaticScanDigestInput<'a> {
    job_id: &'a str,
    profile_id: &'a str,
    profile_version: u16,
    artifact_digest: &'a str,
    cache_object_key: &'a str,
    manifest_kind: &'a str,
    state: JobState,
    findings: &'a [StaticFinding],
    reason_codes: &'a [String],
}

fn static_scan_log_digest(input: StaticScanDigestInput<'_>) -> String {
    sha256_digest(static_scan_log_summary(input).as_bytes())
}

fn static_scan_log_summary(input: StaticScanDigestInput<'_>) -> String {
    let high_count = input
        .findings
        .iter()
        .filter(|finding| finding.severity == FindingSeverity::High)
        .count();
    let suspicious_count = input
        .findings
        .iter()
        .filter(|finding| finding.severity == FindingSeverity::Suspicious)
        .count();
    format!(
        "{STATIC_MANIFEST_SUMMARY_SCHEMA}\njob_id={}\nprofile_id={}\nprofile_version={}\nartifact_digest={}\ncache_object_key={}\nmanifest_kind={}\njob_kind=StaticManifest\nstate={:?}\nfinding_count={}\nhigh_count={high_count}\nsuspicious_count={suspicious_count}\nreason_codes={}\nexecution_enabled=false\ndetonation_attempted=false\nnetwork_attempted=false\nraw_log_captured=false\n",
        safe_summary_value(input.job_id),
        safe_summary_value(input.profile_id),
        input.profile_version,
        safe_summary_value(input.artifact_digest),
        safe_summary_value(input.cache_object_key),
        input.manifest_kind,
        input.state,
        input.findings.len(),
        input.reason_codes.join(",")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_npm_postinstall() {
        let report = scan_npm_package_json(r#"{"scripts":{"postinstall":"node x.js"}}"#);
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "npm_lifecycle_postinstall"));
    }

    #[test]
    fn detects_escaped_and_broader_npm_lifecycle_scripts() {
        let report = scan_npm_package_json(
            r#"{"scripts":{"\u0070ostinstall":"node x.js","preprepare":"node y.js","postprepare":"node z.js","prepublish":"node p.js"}}"#,
        );
        assert!(!report.passed());
        for reason in [
            "npm_lifecycle_postinstall",
            "npm_lifecycle_preprepare",
            "npm_lifecycle_postprepare",
            "npm_lifecycle_prepublish",
        ] {
            assert!(report
                .findings
                .iter()
                .any(|finding| finding.reason_code == reason));
        }
    }

    #[test]
    fn malformed_npm_manifest_fails_closed() {
        let report = scan_npm_package_json(r#"{"scripts":{"postinstall":"node x.js"}"#);
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "npm_package_json_malformed"));
    }

    #[test]
    fn detects_pypi_pep517_backend_without_auto_failure() {
        let report = scan_pyproject_toml(
            r#"[build-system]
build-backend = "fixture_backend""#,
        );
        assert!(report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "pypi_pep517_build_backend"));
    }

    #[test]
    fn malformed_pyproject_fails_closed() {
        let report = scan_pyproject_toml("[build-system\nbuild-backend = \"unterminated");
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "pypi_pyproject_malformed"));
    }

    #[test]
    fn scans_inert_npm_fixture_without_execution() {
        let package_json =
            include_str!("../../../tests/fixtures/npm/postinstall-exfil/package.json");
        let report = scan_npm_package_json(package_json);
        assert!(!report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "npm_lifecycle_postinstall"));
    }

    #[test]
    fn scans_inert_pypi_fixture_without_execution() {
        let pyproject = include_str!("../../../tests/fixtures/pypi/pep517-backend/pyproject.toml");
        let report = scan_pyproject_toml(pyproject);
        assert!(report.passed());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "pypi_pep517_build_backend"));
    }

    #[test]
    fn static_manifest_job_passes_clean_npm_metadata_without_execution() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-1",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: r#"{"name":"clean","version":"1.0.0"}"#,
        });
        assert_eq!(output.state, JobState::Passed);
        assert!(output.reason_codes.is_empty());
        assert!(output.log_digest.starts_with("sha256:"));
        assert_eq!(output.log_digest.len(), 71);
        assert_eq!(output.summary_schema, STATIC_MANIFEST_SUMMARY_SCHEMA);
        assert!(output
            .sanitized_log_summary
            .starts_with("whoathere.static_manifest_job.v1\n"));
        assert!(output
            .sanitized_log_summary
            .contains("raw_log_captured=false"));
        assert!(!output.execution_enabled);
        assert!(!output.detonation_attempted);
        assert!(!output.network_attempted);
        assert!(!output.raw_log_captured);
        assert_eq!(
            output.log_digest,
            sha256_digest(output.sanitized_log_summary.as_bytes())
        );
        assert!(output.audit_event_id.starts_with("audit-static-manifest-"));
    }

    #[test]
    fn static_manifest_job_fails_postinstall_without_raw_log_capture() {
        let package_json =
            include_str!("../../../tests/fixtures/npm/postinstall-exfil/package.json");
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-2",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: package_json,
        });
        assert_eq!(output.state, JobState::Failed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "npm_lifecycle_postinstall"));
        assert!(!output.log_digest.contains("postinstall"));
        assert!(!output.sanitized_log_summary.contains("node postinstall.js"));
        assert!(!output.audit_event_id.contains("postinstall"));
        assert!(!output.execution_enabled);
    }

    #[test]
    fn static_manifest_job_keeps_pep517_suspicion_admission_bindable() {
        let pyproject = include_str!("../../../tests/fixtures/pypi/pep517-backend/pyproject.toml");
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-3",
            profile_id: "pypi.sdist_pep517.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::PyprojectToml,
            manifest_contents: pyproject,
        });
        assert_eq!(output.state, JobState::Passed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "pypi_pep517_build_backend"));
    }

    #[test]
    fn static_manifest_job_empty_manifest_fails_closed() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-4",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: "",
        });
        assert_eq!(output.state, JobState::Failed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "static_manifest_empty"));
    }

    #[test]
    fn static_manifest_job_invalid_identity_fails_closed() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-5",
            profile_id: "",
            profile_version: 0,
            artifact_digest: "sha256:not-canonical",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: r#"{"name":"clean","version":"1.0.0"}"#,
        });
        assert_eq!(output.state, JobState::Failed);
        for reason in [
            "static_manifest_profile_id_empty",
            "static_manifest_profile_version_zero",
            "static_manifest_artifact_digest_invalid",
            "static_manifest_cache_object_key_mismatch",
        ] {
            assert!(output
                .reason_codes
                .iter()
                .any(|candidate| candidate == reason));
        }
    }

    #[test]
    fn static_manifest_job_rejects_control_character_metadata_without_summary_injection() {
        let output = run_static_manifest_job(StaticManifestJobRequest {
            job_id: "static-job-6\nforged=true",
            profile_id: "npm.registry_tarball.v1",
            profile_version: 1,
            artifact_digest:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            cache_object_key:
                "blobs/sha256/1111111111111111111111111111111111111111111111111111111111111111",
            manifest_kind: StaticManifestKind::NpmPackageJson,
            manifest_contents: r#"{"name":"clean","version":"1.0.0"}"#,
        });

        assert_eq!(output.state, JobState::Failed);
        assert!(output
            .reason_codes
            .iter()
            .any(|reason| reason == "static_manifest_metadata_control_character"));
        assert!(!output.sanitized_log_summary.contains("forged=true"));
        assert!(output
            .sanitized_log_summary
            .contains("job_id=<invalid-summary-value>"));
    }
}
