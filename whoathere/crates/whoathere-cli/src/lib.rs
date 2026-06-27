use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use whoathere_admission::AdmissionController;
use whoathere_audit::{
    append_jsonl, redact_token_like, sensitive_key_like, AuditCleanupSummary, AuditProofSummary,
    AuditRecord, AuditReplayStoreSummary,
};
use whoathere_cache::InMemoryCacheStore;
use whoathere_core::{
    classify_package_command, macos_beta_label, parse_config_kv, CommandClassification,
    CommandKind, ContainmentBackend, ExecutionMode, ExitCode, OutageBehavior, WhoaThereConfig,
    WorkflowRisk,
};
use whoathere_detector::{scan_npm_package_json, scan_pyproject_toml};
use whoathere_evidence::{
    minimum_profiles, EvidenceBundle, EvidenceJobBinding, EvidenceJobResult, EvidenceProfile,
    JobState,
};
use whoathere_launch::{
    build_launch_plan, cleanup_runtime_plan, load_cleanup_manifest, CleanupResult, LaunchPlan,
    LaunchRequest, LaunchStatus,
};
use whoathere_macos_vm::{
    classify_artifact, decide_local_sync, default_canaries, default_state_dir,
    default_sync_allowlist, parse_image_manifest, required_local_evidence, scanner_adapters,
    status_from_config, ArtifactSignals, HostPlatform, LocalEvidenceFlags, MacosVmConfig,
    MacosVmImageManifest, PackageClass, DEFAULT_NATIVE_MEMORY_MIB, NETWORK_MODEL, RELEASE_CLAIM,
    RELEASE_TARGET, SYNC_POLICY, TARGET_ARCH, VM_BOUNDARY,
};
use whoathere_policy::{
    evaluate_source_policy, outage_decision, parse_policy_document, NamespaceOwnership,
    NamespaceRule, PolicyDecision, PolicyDocument, SourceKind,
};
use whoathere_runner::{execute_readonly, plan_protected_execution, ExecutionDecision};
use whoathere_sandbox::{
    admit_linux_active_probe_receipt, admit_linux_active_probe_receipt_with_replay_decision,
    evaluate_configured_vault_egress, linux_active_probe_fixture_evidence,
    linux_active_probe_receipt_from_evidence, linux_containment_readiness_from_evidence,
    linux_verification_plan_from_readiness, local_provider_evidence_posture_from_evidence,
    macos_containment_readiness_from_evidence, macos_verification_plan_from_readiness,
    ContainmentProof, EgressProof, LinuxActiveProbeAdmission, LinuxActiveProbeFixtureProfile,
    LinuxActiveProbeReceipt, LinuxLocalProofProvider, LocalVerificationPlan,
    MacosLocalProofProvider, ProofProvider, ProofSubject, ProviderChallengeAttempt,
    ProviderChallengeReplayFileStore, ProviderChallengeReplayGuard, ProviderChallengeUseDecision,
    ProviderChallengeUseStatus, ProviderVerificationChallenge, SandboxBackend, UnsupportedBackend,
    LINUX_ACTIVE_PROBE_COMPLETE_STATUS, LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE,
    LINUX_ACTIVE_PROBE_SCHEMA_VERSION,
};
use whoathere_source::{
    build_sanitized_context, discover_package_identities_for_ecosystem,
    discover_requirements_identities, extract_package_identities, scan_requirements_path,
    scan_source_contents, scan_workspace, vault_host_port, ContextError, PackageIdentity,
    PackageIdentityEcosystem, PackageIdentityReport, PackageIdentitySourceKind,
    SanitizedExecutionContext, SourceFileKind, SourceScanReport,
};
use whoathere_vault_api::{
    bind_fetch_job_result, plan_fetch_job, AdmissionRequest, ArtifactRef, FetchJobRequest,
    FetchJobResult,
};
use whoathere_vault_dev::{
    handle_http_request, serve_loopback_http, to_http_wire, validate_loopback_bind,
    SanitizedRequestLogEntry,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub output: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Doctor {
        json: bool,
        state_dir: Option<String>,
        helper_path: Option<String>,
    },
    Status,
    ShimInstall {
        dry_run: bool,
        dest: Option<String>,
        include_python: bool,
    },
    EndpointSetup {
        shim_dir: Option<String>,
        workspace: Option<String>,
        vault_origin: Option<String>,
        policy_path: Option<String>,
        audit_path: Option<String>,
        replay_store: Option<String>,
        include_python: bool,
    },
    VmStatus {
        state_dir: Option<String>,
        manifest_path: Option<String>,
        helper_path: Option<String>,
        json: bool,
    },
    VmInit {
        state_dir: Option<String>,
        manifest_path: Option<String>,
        helper_path: Option<String>,
        image_path: Option<String>,
        restore_image_path: Option<String>,
        fetch_latest_restore_image: bool,
        memory_mib: Option<u64>,
        disk_gib: Option<u64>,
        execute: bool,
    },
    VmAction {
        action: VmAction,
        state_dir: Option<String>,
        helper_path: Option<String>,
        execute: bool,
    },
    VmDetonate {
        tool: String,
        args: Vec<String>,
        execute: bool,
        state_dir: Option<String>,
        helper_path: Option<String>,
        workspace: Option<String>,
        fixture: Option<String>,
        timeout_seconds: Option<u64>,
        json: bool,
    },
    VmReleasePlan {
        artifact_class: Option<String>,
        ecosystem: Option<String>,
        source: Option<String>,
        filename: Option<String>,
        lifecycle_script: bool,
        pep517_backend: bool,
        native_marker: bool,
        editable: bool,
        evidence: LocalEvidenceFlags,
        json: bool,
    },
    VmCanaries {
        json: bool,
    },
    VmSyncPolicy {
        json: bool,
    },
    VmRedTeamGate {
        json: bool,
    },
    PolicyExplain {
        subject: String,
    },
    PolicyCheck {
        path: String,
    },
    PolicyCheckSource {
        package: String,
        source: String,
        internal_prefix: Option<String>,
        policy_path: Option<String>,
    },
    ConfigCheck {
        path: String,
    },
    ScanManifest {
        kind: String,
        path: String,
    },
    SourceScan {
        kind: String,
        path: String,
        vault_origin: Option<String>,
    },
    SourceScanWorkspace {
        path: String,
        vault_origin: Option<String>,
    },
    SourceContext {
        tool: String,
        vault_origin: Option<String>,
    },
    LaunchPlan {
        tool: String,
        args: Vec<String>,
        execute: bool,
        workspace: Option<String>,
        vault_origin: Option<String>,
        runtime_dir: Option<String>,
        containment_available: bool,
        egress_enforced: bool,
    },
    LaunchProviderCheck {
        tool: String,
        args: Vec<String>,
        execute: bool,
        workspace: Option<String>,
        vault_origin: Option<String>,
        runtime_dir: Option<String>,
        containment_available: bool,
        egress_enforced: bool,
    },
    LaunchAudit {
        tool: String,
        args: Vec<String>,
        execute: bool,
        workspace: Option<String>,
        vault_origin: Option<String>,
        runtime_dir: Option<String>,
        audit_path: Option<String>,
        containment_available: bool,
        egress_enforced: bool,
    },
    LaunchCleanup {
        manifest_path: Option<String>,
        execute: bool,
        audit_path: Option<String>,
    },
    EvidenceProfiles,
    EvidenceProviders {
        json: bool,
        require_ready: bool,
        provider_scope: ProviderScope,
    },
    EvidenceChallenge {
        json: bool,
        provider_scope: ProviderScope,
        subject: Option<String>,
        context_hash: Option<String>,
        vault_host: Option<String>,
    },
    EvidenceLinuxActiveProbeFixture {
        json: bool,
        subject: Option<String>,
        context_hash: Option<String>,
        vault_host: Option<String>,
        profile: Option<String>,
    },
    EvidenceLinuxActiveProbeAdmission {
        json: bool,
        subject: Option<String>,
        context_hash: Option<String>,
        vault_host: Option<String>,
        profile: Option<String>,
        replay: bool,
        unknown_challenge: bool,
        mutate_context: bool,
    },
    EvidenceLinuxActiveProbeDocker {
        json: bool,
        execute: bool,
        admit: bool,
        replay: bool,
        subject: Option<String>,
        context_hash: Option<String>,
        vault_host: Option<String>,
        image: Option<String>,
        docker_network: Option<String>,
        replay_store: Option<String>,
        audit_path: Option<String>,
    },
    VaultSimulate {
        complete: bool,
    },
    VaultChallengeSim {
        replay: bool,
        unknown_challenge: bool,
        mutate_context: bool,
        expired: bool,
    },
    VaultDevHttp {
        method: String,
        path: String,
        headers: Vec<String>,
        body: Option<String>,
    },
    VaultDevServe {
        bind: String,
        max_requests: usize,
        idle_timeout_ms: u64,
    },
    Protect {
        tool: String,
        args: Vec<String>,
        execute: bool,
        policy_path: Option<String>,
        workspace: Option<String>,
        vault_origin: Option<String>,
        audit_path: Option<String>,
    },
    Help,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderScope {
    All,
    Current,
    Linux,
    Macos,
    Invalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmAction {
    Start,
    Suspend,
    Reset,
    Prune,
    Health,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimSpec {
    pub name: &'static str,
    pub tool: &'static str,
}

pub fn default_shims() -> Vec<ShimSpec> {
    vec![
        ShimSpec {
            name: "npm",
            tool: "npm",
        },
        ShimSpec {
            name: "npx",
            tool: "npx",
        },
        ShimSpec {
            name: "pip",
            tool: "pip",
        },
        ShimSpec {
            name: "pip3",
            tool: "pip3",
        },
    ]
}

pub fn optional_python_shims() -> Vec<ShimSpec> {
    vec![
        ShimSpec {
            name: "python",
            tool: "python",
        },
        ShimSpec {
            name: "python3",
            tool: "python3",
        },
    ]
}

pub fn shims_for_materialization(include_python: bool) -> Vec<ShimSpec> {
    let mut shims = default_shims();
    if include_python {
        shims.extend(optional_python_shims());
    }
    shims
}

pub fn render_shim_manifest() -> String {
    let mut rows = default_shims()
        .into_iter()
        .map(|shim| {
            format!(
                "shim={} optional=false target=\"whoathere protect --execute {} --\"",
                shim.name, shim.tool
            )
        })
        .collect::<Vec<_>>();
    rows.extend(optional_python_shims().into_iter().map(|shim| {
        format!(
            "shim={} optional=true target=\"whoathere protect --execute {} --\"",
            shim.name, shim.tool
        )
    }));
    let rows = rows.join("\n");
    format!(
        "whoathere shim manifest\nmutation=false\nenv_defaults=WHOATHERE_WORKSPACE,WHOATHERE_VAULT_ORIGIN,WHOATHERE_POLICY,WHOATHERE_AUDIT_PATH,WHOATHERE_REPLAY_STORE\n{rows}"
    )
}

pub fn materialize_unix_shims(
    dest: &std::path::Path,
    whoathere_bin: &str,
) -> std::io::Result<usize> {
    materialize_unix_shims_with_options(dest, whoathere_bin, false)
}

pub fn materialize_unix_shims_with_options(
    dest: &std::path::Path,
    whoathere_bin: &str,
    include_python: bool,
) -> std::io::Result<usize> {
    std::fs::create_dir_all(dest)?;
    let shims = shims_for_materialization(include_python);
    for shim in &shims {
        let path = dest.join(shim.name);
        let script = format!(
            "#!/bin/sh\nexec {} protect --execute {} -- \"$@\"\n",
            shell_quote(whoathere_bin),
            shim.tool
        );
        write_new_file(&path, script.as_bytes())?;
        set_executable(&path)?;
    }
    Ok(shims.len())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn write_new_file(path: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(content)?;
    file.flush()
}

#[cfg(unix)]
fn set_executable(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_executable(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

pub fn parse_command(args: &[String]) -> Command {
    match args {
        [] => Command::Help,
        [cmd, rest @ ..] if cmd == "doctor" => Command::Doctor {
            json: rest.iter().any(|arg| arg == "--json"),
            state_dir: parse_flag_value(rest, "--state-dir"),
            helper_path: parse_helper_path(rest),
        },
        [cmd] if cmd == "status" => Command::Status,
        [cmd, sub, subject] if cmd == "policy" && sub == "explain" => Command::PolicyExplain {
            subject: subject.clone(),
        },
        [cmd, sub, path] if cmd == "policy" && sub == "check" => {
            Command::PolicyCheck { path: path.clone() }
        }
        [cmd, sub, package, source, rest @ ..] if cmd == "policy" && sub == "check-source" => {
            Command::PolicyCheckSource {
                package: package.clone(),
                source: source.clone(),
                internal_prefix: parse_internal_prefix(rest),
                policy_path: parse_policy_path(rest),
            }
        }
        [cmd, sub, path] if cmd == "config" && sub == "check" => {
            Command::ConfigCheck { path: path.clone() }
        }
        [cmd, sub, kind, path] if cmd == "scan" && sub == "manifest" => Command::ScanManifest {
            kind: kind.clone(),
            path: path.clone(),
        },
        [cmd, sub, kind, path, rest @ ..] if cmd == "source" && sub == "scan" => {
            Command::SourceScan {
                kind: kind.clone(),
                path: path.clone(),
                vault_origin: parse_vault_origin(rest),
            }
        }
        [cmd, sub, path, rest @ ..] if cmd == "source" && sub == "scan-workspace" => {
            Command::SourceScanWorkspace {
                path: path.clone(),
                vault_origin: parse_vault_origin(rest),
            }
        }
        [cmd, sub, tool, rest @ ..] if cmd == "source" && sub == "context" => {
            Command::SourceContext {
                tool: tool.clone(),
                vault_origin: parse_vault_origin(rest),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "launch" && sub == "plan" => parse_launch_plan(rest),
        [cmd, sub, rest @ ..] if cmd == "launch" && sub == "provider-check" => {
            parse_launch_provider_check(rest)
        }
        [cmd, sub, rest @ ..] if cmd == "launch" && sub == "audit" => parse_launch_audit(rest),
        [cmd, sub, rest @ ..] if cmd == "launch" && sub == "cleanup" => parse_launch_cleanup(rest),
        [cmd, sub] if cmd == "evidence" && sub == "profiles" => Command::EvidenceProfiles,
        [cmd, sub, rest @ ..] if cmd == "evidence" && sub == "providers" => {
            Command::EvidenceProviders {
                json: rest.iter().any(|arg| arg == "--json"),
                require_ready: rest.iter().any(|arg| arg == "--require-ready"),
                provider_scope: parse_provider_scope(rest),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "evidence" && sub == "challenge" => {
            Command::EvidenceChallenge {
                json: rest.iter().any(|arg| arg == "--json"),
                provider_scope: parse_provider_challenge_scope(rest),
                subject: parse_flag_value(rest, "--subject"),
                context_hash: parse_flag_value(rest, "--context-hash"),
                vault_host: parse_flag_value(rest, "--vault-host"),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "evidence" && sub == "linux-active-probe-fixture" => {
            Command::EvidenceLinuxActiveProbeFixture {
                json: rest.iter().any(|arg| arg == "--json"),
                subject: parse_flag_value(rest, "--subject"),
                context_hash: parse_flag_value(rest, "--context-hash"),
                vault_host: parse_flag_value(rest, "--vault-host"),
                profile: parse_flag_value(rest, "--profile"),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "evidence" && sub == "linux-active-probe-admission" => {
            Command::EvidenceLinuxActiveProbeAdmission {
                json: rest.iter().any(|arg| arg == "--json"),
                subject: parse_flag_value(rest, "--subject"),
                context_hash: parse_flag_value(rest, "--context-hash"),
                vault_host: parse_flag_value(rest, "--vault-host"),
                profile: parse_flag_value(rest, "--profile"),
                replay: rest.iter().any(|arg| arg == "--replay"),
                unknown_challenge: rest.iter().any(|arg| arg == "--unknown-challenge"),
                mutate_context: rest.iter().any(|arg| arg == "--mutate-context"),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "evidence" && sub == "linux-active-probe-docker" => {
            parse_evidence_linux_active_probe_docker_with_env(rest, |key| std::env::var(key).ok())
        }
        [cmd, sub, flag] if cmd == "vault" && sub == "simulate" => Command::VaultSimulate {
            complete: flag == "--complete",
        },
        [cmd, sub, rest @ ..] if cmd == "vault" && sub == "challenge-sim" => {
            Command::VaultChallengeSim {
                replay: rest.iter().any(|arg| arg == "--replay"),
                unknown_challenge: rest.iter().any(|arg| arg == "--unknown-challenge"),
                mutate_context: rest.iter().any(|arg| arg == "--mutate-context"),
                expired: rest.iter().any(|arg| arg == "--expired"),
            }
        }
        [cmd, sub, method, path, rest @ ..] if cmd == "vault" && sub == "dev-http" => {
            let (headers, body) = parse_vault_dev_http_options(rest);
            Command::VaultDevHttp {
                method: method.clone(),
                path: path.clone(),
                headers,
                body,
            }
        }
        [cmd, sub, rest @ ..] if cmd == "vault" && sub == "dev-serve" => Command::VaultDevServe {
            bind: parse_flag_value(rest, "--bind").unwrap_or_else(|| "127.0.0.1:4873".to_string()),
            max_requests: parse_usize_flag(rest, "--max-requests").unwrap_or(1),
            idle_timeout_ms: parse_u64_flag(rest, "--idle-timeout-ms").unwrap_or(1000),
        },
        [cmd, sub] if cmd == "vault" && sub == "simulate" => {
            Command::VaultSimulate { complete: false }
        }
        [cmd, sub, rest @ ..] if cmd == "shim" && sub == "install" => Command::ShimInstall {
            dry_run: rest.iter().any(|arg| arg == "--dry-run"),
            dest: parse_dest(rest),
            include_python: rest.iter().any(|arg| arg == "--include-python"),
        },
        [cmd, sub, rest @ ..] if cmd == "endpoint" && sub == "setup" => parse_endpoint_setup(rest),
        [cmd, sub, rest @ ..] if cmd == "vm" && sub == "status" => Command::VmStatus {
            state_dir: parse_flag_value(rest, "--state-dir"),
            manifest_path: parse_flag_value(rest, "--manifest"),
            helper_path: parse_helper_path(rest),
            json: rest.iter().any(|arg| arg == "--json"),
        },
        [cmd, sub, rest @ ..] if cmd == "vm" && sub == "init" => Command::VmInit {
            state_dir: parse_flag_value(rest, "--state-dir"),
            manifest_path: parse_flag_value(rest, "--manifest"),
            helper_path: parse_helper_path(rest),
            image_path: parse_flag_value(rest, "--image"),
            restore_image_path: parse_flag_value(rest, "--restore-image"),
            fetch_latest_restore_image: rest
                .iter()
                .any(|arg| arg == "--fetch-latest-restore-image"),
            memory_mib: parse_u64_flag(rest, "--memory-mib"),
            disk_gib: parse_u64_flag(rest, "--disk-gib"),
            execute: rest.iter().any(|arg| arg == "--execute"),
        },
        [cmd, sub, rest @ ..]
            if cmd == "vm"
                && matches!(
                    sub.as_str(),
                    "start" | "suspend" | "reset" | "prune" | "health"
                ) =>
        {
            Command::VmAction {
                action: match sub.as_str() {
                    "start" => VmAction::Start,
                    "suspend" => VmAction::Suspend,
                    "reset" => VmAction::Reset,
                    "prune" => VmAction::Prune,
                    "health" => VmAction::Health,
                    _ => unreachable!(),
                },
                state_dir: parse_flag_value(rest, "--state-dir"),
                helper_path: parse_helper_path(rest),
                execute: rest.iter().any(|arg| arg == "--execute"),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "vm" && sub == "detonate" => parse_vm_detonate(rest),
        [cmd, sub, rest @ ..] if cmd == "vm" && sub == "release-plan" => Command::VmReleasePlan {
            artifact_class: parse_flag_value(rest, "--class"),
            ecosystem: parse_flag_value(rest, "--ecosystem"),
            source: parse_flag_value(rest, "--source"),
            filename: parse_flag_value(rest, "--filename"),
            lifecycle_script: rest.iter().any(|arg| arg == "--lifecycle-script"),
            pep517_backend: rest.iter().any(|arg| arg == "--pep517-backend"),
            native_marker: rest.iter().any(|arg| arg == "--native-marker"),
            editable: rest.iter().any(|arg| arg == "--editable"),
            evidence: parse_local_evidence_flags(rest),
            json: rest.iter().any(|arg| arg == "--json"),
        },
        [cmd, sub, rest @ ..] if cmd == "vm" && sub == "canaries" => Command::VmCanaries {
            json: rest.iter().any(|arg| arg == "--json"),
        },
        [cmd, sub, rest @ ..] if cmd == "vm" && sub == "sync-policy" => Command::VmSyncPolicy {
            json: rest.iter().any(|arg| arg == "--json"),
        },
        [cmd, sub, rest @ ..] if cmd == "vm" && sub == "red-team-gate" => Command::VmRedTeamGate {
            json: rest.iter().any(|arg| arg == "--json"),
        },
        [cmd, rest @ ..] if cmd == "protect" => parse_protect(rest),
        _ => Command::Help,
    }
}

pub fn render_command(command: Command) -> String {
    evaluate_command(command).output
}

pub fn evaluate_command(command: Command) -> CommandResult {
    let output = render_command_text(command);
    let exit_code = infer_exit_code(&output);
    CommandResult { output, exit_code }
}

fn render_command_text(command: Command) -> String {
    match command {
        Command::Doctor {
            json,
            state_dir,
            helper_path,
        } => render_doctor(json, state_dir.as_deref(), helper_path.as_deref()),
        Command::Status => {
            let config = WhoaThereConfig::default();
            format!(
                "whoathere status\nschema_version={}\nmode={:?}\noutage_behavior={:?}\nmacos_mode={}",
                config.schema_version,
                config.mode,
                config.outage_behavior,
                macos_beta_label(false)
            )
        }
        Command::ShimInstall {
            dry_run,
            dest,
            include_python,
        } => {
            if dry_run {
                format!(
                    "whoathere shim install\nmode=dry-run\nmutation=false\ninclude_python={include_python}\n{}",
                    render_shim_manifest()
                )
            } else if let Some(dest) = dest {
                let whoathere_bin = std::env::current_exe()
                    .ok()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| "whoathere".to_string());
                match materialize_unix_shims_with_options(
                    std::path::Path::new(&dest),
                    &whoathere_bin,
                    include_python,
                ) {
                    Ok(count) => {
                        format!("whoathere shim install\nmode=materialize\nmutation=true\ninclude_python={include_python}\ndest={dest}\ninstalled={count}")
                    }
                    Err(error) => {
                        format!("whoathere shim install\nstatus=error\nreason_code=shim_materialize_failed\ndest={dest}\nerror={error}")
                    }
                }
            } else {
                "whoathere shim install\nrefusing mutation without explicit --dest; rerun with --dry-run or --dest <sandbox-dir>".to_string()
            }
        }
        Command::EndpointSetup {
            shim_dir,
            workspace,
            vault_origin,
            policy_path,
            audit_path,
            replay_store,
            include_python,
        } => render_endpoint_setup(
            shim_dir.as_deref(),
            workspace.as_deref(),
            vault_origin.as_deref(),
            policy_path.as_deref(),
            audit_path.as_deref(),
            replay_store.as_deref(),
            include_python,
        ),
        Command::VmStatus {
            state_dir,
            manifest_path,
            helper_path,
            json,
        } => render_vm_status(
            state_dir.as_deref(),
            manifest_path.as_deref(),
            helper_path.as_deref(),
            json,
        ),
        Command::VmInit {
            state_dir,
            manifest_path,
            helper_path,
            image_path,
            restore_image_path,
            fetch_latest_restore_image,
            memory_mib,
            disk_gib,
            execute,
        } => render_vm_init(VmInitRenderArgs {
            state_dir: state_dir.as_deref(),
            manifest_path: manifest_path.as_deref(),
            helper_path: helper_path.as_deref(),
            image_path: image_path.as_deref(),
            restore_image_path: restore_image_path.as_deref(),
            fetch_latest_restore_image,
            memory_mib,
            disk_gib,
            execute,
        }),
        Command::VmAction {
            action,
            state_dir,
            helper_path,
            execute,
        } => render_vm_action(
            action,
            state_dir.as_deref(),
            helper_path.as_deref(),
            execute,
        ),
        Command::VmDetonate {
            tool,
            args,
            execute,
            state_dir,
            helper_path,
            workspace,
            fixture,
            timeout_seconds,
            json,
        } => render_vm_detonate(VmDetonateRenderArgs {
            tool: &tool,
            args: &args,
            execute,
            state_dir: state_dir.as_deref(),
            helper_path: helper_path.as_deref(),
            workspace: workspace.as_deref(),
            fixture: fixture.as_deref(),
            timeout_seconds,
            json,
        }),
        Command::VmReleasePlan {
            artifact_class,
            ecosystem,
            source,
            filename,
            lifecycle_script,
            pep517_backend,
            native_marker,
            editable,
            evidence,
            json,
        } => render_vm_release_plan(VmReleasePlanArgs {
            artifact_class: artifact_class.as_deref(),
            ecosystem: ecosystem.as_deref(),
            source: source.as_deref(),
            filename: filename.as_deref(),
            lifecycle_script,
            pep517_backend,
            native_marker,
            editable,
            evidence,
            json,
        }),
        Command::VmCanaries { json } => render_vm_canaries(json),
        Command::VmSyncPolicy { json } => render_vm_sync_policy(json),
        Command::VmRedTeamGate { json } => render_vm_red_team_gate(json),
        Command::PolicyExplain { subject } => {
            format!(
                "whoathere policy explain\nsubject={subject}\ndefault_ci_outage=deny\nunknown_source=manual_review_or_deny\nexit_deny={}",
                ExitCode::Deny.code()
            )
        }
        Command::PolicyCheck { path } => render_policy_check(&path),
        Command::PolicyCheckSource {
            package,
            source,
            internal_prefix,
            policy_path,
        } => render_policy_check_source(
            &package,
            &source,
            internal_prefix.as_deref(),
            policy_path.as_deref(),
        ),
        Command::ConfigCheck { path } => render_config_check(&path),
        Command::ScanManifest { kind, path } => render_manifest_scan(&kind, &path),
        Command::SourceScan {
            kind,
            path,
            vault_origin,
        } => render_source_scan(&kind, &path, vault_origin.as_deref()),
        Command::SourceScanWorkspace { path, vault_origin } => {
            render_source_workspace_scan(&path, vault_origin.as_deref())
        }
        Command::SourceContext { tool, vault_origin } => {
            render_source_context(&tool, vault_origin.as_deref())
        }
        Command::LaunchPlan {
            tool,
            args,
            execute,
            workspace,
            vault_origin,
            runtime_dir,
            containment_available,
            egress_enforced,
        } => render_launch_plan(LaunchCommandArgs {
            tool: &tool,
            args: &args,
            execute,
            workspace: workspace.as_deref(),
            vault_origin: vault_origin.as_deref(),
            runtime_dir: runtime_dir.as_deref(),
            containment_available,
            egress_enforced,
        }),
        Command::LaunchProviderCheck {
            tool,
            args,
            execute,
            workspace,
            vault_origin,
            runtime_dir,
            containment_available,
            egress_enforced,
        } => render_launch_provider_check(LaunchCommandArgs {
            tool: &tool,
            args: &args,
            execute,
            workspace: workspace.as_deref(),
            vault_origin: vault_origin.as_deref(),
            runtime_dir: runtime_dir.as_deref(),
            containment_available,
            egress_enforced,
        }),
        Command::LaunchAudit {
            tool,
            args,
            execute,
            workspace,
            vault_origin,
            runtime_dir,
            audit_path,
            containment_available,
            egress_enforced,
        } => render_launch_audit(
            LaunchCommandArgs {
                tool: &tool,
                args: &args,
                execute,
                workspace: workspace.as_deref(),
                vault_origin: vault_origin.as_deref(),
                runtime_dir: runtime_dir.as_deref(),
                containment_available,
                egress_enforced,
            },
            audit_path.as_deref(),
        ),
        Command::LaunchCleanup {
            manifest_path,
            execute,
            audit_path,
        } => render_launch_cleanup(manifest_path.as_deref(), execute, audit_path.as_deref()),
        Command::EvidenceProfiles => render_evidence_profiles(),
        Command::EvidenceProviders {
            json,
            require_ready,
            provider_scope,
        } => render_evidence_providers(json, require_ready, provider_scope),
        Command::EvidenceChallenge {
            json,
            provider_scope,
            subject,
            context_hash,
            vault_host,
        } => render_evidence_challenge(
            json,
            provider_scope,
            subject.as_deref(),
            context_hash.as_deref(),
            vault_host.as_deref(),
        ),
        Command::EvidenceLinuxActiveProbeFixture {
            json,
            subject,
            context_hash,
            vault_host,
            profile,
        } => render_evidence_linux_active_probe_fixture(
            json,
            subject.as_deref(),
            context_hash.as_deref(),
            vault_host.as_deref(),
            profile.as_deref(),
        ),
        Command::EvidenceLinuxActiveProbeAdmission {
            json,
            subject,
            context_hash,
            vault_host,
            profile,
            replay,
            unknown_challenge,
            mutate_context,
        } => render_evidence_linux_active_probe_admission(LinuxActiveProbeAdmissionRequest {
            json,
            subject: subject.as_deref(),
            context_hash: context_hash.as_deref(),
            vault_host: vault_host.as_deref(),
            profile: profile.as_deref(),
            replay,
            unknown_challenge,
            mutate_context,
        }),
        Command::EvidenceLinuxActiveProbeDocker {
            json,
            execute,
            admit,
            replay,
            subject,
            context_hash,
            vault_host,
            image,
            docker_network,
            replay_store,
            audit_path,
        } => render_evidence_linux_active_probe_docker(LinuxActiveProbeDockerRequest {
            json,
            execute,
            admit,
            replay,
            subject: subject.as_deref(),
            context_hash: context_hash.as_deref(),
            vault_host: vault_host.as_deref(),
            image: image.as_deref(),
            docker_network: docker_network.as_deref(),
            replay_store: replay_store.as_deref(),
            audit_path: audit_path.as_deref(),
        }),
        Command::VaultSimulate { complete } => render_vault_simulation(complete),
        Command::VaultChallengeSim {
            replay,
            unknown_challenge,
            mutate_context,
            expired,
        } => render_vault_challenge_sim(replay, unknown_challenge, mutate_context, expired),
        Command::VaultDevHttp {
            method,
            path,
            headers,
            body,
        } => render_vault_dev_http(&method, &path, &headers, body),
        Command::VaultDevServe {
            bind,
            max_requests,
            idle_timeout_ms,
        } => render_vault_dev_serve(&bind, max_requests, idle_timeout_ms),
        Command::Protect {
            tool,
            args,
            execute,
            policy_path,
            workspace,
            vault_origin,
            audit_path,
        } => {
            let loaded_policy = match policy_path.as_deref() {
                Some(path) => match load_policy_document(path) {
                    Ok(document) => Some(document),
                    Err(error) => {
                        return format!(
                            "whoathere protect\ntool={}\nargs={:?}\npolicy_status=error\nreason_code=policy_invalid\npolicy_error={}\nexecution_decision=refuse\nexecution_reason=policy_invalid\nexit_code={}",
                            redacted_scalar(&tool),
                            redacted_args(&args),
                            redacted_scalar(&error),
                            ExitCode::Deny.code()
                        );
                    }
                },
                None => None,
            };
            let policy_status = loaded_policy
                .as_ref()
                .map(|document| {
                    format!(
                        "policy_status=ok\npolicy_version={}",
                        document.policy_version
                    )
                })
                .unwrap_or_else(|| "policy_status=default".to_string());
            let policy_document = loaded_policy.clone().unwrap_or_default();
            let classification = classify_package_command(&tool, &args);
            let decision = default_decision(&classification);
            let decision_label = decision_label(decision);
            let identity_gate = render_protect_package_identity_gate(
                &tool,
                &args,
                &classification,
                &workspace,
                &policy_document,
            );
            if let Some(blocked) = identity_gate.blocked_output {
                let audit_status = render_audit_write_status(
                    "package_identity",
                    audit_path.as_deref(),
                    &protect_package_identity_audit_record(&tool, &args, &blocked),
                );
                return format!(
                    "whoathere protect\ntool={}\nargs={:?}\n{}\necosystem={:?}\nkind={:?}\nrisk={:?}\nprotected={}\nbypass_signal={:?}\nreason_codes={:?}\ndefault_outage_decision={decision_label}\nexit_code={}\n{}\n{}\nexecution_requested={execute}\nexecution_decision=refuse\nexecution_reason=package_identity_policy_blocked",
                    redacted_scalar(&tool),
                    redacted_args(&args),
                    policy_status,
                    classification.ecosystem,
                    classification.kind,
                    classification.risk,
                    classification.protected,
                    classification.bypass_signal,
                    classification.reason_codes,
                    ExitCode::Deny.code(),
                    blocked,
                    audit_status
                );
            }
            let source_gate = render_protect_source_gate(
                &tool,
                &args,
                classification.kind,
                &workspace,
                vault_origin.as_deref(),
            );
            if let Some(blocked) = source_gate.blocked_output {
                let audit_status = render_audit_write_status(
                    "source_scan",
                    audit_path.as_deref(),
                    &protect_source_audit_record(&tool, &args, &blocked),
                );
                return format!(
                    "whoathere protect\ntool={}\nargs={:?}\n{}\necosystem={:?}\nkind={:?}\nrisk={:?}\nprotected={}\nbypass_signal={:?}\nreason_codes={:?}\ndefault_outage_decision={decision_label}\nexit_code={}\n{}\n{}\n{}\nexecution_requested={execute}\nexecution_decision=refuse\nexecution_reason=source_scan_blocked",
                    redacted_scalar(&tool),
                    redacted_args(&args),
                    policy_status,
                    classification.ecosystem,
                    classification.kind,
                    classification.risk,
                    classification.protected,
                    classification.bypass_signal,
                    classification.reason_codes,
                    ExitCode::Deny.code(),
                    identity_gate.rendered,
                    blocked,
                    audit_status
                );
            }
            let launch_gate = render_protect_launch_gate(
                &tool,
                &args,
                execute,
                &classification,
                workspace.as_deref(),
                vault_origin.as_deref(),
                audit_path.as_deref(),
            );
            if let Some(blocked) = launch_gate.blocked_output {
                return format!(
                    "whoathere protect\ntool={}\nargs={:?}\n{}\necosystem={:?}\nkind={:?}\nrisk={:?}\nprotected={}\nbypass_signal={:?}\nreason_codes={:?}\ndefault_outage_decision={decision_label}\nexit_code={}\n{}\n{}\n{}\nexecution_requested={execute}\nexecution_decision=refuse\nexecution_reason=launch_plan_blocked",
                    redacted_scalar(&tool),
                    redacted_args(&args),
                    policy_status,
                    classification.ecosystem,
                    classification.kind,
                    classification.risk,
                    classification.protected,
                    classification.bypass_signal,
                    classification.reason_codes,
                    ExitCode::Deny.code(),
                    identity_gate.rendered,
                    source_gate.rendered,
                    blocked
                );
            }
            let execution = render_execution_plan(&tool, &args, execute);
            format!(
                "whoathere protect\ntool={}\nargs={:?}\n{policy_status}\necosystem={:?}\nkind={:?}\nrisk={:?}\nprotected={}\nbypass_signal={:?}\nreason_codes={:?}\ndefault_outage_decision={decision_label}\nexit_code={}\n{}\n{}\n{}\n{}",
                redacted_scalar(&tool),
                redacted_args(&args),
                classification.ecosystem,
                classification.kind,
                classification.risk,
                classification.protected,
                classification.bypass_signal,
                classification.reason_codes,
                decision_exit_code(decision).code(),
                identity_gate.rendered,
                source_gate.rendered,
                launch_gate.rendered,
                execution
            )
        }
        Command::Help => command_help(),
    }
}

fn command_help() -> String {
    concat!(
        "whoathere <",
        "doctor [--json] [--state-dir <dir>] [--helper <path>]",
        "|status",
        "|config check <path>",
        "|policy check <path>",
        "|policy check-source <pkg> <source> [--policy <path>|--internal-prefix <prefix>]",
        "|shim install --dry-run [--include-python]",
        "|shim install --dest <sandbox-dir> [--include-python]",
        "|endpoint setup --shim-dir <dir> --workspace <path> --vault-origin <url> [--policy <path>] [--audit-path <path>] [--replay-store <path>] [--include-python]",
        "|vm status [--state-dir <dir>] [--manifest <path>] [--helper <path>] [--json]",
        "|vm init [--state-dir <dir>] [--manifest <path>] [--helper <path>] [--image <path>|--restore-image <path>|--fetch-latest-restore-image] [--memory-mib <n>] [--disk-gib <n>] [--execute]",
        "|vm start|suspend|reset|prune [--state-dir <dir>] [--helper <path>] [--execute]",
        "|vm health [--state-dir <dir>] [--helper <path>]",
        "|vm detonate [--workspace <path>] [--state-dir <dir>] [--helper <path>] [--fixture <name>] [--timeout-seconds <n>] [--execute] [--json] npm|pip|uv -- <args>",
        "|vm release-plan [--class <class>|--ecosystem <name> --source <kind> --filename <name>] [--vm-ready --static-clean --dynamic-clean --egress-clean --no-canary-access --scanner-clean --diff-clean --freshness-allowed] [--json]",
        "|vm canaries [--json]",
        "|vm sync-policy [--json]",
        "|vm red-team-gate [--json]",
        "|protect [--workspace <path> --vault-origin <url>] npm|pip|uv -- <args>",
        "|scan manifest npm-package-json <path>",
        "|scan manifest pyproject <path>",
        "|source scan <kind> <path> --vault-origin <url>",
        "|source scan-workspace <path> --vault-origin <url>",
        "|source context <tool> --vault-origin <url>",
        "|launch plan [--workspace <path> --vault-origin <url> --runtime-dir <path>] npm -- <args>",
        "|launch provider-check [--workspace <path> --vault-origin <url> --runtime-dir <path>] npm -- <args>",
        "|launch audit [--audit-path <path> --workspace <path> --vault-origin <url> --runtime-dir <path>] npm -- <args>",
        "|launch cleanup --manifest <path> [--execute] [--audit-path <path>]",
        "|evidence profiles",
        "|evidence providers [--json] [--require-ready] [--scope all|current|linux|macos]",
        "|evidence challenge --subject <id> --context-hash <hash> --vault-host <host> [--json] [--scope current|linux|macos]",
        "|evidence linux-active-probe-fixture --subject <id> --context-hash <hash> --vault-host <host> --profile complete|incomplete|overpermissive [--json]",
        "|evidence linux-active-probe-admission --subject <id> --context-hash <hash> --vault-host <host> --profile complete|incomplete|overpermissive [--replay|--unknown-challenge|--mutate-context] [--json]",
        "|evidence linux-active-probe-docker --subject <id> --context-hash <hash> --vault-host <host> [--image <image>] [--docker-network <internal-network>] [--replay-store <path>] [--audit-path <path>] [--execute] [--admit] [--replay] [--json]",
        "|vault simulate [--complete]",
        "|vault challenge-sim [--replay|--unknown-challenge|--mutate-context|--expired]",
        "|vault dev-http <METHOD> <PATH> [--header <name:value>] [body]",
        "|vault dev-serve [--bind <loopback:port>] [--max-requests <n>] [--idle-timeout-ms <ms>]",
        ">"
    )
    .to_string()
}

fn infer_exit_code(output: &str) -> i32 {
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("final_exit_code=") {
            if let Ok(code) = value.parse::<i32>() {
                return code;
            }
        }
    }
    for line in output.lines() {
        if let Some(value) = line.strip_prefix("exit_code=") {
            if let Ok(code) = value.parse::<i32>() {
                return code;
            }
        }
    }
    for line in output.lines() {
        let trimmed = line.trim().trim_end_matches(',');
        if let Some(value) = trimmed.strip_prefix("\"exit_code\": ") {
            if let Ok(code) = value.parse::<i32>() {
                return code;
            }
        }
    }
    if output.contains("status=error") || output.contains("refusing mutation") {
        return ExitCode::Misuse.code();
    }
    if output.contains("execution_decision=refuse") && output.contains("execution_requested=true") {
        return ExitCode::Deny.code();
    }
    0
}

fn parse_vault_dev_http_options(args: &[String]) -> (Vec<String>, Option<String>) {
    let mut headers = Vec::new();
    let mut body = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--header" => {
                if let Some(value) = args.get(index + 1) {
                    headers.push(value.clone());
                    index += 2;
                } else {
                    index += 1;
                }
            }
            value if value.starts_with("--header=") => {
                headers.push(value.trim_start_matches("--header=").to_string());
                index += 1;
            }
            value => {
                if body.is_none() {
                    body = Some(value.to_string());
                }
                index += 1;
            }
        }
    }
    (headers, body)
}

fn parse_launch_plan(args: &[String]) -> Command {
    let mut execute = false;
    let mut workspace = None;
    let mut vault_origin = None;
    let mut runtime_dir = None;
    let mut containment_available = false;
    let mut egress_enforced = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--execute" => {
                execute = true;
                index += 1;
            }
            "--workspace" => {
                workspace = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--workspace=") => {
                workspace = Some(value.trim_start_matches("--workspace=").to_string());
                index += 1;
            }
            "--vault-origin" => {
                vault_origin = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--vault-origin=") => {
                vault_origin = Some(value.trim_start_matches("--vault-origin=").to_string());
                index += 1;
            }
            "--runtime-dir" => {
                runtime_dir = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--runtime-dir=") => {
                runtime_dir = Some(value.trim_start_matches("--runtime-dir=").to_string());
                index += 1;
            }
            "--containment-available" => {
                containment_available = true;
                index += 1;
            }
            "--egress-enforced" => {
                egress_enforced = true;
                index += 1;
            }
            _ => break,
        }
    }

    let Some(tool) = args.get(index).cloned() else {
        return Command::Help;
    };
    let remaining = &args[index + 1..];
    let command_args = if matches!(remaining.first(), Some(separator) if separator == "--") {
        remaining[1..].to_vec()
    } else {
        remaining.to_vec()
    };
    Command::LaunchPlan {
        tool,
        args: command_args,
        execute,
        workspace,
        vault_origin,
        runtime_dir,
        containment_available,
        egress_enforced,
    }
}

fn parse_vm_detonate(args: &[String]) -> Command {
    let mut execute = false;
    let mut json = false;
    let mut state_dir = None;
    let mut helper_path = None;
    let mut workspace = None;
    let mut fixture = None;
    let mut timeout_seconds = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--execute" => {
                execute = true;
                index += 1;
            }
            "--json" => {
                json = true;
                index += 1;
            }
            "--state-dir" => {
                state_dir = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--state-dir=") => {
                state_dir = Some(value.trim_start_matches("--state-dir=").to_string());
                index += 1;
            }
            "--helper" => {
                helper_path = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--helper=") => {
                helper_path = Some(value.trim_start_matches("--helper=").to_string());
                index += 1;
            }
            "--workspace" => {
                workspace = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--workspace=") => {
                workspace = Some(value.trim_start_matches("--workspace=").to_string());
                index += 1;
            }
            "--fixture" => {
                fixture = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--fixture=") => {
                fixture = Some(value.trim_start_matches("--fixture=").to_string());
                index += 1;
            }
            "--timeout-seconds" => {
                timeout_seconds = args.get(index + 1).and_then(|value| value.parse().ok());
                index += 2;
            }
            value if value.starts_with("--timeout-seconds=") => {
                timeout_seconds = value.trim_start_matches("--timeout-seconds=").parse().ok();
                index += 1;
            }
            value if value.starts_with("--") => return Command::Help,
            _ => break,
        }
    }

    let Some(tool) = args.get(index).cloned() else {
        return Command::Help;
    };
    if !matches!(tool.as_str(), "npm" | "pip" | "uv") {
        return Command::Help;
    }
    let remaining = &args[index + 1..];
    let command_args = if matches!(remaining.first(), Some(separator) if separator == "--") {
        remaining[1..].to_vec()
    } else {
        remaining.to_vec()
    };

    Command::VmDetonate {
        tool,
        args: command_args,
        execute,
        state_dir,
        helper_path,
        workspace,
        fixture,
        timeout_seconds,
        json,
    }
}

fn parse_launch_provider_check(args: &[String]) -> Command {
    match parse_launch_plan(args) {
        Command::LaunchPlan {
            tool,
            args,
            execute,
            workspace,
            vault_origin,
            runtime_dir,
            containment_available,
            egress_enforced,
        } => Command::LaunchProviderCheck {
            tool,
            args,
            execute,
            workspace,
            vault_origin,
            runtime_dir,
            containment_available,
            egress_enforced,
        },
        _ => Command::Help,
    }
}

fn parse_launch_audit(args: &[String]) -> Command {
    let (launch_args, audit_path) = extract_audit_path(args);
    match parse_launch_plan(&launch_args) {
        Command::LaunchPlan {
            tool,
            args,
            execute,
            workspace,
            vault_origin,
            runtime_dir,
            containment_available,
            egress_enforced,
        } => Command::LaunchAudit {
            tool,
            args,
            execute,
            workspace,
            vault_origin,
            runtime_dir,
            audit_path,
            containment_available,
            egress_enforced,
        },
        _ => Command::Help,
    }
}

fn parse_launch_cleanup(args: &[String]) -> Command {
    let mut execute = false;
    let mut manifest_path = None;
    let mut audit_path = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--execute" => {
                execute = true;
                index += 1;
            }
            "--manifest" => {
                manifest_path = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--manifest=") => {
                manifest_path = Some(value.trim_start_matches("--manifest=").to_string());
                index += 1;
            }
            "--audit-path" => {
                audit_path = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--audit-path=") => {
                audit_path = Some(value.trim_start_matches("--audit-path=").to_string());
                index += 1;
            }
            _ => break,
        }
    }
    Command::LaunchCleanup {
        manifest_path,
        execute,
        audit_path,
    }
}

fn extract_audit_path(args: &[String]) -> (Vec<String>, Option<String>) {
    let mut cleaned = Vec::with_capacity(args.len());
    let mut audit_path = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--audit-path" => {
                audit_path = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--audit-path=") => {
                audit_path = Some(value.trim_start_matches("--audit-path=").to_string());
                index += 1;
            }
            _ => {
                cleaned.push(args[index].clone());
                index += 1;
            }
        }
    }
    (cleaned, audit_path)
}

fn parse_protect(args: &[String]) -> Command {
    parse_protect_with_env(args, |key| std::env::var(key).ok())
}

fn parse_endpoint_setup(args: &[String]) -> Command {
    parse_endpoint_setup_with_env(args, |key| std::env::var(key).ok())
}

fn parse_evidence_linux_active_probe_docker_with_env(
    args: &[String],
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Command {
    let admit = args.iter().any(|arg| arg == "--admit");
    Command::EvidenceLinuxActiveProbeDocker {
        json: args.iter().any(|arg| arg == "--json"),
        execute: args.iter().any(|arg| arg == "--execute"),
        admit,
        replay: args.iter().any(|arg| arg == "--replay"),
        subject: parse_flag_value(args, "--subject"),
        context_hash: parse_flag_value(args, "--context-hash"),
        vault_host: parse_flag_value(args, "--vault-host"),
        image: parse_flag_value(args, "--image"),
        docker_network: parse_flag_value(args, "--docker-network"),
        replay_store: parse_flag_value(args, "--replay-store").or_else(|| {
            if admit {
                nonempty_env_default(&env_lookup, "WHOATHERE_REPLAY_STORE")
            } else {
                None
            }
        }),
        audit_path: parse_flag_value(args, "--audit-path")
            .or_else(|| nonempty_env_default(&env_lookup, "WHOATHERE_AUDIT_PATH")),
    }
}

fn parse_endpoint_setup_with_env(
    args: &[String],
    env_lookup: impl Fn(&str) -> Option<String>,
) -> Command {
    Command::EndpointSetup {
        shim_dir: parse_flag_value(args, "--shim-dir")
            .or_else(|| nonempty_env_default(&env_lookup, "WHOATHERE_SHIM_DIR")),
        workspace: parse_flag_value(args, "--workspace")
            .or_else(|| nonempty_env_default(&env_lookup, "WHOATHERE_WORKSPACE")),
        vault_origin: parse_flag_value(args, "--vault-origin")
            .or_else(|| nonempty_env_default(&env_lookup, "WHOATHERE_VAULT_ORIGIN")),
        policy_path: parse_flag_value(args, "--policy")
            .or_else(|| nonempty_env_default(&env_lookup, "WHOATHERE_POLICY")),
        audit_path: parse_flag_value(args, "--audit-path")
            .or_else(|| nonempty_env_default(&env_lookup, "WHOATHERE_AUDIT_PATH")),
        replay_store: parse_flag_value(args, "--replay-store")
            .or_else(|| nonempty_env_default(&env_lookup, "WHOATHERE_REPLAY_STORE")),
        include_python: args.iter().any(|arg| arg == "--include-python"),
    }
}

fn parse_protect_with_env(args: &[String], env_lookup: impl Fn(&str) -> Option<String>) -> Command {
    let mut execute = false;
    let mut policy_path = nonempty_env_default(&env_lookup, "WHOATHERE_POLICY");
    let mut workspace = nonempty_env_default(&env_lookup, "WHOATHERE_WORKSPACE");
    let mut vault_origin = nonempty_env_default(&env_lookup, "WHOATHERE_VAULT_ORIGIN");
    let mut audit_path = nonempty_env_default(&env_lookup, "WHOATHERE_AUDIT_PATH");
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--execute" => {
                execute = true;
                index += 1;
            }
            "--policy" => {
                policy_path = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--policy=") => {
                policy_path = Some(value.trim_start_matches("--policy=").to_string());
                index += 1;
            }
            "--workspace" => {
                workspace = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--workspace=") => {
                workspace = Some(value.trim_start_matches("--workspace=").to_string());
                index += 1;
            }
            "--vault-origin" => {
                vault_origin = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--vault-origin=") => {
                vault_origin = Some(value.trim_start_matches("--vault-origin=").to_string());
                index += 1;
            }
            "--audit-path" => {
                audit_path = args.get(index + 1).cloned();
                index += 2;
            }
            value if value.starts_with("--audit-path=") => {
                audit_path = Some(value.trim_start_matches("--audit-path=").to_string());
                index += 1;
            }
            _ => break,
        }
    }

    let Some(tool) = args.get(index).cloned() else {
        return Command::Help;
    };
    let remaining = &args[index + 1..];
    let command_args = if matches!(remaining.first(), Some(separator) if separator == "--") {
        remaining[1..].to_vec()
    } else {
        remaining.to_vec()
    };
    Command::Protect {
        tool,
        args: command_args,
        execute,
        policy_path,
        workspace,
        vault_origin,
        audit_path,
    }
}

fn render_vm_status(
    state_dir: Option<&str>,
    manifest_path: Option<&str>,
    helper_path: Option<&str>,
    json: bool,
) -> String {
    let config = macos_vm_config(state_dir, None, None);
    let default_manifest_path = default_macos_vm_manifest_path(&config);
    let provisioning_path = default_macos_vm_guest_provisioning_path(&config);
    let (manifest, manifest_load_reason, effective_manifest_path) =
        load_macos_vm_manifest(manifest_path, &default_manifest_path);
    let provisioning = load_macos_vm_guest_provisioning(&provisioning_path);
    let status = status_from_config(&config, HostPlatform::current(), manifest.as_ref());
    let helper = run_macos_vm_helper(
        helper_path,
        "status",
        &[
            "--state-dir".to_string(),
            config.state_dir.display().to_string(),
            "--json".to_string(),
        ],
    );
    if json {
        return render_vm_status_json(
            &status,
            &effective_manifest_path,
            manifest_load_reason.as_deref(),
            &provisioning,
            &helper,
        );
    }
    let mut output = format!(
        "whoathere vm status\nschema_version={}\nrelease_target={}\ntarget_arch={}\nvm_boundary={}\nnetwork_model={}\nsync_policy={}\nstate_dir={}\nhost_os={}\nhost_arch={}\nmemory_mib={}\ndisk_gib={}\nauto_suspend_minutes={}\nstate_dir_exists={}\nmanifest_path={}\nmanifest_present={}\nmanifest_valid={}\nhelper_ready_marker_present={}\nimage_ready_marker_present={}\nready={}\nreason_codes={:?}\n{}\n{}",
        status.schema_version,
        status.release_target,
        status.target_arch,
        status.vm_boundary,
        status.network_model,
        status.sync_policy,
        status.state_dir.display(),
        status.host.os,
        status.host.arch,
        status.memory_mib,
        status.disk_gib,
        status.auto_suspend_minutes,
        status.state_dir_exists,
        effective_manifest_path,
        status.manifest_present,
        status.manifest_valid,
        status.helper_ready_marker_present,
        status.image_ready_marker_present,
        status.ready,
        status.reason_codes,
        provisioning.render_text(),
        helper.render_text()
    );
    if let Some(reason) = manifest_load_reason {
        output.push_str(&format!("\nmanifest_load_reason={reason}"));
    }
    output
}

struct VmInitRenderArgs<'a> {
    state_dir: Option<&'a str>,
    manifest_path: Option<&'a str>,
    helper_path: Option<&'a str>,
    image_path: Option<&'a str>,
    restore_image_path: Option<&'a str>,
    fetch_latest_restore_image: bool,
    memory_mib: Option<u64>,
    disk_gib: Option<u64>,
    execute: bool,
}

fn render_vm_init(args: VmInitRenderArgs<'_>) -> String {
    let config = macos_vm_config(args.state_dir, args.memory_mib, args.disk_gib);
    let default_manifest_path = default_macos_vm_manifest_path(&config);
    let (manifest, manifest_load_reason, effective_manifest_path) =
        load_macos_vm_manifest(args.manifest_path, &default_manifest_path);
    let status = status_from_config(&config, HostPlatform::current(), manifest.as_ref());
    let mut reason_codes = status.reason_codes.clone();
    if !args.execute {
        reason_codes.push("macos_vm_init_execute_required_for_mutation".to_string());
    }
    reason_codes.sort();
    reason_codes.dedup();

    let helper = if args.execute {
        let mut helper_args = vec![
            "--state-dir".to_string(),
            config.state_dir.display().to_string(),
            "--memory-mib".to_string(),
            config.memory_mib.to_string(),
            "--disk-gib".to_string(),
            config.disk_gib.to_string(),
            "--execute".to_string(),
            "--json".to_string(),
        ];
        if let Some(image_path) = args.image_path {
            helper_args.push("--image".to_string());
            helper_args.push(image_path.to_string());
        }
        if let Some(restore_image_path) = args.restore_image_path {
            helper_args.push("--restore-image".to_string());
            helper_args.push(restore_image_path.to_string());
        }
        if args.fetch_latest_restore_image {
            helper_args.push("--fetch-latest-restore-image".to_string());
        }
        run_macos_vm_helper(args.helper_path, "init", &helper_args)
    } else {
        run_macos_vm_helper(
            args.helper_path,
            "init",
            &[
                "--state-dir".to_string(),
                config.state_dir.display().to_string(),
                "--memory-mib".to_string(),
                config.memory_mib.to_string(),
                "--disk-gib".to_string(),
                config.disk_gib.to_string(),
                "--json".to_string(),
            ],
        )
    };
    let final_exit_code = if args.execute {
        helper.exit_code.unwrap_or_else(|| ExitCode::Misuse.code())
    } else {
        ExitCode::Allow.code()
    };

    let mut output = format!(
        "whoathere vm init\nschema_version={}\nrelease_target={}\ntarget_arch={}\nvm_boundary={}\nnetwork_model={}\nsync_policy={}\nmutation={}\ndirect_cli_state_mutation=false\nstate_dir={}\nmanifest_path={}\nhelper_required_for_execute={}\nimage_path={}\nrestore_image_path={}\nfetch_latest_restore_image={}\nmemory_mib={}\ndisk_gib={}\nnative_memory_mib={}\nready=false\nreason_codes={:?}\n{}",
        whoathere_macos_vm::STATUS_SCHEMA_VERSION,
        RELEASE_TARGET,
        TARGET_ARCH,
        VM_BOUNDARY,
        NETWORK_MODEL,
        SYNC_POLICY,
        args.execute,
        config.state_dir.display(),
        effective_manifest_path,
        args.execute,
        redacted_option_scalar(args.image_path),
        redacted_option_scalar(args.restore_image_path),
        args.fetch_latest_restore_image,
        config.memory_mib,
        config.disk_gib,
        DEFAULT_NATIVE_MEMORY_MIB,
        reason_codes,
        helper.render_text()
    );
    if let Some(reason) = manifest_load_reason {
        output.push_str(&format!("\nmanifest_load_reason={reason}"));
    }
    output.push_str(&format!("\nexit_code={final_exit_code}"));
    output
}

fn render_vm_action(
    action: VmAction,
    state_dir: Option<&str>,
    helper_path: Option<&str>,
    execute: bool,
) -> String {
    let action_name = match action {
        VmAction::Start => "start",
        VmAction::Suspend => "suspend",
        VmAction::Reset => "reset",
        VmAction::Prune => "prune",
        VmAction::Health => "health",
    };
    let config = macos_vm_config(state_dir, None, None);
    if matches!(action, VmAction::Health) {
        let helper = run_macos_vm_helper(
            helper_path,
            action_name,
            &[
                "--state-dir".to_string(),
                config.state_dir.display().to_string(),
                "--json".to_string(),
            ],
        );
        let exit_code = helper.exit_code.unwrap_or_else(|| ExitCode::Misuse.code());
        return format!(
            "whoathere vm {action_name}\nrelease_target={}\nstate_dir={}\nmutation=false\nready=false\n{}\nexit_code={exit_code}",
            RELEASE_TARGET,
            config.state_dir.display(),
            helper.render_text()
        );
    }
    if execute {
        let helper = run_macos_vm_helper(
            helper_path,
            action_name,
            &[
                "--state-dir".to_string(),
                config.state_dir.display().to_string(),
                "--execute".to_string(),
                "--json".to_string(),
            ],
        );
        let exit_code = helper.exit_code.unwrap_or_else(|| ExitCode::Misuse.code());
        let mutation = exit_code == ExitCode::Allow.code();
        return format!(
            "whoathere vm {action_name}\nrelease_target={}\nstate_dir={}\nmutation_requested=true\nmutation={mutation}\nready=false\n{}\nexit_code={exit_code}",
            RELEASE_TARGET,
            config.state_dir.display(),
            helper.render_text()
        );
    }
    format!(
        "whoathere vm {action_name}\nrelease_target={}\nstate_dir={}\nmutation={}\nstatus=dry_run\nexit_code={}\nready=false\nreason_code=execute_required_for_mutation\nexplanation=rerun with --execute and a configured macOS VM helper to perform lifecycle mutation",
        RELEASE_TARGET,
        config.state_dir.display(),
        execute,
        ExitCode::Allow.code()
    )
}

struct VmDetonateRenderArgs<'a> {
    tool: &'a str,
    args: &'a [String],
    execute: bool,
    state_dir: Option<&'a str>,
    helper_path: Option<&'a str>,
    workspace: Option<&'a str>,
    fixture: Option<&'a str>,
    timeout_seconds: Option<u64>,
    json: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetonationMirrorPlan {
    workspace_configured: bool,
    workspace_path: Option<String>,
    workspace_root: Option<PathBuf>,
    allowed_file_count: usize,
    secret_exclusion_count: usize,
    symlink_escape_count: usize,
    large_file_exclusion_count: usize,
    package_data_file_count: usize,
    risky_file_exclusion_count: usize,
    total_allowed_bytes: u64,
    file_classes: Vec<String>,
    included_paths: Vec<String>,
    files: Vec<DetonationMirrorFile>,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DetonationMirrorFile {
    absolute_path: PathBuf,
    relative_path: String,
    class: String,
    size_bytes: u64,
}

impl DetonationMirrorPlan {
    fn unconfigured() -> Self {
        Self {
            workspace_configured: false,
            workspace_path: None,
            workspace_root: None,
            allowed_file_count: 0,
            secret_exclusion_count: 0,
            symlink_escape_count: 0,
            large_file_exclusion_count: 0,
            package_data_file_count: 0,
            risky_file_exclusion_count: 0,
            total_allowed_bytes: 0,
            file_classes: Vec::new(),
            included_paths: Vec::new(),
            files: Vec::new(),
            reason_codes: vec!["detonation_workspace_not_configured".to_string()],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectDetonationPlan {
    project_mode: bool,
    workflow: Option<String>,
    import_module: Option<String>,
    requirements_path: Option<String>,
    safe_to_execute: bool,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectPayloadPreparation {
    payload_path: String,
    payload_bytes: usize,
    payload_hex_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GuestJobEvidence {
    protocol: Option<String>,
    schema_version: Option<String>,
    agent_version: Option<String>,
    job_id: Option<String>,
    tool: Option<String>,
    command_class: Option<String>,
    fixture: Option<String>,
    status: Option<String>,
    verdict: Option<String>,
    reason_codes: Vec<String>,
    command_exit_code: Option<i32>,
    timed_out: Option<bool>,
    canary_access_detected: Option<bool>,
    network_attempt_detected: Option<bool>,
    filesystem_write_detected: Option<bool>,
    toolchain_available: Option<bool>,
    stdout_captured: Option<bool>,
    stderr_captured: Option<bool>,
    raw_canary_values_captured: Option<bool>,
    sync_back_enabled: Option<bool>,
    host_package_execution_enabled: Option<bool>,
    high_risk_package_execution_enabled: Option<bool>,
    project_mode: Option<bool>,
    project_workflow: Option<String>,
    project_import_module: Option<String>,
    project_requirements_path: Option<String>,
    vm_session_id: Option<String>,
    exit_code: Option<i32>,
}

const MAX_DETONATION_PROJECT_FILES: usize = 128;
const MAX_DETONATION_PROJECT_FILE_BYTES: u64 = 128 * 1024;
const MAX_DETONATION_PROJECT_TOTAL_BYTES: u64 = 512 * 1024;

fn render_vm_detonate(args: VmDetonateRenderArgs<'_>) -> String {
    let config = macos_vm_config(args.state_dir, None, None);
    let timeout_seconds = args.timeout_seconds.unwrap_or(120);
    let command_class = detonation_command_class(args.tool, args.args);
    let mirror_plan = args
        .workspace
        .map(build_detonation_mirror_plan)
        .unwrap_or_else(DetonationMirrorPlan::unconfigured);
    let project_plan =
        build_project_detonation_plan(args.tool, args.args, &mirror_plan, args.fixture);
    let canary_categories = default_canaries()
        .iter()
        .map(|canary| canary.category.to_string())
        .collect::<Vec<_>>();
    let mut reason_codes = mirror_plan.reason_codes.clone();
    reason_codes.extend(project_plan.reason_codes.iter().cloned());
    reason_codes.push("detonation_sync_back_disabled_goal_2".to_string());
    reason_codes.push("detonation_host_package_execution_disabled".to_string());
    if !args.execute {
        reason_codes.push("detonation_execute_required_for_vm_run".to_string());
    }
    if command_class == "unsupported_detonation" {
        reason_codes.push("detonation_workflow_unsupported".to_string());
    }
    if args.execute && args.fixture.is_none() && !project_plan.project_mode {
        reason_codes.push("detonation_fixture_or_project_required".to_string());
    }
    let mut payload_preparation: Option<ProjectPayloadPreparation> = None;
    let mut payload_prepare_error: Option<String> = None;
    if args.execute && project_plan.project_mode && project_plan.safe_to_execute {
        match prepare_project_payload(&config.state_dir, &mirror_plan) {
            Ok(preparation) => payload_preparation = Some(preparation),
            Err(reason) => {
                payload_prepare_error = Some(reason.clone());
                reason_codes.push(reason);
            }
        }
    }
    reason_codes.sort();
    reason_codes.dedup();

    let helper_invocation_allowed = args.execute
        && command_class != "unsupported_detonation"
        && payload_prepare_error.is_none()
        && (args.fixture.is_some() || project_plan.project_mode)
        && (!project_plan.project_mode || project_plan.safe_to_execute);
    let helper = if helper_invocation_allowed {
        let mut helper_args = vec![
            "--state-dir".to_string(),
            config.state_dir.display().to_string(),
            "--tool".to_string(),
            args.tool.to_string(),
            "--command-class".to_string(),
            command_class.to_string(),
            "--timeout-seconds".to_string(),
            timeout_seconds.to_string(),
            "--execute".to_string(),
            "--json".to_string(),
        ];
        if let Some(fixture) = args.fixture {
            helper_args.push("--fixture".to_string());
            helper_args.push(fixture.to_string());
        } else if project_plan.project_mode {
            helper_args.push("--fixture".to_string());
            helper_args.push("project_mirror".to_string());
        }
        if let Some(preparation) = &payload_preparation {
            helper_args.push("--project-payload-path".to_string());
            helper_args.push(preparation.payload_path.clone());
        }
        if let Some(workflow) = &project_plan.workflow {
            helper_args.push("--project-workflow".to_string());
            helper_args.push(workflow.clone());
        }
        if let Some(import_module) = &project_plan.import_module {
            helper_args.push("--project-import-module".to_string());
            helper_args.push(import_module.clone());
        }
        if let Some(requirements_path) = &project_plan.requirements_path {
            helper_args.push("--project-requirements-path".to_string());
            helper_args.push(requirements_path.clone());
        }
        if !args.args.is_empty() {
            helper_args.push("--".to_string());
            helper_args.extend(args.args.iter().cloned());
        }
        Some(run_macos_vm_helper(
            args.helper_path,
            "detonate",
            &helper_args,
        ))
    } else {
        None
    };
    let helper_exit_code = helper
        .as_ref()
        .and_then(|helper| helper.exit_code)
        .unwrap_or_else(|| ExitCode::Allow.code());
    let fail_closed_before_helper = command_class == "unsupported_detonation"
        || (args.fixture.is_none() && !project_plan.project_mode)
        || (project_plan.project_mode && !project_plan.safe_to_execute);
    let final_exit_code = if args.execute {
        if payload_prepare_error.is_some() {
            ExitCode::InternalError.code()
        } else if fail_closed_before_helper {
            ExitCode::Deny.code()
        } else {
            helper_exit_code
        }
    } else {
        ExitCode::Allow.code()
    };
    let verdict = if !args.execute {
        "dry_run_execute_required"
    } else if final_exit_code == ExitCode::Allow.code() {
        "helper_observed_clean"
    } else if final_exit_code == ExitCode::Deny.code()
        || final_exit_code == ExitCode::ManualReview.code()
    {
        "helper_security_outcome"
    } else {
        "helper_error_fail_closed"
    };

    if args.json {
        let helper_json = helper
            .as_ref()
            .map(render_vm_helper_json)
            .unwrap_or_else(|| "null".to_string());
        let guest_job = parse_guest_job_evidence(helper.as_ref());
        let guest_job_json = render_guest_job_evidence_json(guest_job.as_ref());
        return format!(
            "{{\n  \"command\": \"whoathere vm detonate\",\n  \"schema_version\": \"whoathere.macos_vm.detonation.v1\",\n  \"release_target\": {},\n  \"vm_boundary\": {},\n  \"network_model\": {},\n  \"sync_back_enabled\": false,\n  \"host_package_execution_enabled\": false,\n  \"high_risk_package_execution_enabled\": false,\n  \"mutation_requested\": {},\n  \"state_dir\": {},\n  \"tool\": {},\n  \"command_class\": {},\n  \"argv\": {},\n  \"fixture\": {},\n  \"timeout_seconds\": {},\n  \"workspace\": {},\n  \"mirror_plan\": {},\n  \"project_plan\": {},\n  \"project_payload\": {},\n  \"canary_categories\": {},\n  \"verdict\": {},\n  \"reason_codes\": {},\n  \"guest_job\": {},\n  \"helper\": {},\n  \"exit_code\": {}\n}}",
            json_string(RELEASE_TARGET),
            json_string(VM_BOUNDARY),
            json_string(NETWORK_MODEL),
            args.execute,
            json_string(&config.state_dir.display().to_string()),
            json_string(args.tool),
            json_string(command_class),
            json_string_array(
                &args
                    .args
                    .iter()
                    .map(|arg| redacted_scalar(arg))
                    .collect::<Vec<_>>()
            ),
            args.fixture
                .map(json_string)
                .unwrap_or_else(|| "null".to_string()),
            timeout_seconds,
            args.workspace
                .map(redacted_scalar)
                .map(|value| json_string(&value))
                .unwrap_or_else(|| "null".to_string()),
            render_detonation_mirror_plan_json(&mirror_plan),
            render_project_detonation_plan_json(&project_plan),
            render_project_payload_preparation_json(payload_preparation.as_ref()),
            json_string_array(&canary_categories),
            json_string(verdict),
            json_string_array(&reason_codes),
            guest_job_json,
            helper_json,
            final_exit_code
        );
    }

    let helper_text = helper
        .as_ref()
        .map(|helper| helper.render_text())
        .unwrap_or_else(|| "helper_invoked=false".to_string());
    format!(
        "whoathere vm detonate\nschema_version=whoathere.macos_vm.detonation.v1\nrelease_target={}\nvm_boundary={}\nnetwork_model={}\nsync_back_enabled=false\nhost_package_execution_enabled=false\nhigh_risk_package_execution_enabled=false\nmutation_requested={}\nstate_dir={}\ntool={}\ncommand_class={}\nargv={:?}\nfixture={}\ntimeout_seconds={}\nworkspace={}\nmirror_workspace_configured={}\nmirror_allowed_file_count={}\nmirror_secret_exclusion_count={}\nmirror_symlink_escape_count={}\nmirror_large_file_exclusion_count={}\nmirror_package_data_file_count={}\nmirror_risky_file_exclusion_count={}\nmirror_total_allowed_bytes={}\nmirror_file_classes={:?}\nmirror_included_paths={:?}\nmirror_reason_codes={:?}\nproject_mode={}\nproject_workflow={}\nproject_import_module={}\nproject_requirements_path={}\nproject_safe_to_execute={}\nproject_payload_path={}\ncanary_categories={:?}\nverdict={}\nreason_codes={:?}\n{}\nexit_code={}",
        RELEASE_TARGET,
        VM_BOUNDARY,
        NETWORK_MODEL,
        args.execute,
        config.state_dir.display(),
        args.tool,
        command_class,
        args.args
            .iter()
            .map(|arg| redacted_scalar(arg))
            .collect::<Vec<_>>(),
        args.fixture.unwrap_or("none"),
        timeout_seconds,
        args.workspace.map(redacted_scalar).unwrap_or_else(|| "none".to_string()),
        mirror_plan.workspace_configured,
        mirror_plan.allowed_file_count,
        mirror_plan.secret_exclusion_count,
        mirror_plan.symlink_escape_count,
        mirror_plan.large_file_exclusion_count,
        mirror_plan.package_data_file_count,
        mirror_plan.risky_file_exclusion_count,
        mirror_plan.total_allowed_bytes,
        mirror_plan.file_classes,
        mirror_plan.included_paths,
        mirror_plan.reason_codes,
        project_plan.project_mode,
        project_plan.workflow.as_deref().unwrap_or("none"),
        project_plan.import_module.as_deref().unwrap_or("none"),
        project_plan.requirements_path.as_deref().unwrap_or("none"),
        project_plan.safe_to_execute,
        payload_preparation
            .as_ref()
            .map(|payload| redacted_scalar(&payload.payload_path))
            .unwrap_or_else(|| "none".to_string()),
        canary_categories,
        verdict,
        reason_codes,
        helper_text,
        final_exit_code
    )
}

fn detonation_command_class(tool: &str, args: &[String]) -> &'static str {
    match tool {
        "npm" if args.iter().any(|arg| arg == "install" || arg == "ci") => "npm_install_detonation",
        "npm" if args.iter().any(|arg| arg == "exec") => "npm_exec_detonation",
        "npm" if args.iter().any(|arg| arg == "npx") => "npm_exec_detonation",
        "pip" if args.iter().any(|arg| arg == "install") => "pip_install_detonation",
        "uv" if args.iter().any(|arg| arg == "sync") => "uv_sync_detonation",
        "uv" if args
            .windows(2)
            .any(|pair| pair[0] == "pip" && pair[1] == "install") =>
        {
            "uv_sync_detonation"
        }
        _ => "unsupported_detonation",
    }
}

fn build_detonation_mirror_plan(workspace: &str) -> DetonationMirrorPlan {
    let path = Path::new(workspace);
    let canonical = match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => {
            return DetonationMirrorPlan {
                workspace_configured: true,
                workspace_path: Some(redacted_scalar(workspace)),
                workspace_root: None,
                allowed_file_count: 0,
                secret_exclusion_count: 0,
                symlink_escape_count: 0,
                large_file_exclusion_count: 0,
                package_data_file_count: 0,
                risky_file_exclusion_count: 0,
                total_allowed_bytes: 0,
                file_classes: Vec::new(),
                included_paths: Vec::new(),
                files: Vec::new(),
                reason_codes: vec!["detonation_workspace_not_found".to_string()],
            };
        }
    };
    if !canonical.is_dir() {
        return DetonationMirrorPlan {
            workspace_configured: true,
            workspace_path: Some(redacted_scalar(workspace)),
            workspace_root: None,
            allowed_file_count: 0,
            secret_exclusion_count: 0,
            symlink_escape_count: 0,
            large_file_exclusion_count: 0,
            package_data_file_count: 0,
            risky_file_exclusion_count: 0,
            total_allowed_bytes: 0,
            file_classes: Vec::new(),
            included_paths: Vec::new(),
            files: Vec::new(),
            reason_codes: vec!["detonation_workspace_not_directory".to_string()],
        };
    }

    let mut plan = DetonationMirrorPlan {
        workspace_configured: true,
        workspace_path: Some(redacted_scalar(workspace)),
        workspace_root: Some(canonical.clone()),
        allowed_file_count: 0,
        secret_exclusion_count: 0,
        symlink_escape_count: 0,
        large_file_exclusion_count: 0,
        package_data_file_count: 0,
        risky_file_exclusion_count: 0,
        total_allowed_bytes: 0,
        file_classes: Vec::new(),
        included_paths: Vec::new(),
        files: Vec::new(),
        reason_codes: Vec::new(),
    };
    let mut stack = vec![canonical.clone()];
    let mut visited = 0_usize;
    while let Some(directory) = stack.pop() {
        visited += 1;
        if visited > 2048 {
            push_unique(
                &mut plan.reason_codes,
                "detonation_workspace_scan_limit_reached",
            );
            break;
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            push_unique(
                &mut plan.reason_codes,
                "detonation_workspace_read_dir_failed",
            );
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                push_unique(
                    &mut plan.reason_codes,
                    "detonation_workspace_metadata_failed",
                );
                continue;
            };
            if is_secret_or_credential_path(&path) {
                plan.secret_exclusion_count += 1;
                continue;
            }
            let Ok(file_type) = entry.file_type() else {
                push_unique(
                    &mut plan.reason_codes,
                    "detonation_workspace_file_type_failed",
                );
                continue;
            };
            if file_type.is_symlink() {
                match std::fs::canonicalize(&path) {
                    Ok(target) if target.starts_with(&canonical) => {}
                    _ => {
                        plan.symlink_escape_count += 1;
                        push_unique(
                            &mut plan.reason_codes,
                            "detonation_workspace_symlink_escape_blocked",
                        );
                        continue;
                    }
                }
            }
            if metadata.is_dir() {
                if should_skip_mirror_directory(&path) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if !metadata.is_file() {
                continue;
            }
            if let Some(class) = allowed_mirror_input_class(&path, &canonical) {
                if metadata.len() > MAX_DETONATION_PROJECT_FILE_BYTES {
                    plan.large_file_exclusion_count += 1;
                    push_unique(
                        &mut plan.reason_codes,
                        "detonation_workspace_large_file_excluded",
                    );
                    continue;
                }
                if plan.files.len() >= MAX_DETONATION_PROJECT_FILES {
                    push_unique(
                        &mut plan.reason_codes,
                        "detonation_workspace_file_count_limit_reached",
                    );
                    continue;
                }
                let next_total = plan.total_allowed_bytes.saturating_add(metadata.len());
                if next_total > MAX_DETONATION_PROJECT_TOTAL_BYTES {
                    plan.large_file_exclusion_count += 1;
                    push_unique(
                        &mut plan.reason_codes,
                        "detonation_workspace_total_size_limit_reached",
                    );
                    continue;
                }
                let Ok(relative_path) = path.strip_prefix(&canonical) else {
                    push_unique(
                        &mut plan.reason_codes,
                        "detonation_workspace_relative_path_failed",
                    );
                    continue;
                };
                let Some(relative_path) = safe_project_relative_path(relative_path) else {
                    push_unique(
                        &mut plan.reason_codes,
                        "detonation_workspace_unsafe_relative_path_blocked",
                    );
                    continue;
                };
                let Ok(canonical_file) = std::fs::canonicalize(&path) else {
                    push_unique(
                        &mut plan.reason_codes,
                        "detonation_workspace_file_canonicalize_failed",
                    );
                    continue;
                };
                if !canonical_file.starts_with(&canonical) {
                    plan.symlink_escape_count += 1;
                    push_unique(
                        &mut plan.reason_codes,
                        "detonation_workspace_symlink_escape_blocked",
                    );
                    continue;
                }
                plan.allowed_file_count += 1;
                plan.total_allowed_bytes = next_total;
                if class == "python_package_data" {
                    plan.package_data_file_count += 1;
                }
                push_unique(&mut plan.file_classes, class);
                plan.included_paths.push(relative_path.clone());
                plan.files.push(DetonationMirrorFile {
                    absolute_path: path,
                    relative_path,
                    class: class.to_string(),
                    size_bytes: metadata.len(),
                });
            } else if is_risky_project_file(&path) {
                plan.risky_file_exclusion_count += 1;
                push_unique(
                    &mut plan.reason_codes,
                    "detonation_workspace_risky_file_excluded",
                );
            }
        }
    }
    if plan.allowed_file_count == 0 {
        push_unique(
            &mut plan.reason_codes,
            "detonation_workspace_no_allowed_inputs",
        );
    }
    if plan.package_data_file_count > 0 {
        push_unique(
            &mut plan.reason_codes,
            "detonation_workspace_safe_package_data_included",
        );
    }
    plan.file_classes.sort();
    plan.included_paths.sort();
    plan.reason_codes.sort();
    plan
}

fn allowed_mirror_input_class(path: &Path, workspace_root: &Path) -> Option<&'static str> {
    let file_name = path.file_name()?.to_string_lossy().to_ascii_lowercase();
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase());
    match file_name.as_str() {
        "package.json" => Some("npm_manifest"),
        "package-lock.json" | "npm-shrinkwrap.json" => Some("npm_lockfile"),
        "pyproject.toml" | "setup.py" | "setup.cfg" => Some("python_build_config"),
        "uv.lock" | "poetry.lock" => Some("python_lockfile"),
        _ if file_name.starts_with("requirements") && file_name.ends_with(".txt") => {
            Some("python_requirements")
        }
        _ if file_name.starts_with("constraints") && file_name.ends_with(".txt") => {
            Some("python_constraints")
        }
        _ if matches!(extension.as_deref(), Some("js" | "cjs" | "mjs")) => Some("npm_source"),
        "__init__.py" => Some("python_package_init"),
        _ if extension.as_deref() == Some("py") => Some("python_source"),
        _ if extension.as_deref() == Some("pth") => Some("python_startup_hook"),
        _ if is_safe_python_package_data(path, workspace_root) => Some("python_package_data"),
        _ => None,
    }
}

fn is_safe_python_package_data(path: &Path, workspace_root: &Path) -> bool {
    let Some(extension) = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    if !matches!(
        extension.as_str(),
        "txt" | "md" | "rst" | "json" | "toml" | "yaml" | "yml" | "csv"
    ) {
        return false;
    }
    if is_risky_project_file(path) || is_secret_or_credential_path(path) {
        return false;
    }
    package_data_parent_is_python_package(path, workspace_root)
}

fn package_data_parent_is_python_package(path: &Path, workspace_root: &Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    if parent == workspace_root {
        return false;
    }
    let Ok(relative_parent) = parent.strip_prefix(workspace_root) else {
        return false;
    };
    if relative_parent.components().next().is_none() {
        return false;
    }
    let mut current = Some(parent);
    while let Some(directory) = current {
        if directory == workspace_root {
            return false;
        }
        if directory.join("__init__.py").is_file() {
            return true;
        }
        current = directory.parent();
    }
    false
}

fn is_risky_project_file(path: &Path) -> bool {
    let file_name = path.file_name().map(|name| {
        name.to_string_lossy()
            .trim()
            .to_ascii_lowercase()
            .replace('\\', "/")
    });
    let file_name = file_name.as_deref().unwrap_or("");
    if matches!(
        file_name,
        "binding.gyp"
            | "cmakelists.txt"
            | "makefile"
            | "setup.cfg.native"
            | "cargo.toml"
            | "go.mod"
    ) {
        return true;
    }
    let normalized = path
        .to_string_lossy()
        .to_ascii_lowercase()
        .replace('\\', "/");
    if normalized.ends_with(".tar.gz")
        || normalized.ends_with(".tar.bz2")
        || normalized.ends_with(".tar.xz")
    {
        return true;
    }
    let Some(extension) = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
    else {
        return false;
    };
    matches!(
        extension.as_str(),
        "so" | "dylib"
            | "dll"
            | "pyd"
            | "o"
            | "a"
            | "lib"
            | "exe"
            | "bin"
            | "whl"
            | "zip"
            | "gz"
            | "bz2"
            | "xz"
            | "tgz"
            | "c"
            | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "rs"
            | "go"
            | "swift"
            | "m"
            | "mm"
    )
}

fn should_skip_mirror_directory(path: &Path) -> bool {
    path.file_name()
        .map(|name| {
            let name = name.to_string_lossy().to_ascii_lowercase();
            matches!(
                name.as_str(),
                ".git"
                    | ".cache"
                    | "node_modules"
                    | ".venv"
                    | "venv"
                    | "__pycache__"
                    | ".mypy_cache"
                    | ".pytest_cache"
                    | "target"
                    | ".tox"
                    | "build"
                    | "dist"
            ) || name.starts_with('.')
                || name.ends_with(".egg-info")
        })
        .unwrap_or(false)
}

fn is_secret_or_credential_path(path: &Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy().to_ascii_lowercase();
        matches!(
            value.as_str(),
            ".env"
                | ".env.local"
                | ".envrc"
                | ".npmrc"
                | ".pypirc"
                | "pip.conf"
                | "pip.ini"
                | ".netrc"
                | ".aws"
                | ".azure"
                | ".gcp"
                | ".config"
                | ".kube"
                | ".ssh"
                | "application_default_credentials.json"
                | "id_rsa"
                | "id_ed25519"
                | "known_hosts"
                | ".git-credentials"
                | ".gitconfig"
                | ".docker"
        )
    })
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn render_detonation_mirror_plan_json(plan: &DetonationMirrorPlan) -> String {
    format!(
        "{{\"workspace_configured\": {}, \"workspace_path\": {}, \"allowed_file_count\": {}, \"secret_exclusion_count\": {}, \"symlink_escape_count\": {}, \"large_file_exclusion_count\": {}, \"package_data_file_count\": {}, \"risky_file_exclusion_count\": {}, \"total_allowed_bytes\": {}, \"file_classes\": {}, \"included_paths\": {}, \"reason_codes\": {}}}",
        plan.workspace_configured,
        plan.workspace_path
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_string()),
        plan.allowed_file_count,
        plan.secret_exclusion_count,
        plan.symlink_escape_count,
        plan.large_file_exclusion_count,
        plan.package_data_file_count,
        plan.risky_file_exclusion_count,
        plan.total_allowed_bytes,
        json_string_array(&plan.file_classes),
        json_string_array(&plan.included_paths),
        json_string_array(&plan.reason_codes)
    )
}

fn build_project_detonation_plan(
    tool: &str,
    args: &[String],
    mirror_plan: &DetonationMirrorPlan,
    fixture: Option<&str>,
) -> ProjectDetonationPlan {
    if fixture.is_some() {
        return ProjectDetonationPlan {
            project_mode: false,
            workflow: None,
            import_module: None,
            requirements_path: None,
            safe_to_execute: false,
            reason_codes: Vec::new(),
        };
    }
    if tool == "npm" {
        return build_npm_project_detonation_plan(args, mirror_plan);
    }
    if tool != "pip" {
        return ProjectDetonationPlan {
            project_mode: false,
            workflow: None,
            import_module: None,
            requirements_path: None,
            safe_to_execute: false,
            reason_codes: vec!["project_detonation_pip_only_goal_3".to_string()],
        };
    }
    if !mirror_plan.workspace_configured || mirror_plan.workspace_root.is_none() {
        return ProjectDetonationPlan {
            project_mode: false,
            workflow: None,
            import_module: None,
            requirements_path: None,
            safe_to_execute: false,
            reason_codes: vec!["project_detonation_workspace_required".to_string()],
        };
    }

    let mut reason_codes = Vec::new();
    let install_index = args.iter().position(|arg| arg == "install");
    let Some(install_index) = install_index else {
        return ProjectDetonationPlan {
            project_mode: true,
            workflow: None,
            import_module: None,
            requirements_path: None,
            safe_to_execute: false,
            reason_codes: vec!["project_detonation_pip_install_required".to_string()],
        };
    };
    let install_args = &args[install_index + 1..];
    let import_module = infer_project_import_module(mirror_plan);

    if install_args
        .iter()
        .any(|arg| arg == "-e" || arg == "--editable" || arg.starts_with("-e"))
    {
        reason_codes.push("project_editable_dependency_denied".to_string());
    }
    if install_args
        .iter()
        .any(|arg| is_direct_or_vcs_reference(arg))
    {
        reason_codes.push("project_direct_or_vcs_dependency_denied".to_string());
    }
    if install_args
        .iter()
        .any(|arg| arg == "--only-binary" || arg == "--prefer-binary")
    {
        reason_codes.push("project_binary_preference_requires_manual_review".to_string());
    }

    let has_local_project_install = install_args.iter().any(|arg| arg == "." || arg == "./");
    let requirements_path = parse_pip_requirements_path(install_args);
    if has_local_project_install && requirements_path.is_none() {
        if !project_has_python_build_input(mirror_plan) {
            reason_codes.push("project_python_build_input_missing".to_string());
        }
        if mirror_plan.risky_file_exclusion_count > 0 {
            reason_codes.push("project_risky_file_requires_manual_review".to_string());
        }
        if mirror_plan.symlink_escape_count > 0 {
            reason_codes.push("project_symlink_escape_blocked".to_string());
        }
        reason_codes.sort();
        reason_codes.dedup();
        return ProjectDetonationPlan {
            project_mode: true,
            workflow: Some("pip_project_install".to_string()),
            import_module,
            requirements_path: None,
            safe_to_execute: reason_codes.is_empty(),
            reason_codes,
        };
    }

    if let Some(requirements_path) = requirements_path {
        match validate_project_requirements(&requirements_path, mirror_plan) {
            Ok(mut requirements_reasons) => reason_codes.append(&mut requirements_reasons),
            Err(reason) => reason_codes.push(reason),
        }
        if mirror_plan.symlink_escape_count > 0 {
            reason_codes.push("project_symlink_escape_blocked".to_string());
        }
        if mirror_plan.risky_file_exclusion_count > 0 {
            reason_codes.push("project_risky_file_requires_manual_review".to_string());
        }
        reason_codes.sort();
        reason_codes.dedup();
        return ProjectDetonationPlan {
            project_mode: true,
            workflow: Some("pip_requirements_install".to_string()),
            import_module,
            requirements_path: Some(requirements_path),
            safe_to_execute: reason_codes.is_empty(),
            reason_codes,
        };
    }

    reason_codes.push("project_install_target_requires_manual_review".to_string());
    reason_codes.sort();
    reason_codes.dedup();
    ProjectDetonationPlan {
        project_mode: true,
        workflow: None,
        import_module,
        requirements_path: None,
        safe_to_execute: false,
        reason_codes,
    }
}

fn build_npm_project_detonation_plan(
    args: &[String],
    mirror_plan: &DetonationMirrorPlan,
) -> ProjectDetonationPlan {
    if !mirror_plan.workspace_configured || mirror_plan.workspace_root.is_none() {
        return ProjectDetonationPlan {
            project_mode: false,
            workflow: None,
            import_module: None,
            requirements_path: None,
            safe_to_execute: false,
            reason_codes: vec!["project_detonation_workspace_required".to_string()],
        };
    }

    let mut reason_codes = Vec::new();
    let workflow = if args.iter().any(|arg| arg == "ci") {
        if !mirror_plan
            .included_paths
            .iter()
            .any(|path| matches!(path.as_str(), "package-lock.json" | "npm-shrinkwrap.json"))
        {
            reason_codes.push("project_npm_ci_lockfile_required".to_string());
        }
        Some("npm_ci".to_string())
    } else if args.iter().any(|arg| arg == "install") {
        Some("npm_project_install".to_string())
    } else {
        reason_codes.push("project_npm_install_or_ci_required".to_string());
        None
    };

    if !mirror_plan
        .included_paths
        .iter()
        .any(|path| path == "package.json")
    {
        reason_codes.push("project_npm_manifest_required".to_string());
    }
    if mirror_plan.symlink_escape_count > 0 {
        reason_codes.push("project_symlink_escape_blocked".to_string());
    }
    if mirror_plan.risky_file_exclusion_count > 0 {
        reason_codes.push("project_risky_file_requires_manual_review".to_string());
    }
    if npm_args_request_external_resolution(args) {
        reason_codes.push("project_npm_external_package_arg_denied".to_string());
    }
    match validate_npm_project_manifest_and_lock(mirror_plan) {
        Ok(mut npm_reasons) => reason_codes.append(&mut npm_reasons),
        Err(reason) => reason_codes.push(reason),
    }
    reason_codes.sort();
    reason_codes.dedup();

    ProjectDetonationPlan {
        project_mode: true,
        workflow,
        import_module: None,
        requirements_path: None,
        safe_to_execute: reason_codes.is_empty(),
        reason_codes,
    }
}

fn npm_args_request_external_resolution(args: &[String]) -> bool {
    let mut command_seen = false;
    for arg in args {
        if matches!(
            arg.as_str(),
            "--registry" | "--cache" | "--prefix" | "--userconfig" | "--globalconfig"
        ) {
            return true;
        }
        if matches!(arg.as_str(), "-g" | "--global") || arg.starts_with("--registry=") {
            return true;
        }
        if arg == "install" || arg == "ci" {
            command_seen = true;
            continue;
        }
        if !command_seen || arg.starts_with('-') {
            continue;
        }
        return true;
    }
    false
}

fn validate_npm_project_manifest_and_lock(
    mirror_plan: &DetonationMirrorPlan,
) -> Result<Vec<String>, String> {
    let package_file = mirror_plan
        .files
        .iter()
        .find(|file| file.relative_path == "package.json")
        .ok_or_else(|| "project_npm_manifest_required".to_string())?;
    let package_json = std::fs::read_to_string(&package_file.absolute_path)
        .map_err(|_| "project_npm_manifest_read_failed".to_string())?;
    let mut reasons = Vec::new();
    for dependency_key in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundleDependencies",
        "bundledDependencies",
    ] {
        match json_object_field_is_empty(&package_json, dependency_key) {
            JsonObjectFieldState::Missing | JsonObjectFieldState::Empty => {}
            JsonObjectFieldState::NonEmpty => {
                reasons.push("project_npm_dependency_resolution_deferred".to_string())
            }
            JsonObjectFieldState::Invalid => {
                reasons.push("project_npm_manifest_dependency_section_invalid".to_string())
            }
        }
    }
    if contains_npm_source_override(&package_json) {
        reasons.push("project_npm_source_override_denied".to_string());
    }
    if package_json.contains("\"gypfile\"") || package_json.contains("binding.gyp") {
        reasons.push("project_npm_native_marker_requires_manual_review".to_string());
    }

    for lock in mirror_plan.files.iter().filter(|file| {
        matches!(
            file.relative_path.as_str(),
            "package-lock.json" | "npm-shrinkwrap.json"
        )
    }) {
        let lock_text = std::fs::read_to_string(&lock.absolute_path)
            .map_err(|_| "project_npm_lockfile_read_failed".to_string())?;
        if contains_npm_source_override(&lock_text) || lock_text.contains("\"node_modules/") {
            reasons.push("project_npm_lock_resolution_deferred".to_string());
        }
    }

    reasons.sort();
    reasons.dedup();
    Ok(reasons)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonObjectFieldState {
    Missing,
    Empty,
    NonEmpty,
    Invalid,
}

fn json_object_field_is_empty(input: &str, key: &str) -> JsonObjectFieldState {
    let Some(position) = input.find(&format!("\"{key}\"")) else {
        return JsonObjectFieldState::Missing;
    };
    let after_key = &input[position + key.len() + 2..];
    let Some(colon_position) = after_key.find(':') else {
        return JsonObjectFieldState::Invalid;
    };
    let after_colon = after_key[colon_position + 1..].trim_start();
    if !after_colon.starts_with('{') {
        return JsonObjectFieldState::Invalid;
    }
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut saw_content = false;
    for character in after_colon.chars() {
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            if depth == 1 {
                saw_content = true;
            }
            continue;
        }
        match character {
            '"' => {
                in_string = true;
                if depth == 1 {
                    saw_content = true;
                }
            }
            '{' => {
                depth += 1;
                if depth > 1 {
                    saw_content = true;
                }
            }
            '}' => {
                if depth == 1 {
                    return if saw_content {
                        JsonObjectFieldState::NonEmpty
                    } else {
                        JsonObjectFieldState::Empty
                    };
                }
                depth -= 1;
                if depth < 0 {
                    return JsonObjectFieldState::Invalid;
                }
            }
            character if character.is_whitespace() => {}
            _ if depth == 1 => saw_content = true,
            _ => {}
        }
    }
    JsonObjectFieldState::Invalid
}

fn contains_npm_source_override(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("http://")
        || lower.contains("https://")
        || lower.contains("git+")
        || lower.contains("github:")
        || lower.contains("gitlab:")
        || lower.contains("bitbucket:")
        || lower.contains("file:")
        || lower.contains("link:")
        || lower.contains("workspace:")
}

fn project_has_python_build_input(mirror_plan: &DetonationMirrorPlan) -> bool {
    mirror_plan
        .included_paths
        .iter()
        .any(|path| matches!(path.as_str(), "pyproject.toml" | "setup.py" | "setup.cfg"))
}

fn parse_pip_requirements_path(args: &[String]) -> Option<String> {
    for (index, arg) in args.iter().enumerate() {
        if arg == "-r" || arg == "--requirement" {
            return args.get(index + 1).cloned();
        }
        if let Some(value) = arg.strip_prefix("-r") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
        if let Some(value) = arg.strip_prefix("--requirement=") {
            return Some(value.to_string());
        }
    }
    None
}

fn validate_project_requirements(
    requirements_path: &str,
    mirror_plan: &DetonationMirrorPlan,
) -> Result<Vec<String>, String> {
    let normalized = normalize_relative_project_path(requirements_path)
        .ok_or_else(|| "project_requirements_path_escape_blocked".to_string())?;
    let mut reasons = Vec::new();
    let mut visited = Vec::new();
    validate_project_requirements_file(&normalized, mirror_plan, &mut visited, &mut reasons)?;
    reasons.sort();
    reasons.dedup();
    Ok(reasons)
}

fn validate_project_requirements_file(
    requirements_path: &str,
    mirror_plan: &DetonationMirrorPlan,
    visited: &mut Vec<String>,
    reasons: &mut Vec<String>,
) -> Result<(), String> {
    if visited.iter().any(|visited| visited == requirements_path) {
        return Ok(());
    }
    visited.push(requirements_path.to_string());
    let Some(file) = mirror_plan
        .files
        .iter()
        .find(|file| file.relative_path == requirements_path)
    else {
        return Err("project_requirements_file_not_in_mirror".to_string());
    };
    let contents = std::fs::read_to_string(&file.absolute_path)
        .map_err(|_| "project_requirements_read_failed".to_string())?;
    for raw_line in contents.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some(include_path) = line
            .strip_prefix("-r ")
            .or_else(|| line.strip_prefix("--requirement "))
            .or_else(|| line.strip_prefix("-c "))
            .or_else(|| line.strip_prefix("--constraint "))
        {
            let include_path = normalize_relative_project_path(include_path.trim())
                .ok_or_else(|| "project_requirements_path_escape_blocked".to_string())?;
            validate_project_requirements_file(&include_path, mirror_plan, visited, reasons)?;
            continue;
        }
        if let Some(include_path) = line.strip_prefix("--requirement=") {
            let include_path = normalize_relative_project_path(include_path.trim())
                .ok_or_else(|| "project_requirements_path_escape_blocked".to_string())?;
            validate_project_requirements_file(&include_path, mirror_plan, visited, reasons)?;
            continue;
        }
        if let Some(include_path) = line.strip_prefix("--constraint=") {
            let include_path = normalize_relative_project_path(include_path.trim())
                .ok_or_else(|| "project_requirements_path_escape_blocked".to_string())?;
            validate_project_requirements_file(&include_path, mirror_plan, visited, reasons)?;
            continue;
        }
        if line == "." || line.starts_with("./") {
            continue;
        }
        if line.starts_with("-e") || line.starts_with("--editable") {
            reasons.push("project_requirements_editable_denied".to_string());
            continue;
        }
        if is_direct_or_vcs_reference(line) {
            reasons.push("project_requirements_direct_or_vcs_denied".to_string());
            continue;
        }
        reasons.push("project_requirements_public_resolution_deferred".to_string());
    }
    Ok(())
}

fn is_direct_or_vcs_reference(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("://")
        || lower.starts_with("git+")
        || lower.starts_with("hg+")
        || lower.starts_with("svn+")
        || lower.starts_with("bzr+")
        || lower.contains(" @ ")
        || lower.ends_with(".whl")
        || lower.ends_with(".tar.gz")
        || lower.ends_with(".zip")
}

fn infer_project_import_module(mirror_plan: &DetonationMirrorPlan) -> Option<String> {
    mirror_plan
        .included_paths
        .iter()
        .filter_map(|path| path.strip_suffix("/__init__.py"))
        .find(|path| safe_python_module_name(path))
        .map(|path| path.replace('/', "."))
        .or_else(|| {
            mirror_plan.included_paths.iter().find_map(|path| {
                let module = path.strip_suffix(".py")?;
                if matches!(module, "setup" | "whoathere_backend") || module.contains('/') {
                    return None;
                }
                safe_python_module_name(module).then(|| module.to_string())
            })
        })
}

fn safe_python_module_name(value: &str) -> bool {
    !value.is_empty()
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric()
                || character == '_'
                || character == '/'
                || character == '.'
        })
        && !value.contains("..")
        && !value.starts_with('/')
}

fn safe_project_relative_path(path: &Path) -> Option<String> {
    let value = path.to_string_lossy().replace('\\', "/");
    normalize_relative_project_path(&value)
}

fn normalize_relative_project_path(value: &str) -> Option<String> {
    let value = value.trim().replace('\\', "/");
    if value.is_empty() || value.starts_with('/') || value.contains('\0') {
        return None;
    }
    let mut components = Vec::new();
    for component in value.split('/') {
        match component {
            "" | "." => {}
            ".." => return None,
            component => components.push(component),
        }
    }
    if components.is_empty() {
        return None;
    }
    Some(components.join("/"))
}

fn prepare_project_payload(
    state_dir: &Path,
    mirror_plan: &DetonationMirrorPlan,
) -> Result<ProjectPayloadPreparation, String> {
    let payload = encode_project_payload(&mirror_plan.files)?;
    let payload_hex = hex_encode(&payload);
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "project_payload_clock_error".to_string())?
        .as_millis();
    let payload_dir = state_dir.join("runs").join("project-payloads");
    std::fs::create_dir_all(&payload_dir)
        .map_err(|_| "project_payload_directory_create_failed".to_string())?;
    let payload_path = payload_dir.join(format!("{created_at}.payload.hex"));
    let mut file = std::fs::File::create(&payload_path)
        .map_err(|_| "project_payload_write_failed".to_string())?;
    file.write_all(payload_hex.as_bytes())
        .map_err(|_| "project_payload_write_failed".to_string())?;
    Ok(ProjectPayloadPreparation {
        payload_path: payload_path.display().to_string(),
        payload_bytes: payload.len(),
        payload_hex_bytes: payload_hex.len(),
    })
}

fn encode_project_payload(files: &[DetonationMirrorFile]) -> Result<Vec<u8>, String> {
    if files.len() > MAX_DETONATION_PROJECT_FILES {
        return Err("project_payload_file_count_limit_exceeded".to_string());
    }
    let mut payload = Vec::new();
    payload.extend_from_slice(b"WTP1");
    let file_count = u32::try_from(files.len())
        .map_err(|_| "project_payload_file_count_limit_exceeded".to_string())?;
    payload.extend_from_slice(&file_count.to_le_bytes());
    let mut total_bytes = 0_u64;
    for file in files {
        let contents = std::fs::read(&file.absolute_path)
            .map_err(|_| "project_payload_file_read_failed".to_string())?;
        if contents.len() as u64 != file.size_bytes {
            return Err("project_payload_file_changed_during_read".to_string());
        }
        if file.size_bytes > MAX_DETONATION_PROJECT_FILE_BYTES {
            return Err("project_payload_file_size_limit_exceeded".to_string());
        }
        total_bytes = total_bytes.saturating_add(file.size_bytes);
        if total_bytes > MAX_DETONATION_PROJECT_TOTAL_BYTES {
            return Err("project_payload_total_size_limit_exceeded".to_string());
        }
        let path_bytes = file.relative_path.as_bytes();
        let path_len = u16::try_from(path_bytes.len())
            .map_err(|_| "project_payload_path_too_long".to_string())?;
        let content_len = u32::try_from(contents.len())
            .map_err(|_| "project_payload_file_size_limit_exceeded".to_string())?;
        payload.extend_from_slice(&path_len.to_le_bytes());
        payload.extend_from_slice(&content_len.to_le_bytes());
        payload.extend_from_slice(path_bytes);
        payload.extend_from_slice(&contents);
    }
    Ok(payload)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn render_project_detonation_plan_json(plan: &ProjectDetonationPlan) -> String {
    format!(
        "{{\"project_mode\": {}, \"workflow\": {}, \"import_module\": {}, \"requirements_path\": {}, \"safe_to_execute\": {}, \"reason_codes\": {}}}",
        plan.project_mode,
        json_option_string(plan.workflow.as_deref()),
        json_option_string(plan.import_module.as_deref()),
        json_option_string(plan.requirements_path.as_deref()),
        plan.safe_to_execute,
        json_string_array(&plan.reason_codes)
    )
}

fn render_project_payload_preparation_json(payload: Option<&ProjectPayloadPreparation>) -> String {
    payload
        .map(|payload| {
            format!(
                "{{\"payload_path\": {}, \"payload_bytes\": {}, \"payload_hex_bytes\": {}}}",
                json_string(&redacted_scalar(&payload.payload_path)),
                payload.payload_bytes,
                payload.payload_hex_bytes
            )
        })
        .unwrap_or_else(|| "null".to_string())
}

fn render_vm_helper_json(helper: &MacosVmHelperOutput) -> String {
    format!(
        "{{\"path\": {}, \"available\": {}, \"exit_code\": {}, \"reason_codes\": {}, \"stdout_truncated\": {}, \"stderr_truncated\": {}, \"stdout\": {}, \"stderr\": {}}}",
        helper
            .configured_path
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_string()),
        helper.available,
        helper
            .exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "null".to_string()),
        json_string_array(&helper.reason_codes),
        helper.stdout_truncated,
        helper.stderr_truncated,
        json_string(&single_line(&redacted_scalar(&helper.stdout))),
        json_string(&single_line(&redacted_scalar(&helper.stderr)))
    )
}

fn parse_guest_job_evidence(helper: Option<&MacosVmHelperOutput>) -> Option<GuestJobEvidence> {
    let helper = helper?;
    if helper.stdout_truncated || !helper.stdout.contains("whoathere.guest_detonation.v1") {
        return None;
    }
    Some(GuestJobEvidence {
        protocol: json_extract_string_field(&helper.stdout, "protocol"),
        schema_version: json_extract_string_field(&helper.stdout, "schema_version"),
        agent_version: json_extract_string_field(&helper.stdout, "agent_version"),
        job_id: json_extract_string_field(&helper.stdout, "job_id"),
        tool: json_extract_string_field(&helper.stdout, "tool"),
        command_class: json_extract_string_field(&helper.stdout, "command_class"),
        fixture: json_extract_string_field(&helper.stdout, "fixture"),
        status: json_extract_string_field(&helper.stdout, "status"),
        verdict: json_extract_string_field(&helper.stdout, "verdict"),
        reason_codes: json_extract_string_array_field(&helper.stdout, "reason_codes"),
        command_exit_code: json_extract_i32_field(&helper.stdout, "command_exit_code"),
        timed_out: json_extract_bool_field(&helper.stdout, "timed_out"),
        canary_access_detected: json_extract_bool_field(&helper.stdout, "canary_access_detected"),
        network_attempt_detected: json_extract_bool_field(
            &helper.stdout,
            "network_attempt_detected",
        ),
        filesystem_write_detected: json_extract_bool_field(
            &helper.stdout,
            "filesystem_write_detected",
        ),
        toolchain_available: json_extract_bool_field(&helper.stdout, "toolchain_available"),
        stdout_captured: json_extract_bool_field(&helper.stdout, "stdout_captured"),
        stderr_captured: json_extract_bool_field(&helper.stdout, "stderr_captured"),
        raw_canary_values_captured: json_extract_bool_field(
            &helper.stdout,
            "raw_canary_values_captured",
        ),
        sync_back_enabled: json_extract_bool_field(&helper.stdout, "sync_back_enabled"),
        host_package_execution_enabled: json_extract_bool_field(
            &helper.stdout,
            "host_package_execution_enabled",
        ),
        high_risk_package_execution_enabled: json_extract_bool_field(
            &helper.stdout,
            "high_risk_package_execution_enabled",
        ),
        project_mode: json_extract_bool_field(&helper.stdout, "project_mode"),
        project_workflow: json_extract_string_field(&helper.stdout, "project_workflow"),
        project_import_module: json_extract_string_field(&helper.stdout, "project_import_module"),
        project_requirements_path: json_extract_string_field(
            &helper.stdout,
            "project_requirements_path",
        ),
        vm_session_id: json_extract_string_field(&helper.stdout, "vm_session_id"),
        exit_code: json_extract_i32_field(&helper.stdout, "exit_code"),
    })
}

fn render_guest_job_evidence_json(evidence: Option<&GuestJobEvidence>) -> String {
    let Some(evidence) = evidence else {
        return "null".to_string();
    };
    format!(
        "{{\"protocol\": {}, \"schema_version\": {}, \"agent_version\": {}, \"job_id\": {}, \"tool\": {}, \"command_class\": {}, \"fixture\": {}, \"status\": {}, \"verdict\": {}, \"reason_codes\": {}, \"command_exit_code\": {}, \"timed_out\": {}, \"canary_access_detected\": {}, \"network_attempt_detected\": {}, \"filesystem_write_detected\": {}, \"toolchain_available\": {}, \"stdout_captured\": {}, \"stderr_captured\": {}, \"raw_canary_values_captured\": {}, \"sync_back_enabled\": {}, \"host_package_execution_enabled\": {}, \"high_risk_package_execution_enabled\": {}, \"project_mode\": {}, \"project_workflow\": {}, \"project_import_module\": {}, \"project_requirements_path\": {}, \"vm_session_id\": {}, \"exit_code\": {}}}",
        json_option_string_redacted(evidence.protocol.as_deref()),
        json_option_string_redacted(evidence.schema_version.as_deref()),
        json_option_string_redacted(evidence.agent_version.as_deref()),
        json_option_string_redacted(evidence.job_id.as_deref()),
        json_option_string_redacted(evidence.tool.as_deref()),
        json_option_string_redacted(evidence.command_class.as_deref()),
        json_option_string_redacted(evidence.fixture.as_deref()),
        json_option_string_redacted(evidence.status.as_deref()),
        json_option_string_redacted(evidence.verdict.as_deref()),
        json_string_array(
            &evidence
                .reason_codes
                .iter()
                .map(|reason| redacted_scalar(reason))
                .collect::<Vec<_>>()
        ),
        json_option(evidence.command_exit_code),
        json_option(evidence.timed_out),
        json_option(evidence.canary_access_detected),
        json_option(evidence.network_attempt_detected),
        json_option(evidence.filesystem_write_detected),
        json_option(evidence.toolchain_available),
        json_option(evidence.stdout_captured),
        json_option(evidence.stderr_captured),
        json_option(evidence.raw_canary_values_captured),
        json_option(evidence.sync_back_enabled),
        json_option(evidence.host_package_execution_enabled),
        json_option(evidence.high_risk_package_execution_enabled),
        json_option(evidence.project_mode),
        json_option_string_redacted(evidence.project_workflow.as_deref()),
        json_option_string_redacted(evidence.project_import_module.as_deref()),
        json_option_string_redacted(evidence.project_requirements_path.as_deref()),
        json_option_string_redacted(evidence.vm_session_id.as_deref()),
        json_option(evidence.exit_code)
    )
}

fn json_extract_string_field(input: &str, field: &str) -> Option<String> {
    let mut value = json_field_value(input, field)?.trim_start();
    if !value.starts_with('"') {
        return None;
    }
    value = &value[1..];
    let mut output = String::new();
    let mut escaped = false;
    for character in value.chars() {
        if escaped {
            match character {
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                '/' => output.push('/'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                other => output.push(other),
            }
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => return Some(output),
            other => output.push(other),
        }
    }
    None
}

fn json_extract_string_array_field(input: &str, field: &str) -> Vec<String> {
    let Some(value) = json_field_value(input, field).map(str::trim_start) else {
        return Vec::new();
    };
    if !value.starts_with('[') {
        return Vec::new();
    }
    let mut values = Vec::new();
    let mut rest = &value[1..];
    loop {
        rest = rest.trim_start();
        if rest.starts_with(']') {
            return values;
        }
        if !rest.starts_with('"') {
            return Vec::new();
        }
        let Some(parsed) = json_parse_leading_string(rest) else {
            return Vec::new();
        };
        values.push(parsed.0);
        rest = parsed.1.trim_start();
        if rest.starts_with(',') {
            rest = &rest[1..];
            continue;
        }
        if rest.starts_with(']') {
            return values;
        }
        return Vec::new();
    }
}

fn json_parse_leading_string(input: &str) -> Option<(String, &str)> {
    let mut output = String::new();
    let mut escaped = false;
    let mut started = false;
    for (index, character) in input.char_indices() {
        if !started {
            if character != '"' {
                return None;
            }
            started = true;
            continue;
        }
        if escaped {
            match character {
                '"' => output.push('"'),
                '\\' => output.push('\\'),
                '/' => output.push('/'),
                'n' => output.push('\n'),
                'r' => output.push('\r'),
                't' => output.push('\t'),
                other => output.push(other),
            }
            escaped = false;
            continue;
        }
        match character {
            '\\' => escaped = true,
            '"' => return Some((output, &input[index + 1..])),
            other => output.push(other),
        }
    }
    None
}

fn json_extract_bool_field(input: &str, field: &str) -> Option<bool> {
    let value = json_field_value(input, field)?.trim_start();
    if value.starts_with("true") {
        Some(true)
    } else if value.starts_with("false") {
        Some(false)
    } else {
        None
    }
}

fn json_extract_i32_field(input: &str, field: &str) -> Option<i32> {
    let value = json_field_value(input, field)?.trim_start();
    let end = value
        .char_indices()
        .take_while(|(_, character)| character.is_ascii_digit() || *character == '-')
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0);
    if end == 0 {
        return None;
    }
    value[..end].parse().ok()
}

fn json_field_value<'a>(input: &'a str, field: &str) -> Option<&'a str> {
    let needle = format!("\"{field}\"");
    let index = input.find(&needle)?;
    let after_key = &input[index + needle.len()..];
    let colon = after_key.find(':')?;
    Some(&after_key[colon + 1..])
}

fn macos_vm_config(
    state_dir: Option<&str>,
    memory_mib: Option<u64>,
    disk_gib: Option<u64>,
) -> MacosVmConfig {
    let mut config = MacosVmConfig::new(
        state_dir
            .map(PathBuf::from)
            .unwrap_or_else(default_state_dir),
    );
    if let Some(memory_mib) = memory_mib {
        config.memory_mib = memory_mib;
    }
    if let Some(disk_gib) = disk_gib {
        config.disk_gib = disk_gib;
    }
    config
}

fn default_macos_vm_manifest_path(config: &MacosVmConfig) -> PathBuf {
    config.state_dir.join("bundle").join("image.manifest")
}

fn default_macos_vm_guest_provisioning_path(config: &MacosVmConfig) -> PathBuf {
    config
        .state_dir
        .join("bundle")
        .join("guest-provisioning.json")
}

fn load_macos_vm_manifest(
    manifest_path: Option<&str>,
    default_manifest_path: &Path,
) -> (Option<MacosVmImageManifest>, Option<String>, String) {
    let path = manifest_path
        .map(PathBuf::from)
        .unwrap_or_else(|| default_manifest_path.to_path_buf());
    let effective_path = path.display().to_string();
    match std::fs::read_to_string(&path) {
        Ok(contents) => match parse_image_manifest(&contents) {
            Ok(manifest) => (Some(manifest), None, effective_path),
            Err(error) => (None, Some(redacted_scalar(&error)), effective_path),
        },
        Err(error) => (
            None,
            Some(redacted_scalar(&error.to_string())),
            effective_path,
        ),
    }
}

const MACOS_VM_GUEST_PROVISIONING_SCHEMA_VERSION: &str = "whoathere.macos_vm.guest_provisioning.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosVmGuestProvisioningSummary {
    path: PathBuf,
    present: bool,
    load_reason: Option<String>,
    schema_version: Option<String>,
    offline_python_runtime_status: Option<String>,
    offline_python_wheels_status: Option<String>,
    wheel_package_status: Option<String>,
    offline_node_runtime_status: Option<String>,
    offline_node_runtime_npm_version: Option<String>,
    offline_uv_binary_status: Option<String>,
    offline_uv_binary_version: Option<String>,
    high_risk_package_execution_enabled: Option<bool>,
    host_home_mounted: Option<bool>,
    host_secrets_mounted: Option<bool>,
}

impl MacosVmGuestProvisioningSummary {
    fn missing(path: PathBuf, load_reason: String) -> Self {
        Self {
            path,
            present: false,
            load_reason: Some(load_reason),
            schema_version: None,
            offline_python_runtime_status: None,
            offline_python_wheels_status: None,
            wheel_package_status: None,
            offline_node_runtime_status: None,
            offline_node_runtime_npm_version: None,
            offline_uv_binary_status: None,
            offline_uv_binary_version: None,
            high_risk_package_execution_enabled: None,
            host_home_mounted: None,
            host_secrets_mounted: None,
        }
    }

    fn from_contents(path: PathBuf, contents: &str) -> Self {
        Self {
            path,
            present: true,
            load_reason: None,
            schema_version: json_extract_string_field(contents, "schema_version"),
            offline_python_runtime_status: json_extract_string_field(
                contents,
                "offline_python_runtime_status",
            ),
            offline_python_wheels_status: json_extract_string_field(
                contents,
                "offline_python_wheels_status",
            ),
            wheel_package_status: json_extract_string_field(contents, "wheel_package_status"),
            offline_node_runtime_status: json_extract_string_field(
                contents,
                "offline_node_runtime_status",
            ),
            offline_node_runtime_npm_version: json_extract_string_field(
                contents,
                "offline_node_runtime_npm_version",
            ),
            offline_uv_binary_status: json_extract_string_field(
                contents,
                "offline_uv_binary_status",
            ),
            offline_uv_binary_version: json_extract_string_field(
                contents,
                "offline_uv_binary_version",
            ),
            high_risk_package_execution_enabled: json_extract_bool_field(
                contents,
                "high_risk_package_execution_enabled",
            ),
            host_home_mounted: json_extract_bool_field(contents, "host_home_mounted"),
            host_secrets_mounted: json_extract_bool_field(contents, "host_secrets_mounted"),
        }
    }

    fn reason_codes(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.present {
            reasons.push("macos_vm_guest_provisioning_receipt_missing".to_string());
        }
        if self.schema_version.as_deref() != Some(MACOS_VM_GUEST_PROVISIONING_SCHEMA_VERSION) {
            reasons.push("macos_vm_guest_provisioning_schema_invalid".to_string());
        }
        if self.offline_python_runtime_status.as_deref() != Some("installed") {
            reasons.push("macos_vm_guest_python_runtime_not_provisioned".to_string());
        }
        if self.offline_python_wheels_status.as_deref() != Some("installed")
            || self.wheel_package_status.as_deref() != Some("installed")
        {
            reasons.push("macos_vm_guest_pip_tooling_not_provisioned".to_string());
        }
        if self.offline_node_runtime_status.as_deref() != Some("installed") {
            reasons.push("macos_vm_guest_node_runtime_not_provisioned".to_string());
        }
        if self.offline_uv_binary_status.as_deref() != Some("installed") {
            reasons.push("macos_vm_guest_uv_binary_not_provisioned".to_string());
        }
        if self.high_risk_package_execution_enabled != Some(false) {
            reasons
                .push("macos_vm_guest_high_risk_execution_state_not_proven_disabled".to_string());
        }
        if self.host_home_mounted != Some(false) {
            reasons.push("macos_vm_guest_host_home_mount_state_not_proven_disabled".to_string());
        }
        if self.host_secrets_mounted != Some(false) {
            reasons.push("macos_vm_guest_host_secret_mount_state_not_proven_disabled".to_string());
        }
        reasons.sort();
        reasons.dedup();
        reasons
    }

    fn render_text(&self) -> String {
        format!(
            "guest_provisioning_receipt_path={}\nguest_provisioning_receipt_present={}\nguest_provisioning_load_reason={}\nguest_provisioning_reason_codes={:?}\nguest_provisioning_schema_version={}\nguest_provisioning_python_runtime_status={}\nguest_provisioning_python_wheels_status={}\nguest_provisioning_wheel_package_status={}\nguest_provisioning_node_runtime_status={}\nguest_provisioning_npm_version={}\nguest_provisioning_uv_binary_status={}\nguest_provisioning_uv_version={}\nguest_provisioning_high_risk_package_execution_enabled={}\nguest_provisioning_host_home_mounted={}\nguest_provisioning_host_secrets_mounted={}",
            self.path.display(),
            self.present,
            self.load_reason
                .as_deref()
                .map(redacted_scalar)
                .unwrap_or_else(|| "none".to_string()),
            self.reason_codes(),
            self.schema_version
                .as_deref()
                .map(redacted_scalar)
                .unwrap_or_else(|| "missing".to_string()),
            option_string_text(self.offline_python_runtime_status.as_deref()),
            option_string_text(self.offline_python_wheels_status.as_deref()),
            option_string_text(self.wheel_package_status.as_deref()),
            option_string_text(self.offline_node_runtime_status.as_deref()),
            option_string_text(self.offline_node_runtime_npm_version.as_deref()),
            option_string_text(self.offline_uv_binary_status.as_deref()),
            option_string_text(self.offline_uv_binary_version.as_deref()),
            option_bool_text(self.high_risk_package_execution_enabled),
            option_bool_text(self.host_home_mounted),
            option_bool_text(self.host_secrets_mounted),
        )
    }
}

fn load_macos_vm_guest_provisioning(path: &Path) -> MacosVmGuestProvisioningSummary {
    match std::fs::read_to_string(path) {
        Ok(contents) => {
            MacosVmGuestProvisioningSummary::from_contents(path.to_path_buf(), &contents)
        }
        Err(error) => MacosVmGuestProvisioningSummary::missing(
            path.to_path_buf(),
            redacted_scalar(&error.to_string()),
        ),
    }
}

fn option_string_text(value: Option<&str>) -> String {
    value
        .map(redacted_scalar)
        .unwrap_or_else(|| "missing".to_string())
}

fn render_guest_provisioning_json(summary: &MacosVmGuestProvisioningSummary) -> String {
    format!(
        "{{\"receipt_path\": {}, \"receipt_present\": {}, \"load_reason\": {}, \"reason_codes\": {}, \"schema_version\": {}, \"python_runtime_status\": {}, \"python_wheels_status\": {}, \"wheel_package_status\": {}, \"node_runtime_status\": {}, \"npm_version\": {}, \"uv_binary_status\": {}, \"uv_version\": {}, \"high_risk_package_execution_enabled\": {}, \"host_home_mounted\": {}, \"host_secrets_mounted\": {}}}",
        json_string(&summary.path.display().to_string()),
        summary.present,
        json_option_string_redacted(summary.load_reason.as_deref()),
        json_string_array(&summary.reason_codes()),
        json_option_string_redacted(summary.schema_version.as_deref()),
        json_option_string_redacted(summary.offline_python_runtime_status.as_deref()),
        json_option_string_redacted(summary.offline_python_wheels_status.as_deref()),
        json_option_string_redacted(summary.wheel_package_status.as_deref()),
        json_option_string_redacted(summary.offline_node_runtime_status.as_deref()),
        json_option_string_redacted(summary.offline_node_runtime_npm_version.as_deref()),
        json_option_string_redacted(summary.offline_uv_binary_status.as_deref()),
        json_option_string_redacted(summary.offline_uv_binary_version.as_deref()),
        json_option(summary.high_risk_package_execution_enabled),
        json_option(summary.host_home_mounted),
        json_option(summary.host_secrets_mounted),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosVmHelperOutput {
    configured_path: Option<String>,
    available: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    reason_codes: Vec<String>,
}

impl MacosVmHelperOutput {
    fn render_text(&self) -> String {
        format!(
            "helper_path={}\nhelper_available={}\nhelper_exit_code={}\nhelper_reason_codes={:?}\nhelper_stdout_truncated={}\nhelper_stderr_truncated={}\nhelper_stdout={}\nhelper_stderr={}",
            self.configured_path
                .as_deref()
                .map(redacted_scalar)
                .unwrap_or_else(|| "unset".to_string()),
            self.available,
            self.exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "none".to_string()),
            self.reason_codes,
            self.stdout_truncated,
            self.stderr_truncated,
            single_line(&redacted_scalar(&self.stdout)),
            single_line(&redacted_scalar(&self.stderr))
        )
    }
}

fn run_macos_vm_helper(
    helper_path: Option<&str>,
    operation: &str,
    operation_args: &[String],
) -> MacosVmHelperOutput {
    let configured_path = configured_macos_vm_helper_path(helper_path);
    let Some(path) = configured_path.as_ref() else {
        return MacosVmHelperOutput {
            configured_path: None,
            available: false,
            exit_code: Some(ExitCode::Misuse.code()),
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            reason_codes: vec!["macos_vm_helper_path_not_configured".to_string()],
        };
    };
    if !path.is_absolute() {
        return MacosVmHelperOutput {
            configured_path: Some(path.display().to_string()),
            available: false,
            exit_code: Some(ExitCode::Misuse.code()),
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            reason_codes: vec!["macos_vm_helper_path_not_absolute".to_string()],
        };
    }
    let Ok(canonical_path) = path.canonicalize() else {
        return MacosVmHelperOutput {
            configured_path: Some(path.display().to_string()),
            available: false,
            exit_code: Some(ExitCode::Misuse.code()),
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            reason_codes: vec!["macos_vm_helper_not_found".to_string()],
        };
    };
    if !canonical_path.is_file() {
        return MacosVmHelperOutput {
            configured_path: Some(canonical_path.display().to_string()),
            available: false,
            exit_code: Some(ExitCode::Misuse.code()),
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            reason_codes: vec!["macos_vm_helper_not_file".to_string()],
        };
    }

    let mut args = vec![operation.to_string()];
    args.extend(operation_args.iter().cloned());
    let mut command = ProcessCommand::new(&canonical_path);
    command
        .args(&args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    match command.spawn() {
        Ok(mut child) => {
            let stdout_reader = spawn_limited_reader(child.stdout.take());
            let stderr_reader = spawn_limited_reader(child.stderr.take());
            let timeout = macos_vm_helper_timeout(operation);
            let deadline = Instant::now() + timeout;
            let mut timed_out = false;
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) if Instant::now() >= deadline => {
                        timed_out = true;
                        let _ = child.kill();
                        break child.wait().ok();
                    }
                    Ok(None) => sleep(Duration::from_millis(25)),
                    Err(_) => break None,
                }
            };
            let (stdout, stdout_truncated) = join_limited_reader(stdout_reader);
            let (stderr, stderr_truncated) = join_limited_reader(stderr_reader);
            let mut reason_codes = Vec::new();
            if timed_out {
                reason_codes.push("macos_vm_helper_timeout".to_string());
            } else if !status.map(|status| status.success()).unwrap_or(false) {
                reason_codes.push("macos_vm_helper_command_failed".to_string());
            }
            if stdout_truncated {
                reason_codes.push("macos_vm_helper_stdout_truncated".to_string());
            }
            if stderr_truncated {
                reason_codes.push("macos_vm_helper_stderr_truncated".to_string());
            }
            MacosVmHelperOutput {
                configured_path: Some(canonical_path.display().to_string()),
                available: true,
                exit_code: status
                    .and_then(|status| status.code())
                    .or(Some(ExitCode::InternalError.code())),
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
                reason_codes,
            }
        }
        Err(error) => MacosVmHelperOutput {
            configured_path: Some(canonical_path.display().to_string()),
            available: true,
            exit_code: Some(ExitCode::InternalError.code()),
            stdout: String::new(),
            stderr: error.to_string(),
            stdout_truncated: false,
            stderr_truncated: false,
            reason_codes: vec!["macos_vm_helper_spawn_failed".to_string()],
        },
    }
}

fn macos_vm_helper_timeout(operation: &str) -> Duration {
    match operation {
        "init" => Duration::from_secs(4 * 60 * 60),
        "start" | "suspend" | "reset" | "prune" => Duration::from_secs(60),
        "detonate" => Duration::from_secs(20 * 60),
        _ => Duration::from_secs(15),
    }
}

const MACOS_VM_HELPER_OUTPUT_LIMIT: usize = 64 * 1024;

fn spawn_limited_reader<T: Read + Send + 'static>(
    pipe: Option<T>,
) -> Option<std::thread::JoinHandle<(String, bool)>> {
    pipe.map(|pipe| std::thread::spawn(move || read_limited_utf8(Some(pipe))))
}

fn join_limited_reader(reader: Option<std::thread::JoinHandle<(String, bool)>>) -> (String, bool) {
    reader
        .and_then(|reader| reader.join().ok())
        .unwrap_or_else(|| (String::new(), false))
}

fn read_limited_utf8<T: Read>(pipe: Option<T>) -> (String, bool) {
    let Some(mut pipe) = pipe else {
        return (String::new(), false);
    };
    let mut output = Vec::new();
    let mut buffer = [0_u8; 4096];
    let mut truncated = false;
    loop {
        match pipe.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => {
                let remaining = MACOS_VM_HELPER_OUTPUT_LIMIT.saturating_sub(output.len());
                if remaining == 0 {
                    truncated = true;
                    break;
                }
                let keep = remaining.min(count);
                output.extend_from_slice(&buffer[..keep]);
                if keep < count {
                    truncated = true;
                    break;
                }
            }
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&output).into_owned(), truncated)
}

fn configured_macos_vm_helper_path(helper_path: Option<&str>) -> Option<PathBuf> {
    helper_path
        .filter(|value| !value.trim().is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("WHOATHERE_MACOS_VM_HELPER")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .map(PathBuf::from)
        })
}

fn single_line(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn render_vm_status_json(
    status: &whoathere_macos_vm::MacosVmStatus,
    manifest_path: &str,
    manifest_load_reason: Option<&str>,
    provisioning: &MacosVmGuestProvisioningSummary,
    helper: &MacosVmHelperOutput,
) -> String {
    format!(
        "{{\n  \"command\": \"whoathere vm status\",\n  \"schema_version\": {},\n  \"release_target\": {},\n  \"target_arch\": {},\n  \"vm_boundary\": {},\n  \"network_model\": {},\n  \"sync_policy\": {},\n  \"state_dir\": {},\n  \"host_os\": {},\n  \"host_arch\": {},\n  \"memory_mib\": {},\n  \"disk_gib\": {},\n  \"auto_suspend_minutes\": {},\n  \"state_dir_exists\": {},\n  \"manifest_path\": {},\n  \"manifest_present\": {},\n  \"manifest_valid\": {},\n  \"helper_ready_marker_present\": {},\n  \"image_ready_marker_present\": {},\n  \"ready\": {},\n  \"reason_codes\": [{}],\n  \"manifest_load_reason\": {},\n  \"guest_provisioning\": {},\n  \"helper_path\": {},\n  \"helper_available\": {},\n  \"helper_exit_code\": {},\n  \"helper_reason_codes\": {},\n  \"helper_stdout_truncated\": {},\n  \"helper_stderr_truncated\": {},\n  \"helper_stdout\": {},\n  \"helper_stderr\": {}\n}}",
        json_string(status.schema_version),
        json_string(status.release_target),
        json_string(status.target_arch),
        json_string(status.vm_boundary),
        json_string(status.network_model),
        json_string(status.sync_policy),
        json_string(&status.state_dir.display().to_string()),
        json_string(&status.host.os),
        json_string(&status.host.arch),
        status.memory_mib,
        status.disk_gib,
        status.auto_suspend_minutes,
        status.state_dir_exists,
        json_string(manifest_path),
        status.manifest_present,
        status.manifest_valid,
        status.helper_ready_marker_present,
        status.image_ready_marker_present,
        status.ready,
        status
            .reason_codes
            .iter()
            .map(|reason| json_string(reason))
            .collect::<Vec<_>>()
            .join(", "),
        manifest_load_reason
            .map(json_string)
            .unwrap_or_else(|| "null".to_string()),
        render_guest_provisioning_json(provisioning),
        helper
            .configured_path
            .as_deref()
            .map(json_string)
            .unwrap_or_else(|| "null".to_string()),
        helper.available,
        helper
            .exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "null".to_string()),
        json_string_array(&helper.reason_codes),
        helper.stdout_truncated,
        helper.stderr_truncated,
        json_string(&single_line(&redacted_scalar(&helper.stdout))),
        json_string(&single_line(&redacted_scalar(&helper.stderr)))
    )
}

#[derive(Debug, Clone)]
struct VmReleasePlanArgs<'a> {
    artifact_class: Option<&'a str>,
    ecosystem: Option<&'a str>,
    source: Option<&'a str>,
    filename: Option<&'a str>,
    lifecycle_script: bool,
    pep517_backend: bool,
    native_marker: bool,
    editable: bool,
    evidence: LocalEvidenceFlags,
    json: bool,
}

const MACOS_LOCAL_RELEASE_READINESS_SCHEMA_VERSION: &str =
    "whoathere.macos_local_release_readiness.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
struct MacosLocalReleaseReadiness {
    schema_version: &'static str,
    release_ready: bool,
    release_stage: &'static str,
    implemented_workflows: Vec<String>,
    fail_closed_workflows: Vec<String>,
    manual_review_classes: Vec<String>,
    blocking_reason_codes: Vec<String>,
    next_actions: Vec<String>,
}

fn macos_local_release_readiness(
    status: &whoathere_macos_vm::MacosVmStatus,
    provisioning: &MacosVmGuestProvisioningSummary,
    helper: &MacosVmHelperOutput,
    scanner_available_count: usize,
    scanner_required_count: usize,
) -> MacosLocalReleaseReadiness {
    let mut blocking_reason_codes = status.reason_codes.clone();
    blocking_reason_codes.extend(provisioning.reason_codes());
    blocking_reason_codes.extend(helper.reason_codes.iter().cloned());

    if !helper.available {
        blocking_reason_codes.push("macos_vm_helper_unavailable".to_string());
    }
    if helper.available && helper.exit_code != Some(0) {
        blocking_reason_codes.push("macos_vm_helper_status_not_clean".to_string());
    }
    if scanner_available_count < scanner_required_count {
        blocking_reason_codes.push("release_required_scanners_missing".to_string());
    }

    blocking_reason_codes.extend(string_vec(&[
        "release_npm_vm_detonation_not_verified",
        "release_uv_vm_detonation_not_verified",
        "release_public_package_resolution_policy_not_implemented",
        "release_packaging_and_onboarding_not_complete",
        "release_signature_notarization_not_complete",
    ]));
    blocking_reason_codes.sort();
    blocking_reason_codes.dedup();

    MacosLocalReleaseReadiness {
        schema_version: MACOS_LOCAL_RELEASE_READINESS_SCHEMA_VERSION,
        release_ready: blocking_reason_codes.is_empty(),
        release_stage: "pre_release_checkpoint",
        implemented_workflows: string_vec(&[
            "pip.local_project.install",
            "pip.local_requirements.local_only",
            "npm.local_project.no_external_dependency_plan",
            "host.sync_back.disabled_preview",
            "vm.fixture_detonation",
            "vm.release_plan.admission_model",
        ]),
        fail_closed_workflows: string_vec(&[
            "npm.install.project.live_until_guest_toolchain_proven",
            "npm.ci.project.live_until_guest_toolchain_proven",
            "npm.public_dependency_resolution",
            "npm.exec_or_npx",
            "uv.sync",
            "uv.pip_install",
            "pip.public_index_resolution",
            "host.sync_back",
        ]),
        manual_review_classes: string_vec(&[
            "native_extensions",
            "binary_wheels",
            "direct_urls",
            "vcs_dependencies",
            "editable_installs",
            "unsupported_unknown_artifacts",
        ]),
        blocking_reason_codes,
        next_actions: string_vec(&[
            "validate default VM image lifecycle without hidden sudo requirements",
            "reprovision the stopped VM with explicit Node/npm and uv tool sources until receipt and health prove toolchains",
            "make npm detonation either work in VM or remain explicitly unclaimed",
            "keep sync-back disabled for the preview unless a separately tested whitelist is implemented",
            "complete signed packaging and notarization docs for Apple Silicon users",
            "run whoathere vm red-team-gate on every release candidate",
        ]),
    }
}

fn string_vec(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_string()).collect()
}

fn render_doctor(json: bool, state_dir: Option<&str>, helper_path: Option<&str>) -> String {
    let backend = UnsupportedBackend;
    let plan = backend.plan(ExecutionMode::Protected);
    let config = macos_vm_config(state_dir, None, None);
    let default_manifest_path = default_macos_vm_manifest_path(&config);
    let provisioning_path = default_macos_vm_guest_provisioning_path(&config);
    let (manifest, manifest_load_reason, effective_manifest_path) =
        load_macos_vm_manifest(None, &default_manifest_path);
    let provisioning = load_macos_vm_guest_provisioning(&provisioning_path);
    let status = status_from_config(&config, HostPlatform::current(), manifest.as_ref());
    let helper = run_macos_vm_helper(
        helper_path,
        "status",
        &[
            "--state-dir".to_string(),
            config.state_dir.display().to_string(),
            "--json".to_string(),
        ],
    );
    let scanners = scanner_adapters();
    let scanner_available = scanners
        .iter()
        .filter(|adapter| command_on_path(adapter.name))
        .count();
    let scanner_required = scanners
        .iter()
        .filter(|adapter| adapter.required_for_auto_sync)
        .count();
    let readiness = macos_local_release_readiness(
        &status,
        &provisioning,
        &helper,
        scanner_available,
        scanner_required,
    );
    if json {
        let scanner_json = scanners
            .iter()
            .map(|adapter| {
                format!(
                    "{{\"name\": {}, \"available\": {}, \"required_for_auto_sync\": {}, \"evidence_role\": {}}}",
                    json_string(adapter.name),
                    command_on_path(adapter.name),
                    adapter.required_for_auto_sync,
                    json_string(adapter.evidence_role)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "{{\n  \"command\": \"whoathere doctor\",\n  \"status\": \"ok\",\n  \"release_target\": {},\n  \"release_claim\": {},\n  \"sandbox_label\": {},\n  \"high_risk_allowed\": {},\n  \"state_dir\": {},\n  \"vm_manifest_path\": {},\n  \"vm_manifest_load_reason\": {},\n  \"guest_provisioning\": {},\n  \"release_readiness_schema\": {},\n  \"release_stage\": {},\n  \"release_ready\": {},\n  \"release_blocking_reason_codes\": {},\n  \"implemented_workflows\": {},\n  \"fail_closed_workflows\": {},\n  \"manual_review_classes\": {},\n  \"next_actions\": {},\n  \"vm_ready\": {},\n  \"vm_reason_codes\": {},\n  \"helper_path\": {},\n  \"helper_available\": {},\n  \"helper_exit_code\": {},\n  \"helper_reason_codes\": {},\n  \"helper_stdout_truncated\": {},\n  \"helper_stderr_truncated\": {},\n  \"helper_stdout\": {},\n  \"helper_stderr\": {},\n  \"scanner_available_count\": {},\n  \"scanner_required_count\": {},\n  \"scanners\": [{}]\n}}",
            json_string(RELEASE_TARGET),
            json_string(RELEASE_CLAIM),
            json_string(plan.label),
            plan.high_risk_allowed,
            json_string(&config.state_dir.display().to_string()),
            json_string(&effective_manifest_path),
            manifest_load_reason
                .as_deref()
                .map(json_string)
                .unwrap_or_else(|| "null".to_string()),
            render_guest_provisioning_json(&provisioning),
            json_string(readiness.schema_version),
            json_string(readiness.release_stage),
            readiness.release_ready,
            json_string_array(&readiness.blocking_reason_codes),
            json_string_array(&readiness.implemented_workflows),
            json_string_array(&readiness.fail_closed_workflows),
            json_string_array(&readiness.manual_review_classes),
            json_string_array(&readiness.next_actions),
            status.ready,
            json_string_array(&status.reason_codes),
            helper
                .configured_path
                .as_deref()
                .map(json_string)
                .unwrap_or_else(|| "null".to_string()),
            helper.available,
            helper
                .exit_code
                .map(|code| code.to_string())
                .unwrap_or_else(|| "null".to_string()),
            json_string_array(&helper.reason_codes),
            helper.stdout_truncated,
            helper.stderr_truncated,
            json_string(&single_line(&redacted_scalar(&helper.stdout))),
            json_string(&single_line(&redacted_scalar(&helper.stderr))),
            scanner_available,
            scanner_required,
            scanner_json
        );
    }
    let scanner_lines = scanners
        .iter()
        .map(|adapter| {
            format!(
                "scanner_adapter={} available={} required_for_auto_sync={} evidence_role=\"{}\"",
                adapter.name,
                command_on_path(adapter.name),
                adapter.required_for_auto_sync,
                adapter.evidence_role
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "whoathere doctor\nstatus=ok\nrelease_target={}\nrelease_claim={}\nsandbox_label={}\nhigh_risk_allowed={}\nstate_dir={}\nvm_manifest_path={}\nvm_manifest_load_reason={}\n{}\nrelease_readiness_schema={}\nrelease_stage={}\nrelease_ready={}\nrelease_blocking_reason_codes={:?}\nimplemented_workflows={:?}\nfail_closed_workflows={:?}\nmanual_review_classes={:?}\nnext_actions={:?}\nvm_ready={}\nvm_reason_codes={:?}\n{}\nscanner_available_count={}\nscanner_required_count={}\n{}",
        RELEASE_TARGET,
        RELEASE_CLAIM,
        plan.label,
        plan.high_risk_allowed,
        config.state_dir.display(),
        effective_manifest_path,
        manifest_load_reason.unwrap_or_else(|| "none".to_string()),
        provisioning.render_text(),
        readiness.schema_version,
        readiness.release_stage,
        readiness.release_ready,
        readiness.blocking_reason_codes,
        readiness.implemented_workflows,
        readiness.fail_closed_workflows,
        readiness.manual_review_classes,
        readiness.next_actions,
        status.ready,
        status.reason_codes,
        helper.render_text(),
        scanner_available,
        scanner_required,
        scanner_lines
    )
}

fn render_vm_release_plan(args: VmReleasePlanArgs<'_>) -> String {
    let package_class = match package_class_from_release_args(&args) {
        Ok(package_class) => package_class,
        Err(reason) => {
            if args.json {
                return format!(
                    "{{\n  \"command\": \"whoathere vm release-plan\",\n  \"status\": \"error\",\n  \"reason_code\": {},\n  \"exit_code\": {}\n}}",
                    json_string(reason),
                    ExitCode::Misuse.code()
                );
            }
            return format!(
                "whoathere vm release-plan\nstatus=error\nreason_code={reason}\nexit_code={}",
                ExitCode::Misuse.code()
            );
        }
    };
    let decision = decide_local_sync(package_class, &args.evidence);
    let exit_code = local_admission_exit_code(decision.verdict);
    if args.json {
        return format!(
            "{{\n  \"command\": \"whoathere vm release-plan\",\n  \"release_target\": {},\n  \"release_claim\": {},\n  \"vm_boundary\": {},\n  \"network_model\": {},\n  \"sync_policy\": {},\n  \"authorization\": false,\n  \"sync_authorized\": false,\n  \"authorization_reason\": \"release_plan_is_not_runtime_verdict\",\n  \"package_class\": {},\n  \"verdict\": {},\n  \"auto_sync_eligible\": {},\n  \"sync_paths\": {},\n  \"required_evidence\": {},\n  \"reason_codes\": {},\n  \"evidence\": {{\"vm_ready\": {}, \"static_clean\": {}, \"dynamic_clean\": {}, \"egress_clean\": {}, \"no_canary_access\": {}, \"scanner_clean\": {}, \"diff_clean_or_baseline_absent\": {}, \"freshness_allowed\": {}}},\n  \"exit_code\": {exit_code}\n}}",
            json_string(RELEASE_TARGET),
            json_string(RELEASE_CLAIM),
            json_string(VM_BOUNDARY),
            json_string(NETWORK_MODEL),
            json_string(SYNC_POLICY),
            json_string(package_class.as_str()),
            json_string(decision.verdict.as_str()),
            decision.auto_sync_eligible,
            json_string_array(
                &decision
                    .sync_paths
                    .iter()
                    .map(|path| (*path).to_string())
                    .collect::<Vec<_>>()
            ),
            json_string_array(
                &decision
                    .required_evidence
                    .iter()
                    .map(|evidence| (*evidence).to_string())
                    .collect::<Vec<_>>()
            ),
            json_string_array(&decision.reason_codes),
            args.evidence.vm_ready,
            args.evidence.static_clean,
            args.evidence.dynamic_clean,
            args.evidence.egress_clean,
            args.evidence.no_canary_access,
            args.evidence.scanner_clean,
            args.evidence.diff_clean_or_baseline_absent,
            args.evidence.freshness_allowed,
        );
    }
    format!(
        "whoathere vm release-plan\nrelease_target={}\nrelease_claim={}\nvm_boundary={}\nnetwork_model={}\nsync_policy={}\nauthorization=false\nsync_authorized=false\nauthorization_reason=release_plan_is_not_runtime_verdict\npackage_class={}\nverdict={}\nauto_sync_eligible={}\nsync_paths={:?}\nrequired_evidence={:?}\nreason_codes={:?}\nevidence_vm_ready={}\nevidence_static_clean={}\nevidence_dynamic_clean={}\nevidence_egress_clean={}\nevidence_no_canary_access={}\nevidence_scanner_clean={}\nevidence_diff_clean_or_baseline_absent={}\nevidence_freshness_allowed={}\nexit_code={exit_code}",
        RELEASE_TARGET,
        RELEASE_CLAIM,
        VM_BOUNDARY,
        NETWORK_MODEL,
        SYNC_POLICY,
        package_class.as_str(),
        decision.verdict.as_str(),
        decision.auto_sync_eligible,
        decision.sync_paths,
        decision.required_evidence,
        decision.reason_codes,
        args.evidence.vm_ready,
        args.evidence.static_clean,
        args.evidence.dynamic_clean,
        args.evidence.egress_clean,
        args.evidence.no_canary_access,
        args.evidence.scanner_clean,
        args.evidence.diff_clean_or_baseline_absent,
        args.evidence.freshness_allowed,
    )
}

fn render_vm_canaries(json: bool) -> String {
    let canaries = default_canaries();
    if json {
        let canary_json = canaries
            .iter()
            .map(|canary| {
                format!(
                    "{{\"category\": {}, \"env_name\": {}, \"path_hint\": {}}}",
                    json_string(canary.category),
                    json_string(canary.env_name),
                    json_string(canary.path_hint)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "{{\n  \"command\": \"whoathere vm canaries\",\n  \"release_target\": {},\n  \"canaries\": [{}]\n}}",
            json_string(RELEASE_TARGET),
            canary_json
        );
    }
    let rows = canaries
        .iter()
        .map(|canary| {
            format!(
                "canary category={} env_name={} path_hint={}",
                canary.category,
                canary.env_name,
                redacted_scalar(canary.path_hint)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "whoathere vm canaries\nrelease_target={}\nhost_secret_mounting=false\n{}",
        RELEASE_TARGET, rows
    )
}

fn render_vm_sync_policy(json: bool) -> String {
    let rules = default_sync_allowlist();
    let evidence = required_local_evidence();
    let scanners = scanner_adapters();
    if json {
        let rule_json = rules
            .iter()
            .map(|rule| {
                format!(
                    "{{\"path_pattern\": {}, \"reason\": {}}}",
                    json_string(rule.path_pattern),
                    json_string(rule.reason)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let scanner_json = scanners
            .iter()
            .map(|adapter| {
                format!(
                    "{{\"name\": {}, \"required_for_auto_sync\": {}, \"evidence_role\": {}}}",
                    json_string(adapter.name),
                    adapter.required_for_auto_sync,
                    json_string(adapter.evidence_role)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "{{\n  \"command\": \"whoathere vm sync-policy\",\n  \"release_target\": {},\n  \"sync_policy\": {},\n  \"sync_back_enabled\": false,\n  \"policy_scope\": \"future_allowlist_not_release_authorization\",\n  \"auto_sync_classes\": [\"npm.registry_tarball.v1\", \"pypi.pure_wheel.v1\"],\n  \"deny_default_classes\": [\"direct_vcs_editable.v1\", \"unsupported_unknown.v1\"],\n  \"manual_review_classes\": [\"pypi.sdist_pep517.v1\", \"pypi.binary_wheel.v1\", \"native_extension.v1\"],\n  \"sync_allowlist\": [{}],\n  \"required_evidence\": {},\n  \"scanner_adapters\": [{}]\n}}",
            json_string(RELEASE_TARGET),
            json_string(SYNC_POLICY),
            rule_json,
            json_string_array(&evidence.iter().map(|item| (*item).to_string()).collect::<Vec<_>>()),
            scanner_json
        );
    }
    let rule_rows = rules
        .iter()
        .map(|rule| {
            format!(
                "sync_allow path_pattern={} reason=\"{}\"",
                rule.path_pattern, rule.reason
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let scanner_rows = scanners
        .iter()
        .map(|adapter| {
            format!(
                "scanner_adapter={} required_for_auto_sync={} evidence_role=\"{}\"",
                adapter.name, adapter.required_for_auto_sync, adapter.evidence_role
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "whoathere vm sync-policy\nrelease_target={}\nsync_policy={}\nsync_back_enabled=false\npolicy_scope=future_allowlist_not_release_authorization\nauto_sync_classes=[\"npm.registry_tarball.v1\", \"pypi.pure_wheel.v1\"]\nmanual_review_classes=[\"pypi.sdist_pep517.v1\", \"pypi.binary_wheel.v1\", \"native_extension.v1\"]\ndeny_default_classes=[\"direct_vcs_editable.v1\", \"unsupported_unknown.v1\"]\nrequired_evidence={:?}\n{}\n{}",
        RELEASE_TARGET, SYNC_POLICY, evidence, rule_rows, scanner_rows
    )
}

#[derive(Debug, Clone)]
struct RedTeamGateCase {
    name: &'static str,
    category: &'static str,
    comparator: &'static str,
    path: &'static str,
    body: String,
    expected_status: u16,
    required_markers: Vec<&'static str>,
    forbidden_markers: Vec<&'static str>,
}

#[derive(Debug, Clone)]
struct RedTeamGateCaseResult {
    name: &'static str,
    category: &'static str,
    comparator: &'static str,
    expected_status: u16,
    actual_status: u16,
    passed: bool,
    reason_codes: Vec<String>,
}

fn render_vm_red_team_gate(json: bool) -> String {
    let cases = red_team_gate_cases();
    let results = cases.iter().map(run_red_team_gate_case).collect::<Vec<_>>();
    let passed = results.iter().all(|result| result.passed);
    let exit_code = if passed {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };
    let unavailable_scanners = scanner_adapters()
        .into_iter()
        .filter(|adapter| !command_on_path(adapter.name))
        .map(|adapter| adapter.name.to_string())
        .collect::<Vec<_>>();

    if json {
        let case_json = results
            .iter()
            .map(|result| {
                format!(
                    "{{\"name\": {}, \"category\": {}, \"comparator\": {}, \"expected_status\": {}, \"actual_status\": {}, \"passed\": {}, \"reason_codes\": {}}}",
                    json_string(result.name),
                    json_string(result.category),
                    json_string(result.comparator),
                    result.expected_status,
                    result.actual_status,
                    result.passed,
                    json_string_array(&result.reason_codes)
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return format!(
            "{{\n  \"command\": \"whoathere vm red-team-gate\",\n  \"release_target\": {},\n  \"release_claim\": {},\n  \"gate_scope\": \"fixture_safe_local_no_arbitrary_execution\",\n  \"public_network_used\": false,\n  \"external_scanners_required\": false,\n  \"external_scanners_unavailable\": {},\n  \"passed\": {},\n  \"case_count\": {},\n  \"cases\": [{}],\n  \"exit_code\": {}\n}}",
            json_string(RELEASE_TARGET),
            json_string(RELEASE_CLAIM),
            json_string_array(&unavailable_scanners),
            passed,
            results.len(),
            case_json,
            exit_code
        );
    }

    let case_lines = results
        .iter()
        .map(|result| {
            format!(
                "case name={} category={} comparator={} expected_status={} actual_status={} passed={} reason_codes={:?}",
                result.name,
                result.category,
                result.comparator,
                result.expected_status,
                result.actual_status,
                result.passed,
                result.reason_codes
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "whoathere vm red-team-gate\nrelease_target={}\nrelease_claim={}\ngate_scope=fixture_safe_local_no_arbitrary_execution\npublic_network_used=false\nexternal_scanners_required=false\nexternal_scanners_unavailable={:?}\npassed={}\ncase_count={}\n{}\nexit_code={}",
        RELEASE_TARGET,
        RELEASE_CLAIM,
        unavailable_scanners,
        passed,
        results.len(),
        case_lines,
        exit_code
    )
}

fn red_team_gate_cases() -> Vec<RedTeamGateCase> {
    const COMMON_FORBIDDEN: &[&str] = &[
        "WHOATHERE_CANARY_TOKEN",
        "proof-nonce-",
        "/Users/",
        "raw_material_captured\":true",
        "arbitrary_execution_attempted\":true",
        "network_attempted\":true",
    ];
    vec![
        RedTeamGateCase {
            name: "static_clean_npm_manifest",
            category: "static_manifest",
            comparator: "guarddog_lifecycle_baseline",
            path: "/v1/static-manifest-job-simulations",
            body: "manifest=clean_npm".to_string(),
            expected_status: 200,
            required_markers: vec![
                "\"status\":\"ok\"",
                "\"evidence_binding_ready\":true",
                "\"execution_enabled\":false",
                "\"detonation_attempted\":false",
                "\"network_attempted\":false",
            ],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        RedTeamGateCase {
            name: "static_npm_postinstall_block",
            category: "static_manifest",
            comparator: "guarddog_lifecycle_script",
            path: "/v1/static-manifest-job-simulations",
            body: "manifest=malicious_npm".to_string(),
            expected_status: 409,
            required_markers: vec![
                "\"status\":\"fail_closed\"",
                "\"evidence_binding_ready\":false",
                "npm_lifecycle_postinstall",
            ],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        RedTeamGateCase {
            name: "static_pypi_pep517_suspicion",
            category: "static_manifest",
            comparator: "guarddog_pypi_build_backend",
            path: "/v1/static-manifest-job-simulations",
            body: "manifest=pyproject".to_string(),
            expected_status: 200,
            required_markers: vec![
                "\"status\":\"ok\"",
                "\"evidence_binding_ready\":true",
                "pypi_pep517_build_backend",
                "\"execution_enabled\":false",
            ],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        RedTeamGateCase {
            name: "static_raw_log_rejected",
            category: "gate_integrity",
            comparator: "sanitization_contract",
            path: "/v1/static-manifest-job-simulations",
            body: "manifest=clean_npm&raw_log_captured=true".to_string(),
            expected_status: 409,
            required_markers: vec!["\"status\":\"fail_closed\"", "job_log_raw_log_captured"],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        RedTeamGateCase {
            name: "static_tampered_log_rejected",
            category: "gate_integrity",
            comparator: "evidence_digest_binding",
            path: "/v1/static-manifest-job-simulations",
            body: "manifest=clean_npm&tamper_log_digest=true".to_string(),
            expected_status: 409,
            required_markers: vec!["\"status\":\"fail_closed\"", "job_log_digest_mismatch"],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        RedTeamGateCase {
            name: "dynamic_clean_npm_lifecycle",
            category: "dynamic_behavior",
            comparator: "openssf_package_analysis_baseline",
            path: "/v1/dynamic-behavior-job-simulations",
            body: "fixture=clean_npm_lifecycle".to_string(),
            expected_status: 200,
            required_markers: vec![
                "\"status\":\"ok\"",
                "\"dynamic_behavior_binding_ready\":true",
                "\"execution_enabled\":false",
                "\"arbitrary_execution_attempted\":false",
                "\"fixture_mode\":true",
            ],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        dynamic_attack_case(
            "dynamic_npm_postinstall_exfil",
            "npm_postinstall_canary_exfil",
            "guarddog_lifecycle_and_exfil",
            "dynamic_behavior_canary_credential_access_observed",
        ),
        dynamic_attack_case(
            "dynamic_pypi_pep517_backend_abuse",
            "pypi_pep517_canary",
            "guarddog_pypi_build_backend",
            "dynamic_behavior_canary_credential_access_observed",
        ),
        dynamic_attack_case(
            "dynamic_python_import_time_payload",
            "pypi_import_time_canary",
            "openssf_package_analysis_import_probe",
            "dynamic_behavior_environment_access_observed",
        ),
        dynamic_attack_case(
            "dynamic_dns_tunneling",
            "dns_tunneling_canary",
            "openssf_package_analysis_network",
            "dynamic_behavior_dns_tunnel_attempt_observed",
        ),
        dynamic_attack_case(
            "dynamic_https_exfiltration",
            "https_exfil_canary",
            "openssf_package_analysis_network",
            "dynamic_behavior_https_exfil_attempt_observed",
        ),
        dynamic_attack_case(
            "dynamic_delayed_ci_activation",
            "delayed_ci_canary",
            "recent_ci_targeted_campaigns",
            "dynamic_behavior_delayed_execution_observed",
        ),
        dynamic_attack_case(
            "dynamic_native_extension",
            "native_extension_canary",
            "binary_native_manual_review",
            "dynamic_behavior_native_extension_observed",
        ),
        dynamic_attack_case(
            "dynamic_platform_specific_payload",
            "platform_specific_canary",
            "platform_split_payloads",
            "dynamic_behavior_platform_specific_observed",
        ),
        dynamic_attack_case(
            "dynamic_direct_git_tarball",
            "direct_git_tarball_canary",
            "direct_source_policy",
            "dynamic_behavior_direct_source_observed",
        ),
        RedTeamGateCase {
            name: "dynamic_wrong_vault_rejected",
            category: "gate_integrity",
            comparator: "evidence_context_binding",
            path: "/v1/dynamic-behavior-job-simulations",
            body: "fixture=clean_npm_lifecycle&wrong_context=vault".to_string(),
            expected_status: 409,
            required_markers: vec![
                "\"status\":\"fail_closed\"",
                "dynamic_behavior_result_vault_host_mismatch",
            ],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        RedTeamGateCase {
            name: "dynamic_stale_result_rejected",
            category: "gate_integrity",
            comparator: "evidence_freshness_binding",
            path: "/v1/dynamic-behavior-job-simulations",
            body: "fixture=clean_npm_lifecycle&stale=true".to_string(),
            expected_status: 409,
            required_markers: vec![
                "\"status\":\"fail_closed\"",
                "dynamic_behavior_result_stale_or_not_yet_valid",
            ],
            forbidden_markers: COMMON_FORBIDDEN.to_vec(),
        },
        RedTeamGateCase {
            name: "dynamic_raw_material_rejected",
            category: "gate_integrity",
            comparator: "sanitization_contract",
            path: "/v1/dynamic-behavior-job-simulations",
            body: "fixture=clean_npm_lifecycle&raw_material=true".to_string(),
            expected_status: 409,
            required_markers: vec![
                "\"status\":\"fail_closed\"",
                "dynamic_behavior_raw_or_local_material_captured",
            ],
            forbidden_markers: vec![
                "WHOATHERE_CANARY_TOKEN",
                "proof-nonce-",
                "/Users/",
                "arbitrary_execution_attempted\":true",
                "network_attempted\":true",
            ],
        },
    ]
}

fn dynamic_attack_case(
    name: &'static str,
    fixture: &'static str,
    comparator: &'static str,
    required_reason: &'static str,
) -> RedTeamGateCase {
    RedTeamGateCase {
        name,
        category: "dynamic_behavior",
        comparator,
        path: "/v1/dynamic-behavior-job-simulations",
        body: format!("fixture={fixture}"),
        expected_status: 409,
        required_markers: vec![
            "\"status\":\"fail_closed\"",
            "\"dynamic_behavior_binding_ready\":false",
            "dynamic_behavior_high_risk_signal_detected",
            required_reason,
        ],
        forbidden_markers: vec![
            "WHOATHERE_CANARY_TOKEN",
            "proof-nonce-",
            "/Users/",
            "raw_material_captured\":true",
            "arbitrary_execution_attempted\":true",
            "network_attempted\":true",
        ],
    }
}

fn run_red_team_gate_case(case: &RedTeamGateCase) -> RedTeamGateCaseResult {
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{}",
        case.path,
        case.body.len(),
        case.body
    );
    let response = handle_http_request(&request);
    let mut reason_codes = Vec::new();
    if response.status_code != case.expected_status {
        reason_codes.push("red_team_gate_status_mismatch".to_string());
    }
    for marker in &case.required_markers {
        if !response.body.contains(marker) {
            reason_codes.push(format!("red_team_gate_required_marker_missing:{marker}"));
        }
    }
    for marker in &case.forbidden_markers {
        if response.body.contains(marker) {
            reason_codes.push(format!("red_team_gate_forbidden_marker_present:{marker}"));
        }
    }
    reason_codes.sort();
    reason_codes.dedup();

    RedTeamGateCaseResult {
        name: case.name,
        category: case.category,
        comparator: case.comparator,
        expected_status: case.expected_status,
        actual_status: response.status_code,
        passed: reason_codes.is_empty(),
        reason_codes,
    }
}

fn package_class_from_release_args(
    args: &VmReleasePlanArgs<'_>,
) -> Result<PackageClass, &'static str> {
    if let Some(artifact_class) = args.artifact_class {
        return PackageClass::parse(artifact_class).ok_or("macos_vm_package_class_invalid");
    }
    let Some(ecosystem) = args.ecosystem else {
        return Err("macos_vm_release_plan_class_or_ecosystem_required");
    };
    let Some(source) = args.source else {
        return Err("macos_vm_release_plan_class_or_source_required");
    };
    let Some(filename) = args.filename else {
        return Err("macos_vm_release_plan_class_or_filename_required");
    };
    let mut signals = ArtifactSignals::new(ecosystem, source, filename);
    signals.has_lifecycle_script = args.lifecycle_script;
    signals.has_pep517_backend = args.pep517_backend;
    signals.has_native_marker = args.native_marker;
    signals.editable = args.editable;
    Ok(classify_artifact(&signals))
}

fn local_admission_exit_code(verdict: whoathere_macos_vm::LocalAdmissionVerdict) -> i32 {
    match verdict {
        whoathere_macos_vm::LocalAdmissionVerdict::AutoSync => ExitCode::Allow.code(),
        whoathere_macos_vm::LocalAdmissionVerdict::ManualReview => ExitCode::ManualReview.code(),
        whoathere_macos_vm::LocalAdmissionVerdict::Deny => ExitCode::Deny.code(),
    }
}

fn command_on_path(command: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&paths).any(|path| path.join(command).is_file())
}

fn nonempty_env_default(env_lookup: &impl Fn(&str) -> Option<String>, key: &str) -> Option<String> {
    env_lookup(key).filter(|value| !value.trim().is_empty())
}

fn parse_dest(args: &[String]) -> Option<String> {
    parse_flag_value(args, "--dest")
}

fn parse_internal_prefix(args: &[String]) -> Option<String> {
    parse_flag_value(args, "--internal-prefix")
}

fn parse_policy_path(args: &[String]) -> Option<String> {
    parse_flag_value(args, "--policy")
}

fn parse_vault_origin(args: &[String]) -> Option<String> {
    parse_flag_value(args, "--vault-origin")
}

fn parse_helper_path(args: &[String]) -> Option<String> {
    parse_flag_value(args, "--helper")
}

fn parse_provider_scope(args: &[String]) -> ProviderScope {
    match parse_flag_value(args, "--scope").as_deref() {
        None | Some("all") => ProviderScope::All,
        Some("current") => ProviderScope::Current,
        Some("linux") => ProviderScope::Linux,
        Some("macos") => ProviderScope::Macos,
        Some(_) => ProviderScope::Invalid,
    }
}

fn parse_provider_challenge_scope(args: &[String]) -> ProviderScope {
    match parse_flag_value(args, "--scope").as_deref() {
        None | Some("current") => ProviderScope::Current,
        Some("linux") => ProviderScope::Linux,
        Some("macos") => ProviderScope::Macos,
        Some(_) => ProviderScope::Invalid,
    }
}

fn parse_flag_value(args: &[String], flag: &str) -> Option<String> {
    for (index, arg) in args.iter().enumerate() {
        if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(value.to_string());
        }
        if arg == flag {
            return args.get(index + 1).cloned();
        }
    }
    None
}

fn parse_usize_flag(args: &[String], flag: &str) -> Option<usize> {
    parse_flag_value(args, flag)?.parse::<usize>().ok()
}

fn parse_u64_flag(args: &[String], flag: &str) -> Option<u64> {
    parse_flag_value(args, flag)?.parse::<u64>().ok()
}

fn parse_local_evidence_flags(args: &[String]) -> LocalEvidenceFlags {
    LocalEvidenceFlags {
        vm_ready: args.iter().any(|arg| arg == "--vm-ready"),
        static_clean: args.iter().any(|arg| arg == "--static-clean"),
        dynamic_clean: args.iter().any(|arg| arg == "--dynamic-clean"),
        egress_clean: args.iter().any(|arg| arg == "--egress-clean"),
        no_canary_access: args.iter().any(|arg| arg == "--no-canary-access"),
        scanner_clean: args.iter().any(|arg| arg == "--scanner-clean"),
        diff_clean_or_baseline_absent: args.iter().any(|arg| arg == "--diff-clean"),
        freshness_allowed: args.iter().any(|arg| arg == "--freshness-allowed"),
    }
}

fn load_policy_document(path: &str) -> Result<PolicyDocument, String> {
    let contents = std::fs::read_to_string(path).map_err(|error| format!("read_failed:{error}"))?;
    parse_policy_document(&contents).map_err(|error| format!("invalid:{error:?}"))
}

fn render_policy_check(path: &str) -> String {
    match load_policy_document(path) {
        Ok(document) => format!(
            "whoathere policy check\nstatus=ok\npath={path}\nschema_version={}\npolicy_version={}\nfail_closed={}\nnamespace_rules={}",
            document.schema_version,
            document.policy_version,
            document.fail_closed,
            document.namespace_rules.len()
        ),
        Err(error) => format!(
            "whoathere policy check\nstatus=error\nreason_code=policy_invalid\npath={path}\nerror={error}"
        ),
    }
}

fn render_policy_check_source(
    package: &str,
    source: &str,
    internal_prefix: Option<&str>,
    policy_path: Option<&str>,
) -> String {
    let Some(source) = parse_source_kind(source) else {
        return format!(
            "whoathere policy check-source\nstatus=error\nreason_code=unsupported_source_kind\npackage={package}"
        );
    };
    let loaded_policy = if let Some(path) = policy_path {
        match load_policy_document(path) {
            Ok(document) => Some(document),
            Err(error) => {
                return format!(
                    "whoathere policy check-source\nstatus=error\nreason_code=policy_invalid\npackage={package}\nerror={error}"
                );
            }
        }
    } else {
        None
    };
    let inline_rules = internal_prefix
        .map(|prefix| {
            vec![NamespaceRule {
                prefix: prefix.to_string(),
                ownership: NamespaceOwnership::InternalOnly,
            }]
        })
        .unwrap_or_default();
    let rules = loaded_policy
        .as_ref()
        .map(|document| document.namespace_rules.as_slice())
        .unwrap_or(inline_rules.as_slice());
    let evaluation = evaluate_source_policy(package, source, rules, ExecutionMode::CiFailClosed);
    let policy_version = loaded_policy
        .as_ref()
        .map(|document| document.policy_version.as_str())
        .unwrap_or("inline");
    format!(
        "whoathere policy check-source\nstatus=ok\npackage={package}\nsource={source:?}\npolicy_version={policy_version}\ndecision={:?}\nreason_code={}",
        evaluation.decision, evaluation.reason_code
    )
}

fn parse_source_kind(value: &str) -> Option<SourceKind> {
    match value {
        "internal" => Some(SourceKind::Internal),
        "public" => Some(SourceKind::Public),
        "direct_url" => Some(SourceKind::DirectUrl),
        "git" => Some(SourceKind::Git),
        "local_path" => Some(SourceKind::LocalPath),
        _ => None,
    }
}

fn parse_source_file_kind(value: &str) -> Option<SourceFileKind> {
    match value {
        "npmrc" | ".npmrc" => Some(SourceFileKind::NpmRc),
        "pip-conf" | "pip.conf" | "pipconfig" => Some(SourceFileKind::PipConfig),
        "package-lock" | "package-lock.json" | "npm-shrinkwrap" | "npm-shrinkwrap.json" => {
            Some(SourceFileKind::PackageLock)
        }
        "requirements" | "requirements.txt" => Some(SourceFileKind::Requirements),
        _ => None,
    }
}

fn render_source_scan(kind: &str, path: &str, vault_origin: Option<&str>) -> String {
    let Some(vault_origin) = vault_origin else {
        return format!(
            "whoathere source scan\nstatus=error\nreason_code=vault_origin_required\nkind={kind}\npath={}",
            redacted_scalar(path)
        );
    };
    let Some(kind) = parse_source_file_kind(kind) else {
        return format!(
            "whoathere source scan\nstatus=error\nreason_code=unsupported_source_file_kind\nkind={kind}"
        );
    };
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            return format!(
                "whoathere source scan\nstatus=error\nreason_code=source_file_read_failed\npath={}\nerror={}",
                redacted_scalar(path),
                redacted_scalar(&error.to_string())
            );
        }
    };
    let report = scan_source_contents(path, kind, &contents, vault_origin);
    format!(
        "whoathere source scan\nkind={kind:?}\npath={}\n{}",
        redacted_scalar(path),
        render_source_report(&report)
    )
}

fn render_source_workspace_scan(path: &str, vault_origin: Option<&str>) -> String {
    let Some(vault_origin) = vault_origin else {
        return format!(
            "whoathere source scan-workspace\nstatus=error\nreason_code=vault_origin_required\npath={}",
            redacted_scalar(path)
        );
    };
    let report = scan_workspace(std::path::Path::new(path), vault_origin);
    format!(
        "whoathere source scan-workspace\npath={}\n{}",
        redacted_scalar(path),
        render_source_report(&report)
    )
}

fn render_source_context(tool: &str, vault_origin: Option<&str>) -> String {
    let Some(vault_origin) = vault_origin else {
        return format!(
            "whoathere source context\nstatus=error\nreason_code=vault_origin_required\ntool={}",
            redacted_scalar(tool)
        );
    };
    match build_sanitized_context(tool, vault_origin) {
        Ok(context) => format!(
            "whoathere source context\nstatus=ok\n{}",
            render_context_summary(&context)
        ),
        Err(error) => format!(
            "whoathere source context\n{}",
            render_context_error_lines(tool, error)
        ),
    }
}

struct LaunchCommandArgs<'a> {
    tool: &'a str,
    args: &'a [String],
    execute: bool,
    workspace: Option<&'a str>,
    vault_origin: Option<&'a str>,
    runtime_dir: Option<&'a str>,
    containment_available: bool,
    egress_enforced: bool,
}

fn operator_containment_proof(asserted: bool) -> ContainmentProof {
    if asserted {
        let backend = if cfg!(target_os = "macos") {
            ContainmentBackend::MacosVmBeta
        } else if cfg!(target_os = "linux") {
            ContainmentBackend::LinuxNamespace
        } else {
            ContainmentBackend::None
        };
        ContainmentProof::operator_asserted(ExecutionMode::CiFailClosed, backend)
    } else {
        ContainmentProof::missing(ExecutionMode::CiFailClosed)
    }
}

fn operator_egress_proof(asserted: bool, vault_origin: Option<&str>) -> EgressProof {
    if asserted {
        let configured_vault_host = vault_origin.and_then(vault_host_port).unwrap_or_default();
        EgressProof::operator_asserted(configured_vault_host)
    } else {
        EgressProof::missing()
    }
}

fn render_launch_plan(command: LaunchCommandArgs<'_>) -> String {
    let request = launch_request_from_args(&command);
    let plan = build_launch_plan(&request);
    render_launch_plan_output(&plan, command.execute)
}

fn render_launch_provider_check(command: LaunchCommandArgs<'_>) -> String {
    let request = launch_request_from_args(&command);
    let plan = build_launch_plan(&request);
    let launch_output = render_launch_plan_output(&plan, command.execute);
    let provider_output = render_launch_provider_check_output(&plan);
    format!("{launch_output}\n{provider_output}")
}

fn launch_request_from_args(command: &LaunchCommandArgs<'_>) -> LaunchRequest {
    let mut request = LaunchRequest::new(command.tool.to_string(), command.args.to_vec());
    request.execute_requested = command.execute;
    request.workspace = command.workspace.map(std::path::PathBuf::from);
    request.vault_origin = command.vault_origin.map(str::to_string);
    request.runtime_dir = command.runtime_dir.map(std::path::PathBuf::from);
    request.containment_proof = operator_containment_proof(command.containment_available);
    request.egress_proof = operator_egress_proof(command.egress_enforced, command.vault_origin);
    request
}

fn render_launch_plan_output(plan: &LaunchPlan, execute_requested: bool) -> String {
    let final_exit_code = if plan.status == LaunchStatus::Blocked
        || (execute_requested && plan.risk != WorkflowRisk::Low && !plan.execution_allowed)
    {
        ExitCode::Deny.code()
    } else {
        ExitCode::Allow.code()
    };
    let status = match plan.status {
        LaunchStatus::Blocked => "blocked",
        LaunchStatus::Planned => "planned",
    };
    let source = plan
        .source_report
        .as_ref()
        .map(render_source_report)
        .unwrap_or_else(|| "source_scan_status=not_requested".to_string());
    let context = plan
        .context
        .as_ref()
        .map(render_context_summary)
        .unwrap_or_else(|| "launch_context_status=not_planned".to_string());
    let runtime = match plan.runtime.as_ref() {
        Some(runtime) => format!(
            "runtime_materialized=true\nruntime_dir={}\nruntime_home={}\nruntime_xdg_config={}\nruntime_config_path={}\nruntime_config_bytes={}\nruntime_config_private={}\nruntime_dir_private={}\nruntime_home_private={}\nruntime_xdg_private={}\ncleanup_lease_id={}\ncleanup_manifest_path={}\ncleanup_owned_paths={}",
            redacted_scalar(&runtime.runtime_dir.display().to_string()),
            redacted_scalar(&runtime.home_dir.display().to_string()),
            redacted_scalar(&runtime.xdg_config_dir.display().to_string()),
            redacted_scalar(&runtime.config_path.display().to_string()),
            runtime.config_bytes,
            runtime.config_permissions_private,
            runtime.runtime_permissions_private,
            runtime.home_permissions_private,
            runtime.xdg_permissions_private,
            redacted_scalar(&runtime.cleanup_lease_id),
            redacted_scalar(&runtime.cleanup_manifest_path.display().to_string()),
            redacted_scalar(&runtime.cleanup_owned_paths.join(","))
        ),
        None => "runtime_materialized=false".to_string(),
    };
    let launch_context_hash = plan.launch_context_hash.as_deref().unwrap_or("none");
    let source_scan_hash = plan.source_scan_hash.as_deref().unwrap_or("none");
    let proof_challenge = plan
        .proof_challenge
        .as_ref()
        .map(render_provider_challenge_summary)
        .unwrap_or_else(|| {
            "proof_challenge_id=none\nproof_challenge_subject=none\nproof_challenge_context_hash=none\nproof_challenge_configured_vault_host=none\nproof_challenge_probe_count=0\nproof_challenge_expires_at=0\nproof_challenge_nonce_present=false\nproof_challenge_valid=false\nproof_challenge_reason_codes=[\"proof_challenge_not_available\"]\nprovider_challenge_command=none".to_string()
        });
    format!(
        "whoathere launch plan\nfinal_exit_code={final_exit_code}\nlaunch_plan_status={status}\ntool={}\nargs={:?}\ncommand_kind={:?}\nrisk={:?}\nreason_codes={:?}\nexecute_requested={}\nlaunch_context_hash={}\nsource_scan_hash={}\n{}\ncontainment_proof_status={:?}\ncontainment_proof_subject={}\ncontainment_proof_backend={:?}\ncontainment_proof_strength={:?}\ncontainment_proof_provider_id={}\ncontainment_proof_provider_version={}\ncontainment_proof_platform={}\ncontainment_proof_mechanism={:?}\ncontainment_proof_trust={:?}\ncontainment_proof_verified_at={}\ncontainment_proof_expires_at={}\ncontainment_proof_context_hash={}\ncontainment_proof_rule_generation_id={}\ncontainment_proof_evidence_count={}\ncontainment_proof_reason={}\negress_proof_status={:?}\negress_proof_subject={}\negress_proof_provider_id={}\negress_proof_provider_version={}\negress_proof_platform={}\negress_proof_mechanism={:?}\negress_proof_trust={:?}\negress_proof_scope={:?}\negress_proof_verified_at={}\negress_proof_expires_at={}\negress_proof_context_hash={}\negress_proof_rule_generation_id={}\negress_proof_evidence_count={}\negress_proof_configured_vault_host={}\negress_proof_reason={}\nexecution_allowed={}\n{}\n{}\n{}",
        redacted_scalar(&plan.tool),
        redacted_args(&plan.args),
        plan.command_kind,
        plan.risk,
        plan.reason_codes,
        execute_requested,
        redacted_scalar(launch_context_hash),
        redacted_scalar(source_scan_hash),
        proof_challenge,
        plan.containment_proof.status(),
        redacted_scalar(&plan.containment_proof.subject().launch_id),
        plan.containment_proof.backend(),
        plan.containment_proof.strength(),
        redacted_scalar(&plan.containment_proof.provenance().provider_id),
        redacted_scalar(&plan.containment_proof.provenance().provider_version),
        redacted_scalar(&plan.containment_proof.provenance().platform),
        plan.containment_proof.provenance().mechanism,
        plan.containment_proof.provenance().trust,
        plan.containment_proof
            .provenance()
            .verified_at_unix_seconds,
        plan.containment_proof
            .provenance()
            .expires_at_unix_seconds,
        redacted_scalar(&plan.containment_proof.provenance().context_hash),
        redacted_scalar(&plan.containment_proof.provenance().rule_generation_id),
        plan.containment_proof.provenance().evidence.len(),
        plan.containment_proof.reason_code(),
        plan.egress_proof.status(),
        redacted_scalar(&plan.egress_proof.subject().launch_id),
        redacted_scalar(&plan.egress_proof.provenance().provider_id),
        redacted_scalar(&plan.egress_proof.provenance().provider_version),
        redacted_scalar(&plan.egress_proof.provenance().platform),
        plan.egress_proof.provenance().mechanism,
        plan.egress_proof.provenance().trust,
        plan.egress_proof.policy_scope(),
        plan.egress_proof.provenance().verified_at_unix_seconds,
        plan.egress_proof.provenance().expires_at_unix_seconds,
        redacted_scalar(&plan.egress_proof.provenance().context_hash),
        redacted_scalar(&plan.egress_proof.provenance().rule_generation_id),
        plan.egress_proof.provenance().evidence.len(),
        redacted_scalar(plan.egress_proof.configured_vault_host()),
        plan.egress_proof.reason_code(),
        plan.execution_allowed,
        source,
        context,
        runtime
    )
}

fn render_launch_provider_check_output(plan: &LaunchPlan) -> String {
    let Some(challenge) = plan.proof_challenge.as_ref() else {
        return format!(
            "launch_provider_check_status=not_evaluated\nlaunch_provider_check_mutation=false\nlaunch_provider_check_reason=proof_challenge_not_available\nlaunch_provider_check_exit_code={}",
            ExitCode::Deny.code()
        );
    };
    let Some(provider_label) = current_provider_label() else {
        return format!(
            "launch_provider_check_status=fail_closed\nlaunch_provider_check_mutation=false\nlaunch_provider_check_provider=unsupported\nlaunch_provider_check_reason=current_provider_unsupported\nlaunch_provider_check_exit_code={}",
            ExitCode::Deny.code()
        );
    };
    let proofs = match provider_label {
        "linux" => LinuxLocalProofProvider.prove_challenge(challenge, ExecutionMode::CiFailClosed),
        "macos" => MacosLocalProofProvider.prove_challenge(challenge, ExecutionMode::CiFailClosed),
        _ => unreachable!("current provider labels are constrained"),
    };
    let attempt =
        ProviderChallengeAttempt::from_proofs(challenge, &proofs.containment, &proofs.egress);
    let status = if attempt.challenge_satisfied {
        "ok"
    } else {
        "fail_closed"
    };
    let exit_code = if attempt.challenge_satisfied {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };
    format!(
        "launch_provider_check_status={status}\nlaunch_provider_check_mutation=false\nlaunch_provider_check_provider={provider_label}\nlaunch_provider_check_challenge_id={}\nlaunch_provider_check_subject={}\nlaunch_provider_check_context_hash={}\nlaunch_provider_check_configured_vault_host={}\nlaunch_provider_check_probe_count={}\nlaunch_provider_check_containment_status={:?}\nlaunch_provider_check_containment_reason={}\nlaunch_provider_check_egress_status={:?}\nlaunch_provider_check_egress_reason={}\nlaunch_provider_check_satisfied={}\nlaunch_provider_check_reason_codes={:?}\nlaunch_provider_check_exit_code={exit_code}",
        redacted_scalar(&challenge.challenge_id),
        redacted_scalar(&challenge.subject.launch_id),
        redacted_scalar(&challenge.context_hash),
        redacted_scalar(&challenge.configured_vault_host),
        challenge.probe_destinations.len(),
        proofs.containment.status(),
        proofs.containment.reason_code(),
        proofs.egress.status(),
        proofs.egress.reason_code(),
        attempt.challenge_satisfied,
        attempt.reason_codes
    )
}

fn render_provider_challenge_summary(challenge: &ProviderVerificationChallenge) -> String {
    let reason_codes = challenge
        .reason_codes()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let challenge_command = format!(
        "whoathere evidence challenge --scope current --subject {} --context-hash {} --vault-host {}",
        shell_quote(&challenge.subject.launch_id),
        shell_quote(&challenge.context_hash),
        shell_quote(&challenge.configured_vault_host)
    );
    format!(
        "proof_challenge_id={}\nproof_challenge_subject={}\nproof_challenge_context_hash={}\nproof_challenge_configured_vault_host={}\nproof_challenge_probe_count={}\nproof_challenge_expires_at={}\nproof_challenge_nonce_present={}\nproof_challenge_valid={}\nproof_challenge_reason_codes={:?}\nprovider_challenge_command={}",
        redacted_scalar(&challenge.challenge_id),
        redacted_scalar(&challenge.subject.launch_id),
        redacted_scalar(&challenge.context_hash),
        redacted_scalar(&challenge.configured_vault_host),
        challenge.probe_destinations.len(),
        challenge.expires_at_unix_seconds,
        !challenge.challenge_nonce.is_empty(),
        challenge.valid(),
        reason_codes,
        redacted_scalar(&challenge_command)
    )
}

fn render_launch_audit(command: LaunchCommandArgs<'_>, audit_path: Option<&str>) -> String {
    let request = launch_request_from_args(&command);
    let plan = build_launch_plan(&request);
    let record = launch_audit_record(&plan, command.execute);
    let jsonl = record.to_jsonl();
    if let Some(path) = audit_path {
        match append_jsonl(std::path::Path::new(path), &record) {
            Ok(()) => format!(
                "whoathere launch audit\nstatus=written\npath={}\n{}",
                redacted_scalar(path),
                jsonl
            ),
            Err(error) => format!(
                "whoathere launch audit\nstatus=error\nreason_code=audit_write_failed\npath={}\nerror={}",
                redacted_scalar(path),
                redacted_scalar(&error.to_string())
            ),
        }
    } else {
        jsonl
    }
}

fn render_launch_cleanup(
    manifest_path: Option<&str>,
    execute: bool,
    audit_path: Option<&str>,
) -> String {
    let Some(manifest_path) = manifest_path else {
        return format!(
            "whoathere launch cleanup\nstatus=error\nreason_code=cleanup_manifest_required\nexit_code={}",
            ExitCode::Misuse.code()
        );
    };
    let runtime = match load_cleanup_manifest(std::path::Path::new(manifest_path)) {
        Ok(runtime) => runtime,
        Err(error) => {
            return format!(
                "whoathere launch cleanup\nstatus=error\nreason_code=cleanup_manifest_invalid\nmanifest_path={}\nerror={}\nexit_code={}",
                redacted_scalar(manifest_path),
                redacted_scalar(&error),
                ExitCode::Misuse.code()
            );
        }
    };
    let cleanup = if execute {
        cleanup_runtime_plan(&runtime)
    } else {
        CleanupResult {
            attempted: runtime.cleanup_owned_paths.len(),
            removed_paths: Vec::new(),
            refused_paths: Vec::new(),
            reason_codes: vec!["cleanup_report_only".to_string()],
        }
    };
    let cleanup_summary = cleanup_audit_summary(&cleanup);
    let decision = if execute && !cleanup.refused_paths.is_empty() {
        "deny"
    } else {
        "allow"
    };
    let record = AuditRecord::new(
        "launch-cleanup",
        runtime.cleanup_lease_id.clone(),
        format!("launch cleanup {}", redacted_scalar(manifest_path)),
        decision,
        cleanup.reason_codes.clone(),
    )
    .with_cleanup_summary(cleanup_summary);
    let audit_status = render_audit_write_status("cleanup", audit_path, &record);
    let exit_code = if execute && !cleanup.refused_paths.is_empty() {
        ExitCode::Deny.code()
    } else {
        ExitCode::Allow.code()
    };
    format!(
        "whoathere launch cleanup\nstatus=ok\nmutation={execute}\nmanifest_path={}\nruntime_dir={}\ncleanup_lease_id={}\ncleanup_attempted={}\ncleanup_removed_count={}\ncleanup_refused_count={}\ncleanup_reason_codes={:?}\ncleanup_removed_paths={}\ncleanup_refused_paths={}{}{}\nexit_code={exit_code}",
        redacted_scalar(manifest_path),
        redacted_scalar(&runtime.runtime_dir.display().to_string()),
        redacted_scalar(&runtime.cleanup_lease_id),
        cleanup.attempted,
        cleanup.removed_paths.len(),
        cleanup.refused_paths.len(),
        cleanup.reason_codes,
        redacted_scalar(&cleanup.removed_paths.join(",")),
        redacted_scalar(&cleanup.refused_paths.join(",")),
        if audit_status.is_empty() { "" } else { "\n" },
        audit_status
    )
}

fn render_audit_write_status(
    prefix: &str,
    audit_path: Option<&str>,
    record: &AuditRecord,
) -> String {
    let Some(path) = audit_path else {
        return String::new();
    };
    match append_jsonl(std::path::Path::new(path), record) {
        Ok(()) => format!(
            "{prefix}_audit_status=written\n{prefix}_audit_path={}",
            redacted_scalar(path)
        ),
        Err(error) => format!(
            "{prefix}_audit_status=error\n{prefix}_audit_reason=audit_write_failed\n{prefix}_audit_path={}\n{prefix}_audit_error={}",
            redacted_scalar(path),
            redacted_scalar(&error.to_string())
        ),
    }
}

fn cleanup_audit_summary(cleanup: &CleanupResult) -> AuditCleanupSummary {
    AuditCleanupSummary {
        attempted: cleanup.attempted,
        removed_count: cleanup.removed_paths.len(),
        refused_count: cleanup.refused_paths.len(),
        reason_codes: cleanup.reason_codes.clone(),
    }
}

fn launch_audit_record(plan: &LaunchPlan, execute_requested: bool) -> AuditRecord {
    let decision = if plan.status == LaunchStatus::Blocked {
        "deny"
    } else {
        "allow"
    };
    let command = format!("{} {:?}", plan.tool, redacted_args(&plan.args));
    let mut record = AuditRecord::new(
        "launch-plan-preview",
        plan.launch_context_hash
            .as_deref()
            .unwrap_or("launch-context-unavailable"),
        command,
        decision,
        plan.reason_codes.clone(),
    )
    .with_launch_hashes(
        plan.launch_context_hash.clone(),
        plan.source_scan_hash.clone(),
    )
    .with_proof_summary(containment_audit_summary(plan))
    .with_proof_summary(egress_audit_summary(plan));

    if let Some(runtime) = plan.runtime.as_ref() {
        record = record.with_cleanup_summary(AuditCleanupSummary {
            attempted: runtime.cleanup_owned_paths.len(),
            removed_count: 0,
            refused_count: 0,
            reason_codes: vec!["cleanup_not_executed".to_string()],
        });
    } else if execute_requested {
        record = record.with_cleanup_summary(AuditCleanupSummary {
            attempted: 0,
            removed_count: 0,
            refused_count: 0,
            reason_codes: vec!["runtime_not_materialized".to_string()],
        });
    }
    record
}

fn protect_source_audit_record(tool: &str, args: &[String], blocked_output: &str) -> AuditRecord {
    let mut reason_codes = vec!["source_scan_blocked".to_string()];
    for line in blocked_output.lines() {
        if let Some(reason) = line.strip_prefix("source_scan_reason=") {
            reason_codes.push(reason.to_string());
        }
        if let Some(reason) = line.split("reason_code=").nth(1) {
            reason_codes.push(
                reason
                    .split_whitespace()
                    .next()
                    .unwrap_or("source_scan_finding")
                    .trim_matches('"')
                    .to_string(),
            );
        }
        if let Some(reason) = line.split("reason_code:").nth(1) {
            reason_codes.push(
                reason
                    .split_whitespace()
                    .next()
                    .unwrap_or("source_scan_finding")
                    .trim_matches('"')
                    .to_string(),
            );
        }
    }
    reason_codes.sort();
    reason_codes.dedup();
    AuditRecord::new(
        "protect-source-gate",
        "source-scan",
        format!("{} {:?}", tool, redacted_args(args)),
        "deny",
        reason_codes,
    )
}

fn protect_package_identity_audit_record(
    tool: &str,
    args: &[String],
    blocked_output: &str,
) -> AuditRecord {
    let mut reason_codes = vec!["package_identity_policy_blocked".to_string()];
    collect_reason_codes_from_lines(blocked_output, &mut reason_codes);
    reason_codes.sort();
    reason_codes.dedup();
    AuditRecord::new(
        "protect-package-identity-gate",
        "package-identity",
        format!("{} {:?}", tool, redacted_args(args)),
        "deny",
        reason_codes,
    )
}

fn collect_reason_codes_from_lines(lines: &str, reason_codes: &mut Vec<String>) {
    for line in lines.lines() {
        if let Some(reason) = line.strip_prefix("package_identity_reason=") {
            reason_codes.push(reason.to_string());
        }
        if let Some(reason) = line.split("reason_code=").nth(1) {
            reason_codes.push(
                reason
                    .split_whitespace()
                    .next()
                    .unwrap_or("package_identity_finding")
                    .trim_matches('"')
                    .to_string(),
            );
        }
        if let Some(reason) = line.split("reason_code:").nth(1) {
            reason_codes.push(
                reason
                    .split_whitespace()
                    .next()
                    .unwrap_or("package_identity_finding")
                    .trim_matches('"')
                    .to_string(),
            );
        }
    }
}

fn containment_audit_summary(plan: &LaunchPlan) -> AuditProofSummary {
    let proof = &plan.containment_proof;
    AuditProofSummary {
        kind: "containment".to_string(),
        status: format!("{:?}", proof.status()),
        subject: proof.subject().launch_id.clone(),
        provider_id: proof.provenance().provider_id.clone(),
        provider_version: proof.provenance().provider_version.clone(),
        platform: proof.provenance().platform.clone(),
        mechanism: format!("{:?}", proof.provenance().mechanism),
        trust: format!("{:?}", proof.provenance().trust),
        expires_at_unix_seconds: proof.provenance().expires_at_unix_seconds,
        context_hash: proof.provenance().context_hash.clone(),
        rule_generation_id: proof.provenance().rule_generation_id.clone(),
        evidence_count: proof.provenance().evidence.len(),
        reason_code: proof.reason_code().to_string(),
    }
}

fn egress_audit_summary(plan: &LaunchPlan) -> AuditProofSummary {
    let proof = &plan.egress_proof;
    AuditProofSummary {
        kind: "egress".to_string(),
        status: format!("{:?}", proof.status()),
        subject: proof.subject().launch_id.clone(),
        provider_id: proof.provenance().provider_id.clone(),
        provider_version: proof.provenance().provider_version.clone(),
        platform: proof.provenance().platform.clone(),
        mechanism: format!("{:?}", proof.provenance().mechanism),
        trust: format!("{:?}", proof.provenance().trust),
        expires_at_unix_seconds: proof.provenance().expires_at_unix_seconds,
        context_hash: proof.provenance().context_hash.clone(),
        rule_generation_id: proof.provenance().rule_generation_id.clone(),
        evidence_count: proof.provenance().evidence.len(),
        reason_code: proof.reason_code().to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectSourceGate {
    rendered: String,
    blocked_output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectPackageIdentityGate {
    rendered: String,
    blocked_output: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProtectLaunchGate {
    rendered: String,
    blocked_output: Option<String>,
}

fn render_protect_package_identity_gate(
    tool: &str,
    args: &[String],
    classification: &CommandClassification,
    workspace: &Option<String>,
    policy: &PolicyDocument,
) -> ProtectPackageIdentityGate {
    if !package_identity_gate_applies(classification.kind) {
        return ProtectPackageIdentityGate {
            rendered:
                "package_identity_status=skipped\npackage_identity_reason=not_install_workflow"
                    .to_string(),
            blocked_output: None,
        };
    }

    let requirement_files = command_requirement_file_args(args, classification.kind);
    if !requirement_files.is_empty() && workspace.is_none() {
        return ProtectPackageIdentityGate {
            rendered: String::new(),
            blocked_output: Some(render_requirements_workspace_required(
                &requirement_files,
                policy,
            )),
        };
    }

    let mut report = PackageIdentityReport::empty();
    if let Some(workspace) = workspace {
        report.merge(discover_package_identities_for_ecosystem(
            std::path::Path::new(workspace),
            package_identity_ecosystem_for_command(classification.kind),
        ));
        report.merge(command_requirement_file_identities(
            std::path::Path::new(workspace),
            &requirement_files,
        ));
    }
    report.merge(command_package_identities(tool, args, classification.kind));

    let rendered = render_package_identity_report(&report, policy);
    if package_identity_report_blocks(&report, policy) {
        ProtectPackageIdentityGate {
            rendered: String::new(),
            blocked_output: Some(rendered),
        }
    } else {
        ProtectPackageIdentityGate {
            rendered,
            blocked_output: None,
        }
    }
}

fn package_identity_gate_applies(kind: CommandKind) -> bool {
    matches!(
        kind,
        CommandKind::NpmInstall
            | CommandKind::NpmCi
            | CommandKind::NpmExec
            | CommandKind::PipInstall
            | CommandKind::PythonModulePipInstall
            | CommandKind::UvSync
            | CommandKind::UvPipInstall
    )
}

fn package_identity_ecosystem_for_command(kind: CommandKind) -> PackageIdentityEcosystem {
    match kind {
        CommandKind::NpmInstall | CommandKind::NpmCi | CommandKind::NpmExec => {
            PackageIdentityEcosystem::Npm
        }
        CommandKind::PipInstall
        | CommandKind::PythonModulePipInstall
        | CommandKind::UvSync
        | CommandKind::UvPipInstall => PackageIdentityEcosystem::Python,
        CommandKind::VersionProbe | CommandKind::Unknown => PackageIdentityEcosystem::Npm,
    }
}

fn package_identity_report_blocks(report: &PackageIdentityReport, policy: &PolicyDocument) -> bool {
    report.has_blocking_findings()
        || report.identities.iter().any(|identity| {
            evaluate_source_policy(
                &identity.name,
                policy_source_kind(identity.source_kind),
                &policy.namespace_rules,
                ExecutionMode::CiFailClosed,
            )
            .decision
                != PolicyDecision::Allow
        })
}

fn render_package_identity_report(
    report: &PackageIdentityReport,
    policy: &PolicyDocument,
) -> String {
    let parser_blocked = report.has_blocking_findings();
    let evaluations = report
        .identities
        .iter()
        .map(|identity| {
            (
                identity,
                evaluate_source_policy(
                    &identity.name,
                    policy_source_kind(identity.source_kind),
                    &policy.namespace_rules,
                    ExecutionMode::CiFailClosed,
                ),
            )
        })
        .collect::<Vec<_>>();
    let policy_blocked = evaluations
        .iter()
        .any(|(_, evaluation)| evaluation.decision != PolicyDecision::Allow);
    let status = if parser_blocked || policy_blocked {
        "blocked"
    } else {
        "ok"
    };
    let reason = if parser_blocked {
        "package_identity_manifest_blocked"
    } else if policy_blocked {
        evaluations
            .iter()
            .find(|(_, evaluation)| evaluation.decision != PolicyDecision::Allow)
            .map(|(_, evaluation)| evaluation.reason_code)
            .unwrap_or("package_identity_policy_blocked")
    } else if report.identities.is_empty() {
        "no_package_identities_discovered"
    } else {
        "package_identities_allowed"
    };
    let exit_code = if status == "blocked" {
        ExitCode::Deny.code()
    } else {
        ExitCode::Allow.code()
    };
    let finding_lines = report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "package_identity_finding severity={:?} reason_code={} file={} detail=\"{}\"",
                finding.severity,
                finding.reason_code,
                redacted_scalar(&finding.file),
                redacted_scalar(&finding.detail)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let identity_lines = evaluations
        .iter()
        .map(|(identity, evaluation)| {
            format!(
                "package_identity ecosystem={:?} source={:?} file={} package={} decision={:?} reason_code={}",
                identity.ecosystem,
                identity.source_kind,
                redacted_scalar(&identity.file),
                redacted_scalar(&identity.name),
                evaluation.decision,
                evaluation.reason_code
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "package_identity_status={status}\npackage_identity_reason={reason}\npackage_identity_policy_version={}\npackage_identity_files_scanned={}\npackage_identity_count={}\npackage_identity_blocking_findings={}\npackage_identity_exit_code={exit_code}{}{}{}{}",
        redacted_scalar(&policy.policy_version),
        report.files_scanned,
        report.identities.len(),
        parser_blocked || policy_blocked,
        if finding_lines.is_empty() { "" } else { "\n" },
        finding_lines,
        if identity_lines.is_empty() { "" } else { "\n" },
        identity_lines
    )
}

fn render_requirements_workspace_required(files: &[String], policy: &PolicyDocument) -> String {
    let file_lines = files
        .iter()
        .map(|file| {
            format!(
                "package_identity_finding severity=High reason_code=requirements_argv_workspace_required file={} detail=\"pip requirement or constraint file requires --workspace for safe inspection\"",
                redacted_scalar(file)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "package_identity_status=blocked\npackage_identity_reason=requirements_argv_workspace_required\npackage_identity_policy_version={}\npackage_identity_files_scanned=0\npackage_identity_count=0\npackage_identity_blocking_findings=true\npackage_identity_exit_code={}{}{}",
        redacted_scalar(&policy.policy_version),
        ExitCode::Deny.code(),
        if file_lines.is_empty() { "" } else { "\n" },
        file_lines
    )
}

fn policy_source_kind(source_kind: PackageIdentitySourceKind) -> SourceKind {
    match source_kind {
        PackageIdentitySourceKind::PublicRegistry => SourceKind::Public,
        PackageIdentitySourceKind::DirectUrl => SourceKind::DirectUrl,
        PackageIdentitySourceKind::Git => SourceKind::Git,
        PackageIdentitySourceKind::LocalPath => SourceKind::LocalPath,
    }
}

fn command_package_identities(
    tool: &str,
    args: &[String],
    kind: CommandKind,
) -> PackageIdentityReport {
    let mut report = PackageIdentityReport::empty();
    match kind {
        CommandKind::NpmInstall | CommandKind::NpmExec => {
            for name in npm_package_arg_names(args) {
                report.push_identity(PackageIdentity {
                    ecosystem: PackageIdentityEcosystem::Npm,
                    source_kind: PackageIdentitySourceKind::PublicRegistry,
                    file: "<argv>".to_string(),
                    name,
                });
            }
        }
        CommandKind::PipInstall
        | CommandKind::PythonModulePipInstall
        | CommandKind::UvPipInstall => {
            for (name, source_kind) in pip_package_arg_entries(tool, args, kind) {
                report.push_identity(PackageIdentity {
                    ecosystem: PackageIdentityEcosystem::Python,
                    source_kind,
                    file: "<argv>".to_string(),
                    name,
                });
            }
        }
        CommandKind::NpmCi
        | CommandKind::UvSync
        | CommandKind::VersionProbe
        | CommandKind::Unknown => {}
    }
    report
}

fn command_requirement_file_identities(
    workspace: &std::path::Path,
    requirement_files: &[String],
) -> PackageIdentityReport {
    let mut report = PackageIdentityReport::empty();
    for relative in requirement_files {
        if matches!(
            relative.as_str(),
            "requirements.txt" | "requirements-dev.txt"
        ) {
            continue;
        }
        report.merge(discover_requirements_identities(workspace, relative));
    }
    report
}

fn command_requirement_file_args(args: &[String], kind: CommandKind) -> Vec<String> {
    if !matches!(
        kind,
        CommandKind::PipInstall | CommandKind::PythonModulePipInstall
    ) {
        return Vec::new();
    }
    let pip_args = if kind == CommandKind::PythonModulePipInstall && args.len() >= 2 {
        &args[2..]
    } else {
        args
    };
    pip_requirement_file_args(pip_args)
}

fn pip_requirement_file_args(args: &[String]) -> Vec<String> {
    let mut files = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if matches!(arg.as_str(), "-r" | "--requirement" | "-c" | "--constraint") {
            if let Some(value) = args.get(index + 1) {
                push_unique_string(&mut files, value);
            }
            index += 2;
            continue;
        }
        for prefix in ["--requirement=", "--constraint="] {
            if let Some(value) = arg.strip_prefix(prefix) {
                push_unique_string(&mut files, value);
            }
        }
        index += 1;
    }
    files
}

fn push_unique_string(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn npm_package_arg_names(args: &[String]) -> Vec<String> {
    let Some(command_index) = args
        .iter()
        .position(|arg| matches!(arg.as_str(), "install" | "i" | "add" | "exec" | "x"))
    else {
        return Vec::new();
    };
    let mut names = Vec::new();
    let mut index = command_index + 1;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--" {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            index += if option_consumes_next(arg) { 2 } else { 1 };
            continue;
        }
        if let Some(name) = npm_package_name_from_spec(arg) {
            if !names.contains(&name) {
                names.push(name);
            }
        }
        index += 1;
    }
    names
}

fn pip_package_arg_entries(
    _tool: &str,
    args: &[String],
    kind: CommandKind,
) -> Vec<(String, PackageIdentitySourceKind)> {
    let pip_args = if kind == CommandKind::PythonModulePipInstall && args.len() >= 2 {
        &args[2..]
    } else {
        args
    };
    let Some(command_index) = pip_args.iter().position(|arg| arg == "install") else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    let mut index = command_index + 1;
    while index < pip_args.len() {
        let arg = &pip_args[index];
        if arg == "--" {
            index += 1;
            continue;
        }
        if arg.starts_with('-') {
            index += if option_consumes_next(arg) { 2 } else { 1 };
            continue;
        }
        let report = extract_package_identities("<argv>", SourceFileKind::Requirements, arg);
        for identity in report.identities {
            let entry = (identity.name, identity.source_kind);
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
        index += 1;
    }
    entries
}

fn option_consumes_next(arg: &str) -> bool {
    !arg.contains('=')
        && matches!(
            arg,
            "--registry"
                | "--userconfig"
                | "--globalconfig"
                | "--cache"
                | "--prefix"
                | "--index-url"
                | "-i"
                | "--extra-index-url"
                | "--find-links"
                | "-f"
                | "--requirement"
                | "-r"
                | "--constraint"
                | "-c"
                | "--python"
                | "--config-settings"
                | "-C"
        )
}

fn npm_package_name_from_spec(spec: &str) -> Option<String> {
    let spec = spec.trim();
    if spec.is_empty()
        || spec.starts_with("http://")
        || spec.starts_with("https://")
        || spec.starts_with("git+")
        || spec.starts_with("file:")
        || spec.starts_with("./")
        || spec.starts_with("../")
        || spec.starts_with('/')
        || spec.starts_with("github:")
        || spec.contains("://")
    {
        return None;
    }
    let candidate = if spec.starts_with('@') {
        let slash_index = spec.find('/')?;
        let rest = &spec[slash_index + 1..];
        let end = rest.find('@').map(|offset| slash_index + 1 + offset);
        &spec[..end.unwrap_or(spec.len())]
    } else {
        spec.split('@').next().unwrap_or(spec)
    };
    if valid_npm_package_arg_name(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn valid_npm_package_arg_name(value: &str) -> bool {
    if let Some((scope, name)) = value.split_once('/') {
        return scope.starts_with('@')
            && valid_npm_package_arg_segment(&scope[1..])
            && valid_npm_package_arg_segment(name)
            && !name.contains('/');
    }
    valid_npm_package_arg_segment(value)
}

fn valid_npm_package_arg_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '~'))
}

fn render_protect_launch_gate(
    tool: &str,
    args: &[String],
    execute: bool,
    classification: &CommandClassification,
    workspace: Option<&str>,
    vault_origin: Option<&str>,
    audit_path: Option<&str>,
) -> ProtectLaunchGate {
    if !execute {
        return ProtectLaunchGate {
            rendered: "launch_plan_status=skipped\nlaunch_plan_reason=execution_not_requested"
                .to_string(),
            blocked_output: None,
        };
    }
    if classification.risk == WorkflowRisk::Low {
        return ProtectLaunchGate {
            rendered: "launch_plan_status=skipped\nlaunch_plan_reason=readonly_runner_path"
                .to_string(),
            blocked_output: None,
        };
    }

    let mut request = LaunchRequest::new(tool.to_string(), args.to_vec());
    request.execute_requested = execute;
    request.workspace = workspace.map(std::path::PathBuf::from);
    request.vault_origin = vault_origin.map(str::to_string);
    request.containment_proof = ContainmentProof::missing(ExecutionMode::CiFailClosed);
    request.egress_proof = EgressProof::missing();
    let plan = build_launch_plan(&request);
    let audit_status =
        render_audit_write_status("launch", audit_path, &launch_audit_record(&plan, execute));
    let launch_context_hash = plan.launch_context_hash.as_deref().unwrap_or("none");
    let source_scan_hash = plan.source_scan_hash.as_deref().unwrap_or("none");
    let rendered = format!(
        "launch_plan_status={}\nlaunch_plan_reason_codes={:?}\nlaunch_plan_context_hash={}\nlaunch_plan_source_scan_hash={}\nlaunch_plan_containment_proof_status={:?}\nlaunch_plan_containment_proof_subject={}\nlaunch_plan_containment_proof_provider_id={}\nlaunch_plan_containment_proof_mechanism={:?}\nlaunch_plan_containment_proof_trust={:?}\nlaunch_plan_containment_proof_expires_at={}\nlaunch_plan_containment_proof_reason={}\nlaunch_plan_egress_proof_status={:?}\nlaunch_plan_egress_proof_subject={}\nlaunch_plan_egress_proof_provider_id={}\nlaunch_plan_egress_proof_mechanism={:?}\nlaunch_plan_egress_proof_trust={:?}\nlaunch_plan_egress_proof_scope={:?}\nlaunch_plan_egress_proof_expires_at={}\nlaunch_plan_egress_proof_reason={}\nlaunch_plan_execution_allowed={}{}{}",
        match plan.status {
            LaunchStatus::Blocked => "blocked",
            LaunchStatus::Planned => "planned",
        },
        plan.reason_codes,
        redacted_scalar(launch_context_hash),
        redacted_scalar(source_scan_hash),
        plan.containment_proof.status(),
        redacted_scalar(&plan.containment_proof.subject().launch_id),
        redacted_scalar(&plan.containment_proof.provenance().provider_id),
        plan.containment_proof.provenance().mechanism,
        plan.containment_proof.provenance().trust,
        plan.containment_proof
            .provenance()
            .expires_at_unix_seconds,
        plan.containment_proof.reason_code(),
        plan.egress_proof.status(),
        redacted_scalar(&plan.egress_proof.subject().launch_id),
        redacted_scalar(&plan.egress_proof.provenance().provider_id),
        plan.egress_proof.provenance().mechanism,
        plan.egress_proof.provenance().trust,
        plan.egress_proof.policy_scope(),
        plan.egress_proof.provenance().expires_at_unix_seconds,
        plan.egress_proof.reason_code(),
        plan.execution_allowed,
        if audit_status.is_empty() { "" } else { "\n" },
        audit_status
    );
    if plan.status == LaunchStatus::Blocked {
        ProtectLaunchGate {
            rendered: String::new(),
            blocked_output: Some(rendered),
        }
    } else {
        ProtectLaunchGate {
            rendered,
            blocked_output: None,
        }
    }
}

fn render_protect_source_gate(
    tool: &str,
    args: &[String],
    kind: CommandKind,
    workspace: &Option<String>,
    vault_origin: Option<&str>,
) -> ProtectSourceGate {
    let Some(vault_origin) = vault_origin else {
        if workspace.is_some() {
            return ProtectSourceGate {
                rendered: String::new(),
                blocked_output: Some(
                    "source_scan_status=blocked\nsource_scan_reason=vault_origin_required"
                        .to_string(),
                ),
            };
        }
        return ProtectSourceGate {
            rendered:
                "source_scan_status=skipped\nsource_scan_reason=workspace_and_vault_origin_not_configured\nlaunch_context_status=skipped"
                    .to_string(),
            blocked_output: None,
        };
    };

    let context = match build_sanitized_context(tool, vault_origin) {
        Ok(context) => context,
        Err(error) => {
            return ProtectSourceGate {
                rendered: String::new(),
                blocked_output: Some(format!(
                    "source_scan_status=blocked\nsource_scan_reason=invalid_launch_context\n{}",
                    render_context_error_lines(tool, error)
                )),
            };
        }
    };
    let context_summary = render_context_summary(&context);

    let Some(workspace) = workspace else {
        return ProtectSourceGate {
            rendered: format!(
                "source_scan_status=skipped\nsource_scan_reason=workspace_not_configured\n{context_summary}"
            ),
            blocked_output: None,
        };
    };

    let workspace_path = std::path::Path::new(workspace);
    let mut report = scan_workspace(workspace_path, vault_origin);
    report.merge(command_requirement_file_source_scan(
        workspace_path,
        args,
        kind,
        vault_origin,
    ));
    let rendered_report = render_source_report(&report);
    if report.has_blocking_findings() {
        ProtectSourceGate {
            rendered: String::new(),
            blocked_output: Some(format!("{rendered_report}\n{context_summary}")),
        }
    } else {
        ProtectSourceGate {
            rendered: format!("{rendered_report}\n{context_summary}"),
            blocked_output: None,
        }
    }
}

fn command_requirement_file_source_scan(
    workspace: &std::path::Path,
    args: &[String],
    kind: CommandKind,
    vault_origin: &str,
) -> SourceScanReport {
    if !matches!(
        kind,
        CommandKind::PipInstall | CommandKind::PythonModulePipInstall
    ) {
        return SourceScanReport::empty();
    }
    let mut report = SourceScanReport::empty();
    for relative in command_requirement_file_args(args, kind) {
        if matches!(
            relative.as_str(),
            "requirements.txt" | "requirements-dev.txt"
        ) {
            continue;
        }
        report.merge(scan_requirements_path(workspace, &relative, vault_origin));
    }
    report
}

fn render_source_report(report: &SourceScanReport) -> String {
    let status = if report.has_blocking_findings() {
        "blocked"
    } else {
        "ok"
    };
    let exit_code = if report.has_blocking_findings() {
        ExitCode::Deny.code()
    } else {
        ExitCode::Allow.code()
    };
    let finding_lines = report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "finding severity={:?} reason_code={} file={} detail=\"{}\"",
                finding.severity,
                finding.reason_code,
                redacted_scalar(&finding.file),
                redacted_scalar(&finding.detail)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "source_scan_status={status}\nfiles_scanned={}\nfinding_count={}\nblocking_findings={}\nexit_code={exit_code}{}{}",
        report.files_scanned,
        report.findings.len(),
        report.has_blocking_findings(),
        if finding_lines.is_empty() { "" } else { "\n" },
        finding_lines
    )
}

fn render_context_summary(context: &SanitizedExecutionContext) -> String {
    let env_keys = context
        .env
        .iter()
        .map(|(key, _)| key.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let vault_egress = vault_host_port(&context.vault_origin)
        .map(|host| evaluate_configured_vault_egress(&host, &host))
        .map(|decision| decision.reason_code.to_string())
        .unwrap_or_else(|| "egress_vault_origin_unparsed".to_string());
    format!(
        "launch_context_status=planned\nlaunch_context_tool={}\nlaunch_context_vault_origin={}\nlaunch_context_env_clear={}\nlaunch_context_env_keys={}\nlaunch_context_scrubbed_env_names={}\nlaunch_context_scrubbed_env_prefixes={}\nlaunch_context_config_path={}\nlaunch_context_config_bytes={}\nlaunch_context_egress_boundary_required={}\nlaunch_context_egress_probe={}\nlaunch_context_execution_enabled=false",
        redacted_scalar(&context.tool),
        redacted_scalar(&context.vault_origin),
        context.env_clear,
        env_keys,
        context.scrubbed_env_names.join(","),
        context.scrubbed_env_prefixes.join(","),
        redacted_scalar(&context.generated_config_path),
        context.generated_config_contents.len(),
        context.egress_boundary_required,
        vault_egress
    )
}

fn render_context_error_lines(tool: &str, error: ContextError) -> String {
    let reason = match error {
        ContextError::InvalidVaultOrigin(_) => "invalid_vault_origin",
        ContextError::UnsupportedTool(_) => "unsupported_tool",
    };
    format!(
        "status=error\nreason_code={reason}\ntool={}\nerror={}",
        redacted_scalar(tool),
        redacted_scalar(&format!("{error:?}"))
    )
}

fn render_execution_plan(tool: &str, args: &[String], execute: bool) -> String {
    let plan = plan_protected_execution(tool, args, execute);
    match plan.decision {
        ExecutionDecision::ExecuteReadonly => match execute_readonly(tool, args, &plan) {
            Ok(output) => format!(
                "execution_requested=true\nexecution_decision=execute_readonly\nexecution_reason={}\nexecution_status={:?}\nexecution_stdout={:?}\nexecution_stderr={:?}",
                plan.reason_code,
                output.status_code,
                redacted_scalar(&output.stdout),
                redacted_scalar(&output.stderr)
            ),
            Err(error) => format!(
                "execution_requested=true\nexecution_decision=refuse\nexecution_reason=readonly_execution_failed\nexecution_error={}",
                redacted_scalar(&error.to_string())
            ),
        },
        ExecutionDecision::Refuse => format!(
            "execution_requested={execute}\nexecution_decision=refuse\nexecution_reason={}",
            plan.reason_code
        ),
    }
}

fn render_config_check(path: &str) -> String {
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            return format!(
                "whoathere config check\nstatus=error\nreason_code=config_read_failed\npath={path}\nerror={error}"
            );
        }
    };
    match parse_config_kv(&contents) {
        Ok(config) => format!(
            "whoathere config check\nstatus=ok\npath={path}\nschema_version={}\nmode={:?}\noutage_behavior={:?}\ntelemetry_redacted_remote={}\nvault_url_set={}",
            config.schema_version,
            config.mode,
            config.outage_behavior,
            config.telemetry_redacted_remote,
            config.vault_url.is_some()
        ),
        Err(error) => format!(
            "whoathere config check\nstatus=error\nreason_code=config_invalid\npath={path}\nerror={error:?}"
        ),
    }
}

fn render_manifest_scan(kind: &str, path: &str) -> String {
    if !matches!(kind, "npm-package-json" | "pyproject" | "pyproject.toml") {
        return format!(
            "whoathere scan manifest\nstatus=error\nreason_code=unsupported_manifest_kind\nkind={kind}"
        );
    }

    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) => {
            return format!(
                "whoathere scan manifest\nstatus=error\nreason_code=manifest_read_failed\npath={path}\nerror={error}"
            );
        }
    };

    let report = match kind {
        "npm-package-json" => scan_npm_package_json(&contents),
        "pyproject" | "pyproject.toml" => scan_pyproject_toml(&contents),
        _ => unreachable!("unsupported kind returned before file read"),
    };
    let finding_lines = report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "finding severity={:?} reason_code={} detail=\"{}\"",
                finding.severity, finding.reason_code, finding.detail
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "whoathere scan manifest\nstatus=ok\nkind={kind}\npath={path}\npassed={}\nfinding_count={}\n{}",
        report.passed(),
        report.findings.len(),
        finding_lines
    )
}

fn render_evidence_profiles() -> String {
    let rows = minimum_profiles()
        .into_iter()
        .map(|profile| {
            format!(
                "profile={} version={} auto_allow_eligible={} never_auto_allow={} mandatory_jobs={}",
                profile.id,
                profile.version,
                profile.auto_allow_eligible,
                profile.never_auto_allow,
                profile
                    .requirements
                    .iter()
                    .filter(|requirement| requirement.mandatory)
                    .count()
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    format!("whoathere evidence profiles\n{rows}")
}

fn render_endpoint_setup(
    shim_dir: Option<&str>,
    workspace: Option<&str>,
    vault_origin: Option<&str>,
    policy_path: Option<&str>,
    audit_path: Option<&str>,
    replay_store: Option<&str>,
    include_python: bool,
) -> String {
    let mut reason_codes = Vec::new();
    if shim_dir.is_none() {
        reason_codes.push("shim_dir_required");
    }
    if workspace.is_none() {
        reason_codes.push("workspace_required");
    }
    if vault_origin.is_none() {
        reason_codes.push("vault_origin_required");
    }

    if !reason_codes.is_empty() {
        return format!(
            "whoathere endpoint setup\nstatus=error\nmutation=false\nreason_codes={:?}\nshim_dir_set={}\nworkspace_set={}\nvault_origin_set={}\nexit_code={}",
            reason_codes,
            shim_dir.is_some(),
            workspace.is_some(),
            vault_origin.is_some(),
            ExitCode::Misuse.code()
        );
    }

    let shim_dir = shim_dir.expect("checked above");
    let workspace = workspace.expect("checked above");
    let vault_origin = vault_origin.expect("checked above");
    let provider_ready = local_providers_can_verify_now(ProviderScope::Current);
    let provider_exit_code = if provider_ready {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };
    let setup_status = if provider_ready { "ok" } else { "fail_closed" };
    let readiness_reason = if provider_ready {
        "provider_ready"
    } else {
        "provider_not_ready"
    };
    let shim_install_python = if include_python {
        " --include-python"
    } else {
        ""
    };
    let policy_export = export_or_unset("WHOATHERE_POLICY", policy_path);
    let audit_export = export_or_unset("WHOATHERE_AUDIT_PATH", audit_path);
    let replay_store_export = export_or_unset("WHOATHERE_REPLAY_STORE", replay_store);

    format!(
        "whoathere endpoint setup\nstatus={setup_status}\nmutation=false\nreason_codes=[\"{readiness_reason}\"]\nshim_dir={}\nshim_dir_exists={}\nworkspace={}\nworkspace_exists={}\nvault_origin={}\npolicy_path={}\naudit_path={}\nreplay_store={}\ninclude_python={include_python}\nshim_install_command={}\nexport_PATH={}\nexport_WHOATHERE_WORKSPACE={}\nexport_WHOATHERE_VAULT_ORIGIN={}\nexport_WHOATHERE_POLICY={}\nexport_WHOATHERE_AUDIT_PATH={}\nexport_WHOATHERE_REPLAY_STORE={}\nprovider_check_command={}\nprovider_scope=current\ncurrent_provider_platform={}\nprovider_ready={provider_ready}\nprovider_exit_code={provider_exit_code}\nready_for_high_risk_execution={provider_ready}\npath_enablement_mode=fail_closed_interception\nexit_code={provider_exit_code}",
        redacted_scalar(shim_dir),
        std::path::Path::new(shim_dir).exists(),
        redacted_scalar(workspace),
        std::path::Path::new(workspace).exists(),
        redacted_scalar(vault_origin),
        option_text(policy_path),
        option_text(audit_path),
        option_text(replay_store),
        redacted_scalar(&format!(
            "whoathere shim install --dest {}{}",
            shell_quote(shim_dir),
            shim_install_python
        )),
        redacted_scalar(&format!("export PATH={}:\"$PATH\"", shell_quote(shim_dir))),
        redacted_scalar(&format!(
            "export WHOATHERE_WORKSPACE={}",
            shell_quote(workspace)
        )),
        redacted_scalar(&format!(
            "export WHOATHERE_VAULT_ORIGIN={}",
            shell_quote(vault_origin)
        )),
        policy_export,
        audit_export,
        replay_store_export,
        "whoathere evidence providers --json --require-ready --scope current",
        current_provider_label().unwrap_or("unsupported"),
    )
}

fn export_or_unset(key: &str, value: Option<&str>) -> String {
    value
        .map(|value| redacted_scalar(&format!("export {key}={}", shell_quote(value))))
        .unwrap_or_else(|| format!("unset {key}"))
}

fn option_text(value: Option<&str>) -> String {
    value
        .map(redacted_scalar)
        .unwrap_or_else(|| "unset".to_string())
}

fn provider_scope_label(scope: ProviderScope) -> &'static str {
    match scope {
        ProviderScope::All => "all",
        ProviderScope::Current => "current",
        ProviderScope::Linux => "linux",
        ProviderScope::Macos => "macos",
        ProviderScope::Invalid => "invalid",
    }
}

fn current_provider_label() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("linux")
    } else if cfg!(target_os = "macos") {
        Some("macos")
    } else {
        None
    }
}

fn provider_scope_includes(scope: ProviderScope, label: &str) -> bool {
    match scope {
        ProviderScope::All => true,
        ProviderScope::Current => current_provider_label() == Some(label),
        ProviderScope::Linux => label == "linux",
        ProviderScope::Macos => label == "macos",
        ProviderScope::Invalid => false,
    }
}

fn render_evidence_providers(
    json: bool,
    require_ready: bool,
    provider_scope: ProviderScope,
) -> String {
    if provider_scope == ProviderScope::Invalid {
        return render_invalid_provider_scope(json);
    }
    if json {
        return render_evidence_providers_json(require_ready, provider_scope);
    }

    let linux = LinuxLocalProofProvider;
    let macos = MacosLocalProofProvider;
    let providers: [(&str, &dyn ProofProvider); 2] = [("linux", &linux), ("macos", &macos)];
    let rows = providers
        .iter()
        .filter(|(label, _)| provider_scope_includes(provider_scope, label))
        .flat_map(|(label, provider)| {
            let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
            let challenge = diagnostic_provider_challenge(label);
            let challenge_attempt =
                provider.evaluate_challenge(&challenge, ExecutionMode::CiFailClosed);
            let egress = provider.prove_egress(
                ProofSubject::for_launch(format!("{label}-diagnostic")),
                "127.0.0.1:4873",
                &["127.0.0.1:4873"],
            );
            let mut lines = vec![format!(
                "provider={} platform={} containment_status={:?} containment_reason={} containment_mechanism={:?} containment_trust={:?} containment_evidence_count={} egress_status={:?} egress_reason={} egress_mechanism={:?} egress_trust={:?} egress_evidence_count={}",
                redacted_scalar(&containment.provenance().provider_id),
                redacted_scalar(&containment.provenance().platform),
                containment.status(),
                containment.reason_code(),
                containment.provenance().mechanism,
                containment.provenance().trust,
                containment.provenance().evidence.len(),
                egress.status(),
                egress.reason_code(),
                egress.provenance().mechanism,
                egress.provenance().trust,
                egress.provenance().evidence.len()
            )];
            lines.push(render_provider_challenge_attempt_text(
                label,
                &challenge_attempt,
            ));
            lines.push(render_provider_posture_text(
                label,
                &containment.provenance().evidence,
            ));
            if *label == "linux" {
                let active_probe_evidence =
                    combined_proof_evidence(&containment.provenance().evidence, &egress.provenance().evidence);
                let active_probe_receipt =
                    linux_active_probe_receipt_from_evidence(&challenge, &active_probe_evidence);
                lines.push(render_linux_active_probe_receipt_text(
                    &active_probe_receipt,
                ));
                let readiness =
                    linux_containment_readiness_from_evidence(&containment.provenance().evidence);
                lines.push(format!(
                    "provider_readiness provider=linux control_level={} target_matches_host={:?} required_primitives_present={} proof_verification_enabled={} proc_status_available={} user_namespace_observed={} net_namespace_observed={} cgroup_available={} no_new_privs={:?} seccomp_mode={:?} unprivileged_userns_clone={:?} landlock_abi_version={:?} namespace_creation_tool_available={} packet_filter_tool_available={} reason_codes={:?}",
                    readiness.control_level.label(),
                    readiness.target_matches_host,
                    readiness.required_primitives_present,
                    readiness.proof_verification_enabled,
                    readiness.proc_status_available,
                    readiness.user_namespace_observed,
                    readiness.net_namespace_observed,
                    readiness.cgroup_available,
                    readiness.no_new_privs,
                    readiness.seccomp_mode,
                    readiness.unprivileged_userns_clone,
                    readiness.landlock_abi_version,
                    readiness.namespace_creation_tool_available,
                    readiness.packet_filter_tool_available,
                    readiness.reason_codes
                ));
            } else if *label == "macos" {
                let readiness =
                    macos_containment_readiness_from_evidence(&containment.provenance().evidence);
                lines.push(format!(
                    "provider_readiness provider=macos control_level={} target_matches_host={:?} required_primitives_present={} beta_containment={} proof_verification_enabled={} vm_isolation_primitives_present={} egress_control_primitives_present={} telemetry_primitives_present={} hypervisor_framework_available={} virtualization_framework_available={} endpointsecurity_framework_available={} network_extension_framework_available={} sandbox_exec_available={} pfctl_available={} reason_codes={:?}",
                    readiness.control_level.label(),
                    readiness.target_matches_host,
                    readiness.required_primitives_present,
                    readiness.beta_containment,
                    readiness.proof_verification_enabled,
                    readiness.vm_isolation_primitives_present,
                    readiness.egress_control_primitives_present,
                    readiness.telemetry_primitives_present,
                    readiness.hypervisor_framework_available,
                    readiness.virtualization_framework_available,
                    readiness.endpointsecurity_framework_available,
                    readiness.network_extension_framework_available,
                    readiness.sandbox_exec_available,
                    readiness.pfctl_available,
                    readiness.reason_codes
                ));
            }
            lines.extend(containment.provenance().evidence.iter().map(|signal| {
                format!(
                    "provider_evidence provider={} kind=containment signal={}",
                    label,
                    redacted_scalar(signal)
                )
            }));
            lines.extend(egress.provenance().evidence.iter().map(|signal| {
                format!(
                    "provider_evidence provider={} kind=egress signal={}",
                    label,
                    redacted_scalar(signal)
                )
            }));
            lines
        })
        .collect::<Vec<_>>()
        .join("\n");
    let gate = if require_ready {
        render_provider_ready_gate_text(provider_scope)
    } else {
        String::new()
    };
    format!(
        "whoathere evidence providers\nprovider_scope={}\ncurrent_provider_platform={}\n{rows}{gate}",
        provider_scope_label(provider_scope),
        current_provider_label().unwrap_or("unsupported")
    )
}

fn render_evidence_challenge(
    json: bool,
    provider_scope: ProviderScope,
    subject: Option<&str>,
    context_hash: Option<&str>,
    vault_host: Option<&str>,
) -> String {
    let mut reason_codes = Vec::new();
    if provider_scope == ProviderScope::Invalid || provider_scope == ProviderScope::All {
        reason_codes.push("provider_challenge_scope_must_select_one");
    }
    if provider_scope == ProviderScope::Current && current_provider_label().is_none() {
        reason_codes.push("provider_challenge_current_provider_unsupported");
    }
    if subject.is_none() {
        reason_codes.push("provider_challenge_subject_required");
    }
    if context_hash.is_none() {
        reason_codes.push("provider_challenge_context_hash_required");
    }
    if vault_host.is_none() {
        reason_codes.push("provider_challenge_vault_host_required");
    }
    if !reason_codes.is_empty() {
        return render_evidence_challenge_error(json, provider_scope, &reason_codes);
    }

    let label = match provider_scope {
        ProviderScope::Current => current_provider_label().expect("checked above"),
        ProviderScope::Linux => "linux",
        ProviderScope::Macos => "macos",
        ProviderScope::All | ProviderScope::Invalid => unreachable!("checked above"),
    };
    let challenge = ProviderVerificationChallenge::new(
        ProofSubject::for_launch(subject.expect("checked above")),
        context_hash.expect("checked above"),
        vault_host.expect("checked above"),
        1,
    );
    let proofs = match label {
        "linux" => LinuxLocalProofProvider.prove_challenge(&challenge, ExecutionMode::CiFailClosed),
        "macos" => MacosLocalProofProvider.prove_challenge(&challenge, ExecutionMode::CiFailClosed),
        _ => unreachable!("unsupported provider label checked above"),
    };
    let attempt =
        ProviderChallengeAttempt::from_proofs(&challenge, &proofs.containment, &proofs.egress);
    let status = if attempt.challenge_satisfied {
        "ok"
    } else {
        "fail_closed"
    };
    let exit_code = if attempt.challenge_satisfied {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };
    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence challenge\",\n  \"provider_scope\": {},\n  \"current_provider_platform\": {},\n  \"provider\": {},\n  \"mutation\": false,\n  \"status\": {},\n  \"exit_code\": {exit_code},\n  \"challenge\": {},\n  \"challenge_attempt\": {},\n  \"containment\": {{\"status\": {}, \"reason\": {}, \"mechanism\": {}, \"trust\": {}, \"evidence_count\": {}}},\n  \"egress\": {{\"status\": {}, \"reason\": {}, \"mechanism\": {}, \"trust\": {}, \"evidence_count\": {}}}\n}}",
            json_string(provider_scope_label(provider_scope)),
            json_string(current_provider_label().unwrap_or("unsupported")),
            json_string(label),
            json_string(status),
            render_provider_challenge_json(&challenge),
            render_provider_challenge_attempt_json(&attempt),
            json_string(&format!("{:?}", proofs.containment.status())),
            json_string(proofs.containment.reason_code()),
            json_string(&format!("{:?}", proofs.containment.provenance().mechanism)),
            json_string(&format!("{:?}", proofs.containment.provenance().trust)),
            proofs.containment.provenance().evidence.len(),
            json_string(&format!("{:?}", proofs.egress.status())),
            json_string(proofs.egress.reason_code()),
            json_string(&format!("{:?}", proofs.egress.provenance().mechanism)),
            json_string(&format!("{:?}", proofs.egress.provenance().trust)),
            proofs.egress.provenance().evidence.len()
        );
    }
    format!(
        "whoathere evidence challenge\nprovider_scope={}\ncurrent_provider_platform={}\nprovider={label}\nmutation=false\nstatus={status}\nsubject={}\ncontext_hash={}\nconfigured_vault_host={}\nchallenge_id={}\nchallenge_valid={}\nprobe_count={}\ncontainment_status={:?}\ncontainment_reason={}\ncontainment_mechanism={:?}\ncontainment_trust={:?}\ncontainment_evidence_count={}\negress_status={:?}\negress_reason={}\negress_mechanism={:?}\negress_trust={:?}\negress_evidence_count={}\nchallenge_satisfied={}\nreason_codes={:?}\nexit_code={exit_code}",
        provider_scope_label(provider_scope),
        current_provider_label().unwrap_or("unsupported"),
        redacted_scalar(&challenge.subject.launch_id),
        redacted_scalar(&challenge.context_hash),
        redacted_scalar(&challenge.configured_vault_host),
        redacted_scalar(&challenge.challenge_id),
        challenge.valid(),
        challenge.probe_destinations.len(),
        proofs.containment.status(),
        proofs.containment.reason_code(),
        proofs.containment.provenance().mechanism,
        proofs.containment.provenance().trust,
        proofs.containment.provenance().evidence.len(),
        proofs.egress.status(),
        proofs.egress.reason_code(),
        proofs.egress.provenance().mechanism,
        proofs.egress.provenance().trust,
        proofs.egress.provenance().evidence.len(),
        attempt.challenge_satisfied,
        attempt.reason_codes,
    )
}

fn render_evidence_challenge_error(
    json: bool,
    provider_scope: ProviderScope,
    reason_codes: &[&'static str],
) -> String {
    let reason_strings = reason_codes
        .iter()
        .map(|reason| (*reason).to_string())
        .collect::<Vec<_>>();
    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence challenge\",\n  \"provider_scope\": {},\n  \"status\": \"error\",\n  \"reason_codes\": {},\n  \"exit_code\": {}\n}}",
            json_string(provider_scope_label(provider_scope)),
            json_string_array(&reason_strings),
            ExitCode::Misuse.code()
        );
    }
    format!(
        "whoathere evidence challenge\nstatus=error\nprovider_scope={}\nreason_codes={:?}\nexit_code={}",
        provider_scope_label(provider_scope),
        reason_strings,
        ExitCode::Misuse.code()
    )
}

fn render_evidence_linux_active_probe_fixture(
    json: bool,
    subject: Option<&str>,
    context_hash: Option<&str>,
    vault_host: Option<&str>,
    profile: Option<&str>,
) -> String {
    let mut reason_codes = Vec::new();
    if subject.is_none() {
        reason_codes.push("linux_active_probe_fixture_subject_required");
    }
    if context_hash.is_none() {
        reason_codes.push("linux_active_probe_fixture_context_hash_required");
    }
    if vault_host.is_none() {
        reason_codes.push("linux_active_probe_fixture_vault_host_required");
    }
    let profile = parse_linux_active_probe_fixture_profile(
        profile,
        &mut reason_codes,
        "linux_active_probe_fixture_profile_required",
        "linux_active_probe_fixture_profile_invalid",
    );
    if !reason_codes.is_empty() {
        return render_linux_active_probe_fixture_error(json, &reason_codes);
    }

    let profile = profile.expect("checked above");
    let challenge = ProviderVerificationChallenge::new(
        ProofSubject::for_launch(subject.expect("checked above")),
        context_hash.expect("checked above"),
        vault_host.expect("checked above"),
        1,
    );
    let evidence = linux_active_probe_fixture_evidence(&challenge, profile);
    let receipt = linux_active_probe_receipt_from_evidence(&challenge, &evidence);
    let status = if receipt.satisfied {
        "ok"
    } else {
        "fail_closed"
    };
    let exit_code = if receipt.satisfied {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };

    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence linux-active-probe-fixture\",\n  \"mutation\": false,\n  \"authorization\": false,\n  \"proof_minted\": false,\n  \"execution_allowed\": false,\n  \"profile\": {},\n  \"status\": {},\n  \"exit_code\": {exit_code},\n  \"challenge\": {},\n  \"active_probe_receipt\": {},\n  \"evidence_count\": {}\n}}",
            json_string(profile.label()),
            json_string(status),
            render_provider_challenge_json(&challenge),
            render_linux_active_probe_receipt_json(&receipt),
            evidence.len()
        );
    }

    format!(
        "whoathere evidence linux-active-probe-fixture\nmutation=false\nauthorization=false\nproof_minted=false\nexecution_allowed=false\nprofile={}\nstatus={status}\nsubject={}\ncontext_hash={}\nconfigured_vault_host={}\nchallenge_id={}\nprobe_count={}\nreceipt_satisfied={}\nreceipt_reason_codes={:?}\nallowed_probe_count={}\ndenied_probe_count={}\nmissing_probe_count={}\nallowed_non_vault_probe_count={}\nevidence_count={}\nexit_code={exit_code}",
        profile.label(),
        redacted_scalar(&challenge.subject.launch_id),
        redacted_scalar(&challenge.context_hash),
        redacted_scalar(&challenge.configured_vault_host),
        redacted_scalar(&challenge.challenge_id),
        challenge.probe_destinations.len(),
        receipt.satisfied,
        receipt.reason_codes,
        receipt.allowed_destinations.len(),
        receipt.denied_destinations.len(),
        receipt.missing_probe_destinations.len(),
        receipt.allowed_non_vault_destinations.len(),
        evidence.len()
    )
}

fn parse_linux_active_probe_fixture_profile(
    profile: Option<&str>,
    reason_codes: &mut Vec<&'static str>,
    required_reason: &'static str,
    invalid_reason: &'static str,
) -> Option<LinuxActiveProbeFixtureProfile> {
    match profile {
        Some("complete") => Some(LinuxActiveProbeFixtureProfile::Complete),
        Some("incomplete") => Some(LinuxActiveProbeFixtureProfile::Incomplete),
        Some("overpermissive") => Some(LinuxActiveProbeFixtureProfile::Overpermissive),
        Some(_) => {
            reason_codes.push(invalid_reason);
            None
        }
        None => {
            reason_codes.push(required_reason);
            None
        }
    }
}

fn render_linux_active_probe_fixture_error(json: bool, reason_codes: &[&'static str]) -> String {
    let reason_strings = reason_codes
        .iter()
        .map(|reason| (*reason).to_string())
        .collect::<Vec<_>>();
    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence linux-active-probe-fixture\",\n  \"status\": \"error\",\n  \"reason_codes\": {},\n  \"exit_code\": {}\n}}",
            json_string_array(&reason_strings),
            ExitCode::Misuse.code()
        );
    }
    format!(
        "whoathere evidence linux-active-probe-fixture\nstatus=error\nreason_codes={:?}\nexit_code={}",
        reason_strings,
        ExitCode::Misuse.code()
    )
}

struct LinuxActiveProbeAdmissionRequest<'a> {
    json: bool,
    subject: Option<&'a str>,
    context_hash: Option<&'a str>,
    vault_host: Option<&'a str>,
    profile: Option<&'a str>,
    replay: bool,
    unknown_challenge: bool,
    mutate_context: bool,
}

fn render_evidence_linux_active_probe_admission(
    request: LinuxActiveProbeAdmissionRequest<'_>,
) -> String {
    let LinuxActiveProbeAdmissionRequest {
        json,
        subject,
        context_hash,
        vault_host,
        profile,
        replay,
        unknown_challenge,
        mutate_context,
    } = request;
    let mut reason_codes = Vec::new();
    if subject.is_none() {
        reason_codes.push("linux_active_probe_admission_subject_required");
    }
    if context_hash.is_none() {
        reason_codes.push("linux_active_probe_admission_context_hash_required");
    }
    if vault_host.is_none() {
        reason_codes.push("linux_active_probe_admission_vault_host_required");
    }
    let profile = parse_linux_active_probe_fixture_profile(
        profile,
        &mut reason_codes,
        "linux_active_probe_admission_profile_required",
        "linux_active_probe_admission_profile_invalid",
    );
    if unknown_challenge && mutate_context {
        reason_codes.push("linux_active_probe_admission_scenario_conflict");
    }
    if !reason_codes.is_empty() {
        return render_linux_active_probe_admission_error(json, &reason_codes);
    }

    let profile = profile.expect("checked above");
    let subject = subject.expect("checked above");
    let context_hash = context_hash.expect("checked above");
    let vault_host = vault_host.expect("checked above");
    let now = 100;
    let mut guard = ProviderChallengeReplayGuard::new(60);
    let issued = guard.issue(
        ProofSubject::for_launch(subject),
        context_hash,
        vault_host,
        now,
    );
    let challenge = if unknown_challenge {
        ProviderVerificationChallenge::new(
            ProofSubject::for_launch(subject),
            context_hash,
            vault_host,
            now,
        )
    } else if mutate_context {
        let mut challenge = issued.clone();
        challenge.context_hash = format!("{}-mutated", challenge.context_hash);
        challenge
    } else {
        issued.clone()
    };
    let evidence = linux_active_probe_fixture_evidence(&challenge, profile);
    let preconsume = if replay {
        Some(guard.consume(&challenge, now))
    } else {
        None
    };
    let admission = admit_linux_active_probe_receipt(&mut guard, &challenge, &evidence, now);
    let status = if admission.accepted {
        "ok"
    } else {
        "fail_closed"
    };
    let exit_code = if admission.accepted {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };

    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence linux-active-probe-admission\",\n  \"mutation\": false,\n  \"authorization\": false,\n  \"proof_minted\": false,\n  \"execution_allowed\": false,\n  \"profile\": {},\n  \"scenario\": {{\"replay\": {}, \"unknown_challenge\": {}, \"mutate_context\": {}}},\n  \"status\": {},\n  \"exit_code\": {exit_code},\n  \"issued_challenge\": {},\n  \"submitted_challenge\": {},\n  \"preconsume\": {},\n  \"admission\": {},\n  \"active_probe_receipt\": {},\n  \"evidence_count\": {}\n}}",
            json_string(profile.label()),
            replay,
            unknown_challenge,
            mutate_context,
            json_string(status),
            render_provider_challenge_json(&issued),
            render_provider_challenge_json(&challenge),
            preconsume
                .as_ref()
                .map(render_provider_challenge_use_decision_json)
                .unwrap_or_else(|| "null".to_string()),
            render_linux_active_probe_admission_json(&admission),
            render_linux_active_probe_receipt_json(&admission.receipt),
            evidence.len()
        );
    }

    format!(
        "whoathere evidence linux-active-probe-admission\nmutation=false\nauthorization=false\nproof_minted=false\nexecution_allowed=false\nprofile={}\nreplay={replay}\nunknown_challenge={unknown_challenge}\nmutate_context={mutate_context}\nstatus={status}\nissued_challenge_id={}\nsubmitted_challenge_id={}\npreconsume_status={}\nadmission_accepted={}\nadmission_replay_status={:?}\nadmission_reason_codes={:?}\nreceipt_satisfied={}\nreceipt_reason_codes={:?}\nevidence_count={}\nexit_code={exit_code}",
        profile.label(),
        redacted_scalar(&issued.challenge_id),
        redacted_scalar(&challenge.challenge_id),
        preconsume
            .as_ref()
            .map(|decision| format!("{:?}", decision.status))
            .unwrap_or_else(|| "none".to_string()),
        admission.accepted,
        admission.replay_decision.status,
        admission.reason_codes,
        admission.receipt.satisfied,
        admission.receipt.reason_codes,
        evidence.len()
    )
}

fn render_linux_active_probe_admission_error(json: bool, reason_codes: &[&'static str]) -> String {
    let reason_strings = reason_codes
        .iter()
        .map(|reason| (*reason).to_string())
        .collect::<Vec<_>>();
    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence linux-active-probe-admission\",\n  \"status\": \"error\",\n  \"reason_codes\": {},\n  \"exit_code\": {}\n}}",
            json_string_array(&reason_strings),
            ExitCode::Misuse.code()
        );
    }
    format!(
        "whoathere evidence linux-active-probe-admission\nstatus=error\nreason_codes={:?}\nexit_code={}",
        reason_strings,
        ExitCode::Misuse.code()
    )
}

fn render_linux_active_probe_admission_json(
    admission: &whoathere_sandbox::LinuxActiveProbeAdmission,
) -> String {
    format!(
        "{{\"challenge_id\": {}, \"accepted\": {}, \"replay_decision\": {}, \"reason_codes\": {}}}",
        json_string(&redacted_scalar(&admission.challenge_id)),
        admission.accepted,
        render_provider_challenge_use_decision_json(&admission.replay_decision),
        json_string_array(&admission.reason_codes)
    )
}

fn render_provider_challenge_use_decision_json(
    decision: &whoathere_sandbox::ProviderChallengeUseDecision,
) -> String {
    format!(
        "{{\"challenge_id\": {}, \"status\": {}, \"accepted\": {}, \"reason_codes\": {}}}",
        json_string(&redacted_scalar(&decision.challenge_id)),
        json_string(&format!("{:?}", decision.status)),
        decision.accepted(),
        json_string_array(&decision.reason_codes)
    )
}

const DEFAULT_LINUX_ACTIVE_PROBE_DOCKER_IMAGE: &str = "whoathere/linux-active-probe:local";
const LINUX_ACTIVE_PROBE_DOCKER_TIMEOUT_MS: u64 = 10_000;
const LINUX_ACTIVE_PROBE_IMAGE_CONTRACT: &str = "whoathere-linux-active-probe.v1";
const LINUX_ACTIVE_PROBE_DOCKER_USER: &str = "65532:65532";

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxActiveProbeDockerRun {
    execute_requested: bool,
    image: String,
    docker_invoked: bool,
    container_network: String,
    container_user: String,
    network_internal_verified: Option<bool>,
    no_new_privileges_requested: bool,
    cap_drop_all_requested: bool,
    configured_vault_probe_attempted: bool,
    configured_vault_probe_allowed: bool,
    timed_out: bool,
    docker_exit_code: Option<i32>,
    image_contract: Option<String>,
    image_contract_valid: bool,
    stdout_line_count: usize,
    stderr_byte_count: usize,
    evidence: Vec<String>,
    reason_codes: Vec<String>,
}

struct LinuxActiveProbeDockerRequest<'a> {
    json: bool,
    execute: bool,
    admit: bool,
    replay: bool,
    subject: Option<&'a str>,
    context_hash: Option<&'a str>,
    vault_host: Option<&'a str>,
    image: Option<&'a str>,
    docker_network: Option<&'a str>,
    replay_store: Option<&'a str>,
    audit_path: Option<&'a str>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxActiveProbeDockerReplayStoreStatus {
    configured: bool,
    path: Option<String>,
    operation: &'static str,
    available: bool,
    stale_lock_recovered: bool,
    reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LinuxActiveProbeDockerAuditStatus {
    configured: bool,
    status: &'static str,
    path: Option<String>,
    reason: Option<String>,
}

struct LinuxActiveProbeDockerAuditRequest<'a> {
    audit_path: Option<&'a str>,
    decision: &'a str,
    subject: &'a str,
    context_hash: &'a str,
    store_status: &'a LinuxActiveProbeDockerReplayStoreStatus,
    challenge: Option<&'a ProviderVerificationChallenge>,
    admission: Option<&'a LinuxActiveProbeAdmission>,
    reason_codes: &'a [String],
}

fn render_evidence_linux_active_probe_docker(request: LinuxActiveProbeDockerRequest<'_>) -> String {
    let LinuxActiveProbeDockerRequest {
        json,
        execute,
        admit,
        replay,
        subject,
        context_hash,
        vault_host,
        image,
        docker_network,
        replay_store,
        audit_path,
    } = request;
    let mut reason_codes = Vec::new();
    if subject.is_none() {
        reason_codes.push("linux_active_probe_docker_subject_required");
    }
    if context_hash.is_none() {
        reason_codes.push("linux_active_probe_docker_context_hash_required");
    }
    if vault_host.is_none() {
        reason_codes.push("linux_active_probe_docker_vault_host_required");
    }
    if matches!(image, Some(value) if value.trim().is_empty()) {
        reason_codes.push("linux_active_probe_docker_image_invalid");
    }
    if matches!(docker_network, Some(value) if value.trim().is_empty() || value.trim().starts_with('-'))
    {
        reason_codes.push("linux_active_probe_docker_network_invalid");
    }
    if matches!(replay_store, Some(value) if value.trim().is_empty() || value.trim().starts_with('-'))
    {
        reason_codes.push("linux_active_probe_docker_replay_store_invalid");
    }
    if replay && !admit {
        reason_codes.push("linux_active_probe_docker_admission_required_for_replay");
    }
    if replay_store.is_some() && !admit {
        reason_codes.push("linux_active_probe_docker_admission_required_for_replay_store");
    }
    if !reason_codes.is_empty() {
        return render_linux_active_probe_docker_error(json, &reason_codes);
    }

    let image = image.unwrap_or(DEFAULT_LINUX_ACTIVE_PROBE_DOCKER_IMAGE);
    let docker_network = docker_network.unwrap_or("none").trim();
    let replay_store = replay_store.map(str::trim);
    let now = 100;
    let subject = subject.expect("checked above");
    let context_hash = context_hash.expect("checked above");
    let vault_host = vault_host.expect("checked above");
    let mut guard = ProviderChallengeReplayGuard::new(60);
    let store = replay_store.map(|path| ProviderChallengeReplayFileStore::new(path, 60));
    let mut store_status = LinuxActiveProbeDockerReplayStoreStatus {
        configured: replay_store.is_some(),
        path: replay_store.map(str::to_string),
        operation: "none",
        available: true,
        stale_lock_recovered: false,
        reason_codes: Vec::new(),
    };
    let challenge = if admit {
        if let Some(store) = &store {
            match store.issue_with_outcome(
                ProofSubject::for_launch(subject),
                context_hash,
                vault_host,
                now,
            ) {
                Ok((challenge, outcome)) => {
                    store_status.operation = "issue";
                    store_status.stale_lock_recovered |= outcome.stale_lock_recovered;
                    challenge
                }
                Err(error) => {
                    store_status.operation = "issue";
                    store_status.available = false;
                    store_status.reason_codes = linux_active_probe_replay_store_error_codes(&error);
                    let audit_status =
                        write_linux_active_probe_docker_audit(LinuxActiveProbeDockerAuditRequest {
                            audit_path,
                            decision: "deny",
                            subject,
                            context_hash,
                            store_status: &store_status,
                            challenge: None,
                            admission: None,
                            reason_codes: &store_status.reason_codes,
                        });
                    return render_linux_active_probe_docker_store_failure(
                        json,
                        &store_status,
                        &audit_status,
                        &store_status.reason_codes,
                    );
                }
            }
        } else {
            guard.issue(
                ProofSubject::for_launch(subject),
                context_hash,
                vault_host,
                now,
            )
        }
    } else {
        ProviderVerificationChallenge::new(
            ProofSubject::for_launch(subject),
            context_hash,
            vault_host,
            1,
        )
    };
    let run = if execute {
        run_linux_active_probe_docker(&challenge, image, docker_network)
    } else {
        linux_active_probe_docker_not_executed(&challenge, image, docker_network)
    };
    let receipt = linux_active_probe_receipt_from_evidence(&challenge, &run.evidence);
    let preconsume = if admit && replay {
        if let Some(store) = &store {
            Some(consume_linux_active_probe_replay_store(
                store,
                &challenge,
                now,
                &mut store_status,
                "preconsume",
            ))
        } else {
            Some(guard.consume(&challenge, now))
        }
    } else {
        None
    };
    let admission = if admit {
        if let Some(store) = &store {
            let replay_decision = consume_linux_active_probe_replay_store(
                store,
                &challenge,
                now,
                &mut store_status,
                "consume",
            );
            Some(admit_linux_active_probe_receipt_with_replay_decision(
                replay_decision,
                &challenge,
                &run.evidence,
            ))
        } else {
            Some(admit_linux_active_probe_receipt(
                &mut guard,
                &challenge,
                &run.evidence,
                now,
            ))
        }
    } else {
        None
    };
    let accepted = if let Some(admission) = &admission {
        admission.accepted && run.reason_codes.is_empty()
    } else {
        receipt.satisfied && run.reason_codes.is_empty()
    };
    let status = if accepted { "ok" } else { "fail_closed" };
    let exit_code = if accepted {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };
    let mut audit_reason_codes = Vec::new();
    audit_reason_codes.extend(store_status.reason_codes.clone());
    audit_reason_codes.extend(run.reason_codes.clone());
    audit_reason_codes.extend(receipt.reason_codes.clone());
    if let Some(preconsume) = &preconsume {
        audit_reason_codes.extend(preconsume.reason_codes.clone());
    }
    if let Some(admission) = &admission {
        audit_reason_codes.extend(admission.reason_codes.clone());
        audit_reason_codes.extend(admission.replay_decision.reason_codes.clone());
    }
    audit_reason_codes.sort();
    audit_reason_codes.dedup();
    let decision = if accepted { "allow" } else { "deny" };
    let audit_status = write_linux_active_probe_docker_audit(LinuxActiveProbeDockerAuditRequest {
        audit_path,
        decision,
        subject,
        context_hash,
        store_status: &store_status,
        challenge: Some(&challenge),
        admission: admission.as_ref(),
        reason_codes: &audit_reason_codes,
    });

    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence linux-active-probe-docker\",\n  \"mutation\": {},\n  \"authorization\": false,\n  \"proof_minted\": false,\n  \"execution_allowed\": false,\n  \"admission_applied\": {},\n  \"replay_store\": {},\n  \"audit\": {},\n  \"status\": {},\n  \"exit_code\": {exit_code},\n  \"challenge\": {},\n  \"docker\": {},\n  \"preconsume\": {},\n  \"admission\": {},\n  \"active_probe_receipt\": {},\n  \"evidence_count\": {}\n}}",
            execute,
            admit,
            render_linux_active_probe_docker_replay_store_json(&store_status),
            render_linux_active_probe_docker_audit_json(&audit_status),
            json_string(status),
            render_provider_challenge_json(&challenge),
            render_linux_active_probe_docker_run_json(&run),
            preconsume
                .as_ref()
                .map(render_provider_challenge_use_decision_json)
                .unwrap_or_else(|| "null".to_string()),
            admission
                .as_ref()
                .map(render_linux_active_probe_admission_json)
                .unwrap_or_else(|| "null".to_string()),
            render_linux_active_probe_receipt_json(&receipt),
            run.evidence.len()
        );
    }

    format!(
        "whoathere evidence linux-active-probe-docker\nmutation={execute}\nauthorization=false\nproof_minted=false\nexecution_allowed=false\nadmission_applied={admit}\nreplay_store_configured={}\nreplay_store_path={}\nreplay_store_operation={}\nreplay_store_available={}\nreplay_store_stale_lock_recovered={}\nreplay_store_reason_codes={:?}\naudit_status={}\naudit_path={}\naudit_reason={}\nstatus={status}\nsubject={}\ncontext_hash={}\nconfigured_vault_host={}\nchallenge_id={}\nprobe_count={}\ndocker_image={}\ndocker_invoked={}\ndocker_network={}\ndocker_container_user={}\ndocker_network_internal_verified={}\ndocker_exit_code={}\ndocker_image_contract={}\ndocker_image_contract_valid={}\ndocker_configured_vault_probe_attempted={}\ndocker_configured_vault_probe_allowed={}\ndocker_timed_out={}\ndocker_reason_codes={:?}\npreconsume_status={}\nadmission_accepted={}\nadmission_replay_status={}\nadmission_reason_codes={}\nreceipt_satisfied={}\nreceipt_reason_codes={:?}\nallowed_probe_count={}\ndenied_probe_count={}\nmissing_probe_count={}\nallowed_non_vault_probe_count={}\nevidence_count={}\nexit_code={exit_code}",
        store_status.configured,
        store_status
            .path
            .as_deref()
            .map(redacted_scalar)
            .unwrap_or_else(|| "none".to_string()),
        store_status.operation,
        store_status.available,
        store_status.stale_lock_recovered,
        store_status.reason_codes,
        audit_status.status,
        audit_status
            .path
            .as_deref()
            .map(redacted_scalar)
            .unwrap_or_else(|| "none".to_string()),
        audit_status
            .reason
            .as_deref()
            .map(redacted_scalar)
            .unwrap_or_else(|| "none".to_string()),
        redacted_scalar(&challenge.subject.launch_id),
        redacted_scalar(&challenge.context_hash),
        redacted_scalar(&challenge.configured_vault_host),
        redacted_scalar(&challenge.challenge_id),
        challenge.probe_destinations.len(),
        redacted_scalar(&run.image),
        run.docker_invoked,
        redacted_scalar(&run.container_network),
        redacted_scalar(&run.container_user),
        run.network_internal_verified
            .map(|verified| verified.to_string())
            .unwrap_or_else(|| "none".to_string()),
        run.docker_exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "none".to_string()),
        redacted_option_scalar(run.image_contract.as_deref()),
        run.image_contract_valid,
        run.configured_vault_probe_attempted,
        run.configured_vault_probe_allowed,
        run.timed_out,
        run.reason_codes,
        preconsume
            .as_ref()
            .map(|decision| format!("{:?}", decision.status))
            .unwrap_or_else(|| "none".to_string()),
        admission
            .as_ref()
            .map(|admission| admission.accepted.to_string())
            .unwrap_or_else(|| "none".to_string()),
        admission
            .as_ref()
            .map(|admission| format!("{:?}", admission.replay_decision.status))
            .unwrap_or_else(|| "none".to_string()),
        admission
            .as_ref()
            .map(|admission| format!("{:?}", admission.reason_codes))
            .unwrap_or_else(|| "none".to_string()),
        receipt.satisfied,
        receipt.reason_codes,
        receipt.allowed_destinations.len(),
        receipt.denied_destinations.len(),
        receipt.missing_probe_destinations.len(),
        receipt.allowed_non_vault_destinations.len(),
        run.evidence.len()
    )
}

fn consume_linux_active_probe_replay_store(
    store: &ProviderChallengeReplayFileStore,
    challenge: &ProviderVerificationChallenge,
    now_unix_seconds: u64,
    status: &mut LinuxActiveProbeDockerReplayStoreStatus,
    operation: &'static str,
) -> ProviderChallengeUseDecision {
    status.operation = operation;
    match store.consume_with_outcome(challenge, now_unix_seconds) {
        Ok((decision, outcome)) => {
            status.stale_lock_recovered |= outcome.stale_lock_recovered;
            decision
        }
        Err(error) => {
            status.available = false;
            status.reason_codes = linux_active_probe_replay_store_error_codes(&error);
            ProviderChallengeUseDecision {
                challenge_id: challenge.challenge_id.clone(),
                status: ProviderChallengeUseStatus::Rejected,
                reason_codes: status.reason_codes.clone(),
            }
        }
    }
}

fn linux_active_probe_replay_store_error_codes(error: &std::io::Error) -> Vec<String> {
    let mut reason_codes = vec!["linux_active_probe_docker_replay_store_unavailable".to_string()];
    reason_codes.push(
        match error.kind() {
            std::io::ErrorKind::InvalidData => {
                "linux_active_probe_docker_replay_store_invalid_state"
            }
            std::io::ErrorKind::PermissionDenied => {
                "linux_active_probe_docker_replay_store_permission_denied"
            }
            std::io::ErrorKind::WouldBlock => "linux_active_probe_docker_replay_store_lock_busy",
            _ => "linux_active_probe_docker_replay_store_io_error",
        }
        .to_string(),
    );
    reason_codes.sort();
    reason_codes.dedup();
    reason_codes
}

fn render_linux_active_probe_docker_replay_store_json(
    status: &LinuxActiveProbeDockerReplayStoreStatus,
) -> String {
    format!(
        "{{\"configured\": {}, \"path\": {}, \"operation\": {}, \"available\": {}, \"stale_lock_recovered\": {}, \"reason_codes\": {}}}",
        status.configured,
        status
            .path
            .as_deref()
            .map(|path| json_string(&redacted_scalar(path)))
            .unwrap_or_else(|| "null".to_string()),
        json_string(status.operation),
        status.available,
        status.stale_lock_recovered,
        json_string_array(&status.reason_codes)
    )
}

fn write_linux_active_probe_docker_audit(
    request: LinuxActiveProbeDockerAuditRequest<'_>,
) -> LinuxActiveProbeDockerAuditStatus {
    let LinuxActiveProbeDockerAuditRequest {
        audit_path,
        decision,
        subject,
        context_hash,
        store_status,
        challenge,
        admission,
        reason_codes,
    } = request;
    let Some(path) = audit_path else {
        return LinuxActiveProbeDockerAuditStatus {
            configured: false,
            status: "disabled",
            path: None,
            reason: None,
        };
    };
    let record = linux_active_probe_docker_audit_record(
        decision,
        subject,
        context_hash,
        store_status,
        challenge,
        admission,
        reason_codes,
    );
    match append_jsonl(std::path::Path::new(path), &record) {
        Ok(()) => LinuxActiveProbeDockerAuditStatus {
            configured: true,
            status: "written",
            path: Some(path.to_string()),
            reason: None,
        },
        Err(error) => LinuxActiveProbeDockerAuditStatus {
            configured: true,
            status: "error",
            path: Some(path.to_string()),
            reason: Some(error.to_string()),
        },
    }
}

fn linux_active_probe_docker_audit_record(
    decision: &str,
    subject: &str,
    context_hash: &str,
    store_status: &LinuxActiveProbeDockerReplayStoreStatus,
    challenge: Option<&ProviderVerificationChallenge>,
    admission: Option<&LinuxActiveProbeAdmission>,
    reason_codes: &[String],
) -> AuditRecord {
    let challenge_id = challenge
        .map(|challenge| challenge.challenge_id.clone())
        .unwrap_or_else(|| "none".to_string());
    let replay_status = admission
        .map(|admission| format!("{:?}", admission.replay_decision.status))
        .unwrap_or_else(|| "not_attempted".to_string());
    let accepted = admission
        .map(|admission| admission.accepted)
        .unwrap_or(false);
    let mut replay_reason_codes = reason_codes.to_vec();
    replay_reason_codes.extend(store_status.reason_codes.clone());
    if let Some(admission) = admission {
        replay_reason_codes.extend(admission.replay_decision.reason_codes.clone());
    }
    replay_reason_codes.sort();
    replay_reason_codes.dedup();

    AuditRecord::new(
        "linux-active-probe-docker-replay-store-admission",
        challenge_id.clone(),
        format!(
            "whoathere evidence linux-active-probe-docker subject={} context_hash={} replay_store_configured={}",
            redacted_scalar(subject),
            redacted_scalar(context_hash),
            store_status.configured
        ),
        decision,
        replay_reason_codes.clone(),
    )
    .with_launch_hashes(Some(context_hash.to_string()), None::<String>)
    .with_replay_store_summary(AuditReplayStoreSummary {
        configured: store_status.configured,
        operation: store_status.operation.to_string(),
        available: store_status.available,
        stale_lock_recovered: store_status.stale_lock_recovered,
        challenge_id,
        replay_status,
        accepted,
        reason_codes: replay_reason_codes,
    })
}

fn render_linux_active_probe_docker_audit_json(
    status: &LinuxActiveProbeDockerAuditStatus,
) -> String {
    format!(
        "{{\"configured\": {}, \"status\": {}, \"path\": {}, \"reason\": {}}}",
        status.configured,
        json_string(status.status),
        status
            .path
            .as_deref()
            .map(|path| json_string(&redacted_scalar(path)))
            .unwrap_or_else(|| "null".to_string()),
        status
            .reason
            .as_deref()
            .map(|reason| json_string(&redacted_scalar(reason)))
            .unwrap_or_else(|| "null".to_string())
    )
}

fn render_linux_active_probe_docker_store_failure(
    json: bool,
    store_status: &LinuxActiveProbeDockerReplayStoreStatus,
    audit_status: &LinuxActiveProbeDockerAuditStatus,
    reason_codes: &[String],
) -> String {
    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence linux-active-probe-docker\",\n  \"mutation\": false,\n  \"authorization\": false,\n  \"proof_minted\": false,\n  \"execution_allowed\": false,\n  \"admission_applied\": true,\n  \"replay_store\": {},\n  \"audit\": {},\n  \"status\": \"fail_closed\",\n  \"reason_codes\": {},\n  \"exit_code\": {}\n}}",
            render_linux_active_probe_docker_replay_store_json(store_status),
            render_linux_active_probe_docker_audit_json(audit_status),
            json_string_array(reason_codes),
            ExitCode::Deny.code()
        );
    }

    format!(
        "whoathere evidence linux-active-probe-docker\nmutation=false\nauthorization=false\nproof_minted=false\nexecution_allowed=false\nadmission_applied=true\nreplay_store_configured={}\nreplay_store_path={}\nreplay_store_operation={}\nreplay_store_available={}\nreplay_store_stale_lock_recovered={}\naudit_status={}\naudit_path={}\naudit_reason={}\nstatus=fail_closed\nreason_codes={:?}\nexit_code={}",
        store_status.configured,
        store_status
            .path
            .as_deref()
            .map(redacted_scalar)
            .unwrap_or_else(|| "none".to_string()),
        store_status.operation,
        store_status.available,
        store_status.stale_lock_recovered,
        audit_status.status,
        audit_status
            .path
            .as_deref()
            .map(redacted_scalar)
            .unwrap_or_else(|| "none".to_string()),
        audit_status
            .reason
            .as_deref()
            .map(redacted_scalar)
            .unwrap_or_else(|| "none".to_string()),
        reason_codes,
        ExitCode::Deny.code()
    )
}

fn render_linux_active_probe_docker_error(json: bool, reason_codes: &[&'static str]) -> String {
    let reason_strings = reason_codes
        .iter()
        .map(|reason| (*reason).to_string())
        .collect::<Vec<_>>();
    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence linux-active-probe-docker\",\n  \"status\": \"error\",\n  \"reason_codes\": {},\n  \"exit_code\": {}\n}}",
            json_string_array(&reason_strings),
            ExitCode::Misuse.code()
        );
    }
    format!(
        "whoathere evidence linux-active-probe-docker\nstatus=error\nreason_codes={:?}\nexit_code={}",
        reason_strings,
        ExitCode::Misuse.code()
    )
}

fn linux_active_probe_docker_not_executed(
    challenge: &ProviderVerificationChallenge,
    image: &str,
    docker_network: &str,
) -> LinuxActiveProbeDockerRun {
    LinuxActiveProbeDockerRun {
        execute_requested: false,
        image: image.to_string(),
        docker_invoked: false,
        container_network: docker_network.to_string(),
        container_user: LINUX_ACTIVE_PROBE_DOCKER_USER.to_string(),
        network_internal_verified: None,
        no_new_privileges_requested: true,
        cap_drop_all_requested: true,
        configured_vault_probe_attempted: false,
        configured_vault_probe_allowed: false,
        timed_out: false,
        docker_exit_code: None,
        image_contract: None,
        image_contract_valid: false,
        stdout_line_count: 0,
        stderr_byte_count: 0,
        evidence: linux_active_probe_docker_incomplete_evidence(challenge),
        reason_codes: vec!["linux_active_probe_docker_execute_required".to_string()],
    }
}

fn run_linux_active_probe_docker(
    challenge: &ProviderVerificationChallenge,
    image: &str,
    docker_network: &str,
) -> LinuxActiveProbeDockerRun {
    let mut preflight_reason_codes = Vec::new();
    let network_internal_verified = if docker_network == "none" {
        None
    } else {
        match docker_network_internal(docker_network) {
            Ok(true) => Some(true),
            Ok(false) => {
                preflight_reason_codes
                    .push("linux_active_probe_docker_network_not_internal".to_string());
                Some(false)
            }
            Err(_) => {
                preflight_reason_codes
                    .push("linux_active_probe_docker_network_inspect_failed".to_string());
                None
            }
        }
    };
    if !preflight_reason_codes.is_empty() {
        return LinuxActiveProbeDockerRun {
            execute_requested: true,
            image: image.to_string(),
            docker_invoked: false,
            container_network: docker_network.to_string(),
            container_user: LINUX_ACTIVE_PROBE_DOCKER_USER.to_string(),
            network_internal_verified,
            no_new_privileges_requested: true,
            cap_drop_all_requested: true,
            configured_vault_probe_attempted: false,
            configured_vault_probe_allowed: false,
            timed_out: false,
            docker_exit_code: None,
            image_contract: None,
            image_contract_valid: false,
            stdout_line_count: 0,
            stderr_byte_count: 0,
            evidence: linux_active_probe_docker_incomplete_evidence(challenge),
            reason_codes: preflight_reason_codes,
        };
    }

    let cidfile = linux_active_probe_docker_cidfile(challenge);
    let cidfile_arg = cidfile.display().to_string();
    let mut command = std::process::Command::new("docker");
    command.args([
        "run",
        "--rm",
        "--cidfile",
        &cidfile_arg,
        "--network",
        docker_network,
        "--user",
        LINUX_ACTIVE_PROBE_DOCKER_USER,
        "--security-opt",
        "no-new-privileges",
        "--cap-drop",
        "ALL",
        "--pids-limit",
        "64",
        "--memory",
        "128m",
        "--cpus",
        "1",
        "--entrypoint",
        "/bin/sh",
    ]);
    if docker_network != "none" {
        command.args([
            "--env",
            &format!(
                "WHOATHERE_ACTIVE_PROBE_VAULT_HOST={}",
                challenge.configured_vault_host
            ),
        ]);
    }
    command.args([image, "-c", linux_active_probe_docker_inner_script()]);

    let process = run_process_with_timeout(
        command,
        std::time::Duration::from_millis(LINUX_ACTIVE_PROBE_DOCKER_TIMEOUT_MS),
    );
    match process {
        Ok(process) => {
            if process.timed_out {
                cleanup_docker_container_from_cidfile(&cidfile);
            }
            let _ = std::fs::remove_file(&cidfile);
            let stdout = String::from_utf8_lossy(&process.stdout).to_string();
            let stderr_byte_count = process.stderr.len();
            let stdout_line_count = stdout.lines().count();
            let image_contract =
                docker_probe_fact(&stdout, "probe.image_contract=").map(str::to_string);
            let image_contract_valid =
                image_contract.as_deref() == Some(LINUX_ACTIVE_PROBE_IMAGE_CONTRACT);
            let configured_vault_probe_allowed =
                docker_probe_fact(&stdout, "probe.vault_connect=") == Some("allowed");
            let configured_vault_probe_attempted =
                docker_probe_fact(&stdout, "probe.vault_connect=").is_some();
            let mut reason_codes = Vec::new();
            if process.timed_out {
                reason_codes.push("linux_active_probe_docker_timeout".to_string());
            }
            if process.exit_code != Some(0) {
                reason_codes.push("linux_active_probe_docker_command_failed".to_string());
            }
            let evidence = if reason_codes.is_empty() {
                linux_active_probe_docker_evidence_from_stdout(
                    challenge,
                    &stdout,
                    network_internal_verified == Some(true),
                )
            } else {
                linux_active_probe_docker_incomplete_evidence(challenge)
            };
            LinuxActiveProbeDockerRun {
                execute_requested: true,
                image: image.to_string(),
                docker_invoked: true,
                container_network: docker_network.to_string(),
                container_user: LINUX_ACTIVE_PROBE_DOCKER_USER.to_string(),
                network_internal_verified,
                no_new_privileges_requested: true,
                cap_drop_all_requested: true,
                configured_vault_probe_attempted,
                configured_vault_probe_allowed,
                timed_out: process.timed_out,
                docker_exit_code: process.exit_code,
                image_contract,
                image_contract_valid,
                stdout_line_count,
                stderr_byte_count,
                evidence,
                reason_codes,
            }
        }
        Err(_) => {
            let _ = std::fs::remove_file(&cidfile);
            LinuxActiveProbeDockerRun {
                execute_requested: true,
                image: image.to_string(),
                docker_invoked: false,
                container_network: docker_network.to_string(),
                container_user: LINUX_ACTIVE_PROBE_DOCKER_USER.to_string(),
                network_internal_verified,
                no_new_privileges_requested: true,
                cap_drop_all_requested: true,
                configured_vault_probe_attempted: false,
                configured_vault_probe_allowed: false,
                timed_out: false,
                docker_exit_code: None,
                image_contract: None,
                image_contract_valid: false,
                stdout_line_count: 0,
                stderr_byte_count: 0,
                evidence: linux_active_probe_docker_incomplete_evidence(challenge),
                reason_codes: vec!["linux_active_probe_docker_spawn_failed".to_string()],
            }
        }
    }
}

fn linux_active_probe_docker_cidfile(
    challenge: &ProviderVerificationChallenge,
) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "whoathere-active-probe-{}-{}.cid",
        std::process::id(),
        safe_filename_fragment(&challenge.challenge_id)
    ))
}

fn cleanup_docker_container_from_cidfile(cidfile: &std::path::Path) {
    let Ok(container_id) = std::fs::read_to_string(cidfile) else {
        return;
    };
    let container_id = container_id.trim();
    if container_id.is_empty()
        || !container_id
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return;
    }
    let _ = std::process::Command::new("docker")
        .args(["rm", "-f", container_id])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

fn docker_network_internal(network: &str) -> std::io::Result<bool> {
    let mut command = std::process::Command::new("docker");
    command.args(["network", "inspect", "--format", "{{.Internal}}", network]);
    let output = run_process_with_timeout(
        command,
        std::time::Duration::from_millis(LINUX_ACTIVE_PROBE_DOCKER_TIMEOUT_MS),
    )?;
    if output.exit_code != Some(0) || output.timed_out {
        return Ok(false);
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}

fn safe_filename_fragment(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '_'
            }
        })
        .take(96)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TimedProcessOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    timed_out: bool,
}

fn run_process_with_timeout(
    mut command: std::process::Command,
    timeout: std::time::Duration,
) -> std::io::Result<TimedProcessOutput> {
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()?;
    let started = std::time::Instant::now();
    loop {
        if child.try_wait()?.is_some() {
            let output = child.wait_with_output()?;
            return Ok(TimedProcessOutput {
                stdout: output.stdout,
                stderr: output.stderr,
                exit_code: output.status.code(),
                timed_out: false,
            });
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let output = child.wait_with_output()?;
            return Ok(TimedProcessOutput {
                stdout: output.stdout,
                stderr: output.stderr,
                exit_code: output.status.code(),
                timed_out: true,
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

fn linux_active_probe_docker_inner_script() -> &'static str {
    r#"set -u
if test -x /usr/local/bin/whoathere-active-probe; then
  exec /usr/local/bin/whoathere-active-probe
fi
printf 'probe.image_contract=inline-fallback\n'
printf 'probe.kernel=%s\n' "$(uname -s 2>/dev/null || printf unknown)"
printf 'probe.uid=%s\n' "$(id -u 2>/dev/null || printf unknown)"
printf 'probe.gid=%s\n' "$(id -g 2>/dev/null || printf unknown)"
if test -r /proc/self/status; then
  awk '/^NoNewPrivs:/{print "probe.no_new_privs="$2} /^Seccomp:/{print "probe.seccomp="$2}' /proc/self/status
fi
printf 'probe.userns=%s\n' "$(readlink /proc/self/ns/user 2>/dev/null || printf missing)"
printf 'probe.netns=%s\n' "$(readlink /proc/self/ns/net 2>/dev/null || printf missing)"
if test -r /proc/self/uid_map; then
  awk 'NR==1{print "probe.uid_map="$1 ":" $2 ":" $3}' /proc/self/uid_map
fi
if test -r /proc/self/gid_map; then
  awk 'NR==1{print "probe.gid_map="$1 ":" $2 ":" $3}' /proc/self/gid_map
fi
if command -v unshare >/dev/null 2>&1; then
  if nested_output="$(unshare -Ur /bin/sh -c 'printf "probe.nested_userns=%s\n" "$(readlink /proc/self/ns/user 2>/dev/null || printf missing)"; if test -r /proc/self/uid_map; then awk '\''NR==1{print "probe.nested_uid_map="$1 ":" $2 ":" $3}'\'' /proc/self/uid_map; fi; if test -r /proc/self/gid_map; then awk '\''NR==1{print "probe.nested_gid_map="$1 ":" $2 ":" $3}'\'' /proc/self/gid_map; fi' 2>/dev/null)"; then
    printf 'probe.userns_unshare=allowed\n'
    printf '%s\n' "$nested_output"
  else
    printf 'probe.userns_unshare=denied\n'
  fi
else
  printf 'probe.userns_unshare=missing\n'
fi
if test -r /sys/fs/cgroup/memory.max; then
  printf 'probe.cgroup.memory_max=%s\n' "$(cat /sys/fs/cgroup/memory.max 2>/dev/null || printf missing)"
fi
if test -r /sys/fs/cgroup/pids.max; then
  printf 'probe.cgroup.pids_max=%s\n' "$(cat /sys/fs/cgroup/pids.max 2>/dev/null || printf missing)"
fi
if test -r /sys/fs/cgroup/cpu.max; then
  printf 'probe.cgroup.cpu_max=%s\n' "$(cat /sys/fs/cgroup/cpu.max 2>/dev/null || printf missing)"
fi
if test -n "${WHOATHERE_ACTIVE_PROBE_VAULT_HOST:-}"; then
  vault_host="${WHOATHERE_ACTIVE_PROBE_VAULT_HOST%:*}"
  vault_port="${WHOATHERE_ACTIVE_PROBE_VAULT_HOST##*:}"
  if test -n "$vault_host" && test -n "$vault_port" && nc -z -w 2 "$vault_host" "$vault_port" >/dev/null 2>&1; then
    printf 'probe.vault_connect=allowed\n'
  else
    printf 'probe.vault_connect=denied\n'
  fi
fi
"#
}

fn linux_active_probe_docker_incomplete_evidence(
    challenge: &ProviderVerificationChallenge,
) -> Vec<String> {
    linux_active_probe_docker_base_evidence(challenge, "active_probe_incomplete", false)
}

fn linux_active_probe_docker_evidence_from_stdout(
    challenge: &ProviderVerificationChallenge,
    stdout: &str,
    network_internal_verified: bool,
) -> Vec<String> {
    let kernel_is_linux = docker_probe_fact(stdout, "probe.kernel=") == Some("Linux");
    let no_new_privs = docker_probe_fact(stdout, "probe.no_new_privs=") == Some("1");
    let seccomp_filter_enforced = docker_probe_fact(stdout, "probe.seccomp=")
        .and_then(|value| value.parse::<u32>().ok())
        .is_some_and(|value| value >= 2);
    let memory_limited = docker_probe_fact(stdout, "probe.cgroup.memory_max=")
        .is_some_and(|value| !value.is_empty() && value != "max" && value != "missing");
    let pids_limited = docker_probe_fact(stdout, "probe.cgroup.pids_max=")
        .is_some_and(|value| !value.is_empty() && value != "max" && value != "missing");
    let cgroup_scoped = memory_limited && pids_limited;
    let uid = docker_probe_fact(stdout, "probe.uid=").unwrap_or("unknown");
    let gid = docker_probe_fact(stdout, "probe.gid=").unwrap_or("unknown");
    let uid_map = docker_probe_fact(stdout, "probe.uid_map=").unwrap_or("missing");
    let gid_map = docker_probe_fact(stdout, "probe.gid_map=").unwrap_or("missing");
    let nested_attempt = docker_probe_fact(stdout, "probe.userns_unshare=").unwrap_or("missing");
    let nested_created = nested_attempt == "allowed";
    let nested_uid_map = docker_probe_fact(stdout, "probe.nested_uid_map=").unwrap_or("missing");
    let nested_gid_map = docker_probe_fact(stdout, "probe.nested_gid_map=").unwrap_or("missing");
    let user_namespace_isolated = linux_active_probe_id_map_is_remapped(uid_map)
        && linux_active_probe_id_map_is_remapped(gid_map);
    let vault_connect_allowed =
        docker_probe_fact(stdout, "probe.vault_connect=") == Some("allowed");
    let default_deny_except_configured_vault = network_internal_verified && vault_connect_allowed;

    let mut evidence = linux_active_probe_docker_base_evidence(
        challenge,
        LINUX_ACTIVE_PROBE_COMPLETE_STATUS,
        kernel_is_linux,
    );
    evidence.extend([
        format!("linux.active_probe.user_namespace.isolated={user_namespace_isolated}"),
        format!("linux.active_probe.user_namespace.uid={uid}"),
        format!("linux.active_probe.user_namespace.gid={gid}"),
        format!("linux.active_probe.user_namespace.uid_map={uid_map}"),
        format!("linux.active_probe.user_namespace.gid_map={gid_map}"),
        format!("linux.active_probe.user_namespace.nested_attempt={nested_attempt}"),
        format!("linux.active_probe.user_namespace.nested_created={nested_created}"),
        format!("linux.active_probe.user_namespace.nested_uid_map={nested_uid_map}"),
        format!("linux.active_probe.user_namespace.nested_gid_map={nested_gid_map}"),
        format!(
            "linux.active_probe.network_namespace.isolated={}",
            kernel_is_linux
        ),
        format!("linux.active_probe.no_new_privs={no_new_privs}"),
        format!("linux.active_probe.seccomp_filter.enforced={seccomp_filter_enforced}"),
        format!("linux.active_probe.cgroup.scoped={cgroup_scoped}"),
        format!(
            "linux.active_probe.egress.default_deny_except_configured_vault={default_deny_except_configured_vault}"
        ),
        format!("linux.active_probe.os_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"),
        format!(
            "linux.active_probe.network_mutation_scope={LINUX_ACTIVE_PROBE_NAMESPACE_ONLY_SCOPE}"
        ),
    ]);
    if kernel_is_linux {
        for probe in &challenge.probe_destinations {
            if default_deny_except_configured_vault && probe == &challenge.configured_vault_host {
                evidence.push(format!("linux.active_probe.egress.allowed={probe}"));
            } else {
                evidence.push(format!("linux.active_probe.egress.denied={probe}"));
            }
        }
    }
    evidence
}

fn linux_active_probe_id_map_is_remapped(value: &str) -> bool {
    let mut fields = value.split(':');
    let Some(inside) = fields.next().and_then(|part| part.parse::<u64>().ok()) else {
        return false;
    };
    let Some(outside) = fields.next().and_then(|part| part.parse::<u64>().ok()) else {
        return false;
    };
    let Some(length) = fields.next().and_then(|part| part.parse::<u64>().ok()) else {
        return false;
    };
    inside == 0 && outside != 0 && length > 0
}

fn linux_active_probe_docker_base_evidence(
    challenge: &ProviderVerificationChallenge,
    status: &str,
    target_matches_host: bool,
) -> Vec<String> {
    vec![
        format!("provider_evidence_schema={LINUX_ACTIVE_PROBE_SCHEMA_VERSION}"),
        format!("provider_status={status}"),
        format!("provider_target_matches_host={target_matches_host}"),
        format!("provider_challenge_id={}", challenge.challenge_id),
        format!("provider_challenge_subject={}", challenge.subject.launch_id),
        format!("provider_challenge_context_hash={}", challenge.context_hash),
        format!(
            "provider_challenge_configured_vault_host={}",
            challenge.configured_vault_host
        ),
        "provider_package_execution_attempted=false".to_string(),
        "provider_public_network_probe_attempted=false".to_string(),
    ]
}

fn docker_probe_fact<'a>(stdout: &'a str, prefix: &str) -> Option<&'a str> {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(prefix).map(str::trim))
}

fn render_linux_active_probe_docker_run_json(run: &LinuxActiveProbeDockerRun) -> String {
    format!(
        "{{\"execute_requested\": {}, \"image\": {}, \"docker_invoked\": {}, \"container_network\": {}, \"container_user\": {}, \"network_internal_verified\": {}, \"no_new_privileges_requested\": {}, \"cap_drop_all_requested\": {}, \"configured_vault_probe_attempted\": {}, \"configured_vault_probe_allowed\": {}, \"timed_out\": {}, \"docker_exit_code\": {}, \"image_contract\": {}, \"image_contract_valid\": {}, \"stdout_line_count\": {}, \"stderr_byte_count\": {}, \"reason_codes\": {}}}",
        run.execute_requested,
        json_string(&redacted_scalar(&run.image)),
        run.docker_invoked,
        json_string(&redacted_scalar(&run.container_network)),
        json_string(&redacted_scalar(&run.container_user)),
        json_option(run.network_internal_verified),
        run.no_new_privileges_requested,
        run.cap_drop_all_requested,
        run.configured_vault_probe_attempted,
        run.configured_vault_probe_allowed,
        run.timed_out,
        json_option(run.docker_exit_code),
        json_option_string(run.image_contract.as_deref()),
        run.image_contract_valid,
        run.stdout_line_count,
        run.stderr_byte_count,
        json_string_array(&run.reason_codes)
    )
}

fn render_invalid_provider_scope(json: bool) -> String {
    if json {
        return format!(
            "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence providers\",\n  \"status\": \"error\",\n  \"reason_code\": \"invalid_provider_scope\",\n  \"exit_code\": {}\n}}",
            ExitCode::Misuse.code()
        );
    }
    format!(
        "whoathere evidence providers\nstatus=error\nreason_code=invalid_provider_scope\nexit_code={}",
        ExitCode::Misuse.code()
    )
}

fn render_evidence_providers_json(require_ready: bool, provider_scope: ProviderScope) -> String {
    let linux = LinuxLocalProofProvider;
    let macos = MacosLocalProofProvider;
    let providers: [(&str, &dyn ProofProvider); 2] = [("linux", &linux), ("macos", &macos)];
    let provider_entries = providers
        .iter()
        .filter(|(label, _)| provider_scope_includes(provider_scope, label))
        .map(|(label, provider)| render_provider_diagnostic_json(label, *provider))
        .collect::<Vec<_>>()
        .join(",\n");
    let provider_ready = local_providers_can_verify_now(provider_scope);
    let status = if require_ready && !provider_ready {
        "fail_closed"
    } else {
        "ok"
    };
    let exit_code = if require_ready && !provider_ready {
        ExitCode::Deny.code()
    } else {
        ExitCode::Allow.code()
    };
    format!(
        "{{\n  \"schema_version\": 1,\n  \"command\": \"whoathere evidence providers\",\n  \"require_ready\": {require_ready},\n  \"provider_scope\": {},\n  \"current_provider_platform\": {},\n  \"provider_ready\": {provider_ready},\n  \"status\": {},\n  \"exit_code\": {exit_code},\n  \"providers\": [\n{provider_entries}\n  ]\n}}",
        json_string(provider_scope_label(provider_scope)),
        json_string(current_provider_label().unwrap_or("unsupported")),
        json_string(status)
    )
}

fn render_provider_ready_gate_text(provider_scope: ProviderScope) -> String {
    let provider_ready = local_providers_can_verify_now(provider_scope);
    let status = if provider_ready { "ok" } else { "fail_closed" };
    let exit_code = if provider_ready {
        ExitCode::Allow.code()
    } else {
        ExitCode::Deny.code()
    };
    format!(
        "\nrequire_ready=true\nprovider_scope={}\nprovider_ready={provider_ready}\nstatus={status}\nexit_code={exit_code}",
        provider_scope_label(provider_scope)
    )
}

fn local_providers_can_verify_now(provider_scope: ProviderScope) -> bool {
    let plans = [
        ("linux", linux_diagnostic_plan()),
        ("macos", macos_diagnostic_plan()),
    ];
    let scoped_plans = plans
        .iter()
        .filter(|(label, _)| provider_scope_includes(provider_scope, label))
        .collect::<Vec<_>>();
    !scoped_plans.is_empty() && scoped_plans.iter().all(|(_, plan)| plan.can_verify_now)
}

fn linux_diagnostic_plan() -> LocalVerificationPlan {
    let provider = LinuxLocalProofProvider;
    let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
    let readiness = linux_containment_readiness_from_evidence(&containment.provenance().evidence);
    linux_verification_plan_from_readiness(&readiness)
}

fn macos_diagnostic_plan() -> LocalVerificationPlan {
    let provider = MacosLocalProofProvider;
    let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
    let readiness = macos_containment_readiness_from_evidence(&containment.provenance().evidence);
    macos_verification_plan_from_readiness(&readiness)
}

fn render_provider_diagnostic_json(label: &str, provider: &dyn ProofProvider) -> String {
    let containment = provider.prove_containment(ExecutionMode::CiFailClosed);
    let challenge = diagnostic_provider_challenge(label);
    let challenge_attempt = provider.evaluate_challenge(&challenge, ExecutionMode::CiFailClosed);
    let egress = provider.prove_egress(
        ProofSubject::for_launch(format!("{label}-diagnostic")),
        "127.0.0.1:4873",
        &["127.0.0.1:4873"],
    );
    let containment_provenance = containment.provenance();
    let egress_provenance = egress.provenance();
    let containment_evidence = containment_provenance
        .evidence
        .iter()
        .map(|signal| redacted_scalar(signal))
        .collect::<Vec<_>>();
    let egress_evidence = egress_provenance
        .evidence
        .iter()
        .map(|signal| redacted_scalar(signal))
        .collect::<Vec<_>>();
    let (readiness, verification_plan, active_probe_receipt) = if label == "linux" {
        let readiness = linux_containment_readiness_from_evidence(&containment_provenance.evidence);
        let plan = linux_verification_plan_from_readiness(&readiness);
        let active_probe_evidence = combined_proof_evidence(
            &containment_provenance.evidence,
            &egress_provenance.evidence,
        );
        let active_probe_receipt =
            linux_active_probe_receipt_from_evidence(&challenge, &active_probe_evidence);
        (
            format!(
                "{{\"platform\": \"linux\", \"control_level\": {}, \"target_matches_host\": {}, \"required_primitives_present\": {}, \"proof_verification_enabled\": {}, \"proc_status_available\": {}, \"user_namespace_observed\": {}, \"net_namespace_observed\": {}, \"cgroup_available\": {}, \"no_new_privs\": {}, \"seccomp_mode\": {}, \"unprivileged_userns_clone\": {}, \"landlock_abi_version\": {}, \"namespace_creation_tool_available\": {}, \"packet_filter_tool_available\": {}, \"reason_codes\": {}}}",
                json_string(readiness.control_level.label()),
                json_option(readiness.target_matches_host),
                readiness.required_primitives_present,
                readiness.proof_verification_enabled,
                readiness.proc_status_available,
                readiness.user_namespace_observed,
                readiness.net_namespace_observed,
                readiness.cgroup_available,
                json_option(readiness.no_new_privs),
                json_option(readiness.seccomp_mode),
                json_option(readiness.unprivileged_userns_clone),
                json_option(readiness.landlock_abi_version),
                readiness.namespace_creation_tool_available,
                readiness.packet_filter_tool_available,
                json_string_array(&readiness.reason_codes)
            ),
            render_verification_plan_json(&plan),
            render_linux_active_probe_receipt_json(&active_probe_receipt),
        )
    } else {
        let readiness = macos_containment_readiness_from_evidence(&containment_provenance.evidence);
        let plan = macos_verification_plan_from_readiness(&readiness);
        (
            format!(
                "{{\"platform\": \"macos\", \"control_level\": {}, \"target_matches_host\": {}, \"required_primitives_present\": {}, \"beta_containment\": {}, \"proof_verification_enabled\": {}, \"vm_isolation_primitives_present\": {}, \"egress_control_primitives_present\": {}, \"telemetry_primitives_present\": {}, \"hypervisor_framework_available\": {}, \"virtualization_framework_available\": {}, \"endpointsecurity_framework_available\": {}, \"network_extension_framework_available\": {}, \"sandbox_exec_available\": {}, \"pfctl_available\": {}, \"reason_codes\": {}}}",
                json_string(readiness.control_level.label()),
                json_option(readiness.target_matches_host),
                readiness.required_primitives_present,
                readiness.beta_containment,
                readiness.proof_verification_enabled,
                readiness.vm_isolation_primitives_present,
                readiness.egress_control_primitives_present,
                readiness.telemetry_primitives_present,
                readiness.hypervisor_framework_available,
                readiness.virtualization_framework_available,
                readiness.endpointsecurity_framework_available,
                readiness.network_extension_framework_available,
                readiness.sandbox_exec_available,
                readiness.pfctl_available,
                json_string_array(&readiness.reason_codes)
            ),
            render_verification_plan_json(&plan),
            "null".to_string(),
        )
    };
    format!(
        "    {{\n      \"provider\": {},\n      \"provider_id\": {},\n      \"platform\": {},\n      \"containment\": {{\"status\": {}, \"reason\": {}, \"mechanism\": {}, \"trust\": {}, \"evidence_count\": {}}},\n      \"egress\": {{\"status\": {}, \"reason\": {}, \"mechanism\": {}, \"trust\": {}, \"evidence_count\": {}}},\n      \"challenge\": {},\n      \"challenge_attempt\": {},\n      \"posture\": {},\n      \"readiness\": {readiness},\n      \"verification_plan\": {verification_plan},\n      \"active_probe_receipt\": {active_probe_receipt},\n      \"evidence\": {{\"containment\": {}, \"egress\": {}}}\n    }}",
        json_string(label),
        json_string(&redacted_scalar(&containment_provenance.provider_id)),
        json_string(&redacted_scalar(&containment_provenance.platform)),
        json_string(&format!("{:?}", containment.status())),
        json_string(containment.reason_code()),
        json_string(&format!("{:?}", containment_provenance.mechanism)),
        json_string(&format!("{:?}", containment_provenance.trust)),
        containment_provenance.evidence.len(),
        json_string(&format!("{:?}", egress.status())),
        json_string(egress.reason_code()),
        json_string(&format!("{:?}", egress_provenance.mechanism)),
        json_string(&format!("{:?}", egress_provenance.trust)),
        egress_provenance.evidence.len(),
        render_provider_challenge_json(&challenge),
        render_provider_challenge_attempt_json(&challenge_attempt),
        render_provider_posture_json(&containment_provenance.evidence),
        json_string_array(&containment_evidence),
        json_string_array(&egress_evidence)
    )
}

fn diagnostic_provider_challenge(label: &str) -> ProviderVerificationChallenge {
    ProviderVerificationChallenge::new(
        ProofSubject::for_launch(format!("{label}-diagnostic")),
        format!("sha256:diagnostic-{label}"),
        "127.0.0.1:4873",
        1,
    )
}

fn render_provider_challenge_attempt_text(
    label: &str,
    attempt: &ProviderChallengeAttempt,
) -> String {
    format!(
        "provider_challenge provider={} challenge_id={} subject={} context_hash={} configured_vault_host={} probe_count={} containment_status={:?} egress_status={:?} satisfied={} reason_codes={:?}",
        label,
        redacted_scalar(&attempt.challenge_id),
        redacted_scalar(&attempt.subject.launch_id),
        redacted_scalar(&attempt.context_hash),
        redacted_scalar(&attempt.configured_vault_host),
        attempt.probe_destination_count,
        attempt.containment_status,
        attempt.egress_status,
        attempt.challenge_satisfied,
        attempt.reason_codes
    )
}

fn render_provider_posture_text(label: &str, evidence: &[String]) -> String {
    let posture = local_provider_evidence_posture_from_evidence(evidence);
    format!(
        "provider_posture provider={} schema_version={} status={} verdict={} host_platform={} target_platform={} target_matches_host={} active_verification_enabled={} package_execution_attempted={} os_mutation_attempted={} network_mutation_attempted={} public_network_probe_attempted={}",
        label,
        redacted_option_scalar(posture.schema_version.as_deref()),
        redacted_option_scalar(posture.status.as_deref()),
        redacted_option_scalar(posture.verdict.as_deref()),
        redacted_option_scalar(posture.host_platform.as_deref()),
        redacted_option_scalar(posture.target_platform.as_deref()),
        option_bool_text(posture.target_matches_host),
        option_bool_text(posture.active_verification_enabled),
        option_bool_text(posture.package_execution_attempted),
        option_bool_text(posture.os_mutation_attempted),
        option_bool_text(posture.network_mutation_attempted),
        option_bool_text(posture.public_network_probe_attempted)
    )
}

fn render_provider_posture_json(evidence: &[String]) -> String {
    let posture = local_provider_evidence_posture_from_evidence(evidence);
    format!(
        "{{\"schema_version\": {}, \"status\": {}, \"verdict\": {}, \"host_platform\": {}, \"target_platform\": {}, \"target_matches_host\": {}, \"active_verification_enabled\": {}, \"package_execution_attempted\": {}, \"os_mutation_attempted\": {}, \"network_mutation_attempted\": {}, \"public_network_probe_attempted\": {}}}",
        json_option_string(posture.schema_version.as_deref()),
        json_option_string(posture.status.as_deref()),
        json_option_string(posture.verdict.as_deref()),
        json_option_string(posture.host_platform.as_deref()),
        json_option_string(posture.target_platform.as_deref()),
        json_option(posture.target_matches_host),
        json_option(posture.active_verification_enabled),
        json_option(posture.package_execution_attempted),
        json_option(posture.os_mutation_attempted),
        json_option(posture.network_mutation_attempted),
        json_option(posture.public_network_probe_attempted)
    )
}

fn combined_proof_evidence(containment: &[String], egress: &[String]) -> Vec<String> {
    let mut evidence = Vec::with_capacity(containment.len() + egress.len());
    evidence.extend(containment.iter().cloned());
    evidence.extend(egress.iter().cloned());
    evidence
}

fn render_linux_active_probe_receipt_text(receipt: &LinuxActiveProbeReceipt) -> String {
    format!(
        "provider_active_probe provider=linux schema_version={} status={} target_matches_host={} satisfied={} user_namespace_uid={} user_namespace_gid={} user_namespace_uid_map={} user_namespace_gid_map={} nested_user_namespace_attempt={} nested_user_namespace_created={} allowed_probe_count={} denied_probe_count={} missing_probe_count={} allowed_non_vault_probe_count={} package_execution_attempted={} public_network_probe_attempted={} os_mutation_scope={} network_mutation_scope={} reason_codes={:?}",
        redacted_option_scalar(receipt.schema_version.as_deref()),
        redacted_option_scalar(receipt.status.as_deref()),
        option_bool_text(receipt.target_matches_host),
        receipt.satisfied,
        redacted_option_scalar(receipt.user_namespace_uid.as_deref()),
        redacted_option_scalar(receipt.user_namespace_gid.as_deref()),
        redacted_option_scalar(receipt.user_namespace_uid_map.as_deref()),
        redacted_option_scalar(receipt.user_namespace_gid_map.as_deref()),
        redacted_option_scalar(receipt.nested_user_namespace_attempt.as_deref()),
        option_bool_text(receipt.nested_user_namespace_created),
        receipt.allowed_destinations.len(),
        receipt.denied_destinations.len(),
        receipt.missing_probe_destinations.len(),
        receipt.allowed_non_vault_destinations.len(),
        option_bool_text(receipt.package_execution_attempted),
        option_bool_text(receipt.public_network_probe_attempted),
        redacted_option_scalar(receipt.os_mutation_scope.as_deref()),
        redacted_option_scalar(receipt.network_mutation_scope.as_deref()),
        receipt.reason_codes
    )
}

fn render_linux_active_probe_receipt_json(receipt: &LinuxActiveProbeReceipt) -> String {
    format!(
        "{{\"schema_version\": {}, \"status\": {}, \"target_matches_host\": {}, \"satisfied\": {}, \"challenge_id\": {}, \"subject\": {}, \"context_hash\": {}, \"configured_vault_host\": {}, \"user_namespace_isolated\": {}, \"user_namespace_uid\": {}, \"user_namespace_gid\": {}, \"user_namespace_uid_map\": {}, \"user_namespace_gid_map\": {}, \"nested_user_namespace_attempt\": {}, \"nested_user_namespace_created\": {}, \"nested_user_namespace_uid_map\": {}, \"nested_user_namespace_gid_map\": {}, \"network_namespace_isolated\": {}, \"no_new_privs\": {}, \"seccomp_filter_enforced\": {}, \"cgroup_scoped\": {}, \"default_deny_except_configured_vault\": {}, \"package_execution_attempted\": {}, \"public_network_probe_attempted\": {}, \"os_mutation_scope\": {}, \"network_mutation_scope\": {}, \"allowed_probe_count\": {}, \"denied_probe_count\": {}, \"allowed_probe_destinations\": {}, \"denied_probe_destinations\": {}, \"missing_probe_destinations\": {}, \"allowed_non_vault_destinations\": {}, \"reason_codes\": {}}}",
        json_option_string(receipt.schema_version.as_deref()),
        json_option_string(receipt.status.as_deref()),
        json_option(receipt.target_matches_host),
        receipt.satisfied,
        json_option_string(receipt.challenge_id.as_deref()),
        json_option_string(receipt.subject.as_deref()),
        json_option_string(receipt.context_hash.as_deref()),
        json_option_string(receipt.configured_vault_host.as_deref()),
        json_option(receipt.user_namespace_isolated),
        json_option_string(receipt.user_namespace_uid.as_deref()),
        json_option_string(receipt.user_namespace_gid.as_deref()),
        json_option_string(receipt.user_namespace_uid_map.as_deref()),
        json_option_string(receipt.user_namespace_gid_map.as_deref()),
        json_option_string(receipt.nested_user_namespace_attempt.as_deref()),
        json_option(receipt.nested_user_namespace_created),
        json_option_string(receipt.nested_user_namespace_uid_map.as_deref()),
        json_option_string(receipt.nested_user_namespace_gid_map.as_deref()),
        json_option(receipt.network_namespace_isolated),
        json_option(receipt.no_new_privs),
        json_option(receipt.seccomp_filter_enforced),
        json_option(receipt.cgroup_scoped),
        json_option(receipt.default_deny_except_configured_vault),
        json_option(receipt.package_execution_attempted),
        json_option(receipt.public_network_probe_attempted),
        json_option_string(receipt.os_mutation_scope.as_deref()),
        json_option_string(receipt.network_mutation_scope.as_deref()),
        receipt.allowed_destinations.len(),
        receipt.denied_destinations.len(),
        json_string_array(&receipt.allowed_destinations),
        json_string_array(&receipt.denied_destinations),
        json_string_array(&receipt.missing_probe_destinations),
        json_string_array(&receipt.allowed_non_vault_destinations),
        json_string_array(&receipt.reason_codes)
    )
}

fn render_provider_challenge_json(challenge: &ProviderVerificationChallenge) -> String {
    let reason_codes = challenge
        .reason_codes()
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
    format!(
        "{{\"challenge_id\": {}, \"subject\": {}, \"context_hash\": {}, \"configured_vault_host\": {}, \"probe_destination_count\": {}, \"probe_destinations\": {}, \"expires_at_unix_seconds\": {}, \"nonce_present\": {}, \"valid\": {}, \"reason_codes\": {}}}",
        json_string(&redacted_scalar(&challenge.challenge_id)),
        json_string(&redacted_scalar(&challenge.subject.launch_id)),
        json_string(&redacted_scalar(&challenge.context_hash)),
        json_string(&redacted_scalar(&challenge.configured_vault_host)),
        challenge.probe_destinations.len(),
        json_string_array(&challenge.probe_destinations),
        challenge.expires_at_unix_seconds,
        !challenge.challenge_nonce.is_empty(),
        challenge.valid(),
        json_string_array(&reason_codes)
    )
}

fn render_provider_challenge_attempt_json(attempt: &ProviderChallengeAttempt) -> String {
    format!(
        "{{\"challenge_id\": {}, \"provider_id\": {}, \"subject\": {}, \"context_hash\": {}, \"configured_vault_host\": {}, \"probe_destination_count\": {}, \"containment_status\": {}, \"egress_status\": {}, \"satisfied\": {}, \"reason_codes\": {}}}",
        json_string(&redacted_scalar(&attempt.challenge_id)),
        json_string(&redacted_scalar(&attempt.provider_id)),
        json_string(&redacted_scalar(&attempt.subject.launch_id)),
        json_string(&redacted_scalar(&attempt.context_hash)),
        json_string(&redacted_scalar(&attempt.configured_vault_host)),
        attempt.probe_destination_count,
        json_string(&format!("{:?}", attempt.containment_status)),
        json_string(&format!("{:?}", attempt.egress_status)),
        attempt.challenge_satisfied,
        json_string_array(&attempt.reason_codes)
    )
}

fn render_verification_plan_json(plan: &LocalVerificationPlan) -> String {
    format!(
        "{{\"platform\": {}, \"enforcement_strategy\": {}, \"control_level\": {}, \"prerequisites_present\": {}, \"proof_verification_enabled\": {}, \"can_verify_now\": {}, \"required_checks\": {}, \"blocking_reason_codes\": {}}}",
        json_string(plan.platform),
        json_string(plan.enforcement_strategy),
        json_string(plan.control_level.label()),
        plan.prerequisites_present,
        plan.proof_verification_enabled,
        plan.can_verify_now,
        json_string_array(&plan.required_checks),
        json_string_array(&plan.blocking_reason_codes)
    )
}

fn json_option<T: std::fmt::Display>(value: Option<T>) -> String {
    value
        .map(|inner| inner.to_string())
        .unwrap_or_else(|| "null".to_string())
}

fn json_option_string(value: Option<&str>) -> String {
    value.map(json_string).unwrap_or_else(|| "null".to_string())
}

fn json_option_string_redacted(value: Option<&str>) -> String {
    value
        .map(redacted_scalar)
        .map(|value| json_string(&value))
        .unwrap_or_else(|| "null".to_string())
}

fn json_string_array(values: &[String]) -> String {
    let elements = values
        .iter()
        .map(|value| json_string(value))
        .collect::<Vec<_>>()
        .join(", ");
    format!("[{elements}]")
}

fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len() + 2);
    escaped.push('"');
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }
    }
    escaped.push('"');
    escaped
}

fn render_vault_simulation(complete: bool) -> String {
    let mut controller = AdmissionController::new();
    let request = AdmissionRequest {
        request_id: "sim-1".to_string(),
        tenant_id: "tenant-local".to_string(),
        policy_version: "policy-local".to_string(),
        artifact: ArtifactRef {
            ecosystem: "npm".to_string(),
            name: "fixture".to_string(),
            version: "1.0.0".to_string(),
            digest: "sha256:b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f"
                .to_string(),
            source: "local-fixture".to_string(),
        },
    };
    if let Err(error) = controller.request(request.clone()) {
        return format!(
            "whoathere vault simulate\nstatus=fail_closed\nreason_code={}\npromoted=false\nretryable={}",
            error.reason_code, error.retryable
        );
    }
    if complete {
        let mut store = InMemoryCacheStore::new();
        let receipt = match store.quarantine(
            request.artifact.clone(),
            b"inert cache fixture bytes".to_vec(),
        ) {
            Ok(receipt) => receipt,
            Err(error) => {
                return format!(
                    "whoathere vault simulate\nstatus=fail_closed\nreason_code={}\npromoted=false\nretryable=false",
                    error.reason_code()
                );
            }
        };
        let plan = plan_fetch_job(FetchJobRequest {
            job_id: "fetch-sim-1".to_string(),
            tenant_id: request.tenant_id.clone(),
            admission_request_id: request.request_id.clone(),
            artifact: request.artifact.clone(),
            source_url: "https://registry.example/fixture.tgz".to_string(),
            expected_digest: request.artifact.digest.clone(),
            byte_limit: 10_485_760,
        });
        let binding = bind_fetch_job_result(
            &plan,
            FetchJobResult {
                job_id: plan.job_id.clone(),
                tenant_id: plan.tenant_id.clone(),
                admission_request_id: plan.admission_request_id.clone(),
                artifact: plan.artifact.clone(),
                source_url: plan.source_url.clone(),
                expected_digest: plan.expected_digest.clone(),
                verified_digest: plan.expected_digest.clone(),
                cache_object_key: receipt.cache_object_key.clone(),
                byte_len: receipt.byte_len as u64,
                byte_limit: plan.byte_limit,
                quarantine_id: receipt.quarantine_id,
                fetch_enabled: plan.fetch_enabled,
                network_attempted: plan.network_attempted,
                stored_in_quarantine: true,
                audit_event_id: "audit-fetch-sim-1".to_string(),
            },
        );
        if let Err(error) = controller.attach_fetch_result("sim-1", binding) {
            return format!(
                "whoathere vault simulate\nstatus=fail_closed\nreason_code={}\npromoted=false\nretryable={}",
                error.reason_code, error.retryable
            );
        }
    }
    let profile = minimum_profiles()
        .into_iter()
        .find(|profile| profile.id == "npm.registry_tarball.v1")
        .expect("minimum profile must exist");
    let evidence = simulation_evidence_bundle(&profile, &request.artifact, complete);
    match controller.decide("sim-1", &profile, evidence) {
        Ok(verdict) => {
            let generation = controller.servable(&request.tenant_id, &request.artifact);
            let fetch_job_id = generation
                .map(|generation| generation.fetch_job_id.as_str())
                .unwrap_or_default();
            let cache_object_key = generation
                .map(|generation| generation.cache_object_key.as_str())
                .unwrap_or_default();
            format!(
                "whoathere vault simulate\nstatus=ok\nverdict={verdict:?}\npromoted={}\ncache_object_key={cache_object_key}\nfetch_job_id={fetch_job_id}",
                generation.is_some()
            )
        }
        Err(error) => format!(
            "whoathere vault simulate\nstatus=fail_closed\nreason_code={}\npromoted=false\nretryable={}",
            error.reason_code, error.retryable
        ),
    }
}

fn render_vault_challenge_sim(
    replay: bool,
    unknown_challenge: bool,
    mutate_context: bool,
    expired: bool,
) -> String {
    let mut body = vec![
        "subject=vault-challenge-cli-sim".to_string(),
        "context_hash=sha256:1111111111111111111111111111111111111111111111111111111111111111"
            .to_string(),
        "vault_host=127.0.0.1:4873".to_string(),
    ];
    if replay {
        body.push("replay=true".to_string());
    }
    if unknown_challenge {
        body.push("unknown_challenge=true".to_string());
    }
    if mutate_context {
        body.push("mutate_context=true".to_string());
    }
    if expired {
        body.push("expired=true".to_string());
    }
    let body = body.join("&");
    let request = format!(
        "POST /v1/challenge-authority-simulations HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\n\r\n{}",
        body.len(),
        body
    );
    let response = handle_http_request(&request);
    let exit_code = if response.status_code == 200 { 0 } else { 20 };
    format!(
        "whoathere vault challenge-sim\nmode=local_dev\nstatus_code={}\nexit_code={exit_code}\n{}",
        response.status_code,
        to_http_wire(&response)
    )
}

fn simulation_evidence_bundle(
    profile: &EvidenceProfile,
    artifact: &ArtifactRef,
    complete: bool,
) -> EvidenceBundle {
    let selected = if complete {
        profile.requirements.as_slice()
    } else {
        &profile.requirements[..1]
    };
    let results = selected
        .iter()
        .enumerate()
        .map(|(index, requirement)| EvidenceJobResult {
            job_id: format!("evidence-sim-job-{index}"),
            job_kind: requirement.job_kind,
            state: JobState::Passed,
            log_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            reason_codes: vec![],
        })
        .collect::<Vec<_>>();
    let cache_object_key = artifact.cache_object_key().unwrap_or_default();
    let job_bindings = results
        .iter()
        .map(|result| EvidenceJobBinding {
            job_id: result.job_id.clone(),
            job_kind: result.job_kind,
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            artifact_digest: artifact.digest.clone(),
            cache_object_key: cache_object_key.clone(),
            log_digest: result.log_digest.clone(),
            admission_ready: true,
        })
        .collect();
    EvidenceBundle {
        profile_id: profile.id.to_string(),
        profile_version: profile.version,
        artifact_digest: artifact.digest.clone(),
        cache_object_key,
        results,
        job_bindings,
    }
}

fn render_vault_dev_http(
    method: &str,
    path: &str,
    headers: &[String],
    body: Option<String>,
) -> String {
    if validate_loopback_bind("127.0.0.1:0").is_err() {
        return "whoathere vault dev-http\nstatus=error\nreason_code=loopback_validation_failed"
            .to_string();
    }
    let mut rendered_headers = String::new();
    for header in headers {
        if let Err(reason_code) = validate_dev_http_header(header) {
            return format!(
                "whoathere vault dev-http\nmode=local_dev\nstatus=fail_closed\nreason_code={reason_code}"
            );
        }
        rendered_headers.push_str(header);
        rendered_headers.push_str("\r\n");
    }
    let body = body.unwrap_or_default();
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n{}Content-Length: {}\r\n\r\n{}",
        rendered_headers,
        body.len(),
        body
    );
    let response = handle_http_request(&request);
    format!(
        "whoathere vault dev-http\nmode=local_dev\nstatus_code={}\n{}",
        response.status_code,
        to_http_wire(&response)
    )
}

fn validate_dev_http_header(header: &str) -> Result<(), &'static str> {
    if header.contains('\r') || header.contains('\n') {
        return Err("dev_http_header_contains_control_line_break");
    }
    let Some((name, value)) = header.split_once(':') else {
        return Err("dev_http_header_missing_colon");
    };
    let name = name.trim();
    if name.is_empty() || value.trim().is_empty() {
        return Err("dev_http_header_empty_name_or_value");
    }
    if !name
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    {
        return Err("dev_http_header_name_invalid");
    }
    if name.eq_ignore_ascii_case("host") || name.eq_ignore_ascii_case("content-length") {
        return Err("dev_http_header_reserved");
    }
    Ok(())
}

fn render_vault_dev_serve(bind: &str, max_requests: usize, idle_timeout_ms: u64) -> String {
    match serve_loopback_http(
        bind,
        max_requests,
        std::time::Duration::from_millis(idle_timeout_ms),
    ) {
        Ok(summary) => {
            let mut output = format!(
                "whoathere vault dev-serve\nmode=local_dev\nstatus=ok\nbind_addr={}\nserved_requests={}\nmax_requests={}\nidle_timeout_ms={}\nrequest_log_count={}",
                summary.bind_addr,
                summary.served_requests,
                summary.max_requests,
                summary.idle_timeout_ms,
                summary.request_logs.len()
            );
            for (index, log_entry) in summary.request_logs.iter().enumerate() {
                output.push('\n');
                output.push_str(&render_dev_server_request_log(index, log_entry));
            }
            output
        }
        Err(error) => format!(
            "whoathere vault dev-serve\nmode=local_dev\nstatus=fail_closed\nreason_code={}\nserved_requests=0",
            error.reason_code()
        ),
    }
}

fn render_dev_server_request_log(index: usize, log_entry: &SanitizedRequestLogEntry) -> String {
    format!(
        "request_log[{index}].method={}\nrequest_log[{index}].route_kind={}\nrequest_log[{index}].status_code={}\nrequest_log[{index}].range_state={}\nrequest_log[{index}].declared_response_body_bytes={}\nrequest_log[{index}].wire_response_body_bytes={}\nrequest_log[{index}].request_body_logged={}\nrequest_log[{index}].response_body_logged={}",
        log_entry.method,
        log_entry.route_kind,
        log_entry.status_code,
        log_entry.range_state,
        log_entry.declared_response_body_bytes,
        log_entry.wire_response_body_bytes,
        log_entry.request_body_logged,
        log_entry.response_body_logged
    )
}

fn default_decision(classification: &CommandClassification) -> PolicyDecision {
    if classification.risk == WorkflowRisk::Low {
        return PolicyDecision::Allow;
    }
    if classification.protected {
        outage_decision(ExecutionMode::CiFailClosed, OutageBehavior::Block, false)
    } else {
        PolicyDecision::Deny
    }
}

fn decision_label(decision: PolicyDecision) -> &'static str {
    match decision {
        PolicyDecision::Allow => "allow",
        PolicyDecision::Deny => "deny",
        PolicyDecision::Quarantine => "quarantine",
        PolicyDecision::ManualReview => "manual_review",
        PolicyDecision::BreakGlassRequired => "break_glass_required",
    }
}

fn decision_exit_code(decision: PolicyDecision) -> ExitCode {
    match decision {
        PolicyDecision::Allow => ExitCode::Allow,
        PolicyDecision::Deny => ExitCode::Deny,
        PolicyDecision::Quarantine => ExitCode::Quarantine,
        PolicyDecision::ManualReview | PolicyDecision::BreakGlassRequired => ExitCode::ManualReview,
    }
}

fn redacted_args(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut redact_next = false;
    for arg in args {
        let sensitive_current = sensitive_key_like(arg);
        if redact_next {
            redacted.push("[REDACTED]".to_string());
        } else {
            redacted.push(redacted_scalar(arg));
        }
        redact_next = sensitive_current && !arg.contains('=');
    }
    redacted
}

fn redacted_scalar(value: &str) -> String {
    let (redacted, _) = redact_token_like(value);
    redacted
}

fn redacted_option_scalar(value: Option<&str>) -> String {
    value
        .map(redacted_scalar)
        .unwrap_or_else(|| "missing".to_string())
}

fn option_bool_text(value: Option<bool>) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "missing",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dry_run_shim() {
        let args = vec![
            "shim".to_string(),
            "install".to_string(),
            "--dry-run".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::ShimInstall {
                dry_run: true,
                dest: None,
                include_python: false
            }
        );
    }

    #[test]
    fn parses_doctor_state_dir_and_helper() {
        let args = vec![
            "doctor".to_string(),
            "--json".to_string(),
            "--state-dir".to_string(),
            "/tmp/whoathere-vm".to_string(),
            "--helper".to_string(),
            "/tmp/helper".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::Doctor {
                json: true,
                state_dir: Some("/tmp/whoathere-vm".to_string()),
                helper_path: Some("/tmp/helper".to_string()),
            }
        );
    }

    #[test]
    fn parses_vm_status_command() {
        let args = vec![
            "vm".to_string(),
            "status".to_string(),
            "--state-dir".to_string(),
            "/tmp/whoathere-vm".to_string(),
            "--manifest".to_string(),
            "/tmp/whoathere-vm/image.manifest".to_string(),
            "--json".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::VmStatus {
                state_dir: Some("/tmp/whoathere-vm".to_string()),
                manifest_path: Some("/tmp/whoathere-vm/image.manifest".to_string()),
                helper_path: None,
                json: true
            }
        );
    }

    #[test]
    fn parses_vm_health_command() {
        let args = vec![
            "vm".to_string(),
            "health".to_string(),
            "--state-dir".to_string(),
            "/tmp/whoathere-vm".to_string(),
            "--helper".to_string(),
            "/tmp/helper".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::VmAction {
                action: VmAction::Health,
                state_dir: Some("/tmp/whoathere-vm".to_string()),
                helper_path: Some("/tmp/helper".to_string()),
                execute: false
            }
        );
    }

    #[test]
    fn vm_status_reports_release_contract_without_authorizing_runtime() {
        let result = evaluate_command(Command::VmStatus {
            state_dir: Some("/tmp/whoathere-vm-status-test".to_string()),
            manifest_path: None,
            helper_path: None,
            json: false,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result
            .output
            .contains("release_target=macos_apple_silicon_local_vm"));
        assert!(result
            .output
            .contains("vm_boundary=apple_virtualization_macos_guest"));
        assert!(result.output.contains("network_model=recorded_egress"));
        assert!(result
            .output
            .contains("sync_policy=sync_back_disabled_preview"));
        assert!(result.output.contains("ready=false"));
        assert!(result.output.contains("macos_vm_runtime_not_verified"));
    }

    #[test]
    fn vm_status_loads_default_state_dir_manifest() {
        let root = temp_root("whoathere-cli-vm-status-default-manifest");
        let state_dir = root.join("state");
        let bundle_dir = state_dir.join("bundle");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&bundle_dir).expect("bundle dir");
        std::fs::write(
            bundle_dir.join("image.manifest"),
            "schema_version=whoathere.macos_vm_image.v1\nimage_id=local-restore-image-install\nmacos_version=26.5.1\nmacos_build_version=25F80\narchitecture=arm64\nrestore_image_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\ncpu_count=2\nmemory_mib=6144\nsignature_status=signature_verification_not_implemented\nhelper_version=0.1.0\n",
        )
        .expect("manifest");

        let result = evaluate_command(Command::VmStatus {
            state_dir: Some(state_dir.display().to_string()),
            manifest_path: None,
            helper_path: None,
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("manifest_present=true"));
        assert!(result.output.contains(&format!(
            "manifest_path={}",
            bundle_dir.join("image.manifest").display()
        )));
        assert!(result
            .output
            .contains("macos_vm_manifest_signature_not_verified"));
        assert!(!result.output.contains("macos_vm_image_manifest_missing"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_init_execute_requires_real_helper() {
        let root = temp_root("whoathere-cli-vm-init");
        let _ = std::fs::remove_dir_all(&root);
        let result = evaluate_command(Command::VmInit {
            state_dir: Some(root.display().to_string()),
            manifest_path: None,
            helper_path: None,
            image_path: None,
            restore_image_path: None,
            fetch_latest_restore_image: false,
            memory_mib: Some(6144),
            disk_gib: Some(64),
            execute: true,
        });
        assert_eq!(result.exit_code, 64);
        assert!(result.output.contains("mutation=true"));
        assert!(result.output.contains("direct_cli_state_mutation=false"));
        assert!(result.output.contains("helper_required_for_execute=true"));
        assert!(result
            .output
            .contains("macos_vm_helper_path_not_configured"));
        assert!(!root.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_runtime_actions_remain_blocked_until_helper_exists() {
        let result = evaluate_command(Command::VmAction {
            action: VmAction::Start,
            state_dir: Some("/tmp/whoathere-vm-action".to_string()),
            helper_path: None,
            execute: true,
        });
        assert_eq!(result.exit_code, 64);
        assert!(result
            .output
            .contains("macos_vm_helper_path_not_configured"));
        assert!(result.output.contains("mutation_requested=true"));
        assert!(result.output.contains("mutation=false"));
    }

    #[test]
    fn vm_status_invokes_configured_helper_without_authorizing_runtime() {
        let root = temp_root("whoathere-cli-vm-helper");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf '{\"status\":\"fail_closed\",\"exit_code\":20,\"reason_codes\":[\"fixture_bundle_missing\"]}\\n'\nexit 20\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let result = evaluate_command(Command::VmStatus {
            state_dir: Some(root.join("state").display().to_string()),
            manifest_path: None,
            helper_path: Some(helper.display().to_string()),
            json: false,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("helper_available=true"));
        assert!(result.output.contains("helper_exit_code=20"));
        assert!(result.output.contains("fixture_bundle_missing"));
        assert!(result.output.contains("ready=false"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_init_dry_run_forwards_state_dir_to_helper() {
        let root = temp_root("whoathere-cli-vm-init-helper");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'args='\nfor arg in \"$@\"; do printf '<%s>' \"$arg\"; done\nprintf '\\n'\nexit 0\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let state_dir = root.join("state");
        let result = evaluate_command(Command::VmInit {
            state_dir: Some(state_dir.display().to_string()),
            manifest_path: None,
            helper_path: Some(helper.display().to_string()),
            image_path: None,
            restore_image_path: None,
            fetch_latest_restore_image: false,
            memory_mib: Some(4096),
            disk_gib: Some(64),
            execute: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("helper_available=true"));
        assert!(result.output.contains(&format!(
            "<init><--state-dir><{}><--memory-mib><4096><--disk-gib><64><--json>",
            state_dir.display()
        )));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_init_execute_forwards_latest_restore_image_fetch_flag() {
        let root = temp_root("whoathere-cli-vm-init-latest-helper");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'args='\nfor arg in \"$@\"; do printf '<%s>' \"$arg\"; done\nprintf '\\n'\nexit 20\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let state_dir = root.join("state");
        let result = evaluate_command(Command::VmInit {
            state_dir: Some(state_dir.display().to_string()),
            manifest_path: None,
            helper_path: Some(helper.display().to_string()),
            image_path: None,
            restore_image_path: None,
            fetch_latest_restore_image: true,
            memory_mib: Some(4096),
            disk_gib: Some(64),
            execute: true,
        });

        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("fetch_latest_restore_image=true"));
        assert!(result.output.contains(&format!(
            "<init><--state-dir><{}><--memory-mib><4096><--disk-gib><64><--execute><--json><--fetch-latest-restore-image>",
            state_dir.display()
        )));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_health_invokes_helper_without_execute() {
        let root = temp_root("whoathere-cli-vm-health-helper");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'args='\nfor arg in \"$@\"; do printf '<%s>' \"$arg\"; done\nprintf '\\n'\nexit 20\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let state_dir = root.join("state");
        let result = evaluate_command(Command::VmAction {
            action: VmAction::Health,
            state_dir: Some(state_dir.display().to_string()),
            helper_path: Some(helper.display().to_string()),
            execute: false,
        });

        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("mutation=false"));
        assert!(result.output.contains(&format!(
            "<health><--state-dir><{}><--json>",
            state_dir.display()
        )));
        assert!(!result.output.contains("<--execute>"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parses_vm_detonate_command() {
        let args = vec![
            "vm".to_string(),
            "detonate".to_string(),
            "--workspace".to_string(),
            "/work".to_string(),
            "--state-dir=/tmp/whoathere-vm".to_string(),
            "--helper".to_string(),
            "/tmp/helper".to_string(),
            "--fixture=clean_npm_lifecycle".to_string(),
            "--timeout-seconds".to_string(),
            "45".to_string(),
            "--execute".to_string(),
            "--json".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::VmDetonate {
                tool: "npm".to_string(),
                args: vec!["ci".to_string()],
                execute: true,
                state_dir: Some("/tmp/whoathere-vm".to_string()),
                helper_path: Some("/tmp/helper".to_string()),
                workspace: Some("/work".to_string()),
                fixture: Some("clean_npm_lifecycle".to_string()),
                timeout_seconds: Some(45),
                json: true,
            }
        );
    }

    #[test]
    fn vm_detonate_dry_run_never_invokes_helper_or_syncs() {
        let root = temp_root("whoathere-cli-vm-detonate-dry-run");
        std::fs::write(root.join("package.json"), r#"{"name":"clean"}"#).expect("package json");
        std::fs::write(root.join(".env"), "TOKEN=real-secret").expect("env");
        let result = evaluate_command(Command::VmDetonate {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: false,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some("/tmp/nonexistent-helper".to_string()),
            workspace: Some(root.display().to_string()),
            fixture: Some("clean_npm_lifecycle".to_string()),
            timeout_seconds: Some(30),
            json: false,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("sync_back_enabled=false"));
        assert!(result
            .output
            .contains("host_package_execution_enabled=false"));
        assert!(result
            .output
            .contains("high_risk_package_execution_enabled=false"));
        assert!(result
            .output
            .contains("command_class=npm_install_detonation"));
        assert!(result.output.contains("mirror_allowed_file_count=1"));
        assert!(result.output.contains("npm_manifest"));
        assert!(result.output.contains("mirror_secret_exclusion_count=1"));
        assert!(result.output.contains("verdict=dry_run_execute_required"));
        assert!(result.output.contains("helper_invoked=false"));
        assert!(!result.output.contains("real-secret"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_execute_forwards_bounded_job_to_helper() {
        let root = temp_root("whoathere-cli-vm-detonate-helper");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'args='\nfor arg in \"$@\"; do printf '<%s>' \"$arg\"; done\nprintf '\\n'\nexit 20\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");
        let state_dir = root.join("state");
        let result = evaluate_command(Command::VmDetonate {
            tool: "pip".to_string(),
            args: vec![
                "install".to_string(),
                "-r".to_string(),
                "requirements.txt".to_string(),
            ],
            execute: true,
            state_dir: Some(state_dir.display().to_string()),
            helper_path: Some(helper.display().to_string()),
            workspace: None,
            fixture: Some("pypi_pep517_canary".to_string()),
            timeout_seconds: Some(75),
            json: false,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("mutation_requested=true"));
        assert!(result
            .output
            .contains("command_class=pip_install_detonation"));
        assert!(result.output.contains(&format!(
            "<detonate><--state-dir><{}><--tool><pip><--command-class><pip_install_detonation><--timeout-seconds><75><--execute><--json><--fixture><pypi_pep517_canary><--><install><-r><requirements.txt>",
            state_dir.display()
        )));
        assert!(result.output.contains("verdict=helper_security_outcome"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_project_dry_run_plans_safe_pip_project() {
        let root = temp_root("whoathere-cli-vm-project-dry-run");
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='whoathere-clean', version='0.0.1', py_modules=['whoathere_clean'])\n",
        )
        .expect("setup py");
        std::fs::write(root.join("whoathere_clean.py"), "VALUE = 'clean'\n").expect("module");
        std::fs::write(root.join(".env"), "TOKEN=real-secret").expect("env");

        let result = evaluate_command(Command::VmDetonate {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), ".".to_string()],
            execute: false,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some("/tmp/nonexistent-helper".to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(30),
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("project_mode=true"));
        assert!(result
            .output
            .contains("project_workflow=pip_project_install"));
        assert!(result
            .output
            .contains("project_import_module=whoathere_clean"));
        assert!(result.output.contains("project_safe_to_execute=true"));
        assert!(result.output.contains("mirror_secret_exclusion_count=1"));
        assert!(!result.output.contains("real-secret"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_project_execute_forwards_payload_to_helper() {
        let root = temp_root("whoathere-cli-vm-project-helper");
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='whoathere-clean', version='0.0.1', py_modules=['whoathere_clean'])\n",
        )
        .expect("setup py");
        std::fs::write(root.join("whoathere_clean.py"), "VALUE = 'clean'\n").expect("module");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'args='\nfor arg in \"$@\"; do printf '<%s>' \"$arg\"; done\nprintf '\\n'\nexit 0\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");
        let state_dir = root.join("state");

        let result = evaluate_command(Command::VmDetonate {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), ".".to_string()],
            execute: true,
            state_dir: Some(state_dir.display().to_string()),
            helper_path: Some(helper.display().to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(75),
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("<--fixture><project_mirror>"));
        assert!(result.output.contains("<--project-payload-path>"));
        assert!(result
            .output
            .contains("<--project-workflow><pip_project_install>"));
        assert!(result
            .output
            .contains("<--project-import-module><whoathere_clean>"));
        assert!(result.output.contains("project_payload_path="));
        let payload_dir = state_dir.join("runs").join("project-payloads");
        let payload_count = std::fs::read_dir(payload_dir)
            .expect("payload dir")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".payload.hex")
            })
            .count();
        assert_eq!(payload_count, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_npm_project_dry_run_plans_safe_no_dependency_project() {
        let root = temp_root("whoathere-cli-vm-npm-project-dry-run");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"whoathere-clean-npm","version":"0.0.1","main":"index.js","scripts":{"postinstall":"node index.js"},"dependencies":{}}"#,
        )
        .expect("package json");
        std::fs::write(
            root.join("index.js"),
            "module.exports = { run() { return 'clean'; } };\n",
        )
        .expect("index js");
        std::fs::write(
            root.join(".npmrc"),
            "//registry.npmjs.org/:_authToken=real-secret",
        )
        .expect("npmrc");

        let result = evaluate_command(Command::VmDetonate {
            tool: "npm".to_string(),
            args: vec!["install".to_string()],
            execute: false,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some("/tmp/nonexistent-helper".to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(30),
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("project_mode=true"));
        assert!(result
            .output
            .contains("project_workflow=npm_project_install"));
        assert!(result.output.contains("project_safe_to_execute=true"));
        assert!(result.output.contains("npm_manifest"));
        assert!(result.output.contains("npm_source"));
        assert!(result.output.contains("mirror_secret_exclusion_count=1"));
        assert!(!result.output.contains("real-secret"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_npm_project_execute_forwards_payload_to_helper() {
        let root = temp_root("whoathere-cli-vm-npm-project-helper");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"whoathere-clean-npm","version":"0.0.1","main":"index.js","scripts":{"postinstall":"node index.js"}}"#,
        )
        .expect("package json");
        std::fs::write(
            root.join("index.js"),
            "module.exports = { run() { return 'clean'; } };\n",
        )
        .expect("index js");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'args='\nfor arg in \"$@\"; do printf '<%s>' \"$arg\"; done\nprintf '\\n'\nexit 0\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");
        let state_dir = root.join("state");

        let result = evaluate_command(Command::VmDetonate {
            tool: "npm".to_string(),
            args: vec!["install".to_string()],
            execute: true,
            state_dir: Some(state_dir.display().to_string()),
            helper_path: Some(helper.display().to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(75),
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("<--tool><npm>"));
        assert!(result.output.contains("<--fixture><project_mirror>"));
        assert!(result.output.contains("<--project-payload-path>"));
        assert!(result
            .output
            .contains("<--project-workflow><npm_project_install>"));
        assert!(!result.output.contains("<--project-import-module>"));
        let payload_dir = state_dir.join("runs").join("project-payloads");
        let payload_count = std::fs::read_dir(payload_dir)
            .expect("payload dir")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .ends_with(".payload.hex")
            })
            .count();
        assert_eq!(payload_count, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_npm_project_public_dependency_fails_before_helper() {
        let root = temp_root("whoathere-cli-vm-npm-project-public-dep");
        std::fs::write(
            root.join("package.json"),
            r#"{"name":"whoathere-risky-npm","version":"0.0.1","dependencies":{"left-pad":"^1.3.0"}}"#,
        )
        .expect("package json");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'helper should not run\\n'\nexit 0\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let result = evaluate_command(Command::VmDetonate {
            tool: "npm".to_string(),
            args: vec!["install".to_string()],
            execute: true,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some(helper.display().to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(75),
            json: false,
        });

        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("project_mode=true"));
        assert!(result.output.contains("project_safe_to_execute=false"));
        assert!(result
            .output
            .contains("project_npm_dependency_resolution_deferred"));
        assert!(result.output.contains("helper_invoked=false"));
        assert!(!result.output.contains("helper should not run"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_json_exposes_structured_guest_job_evidence() {
        let root = temp_root("whoathere-cli-vm-project-json-evidence");
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='whoathere-clean', version='0.0.1', py_modules=['whoathere_clean'])\n",
        )
        .expect("setup py");
        std::fs::write(root.join("whoathere_clean.py"), "VALUE = 'clean'\n").expect("module");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            br#"#!/bin/sh
cat <<'JSON'
{"protocol":"whoathere.guest_detonation.v1","schema_version":"whoathere.macos_vm.bundle.v1","agent_version":"0.2.0","job_id":"job-123","tool":"pip","command_class":"pip_install_detonation","fixture":"project_mirror","status":"ok","verdict":"allow_observed_clean","reason_codes":["token=supersecret"],"command_exit_code":0,"timed_out":false,"canary_access_detected":false,"network_attempt_detected":false,"filesystem_write_detected":false,"toolchain_available":true,"stdout_captured":false,"stderr_captured":false,"raw_canary_values_captured":false,"sync_back_enabled":false,"host_package_execution_enabled":false,"high_risk_package_execution_enabled":false,"project_mode":true,"project_workflow":"pip_project_install","project_import_module":"whoathere_clean","project_requirements_path":"none","vm_session_id":"session-123","exit_code":0}
JSON
exit 0
"#,
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let result = evaluate_command(Command::VmDetonate {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), ".".to_string()],
            execute: true,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some(helper.display().to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(75),
            json: true,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("\"guest_job\": {"));
        assert!(result
            .output
            .contains("\"protocol\": \"whoathere.guest_detonation.v1\""));
        assert!(result
            .output
            .contains("\"verdict\": \"allow_observed_clean\""));
        assert!(result
            .output
            .contains("\"project_workflow\": \"pip_project_install\""));
        assert!(result
            .output
            .contains("\"raw_canary_values_captured\": false"));
        assert!(result.output.contains("\"sync_back_enabled\": false"));
        assert!(result
            .output
            .contains("\"host_package_execution_enabled\": false"));
        assert!(!result.output.contains("supersecret"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_project_mirror_allows_narrow_package_data() {
        let root = temp_root("whoathere-cli-vm-project-package-data");
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='whoathere-clean', version='0.0.1', packages=['whoathere_pkg'])\n",
        )
        .expect("setup py");
        std::fs::create_dir_all(root.join("whoathere_pkg").join("data")).expect("data dir");
        std::fs::write(
            root.join("whoathere_pkg").join("__init__.py"),
            "VALUE = 'clean'\n",
        )
        .expect("init");
        std::fs::write(
            root.join("whoathere_pkg").join("data").join("schema.json"),
            r#"{"safe":true}"#,
        )
        .expect("schema");
        std::fs::write(root.join("README.md"), "root readme omitted\n").expect("readme");

        let result = evaluate_command(Command::VmDetonate {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), ".".to_string()],
            execute: false,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some("/tmp/nonexistent-helper".to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(30),
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("project_safe_to_execute=true"));
        assert!(result.output.contains("mirror_package_data_file_count=1"));
        assert!(result.output.contains("python_package_data"));
        assert!(result
            .output
            .contains("detonation_workspace_safe_package_data_included"));
        assert!(result.output.contains("whoathere_pkg/data/schema.json"));
        assert!(!result.output.contains("README.md"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_project_risky_package_files_fail_before_helper() {
        let root = temp_root("whoathere-cli-vm-project-risky-data");
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='whoathere-clean', version='0.0.1', packages=['whoathere_pkg'])\n",
        )
        .expect("setup py");
        std::fs::create_dir_all(root.join("whoathere_pkg")).expect("package dir");
        std::fs::write(
            root.join("whoathere_pkg").join("__init__.py"),
            "VALUE = 'clean'\n",
        )
        .expect("init");
        std::fs::write(root.join("whoathere_pkg").join("native.so"), "not real").expect("so");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'helper should not run\\n'\nexit 0\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let result = evaluate_command(Command::VmDetonate {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), ".".to_string()],
            execute: true,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some(helper.display().to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(75),
            json: false,
        });

        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("project_safe_to_execute=false"));
        assert!(result
            .output
            .contains("mirror_risky_file_exclusion_count=1"));
        assert!(result
            .output
            .contains("detonation_workspace_risky_file_excluded"));
        assert!(result
            .output
            .contains("project_risky_file_requires_manual_review"));
        assert!(result.output.contains("helper_invoked=false"));
        assert!(!result.output.contains("helper should not run"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonate_project_requirements_public_resolution_fails_before_helper() {
        let root = temp_root("whoathere-cli-vm-project-unsafe-requirements");
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='whoathere-clean', version='0.0.1', py_modules=['whoathere_clean'])\n",
        )
        .expect("setup py");
        std::fs::write(root.join("whoathere_clean.py"), "VALUE = 'clean'\n").expect("module");
        std::fs::write(root.join("requirements.txt"), "requests\n").expect("requirements");
        let helper = root.join("helper.sh");
        write_new_file(
            &helper,
            b"#!/bin/sh\nprintf 'helper should not run\\n'\nexit 0\n",
        )
        .expect("helper script");
        set_executable(&helper).expect("executable helper");

        let result = evaluate_command(Command::VmDetonate {
            tool: "pip".to_string(),
            args: vec![
                "install".to_string(),
                "-r".to_string(),
                "requirements.txt".to_string(),
            ],
            execute: true,
            state_dir: Some(root.join("state").display().to_string()),
            helper_path: Some(helper.display().to_string()),
            workspace: Some(root.display().to_string()),
            fixture: None,
            timeout_seconds: Some(75),
            json: false,
        });

        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("project_mode=true"));
        assert!(result.output.contains("project_safe_to_execute=false"));
        assert!(result
            .output
            .contains("project_requirements_public_resolution_deferred"));
        assert!(result.output.contains("helper_invoked=false"));
        assert!(!result.output.contains("helper should not run"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn project_payload_excludes_secret_files() {
        let root = temp_root("whoathere-cli-vm-project-payload-secrets");
        std::fs::write(
            root.join("setup.py"),
            "from setuptools import setup\nsetup(name='whoathere-clean', version='0.0.1', py_modules=['whoathere_clean'])\n",
        )
        .expect("setup py");
        std::fs::write(root.join("whoathere_clean.py"), "VALUE = 'clean'\n").expect("module");
        std::fs::write(root.join(".pypirc"), "password=real-secret").expect("pypirc");
        std::fs::create_dir_all(root.join(".gcp")).expect("gcp dir");
        std::fs::write(
            root.join(".gcp")
                .join("application_default_credentials.json"),
            r#"{"token":"real-gcp-secret"}"#,
        )
        .expect("gcp credentials");

        let plan = build_detonation_mirror_plan(&root.display().to_string());
        assert_eq!(plan.secret_exclusion_count, 2);
        let payload = encode_project_payload(&plan.files).expect("payload");
        let payload_text = String::from_utf8_lossy(&payload);
        assert!(payload_text.contains("setup.py"));
        assert!(payload_text.contains("whoathere_clean.py"));
        assert!(!payload_text.contains(".pypirc"));
        assert!(!payload_text.contains(".gcp"));
        assert!(!payload_text.contains("real-secret"));
        assert!(!payload_text.contains("real-gcp-secret"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_detonation_mirror_blocks_symlink_escape() {
        let root = temp_root("whoathere-cli-vm-detonate-symlink");
        std::fs::write(root.join("setup.py"), "from setuptools import setup\n").expect("setup py");
        let outside = root.with_extension("outside");
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(&outside).expect("outside");
        std::fs::write(outside.join("requirements.txt"), "private==1.0").expect("outside req");
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.join("requirements.txt"), root.join("escape.txt"))
            .expect("symlink");

        let plan = build_detonation_mirror_plan(&root.display().to_string());
        assert_eq!(plan.allowed_file_count, 1);
        #[cfg(unix)]
        {
            assert_eq!(plan.symlink_escape_count, 1);
            assert!(plan
                .reason_codes
                .contains(&"detonation_workspace_symlink_escape_blocked".to_string()));
        }

        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn vm_helper_invocation_rejects_relative_path() {
        let result = evaluate_command(Command::VmStatus {
            state_dir: Some("/tmp/whoathere-vm-relative-helper".to_string()),
            manifest_path: None,
            helper_path: Some("relative-helper".to_string()),
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("macos_vm_helper_path_not_absolute"));
        assert!(result.output.contains("helper_available=false"));
    }

    #[test]
    fn vm_helper_invocation_clears_host_environment() {
        let root = temp_root("whoathere-cli-vm-helper-env");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("temp root");
        let helper = root.join("helper.sh");
        write_new_file(&helper, b"#!/bin/sh\n/usr/bin/env\nexit 0\n").expect("helper script");
        set_executable(&helper).expect("executable helper");

        let result = evaluate_command(Command::VmStatus {
            state_dir: Some(root.join("state").display().to_string()),
            manifest_path: None,
            helper_path: Some(helper.display().to_string()),
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("helper_available=true"));
        assert!(result.output.contains("PATH="));
        assert!(!result.output.contains("HOME="));
        assert!(!result.output.contains("SSH_AUTH_SOCK="));
        assert!(!result.output.contains("AWS_SECRET_ACCESS_KEY="));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_release_plan_auto_sync_requires_complete_clean_evidence() {
        let result = evaluate_command(Command::VmReleasePlan {
            artifact_class: Some("npm.registry_tarball.v1".to_string()),
            ecosystem: None,
            source: None,
            filename: None,
            lifecycle_script: false,
            pep517_backend: false,
            native_marker: false,
            editable: false,
            evidence: LocalEvidenceFlags::clean(true),
            json: false,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("verdict=auto_sync"));
        assert!(result
            .output
            .contains("sync_paths=[\"node_modules/**\", \"package-lock.json\"]"));
    }

    #[test]
    fn vm_release_plan_keeps_binary_and_direct_classes_out_of_auto_sync() {
        let binary = evaluate_command(Command::VmReleasePlan {
            artifact_class: Some("pypi.binary_wheel.v1".to_string()),
            ecosystem: None,
            source: None,
            filename: None,
            lifecycle_script: false,
            pep517_backend: false,
            native_marker: false,
            editable: false,
            evidence: LocalEvidenceFlags::clean(true),
            json: false,
        });
        assert_eq!(binary.exit_code, 22);
        assert!(binary.output.contains("verdict=manual_review"));
        assert!(binary
            .output
            .contains("binary_wheel_requires_manual_review"));

        let direct = evaluate_command(Command::VmReleasePlan {
            artifact_class: Some("direct_vcs_editable.v1".to_string()),
            ecosystem: None,
            source: None,
            filename: None,
            lifecycle_script: false,
            pep517_backend: false,
            native_marker: false,
            editable: false,
            evidence: LocalEvidenceFlags::clean(true),
            json: false,
        });
        assert_eq!(direct.exit_code, 20);
        assert!(direct.output.contains("verdict=deny"));
        assert!(direct
            .output
            .contains("direct_vcs_editable_denied_by_default"));
    }

    #[test]
    fn vm_release_plan_can_classify_from_artifact_signals() {
        let result = evaluate_command(Command::VmReleasePlan {
            artifact_class: None,
            ecosystem: Some("pypi".to_string()),
            source: Some("registry".to_string()),
            filename: Some("pkg-1.0.0-py3-none-any.whl".to_string()),
            lifecycle_script: false,
            pep517_backend: false,
            native_marker: false,
            editable: false,
            evidence: LocalEvidenceFlags::clean(true),
            json: true,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result
            .output
            .contains("\"package_class\": \"pypi.pure_wheel.v1\""));
        assert!(result.output.contains("\"verdict\": \"auto_sync\""));
    }

    #[test]
    fn vm_canaries_and_sync_policy_expose_release_contract() {
        let canaries = evaluate_command(Command::VmCanaries { json: false });
        assert_eq!(canaries.exit_code, 0);
        assert!(canaries.output.contains("host_secret_mounting=false"));
        assert!(canaries.output.contains("env_name=NPM_TOKEN"));
        assert!(canaries.output.contains("env_name=OPENAI_API_KEY"));

        let sync = evaluate_command(Command::VmSyncPolicy { json: false });
        assert_eq!(sync.exit_code, 0);
        assert!(sync.output.contains("sync_back_enabled=false"));
        assert!(sync
            .output
            .contains("policy_scope=future_allowlist_not_release_authorization"));
        assert!(sync
            .output
            .contains("auto_sync_classes=[\"npm.registry_tarball.v1\", \"pypi.pure_wheel.v1\"]"));
        assert!(sync.output.contains(
            "deny_default_classes=[\"direct_vcs_editable.v1\", \"unsupported_unknown.v1\"]"
        ));
        assert!(sync.output.contains("scanner_adapter=guarddog"));
    }

    #[test]
    fn vm_red_team_gate_passes_fixture_safe_comparator_cases() {
        let result = evaluate_command(Command::VmRedTeamGate { json: false });
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("passed=true"));
        assert!(result.output.contains("case_count=18"));
        assert!(result.output.contains("public_network_used=false"));
        assert!(result.output.contains("external_scanners_required=false"));
        assert!(result.output.contains("static_npm_postinstall_block"));
        assert!(result.output.contains("dynamic_npm_postinstall_exfil"));
        assert!(result.output.contains("dynamic_pypi_pep517_backend_abuse"));
        assert!(result.output.contains("dynamic_dns_tunneling"));
        assert!(result.output.contains("dynamic_raw_material_rejected"));
        assert!(result.output.contains("passed=true reason_codes=[]"));
        assert!(!result.output.contains("WHOATHERE_CANARY_TOKEN"));
        assert!(!result.output.contains("/Users/"));
    }

    #[test]
    fn vm_red_team_gate_json_reports_release_gate_scope() {
        let result = evaluate_command(Command::VmRedTeamGate { json: true });
        assert_eq!(result.exit_code, 0);
        assert!(result
            .output
            .contains("\"command\": \"whoathere vm red-team-gate\""));
        assert!(result
            .output
            .contains("\"release_claim\": \"vm_detonation_admission_only_no_sync_back\""));
        assert!(result.output.contains("\"passed\": true"));
        assert!(result.output.contains("\"case_count\": 18"));
        assert!(result.output.contains("\"public_network_used\": false"));
        assert!(result
            .output
            .contains("\"external_scanners_required\": false"));
        assert!(result
            .output
            .contains("\"name\": \"dynamic_stale_result_rejected\""));
        assert!(!result.output.contains("WHOATHERE_CANARY_TOKEN"));
    }

    #[test]
    fn doctor_json_reports_vm_release_readiness_without_enabling_runtime() {
        let result = evaluate_command(Command::Doctor {
            json: true,
            state_dir: None,
            helper_path: None,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result
            .output
            .contains("\"release_target\": \"macos_apple_silicon_local_vm\""));
        assert!(result
            .output
            .contains("\"release_claim\": \"vm_detonation_admission_only_no_sync_back\""));
        assert!(result.output.contains(
            "\"release_readiness_schema\": \"whoathere.macos_local_release_readiness.v1\""
        ));
        assert!(result.output.contains("\"release_ready\": false"));
        assert!(result.output.contains("\"state_dir\":"));
        assert!(result
            .output
            .contains("release_npm_vm_detonation_not_verified"));
        assert!(result.output.contains("host.sync_back.disabled_preview"));
        assert!(!result
            .output
            .contains("release_safe_sync_back_not_implemented"));
        assert!(result.output.contains("pip.local_project.install"));
        assert!(result.output.contains("npm.install.project"));
        assert!(result.output.contains("\"vm_ready\": false"));
        assert!(result.output.contains("\"helper_available\": false"));
        assert!(result.output.contains("macos_vm_runtime_not_verified"));
        assert!(result.output.contains("\"high_risk_allowed\": false"));
    }

    #[test]
    fn doctor_accepts_state_dir_for_release_readiness_targeting() {
        let result = evaluate_command(Command::Doctor {
            json: true,
            state_dir: Some("/private/tmp/whoathere-doctor-state".to_string()),
            helper_path: None,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result
            .output
            .contains("\"state_dir\": \"/private/tmp/whoathere-doctor-state\""));
        assert!(result.output.contains("\"release_ready\": false"));
        assert!(result.output.contains("\"high_risk_allowed\": false"));
    }

    #[test]
    fn doctor_loads_default_state_dir_manifest_for_readiness() {
        let root = temp_root("whoathere-cli-doctor-default-manifest");
        let state_dir = root.join("state");
        let bundle_dir = state_dir.join("bundle");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&bundle_dir).expect("bundle dir");
        std::fs::write(
            bundle_dir.join("image.manifest"),
            "schema_version=whoathere.macos_vm_image.v1\nimage_id=local-restore-image-install\nmacos_version=26.5.1\nmacos_build_version=25F80\narchitecture=arm64\nrestore_image_digest=sha256:1111111111111111111111111111111111111111111111111111111111111111\ncpu_count=2\nmemory_mib=6144\nsignature_status=signature_verification_not_implemented\nhelper_version=0.1.0\n",
        )
        .expect("manifest");

        let result = evaluate_command(Command::Doctor {
            json: true,
            state_dir: Some(state_dir.display().to_string()),
            helper_path: None,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains(&format!(
            "\"vm_manifest_path\": \"{}\"",
            bundle_dir.join("image.manifest").display()
        )));
        assert!(result
            .output
            .contains("macos_vm_manifest_signature_not_verified"));
        assert!(!result.output.contains("macos_vm_image_manifest_missing"));
        assert!(result.output.contains("\"release_ready\": false"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn vm_status_reports_guest_provisioning_summary() {
        let root = temp_root("whoathere-cli-vm-status-provisioning");
        let state_dir = root.join("state");
        let bundle_dir = state_dir.join("bundle");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&bundle_dir).expect("bundle dir");
        std::fs::write(
            bundle_dir.join("guest-provisioning.json"),
            r#"{
  "schema_version": "whoathere.macos_vm.guest_provisioning.v1",
  "offline_python_runtime_status": "installed",
  "offline_python_wheels_status": "installed",
  "wheel_package_status": "installed",
  "offline_node_runtime_status": "installed",
  "offline_node_runtime_npm_version": "10.9.8",
  "offline_uv_binary_status": "installed",
  "offline_uv_binary_version": "uv 0.10.9",
  "high_risk_package_execution_enabled": false,
  "host_home_mounted": false,
  "host_secrets_mounted": false
}"#,
        )
        .expect("receipt");

        let result = evaluate_command(Command::VmStatus {
            state_dir: Some(state_dir.display().to_string()),
            manifest_path: None,
            helper_path: None,
            json: false,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result
            .output
            .contains("guest_provisioning_receipt_present=true"));
        assert!(result
            .output
            .contains("guest_provisioning_node_runtime_status=installed"));
        assert!(result
            .output
            .contains("guest_provisioning_npm_version=10.9.8"));
        assert!(result
            .output
            .contains("guest_provisioning_uv_binary_status=installed"));
        assert!(result.output.contains("guest_provisioning_reason_codes=[]"));
        assert!(!result
            .output
            .contains("macos_vm_guest_node_runtime_not_provisioned"));
        assert!(!result
            .output
            .contains("macos_vm_guest_uv_binary_not_provisioned"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn doctor_reports_stale_guest_provisioning_as_release_blocker() {
        let root = temp_root("whoathere-cli-doctor-stale-provisioning");
        let state_dir = root.join("state");
        let bundle_dir = state_dir.join("bundle");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&bundle_dir).expect("bundle dir");
        std::fs::write(
            bundle_dir.join("guest-provisioning.json"),
            r#"{
  "schema_version": "whoathere.macos_vm.guest_provisioning.v1",
  "offline_python_runtime_status": "installed",
  "offline_python_wheels_status": "installed",
  "wheel_package_status": "installed",
  "high_risk_package_execution_enabled": false,
  "host_home_mounted": false,
  "host_secrets_mounted": false
}"#,
        )
        .expect("receipt");

        let result = evaluate_command(Command::Doctor {
            json: true,
            state_dir: Some(state_dir.display().to_string()),
            helper_path: None,
        });

        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("\"guest_provisioning\": {"));
        assert!(result.output.contains("\"receipt_present\": true"));
        assert!(result
            .output
            .contains("\"python_runtime_status\": \"installed\""));
        assert!(result.output.contains("\"node_runtime_status\": null"));
        assert!(result
            .output
            .contains("macos_vm_guest_node_runtime_not_provisioned"));
        assert!(result
            .output
            .contains("macos_vm_guest_uv_binary_not_provisioned"));
        assert!(result.output.contains("\"release_ready\": false"));
        assert!(result.output.contains("\"high_risk_allowed\": false"));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_uv_sync_is_classified_before_fail_closed_execution() {
        let result = evaluate_command(Command::Protect {
            tool: "uv".to_string(),
            args: vec!["sync".to_string()],
            execute: false,
            policy_path: None,
            workspace: None,
            vault_origin: None,
            audit_path: None,
        });
        assert!(result.output.contains("ecosystem=Pypi"));
        assert!(result.output.contains("kind=UvSync"));
        assert!(result.output.contains("risk=High"));
        assert!(result.output.contains("uv_sync_project_environment"));
    }

    #[test]
    fn protect_defaults_fail_closed() {
        let args = vec![
            "protect".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        let output = render_command(parse_command(&args));
        assert!(output.contains("default_outage_decision=deny"));
    }

    #[test]
    fn denied_protect_returns_nonzero_exit_code() {
        let args = vec![
            "protect".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("exit_code=20"));
    }

    #[test]
    fn protect_parses_policy_path() {
        let args = vec![
            "protect".to_string(),
            "--policy".to_string(),
            "/tmp/whoathere.policy".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::Protect {
                tool: "npm".to_string(),
                args: vec!["ci".to_string()],
                execute: false,
                policy_path: Some("/tmp/whoathere.policy".to_string()),
                workspace: None,
                vault_origin: None,
                audit_path: None,
            }
        );
    }

    #[test]
    fn protect_parses_workspace_and_vault_origin() {
        let args = vec![
            "protect".to_string(),
            "--workspace".to_string(),
            "/work".to_string(),
            "--vault-origin".to_string(),
            "http://127.0.0.1:4873".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::Protect {
                tool: "npm".to_string(),
                args: vec!["ci".to_string()],
                execute: false,
                policy_path: None,
                workspace: Some("/work".to_string()),
                vault_origin: Some("http://127.0.0.1:4873".to_string()),
                audit_path: None,
            }
        );
    }

    #[test]
    fn protect_parses_audit_path() {
        let args = vec![
            "protect".to_string(),
            "--execute".to_string(),
            "--audit-path=/audit.jsonl".to_string(),
            "--workspace".to_string(),
            "/work".to_string(),
            "--vault-origin".to_string(),
            "http://127.0.0.1:4873".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::Protect {
                tool: "npm".to_string(),
                args: vec!["ci".to_string()],
                execute: true,
                policy_path: None,
                workspace: Some("/work".to_string()),
                vault_origin: Some("http://127.0.0.1:4873".to_string()),
                audit_path: Some("/audit.jsonl".to_string()),
            }
        );
    }

    #[test]
    fn protect_uses_environment_defaults_without_enabling_execution() {
        let args = vec!["npm".to_string(), "--".to_string(), "ci".to_string()];
        let command = parse_protect_with_env(&args, |key| match key {
            "WHOATHERE_WORKSPACE" => Some("/tmp/whoathere-workspace".to_string()),
            "WHOATHERE_VAULT_ORIGIN" => Some("http://127.0.0.1:4873".to_string()),
            "WHOATHERE_POLICY" => Some("/tmp/whoathere-policy.txt".to_string()),
            "WHOATHERE_AUDIT_PATH" => Some("/tmp/whoathere-audit.jsonl".to_string()),
            _ => None,
        });
        assert_eq!(
            command,
            Command::Protect {
                tool: "npm".to_string(),
                args: vec!["ci".to_string()],
                execute: false,
                policy_path: Some("/tmp/whoathere-policy.txt".to_string()),
                workspace: Some("/tmp/whoathere-workspace".to_string()),
                vault_origin: Some("http://127.0.0.1:4873".to_string()),
                audit_path: Some("/tmp/whoathere-audit.jsonl".to_string()),
            }
        );
    }

    #[test]
    fn protect_cli_flags_override_environment_defaults() {
        let args = vec![
            "--workspace".to_string(),
            "/tmp/cli-workspace".to_string(),
            "--vault-origin=http://127.0.0.1:5999".to_string(),
            "--policy".to_string(),
            "/tmp/cli-policy.txt".to_string(),
            "--audit-path=/tmp/cli-audit.jsonl".to_string(),
            "pip".to_string(),
            "--".to_string(),
            "install".to_string(),
            "fixture".to_string(),
        ];
        let command = parse_protect_with_env(&args, |key| match key {
            "WHOATHERE_WORKSPACE" => Some("/tmp/env-workspace".to_string()),
            "WHOATHERE_VAULT_ORIGIN" => Some("http://127.0.0.1:4873".to_string()),
            "WHOATHERE_POLICY" => Some("/tmp/env-policy.txt".to_string()),
            "WHOATHERE_AUDIT_PATH" => Some("/tmp/env-audit.jsonl".to_string()),
            _ => None,
        });
        assert_eq!(
            command,
            Command::Protect {
                tool: "pip".to_string(),
                args: vec!["install".to_string(), "fixture".to_string()],
                execute: false,
                policy_path: Some("/tmp/cli-policy.txt".to_string()),
                workspace: Some("/tmp/cli-workspace".to_string()),
                vault_origin: Some("http://127.0.0.1:5999".to_string()),
                audit_path: Some("/tmp/cli-audit.jsonl".to_string()),
            }
        );
    }

    #[test]
    fn endpoint_setup_uses_environment_defaults_and_cli_overrides() {
        let args = vec![
            "--shim-dir=/tmp/cli-shims".to_string(),
            "--vault-origin".to_string(),
            "http://127.0.0.1:5999".to_string(),
            "--include-python".to_string(),
        ];
        let command = parse_endpoint_setup_with_env(&args, |key| match key {
            "WHOATHERE_SHIM_DIR" => Some("/tmp/env-shims".to_string()),
            "WHOATHERE_WORKSPACE" => Some("/tmp/env-workspace".to_string()),
            "WHOATHERE_VAULT_ORIGIN" => Some("http://127.0.0.1:4873".to_string()),
            "WHOATHERE_POLICY" => Some("/tmp/env-policy.txt".to_string()),
            "WHOATHERE_AUDIT_PATH" => Some("/tmp/env-audit.jsonl".to_string()),
            "WHOATHERE_REPLAY_STORE" => Some("/tmp/env-replay-store.txt".to_string()),
            _ => None,
        });
        assert_eq!(
            command,
            Command::EndpointSetup {
                shim_dir: Some("/tmp/cli-shims".to_string()),
                workspace: Some("/tmp/env-workspace".to_string()),
                vault_origin: Some("http://127.0.0.1:5999".to_string()),
                policy_path: Some("/tmp/env-policy.txt".to_string()),
                audit_path: Some("/tmp/env-audit.jsonl".to_string()),
                replay_store: Some("/tmp/env-replay-store.txt".to_string()),
                include_python: true,
            }
        );
    }

    #[test]
    fn endpoint_setup_reports_missing_required_values_as_misuse() {
        let result = evaluate_command(Command::EndpointSetup {
            shim_dir: None,
            workspace: Some("/tmp/workspace".to_string()),
            vault_origin: None,
            policy_path: None,
            audit_path: None,
            replay_store: None,
            include_python: false,
        });
        assert_eq!(result.exit_code, ExitCode::Misuse.code());
        assert!(result.output.contains("status=error"));
        assert!(result.output.contains("shim_dir_required"));
        assert!(result.output.contains("vault_origin_required"));
        assert!(result.output.contains("mutation=false"));
    }

    #[test]
    fn endpoint_setup_outputs_fail_closed_setup_plan() {
        let root = temp_root("whoathere-endpoint-setup");
        let shim_dir = root.join("shims");
        let workspace = root.join("workspace");
        std::fs::create_dir_all(&workspace).expect("workspace");
        let result = evaluate_command(Command::EndpointSetup {
            shim_dir: Some(shim_dir.display().to_string()),
            workspace: Some(workspace.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            policy_path: None,
            audit_path: Some(root.join("audit.jsonl").display().to_string()),
            replay_store: Some(root.join("replay-store.txt").display().to_string()),
            include_python: false,
        });
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("whoathere endpoint setup"));
        assert!(result.output.contains("status=fail_closed"));
        assert!(result.output.contains("provider_scope=current"));
        assert!(result.output.contains("provider_ready=false"));
        assert!(result.output.contains("provider_not_ready"));
        assert!(result
            .output
            .contains("shim_install_command=whoathere shim install --dest"));
        assert!(result
            .output
            .contains("export_WHOATHERE_WORKSPACE=export WHOATHERE_WORKSPACE="));
        assert!(result.output.contains("replay_store="));
        assert!(result
            .output
            .contains("export_WHOATHERE_REPLAY_STORE=export WHOATHERE_REPLAY_STORE="));
        assert!(result
            .output
            .contains("provider_check_command=whoathere evidence providers --json --require-ready --scope current"));
        assert!(result
            .output
            .contains("ready_for_high_risk_execution=false"));
        assert!(result
            .output
            .contains("path_enablement_mode=fail_closed_interception"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn launch_plan_parses_gate_flags() {
        let args = vec![
            "launch".to_string(),
            "plan".to_string(),
            "--execute".to_string(),
            "--workspace".to_string(),
            "/work".to_string(),
            "--vault-origin".to_string(),
            "http://127.0.0.1:4873".to_string(),
            "--runtime-dir".to_string(),
            "/runtime".to_string(),
            "--containment-available".to_string(),
            "--egress-enforced".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::LaunchPlan {
                tool: "npm".to_string(),
                args: vec!["ci".to_string()],
                execute: true,
                workspace: Some("/work".to_string()),
                vault_origin: Some("http://127.0.0.1:4873".to_string()),
                runtime_dir: Some("/runtime".to_string()),
                containment_available: true,
                egress_enforced: true,
            }
        );
    }

    #[test]
    fn launch_audit_parses_gate_flags() {
        let args = vec![
            "launch".to_string(),
            "audit".to_string(),
            "--execute".to_string(),
            "--audit-path".to_string(),
            "/audit.jsonl".to_string(),
            "--workspace".to_string(),
            "/work".to_string(),
            "--vault-origin".to_string(),
            "http://127.0.0.1:4873".to_string(),
            "--runtime-dir".to_string(),
            "/runtime".to_string(),
            "--containment-available".to_string(),
            "--egress-enforced".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::LaunchAudit {
                tool: "npm".to_string(),
                args: vec!["ci".to_string()],
                execute: true,
                workspace: Some("/work".to_string()),
                vault_origin: Some("http://127.0.0.1:4873".to_string()),
                runtime_dir: Some("/runtime".to_string()),
                audit_path: Some("/audit.jsonl".to_string()),
                containment_available: true,
                egress_enforced: true,
            }
        );
    }

    #[test]
    fn launch_cleanup_parses_manifest_execute_and_audit_path() {
        let args = vec![
            "launch".to_string(),
            "cleanup".to_string(),
            "--execute".to_string(),
            "--manifest=/runtime/.whoathere-cleanup.manifest".to_string(),
            "--audit-path".to_string(),
            "/audit.jsonl".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::LaunchCleanup {
                manifest_path: Some("/runtime/.whoathere-cleanup.manifest".to_string()),
                execute: true,
                audit_path: Some("/audit.jsonl".to_string()),
            }
        );
    }

    #[test]
    fn protect_invalid_policy_denies_before_execution() {
        let path = std::env::temp_dir().join(format!(
            "whoathere-invalid-protect-policy-{}.txt",
            std::process::id()
        ));
        std::fs::write(&path, "schema_version=9.9.9").expect("write invalid policy");
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["--version".to_string()],
            execute: true,
            policy_path: Some(path.display().to_string()),
            workspace: None,
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("policy_status=error"));
        assert!(result.output.contains("execution_reason=policy_invalid"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn protect_source_scan_blocks_before_runner_plan() {
        let root = temp_root("whoathere-cli-source-block");
        std::fs::write(
            root.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .expect("write npmrc");
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("source_scan_status=blocked"));
        assert!(result.output.contains("npm_registry_override"));
        assert!(result
            .output
            .contains("execution_reason=source_scan_blocked"));
        assert!(!result.output.contains("package_manager_execution_gated"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_source_scan_writes_audit_for_blocked_source() {
        let root = temp_root("whoathere-cli-source-audit-block");
        std::fs::write(
            root.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .expect("write npmrc");
        let audit_path = std::env::temp_dir().join(format!(
            "whoathere-cli-protect-source-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&audit_path);
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec![
                "ci".to_string(),
                "--//registry.npmjs.org/:_authToken=secret".to_string(),
            ],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: Some(audit_path.display().to_string()),
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("source_scan_audit_status=written"));
        assert!(result
            .output
            .contains("execution_reason=source_scan_blocked"));
        assert!(!result.output.contains("_authToken=secret"));
        let persisted = std::fs::read_to_string(&audit_path).expect("audit jsonl");
        assert!(persisted.contains("\"event_id\":\"protect-source-gate\""));
        assert!(persisted.contains("\"decision\":\"deny\""));
        assert!(persisted.contains("\"source_scan_blocked\""));
        assert!(persisted.contains("\"npm_registry_override\""));
        assert!(!persisted.contains("_authToken=secret"));
        let _ = std::fs::remove_file(&audit_path);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_blocks_internal_npm_dependency_before_source_gate() {
        let root = temp_root("whoathere-cli-package-identity-npm-block");
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"@company/build-tools":"^1.0.0"}}"#,
        )
        .expect("write package json");
        let policy_path = root.join("whoathere.policy");
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-identity\nfail_closed=true\ninternal_namespace=@company/\n",
        )
        .expect("write policy");
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: Some(root.display().to_string()),
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("package_identity_status=blocked"));
        assert!(result
            .output
            .contains("dependency_confusion_public_source_denied"));
        assert!(result
            .output
            .contains("execution_reason=package_identity_policy_blocked"));
        assert!(!result.output.contains("vault_origin_required"));
        assert!(!result.output.contains("launch_plan_status="));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_blocks_internal_npm_argv_dependency() {
        let policy_path = std::env::temp_dir().join(format!(
            "whoathere-cli-package-identity-argv-{}.policy",
            std::process::id()
        ));
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-argv\nfail_closed=true\ninternal_namespace=@company/\n",
        )
        .expect("write policy");
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["install".to_string(), "@company/build-tools".to_string()],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: None,
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("file=<argv>"));
        assert!(result.output.contains("package=@company/build-tools"));
        assert!(result
            .output
            .contains("dependency_confusion_public_source_denied"));
        let _ = std::fs::remove_file(&policy_path);
    }

    #[test]
    fn protect_package_identity_blocks_internal_pip_requirement() {
        let root = temp_root("whoathere-cli-package-identity-pip-block");
        std::fs::write(root.join("requirements.txt"), "company-internal>=1.0\n")
            .expect("write requirements");
        let policy_path = root.join("whoathere.policy");
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-pip\nfail_closed=true\ninternal_namespace=company-\n",
        )
        .expect("write policy");
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec![
                "install".to_string(),
                "-r".to_string(),
                "requirements.txt".to_string(),
            ],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: Some(root.display().to_string()),
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("package=company-internal"));
        assert!(result
            .output
            .contains("dependency_confusion_public_source_denied"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_blocks_internal_custom_pip_requirement_file() {
        let root = temp_root("whoathere-cli-package-identity-pip-custom-block");
        std::fs::write(
            root.join("custom-requirements.txt"),
            "company-internal>=1.0\n",
        )
        .expect("write custom requirements");
        let policy_path = root.join("whoathere.policy");
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-pip-custom\nfail_closed=true\ninternal_namespace=company-\n",
        )
        .expect("write policy");
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec![
                "install".to_string(),
                "-r".to_string(),
                "custom-requirements.txt".to_string(),
            ],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: Some(root.display().to_string()),
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("file=custom-requirements.txt"));
        assert!(result.output.contains("package=company-internal"));
        assert!(result
            .output
            .contains("execution_reason=package_identity_policy_blocked"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_requires_workspace_for_pip_requirement_argv() {
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec![
                "install".to_string(),
                "-r".to_string(),
                "custom-requirements.txt".to_string(),
            ],
            execute: true,
            policy_path: None,
            workspace: None,
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result
            .output
            .contains("requirements_argv_workspace_required"));
        assert!(result
            .output
            .contains("execution_reason=package_identity_policy_blocked"));
        assert!(!result.output.contains("launch_plan_status="));
    }

    #[test]
    fn protect_package_identity_reads_equals_form_pip_requirement_file() {
        let root = temp_root("whoathere-cli-package-identity-pip-equals-block");
        std::fs::write(root.join("custom.in"), "company-internal>=1.0\n")
            .expect("write custom requirements");
        let policy_path = root.join("whoathere.policy");
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-pip-equals\nfail_closed=true\ninternal_namespace=company-\n",
        )
        .expect("write policy");
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), "--requirement=custom.in".to_string()],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: Some(root.display().to_string()),
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("file=custom.in"));
        assert!(result.output.contains("package=company-internal"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_reads_python_module_pip_requirement_file() {
        let root = temp_root("whoathere-cli-package-identity-python-module-pip");
        std::fs::write(root.join("custom.in"), "company-internal>=1.0\n")
            .expect("write custom requirements");
        let policy_path = root.join("whoathere.policy");
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-python-module\nfail_closed=true\ninternal_namespace=company-\n",
        )
        .expect("write policy");
        let result = evaluate_command(Command::Protect {
            tool: "python3".to_string(),
            args: vec![
                "-m".to_string(),
                "pip".to_string(),
                "install".to_string(),
                "-r".to_string(),
                "custom.in".to_string(),
            ],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: Some(root.display().to_string()),
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("kind=PythonModulePipInstall"));
        assert!(result.output.contains("file=custom.in"));
        assert!(result.output.contains("package=company-internal"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_source_scan_blocks_custom_pip_requirement_source_override() {
        let root = temp_root("whoathere-cli-source-custom-req-block");
        std::fs::write(
            root.join("custom-requirements.txt"),
            "--index-url https://pypi.org/simple\npublic-package>=1.0\n",
        )
        .expect("write custom requirements");
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec![
                "install".to_string(),
                "-r".to_string(),
                "custom-requirements.txt".to_string(),
            ],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("package_identity_status=ok"));
        assert!(result.output.contains("source_scan_status=blocked"));
        assert!(result.output.contains("requirements_index_override"));
        assert!(result
            .output
            .contains("execution_reason=source_scan_blocked"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_source_scan_blocks_custom_pip_constraint_source_override() {
        let root = temp_root("whoathere-cli-source-custom-constraint-block");
        std::fs::write(
            root.join("constraints.txt"),
            "--find-links https://files.pythonhosted.org/packages/\n",
        )
        .expect("write constraints");
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec![
                "install".to_string(),
                "public-package".to_string(),
                "--constraint=constraints.txt".to_string(),
            ],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("package_identity_status=ok"));
        assert!(result.output.contains("source_scan_status=blocked"));
        assert!(result.output.contains("requirements_index_override"));
        assert!(result
            .output
            .contains("execution_reason=source_scan_blocked"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_filters_workspace_manifests_by_command_ecosystem() {
        let root = temp_root("whoathere-cli-package-identity-ecosystem-filter");
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"@company/build-tools":"^1.0.0"}}"#,
        )
        .expect("write package json");
        let policy_path = root.join("whoathere.policy");
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-filter\nfail_closed=true\ninternal_namespace=@company/\n",
        )
        .expect("write policy");
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), "public-package".to_string()],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: Some(root.display().to_string()),
            vault_origin: None,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("package_identity_status=ok"));
        assert!(result.output.contains("package=public-package"));
        assert!(!result.output.contains("@company/build-tools"));
        assert!(result
            .output
            .contains("execution_reason=source_scan_blocked"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_blocks_package_json_git_source_by_default() {
        let root = temp_root("whoathere-cli-package-identity-git-block");
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"left-pad":"git+https://github.com/acme/left-pad.git"}}"#,
        )
        .expect("write package json");
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["install".to_string()],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("source=Git"));
        assert!(result.output.contains("untrusted_direct_source"));
        assert!(result
            .output
            .contains("execution_reason=package_identity_policy_blocked"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_package_identity_writes_audit_for_blocked_identity() {
        let root = temp_root("whoathere-cli-package-identity-audit-block");
        std::fs::write(
            root.join("package.json"),
            r#"{"dependencies":{"@company/build-tools":"^1.0.0"}}"#,
        )
        .expect("write package json");
        let policy_path = root.join("whoathere.policy");
        std::fs::write(
            &policy_path,
            "schema_version=0.1.0\npolicy_version=test-audit\nfail_closed=true\ninternal_namespace=@company/\n",
        )
        .expect("write policy");
        let audit_path = std::env::temp_dir().join(format!(
            "whoathere-cli-package-identity-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&audit_path);
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec![
                "ci".to_string(),
                "--//registry.npmjs.org/:_authToken=secret".to_string(),
            ],
            execute: true,
            policy_path: Some(policy_path.display().to_string()),
            workspace: Some(root.display().to_string()),
            vault_origin: None,
            audit_path: Some(audit_path.display().to_string()),
        });
        assert_eq!(result.exit_code, 20);
        assert!(result
            .output
            .contains("package_identity_audit_status=written"));
        assert!(!result.output.contains("_authToken=secret"));
        let persisted = std::fs::read_to_string(&audit_path).expect("audit jsonl");
        assert!(persisted.contains("\"event_id\":\"protect-package-identity-gate\""));
        assert!(persisted.contains("\"decision\":\"deny\""));
        assert!(persisted.contains("\"dependency_confusion_public_source_denied\""));
        assert!(!persisted.contains("_authToken=secret"));
        let _ = std::fs::remove_file(&audit_path);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_clean_workspace_plans_vault_context_but_keeps_install_gated() {
        let root = temp_root("whoathere-cli-source-clean");
        std::fs::write(root.join(".npmrc"), "registry=http://127.0.0.1:4873/npm/\n")
            .expect("write npmrc");
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("source_scan_status=ok"));
        assert!(result.output.contains("launch_context_status=planned"));
        assert!(result
            .output
            .contains("launch_context_execution_enabled=false"));
        assert!(result.output.contains("launch_plan_status=blocked"));
        assert!(result.output.contains("egress_proof_missing"));
        assert!(result.output.contains("egress_verified_proof_required"));
        assert!(result
            .output
            .contains("execution_reason=launch_plan_blocked"));
        assert!(!result.output.contains("package_manager_execution_gated"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_pip_install_remains_fail_closed_after_source_gate() {
        let root = temp_root("whoathere-cli-pip-clean");
        let result = evaluate_command(Command::Protect {
            tool: "pip".to_string(),
            args: vec!["install".to_string(), "fixture".to_string()],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("launch_plan_status=blocked"));
        assert!(result.output.contains("egress_proof_missing"));
        assert!(result.output.contains("egress_verified_proof_required"));
        assert!(result
            .output
            .contains("execution_reason=launch_plan_blocked"));
        assert!(!result.output.contains("execution_decision=allow"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_launch_gate_writes_audit_for_blocked_install() {
        let root = temp_root("whoathere-cli-launch-audit-block");
        std::fs::write(root.join(".npmrc"), "registry=http://127.0.0.1:4873/npm/\n")
            .expect("write npmrc");
        let audit_path = std::env::temp_dir().join(format!(
            "whoathere-cli-protect-launch-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&audit_path);
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: true,
            policy_path: None,
            workspace: Some(root.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            audit_path: Some(audit_path.display().to_string()),
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("source_scan_status=ok"));
        assert!(result.output.contains("launch_plan_status=blocked"));
        assert!(result.output.contains("launch_audit_status=written"));
        assert!(result
            .output
            .contains("execution_reason=launch_plan_blocked"));
        let persisted = std::fs::read_to_string(&audit_path).expect("audit jsonl");
        assert!(persisted.contains("\"event_id\":\"launch-plan-preview\""));
        assert!(persisted.contains("\"decision\":\"deny\""));
        assert!(persisted.contains("\"launch_context_hash\":\"sha256:"));
        assert!(persisted.contains("\"source_scan_hash\":\"sha256:"));
        assert!(persisted.contains("\"proof_summaries\""));
        assert!(persisted.contains("\"runtime_not_materialized\""));
        assert!(persisted.contains("\"egress_verified_proof_required\""));
        let _ = std::fs::remove_file(&audit_path);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn protect_invalid_vault_origin_blocks_before_runner_plan() {
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: true,
            policy_path: None,
            workspace: None,
            vault_origin: Some("https://registry.npmjs.org".to_string()),
            audit_path: None,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("invalid_launch_context"));
        assert!(result.output.contains("invalid_vault_origin"));
        assert!(!result.output.contains("package_manager_execution_gated"));
    }

    #[test]
    fn protect_redacts_sensitive_args() {
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec![
                "install".to_string(),
                "--//registry.npmjs.org/:_authToken=secret".to_string(),
            ],
            execute: false,
            policy_path: None,
            workspace: None,
            vault_origin: None,
            audit_path: None,
        });
        assert!(result.output.contains("[REDACTED]"));
        assert!(!result.output.contains("secret"));
    }

    #[test]
    fn protect_redacts_split_sensitive_args() {
        let result = evaluate_command(Command::Protect {
            tool: "npm".to_string(),
            args: vec![
                "config".to_string(),
                "set".to_string(),
                "//registry.npmjs.org/:_authToken".to_string(),
                "secret".to_string(),
                "--password".to_string(),
                "also-secret".to_string(),
            ],
            execute: false,
            policy_path: None,
            workspace: None,
            vault_origin: None,
            audit_path: None,
        });
        assert!(result.output.contains("[REDACTED]"));
        assert!(!result.output.contains("secret"));
        assert!(!result.output.contains("also-secret"));
    }

    #[test]
    fn launch_plan_blocks_without_egress_proof_before_runtime() {
        let workspace = temp_root("whoathere-cli-launch-workspace");
        std::fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-cli-launch-runtime");
        let _ = std::fs::remove_dir_all(&runtime);
        let result = evaluate_command(Command::LaunchPlan {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: true,
            workspace: Some(workspace.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            runtime_dir: Some(runtime.display().to_string()),
            containment_available: true,
            egress_enforced: false,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("launch_plan_status=blocked"));
        assert!(result.output.contains("egress_proof_missing"));
        assert!(result.output.contains("egress_verified_proof_required"));
        assert!(result.output.contains("runtime_materialized=false"));
        assert!(result.output.contains("execution_allowed=false"));
        assert!(!runtime.exists());
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&runtime);
    }

    #[test]
    fn launch_plan_operator_assertions_do_not_verify_egress_proof() {
        let workspace = temp_root("whoathere-cli-launch-operator-workspace");
        std::fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-cli-launch-operator-runtime");
        let _ = std::fs::remove_dir_all(&runtime);
        let result = evaluate_command(Command::LaunchPlan {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            execute: true,
            workspace: Some(workspace.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            runtime_dir: Some(runtime.display().to_string()),
            containment_available: true,
            egress_enforced: true,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("launch_plan_status=blocked"));
        assert!(!result.output.contains("launch_plan_status=planned"));
        assert!(result.output.contains("launch_context_hash=sha256:"));
        assert!(result.output.contains("source_scan_hash=sha256:"));
        assert!(result
            .output
            .contains("proof_challenge_id=proof-challenge-sha256:"));
        assert!(result
            .output
            .contains("proof_challenge_subject=launch-sha256-"));
        assert!(result
            .output
            .contains("proof_challenge_context_hash=sha256:"));
        assert!(result
            .output
            .contains("proof_challenge_configured_vault_host=127.0.0.1:4873"));
        assert!(result.output.contains("proof_challenge_probe_count=15"));
        assert!(result.output.contains("proof_challenge_expires_at="));
        assert!(result.output.contains("proof_challenge_nonce_present=true"));
        assert!(result.output.contains("proof_challenge_valid=true"));
        assert!(result
            .output
            .contains("provider_challenge_command=whoathere evidence challenge --scope current"));
        assert!(result.output.contains("--context-hash 'sha256:"));
        assert!(result
            .output
            .contains("containment_proof_status=OperatorAsserted"));
        assert!(result.output.contains("containment_proof_subject=unbound"));
        assert!(result
            .output
            .contains("containment_proof_mechanism=OperatorAssertion"));
        assert!(result.output.contains("containment_proof_expires_at=0"));
        assert!(result
            .output
            .contains("egress_proof_status=OperatorAsserted"));
        assert!(result.output.contains("egress_proof_subject=unbound"));
        assert!(result
            .output
            .contains("egress_proof_mechanism=OperatorAssertion"));
        assert!(result.output.contains("egress_proof_scope=Unknown"));
        assert!(result.output.contains("egress_proof_expires_at=0"));
        assert!(result
            .output
            .contains("egress_operator_assertion_not_verified"));
        assert!(result.output.contains("egress_verified_proof_required"));
        assert!(result.output.contains("runtime_materialized=false"));
        assert!(!runtime.exists());
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&runtime);
    }

    #[test]
    fn launch_provider_check_evaluates_generated_challenge_without_execution() {
        let workspace = temp_root("whoathere-cli-launch-provider-check-workspace");
        std::fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-cli-launch-provider-check-runtime");
        let _ = std::fs::remove_dir_all(&runtime);
        let parsed = parse_command(&[
            "launch".to_string(),
            "provider-check".to_string(),
            "--execute".to_string(),
            "--workspace".to_string(),
            workspace.display().to_string(),
            "--vault-origin".to_string(),
            "http://127.0.0.1:4873".to_string(),
            "--runtime-dir".to_string(),
            runtime.display().to_string(),
            "--egress-enforced".to_string(),
            "--containment-available".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "ci".to_string(),
        ]);
        assert!(matches!(parsed, Command::LaunchProviderCheck { .. }));
        let result = evaluate_command(parsed);
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("launch_plan_status=blocked"));
        assert!(result
            .output
            .contains("provider_challenge_command=whoathere evidence challenge"));
        assert!(result
            .output
            .contains("launch_provider_check_status=fail_closed"));
        assert!(result
            .output
            .contains("launch_provider_check_mutation=false"));
        assert!(result.output.contains("launch_provider_check_provider="));
        assert!(result
            .output
            .contains("launch_provider_check_challenge_id=proof-challenge-sha256:"));
        assert!(result
            .output
            .contains("launch_provider_check_subject=launch-sha256-"));
        assert!(result
            .output
            .contains("launch_provider_check_context_hash=sha256:"));
        assert!(result
            .output
            .contains("launch_provider_check_configured_vault_host=127.0.0.1:4873"));
        assert!(result
            .output
            .contains("launch_provider_check_satisfied=false"));
        assert!(result
            .output
            .contains("provider_challenge_egress_probe_missing"));
        assert!(result.output.contains("provider_challenge_proof_not_fresh"));
        assert!(result.output.contains("execution_allowed=false"));
        assert!(result.output.contains("runtime_materialized=false"));
        assert!(!runtime.exists());
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&runtime);
    }

    #[test]
    fn launch_plan_execute_reports_deny_when_install_still_disabled() {
        let plan = LaunchPlan {
            status: LaunchStatus::Planned,
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            command_kind: CommandKind::NpmCi,
            risk: WorkflowRisk::Medium,
            reason_codes: vec!["install_execution_not_enabled".to_string()],
            source_report: None,
            context: None,
            launch_context_hash: Some("sha256:test".to_string()),
            source_scan_hash: Some("sha256:test-source".to_string()),
            runtime: None,
            proof_challenge: None,
            containment_proof: ContainmentProof::missing(ExecutionMode::CiFailClosed),
            egress_proof: EgressProof::missing(),
            execution_allowed: false,
        };
        let output = render_launch_plan_output(&plan, true);
        assert!(output.contains("final_exit_code=20"));
        assert!(output.contains("launch_plan_status=planned"));
        assert!(output.contains("execution_allowed=false"));
    }

    #[test]
    fn launch_audit_renders_proof_and_cleanup_summaries() {
        let workspace = temp_root("whoathere-cli-launch-audit-workspace");
        std::fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-cli-launch-audit-runtime");
        let _ = std::fs::remove_dir_all(&runtime);
        let audit_path = std::env::temp_dir().join(format!(
            "whoathere-cli-launch-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&audit_path);
        let result = evaluate_command(Command::LaunchAudit {
            tool: "npm".to_string(),
            args: vec![
                "ci".to_string(),
                "--//registry.npmjs.org/:_authToken=secret".to_string(),
            ],
            execute: true,
            workspace: Some(workspace.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            runtime_dir: Some(runtime.display().to_string()),
            audit_path: Some(audit_path.display().to_string()),
            containment_available: true,
            egress_enforced: true,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("status=written"));
        assert!(result.output.contains("\"decision\":\"deny\""));
        assert!(result.output.contains("\"launch_context_hash\":\"sha256:"));
        assert!(result.output.contains("\"source_scan_hash\":\"sha256:"));
        assert!(result.output.contains("\"kind\":\"containment\""));
        assert!(result.output.contains("\"kind\":\"egress\""));
        assert!(result
            .output
            .contains("\"mechanism\":\"OperatorAssertion\""));
        assert!(result.output.contains("\"cleanup_summary\""));
        assert!(result.output.contains("\"runtime_not_materialized\""));
        assert!(result.output.contains("[REDACTED]"));
        assert!(!result.output.contains("_authToken=secret"));
        let persisted = std::fs::read_to_string(&audit_path).expect("audit jsonl");
        assert!(persisted.contains("\"proof_summaries\""));
        assert!(persisted.contains("\"cleanup_summary\""));
        assert!(!persisted.contains("_authToken=secret"));
        assert!(!runtime.exists());
        let _ = std::fs::remove_file(&audit_path);
        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&runtime);
    }

    #[test]
    fn launch_cleanup_reports_without_removing_paths() {
        let runtime = temp_root("whoathere-cli-cleanup-report-runtime");
        let manifest = write_cleanup_manifest_fixture(&runtime);
        let config = runtime.join("npmrc");
        let result = evaluate_command(Command::LaunchCleanup {
            manifest_path: Some(manifest.display().to_string()),
            execute: false,
            audit_path: None,
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("mutation=false"));
        assert!(result.output.contains("cleanup_report_only"));
        assert!(result.output.contains("cleanup_removed_count=0"));
        assert!(runtime.exists());
        assert!(config.exists());
        assert!(manifest.exists());
        let _ = std::fs::remove_dir_all(&runtime);
    }

    #[test]
    fn launch_cleanup_executes_guarded_cleanup_and_writes_audit() {
        let runtime = temp_root("whoathere-cli-cleanup-execute-runtime");
        let manifest = write_cleanup_manifest_fixture(&runtime);
        let audit_path = std::env::temp_dir().join(format!(
            "whoathere-cli-cleanup-audit-{}.jsonl",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&audit_path);
        let result = evaluate_command(Command::LaunchCleanup {
            manifest_path: Some(manifest.display().to_string()),
            execute: true,
            audit_path: Some(audit_path.display().to_string()),
        });
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("mutation=true"));
        assert!(result.output.contains("cleanup_removed_count=5"));
        assert!(result.output.contains("cleanup_refused_count=0"));
        assert!(result.output.contains("cleanup_audit_status=written"));
        assert!(!runtime.exists());
        let persisted = std::fs::read_to_string(&audit_path).expect("cleanup audit jsonl");
        assert!(persisted.contains("\"event_id\":\"launch-cleanup\""));
        assert!(persisted.contains("\"decision\":\"allow\""));
        assert!(persisted.contains("\"cleanup_summary\""));
        assert!(persisted.contains("\"removed_count\":5"));
        let _ = std::fs::remove_file(&audit_path);
    }

    #[test]
    fn launch_plan_blocks_argv_source_override_before_runtime() {
        let workspace = temp_root("whoathere-cli-launch-argv-workspace");
        std::fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-cli-launch-argv-runtime");
        let _ = std::fs::remove_dir_all(&runtime);
        let result = evaluate_command(Command::LaunchPlan {
            tool: "npm".to_string(),
            args: vec![
                "ci".to_string(),
                "--registry=https://registry.npmjs.org".to_string(),
            ],
            execute: true,
            workspace: Some(workspace.display().to_string()),
            vault_origin: Some("http://127.0.0.1:4873".to_string()),
            runtime_dir: Some(runtime.display().to_string()),
            containment_available: true,
            egress_enforced: true,
        });
        assert_eq!(result.exit_code, 20);
        assert!(result.output.contains("argv_source_override_blocked"));
        assert!(result.output.contains("runtime_materialized=false"));
        assert!(!runtime.exists());
        let _ = std::fs::remove_dir_all(&workspace);
    }

    #[test]
    fn shim_dry_run_renders_manifest() {
        let output = render_command(Command::ShimInstall {
            dry_run: true,
            dest: None,
            include_python: false,
        });
        assert!(output.contains("shim=npm"));
        assert!(output.contains("target=\"whoathere protect --execute npm --\""));
        assert!(output.contains("mutation=false"));
        assert!(output.contains("include_python=false"));
        assert!(output.contains("env_defaults=WHOATHERE_WORKSPACE,WHOATHERE_VAULT_ORIGIN,WHOATHERE_POLICY,WHOATHERE_AUDIT_PATH,WHOATHERE_REPLAY_STORE"));
        assert!(output.contains("shim=python optional=true"));
    }

    #[test]
    fn parses_shim_dest() {
        let args = vec![
            "shim".to_string(),
            "install".to_string(),
            "--dest".to_string(),
            "/tmp/whoathere-shims".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::ShimInstall {
                dry_run: false,
                dest: Some("/tmp/whoathere-shims".to_string()),
                include_python: false
            }
        );
    }

    #[test]
    fn parses_python_shim_opt_in() {
        let args = vec![
            "shim".to_string(),
            "install".to_string(),
            "--include-python".to_string(),
            "--dest".to_string(),
            "/tmp/whoathere-shims".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::ShimInstall {
                dry_run: false,
                dest: Some("/tmp/whoathere-shims".to_string()),
                include_python: true
            }
        );
    }

    #[test]
    fn materializes_shims_in_explicit_directory() {
        let dest = std::env::temp_dir().join(format!("whoathere-shim-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        let installed =
            materialize_unix_shims(&dest, "/tmp/whoathere-bin").expect("shim materialization");
        assert_eq!(installed, default_shims().len());
        let npm = std::fs::read_to_string(dest.join("npm")).expect("npm shim should exist");
        assert!(npm.contains("protect --execute npm --"));
        assert!(!dest.join("python").exists());
        assert!(!dest.join("python3").exists());
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn materializes_python_shims_only_when_explicit() {
        let dest =
            std::env::temp_dir().join(format!("whoathere-python-shim-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        let installed = materialize_unix_shims_with_options(&dest, "/tmp/whoathere-bin", true)
            .expect("shim materialization");
        assert_eq!(
            installed,
            default_shims().len() + optional_python_shims().len()
        );
        let python =
            std::fs::read_to_string(dest.join("python")).expect("python shim should exist");
        let python3 =
            std::fs::read_to_string(dest.join("python3")).expect("python3 shim should exist");
        assert!(python.contains("protect --execute python --"));
        assert!(python3.contains("protect --execute python3 --"));
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn materialize_refuses_existing_shim_file() {
        let dest = std::env::temp_dir().join(format!(
            "whoathere-shim-existing-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dest);
        std::fs::create_dir_all(&dest).expect("create dest");
        std::fs::write(dest.join("npm"), "existing").expect("write existing shim");
        let error = materialize_unix_shims(&dest, "/tmp/whoathere-bin").unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn shim_quote_prevents_shell_expansion() {
        let dest =
            std::env::temp_dir().join(format!("whoathere-shim-quote-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dest);
        materialize_unix_shims(&dest, "/tmp/whoathere $(touch should-not-run)")
            .expect("shim materialization");
        let npm = std::fs::read_to_string(dest.join("npm")).expect("npm shim should exist");
        assert!(npm.contains("'/tmp/whoathere $(touch should-not-run)'"));
        let _ = std::fs::remove_dir_all(&dest);
    }

    #[test]
    fn protect_reports_npx_as_unprotected_high_risk() {
        let args = vec![
            "protect".to_string(),
            "npx".to_string(),
            "--".to_string(),
            "left-pad".to_string(),
        ];
        let output = render_command(parse_command(&args));
        assert!(output.contains("kind=NpmExec"));
        assert!(output.contains("risk=High"));
        assert!(output.contains("protected=false"));
    }

    #[test]
    fn protect_version_probe_is_allowed_without_execution_by_default() {
        let args = vec![
            "protect".to_string(),
            "npm".to_string(),
            "--".to_string(),
            "--version".to_string(),
        ];
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, 0);
        assert!(result.output.contains("kind=VersionProbe"));
        assert!(result.output.contains("default_outage_decision=allow"));
        assert!(result.output.contains("execution_requested=false"));
    }

    #[test]
    fn scan_unknown_manifest_kind_fails_closed() {
        let output = render_command(Command::ScanManifest {
            kind: "unknown".to_string(),
            path: "does-not-matter".to_string(),
        });
        assert!(output.contains("unsupported_manifest_kind"));
    }

    #[test]
    fn config_check_reports_invalid_config_without_applying() {
        let path =
            std::env::temp_dir().join(format!("whoathere-config-test-{}.txt", std::process::id()));
        std::fs::write(&path, "collect_secrets=true").expect("write config");
        let output = render_command(Command::ConfigCheck {
            path: path.display().to_string(),
        });
        assert!(output.contains("config_invalid"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_check_source_blocks_dependency_confusion() {
        let output = render_command(Command::PolicyCheckSource {
            package: "@company/build-tools".to_string(),
            source: "public".to_string(),
            internal_prefix: Some("@company/".to_string()),
            policy_path: None,
        });
        assert!(output.contains("decision=Deny"));
        assert!(output.contains("dependency_confusion_public_source_denied"));
    }

    #[test]
    fn policy_check_validates_policy_file() {
        let path =
            std::env::temp_dir().join(format!("whoathere-policy-test-{}.txt", std::process::id()));
        std::fs::write(
            &path,
            "schema_version=0.1.0\npolicy_version=test\nfail_closed=true\ninternal_namespace=@company/\n",
        )
        .expect("write policy");
        let output = render_command(Command::PolicyCheck {
            path: path.display().to_string(),
        });
        assert!(output.contains("status=ok"));
        assert!(output.contains("namespace_rules=1"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn policy_check_source_uses_policy_file() {
        let path = std::env::temp_dir().join(format!(
            "whoathere-policy-source-test-{}.txt",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "schema_version=0.1.0\npolicy_version=test-file\nfail_closed=true\ninternal_namespace=@company/\n",
        )
        .expect("write policy");
        let output = render_command(Command::PolicyCheckSource {
            package: "@company/build-tools".to_string(),
            source: "public".to_string(),
            internal_prefix: None,
            policy_path: Some(path.display().to_string()),
        });
        assert!(output.contains("policy_version=test-file"));
        assert!(output.contains("decision=Deny"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn evidence_profiles_lists_minimum_profiles() {
        let output = render_command(Command::EvidenceProfiles);
        assert!(output.contains("npm.registry_tarball.v1"));
        assert!(output.contains("pypi.sdist_pep517.v1"));
    }

    #[test]
    fn evidence_providers_report_fail_closed_diagnostics() {
        let output = render_command(Command::EvidenceProviders {
            json: false,
            require_ready: false,
            provider_scope: ProviderScope::All,
        });
        assert!(output.contains("whoathere evidence providers"));
        assert!(output.contains("provider_scope=all"));
        assert!(output.contains("provider=linux-local-proof-provider"));
        assert!(output.contains("provider=macos-local-proof-provider"));
        assert!(output.contains("containment_status=Missing"));
        assert!(output.contains("egress_status=Missing"));
        assert!(output.contains("linux_containment_provider_unimplemented"));
        assert!(output.contains("macos_containment_provider_unimplemented"));
        assert!(output.contains("provider_readiness provider=linux"));
        assert!(output.contains("provider_readiness provider=macos"));
        assert!(output.contains("control_level="));
        assert!(output.contains("provider_challenge provider=linux"));
        assert!(output.contains("provider_challenge provider=macos"));
        assert!(output.contains("provider_posture provider=linux"));
        assert!(output.contains("provider_posture provider=macos"));
        assert!(output.contains("provider_active_probe provider=linux"));
        assert!(output.contains("linux_active_probe_receipt_missing"));
        assert!(output.contains("linux_active_probe_not_complete"));
        assert!(output.contains("linux_active_probe_denied_probe_missing"));
        assert!(output.contains("schema_version=local_provider_readiness.v1"));
        assert!(output.contains("provider_target_platform=linux"));
        assert!(output.contains("provider_target_platform=macos"));
        assert!(output.contains("provider_host_platform="));
        assert!(output.contains("provider_target_matches_host="));
        assert!(output.contains("active_verification_enabled=false"));
        assert!(output.contains("package_execution_attempted=false"));
        assert!(output.contains("os_mutation_attempted=false"));
        assert!(output.contains("network_mutation_attempted=false"));
        assert!(output.contains("public_network_probe_attempted=false"));
        assert!(output.contains("challenge_id=proof-challenge-sha256:"));
        assert!(output.contains("satisfied=false"));
        assert!(output.contains("provider_challenge_egress_probe_missing"));
        assert!(output.contains("provider_challenge_proof_not_fresh"));
        assert!(output.contains("proof_verification_enabled=false"));
        assert!(output.contains("linux_proof_verification_not_implemented"));
        assert!(output.contains("macos_proof_verification_not_implemented"));
        assert!(output.contains("macos_vm_containment_beta"));
        assert!(output.contains("provider_status=read_only_probe"));
        assert!(output.contains("platform_target=linux"));
        assert!(output.contains("platform_target=macos"));
    }

    #[test]
    fn evidence_providers_json_reports_fail_closed_readiness() {
        let args = vec![
            "evidence".to_string(),
            "providers".to_string(),
            "--json".to_string(),
        ];
        let command = parse_command(&args);
        assert_eq!(
            command,
            Command::EvidenceProviders {
                json: true,
                require_ready: false,
                provider_scope: ProviderScope::All
            }
        );
        let output = render_command(command);
        assert!(output.starts_with("{\n"));
        assert!(output.contains("\"schema_version\": 1"));
        assert!(output.contains("\"provider_scope\": \"all\""));
        assert!(output.contains("\"current_provider_platform\":"));
        assert!(output.contains("\"provider\": \"linux\""));
        assert!(output.contains("\"provider\": \"macos\""));
        assert!(output.contains("\"control_level\":"));
        assert!(output.contains("\"status\": \"Missing\""));
        assert!(output.contains("\"proof_verification_enabled\": false"));
        assert!(output.contains("\"verification_plan\""));
        assert!(output.contains("\"challenge\""));
        assert!(output.contains("\"probe_destinations\""));
        assert!(output.contains("\"registry.npmjs.org\""));
        assert!(output.contains("\"10.0.0.1\""));
        assert!(output.contains("\"8.8.8.8:53\""));
        assert!(output.contains("\"expires_at_unix_seconds\""));
        assert!(output.contains("\"nonce_present\": true"));
        assert!(output.contains("\"challenge_attempt\""));
        assert!(output.contains("\"posture\""));
        assert!(output.contains("\"active_probe_receipt\""));
        assert!(output.contains("\"linux_active_probe_receipt_missing\""));
        assert!(output.contains("\"linux_active_probe_not_complete\""));
        assert!(output.contains("\"linux_active_probe_denied_probe_missing\""));
        assert!(output.contains("\"schema_version\": \"local_provider_readiness.v1\""));
        assert!(output.contains("\"target_platform\": \"linux\""));
        assert!(output.contains("\"target_platform\": \"macos\""));
        assert!(output.contains("\"host_platform\":"));
        assert!(output.contains("\"target_matches_host\":"));
        assert!(output.contains("\"active_verification_enabled\": false"));
        assert!(output.contains("\"package_execution_attempted\": false"));
        assert!(output.contains("\"os_mutation_attempted\": false"));
        assert!(output.contains("\"network_mutation_attempted\": false"));
        assert!(output.contains("\"public_network_probe_attempted\": false"));
        assert!(output.contains("\"satisfied\": false"));
        assert!(output.contains("\"provider_challenge_egress_probe_missing\""));
        assert!(output.contains("\"provider_challenge_proof_not_fresh\""));
        assert!(output.contains("\"can_verify_now\": false"));
        assert!(output.contains("\"verify_seccomp_filter\""));
        assert!(output.contains("\"verify_virtualization_vm_boundary\""));
        assert!(output.contains("\"macos_vm_containment_beta\""));
        assert!(output.contains("\"evidence\""));
    }

    #[test]
    fn evidence_providers_scope_filters_provider_diagnostics() {
        let linux_output = render_command(parse_command(&[
            "evidence".to_string(),
            "providers".to_string(),
            "--scope=linux".to_string(),
        ]));
        assert!(linux_output.contains("provider_scope=linux"));
        assert!(linux_output.contains("provider=linux-local-proof-provider"));
        assert!(!linux_output.contains("provider=macos-local-proof-provider"));

        let current_output = render_command(parse_command(&[
            "evidence".to_string(),
            "providers".to_string(),
            "--json".to_string(),
            "--scope".to_string(),
            "current".to_string(),
        ]));
        assert!(current_output.contains("\"provider_scope\": \"current\""));
        if let Some(label) = current_provider_label() {
            assert!(current_output.contains(&format!("\"provider\": \"{label}\"")));
        } else {
            assert!(current_output.contains("\"providers\": [\n\n  ]"));
        }
    }

    #[test]
    fn evidence_linux_active_probe_fixture_complete_validates_receipt_without_authorization() {
        let args = vec![
            "evidence".to_string(),
            "linux-active-probe-fixture".to_string(),
            "--subject".to_string(),
            "launch-1".to_string(),
            "--context-hash".to_string(),
            "sha256:context".to_string(),
            "--vault-host".to_string(),
            "127.0.0.1:4873".to_string(),
            "--profile".to_string(),
            "complete".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::EvidenceLinuxActiveProbeFixture {
                json: false,
                subject: Some("launch-1".to_string()),
                context_hash: Some("sha256:context".to_string()),
                vault_host: Some("127.0.0.1:4873".to_string()),
                profile: Some("complete".to_string())
            }
        );
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, ExitCode::Allow.code());
        assert!(result
            .output
            .contains("whoathere evidence linux-active-probe-fixture"));
        assert!(result.output.contains("profile=complete"));
        assert!(result.output.contains("status=ok"));
        assert!(result.output.contains("receipt_satisfied=true"));
        assert!(result.output.contains("receipt_reason_codes=[]"));
        assert!(result.output.contains("authorization=false"));
        assert!(result.output.contains("proof_minted=false"));
        assert!(result.output.contains("execution_allowed=false"));
    }

    #[test]
    fn evidence_linux_active_probe_fixture_rejects_overpermissive_profile() {
        let result = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-fixture".to_string(),
            "--json".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
            "--profile=overpermissive".to_string(),
        ]));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result
            .output
            .contains("\"command\": \"whoathere evidence linux-active-probe-fixture\""));
        assert!(result.output.contains("\"profile\": \"overpermissive\""));
        assert!(result.output.contains("\"probe_destinations\""));
        assert!(result.output.contains("\"authorization\": false"));
        assert!(result.output.contains("\"proof_minted\": false"));
        assert!(result.output.contains("\"execution_allowed\": false"));
        assert!(result.output.contains("\"satisfied\": false"));
        assert!(result
            .output
            .contains("\"linux_active_probe_non_vault_probe_allowed\""));
    }

    #[test]
    fn evidence_linux_active_probe_fixture_requires_explicit_inputs_and_profile() {
        let result = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-fixture".to_string(),
            "--json".to_string(),
            "--profile=unknown".to_string(),
        ]));
        assert_eq!(result.exit_code, ExitCode::Misuse.code());
        assert!(result.output.contains("\"status\": \"error\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_fixture_subject_required\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_fixture_context_hash_required\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_fixture_vault_host_required\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_fixture_profile_invalid\""));
    }

    #[test]
    fn evidence_linux_active_probe_admission_accepts_replay_owned_receipt_without_authorization() {
        let args = vec![
            "evidence".to_string(),
            "linux-active-probe-admission".to_string(),
            "--json".to_string(),
            "--subject".to_string(),
            "launch-1".to_string(),
            "--context-hash".to_string(),
            "sha256:context".to_string(),
            "--vault-host".to_string(),
            "127.0.0.1:4873".to_string(),
            "--profile".to_string(),
            "complete".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::EvidenceLinuxActiveProbeAdmission {
                json: true,
                subject: Some("launch-1".to_string()),
                context_hash: Some("sha256:context".to_string()),
                vault_host: Some("127.0.0.1:4873".to_string()),
                profile: Some("complete".to_string()),
                replay: false,
                unknown_challenge: false,
                mutate_context: false
            }
        );
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, ExitCode::Allow.code());
        assert!(result
            .output
            .contains("\"command\": \"whoathere evidence linux-active-probe-admission\""));
        assert!(result.output.contains("\"authorization\": false"));
        assert!(result.output.contains("\"proof_minted\": false"));
        assert!(result.output.contains("\"execution_allowed\": false"));
        assert!(result.output.contains("\"accepted\": true"));
        assert!(result.output.contains("\"status\": \"Accepted\""));
        assert!(result.output.contains("\"satisfied\": true"));
        assert!(result.output.contains("\"preconsume\": null"));
    }

    #[test]
    fn evidence_linux_active_probe_admission_rejects_replay_unknown_and_invalid_receipts() {
        let replay = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-admission".to_string(),
            "--json".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
            "--profile=complete".to_string(),
            "--replay".to_string(),
        ]));
        assert_eq!(replay.exit_code, ExitCode::Deny.code());
        assert!(replay.output.contains("\"preconsume\": {"));
        assert!(replay.output.contains("\"accepted\": false"));
        assert!(replay.output.contains("\"provider_challenge_replayed\""));
        assert!(replay.output.contains("\"satisfied\": true"));

        let unknown = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-admission".to_string(),
            "--json".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
            "--profile=complete".to_string(),
            "--unknown-challenge".to_string(),
        ]));
        assert_eq!(unknown.exit_code, ExitCode::Deny.code());
        assert!(unknown.output.contains("\"provider_challenge_not_issued\""));
        assert!(unknown.output.contains("\"satisfied\": true"));

        let incomplete = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-admission".to_string(),
            "--json".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
            "--profile=incomplete".to_string(),
        ]));
        assert_eq!(incomplete.exit_code, ExitCode::Deny.code());
        assert!(incomplete.output.contains("\"status\": \"Accepted\""));
        assert!(incomplete.output.contains("\"accepted\": false"));
        assert!(incomplete
            .output
            .contains("\"linux_active_probe_not_complete\""));
    }

    #[test]
    fn evidence_linux_active_probe_admission_rejects_misuse_and_mutation() {
        let misuse = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-admission".to_string(),
            "--json".to_string(),
            "--profile=unknown".to_string(),
        ]));
        assert_eq!(misuse.exit_code, ExitCode::Misuse.code());
        assert!(misuse
            .output
            .contains("\"linux_active_probe_admission_subject_required\""));
        assert!(misuse
            .output
            .contains("\"linux_active_probe_admission_profile_invalid\""));

        let mutated = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-admission".to_string(),
            "--json".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
            "--profile=complete".to_string(),
            "--mutate-context".to_string(),
        ]));
        assert_eq!(mutated.exit_code, ExitCode::Deny.code());
        assert!(mutated
            .output
            .contains("\"provider_challenge_context_mutated\""));
        assert!(mutated.output.contains("\"satisfied\": true"));
    }

    #[test]
    fn evidence_linux_active_probe_docker_requires_execute_and_never_authorizes() {
        let args = vec![
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--subject".to_string(),
            "launch-1".to_string(),
            "--context-hash".to_string(),
            "sha256:context".to_string(),
            "--vault-host".to_string(),
            "127.0.0.1:4873".to_string(),
            "--image".to_string(),
            "local/probe:dev".to_string(),
            "--docker-network".to_string(),
            "whoathere-internal".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::EvidenceLinuxActiveProbeDocker {
                json: true,
                execute: false,
                admit: false,
                replay: false,
                subject: Some("launch-1".to_string()),
                context_hash: Some("sha256:context".to_string()),
                vault_host: Some("127.0.0.1:4873".to_string()),
                image: Some("local/probe:dev".to_string()),
                docker_network: Some("whoathere-internal".to_string()),
                replay_store: None,
                audit_path: None
            }
        );
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result
            .output
            .contains("\"command\": \"whoathere evidence linux-active-probe-docker\""));
        assert!(result.output.contains("\"execute_requested\": false"));
        assert!(result.output.contains("\"docker_invoked\": false"));
        assert!(result
            .output
            .contains("\"container_network\": \"whoathere-internal\""));
        assert!(result
            .output
            .contains("\"container_user\": \"65532:65532\""));
        assert!(result
            .output
            .contains("\"network_internal_verified\": null"));
        assert!(result.output.contains("\"image_contract\": null"));
        assert!(result.output.contains("\"image_contract_valid\": false"));
        assert!(result
            .output
            .contains("\"linux_active_probe_docker_execute_required\""));
        assert!(result.output.contains("\"authorization\": false"));
        assert!(result.output.contains("\"proof_minted\": false"));
        assert!(result.output.contains("\"execution_allowed\": false"));
        assert!(result.output.contains("\"admission_applied\": false"));
        assert!(result.output.contains("\"admission\": null"));
        assert!(result.output.contains("\"satisfied\": false"));
    }

    #[test]
    fn evidence_linux_active_probe_docker_requires_explicit_inputs() {
        let result = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
        ]));
        assert_eq!(result.exit_code, ExitCode::Misuse.code());
        assert!(result.output.contains("\"status\": \"error\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_docker_subject_required\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_docker_context_hash_required\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_docker_vault_host_required\""));
    }

    #[test]
    fn evidence_linux_active_probe_docker_admission_binds_replay_guard_without_authorization() {
        let admitted = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(admitted.exit_code, ExitCode::Deny.code());
        assert!(admitted.output.contains("\"admission_applied\": true"));
        assert!(admitted.output.contains("\"preconsume\": null"));
        assert!(admitted.output.contains("\"admission\": {"));
        assert!(admitted.output.contains("\"status\": \"Accepted\""));
        assert!(admitted.output.contains("\"accepted\": false"));
        assert!(admitted
            .output
            .contains("\"linux_active_probe_not_complete\""));
        assert!(admitted
            .output
            .contains("\"linux_active_probe_docker_execute_required\""));
        assert!(admitted.output.contains("\"authorization\": false"));
        assert!(admitted.output.contains("\"proof_minted\": false"));
        assert!(admitted.output.contains("\"execution_allowed\": false"));

        let replay = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--replay".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(replay.exit_code, ExitCode::Deny.code());
        assert!(replay.output.contains("\"preconsume\": {"));
        assert!(replay.output.contains("\"provider_challenge_replayed\""));
        assert!(replay.output.contains("\"accepted\": false"));

        let misuse = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--replay".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(misuse.exit_code, ExitCode::Misuse.code());
        assert!(misuse
            .output
            .contains("\"linux_active_probe_docker_admission_required_for_replay\""));
    }

    #[test]
    fn evidence_linux_active_probe_docker_replay_store_env_applies_only_to_admission() {
        let admitted_args = vec![
            "--json".to_string(),
            "--admit".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ];
        assert_eq!(
            parse_evidence_linux_active_probe_docker_with_env(&admitted_args, |key| match key {
                "WHOATHERE_REPLAY_STORE" => Some("/tmp/env-replay-store.txt".to_string()),
                _ => None,
            }),
            Command::EvidenceLinuxActiveProbeDocker {
                json: true,
                execute: false,
                admit: true,
                replay: false,
                subject: Some("launch-1".to_string()),
                context_hash: Some("sha256:context".to_string()),
                vault_host: Some("127.0.0.1:4873".to_string()),
                image: None,
                docker_network: None,
                replay_store: Some("/tmp/env-replay-store.txt".to_string()),
                audit_path: None
            }
        );

        let diagnostic_args = vec![
            "--json".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ];
        assert_eq!(
            parse_evidence_linux_active_probe_docker_with_env(&diagnostic_args, |key| match key {
                "WHOATHERE_REPLAY_STORE" => Some("/tmp/env-replay-store.txt".to_string()),
                _ => None,
            }),
            Command::EvidenceLinuxActiveProbeDocker {
                json: true,
                execute: false,
                admit: false,
                replay: false,
                subject: Some("launch-1".to_string()),
                context_hash: Some("sha256:context".to_string()),
                vault_host: Some("127.0.0.1:4873".to_string()),
                image: None,
                docker_network: None,
                replay_store: None,
                audit_path: None
            }
        );

        let override_args = vec![
            "--json".to_string(),
            "--admit".to_string(),
            "--replay-store=/tmp/cli-replay-store.txt".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ];
        assert_eq!(
            parse_evidence_linux_active_probe_docker_with_env(&override_args, |key| match key {
                "WHOATHERE_REPLAY_STORE" => Some("/tmp/env-replay-store.txt".to_string()),
                _ => None,
            }),
            Command::EvidenceLinuxActiveProbeDocker {
                json: true,
                execute: false,
                admit: true,
                replay: false,
                subject: Some("launch-1".to_string()),
                context_hash: Some("sha256:context".to_string()),
                vault_host: Some("127.0.0.1:4873".to_string()),
                image: None,
                docker_network: None,
                replay_store: Some("/tmp/cli-replay-store.txt".to_string()),
                audit_path: None
            }
        );
    }

    #[test]
    fn evidence_linux_active_probe_docker_admission_uses_file_replay_store_without_authorization() {
        let root = temp_root("whoathere-docker-replay-store-test");
        let store_path = root.join("replay-store.txt");
        let store_arg = store_path.to_string_lossy().to_string();

        let first = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--replay-store".to_string(),
            store_arg.clone(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(first.exit_code, ExitCode::Deny.code());
        assert!(first.output.contains("\"admission_applied\": true"));
        assert!(first.output.contains("\"replay_store\": {"));
        assert!(first.output.contains("\"configured\": true"));
        assert!(first.output.contains("\"operation\": \"consume\""));
        assert!(first.output.contains("\"available\": true"));
        assert!(first.output.contains("\"status\": \"Accepted\""));
        assert!(first.output.contains("\"accepted\": false"));
        assert!(first
            .output
            .contains("\"linux_active_probe_docker_execute_required\""));
        assert!(first.output.contains("\"authorization\": false"));
        assert!(first.output.contains("\"proof_minted\": false"));
        assert!(first.output.contains("\"execution_allowed\": false"));

        let first_store = std::fs::read_to_string(&store_path).expect("read first store");
        assert!(first_store.contains("whoathere.provider_challenge_replay_store.v1"));
        assert!(first_store.contains("challenge_nonce_digest="));
        assert!(!first_store.contains("proof-nonce-"));
        assert_eq!(first_store.matches("record ").count(), 1);
        assert!(first_store.contains(" consumed=true"));

        let second = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--replay-store".to_string(),
            store_arg.clone(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(second.exit_code, ExitCode::Deny.code());
        assert!(second.output.contains("\"operation\": \"consume\""));
        assert!(second.output.contains("\"available\": true"));
        let second_store = std::fs::read_to_string(&store_path).expect("read second store");
        assert_eq!(second_store.matches("record ").count(), 2);
        assert_eq!(second_store.matches(" consumed=true").count(), 2);

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn evidence_linux_active_probe_docker_replay_store_writes_minimized_audit() {
        let root = temp_root("whoathere-docker-replay-store-audit-test");
        let store_path = root.join("replay-store.txt");
        let audit_path = root.join("audit.jsonl");
        let store_arg = store_path.to_string_lossy().to_string();
        let audit_arg = audit_path.to_string_lossy().to_string();

        let result = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--replay-store".to_string(),
            store_arg.clone(),
            "--audit-path".to_string(),
            audit_arg.clone(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("\"audit\": {"));
        assert!(result.output.contains("\"status\": \"written\""));
        assert!(result.output.contains("\"stale_lock_recovered\": false"));

        let persisted = std::fs::read_to_string(&audit_path).expect("audit jsonl");
        assert!(
            persisted.contains("\"event_id\":\"linux-active-probe-docker-replay-store-admission\"")
        );
        assert!(persisted.contains("\"replay_store_summary\""));
        assert!(persisted.contains("\"operation\":\"consume\""));
        assert!(persisted.contains("\"replay_status\":\"Accepted\""));
        assert!(persisted.contains("\"accepted\":false"));
        assert!(persisted.contains("\"launch_context_hash\":\"sha256:context\""));
        assert!(!persisted.contains("proof-nonce-"));
        assert!(!persisted.contains(&store_arg));
        assert!(!persisted.contains(&audit_arg));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn evidence_linux_active_probe_docker_replay_store_audits_issue_failure() {
        let root = temp_root("whoathere-docker-replay-store-audit-failure-test");
        let store_path = root.join("replay-store.txt");
        let audit_path = root.join("audit.jsonl");
        std::fs::write(&store_path, "not a replay store\n").expect("write corrupt store");
        let store_arg = store_path.to_string_lossy().to_string();
        let audit_arg = audit_path.to_string_lossy().to_string();

        let result = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--replay-store".to_string(),
            store_arg.clone(),
            "--audit-path".to_string(),
            audit_arg.clone(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("\"status\": \"written\""));
        assert!(result
            .output
            .contains("\"linux_active_probe_docker_replay_store_invalid_state\""));

        let persisted = std::fs::read_to_string(&audit_path).expect("audit jsonl");
        assert!(persisted.contains("\"operation\":\"issue\""));
        assert!(persisted.contains("\"available\":false"));
        assert!(persisted.contains("\"replay_status\":\"not_attempted\""));
        assert!(persisted.contains("\"challenge_id\":\"none\""));
        assert!(!persisted.contains("proof-nonce-"));
        assert!(!persisted.contains(&store_arg));
        assert!(!persisted.contains(&audit_arg));

        std::fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn evidence_linux_active_probe_docker_file_replay_store_rejects_replay_and_corruption() {
        let replay_root = temp_root("whoathere-docker-replay-store-replay-test");
        let replay_store_path = replay_root.join("replay-store.txt");
        let replay_store_arg = replay_store_path.to_string_lossy().to_string();
        let replay = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--replay".to_string(),
            "--replay-store".to_string(),
            replay_store_arg,
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(replay.exit_code, ExitCode::Deny.code());
        assert!(replay.output.contains("\"preconsume\": {"));
        assert!(replay.output.contains("\"provider_challenge_replayed\""));
        assert!(replay.output.contains("\"operation\": \"consume\""));
        let replay_store = std::fs::read_to_string(&replay_store_path).expect("read replay store");
        assert_eq!(replay_store.matches("record ").count(), 1);
        assert!(replay_store.contains(" consumed=true"));
        std::fs::remove_dir_all(replay_root).expect("cleanup replay root");

        let corrupt_root = temp_root("whoathere-docker-replay-store-corrupt-test");
        let corrupt_store_path = corrupt_root.join("replay-store.txt");
        std::fs::write(&corrupt_store_path, "not a replay store\n").expect("write corrupt store");
        let corrupt_store_arg = corrupt_store_path.to_string_lossy().to_string();
        let corrupt = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--admit".to_string(),
            "--replay-store".to_string(),
            corrupt_store_arg,
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(corrupt.exit_code, ExitCode::Deny.code());
        assert!(corrupt.output.contains("\"status\": \"fail_closed\""));
        assert!(corrupt.output.contains("\"available\": false"));
        assert!(corrupt
            .output
            .contains("\"linux_active_probe_docker_replay_store_invalid_state\""));
        assert_eq!(
            std::fs::read_to_string(&corrupt_store_path).expect("corrupt store remains"),
            "not a replay store\n"
        );
        std::fs::remove_dir_all(corrupt_root).expect("cleanup corrupt root");

        let misuse = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "linux-active-probe-docker".to_string(),
            "--json".to_string(),
            "--replay-store=/tmp/whoathere-replay-store.txt".to_string(),
            "--subject=launch-1".to_string(),
            "--context-hash=sha256:context".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(misuse.exit_code, ExitCode::Misuse.code());
        assert!(misuse
            .output
            .contains("\"linux_active_probe_docker_admission_required_for_replay_store\""));
    }

    #[test]
    fn linux_active_probe_docker_stdout_records_no_network_limitations() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "127.0.0.1:4873",
            1,
        );
        let evidence = linux_active_probe_docker_evidence_from_stdout(
            &challenge,
            "probe.kernel=Linux\nprobe.uid=65532\nprobe.gid=65532\nprobe.no_new_privs=1\nprobe.seccomp=2\nprobe.userns=user:[4026531837]\nprobe.netns=net:[4026532902]\nprobe.uid_map=0:0:4294967295\nprobe.gid_map=0:0:4294967295\nprobe.userns_unshare=denied\nprobe.cgroup.memory_max=134217728\nprobe.cgroup.pids_max=64\nprobe.cgroup.cpu_max=100000 100000\n",
            false,
        );
        let receipt = linux_active_probe_receipt_from_evidence(&challenge, &evidence);
        assert!(!receipt.satisfied);
        assert_eq!(receipt.target_matches_host, Some(true));
        assert_eq!(receipt.network_namespace_isolated, Some(true));
        assert_eq!(receipt.no_new_privs, Some(true));
        assert_eq!(receipt.seccomp_filter_enforced, Some(true));
        assert_eq!(receipt.cgroup_scoped, Some(true));
        assert_eq!(receipt.user_namespace_isolated, Some(false));
        assert_eq!(receipt.user_namespace_uid.as_deref(), Some("65532"));
        assert_eq!(
            receipt.user_namespace_uid_map.as_deref(),
            Some("0:0:4294967295")
        );
        assert_eq!(
            receipt.nested_user_namespace_attempt.as_deref(),
            Some("denied")
        );
        assert_eq!(receipt.nested_user_namespace_created, Some(false));
        assert_eq!(receipt.default_deny_except_configured_vault, Some(false));
        assert_eq!(
            receipt.denied_destinations.len(),
            challenge.probe_destinations.len()
        );
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_user_namespace_not_isolated".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_default_deny_not_attested".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_vault_probe_denied".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_vault_probe_missing".to_string()));
    }

    #[test]
    fn linux_active_probe_docker_stdout_records_internal_vault_allowance() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "whoathere-vault-fixture:4873",
            1,
        );
        let evidence = linux_active_probe_docker_evidence_from_stdout(
            &challenge,
            "probe.kernel=Linux\nprobe.uid=65532\nprobe.gid=65532\nprobe.no_new_privs=1\nprobe.seccomp=2\nprobe.userns=user:[4026531837]\nprobe.netns=net:[4026532902]\nprobe.uid_map=0:0:4294967295\nprobe.gid_map=0:0:4294967295\nprobe.userns_unshare=denied\nprobe.cgroup.memory_max=134217728\nprobe.cgroup.pids_max=64\nprobe.cgroup.cpu_max=100000 100000\nprobe.vault_connect=allowed\n",
            true,
        );
        let receipt = linux_active_probe_receipt_from_evidence(&challenge, &evidence);
        assert!(!receipt.satisfied);
        assert_eq!(receipt.default_deny_except_configured_vault, Some(true));
        assert_eq!(
            receipt.allowed_destinations,
            vec!["whoathere-vault-fixture:4873".to_string()]
        );
        assert_eq!(
            receipt.denied_destinations.len(),
            challenge.probe_destinations.len() - 1
        );
        assert!(receipt.missing_probe_destinations.is_empty());
        assert!(!receipt
            .reason_codes
            .contains(&"linux_active_probe_default_deny_not_attested".to_string()));
        assert!(!receipt
            .reason_codes
            .contains(&"linux_active_probe_vault_probe_missing".to_string()));
        assert!(receipt
            .reason_codes
            .contains(&"linux_active_probe_user_namespace_not_isolated".to_string()));
    }

    #[test]
    fn linux_active_probe_docker_stdout_accepts_remapped_user_namespace_evidence() {
        let challenge = ProviderVerificationChallenge::new(
            ProofSubject::for_launch("launch-1"),
            "sha256:context",
            "whoathere-vault-fixture:4873",
            1,
        );
        let evidence = linux_active_probe_docker_evidence_from_stdout(
            &challenge,
            "probe.kernel=Linux\nprobe.uid=65532\nprobe.gid=65532\nprobe.no_new_privs=1\nprobe.seccomp=2\nprobe.userns=user:[4026532999]\nprobe.netns=net:[4026533000]\nprobe.uid_map=0:100000:65536\nprobe.gid_map=0:100000:65536\nprobe.userns_unshare=missing\nprobe.cgroup.memory_max=134217728\nprobe.cgroup.pids_max=64\nprobe.cgroup.cpu_max=100000 100000\nprobe.vault_connect=allowed\n",
            true,
        );
        let receipt = linux_active_probe_receipt_from_evidence(&challenge, &evidence);
        assert!(receipt.satisfied);
        assert_eq!(receipt.user_namespace_isolated, Some(true));
        assert_eq!(
            receipt.user_namespace_uid_map.as_deref(),
            Some("0:100000:65536")
        );
        assert_eq!(
            receipt.user_namespace_gid_map.as_deref(),
            Some("0:100000:65536")
        );
        assert_eq!(
            receipt.allowed_destinations,
            vec![challenge.configured_vault_host]
        );
        assert!(receipt.reason_codes.is_empty());
    }

    #[test]
    fn linux_active_probe_docker_run_json_records_image_contract() {
        let run = LinuxActiveProbeDockerRun {
            execute_requested: true,
            image: "whoathere/linux-active-probe:local".to_string(),
            docker_invoked: true,
            container_network: "none".to_string(),
            container_user: LINUX_ACTIVE_PROBE_DOCKER_USER.to_string(),
            network_internal_verified: None,
            no_new_privileges_requested: true,
            cap_drop_all_requested: true,
            configured_vault_probe_attempted: false,
            configured_vault_probe_allowed: false,
            timed_out: false,
            docker_exit_code: Some(0),
            image_contract: Some(LINUX_ACTIVE_PROBE_IMAGE_CONTRACT.to_string()),
            image_contract_valid: true,
            stdout_line_count: 9,
            stderr_byte_count: 0,
            evidence: Vec::new(),
            reason_codes: Vec::new(),
        };
        let output = render_linux_active_probe_docker_run_json(&run);
        assert!(output.contains("\"image\": \"whoathere/linux-active-probe:local\""));
        assert!(output.contains("\"container_user\": \"65532:65532\""));
        assert!(output.contains("\"network_internal_verified\": null"));
        assert!(output.contains("\"configured_vault_probe_attempted\": false"));
        assert!(output.contains("\"configured_vault_probe_allowed\": false"));
        assert!(output.contains("\"image_contract\": \"whoathere-linux-active-probe.v1\""));
        assert!(output.contains("\"image_contract_valid\": true"));
    }

    #[test]
    fn evidence_challenge_evaluates_explicit_current_provider_challenge() {
        let args = vec![
            "evidence".to_string(),
            "challenge".to_string(),
            "--subject".to_string(),
            "launch-sha256-test".to_string(),
            "--context-hash".to_string(),
            "sha256:context-test".to_string(),
            "--vault-host".to_string(),
            "127.0.0.1:4873".to_string(),
        ];
        assert_eq!(
            parse_command(&args),
            Command::EvidenceChallenge {
                json: false,
                provider_scope: ProviderScope::Current,
                subject: Some("launch-sha256-test".to_string()),
                context_hash: Some("sha256:context-test".to_string()),
                vault_host: Some("127.0.0.1:4873".to_string())
            }
        );
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("whoathere evidence challenge"));
        assert!(result.output.contains("provider_scope=current"));
        assert!(result.output.contains("mutation=false"));
        assert!(result.output.contains("status=fail_closed"));
        assert!(result.output.contains("challenge_valid=true"));
        assert!(result.output.contains("challenge_satisfied=false"));
        assert!(result
            .output
            .contains("provider_challenge_egress_probe_missing"));
        assert!(result.output.contains("provider_challenge_proof_not_fresh"));
    }

    #[test]
    fn evidence_challenge_json_reports_fail_closed_attempt() {
        let result = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "challenge".to_string(),
            "--json".to_string(),
            "--scope=macos".to_string(),
            "--subject=launch-sha256-test".to_string(),
            "--context-hash=sha256:context-test".to_string(),
            "--vault-host=127.0.0.1:4873".to_string(),
        ]));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.starts_with("{\n"));
        assert!(result
            .output
            .contains("\"command\": \"whoathere evidence challenge\""));
        assert!(result.output.contains("\"provider_scope\": \"macos\""));
        assert!(result.output.contains("\"provider\": \"macos\""));
        assert!(result.output.contains("\"mutation\": false"));
        assert!(result.output.contains("\"status\": \"fail_closed\""));
        assert!(result.output.contains("\"exit_code\": 20"));
        assert!(result.output.contains("\"challenge\""));
        assert!(result.output.contains("\"probe_destinations\""));
        assert!(result.output.contains("\"registry.npmjs.org\""));
        assert!(result.output.contains("\"127.0.0.1:4873\""));
        assert!(result.output.contains("\"challenge_attempt\""));
        assert!(result.output.contains("\"satisfied\": false"));
    }

    #[test]
    fn evidence_challenge_requires_explicit_subject_context_and_vault() {
        let result = evaluate_command(parse_command(&[
            "evidence".to_string(),
            "challenge".to_string(),
            "--scope=all".to_string(),
            "--json".to_string(),
        ]));
        assert_eq!(result.exit_code, ExitCode::Misuse.code());
        assert!(result.output.contains("\"status\": \"error\""));
        assert!(result
            .output
            .contains("provider_challenge_scope_must_select_one"));
        assert!(result
            .output
            .contains("provider_challenge_subject_required"));
        assert!(result
            .output
            .contains("provider_challenge_context_hash_required"));
        assert!(result
            .output
            .contains("provider_challenge_vault_host_required"));
    }

    #[test]
    fn evidence_providers_require_ready_fails_closed_without_verifiers() {
        let args = vec![
            "evidence".to_string(),
            "providers".to_string(),
            "--json".to_string(),
            "--require-ready".to_string(),
        ];
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("\"require_ready\": true"));
        assert!(result.output.contains("\"provider_scope\": \"all\""));
        assert!(result.output.contains("\"provider_ready\": false"));
        assert!(result.output.contains("\"status\": \"fail_closed\""));
        assert!(result.output.contains("\"exit_code\": 20"));
        assert!(result.output.contains("\"can_verify_now\": false"));
    }

    #[test]
    fn evidence_providers_require_ready_current_scope_still_fails_closed() {
        let args = vec![
            "evidence".to_string(),
            "providers".to_string(),
            "--json".to_string(),
            "--require-ready".to_string(),
            "--scope".to_string(),
            "current".to_string(),
        ];
        let result = evaluate_command(parse_command(&args));
        assert_eq!(result.exit_code, ExitCode::Deny.code());
        assert!(result.output.contains("\"provider_scope\": \"current\""));
        assert!(result.output.contains("\"provider_ready\": false"));
        assert!(result.output.contains("\"status\": \"fail_closed\""));
    }

    #[test]
    fn evidence_providers_invalid_scope_is_misuse() {
        let args = vec![
            "evidence".to_string(),
            "providers".to_string(),
            "--json".to_string(),
            "--scope=windows".to_string(),
        ];
        let command = parse_command(&args);
        assert_eq!(
            command,
            Command::EvidenceProviders {
                json: true,
                require_ready: false,
                provider_scope: ProviderScope::Invalid
            }
        );
        let result = evaluate_command(command);
        assert_eq!(result.exit_code, ExitCode::Misuse.code());
        assert!(result.output.contains("\"status\": \"error\""));
        assert!(result
            .output
            .contains("\"reason_code\": \"invalid_provider_scope\""));
    }

    #[test]
    fn json_string_escapes_control_characters() {
        assert_eq!(
            json_string("token=\"x\"\npath\\value"),
            "\"token=\\\"x\\\"\\npath\\\\value\""
        );
    }

    #[test]
    fn vault_simulation_requires_complete_evidence() {
        let incomplete = render_command(Command::VaultSimulate { complete: false });
        assert!(incomplete.contains("status=fail_closed"));
        assert!(incomplete.contains("mandatory_evidence_incomplete"));

        let complete = render_command(Command::VaultSimulate { complete: true });
        assert!(complete.contains("verdict=Allow"));
        assert!(complete.contains("promoted=true"));
        assert!(complete
            .contains("cache_object_key=blobs/sha256/b7c9f9f9e2f45cf57b4b52a720fd62bfde8c8f7d69dd9f99202a00cb0872599f"));
        assert!(complete.contains("fetch_job_id=fetch-sim-1"));
    }

    #[test]
    fn vault_challenge_simulation_exposes_vault_authority_contract() {
        let output = render_command(Command::VaultChallengeSim {
            replay: false,
            unknown_challenge: false,
            mutate_context: false,
            expired: false,
        });
        assert!(output.contains("whoathere vault challenge-sim"));
        assert!(output.contains("status_code=200"));
        assert!(output.contains("\"authority\":\"vault_challenge_authority.v1\""));
        assert!(output.contains("\"trusted_time_source\":\"vault_server_clock\""));
        assert!(output.contains("\"first_consume_status\":\"Accepted\""));
        assert!(output.contains("\"accepted\":true"));
        assert!(output.contains("\"nonce_present\":true"));
        assert!(output.contains("\"raw_nonce_returned\":false"));
        assert!(!output.contains("proof-nonce-"));
    }

    #[test]
    fn vault_challenge_simulation_fails_closed_for_replay() {
        let args = [
            "vault",
            "challenge-sim",
            "--replay",
            "--expired",
            "--mutate-context",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        assert_eq!(
            parse_command(&args),
            Command::VaultChallengeSim {
                replay: true,
                unknown_challenge: false,
                mutate_context: true,
                expired: true,
            }
        );

        let output = render_command(Command::VaultChallengeSim {
            replay: true,
            unknown_challenge: false,
            mutate_context: false,
            expired: false,
        });
        assert!(output.contains("status_code=409"));
        assert!(output.contains("\"status\":\"fail_closed\""));
        assert!(output.contains("\"replay_consume_status\":\"Rejected\""));
        assert!(output.contains("provider_challenge_replayed"));
        assert!(output.contains("\"exit_code\":20"));
        assert!(!output.contains("proof-nonce-"));
    }

    #[test]
    fn vault_dev_http_healthz_uses_loopback_router() {
        let output = render_command(Command::VaultDevHttp {
            method: "GET".to_string(),
            path: "/healthz".to_string(),
            headers: Vec::new(),
            body: None,
        });
        assert!(output.contains("status_code=200"));
        assert!(output.contains("\"mode\":\"local_dev\""));
    }

    #[test]
    fn vault_dev_http_parses_repeated_headers_and_body() {
        let args = [
            "vault",
            "dev-http",
            "POST",
            "/v1/static-manifest-job-simulations",
            "--header",
            "X-Test-Mode: local",
            "--header=Range: bytes=0-4",
            "manifest=clean_npm",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        assert_eq!(
            parse_command(&args),
            Command::VaultDevHttp {
                method: "POST".to_string(),
                path: "/v1/static-manifest-job-simulations".to_string(),
                headers: vec![
                    "X-Test-Mode: local".to_string(),
                    "Range: bytes=0-4".to_string()
                ],
                body: Some("manifest=clean_npm".to_string()),
            }
        );
    }

    #[test]
    fn vault_dev_http_header_can_exercise_range_without_socket() {
        let output = render_command(Command::VaultDevHttp {
            method: "GET".to_string(),
            path: "/v1/registry-simulations/npm/tarballs/fixture/1.0.0".to_string(),
            headers: vec!["Range: bytes=6-10".to_string()],
            body: None,
        });
        assert!(output.contains("status_code=206"));
        assert!(output.contains("HTTP/1.1 206 Partial Content"));
        assert!(output.contains("Content-Range: bytes 6-10/25"));
        assert!(output.ends_with("cache"));
    }

    #[test]
    fn vault_dev_http_rejects_invalid_or_reserved_headers() {
        let malformed = render_command(Command::VaultDevHttp {
            method: "GET".to_string(),
            path: "/healthz".to_string(),
            headers: vec!["Range bytes=0-4".to_string()],
            body: None,
        });
        assert!(malformed.contains("status=fail_closed"));
        assert!(malformed.contains("dev_http_header_missing_colon"));

        let reserved = render_command(Command::VaultDevHttp {
            method: "GET".to_string(),
            path: "/healthz".to_string(),
            headers: vec!["Content-Length: 999".to_string()],
            body: None,
        });
        assert!(reserved.contains("status=fail_closed"));
        assert!(reserved.contains("dev_http_header_reserved"));
    }

    #[test]
    fn vault_dev_serve_parses_bounded_loopback_options() {
        let args = [
            "vault",
            "dev-serve",
            "--bind",
            "127.0.0.1:0",
            "--max-requests=2",
            "--idle-timeout-ms",
            "5",
        ]
        .into_iter()
        .map(str::to_string)
        .collect::<Vec<_>>();
        assert_eq!(
            parse_command(&args),
            Command::VaultDevServe {
                bind: "127.0.0.1:0".to_string(),
                max_requests: 2,
                idle_timeout_ms: 5,
            }
        );
    }

    #[test]
    fn vault_dev_serve_rejects_zero_max_requests_without_binding() {
        let output = render_command(Command::VaultDevServe {
            bind: "127.0.0.1:0".to_string(),
            max_requests: 0,
            idle_timeout_ms: 1,
        });
        assert!(output.contains("status=fail_closed"));
        assert!(output.contains("dev_server_max_requests_zero"));
        assert!(output.contains("served_requests=0"));
    }

    #[test]
    fn vault_dev_serve_rejects_non_loopback_bind() {
        let output = render_command(Command::VaultDevServe {
            bind: "0.0.0.0:0".to_string(),
            max_requests: 1,
            idle_timeout_ms: 1,
        });
        assert!(output.contains("status=fail_closed"));
        assert!(output.contains("dev_server_bind_not_loopback"));
    }

    #[test]
    fn vault_dev_serve_request_log_renderer_is_sanitized() {
        let output = render_dev_server_request_log(
            0,
            &SanitizedRequestLogEntry {
                method: "GET".to_string(),
                route_kind: "registry_npm_tarball",
                status_code: 206,
                range_state: "served",
                declared_response_body_bytes: 5,
                wire_response_body_bytes: 5,
                request_body_logged: false,
                response_body_logged: false,
            },
        );
        assert!(output.contains("request_log[0].method=GET"));
        assert!(output.contains("request_log[0].route_kind=registry_npm_tarball"));
        assert!(output.contains("request_log[0].status_code=206"));
        assert!(output.contains("request_log[0].range_state=served"));
        assert!(output.contains("request_log[0].declared_response_body_bytes=5"));
        assert!(output.contains("request_log[0].wire_response_body_bytes=5"));
        assert!(output.contains("request_log[0].request_body_logged=false"));
        assert!(output.contains("request_log[0].response_body_logged=false"));
        assert!(!output.contains("Authorization"));
        assert!(!output.contains("inert cache fixture bytes"));
    }

    fn temp_root(prefix: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create temp root");
        root
    }

    fn write_cleanup_manifest_fixture(runtime: &std::path::Path) -> std::path::PathBuf {
        let home = runtime.join("home");
        let xdg = runtime.join("xdg");
        let config = runtime.join("npmrc");
        let manifest = runtime.join(".whoathere-cleanup.manifest");
        std::fs::create_dir_all(&home).expect("create home");
        std::fs::create_dir_all(&xdg).expect("create xdg");
        std::fs::write(&config, "registry=http://127.0.0.1:4873/npm/\n").expect("write config");
        std::fs::write(
            &manifest,
            format!(
                "schema_version=1\ncleanup_lease_id=test-cleanup\nruntime_dir={}\ncleanup_manifest_path={}\nowned_path={}\nowned_path={}\nowned_path={}\nowned_path={}\nowned_path={}\n",
                runtime.display(),
                manifest.display(),
                runtime.display(),
                home.display(),
                xdg.display(),
                config.display(),
                manifest.display()
            ),
        )
        .expect("write cleanup manifest");
        manifest
    }
}
