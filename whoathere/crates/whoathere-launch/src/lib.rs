use std::fs;
use std::path::{Component, Path, PathBuf};

use whoathere_core::{classify_package_command, CommandKind, ExecutionMode, WorkflowRisk};
use whoathere_hash::sha256_digest;
use whoathere_sandbox::{
    CleanupLease, ContainmentProof, EgressProof, ProofSubject, ProviderVerificationChallenge,
};
use whoathere_source::{
    build_sanitized_context, materialize_sanitized_config, scan_workspace, vault_host_port,
    SanitizedExecutionContext, SourceScanReport,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStatus {
    Blocked,
    Planned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchRequest {
    pub tool: String,
    pub args: Vec<String>,
    pub workspace: Option<PathBuf>,
    pub vault_origin: Option<String>,
    pub runtime_dir: Option<PathBuf>,
    pub execute_requested: bool,
    pub proof_validation_time_unix_seconds: u64,
    pub containment_proof: ContainmentProof,
    pub egress_proof: EgressProof,
}

impl LaunchRequest {
    pub fn new(tool: impl Into<String>, args: Vec<String>) -> Self {
        Self {
            tool: tool.into(),
            args,
            workspace: None,
            vault_origin: None,
            runtime_dir: None,
            execute_requested: false,
            proof_validation_time_unix_seconds: 1,
            containment_proof: ContainmentProof::missing(ExecutionMode::CiFailClosed),
            egress_proof: EgressProof::missing(),
        }
    }
}

pub fn preview_launch_context_hash(tool: &str, vault_origin: &str) -> Result<String, String> {
    build_sanitized_context(tool, vault_origin)
        .map(|context| fingerprint_context(&context))
        .map_err(|error| format!("{error:?}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimePlan {
    pub runtime_dir: PathBuf,
    pub home_dir: PathBuf,
    pub xdg_config_dir: PathBuf,
    pub config_path: PathBuf,
    pub cleanup_manifest_path: PathBuf,
    pub config_bytes: usize,
    pub config_permissions_private: bool,
    pub runtime_permissions_private: bool,
    pub home_permissions_private: bool,
    pub xdg_permissions_private: bool,
    pub cleanup_lease_id: String,
    pub cleanup_owned_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchPlan {
    pub status: LaunchStatus,
    pub tool: String,
    pub args: Vec<String>,
    pub command_kind: CommandKind,
    pub risk: WorkflowRisk,
    pub reason_codes: Vec<String>,
    pub source_report: Option<SourceScanReport>,
    pub context: Option<SanitizedExecutionContext>,
    pub launch_context_hash: Option<String>,
    pub source_scan_hash: Option<String>,
    pub runtime: Option<RuntimePlan>,
    pub proof_challenge: Option<ProviderVerificationChallenge>,
    pub containment_proof: ContainmentProof,
    pub egress_proof: EgressProof,
    pub execution_allowed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchExecutionResult {
    pub spawned: bool,
    pub status_code: Option<i32>,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CleanupResult {
    pub attempted: usize,
    pub removed_paths: Vec<String>,
    pub refused_paths: Vec<String>,
    pub reason_codes: Vec<String>,
}

pub fn build_launch_plan(request: &LaunchRequest) -> LaunchPlan {
    let classification = classify_package_command(&request.tool, &request.args);
    let mut plan = LaunchPlan {
        status: LaunchStatus::Blocked,
        tool: request.tool.clone(),
        args: request.args.clone(),
        command_kind: classification.kind,
        risk: classification.risk,
        reason_codes: Vec::new(),
        source_report: None,
        context: None,
        launch_context_hash: None,
        source_scan_hash: None,
        runtime: None,
        proof_challenge: None,
        containment_proof: request.containment_proof.clone(),
        egress_proof: request.egress_proof.clone(),
        execution_allowed: false,
    };

    let Some(vault_origin) = request.vault_origin.as_deref() else {
        plan.reason_codes.push("vault_origin_required".to_string());
        return plan;
    };

    let context = match build_sanitized_context(&request.tool, vault_origin) {
        Ok(context) => context,
        Err(error) => {
            plan.reason_codes.push("invalid_launch_context".to_string());
            plan.reason_codes.push(format!("{error:?}"));
            return plan;
        }
    };
    plan.launch_context_hash = Some(fingerprint_context(&context));
    if let Some(launch_context_hash) = plan.launch_context_hash.as_deref() {
        let configured_vault_host = vault_host_port(vault_origin).unwrap_or_default();
        plan.proof_challenge = Some(ProviderVerificationChallenge::new(
            challenge_subject_for_context(launch_context_hash),
            launch_context_hash,
            configured_vault_host,
            request.proof_validation_time_unix_seconds,
        ));
    }

    if request.execute_requested
        && request.workspace.is_none()
        && classification.risk != WorkflowRisk::Low
    {
        plan.reason_codes
            .push("workspace_required_for_install_launch".to_string());
        plan.context = Some(context);
        return plan;
    }

    if classification.risk != WorkflowRisk::Low && !classification.protected {
        plan.reason_codes
            .push("argv_source_override_blocked".to_string());
        plan.context = Some(context);
        return plan;
    }

    if let Some(workspace) = request.workspace.as_deref() {
        let report = scan_workspace(workspace, vault_origin);
        let source_hash = fingerprint_source_report(&report);
        if report.has_blocking_findings() {
            plan.reason_codes.push("source_scan_blocked".to_string());
            plan.source_scan_hash = Some(source_hash);
            plan.source_report = Some(report);
            plan.context = Some(context);
            return plan;
        }
        plan.source_scan_hash = Some(source_hash);
        plan.source_report = Some(report);
    }

    if classification.risk != WorkflowRisk::Low {
        if !verified_egress_matches_vault(vault_origin, &request.egress_proof) {
            plan.reason_codes
                .push(request.egress_proof.reason_code().to_string());
            plan.reason_codes
                .push("egress_verified_proof_required".to_string());
            plan.context = Some(context);
            return plan;
        }
        if !request.containment_proof.permits_high_risk() {
            plan.reason_codes
                .push(request.containment_proof.reason_code().to_string());
            plan.reason_codes
                .push("containment_verified_proof_required".to_string());
            plan.context = Some(context);
            return plan;
        }
        if !verified_proofs_share_subject(&request.containment_proof, &request.egress_proof) {
            plan.reason_codes.push("proof_subject_mismatch".to_string());
            plan.context = Some(context);
            return plan;
        }
        if !verified_proofs_share_provider_session(
            &request.containment_proof,
            &request.egress_proof,
        ) {
            plan.reason_codes
                .push("proof_provider_session_mismatch".to_string());
            plan.context = Some(context);
            return plan;
        }
        if !verified_proofs_match_launch_context(
            plan.launch_context_hash.as_deref(),
            &request.containment_proof,
            &request.egress_proof,
        ) {
            plan.reason_codes
                .push("proof_context_hash_mismatch".to_string());
            plan.context = Some(context);
            return plan;
        }
        if !verified_proofs_are_fresh_at(
            &request.containment_proof,
            &request.egress_proof,
            request.proof_validation_time_unix_seconds,
        ) {
            plan.reason_codes
                .push("proof_expired_or_not_yet_valid".to_string());
            plan.context = Some(context);
            return plan;
        }
        if !verified_proofs_match_challenge(
            plan.proof_challenge.as_ref(),
            &request.containment_proof,
            &request.egress_proof,
        ) {
            plan.reason_codes
                .push("proof_challenge_subject_mismatch".to_string());
            plan.context = Some(context);
            return plan;
        }
    }

    let context = match request.runtime_dir.as_deref() {
        Some(runtime_dir) => match materialize_runtime(context, runtime_dir) {
            Ok((context, runtime)) => {
                plan.runtime = Some(runtime);
                context
            }
            Err(error) => {
                plan.reason_codes
                    .push("runtime_materialization_failed".to_string());
                plan.reason_codes.push(error);
                return plan;
            }
        },
        None => context,
    };
    plan.context = Some(context);

    if classification.risk == WorkflowRisk::Low {
        plan.status = LaunchStatus::Planned;
        plan.reason_codes
            .push("readonly_launch_delegates_to_runner".to_string());
        return plan;
    }

    plan.status = LaunchStatus::Planned;
    plan.reason_codes
        .push("install_execution_not_enabled".to_string());
    plan
}

pub fn execute_launch_plan(plan: &LaunchPlan) -> LaunchExecutionResult {
    if !plan.execution_allowed {
        return LaunchExecutionResult {
            spawned: false,
            status_code: Some(70),
            reason_code: plan
                .reason_codes
                .first()
                .cloned()
                .unwrap_or_else(|| "launch_execution_not_allowed".to_string()),
        };
    }

    LaunchExecutionResult {
        spawned: false,
        status_code: Some(70),
        reason_code: "launch_execution_not_implemented".to_string(),
    }
}

pub fn cleanup_runtime_plan(runtime: &RuntimePlan) -> CleanupResult {
    let mut result = CleanupResult {
        attempted: runtime.cleanup_owned_paths.len(),
        removed_paths: Vec::new(),
        refused_paths: Vec::new(),
        reason_codes: Vec::new(),
    };

    if !cleanup_root_is_safe(&runtime.runtime_dir) {
        result
            .reason_codes
            .push("cleanup_runtime_root_refused".to_string());
        result
            .refused_paths
            .extend(runtime.cleanup_owned_paths.iter().cloned());
        return result;
    }

    for owned in runtime.cleanup_owned_paths.iter().rev() {
        let path = PathBuf::from(owned);
        if !cleanup_owned_path_is_safe(&path, &runtime.runtime_dir) {
            result
                .reason_codes
                .push("cleanup_path_outside_runtime_refused".to_string());
            result.refused_paths.push(owned.clone());
            continue;
        }
        if !path.exists() {
            result
                .reason_codes
                .push("cleanup_path_already_absent".to_string());
            continue;
        }
        let removed = if path.is_dir() {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_file(&path)
        };
        match removed {
            Ok(()) => result.removed_paths.push(owned.clone()),
            Err(error) => {
                result
                    .reason_codes
                    .push(format!("cleanup_remove_failed:{error}"));
                result.refused_paths.push(owned.clone());
            }
        }
    }

    result
}

pub fn load_cleanup_manifest(manifest_path: &Path) -> Result<RuntimePlan, String> {
    let contents = fs::read_to_string(manifest_path)
        .map_err(|error| format!("cleanup_manifest_read:{error}"))?;
    let mut schema_version = None;
    let mut cleanup_lease_id = None;
    let mut runtime_dir = None;
    let mut cleanup_manifest_path = None;
    let mut cleanup_owned_paths = Vec::new();

    for (line_number, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "cleanup_manifest_invalid_line:{}",
                line_number.saturating_add(1)
            )
        })?;
        let value = unescape_manifest_value(value)?;
        match key {
            "schema_version" => schema_version = Some(value),
            "cleanup_lease_id" => cleanup_lease_id = Some(value),
            "runtime_dir" => runtime_dir = Some(PathBuf::from(value)),
            "cleanup_manifest_path" => cleanup_manifest_path = Some(PathBuf::from(value)),
            "owned_path" => cleanup_owned_paths.push(value),
            _ => return Err(format!("cleanup_manifest_unknown_key:{key}")),
        }
    }

    if schema_version.as_deref() != Some("1") {
        return Err("cleanup_manifest_unsupported_schema".to_string());
    }
    let cleanup_lease_id =
        cleanup_lease_id.ok_or_else(|| "cleanup_manifest_missing_lease".to_string())?;
    let runtime_dir =
        runtime_dir.ok_or_else(|| "cleanup_manifest_missing_runtime_dir".to_string())?;
    let cleanup_manifest_path = cleanup_manifest_path
        .ok_or_else(|| "cleanup_manifest_missing_manifest_path".to_string())?;
    if cleanup_owned_paths.is_empty() {
        return Err("cleanup_manifest_missing_owned_paths".to_string());
    }
    if !manifest_path.starts_with(&runtime_dir) || cleanup_manifest_path != manifest_path {
        return Err("cleanup_manifest_path_mismatch".to_string());
    }
    if !cleanup_owned_paths
        .iter()
        .any(|owned| Path::new(owned) == cleanup_manifest_path)
    {
        return Err("cleanup_manifest_not_owned".to_string());
    }

    let home_dir = runtime_dir.join("home");
    let xdg_config_dir = runtime_dir.join("xdg");
    let config_path = cleanup_owned_paths
        .iter()
        .map(PathBuf::from)
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == "npmrc" || name == "pip.conf")
        })
        .unwrap_or_else(|| runtime_dir.join("config"));
    let config_bytes = fs::metadata(&config_path)
        .map(|metadata| metadata.len() as usize)
        .unwrap_or(0);

    Ok(RuntimePlan {
        runtime_dir: runtime_dir.clone(),
        home_dir: home_dir.clone(),
        xdg_config_dir: xdg_config_dir.clone(),
        config_path: config_path.clone(),
        cleanup_manifest_path,
        config_bytes,
        config_permissions_private: private_file_permissions(&config_path),
        runtime_permissions_private: private_dir_permissions(&runtime_dir),
        home_permissions_private: private_dir_permissions(&home_dir),
        xdg_permissions_private: private_dir_permissions(&xdg_config_dir),
        cleanup_lease_id,
        cleanup_owned_paths,
    })
}

fn fingerprint_context(context: &SanitizedExecutionContext) -> String {
    let mut parts = vec![
        "context:v1".to_string(),
        context.tool.clone(),
        context.vault_origin.clone(),
        context.env_clear.to_string(),
        context.generated_config_path.clone(),
        context.generated_config_contents.clone(),
        context.egress_boundary_required.to_string(),
    ];
    for (key, value) in &context.env {
        parts.push(format!("env:{key}={value}"));
    }
    for arg in &context.args {
        parts.push(format!("arg:{arg}"));
    }
    for name in &context.scrubbed_env_names {
        parts.push(format!("scrub-name:{name}"));
    }
    for prefix in &context.scrubbed_env_prefixes {
        parts.push(format!("scrub-prefix:{prefix}"));
    }
    fingerprint_parts(&parts)
}

fn fingerprint_source_report(report: &SourceScanReport) -> String {
    let mut parts = vec![
        "source-report:v1".to_string(),
        format!("files:{}", report.files_scanned),
    ];
    let mut findings = report
        .findings
        .iter()
        .map(|finding| {
            format!(
                "finding:{}:{:?}:{}:{}",
                finding.file, finding.severity, finding.reason_code, finding.detail
            )
        })
        .collect::<Vec<_>>();
    findings.sort();
    parts.extend(findings);
    fingerprint_parts(&parts)
}

fn challenge_subject_for_context(launch_context_hash: &str) -> ProofSubject {
    let suffix = launch_context_hash
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    ProofSubject::for_launch(format!("launch-{suffix}"))
}

fn fingerprint_parts(parts: &[String]) -> String {
    let mut bytes = Vec::new();
    for part in parts {
        bytes.extend_from_slice(part.as_bytes());
        bytes.push(0xff);
    }
    sha256_digest(&bytes)
}

fn cleanup_root_is_safe(runtime_dir: &Path) -> bool {
    let temp_dir = std::env::temp_dir();
    runtime_dir.starts_with(&temp_dir)
        && runtime_dir
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("whoathere"))
}

fn cleanup_owned_path_is_safe(path: &Path, runtime_dir: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        && path.starts_with(runtime_dir)
}

fn materialize_runtime(
    context: SanitizedExecutionContext,
    runtime_dir: &Path,
) -> Result<(SanitizedExecutionContext, RuntimePlan), String> {
    create_private_dir(runtime_dir).map_err(|error| format!("create_runtime_dir:{error}"))?;
    let home_dir = runtime_dir.join("home");
    let xdg_config_dir = runtime_dir.join("xdg");
    create_private_dir(&home_dir).map_err(|error| format!("create_home_dir:{error}"))?;
    create_private_dir(&xdg_config_dir).map_err(|error| format!("create_xdg_dir:{error}"))?;

    let materialized = materialize_sanitized_config(&context, runtime_dir)
        .map_err(|error| format!("write_config:{error}"))?;
    let context = concretize_context(context, runtime_dir, &home_dir, &materialized.config_path);
    let mut cleanup_lease = CleanupLease::new(format!(
        "launch-{}",
        runtime_dir
            .file_name()
            .map(|name| name.to_string_lossy())
            .unwrap_or_else(|| "runtime".into())
    ));
    cleanup_lease.track_path(runtime_dir.display().to_string());
    cleanup_lease.track_path(home_dir.display().to_string());
    cleanup_lease.track_path(xdg_config_dir.display().to_string());
    cleanup_lease.track_path(materialized.config_path.display().to_string());
    let cleanup_manifest_path = runtime_dir.join(".whoathere-cleanup.manifest");
    cleanup_lease.track_path(cleanup_manifest_path.display().to_string());
    let runtime = RuntimePlan {
        runtime_dir: runtime_dir.to_path_buf(),
        home_dir,
        xdg_config_dir,
        config_path: materialized.config_path,
        cleanup_manifest_path,
        config_bytes: materialized.bytes_written,
        config_permissions_private: materialized.permissions_private,
        runtime_permissions_private: private_dir_permissions(runtime_dir),
        home_permissions_private: private_dir_permissions(&runtime_dir.join("home")),
        xdg_permissions_private: private_dir_permissions(&runtime_dir.join("xdg")),
        cleanup_lease_id: cleanup_lease.lease_id,
        cleanup_owned_paths: cleanup_lease.owned_paths,
    };
    write_cleanup_manifest(&runtime)?;
    Ok((context, runtime))
}

fn write_cleanup_manifest(runtime: &RuntimePlan) -> Result<(), String> {
    let mut contents = String::new();
    contents.push_str("schema_version=1\n");
    contents.push_str(&format!(
        "cleanup_lease_id={}\n",
        escape_manifest_value(&runtime.cleanup_lease_id)
    ));
    contents.push_str(&format!(
        "runtime_dir={}\n",
        escape_manifest_value(&runtime.runtime_dir.display().to_string())
    ));
    contents.push_str(&format!(
        "cleanup_manifest_path={}\n",
        escape_manifest_value(&runtime.cleanup_manifest_path.display().to_string())
    ));
    for owned in &runtime.cleanup_owned_paths {
        contents.push_str(&format!("owned_path={}\n", escape_manifest_value(owned)));
    }
    fs::write(&runtime.cleanup_manifest_path, contents)
        .map_err(|error| format!("write_cleanup_manifest:{error}"))?;
    set_private_file_permissions(&runtime.cleanup_manifest_path)
        .map_err(|error| format!("chmod_cleanup_manifest:{error}"))
}

fn escape_manifest_value(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn unescape_manifest_value(value: &str) -> Result<String, String> {
    let mut unescaped = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            unescaped.push(ch);
            continue;
        }
        let Some(next) = chars.next() else {
            return Err("cleanup_manifest_bad_escape".to_string());
        };
        match next {
            '\\' => unescaped.push('\\'),
            'n' => unescaped.push('\n'),
            'r' => unescaped.push('\r'),
            't' => unescaped.push('\t'),
            _ => return Err("cleanup_manifest_bad_escape".to_string()),
        }
    }
    Ok(unescaped)
}

fn concretize_context(
    mut context: SanitizedExecutionContext,
    runtime_dir: &Path,
    home_dir: &Path,
    config_path: &Path,
) -> SanitizedExecutionContext {
    let runtime = runtime_dir.display().to_string();
    let home = home_dir.display().to_string();
    let config = config_path.display().to_string();
    for (_, value) in &mut context.env {
        *value = value
            .replace("<whoathere-runtime-home>", &home)
            .replace("<whoathere-runtime>/npmrc", &config)
            .replace("<whoathere-runtime>/pip.conf", &config)
            .replace("<whoathere-runtime>", &runtime);
    }
    for value in &mut context.args {
        *value = value
            .replace("<whoathere-runtime-home>", &home)
            .replace("<whoathere-runtime>/npmrc", &config)
            .replace("<whoathere-runtime>/pip.conf", &config)
            .replace("<whoathere-runtime>", &runtime);
    }
    context.generated_config_path = config;
    context
}

fn verified_egress_matches_vault(vault_origin: &str, proof: &EgressProof) -> bool {
    let Some(host) = vault_host_port(vault_origin) else {
        return false;
    };
    proof.configured_vault_host() == host && proof.permits_only_configured_vault()
}

fn verified_proofs_share_subject(containment: &ContainmentProof, egress: &EgressProof) -> bool {
    containment.subject().is_bound()
        && containment.subject() == egress.subject()
        && egress.subject().is_bound()
}

fn verified_proofs_match_launch_context(
    launch_context_hash: Option<&str>,
    containment: &ContainmentProof,
    egress: &EgressProof,
) -> bool {
    let Some(launch_context_hash) = launch_context_hash else {
        return false;
    };
    containment.provenance().context_hash == launch_context_hash
        && egress.provenance().context_hash == launch_context_hash
}

fn verified_proofs_share_provider_session(
    containment: &ContainmentProof,
    egress: &EgressProof,
) -> bool {
    let containment_provenance = containment.provenance();
    let egress_provenance = egress.provenance();
    !containment_provenance.provider_id.is_empty()
        && containment_provenance.provider_id == egress_provenance.provider_id
        && containment_provenance.platform == egress_provenance.platform
        && containment_provenance.rule_generation_id == egress_provenance.rule_generation_id
}

fn verified_proofs_are_fresh_at(
    containment: &ContainmentProof,
    egress: &EgressProof,
    validation_time_unix_seconds: u64,
) -> bool {
    containment.fresh_at(validation_time_unix_seconds)
        && egress.fresh_at(validation_time_unix_seconds)
}

fn verified_proofs_match_challenge(
    challenge: Option<&ProviderVerificationChallenge>,
    containment: &ContainmentProof,
    egress: &EgressProof,
) -> bool {
    let Some(challenge) = challenge else {
        return false;
    };
    challenge.valid()
        && containment.subject() == &challenge.subject
        && egress.subject() == &challenge.subject
}

fn create_private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_file_permissions(path: &Path) -> std::io::Result<()> {
    let _ = fs::metadata(path)?;
    Ok(())
}

#[cfg(unix)]
fn private_dir_permissions(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777 == 0o700)
        .unwrap_or(false)
}

#[cfg(unix)]
fn private_file_permissions(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn private_dir_permissions(path: &Path) -> bool {
    path.is_dir()
}

#[cfg(not(unix))]
fn private_file_permissions(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use whoathere_sandbox::test_support::{
        expired_containment_for_context as test_expired_containment_for_context,
        expired_egress_for_context as test_expired_egress_for_context,
        verified_containment_for_context as test_verified_containment_for_context,
        verified_containment_for_context_and_rule as test_verified_containment_for_context_and_rule,
        verified_egress_for_context as test_verified_egress_for_context,
        verified_egress_for_context_and_rule as test_verified_egress_for_context_and_rule,
        TestOnlyProofProvider,
    };
    use whoathere_sandbox::ProofProvider;

    const VAULT: &str = "http://127.0.0.1:4873";

    #[test]
    fn missing_vault_origin_blocks_before_runtime_materialization() {
        let runtime = temp_root("whoathere-launch-missing-vault");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: None,
            vault_origin: None,
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment(),
            egress_proof: verified_egress(),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"vault_origin_required".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
    }

    #[test]
    fn unsafe_source_blocks_and_does_not_materialize_runtime() {
        let workspace = temp_root("whoathere-launch-unsafe-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-unsafe-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment(),
            egress_proof: verified_egress(),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"source_scan_blocked".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn clean_workspace_missing_egress_proof_does_not_materialize_runtime() {
        let workspace = temp_root("whoathere-launch-clean-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-clean-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment(),
            egress_proof: EgressProof::missing(),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"egress_verified_proof_required".to_string()));
        let challenge = plan
            .proof_challenge
            .as_ref()
            .expect("launch context should produce provider challenge");
        assert!(challenge.valid());
        assert!(challenge
            .challenge_id
            .starts_with("proof-challenge-sha256:"));
        assert_eq!(challenge.configured_vault_host, "127.0.0.1:4873");
        assert!(challenge.context_hash.starts_with("sha256:"));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn egress_without_containment_still_blocks() {
        let workspace = temp_root("whoathere-launch-containment-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: None,
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: ContainmentProof::missing(ExecutionMode::CiFailClosed),
            egress_proof: verified_egress(),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"containment_verified_proof_required".to_string()));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn argv_source_override_blocks_before_runtime_materialization() {
        let workspace = temp_root("whoathere-launch-argv-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-argv-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec![
                "ci".to_string(),
                "--registry=https://registry.npmjs.org".to_string(),
            ],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment(),
            egress_proof: verified_egress(),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"argv_source_override_blocked".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn all_gates_present_plans_but_keeps_install_execution_disabled() {
        let workspace = temp_root("whoathere-launch-all-gates-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-all-gates-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment(),
            egress_proof: verified_egress(),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Planned);
        assert!(plan
            .launch_context_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert!(plan
            .source_scan_hash
            .as_deref()
            .is_some_and(|hash| hash.starts_with("sha256:")));
        assert!(!plan.execution_allowed);
        assert!(plan
            .reason_codes
            .contains(&"install_execution_not_enabled".to_string()));
        let runtime_plan = plan.runtime.expect("runtime should materialize");
        assert!(runtime_plan.config_permissions_private);
        assert!(runtime_plan.runtime_permissions_private);
        assert!(runtime_plan.home_permissions_private);
        assert!(runtime_plan.xdg_permissions_private);
        assert!(runtime_plan.config_path.ends_with("npmrc"));
        assert!(runtime_plan.cleanup_manifest_path.exists());
        assert!(private_file_permissions(
            &runtime_plan.cleanup_manifest_path
        ));
        assert!(runtime_plan
            .cleanup_owned_paths
            .iter()
            .any(|path| path == &runtime_plan.config_path.display().to_string()));
        assert!(runtime_plan
            .cleanup_owned_paths
            .iter()
            .any(|path| path == &runtime_plan.cleanup_manifest_path.display().to_string()));
        let context = plan.context.expect("context");
        assert!(context
            .env
            .iter()
            .all(|(_, value)| !value.contains("<whoathere-runtime>")));
        assert!(context
            .args
            .iter()
            .all(|value| !value.contains("<whoathere-runtime>")));
        let contents = fs::read_to_string(runtime_plan.config_path).expect("read config");
        assert!(contents.contains("http://127.0.0.1:4873/npm/"));
        assert!(!contents.contains("registry.npmjs.org"));
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&runtime);
    }

    #[test]
    fn test_only_provider_harness_materializes_runtime_without_enabling_install() {
        let workspace = temp_root("whoathere-launch-provider-harness-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-provider-harness-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let context_hash = test_launch_context_hash();
        let subject = challenge_subject_for_context(&context_hash);
        let provider = TestOnlyProofProvider::new_for_context(
            subject.launch_id.clone(),
            "127.0.0.1:4873",
            &context_hash,
        );
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: provider.prove_containment(ExecutionMode::CiFailClosed),
            egress_proof: provider.prove_egress(subject, "127.0.0.1:4873", &["127.0.0.1:4873"]),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Planned);
        assert!(!plan.execution_allowed);
        assert!(plan
            .reason_codes
            .contains(&"install_execution_not_enabled".to_string()));
        let execution = execute_launch_plan(&plan);
        assert!(!execution.spawned);
        assert_eq!(execution.reason_code, "install_execution_not_enabled");
        let runtime_plan = plan.runtime.expect("runtime should materialize");
        assert!(runtime_plan.cleanup_manifest_path.exists());
        let cleanup = cleanup_runtime_plan(&runtime_plan);
        assert!(cleanup.refused_paths.is_empty());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn cleanup_runtime_plan_removes_owned_temp_paths() {
        let workspace = temp_root("whoathere-launch-cleanup-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-cleanup-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment(),
            egress_proof: verified_egress(),
        };
        let plan = build_launch_plan(&request);
        let runtime_plan = plan.runtime.expect("runtime should materialize");
        assert!(runtime_plan.config_path.exists());
        assert!(runtime_plan.cleanup_manifest_path.exists());
        let loaded =
            load_cleanup_manifest(&runtime_plan.cleanup_manifest_path).expect("load manifest");
        assert_eq!(loaded.cleanup_lease_id, runtime_plan.cleanup_lease_id);
        assert_eq!(loaded.cleanup_owned_paths, runtime_plan.cleanup_owned_paths);
        let cleanup = cleanup_runtime_plan(&runtime_plan);
        assert!(cleanup.refused_paths.is_empty());
        assert!(cleanup
            .removed_paths
            .contains(&runtime_plan.config_path.display().to_string()));
        assert!(cleanup
            .removed_paths
            .contains(&runtime_plan.cleanup_manifest_path.display().to_string()));
        assert!(!runtime_plan.runtime_dir.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn cleanup_runtime_plan_refuses_non_whoathere_temp_root() {
        let root = temp_root("not-owned-runtime");
        let config = root.join("npmrc");
        fs::write(&config, "registry=http://127.0.0.1:4873/npm/\n").expect("write config");
        let runtime = RuntimePlan {
            runtime_dir: root.clone(),
            home_dir: root.join("home"),
            xdg_config_dir: root.join("xdg"),
            config_path: config.clone(),
            cleanup_manifest_path: root.join(".whoathere-cleanup.manifest"),
            config_bytes: 39,
            config_permissions_private: false,
            runtime_permissions_private: false,
            home_permissions_private: false,
            xdg_permissions_private: false,
            cleanup_lease_id: "manual-test".to_string(),
            cleanup_owned_paths: vec![config.display().to_string(), root.display().to_string()],
        };
        let cleanup = cleanup_runtime_plan(&runtime);
        assert!(cleanup.removed_paths.is_empty());
        assert_eq!(cleanup.refused_paths.len(), 2);
        assert!(root.exists());
        assert!(config.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn cleanup_runtime_plan_refuses_parent_dir_escape() {
        let root = temp_root("whoathere-launch-cleanup-escape");
        let outside = std::env::temp_dir().join(format!(
            "whoathere-launch-cleanup-outside-{}",
            std::process::id()
        ));
        fs::write(&outside, "do not delete").expect("write outside file");
        let escaped = root.join("..").join(
            outside
                .file_name()
                .expect("outside file name")
                .to_string_lossy()
                .as_ref(),
        );
        let runtime = RuntimePlan {
            runtime_dir: root.clone(),
            home_dir: root.join("home"),
            xdg_config_dir: root.join("xdg"),
            config_path: root.join("npmrc"),
            cleanup_manifest_path: root.join(".whoathere-cleanup.manifest"),
            config_bytes: 0,
            config_permissions_private: false,
            runtime_permissions_private: true,
            home_permissions_private: false,
            xdg_permissions_private: false,
            cleanup_lease_id: "manual-test".to_string(),
            cleanup_owned_paths: vec![escaped.display().to_string()],
        };
        let cleanup = cleanup_runtime_plan(&runtime);
        assert!(cleanup.removed_paths.is_empty());
        assert_eq!(cleanup.refused_paths, vec![escaped.display().to_string()]);
        assert!(cleanup
            .reason_codes
            .contains(&"cleanup_path_outside_runtime_refused".to_string()));
        assert!(outside.exists());
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_file(&outside);
    }

    #[test]
    fn mismatched_proof_subjects_block_before_runtime_materialization() {
        let workspace = temp_root("whoathere-launch-subject-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-subject-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment_for(
                "launch-containment",
                &test_launch_context_hash(),
            ),
            egress_proof: verified_egress_for(
                "launch-egress",
                "127.0.0.1:4873",
                &test_launch_context_hash(),
            ),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"proof_subject_mismatch".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn shared_non_challenge_subject_blocks_before_runtime_materialization() {
        let workspace = temp_root("whoathere-launch-challenge-subject-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-challenge-subject-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let context_hash = test_launch_context_hash();
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment_for(
                "launch-shared-but-not-challenge",
                &context_hash,
            ),
            egress_proof: verified_egress_for(
                "launch-shared-but-not-challenge",
                "127.0.0.1:4873",
                &context_hash,
            ),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"proof_challenge_subject_mismatch".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn mismatched_provider_session_blocks_before_runtime_materialization() {
        let workspace = temp_root("whoathere-launch-provider-session-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-provider-session-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let context_hash = test_launch_context_hash();
        let subject = challenge_subject_for_context(&context_hash).launch_id;
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: test_verified_containment_for_context_and_rule(
                &subject,
                &context_hash,
                "containment-rule-generation",
            ),
            egress_proof: test_verified_egress_for_context_and_rule(
                &subject,
                "127.0.0.1:4873",
                &context_hash,
                "egress-rule-generation",
            ),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"proof_provider_session_mismatch".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn wrong_vault_egress_proof_blocks_before_runtime_materialization() {
        let workspace = temp_root("whoathere-launch-wrong-vault-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-wrong-vault-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment(),
            egress_proof: verified_egress_for(
                "launch-unit-test-subject",
                "127.0.0.1:4888",
                &test_launch_context_hash(),
            ),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"egress_verified_proof_required".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn stale_proofs_block_before_runtime_materialization() {
        let workspace = temp_root("whoathere-launch-stale-proof-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-stale-proof-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 3,
            containment_proof: expired_containment_for(
                "launch-unit-test-subject",
                &test_launch_context_hash(),
            ),
            egress_proof: expired_egress_for(
                "launch-unit-test-subject",
                "127.0.0.1:4873",
                &test_launch_context_hash(),
            ),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"proof_expired_or_not_yet_valid".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn proof_context_hash_mismatch_blocks_before_runtime_materialization() {
        let workspace = temp_root("whoathere-launch-context-mismatch-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let runtime = temp_root("whoathere-launch-context-mismatch-runtime");
        let _ = fs::remove_dir_all(&runtime);
        let request = LaunchRequest {
            tool: "npm".to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: Some(runtime.clone()),
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: verified_containment_for(
                "launch-unit-test-subject",
                "sha256:stale-context",
            ),
            egress_proof: verified_egress_for(
                "launch-unit-test-subject",
                "127.0.0.1:4873",
                "sha256:stale-context",
            ),
        };
        let plan = build_launch_plan(&request);
        assert_eq!(plan.status, LaunchStatus::Blocked);
        assert!(plan
            .reason_codes
            .contains(&"proof_context_hash_mismatch".to_string()));
        assert!(plan.runtime.is_none());
        assert!(!runtime.exists());
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn refused_launch_plan_never_spawns_fake_package_manager() {
        let workspace = temp_root("whoathere-launch-fake-workspace");
        fs::write(
            workspace.join(".npmrc"),
            "registry=http://127.0.0.1:4873/npm/\n",
        )
        .expect("write npmrc");
        let fake_dir = temp_root("whoathere-launch-fake-bin");
        let marker = fake_dir.join("spawned-marker");
        let fake_tool = fake_dir.join(if cfg!(windows) { "npm.cmd" } else { "npm" });
        fs::write(&fake_tool, fake_package_manager_body(&marker)).expect("write fake tool");
        make_executable(&fake_tool);

        let request = LaunchRequest {
            tool: fake_tool.display().to_string(),
            args: vec!["ci".to_string()],
            workspace: Some(workspace.clone()),
            vault_origin: Some(VAULT.to_string()),
            runtime_dir: None,
            execute_requested: true,
            proof_validation_time_unix_seconds: 1,
            containment_proof: ContainmentProof::missing(ExecutionMode::CiFailClosed),
            egress_proof: EgressProof::missing(),
        };
        let plan = build_launch_plan(&request);
        let result = execute_launch_plan(&plan);
        assert!(!result.spawned);
        assert!(!marker.exists());
        let _ = fs::remove_dir_all(&workspace);
        let _ = fs::remove_dir_all(&fake_dir);
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create root");
        root
    }

    fn verified_containment() -> ContainmentProof {
        let context_hash = test_launch_context_hash();
        verified_containment_for(
            &challenge_subject_for_context(&context_hash).launch_id,
            &context_hash,
        )
    }

    fn verified_containment_for(subject: &str, context_hash: &str) -> ContainmentProof {
        test_verified_containment_for_context(subject, context_hash)
    }

    fn verified_egress() -> EgressProof {
        let context_hash = test_launch_context_hash();
        verified_egress_for(
            &challenge_subject_for_context(&context_hash).launch_id,
            "127.0.0.1:4873",
            &context_hash,
        )
    }

    fn verified_egress_for(subject: &str, vault_host: &str, context_hash: &str) -> EgressProof {
        test_verified_egress_for_context(subject, vault_host, context_hash)
    }

    fn expired_containment_for(subject: &str, context_hash: &str) -> ContainmentProof {
        test_expired_containment_for_context(subject, context_hash)
    }

    fn expired_egress_for(subject: &str, vault_host: &str, context_hash: &str) -> EgressProof {
        test_expired_egress_for_context(subject, vault_host, context_hash)
    }

    fn test_launch_context_hash() -> String {
        preview_launch_context_hash("npm", VAULT).expect("preview launch context hash")
    }

    fn fake_package_manager_body(marker: &Path) -> String {
        if cfg!(windows) {
            format!("@echo off\necho spawned>{}\n", marker.display())
        } else {
            format!("#!/bin/sh\necho spawned > '{}'\n", marker.display())
        }
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}
}
