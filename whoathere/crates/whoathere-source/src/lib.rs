use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFileKind {
    NpmRc,
    PipConfig,
    PackageLock,
    PackageJson,
    Requirements,
    PyProjectToml,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingSeverity {
    Info,
    Suspicious,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFinding {
    pub file: String,
    pub severity: FindingSeverity,
    pub reason_code: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceScanReport {
    pub files_scanned: usize,
    pub findings: Vec<SourceFinding>,
}

impl SourceScanReport {
    pub fn empty() -> Self {
        Self {
            files_scanned: 0,
            findings: Vec::new(),
        }
    }

    pub fn has_blocking_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::High)
    }

    pub fn merge(&mut self, other: SourceScanReport) {
        self.files_scanned += other.files_scanned;
        self.findings.extend(other.findings);
    }

    fn push(&mut self, file: &str, severity: FindingSeverity, reason_code: &str, detail: &str) {
        self.findings.push(SourceFinding {
            file: file.to_string(),
            severity,
            reason_code: reason_code.to_string(),
            detail: detail.to_string(),
        });
    }

    fn push_high(&mut self, file: &str, reason_code: &str, detail: &str) {
        self.push(file, FindingSeverity::High, reason_code, detail);
    }

    fn push_suspicious(&mut self, file: &str, reason_code: &str, detail: &str) {
        self.push(file, FindingSeverity::Suspicious, reason_code, detail);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextError {
    InvalidVaultOrigin(String),
    UnsupportedTool(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedExecutionContext {
    pub tool: String,
    pub vault_origin: String,
    pub env_clear: bool,
    pub env: Vec<(String, String)>,
    pub args: Vec<String>,
    pub scrubbed_env_names: Vec<String>,
    pub scrubbed_env_prefixes: Vec<String>,
    pub generated_config_path: String,
    pub generated_config_contents: String,
    pub egress_boundary_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaterializedContext {
    pub config_path: PathBuf,
    pub bytes_written: usize,
    pub permissions_private: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageIdentityEcosystem {
    Npm,
    Python,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageIdentitySourceKind {
    PublicRegistry,
    DirectUrl,
    Git,
    LocalPath,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIdentity {
    pub ecosystem: PackageIdentityEcosystem,
    pub source_kind: PackageIdentitySourceKind,
    pub file: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageIdentityReport {
    pub files_scanned: usize,
    pub identities: Vec<PackageIdentity>,
    pub findings: Vec<SourceFinding>,
}

impl PackageIdentityReport {
    pub fn empty() -> Self {
        Self {
            files_scanned: 0,
            identities: Vec::new(),
            findings: Vec::new(),
        }
    }

    pub fn has_blocking_findings(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == FindingSeverity::High)
    }

    pub fn merge(&mut self, other: PackageIdentityReport) {
        self.files_scanned += other.files_scanned;
        for identity in other.identities {
            self.push_identity(identity);
        }
        self.findings.extend(other.findings);
    }

    pub fn push_identity(&mut self, identity: PackageIdentity) {
        if !self.identities.iter().any(|existing| existing == &identity) {
            self.identities.push(identity);
        }
    }

    fn push_high(&mut self, file: &str, reason_code: &str, detail: &str) {
        self.findings.push(SourceFinding {
            file: file.to_string(),
            severity: FindingSeverity::High,
            reason_code: reason_code.to_string(),
            detail: detail.to_string(),
        });
    }
}

pub fn scan_workspace(root: &Path, vault_origin: &str) -> SourceScanReport {
    let origin = match normalize_vault_origin(vault_origin) {
        Ok(origin) => origin,
        Err(error) => return invalid_origin_report(error),
    };

    let mut report = SourceScanReport::empty();
    let mut scanned_requirements = HashSet::new();
    for (relative, kind) in known_source_files() {
        if kind == SourceFileKind::Requirements {
            let path = root.join(relative);
            if path.exists() {
                report.merge(scan_requirements_file(
                    root,
                    relative,
                    &origin,
                    &mut scanned_requirements,
                ));
            }
            continue;
        }

        let path = root.join(relative);
        match read_workspace_file(root, relative) {
            Ok(contents) => report.merge(scan_source_contents_with_origin(
                relative, kind, &contents, &origin,
            )),
            Err(WorkspaceReadError::EscapesWorkspace) => report.push_high(
                relative,
                "source_file_path_traversal",
                "source file path escapes the scanned workspace",
            ),
            Err(WorkspaceReadError::Io(error)) if path.exists() => report.push_high(
                relative,
                "source_file_read_failed",
                &format!("source file could not be read: {error}"),
            ),
            Err(WorkspaceReadError::Io(_)) => {}
        }
    }
    report
}

pub fn discover_package_identities(root: &Path) -> PackageIdentityReport {
    let mut report = discover_package_identities_for_ecosystem(root, PackageIdentityEcosystem::Npm);
    report.merge(discover_package_identities_for_ecosystem(
        root,
        PackageIdentityEcosystem::Python,
    ));
    report
}

pub fn discover_package_identities_for_ecosystem(
    root: &Path,
    ecosystem: PackageIdentityEcosystem,
) -> PackageIdentityReport {
    match ecosystem {
        PackageIdentityEcosystem::Npm => discover_package_identities_from_files(
            root,
            &[("package.json", SourceFileKind::PackageJson)],
        ),
        PackageIdentityEcosystem::Python => {
            let mut report = PackageIdentityReport::empty();
            for relative in ["requirements.txt", "requirements-dev.txt"] {
                if root.join(relative).exists() {
                    report.merge(discover_requirements_identities(root, relative));
                }
            }
            report.merge(discover_package_identities_from_files(
                root,
                &[("pyproject.toml", SourceFileKind::PyProjectToml)],
            ));
            report
        }
    }
}

fn discover_package_identities_from_files(
    root: &Path,
    files: &[(&'static str, SourceFileKind)],
) -> PackageIdentityReport {
    let mut report = PackageIdentityReport::empty();
    for (relative, kind) in files {
        let path = root.join(relative);
        match read_workspace_file(root, relative) {
            Ok(contents) => report.merge(extract_package_identities(relative, *kind, &contents)),
            Err(WorkspaceReadError::EscapesWorkspace) => report.push_high(
                relative,
                "package_identity_manifest_path_traversal",
                "package identity manifest escapes the scanned workspace",
            ),
            Err(WorkspaceReadError::Io(error)) if path.exists() => report.push_high(
                relative,
                "package_identity_manifest_read_failed",
                &format!("package identity manifest could not be read: {error}"),
            ),
            Err(WorkspaceReadError::Io(_)) => {}
        }
    }
    report
}

pub fn discover_requirements_identities(root: &Path, relative: &str) -> PackageIdentityReport {
    let mut seen = HashSet::new();
    discover_requirements_identity_file(root, relative, &mut seen)
}

fn discover_requirements_identity_file(
    root: &Path,
    relative: &str,
    seen: &mut HashSet<String>,
) -> PackageIdentityReport {
    let mut report = PackageIdentityReport::empty();
    if !safe_relative_path(relative) {
        report.push_high(
            relative,
            "requirements_identity_include_path_traversal",
            "requirements identity include escapes the scanned workspace",
        );
        return report;
    }
    if !seen.insert(relative.to_string()) {
        report.push_high(
            relative,
            "requirements_identity_include_cycle",
            "requirements identity include graph contains a cycle",
        );
        return report;
    }

    let contents = match read_workspace_file(root, relative) {
        Ok(contents) => contents,
        Err(WorkspaceReadError::EscapesWorkspace) => {
            report.push_high(
                relative,
                "requirements_identity_include_path_traversal",
                "requirements identity include escapes the scanned workspace",
            );
            return report;
        }
        Err(WorkspaceReadError::Io(error)) => {
            report.push_high(
                relative,
                "requirements_identity_include_unreadable",
                &format!("requirements identity file could not be read: {error}"),
            );
            return report;
        }
    };
    report.merge(extract_package_identities(
        relative,
        SourceFileKind::Requirements,
        &contents,
    ));

    for include in requirement_includes(&contents) {
        let include = resolve_requirements_include(relative, &include);
        report.merge(discover_requirements_identity_file(root, &include, seen));
    }
    report
}

pub fn extract_package_identities(
    file: &str,
    kind: SourceFileKind,
    contents: &str,
) -> PackageIdentityReport {
    let mut report = PackageIdentityReport {
        files_scanned: 1,
        identities: Vec::new(),
        findings: Vec::new(),
    };
    match kind {
        SourceFileKind::NpmRc | SourceFileKind::PipConfig | SourceFileKind::PackageLock => {}
        SourceFileKind::PackageJson => match npm_package_json_dependency_entries(contents) {
            Ok(entries) => {
                for (name, source_kind) in entries {
                    report.push_identity(PackageIdentity {
                        ecosystem: PackageIdentityEcosystem::Npm,
                        source_kind,
                        file: file.to_string(),
                        name,
                    });
                }
            }
            Err(error) => report.push_high(
                file,
                "package_identity_manifest_parse_error",
                &format!("package.json dependencies could not be parsed safely: {error}"),
            ),
        },
        SourceFileKind::Requirements => {
            for (name, source_kind) in requirements_dependency_entries(contents) {
                report.push_identity(PackageIdentity {
                    ecosystem: PackageIdentityEcosystem::Python,
                    source_kind,
                    file: file.to_string(),
                    name,
                });
            }
        }
        SourceFileKind::PyProjectToml => match pyproject_dependency_entries(contents) {
            Ok(entries) => {
                for (name, source_kind) in entries {
                    report.push_identity(PackageIdentity {
                        ecosystem: PackageIdentityEcosystem::Python,
                        source_kind,
                        file: file.to_string(),
                        name,
                    });
                }
            }
            Err(error) => report.push_high(
                file,
                "package_identity_manifest_parse_error",
                &format!("pyproject dependencies could not be parsed safely: {error}"),
            ),
        },
    }
    report
}

pub fn scan_source_contents(
    file: &str,
    kind: SourceFileKind,
    contents: &str,
    vault_origin: &str,
) -> SourceScanReport {
    match normalize_vault_origin(vault_origin) {
        Ok(origin) => scan_source_contents_with_origin(file, kind, contents, &origin),
        Err(error) => invalid_origin_report(error),
    }
}

pub fn scan_requirements_path(root: &Path, relative: &str, vault_origin: &str) -> SourceScanReport {
    let origin = match normalize_vault_origin(vault_origin) {
        Ok(origin) => origin,
        Err(error) => return invalid_origin_report(error),
    };
    let mut seen = HashSet::new();
    scan_requirements_file(root, relative, &origin, &mut seen)
}

pub fn build_sanitized_context(
    tool: &str,
    vault_origin: &str,
) -> Result<SanitizedExecutionContext, ContextError> {
    let origin = normalize_vault_origin(vault_origin)?;
    match basename(tool) {
        "npm" | "npx" => Ok(npm_context(tool, &origin)),
        "pip" | "pip3" | "python" | "python3" => Ok(pip_context(tool, &origin)),
        _ => Err(ContextError::UnsupportedTool(tool.to_string())),
    }
}

pub fn materialize_sanitized_config(
    context: &SanitizedExecutionContext,
    runtime_dir: &Path,
) -> io::Result<MaterializedContext> {
    fs::create_dir_all(runtime_dir)?;
    let filename = if matches!(basename(&context.tool), "npm" | "npx") {
        "npmrc"
    } else {
        "pip.conf"
    };
    let config_path = runtime_dir.join(filename);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&config_path)?;
    file.write_all(context.generated_config_contents.as_bytes())?;
    file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&config_path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(MaterializedContext {
        config_path,
        bytes_written: context.generated_config_contents.len(),
        permissions_private: private_permissions(&runtime_dir.join(filename)),
    })
}

pub fn vault_host_port(vault_origin: &str) -> Option<String> {
    normalize_vault_origin(vault_origin)
        .ok()
        .and_then(|origin| authority_from_url(&origin).map(str::to_string))
}

fn scan_source_contents_with_origin(
    file: &str,
    kind: SourceFileKind,
    contents: &str,
    vault_origin: &str,
) -> SourceScanReport {
    let mut report = SourceScanReport {
        files_scanned: 1,
        findings: Vec::new(),
    };

    match kind {
        SourceFileKind::NpmRc => scan_npmrc(file, contents, vault_origin, &mut report),
        SourceFileKind::PipConfig => scan_pip_config(file, contents, vault_origin, &mut report),
        SourceFileKind::PackageLock => scan_package_lock(file, contents, vault_origin, &mut report),
        SourceFileKind::PackageJson | SourceFileKind::PyProjectToml => {}
        SourceFileKind::Requirements => {
            scan_requirements_contents(file, contents, vault_origin, &mut report)
        }
    }

    report
}

fn scan_requirements_file(
    root: &Path,
    relative: &str,
    vault_origin: &str,
    seen: &mut HashSet<String>,
) -> SourceScanReport {
    let mut report = SourceScanReport::empty();
    if !safe_relative_path(relative) {
        report.push_high(
            relative,
            "requirements_include_path_traversal",
            "requirements include escapes the scanned workspace",
        );
        return report;
    }
    if !seen.insert(relative.to_string()) {
        report.push_high(
            relative,
            "requirements_include_cycle",
            "requirements include graph contains a cycle",
        );
        return report;
    }

    let contents = match read_workspace_file(root, relative) {
        Ok(contents) => contents,
        Err(WorkspaceReadError::EscapesWorkspace) => {
            report.push_high(
                relative,
                "requirements_include_path_traversal",
                "requirements include escapes the scanned workspace",
            );
            return report;
        }
        Err(WorkspaceReadError::Io(error)) => {
            report.push_high(
                relative,
                "requirements_include_unreadable",
                &format!("requirements file could not be read: {error}"),
            );
            return report;
        }
    };
    report.merge(scan_source_contents_with_origin(
        relative,
        SourceFileKind::Requirements,
        &contents,
        vault_origin,
    ));

    for include in requirement_includes(&contents) {
        let include = resolve_requirements_include(relative, &include);
        report.merge(scan_requirements_file(root, &include, vault_origin, seen));
    }
    report
}

fn known_source_files() -> Vec<(&'static str, SourceFileKind)> {
    vec![
        (".npmrc", SourceFileKind::NpmRc),
        ("package-lock.json", SourceFileKind::PackageLock),
        ("npm-shrinkwrap.json", SourceFileKind::PackageLock),
        ("requirements.txt", SourceFileKind::Requirements),
        ("requirements-dev.txt", SourceFileKind::Requirements),
        ("pip.conf", SourceFileKind::PipConfig),
        (".pip/pip.conf", SourceFileKind::PipConfig),
    ]
}

fn scan_npmrc(file: &str, contents: &str, vault_origin: &str, report: &mut SourceScanReport) {
    for raw_line in contents.lines() {
        let Some(entry) = parse_config_entry(raw_line) else {
            continue;
        };
        let key = entry.key.to_ascii_lowercase();
        let value = unquote(entry.value);

        if has_env_interpolation(entry.key) || has_env_interpolation(value) {
            report.push_high(
                file,
                "env_interpolation_in_package_config",
                "package-manager config uses environment interpolation",
            );
        }
        if url_has_credentials(value) {
            report.push_high(
                file,
                "url_credentials_in_package_config",
                "package-manager config contains URL credentials",
            );
        }
        if npm_credential_key(&key) {
            report.push_high(
                file,
                "credential_in_package_manager_config",
                "credential-like npm config entry",
            );
        }
        if key == "registry" || key.ends_with(":registry") {
            require_vault_url(report, file, "npm_registry_override", value, vault_origin);
        }
        if matches!(key.as_str(), "proxy" | "https-proxy" | "http-proxy") {
            require_vault_url(report, file, "npm_proxy_override", value, vault_origin);
        }
        if key == "strict-ssl" && value.eq_ignore_ascii_case("false") {
            report.push_high(
                file,
                "npm_transport_integrity_disabled",
                "npm strict-ssl is disabled",
            );
        }
        if key == "ignore-scripts" && value.eq_ignore_ascii_case("false") {
            report.push_high(
                file,
                "npm_lifecycle_scripts_enabled",
                "npm config explicitly enables lifecycle scripts",
            );
        }
        if key == "foreground-scripts" && truthy_config_value(value) {
            report.push_high(
                file,
                "npm_foreground_scripts_enabled",
                "npm foreground-scripts increases lifecycle script visibility and execution surface",
            );
        }
        if matches!(key.as_str(), "script-shell" | "userconfig" | "globalconfig") {
            report.push_high(
                file,
                "npm_config_indirection",
                "npm config redirects shell or config loading",
            );
        }
        if key == "always-auth" && truthy_config_value(value) {
            report.push_suspicious(
                file,
                "npm_always_auth_enabled",
                "npm always-auth can broaden credential exposure",
            );
        }
    }
}

fn scan_pip_config(file: &str, contents: &str, vault_origin: &str, report: &mut SourceScanReport) {
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || (line.starts_with('[') && line.ends_with(']'))
        {
            continue;
        }
        let Some(entry) = parse_config_entry(raw_line) else {
            continue;
        };
        let key = entry.key.to_ascii_lowercase();
        let value = unquote(entry.value);
        if has_env_interpolation(entry.key) || has_env_interpolation(value) {
            report.push_high(
                file,
                "env_interpolation_in_package_config",
                "package-manager config uses environment interpolation",
            );
        }
        if url_has_credentials(value) {
            report.push_high(
                file,
                "url_credentials_in_package_config",
                "package-manager config contains URL credentials",
            );
        }
        match key.as_str() {
            "index-url" | "extra-index-url" | "find-links" => {
                for candidate in split_config_values(value) {
                    require_vault_url(report, file, "pip_index_override", candidate, vault_origin);
                }
            }
            "trusted-host" => report.push_high(
                file,
                "pip_trusted_host_override",
                "pip trusted-host weakens source transport controls",
            ),
            "no-index" if truthy_config_value(value) => report.push_high(
                file,
                "pip_no_index_override",
                "pip no-index bypasses configured package indexes",
            ),
            "cert" | "client-cert" => report.push_high(
                file,
                "pip_certificate_override",
                "pip certificate configuration changes transport identity",
            ),
            "proxy" => report.push_high(
                file,
                "pip_proxy_override",
                "pip proxy setting can redirect package traffic",
            ),
            "no-build-isolation" if truthy_config_value(value) => report.push_high(
                file,
                "pip_build_isolation_disabled",
                "pip build isolation is disabled",
            ),
            "require-hashes" if value.eq_ignore_ascii_case("false") => report.push_high(
                file,
                "pip_hash_mode_disabled",
                "pip hash checking is explicitly disabled",
            ),
            _ => {}
        }
    }
}

fn scan_package_lock(
    file: &str,
    contents: &str,
    vault_origin: &str,
    report: &mut SourceScanReport,
) {
    let pairs = match json_string_pairs(contents) {
        Ok(pairs) => pairs,
        Err(error) => {
            report.push_high(
                file,
                "lockfile_parse_error",
                &format!("lockfile could not be parsed safely: {error}"),
            );
            return;
        }
    };
    for (key, value) in pairs {
        let key = key.to_ascii_lowercase();
        if matches!(key.as_str(), "resolved" | "version") {
            scan_source_value(
                report,
                file,
                &value,
                vault_origin,
                "lockfile_external_source",
                "lockfile_git_source",
                "lockfile_local_source",
            );
        }
        if key == "integrity" && value.trim().is_empty() {
            report.push_high(
                file,
                "lockfile_empty_integrity",
                "lockfile contains an empty integrity value",
            );
        }
    }
}

fn scan_requirements_contents(
    file: &str,
    contents: &str,
    vault_origin: &str,
    report: &mut SourceScanReport,
) {
    for raw_logical_line in join_line_continuations(contents) {
        let line = strip_requirement_comment(&raw_logical_line);
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        scan_requirements_line(file, line, vault_origin, report);
    }
}

fn scan_requirements_line(
    file: &str,
    line: &str,
    vault_origin: &str,
    report: &mut SourceScanReport,
) {
    let tokens = tokenize_requirement_line(line);
    let mut index = 0;
    while index < tokens.len() {
        let token = tokens[index];
        if let Some((flag, inline_value)) = split_option_value(token) {
            match flag {
                "--index-url" | "-i" | "--extra-index-url" | "--find-links" | "-f" => {
                    let value = inline_value.or_else(|| tokens.get(index + 1).copied());
                    match value {
                        Some(value) => require_vault_url(
                            report,
                            file,
                            "requirements_index_override",
                            value,
                            vault_origin,
                        ),
                        None => report.push_high(
                            file,
                            "requirements_parse_error",
                            "requirements source flag is missing a value",
                        ),
                    }
                }
                "--trusted-host" => report.push_high(
                    file,
                    "requirements_trusted_host_override",
                    "requirements file weakens transport verification",
                ),
                "--no-index" => report.push_high(
                    file,
                    "requirements_no_index_override",
                    "requirements file disables package indexes",
                ),
                "--no-build-isolation" => report.push_high(
                    file,
                    "requirements_build_isolation_disabled",
                    "requirements file disables build isolation",
                ),
                "-e" | "--editable" => report.push_high(
                    file,
                    "requirements_editable_source",
                    "requirements file references editable source",
                ),
                "--require-hashes" => report.push_suspicious(
                    file,
                    "requirements_hash_mode_enabled",
                    "requirements file enables hash checking",
                ),
                _ => {}
            }
        }
        index += 1;
    }

    if has_env_interpolation(line) {
        report.push_high(
            file,
            "env_interpolation_in_package_config",
            "requirements file uses environment interpolation",
        );
    }
    if url_has_credentials(line) {
        report.push_high(
            file,
            "url_credentials_in_package_config",
            "requirements file contains URL credentials",
        );
    }
    for value in requirement_source_values(line) {
        scan_source_value(
            report,
            file,
            value,
            vault_origin,
            "requirements_direct_source",
            "requirements_vcs_source",
            "requirements_local_path_source",
        );
    }
}

fn requirement_includes(contents: &str) -> Vec<String> {
    let mut includes = Vec::new();
    for raw_logical_line in join_line_continuations(contents) {
        let line = strip_requirement_comment(&raw_logical_line);
        let tokens = tokenize_requirement_line(line.trim());
        let mut index = 0;
        while index < tokens.len() {
            let token = tokens[index];
            if let Some((flag, inline_value)) = split_option_value(token) {
                if matches!(flag, "-r" | "--requirement" | "-c" | "--constraint") {
                    if let Some(value) = inline_value.or_else(|| tokens.get(index + 1).copied()) {
                        includes.push(value.to_string());
                    }
                }
            }
            index += 1;
        }
    }
    includes
}

fn npm_package_json_dependency_entries(
    contents: &str,
) -> Result<Vec<(String, PackageIdentitySourceKind)>, String> {
    const SECTIONS: &[&str] = &[
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
        "bundleDependencies",
        "bundledDependencies",
    ];
    let entries = json_dependency_entries_for_sections(contents, SECTIONS)?;
    Ok(entries
        .into_iter()
        .filter(|(name, _)| valid_npm_package_name(name))
        .collect())
}

fn requirements_dependency_entries(contents: &str) -> Vec<(String, PackageIdentitySourceKind)> {
    let mut entries = Vec::new();
    for raw_logical_line in join_line_continuations(contents) {
        let line = strip_requirement_comment(&raw_logical_line);
        if let Some(entry) = requirement_dependency_entry(line.trim()) {
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
    }
    entries
}

fn pyproject_dependency_entries(
    contents: &str,
) -> Result<Vec<(String, PackageIdentitySourceKind)>, String> {
    let mut entries = Vec::new();
    let mut section = "";
    let mut dependency_array_active = false;

    for raw_line in contents.lines() {
        let line = strip_requirement_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if dependency_array_active {
                return Err("dependency array was not closed".to_string());
            }
            section = line.trim_matches(['[', ']'].as_ref()).trim();
            continue;
        }

        if section == "project" {
            if dependency_array_active || line.starts_with("dependencies") {
                dependency_array_active =
                    collect_toml_dependency_strings(line, &mut entries, dependency_array_active);
            }
        } else if section == "build-system" {
            if dependency_array_active || line.starts_with("requires") {
                dependency_array_active =
                    collect_toml_dependency_strings(line, &mut entries, dependency_array_active);
            }
        } else if section == "project.optional-dependencies"
            && (dependency_array_active || line.contains('='))
        {
            dependency_array_active =
                collect_toml_dependency_strings(line, &mut entries, dependency_array_active);
        }
    }

    if dependency_array_active {
        return Err("dependency array was not closed".to_string());
    }
    Ok(entries)
}

fn collect_toml_dependency_strings(
    line: &str,
    entries: &mut Vec<(String, PackageIdentitySourceKind)>,
    already_active: bool,
) -> bool {
    for value in quoted_strings(line) {
        if let Some(entry) = requirement_dependency_entry(&value) {
            if !entries.contains(&entry) {
                entries.push(entry);
            }
        }
    }
    if already_active {
        !line.contains(']')
    } else {
        line.contains('[') && !line.contains(']')
    }
}

fn requirement_dependency_entry(line: &str) -> Option<(String, PackageIdentitySourceKind)> {
    if line.is_empty() || line.starts_with('-') || is_url_source(line) || is_vcs_source(line) {
        return None;
    }
    let source_kind = package_identity_source_kind(line);
    let candidate = if let Some((name, _)) = line.split_once(" @ ") {
        name
    } else {
        line.split_whitespace().next().unwrap_or(line)
    };
    let candidate = candidate
        .split(';')
        .next()
        .unwrap_or(candidate)
        .split('[')
        .next()
        .unwrap_or(candidate);
    let candidate = split_python_version_operator(candidate)
        .next()
        .unwrap_or(candidate)
        .trim();
    if valid_python_package_name(candidate) {
        Some((candidate.to_string(), source_kind))
    } else {
        None
    }
}

fn package_identity_source_kind(value: &str) -> PackageIdentitySourceKind {
    for source in requirement_source_values(value) {
        if is_vcs_source(source) {
            return PackageIdentitySourceKind::Git;
        }
        if is_url_source(source) {
            return PackageIdentitySourceKind::DirectUrl;
        }
        if is_local_source(source) {
            return PackageIdentitySourceKind::LocalPath;
        }
    }
    let value = clean_value(value);
    if is_vcs_source(value) {
        PackageIdentitySourceKind::Git
    } else if is_url_source(value) {
        PackageIdentitySourceKind::DirectUrl
    } else if is_local_source(value) {
        PackageIdentitySourceKind::LocalPath
    } else {
        PackageIdentitySourceKind::PublicRegistry
    }
}

fn split_python_version_operator(value: &str) -> impl Iterator<Item = &str> {
    value.split(['=', '!', '~', '<', '>'])
}

fn valid_python_package_name(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
        && value
            .chars()
            .last()
            .is_some_and(|ch| ch.is_ascii_alphanumeric())
}

fn valid_npm_package_name(value: &str) -> bool {
    if let Some((scope, package)) = value.split_once('/') {
        return scope.starts_with('@')
            && valid_npm_name_segment(&scope[1..])
            && valid_npm_name_segment(package);
    }
    valid_npm_name_segment(value)
}

fn valid_npm_name_segment(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '~'))
}

fn quoted_strings(line: &str) -> Vec<String> {
    let chars = line.chars().collect::<Vec<_>>();
    let mut values = Vec::new();
    let mut index = 0;
    while let Some(ch) = chars.get(index).copied() {
        if !matches!(ch, '"' | '\'') {
            index += 1;
            continue;
        }
        let quote = ch;
        index += 1;
        let mut value = String::new();
        let mut closed = false;
        while let Some(inner) = chars.get(index).copied() {
            if inner == quote {
                closed = true;
                index += 1;
                break;
            }
            if inner == '\\' && quote == '"' {
                index += 1;
                if let Some(escaped) = chars.get(index).copied() {
                    value.push(escaped);
                    index += 1;
                    continue;
                }
                break;
            }
            value.push(inner);
            index += 1;
        }
        if closed {
            values.push(value);
        }
    }
    values
}

fn json_dependency_entries_for_sections(
    input: &str,
    sections: &[&str],
) -> Result<Vec<(String, PackageIdentitySourceKind)>, String> {
    let chars = input.chars().collect::<Vec<_>>();
    let mut index = skip_whitespace(&chars, 0);
    if chars.get(index) != Some(&'{') {
        return Err("top-level JSON value is not an object".to_string());
    }
    index += 1;
    let mut values = Vec::new();
    loop {
        index = skip_whitespace(&chars, index);
        match chars.get(index) {
            Some('}') => return Ok(values),
            Some('"') => {}
            Some(_) => return Err("expected top-level object key".to_string()),
            None => return Err("unterminated top-level object".to_string()),
        }
        let (key, next_index) = parse_json_string(&chars, index)?;
        index = skip_whitespace(&chars, next_index);
        if chars.get(index) != Some(&':') {
            return Err("expected colon after top-level object key".to_string());
        }
        index = skip_whitespace(&chars, index + 1);
        if sections.contains(&key.as_str()) {
            if chars.get(index) == Some(&'{') {
                let (entries, next_index) = json_object_dependency_entries(&chars, index)?;
                for entry in entries {
                    if !values.contains(&entry) {
                        values.push(entry);
                    }
                }
                index = next_index;
            } else if chars.get(index) == Some(&'[') {
                let (strings, next_index) = json_string_array_values(&chars, index)?;
                for value in strings {
                    let entry = (value, PackageIdentitySourceKind::PublicRegistry);
                    if !values.contains(&entry) {
                        values.push(entry);
                    }
                }
                index = next_index;
            } else {
                index = skip_json_value(&chars, index)?;
            }
        } else {
            index = skip_json_value(&chars, index)?;
        }
        index = skip_whitespace(&chars, index);
        match chars.get(index) {
            Some(',') => index += 1,
            Some('}') => return Ok(values),
            Some(_) => return Err("expected comma or object close".to_string()),
            None => return Err("unterminated top-level object".to_string()),
        }
    }
}

fn json_object_dependency_entries(
    chars: &[char],
    start: usize,
) -> Result<(Vec<(String, PackageIdentitySourceKind)>, usize), String> {
    if chars.get(start) != Some(&'{') {
        return Err("expected object".to_string());
    }
    let mut index = start + 1;
    let mut entries = Vec::new();
    loop {
        index = skip_whitespace(chars, index);
        match chars.get(index) {
            Some('}') => return Ok((entries, index + 1)),
            Some('"') => {}
            Some(_) => return Err("expected object member key".to_string()),
            None => return Err("unterminated object".to_string()),
        }
        let (key, next_index) = parse_json_string(chars, index)?;
        index = skip_whitespace(chars, next_index);
        if chars.get(index) != Some(&':') {
            return Err("expected colon after object member key".to_string());
        }
        index = skip_whitespace(chars, index + 1);
        let source_kind = if chars.get(index) == Some(&'"') {
            let (value, next_index) = parse_json_string(chars, index)?;
            index = next_index;
            package_identity_source_kind(&value)
        } else {
            index = skip_json_value(chars, index)?;
            PackageIdentitySourceKind::PublicRegistry
        };
        let entry = (key, source_kind);
        if !entries.contains(&entry) {
            entries.push(entry);
        }
        index = skip_whitespace(chars, index);
        match chars.get(index) {
            Some(',') => index += 1,
            Some('}') => return Ok((entries, index + 1)),
            Some(_) => return Err("expected comma or object close".to_string()),
            None => return Err("unterminated object".to_string()),
        }
    }
}

fn json_string_array_values(chars: &[char], start: usize) -> Result<(Vec<String>, usize), String> {
    if chars.get(start) != Some(&'[') {
        return Err("expected array".to_string());
    }
    let mut index = start + 1;
    let mut values = Vec::new();
    loop {
        index = skip_whitespace(chars, index);
        match chars.get(index) {
            Some(']') => return Ok((values, index + 1)),
            Some('"') => {
                let (value, next_index) = parse_json_string(chars, index)?;
                if !values.contains(&value) {
                    values.push(value);
                }
                index = next_index;
            }
            Some(_) => index = skip_json_value(chars, index)?,
            None => return Err("unterminated array".to_string()),
        }
        index = skip_whitespace(chars, index);
        match chars.get(index) {
            Some(',') => index += 1,
            Some(']') => return Ok((values, index + 1)),
            Some(_) => return Err("expected comma or array close".to_string()),
            None => return Err("unterminated array".to_string()),
        }
    }
}

fn skip_json_value(chars: &[char], start: usize) -> Result<usize, String> {
    match chars.get(start).copied() {
        Some('"') => parse_json_string(chars, start).map(|(_, next)| next),
        Some('{') => skip_json_container(chars, start, '{', '}'),
        Some('[') => skip_json_container(chars, start, '[', ']'),
        Some(_) => {
            let mut index = start;
            while let Some(ch) = chars.get(index) {
                if matches!(ch, ',' | '}' | ']') {
                    break;
                }
                index += 1;
            }
            Ok(index)
        }
        None => Err("expected JSON value".to_string()),
    }
}

fn skip_json_container(
    chars: &[char],
    start: usize,
    open: char,
    _close: char,
) -> Result<usize, String> {
    if chars.get(start) != Some(&open) {
        return Err("expected JSON container".to_string());
    }
    let expected_close = match open {
        '{' => '}',
        '[' => ']',
        _ => _close,
    };
    let mut index = start + 1;
    let mut stack = vec![expected_close];
    while let Some(ch) = chars.get(index).copied() {
        match ch {
            '"' => {
                let (_, next_index) = parse_json_string(chars, index)?;
                index = next_index;
                continue;
            }
            '{' => stack.push('}'),
            '[' => stack.push(']'),
            '}' | ']' => {
                if stack.pop() != Some(ch) {
                    return Err("mismatched JSON container close".to_string());
                }
                if stack.is_empty() {
                    return Ok(index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    Err("unterminated JSON container".to_string())
}

fn resolve_requirements_include(parent: &str, include: &str) -> String {
    let include_path = Path::new(include);
    if include_path.is_absolute() {
        return include.to_string();
    }
    Path::new(parent)
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .join(include_path)
        .to_string_lossy()
        .into_owned()
}

fn scan_source_value(
    report: &mut SourceScanReport,
    file: &str,
    raw_value: &str,
    vault_origin: &str,
    external_reason: &str,
    vcs_reason: &str,
    local_reason: &str,
) {
    let value = clean_value(raw_value);
    if value.is_empty() {
        return;
    }
    if url_has_credentials(value) {
        report.push_high(
            file,
            "url_credentials_in_package_config",
            "package source contains URL credentials",
        );
    }
    if is_vcs_source(value) {
        report.push_high(file, vcs_reason, "package source references VCS");
    } else if is_url_source(value) {
        if !is_vault_url(value, vault_origin) {
            report.push_high(file, external_reason, "package source points outside Vault");
        }
    } else if is_local_source(value) {
        report.push_high(file, local_reason, "package source references a local path");
    }
}

fn require_vault_url(
    report: &mut SourceScanReport,
    file: &str,
    reason_code: &str,
    value: &str,
    vault_origin: &str,
) {
    let value = clean_value(value);
    if value.is_empty() || !is_vault_url(value, vault_origin) {
        report.push_high(
            file,
            reason_code,
            "package source points outside configured Vault origin",
        );
    }
}

fn npm_context(tool: &str, origin: &str) -> SanitizedExecutionContext {
    let registry = format!("{origin}/npm/");
    SanitizedExecutionContext {
        tool: tool.to_string(),
        vault_origin: origin.to_string(),
        env_clear: true,
        env: vec![
            ("HOME".to_string(), "<whoathere-runtime-home>".to_string()),
            ("NPM_CONFIG_REGISTRY".to_string(), registry.clone()),
            (
                "NPM_CONFIG_USERCONFIG".to_string(),
                "<whoathere-runtime>/npmrc".to_string(),
            ),
            (
                "NPM_CONFIG_GLOBALCONFIG".to_string(),
                "<whoathere-runtime>/npmrc".to_string(),
            ),
            ("NPM_CONFIG_AUDIT".to_string(), "false".to_string()),
            ("NPM_CONFIG_FUND".to_string(), "false".to_string()),
            ("NPM_CONFIG_IGNORE_SCRIPTS".to_string(), "false".to_string()),
        ],
        args: vec![
            "--registry".to_string(),
            registry.clone(),
            "--userconfig".to_string(),
            "<whoathere-runtime>/npmrc".to_string(),
            "--globalconfig".to_string(),
            "<whoathere-runtime>/npmrc".to_string(),
        ],
        scrubbed_env_names: vec![
            "NODE_AUTH_TOKEN".to_string(),
            "NPM_TOKEN".to_string(),
            "npm_config_registry".to_string(),
            "HTTP_PROXY".to_string(),
            "HTTPS_PROXY".to_string(),
            "ALL_PROXY".to_string(),
        ],
        scrubbed_env_prefixes: vec!["NPM_CONFIG_".to_string(), "npm_config_".to_string()],
        generated_config_path: "<whoathere-runtime>/npmrc".to_string(),
        generated_config_contents: format!("registry={registry}\naudit=false\nfund=false\n"),
        egress_boundary_required: true,
    }
}

fn pip_context(tool: &str, origin: &str) -> SanitizedExecutionContext {
    let index = format!("{origin}/pypi/simple");
    SanitizedExecutionContext {
        tool: tool.to_string(),
        vault_origin: origin.to_string(),
        env_clear: true,
        env: vec![
            ("HOME".to_string(), "<whoathere-runtime-home>".to_string()),
            (
                "XDG_CONFIG_HOME".to_string(),
                "<whoathere-runtime>/xdg".to_string(),
            ),
            ("PIP_INDEX_URL".to_string(), index.clone()),
            (
                "PIP_CONFIG_FILE".to_string(),
                "<whoathere-runtime>/pip.conf".to_string(),
            ),
            ("PIP_DISABLE_PIP_VERSION_CHECK".to_string(), "1".to_string()),
            ("PIP_NO_INPUT".to_string(), "1".to_string()),
            ("PYTHONNOUSERSITE".to_string(), "1".to_string()),
        ],
        args: vec![
            "--index-url".to_string(),
            index.clone(),
            "--no-input".to_string(),
        ],
        scrubbed_env_names: vec![
            "PIP_INDEX_URL".to_string(),
            "PIP_EXTRA_INDEX_URL".to_string(),
            "PIP_FIND_LINKS".to_string(),
            "PIP_CONFIG_FILE".to_string(),
            "HTTP_PROXY".to_string(),
            "HTTPS_PROXY".to_string(),
            "ALL_PROXY".to_string(),
            "NETRC".to_string(),
            "AWS_SECRET_ACCESS_KEY".to_string(),
            "GOOGLE_APPLICATION_CREDENTIALS".to_string(),
        ],
        scrubbed_env_prefixes: vec!["PIP_".to_string()],
        generated_config_path: "<whoathere-runtime>/pip.conf".to_string(),
        generated_config_contents: format!(
            "[global]\nindex-url = {index}\ndisable-pip-version-check = true\nno-input = true\n"
        ),
        egress_boundary_required: true,
    }
}

fn normalize_vault_origin(origin: &str) -> Result<String, ContextError> {
    let trimmed = origin.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.contains(char::is_whitespace) {
        return Err(ContextError::InvalidVaultOrigin(origin.to_string()));
    }
    if authority_from_url(trimmed).is_none() || trimmed.contains('@') {
        return Err(ContextError::InvalidVaultOrigin(origin.to_string()));
    }
    let Some(host) = host_from_url(trimmed) else {
        return Err(ContextError::InvalidVaultOrigin(origin.to_string()));
    };
    if is_known_public_registry_host(host) {
        return Err(ContextError::InvalidVaultOrigin(origin.to_string()));
    }
    if trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if trimmed.starts_with("http://127.0.0.1:") || trimmed.starts_with("http://[::1]:") {
        return Ok(trimmed.to_string());
    }
    Err(ContextError::InvalidVaultOrigin(origin.to_string()))
}

fn invalid_origin_report(error: ContextError) -> SourceScanReport {
    let mut report = SourceScanReport::empty();
    report.push_high(
        "<vault-origin>",
        "invalid_vault_origin",
        &format!("Vault origin is invalid: {error:?}"),
    );
    report
}

fn is_vault_url(value: &str, vault_origin: &str) -> bool {
    let value = clean_value(value);
    if value.contains('@') {
        return false;
    }
    value == vault_origin || value.starts_with(&format!("{vault_origin}/"))
}

fn parse_config_entry(line: &str) -> Option<ConfigEntry<'_>> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
        return None;
    }
    if let Some((key, value)) = trimmed.split_once('=') {
        return Some(ConfigEntry {
            key: key.trim(),
            value: value.trim(),
        });
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let key = parts.next()?.trim();
    let value = parts.next()?.trim();
    if key.is_empty() || value.is_empty() {
        None
    } else {
        Some(ConfigEntry { key, value })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ConfigEntry<'a> {
    key: &'a str,
    value: &'a str,
}

fn split_config_values(value: &str) -> Vec<&str> {
    value
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .collect()
}

fn split_option_value(token: &str) -> Option<(&str, Option<&str>)> {
    if let Some((flag, value)) = token.split_once('=') {
        return Some((flag, Some(value)));
    }
    if token.starts_with('-') {
        Some((token, None))
    } else {
        None
    }
}

fn tokenize_requirement_line(line: &str) -> Vec<&str> {
    line.split_whitespace().collect()
}

fn requirement_source_values(line: &str) -> Vec<&str> {
    let tokens = tokenize_requirement_line(line);
    let mut values = Vec::new();
    for (index, token) in tokens.iter().enumerate() {
        if is_url_source(token) || is_vcs_source(token) || is_local_source(token) {
            push_unique(&mut values, token);
        }
        if *token == "@" {
            if let Some(value) = tokens.get(index + 1) {
                push_unique(&mut values, value);
            }
        } else if let Some((_, value)) = token.split_once('@') {
            if is_url_source(value) || is_vcs_source(value) {
                push_unique(&mut values, value);
            }
        }
    }
    values
}

fn push_unique<'a>(values: &mut Vec<&'a str>, value: &'a str) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn strip_requirement_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if *byte == b'#' && (index == 0 || bytes[index - 1].is_ascii_whitespace()) {
            return &line[..index];
        }
    }
    line
}

fn join_line_continuations(contents: &str) -> Vec<String> {
    let mut logical = Vec::new();
    let mut current = String::new();
    for line in contents.lines() {
        let trimmed_end = line.trim_end();
        if let Some(prefix) = trimmed_end.strip_suffix('\\') {
            current.push_str(prefix);
            current.push(' ');
        } else {
            current.push_str(trimmed_end);
            logical.push(std::mem::take(&mut current));
        }
    }
    if !current.is_empty() {
        logical.push(current);
    }
    logical
}

fn json_string_pairs(input: &str) -> Result<Vec<(String, String)>, String> {
    let chars = input.chars().collect::<Vec<_>>();
    let mut pairs = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        if chars[index] != '"' {
            index += 1;
            continue;
        }
        let (key, next_index) = parse_json_string(&chars, index)?;
        index = skip_whitespace(&chars, next_index);
        if chars.get(index) != Some(&':') {
            continue;
        }
        index = skip_whitespace(&chars, index + 1);
        if chars.get(index) != Some(&'"') {
            continue;
        }
        let (value, next_index) = parse_json_string(&chars, index)?;
        pairs.push((key, value));
        index = next_index;
    }
    Ok(pairs)
}

fn parse_json_string(chars: &[char], start: usize) -> Result<(String, usize), String> {
    let mut out = String::new();
    let mut index = start + 1;
    while let Some(ch) = chars.get(index).copied() {
        match ch {
            '"' => return Ok((out, index + 1)),
            '\\' => {
                index += 1;
                let Some(escaped) = chars.get(index).copied() else {
                    return Err("unterminated escape sequence".to_string());
                };
                match escaped {
                    '"' | '\\' | '/' => out.push(escaped),
                    'b' => out.push('\u{0008}'),
                    'f' => out.push('\u{000c}'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        if index + 4 >= chars.len() {
                            return Err("truncated unicode escape".to_string());
                        }
                        let hex = chars[index + 1..=index + 4].iter().collect::<String>();
                        let codepoint = u32::from_str_radix(&hex, 16)
                            .map_err(|_| "invalid unicode escape".to_string())?;
                        let Some(decoded) = char::from_u32(codepoint) else {
                            return Err("invalid unicode codepoint".to_string());
                        };
                        out.push(decoded);
                        index += 4;
                    }
                    _ => return Err("invalid escape sequence".to_string()),
                }
            }
            _ => out.push(ch),
        }
        index += 1;
    }
    Err("unterminated JSON string".to_string())
}

fn skip_whitespace(chars: &[char], mut index: usize) -> usize {
    while chars.get(index).is_some_and(|ch| ch.is_whitespace()) {
        index += 1;
    }
    index
}

fn clean_value(value: &str) -> &str {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_end_matches([',', ')', ']', ';'])
}

fn unquote(value: &str) -> &str {
    value.trim().trim_matches('"').trim_matches('\'')
}

fn has_env_interpolation(value: &str) -> bool {
    value.contains("${") || value.contains("%(")
}

fn truthy_config_value(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

fn npm_credential_key(key: &str) -> bool {
    key.contains("_authtoken")
        || key == "_auth"
        || key.ends_with(":_auth")
        || key.ends_with(":_authtoken")
        || key == "username"
        || key.ends_with(":username")
        || key == "password"
        || key.ends_with(":password")
}

fn is_url_source(value: &str) -> bool {
    let value = clean_value(value);
    value.starts_with("http://") || value.starts_with("https://")
}

fn is_vcs_source(value: &str) -> bool {
    let value = clean_value(value);
    value.starts_with("git+")
        || value.starts_with("hg+")
        || value.starts_with("svn+")
        || value.starts_with("bzr+")
        || value.starts_with("git:")
        || value.starts_with("ssh:")
        || value.starts_with("git@")
        || value.starts_with("github:")
}

fn is_local_source(value: &str) -> bool {
    let value = clean_value(value);
    if value.is_empty()
        || value.starts_with('-')
        || value.contains("://")
        || value.contains('@')
        || value.contains("==")
        || value.contains(">=")
        || value.contains("<=")
        || value.contains('>')
        || value.contains('<')
        || value.contains(';')
    {
        return false;
    }
    value.starts_with("file:")
        || value.starts_with("link:")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || value.starts_with("~/")
        || value.contains('/')
        || value.contains('\\')
        || value.ends_with(".whl")
        || value.ends_with(".tar.gz")
        || value.ends_with(".zip")
}

fn url_has_credentials(value: &str) -> bool {
    authority_from_url(clean_value(value)).is_some_and(|authority| authority.contains('@'))
}

fn authority_from_url(value: &str) -> Option<&str> {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))?;
    rest.split(['/', '?', '#']).next()
}

fn host_from_url(value: &str) -> Option<&str> {
    let authority = authority_from_url(value)?;
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.starts_with('[') {
        return authority
            .split_once(']')
            .map(|(host, _)| host.trim_start_matches('['));
    }
    authority.split(':').next()
}

fn is_known_public_registry_host(host: &str) -> bool {
    matches!(
        host.to_ascii_lowercase().as_str(),
        "registry.npmjs.org"
            | "npmjs.org"
            | "www.npmjs.com"
            | "pypi.org"
            | "files.pythonhosted.org"
            | "pythonhosted.org"
            | "github.com"
    )
}

fn safe_relative_path(relative: &str) -> bool {
    let path = Path::new(relative);
    if path.is_absolute() {
        return false;
    }
    path.components().all(|component| {
        matches!(
            component,
            Component::Normal(_) | Component::CurDir | Component::ParentDir
        ) && !matches!(component, Component::ParentDir)
    })
}

#[derive(Debug)]
enum WorkspaceReadError {
    Io(io::Error),
    EscapesWorkspace,
}

fn read_workspace_file(root: &Path, relative: &str) -> Result<String, WorkspaceReadError> {
    if !safe_relative_path(relative) {
        return Err(WorkspaceReadError::EscapesWorkspace);
    }
    let root = fs::canonicalize(root).map_err(WorkspaceReadError::Io)?;
    let candidate = fs::canonicalize(root.join(relative)).map_err(WorkspaceReadError::Io)?;
    if !candidate.starts_with(&root) {
        return Err(WorkspaceReadError::EscapesWorkspace);
    }
    fs::read_to_string(candidate).map_err(WorkspaceReadError::Io)
}

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

#[cfg(unix)]
fn private_permissions(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(path)
        .map(|metadata| metadata.permissions().mode() & 0o777 == 0o600)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn private_permissions(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    const VAULT: &str = "http://127.0.0.1:4873";

    #[test]
    fn npmrc_public_registry_blocks() {
        let report = scan_source_contents(
            ".npmrc",
            SourceFileKind::NpmRc,
            "registry=https://registry.npmjs.org/\n",
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(report.findings[0].reason_code, "npm_registry_override");
    }

    #[test]
    fn npmrc_vault_registry_allows() {
        let report = scan_source_contents(
            ".npmrc",
            SourceFileKind::NpmRc,
            "registry=http://127.0.0.1:4873/npm/\n@company:registry=http://127.0.0.1:4873/npm/\n",
            VAULT,
        );
        assert!(!report.has_blocking_findings());
    }

    #[test]
    fn npmrc_tokens_and_env_interpolation_block() {
        let report = scan_source_contents(
            ".npmrc",
            SourceFileKind::NpmRc,
            "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nstrict-ssl=false\n",
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "credential_in_package_manager_config"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "env_interpolation_in_package_config"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "npm_transport_integrity_disabled"));
    }

    #[test]
    fn pip_config_extra_index_blocks() {
        let report = scan_source_contents(
            "pip.conf",
            SourceFileKind::PipConfig,
            "[global]\nextra-index-url = https://pypi.org/simple\n",
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(report.findings[0].reason_code, "pip_index_override");
    }

    #[test]
    fn pip_config_transport_and_proxy_controls_block() {
        let report = scan_source_contents(
            "pip.conf",
            SourceFileKind::PipConfig,
            "trusted-host = pypi.org\nproxy = https://user:pass@proxy.example.test\nno-build-isolation = true\n",
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "url_credentials_in_package_config"));
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "pip_proxy_override"));
    }

    #[test]
    fn package_lock_external_resolved_blocks() {
        let report = scan_source_contents(
            "package-lock.json",
            SourceFileKind::PackageLock,
            r#""resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz""#,
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(report.findings[0].reason_code, "lockfile_external_source");
    }

    #[test]
    fn package_lock_vault_resolved_allows() {
        let report = scan_source_contents(
            "package-lock.json",
            SourceFileKind::PackageLock,
            r#""resolved": "http:\/\/127.0.0.1:4873\/npm\/left-pad\/-\/left-pad-1.3.0.tgz""#,
            VAULT,
        );
        assert!(!report.has_blocking_findings());
    }

    #[test]
    fn package_lock_unicode_escaped_external_url_blocks() {
        let report = scan_source_contents(
            "package-lock.json",
            SourceFileKind::PackageLock,
            r#""resolved": "\u0068\u0074\u0074\u0070\u0073://registry.npmjs.org/pkg/-/pkg.tgz""#,
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(report.findings[0].reason_code, "lockfile_external_source");
    }

    #[test]
    fn package_lock_parse_error_blocks() {
        let report = scan_source_contents(
            "package-lock.json",
            SourceFileKind::PackageLock,
            r#""resolved": "https://registry.npmjs.org/pkg"#,
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(report.findings[0].reason_code, "lockfile_parse_error");
    }

    #[test]
    fn requirements_direct_url_blocks() {
        let report = scan_source_contents(
            "requirements.txt",
            SourceFileKind::Requirements,
            "pkg @ https://example.test/pkg.whl\n",
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(report.findings[0].reason_code, "requirements_direct_source");
    }

    #[test]
    fn requirements_vault_index_allows() {
        let report = scan_source_contents(
            "requirements.txt",
            SourceFileKind::Requirements,
            "--index-url http://127.0.0.1:4873/pypi/simple\n",
            VAULT,
        );
        assert!(!report.has_blocking_findings());
    }

    #[test]
    fn requirements_bare_relative_path_blocks() {
        let report = scan_source_contents(
            "requirements.txt",
            SourceFileKind::Requirements,
            "vendor/pkg\n",
            VAULT,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(
            report.findings[0].reason_code,
            "requirements_local_path_source"
        );
    }

    #[test]
    fn requirements_include_path_traversal_blocks() {
        let root = temp_root("whoathere-req-traversal");
        fs::write(root.join("requirements.txt"), "-r ../outside.txt\n").expect("write req");
        let report = scan_workspace(&root, VAULT);
        assert!(report.has_blocking_findings());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "requirements_include_path_traversal"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn workspace_scan_reads_known_files_and_includes() {
        let root = temp_root("whoathere-source-scan");
        fs::write(
            root.join(".npmrc"),
            "registry=https://registry.npmjs.org/\n",
        )
        .expect("write npmrc");
        fs::write(root.join("requirements.txt"), "-r constraints.txt\n").expect("write req");
        fs::write(
            root.join("constraints.txt"),
            "pkg @ git+https://github.com/acme/pkg\n",
        )
        .expect("write constraints");
        let report = scan_workspace(&root, VAULT);
        assert_eq!(report.files_scanned, 3);
        assert!(report.has_blocking_findings());
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "requirements_vcs_source"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn package_json_identity_discovery_uses_dependency_sections_only() {
        let report = extract_package_identities(
            "package.json",
            SourceFileKind::PackageJson,
            r#"{
                "scripts": {"postinstall": "echo @company/not-a-dep"},
                "dependencies": {
                    "@company/build-tools": "^1.0.0",
                    "left-pad": "git+https://github.com/acme/left-pad.git"
                }
            }"#,
        );
        assert!(!report.has_blocking_findings());
        assert!(report.identities.iter().any(|identity| {
            identity.name == "@company/build-tools"
                && identity.source_kind == PackageIdentitySourceKind::PublicRegistry
        }));
        assert!(report.identities.iter().any(|identity| {
            identity.name == "left-pad" && identity.source_kind == PackageIdentitySourceKind::Git
        }));
        assert!(!report
            .identities
            .iter()
            .any(|identity| identity.name == "@company/not-a-dep"));
    }

    #[test]
    fn malformed_package_json_identity_discovery_fails_closed() {
        let report = extract_package_identities(
            "package.json",
            SourceFileKind::PackageJson,
            r#"{"dependencies": {"@company/build-tools": "^1.0.0""#,
        );
        assert!(report.has_blocking_findings());
        assert_eq!(
            report.findings[0].reason_code,
            "package_identity_manifest_parse_error"
        );
    }

    #[test]
    fn requirements_identity_discovery_extracts_names_and_sources() {
        let report = extract_package_identities(
            "requirements.txt",
            SourceFileKind::Requirements,
            "company-internal[cli]>=1.0 ; python_version >= \"3.11\"\ncompany-direct @ https://example.test/pkg.whl\n",
        );
        assert!(report.identities.iter().any(|identity| {
            identity.name == "company-internal"
                && identity.source_kind == PackageIdentitySourceKind::PublicRegistry
        }));
        assert!(report.identities.iter().any(|identity| {
            identity.name == "company-direct"
                && identity.source_kind == PackageIdentitySourceKind::DirectUrl
        }));
    }

    #[test]
    fn requirements_identity_discovery_follows_safe_includes() {
        let root = temp_root("whoathere-req-identity-includes");
        fs::write(root.join("custom.txt"), "-r nested/constraints.txt\n")
            .expect("write custom req");
        fs::create_dir_all(root.join("nested")).expect("create nested");
        fs::write(
            root.join("nested/constraints.txt"),
            "company-internal>=1.0\n",
        )
        .expect("write nested req");
        let report = discover_requirements_identities(&root, "custom.txt");
        assert_eq!(report.files_scanned, 2);
        assert!(report.identities.iter().any(|identity| {
            identity.file == "nested/constraints.txt" && identity.name == "company-internal"
        }));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn requirements_identity_discovery_blocks_path_traversal() {
        let root = temp_root("whoathere-req-identity-traversal");
        fs::write(root.join("custom.txt"), "-r ../outside.txt\n").expect("write custom req");
        let report = discover_requirements_identities(&root, "custom.txt");
        assert!(report.has_blocking_findings());
        assert!(report.findings.iter().any(|finding| {
            finding.reason_code == "requirements_identity_include_path_traversal"
        }));
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn requirements_identity_discovery_blocks_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = temp_root("whoathere-req-identity-symlink");
        let outside = root.with_extension("outside.txt");
        fs::write(&outside, "company-outside>=1.0\n").expect("write outside req");
        symlink(&outside, root.join("linked.txt")).expect("symlink outside");
        let report = discover_requirements_identities(&root, "linked.txt");
        assert!(report.has_blocking_findings());
        assert!(report.findings.iter().any(|finding| {
            finding.reason_code == "requirements_identity_include_path_traversal"
        }));
        assert!(!report
            .identities
            .iter()
            .any(|identity| identity.name == "company-outside"));
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn requirements_source_scan_blocks_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = temp_root("whoathere-req-source-symlink");
        let outside = root.with_extension("outside-source.txt");
        fs::write(&outside, "--index-url https://pypi.org/simple\n").expect("write outside req");
        symlink(&outside, root.join("linked.txt")).expect("symlink outside");
        let report = scan_requirements_path(&root, "linked.txt", VAULT);
        assert!(report.has_blocking_findings());
        assert!(report
            .findings
            .iter()
            .any(|finding| { finding.reason_code == "requirements_include_path_traversal" }));
        assert!(!report
            .findings
            .iter()
            .any(|finding| finding.reason_code == "requirements_index_override"));
        let _ = fs::remove_file(&outside);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn pyproject_identity_discovery_extracts_project_optional_and_build_dependencies() {
        let report = extract_package_identities(
            "pyproject.toml",
            SourceFileKind::PyProjectToml,
            r#"
[build-system]
requires = ["company-build-backend>=1.0"]

[project]
dependencies = [
  "company-runtime>=2.0",
]

[project.optional-dependencies]
dev = ["company-dev @ git+https://github.com/acme/company-dev.git"]
"#,
        );
        assert!(report.identities.iter().any(|identity| {
            identity.name == "company-build-backend"
                && identity.source_kind == PackageIdentitySourceKind::PublicRegistry
        }));
        assert!(report
            .identities
            .iter()
            .any(|identity| identity.name == "company-runtime"));
        assert!(report.identities.iter().any(|identity| {
            identity.name == "company-dev" && identity.source_kind == PackageIdentitySourceKind::Git
        }));
    }

    #[test]
    fn npm_context_points_only_to_vault_and_scrubs_ambient_env() {
        let context = build_sanitized_context("npm", VAULT).expect("context");
        assert!(context.env_clear);
        assert!(context.env.iter().any(|(key, value)| {
            key == "NPM_CONFIG_REGISTRY" && value == "http://127.0.0.1:4873/npm/"
        }));
        assert!(context
            .scrubbed_env_prefixes
            .contains(&"NPM_CONFIG_".to_string()));
        assert!(!context
            .generated_config_contents
            .contains("registry.npmjs.org"));
        assert!(context.egress_boundary_required);
    }

    #[test]
    fn pip_context_points_only_to_vault_and_scrubs_ambient_env() {
        let context = build_sanitized_context("pip", VAULT).expect("context");
        assert!(context.env.iter().any(|(key, value)| {
            key == "PIP_INDEX_URL" && value == "http://127.0.0.1:4873/pypi/simple"
        }));
        assert!(context.scrubbed_env_prefixes.contains(&"PIP_".to_string()));
        assert!(!context.generated_config_contents.contains("pypi.org"));
    }

    #[test]
    fn materialized_context_uses_private_permissions() {
        let root = temp_root("whoathere-context");
        let context = build_sanitized_context("npm", VAULT).expect("context");
        let materialized = materialize_sanitized_config(&context, &root).expect("materialize");
        assert_eq!(
            materialized.bytes_written,
            context.generated_config_contents.len()
        );
        assert!(materialized.permissions_private);
        assert!(materialized.config_path.ends_with("npmrc"));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn rejects_plain_http_public_vault_origin() {
        let error = build_sanitized_context("npm", "http://registry.npmjs.org").unwrap_err();
        assert_eq!(
            error,
            ContextError::InvalidVaultOrigin("http://registry.npmjs.org".to_string())
        );
    }

    #[test]
    fn rejects_https_public_registry_as_vault_origin() {
        let error = build_sanitized_context("pip", "https://pypi.org").unwrap_err();
        assert_eq!(
            error,
            ContextError::InvalidVaultOrigin("https://pypi.org".to_string())
        );
    }

    fn temp_root(prefix: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).expect("create root");
        root
    }
}
