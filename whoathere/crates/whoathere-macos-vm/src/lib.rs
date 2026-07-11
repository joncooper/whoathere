mod artifact_backend;
mod artifact_guest_auth;
mod artifact_guest_control;
mod artifact_guest_receipt;
mod artifact_guest_staging;
mod artifact_guest_supervisor;
mod artifact_transport;
mod wheel_backend;
mod wheel_transport;

pub use artifact_backend::*;
pub use artifact_guest_auth::*;
pub use artifact_guest_control::*;
pub use artifact_guest_receipt::*;
pub use artifact_guest_staging::*;
pub use artifact_guest_supervisor::*;
pub use artifact_transport::*;
pub use wheel_backend::*;
pub use wheel_transport::*;

use std::path::{Path, PathBuf};

pub const STATUS_SCHEMA_VERSION: &str = "whoathere.macos_vm.status.v1";
pub const IMAGE_MANIFEST_SCHEMA_VERSION: &str = "whoathere.macos_vm_image.v1";
pub const RELEASE_TARGET: &str = "macos_apple_silicon_local_vm";
pub const TARGET_ARCH: &str = "arm64";
pub const VM_BOUNDARY: &str = "apple_virtualization_macos_guest";
pub const NETWORK_MODEL: &str = "recorded_egress";
pub const SYNC_POLICY: &str = "sync_back_local_beta_allowlist_v1";
pub const ARTIFACT_DETECTION_SYNC_BACK_DENIED: &str = "artifact_detection_sync_back_forbidden";
pub const UNKNOWN_ARTIFACT_SYNC_BACK_DENIED: &str = "unknown_artifact_sync_back_forbidden";
pub const RESTRICTED_MALWARE_LAB_SYNC_BACK_DENIED: &str =
    "restricted_malware_lab_sync_back_forbidden";
pub const RELEASE_CLAIM: &str = "vm_detonation_with_safe_sync_back_beta";
pub const DEFAULT_MEMORY_MIB: u64 = 6144;
pub const DEFAULT_NATIVE_MEMORY_MIB: u64 = 8192;
pub const DEFAULT_DISK_GIB: u64 = 64;
pub const MIN_DISK_GIB: u64 = 64;
pub const DEFAULT_AUTO_SUSPEND_MINUTES: u64 = 15;

/// Security scope for a VM detonation job.
///
/// The local-beta project workflow predates artifact-native detection and may
/// still request its evidence-bound allowlist sync. Artifact detection jobs do
/// not trust files produced by the guest and therefore cannot authorize the
/// helper's `--sync-back` flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetonationJobScope {
    ProjectAdmission,
    ArtifactDetection,
    UnknownArtifactDetection,
    RestrictedMalwareLab,
}

impl DetonationJobScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProjectAdmission => "project_admission",
            Self::ArtifactDetection => "artifact_detection",
            Self::UnknownArtifactDetection => "unknown_artifact_detection",
            Self::RestrictedMalwareLab => "restricted_malware_lab",
        }
    }
}

/// Scope-bound decision controlling whether the VM helper may receive a
/// sync-back argument.
///
/// Fields are private so callers cannot construct an enabled decision without
/// passing through [`decide_detonation_sync_back`]. Artifact-native callers
/// should forward only [`Self::helper_argument`] rather than retaining a raw
/// sync-back boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use = "the scope-bound sync-back decision must be enforced"]
pub struct DetonationSyncBackDecision {
    scope: DetonationJobScope,
    requested: bool,
    enabled: bool,
    denial_reason_code: Option<&'static str>,
}

impl DetonationSyncBackDecision {
    pub fn scope(self) -> DetonationJobScope {
        self.scope
    }

    pub fn requested(self) -> bool {
        self.requested
    }

    pub fn enabled(self) -> bool {
        self.enabled
    }

    pub fn denial_reason_code(self) -> Option<&'static str> {
        self.denial_reason_code
    }

    pub fn helper_argument(self) -> Option<&'static str> {
        self.enabled.then_some("--sync-back")
    }
}

/// Decide whether a detonation job may request guest-to-host copy-back.
///
/// Artifact-native, unknown-artifact, and restricted-malware scopes always
/// return a disabled decision. A request in one of those scopes is retained as
/// an auditable policy denial with a stable reason code.
#[must_use = "the scope-bound sync-back decision must be enforced"]
pub fn decide_detonation_sync_back(
    scope: DetonationJobScope,
    requested: bool,
) -> DetonationSyncBackDecision {
    let denial_reason_code = if requested {
        match scope {
            DetonationJobScope::ProjectAdmission => None,
            DetonationJobScope::ArtifactDetection => Some(ARTIFACT_DETECTION_SYNC_BACK_DENIED),
            DetonationJobScope::UnknownArtifactDetection => Some(UNKNOWN_ARTIFACT_SYNC_BACK_DENIED),
            DetonationJobScope::RestrictedMalwareLab => {
                Some(RESTRICTED_MALWARE_LAB_SYNC_BACK_DENIED)
            }
        }
    } else {
        None
    };
    let enabled =
        requested && scope == DetonationJobScope::ProjectAdmission && denial_reason_code.is_none();

    DetonationSyncBackDecision {
        scope,
        requested,
        enabled,
        denial_reason_code,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPlatform {
    pub os: String,
    pub arch: String,
}

impl HostPlatform {
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
        }
    }

    pub fn is_supported_apple_silicon_macos(&self) -> bool {
        self.os == "macos" && normalize_arch(&self.arch) == TARGET_ARCH
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosVmConfig {
    pub state_dir: PathBuf,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub auto_suspend_minutes: u64,
}

impl MacosVmConfig {
    pub fn new(state_dir: PathBuf) -> Self {
        Self {
            state_dir,
            memory_mib: DEFAULT_MEMORY_MIB,
            disk_gib: DEFAULT_DISK_GIB,
            auto_suspend_minutes: DEFAULT_AUTO_SUSPEND_MINUTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosVmImageManifest {
    pub schema_version: String,
    pub image_id: String,
    pub macos_version: String,
    pub architecture: String,
    pub image_digest: String,
    pub signature_status: String,
}

impl MacosVmImageManifest {
    pub fn validate(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.schema_version != IMAGE_MANIFEST_SCHEMA_VERSION {
            reasons.push("macos_vm_manifest_schema_invalid".to_string());
        }
        if self.image_id.trim().is_empty() {
            reasons.push("macos_vm_manifest_image_id_empty".to_string());
        }
        if self.macos_version.trim().is_empty() {
            reasons.push("macos_vm_manifest_macos_version_empty".to_string());
        }
        if normalize_arch(&self.architecture) != TARGET_ARCH {
            reasons.push("macos_vm_manifest_arch_not_arm64".to_string());
        }
        if !valid_sha256_digest(&self.image_digest) {
            reasons.push("macos_vm_manifest_image_digest_invalid".to_string());
        }
        if !matches!(
            self.signature_status.as_str(),
            "verified" | "local_developer_verified"
        ) {
            reasons.push("macos_vm_manifest_signature_not_verified".to_string());
        }
        reasons
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosVmStatus {
    pub schema_version: &'static str,
    pub release_target: &'static str,
    pub target_arch: &'static str,
    pub vm_boundary: &'static str,
    pub network_model: &'static str,
    pub sync_policy: &'static str,
    pub state_dir: PathBuf,
    pub host: HostPlatform,
    pub memory_mib: u64,
    pub disk_gib: u64,
    pub auto_suspend_minutes: u64,
    pub state_dir_exists: bool,
    pub manifest_present: bool,
    pub manifest_valid: bool,
    pub helper_ready_marker_present: bool,
    pub image_ready_marker_present: bool,
    pub ready: bool,
    pub reason_codes: Vec<String>,
}

pub fn default_state_dir() -> PathBuf {
    std::env::var("HOME")
        .map(|home| PathBuf::from(home).join(".whoathere").join("macos-vm"))
        .unwrap_or_else(|_| PathBuf::from(".whoathere").join("macos-vm"))
}

pub fn status_from_config(
    config: &MacosVmConfig,
    host: HostPlatform,
    manifest: Option<&MacosVmImageManifest>,
) -> MacosVmStatus {
    let state_dir_exists = config.state_dir.is_dir();
    let helper_ready_marker_present = config.state_dir.join("helper.ready").is_file();
    let image_ready_marker_present = config.state_dir.join("image.ready").is_file();
    let mut reason_codes = Vec::new();

    if host.os != "macos" {
        reason_codes.push("macos_vm_host_not_macos".to_string());
    }
    if normalize_arch(&host.arch) != TARGET_ARCH {
        reason_codes.push("macos_vm_host_not_apple_silicon".to_string());
    }
    if config.memory_mib < 4096 {
        reason_codes.push("macos_vm_memory_below_minimum".to_string());
    }
    if config.disk_gib < MIN_DISK_GIB {
        reason_codes.push("macos_vm_disk_below_minimum".to_string());
    }
    if !state_dir_exists {
        reason_codes.push("macos_vm_state_dir_missing".to_string());
    }

    let manifest_present = manifest.is_some();
    let manifest_valid = manifest
        .map(|manifest| {
            let manifest_reasons = manifest.validate();
            reason_codes.extend(manifest_reasons.iter().cloned());
            manifest_reasons.is_empty()
        })
        .unwrap_or_else(|| {
            reason_codes.push("macos_vm_image_manifest_missing".to_string());
            false
        });

    if !helper_ready_marker_present {
        reason_codes.push("macos_vm_helper_not_ready".to_string());
    }
    if !image_ready_marker_present {
        reason_codes.push("macos_vm_image_not_ready".to_string());
    }

    reason_codes.push("macos_vm_runtime_not_verified".to_string());
    reason_codes.sort();
    reason_codes.dedup();

    MacosVmStatus {
        schema_version: STATUS_SCHEMA_VERSION,
        release_target: RELEASE_TARGET,
        target_arch: TARGET_ARCH,
        vm_boundary: VM_BOUNDARY,
        network_model: NETWORK_MODEL,
        sync_policy: SYNC_POLICY,
        state_dir: config.state_dir.clone(),
        host,
        memory_mib: config.memory_mib,
        disk_gib: config.disk_gib,
        auto_suspend_minutes: config.auto_suspend_minutes,
        state_dir_exists,
        manifest_present,
        manifest_valid,
        helper_ready_marker_present,
        image_ready_marker_present,
        ready: false,
        reason_codes,
    }
}

pub fn parse_image_manifest(input: &str) -> Result<MacosVmImageManifest, String> {
    let mut schema_version = None;
    let mut image_id = None;
    let mut macos_version = None;
    let mut architecture = None;
    let mut image_digest = None;
    let mut signature_status = None;

    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("manifest_line_invalid:{line}"));
        };
        let value = value.trim().to_string();
        match key.trim() {
            "schema_version" => schema_version = Some(value),
            "image_id" => image_id = Some(value),
            "macos_version" => macos_version = Some(value),
            "architecture" => architecture = Some(value),
            "image_digest" | "restore_image_digest" => image_digest = Some(value),
            "signature_status" => signature_status = Some(value),
            "macos_build_version" | "cpu_count" | "memory_mib" | "helper_version" => {}
            unknown => return Err(format!("manifest_key_unknown:{unknown}")),
        }
    }

    Ok(MacosVmImageManifest {
        schema_version: schema_version.unwrap_or_default(),
        image_id: image_id.unwrap_or_default(),
        macos_version: macos_version.unwrap_or_default(),
        architecture: architecture.unwrap_or_default(),
        image_digest: image_digest.unwrap_or_default(),
        signature_status: signature_status.unwrap_or_default(),
    })
}

pub fn create_state_dirs(state_dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(state_dir.join("cache"))?;
    std::fs::create_dir_all(state_dir.join("runs"))?;
    std::fs::create_dir_all(state_dir.join("reports"))?;
    std::fs::create_dir_all(state_dir.join("overlays"))?;
    Ok(())
}

pub fn normalize_arch(arch: &str) -> &str {
    match arch {
        "aarch64" | "arm64" => "arm64",
        value => value,
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageClass {
    NpmRegistryTarball,
    PypiPureWheel,
    PypiSdistPep517,
    PypiBinaryWheel,
    NativeExtension,
    DirectVcsEditable,
    UnsupportedUnknown,
}

impl PackageClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NpmRegistryTarball => "npm.registry_tarball.v1",
            Self::PypiPureWheel => "pypi.pure_wheel.v1",
            Self::PypiSdistPep517 => "pypi.sdist_pep517.v1",
            Self::PypiBinaryWheel => "pypi.binary_wheel.v1",
            Self::NativeExtension => "native_extension.v1",
            Self::DirectVcsEditable => "direct_vcs_editable.v1",
            Self::UnsupportedUnknown => "unsupported_unknown.v1",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "npm.registry_tarball.v1" | "npm" | "npm-registry-tarball" => {
                Some(Self::NpmRegistryTarball)
            }
            "pypi.pure_wheel.v1" | "pypi-pure-wheel" | "pure-wheel" => Some(Self::PypiPureWheel),
            "pypi.sdist_pep517.v1" | "pypi-sdist-pep517" | "sdist" | "pep517" => {
                Some(Self::PypiSdistPep517)
            }
            "pypi.binary_wheel.v1" | "pypi-binary-wheel" | "binary-wheel" => {
                Some(Self::PypiBinaryWheel)
            }
            "native_extension.v1" | "native-extension" | "native" => Some(Self::NativeExtension),
            "direct_vcs_editable.v1" | "direct" | "vcs" | "editable" => {
                Some(Self::DirectVcsEditable)
            }
            "unsupported_unknown.v1" | "unknown" | "unsupported" => Some(Self::UnsupportedUnknown),
            _ => None,
        }
    }

    pub fn auto_sync_eligible(self) -> bool {
        matches!(self, Self::NpmRegistryTarball | Self::PypiPureWheel)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactSignals {
    pub ecosystem: String,
    pub source: String,
    pub filename: String,
    pub has_lifecycle_script: bool,
    pub has_pep517_backend: bool,
    pub has_native_marker: bool,
    pub editable: bool,
}

impl ArtifactSignals {
    pub fn new(
        ecosystem: impl Into<String>,
        source: impl Into<String>,
        filename: impl Into<String>,
    ) -> Self {
        Self {
            ecosystem: ecosystem.into(),
            source: source.into(),
            filename: filename.into(),
            has_lifecycle_script: false,
            has_pep517_backend: false,
            has_native_marker: false,
            editable: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalAdmissionVerdict {
    AutoSync,
    ManualReview,
    Deny,
}

impl LocalAdmissionVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AutoSync => "auto_sync",
            Self::ManualReview => "manual_review",
            Self::Deny => "deny",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEvidenceFlags {
    pub vm_ready: bool,
    pub static_clean: bool,
    pub dynamic_clean: bool,
    pub egress_clean: bool,
    pub no_canary_access: bool,
    pub scanner_clean: bool,
    pub diff_clean_or_baseline_absent: bool,
    pub freshness_allowed: bool,
}

impl LocalEvidenceFlags {
    pub fn clean(vm_ready: bool) -> Self {
        Self {
            vm_ready,
            static_clean: true,
            dynamic_clean: true,
            egress_clean: true,
            no_canary_access: true,
            scanner_clean: true,
            diff_clean_or_baseline_absent: true,
            freshness_allowed: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalAdmissionDecision {
    pub package_class: PackageClass,
    pub verdict: LocalAdmissionVerdict,
    pub auto_sync_eligible: bool,
    pub sync_paths: Vec<&'static str>,
    pub required_evidence: Vec<&'static str>,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanarySpec {
    pub category: &'static str,
    pub env_name: &'static str,
    pub path_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncPathRule {
    pub path_pattern: &'static str,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScannerAdapterSpec {
    pub name: &'static str,
    pub required_for_auto_sync: bool,
    pub evidence_role: &'static str,
}

pub fn classify_artifact(signals: &ArtifactSignals) -> PackageClass {
    let ecosystem = signals.ecosystem.to_ascii_lowercase();
    let source = signals.source.to_ascii_lowercase();
    let filename = signals.filename.to_ascii_lowercase();

    if signals.editable
        || matches!(
            source.as_str(),
            "direct" | "direct_url" | "url" | "vcs" | "git" | "local" | "path" | "editable"
        )
        || filename.starts_with("git+")
        || filename.starts_with("http://")
        || filename.starts_with("https://")
    {
        return PackageClass::DirectVcsEditable;
    }

    if signals.has_native_marker
        || filename.contains("binding.gyp")
        || filename.contains("node-gyp")
        || filename.contains("native")
    {
        return PackageClass::NativeExtension;
    }

    match ecosystem.as_str() {
        "npm" if matches!(source.as_str(), "registry" | "tarball" | "npm") => {
            PackageClass::NpmRegistryTarball
        }
        "pypi" | "pip" | "uv" | "python" => {
            if filename.ends_with(".whl") {
                if filename.contains("-none-any.whl") && !signals.has_pep517_backend {
                    PackageClass::PypiPureWheel
                } else {
                    PackageClass::PypiBinaryWheel
                }
            } else if signals.has_pep517_backend
                || filename.ends_with(".tar.gz")
                || filename.ends_with(".zip")
            {
                PackageClass::PypiSdistPep517
            } else {
                PackageClass::UnsupportedUnknown
            }
        }
        _ => PackageClass::UnsupportedUnknown,
    }
}

pub fn decide_local_sync(
    package_class: PackageClass,
    evidence: &LocalEvidenceFlags,
) -> LocalAdmissionDecision {
    let mut reason_codes = Vec::new();

    if !evidence.vm_ready {
        reason_codes.push("macos_vm_not_ready".to_string());
    }
    if !evidence.static_clean {
        reason_codes.push("static_evidence_not_clean".to_string());
    }
    if !evidence.dynamic_clean {
        reason_codes.push("dynamic_evidence_not_clean".to_string());
    }
    if !evidence.egress_clean {
        reason_codes.push("recorded_egress_not_clean".to_string());
    }
    if !evidence.no_canary_access {
        reason_codes.push("canary_access_observed".to_string());
    }
    if !evidence.scanner_clean {
        reason_codes.push("scanner_evidence_not_clean".to_string());
    }
    if !evidence.diff_clean_or_baseline_absent {
        reason_codes.push("known_good_diff_not_clean".to_string());
    }
    if !evidence.freshness_allowed {
        reason_codes.push("fresh_release_cooldown_active".to_string());
    }

    let class_reason = match package_class {
        PackageClass::NpmRegistryTarball | PackageClass::PypiPureWheel => None,
        PackageClass::PypiSdistPep517 => Some("pypi_sdist_or_pep517_requires_manual_review"),
        PackageClass::PypiBinaryWheel => Some("binary_wheel_requires_manual_review"),
        PackageClass::NativeExtension => Some("native_extension_requires_manual_review"),
        PackageClass::DirectVcsEditable => Some("direct_vcs_editable_denied_by_default"),
        PackageClass::UnsupportedUnknown => Some("unsupported_package_class_denied_by_default"),
    };
    if let Some(reason) = class_reason {
        reason_codes.push(reason.to_string());
    }

    let verdict = if matches!(
        package_class,
        PackageClass::DirectVcsEditable | PackageClass::UnsupportedUnknown
    ) {
        LocalAdmissionVerdict::Deny
    } else if !package_class.auto_sync_eligible() {
        LocalAdmissionVerdict::ManualReview
    } else if evidence.vm_ready
        && evidence.static_clean
        && evidence.dynamic_clean
        && evidence.egress_clean
        && evidence.no_canary_access
        && evidence.scanner_clean
        && evidence.diff_clean_or_baseline_absent
        && evidence.freshness_allowed
    {
        LocalAdmissionVerdict::AutoSync
    } else if !evidence.egress_clean || !evidence.no_canary_access {
        LocalAdmissionVerdict::Deny
    } else {
        LocalAdmissionVerdict::ManualReview
    };

    reason_codes.sort();
    reason_codes.dedup();

    LocalAdmissionDecision {
        package_class,
        verdict,
        auto_sync_eligible: package_class.auto_sync_eligible(),
        sync_paths: sync_paths_for_class(package_class),
        required_evidence: required_local_evidence(),
        reason_codes,
    }
}

pub fn required_local_evidence() -> Vec<&'static str> {
    vec![
        "signed_vm_image_manifest_verified",
        "vm_guest_isolation_ready",
        "sanitized_project_mirror_used",
        "static_scan_clean",
        "dynamic_install_build_import_probes_clean",
        "recorded_egress_clean",
        "canary_credentials_not_accessed",
        "scanner_adapters_clean",
        "known_good_diff_clean_or_absent",
        "fresh_release_cooldown_satisfied",
    ]
}

pub fn default_canaries() -> Vec<CanarySpec> {
    vec![
        CanarySpec {
            category: "npm",
            env_name: "NPM_TOKEN",
            path_hint: "~/.npmrc",
        },
        CanarySpec {
            category: "pypi",
            env_name: "TWINE_PASSWORD",
            path_hint: "~/.pypirc",
        },
        CanarySpec {
            category: "github",
            env_name: "GITHUB_TOKEN",
            path_hint: "~/.config/gh/hosts.yml",
        },
        CanarySpec {
            category: "ssh",
            env_name: "SSH_AUTH_SOCK",
            path_hint: "~/.ssh",
        },
        CanarySpec {
            category: "cloud",
            env_name: "AWS_ACCESS_KEY_ID",
            path_hint: "~/.aws/credentials",
        },
        CanarySpec {
            category: "kubernetes",
            env_name: "KUBECONFIG",
            path_hint: "~/.kube/config",
        },
        CanarySpec {
            category: "vault",
            env_name: "VAULT_TOKEN",
            path_hint: "~/.vault-token",
        },
        CanarySpec {
            category: "env",
            env_name: "WHOATHERE_CANARY_ENV",
            path_hint: ".env",
        },
        CanarySpec {
            category: "ai_tool",
            env_name: "OPENAI_API_KEY",
            path_hint: "~/.config",
        },
    ]
}

pub fn default_sync_allowlist() -> Vec<SyncPathRule> {
    vec![
        SyncPathRule {
            path_pattern: "node_modules/**",
            reason: "npm project dependency output",
        },
        SyncPathRule {
            path_pattern: "package-lock.json",
            reason: "npm lockfile output",
        },
        SyncPathRule {
            path_pattern: ".venv/**",
            reason: "project-local Python virtual environment output",
        },
        SyncPathRule {
            path_pattern: "uv.lock",
            reason: "uv lockfile output",
        },
        SyncPathRule {
            path_pattern: "requirements*.txt",
            reason: "explicit package-manager output only",
        },
    ]
}

pub fn scanner_adapters() -> Vec<ScannerAdapterSpec> {
    vec![
        ScannerAdapterSpec {
            name: "guarddog",
            required_for_auto_sync: true,
            evidence_role: "malicious package static indicators",
        },
        ScannerAdapterSpec {
            name: "osv-scanner",
            required_for_auto_sync: true,
            evidence_role: "known vulnerability evidence",
        },
        ScannerAdapterSpec {
            name: "pip-audit",
            required_for_auto_sync: true,
            evidence_role: "Python dependency vulnerability evidence",
        },
        ScannerAdapterSpec {
            name: "scorecard",
            required_for_auto_sync: false,
            evidence_role: "source repository reputation evidence",
        },
        ScannerAdapterSpec {
            name: "syft",
            required_for_auto_sync: false,
            evidence_role: "SBOM evidence",
        },
        ScannerAdapterSpec {
            name: "grype",
            required_for_auto_sync: false,
            evidence_role: "SBOM vulnerability evidence",
        },
        ScannerAdapterSpec {
            name: "trivy",
            required_for_auto_sync: false,
            evidence_role: "vulnerability and secret evidence",
        },
    ]
}

fn sync_paths_for_class(package_class: PackageClass) -> Vec<&'static str> {
    match package_class {
        PackageClass::NpmRegistryTarball => vec!["node_modules/**", "package-lock.json"],
        PackageClass::PypiPureWheel => vec![".venv/**", "uv.lock", "requirements*.txt"],
        PackageClass::PypiSdistPep517
        | PackageClass::PypiBinaryWheel
        | PackageClass::NativeExtension
        | PackageClass::DirectVcsEditable
        | PackageClass::UnsupportedUnknown => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

    #[test]
    fn parses_and_validates_signed_arm64_manifest() {
        let manifest = parse_image_manifest(&format!(
            "schema_version={IMAGE_MANIFEST_SCHEMA_VERSION}\nimage_id=ventura-base\nmacos_version=14.5\narchitecture=arm64\nimage_digest={DIGEST}\nsignature_status=verified\n"
        ))
        .expect("manifest");
        assert!(manifest.validate().is_empty());
    }

    #[test]
    fn parses_and_validates_local_developer_verified_manifest() {
        let manifest = parse_image_manifest(&format!(
            "schema_version={IMAGE_MANIFEST_SCHEMA_VERSION}\nimage_id=local-restore-image-install\nmacos_version=26.5.1\nmacos_build_version=25F80\narchitecture=arm64\nrestore_image_digest={DIGEST}\ncpu_count=2\nmemory_mib=6144\nsignature_status=local_developer_verified\nhelper_version=0.1.0\n"
        ))
        .expect("manifest");
        assert_eq!(manifest.image_digest, DIGEST);
        assert_eq!(manifest.signature_status, "local_developer_verified");
        assert!(manifest.validate().is_empty());
    }

    #[test]
    fn parses_helper_restore_image_manifest_shape() {
        let manifest = parse_image_manifest(&format!(
            "schema_version={IMAGE_MANIFEST_SCHEMA_VERSION}\nimage_id=local-restore-image-install\nmacos_version=26.5.1\nmacos_build_version=25F80\narchitecture=arm64\nrestore_image_digest={DIGEST}\ncpu_count=2\nmemory_mib=6144\nsignature_status=signature_verification_not_implemented\nhelper_version=0.1.0\n"
        ))
        .expect("manifest");
        assert_eq!(manifest.image_digest, DIGEST);
        assert_eq!(
            manifest.signature_status,
            "signature_verification_not_implemented"
        );
        assert_eq!(
            manifest.validate(),
            vec!["macos_vm_manifest_signature_not_verified".to_string()]
        );
    }

    #[test]
    fn invalid_manifest_reports_specific_reasons() {
        let manifest = MacosVmImageManifest {
            schema_version: "old".to_string(),
            image_id: "".to_string(),
            macos_version: "".to_string(),
            architecture: "x86_64".to_string(),
            image_digest: "sha256:bad".to_string(),
            signature_status: "unsigned".to_string(),
        };
        let reasons = manifest.validate();
        assert!(reasons.contains(&"macos_vm_manifest_schema_invalid".to_string()));
        assert!(reasons.contains(&"macos_vm_manifest_arch_not_arm64".to_string()));
        assert!(reasons.contains(&"macos_vm_manifest_image_digest_invalid".to_string()));
        assert!(reasons.contains(&"macos_vm_manifest_signature_not_verified".to_string()));
    }

    #[test]
    fn status_is_fail_closed_until_runtime_exists() {
        let root =
            std::env::temp_dir().join(format!("whoathere-macos-vm-status-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        create_state_dirs(&root).expect("state dirs");
        std::fs::write(root.join("helper.ready"), "fixture").expect("helper marker");
        std::fs::write(root.join("image.ready"), "fixture").expect("image marker");
        let manifest = MacosVmImageManifest {
            schema_version: IMAGE_MANIFEST_SCHEMA_VERSION.to_string(),
            image_id: "fixture".to_string(),
            macos_version: "14.5".to_string(),
            architecture: "aarch64".to_string(),
            image_digest: DIGEST.to_string(),
            signature_status: "verified".to_string(),
        };
        let status = status_from_config(
            &MacosVmConfig::new(root.clone()),
            HostPlatform {
                os: "macos".to_string(),
                arch: "aarch64".to_string(),
            },
            Some(&manifest),
        );
        assert!(!status.ready);
        assert!(status
            .reason_codes
            .contains(&"macos_vm_runtime_not_verified".to_string()));
        assert!(!status
            .reason_codes
            .contains(&"macos_vm_host_not_apple_silicon".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn status_rejects_restore_disk_below_minimum() {
        let root = std::env::temp_dir().join(format!(
            "whoathere-macos-vm-small-disk-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        create_state_dirs(&root).expect("state dirs");
        let mut config = MacosVmConfig::new(root.clone());
        config.disk_gib = MIN_DISK_GIB - 1;
        let status = status_from_config(
            &config,
            HostPlatform {
                os: "macos".to_string(),
                arch: "aarch64".to_string(),
            },
            None,
        );
        assert!(status
            .reason_codes
            .contains(&"macos_vm_disk_below_minimum".to_string()));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn artifact_and_restricted_detonations_cannot_enable_sync_back() {
        for (scope, expected_reason) in [
            (
                DetonationJobScope::ArtifactDetection,
                ARTIFACT_DETECTION_SYNC_BACK_DENIED,
            ),
            (
                DetonationJobScope::UnknownArtifactDetection,
                UNKNOWN_ARTIFACT_SYNC_BACK_DENIED,
            ),
            (
                DetonationJobScope::RestrictedMalwareLab,
                RESTRICTED_MALWARE_LAB_SYNC_BACK_DENIED,
            ),
        ] {
            let decision = decide_detonation_sync_back(scope, true);
            assert!(decision.requested());
            assert!(!decision.enabled());
            assert_eq!(decision.scope(), scope);
            assert_eq!(decision.denial_reason_code(), Some(expected_reason));
            assert_eq!(decision.helper_argument(), None);
        }
    }

    #[test]
    fn artifact_detonation_no_sync_is_structurally_forwarded_without_helper_flag() {
        let decision = decide_detonation_sync_back(DetonationJobScope::ArtifactDetection, false);
        assert!(!decision.requested());
        assert!(!decision.enabled());
        assert_eq!(decision.denial_reason_code(), None);
        assert_eq!(decision.helper_argument(), None);
    }

    #[test]
    fn project_admission_sync_back_behavior_remains_backward_compatible() {
        let requested = decide_detonation_sync_back(DetonationJobScope::ProjectAdmission, true);
        assert!(requested.enabled());
        assert_eq!(requested.denial_reason_code(), None);
        assert_eq!(requested.helper_argument(), Some("--sync-back"));

        let not_requested =
            decide_detonation_sync_back(DetonationJobScope::ProjectAdmission, false);
        assert!(!not_requested.enabled());
        assert_eq!(not_requested.helper_argument(), None);
    }

    #[test]
    fn classifies_only_pure_safe_artifacts_as_auto_sync_candidates() {
        let npm = ArtifactSignals::new("npm", "registry", "left-pad-1.3.0.tgz");
        assert_eq!(classify_artifact(&npm), PackageClass::NpmRegistryTarball);

        let wheel = ArtifactSignals::new("pypi", "registry", "pkg-1.0.0-py3-none-any.whl");
        assert_eq!(classify_artifact(&wheel), PackageClass::PypiPureWheel);

        let binary = ArtifactSignals::new("pypi", "registry", "pkg-1.0.0-cp312-macosx.whl");
        assert_eq!(classify_artifact(&binary), PackageClass::PypiBinaryWheel);

        let direct = ArtifactSignals::new("pypi", "git", "git+https://example.invalid/pkg.git");
        assert_eq!(classify_artifact(&direct), PackageClass::DirectVcsEditable);
    }

    #[test]
    fn auto_sync_requires_vm_and_complete_clean_evidence() {
        let blocked = decide_local_sync(
            PackageClass::NpmRegistryTarball,
            &LocalEvidenceFlags::clean(false),
        );
        assert_eq!(blocked.verdict, LocalAdmissionVerdict::ManualReview);
        assert!(blocked
            .reason_codes
            .contains(&"macos_vm_not_ready".to_string()));

        let allowed = decide_local_sync(
            PackageClass::NpmRegistryTarball,
            &LocalEvidenceFlags::clean(true),
        );
        assert_eq!(allowed.verdict, LocalAdmissionVerdict::AutoSync);
        assert!(allowed.reason_codes.is_empty());
        assert_eq!(
            allowed.sync_paths,
            vec!["node_modules/**", "package-lock.json"]
        );
    }

    #[test]
    fn risky_classes_do_not_auto_sync_even_with_clean_evidence() {
        for package_class in [
            PackageClass::PypiSdistPep517,
            PackageClass::PypiBinaryWheel,
            PackageClass::NativeExtension,
        ] {
            let decision = decide_local_sync(package_class, &LocalEvidenceFlags::clean(true));
            assert_eq!(decision.verdict, LocalAdmissionVerdict::ManualReview);
            assert!(!decision.auto_sync_eligible);
            assert!(decision.sync_paths.is_empty());
        }

        let direct = decide_local_sync(
            PackageClass::DirectVcsEditable,
            &LocalEvidenceFlags::clean(true),
        );
        assert_eq!(direct.verdict, LocalAdmissionVerdict::Deny);
    }

    #[test]
    fn canaries_and_scanners_cover_release_contract() {
        let canaries = default_canaries();
        assert!(canaries.iter().any(|canary| canary.env_name == "NPM_TOKEN"));
        assert!(canaries
            .iter()
            .any(|canary| canary.env_name == "OPENAI_API_KEY"));

        let adapters = scanner_adapters();
        assert!(adapters
            .iter()
            .any(|adapter| adapter.name == "guarddog" && adapter.required_for_auto_sync));
        assert!(adapters.iter().any(|adapter| adapter.name == "osv-scanner"));
        assert!(adapters.iter().any(|adapter| adapter.name == "pip-audit"));
    }
}
