//! Artifact-bound deterministic analysis over immutable normalized bytes.
//!
//! This module intentionally has no filesystem or workspace entrypoint. The
//! archive is parsed once by whoathere-artifact; all source access here is by
//! file ID through the resulting NormalizedArtifact.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;
use whoathere_artifact::{
    ArtifactFormat, MemberType, NormalizationCompleteness, NormalizedArtifact,
    NormalizedMemberContent, Sha256Digest,
};

pub const ARTIFACT_STATIC_ANALYSIS_SCHEMA_VERSION: &str = "whoathere.artifact_static_analysis.v1";
pub const ARTIFACT_STATIC_FINDING_SCHEMA_VERSION: &str = "whoathere.artifact_static_finding.v1";
pub const ARTIFACT_TRIGGER_GRAPH_SCHEMA_VERSION: &str = "whoathere.artifact_trigger_graph.v1";
pub const MAX_DETERMINISTIC_TEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_TRIGGER_SURFACES: usize = 512;
pub const MAX_LOCAL_CODE_EDGES: usize = 20_000;
pub const MAX_IMPORT_ATTEMPTS: usize = 50_000;
pub const MAX_TOTAL_REACHABLE_FILE_IDS: usize = 200_000;
pub const MAX_TOTAL_ANALYZED_TEXT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_COMMAND_PATH_CANDIDATES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFindingCategory {
    EnvironmentAccess,
    CredentialAccess,
    SensitivePathAccess,
    NetworkCapability,
    ProcessExecution,
    EnvironmentExfiltrationCapability,
    CredentialExfiltrationCapability,
    SensitiveFileExfiltrationCapability,
    DownloadExecuteCapability,
    EnvironmentToProcessCapability,
}

impl ArtifactFindingCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::EnvironmentAccess => "environment_access",
            Self::CredentialAccess => "credential_access",
            Self::SensitivePathAccess => "sensitive_path_access",
            Self::NetworkCapability => "network_capability",
            Self::ProcessExecution => "process_execution",
            Self::EnvironmentExfiltrationCapability => "environment_exfiltration_capability",
            Self::CredentialExfiltrationCapability => "credential_exfiltration_capability",
            Self::SensitiveFileExfiltrationCapability => "sensitive_file_exfiltration_capability",
            Self::DownloadExecuteCapability => "download_execute_capability",
            Self::EnvironmentToProcessCapability => "environment_to_process_capability",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ArtifactFindingSeverity {
    fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSpecificity {
    PackageSpecific,
    GenericRisk,
    InfrastructureRelated,
}

impl FindingSpecificity {
    fn as_str(self) -> &'static str {
        match self {
            Self::PackageSpecific => "package_specific",
            Self::GenericRisk => "generic_risk",
            Self::InfrastructureRelated => "infrastructure_related",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    Moderate,
    High,
}

impl FindingConfidence {
    fn as_str(self) -> &'static str {
        match self {
            Self::Moderate => "moderate",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceRange {
    Lines {
        start_line: u64,
        end_line: u64,
        start_byte: u64,
        end_byte: u64,
    },
    Bytes {
        start_byte: u64,
        end_byte: u64,
    },
}

impl EvidenceRange {
    fn byte_bounds(&self) -> (u64, u64) {
        match *self {
            Self::Lines {
                start_byte,
                end_byte,
                ..
            }
            | Self::Bytes {
                start_byte,
                end_byte,
            } => (start_byte, end_byte),
        }
    }

    fn canonical_value(&self) -> String {
        match *self {
            Self::Lines {
                start_line,
                end_line,
                start_byte,
                end_byte,
            } => format!("lines:{start_line}:{end_line}:{start_byte}:{end_byte}"),
            Self::Bytes {
                start_byte,
                end_byte,
            } => format!("bytes:{start_byte}:{end_byte}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingLocation {
    File {
        file_id: Sha256Digest,
        file_sha256: Sha256Digest,
        range: EvidenceRange,
        selected_bytes_sha256: Sha256Digest,
    },
    None {
        reason_code: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum FindingTrigger {
    Surface { trigger_id: Sha256Digest },
    None { reason_code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactStaticFinding {
    pub schema_version: String,
    pub rule_id: String,
    pub rule_version: u16,
    pub category: ArtifactFindingCategory,
    pub severity: ArtifactFindingSeverity,
    pub artifact_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub location: FindingLocation,
    pub trigger: FindingTrigger,
    pub capability_summary: String,
    pub confidence: FindingConfidence,
    pub limitations: Vec<String>,
    pub evidence_digest: Sha256Digest,
    pub specificity: FindingSpecificity,
    pub related_file_ids: Vec<Sha256Digest>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerKind {
    NpmLifecycle,
    NpmBin,
    NpmExport,
    NpmDefaultImport,
    NpmImplicitNodeGyp,
    WheelPth,
    WheelImport,
    WheelEntryPoint,
    WheelScript,
    WheelNativeLoad,
    SdistBuildBackend,
    SdistSetupPy,
    SdistSetupCfg,
    SdistImport,
    SdistNativeLoad,
}

impl TriggerKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::NpmLifecycle => "npm_lifecycle",
            Self::NpmBin => "npm_bin",
            Self::NpmExport => "npm_export",
            Self::NpmDefaultImport => "npm_default_import",
            Self::NpmImplicitNodeGyp => "npm_implicit_node_gyp",
            Self::WheelPth => "wheel_pth",
            Self::WheelImport => "wheel_import",
            Self::WheelEntryPoint => "wheel_entry_point",
            Self::WheelScript => "wheel_script",
            Self::WheelNativeLoad => "wheel_native_load",
            Self::SdistBuildBackend => "sdist_build_backend",
            Self::SdistSetupPy => "sdist_setup_py",
            Self::SdistSetupCfg => "sdist_setup_cfg",
            Self::SdistImport => "sdist_import",
            Self::SdistNativeLoad => "sdist_native_load",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerResolution {
    ResolvedFile,
    MetadataInline,
    ExternalBackend,
    InventoryOnly,
    Unresolved,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerSurface {
    pub trigger_id: Sha256Digest,
    pub kind: TriggerKind,
    pub label: String,
    pub declaration_sha256: Sha256Digest,
    pub declared_by_file_id: Option<Sha256Digest>,
    pub target_file_id: Option<Sha256Digest>,
    pub target_path: Option<String>,
    pub resolution: TriggerResolution,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalCodeEdgeKind {
    JavascriptImport,
    JavascriptRequire,
    PythonImport,
    PthImport,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCodeEdge {
    pub from_file_id: Sha256Digest,
    pub to_file_id: Sha256Digest,
    pub kind: LocalCodeEdgeKind,
    pub specifier_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerReachability {
    pub trigger_id: Sha256Digest,
    pub reachable_file_ids: Vec<Sha256Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactTriggerGraph {
    pub schema_version: String,
    pub artifact_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub surfaces: Vec<TriggerSurface>,
    pub local_code_edges: Vec<LocalCodeEdge>,
    pub reachability: Vec<TriggerReachability>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceLanguage {
    Javascript,
    Typescript,
    Python,
    Shell,
    Pth,
    JsonMetadata,
    TomlMetadata,
    IniMetadata,
    NativeBinary,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Analyzed,
    AnalyzedMetadata,
    MetadataInventoryOnly,
    UnsupportedLanguage,
    InvalidText,
    SizeLimitExceeded,
    WorkBudgetExceeded,
    NativeInventoryOnly,
}

impl CoverageStatus {
    fn is_complete(self) -> bool {
        matches!(self, Self::Analyzed | Self::AnalyzedMetadata)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileCoverage {
    pub file_id: Sha256Digest,
    pub normalized_path: String,
    pub language: SourceLanguage,
    pub status: CoverageStatus,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAnalysisCompleteness {
    Complete,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAnalysisOutcome {
    Findings,
    FindingsWithIncompleteCoverage,
    BoundedNoFinding,
    IncompleteNoFinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAnalysisCoverage {
    pub completeness: ArtifactAnalysisCompleteness,
    pub files: Vec<FileCoverage>,
    pub unresolved_trigger_ids: Vec<Sha256Digest>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactStaticAnalysis {
    pub schema_version: String,
    pub artifact_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub trigger_graph: ArtifactTriggerGraph,
    pub coverage: ArtifactAnalysisCoverage,
    pub outcome: ArtifactAnalysisOutcome,
    pub findings: Vec<ArtifactStaticFinding>,
}

impl ArtifactStaticAnalysis {
    /// This is a bounded static observation for later evidence fusion, never an
    /// admission or install authorization.
    pub fn is_bounded_no_finding(
        &self,
        artifact: &NormalizedArtifact,
    ) -> Result<bool, ArtifactDetectorError> {
        self.validate(artifact)?;
        Ok(self.outcome == ArtifactAnalysisOutcome::BoundedNoFinding)
    }

    /// Deterministic JSON for result-digest and evidence transport.
    pub fn canonical_json(&self) -> Result<Vec<u8>, ArtifactDetectorError> {
        serde_json::to_vec(self)
            .map_err(|error| ArtifactDetectorError::Serialization(error.to_string()))
    }

    pub fn analysis_sha256(&self) -> Result<Sha256Digest, ArtifactDetectorError> {
        self.canonical_json()
            .map(|bytes| Sha256Digest::from_bytes(&bytes))
    }

    pub fn validate(&self, artifact: &NormalizedArtifact) -> Result<(), ArtifactDetectorError> {
        artifact
            .validate()
            .map_err(|error| ArtifactDetectorError::InvalidArtifact(error.to_string()))?;
        if self.schema_version != ARTIFACT_STATIC_ANALYSIS_SCHEMA_VERSION
            || self.artifact_sha256 != artifact.manifest.artifact_sha256
            || self.manifest_sha256 != artifact.manifest.manifest_sha256
        {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "analysis identity or schema does not match normalized artifact".to_string(),
            ));
        }
        validate_trigger_graph(&self.trigger_graph, artifact)?;
        validate_coverage(&self.coverage, &self.trigger_graph, artifact)?;
        for finding in &self.findings {
            validate_finding(finding, &self.trigger_graph, artifact)?;
        }
        if self
            .findings
            .windows(2)
            .any(|pair| finding_sort_key(&pair[0]) >= finding_sort_key(&pair[1]))
        {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "findings are duplicated or not canonically ordered".to_string(),
            ));
        }
        let mut expected_findings =
            run_behavior_rules(artifact, &self.trigger_graph, &self.coverage);
        expected_findings.sort_by_key(finding_sort_key);
        expected_findings.dedup_by(|left, right| finding_sort_key(left) == finding_sort_key(right));
        if self.findings != expected_findings {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "findings do not match deterministic rules over normalized bytes".to_string(),
            ));
        }
        if self.outcome != analysis_outcome(self.coverage.completeness, !self.findings.is_empty()) {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "analysis outcome disagrees with findings or coverage".to_string(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactDetectorError {
    InvalidArtifact(String),
    InvalidAnalysis(String),
    Serialization(String),
}

impl fmt::Display for ArtifactDetectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArtifact(detail) => {
                write!(formatter, "invalid normalized artifact: {detail}")
            }
            Self::InvalidAnalysis(detail) => {
                write!(formatter, "invalid artifact analysis: {detail}")
            }
            Self::Serialization(detail) => {
                write!(
                    formatter,
                    "artifact analysis serialization failed: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for ArtifactDetectorError {}

/// Analyze exact normalized member bytes from the same archive parse that
/// produced the manifest. No path-based overload exists.
pub fn analyze_normalized_artifact(
    artifact: &NormalizedArtifact,
) -> Result<ArtifactStaticAnalysis, ArtifactDetectorError> {
    artifact
        .validate()
        .map_err(|error| ArtifactDetectorError::InvalidArtifact(error.to_string()))?;
    let graph = complete_trigger_graph(artifact);
    let coverage = build_coverage(artifact, &graph);
    let mut findings = run_behavior_rules(artifact, &graph, &coverage);
    findings.sort_by_key(finding_sort_key);
    findings.dedup_by(|left, right| finding_sort_key(left) == finding_sort_key(right));
    let analysis = ArtifactStaticAnalysis {
        schema_version: ARTIFACT_STATIC_ANALYSIS_SCHEMA_VERSION.to_string(),
        artifact_sha256: artifact.manifest.artifact_sha256.clone(),
        manifest_sha256: artifact.manifest.manifest_sha256.clone(),
        trigger_graph: graph,
        outcome: analysis_outcome(coverage.completeness, !findings.is_empty()),
        coverage,
        findings,
    };
    analysis.validate(artifact)?;
    Ok(analysis)
}

fn complete_trigger_graph(artifact: &NormalizedArtifact) -> ArtifactTriggerGraph {
    let mut graph = build_trigger_graph(artifact);
    let (edges, edge_limitations) = build_local_code_edges(artifact);
    graph.local_code_edges = edges;
    graph.limitations.extend(edge_limitations);
    graph.local_code_edges.sort();
    graph.local_code_edges.dedup();
    let (reachability, reachability_limit_reached) = build_reachability(&graph);
    graph.reachability = reachability;
    if reachability_limit_reached {
        graph
            .limitations
            .push("total_reachability_budget_reached".to_string());
    }
    graph.limitations.sort();
    graph.limitations.dedup();
    graph
}

fn analysis_outcome(
    completeness: ArtifactAnalysisCompleteness,
    has_findings: bool,
) -> ArtifactAnalysisOutcome {
    match (completeness, has_findings) {
        (ArtifactAnalysisCompleteness::Complete, false) => {
            ArtifactAnalysisOutcome::BoundedNoFinding
        }
        (ArtifactAnalysisCompleteness::Complete, true) => ArtifactAnalysisOutcome::Findings,
        (ArtifactAnalysisCompleteness::Incomplete, false) => {
            ArtifactAnalysisOutcome::IncompleteNoFinding
        }
        (ArtifactAnalysisCompleteness::Incomplete, true) => {
            ArtifactAnalysisOutcome::FindingsWithIncompleteCoverage
        }
    }
}

fn build_trigger_graph(artifact: &NormalizedArtifact) -> ArtifactTriggerGraph {
    let mut graph = ArtifactTriggerGraph {
        schema_version: ARTIFACT_TRIGGER_GRAPH_SCHEMA_VERSION.to_string(),
        artifact_sha256: artifact.manifest.artifact_sha256.clone(),
        manifest_sha256: artifact.manifest.manifest_sha256.clone(),
        surfaces: Vec::new(),
        local_code_edges: Vec::new(),
        reachability: Vec::new(),
        limitations: vec![
            "local_import_graph_is_conservative_and_syntax_heuristic".to_string(),
            "dynamic_import_and_runtime_dispatch_may_be_unresolved".to_string(),
        ],
    };
    match artifact.manifest.magic_detected_format {
        ArtifactFormat::NpmTarGzip => add_npm_triggers(artifact, &mut graph),
        ArtifactFormat::WheelZip => add_wheel_triggers(artifact, &mut graph),
        ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip => {
            add_sdist_triggers(artifact, &mut graph)
        }
        ArtifactFormat::Unknown => {}
    }
    graph
        .surfaces
        .sort_by(|left, right| left.trigger_id.cmp(&right.trigger_id));
    graph
        .surfaces
        .dedup_by(|left, right| left.trigger_id == right.trigger_id);
    graph.limitations.sort();
    graph.limitations.dedup();
    graph
}

fn add_npm_triggers(artifact: &NormalizedArtifact, graph: &mut ArtifactTriggerGraph) {
    let Some(npm) = artifact.manifest.metadata.npm.as_ref() else {
        return;
    };
    let declared = npm.package_json_file_id.clone();
    for (name, command) in &npm.lifecycle_scripts {
        if command
            .split_whitespace()
            .any(|token| token.trim_matches(['\'', '"', ';', '&', '|']) == "node-gyp")
        {
            add_path_surface(
                graph,
                artifact,
                TriggerKind::NpmImplicitNodeGyp,
                &format!("npm_explicit_node_gyp:{}", safe_label(name)),
                "binding.gyp",
                declared.clone(),
                "npm_binding_gyp_not_resolved",
            );
        }
        let (candidates, candidate_limit_reached) = command_path_candidates(command);
        if candidate_limit_reached {
            graph
                .limitations
                .push("npm_lifecycle_command_candidate_limit_reached".to_string());
        }
        if candidates.is_empty() {
            push_surface(
                graph,
                artifact,
                TriggerKind::NpmLifecycle,
                &format!("npm_lifecycle:{}:inline", safe_label(name)),
                command.as_bytes(),
                declared.clone(),
                None,
                None,
                TriggerResolution::MetadataInline,
                vec!["npm_lifecycle_inline_command_not_semantically_analyzed".to_string()],
            );
        } else {
            for (index, candidate) in candidates.iter().enumerate() {
                let resolved = file_id_for_path_with_runtime_defaults(artifact, candidate);
                let resolution = if resolved.is_some() {
                    TriggerResolution::ResolvedFile
                } else {
                    TriggerResolution::Unresolved
                };
                let limitations = if resolution == TriggerResolution::Unresolved {
                    vec!["npm_lifecycle_target_not_resolved".to_string()]
                } else {
                    Vec::new()
                };
                let resolved_path = resolved
                    .as_ref()
                    .and_then(|file_id| path_for_file_id(artifact, file_id));
                push_surface(
                    graph,
                    artifact,
                    TriggerKind::NpmLifecycle,
                    &format!("npm_lifecycle:{}:{index}", safe_label(name)),
                    command.as_bytes(),
                    declared.clone(),
                    resolved,
                    resolved_path,
                    resolution,
                    limitations,
                );
            }
        }
    }
    for (name, target) in &npm.bin_targets {
        add_path_surface(
            graph,
            artifact,
            TriggerKind::NpmBin,
            &format!("npm_bin:{}", safe_label(name)),
            target,
            declared.clone(),
            "npm_bin_target_not_resolved",
        );
    }
    for (index, target) in npm.export_targets.iter().enumerate() {
        add_path_surface(
            graph,
            artifact,
            TriggerKind::NpmExport,
            &format!("npm_export:{index}"),
            target,
            declared.clone(),
            "npm_export_target_not_resolved",
        );
    }
    if let Some(main) = npm.main_target.as_deref() {
        add_path_surface(
            graph,
            artifact,
            TriggerKind::NpmDefaultImport,
            "npm_main_import",
            main,
            declared.clone(),
            "npm_main_target_not_resolved",
        );
    } else if npm.export_targets.is_empty() {
        for candidate in ["index.js", "index.cjs", "index.mjs"] {
            if let Some(file_id) = file_id_for_path(artifact, candidate) {
                push_surface(
                    graph,
                    artifact,
                    TriggerKind::NpmDefaultImport,
                    "npm_default_import",
                    candidate.as_bytes(),
                    declared.clone(),
                    Some(file_id),
                    Some(candidate.to_string()),
                    TriggerResolution::ResolvedFile,
                    Vec::new(),
                );
                break;
            }
        }
    }
    if npm.implicit_node_gyp_rebuild {
        add_path_surface(
            graph,
            artifact,
            TriggerKind::NpmImplicitNodeGyp,
            "npm_implicit_node_gyp",
            "binding.gyp",
            declared,
            "npm_binding_gyp_not_resolved",
        );
    }
}

fn add_wheel_triggers(artifact: &NormalizedArtifact, graph: &mut ArtifactTriggerGraph) {
    let Some(wheel) = artifact.manifest.metadata.wheel.as_ref() else {
        return;
    };
    for file_id in &wheel.pth_file_ids {
        push_surface(
            graph,
            artifact,
            TriggerKind::WheelPth,
            "wheel_pth_startup",
            file_id.as_str().as_bytes(),
            wheel.record_file_id.clone(),
            Some(file_id.clone()),
            path_for_file_id(artifact, file_id),
            TriggerResolution::ResolvedFile,
            Vec::new(),
        );
    }
    for root in &wheel.import_roots {
        add_python_module_surface(
            graph,
            artifact,
            TriggerKind::WheelImport,
            &format!("wheel_import:{}", safe_label(root)),
            root,
            wheel.metadata_file_id.clone(),
            &[],
            "wheel_import_root_not_resolved",
        );
    }
    for (group, entries) in &wheel.entry_points {
        for (name, target) in entries {
            add_python_module_surface(
                graph,
                artifact,
                TriggerKind::WheelEntryPoint,
                &format!(
                    "wheel_entry_point:{}:{}",
                    safe_label(group),
                    safe_label(name)
                ),
                target.split(':').next().unwrap_or(target),
                wheel.entry_points_file_id.clone(),
                &[],
                "wheel_entry_point_target_not_resolved",
            );
        }
    }
    for file_id in &wheel.script_file_ids {
        push_surface(
            graph,
            artifact,
            TriggerKind::WheelScript,
            "wheel_data_script",
            file_id.as_str().as_bytes(),
            wheel.record_file_id.clone(),
            Some(file_id.clone()),
            path_for_file_id(artifact, file_id),
            TriggerResolution::ResolvedFile,
            Vec::new(),
        );
    }
    add_native_triggers(artifact, graph, TriggerKind::WheelNativeLoad);
}

fn add_sdist_triggers(artifact: &NormalizedArtifact, graph: &mut ArtifactTriggerGraph) {
    let Some(sdist) = artifact.manifest.metadata.sdist.as_ref() else {
        return;
    };
    if let Some(backend) = &sdist.build_backend {
        if sdist.backend_paths.is_empty() {
            push_surface(
                graph,
                artifact,
                TriggerKind::SdistBuildBackend,
                "sdist_external_build_backend",
                backend.as_bytes(),
                sdist.pyproject_file_id.clone(),
                None,
                None,
                TriggerResolution::ExternalBackend,
                vec!["external_build_backend_code_is_not_part_of_artifact".to_string()],
            );
        } else {
            add_python_module_surface(
                graph,
                artifact,
                TriggerKind::SdistBuildBackend,
                "sdist_local_build_backend",
                backend,
                sdist.pyproject_file_id.clone(),
                &sdist.backend_paths,
                "sdist_local_build_backend_not_resolved",
            );
        }
    }
    if let Some(file_id) = &sdist.setup_py_file_id {
        push_surface(
            graph,
            artifact,
            TriggerKind::SdistSetupPy,
            "sdist_setup_py",
            file_id.as_str().as_bytes(),
            sdist.pyproject_file_id.clone(),
            Some(file_id.clone()),
            path_for_file_id(artifact, file_id),
            TriggerResolution::ResolvedFile,
            Vec::new(),
        );
    }
    if let Some(file_id) = &sdist.setup_cfg_file_id {
        push_surface(
            graph,
            artifact,
            TriggerKind::SdistSetupCfg,
            "sdist_setup_cfg",
            file_id.as_str().as_bytes(),
            sdist.pyproject_file_id.clone(),
            Some(file_id.clone()),
            path_for_file_id(artifact, file_id),
            TriggerResolution::ResolvedFile,
            vec!["setup_cfg_is_metadata_analyzed_without_execution".to_string()],
        );
    }
    for package_root in &sdist.package_roots {
        let target = if file_id_for_path(artifact, package_root).is_some() {
            package_root.clone()
        } else {
            format!("{package_root}/__init__.py")
        };
        add_path_surface(
            graph,
            artifact,
            TriggerKind::SdistImport,
            &format!("sdist_import:{}", safe_label(package_root)),
            &target,
            sdist.pkg_info_file_id.clone(),
            "sdist_import_root_not_resolved",
        );
    }
    add_native_triggers(artifact, graph, TriggerKind::SdistNativeLoad);
}

fn add_native_triggers(
    artifact: &NormalizedArtifact,
    graph: &mut ArtifactTriggerGraph,
    kind: TriggerKind,
) {
    for file_id in &artifact.manifest.native_binary_file_ids {
        push_surface(
            graph,
            artifact,
            kind,
            "native_binary_inventory",
            file_id.as_str().as_bytes(),
            None,
            Some(file_id.clone()),
            path_for_file_id(artifact, file_id),
            TriggerResolution::InventoryOnly,
            vec!["native_binary_semantics_not_analyzed".to_string()],
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_surface(
    graph: &mut ArtifactTriggerGraph,
    artifact: &NormalizedArtifact,
    kind: TriggerKind,
    label: &str,
    declaration: &[u8],
    declared_by_file_id: Option<Sha256Digest>,
    target_file_id: Option<Sha256Digest>,
    target_path: Option<String>,
    resolution: TriggerResolution,
    mut limitations: Vec<String>,
) {
    if graph.surfaces.len() >= MAX_TRIGGER_SURFACES {
        graph
            .limitations
            .push("trigger_surface_limit_reached".to_string());
        return;
    }
    limitations.sort();
    limitations.dedup();
    let label = safe_label(label);
    let declaration_sha256 = Sha256Digest::from_bytes(declaration);
    let trigger_id = compute_trigger_id(
        &artifact.manifest.artifact_sha256,
        kind,
        &label,
        &declaration_sha256,
        declared_by_file_id.as_ref(),
        target_file_id.as_ref(),
    );
    graph.surfaces.push(TriggerSurface {
        trigger_id,
        kind,
        label,
        declaration_sha256,
        declared_by_file_id,
        target_file_id,
        target_path,
        resolution,
        limitations,
    });
}

fn add_path_surface(
    graph: &mut ArtifactTriggerGraph,
    artifact: &NormalizedArtifact,
    kind: TriggerKind,
    label: &str,
    target: &str,
    declared_by: Option<Sha256Digest>,
    unresolved_reason: &str,
) {
    let normalized = clean_declared_path(target);
    let target_id = normalized.as_deref().and_then(|path| {
        if matches!(
            kind,
            TriggerKind::NpmLifecycle
                | TriggerKind::NpmBin
                | TriggerKind::NpmExport
                | TriggerKind::NpmDefaultImport
        ) {
            file_id_for_path_with_runtime_defaults(artifact, path)
        } else {
            file_id_for_path(artifact, path)
        }
    });
    let resolution = if target_id.is_some() {
        TriggerResolution::ResolvedFile
    } else {
        TriggerResolution::Unresolved
    };
    let limitations = if target_id.is_some() {
        Vec::new()
    } else {
        vec![unresolved_reason.to_string()]
    };
    push_surface(
        graph,
        artifact,
        kind,
        label,
        target.as_bytes(),
        declared_by,
        target_id.clone(),
        target_id
            .as_ref()
            .and_then(|file_id| path_for_file_id(artifact, file_id))
            .or(normalized),
        resolution,
        limitations,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_python_module_surface(
    graph: &mut ArtifactTriggerGraph,
    artifact: &NormalizedArtifact,
    kind: TriggerKind,
    label: &str,
    module: &str,
    declared_by: Option<Sha256Digest>,
    search_roots: &[String],
    unresolved_reason: &str,
) {
    let target = resolve_python_module(artifact, module, search_roots);
    let resolution = if target.is_some() {
        TriggerResolution::ResolvedFile
    } else {
        TriggerResolution::Unresolved
    };
    let limitations = if target.is_some() {
        Vec::new()
    } else {
        vec![unresolved_reason.to_string()]
    };
    let target_path = target
        .as_ref()
        .and_then(|file_id| path_for_file_id(artifact, file_id));
    push_surface(
        graph,
        artifact,
        kind,
        label,
        module.as_bytes(),
        declared_by,
        target,
        target_path,
        resolution,
        limitations,
    );
}

fn compute_trigger_id(
    artifact_sha256: &Sha256Digest,
    kind: TriggerKind,
    label: &str,
    declaration_sha256: &Sha256Digest,
    declared_by: Option<&Sha256Digest>,
    target: Option<&Sha256Digest>,
) -> Sha256Digest {
    let material = format!(
        "whoathere.trigger.v1\0{}\0{}\0{}\0{}\0{}\0{}",
        artifact_sha256,
        kind.as_str(),
        label,
        declaration_sha256,
        declared_by.map(Sha256Digest::as_str).unwrap_or("none"),
        target.map(Sha256Digest::as_str).unwrap_or("none")
    );
    Sha256Digest::from_bytes(material.as_bytes())
}

#[derive(Debug)]
struct ImportSpecifier {
    kind: LocalCodeEdgeKind,
    specifier: String,
}

fn build_local_code_edges(artifact: &NormalizedArtifact) -> (Vec<LocalCodeEdge>, Vec<String>) {
    let mut edges = Vec::new();
    let mut limitations = Vec::new();
    let mut import_attempts = 0usize;
    let mut text_bytes = 0usize;
    let path_index = artifact
        .manifest
        .members
        .iter()
        .filter(|member| member.member_type == MemberType::File)
        .map(|member| (member.normalized_path.as_str(), member.file_id.clone()))
        .collect::<BTreeMap<_, _>>();
    for file in artifact.files() {
        let language = language_for(file);
        if !matches!(
            language,
            SourceLanguage::Javascript
                | SourceLanguage::Typescript
                | SourceLanguage::Python
                | SourceLanguage::Pth
        ) {
            continue;
        }
        if file.bytes().len() > MAX_DETERMINISTIC_TEXT_BYTES {
            continue;
        }
        let Some(new_text_bytes) = text_bytes.checked_add(file.bytes().len()) else {
            limitations.push("local_import_text_budget_reached".to_string());
            break;
        };
        if new_text_bytes > MAX_TOTAL_ANALYZED_TEXT_BYTES {
            limitations.push("local_import_text_budget_reached".to_string());
            break;
        }
        text_bytes = new_text_bytes;
        let Ok(text) = std::str::from_utf8(file.bytes()) else {
            continue;
        };
        let mut imports = match language {
            SourceLanguage::Javascript | SourceLanguage::Typescript => javascript_imports(text),
            SourceLanguage::Python => python_imports(text),
            SourceLanguage::Pth => pth_imports(text),
            _ => Vec::new(),
        };
        let remaining_attempts = MAX_IMPORT_ATTEMPTS.saturating_sub(import_attempts);
        if imports.len() > remaining_attempts {
            imports.truncate(remaining_attempts);
            limitations.push("local_import_attempt_limit_reached".to_string());
        }
        for import in imports {
            import_attempts += 1;
            let target = match import.kind {
                LocalCodeEdgeKind::JavascriptImport | LocalCodeEdgeKind::JavascriptRequire => {
                    resolve_javascript_specifier_indexed(
                        &path_index,
                        &file.normalized_path,
                        &import.specifier,
                    )
                }
                LocalCodeEdgeKind::PythonImport | LocalCodeEdgeKind::PthImport => {
                    resolve_python_import_indexed(
                        &path_index,
                        &file.normalized_path,
                        &import.specifier,
                    )
                }
            };
            if let Some(to_file_id) = target {
                if edges.len() >= MAX_LOCAL_CODE_EDGES {
                    limitations.push("local_code_edge_limit_reached".to_string());
                    break;
                }
                edges.push(LocalCodeEdge {
                    from_file_id: file.file_id.clone(),
                    to_file_id,
                    kind: import.kind,
                    specifier_sha256: Sha256Digest::from_bytes(import.specifier.as_bytes()),
                });
            }
        }
        if import_attempts >= MAX_IMPORT_ATTEMPTS || edges.len() >= MAX_LOCAL_CODE_EDGES {
            break;
        }
    }
    if import_attempts >= MAX_IMPORT_ATTEMPTS {
        limitations.push("local_import_attempt_limit_reached".to_string());
    }
    if edges.len() >= MAX_LOCAL_CODE_EDGES {
        limitations.push("local_code_edge_limit_reached".to_string());
    }
    limitations.sort();
    limitations.dedup();
    (edges, limitations)
}

fn javascript_imports(text: &str) -> Vec<ImportSpecifier> {
    let mut output = Vec::new();
    for line in text.lines() {
        for specifier in quoted_arguments_after(line, "require(") {
            if specifier.starts_with('.') {
                output.push(ImportSpecifier {
                    kind: LocalCodeEdgeKind::JavascriptRequire,
                    specifier,
                });
            }
        }
        for specifier in quoted_arguments_after(line, "import(") {
            if specifier.starts_with('.') {
                output.push(ImportSpecifier {
                    kind: LocalCodeEdgeKind::JavascriptImport,
                    specifier,
                });
            }
        }
        if line.contains("import ") || line.contains("export ") {
            for specifier in quoted_strings(line) {
                if specifier.starts_with('.') {
                    output.push(ImportSpecifier {
                        kind: LocalCodeEdgeKind::JavascriptImport,
                        specifier,
                    });
                }
            }
        }
    }
    output
}

fn python_imports(text: &str) -> Vec<ImportSpecifier> {
    let mut output = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("from ") {
            if let Some(module) = rest.split_whitespace().next() {
                output.push(ImportSpecifier {
                    kind: LocalCodeEdgeKind::PythonImport,
                    specifier: module.to_string(),
                });
                if module.chars().all(|character| character == '.') {
                    if let Some((_, imported)) = rest.split_once(" import ") {
                        for name in imported.split(',') {
                            let name = name.split_whitespace().next().unwrap_or_default();
                            if !name.is_empty() && name != "*" {
                                output.push(ImportSpecifier {
                                    kind: LocalCodeEdgeKind::PythonImport,
                                    specifier: format!("{module}{name}"),
                                });
                            }
                        }
                    }
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("import ") {
            for module in rest.split(',') {
                let module = module.split_whitespace().next().unwrap_or_default();
                if !module.is_empty() {
                    output.push(ImportSpecifier {
                        kind: LocalCodeEdgeKind::PythonImport,
                        specifier: module.to_string(),
                    });
                }
            }
        }
    }
    output
}

fn pth_imports(text: &str) -> Vec<ImportSpecifier> {
    text.lines()
        .filter_map(|line| {
            line.trim_start()
                .strip_prefix("import ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(|module| ImportSpecifier {
                    kind: LocalCodeEdgeKind::PthImport,
                    specifier: module.trim_end_matches(';').to_string(),
                })
        })
        .collect()
}

fn build_reachability(graph: &ArtifactTriggerGraph) -> (Vec<TriggerReachability>, bool) {
    let mut adjacency: BTreeMap<Sha256Digest, Vec<Sha256Digest>> = BTreeMap::new();
    for edge in &graph.local_code_edges {
        adjacency
            .entry(edge.from_file_id.clone())
            .or_default()
            .push(edge.to_file_id.clone());
    }
    let mut output = Vec::new();
    let mut total_reachable_ids = 0usize;
    let mut limit_reached = false;
    for surface in &graph.surfaces {
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::new();
        for seed in [&surface.declared_by_file_id, &surface.target_file_id]
            .into_iter()
            .flatten()
        {
            if seen.insert(seed.clone()) {
                queue.push_back(seed.clone());
            }
        }
        while let Some(file_id) = queue.pop_front() {
            if total_reachable_ids.saturating_add(seen.len()) > MAX_TOTAL_REACHABLE_FILE_IDS {
                limit_reached = true;
                seen.clear();
                queue.clear();
                break;
            }
            for target in adjacency.get(&file_id).into_iter().flatten() {
                if seen.insert(target.clone()) {
                    queue.push_back(target.clone());
                }
            }
        }
        total_reachable_ids = total_reachable_ids.saturating_add(seen.len());
        output.push(TriggerReachability {
            trigger_id: surface.trigger_id.clone(),
            reachable_file_ids: seen.into_iter().collect(),
        });
    }
    output.sort_by(|left, right| left.trigger_id.cmp(&right.trigger_id));
    (output, limit_reached)
}

fn build_coverage(
    artifact: &NormalizedArtifact,
    graph: &ArtifactTriggerGraph,
) -> ArtifactAnalysisCoverage {
    let native = artifact
        .manifest
        .native_binary_file_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let inventory = artifact
        .manifest
        .executable_text_file_ids
        .iter()
        .chain(&artifact.manifest.native_binary_file_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut files = Vec::new();
    let mut analyzed_text_bytes = 0usize;
    for file_id in inventory {
        let Some(file) = artifact.file(&file_id) else {
            continue;
        };
        let language = if native.contains(&file_id) {
            SourceLanguage::NativeBinary
        } else {
            language_for(file)
        };
        let (status, limitations) = if native.contains(&file_id) {
            (
                CoverageStatus::NativeInventoryOnly,
                vec!["native_binary_semantics_not_analyzed".to_string()],
            )
        } else if file.bytes().len() > MAX_DETERMINISTIC_TEXT_BYTES {
            (
                CoverageStatus::SizeLimitExceeded,
                vec![format!(
                    "deterministic_text_limit_exceeded:{}>{}",
                    file.bytes().len(),
                    MAX_DETERMINISTIC_TEXT_BYTES
                )],
            )
        } else if file.bytes().contains(&0) || std::str::from_utf8(file.bytes()).is_err() {
            (
                CoverageStatus::InvalidText,
                vec!["executable_text_is_not_valid_nul_free_utf8".to_string()],
            )
        } else if analyzed_text_bytes.saturating_add(file.bytes().len())
            > MAX_TOTAL_ANALYZED_TEXT_BYTES
        {
            (
                CoverageStatus::WorkBudgetExceeded,
                vec!["deterministic_total_text_budget_exceeded".to_string()],
            )
        } else {
            analyzed_text_bytes += file.bytes().len();
            match language {
                SourceLanguage::Javascript
                | SourceLanguage::Typescript
                | SourceLanguage::Python
                | SourceLanguage::Shell
                | SourceLanguage::Pth => (
                    CoverageStatus::Analyzed,
                    vec![
                        "lexical_capability_rules_and_conservative_local_import_graph".to_string(),
                    ],
                ),
                SourceLanguage::JsonMetadata
                | SourceLanguage::TomlMetadata
                | SourceLanguage::IniMetadata
                    if metadata_file_was_structurally_normalized(artifact, &file_id) =>
                {
                    (
                        CoverageStatus::AnalyzedMetadata,
                        vec![
                            "supported_package_metadata_fields_structurally_normalized".to_string()
                        ],
                    )
                }
                SourceLanguage::JsonMetadata
                | SourceLanguage::TomlMetadata
                | SourceLanguage::IniMetadata => (
                    CoverageStatus::MetadataInventoryOnly,
                    vec![
                        "metadata_semantics_inventoried_but_not_structurally_analyzed".to_string(),
                    ],
                ),
                SourceLanguage::NativeBinary | SourceLanguage::Unknown => (
                    CoverageStatus::UnsupportedLanguage,
                    vec!["executable_language_not_supported_by_deterministic_rules_v1".to_string()],
                ),
            }
        };
        files.push(FileCoverage {
            file_id,
            normalized_path: file.normalized_path.clone(),
            language,
            status,
            limitations,
        });
    }
    files.sort_by(|left, right| left.file_id.cmp(&right.file_id));
    let mut unresolved_trigger_ids = graph
        .surfaces
        .iter()
        .filter(|surface| {
            matches!(
                surface.resolution,
                TriggerResolution::Unresolved
                    | TriggerResolution::MetadataInline
                    | TriggerResolution::ExternalBackend
            )
        })
        .map(|surface| surface.trigger_id.clone())
        .collect::<Vec<_>>();
    unresolved_trigger_ids.sort();
    let mut limitations = Vec::new();
    if artifact.manifest.normalization_completeness != NormalizationCompleteness::Complete {
        limitations.push("artifact_normalization_is_not_complete".to_string());
    }
    if !artifact.manifest.excluded_members.is_empty() {
        limitations.push("artifact_members_were_excluded_during_normalization".to_string());
    }
    if !artifact.manifest.issues.is_empty() {
        limitations.push("artifact_manifest_contains_normalization_issues".to_string());
    }
    if !unresolved_trigger_ids.is_empty() {
        limitations.push("one_or_more_trigger_targets_are_not_locally_resolved".to_string());
    }
    if !graph.limitations.is_empty() {
        limitations.push("trigger_graph_has_known_analysis_limitations".to_string());
    }
    if files.iter().any(|file| !file.status.is_complete()) {
        limitations.push("one_or_more_executable_members_are_not_fully_analyzed".to_string());
    }
    let fully_analyzed = files
        .iter()
        .filter(|file| file.status.is_complete())
        .map(|file| file.file_id.clone())
        .collect::<BTreeSet<_>>();
    if graph.surfaces.iter().any(|surface| {
        surface.resolution == TriggerResolution::ResolvedFile
            && surface
                .target_file_id
                .as_ref()
                .is_some_and(|file_id| !fully_analyzed.contains(file_id))
    }) {
        limitations.push("resolved_trigger_target_was_not_fully_analyzed".to_string());
    }
    let dependency_closure_required = artifact
        .manifest
        .metadata
        .npm
        .as_ref()
        .is_some_and(|npm| npm.requires_offline_closure)
        || artifact
            .manifest
            .metadata
            .wheel
            .as_ref()
            .is_some_and(|wheel| !wheel.requires_dist.is_empty())
        || artifact
            .manifest
            .metadata
            .sdist
            .as_ref()
            .is_some_and(|sdist| !sdist.build_requires.is_empty());
    if dependency_closure_required {
        limitations.push("declared_dependency_closure_was_not_analyzed".to_string());
    }
    limitations.sort();
    limitations.dedup();
    let completeness = if limitations.is_empty() {
        ArtifactAnalysisCompleteness::Complete
    } else {
        ArtifactAnalysisCompleteness::Incomplete
    };
    ArtifactAnalysisCoverage {
        completeness,
        files,
        unresolved_trigger_ids,
        limitations,
    }
}

fn metadata_file_was_structurally_normalized(
    artifact: &NormalizedArtifact,
    file_id: &Sha256Digest,
) -> bool {
    let npm_parsed = artifact
        .manifest
        .metadata
        .npm
        .as_ref()
        .and_then(|metadata| metadata.package_json_file_id.as_ref())
        .is_some_and(|candidate| candidate == file_id);
    let wheel_parsed = artifact
        .manifest
        .metadata
        .wheel
        .as_ref()
        .is_some_and(|metadata| {
            [
                metadata.metadata_file_id.as_ref(),
                metadata.wheel_file_id.as_ref(),
                metadata.record_file_id.as_ref(),
                metadata.entry_points_file_id.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|candidate| candidate == file_id)
        });
    let sdist_parsed = artifact
        .manifest
        .metadata
        .sdist
        .as_ref()
        .is_some_and(|metadata| {
            [
                metadata.pkg_info_file_id.as_ref(),
                metadata.pyproject_file_id.as_ref(),
                metadata.setup_cfg_file_id.as_ref(),
            ]
            .into_iter()
            .flatten()
            .any(|candidate| candidate == file_id)
        });
    npm_parsed || wheel_parsed || sdist_parsed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CapabilityKind {
    Environment,
    Credential,
    SensitivePath,
    Network,
    Process,
}

#[derive(Debug, Clone)]
struct CapabilityMatch {
    kind: CapabilityKind,
    file_id: Sha256Digest,
    range: EvidenceRange,
}

fn run_behavior_rules(
    artifact: &NormalizedArtifact,
    graph: &ArtifactTriggerGraph,
    coverage: &ArtifactAnalysisCoverage,
) -> Vec<ArtifactStaticFinding> {
    let analyzed = coverage
        .files
        .iter()
        .filter(|file| file.status.is_complete())
        .map(|file| file.file_id.clone())
        .collect::<BTreeSet<_>>();
    let capability_cache = analyzed
        .iter()
        .filter_map(|file_id| {
            artifact
                .file(file_id)
                .map(|file| (file_id.clone(), scan_capabilities(file)))
        })
        .collect::<BTreeMap<_, _>>();
    let mut findings = Vec::new();
    for reachable in &graph.reachability {
        let mut match_by_capability = BTreeMap::new();
        for file_id in &reachable.reachable_file_ids {
            if !analyzed.contains(file_id) {
                continue;
            }
            for capability in capability_cache.get(file_id).into_iter().flatten() {
                match_by_capability
                    .entry(capability.kind)
                    .or_insert_with(|| capability.clone());
            }
        }
        let matches = match_by_capability.into_values().collect::<Vec<_>>();
        for capability in &matches {
            let (rule_id, category, severity, summary) = match capability.kind {
                CapabilityKind::Environment => (
                    "WT-ENV-001",
                    ArtifactFindingCategory::EnvironmentAccess,
                    ArtifactFindingSeverity::Medium,
                    "Trigger-reachable package code can read process environment values.",
                ),
                CapabilityKind::Credential => (
                    "WT-CRED-001",
                    ArtifactFindingCategory::CredentialAccess,
                    ArtifactFindingSeverity::High,
                    "Trigger-reachable code names a credential-like value at an environment-access site.",
                ),
                CapabilityKind::SensitivePath => (
                    "WT-SENSITIVE-001",
                    ArtifactFindingCategory::SensitivePathAccess,
                    ArtifactFindingSeverity::High,
                    "Trigger-reachable code can access a credential-bearing or sensitive local path.",
                ),
                CapabilityKind::Network => (
                    "WT-NET-001",
                    ArtifactFindingCategory::NetworkCapability,
                    ArtifactFindingSeverity::Medium,
                    "Trigger-reachable code contains a concrete network client or socket API.",
                ),
                CapabilityKind::Process => (
                    "WT-PROC-001",
                    ArtifactFindingCategory::ProcessExecution,
                    ArtifactFindingSeverity::High,
                    "Trigger-reachable code contains a concrete subprocess or shell execution API.",
                ),
            };
            findings.push(make_finding(
                artifact,
                graph,
                reachable,
                capability,
                rule_id,
                category,
                severity,
                summary,
                Vec::new(),
            ));
        }
        add_composite_findings(artifact, graph, reachable, &matches, &mut findings);
    }
    findings
}

fn scan_capabilities(file: &NormalizedMemberContent) -> Vec<CapabilityMatch> {
    let Ok(text) = std::str::from_utf8(file.bytes()) else {
        return Vec::new();
    };
    let mut found = BTreeMap::<CapabilityKind, EvidenceRange>::new();
    let mut offset = 0usize;
    for (line_index, inclusive_line) in text.split_inclusive('\n').enumerate() {
        let line = inclusive_line.strip_suffix('\n').unwrap_or(inclusive_line);
        if let Some((start, pattern)) = first_pattern(line, ENVIRONMENT_PATTERNS) {
            found
                .entry(CapabilityKind::Environment)
                .or_insert_with(|| line_range(line_index, offset + start, pattern.len()));
            if let Some((credential_start, credential_pattern)) =
                first_pattern(line, CREDENTIAL_NAME_PATTERNS)
            {
                found.entry(CapabilityKind::Credential).or_insert_with(|| {
                    line_range(
                        line_index,
                        offset + credential_start,
                        credential_pattern.len(),
                    )
                });
            }
        }
        if sensitive_path_access(line) {
            if let Some((start, pattern)) = first_pattern(line, SENSITIVE_PATH_PATTERNS) {
                found
                    .entry(CapabilityKind::SensitivePath)
                    .or_insert_with(|| line_range(line_index, offset + start, pattern.len()));
            }
        }
        if let Some((start, pattern)) = first_pattern(line, NETWORK_PATTERNS) {
            found
                .entry(CapabilityKind::Network)
                .or_insert_with(|| line_range(line_index, offset + start, pattern.len()));
        }
        if let Some((start, pattern)) = first_pattern(line, PROCESS_PATTERNS) {
            found
                .entry(CapabilityKind::Process)
                .or_insert_with(|| line_range(line_index, offset + start, pattern.len()));
        }
        offset += inclusive_line.len();
    }
    found
        .into_iter()
        .map(|(kind, range)| CapabilityMatch {
            kind,
            file_id: file.file_id.clone(),
            range,
        })
        .collect()
}

fn add_composite_findings(
    artifact: &NormalizedArtifact,
    graph: &ArtifactTriggerGraph,
    reachable: &TriggerReachability,
    matches: &[CapabilityMatch],
    output: &mut Vec<ArtifactStaticFinding>,
) {
    let first = |kind| matches.iter().find(|candidate| candidate.kind == kind);
    let environment = first(CapabilityKind::Environment);
    let credential = first(CapabilityKind::Credential);
    let sensitive = first(CapabilityKind::SensitivePath);
    let network = first(CapabilityKind::Network);
    let process = first(CapabilityKind::Process);

    if let (Some(source), Some(sink)) = (credential, network) {
        output.push(make_finding(
            artifact,
            graph,
            reachable,
            sink,
            "WT-CREDENTIAL-EXFIL-001",
            ArtifactFindingCategory::CredentialExfiltrationCapability,
            ArtifactFindingSeverity::Critical,
            "One trigger-reachable closure contains credential access and a network sink.",
            vec![source.file_id.clone()],
        ));
    } else if let (Some(source), Some(sink)) = (environment, network) {
        output.push(make_finding(
            artifact,
            graph,
            reachable,
            sink,
            "WT-ENV-EXFIL-001",
            ArtifactFindingCategory::EnvironmentExfiltrationCapability,
            ArtifactFindingSeverity::High,
            "One trigger-reachable closure contains environment access and a network sink.",
            vec![source.file_id.clone()],
        ));
    }
    if let (Some(source), Some(sink)) = (sensitive, network) {
        output.push(make_finding(
            artifact,
            graph,
            reachable,
            sink,
            "WT-SENSITIVE-EXFIL-001",
            ArtifactFindingCategory::SensitiveFileExfiltrationCapability,
            ArtifactFindingSeverity::Critical,
            "One trigger-reachable closure contains sensitive-path access and a network sink.",
            vec![source.file_id.clone()],
        ));
    }
    if let (Some(source), Some(sink)) = (network, process) {
        output.push(make_finding(
            artifact,
            graph,
            reachable,
            sink,
            "WT-DOWNLOAD-EXEC-001",
            ArtifactFindingCategory::DownloadExecuteCapability,
            ArtifactFindingSeverity::High,
            "One trigger-reachable closure contains network and process execution capabilities.",
            vec![source.file_id.clone()],
        ));
    }
    if let (Some(source), Some(sink)) = (credential.or(environment), process) {
        output.push(make_finding(
            artifact,
            graph,
            reachable,
            sink,
            "WT-ENV-PROCESS-001",
            ArtifactFindingCategory::EnvironmentToProcessCapability,
            ArtifactFindingSeverity::High,
            "One trigger-reachable closure contains environment and process execution capabilities.",
            vec![source.file_id.clone()],
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn make_finding(
    artifact: &NormalizedArtifact,
    graph: &ArtifactTriggerGraph,
    reachable: &TriggerReachability,
    primary: &CapabilityMatch,
    rule_id: &str,
    category: ArtifactFindingCategory,
    severity: ArtifactFindingSeverity,
    capability_summary: &str,
    mut related_file_ids: Vec<Sha256Digest>,
) -> ArtifactStaticFinding {
    related_file_ids.sort();
    related_file_ids.dedup();
    let file = artifact
        .file(&primary.file_id)
        .expect("capability matches originate from normalized files");
    let (start, end) = primary.range.byte_bounds();
    let location = FindingLocation::File {
        file_id: file.file_id.clone(),
        file_sha256: file.sha256.clone(),
        range: primary.range.clone(),
        selected_bytes_sha256: Sha256Digest::from_bytes(
            &file.bytes()[start as usize..end as usize],
        ),
    };
    let mut limitations = vec![
        "lexical_rule_does_not_establish_runtime_values_or_destination".to_string(),
        "static_capability_is_not_proof_of_execution".to_string(),
    ];
    if graph
        .surfaces
        .iter()
        .find(|surface| surface.trigger_id == reachable.trigger_id)
        .is_some_and(|surface| surface.declared_by_file_id.as_ref() != Some(&file.file_id))
    {
        limitations.push("reachability_uses_conservative_local_import_edges".to_string());
    }
    limitations.sort();
    limitations.dedup();
    let mut finding = ArtifactStaticFinding {
        schema_version: ARTIFACT_STATIC_FINDING_SCHEMA_VERSION.to_string(),
        rule_id: rule_id.to_string(),
        rule_version: 1,
        category,
        severity,
        artifact_sha256: artifact.manifest.artifact_sha256.clone(),
        manifest_sha256: artifact.manifest.manifest_sha256.clone(),
        location,
        trigger: FindingTrigger::Surface {
            trigger_id: reachable.trigger_id.clone(),
        },
        capability_summary: capability_summary.to_string(),
        confidence: FindingConfidence::Moderate,
        limitations,
        evidence_digest: Sha256Digest::from_bytes(&[]),
        specificity: FindingSpecificity::PackageSpecific,
        related_file_ids,
    };
    finding.evidence_digest = compute_finding_evidence_digest(&finding);
    finding
}

fn compute_finding_evidence_digest(finding: &ArtifactStaticFinding) -> Sha256Digest {
    let mut material = Vec::new();
    push_digest_field(&mut material, "schema", &finding.schema_version);
    push_digest_field(&mut material, "rule", &finding.rule_id);
    push_digest_field(
        &mut material,
        "rule_version",
        &finding.rule_version.to_string(),
    );
    push_digest_field(&mut material, "category", finding.category.as_str());
    push_digest_field(&mut material, "severity", finding.severity.as_str());
    push_digest_field(&mut material, "artifact", finding.artifact_sha256.as_str());
    push_digest_field(&mut material, "manifest", finding.manifest_sha256.as_str());
    match &finding.location {
        FindingLocation::File {
            file_id,
            file_sha256,
            range,
            selected_bytes_sha256,
        } => {
            push_digest_field(&mut material, "location", "file");
            push_digest_field(&mut material, "file_id", file_id.as_str());
            push_digest_field(&mut material, "file_sha256", file_sha256.as_str());
            push_digest_field(&mut material, "range", &range.canonical_value());
            push_digest_field(
                &mut material,
                "selected_bytes_sha256",
                selected_bytes_sha256.as_str(),
            );
        }
        FindingLocation::None { reason_code } => {
            push_digest_field(&mut material, "location", "none");
            push_digest_field(&mut material, "location_reason", reason_code);
        }
    }
    match &finding.trigger {
        FindingTrigger::Surface { trigger_id } => {
            push_digest_field(&mut material, "trigger", trigger_id.as_str());
        }
        FindingTrigger::None { reason_code } => {
            push_digest_field(&mut material, "trigger_none", reason_code);
        }
    }
    push_digest_field(&mut material, "summary", &finding.capability_summary);
    push_digest_field(&mut material, "confidence", finding.confidence.as_str());
    push_digest_field(&mut material, "specificity", finding.specificity.as_str());
    for limitation in &finding.limitations {
        push_digest_field(&mut material, "limitation", limitation);
    }
    for file_id in &finding.related_file_ids {
        push_digest_field(&mut material, "related_file", file_id.as_str());
    }
    Sha256Digest::from_bytes(&material)
}

fn push_digest_field(material: &mut Vec<u8>, name: &str, value: &str) {
    material.extend_from_slice(name.as_bytes());
    material.push(0);
    material.extend_from_slice(value.len().to_string().as_bytes());
    material.push(0);
    material.extend_from_slice(value.as_bytes());
    material.push(b'\n');
}

fn validate_trigger_graph(
    graph: &ArtifactTriggerGraph,
    artifact: &NormalizedArtifact,
) -> Result<(), ArtifactDetectorError> {
    if graph.schema_version != ARTIFACT_TRIGGER_GRAPH_SCHEMA_VERSION
        || graph.artifact_sha256 != artifact.manifest.artifact_sha256
        || graph.manifest_sha256 != artifact.manifest.manifest_sha256
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "trigger graph identity or schema mismatch".to_string(),
        ));
    }
    let mut triggers = BTreeSet::new();
    for surface in &graph.surfaces {
        let expected = compute_trigger_id(
            &graph.artifact_sha256,
            surface.kind,
            &surface.label,
            &surface.declaration_sha256,
            surface.declared_by_file_id.as_ref(),
            surface.target_file_id.as_ref(),
        );
        if surface.trigger_id != expected || !triggers.insert(surface.trigger_id.clone()) {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "trigger id is invalid or duplicated".to_string(),
            ));
        }
        for file_id in [&surface.declared_by_file_id, &surface.target_file_id]
            .into_iter()
            .flatten()
        {
            if artifact.file(file_id).is_none() {
                return Err(ArtifactDetectorError::InvalidAnalysis(
                    "trigger references an unknown normalized file".to_string(),
                ));
            }
        }
        if surface.resolution == TriggerResolution::ResolvedFile && surface.target_file_id.is_none()
        {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "resolved trigger lacks a target file".to_string(),
            ));
        }
    }
    if graph
        .surfaces
        .windows(2)
        .any(|pair| pair[0].trigger_id >= pair[1].trigger_id)
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "trigger surfaces are duplicated or not canonically ordered".to_string(),
        ));
    }
    for edge in &graph.local_code_edges {
        if artifact.file(&edge.from_file_id).is_none() || artifact.file(&edge.to_file_id).is_none()
        {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "local-code edge references an unknown normalized file".to_string(),
            ));
        }
    }
    if graph
        .local_code_edges
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "local-code edges are duplicated or not canonically ordered".to_string(),
        ));
    }
    let (expected_reachability, reachability_limited) = build_reachability(graph);
    if graph.reachability != expected_reachability
        || reachability_limited
            != graph
                .limitations
                .iter()
                .any(|limitation| limitation == "total_reachability_budget_reached")
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "trigger reachability does not match graph edges".to_string(),
        ));
    }
    if graph != &complete_trigger_graph(artifact) {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "trigger graph does not match normalized artifact metadata and bytes".to_string(),
        ));
    }
    Ok(())
}

fn validate_coverage(
    coverage: &ArtifactAnalysisCoverage,
    graph: &ArtifactTriggerGraph,
    artifact: &NormalizedArtifact,
) -> Result<(), ArtifactDetectorError> {
    let expected_inventory = artifact
        .manifest
        .executable_text_file_ids
        .iter()
        .chain(&artifact.manifest.native_binary_file_ids)
        .cloned()
        .collect::<BTreeSet<_>>();
    let actual_inventory = coverage
        .files
        .iter()
        .map(|file| file.file_id.clone())
        .collect::<BTreeSet<_>>();
    if expected_inventory != actual_inventory || coverage.files.len() != actual_inventory.len() {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "coverage does not exactly inventory executable and native members".to_string(),
        ));
    }
    if coverage
        .files
        .windows(2)
        .any(|pair| pair[0].file_id >= pair[1].file_id)
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "coverage files are duplicated or not canonically ordered".to_string(),
        ));
    }
    for file in &coverage.files {
        let Some(content) = artifact.file(&file.file_id) else {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "coverage references an unknown normalized file".to_string(),
            ));
        };
        if file.normalized_path != content.normalized_path {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "coverage path does not match file id".to_string(),
            ));
        }
    }
    let expected_unresolved = graph
        .surfaces
        .iter()
        .filter(|surface| {
            matches!(
                surface.resolution,
                TriggerResolution::Unresolved
                    | TriggerResolution::MetadataInline
                    | TriggerResolution::ExternalBackend
            )
        })
        .map(|surface| surface.trigger_id.clone())
        .collect::<BTreeSet<_>>();
    if coverage
        .unresolved_trigger_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_unresolved
        || coverage.unresolved_trigger_ids.len() != expected_unresolved.len()
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "coverage unresolved-trigger inventory is invalid".to_string(),
        ));
    }
    let should_be_incomplete = !coverage.limitations.is_empty();
    let expected = if should_be_incomplete {
        ArtifactAnalysisCompleteness::Incomplete
    } else {
        ArtifactAnalysisCompleteness::Complete
    };
    if coverage.completeness != expected {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "coverage completeness disagrees with explicit gaps".to_string(),
        ));
    }
    if coverage != &build_coverage(artifact, graph) {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "coverage does not match normalized artifact inventory".to_string(),
        ));
    }
    Ok(())
}

fn validate_finding(
    finding: &ArtifactStaticFinding,
    graph: &ArtifactTriggerGraph,
    artifact: &NormalizedArtifact,
) -> Result<(), ArtifactDetectorError> {
    if finding.schema_version != ARTIFACT_STATIC_FINDING_SCHEMA_VERSION
        || finding.rule_id.is_empty()
        || finding.rule_version == 0
        || finding.artifact_sha256 != artifact.manifest.artifact_sha256
        || finding.manifest_sha256 != artifact.manifest.manifest_sha256
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "finding identity, rule, or schema is invalid".to_string(),
        ));
    }
    match &finding.location {
        FindingLocation::File {
            file_id,
            file_sha256,
            range,
            selected_bytes_sha256,
        } => {
            let file = artifact.file(file_id).ok_or_else(|| {
                ArtifactDetectorError::InvalidAnalysis(
                    "finding cites a file outside normalized artifact".to_string(),
                )
            })?;
            if &file.sha256 != file_sha256 {
                return Err(ArtifactDetectorError::InvalidAnalysis(
                    "finding file digest does not match file id".to_string(),
                ));
            }
            let (start, end) = range.byte_bounds();
            if start >= end || end > file.bytes().len() as u64 {
                return Err(ArtifactDetectorError::InvalidAnalysis(
                    "finding byte range is outside normalized file".to_string(),
                ));
            }
            if let EvidenceRange::Lines {
                start_line,
                end_line,
                start_byte,
                end_byte,
            } = range
            {
                let actual_start = line_number_at(file.bytes(), *start_byte as usize);
                let actual_end =
                    line_number_at(file.bytes(), (*end_byte as usize).saturating_sub(1));
                if *start_line == 0
                    || *start_line > *end_line
                    || *start_line != actual_start
                    || *end_line != actual_end
                {
                    return Err(ArtifactDetectorError::InvalidAnalysis(
                        "finding line range does not match byte range".to_string(),
                    ));
                }
            }
            if &Sha256Digest::from_bytes(&file.bytes()[start as usize..end as usize])
                != selected_bytes_sha256
            {
                return Err(ArtifactDetectorError::InvalidAnalysis(
                    "finding selected-byte digest is invalid".to_string(),
                ));
            }
        }
        FindingLocation::None { reason_code } if reason_code.is_empty() => {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "finding without file lacks explicit reason".to_string(),
            ));
        }
        FindingLocation::None { .. } => {}
    }
    match &finding.trigger {
        FindingTrigger::Surface { trigger_id } => {
            if !graph
                .surfaces
                .iter()
                .any(|surface| &surface.trigger_id == trigger_id)
            {
                return Err(ArtifactDetectorError::InvalidAnalysis(
                    "finding references an unknown trigger".to_string(),
                ));
            }
        }
        FindingTrigger::None { reason_code } if reason_code.is_empty() => {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "finding without trigger lacks explicit reason".to_string(),
            ));
        }
        FindingTrigger::None { .. } => {}
    }
    for file_id in &finding.related_file_ids {
        if artifact.file(file_id).is_none() {
            return Err(ArtifactDetectorError::InvalidAnalysis(
                "finding related file is outside normalized artifact".to_string(),
            ));
        }
    }
    if finding
        .limitations
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "finding limitations are duplicated or not ordered".to_string(),
        ));
    }
    if finding
        .related_file_ids
        .windows(2)
        .any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "finding related files are duplicated or not ordered".to_string(),
        ));
    }
    if finding.evidence_digest != compute_finding_evidence_digest(finding) {
        return Err(ArtifactDetectorError::InvalidAnalysis(
            "finding evidence digest does not match canonical evidence".to_string(),
        ));
    }
    Ok(())
}

fn finding_sort_key(finding: &ArtifactStaticFinding) -> (String, String, String, String) {
    let trigger = match &finding.trigger {
        FindingTrigger::Surface { trigger_id } => trigger_id.as_str().to_string(),
        FindingTrigger::None { reason_code } => reason_code.clone(),
    };
    let file = match &finding.location {
        FindingLocation::File { file_id, .. } => file_id.as_str().to_string(),
        FindingLocation::None { reason_code } => reason_code.clone(),
    };
    (
        finding.rule_id.clone(),
        trigger,
        file,
        finding.evidence_digest.as_str().to_string(),
    )
}

fn line_range(line_index: usize, start_byte: usize, length: usize) -> EvidenceRange {
    EvidenceRange::Lines {
        start_line: line_index as u64 + 1,
        end_line: line_index as u64 + 1,
        start_byte: start_byte as u64,
        end_byte: (start_byte + length) as u64,
    }
}

fn line_number_at(bytes: &[u8], offset: usize) -> u64 {
    bytes[..offset.min(bytes.len())]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u64
        + 1
}

fn language_for(file: &NormalizedMemberContent) -> SourceLanguage {
    let lower = file.normalized_path.to_ascii_lowercase();
    if [".js", ".cjs", ".mjs", ".jsx"]
        .iter()
        .any(|extension| lower.ends_with(extension))
    {
        SourceLanguage::Javascript
    } else if [".ts", ".tsx"]
        .iter()
        .any(|extension| lower.ends_with(extension))
    {
        SourceLanguage::Typescript
    } else if lower.ends_with(".py") || lower.ends_with(".pyi") {
        SourceLanguage::Python
    } else if [".sh", ".bash", ".zsh"]
        .iter()
        .any(|extension| lower.ends_with(extension))
    {
        SourceLanguage::Shell
    } else if lower.ends_with(".pth") {
        SourceLanguage::Pth
    } else if lower.ends_with(".json") || lower.ends_with(".gyp") {
        SourceLanguage::JsonMetadata
    } else if lower.ends_with(".toml") {
        SourceLanguage::TomlMetadata
    } else if lower.ends_with(".cfg") || lower.ends_with(".ini") {
        SourceLanguage::IniMetadata
    } else if file.bytes().starts_with(b"#!") {
        let first_line = file
            .bytes()
            .split(|byte| *byte == b'\n')
            .next()
            .unwrap_or_default();
        if first_line.windows(6).any(|window| window == b"python") {
            SourceLanguage::Python
        } else if first_line.windows(4).any(|window| window == b"node") {
            SourceLanguage::Javascript
        } else if first_line.windows(2).any(|window| window == b"sh") {
            SourceLanguage::Shell
        } else {
            SourceLanguage::Unknown
        }
    } else {
        SourceLanguage::Unknown
    }
}

fn file_id_for_path(artifact: &NormalizedArtifact, path: &str) -> Option<Sha256Digest> {
    artifact
        .manifest
        .members
        .iter()
        .find(|member| member.member_type == MemberType::File && member.normalized_path == path)
        .map(|member| member.file_id.clone())
}

fn file_id_for_path_with_runtime_defaults(
    artifact: &NormalizedArtifact,
    path: &str,
) -> Option<Sha256Digest> {
    let path = clean_declared_path(path)?;
    let mut candidates = vec![path.clone()];
    for extension in ["js", "cjs", "mjs", "jsx", "ts", "tsx", "py", "sh"] {
        candidates.push(format!("{path}.{extension}"));
        candidates.push(format!("{path}/index.{extension}"));
    }
    candidates
        .iter()
        .find_map(|candidate| file_id_for_path(artifact, candidate))
}

fn path_for_file_id(artifact: &NormalizedArtifact, file_id: &Sha256Digest) -> Option<String> {
    artifact
        .file(file_id)
        .map(|file| file.normalized_path.clone())
}

fn clean_declared_path(value: &str) -> Option<String> {
    let mut value = value.trim().trim_matches(['\'', '"']).replace('\\', "/");
    while value.starts_with("./") {
        value = value[2..].to_string();
    }
    if value.is_empty() || value.starts_with('/') || value.split('/').any(|part| part == "..") {
        None
    } else {
        Some(value)
    }
}

fn command_path_candidates(command: &str) -> (Vec<String>, bool) {
    let mut output = Vec::new();
    let mut limit_reached = false;
    for token in command.split_whitespace() {
        let token = token.trim_matches(|character: char| {
            matches!(character, '\'' | '"' | ';' | '(' | ')' | '&' | '|')
        });
        if token.is_empty()
            || token.starts_with('-')
            || token.contains("://")
            || token.contains('=')
            || matches!(
                token,
                "node"
                    | "nodejs"
                    | "npm"
                    | "npx"
                    | "python"
                    | "python3"
                    | "sh"
                    | "bash"
                    | "zsh"
                    | "cmd"
                    | "cmd.exe"
                    | "powershell"
                    | "pwsh"
                    | "node-gyp"
            )
        {
            continue;
        }
        let path = token.split(['?', '#']).next().unwrap_or(token);
        if let Some(path) = clean_declared_path(path) {
            if output.len() >= MAX_COMMAND_PATH_CANDIDATES {
                limit_reached = true;
                break;
            }
            output.push(path);
        }
    }
    output.sort();
    output.dedup();
    (output, limit_reached)
}

fn resolve_javascript_specifier_indexed(
    path_index: &BTreeMap<&str, Sha256Digest>,
    from_path: &str,
    specifier: &str,
) -> Option<Sha256Digest> {
    if !specifier.starts_with('.') {
        return None;
    }
    let base = from_path.rsplit_once('/').map(|pair| pair.0).unwrap_or("");
    let joined = normalize_relative_path(base, specifier)?;
    let mut candidates = vec![joined.clone()];
    for extension in ["js", "cjs", "mjs", "jsx", "ts", "tsx", "json"] {
        candidates.push(format!("{joined}.{extension}"));
        candidates.push(format!("{joined}/index.{extension}"));
    }
    candidates
        .iter()
        .find_map(|candidate| path_index.get(candidate.as_str()).cloned())
}

fn resolve_python_import_indexed(
    path_index: &BTreeMap<&str, Sha256Digest>,
    from_path: &str,
    specifier: &str,
) -> Option<Sha256Digest> {
    if specifier.starts_with('.') {
        let dots = specifier
            .chars()
            .take_while(|character| *character == '.')
            .count();
        let module = specifier[dots..].replace('.', "/");
        let mut base = from_path
            .rsplit_once('/')
            .map(|pair| pair.0.to_string())
            .unwrap_or_default();
        for _ in 1..dots {
            base = base
                .rsplit_once('/')
                .map(|pair| pair.0.to_string())
                .unwrap_or_default();
        }
        let joined = if module.is_empty() {
            base
        } else {
            normalize_relative_path(&base, &module)?
        };
        resolve_python_path_indexed(path_index, &joined)
    } else {
        let module = specifier
            .split(':')
            .next()
            .unwrap_or(specifier)
            .replace('.', "/");
        let sibling = from_path.rsplit_once('/').map(|pair| pair.0).unwrap_or("");
        for root in ["", sibling] {
            let path = if root.is_empty() {
                module.clone()
            } else {
                format!("{root}/{module}")
            };
            if let Some(file_id) = resolve_python_path_indexed(path_index, &path) {
                return Some(file_id);
            }
        }
        None
    }
}

fn resolve_python_path_indexed(
    path_index: &BTreeMap<&str, Sha256Digest>,
    path: &str,
) -> Option<Sha256Digest> {
    [format!("{path}.py"), format!("{path}/__init__.py")]
        .iter()
        .find_map(|candidate| path_index.get(candidate.as_str()).cloned())
}

fn resolve_python_module(
    artifact: &NormalizedArtifact,
    module: &str,
    search_roots: &[String],
) -> Option<Sha256Digest> {
    let module = module.split(':').next().unwrap_or(module).replace('.', "/");
    let roots = if search_roots.is_empty() {
        vec![String::new()]
    } else {
        search_roots.to_vec()
    };
    for root in roots {
        let root = clean_declared_path(&root).unwrap_or_default();
        let path = if root.is_empty() {
            module.clone()
        } else {
            format!("{root}/{module}")
        };
        if let Some(file_id) = resolve_python_path(artifact, &path) {
            return Some(file_id);
        }
    }
    None
}

fn resolve_python_path(artifact: &NormalizedArtifact, path: &str) -> Option<Sha256Digest> {
    [format!("{path}.py"), format!("{path}/__init__.py")]
        .iter()
        .find_map(|candidate| file_id_for_path(artifact, candidate))
}

fn normalize_relative_path(base: &str, relative: &str) -> Option<String> {
    let mut parts = base
        .split('/')
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect::<Vec<_>>();
    for part in relative.replace('\\', "/").split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            value => parts.push(value.to_string()),
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

fn quoted_arguments_after(line: &str, marker: &str) -> Vec<String> {
    let mut output = Vec::new();
    let mut remaining = line;
    while let Some(index) = remaining.find(marker) {
        remaining = &remaining[index + marker.len()..];
        let trimmed = remaining.trim_start();
        let Some(quote) = trimmed
            .chars()
            .next()
            .filter(|character| matches!(character, '\'' | '"'))
        else {
            continue;
        };
        let after = &trimmed[quote.len_utf8()..];
        if let Some(end) = after.find(quote) {
            output.push(after[..end].to_string());
            remaining = &after[end + quote.len_utf8()..];
        }
    }
    output
}

fn quoted_strings(line: &str) -> Vec<String> {
    let mut output = Vec::new();
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\'' || bytes[index] == b'"' {
            let quote = bytes[index];
            let start = index + 1;
            index = start;
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index] == b'\\' {
                    index = index.saturating_add(1);
                }
                index = index.saturating_add(1);
            }
            if index <= bytes.len() {
                output.push(line[start..index.min(bytes.len())].to_string());
            }
        }
        index += 1;
    }
    output
}

fn safe_label(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '?'
            } else {
                character
            }
        })
        .take(160)
        .collect()
}

fn first_pattern<'a>(line: &str, patterns: &'a [&'a str]) -> Option<(usize, &'a str)> {
    patterns
        .iter()
        .filter_map(|pattern| line.find(pattern).map(|index| (index, *pattern)))
        .min_by_key(|(index, _)| *index)
}

fn sensitive_path_access(line: &str) -> bool {
    first_pattern(line, SENSITIVE_PATH_PATTERNS).is_some()
        && first_pattern(line, FILE_ACCESS_PATTERNS).is_some()
}

const ENVIRONMENT_PATTERNS: &[&str] = &[
    "process.env",
    "process['env']",
    "process[\"env\"]",
    "Deno.env.get(",
    "Bun.env",
    "os.environ",
    "os.getenv(",
    "os.environ.get(",
    "getenv(",
    "printenv ",
];

const CREDENTIAL_NAME_PATTERNS: &[&str] = &[
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "NODE_AUTH_TOKEN",
    "PYPI_TOKEN",
    "TWINE_PASSWORD",
    "SLACK_TOKEN",
    "SLACK_WEBHOOK",
    "CI_JOB_TOKEN",
    "AZURE_CLIENT_SECRET",
    "GOOGLE_APPLICATION_CREDENTIALS",
];

const SENSITIVE_PATH_PATTERNS: &[&str] = &[
    ".npmrc",
    ".pypirc",
    ".aws/credentials",
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    ".config/gcloud",
    ".azure/",
    ".docker/config.json",
    "/etc/passwd",
    "/etc/shadow",
    "Login Data",
];

const FILE_ACCESS_PATTERNS: &[&str] = &[
    "readFile(",
    "readFileSync(",
    "read_to_string(",
    "open(",
    "Path(",
    "createReadStream(",
    "glob(",
    "walk(",
    "cat ",
    "Get-Content ",
];

const NETWORK_PATTERNS: &[&str] = &[
    "https.request(",
    "http.request(",
    "https.get(",
    "http.get(",
    "fetch(",
    "globalThis.fetch(",
    "axios.get(",
    "axios.post(",
    "axios.request(",
    "got(",
    "net.connect(",
    "dns.resolve(",
    "dns.resolveTxt(",
    "WebSocket(",
    "requests.get(",
    "requests.post(",
    "requests.request(",
    "httpx.get(",
    "httpx.post(",
    "urllib.request",
    "socket.socket(",
    "socket.create_connection(",
    "aiohttp.ClientSession(",
    "dns.resolver",
    "curl ",
    "wget ",
    "ncat ",
    "nc ",
    "/dev/tcp/",
    "dig ",
    "nslookup ",
];

const PROCESS_PATTERNS: &[&str] = &[
    "node:child_process",
    "require('child_process')",
    "require(\"child_process\")",
    "child_process.exec(",
    "child_process.execFile(",
    "child_process.spawn(",
    "execSync(",
    "spawnSync(",
    "Bun.spawn(",
    "Deno.Command(",
    "subprocess.run(",
    "subprocess.Popen(",
    "subprocess.call(",
    "subprocess.check_output(",
    "os.system(",
    "os.popen(",
    "pty.spawn(",
    "bash -c ",
    "sh -c ",
    "eval ",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_resolution_rejects_escape() {
        assert_eq!(
            normalize_relative_path("lib/nested", "../safe"),
            Some("lib/safe".to_string())
        );
        assert_eq!(normalize_relative_path("", "../escape"), None);
    }

    #[test]
    fn labels_are_bounded_and_control_character_free() {
        let label = safe_label(&format!("before\nafter{}", "x".repeat(500)));
        assert!(!label.contains('\n'));
        assert!(label.chars().count() <= 160);
    }

    #[test]
    fn credential_names_alone_are_not_environment_access() {
        let plain = "const documented = 'NPM_TOKEN';";
        assert!(first_pattern(plain, CREDENTIAL_NAME_PATTERNS).is_some());
        assert!(first_pattern(plain, ENVIRONMENT_PATTERNS).is_none());
    }
}
