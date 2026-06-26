use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use whoathere_evidence::{
    EvidenceJobBinding, EvidenceJobKind, EvidenceProfile, JobState, NetworkMode,
};
use whoathere_hash::sha256_digest;
use whoathere_sandbox::{
    ProofSubject, ProviderChallengeReplayGuard, ProviderChallengeUseStatus,
    ProviderVerificationChallenge,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Quarantine,
    ManualReview,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionState {
    Requested,
    Quarantined,
    EvidencePending,
    EvidenceComplete,
    Promoted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactRef {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
    pub digest: String,
    pub source: String,
}

impl ArtifactRef {
    pub fn cache_key(&self) -> String {
        format!(
            "{}/{}/{}/{}",
            self.ecosystem, self.name, self.version, self.digest
        )
    }

    pub fn cache_object_key(&self) -> Result<String, CacheKeyError> {
        cache_object_key_for_digest(&self.digest)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheKeyError {
    MissingSeparator,
    EmptyAlgorithm,
    EmptyDigest,
    UnsupportedAlgorithm,
    InvalidDigestLength,
    NonCanonicalDigest,
    UnsafeDigest,
}

impl CacheKeyError {
    pub fn reason_code(self) -> &'static str {
        match self {
            Self::MissingSeparator => "artifact_digest_missing_algorithm_separator",
            Self::EmptyAlgorithm => "artifact_digest_algorithm_empty",
            Self::EmptyDigest => "artifact_digest_empty",
            Self::UnsupportedAlgorithm => "artifact_digest_algorithm_unsupported",
            Self::InvalidDigestLength => "artifact_digest_invalid_length",
            Self::NonCanonicalDigest => "artifact_digest_not_canonical_lower_hex",
            Self::UnsafeDigest => "artifact_digest_contains_unsafe_characters",
        }
    }
}

pub fn cache_object_key_for_digest(digest: &str) -> Result<String, CacheKeyError> {
    let Some((algorithm, value)) = digest.split_once(':') else {
        return Err(CacheKeyError::MissingSeparator);
    };
    if algorithm.is_empty() {
        return Err(CacheKeyError::EmptyAlgorithm);
    }
    if value.is_empty() {
        return Err(CacheKeyError::EmptyDigest);
    }
    if algorithm != "sha256" {
        return Err(CacheKeyError::UnsupportedAlgorithm);
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-' | '='))
    {
        return Err(CacheKeyError::UnsafeDigest);
    }
    if value.len() != 64 {
        return Err(CacheKeyError::InvalidDigestLength);
    }
    if !value
        .chars()
        .all(|character| character.is_ascii_digit() || matches!(character, 'a'..='f'))
    {
        return Err(CacheKeyError::NonCanonicalDigest);
    }
    Ok(format!("blobs/{algorithm}/{value}"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchJobState {
    Planned,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchJobRequest {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub source_url: String,
    pub expected_digest: String,
    pub byte_limit: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchJobPlan {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub state: FetchJobState,
    pub fetch_enabled: bool,
    pub network_attempted: bool,
    pub cache_object_key: Option<String>,
    pub source_url: String,
    pub expected_digest: String,
    pub byte_limit: u64,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchResultState {
    Verified,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchJobResult {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub source_url: String,
    pub expected_digest: String,
    pub verified_digest: String,
    pub cache_object_key: String,
    pub byte_len: u64,
    pub byte_limit: u64,
    pub quarantine_id: String,
    pub fetch_enabled: bool,
    pub network_attempted: bool,
    pub stored_in_quarantine: bool,
    pub audit_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchResultBinding {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub state: FetchResultState,
    pub admission_ready: bool,
    pub cache_object_key: Option<String>,
    pub byte_len: u64,
    pub byte_limit: u64,
    pub quarantine_id: String,
    pub audit_event_id: String,
    pub reason_codes: Vec<String>,
}

pub fn plan_fetch_job(request: FetchJobRequest) -> FetchJobPlan {
    let mut reason_codes = vec!["fetch_execution_not_enabled".to_string()];
    let cache_object_key = match request.artifact.cache_object_key() {
        Ok(key) => Some(key),
        Err(error) => {
            reason_codes.push(error.reason_code().to_string());
            None
        }
    };
    if request.expected_digest != request.artifact.digest {
        reason_codes.push("fetch_expected_digest_mismatch".to_string());
    }
    if request.byte_limit == 0 {
        reason_codes.push("fetch_byte_limit_zero".to_string());
    }
    if !request.source_url.starts_with("https://") {
        reason_codes.push("fetch_source_url_not_https".to_string());
    }
    let state = if cache_object_key.is_some()
        && request.expected_digest == request.artifact.digest
        && request.byte_limit > 0
        && request.source_url.starts_with("https://")
    {
        FetchJobState::Planned
    } else {
        FetchJobState::Rejected
    };
    FetchJobPlan {
        job_id: request.job_id,
        tenant_id: request.tenant_id,
        admission_request_id: request.admission_request_id,
        artifact: request.artifact,
        state,
        fetch_enabled: false,
        network_attempted: false,
        cache_object_key,
        source_url: request.source_url,
        expected_digest: request.expected_digest,
        byte_limit: request.byte_limit,
        reason_codes,
    }
}

pub fn bind_fetch_job_result(plan: &FetchJobPlan, result: FetchJobResult) -> FetchResultBinding {
    let mut reason_codes = Vec::new();
    if plan.state != FetchJobState::Planned {
        reason_codes.push("fetch_plan_not_planned".to_string());
    }
    if result.job_id != plan.job_id {
        reason_codes.push("fetch_result_job_mismatch".to_string());
    }
    if result.tenant_id != plan.tenant_id {
        reason_codes.push("fetch_result_tenant_mismatch".to_string());
    }
    if result.admission_request_id != plan.admission_request_id {
        reason_codes.push("fetch_result_admission_request_mismatch".to_string());
    }
    if result.artifact != plan.artifact {
        reason_codes.push("fetch_result_artifact_mismatch".to_string());
    }
    if result.source_url != plan.source_url {
        reason_codes.push("fetch_result_source_url_mismatch".to_string());
    }
    if result.expected_digest != plan.expected_digest {
        reason_codes.push("fetch_result_expected_digest_mismatch".to_string());
    }
    if result.verified_digest != plan.expected_digest {
        reason_codes.push("fetch_result_verified_digest_mismatch".to_string());
    }
    if result.byte_len == 0 {
        reason_codes.push("fetch_result_byte_len_zero".to_string());
    }
    if result.byte_limit != plan.byte_limit {
        reason_codes.push("fetch_result_byte_limit_mismatch".to_string());
    }
    if result.byte_len > plan.byte_limit {
        reason_codes.push("fetch_result_byte_limit_exceeded".to_string());
    }
    if result.quarantine_id.is_empty() {
        reason_codes.push("fetch_result_quarantine_id_empty".to_string());
    }
    if result.fetch_enabled != plan.fetch_enabled {
        reason_codes.push("fetch_result_fetch_enabled_mismatch".to_string());
    }
    if result.network_attempted && !plan.fetch_enabled {
        reason_codes.push("fetch_result_network_attempted_for_disabled_plan".to_string());
    }
    if !result.stored_in_quarantine {
        reason_codes.push("fetch_result_not_quarantined".to_string());
    }

    let expected_cache_key = match result.artifact.cache_object_key() {
        Ok(key) => Some(key),
        Err(error) => {
            reason_codes.push(error.reason_code().to_string());
            None
        }
    };
    if plan.cache_object_key.as_deref() != expected_cache_key.as_deref()
        || expected_cache_key.as_deref() != Some(result.cache_object_key.as_str())
    {
        reason_codes.push("fetch_result_cache_key_mismatch".to_string());
    }

    let state = if reason_codes.is_empty() {
        FetchResultState::Verified
    } else {
        FetchResultState::Rejected
    };
    FetchResultBinding {
        job_id: result.job_id,
        tenant_id: result.tenant_id,
        admission_request_id: result.admission_request_id,
        artifact: result.artifact,
        state,
        admission_ready: state == FetchResultState::Verified,
        cache_object_key: expected_cache_key,
        byte_len: result.byte_len,
        byte_limit: result.byte_limit,
        quarantine_id: result.quarantine_id,
        audit_event_id: result.audit_event_id,
        reason_codes,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceJobPlanState {
    Planned,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceJobResultState {
    Bound,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobRequest {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub cache_object_key: String,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobPlan {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub state: EvidenceJobPlanState,
    pub execution_enabled: bool,
    pub detonation_attempted: bool,
    pub network_attempted: bool,
    pub network_mode: Option<NetworkMode>,
    pub cache_object_key: Option<String>,
    pub timeout_seconds: u64,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobResultRecord {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub cache_object_key: String,
    pub state: JobState,
    pub log_digest: String,
    pub execution_enabled: bool,
    pub detonation_attempted: bool,
    pub network_attempted: bool,
    pub audit_event_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceJobResultBinding {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub state: EvidenceJobResultState,
    pub job_state: JobState,
    pub admission_ready: bool,
    pub cache_object_key: Option<String>,
    pub log_digest: String,
    pub execution_enabled: bool,
    pub detonation_attempted: bool,
    pub network_attempted: bool,
    pub audit_event_id: String,
    pub reason_codes: Vec<String>,
}

impl EvidenceJobResultBinding {
    pub fn evidence_binding(&self) -> EvidenceJobBinding {
        EvidenceJobBinding {
            job_id: self.job_id.clone(),
            job_kind: self.job_kind,
            profile_id: self.profile_id.clone(),
            profile_version: self.profile_version,
            artifact_digest: self.artifact.digest.clone(),
            cache_object_key: self.cache_object_key.clone().unwrap_or_default(),
            log_digest: self.log_digest.clone(),
            admission_ready: self.admission_ready,
        }
    }
}

pub fn plan_evidence_job(
    request: EvidenceJobRequest,
    profile: &EvidenceProfile,
) -> EvidenceJobPlan {
    let mut reason_codes = vec!["evidence_job_execution_not_enabled".to_string()];
    if request.job_id.is_empty() {
        reason_codes.push("evidence_job_id_empty".to_string());
    }
    if request.profile_id != profile.id {
        reason_codes.push("evidence_job_profile_id_mismatch".to_string());
    }
    if request.profile_version != profile.version {
        reason_codes.push("evidence_job_profile_version_mismatch".to_string());
    }
    let requirement = profile
        .requirements
        .iter()
        .find(|requirement| requirement.job_kind == request.job_kind);
    if requirement.is_none() {
        reason_codes.push("evidence_job_kind_unexpected_for_profile".to_string());
    }
    if request.timeout_seconds == 0 {
        reason_codes.push("evidence_job_timeout_zero".to_string());
    }
    let expected_cache_key = match request.artifact.cache_object_key() {
        Ok(key) => Some(key),
        Err(error) => {
            reason_codes.push(error.reason_code().to_string());
            None
        }
    };
    if expected_cache_key.as_deref() != Some(request.cache_object_key.as_str()) {
        reason_codes.push("evidence_job_cache_key_mismatch".to_string());
    }

    let state = if reason_codes.len() == 1
        && expected_cache_key.as_deref() == Some(request.cache_object_key.as_str())
        && request.timeout_seconds > 0
        && requirement.is_some()
        && request.profile_id == profile.id
        && request.profile_version == profile.version
        && !request.job_id.is_empty()
    {
        EvidenceJobPlanState::Planned
    } else {
        EvidenceJobPlanState::Rejected
    };
    EvidenceJobPlan {
        job_id: request.job_id,
        tenant_id: request.tenant_id,
        admission_request_id: request.admission_request_id,
        artifact: request.artifact,
        profile_id: request.profile_id,
        profile_version: request.profile_version,
        job_kind: request.job_kind,
        state,
        execution_enabled: false,
        detonation_attempted: false,
        network_attempted: false,
        network_mode: requirement.map(|requirement| requirement.network_mode),
        cache_object_key: expected_cache_key,
        timeout_seconds: request.timeout_seconds,
        reason_codes,
    }
}

pub fn bind_evidence_job_result(
    plan: &EvidenceJobPlan,
    result: EvidenceJobResultRecord,
) -> EvidenceJobResultBinding {
    let mut reason_codes = Vec::new();
    if plan.state != EvidenceJobPlanState::Planned {
        reason_codes.push("evidence_job_plan_not_planned".to_string());
    }
    if result.job_id != plan.job_id {
        reason_codes.push("evidence_job_result_job_mismatch".to_string());
    }
    if result.tenant_id != plan.tenant_id {
        reason_codes.push("evidence_job_result_tenant_mismatch".to_string());
    }
    if result.admission_request_id != plan.admission_request_id {
        reason_codes.push("evidence_job_result_admission_request_mismatch".to_string());
    }
    if result.artifact != plan.artifact {
        reason_codes.push("evidence_job_result_artifact_mismatch".to_string());
    }
    if result.profile_id != plan.profile_id {
        reason_codes.push("evidence_job_result_profile_id_mismatch".to_string());
    }
    if result.profile_version != plan.profile_version {
        reason_codes.push("evidence_job_result_profile_version_mismatch".to_string());
    }
    if result.job_kind != plan.job_kind {
        reason_codes.push("evidence_job_result_kind_mismatch".to_string());
    }
    if plan.cache_object_key.as_deref() != Some(result.cache_object_key.as_str()) {
        reason_codes.push("evidence_job_result_cache_key_mismatch".to_string());
    }
    if result.execution_enabled != plan.execution_enabled {
        reason_codes.push("evidence_job_result_execution_enabled_mismatch".to_string());
    }
    if result.execution_enabled {
        reason_codes.push("evidence_job_result_execution_attempted".to_string());
    }
    if result.detonation_attempted {
        reason_codes.push("evidence_job_result_detonation_attempted".to_string());
    }
    if result.network_attempted {
        reason_codes.push("evidence_job_result_network_attempted".to_string());
    }
    if !valid_sha256_digest(&result.log_digest) {
        reason_codes.push("evidence_job_result_log_digest_invalid".to_string());
    }
    if result.audit_event_id.is_empty() {
        reason_codes.push("evidence_job_result_audit_event_id_empty".to_string());
    }
    if result.state != JobState::Passed {
        reason_codes.push("evidence_job_result_not_passed".to_string());
    }

    let state = if reason_codes.is_empty() {
        EvidenceJobResultState::Bound
    } else {
        EvidenceJobResultState::Rejected
    };
    EvidenceJobResultBinding {
        job_id: result.job_id,
        tenant_id: result.tenant_id,
        admission_request_id: result.admission_request_id,
        artifact: result.artifact,
        profile_id: result.profile_id,
        profile_version: result.profile_version,
        job_kind: result.job_kind,
        state,
        job_state: result.state,
        admission_ready: state == EvidenceJobResultState::Bound,
        cache_object_key: plan.cache_object_key.clone(),
        log_digest: result.log_digest,
        execution_enabled: result.execution_enabled,
        detonation_attempted: result.detonation_attempted,
        network_attempted: result.network_attempted,
        audit_event_id: result.audit_event_id,
        reason_codes,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicBehaviorSignalSummary {
    pub trigger_kind: String,
    pub process_intent_count: u16,
    pub filesystem_write_count: u16,
    pub network_attempt_count: u16,
    pub dns_attempt_count: u16,
    pub env_access_count: u16,
    pub credential_access_count: u16,
    pub delayed_execution_detected: bool,
    pub native_extension_detected: bool,
    pub platform_specific_detected: bool,
    pub direct_source_detected: bool,
}

impl DynamicBehaviorSignalSummary {
    pub fn clean() -> Self {
        Self {
            trigger_kind: "fixture_clean".to_string(),
            process_intent_count: 0,
            filesystem_write_count: 0,
            network_attempt_count: 0,
            dns_attempt_count: 0,
            env_access_count: 0,
            credential_access_count: 0,
            delayed_execution_detected: false,
            native_extension_detected: false,
            platform_specific_detected: false,
            direct_source_detected: false,
        }
    }

    fn has_high_risk_signal(&self) -> bool {
        self.network_attempt_count > 0
            || self.dns_attempt_count > 0
            || self.credential_access_count > 0
            || self.delayed_execution_detected
            || self.native_extension_detected
            || self.platform_specific_detected
            || self.direct_source_detected
    }

    fn metadata_is_safe(&self) -> bool {
        signal_metadata_value_is_safe(&self.trigger_kind)
    }

    fn sanitized_for_binding(mut self) -> Self {
        if !signal_metadata_value_is_safe(&self.trigger_kind) {
            self.trigger_kind = "<invalid-signal-metadata>".to_string();
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicBehaviorPlanState {
    Planned,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicBehaviorResultState {
    Bound,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicBehaviorJobRequest {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub cache_object_key: String,
    pub runner_id: String,
    pub runner_session_id: String,
    pub isolation_proof_id: String,
    pub egress_proof_id: String,
    pub configured_vault_host: String,
    pub fixture_mode: bool,
    pub issued_at_unix_seconds: u64,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicBehaviorJobPlan {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub state: DynamicBehaviorPlanState,
    pub execution_enabled: bool,
    pub arbitrary_execution_enabled: bool,
    pub fixture_mode: bool,
    pub network_attempted: bool,
    pub cache_object_key: Option<String>,
    pub runner_id: String,
    pub runner_session_id: String,
    pub isolation_proof_id: String,
    pub egress_proof_id: String,
    pub configured_vault_host: String,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicBehaviorJobResultRecord {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub cache_object_key: String,
    pub runner_id: String,
    pub runner_session_id: String,
    pub isolation_proof_id: String,
    pub egress_proof_id: String,
    pub configured_vault_host: String,
    pub observed_at_unix_seconds: u64,
    pub job_state: JobState,
    pub behavior_schema: String,
    pub behavior_log_digest: String,
    pub signal_summary: DynamicBehaviorSignalSummary,
    pub execution_enabled: bool,
    pub arbitrary_execution_attempted: bool,
    pub fixture_mode: bool,
    pub network_attempted: bool,
    pub isolation_verified: bool,
    pub egress_vault_only_verified: bool,
    pub raw_log_captured: bool,
    pub raw_env_captured: bool,
    pub raw_network_payload_captured: bool,
    pub raw_package_bytes_captured: bool,
    pub local_paths_captured: bool,
    pub audit_event_id: String,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicBehaviorResultBinding {
    pub job_id: String,
    pub tenant_id: String,
    pub admission_request_id: String,
    pub artifact: ArtifactRef,
    pub profile_id: String,
    pub profile_version: u16,
    pub job_kind: EvidenceJobKind,
    pub state: DynamicBehaviorResultState,
    pub job_state: JobState,
    pub admission_ready: bool,
    pub cache_object_key: Option<String>,
    pub behavior_log_digest: String,
    pub runner_id: String,
    pub runner_session_id: String,
    pub isolation_proof_id: String,
    pub egress_proof_id: String,
    pub configured_vault_host: String,
    pub audit_event_id: String,
    pub signal_summary: DynamicBehaviorSignalSummary,
    pub reason_codes: Vec<String>,
}

impl DynamicBehaviorResultBinding {
    pub fn evidence_job_result(&self) -> whoathere_evidence::EvidenceJobResult {
        whoathere_evidence::EvidenceJobResult {
            job_id: self.job_id.clone(),
            job_kind: self.job_kind,
            state: self.job_state,
            log_digest: self.behavior_log_digest.clone(),
            reason_codes: self.reason_codes.clone(),
        }
    }

    pub fn evidence_binding(&self) -> EvidenceJobBinding {
        EvidenceJobBinding {
            job_id: self.job_id.clone(),
            job_kind: self.job_kind,
            profile_id: self.profile_id.clone(),
            profile_version: self.profile_version,
            artifact_digest: self.artifact.digest.clone(),
            cache_object_key: self.cache_object_key.clone().unwrap_or_default(),
            log_digest: self.behavior_log_digest.clone(),
            admission_ready: self.admission_ready,
        }
    }
}

pub fn plan_dynamic_behavior_job(
    request: DynamicBehaviorJobRequest,
    profile: &EvidenceProfile,
) -> DynamicBehaviorJobPlan {
    let mut reason_codes = vec!["dynamic_behavior_arbitrary_execution_disabled".to_string()];
    if request.job_id.is_empty() {
        reason_codes.push("dynamic_behavior_job_id_empty".to_string());
    }
    if request.profile_id != profile.id {
        reason_codes.push("dynamic_behavior_profile_id_mismatch".to_string());
    }
    if request.profile_version != profile.version {
        reason_codes.push("dynamic_behavior_profile_version_mismatch".to_string());
    }
    if !matches!(
        request.job_kind,
        EvidenceJobKind::LifecycleDetonation
            | EvidenceJobKind::ImportSmoke
            | EvidenceJobKind::NativeBuild
    ) {
        reason_codes.push("dynamic_behavior_job_kind_not_dynamic".to_string());
    }
    let requirement = profile
        .requirements
        .iter()
        .find(|requirement| requirement.job_kind == request.job_kind);
    if requirement.is_none() {
        reason_codes.push("dynamic_behavior_job_kind_unexpected_for_profile".to_string());
    }
    if !request.fixture_mode {
        reason_codes.push("dynamic_behavior_fixture_mode_required".to_string());
    }
    if request.timeout_seconds == 0 {
        reason_codes.push("dynamic_behavior_timeout_zero".to_string());
    }
    for (value, reason) in [
        (&request.runner_id, "dynamic_behavior_runner_id_empty"),
        (
            &request.runner_session_id,
            "dynamic_behavior_runner_session_id_empty",
        ),
        (
            &request.isolation_proof_id,
            "dynamic_behavior_isolation_proof_id_empty",
        ),
        (
            &request.egress_proof_id,
            "dynamic_behavior_egress_proof_id_empty",
        ),
        (
            &request.configured_vault_host,
            "dynamic_behavior_configured_vault_host_empty",
        ),
    ] {
        if value.is_empty() {
            reason_codes.push(reason.to_string());
        }
    }
    for value in [
        request.job_id.as_str(),
        request.tenant_id.as_str(),
        request.admission_request_id.as_str(),
        request.runner_id.as_str(),
        request.runner_session_id.as_str(),
        request.isolation_proof_id.as_str(),
        request.egress_proof_id.as_str(),
        request.configured_vault_host.as_str(),
    ] {
        if !metadata_value_is_safe(value) {
            reason_codes.push("dynamic_behavior_metadata_control_character".to_string());
            break;
        }
    }
    let expected_cache_key = match request.artifact.cache_object_key() {
        Ok(key) => Some(key),
        Err(error) => {
            reason_codes.push(error.reason_code().to_string());
            None
        }
    };
    if expected_cache_key.as_deref() != Some(request.cache_object_key.as_str()) {
        reason_codes.push("dynamic_behavior_cache_key_mismatch".to_string());
    }
    let state = if reason_codes.len() == 1
        && request.fixture_mode
        && request.timeout_seconds > 0
        && requirement.is_some()
        && expected_cache_key.as_deref() == Some(request.cache_object_key.as_str())
        && !request.job_id.is_empty()
        && !request.runner_id.is_empty()
        && !request.runner_session_id.is_empty()
        && !request.isolation_proof_id.is_empty()
        && !request.egress_proof_id.is_empty()
        && !request.configured_vault_host.is_empty()
    {
        DynamicBehaviorPlanState::Planned
    } else {
        DynamicBehaviorPlanState::Rejected
    };
    DynamicBehaviorJobPlan {
        job_id: request.job_id,
        tenant_id: request.tenant_id,
        admission_request_id: request.admission_request_id,
        artifact: request.artifact,
        profile_id: request.profile_id,
        profile_version: request.profile_version,
        job_kind: request.job_kind,
        state,
        execution_enabled: false,
        arbitrary_execution_enabled: false,
        fixture_mode: request.fixture_mode,
        network_attempted: false,
        cache_object_key: expected_cache_key,
        runner_id: request.runner_id,
        runner_session_id: request.runner_session_id,
        isolation_proof_id: request.isolation_proof_id,
        egress_proof_id: request.egress_proof_id,
        configured_vault_host: request.configured_vault_host,
        issued_at_unix_seconds: request.issued_at_unix_seconds,
        expires_at_unix_seconds: request.issued_at_unix_seconds + request.timeout_seconds,
        reason_codes,
    }
}

pub fn bind_dynamic_behavior_result(
    plan: &DynamicBehaviorJobPlan,
    result: DynamicBehaviorJobResultRecord,
) -> DynamicBehaviorResultBinding {
    let mut reason_codes = Vec::new();
    append_safe_reason_codes(
        &mut reason_codes,
        &result.reason_codes,
        "dynamic_behavior_result_reason_code_invalid",
    );
    if plan.state != DynamicBehaviorPlanState::Planned {
        reason_codes.push("dynamic_behavior_plan_not_planned".to_string());
    }
    if result.job_id != plan.job_id {
        reason_codes.push("dynamic_behavior_result_job_mismatch".to_string());
    }
    if result.tenant_id != plan.tenant_id {
        reason_codes.push("dynamic_behavior_result_tenant_mismatch".to_string());
    }
    if result.admission_request_id != plan.admission_request_id {
        reason_codes.push("dynamic_behavior_result_admission_request_mismatch".to_string());
    }
    if result.artifact != plan.artifact {
        reason_codes.push("dynamic_behavior_result_artifact_mismatch".to_string());
    }
    if result.profile_id != plan.profile_id {
        reason_codes.push("dynamic_behavior_result_profile_id_mismatch".to_string());
    }
    if result.profile_version != plan.profile_version {
        reason_codes.push("dynamic_behavior_result_profile_version_mismatch".to_string());
    }
    if result.job_kind != plan.job_kind {
        reason_codes.push("dynamic_behavior_result_kind_mismatch".to_string());
    }
    if plan.cache_object_key.as_deref() != Some(result.cache_object_key.as_str()) {
        reason_codes.push("dynamic_behavior_result_cache_key_mismatch".to_string());
    }
    if result.runner_id != plan.runner_id {
        reason_codes.push("dynamic_behavior_result_runner_mismatch".to_string());
    }
    if result.runner_session_id != plan.runner_session_id {
        reason_codes.push("dynamic_behavior_result_runner_session_mismatch".to_string());
    }
    if result.isolation_proof_id != plan.isolation_proof_id {
        reason_codes.push("dynamic_behavior_result_isolation_proof_mismatch".to_string());
    }
    if result.egress_proof_id != plan.egress_proof_id {
        reason_codes.push("dynamic_behavior_result_egress_proof_mismatch".to_string());
    }
    if result.configured_vault_host != plan.configured_vault_host {
        reason_codes.push("dynamic_behavior_result_vault_host_mismatch".to_string());
    }
    if result.observed_at_unix_seconds < plan.issued_at_unix_seconds
        || result.observed_at_unix_seconds > plan.expires_at_unix_seconds
    {
        reason_codes.push("dynamic_behavior_result_stale_or_not_yet_valid".to_string());
    }
    if result.execution_enabled != plan.execution_enabled {
        reason_codes.push("dynamic_behavior_result_execution_enabled_mismatch".to_string());
    }
    if result.execution_enabled || result.arbitrary_execution_attempted {
        reason_codes.push("dynamic_behavior_arbitrary_execution_attempted".to_string());
    }
    if result.fixture_mode != plan.fixture_mode {
        reason_codes.push("dynamic_behavior_fixture_mode_mismatch".to_string());
    }
    if result.network_attempted {
        reason_codes.push("dynamic_behavior_network_attempted".to_string());
    }
    if !result.isolation_verified {
        reason_codes.push("dynamic_behavior_isolation_not_verified".to_string());
    }
    if !result.egress_vault_only_verified {
        reason_codes.push("dynamic_behavior_egress_not_verified".to_string());
    }
    if result.raw_log_captured
        || result.raw_env_captured
        || result.raw_network_payload_captured
        || result.raw_package_bytes_captured
        || result.local_paths_captured
    {
        reason_codes.push("dynamic_behavior_raw_or_local_material_captured".to_string());
    }
    if result.behavior_schema != "whoathere.dynamic_behavior.v1" {
        reason_codes.push("dynamic_behavior_schema_mismatch".to_string());
    }
    if !valid_sha256_digest(&result.behavior_log_digest) {
        reason_codes.push("dynamic_behavior_log_digest_invalid".to_string());
    }
    if result.audit_event_id.is_empty() {
        reason_codes.push("dynamic_behavior_audit_event_id_empty".to_string());
    }
    if result.job_state != JobState::Passed {
        reason_codes.push("dynamic_behavior_result_not_passed".to_string());
    }
    if result.signal_summary.has_high_risk_signal() {
        reason_codes.push("dynamic_behavior_high_risk_signal_detected".to_string());
    }
    let signal_metadata_is_safe = result.signal_summary.metadata_is_safe();
    if !signal_metadata_is_safe {
        reason_codes.push("dynamic_behavior_signal_metadata_control_character".to_string());
    }
    reason_codes.sort();
    reason_codes.dedup();

    let state = if reason_codes.is_empty() {
        DynamicBehaviorResultState::Bound
    } else {
        DynamicBehaviorResultState::Rejected
    };
    DynamicBehaviorResultBinding {
        job_id: result.job_id,
        tenant_id: result.tenant_id,
        admission_request_id: result.admission_request_id,
        artifact: result.artifact,
        profile_id: result.profile_id,
        profile_version: result.profile_version,
        job_kind: result.job_kind,
        state,
        job_state: result.job_state,
        admission_ready: state == DynamicBehaviorResultState::Bound,
        cache_object_key: plan.cache_object_key.clone(),
        behavior_log_digest: result.behavior_log_digest,
        runner_id: result.runner_id,
        runner_session_id: result.runner_session_id,
        isolation_proof_id: result.isolation_proof_id,
        egress_proof_id: result.egress_proof_id,
        configured_vault_host: result.configured_vault_host,
        audit_event_id: result.audit_event_id,
        signal_summary: result.signal_summary.sanitized_for_binding(),
        reason_codes,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminWorkflowAction {
    ManualReview,
    Quarantine,
    Deny,
    AllowAfterReview,
    BreakGlass,
    AuditSearch,
    AuditExport,
}

impl AdminWorkflowAction {
    pub fn label(self) -> &'static str {
        match self {
            Self::ManualReview => "manual_review",
            Self::Quarantine => "quarantine",
            Self::Deny => "deny",
            Self::AllowAfterReview => "allow_after_review",
            Self::BreakGlass => "break_glass",
            Self::AuditSearch => "audit_search",
            Self::AuditExport => "audit_export",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminWorkflowDecisionState {
    Accepted,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminWorkflowRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub artifact: ArtifactRef,
    pub action: AdminWorkflowAction,
    pub operator_id: String,
    pub reason_code: String,
    pub ticket_id: String,
    pub break_glass: bool,
    pub policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminWorkflowDecision {
    pub request_id: String,
    pub tenant_id: String,
    pub artifact: ArtifactRef,
    pub action: AdminWorkflowAction,
    pub state: AdminWorkflowDecisionState,
    pub audit_event_id: String,
    pub decision: Verdict,
    pub requires_second_approval: bool,
    pub raw_reason_logged: bool,
    pub raw_operator_token_logged: bool,
    pub reason_codes: Vec<String>,
}

pub fn plan_admin_workflow_action(request: AdminWorkflowRequest) -> AdminWorkflowDecision {
    let mut reason_codes = Vec::new();
    if request.request_id.is_empty() {
        reason_codes.push("admin_workflow_request_id_empty".to_string());
    }
    if request.tenant_id.is_empty() {
        reason_codes.push("admin_workflow_tenant_id_empty".to_string());
    }
    if request.operator_id.is_empty() {
        reason_codes.push("admin_workflow_operator_id_empty".to_string());
    }
    if request.ticket_id.is_empty() {
        reason_codes.push("admin_workflow_ticket_id_empty".to_string());
    }
    if request.reason_code.is_empty() {
        reason_codes.push("admin_workflow_reason_code_empty".to_string());
    }
    if request.policy_version.is_empty() {
        reason_codes.push("admin_workflow_policy_version_empty".to_string());
    }
    if request.artifact.cache_object_key().is_err() {
        reason_codes.push("admin_workflow_artifact_digest_invalid".to_string());
    }
    for value in [
        request.request_id.as_str(),
        request.tenant_id.as_str(),
        request.operator_id.as_str(),
        request.ticket_id.as_str(),
        request.reason_code.as_str(),
        request.policy_version.as_str(),
    ] {
        if !metadata_value_is_safe(value) {
            reason_codes.push("admin_workflow_metadata_control_character".to_string());
            break;
        }
    }
    if request.action == AdminWorkflowAction::BreakGlass && !request.break_glass {
        reason_codes.push("admin_workflow_break_glass_confirmation_required".to_string());
    }
    if request.action == AdminWorkflowAction::AllowAfterReview && request.break_glass {
        reason_codes.push("admin_workflow_break_glass_not_allowed_for_review_allow".to_string());
    }

    let state = if reason_codes.is_empty() {
        AdminWorkflowDecisionState::Accepted
    } else {
        AdminWorkflowDecisionState::Rejected
    };
    let decision = match (request.action, state) {
        (_, AdminWorkflowDecisionState::Rejected) => Verdict::Deny,
        (AdminWorkflowAction::ManualReview, _) => Verdict::ManualReview,
        (AdminWorkflowAction::Quarantine, _) => Verdict::Quarantine,
        (AdminWorkflowAction::Deny, _) => Verdict::Deny,
        (AdminWorkflowAction::AllowAfterReview, _) => Verdict::Allow,
        (AdminWorkflowAction::BreakGlass, _) => Verdict::Allow,
        (AdminWorkflowAction::AuditSearch | AdminWorkflowAction::AuditExport, _) => {
            Verdict::Pending
        }
    };
    let audit_fragment = sha256_digest(
        format!(
            "{}:{}:{}:{}",
            request.tenant_id,
            request.request_id,
            request.action.label(),
            request.ticket_id
        )
        .as_bytes(),
    )
    .strip_prefix("sha256:")
    .unwrap_or_default()
    .chars()
    .take(16)
    .collect::<String>();
    AdminWorkflowDecision {
        request_id: request.request_id,
        tenant_id: request.tenant_id,
        artifact: request.artifact,
        action: request.action,
        state,
        audit_event_id: format!("audit-admin-{audit_fragment}"),
        decision,
        requires_second_approval: request.action == AdminWorkflowAction::BreakGlass,
        raw_reason_logged: false,
        raw_operator_token_logged: false,
        reason_codes,
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

fn metadata_value_is_safe(value: &str) -> bool {
    value
        .chars()
        .all(|character| !character.is_control() && character != '\n' && character != '\r')
}

fn signal_metadata_value_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.chars().all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || matches!(character, '_' | '-' | '.')
        })
}

fn append_safe_reason_codes(target: &mut Vec<String>, source: &[String], invalid_reason: &str) {
    let mut saw_invalid = false;
    for reason in source {
        if reason_code_value_is_safe(reason) {
            target.push(reason.clone());
        } else {
            saw_invalid = true;
        }
    }
    if saw_invalid {
        target.push(invalid_reason.to_string());
    }
}

fn reason_code_value_is_safe(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub artifact: ArtifactRef,
    pub policy_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub reason_code: String,
    pub retryable: bool,
    pub audit_event_id: String,
    pub policy_version: String,
    pub admission_request_id: String,
}

impl ApiError {
    pub fn fail_closed(request: &AdmissionRequest, reason_code: impl Into<String>) -> Self {
        Self {
            reason_code: reason_code.into(),
            retryable: false,
            audit_event_id: format!("audit-{}", request.request_id),
            policy_version: request.policy_version.clone(),
            admission_request_id: request.request_id.clone(),
        }
    }

    pub fn unknown_request(request_id: impl Into<String>) -> Self {
        let request_id = request_id.into();
        Self {
            reason_code: "admission_request_not_found".to_string(),
            retryable: false,
            audit_event_id: format!("audit-{request_id}"),
            policy_version: "unknown".to_string(),
            admission_request_id: request_id,
        }
    }
}

pub const CHALLENGE_AUTHORITY_NAME: &str = "vault_challenge_authority.v1";
pub const CHALLENGE_AUTHORITY_TRUSTED_TIME_SOURCE: &str = "vault_server_clock";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ChallengeAuthorityScenario {
    pub replay: bool,
    pub unknown_challenge: bool,
    pub mutate_context: bool,
    pub expired: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeAuthorityRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub subject: String,
    pub context_hash: String,
    pub configured_vault_host: String,
    pub now_unix_seconds: u64,
    pub ttl_seconds: u64,
    pub scenario: ChallengeAuthorityScenario,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeAuthorityStatus {
    Ok,
    FailClosed,
}

impl ChallengeAuthorityStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::FailClosed => "fail_closed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeAuthorityDecision {
    pub request_id: String,
    pub tenant_id: String,
    pub status: ChallengeAuthorityStatus,
    pub authority: &'static str,
    pub authorization: bool,
    pub proof_minted: bool,
    pub execution_allowed: bool,
    pub trusted_time_source: &'static str,
    pub client_time_accepted: bool,
    pub ttl_seconds: u64,
    pub issued_challenge_id: String,
    pub submitted_challenge_id: String,
    pub nonce_present: bool,
    pub raw_nonce_returned: bool,
    pub probe_destination_count: usize,
    pub expires_at_unix_seconds: u64,
    pub scenario: ChallengeAuthorityScenario,
    pub first_consume_status: ProviderChallengeUseStatus,
    pub replay_consume_status: Option<ProviderChallengeUseStatus>,
    pub accepted: bool,
    pub reason_codes: Vec<String>,
    pub replay_reason_codes: Vec<String>,
    pub http_status_code: u16,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeIssueRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub subject: String,
    pub context_hash: String,
    pub configured_vault_host: String,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeIssueDecision {
    pub request_id: String,
    pub tenant_id: String,
    pub status: ChallengeAuthorityStatus,
    pub authority: &'static str,
    pub trusted_time_source: &'static str,
    pub client_time_accepted: bool,
    pub ttl_seconds: u64,
    pub challenge_id: String,
    pub subject: String,
    pub context_hash: String,
    pub configured_vault_host: String,
    pub nonce_present: bool,
    pub raw_nonce_returned: bool,
    pub probe_destination_count: usize,
    pub expires_at_unix_seconds: u64,
    pub reason_codes: Vec<String>,
    pub http_status_code: u16,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeConsumeRequest {
    pub request_id: String,
    pub tenant_id: String,
    pub challenge_id: String,
    pub submitted_subject: String,
    pub submitted_context_hash: String,
    pub submitted_configured_vault_host: String,
    pub now_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeConsumeDecision {
    pub request_id: String,
    pub tenant_id: String,
    pub status: ChallengeAuthorityStatus,
    pub authority: &'static str,
    pub trusted_time_source: &'static str,
    pub client_time_accepted: bool,
    pub ttl_seconds: u64,
    pub challenge_id: String,
    pub consume_status: ProviderChallengeUseStatus,
    pub accepted: bool,
    pub nonce_present: bool,
    pub raw_nonce_returned: bool,
    pub raw_nonce_stored: bool,
    pub probe_destination_count: usize,
    pub expires_at_unix_seconds: u64,
    pub reason_codes: Vec<String>,
    pub http_status_code: u16,
    pub exit_code: i32,
}

impl ChallengeConsumeDecision {
    pub fn consume_status_label(&self) -> &'static str {
        challenge_use_status_label(self.consume_status)
    }
}

#[derive(Debug)]
pub struct InMemoryChallengeAuthority {
    ttl_seconds: u64,
    next_sequence: u64,
    records: BTreeMap<String, ChallengeAuthorityRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeAuthorityRecord {
    pub issued_sequence: u64,
    pub tenant_id: String,
    pub challenge_id: String,
    pub subject: String,
    pub context_hash: String,
    pub configured_vault_host: String,
    pub probe_destinations: Vec<String>,
    pub validation_time_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub nonce_present: bool,
    pub raw_nonce_stored: bool,
    pub consumed: bool,
}

impl InMemoryChallengeAuthority {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            ttl_seconds,
            next_sequence: 0,
            records: BTreeMap::new(),
        }
    }

    pub fn restore(
        ttl_seconds: u64,
        next_sequence: u64,
        records: impl IntoIterator<Item = ChallengeAuthorityRecord>,
    ) -> Self {
        let mut authority = Self {
            ttl_seconds,
            next_sequence,
            records: BTreeMap::new(),
        };
        for record in records {
            authority
                .records
                .insert(record.challenge_id.clone(), record);
        }
        authority
    }

    pub fn issue(&mut self, request: ChallengeIssueRequest) -> ChallengeIssueDecision {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.saturating_add(1);
        let nonce_basis = format!(
            "vault-authority;sequence={sequence};tenant_id={};subject={};context_hash={};configured_vault_host={};issued_at={}",
            request.tenant_id,
            request.subject,
            request.context_hash,
            request.configured_vault_host,
            request.now_unix_seconds
        );
        let challenge_nonce = format!("proof-nonce-{}", sha256_digest(nonce_basis.as_bytes()));
        let challenge = ProviderVerificationChallenge::new_with_nonce(
            ProofSubject::for_launch(&request.subject),
            request.context_hash.clone(),
            request.configured_vault_host.clone(),
            request.now_unix_seconds,
            challenge_nonce,
            request.now_unix_seconds.saturating_add(self.ttl_seconds),
        );
        let reason_codes = challenge
            .reason_codes_at(request.now_unix_seconds)
            .into_iter()
            .map(str::to_string)
            .collect::<Vec<_>>();
        let record = ChallengeAuthorityRecord {
            issued_sequence: sequence,
            tenant_id: request.tenant_id.clone(),
            challenge_id: challenge.challenge_id.clone(),
            subject: challenge.subject.launch_id.clone(),
            context_hash: challenge.context_hash.clone(),
            configured_vault_host: challenge.configured_vault_host.clone(),
            probe_destinations: challenge.probe_destinations.clone(),
            validation_time_unix_seconds: challenge.validation_time_unix_seconds,
            expires_at_unix_seconds: challenge.expires_at_unix_seconds,
            nonce_present: !challenge.challenge_nonce.is_empty(),
            raw_nonce_stored: false,
            consumed: false,
        };
        let status = if reason_codes.is_empty() {
            self.records
                .insert(record.challenge_id.clone(), record.clone());
            ChallengeAuthorityStatus::Ok
        } else {
            ChallengeAuthorityStatus::FailClosed
        };
        let http_status_code = if status == ChallengeAuthorityStatus::Ok {
            200
        } else {
            409
        };
        let exit_code = if status == ChallengeAuthorityStatus::Ok {
            0
        } else {
            20
        };
        ChallengeIssueDecision {
            request_id: request.request_id,
            tenant_id: request.tenant_id,
            status,
            authority: CHALLENGE_AUTHORITY_NAME,
            trusted_time_source: CHALLENGE_AUTHORITY_TRUSTED_TIME_SOURCE,
            client_time_accepted: false,
            ttl_seconds: self.ttl_seconds,
            challenge_id: record.challenge_id,
            subject: record.subject,
            context_hash: record.context_hash,
            configured_vault_host: record.configured_vault_host,
            nonce_present: record.nonce_present,
            raw_nonce_returned: record.raw_nonce_stored,
            probe_destination_count: record.probe_destinations.len(),
            expires_at_unix_seconds: record.expires_at_unix_seconds,
            reason_codes,
            http_status_code,
            exit_code,
        }
    }

    pub fn consume(&mut self, request: ChallengeConsumeRequest) -> ChallengeConsumeDecision {
        let (
            consume_status,
            accepted,
            reason_codes,
            nonce_present,
            raw_nonce_stored,
            probe_destination_count,
            expires_at_unix_seconds,
        ) = match self.records.get_mut(&request.challenge_id) {
            Some(record) if record.tenant_id == request.tenant_id => {
                let mut reason_codes = Vec::new();
                if request.submitted_subject != record.subject {
                    reason_codes.push("challenge_authority_subject_mismatch".to_string());
                }
                if request.submitted_context_hash != record.context_hash {
                    reason_codes.push("challenge_authority_context_hash_mismatch".to_string());
                }
                if request.submitted_configured_vault_host != record.configured_vault_host {
                    reason_codes
                        .push("challenge_authority_configured_vault_host_mismatch".to_string());
                }
                if record.consumed {
                    reason_codes.push("provider_challenge_replayed".to_string());
                }
                if request.now_unix_seconds < record.validation_time_unix_seconds {
                    reason_codes.push("provider_challenge_not_yet_valid".to_string());
                }
                if request.now_unix_seconds >= record.expires_at_unix_seconds {
                    reason_codes.push("provider_challenge_expired".to_string());
                }
                reason_codes.sort();
                reason_codes.dedup();
                if reason_codes.is_empty() {
                    record.consumed = true;
                    (
                        ProviderChallengeUseStatus::Accepted,
                        true,
                        reason_codes,
                        record.nonce_present,
                        record.raw_nonce_stored,
                        record.probe_destinations.len(),
                        record.expires_at_unix_seconds,
                    )
                } else {
                    (
                        ProviderChallengeUseStatus::Rejected,
                        false,
                        reason_codes,
                        record.nonce_present,
                        record.raw_nonce_stored,
                        record.probe_destinations.len(),
                        record.expires_at_unix_seconds,
                    )
                }
            }
            Some(_) => (
                ProviderChallengeUseStatus::Rejected,
                false,
                vec!["challenge_authority_tenant_mismatch".to_string()],
                false,
                false,
                0,
                0,
            ),
            None => (
                ProviderChallengeUseStatus::Rejected,
                false,
                vec!["provider_challenge_not_issued".to_string()],
                false,
                false,
                0,
                0,
            ),
        };
        let status = if accepted {
            ChallengeAuthorityStatus::Ok
        } else {
            ChallengeAuthorityStatus::FailClosed
        };
        let http_status_code = if accepted { 200 } else { 409 };
        let exit_code = if accepted { 0 } else { 20 };
        ChallengeConsumeDecision {
            request_id: request.request_id,
            tenant_id: request.tenant_id,
            status,
            authority: CHALLENGE_AUTHORITY_NAME,
            trusted_time_source: CHALLENGE_AUTHORITY_TRUSTED_TIME_SOURCE,
            client_time_accepted: false,
            ttl_seconds: self.ttl_seconds,
            challenge_id: request.challenge_id,
            consume_status,
            accepted,
            nonce_present,
            raw_nonce_returned: false,
            raw_nonce_stored,
            probe_destination_count,
            expires_at_unix_seconds,
            reason_codes,
            http_status_code,
            exit_code,
        }
    }

    pub fn records(&self) -> Vec<ChallengeAuthorityRecord> {
        self.records.values().cloned().collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeAuthorityFileStore {
    path: PathBuf,
    ttl_seconds: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeAuthorityFileStoreOperationOutcome {
    pub stale_lock_recovered: bool,
}

impl ChallengeAuthorityFileStore {
    pub fn new(path: impl Into<PathBuf>, ttl_seconds: u64) -> Self {
        Self {
            path: path.into(),
            ttl_seconds,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn issue(&self, request: ChallengeIssueRequest) -> std::io::Result<ChallengeIssueDecision> {
        self.issue_with_outcome(request)
            .map(|(decision, _outcome)| decision)
    }

    pub fn issue_with_outcome(
        &self,
        request: ChallengeIssueRequest,
    ) -> std::io::Result<(
        ChallengeIssueDecision,
        ChallengeAuthorityFileStoreOperationOutcome,
    )> {
        let lock = self.acquire_lock(request.now_unix_seconds)?;
        let outcome = lock.outcome();
        let mut authority = self.read_authority_locked()?;
        let decision = authority.issue(request);
        self.write_authority_locked(&authority)?;
        Ok((decision, outcome))
    }

    pub fn consume(
        &self,
        request: ChallengeConsumeRequest,
    ) -> std::io::Result<ChallengeConsumeDecision> {
        self.consume_with_outcome(request)
            .map(|(decision, _outcome)| decision)
    }

    pub fn consume_with_outcome(
        &self,
        request: ChallengeConsumeRequest,
    ) -> std::io::Result<(
        ChallengeConsumeDecision,
        ChallengeAuthorityFileStoreOperationOutcome,
    )> {
        let lock = self.acquire_lock(request.now_unix_seconds)?;
        let outcome = lock.outcome();
        let mut authority = self.read_authority_locked()?;
        let decision = authority.consume(request);
        self.write_authority_locked(&authority)?;
        Ok((decision, outcome))
    }

    pub fn records(&self) -> std::io::Result<Vec<ChallengeAuthorityRecord>> {
        let _lock = self.acquire_lock(current_unix_seconds())?;
        Ok(self.read_authority_locked()?.records())
    }

    fn acquire_lock(&self, now_unix_seconds: u64) -> std::io::Result<ChallengeAuthorityFileLock> {
        ChallengeAuthorityFileLock::acquire(
            challenge_authority_lock_path(&self.path),
            now_unix_seconds,
            self.ttl_seconds.max(1),
        )
    }

    fn read_authority_locked(&self) -> std::io::Result<InMemoryChallengeAuthority> {
        match fs::read_to_string(&self.path) {
            Ok(contents) => challenge_authority_store_decode(&contents),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Ok(InMemoryChallengeAuthority::new(self.ttl_seconds))
            }
            Err(error) => Err(error),
        }
    }

    fn write_authority_locked(
        &self,
        authority: &InMemoryChallengeAuthority,
    ) -> std::io::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp_path = challenge_authority_tmp_path(&self.path);
        let bytes = challenge_authority_store_encode(authority);
        write_private_file_new(&tmp_path, bytes.as_bytes())?;
        fs::rename(&tmp_path, &self.path)?;
        set_private_file_permissions(&self.path)?;
        Ok(())
    }
}

struct ChallengeAuthorityFileLock {
    path: PathBuf,
    stale_lock_recovered: bool,
}

impl ChallengeAuthorityFileLock {
    fn acquire(
        path: PathBuf,
        now_unix_seconds: u64,
        stale_after_seconds: u64,
    ) -> std::io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut stale_lock_recovered = false;
        for _ in 0..50 {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(mut file) => {
                    if let Err(error) =
                        write_challenge_authority_lock_file(&mut file, now_unix_seconds)
                    {
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    if let Err(error) = set_private_file_permissions(&path) {
                        let _ = fs::remove_file(&path);
                        return Err(error);
                    }
                    return Ok(Self {
                        path,
                        stale_lock_recovered,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    if challenge_authority_lock_is_stale(
                        &path,
                        now_unix_seconds,
                        stale_after_seconds,
                    )? {
                        match fs::remove_file(&path) {
                            Ok(()) => {
                                stale_lock_recovered = true;
                                continue;
                            }
                            Err(remove_error)
                                if remove_error.kind() == std::io::ErrorKind::NotFound =>
                            {
                                stale_lock_recovered = true;
                                continue;
                            }
                            Err(remove_error) => return Err(remove_error),
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::WouldBlock,
            "challenge authority store lock busy",
        ))
    }

    fn outcome(&self) -> ChallengeAuthorityFileStoreOperationOutcome {
        ChallengeAuthorityFileStoreOperationOutcome {
            stale_lock_recovered: self.stale_lock_recovered,
        }
    }
}

impl Drop for ChallengeAuthorityFileLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

const CHALLENGE_AUTHORITY_STORE_SCHEMA: &str = "whoathere.vault_challenge_authority_store.v1";
const CHALLENGE_AUTHORITY_LOCK_SCHEMA: &str = "whoathere.vault_challenge_authority_lock.v1";

fn challenge_authority_store_encode(authority: &InMemoryChallengeAuthority) -> String {
    let mut lines = vec![
        CHALLENGE_AUTHORITY_STORE_SCHEMA.to_string(),
        format!("ttl_seconds={}", authority.ttl_seconds),
        format!("next_sequence={}", authority.next_sequence),
    ];
    for record in authority.records() {
        lines.push(format!(
            "record issued_sequence={} tenant_id={} challenge_id={} subject={} context_hash={} configured_vault_host={} probe_destinations={} validation_time_unix_seconds={} expires_at_unix_seconds={} nonce_present={} raw_nonce_stored={} consumed={}",
            record.issued_sequence,
            store_hex_encode(record.tenant_id.as_bytes()),
            store_hex_encode(record.challenge_id.as_bytes()),
            store_hex_encode(record.subject.as_bytes()),
            store_hex_encode(record.context_hash.as_bytes()),
            store_hex_encode(record.configured_vault_host.as_bytes()),
            record
                .probe_destinations
                .iter()
                .map(|probe| store_hex_encode(probe.as_bytes()))
                .collect::<Vec<_>>()
                .join(","),
            record.validation_time_unix_seconds,
            record.expires_at_unix_seconds,
            record.nonce_present,
            record.raw_nonce_stored,
            record.consumed
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn challenge_authority_store_decode(contents: &str) -> std::io::Result<InMemoryChallengeAuthority> {
    let mut lines = contents.lines();
    if lines.next() != Some(CHALLENGE_AUTHORITY_STORE_SCHEMA) {
        return Err(invalid_challenge_authority_store("schema"));
    }
    let ttl_seconds = parse_store_u64(lines.next(), "ttl_seconds")?;
    let next_sequence = parse_store_u64(lines.next(), "next_sequence")?;
    let mut records = Vec::new();
    let mut challenge_ids = BTreeSet::new();
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some(fields) = line.strip_prefix("record ") else {
            return Err(invalid_challenge_authority_store("record_prefix"));
        };
        let record = challenge_authority_record_decode(fields)?;
        if !challenge_ids.insert(record.challenge_id.clone()) {
            return Err(invalid_challenge_authority_store("duplicate_challenge_id"));
        }
        if record.raw_nonce_stored {
            return Err(invalid_challenge_authority_store("raw_nonce_stored"));
        }
        records.push(record);
    }
    Ok(InMemoryChallengeAuthority::restore(
        ttl_seconds,
        next_sequence,
        records,
    ))
}

fn challenge_authority_record_decode(fields: &str) -> std::io::Result<ChallengeAuthorityRecord> {
    let mut map = BTreeMap::new();
    for field in fields.split_whitespace() {
        let Some((key, value)) = field.split_once('=') else {
            return Err(invalid_challenge_authority_store("record_field"));
        };
        if map.insert(key, value).is_some() {
            return Err(invalid_challenge_authority_store("duplicate_field"));
        }
    }
    let probe_destinations = required_store_field(&map, "probe_destinations")?
        .split(',')
        .filter(|encoded| !encoded.is_empty())
        .map(store_hex_decode_string)
        .collect::<std::io::Result<Vec<_>>>()?;
    Ok(ChallengeAuthorityRecord {
        issued_sequence: parse_record_u64(&map, "issued_sequence")?,
        tenant_id: store_hex_decode_string(required_store_field(&map, "tenant_id")?)?,
        challenge_id: store_hex_decode_string(required_store_field(&map, "challenge_id")?)?,
        subject: store_hex_decode_string(required_store_field(&map, "subject")?)?,
        context_hash: store_hex_decode_string(required_store_field(&map, "context_hash")?)?,
        configured_vault_host: store_hex_decode_string(required_store_field(
            &map,
            "configured_vault_host",
        )?)?,
        probe_destinations,
        validation_time_unix_seconds: parse_record_u64(&map, "validation_time_unix_seconds")?,
        expires_at_unix_seconds: parse_record_u64(&map, "expires_at_unix_seconds")?,
        nonce_present: parse_record_bool(&map, "nonce_present")?,
        raw_nonce_stored: parse_record_bool(&map, "raw_nonce_stored")?,
        consumed: parse_record_bool(&map, "consumed")?,
    })
}

fn parse_store_u64(line: Option<&str>, key: &str) -> std::io::Result<u64> {
    let Some(line) = line else {
        return Err(invalid_challenge_authority_store(key));
    };
    let Some(value) = line.strip_prefix(&format!("{key}=")) else {
        return Err(invalid_challenge_authority_store(key));
    };
    value
        .parse::<u64>()
        .map_err(|_| invalid_challenge_authority_store(key))
}

fn required_store_field<'a>(map: &'a BTreeMap<&str, &str>, key: &str) -> std::io::Result<&'a str> {
    map.get(key)
        .copied()
        .ok_or_else(|| invalid_challenge_authority_store(key))
}

fn parse_record_u64(map: &BTreeMap<&str, &str>, key: &str) -> std::io::Result<u64> {
    required_store_field(map, key)?
        .parse::<u64>()
        .map_err(|_| invalid_challenge_authority_store(key))
}

fn parse_record_bool(map: &BTreeMap<&str, &str>, key: &str) -> std::io::Result<bool> {
    match required_store_field(map, key)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(invalid_challenge_authority_store(key)),
    }
}

fn invalid_challenge_authority_store(field: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("invalid challenge authority store: {field}"),
    )
}

fn write_challenge_authority_lock_file(
    file: &mut std::fs::File,
    now_unix_seconds: u64,
) -> std::io::Result<()> {
    use std::io::Write;

    writeln!(file, "{CHALLENGE_AUTHORITY_LOCK_SCHEMA}")?;
    writeln!(file, "created_at_unix_seconds={now_unix_seconds}")?;
    writeln!(file, "pid={}", std::process::id())?;
    file.flush()
}

fn challenge_authority_lock_is_stale(
    path: &Path,
    now_unix_seconds: u64,
    stale_after_seconds: u64,
) -> std::io::Result<bool> {
    match fs::read_to_string(path) {
        Ok(contents) => match challenge_authority_lock_created_at(&contents) {
            Some(created_at) => {
                Ok(now_unix_seconds.saturating_sub(created_at) > stale_after_seconds)
            }
            None => challenge_authority_lock_metadata_is_stale(path, stale_after_seconds),
        },
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn challenge_authority_lock_metadata_is_stale(
    path: &Path,
    stale_after_seconds: u64,
) -> std::io::Result<bool> {
    let modified = fs::metadata(path)?.modified()?;
    match std::time::SystemTime::now().duration_since(modified) {
        Ok(age) => Ok(age.as_secs() > stale_after_seconds),
        Err(_) => Ok(false),
    }
}

fn challenge_authority_lock_created_at(contents: &str) -> Option<u64> {
    let mut lines = contents.lines();
    if lines.next()? != CHALLENGE_AUTHORITY_LOCK_SCHEMA {
        return None;
    }
    for line in lines {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key == "created_at_unix_seconds" {
            return value.parse::<u64>().ok();
        }
    }
    None
}

fn challenge_authority_lock_path(path: &Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_os_string();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn challenge_authority_tmp_path(path: &Path) -> PathBuf {
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(
        ".tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    PathBuf::from(tmp_path)
}

fn current_unix_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn write_private_file_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    set_private_file_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    fs::set_permissions(path, permissions)
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

fn store_hex_encode(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(store_hex_digit(byte >> 4));
        encoded.push(store_hex_digit(byte & 0x0f));
    }
    encoded
}

fn store_hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("nibble is always 0..=15"),
    }
}

fn store_hex_decode_string(value: &str) -> std::io::Result<String> {
    let bytes = store_hex_decode(value)?;
    String::from_utf8(bytes).map_err(|_| invalid_challenge_authority_store("utf8"))
}

fn store_hex_decode(value: &str) -> std::io::Result<Vec<u8>> {
    let bytes = value.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid_challenge_authority_store("hex_length"));
    }
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let high = store_hex_value(chunk[0])?;
        let low = store_hex_value(chunk[1])?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn store_hex_value(value: u8) -> std::io::Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(invalid_challenge_authority_store("hex")),
    }
}

impl ChallengeAuthorityDecision {
    pub fn first_consume_status_label(&self) -> &'static str {
        challenge_use_status_label(self.first_consume_status)
    }

    pub fn replay_consume_status_label(&self) -> Option<&'static str> {
        self.replay_consume_status.map(challenge_use_status_label)
    }
}

pub fn plan_challenge_authority(request: ChallengeAuthorityRequest) -> ChallengeAuthorityDecision {
    let mut guard = ProviderChallengeReplayGuard::new(request.ttl_seconds);
    let issued = guard.issue(
        ProofSubject::for_launch(&request.subject),
        request.context_hash.clone(),
        request.configured_vault_host.clone(),
        request.now_unix_seconds,
    );
    let submitted = submitted_challenge_for_scenario(&request, &issued);
    let consume_at = if request.scenario.expired {
        issued.expires_at_unix_seconds
    } else {
        request.now_unix_seconds
    };
    let first_decision = guard.consume(&submitted, consume_at);
    let replay_decision = request
        .scenario
        .replay
        .then(|| guard.consume(&submitted, consume_at));
    let final_accepted = replay_decision
        .as_ref()
        .unwrap_or(&first_decision)
        .accepted();
    let status = if final_accepted {
        ChallengeAuthorityStatus::Ok
    } else {
        ChallengeAuthorityStatus::FailClosed
    };
    let http_status_code = if final_accepted { 200 } else { 409 };
    let exit_code = if final_accepted { 0 } else { 20 };
    let reason_codes = replay_decision
        .as_ref()
        .unwrap_or(&first_decision)
        .reason_codes
        .clone();
    let replay_reason_codes = replay_decision
        .as_ref()
        .map(|decision| decision.reason_codes.clone())
        .unwrap_or_default();

    ChallengeAuthorityDecision {
        request_id: request.request_id,
        tenant_id: request.tenant_id,
        status,
        authority: CHALLENGE_AUTHORITY_NAME,
        authorization: false,
        proof_minted: false,
        execution_allowed: false,
        trusted_time_source: CHALLENGE_AUTHORITY_TRUSTED_TIME_SOURCE,
        client_time_accepted: false,
        ttl_seconds: request.ttl_seconds,
        issued_challenge_id: issued.challenge_id,
        submitted_challenge_id: submitted.challenge_id,
        nonce_present: !issued.challenge_nonce.is_empty(),
        raw_nonce_returned: false,
        probe_destination_count: issued.probe_destinations.len(),
        expires_at_unix_seconds: issued.expires_at_unix_seconds,
        scenario: request.scenario,
        first_consume_status: first_decision.status,
        replay_consume_status: replay_decision.as_ref().map(|decision| decision.status),
        accepted: final_accepted,
        reason_codes,
        replay_reason_codes,
        http_status_code,
        exit_code,
    }
}

fn submitted_challenge_for_scenario(
    request: &ChallengeAuthorityRequest,
    issued: &ProviderVerificationChallenge,
) -> ProviderVerificationChallenge {
    if request.scenario.unknown_challenge {
        ProviderVerificationChallenge::new_with_nonce(
            ProofSubject::for_launch(&request.subject),
            request.context_hash.clone(),
            request.configured_vault_host.clone(),
            request.now_unix_seconds,
            "proof-nonce-vault-authority-unknown",
            request.now_unix_seconds.saturating_add(request.ttl_seconds),
        )
    } else if request.scenario.mutate_context {
        let mut challenge = issued.clone();
        challenge.context_hash = format!("{}-mutated", challenge.context_hash);
        challenge
    } else {
        issued.clone()
    }
}

fn challenge_use_status_label(status: ProviderChallengeUseStatus) -> &'static str {
    match status {
        ProviderChallengeUseStatus::Accepted => "Accepted",
        ProviderChallengeUseStatus::Rejected => "Rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use whoathere_evidence::minimum_profiles;

    const ABC_DIGEST: &str =
        "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const ABC_OBJECT_KEY: &str =
        "blobs/sha256/ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const DEF_DIGEST: &str =
        "sha256:cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34";
    const DEF_OBJECT_KEY: &str =
        "blobs/sha256/cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34";

    #[test]
    fn cache_key_is_content_addressed() {
        let artifact = ArtifactRef {
            ecosystem: "npm".to_string(),
            name: "left-pad".to_string(),
            version: "1.0.0".to_string(),
            digest: ABC_DIGEST.to_string(),
            source: "registry".to_string(),
        };
        assert_eq!(
            artifact.cache_key(),
            format!("npm/left-pad/1.0.0/{ABC_DIGEST}")
        );
        assert_eq!(artifact.cache_object_key().unwrap(), ABC_OBJECT_KEY);
    }

    #[test]
    fn cache_object_key_rejects_unsafe_or_unsupported_digest() {
        assert_eq!(
            cache_object_key_for_digest(
                "md5:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
            )
            .unwrap_err(),
            CacheKeyError::UnsupportedAlgorithm
        );
        assert_eq!(
            cache_object_key_for_digest("sha256:../abc").unwrap_err(),
            CacheKeyError::UnsafeDigest
        );
        assert_eq!(
            cache_object_key_for_digest("sha256").unwrap_err(),
            CacheKeyError::MissingSeparator
        );
        assert_eq!(
            cache_object_key_for_digest("sha256:abc").unwrap_err(),
            CacheKeyError::InvalidDigestLength
        );
        assert_eq!(
            cache_object_key_for_digest(
                "sha256:BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
            )
            .unwrap_err(),
            CacheKeyError::NonCanonicalDigest
        );
    }

    #[test]
    fn fetch_job_plan_validates_metadata_without_enabling_fetch() {
        let plan = plan_fetch_job(sample_fetch_request(
            ABC_DIGEST,
            ABC_DIGEST,
            1024,
            "https://registry.example/fixture.tgz",
        ));
        assert_eq!(plan.state, FetchJobState::Planned);
        assert!(!plan.fetch_enabled);
        assert_eq!(plan.cache_object_key, Some(ABC_OBJECT_KEY.to_string()));
        assert_eq!(plan.reason_codes, vec!["fetch_execution_not_enabled"]);
    }

    #[test]
    fn fetch_job_plan_rejects_digest_mismatch() {
        let plan = plan_fetch_job(sample_fetch_request(
            ABC_DIGEST,
            DEF_DIGEST,
            1024,
            "https://registry.example/fixture.tgz",
        ));
        assert_eq!(plan.state, FetchJobState::Rejected);
        assert!(plan
            .reason_codes
            .contains(&"fetch_expected_digest_mismatch".to_string()));
    }

    #[test]
    fn fetch_job_plan_rejects_unsafe_digest() {
        let plan = plan_fetch_job(sample_fetch_request(
            "sha256:../escape",
            "sha256:../escape",
            1024,
            "https://registry.example/fixture.tgz",
        ));
        assert_eq!(plan.state, FetchJobState::Rejected);
        assert!(plan.cache_object_key.is_none());
        assert!(plan
            .reason_codes
            .contains(&"artifact_digest_contains_unsafe_characters".to_string()));
    }

    #[test]
    fn fetch_job_plan_rejects_zero_limit_or_non_https_source() {
        let plan = plan_fetch_job(sample_fetch_request(
            ABC_DIGEST,
            ABC_DIGEST,
            0,
            "http://registry.example/fixture.tgz",
        ));
        assert_eq!(plan.state, FetchJobState::Rejected);
        assert!(plan
            .reason_codes
            .contains(&"fetch_byte_limit_zero".to_string()));
        assert!(plan
            .reason_codes
            .contains(&"fetch_source_url_not_https".to_string()));
    }

    #[test]
    fn fetch_result_binding_accepts_matching_quarantine_result() {
        let plan = plan_fetch_job(sample_fetch_request(
            ABC_DIGEST,
            ABC_DIGEST,
            1024,
            "https://registry.example/fixture.tgz",
        ));
        let binding = bind_fetch_job_result(&plan, sample_fetch_result(&plan, 3));
        assert_eq!(binding.state, FetchResultState::Verified);
        assert!(binding.admission_ready);
        assert_eq!(binding.cache_object_key, Some(ABC_OBJECT_KEY.to_string()));
        assert!(binding.reason_codes.is_empty());
    }

    #[test]
    fn fetch_result_binding_rejects_digest_and_cache_mismatch() {
        let plan = plan_fetch_job(sample_fetch_request(
            ABC_DIGEST,
            ABC_DIGEST,
            1024,
            "https://registry.example/fixture.tgz",
        ));
        let mut result = sample_fetch_result(&plan, 3);
        result.verified_digest = DEF_DIGEST.to_string();
        result.cache_object_key = DEF_OBJECT_KEY.to_string();
        let binding = bind_fetch_job_result(&plan, result);
        assert_eq!(binding.state, FetchResultState::Rejected);
        assert!(!binding.admission_ready);
        assert!(binding
            .reason_codes
            .contains(&"fetch_result_verified_digest_mismatch".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"fetch_result_cache_key_mismatch".to_string()));
    }

    #[test]
    fn fetch_result_binding_rejects_unquarantined_or_oversized_result() {
        let plan = plan_fetch_job(sample_fetch_request(
            ABC_DIGEST,
            ABC_DIGEST,
            2,
            "https://registry.example/fixture.tgz",
        ));
        let mut result = sample_fetch_result(&plan, 3);
        result.stored_in_quarantine = false;
        let binding = bind_fetch_job_result(&plan, result);
        assert_eq!(binding.state, FetchResultState::Rejected);
        assert!(binding
            .reason_codes
            .contains(&"fetch_result_not_quarantined".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"fetch_result_byte_limit_exceeded".to_string()));
    }

    #[test]
    fn evidence_job_plan_validates_metadata_without_enabling_execution() {
        let profile = sample_profile();
        let plan = plan_evidence_job(sample_evidence_job_request(&profile), &profile);
        assert_eq!(plan.state, EvidenceJobPlanState::Planned);
        assert!(!plan.execution_enabled);
        assert!(!plan.detonation_attempted);
        assert!(!plan.network_attempted);
        assert_eq!(plan.cache_object_key, Some(ABC_OBJECT_KEY.to_string()));
        assert_eq!(
            plan.reason_codes,
            vec!["evidence_job_execution_not_enabled"]
        );
    }

    #[test]
    fn evidence_job_result_binding_accepts_matching_metadata_only_result() {
        let profile = sample_profile();
        let plan = plan_evidence_job(sample_evidence_job_request(&profile), &profile);
        let binding = bind_evidence_job_result(&plan, sample_evidence_job_result(&plan));
        assert_eq!(binding.state, EvidenceJobResultState::Bound);
        assert!(binding.admission_ready);
        assert!(binding.reason_codes.is_empty());
        assert_eq!(binding.cache_object_key, Some(ABC_OBJECT_KEY.to_string()));
        assert_eq!(
            binding.evidence_binding().cache_object_key,
            ABC_OBJECT_KEY.to_string()
        );
    }

    #[test]
    fn evidence_job_result_binding_rejects_mismatched_or_invalid_metadata() {
        let profile = sample_profile();
        let plan = plan_evidence_job(sample_evidence_job_request(&profile), &profile);
        let mut result = sample_evidence_job_result(&plan);
        result.job_id = "job-other".to_string();
        result.cache_object_key = DEF_OBJECT_KEY.to_string();
        result.log_digest = "sha256:not-canonical".to_string();
        let binding = bind_evidence_job_result(&plan, result);
        assert_eq!(binding.state, EvidenceJobResultState::Rejected);
        assert!(!binding.admission_ready);
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_job_mismatch".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_cache_key_mismatch".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_log_digest_invalid".to_string()));
    }

    #[test]
    fn evidence_job_result_binding_rejects_execution_detonation_or_network_attempts() {
        let profile = sample_profile();
        let plan = plan_evidence_job(sample_evidence_job_request(&profile), &profile);
        let mut result = sample_evidence_job_result(&plan);
        result.execution_enabled = true;
        result.detonation_attempted = true;
        result.network_attempted = true;
        let binding = bind_evidence_job_result(&plan, result);
        assert_eq!(binding.state, EvidenceJobResultState::Rejected);
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_execution_enabled_mismatch".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_execution_attempted".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_detonation_attempted".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_network_attempted".to_string()));
    }

    #[test]
    fn evidence_job_result_binding_rejects_non_passed_job_state() {
        let profile = sample_profile();
        let plan = plan_evidence_job(sample_evidence_job_request(&profile), &profile);
        let mut result = sample_evidence_job_result(&plan);
        result.state = JobState::Failed;
        let binding = bind_evidence_job_result(&plan, result);
        assert_eq!(binding.state, EvidenceJobResultState::Rejected);
        assert!(binding
            .reason_codes
            .contains(&"evidence_job_result_not_passed".to_string()));
    }

    #[test]
    fn dynamic_behavior_plan_requires_fixture_mode_without_enabling_arbitrary_execution() {
        let profile = sample_profile();
        let plan = plan_dynamic_behavior_job(sample_dynamic_behavior_request(&profile), &profile);
        assert_eq!(plan.state, DynamicBehaviorPlanState::Planned);
        assert!(!plan.execution_enabled);
        assert!(!plan.arbitrary_execution_enabled);
        assert!(plan.fixture_mode);
        assert!(!plan.network_attempted);
        assert_eq!(plan.cache_object_key, Some(ABC_OBJECT_KEY.to_string()));
        assert_eq!(
            plan.reason_codes,
            vec!["dynamic_behavior_arbitrary_execution_disabled"]
        );

        let mut arbitrary = sample_dynamic_behavior_request(&profile);
        arbitrary.fixture_mode = false;
        let rejected = plan_dynamic_behavior_job(arbitrary, &profile);
        assert_eq!(rejected.state, DynamicBehaviorPlanState::Rejected);
        assert!(rejected
            .reason_codes
            .contains(&"dynamic_behavior_fixture_mode_required".to_string()));
    }

    #[test]
    fn dynamic_behavior_binding_accepts_clean_fixture_result() {
        let profile = sample_profile();
        let plan = plan_dynamic_behavior_job(sample_dynamic_behavior_request(&profile), &profile);
        let binding = bind_dynamic_behavior_result(&plan, sample_dynamic_behavior_result(&plan));
        assert_eq!(binding.state, DynamicBehaviorResultState::Bound);
        assert!(binding.admission_ready);
        assert!(binding.reason_codes.is_empty());
        assert_eq!(binding.job_kind, EvidenceJobKind::LifecycleDetonation);
        assert_eq!(binding.cache_object_key, Some(ABC_OBJECT_KEY.to_string()));
        assert_eq!(
            binding.evidence_binding().cache_object_key,
            ABC_OBJECT_KEY.to_string()
        );
        assert_eq!(binding.evidence_job_result().state, JobState::Passed);
    }

    #[test]
    fn dynamic_behavior_binding_rejects_identity_proof_stale_and_runner_mismatches() {
        let profile = sample_profile();
        let plan = plan_dynamic_behavior_job(sample_dynamic_behavior_request(&profile), &profile);
        let mut result = sample_dynamic_behavior_result(&plan);
        result.tenant_id = "tenant-other".to_string();
        result.artifact.digest = DEF_DIGEST.to_string();
        result.cache_object_key = DEF_OBJECT_KEY.to_string();
        result.runner_session_id = "runner-session-other".to_string();
        result.isolation_proof_id = "isolation-proof-other".to_string();
        result.egress_proof_id = "egress-proof-other".to_string();
        result.configured_vault_host = "vault.other:4873".to_string();
        result.observed_at_unix_seconds = plan.expires_at_unix_seconds + 1;
        let binding = bind_dynamic_behavior_result(&plan, result);
        assert_eq!(binding.state, DynamicBehaviorResultState::Rejected);
        for reason in [
            "dynamic_behavior_result_tenant_mismatch",
            "dynamic_behavior_result_artifact_mismatch",
            "dynamic_behavior_result_cache_key_mismatch",
            "dynamic_behavior_result_runner_session_mismatch",
            "dynamic_behavior_result_isolation_proof_mismatch",
            "dynamic_behavior_result_egress_proof_mismatch",
            "dynamic_behavior_result_vault_host_mismatch",
            "dynamic_behavior_result_stale_or_not_yet_valid",
        ] {
            assert!(
                binding.reason_codes.contains(&reason.to_string()),
                "{reason}"
            );
        }
        assert!(!binding.admission_ready);
    }

    #[test]
    fn dynamic_behavior_binding_rejects_high_risk_or_overpermissive_results() {
        let profile = sample_profile();
        let plan = plan_dynamic_behavior_job(sample_dynamic_behavior_request(&profile), &profile);
        let mut result = sample_dynamic_behavior_result(&plan);
        result.job_state = JobState::Failed;
        result.signal_summary.network_attempt_count = 1;
        result.signal_summary.dns_attempt_count = 1;
        result.signal_summary.credential_access_count = 1;
        result.signal_summary.delayed_execution_detected = true;
        result.signal_summary.native_extension_detected = true;
        result.signal_summary.platform_specific_detected = true;
        result.signal_summary.direct_source_detected = true;
        result.network_attempted = true;
        result.isolation_verified = false;
        result.egress_vault_only_verified = false;
        result.raw_log_captured = true;
        result.raw_env_captured = true;
        result.raw_network_payload_captured = true;
        result.raw_package_bytes_captured = true;
        result.local_paths_captured = true;
        let binding = bind_dynamic_behavior_result(&plan, result);
        assert_eq!(binding.state, DynamicBehaviorResultState::Rejected);
        for reason in [
            "dynamic_behavior_result_not_passed",
            "dynamic_behavior_high_risk_signal_detected",
            "dynamic_behavior_network_attempted",
            "dynamic_behavior_isolation_not_verified",
            "dynamic_behavior_egress_not_verified",
            "dynamic_behavior_raw_or_local_material_captured",
        ] {
            assert!(
                binding.reason_codes.contains(&reason.to_string()),
                "{reason}"
            );
        }
    }

    #[test]
    fn dynamic_behavior_binding_sanitizes_untrusted_result_metadata() {
        let profile = sample_profile();
        let plan = plan_dynamic_behavior_job(sample_dynamic_behavior_request(&profile), &profile);
        let mut result = sample_dynamic_behavior_result(&plan);
        result.signal_summary.trigger_kind =
            "/Users/jdc/.npmrc?token=WHOATHERE_CANARY_TOKEN".to_string();
        result.reason_codes = vec![
            "dynamic_behavior_fixture_notice".to_string(),
            "secret=https://exfil.invalid/WHOATHERE_CANARY_TOKEN".to_string(),
        ];

        let binding = bind_dynamic_behavior_result(&plan, result);

        assert_eq!(binding.state, DynamicBehaviorResultState::Rejected);
        assert_eq!(
            binding.signal_summary.trigger_kind,
            "<invalid-signal-metadata>"
        );
        assert!(binding
            .reason_codes
            .contains(&"dynamic_behavior_fixture_notice".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"dynamic_behavior_result_reason_code_invalid".to_string()));
        assert!(binding
            .reason_codes
            .contains(&"dynamic_behavior_signal_metadata_control_character".to_string()));
        assert!(!binding
            .reason_codes
            .iter()
            .any(|reason| reason.contains("WHOATHERE_CANARY_TOKEN")
                || reason.contains("exfil.invalid")
                || reason.contains("/Users/")));
    }

    #[test]
    fn admin_workflow_contracts_are_typed_and_audit_safe() {
        let allow = plan_admin_workflow_action(sample_admin_workflow_request(
            AdminWorkflowAction::AllowAfterReview,
            false,
        ));
        assert_eq!(allow.state, AdminWorkflowDecisionState::Accepted);
        assert_eq!(allow.decision, Verdict::Allow);
        assert!(allow.audit_event_id.starts_with("audit-admin-"));
        assert!(!allow.raw_reason_logged);
        assert!(!allow.raw_operator_token_logged);
        assert!(!allow.requires_second_approval);

        let break_glass = plan_admin_workflow_action(sample_admin_workflow_request(
            AdminWorkflowAction::BreakGlass,
            true,
        ));
        assert_eq!(break_glass.state, AdminWorkflowDecisionState::Accepted);
        assert_eq!(break_glass.decision, Verdict::Allow);
        assert!(break_glass.requires_second_approval);

        let missing_confirmation = plan_admin_workflow_action(sample_admin_workflow_request(
            AdminWorkflowAction::BreakGlass,
            false,
        ));
        assert_eq!(
            missing_confirmation.state,
            AdminWorkflowDecisionState::Rejected
        );
        assert_eq!(missing_confirmation.decision, Verdict::Deny);
        assert!(missing_confirmation
            .reason_codes
            .contains(&"admin_workflow_break_glass_confirmation_required".to_string()));
    }

    #[test]
    fn challenge_authority_accepts_first_consume_without_returning_nonce() {
        let decision =
            plan_challenge_authority(sample_challenge_authority_request(Default::default()));
        assert_eq!(decision.status, ChallengeAuthorityStatus::Ok);
        assert_eq!(decision.status.label(), "ok");
        assert_eq!(decision.http_status_code, 200);
        assert_eq!(decision.exit_code, 0);
        assert_eq!(decision.authority, CHALLENGE_AUTHORITY_NAME);
        assert_eq!(
            decision.trusted_time_source,
            CHALLENGE_AUTHORITY_TRUSTED_TIME_SOURCE
        );
        assert!(!decision.authorization);
        assert!(!decision.proof_minted);
        assert!(!decision.execution_allowed);
        assert!(!decision.client_time_accepted);
        assert!(decision.nonce_present);
        assert!(!decision.raw_nonce_returned);
        assert_eq!(
            decision.first_consume_status,
            ProviderChallengeUseStatus::Accepted
        );
        assert_eq!(decision.first_consume_status_label(), "Accepted");
        assert_eq!(decision.replay_consume_status, None);
        assert!(decision.accepted);
        assert!(decision.reason_codes.is_empty());
        assert!(!format!("{decision:?}").contains("proof-nonce-"));
    }

    #[test]
    fn challenge_authority_fails_closed_for_replay_unknown_tamper_and_expiry() {
        for (scenario, reason) in [
            (
                ChallengeAuthorityScenario {
                    replay: true,
                    ..Default::default()
                },
                "provider_challenge_replayed",
            ),
            (
                ChallengeAuthorityScenario {
                    unknown_challenge: true,
                    ..Default::default()
                },
                "provider_challenge_not_issued",
            ),
            (
                ChallengeAuthorityScenario {
                    mutate_context: true,
                    ..Default::default()
                },
                "provider_challenge_context_mutated",
            ),
            (
                ChallengeAuthorityScenario {
                    expired: true,
                    ..Default::default()
                },
                "provider_challenge_expired",
            ),
        ] {
            let decision = plan_challenge_authority(sample_challenge_authority_request(scenario));
            assert_eq!(decision.status, ChallengeAuthorityStatus::FailClosed);
            assert_eq!(decision.status.label(), "fail_closed");
            assert_eq!(decision.http_status_code, 409);
            assert_eq!(decision.exit_code, 20);
            assert!(!decision.accepted);
            assert!(decision.reason_codes.contains(&reason.to_string()));
            assert!(!format!("{decision:?}").contains("proof-nonce-"));
        }
    }

    #[test]
    fn in_memory_challenge_authority_issues_sanitized_challenge_and_consumes_once() {
        let mut authority = InMemoryChallengeAuthority::new(60);
        let issue = authority.issue(sample_challenge_issue_request("tenant-1", 100));
        assert_eq!(issue.status, ChallengeAuthorityStatus::Ok);
        assert_eq!(issue.http_status_code, 200);
        assert_eq!(issue.exit_code, 0);
        assert_eq!(issue.authority, CHALLENGE_AUTHORITY_NAME);
        assert_eq!(
            issue.trusted_time_source,
            CHALLENGE_AUTHORITY_TRUSTED_TIME_SOURCE
        );
        assert!(!issue.client_time_accepted);
        assert!(issue.nonce_present);
        assert!(!issue.raw_nonce_returned);
        assert!(issue.reason_codes.is_empty());
        assert!(!format!("{issue:?}").contains("proof-nonce-"));
        let records = authority.records();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].challenge_id, issue.challenge_id);
        assert!(records[0].nonce_present);
        assert!(!records[0].raw_nonce_stored);
        assert!(!records[0].consumed);
        assert!(!format!("{records:?}").contains("proof-nonce-"));

        let accepted = authority.consume(sample_challenge_consume_request(
            "tenant-1",
            &issue.challenge_id,
            100,
        ));
        assert_eq!(accepted.status, ChallengeAuthorityStatus::Ok);
        assert_eq!(
            accepted.consume_status,
            ProviderChallengeUseStatus::Accepted
        );
        assert_eq!(
            accepted.trusted_time_source,
            CHALLENGE_AUTHORITY_TRUSTED_TIME_SOURCE
        );
        assert!(!accepted.client_time_accepted);
        assert_eq!(accepted.ttl_seconds, 60);
        assert!(accepted.nonce_present);
        assert!(!accepted.raw_nonce_returned);
        assert!(!accepted.raw_nonce_stored);
        assert!(accepted.probe_destination_count > 0);
        assert_eq!(
            accepted.expires_at_unix_seconds,
            issue.expires_at_unix_seconds
        );
        assert_eq!(accepted.consume_status_label(), "Accepted");
        assert!(accepted.accepted);
        assert!(accepted.reason_codes.is_empty());
        let consumed_records = authority.records();
        assert!(consumed_records[0].consumed);

        let replay = authority.consume(sample_challenge_consume_request(
            "tenant-1",
            &issue.challenge_id,
            100,
        ));
        assert_eq!(replay.status, ChallengeAuthorityStatus::FailClosed);
        assert_eq!(replay.http_status_code, 409);
        assert_eq!(replay.exit_code, 20);
        assert_eq!(replay.consume_status, ProviderChallengeUseStatus::Rejected);
        assert!(replay.nonce_present);
        assert!(!replay.raw_nonce_returned);
        assert!(!replay.raw_nonce_stored);
        assert_eq!(
            replay.probe_destination_count,
            issue.probe_destination_count
        );
        assert!(replay
            .reason_codes
            .contains(&"provider_challenge_replayed".to_string()));
        assert!(!format!("{replay:?}").contains("proof-nonce-"));
    }

    #[test]
    fn in_memory_challenge_authority_rejects_unknown_tenant_mismatch_and_expiry() {
        let mut authority = InMemoryChallengeAuthority::new(60);
        let unknown = authority.consume(sample_challenge_consume_request(
            "tenant-1",
            "proof-challenge-sha256:unknown",
            100,
        ));
        assert_eq!(unknown.status, ChallengeAuthorityStatus::FailClosed);
        assert!(!unknown.nonce_present);
        assert_eq!(unknown.probe_destination_count, 0);
        assert_eq!(unknown.expires_at_unix_seconds, 0);
        assert!(unknown
            .reason_codes
            .contains(&"provider_challenge_not_issued".to_string()));

        let issue = authority.issue(sample_challenge_issue_request("tenant-1", 100));
        let tenant_mismatch = authority.consume(sample_challenge_consume_request(
            "tenant-2",
            &issue.challenge_id,
            100,
        ));
        assert_eq!(tenant_mismatch.status, ChallengeAuthorityStatus::FailClosed);
        assert!(!tenant_mismatch.nonce_present);
        assert_eq!(tenant_mismatch.probe_destination_count, 0);
        assert_eq!(tenant_mismatch.expires_at_unix_seconds, 0);
        assert!(tenant_mismatch
            .reason_codes
            .contains(&"challenge_authority_tenant_mismatch".to_string()));

        let expired_issue = authority.issue(sample_challenge_issue_request("tenant-1", 200));
        let expired = authority.consume(sample_challenge_consume_request(
            "tenant-1",
            &expired_issue.challenge_id,
            260,
        ));
        assert_eq!(expired.status, ChallengeAuthorityStatus::FailClosed);
        assert!(expired
            .reason_codes
            .contains(&"provider_challenge_expired".to_string()));
    }

    #[test]
    fn in_memory_challenge_authority_requires_submitted_metadata_to_match_record() {
        let mut authority = InMemoryChallengeAuthority::new(60);
        let issue = authority.issue(sample_challenge_issue_request("tenant-1", 100));
        let mut mismatched = sample_challenge_consume_request("tenant-1", &issue.challenge_id, 100);
        mismatched.submitted_subject = "other-launch".to_string();
        mismatched.submitted_context_hash =
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_string();
        mismatched.submitted_configured_vault_host = "vault.other:4873".to_string();

        let rejected = authority.consume(mismatched);
        assert_eq!(rejected.status, ChallengeAuthorityStatus::FailClosed);
        assert!(!rejected.accepted);
        assert!(rejected
            .reason_codes
            .contains(&"challenge_authority_subject_mismatch".to_string()));
        assert!(rejected
            .reason_codes
            .contains(&"challenge_authority_context_hash_mismatch".to_string()));
        assert!(rejected
            .reason_codes
            .contains(&"challenge_authority_configured_vault_host_mismatch".to_string()));
        assert!(!authority.records()[0].consumed);

        let accepted = authority.consume(sample_challenge_consume_request(
            "tenant-1",
            &issue.challenge_id,
            100,
        ));
        assert_eq!(accepted.status, ChallengeAuthorityStatus::Ok);
        assert!(accepted.accepted);
    }

    #[test]
    fn challenge_authority_file_store_persists_single_use_without_raw_nonce() {
        let path = unique_test_path("challenge-authority-file-store-persist");
        let store = ChallengeAuthorityFileStore::new(&path, 60);
        let issue = store
            .issue(sample_challenge_issue_request("tenant-file-1", 100))
            .expect("issue persists");
        assert_eq!(issue.status, ChallengeAuthorityStatus::Ok);
        let persisted = std::fs::read_to_string(&path).expect("store contents");
        assert!(persisted.contains(CHALLENGE_AUTHORITY_STORE_SCHEMA));
        assert!(persisted.contains("raw_nonce_stored=false"));
        assert!(!persisted.contains("proof-nonce-"));

        let records = ChallengeAuthorityFileStore::new(&path, 60)
            .records()
            .expect("records reload");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].challenge_id, issue.challenge_id);
        assert!(records[0].nonce_present);
        assert!(!records[0].raw_nonce_stored);
        assert!(!records[0].consumed);

        let accepted = ChallengeAuthorityFileStore::new(&path, 60)
            .consume(sample_challenge_consume_request(
                "tenant-file-1",
                &issue.challenge_id,
                100,
            ))
            .expect("consume persists");
        assert_eq!(accepted.status, ChallengeAuthorityStatus::Ok);
        assert!(accepted.accepted);
        assert!(accepted.nonce_present);
        assert!(!accepted.raw_nonce_stored);

        let replay = ChallengeAuthorityFileStore::new(&path, 60)
            .consume(sample_challenge_consume_request(
                "tenant-file-1",
                &issue.challenge_id,
                100,
            ))
            .expect("replay persists");
        assert_eq!(replay.status, ChallengeAuthorityStatus::FailClosed);
        assert!(replay
            .reason_codes
            .contains(&"provider_challenge_replayed".to_string()));
        let consumed_records = ChallengeAuthorityFileStore::new(&path, 60)
            .records()
            .expect("consumed records reload");
        assert!(consumed_records[0].consumed);
        assert!(!challenge_authority_lock_path(&path).exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn challenge_authority_file_store_rejects_metadata_mismatch_without_consuming() {
        let path = unique_test_path("challenge-authority-file-store-metadata-mismatch");
        let issue = ChallengeAuthorityFileStore::new(&path, 60)
            .issue(sample_challenge_issue_request("tenant-file-mismatch", 100))
            .expect("issue persists");
        let mut mismatched =
            sample_challenge_consume_request("tenant-file-mismatch", &issue.challenge_id, 100);
        mismatched.submitted_context_hash =
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_string();

        let rejected = ChallengeAuthorityFileStore::new(&path, 60)
            .consume(mismatched)
            .expect("mismatch fails closed");
        assert_eq!(rejected.status, ChallengeAuthorityStatus::FailClosed);
        assert!(rejected
            .reason_codes
            .contains(&"challenge_authority_context_hash_mismatch".to_string()));
        let records = ChallengeAuthorityFileStore::new(&path, 60)
            .records()
            .expect("records");
        assert!(!records[0].consumed);

        let accepted = ChallengeAuthorityFileStore::new(&path, 60)
            .consume(sample_challenge_consume_request(
                "tenant-file-mismatch",
                &issue.challenge_id,
                100,
            ))
            .expect("matching consume succeeds");
        assert!(accepted.accepted);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn challenge_authority_file_store_rejects_corrupt_state_without_mutation() {
        let path = unique_test_path("challenge-authority-file-store-corrupt");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("create dir");
        std::fs::write(&path, "not-a-store\n").expect("write corrupt store");
        let before = std::fs::read_to_string(&path).expect("before");
        let error = ChallengeAuthorityFileStore::new(&path, 60)
            .issue(sample_challenge_issue_request("tenant-file-corrupt", 100))
            .expect_err("corrupt store fails closed");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let after = std::fs::read_to_string(&path).expect("after");
        assert_eq!(after, before);
        assert!(!challenge_authority_lock_path(&path).exists());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn challenge_authority_file_store_rejects_raw_nonce_and_duplicate_ids() {
        let mut authority = InMemoryChallengeAuthority::new(60);
        let issue = authority.issue(sample_challenge_issue_request("tenant-file-tamper", 100));
        let mut encoded = challenge_authority_store_encode(&authority);
        encoded = encoded.replace("raw_nonce_stored=false", "raw_nonce_stored=true");
        assert_eq!(
            challenge_authority_store_decode(&encoded)
                .expect_err("raw nonce marker rejected")
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        let encoded_once = challenge_authority_store_encode(&authority);
        let record_line = encoded_once
            .lines()
            .find(|line| line.starts_with("record "))
            .expect("record line");
        let duplicated_encoded = format!("{}\n{}\n", encoded_once.trim_end(), record_line);
        assert!(duplicated_encoded.contains(&store_hex_encode(issue.challenge_id.as_bytes())));
        assert_eq!(
            challenge_authority_store_decode(&duplicated_encoded)
                .expect_err("duplicate challenge id rejected")
                .kind(),
            std::io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn challenge_authority_file_store_recovers_stale_lock() {
        let path = unique_test_path("challenge-authority-file-store-stale-lock");
        let lock_path = challenge_authority_lock_path(&path);
        std::fs::create_dir_all(lock_path.parent().expect("parent")).expect("create dir");
        let mut lock = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .expect("create stale lock");
        write_challenge_authority_lock_file(&mut lock, 10).expect("write stale lock");
        set_private_file_permissions(&lock_path).expect("private stale lock");
        assert!(challenge_authority_lock_is_stale(&lock_path, 100, 60).expect("stale lock check"));
        let (_issue, outcome) = ChallengeAuthorityFileStore::new(&path, 60)
            .issue_with_outcome(sample_challenge_issue_request("tenant-file-stale", 100))
            .expect("stale lock recovered");
        assert!(outcome.stale_lock_recovered);
        assert!(!lock_path.exists());
        let _ = std::fs::remove_file(&path);
    }

    fn sample_fetch_request(
        digest: &str,
        expected_digest: &str,
        byte_limit: u64,
        source_url: &str,
    ) -> FetchJobRequest {
        FetchJobRequest {
            job_id: "fetch-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            admission_request_id: "admission-1".to_string(),
            artifact: ArtifactRef {
                ecosystem: "npm".to_string(),
                name: "fixture".to_string(),
                version: "1.0.0".to_string(),
                digest: digest.to_string(),
                source: "registry".to_string(),
            },
            source_url: source_url.to_string(),
            expected_digest: expected_digest.to_string(),
            byte_limit,
        }
    }

    fn sample_fetch_result(plan: &FetchJobPlan, byte_len: u64) -> FetchJobResult {
        FetchJobResult {
            job_id: plan.job_id.clone(),
            tenant_id: plan.tenant_id.clone(),
            admission_request_id: plan.admission_request_id.clone(),
            artifact: plan.artifact.clone(),
            source_url: plan.source_url.clone(),
            expected_digest: plan.expected_digest.clone(),
            verified_digest: plan.expected_digest.clone(),
            cache_object_key: plan.cache_object_key.clone().unwrap(),
            byte_len,
            byte_limit: plan.byte_limit,
            quarantine_id: "quarantine-1".to_string(),
            fetch_enabled: plan.fetch_enabled,
            network_attempted: plan.network_attempted,
            stored_in_quarantine: true,
            audit_event_id: "audit-fetch-1".to_string(),
        }
    }

    fn sample_challenge_issue_request(
        tenant_id: &str,
        now_unix_seconds: u64,
    ) -> ChallengeIssueRequest {
        ChallengeIssueRequest {
            request_id: format!("challenge-issue-{now_unix_seconds}"),
            tenant_id: tenant_id.to_string(),
            subject: "launch-1".to_string(),
            context_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            configured_vault_host: "127.0.0.1:4873".to_string(),
            now_unix_seconds,
        }
    }

    fn sample_challenge_consume_request(
        tenant_id: &str,
        challenge_id: &str,
        now_unix_seconds: u64,
    ) -> ChallengeConsumeRequest {
        ChallengeConsumeRequest {
            request_id: format!("challenge-consume-{now_unix_seconds}"),
            tenant_id: tenant_id.to_string(),
            challenge_id: challenge_id.to_string(),
            submitted_subject: "launch-1".to_string(),
            submitted_context_hash:
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            submitted_configured_vault_host: "127.0.0.1:4873".to_string(),
            now_unix_seconds,
        }
    }

    fn sample_challenge_authority_request(
        scenario: ChallengeAuthorityScenario,
    ) -> ChallengeAuthorityRequest {
        ChallengeAuthorityRequest {
            request_id: "challenge-request-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            subject: "launch-1".to_string(),
            context_hash: "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                .to_string(),
            configured_vault_host: "127.0.0.1:4873".to_string(),
            now_unix_seconds: 1_800_000_000,
            ttl_seconds: 60,
            scenario,
        }
    }

    fn sample_profile() -> whoathere_evidence::EvidenceProfile {
        minimum_profiles()
            .into_iter()
            .find(|profile| profile.id == "npm.registry_tarball.v1")
            .unwrap()
    }

    fn sample_evidence_job_request(
        profile: &whoathere_evidence::EvidenceProfile,
    ) -> EvidenceJobRequest {
        EvidenceJobRequest {
            job_id: "evidence-job-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            admission_request_id: "admission-1".to_string(),
            artifact: ArtifactRef {
                ecosystem: "npm".to_string(),
                name: "fixture".to_string(),
                version: "1.0.0".to_string(),
                digest: ABC_DIGEST.to_string(),
                source: "registry".to_string(),
            },
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            job_kind: profile.requirements[0].job_kind,
            cache_object_key: ABC_OBJECT_KEY.to_string(),
            timeout_seconds: 300,
        }
    }

    fn sample_evidence_job_result(plan: &EvidenceJobPlan) -> EvidenceJobResultRecord {
        EvidenceJobResultRecord {
            job_id: plan.job_id.clone(),
            tenant_id: plan.tenant_id.clone(),
            admission_request_id: plan.admission_request_id.clone(),
            artifact: plan.artifact.clone(),
            profile_id: plan.profile_id.clone(),
            profile_version: plan.profile_version,
            job_kind: plan.job_kind,
            cache_object_key: plan.cache_object_key.clone().unwrap(),
            state: JobState::Passed,
            log_digest: "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                .to_string(),
            execution_enabled: plan.execution_enabled,
            detonation_attempted: plan.detonation_attempted,
            network_attempted: plan.network_attempted,
            audit_event_id: "audit-evidence-job-1".to_string(),
        }
    }

    fn sample_dynamic_behavior_request(
        profile: &whoathere_evidence::EvidenceProfile,
    ) -> DynamicBehaviorJobRequest {
        DynamicBehaviorJobRequest {
            job_id: "dynamic-behavior-job-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            admission_request_id: "admission-1".to_string(),
            artifact: ArtifactRef {
                ecosystem: "npm".to_string(),
                name: "fixture".to_string(),
                version: "1.0.0".to_string(),
                digest: ABC_DIGEST.to_string(),
                source: "registry".to_string(),
            },
            profile_id: profile.id.to_string(),
            profile_version: profile.version,
            job_kind: EvidenceJobKind::LifecycleDetonation,
            cache_object_key: ABC_OBJECT_KEY.to_string(),
            runner_id: "fixture-runner-macos-linux".to_string(),
            runner_session_id: "runner-session-1".to_string(),
            isolation_proof_id: "isolation-proof-1".to_string(),
            egress_proof_id: "egress-proof-1".to_string(),
            configured_vault_host: "127.0.0.1:4873".to_string(),
            fixture_mode: true,
            issued_at_unix_seconds: 1_800_000_000,
            timeout_seconds: 60,
        }
    }

    fn sample_dynamic_behavior_result(
        plan: &DynamicBehaviorJobPlan,
    ) -> DynamicBehaviorJobResultRecord {
        DynamicBehaviorJobResultRecord {
            job_id: plan.job_id.clone(),
            tenant_id: plan.tenant_id.clone(),
            admission_request_id: plan.admission_request_id.clone(),
            artifact: plan.artifact.clone(),
            profile_id: plan.profile_id.clone(),
            profile_version: plan.profile_version,
            job_kind: plan.job_kind,
            cache_object_key: plan.cache_object_key.clone().unwrap(),
            runner_id: plan.runner_id.clone(),
            runner_session_id: plan.runner_session_id.clone(),
            isolation_proof_id: plan.isolation_proof_id.clone(),
            egress_proof_id: plan.egress_proof_id.clone(),
            configured_vault_host: plan.configured_vault_host.clone(),
            observed_at_unix_seconds: plan.issued_at_unix_seconds + 1,
            job_state: JobState::Passed,
            behavior_schema: "whoathere.dynamic_behavior.v1".to_string(),
            behavior_log_digest:
                "sha256:3333333333333333333333333333333333333333333333333333333333333333"
                    .to_string(),
            signal_summary: DynamicBehaviorSignalSummary::clean(),
            execution_enabled: plan.execution_enabled,
            arbitrary_execution_attempted: false,
            fixture_mode: plan.fixture_mode,
            network_attempted: false,
            isolation_verified: true,
            egress_vault_only_verified: true,
            raw_log_captured: false,
            raw_env_captured: false,
            raw_network_payload_captured: false,
            raw_package_bytes_captured: false,
            local_paths_captured: false,
            audit_event_id: "audit-dynamic-behavior-1".to_string(),
            reason_codes: Vec::new(),
        }
    }

    fn sample_admin_workflow_request(
        action: AdminWorkflowAction,
        break_glass: bool,
    ) -> AdminWorkflowRequest {
        AdminWorkflowRequest {
            request_id: "admin-request-1".to_string(),
            tenant_id: "tenant-1".to_string(),
            artifact: ArtifactRef {
                ecosystem: "npm".to_string(),
                name: "fixture".to_string(),
                version: "1.0.0".to_string(),
                digest: ABC_DIGEST.to_string(),
                source: "registry".to_string(),
            },
            action,
            operator_id: "operator-1".to_string(),
            reason_code: "manual_review_clean_fixture".to_string(),
            ticket_id: "SEC-123".to_string(),
            break_glass,
            policy_version: "policy-1".to_string(),
        }
    }

    fn unique_test_path(label: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir()
            .join(format!("{label}-{}-{unique}", std::process::id()))
            .join("store.txt")
    }
}
