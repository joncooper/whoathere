mod behavior_codex_observer;
mod behavior_evidence_projector;
mod exact_artifact;
mod exact_artifact_codex;
mod exact_npm_linux_vz;
mod exact_sdist_linux_vz;
mod exact_wheel_linux_vz;
mod linux_vz_helper_diagnostics;
mod static_download_execute_projection;

pub use behavior_codex_observer::*;
pub use behavior_evidence_projector::*;
pub use exact_artifact::*;
pub use exact_artifact_codex::*;
pub use exact_npm_linux_vz::*;
pub use exact_sdist_linux_vz::*;
pub use exact_wheel_linux_vz::*;
pub use static_download_execute_projection::*;

use whoathere_artifact::{
    detect_artifact_format, normalize_artifact, ArtifactEnvelope, ArtifactEnvelopeInput,
    NormalizationError, NormalizationLimits, NormalizedArtifact,
};
use whoathere_cache::{
    PersistentCasError, PersistentQuarantineCas, QuarantinedArtifact, VerifiedArtifactLease,
};
use whoathere_detector::{
    analyze_normalized_artifact, ArtifactDetectorError, ArtifactStaticAnalysis,
};
use whoathere_evidence::v2::{
    AnalyzerIdentityV2, ArtifactEvidenceSubjectV2, EvidenceCompletenessV2, EvidenceCoverageV2,
    EvidenceJobCompletionV2, EvidenceJobResultV2, EvidenceLimitationStateV2, EvidenceLimitationV2,
    EvidenceProducerIdentityV2, EvidenceValidationErrorV2,
};

/// One exact artifact prepared from a sealed, reverified quarantine object.
///
/// The envelope, normalized files, and evidence subject are all derived from a
/// single verified CAS snapshot. The opaque quarantine handle is retained so
/// detonation can reopen and rehash the same object instead of resolving the
/// package coordinate again.
#[derive(Clone, PartialEq, Eq)]
pub struct PreparedArtifact {
    quarantined_artifact: QuarantinedArtifact,
    envelope: ArtifactEnvelope,
    normalized: NormalizedArtifact,
    evidence_subject: ArtifactEvidenceSubjectV2,
}

impl std::fmt::Debug for PreparedArtifact {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedArtifact")
            .field("artifact_sha256", &self.evidence_subject.artifact_sha256())
            .field("manifest_sha256", &self.evidence_subject.manifest_sha256())
            .field("cas_object_key", &self.evidence_subject.cas_object_key())
            .field(
                "normalized_member_count",
                &self.normalized.manifest.members.len(),
            )
            .field("member_bytes", &"<redacted>")
            .finish()
    }
}

impl PreparedArtifact {
    pub fn quarantined_artifact(&self) -> &QuarantinedArtifact {
        &self.quarantined_artifact
    }

    pub fn envelope(&self) -> &ArtifactEnvelope {
        &self.envelope
    }

    pub fn normalized(&self) -> &NormalizedArtifact {
        &self.normalized
    }

    pub fn evidence_subject(&self) -> &ArtifactEvidenceSubjectV2 {
        &self.evidence_subject
    }

    /// Run deterministic analysis only over normalized bytes retained from the
    /// verified quarantine snapshot.
    pub fn analyze_deterministically(
        &self,
    ) -> Result<ArtifactStaticAnalysis, ArtifactPreparationError> {
        analyze_normalized_artifact(&self.normalized).map_err(ArtifactPreparationError::from)
    }

    /// Projects a validated deterministic analysis into an unauthenticated,
    /// artifact-bound evidence job. A later control-plane step must place this
    /// job in an envelope, authenticate canonical bytes, and reserve replay ID.
    pub fn deterministic_evidence_job(
        &self,
        analysis: &ArtifactStaticAnalysis,
        request: DeterministicEvidenceJobRequest<'_>,
    ) -> Result<EvidenceJobResultV2, ArtifactPreparationError> {
        analysis.validate(&self.normalized)?;
        let result_sha256 = analysis.analysis_sha256()?.to_string();
        let coverage = if analysis.coverage.completeness
            == whoathere_detector::ArtifactAnalysisCompleteness::Complete
            && analysis.coverage.limitations.is_empty()
        {
            EvidenceCoverageV2::complete()
        } else {
            let mut codes = analysis.coverage.limitations.clone();
            codes.sort();
            codes.dedup();
            if codes.len() > 127 {
                codes.truncate(127);
                codes.push("detector_limitation_count_exceeded".to_string());
            }
            if codes.is_empty() {
                codes.push("detector_coverage_incomplete".to_string());
            }
            EvidenceCoverageV2 {
                completeness: EvidenceCompletenessV2::Incomplete,
                limitations: EvidenceLimitationStateV2::Present(
                    codes
                        .into_iter()
                        .map(|code| EvidenceLimitationV2 {
                            code,
                            evidence_sha256: Some(result_sha256.clone()),
                        })
                        .collect(),
                ),
            }
        };
        Ok(EvidenceJobResultV2 {
            job_id: request.job_id.to_string(),
            evidence_id: request.evidence_id.to_string(),
            run_id: request.run_id.to_string(),
            job_spec_sha256: request.job_spec_sha256.to_string(),
            produced_at_unix_seconds: request.produced_at_unix_seconds,
            subject: self.evidence_subject.clone(),
            policy_sha256: request.policy_sha256.to_string(),
            producer: EvidenceProducerIdentityV2::Analyzer(request.analyzer),
            completion: EvidenceJobCompletionV2::Completed,
            coverage,
            result_sha256,
        })
    }

    /// Reopens and rehashes the prepared artifact as a guest-transport source.
    ///
    /// This deliberately returns a verified host-side snapshot rather than a
    /// registry coordinate or filesystem path. It is not proof of guest receipt;
    /// transport and the guest must verify the digest again before execution.
    pub fn verified_transport_source(
        &self,
        cas: &PersistentQuarantineCas,
    ) -> Result<VerifiedArtifactLease, ArtifactPreparationError> {
        let lease = cas.verified_lease(&self.quarantined_artifact)?;
        if !self.envelope.matches_original_bytes(lease.bytes())
            || self.envelope.original_sha256.as_str() != self.quarantined_artifact.digest()
            || self.evidence_subject.artifact_sha256() != self.quarantined_artifact.digest()
            || self.evidence_subject.cas_object_key() != self.quarantined_artifact.object_key()
        {
            return Err(ArtifactPreparationError::identity_mismatch());
        }
        Ok(lease)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeterministicEvidenceJobRequest<'a> {
    pub evidence_id: &'a str,
    pub run_id: &'a str,
    pub job_id: &'a str,
    pub job_spec_sha256: &'a str,
    pub produced_at_unix_seconds: u64,
    pub policy_sha256: &'a str,
    pub analyzer: AnalyzerIdentityV2,
}

pub struct ArtifactPreparationError {
    reason_code: &'static str,
}

impl ArtifactPreparationError {
    pub fn reason_code(&self) -> &'static str {
        self.reason_code
    }

    fn identity_mismatch() -> Self {
        Self::with_reason("artifact_preparation_identity_mismatch")
    }

    fn with_reason(reason_code: &'static str) -> Self {
        Self { reason_code }
    }
}

impl std::fmt::Debug for ArtifactPreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactPreparationError")
            .field("reason_code", &self.reason_code)
            .finish()
    }
}

impl std::fmt::Display for ArtifactPreparationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code)
    }
}

impl std::error::Error for ArtifactPreparationError {}

impl From<PersistentCasError> for ArtifactPreparationError {
    fn from(error: PersistentCasError) -> Self {
        Self {
            reason_code: error.reason_code(),
        }
    }
}

impl From<NormalizationError> for ArtifactPreparationError {
    fn from(_error: NormalizationError) -> Self {
        Self {
            reason_code: "artifact_preparation_normalization_failed",
        }
    }
}

impl From<EvidenceValidationErrorV2> for ArtifactPreparationError {
    fn from(error: EvidenceValidationErrorV2) -> Self {
        Self {
            reason_code: error.reason_code(),
        }
    }
}

impl From<ArtifactDetectorError> for ArtifactPreparationError {
    fn from(_error: ArtifactDetectorError) -> Self {
        Self {
            reason_code: "artifact_preparation_detector_failed",
        }
    }
}

/// Prepare one package artifact without resolving or executing it.
///
/// `envelope_input.custody_reference` is replaced with the canonical CAS key;
/// callers cannot bind the envelope to an unverified registry or workspace
/// location. Every other acquisition field remains caller-supplied context and
/// is checked by the artifact normalizer where applicable.
pub fn prepare_quarantined_artifact(
    cas: &PersistentQuarantineCas,
    quarantined_artifact: &QuarantinedArtifact,
    mut envelope_input: ArtifactEnvelopeInput,
    limits: NormalizationLimits,
) -> Result<PreparedArtifact, ArtifactPreparationError> {
    if quarantined_artifact.byte_len() > limits.max_original_bytes {
        return Err(NormalizationError::OriginalSizeLimit {
            actual: quarantined_artifact.byte_len(),
            limit: limits.max_original_bytes,
        }
        .into());
    }
    let lease = cas.verified_lease(quarantined_artifact)?;
    let detected_format = detect_artifact_format(
        envelope_input.ecosystem,
        &envelope_input.original_filename,
        lease.bytes(),
    )?;
    envelope_input.custody_reference =
        format!("quarantine-cas:{}", quarantined_artifact.object_key());
    let envelope =
        ArtifactEnvelope::from_original_bytes(envelope_input, lease.bytes(), detected_format);
    if envelope.original_sha256.as_str() != quarantined_artifact.digest()
        || envelope.original_byte_length != quarantined_artifact.byte_len()
    {
        return Err(ArtifactPreparationError::identity_mismatch());
    }

    let normalized = normalize_artifact(&envelope, lease.bytes(), limits)?;
    if normalized.manifest.artifact_sha256 != envelope.original_sha256 {
        return Err(ArtifactPreparationError::identity_mismatch());
    }
    let envelope_sha256 = envelope.envelope_sha256().map_err(|_| {
        ArtifactPreparationError::with_reason("artifact_preparation_envelope_digest_failed")
    })?;
    let evidence_subject = ArtifactEvidenceSubjectV2::new(
        envelope.original_sha256.as_str(),
        envelope_sha256.as_str(),
        normalized.manifest.manifest_sha256.as_str(),
        quarantined_artifact.object_key(),
    )?;

    Ok(PreparedArtifact {
        quarantined_artifact: quarantined_artifact.clone(),
        envelope,
        normalized,
        evidence_subject,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionDecision {
    ExecuteReadonly,
    Refuse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionPlan {
    decision: ExecutionDecision,
    reason_code: &'static str,
}

impl ExecutionPlan {
    pub const fn decision(&self) -> ExecutionDecision {
        self.decision
    }

    pub const fn reason_code(&self) -> &'static str {
        self.reason_code
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionOutput {
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

pub fn plan_protected_execution(
    tool: &str,
    args: &[String],
    execute_requested: bool,
) -> ExecutionPlan {
    if !execute_requested {
        return ExecutionPlan {
            decision: ExecutionDecision::Refuse,
            reason_code: "execution_not_requested",
        };
    }

    if !is_supported_tool(tool) {
        return ExecutionPlan {
            decision: ExecutionDecision::Refuse,
            reason_code: "unsupported_tool_execution_refused",
        };
    }

    if is_readonly_version_probe(args) {
        return ExecutionPlan {
            decision: ExecutionDecision::Refuse,
            reason_code: "host_readonly_probe_disabled",
        };
    }

    ExecutionPlan {
        decision: ExecutionDecision::Refuse,
        reason_code: "package_manager_execution_gated",
    }
}

pub fn execute_readonly(plan: &ExecutionPlan) -> std::io::Result<ExecutionOutput> {
    Ok(ExecutionOutput {
        status_code: Some(70),
        stdout: String::new(),
        stderr: format!("refused: {}", plan.reason_code),
    })
}

fn is_supported_tool(tool: &str) -> bool {
    matches!(
        basename(tool),
        "npm" | "npx" | "pip" | "pip3" | "python" | "python3"
    )
}

fn is_readonly_version_probe(args: &[String]) -> bool {
    matches!(args, [arg] if arg == "--version" || arg == "-V" || arg == "-v")
}

fn basename(value: &str) -> &str {
    value.rsplit(['/', '\\']).next().unwrap_or(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::sync::atomic::{AtomicU64, Ordering};
    use whoathere_artifact::{
        AcquisitionMethod, ArtifactFormat, ArtifactSourceType, Ecosystem, Sha256Digest,
    };
    use whoathere_detector::{ArtifactAnalysisOutcome, ArtifactFindingCategory};
    use whoathere_evidence::v2::{
        EvidenceEnvelopeV2, EvidenceJobExpectationV2, EvidenceProducerIdentityV2,
        EvidenceValidationContextV2, EvidenceValidationErrorV2, EVIDENCE_ENVELOPE_SCHEMA_V2,
    };
    use whoathere_hash::sha256_digest;

    static TEMP_ROOT_COUNTER: AtomicU64 = AtomicU64::new(1);

    fn temp_root(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "{label}-{}-{}",
            std::process::id(),
            TEMP_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn npm_tgz(package_json: &[u8], index_js: &[u8]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        append_tar_file(&mut archive, "package/package.json", package_json);
        append_tar_file(&mut archive, "package/index.js", index_js);
        let encoder = archive.into_inner().expect("finish tar archive");
        encoder.finish().expect("finish gzip archive")
    }

    fn append_tar_file(archive: &mut tar::Builder<GzEncoder<Vec<u8>>>, path: &str, bytes: &[u8]) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(1);
        header.set_cksum();
        archive
            .append_data(&mut header, path, bytes)
            .expect("append inert fixture member");
    }

    fn npm_envelope_input() -> ArtifactEnvelopeInput {
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("safe-pkg".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "npm:safe-pkg@1.0.0".to_string(),
            source_type: ArtifactSourceType::Registry,
            acquired_at: "2026-07-09T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::RegistryDownload,
            original_filename: "safe-pkg-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "untrusted-caller-location".to_string(),
            resolver_metadata_sha256: Some(Sha256Digest::from_bytes(b"resolver metadata")),
            registry_metadata_sha256: Some(Sha256Digest::from_bytes(b"registry metadata")),
            policy_version: "artifact-policy-v1".to_string(),
            requires_external_dependency_resolution: false,
        }
    }

    #[test]
    fn refuses_execution_when_not_requested() {
        let args = vec!["--version".to_string()];
        let plan = plan_protected_execution("npm", &args, false);
        assert_eq!(plan.decision(), ExecutionDecision::Refuse);
        assert_eq!(plan.reason_code(), "execution_not_requested");
    }

    #[test]
    fn refuses_relative_readonly_version_probe_when_requested() {
        let args = vec!["--version".to_string()];
        let plan = plan_protected_execution("npm", &args, true);
        assert_eq!(plan.decision(), ExecutionDecision::Refuse);
        assert_eq!(plan.reason_code(), "host_readonly_probe_disabled");
    }

    #[test]
    fn absolute_readonly_probe_does_not_spawn_on_the_host() {
        let args = vec!["--version".to_string()];
        let plan = plan_protected_execution("/usr/bin/npm", &args, true);
        assert_eq!(plan.decision(), ExecutionDecision::Refuse);
        assert_eq!(plan.reason_code(), "host_readonly_probe_disabled");
        let output = execute_readonly(&plan).expect("refusal is local");
        assert_eq!(output.status_code, Some(70));
        assert!(output.stderr.contains("host_readonly_probe_disabled"));
    }

    #[test]
    fn python_verbose_startup_is_never_executed_as_a_version_probe() {
        let args = vec!["-v".to_string()];
        let plan = plan_protected_execution("/usr/bin/python3", &args, true);
        assert_eq!(plan.decision(), ExecutionDecision::Refuse);
        assert_eq!(plan.reason_code(), "host_readonly_probe_disabled");
    }

    #[test]
    fn refuses_install_even_when_requested() {
        let args = vec!["ci".to_string()];
        let plan = plan_protected_execution("npm", &args, true);
        assert_eq!(plan.decision(), ExecutionDecision::Refuse);
        assert_eq!(plan.reason_code(), "package_manager_execution_gated");
    }

    #[test]
    fn refused_plan_does_not_spawn_process() {
        let args = vec!["ci".to_string()];
        let plan = plan_protected_execution("npm", &args, true);
        let output = execute_readonly(&plan).expect("refusal is local");
        assert_eq!(output.status_code, Some(70));
        assert!(output.stderr.contains("package_manager_execution_gated"));
    }

    #[test]
    fn prepares_envelope_manifest_and_evidence_from_one_verified_cas_snapshot() {
        let root = temp_root("whoathere-runner-prepared-artifact");
        let bytes = npm_tgz(
            br#"{"name":"safe-pkg","version":"1.0.0","main":"index.js"}"#,
            b"module.exports = 42;\n",
        );
        let digest = sha256_digest(&bytes);
        let cas = PersistentQuarantineCas::create(&root, 1024 * 1024).expect("private CAS");
        let quarantined = cas
            .quarantine_bytes(&digest, &bytes)
            .expect("quarantine exact fixture bytes");

        let prepared = prepare_quarantined_artifact(
            &cas,
            &quarantined,
            npm_envelope_input(),
            NormalizationLimits::default(),
        )
        .expect("prepare exact fixture artifact");

        assert_eq!(prepared.envelope().original_sha256.as_str(), digest);
        assert_eq!(
            prepared.envelope().custody_reference,
            format!("quarantine-cas:{}", quarantined.object_key())
        );
        assert_eq!(
            prepared.normalized().manifest.artifact_sha256,
            prepared.envelope().original_sha256
        );
        assert_eq!(prepared.evidence_subject().artifact_sha256(), digest);
        assert_eq!(
            prepared.evidence_subject().manifest_sha256(),
            prepared.normalized().manifest.manifest_sha256.as_str()
        );
        assert_eq!(
            prepared.evidence_subject().cas_object_key(),
            quarantined.object_key()
        );
        assert_eq!(
            prepared.evidence_subject().envelope_sha256(),
            prepared
                .envelope()
                .envelope_sha256()
                .expect("canonical envelope digest")
                .as_str()
        );
        let execution_lease = prepared
            .verified_transport_source(&cas)
            .expect("reverify exact execution bytes");
        assert_eq!(execution_lease.bytes(), bytes);
        let debug_output = format!("{prepared:?}");
        assert!(!debug_output.contains("module.exports"));
        assert!(debug_output.contains("<redacted>"));

        std::fs::remove_dir_all(&root).expect("remove fixture CAS");
    }

    #[test]
    fn same_coordinate_different_bytes_never_share_artifact_identity() {
        let root = temp_root("whoathere-runner-coordinate-substitution");
        let first_bytes = npm_tgz(
            br#"{"name":"safe-pkg","version":"1.0.0","main":"index.js"}"#,
            b"module.exports = 'first';\n",
        );
        let substituted_bytes = npm_tgz(
            br#"{"name":"safe-pkg","version":"1.0.0","main":"index.js"}"#,
            b"module.exports = 'substituted';\n",
        );
        let first_digest = sha256_digest(&first_bytes);
        let substituted_digest = sha256_digest(&substituted_bytes);
        let cas = PersistentQuarantineCas::create(&root, 1024 * 1024).expect("private CAS");
        assert_eq!(
            cas.quarantine_bytes(&first_digest, &substituted_bytes)
                .expect_err("wrong bytes must not enter expected object")
                .reason_code(),
            "quarantine_cas_digest_mismatch"
        );
        let first_handle = cas
            .quarantine_bytes(&first_digest, &first_bytes)
            .expect("first exact artifact");
        let substituted_handle = cas
            .quarantine_bytes(&substituted_digest, &substituted_bytes)
            .expect("substituted exact artifact");
        let first = prepare_quarantined_artifact(
            &cas,
            &first_handle,
            npm_envelope_input(),
            NormalizationLimits::default(),
        )
        .expect("first prepared artifact");
        let substituted = prepare_quarantined_artifact(
            &cas,
            &substituted_handle,
            npm_envelope_input(),
            NormalizationLimits::default(),
        )
        .expect("substituted prepared artifact");

        assert_eq!(
            first.envelope().source_coordinate,
            substituted.envelope().source_coordinate
        );
        assert_ne!(
            first.evidence_subject().artifact_sha256(),
            substituted.evidence_subject().artifact_sha256()
        );
        assert_ne!(
            first.evidence_subject().manifest_sha256(),
            substituted.evidence_subject().manifest_sha256()
        );
        assert_eq!(
            first
                .verified_transport_source(&cas)
                .expect("first execution lease")
                .bytes(),
            first_bytes
        );

        std::fs::remove_dir_all(&root).expect("remove fixture CAS");
    }

    #[test]
    fn registry_coordinate_must_match_the_normalized_package_identity() {
        let root = temp_root("whoathere-runner-coordinate-binding");
        let bytes = npm_tgz(
            br#"{"name":"safe-pkg","version":"1.0.0","main":"index.js"}"#,
            b"module.exports = 42;\n",
        );
        let digest = sha256_digest(&bytes);
        let cas = PersistentQuarantineCas::create(&root, 1024 * 1024).expect("private CAS");
        let quarantined = cas
            .quarantine_bytes(&digest, &bytes)
            .expect("quarantine fixture");
        let mut wrong_identity = npm_envelope_input();
        wrong_identity.package_name = Some("different-pkg".to_string());
        wrong_identity.source_coordinate = "npm:different-pkg@1.0.0".to_string();

        let error = prepare_quarantined_artifact(
            &cas,
            &quarantined,
            wrong_identity,
            NormalizationLimits::default(),
        )
        .expect_err("coordinate substitution must fail normalization");
        assert_eq!(
            error.reason_code(),
            "artifact_preparation_normalization_failed"
        );

        std::fs::remove_dir_all(&root).expect("remove fixture CAS");
    }

    #[test]
    fn preparation_preflights_parser_limit_and_redacts_artifact_controlled_errors() {
        let root = temp_root("whoathere-runner-preflight-redaction");
        let bytes = npm_tgz(
            br#"{"name":"safe-pkg","version":"1.0.0","main":"index.js"}"#,
            b"module.exports = 42;\n",
        );
        let digest = sha256_digest(&bytes);
        let cas = PersistentQuarantineCas::create(&root, 1024 * 1024).expect("private CAS");
        let quarantined = cas
            .quarantine_bytes(&digest, &bytes)
            .expect("quarantine fixture");
        let limits = NormalizationLimits {
            max_original_bytes: bytes.len() as u64 - 1,
            ..NormalizationLimits::default()
        };

        let preflight_error =
            prepare_quarantined_artifact(&cas, &quarantined, npm_envelope_input(), limits)
                .expect_err("parser limit must be checked before leasing bytes");
        assert_eq!(
            preflight_error.reason_code(),
            "artifact_preparation_normalization_failed"
        );

        let mut wrong_identity = npm_envelope_input();
        wrong_identity.package_name = Some("WHOATHERE_SECRET_CANARY".to_string());
        wrong_identity.source_coordinate = "npm:WHOATHERE_SECRET_CANARY@1.0.0".to_string();
        let controlled_error = prepare_quarantined_artifact(
            &cas,
            &quarantined,
            wrong_identity,
            NormalizationLimits::default(),
        )
        .expect_err("wrong identity must fail");
        assert!(!controlled_error
            .to_string()
            .contains("WHOATHERE_SECRET_CANARY"));
        assert!(!format!("{controlled_error:?}").contains("WHOATHERE_SECRET_CANARY"));

        std::fs::remove_dir_all(&root).expect("remove fixture CAS");
    }

    #[test]
    fn same_bytes_bind_distinct_acquisition_envelopes_without_rescanning_registry() {
        let root = temp_root("whoathere-runner-provenance-binding");
        let bytes = npm_tgz(
            br#"{"name":"safe-pkg","version":"1.0.0","main":"index.js"}"#,
            b"module.exports = 42;\n",
        );
        let digest = sha256_digest(&bytes);
        let first_cas = PersistentQuarantineCas::create(&root, 1024 * 1024).expect("private CAS");
        let first_handle = first_cas
            .quarantine_bytes(&digest, &bytes)
            .expect("quarantine fixture");
        let first = prepare_quarantined_artifact(
            &first_cas,
            &first_handle,
            npm_envelope_input(),
            NormalizationLimits::default(),
        )
        .expect("first acquisition context");
        drop(first_cas);

        let reopened_cas = PersistentQuarantineCas::create(&root, 1024 * 1024).expect("reopen CAS");
        let reopened = reopened_cas
            .reopen_quarantined(&digest, bytes.len() as u64)
            .expect("reopen from durable digest receipt");
        let mut second_input = npm_envelope_input();
        second_input.acquired_at = "2026-07-09T00:00:01Z".to_string();
        second_input.registry_metadata_sha256 =
            Some(Sha256Digest::from_bytes(b"second registry metadata"));
        let second = prepare_quarantined_artifact(
            &reopened_cas,
            &reopened,
            second_input,
            NormalizationLimits::default(),
        )
        .expect("second acquisition context over persisted exact bytes");

        assert_eq!(
            first.evidence_subject().artifact_sha256(),
            second.evidence_subject().artifact_sha256()
        );
        assert_eq!(
            first.evidence_subject().manifest_sha256(),
            second.evidence_subject().manifest_sha256()
        );
        assert_ne!(
            first.evidence_subject().envelope_sha256(),
            second.evidence_subject().envelope_sha256()
        );

        std::fs::remove_dir_all(&root).expect("remove fixture CAS");
    }

    #[test]
    fn deterministic_analysis_is_bound_to_the_prepared_artifact() {
        let root = temp_root("whoathere-runner-bound-static-analysis");
        let bytes = npm_tgz(
            br#"{"name":"safe-pkg","version":"1.0.0","scripts":{"postinstall":"node index.js"}}"#,
            br#"const fs = require('node:fs');
const token = process.env.NPM_TOKEN;
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
const https = require('node:https');
https.request({method: 'POST'});
require('node:child_process').spawn('printf', [token, config.length]);
"#,
        );
        let digest = sha256_digest(&bytes);
        let cas = PersistentQuarantineCas::create(&root, 1024 * 1024).expect("private CAS");
        let quarantined = cas
            .quarantine_bytes(&digest, &bytes)
            .expect("quarantine exact fixture");
        let prepared = prepare_quarantined_artifact(
            &cas,
            &quarantined,
            npm_envelope_input(),
            NormalizationLimits::default(),
        )
        .expect("prepare exact fixture artifact");

        let analysis = prepared
            .analyze_deterministically()
            .expect("analyze normalized artifact bytes");
        assert_eq!(analysis.artifact_sha256.as_str(), digest);
        assert_eq!(
            analysis.manifest_sha256.as_str(),
            prepared.evidence_subject().manifest_sha256()
        );
        assert!(matches!(
            analysis.outcome,
            ArtifactAnalysisOutcome::Findings
                | ArtifactAnalysisOutcome::FindingsWithIncompleteCoverage
        ));
        for category in [
            ArtifactFindingCategory::CredentialAccess,
            ArtifactFindingCategory::SensitivePathAccess,
            ArtifactFindingCategory::NetworkCapability,
            ArtifactFindingCategory::ProcessExecution,
        ] {
            assert!(analysis
                .findings
                .iter()
                .any(|finding| finding.category == category));
        }
        analysis
            .validate(prepared.normalized())
            .expect("all finding citations and digests revalidate");
        let policy_sha256 = Sha256Digest::from_bytes(b"detector policy").to_string();
        let job_spec_sha256 = Sha256Digest::from_bytes(b"static job spec").to_string();
        let analyzer = AnalyzerIdentityV2 {
            analyzer_id: "artifact-static".to_string(),
            analyzer_version: "1.0.0".to_string(),
            analyzer_sha256: Sha256Digest::from_bytes(b"artifact detector binary").to_string(),
        };
        let job = prepared
            .deterministic_evidence_job(
                &analysis,
                DeterministicEvidenceJobRequest {
                    evidence_id: "evidence-static-1",
                    run_id: "run-static-1",
                    job_id: "artifact-static-1",
                    job_spec_sha256: &job_spec_sha256,
                    produced_at_unix_seconds: 1_025,
                    policy_sha256: &policy_sha256,
                    analyzer: analyzer.clone(),
                },
            )
            .expect("project exact static result into evidence job");
        assert_eq!(
            job.result_sha256,
            analysis
                .analysis_sha256()
                .expect("analysis digest")
                .as_str()
        );
        let envelope = EvidenceEnvelopeV2 {
            schema_version: EVIDENCE_ENVELOPE_SCHEMA_V2.to_string(),
            evidence_id: "evidence-static-1".to_string(),
            run_id: "run-static-1".to_string(),
            run_started_at_unix_seconds: 1_000,
            issued_at_unix_seconds: 1_040,
            expires_at_unix_seconds: 1_200,
            subject: prepared.evidence_subject().clone(),
            policy_sha256: policy_sha256.clone(),
            coverage: job.coverage.clone(),
            jobs: vec![job],
        };
        let validated = envelope
            .validate_structure(&EvidenceValidationContextV2 {
                expected_evidence_id: "evidence-static-1".to_string(),
                expected_run_id: "run-static-1".to_string(),
                expected_subject: prepared.evidence_subject().clone(),
                expected_policy_sha256: policy_sha256,
                expected_jobs: vec![EvidenceJobExpectationV2 {
                    job_id: "artifact-static-1".to_string(),
                    job_spec_sha256,
                    producer: EvidenceProducerIdentityV2::Analyzer(analyzer),
                }],
                now_unix_seconds: 1_050,
                maximum_age_seconds: 300,
                previously_accepted_evidence_ids: Vec::new(),
            })
            .expect("structurally validate artifact-bound evidence");
        assert!(!validated.is_authenticated());
        assert_eq!(
            validated.check_complete().unwrap_err(),
            EvidenceValidationErrorV2::IncompleteCoverage
        );
        let normalized_debug = format!("{:?}", prepared.normalized());
        assert!(!normalized_debug.contains("postinstall"));
        assert!(!normalized_debug.contains("NPM_TOKEN"));
        assert!(normalized_debug.contains("<redacted>"));
        assert_eq!(
            prepared
                .verified_transport_source(&cas)
                .expect("same bytes remain available for later detonation")
                .bytes(),
            bytes
        );

        std::fs::remove_dir_all(&root).expect("remove fixture CAS");
    }
}
