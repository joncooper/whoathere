use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Cursor;
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, NormalizedArtifact, Sha256Digest,
};
use whoathere_detector::{
    analyze_normalized_artifact, artifact_review_adapter_result_schema_sha256_v2,
    artifact_review_finding_evidence_sha256_v2, artifact_review_prompt_template_sha256_v2,
    build_artifact_review_request_v2, decode_and_structurally_validate_artifact_review_result_v2,
    normalize_artifact_review_provider_outputs_v2, ArtifactReviewChannelIsolationV2,
    ArtifactReviewConfigV2, ArtifactReviewErrorV2, ArtifactReviewExecutionReportV2,
    ArtifactReviewFindingCategoryV2, ArtifactReviewFindingEvidenceInputV2,
    ArtifactReviewFindingSeverityV2, ArtifactReviewInferenceSettingsV2,
    ArtifactReviewModelIdentityV2, ArtifactReviewNormalizationErrorV2,
    ArtifactReviewPrivacyPostureV2, ArtifactReviewPromptIdentityV2,
    ArtifactReviewProviderIdentityV2, ArtifactReviewProviderOutputErrorV2,
    ArtifactReviewProviderOutputV2, ArtifactReviewRequestV2, ArtifactReviewVerdictV2,
    ArtifactReviewWorkItemNormalizationStatusV2, ArtifactReviewWorkItemStatusV2,
    ArtifactStaticAnalysis, ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2,
    ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2, ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2,
    MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};

fn tar_gzip(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, bytes, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(*mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, *path, Cursor::new(*bytes))
            .expect("append inert fixture member");
    }
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn fixture_artifact_with_index(index_bytes: &[u8]) -> NormalizedArtifact {
    let bytes = tar_gzip(&[
        (
            "package/package.json",
            br#"{"name":"normalizer-fixture","version":"1.0.0","scripts":{"postinstall":"node index.js"}}"#,
            0o644,
        ),
        (
            "package/index.js",
            index_bytes,
            0o644,
        ),
    ]);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("normalizer-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:normalizer-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-09T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "normalizer-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "inert-artifact-review-normalizer-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "artifact-review-normalizer-test.v2".to_string(),
            requires_external_dependency_resolution: false,
        },
        &bytes,
        ArtifactFormat::NpmTarGzip,
    );
    normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert npm fixture")
}

fn fixture_artifact() -> NormalizedArtifact {
    fixture_artifact_with_index(
        "const ordinary = 1;\nconst unicode = 'snowman ☃';\nconst credential = process.env.DEMO_TOKEN;\nconsole.log(ordinary, credential);\n".as_bytes(),
    )
}

fn subject(artifact: &NormalizedArtifact) -> ArtifactEvidenceSubjectV2 {
    let artifact_digest = artifact.manifest.artifact_sha256.as_str();
    ArtifactEvidenceSubjectV2::new(
        artifact_digest,
        Sha256Digest::from_bytes(b"inert normalizer acquisition envelope").to_string(),
        artifact.manifest.manifest_sha256.to_string(),
        canonical_cas_object_key_for_artifact(artifact_digest).expect("canonical object key"),
    )
    .expect("valid exact subject")
}

fn config() -> ArtifactReviewConfigV2 {
    ArtifactReviewConfigV2 {
        policy_sha256: Sha256Digest::from_bytes(b"artifact review normalizer policy"),
        provider: ArtifactReviewProviderIdentityV2 {
            adapter_id: "local-inert-normalizer-adapter".to_string(),
            adapter_version: "2.0.0".to_string(),
            adapter_sha256: Sha256Digest::from_bytes(b"inert normalizer adapter"),
        },
        model: ArtifactReviewModelIdentityV2::measured_local(
            "inert-review-model",
            "2026-07-09",
            Sha256Digest::from_bytes(b"immutable inert model"),
        ),
        prompt: ArtifactReviewPromptIdentityV2 {
            template_id: ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2.to_string(),
            template_version: ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2.to_string(),
            template_sha256: artifact_review_prompt_template_sha256_v2(),
        },
        adapter_result_schema_sha256: artifact_review_adapter_result_schema_sha256_v2(),
        privacy_posture: ArtifactReviewPrivacyPostureV2::LocalOnly,
        inference: ArtifactReviewInferenceSettingsV2 {
            seed: 23,
            temperature_milli: 0,
            top_p_milli: 1_000,
            context_tokens: 16_384,
            max_output_tokens: 2_048,
        },
    }
}

fn fixture() -> (
    NormalizedArtifact,
    ArtifactStaticAnalysis,
    ArtifactEvidenceSubjectV2,
    ArtifactReviewRequestV2,
) {
    let artifact = fixture_artifact();
    let analysis = analyze_normalized_artifact(&artifact).expect("static analysis");
    let subject = subject(&artifact);
    let request = build_artifact_review_request_v2(&subject, &artifact, &analysis, config())
        .expect("review request");
    (artifact, analysis, subject, request)
}

fn model_output(
    request: &ArtifactReviewRequestV2,
    work_item_id: &Sha256Digest,
    verdict: &str,
    findings: serde_json::Value,
) -> Vec<u8> {
    let invocation_sha256 = request
        .invocation_sha256(work_item_id)
        .expect("known work item invocation");
    model_output_with_invocation(work_item_id, &invocation_sha256, verdict, findings)
}

fn model_output_with_invocation(
    work_item_id: &Sha256Digest,
    invocation_sha256: &Sha256Digest,
    verdict: &str,
    findings: serde_json::Value,
) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2,
        "work_item_id": work_item_id,
        "invocation_sha256": invocation_sha256,
        "verdict": verdict,
        "findings": findings,
    }))
    .expect("model output JSON")
}

fn complete_output(
    work_item_id: &Sha256Digest,
    raw_output: Vec<u8>,
) -> ArtifactReviewProviderOutputV2 {
    ArtifactReviewProviderOutputV2::new_complete(
        work_item_id.clone(),
        raw_output,
        ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted,
    )
    .expect("bounded internally consistent provider output")
}

#[test]
fn normalizer_resolves_chunk_relative_finding_to_exact_artifact_evidence() {
    let (artifact, analysis, subject, request) = fixture();
    let file = artifact
        .files()
        .find(|file| file.normalized_path == "index.js")
        .expect("index.js");
    let item = request
        .work_items()
        .iter()
        .find(|item| item.file_id() == &file.file_id)
        .expect("index work item");
    let invocation = request
        .invocation(&artifact, item.work_item_id())
        .expect("exact invocation");
    let token = b"process.env.DEMO_TOKEN";
    let relative_start = invocation
        .untrusted()
        .bytes()
        .windows(token.len())
        .position(|window| window == token)
        .expect("evidence token");
    let context = &invocation.untrusted().contexts()[0];
    let explanation = "Exact inert credential-read surface requires review.";
    let raw = model_output(
        &request,
        item.work_item_id(),
        "no_finding",
        serde_json::json!([{
            "category": "credential_access",
            "severity": "high",
            "context_id": context.context_id(),
            "context_kind": context.kind(),
            "chunk_relative_start_byte": relative_start,
            "chunk_relative_end_byte": relative_start + token.len(),
            "explanation": explanation,
        }]),
    );
    assert!(!String::from_utf8_lossy(&raw).contains("evidence_sha256"));
    let raw_sha256 = Sha256Digest::from_bytes(&raw);
    let raw_byte_len = raw.len() as u64;
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[complete_output(item.work_item_id(), raw)],
    )
    .expect("normalize exact finding");

    let validated = normalized.structurally_validated_result();
    assert_eq!(validated.verdict(), ArtifactReviewVerdictV2::Suspicious);
    assert!(validated.has_structurally_validated_findings());
    assert!(!validated.is_authenticated());
    assert!(!validated.can_authorize_allow());
    let finding = &validated.findings()[0];
    assert_eq!(finding.file_id(), &file.file_id);
    assert_eq!(finding.selected_sha256(), &Sha256Digest::from_bytes(token));
    assert_eq!(
        finding.start_byte(),
        invocation.untrusted().start_byte() + relative_start as u64
    );
    assert_eq!(finding.explanation(), explanation);
    assert!(!finding.behavior_gate_eligible());
    let adapter_wire: serde_json::Value =
        serde_json::from_slice(normalized.adapter_normalized_output())
            .expect("strict adapter result JSON");
    assert_eq!(
        adapter_wire["findings"][0]["behavior_gate_eligible"],
        serde_json::json!(false)
    );
    assert_eq!(
        adapter_wire["findings"][0]["finding_id_sha256"],
        serde_json::json!(finding.finding_id_sha256())
    );
    assert_eq!(normalized.outcomes().len(), 1);
    assert_eq!(
        normalized.outcomes()[0].status(),
        ArtifactReviewWorkItemNormalizationStatusV2::Normalized
    );
    assert_eq!(
        normalized.outcomes()[0].provider_output_capture_sha256(),
        &raw_sha256
    );
    assert_eq!(
        normalized.outcomes()[0].provider_output_capture_byte_len(),
        raw_byte_len
    );
    assert_eq!(
        normalized.execution_report().work_item_claims()[0].status(),
        ArtifactReviewWorkItemStatusV2::Completed
    );
    assert_eq!(
        normalized.missing_work_item_ids().len(),
        request.work_items().len() - 1
    );
    assert!(!normalized
        .missing_work_item_ids()
        .iter()
        .any(|missing| missing == item.work_item_id()));
    assert!(!normalized.coverage_complete());
    assert!(!format!("{normalized:?}").contains(explanation));

    let independently_validated = decode_and_structurally_validate_artifact_review_result_v2(
        normalized.adapter_normalized_output(),
        &request,
        &artifact,
        &analysis,
        normalized.execution_report(),
    )
    .expect("independent structural self-check");
    assert_eq!(
        independently_validated.findings()[0].evidence_sha256(),
        finding.evidence_sha256()
    );
}

#[test]
fn output_order_is_canonical_and_malformed_truncated_items_fail_closed() {
    let (artifact, analysis, subject, request) = fixture();
    let first = request.work_items()[0].work_item_id().clone();
    let second = request.work_items()[1].work_item_id().clone();
    let first_raw = model_output(&request, &first, "no_finding", serde_json::json!([]));
    let second_raw = model_output(&request, &second, "suspicious", serde_json::json!([]));
    let forward = vec![
        complete_output(&first, first_raw.clone()),
        ArtifactReviewProviderOutputV2::new_truncated_capture(
            second.clone(),
            b"valid-looking prefix that is intentionally truncated".to_vec(),
            ArtifactReviewChannelIsolationV2::CollapsedPrompt,
        )
        .expect("bounded truncated output"),
    ];
    let reverse = vec![
        ArtifactReviewProviderOutputV2::new_truncated_capture(
            second.clone(),
            b"valid-looking prefix that is intentionally truncated".to_vec(),
            ArtifactReviewChannelIsolationV2::CollapsedPrompt,
        )
        .expect("bounded truncated output"),
        complete_output(&first, first_raw),
    ];
    let left = normalize_artifact_review_provider_outputs_v2(
        &subject, &artifact, &analysis, &request, &forward,
    )
    .expect("forward normalization");
    let right = normalize_artifact_review_provider_outputs_v2(
        &subject, &artifact, &analysis, &request, &reverse,
    )
    .expect("reverse normalization");
    assert_eq!(
        left.adapter_normalized_output(),
        right.adapter_normalized_output()
    );
    assert_eq!(
        left.execution_report().execution_claims_sha256(),
        right.execution_report().execution_claims_sha256()
    );
    assert_eq!(
        left.structurally_validated_result().verdict(),
        ArtifactReviewVerdictV2::Uncertain
    );
    assert!(left.structurally_validated_result().findings().is_empty());
    assert_eq!(
        left.outcomes()
            .iter()
            .find(|outcome| outcome.work_item_id() == &second)
            .expect("truncated outcome")
            .status(),
        ArtifactReviewWorkItemNormalizationStatusV2::Truncated
    );
    assert_eq!(
        left.execution_report()
            .work_item_claims()
            .iter()
            .find(|claim| claim.work_item_id() == &second)
            .expect("truncated claim")
            .status(),
        ArtifactReviewWorkItemStatusV2::Truncated
    );
    assert!(!String::from_utf8_lossy(&second_raw).contains("selected_sha256"));
}

#[test]
fn malformed_items_fail_individually_while_a_valid_positive_is_preserved() {
    let (artifact, analysis, subject, request) = fixture();
    let file = artifact
        .files()
        .find(|file| file.normalized_path == "index.js")
        .expect("index.js");
    let items = request
        .work_items()
        .iter()
        .filter(|item| item.file_id() == &file.file_id)
        .take(2)
        .collect::<Vec<_>>();
    let invocation = request
        .invocation(&artifact, items[0].work_item_id())
        .expect("invocation");
    let token = b"process.env";
    let relative_start = invocation
        .untrusted()
        .bytes()
        .windows(token.len())
        .position(|window| window == token)
        .expect("token");
    let context = &invocation.untrusted().contexts()[0];
    let positive = model_output(
        &request,
        items[0].work_item_id(),
        "uncertain",
        serde_json::json!([{
            "category": "credential_access",
            "severity": "high",
            "context_id": context.context_id(),
            "context_kind": context.kind(),
            "chunk_relative_start_byte": relative_start,
            "chunk_relative_end_byte": relative_start + token.len(),
            "explanation": "Inert exact finding survives another malformed response.",
        }]),
    );
    let malformed = b"```json\n{\"verdict\":\"no_finding\"}\n```".to_vec();
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[
            complete_output(items[0].work_item_id(), positive),
            complete_output(items[1].work_item_id(), malformed),
        ],
    )
    .expect("malformed item fails closed without suppressing positive");
    assert_eq!(
        normalized.structurally_validated_result().verdict(),
        ArtifactReviewVerdictV2::Suspicious
    );
    assert_eq!(
        normalized.structurally_validated_result().findings().len(),
        1
    );
    assert_eq!(
        normalized
            .outcomes()
            .iter()
            .find(|outcome| outcome.work_item_id() == items[1].work_item_id())
            .expect("malformed outcome")
            .status(),
        ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire
    );
    assert_eq!(
        normalized
            .execution_report()
            .work_item_claims()
            .iter()
            .find(|claim| claim.work_item_id() == items[1].work_item_id())
            .expect("captured claim")
            .status(),
        ArtifactReviewWorkItemStatusV2::Completed
    );
    let malformed_outcome = normalized
        .outcomes()
        .iter()
        .find(|outcome| outcome.work_item_id() == items[1].work_item_id())
        .expect("malformed outcome");
    assert!(!malformed_outcome.coverage_complete());
    assert_eq!(
        malformed_outcome.rejection_reasons(),
        &[ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire]
    );
}

#[test]
fn invalid_finding_sibling_marks_partial_coverage_without_erasing_a_valid_positive() {
    let (artifact, analysis, subject, request) = fixture();
    let file = artifact
        .files()
        .find(|file| file.normalized_path == "index.js")
        .expect("index.js");
    let item = request
        .work_items()
        .iter()
        .find(|item| item.file_id() == &file.file_id)
        .expect("index work item");
    let invocation = request
        .invocation(&artifact, item.work_item_id())
        .expect("invocation");
    let context = &invocation.untrusted().contexts()[0];
    let token = b"process.env";
    let relative_start = invocation
        .untrusted()
        .bytes()
        .windows(token.len())
        .position(|window| window == token)
        .expect("token");
    let findings = serde_json::json!([
        {
            "category": "credential_access",
            "severity": "high",
            "context_id": context.context_id(),
            "context_kind": context.kind(),
            "chunk_relative_start_byte": relative_start,
            "chunk_relative_end_byte": relative_start + token.len(),
            "explanation": "This structurally valid positive must survive its malformed sibling."
        },
        {
            "category": "not_a_real_category",
            "severity": "high"
        }
    ]);
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[complete_output(
            item.work_item_id(),
            model_output(&request, item.work_item_id(), "no_finding", findings),
        )],
    )
    .expect("valid sibling is salvaged");

    assert_eq!(
        normalized.structurally_validated_result().findings().len(),
        1
    );
    assert_eq!(
        normalized.structurally_validated_result().verdict(),
        ArtifactReviewVerdictV2::Suspicious
    );
    let outcome = &normalized.outcomes()[0];
    assert_eq!(
        outcome.status(),
        ArtifactReviewWorkItemNormalizationStatusV2::PartiallyNormalized
    );
    assert_eq!(outcome.declared_finding_count(), 2);
    assert_eq!(outcome.structurally_valid_finding_count(), 1);
    assert_eq!(outcome.retained_finding_count(), 1);
    assert_eq!(outcome.rejected_finding_count(), 1);
    assert_eq!(
        outcome.rejection_reasons(),
        &[ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingWire]
    );
    assert!(!outcome.coverage_complete());
    assert!(!normalized.coverage_complete());
}

#[test]
fn complete_json_marked_failed_or_truncated_keeps_positive_but_not_complete_coverage() {
    let (artifact, analysis, subject, request) = fixture();
    let file = artifact
        .files()
        .find(|file| file.normalized_path == "index.js")
        .expect("index.js");
    let item = request
        .work_items()
        .iter()
        .find(|item| item.file_id() == &file.file_id)
        .expect("index work item");
    let invocation = request
        .invocation(&artifact, item.work_item_id())
        .expect("invocation");
    let context = &invocation.untrusted().contexts()[0];
    let raw = model_output(
        &request,
        item.work_item_id(),
        "suspicious",
        serde_json::json!([{
            "category": "environment_gating",
            "severity": "high",
            "context_id": context.context_id(),
            "context_kind": context.kind(),
            "chunk_relative_start_byte": 0,
            "chunk_relative_end_byte": 1,
            "explanation": "A valid citation remains evidence even when later coverage truncated."
        }]),
    );
    let output = ArtifactReviewProviderOutputV2::new_truncated_capture(
        item.work_item_id().clone(),
        raw.clone(),
        ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted,
    )
    .expect("bounded capture");
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[output],
    )
    .expect("positive survives truncated coverage");

    assert_eq!(
        normalized.structurally_validated_result().findings().len(),
        1
    );
    assert_eq!(
        normalized.outcomes()[0].status(),
        ArtifactReviewWorkItemNormalizationStatusV2::PartiallyNormalized
    );
    assert_eq!(
        normalized.outcomes()[0].rejection_reasons(),
        &[ArtifactReviewWorkItemNormalizationStatusV2::Truncated]
    );
    assert_eq!(
        normalized.execution_report().work_item_claims()[0].status(),
        ArtifactReviewWorkItemStatusV2::Truncated
    );
    assert!(!normalized.coverage_complete());

    let failed_output = ArtifactReviewProviderOutputV2::new_failed_capture(
        item.work_item_id().clone(),
        raw,
        ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted,
        true,
    )
    .expect("bounded failed capture");
    let failed = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[failed_output],
    )
    .expect("positive survives provider failure status");
    assert_eq!(failed.structurally_validated_result().findings().len(), 1);
    assert_eq!(
        failed.outcomes()[0].status(),
        ArtifactReviewWorkItemNormalizationStatusV2::PartiallyNormalized
    );
    assert_eq!(
        failed.outcomes()[0].rejection_reasons(),
        &[ArtifactReviewWorkItemNormalizationStatusV2::ProviderFailed]
    );
    assert_eq!(
        failed.execution_report().work_item_claims()[0].status(),
        ArtifactReviewWorkItemStatusV2::Failed
    );
    assert!(!failed.coverage_complete());
}

#[test]
fn structural_finding_identity_is_stable_across_rewording_but_evidence_digest_is_not() {
    let (artifact, analysis, subject, request) = fixture();
    let file = artifact
        .files()
        .find(|file| file.normalized_path == "index.js")
        .expect("index.js");
    let item = request
        .work_items()
        .iter()
        .find(|item| item.file_id() == &file.file_id)
        .expect("index work item");
    let invocation = request
        .invocation(&artifact, item.work_item_id())
        .expect("invocation");
    let context = &invocation.untrusted().contexts()[0];
    let normalize_with_explanation = |explanation: &str| {
        normalize_artifact_review_provider_outputs_v2(
            &subject,
            &artifact,
            &analysis,
            &request,
            &[complete_output(
                item.work_item_id(),
                model_output(
                    &request,
                    item.work_item_id(),
                    "suspicious",
                    serde_json::json!([{
                        "category": "obfuscation",
                        "severity": "medium",
                        "context_id": context.context_id(),
                        "context_kind": context.kind(),
                        "chunk_relative_start_byte": 0,
                        "chunk_relative_end_byte": 1,
                        "explanation": explanation
                    }]),
                ),
            )],
        )
        .expect("normalize reworded citation")
    };
    let first = normalize_with_explanation("First bounded explanation of the same exact range.");
    let second = normalize_with_explanation("Different prose, identical structural citation.");
    let first_finding = &first.structurally_validated_result().findings()[0];
    let second_finding = &second.structurally_validated_result().findings()[0];

    assert_eq!(
        first_finding.finding_id_sha256(),
        second_finding.finding_id_sha256()
    );
    assert_ne!(
        first_finding.evidence_sha256(),
        second_finding.evidence_sha256()
    );
    assert!(!first_finding.behavior_gate_eligible());
    assert!(!second_finding.behavior_gate_eligible());
}

#[test]
fn complete_ai_no_finding_outputs_remain_uncertain_and_cannot_authorize_allow() {
    let (artifact, analysis, subject, request) = fixture();
    let outputs = request
        .work_items()
        .iter()
        .map(|item| {
            complete_output(
                item.work_item_id(),
                model_output(
                    &request,
                    item.work_item_id(),
                    "no_finding",
                    serde_json::json!([]),
                ),
            )
        })
        .collect::<Vec<_>>();
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject, &artifact, &analysis, &request, &outputs,
    )
    .expect("complete empty review graph");
    let result = normalized.structurally_validated_result();

    assert!(normalized.coverage_complete());
    assert_eq!(result.verdict(), ArtifactReviewVerdictV2::Uncertain);
    assert!(result.findings().is_empty());
    assert!(!result.is_authenticated());
    assert!(!result.can_authorize_allow());
}

#[test]
fn duplicate_unknown_and_oversized_outputs_fail_or_downgrade_without_salvage() {
    let (artifact, analysis, subject, request) = fixture();
    let item = &request.work_items()[0];
    let clean = model_output(
        &request,
        item.work_item_id(),
        "no_finding",
        serde_json::json!([]),
    );
    assert!(matches!(
        normalize_artifact_review_provider_outputs_v2(
            &subject,
            &artifact,
            &analysis,
            &request,
            &[
                complete_output(item.work_item_id(), clean.clone()),
                complete_output(item.work_item_id(), clean),
            ],
        ),
        Err(ArtifactReviewNormalizationErrorV2::DuplicateWorkItemOutput)
    ));

    let unknown = Sha256Digest::from_bytes(b"unknown work item");
    assert!(matches!(
        normalize_artifact_review_provider_outputs_v2(
            &subject,
            &artifact,
            &analysis,
            &request,
            &[complete_output(
                &unknown,
                model_output_with_invocation(
                    &unknown,
                    &Sha256Digest::from_bytes(b"unknown invocation"),
                    "no_finding",
                    serde_json::json!([]),
                ),
            )],
        ),
        Err(ArtifactReviewNormalizationErrorV2::UnknownWorkItem)
    ));

    assert!(matches!(
        ArtifactReviewProviderOutputV2::new_complete(
            item.work_item_id().clone(),
            vec![b' '; MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2 + 1],
            ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted,
        ),
        Err(ArtifactReviewProviderOutputErrorV2::OutputLimitExceeded)
    ));
    let exact_cap = vec![b'x'; MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2];
    let exact_cap_sha256 = Sha256Digest::from_bytes(&exact_cap);
    let truncated = ArtifactReviewProviderOutputV2::new_truncated_capture(
        item.work_item_id().clone(),
        exact_cap,
        ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted,
    )
    .expect("an exact-cap captured prefix is representable as truncated");
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[truncated],
    )
    .expect("truncated capture remains fail-closed");
    assert_eq!(
        normalized.outcomes()[0].status(),
        ArtifactReviewWorkItemNormalizationStatusV2::Truncated
    );
    assert_eq!(
        normalized.outcomes()[0].provider_output_capture_sha256(),
        &exact_cap_sha256
    );
    assert_eq!(
        normalized.outcomes()[0].provider_output_capture_byte_len(),
        MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2 as u64
    );
    let claim = &normalized.execution_report().work_item_claims()[0];
    assert_eq!(claim.status(), ArtifactReviewWorkItemStatusV2::Truncated);
    assert_eq!(claim.provider_output_capture_sha256(), &exact_cap_sha256);
    assert_eq!(
        claim.provider_output_capture_byte_len(),
        MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2 as u64
    );
    assert_eq!(
        normalized.structurally_validated_result().verdict(),
        ArtifactReviewVerdictV2::Uncertain
    );
}

#[test]
fn reworded_structural_duplicates_cannot_crowd_a_later_threat_class() {
    let (artifact, analysis, subject, request) = fixture();
    let first = &request.work_items()[0];
    let second = &request.work_items()[1];
    let first_invocation = request
        .invocation(&artifact, first.work_item_id())
        .expect("first invocation");
    let second_invocation = request
        .invocation(&artifact, second.work_item_id())
        .expect("second invocation");
    let first_context = &first_invocation.untrusted().contexts()[0];
    let second_context = &second_invocation.untrusted().contexts()[0];
    let first_findings = (0..256)
        .map(|index| {
            serde_json::json!({
                "category": "obfuscation",
                "severity": "medium",
                "context_id": first_context.context_id(),
                "context_kind": first_context.kind(),
                "chunk_relative_start_byte": 0,
                "chunk_relative_end_byte": 1,
                "explanation": format!("Inert bounded aggregate finding {index:03}."),
            })
        })
        .collect::<Vec<_>>();
    let second_finding = serde_json::json!([{
        "category": "process_execution",
        "severity": "high",
        "context_id": second_context.context_id(),
        "context_kind": second_context.kind(),
        "chunk_relative_start_byte": 0,
        "chunk_relative_end_byte": 1,
        "explanation": "This later item exceeds the aggregate finding ceiling.",
    }]);
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[
            complete_output(
                first.work_item_id(),
                model_output(
                    &request,
                    first.work_item_id(),
                    "suspicious",
                    serde_json::Value::Array(first_findings),
                ),
            ),
            complete_output(
                second.work_item_id(),
                model_output(
                    &request,
                    second.work_item_id(),
                    "suspicious",
                    second_finding,
                ),
            ),
        ],
    )
    .expect("structural duplicates do not consume the aggregate ceiling");
    assert_eq!(
        normalized.structurally_validated_result().findings().len(),
        2
    );
    assert!(normalized
        .structurally_validated_result()
        .findings()
        .iter()
        .any(|finding| finding.category() == ArtifactReviewFindingCategoryV2::ProcessExecution));
    assert_eq!(
        normalized.structurally_validated_result().verdict(),
        ArtifactReviewVerdictV2::Suspicious
    );
    assert_eq!(
        normalized
            .outcomes()
            .iter()
            .find(|outcome| outcome.work_item_id() == second.work_item_id())
            .expect("later-class outcome")
            .status(),
        ArtifactReviewWorkItemNormalizationStatusV2::Normalized
    );
    assert_eq!(
        normalized
            .execution_report()
            .work_item_claims()
            .iter()
            .find(|claim| claim.work_item_id() == second.work_item_id())
            .expect("later-class claim")
            .status(),
        ArtifactReviewWorkItemStatusV2::Completed
    );
    let duplicate_outcome = normalized
        .outcomes()
        .iter()
        .find(|outcome| outcome.work_item_id() == first.work_item_id())
        .expect("duplicate outcome");
    assert_eq!(duplicate_outcome.retained_finding_count(), 1);
    assert_eq!(duplicate_outcome.deduplicated_finding_count(), 255);
    assert_eq!(duplicate_outcome.rejected_finding_count(), 0);
    assert!(duplicate_outcome.coverage_complete());
}

#[test]
fn aggregate_cap_is_deterministic_and_fair_across_threat_classes() {
    let large_source = vec![b'a'; 700];
    let artifact = fixture_artifact_with_index(&large_source);
    let analysis = analyze_normalized_artifact(&artifact).expect("static analysis");
    let subject = subject(&artifact);
    let request = build_artifact_review_request_v2(&subject, &artifact, &analysis, config())
        .expect("large fixture review request");
    let file = artifact
        .files()
        .find(|file| file.normalized_path == "index.js")
        .expect("index.js");
    let item = request
        .work_items()
        .iter()
        .find(|item| item.file_id() == &file.file_id)
        .expect("large index work item");
    let invocation = request
        .invocation(&artifact, item.work_item_id())
        .expect("invocation");
    assert!(invocation.untrusted().bytes().len() > 300);
    let context = &invocation.untrusted().contexts()[0];
    let mut findings = (0..256)
        .map(|index| {
            serde_json::json!({
                "category": "obfuscation",
                "severity": "medium",
                "context_id": context.context_id(),
                "context_kind": context.kind(),
                "chunk_relative_start_byte": index,
                "chunk_relative_end_byte": index + 1,
                "explanation": format!("Distinct inert range {index:03} exercises the cap.")
            })
        })
        .collect::<Vec<_>>();
    findings.push(serde_json::json!({
        "category": "process_execution",
        "severity": "high",
        "context_id": context.context_id(),
        "context_kind": context.kind(),
        "chunk_relative_start_byte": 300,
        "chunk_relative_end_byte": 301,
        "explanation": "A later threat class must receive a fair aggregate slot."
    }));
    let normalize = || {
        normalize_artifact_review_provider_outputs_v2(
            &subject,
            &artifact,
            &analysis,
            &request,
            &[complete_output(
                item.work_item_id(),
                model_output(
                    &request,
                    item.work_item_id(),
                    "suspicious",
                    serde_json::Value::Array(findings.clone()),
                ),
            )],
        )
        .expect("fairly cap valid findings")
    };
    let first = normalize();
    let second = normalize();

    assert_eq!(
        first.adapter_normalized_output(),
        second.adapter_normalized_output(),
        "fair selection is deterministic"
    );
    let retained = first.structurally_validated_result().findings();
    assert_eq!(retained.len(), 256);
    assert_eq!(
        retained
            .iter()
            .filter(|finding| {
                finding.category() == ArtifactReviewFindingCategoryV2::ProcessExecution
            })
            .count(),
        1,
        "the later threat class cannot be crowded out"
    );
    let outcome = &first.outcomes()[0];
    assert_eq!(
        outcome.status(),
        ArtifactReviewWorkItemNormalizationStatusV2::PartiallyNormalized
    );
    assert_eq!(outcome.declared_finding_count(), 257);
    assert_eq!(outcome.structurally_valid_finding_count(), 257);
    assert_eq!(outcome.retained_finding_count(), 256);
    assert_eq!(outcome.rejected_finding_count(), 1);
    assert_eq!(
        outcome.rejection_reasons(),
        &[
            ArtifactReviewWorkItemNormalizationStatusV2::TooManyFindings,
            ArtifactReviewWorkItemNormalizationStatusV2::AggregateFindingLimitExceeded,
        ]
    );
    assert!(!first.coverage_complete());
}

#[test]
fn invalid_context_range_and_invalid_top_level_json_fail_closed() {
    let (artifact, analysis, subject, request) = fixture();
    let index_file = artifact
        .files()
        .find(|file| file.normalized_path == "index.js")
        .expect("index.js");
    let item = request
        .work_items()
        .iter()
        .find(|item| item.file_id() == &index_file.file_id)
        .expect("index work item");
    let invocation = request
        .invocation(&artifact, item.work_item_id())
        .expect("invocation");
    let context = &invocation.untrusted().contexts()[0];
    let base_finding = |context_id: Sha256Digest, end: usize| {
        serde_json::json!([{
            "category": "obfuscation",
            "severity": "medium",
            "context_id": context_id,
            "context_kind": context.kind(),
            "chunk_relative_start_byte": 0,
            "chunk_relative_end_byte": end,
            "explanation": "Inert finding used to exercise strict normalization.",
        }])
    };

    let wrong_context = model_output(
        &request,
        item.work_item_id(),
        "suspicious",
        base_finding(Sha256Digest::from_bytes(b"wrong context"), 1),
    );
    let out_of_range = model_output(
        &request,
        item.work_item_id(),
        "suspicious",
        base_finding(
            context.context_id().clone(),
            invocation.untrusted().bytes().len() + 1,
        ),
    );
    let mut unknown_field: serde_json::Value = serde_json::from_slice(&model_output(
        &request,
        item.work_item_id(),
        "no_finding",
        serde_json::json!([]),
    ))
    .unwrap();
    unknown_field["extra"] = serde_json::json!(true);
    let unknown_field = serde_json::to_vec(&unknown_field).unwrap();
    let mut trailing = model_output(
        &request,
        item.work_item_id(),
        "no_finding",
        serde_json::json!([]),
    );
    trailing.extend_from_slice(b"{}");
    let snowman = "☃".as_bytes();
    let snowman_start = invocation
        .untrusted()
        .bytes()
        .windows(snowman.len())
        .position(|window| window == snowman)
        .expect("snowman");
    let split_unicode = model_output(
        &request,
        item.work_item_id(),
        "suspicious",
        serde_json::json!([{
            "category": "obfuscation",
            "severity": "medium",
            "context_id": context.context_id(),
            "context_kind": context.kind(),
            "chunk_relative_start_byte": snowman_start + 1,
            "chunk_relative_end_byte": snowman_start + 2,
            "explanation": "Range splits one inert UTF-8 code point.",
        }]),
    );
    let control_explanation = model_output(
        &request,
        item.work_item_id(),
        "suspicious",
        serde_json::json!([{
            "category": "obfuscation",
            "severity": "medium",
            "context_id": context.context_id(),
            "context_kind": context.kind(),
            "chunk_relative_start_byte": 0,
            "chunk_relative_end_byte": 1,
            "explanation": "line one\nline two",
        }]),
    );

    for (raw, expected) in [
        (
            wrong_context,
            ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingReference,
        ),
        (
            out_of_range,
            ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence,
        ),
        (
            unknown_field,
            ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire,
        ),
        (
            trailing,
            ArtifactReviewWorkItemNormalizationStatusV2::InvalidModelOutputWire,
        ),
        (
            split_unicode,
            ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence,
        ),
        (
            control_explanation,
            ArtifactReviewWorkItemNormalizationStatusV2::InvalidFindingEvidence,
        ),
    ] {
        let normalized = normalize_artifact_review_provider_outputs_v2(
            &subject,
            &artifact,
            &analysis,
            &request,
            &[complete_output(item.work_item_id(), raw)],
        )
        .expect("invalid item is represented fail-closed");
        assert_eq!(normalized.outcomes()[0].status(), expected);
        assert_eq!(
            normalized.execution_report().work_item_claims()[0].status(),
            ArtifactReviewWorkItemStatusV2::Completed
        );
        assert!(normalized
            .structurally_validated_result()
            .findings()
            .is_empty());
        assert_eq!(
            normalized.structurally_validated_result().verdict(),
            ArtifactReviewVerdictV2::Uncertain
        );
    }

    let unicode_explanation = "🦀".repeat(200);
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[complete_output(
            item.work_item_id(),
            model_output(
                &request,
                item.work_item_id(),
                "suspicious",
                serde_json::json!([{
                    "category": "obfuscation",
                    "severity": "medium",
                    "context_id": context.context_id(),
                    "context_kind": context.kind(),
                    "chunk_relative_start_byte": 0,
                    "chunk_relative_end_byte": 1,
                    "explanation": unicode_explanation,
                }]),
            ),
        )],
    )
    .expect("JSON Schema and runtime both use Unicode character length");
    assert_eq!(
        normalized.outcomes()[0].status(),
        ArtifactReviewWorkItemNormalizationStatusV2::Normalized
    );
    assert_eq!(
        normalized.structurally_validated_result().verdict(),
        ArtifactReviewVerdictV2::Suspicious
    );

    let boundary_explanation = "Exact snowman range is valid before boundary tampering.";
    let valid_boundary = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &request,
        &[complete_output(
            item.work_item_id(),
            model_output(
                &request,
                item.work_item_id(),
                "suspicious",
                serde_json::json!([{
                    "category": "obfuscation",
                    "severity": "medium",
                    "context_id": context.context_id(),
                    "context_kind": context.kind(),
                    "chunk_relative_start_byte": snowman_start,
                    "chunk_relative_end_byte": snowman_start + snowman.len(),
                    "explanation": boundary_explanation,
                }]),
            ),
        )],
    )
    .expect("valid UTF-8 boundary finding");
    let mut fabricated: serde_json::Value =
        serde_json::from_slice(valid_boundary.adapter_normalized_output()).unwrap();
    let split_start = invocation.untrusted().start_byte() + snowman_start as u64 + 1;
    let split_end = split_start + 1;
    let selected_sha256 =
        Sha256Digest::from_bytes(&index_file.bytes()[split_start as usize..split_end as usize]);
    let start_line = fabricated["findings"][0]["start_line"].as_u64().unwrap();
    let end_line = fabricated["findings"][0]["end_line"].as_u64().unwrap();
    let evidence_sha256 =
        artifact_review_finding_evidence_sha256_v2(ArtifactReviewFindingEvidenceInputV2 {
            request_sha256: &request.request_sha256().unwrap(),
            work_item_id: item.work_item_id(),
            category: ArtifactReviewFindingCategoryV2::Obfuscation,
            severity: ArtifactReviewFindingSeverityV2::Medium,
            file_id: &index_file.file_id,
            chunk_id: item.chunk_id(),
            context_id: context.context_id(),
            context_kind: context.kind(),
            start_byte: split_start,
            end_byte: split_end,
            start_line,
            end_line,
            selected_sha256: &selected_sha256,
            explanation: boundary_explanation,
        });
    fabricated["findings"][0]["start_byte"] = serde_json::json!(split_start);
    fabricated["findings"][0]["end_byte"] = serde_json::json!(split_end);
    fabricated["findings"][0]["selected_sha256"] = serde_json::json!(selected_sha256);
    fabricated["findings"][0]["evidence_sha256"] = serde_json::json!(evidence_sha256);
    let fabricated = serde_json::to_vec(&fabricated).unwrap();
    let fabricated_report = ArtifactReviewExecutionReportV2::from_adapter_claims(
        &request,
        valid_boundary
            .execution_report()
            .work_item_claims()
            .to_vec(),
        &fabricated,
    )
    .expect("structurally bound fabricated report");
    assert!(matches!(
        decode_and_structurally_validate_artifact_review_result_v2(
            &fabricated,
            &request,
            &artifact,
            &analysis,
            &fabricated_report,
        ),
        Err(ArtifactReviewErrorV2::InvalidFindingEvidence)
    ));
}

#[test]
fn raw_model_output_cannot_be_replayed_across_request_or_model_settings() {
    let (artifact, analysis, subject, first_request) = fixture();
    let mut changed_config = config();
    changed_config.inference.seed += 1;
    let second_request =
        build_artifact_review_request_v2(&subject, &artifact, &analysis, changed_config)
            .expect("second request");
    let item = &first_request.work_items()[0];
    assert_eq!(
        item.work_item_id(),
        second_request.work_items()[0].work_item_id(),
        "work item alone intentionally does not bind model settings"
    );
    assert_ne!(
        first_request
            .invocation_sha256(item.work_item_id())
            .unwrap(),
        second_request
            .invocation_sha256(item.work_item_id())
            .unwrap()
    );
    let invocation = first_request
        .invocation(&artifact, item.work_item_id())
        .expect("first invocation");
    let context = &invocation.untrusted().contexts()[0];
    let replayed = model_output(
        &first_request,
        item.work_item_id(),
        "suspicious",
        serde_json::json!([{
            "category": "obfuscation",
            "severity": "medium",
            "context_id": context.context_id(),
            "context_kind": context.kind(),
            "chunk_relative_start_byte": 0,
            "chunk_relative_end_byte": 1,
            "explanation": "Request-bound inert finding must not be re-attributed.",
        }]),
    );
    let normalized = normalize_artifact_review_provider_outputs_v2(
        &subject,
        &artifact,
        &analysis,
        &second_request,
        &[complete_output(item.work_item_id(), replayed)],
    )
    .expect("replay becomes a failed per-item outcome");
    assert_eq!(
        normalized.outcomes()[0].status(),
        ArtifactReviewWorkItemNormalizationStatusV2::ModelOutputBindingMismatch
    );
    assert_eq!(
        normalized.execution_report().work_item_claims()[0].status(),
        ArtifactReviewWorkItemStatusV2::Completed
    );
    assert!(normalized
        .structurally_validated_result()
        .findings()
        .is_empty());
    assert_eq!(
        normalized.structurally_validated_result().verdict(),
        ArtifactReviewVerdictV2::Uncertain
    );
}
