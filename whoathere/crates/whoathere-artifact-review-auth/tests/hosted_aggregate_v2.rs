use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{Cursor, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, NormalizedArtifact, Sha256Digest,
};
use whoathere_artifact_review_auth::{
    artifact_review_expected_work_set_sha256_v2, canonical_artifact_review_lineage_scope_v2,
    hosted_runtime_challenge_v3, sign_hosted_provider_artifact_review_evidence_v2,
    verify_and_accept_hosted_provider_artifact_review_evidence_v2, ArtifactReviewAuthErrorV2,
    ArtifactReviewChallengeAuthorityV2, ArtifactReviewChallengeBindingV2,
    ArtifactReviewChallengeDraftV2, ArtifactReviewEvidenceCompletenessV2,
    ArtifactReviewEvidenceModelIdentityPostureV2, ArtifactReviewEvidenceRunContextV2,
    ArtifactReviewKeyIdentityV2, ArtifactReviewKeyRegistryV2, ArtifactReviewSigningKeyV2,
    ArtifactReviewSubjectBindingV2, ExplicitDigestStateV2,
    SignedHostedArtifactReviewEvidencePackageV2, UnauthenticatedImportedHostedInvocationV3,
    HOSTED_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_SCHEMA_V2,
};
use whoathere_artifact_review_runtime::{
    hosted_cli_provider_identity_v2, inspect_hosted_cli_executable_v2, ArtifactAiProviderErrorV2,
    ArtifactAiProviderKindV2, ArtifactReviewCancellationTokenV2, AuthorizedHostedCliProviderV2,
    HostedCliRuntimePolicyV2, VerifiedHostedRuntimeBatchV3, VerifiedHostedRuntimeRowStateV3,
    HOSTED_AUTH_HOME_MARKER_CONTENT_V3, HOSTED_AUTH_HOME_MARKER_FILE_V3,
};
use whoathere_detector::{
    analyze_normalized_artifact, artifact_review_adapter_result_schema_sha256_v2,
    artifact_review_prompt_template_sha256_v2, build_artifact_review_request_v2,
    ArtifactReviewChannelIsolationV2, ArtifactReviewConfigV2, ArtifactReviewInferenceSettingsV2,
    ArtifactReviewModelIdentityV2, ArtifactReviewPrivacyPostureV2, ArtifactReviewPromptIdentityV2,
    ArtifactReviewProviderOutputV2, ArtifactReviewRequestV2, ArtifactReviewVerdictV2,
    ArtifactStaticAnalysis, ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2,
    ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2, ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

struct PrivateRoot(PathBuf);

impl PrivateRoot {
    fn new() -> Self {
        for _ in 0..128 {
            let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "whoathere-hosted-auth-test-{}-{counter}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create private root: {error}"),
            }
        }
        panic!("could not create private test root")
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    artifact: NormalizedArtifact,
    analysis: ArtifactStaticAnalysis,
    subject: ArtifactEvidenceSubjectV2,
    request: ArtifactReviewRequestV2,
}

fn digest(label: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(label.as_bytes())
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time after epoch")
        .as_secs()
}

fn assert_no_numbers_or_nulls(value: &serde_json::Value, path: &str) {
    match value {
        serde_json::Value::Null => panic!("canonical hosted manifest contains null at {path}"),
        serde_json::Value::Number(_) => {
            panic!("canonical hosted manifest contains a JSON number at {path}")
        }
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                assert_no_numbers_or_nulls(value, &format!("{path}[{index}]"));
            }
        }
        serde_json::Value::Object(entries) => {
            for (key, value) in entries {
                assert_no_numbers_or_nulls(value, &format!("{path}.{key}"));
            }
        }
        serde_json::Value::Bool(_) | serde_json::Value::String(_) => {}
    }
}

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
            .expect("append fixture");
    }
    archive
        .into_inner()
        .expect("finish archive")
        .finish()
        .expect("finish gzip")
}

fn fixture_with_policy(policy_label: &str) -> Fixture {
    let bytes = tar_gzip(&[
        (
            "package/package.json",
            br#"{"name":"hosted-auth-fixture","version":"1.0.0","scripts":{"postinstall":"node -e 'process.env.INERT_TOKEN'"},"main":"index.js"}"#,
            0o644,
        ),
        ("package/index.js", b"module.exports = 1;\n", 0o644),
    ]);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("hosted-auth-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:hosted-auth-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-15T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "hosted-auth-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "hosted-auth-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "hosted-artifact-review-auth-test.v3".to_string(),
            requires_external_dependency_resolution: false,
        },
        &bytes,
        ArtifactFormat::NpmTarGzip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize fixture");
    let artifact_sha256 = artifact.manifest.artifact_sha256.clone();
    let subject = ArtifactEvidenceSubjectV2::new(
        artifact_sha256.as_str(),
        digest("hosted-auth-envelope").as_str(),
        artifact.manifest.manifest_sha256.as_str(),
        canonical_cas_object_key_for_artifact(artifact_sha256.as_str()).expect("CAS key"),
    )
    .expect("subject");
    let analysis = analyze_normalized_artifact(&artifact).expect("analysis");
    let request = build_artifact_review_request_v2(
        &subject,
        &artifact,
        &analysis,
        ArtifactReviewConfigV2 {
            policy_sha256: digest(policy_label),
            provider: hosted_cli_provider_identity_v2(ArtifactAiProviderKindV2::Claude),
            model: ArtifactReviewModelIdentityV2::hosted_opaque(
                "claude-inert-opaque-2026-07-15",
                "provider-hosted-opaque-version-2026-07-15",
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
    .expect("request");
    Fixture {
        artifact,
        analysis,
        subject,
        request,
    }
}

fn fixture() -> Fixture {
    fixture_with_policy("hosted-auth-policy")
}

fn key_identity() -> ArtifactReviewKeyIdentityV2 {
    ArtifactReviewKeyIdentityV2::new_host_control_plane(
        "hosted-auth-test",
        "whoathere-host-control",
        "hosted-auth-test-key",
        1,
    )
    .expect("key identity")
}

fn signer() -> ArtifactReviewSigningKeyV2 {
    let now = now_seconds();
    let mut seed = [23_u8; 32];
    ArtifactReviewSigningKeyV2::from_seed(
        key_identity(),
        &mut seed,
        now.saturating_sub(60),
        now + 3_600,
        None,
    )
    .expect("signer")
}

fn context(
    fixture: &Fixture,
    authority: &ArtifactReviewChallengeAuthorityV2,
    evidence_id: &str,
    run_id: &str,
) -> ArtifactReviewEvidenceRunContextV2 {
    let now = now_seconds();
    let subject =
        ArtifactReviewSubjectBindingV2::from_subject(&fixture.subject).expect("subject binding");
    let lineage_scope =
        canonical_artifact_review_lineage_scope_v2(&subject).expect("lineage scope");
    let challenge = authority
        .issue(
            ArtifactReviewChallengeBindingV2::new(ArtifactReviewChallengeDraftV2 {
                evidence_id: evidence_id.to_string(),
                run_id: run_id.to_string(),
                subject,
                policy_sha256: fixture.request.policy_sha256().clone(),
                request_sha256: fixture.request.request_sha256().expect("request digest"),
                expected_work_set_sha256: artifact_review_expected_work_set_sha256_v2(
                    &fixture.request,
                )
                .expect("work set"),
                expected_work_item_count: fixture.request.work_items().len() as u32,
                key_identity: key_identity(),
                lineage_scope,
                predecessor_evidence_sha256: ExplicitDigestStateV2::Absent,
                issued_at_unix_seconds: now.saturating_sub(2),
                expires_at_unix_seconds: now + 600,
            })
            .expect("challenge binding"),
        )
        .expect("challenge")
        .into_challenge();
    ArtifactReviewEvidenceRunContextV2::new(
        challenge,
        digest("hosted-auth-control-plane-build"),
        120,
    )
    .expect("context")
}

fn fake_client_path() -> PathBuf {
    PathBuf::from(env!(
        "CARGO_BIN_EXE_whoathere-auth-inert-hosted-subscription-cli"
    ))
}

fn create_private_auth_home(root: &PrivateRoot, mode: Option<&str>) -> PathBuf {
    let auth_home = root.path().join("auth-home");
    let mut auth_builder = DirBuilder::new();
    auth_builder.mode(0o700);
    auth_builder.create(&auth_home).expect("auth home");
    let mut marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(auth_home.join(HOSTED_AUTH_HOME_MARKER_FILE_V3))
        .expect("auth home marker");
    marker
        .write_all(HOSTED_AUTH_HOME_MARKER_CONTENT_V3)
        .expect("write auth home marker");
    if let Some(mode) = mode {
        fs::write(
            auth_home.join(".whoathere-inert-hosted-cli-mode"),
            format!("{mode}\n"),
        )
        .expect("write inert client mode");
    }
    assert_eq!(
        fs::metadata(&auth_home)
            .expect("auth home metadata")
            .permissions()
            .mode()
            & 0o077,
        0
    );
    auth_home
}

fn authorization_for(fixture: &Fixture, executable: PathBuf) -> AuthorizedHostedCliProviderV2 {
    let executable_sha256 = inspect_hosted_cli_executable_v2(&executable)
        .expect("inspect inert hosted client")
        .sha256()
        .clone();
    AuthorizedHostedCliProviderV2::new_claude_subscription(
        &fixture.request,
        executable,
        executable_sha256,
    )
    .expect("authorize inert hosted client")
}

fn invoke_sealed_batch(
    fixture: &Fixture,
    context: &ArtifactReviewEvidenceRunContextV2,
    mode: Option<&str>,
) -> Result<VerifiedHostedRuntimeBatchV3, ArtifactAiProviderErrorV2> {
    let root = PrivateRoot::new();
    let auth_home = create_private_auth_home(&root, mode);
    let policy = HostedCliRuntimePolicyV2::new(
        root.path().join("runtime"),
        auth_home,
        Duration::from_secs(5),
        Duration::from_millis(250),
    )
    .expect("runtime policy");
    let authorization = authorization_for(fixture, fake_client_path());
    let challenge = hosted_runtime_challenge_v3(context, &fixture.request)
        .expect("pre-challenged runtime token");
    authorization.invoke_verified_batch_v3(
        challenge,
        &fixture.request,
        &fixture.artifact,
        &policy,
        &ArtifactReviewCancellationTokenV2::new(),
    )
}

fn sign_batch(
    fixture: &Fixture,
    context: &ArtifactReviewEvidenceRunContextV2,
    batch: VerifiedHostedRuntimeBatchV3,
    signer: &ArtifactReviewSigningKeyV2,
    authority: &ArtifactReviewChallengeAuthorityV2,
) -> Result<SignedHostedArtifactReviewEvidencePackageV2, ArtifactReviewAuthErrorV2> {
    sign_hosted_provider_artifact_review_evidence_v2(
        &fixture.subject,
        &fixture.artifact,
        &fixture.analysis,
        &fixture.request,
        context,
        batch,
        signer,
        authority,
    )
}

fn unauthenticated_no_finding_output(fixture: &Fixture) -> ArtifactReviewProviderOutputV2 {
    let item = &fixture.request.work_items()[0];
    let bytes = serde_json::to_vec(&serde_json::json!({
        "schema_version": ARTIFACT_REVIEW_MODEL_OUTPUT_SCHEMA_V2,
        "work_item_id": item.work_item_id(),
        "invocation_sha256": fixture.request.invocation_sha256(item.work_item_id()).expect("invocation digest"),
        "verdict": "no_finding",
        "findings": [],
    }))
    .expect("model output");
    ArtifactReviewProviderOutputV2::new_complete(
        item.work_item_id().clone(),
        bytes,
        ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted,
    )
    .expect("bounded imported output")
}

#[test]
fn real_runtime_positive_and_failed_sibling_roundtrip_is_suspicious_incomplete_and_never_allows() {
    let fixture = fixture();
    let authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
    let context = context(&fixture, &authority, "hosted-runtime", "run-runtime");
    let signer = signer();
    let registry =
        ArtifactReviewKeyRegistryV2::new([signer.verification_record()]).expect("registry");
    let batch = invoke_sealed_batch(&fixture, &context, Some("mixed_failure"))
        .expect("sealed mixed-success runtime batch");
    assert!(batch
        .rows()
        .iter()
        .any(|row| row.state() == VerifiedHostedRuntimeRowStateV3::Complete));
    assert!(batch
        .rows()
        .iter()
        .any(|row| row.state() == VerifiedHostedRuntimeRowStateV3::Failed));
    assert!(!batch.coverage_complete());

    let package = sign_batch(&fixture, &context, batch, &signer, &authority)
        .expect("sign sealed hosted evidence");
    assert!(!package.can_authorize_allow());
    let (statement, material) = package.into_parts();
    let manifest: serde_json::Value =
        serde_json::from_slice(material.aggregate_manifest_bytes()).expect("manifest");
    assert_eq!(
        manifest["schema_version"],
        HOSTED_ARTIFACT_REVIEW_AGGREGATE_MANIFEST_SCHEMA_V2
    );
    assert_eq!(
        manifest["signer_attestation_scope"],
        "host_observed_adapter_evidence_only"
    );
    assert_eq!(manifest["admission_authority"], "none");
    assert_eq!(
        manifest["model_identity_posture"],
        "provider_hosted_opaque_version"
    );
    assert_eq!(
        manifest["runtime_model_identity_posture"],
        "provider_hosted_opaque_version"
    );
    assert_eq!(
        manifest["hosted_receipt_projection"],
        "whoathere.hosted_receipt.decimal_strings.tagged_absence.v3"
    );
    assert_eq!(
        manifest["runtime_batch_schema"],
        "whoathere.verified_hosted_runtime_batch.v3"
    );
    assert_eq!(manifest["runtime_coverage_complete"], false);
    assert_no_numbers_or_nulls(&manifest, "$");

    let authenticated = verify_and_accept_hosted_provider_artifact_review_evidence_v2(
        SignedHostedArtifactReviewEvidencePackageV2::from_parts(statement, material),
        &fixture.subject,
        &fixture.artifact,
        &fixture.analysis,
        &fixture.request,
        &context,
        &registry,
        &authority,
    )
    .expect("authenticate hosted evidence");
    assert!(authenticated.is_authenticated());
    assert!(!authenticated.is_complete());
    assert!(!authenticated.can_authorize_allow());
    assert_eq!(
        authenticated.statement().completeness(),
        ArtifactReviewEvidenceCompletenessV2::Incomplete
    );
    assert_eq!(
        authenticated.statement().model_identity_posture(),
        ArtifactReviewEvidenceModelIdentityPostureV2::ProviderHostedOpaqueVersion
    );
    assert_eq!(
        authenticated.statement().model_identity_sha256(),
        &fixture.request.model().identity_sha256()
    );
    assert_eq!(
        authenticated.result().verdict(),
        ArtifactReviewVerdictV2::Suspicious
    );
    assert!(!authenticated.result().findings().is_empty());
    assert!(authenticated
        .result()
        .findings()
        .iter()
        .all(|finding| !finding.behavior_gate_eligible()));
    assert!(authenticated
        .statement()
        .limitations()
        .contains(&"hosted_provider_execution_client_non_zero_exit".to_string()));
}

#[test]
fn arbitrary_imported_receipt_and_output_pair_is_explicitly_non_signable() {
    let fixture = fixture();
    let imported = UnauthenticatedImportedHostedInvocationV3::from_imported_parts(
        unauthenticated_no_finding_output(&fixture),
        br#"{"schema_version":"synthetic-untrusted-receipt"}"#.to_vec(),
    )
    .expect("bounded unauthenticated import");

    assert!(!imported.is_authenticated());
    assert!(!imported.can_be_signed());
    assert!(!imported.can_authorize_allow());
}

#[test]
fn prechallenged_runtime_batch_cannot_be_rebound_to_another_context() {
    let fixture = fixture();
    let authority_a = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority A");
    let authority_b = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority B");
    let context_a = context(&fixture, &authority_a, "hosted-bind-a", "run-bind-a");
    let context_b = context(&fixture, &authority_b, "hosted-bind-b", "run-bind-b");
    let batch = invoke_sealed_batch(&fixture, &context_a, None).expect("sealed batch A");
    let error = sign_batch(&fixture, &context_b, batch, &signer(), &authority_b)
        .expect_err("challenge rebind must fail");
    assert_eq!(error, ArtifactReviewAuthErrorV2::ChallengeBindingMismatch);
}

#[test]
fn swapped_runtime_material_cannot_validate_under_another_signed_statement() {
    let fixture = fixture();
    let authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
    let context = context(&fixture, &authority, "hosted-swap", "run-swap");
    let signer = signer();
    let registry =
        ArtifactReviewKeyRegistryV2::new([signer.verification_record()]).expect("registry");
    let package_a = sign_batch(
        &fixture,
        &context,
        invoke_sealed_batch(&fixture, &context, None).expect("batch A"),
        &signer,
        &authority,
    )
    .expect("package A");
    std::thread::sleep(Duration::from_millis(2));
    let package_b = sign_batch(
        &fixture,
        &context,
        invoke_sealed_batch(&fixture, &context, None).expect("batch B"),
        &signer,
        &authority,
    )
    .expect("package B");
    let (statement_a, _material_a) = package_a.into_parts();
    let (_statement_b, material_b) = package_b.into_parts();
    let error = verify_and_accept_hosted_provider_artifact_review_evidence_v2(
        SignedHostedArtifactReviewEvidencePackageV2::from_parts(statement_a, material_b),
        &fixture.subject,
        &fixture.artifact,
        &fixture.analysis,
        &fixture.request,
        &context,
        &registry,
        &authority,
    )
    .expect_err("swapped runtime material must fail");
    assert!(matches!(
        error,
        ArtifactReviewAuthErrorV2::AggregateManifestMismatch
            | ArtifactReviewAuthErrorV2::InvalidStatement
            | ArtifactReviewAuthErrorV2::SignatureVerificationFailed
    ));
}

#[test]
fn second_distinct_runtime_batch_for_one_challenge_is_replay_or_equivocation() {
    let fixture = fixture();
    let authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
    let context = context(&fixture, &authority, "hosted-replay", "run-replay");
    let signer = signer();
    let registry =
        ArtifactReviewKeyRegistryV2::new([signer.verification_record()]).expect("registry");
    let package_a = sign_batch(
        &fixture,
        &context,
        invoke_sealed_batch(&fixture, &context, None).expect("batch A"),
        &signer,
        &authority,
    )
    .expect("package A");
    std::thread::sleep(Duration::from_millis(2));
    let package_b = sign_batch(
        &fixture,
        &context,
        invoke_sealed_batch(&fixture, &context, None).expect("batch B"),
        &signer,
        &authority,
    )
    .expect("package B");
    verify_and_accept_hosted_provider_artifact_review_evidence_v2(
        package_a,
        &fixture.subject,
        &fixture.artifact,
        &fixture.analysis,
        &fixture.request,
        &context,
        &registry,
        &authority,
    )
    .expect("first evidence accepted");
    let error = verify_and_accept_hosted_provider_artifact_review_evidence_v2(
        package_b,
        &fixture.subject,
        &fixture.artifact,
        &fixture.analysis,
        &fixture.request,
        &context,
        &registry,
        &authority,
    )
    .expect_err("second distinct evidence rejected");
    assert_eq!(error, ArtifactReviewAuthErrorV2::ReplayOrEquivocation);
}

#[test]
fn model_mismatch_or_api_authentication_can_never_reach_a_signed_package() {
    let fixture = fixture();
    let authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
    let model_context = context(&fixture, &authority, "hosted-model", "run-model");
    if let Ok(batch) = invoke_sealed_batch(&fixture, &model_context, Some("model_mismatch")) {
        let error = sign_batch(&fixture, &model_context, batch, &signer(), &authority)
            .expect_err("model mismatch must not sign");
        assert_eq!(error, ArtifactReviewAuthErrorV2::InvalidRuntimeEvidence);
    }

    let auth_authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
    let auth_context = context(&fixture, &auth_authority, "hosted-auth", "run-auth");
    let error = invoke_sealed_batch(&fixture, &auth_context, Some("api_key"))
        .expect_err("API-key mode must not seal a subscription batch");
    assert!(matches!(
        error,
        ArtifactAiProviderErrorV2::ProviderNotReady
            | ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid
    ));
}

#[test]
fn changed_client_identity_and_request_rebinding_never_produce_a_sealed_batch() {
    let fixture = fixture();
    let authority = ArtifactReviewChallengeAuthorityV2::new_memory_only().expect("authority");
    let context = context(&fixture, &authority, "hosted-client", "run-client");
    let root = PrivateRoot::new();
    let copied_client = root.path().join("hosted-client");
    fs::copy(fake_client_path(), &copied_client).expect("copy inert client");
    let mut permissions = fs::metadata(&copied_client)
        .expect("copied client metadata")
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&copied_client, permissions).expect("set client mode");
    let authorization = authorization_for(&fixture, copied_client.clone());
    OpenOptions::new()
        .append(true)
        .open(&copied_client)
        .expect("open client for mutation")
        .write_all(b"\0")
        .expect("mutate held client identity");
    let auth_home = create_private_auth_home(&root, None);
    let policy = HostedCliRuntimePolicyV2::new(
        root.path().join("runtime"),
        auth_home,
        Duration::from_secs(5),
        Duration::from_millis(250),
    )
    .expect("policy");
    let challenge = hosted_runtime_challenge_v3(&context, &fixture.request).expect("challenge");
    assert!(authorization
        .invoke_verified_batch_v3(
            challenge,
            &fixture.request,
            &fixture.artifact,
            &policy,
            &ArtifactReviewCancellationTokenV2::new(),
        )
        .is_err());

    let different = fixture_with_policy("hosted-auth-different-policy");
    let different_authorization = authorization_for(&different, fake_client_path());
    let different_root = PrivateRoot::new();
    let different_policy = HostedCliRuntimePolicyV2::new(
        different_root.path().join("runtime"),
        create_private_auth_home(&different_root, None),
        Duration::from_secs(5),
        Duration::from_millis(250),
    )
    .expect("different policy");
    let request_bound_challenge =
        hosted_runtime_challenge_v3(&context, &fixture.request).expect("request-bound challenge");
    assert!(different_authorization
        .invoke_verified_batch_v3(
            request_bound_challenge,
            &different.request,
            &different.artifact,
            &different_policy,
            &ArtifactReviewCancellationTokenV2::new(),
        )
        .is_err());
}
