use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, NormalizedArtifact, Sha256Digest,
};
use whoathere_detector::{
    analyze_normalized_artifact, artifact_review_adapter_result_schema_sha256_v2,
    artifact_review_prompt_template_sha256_v2, build_artifact_review_request_v2,
    decode_and_structurally_validate_artifact_review_result_v2, ArtifactReviewChannelIsolationV2,
    ArtifactReviewConfigV2, ArtifactReviewCoverageCompletenessV2, ArtifactReviewErrorV2,
    ArtifactReviewExecutionReportV2, ArtifactReviewFileDispositionV2,
    ArtifactReviewInferenceSettingsV2, ArtifactReviewModelIdentityV2,
    ArtifactReviewPrivacyPostureV2, ArtifactReviewPromptIdentityV2,
    ArtifactReviewProviderIdentityV2, ArtifactReviewRequestV2, ArtifactReviewWorkItemStatusV2,
    ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2, ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2,
    ARTIFACT_REVIEW_RESULT_SCHEMA_V2, MAX_ARTIFACT_REVIEW_CHUNK_BYTES_V2,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use zip::write::SimpleFileOptions;

fn envelope(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    filename: &str,
    format: ArtifactFormat,
    bytes: &[u8],
    requires_external_dependency_resolution: bool,
) -> ArtifactEnvelope {
    ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem,
            package_name: Some(name.to_string()),
            package_version: Some(version.to_string()),
            source_coordinate: format!("fixture:{name}@{version}"),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-09T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: filename.to_string(),
            declared_format: Some(format),
            custody_reference: format!("inert-artifact-review-ecosystem:{filename}"),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "artifact-review-ecosystem-test.v2".to_string(),
            requires_external_dependency_resolution,
        },
        bytes,
        format,
    )
}

fn subject(artifact: &NormalizedArtifact) -> ArtifactEvidenceSubjectV2 {
    let artifact_digest = artifact.manifest.artifact_sha256.as_str();
    ArtifactEvidenceSubjectV2::new(
        artifact_digest,
        Sha256Digest::from_bytes(b"inert ecosystem acquisition envelope").to_string(),
        artifact.manifest.manifest_sha256.to_string(),
        canonical_cas_object_key_for_artifact(artifact_digest).expect("canonical object key"),
    )
    .expect("valid exact subject")
}

fn config() -> ArtifactReviewConfigV2 {
    ArtifactReviewConfigV2 {
        policy_sha256: Sha256Digest::from_bytes(b"artifact review ecosystem policy"),
        provider: ArtifactReviewProviderIdentityV2 {
            adapter_id: "local-inert-review-adapter".to_string(),
            adapter_version: "2.0.0".to_string(),
            adapter_sha256: Sha256Digest::from_bytes(b"inert provider adapter"),
        },
        model: ArtifactReviewModelIdentityV2::measured_local(
            "inert-review-model",
            "2026-07-09",
            Sha256Digest::from_bytes(b"immutable inert model content"),
        ),
        prompt: ArtifactReviewPromptIdentityV2 {
            template_id: ARTIFACT_REVIEW_PROMPT_TEMPLATE_ID_V2.to_string(),
            template_version: ARTIFACT_REVIEW_PROMPT_TEMPLATE_VERSION_V2.to_string(),
            template_sha256: artifact_review_prompt_template_sha256_v2(),
        },
        adapter_result_schema_sha256: artifact_review_adapter_result_schema_sha256_v2(),
        privacy_posture: ArtifactReviewPrivacyPostureV2::LocalOnly,
        inference: ArtifactReviewInferenceSettingsV2 {
            seed: 17,
            temperature_milli: 0,
            top_p_milli: 1_000,
            context_tokens: 16_384,
            max_output_tokens: 2_048,
        },
    }
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 3) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 15) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 63) as usize] as char);
        }
    }
    output
}

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest_hex = whoathere_hash::sha256_hex(bytes);
    let digest_bytes = digest_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("digest is ASCII");
            u8::from_str_radix(pair, 16).expect("digest is hexadecimal")
        })
        .collect::<Vec<_>>();
    format!("sha256={}", base64_url_no_pad(&digest_bytes))
}

fn wheel_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let record_path = "review_wheel-1.0.0.dist-info/RECORD";
    let mut record = String::new();
    for (path, bytes) in entries {
        record.push_str(path);
        record.push(',');
        record.push_str(&wheel_record_hash(bytes));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str(record_path);
    record.push_str(",,\n");

    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in entries {
        writer
            .start_file(
                *path,
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
            )
            .expect("start inert wheel member");
        writer.write_all(bytes).expect("write inert wheel member");
    }
    writer
        .start_file(
            record_path,
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
        )
        .expect("start wheel RECORD");
    writer
        .write_all(record.as_bytes())
        .expect("write wheel RECORD");
    writer.finish().expect("finish inert wheel").into_inner()
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
            .expect("append inert sdist member");
    }
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn long_python(tail: &[u8]) -> Vec<u8> {
    let mut source = Vec::new();
    while source.len() <= MAX_ARTIFACT_REVIEW_CHUNK_BYTES_V2 + 4_096 {
        source.extend_from_slice(b"inert_review_value = 42\n");
    }
    source.extend_from_slice(tail);
    source
}

fn assert_every_normalized_file_is_inventoried(
    artifact: &NormalizedArtifact,
    request: &ArtifactReviewRequestV2,
) {
    let expected = artifact
        .files()
        .map(|file| file.file_id.clone())
        .collect::<BTreeSet<_>>();
    let covered = request
        .coverage()
        .files()
        .iter()
        .map(|file| file.file_id().clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered, expected);
    assert_eq!(request.coverage().files().len(), artifact.files().count());
}

fn coverage_for_path<'a>(
    artifact: &'a NormalizedArtifact,
    request: &'a ArtifactReviewRequestV2,
    path: &str,
) -> &'a whoathere_detector::ArtifactReviewFileCoverageV2 {
    let file = artifact
        .files()
        .find(|file| file.normalized_path == path)
        .unwrap_or_else(|| panic!("normalized fixture file {path}"));
    request
        .coverage()
        .files()
        .iter()
        .find(|coverage| coverage.file_id() == &file.file_id)
        .unwrap_or_else(|| panic!("coverage for {path}"))
}

fn assert_selected_with_exact_invocations(
    artifact: &NormalizedArtifact,
    request: &ArtifactReviewRequestV2,
    path: &str,
) {
    let file = artifact
        .files()
        .find(|file| file.normalized_path == path)
        .unwrap_or_else(|| panic!("normalized fixture file {path}"));
    let coverage = coverage_for_path(artifact, request, path);
    assert_eq!(
        coverage.disposition(),
        ArtifactReviewFileDispositionV2::SelectedForReview,
        "{path} must be selected for semantic review"
    );
    assert!(!coverage.chunks().is_empty(), "{path} must have chunks");
    let file_work_items = request
        .work_items()
        .iter()
        .filter(|item| item.file_id() == &file.file_id)
        .collect::<Vec<_>>();
    assert_eq!(
        file_work_items.len(),
        coverage.chunks().len() * coverage.required_passes().len(),
        "{path} needs every required pass for every exact chunk"
    );

    let mut reconstructed = Vec::new();
    for chunk in coverage.chunks() {
        for pass in coverage.required_passes() {
            assert!(file_work_items
                .iter()
                .any(|item| { item.chunk_id() == chunk.chunk_id() && item.pass() == *pass }));
        }
        let item = file_work_items
            .iter()
            .find(|item| item.chunk_id() == chunk.chunk_id())
            .expect("chunk work item");
        let invocation = request
            .invocation(artifact, item.work_item_id())
            .expect("exact bound invocation");
        let start = usize::try_from(chunk.start_byte()).expect("chunk start fits usize");
        let end = usize::try_from(chunk.end_byte()).expect("chunk end fits usize");
        assert_eq!(invocation.untrusted().normalized_path(), path);
        assert_eq!(invocation.untrusted().file_id(), &file.file_id);
        assert_eq!(invocation.untrusted().file_sha256(), &file.sha256);
        assert_eq!(invocation.untrusted().start_byte(), chunk.start_byte());
        assert_eq!(invocation.untrusted().end_byte(), chunk.end_byte());
        assert_eq!(invocation.untrusted().bytes(), &file.bytes()[start..end]);
        reconstructed.extend_from_slice(invocation.untrusted().bytes());
    }
    assert_eq!(
        reconstructed,
        file.bytes(),
        "{path} exact chunk reconstruction"
    );
}

fn assert_exact_multichunk_tail(
    artifact: &NormalizedArtifact,
    request: &ArtifactReviewRequestV2,
    path: &str,
    expected_tail: &[u8],
) {
    let file = artifact
        .files()
        .find(|file| file.normalized_path == path)
        .expect("deep source file");
    let coverage = coverage_for_path(artifact, request, path);
    assert!(
        coverage.chunks().len() > 1,
        "fixture must exercise a tail chunk"
    );
    let tail = coverage.chunks().last().expect("tail chunk");
    let tail_item = request
        .work_items()
        .iter()
        .find(|item| item.file_id() == &file.file_id && item.chunk_id() == tail.chunk_id())
        .expect("tail work item");
    let invocation = request
        .invocation(artifact, tail_item.work_item_id())
        .expect("exact tail invocation");
    let start = usize::try_from(tail.start_byte()).expect("tail start fits usize");
    let end = usize::try_from(tail.end_byte()).expect("tail end fits usize");
    assert_eq!(invocation.untrusted().bytes(), &file.bytes()[start..end]);
    assert!(invocation.untrusted().bytes().ends_with(expected_tail));
}

fn assert_native_inventory_only(
    artifact: &NormalizedArtifact,
    request: &ArtifactReviewRequestV2,
    path: &str,
) {
    let file = artifact
        .files()
        .find(|file| file.normalized_path == path)
        .unwrap_or_else(|| panic!("normalized native fixture {path}"));
    let coverage = coverage_for_path(artifact, request, path);
    assert_eq!(
        coverage.disposition(),
        ArtifactReviewFileDispositionV2::NativeInventoryOnly
    );
    assert!(coverage
        .limitations()
        .iter()
        .any(|code| code == "native_binary_bytes_not_sent_to_text_model"));
    assert!(coverage.chunks().is_empty());
    assert!(!request
        .work_items()
        .iter()
        .any(|item| item.file_id() == &file.file_id));
}

fn result_json(request: &ArtifactReviewRequestV2, verdict: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "schema_version": ARTIFACT_REVIEW_RESULT_SCHEMA_V2,
        "artifact_sha256": request.artifact_sha256(),
        "manifest_sha256": request.manifest_sha256(),
        "request_sha256": request.request_sha256().expect("request digest"),
        "coverage_manifest_sha256": request.coverage_manifest_sha256(),
        "provider_adapter_sha256": request.provider().adapter_sha256,
        "model_identity_sha256": request.model().identity_sha256(),
        "prompt_template_sha256": request.prompt().template_sha256,
        "model_output_schema_sha256": request.model_output_schema_sha256(),
        "adapter_result_schema_sha256": request.adapter_result_schema_sha256(),
        "verdict": verdict,
        "findings": [],
    }))
    .expect("result JSON")
}

fn assert_zero_findings_cannot_be_promoted_to_no_finding(
    artifact: &NormalizedArtifact,
    analysis: &whoathere_detector::ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
) {
    assert!(analysis.findings.is_empty(), "fixture must remain inert");
    assert_eq!(
        request.coverage().completeness(),
        ArtifactReviewCoverageCompletenessV2::Incomplete
    );
    for qualification_gap in [
        "artifact_review_v2_aggregate_graph_context_not_implemented",
        "artifact_review_v2_aggregate_synthesis_not_implemented",
        "artifact_review_v2_provider_attestation_not_implemented",
        "artifact_review_v2_tokenizer_budget_not_verified",
        "artifact_review_v2_version_diff_context_not_implemented",
    ] {
        assert!(request
            .coverage()
            .limitations()
            .iter()
            .any(|code| code == qualification_gap));
    }

    let falsely_clean = result_json(request, "no_finding");
    let claim_builder = request
        .execution_claim_builder()
        .expect("execution claim builder");
    let claims = request
        .work_items()
        .iter()
        .map(|item| {
            claim_builder.from_adapter_claims(
                item.work_item_id().clone(),
                Sha256Digest::from_bytes(b"inert provider output capture"),
                b"inert provider output capture".len() as u64,
                ArtifactReviewWorkItemStatusV2::Completed,
                ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted,
                true,
            )
        })
        .collect::<Result<Vec<_>, _>>()
        .expect("bounded per-work-item claims");
    let receipt =
        ArtifactReviewExecutionReportV2::from_adapter_claims(request, claims, &falsely_clean)
            .expect("complete inert execution receipt");
    assert!(matches!(
        decode_and_structurally_validate_artifact_review_result_v2(
            &falsely_clean,
            request,
            artifact,
            analysis,
            &receipt,
        ),
        Err(ArtifactReviewErrorV2::VerdictMismatch)
    ));
}

#[test]
fn wheel_review_inventories_and_selects_all_semantic_artifact_surfaces() {
    const METADATA: &[u8] = b"Metadata-Version: 2.1\nName: review-wheel\nVersion: 1.0.0\n\n";
    const WHEEL: &[u8] =
        b"Wheel-Version: 1.0\nGenerator: inert-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
    const ENTRY_POINTS: &[u8] = b"[console_scripts]\nreview-wheel = review_wheel.cli:main\n";
    const PTH: &[u8] = b"review_wheel_support\n";
    const CLI: &[u8] = b"def main():\n    return 0\n";
    const SCRIPT: &[u8] = b"#!/usr/bin/env python3\nprint('inert wheel script')\n";
    const NATIVE_BY_EXTENSION: &[u8] = b"inert native-extension placeholder";
    const NATIVE_BY_MAGIC: &[u8] = b"\x7fELFinert-native-magic-placeholder";
    const DEEP_TAIL: &[u8] = b"WHEEL_REVIEW_TAIL = 'inert-wheel-tail'\n";
    let deep_python = long_python(DEEP_TAIL);
    let entries = [
        ("review_wheel-1.0.0.dist-info/METADATA", METADATA),
        ("review_wheel-1.0.0.dist-info/WHEEL", WHEEL),
        (
            "review_wheel-1.0.0.dist-info/entry_points.txt",
            ENTRY_POINTS,
        ),
        ("review_wheel.pth", PTH),
        ("review_wheel/cli.py", CLI),
        ("review_wheel/deep/nested/module.py", deep_python.as_slice()),
        ("review_wheel-1.0.0.data/scripts/review-wheel", SCRIPT),
        ("review_wheel/native.so", NATIVE_BY_EXTENSION),
        ("review_wheel/native_payload", NATIVE_BY_MAGIC),
    ];
    let bytes = wheel_zip(&entries);
    let envelope = envelope(
        Ecosystem::Pypi,
        "review-wheel",
        "1.0.0",
        "review_wheel-1.0.0-py3-none-any.whl",
        ArtifactFormat::WheelZip,
        &bytes,
        false,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert wheel");
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze inert wheel");
    let request =
        build_artifact_review_request_v2(&subject(&artifact), &artifact, &analysis, config())
            .expect("build wheel review request");

    assert_every_normalized_file_is_inventoried(&artifact, &request);
    for path in [
        "review_wheel-1.0.0.dist-info/METADATA",
        "review_wheel-1.0.0.dist-info/WHEEL",
        "review_wheel-1.0.0.dist-info/RECORD",
        "review_wheel-1.0.0.dist-info/entry_points.txt",
        "review_wheel.pth",
        "review_wheel/cli.py",
        "review_wheel/deep/nested/module.py",
        "review_wheel-1.0.0.data/scripts/review-wheel",
    ] {
        assert_selected_with_exact_invocations(&artifact, &request, path);
    }
    assert_exact_multichunk_tail(
        &artifact,
        &request,
        "review_wheel/deep/nested/module.py",
        DEEP_TAIL,
    );
    assert_native_inventory_only(&artifact, &request, "review_wheel/native.so");
    assert_native_inventory_only(&artifact, &request, "review_wheel/native_payload");
    assert_zero_findings_cannot_be_promoted_to_no_finding(&artifact, &analysis, &request);
}

#[test]
fn sdist_review_inventories_and_selects_all_semantic_artifact_surfaces() {
    const PKG_INFO: &[u8] = b"Metadata-Version: 2.1\nName: review-sdist\nVersion: 1.0.0\n\n";
    const PYPROJECT: &[u8] = br#"[build-system]
requires = []
build-backend = "backend_impl"
backend-path = ["backend"]
"#;
    const SETUP_PY: &[u8] = b"from setuptools import setup\nsetup()\n";
    const SETUP_CFG: &[u8] = b"[metadata]\nname = review-sdist\nversion = 1.0.0\n";
    const BACKEND: &[u8] = b"def build_wheel(*args, **kwargs):\n    return 'inert.whl'\n";
    const INIT: &[u8] = b"VALUE = 42\n";
    const SHELL: &[u8] = b"#!/bin/sh\nprintf '%s\\n' 'inert sdist script'\n";
    const EXTENSIONLESS: &[u8] = b"#!/bin/sh\nprintf '%s\\n' 'inert extensionless helper'\n";
    const NATIVE_BY_EXTENSION: &[u8] = b"inert native-extension placeholder";
    const NATIVE_BY_MAGIC: &[u8] = b"\x7fELFinert-native-magic-placeholder";
    const DEEP_TAIL: &[u8] = b"SDIST_REVIEW_TAIL = 'inert-sdist-tail'\n";
    let deep_python = long_python(DEEP_TAIL);
    let bytes = tar_gzip(&[
        ("review_sdist-1.0.0/PKG-INFO", PKG_INFO, 0o644),
        ("review_sdist-1.0.0/pyproject.toml", PYPROJECT, 0o644),
        ("review_sdist-1.0.0/setup.py", SETUP_PY, 0o644),
        ("review_sdist-1.0.0/setup.cfg", SETUP_CFG, 0o644),
        ("review_sdist-1.0.0/backend/backend_impl.py", BACKEND, 0o644),
        (
            "review_sdist-1.0.0/src/review_sdist/__init__.py",
            INIT,
            0o644,
        ),
        (
            "review_sdist-1.0.0/src/review_sdist/deep/nested/module.py",
            deep_python.as_slice(),
            0o644,
        ),
        ("review_sdist-1.0.0/tools/build.sh", SHELL, 0o755),
        (
            "review_sdist-1.0.0/tools/review-helper",
            EXTENSIONLESS,
            0o755,
        ),
        (
            "review_sdist-1.0.0/src/review_sdist/native.pyd",
            NATIVE_BY_EXTENSION,
            0o644,
        ),
        (
            "review_sdist-1.0.0/src/review_sdist/native_payload",
            NATIVE_BY_MAGIC,
            0o644,
        ),
    ]);
    let envelope = envelope(
        Ecosystem::Pypi,
        "review-sdist",
        "1.0.0",
        "review_sdist-1.0.0.tar.gz",
        ArtifactFormat::SdistTarGzip,
        &bytes,
        true,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert sdist");
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze inert sdist");
    let request =
        build_artifact_review_request_v2(&subject(&artifact), &artifact, &analysis, config())
            .expect("build sdist review request");

    assert_every_normalized_file_is_inventoried(&artifact, &request);
    for path in [
        "PKG-INFO",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "backend/backend_impl.py",
        "src/review_sdist/__init__.py",
        "src/review_sdist/deep/nested/module.py",
        "tools/build.sh",
        "tools/review-helper",
    ] {
        assert_selected_with_exact_invocations(&artifact, &request, path);
    }
    assert_exact_multichunk_tail(
        &artifact,
        &request,
        "src/review_sdist/deep/nested/module.py",
        DEEP_TAIL,
    );
    assert_native_inventory_only(&artifact, &request, "src/review_sdist/native.pyd");
    assert_native_inventory_only(&artifact, &request, "src/review_sdist/native_payload");
    assert_zero_findings_cannot_be_promoted_to_no_finding(&artifact, &analysis, &request);
}
