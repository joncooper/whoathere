use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{self, Cursor, Write};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_artifact_scenarios_v1, ArtifactScenarioCompilationRequestV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioIdentitySetV1, ArtifactScenarioPolicyV1,
    NpmRuntimeProfileV1, MAX_ARTIFACT_SCENARIO_BYTES_V1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    compile_macos_artifact_run_spec_v1, decode_and_validate_macos_artifact_run_spec_v1,
    decode_macos_artifact_submission_frame_v1, encode_macos_artifact_submission_frame_v1,
    write_macos_artifact_submission_frame_v1, MacosArtifactBackendCapabilitiesV1,
    MacosArtifactBackendIdentityV1, MacosArtifactRunErrorV1, MacosArtifactSubmissionBindingsV1,
    MacosArtifactSubmissionErrorV1, MacosArtifactSubmissionHeaderV1,
    MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1,
};

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn npm_tgz(entries: &[(&str, &[u8])]) -> Vec<u8> {
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
            .expect("append inert fixture member");
    }
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn compiled_template() -> (whoathere_detonation::ArtifactScenarioTemplateV1, Vec<u8>) {
    let bytes = npm_tgz(&[
        (
            "package/package.json",
            br#"{"name":"macos-artifact-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js --inert-marker"}}"#,
        ),
        ("package/post.js", b"process.exit(0)"),
    ]);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("macos-artifact-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:macos-artifact-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-10T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "macos-artifact-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "repository-inert-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "macos-artifact-first-slice.v1".to_string(),
            requires_external_dependency_resolution: false,
        },
        &bytes,
        ArtifactFormat::NpmTarGzip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize fixture");
    let subject = ArtifactEvidenceSubjectV2::new(
        artifact.manifest.artifact_sha256.as_str(),
        envelope
            .envelope_sha256()
            .expect("envelope digest")
            .as_str(),
        artifact.manifest.manifest_sha256.as_str(),
        canonical_cas_object_key_for_artifact(artifact.manifest.artifact_sha256.as_str())
            .expect("CAS key"),
    )
    .expect("subject");
    let runtime = NpmRuntimeProfileV1::new(
        "macos-arm64-node22-npm11-inert",
        "22.17.0",
        digest(b"measured node"),
        "11.18.0",
        digest(b"measured npm"),
    )
    .expect("runtime");
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        envelope.original_sha256.clone(),
        runtime,
    )
    .expect("policy");
    let identities = ArtifactScenarioIdentitySetV1::new(
        "macos-plan",
        ArtifactScenarioExecutionIdentityV1::new(
            "job-false",
            "run-false",
            "evidence-false",
            "scenario-false",
        )
        .expect("false identity"),
        ArtifactScenarioExecutionIdentityV1::new(
            "job-true",
            "run-true",
            "evidence-true",
            "scenario-true",
        )
        .expect("true identity"),
    )
    .expect("identities");
    let plan = compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &artifact.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })
    .expect("scenario plan");
    (plan.templates()[0].clone(), bytes)
}

fn backend(npm_digest: Sha256Digest) -> MacosArtifactBackendCapabilitiesV1 {
    let identity = MacosArtifactBackendIdentityV1::new(
        "base-generation-inert-v1",
        digest(b"base disk"),
        digest(b"base auxiliary storage"),
        digest(b"post provisioning receipt"),
        digest(b"signed swift helper"),
        digest(b"root guest supervisor"),
        digest(b"runner configuration"),
        "22.17.0",
        digest(b"measured node"),
        "11.18.0",
        npm_digest,
        digest(b"apfs clone implementation"),
    )
    .expect("backend identity");
    MacosArtifactBackendCapabilitiesV1::inert_first_slice(identity)
}

#[test]
fn complete_template_is_nested_in_a_closed_no_nic_one_clone_run_spec() {
    let (template, _) = compiled_template();
    let run_spec = compile_macos_artifact_run_spec_v1(&template, &backend(digest(b"measured npm")))
        .expect("Mac run spec");
    let bytes = run_spec.canonical_json_v1();
    let text = std::str::from_utf8(bytes).expect("run spec UTF-8");
    assert!(text.contains("zero_network_devices"));
    assert!(text.contains("apfs_clone_required_no_copy_fallback"));
    assert!(text.contains("one_boot_one_scenario_destroy_clone"));
    assert!(!text.contains("sync"));
    assert!(!text.contains("inert-marker"));
    assert!(!text.contains("registry"));
    assert!(!text.contains("verdict"));
    let decoded = decode_and_validate_macos_artifact_run_spec_v1(bytes).expect("strict run spec");
    assert_eq!(decoded.run_spec_sha256(), run_spec.run_spec_sha256());
    assert_eq!(decoded.template_sha256(), template.template_sha256());

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(bytes);
    assert_eq!(
        decode_and_validate_macos_artifact_run_spec_v1(&noncanonical),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );
    let mut unknown: serde_json::Value = serde_json::from_slice(bytes).expect("run spec value");
    unknown
        .as_object_mut()
        .expect("run spec object")
        .insert("sync_back".to_string(), serde_json::json!(false));
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown-field run spec");
    assert_eq!(
        decode_and_validate_macos_artifact_run_spec_v1(&unknown),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );
    let mut duplicate = b"{\"canonicalization\":\"rfc8785.jcs.v1\",".to_vec();
    duplicate.extend_from_slice(&bytes[1..]);
    assert_eq!(
        decode_and_validate_macos_artifact_run_spec_v1(&duplicate),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );

    assert_eq!(
        compile_macos_artifact_run_spec_v1(&template, &backend(digest(b"wrong npm"))),
        Err(MacosArtifactRunErrorV1::BackendCapabilityMismatch)
    );
}

#[test]
fn exact_run_spec_and_artifact_round_trip_through_the_binary_submission() {
    let (template, artifact) = compiled_template();
    let run_spec = compile_macos_artifact_run_spec_v1(&template, &backend(digest(b"measured npm")))
        .expect("Mac run spec");
    let bindings = MacosArtifactSubmissionBindingsV1::for_run_spec(digest(b"challenge"), &run_spec);
    let header = MacosArtifactSubmissionHeaderV1::new(run_spec.clone(), bindings.clone())
        .expect("submission header");
    let encoded =
        encode_macos_artifact_submission_frame_v1(&header, &artifact).expect("submission frame");
    assert!(encoded.ends_with(&artifact));
    assert_eq!(
        encoded.len(),
        MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1
            + header.canonical_json_v1().len()
            + artifact.len()
    );
    let decoded =
        decode_macos_artifact_submission_frame_v1(&encoded, &bindings).expect("decoded submission");
    assert_eq!(decoded.header().run_spec(), &run_spec);
    assert_eq!(decoded.artifact_bytes(), artifact);
}

#[test]
fn submission_rejects_truncation_trailing_mutation_unknown_fields_and_rebinding() {
    let (template, artifact) = compiled_template();
    let run_spec = compile_macos_artifact_run_spec_v1(&template, &backend(digest(b"measured npm")))
        .expect("Mac run spec");
    let bindings = MacosArtifactSubmissionBindingsV1::for_run_spec(digest(b"challenge"), &run_spec);
    let header =
        MacosArtifactSubmissionHeaderV1::new(run_spec.clone(), bindings.clone()).expect("header");
    let encoded =
        encode_macos_artifact_submission_frame_v1(&header, &artifact).expect("encoded frame");

    for length in [0, 55, encoded.len() - 1] {
        assert_eq!(
            decode_macos_artifact_submission_frame_v1(&encoded[..length], &bindings),
            Err(MacosArtifactSubmissionErrorV1::Truncated)
        );
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        decode_macos_artifact_submission_frame_v1(&trailing, &bindings),
        Err(MacosArtifactSubmissionErrorV1::TrailingData)
    );
    let mut mutated = encoded.clone();
    *mutated.last_mut().expect("artifact byte") ^= 1;
    assert_eq!(
        decode_macos_artifact_submission_frame_v1(&mutated, &bindings),
        Err(MacosArtifactSubmissionErrorV1::ArtifactDigestMismatch)
    );
    let wrong_bindings =
        MacosArtifactSubmissionBindingsV1::for_run_spec(digest(b"other challenge"), &run_spec);
    assert_eq!(
        decode_macos_artifact_submission_frame_v1(&encoded, &wrong_bindings),
        Err(MacosArtifactSubmissionErrorV1::BindingMismatch)
    );

    let header_len =
        u32::from_be_bytes(encoded[12..16].try_into().expect("header length")) as usize;
    let header_start = MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1;
    let header_end = header_start + header_len;
    let mut value: serde_json::Value =
        serde_json::from_slice(&encoded[header_start..header_end]).expect("header JSON");
    value
        .as_object_mut()
        .expect("header object")
        .insert("sync_back".to_string(), serde_json::json!(false));
    let unknown = serde_json_canonicalizer::to_vec(&value).expect("unknown header");
    let rebuilt = rebuild_with_header(&encoded, &unknown);
    assert_eq!(
        decode_macos_artifact_submission_frame_v1(&rebuilt, &bindings),
        Err(MacosArtifactSubmissionErrorV1::InvalidHeader)
    );

    value
        .as_object_mut()
        .expect("header object")
        .remove("sync_back");
    value["run_spec"]["backend_identity"]["helper_sha256"] =
        serde_json::json!(digest(b"forged helper").as_str());
    let forged_run_spec =
        serde_json_canonicalizer::to_vec(&value["run_spec"]).expect("forged run spec");
    let forged_run_spec_sha256 = Sha256Digest::from_bytes(&forged_run_spec);
    value["run_spec_sha256"] = serde_json::json!(forged_run_spec_sha256.as_str());
    let forged_execution_binding = Sha256Digest::from_bytes(
        format!(
            "whoathere.macos_artifact_submission_execution_binding.v1\0{}\0{}",
            bindings.challenge_binding_sha256(),
            forged_run_spec_sha256
        )
        .as_bytes(),
    );
    value["execution_binding_sha256"] = serde_json::json!(forged_execution_binding.as_str());
    let forged = serde_json_canonicalizer::to_vec(&value).expect("forged header");
    let rebuilt = rebuild_with_header(&encoded, &forged);
    assert_eq!(
        decode_macos_artifact_submission_frame_v1(&rebuilt, &bindings),
        Err(MacosArtifactSubmissionErrorV1::BindingMismatch)
    );
}

fn rebuild_with_header(original: &[u8], replacement: &[u8]) -> Vec<u8> {
    let old_header_len =
        u32::from_be_bytes(original[12..16].try_into().expect("old header length")) as usize;
    let old_payload_start = MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1 + old_header_len;
    let mut rebuilt = Vec::new();
    rebuilt.extend_from_slice(&original[..12]);
    rebuilt.extend_from_slice(&(replacement.len() as u32).to_be_bytes());
    rebuilt.extend_from_slice(&original[16..MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1]);
    rebuilt.extend_from_slice(replacement);
    rebuilt.extend_from_slice(&original[old_payload_start..]);
    rebuilt
}

struct CountingWriter(u64);

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("counter overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn writer_rejects_size_mismatch_before_write_and_prefix_enforces_ceiling() {
    let (template, artifact) = compiled_template();
    let run_spec = compile_macos_artifact_run_spec_v1(&template, &backend(digest(b"measured npm")))
        .expect("Mac run spec");
    let bindings = MacosArtifactSubmissionBindingsV1::for_run_spec(digest(b"challenge"), &run_spec);
    let header = MacosArtifactSubmissionHeaderV1::new(run_spec, bindings.clone()).expect("header");
    let mut writer = CountingWriter(0);
    let wrong_sized = vec![0u8; 1];
    assert_eq!(
        write_macos_artifact_submission_frame_v1(&mut writer, &header, &wrong_sized),
        Err(MacosArtifactSubmissionErrorV1::ArtifactLimitExceeded)
    );
    assert_eq!(writer.0, 0);

    let encoded =
        encode_macos_artifact_submission_frame_v1(&header, &artifact).expect("encoded frame");
    let mut exact_ceiling_prefix = encoded.clone();
    exact_ceiling_prefix[16..24].copy_from_slice(&MAX_ARTIFACT_SCENARIO_BYTES_V1.to_be_bytes());
    assert_eq!(
        decode_macos_artifact_submission_frame_v1(&exact_ceiling_prefix, &bindings),
        Err(MacosArtifactSubmissionErrorV1::Truncated)
    );
    let mut over_ceiling_prefix = encoded;
    over_ceiling_prefix[16..24]
        .copy_from_slice(&(MAX_ARTIFACT_SCENARIO_BYTES_V1 + 1).to_be_bytes());
    assert_eq!(
        decode_macos_artifact_submission_frame_v1(&over_ceiling_prefix, &bindings),
        Err(MacosArtifactSubmissionErrorV1::ArtifactLimitExceeded)
    );
}
