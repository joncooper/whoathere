use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs;
use std::io::{self, Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
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
    decode_macos_artifact_guest_auth_challenge_v1, decode_macos_artifact_submission_frame_v1,
    encode_macos_artifact_submission_frame_v1, read_macos_artifact_guest_control_frame_v1,
    require_macos_artifact_guest_control_eof_v1, sign_macos_artifact_guest_auth_response_v1,
    sign_macos_artifact_guest_staging_receipt_v1, stage_macos_artifact_guest_submission_v1,
    stream_macos_artifact_guest_submission_v1, verify_macos_artifact_guest_auth_response_v1,
    verify_macos_artifact_guest_staging_receipt_v1, write_macos_artifact_guest_control_frame_v1,
    write_macos_artifact_submission_frame_v1, ArtifactGuestRehashPhaseV1,
    MacosArtifactBackendCapabilitiesV1, MacosArtifactBackendIdentityV1,
    MacosArtifactGuestAuthChallengeV1, MacosArtifactGuestAuthClaimsV1,
    MacosArtifactGuestAuthErrorV1, MacosArtifactGuestControlErrorV1,
    MacosArtifactGuestControlFrameTypeV1, MacosArtifactGuestStagingErrorV1,
    MacosArtifactGuestStagingPolicyV1, MacosArtifactGuestStagingReceiptClaimsV1,
    MacosArtifactRunErrorV1, MacosArtifactSubmissionBindingsV1, MacosArtifactSubmissionErrorV1,
    MacosArtifactSubmissionHeaderV1, MACOS_ARTIFACT_GUEST_SUBMISSION_MAGIC_V1,
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
        digest(b"hardware model"),
        digest(b"machine identifier"),
        4,
        6_144,
        digest(b"post provisioning receipt"),
        digest(b"signed swift helper"),
        digest(b"root guest supervisor"),
        digest(b"guest auth Ed25519 public key"),
        digest(b"runner configuration"),
        502,
        502,
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
    let mut invalid_package_uid: serde_json::Value =
        serde_json::from_slice(bytes).expect("run spec value");
    invalid_package_uid["backend_identity"]["package_uid"] = serde_json::json!(0);
    let invalid_package_uid =
        serde_json_canonicalizer::to_vec(&invalid_package_uid).expect("invalid UID run spec");
    assert_eq!(
        decode_and_validate_macos_artifact_run_spec_v1(&invalid_package_uid),
        Err(MacosArtifactRunErrorV1::InvalidBackendIdentity)
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

#[test]
fn guest_submission_streams_exact_bytes_and_rejects_wrong_domain_corruption_and_trailing_data() {
    let (template, artifact) = compiled_template();
    let run_spec = compile_macos_artifact_run_spec_v1(&template, &backend(digest(b"measured npm")))
        .expect("Mac run spec");
    let bindings = MacosArtifactSubmissionBindingsV1::for_run_spec(digest(b"challenge"), &run_spec);
    let header = MacosArtifactSubmissionHeaderV1::new(run_spec.clone(), bindings)
        .expect("submission header");
    let mut guest =
        encode_macos_artifact_submission_frame_v1(&header, &artifact).expect("host frame");
    guest[..8].copy_from_slice(&MACOS_ARTIFACT_GUEST_SUBMISSION_MAGIC_V1);

    let mut fragmented = FragmentedReader::new(&guest, 3);
    let mut staged = Vec::new();
    let observation = stream_macos_artifact_guest_submission_v1(&mut fragmented, &mut staged)
        .expect("streamed guest frame");
    assert_eq!(staged, artifact);
    assert_eq!(observation.artifact_sha256(), run_spec.artifact_sha256());
    assert_eq!(observation.artifact_byte_length(), artifact.len() as u64);
    assert_eq!(observation.header().run_spec(), &run_spec);

    let mut wrong_domain = guest.clone();
    wrong_domain[..8].copy_from_slice(b"WHOAART1");
    let mut staged = Vec::new();
    assert_eq!(
        stream_macos_artifact_guest_submission_v1(&mut Cursor::new(wrong_domain), &mut staged),
        Err(MacosArtifactSubmissionErrorV1::InvalidMagic)
    );
    assert!(staged.is_empty());

    let mut mutated = guest.clone();
    *mutated.last_mut().expect("artifact byte") ^= 1;
    let mut staged = Vec::new();
    assert_eq!(
        stream_macos_artifact_guest_submission_v1(&mut Cursor::new(mutated), &mut staged),
        Err(MacosArtifactSubmissionErrorV1::ArtifactDigestMismatch)
    );
    assert_eq!(staged.len(), artifact.len());

    let mut trailing = guest.clone();
    trailing.push(0);
    let mut staged = Vec::new();
    assert_eq!(
        stream_macos_artifact_guest_submission_v1(&mut Cursor::new(trailing), &mut staged),
        Err(MacosArtifactSubmissionErrorV1::TrailingData)
    );
    assert_eq!(staged, artifact);

    let mut staged = Vec::new();
    assert_eq!(
        stream_macos_artifact_guest_submission_v1(
            &mut Cursor::new(&guest[..guest.len() - 1]),
            &mut staged
        ),
        Err(MacosArtifactSubmissionErrorV1::Truncated)
    );
}

#[test]
fn guest_staging_is_exclusive_read_only_rehashed_and_removed() {
    let (guest, artifact, run_spec) = guest_frame();
    let root = temporary_staging_root("success");
    let policy = staging_policy(&root);
    let mut staged = stage_macos_artifact_guest_submission_v1(&mut Cursor::new(guest), &policy)
        .expect("stage inert artifact");
    let path = staged.artifact_path().to_path_buf();
    let metadata = fs::symlink_metadata(&path).expect("staged metadata");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o777, 0o444);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.len(), artifact.len() as u64);
    assert_eq!(
        staged.transport().artifact_sha256(),
        run_spec.artifact_sha256()
    );

    let prelaunch = staged.verify_prelaunch().expect("prelaunch rehash");
    let postrun = staged.verify_postrun().expect("postrun rehash");
    assert_eq!(prelaunch.phase(), ArtifactGuestRehashPhaseV1::Prelaunch);
    assert_eq!(postrun.phase(), ArtifactGuestRehashPhaseV1::Postrun);
    assert_eq!(prelaunch.artifact_sha256(), run_spec.artifact_sha256());
    assert_eq!(prelaunch.artifact_byte_length(), artifact.len() as u64);
    assert_eq!(prelaunch.device(), postrun.device());
    assert_eq!(prelaunch.inode(), postrun.inode());

    let directory = path.parent().expect("scenario directory").to_path_buf();
    staged.cleanup().expect("verified cleanup");
    assert!(!directory.exists());
    assert_eq!(fs::read_dir(&root).expect("empty root").count(), 0);
    fs::remove_dir(root).expect("remove staging root");
}

#[test]
fn guest_staging_discards_bad_transport_and_detects_path_replacement_before_launch() {
    let (mut guest, _, _) = guest_frame();
    let root = temporary_staging_root("failure");
    let policy = staging_policy(&root);
    *guest.last_mut().expect("artifact byte") ^= 1;
    assert_eq!(
        stage_macos_artifact_guest_submission_v1(&mut Cursor::new(guest), &policy)
            .expect_err("mutated body must fail"),
        MacosArtifactGuestStagingErrorV1::Transport(
            MacosArtifactSubmissionErrorV1::ArtifactDigestMismatch
        )
    );
    assert_eq!(fs::read_dir(&root).expect("cleaned root").count(), 0);

    let (guest, artifact, _) = guest_frame();
    let mut staged = stage_macos_artifact_guest_submission_v1(&mut Cursor::new(guest), &policy)
        .expect("stage replacement fixture");
    let path = staged.artifact_path().to_path_buf();
    let held = path.with_file_name("held-original.tgz");
    fs::rename(&path, &held).expect("move original as simulated root tamper");
    fs::write(&path, &artifact).expect("write replacement");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444)).expect("protect replacement");
    assert_eq!(
        staged.verify_prelaunch(),
        Err(MacosArtifactGuestStagingErrorV1::VerificationFailed)
    );
    assert_eq!(
        staged.cleanup(),
        Err(MacosArtifactGuestStagingErrorV1::CleanupFailed)
    );
    assert!(held.exists());
    fs::remove_file(held).expect("remove simulated tamper residue");
    staged.cleanup().expect("retry cleanup");
    assert_eq!(fs::read_dir(&root).expect("clean root").count(), 0);
    fs::remove_dir(root).expect("remove staging root");
}

#[test]
fn guest_authentication_binds_fresh_challenge_signed_claims_and_measured_public_key() {
    let seed = [7_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let challenge = MacosArtifactGuestAuthChallengeV1::new(
        [9_u8; 32],
        digest(b"execution binding"),
        digest(b"run spec"),
        digest(b"clone binding"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("guest auth challenge");
    let decoded = decode_macos_artifact_guest_auth_challenge_v1(challenge.canonical_json_v1())
        .expect("strict challenge decode");
    assert_eq!(decoded, challenge);
    let claims = MacosArtifactGuestAuthClaimsV1::new(
        digest(b"guest supervisor"),
        digest(b"runner configuration"),
        502,
        502,
    )
    .expect("guest claims");
    let response = sign_macos_artifact_guest_auth_response_v1(&challenge, seed, &claims)
        .expect("signed guest auth response");
    assert_eq!(
        std::str::from_utf8(challenge.canonical_json_v1()).expect("challenge UTF-8"),
        r#"{"clone_binding_sha256":"sha256:92514cfc03f94cbbc544178a0e7b999522b708efd7db40bd0c3d3796f9515564","execution_binding_sha256":"sha256:0adeabc9b469d31f8f4074566c3aec953f83419cc5700ece10e2c6c63272daf2","guest_auth_public_key_sha256":"sha256:fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889","nonce_hex":"0909090909090909090909090909090909090909090909090909090909090909","run_spec_sha256":"sha256:3626162ee4f7e66251d3d4fd61e2414e2153f65311611ebb72efc42565984fa3","schema_version":"whoathere.artifact_guest_auth_challenge.v1"}"#
    );
    assert_eq!(
        std::str::from_utf8(&response).expect("response UTF-8"),
        r#"{"challenge_sha256":"sha256:c5d93c1b625d9725401bbb47a3914fc65c54e74969e4c3031e2ac2565ee372cc","clone_binding_sha256":"sha256:92514cfc03f94cbbc544178a0e7b999522b708efd7db40bd0c3d3796f9515564","execution_binding_sha256":"sha256:0adeabc9b469d31f8f4074566c3aec953f83419cc5700ece10e2c6c63272daf2","guest_supervisor_sha256":"sha256:2c70f775aa20c6807b3fa4c5a05c8f5ab466d7c0c4e588280cd7ccbead6ae3a3","package_gid":"502","package_uid":"502","run_spec_sha256":"sha256:3626162ee4f7e66251d3d4fd61e2414e2153f65311611ebb72efc42565984fa3","runner_configuration_sha256":"sha256:153857d8963121612c0fff30058d06703606855e9bc96a83e45964ce0586dca3","schema_version":"whoathere.artifact_guest_auth_response.v1","signature_ed25519_hex":"e4096174087ef60f64ebf9ccadfaa2c13e214a9bfe391b8b8bac85f86f443e5e408fdff74cbb17c9672d895d7ef43446e710611c31415e9be4dc811c34e69709"}"#
    );
    verify_macos_artifact_guest_auth_response_v1(&challenge, &response, verifying_key, &claims)
        .expect("verified guest auth response");

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(challenge.canonical_json_v1());
    assert_eq!(
        decode_macos_artifact_guest_auth_challenge_v1(&noncanonical),
        Err(MacosArtifactGuestAuthErrorV1::NonCanonical)
    );

    let fresh_challenge = MacosArtifactGuestAuthChallengeV1::new(
        [10_u8; 32],
        digest(b"execution binding"),
        digest(b"run spec"),
        digest(b"clone binding"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("fresh guest auth challenge");
    assert_eq!(
        verify_macos_artifact_guest_auth_response_v1(
            &fresh_challenge,
            &response,
            verifying_key,
            &claims
        ),
        Err(MacosArtifactGuestAuthErrorV1::InvalidResponse)
    );

    let forged_claims = MacosArtifactGuestAuthClaimsV1::new(
        digest(b"guest supervisor"),
        digest(b"runner configuration"),
        503,
        502,
    )
    .expect("forged claims");
    let mut forged: serde_json::Value = serde_json::from_slice(&response).expect("response JSON");
    forged["package_uid"] = serde_json::json!("503");
    let forged = serde_json_canonicalizer::to_vec(&forged).expect("forged response");
    assert_eq!(
        verify_macos_artifact_guest_auth_response_v1(
            &challenge,
            &forged,
            verifying_key,
            &forged_claims
        ),
        Err(MacosArtifactGuestAuthErrorV1::SignatureFailed)
    );

    assert_eq!(
        sign_macos_artifact_guest_auth_response_v1(&challenge, [8_u8; 32], &claims),
        Err(MacosArtifactGuestAuthErrorV1::PublicKeyMismatch)
    );
}

#[test]
fn signed_guest_staging_receipt_binds_rehash_identity_and_no_execution_posture() {
    let seed = [7_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let challenge = MacosArtifactGuestAuthChallengeV1::new(
        [9_u8; 32],
        digest(b"execution binding"),
        digest(b"run spec"),
        digest(b"clone binding"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("receipt challenge");
    let auth_claims = MacosArtifactGuestAuthClaimsV1::new(
        digest(b"guest supervisor"),
        digest(b"runner configuration"),
        502,
        502,
    )
    .expect("auth claims");
    let staging_claims = MacosArtifactGuestStagingReceiptClaimsV1::new(
        digest(b"artifact"),
        205,
        digest(b"artifact"),
        205,
        123,
        456,
    )
    .expect("staging claims");
    let receipt = sign_macos_artifact_guest_staging_receipt_v1(
        &challenge,
        seed,
        &auth_claims,
        &staging_claims,
    )
    .expect("signed staging receipt");
    let observation = verify_macos_artifact_guest_staging_receipt_v1(
        &challenge,
        &receipt,
        verifying_key,
        &auth_claims,
        &staging_claims,
    )
    .expect("verified staging receipt");
    assert_eq!(observation.claims(), &staging_claims);
    assert_eq!(observation.package_uid(), 502);
    assert_eq!(observation.package_gid(), 502);

    let mut enabled: serde_json::Value = serde_json::from_slice(&receipt).expect("receipt JSON");
    enabled["package_execution_enabled"] = serde_json::json!(true);
    let enabled = serde_json_canonicalizer::to_vec(&enabled).expect("enabled receipt");
    assert_eq!(
        verify_macos_artifact_guest_staging_receipt_v1(
            &challenge,
            &enabled,
            verifying_key,
            &auth_claims,
            &staging_claims
        ),
        Err(MacosArtifactGuestAuthErrorV1::InvalidResponse)
    );

    let changed_staging = MacosArtifactGuestStagingReceiptClaimsV1::new(
        digest(b"artifact"),
        205,
        digest(b"artifact"),
        205,
        123,
        457,
    )
    .expect("changed staging claims");
    assert_eq!(
        verify_macos_artifact_guest_staging_receipt_v1(
            &challenge,
            &receipt,
            verifying_key,
            &auth_claims,
            &changed_staging
        ),
        Err(MacosArtifactGuestAuthErrorV1::InvalidResponse)
    );
}

#[test]
fn guest_control_frames_are_ordered_bounded_fragment_tolerant_and_explicitly_terminated() {
    let challenge = b"{\"challenge\":\"inert\"}";
    let response = b"{\"response\":\"inert\"}";
    let mut wire = Vec::new();
    write_macos_artifact_guest_control_frame_v1(
        &mut wire,
        MacosArtifactGuestControlFrameTypeV1::AuthenticationChallenge,
        challenge,
    )
    .expect("challenge frame");
    write_macos_artifact_guest_control_frame_v1(
        &mut wire,
        MacosArtifactGuestControlFrameTypeV1::AuthenticationResponse,
        response,
    )
    .expect("response frame");
    let mut fragmented = FragmentedReader::new(&wire, 1);
    assert_eq!(
        read_macos_artifact_guest_control_frame_v1(
            &mut fragmented,
            MacosArtifactGuestControlFrameTypeV1::AuthenticationChallenge,
            1024
        )
        .expect("read challenge"),
        challenge
    );
    assert_eq!(
        read_macos_artifact_guest_control_frame_v1(
            &mut fragmented,
            MacosArtifactGuestControlFrameTypeV1::AuthenticationResponse,
            1024
        )
        .expect("read response"),
        response
    );
    require_macos_artifact_guest_control_eof_v1(&mut fragmented).expect("control EOF");

    let mut wrong_type = Cursor::new(&wire);
    assert_eq!(
        read_macos_artifact_guest_control_frame_v1(
            &mut wrong_type,
            MacosArtifactGuestControlFrameTypeV1::StagingReceipt,
            1024
        ),
        Err(MacosArtifactGuestControlErrorV1::UnexpectedFrameType)
    );
    let mut truncated = Cursor::new(&wire[..10]);
    assert_eq!(
        read_macos_artifact_guest_control_frame_v1(
            &mut truncated,
            MacosArtifactGuestControlFrameTypeV1::AuthenticationChallenge,
            1024
        ),
        Err(MacosArtifactGuestControlErrorV1::Truncated)
    );
    let mut trailing = Cursor::new([0_u8]);
    assert_eq!(
        require_macos_artifact_guest_control_eof_v1(&mut trailing),
        Err(MacosArtifactGuestControlErrorV1::TrailingData)
    );
}

fn guest_frame() -> (Vec<u8>, Vec<u8>, whoathere_macos_vm::MacosArtifactRunSpecV1) {
    let (template, artifact) = compiled_template();
    let run_spec = compile_macos_artifact_run_spec_v1(&template, &backend(digest(b"measured npm")))
        .expect("Mac run spec");
    let bindings = MacosArtifactSubmissionBindingsV1::for_run_spec(digest(b"challenge"), &run_spec);
    let header = MacosArtifactSubmissionHeaderV1::new(run_spec.clone(), bindings)
        .expect("submission header");
    let mut guest =
        encode_macos_artifact_submission_frame_v1(&header, &artifact).expect("host frame");
    guest[..8].copy_from_slice(&MACOS_ARTIFACT_GUEST_SUBMISSION_MAGIC_V1);
    (guest, artifact, run_spec)
}

fn temporary_staging_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "whoathere-guest-staging-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create staging root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect staging root");
    root
}

fn staging_policy(root: &std::path::Path) -> MacosArtifactGuestStagingPolicyV1 {
    let supervisor_uid = fs::symlink_metadata(root).expect("root metadata").uid();
    let package_uid = if supervisor_uid == u32::MAX {
        1
    } else {
        (supervisor_uid + 1).max(1)
    };
    MacosArtifactGuestStagingPolicyV1::for_current_supervisor(root.to_path_buf(), package_uid)
        .expect("staging policy")
}

struct FragmentedReader<'a> {
    input: &'a [u8],
    offset: usize,
    maximum_read: usize,
}

impl<'a> FragmentedReader<'a> {
    fn new(input: &'a [u8], maximum_read: usize) -> Self {
        Self {
            input,
            offset: 0,
            maximum_read,
        }
    }
}

impl Read for FragmentedReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.offset == self.input.len() {
            return Ok(0);
        }
        let count = output
            .len()
            .min(self.maximum_read)
            .min(self.input.len() - self.offset);
        output[..count].copy_from_slice(&self.input[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
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
