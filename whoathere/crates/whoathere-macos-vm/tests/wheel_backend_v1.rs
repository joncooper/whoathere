use ed25519_dalek::SigningKey;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_wheel_scenarios_v1, expected_wheel_scenario_kinds_v1, ArtifactRuntimeTargetV1,
    ArtifactScenarioExecutionIdentityV1, WheelRuntimeProfileV1, WheelScenarioCompilationRequestV1,
    WheelScenarioIdentitySetV1, WheelScenarioPlanV1, WheelScenarioPolicyV1,
    WheelScenarioTemplateV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    compile_macos_wheel_run_spec_v1, decode_and_validate_macos_artifact_run_spec_v1,
    decode_and_validate_macos_wheel_run_spec_v1, decode_macos_wheel_guest_auth_challenge_v1,
    decode_macos_wheel_submission_frame_v1, encode_macos_wheel_submission_frame_v1,
    macos_wheel_execution_binding_sha256_v1, prepare_macos_wheel_launch_v1,
    read_macos_wheel_guest_control_frame_v1, require_macos_wheel_guest_control_eof_v1,
    run_macos_wheel_guest_nonexecuting_session_v1, sign_macos_wheel_guest_auth_response_v1,
    sign_macos_wheel_guest_staging_receipt_v1, stage_macos_wheel_guest_submission_v1,
    stream_macos_wheel_guest_submission_v1,
    validate_macos_linux_vz_typed_package_scenario_binding_v1,
    verify_macos_wheel_guest_auth_response_v1, verify_macos_wheel_guest_staging_receipt_v1,
    write_macos_wheel_guest_control_frame_v1, MacosArtifactRunErrorV1,
    MacosLinuxVzPackageArtifactKindV1, MacosLinuxVzPackageAuthorityRequestErrorV1,
    MacosWheelBackendCapabilitiesV1, MacosWheelBackendIdentityV1, MacosWheelGuestAuthChallengeV1,
    MacosWheelGuestAuthClaimsV1, MacosWheelGuestAuthErrorV1, MacosWheelGuestControlErrorV1,
    MacosWheelGuestControlFrameTypeV1, MacosWheelGuestStagingErrorV1,
    MacosWheelGuestStagingPolicyV1, MacosWheelGuestStagingReceiptClaimsV1,
    MacosWheelGuestSupervisorPrimaryErrorV1, MacosWheelLaunchAuthorityErrorV1,
    MacosWheelSubmissionBindingsV1, MacosWheelSubmissionErrorV1, MacosWheelSubmissionHeaderV1,
    WheelGuestRehashPhaseV1, MACOS_WHEEL_GUEST_SUBMISSION_MAGIC_V1,
    MACOS_WHEEL_LAUNCH_AUTHORITY_SCHEMA_V1, MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1,
    MACOS_WHEEL_SUBMISSION_MAGIC_V1, MAX_MACOS_WHEEL_LAUNCH_AUTHORITY_LIFETIME_SECONDS_V1,
};
use zip::write::SimpleFileOptions;

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(bytes)
}

fn compiled_template(init_bytes: &[u8]) -> (WheelScenarioTemplateV1, Vec<u8>) {
    let (plan, bytes) = compiled_plan(ArtifactRuntimeTargetV1::MacosArm64, init_bytes);
    (plan.templates()[1].clone(), bytes)
}

fn compiled_plan(
    runtime_target: ArtifactRuntimeTargetV1,
    init_bytes: &[u8],
) -> (WheelScenarioPlanV1, Vec<u8>) {
    const DIST_INFO: &str = "macos_wheel_fixture-1.0.0.dist-info";
    let members = vec![
        (
            format!("{DIST_INFO}/METADATA"),
            b"Metadata-Version: 2.1\nName: macos-wheel-fixture\nVersion: 1.0.0\n\n".to_vec(),
        ),
        (
            format!("{DIST_INFO}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: whoathere-inert\nRoot-Is-Purelib: true\nTag: py3-none-any\n".to_vec(),
        ),
        ("macos_wheel_fixture/__init__.py".to_string(), init_bytes.to_vec()),
    ];
    let bytes = wheel_zip(&members, DIST_INFO);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("macos-wheel-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:macos-wheel-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-10T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "macos_wheel_fixture-1.0.0-py3-none-any.whl".to_string(),
            declared_format: Some(ArtifactFormat::WheelZip),
            custody_reference: "repository-inert-wheel-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "macos-wheel-first-slice.v1".to_string(),
            requires_external_dependency_resolution: false,
        },
        &bytes,
        ArtifactFormat::WheelZip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize wheel");
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
    let runtime = WheelRuntimeProfileV1::new_for_target(
        runtime_target,
        match runtime_target {
            ArtifactRuntimeTargetV1::MacosArm64 => "macos-arm64-python312-pip26-inert",
            ArtifactRuntimeTargetV1::LinuxArm64 => "linux-arm64-python312-pip26-inert",
        },
        "3.12.13",
        digest(b"measured python"),
        "26.1.2",
        digest(b"measured pip"),
    )
    .expect("runtime");
    let policy =
        WheelScenarioPolicyV1::inert_qualification_only(envelope.original_sha256.clone(), runtime)
            .expect("policy");
    let identities = expected_wheel_scenario_kinds_v1(&artifact.manifest)
        .expect("scenario kinds")
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let suffix = index + 1;
            (
                kind,
                ArtifactScenarioExecutionIdentityV1::new(
                    format!("wheel-job-{suffix}"),
                    format!("wheel-run-{suffix}"),
                    format!("wheel-evidence-{suffix}"),
                    format!("wheel-scenario-{suffix}"),
                )
                .expect("identity"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let identities =
        WheelScenarioIdentitySetV1::new("macos-wheel-plan", identities).expect("identity set");
    let plan = compile_wheel_scenarios_v1(WheelScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &artifact.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })
    .expect("wheel plan");
    (plan, bytes)
}

#[test]
fn linux_vz_wheel_binding_requires_a_linux_plan_and_exact_selected_template() {
    let (plan, _) = compiled_plan(ArtifactRuntimeTargetV1::LinuxArm64, b"VALUE = 1\n");
    let plan_bytes = plan.canonical_json_v1().expect("Linux wheel plan bytes");
    let template_bytes = plan.templates()[0]
        .canonical_json_v1()
        .expect("Linux wheel template bytes");
    let binding = validate_macos_linux_vz_typed_package_scenario_binding_v1(
        MacosLinuxVzPackageArtifactKindV1::PypiWheel,
        &plan_bytes,
        &template_bytes,
    )
    .expect("Linux wheel binding");
    assert_eq!(
        binding.runtime_target(),
        ArtifactRuntimeTargetV1::LinuxArm64
    );
    assert_eq!(binding.scenario_plan_sha256(), plan.plan_sha256());
    assert_eq!(
        binding.scenario_template_sha256(),
        plan.templates()[0].template_sha256()
    );

    let (macos_plan, _) = compiled_plan(ArtifactRuntimeTargetV1::MacosArm64, b"VALUE = 1\n");
    assert_eq!(
        validate_macos_linux_vz_typed_package_scenario_binding_v1(
            MacosLinuxVzPackageArtifactKindV1::PypiWheel,
            &macos_plan.canonical_json_v1().expect("macOS wheel plan"),
            &macos_plan.templates()[0]
                .canonical_json_v1()
                .expect("macOS wheel template"),
        ),
        Err(MacosLinuxVzPackageAuthorityRequestErrorV1::RuntimeTargetMismatch)
    );
}

fn wheel_zip(members: &[(String, Vec<u8>)], dist_info: &str) -> Vec<u8> {
    let record_path = format!("{dist_info}/RECORD");
    let mut record = String::new();
    for (path, bytes) in members {
        record.push_str(path);
        record.push(',');
        record.push_str(&wheel_record_hash(bytes));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str(&record_path);
    record.push_str(",,\n");
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in members {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start wheel member");
        writer.write_all(bytes).expect("write wheel member");
    }
    writer
        .start_file(record_path, SimpleFileOptions::default())
        .expect("start RECORD");
    writer.write_all(record.as_bytes()).expect("write RECORD");
    writer.finish().expect("finish wheel").into_inner()
}

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest = Sha256Digest::from_bytes(bytes);
    let digest_hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("digest prefix");
    let digest_bytes = digest_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex utf8"), 16).expect("hex byte")
        })
        .collect::<Vec<_>>();
    format!("sha256={}", base64_url_no_pad(&digest_bytes))
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

#[test]
fn wheel_launch_authority_is_random_single_use_state_bound_to_the_exact_run_spec() {
    let (template, _) = compiled_template(b"VALUE = 1\n");
    let backend = backend(digest(b"measured pip"));
    let run_spec = compile_macos_wheel_run_spec_v1(&template, &backend).expect("run spec");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "whoathere-wheel-authority-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("state root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("protect state root");

    let first = prepare_macos_wheel_launch_v1(&root, run_spec.clone(), 2_000_000_000, 120)
        .expect("first authority");
    let second = prepare_macos_wheel_launch_v1(&root, run_spec.clone(), 2_000_000_001, 120)
        .expect("second authority");
    assert_ne!(
        first.authority().record().authority_id(),
        second.authority().record().authority_id()
    );
    assert_ne!(
        first.authority().record().challenge_binding_sha256(),
        second.authority().record().challenge_binding_sha256()
    );
    assert_eq!(
        first.header().bindings().challenge_binding_sha256(),
        first.authority().record().challenge_binding_sha256()
    );
    assert_eq!(
        first.authority().record().run_spec_sha256(),
        run_spec.run_spec_sha256()
    );
    assert_eq!(
        first.authority().record().artifact_sha256(),
        run_spec.artifact_sha256()
    );
    assert_eq!(
        first.authority().record().issued_at_unix_seconds(),
        2_000_000_000
    );
    assert_eq!(
        first.authority().record().expires_at_unix_seconds(),
        2_000_000_120
    );
    let bytes = fs::read(first.authority().pending_path()).expect("authority bytes");
    assert_eq!(
        first.authority().record_sha256(),
        &Sha256Digest::from_bytes(&bytes)
    );
    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("authority JSON");
    assert_eq!(
        value
            .get("schema_version")
            .and_then(serde_json::Value::as_str),
        Some(MACOS_WHEEL_LAUNCH_AUTHORITY_SCHEMA_V1)
    );
    assert_eq!(
        fs::metadata(first.authority().pending_path())
            .expect("authority metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    for name in [
        "wheel-authorities",
        "wheel-authorities/pending",
        "wheel-authorities/consumed",
    ] {
        assert_eq!(
            fs::metadata(root.join(name))
                .expect("authority directory metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    fs::remove_dir_all(&root).expect("remove authority fixture");
}

#[test]
fn wheel_launch_authority_rejects_unsafe_state_and_excess_lifetime() {
    let (template, _) = compiled_template(b"VALUE = 1\n");
    let backend = backend(digest(b"measured pip"));
    let run_spec = compile_macos_wheel_run_spec_v1(&template, &backend).expect("run spec");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "whoathere-wheel-authority-unsafe-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("state root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).expect("weaken state root");
    assert_eq!(
        prepare_macos_wheel_launch_v1(&root, run_spec.clone(), 2_000_000_000, 120)
            .expect_err("unsafe root"),
        MacosWheelLaunchAuthorityErrorV1::UnsafeStateDirectory
    );
    assert_eq!(
        prepare_macos_wheel_launch_v1(
            &root,
            run_spec,
            2_000_000_000,
            MAX_MACOS_WHEEL_LAUNCH_AUTHORITY_LIFETIME_SECONDS_V1 + 1,
        )
        .expect_err("excess lifetime"),
        MacosWheelLaunchAuthorityErrorV1::InvalidTime
    );
    fs::remove_dir(&root).expect("remove unsafe state root");
}

fn backend(pip_digest: Sha256Digest) -> MacosWheelBackendCapabilitiesV1 {
    backend_with_base(pip_digest, digest(b"base disk"))
}

fn backend_with_base(
    pip_digest: Sha256Digest,
    base_disk_sha256: Sha256Digest,
) -> MacosWheelBackendCapabilitiesV1 {
    let identity = MacosWheelBackendIdentityV1::new(
        "wheel-base-generation-inert-v1",
        base_disk_sha256,
        digest(b"base auxiliary storage"),
        digest(b"hardware model"),
        digest(b"machine identifier"),
        4,
        6_144,
        digest(b"wheel provisioning receipt"),
        digest(b"signed swift helper"),
        digest(b"root wheel guest supervisor"),
        digest(b"guest auth Ed25519 public key"),
        digest(b"wheel runner configuration"),
        499,
        499,
        "3.12.13",
        digest(b"measured python"),
        "26.1.2",
        pip_digest,
        digest(b"apfs clone implementation"),
    )
    .expect("wheel backend identity");
    MacosWheelBackendCapabilitiesV1::inert_first_slice(identity)
}

fn backend_with_guest_identity(
    guest_auth_public_key_sha256: Sha256Digest,
    package_uid: u32,
    package_gid: u32,
) -> MacosWheelBackendCapabilitiesV1 {
    let identity = MacosWheelBackendIdentityV1::new(
        "wheel-base-generation-inert-v1",
        digest(b"base disk"),
        digest(b"base auxiliary storage"),
        digest(b"hardware model"),
        digest(b"machine identifier"),
        4,
        6_144,
        digest(b"wheel provisioning receipt"),
        digest(b"signed swift helper"),
        digest(b"root wheel guest supervisor"),
        guest_auth_public_key_sha256,
        digest(b"wheel runner configuration"),
        package_uid,
        package_gid,
        "3.12.13",
        digest(b"measured python"),
        "26.1.2",
        digest(b"measured pip"),
        digest(b"apfs clone implementation"),
    )
    .expect("wheel guest backend identity");
    MacosWheelBackendCapabilitiesV1::inert_first_slice(identity)
}

#[test]
fn wheel_template_is_nested_in_a_distinct_closed_macos_run_spec() {
    let (template, _) = compiled_template(b"VALUE = 'inert'\n");
    let run_spec = compile_macos_wheel_run_spec_v1(&template, &backend(digest(b"measured pip")))
        .expect("Mac wheel run spec");
    let bytes = run_spec.canonical_json_v1();
    let text = std::str::from_utf8(bytes).expect("run spec UTF-8");
    assert!(text.contains("whoathere.macos_wheel_run_spec.v1"));
    assert!(text.contains("whoathere.wheel_artifact_scenario.v1"));
    assert!(text.contains("zero_network_devices"));
    assert!(text.contains("apfs_clone_required_no_copy_fallback"));
    assert!(text.contains("one_boot_one_scenario_destroy_clone"));
    assert!(text.contains("python_version"));
    assert!(text.contains("pip_version"));
    assert!(text.contains("\"package_username\":\"_whoatherepkg\""));
    assert!(!text.contains("node_version"));
    assert!(!text.contains("npm_version"));
    assert!(!text.contains("sync"));
    assert!(!text.contains("registry"));
    assert!(!text.contains("argv"));
    assert!(!text.contains("verdict"));

    let decoded = decode_and_validate_macos_wheel_run_spec_v1(bytes).expect("strict run spec");
    assert_eq!(decoded.run_spec_sha256(), run_spec.run_spec_sha256());
    assert_eq!(decoded.template_sha256(), template.template_sha256());
    assert_eq!(decoded.scenario_kind(), template.scenario_kind());
    assert_eq!(
        decode_and_validate_macos_artifact_run_spec_v1(bytes),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );
    assert_eq!(
        compile_macos_wheel_run_spec_v1(&template, &backend(digest(b"wrong pip"))),
        Err(MacosArtifactRunErrorV1::BackendCapabilityMismatch)
    );
}

#[test]
fn wheel_run_spec_rejects_noncanonical_unknown_cross_schema_and_backend_tampering() {
    let (template, _) = compiled_template(b"VALUE = 'inert'\n");
    let run_spec = compile_macos_wheel_run_spec_v1(&template, &backend(digest(b"measured pip")))
        .expect("Mac wheel run spec");
    let bytes = run_spec.canonical_json_v1();

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(bytes);
    assert_eq!(
        decode_and_validate_macos_wheel_run_spec_v1(&noncanonical),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(bytes).expect("run spec value");
    unknown["sync_back"] = serde_json::json!(false);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown wire");
    assert_eq!(
        decode_and_validate_macos_wheel_run_spec_v1(&unknown),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );

    let mut cross_schema: serde_json::Value =
        serde_json::from_slice(bytes).expect("run spec value");
    cross_schema["schema_version"] = serde_json::json!("whoathere.macos_artifact_run_spec.v1");
    let cross_schema = serde_json_canonicalizer::to_vec(&cross_schema).expect("cross schema");
    assert_eq!(
        decode_and_validate_macos_wheel_run_spec_v1(&cross_schema),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );

    let mut invalid_uid: serde_json::Value = serde_json::from_slice(bytes).expect("run spec value");
    invalid_uid["backend_identity"]["package_uid"] = serde_json::json!(0);
    let invalid_uid = serde_json_canonicalizer::to_vec(&invalid_uid).expect("invalid UID");
    assert_eq!(
        decode_and_validate_macos_wheel_run_spec_v1(&invalid_uid),
        Err(MacosArtifactRunErrorV1::InvalidBackendIdentity)
    );

    let mut protocol: serde_json::Value = serde_json::from_slice(bytes).expect("run spec value");
    protocol["guest_protocol"] = serde_json::json!("whoathere.artifact_scenario.v1");
    let protocol = serde_json_canonicalizer::to_vec(&protocol).expect("protocol wire");
    assert_eq!(
        decode_and_validate_macos_wheel_run_spec_v1(&protocol),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );
}

#[test]
fn exact_wheel_and_backend_measurements_rebind_macos_wheel_run_spec() {
    let (first, _) = compiled_template(b"VALUE = 'inert'\n");
    let (changed, _) = compiled_template(b"VALUE = 'changed inert byte'\n");
    let backend = backend(digest(b"measured pip"));
    let first_spec = compile_macos_wheel_run_spec_v1(&first, &backend).expect("first spec");
    let changed_spec = compile_macos_wheel_run_spec_v1(&changed, &backend).expect("changed spec");
    assert_ne!(first_spec.run_spec_sha256(), changed_spec.run_spec_sha256());
    assert_ne!(first_spec.artifact_sha256(), changed_spec.artifact_sha256());

    let changed_backend = backend_with_base(digest(b"measured pip"), digest(b"changed base disk"));
    let changed_backend_spec =
        compile_macos_wheel_run_spec_v1(&first, &changed_backend).expect("changed backend spec");
    assert_ne!(
        first_spec.run_spec_sha256(),
        changed_backend_spec.run_spec_sha256()
    );
    assert_eq!(
        first_spec.template_sha256(),
        changed_backend_spec.template_sha256()
    );
}

#[test]
fn exact_wheel_round_trips_through_a_distinct_challenge_bound_binary_frame() {
    let (template, artifact) = compiled_template(b"VALUE = 'inert'\n");
    let run_spec = compile_macos_wheel_run_spec_v1(&template, &backend(digest(b"measured pip")))
        .expect("Mac wheel run spec");
    let bindings =
        MacosWheelSubmissionBindingsV1::for_run_spec(digest(b"wheel challenge"), &run_spec);
    let header = MacosWheelSubmissionHeaderV1::new(run_spec.clone(), bindings.clone())
        .expect("wheel header");
    let encoded = encode_macos_wheel_submission_frame_v1(&header, &artifact).expect("wheel frame");
    assert_eq!(&encoded[..8], &MACOS_WHEEL_SUBMISSION_MAGIC_V1);
    assert!(encoded.ends_with(&artifact));
    assert_eq!(
        encoded.len(),
        MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1
            + header.canonical_json_v1().len()
            + artifact.len()
    );
    let decoded =
        decode_macos_wheel_submission_frame_v1(&encoded, &bindings).expect("decoded frame");
    assert_eq!(decoded.header().run_spec(), &run_spec);
    assert_eq!(decoded.artifact_bytes(), artifact);

    let wrong_bindings =
        MacosWheelSubmissionBindingsV1::for_run_spec(digest(b"other challenge"), &run_spec);
    assert_eq!(
        decode_macos_wheel_submission_frame_v1(&encoded, &wrong_bindings),
        Err(MacosWheelSubmissionErrorV1::BindingMismatch)
    );

    let mut truncated = encoded.clone();
    truncated.pop();
    assert_eq!(
        decode_macos_wheel_submission_frame_v1(&truncated, &bindings),
        Err(MacosWheelSubmissionErrorV1::Truncated)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        decode_macos_wheel_submission_frame_v1(&trailing, &bindings),
        Err(MacosWheelSubmissionErrorV1::TrailingData)
    );
    let mut mutated = encoded.clone();
    *mutated.last_mut().expect("artifact byte") ^= 1;
    assert_eq!(
        decode_macos_wheel_submission_frame_v1(&mutated, &bindings),
        Err(MacosWheelSubmissionErrorV1::ArtifactDigestMismatch)
    );
    let mut npm_magic = encoded.clone();
    npm_magic[..8].copy_from_slice(b"WHOAART1");
    assert_eq!(
        decode_macos_wheel_submission_frame_v1(&npm_magic, &bindings),
        Err(MacosWheelSubmissionErrorV1::InvalidMagic)
    );

    let header_start = MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1;
    let header_len =
        u32::from_be_bytes(encoded[12..16].try_into().expect("header length")) as usize;
    let mut header_value: serde_json::Value =
        serde_json::from_slice(&encoded[header_start..header_start + header_len])
            .expect("header value");
    header_value["sync_back"] = serde_json::json!(false);
    let unknown_header = serde_json_canonicalizer::to_vec(&header_value).expect("unknown header");
    let rebuilt = rebuild_wheel_frame(&encoded, &unknown_header);
    assert_eq!(
        decode_macos_wheel_submission_frame_v1(&rebuilt, &bindings),
        Err(MacosWheelSubmissionErrorV1::InvalidHeader)
    );
}

#[test]
fn wheel_guest_submission_streams_exact_bytes_and_rejects_other_transport_domains() {
    let (template, artifact) = compiled_template(b"VALUE = 'inert'\n");
    let run_spec = compile_macos_wheel_run_spec_v1(&template, &backend(digest(b"measured pip")))
        .expect("Mac wheel run spec");
    let bindings =
        MacosWheelSubmissionBindingsV1::for_run_spec(digest(b"wheel challenge"), &run_spec);
    let header =
        MacosWheelSubmissionHeaderV1::new(run_spec.clone(), bindings).expect("wheel header");
    let mut guest =
        encode_macos_wheel_submission_frame_v1(&header, &artifact).expect("host wheel frame");
    guest[..8].copy_from_slice(&MACOS_WHEEL_GUEST_SUBMISSION_MAGIC_V1);

    let mut fragmented = FragmentedReader::new(&guest, 3);
    let mut staged = Vec::new();
    let observation = stream_macos_wheel_guest_submission_v1(&mut fragmented, &mut staged)
        .expect("streamed wheel guest frame");
    assert_eq!(staged, artifact);
    assert_eq!(observation.artifact_sha256(), run_spec.artifact_sha256());
    assert_eq!(observation.artifact_byte_length(), artifact.len() as u64);
    assert_eq!(observation.header().run_spec(), &run_spec);

    for wrong_magic in [MACOS_WHEEL_SUBMISSION_MAGIC_V1, *b"WHOAGST1"] {
        let mut wrong = guest.clone();
        wrong[..8].copy_from_slice(&wrong_magic);
        let mut staged = Vec::new();
        assert_eq!(
            stream_macos_wheel_guest_submission_v1(&mut Cursor::new(wrong), &mut staged),
            Err(MacosWheelSubmissionErrorV1::InvalidMagic)
        );
        assert!(staged.is_empty());
    }

    let mut mutated = guest.clone();
    *mutated.last_mut().expect("artifact byte") ^= 1;
    let mut staged = Vec::new();
    assert_eq!(
        stream_macos_wheel_guest_submission_v1(&mut Cursor::new(mutated), &mut staged),
        Err(MacosWheelSubmissionErrorV1::ArtifactDigestMismatch)
    );
    assert_eq!(staged.len(), artifact.len());

    let mut trailing = guest.clone();
    trailing.push(0);
    let mut staged = Vec::new();
    assert_eq!(
        stream_macos_wheel_guest_submission_v1(&mut Cursor::new(trailing), &mut staged),
        Err(MacosWheelSubmissionErrorV1::TrailingData)
    );
    assert_eq!(staged, artifact);

    let mut staged = Vec::new();
    assert_eq!(
        stream_macos_wheel_guest_submission_v1(
            &mut Cursor::new(&guest[..guest.len() - 1]),
            &mut staged
        ),
        Err(MacosWheelSubmissionErrorV1::Truncated)
    );
}

struct FragmentedReader<'a> {
    bytes: &'a [u8],
    offset: usize,
    maximum_chunk: usize,
}

impl<'a> FragmentedReader<'a> {
    fn new(bytes: &'a [u8], maximum_chunk: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            maximum_chunk,
        }
    }
}

impl Read for FragmentedReader<'_> {
    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
        if self.offset == self.bytes.len() {
            return Ok(0);
        }
        let count = destination
            .len()
            .min(self.maximum_chunk)
            .min(self.bytes.len() - self.offset);
        destination[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

fn rebuild_wheel_frame(frame: &[u8], header: &[u8]) -> Vec<u8> {
    let old_header_len =
        u32::from_be_bytes(frame[12..16].try_into().expect("header length")) as usize;
    let artifact_start = MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1 + old_header_len;
    let mut rebuilt = Vec::with_capacity(
        MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1 + header.len() + frame.len() - artifact_start,
    );
    rebuilt.extend_from_slice(&frame[..12]);
    rebuilt.extend_from_slice(&(header.len() as u32).to_be_bytes());
    rebuilt.extend_from_slice(&frame[16..MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1]);
    rebuilt.extend_from_slice(header);
    rebuilt.extend_from_slice(&frame[artifact_start..]);
    rebuilt
}

#[test]
fn wheel_execution_binding_matches_the_cross_language_golden() {
    let challenge = digest(b"wheel challenge");
    let run_spec = digest(b"wheel run spec");
    assert_eq!(
        challenge.as_str(),
        "sha256:b1ab8715aa7684198e18b8edf39eda977c1ed27ea8ef39d3bbed8289e6fbcae2"
    );
    assert_eq!(
        run_spec.as_str(),
        "sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e"
    );
    assert_eq!(
        macos_wheel_execution_binding_sha256_v1(&challenge, &run_spec).as_str(),
        "sha256:fc895a01869db614532cae70220cdafe0eec5a6682b8197dcc6bab91fc04ef33"
    );
}

#[test]
fn wheel_guest_authentication_is_signed_fresh_and_cross_ecosystem_closed() {
    let seed = [7_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let challenge = MacosWheelGuestAuthChallengeV1::new(
        [11_u8; 32],
        digest(b"wheel execution binding"),
        digest(b"wheel run spec"),
        digest(b"wheel clone binding"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("wheel guest challenge");
    assert_eq!(
        decode_macos_wheel_guest_auth_challenge_v1(challenge.canonical_json_v1())
            .expect("strict wheel challenge"),
        challenge
    );
    let claims = MacosWheelGuestAuthClaimsV1::new(
        digest(b"wheel guest supervisor"),
        digest(b"wheel runner configuration"),
        499,
        499,
    )
    .expect("wheel claims");
    let response = sign_macos_wheel_guest_auth_response_v1(&challenge, seed, &claims)
        .expect("signed wheel response");
    verify_macos_wheel_guest_auth_response_v1(&challenge, &response, verifying_key, &claims)
        .expect("verified wheel response");

    assert_eq!(
        std::str::from_utf8(challenge.canonical_json_v1()).expect("challenge UTF-8"),
        r#"{"clone_binding_sha256":"sha256:29bea0252f37265b288224ebf9b5220fd7d9696fc64aa65f4d6322560182cb51","execution_binding_sha256":"sha256:26ba19f41ff9747505dcbc06292c2debb15a97fe8cb80f2a7625ceba0653356d","guest_auth_public_key_sha256":"sha256:fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889","nonce_hex":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","run_spec_sha256":"sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e","schema_version":"whoathere.wheel_guest_auth_challenge.v1"}"#
    );
    assert_eq!(
        std::str::from_utf8(&response).expect("response UTF-8"),
        r#"{"challenge_sha256":"sha256:763b43adeed736fc4fe75497780a71f412e4ea13628f50b63e0448c44e1c6d41","clone_binding_sha256":"sha256:29bea0252f37265b288224ebf9b5220fd7d9696fc64aa65f4d6322560182cb51","execution_binding_sha256":"sha256:26ba19f41ff9747505dcbc06292c2debb15a97fe8cb80f2a7625ceba0653356d","guest_supervisor_sha256":"sha256:0d2f2274c6f58bd4cc5430838896cc59b5e5ed4840de084cea26af903f93276e","package_gid":"499","package_uid":"499","run_spec_sha256":"sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e","runner_configuration_sha256":"sha256:0e539a3c126c40c4efdfae8fb67ad5fb81f57660a4de665743586531faafc67b","schema_version":"whoathere.wheel_guest_auth_response.v1","signature_ed25519_hex":"deca32783d5e3774da376dad89cce630f9c9ddc69cf14abffcb921213e6fc9c2832f3d97c7b6d62062829f74843281aa8ebbe52f0876199871dcbd461dc6bb01"}"#
    );

    let mut npm_schema: serde_json::Value =
        serde_json::from_slice(challenge.canonical_json_v1()).expect("challenge JSON");
    npm_schema["schema_version"] = serde_json::json!("whoathere.artifact_guest_auth_challenge.v1");
    let npm_schema = serde_json_canonicalizer::to_vec(&npm_schema).expect("npm challenge schema");
    assert_eq!(
        decode_macos_wheel_guest_auth_challenge_v1(&npm_schema),
        Err(MacosWheelGuestAuthErrorV1::NonCanonical)
    );

    let fresh = MacosWheelGuestAuthChallengeV1::new(
        [12_u8; 32],
        digest(b"wheel execution binding"),
        digest(b"wheel run spec"),
        digest(b"wheel clone binding"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("fresh wheel challenge");
    assert_eq!(
        verify_macos_wheel_guest_auth_response_v1(&fresh, &response, verifying_key, &claims),
        Err(MacosWheelGuestAuthErrorV1::InvalidResponse)
    );

    let forged_claims = MacosWheelGuestAuthClaimsV1::new(
        digest(b"wheel guest supervisor"),
        digest(b"wheel runner configuration"),
        500,
        499,
    )
    .expect("forged wheel claims");
    let mut forged: serde_json::Value =
        serde_json::from_slice(&response).expect("wheel response JSON");
    forged["package_uid"] = serde_json::json!("500");
    let forged = serde_json_canonicalizer::to_vec(&forged).expect("forged wheel response");
    assert_eq!(
        verify_macos_wheel_guest_auth_response_v1(
            &challenge,
            &forged,
            verifying_key,
            &forged_claims
        ),
        Err(MacosWheelGuestAuthErrorV1::SignatureFailed)
    );
    assert_eq!(
        sign_macos_wheel_guest_auth_response_v1(&challenge, [8_u8; 32], &claims),
        Err(MacosWheelGuestAuthErrorV1::PublicKeyMismatch)
    );
}

#[test]
fn wheel_guest_control_frames_are_bounded_ordered_and_cross_ecosystem_closed() {
    let challenge = br#"{"wheel_challenge":"inert"}"#;
    let response = br#"{"wheel_response":"inert"}"#;
    let receipt = br#"{"wheel_receipt":"inert"}"#;
    let mut wire = Vec::new();
    write_macos_wheel_guest_control_frame_v1(
        &mut wire,
        MacosWheelGuestControlFrameTypeV1::AuthenticationChallenge,
        challenge,
    )
    .expect("challenge frame");
    write_macos_wheel_guest_control_frame_v1(
        &mut wire,
        MacosWheelGuestControlFrameTypeV1::AuthenticationResponse,
        response,
    )
    .expect("response frame");
    write_macos_wheel_guest_control_frame_v1(
        &mut wire,
        MacosWheelGuestControlFrameTypeV1::StagingReceipt,
        receipt,
    )
    .expect("receipt frame");

    let mut reader = FragmentedReader::new(&wire, 2);
    assert_eq!(
        read_macos_wheel_guest_control_frame_v1(
            &mut reader,
            MacosWheelGuestControlFrameTypeV1::AuthenticationChallenge,
            1024,
        )
        .expect("challenge"),
        challenge
    );
    assert_eq!(
        read_macos_wheel_guest_control_frame_v1(
            &mut reader,
            MacosWheelGuestControlFrameTypeV1::AuthenticationResponse,
            1024,
        )
        .expect("response"),
        response
    );
    assert_eq!(
        read_macos_wheel_guest_control_frame_v1(
            &mut reader,
            MacosWheelGuestControlFrameTypeV1::StagingReceipt,
            1024,
        )
        .expect("receipt"),
        receipt
    );
    require_macos_wheel_guest_control_eof_v1(&mut reader).expect("control EOF");

    let mut npm_magic = wire.clone();
    npm_magic[..8].copy_from_slice(b"WHOACTL1");
    assert_eq!(
        read_macos_wheel_guest_control_frame_v1(
            &mut Cursor::new(npm_magic),
            MacosWheelGuestControlFrameTypeV1::AuthenticationChallenge,
            1024,
        ),
        Err(MacosWheelGuestControlErrorV1::InvalidMagic)
    );
    assert_eq!(
        read_macos_wheel_guest_control_frame_v1(
            &mut Cursor::new(&wire),
            MacosWheelGuestControlFrameTypeV1::AuthenticationResponse,
            1024,
        ),
        Err(MacosWheelGuestControlErrorV1::UnexpectedFrameType)
    );
    assert_eq!(
        read_macos_wheel_guest_control_frame_v1(
            &mut Cursor::new(&wire[..15]),
            MacosWheelGuestControlFrameTypeV1::AuthenticationChallenge,
            1024,
        ),
        Err(MacosWheelGuestControlErrorV1::Truncated)
    );
    assert_eq!(
        write_macos_wheel_guest_control_frame_v1(
            &mut Vec::new(),
            MacosWheelGuestControlFrameTypeV1::AuthenticationChallenge,
            &[],
        ),
        Err(MacosWheelGuestControlErrorV1::BodyLimitExceeded)
    );
}

#[test]
fn wheel_guest_staging_is_exclusive_read_only_rehashed_and_removed() {
    let (guest, artifact, run_spec) = wheel_guest_staging_frame();
    let root = temporary_wheel_staging_root("success");
    let policy = wheel_staging_policy(&root);
    let mut staged = stage_macos_wheel_guest_submission_v1(&mut Cursor::new(guest), &policy)
        .expect("stage inert wheel");
    let path = staged.artifact_path().to_path_buf();
    assert_eq!(
        path.file_name().and_then(|value| value.to_str()),
        Some("artifact.whl")
    );
    let metadata = fs::symlink_metadata(&path).expect("staged wheel metadata");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o777, 0o444);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.len(), artifact.len() as u64);
    assert_eq!(
        staged.transport().artifact_sha256(),
        run_spec.artifact_sha256()
    );

    let prelaunch = staged.verify_prelaunch().expect("wheel prelaunch rehash");
    let postrun = staged.verify_postrun().expect("wheel postrun rehash");
    assert_eq!(prelaunch.phase(), WheelGuestRehashPhaseV1::Prelaunch);
    assert_eq!(postrun.phase(), WheelGuestRehashPhaseV1::Postrun);
    assert_eq!(prelaunch.artifact_sha256(), run_spec.artifact_sha256());
    assert_eq!(prelaunch.artifact_byte_length(), artifact.len() as u64);
    assert_eq!(prelaunch.device(), postrun.device());
    assert_eq!(prelaunch.inode(), postrun.inode());

    let directory = path
        .parent()
        .expect("wheel scenario directory")
        .to_path_buf();
    staged.cleanup().expect("verified wheel cleanup");
    assert!(!directory.exists());
    assert_eq!(fs::read_dir(&root).expect("empty wheel root").count(), 0);
    fs::remove_dir(root).expect("remove wheel staging root");
}

#[test]
fn wheel_guest_staging_discards_bad_transport_and_detects_path_replacement() {
    let (mut guest, _, _) = wheel_guest_staging_frame();
    let root = temporary_wheel_staging_root("failure");
    let policy = wheel_staging_policy(&root);
    *guest.last_mut().expect("wheel byte") ^= 1;
    assert_eq!(
        stage_macos_wheel_guest_submission_v1(&mut Cursor::new(guest), &policy)
            .expect_err("mutated wheel must fail"),
        MacosWheelGuestStagingErrorV1::Transport(
            MacosWheelSubmissionErrorV1::ArtifactDigestMismatch
        )
    );
    assert_eq!(fs::read_dir(&root).expect("cleaned wheel root").count(), 0);

    let (guest, artifact, _) = wheel_guest_staging_frame();
    let mut staged = stage_macos_wheel_guest_submission_v1(&mut Cursor::new(guest), &policy)
        .expect("stage replacement fixture");
    let path = staged.artifact_path().to_path_buf();
    let held = path.with_file_name("held-original.whl");
    fs::rename(&path, &held).expect("move original wheel");
    fs::write(&path, &artifact).expect("write replacement wheel");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
        .expect("protect replacement wheel");
    assert_eq!(
        staged.verify_prelaunch(),
        Err(MacosWheelGuestStagingErrorV1::VerificationFailed)
    );
    assert_eq!(
        staged.cleanup(),
        Err(MacosWheelGuestStagingErrorV1::CleanupFailed)
    );
    assert!(held.exists());
    fs::remove_file(held).expect("remove held original wheel");
    staged.cleanup().expect("retry wheel cleanup");
    assert_eq!(fs::read_dir(&root).expect("clean wheel root").count(), 0);
    fs::remove_dir(root).expect("remove wheel staging root");
}

#[test]
fn signed_wheel_staging_receipt_binds_held_inode_and_no_execution_posture() {
    let seed = [7_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let challenge = MacosWheelGuestAuthChallengeV1::new(
        [11_u8; 32],
        digest(b"wheel execution binding"),
        digest(b"wheel run spec"),
        digest(b"wheel clone binding"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("wheel receipt challenge");
    let auth_claims = MacosWheelGuestAuthClaimsV1::new(
        digest(b"wheel guest supervisor"),
        digest(b"wheel runner configuration"),
        499,
        499,
    )
    .expect("wheel auth claims");
    let staging_claims = MacosWheelGuestStagingReceiptClaimsV1::new(
        digest(b"wheel artifact"),
        205,
        digest(b"wheel artifact"),
        205,
        123,
        456,
    )
    .expect("wheel staging claims");
    let receipt =
        sign_macos_wheel_guest_staging_receipt_v1(&challenge, seed, &auth_claims, &staging_claims)
            .expect("signed wheel staging receipt");
    let observation = verify_macos_wheel_guest_staging_receipt_v1(
        &challenge,
        &receipt,
        verifying_key,
        &auth_claims,
        &staging_claims,
    )
    .expect("verified wheel staging receipt");
    assert_eq!(observation.package_uid(), 499);
    assert_eq!(observation.package_gid(), 499);
    assert_eq!(observation.claims().staged_device(), 123);
    assert_eq!(observation.claims().staged_inode(), 456);
    assert_eq!(
        std::str::from_utf8(&receipt).expect("receipt UTF-8"),
        r#"{"artifact_byte_length":"205","artifact_file_mode":"0444","artifact_file_name":"artifact.whl","artifact_sha256":"sha256:b0d81135ac556bd1bd195274005aed8ae034601b9393d1900347076a4e8928b1","challenge_sha256":"sha256:763b43adeed736fc4fe75497780a71f412e4ea13628f50b63e0448c44e1c6d41","clone_binding_sha256":"sha256:29bea0252f37265b288224ebf9b5220fd7d9696fc64aa65f4d6322560182cb51","execution_binding_sha256":"sha256:26ba19f41ff9747505dcbc06292c2debb15a97fe8cb80f2a7625ceba0653356d","first_rehash_byte_length":"205","first_rehash_sha256":"sha256:b0d81135ac556bd1bd195274005aed8ae034601b9393d1900347076a4e8928b1","package_execution_enabled":false,"package_gid":"499","package_uid":"499","run_spec_sha256":"sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e","schema_version":"whoathere.wheel_guest_staging_receipt.v1","signature_ed25519_hex":"4a5e8648d3d1757c69af3c66bfc6bfdd50ac12af8bbe3cc59219a0810f224e14836e5836d7f33830594d7d777125ef2e67cde9019790635be978868fa51fdf04","staged_device":"123","staged_inode":"456","staging_directory_mode":"0711","status":"staged_no_execution"}"#
    );

    let mut execution_enabled: serde_json::Value =
        serde_json::from_slice(&receipt).expect("receipt JSON");
    execution_enabled["package_execution_enabled"] = serde_json::json!(true);
    let execution_enabled =
        serde_json_canonicalizer::to_vec(&execution_enabled).expect("enabled receipt");
    assert_eq!(
        verify_macos_wheel_guest_staging_receipt_v1(
            &challenge,
            &execution_enabled,
            verifying_key,
            &auth_claims,
            &staging_claims,
        ),
        Err(MacosWheelGuestAuthErrorV1::InvalidResponse)
    );

    let wrong_inode = MacosWheelGuestStagingReceiptClaimsV1::new(
        digest(b"wheel artifact"),
        205,
        digest(b"wheel artifact"),
        205,
        123,
        457,
    )
    .expect("wrong inode claims");
    assert_eq!(
        verify_macos_wheel_guest_staging_receipt_v1(
            &challenge,
            &receipt,
            verifying_key,
            &auth_claims,
            &wrong_inode,
        ),
        Err(MacosWheelGuestAuthErrorV1::InvalidResponse)
    );
}

#[test]
fn wheel_guest_supervisor_authenticates_stages_cleans_attests_and_never_executes() {
    let seed = [7_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let root = temporary_wheel_staging_root("supervisor-success");
    let policy = wheel_staging_policy(&root);
    let package_gid = 499;
    let (guest, artifact, run_spec, bindings) =
        wheel_supervisor_guest_frame(verifying_key, policy.package_uid(), package_gid);
    let claims = MacosWheelGuestAuthClaimsV1::new(
        digest(b"root wheel guest supervisor"),
        digest(b"wheel runner configuration"),
        policy.package_uid(),
        package_gid,
    )
    .expect("wheel supervisor claims");
    let challenge = MacosWheelGuestAuthChallengeV1::new(
        [13_u8; 32],
        bindings.execution_binding_sha256().clone(),
        run_spec.run_spec_sha256().clone(),
        digest(b"unique wheel clone"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("wheel supervisor challenge");
    let mut input = Vec::new();
    write_macos_wheel_guest_control_frame_v1(
        &mut input,
        MacosWheelGuestControlFrameTypeV1::AuthenticationChallenge,
        challenge.canonical_json_v1(),
    )
    .expect("wheel challenge frame");
    input.extend_from_slice(&guest);

    let mut output = Vec::new();
    let observation = run_macos_wheel_guest_nonexecuting_session_v1(
        &mut Cursor::new(input),
        &mut output,
        seed,
        &claims,
        &policy,
    )
    .expect("non-executing wheel session");
    assert_eq!(observation.artifact_sha256(), &digest(&artifact));
    assert_eq!(observation.artifact_byte_length(), artifact.len() as u64);
    assert_eq!(observation.first_rehash_sha256(), &digest(&artifact));
    assert_eq!(observation.package_uid(), policy.package_uid());
    assert_eq!(observation.package_gid(), package_gid);
    assert!(observation.staging_cleanup_succeeded());
    assert!(!observation.package_execution_enabled());
    assert_eq!(fs::read_dir(&root).expect("clean wheel root").count(), 0);

    let mut output = Cursor::new(output);
    let auth_response = read_macos_wheel_guest_control_frame_v1(
        &mut output,
        MacosWheelGuestControlFrameTypeV1::AuthenticationResponse,
        16 * 1024,
    )
    .expect("wheel auth response");
    verify_macos_wheel_guest_auth_response_v1(&challenge, &auth_response, verifying_key, &claims)
        .expect("verified wheel auth response");
    let receipt = read_macos_wheel_guest_control_frame_v1(
        &mut output,
        MacosWheelGuestControlFrameTypeV1::StagingReceipt,
        16 * 1024,
    )
    .expect("wheel staging receipt");
    let staging_claims = MacosWheelGuestStagingReceiptClaimsV1::new(
        observation.artifact_sha256().clone(),
        observation.artifact_byte_length(),
        observation.first_rehash_sha256().clone(),
        observation.first_rehash_byte_length(),
        observation.staged_device(),
        observation.staged_inode(),
    )
    .expect("wheel expected staging claims");
    verify_macos_wheel_guest_staging_receipt_v1(
        &challenge,
        &receipt,
        verifying_key,
        &claims,
        &staging_claims,
    )
    .expect("verified wheel staging receipt");
    require_macos_wheel_guest_control_eof_v1(&mut output).expect("wheel supervisor EOF");
    fs::remove_dir(&root).expect("remove clean wheel root");
}

#[test]
fn wheel_guest_supervisor_rejects_challenge_rebinding_and_cleans_staging() {
    let seed = [7_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let root = temporary_wheel_staging_root("supervisor-rebinding");
    let policy = wheel_staging_policy(&root);
    let package_gid = 499;
    let (guest, _, run_spec, _) =
        wheel_supervisor_guest_frame(verifying_key, policy.package_uid(), package_gid);
    let claims = MacosWheelGuestAuthClaimsV1::new(
        digest(b"root wheel guest supervisor"),
        digest(b"wheel runner configuration"),
        policy.package_uid(),
        package_gid,
    )
    .expect("wheel supervisor claims");
    let challenge = MacosWheelGuestAuthChallengeV1::new(
        [14_u8; 32],
        digest(b"wrong wheel execution binding"),
        run_spec.run_spec_sha256().clone(),
        digest(b"unique wheel clone"),
        Sha256Digest::from_bytes(&verifying_key),
    )
    .expect("rebound wheel challenge");
    let mut input = Vec::new();
    write_macos_wheel_guest_control_frame_v1(
        &mut input,
        MacosWheelGuestControlFrameTypeV1::AuthenticationChallenge,
        challenge.canonical_json_v1(),
    )
    .expect("wheel challenge frame");
    input.extend_from_slice(&guest);

    let mut output = Vec::new();
    let failure = run_macos_wheel_guest_nonexecuting_session_v1(
        &mut Cursor::new(input),
        &mut output,
        seed,
        &claims,
        &policy,
    )
    .expect_err("rebound wheel must fail");
    assert_eq!(
        failure.primary(),
        MacosWheelGuestSupervisorPrimaryErrorV1::BindingMismatch
    );
    assert!(!failure.staging_cleanup_failed());
    assert_eq!(fs::read_dir(&root).expect("clean wheel root").count(), 0);

    let mut output = Cursor::new(output);
    let auth_response = read_macos_wheel_guest_control_frame_v1(
        &mut output,
        MacosWheelGuestControlFrameTypeV1::AuthenticationResponse,
        16 * 1024,
    )
    .expect("auth response precedes wheel");
    verify_macos_wheel_guest_auth_response_v1(&challenge, &auth_response, verifying_key, &claims)
        .expect("verified rebound auth response");
    require_macos_wheel_guest_control_eof_v1(&mut output)
        .expect("no receipt after wheel binding failure");
    fs::remove_dir(&root).expect("remove rebound wheel root");
}

fn wheel_supervisor_guest_frame(
    verifying_key: [u8; 32],
    package_uid: u32,
    package_gid: u32,
) -> (
    Vec<u8>,
    Vec<u8>,
    whoathere_macos_vm::MacosWheelRunSpecV1,
    MacosWheelSubmissionBindingsV1,
) {
    let (template, artifact) = compiled_template(b"VALUE = 'inert'\n");
    let backend = backend_with_guest_identity(
        Sha256Digest::from_bytes(&verifying_key),
        package_uid,
        package_gid,
    );
    let run_spec =
        compile_macos_wheel_run_spec_v1(&template, &backend).expect("wheel supervisor run spec");
    let bindings =
        MacosWheelSubmissionBindingsV1::for_run_spec(digest(b"wheel challenge"), &run_spec);
    let header = MacosWheelSubmissionHeaderV1::new(run_spec.clone(), bindings.clone())
        .expect("wheel supervisor header");
    let mut guest =
        encode_macos_wheel_submission_frame_v1(&header, &artifact).expect("wheel supervisor frame");
    guest[..8].copy_from_slice(&MACOS_WHEEL_GUEST_SUBMISSION_MAGIC_V1);
    (guest, artifact, run_spec, bindings)
}

fn wheel_guest_staging_frame() -> (Vec<u8>, Vec<u8>, whoathere_macos_vm::MacosWheelRunSpecV1) {
    let (template, artifact) = compiled_template(b"VALUE = 'inert'\n");
    let run_spec = compile_macos_wheel_run_spec_v1(&template, &backend(digest(b"measured pip")))
        .expect("wheel staging run spec");
    let bindings =
        MacosWheelSubmissionBindingsV1::for_run_spec(digest(b"wheel staging challenge"), &run_spec);
    let header = MacosWheelSubmissionHeaderV1::new(run_spec.clone(), bindings)
        .expect("wheel staging header");
    let mut guest =
        encode_macos_wheel_submission_frame_v1(&header, &artifact).expect("wheel staging frame");
    guest[..8].copy_from_slice(&MACOS_WHEEL_GUEST_SUBMISSION_MAGIC_V1);
    (guest, artifact, run_spec)
}

fn temporary_wheel_staging_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "whoathere-wheel-staging-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create wheel staging root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("protect wheel staging root");
    root
}

fn wheel_staging_policy(root: &std::path::Path) -> MacosWheelGuestStagingPolicyV1 {
    let supervisor_uid = fs::symlink_metadata(root)
        .expect("wheel root metadata")
        .uid();
    let package_uid = if supervisor_uid == u32::MAX {
        1
    } else {
        (supervisor_uid + 1).max(1)
    };
    MacosWheelGuestStagingPolicyV1::for_current_supervisor(root.to_path_buf(), package_uid)
        .expect("wheel staging policy")
}
