use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Barrier};
use std::time::{SystemTime, UNIX_EPOCH};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_sdist_scenarios_v1, expected_sdist_scenario_kinds_v1,
    ArtifactScenarioExecutionIdentityV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
    SdistRuntimeProfileV1, SdistScenarioCompilationRequestV1, SdistScenarioIdentitySetV1,
    SdistScenarioKindV1, SdistScenarioPolicyV1, SdistScenarioTemplateV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    compile_macos_sdist_run_spec_v1, consume_and_authorize_macos_sdist_guest_session_v1,
    consume_macos_sdist_launch_authority_v1, decode_and_validate_macos_artifact_run_spec_v1,
    decode_and_validate_macos_sdist_run_spec_v1, decode_and_validate_macos_wheel_run_spec_v1,
    decode_macos_sdist_guest_auth_challenge_v1, decode_macos_sdist_submission_frame_v1,
    encode_macos_sdist_submission_frame_v1, prepare_macos_sdist_launch_v1,
    read_macos_sdist_guest_control_frame_v1, require_macos_sdist_guest_control_eof_v1,
    run_macos_sdist_guest_nonexecuting_session_v1, sign_macos_sdist_guest_auth_response_v1,
    sign_macos_sdist_guest_staging_receipt_v1, stage_macos_sdist_guest_submission_v1,
    stream_macos_sdist_guest_submission_v1, verify_macos_sdist_guest_auth_response_v1,
    verify_macos_sdist_guest_staging_receipt_v1, write_macos_sdist_guest_control_frame_v1,
    MacosArtifactRunErrorV1, MacosSdistBackendCapabilitiesV1, MacosSdistBackendIdentityV1,
    MacosSdistGuestAuthChallengeV1, MacosSdistGuestAuthClaimsV1, MacosSdistGuestAuthErrorV1,
    MacosSdistGuestControlErrorV1, MacosSdistGuestControlFrameTypeV1,
    MacosSdistGuestStagingErrorV1, MacosSdistGuestStagingPolicyV1,
    MacosSdistGuestStagingReceiptClaimsV1, MacosSdistGuestSupervisorPrimaryErrorV1,
    MacosSdistLaunchAuthorityConsumptionRequestV1, MacosSdistLaunchAuthorityErrorV1,
    MacosSdistSubmissionBindingsV1, MacosSdistSubmissionErrorV1, MacosSdistSubmissionHeaderV1,
    SdistGuestRehashPhaseV1, MACOS_SDIST_GUEST_PROTOCOL_V1, MACOS_SDIST_GUEST_SUBMISSION_MAGIC_V1,
    MACOS_SDIST_RUN_SPEC_SCHEMA_V1, MACOS_SDIST_SUBMISSION_FIXED_PREFIX_BYTES_V1,
    MACOS_SDIST_SUBMISSION_MAGIC_V1, MAX_MACOS_SDIST_LAUNCH_AUTHORITY_LIFETIME_SECONDS_V1,
};

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(bytes)
}

fn tar_gzip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
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
            .append_data(&mut header, path, Cursor::new(bytes))
            .expect("append inert member");
    }
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn compiled_templates(init_bytes: &[u8]) -> (Vec<SdistScenarioTemplateV1>, Vec<u8>) {
    const ROOT: &str = "macos_sdist_fixture-1.0.0";
    let mut entries = vec![
        (
            format!("{ROOT}/PKG-INFO"),
            b"Metadata-Version: 2.3\nName: macos-sdist-fixture\nVersion: 1.0.0\n"
                .to_vec(),
        ),
        (
            format!("{ROOT}/pyproject.toml"),
            b"[build-system]\nrequires = [\"setuptools==75.0.0\", \"wheel==0.44.0\"]\nbuild-backend = \"setuptools.build_meta\"\n\n[project]\nname = \"macos-sdist-fixture\"\nversion = \"1.0.0\"\n"
                .to_vec(),
        ),
        (
            format!("{ROOT}/setup.cfg"),
            b"[metadata]\nname = macos-sdist-fixture\nversion = 1.0.0\n\n[options]\npackage_dir =\n    =src\npackages = find:\n"
                .to_vec(),
        ),
        (
            format!("{ROOT}/setup.py"),
            b"from setuptools import setup\nsetup()\n".to_vec(),
        ),
        (
            format!("{ROOT}/src/macos_sdist_fixture/__init__.py"),
            init_bytes.to_vec(),
        ),
    ];
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let bytes = tar_gzip(&entries);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("macos-sdist-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:macos-sdist-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-11T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "macos_sdist_fixture-1.0.0.tar.gz".to_string(),
            declared_format: Some(ArtifactFormat::SdistTarGzip),
            custody_reference: "repository-inert-sdist-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "macos-sdist-first-slice.v1".to_string(),
            requires_external_dependency_resolution: true,
        },
        &bytes,
        ArtifactFormat::SdistTarGzip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize sdist");
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
    let runtime = SdistRuntimeProfileV1::new(
        "macos-arm64-python312-pip26-inert",
        "3.12.13",
        digest(b"measured python"),
        "26.1.2",
        digest(b"measured pip"),
    )
    .expect("runtime");
    let build_requires = artifact
        .manifest
        .metadata
        .sdist
        .as_ref()
        .expect("sdist metadata")
        .build_requires
        .clone();
    let closure = SdistBuildClosureV1::new(
        &build_requires,
        vec![
            SdistBuildClosureArtifactV1::new(
                "setuptools",
                "75.0.0",
                digest(b"exact setuptools closure artifact"),
                12_345,
            )
            .expect("setuptools closure"),
            SdistBuildClosureArtifactV1::new(
                "wheel",
                "0.44.0",
                digest(b"exact wheel closure artifact"),
                6_789,
            )
            .expect("wheel closure"),
        ],
    )
    .expect("build closure");
    let policy = SdistScenarioPolicyV1::inert_qualification_only(
        envelope.original_sha256.clone(),
        runtime,
        closure,
    )
    .expect("policy");
    let identities = expected_sdist_scenario_kinds_v1(&artifact.manifest)
        .expect("scenario kinds")
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let suffix = index + 1;
            (
                kind,
                ArtifactScenarioExecutionIdentityV1::new(
                    format!("sdist-job-{suffix}"),
                    format!("sdist-run-{suffix}"),
                    format!("sdist-evidence-{suffix}"),
                    format!("sdist-scenario-{suffix}"),
                )
                .expect("identity"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let identities =
        SdistScenarioIdentitySetV1::new("macos-sdist-plan", identities).expect("identity set");
    let plan = compile_sdist_scenarios_v1(SdistScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &artifact.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })
    .expect("sdist plan");
    (plan.templates().to_vec(), bytes)
}

fn backend(pip_cli_sha256: Sha256Digest) -> MacosSdistBackendCapabilitiesV1 {
    backend_with_guest_identity(
        pip_cli_sha256,
        digest(b"sdist guest auth public key"),
        digest(b"sdist supervisor"),
        digest(b"sdist runner configuration"),
        501,
        20,
    )
}

fn backend_with_guest_identity(
    pip_cli_sha256: Sha256Digest,
    guest_auth_public_key_sha256: Sha256Digest,
    guest_supervisor_sha256: Sha256Digest,
    runner_configuration_sha256: Sha256Digest,
    package_uid: u32,
    package_gid: u32,
) -> MacosSdistBackendCapabilitiesV1 {
    let identity = MacosSdistBackendIdentityV1::new(
        "base-generation-2026-07-11",
        digest(b"base disk"),
        digest(b"aux storage"),
        digest(b"hardware model"),
        digest(b"machine identifier"),
        4,
        8_192,
        digest(b"provisioning receipt"),
        digest(b"sdist helper"),
        guest_supervisor_sha256,
        guest_auth_public_key_sha256,
        runner_configuration_sha256,
        package_uid,
        package_gid,
        "3.12.13",
        digest(b"measured python"),
        "26.1.2",
        pip_cli_sha256,
        digest(b"clone implementation"),
    )
    .expect("backend identity");
    MacosSdistBackendCapabilitiesV1::inert_first_slice(identity)
}

struct FragmentedReader {
    bytes: Vec<u8>,
    offset: usize,
    max_chunk: usize,
}

impl FragmentedReader {
    fn new(bytes: Vec<u8>, max_chunk: usize) -> Self {
        Self {
            bytes,
            offset: 0,
            max_chunk,
        }
    }
}

impl Read for FragmentedReader {
    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<usize> {
        if self.offset == self.bytes.len() {
            return Ok(0);
        }
        let count = destination
            .len()
            .min(self.max_chunk)
            .min(self.bytes.len() - self.offset);
        destination[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[test]
fn every_sdist_scenario_nests_in_a_distinct_closed_no_nic_one_clone_run_spec() {
    let (templates, bytes) = compiled_templates(b"VALUE = 'inert'\n");
    let backend = backend(digest(b"measured pip"));
    assert_eq!(templates.len(), 4);
    let expected_closure = templates[0]
        .canonical_json_v1()
        .map(|wire| {
            whoathere_detonation::decode_and_validate_sdist_scenario_template_v1(&wire)
                .expect("validated template")
                .build_closure_sha256()
                .clone()
        })
        .expect("template wire");
    for template in &templates {
        let run_spec = compile_macos_sdist_run_spec_v1(template, &backend).expect("run spec");
        assert_eq!(run_spec.artifact_sha256(), &digest(&bytes));
        assert_eq!(run_spec.artifact_byte_length(), bytes.len() as u64);
        assert_eq!(run_spec.build_closure_sha256(), &expected_closure);
        assert_eq!(run_spec.scenario_id(), template.identity().scenario_id());
        assert_eq!(run_spec.scenario_kind(), template.scenario_kind());
        let decoded = decode_and_validate_macos_sdist_run_spec_v1(run_spec.canonical_json_v1())
            .expect("decoded run spec");
        assert_eq!(decoded.run_spec_sha256(), run_spec.run_spec_sha256());
        let text = std::str::from_utf8(run_spec.canonical_json_v1()).expect("run spec utf8");
        assert!(text.contains(MACOS_SDIST_RUN_SPEC_SCHEMA_V1));
        assert!(text.contains(MACOS_SDIST_GUEST_PROTOCOL_V1));
        assert!(text.contains("\"network_configuration\":\"zero_network_devices\""));
        assert!(text.contains("\"reuse_policy\":\"one_boot_one_scenario_destroy_clone\""));
        assert!(text
            .contains("\"derived_wheel_policy\":\"rehash_validate_fresh_scenario_no_host_copy\""));
        assert!(!text.contains("sync_back"));
        assert!(!text.contains("registry"));
        assert!(!text.contains("argv"));
        assert_eq!(
            decode_and_validate_macos_wheel_run_spec_v1(run_spec.canonical_json_v1()),
            Err(MacosArtifactRunErrorV1::InvalidRunSpec)
        );
        assert_eq!(
            decode_and_validate_macos_artifact_run_spec_v1(run_spec.canonical_json_v1()),
            Err(MacosArtifactRunErrorV1::InvalidRunSpec)
        );
    }
    assert!(matches!(
        templates[0].scenario_kind(),
        SdistScenarioKindV1::BuildExactSdist { .. }
    ));
}

#[test]
fn backend_measurement_mismatch_and_run_spec_tampering_fail_closed() {
    let (templates, _) = compiled_templates(b"VALUE = 'inert'\n");
    assert_eq!(
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"wrong measured pip"))),
        Err(MacosArtifactRunErrorV1::BackendCapabilityMismatch)
    );

    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("run spec");
    let mut unknown: serde_json::Value =
        serde_json::from_slice(run_spec.canonical_json_v1()).expect("run spec value");
    unknown["sync_back"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown run spec");
    assert_eq!(
        decode_and_validate_macos_sdist_run_spec_v1(&unknown),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );

    let mut closure: serde_json::Value =
        serde_json::from_slice(run_spec.canonical_json_v1()).expect("run spec value");
    closure["build_closure_sha256"] = serde_json::json!(digest(b"forged closure").as_str());
    let closure = serde_json_canonicalizer::to_vec(&closure).expect("closure run spec");
    assert_eq!(
        decode_and_validate_macos_sdist_run_spec_v1(&closure),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );

    let mut protocol: serde_json::Value =
        serde_json::from_slice(run_spec.canonical_json_v1()).expect("run spec value");
    protocol["guest_protocol"] = serde_json::json!("whoathere.wheel_artifact_scenario.v1");
    let protocol = serde_json_canonicalizer::to_vec(&protocol).expect("protocol run spec");
    assert_eq!(
        decode_and_validate_macos_sdist_run_spec_v1(&protocol),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(run_spec.canonical_json_v1());
    assert_eq!(
        decode_and_validate_macos_sdist_run_spec_v1(&noncanonical),
        Err(MacosArtifactRunErrorV1::InvalidRunSpec)
    );
}

#[test]
fn exact_sdist_and_backend_measurements_rebind_the_macos_run_spec() {
    let (first_templates, _) = compiled_templates(b"VALUE = 'first inert byte'\n");
    let (changed_templates, _) = compiled_templates(b"VALUE = 'changed inert byte'\n");
    let backend = backend(digest(b"measured pip"));
    let first =
        compile_macos_sdist_run_spec_v1(&first_templates[0], &backend).expect("first run spec");
    let changed =
        compile_macos_sdist_run_spec_v1(&changed_templates[0], &backend).expect("changed run spec");
    assert_ne!(first.artifact_sha256(), changed.artifact_sha256());
    assert_ne!(first.run_spec_sha256(), changed.run_spec_sha256());

    let changed_backend_identity = MacosSdistBackendIdentityV1::new(
        "base-generation-2026-07-11",
        digest(b"different base disk"),
        digest(b"aux storage"),
        digest(b"hardware model"),
        digest(b"machine identifier"),
        4,
        8_192,
        digest(b"provisioning receipt"),
        digest(b"sdist helper"),
        digest(b"sdist supervisor"),
        digest(b"sdist guest auth public key"),
        digest(b"sdist runner configuration"),
        501,
        20,
        "3.12.13",
        digest(b"measured python"),
        "26.1.2",
        digest(b"measured pip"),
        digest(b"clone implementation"),
    )
    .expect("changed backend");
    let changed_backend =
        MacosSdistBackendCapabilitiesV1::inert_first_slice(changed_backend_identity);
    let rebound = compile_macos_sdist_run_spec_v1(&first_templates[0], &changed_backend)
        .expect("rebound run spec");
    assert_ne!(first.run_spec_sha256(), rebound.run_spec_sha256());
}

fn sdist_guest_staging_frame() -> (Vec<u8>, Vec<u8>, whoathere_macos_vm::MacosSdistRunSpecV1) {
    let (templates, artifact) = compiled_templates(b"VALUE = 'staging inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("staging run spec");
    let bindings =
        MacosSdistSubmissionBindingsV1::for_run_spec(digest(b"sdist staging challenge"), &run_spec);
    let header =
        MacosSdistSubmissionHeaderV1::new(run_spec.clone(), bindings).expect("staging header");
    let mut guest =
        encode_macos_sdist_submission_frame_v1(&header, &artifact).expect("staging frame");
    guest[..8].copy_from_slice(&MACOS_SDIST_GUEST_SUBMISSION_MAGIC_V1);
    (guest, artifact, run_spec)
}

fn temporary_sdist_staging_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "whoathere-sdist-staging-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create sdist staging root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("protect sdist staging root");
    root
}

fn sdist_staging_policy(root: &std::path::Path) -> MacosSdistGuestStagingPolicyV1 {
    let supervisor_uid = fs::symlink_metadata(root)
        .expect("sdist root metadata")
        .uid();
    let package_uid = if supervisor_uid == u32::MAX {
        1
    } else {
        (supervisor_uid + 1).max(1)
    };
    MacosSdistGuestStagingPolicyV1::for_current_supervisor(root.to_path_buf(), package_uid)
        .expect("sdist staging policy")
}

#[test]
fn exact_sdist_round_trips_through_a_distinct_challenge_bound_binary_frame() {
    let (templates, artifact) = compiled_templates(b"VALUE = 'transport inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("run spec");
    let bindings =
        MacosSdistSubmissionBindingsV1::for_run_spec(digest(b"challenge binding"), &run_spec);
    let header = MacosSdistSubmissionHeaderV1::new(run_spec.clone(), bindings.clone())
        .expect("submission header");
    let encoded =
        encode_macos_sdist_submission_frame_v1(&header, &artifact).expect("submission frame");
    assert_eq!(&encoded[..8], &MACOS_SDIST_SUBMISSION_MAGIC_V1);
    assert_eq!(
        encoded.len(),
        MACOS_SDIST_SUBMISSION_FIXED_PREFIX_BYTES_V1
            + header.canonical_json_v1().len()
            + artifact.len()
    );
    let decoded =
        decode_macos_sdist_submission_frame_v1(&encoded, &bindings).expect("decoded frame");
    assert_eq!(decoded.artifact_bytes(), artifact);
    assert_eq!(
        decoded.header().run_spec().run_spec_sha256(),
        run_spec.run_spec_sha256()
    );
    assert_eq!(
        decoded.header().run_spec().build_closure_sha256(),
        run_spec.build_closure_sha256()
    );

    let wrong_bindings = MacosSdistSubmissionBindingsV1::for_run_spec(
        digest(b"different challenge binding"),
        &run_spec,
    );
    assert_eq!(
        decode_macos_sdist_submission_frame_v1(&encoded, &wrong_bindings),
        Err(MacosSdistSubmissionErrorV1::BindingMismatch)
    );

    let mut truncated = encoded.clone();
    truncated.pop();
    assert_eq!(
        decode_macos_sdist_submission_frame_v1(&truncated, &bindings),
        Err(MacosSdistSubmissionErrorV1::Truncated)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        decode_macos_sdist_submission_frame_v1(&trailing, &bindings),
        Err(MacosSdistSubmissionErrorV1::TrailingData)
    );
    let mut mutated = encoded.clone();
    *mutated.last_mut().expect("artifact byte") ^= 1;
    assert_eq!(
        decode_macos_sdist_submission_frame_v1(&mutated, &bindings),
        Err(MacosSdistSubmissionErrorV1::ArtifactDigestMismatch)
    );
    let mut wheel_magic = encoded.clone();
    wheel_magic[..8].copy_from_slice(b"WHOAWHE1");
    assert_eq!(
        decode_macos_sdist_submission_frame_v1(&wheel_magic, &bindings),
        Err(MacosSdistSubmissionErrorV1::InvalidMagic)
    );

    let header_start = MACOS_SDIST_SUBMISSION_FIXED_PREFIX_BYTES_V1;
    let header_end = header_start + header.canonical_json_v1().len();
    let mut value: serde_json::Value =
        serde_json::from_slice(&encoded[header_start..header_end]).expect("header value");
    value["build_closure_sha256"] = serde_json::json!(digest(b"forged closure").as_str());
    let forged_header = serde_json_canonicalizer::to_vec(&value).expect("forged header");
    assert_eq!(forged_header.len(), header.canonical_json_v1().len());
    let mut forged = encoded.clone();
    forged[header_start..header_end].copy_from_slice(&forged_header);
    assert_eq!(
        decode_macos_sdist_submission_frame_v1(&forged, &bindings),
        Err(MacosSdistSubmissionErrorV1::ArtifactDigestMismatch)
    );
}

#[test]
fn sdist_guest_submission_streams_exact_bytes_and_rejects_other_transport_domains() {
    let (templates, artifact) = compiled_templates(b"VALUE = 'guest transport inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("run spec");
    let bindings =
        MacosSdistSubmissionBindingsV1::for_run_spec(digest(b"challenge binding"), &run_spec);
    let header = MacosSdistSubmissionHeaderV1::new(run_spec, bindings).expect("header");
    let mut guest = encode_macos_sdist_submission_frame_v1(&header, &artifact).expect("host frame");
    guest[..8].copy_from_slice(&MACOS_SDIST_GUEST_SUBMISSION_MAGIC_V1);

    let mut staged = Vec::new();
    let observation = stream_macos_sdist_guest_submission_v1(
        &mut FragmentedReader::new(guest.clone(), 7),
        &mut staged,
    )
    .expect("stream guest frame");
    assert_eq!(staged, artifact);
    assert_eq!(observation.artifact_sha256(), &digest(&artifact));
    assert_eq!(observation.artifact_byte_length(), artifact.len() as u64);
    assert_eq!(
        observation.header().run_spec().build_closure_sha256(),
        header.run_spec().build_closure_sha256()
    );

    let mut host_domain = guest.clone();
    host_domain[..8].copy_from_slice(&MACOS_SDIST_SUBMISSION_MAGIC_V1);
    assert_eq!(
        stream_macos_sdist_guest_submission_v1(&mut Cursor::new(host_domain), &mut Vec::new()),
        Err(MacosSdistSubmissionErrorV1::InvalidMagic)
    );
    let mut wheel_domain = guest.clone();
    wheel_domain[..8].copy_from_slice(b"WHOWGST1");
    assert_eq!(
        stream_macos_sdist_guest_submission_v1(&mut Cursor::new(wheel_domain), &mut Vec::new()),
        Err(MacosSdistSubmissionErrorV1::InvalidMagic)
    );
    let mut mutated = guest.clone();
    *mutated.last_mut().expect("artifact byte") ^= 1;
    assert_eq!(
        stream_macos_sdist_guest_submission_v1(&mut Cursor::new(mutated), &mut Vec::new()),
        Err(MacosSdistSubmissionErrorV1::ArtifactDigestMismatch)
    );
    let mut trailing = guest.clone();
    trailing.push(0);
    assert_eq!(
        stream_macos_sdist_guest_submission_v1(&mut Cursor::new(trailing), &mut Vec::new()),
        Err(MacosSdistSubmissionErrorV1::TrailingData)
    );
    let mut truncated = guest;
    truncated.pop();
    assert_eq!(
        stream_macos_sdist_guest_submission_v1(&mut Cursor::new(truncated), &mut Vec::new()),
        Err(MacosSdistSubmissionErrorV1::Truncated)
    );
}

#[test]
fn sdist_guest_staging_is_exclusive_read_only_rehashed_and_removed() {
    let (guest, artifact, run_spec) = sdist_guest_staging_frame();
    let root = temporary_sdist_staging_root("success");
    let policy = sdist_staging_policy(&root);
    let mut staged = stage_macos_sdist_guest_submission_v1(&mut Cursor::new(guest), &policy)
        .expect("stage inert sdist");
    let path = staged.artifact_path().to_path_buf();
    assert_eq!(
        path.file_name().and_then(|value| value.to_str()),
        Some("artifact.sdist")
    );
    let metadata = fs::symlink_metadata(&path).expect("staged sdist metadata");
    assert!(metadata.file_type().is_file());
    assert_eq!(metadata.mode() & 0o777, 0o444);
    assert_eq!(metadata.nlink(), 1);
    assert_eq!(metadata.len(), artifact.len() as u64);
    assert_eq!(
        staged.transport().artifact_sha256(),
        run_spec.artifact_sha256()
    );
    assert_eq!(
        staged
            .transport()
            .header()
            .run_spec()
            .build_closure_sha256(),
        run_spec.build_closure_sha256()
    );

    let prelaunch = staged.verify_prelaunch().expect("sdist prelaunch rehash");
    let postrun = staged.verify_postrun().expect("sdist postrun rehash");
    assert_eq!(prelaunch.phase(), SdistGuestRehashPhaseV1::Prelaunch);
    assert_eq!(postrun.phase(), SdistGuestRehashPhaseV1::Postrun);
    assert_eq!(prelaunch.artifact_sha256(), run_spec.artifact_sha256());
    assert_eq!(prelaunch.artifact_byte_length(), artifact.len() as u64);
    assert_eq!(prelaunch.device(), postrun.device());
    assert_eq!(prelaunch.inode(), postrun.inode());

    let directory = path.parent().expect("scenario directory").to_path_buf();
    staged.cleanup().expect("verified sdist cleanup");
    assert!(!directory.exists());
    assert_eq!(fs::read_dir(&root).expect("empty sdist root").count(), 0);
    fs::remove_dir(root).expect("remove sdist staging root");
}

#[test]
fn sdist_guest_staging_discards_bad_transport_and_detects_path_replacement() {
    let (mut guest, _, _) = sdist_guest_staging_frame();
    let root = temporary_sdist_staging_root("failure");
    let policy = sdist_staging_policy(&root);
    *guest.last_mut().expect("sdist byte") ^= 1;
    assert_eq!(
        stage_macos_sdist_guest_submission_v1(&mut Cursor::new(guest), &policy)
            .expect_err("mutated sdist must fail"),
        MacosSdistGuestStagingErrorV1::Transport(
            MacosSdistSubmissionErrorV1::ArtifactDigestMismatch
        )
    );
    assert_eq!(fs::read_dir(&root).expect("cleaned sdist root").count(), 0);

    let (guest, artifact, _) = sdist_guest_staging_frame();
    let mut staged = stage_macos_sdist_guest_submission_v1(&mut Cursor::new(guest), &policy)
        .expect("stage replacement fixture");
    let path = staged.artifact_path().to_path_buf();
    let held = path.with_file_name("held-original.sdist");
    fs::rename(&path, &held).expect("move original sdist");
    fs::write(&path, &artifact).expect("write replacement sdist");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o444))
        .expect("protect replacement sdist");
    assert_eq!(
        staged.verify_prelaunch(),
        Err(MacosSdistGuestStagingErrorV1::VerificationFailed)
    );
    assert_eq!(
        staged.cleanup(),
        Err(MacosSdistGuestStagingErrorV1::CleanupFailed)
    );
    assert!(held.exists());
    fs::remove_file(held).expect("remove held original sdist");
    staged.cleanup().expect("retry sdist cleanup");
    assert_eq!(fs::read_dir(&root).expect("clean sdist root").count(), 0);
    fs::remove_dir(root).expect("remove sdist staging root");
}

#[test]
fn sdist_guest_authentication_binds_closure_challenge_claims_and_measured_key() {
    let seed = [41_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let challenge = MacosSdistGuestAuthChallengeV1::new(
        [13_u8; 32],
        digest(b"sdist execution binding"),
        digest(b"sdist run spec"),
        digest(b"sdist build closure"),
        digest(b"sdist clone binding"),
        digest(&verifying_key),
    )
    .expect("sdist challenge");
    let decoded = decode_macos_sdist_guest_auth_challenge_v1(challenge.canonical_json_v1())
        .expect("decoded challenge");
    assert_eq!(decoded.run_spec_sha256(), challenge.run_spec_sha256());
    assert_eq!(
        decoded.build_closure_sha256(),
        challenge.build_closure_sha256()
    );
    let claims = MacosSdistGuestAuthClaimsV1::new(
        digest(b"sdist guest supervisor"),
        digest(b"sdist runner configuration"),
        501,
        20,
    )
    .expect("auth claims");
    let response = sign_macos_sdist_guest_auth_response_v1(&challenge, seed, &claims)
        .expect("signed response");
    verify_macos_sdist_guest_auth_response_v1(&challenge, &response, verifying_key, &claims)
        .expect("verified response");

    let changed_closure = MacosSdistGuestAuthChallengeV1::new(
        [13_u8; 32],
        digest(b"sdist execution binding"),
        digest(b"sdist run spec"),
        digest(b"different build closure"),
        digest(b"sdist clone binding"),
        digest(&verifying_key),
    )
    .expect("changed challenge");
    assert_eq!(
        verify_macos_sdist_guest_auth_response_v1(
            &changed_closure,
            &response,
            verifying_key,
            &claims
        ),
        Err(MacosSdistGuestAuthErrorV1::InvalidResponse)
    );

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&response).expect("response value");
    tampered["runner_configuration_sha256"] =
        serde_json::json!(digest(b"forged runner configuration").as_str());
    let tampered = serde_json_canonicalizer::to_vec(&tampered).expect("tampered response");
    assert_eq!(
        verify_macos_sdist_guest_auth_response_v1(&challenge, &tampered, verifying_key, &claims),
        Err(MacosSdistGuestAuthErrorV1::InvalidResponse)
    );

    let mut wheel_schema: serde_json::Value =
        serde_json::from_slice(challenge.canonical_json_v1()).expect("challenge value");
    wheel_schema["schema_version"] = serde_json::json!("whoathere.wheel_guest_auth_challenge.v1");
    let wheel_schema = serde_json_canonicalizer::to_vec(&wheel_schema).expect("wheel schema");
    assert_eq!(
        decode_macos_sdist_guest_auth_challenge_v1(&wheel_schema),
        Err(MacosSdistGuestAuthErrorV1::NonCanonical)
    );
}

#[test]
fn sdist_guest_control_frames_are_bounded_ordered_and_cross_ecosystem_closed() {
    let challenge = b"inert sdist challenge";
    let response = b"inert sdist response";
    let receipt = b"inert sdist receipt";
    let mut wire = Vec::new();
    write_macos_sdist_guest_control_frame_v1(
        &mut wire,
        MacosSdistGuestControlFrameTypeV1::AuthenticationChallenge,
        challenge,
    )
    .expect("challenge frame");
    write_macos_sdist_guest_control_frame_v1(
        &mut wire,
        MacosSdistGuestControlFrameTypeV1::AuthenticationResponse,
        response,
    )
    .expect("response frame");
    write_macos_sdist_guest_control_frame_v1(
        &mut wire,
        MacosSdistGuestControlFrameTypeV1::StagingReceipt,
        receipt,
    )
    .expect("receipt frame");
    let mut reader = FragmentedReader::new(wire.clone(), 3);
    assert_eq!(
        read_macos_sdist_guest_control_frame_v1(
            &mut reader,
            MacosSdistGuestControlFrameTypeV1::AuthenticationChallenge,
            1024,
        )
        .expect("challenge"),
        challenge
    );
    assert_eq!(
        read_macos_sdist_guest_control_frame_v1(
            &mut reader,
            MacosSdistGuestControlFrameTypeV1::AuthenticationResponse,
            1024,
        )
        .expect("response"),
        response
    );
    assert_eq!(
        read_macos_sdist_guest_control_frame_v1(
            &mut reader,
            MacosSdistGuestControlFrameTypeV1::StagingReceipt,
            1024,
        )
        .expect("receipt"),
        receipt
    );
    require_macos_sdist_guest_control_eof_v1(&mut reader).expect("control EOF");

    let mut wheel_magic = wire.clone();
    wheel_magic[..8].copy_from_slice(b"WHOWCTL1");
    assert_eq!(
        read_macos_sdist_guest_control_frame_v1(
            &mut Cursor::new(wheel_magic),
            MacosSdistGuestControlFrameTypeV1::AuthenticationChallenge,
            1024,
        ),
        Err(MacosSdistGuestControlErrorV1::InvalidMagic)
    );
    assert_eq!(
        read_macos_sdist_guest_control_frame_v1(
            &mut Cursor::new(wire),
            MacosSdistGuestControlFrameTypeV1::AuthenticationResponse,
            1024,
        ),
        Err(MacosSdistGuestControlErrorV1::UnexpectedFrameType)
    );
    assert_eq!(
        write_macos_sdist_guest_control_frame_v1(
            &mut Vec::new(),
            MacosSdistGuestControlFrameTypeV1::AuthenticationChallenge,
            &[],
        ),
        Err(MacosSdistGuestControlErrorV1::BodyLimitExceeded)
    );
}

#[test]
fn signed_sdist_staging_receipt_binds_closure_inode_and_no_execution_posture() {
    let seed = [43_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let closure = digest(b"sdist receipt build closure");
    let challenge = MacosSdistGuestAuthChallengeV1::new(
        [17_u8; 32],
        digest(b"sdist receipt execution binding"),
        digest(b"sdist receipt run spec"),
        closure.clone(),
        digest(b"sdist receipt clone binding"),
        digest(&verifying_key),
    )
    .expect("receipt challenge");
    let auth_claims = MacosSdistGuestAuthClaimsV1::new(
        digest(b"sdist receipt supervisor"),
        digest(b"sdist receipt runner configuration"),
        501,
        20,
    )
    .expect("receipt auth claims");
    let artifact = digest(b"exact inert staged sdist");
    let staging_claims = MacosSdistGuestStagingReceiptClaimsV1::new(
        artifact.clone(),
        4096,
        closure.clone(),
        artifact,
        4096,
        123,
        456,
    )
    .expect("staging claims");
    let receipt =
        sign_macos_sdist_guest_staging_receipt_v1(&challenge, seed, &auth_claims, &staging_claims)
            .expect("signed receipt");
    let value: serde_json::Value = serde_json::from_slice(&receipt).expect("receipt value");
    assert_eq!(
        value.get("status").and_then(serde_json::Value::as_str),
        Some("staged_no_execution_no_closure_materialization")
    );
    assert_eq!(
        value
            .get("package_execution_enabled")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value
            .get("sync_back_enabled")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    assert_eq!(
        value
            .get("build_closure_materialized")
            .and_then(serde_json::Value::as_bool),
        Some(false)
    );
    let observation = verify_macos_sdist_guest_staging_receipt_v1(
        &challenge,
        &receipt,
        verifying_key,
        &auth_claims,
        &staging_claims,
    )
    .expect("verified receipt");
    assert_eq!(observation.build_closure_sha256(), &closure);
    assert_eq!(observation.claims().staged_device(), 123);
    assert_eq!(observation.claims().staged_inode(), 456);
    assert!(!observation.package_execution_enabled());
    assert!(!observation.sync_back_enabled());
    assert!(!observation.build_closure_materialized());

    let wrong_artifact = digest(b"exact inert staged sdist");
    let wrong_closure_claims = MacosSdistGuestStagingReceiptClaimsV1::new(
        wrong_artifact.clone(),
        4096,
        digest(b"wrong closure"),
        wrong_artifact,
        4096,
        123,
        456,
    )
    .expect("wrong closure claims");
    assert_eq!(
        sign_macos_sdist_guest_staging_receipt_v1(
            &challenge,
            seed,
            &auth_claims,
            &wrong_closure_claims,
        ),
        Err(MacosSdistGuestAuthErrorV1::InvalidResponse)
    );

    let mut tampered: serde_json::Value = serde_json::from_slice(&receipt).expect("receipt value");
    tampered["sync_back_enabled"] = serde_json::json!(true);
    let tampered = serde_json_canonicalizer::to_vec(&tampered).expect("tampered receipt");
    assert_eq!(
        verify_macos_sdist_guest_staging_receipt_v1(
            &challenge,
            &tampered,
            verifying_key,
            &auth_claims,
            &staging_claims,
        ),
        Err(MacosSdistGuestAuthErrorV1::InvalidResponse)
    );
}

#[test]
fn sdist_guest_supervisor_authenticates_stages_cleans_attests_and_never_executes() {
    let root = temporary_sdist_staging_root("supervisor-success");
    let staging_policy = sdist_staging_policy(&root);
    let seed = [47_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let supervisor = digest(b"measured sdist supervisor");
    let runner = digest(b"measured sdist runner configuration");
    let package_gid = 20;
    let backend = backend_with_guest_identity(
        digest(b"measured pip"),
        digest(&verifying_key),
        supervisor.clone(),
        runner.clone(),
        staging_policy.package_uid(),
        package_gid,
    );
    let (templates, artifact) = compiled_templates(b"VALUE = 'supervisor inert'\n");
    let run_spec = compile_macos_sdist_run_spec_v1(&templates[0], &backend).expect("run spec");
    let bindings =
        MacosSdistSubmissionBindingsV1::for_run_spec(digest(b"session challenge"), &run_spec);
    let header = MacosSdistSubmissionHeaderV1::new(run_spec.clone(), bindings.clone())
        .expect("session header");
    let mut guest =
        encode_macos_sdist_submission_frame_v1(&header, &artifact).expect("session frame");
    guest[..8].copy_from_slice(&MACOS_SDIST_GUEST_SUBMISSION_MAGIC_V1);
    let challenge = MacosSdistGuestAuthChallengeV1::new(
        [19_u8; 32],
        bindings.execution_binding_sha256().clone(),
        run_spec.run_spec_sha256().clone(),
        run_spec.build_closure_sha256().clone(),
        digest(b"session clone"),
        digest(&verifying_key),
    )
    .expect("session challenge");
    let auth_claims = MacosSdistGuestAuthClaimsV1::new(
        supervisor,
        runner,
        staging_policy.package_uid(),
        package_gid,
    )
    .expect("session claims");
    let mut input = Vec::new();
    write_macos_sdist_guest_control_frame_v1(
        &mut input,
        MacosSdistGuestControlFrameTypeV1::AuthenticationChallenge,
        challenge.canonical_json_v1(),
    )
    .expect("write challenge");
    input.extend_from_slice(&guest);
    let mut output = Vec::new();
    let observation = run_macos_sdist_guest_nonexecuting_session_v1(
        &mut FragmentedReader::new(input, 11),
        &mut output,
        seed,
        &auth_claims,
        &staging_policy,
    )
    .expect("nonexecuting session");
    assert_eq!(observation.artifact_sha256(), run_spec.artifact_sha256());
    assert_eq!(
        observation.build_closure_sha256(),
        run_spec.build_closure_sha256()
    );
    assert!(observation.staging_cleanup_succeeded());
    assert!(!observation.package_execution_enabled());
    assert!(!observation.sync_back_enabled());
    assert!(!observation.build_closure_materialized());
    assert_eq!(fs::read_dir(&root).expect("clean root").count(), 0);

    let mut output_reader = FragmentedReader::new(output, 5);
    let response = read_macos_sdist_guest_control_frame_v1(
        &mut output_reader,
        MacosSdistGuestControlFrameTypeV1::AuthenticationResponse,
        16 * 1024,
    )
    .expect("auth response");
    verify_macos_sdist_guest_auth_response_v1(&challenge, &response, verifying_key, &auth_claims)
        .expect("verify auth response");
    let receipt = read_macos_sdist_guest_control_frame_v1(
        &mut output_reader,
        MacosSdistGuestControlFrameTypeV1::StagingReceipt,
        16 * 1024,
    )
    .expect("staging receipt");
    let expected_staging_claims = MacosSdistGuestStagingReceiptClaimsV1::new(
        observation.artifact_sha256().clone(),
        observation.artifact_byte_length(),
        observation.build_closure_sha256().clone(),
        observation.first_rehash_sha256().clone(),
        observation.first_rehash_byte_length(),
        observation.staged_device(),
        observation.staged_inode(),
    )
    .expect("expected staging claims");
    verify_macos_sdist_guest_staging_receipt_v1(
        &challenge,
        &receipt,
        verifying_key,
        &auth_claims,
        &expected_staging_claims,
    )
    .expect("verify staging receipt");
    require_macos_sdist_guest_control_eof_v1(&mut output_reader).expect("output EOF");
    fs::remove_dir(root).expect("remove supervisor root");
}

#[test]
fn sdist_guest_supervisor_rejects_closure_rebinding_and_cleans_staging() {
    let root = temporary_sdist_staging_root("supervisor-rebind");
    let staging_policy = sdist_staging_policy(&root);
    let seed = [53_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let supervisor = digest(b"rebind sdist supervisor");
    let runner = digest(b"rebind sdist runner configuration");
    let backend = backend_with_guest_identity(
        digest(b"measured pip"),
        digest(&verifying_key),
        supervisor.clone(),
        runner.clone(),
        staging_policy.package_uid(),
        20,
    );
    let (templates, artifact) = compiled_templates(b"VALUE = 'rebind inert'\n");
    let run_spec = compile_macos_sdist_run_spec_v1(&templates[0], &backend).expect("run spec");
    let bindings =
        MacosSdistSubmissionBindingsV1::for_run_spec(digest(b"rebind challenge"), &run_spec);
    let header =
        MacosSdistSubmissionHeaderV1::new(run_spec.clone(), bindings.clone()).expect("header");
    let mut guest =
        encode_macos_sdist_submission_frame_v1(&header, &artifact).expect("guest frame");
    guest[..8].copy_from_slice(&MACOS_SDIST_GUEST_SUBMISSION_MAGIC_V1);
    let challenge = MacosSdistGuestAuthChallengeV1::new(
        [23_u8; 32],
        bindings.execution_binding_sha256().clone(),
        run_spec.run_spec_sha256().clone(),
        digest(b"forged closure binding"),
        digest(b"rebind clone"),
        digest(&verifying_key),
    )
    .expect("rebound challenge");
    let auth_claims =
        MacosSdistGuestAuthClaimsV1::new(supervisor, runner, staging_policy.package_uid(), 20)
            .expect("claims");
    let mut input = Vec::new();
    write_macos_sdist_guest_control_frame_v1(
        &mut input,
        MacosSdistGuestControlFrameTypeV1::AuthenticationChallenge,
        challenge.canonical_json_v1(),
    )
    .expect("challenge frame");
    input.extend_from_slice(&guest);
    let failure = run_macos_sdist_guest_nonexecuting_session_v1(
        &mut Cursor::new(input),
        &mut Vec::new(),
        seed,
        &auth_claims,
        &staging_policy,
    )
    .expect_err("closure rebinding must fail");
    assert_eq!(
        failure.primary(),
        MacosSdistGuestSupervisorPrimaryErrorV1::BindingMismatch
    );
    assert!(!failure.staging_cleanup_failed());
    assert_eq!(fs::read_dir(&root).expect("clean root").count(), 0);
    fs::remove_dir(root).expect("remove rebind root");
}

#[test]
fn sdist_launch_authority_is_random_expiring_and_bound_to_artifact_run_spec_and_closure() {
    let (templates, _) = compiled_templates(b"VALUE = 'authority inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("authority run spec");
    let root = temporary_sdist_staging_root("authority");
    let first = prepare_macos_sdist_launch_v1(&root, run_spec.clone(), 2_000_000_000, 120)
        .expect("first authority");
    let second = prepare_macos_sdist_launch_v1(&root, run_spec.clone(), 2_000_000_001, 120)
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
        first.authority().record().build_closure_sha256(),
        run_spec.build_closure_sha256()
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
    assert_eq!(
        fs::metadata(first.authority().pending_path())
            .expect("authority metadata")
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert_eq!(
        prepare_macos_sdist_launch_v1(
            &root,
            run_spec.clone(),
            2_000_000_000,
            MAX_MACOS_SDIST_LAUNCH_AUTHORITY_LIFETIME_SECONDS_V1 + 1,
        ),
        Err(MacosSdistLaunchAuthorityErrorV1::InvalidTime)
    );

    let unsafe_root = temporary_sdist_staging_root("authority-unsafe");
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o777))
        .expect("make unsafe authority root");
    assert_eq!(
        prepare_macos_sdist_launch_v1(&unsafe_root, run_spec, 2_000_000_000, 120),
        Err(MacosSdistLaunchAuthorityErrorV1::UnsafeStateDirectory)
    );
    fs::set_permissions(&unsafe_root, fs::Permissions::from_mode(0o700))
        .expect("restore authority root");
    fs::remove_dir(unsafe_root).expect("remove unsafe authority root");
    fs::remove_dir_all(root).expect("remove authority tree");
}

#[test]
fn sdist_launch_authority_consumption_is_atomic_single_use_and_exactly_bound() {
    let (templates, _) = compiled_templates(b"VALUE = 'consume inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("consume run spec");
    let root = temporary_sdist_staging_root("authority-consume");
    let prepared = prepare_macos_sdist_launch_v1(&root, run_spec.clone(), 2_100_000_000, 120)
        .expect("prepared authority");
    let request = MacosSdistLaunchAuthorityConsumptionRequestV1::for_prepared(&prepared)
        .expect("consumption request");
    let pending_path = prepared.authority().pending_path().to_path_buf();
    let consumed = consume_macos_sdist_launch_authority_v1(&root, &request, 2_100_000_001)
        .expect("consumed authority");
    assert!(!pending_path.exists());
    assert!(consumed.consumed_path().exists());
    assert_eq!(consumed.record_sha256(), request.record_sha256());
    assert_eq!(
        consumed.record().run_spec_sha256(),
        run_spec.run_spec_sha256()
    );
    assert_eq!(
        consumed.record().artifact_sha256(),
        run_spec.artifact_sha256()
    );
    assert_eq!(
        consumed.record().build_closure_sha256(),
        run_spec.build_closure_sha256()
    );
    assert_eq!(consumed.consumed_at_unix_seconds(), 2_100_000_001);
    assert_eq!(
        consume_macos_sdist_launch_authority_v1(&root, &request, 2_100_000_002),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
    );
    fs::remove_dir_all(root).expect("remove consumed authority tree");
}

#[test]
fn expired_or_header_rebound_sdist_authorities_are_burned_before_rejection() {
    let (templates, _) = compiled_templates(b"VALUE = 'authority rejection inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("rejection run spec");
    let root = temporary_sdist_staging_root("authority-rejection");

    let expired = prepare_macos_sdist_launch_v1(&root, run_spec.clone(), 2_200_000_000, 10)
        .expect("expired authority");
    let expired_request = MacosSdistLaunchAuthorityConsumptionRequestV1::for_prepared(&expired)
        .expect("expired request");
    assert_eq!(
        consume_macos_sdist_launch_authority_v1(&root, &expired_request, 2_200_000_010),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityExpired)
    );
    assert!(!expired.authority().pending_path().exists());
    assert_eq!(
        consume_macos_sdist_launch_authority_v1(&root, &expired_request, 2_200_000_005),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
    );

    let first = prepare_macos_sdist_launch_v1(&root, run_spec.clone(), 2_200_000_020, 120)
        .expect("first authority");
    let second = prepare_macos_sdist_launch_v1(&root, run_spec, 2_200_000_020, 120)
        .expect("second authority");
    let rebound = MacosSdistLaunchAuthorityConsumptionRequestV1::new(
        first.authority().record().authority_id(),
        first.authority().record_sha256().clone(),
        second.header().clone(),
    )
    .expect("rebound request");
    assert_eq!(
        consume_macos_sdist_launch_authority_v1(&root, &rebound, 2_200_000_021),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityBindingMismatch)
    );
    assert!(!first.authority().pending_path().exists());
    assert_eq!(
        consume_macos_sdist_launch_authority_v1(&root, &rebound, 2_200_000_022),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
    );
    fs::remove_dir_all(root).expect("remove rejected authority tree");
}

#[test]
fn mutated_sdist_authority_record_is_consumed_and_rejected_without_retry() {
    let (templates, _) = compiled_templates(b"VALUE = 'authority mutation inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("mutation run spec");
    let root = temporary_sdist_staging_root("authority-mutation");
    let prepared = prepare_macos_sdist_launch_v1(&root, run_spec, 2_300_000_000, 120)
        .expect("mutation authority");
    let request = MacosSdistLaunchAuthorityConsumptionRequestV1::for_prepared(&prepared)
        .expect("mutation request");
    let mut bytes = fs::read(prepared.authority().pending_path()).expect("authority bytes");
    *bytes.last_mut().expect("authority byte") ^= 1;
    fs::write(prepared.authority().pending_path(), bytes).expect("mutate authority record");
    assert_eq!(
        consume_macos_sdist_launch_authority_v1(&root, &request, 2_300_000_001),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityRecordInvalid)
    );
    assert!(!prepared.authority().pending_path().exists());
    assert_eq!(
        consume_macos_sdist_launch_authority_v1(&root, &request, 2_300_000_002),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
    );
    fs::remove_dir_all(root).expect("remove mutated authority tree");
}

#[test]
fn concurrent_sdist_authority_consumers_have_exactly_one_winner() {
    let (templates, _) = compiled_templates(b"VALUE = 'authority race inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend(digest(b"measured pip")))
            .expect("race run spec");
    let root = temporary_sdist_staging_root("authority-race");
    let prepared =
        prepare_macos_sdist_launch_v1(&root, run_spec, 2_400_000_000, 120).expect("race authority");
    let request = Arc::new(
        MacosSdistLaunchAuthorityConsumptionRequestV1::for_prepared(&prepared)
            .expect("race request"),
    );
    let barrier = Arc::new(Barrier::new(3));
    let handles = (0..2)
        .map(|_| {
            let root = root.clone();
            let request = Arc::clone(&request);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                consume_macos_sdist_launch_authority_v1(&root, &request, 2_400_000_001)
            })
        })
        .collect::<Vec<_>>();
    barrier.wait();
    let results = handles
        .into_iter()
        .map(|handle| handle.join().expect("consumer thread"))
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
                )
            })
            .count(),
        1
    );
    fs::remove_dir_all(root).expect("remove raced authority tree");
}

#[test]
fn consumed_sdist_authority_constructs_the_exact_guest_challenge() {
    let seed = [59_u8; 32];
    let verifying_key = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let backend = backend_with_guest_identity(
        digest(b"measured pip"),
        digest(&verifying_key),
        digest(b"authorized supervisor"),
        digest(b"authorized runner"),
        501,
        20,
    );
    let (templates, _) = compiled_templates(b"VALUE = 'authorize inert'\n");
    let run_spec =
        compile_macos_sdist_run_spec_v1(&templates[0], &backend).expect("authorized run spec");
    let root = temporary_sdist_staging_root("authority-authorize");
    let prepared = prepare_macos_sdist_launch_v1(&root, run_spec.clone(), 2_500_000_000, 120)
        .expect("prepared authorized launch");
    let request = MacosSdistLaunchAuthorityConsumptionRequestV1::for_prepared(&prepared)
        .expect("authorized request");
    let clone_binding = digest(b"authorized clone binding");
    let authorized = consume_and_authorize_macos_sdist_guest_session_v1(
        &root,
        &request,
        2_500_000_001,
        [29_u8; 32],
        clone_binding.clone(),
    )
    .expect("authorized guest session");
    assert!(authorized.consumed_authority().consumed_path().exists());
    assert_eq!(
        authorized.header().run_spec().run_spec_sha256(),
        run_spec.run_spec_sha256()
    );
    assert_eq!(
        authorized.challenge().execution_binding_sha256(),
        prepared.header().bindings().execution_binding_sha256()
    );
    assert_eq!(
        authorized.challenge().run_spec_sha256(),
        run_spec.run_spec_sha256()
    );
    assert_eq!(
        authorized.challenge().build_closure_sha256(),
        run_spec.build_closure_sha256()
    );
    assert_eq!(
        authorized.challenge().clone_binding_sha256(),
        &clone_binding
    );
    assert_eq!(
        authorized.challenge().guest_auth_public_key_sha256(),
        &digest(&verifying_key)
    );
    assert_eq!(
        consume_and_authorize_macos_sdist_guest_session_v1(
            &root,
            &request,
            2_500_000_002,
            [31_u8; 32],
            clone_binding,
        ),
        Err(MacosSdistLaunchAuthorityErrorV1::AuthorityUnavailable)
    );
    fs::remove_dir_all(root).expect("remove authorized authority tree");
}
