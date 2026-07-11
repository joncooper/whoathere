use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::BTreeMap;
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::PathBuf;
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
    compile_macos_sdist_run_spec_v1, decode_and_validate_macos_artifact_run_spec_v1,
    decode_and_validate_macos_sdist_run_spec_v1, decode_and_validate_macos_wheel_run_spec_v1,
    decode_macos_sdist_submission_frame_v1, encode_macos_sdist_submission_frame_v1,
    stage_macos_sdist_guest_submission_v1, stream_macos_sdist_guest_submission_v1,
    MacosArtifactRunErrorV1, MacosSdistBackendCapabilitiesV1, MacosSdistBackendIdentityV1,
    MacosSdistGuestStagingErrorV1, MacosSdistGuestStagingPolicyV1, MacosSdistSubmissionBindingsV1,
    MacosSdistSubmissionErrorV1, MacosSdistSubmissionHeaderV1, SdistGuestRehashPhaseV1,
    MACOS_SDIST_GUEST_PROTOCOL_V1, MACOS_SDIST_GUEST_SUBMISSION_MAGIC_V1,
    MACOS_SDIST_RUN_SPEC_SCHEMA_V1, MACOS_SDIST_SUBMISSION_FIXED_PREFIX_BYTES_V1,
    MACOS_SDIST_SUBMISSION_MAGIC_V1,
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
        digest(b"sdist supervisor"),
        digest(b"sdist guest auth public key"),
        digest(b"sdist runner configuration"),
        501,
        20,
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
