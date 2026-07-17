use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;
use std::io::Cursor;
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_artifact_scenarios_v1, compile_artifact_scenarios_with_npm_closure_v1,
    decode_and_validate_artifact_scenario_plan_v1,
    decode_and_validate_artifact_scenario_template_v1, ArtifactRuntimeTargetV1,
    ArtifactScenarioCompilationRequestV1, ArtifactScenarioCompileErrorV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioIdentitySetV1, ArtifactScenarioPolicyV1,
    DependencyClosureV1, NpmEnvironmentProfileV1, NpmRuntimeProfileV1,
    SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};

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

struct Fixture {
    envelope: ArtifactEnvelope,
    artifact: whoathere_artifact::NormalizedArtifact,
    subject: ArtifactEvidenceSubjectV2,
}

fn fixture(package_json: &[u8], extra: &[(&str, &[u8])], requires_closure: bool) -> Fixture {
    fixture_at_root("odd-root", package_json, extra, requires_closure)
}

fn fixture_at_root(
    root: &str,
    package_json: &[u8],
    extra: &[(&str, &[u8])],
    requires_closure: bool,
) -> Fixture {
    let package_json_path = format!("{root}/package.json");
    let mut entries = vec![(package_json_path.as_str(), package_json)];
    entries.extend_from_slice(extra);
    let bytes = npm_tgz(&entries);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("artifact-scenario-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:artifact-scenario-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-10T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "artifact-scenario-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "repository-inert-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "artifact-scenario-first-slice.v1".to_string(),
            requires_external_dependency_resolution: requires_closure,
        },
        &bytes,
        ArtifactFormat::NpmTarGzip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert fixture");
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
    .expect("evidence subject");
    Fixture {
        envelope,
        artifact,
        subject,
    }
}

fn runtime_profile() -> NpmRuntimeProfileV1 {
    NpmRuntimeProfileV1::new(
        "macos-arm64-node22-npm11-inert",
        "22.17.0",
        Sha256Digest::from_bytes(b"measured inert node executable"),
        "11.18.0",
        Sha256Digest::from_bytes(b"measured inert npm cli"),
    )
    .expect("runtime profile")
}

fn identities(suffix: &str) -> ArtifactScenarioIdentitySetV1 {
    ArtifactScenarioIdentitySetV1::new(
        format!("plan-{suffix}"),
        ArtifactScenarioExecutionIdentityV1::new(
            format!("job-ci-false-{suffix}"),
            format!("run-ci-false-{suffix}"),
            format!("evidence-ci-false-{suffix}"),
            format!("scenario-ci-false-{suffix}"),
        )
        .expect("CI=false identity"),
        ArtifactScenarioExecutionIdentityV1::new(
            format!("job-ci-true-{suffix}"),
            format!("run-ci-true-{suffix}"),
            format!("evidence-ci-true-{suffix}"),
            format!("scenario-ci-true-{suffix}"),
        )
        .expect("CI=true identity"),
    )
    .expect("identity set")
}

fn compile<'a>(
    fixture: &'a Fixture,
    policy: &'a ArtifactScenarioPolicyV1,
    ids: &'a ArtifactScenarioIdentitySetV1,
) -> Result<whoathere_detonation::ArtifactScenarioPlanV1, ArtifactScenarioCompileErrorV1> {
    compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
        envelope: &fixture.envelope,
        manifest: &fixture.artifact.manifest,
        subject: &fixture.subject,
        policy,
        identities: ids,
    })
}

#[test]
fn dependency_free_npm_compiles_to_two_exact_ordered_no_sync_scenarios() {
    let fixture = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","scripts":{"preinstall":"node pre.js --inert-pre-marker","install":"node install.js --inert-install-marker","postinstall":"node post.js --inert-post-marker"}}"#,
        &[
            ("odd-root/pre.js", b"process.exit(0)"),
            ("odd-root/install.js", b"process.exit(0)"),
            ("odd-root/post.js", b"process.exit(0)"),
        ],
        false,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let ids = identities("a");
    let first = compile(&fixture, &policy, &ids).expect("compiled plan");
    let second = compile(&fixture, &policy, &ids).expect("repeat compiled plan");
    assert_eq!(first, second);
    assert_eq!(first.templates().len(), 2);
    assert_eq!(
        first.templates()[0].scenario_kind().environment(),
        Some(NpmEnvironmentProfileV1::CiFalse)
    );
    assert_eq!(
        first.templates()[1].scenario_kind().environment(),
        Some(NpmEnvironmentProfileV1::CiTrue)
    );
    assert_ne!(
        first.templates()[0].identity().run_id(),
        first.templates()[1].identity().run_id()
    );
    assert_eq!(first.templates()[0].lifecycle_hooks().len(), 3);

    for template in first.templates() {
        let bytes = template.canonical_json_v1().expect("template JSON");
        let text = std::str::from_utf8(&bytes).expect("UTF-8 template");
        assert!(!text.contains("sync"));
        assert!(!text.contains("argv"));
        assert!(!text.contains("registry"));
        assert!(!text.contains("inert-pre-marker"));
        assert!(!text.contains("inert-install-marker"));
        assert!(!text.contains("inert-post-marker"));
        let decoded = decode_and_validate_artifact_scenario_template_v1(&bytes)
            .expect("strict template wire");
        assert_eq!(decoded.template_sha256(), template.template_sha256());
        assert_eq!(
            decoded.artifact_sha256().as_str(),
            fixture.subject.artifact_sha256()
        );
    }
    let plan_bytes = first.canonical_json_v1().expect("plan JSON");
    let decoded =
        decode_and_validate_artifact_scenario_plan_v1(&plan_bytes).expect("strict plan wire");
    assert_eq!(decoded.plan_sha256(), first.plan_sha256());
    assert_eq!(decoded.plan_id(), first.plan_id());
}

#[test]
fn canonical_package_root_compiles_under_the_same_closed_contract() {
    let fixture = fixture_at_root(
        "package",
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#,
        &[("package/post.js", b"process.exit(0)")],
        false,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let plan = compile(&fixture, &policy, &identities("canonical-root")).expect("compiled plan");
    assert_eq!(plan.templates().len(), 2);
    assert!(plan
        .templates()
        .iter()
        .all(|template| template.lifecycle_hooks().len() == 1));
}

#[test]
fn development_dependencies_do_not_create_a_runtime_closure() {
    let fixture = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","devDependencies":{"rollup":"1.0.0"}}"#,
        &[],
        false,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let plan = compile(&fixture, &policy, &identities("dev-only"))
        .expect("development-only dependencies do not execute at install time");
    assert_eq!(plan.templates().len(), 2);
}

#[test]
fn unsupported_closure_native_and_unqualified_hook_fail_before_any_backend() {
    let dependency = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}"#,
        &[],
        true,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        dependency.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("dependency policy");
    assert_eq!(
        compile(&dependency, &policy, &identities("dependency")),
        Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure)
    );

    let native = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0"}"#,
        &[("odd-root/binding.gyp", b"{}")],
        false,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        native.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("native policy");
    assert_eq!(
        compile(&native, &policy, &identities("native")),
        Err(ArtifactScenarioCompileErrorV1::UnsupportedNativeArtifact)
    );

    let prepare = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","scripts":{"prepare":"node prepare.js"}}"#,
        &[("odd-root/prepare.js", b"process.exit(0)")],
        false,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        prepare.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("prepare policy");
    assert_eq!(
        compile(&prepare, &policy, &identities("prepare")),
        Err(ArtifactScenarioCompileErrorV1::UnsupportedLifecycleHook)
    );
}

#[test]
fn exact_npm_tarball_closure_is_bound_into_both_install_profiles() {
    let fixture = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","dependencies":{"left-pad":"1.3.0"},"peerDependencies":{"react":">=16.8.0","react-dom":">=16.8.0"},"scripts":{"postinstall":"node post.js"}}"#,
        &[("odd-root/post.js", b"process.exit(0)")],
        true,
    );
    let left_pad = b"exact inert left-pad tarball";
    let react = b"exact inert react tarball";
    let react_dom = b"exact inert react-dom tarball";
    let closure = SdistBuildClosureV1::new(
        &[
            "left-pad 1.3.0".to_string(),
            "react >=16.8.0".to_string(),
            "react-dom >=16.8.0".to_string(),
        ],
        vec![
            SdistBuildClosureArtifactV1::new(
                "left-pad",
                "1.3.0",
                "left-pad-1.3.0.tgz",
                SdistBuildClosureArtifactFormatV1::NpmTarGzip,
                Sha256Digest::from_bytes(left_pad),
                left_pad.len() as u64,
            )
            .expect("left-pad descriptor"),
            SdistBuildClosureArtifactV1::new(
                "react",
                "18.3.1",
                "react-18.3.1.tgz",
                SdistBuildClosureArtifactFormatV1::NpmTarGzip,
                Sha256Digest::from_bytes(react),
                react.len() as u64,
            )
            .expect("react descriptor"),
            SdistBuildClosureArtifactV1::new(
                "react-dom",
                "18.3.1",
                "react-dom-18.3.1.tgz",
                SdistBuildClosureArtifactFormatV1::NpmTarGzip,
                Sha256Digest::from_bytes(react_dom),
                react_dom.len() as u64,
            )
            .expect("react-dom descriptor"),
        ],
    )
    .expect("npm closure");
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let plan = compile_artifact_scenarios_with_npm_closure_v1(
        ArtifactScenarioCompilationRequestV1 {
            envelope: &fixture.envelope,
            manifest: &fixture.artifact.manifest,
            subject: &fixture.subject,
            policy: &policy,
            identities: &identities("fixed-closure"),
        },
        Some(&closure),
    )
    .expect("compile exact npm closure");

    assert_eq!(plan.templates().len(), 2);
    for template in plan.templates() {
        assert!(matches!(
            template.dependency_closure(),
            DependencyClosureV1::NpmTarballSet { closure: bound } if bound == &closure
        ));
        let decoded = decode_and_validate_artifact_scenario_template_v1(
            &template.canonical_json_v1().expect("template bytes"),
        )
        .expect("decode populated closure template");
        assert_eq!(
            decoded.dependency_closure_sha256(),
            closure.closure_sha256()
        );
        assert_eq!(
            decoded.dependency_closure().npm_tarball_closure(),
            Some(&closure)
        );
    }

    let wrong = SdistBuildClosureV1::new(
        &["left-pad 1.3.0".to_string()],
        vec![closure.artifacts()[0].clone()],
    )
    .expect("wrong closure");
    assert_eq!(
        compile_artifact_scenarios_with_npm_closure_v1(
            ArtifactScenarioCompilationRequestV1 {
                envelope: &fixture.envelope,
                manifest: &fixture.artifact.manifest,
                subject: &fixture.subject,
                policy: &policy,
                identities: &identities("wrong-fixed-closure"),
            },
            Some(&wrong),
        ),
        Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure)
    );
}

#[test]
fn inert_digest_guard_and_subject_binding_are_fail_closed() {
    let fixture = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#,
        &[("odd-root/post.js", b"process.exit(0)")],
        false,
    );
    let wrong_policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        Sha256Digest::from_bytes(b"different inert fixture"),
        runtime_profile(),
    )
    .expect("wrong policy");
    assert_eq!(
        compile(&fixture, &wrong_policy, &identities("wrong-policy")),
        Err(ArtifactScenarioCompileErrorV1::PolicyMismatch)
    );

    let wrong_subject = ArtifactEvidenceSubjectV2::new(
        fixture.subject.artifact_sha256(),
        Sha256Digest::from_bytes(b"wrong envelope").as_str(),
        fixture.subject.manifest_sha256(),
        fixture.subject.cas_object_key(),
    )
    .expect("structurally valid wrong subject");
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    assert_eq!(
        compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
            envelope: &fixture.envelope,
            manifest: &fixture.artifact.manifest,
            subject: &wrong_subject,
            policy: &policy,
            identities: &identities("wrong-subject"),
        }),
        Err(ArtifactScenarioCompileErrorV1::SubjectMismatch)
    );
}

#[test]
fn canonical_wire_rejects_unknown_noncanonical_trailing_and_tampered_closure() {
    let fixture = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#,
        &[("odd-root/post.js", b"process.exit(0)")],
        false,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let plan = compile(&fixture, &policy, &identities("wire")).expect("plan");
    let canonical = plan.templates()[0]
        .canonical_json_v1()
        .expect("template JSON");

    let mut spaced = b" ".to_vec();
    spaced.extend_from_slice(&canonical);
    assert_eq!(
        decode_and_validate_artifact_scenario_template_v1(&spaced),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );
    let mut trailing = canonical.clone();
    trailing.extend_from_slice(b"{}\n");
    assert_eq!(
        decode_and_validate_artifact_scenario_template_v1(&trailing),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut duplicate = b"{\"artifact_byte_length\":1,".to_vec();
    duplicate.extend_from_slice(&canonical[1..]);
    assert_eq!(
        decode_and_validate_artifact_scenario_template_v1(&duplicate),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut unknown: serde_json::Value =
        serde_json::from_slice(&canonical).expect("template value");
    unknown
        .as_object_mut()
        .expect("template object")
        .insert("sync_back".to_string(), json!(false));
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("canonical unknown wire");
    assert_eq!(
        decode_and_validate_artifact_scenario_template_v1(&unknown),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&canonical).expect("template value");
    tampered["dependency_closure"]["declaration_set_sha256"] =
        json!(Sha256Digest::from_bytes(b"forged empty closure").as_str());
    let tampered = serde_json_canonicalizer::to_vec(&tampered).expect("canonical tampered wire");
    assert_eq!(
        decode_and_validate_artifact_scenario_template_v1(&tampered),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );
}

#[test]
fn trusted_identity_changes_rebind_template_and_plan_digests() {
    let fixture = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#,
        &[("odd-root/post.js", b"process.exit(0)")],
        false,
    );
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let first = compile(&fixture, &policy, &identities("first")).expect("first plan");
    let second = compile(&fixture, &policy, &identities("second")).expect("second plan");
    assert_ne!(first.plan_sha256(), second.plan_sha256());
    assert_ne!(
        first.templates()[0].template_sha256(),
        second.templates()[0].template_sha256()
    );

    let changed_runtime = NpmRuntimeProfileV1::new(
        "macos-arm64-node22-npm11-inert",
        "22.17.0",
        Sha256Digest::from_bytes(b"measured inert node executable"),
        "11.18.0",
        Sha256Digest::from_bytes(b"different measured inert npm cli"),
    )
    .expect("changed runtime");
    let changed_policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        changed_runtime,
    )
    .expect("changed policy");
    let changed =
        compile(&fixture, &changed_policy, &identities("first")).expect("changed-runtime plan");
    assert_ne!(first.plan_sha256(), changed.plan_sha256());
    assert_ne!(
        first.templates()[0].template_sha256(),
        changed.templates()[0].template_sha256()
    );
}

#[test]
fn linux_runtime_is_distinct_and_cross_target_template_rebinding_fails_closed() {
    let fixture = fixture(
        br#"{"name":"artifact-scenario-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#,
        &[("odd-root/post.js", b"process.exit(0)")],
        false,
    );
    let linux_runtime = NpmRuntimeProfileV1::new_for_target(
        ArtifactRuntimeTargetV1::LinuxArm64,
        "linux-arm64-node22-npm11-inert",
        "22.17.0",
        Sha256Digest::from_bytes(b"measured inert node executable"),
        "11.18.0",
        Sha256Digest::from_bytes(b"measured inert npm cli"),
    )
    .expect("Linux runtime profile");
    assert_eq!(
        linux_runtime.runtime_target(),
        ArtifactRuntimeTargetV1::LinuxArm64
    );
    assert_ne!(
        linux_runtime.profile_sha256(),
        runtime_profile().profile_sha256()
    );

    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        linux_runtime,
    )
    .expect("Linux policy");
    let plan = compile(&fixture, &policy, &identities("linux")).expect("Linux plan");
    let template_bytes = plan.templates()[0]
        .canonical_json_v1()
        .expect("Linux template");
    let validated = decode_and_validate_artifact_scenario_template_v1(&template_bytes)
        .expect("strict Linux template");
    assert_eq!(
        validated.runtime_target(),
        ArtifactRuntimeTargetV1::LinuxArm64
    );

    let mut rebound: serde_json::Value =
        serde_json::from_slice(&template_bytes).expect("template value");
    rebound["target_os"] = json!("macos");
    let rebound = serde_json_canonicalizer::to_vec(&rebound).expect("canonical rebound template");
    assert_eq!(
        decode_and_validate_artifact_scenario_template_v1(&rebound),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );
}
