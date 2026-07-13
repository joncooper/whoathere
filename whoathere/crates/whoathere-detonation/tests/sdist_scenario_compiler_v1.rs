use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::BTreeMap;
use std::io::Cursor;
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_sdist_scenarios_v1, decode_and_validate_sdist_scenario_plan_v1,
    decode_and_validate_sdist_scenario_template_v1, expected_sdist_scenario_kinds_v1,
    ArtifactRuntimeTargetV1, ArtifactScenarioCompileErrorV1, ArtifactScenarioExecutionIdentityV1,
    SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
    SdistBuildModeV1, SdistRuntimeProfileV1, SdistScenarioCompilationRequestV1,
    SdistScenarioIdentitySetV1, SdistScenarioKindV1, SdistScenarioPlanV1, SdistScenarioPolicyV1,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

const DEFAULT_PYPROJECT: &str = r#"[build-system]
requires = ["setuptools==75.0.0", "wheel==0.44.0"]
build-backend = "setuptools.build_meta"

[project]
name = "nested-sdist"
version = "2.0.0"
"#;

const OBJECT_BACKEND_PYPROJECT: &str = r#"[build-system]
requires = ["setuptools==75.0.0", "wheel==0.44.0"]
build-backend = "backend.api:build_wheel"
backend-path = ["backend"]

[project]
name = "nested-sdist"
version = "2.0.0"
"#;

struct SdistFixture {
    envelope: ArtifactEnvelope,
    artifact: whoathere_artifact::NormalizedArtifact,
}

fn tar_gzip(entries: &[(String, Vec<u8>, u32)]) -> Vec<u8> {
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
            .append_data(&mut header, path, Cursor::new(bytes))
            .expect("append inert sdist member");
    }
    archive
        .into_inner()
        .expect("finish inert tar archive")
        .finish()
        .expect("finish inert gzip stream")
}

fn sdist_fixture(
    pyproject: Option<&str>,
    pkg_info_extra: &str,
    init_bytes: &[u8],
    extra_members: &[(&str, &[u8])],
) -> SdistFixture {
    const ROOT: &str = "nested_sdist-2.0.0";
    let pkg_info = format!(
        "Metadata-Version: 2.3\nName: nested-sdist\nVersion: 2.0.0\nSummary: Inert sdist scenario fixture\n{pkg_info_extra}"
    );
    let requires_external_dependency_resolution = pyproject.is_some() || !pkg_info_extra.is_empty();
    let mut entries = vec![
        (format!("{ROOT}/PKG-INFO"), pkg_info.into_bytes(), 0o644),
        (
            format!("{ROOT}/setup.cfg"),
            b"[metadata]\nname = nested-sdist\nversion = 2.0.0\n\n[options]\npackage_dir =\n    =src\npackages = find:\n"
                .to_vec(),
            0o644,
        ),
        (
            format!("{ROOT}/setup.py"),
            b"from setuptools import setup\n\nif __name__ == \"__main__\":\n    setup()\n"
                .to_vec(),
            0o644,
        ),
        (
            format!("{ROOT}/src/nested_sdist/__init__.py"),
            init_bytes.to_vec(),
            0o644,
        ),
    ];
    if let Some(pyproject) = pyproject {
        entries.push((
            format!("{ROOT}/pyproject.toml"),
            pyproject.as_bytes().to_vec(),
            0o644,
        ));
    }
    entries.extend(
        extra_members
            .iter()
            .map(|(path, bytes)| (format!("{ROOT}/{path}"), (*bytes).to_vec(), 0o644)),
    );
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    let bytes = tar_gzip(&entries);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("nested-sdist".to_string()),
            package_version: Some("2.0.0".to_string()),
            source_coordinate: "fixture:nested-sdist@2.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-11T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "nested_sdist-2.0.0.tar.gz".to_string(),
            declared_format: Some(ArtifactFormat::SdistTarGzip),
            custody_reference: "inert-fixture:sdist-scenario".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "sdist-scenario-test.v1".to_string(),
            requires_external_dependency_resolution,
        },
        &bytes,
        ArtifactFormat::SdistTarGzip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert sdist");
    SdistFixture { envelope, artifact }
}

fn default_fixture() -> SdistFixture {
    sdist_fixture(Some(DEFAULT_PYPROJECT), "", b"VALUE = 'inert'\n", &[])
}

fn runtime_profile() -> SdistRuntimeProfileV1 {
    SdistRuntimeProfileV1::new(
        "macos-arm64-python312-pip26-inert",
        "3.12.13",
        Sha256Digest::from_bytes(b"measured inert python executable"),
        "26.1.2",
        Sha256Digest::from_bytes(b"measured inert pip cli"),
    )
    .expect("sdist runtime")
}

fn build_closure(
    build_requires: &[String],
) -> Result<SdistBuildClosureV1, ArtifactScenarioCompileErrorV1> {
    let artifacts = if build_requires.is_empty() {
        Vec::new()
    } else {
        vec![
            SdistBuildClosureArtifactV1::new(
                "setuptools",
                "75.0.0",
                "setuptools-75.0.0-py3-none-any.whl",
                SdistBuildClosureArtifactFormatV1::Wheel,
                Sha256Digest::from_bytes(b"exact inert setuptools wheel"),
                12_345,
            )?,
            SdistBuildClosureArtifactV1::new(
                "wheel",
                "0.44.0",
                "wheel-0.44.0-py3-none-any.whl",
                SdistBuildClosureArtifactFormatV1::Wheel,
                Sha256Digest::from_bytes(b"exact inert wheel build dependency"),
                6_789,
            )?,
        ]
    };
    SdistBuildClosureV1::new(build_requires, artifacts)
}

fn fixture_build_closure(
    fixture: &SdistFixture,
) -> Result<SdistBuildClosureV1, ArtifactScenarioCompileErrorV1> {
    let build_requires = &fixture
        .artifact
        .manifest
        .metadata
        .sdist
        .as_ref()
        .expect("sdist metadata")
        .build_requires;
    build_closure(build_requires)
}

fn subject(fixture: &SdistFixture) -> ArtifactEvidenceSubjectV2 {
    let envelope_sha256 = fixture.envelope.envelope_sha256().expect("envelope digest");
    let hex = fixture
        .envelope
        .original_sha256
        .as_str()
        .strip_prefix("sha256:")
        .expect("digest prefix");
    ArtifactEvidenceSubjectV2::new(
        fixture.envelope.original_sha256.as_str(),
        envelope_sha256.as_str(),
        fixture.artifact.manifest.manifest_sha256.as_str(),
        format!("blobs/sha256/{hex}"),
    )
    .expect("evidence subject")
}

fn identity_values(
    fixture: &SdistFixture,
    label: &str,
) -> Result<
    BTreeMap<SdistScenarioKindV1, ArtifactScenarioExecutionIdentityV1>,
    ArtifactScenarioCompileErrorV1,
> {
    expected_sdist_scenario_kinds_v1(&fixture.artifact.manifest)?
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let suffix = index + 1;
            ArtifactScenarioExecutionIdentityV1::new(
                format!("sdist-job-{label}-{suffix}"),
                format!("sdist-run-{label}-{suffix}"),
                format!("sdist-evidence-{label}-{suffix}"),
                format!("sdist-scenario-{label}-{suffix}"),
            )
            .map(|identity| (kind, identity))
        })
        .collect()
}

fn identities(
    fixture: &SdistFixture,
    label: &str,
) -> Result<SdistScenarioIdentitySetV1, ArtifactScenarioCompileErrorV1> {
    SdistScenarioIdentitySetV1::new(
        format!("sdist-plan-{label}"),
        identity_values(fixture, label)?,
    )
}

fn compile(
    fixture: &SdistFixture,
    policy: &SdistScenarioPolicyV1,
    identities: &SdistScenarioIdentitySetV1,
) -> Result<SdistScenarioPlanV1, ArtifactScenarioCompileErrorV1> {
    compile_sdist_scenarios_v1(SdistScenarioCompilationRequestV1 {
        envelope: &fixture.envelope,
        manifest: &fixture.artifact.manifest,
        subject: &subject(fixture),
        policy,
        identities,
    })
}

#[test]
fn exact_sdist_compiles_build_inspect_install_and_import_scenarios() {
    let fixture = default_fixture();
    let closure = fixture_build_closure(&fixture).expect("build closure");
    let closure_sha256 = closure.closure_sha256().clone();
    let policy = SdistScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
        closure,
    )
    .expect("policy");
    let plan = compile(
        &fixture,
        &policy,
        &identities(&fixture, "matrix").expect("identities"),
    )
    .expect("sdist plan");

    assert_eq!(plan.templates().len(), 4);
    assert!(matches!(
        plan.templates()[0].scenario_kind(),
        SdistScenarioKindV1::BuildExactSdist {
            build_mode: SdistBuildModeV1::Pep517,
            build_backend: Some(backend),
            backend_paths,
            ..
        } if backend == "setuptools.build_meta" && backend_paths.is_empty()
    ));
    assert_eq!(
        plan.templates()[1].scenario_kind(),
        &SdistScenarioKindV1::InspectDerivedWheel
    );
    assert_eq!(
        plan.templates()[2].scenario_kind(),
        &SdistScenarioKindV1::InstallDerivedWheel
    );
    assert_eq!(
        plan.templates()[3].scenario_kind(),
        &SdistScenarioKindV1::ImportRoot {
            module: "nested_sdist".to_string()
        }
    );

    for template in plan.templates() {
        let wire = template.canonical_json_v1().expect("canonical template");
        let decoded =
            decode_and_validate_sdist_scenario_template_v1(&wire).expect("validated template");
        assert_eq!(decoded.template_sha256(), template.template_sha256());
        assert_eq!(decoded.artifact_sha256(), &fixture.envelope.original_sha256);
        assert_eq!(decoded.artifact_format(), ArtifactFormat::SdistTarGzip);
        assert_eq!(
            decoded.artifact_byte_length(),
            fixture.envelope.original_byte_length
        );
        assert_eq!(decoded.build_closure_sha256(), &closure_sha256);
        let text = std::str::from_utf8(&wire).expect("wire utf8");
        assert!(text.contains("\"build_environment\":\"fresh_isolated_virtual_environment\""));
        assert!(text.contains("\"artifact_format\":\"sdist_tar_gzip\""));
        assert!(text.contains("\"resolver_policy\":\"no_index_fixed_closure_only\""));
        assert!(
            text.contains("\"dynamic_build_requirements_policy\":\"deny_outside_fixed_closure\"")
        );
        assert!(text
            .contains("\"derived_wheel_policy\":\"rehash_validate_fresh_scenario_no_host_copy\""));
        assert!(text.contains("\"network_policy\":\"no_network_device\""));
        assert!(text.contains("\"clone_disposition\":\"destroy_clone\""));
        assert!(!text.contains("sync_back"));
        assert!(!text.contains("registry"));
    }

    let plan_wire = plan.canonical_json_v1().expect("canonical plan");
    let decoded = decode_and_validate_sdist_scenario_plan_v1(&plan_wire).expect("validated plan");
    assert_eq!(decoded.plan_sha256(), plan.plan_sha256());
    assert_eq!(decoded.plan_id(), plan.plan_id());
    assert_eq!(decoded.artifact_sha256(), &fixture.envelope.original_sha256);
    assert_eq!(decoded.policy_sha256(), plan.policy_sha256());
    assert_eq!(decoded.templates().len(), 4);
}

#[test]
fn pep517_object_backend_and_legacy_setup_paths_are_distinct_and_typed() {
    let pep517 = sdist_fixture(
        Some(OBJECT_BACKEND_PYPROJECT),
        "",
        b"VALUE = 'object backend inert'\n",
        &[(
            "backend/api.py",
            b"def build_wheel(*args):\n    return 'inert'\n",
        )],
    );
    let kinds = expected_sdist_scenario_kinds_v1(&pep517.artifact.manifest)
        .expect("object backend scenarios");
    assert!(matches!(
        &kinds[0],
        SdistScenarioKindV1::BuildExactSdist {
            build_mode: SdistBuildModeV1::Pep517,
            build_backend: Some(backend),
            backend_paths,
            ..
        } if backend == "backend.api:build_wheel" && backend_paths == &["backend"]
    ));

    let legacy = sdist_fixture(None, "", b"VALUE = 'legacy inert'\n", &[]);
    let closure = fixture_build_closure(&legacy).expect("empty legacy closure");
    let policy = SdistScenarioPolicyV1::inert_qualification_only(
        legacy.envelope.original_sha256.clone(),
        runtime_profile(),
        closure,
    )
    .expect("legacy policy");
    let plan = compile(
        &legacy,
        &policy,
        &identities(&legacy, "legacy").expect("legacy identities"),
    )
    .expect("legacy plan");
    assert!(matches!(
        plan.templates()[0].scenario_kind(),
        SdistScenarioKindV1::BuildExactSdist {
            build_mode: SdistBuildModeV1::LegacySetupPy,
            build_backend: None,
            backend_paths,
            ..
        } if backend_paths.is_empty()
    ));
}

#[test]
fn fixed_build_closure_and_unsupported_sdist_classes_fail_closed() {
    let requirements = vec![
        "setuptools==75.0.0".to_string(),
        "wheel==0.44.0".to_string(),
    ];
    let incomplete = vec![SdistBuildClosureArtifactV1::new(
        "setuptools",
        "75.0.0",
        "setuptools-75.0.0-py3-none-any.whl",
        SdistBuildClosureArtifactFormatV1::Wheel,
        Sha256Digest::from_bytes(b"only one build dependency"),
        100,
    )
    .expect("closure artifact")];
    assert_eq!(
        SdistBuildClosureV1::new(&requirements, incomplete),
        Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure)
    );

    let fixture = default_fixture();
    let mismatched_requirements = vec![
        "setuptools==74.0.0".to_string(),
        "wheel==0.44.0".to_string(),
    ];
    let wrong_policy = SdistScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
        build_closure(&mismatched_requirements).expect("wrong closure"),
    )
    .expect("wrong policy");
    assert_eq!(
        compile(
            &fixture,
            &wrong_policy,
            &identities(&fixture, "wrong-closure").expect("identities")
        ),
        Err(ArtifactScenarioCompileErrorV1::PolicyMismatch)
    );

    let dependency = sdist_fixture(
        Some(DEFAULT_PYPROJECT),
        "Requires-Dist: requests>=2\n",
        b"VALUE = 'dependency inert'\n",
        &[],
    );
    let dependency_policy = SdistScenarioPolicyV1::inert_qualification_only(
        dependency.envelope.original_sha256.clone(),
        runtime_profile(),
        fixture_build_closure(&dependency).expect("dependency build closure"),
    )
    .expect("dependency policy");
    assert_eq!(
        compile(
            &dependency,
            &dependency_policy,
            &identities(&dependency, "runtime-dependency").expect("identities")
        ),
        Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure)
    );

    let native = sdist_fixture(
        Some(DEFAULT_PYPROJECT),
        "",
        b"VALUE = 'native inventory inert'\n",
        &[("src/nested_sdist/native.so", b"inert native inventory")],
    );
    let native_policy = SdistScenarioPolicyV1::inert_qualification_only(
        native.envelope.original_sha256.clone(),
        runtime_profile(),
        fixture_build_closure(&native).expect("native build closure"),
    )
    .expect("native policy");
    assert_eq!(
        compile(
            &native,
            &native_policy,
            &identities(&native, "native").expect("identities")
        ),
        Err(ArtifactScenarioCompileErrorV1::UnsupportedNativeArtifact)
    );
}

#[test]
fn build_closure_artifact_names_formats_and_materialization_names_fail_closed() {
    let valid = SdistBuildClosureArtifactV1::new(
        "setuptools",
        "75.0.0",
        "setuptools-75.0.0-py3-none-any.whl",
        SdistBuildClosureArtifactFormatV1::Wheel,
        Sha256Digest::from_bytes(b"valid exact wheel bytes"),
        23,
    )
    .expect("valid closure artifact");
    for filename in [
        "../setuptools-75.0.0-py3-none-any.whl",
        "nested/setuptools-75.0.0-py3-none-any.whl",
        "nested\\setuptools-75.0.0-py3-none-any.whl",
        "wheel-75.0.0-py3-none-any.whl",
        "setuptools-74.0.0-py3-none-any.whl",
        "setuptools-75.0.0-py3-none.whl",
        "setuptools-75.0.0-build-py3-none-any.whl",
        "setuptools-75.0.0-py3..py4-none-any.whl",
        "setuptools-75.0.0-py3-none-any.tar.gz",
    ] {
        let mut value = serde_json::to_value(&valid).expect("closure artifact json");
        value["artifact_filename"] = serde_json::json!(filename);
        let invalid: SdistBuildClosureArtifactV1 =
            serde_json::from_value(value).expect("typed malformed filename");
        assert_eq!(
            SdistBuildClosureV1::new(&[], vec![invalid]),
            Err(ArtifactScenarioCompileErrorV1::InvalidPolicy),
            "filename must fail closed: {filename}"
        );
    }

    let mut unknown_format = serde_json::to_value(&valid).expect("format artifact json");
    unknown_format["artifact_format"] = serde_json::json!("sdist");
    assert!(serde_json::from_value::<SdistBuildClosureArtifactV1>(unknown_format).is_err());

    let first = valid;
    let second = SdistBuildClosureArtifactV1::new(
        "setuptools",
        "75.0.0",
        "setuptools-75.0.0-py3-none-any.whl",
        SdistBuildClosureArtifactFormatV1::Wheel,
        Sha256Digest::from_bytes(b"different bytes at the same materialization name"),
        48,
    )
    .expect("individually valid duplicate name");
    let mut duplicates = vec![first, second];
    duplicates.sort();
    assert_eq!(
        SdistBuildClosureV1::new(&[], duplicates),
        Err(ArtifactScenarioCompileErrorV1::InvalidPolicy)
    );
}

#[test]
fn sdist_wire_is_closed_canonical_and_tamper_evident() {
    let fixture = default_fixture();
    let policy = SdistScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
        fixture_build_closure(&fixture).expect("build closure"),
    )
    .expect("policy");
    let plan = compile(
        &fixture,
        &policy,
        &identities(&fixture, "wire").expect("identities"),
    )
    .expect("plan");
    let canonical = plan.templates()[0]
        .canonical_json_v1()
        .expect("canonical template");

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(&canonical);
    assert_eq!(
        decode_and_validate_sdist_scenario_template_v1(&noncanonical),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&canonical).expect("wire value");
    unknown["sync_back"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown wire");
    assert_eq!(
        decode_and_validate_sdist_scenario_template_v1(&unknown),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut closure: serde_json::Value = serde_json::from_slice(&canonical).expect("wire value");
    closure["build_closure"]["closure_sha256"] =
        serde_json::json!(Sha256Digest::from_bytes(b"forged closure").as_str());
    let closure = serde_json_canonicalizer::to_vec(&closure).expect("closure wire");
    assert_eq!(
        decode_and_validate_sdist_scenario_template_v1(&closure),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut declaration: serde_json::Value =
        serde_json::from_slice(&canonical).expect("wire value");
    declaration["scenario_kind"]["build_requires_sha256"] =
        serde_json::json!(Sha256Digest::from_bytes(b"forged declarations").as_str());
    let declaration = serde_json_canonicalizer::to_vec(&declaration).expect("declaration wire");
    assert_eq!(
        decode_and_validate_sdist_scenario_template_v1(&declaration),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut package: serde_json::Value = serde_json::from_slice(&canonical).expect("wire value");
    package["package"]["normalized_name"] = serde_json::json!("bad\nname");
    let package = serde_json_canonicalizer::to_vec(&package).expect("package wire");
    assert_eq!(
        decode_and_validate_sdist_scenario_template_v1(&package),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let plan_wire = plan.canonical_json_v1().expect("plan wire");
    let mut reordered: serde_json::Value = serde_json::from_slice(&plan_wire).expect("plan value");
    reordered["templates"]
        .as_array_mut()
        .expect("templates")
        .swap(0, 1);
    let reordered = serde_json_canonicalizer::to_vec(&reordered).expect("reordered plan");
    assert_eq!(
        decode_and_validate_sdist_scenario_plan_v1(&reordered),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );
}

#[test]
fn exact_bytes_runtime_subject_and_identity_set_rebind_or_reject_the_plan() {
    let first = default_fixture();
    let changed = sdist_fixture(
        Some(DEFAULT_PYPROJECT),
        "",
        b"VALUE = 'changed inert byte'\n",
        &[],
    );
    let first_policy = SdistScenarioPolicyV1::inert_qualification_only(
        first.envelope.original_sha256.clone(),
        runtime_profile(),
        fixture_build_closure(&first).expect("first closure"),
    )
    .expect("first policy");
    let changed_policy = SdistScenarioPolicyV1::inert_qualification_only(
        changed.envelope.original_sha256.clone(),
        runtime_profile(),
        fixture_build_closure(&changed).expect("changed closure"),
    )
    .expect("changed policy");
    let first_plan = compile(
        &first,
        &first_policy,
        &identities(&first, "binding").expect("first identities"),
    )
    .expect("first plan");
    let changed_plan = compile(
        &changed,
        &changed_policy,
        &identities(&changed, "binding").expect("changed identities"),
    )
    .expect("changed plan");
    assert_ne!(first_plan.plan_sha256(), changed_plan.plan_sha256());
    assert_ne!(
        first_plan.templates()[0].template_sha256(),
        changed_plan.templates()[0].template_sha256()
    );

    let changed_runtime = SdistRuntimeProfileV1::new(
        "macos-arm64-python312-pip26-inert",
        "3.12.13",
        Sha256Digest::from_bytes(b"measured inert python executable"),
        "26.1.2",
        Sha256Digest::from_bytes(b"different measured inert pip cli"),
    )
    .expect("changed runtime");
    let runtime_policy = SdistScenarioPolicyV1::inert_qualification_only(
        first.envelope.original_sha256.clone(),
        changed_runtime,
        fixture_build_closure(&first).expect("runtime closure"),
    )
    .expect("runtime policy");
    let runtime_plan = compile(
        &first,
        &runtime_policy,
        &identities(&first, "binding").expect("runtime identities"),
    )
    .expect("runtime plan");
    assert_ne!(first_plan.plan_sha256(), runtime_plan.plan_sha256());

    assert_eq!(
        compile_sdist_scenarios_v1(SdistScenarioCompilationRequestV1 {
            envelope: &first.envelope,
            manifest: &first.artifact.manifest,
            subject: &subject(&changed),
            policy: &first_policy,
            identities: &identities(&first, "subject").expect("subject identities"),
        }),
        Err(ArtifactScenarioCompileErrorV1::SubjectMismatch)
    );

    let mut missing_values = identity_values(&first, "missing").expect("identity values");
    let last = missing_values
        .keys()
        .next_back()
        .expect("last scenario")
        .clone();
    missing_values.remove(&last);
    let missing = SdistScenarioIdentitySetV1::new("sdist-plan-missing", missing_values)
        .expect("internally valid incomplete identities");
    assert_eq!(
        compile(&first, &first_policy, &missing),
        Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers)
    );
}

#[test]
fn linux_sdist_runtime_is_distinct_and_cross_target_rebinding_fails_closed() {
    let fixture = default_fixture();
    let linux_runtime = SdistRuntimeProfileV1::new_for_target(
        ArtifactRuntimeTargetV1::LinuxArm64,
        "linux-arm64-python312-pip26-inert",
        "3.12.13",
        Sha256Digest::from_bytes(b"measured inert python executable"),
        "26.1.2",
        Sha256Digest::from_bytes(b"measured inert pip cli"),
    )
    .expect("Linux sdist runtime");
    assert_eq!(
        linux_runtime.runtime_target(),
        ArtifactRuntimeTargetV1::LinuxArm64
    );
    assert_ne!(
        linux_runtime.profile_sha256(),
        runtime_profile().profile_sha256()
    );
    let policy = SdistScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        linux_runtime,
        fixture_build_closure(&fixture).expect("Linux closure"),
    )
    .expect("Linux sdist policy");
    let plan = compile(
        &fixture,
        &policy,
        &identities(&fixture, "linux").expect("Linux identities"),
    )
    .expect("Linux sdist plan");
    let bytes = plan.templates()[0]
        .canonical_json_v1()
        .expect("Linux sdist template");
    let validated = decode_and_validate_sdist_scenario_template_v1(&bytes)
        .expect("strict Linux sdist template");
    assert_eq!(
        validated.runtime_target(),
        ArtifactRuntimeTargetV1::LinuxArm64
    );

    let mut rebound: serde_json::Value = serde_json::from_slice(&bytes).expect("template value");
    rebound["target_arch"] = serde_json::json!("x86_64");
    let rebound = serde_json_canonicalizer::to_vec(&rebound).expect("canonical rebound template");
    assert_eq!(
        decode_and_validate_sdist_scenario_template_v1(&rebound),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );
}
