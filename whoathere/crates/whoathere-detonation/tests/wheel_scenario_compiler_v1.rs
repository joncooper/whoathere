use std::collections::BTreeMap;
use std::io::{Cursor, Write};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_wheel_scenarios_v1, decode_and_validate_wheel_scenario_plan_v1,
    decode_and_validate_wheel_scenario_template_v1, expected_wheel_scenario_kinds_v1,
    ArtifactScenarioCompileErrorV1, ArtifactScenarioExecutionIdentityV1,
    WheelConsoleArgumentProfileV1, WheelRuntimeProfileV1, WheelScenarioCompilationRequestV1,
    WheelScenarioIdentitySetV1, WheelScenarioKindV1, WheelScenarioPlanV1, WheelScenarioPolicyV1,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;
use zip::write::SimpleFileOptions;

struct WheelFixture {
    envelope: ArtifactEnvelope,
    artifact: whoathere_artifact::NormalizedArtifact,
}

fn wheel_fixture(
    metadata_extra: &str,
    entry_points: &str,
    extra_members: &[(&str, &[u8])],
    init_bytes: &[u8],
) -> WheelFixture {
    const DIST_INFO: &str = "wheel_fixture-1.0.0.dist-info";
    let metadata =
        format!("Metadata-Version: 2.1\nName: wheel-fixture\nVersion: 1.0.0\n{metadata_extra}\n");
    let wheel = b"Wheel-Version: 1.0\nGenerator: whoathere-inert\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
    let mut members = vec![
        (format!("{DIST_INFO}/METADATA"), metadata.into_bytes()),
        (format!("{DIST_INFO}/WHEEL"), wheel.to_vec()),
        (
            format!("{DIST_INFO}/entry_points.txt"),
            entry_points.as_bytes().to_vec(),
        ),
        (
            "wheel_fixture.pth".to_string(),
            b"import wheel_fixture.bootstrap\n".to_vec(),
        ),
        ("wheel_fixture/__init__.py".to_string(), init_bytes.to_vec()),
        (
            "wheel_fixture/bootstrap.py".to_string(),
            b"BOOTSTRAP = 'inert'\n".to_vec(),
        ),
        (
            "wheel_fixture/cli.py".to_string(),
            b"def main():\n    return 0\n".to_vec(),
        ),
    ];
    members.extend(
        extra_members
            .iter()
            .map(|(path, bytes)| ((*path).to_string(), bytes.to_vec())),
    );
    let bytes = wheel_zip(&members, DIST_INFO);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("wheel-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:wheel-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-10T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "wheel_fixture-1.0.0-py3-none-any.whl".to_string(),
            declared_format: Some(ArtifactFormat::WheelZip),
            custody_reference: "inert-fixture:wheel-scenario".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "wheel-scenario-test.v1".to_string(),
            requires_external_dependency_resolution: metadata_extra.contains("Requires-Dist:"),
        },
        &bytes,
        ArtifactFormat::WheelZip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert wheel");
    WheelFixture { envelope, artifact }
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
    let digest_hex = whoathere_hash::sha256_hex(bytes);
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

fn default_fixture() -> WheelFixture {
    wheel_fixture(
        "",
        "[console_scripts]\nwheel-tool = wheel_fixture.cli:main\n",
        &[],
        b"VALUE = 'inert'\n",
    )
}

fn runtime_profile() -> WheelRuntimeProfileV1 {
    WheelRuntimeProfileV1::new(
        "macos-arm64-python312-pip26-inert",
        "3.12.13",
        Sha256Digest::from_bytes(b"measured inert python executable"),
        "26.1.2",
        Sha256Digest::from_bytes(b"measured inert pip cli"),
    )
    .expect("wheel runtime")
}

fn subject(fixture: &WheelFixture) -> ArtifactEvidenceSubjectV2 {
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

fn identities(
    fixture: &WheelFixture,
    label: &str,
) -> Result<WheelScenarioIdentitySetV1, ArtifactScenarioCompileErrorV1> {
    WheelScenarioIdentitySetV1::new(
        format!("wheel-plan-{label}"),
        identity_values(fixture, label)?,
    )
}

fn identity_values(
    fixture: &WheelFixture,
    label: &str,
) -> Result<
    BTreeMap<WheelScenarioKindV1, ArtifactScenarioExecutionIdentityV1>,
    ArtifactScenarioCompileErrorV1,
> {
    let kinds = expected_wheel_scenario_kinds_v1(&fixture.artifact.manifest)?;
    kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let suffix = index + 1;
            ArtifactScenarioExecutionIdentityV1::new(
                format!("wheel-job-{label}-{suffix}"),
                format!("wheel-run-{label}-{suffix}"),
                format!("wheel-evidence-{label}-{suffix}"),
                format!("wheel-scenario-{label}-{suffix}"),
            )
            .map(|identity| (kind, identity))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()
}

fn compile(
    fixture: &WheelFixture,
    policy: &WheelScenarioPolicyV1,
    identities: &WheelScenarioIdentitySetV1,
) -> Result<WheelScenarioPlanV1, ArtifactScenarioCompileErrorV1> {
    compile_wheel_scenarios_v1(WheelScenarioCompilationRequestV1 {
        envelope: &fixture.envelope,
        manifest: &fixture.artifact.manifest,
        subject: &subject(fixture),
        policy,
        identities,
    })
}

#[test]
fn exact_wheel_compiles_install_pth_import_and_console_scenarios() {
    let fixture = default_fixture();
    let policy = WheelScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let identities = identities(&fixture, "matrix").expect("identities");
    let plan = compile(&fixture, &policy, &identities).expect("wheel plan");
    assert_eq!(plan.templates().len(), 4);
    assert!(matches!(
        plan.templates()[0].scenario_kind(),
        WheelScenarioKindV1::InstallExactWheel
    ));
    assert!(matches!(
        plan.templates()[1].scenario_kind(),
        WheelScenarioKindV1::FreshInterpreterPth { pth_file_ids }
            if pth_file_ids.len() == 1
    ));
    assert_eq!(
        plan.templates()[2].scenario_kind(),
        &WheelScenarioKindV1::ImportRoot {
            module: "wheel_fixture".to_string()
        }
    );
    assert!(matches!(
        plan.templates()[3].scenario_kind(),
        WheelScenarioKindV1::ConsoleEntryPoint {
            command_name,
            module,
            callable,
            argument_profile: WheelConsoleArgumentProfileV1::HelpOnly,
            ..
        } if command_name == "wheel-tool" && module == "wheel_fixture.cli" && callable == "main"
    ));

    for template in plan.templates() {
        let wire = template.canonical_json_v1().expect("canonical template");
        let decoded =
            decode_and_validate_wheel_scenario_template_v1(&wire).expect("validated template");
        assert_eq!(decoded.template_sha256(), template.template_sha256());
        assert_eq!(decoded.artifact_sha256(), &fixture.envelope.original_sha256);
        let text = std::str::from_utf8(&wire).expect("wire utf8");
        assert!(text.contains("\"install_environment\":\"fresh_virtual_environment\""));
        assert!(text.contains("\"resolver_policy\":\"no_index_no_dependencies\""));
        assert!(text.contains("\"interpreter_policy\":\"fresh_interpreter_per_probe\""));
        assert!(!text.contains("sync"));
        assert!(!text.contains("registry"));
        assert!(!text.contains("argv"));
    }
    let plan_wire = plan.canonical_json_v1().expect("canonical plan");
    let decoded_plan =
        decode_and_validate_wheel_scenario_plan_v1(&plan_wire).expect("validated plan");
    assert_eq!(decoded_plan.plan_sha256(), plan.plan_sha256());
    assert_eq!(decoded_plan.templates().len(), 4);
    assert!(!std::str::from_utf8(&plan_wire)
        .expect("plan utf8")
        .contains("sync"));
}

#[test]
fn wheel_compiler_rejects_dependencies_native_scripts_and_unvalidated_targets() {
    let cases = [
        (
            wheel_fixture(
                "Requires-Dist: requests>=2\n",
                "[console_scripts]\nwheel-tool = wheel_fixture.cli:main\n",
                &[],
                b"VALUE = 'inert'\n",
            ),
            ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure,
        ),
        (
            wheel_fixture(
                "",
                "[console_scripts]\nwheel-tool = wheel_fixture.cli:main\n",
                &[("wheel_fixture/native.so", b"inert native inventory")],
                b"VALUE = 'inert'\n",
            ),
            ArtifactScenarioCompileErrorV1::UnsupportedNativeArtifact,
        ),
        (
            wheel_fixture(
                "",
                "[console_scripts]\nwheel-tool = wheel_fixture.cli:main\n",
                &[("wheel_fixture-1.0.0.data/scripts/raw-tool", b"#!/bin/sh\n")],
                b"VALUE = 'inert'\n",
            ),
            ArtifactScenarioCompileErrorV1::UnsupportedWheelScript,
        ),
        (
            wheel_fixture(
                "",
                "[console_scripts]\nwheel-tool = wheel_fixture.cli:main [extra]\n",
                &[],
                b"VALUE = 'inert'\n",
            ),
            ArtifactScenarioCompileErrorV1::InvalidTriggerSurface,
        ),
    ];
    for (index, (fixture, expected)) in cases.into_iter().enumerate() {
        let policy = WheelScenarioPolicyV1::inert_qualification_only(
            fixture.envelope.original_sha256.clone(),
            runtime_profile(),
        )
        .expect("policy");
        let identities = identities(&fixture, &format!("reject-{index}"));
        if expected == ArtifactScenarioCompileErrorV1::InvalidTriggerSurface {
            assert_eq!(identities, Err(expected));
            continue;
        }
        assert_eq!(
            compile(&fixture, &policy, &identities.expect("identities")),
            Err(expected)
        );
    }
}

#[test]
fn wheel_wire_is_closed_canonical_and_tamper_evident() {
    let fixture = default_fixture();
    let policy = WheelScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let plan = compile(
        &fixture,
        &policy,
        &identities(&fixture, "wire").expect("identities"),
    )
    .expect("plan");
    let canonical = plan.templates()[2]
        .canonical_json_v1()
        .expect("canonical template");

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(&canonical);
    assert_eq!(
        decode_and_validate_wheel_scenario_template_v1(&noncanonical),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&canonical).expect("wire value");
    unknown["sync_back"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown wire");
    assert_eq!(
        decode_and_validate_wheel_scenario_template_v1(&unknown),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut trigger: serde_json::Value = serde_json::from_slice(&canonical).expect("wire value");
    trigger["scenario_kind"]["module"] = serde_json::json!("../../escape");
    let trigger = serde_json_canonicalizer::to_vec(&trigger).expect("trigger wire");
    assert_eq!(
        decode_and_validate_wheel_scenario_template_v1(&trigger),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let console = plan.templates()[3]
        .canonical_json_v1()
        .expect("console template");
    let mut target_digest: serde_json::Value =
        serde_json::from_slice(&console).expect("console wire value");
    target_digest["scenario_kind"]["target_sha256"] =
        serde_json::json!(Sha256Digest::from_bytes(b"forged target").as_str());
    let target_digest =
        serde_json_canonicalizer::to_vec(&target_digest).expect("target digest wire");
    assert_eq!(
        decode_and_validate_wheel_scenario_template_v1(&target_digest),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );

    let mut closure: serde_json::Value = serde_json::from_slice(&canonical).expect("wire value");
    closure["dependency_closure"]["declaration_set_sha256"] =
        serde_json::json!(Sha256Digest::from_bytes(b"forged closure").as_str());
    let closure = serde_json_canonicalizer::to_vec(&closure).expect("closure wire");
    assert_eq!(
        decode_and_validate_wheel_scenario_template_v1(&closure),
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
        decode_and_validate_wheel_scenario_plan_v1(&reordered),
        Err(ArtifactScenarioCompileErrorV1::InvalidWire)
    );
}

#[test]
fn exact_byte_identity_runtime_and_trusted_ids_rebind_wheel_plan() {
    let first = default_fixture();
    let changed = wheel_fixture(
        "",
        "[console_scripts]\nwheel-tool = wheel_fixture.cli:main\n",
        &[],
        b"VALUE = 'changed inert byte'\n",
    );
    let first_policy = WheelScenarioPolicyV1::inert_qualification_only(
        first.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("first policy");
    let changed_policy = WheelScenarioPolicyV1::inert_qualification_only(
        changed.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("changed policy");
    let first_plan = compile(
        &first,
        &first_policy,
        &identities(&first, "first").expect("first identities"),
    )
    .expect("first plan");
    let changed_plan = compile(
        &changed,
        &changed_policy,
        &identities(&changed, "first").expect("changed identities"),
    )
    .expect("changed plan");
    assert_ne!(first_plan.plan_sha256(), changed_plan.plan_sha256());
    assert_ne!(
        first_plan.templates()[0].template_sha256(),
        changed_plan.templates()[0].template_sha256()
    );

    let changed_runtime = WheelRuntimeProfileV1::new(
        "macos-arm64-python312-pip26-inert",
        "3.12.13",
        Sha256Digest::from_bytes(b"measured inert python executable"),
        "26.1.2",
        Sha256Digest::from_bytes(b"different measured inert pip cli"),
    )
    .expect("changed runtime");
    let runtime_policy = WheelScenarioPolicyV1::inert_qualification_only(
        first.envelope.original_sha256.clone(),
        changed_runtime,
    )
    .expect("runtime policy");
    let runtime_plan = compile(
        &first,
        &runtime_policy,
        &identities(&first, "first").expect("identities"),
    )
    .expect("runtime plan");
    assert_ne!(first_plan.plan_sha256(), runtime_plan.plan_sha256());

    let other_ids = identities(&first, "other").expect("other ids");
    let other_plan = compile(&first, &first_policy, &other_ids).expect("other plan");
    assert_ne!(first_plan.plan_sha256(), other_plan.plan_sha256());
}

#[test]
fn subject_policy_and_complete_identity_set_are_fail_closed() {
    let fixture = default_fixture();
    let other = wheel_fixture(
        "",
        "[console_scripts]\nwheel-tool = wheel_fixture.cli:main\n",
        &[],
        b"VALUE = 'other inert bytes'\n",
    );
    let policy = WheelScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("policy");
    let ids = identities(&fixture, "bindings").expect("identities");

    assert_eq!(
        compile_wheel_scenarios_v1(WheelScenarioCompilationRequestV1 {
            envelope: &fixture.envelope,
            manifest: &fixture.artifact.manifest,
            subject: &subject(&other),
            policy: &policy,
            identities: &ids,
        }),
        Err(ArtifactScenarioCompileErrorV1::SubjectMismatch)
    );

    let wrong_policy = WheelScenarioPolicyV1::inert_qualification_only(
        other.envelope.original_sha256.clone(),
        runtime_profile(),
    )
    .expect("wrong policy");
    assert_eq!(
        compile(&fixture, &wrong_policy, &ids),
        Err(ArtifactScenarioCompileErrorV1::PolicyMismatch)
    );

    let mut missing_values = identity_values(&fixture, "missing").expect("identity values");
    let last = missing_values
        .keys()
        .next_back()
        .expect("last scenario")
        .clone();
    missing_values.remove(&last);
    let missing = WheelScenarioIdentitySetV1::new("wheel-plan-missing", missing_values)
        .expect("internally valid incomplete identities");
    assert_eq!(
        compile(&fixture, &policy, &missing),
        Err(ArtifactScenarioCompileErrorV1::InvalidIdentifiers)
    );
}
