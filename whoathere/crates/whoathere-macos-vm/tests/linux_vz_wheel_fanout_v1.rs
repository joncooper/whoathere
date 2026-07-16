use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Write};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_wheel_scenarios_v1, expected_wheel_scenario_kinds_v1, ArtifactRuntimeTargetV1,
    ArtifactScenarioExecutionIdentityV1, WheelConsoleArgumentProfileV1, WheelRuntimeProfileV1,
    WheelScenarioCompilationRequestV1, WheelScenarioIdentitySetV1, WheelScenarioKindV1,
    WheelScenarioPlanV1, WheelScenarioPolicyV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    compile_macos_linux_vz_wheel_execution_fanout_v1, MacosLinuxVzWheelEnvironmentIntentV1,
    MacosLinuxVzWheelExecutionFanoutErrorV1, MacosLinuxVzWheelExecutionFanoutRequestV1,
    MacosLinuxVzWheelGrantIntentV1, MacosLinuxVzWheelTeardownIntentV1,
    MacosLinuxVzWheelVmIsolationIntentV1,
};
use zip::write::SimpleFileOptions;

struct WheelFixture {
    bytes: Vec<u8>,
    envelope: ArtifactEnvelope,
    normalized: whoathere_artifact::NormalizedArtifact,
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_bytes(value.as_bytes())
}

fn eight_action_fixture() -> WheelFixture {
    wheel_fixture("", None)
}

fn wheel_fixture(metadata_extra: &str, inventory_only_pth_path: Option<&str>) -> WheelFixture {
    const DIST_INFO: &str = "fanout_fixture-1.0.0.dist-info";
    let metadata =
        format!("Metadata-Version: 2.1\nName: fanout-fixture\nVersion: 1.0.0\n{metadata_extra}\n");
    let mut members = vec![
        (
            format!("{DIST_INFO}/METADATA"),
            metadata.into_bytes(),
        ),
        (
            format!("{DIST_INFO}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: whoathere-inert\nRoot-Is-Purelib: true\nTag: py3-none-any\n".to_vec(),
        ),
        (
            format!("{DIST_INFO}/entry_points.txt"),
            b"[console_scripts]\nalpha-tool = alpha.cli:main\nbeta-tool = beta:main\n".to_vec(),
        ),
        (
            "fanout_activation.pth".to_string(),
            b"# inert activation fixture\n".to_vec(),
        ),
        ("alpha/__init__.py".to_string(), b"VALUE = 1\n".to_vec()),
        (
            "alpha/cli.py".to_string(),
            b"def main():\n    return 0\n".to_vec(),
        ),
        (
            "beta.py".to_string(),
            b"def main():\n    return 0\n".to_vec(),
        ),
    ];
    if let Some(path) = inventory_only_pth_path {
        members.push((path.to_string(), b"# inventory-only pth\n".to_vec()));
    }
    members.sort_by(|left, right| left.0.cmp(&right.0));
    let bytes = wheel_zip(&members, DIST_INFO);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("fanout-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:fanout-fixture==1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-15T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "fanout_fixture-1.0.0-py3-none-any.whl".to_string(),
            declared_format: Some(ArtifactFormat::WheelZip),
            custody_reference: "repository-inert-wheel-fanout-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "linux-vz-wheel-fanout.v1".to_string(),
            requires_external_dependency_resolution: !metadata_extra.is_empty(),
        },
        &bytes,
        ArtifactFormat::WheelZip,
    );
    let normalized = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize six-action wheel fixture");
    WheelFixture {
        bytes,
        envelope,
        normalized,
    }
}

fn compile_plan(fixture: &WheelFixture, target: ArtifactRuntimeTargetV1) -> WheelScenarioPlanV1 {
    let runtime = WheelRuntimeProfileV1::new_for_target(
        target,
        match target {
            ArtifactRuntimeTargetV1::LinuxArm64 => "linux-arm64-python314-pip25-fanout",
            ArtifactRuntimeTargetV1::MacosArm64 => "macos-arm64-python314-pip25-fanout",
        },
        "3.14.0",
        digest("measured fanout python"),
        "25.2",
        digest("measured fanout pip"),
    )
    .expect("runtime profile");
    let policy = WheelScenarioPolicyV1::inert_qualification_only(
        fixture.envelope.original_sha256.clone(),
        runtime,
    )
    .expect("wheel policy");
    let kinds = expected_wheel_scenario_kinds_v1(&fixture.normalized.manifest)
        .expect("supported wheel kinds");
    let identities = kinds
        .into_iter()
        .enumerate()
        .map(|(index, kind)| {
            let ordinal = index + 1;
            (
                kind,
                ArtifactScenarioExecutionIdentityV1::new(
                    format!("wheel-fanout-job-{ordinal}"),
                    format!("wheel-fanout-run-{ordinal}"),
                    format!("wheel-fanout-evidence-{ordinal}"),
                    format!("wheel-fanout-scenario-{ordinal}"),
                )
                .expect("scenario identity"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let identities =
        WheelScenarioIdentitySetV1::new("wheel-fanout-plan", identities).expect("identity set");
    let subject = ArtifactEvidenceSubjectV2::new(
        fixture.normalized.manifest.artifact_sha256.as_str(),
        fixture
            .envelope
            .envelope_sha256()
            .expect("envelope digest")
            .as_str(),
        fixture.normalized.manifest.manifest_sha256.as_str(),
        canonical_cas_object_key_for_artifact(fixture.normalized.manifest.artifact_sha256.as_str())
            .expect("CAS key"),
    )
    .expect("evidence subject");
    compile_wheel_scenarios_v1(WheelScenarioCompilationRequestV1 {
        envelope: &fixture.envelope,
        manifest: &fixture.normalized.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })
    .expect("compile wheel scenario plan")
}

#[test]
fn exact_wheel_fans_out_to_eight_fresh_grant_vm_actions() {
    let fixture = eight_action_fixture();
    let plan = compile_plan(&fixture, ArtifactRuntimeTargetV1::LinuxArm64);
    let fanout = compile_macos_linux_vz_wheel_execution_fanout_v1(
        MacosLinuxVzWheelExecutionFanoutRequestV1 {
            envelope: &fixture.envelope,
            artifact_bytes: &fixture.bytes,
            manifest: &fixture.normalized.manifest,
            scenario_plan: &plan,
            expected_scenario_count: 8,
            normalization_limits: NormalizationLimits::default(),
        },
    )
    .expect("eight-action wheel fanout");

    assert_eq!(fanout.expected_scenario_count(), 8);
    assert_eq!(fanout.actions().len(), 8);
    assert_eq!(fanout.artifact_sha256(), &digest_bytes(&fixture.bytes));
    assert_eq!(
        fanout.manifest_sha256(),
        &fixture.normalized.manifest.manifest_sha256
    );
    assert_eq!(fanout.scenario_plan_sha256(), plan.plan_sha256());
    assert_eq!(
        fanout.scenario_plan_sha256(),
        &digest_bytes(fanout.scenario_plan_canonical_json_v1())
    );
    assert!(!fanout.execution_authority_issued());
    assert!(!fanout.observed_clean_permitted());
    assert!(!fanout.public_network_route_present());
    assert!(!fanout.sync_back_permitted());

    assert!(matches!(
        fanout.actions()[0].scenario_kind(),
        WheelScenarioKindV1::InstallExactWheel
    ));
    assert!(matches!(
        fanout.actions()[1].scenario_kind(),
        WheelScenarioKindV1::FreshInterpreterPth { pth_file_ids }
            if pth_file_ids.len() == 1
    ));
    assert_eq!(
        fanout.actions()[2].scenario_kind(),
        &WheelScenarioKindV1::ImportRoot {
            module: "alpha".to_string(),
        }
    );
    assert_eq!(
        fanout.actions()[3].scenario_kind(),
        &WheelScenarioKindV1::ImportRoot {
            module: "beta".to_string(),
        }
    );
    for (action, (command, profile)) in fanout.actions()[4..].iter().zip([
        (
            "alpha-tool",
            WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperHelp,
        ),
        (
            "alpha-tool",
            WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperNoArguments,
        ),
        (
            "beta-tool",
            WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperHelp,
        ),
        (
            "beta-tool",
            WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperNoArguments,
        ),
    ]) {
        assert!(matches!(
            action.scenario_kind(),
            WheelScenarioKindV1::ConsoleEntryPoint {
                command_name,
                argument_profile,
                ..
            } if command_name == command && argument_profile == &profile
        ));
    }

    let mut binding_subjects = BTreeSet::new();
    let expected_process_counts = [3, 4, 4, 4, 5, 5, 5, 5];
    for (index, action) in fanout.actions().iter().enumerate() {
        assert_eq!(action.action_index(), index as u32);
        assert_eq!(
            action.scenario_template_sha256(),
            &digest_bytes(action.scenario_template_canonical_json_v1())
        );
        assert!(action.exact_offline_install_required());
        assert_eq!(
            action.expected_process_action_count(),
            expected_process_counts[index]
        );
        assert_eq!(
            action.vm_isolation_intent(),
            MacosLinuxVzWheelVmIsolationIntentV1::FreshDisposableVmClonePerAction
        );
        assert_eq!(
            action.grant_intent(),
            MacosLinuxVzWheelGrantIntentV1::FreshOneUseGrantPerActionNotYetIssued
        );
        assert_eq!(
            action.environment_intent(),
            MacosLinuxVzWheelEnvironmentIntentV1::FreshVirtualEnvironmentPerAction
        );
        assert_eq!(
            action.teardown_intent(),
            MacosLinuxVzWheelTeardownIntentV1::StopVmDestroyCloneNoSyncBack
        );
        assert!(!action.execution_authority_issued());
        assert!(!action.public_network_route_present());
        assert!(!action.sync_back_permitted());
        assert!(!action.establishes_clean_behavior());
        assert!(binding_subjects.insert(action.authority_binding_subject_sha256()));
    }

    let text = std::str::from_utf8(fanout.canonical_json_v1()).expect("fanout JSON");
    assert!(text.contains("installed_generated_wrapper_help"));
    assert!(text.contains("installed_generated_wrapper_no_arguments"));
    assert!(text.contains("fresh_one_use_grant_per_action_not_yet_issued"));
    assert!(text.contains("\"expected_scenario_count\":8"));
    assert!(text.contains("\"observed_clean_permitted\":false"));
    assert!(!text.contains("\"execution_authority_issued\":true"));
    assert_eq!(fanout.fanout_sha256(), &digest_without_fanout_field(text));
}

#[test]
fn fanout_rejects_missing_or_extra_actions_and_cross_target_plans() {
    let fixture = eight_action_fixture();
    let linux = compile_plan(&fixture, ArtifactRuntimeTargetV1::LinuxArm64);
    for expected_scenario_count in [7, 9] {
        assert_eq!(
            compile_macos_linux_vz_wheel_execution_fanout_v1(
                MacosLinuxVzWheelExecutionFanoutRequestV1 {
                    envelope: &fixture.envelope,
                    artifact_bytes: &fixture.bytes,
                    manifest: &fixture.normalized.manifest,
                    scenario_plan: &linux,
                    expected_scenario_count,
                    normalization_limits: NormalizationLimits::default(),
                },
            ),
            Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ExpectedScenarioCountMismatch)
        );
    }

    let macos = compile_plan(&fixture, ArtifactRuntimeTargetV1::MacosArm64);
    assert_eq!(
        compile_macos_linux_vz_wheel_execution_fanout_v1(
            MacosLinuxVzWheelExecutionFanoutRequestV1 {
                envelope: &fixture.envelope,
                artifact_bytes: &fixture.bytes,
                manifest: &fixture.normalized.manifest,
                scenario_plan: &macos,
                expected_scenario_count: 8,
                normalization_limits: NormalizationLimits::default(),
            },
        ),
        Err(MacosLinuxVzWheelExecutionFanoutErrorV1::RuntimeTargetMismatch)
    );
}

#[test]
fn fanout_rejects_artifact_rebinding_and_recomputed_manifest_metadata_removal() {
    let fixture = eight_action_fixture();
    let plan = compile_plan(&fixture, ArtifactRuntimeTargetV1::LinuxArm64);
    let mut changed_bytes = fixture.bytes.clone();
    *changed_bytes.last_mut().expect("wheel byte") ^= 1;
    assert_eq!(
        compile_macos_linux_vz_wheel_execution_fanout_v1(
            MacosLinuxVzWheelExecutionFanoutRequestV1 {
                envelope: &fixture.envelope,
                artifact_bytes: &changed_bytes,
                manifest: &fixture.normalized.manifest,
                scenario_plan: &plan,
                expected_scenario_count: 8,
                normalization_limits: NormalizationLimits::default(),
            },
        ),
        Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ExactArtifactInvalid)
    );

    let mut unbound = fixture.normalized.manifest.clone();
    let non_pth_file_id = unbound
        .members
        .iter()
        .find(|member| member.normalized_path == "alpha/__init__.py")
        .expect("non-pth member")
        .file_id
        .clone();
    unbound.metadata.wheel.as_mut().expect("wheel").pth_file_ids = vec![non_pth_file_id];
    unbound.manifest_sha256 = unbound
        .recompute_manifest_sha256()
        .expect("manifest digest");
    unbound
        .validate()
        .expect("structurally valid rebound manifest");
    assert_eq!(
        compile_macos_linux_vz_wheel_execution_fanout_v1(
            MacosLinuxVzWheelExecutionFanoutRequestV1 {
                envelope: &fixture.envelope,
                artifact_bytes: &fixture.bytes,
                manifest: &unbound,
                scenario_plan: &plan,
                expected_scenario_count: 8,
                normalization_limits: NormalizationLimits::default(),
            },
        ),
        Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ManifestArtifactMismatch)
    );

    let mut removed_triggers = fixture.normalized.manifest.clone();
    let wheel = removed_triggers.metadata.wheel.as_mut().expect("wheel");
    wheel.import_roots.clear();
    wheel.console_entry_points.clear();
    wheel.entry_points.clear();
    wheel.entry_points_file_id = None;
    removed_triggers.manifest_sha256 = removed_triggers
        .recompute_manifest_sha256()
        .expect("recomputed attacker-controlled manifest digest");
    removed_triggers
        .validate()
        .expect("self-consistent metadata-removal manifest");
    assert_eq!(
        compile_macos_linux_vz_wheel_execution_fanout_v1(
            MacosLinuxVzWheelExecutionFanoutRequestV1 {
                envelope: &fixture.envelope,
                artifact_bytes: &fixture.bytes,
                manifest: &removed_triggers,
                scenario_plan: &plan,
                expected_scenario_count: 8,
                normalization_limits: NormalizationLimits::default(),
            },
        ),
        Err(MacosLinuxVzWheelExecutionFanoutErrorV1::ManifestArtifactMismatch)
    );
}

#[test]
fn dependency_bearing_pure_wheel_fans_out_offline_and_never_claims_clean() {
    let fixture = wheel_fixture("Requires-Dist: requests>=2\n", None);
    let plan = compile_plan(&fixture, ArtifactRuntimeTargetV1::LinuxArm64);
    let fanout = compile_macos_linux_vz_wheel_execution_fanout_v1(
        MacosLinuxVzWheelExecutionFanoutRequestV1 {
            envelope: &fixture.envelope,
            artifact_bytes: &fixture.bytes,
            manifest: &fixture.normalized.manifest,
            scenario_plan: &plan,
            expected_scenario_count: 8,
            normalization_limits: NormalizationLimits::default(),
        },
    )
    .expect("dependency-bearing wheel fanout");

    assert_eq!(fanout.actions().len(), 8);
    assert!(fanout
        .actions()
        .iter()
        .all(|action| action.exact_offline_install_required()));
    assert!(!fanout.observed_clean_permitted());
    assert!(!fanout.execution_authority_issued());
}

#[test]
fn nested_pth_is_inventory_only_and_requires_manual_review() {
    let clean = eight_action_fixture();
    let plan = compile_plan(&clean, ArtifactRuntimeTargetV1::LinuxArm64);
    for path in [
        "alpha/nested_activation.pth",
        "fanout_fixture-1.0.0.dist-info/metadata_activation.pth",
    ] {
        let fixture = wheel_fixture("", Some(path));
        let wheel = fixture
            .normalized
            .manifest
            .metadata
            .wheel
            .as_ref()
            .expect("wheel metadata");
        assert_eq!(wheel.pth_file_ids.len(), 1, "only root .pth activates");
        assert_eq!(
            fixture.normalized.manifest.normalization_completeness,
            whoathere_artifact::NormalizationCompleteness::Incomplete
        );
        assert!(fixture.normalized.manifest.issues.iter().any(|issue| {
            issue.reason_code == "wheel_pth_inventory_not_site_packages_activation"
                && issue.path.as_deref() == Some(path)
        }));

        let error = compile_macos_linux_vz_wheel_execution_fanout_v1(
            MacosLinuxVzWheelExecutionFanoutRequestV1 {
                envelope: &fixture.envelope,
                artifact_bytes: &fixture.bytes,
                manifest: &fixture.normalized.manifest,
                scenario_plan: &plan,
                expected_scenario_count: 8,
                normalization_limits: NormalizationLimits::default(),
            },
        )
        .expect_err("inventory-only .pth must fail closed");
        assert_eq!(
            error,
            MacosLinuxVzWheelExecutionFanoutErrorV1::UnsupportedPthInventory
        );
        assert_eq!(
            error.disposition(),
            whoathere_macos_vm::MacosLinuxVzWheelExecutionFanoutFailureDispositionV1::ManualReview
        );
        assert!(!error.establishes_clean_behavior());
    }
}

#[test]
fn wheel_data_purelib_and_platlib_pth_are_bound_as_real_activation_surfaces() {
    for scheme in ["purelib", "platlib"] {
        let path = format!("fanout_fixture-1.0.0.data/{scheme}/data_activation.pth");
        let fixture = wheel_fixture("", Some(&path));
        let wheel = fixture
            .normalized
            .manifest
            .metadata
            .wheel
            .as_ref()
            .expect("wheel metadata");
        assert_eq!(
            wheel.pth_file_ids.len(),
            2,
            "root and wheel .data .pth activate"
        );
        assert_eq!(
            fixture.normalized.manifest.normalization_completeness,
            whoathere_artifact::NormalizationCompleteness::Complete
        );
        let plan = compile_plan(&fixture, ArtifactRuntimeTargetV1::LinuxArm64);
        let fanout = compile_macos_linux_vz_wheel_execution_fanout_v1(
            MacosLinuxVzWheelExecutionFanoutRequestV1 {
                envelope: &fixture.envelope,
                artifact_bytes: &fixture.bytes,
                manifest: &fixture.normalized.manifest,
                scenario_plan: &plan,
                expected_scenario_count: 8,
                normalization_limits: NormalizationLimits::default(),
            },
        )
        .expect("wheel .data .pth activation is supported and exactly bound");
        assert!(matches!(
            fanout.actions()[1].scenario_kind(),
            WheelScenarioKindV1::FreshInterpreterPth { pth_file_ids }
                if pth_file_ids.len() == 2
        ));
    }
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
    let digest = digest_bytes(bytes);
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

fn digest_bytes(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(bytes)
}

fn digest_without_fanout_field(canonical_json: &str) -> Sha256Digest {
    let mut value: serde_json::Value = serde_json::from_str(canonical_json).expect("fanout value");
    value
        .as_object_mut()
        .expect("fanout object")
        .remove("fanout_sha256");
    let bytes = serde_json_canonicalizer::to_vec(&value).expect("fanout digest wire");
    Sha256Digest::from_bytes(&bytes)
}
