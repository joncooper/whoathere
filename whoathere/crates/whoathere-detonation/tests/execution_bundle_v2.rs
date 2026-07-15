use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    decode_and_validate_execution_bundle_v2, ArtifactScenarioKindV1, ExecutionBundleArtifactKindV2,
    ExecutionBundleClosureKindV2, ExecutionBundleClosureRequirementV2, ExecutionBundleClosureV2,
    ExecutionBundleErrorV2, ExecutionBundleInputV2, ExecutionBundlePolicyIdentityV2,
    ExecutionBundlePreflightDispositionV2, ExecutionBundlePreflightReasonV2,
    ExecutionBundlePreflightV2, ExecutionBundleScenarioKindV2, ExecutionBundleSelectedScenarioV2,
    ExecutionBundleV2, NpmEnvironmentProfileV1, SdistScenarioClassV1, WheelScenarioClassV1,
    EXECUTION_BUNDLE_ARTIFACT_FILE_V2, EXECUTION_BUNDLE_CLOSURE_FILE_V2,
};

const NPM_BYTES: &[u8] = b"inert exact npm tgz bytes";
const WHEEL_BYTES: &[u8] = b"inert exact wheel bytes";
const SDIST_BYTES: &[u8] = b"inert exact sdist bytes";
const CLOSURE_BYTES: &[u8] = b"inert exact offline closure bytes";

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn policy() -> ExecutionBundlePolicyIdentityV2 {
    ExecutionBundlePolicyIdentityV2::new(
        "local-detection-beta-policy-v2",
        digest(b"inert execution policy"),
    )
    .expect("policy identity")
}

fn npm_scenario() -> ExecutionBundleSelectedScenarioV2 {
    ExecutionBundleSelectedScenarioV2::new(
        "npm-ci-false",
        ExecutionBundleScenarioKindV2::NpmTgz {
            scenario: ArtifactScenarioKindV1::NpmLocalTarballInstall {
                environment: NpmEnvironmentProfileV1::CiFalse,
            },
        },
        digest(b"compiled npm scenario template"),
    )
    .expect("npm scenario")
}

fn wheel_scenario() -> ExecutionBundleSelectedScenarioV2 {
    ExecutionBundleSelectedScenarioV2::new(
        "wheel-import-root",
        ExecutionBundleScenarioKindV2::Wheel {
            scenario_class: WheelScenarioClassV1::ImportRoot,
        },
        digest(b"compiled wheel import scenario template"),
    )
    .expect("wheel scenario")
}

fn sdist_scenario() -> ExecutionBundleSelectedScenarioV2 {
    ExecutionBundleSelectedScenarioV2::new(
        "sdist-build-pep517",
        ExecutionBundleScenarioKindV2::Sdist {
            scenario_class: SdistScenarioClassV1::BuildExactSdist,
        },
        digest(b"compiled sdist build scenario template"),
    )
    .expect("sdist scenario")
}

fn npm_input() -> ExecutionBundleInputV2 {
    ExecutionBundleInputV2 {
        artifact_kind: ExecutionBundleArtifactKindV2::NpmTgz,
        artifact_sha256: digest(NPM_BYTES),
        artifact_byte_length: NPM_BYTES.len() as u64,
        selected_scenario: npm_scenario(),
        expected_action_count: 1,
        closure_requirement: ExecutionBundleClosureRequirementV2::NotRequired,
        closure: None,
        policy: policy(),
        preflight: ExecutionBundlePreflightV2::ready_for_disposable_vm(),
    }
}

#[test]
fn exact_npm_bundle_round_trips_and_binds_artifact_bin() {
    let bundle = ExecutionBundleV2::new(npm_input()).expect("npm bundle");
    assert_eq!(
        bundle.artifact_file_name(),
        EXECUTION_BUNDLE_ARTIFACT_FILE_V2
    );
    assert!(bundle.matches_artifact_bytes(NPM_BYTES));
    assert!(!bundle.matches_artifact_bytes(b"different artifact bytes"));
    assert!(bundle.preflight().permits_vm_execution());
    assert!(!bundle.preflight().authorizes_admission());
    assert!(!bundle.preflight().establishes_clean_behavior());

    let wire = bundle.canonical_json_v2().expect("canonical bundle");
    let decoded = decode_and_validate_execution_bundle_v2(&wire).expect("decode bundle");
    assert_eq!(decoded, bundle);
    assert_eq!(decoded.bundle_sha256(), bundle.bundle_sha256());
    assert_eq!(decoded.selected_scenario().scenario_id(), "npm-ci-false");
}

#[test]
fn wheel_dependency_closure_is_exact_and_digest_bound() {
    let closure = ExecutionBundleClosureV2::new(
        ExecutionBundleClosureKindV2::Dependency,
        digest(CLOSURE_BYTES),
        CLOSURE_BYTES.len() as u64,
    )
    .expect("dependency closure");
    let bundle = ExecutionBundleV2::new(ExecutionBundleInputV2 {
        artifact_kind: ExecutionBundleArtifactKindV2::Wheel,
        artifact_sha256: digest(WHEEL_BYTES),
        artifact_byte_length: WHEEL_BYTES.len() as u64,
        selected_scenario: wheel_scenario(),
        expected_action_count: 3,
        closure_requirement: ExecutionBundleClosureRequirementV2::Dependency,
        closure: Some(closure),
        policy: policy(),
        preflight: ExecutionBundlePreflightV2::ready_for_disposable_vm(),
    })
    .expect("wheel bundle");

    let bound = bundle.closure().expect("bound closure");
    assert_eq!(bound.file_name(), EXECUTION_BUNDLE_CLOSURE_FILE_V2);
    assert!(bound.matches_bytes(CLOSURE_BYTES));
    assert!(!bound.matches_bytes(b"different closure bytes"));
    assert_eq!(bundle.expected_action_count(), 3);
}

#[test]
fn sdist_build_closure_is_supported_but_not_for_other_artifact_kinds() {
    let closure = ExecutionBundleClosureV2::new(
        ExecutionBundleClosureKindV2::Build,
        digest(CLOSURE_BYTES),
        CLOSURE_BYTES.len() as u64,
    )
    .expect("build closure");
    let sdist = ExecutionBundleV2::new(ExecutionBundleInputV2 {
        artifact_kind: ExecutionBundleArtifactKindV2::Sdist,
        artifact_sha256: digest(SDIST_BYTES),
        artifact_byte_length: SDIST_BYTES.len() as u64,
        selected_scenario: sdist_scenario(),
        expected_action_count: 2,
        closure_requirement: ExecutionBundleClosureRequirementV2::Build,
        closure: Some(closure.clone()),
        policy: policy(),
        preflight: ExecutionBundlePreflightV2::ready_for_disposable_vm(),
    })
    .expect("sdist bundle");
    assert_eq!(
        sdist.closure().expect("sdist closure").kind(),
        ExecutionBundleClosureKindV2::Build
    );

    let error = ExecutionBundleV2::new(ExecutionBundleInputV2 {
        artifact_kind: ExecutionBundleArtifactKindV2::Wheel,
        artifact_sha256: digest(WHEEL_BYTES),
        artifact_byte_length: WHEEL_BYTES.len() as u64,
        selected_scenario: wheel_scenario(),
        expected_action_count: 1,
        closure_requirement: ExecutionBundleClosureRequirementV2::Build,
        closure: Some(closure),
        policy: policy(),
        preflight: ExecutionBundlePreflightV2::ready_for_disposable_vm(),
    })
    .expect_err("wheel cannot carry a build closure");
    assert_eq!(error, ExecutionBundleErrorV2::InvalidClosureBinding);
}

#[test]
fn missing_dependencies_are_inconclusive_and_can_never_be_clean() {
    let preflight = ExecutionBundlePreflightV2::inconclusive(vec![
        ExecutionBundlePreflightReasonV2::MissingDependencyClosure,
        ExecutionBundlePreflightReasonV2::UnresolvedDependencies,
    ])
    .expect("inconclusive preflight");
    let bundle = ExecutionBundleV2::new(ExecutionBundleInputV2 {
        artifact_kind: ExecutionBundleArtifactKindV2::Wheel,
        artifact_sha256: digest(WHEEL_BYTES),
        artifact_byte_length: WHEEL_BYTES.len() as u64,
        selected_scenario: wheel_scenario(),
        expected_action_count: 1,
        closure_requirement: ExecutionBundleClosureRequirementV2::Dependency,
        closure: None,
        policy: policy(),
        preflight,
    })
    .expect("inconclusive wheel bundle");

    assert_eq!(
        bundle.preflight().disposition(),
        ExecutionBundlePreflightDispositionV2::Inconclusive
    );
    assert!(!bundle.preflight().permits_vm_execution());
    assert!(!bundle.preflight().authorizes_admission());
    assert!(!bundle.preflight().establishes_clean_behavior());

    let mut ready = npm_input();
    ready.artifact_kind = ExecutionBundleArtifactKindV2::Wheel;
    ready.artifact_sha256 = digest(WHEEL_BYTES);
    ready.artifact_byte_length = WHEEL_BYTES.len() as u64;
    ready.selected_scenario = wheel_scenario();
    ready.closure_requirement = ExecutionBundleClosureRequirementV2::Dependency;
    assert_eq!(
        ExecutionBundleV2::new(ready).expect_err("ready bundle requires exact closure"),
        ExecutionBundleErrorV2::MissingRequiredClosure
    );
}

#[test]
fn unsupported_form_is_manual_review_not_a_clean_result() {
    let preflight = ExecutionBundlePreflightV2::manual_review(vec![
        ExecutionBundlePreflightReasonV2::UnsupportedArtifactForm,
    ])
    .expect("manual review preflight");
    let mut input = npm_input();
    input.preflight = preflight;
    let bundle = ExecutionBundleV2::new(input).expect("manual-review bundle");

    assert_eq!(
        bundle.preflight().disposition(),
        ExecutionBundlePreflightDispositionV2::ManualReview
    );
    assert!(!bundle.preflight().permits_vm_execution());
    assert!(!bundle.preflight().establishes_clean_behavior());
    assert!(!bundle.preflight().authorizes_admission());
}

#[test]
fn artifact_kind_and_typed_scenario_must_match() {
    let mut input = npm_input();
    input.artifact_kind = ExecutionBundleArtifactKindV2::Wheel;
    assert_eq!(
        ExecutionBundleV2::new(input).expect_err("mismatched typed scenario"),
        ExecutionBundleErrorV2::ArtifactScenarioMismatch
    );
}

#[test]
fn action_count_and_preflight_reasons_are_bounded_and_canonical() {
    let mut input = npm_input();
    input.expected_action_count = 0;
    assert_eq!(
        ExecutionBundleV2::new(input).expect_err("zero actions"),
        ExecutionBundleErrorV2::InvalidActionCount
    );

    assert_eq!(
        ExecutionBundlePreflightV2::manual_review(vec![
            ExecutionBundlePreflightReasonV2::UnsupportedNativeTag,
            ExecutionBundlePreflightReasonV2::UnsupportedArtifactForm,
        ])
        .expect_err("reasons must be sorted"),
        ExecutionBundleErrorV2::InvalidPreflight
    );
    assert_eq!(
        ExecutionBundlePreflightV2::inconclusive(Vec::new())
            .expect_err("inconclusive requires a reason"),
        ExecutionBundleErrorV2::InvalidPreflight
    );
}

#[test]
fn strict_wire_rejects_unknown_fields_trailing_data_and_tampering() {
    let bundle = ExecutionBundleV2::new(npm_input()).expect("npm bundle");
    let canonical = bundle.canonical_json_v2().expect("canonical bundle");

    let mut unknown: serde_json::Value = serde_json::from_slice(&canonical).expect("JSON value");
    unknown["unexpected"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("canonical unknown JSON");
    assert_eq!(
        decode_and_validate_execution_bundle_v2(&unknown)
            .expect_err("unknown field must be rejected"),
        ExecutionBundleErrorV2::InvalidWire
    );

    let mut nested_unknown: serde_json::Value =
        serde_json::from_slice(&canonical).expect("nested JSON value");
    nested_unknown["selected_scenario"]["unexpected"] = serde_json::json!(true);
    let nested_unknown =
        serde_json_canonicalizer::to_vec(&nested_unknown).expect("canonical nested JSON");
    assert_eq!(
        decode_and_validate_execution_bundle_v2(&nested_unknown)
            .expect_err("nested unknown field must be rejected"),
        ExecutionBundleErrorV2::InvalidWire
    );

    let mut tampered: serde_json::Value =
        serde_json::from_slice(&canonical).expect("tampered JSON value");
    tampered["expected_action_count"] = serde_json::json!(2);
    let tampered = serde_json_canonicalizer::to_vec(&tampered).expect("canonical tampered JSON");
    assert_eq!(
        decode_and_validate_execution_bundle_v2(&tampered)
            .expect_err("bundle digest must bind action count"),
        ExecutionBundleErrorV2::BundleDigestMismatch
    );

    let mut trailing = canonical.clone();
    trailing.extend_from_slice(b"\n{}");
    assert_eq!(
        decode_and_validate_execution_bundle_v2(&trailing)
            .expect_err("trailing JSON must be rejected"),
        ExecutionBundleErrorV2::InvalidWire
    );

    let pretty = serde_json::to_vec_pretty(&bundle).expect("pretty JSON");
    assert_eq!(
        decode_and_validate_execution_bundle_v2(&pretty).expect_err("wire must be canonical JSON"),
        ExecutionBundleErrorV2::InvalidWire
    );
}
