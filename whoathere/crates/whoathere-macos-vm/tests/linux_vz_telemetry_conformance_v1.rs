use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    ArtifactProtectedTelemetryRequirementsV1, ArtifactProtectedTelemetrySensorV1,
};
use whoathere_macos_vm::{
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1,
    LinuxVzTelemetryConformanceFixtureV1, MacosLinuxVzTelemetryConformanceRunSpecErrorV1,
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn backend(
    requirements: &ArtifactProtectedTelemetryRequirementsV1,
) -> UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1 {
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
        "linux-vz-base-generation-inert-v1",
        "whoathere-linux-inert-v1",
        "6.12.0-whoathere-inert-v1",
        digest(b"inert kernel image"),
        digest(b"inert initramfs"),
        digest(b"inert root disk"),
        digest(b"inert kernel config"),
        digest(b"inert kernel btf"),
        digest(b"inert guest runner"),
        digest(b"inert guest sensor"),
        digest(b"inert guest bpf bundle"),
        digest(b"inert guest sensor configuration"),
        digest(b"inert guest evidence public key"),
        digest(b"inert host helper"),
        digest(b"inert host packet sensor"),
        digest(b"inert host packet configuration"),
        requirements,
        499,
        499,
    )
    .expect("unqualified conformance backend")
}

#[test]
fn every_inert_conformance_fixture_is_exact_bound_and_package_execution_disabled() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = backend(&requirements);
    let fixtures = [
        LinuxVzTelemetryConformanceFixtureV1::ProcessLineage,
        LinuxVzTelemetryConformanceFixtureV1::FileCanary,
        LinuxVzTelemetryConformanceFixtureV1::NetworkIntent,
        LinuxVzTelemetryConformanceFixtureV1::DropAccounting,
        LinuxVzTelemetryConformanceFixtureV1::TeardownStress,
        LinuxVzTelemetryConformanceFixtureV1::SensorTamper,
    ];
    let mut digests = Vec::new();
    for (index, fixture) in fixtures.into_iter().enumerate() {
        let spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
            format!("linux-vz-conformance-run-{index}"),
            format!("linux-vz-conformance-evidence-{index}"),
            fixture,
            digest(format!("inert fixture binary {index}").as_bytes()),
            &requirements,
            &backend,
        )
        .expect("compile conformance spec");
        assert_eq!(spec.fixture(), fixture);
        assert!(!spec.package_execution_authority_permitted());
        assert!(!spec.expected_sensors().is_empty());
        assert!(spec
            .expected_sensors()
            .contains(&ArtifactProtectedTelemetrySensorV1::SensorHealthHeartbeat));
        assert!(spec
            .expected_sensors()
            .contains(&ArtifactProtectedTelemetrySensorV1::DroppedEventAccounting));
        let decoded = decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(
            spec.canonical_json_v1(),
        )
        .expect("decode conformance spec");
        assert_eq!(decoded, spec);
        let text = String::from_utf8(spec.canonical_json_v1().to_vec()).expect("spec UTF-8");
        assert!(text.contains("trusted_inert_fixture_only_no_package_code"));
        assert!(text.contains("\"package_execution\":\"disabled\""));
        assert!(text.contains("\"sync_back_policy\":\"structurally_absent\""));
        assert!(text.contains("\"external_network\":\"no_external_route\""));
        assert!(!text.contains("artifact_sha256"));
        digests.push(spec.run_spec_sha256().clone());
    }
    digests.sort();
    digests.dedup();
    assert_eq!(digests.len(), fixtures.len());
}

#[test]
fn conformance_run_spec_matches_independent_swift_golden() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = backend(&requirements);
    let spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        "linux-vz-conformance-run-golden",
        "linux-vz-conformance-evidence-golden",
        LinuxVzTelemetryConformanceFixtureV1::NetworkIntent,
        digest(b"inert golden conformance fixture"),
        &requirements,
        &backend,
    )
    .expect("golden conformance spec");

    assert_eq!(
        spec.run_spec_sha256().as_str(),
        "sha256:325a67c4e1690f2b04b6735d5f4463beb248ce68e15868e0337d4b0443ddd671"
    );
}

#[test]
fn conformance_run_spec_rejects_sensor_gaps_backend_rebinding_unknowns_and_cross_schema() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = backend(&requirements);
    let spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        "linux-vz-conformance-run-adversarial",
        "linux-vz-conformance-evidence-adversarial",
        LinuxVzTelemetryConformanceFixtureV1::NetworkIntent,
        digest(b"inert adversarial fixture binary"),
        &requirements,
        &backend,
    )
    .expect("adversarial conformance spec");
    let bytes = spec.canonical_json_v1();

    let mut missing: serde_json::Value =
        serde_json::from_slice(bytes).expect("missing sensor value");
    missing["expected_sensors"]
        .as_array_mut()
        .expect("expected sensors")
        .pop();
    let missing = serde_json_canonicalizer::to_vec(&missing).expect("missing sensor wire");
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&missing),
        Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidFixture)
    );

    let mut rebound: serde_json::Value =
        serde_json::from_slice(bytes).expect("rebound backend value");
    rebound["backend_identity_sha256"] = serde_json::json!(digest(b"rebound backend").as_str());
    let rebound = serde_json_canonicalizer::to_vec(&rebound).expect("rebound backend wire");
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&rebound),
        Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::RequirementsMismatch)
    );

    let mut unknown: serde_json::Value =
        serde_json::from_slice(bytes).expect("unknown field value");
    unknown["execute"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown field wire");
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&unknown),
        Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidSchema)
    );

    let mut cross_schema: serde_json::Value =
        serde_json::from_slice(bytes).expect("cross schema value");
    cross_schema["schema_version"] = serde_json::json!("whoathere.macos_sdist_run_spec.v1");
    let cross_schema = serde_json_canonicalizer::to_vec(&cross_schema).expect("cross schema wire");
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&cross_schema),
        Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::InvalidSchema)
    );

    let mut noncanonical = bytes.to_vec();
    noncanonical.push(b'\n');
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&noncanonical),
        Err(MacosLinuxVzTelemetryConformanceRunSpecErrorV1::NonCanonical)
    );
}
