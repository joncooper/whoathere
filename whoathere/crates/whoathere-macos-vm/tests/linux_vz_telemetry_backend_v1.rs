use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    MacosLinuxVzTelemetryBackendErrorV1, MacosLinuxVzTelemetryQualificationStateV1,
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn identity(
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
    .expect("unqualified Linux VZ identity")
}

#[test]
fn unqualified_linux_vz_identity_binds_every_measured_component_and_never_executes() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let identity = identity(&requirements);
    assert_eq!(
        identity.qualification_state(),
        MacosLinuxVzTelemetryQualificationStateV1::CandidateUnqualified
    );
    assert_eq!(identity.package_uid(), 499);
    assert_eq!(identity.package_gid(), 499);
    assert_eq!(
        identity.telemetry_requirements_sha256(),
        &requirements
            .requirements_sha256_v1()
            .expect("requirements digest")
    );
    assert!(!identity.execution_authority_permitted());
    assert_eq!(
        identity.require_execution_authority(),
        Err(MacosLinuxVzTelemetryBackendErrorV1::TelemetryConformanceMissing)
    );
    let bytes = identity.canonical_json_v1().expect("canonical identity");
    let decoded =
        decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(&bytes, &requirements)
            .expect("decode unqualified identity");
    assert_eq!(decoded, identity);
    assert_eq!(
        requirements
            .requirements_sha256_v1()
            .expect("cross-language requirements digest")
            .as_str(),
        "sha256:3ff8c862243232fbc48ec91d5926e587bf9817f678853d02d9730cde2c464946"
    );
    assert_eq!(
        identity
            .identity_sha256_v1()
            .expect("cross-language identity digest")
            .as_str(),
        "sha256:45c12920320ff882bf39fa45a9a746d51d635973843d05817939df0afdf3fdc6"
    );
    let text = String::from_utf8(bytes).expect("identity UTF-8");
    assert!(text.contains("candidate_unqualified"));
    assert!(!text.contains("qualified\":true"));
    assert!(!text.contains("execution_enabled"));
    assert!(!text.contains("sync_back"));

    let changed = UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
        identity.base_generation_id(),
        identity.linux_distribution_id(),
        identity.kernel_release(),
        digest(b"changed kernel image"),
        identity.initramfs_sha256().clone(),
        identity.root_disk_sha256().clone(),
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
        &requirements,
        499,
        499,
    )
    .expect("changed identity");
    assert_ne!(
        changed.identity_sha256_v1().expect("changed digest"),
        identity.identity_sha256_v1().expect("identity digest")
    );
}

#[test]
fn linux_vz_identity_rejects_tampering_rebinding_unknowns_and_noncanonical_wire() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let identity = identity(&requirements);
    let bytes = identity.canonical_json_v1().expect("canonical identity");

    let mut rebound: serde_json::Value = serde_json::from_slice(&bytes).expect("rebound identity");
    rebound["telemetry_requirements_sha256"] =
        serde_json::json!(digest(b"different requirements").as_str());
    let rebound = serde_json_canonicalizer::to_vec(&rebound).expect("rebound wire");
    assert_eq!(
        decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(&rebound, &requirements),
        Err(MacosLinuxVzTelemetryBackendErrorV1::RequirementsMismatch)
    );

    let mut qualified: serde_json::Value =
        serde_json::from_slice(&bytes).expect("qualified identity");
    qualified["qualification_state"] = serde_json::json!("qualified");
    let qualified = serde_json_canonicalizer::to_vec(&qualified).expect("qualified wire");
    assert_eq!(
        decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(&qualified, &requirements),
        Err(MacosLinuxVzTelemetryBackendErrorV1::InvalidIdentity)
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(&bytes).expect("unknown identity");
    unknown["execution_enabled"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown wire");
    assert_eq!(
        decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(&unknown, &requirements),
        Err(MacosLinuxVzTelemetryBackendErrorV1::InvalidIdentity)
    );

    let mut noncanonical = bytes;
    noncanonical.push(b'\n');
    assert_eq!(
        decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
            &noncanonical,
            &requirements
        ),
        Err(MacosLinuxVzTelemetryBackendErrorV1::NonCanonical)
    );
}
