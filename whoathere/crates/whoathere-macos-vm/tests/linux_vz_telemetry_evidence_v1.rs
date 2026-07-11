use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1,
    LinuxVzTelemetryConformanceCaseV1, MacosLinuxVzTelemetryConformanceChallengeV1,
    MacosLinuxVzTelemetryEvidenceErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
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
        digest(b"inert host evidence public key"),
        requirements,
        499,
        499,
    )
    .expect("unqualified evidence backend")
}

#[test]
fn challenge_is_fresh_clone_bound_cross_language_and_never_authorizes_packages() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = backend(&requirements);
    let run_spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        "linux-vz-conformance-run-challenge-golden",
        "linux-vz-conformance-evidence-challenge-golden",
        LinuxVzTelemetryConformanceCaseV1::DnsPlaintext,
        &requirements,
        &backend,
    )
    .expect("challenge run spec");
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x42; 32],
        &run_spec,
        &backend,
        digest(b"inert disposable clone binding"),
    )
    .expect("conformance challenge");
    assert!(!challenge.package_execution_authority_permitted());
    assert_eq!(challenge.run_spec_sha256(), run_spec.run_spec_sha256());
    assert_eq!(
        challenge.backend_identity_sha256(),
        run_spec.backend_identity_sha256()
    );
    assert_eq!(
        challenge.telemetry_requirements_sha256(),
        run_spec.telemetry_requirements_sha256()
    );
    assert_eq!(
        challenge.guest_evidence_public_key_sha256(),
        backend.guest_evidence_public_key_sha256()
    );
    assert_eq!(
        challenge.host_evidence_public_key_sha256(),
        backend.host_evidence_public_key_sha256()
    );
    let decoded = decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
        challenge.canonical_json_v1(),
        &run_spec,
        &backend,
    )
    .expect("decode challenge");
    assert_eq!(decoded, challenge);
    assert_eq!(
        challenge.challenge_sha256().as_str(),
        "sha256:28136636fa8be52022213f238b9a39b55c35a837eb8262552dc5eeae55400ff6"
    );

    let other_nonce = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x43; 32],
        &run_spec,
        &backend,
        digest(b"inert disposable clone binding"),
    )
    .expect("other nonce challenge");
    let other_clone = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x42; 32],
        &run_spec,
        &backend,
        digest(b"other disposable clone binding"),
    )
    .expect("other clone challenge");
    assert_ne!(challenge.challenge_sha256(), other_nonce.challenge_sha256());
    assert_ne!(challenge.challenge_sha256(), other_clone.challenge_sha256());
}

#[test]
fn challenge_rejects_rebinding_execution_unknowns_and_noncanonical_wire() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = backend(&requirements);
    let run_spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        "linux-vz-conformance-run-challenge-adversarial",
        "linux-vz-conformance-evidence-challenge-adversarial",
        LinuxVzTelemetryConformanceCaseV1::ForkExecExit,
        &requirements,
        &backend,
    )
    .expect("challenge adversarial spec");
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x24; 32],
        &run_spec,
        &backend,
        digest(b"adversarial clone binding"),
    )
    .expect("adversarial challenge");
    let bytes = challenge.canonical_json_v1();

    let mutations = [
        ("run_spec_sha256", digest(b"rebound run spec")),
        ("backend_identity_sha256", digest(b"rebound backend")),
        (
            "guest_evidence_public_key_sha256",
            digest(b"rebound guest evidence key"),
        ),
        (
            "host_evidence_public_key_sha256",
            digest(b"rebound host evidence key"),
        ),
    ];
    for (key, rebound) in mutations {
        let mut value: serde_json::Value = serde_json::from_slice(bytes).expect("challenge value");
        value[key] = serde_json::json!(rebound.as_str());
        let value = serde_json_canonicalizer::to_vec(&value).expect("rebound challenge wire");
        assert!(
            decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
                &value, &run_spec, &backend
            )
            .is_err()
        );
    }

    let mut executing: serde_json::Value =
        serde_json::from_slice(bytes).expect("executing challenge value");
    executing["package_execution"] = serde_json::json!("enabled");
    let executing = serde_json_canonicalizer::to_vec(&executing).expect("executing wire");
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
            &executing, &run_spec, &backend
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidSchema)
    );

    let mut unknown: serde_json::Value = serde_json::from_slice(bytes).expect("unknown value");
    unknown["execute"] = serde_json::json!(true);
    let unknown = serde_json_canonicalizer::to_vec(&unknown).expect("unknown wire");
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
            &unknown, &run_spec, &backend
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidSchema)
    );

    let mut noncanonical = bytes.to_vec();
    noncanonical.push(b'\n');
    assert_eq!(
        decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
            &noncanonical,
            &run_spec,
            &backend
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::NonCanonical)
    );
}
