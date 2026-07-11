use ed25519_dalek::SigningKey;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1,
    sign_macos_linux_vz_telemetry_guest_receipt_v1, sign_macos_linux_vz_telemetry_host_receipt_v1,
    verify_macos_linux_vz_telemetry_conformance_case_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_host_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryGuestObservationClaimsV1,
    LinuxVzTelemetryHostObservationClaimsV1, MacosLinuxVzTelemetryConformanceChallengeV1,
    MacosLinuxVzTelemetryEvidenceErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};

fn digest(label: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(label)
}

fn backend(
    requirements: &ArtifactProtectedTelemetryRequirementsV1,
) -> UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1 {
    backend_with_keys(
        requirements,
        digest(b"inert guest evidence public key"),
        digest(b"inert host evidence public key"),
    )
}

fn backend_with_keys(
    requirements: &ArtifactProtectedTelemetryRequirementsV1,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
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
        guest_evidence_public_key_sha256,
        digest(b"inert host helper"),
        digest(b"inert host packet sensor"),
        digest(b"inert host packet configuration"),
        host_evidence_public_key_sha256,
        requirements,
        499,
        499,
    )
    .expect("unqualified evidence backend")
}

#[test]
fn independently_signed_guest_and_host_receipts_bind_exact_observations_and_never_authorize() {
    let guest_seed = [0x11; 32];
    let host_seed = [0x22; 32];
    let guest_key = SigningKey::from_bytes(&guest_seed).verifying_key();
    let host_key = SigningKey::from_bytes(&host_seed).verifying_key();
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = backend_with_keys(
        &requirements,
        Sha256Digest::from_bytes(guest_key.as_bytes()),
        Sha256Digest::from_bytes(host_key.as_bytes()),
    );
    let run_spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        "linux-vz-conformance-run-receipt-golden",
        "linux-vz-conformance-evidence-receipt-golden",
        LinuxVzTelemetryConformanceCaseV1::DnsPlaintext,
        &requirements,
        &backend,
    )
    .expect("receipt run spec");
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x33; 32],
        &run_spec,
        &backend,
        digest(b"receipt disposable clone binding"),
    )
    .expect("receipt challenge");
    let guest_claims = LinuxVzTelemetryGuestObservationClaimsV1::new(
        digest(b"canonical guest telemetry evidence payload"),
        4096,
        10,
        89,
        80,
        4,
        0,
        true,
        false,
        true,
        LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
    )
    .expect("guest claims");
    let host_claims = LinuxVzTelemetryHostObservationClaimsV1::new(
        digest(b"canonical host telemetry evidence payload"),
        2048,
        100,
        139,
        40,
        4,
        0,
        true,
        false,
        true,
        true,
        true,
        true,
        0,
        LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
    )
    .expect("host claims");
    let guest_receipt = sign_macos_linux_vz_telemetry_guest_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &guest_claims,
        guest_seed,
    )
    .expect("sign guest receipt");
    let host_receipt = sign_macos_linux_vz_telemetry_host_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &host_claims,
        host_seed,
    )
    .expect("sign host receipt");
    let guest = verify_macos_linux_vz_telemetry_guest_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &guest_receipt,
        guest_key.to_bytes(),
        &guest_claims,
    )
    .expect("verify guest receipt");
    let host = verify_macos_linux_vz_telemetry_host_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &host_receipt,
        host_key.to_bytes(),
        &host_claims,
    )
    .expect("verify host receipt");
    let mut guest_unsigned: serde_json::Value =
        serde_json::from_slice(&guest_receipt).expect("guest unsigned value");
    guest_unsigned
        .as_object_mut()
        .expect("guest unsigned object")
        .remove("signature_ed25519_hex");
    let guest_unsigned =
        serde_json_canonicalizer::to_vec(&guest_unsigned).expect("guest unsigned wire");
    let mut host_unsigned: serde_json::Value =
        serde_json::from_slice(&host_receipt).expect("host unsigned value");
    host_unsigned
        .as_object_mut()
        .expect("host unsigned object")
        .remove("signature_ed25519_hex");
    let host_unsigned =
        serde_json_canonicalizer::to_vec(&host_unsigned).expect("host unsigned wire");
    assert_eq!(
        Sha256Digest::from_bytes(&guest_unsigned).as_str(),
        "sha256:a6a9a44200b03f9865b8ad1a7d5eb58c6bcadd39499f13a22856926e65acec92"
    );
    assert_eq!(
        Sha256Digest::from_bytes(&host_unsigned).as_str(),
        "sha256:e983821449e2c24ecd5fb70e7f214fce38f8471314ac0e61f4b5647cc3c3d979"
    );
    assert_eq!(guest.challenge_sha256(), challenge.challenge_sha256());
    assert_eq!(host.challenge_sha256(), challenge.challenge_sha256());
    assert_eq!(
        guest.observed_sensors(),
        run_spec.expected_guest_sensors_v1()
    );
    assert_eq!(host.observed_sensors(), run_spec.expected_host_sensors_v1());
    assert!(!guest.package_execution_authority_permitted());
    assert!(!host.package_execution_authority_permitted());
    let verified_case = verify_macos_linux_vz_telemetry_conformance_case_v1(
        &challenge,
        &run_spec,
        Some(&guest),
        &host,
    )
    .expect("verify complete conformance case");
    assert_eq!(
        verified_case.fixture_case(),
        LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
    );
    assert!(verified_case.guest_receipt_present());
    assert!(!verified_case.package_execution_authority_permitted());
    assert_eq!(
        Sha256Digest::from_bytes(&guest_receipt).as_str(),
        "sha256:9bad56c2d3def2391e9f164f7262963c83ec7ba2fe3946e7301bc3d7122224ef"
    );
    assert_eq!(
        Sha256Digest::from_bytes(&host_receipt).as_str(),
        "sha256:48a21bb1719681148070688cbf3bf890ca7c84c735eb5ba954558179608dac43"
    );
    let guest_text = String::from_utf8(guest_receipt.clone()).expect("guest receipt UTF-8");
    let host_text = String::from_utf8(host_receipt.clone()).expect("host receipt UTF-8");
    for text in [&guest_text, &host_text] {
        assert!(text.contains("\"package_execution\":\"disabled\""));
        assert!(text.contains("\"sync_back_policy\":\"structurally_absent\""));
    }
    assert!(guest_text.contains("\"public_network_reachable\":false"));
    assert!(host_text.contains("\"public_network_route_present\":false"));

    assert_eq!(
        verify_macos_linux_vz_telemetry_host_receipt_v1(
            &challenge,
            &run_spec,
            &backend,
            &guest_receipt,
            host_key.to_bytes(),
            &host_claims,
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)
    );
    assert_eq!(
        verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge,
            &run_spec,
            &backend,
            &host_receipt,
            guest_key.to_bytes(),
            &guest_claims,
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)
    );
}

#[test]
fn receipts_reject_signature_claim_sensor_execution_and_network_rebinding() {
    let guest_seed = [0x51; 32];
    let host_seed = [0x52; 32];
    let guest_key = SigningKey::from_bytes(&guest_seed).verifying_key();
    let host_key = SigningKey::from_bytes(&host_seed).verifying_key();
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = backend_with_keys(
        &requirements,
        Sha256Digest::from_bytes(guest_key.as_bytes()),
        Sha256Digest::from_bytes(host_key.as_bytes()),
    );
    let run_spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        "linux-vz-conformance-run-receipt-adversarial",
        "linux-vz-conformance-evidence-receipt-adversarial",
        LinuxVzTelemetryConformanceCaseV1::ForkExecExit,
        &requirements,
        &backend,
    )
    .expect("adversarial receipt spec");
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x53; 32],
        &run_spec,
        &backend,
        digest(b"adversarial receipt clone"),
    )
    .expect("adversarial receipt challenge");
    let guest_claims = LinuxVzTelemetryGuestObservationClaimsV1::new(
        digest(b"adversarial guest evidence"),
        1024,
        1,
        10,
        10,
        2,
        0,
        true,
        false,
        true,
        LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
    )
    .expect("adversarial guest claims");
    let receipt = sign_macos_linux_vz_telemetry_guest_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &guest_claims,
        guest_seed,
    )
    .expect("adversarial guest receipt");

    for (key, value) in [
        ("package_execution", serde_json::json!("enabled")),
        ("public_network_reachable", serde_json::json!(true)),
        ("package_capabilities_present", serde_json::json!(true)),
        ("evidence_truncated", serde_json::json!(true)),
    ] {
        let mut mutated: serde_json::Value =
            serde_json::from_slice(&receipt).expect("mutated receipt value");
        mutated[key] = value;
        let mutated = serde_json_canonicalizer::to_vec(&mutated).expect("mutated receipt wire");
        assert_eq!(
            verify_macos_linux_vz_telemetry_guest_receipt_v1(
                &challenge,
                &run_spec,
                &backend,
                &mutated,
                guest_key.to_bytes(),
                &guest_claims,
            ),
            Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)
        );
    }
    let mut sensors: serde_json::Value =
        serde_json::from_slice(&receipt).expect("sensor receipt value");
    sensors["observed_sensors"]
        .as_array_mut()
        .expect("observed sensors")
        .pop();
    let sensors = serde_json_canonicalizer::to_vec(&sensors).expect("sensor receipt wire");
    assert_eq!(
        verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge,
            &run_spec,
            &backend,
            &sensors,
            guest_key.to_bytes(),
            &guest_claims,
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)
    );
    let mut signature: serde_json::Value =
        serde_json::from_slice(&receipt).expect("signature receipt value");
    signature["signature_ed25519_hex"] = serde_json::json!("00".repeat(64));
    let signature = serde_json_canonicalizer::to_vec(&signature).expect("signature receipt wire");
    assert_eq!(
        verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge,
            &run_spec,
            &backend,
            &signature,
            guest_key.to_bytes(),
            &guest_claims,
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::SignatureFailed)
    );
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
