use ed25519_dalek::SigningKey;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1, expected_terminal_for_case_v1,
    qualify_macos_linux_vz_telemetry_backend_v1, sign_macos_linux_vz_telemetry_guest_receipt_v1,
    sign_macos_linux_vz_telemetry_host_receipt_v1,
    verify_macos_linux_vz_telemetry_conformance_case_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_host_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    LinuxVzTelemetryConformanceExpectedTerminalV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, LinuxVzTelemetryHostObservationClaimsV1,
    MacosLinuxVzTelemetryConformanceChallengeV1, MacosLinuxVzTelemetryEvidenceErrorV1,
    MacosLinuxVzTelemetryQualificationErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    VerifiedLinuxVzTelemetryConformanceCaseV1, ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1,
};

const GUEST_SEED: [u8; 32] = [0x61; 32];
const HOST_SEED: [u8; 32] = [0x62; 32];

fn digest(label: impl AsRef<[u8]>) -> Sha256Digest {
    Sha256Digest::from_bytes(label.as_ref())
}

fn build_backend(
    requirements: &ArtifactProtectedTelemetryRequirementsV1,
    kernel_label: &[u8],
) -> UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1 {
    let guest_key = SigningKey::from_bytes(&GUEST_SEED).verifying_key();
    let host_key = SigningKey::from_bytes(&HOST_SEED).verifying_key();
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
        "linux-vz-base-generation-inert-v1",
        "whoathere-linux-inert-v1",
        "6.12.0-whoathere-inert-v1",
        digest(kernel_label),
        digest(b"inert initramfs"),
        digest(b"inert root disk"),
        digest(b"inert kernel config"),
        digest(b"inert kernel btf"),
        digest(b"inert guest runner"),
        digest(b"inert guest sensor"),
        digest(b"inert guest bpf bundle"),
        digest(b"inert guest sensor configuration"),
        Sha256Digest::from_bytes(guest_key.as_bytes()),
        digest(b"inert host helper"),
        digest(b"inert host packet sensor"),
        digest(b"inert host packet configuration"),
        Sha256Digest::from_bytes(host_key.as_bytes()),
        requirements,
        499,
        499,
    )
    .expect("qualification backend")
}

fn observed_terminal(
    expected: LinuxVzTelemetryConformanceExpectedTerminalV1,
) -> LinuxVzTelemetryConformanceObservedTerminalV1 {
    match expected {
        LinuxVzTelemetryConformanceExpectedTerminalV1::ObservationComplete => {
            LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete
        }
        LinuxVzTelemetryConformanceExpectedTerminalV1::IncompleteOnInjectedGap => {
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap
        }
        LinuxVzTelemetryConformanceExpectedTerminalV1::TimeoutWithTeardown => {
            LinuxVzTelemetryConformanceObservedTerminalV1::TimeoutWithTeardown
        }
        LinuxVzTelemetryConformanceExpectedTerminalV1::InfrastructureErrorWithTeardown => {
            LinuxVzTelemetryConformanceObservedTerminalV1::InfrastructureErrorWithTeardown
        }
        LinuxVzTelemetryConformanceExpectedTerminalV1::AccessDeniedWithCompleteEvidence => {
            LinuxVzTelemetryConformanceObservedTerminalV1::AccessDeniedWithCompleteEvidence
        }
    }
}

fn verified_case(
    index: usize,
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    requirements: &ArtifactProtectedTelemetryRequirementsV1,
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    clone_index: usize,
    external_frames_forwarded: u64,
) -> Result<VerifiedLinuxVzTelemetryConformanceCaseV1, MacosLinuxVzTelemetryEvidenceErrorV1> {
    let run_spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        format!("linux-vz-qualification-run-{index}"),
        format!("linux-vz-qualification-evidence-{index}"),
        fixture_case,
        requirements,
        backend,
    )
    .expect("qualification run spec");
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [(index + 1) as u8; 32],
        &run_spec,
        backend,
        digest(format!("qualification clone {clone_index}")),
    )
    .expect("qualification challenge");
    let expected = expected_terminal_for_case_v1(fixture_case);
    let observed = observed_terminal(expected);
    let guest_absent = matches!(
        fixture_case,
        LinuxVzTelemetryConformanceCaseV1::GuestSensorDeath
            | LinuxVzTelemetryConformanceCaseV1::ChannelInterruption
            | LinuxVzTelemetryConformanceCaseV1::VmStop
    );
    let guest_drop = u64::from(matches!(
        fixture_case,
        LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure
            | LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow
    ));
    let host_drop = u64::from(fixture_case == LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow);
    let host_healthy = fixture_case != LinuxVzTelemetryConformanceCaseV1::HostSensorDeath;
    let guest_key = SigningKey::from_bytes(&GUEST_SEED).verifying_key();
    let host_key = SigningKey::from_bytes(&HOST_SEED).verifying_key();

    let verified_guest = if guest_absent {
        None
    } else {
        let claims = LinuxVzTelemetryGuestObservationClaimsV1::new(
            digest(format!("qualification guest payload {index}")),
            2048,
            1,
            32,
            32,
            2,
            guest_drop,
            true,
            false,
            true,
            observed,
        )?;
        let bytes = sign_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge, &run_spec, backend, &claims, GUEST_SEED,
        )?;
        Some(verify_macos_linux_vz_telemetry_guest_receipt_v1(
            &challenge,
            &run_spec,
            backend,
            &bytes,
            guest_key.to_bytes(),
            &claims,
        )?)
    };
    let host_claims = LinuxVzTelemetryHostObservationClaimsV1::new(
        digest(format!("qualification host payload {index}")),
        2048,
        1,
        16,
        16,
        2,
        host_drop,
        host_healthy,
        false,
        true,
        true,
        true,
        true,
        external_frames_forwarded,
        observed,
    )?;
    let host_bytes = sign_macos_linux_vz_telemetry_host_receipt_v1(
        &challenge,
        &run_spec,
        backend,
        &host_claims,
        HOST_SEED,
    )?;
    let verified_host = verify_macos_linux_vz_telemetry_host_receipt_v1(
        &challenge,
        &run_spec,
        backend,
        &host_bytes,
        host_key.to_bytes(),
        &host_claims,
    )?;
    verify_macos_linux_vz_telemetry_conformance_case_v1(
        &challenge,
        &run_spec,
        verified_guest.as_ref(),
        &verified_host,
    )
}

fn complete_matrix(
    requirements: &ArtifactProtectedTelemetryRequirementsV1,
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Vec<VerifiedLinuxVzTelemetryConformanceCaseV1> {
    ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1
        .into_iter()
        .enumerate()
        .map(|(index, fixture_case)| {
            verified_case(index, fixture_case, requirements, backend, index, 0)
                .expect("verified qualification case")
        })
        .collect()
}

#[test]
fn exact_complete_matrix_constructs_distinct_non_authorizing_qualified_backend() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = build_backend(&requirements, b"inert kernel image");
    let matrix = complete_matrix(&requirements, &backend);
    assert_eq!(matrix.len(), 38);
    let qualified = qualify_macos_linux_vz_telemetry_backend_v1(&backend, matrix.clone())
        .expect("qualified backend");
    assert!(qualified.eligible_for_typed_package_execution_authority_request());
    assert!(!qualified.package_execution_authority_permitted());
    assert!(!qualified.sync_back_permitted());
    assert_eq!(
        qualified.backend_identity_sha256(),
        &backend
            .identity_sha256_v1()
            .expect("backend identity digest")
    );
    assert_eq!(
        qualified.telemetry_requirements_sha256(),
        backend.telemetry_requirements_sha256()
    );
    let text =
        String::from_utf8(qualified.canonical_json_v1().to_vec()).expect("qualified backend UTF-8");
    assert!(text.contains("complete_inert_conformance_matrix_verified"));
    assert!(text.contains("\"conformance_case_count\":\"38\""));
    assert!(text.contains("\"execution_authority_issued\":false"));
    assert!(text.contains("\"sync_back_policy\":\"structurally_absent\""));
    assert!(!text.contains("observed_clean"));
    assert!(!text.contains("allow"));
    assert_eq!(
        qualified.qualified_backend_sha256().as_str(),
        "sha256:455c3566f07451d9a763ba594652938aced20bd8f90eb7c712995a8e13e91c1a"
    );

    let mut reversed = matrix;
    reversed.reverse();
    let reversed = qualify_macos_linux_vz_telemetry_backend_v1(&backend, reversed)
        .expect("order-independent qualified backend");
    assert_eq!(reversed, qualified);
}

#[test]
fn qualification_rejects_omissions_duplicates_clone_reuse_mixing_and_external_frames() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = build_backend(&requirements, b"inert kernel image");
    let mut missing = complete_matrix(&requirements, &backend);
    missing.pop();
    assert_eq!(
        qualify_macos_linux_vz_telemetry_backend_v1(&backend, missing),
        Err(MacosLinuxVzTelemetryQualificationErrorV1::IncompleteMatrix)
    );

    let mut duplicate = complete_matrix(&requirements, &backend);
    duplicate[37] = duplicate[0].clone();
    assert_eq!(
        qualify_macos_linux_vz_telemetry_backend_v1(&backend, duplicate),
        Err(MacosLinuxVzTelemetryQualificationErrorV1::DuplicateCase)
    );

    let mut reused = complete_matrix(&requirements, &backend);
    reused[1] = verified_case(
        1,
        ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1[1],
        &requirements,
        &backend,
        0,
        0,
    )
    .expect("clone-reused case");
    assert_eq!(
        qualify_macos_linux_vz_telemetry_backend_v1(&backend, reused),
        Err(MacosLinuxVzTelemetryQualificationErrorV1::CloneReuse)
    );

    let other_backend = build_backend(&requirements, b"other inert kernel image");
    let mut mixed = complete_matrix(&requirements, &backend);
    mixed[37] = verified_case(
        37,
        ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1[37],
        &requirements,
        &other_backend,
        37,
        0,
    )
    .expect("mixed backend case");
    assert_eq!(
        qualify_macos_linux_vz_telemetry_backend_v1(&backend, mixed),
        Err(MacosLinuxVzTelemetryQualificationErrorV1::MixedBackend)
    );

    assert_eq!(
        verified_case(
            0,
            LinuxVzTelemetryConformanceCaseV1::DnsPlaintext,
            &requirements,
            &backend,
            0,
            1,
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::ConformanceFailed)
    );
}
