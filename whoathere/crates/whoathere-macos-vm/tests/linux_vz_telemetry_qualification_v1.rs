use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Cursor;
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_artifact_scenarios_v1, ArtifactProtectedTelemetryRequirementsV1,
    ArtifactRuntimeTargetV1, ArtifactScenarioCompilationRequestV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioIdentitySetV1, ArtifactScenarioPlanV1,
    ArtifactScenarioPolicyV1, NpmRuntimeProfileV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    build_macos_linux_vz_package_authority_request_v1,
    build_macos_linux_vz_package_runtime_qualification_request_v1,
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_and_verify_macos_linux_vz_package_authority_request_v1,
    decode_and_verify_macos_linux_vz_package_runtime_qualification_request_v1,
    decode_macos_linux_vz_package_runtime_qualification_request_v1,
    decode_qualified_macos_linux_vz_telemetry_backend_v1, expected_terminal_for_case_v1,
    qualify_macos_linux_vz_telemetry_backend_v1,
    sign_macos_linux_vz_package_runtime_qualification_guest_receipt_v1,
    sign_macos_linux_vz_telemetry_guest_receipt_v1, sign_macos_linux_vz_telemetry_host_receipt_v1,
    verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_conformance_case_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_host_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    LinuxVzTelemetryConformanceExpectedTerminalV1, LinuxVzTelemetryConformanceObservedTerminalV1,
    LinuxVzTelemetryGuestObservationClaimsV1, LinuxVzTelemetryHostObservationClaimsV1,
    MacosLinuxVzCandidatePackageRuntimeV1, MacosLinuxVzPackageArtifactKindV1,
    MacosLinuxVzPackageAuthorityRequestErrorV1,
    MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
    MacosLinuxVzPackageRuntimeQualificationImageV1,
    MacosLinuxVzPackageRuntimeQualificationRequestErrorV1,
    MacosLinuxVzTelemetryConformanceChallengeV1, MacosLinuxVzTelemetryEvidenceErrorV1,
    MacosLinuxVzTelemetryQualificationErrorV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    VerifiedLinuxVzTelemetryConformanceCaseV1, ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1,
    MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
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
            .expect("append inert npm member");
    }
    archive
        .into_inner()
        .expect("finish inert tar")
        .finish()
        .expect("finish inert gzip")
}

fn linux_npm_plan() -> (ArtifactScenarioPlanV1, Vec<u8>) {
    let bytes = npm_tgz(&[
        (
            "package/package.json",
            br#"{"name":"linux-vz-authority-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#,
        ),
        ("package/post.js", b"process.exit(0)"),
    ]);
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("linux-vz-authority-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:linux-vz-authority-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-13T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "linux-vz-authority-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "repository-inert-linux-vz-authority-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "linux-vz-authority-request.v1".to_string(),
            requires_external_dependency_resolution: false,
        },
        &bytes,
        ArtifactFormat::NpmTarGzip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert npm fixture");
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
    let runtime = NpmRuntimeProfileV1::new_for_target(
        ArtifactRuntimeTargetV1::LinuxArm64,
        "linux-arm64-node22-npm11-inert",
        "22.17.0",
        digest(b"measured Linux node"),
        "11.18.0",
        digest(b"measured Linux npm"),
    )
    .expect("Linux npm runtime");
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        envelope.original_sha256.clone(),
        runtime,
    )
    .expect("Linux npm policy");
    let identities = ArtifactScenarioIdentitySetV1::new(
        "linux-vz-authority-plan",
        ArtifactScenarioExecutionIdentityV1::new(
            "linux-vz-authority-job-false",
            "linux-vz-authority-run-false",
            "linux-vz-authority-evidence-false",
            "linux-vz-authority-scenario-false",
        )
        .expect("false identity"),
        ArtifactScenarioExecutionIdentityV1::new(
            "linux-vz-authority-job-true",
            "linux-vz-authority-run-true",
            "linux-vz-authority-evidence-true",
            "linux-vz-authority-scenario-true",
        )
        .expect("true identity"),
    )
    .expect("identity set");
    let plan = compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &artifact.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })
    .expect("Linux npm plan");
    (plan, bytes)
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
    let decoded = decode_qualified_macos_linux_vz_telemetry_backend_v1(
        qualified.canonical_json_v1(),
        &backend,
    )
    .expect("decoded exact qualified backend");
    assert_eq!(decoded, qualified);
    let mut elevated: serde_json::Value =
        serde_json::from_slice(qualified.canonical_json_v1()).expect("qualified backend value");
    elevated["execution_authority_issued"] = serde_json::json!(true);
    let elevated = serde_json_canonicalizer::to_vec(&elevated).expect("elevated backend");
    assert_eq!(
        decode_qualified_macos_linux_vz_telemetry_backend_v1(&elevated, &backend),
        Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid)
    );

    let mut reversed = matrix;
    reversed.reverse();
    let reversed = qualify_macos_linux_vz_telemetry_backend_v1(&backend, reversed)
        .expect("order-independent qualified backend");
    assert_eq!(reversed, qualified);
}

#[test]
fn qualified_backend_binds_an_exact_linux_npm_request_without_issuing_authority() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = build_backend(&requirements, b"inert kernel image");
    let qualified = qualify_macos_linux_vz_telemetry_backend_v1(
        &backend,
        complete_matrix(&requirements, &backend),
    )
    .expect("qualified backend");
    let (plan, artifact_bytes) = linux_npm_plan();
    let plan_bytes = plan.canonical_json_v1().expect("plan bytes");
    let template_bytes = plan.templates()[0]
        .canonical_json_v1()
        .expect("template bytes");
    let candidate_runtime = MacosLinuxVzCandidatePackageRuntimeV1::from_exact_bytes(
        b"inert candidate Linux runtime rootfs bytes",
        br#"{"schema_version":"whoathere.inert_candidate_runtime_manifest.v1"}"#,
        b"inert candidate package runner bytes",
    )
    .expect("candidate runtime");
    let challenge = [0x91; 32];
    let clone_binding = digest(b"dedicated disposable package clone");
    let request = build_macos_linux_vz_package_authority_request_v1(
        &qualified,
        MacosLinuxVzPackageArtifactKindV1::NpmTarball,
        &artifact_bytes,
        &plan_bytes,
        &template_bytes,
        &candidate_runtime,
        challenge,
        clone_binding.clone(),
    )
    .expect("bound authority request");
    assert!(request.eligible_for_independent_runtime_qualification());
    assert!(!request.package_execution_authority_permitted());
    assert!(!request.sync_back_permitted());
    assert_eq!(
        request.qualified_telemetry_backend_sha256(),
        qualified.qualified_backend_sha256()
    );
    assert_eq!(request.scenario_plan_sha256(), plan.plan_sha256());
    let text = std::str::from_utf8(request.canonical_json_v1()).expect("request UTF-8");
    assert!(text.contains("candidate_exact_bytes_not_yet_independently_qualified"));
    assert!(text.contains("\"execution_authority_issued\":false"));
    assert!(text.contains("\"package_execution_permitted\":false"));
    assert!(text.contains("\"sync_back_policy\":\"structurally_absent\""));
    assert!(!text.contains("capability"));
    assert!(!text.contains("allow"));

    let verified = decode_and_verify_macos_linux_vz_package_authority_request_v1(
        request.canonical_json_v1(),
        &qualified,
        MacosLinuxVzPackageArtifactKindV1::NpmTarball,
        &artifact_bytes,
        &plan_bytes,
        &template_bytes,
        &candidate_runtime,
        challenge,
        clone_binding.clone(),
    )
    .expect("independently verified request");
    assert_eq!(verified.request_sha256(), request.request_sha256());

    assert_eq!(
        build_macos_linux_vz_package_authority_request_v1(
            &qualified,
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact_bytes,
            &plan_bytes,
            &template_bytes,
            &candidate_runtime,
            [0_u8; 32],
            clone_binding.clone(),
        ),
        Err(MacosLinuxVzPackageAuthorityRequestErrorV1::ChallengeInvalid)
    );
    assert_eq!(
        build_macos_linux_vz_package_authority_request_v1(
            &qualified,
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact_bytes,
            &plan_bytes,
            &template_bytes,
            &candidate_runtime,
            challenge,
            Sha256Digest::from_bytes(&challenge),
        ),
        Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CloneBindingInvalid)
    );
    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(request.canonical_json_v1());
    assert_eq!(
        decode_and_verify_macos_linux_vz_package_authority_request_v1(
            &noncanonical,
            &qualified,
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact_bytes,
            &plan_bytes,
            &template_bytes,
            &candidate_runtime,
            challenge,
            clone_binding.clone(),
        ),
        Err(MacosLinuxVzPackageAuthorityRequestErrorV1::NonCanonical)
    );

    let mut changed_artifact = artifact_bytes.clone();
    changed_artifact[0] ^= 0x01;
    assert_eq!(
        build_macos_linux_vz_package_authority_request_v1(
            &qualified,
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &changed_artifact,
            &plan_bytes,
            &template_bytes,
            &candidate_runtime,
            challenge,
            clone_binding.clone(),
        ),
        Err(MacosLinuxVzPackageAuthorityRequestErrorV1::ArtifactInvalid)
    );
    assert_eq!(
        decode_and_verify_macos_linux_vz_package_authority_request_v1(
            request.canonical_json_v1(),
            &qualified,
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact_bytes,
            &plan_bytes,
            &template_bytes,
            &candidate_runtime,
            challenge,
            digest(b"rebound clone"),
        ),
        Err(MacosLinuxVzPackageAuthorityRequestErrorV1::BindingMismatch)
    );
    let mut elevated: serde_json::Value =
        serde_json::from_slice(request.canonical_json_v1()).expect("request value");
    elevated["execution_authority_issued"] = serde_json::json!(true);
    elevated["package_execution_permitted"] = serde_json::json!(true);
    let elevated = serde_json_canonicalizer::to_vec(&elevated).expect("elevated request");
    assert_eq!(
        decode_and_verify_macos_linux_vz_package_authority_request_v1(
            &elevated,
            &qualified,
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            &artifact_bytes,
            &plan_bytes,
            &template_bytes,
            &candidate_runtime,
            challenge,
            clone_binding,
        ),
        Err(MacosLinuxVzPackageAuthorityRequestErrorV1::BindingMismatch)
    );
}

#[test]
fn runtime_qualification_binds_one_fixed_probe_without_issuing_execution_authority() {
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = build_backend(&requirements, b"inert kernel image");
    let qualified = qualify_macos_linux_vz_telemetry_backend_v1(
        &backend,
        complete_matrix(&requirements, &backend),
    )
    .expect("qualified backend");
    let candidate_runtime = MacosLinuxVzCandidatePackageRuntimeV1::from_exact_bytes(
        b"inert qualification candidate rootfs bytes",
        br#"{"schema_version":"whoathere.inert_candidate_runtime_manifest.v1"}"#,
        b"inert qualification package runner bytes",
    )
    .expect("candidate runtime");
    let qualification_image = MacosLinuxVzPackageRuntimeQualificationImageV1::from_exact_bytes(
        b"inert runtime qualification initramfs bytes",
        b"inert runtime qualification guest agent bytes",
        b"inert runtime qualification guest init bytes",
        b"inert runtime qualification module bundle bytes",
    )
    .expect("qualification image");
    let challenge = [0x92; 32];
    let clone_binding = digest(b"unique qualification rootfs clone");
    let request = build_macos_linux_vz_package_runtime_qualification_request_v1(
        &qualified,
        &backend,
        &candidate_runtime,
        &qualification_image,
        challenge,
        clone_binding.clone(),
    )
    .expect("bound runtime qualification request");

    assert!(request.fixed_nonexecuting_probe_permitted());
    assert!(!request.package_execution_authority_permitted());
    assert!(!request.sync_back_permitted());
    assert_eq!(
        request.qualified_telemetry_backend_sha256(),
        qualified.qualified_backend_sha256()
    );
    assert_eq!(
        request.runtime_qualification_initramfs_sha256(),
        qualification_image.initramfs_sha256()
    );
    assert_eq!(
        request.candidate_runtime_rootfs_sha256(),
        candidate_runtime.rootfs_sha256()
    );
    assert_eq!(
        request.expected_probe_report_sha256(),
        &Sha256Digest::from_bytes(MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1)
    );
    let text = std::str::from_utf8(request.canonical_json_v1()).expect("request UTF-8");
    assert!(text.contains("\"operation\":\"fixed_nonexecuting_probe\""));
    assert_eq!(
        request.request_sha256().as_str(),
        "sha256:08cf56cbf44a30bd906efa2fcb72383fe2145a709ffe505cb376f4ddf83d1e0d"
    );
    assert!(text.contains("\"protected_sensor_case\":\"fork_exec_exit\""));
    assert!(text.contains("\"package_runner_argument\":\"fork_exec_exit\""));
    assert!(text.contains("\"nonexecuting_probe_permitted\":true"));
    assert!(text.contains("\"execution_authority_issued\":false"));
    assert!(text.contains("\"package_execution_permitted\":false"));
    assert!(text.contains("\"sync_back_policy\":\"structurally_absent\""));
    assert!(!text.contains("capability"));
    assert!(!text.contains("allow"));

    let structurally_verified =
        decode_macos_linux_vz_package_runtime_qualification_request_v1(request.canonical_json_v1())
            .expect("structurally verified qualification request");
    assert_eq!(
        structurally_verified.backend_identity_sha256(),
        qualified.backend_identity_sha256()
    );
    assert_eq!(
        structurally_verified.qualified_protected_sensor_sha256(),
        backend.guest_bpf_bundle_sha256()
    );
    assert_eq!(
        structurally_verified.runtime_qualification_guest_agent_sha256(),
        qualification_image.guest_agent_sha256()
    );
    assert_eq!(
        structurally_verified.runtime_qualification_guest_init_sha256(),
        qualification_image.guest_init_sha256()
    );
    assert_eq!(
        structurally_verified.runtime_qualification_module_bundle_sha256(),
        qualification_image.module_bundle_sha256()
    );
    assert_eq!(
        structurally_verified.candidate_runtime_rootfs_byte_length(),
        candidate_runtime.rootfs_byte_length()
    );
    assert_eq!(structurally_verified.package_uid(), backend.package_uid());
    assert_eq!(structurally_verified.package_gid(), backend.package_gid());

    let process_evidence = b"inert protected fork exec exit evidence";
    let process_claims = LinuxVzTelemetryGuestObservationClaimsV1::new(
        Sha256Digest::from_bytes(process_evidence),
        process_evidence.len() as u64,
        1,
        3,
        3,
        2,
        0,
        true,
        false,
        true,
        LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete,
    )
    .expect("runtime qualification process claims");
    let qualification_claims = MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1::new(
        &structurally_verified,
        process_claims,
        MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
        candidate_runtime.rootfs_sha256().clone(),
    )
    .expect("runtime qualification guest claims");
    let guest_receipt = sign_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
        &structurally_verified,
        &qualification_claims,
        GUEST_SEED,
    )
    .expect("runtime qualification guest receipt");
    let guest_key = SigningKey::from_bytes(&GUEST_SEED).verifying_key();
    let verified_guest = verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
        &structurally_verified,
        &guest_receipt,
        guest_key.to_bytes(),
        &qualification_claims,
    )
    .expect("verified runtime qualification guest receipt");
    assert_eq!(
        verified_guest.qualification_request_sha256(),
        request.request_sha256()
    );
    assert!(!verified_guest.package_execution_authority_permitted());
    assert!(!verified_guest.sync_back_permitted());
    let receipt_text = std::str::from_utf8(&guest_receipt).expect("guest receipt UTF-8");
    assert!(receipt_text.contains("\"nonexecuting_probe_observed\":true"));
    assert!(receipt_text.contains("\"package_execution\":false"));
    assert!(receipt_text.contains("\"execution_authority_issued\":false"));

    let mut elevated_receipt: serde_json::Value =
        serde_json::from_slice(&guest_receipt).expect("guest receipt value");
    elevated_receipt["package_execution"] = serde_json::json!(true);
    let elevated_receipt =
        serde_json_canonicalizer::to_vec(&elevated_receipt).expect("elevated guest receipt");
    assert_eq!(
        verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
            &structurally_verified,
            &elevated_receipt,
            guest_key.to_bytes(),
            &qualification_claims,
        ),
        Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)
    );

    let verified = decode_and_verify_macos_linux_vz_package_runtime_qualification_request_v1(
        request.canonical_json_v1(),
        &qualified,
        &backend,
        &candidate_runtime,
        &qualification_image,
        challenge,
        clone_binding.clone(),
    )
    .expect("independently verified qualification request");
    assert_eq!(verified.request_sha256(), request.request_sha256());

    assert_eq!(
        build_macos_linux_vz_package_runtime_qualification_request_v1(
            &qualified,
            &backend,
            &candidate_runtime,
            &qualification_image,
            [0_u8; 32],
            clone_binding.clone(),
        ),
        Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::ChallengeInvalid)
    );
    assert_eq!(
        build_macos_linux_vz_package_runtime_qualification_request_v1(
            &qualified,
            &backend,
            &candidate_runtime,
            &qualification_image,
            challenge,
            candidate_runtime.rootfs_sha256().clone(),
        ),
        Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::CloneBindingInvalid)
    );

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(request.canonical_json_v1());
    assert_eq!(
        decode_and_verify_macos_linux_vz_package_runtime_qualification_request_v1(
            &noncanonical,
            &qualified,
            &backend,
            &candidate_runtime,
            &qualification_image,
            challenge,
            clone_binding.clone(),
        ),
        Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::NonCanonical)
    );

    let rebound_runtime = MacosLinuxVzCandidatePackageRuntimeV1::from_exact_bytes(
        b"different inert qualification candidate rootfs bytes",
        br#"{"schema_version":"whoathere.inert_candidate_runtime_manifest.v1"}"#,
        b"inert qualification package runner bytes",
    )
    .expect("rebound candidate runtime");
    assert_eq!(
        decode_and_verify_macos_linux_vz_package_runtime_qualification_request_v1(
            request.canonical_json_v1(),
            &qualified,
            &backend,
            &rebound_runtime,
            &qualification_image,
            challenge,
            clone_binding.clone(),
        ),
        Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::BindingMismatch)
    );

    let mut elevated: serde_json::Value =
        serde_json::from_slice(request.canonical_json_v1()).expect("request value");
    elevated["execution_authority_issued"] = serde_json::json!(true);
    elevated["package_execution_permitted"] = serde_json::json!(true);
    let elevated = serde_json_canonicalizer::to_vec(&elevated).expect("elevated request");
    assert_eq!(
        decode_and_verify_macos_linux_vz_package_runtime_qualification_request_v1(
            &elevated,
            &qualified,
            &backend,
            &candidate_runtime,
            &qualification_image,
            challenge,
            clone_binding,
        ),
        Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::InvalidRequest)
    );
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
