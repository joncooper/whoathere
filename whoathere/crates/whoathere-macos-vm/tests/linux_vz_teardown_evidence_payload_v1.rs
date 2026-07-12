use ed25519_dalek::SigningKey;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_linux_vz_teardown_evidence_from_serial_v1,
    sign_macos_linux_vz_telemetry_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    LinuxVzTelemetryConformanceObservedTerminalV1, MacosLinuxVzTelemetryConformanceChallengeV1,
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};

const PAYLOAD: &str = r#"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"5000000000","deadline_reached":false,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"42","timestamp_ns":"300"}],"evidence_truncated":false,"fixture_case":"normal_exit","fixture_exit_status":"0","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"natural_exit","termination_signal_count":"0"}"#;

fn digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(value)
}

#[test]
fn natural_exit_evidence_maps_exactly_into_challenge_bound_guest_receipt_claims() {
    let serial = format!("prefix\nWHOATHERE_GUEST_TEARDOWN_EVIDENCE {PAYLOAD}\r\n");
    let evidence = decode_linux_vz_teardown_evidence_from_serial_v1(serial.as_bytes())
        .expect("normal-exit teardown evidence");
    let claims = evidence
        .guest_observation_claims_v1()
        .expect("guest receipt claims");
    assert_eq!(claims.evidence_payload_sha256(), evidence.payload_sha256());
    assert_eq!(claims.dropped_event_count(), 0);
    assert!(claims.sensor_healthy());
    assert!(claims.descendant_teardown_complete());
    assert_eq!(
        claims.observed_terminal(),
        LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete
    );

    let seed = [0x71; 32];
    let key = SigningKey::from_bytes(&seed).verifying_key();
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
        "linux-vz-teardown-evidence-bridge-v1",
        "whoathere-linux-inert-teardown-evidence-v1",
        "6.18.35-0-virt",
        digest(b"kernel"),
        digest(b"initramfs"),
        digest(b"root-disk-absent"),
        digest(b"kernel-config"),
        digest(b"kernel-btf"),
        digest(b"guest-runner"),
        digest(b"guest-sensor"),
        digest(b"guest-bpf"),
        digest(b"guest-sensor-config"),
        digest(key.as_bytes()),
        digest(b"host-helper"),
        digest(b"host-packet-sensor"),
        digest(b"host-packet-config"),
        digest(b"host-key"),
        &requirements,
        65534,
        65534,
    )
    .expect("unqualified backend");
    let run_spec = compile_macos_linux_vz_telemetry_conformance_run_spec_v1(
        "linux-vz-normal-exit-run-v1",
        "linux-vz-normal-exit-fixture-v1",
        LinuxVzTelemetryConformanceCaseV1::NormalExit,
        &requirements,
        &backend,
    )
    .expect("normal exit run spec");
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x72; 32],
        &run_spec,
        &backend,
        digest(b"normal exit disposable clone"),
    )
    .expect("challenge");
    let receipt = sign_macos_linux_vz_telemetry_guest_receipt_v1(
        &challenge, &run_spec, &backend, &claims, seed,
    )
    .expect("signed receipt");
    let verified = verify_macos_linux_vz_telemetry_guest_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &receipt,
        key.to_bytes(),
        &claims,
    )
    .expect("verified receipt");
    assert_eq!(verified.claims(), &claims);
    assert!(!verified.package_execution_authority_permitted());
}

#[test]
fn normal_exit_serial_rejects_duplicate_records() {
    let duplicate = format!(
        "WHOATHERE_GUEST_TEARDOWN_EVIDENCE {PAYLOAD}\n\
         WHOATHERE_GUEST_TEARDOWN_EVIDENCE {PAYLOAD}\n"
    );
    assert!(decode_linux_vz_teardown_evidence_from_serial_v1(duplicate.as_bytes()).is_err());
}
