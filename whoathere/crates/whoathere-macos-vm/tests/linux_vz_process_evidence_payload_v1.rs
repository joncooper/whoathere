use ed25519_dalek::SigningKey;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    compile_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_linux_vz_process_evidence_from_serial_v1,
    sign_macos_linux_vz_telemetry_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    LinuxVzTelemetryConformanceObservedTerminalV1, MacosLinuxVzTelemetryConformanceChallengeV1,
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};

const PAYLOAD: &str = r#"{"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"42","timestamp_ns":"300"}],"evidence_truncated":false,"heartbeat_count":"2","package_gid":"65534","package_uid":"65534","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true}"#;

fn digest(value: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(value)
}

#[test]
fn ordered_live_shape_maps_exactly_into_challenge_bound_guest_receipt_claims() {
    let serial = format!("prefix\nWHOATHERE_GUEST_PROCESS_EVIDENCE {PAYLOAD}\r\n");
    let payload = decode_linux_vz_process_evidence_from_serial_v1(serial.as_bytes())
        .expect("ordered process evidence");
    let claims = payload
        .guest_observation_claims_v1()
        .expect("guest receipt claims");
    assert_eq!(claims.evidence_payload_sha256(), payload.payload_sha256());
    assert_eq!(claims.dropped_event_count(), 0);
    assert!(claims.sensor_healthy());
    assert!(!claims.evidence_truncated());
    assert!(claims.descendant_teardown_complete());
    assert_eq!(
        claims.observed_terminal(),
        LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete
    );

    let seed = [0x61; 32];
    let key = SigningKey::from_bytes(&seed).verifying_key();
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend = UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
        "linux-vz-process-evidence-bridge-v1",
        "whoathere-linux-inert-process-evidence-v1",
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
        "linux-vz-process-evidence-run-v1",
        "linux-vz-process-evidence-fixture-v1",
        LinuxVzTelemetryConformanceCaseV1::ForkExecExit,
        &requirements,
        &backend,
    )
    .expect("fork exec exit run spec");
    let challenge = MacosLinuxVzTelemetryConformanceChallengeV1::new(
        [0x62; 32],
        &run_spec,
        &backend,
        digest(b"process evidence disposable clone"),
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
fn ordered_payload_rejects_duplicates_drops_and_lineage_reordering() {
    let duplicate = format!(
        "WHOATHERE_GUEST_PROCESS_EVIDENCE {PAYLOAD}\nWHOATHERE_GUEST_PROCESS_EVIDENCE {PAYLOAD}\n"
    );
    assert!(decode_linux_vz_process_evidence_from_serial_v1(duplicate.as_bytes()).is_err());

    for mutated in [
        PAYLOAD.replace(
            "\"dropped_event_count\":\"0\"",
            "\"dropped_event_count\":\"1\"",
        ),
        PAYLOAD.replace("\"timestamp_ns\":\"200\"", "\"timestamp_ns\":\"99\""),
        PAYLOAD.replacen("\"cgroup_id\":\"9001\"", "\"cgroup_id\":\"9002\"", 1),
    ] {
        let serial = format!("WHOATHERE_GUEST_PROCESS_EVIDENCE {mutated}\n");
        assert!(decode_linux_vz_process_evidence_from_serial_v1(serial.as_bytes()).is_err());
    }
}
