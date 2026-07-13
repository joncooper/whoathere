use std::{env, fs, path::Path};
use whoathere_macos_vm::{
    decode_linux_vz_process_evidence_from_serial_v1, LinuxVzTelemetryConformanceCaseV1,
};

const MAX_SERIAL_BYTES: u64 = 16 * 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere process evidence inspection failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = env::args().collect::<Vec<_>>();
    if arguments.len() != 2 || !arguments[1].starts_with('/') {
        return Err(
            "usage: whoathere-linux-vz-process-evidence-inspect /absolute/serial.log".into(),
        );
    }
    let path = Path::new(&arguments[1]);
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() == 0
        || metadata.len() > MAX_SERIAL_BYTES
    {
        return Err("serial evidence must be a bounded regular non-symlink file".into());
    }
    let serial = fs::read(path)?;
    let payload = decode_linux_vz_process_evidence_from_serial_v1(&serial)?;
    let claims = if payload.fixture_case() == LinuxVzTelemetryConformanceCaseV1::HostSensorDeath {
        payload.guest_observation_claims_for_terminal_v1(
            whoathere_macos_vm::LinuxVzTelemetryConformanceObservedTerminalV1::InfrastructureErrorWithTeardown,
        )?
    } else {
        payload.guest_observation_claims_v1()?
    };
    let fixture_case = match payload.fixture_case() {
        LinuxVzTelemetryConformanceCaseV1::ForkExecExit => "fork_exec_exit",
        LinuxVzTelemetryConformanceCaseV1::Reparenting => "reparenting",
        LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization => "double_fork_daemonization",
        LinuxVzTelemetryConformanceCaseV1::SetsidEscape => "setsid_escape",
        LinuxVzTelemetryConformanceCaseV1::CredentialChange => "credential_change",
        LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad => "dynamic_library_load",
        LinuxVzTelemetryConformanceCaseV1::HostSensorDeath => "host_sensor_death",
        _ => return Err("unsupported process evidence fixture case".into()),
    };
    let result = serde_json::json!({
        "descendant_teardown_complete": claims.descendant_teardown_complete(),
        "dropped_event_count": payload.dropped_event_count().to_string(),
        "event_count": payload.event_count().to_string(),
        "event_sequence_end": payload.event_sequence_end().to_string(),
        "event_sequence_start": payload.event_sequence_start().to_string(),
        "evidence_byte_length": payload.evidence_byte_length().to_string(),
        "evidence_payload_sha256": payload.payload_sha256(),
        "evidence_truncated": claims.evidence_truncated(),
        "fixture_case": fixture_case,
        "heartbeat_count": payload.heartbeat_count().to_string(),
        "operation": "inspect_only_no_signing",
        "package_execution": false,
        "package_gid": payload.package_gid().to_string(),
        "package_uid": payload.package_uid().to_string(),
        "receipt_signing": false,
        "schema_version": "whoathere.linux_vz_process_evidence_inspection.v1",
        "sensor_healthy": claims.sensor_healthy(),
        "sync_back": false
    });
    let bytes = serde_json_canonicalizer::to_vec(&result)?;
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}
