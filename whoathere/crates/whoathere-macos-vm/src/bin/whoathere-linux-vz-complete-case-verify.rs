use serde::Deserialize;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::{
    decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1,
    decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1,
    decode_linux_vz_bpf_program_type_evidence_from_serial_v1,
    decode_linux_vz_cgroup_evidence_from_serial_v1, decode_linux_vz_drop_evidence_from_serial_v1,
    decode_linux_vz_fanotify_overflow_evidence_from_serial_v1,
    decode_linux_vz_file_evidence_from_serial_v1, decode_linux_vz_host_evidence_payload_v1,
    decode_linux_vz_host_frame_overflow_guest_evidence_from_serial_v1,
    decode_linux_vz_host_frame_overflow_host_evidence_payload_v1,
    decode_linux_vz_network_evidence_from_serial_v1,
    decode_linux_vz_network_host_evidence_payload_v1,
    decode_linux_vz_platform_evidence_from_serial_v1,
    decode_linux_vz_process_evidence_from_serial_v1,
    decode_linux_vz_teardown_evidence_from_serial_v1,
    decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1,
    encode_linux_vz_guest_signer_request_v1, encode_linux_vz_guest_signer_response_v1,
    qualify_macos_linux_vz_telemetry_backend_v1,
    verify_macos_linux_vz_telemetry_conformance_case_v1,
    verify_macos_linux_vz_telemetry_guest_receipt_v1,
    verify_macos_linux_vz_telemetry_host_receipt_v1, LinuxVzTelemetryConformanceCaseV1,
    LinuxVzTelemetryConformanceObservedTerminalV1, VerifiedLinuxVzTelemetryConformanceCaseV1,
    ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1, MAX_LINUX_VZ_HOST_EVIDENCE_PAYLOAD_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1,
    MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ complete-case verification failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() == 4
        && arguments[1] == "--qualify"
        && arguments[2..].iter().all(|value| value.starts_with('/'))
    {
        return qualify_matrix(&arguments[2], &arguments[3]);
    }
    let verification = verify_case(&arguments)?;
    println!("{}", verification.summary_json);
    Ok(())
}

struct CompleteCaseVerificationV1 {
    verified_case: VerifiedLinuxVzTelemetryConformanceCaseV1,
    summary_json: String,
}

fn verify_case(
    arguments: &[String],
) -> Result<CompleteCaseVerificationV1, Box<dyn std::error::Error>> {
    if arguments.len() != 10 || arguments[1..].iter().any(|value| !value.starts_with('/')) {
        return Err("usage: complete-case-verify RUN_SPEC CHALLENGE BACKEND GUEST_PUBLIC_KEY HOST_PUBLIC_KEY SERIAL GUEST_RECEIPT HOST_EVIDENCE HOST_RECEIPT".into());
    }
    let run_spec_bytes = read_bounded(
        &arguments[1],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_RUN_SPEC_BYTES_V1 as u64,
    )?;
    let challenge_bytes = read_bounded(
        &arguments[2],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
    )?;
    let backend_bytes = read_bounded(
        &arguments[3],
        MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1 as u64,
    )?;
    let guest_public_key = exact_key(&arguments[4])?;
    let host_public_key = exact_key(&arguments[5])?;
    let serial = read_bounded(&arguments[6], 1024 * 1024)?;
    let host_evidence = read_bounded(
        &arguments[8],
        MAX_LINUX_VZ_HOST_EVIDENCE_PAYLOAD_BYTES_V1 as u64,
    )?;
    let host_receipt = read_bounded(
        &arguments[9],
        MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
    )?;
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let run_spec =
        decode_and_validate_macos_linux_vz_telemetry_conformance_run_spec_v1(&run_spec_bytes)?;
    let channel_interruption =
        run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::ChannelInterruption;
    let vm_stop = run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::VmStop;
    let guest_sensor_death =
        run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::GuestSensorDeath;
    let host_only = channel_interruption || vm_stop || guest_sensor_death;
    let guest_receipt = if host_only {
        require_absent(&arguments[7])?;
        None
    } else {
        Some(read_bounded(
            &arguments[7],
            MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 as u64,
        )?)
    };
    let fixture_case = match run_spec.fixture_case() {
        LinuxVzTelemetryConformanceCaseV1::KernelConfigAndBtf => "kernel_config_and_btf",
        LinuxVzTelemetryConformanceCaseV1::CgroupV2 => "cgroup_v2",
        LinuxVzTelemetryConformanceCaseV1::FanotifyPermission => "fanotify_permission",
        LinuxVzTelemetryConformanceCaseV1::BpfProgramTypes => "bpf_program_types",
        LinuxVzTelemetryConformanceCaseV1::RawFrameAttachment => "raw_frame_attachment",
        LinuxVzTelemetryConformanceCaseV1::ForkExecExit => "fork_exec_exit",
        LinuxVzTelemetryConformanceCaseV1::Reparenting => "reparenting",
        LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization => "double_fork_daemonization",
        LinuxVzTelemetryConformanceCaseV1::SetsidEscape => "setsid_escape",
        LinuxVzTelemetryConformanceCaseV1::CredentialChange => "credential_change",
        LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad => "dynamic_library_load",
        LinuxVzTelemetryConformanceCaseV1::Ipv4Connect => "ipv4_connect",
        LinuxVzTelemetryConformanceCaseV1::Ipv6Connect => "ipv6_connect",
        LinuxVzTelemetryConformanceCaseV1::UdpSend => "udp_send",
        LinuxVzTelemetryConformanceCaseV1::LoopbackConnect => "loopback_connect",
        LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect => "private_address_connect",
        LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect => "link_local_connect",
        LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect => "metadata_address_connect",
        LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect => "public_address_connect",
        LinuxVzTelemetryConformanceCaseV1::DnsPlaintext => "dns_plaintext",
        LinuxVzTelemetryConformanceCaseV1::DnsMalformed => "dns_malformed",
        LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect => "encrypted_dns_connect",
        LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete => {
            "protected_open_read_write_rename_delete"
        }
        LinuxVzTelemetryConformanceCaseV1::MmapAccess => "mmap_access",
        LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure => "bpf_reservation_failure",
        LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow => "fanotify_queue_overflow",
        LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow => "host_frame_overflow",
        LinuxVzTelemetryConformanceCaseV1::NormalExit => "normal_exit",
        LinuxVzTelemetryConformanceCaseV1::Timeout => "timeout",
        LinuxVzTelemetryConformanceCaseV1::TermResistance => "term_resistance",
        LinuxVzTelemetryConformanceCaseV1::EscapedSession => "escaped_session",
        LinuxVzTelemetryConformanceCaseV1::ReparentedChild => "reparented_child",
        LinuxVzTelemetryConformanceCaseV1::BackgroundListener => "background_listener",
        LinuxVzTelemetryConformanceCaseV1::ChannelInterruption => "channel_interruption",
        LinuxVzTelemetryConformanceCaseV1::VmStop => "vm_stop",
        LinuxVzTelemetryConformanceCaseV1::GuestSensorDeath => "guest_sensor_death",
        LinuxVzTelemetryConformanceCaseV1::HostSensorDeath => "host_sensor_death",
        LinuxVzTelemetryConformanceCaseV1::AllProtectedAssetsDenied => {
            "all_protected_assets_denied"
        }
    };
    let backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &backend_bytes,
        &requirements,
    )?;
    let challenge = decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
        &challenge_bytes,
        &run_spec,
        &backend,
    )?;
    let guest_observation = if host_only {
        if channel_interruption {
            validate_channel_interruption_serial(&serial)?;
        } else if vm_stop {
            validate_vm_stop_serial(&serial)?;
        } else {
            validate_guest_sensor_death_serial(&serial)?;
        }
        None
    } else {
        Some(match run_spec.fixture_case() {
            LinuxVzTelemetryConformanceCaseV1::KernelConfigAndBtf => {
                let evidence = decode_linux_vz_platform_evidence_from_serial_v1(&serial, &backend)?;
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    None,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::CgroupV2 => {
                let evidence = decode_linux_vz_cgroup_evidence_from_serial_v1(&serial, &backend)?;
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    None,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::BpfProgramTypes => {
                let evidence = decode_linux_vz_bpf_program_type_evidence_from_serial_v1(&serial)?;
                if evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest BPF program-type evidence binding mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    None,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::ForkExecExit
            | LinuxVzTelemetryConformanceCaseV1::HostSensorDeath
            | LinuxVzTelemetryConformanceCaseV1::AllProtectedAssetsDenied
            | LinuxVzTelemetryConformanceCaseV1::Reparenting
            | LinuxVzTelemetryConformanceCaseV1::DoubleForkDaemonization
            | LinuxVzTelemetryConformanceCaseV1::SetsidEscape
            | LinuxVzTelemetryConformanceCaseV1::CredentialChange
            | LinuxVzTelemetryConformanceCaseV1::DynamicLibraryLoad => {
                let evidence = decode_linux_vz_process_evidence_from_serial_v1(&serial)?;
                if evidence.fixture_case() != run_spec.fixture_case()
                    || evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest evidence package identity mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    match run_spec.fixture_case() {
                        LinuxVzTelemetryConformanceCaseV1::HostSensorDeath => evidence
                            .guest_observation_claims_for_terminal_v1(
                                LinuxVzTelemetryConformanceObservedTerminalV1::InfrastructureErrorWithTeardown,
                            )?,
                        LinuxVzTelemetryConformanceCaseV1::AllProtectedAssetsDenied => evidence
                            .guest_observation_claims_for_terminal_v1(
                                LinuxVzTelemetryConformanceObservedTerminalV1::AccessDeniedWithCompleteEvidence,
                            )?,
                        _ => evidence.guest_observation_claims_v1()?,
                    },
                    None,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::FanotifyPermission
            | LinuxVzTelemetryConformanceCaseV1::ProtectedOpenReadWriteRenameDelete
            | LinuxVzTelemetryConformanceCaseV1::MmapAccess => {
                let evidence = decode_linux_vz_file_evidence_from_serial_v1(&serial)?;
                if evidence.fixture_case() != run_spec.fixture_case()
                    || evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest file evidence binding mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    None,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::Ipv4Connect
            | LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
            | LinuxVzTelemetryConformanceCaseV1::UdpSend
            | LinuxVzTelemetryConformanceCaseV1::RawFrameAttachment
            | LinuxVzTelemetryConformanceCaseV1::LoopbackConnect
            | LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect
            | LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
            | LinuxVzTelemetryConformanceCaseV1::DnsMalformed
            | LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect => {
                let evidence = decode_linux_vz_network_evidence_from_serial_v1(&serial)?;
                if evidence.fixture_case() != run_spec.fixture_case()
                    || evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest network evidence binding mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    Some(evidence.source_port()),
                )
            }
            LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure => {
                let evidence = decode_linux_vz_drop_evidence_from_serial_v1(&serial)?;
                if evidence.fixture_case() != run_spec.fixture_case()
                    || evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest drop evidence binding mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    None,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow => {
                let evidence = decode_linux_vz_fanotify_overflow_evidence_from_serial_v1(&serial)?;
                if evidence.fixture_case() != run_spec.fixture_case()
                    || evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest fanotify overflow evidence binding mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    None,
                )
            }
            LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow => {
                let evidence =
                    decode_linux_vz_host_frame_overflow_guest_evidence_from_serial_v1(&serial)?;
                if evidence.fixture_case() != run_spec.fixture_case()
                    || evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest host-frame-overflow evidence binding mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    Some(evidence.source_port()),
                )
            }
            LinuxVzTelemetryConformanceCaseV1::NormalExit
            | LinuxVzTelemetryConformanceCaseV1::Timeout
            | LinuxVzTelemetryConformanceCaseV1::TermResistance
            | LinuxVzTelemetryConformanceCaseV1::EscapedSession
            | LinuxVzTelemetryConformanceCaseV1::ReparentedChild
            | LinuxVzTelemetryConformanceCaseV1::BackgroundListener => {
                let evidence = decode_linux_vz_teardown_evidence_from_serial_v1(&serial)?;
                if evidence.fixture_case() != run_spec.fixture_case()
                    || evidence.package_uid() != backend.package_uid()
                    || evidence.package_gid() != backend.package_gid()
                {
                    return Err("guest teardown evidence binding mismatch".into());
                }
                (
                    evidence.payload_sha256().clone(),
                    evidence.guest_observation_claims_v1()?,
                    None,
                )
            }
            _ => return Err("complete-case verifier does not implement this inert case".into()),
        })
    };
    let verified_guest = match (&guest_observation, guest_receipt.as_deref()) {
        (Some((_, claims, _)), Some(receipt)) => {
            Some(verify_macos_linux_vz_telemetry_guest_receipt_v1(
                &challenge,
                &run_spec,
                &backend,
                receipt,
                guest_public_key,
                claims,
            )?)
        }
        (None, None) => None,
        _ => return Err("guest receipt presence does not match fixture contract".into()),
    };
    let guest_source_port = guest_observation
        .as_ref()
        .and_then(|(_, _, source_port)| *source_port);
    let (host_evidence_payload_sha256, host_claims) = if run_spec.fixture_case()
        == LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow
    {
        let evidence =
            decode_linux_vz_host_frame_overflow_host_evidence_payload_v1(&host_evidence)?;
        if Some(evidence.source_port()) != guest_source_port {
            return Err("guest and host overflow source port mismatch".into());
        }
        (
            evidence.payload_sha256().clone(),
            evidence.host_observation_claims_v1()?,
        )
    } else if matches!(
        run_spec.fixture_case(),
        LinuxVzTelemetryConformanceCaseV1::Ipv4Connect
            | LinuxVzTelemetryConformanceCaseV1::Ipv6Connect
            | LinuxVzTelemetryConformanceCaseV1::UdpSend
            | LinuxVzTelemetryConformanceCaseV1::RawFrameAttachment
            | LinuxVzTelemetryConformanceCaseV1::PrivateAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::LinkLocalConnect
            | LinuxVzTelemetryConformanceCaseV1::MetadataAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::PublicAddressConnect
            | LinuxVzTelemetryConformanceCaseV1::DnsPlaintext
            | LinuxVzTelemetryConformanceCaseV1::DnsMalformed
            | LinuxVzTelemetryConformanceCaseV1::EncryptedDnsConnect
    ) {
        let evidence = decode_linux_vz_network_host_evidence_payload_v1(&host_evidence)?;
        if evidence.fixture_case() != run_spec.fixture_case()
            || Some(evidence.source_port()) != guest_source_port
        {
            return Err("guest and host network source port mismatch".into());
        }
        (
            evidence.payload_sha256().clone(),
            evidence.host_observation_claims_v1()?,
        )
    } else {
        let evidence = decode_linux_vz_host_evidence_payload_v1(&host_evidence)?;
        if channel_interruption {
            let interruption = evidence
                .channel_interruption()
                .ok_or("channel interruption evidence is absent")?;
            let expected_request_bytes =
                encode_linux_vz_guest_signer_request_v1(&run_spec_bytes, &challenge_bytes)?.len()
                    as u64;
            if interruption.request_frame_bytes() != expected_request_bytes
                || interruption.transmitted_prefix_bytes() != 16
                || interruption.response_bytes() != 0
            {
                return Err("channel interruption evidence is rebound".into());
            }
        } else if vm_stop {
            let stop = evidence.vm_stop().ok_or("VM-stop evidence is absent")?;
            let expected_request_bytes =
                encode_linux_vz_guest_signer_request_v1(&run_spec_bytes, &challenge_bytes)?.len()
                    as u64;
            if stop.request_frame_bytes() != expected_request_bytes
                || stop.transmitted_request_bytes() != expected_request_bytes
                || stop.response_bytes() != 0
                || !stop.fixture_active_marker_observed()
            {
                return Err("VM-stop evidence is rebound".into());
            }
        } else if guest_sensor_death {
            let death = evidence
                .guest_sensor_death()
                .ok_or("guest-sensor-death evidence is absent")?;
            let expected_request_bytes =
                encode_linux_vz_guest_signer_request_v1(&run_spec_bytes, &challenge_bytes)?.len()
                    as u64;
            if death.request_frame_bytes() != expected_request_bytes
                || death.transmitted_request_bytes() != expected_request_bytes
                || death.response_bytes() != 0
                || !death.fixture_active_marker_observed()
                || death.signal() != 9
            {
                return Err("guest-sensor-death evidence is rebound".into());
            }
        } else if run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::HostSensorDeath {
            let death = evidence
                .host_sensor_death()
                .ok_or("host-sensor-death evidence is absent")?;
            let expected_request_bytes =
                encode_linux_vz_guest_signer_request_v1(&run_spec_bytes, &challenge_bytes)?.len()
                    as u64;
            let expected_response_bytes = encode_linux_vz_guest_signer_response_v1(
                guest_receipt
                    .as_deref()
                    .ok_or("host-sensor-death guest receipt is absent")?,
            )?
            .len() as u64;
            if death.request_frame_bytes() != expected_request_bytes
                || death.transmitted_request_bytes() != expected_request_bytes
                || death.response_bytes() != expected_response_bytes
                || !death.worker_started()
                || !death.injected()
                || !death.worker_terminated()
            {
                return Err("host-sensor-death evidence is rebound".into());
            }
        } else if evidence.channel_interruption().is_some()
            || evidence.vm_stop().is_some()
            || evidence.guest_sensor_death().is_some()
            || evidence.host_sensor_death().is_some()
        {
            return Err("unexpected host-fault evidence".into());
        }
        if channel_interruption
            && (evidence.vm_stop().is_some()
                || evidence.guest_sensor_death().is_some()
                || evidence.host_sensor_death().is_some())
        {
            return Err("unexpected non-channel host-fault evidence".into());
        }
        if vm_stop
            && (evidence.channel_interruption().is_some()
                || evidence.guest_sensor_death().is_some()
                || evidence.host_sensor_death().is_some())
        {
            return Err("unexpected non-VM-stop host-fault evidence".into());
        }
        if guest_sensor_death
            && (evidence.channel_interruption().is_some()
                || evidence.vm_stop().is_some()
                || evidence.host_sensor_death().is_some())
        {
            return Err("unexpected non-guest-sensor-death host-fault evidence".into());
        }
        if run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::HostSensorDeath
            && (evidence.channel_interruption().is_some()
                || evidence.vm_stop().is_some()
                || evidence.guest_sensor_death().is_some())
        {
            return Err("unexpected non-host-sensor-death host-fault evidence".into());
        }
        let terminal = if matches!(
            run_spec.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::BpfReservationFailure
                | LinuxVzTelemetryConformanceCaseV1::FanotifyQueueOverflow
                | LinuxVzTelemetryConformanceCaseV1::HostFrameOverflow
        ) {
            LinuxVzTelemetryConformanceObservedTerminalV1::IncompleteOnInjectedGap
        } else if matches!(
            run_spec.fixture_case(),
            LinuxVzTelemetryConformanceCaseV1::Timeout
                | LinuxVzTelemetryConformanceCaseV1::TermResistance
                | LinuxVzTelemetryConformanceCaseV1::EscapedSession
                | LinuxVzTelemetryConformanceCaseV1::ReparentedChild
                | LinuxVzTelemetryConformanceCaseV1::BackgroundListener
        ) {
            LinuxVzTelemetryConformanceObservedTerminalV1::TimeoutWithTeardown
        } else if host_only
            || run_spec.fixture_case() == LinuxVzTelemetryConformanceCaseV1::HostSensorDeath
        {
            LinuxVzTelemetryConformanceObservedTerminalV1::InfrastructureErrorWithTeardown
        } else if run_spec.fixture_case()
            == LinuxVzTelemetryConformanceCaseV1::AllProtectedAssetsDenied
        {
            LinuxVzTelemetryConformanceObservedTerminalV1::AccessDeniedWithCompleteEvidence
        } else {
            LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete
        };
        (
            evidence.payload_sha256().clone(),
            evidence.host_observation_claims_for_terminal_v1(terminal)?,
        )
    };
    let verified_host = verify_macos_linux_vz_telemetry_host_receipt_v1(
        &challenge,
        &run_spec,
        &backend,
        &host_receipt,
        host_public_key,
        &host_claims,
    )?;
    let verified_case = verify_macos_linux_vz_telemetry_conformance_case_v1(
        &challenge,
        &run_spec,
        verified_guest.as_ref(),
        &verified_host,
    )?;
    if verified_case.package_execution_authority_permitted()
        || verified_case.guest_receipt_present() == host_only
    {
        return Err("complete case unexpectedly grants execution authority".into());
    }
    let summary_json = if host_only {
        format!(
            "{{\"backend_identity_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"complete_conformance_case_verified\":true,\"execution_authority\":false,\"fixture_case\":\"{}\",\"guest_receipt_present\":false,\"host_evidence_payload_sha256\":\"{}\",\"host_receipt_sha256\":\"{}\",\"package_execution\":false,\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_complete_case_verification.v1\",\"sync_back\":false}}",
            backend.identity_sha256_v1()?,
            challenge.challenge_sha256(),
            fixture_case,
            host_evidence_payload_sha256,
            Sha256Digest::from_bytes(&host_receipt),
            run_spec.run_spec_sha256(),
        )
    } else {
        let (guest_evidence_payload_sha256, _, _) = guest_observation
            .as_ref()
            .ok_or("guest observation unexpectedly absent")?;
        let guest_receipt = guest_receipt
            .as_deref()
            .ok_or("guest receipt unexpectedly absent")?;
        format!(
            "{{\"backend_identity_sha256\":\"{}\",\"challenge_sha256\":\"{}\",\"complete_conformance_case_verified\":true,\"execution_authority\":false,\"fixture_case\":\"{}\",\"guest_evidence_payload_sha256\":\"{}\",\"guest_receipt_sha256\":\"{}\",\"host_evidence_payload_sha256\":\"{}\",\"host_receipt_sha256\":\"{}\",\"package_execution\":false,\"run_spec_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_complete_case_verification.v1\",\"sync_back\":false}}",
            backend.identity_sha256_v1()?,
            challenge.challenge_sha256(),
            fixture_case,
            guest_evidence_payload_sha256,
            Sha256Digest::from_bytes(guest_receipt),
            host_evidence_payload_sha256,
            Sha256Digest::from_bytes(&host_receipt),
            run_spec.run_spec_sha256(),
        )
    };
    Ok(CompleteCaseVerificationV1 {
        verified_case,
        summary_json,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationManifestV1 {
    schema_version: String,
    backend_identity: String,
    guest_public_key: String,
    host_public_key: String,
    cases: Vec<QualificationCaseInputsV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct QualificationCaseInputsV1 {
    run_spec: String,
    challenge: String,
    serial: String,
    guest_receipt: String,
    host_evidence: String,
    host_receipt: String,
}

fn qualify_matrix(
    manifest_path: &str,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let manifest_bytes = read_bounded(manifest_path, 1024 * 1024)?;
    let manifest: QualificationManifestV1 = serde_json::from_slice(&manifest_bytes)?;
    let canonical_manifest = serde_json_canonicalizer::to_vec(&serde_json::from_slice::<
        serde_json::Value,
    >(&manifest_bytes)?)?;
    let mut canonical_manifest_with_newline = canonical_manifest.clone();
    canonical_manifest_with_newline.push(b'\n');
    if manifest_bytes != canonical_manifest && manifest_bytes != canonical_manifest_with_newline {
        return Err("qualification manifest must be canonical JSON".into());
    }
    if manifest.schema_version != "whoathere.linux_vz_qualification_inputs.v1"
        || manifest.cases.len() != ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1.len()
        || !manifest.backend_identity.starts_with('/')
        || !manifest.guest_public_key.starts_with('/')
        || !manifest.host_public_key.starts_with('/')
        || manifest.cases.iter().any(|case| {
            [
                &case.run_spec,
                &case.challenge,
                &case.serial,
                &case.guest_receipt,
                &case.host_evidence,
                &case.host_receipt,
            ]
            .into_iter()
            .any(|path| !path.starts_with('/'))
        })
    {
        return Err("qualification manifest is not an exact 38-case absolute-path contract".into());
    }
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let backend_bytes = read_bounded(
        &manifest.backend_identity,
        MAX_MACOS_LINUX_VZ_TELEMETRY_BACKEND_IDENTITY_BYTES_V1 as u64,
    )?;
    let backend = decode_unqualified_macos_linux_vz_telemetry_backend_identity_v1(
        &backend_bytes,
        &requirements,
    )?;
    let mut verified_cases = Vec::with_capacity(manifest.cases.len());
    for case in manifest.cases {
        let arguments = vec![
            "whoathere-linux-vz-complete-case-verify".to_string(),
            case.run_spec,
            case.challenge,
            manifest.backend_identity.clone(),
            manifest.guest_public_key.clone(),
            manifest.host_public_key.clone(),
            case.serial,
            case.guest_receipt,
            case.host_evidence,
            case.host_receipt,
        ];
        verified_cases.push(verify_case(&arguments)?.verified_case);
    }
    let qualified = qualify_macos_linux_vz_telemetry_backend_v1(&backend, verified_cases)?;
    if qualified.package_execution_authority_permitted() || qualified.sync_back_permitted() {
        return Err(
            "qualified backend unexpectedly grants execution or sync-back authority".into(),
        );
    }
    write_new_private_file(output_path, qualified.canonical_json_v1())?;
    println!(
        "{{\"backend_identity_sha256\":\"{}\",\"conformance_case_count\":\"{}\",\"conformance_evidence_set_sha256\":\"{}\",\"execution_authority\":false,\"package_execution\":false,\"qualified_backend_sha256\":\"{}\",\"schema_version\":\"whoathere.linux_vz_telemetry_qualification_build_result.v1\",\"status\":\"qualified\",\"sync_back\":false}}",
        qualified.backend_identity_sha256(),
        ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1.len(),
        qualified.conformance_evidence_set_sha256(),
        qualified.qualified_backend_sha256(),
    );
    Ok(())
}

fn write_new_private_file(path: &str, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(value)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != value.len() as u64
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err("qualified backend output verification failed".into());
    }
    Ok(())
}

fn validate_channel_interruption_serial(serial: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let lines = serial
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect::<Vec<_>>();
    let required: &[&[u8]] = &[
        b"WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN",
        b"WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
        b"WHOATHERE_CAPABILITY architecture=aarch64",
        b"WHOATHERE_CAPABILITY kernel_btf=present",
        b"WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb",
        b"WHOATHERE_CAPABILITY cgroup_v2=mounted",
        b"WHOATHERE_CAPABILITY bpf_fs=mounted",
        b"WHOATHERE_CAPABILITY fanotify_init=available",
        b"WHOATHERE_CAPABILITY bpf_program_load=available",
        b"WHOATHERE_CAPABILITY syscall_probe=passed",
        b"WHOATHERE_CAPABILITY virtio_vsock=loaded",
        b"WHOATHERE_CAPABILITY virtio_net=loaded",
        b"WHOATHERE_GUEST_SIGNER_READY port=40551",
        b"WHOATHERE_GUEST_SIGNER_FAILED reason=linux_vz_guest_signer_transport_length_invalid",
        b"WHOATHERE_CAPABILITY guest_receipt_signing=failed",
        b"WHOATHERE_CAPABILITY external_route_configured=false",
        b"WHOATHERE_CAPABILITY package_execution=false",
        b"WHOATHERE_CAPABILITY sync_back=false",
        b"WHOATHERE_LINUX_VZ_SIGNED_INERT_FAILED",
    ];
    if required
        .iter()
        .any(|required_line| !lines.iter().any(|line| line == required_line))
        || lines.iter().any(|line| {
            *line == b"WHOATHERE_CAPABILITY guest_receipt_signing=passed"
                || *line == b"WHOATHERE_LINUX_VZ_SIGNED_INERT_OK"
                || line.starts_with(b"WHOATHERE_SENSOR")
                || line.starts_with(b"WHOATHERE_GUEST_PROCESS_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_FILE_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_NETWORK_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_TEARDOWN_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_SIGNER_RECEIPT_OK ")
        })
    {
        return Err("channel interruption serial evidence is incomplete or contradictory".into());
    }
    Ok(())
}

fn validate_vm_stop_serial(serial: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let lines = serial
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect::<Vec<_>>();
    let required: &[&[u8]] = &[
        b"WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN",
        b"WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
        b"WHOATHERE_CAPABILITY architecture=aarch64",
        b"WHOATHERE_CAPABILITY kernel_btf=present",
        b"WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb",
        b"WHOATHERE_CAPABILITY cgroup_v2=mounted",
        b"WHOATHERE_CAPABILITY bpf_fs=mounted",
        b"WHOATHERE_CAPABILITY fanotify_init=available",
        b"WHOATHERE_CAPABILITY bpf_program_load=available",
        b"WHOATHERE_CAPABILITY syscall_probe=passed",
        b"WHOATHERE_CAPABILITY virtio_vsock=loaded",
        b"WHOATHERE_CAPABILITY virtio_net=loaded",
        b"WHOATHERE_GUEST_SIGNER_READY port=40551",
        b"WHOATHERE_SENSOR vm_stop_fixture=active",
    ];
    if required
        .iter()
        .any(|required_line| !lines.iter().any(|line| line == required_line))
        || lines.iter().any(|line| {
            *line == b"WHOATHERE_CAPABILITY guest_receipt_signing=passed"
                || *line == b"WHOATHERE_LINUX_VZ_SIGNED_INERT_OK"
                || *line == b"WHOATHERE_LINUX_VZ_SIGNED_INERT_FAILED"
                || (line.starts_with(b"WHOATHERE_SENSOR ")
                    && *line != b"WHOATHERE_SENSOR vm_stop_fixture=active")
                || line.starts_with(b"WHOATHERE_SENSOR_PROCESS_PROBE_")
                || line.starts_with(b"WHOATHERE_GUEST_PROCESS_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_FILE_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_NETWORK_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_TEARDOWN_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_SIGNER_RECEIPT_OK ")
                || line.starts_with(b"WHOATHERE_GUEST_SIGNER_FAILED ")
        })
    {
        return Err("VM-stop serial evidence is incomplete or contradictory".into());
    }
    Ok(())
}

fn validate_guest_sensor_death_serial(serial: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let lines = serial
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .collect::<Vec<_>>();
    let required: &[&[u8]] = &[
        b"WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN",
        b"WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
        b"WHOATHERE_CAPABILITY architecture=aarch64",
        b"WHOATHERE_CAPABILITY kernel_btf=present",
        b"WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb",
        b"WHOATHERE_CAPABILITY cgroup_v2=mounted",
        b"WHOATHERE_CAPABILITY bpf_fs=mounted",
        b"WHOATHERE_CAPABILITY fanotify_init=available",
        b"WHOATHERE_CAPABILITY bpf_program_load=available",
        b"WHOATHERE_CAPABILITY syscall_probe=passed",
        b"WHOATHERE_CAPABILITY virtio_vsock=loaded",
        b"WHOATHERE_CAPABILITY virtio_net=loaded",
        b"WHOATHERE_GUEST_SIGNER_READY port=40551",
        b"WHOATHERE_SENSOR guest_sensor_death_fixture=active",
        b"WHOATHERE_GUEST_SENSOR_DEATH observed_signal=9",
        b"WHOATHERE_GUEST_SIGNER_FAILED reason=guest_sensor_death_injected",
        b"WHOATHERE_CAPABILITY guest_receipt_signing=failed",
        b"WHOATHERE_CAPABILITY external_route_configured=false",
        b"WHOATHERE_CAPABILITY package_execution=false",
        b"WHOATHERE_CAPABILITY sync_back=false",
        b"WHOATHERE_LINUX_VZ_SIGNED_INERT_FAILED",
    ];
    if required
        .iter()
        .any(|required_line| !lines.iter().any(|line| line == required_line))
        || lines.iter().any(|line| {
            *line == b"WHOATHERE_CAPABILITY guest_receipt_signing=passed"
                || *line == b"WHOATHERE_LINUX_VZ_SIGNED_INERT_OK"
                || (line.starts_with(b"WHOATHERE_SENSOR ")
                    && *line != b"WHOATHERE_SENSOR guest_sensor_death_fixture=active")
                || line.starts_with(b"WHOATHERE_SENSOR_PROCESS_PROBE_")
                || line.starts_with(b"WHOATHERE_GUEST_PROCESS_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_FILE_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_NETWORK_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_TEARDOWN_EVIDENCE ")
                || line.starts_with(b"WHOATHERE_GUEST_SIGNER_RECEIPT_OK ")
        })
    {
        return Err("guest-sensor-death serial evidence is incomplete or contradictory".into());
    }
    Ok(())
}

fn require_absent(path: &str) -> Result<(), Box<dyn std::error::Error>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("guest receipt path must be absent for this fixture".into()),
    }
}

fn exact_key(path: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    read_bounded(path, 32)?
        .try_into()
        .map_err(|_| "evidence public key must be exactly 32 bytes".into())
}

fn read_bounded(path: &str, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("input is not a bounded regular non-symlink file".into());
    }
    let mut value = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut value)?;
    if value.is_empty() || value.len() as u64 > maximum {
        return Err("input is not a bounded regular non-symlink file".into());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::{
        validate_channel_interruption_serial, validate_guest_sensor_death_serial,
        validate_vm_stop_serial,
    };

    const CHANNEL_SERIAL: &str = "WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN\n\
WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt\n\
WHOATHERE_CAPABILITY architecture=aarch64\n\
WHOATHERE_CAPABILITY kernel_btf=present\n\
WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb\n\
WHOATHERE_CAPABILITY cgroup_v2=mounted\n\
WHOATHERE_CAPABILITY bpf_fs=mounted\n\
WHOATHERE_CAPABILITY fanotify_init=available\n\
WHOATHERE_CAPABILITY bpf_program_load=available\n\
WHOATHERE_CAPABILITY syscall_probe=passed\n\
WHOATHERE_CAPABILITY virtio_vsock=loaded\n\
WHOATHERE_CAPABILITY virtio_net=loaded\n\
WHOATHERE_GUEST_SIGNER_READY port=40551\n\
WHOATHERE_GUEST_SIGNER_FAILED reason=linux_vz_guest_signer_transport_length_invalid\n\
WHOATHERE_CAPABILITY guest_receipt_signing=failed\n\
WHOATHERE_CAPABILITY external_route_configured=false\n\
WHOATHERE_CAPABILITY package_execution=false\n\
WHOATHERE_CAPABILITY sync_back=false\n\
WHOATHERE_LINUX_VZ_SIGNED_INERT_FAILED\n";

    const VM_STOP_SERIAL: &str = "WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN\n\
WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt\n\
WHOATHERE_CAPABILITY architecture=aarch64\n\
WHOATHERE_CAPABILITY kernel_btf=present\n\
WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb\n\
WHOATHERE_CAPABILITY cgroup_v2=mounted\n\
WHOATHERE_CAPABILITY bpf_fs=mounted\n\
WHOATHERE_CAPABILITY fanotify_init=available\n\
WHOATHERE_CAPABILITY bpf_program_load=available\n\
WHOATHERE_CAPABILITY syscall_probe=passed\n\
WHOATHERE_CAPABILITY virtio_vsock=loaded\n\
WHOATHERE_CAPABILITY virtio_net=loaded\n\
WHOATHERE_GUEST_SIGNER_READY port=40551\n\
WHOATHERE_SENSOR vm_stop_fixture=active\n";

    const GUEST_SENSOR_DEATH_SERIAL: &str = "WHOATHERE_LINUX_VZ_SIGNED_INERT_BEGIN\n\
WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt\n\
WHOATHERE_CAPABILITY architecture=aarch64\n\
WHOATHERE_CAPABILITY kernel_btf=present\n\
WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb\n\
WHOATHERE_CAPABILITY cgroup_v2=mounted\n\
WHOATHERE_CAPABILITY bpf_fs=mounted\n\
WHOATHERE_CAPABILITY fanotify_init=available\n\
WHOATHERE_CAPABILITY bpf_program_load=available\n\
WHOATHERE_CAPABILITY syscall_probe=passed\n\
WHOATHERE_CAPABILITY virtio_vsock=loaded\n\
WHOATHERE_CAPABILITY virtio_net=loaded\n\
WHOATHERE_GUEST_SIGNER_READY port=40551\n\
WHOATHERE_SENSOR guest_sensor_death_fixture=active\n\
WHOATHERE_GUEST_SENSOR_DEATH observed_signal=9\n\
WHOATHERE_GUEST_SIGNER_FAILED reason=guest_sensor_death_injected\n\
WHOATHERE_CAPABILITY guest_receipt_signing=failed\n\
WHOATHERE_CAPABILITY external_route_configured=false\n\
WHOATHERE_CAPABILITY package_execution=false\n\
WHOATHERE_CAPABILITY sync_back=false\n\
WHOATHERE_LINUX_VZ_SIGNED_INERT_FAILED\n";

    #[test]
    fn channel_interruption_serial_requires_exact_failure_without_evidence() {
        validate_channel_interruption_serial(CHANNEL_SERIAL.as_bytes()).unwrap();
        assert!(validate_channel_interruption_serial(
            CHANNEL_SERIAL
                .replace(
                    "WHOATHERE_CAPABILITY guest_receipt_signing=failed\n",
                    "WHOATHERE_CAPABILITY guest_receipt_signing=passed\n",
                )
                .as_bytes(),
        )
        .is_err());
        assert!(validate_channel_interruption_serial(
            format!("{CHANNEL_SERIAL}WHOATHERE_SENSOR process_exec=observed\n").as_bytes(),
        )
        .is_err());
        assert!(validate_channel_interruption_serial(
            CHANNEL_SERIAL
                .replace("WHOATHERE_GUEST_SIGNER_FAILED reason=linux_vz_guest_signer_transport_length_invalid\n", "")
                .as_bytes(),
        )
        .is_err());
    }

    #[test]
    fn vm_stop_serial_requires_exact_active_marker_without_receipt() {
        validate_vm_stop_serial(VM_STOP_SERIAL.as_bytes()).unwrap();
        assert!(validate_vm_stop_serial(
            VM_STOP_SERIAL
                .replace("WHOATHERE_SENSOR vm_stop_fixture=active\n", "")
                .as_bytes(),
        )
        .is_err());
        assert!(validate_vm_stop_serial(
            format!("{VM_STOP_SERIAL}WHOATHERE_GUEST_SIGNER_RECEIPT_OK digest=x\n").as_bytes(),
        )
        .is_err());
        assert!(validate_vm_stop_serial(
            format!("{VM_STOP_SERIAL}WHOATHERE_SENSOR process_exec=observed\n").as_bytes(),
        )
        .is_err());
    }

    #[test]
    fn guest_sensor_death_serial_requires_active_sigkill_and_failure() {
        validate_guest_sensor_death_serial(GUEST_SENSOR_DEATH_SERIAL.as_bytes()).unwrap();
        assert!(validate_guest_sensor_death_serial(
            GUEST_SENSOR_DEATH_SERIAL
                .replace("WHOATHERE_GUEST_SENSOR_DEATH observed_signal=9\n", "")
                .as_bytes(),
        )
        .is_err());
        assert!(validate_guest_sensor_death_serial(
            GUEST_SENSOR_DEATH_SERIAL
                .replace("observed_signal=9", "observed_signal=15")
                .as_bytes(),
        )
        .is_err());
        assert!(validate_guest_sensor_death_serial(
            format!("{GUEST_SENSOR_DEATH_SERIAL}WHOATHERE_GUEST_SIGNER_RECEIPT_OK x\n").as_bytes(),
        )
        .is_err());
    }
}
