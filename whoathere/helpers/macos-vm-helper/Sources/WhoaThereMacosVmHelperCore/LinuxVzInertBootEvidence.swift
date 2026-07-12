import Foundation

public let linuxVzInertSuccessMarkerV1 = "WHOATHERE_LINUX_VZ_INERT_OK"

public let linuxVzInertRequiredCapabilityMarkersV1 = [
    "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
    "WHOATHERE_CAPABILITY architecture=aarch64",
    "WHOATHERE_CAPABILITY kernel_btf=present",
    "WHOATHERE_CAPABILITY kernel_btf_sha256=sha256:d7f143446e11cfd67fa53392616afdbca6511a6af432e6bd56fb053aa4e7becb",
    "WHOATHERE_CAPABILITY cgroup_v2=mounted",
    "WHOATHERE_CAPABILITY bpf_fs=mounted",
    "WHOATHERE_CAPABILITY fanotify_init=available",
    "WHOATHERE_CAPABILITY bpf_program_load=available",
    "WHOATHERE_CAPABILITY syscall_probe=passed",
    "WHOATHERE_CAPABILITY virtio_net=loaded",
    "WHOATHERE_CAPABILITY external_route_configured=false",
    "WHOATHERE_CAPABILITY package_execution=false",
    "WHOATHERE_CAPABILITY sync_back=false",
]

public let linuxVzInertProcessSensorMarkersV2 = [
    "WHOATHERE_SENSOR process_cgroup_filter=observed",
    "WHOATHERE_SENSOR process_fork=observed",
    "WHOATHERE_SENSOR process_exec=observed",
    "WHOATHERE_SENSOR process_exit=observed",
    "WHOATHERE_SENSOR unprivileged_fixture=uid_65534_gid_65534",
    "WHOATHERE_SENSOR protected_sensor_read=denied",
    "WHOATHERE_SENSOR protected_sensor_write=denied",
    "WHOATHERE_SENSOR_PROCESS_PROBE_OK",
]

public let linuxVzInertDoubleForkSensorMarkersV1 = [
    "WHOATHERE_SENSOR process_double_fork=observed",
    "WHOATHERE_SENSOR process_daemon_reaped=observed",
]

public let linuxVzInertReparentingSensorMarkersV1 = [
    "WHOATHERE_SENSOR process_reparenting=observed",
    "WHOATHERE_SENSOR process_subreaper_teardown=observed",
]

public let linuxVzInertSetsidSensorMarkersV1 = [
    "WHOATHERE_SENSOR process_setsid=observed",
    "WHOATHERE_SENSOR process_session_escape=observed",
]

public let linuxVzInertCredentialSensorMarkersV1 = [
    "WHOATHERE_SENSOR process_credential_change=observed",
    "WHOATHERE_SENSOR process_credentials=uid_65534_gid_65534_no_supplementary_groups",
]

public let linuxVzInertDynamicLibrarySensorMarkersV1 = [
    "WHOATHERE_SENSOR dynamic_library_load=observed",
    "WHOATHERE_SENSOR dynamic_library_target=measured_inert_fixture_library",
]

public let linuxVzInertIPv4ConnectSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_ipv4_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=syn_sent",
    "WHOATHERE_SENSOR network_target=documentation_sinkhole_192_0_2_1_443"
]

public let linuxVzInertIPv6ConnectSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_ipv6_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=syn_sent",
    "WHOATHERE_SENSOR network_target=documentation_sinkhole_2001_db8_1_443"
]

public let linuxVzInertUDPSendSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_udp_send=observed",
    "WHOATHERE_SENSOR network_socket_state=unconnected_bound",
    "WHOATHERE_SENSOR network_payload=whoathere_udp_v1_16_bytes",
    "WHOATHERE_SENSOR network_target=documentation_sinkhole_192_0_2_1_443"
]

public let linuxVzInertLoopbackConnectSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_loopback_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=established",
    "WHOATHERE_SENSOR network_loopback_peer=accepted",
    "WHOATHERE_SENSOR network_target=guest_loopback_sinkhole_127_0_0_1_40552"
]

public let linuxVzInertPrivateAddressConnectSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_private_address_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=syn_sent",
    "WHOATHERE_SENSOR network_destination_class=private_rfc1918",
    "WHOATHERE_SENSOR network_target=private_sinkhole_10_0_0_1_443"
]

public let linuxVzInertLinkLocalConnectSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_link_local_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=syn_sent",
    "WHOATHERE_SENSOR network_destination_class=link_local",
    "WHOATHERE_SENSOR network_target=link_local_sinkhole_169_254_100_1_443"
]

public let linuxVzInertMetadataAddressConnectSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_metadata_address_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=syn_sent",
    "WHOATHERE_SENSOR network_destination_class=cloud_metadata",
    "WHOATHERE_SENSOR network_target=metadata_sinkhole_169_254_169_254_443"
]

public let linuxVzInertPublicAddressConnectSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_public_address_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=syn_sent",
    "WHOATHERE_SENSOR network_destination_class=public_documentation",
    "WHOATHERE_SENSOR network_target=public_sinkhole_198_51_100_1_443"
]

public let linuxVzInertDNSPlaintextSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_dns_plaintext=observed",
    "WHOATHERE_SENSOR network_socket_state=unconnected_bound",
    "WHOATHERE_SENSOR network_dns_transport=udp",
    "WHOATHERE_SENSOR network_dns_question=whoathere_invalid_a_in",
    "WHOATHERE_SENSOR network_target=dns_sinkhole_192_0_2_53_53"
]

public let linuxVzInertDNSMalformedSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_dns_malformed=observed",
    "WHOATHERE_SENSOR network_socket_state=unconnected_bound",
    "WHOATHERE_SENSOR network_dns_transport=udp",
    "WHOATHERE_SENSOR network_dns_malformed_shape=question_declared_body_absent",
    "WHOATHERE_SENSOR network_target=dns_sinkhole_192_0_2_53_53"
]

public let linuxVzInertEncryptedDNSSensorMarkersV1 = [
    "WHOATHERE_SENSOR network_encrypted_dns_connect=observed",
    "WHOATHERE_SENSOR network_socket_state=syn_sent",
    "WHOATHERE_SENSOR network_dns_transport=tcp_853",
    "WHOATHERE_SENSOR network_dns_encryption_intent=dot",
    "WHOATHERE_SENSOR network_target=dns_sinkhole_192_0_2_53_853"
]

public let linuxVzInertBPFReservationFailureSensorMarkersV1 = [
    "WHOATHERE_SENSOR bpf_reservation_failure=injected",
    "WHOATHERE_SENSOR dropped_event_accounting=observed",
    "WHOATHERE_SENSOR drop_accounting_terminal=incomplete_on_injected_gap"
]

public let linuxVzInertFanotifyQueueOverflowSensorMarkersV1 = [
    "WHOATHERE_SENSOR fanotify_queue_overflow=injected",
    "WHOATHERE_SENSOR dropped_event_accounting=observed",
    "WHOATHERE_SENSOR fanotify_queue_limit=restored",
    "WHOATHERE_SENSOR drop_accounting_terminal=incomplete_on_injected_gap"
]

public let linuxVzInertHostFrameOverflowSensorMarkersV1 = [
    "WHOATHERE_SENSOR host_frame_overflow_guest_trigger=observed",
    "WHOATHERE_SENSOR host_frame_guest_tx_drop_count=zero",
    "WHOATHERE_SENSOR network_target=documentation_sinkhole_192_0_2_1_443",
    "WHOATHERE_SENSOR drop_accounting_terminal=incomplete_on_injected_gap"
]

public let linuxVzInertNormalExitSensorMarkersV1 = [
    "WHOATHERE_SENSOR teardown_trigger=natural_exit",
    "WHOATHERE_SENSOR teardown_deadline=not_reached",
    "WHOATHERE_SENSOR teardown_signals=none",
    "WHOATHERE_SENSOR teardown_descendants=none_remaining",
    "WHOATHERE_SENSOR teardown_sensor=closed",
    "WHOATHERE_SENSOR teardown_cgroup=removed",
    "WHOATHERE_SENSOR teardown_terminal=observation_complete"
]

public let linuxVzInertTimeoutSensorMarkersV1 = [
    "WHOATHERE_SENSOR teardown_trigger=deadline",
    "WHOATHERE_SENSOR teardown_deadline=reached",
    "WHOATHERE_SENSOR teardown_term_signal=delivered",
    "WHOATHERE_SENSOR teardown_kill_signal=not_required",
    "WHOATHERE_SENSOR teardown_descendants=none_remaining",
    "WHOATHERE_SENSOR teardown_sensor=closed",
    "WHOATHERE_SENSOR teardown_cgroup=removed",
    "WHOATHERE_SENSOR teardown_terminal=timeout_with_teardown"
]

public let linuxVzInertRequiredEvidenceMarkersV2 =
    linuxVzInertRequiredCapabilityMarkersV1 + linuxVzInertProcessSensorMarkersV2

public let linuxVzInertFileSensorMarkersV1 = [
    "WHOATHERE_SENSOR file_fanotify_permission=observed",
    "WHOATHERE_SENSOR file_mmap_bpf=observed",
    "WHOATHERE_SENSOR persistence_write=observed",
    "WHOATHERE_SENSOR file_system_diff=observed",
]

public func linuxVzInertSerialContainsExactMarker(_ serialData: Data, marker: String) -> Bool {
    linuxVzInertSerialLines(serialData).contains(marker)
}

public func linuxVzInertMissingCapabilityMarkers(_ serialData: Data) -> [String] {
    let lines = linuxVzInertSerialLines(serialData)
    return linuxVzInertRequiredCapabilityMarkersV1.filter { !lines.contains($0) }
}

public func linuxVzInertMissingRequiredEvidenceMarkersV2(_ serialData: Data) -> [String] {
    let lines = linuxVzInertSerialLines(serialData)
    return linuxVzInertRequiredEvidenceMarkersV2.filter { !lines.contains($0) }
}

private func linuxVzInertSerialLines(_ serialData: Data) -> Set<String> {
    Set(serialData.split(separator: 0x0A).map { line in
        var bytes = Array(line)
        if bytes.last == 0x0D {
            bytes.removeLast()
        }
        return String(decoding: bytes, as: UTF8.self)
    })
}
