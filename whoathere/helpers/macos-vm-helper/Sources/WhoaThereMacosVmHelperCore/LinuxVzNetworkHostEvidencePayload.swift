import Foundation

public let linuxVzNetworkHostEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_network_host_evidence_payload.v1"

public struct LinuxVzNetworkHostEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let fixtureCase: String
    public let sourcePort: UInt16
    public let claims: LinuxVzTelemetryHostObservationClaims
}

public func makeLinuxVzIPv4ConnectHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "ipv4_connect",
        frameKind: "ipv4_tcp_syn",
        sourceAddress: "192.0.2.2",
        targetAddress: "192.0.2.1",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzIPv6ConnectHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "ipv6_connect",
        frameKind: "ipv6_tcp_syn",
        sourceAddress: "2001:db8::2",
        targetAddress: "2001:db8::1",
        bootstrapFrameCount: 1,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzUDPSendHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "udp_send",
        frameKind: "ipv4_udp_datagram",
        sourceAddress: "192.0.2.2",
        targetAddress: "192.0.2.1",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzPrivateAddressConnectHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "private_address_connect",
        frameKind: "ipv4_tcp_syn_private",
        sourceAddress: "10.0.0.2",
        targetAddress: "10.0.0.1",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzLinkLocalConnectHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "link_local_connect",
        frameKind: "ipv4_tcp_syn_link_local",
        sourceAddress: "169.254.100.2",
        targetAddress: "169.254.100.1",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzMetadataAddressConnectHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "metadata_address_connect",
        frameKind: "ipv4_tcp_syn_metadata",
        sourceAddress: "169.254.169.253",
        targetAddress: "169.254.169.254",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzPublicAddressConnectHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "public_address_connect",
        frameKind: "ipv4_tcp_syn_public",
        sourceAddress: "198.51.100.2",
        targetAddress: "198.51.100.1",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzDNSPlaintextHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "dns_plaintext",
        frameKind: "ipv4_udp_dns_plaintext_query",
        sourceAddress: "192.0.2.2",
        targetAddress: "192.0.2.53",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

public func makeLinuxVzDNSMalformedHostEvidencePayload(
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    try makeLinuxVzConnectHostEvidencePayload(
        fixtureCase: "dns_malformed",
        frameKind: "ipv4_udp_dns_malformed_truncated_question",
        sourceAddress: "192.0.2.2",
        targetAddress: "192.0.2.53",
        bootstrapFrameCount: 0,
        sourcePort: sourcePort,
        rawFrameCount: rawFrameCount,
        matchedFrameCount: matchedFrameCount,
        unexpectedFrameCount: unexpectedFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        storageDeviceCount: storageDeviceCount
    )
}

private func makeLinuxVzConnectHostEvidencePayload(
    fixtureCase: String,
    frameKind: String,
    sourceAddress: String,
    targetAddress: String,
    bootstrapFrameCount: UInt64,
    sourcePort: UInt16,
    rawFrameCount: UInt64,
    matchedFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzNetworkHostEvidencePayload {
    let value: [String: Any] = [
        "bootstrap_frame_count": String(bootstrapFrameCount),
        "clone_destroyed": true,
        "dropped_frame_count": "0",
        "event_count": "7",
        "event_sequence_end": "7",
        "event_sequence_start": "1",
        "events": [
            ["kind": "vm_started", "sequence": "1"],
            ["kind": "guest_channel_connected", "sequence": "2"],
            ["kind": "sinkhole_frame_observed", "sequence": "3"],
            ["kind": "guest_channel_terminated", "sequence": "4"],
            ["kind": "host_packet_sensor_complete", "sequence": "5"],
            ["kind": "vm_stopped", "sequence": "6"],
            ["kind": "ephemeral_clone_destroyed", "sequence": "7"]
        ],
        "evidence_truncated": false,
        "external_frames_forwarded": "0",
        "external_route_configured": false,
        "fixture_case": fixtureCase,
        "frame_kind": frameKind,
        "guest_channel_terminated": true,
        "heartbeat_count": "2",
        "ip_checksum_valid": fixtureCase != "ipv6_connect",
        "matched_frame_count": String(matchedFrameCount),
        "package_execution": false,
        "packet_sensor_healthy": packetSensorHealthy,
        "packet_sensor_terminal": packetSensorTerminal,
        "raw_frame_count": String(rawFrameCount),
        "root_disk_present": false,
        "schema_version": linuxVzNetworkHostEvidencePayloadSchemaV1,
        "source_address": sourceAddress,
        "source_mac": "02:57:48:4f:41:31",
        "source_port": String(sourcePort),
        "storage_device_count": String(storageDeviceCount),
        "sync_back": false,
        "target_address": targetAddress,
        "target_mac": "02:57:48:4f:41:fe",
        "target_port": fixtureCase == "dns_plaintext" || fixtureCase == "dns_malformed"
            ? "53" : "443",
        "transport_checksum_valid": true,
        "unexpected_frame_count": String(unexpectedFrameCount),
        "vm_started": true,
        "vm_stopped": true
    ]
    return try decodeLinuxVzNetworkHostEvidencePayload(canonicalJSONData(value))
}

public func decodeLinuxVzNetworkHostEvidencePayload(
    _ data: Data
) throws -> LinuxVzNetworkHostEvidencePayload {
    guard !data.isEmpty, data.count <= maximumLinuxVzHostEvidencePayloadBytesV1 else {
        throw LinuxVzHostEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzHostEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzHostEvidencePayloadError.nonCanonical
    }
    let fixtureCase: String
    switch (
        value["fixture_case"] as? String,
        value["frame_kind"] as? String,
        value["source_address"] as? String,
        value["target_address"] as? String
    ) {
    case ("ipv4_connect", "ipv4_tcp_syn", "192.0.2.2", "192.0.2.1"):
        fixtureCase = "ipv4_connect"
    case ("ipv6_connect", "ipv6_tcp_syn", "2001:db8::2", "2001:db8::1"):
        fixtureCase = "ipv6_connect"
    case ("udp_send", "ipv4_udp_datagram", "192.0.2.2", "192.0.2.1"):
        fixtureCase = "udp_send"
    case ("private_address_connect", "ipv4_tcp_syn_private", "10.0.0.2", "10.0.0.1"):
        fixtureCase = "private_address_connect"
    case ("link_local_connect", "ipv4_tcp_syn_link_local", "169.254.100.2", "169.254.100.1"):
        fixtureCase = "link_local_connect"
    case ("metadata_address_connect", "ipv4_tcp_syn_metadata", "169.254.169.253", "169.254.169.254"):
        fixtureCase = "metadata_address_connect"
    case ("public_address_connect", "ipv4_tcp_syn_public", "198.51.100.2", "198.51.100.1"):
        fixtureCase = "public_address_connect"
    case ("dns_plaintext", "ipv4_udp_dns_plaintext_query", "192.0.2.2", "192.0.2.53"):
        fixtureCase = "dns_plaintext"
    case ("dns_malformed", "ipv4_udp_dns_malformed_truncated_question", "192.0.2.2", "192.0.2.53"):
        fixtureCase = "dns_malformed"
    default:
        throw LinuxVzHostEvidencePayloadError.invalidSchema
    }
    guard Set(value.keys) == Set([
        "bootstrap_frame_count", "clone_destroyed", "dropped_frame_count", "event_count", "event_sequence_end",
        "event_sequence_start", "events", "evidence_truncated", "external_frames_forwarded",
        "external_route_configured", "fixture_case", "frame_kind", "guest_channel_terminated",
        "heartbeat_count", "ip_checksum_valid", "matched_frame_count", "package_execution",
        "packet_sensor_healthy", "packet_sensor_terminal", "raw_frame_count",
        "root_disk_present", "schema_version", "source_address", "source_mac", "source_port",
        "storage_device_count", "sync_back", "target_address", "target_mac", "target_port",
        "transport_checksum_valid", "unexpected_frame_count", "vm_started", "vm_stopped"
    ]),
    value["schema_version"] as? String == linuxVzNetworkHostEvidencePayloadSchemaV1,
    value["source_mac"] as? String == "02:57:48:4f:41:31",
    value["target_mac"] as? String == "02:57:48:4f:41:fe",
    let sourcePort = networkHostDecimal(value["source_port"]),
    sourcePort > 0, sourcePort <= UInt64(UInt16.max),
    networkHostDecimal(value["target_port"]) ==
        (fixtureCase == "dns_plaintext" || fixtureCase == "dns_malformed" ? 53 : 443),
    networkHostDecimal(value["event_sequence_start"]) == 1,
    networkHostDecimal(value["event_sequence_end"]) == 7,
    networkHostDecimal(value["event_count"]) == 7,
    networkHostDecimal(value["heartbeat_count"]) == 2,
    networkHostDecimal(value["bootstrap_frame_count"]) == (fixtureCase == "ipv6_connect" ? 1 : 0),
    networkHostDecimal(value["raw_frame_count"]) == (fixtureCase == "ipv6_connect" ? 2 : 1),
    networkHostDecimal(value["matched_frame_count"]) == 1,
    networkHostDecimal(value["unexpected_frame_count"]) == 0,
    networkHostDecimal(value["dropped_frame_count"]) == 0,
    networkHostDecimal(value["external_frames_forwarded"]) == 0,
    networkHostDecimal(value["storage_device_count"]) == 0,
    value["ip_checksum_valid"] as? Bool == (fixtureCase != "ipv6_connect"),
    value["transport_checksum_valid"] as? Bool == true,
    value["packet_sensor_healthy"] as? Bool == true,
    value["packet_sensor_terminal"] as? String == "drained_would_block",
    value["evidence_truncated"] as? Bool == false,
    value["guest_channel_terminated"] as? Bool == true,
    value["vm_started"] as? Bool == true,
    value["vm_stopped"] as? Bool == true,
    value["clone_destroyed"] as? Bool == true,
    value["root_disk_present"] as? Bool == false,
    value["external_route_configured"] as? Bool == false,
    value["package_execution"] as? Bool == false,
    value["sync_back"] as? Bool == false,
    let events = value["events"] as? [[String: Any]], events.count == 7 else {
        throw LinuxVzHostEvidencePayloadError.invalidSchema
    }
    let expectedKinds = [
        "vm_started", "guest_channel_connected", "sinkhole_frame_observed",
        "guest_channel_terminated", "host_packet_sensor_complete", "vm_stopped",
        "ephemeral_clone_destroyed"
    ]
    for (index, event) in events.enumerated() {
        guard Set(event.keys) == Set(["kind", "sequence"]),
              event["kind"] as? String == expectedKinds[index],
              networkHostDecimal(event["sequence"]) == UInt64(index + 1) else {
            throw LinuxVzHostEvidencePayloadError.invalidEvent
        }
    }
    let claims = LinuxVzTelemetryHostObservationClaims(
        evidencePayloadSHA256: sha256(data),
        evidenceByteLength: UInt64(data.count),
        eventSequenceStart: 1,
        eventSequenceEnd: 7,
        eventCount: 7,
        heartbeatCount: 2,
        droppedFrameCount: 0,
        packetSensorHealthy: true,
        evidenceTruncated: false,
        guestChannelTerminated: true,
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        externalFramesForwarded: 0,
        observedTerminal: "observation_complete"
    )
    return LinuxVzNetworkHostEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        fixtureCase: fixtureCase,
        sourcePort: UInt16(sourcePort),
        claims: claims
    )
}

private func networkHostDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
