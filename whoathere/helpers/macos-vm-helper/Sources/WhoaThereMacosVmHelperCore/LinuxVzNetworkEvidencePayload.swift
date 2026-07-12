import Foundation

public let linuxVzNetworkEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_network_evidence_payload.v1"
public let linuxVzNetworkEvidenceSerialPrefixV1 = Data(
    "WHOATHERE_GUEST_NETWORK_EVIDENCE ".utf8
)
public let maximumLinuxVzNetworkEvidencePayloadBytesV1 = 64 * 1024

public enum LinuxVzNetworkEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzNetworkEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let evidenceByteLength: UInt64
    public let fixtureCase: String
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let sourcePort: UInt16
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzNetworkEvidencePayloadV1(
    _ serial: Data
) throws -> LinuxVzNetworkEvidencePayload {
    var payload: Data?
    for rawLine in serial.split(separator: 0x0a, omittingEmptySubsequences: false) {
        var line = Data(rawLine)
        if line.last == 0x0d { line.removeLast() }
        guard line.starts(with: linuxVzNetworkEvidenceSerialPrefixV1) else { continue }
        guard payload == nil else { throw LinuxVzNetworkEvidencePayloadError.duplicate }
        payload = line.dropFirst(linuxVzNetworkEvidenceSerialPrefixV1.count)
    }
    guard let payload else { throw LinuxVzNetworkEvidencePayloadError.missing }
    return try decodeLinuxVzNetworkEvidenceJSONV1(payload)
}

public func decodeLinuxVzNetworkEvidenceJSONV1(
    _ data: Data
) throws -> LinuxVzNetworkEvidencePayload {
    guard !data.isEmpty, data.count <= maximumLinuxVzNetworkEvidencePayloadBytesV1 else {
        throw LinuxVzNetworkEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzNetworkEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzNetworkEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "fixture_case", "heartbeat_count", "network_action", "network_family",
        "network_protocol", "network_socket_state", "network_source", "network_source_port",
        "network_target", "network_target_port", "package_gid", "package_uid",
        "reaped_process_count", "schema_version", "sensor_healthy"
    ])
    let fixtureCase: String
    switch (
        value["fixture_case"] as? String,
        value["network_family"] as? String,
        value["network_source"] as? String,
        value["network_target"] as? String
    ) {
    case ("ipv4_connect", "ipv4", "192.0.2.2", "192.0.2.1"):
        fixtureCase = "ipv4_connect"
    case ("ipv6_connect", "ipv6", "2001:db8::2", "2001:db8::1"):
        fixtureCase = "ipv6_connect"
    case ("udp_send", "ipv4", "192.0.2.2", "192.0.2.1"):
        fixtureCase = "udp_send"
    case ("loopback_connect", "ipv4", "127.0.0.1", "127.0.0.1"):
        fixtureCase = "loopback_connect"
    case ("private_address_connect", "ipv4", "10.0.0.2", "10.0.0.1"):
        fixtureCase = "private_address_connect"
    case ("link_local_connect", "ipv4", "169.254.100.2", "169.254.100.1"):
        fixtureCase = "link_local_connect"
    case ("metadata_address_connect", "ipv4", "169.254.169.253", "169.254.169.254"):
        fixtureCase = "metadata_address_connect"
    case ("public_address_connect", "ipv4", "198.51.100.2", "198.51.100.1"):
        fixtureCase = "public_address_connect"
    case ("dns_plaintext", "ipv4", "192.0.2.2", "192.0.2.53"):
        fixtureCase = "dns_plaintext"
    default:
        throw LinuxVzNetworkEvidencePayloadError.invalidSchema
    }
    let expectedAction = fixtureCase == "dns_plaintext" ? "dns_query" :
        (fixtureCase == "udp_send" ? "udp_send" : "tcp_connect")
    let udpActivity = fixtureCase == "udp_send" || fixtureCase == "dns_plaintext"
    let expectedProtocol = udpActivity ? "udp" : "tcp"
    let expectedSocketState = udpActivity ? "unconnected_bound" :
        (fixtureCase == "loopback_connect" ? "established" : "syn_sent")
    let expectedTargetPort: UInt64 = fixtureCase == "dns_plaintext" ? 53 :
        (fixtureCase == "loopback_connect" ? 40_552 : 443)
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzNetworkEvidencePayloadSchemaV1,
          value["network_action"] as? String == expectedAction,
          value["network_protocol"] as? String == expectedProtocol,
          value["network_socket_state"] as? String == expectedSocketState,
          networkEvidenceDecimal(value["network_target_port"]) == expectedTargetPort,
          let sourcePort = networkEvidenceDecimal(value["network_source_port"]),
          sourcePort > 0, sourcePort <= UInt64(UInt16.max),
          networkEvidenceDecimal(value["event_sequence_start"]) == 1,
          networkEvidenceDecimal(value["event_sequence_end"]) == 4,
          networkEvidenceDecimal(value["event_count"]) == 4,
          networkEvidenceDecimal(value["heartbeat_count"]) == 2,
          networkEvidenceDecimal(value["dropped_event_count"]) == 0,
          networkEvidenceDecimal(value["package_uid"]) == 65534,
          networkEvidenceDecimal(value["package_gid"]) == 65534,
          networkEvidenceDecimal(value["reaped_process_count"]) == 1,
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          value["descendant_teardown_complete"] as? Bool == true,
          let events = value["events"] as? [[String: Any]], events.count == 4 else {
        throw LinuxVzNetworkEvidencePayloadError.invalidSchema
    }
    let expectedKinds = ["fork", "exec", udpActivity ? "sendto" : "connect", "exit"]
    var childPID: UInt64?
    var cgroupID: UInt64?
    var previousTimestamp: UInt64 = 0
    for (index, event) in events.enumerated() {
        guard Set(event.keys) == Set([
            "actor_pid", "cgroup_id", "kind", "sequence", "subject_pid", "timestamp_ns"
        ]),
        event["kind"] as? String == expectedKinds[index],
        networkEvidenceDecimal(event["sequence"]) == UInt64(index + 1),
        let actor = networkEvidenceDecimal(event["actor_pid"]), actor > 0,
        let subject = networkEvidenceDecimal(event["subject_pid"]), subject > 0,
        let cgroup = networkEvidenceDecimal(event["cgroup_id"]), cgroup > 0,
        let timestamp = networkEvidenceDecimal(event["timestamp_ns"]),
        timestamp > previousTimestamp else {
            throw LinuxVzNetworkEvidencePayloadError.invalidEvent
        }
        if index == 0 {
            guard actor != subject else { throw LinuxVzNetworkEvidencePayloadError.invalidEvent }
            childPID = subject
            cgroupID = cgroup
        } else {
            guard actor == childPID, subject == childPID, cgroup == cgroupID else {
                throw LinuxVzNetworkEvidencePayloadError.invalidEvent
            }
        }
        previousTimestamp = timestamp
    }
    let claims = LinuxVzTelemetryGuestObservationClaims(
        evidencePayloadSHA256: sha256(data),
        evidenceByteLength: UInt64(data.count),
        eventSequenceStart: 1,
        eventSequenceEnd: 4,
        eventCount: 4,
        heartbeatCount: 2,
        droppedEventCount: 0,
        sensorHealthy: true,
        evidenceTruncated: false,
        descendantTeardownComplete: true,
        observedTerminal: "observation_complete"
    )
    return LinuxVzNetworkEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        evidenceByteLength: UInt64(data.count),
        fixtureCase: fixtureCase,
        packageUID: 65534,
        packageGID: 65534,
        sourcePort: UInt16(sourcePort),
        claims: claims
    )
}

private func networkEvidenceDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
