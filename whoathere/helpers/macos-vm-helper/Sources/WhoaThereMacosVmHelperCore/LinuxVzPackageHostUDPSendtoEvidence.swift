import Foundation

public let linuxVzPackageHostUDPSendtoEvidenceSchemaV2 =
    "whoathere.linux_vz_package_host_udp_sendto_evidence.v2"
public let linuxVzPackageHostUDPSendtoEvidenceSchemaV1 =
    linuxVzPackageHostUDPSendtoEvidenceSchemaV2
public let maximumLinuxVzPackageHostUDPSendtoEvidenceBytesV1 = 64 * 1024

private let linuxVzPackageHostUDPSendtoUnobservedV1 = [
    "ipv6_host_frames",
    "kernel_socket_buffer_drop_accounting",
    "non_udp_sendto_host_frames",
    "retransmission_and_multi_frame_events",
]

public enum LinuxVzPackageHostUDPSendtoEvidenceError: Error, Equatable {
    case empty
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidBinding
    case incompleteCollection
    case invalidFrame
    case correlationMismatch
    case invalidSchema
}

public struct LinuxVzPackageHostUDPSendtoEvidenceV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let rootNetworkEvidenceSHA256: String
    public let processEvidenceSHA256: String
    public let destinationTokenSHA256: String
    public let egressPacketCorrelationSHA256: String
    public let frameSHA256: String
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let payloadByteCount: UInt64
    public var selectedCorrelationComplete: Bool { true }
    public var broadHostFrameCoverageComplete: Bool { false }
}

public struct LinuxVzPackageExpectedHostUDPSendtoV1: Equatable, Sendable {
    public let rootNetworkEvidenceSHA256: String
    public let processEvidenceSHA256: String
    public let sensorSessionChallengeSHA256: String
    public let destinationTokenSHA256: String
    public let egressPacketCorrelationSHA256: String
    public let destinationClass: LinuxVzPackageHostDestinationClassV1
    public let destinationPort: UInt16
    public let enterSourceSequence: UInt64
    public let syscallResult: UInt64

    public init(
        rootNetworkEvidenceSHA256: String,
        processEvidenceSHA256: String,
        sensorSessionChallengeSHA256: String,
        destinationTokenSHA256: String,
        egressPacketCorrelationSHA256: String,
        destinationClass: LinuxVzPackageHostDestinationClassV1,
        destinationPort: UInt16,
        enterSourceSequence: UInt64,
        syscallResult: UInt64
    ) throws {
        guard [rootNetworkEvidenceSHA256, processEvidenceSHA256,
               sensorSessionChallengeSHA256, destinationTokenSHA256,
               egressPacketCorrelationSHA256]
                .allSatisfy(linuxVzPackageHostUDPSendtoDigestV1),
              Set([rootNetworkEvidenceSHA256, processEvidenceSHA256,
                   sensorSessionChallengeSHA256, destinationTokenSHA256,
                   egressPacketCorrelationSHA256]).count == 5,
              destinationPort > 0, enterSourceSequence > 0,
              syscallResult > 0, syscallResult <= UInt64(UInt16.max) else {
            throw LinuxVzPackageHostUDPSendtoEvidenceError.invalidBinding
        }
        self.rootNetworkEvidenceSHA256 = rootNetworkEvidenceSHA256
        self.processEvidenceSHA256 = processEvidenceSHA256
        self.sensorSessionChallengeSHA256 = sensorSessionChallengeSHA256
        self.destinationTokenSHA256 = destinationTokenSHA256
        self.egressPacketCorrelationSHA256 = egressPacketCorrelationSHA256
        self.destinationClass = destinationClass
        self.destinationPort = destinationPort
        self.enterSourceSequence = enterSourceSequence
        self.syscallResult = syscallResult
    }
}

public func makeLinuxVzPackageHostUDPSendtoEvidenceV1(
    expected: LinuxVzPackageExpectedHostUDPSendtoV1,
    collection: LinuxVzBoundedHostRawFrameCollection,
    expectedSourceMAC: Data
) throws -> LinuxVzPackageHostUDPSendtoEvidenceV1 {
    guard collection.healthy,
          collection.terminal == "drained_after_stop",
          collection.ingressFrameCount == 1,
          collection.retainedFrameCount == 1,
          collection.droppedFrameCount == 0,
          collection.truncatedFrameCount == 0 else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.incompleteCollection
    }
    let frame: LinuxVzPackageHostIPv4FrameV1
    do {
        frame = try decodeLinuxVzPackageHostIPv4FrameV1(
            collection.retainedFrames[0],
            expectedSourceMAC: expectedSourceMAC
        )
    } catch {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.invalidFrame
    }
    let token: String
    do {
        token = try frame.destinationTokenSHA256(
            sensorSessionChallengeSHA256: expected.sensorSessionChallengeSHA256,
            eventKind: "sendto",
            enterSourceSequence: expected.enterSourceSequence
        )
    } catch {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.correlationMismatch
    }
    guard frame.transport == .udp,
          frame.destinationClass == expected.destinationClass,
          frame.destinationPort == expected.destinationPort,
          frame.transportPayloadByteCount == Int(expected.syscallResult),
          frame.networkLayerCorrelationSHA256 == expected.egressPacketCorrelationSHA256,
          token == expected.destinationTokenSHA256 else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.correlationMismatch
    }
    let value: [String: Any] = [
        "binding": [
            "egress_packet_correlation_sha256": expected.egressPacketCorrelationSHA256,
            "process_evidence_sha256": expected.processEvidenceSHA256,
            "root_network_evidence_sha256": expected.rootNetworkEvidenceSHA256,
            "sensor_session_challenge_sha256": expected.sensorSessionChallengeSHA256,
        ],
        "collector": [
            "dropped_frame_count": "0",
            "healthy": true,
            "ingress_frame_count": "1",
            "retained_frame_count": "1",
            "terminal": "drained_after_stop",
            "truncated_frame_count": "0",
        ],
        "coverage": [
            "broad_host_frame_coverage_complete": false,
            "correlated_transmitted_event_count": "1",
            "raw_addresses_serialized": false,
            "raw_frame_bytes_serialized": false,
            "selected_udp_sendto_correlation_complete": true,
            "unobserved_capabilities": linuxVzPackageHostUDPSendtoUnobservedV1,
        ],
        "event": [
            "destination_class": expected.destinationClass.rawValue,
            "destination_port": String(expected.destinationPort),
            "destination_token_sha256": expected.destinationTokenSHA256,
            "enter_source_sequence": String(expected.enterSourceSequence),
            "event_kind": "sendto",
            "frame_sha256": frame.frameSHA256,
            "network_layer_correlation_sha256": frame.networkLayerCorrelationSHA256,
            "source_port": String(frame.sourcePort),
            "syscall_result": String(expected.syscallResult),
            "transport": "udp",
            "transport_payload_byte_count": String(frame.transportPayloadByteCount),
        ],
        "schema_version": linuxVzPackageHostUDPSendtoEvidenceSchemaV2,
    ]
    return try decodeLinuxVzPackageHostUDPSendtoEvidenceV1(
        canonicalJSONData(value),
        expected: expected
    )
}

public func decodeLinuxVzPackageHostUDPSendtoEvidenceV1(
    _ data: Data,
    expected: LinuxVzPackageExpectedHostUDPSendtoV1
) throws -> LinuxVzPackageHostUDPSendtoEvidenceV1 {
    guard !data.isEmpty else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.empty
    }
    guard data.count <= maximumLinuxVzPackageHostUDPSendtoEvidenceBytesV1 else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.nonCanonical
    }
    guard Set(value.keys) == Set(["binding", "collector", "coverage", "event", "schema_version"]),
          value["schema_version"] as? String == linuxVzPackageHostUDPSendtoEvidenceSchemaV2,
          let binding = value["binding"] as? [String: Any],
          Set(binding.keys) == Set([
              "egress_packet_correlation_sha256", "process_evidence_sha256",
              "root_network_evidence_sha256",
              "sensor_session_challenge_sha256",
          ]),
          binding["egress_packet_correlation_sha256"] as? String ==
            expected.egressPacketCorrelationSHA256,
          binding["process_evidence_sha256"] as? String == expected.processEvidenceSHA256,
          binding["root_network_evidence_sha256"] as? String ==
            expected.rootNetworkEvidenceSHA256,
          binding["sensor_session_challenge_sha256"] as? String ==
            expected.sensorSessionChallengeSHA256 else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.invalidBinding
    }
    guard let collector = value["collector"] as? [String: Any],
          Set(collector.keys) == Set([
              "dropped_frame_count", "healthy", "ingress_frame_count",
              "retained_frame_count", "terminal", "truncated_frame_count",
          ]),
          linuxVzPackageHostUDPSendtoDecimalV1(collector["dropped_frame_count"]) == 0,
          collector["healthy"] as? Bool == true,
          linuxVzPackageHostUDPSendtoDecimalV1(collector["ingress_frame_count"]) == 1,
          linuxVzPackageHostUDPSendtoDecimalV1(collector["retained_frame_count"]) == 1,
          collector["terminal"] as? String == "drained_after_stop",
          linuxVzPackageHostUDPSendtoDecimalV1(collector["truncated_frame_count"]) == 0 else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.incompleteCollection
    }
    guard let coverage = value["coverage"] as? [String: Any],
          Set(coverage.keys) == Set([
              "broad_host_frame_coverage_complete", "correlated_transmitted_event_count",
              "raw_addresses_serialized", "raw_frame_bytes_serialized",
              "selected_udp_sendto_correlation_complete", "unobserved_capabilities",
          ]),
          coverage["broad_host_frame_coverage_complete"] as? Bool == false,
          linuxVzPackageHostUDPSendtoDecimalV1(
              coverage["correlated_transmitted_event_count"]
          ) == 1,
          coverage["raw_addresses_serialized"] as? Bool == false,
          coverage["raw_frame_bytes_serialized"] as? Bool == false,
          coverage["selected_udp_sendto_correlation_complete"] as? Bool == true,
          coverage["unobserved_capabilities"] as? [String] ==
            linuxVzPackageHostUDPSendtoUnobservedV1 else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.invalidSchema
    }
    guard let event = value["event"] as? [String: Any],
          Set(event.keys) == Set([
              "destination_class", "destination_port", "destination_token_sha256",
              "enter_source_sequence", "event_kind", "frame_sha256",
              "network_layer_correlation_sha256", "source_port",
              "syscall_result", "transport", "transport_payload_byte_count",
          ]),
          event["destination_class"] as? String == expected.destinationClass.rawValue,
          linuxVzPackageHostUDPSendtoDecimalV1(event["destination_port"]) ==
            UInt64(expected.destinationPort),
          event["destination_token_sha256"] as? String == expected.destinationTokenSHA256,
          linuxVzPackageHostUDPSendtoDecimalV1(event["enter_source_sequence"]) ==
            expected.enterSourceSequence,
          event["event_kind"] as? String == "sendto",
          let frameSHA256 = event["frame_sha256"] as? String,
          linuxVzPackageHostUDPSendtoDigestV1(frameSHA256),
          ![expected.rootNetworkEvidenceSHA256, expected.processEvidenceSHA256,
             expected.sensorSessionChallengeSHA256, expected.destinationTokenSHA256,
             expected.egressPacketCorrelationSHA256]
                .contains(frameSHA256),
          event["network_layer_correlation_sha256"] as? String ==
            expected.egressPacketCorrelationSHA256,
          let sourcePortValue = linuxVzPackageHostUDPSendtoDecimalV1(event["source_port"]),
          sourcePortValue > 0, sourcePortValue <= UInt64(UInt16.max),
          linuxVzPackageHostUDPSendtoDecimalV1(event["syscall_result"]) ==
            expected.syscallResult,
          event["transport"] as? String == "udp",
          linuxVzPackageHostUDPSendtoDecimalV1(event["transport_payload_byte_count"]) ==
            expected.syscallResult else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.correlationMismatch
    }
    return LinuxVzPackageHostUDPSendtoEvidenceV1(
        canonicalJSON: data,
        payloadSHA256: sha256(data),
        rootNetworkEvidenceSHA256: expected.rootNetworkEvidenceSHA256,
        processEvidenceSHA256: expected.processEvidenceSHA256,
        destinationTokenSHA256: expected.destinationTokenSHA256,
        egressPacketCorrelationSHA256: expected.egressPacketCorrelationSHA256,
        frameSHA256: frameSHA256,
        sourcePort: UInt16(sourcePortValue),
        destinationPort: expected.destinationPort,
        payloadByteCount: expected.syscallResult
    )
}

private func linuxVzPackageHostUDPSendtoDecimalV1(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || text.first != "0" else { return nil }
    return UInt64(text)
}

private func linuxVzPackageHostUDPSendtoDigestV1(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
