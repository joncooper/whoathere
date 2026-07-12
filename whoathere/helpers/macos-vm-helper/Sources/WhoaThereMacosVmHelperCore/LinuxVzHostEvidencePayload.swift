import Foundation

public let linuxVzHostEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_host_evidence_payload.v1"
public let maximumLinuxVzHostEvidencePayloadBytesV1 = 64 * 1024

public enum LinuxVzHostEvidencePayloadError: Error, Equatable {
    case empty
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzHostEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let rawFrameCount: UInt64
    public let channelInterruptionKind: String?
    public let channelRequestFrameBytes: UInt64?
    public let channelResponseBytes: UInt64?
    public let channelTransmittedPrefixBytes: UInt64?
    public let vmStopKind: String?
    public let vmStopRequestFrameBytes: UInt64?
    public let vmStopTransmittedRequestBytes: UInt64?
    public let vmStopResponseBytes: UInt64?
    public let vmStopFixtureActiveMarkerObserved: Bool?
    public let claims: LinuxVzTelemetryHostObservationClaims
}

public func makeLinuxVzInertHostEvidencePayload(
    rawFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    guestChannelTerminated: Bool,
    vmStarted: Bool,
    vmStopped: Bool,
    cloneDestroyed: Bool,
    storageDeviceCount: UInt64,
    observedTerminal: String = "observation_complete"
) throws -> LinuxVzHostEvidencePayload {
    try makeLinuxVzHostEvidencePayload(
        rawFrameCount: rawFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        guestChannelTerminated: guestChannelTerminated,
        vmStarted: vmStarted,
        vmStopped: vmStopped,
        cloneDestroyed: cloneDestroyed,
        storageDeviceCount: storageDeviceCount,
        observedTerminal: observedTerminal,
        channelRequestFrameBytes: nil,
        vmStopRequestFrameBytes: nil
    )
}

public func makeLinuxVzChannelInterruptionHostEvidencePayload(
    requestFrameBytes: UInt64,
    rawFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    vmStarted: Bool,
    vmStopped: Bool,
    cloneDestroyed: Bool,
    storageDeviceCount: UInt64
) throws -> LinuxVzHostEvidencePayload {
    try makeLinuxVzHostEvidencePayload(
        rawFrameCount: rawFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        guestChannelTerminated: true,
        vmStarted: vmStarted,
        vmStopped: vmStopped,
        cloneDestroyed: cloneDestroyed,
        storageDeviceCount: storageDeviceCount,
        observedTerminal: "infrastructure_error_with_teardown",
        channelRequestFrameBytes: requestFrameBytes,
        vmStopRequestFrameBytes: nil
    )
}

public func makeLinuxVzVmStopHostEvidencePayload(
    requestFrameBytes: UInt64,
    rawFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    vmStarted: Bool,
    vmStopped: Bool,
    cloneDestroyed: Bool,
    storageDeviceCount: UInt64
) throws -> LinuxVzHostEvidencePayload {
    try makeLinuxVzHostEvidencePayload(
        rawFrameCount: rawFrameCount,
        packetSensorHealthy: packetSensorHealthy,
        packetSensorTerminal: packetSensorTerminal,
        guestChannelTerminated: true,
        vmStarted: vmStarted,
        vmStopped: vmStopped,
        cloneDestroyed: cloneDestroyed,
        storageDeviceCount: storageDeviceCount,
        observedTerminal: "infrastructure_error_with_teardown",
        channelRequestFrameBytes: nil,
        vmStopRequestFrameBytes: requestFrameBytes
    )
}

private func makeLinuxVzHostEvidencePayload(
    rawFrameCount: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    guestChannelTerminated: Bool,
    vmStarted: Bool,
    vmStopped: Bool,
    cloneDestroyed: Bool,
    storageDeviceCount: UInt64,
    observedTerminal: String,
    channelRequestFrameBytes: UInt64?,
    vmStopRequestFrameBytes: UInt64?
) throws -> LinuxVzHostEvidencePayload {
    guard channelRequestFrameBytes == nil || vmStopRequestFrameBytes == nil else {
        throw LinuxVzHostEvidencePayloadError.invalidSchema
    }
    let events: [[String: String]] = [
        ["kind": "vm_started", "sequence": "1"],
        ["kind": "guest_channel_connected", "sequence": "2"],
        ["kind": "guest_channel_terminated", "sequence": "3"],
        ["kind": "host_packet_sensor_complete", "sequence": "4"],
        ["kind": "vm_stopped", "sequence": "5"],
        ["kind": "ephemeral_clone_destroyed", "sequence": "6"]
    ]
    var value: [String: Any] = [
        "clone_destroyed": cloneDestroyed,
        "dropped_frame_count": "0",
        "event_count": "6",
        "event_sequence_end": "6",
        "event_sequence_start": "1",
        "events": events,
        "evidence_truncated": false,
        "external_frames_forwarded": "0",
        "external_route_configured": false,
        "guest_channel_terminated": guestChannelTerminated,
        "heartbeat_count": "2",
        "package_execution": false,
        "packet_sensor_healthy": packetSensorHealthy,
        "packet_sensor_terminal": packetSensorTerminal,
        "raw_frame_count": String(rawFrameCount),
        "root_disk_present": false,
        "schema_version": linuxVzHostEvidencePayloadSchemaV1,
        "storage_device_count": String(storageDeviceCount),
        "sync_back": false,
        "vm_started": vmStarted,
        "vm_stopped": vmStopped
    ]
    if let channelRequestFrameBytes {
        value["channel_interruption_kind"] =
            "host_write_half_close_after_request_header"
        value["channel_request_frame_bytes"] = String(channelRequestFrameBytes)
        value["channel_response_bytes"] = "0"
        value["channel_transmitted_prefix_bytes"] = "16"
    }
    if let vmStopRequestFrameBytes {
        value["vm_stop_kind"] = "host_stop_after_guest_fixture_active"
        value["vm_stop_request_frame_bytes"] = String(vmStopRequestFrameBytes)
        value["vm_stop_transmitted_request_bytes"] = String(vmStopRequestFrameBytes)
        value["vm_stop_response_bytes"] = "0"
        value["vm_stop_fixture_active_marker_observed"] = true
    }
    return try decodeLinuxVzHostEvidencePayload(
        canonicalJSONData(value),
        observedTerminal: observedTerminal,
        expectedChannelRequestFrameBytes: channelRequestFrameBytes,
        expectedVmStopRequestFrameBytes: vmStopRequestFrameBytes
    )
}

public func decodeLinuxVzHostEvidencePayload(
    _ data: Data,
    observedTerminal: String = "observation_complete",
    expectedChannelRequestFrameBytes: UInt64? = nil,
    expectedVmStopRequestFrameBytes: UInt64? = nil
) throws -> LinuxVzHostEvidencePayload {
    guard !data.isEmpty else { throw LinuxVzHostEvidencePayloadError.empty }
    guard data.count <= maximumLinuxVzHostEvidencePayloadBytesV1 else {
        throw LinuxVzHostEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzHostEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzHostEvidencePayloadError.nonCanonical
    }
    guard observedTerminal == "observation_complete"
        || observedTerminal == "incomplete_on_injected_gap"
        || observedTerminal == "timeout_with_teardown"
        || observedTerminal == "infrastructure_error_with_teardown" else {
        throw LinuxVzHostEvidencePayloadError.invalidSchema
    }
    guard expectedChannelRequestFrameBytes == nil || expectedVmStopRequestFrameBytes == nil else {
        throw LinuxVzHostEvidencePayloadError.invalidSchema
    }
    var expectedKeys = Set([
        "clone_destroyed", "dropped_frame_count", "event_count", "event_sequence_end",
        "event_sequence_start", "events", "evidence_truncated", "external_frames_forwarded",
        "external_route_configured", "guest_channel_terminated", "heartbeat_count",
        "package_execution", "packet_sensor_healthy", "packet_sensor_terminal",
        "raw_frame_count", "root_disk_present", "schema_version", "storage_device_count",
        "sync_back", "vm_started", "vm_stopped"
    ])
    if expectedChannelRequestFrameBytes != nil {
        expectedKeys.formUnion([
            "channel_interruption_kind", "channel_request_frame_bytes",
            "channel_response_bytes", "channel_transmitted_prefix_bytes"
        ])
    }
    if expectedVmStopRequestFrameBytes != nil {
        expectedKeys.formUnion([
            "vm_stop_fixture_active_marker_observed", "vm_stop_kind",
            "vm_stop_request_frame_bytes", "vm_stop_response_bytes",
            "vm_stop_transmitted_request_bytes"
        ])
    }
    guard Set(value.keys) == expectedKeys,
    value["schema_version"] as? String == linuxVzHostEvidencePayloadSchemaV1,
    hostEvidenceDecimal(value["event_sequence_start"]) == 1,
    hostEvidenceDecimal(value["event_sequence_end"]) == 6,
    hostEvidenceDecimal(value["event_count"]) == 6,
    hostEvidenceDecimal(value["heartbeat_count"]) == 2,
    hostEvidenceDecimal(value["dropped_frame_count"]) == 0,
    hostEvidenceDecimal(value["external_frames_forwarded"]) == 0,
    let rawFrameCount = hostEvidenceDecimal(value["raw_frame_count"]),
    rawFrameCount == 0,
    hostEvidenceDecimal(value["storage_device_count"]) == 0,
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
    let events = value["events"] as? [[String: Any]],
    events.count == 6 else {
        throw LinuxVzHostEvidencePayloadError.invalidSchema
    }
    if let expectedChannelRequestFrameBytes {
        guard expectedChannelRequestFrameBytes > 16,
              value["channel_interruption_kind"] as? String ==
                "host_write_half_close_after_request_header",
              hostEvidenceDecimal(value["channel_request_frame_bytes"]) ==
                expectedChannelRequestFrameBytes,
              hostEvidenceDecimal(value["channel_response_bytes"]) == 0,
              hostEvidenceDecimal(value["channel_transmitted_prefix_bytes"]) == 16 else {
            throw LinuxVzHostEvidencePayloadError.invalidSchema
        }
    }
    if let expectedVmStopRequestFrameBytes {
        guard expectedVmStopRequestFrameBytes > 16,
              value["vm_stop_kind"] as? String ==
                "host_stop_after_guest_fixture_active",
              hostEvidenceDecimal(value["vm_stop_request_frame_bytes"]) ==
                expectedVmStopRequestFrameBytes,
              hostEvidenceDecimal(value["vm_stop_transmitted_request_bytes"]) ==
                expectedVmStopRequestFrameBytes,
              hostEvidenceDecimal(value["vm_stop_response_bytes"]) == 0,
              value["vm_stop_fixture_active_marker_observed"] as? Bool == true else {
            throw LinuxVzHostEvidencePayloadError.invalidSchema
        }
    }
    let expectedKinds = [
        "vm_started", "guest_channel_connected", "guest_channel_terminated",
        "host_packet_sensor_complete", "vm_stopped", "ephemeral_clone_destroyed"
    ]
    for (index, event) in events.enumerated() {
        guard Set(event.keys) == Set(["kind", "sequence"]),
              event["kind"] as? String == expectedKinds[index],
              hostEvidenceDecimal(event["sequence"]) == UInt64(index + 1) else {
            throw LinuxVzHostEvidencePayloadError.invalidEvent
        }
    }
    let claims = LinuxVzTelemetryHostObservationClaims(
        evidencePayloadSHA256: sha256(data),
        evidenceByteLength: UInt64(data.count),
        eventSequenceStart: 1,
        eventSequenceEnd: 6,
        eventCount: 6,
        heartbeatCount: 2,
        droppedFrameCount: 0,
        packetSensorHealthy: true,
        evidenceTruncated: false,
        guestChannelTerminated: true,
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        externalFramesForwarded: 0,
        observedTerminal: observedTerminal
    )
    return LinuxVzHostEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        rawFrameCount: rawFrameCount,
        channelInterruptionKind: value["channel_interruption_kind"] as? String,
        channelRequestFrameBytes: hostEvidenceDecimal(value["channel_request_frame_bytes"]),
        channelResponseBytes: hostEvidenceDecimal(value["channel_response_bytes"]),
        channelTransmittedPrefixBytes:
            hostEvidenceDecimal(value["channel_transmitted_prefix_bytes"]),
        vmStopKind: value["vm_stop_kind"] as? String,
        vmStopRequestFrameBytes: hostEvidenceDecimal(value["vm_stop_request_frame_bytes"]),
        vmStopTransmittedRequestBytes:
            hostEvidenceDecimal(value["vm_stop_transmitted_request_bytes"]),
        vmStopResponseBytes: hostEvidenceDecimal(value["vm_stop_response_bytes"]),
        vmStopFixtureActiveMarkerObserved:
            value["vm_stop_fixture_active_marker_observed"] as? Bool,
        claims: claims
    )
}

private func hostEvidenceDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
