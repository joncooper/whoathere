import Foundation

public let linuxVzHostFrameOverflowHostEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_host_frame_overflow_host_evidence_payload.v1"
public let maximumLinuxVzHostFrameOverflowHostEvidencePayloadBytesV1 = 64 * 1024

public enum LinuxVzHostFrameOverflowHostEvidencePayloadError: Error, Equatable {
    case empty
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzHostFrameOverflowHostEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let droppedFrameCount: UInt64
    public let observedFrameCount: UInt64
    public let claims: LinuxVzTelemetryHostObservationClaims
}

public func makeLinuxVzHostFrameOverflowHostEvidencePayloadV1(
    triggerFrameCount: UInt64,
    ingressFrameCount: UInt64,
    observedFrameCount: UInt64,
    uniqueSequenceCount: UInt64,
    duplicateFrameCount: UInt64,
    unexpectedFrameCount: UInt64,
    sourcePort: UInt16,
    hostFrameQueueCapacity: UInt64,
    packetSensorHealthy: Bool,
    packetSensorTerminal: String,
    storageDeviceCount: UInt64
) throws -> LinuxVzHostFrameOverflowHostEvidencePayload {
    guard observedFrameCount <= triggerFrameCount else {
        throw LinuxVzHostFrameOverflowHostEvidencePayloadError.invalidSchema
    }
    let dropped = triggerFrameCount - observedFrameCount
    let events: [[String: String]] = [
        ["kind": "vm_started", "sequence": "1"],
        ["kind": "host_frame_queue_bounded", "sequence": "2"],
        ["kind": "guest_channel_connected", "sequence": "3"],
        ["kind": "guest_channel_terminated", "sequence": "4"],
        ["kind": "host_packet_sensor_incomplete", "sequence": "5"],
        ["kind": "vm_stopped", "sequence": "6"],
        ["kind": "ephemeral_clone_destroyed", "sequence": "7"]
    ]
    let value: [String: Any] = [
        "clone_destroyed": true,
        "dropped_frame_count": String(dropped),
        "duplicate_frame_count": String(duplicateFrameCount),
        "event_count": "7",
        "event_sequence_end": "7",
        "event_sequence_start": "1",
        "events": events,
        "evidence_truncated": false,
        "external_frames_forwarded": "0",
        "external_route_configured": false,
        "guest_channel_terminated": true,
        "guest_trigger_frame_count": String(triggerFrameCount),
        "heartbeat_count": "2",
        "host_frame_queue_capacity": String(hostFrameQueueCapacity),
        "ingress_frame_count": String(ingressFrameCount),
        "observed_frame_count": String(observedFrameCount),
        "package_execution": false,
        "packet_sensor_healthy": packetSensorHealthy,
        "packet_sensor_terminal": packetSensorTerminal,
        "raw_frame_count": String(observedFrameCount),
        "root_disk_present": false,
        "schema_version": linuxVzHostFrameOverflowHostEvidencePayloadSchemaV1,
        "source_port": String(sourcePort),
        "storage_device_count": String(storageDeviceCount),
        "sync_back": false,
        "unexpected_frame_count": String(unexpectedFrameCount),
        "unique_sequence_count": String(uniqueSequenceCount),
        "vm_started": true,
        "vm_stopped": true
    ]
    return try decodeLinuxVzHostFrameOverflowHostEvidencePayloadV1(canonicalJSONData(value))
}

public func decodeLinuxVzHostFrameOverflowHostEvidencePayloadV1(
    _ data: Data
) throws -> LinuxVzHostFrameOverflowHostEvidencePayload {
    guard !data.isEmpty else { throw LinuxVzHostFrameOverflowHostEvidencePayloadError.empty }
    guard data.count <= maximumLinuxVzHostFrameOverflowHostEvidencePayloadBytesV1 else {
        throw LinuxVzHostFrameOverflowHostEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzHostFrameOverflowHostEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzHostFrameOverflowHostEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "clone_destroyed", "dropped_frame_count", "duplicate_frame_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "external_frames_forwarded", "external_route_configured", "guest_channel_terminated",
        "guest_trigger_frame_count", "heartbeat_count", "host_frame_queue_capacity",
        "ingress_frame_count", "observed_frame_count", "package_execution", "packet_sensor_healthy",
        "packet_sensor_terminal", "raw_frame_count", "root_disk_present", "schema_version",
        "source_port", "storage_device_count", "sync_back", "unexpected_frame_count",
        "unique_sequence_count", "vm_started", "vm_stopped"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String ==
              linuxVzHostFrameOverflowHostEvidencePayloadSchemaV1,
          hostFrameHostDecimal(value["event_sequence_start"]) == 1,
          hostFrameHostDecimal(value["event_sequence_end"]) == 7,
          hostFrameHostDecimal(value["event_count"]) == 7,
          hostFrameHostDecimal(value["heartbeat_count"]) == 2,
          let triggers = hostFrameHostDecimal(value["guest_trigger_frame_count"]),
          triggers == 512,
          hostFrameHostDecimal(value["ingress_frame_count"]) == triggers,
          let observed = hostFrameHostDecimal(value["observed_frame_count"]),
          observed == 64,
          let dropped = hostFrameHostDecimal(value["dropped_frame_count"]),
          dropped == 448,
          observed.addingReportingOverflow(dropped) == (triggers, false),
          hostFrameHostDecimal(value["raw_frame_count"]) == observed,
          hostFrameHostDecimal(value["unique_sequence_count"]) == observed,
          hostFrameHostDecimal(value["duplicate_frame_count"]) == 0,
          hostFrameHostDecimal(value["unexpected_frame_count"]) == 0,
          hostFrameHostDecimal(value["host_frame_queue_capacity"]) == observed,
          let sourcePort = hostFrameHostDecimal(value["source_port"]),
          sourcePort > 0, sourcePort <= UInt64(UInt16.max),
          hostFrameHostDecimal(value["external_frames_forwarded"]) == 0,
          hostFrameHostDecimal(value["storage_device_count"]) == 0,
          value["packet_sensor_healthy"] as? Bool == true,
          value["packet_sensor_terminal"] as? String == "bounded_queue_overflow_accounted",
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
        throw LinuxVzHostFrameOverflowHostEvidencePayloadError.invalidSchema
    }
    let expectedKinds = [
        "vm_started", "host_frame_queue_bounded", "guest_channel_connected",
        "guest_channel_terminated", "host_packet_sensor_incomplete", "vm_stopped",
        "ephemeral_clone_destroyed"
    ]
    for (index, event) in events.enumerated() {
        guard Set(event.keys) == Set(["kind", "sequence"]),
              event["kind"] as? String == expectedKinds[index],
              hostFrameHostDecimal(event["sequence"]) == UInt64(index + 1) else {
            throw LinuxVzHostFrameOverflowHostEvidencePayloadError.invalidEvent
        }
    }
    let claims = LinuxVzTelemetryHostObservationClaims(
        evidencePayloadSHA256: sha256(data),
        evidenceByteLength: UInt64(data.count),
        eventSequenceStart: 1,
        eventSequenceEnd: 7,
        eventCount: 7,
        heartbeatCount: 2,
        droppedFrameCount: dropped,
        packetSensorHealthy: true,
        evidenceTruncated: false,
        guestChannelTerminated: true,
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        externalFramesForwarded: 0,
        observedTerminal: "incomplete_on_injected_gap"
    )
    return LinuxVzHostFrameOverflowHostEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        droppedFrameCount: dropped,
        observedFrameCount: observed,
        claims: claims
    )
}

private func hostFrameHostDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
