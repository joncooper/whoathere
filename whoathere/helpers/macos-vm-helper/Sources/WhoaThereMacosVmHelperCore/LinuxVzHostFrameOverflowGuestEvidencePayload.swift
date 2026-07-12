import Foundation

public let linuxVzHostFrameOverflowGuestEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_host_frame_overflow_guest_evidence_payload.v1"
public let maximumLinuxVzHostFrameOverflowGuestEvidencePayloadBytesV1 = 64 * 1024
private let linuxVzHostFrameOverflowGuestEvidencePrefixV1 =
    Data("WHOATHERE_GUEST_HOST_FRAME_OVERFLOW_EVIDENCE ".utf8)

public enum LinuxVzHostFrameOverflowGuestEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzHostFrameOverflowGuestEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let fixtureCase: String
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let sourcePort: UInt16
    public let triggerCount: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzHostFrameOverflowGuestEvidencePayloadV1(
    _ serial: Data
) throws -> LinuxVzHostFrameOverflowGuestEvidencePayload {
    var payload: Data?
    for rawLine in serial.split(separator: 0x0a, omittingEmptySubsequences: false) {
        var line = Data(rawLine)
        if line.last == 0x0d { line.removeLast() }
        guard line.starts(with: linuxVzHostFrameOverflowGuestEvidencePrefixV1) else { continue }
        guard payload == nil else {
            throw LinuxVzHostFrameOverflowGuestEvidencePayloadError.duplicate
        }
        payload = line.dropFirst(linuxVzHostFrameOverflowGuestEvidencePrefixV1.count)
    }
    guard let payload else {
        throw LinuxVzHostFrameOverflowGuestEvidencePayloadError.missing
    }
    return try decodeLinuxVzHostFrameOverflowGuestEvidenceJSONV1(payload)
}

public func decodeLinuxVzHostFrameOverflowGuestEvidenceJSONV1(
    _ data: Data
) throws -> LinuxVzHostFrameOverflowGuestEvidencePayload {
    guard !data.isEmpty,
          data.count <= maximumLinuxVzHostFrameOverflowGuestEvidencePayloadBytesV1 else {
        throw LinuxVzHostFrameOverflowGuestEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzHostFrameOverflowGuestEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzHostFrameOverflowGuestEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "fixture_case", "heartbeat_count", "host_frame_payload_bytes",
        "host_frame_source_port", "host_frame_transmitted_count", "host_frame_trigger_count",
        "host_frame_tx_dropped_count", "host_frame_tx_error_count", "package_gid",
        "package_uid", "schema_version", "sensor_healthy", "traffic_kind"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String ==
              linuxVzHostFrameOverflowGuestEvidencePayloadSchemaV1,
          value["fixture_case"] as? String == "host_frame_overflow",
          value["traffic_kind"] as? String == "sequenced_udp_sinkhole_frames",
          hostFrameGuestDecimal(value["event_sequence_start"]) == 1,
          hostFrameGuestDecimal(value["event_sequence_end"]) == 1,
          hostFrameGuestDecimal(value["event_count"]) == 1,
          hostFrameGuestDecimal(value["heartbeat_count"]) == 2,
          hostFrameGuestDecimal(value["dropped_event_count"]) == 0,
          hostFrameGuestDecimal(value["host_frame_payload_bytes"]) == 16,
          let sourcePortValue = hostFrameGuestDecimal(value["host_frame_source_port"]),
          sourcePortValue > 0, sourcePortValue <= UInt64(UInt16.max),
          let triggerCount = hostFrameGuestDecimal(value["host_frame_trigger_count"]),
          triggerCount == 512,
          hostFrameGuestDecimal(value["host_frame_transmitted_count"]) == triggerCount,
          hostFrameGuestDecimal(value["host_frame_tx_dropped_count"]) == 0,
          hostFrameGuestDecimal(value["host_frame_tx_error_count"]) == 0,
          hostFrameGuestDecimal(value["package_uid"]) == 65534,
          hostFrameGuestDecimal(value["package_gid"]) == 65534,
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          value["descendant_teardown_complete"] as? Bool == true,
          let events = value["events"] as? [[String: Any]], events.count == 1 else {
        throw LinuxVzHostFrameOverflowGuestEvidencePayloadError.invalidSchema
    }
    let event = events[0]
    guard Set(event.keys) == Set(["actor_pid", "kind", "sequence", "timestamp_ns"]),
          event["kind"] as? String == "host_frame_overflow_trigger",
          hostFrameGuestDecimal(event["sequence"]) == 1,
          let actor = hostFrameGuestDecimal(event["actor_pid"]), actor > 0,
          let timestamp = hostFrameGuestDecimal(event["timestamp_ns"]), timestamp > 0 else {
        throw LinuxVzHostFrameOverflowGuestEvidencePayloadError.invalidEvent
    }
    let claims = LinuxVzTelemetryGuestObservationClaims(
        evidencePayloadSHA256: sha256(data),
        evidenceByteLength: UInt64(data.count),
        eventSequenceStart: 1,
        eventSequenceEnd: 1,
        eventCount: 1,
        heartbeatCount: 2,
        droppedEventCount: 0,
        sensorHealthy: true,
        evidenceTruncated: false,
        descendantTeardownComplete: true,
        observedTerminal: "incomplete_on_injected_gap"
    )
    return LinuxVzHostFrameOverflowGuestEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        fixtureCase: "host_frame_overflow",
        packageUID: 65534,
        packageGID: 65534,
        sourcePort: UInt16(sourcePortValue),
        triggerCount: triggerCount,
        claims: claims
    )
}

private func hostFrameGuestDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
