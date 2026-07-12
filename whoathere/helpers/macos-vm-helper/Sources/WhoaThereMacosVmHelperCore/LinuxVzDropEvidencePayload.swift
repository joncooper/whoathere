import Foundation

public let linuxVzDropEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_drop_evidence_payload.v1"
public let maximumLinuxVzDropEvidencePayloadBytesV1 = 64 * 1024
private let linuxVzDropEvidencePrefixV1 = Data("WHOATHERE_GUEST_DROP_EVIDENCE ".utf8)

public enum LinuxVzDropEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzDropEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let fixtureCase: String
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let droppedEventCount: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzDropEvidencePayloadV1(
    _ serial: Data
) throws -> LinuxVzDropEvidencePayload {
    var payload: Data?
    for rawLine in serial.split(separator: 0x0a, omittingEmptySubsequences: false) {
        var line = Data(rawLine)
        if line.last == 0x0d { line.removeLast() }
        guard line.starts(with: linuxVzDropEvidencePrefixV1) else { continue }
        guard payload == nil else { throw LinuxVzDropEvidencePayloadError.duplicate }
        payload = line.dropFirst(linuxVzDropEvidencePrefixV1.count)
    }
    guard let payload else { throw LinuxVzDropEvidencePayloadError.missing }
    return try decodeLinuxVzDropEvidenceJSONV1(payload)
}

public func decodeLinuxVzDropEvidenceJSONV1(
    _ data: Data
) throws -> LinuxVzDropEvidencePayload {
    guard !data.isEmpty, data.count <= maximumLinuxVzDropEvidencePayloadBytesV1 else {
        throw LinuxVzDropEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzDropEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzDropEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "fixture_case", "heartbeat_count", "injection_kind", "package_gid", "package_uid",
        "reservation_attempt_count", "reservation_success_count", "ring_buffer_capacity_bytes",
        "schema_version", "sensor_healthy"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzDropEvidencePayloadSchemaV1,
          value["fixture_case"] as? String == "bpf_reservation_failure",
          value["injection_kind"] as? String == "ringbuf_reserve_exhaustion",
          dropEvidenceDecimal(value["event_sequence_start"]) == 1,
          dropEvidenceDecimal(value["event_sequence_end"]) == 1,
          dropEvidenceDecimal(value["event_count"]) == 1,
          dropEvidenceDecimal(value["heartbeat_count"]) == 2,
          dropEvidenceDecimal(value["ring_buffer_capacity_bytes"]) == 4096,
          dropEvidenceDecimal(value["reservation_attempt_count"]) == 2048,
          let dropped = dropEvidenceDecimal(value["dropped_event_count"]), dropped > 0,
          let successes = dropEvidenceDecimal(value["reservation_success_count"]), successes > 0,
          dropped.addingReportingOverflow(successes) == (2048, false),
          dropEvidenceDecimal(value["package_uid"]) == 65534,
          dropEvidenceDecimal(value["package_gid"]) == 65534,
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          value["descendant_teardown_complete"] as? Bool == true,
          let events = value["events"] as? [[String: Any]], events.count == 1 else {
        throw LinuxVzDropEvidencePayloadError.invalidSchema
    }
    let event = events[0]
    guard Set(event.keys) == Set(["actor_pid", "kind", "sequence", "timestamp_ns"]),
          event["kind"] as? String == "bpf_reservation_failure",
          dropEvidenceDecimal(event["sequence"]) == 1,
          let actor = dropEvidenceDecimal(event["actor_pid"]), actor > 0,
          let timestamp = dropEvidenceDecimal(event["timestamp_ns"]), timestamp > 0 else {
        throw LinuxVzDropEvidencePayloadError.invalidEvent
    }
    let claims = LinuxVzTelemetryGuestObservationClaims(
        evidencePayloadSHA256: sha256(data),
        evidenceByteLength: UInt64(data.count),
        eventSequenceStart: 1,
        eventSequenceEnd: 1,
        eventCount: 1,
        heartbeatCount: 2,
        droppedEventCount: dropped,
        sensorHealthy: true,
        evidenceTruncated: false,
        descendantTeardownComplete: true,
        observedTerminal: "incomplete_on_injected_gap"
    )
    return LinuxVzDropEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        fixtureCase: "bpf_reservation_failure",
        packageUID: 65534,
        packageGID: 65534,
        droppedEventCount: dropped,
        claims: claims
    )
}

private func dropEvidenceDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
