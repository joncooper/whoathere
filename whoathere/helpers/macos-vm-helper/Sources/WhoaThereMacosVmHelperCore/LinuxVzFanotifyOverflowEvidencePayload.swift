import Foundation

public let linuxVzFanotifyOverflowEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_fanotify_overflow_evidence_payload.v1"
public let maximumLinuxVzFanotifyOverflowEvidencePayloadBytesV1 = 64 * 1024
private let linuxVzFanotifyOverflowEvidencePrefixV1 =
    Data("WHOATHERE_GUEST_FANOTIFY_OVERFLOW_EVIDENCE ".utf8)

public enum LinuxVzFanotifyOverflowEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzFanotifyOverflowEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let fixtureCase: String
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let droppedEventCount: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzFanotifyOverflowEvidencePayloadV1(
    _ serial: Data
) throws -> LinuxVzFanotifyOverflowEvidencePayload {
    var payload: Data?
    for rawLine in serial.split(separator: 0x0a, omittingEmptySubsequences: false) {
        var line = Data(rawLine)
        if line.last == 0x0d { line.removeLast() }
        guard line.starts(with: linuxVzFanotifyOverflowEvidencePrefixV1) else { continue }
        guard payload == nil else {
            throw LinuxVzFanotifyOverflowEvidencePayloadError.duplicate
        }
        payload = line.dropFirst(linuxVzFanotifyOverflowEvidencePrefixV1.count)
    }
    guard let payload else { throw LinuxVzFanotifyOverflowEvidencePayloadError.missing }
    return try decodeLinuxVzFanotifyOverflowEvidenceJSONV1(payload)
}

public func decodeLinuxVzFanotifyOverflowEvidenceJSONV1(
    _ data: Data
) throws -> LinuxVzFanotifyOverflowEvidencePayload {
    guard !data.isEmpty,
          data.count <= maximumLinuxVzFanotifyOverflowEvidencePayloadBytesV1 else {
        throw LinuxVzFanotifyOverflowEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzFanotifyOverflowEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzFanotifyOverflowEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "fanotify_observed_event_count", "fanotify_overflow_marker_count",
        "fanotify_queue_limit_injected", "fanotify_queue_limit_original",
        "fanotify_queue_limit_restored", "fanotify_trigger_count",
        "fanotify_unique_inode_count", "fixture_case", "heartbeat_count", "injection_kind",
        "package_gid", "package_uid", "schema_version", "sensor_healthy"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzFanotifyOverflowEvidencePayloadSchemaV1,
          value["fixture_case"] as? String == "fanotify_queue_overflow",
          value["injection_kind"] as? String == "fanotify_queue_limit_exhaustion",
          fanotifyOverflowDecimal(value["event_sequence_start"]) == 1,
          fanotifyOverflowDecimal(value["event_sequence_end"]) == 1,
          fanotifyOverflowDecimal(value["event_count"]) == 1,
          fanotifyOverflowDecimal(value["heartbeat_count"]) == 2,
          let injected = fanotifyOverflowDecimal(value["fanotify_queue_limit_injected"]),
          injected == 64,
          let original = fanotifyOverflowDecimal(value["fanotify_queue_limit_original"]),
          original >= injected,
          let triggers = fanotifyOverflowDecimal(value["fanotify_trigger_count"]),
          triggers == 256,
          fanotifyOverflowDecimal(value["fanotify_unique_inode_count"]) == triggers,
          let observed = fanotifyOverflowDecimal(value["fanotify_observed_event_count"]),
          observed == injected,
          let dropped = fanotifyOverflowDecimal(value["dropped_event_count"]),
          dropped == 192,
          observed.addingReportingOverflow(dropped) == (triggers, false),
          fanotifyOverflowDecimal(value["fanotify_overflow_marker_count"]) == 1,
          value["fanotify_queue_limit_restored"] as? Bool == true,
          fanotifyOverflowDecimal(value["package_uid"]) == 65534,
          fanotifyOverflowDecimal(value["package_gid"]) == 65534,
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          value["descendant_teardown_complete"] as? Bool == true,
          let events = value["events"] as? [[String: Any]], events.count == 1 else {
        throw LinuxVzFanotifyOverflowEvidencePayloadError.invalidSchema
    }
    let event = events[0]
    guard Set(event.keys) == Set(["actor_pid", "kind", "sequence", "timestamp_ns"]),
          event["kind"] as? String == "fanotify_queue_overflow",
          fanotifyOverflowDecimal(event["sequence"]) == 1,
          let actor = fanotifyOverflowDecimal(event["actor_pid"]), actor > 0,
          let timestamp = fanotifyOverflowDecimal(event["timestamp_ns"]), timestamp > 0 else {
        throw LinuxVzFanotifyOverflowEvidencePayloadError.invalidEvent
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
    return LinuxVzFanotifyOverflowEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        fixtureCase: "fanotify_queue_overflow",
        packageUID: 65534,
        packageGID: 65534,
        droppedEventCount: dropped,
        claims: claims
    )
}

private func fanotifyOverflowDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
