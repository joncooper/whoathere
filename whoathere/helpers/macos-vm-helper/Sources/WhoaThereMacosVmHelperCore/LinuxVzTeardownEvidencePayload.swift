import Foundation

public let linuxVzTeardownEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_teardown_evidence_payload.v1"
public let maximumLinuxVzTeardownEvidencePayloadBytesV1 = 64 * 1024
private let linuxVzTeardownEvidencePrefixV1 =
    Data("WHOATHERE_GUEST_TEARDOWN_EVIDENCE ".utf8)

public enum LinuxVzTeardownEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzTeardownEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let fixtureCase: String
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

private struct LinuxVzTeardownEvent {
    let actorPID: UInt64
    let cgroupID: UInt64
    let kind: String
    let sequence: UInt64
    let subjectPID: UInt64
    let timestampNS: UInt64
}

public func decodeLinuxVzTeardownEvidencePayloadV1(
    _ serial: Data
) throws -> LinuxVzTeardownEvidencePayload {
    var payload: Data?
    for rawLine in serial.split(separator: 0x0a, omittingEmptySubsequences: false) {
        var line = Data(rawLine)
        if line.last == 0x0d { line.removeLast() }
        guard line.starts(with: linuxVzTeardownEvidencePrefixV1) else { continue }
        guard payload == nil else { throw LinuxVzTeardownEvidencePayloadError.duplicate }
        payload = line.dropFirst(linuxVzTeardownEvidencePrefixV1.count)
    }
    guard let payload else { throw LinuxVzTeardownEvidencePayloadError.missing }
    return try decodeLinuxVzTeardownEvidenceJSONV1(payload)
}

public func decodeLinuxVzTeardownEvidenceJSONV1(
    _ data: Data
) throws -> LinuxVzTeardownEvidencePayload {
    guard !data.isEmpty, data.count <= maximumLinuxVzTeardownEvidencePayloadBytesV1 else {
        throw LinuxVzTeardownEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTeardownEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzTeardownEvidencePayloadError.nonCanonical
    }
    let baseKeys = Set([
        "cgroup_empty_after_reap", "cgroup_removed", "deadline_limit_ns", "deadline_reached",
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "fixture_case", "heartbeat_count", "kill_signal_count",
        "package_gid", "package_uid", "reaped_process_count", "schema_version",
        "sensor_healthy", "sensor_teardown_complete", "teardown_trigger",
        "termination_signal_count"
    ])
    guard let fixtureCase = value["fixture_case"] as? String else {
        throw LinuxVzTeardownEvidencePayloadError.invalidSchema
    }
    let expectedKeys: Set<String>
    let expectedKinds: [String]
    let observedTerminal: String
    switch fixtureCase {
    case "normal_exit":
        expectedKeys = baseKeys.union(["fixture_exit_status"])
        expectedKinds = ["fork", "exec", "exit"]
        observedTerminal = "observation_complete"
        guard value["teardown_trigger"] as? String == "natural_exit",
              teardownDecimal(value["deadline_limit_ns"]) == 5_000_000_000,
              value["deadline_reached"] as? Bool == false,
              teardownDecimal(value["fixture_exit_status"]) == 0,
              value["fixture_termination_signal"] == nil,
              value["term_grace_limit_ns"] == nil,
              value["term_grace_reached"] == nil,
              value["term_resistance_proven"] == nil,
              teardownDecimal(value["termination_signal_count"]) == 0,
              teardownDecimal(value["kill_signal_count"]) == 0 else {
            throw LinuxVzTeardownEvidencePayloadError.invalidSchema
        }
    case "timeout":
        expectedKeys = baseKeys.union(["fixture_termination_signal"])
        expectedKinds = ["fork", "exec", "signal_term", "exit"]
        observedTerminal = "timeout_with_teardown"
        guard value["teardown_trigger"] as? String == "deadline",
              teardownDecimal(value["deadline_limit_ns"]) == 1_000_000_000,
              value["deadline_reached"] as? Bool == true,
              value["fixture_exit_status"] == nil,
              teardownDecimal(value["fixture_termination_signal"]) == 15,
              value["term_grace_limit_ns"] == nil,
              value["term_grace_reached"] == nil,
              value["term_resistance_proven"] == nil,
              teardownDecimal(value["termination_signal_count"]) == 1,
              teardownDecimal(value["kill_signal_count"]) == 0 else {
            throw LinuxVzTeardownEvidencePayloadError.invalidSchema
        }
    case "term_resistance":
        expectedKeys = baseKeys.union([
            "fixture_termination_signal", "term_grace_limit_ns", "term_grace_reached",
            "term_resistance_proven"
        ])
        expectedKinds = ["fork", "exec", "signal_term", "signal_kill", "exit"]
        observedTerminal = "timeout_with_teardown"
        guard value["teardown_trigger"] as? String == "deadline",
              teardownDecimal(value["deadline_limit_ns"]) == 1_000_000_000,
              value["deadline_reached"] as? Bool == true,
              value["fixture_exit_status"] == nil,
              teardownDecimal(value["fixture_termination_signal"]) == 9,
              teardownDecimal(value["term_grace_limit_ns"]) == 250_000_000,
              value["term_grace_reached"] as? Bool == true,
              value["term_resistance_proven"] as? Bool == true,
              teardownDecimal(value["termination_signal_count"]) == 1,
              teardownDecimal(value["kill_signal_count"]) == 1 else {
            throw LinuxVzTeardownEvidencePayloadError.invalidSchema
        }
    case "escaped_session":
        expectedKeys = baseKeys.union([
            "fixture_termination_signal", "session_escape_count", "session_target"
        ])
        expectedKinds = ["fork", "exec", "setsid", "signal_term", "exit"]
        observedTerminal = "timeout_with_teardown"
        guard value["teardown_trigger"] as? String == "deadline",
              teardownDecimal(value["deadline_limit_ns"]) == 1_000_000_000,
              value["deadline_reached"] as? Bool == true,
              value["fixture_exit_status"] == nil,
              teardownDecimal(value["fixture_termination_signal"]) == 15,
              teardownDecimal(value["session_escape_count"]) == 1,
              value["session_target"] as? String == "new_session_leader_at_deadline",
              value["term_grace_limit_ns"] == nil,
              value["term_grace_reached"] == nil,
              value["term_resistance_proven"] == nil,
              teardownDecimal(value["termination_signal_count"]) == 1,
              teardownDecimal(value["kill_signal_count"]) == 0 else {
            throw LinuxVzTeardownEvidencePayloadError.invalidSchema
        }
    case "reparented_child":
        expectedKeys = baseKeys.union([
            "fixture_termination_signal", "fork_count", "reparent_target",
            "reparented_process_count"
        ])
        expectedKinds = ["exec", "fork", "reparent", "signal_term", "exit"]
        observedTerminal = "timeout_with_teardown"
        guard value["teardown_trigger"] as? String == "deadline",
              teardownDecimal(value["deadline_limit_ns"]) == 1_000_000_000,
              value["deadline_reached"] as? Bool == true,
              value["fixture_exit_status"] == nil,
              teardownDecimal(value["fixture_termination_signal"]) == 15,
              teardownDecimal(value["fork_count"]) == 2,
              teardownDecimal(value["reaped_process_count"]) == 2,
              value["reparent_target"] as? String == "protected_subreaper_at_deadline",
              teardownDecimal(value["reparented_process_count"]) == 1,
              value["session_escape_count"] == nil,
              value["session_target"] == nil,
              value["term_grace_limit_ns"] == nil,
              value["term_grace_reached"] == nil,
              value["term_resistance_proven"] == nil,
              teardownDecimal(value["termination_signal_count"]) == 1,
              teardownDecimal(value["kill_signal_count"]) == 0 else {
            throw LinuxVzTeardownEvidencePayloadError.invalidSchema
        }
    default:
        throw LinuxVzTeardownEvidencePayloadError.invalidSchema
    }
    let eventCount = UInt64(expectedKinds.count)
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzTeardownEvidencePayloadSchemaV1,
          value["descendant_teardown_complete"] as? Bool == true,
          value["cgroup_empty_after_reap"] as? Bool == true,
          value["cgroup_removed"] as? Bool == true,
          value["sensor_teardown_complete"] as? Bool == true,
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          teardownDecimal(value["reaped_process_count"]) ==
            (fixtureCase == "reparented_child" ? 2 : 1),
          teardownDecimal(value["event_sequence_start"]) == 1,
          teardownDecimal(value["event_sequence_end"]) == eventCount,
          teardownDecimal(value["event_count"]) == eventCount,
          teardownDecimal(value["heartbeat_count"]) == 2,
          teardownDecimal(value["dropped_event_count"]) == 0,
          teardownDecimal(value["package_uid"]) == 65534,
          teardownDecimal(value["package_gid"]) == 65534,
          let rawEvents = value["events"] as? [[String: Any]],
          rawEvents.count == expectedKinds.count else {
        throw LinuxVzTeardownEvidencePayloadError.invalidSchema
    }
    let events = try rawEvents.map(decodeLinuxVzTeardownEvent)
    guard events.map(\.kind) == expectedKinds,
          events.enumerated().allSatisfy({ $0.element.sequence == UInt64($0.offset + 1) }),
          events.allSatisfy({
              $0.actorPID > 0 && $0.subjectPID > 0 && $0.cgroupID > 0 && $0.timestampNS > 0
          }),
          events.dropFirst().allSatisfy({ $0.cgroupID == events[0].cgroupID }),
          zip(events, events.dropFirst()).allSatisfy({ pair in
              pair.0.timestampNS < pair.1.timestampNS
          }),
          fixtureCase == "reparented_child" ||
            events[0].actorPID != events[0].subjectPID else {
        throw LinuxVzTeardownEvidencePayloadError.invalidEvent
    }
    switch fixtureCase {
    case "normal_exit":
        guard events.dropFirst().allSatisfy({
            $0.actorPID == events[0].subjectPID && $0.subjectPID == events[0].subjectPID
        }) else {
            throw LinuxVzTeardownEvidencePayloadError.invalidEvent
        }
    case "timeout":
        guard events[1].actorPID == events[0].subjectPID,
              events[1].subjectPID == events[0].subjectPID,
              events[2].actorPID == events[0].actorPID,
              events[2].subjectPID == events[0].subjectPID,
              events[3].actorPID == events[0].subjectPID,
              events[3].subjectPID == events[0].subjectPID else {
            throw LinuxVzTeardownEvidencePayloadError.invalidEvent
        }
    case "term_resistance":
        guard events[1].actorPID == events[0].subjectPID,
              events[1].subjectPID == events[0].subjectPID,
              events[2].actorPID == events[0].actorPID,
              events[2].subjectPID == events[0].subjectPID,
              events[3].actorPID == events[0].actorPID,
              events[3].subjectPID == events[0].subjectPID,
              events[4].actorPID == events[0].subjectPID,
              events[4].subjectPID == events[0].subjectPID else {
            throw LinuxVzTeardownEvidencePayloadError.invalidEvent
        }
    case "escaped_session":
        guard events[1].actorPID == events[0].subjectPID,
              events[1].subjectPID == events[0].subjectPID,
              events[2].actorPID == events[0].subjectPID,
              events[2].subjectPID == events[0].subjectPID,
              events[3].actorPID == events[0].actorPID,
              events[3].subjectPID == events[0].subjectPID,
              events[4].actorPID == events[0].subjectPID,
              events[4].subjectPID == events[0].subjectPID else {
            throw LinuxVzTeardownEvidencePayloadError.invalidEvent
        }
    case "reparented_child":
        guard events[0].actorPID == events[0].subjectPID,
              events[1].actorPID == events[0].actorPID,
              events[1].subjectPID != events[0].actorPID,
              events[2].actorPID != events[0].actorPID,
              events[2].actorPID != events[1].subjectPID,
              events[2].subjectPID == events[1].subjectPID,
              events[3].actorPID == events[2].actorPID,
              events[3].subjectPID == events[1].subjectPID,
              events[4].actorPID == events[1].subjectPID,
              events[4].subjectPID == events[1].subjectPID else {
            throw LinuxVzTeardownEvidencePayloadError.invalidEvent
        }
    default:
        throw LinuxVzTeardownEvidencePayloadError.invalidSchema
    }
    let claims = LinuxVzTelemetryGuestObservationClaims(
        evidencePayloadSHA256: sha256(data),
        evidenceByteLength: UInt64(data.count),
        eventSequenceStart: 1,
        eventSequenceEnd: eventCount,
        eventCount: eventCount,
        heartbeatCount: 2,
        droppedEventCount: 0,
        sensorHealthy: true,
        evidenceTruncated: false,
        descendantTeardownComplete: true,
        observedTerminal: observedTerminal
    )
    return LinuxVzTeardownEvidencePayload(
        canonicalJSON: data,
        payloadSHA256: claims.evidencePayloadSHA256,
        fixtureCase: fixtureCase,
        packageUID: 65534,
        packageGID: 65534,
        claims: claims
    )
}

private func decodeLinuxVzTeardownEvent(
    _ value: [String: Any]
) throws -> LinuxVzTeardownEvent {
    guard Set(value.keys) == Set([
        "actor_pid", "cgroup_id", "kind", "sequence", "subject_pid", "timestamp_ns"
    ]),
    let actorPID = teardownDecimal(value["actor_pid"]),
    let cgroupID = teardownDecimal(value["cgroup_id"]),
    let kind = value["kind"] as? String,
    let sequence = teardownDecimal(value["sequence"]),
    let subjectPID = teardownDecimal(value["subject_pid"]),
    let timestampNS = teardownDecimal(value["timestamp_ns"]) else {
        throw LinuxVzTeardownEvidencePayloadError.invalidEvent
    }
    return LinuxVzTeardownEvent(
        actorPID: actorPID,
        cgroupID: cgroupID,
        kind: kind,
        sequence: sequence,
        subjectPID: subjectPID,
        timestampNS: timestampNS
    )
}

private func teardownDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
