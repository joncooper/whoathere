import Foundation

public let linuxVzProcessEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_process_evidence_payload.v1"
public let linuxVzProcessEvidenceSerialPrefixV1 =
    "WHOATHERE_GUEST_PROCESS_EVIDENCE "

public enum LinuxVzProcessEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzProcessEvidencePayloadV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let evidenceByteLength: UInt64
    public let eventSequenceStart: UInt64
    public let eventSequenceEnd: UInt64
    public let eventCount: UInt64
    public let heartbeatCount: UInt64
    public let droppedEventCount: UInt64
    public let sensorHealthy: Bool
    public let evidenceTruncated: Bool
    public let descendantTeardownComplete: Bool
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let fixtureCase: String
}

private struct LinuxVzProcessEventV1 {
    let actorPID: UInt64
    let cgroupID: UInt64
    let kind: String
    let sequence: UInt64
    let subjectPID: UInt64
    let timestampNS: UInt64
}

public func decodeLinuxVzProcessEvidencePayloadV1(
    _ serialData: Data
) throws -> LinuxVzProcessEvidencePayloadV1 {
    let prefix = Array(linuxVzProcessEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else { throw LinuxVzProcessEvidencePayloadError.missing }
    guard payloads.count == 1 else { throw LinuxVzProcessEvidencePayloadError.duplicate }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 64 * 1024 else {
        throw LinuxVzProcessEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzProcessEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzProcessEvidencePayloadError.nonCanonical
    }
    let baseKeys = Set([
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "heartbeat_count", "package_gid", "package_uid", "schema_version", "sensor_healthy"
    ])
    let fixtureCase = value["fixture_case"] as? String ?? "fork_exec_exit"
    let expectedKeys: Set<String>
    let expectedKinds: [String]
    switch fixtureCase {
    case "fork_exec_exit":
        expectedKeys = baseKeys
        expectedKinds = ["fork", "exec", "exit"]
    case "host_sensor_death":
        expectedKeys = baseKeys.union(["fixture_case"])
        expectedKinds = ["fork", "exec", "exit"]
    case "all_protected_assets_denied":
        expectedKeys = baseKeys.union([
            "fixture_case", "protected_asset_count", "protected_asset_read_denied_count",
            "protected_asset_write_denied_count", "protected_assets"
        ])
        expectedKinds = ["fork", "exec", "exit"]
    case "double_fork_daemonization":
        expectedKeys = baseKeys.union([
            "exec_count", "exit_count", "fixture_case", "fork_count", "reaped_process_count"
        ])
        expectedKinds = ["exec", "fork", "exit"]
    case "reparenting":
        expectedKeys = baseKeys.union([
            "exec_count", "exit_count", "fixture_case", "fork_count", "reparent_target",
            "reparented_process_count", "reaped_process_count"
        ])
        expectedKinds = ["exec", "fork", "reparent", "exit"]
    case "setsid_escape":
        expectedKeys = baseKeys.union([
            "exec_count", "exit_count", "fixture_case", "fork_count", "reaped_process_count",
            "session_escape_count", "session_target"
        ])
        expectedKinds = ["fork", "exec", "setsid", "exit"]
    case "credential_change":
        expectedKeys = baseKeys.union([
            "credential_change_count", "credential_target", "exec_count", "exit_count",
            "fixture_case", "fork_count", "reaped_process_count"
        ])
        expectedKinds = ["fork", "setgroups", "setgid", "setuid", "exec", "exit"]
    case "dynamic_library_load":
        expectedKeys = baseKeys.union([
            "dynamic_library_load_count", "dynamic_library_target", "exec_count", "exit_count",
            "fixture_case", "fork_count", "reaped_process_count"
        ])
        expectedKinds = ["fork", "exec", "dynamic_library_load", "exit"]
    default:
        throw LinuxVzProcessEvidencePayloadError.invalidSchema
    }
    guard Set(value.keys) == expectedKeys,
    value["schema_version"] as? String == linuxVzProcessEvidencePayloadSchemaV1,
    value["sensor_healthy"] as? Bool == true,
    value["evidence_truncated"] as? Bool == false,
    value["descendant_teardown_complete"] as? Bool == true,
    let eventSequenceStart = decimalUInt64(value["event_sequence_start"]),
    let eventSequenceEnd = decimalUInt64(value["event_sequence_end"]),
    let eventCount = decimalUInt64(value["event_count"]),
    let heartbeatCount = decimalUInt64(value["heartbeat_count"]),
    let droppedEventCount = decimalUInt64(value["dropped_event_count"]),
    let packageUID = decimalUInt64(value["package_uid"]),
    let packageGID = decimalUInt64(value["package_gid"]),
    let rawEvents = value["events"] as? [[String: Any]],
    eventSequenceStart == 1,
    eventSequenceEnd == UInt64(expectedKinds.count),
    eventCount == UInt64(expectedKinds.count),
    heartbeatCount == 2,
    droppedEventCount == 0,
    packageUID == 65534,
    packageGID == 65534,
    rawEvents.count == expectedKinds.count else {
        throw LinuxVzProcessEvidencePayloadError.invalidSchema
    }
    if fixtureCase == "double_fork_daemonization" {
        guard decimalUInt64(value["fork_count"]) == 3,
              decimalUInt64(value["exec_count"]) == 1,
              decimalUInt64(value["exit_count"]) == 3,
              decimalUInt64(value["reaped_process_count"]) == 3 else {
            throw LinuxVzProcessEvidencePayloadError.invalidSchema
        }
    } else if fixtureCase == "reparenting" {
        guard decimalUInt64(value["fork_count"]) == 2,
              decimalUInt64(value["exec_count"]) == 1,
              decimalUInt64(value["exit_count"]) == 2,
              decimalUInt64(value["reaped_process_count"]) == 2,
              decimalUInt64(value["reparented_process_count"]) == 1,
              value["reparent_target"] as? String == "protected_subreaper" else {
            throw LinuxVzProcessEvidencePayloadError.invalidSchema
        }
    } else if fixtureCase == "setsid_escape" {
        guard decimalUInt64(value["fork_count"]) == 1,
              decimalUInt64(value["exec_count"]) == 1,
              decimalUInt64(value["exit_count"]) == 1,
              decimalUInt64(value["reaped_process_count"]) == 1,
              decimalUInt64(value["session_escape_count"]) == 1,
              value["session_target"] as? String == "new_session_leader" else {
            throw LinuxVzProcessEvidencePayloadError.invalidSchema
        }
    } else if fixtureCase == "credential_change" {
        guard decimalUInt64(value["credential_change_count"]) == 3,
              value["credential_target"] as? String ==
                "uid_65534_gid_65534_no_supplementary_groups",
              decimalUInt64(value["fork_count"]) == 1,
              decimalUInt64(value["exec_count"]) == 1,
              decimalUInt64(value["exit_count"]) == 1,
              decimalUInt64(value["reaped_process_count"]) == 1 else {
            throw LinuxVzProcessEvidencePayloadError.invalidSchema
        }
    } else if fixtureCase == "dynamic_library_load" {
        guard decimalUInt64(value["dynamic_library_load_count"]) == 1,
              value["dynamic_library_target"] as? String == "measured_inert_fixture_library",
              decimalUInt64(value["fork_count"]) == 1,
              decimalUInt64(value["exec_count"]) == 2,
              decimalUInt64(value["exit_count"]) == 1,
              decimalUInt64(value["reaped_process_count"]) == 1 else {
            throw LinuxVzProcessEvidencePayloadError.invalidSchema
        }
    } else if fixtureCase == "all_protected_assets_denied" {
        let expectedAssets = [
            "capability_probe", "guest_ed25519_seed", "guest_signer",
            "process_sensor_probe", "virtio_vsock_module",
            "virtio_vsock_transport_common_module", "virtio_vsock_transport_module"
        ]
        guard decimalUInt64(value["protected_asset_count"]) == 7,
              decimalUInt64(value["protected_asset_read_denied_count"]) == 7,
              decimalUInt64(value["protected_asset_write_denied_count"]) == 7,
              value["protected_assets"] as? [String] == expectedAssets else {
            throw LinuxVzProcessEvidencePayloadError.invalidSchema
        }
    }

    let events = try rawEvents.map(decodeLinuxVzProcessEventV1)
    guard events.map(\.kind) == expectedKinds,
          events.enumerated().allSatisfy({ $0.element.sequence == UInt64($0.offset + 1) }),
          events.allSatisfy({ $0.actorPID > 0 && $0.subjectPID > 0 && $0.cgroupID > 0 }),
          zip(events, events.dropFirst()).allSatisfy({ pair in
              pair.0.cgroupID == pair.1.cgroupID && pair.0.timestampNS < pair.1.timestampNS
          }) else {
        throw LinuxVzProcessEvidencePayloadError.invalidEvent
    }
    if fixtureCase == "fork_exec_exit" || fixtureCase == "host_sensor_death" ||
        fixtureCase == "all_protected_assets_denied" {
        guard events[0].actorPID != events[0].subjectPID,
              events[1].actorPID == events[0].subjectPID,
              events[1].subjectPID == events[0].subjectPID,
              events[2].actorPID == events[0].subjectPID,
              events[2].subjectPID == events[0].subjectPID else {
            throw LinuxVzProcessEvidencePayloadError.invalidEvent
        }
    } else if fixtureCase == "double_fork_daemonization" {
        guard events[0].actorPID == events[0].subjectPID,
              events[1].actorPID != events[1].subjectPID,
              events[2].actorPID == events[2].subjectPID,
              events[1].subjectPID == events[2].actorPID,
              events[0].actorPID != events[1].actorPID,
              events[0].actorPID != events[2].actorPID else {
            throw LinuxVzProcessEvidencePayloadError.invalidEvent
        }
    } else if fixtureCase == "reparenting" {
        guard events[0].actorPID == events[0].subjectPID,
              events[1].actorPID == events[0].actorPID,
              events[1].actorPID != events[1].subjectPID,
              events[2].actorPID != events[2].subjectPID,
              events[2].subjectPID == events[1].subjectPID,
              events[2].actorPID != events[0].actorPID,
              events[3].actorPID == events[3].subjectPID,
              events[3].actorPID == events[1].subjectPID else {
            throw LinuxVzProcessEvidencePayloadError.invalidEvent
        }
    } else if fixtureCase == "setsid_escape" {
        guard events[0].actorPID != events[0].subjectPID,
              events[1].actorPID == events[0].subjectPID,
              events[1].subjectPID == events[0].subjectPID,
              events[2].actorPID == events[0].subjectPID,
              events[2].subjectPID == events[0].subjectPID,
              events[3].actorPID == events[0].subjectPID,
              events[3].subjectPID == events[0].subjectPID else {
            throw LinuxVzProcessEvidencePayloadError.invalidEvent
        }
    } else if fixtureCase == "credential_change" {
        guard events[0].actorPID != events[0].subjectPID,
              events.dropFirst().allSatisfy({
                  $0.actorPID == events[0].subjectPID &&
                    $0.subjectPID == events[0].subjectPID
              }) else {
            throw LinuxVzProcessEvidencePayloadError.invalidEvent
        }
    } else {
        guard events[0].actorPID != events[0].subjectPID,
              events.dropFirst().allSatisfy({
                  $0.actorPID == events[0].subjectPID &&
                    $0.subjectPID == events[0].subjectPID
              }) else {
            throw LinuxVzProcessEvidencePayloadError.invalidEvent
        }
    }

    return LinuxVzProcessEvidencePayloadV1(
        canonicalJSON: payload,
        payloadSHA256: sha256(payload),
        evidenceByteLength: UInt64(payload.count),
        eventSequenceStart: eventSequenceStart,
        eventSequenceEnd: eventSequenceEnd,
        eventCount: eventCount,
        heartbeatCount: heartbeatCount,
        droppedEventCount: droppedEventCount,
        sensorHealthy: true,
        evidenceTruncated: false,
        descendantTeardownComplete: true,
        packageUID: packageUID,
        packageGID: packageGID,
        fixtureCase: fixtureCase
    )
}

private func decodeLinuxVzProcessEventV1(
    _ value: [String: Any]
) throws -> LinuxVzProcessEventV1 {
    guard Set(value.keys) == Set([
        "actor_pid", "cgroup_id", "kind", "sequence", "subject_pid", "timestamp_ns"
    ]),
    let actorPID = decimalUInt64(value["actor_pid"]),
    let cgroupID = decimalUInt64(value["cgroup_id"]),
    let kind = value["kind"] as? String,
    let sequence = decimalUInt64(value["sequence"]),
    let subjectPID = decimalUInt64(value["subject_pid"]),
    let timestampNS = decimalUInt64(value["timestamp_ns"]) else {
        throw LinuxVzProcessEvidencePayloadError.invalidEvent
    }
    return LinuxVzProcessEventV1(
        actorPID: actorPID,
        cgroupID: cgroupID,
        kind: kind,
        sequence: sequence,
        subjectPID: subjectPID,
        timestampNS: timestampNS
    )
}

private func decimalUInt64(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (text.first != "0" && text.allSatisfy(\.isNumber)) else {
        return nil
    }
    return UInt64(text)
}
