import Foundation

public let linuxVzFileEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_file_evidence_payload.v1"
public let linuxVzFileEvidenceSerialPrefixV1 = "WHOATHERE_GUEST_FILE_EVIDENCE "

public enum LinuxVzFileEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
    case invalidEvent
}

public struct LinuxVzFileEvidencePayload: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let fixtureCase: String
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzFileEvidencePayload(
    _ serialData: Data
) throws -> LinuxVzFileEvidencePayload {
    let prefix = Array(linuxVzFileEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else { throw LinuxVzFileEvidencePayloadError.missing }
    guard payloads.count == 1 else { throw LinuxVzFileEvidencePayloadError.duplicate }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 64 * 1024 else {
        throw LinuxVzFileEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzFileEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzFileEvidencePayloadError.nonCanonical
    }
    guard Set(value.keys) == Set([
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "events", "evidence_truncated",
        "fanotify_permission_responses", "file_system_diff_complete", "fixture_case",
        "heartbeat_count", "mmap_bpf_correlated", "package_gid", "package_uid",
        "persistence_target", "raw_paths_captured", "schema_version", "sensor_healthy"
    ]),
    value["schema_version"] as? String == linuxVzFileEvidencePayloadSchemaV1,
    let fixtureCase = value["fixture_case"] as? String,
    ["protected_open_read_write_rename_delete", "mmap_access"].contains(fixtureCase),
    fileEvidenceDecimal(value["event_sequence_start"]) == 1,
    fileEvidenceDecimal(value["event_sequence_end"]) == 8,
    fileEvidenceDecimal(value["event_count"]) == 8,
    fileEvidenceDecimal(value["heartbeat_count"]) == 2,
    fileEvidenceDecimal(value["dropped_event_count"]) == 0,
    let permissionResponses = fileEvidenceDecimal(value["fanotify_permission_responses"]),
    permissionResponses >= 2,
    let packageUID = fileEvidenceDecimal(value["package_uid"]),
    let packageGID = fileEvidenceDecimal(value["package_gid"]),
    packageUID == 65534,
    packageGID == 65534,
    value["sensor_healthy"] as? Bool == true,
    value["evidence_truncated"] as? Bool == false,
    value["descendant_teardown_complete"] as? Bool == true,
    value["file_system_diff_complete"] as? Bool == true,
    value["mmap_bpf_correlated"] as? Bool == true,
    value["persistence_target"] as? String == "fake_user_startup",
    value["raw_paths_captured"] as? Bool == false,
    let events = value["events"] as? [[String: Any]],
    events.count == 8 else {
        throw LinuxVzFileEvidencePayloadError.invalidSchema
    }
    let expectedKinds = [
        "file_open", "file_read", "file_write", "file_rename", "file_delete",
        "file_mmap", "persistence_write", "file_system_diff"
    ]
    var actorPID: UInt64 = 0
    var cgroupID: UInt64 = 0
    var lastTimestamp: UInt64 = 0
    for (index, event) in events.enumerated() {
        guard Set(event.keys) == Set([
            "actor_pid", "cgroup_id", "kind", "sequence", "timestamp_ns"
        ]),
        event["kind"] as? String == expectedKinds[index],
        fileEvidenceDecimal(event["sequence"]) == UInt64(index + 1),
        let currentActor = fileEvidenceDecimal(event["actor_pid"]),
        let currentCgroup = fileEvidenceDecimal(event["cgroup_id"]),
        let timestamp = fileEvidenceDecimal(event["timestamp_ns"]),
        currentActor > 0,
        currentCgroup > 0,
        timestamp > lastTimestamp,
        index == 0 || (currentActor == actorPID && currentCgroup == cgroupID) else {
            throw LinuxVzFileEvidencePayloadError.invalidEvent
        }
        actorPID = currentActor
        cgroupID = currentCgroup
        lastTimestamp = timestamp
    }
    let claims = LinuxVzTelemetryGuestObservationClaims(
        evidencePayloadSHA256: sha256(payload),
        evidenceByteLength: UInt64(payload.count),
        eventSequenceStart: 1,
        eventSequenceEnd: 8,
        eventCount: 8,
        heartbeatCount: 2,
        droppedEventCount: 0,
        sensorHealthy: true,
        evidenceTruncated: false,
        descendantTeardownComplete: true,
        observedTerminal: "observation_complete"
    )
    return LinuxVzFileEvidencePayload(
        canonicalJSON: payload,
        payloadSHA256: claims.evidencePayloadSHA256,
        fixtureCase: fixtureCase,
        packageUID: packageUID,
        packageGID: packageGID,
        claims: claims
    )
}

private func fileEvidenceDecimal(_ value: Any?) -> UInt64? {
    guard let text = value as? String, !text.isEmpty,
          text == "0" || (
            text.first != "0" && text.utf8.allSatisfy { $0 >= 48 && $0 <= 57 }
          ) else {
        return nil
    }
    return UInt64(text)
}
