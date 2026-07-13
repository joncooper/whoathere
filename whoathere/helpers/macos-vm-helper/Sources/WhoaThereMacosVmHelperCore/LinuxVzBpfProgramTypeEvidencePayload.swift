import Foundation

public let linuxVzBpfProgramTypeEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_bpf_program_type_evidence_payload.v1"
public let linuxVzBpfProgramTypeEvidenceSerialPrefixV1 =
    "WHOATHERE_GUEST_BPF_PROGRAM_TYPE_EVIDENCE "

public enum LinuxVzBpfProgramTypeEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
}

public struct LinuxVzBpfProgramTypeEvidencePayloadV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let rawTracepointActorPID: UInt64
    public let rawTracepointCgroupID: UInt64
    public let rawTracepointProgramID: UInt64
    public let socketFilterProgramID: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzBpfProgramTypeEvidencePayloadV1(
    _ serialData: Data
) throws -> LinuxVzBpfProgramTypeEvidencePayloadV1 {
    let prefix = Array(linuxVzBpfProgramTypeEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else { throw LinuxVzBpfProgramTypeEvidencePayloadError.missing }
    guard payloads.count == 1 else { throw LinuxVzBpfProgramTypeEvidencePayloadError.duplicate }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 16 * 1024 else {
        throw LinuxVzBpfProgramTypeEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzBpfProgramTypeEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzBpfProgramTypeEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "descendant_teardown_complete", "dropped_event_count", "event_count",
        "event_sequence_end", "event_sequence_start", "evidence_truncated", "fixture_case",
        "heartbeat_count", "observation_map_type", "package_gid", "package_uid",
        "raw_tracepoint_actor_pid", "raw_tracepoint_attach_command",
        "raw_tracepoint_cgroup_id", "raw_tracepoint_name",
        "raw_tracepoint_observation_count", "raw_tracepoint_program_id",
        "raw_tracepoint_program_type", "raw_tracepoint_timestamp_ns",
        "resource_teardown_complete", "schema_version", "sensor_healthy",
        "socket_filter_attach_option", "socket_filter_input_bytes",
        "socket_filter_output_bytes", "socket_filter_program_id", "socket_filter_program_type"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzBpfProgramTypeEvidencePayloadSchemaV1,
          value["fixture_case"] as? String == "bpf_program_types",
          value["observation_map_type"] as? String == "BPF_MAP_TYPE_ARRAY",
          value["raw_tracepoint_attach_command"] as? String == "BPF_RAW_TRACEPOINT_OPEN",
          value["raw_tracepoint_name"] as? String == "sys_enter",
          value["raw_tracepoint_program_type"] as? String == "BPF_PROG_TYPE_RAW_TRACEPOINT",
          value["socket_filter_attach_option"] as? String == "SO_ATTACH_BPF",
          value["socket_filter_program_type"] as? String == "BPF_PROG_TYPE_SOCKET_FILTER",
          bpfProgramTypeEvidenceDecimal(value["event_sequence_start"]) == 1,
          bpfProgramTypeEvidenceDecimal(value["event_sequence_end"]) == 2,
          bpfProgramTypeEvidenceDecimal(value["event_count"]) == 2,
          bpfProgramTypeEvidenceDecimal(value["heartbeat_count"]) == 2,
          bpfProgramTypeEvidenceDecimal(value["dropped_event_count"]) == 0,
          bpfProgramTypeEvidenceDecimal(value["raw_tracepoint_observation_count"]) == 1,
          let timestamp = bpfProgramTypeEvidenceDecimal(value["raw_tracepoint_timestamp_ns"]),
          timestamp > 0,
          bpfProgramTypeEvidenceDecimal(value["socket_filter_input_bytes"]) == 8,
          bpfProgramTypeEvidenceDecimal(value["socket_filter_output_bytes"]) == 4,
          let packageUID = bpfProgramTypeEvidenceDecimal(value["package_uid"]),
          let packageGID = bpfProgramTypeEvidenceDecimal(value["package_gid"]),
          packageUID == 65534, packageGID == 65534,
          let actorPID = bpfProgramTypeEvidenceDecimal(value["raw_tracepoint_actor_pid"]),
          actorPID >= 2, actorPID <= UInt64(Int32.max),
          let cgroupID = bpfProgramTypeEvidenceDecimal(value["raw_tracepoint_cgroup_id"]),
          cgroupID > 0,
          let rawProgramID = bpfProgramTypeEvidenceDecimal(value["raw_tracepoint_program_id"]),
          rawProgramID > 0, rawProgramID <= UInt64(UInt32.max),
          let socketProgramID = bpfProgramTypeEvidenceDecimal(value["socket_filter_program_id"]),
          socketProgramID > 0, socketProgramID <= UInt64(UInt32.max),
          rawProgramID != socketProgramID,
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          value["descendant_teardown_complete"] as? Bool == true,
          value["resource_teardown_complete"] as? Bool == true else {
        throw LinuxVzBpfProgramTypeEvidencePayloadError.invalidSchema
    }
    return LinuxVzBpfProgramTypeEvidencePayloadV1(
        canonicalJSON: payload,
        payloadSHA256: sha256(payload),
        packageUID: packageUID,
        packageGID: packageGID,
        rawTracepointActorPID: actorPID,
        rawTracepointCgroupID: cgroupID,
        rawTracepointProgramID: rawProgramID,
        socketFilterProgramID: socketProgramID,
        claims: LinuxVzTelemetryGuestObservationClaims(
            evidencePayloadSHA256: sha256(payload),
            evidenceByteLength: UInt64(payload.count),
            eventSequenceStart: 1,
            eventSequenceEnd: 2,
            eventCount: 2,
            heartbeatCount: 2,
            droppedEventCount: 0,
            sensorHealthy: true,
            evidenceTruncated: false,
            descendantTeardownComplete: true,
            observedTerminal: "observation_complete"
        )
    )
}

private func bpfProgramTypeEvidenceDecimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}
