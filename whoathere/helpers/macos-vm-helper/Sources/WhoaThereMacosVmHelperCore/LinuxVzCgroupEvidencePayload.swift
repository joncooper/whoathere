import Foundation

public let linuxVzCgroupEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_cgroup_evidence_payload.v1"
public let linuxVzCgroupEvidenceSerialPrefixV1 =
    "WHOATHERE_GUEST_CGROUP_EVIDENCE "

public enum LinuxVzCgroupEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
}

public struct LinuxVzCgroupEvidencePayloadV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let controllers: [String]
    public let membershipPID: UInt64
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzCgroupEvidencePayloadV1(
    _ serialData: Data,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity
) throws -> LinuxVzCgroupEvidencePayloadV1 {
    let prefix = Array(linuxVzCgroupEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else { throw LinuxVzCgroupEvidencePayloadError.missing }
    guard payloads.count == 1 else { throw LinuxVzCgroupEvidencePayloadError.duplicate }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 16 * 1024 else {
        throw LinuxVzCgroupEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzCgroupEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzCgroupEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "cgroup2_filesystem_magic", "child_cgroup_created", "child_cgroup_name",
        "child_cgroup_removed", "child_cgroup_type", "child_empty_after_return",
        "child_membership_observed", "child_populated_observed", "controller_count",
        "controllers", "descendant_teardown_complete", "dropped_event_count",
        "event_count", "event_sequence_end", "event_sequence_start", "evidence_truncated",
        "fixture_case", "heartbeat_count", "membership_pid", "membership_process_binding",
        "mount_path", "mountinfo_filesystem", "package_gid", "package_uid",
        "schema_version", "sensor_healthy"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzCgroupEvidencePayloadSchemaV1,
          value["fixture_case"] as? String == "cgroup_v2",
          value["cgroup2_filesystem_magic"] as? String == "63677270",
          value["mount_path"] as? String == "/sys/fs/cgroup",
          value["mountinfo_filesystem"] as? String == "cgroup2",
          value["child_cgroup_name"] as? String == "whoathere-cgroup-v2-probe",
          value["child_cgroup_type"] as? String == "domain",
          value["child_cgroup_created"] as? Bool == true,
          value["child_membership_observed"] as? Bool == true,
          value["child_populated_observed"] as? Bool == true,
          value["child_empty_after_return"] as? Bool == true,
          value["child_cgroup_removed"] as? Bool == true,
          value["membership_process_binding"] as? String == "measured_guest_signer_process",
          let controllers = value["controllers"] as? [String],
          validCgroupControllers(controllers),
          let membershipPID = cgroupEvidenceDecimal(value["membership_pid"]),
          membershipPID > 1, membershipPID <= UInt64(UInt32.max),
          let packageUID = cgroupEvidenceDecimal(value["package_uid"]),
          let packageGID = cgroupEvidenceDecimal(value["package_gid"]),
          cgroupEvidenceDecimal(value["controller_count"]) == UInt64(controllers.count),
          cgroupEvidenceDecimal(value["event_sequence_start"]) == 1,
          cgroupEvidenceDecimal(value["event_sequence_end"]) == 5,
          cgroupEvidenceDecimal(value["event_count"]) == 5,
          cgroupEvidenceDecimal(value["heartbeat_count"]) == 2,
          cgroupEvidenceDecimal(value["dropped_event_count"]) == 0,
          packageUID == UInt64(backend.packageUID),
          packageGID == UInt64(backend.packageGID),
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          value["descendant_teardown_complete"] as? Bool == true else {
        throw LinuxVzCgroupEvidencePayloadError.invalidSchema
    }
    let payloadSHA256 = sha256(payload)
    return LinuxVzCgroupEvidencePayloadV1(
        canonicalJSON: payload,
        payloadSHA256: payloadSHA256,
        controllers: controllers,
        membershipPID: membershipPID,
        packageUID: packageUID,
        packageGID: packageGID,
        claims: LinuxVzTelemetryGuestObservationClaims(
            evidencePayloadSHA256: payloadSHA256,
            evidenceByteLength: UInt64(payload.count),
            eventSequenceStart: 1,
            eventSequenceEnd: 5,
            eventCount: 5,
            heartbeatCount: 2,
            droppedEventCount: 0,
            sensorHealthy: true,
            evidenceTruncated: false,
            descendantTeardownComplete: true,
            observedTerminal: "observation_complete"
        )
    )
}

private func validCgroupControllers(_ controllers: [String]) -> Bool {
    guard !controllers.isEmpty, controllers.count <= 64 else { return false }
    guard zip(controllers, controllers.dropFirst()).allSatisfy({ $0 < $1 }) else {
        return false
    }
    return controllers.allSatisfy { controller in
        !controller.isEmpty && controller.utf8.count <= 64
            && controller.utf8.allSatisfy { ($0 >= 97 && $0 <= 122) || $0 == 95 }
    }
}

private func cgroupEvidenceDecimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}
