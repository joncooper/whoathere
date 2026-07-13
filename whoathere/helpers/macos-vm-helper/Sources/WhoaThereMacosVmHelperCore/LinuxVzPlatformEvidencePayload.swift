import Foundation

public let linuxVzPlatformEvidencePayloadSchemaV1 =
    "whoathere.linux_vz_platform_evidence_payload.v1"
public let linuxVzPlatformEvidenceSerialPrefixV1 =
    "WHOATHERE_GUEST_PLATFORM_EVIDENCE "

public enum LinuxVzPlatformEvidencePayloadError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
}

public struct LinuxVzPlatformEvidencePayloadV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let btfByteLength: UInt64
    public let packageUID: UInt64
    public let packageGID: UInt64
    public let claims: LinuxVzTelemetryGuestObservationClaims
}

public func decodeLinuxVzPlatformEvidencePayloadV1(
    _ serialData: Data,
    backend: UnqualifiedLinuxVzTelemetryBackendIdentity
) throws -> LinuxVzPlatformEvidencePayloadV1 {
    let prefix = Array(linuxVzPlatformEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else { throw LinuxVzPlatformEvidencePayloadError.missing }
    guard payloads.count == 1 else { throw LinuxVzPlatformEvidencePayloadError.duplicate }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 16 * 1024 else {
        throw LinuxVzPlatformEvidencePayloadError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzPlatformEvidencePayloadError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzPlatformEvidencePayloadError.nonCanonical
    }
    let expectedKeys = Set([
        "btf_byte_length", "descendant_teardown_complete", "dropped_event_count",
        "event_count", "event_sequence_end", "event_sequence_start", "evidence_truncated",
        "fixture_case", "heartbeat_count", "kernel_btf_magic", "kernel_btf_sha256",
        "kernel_config_binding", "kernel_config_sha256", "kernel_release", "package_gid",
        "package_uid", "schema_version", "sensor_healthy"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzPlatformEvidencePayloadSchemaV1,
          value["fixture_case"] as? String == "kernel_config_and_btf",
          value["kernel_release"] as? String == backend.kernelRelease,
          value["kernel_config_sha256"] as? String == backend.kernelConfigSHA256,
          value["kernel_config_binding"] as? String == "measured_backend_manifest",
          value["kernel_btf_sha256"] as? String == backend.btfSHA256,
          value["kernel_btf_magic"] as? String == "9feb",
          let btfByteLength = platformEvidenceDecimal(value["btf_byte_length"]),
          let packageUID = platformEvidenceDecimal(value["package_uid"]),
          let packageGID = platformEvidenceDecimal(value["package_gid"]),
          platformEvidenceDecimal(value["event_sequence_start"]) == 1,
          platformEvidenceDecimal(value["event_sequence_end"]) == 2,
          platformEvidenceDecimal(value["event_count"]) == 2,
          platformEvidenceDecimal(value["heartbeat_count"]) == 2,
          platformEvidenceDecimal(value["dropped_event_count"]) == 0,
          btfByteLength >= 24,
          packageUID == UInt64(backend.packageUID),
          packageGID == UInt64(backend.packageGID),
          value["sensor_healthy"] as? Bool == true,
          value["evidence_truncated"] as? Bool == false,
          value["descendant_teardown_complete"] as? Bool == true else {
        throw LinuxVzPlatformEvidencePayloadError.invalidSchema
    }
    return LinuxVzPlatformEvidencePayloadV1(
        canonicalJSON: payload,
        payloadSHA256: sha256(payload),
        btfByteLength: btfByteLength,
        packageUID: packageUID,
        packageGID: packageGID,
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

private func platformEvidenceDecimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}
