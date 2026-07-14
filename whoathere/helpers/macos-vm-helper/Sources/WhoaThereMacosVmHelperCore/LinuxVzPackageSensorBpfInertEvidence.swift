import Foundation

public let linuxVzPackageSensorBpfInertEvidenceSchemaV1 =
    "whoathere.linux_vz_package_sensor_bpf_inert_probe.v1"
public let linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1 =
    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_EVIDENCE "

public let linuxVzPackageSensorBpfInertRequiredMarkersV1 = [
    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_BEGIN",
    "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
    "WHOATHERE_CAPABILITY architecture=aarch64",
    "WHOATHERE_CAPABILITY cgroup_v2=mounted",
    "WHOATHERE_CAPABILITY bpf_fs=mounted",
    "WHOATHERE_CAPABILITY tracefs=mounted",
    "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_OK",
    "WHOATHERE_CAPABILITY inert_fixture_execution=true",
    "WHOATHERE_CAPABILITY external_route_configured=false",
    "WHOATHERE_CAPABILITY package_execution=false",
    "WHOATHERE_CAPABILITY malware_execution=false",
    "WHOATHERE_CAPABILITY sync_back=false",
]

public enum LinuxVzPackageSensorBpfInertEvidenceError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
}

public struct LinuxVzPackageSensorBpfInertEvidenceV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let evidenceByteLength: UInt64
    public let cgroupID: UInt64
    public let fixturePID: UInt64
    public let fixtureSHA256: String
    public let tracepointFormatSHA256: [String: String]
}

public func decodeLinuxVzPackageSensorBpfInertEvidenceV1(
    _ serialData: Data,
    expectedFixtureSHA256: String
) throws -> LinuxVzPackageSensorBpfInertEvidenceV1 {
    guard packageSensorBpfInertDigest(expectedFixtureSHA256) else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema
    }
    let prefix = Array(linuxVzPackageSensorBpfInertEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.missing
    }
    guard payloads.count == 1 else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.duplicate
    }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 16 * 1024 else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.nonCanonical
    }
    let expectedKeys = Set([
        "attachment_cpu", "attachment_scope", "cgroup_id", "discarded_record_count",
        "dropped_event_count", "event_count", "event_kinds", "event_sequence_end",
        "event_sequence_start", "fixture_exit_status", "fixture_pid", "fixture_sha256",
        "malware_execution", "online_cpus", "package_execution", "package_gid",
        "package_uid", "schema_version", "sync_back", "tracepoint_format_sha256",
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzPackageSensorBpfInertEvidenceSchemaV1,
          value["attachment_cpu"] as? String == "0",
          value["attachment_scope"] as? String == "tracepoint_wide",
          packageSensorBpfInertDecimal(value["discarded_record_count"]) == 0,
          packageSensorBpfInertDecimal(value["dropped_event_count"]) == 0,
          packageSensorBpfInertDecimal(value["event_count"]) == 2,
          value["event_kinds"] as? [String] == ["exec", "exit"],
          packageSensorBpfInertDecimal(value["event_sequence_start"]) == 1,
          packageSensorBpfInertDecimal(value["event_sequence_end"]) == 2,
          packageSensorBpfInertDecimal(value["fixture_exit_status"]) == 0,
          let cgroupID = packageSensorBpfInertDecimal(value["cgroup_id"]),
          cgroupID > 0,
          let fixturePID = packageSensorBpfInertDecimal(value["fixture_pid"]),
          fixturePID >= 2, fixturePID <= UInt64(Int32.max),
          value["fixture_sha256"] as? String == expectedFixtureSHA256,
          value["malware_execution"] as? Bool == false,
          value["online_cpus"] as? [String] == ["0", "1"],
          value["package_execution"] as? Bool == false,
          packageSensorBpfInertDecimal(value["package_gid"]) == 65534,
          packageSensorBpfInertDecimal(value["package_uid"]) == 65534,
          value["sync_back"] as? Bool == false,
          let tracepoints = value["tracepoint_format_sha256"] as? [String: String],
          Set(tracepoints.keys) == Set([
              "sched_process_exec", "sched_process_exit", "sched_process_fork",
          ]),
          tracepoints.values.allSatisfy(packageSensorBpfInertDigest),
          Set(tracepoints.values).count == tracepoints.count else {
        throw LinuxVzPackageSensorBpfInertEvidenceError.invalidSchema
    }
    return LinuxVzPackageSensorBpfInertEvidenceV1(
        canonicalJSON: payload,
        payloadSHA256: sha256(payload),
        evidenceByteLength: UInt64(payload.count),
        cgroupID: cgroupID,
        fixturePID: fixturePID,
        fixtureSHA256: expectedFixtureSHA256,
        tracepointFormatSHA256: tracepoints
    )
}

public func linuxVzPackageSensorBpfInertMissingMarkersV1(_ serialData: Data) -> [String] {
    let lines = packageSensorBpfInertSerialLines(serialData)
    return linuxVzPackageSensorBpfInertRequiredMarkersV1.filter { !lines.contains($0) }
}

public func linuxVzPackageSensorBpfInertFailurePresentV1(_ serialData: Data) -> Bool {
    packageSensorBpfInertSerialLines(serialData).contains { line in
        line == "WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAILED"
            || line.hasPrefix("WHOATHERE_PACKAGE_SENSOR_BPF_INERT_FAILED ")
    }
}

private func packageSensorBpfInertSerialLines(_ serialData: Data) -> Set<String> {
    Set(serialData.split(separator: 0x0A).map { rawLine in
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        return String(decoding: line, as: UTF8.self)
    })
}

private func packageSensorBpfInertDecimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}

private func packageSensorBpfInertDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
