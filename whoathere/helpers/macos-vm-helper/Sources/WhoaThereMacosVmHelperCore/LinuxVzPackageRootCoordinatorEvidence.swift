import Foundation

public let linuxVzPackageRootCoordinatorEvidenceSchemaV1 =
    "whoathere.linux_vz_package_root_coordinator_probe.v1"
public let linuxVzPackageRootCoordinatorEvidenceSerialPrefixV1 =
    "WHOATHERE_PACKAGE_ROOT_COORDINATOR_EVIDENCE "

public let linuxVzPackageRootCoordinatorRequiredMarkersV1 = [
    "WHOATHERE_PACKAGE_ROOT_COORDINATOR_BEGIN",
    "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
    "WHOATHERE_CAPABILITY architecture=aarch64",
    "WHOATHERE_PACKAGE_ROOT_COORDINATOR_OK",
    "WHOATHERE_CAPABILITY external_route_configured=false",
    "WHOATHERE_CAPABILITY package_execution=false",
    "WHOATHERE_CAPABILITY malware_execution=false",
    "WHOATHERE_CAPABILITY sync_back=false",
]

public enum LinuxVzPackageRootCoordinatorEvidenceError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
}

public struct LinuxVzPackageRootCoordinatorEvidenceV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let probeSHA256: String
    public let publicKeySHA256: String
    public let servicePID: UInt64
    public let runnerPID: UInt64
    public let inheritableCapabilities: UInt64
    public let permittedCapabilities: UInt64
    public let effectiveCapabilities: UInt64
    public let boundingCapabilities: UInt64
    public let ambientCapabilities: UInt64
    public let openDescriptorCount: UInt64
    public let threadCount: UInt64
}

public func decodeLinuxVzPackageRootCoordinatorEvidenceV1(
    _ serialData: Data,
    expectedProbeSHA256: String,
    expectedPublicKeySHA256: String
) throws -> LinuxVzPackageRootCoordinatorEvidenceV1 {
    guard rootCoordinatorDigest(expectedProbeSHA256),
          rootCoordinatorDigest(expectedPublicKeySHA256) else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.invalidSchema
    }
    let prefix = Array(linuxVzPackageRootCoordinatorEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.missing
    }
    guard payloads.count == 1 else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.duplicate
    }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 8 * 1024 else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.nonCanonical
    }
    let expectedKeys = Set([
        "ambient_capabilities", "bounding_capabilities", "effective_capabilities",
        "inheritable_capabilities", "malware_execution", "no_new_privileges",
        "open_descriptor_count", "package_execution", "permitted_capabilities",
        "probe_sha256", "ptrace_capability_present", "root_credentials_verified",
        "runner_control_release_bound", "runner_exit_status",
        "runner_parent_death_signal_sigkill", "runner_pid", "runner_self_dumpable",
        "runner_seed_descriptor_closed", "runner_thread_count", "schema_version",
        "seed_byte_length", "seed_pipe_exact_eof", "seed_public_key_sha256",
        "seed_read_after_runner_boundary_verification", "service_dumpable", "service_pid",
        "sync_back", "tracer_absent", "unexpected_descriptor_count",
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String
            == linuxVzPackageRootCoordinatorEvidenceSchemaV1,
          value["probe_sha256"] as? String == expectedProbeSHA256,
          value["seed_public_key_sha256"] as? String == expectedPublicKeySHA256,
          rootCoordinatorBool(value["malware_execution"]) == false,
          rootCoordinatorBool(value["package_execution"]) == false,
          rootCoordinatorBool(value["ptrace_capability_present"]) == false,
          rootCoordinatorBool(value["runner_self_dumpable"]) == false,
          rootCoordinatorBool(value["service_dumpable"]) == false,
          rootCoordinatorBool(value["sync_back"]) == false,
          rootCoordinatorBool(value["no_new_privileges"]) == true,
          rootCoordinatorBool(value["root_credentials_verified"]) == true,
          rootCoordinatorBool(value["runner_control_release_bound"]) == true,
          rootCoordinatorBool(value["runner_parent_death_signal_sigkill"]) == true,
          rootCoordinatorBool(value["runner_seed_descriptor_closed"]) == true,
          rootCoordinatorBool(value["seed_pipe_exact_eof"]) == true,
          rootCoordinatorBool(value["seed_read_after_runner_boundary_verification"]) == true,
          rootCoordinatorBool(value["tracer_absent"]) == true,
          rootCoordinatorDecimal(value["open_descriptor_count"]) == 4,
          rootCoordinatorDecimal(value["runner_exit_status"]) == 0,
          rootCoordinatorDecimal(value["runner_thread_count"]) == 1,
          rootCoordinatorDecimal(value["seed_byte_length"]) == 32,
          rootCoordinatorDecimal(value["unexpected_descriptor_count"]) == 0,
          let servicePID = rootCoordinatorDecimal(value["service_pid"]), servicePID > 1,
          let runnerPID = rootCoordinatorDecimal(value["runner_pid"]), runnerPID > 1,
          servicePID != runnerPID,
          let inheritable = rootCoordinatorCapabilities(value["inheritable_capabilities"]),
          let permitted = rootCoordinatorCapabilities(value["permitted_capabilities"]),
          let effective = rootCoordinatorCapabilities(value["effective_capabilities"]),
          let bounding = rootCoordinatorCapabilities(value["bounding_capabilities"]),
          let ambient = rootCoordinatorCapabilities(value["ambient_capabilities"]),
          ambient == 0 else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.invalidSchema
    }
    let ptraceMask = UInt64(1) << 19
    guard inheritable & ptraceMask == 0, permitted & ptraceMask == 0,
          effective & ptraceMask == 0, bounding & ptraceMask == 0 else {
        throw LinuxVzPackageRootCoordinatorEvidenceError.invalidSchema
    }
    return LinuxVzPackageRootCoordinatorEvidenceV1(
        canonicalJSON: payload,
        payloadSHA256: sha256(payload),
        probeSHA256: expectedProbeSHA256,
        publicKeySHA256: expectedPublicKeySHA256,
        servicePID: servicePID,
        runnerPID: runnerPID,
        inheritableCapabilities: inheritable,
        permittedCapabilities: permitted,
        effectiveCapabilities: effective,
        boundingCapabilities: bounding,
        ambientCapabilities: ambient,
        openDescriptorCount: 4,
        threadCount: 1
    )
}

public func linuxVzPackageRootCoordinatorMissingMarkersV1(_ serialData: Data) -> [String] {
    let lines = rootCoordinatorSerialLines(serialData)
    return linuxVzPackageRootCoordinatorRequiredMarkersV1.filter { !lines.contains($0) }
}

public func linuxVzPackageRootCoordinatorFailurePresentV1(_ serialData: Data) -> Bool {
    rootCoordinatorSerialLines(serialData).contains { line in
        line == "WHOATHERE_PACKAGE_ROOT_COORDINATOR_FAILED"
            || line.hasPrefix("WHOATHERE_PACKAGE_ROOT_COORDINATOR_FAILED ")
    }
}

private func rootCoordinatorSerialLines(_ serialData: Data) -> Set<String> {
    Set(serialData.split(separator: 0x0A).map { rawLine in
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        return String(decoding: line, as: UTF8.self)
    })
}

private func rootCoordinatorBool(_ value: Any?) -> Bool? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
    return number.boolValue
}

private func rootCoordinatorDecimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
    return UInt64(value)
}

private func rootCoordinatorCapabilities(_ value: Any?) -> UInt64? {
    guard let value = value as? String, value.utf8.count == 16,
          value.utf8.allSatisfy({ byte in
              (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
          }) else { return nil }
    return UInt64(value, radix: 16)
}

private func rootCoordinatorDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
