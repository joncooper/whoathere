import Foundation

public let linuxVzPackageExecutionRuntimeQualificationEvidenceSchemaV1 =
    "whoathere.linux_vz_package_execution_runtime_qualification_probe.v1"
public let linuxVzPackageExecutionRuntimeQualificationEvidenceSerialPrefixV1 =
    "WHOATHERE_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_EVIDENCE "

public let linuxVzPackageExecutionRuntimeQualificationRequiredMarkersV1 = [
    "WHOATHERE_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_BEGIN",
    "WHOATHERE_CAPABILITY kernel_release=6.18.35-0-virt",
    "WHOATHERE_CAPABILITY architecture=aarch64",
    "WHOATHERE_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_OK",
    "WHOATHERE_CAPABILITY external_route_configured=false",
    "WHOATHERE_CAPABILITY package_execution=false",
    "WHOATHERE_CAPABILITY malware_execution=false",
    "WHOATHERE_CAPABILITY sync_back=false",
]

public enum LinuxVzPackageExecutionRuntimeQualificationEvidenceError: Error, Equatable {
    case missing
    case duplicate
    case limitExceeded
    case invalidJSON
    case nonCanonical
    case invalidSchema
}

public struct LinuxVzPackageExecutionRuntimeQualificationEvidenceV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let payloadSHA256: String
    public let runtimeSHA256: String
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

public func decodeLinuxVzPackageExecutionRuntimeQualificationEvidenceV1(
    _ serialData: Data,
    expectedRuntimeSHA256: String,
    expectedPublicKeySHA256: String
) throws -> LinuxVzPackageExecutionRuntimeQualificationEvidenceV1 {
    guard executionRuntimeQualificationDigest(expectedRuntimeSHA256),
          executionRuntimeQualificationDigest(expectedPublicKeySHA256) else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.invalidSchema
    }
    let prefix = Array(linuxVzPackageExecutionRuntimeQualificationEvidenceSerialPrefixV1.utf8)
    var payloads = [Data]()
    for rawLine in serialData.split(separator: 0x0A) {
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        guard line.starts(with: prefix) else { continue }
        payloads.append(Data(line.dropFirst(prefix.count)))
    }
    guard !payloads.isEmpty else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.missing
    }
    guard payloads.count == 1 else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.duplicate
    }
    let payload = payloads[0]
    guard !payload.isEmpty, payload.count <= 64 * 1024 else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: payload) as? [String: Any] else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.invalidJSON
    }
    guard try canonicalJSONData(value) == payload else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.nonCanonical
    }
    let expectedKeys = Set([
        "coordinator_split_exercised", "execution_authority_issued",
        "execution_grant_consumed", "execution_request_consumed",
        "fixed_execution_entrypoint_measured", "no_new_privileges", "package_execution",
        "ptrace_capability_present", "root_credentials_verified",
        "runner_ambient_capabilities", "runner_bounding_capabilities",
        "runner_control_release_bound", "runner_effective_capabilities", "runner_exit_status",
        "runner_inheritable_capabilities", "runner_open_descriptor_count",
        "runner_parent_death_signal_sigkill", "runner_permitted_capabilities", "runner_pid",
        "runner_seed_descriptor_closed", "runner_self_dumpable", "runner_thread_count",
        "runner_unexpected_descriptor_count", "runtime_sha256", "schema_version",
        "seed_byte_length", "seed_pipe_exact_eof", "seed_public_key_sha256",
        "seed_read_after_runner_boundary_verification", "service_dumpable", "service_pid",
        "sync_back", "tracer_absent",
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String
            == linuxVzPackageExecutionRuntimeQualificationEvidenceSchemaV1,
          value["runtime_sha256"] as? String == expectedRuntimeSHA256,
          value["seed_public_key_sha256"] as? String == expectedPublicKeySHA256,
          executionRuntimeQualificationBool(value["coordinator_split_exercised"]) == true,
          executionRuntimeQualificationBool(value["fixed_execution_entrypoint_measured"]) == true,
          executionRuntimeQualificationBool(value["execution_authority_issued"]) == false,
          executionRuntimeQualificationBool(value["execution_grant_consumed"]) == false,
          executionRuntimeQualificationBool(value["execution_request_consumed"]) == false,
          executionRuntimeQualificationBool(value["package_execution"]) == false,
          executionRuntimeQualificationBool(value["ptrace_capability_present"]) == false,
          executionRuntimeQualificationBool(value["runner_self_dumpable"]) == false,
          executionRuntimeQualificationBool(value["service_dumpable"]) == false,
          executionRuntimeQualificationBool(value["sync_back"]) == false,
          executionRuntimeQualificationBool(value["no_new_privileges"]) == true,
          executionRuntimeQualificationBool(value["root_credentials_verified"]) == true,
          executionRuntimeQualificationBool(value["runner_control_release_bound"]) == true,
          executionRuntimeQualificationBool(value["runner_parent_death_signal_sigkill"]) == true,
          executionRuntimeQualificationBool(value["runner_seed_descriptor_closed"]) == true,
          executionRuntimeQualificationBool(value["seed_pipe_exact_eof"]) == true,
          executionRuntimeQualificationBool(
            value["seed_read_after_runner_boundary_verification"]
          ) == true,
          executionRuntimeQualificationBool(value["tracer_absent"]) == true,
          executionRuntimeQualificationDecimal(value["runner_open_descriptor_count"]) == 4,
          executionRuntimeQualificationDecimal(value["runner_exit_status"]) == 0,
          executionRuntimeQualificationDecimal(value["runner_thread_count"]) == 1,
          executionRuntimeQualificationDecimal(value["seed_byte_length"]) == 32,
          executionRuntimeQualificationDecimal(value["runner_unexpected_descriptor_count"]) == 0,
          let servicePID = executionRuntimeQualificationDecimal(value["service_pid"]),
          servicePID > 1,
          let runnerPID = executionRuntimeQualificationDecimal(value["runner_pid"]), runnerPID > 1,
          servicePID != runnerPID,
          let inheritable = executionRuntimeQualificationCapabilities(
            value["runner_inheritable_capabilities"]
          ),
          let permitted = executionRuntimeQualificationCapabilities(
            value["runner_permitted_capabilities"]
          ),
          let effective = executionRuntimeQualificationCapabilities(
            value["runner_effective_capabilities"]
          ),
          let bounding = executionRuntimeQualificationCapabilities(
            value["runner_bounding_capabilities"]
          ),
          let ambient = executionRuntimeQualificationCapabilities(
            value["runner_ambient_capabilities"]
          ),
          ambient == 0 else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.invalidSchema
    }
    let ptraceMask = UInt64(1) << 19
    guard inheritable & ptraceMask == 0, permitted & ptraceMask == 0,
          effective & ptraceMask == 0, bounding & ptraceMask == 0 else {
        throw LinuxVzPackageExecutionRuntimeQualificationEvidenceError.invalidSchema
    }
    return LinuxVzPackageExecutionRuntimeQualificationEvidenceV1(
        canonicalJSON: payload,
        payloadSHA256: sha256(payload),
        runtimeSHA256: expectedRuntimeSHA256,
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

public func linuxVzPackageExecutionRuntimeQualificationMissingMarkersV1(
    _ serialData: Data
) -> [String] {
    let lines = executionRuntimeQualificationSerialLines(serialData)
    return linuxVzPackageExecutionRuntimeQualificationRequiredMarkersV1.filter {
        !lines.contains($0)
    }
}

public func linuxVzPackageExecutionRuntimeQualificationFailurePresentV1(
    _ serialData: Data
) -> Bool {
    executionRuntimeQualificationSerialLines(serialData).contains { line in
        line == "WHOATHERE_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_FAILED"
            || line.hasPrefix("WHOATHERE_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_FAILED ")
            || line.hasPrefix("WHOATHERE_PACKAGE_ROOT_RUNTIME_FAILED ")
    }
}

private func executionRuntimeQualificationSerialLines(_ serialData: Data) -> Set<String> {
    Set(serialData.split(separator: 0x0A).map { rawLine in
        var line = Array(rawLine)
        if line.last == 0x0D { line.removeLast() }
        return String(decoding: line, as: UTF8.self)
    })
}

private func executionRuntimeQualificationBool(_ value: Any?) -> Bool? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
    return number.boolValue
}

private func executionRuntimeQualificationDecimal(_ value: Any?) -> UInt64? {
    guard let value = value as? String, !value.isEmpty,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else { return nil }
    return UInt64(value)
}

private func executionRuntimeQualificationCapabilities(_ value: Any?) -> UInt64? {
    guard let value = value as? String, value.utf8.count == 16,
          value.utf8.allSatisfy({ byte in
              (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
          }) else { return nil }
    return UInt64(value, radix: 16)
}

private func executionRuntimeQualificationDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
