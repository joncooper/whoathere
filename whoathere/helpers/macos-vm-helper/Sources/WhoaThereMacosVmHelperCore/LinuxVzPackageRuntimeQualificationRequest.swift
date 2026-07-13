import Foundation

public let linuxVzPackageRuntimeQualificationRequestSchemaV1 =
    "whoathere.macos_linux_vz_package_runtime_qualification_request.v1"
public let maximumLinuxVzPackageRuntimeQualificationRequestBytesV1 = 64 * 1024
public let linuxVzPackageRuntimeProbeReportV1 = Data(
    "{\"execution_authority\":false,\"package_execution\":false,\"schema_version\":\"whoathere.linux_vz_package_runtime_probe.v1\",\"status\":\"candidate_runtime_nonexecuting\",\"sync_back\":false}\n".utf8
)

public enum LinuxVzPackageRuntimeQualificationRequestError: Error, Equatable,
    CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidBinding
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_package_runtime_qualification_request_empty"
        case .limitExceeded:
            return "linux_vz_package_runtime_qualification_request_limit_exceeded"
        case .invalidSchema:
            return "linux_vz_package_runtime_qualification_request_schema_invalid"
        case .invalidBinding:
            return "linux_vz_package_runtime_qualification_request_binding_invalid"
        case .nonCanonical:
            return "linux_vz_package_runtime_qualification_request_noncanonical"
        }
    }
}

public struct ParsedLinuxVzPackageRuntimeQualificationRequest: Equatable, Sendable {
    public let canonicalJSON: Data
    public let requestSHA256: String
    public let qualifiedTelemetryBackendSHA256: String
    public let backendIdentitySHA256: String
    public let runtimeQualificationInitramfsSHA256: String
    public let runtimeQualificationGuestAgentSHA256: String
    public let runtimeQualificationGuestInitSHA256: String
    public let runtimeQualificationModuleBundleSHA256: String
    public let candidateRuntimeRootfsSHA256: String
    public let candidateRuntimeRootfsByteLength: UInt64
    public let candidateRuntimeManifestSHA256: String
    public let candidatePackageRunnerSHA256: String
    public let expectedProbeReportSHA256: String
    public let requestChallengeSHA256: String
    public let cloneBindingSHA256: String
    public let packageUID: UInt32
    public let packageGID: UInt32

    public var fixedNonexecutingProbePermitted: Bool { true }
    public var packageExecutionAuthorityPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func decodeLinuxVzPackageRuntimeQualificationRequest(
    _ data: Data
) throws -> ParsedLinuxVzPackageRuntimeQualificationRequest {
    guard !data.isEmpty else {
        throw LinuxVzPackageRuntimeQualificationRequestError.empty
    }
    guard data.count <= maximumLinuxVzPackageRuntimeQualificationRequestBytesV1 else {
        throw LinuxVzPackageRuntimeQualificationRequestError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzPackageRuntimeQualificationRequestError.invalidSchema
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzPackageRuntimeQualificationRequestError.nonCanonical
    }
    let expectedKeys = Set([
        "schema_version", "operation", "qualified_telemetry_backend_sha256",
        "backend_identity_sha256", "telemetry_requirements_sha256",
        "conformance_evidence_set_sha256", "kernel_image_sha256",
        "qualified_initramfs_sha256", "qualified_guest_signer_sha256",
        "qualified_protected_sensor_sha256", "guest_evidence_public_key_sha256",
        "host_evidence_public_key_sha256", "runtime_qualification_initramfs_sha256",
        "runtime_qualification_guest_agent_sha256", "runtime_qualification_guest_init_sha256",
        "runtime_qualification_module_bundle_sha256", "candidate_runtime_rootfs_sha256",
        "candidate_runtime_rootfs_byte_length", "candidate_runtime_manifest_sha256",
        "candidate_package_runner_sha256", "expected_probe_report_sha256",
        "protected_sensor_case", "package_runner_argument", "request_challenge_sha256",
        "clone_binding_sha256", "package_uid", "package_gid", "storage_policy",
        "network_policy", "directory_share_policy", "public_resolver_reachable",
        "nonexecuting_probe_permitted", "execution_authority_issued",
        "package_execution_permitted", "sync_back_policy"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String
            == linuxVzPackageRuntimeQualificationRequestSchemaV1,
          value["operation"] as? String == "fixed_nonexecuting_probe",
          value["protected_sensor_case"] as? String == "fork_exec_exit",
          value["package_runner_argument"] as? String == "fork_exec_exit",
          value["storage_policy"] as? String
            == "one_unique_writable_clone_destroy_after_vm_stop",
          value["network_policy"] as? String
            == "host_raw_frame_sinkhole_no_external_route",
          value["directory_share_policy"] as? String == "structurally_absent",
          value["public_resolver_reachable"] as? Bool == false,
          value["nonexecuting_probe_permitted"] as? Bool == true,
          value["execution_authority_issued"] as? Bool == false,
          value["package_execution_permitted"] as? Bool == false,
          value["sync_back_policy"] as? String == "structurally_absent",
          let rootfsByteLengthText = value["candidate_runtime_rootfs_byte_length"] as? String,
          let rootfsByteLength = linuxVzRuntimeQualificationUInt64(rootfsByteLengthText),
          rootfsByteLength <= 64 * 1024 * 1024 * 1024,
          let packageUIDText = value["package_uid"] as? String,
          let packageUID = linuxVzRuntimeQualificationUInt32(packageUIDText),
          let packageGIDText = value["package_gid"] as? String,
          let packageGID = linuxVzRuntimeQualificationUInt32(packageGIDText) else {
        throw LinuxVzPackageRuntimeQualificationRequestError.invalidSchema
    }

    let digestKeys = [
        "qualified_telemetry_backend_sha256", "backend_identity_sha256",
        "telemetry_requirements_sha256", "conformance_evidence_set_sha256",
        "kernel_image_sha256", "qualified_initramfs_sha256",
        "qualified_guest_signer_sha256", "qualified_protected_sensor_sha256",
        "guest_evidence_public_key_sha256", "host_evidence_public_key_sha256",
        "runtime_qualification_initramfs_sha256", "runtime_qualification_guest_agent_sha256",
        "runtime_qualification_guest_init_sha256", "runtime_qualification_module_bundle_sha256",
        "candidate_runtime_rootfs_sha256", "candidate_runtime_manifest_sha256",
        "candidate_package_runner_sha256", "expected_probe_report_sha256",
        "request_challenge_sha256", "clone_binding_sha256"
    ]
    var digests: [String: String] = [:]
    for key in digestKeys {
        guard let digest = value[key] as? String,
              linuxVzRuntimeQualificationValidDigest(digest) else {
            throw LinuxVzPackageRuntimeQualificationRequestError.invalidBinding
        }
        digests[key] = digest
    }

    let emptySHA256 = sha256(Data())
    let candidateDigests = [
        digests["candidate_runtime_rootfs_sha256"]!,
        digests["candidate_runtime_manifest_sha256"]!,
        digests["candidate_package_runner_sha256"]!
    ]
    let imageDigests = [
        digests["runtime_qualification_initramfs_sha256"]!,
        digests["runtime_qualification_guest_agent_sha256"]!,
        digests["runtime_qualification_guest_init_sha256"]!,
        digests["runtime_qualification_module_bundle_sha256"]!
    ]
    let cloneBinding = digests["clone_binding_sha256"]!
    guard !digests.values.contains(emptySHA256),
          !candidateDigests.contains(emptySHA256),
          Set(candidateDigests).count == candidateDigests.count,
          !imageDigests.contains(emptySHA256),
          Set(imageDigests).count == imageDigests.count,
          imageDigests[0] != digests["qualified_initramfs_sha256"],
          imageDigests[1] != digests["qualified_guest_signer_sha256"],
          imageDigests[3] != digests["qualified_protected_sensor_sha256"],
          cloneBinding != emptySHA256,
          cloneBinding != digests["request_challenge_sha256"],
          cloneBinding != candidateDigests[0],
          cloneBinding != imageDigests[0],
          digests["expected_probe_report_sha256"] == sha256(linuxVzPackageRuntimeProbeReportV1)
    else {
        throw LinuxVzPackageRuntimeQualificationRequestError.invalidBinding
    }

    return ParsedLinuxVzPackageRuntimeQualificationRequest(
        canonicalJSON: data,
        requestSHA256: sha256(data),
        qualifiedTelemetryBackendSHA256: digests["qualified_telemetry_backend_sha256"]!,
        backendIdentitySHA256: digests["backend_identity_sha256"]!,
        runtimeQualificationInitramfsSHA256: imageDigests[0],
        runtimeQualificationGuestAgentSHA256: imageDigests[1],
        runtimeQualificationGuestInitSHA256: imageDigests[2],
        runtimeQualificationModuleBundleSHA256: imageDigests[3],
        candidateRuntimeRootfsSHA256: candidateDigests[0],
        candidateRuntimeRootfsByteLength: rootfsByteLength,
        candidateRuntimeManifestSHA256: candidateDigests[1],
        candidatePackageRunnerSHA256: candidateDigests[2],
        expectedProbeReportSHA256: digests["expected_probe_report_sha256"]!,
        requestChallengeSHA256: digests["request_challenge_sha256"]!,
        cloneBindingSHA256: cloneBinding,
        packageUID: packageUID,
        packageGID: packageGID
    )
}

private func linuxVzRuntimeQualificationValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func linuxVzRuntimeQualificationUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(value), parsed > 0 else {
        return nil
    }
    return parsed
}

private func linuxVzRuntimeQualificationUInt32(_ value: String) -> UInt32? {
    guard !value.isEmpty, value.utf8.count <= 10,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt32(value), parsed > 0 else {
        return nil
    }
    return parsed
}
