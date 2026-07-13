import Foundation

public let linuxVzPackageRuntimeManifestSchemaV1 =
    "whoathere.linux_vz_package_runtime_manifest.v1"
public let maximumLinuxVzPackageRuntimeManifestBytesV1 = 64 * 1024

public enum LinuxVzPackageRuntimeManifestError: Error, Equatable,
    CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidBinding
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_package_runtime_manifest_empty"
        case .limitExceeded: return "linux_vz_package_runtime_manifest_limit_exceeded"
        case .invalidSchema: return "linux_vz_package_runtime_manifest_schema_invalid"
        case .invalidBinding: return "linux_vz_package_runtime_manifest_binding_invalid"
        case .nonCanonical: return "linux_vz_package_runtime_manifest_noncanonical"
        }
    }
}

public struct ParsedLinuxVzPackageRuntimeManifest: Equatable, Sendable {
    public let canonicalJSON: Data
    public let manifestSHA256: String
    public let rootfsSHA256: String
    public let rootfsByteLength: UInt64
    public let rootfsTarSHA256: String
    public let packageRunnerSHA256: String
    public let packageUID: UInt32
    public let packageGID: UInt32

    public var runtimeQualificationPermitted: Bool { true }
    public var packageExecutionPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func decodeLinuxVzPackageRuntimeManifest(
    _ data: Data
) throws -> ParsedLinuxVzPackageRuntimeManifest {
    guard !data.isEmpty else { throw LinuxVzPackageRuntimeManifestError.empty }
    guard data.count <= maximumLinuxVzPackageRuntimeManifestBytesV1 else {
        throw LinuxVzPackageRuntimeManifestError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzPackageRuntimeManifestError.invalidSchema
    }
    var expectedCanonical = try canonicalJSONData(value)
    expectedCanonical.append(0x0a)
    guard expectedCanonical == data else {
        throw LinuxVzPackageRuntimeManifestError.nonCanonical
    }
    let expectedKeys = Set([
        "architecture", "alpine_release", "builder_source_sha256",
        "candidate_runtime_qualification", "container_builder_source_sha256",
        "external_network", "image_state", "node_executable_sha256", "node_version",
        "npm_cli_sha256", "npm_version", "package_execution", "package_gid",
        "package_runner_mode", "package_runner_sha256", "package_uid",
        "pip_entrypoint_sha256", "pip_version", "python_executable_sha256",
        "python_version", "reproducible_epoch", "rootfs_byte_length", "rootfs_format",
        "rootfs_sha256", "rootfs_tar_byte_length", "rootfs_tar_sha256", "rootfs_uuid",
        "runtime_container_arm64_image_id", "runtime_container_digest",
        "runtime_inputs_lock_sha256", "runtime_probe_source_sha256", "schema_version",
        "source_minirootfs_sha256", "sync_back", "zig_version"
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String == linuxVzPackageRuntimeManifestSchemaV1,
          value["architecture"] as? String == "aarch64",
          value["alpine_release"] as? String == "3.24.1",
          value["candidate_runtime_qualification"] as? String == "required",
          value["external_network"] as? String == "structurally_absent",
          value["image_state"] as? String
            == "candidate_exact_bytes_not_yet_independently_qualified",
          value["node_version"] as? String == "v24.17.0",
          value["npm_version"] as? String == "11.12.1",
          value["pip_version"] as? String == "26.1.2",
          value["python_version"] as? String == "3.14.5",
          value["package_execution"] as? Bool == false,
          value["package_runner_mode"] as? String == "nonexecuting_runtime_probe_only",
          value["package_uid"] as? String == "65534",
          value["package_gid"] as? String == "65534",
          value["reproducible_epoch"] as? String == "1783900800",
          value["rootfs_format"] as? String == "raw_ext2_block_image_v1",
          value["rootfs_uuid"] as? String == "57484f41-5448-4552-5254-554e54494d45",
          value["runtime_container_arm64_image_id"] as? String
            == "sha256:1991bd789d7184290c3cce84fd6af068b8b745e9bddf178661ce7f5ecf68135c",
          value["runtime_container_digest"] as? String
            == "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
          value["source_minirootfs_sha256"] as? String
            == "sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
          value["sync_back"] as? Bool == false,
          value["zig_version"] as? String == "0.15.2",
          let rootfsLengthText = value["rootfs_byte_length"] as? String,
          let rootfsByteLength = linuxVzPackageRuntimeUInt64(rootfsLengthText),
          rootfsByteLength <= 64 * 1024 * 1024 * 1024,
          let rootfsTarLengthText = value["rootfs_tar_byte_length"] as? String,
          linuxVzPackageRuntimeUInt64(rootfsTarLengthText) != nil else {
        throw LinuxVzPackageRuntimeManifestError.invalidSchema
    }

    let digestKeys = [
        "builder_source_sha256", "container_builder_source_sha256",
        "node_executable_sha256", "npm_cli_sha256", "package_runner_sha256",
        "pip_entrypoint_sha256", "python_executable_sha256", "rootfs_sha256",
        "rootfs_tar_sha256", "runtime_container_arm64_image_id",
        "runtime_container_digest", "runtime_inputs_lock_sha256",
        "runtime_probe_source_sha256", "source_minirootfs_sha256"
    ]
    var digests: [String: String] = [:]
    for key in digestKeys {
        guard let digest = value[key] as? String,
              linuxVzPackageRuntimeValidDigest(digest) else {
            throw LinuxVzPackageRuntimeManifestError.invalidBinding
        }
        digests[key] = digest
    }
    let boundDigests = [
        digests["rootfs_sha256"]!, digests["rootfs_tar_sha256"]!,
        digests["package_runner_sha256"]!
    ]
    guard !boundDigests.contains(sha256(Data())),
          Set(boundDigests).count == boundDigests.count else {
        throw LinuxVzPackageRuntimeManifestError.invalidBinding
    }
    return ParsedLinuxVzPackageRuntimeManifest(
        canonicalJSON: data,
        manifestSHA256: sha256(data),
        rootfsSHA256: digests["rootfs_sha256"]!,
        rootfsByteLength: rootfsByteLength,
        rootfsTarSHA256: digests["rootfs_tar_sha256"]!,
        packageRunnerSHA256: digests["package_runner_sha256"]!,
        packageUID: 65_534,
        packageGID: 65_534
    )
}

private func linuxVzPackageRuntimeValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func linuxVzPackageRuntimeUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(value), parsed > 0 else {
        return nil
    }
    return parsed
}
