import Foundation

public let linuxVzPackageExecutionRuntimeQualificationImageManifestSchemaV1 =
    "whoathere.linux_vz_package_execution_runtime_rootfs_qualification_image_manifest.v1"
public let maximumLinuxVzPackageExecutionRuntimeQualificationImageManifestBytesV1 = 64 * 1024

public enum LinuxVzPackageExecutionRuntimeQualificationImageManifestError: Error, Equatable {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidBinding
    case nonCanonical
}

public struct ParsedLinuxVzPackageExecutionRuntimeQualificationImageManifest: Equatable,
    Sendable {
    public let canonicalJSON: Data
    public let manifestSHA256: String
    public let baseInitramfsSHA256: String
    public let builderSourceSHA256: String
    public let initramfsSHA256: String
    public let qualificationInitSHA256: String
    public let qualificationInitSourceSHA256: String
    public let overlayCPIOGzipSHA256: String
    public let overlayCPIOSHA256: String
    public let writerSourceSHA256: String
    public let runtimeManifestSHA256: String
    public let runtimeRootfsSHA256: String
    public let runtimeRootfsByteLength: UInt64
    public let packageRunnerSHA256: String
    public let nodeExecutableSHA256: String
    public let npmCLISHA256: String
    public let pythonExecutableSHA256: String
    public let pipEntrypointSHA256: String
    public let guestEvidencePublicKeySHA256: String

    public var executionAuthorityIssued: Bool { false }
    public var packageExecutionObserved: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func decodeLinuxVzPackageExecutionRuntimeQualificationImageManifest(
    _ data: Data,
    runtimeManifest: ParsedLinuxVzPackageExecutionRuntimeManifest,
    expectedGuestEvidencePublicKeySHA256: String
) throws -> ParsedLinuxVzPackageExecutionRuntimeQualificationImageManifest {
    guard !data.isEmpty else {
        throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.empty
    }
    guard data.count <= maximumLinuxVzPackageExecutionRuntimeQualificationImageManifestBytesV1
    else {
        throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.limitExceeded
    }
    guard qualificationImageManifestDigest(expectedGuestEvidencePublicKeySHA256),
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.invalidSchema
    }
    var expectedCanonical = try canonicalJSONData(value)
    expectedCanonical.append(0x0a)
    guard expectedCanonical == data else {
        throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.nonCanonical
    }
    let expectedKeys = Set([
        "architecture", "base_initramfs_sha256", "builder_source_sha256",
        "candidate_runtime_manifest_sha256", "candidate_runtime_rootfs_byte_length",
        "candidate_runtime_rootfs_sha256", "execution_authority_issued",
        "external_network", "guest_evidence_public_key_sha256", "node_executable_sha256",
        "npm_cli_sha256", "package_execution", "package_execution_runtime_sha256",
        "pip_entrypoint_sha256", "python_executable_sha256", "qualification_init_sha256",
        "qualification_init_source_sha256", "qualification_initramfs_sha256",
        "qualification_operation", "qualification_overlay_cpio_gzip_sha256",
        "qualification_overlay_cpio_sha256", "rootfs_attachment", "schema_version",
        "sync_back", "writer_source_sha256",
    ])
    guard Set(value.keys) == expectedKeys,
          value["schema_version"] as? String
            == linuxVzPackageExecutionRuntimeQualificationImageManifestSchemaV1,
          value["architecture"] as? String == "aarch64",
          value["qualification_operation"] as? String
            == "fixed_root_coordinator_custody_probe_from_exact_read_only_rootfs",
          value["rootfs_attachment"] as? String == "virtio_block_read_only",
          value["external_network"] as? String
            == "host_raw_frame_sinkhole_no_external_route",
          qualificationImageManifestBool(value["execution_authority_issued"]) == false,
          qualificationImageManifestBool(value["package_execution"]) == false,
          qualificationImageManifestBool(value["sync_back"]) == false else {
        throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.invalidSchema
    }
    guard
          value["candidate_runtime_manifest_sha256"] as? String
            == runtimeManifest.manifestSHA256,
          value["candidate_runtime_rootfs_sha256"] as? String
            == runtimeManifest.rootfsSHA256,
          value["candidate_runtime_rootfs_byte_length"] as? String
            == String(runtimeManifest.rootfsByteLength),
          value["package_execution_runtime_sha256"] as? String
            == runtimeManifest.packageRunnerSHA256,
          value["node_executable_sha256"] as? String
            == runtimeManifest.nodeExecutableSHA256,
          value["npm_cli_sha256"] as? String == runtimeManifest.npmCLISHA256,
          value["python_executable_sha256"] as? String
            == runtimeManifest.pythonExecutableSHA256,
          value["pip_entrypoint_sha256"] as? String
            == runtimeManifest.pipEntrypointSHA256,
          value["guest_evidence_public_key_sha256"] as? String
            == expectedGuestEvidencePublicKeySHA256 else {
        throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.invalidBinding
    }
    let digestKeys = [
        "base_initramfs_sha256", "builder_source_sha256",
        "candidate_runtime_manifest_sha256", "candidate_runtime_rootfs_sha256",
        "guest_evidence_public_key_sha256", "node_executable_sha256", "npm_cli_sha256",
        "package_execution_runtime_sha256", "pip_entrypoint_sha256",
        "python_executable_sha256", "qualification_init_sha256",
        "qualification_init_source_sha256", "qualification_initramfs_sha256",
        "qualification_overlay_cpio_gzip_sha256", "qualification_overlay_cpio_sha256",
        "writer_source_sha256",
    ]
    var digests = [String: String]()
    for key in digestKeys {
        guard let digest = value[key] as? String,
              qualificationImageManifestDigest(digest) else {
            throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.invalidBinding
        }
        digests[key] = digest
    }
    let independentlyBuiltComponents = [
        digests["base_initramfs_sha256"]!, digests["builder_source_sha256"]!,
        digests["qualification_init_sha256"]!,
        digests["qualification_init_source_sha256"]!,
        digests["qualification_initramfs_sha256"]!,
        digests["qualification_overlay_cpio_gzip_sha256"]!,
        digests["qualification_overlay_cpio_sha256"]!, digests["writer_source_sha256"]!,
    ]
    guard !independentlyBuiltComponents.contains(sha256(Data())),
          Set(independentlyBuiltComponents).count == independentlyBuiltComponents.count else {
        throw LinuxVzPackageExecutionRuntimeQualificationImageManifestError.invalidBinding
    }
    return ParsedLinuxVzPackageExecutionRuntimeQualificationImageManifest(
        canonicalJSON: data,
        manifestSHA256: sha256(data),
        baseInitramfsSHA256: digests["base_initramfs_sha256"]!,
        builderSourceSHA256: digests["builder_source_sha256"]!,
        initramfsSHA256: digests["qualification_initramfs_sha256"]!,
        qualificationInitSHA256: digests["qualification_init_sha256"]!,
        qualificationInitSourceSHA256: digests["qualification_init_source_sha256"]!,
        overlayCPIOGzipSHA256: digests["qualification_overlay_cpio_gzip_sha256"]!,
        overlayCPIOSHA256: digests["qualification_overlay_cpio_sha256"]!,
        writerSourceSHA256: digests["writer_source_sha256"]!,
        runtimeManifestSHA256: runtimeManifest.manifestSHA256,
        runtimeRootfsSHA256: runtimeManifest.rootfsSHA256,
        runtimeRootfsByteLength: runtimeManifest.rootfsByteLength,
        packageRunnerSHA256: runtimeManifest.packageRunnerSHA256,
        nodeExecutableSHA256: runtimeManifest.nodeExecutableSHA256,
        npmCLISHA256: runtimeManifest.npmCLISHA256,
        pythonExecutableSHA256: runtimeManifest.pythonExecutableSHA256,
        pipEntrypointSHA256: runtimeManifest.pipEntrypointSHA256,
        guestEvidencePublicKeySHA256: expectedGuestEvidencePublicKeySHA256
    )
}

private func qualificationImageManifestBool(_ value: Any?) -> Bool? {
    guard let number = value as? NSNumber,
          CFGetTypeID(number) == CFBooleanGetTypeID() else { return nil }
    return number.boolValue
}

private func qualificationImageManifestDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
