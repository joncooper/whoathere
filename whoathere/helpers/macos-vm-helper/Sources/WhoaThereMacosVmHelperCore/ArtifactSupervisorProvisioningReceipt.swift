import Foundation

public let artifactSupervisorProvisioningReceiptSchemaV1 =
    "whoathere.artifact_supervisor_provisioning.v1"

public struct ArtifactSupervisorProvisioningObservation: Equatable, Sendable {
    public let baseGenerationID: String
    public let guestSupervisorSHA256: String
    public let guestAuthPublicKeySHA256: String
    public let runnerConfigurationSHA256: String
    public let nodeExecutableSHA256: String
    public let nodeVersion: String
    public let npmCLISHA256: String
    public let npmVersion: String
    public let cloneImplementationSHA256: String
    public let cpuCount: UInt32
    public let memoryMiB: UInt64
    public let packageUID: UInt32
    public let packageGID: UInt32
    public let artifactVSOCKPort: UInt32
    public let packageExecutionEnabled: Bool
    public let syncBackEnabled: Bool
}

public func verifyArtifactSupervisorProvisioningReceipt(
    _ data: Data,
    identity: ArtifactRunBackendIdentity,
    guestAuthPublicKey: Data
) throws -> ArtifactSupervisorProvisioningObservation {
    guard !data.isEmpty, data.count <= 4 * 1024 * 1024,
          let receipt = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(receipt) == data,
          Set(receipt.keys) == Set([
            "artifact_vsock_port", "base_generation_id", "clone_implementation_sha256",
            "cpu_count",
            "guest_auth_public_key_sha256", "guest_supervisor_sha256",
            "memory_mib", "node_executable_sha256", "node_version", "npm_cli_sha256", "npm_version",
            "package_execution_enabled", "package_gid", "package_uid",
            "runner_configuration_sha256", "schema_version", "sync_back_enabled"
          ]),
          receipt["schema_version"] as? String
            == artifactSupervisorProvisioningReceiptSchemaV1,
          receipt["base_generation_id"] as? String == identity.baseGenerationID,
          receipt["guest_supervisor_sha256"] as? String
            == identity.guestSupervisorSHA256,
          receipt["guest_auth_public_key_sha256"] as? String
            == identity.guestAuthPublicKeySHA256,
          receipt["runner_configuration_sha256"] as? String
            == identity.runnerConfigurationSHA256,
          receipt["node_executable_sha256"] as? String == identity.nodeExecutableSHA256,
          receipt["node_version"] as? String == identity.nodeVersion,
          receipt["npm_cli_sha256"] as? String == identity.npmCLISHA256,
          receipt["npm_version"] as? String == identity.npmVersion,
          receipt["clone_implementation_sha256"] as? String
            == identity.cloneImplementationSHA256,
          identity.cloneImplementationSHA256
            == sha256(Data("whoathere.swift.fclonefileat.direct.v1".utf8)),
          sha256(guestAuthPublicKey) == identity.guestAuthPublicKeySHA256,
          receipt["package_execution_enabled"] as? Bool == false,
          receipt["sync_back_enabled"] as? Bool == false,
          let packageUIDText = receipt["package_uid"] as? String,
          let packageGIDText = receipt["package_gid"] as? String,
          let portText = receipt["artifact_vsock_port"] as? String,
          let cpuText = receipt["cpu_count"] as? String,
          let memoryText = receipt["memory_mib"] as? String,
          let packageUID = canonicalProvisioningUInt32(packageUIDText),
          let packageGID = canonicalProvisioningUInt32(packageGIDText),
          let port = canonicalProvisioningUInt32(portText),
          let cpuCount = canonicalProvisioningUInt32(cpuText),
          let memoryMiB = canonicalProvisioningUInt64(memoryText),
          packageUID == identity.packageUID,
          packageGID == identity.packageGID,
          cpuCount == identity.cpuCount,
          memoryMiB == identity.memoryMiB,
          port == 47_079,
          validProvisioningDigest(identity.guestSupervisorSHA256),
          validProvisioningDigest(identity.guestAuthPublicKeySHA256),
          validProvisioningDigest(identity.runnerConfigurationSHA256),
          validProvisioningDigest(identity.nodeExecutableSHA256),
          validProvisioningDigest(identity.npmCLISHA256),
          validProvisioningDigest(identity.cloneImplementationSHA256) else {
        throw ArtifactRunLifecycleError.provisioningReceiptInvalid
    }
    return ArtifactSupervisorProvisioningObservation(
        baseGenerationID: identity.baseGenerationID,
        guestSupervisorSHA256: identity.guestSupervisorSHA256,
        guestAuthPublicKeySHA256: identity.guestAuthPublicKeySHA256,
        runnerConfigurationSHA256: identity.runnerConfigurationSHA256,
        nodeExecutableSHA256: identity.nodeExecutableSHA256,
        nodeVersion: identity.nodeVersion,
        npmCLISHA256: identity.npmCLISHA256,
        npmVersion: identity.npmVersion,
        cloneImplementationSHA256: identity.cloneImplementationSHA256,
        cpuCount: cpuCount,
        memoryMiB: memoryMiB,
        packageUID: packageUID,
        packageGID: packageGID,
        artifactVSOCKPort: port,
        packageExecutionEnabled: false,
        syncBackEnabled: false
    )
}

private func canonicalProvisioningUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(value), parsed != 0 else {
        return nil
    }
    return parsed
}

private func canonicalProvisioningUInt32(_ value: String) -> UInt32? {
    guard !value.isEmpty, value.utf8.count <= 10,
          !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt32(value), parsed != 0 else {
        return nil
    }
    return parsed
}

private func validProvisioningDigest(_ value: String) -> Bool {
    guard value.utf8.count == 71, value.hasPrefix("sha256:") else { return false }
    return value.dropFirst(7).utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}
