import Foundation

public let sdistSupervisorProvisioningReceiptSchemaV1 =
    "whoathere.sdist_supervisor_provisioning.v1"
public let sdistGuestVSOCKPortV1: UInt32 = 47_081

public struct SdistSupervisorProvisioningObservation: Equatable, Sendable {
    public let baseGenerationID: String
    public let guestSupervisorSHA256: String
    public let guestAuthPublicKeySHA256: String
    public let runnerConfigurationSHA256: String
    public let pythonExecutableSHA256: String
    public let pythonVersion: String
    public let pipCLISHA256: String
    public let pipVersion: String
    public let cloneImplementationSHA256: String
    public let guestProtocolSHA256: String
    public let cpuCount: UInt32
    public let memoryMiB: UInt64
    public let packageUID: UInt32
    public let packageGID: UInt32
    public let packageUsername: String
    public let sdistVSOCKPort: UInt32
    public let packageExecutionEnabled: Bool
    public let syncBackEnabled: Bool
    public let buildClosureMaterializationEnabled: Bool
    public let publicResolutionEnabled: Bool
}

public func verifySdistSupervisorProvisioningReceipt(
    _ data: Data,
    identity: SdistRunBackendIdentity,
    guestAuthPublicKey: Data
) throws -> SdistSupervisorProvisioningObservation {
    guard !data.isEmpty, data.count <= 4 * 1024 * 1024,
          let receipt = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(receipt) == data,
          Set(receipt.keys) == Set([
              "base_generation_id", "build_closure_materialization_enabled",
              "clone_implementation_sha256", "cpu_count", "guest_auth_public_key_sha256",
              "guest_protocol_sha256", "guest_supervisor_sha256", "memory_mib",
              "package_execution_enabled", "package_gid", "package_uid", "package_username",
              "pip_cli_sha256", "pip_version", "public_resolution_enabled",
              "python_executable_sha256", "python_version", "runner_configuration_sha256",
              "schema_version", "sdist_vsock_port", "sync_back_enabled"
          ]),
          receipt["schema_version"] as? String
            == sdistSupervisorProvisioningReceiptSchemaV1,
          receipt["base_generation_id"] as? String == identity.baseGenerationID,
          receipt["guest_supervisor_sha256"] as? String
            == identity.guestSupervisorSHA256,
          receipt["guest_auth_public_key_sha256"] as? String
            == identity.guestAuthPublicKeySHA256,
          receipt["runner_configuration_sha256"] as? String
            == identity.runnerConfigurationSHA256,
          receipt["python_executable_sha256"] as? String
            == identity.pythonExecutableSHA256,
          receipt["python_version"] as? String == identity.pythonVersion,
          receipt["pip_cli_sha256"] as? String == identity.pipCLISHA256,
          receipt["pip_version"] as? String == identity.pipVersion,
          receipt["clone_implementation_sha256"] as? String
            == identity.cloneImplementationSHA256,
          receipt["guest_protocol_sha256"] as? String == identity.guestProtocolSHA256,
          identity.cloneImplementationSHA256
            == sha256(Data("whoathere.swift.fclonefileat.direct.v1".utf8)),
          identity.guestProtocolSHA256
            == sha256(Data("whoathere.sdist_artifact_scenario.v1".utf8)),
          sha256(guestAuthPublicKey) == identity.guestAuthPublicKeySHA256,
          receipt["package_execution_enabled"] as? Bool == false,
          receipt["sync_back_enabled"] as? Bool == false,
          receipt["build_closure_materialization_enabled"] as? Bool == false,
          receipt["public_resolution_enabled"] as? Bool == false,
          receipt["package_username"] as? String == "_whoatherepkg",
          let packageUIDText = receipt["package_uid"] as? String,
          let packageGIDText = receipt["package_gid"] as? String,
          let portText = receipt["sdist_vsock_port"] as? String,
          let cpuText = receipt["cpu_count"] as? String,
          let memoryText = receipt["memory_mib"] as? String,
          let packageUID = canonicalSdistProvisioningUInt32(packageUIDText),
          let packageGID = canonicalSdistProvisioningUInt32(packageGIDText),
          let port = canonicalSdistProvisioningUInt32(portText),
          let cpuCount = canonicalSdistProvisioningUInt32(cpuText),
          let memoryMiB = canonicalSdistProvisioningUInt64(memoryText),
          packageUID == identity.packageUID,
          packageGID == identity.packageGID,
          cpuCount == identity.cpuCount,
          memoryMiB == identity.memoryMiB,
          port == sdistGuestVSOCKPortV1,
          validSdistProvisioningDigest(identity.guestSupervisorSHA256),
          validSdistProvisioningDigest(identity.guestAuthPublicKeySHA256),
          validSdistProvisioningDigest(identity.runnerConfigurationSHA256),
          validSdistProvisioningDigest(identity.pythonExecutableSHA256),
          validSdistProvisioningDigest(identity.pipCLISHA256),
          validSdistProvisioningDigest(identity.cloneImplementationSHA256),
          validSdistProvisioningDigest(identity.guestProtocolSHA256) else {
        throw ArtifactRunLifecycleError.sdistProvisioningReceiptInvalid
    }
    return SdistSupervisorProvisioningObservation(
        baseGenerationID: identity.baseGenerationID,
        guestSupervisorSHA256: identity.guestSupervisorSHA256,
        guestAuthPublicKeySHA256: identity.guestAuthPublicKeySHA256,
        runnerConfigurationSHA256: identity.runnerConfigurationSHA256,
        pythonExecutableSHA256: identity.pythonExecutableSHA256,
        pythonVersion: identity.pythonVersion,
        pipCLISHA256: identity.pipCLISHA256,
        pipVersion: identity.pipVersion,
        cloneImplementationSHA256: identity.cloneImplementationSHA256,
        guestProtocolSHA256: identity.guestProtocolSHA256,
        cpuCount: cpuCount,
        memoryMiB: memoryMiB,
        packageUID: packageUID,
        packageGID: packageGID,
        packageUsername: "_whoatherepkg",
        sdistVSOCKPort: port,
        packageExecutionEnabled: false,
        syncBackEnabled: false,
        buildClosureMaterializationEnabled: false,
        publicResolutionEnabled: false
    )
}

private func canonicalSdistProvisioningUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(value), parsed != 0 else {
        return nil
    }
    return parsed
}

private func canonicalSdistProvisioningUInt32(_ value: String) -> UInt32? {
    guard !value.isEmpty, value.utf8.count <= 10,
          !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt32(value), parsed != 0 else {
        return nil
    }
    return parsed
}

private func validSdistProvisioningDigest(_ value: String) -> Bool {
    guard value.utf8.count == 71, value.hasPrefix("sha256:") else { return false }
    return value.dropFirst(7).utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}
