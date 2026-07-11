import Foundation

public let wheelSupervisorProvisioningReceiptSchemaV1 =
    "whoathere.wheel_supervisor_provisioning.v1"
public let wheelGuestVSOCKPortV1: UInt32 = 47_080

public struct WheelSupervisorProvisioningObservation: Equatable, Sendable {
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
    public let wheelVSOCKPort: UInt32
    public let packageExecutionEnabled: Bool
    public let syncBackEnabled: Bool
}

public func verifyWheelSupervisorProvisioningReceipt(
    _ data: Data,
    identity: WheelRunBackendIdentity,
    guestAuthPublicKey: Data
) throws -> WheelSupervisorProvisioningObservation {
    guard !data.isEmpty, data.count <= 4 * 1024 * 1024,
          let receipt = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(receipt) == data,
          Set(receipt.keys) == Set([
              "base_generation_id", "clone_implementation_sha256", "cpu_count",
              "guest_auth_public_key_sha256", "guest_protocol_sha256",
              "guest_supervisor_sha256", "memory_mib", "package_execution_enabled",
              "package_gid", "package_uid", "package_username", "pip_cli_sha256",
              "pip_version", "python_executable_sha256", "python_version",
              "runner_configuration_sha256", "schema_version", "sync_back_enabled",
              "wheel_vsock_port"
          ]),
          receipt["schema_version"] as? String
            == wheelSupervisorProvisioningReceiptSchemaV1,
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
            == sha256(Data("whoathere.wheel_artifact_scenario.v1".utf8)),
          sha256(guestAuthPublicKey) == identity.guestAuthPublicKeySHA256,
          receipt["package_execution_enabled"] as? Bool == false,
          receipt["sync_back_enabled"] as? Bool == false,
          receipt["package_username"] as? String == "_whoatherepkg",
          let packageUIDText = receipt["package_uid"] as? String,
          let packageGIDText = receipt["package_gid"] as? String,
          let portText = receipt["wheel_vsock_port"] as? String,
          let cpuText = receipt["cpu_count"] as? String,
          let memoryText = receipt["memory_mib"] as? String,
          let packageUID = canonicalWheelProvisioningUInt32(packageUIDText),
          let packageGID = canonicalWheelProvisioningUInt32(packageGIDText),
          let port = canonicalWheelProvisioningUInt32(portText),
          let cpuCount = canonicalWheelProvisioningUInt32(cpuText),
          let memoryMiB = canonicalWheelProvisioningUInt64(memoryText),
          packageUID == identity.packageUID,
          packageGID == identity.packageGID,
          cpuCount == identity.cpuCount,
          memoryMiB == identity.memoryMiB,
          port == wheelGuestVSOCKPortV1,
          validWheelProvisioningDigest(identity.guestSupervisorSHA256),
          validWheelProvisioningDigest(identity.guestAuthPublicKeySHA256),
          validWheelProvisioningDigest(identity.runnerConfigurationSHA256),
          validWheelProvisioningDigest(identity.pythonExecutableSHA256),
          validWheelProvisioningDigest(identity.pipCLISHA256),
          validWheelProvisioningDigest(identity.cloneImplementationSHA256),
          validWheelProvisioningDigest(identity.guestProtocolSHA256) else {
        throw ArtifactRunLifecycleError.wheelProvisioningReceiptInvalid
    }
    return WheelSupervisorProvisioningObservation(
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
        wheelVSOCKPort: port,
        packageExecutionEnabled: false,
        syncBackEnabled: false
    )
}

private func canonicalWheelProvisioningUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(value), parsed != 0 else {
        return nil
    }
    return parsed
}

private func canonicalWheelProvisioningUInt32(_ value: String) -> UInt32? {
    guard !value.isEmpty, value.utf8.count <= 10,
          !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt32(value), parsed != 0 else {
        return nil
    }
    return parsed
}

private func validWheelProvisioningDigest(_ value: String) -> Bool {
    guard value.utf8.count == 71, value.hasPrefix("sha256:") else { return false }
    return value.dropFirst(7).utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}
