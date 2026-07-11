import Foundation

public let linuxVzTelemetryBackendIdentitySchemaV1 =
    "whoathere.macos_linux_vz_telemetry_backend_identity.v1"
public let maximumLinuxVzTelemetryBackendIdentityBytesV1 = 64 * 1024

public enum LinuxVzTelemetryBackendIdentityError: Error, Equatable, CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidIdentity
    case requirementsMismatch
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_telemetry_backend_empty"
        case .limitExceeded: return "linux_vz_telemetry_backend_limit_exceeded"
        case .invalidSchema: return "linux_vz_telemetry_backend_schema_invalid"
        case .invalidIdentity: return "linux_vz_telemetry_backend_identity_invalid"
        case .requirementsMismatch: return "linux_vz_telemetry_requirements_mismatch"
        case .nonCanonical: return "linux_vz_telemetry_backend_noncanonical"
        }
    }
}

public struct UnqualifiedLinuxVzTelemetryBackendIdentity: Equatable, Sendable {
    public let canonicalJSON: Data
    public let identitySHA256: String
    public let baseGenerationID: String
    public let linuxDistributionID: String
    public let kernelRelease: String
    public let kernelImageSHA256: String
    public let initramfsSHA256: String
    public let rootDiskSHA256: String
    public let kernelConfigSHA256: String
    public let btfSHA256: String
    public let guestRunnerSHA256: String
    public let guestSensorSHA256: String
    public let guestBPFBundleSHA256: String
    public let guestSensorConfigurationSHA256: String
    public let guestEvidencePublicKeySHA256: String
    public let hostHelperSHA256: String
    public let hostPacketSensorSHA256: String
    public let hostPacketSensorConfigurationSHA256: String
    public let telemetryRequirementsSHA256: String
    public let packageUID: UInt32
    public let packageGID: UInt32

    public var executionAuthorityPermitted: Bool { false }
}

public func decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
    _ data: Data,
    expectedTelemetryRequirementsSHA256: String
) throws -> UnqualifiedLinuxVzTelemetryBackendIdentity {
    guard !data.isEmpty else { throw LinuxVzTelemetryBackendIdentityError.empty }
    guard data.count <= maximumLinuxVzTelemetryBackendIdentityBytesV1 else {
        throw LinuxVzTelemetryBackendIdentityError.limitExceeded
    }
    guard linuxVzIdentityValidDigest(expectedTelemetryRequirementsSHA256) else {
        throw LinuxVzTelemetryBackendIdentityError.requirementsMismatch
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzTelemetryBackendIdentityError.nonCanonical
    }
    let expectedKeys = Set([
        "schema_version", "qualification_state", "base_generation_id",
        "linux_distribution_id", "kernel_release", "kernel_image_sha256",
        "initramfs_sha256", "root_disk_sha256", "kernel_config_sha256", "btf_sha256",
        "guest_runner_sha256", "guest_sensor_sha256", "guest_bpf_bundle_sha256",
        "guest_sensor_configuration_sha256", "guest_evidence_public_key_sha256",
        "host_helper_sha256", "host_packet_sensor_sha256",
        "host_packet_sensor_configuration_sha256", "telemetry_requirements_sha256",
        "package_uid", "package_gid"
    ])
    guard Set(value.keys) == expectedKeys else {
        throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
    }
    guard value["schema_version"] as? String == linuxVzTelemetryBackendIdentitySchemaV1 else {
        throw LinuxVzTelemetryBackendIdentityError.invalidSchema
    }
    guard value["qualification_state"] as? String == "candidate_unqualified",
          let baseGenerationID = value["base_generation_id"] as? String,
          let linuxDistributionID = value["linux_distribution_id"] as? String,
          let kernelRelease = value["kernel_release"] as? String,
          linuxVzIdentityValidComponent(baseGenerationID),
          linuxVzIdentityValidComponent(linuxDistributionID),
          linuxVzIdentityValidComponent(kernelRelease),
          let packageUIDText = value["package_uid"] as? String,
          let packageGIDText = value["package_gid"] as? String,
          let packageUID = linuxVzIdentityUInt32(packageUIDText),
          let packageGID = linuxVzIdentityUInt32(packageGIDText) else {
        throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
    }
    let digestKeys = [
        "kernel_image_sha256", "initramfs_sha256", "root_disk_sha256",
        "kernel_config_sha256", "btf_sha256", "guest_runner_sha256",
        "guest_sensor_sha256", "guest_bpf_bundle_sha256",
        "guest_sensor_configuration_sha256", "guest_evidence_public_key_sha256",
        "host_helper_sha256", "host_packet_sensor_sha256",
        "host_packet_sensor_configuration_sha256", "telemetry_requirements_sha256"
    ]
    var digests: [String: String] = [:]
    for key in digestKeys {
        guard let digest = value[key] as? String, linuxVzIdentityValidDigest(digest) else {
            throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
        }
        digests[key] = digest
    }
    guard digests["telemetry_requirements_sha256"]
            == expectedTelemetryRequirementsSHA256 else {
        throw LinuxVzTelemetryBackendIdentityError.requirementsMismatch
    }
    return UnqualifiedLinuxVzTelemetryBackendIdentity(
        canonicalJSON: data,
        identitySHA256: sha256(data),
        baseGenerationID: baseGenerationID,
        linuxDistributionID: linuxDistributionID,
        kernelRelease: kernelRelease,
        kernelImageSHA256: digests["kernel_image_sha256"]!,
        initramfsSHA256: digests["initramfs_sha256"]!,
        rootDiskSHA256: digests["root_disk_sha256"]!,
        kernelConfigSHA256: digests["kernel_config_sha256"]!,
        btfSHA256: digests["btf_sha256"]!,
        guestRunnerSHA256: digests["guest_runner_sha256"]!,
        guestSensorSHA256: digests["guest_sensor_sha256"]!,
        guestBPFBundleSHA256: digests["guest_bpf_bundle_sha256"]!,
        guestSensorConfigurationSHA256: digests["guest_sensor_configuration_sha256"]!,
        guestEvidencePublicKeySHA256: digests["guest_evidence_public_key_sha256"]!,
        hostHelperSHA256: digests["host_helper_sha256"]!,
        hostPacketSensorSHA256: digests["host_packet_sensor_sha256"]!,
        hostPacketSensorConfigurationSHA256:
            digests["host_packet_sensor_configuration_sha256"]!,
        telemetryRequirementsSHA256: digests["telemetry_requirements_sha256"]!,
        packageUID: packageUID,
        packageGID: packageGID
    )
}

private func linuxVzIdentityValidComponent(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 128
        && value.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (
                (scalar.value >= 48 && scalar.value <= 57)
                    || (scalar.value >= 65 && scalar.value <= 90)
                    || (scalar.value >= 97 && scalar.value <= 122)
                    || [45, 46, 95].contains(scalar.value)
            )
        }
}

private func linuxVzIdentityValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func linuxVzIdentityUInt32(_ value: String) -> UInt32? {
    guard !value.isEmpty, value.utf8.count <= 10,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt32(value), parsed != 0 else {
        return nil
    }
    return parsed
}
