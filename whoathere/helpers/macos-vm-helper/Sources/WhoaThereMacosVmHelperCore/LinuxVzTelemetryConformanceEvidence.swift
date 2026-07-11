import Foundation

public let linuxVzTelemetryConformanceChallengeSchemaV1 =
    "whoathere.macos_linux_vz_telemetry_conformance_challenge.v1"
public let maximumLinuxVzTelemetryConformanceEvidenceBytesV1 = 16 * 1024 * 1024

public enum LinuxVzTelemetryConformanceEvidenceError: Error, Equatable,
    CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidNonce
    case runSpecMismatch
    case backendMismatch
    case cloneMismatch
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_telemetry_evidence_empty"
        case .limitExceeded: return "linux_vz_telemetry_evidence_limit_exceeded"
        case .invalidSchema: return "linux_vz_telemetry_evidence_schema_invalid"
        case .invalidNonce: return "linux_vz_telemetry_evidence_nonce_invalid"
        case .runSpecMismatch: return "linux_vz_telemetry_evidence_run_spec_mismatch"
        case .backendMismatch: return "linux_vz_telemetry_evidence_backend_mismatch"
        case .cloneMismatch: return "linux_vz_telemetry_evidence_clone_mismatch"
        case .nonCanonical: return "linux_vz_telemetry_evidence_noncanonical"
        }
    }
}

public struct LinuxVzTelemetryConformanceChallenge: Equatable, Sendable {
    public let canonicalJSON: Data
    public let challengeSHA256: String
    public let runSpecSHA256: String
    public let backendIdentitySHA256: String
    public let telemetryRequirementsSHA256: String
    public let cloneBindingSHA256: String
    public let guestEvidencePublicKeySHA256: String
    public let hostEvidencePublicKeySHA256: String

    public var packageExecutionAuthorityPermitted: Bool { false }
}

public func decodeLinuxVzTelemetryConformanceChallenge(
    _ data: Data,
    expectedRunSpec: LinuxVzTelemetryConformanceRunSpec,
    expectedBackend: UnqualifiedLinuxVzTelemetryBackendIdentity
) throws -> LinuxVzTelemetryConformanceChallenge {
    guard !data.isEmpty else { throw LinuxVzTelemetryConformanceEvidenceError.empty }
    guard data.count <= maximumLinuxVzTelemetryConformanceEvidenceBytesV1 else {
        throw LinuxVzTelemetryConformanceEvidenceError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidSchema
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzTelemetryConformanceEvidenceError.nonCanonical
    }
    guard Set(value.keys) == Set([
        "schema_version", "nonce_hex", "challenge_purpose", "run_spec_sha256",
        "backend_identity_sha256", "telemetry_requirements_sha256",
        "clone_binding_sha256", "guest_evidence_public_key_sha256",
        "host_evidence_public_key_sha256", "package_execution", "sync_back_policy"
    ]) else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidSchema
    }
    guard value["schema_version"] as? String == linuxVzTelemetryConformanceChallengeSchemaV1,
          value["challenge_purpose"] as? String
            == "trusted_inert_telemetry_conformance_only",
          value["package_execution"] as? String == "disabled",
          value["sync_back_policy"] as? String == "structurally_absent",
          let nonce = value["nonce_hex"] as? String,
          linuxVzEvidenceValidLowerHex(nonce, length: 64),
          let runSpecSHA256 = value["run_spec_sha256"] as? String,
          let backendSHA256 = value["backend_identity_sha256"] as? String,
          let requirementsSHA256 = value["telemetry_requirements_sha256"] as? String,
          let cloneSHA256 = value["clone_binding_sha256"] as? String,
          let guestKeySHA256 = value["guest_evidence_public_key_sha256"] as? String,
          let hostKeySHA256 = value["host_evidence_public_key_sha256"] as? String,
          [runSpecSHA256, backendSHA256, requirementsSHA256, cloneSHA256,
           guestKeySHA256, hostKeySHA256].allSatisfy(linuxVzEvidenceValidDigest) else {
        throw LinuxVzTelemetryConformanceEvidenceError.invalidSchema
    }
    guard runSpecSHA256 == expectedRunSpec.runSpecSHA256,
          !expectedRunSpec.packageExecutionAuthorityPermitted else {
        throw LinuxVzTelemetryConformanceEvidenceError.runSpecMismatch
    }
    guard backendSHA256 == expectedBackend.identitySHA256,
          backendSHA256 == expectedRunSpec.backendIdentitySHA256,
          requirementsSHA256 == expectedBackend.telemetryRequirementsSHA256,
          requirementsSHA256 == expectedRunSpec.telemetryRequirementsSHA256,
          guestKeySHA256 == expectedBackend.guestEvidencePublicKeySHA256,
          hostKeySHA256 == expectedBackend.hostEvidencePublicKeySHA256,
          !expectedBackend.executionAuthorityPermitted else {
        throw LinuxVzTelemetryConformanceEvidenceError.backendMismatch
    }
    return LinuxVzTelemetryConformanceChallenge(
        canonicalJSON: data,
        challengeSHA256: sha256(data),
        runSpecSHA256: runSpecSHA256,
        backendIdentitySHA256: backendSHA256,
        telemetryRequirementsSHA256: requirementsSHA256,
        cloneBindingSHA256: cloneSHA256,
        guestEvidencePublicKeySHA256: guestKeySHA256,
        hostEvidencePublicKeySHA256: hostKeySHA256
    )
}

private func linuxVzEvidenceValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && linuxVzEvidenceValidLowerHex(String(value.dropFirst(7)), length: 64)
}

private func linuxVzEvidenceValidLowerHex(_ value: String, length: Int) -> Bool {
    value.utf8.count == length && value.utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}
