import CryptoKit
import Foundation
import Security

public let artifactGuestAuthChallengeSchemaV1 = "whoathere.artifact_guest_auth_challenge.v1"
public let artifactGuestAuthResponseSchemaV1 = "whoathere.artifact_guest_auth_response.v1"
public let maximumArtifactGuestAuthBytesV1 = 16 * 1024

private let artifactGuestAuthResponseSignatureDomainV1 = Data(
    "whoathere.artifact_guest_auth.response_signature.v1\0".utf8
)

public enum ArtifactGuestAuthenticationError: Error, Equatable, CustomStringConvertible {
    case invalidChallenge
    case invalidResponse
    case nonCanonical
    case publicKeyMismatch
    case signatureFailed
    case limitExceeded
    case entropyUnavailable

    public var description: String {
        switch self {
        case .invalidChallenge: return "artifact_guest_auth_challenge_invalid"
        case .invalidResponse: return "artifact_guest_auth_response_invalid"
        case .nonCanonical: return "artifact_guest_auth_noncanonical"
        case .publicKeyMismatch: return "artifact_guest_auth_public_key_mismatch"
        case .signatureFailed: return "artifact_guest_auth_signature_failed"
        case .limitExceeded: return "artifact_guest_auth_limit_exceeded"
        case .entropyUnavailable: return "artifact_guest_auth_entropy_unavailable"
        }
    }
}

public struct ArtifactGuestAuthChallenge: Equatable, Sendable {
    public let canonicalJSON: Data
    public let executionBindingSHA256: String
    public let runSpecSHA256: String
    public let cloneBindingSHA256: String
    public let guestAuthPublicKeySHA256: String

    fileprivate init(
        canonicalJSON: Data,
        executionBindingSHA256: String,
        runSpecSHA256: String,
        cloneBindingSHA256: String,
        guestAuthPublicKeySHA256: String
    ) {
        self.canonicalJSON = canonicalJSON
        self.executionBindingSHA256 = executionBindingSHA256
        self.runSpecSHA256 = runSpecSHA256
        self.cloneBindingSHA256 = cloneBindingSHA256
        self.guestAuthPublicKeySHA256 = guestAuthPublicKeySHA256
    }
}

public struct ArtifactGuestAuthObservation: Equatable, Sendable {
    public let challengeSHA256: String
    public let executionBindingSHA256: String
    public let runSpecSHA256: String
    public let cloneBindingSHA256: String
    public let guestSupervisorSHA256: String
    public let runnerConfigurationSHA256: String
    public let packageUID: UInt32
    public let packageGID: UInt32
    public let signatureVerified: Bool
}

public func artifactCloneBindingSHA256(
    base: LockedArtifactRunBase,
    clone: DisposableArtifactRunClone
) -> String {
    let input = "whoathere.macos_artifact_clone_binding.v1\0"
        + base.identity.baseGenerationID + "\0"
        + clone.runID + "\0"
        + clone.diskSHA256 + "\0"
        + clone.auxiliaryStorageSHA256
    return sha256(Data(input.utf8))
}

public func makeArtifactGuestAuthChallenge(
    prelude: ArtifactRunSubmissionPrelude,
    cloneBindingSHA256: String,
    guestAuthPublicKey: Data
) throws -> ArtifactGuestAuthChallenge {
    var nonce = Data(count: 32)
    let result = nonce.withUnsafeMutableBytes { buffer in
        SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard result == errSecSuccess else {
        throw ArtifactGuestAuthenticationError.entropyUnavailable
    }
    return try makeArtifactGuestAuthChallenge(
        executionBindingSHA256: prelude.executionBindingSHA256,
        runSpecSHA256: prelude.runSpecSHA256,
        cloneBindingSHA256: cloneBindingSHA256,
        expectedPublicKeySHA256: prelude.backendIdentity.guestAuthPublicKeySHA256,
        guestAuthPublicKey: guestAuthPublicKey,
        nonce: nonce
    )
}

func makeArtifactGuestAuthChallenge(
    executionBindingSHA256: String,
    runSpecSHA256: String,
    cloneBindingSHA256: String,
    expectedPublicKeySHA256: String,
    guestAuthPublicKey: Data,
    nonce: Data
) throws -> ArtifactGuestAuthChallenge {
    guard nonce.count == 32,
          guestAuthPublicKey.count == 32,
          validGuestAuthDigest(executionBindingSHA256),
          validGuestAuthDigest(runSpecSHA256),
          validGuestAuthDigest(cloneBindingSHA256),
          validGuestAuthDigest(expectedPublicKeySHA256),
          sha256(guestAuthPublicKey) == expectedPublicKeySHA256 else {
        throw ArtifactGuestAuthenticationError.invalidChallenge
    }
    let body: [String: Any] = [
        "schema_version": artifactGuestAuthChallengeSchemaV1,
        "nonce_hex": nonce.map { String(format: "%02x", $0) }.joined(),
        "execution_binding_sha256": executionBindingSHA256,
        "run_spec_sha256": runSpecSHA256,
        "clone_binding_sha256": cloneBindingSHA256,
        "guest_auth_public_key_sha256": expectedPublicKeySHA256
    ]
    let canonical = try canonicalJSONData(body)
    guard canonical.count <= maximumArtifactGuestAuthBytesV1 else {
        throw ArtifactGuestAuthenticationError.limitExceeded
    }
    return ArtifactGuestAuthChallenge(
        canonicalJSON: canonical,
        executionBindingSHA256: executionBindingSHA256,
        runSpecSHA256: runSpecSHA256,
        cloneBindingSHA256: cloneBindingSHA256,
        guestAuthPublicKeySHA256: expectedPublicKeySHA256
    )
}

public func decodeArtifactGuestAuthChallenge(
    _ data: Data
) throws -> ArtifactGuestAuthChallenge {
    guard !data.isEmpty, data.count <= maximumArtifactGuestAuthBytesV1 else {
        throw ArtifactGuestAuthenticationError.limitExceeded
    }
    guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(object) == data,
          Set(object.keys) == Set([
            "schema_version", "nonce_hex", "execution_binding_sha256", "run_spec_sha256",
            "clone_binding_sha256", "guest_auth_public_key_sha256"
          ]),
          object["schema_version"] as? String == artifactGuestAuthChallengeSchemaV1,
          let nonce = object["nonce_hex"] as? String,
          validLowerHex(nonce, length: 64),
          let execution = object["execution_binding_sha256"] as? String,
          let runSpec = object["run_spec_sha256"] as? String,
          let clone = object["clone_binding_sha256"] as? String,
          let publicKey = object["guest_auth_public_key_sha256"] as? String,
          validGuestAuthDigest(execution), validGuestAuthDigest(runSpec),
          validGuestAuthDigest(clone), validGuestAuthDigest(publicKey) else {
        throw ArtifactGuestAuthenticationError.nonCanonical
    }
    return ArtifactGuestAuthChallenge(
        canonicalJSON: data,
        executionBindingSHA256: execution,
        runSpecSHA256: runSpec,
        cloneBindingSHA256: clone,
        guestAuthPublicKeySHA256: publicKey
    )
}

public func verifyArtifactGuestAuthResponse(
    _ responseData: Data,
    challenge: ArtifactGuestAuthChallenge,
    prelude: ArtifactRunSubmissionPrelude,
    guestAuthPublicKey: Data
) throws -> ArtifactGuestAuthObservation {
    guard !responseData.isEmpty, responseData.count <= maximumArtifactGuestAuthBytesV1 else {
        throw ArtifactGuestAuthenticationError.limitExceeded
    }
    guard guestAuthPublicKey.count == 32,
          sha256(guestAuthPublicKey) == challenge.guestAuthPublicKeySHA256,
          challenge.executionBindingSHA256 == prelude.executionBindingSHA256,
          challenge.runSpecSHA256 == prelude.runSpecSHA256,
          challenge.guestAuthPublicKeySHA256
            == prelude.backendIdentity.guestAuthPublicKeySHA256 else {
        throw ArtifactGuestAuthenticationError.publicKeyMismatch
    }
    guard let response = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
          try canonicalJSONData(response) == responseData,
          Set(response.keys) == Set([
            "schema_version", "challenge_sha256", "execution_binding_sha256",
            "run_spec_sha256", "clone_binding_sha256", "guest_supervisor_sha256",
            "runner_configuration_sha256", "package_uid", "package_gid",
            "signature_ed25519_hex"
          ]),
          response["schema_version"] as? String == artifactGuestAuthResponseSchemaV1,
          response["challenge_sha256"] as? String == sha256(challenge.canonicalJSON),
          response["execution_binding_sha256"] as? String == challenge.executionBindingSHA256,
          response["run_spec_sha256"] as? String == challenge.runSpecSHA256,
          response["clone_binding_sha256"] as? String == challenge.cloneBindingSHA256,
          response["guest_supervisor_sha256"] as? String
            == prelude.backendIdentity.guestSupervisorSHA256,
          response["runner_configuration_sha256"] as? String
            == prelude.backendIdentity.runnerConfigurationSHA256,
          response["package_uid"] as? String == String(prelude.backendIdentity.packageUID),
          response["package_gid"] as? String == String(prelude.backendIdentity.packageGID),
          let signatureHex = response["signature_ed25519_hex"] as? String,
          let signature = decodeLowerHex(signatureHex, byteCount: 64) else {
        throw ArtifactGuestAuthenticationError.invalidResponse
    }
    var unsigned = response
    unsigned.removeValue(forKey: "signature_ed25519_hex")
    let unsignedData = try canonicalJSONData(unsigned)
    var message = artifactGuestAuthResponseSignatureDomainV1
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let publicKey: Curve25519.Signing.PublicKey
    do {
        publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: guestAuthPublicKey)
    } catch {
        throw ArtifactGuestAuthenticationError.publicKeyMismatch
    }
    guard publicKey.isValidSignature(signature, for: message) else {
        throw ArtifactGuestAuthenticationError.signatureFailed
    }
    return ArtifactGuestAuthObservation(
        challengeSHA256: sha256(challenge.canonicalJSON),
        executionBindingSHA256: challenge.executionBindingSHA256,
        runSpecSHA256: challenge.runSpecSHA256,
        cloneBindingSHA256: challenge.cloneBindingSHA256,
        guestSupervisorSHA256: prelude.backendIdentity.guestSupervisorSHA256,
        runnerConfigurationSHA256: prelude.backendIdentity.runnerConfigurationSHA256,
        packageUID: prelude.backendIdentity.packageUID,
        packageGID: prelude.backendIdentity.packageGID,
        signatureVerified: true
    )
}

private func validGuestAuthDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && validLowerHex(String(value.dropFirst(7)), length: 64)
}

private func validLowerHex(_ value: String, length: Int) -> Bool {
    value.utf8.count == length && value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

private func decodeLowerHex(_ value: String, byteCount: Int) -> Data? {
    guard validLowerHex(value, length: byteCount * 2) else { return nil }
    var output = Data()
    output.reserveCapacity(byteCount)
    var index = value.startIndex
    for _ in 0..<byteCount {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16) else { return nil }
        output.append(byte)
        index = next
    }
    return output
}
