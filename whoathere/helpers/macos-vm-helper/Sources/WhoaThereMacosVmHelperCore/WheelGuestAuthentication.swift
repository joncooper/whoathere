import CryptoKit
import Foundation
import Security

public let wheelGuestAuthChallengeSchemaV1 = "whoathere.wheel_guest_auth_challenge.v1"
public let wheelGuestAuthResponseSchemaV1 = "whoathere.wheel_guest_auth_response.v1"
public let maximumWheelGuestAuthBytesV1 = 16 * 1024

private let wheelGuestAuthResponseSignatureDomainV1 = Data(
    "whoathere.wheel_guest_auth.response_signature.v1\0".utf8
)

public enum WheelGuestAuthenticationError: Error, Equatable, CustomStringConvertible {
    case invalidChallenge
    case invalidResponse
    case nonCanonical
    case publicKeyMismatch
    case signatureFailed
    case limitExceeded
    case entropyUnavailable

    public var description: String {
        switch self {
        case .invalidChallenge: return "wheel_guest_auth_challenge_invalid"
        case .invalidResponse: return "wheel_guest_auth_response_invalid"
        case .nonCanonical: return "wheel_guest_auth_noncanonical"
        case .publicKeyMismatch: return "wheel_guest_auth_public_key_mismatch"
        case .signatureFailed: return "wheel_guest_auth_signature_failed"
        case .limitExceeded: return "wheel_guest_auth_limit_exceeded"
        case .entropyUnavailable: return "wheel_guest_auth_entropy_unavailable"
        }
    }
}

public struct WheelGuestAuthChallenge: Equatable, Sendable {
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

public struct WheelGuestAuthObservation: Equatable, Sendable {
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

public func wheelCloneBindingSHA256(
    baseGenerationID: String,
    runID: String,
    diskSHA256: String,
    auxiliaryStorageSHA256: String
) -> String {
    let input = "whoathere.macos_wheel_clone_binding.v1\0"
        + baseGenerationID + "\0"
        + runID + "\0"
        + diskSHA256 + "\0"
        + auxiliaryStorageSHA256
    return sha256(Data(input.utf8))
}

public func makeWheelGuestAuthChallenge(
    prelude: WheelRunSubmissionPrelude,
    cloneBindingSHA256: String,
    guestAuthPublicKey: Data
) throws -> WheelGuestAuthChallenge {
    var nonce = Data(count: 32)
    let result = nonce.withUnsafeMutableBytes { buffer in
        SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard result == errSecSuccess else {
        throw WheelGuestAuthenticationError.entropyUnavailable
    }
    return try makeWheelGuestAuthChallenge(
        executionBindingSHA256: prelude.executionBindingSHA256,
        runSpecSHA256: prelude.runSpecSHA256,
        cloneBindingSHA256: cloneBindingSHA256,
        expectedPublicKeySHA256: prelude.backendIdentity.guestAuthPublicKeySHA256,
        guestAuthPublicKey: guestAuthPublicKey,
        nonce: nonce
    )
}

func makeWheelGuestAuthChallenge(
    executionBindingSHA256: String,
    runSpecSHA256: String,
    cloneBindingSHA256: String,
    expectedPublicKeySHA256: String,
    guestAuthPublicKey: Data,
    nonce: Data
) throws -> WheelGuestAuthChallenge {
    guard nonce.count == 32,
          guestAuthPublicKey.count == 32,
          wheelValidGuestAuthDigest(executionBindingSHA256),
          wheelValidGuestAuthDigest(runSpecSHA256),
          wheelValidGuestAuthDigest(cloneBindingSHA256),
          wheelValidGuestAuthDigest(expectedPublicKeySHA256),
          sha256(guestAuthPublicKey) == expectedPublicKeySHA256 else {
        throw WheelGuestAuthenticationError.invalidChallenge
    }
    let body: [String: Any] = [
        "schema_version": wheelGuestAuthChallengeSchemaV1,
        "nonce_hex": nonce.map { String(format: "%02x", $0) }.joined(),
        "execution_binding_sha256": executionBindingSHA256,
        "run_spec_sha256": runSpecSHA256,
        "clone_binding_sha256": cloneBindingSHA256,
        "guest_auth_public_key_sha256": expectedPublicKeySHA256
    ]
    let canonical = try canonicalJSONData(body)
    guard canonical.count <= maximumWheelGuestAuthBytesV1 else {
        throw WheelGuestAuthenticationError.limitExceeded
    }
    return WheelGuestAuthChallenge(
        canonicalJSON: canonical,
        executionBindingSHA256: executionBindingSHA256,
        runSpecSHA256: runSpecSHA256,
        cloneBindingSHA256: cloneBindingSHA256,
        guestAuthPublicKeySHA256: expectedPublicKeySHA256
    )
}

public func decodeWheelGuestAuthChallenge(
    _ data: Data
) throws -> WheelGuestAuthChallenge {
    guard !data.isEmpty, data.count <= maximumWheelGuestAuthBytesV1 else {
        throw WheelGuestAuthenticationError.limitExceeded
    }
    guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(object) == data,
          Set(object.keys) == Set([
            "schema_version", "nonce_hex", "execution_binding_sha256", "run_spec_sha256",
            "clone_binding_sha256", "guest_auth_public_key_sha256"
          ]),
          object["schema_version"] as? String == wheelGuestAuthChallengeSchemaV1,
          let nonce = object["nonce_hex"] as? String,
          wheelValidLowerHex(nonce, length: 64),
          let execution = object["execution_binding_sha256"] as? String,
          let runSpec = object["run_spec_sha256"] as? String,
          let clone = object["clone_binding_sha256"] as? String,
          let publicKey = object["guest_auth_public_key_sha256"] as? String,
          wheelValidGuestAuthDigest(execution), wheelValidGuestAuthDigest(runSpec),
          wheelValidGuestAuthDigest(clone), wheelValidGuestAuthDigest(publicKey) else {
        throw WheelGuestAuthenticationError.nonCanonical
    }
    return WheelGuestAuthChallenge(
        canonicalJSON: data,
        executionBindingSHA256: execution,
        runSpecSHA256: runSpec,
        cloneBindingSHA256: clone,
        guestAuthPublicKeySHA256: publicKey
    )
}

public func verifyWheelGuestAuthResponse(
    _ responseData: Data,
    challenge: WheelGuestAuthChallenge,
    prelude: WheelRunSubmissionPrelude,
    guestAuthPublicKey: Data
) throws -> WheelGuestAuthObservation {
    guard !responseData.isEmpty, responseData.count <= maximumWheelGuestAuthBytesV1 else {
        throw WheelGuestAuthenticationError.limitExceeded
    }
    guard guestAuthPublicKey.count == 32,
          sha256(guestAuthPublicKey) == challenge.guestAuthPublicKeySHA256,
          challenge.executionBindingSHA256 == prelude.executionBindingSHA256,
          challenge.runSpecSHA256 == prelude.runSpecSHA256,
          challenge.guestAuthPublicKeySHA256
            == prelude.backendIdentity.guestAuthPublicKeySHA256 else {
        throw WheelGuestAuthenticationError.publicKeyMismatch
    }
    guard let response = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
          try canonicalJSONData(response) == responseData,
          Set(response.keys) == Set([
            "schema_version", "challenge_sha256", "execution_binding_sha256",
            "run_spec_sha256", "clone_binding_sha256", "guest_supervisor_sha256",
            "runner_configuration_sha256", "package_uid", "package_gid",
            "signature_ed25519_hex"
          ]),
          response["schema_version"] as? String == wheelGuestAuthResponseSchemaV1,
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
          let signature = wheelDecodeLowerHex(signatureHex, byteCount: 64) else {
        throw WheelGuestAuthenticationError.invalidResponse
    }
    var unsigned = response
    unsigned.removeValue(forKey: "signature_ed25519_hex")
    let unsignedData = try canonicalJSONData(unsigned)
    var message = wheelGuestAuthResponseSignatureDomainV1
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let publicKey: Curve25519.Signing.PublicKey
    do {
        publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: guestAuthPublicKey)
    } catch {
        throw WheelGuestAuthenticationError.publicKeyMismatch
    }
    guard publicKey.isValidSignature(signature, for: message) else {
        throw WheelGuestAuthenticationError.signatureFailed
    }
    return WheelGuestAuthObservation(
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

private func wheelValidGuestAuthDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && wheelValidLowerHex(String(value.dropFirst(7)), length: 64)
}

private func wheelValidLowerHex(_ value: String, length: Int) -> Bool {
    value.utf8.count == length && value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

private func wheelDecodeLowerHex(_ value: String, byteCount: Int) -> Data? {
    guard wheelValidLowerHex(value, length: byteCount * 2) else { return nil }
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
