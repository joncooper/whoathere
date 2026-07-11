import CryptoKit
import Foundation
import Security

public let sdistGuestAuthChallengeSchemaV1 = "whoathere.sdist_guest_auth_challenge.v1"
public let sdistGuestAuthResponseSchemaV1 = "whoathere.sdist_guest_auth_response.v1"
public let maximumSdistGuestAuthBytesV1 = 16 * 1024

private let sdistGuestAuthResponseSignatureDomainV1 = Data(
    "whoathere.sdist_guest_auth.response_signature.v1\0".utf8
)

public enum SdistGuestAuthenticationError: Error, Equatable, CustomStringConvertible {
    case invalidChallenge
    case invalidResponse
    case nonCanonical
    case publicKeyMismatch
    case signatureFailed
    case limitExceeded
    case entropyUnavailable

    public var description: String {
        switch self {
        case .invalidChallenge: return "sdist_guest_auth_challenge_invalid"
        case .invalidResponse: return "sdist_guest_auth_response_invalid"
        case .nonCanonical: return "sdist_guest_auth_noncanonical"
        case .publicKeyMismatch: return "sdist_guest_auth_public_key_mismatch"
        case .signatureFailed: return "sdist_guest_auth_signature_failed"
        case .limitExceeded: return "sdist_guest_auth_limit_exceeded"
        case .entropyUnavailable: return "sdist_guest_auth_entropy_unavailable"
        }
    }
}

public struct SdistGuestAuthChallenge: Equatable, Sendable {
    public let canonicalJSON: Data
    public let executionBindingSHA256: String
    public let runSpecSHA256: String
    public let buildClosureSHA256: String
    public let cloneBindingSHA256: String
    public let guestAuthPublicKeySHA256: String

    fileprivate init(
        canonicalJSON: Data,
        executionBindingSHA256: String,
        runSpecSHA256: String,
        buildClosureSHA256: String,
        cloneBindingSHA256: String,
        guestAuthPublicKeySHA256: String
    ) {
        self.canonicalJSON = canonicalJSON
        self.executionBindingSHA256 = executionBindingSHA256
        self.runSpecSHA256 = runSpecSHA256
        self.buildClosureSHA256 = buildClosureSHA256
        self.cloneBindingSHA256 = cloneBindingSHA256
        self.guestAuthPublicKeySHA256 = guestAuthPublicKeySHA256
    }
}

public struct SdistGuestAuthObservation: Equatable, Sendable {
    public let challengeSHA256: String
    public let executionBindingSHA256: String
    public let runSpecSHA256: String
    public let buildClosureSHA256: String
    public let cloneBindingSHA256: String
    public let guestSupervisorSHA256: String
    public let runnerConfigurationSHA256: String
    public let packageUID: UInt32
    public let packageGID: UInt32
    public let signatureVerified: Bool
}

public struct SdistGuestAuthenticatedSession: Equatable, Sendable {
    public let challenge: SdistGuestAuthChallenge
    public let observation: SdistGuestAuthObservation

    init(
        challenge: SdistGuestAuthChallenge,
        observation: SdistGuestAuthObservation
    ) {
        self.challenge = challenge
        self.observation = observation
    }
}

public func sdistCloneBindingSHA256(
    baseGenerationID: String,
    runID: String,
    diskSHA256: String,
    auxiliaryStorageSHA256: String
) -> String {
    let input = "whoathere.macos_sdist_clone_binding.v1\0"
        + baseGenerationID + "\0"
        + runID + "\0"
        + diskSHA256 + "\0"
        + auxiliaryStorageSHA256
    return sha256(Data(input.utf8))
}

/// Constructs an sdist challenge only from a successfully consumed authority-bound submission.
public func makeSdistGuestAuthChallenge(
    authorized: AuthorizedSdistRunSubmission,
    cloneBindingSHA256: String,
    guestAuthPublicKey: Data
) throws -> SdistGuestAuthChallenge {
    let prelude = authorized.prelude
    let authority = authorized.authority
    guard authority.replayStatePersisted,
          authority.challengeBindingSHA256 == prelude.challengeBindingSHA256,
          authority.runSpecSHA256 == prelude.runSpecSHA256,
          authority.artifactSHA256 == prelude.artifactSHA256,
          authority.buildClosureSHA256 == prelude.buildClosureSHA256 else {
        throw SdistGuestAuthenticationError.invalidChallenge
    }
    var nonce = Data(count: 32)
    let result = nonce.withUnsafeMutableBytes { buffer in
        SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard result == errSecSuccess else {
        throw SdistGuestAuthenticationError.entropyUnavailable
    }
    return try makeSdistGuestAuthChallenge(
        executionBindingSHA256: prelude.executionBindingSHA256,
        runSpecSHA256: authority.runSpecSHA256,
        buildClosureSHA256: authority.buildClosureSHA256,
        cloneBindingSHA256: cloneBindingSHA256,
        expectedPublicKeySHA256: prelude.backendIdentity.guestAuthPublicKeySHA256,
        guestAuthPublicKey: guestAuthPublicKey,
        nonce: nonce
    )
}

func makeSdistGuestAuthChallenge(
    executionBindingSHA256: String,
    runSpecSHA256: String,
    buildClosureSHA256: String,
    cloneBindingSHA256: String,
    expectedPublicKeySHA256: String,
    guestAuthPublicKey: Data,
    nonce: Data
) throws -> SdistGuestAuthChallenge {
    guard nonce.count == 32,
          guestAuthPublicKey.count == 32,
          sdistValidGuestAuthDigest(executionBindingSHA256),
          sdistValidGuestAuthDigest(runSpecSHA256),
          sdistValidGuestAuthDigest(buildClosureSHA256),
          sdistValidGuestAuthDigest(cloneBindingSHA256),
          sdistValidGuestAuthDigest(expectedPublicKeySHA256),
          sha256(guestAuthPublicKey) == expectedPublicKeySHA256 else {
        throw SdistGuestAuthenticationError.invalidChallenge
    }
    let body: [String: Any] = [
        "schema_version": sdistGuestAuthChallengeSchemaV1,
        "nonce_hex": nonce.map { String(format: "%02x", $0) }.joined(),
        "execution_binding_sha256": executionBindingSHA256,
        "run_spec_sha256": runSpecSHA256,
        "build_closure_sha256": buildClosureSHA256,
        "clone_binding_sha256": cloneBindingSHA256,
        "guest_auth_public_key_sha256": expectedPublicKeySHA256
    ]
    let canonical = try canonicalJSONData(body)
    guard canonical.count <= maximumSdistGuestAuthBytesV1 else {
        throw SdistGuestAuthenticationError.limitExceeded
    }
    return SdistGuestAuthChallenge(
        canonicalJSON: canonical,
        executionBindingSHA256: executionBindingSHA256,
        runSpecSHA256: runSpecSHA256,
        buildClosureSHA256: buildClosureSHA256,
        cloneBindingSHA256: cloneBindingSHA256,
        guestAuthPublicKeySHA256: expectedPublicKeySHA256
    )
}

public func decodeSdistGuestAuthChallenge(_ data: Data) throws -> SdistGuestAuthChallenge {
    guard !data.isEmpty, data.count <= maximumSdistGuestAuthBytesV1 else {
        throw SdistGuestAuthenticationError.limitExceeded
    }
    guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(object) == data,
          Set(object.keys) == Set([
              "schema_version", "nonce_hex", "execution_binding_sha256", "run_spec_sha256",
              "build_closure_sha256", "clone_binding_sha256",
              "guest_auth_public_key_sha256"
          ]),
          object["schema_version"] as? String == sdistGuestAuthChallengeSchemaV1,
          let nonce = object["nonce_hex"] as? String,
          sdistValidLowerHex(nonce, length: 64),
          let execution = object["execution_binding_sha256"] as? String,
          let runSpec = object["run_spec_sha256"] as? String,
          let closure = object["build_closure_sha256"] as? String,
          let clone = object["clone_binding_sha256"] as? String,
          let publicKey = object["guest_auth_public_key_sha256"] as? String,
          sdistValidGuestAuthDigest(execution),
          sdistValidGuestAuthDigest(runSpec),
          sdistValidGuestAuthDigest(closure),
          sdistValidGuestAuthDigest(clone),
          sdistValidGuestAuthDigest(publicKey) else {
        throw SdistGuestAuthenticationError.nonCanonical
    }
    return SdistGuestAuthChallenge(
        canonicalJSON: data,
        executionBindingSHA256: execution,
        runSpecSHA256: runSpec,
        buildClosureSHA256: closure,
        cloneBindingSHA256: clone,
        guestAuthPublicKeySHA256: publicKey
    )
}

public func verifySdistGuestAuthResponse(
    _ responseData: Data,
    challenge: SdistGuestAuthChallenge,
    authorized: AuthorizedSdistRunSubmission,
    guestAuthPublicKey: Data
) throws -> SdistGuestAuthObservation {
    guard !responseData.isEmpty, responseData.count <= maximumSdistGuestAuthBytesV1 else {
        throw SdistGuestAuthenticationError.limitExceeded
    }
    let prelude = authorized.prelude
    let authority = authorized.authority
    guard guestAuthPublicKey.count == 32,
          sha256(guestAuthPublicKey) == challenge.guestAuthPublicKeySHA256,
          authority.replayStatePersisted,
          challenge.executionBindingSHA256 == prelude.executionBindingSHA256,
          challenge.runSpecSHA256 == authority.runSpecSHA256,
          challenge.buildClosureSHA256 == authority.buildClosureSHA256,
          challenge.guestAuthPublicKeySHA256
            == prelude.backendIdentity.guestAuthPublicKeySHA256 else {
        throw SdistGuestAuthenticationError.publicKeyMismatch
    }
    guard let response = try? JSONSerialization.jsonObject(with: responseData) as? [String: Any],
          try canonicalJSONData(response) == responseData,
          Set(response.keys) == Set([
              "schema_version", "challenge_sha256", "execution_binding_sha256",
              "run_spec_sha256", "build_closure_sha256", "clone_binding_sha256",
              "guest_supervisor_sha256", "runner_configuration_sha256", "package_uid",
              "package_gid", "signature_ed25519_hex"
          ]),
          response["schema_version"] as? String == sdistGuestAuthResponseSchemaV1,
          response["challenge_sha256"] as? String == sha256(challenge.canonicalJSON),
          response["execution_binding_sha256"] as? String == challenge.executionBindingSHA256,
          response["run_spec_sha256"] as? String == challenge.runSpecSHA256,
          response["build_closure_sha256"] as? String == challenge.buildClosureSHA256,
          response["clone_binding_sha256"] as? String == challenge.cloneBindingSHA256,
          response["guest_supervisor_sha256"] as? String
            == prelude.backendIdentity.guestSupervisorSHA256,
          response["runner_configuration_sha256"] as? String
            == prelude.backendIdentity.runnerConfigurationSHA256,
          response["package_uid"] as? String == String(prelude.backendIdentity.packageUID),
          response["package_gid"] as? String == String(prelude.backendIdentity.packageGID),
          let signatureHex = response["signature_ed25519_hex"] as? String,
          let signature = sdistDecodeLowerHex(signatureHex, byteCount: 64) else {
        throw SdistGuestAuthenticationError.invalidResponse
    }
    var unsigned = response
    unsigned.removeValue(forKey: "signature_ed25519_hex")
    let unsignedData = try canonicalJSONData(unsigned)
    var message = sdistGuestAuthResponseSignatureDomainV1
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let publicKey: Curve25519.Signing.PublicKey
    do {
        publicKey = try Curve25519.Signing.PublicKey(rawRepresentation: guestAuthPublicKey)
    } catch {
        throw SdistGuestAuthenticationError.publicKeyMismatch
    }
    guard publicKey.isValidSignature(signature, for: message) else {
        throw SdistGuestAuthenticationError.signatureFailed
    }
    return SdistGuestAuthObservation(
        challengeSHA256: sha256(challenge.canonicalJSON),
        executionBindingSHA256: challenge.executionBindingSHA256,
        runSpecSHA256: challenge.runSpecSHA256,
        buildClosureSHA256: challenge.buildClosureSHA256,
        cloneBindingSHA256: challenge.cloneBindingSHA256,
        guestSupervisorSHA256: prelude.backendIdentity.guestSupervisorSHA256,
        runnerConfigurationSHA256: prelude.backendIdentity.runnerConfigurationSHA256,
        packageUID: prelude.backendIdentity.packageUID,
        packageGID: prelude.backendIdentity.packageGID,
        signatureVerified: true
    )
}

private func sdistValidGuestAuthDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && sdistValidLowerHex(String(value.dropFirst(7)), length: 64)
}

private func sdistValidLowerHex(_ value: String, length: Int) -> Bool {
    value.utf8.count == length && value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
    }
}

private func sdistDecodeLowerHex(_ value: String, byteCount: Int) -> Data? {
    guard sdistValidLowerHex(value, length: byteCount * 2) else { return nil }
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
