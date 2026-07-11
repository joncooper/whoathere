import CryptoKit
import Foundation

public let artifactGuestStagingReceiptSchemaV1 = "whoathere.artifact_guest_staging_receipt.v1"
private let artifactGuestStagingReceiptSignatureDomainV1 = Data(
    "whoathere.artifact_guest_staging_receipt.signature.v1\0".utf8
)

public struct ArtifactGuestStagingReceiptObservation: Equatable, Sendable {
    public let challengeSHA256: String
    public let executionBindingSHA256: String
    public let runSpecSHA256: String
    public let cloneBindingSHA256: String
    public let artifactSHA256: String
    public let artifactByteLength: UInt64
    public let firstRehashSHA256: String
    public let firstRehashByteLength: UInt64
    public let stagedDevice: UInt64
    public let stagedInode: UInt64
    public let packageUID: UInt32
    public let packageGID: UInt32
    public let packageExecutionEnabled: Bool
    public let signatureVerified: Bool
}

public func receiveArtifactGuestStagingReceipt(
    descriptor: Int32,
    authenticated: ArtifactGuestAuthenticatedSession,
    prelude: ArtifactRunSubmissionPrelude,
    transport: ArtifactRunTransportObservation,
    base: LockedArtifactRunBase,
    timeoutMillis: Int32 = 10_000
) throws -> ArtifactGuestStagingReceiptObservation {
    guard base.identity == prelude.backendIdentity else {
        throw ArtifactGuestAuthenticationError.invalidResponse
    }
    let body = try readArtifactGuestControlFrame(
        descriptor: descriptor,
        expectedType: .stagingReceipt,
        maximumBodyBytes: maximumArtifactGuestAuthBytesV1,
        timeoutMillis: timeoutMillis
    )
    let observation = try verifyArtifactGuestStagingReceipt(
        body,
        authenticated: authenticated,
        prelude: prelude,
        transport: transport,
        guestAuthPublicKey: base.guestAuthPublicKeyData
    )
    try requireArtifactGuestControlEOF(
        descriptor: descriptor,
        timeoutMillis: timeoutMillis
    )
    return observation
}

public func verifyArtifactGuestStagingReceipt(
    _ receiptData: Data,
    authenticated: ArtifactGuestAuthenticatedSession,
    prelude: ArtifactRunSubmissionPrelude,
    transport: ArtifactRunTransportObservation,
    guestAuthPublicKey: Data
) throws -> ArtifactGuestStagingReceiptObservation {
    guard !receiptData.isEmpty, receiptData.count <= maximumArtifactGuestAuthBytesV1 else {
        throw ArtifactGuestAuthenticationError.limitExceeded
    }
    let challenge = authenticated.challenge
    guard authenticated.observation.signatureVerified,
          authenticated.observation.challengeSHA256 == sha256(challenge.canonicalJSON),
          authenticated.observation.executionBindingSHA256 == prelude.executionBindingSHA256,
          authenticated.observation.runSpecSHA256 == prelude.runSpecSHA256,
          authenticated.observation.cloneBindingSHA256 == challenge.cloneBindingSHA256,
          authenticated.observation.guestSupervisorSHA256
            == prelude.backendIdentity.guestSupervisorSHA256,
          authenticated.observation.runnerConfigurationSHA256
            == prelude.backendIdentity.runnerConfigurationSHA256,
          authenticated.observation.packageUID == prelude.backendIdentity.packageUID,
          authenticated.observation.packageGID == prelude.backendIdentity.packageGID,
          guestAuthPublicKey.count == 32,
          sha256(guestAuthPublicKey) == challenge.guestAuthPublicKeySHA256,
          transport.executionBindingSHA256 == prelude.executionBindingSHA256,
          transport.runSpecSHA256 == prelude.runSpecSHA256,
          transport.artifactSHA256 == prelude.artifactSHA256,
          transport.artifactByteLength == prelude.artifactByteLength else {
        throw ArtifactGuestAuthenticationError.invalidResponse
    }
    guard let receipt = try? JSONSerialization.jsonObject(with: receiptData) as? [String: Any],
          try canonicalJSONData(receipt) == receiptData,
          Set(receipt.keys) == Set([
            "schema_version", "status", "challenge_sha256", "execution_binding_sha256",
            "run_spec_sha256", "clone_binding_sha256", "artifact_sha256",
            "artifact_byte_length", "first_rehash_sha256", "first_rehash_byte_length",
            "staged_device", "staged_inode", "artifact_file_mode",
            "staging_directory_mode", "package_uid", "package_gid",
            "package_execution_enabled", "signature_ed25519_hex"
          ]),
          receipt["schema_version"] as? String == artifactGuestStagingReceiptSchemaV1,
          receipt["status"] as? String == "staged_no_execution",
          receipt["challenge_sha256"] as? String == sha256(challenge.canonicalJSON),
          receipt["execution_binding_sha256"] as? String == challenge.executionBindingSHA256,
          receipt["run_spec_sha256"] as? String == challenge.runSpecSHA256,
          receipt["clone_binding_sha256"] as? String == challenge.cloneBindingSHA256,
          receipt["artifact_sha256"] as? String == transport.artifactSHA256,
          receipt["first_rehash_sha256"] as? String == transport.artifactSHA256,
          receipt["artifact_file_mode"] as? String == "0444",
          receipt["staging_directory_mode"] as? String == "0711",
          receipt["package_uid"] as? String == String(prelude.backendIdentity.packageUID),
          receipt["package_gid"] as? String == String(prelude.backendIdentity.packageGID),
          receipt["package_execution_enabled"] as? Bool == false,
          let artifactLengthText = receipt["artifact_byte_length"] as? String,
          let rehashLengthText = receipt["first_rehash_byte_length"] as? String,
          let deviceText = receipt["staged_device"] as? String,
          let inodeText = receipt["staged_inode"] as? String,
          let artifactLength = canonicalReceiptUInt64(artifactLengthText),
          let rehashLength = canonicalReceiptUInt64(rehashLengthText),
          let device = canonicalReceiptUInt64(deviceText),
          let inode = canonicalReceiptUInt64(inodeText),
          artifactLength == transport.artifactByteLength,
          rehashLength == transport.artifactByteLength,
          device > 0, inode > 0,
          let signatureHex = receipt["signature_ed25519_hex"] as? String,
          let signature = receiptSignatureData(signatureHex) else {
        throw ArtifactGuestAuthenticationError.invalidResponse
    }
    var unsigned = receipt
    unsigned.removeValue(forKey: "signature_ed25519_hex")
    let unsignedData = try canonicalJSONData(unsigned)
    var message = artifactGuestStagingReceiptSignatureDomainV1
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
    return ArtifactGuestStagingReceiptObservation(
        challengeSHA256: sha256(challenge.canonicalJSON),
        executionBindingSHA256: challenge.executionBindingSHA256,
        runSpecSHA256: challenge.runSpecSHA256,
        cloneBindingSHA256: challenge.cloneBindingSHA256,
        artifactSHA256: transport.artifactSHA256,
        artifactByteLength: artifactLength,
        firstRehashSHA256: transport.artifactSHA256,
        firstRehashByteLength: rehashLength,
        stagedDevice: device,
        stagedInode: inode,
        packageUID: prelude.backendIdentity.packageUID,
        packageGID: prelude.backendIdentity.packageGID,
        packageExecutionEnabled: false,
        signatureVerified: true
    )
}

private func canonicalReceiptUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}

private func receiptSignatureData(_ value: String) -> Data? {
    guard value.utf8.count == 128 else { return nil }
    var data = Data()
    data.reserveCapacity(64)
    var index = value.startIndex
    for _ in 0..<64 {
        let next = value.index(index, offsetBy: 2)
        guard let byte = UInt8(value[index..<next], radix: 16),
              value[index..<next].utf8.allSatisfy({
                ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
              }) else {
            return nil
        }
        data.append(byte)
        index = next
    }
    return data
}
