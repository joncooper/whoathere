import CryptoKit
import Foundation

public let sdistGuestStagingReceiptSchemaV1 = "whoathere.sdist_guest_staging_receipt.v1"
private let sdistGuestStagingReceiptSignatureDomainV1 = Data(
    "whoathere.sdist_guest_staging_receipt.signature.v1\0".utf8
)

public struct SdistGuestStagingReceiptObservation: Equatable, Sendable {
    public let challengeSHA256: String
    public let executionBindingSHA256: String
    public let runSpecSHA256: String
    public let buildClosureSHA256: String
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
    public let syncBackEnabled: Bool
    public let buildClosureMaterialized: Bool
    public let signatureVerified: Bool
}

public func verifySdistGuestStagingReceipt(
    _ receiptData: Data,
    authenticated: SdistGuestAuthenticatedSession,
    authorized: AuthorizedSdistRunSubmission,
    transport: SdistRunTransportObservation,
    guestAuthPublicKey: Data
) throws -> SdistGuestStagingReceiptObservation {
    guard !receiptData.isEmpty, receiptData.count <= maximumSdistGuestAuthBytesV1 else {
        throw SdistGuestAuthenticationError.limitExceeded
    }
    let challenge = authenticated.challenge
    let prelude = authorized.prelude
    let authority = authorized.authority
    guard authenticated.observation.signatureVerified,
          authenticated.observation.challengeSHA256 == sha256(challenge.canonicalJSON),
          authenticated.observation.executionBindingSHA256 == prelude.executionBindingSHA256,
          authenticated.observation.runSpecSHA256 == authority.runSpecSHA256,
          authenticated.observation.buildClosureSHA256 == authority.buildClosureSHA256,
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
          transport.runSpecSHA256 == authority.runSpecSHA256,
          transport.buildClosureSHA256 == authority.buildClosureSHA256,
          transport.artifactSHA256 == authority.artifactSHA256,
          transport.artifactByteLength == prelude.artifactByteLength else {
        throw SdistGuestAuthenticationError.invalidResponse
    }
    guard let receipt = try? JSONSerialization.jsonObject(with: receiptData) as? [String: Any],
          try canonicalJSONData(receipt) == receiptData,
          Set(receipt.keys) == Set([
              "schema_version", "status", "challenge_sha256", "execution_binding_sha256",
              "run_spec_sha256", "build_closure_sha256", "clone_binding_sha256",
              "artifact_sha256", "artifact_byte_length", "first_rehash_sha256",
              "first_rehash_byte_length", "staged_device", "staged_inode",
              "artifact_file_name", "artifact_file_mode", "staging_directory_mode",
              "package_uid", "package_gid", "package_execution_enabled", "sync_back_enabled",
              "build_closure_materialized", "signature_ed25519_hex"
          ]),
          receipt["schema_version"] as? String == sdistGuestStagingReceiptSchemaV1,
          receipt["status"] as? String == "staged_no_execution_no_closure_materialization",
          receipt["challenge_sha256"] as? String == sha256(challenge.canonicalJSON),
          receipt["execution_binding_sha256"] as? String == challenge.executionBindingSHA256,
          receipt["run_spec_sha256"] as? String == challenge.runSpecSHA256,
          receipt["build_closure_sha256"] as? String == challenge.buildClosureSHA256,
          receipt["clone_binding_sha256"] as? String == challenge.cloneBindingSHA256,
          receipt["artifact_sha256"] as? String == transport.artifactSHA256,
          receipt["first_rehash_sha256"] as? String == transport.artifactSHA256,
          receipt["artifact_file_name"] as? String == "artifact.sdist",
          receipt["artifact_file_mode"] as? String == "0444",
          receipt["staging_directory_mode"] as? String == "0711",
          receipt["package_uid"] as? String == String(prelude.backendIdentity.packageUID),
          receipt["package_gid"] as? String == String(prelude.backendIdentity.packageGID),
          receipt["package_execution_enabled"] as? Bool == false,
          receipt["sync_back_enabled"] as? Bool == false,
          receipt["build_closure_materialized"] as? Bool == false,
          let artifactLengthText = receipt["artifact_byte_length"] as? String,
          let rehashLengthText = receipt["first_rehash_byte_length"] as? String,
          let deviceText = receipt["staged_device"] as? String,
          let inodeText = receipt["staged_inode"] as? String,
          let artifactLength = sdistReceiptUInt64(artifactLengthText),
          let rehashLength = sdistReceiptUInt64(rehashLengthText),
          let device = sdistReceiptUInt64(deviceText),
          let inode = sdistReceiptUInt64(inodeText),
          artifactLength == transport.artifactByteLength,
          rehashLength == transport.artifactByteLength,
          device > 0, inode > 0,
          let signatureHex = receipt["signature_ed25519_hex"] as? String,
          let signature = sdistReceiptSignatureData(signatureHex) else {
        throw SdistGuestAuthenticationError.invalidResponse
    }
    var unsigned = receipt
    unsigned.removeValue(forKey: "signature_ed25519_hex")
    let unsignedData = try canonicalJSONData(unsigned)
    var message = sdistGuestStagingReceiptSignatureDomainV1
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
    return SdistGuestStagingReceiptObservation(
        challengeSHA256: sha256(challenge.canonicalJSON),
        executionBindingSHA256: challenge.executionBindingSHA256,
        runSpecSHA256: challenge.runSpecSHA256,
        buildClosureSHA256: challenge.buildClosureSHA256,
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
        syncBackEnabled: false,
        buildClosureMaterialized: false,
        signatureVerified: true
    )
}

private func sdistReceiptUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}

private func sdistReceiptSignatureData(_ value: String) -> Data? {
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
