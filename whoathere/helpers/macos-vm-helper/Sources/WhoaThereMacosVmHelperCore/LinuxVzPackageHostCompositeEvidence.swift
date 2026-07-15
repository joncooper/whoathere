import CryptoKit
import Foundation

public let linuxVzPackageHostCompositeEvidenceSchemaV1 =
    "whoathere.linux_vz_package_host_composite_evidence.v1"
public let linuxVzPackageHostCompositeReceiptSchemaV1 =
    "whoathere.linux_vz_package_host_composite_receipt.v1"
public let maximumLinuxVzPackageHostCompositeEvidenceBytesV1 = 512 * 1024
public let maximumLinuxVzPackageHostCompositeReceiptBytesV1 = 64 * 1024
public let maximumLinuxVzPackageHostCompositeReceiptLifetimeSecondsV1: UInt64 = 10 * 60

private let linuxVzPackageHostCompositeReceiptDomainV1 = Data(
    "whoathere.linux_vz_package_host_composite_receipt.signature.v1\0".utf8
)

public enum LinuxVzPackageHostCompositeEvidenceError: Error, Equatable,
    CustomStringConvertible {
    case invalidLifecycle
    case invalidBinding
    case invalidEvidence
    case invalidReceipt
    case nonCanonical
    case publicKeyMismatch
    case signatureFailed
    case invalidTime
    case limitExceeded

    public var description: String {
        switch self {
        case .invalidLifecycle: return "linux_vz_package_host_composite_lifecycle_invalid"
        case .invalidBinding: return "linux_vz_package_host_composite_binding_invalid"
        case .invalidEvidence: return "linux_vz_package_host_composite_evidence_invalid"
        case .invalidReceipt: return "linux_vz_package_host_composite_receipt_invalid"
        case .nonCanonical: return "linux_vz_package_host_composite_noncanonical"
        case .publicKeyMismatch:
            return "linux_vz_package_host_composite_public_key_mismatch"
        case .signatureFailed: return "linux_vz_package_host_composite_signature_failed"
        case .invalidTime: return "linux_vz_package_host_composite_time_invalid"
        case .limitExceeded: return "linux_vz_package_host_composite_limit_exceeded"
        }
    }
}

/// Mac-owned lifecycle facts recorded only after the guest channel and VM have terminated and the
/// unique writable clone has been destroyed. Restricted evidence is referenced by digest only;
/// host paths and raw bytes never enter the portable envelope.
public struct LinuxVzPackageHostCompositeLifecycleV1: Equatable, Sendable {
    public let cloneBindingSHA256: String
    public let executionRuntimeRootfsSHA256: String
    public let executionRuntimeManifestSHA256: String
    public let packageExecutionRunnerSHA256: String
    public let hostEvidencePublicKeySHA256: String
    public let serialLogSHA256: String
    public let restrictedEvidenceReferenceSHA256s: [String]
    public let vmStarted: Bool
    public let guestChannelTerminated: Bool
    public let vmStopped: Bool
    public let imageIdentityStable: Bool
    public let cloneDestroyedAfterStop: Bool
    public let externalFramesForwarded: UInt64

    public init(
        cloneBindingSHA256: String,
        executionRuntimeRootfsSHA256: String,
        executionRuntimeManifestSHA256: String,
        packageExecutionRunnerSHA256: String,
        hostEvidencePublicKeySHA256: String,
        serialLogSHA256: String,
        restrictedEvidenceReferenceSHA256s: [String],
        vmStarted: Bool,
        guestChannelTerminated: Bool,
        vmStopped: Bool,
        imageIdentityStable: Bool,
        cloneDestroyedAfterStop: Bool,
        externalFramesForwarded: UInt64
    ) throws {
        let digests = [
            cloneBindingSHA256, executionRuntimeRootfsSHA256,
            executionRuntimeManifestSHA256, packageExecutionRunnerSHA256,
            hostEvidencePublicKeySHA256, serialLogSHA256
        ] + restrictedEvidenceReferenceSHA256s
        guard digests.allSatisfy(linuxVzPackageHostCompositeValidDigestV1),
              !restrictedEvidenceReferenceSHA256s.isEmpty,
              restrictedEvidenceReferenceSHA256s
                == restrictedEvidenceReferenceSHA256s.sorted(),
              Set(restrictedEvidenceReferenceSHA256s).count
                == restrictedEvidenceReferenceSHA256s.count,
              Set(digests).count == digests.count,
              vmStarted, guestChannelTerminated, vmStopped, imageIdentityStable,
              cloneDestroyedAfterStop, externalFramesForwarded == 0 else {
            throw LinuxVzPackageHostCompositeEvidenceError.invalidLifecycle
        }
        self.cloneBindingSHA256 = cloneBindingSHA256
        self.executionRuntimeRootfsSHA256 = executionRuntimeRootfsSHA256
        self.executionRuntimeManifestSHA256 = executionRuntimeManifestSHA256
        self.packageExecutionRunnerSHA256 = packageExecutionRunnerSHA256
        self.hostEvidencePublicKeySHA256 = hostEvidencePublicKeySHA256
        self.serialLogSHA256 = serialLogSHA256
        self.restrictedEvidenceReferenceSHA256s = restrictedEvidenceReferenceSHA256s
        self.vmStarted = vmStarted
        self.guestChannelTerminated = guestChannelTerminated
        self.vmStopped = vmStopped
        self.imageIdentityStable = imageIdentityStable
        self.cloneDestroyedAfterStop = cloneDestroyedAfterStop
        self.externalFramesForwarded = externalFramesForwarded
    }
}

public struct LinuxVzPackageHostCompositeEvidenceV1: Equatable, Sendable {
    public let canonicalJSON: Data
    public let evidenceSHA256: String
    public let rootReceiptSHA256: String
    public let hostNetworkEvidenceSHA256: String
    public let artifactSHA256: String
    public let executionGrantSHA256: String
    public let cloneBindingSHA256: String
    public let hostEvidencePublicKeySHA256: String
    public var lifecycleComplete: Bool { true }
    public var selectedHostCorrelationComplete: Bool { true }
    public var broadHostNetworkCoverageComplete: Bool { false }
    public var compositeEvidenceComplete: Bool { false }
    public var authoritativeVerdictPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public struct VerifiedLinuxVzPackageHostCompositeReceiptV1: Equatable, Sendable {
    public let receiptSHA256: String
    public let compositeEvidenceSHA256: String
    public let rootReceiptSHA256: String
    public let hostNetworkEvidenceSHA256: String
    public let artifactSHA256: String
    public let executionGrantSHA256: String
    public let cloneBindingSHA256: String
    public let createdAtUnixSeconds: UInt64
    public let expiresAtUnixSeconds: UInt64
    public var lifecycleComplete: Bool { true }
    public var selectedHostCorrelationComplete: Bool { true }
    public var broadHostNetworkCoverageComplete: Bool { false }
    public var compositeEvidenceComplete: Bool { false }
    public var authoritativeVerdictPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func makeLinuxVzPackageHostCompositeEvidenceV1(
    verifiedRootReceipt: VerifiedLinuxVzPackageRootEvidenceReceiptV2,
    rootReceiptData: Data,
    hostNetworkEvidence: LinuxVzPackageHostUDPSendtoEvidenceV1,
    lifecycle: LinuxVzPackageHostCompositeLifecycleV1
) throws -> LinuxVzPackageHostCompositeEvidenceV1 {
    guard sha256(rootReceiptData) == verifiedRootReceipt.receiptSHA256,
          hostNetworkEvidence.payloadSHA256 == sha256(hostNetworkEvidence.canonicalJSON),
          hostNetworkEvidence.rootNetworkEvidenceSHA256
            == verifiedRootReceipt.networkEvidenceSHA256,
          hostNetworkEvidence.processEvidenceSHA256
            == verifiedRootReceipt.processEvidenceSHA256,
          hostNetworkEvidence.selectedCorrelationComplete,
          !hostNetworkEvidence.broadHostFrameCoverageComplete,
          lifecycle.cloneBindingSHA256 == verifiedRootReceipt.cloneBindingSHA256,
          lifecycle.executionRuntimeRootfsSHA256
            == verifiedRootReceipt.executionRuntimeRootfsSHA256,
          lifecycle.executionRuntimeManifestSHA256
            == verifiedRootReceipt.executionRuntimeManifestSHA256,
          lifecycle.packageExecutionRunnerSHA256
            == verifiedRootReceipt.packageExecutionRunnerSHA256,
          lifecycle.hostEvidencePublicKeySHA256
            != verifiedRootReceipt.guestEvidencePublicKeySHA256 else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidBinding
    }
    let events: [[String: Any]] = [
        ["event": "guest_root_receipt_verified", "sequence": "1"],
        ["event": "host_raw_frame_correlated_and_drained", "sequence": "2"],
        ["event": "guest_channel_terminated", "sequence": "3"],
        ["event": "vm_stopped", "sequence": "4"],
        ["event": "image_identity_remeasured_stable", "sequence": "5"],
        ["event": "clone_destroyed_after_stop", "sequence": "6"]
    ]
    let value: [String: Any] = [
        "schema_version": linuxVzPackageHostCompositeEvidenceSchemaV1,
        "authority": "mac_host_lifecycle_and_raw_frame_composer",
        "artifact_sha256": verifiedRootReceipt.artifactSHA256,
        "package_authority_request_sha256":
            verifiedRootReceipt.packageAuthorityRequestSHA256,
        "execution_grant_sha256": verifiedRootReceipt.executionGrantSHA256,
        "clone_binding_sha256": verifiedRootReceipt.cloneBindingSHA256,
        "execution_runtime_rootfs_sha256":
            verifiedRootReceipt.executionRuntimeRootfsSHA256,
        "execution_runtime_manifest_sha256":
            verifiedRootReceipt.executionRuntimeManifestSHA256,
        "package_execution_runner_sha256":
            verifiedRootReceipt.packageExecutionRunnerSHA256,
        "guest_evidence_public_key_sha256":
            verifiedRootReceipt.guestEvidencePublicKeySHA256,
        "host_evidence_public_key_sha256": lifecycle.hostEvidencePublicKeySHA256,
        "guest_root_receipt_sha256": verifiedRootReceipt.receiptSHA256,
        "guest_process_evidence_sha256": verifiedRootReceipt.processEvidenceSHA256,
        "guest_file_evidence_sha256": verifiedRootReceipt.fileEvidenceSHA256,
        "guest_network_evidence_sha256": verifiedRootReceipt.networkEvidenceSHA256,
        "host_network_evidence_schema": linuxVzPackageHostUDPSendtoEvidenceSchemaV2,
        "host_network_evidence_sha256": hostNetworkEvidence.payloadSHA256,
        "host_frame_sha256": hostNetworkEvidence.frameSHA256,
        "host_egress_packet_correlation_sha256":
            hostNetworkEvidence.egressPacketCorrelationSHA256,
        "serial_log_sha256": lifecycle.serialLogSHA256,
        "restricted_evidence_reference_sha256s":
            lifecycle.restrictedEvidenceReferenceSHA256s,
        "events": events,
        "event_sequence_start": "1",
        "event_sequence_end": "6",
        "event_count": "6",
        "root_evidence_complete": verifiedRootReceipt.evidenceComplete,
        "selected_udp_sendto_host_correlation_complete": true,
        "broad_host_network_coverage_complete": false,
        "host_lifecycle_complete": true,
        "composite_evidence_complete": false,
        "vm_started": lifecycle.vmStarted,
        "guest_channel_terminated": lifecycle.guestChannelTerminated,
        "vm_stopped": lifecycle.vmStopped,
        "image_identity_stable": lifecycle.imageIdentityStable,
        "clone_destroyed_after_stop": lifecycle.cloneDestroyedAfterStop,
        "external_frames_forwarded": String(lifecycle.externalFramesForwarded),
        "public_network_route_present": false,
        "restricted_evidence_references_are_digests_only": true,
        "verdict_state": "inconclusive_incomplete_coverage",
        "authoritative_verdict_permitted": false,
        "sync_back_policy": "structurally_absent"
    ]
    let canonical = try canonicalJSONData(value)
    guard canonical.count <= maximumLinuxVzPackageHostCompositeEvidenceBytesV1 else {
        throw LinuxVzPackageHostCompositeEvidenceError.limitExceeded
    }
    return LinuxVzPackageHostCompositeEvidenceV1(
        canonicalJSON: canonical,
        evidenceSHA256: sha256(canonical),
        rootReceiptSHA256: verifiedRootReceipt.receiptSHA256,
        hostNetworkEvidenceSHA256: hostNetworkEvidence.payloadSHA256,
        artifactSHA256: verifiedRootReceipt.artifactSHA256,
        executionGrantSHA256: verifiedRootReceipt.executionGrantSHA256,
        cloneBindingSHA256: verifiedRootReceipt.cloneBindingSHA256,
        hostEvidencePublicKeySHA256: lifecycle.hostEvidencePublicKeySHA256
    )
}

public func decodeLinuxVzPackageHostCompositeEvidenceV1(
    _ data: Data,
    verifiedRootReceipt: VerifiedLinuxVzPackageRootEvidenceReceiptV2,
    rootReceiptData: Data,
    hostNetworkEvidence: LinuxVzPackageHostUDPSendtoEvidenceV1,
    lifecycle: LinuxVzPackageHostCompositeLifecycleV1
) throws -> LinuxVzPackageHostCompositeEvidenceV1 {
    guard !data.isEmpty,
          data.count <= maximumLinuxVzPackageHostCompositeEvidenceBytesV1,
          let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidEvidence
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzPackageHostCompositeEvidenceError.nonCanonical
    }
    let expected = try makeLinuxVzPackageHostCompositeEvidenceV1(
        verifiedRootReceipt: verifiedRootReceipt,
        rootReceiptData: rootReceiptData,
        hostNetworkEvidence: hostNetworkEvidence,
        lifecycle: lifecycle
    )
    guard data == expected.canonicalJSON else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidBinding
    }
    return expected
}

public func signLinuxVzPackageHostCompositeReceiptV1(
    evidence: LinuxVzPackageHostCompositeEvidenceV1,
    lifecycle: LinuxVzPackageHostCompositeLifecycleV1,
    createdAtUnixSeconds: UInt64,
    expiresAtUnixSeconds: UInt64,
    signingSeed: inout Data
) throws -> Data {
    defer { signingSeed.resetBytes(in: 0..<signingSeed.count) }
    try linuxVzPackageHostCompositeValidateTimeV1(
        createdAtUnixSeconds: createdAtUnixSeconds,
        expiresAtUnixSeconds: expiresAtUnixSeconds,
        observedAtUnixSeconds: createdAtUnixSeconds
    )
    guard signingSeed.count == 32,
          let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingSeed),
          sha256(privateKey.publicKey.rawRepresentation)
            == lifecycle.hostEvidencePublicKeySHA256,
          evidence.hostEvidencePublicKeySHA256 == lifecycle.hostEvidencePublicKeySHA256 else {
        throw LinuxVzPackageHostCompositeEvidenceError.publicKeyMismatch
    }
    let unsigned = linuxVzPackageHostCompositeUnsignedReceiptV1(
        evidence: evidence,
        createdAtUnixSeconds: createdAtUnixSeconds,
        expiresAtUnixSeconds: expiresAtUnixSeconds
    )
    let unsignedData = try canonicalJSONData(unsigned)
    let message = linuxVzPackageHostCompositeSignatureMessageV1(
        evidence: evidence.canonicalJSON,
        unsignedReceipt: unsignedData
    )
    let signature = try privateKey.signature(for: message)
    var receipt = unsigned
    receipt["signature_ed25519_hex"] = linuxVzPackageHostCompositeHexV1(signature)
    let data = try canonicalJSONData(receipt)
    guard data.count <= maximumLinuxVzPackageHostCompositeReceiptBytesV1 else {
        throw LinuxVzPackageHostCompositeEvidenceError.limitExceeded
    }
    return data
}

public func verifyLinuxVzPackageHostCompositeReceiptV1(
    _ receiptData: Data,
    evidence: LinuxVzPackageHostCompositeEvidenceV1,
    lifecycle: LinuxVzPackageHostCompositeLifecycleV1,
    hostVerifyingKey: Data,
    observedAtUnixSeconds: UInt64
) throws -> VerifiedLinuxVzPackageHostCompositeReceiptV1 {
    guard !receiptData.isEmpty,
          receiptData.count <= maximumLinuxVzPackageHostCompositeReceiptBytesV1,
          let receipt = try? JSONSerialization.jsonObject(with: receiptData)
            as? [String: Any] else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidReceipt
    }
    guard try canonicalJSONData(receipt) == receiptData else {
        throw LinuxVzPackageHostCompositeEvidenceError.nonCanonical
    }
    var unsigned = receipt
    guard let signatureHex = unsigned.removeValue(forKey: "signature_ed25519_hex") as? String,
          Set(unsigned.keys) == linuxVzPackageHostCompositeReceiptKeysV1,
          let signature = linuxVzPackageHostCompositeDecodeHexV1(
            signatureHex, byteCount: 64
          ) else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidReceipt
    }
    let expected = linuxVzPackageHostCompositeUnsignedReceiptV1(
        evidence: evidence,
        createdAtUnixSeconds: try linuxVzPackageHostCompositeUInt64V1(
            unsigned["created_at_unix_seconds"]
        ),
        expiresAtUnixSeconds: try linuxVzPackageHostCompositeUInt64V1(
            unsigned["expires_at_unix_seconds"]
        )
    )
    guard try canonicalJSONData(unsigned) == canonicalJSONData(expected) else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidBinding
    }
    let createdAt = try linuxVzPackageHostCompositeUInt64V1(
        unsigned["created_at_unix_seconds"]
    )
    let expiresAt = try linuxVzPackageHostCompositeUInt64V1(
        unsigned["expires_at_unix_seconds"]
    )
    try linuxVzPackageHostCompositeValidateTimeV1(
        createdAtUnixSeconds: createdAt,
        expiresAtUnixSeconds: expiresAt,
        observedAtUnixSeconds: observedAtUnixSeconds
    )
    guard hostVerifyingKey.count == 32,
          !hostVerifyingKey.allSatisfy({ $0 == 0 }),
          sha256(hostVerifyingKey) == lifecycle.hostEvidencePublicKeySHA256,
          let publicKey = try? Curve25519.Signing.PublicKey(
            rawRepresentation: hostVerifyingKey
          ) else {
        throw LinuxVzPackageHostCompositeEvidenceError.publicKeyMismatch
    }
    let unsignedData = try canonicalJSONData(unsigned)
    let message = linuxVzPackageHostCompositeSignatureMessageV1(
        evidence: evidence.canonicalJSON,
        unsignedReceipt: unsignedData
    )
    guard publicKey.isValidSignature(signature, for: message) else {
        throw LinuxVzPackageHostCompositeEvidenceError.signatureFailed
    }
    return VerifiedLinuxVzPackageHostCompositeReceiptV1(
        receiptSHA256: sha256(receiptData),
        compositeEvidenceSHA256: evidence.evidenceSHA256,
        rootReceiptSHA256: evidence.rootReceiptSHA256,
        hostNetworkEvidenceSHA256: evidence.hostNetworkEvidenceSHA256,
        artifactSHA256: evidence.artifactSHA256,
        executionGrantSHA256: evidence.executionGrantSHA256,
        cloneBindingSHA256: evidence.cloneBindingSHA256,
        createdAtUnixSeconds: createdAt,
        expiresAtUnixSeconds: expiresAt
    )
}

private func linuxVzPackageHostCompositeUnsignedReceiptV1(
    evidence: LinuxVzPackageHostCompositeEvidenceV1,
    createdAtUnixSeconds: UInt64,
    expiresAtUnixSeconds: UInt64
) -> [String: Any] {
    [
        "schema_version": linuxVzPackageHostCompositeReceiptSchemaV1,
        "authority": "mac_host_composite_evidence_signer",
        "composite_evidence_sha256": evidence.evidenceSHA256,
        "guest_root_receipt_sha256": evidence.rootReceiptSHA256,
        "host_network_evidence_sha256": evidence.hostNetworkEvidenceSHA256,
        "artifact_sha256": evidence.artifactSHA256,
        "execution_grant_sha256": evidence.executionGrantSHA256,
        "clone_binding_sha256": evidence.cloneBindingSHA256,
        "host_evidence_public_key_sha256": evidence.hostEvidencePublicKeySHA256,
        "host_lifecycle_complete": true,
        "selected_udp_sendto_host_correlation_complete": true,
        "broad_host_network_coverage_complete": false,
        "composite_evidence_complete": false,
        "verdict_state": "inconclusive_incomplete_coverage",
        "authoritative_verdict_permitted": false,
        "sync_back_policy": "structurally_absent",
        "created_at_unix_seconds": String(createdAtUnixSeconds),
        "expires_at_unix_seconds": String(expiresAtUnixSeconds)
    ]
}

private let linuxVzPackageHostCompositeReceiptKeysV1 = Set([
    "schema_version", "authority", "composite_evidence_sha256",
    "guest_root_receipt_sha256", "host_network_evidence_sha256", "artifact_sha256",
    "execution_grant_sha256", "clone_binding_sha256", "host_evidence_public_key_sha256",
    "host_lifecycle_complete", "selected_udp_sendto_host_correlation_complete",
    "broad_host_network_coverage_complete", "composite_evidence_complete", "verdict_state",
    "authoritative_verdict_permitted", "sync_back_policy", "created_at_unix_seconds",
    "expires_at_unix_seconds"
])

private func linuxVzPackageHostCompositeSignatureMessageV1(
    evidence: Data,
    unsignedReceipt: Data
) -> Data {
    var message = linuxVzPackageHostCompositeReceiptDomainV1
    linuxVzPackageHostCompositeAppendUInt64V1(UInt64(evidence.count), to: &message)
    message.append(evidence)
    linuxVzPackageHostCompositeAppendUInt64V1(UInt64(unsignedReceipt.count), to: &message)
    message.append(unsignedReceipt)
    return message
}

private func linuxVzPackageHostCompositeValidateTimeV1(
    createdAtUnixSeconds: UInt64,
    expiresAtUnixSeconds: UInt64,
    observedAtUnixSeconds: UInt64
) throws {
    guard createdAtUnixSeconds > 0,
          expiresAtUnixSeconds > createdAtUnixSeconds,
          expiresAtUnixSeconds - createdAtUnixSeconds
            <= maximumLinuxVzPackageHostCompositeReceiptLifetimeSecondsV1,
          observedAtUnixSeconds >= createdAtUnixSeconds,
          observedAtUnixSeconds < expiresAtUnixSeconds else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidTime
    }
}

private func linuxVzPackageHostCompositeValidDigestV1(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func linuxVzPackageHostCompositeUInt64V1(_ value: Any?) throws -> UInt64 {
    guard let text = value as? String,
          !text.isEmpty, text.utf8.count <= 20,
          text == "0" || !text.hasPrefix("0"),
          text.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(text) else {
        throw LinuxVzPackageHostCompositeEvidenceError.invalidReceipt
    }
    return parsed
}

private func linuxVzPackageHostCompositeAppendUInt64V1(
    _ value: UInt64,
    to data: inout Data
) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func linuxVzPackageHostCompositeHexV1(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func linuxVzPackageHostCompositeDecodeHexV1(
    _ value: String,
    byteCount: Int
) -> Data? {
    guard value.utf8.count == byteCount * 2 else { return nil }
    var data = Data(capacity: byteCount)
    var index = value.startIndex
    for _ in 0..<byteCount {
        let next = value.index(index, offsetBy: 2)
        let pair = value[index..<next]
        guard pair.utf8.allSatisfy({ byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }), let byte = UInt8(pair, radix: 16) else { return nil }
        data.append(byte)
        index = next
    }
    return data
}
