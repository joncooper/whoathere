import CryptoKit
import Foundation

public let linuxVzPackageRuntimeQualificationHostEvidenceSchemaV1 =
    "whoathere.macos_linux_vz_package_runtime_qualification_host_evidence.v1"
public let linuxVzPackageRuntimeQualificationHostReceiptSchemaV1 =
    "whoathere.macos_linux_vz_package_runtime_qualification_host_receipt.v1"
private let linuxVzPackageRuntimeQualificationHostReceiptDomainV1 = Data(
    "whoathere.macos_linux_vz_package_runtime_qualification_host_receipt.signature.v1\0".utf8
)

public enum LinuxVzPackageRuntimeQualificationHostReceiptError: Error, Equatable {
    case invalidEvidence
    case invalidReceipt
    case publicKeyMismatch
    case signatureFailed
    case nonCanonical
}

public struct LinuxVzPackageRuntimeQualificationHostEvidence: Equatable, Sendable {
    public let canonicalJSON: Data
    public let evidenceSHA256: String
    public let requestFrameSHA256: String
    public let responseFrameSHA256: String
    public let guestReceiptSHA256: String
    public let processEvidenceSHA256: String
    public let serialLogSHA256: String
    public var executionAuthorityPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public struct VerifiedLinuxVzPackageRuntimeQualificationHostReceipt: Equatable, Sendable {
    public let qualificationRequestSHA256: String
    public let hostEvidenceSHA256: String
    public let cloneBindingSHA256: String
    public var executionAuthorityPermitted: Bool { false }
    public var packageExecutionPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func makeLinuxVzPackageRuntimeQualificationHostEvidence(
    request: ParsedLinuxVzPackageRuntimeQualificationRequest,
    requestFrame: Data,
    responseFrame: Data,
    response: LinuxVzPackageRuntimeQualificationResponse,
    serialLogSHA256: String,
    rawFrameCount: UInt64,
    droppedFrameCount: UInt64,
    packetSensorHealthy: Bool,
    guestChannelTerminated: Bool,
    vmStarted: Bool,
    vmStopped: Bool,
    cloneDestroyed: Bool,
    imageIdentityStable: Bool
) throws -> LinuxVzPackageRuntimeQualificationHostEvidence {
    guard try decodeLinuxVzPackageRuntimeQualificationRequestFrame(requestFrame)
            == request.canonicalJSON,
          try decodeLinuxVzPackageRuntimeQualificationResponse(responseFrame) == response,
          linuxVzRuntimeQualificationHostValidDigest(serialLogSHA256),
          response.probeReport == linuxVzPackageRuntimeProbeReportV1,
          rawFrameCount == 0,
          droppedFrameCount == 0,
          packetSensorHealthy,
          guestChannelTerminated,
          vmStarted,
          vmStopped,
          cloneDestroyed,
          imageIdentityStable else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.invalidEvidence
    }
    let processEvidenceSHA256 = sha256(response.processEvidence)
    let events: [[String: Any]] = [
        ["event": "clone_created_and_bound", "sequence": "1"],
        ["event": "vm_started", "sequence": "2"],
        ["event": "guest_response_completed", "sequence": "3"],
        ["event": "raw_frame_sinkhole_drained", "sequence": "4"],
        ["event": "vm_stopped", "sequence": "5"],
        ["event": "clone_destroyed_after_stop", "sequence": "6"]
    ]
    let value: [String: Any] = [
        "schema_version": linuxVzPackageRuntimeQualificationHostEvidenceSchemaV1,
        "authority": "host_vm_network_and_clone_lifecycle",
        "qualification_request_sha256": request.requestSHA256,
        "request_frame_sha256": sha256(requestFrame),
        "response_frame_sha256": sha256(responseFrame),
        "guest_receipt_sha256": sha256(response.guestReceipt),
        "process_evidence_sha256": processEvidenceSHA256,
        "probe_report_sha256": sha256(response.probeReport),
        "serial_log_sha256": serialLogSHA256,
        "clone_binding_sha256": request.cloneBindingSHA256,
        "events": events,
        "event_sequence_start": "1",
        "event_sequence_end": "6",
        "event_count": "6",
        "raw_frame_count": "0",
        "dropped_frame_count": "0",
        "external_frames_forwarded": "0",
        "packet_sensor_healthy": true,
        "guest_channel_terminated": true,
        "vm_started": true,
        "vm_stopped": true,
        "clone_destroyed": true,
        "image_identity_stable": true,
        "public_network_route_present": false,
        "package_execution": false,
        "execution_authority_issued": false,
        "sync_back_policy": "structurally_absent"
    ]
    let canonicalJSON = try canonicalJSONData(value)
    return LinuxVzPackageRuntimeQualificationHostEvidence(
        canonicalJSON: canonicalJSON,
        evidenceSHA256: sha256(canonicalJSON),
        requestFrameSHA256: sha256(requestFrame),
        responseFrameSHA256: sha256(responseFrame),
        guestReceiptSHA256: sha256(response.guestReceipt),
        processEvidenceSHA256: processEvidenceSHA256,
        serialLogSHA256: serialLogSHA256
    )
}

public func signLinuxVzPackageRuntimeQualificationHostReceipt(
    request: ParsedLinuxVzPackageRuntimeQualificationRequest,
    evidence: LinuxVzPackageRuntimeQualificationHostEvidence,
    signingSeed: inout Data
) throws -> Data {
    defer { signingSeed.resetBytes(in: 0..<signingSeed.count) }
    guard signingSeed.count == 32,
          let privateKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: signingSeed),
          sha256(privateKey.publicKey.rawRepresentation)
            == request.hostEvidencePublicKeySHA256 else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.publicKeyMismatch
    }
    let unsigned = linuxVzRuntimeQualificationHostUnsignedReceipt(
        request: request,
        evidence: evidence
    )
    let unsignedData = try canonicalJSONData(unsigned)
    let message = linuxVzRuntimeQualificationHostSignatureMessage(
        request: request.canonicalJSON,
        evidence: evidence.canonicalJSON,
        unsignedReceipt: unsignedData
    )
    let signature = try privateKey.signature(for: message)
    var receipt = unsigned
    receipt["signature_ed25519_hex"] = signature.map {
        String(format: "%02x", $0)
    }.joined()
    return try canonicalJSONData(receipt)
}

public func verifyLinuxVzPackageRuntimeQualificationHostReceipt(
    _ data: Data,
    request: ParsedLinuxVzPackageRuntimeQualificationRequest,
    evidence: LinuxVzPackageRuntimeQualificationHostEvidence,
    hostVerifyingKey: Data
) throws -> VerifiedLinuxVzPackageRuntimeQualificationHostReceipt {
    guard sha256(hostVerifyingKey) == request.hostEvidencePublicKeySHA256,
          let publicKey = try? Curve25519.Signing.PublicKey(
            rawRepresentation: hostVerifyingKey
          ) else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.publicKeyMismatch
    }
    guard let receipt = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.invalidReceipt
    }
    guard try canonicalJSONData(receipt) == data else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.nonCanonical
    }
    var unsigned = receipt
    guard let signatureHex = unsigned.removeValue(forKey: "signature_ed25519_hex") as? String,
          let signature = linuxVzRuntimeQualificationHostDecodeHex(
            signatureHex,
            byteCount: 64
          ) else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.invalidReceipt
    }
    let expected = linuxVzRuntimeQualificationHostUnsignedReceipt(
        request: request,
        evidence: evidence
    )
    guard Set(unsigned.keys) == Set(expected.keys),
          try canonicalJSONData(unsigned) == canonicalJSONData(expected) else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.invalidReceipt
    }
    let unsignedData = try canonicalJSONData(unsigned)
    let message = linuxVzRuntimeQualificationHostSignatureMessage(
        request: request.canonicalJSON,
        evidence: evidence.canonicalJSON,
        unsignedReceipt: unsignedData
    )
    guard publicKey.isValidSignature(signature, for: message) else {
        throw LinuxVzPackageRuntimeQualificationHostReceiptError.signatureFailed
    }
    return VerifiedLinuxVzPackageRuntimeQualificationHostReceipt(
        qualificationRequestSHA256: request.requestSHA256,
        hostEvidenceSHA256: evidence.evidenceSHA256,
        cloneBindingSHA256: request.cloneBindingSHA256
    )
}

private func linuxVzRuntimeQualificationHostUnsignedReceipt(
    request: ParsedLinuxVzPackageRuntimeQualificationRequest,
    evidence: LinuxVzPackageRuntimeQualificationHostEvidence
) -> [String: Any] {
    [
        "schema_version": linuxVzPackageRuntimeQualificationHostReceiptSchemaV1,
        "authority": "host_vm_network_and_clone_lifecycle",
        "qualification_request_sha256": request.requestSHA256,
        "qualified_telemetry_backend_sha256": request.qualifiedTelemetryBackendSHA256,
        "backend_identity_sha256": request.backendIdentitySHA256,
        "telemetry_requirements_sha256": request.telemetryRequirementsSHA256,
        "runtime_qualification_initramfs_sha256":
            request.runtimeQualificationInitramfsSHA256,
        "candidate_runtime_rootfs_sha256": request.candidateRuntimeRootfsSHA256,
        "clone_binding_sha256": request.cloneBindingSHA256,
        "request_challenge_sha256": request.requestChallengeSHA256,
        "host_evidence_sha256": evidence.evidenceSHA256,
        "request_frame_sha256": evidence.requestFrameSHA256,
        "response_frame_sha256": evidence.responseFrameSHA256,
        "guest_receipt_sha256": evidence.guestReceiptSHA256,
        "process_evidence_sha256": evidence.processEvidenceSHA256,
        "serial_log_sha256": evidence.serialLogSHA256,
        "observed_sensors": [
            "raw_frame_sinkhole", "vm_lifecycle", "guest_channel_lifecycle",
            "clone_lifecycle", "image_identity"
        ],
        "raw_frame_count": "0",
        "dropped_frame_count": "0",
        "external_frames_forwarded": "0",
        "packet_sensor_healthy": true,
        "guest_channel_terminated": true,
        "vm_started": true,
        "vm_stopped": true,
        "clone_destroyed": true,
        "image_identity_stable": true,
        "public_network_route_present": false,
        "execution_authority_issued": false,
        "package_execution": false,
        "sync_back_policy": "structurally_absent"
    ]
}

private func linuxVzRuntimeQualificationHostSignatureMessage(
    request: Data,
    evidence: Data,
    unsignedReceipt: Data
) -> Data {
    var message = Data()
    message.append(linuxVzPackageRuntimeQualificationHostReceiptDomainV1)
    linuxVzRuntimeQualificationHostAppendUInt64(UInt64(request.count), to: &message)
    message.append(request)
    linuxVzRuntimeQualificationHostAppendUInt64(UInt64(evidence.count), to: &message)
    message.append(evidence)
    linuxVzRuntimeQualificationHostAppendUInt64(UInt64(unsignedReceipt.count), to: &message)
    message.append(unsignedReceipt)
    return message
}

private func linuxVzRuntimeQualificationHostAppendUInt64(
    _ value: UInt64,
    to data: inout Data
) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func linuxVzRuntimeQualificationHostDecodeHex(
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
        }), let byte = UInt8(pair, radix: 16) else {
            return nil
        }
        data.append(byte)
        index = next
    }
    return data
}

private func linuxVzRuntimeQualificationHostValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}
