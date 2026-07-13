import CryptoKit
import Foundation

public let linuxVzPackageRuntimeQualificationGuestReceiptSchemaV1 =
    "whoathere.macos_linux_vz_package_runtime_qualification_guest_receipt.v1"
private let linuxVzPackageRuntimeQualificationReceiptDomainV1 = Data(
    "whoathere.macos_linux_vz_package_runtime_qualification_guest_receipt.signature.v1\0".utf8
)

public enum LinuxVzPackageRuntimeQualificationReceiptError: Error, Equatable {
    case empty
    case limitExceeded
    case invalidReceipt
    case publicKeyMismatch
    case signatureFailed
    case nonCanonical
}

public struct VerifiedLinuxVzPackageRuntimeQualificationReceipt: Equatable, Sendable {
    public let qualificationRequestSHA256: String
    public let rootfsBlockDeviceSHA256: String
    public let processEvidenceSHA256: String
    public var packageExecutionAuthorityPermitted: Bool { false }
    public var syncBackPermitted: Bool { false }
}

public func verifyLinuxVzPackageRuntimeQualificationReceipt(
    response: LinuxVzPackageRuntimeQualificationResponse,
    request: ParsedLinuxVzPackageRuntimeQualificationRequest,
    guestVerifyingKey: Data
) throws -> VerifiedLinuxVzPackageRuntimeQualificationReceipt {
    guard response.probeReport == linuxVzPackageRuntimeProbeReportV1 else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.invalidReceipt
    }
    var serialEvidence = Data(linuxVzProcessEvidenceSerialPrefixV1.utf8)
    serialEvidence.append(response.processEvidence)
    serialEvidence.append(0x0a)
    let process = try decodeLinuxVzProcessEvidencePayloadV1(serialEvidence)
    guard process.canonicalJSON == response.processEvidence,
          process.fixtureCase == "fork_exec_exit",
          process.packageUID == UInt64(request.packageUID),
          process.packageGID == UInt64(request.packageGID),
          process.eventSequenceStart == 1,
          process.eventSequenceEnd == 3,
          process.eventCount == 3,
          process.heartbeatCount == 2,
          process.droppedEventCount == 0,
          process.sensorHealthy,
          !process.evidenceTruncated,
          process.descendantTeardownComplete else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.invalidReceipt
    }
    guard !response.guestReceipt.isEmpty else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.empty
    }
    guard response.guestReceipt.count <= 1024 * 1024 else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.limitExceeded
    }
    guard sha256(guestVerifyingKey) == request.guestEvidencePublicKeySHA256,
          let publicKey = try? Curve25519.Signing.PublicKey(
            rawRepresentation: guestVerifyingKey
          ) else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.publicKeyMismatch
    }
    guard let receipt = try? JSONSerialization.jsonObject(
        with: response.guestReceipt
    ) as? [String: Any] else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.invalidReceipt
    }
    guard try canonicalJSONData(receipt) == response.guestReceipt else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.nonCanonical
    }
    var unsigned = receipt
    guard let signatureHex = unsigned.removeValue(
        forKey: "signature_ed25519_hex"
    ) as? String,
    let signature = linuxVzRuntimeQualificationDecodeHex(signatureHex, byteCount: 64) else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.invalidReceipt
    }
    let expected = linuxVzRuntimeQualificationUnsignedReceipt(
        request: request,
        process: process,
        probeReport: response.probeReport
    )
    guard Set(unsigned.keys) == Set(expected.keys),
          try canonicalJSONData(unsigned) == canonicalJSONData(expected) else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.invalidReceipt
    }
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data()
    message.append(linuxVzPackageRuntimeQualificationReceiptDomainV1)
    linuxVzRuntimeQualificationAppendUInt64(
        UInt64(request.canonicalJSON.count), to: &message
    )
    message.append(request.canonicalJSON)
    linuxVzRuntimeQualificationAppendUInt64(UInt64(unsignedData.count), to: &message)
    message.append(unsignedData)
    guard publicKey.isValidSignature(signature, for: message) else {
        throw LinuxVzPackageRuntimeQualificationReceiptError.signatureFailed
    }
    return VerifiedLinuxVzPackageRuntimeQualificationReceipt(
        qualificationRequestSHA256: request.requestSHA256,
        rootfsBlockDeviceSHA256: request.candidateRuntimeRootfsSHA256,
        processEvidenceSHA256: process.payloadSHA256
    )
}

private func linuxVzRuntimeQualificationUnsignedReceipt(
    request: ParsedLinuxVzPackageRuntimeQualificationRequest,
    process: LinuxVzProcessEvidencePayloadV1,
    probeReport: Data
) -> [String: Any] {
    [
        "schema_version": linuxVzPackageRuntimeQualificationGuestReceiptSchemaV1,
        "authority": "guest_protected_runtime_qualification",
        "qualification_request_sha256": request.requestSHA256,
        "qualified_telemetry_backend_sha256": request.qualifiedTelemetryBackendSHA256,
        "backend_identity_sha256": request.backendIdentitySHA256,
        "telemetry_requirements_sha256": request.telemetryRequirementsSHA256,
        "conformance_evidence_set_sha256": request.conformanceEvidenceSetSHA256,
        "kernel_image_sha256": request.kernelImageSHA256,
        "qualified_initramfs_sha256": request.qualifiedInitramfsSHA256,
        "qualified_guest_signer_sha256": request.qualifiedGuestSignerSHA256,
        "qualified_protected_sensor_sha256": request.qualifiedProtectedSensorSHA256,
        "runtime_qualification_initramfs_sha256":
            request.runtimeQualificationInitramfsSHA256,
        "runtime_qualification_guest_agent_sha256":
            request.runtimeQualificationGuestAgentSHA256,
        "runtime_qualification_guest_init_sha256":
            request.runtimeQualificationGuestInitSHA256,
        "runtime_qualification_module_bundle_sha256":
            request.runtimeQualificationModuleBundleSHA256,
        "candidate_runtime_rootfs_sha256": request.candidateRuntimeRootfsSHA256,
        "candidate_runtime_rootfs_byte_length":
            String(request.candidateRuntimeRootfsByteLength),
        "candidate_runtime_manifest_sha256": request.candidateRuntimeManifestSHA256,
        "candidate_package_runner_sha256": request.candidatePackageRunnerSHA256,
        "request_challenge_sha256": request.requestChallengeSHA256,
        "clone_binding_sha256": request.cloneBindingSHA256,
        "expected_probe_report_sha256": request.expectedProbeReportSHA256,
        "observed_probe_report_sha256": sha256(probeReport),
        "rootfs_block_device": "/dev/vda",
        "rootfs_block_device_sha256": request.candidateRuntimeRootfsSHA256,
        "rootfs_filesystem_type": "ext2",
        "rootfs_filesystem_uuid": "57484F41-5448-4552-5254-554E54494D45",
        "rootfs_mount_options": ["nodev", "nosuid", "ro"],
        "package_runner_path": "/runtime/whoathere/package-runtime-probe",
        "package_runner_argument": "fork_exec_exit",
        "package_runner_exit_status": "0",
        "process_evidence_payload_sha256": process.payloadSHA256,
        "process_evidence_byte_length": String(process.evidenceByteLength),
        "event_sequence_start": String(process.eventSequenceStart),
        "event_sequence_end": String(process.eventSequenceEnd),
        "event_count": String(process.eventCount),
        "heartbeat_count": String(process.heartbeatCount),
        "dropped_event_count": String(process.droppedEventCount),
        "sensor_healthy": process.sensorHealthy,
        "evidence_truncated": process.evidenceTruncated,
        "descendant_teardown_complete": process.descendantTeardownComplete,
        "observed_sensors": [
            "process_fork_exec_exit", "process_credentials", "descendant_teardown",
            "sensor_health_heartbeat", "dropped_event_accounting"
        ],
        "package_uid": String(request.packageUID),
        "package_gid": String(request.packageGID),
        "package_capabilities_present": false,
        "public_network_reachable": false,
        "nonexecuting_probe_observed": true,
        "execution_authority_issued": false,
        "package_execution": false,
        "sync_back_policy": "structurally_absent"
    ]
}

private func linuxVzRuntimeQualificationAppendUInt64(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private func linuxVzRuntimeQualificationDecodeHex(
    _ value: String, byteCount: Int
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
