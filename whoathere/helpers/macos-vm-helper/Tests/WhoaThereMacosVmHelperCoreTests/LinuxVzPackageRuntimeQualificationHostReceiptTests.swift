import CryptoKit
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzRuntimeQualificationHostReceiptBindsClosedLifecycle() throws {
    let hostKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 7, count: 32)
    )
    let hostPublicKey = hostKey.publicKey.rawRepresentation
    let requestData = try canonicalJSONData(
        runtimeQualificationHostRequestFixture(
            hostKeySHA256: sha256(hostPublicKey)
        )
    )
    let request = try decodeLinuxVzPackageRuntimeQualificationRequest(requestData)
    #expect(request.hostEvidencePublicKeySHA256 == sha256(hostPublicKey))
    let requestFrame = try encodeLinuxVzPackageRuntimeQualificationRequest(requestData)
    let response = LinuxVzPackageRuntimeQualificationResponse(
        probeReport: linuxVzPackageRuntimeProbeReportV1,
        processEvidence: Data("inert process evidence".utf8),
        guestReceipt: Data("inert guest receipt".utf8)
    )
    let responseFrame = runtimeQualificationHostResponseFrame(response)
    let evidence = try makeLinuxVzPackageRuntimeQualificationHostEvidence(
        request: request,
        requestFrame: requestFrame,
        responseFrame: responseFrame,
        response: response,
        serialLogSHA256: hostQualificationDigest("serial log"),
        rawFrameCount: 0,
        droppedFrameCount: 0,
        packetSensorHealthy: true,
        guestChannelTerminated: true,
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        imageIdentityStable: true
    )
    var seed = hostKey.rawRepresentation
    #expect(seed.count == 32)
    #expect(
        sha256(try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
            .publicKey.rawRepresentation) == request.hostEvidencePublicKeySHA256
    )
    let receipt = try signLinuxVzPackageRuntimeQualificationHostReceipt(
        request: request,
        evidence: evidence,
        signingSeed: &seed
    )
    #expect(
        evidence.evidenceSHA256
            == "sha256:2b4e607f017cd84dc667f532fa80c9bb8460f499facb1ddbd6758e3d2612997d"
    )
    var unsignedReceipt = try #require(
        JSONSerialization.jsonObject(with: receipt) as? [String: Any]
    )
    _ = try #require(
        unsignedReceipt.removeValue(forKey: "signature_ed25519_hex") as? String
    )
    #expect(
        sha256(try canonicalJSONData(unsignedReceipt))
            == "sha256:19e145cde9212b195f788f79dc8b6a9bf28fc7214252ee0c0632697d2573d986"
    )
    #expect(seed == Data(repeating: 0, count: 32))
    let verified = try verifyLinuxVzPackageRuntimeQualificationHostReceipt(
        receipt,
        request: request,
        evidence: evidence,
        hostVerifyingKey: hostPublicKey
    )
    #expect(verified.qualificationRequestSHA256 == request.requestSHA256)
    #expect(verified.hostEvidenceSHA256 == evidence.evidenceSHA256)
    #expect(!verified.executionAuthorityPermitted)
    #expect(!verified.packageExecutionPermitted)
    #expect(!verified.syncBackPermitted)

    var changed = receipt
    changed[changed.index(before: changed.endIndex)] ^= 1
    #expect(throws: (any Error).self) {
        try verifyLinuxVzPackageRuntimeQualificationHostReceipt(
            changed,
            request: request,
            evidence: evidence,
            hostVerifyingKey: hostPublicKey
        )
    }
    #expect(throws: LinuxVzPackageRuntimeQualificationHostReceiptError.invalidEvidence) {
        try makeLinuxVzPackageRuntimeQualificationHostEvidence(
            request: request,
            requestFrame: requestFrame,
            responseFrame: responseFrame,
            response: response,
            serialLogSHA256: hostQualificationDigest("serial log"),
            rawFrameCount: 1,
            droppedFrameCount: 0,
            packetSensorHealthy: true,
            guestChannelTerminated: true,
            vmStarted: true,
            vmStopped: true,
            cloneDestroyed: true,
            imageIdentityStable: true
        )
    }
}

private func runtimeQualificationHostResponseFrame(
    _ response: LinuxVzPackageRuntimeQualificationResponse
) -> Data {
    var frame = Data("WHVZRQP1".utf8)
    for count in [
        response.probeReport.count,
        response.processEvidence.count,
        response.guestReceipt.count
    ] {
        let value = UInt32(count)
        frame.append(UInt8((value >> 24) & 0xff))
        frame.append(UInt8((value >> 16) & 0xff))
        frame.append(UInt8((value >> 8) & 0xff))
        frame.append(UInt8(value & 0xff))
    }
    frame.append(response.probeReport)
    frame.append(response.processEvidence)
    frame.append(response.guestReceipt)
    return frame
}

private func runtimeQualificationHostRequestFixture(
    hostKeySHA256: String
) -> [String: Any] {
    [
        "schema_version": linuxVzPackageRuntimeQualificationRequestSchemaV1,
        "operation": "fixed_nonexecuting_probe",
        "qualified_telemetry_backend_sha256": hostQualificationDigest("qualified backend"),
        "backend_identity_sha256": hostQualificationDigest("backend identity"),
        "telemetry_requirements_sha256": hostQualificationDigest("requirements"),
        "conformance_evidence_set_sha256": hostQualificationDigest("evidence set"),
        "kernel_image_sha256": hostQualificationDigest("kernel"),
        "qualified_initramfs_sha256": hostQualificationDigest("qualified initramfs"),
        "qualified_guest_signer_sha256": hostQualificationDigest("guest signer"),
        "qualified_protected_sensor_sha256": hostQualificationDigest("protected sensor"),
        "guest_evidence_public_key_sha256": hostQualificationDigest("guest public key"),
        "host_evidence_public_key_sha256": hostKeySHA256,
        "runtime_qualification_initramfs_sha256": hostQualificationDigest(
            "qualification initramfs"
        ),
        "runtime_qualification_guest_agent_sha256": hostQualificationDigest("guest agent"),
        "runtime_qualification_guest_init_sha256": hostQualificationDigest("guest init"),
        "runtime_qualification_module_bundle_sha256": hostQualificationDigest("modules"),
        "candidate_runtime_rootfs_sha256": hostQualificationDigest("runtime rootfs"),
        "candidate_runtime_rootfs_byte_length": "42",
        "candidate_runtime_manifest_sha256": hostQualificationDigest("runtime manifest"),
        "candidate_package_runner_sha256": hostQualificationDigest("package runner"),
        "expected_probe_report_sha256": sha256(linuxVzPackageRuntimeProbeReportV1),
        "protected_sensor_case": "fork_exec_exit",
        "package_runner_argument": "fork_exec_exit",
        "request_challenge_sha256": hostQualificationDigest("fresh challenge"),
        "clone_binding_sha256": hostQualificationDigest("unique clone"),
        "package_uid": "65534",
        "package_gid": "65534",
        "storage_policy": "one_unique_writable_clone_destroy_after_vm_stop",
        "network_policy": "host_raw_frame_sinkhole_no_external_route",
        "directory_share_policy": "structurally_absent",
        "public_resolver_reachable": false,
        "nonexecuting_probe_permitted": true,
        "execution_authority_issued": false,
        "package_execution_permitted": false,
        "sync_back_policy": "structurally_absent"
    ]
}

private func hostQualificationDigest(_ value: String) -> String {
    sha256(Data(value.utf8))
}
