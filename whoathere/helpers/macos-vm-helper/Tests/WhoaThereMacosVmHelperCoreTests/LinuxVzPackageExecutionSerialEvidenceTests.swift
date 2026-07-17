import CryptoKit
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzPackageExecutionSerialEvidenceAcceptsGuestCRLF() throws {
    let result = Data(repeating: 0x41, count: 57)
    let lines = [
        "WHOATHERE_PACKAGE_EXECUTION_BEGIN",
        "WHOATHERE_CAPABILITY signed_execution_inputs=verified_exact",
        "WHOATHERE_CAPABILITY rootfs=verified_exact_read_only",
        "WHOATHERE_CAPABILITY external_route_configured=false",
        "WHOATHERE_PACKAGE_EXECUTION_RESULT_BASE64_BEGIN",
        result.base64EncodedString()
            + "[   22.587663] inert kernel console line interleaved before newline",
        "WHOATHERE_PACKAGE_EXECUTION_RESULT_BASE64_END sha256=\(sha256(result)) byte_length=\(result.count)",
        "WHOATHERE_PACKAGE_EXECUTION_OK",
        "WHOATHERE_CAPABILITY package_execution=true",
        "WHOATHERE_CAPABILITY sync_back=false",
    ]
    let serial = Data((lines.joined(separator: "\r\n") + "\r\n").utf8)

    let evidence = try parseLinuxVzPackageExecutionSerialEvidenceV1(serial)

    #expect(evidence.result == result)
    #expect(evidence.guestExecutionComplete)
    #expect(!evidence.publicNetworkRoutePresent)
    #expect(!evidence.syncBackPermitted)
}

@Test func linuxVzPackageExecutionSerialEvidenceCarriesBLK006SizedRuntimeResult() throws {
    let expectedResultBytes = 5_945_958
    let transcript = Data("action 3 completed in the guest".utf8)
    let supervisor = Data("supervisor".utf8)
    let rootReceipt = Data("root receipt".utf8)
    let file = Data("file evidence".utf8)
    let network = Data("network evidence".utf8)
    let summary = try canonicalJSONData([
        "artifact_sha256": sha256(Data("artifact".utf8)),
        "attempt_binding_sha256": sha256(Data("attempt".utf8)),
        "authoritative_verdict_permitted": false,
        "execution_grant_sha256": sha256(Data("grant".utf8)),
        "execution_request_sha256": sha256(Data("request".utf8)),
        "host_composition_required": true,
        "package_execution": true,
        "process_action_count": "1",
        "process_action_indexes": ["3"],
        "process_plan_sha256": sha256(Data("plan".utf8)),
        "public_network_route_present": false,
        "result_frame_count": "7",
        "root_evidence_authenticated": true,
        "schema_version": "whoathere.linux_vz_package_root_runtime_result.v1",
        "sync_back": false,
        "terminal": "complete",
        "transcript_sha256": sha256(transcript),
    ])
    let frameHeaderBytes = 56
    let fixedPayloadBytes =
        transcript.count + supervisor.count + rootReceipt.count + file.count + network.count
        + summary.count
    let processByteCount = expectedResultBytes - (7 * frameHeaderBytes) - fixedPayloadBytes
    #expect(processByteCount > 4 * 1024 * 1024)
    #expect(processByteCount < maximumLinuxVzPackageRootRuntimeEvidenceFrameBytesV1)
    let process = Data(repeating: 0x41, count: processByteCount)

    var runtimeResult = Data(capacity: expectedResultBytes)
    runtimeResult.append(runtimeResultFrame(kind: 1, actionIndex: 0, payload: transcript))
    runtimeResult.append(runtimeResultFrame(kind: 2, actionIndex: 3, payload: supervisor))
    runtimeResult.append(runtimeResultFrame(kind: 3, actionIndex: 3, payload: rootReceipt))
    runtimeResult.append(runtimeResultFrame(kind: 4, actionIndex: 3, payload: process))
    runtimeResult.append(runtimeResultFrame(kind: 5, actionIndex: 3, payload: file))
    runtimeResult.append(runtimeResultFrame(kind: 6, actionIndex: 3, payload: network))
    runtimeResult.append(runtimeResultFrame(kind: 7, actionIndex: 0, payload: summary))
    #expect(runtimeResult.count == expectedResultBytes)

    let serial = packageExecutionSerial(result: runtimeResult)
    let serialEvidence = try parseLinuxVzPackageExecutionSerialEvidenceV1(serial)
    #expect(serialEvidence.result.count == expectedResultBytes)
    #expect(serialEvidence.result == runtimeResult)

    let parsed = try parseLinuxVzPackageRootRuntimeResultV1(serialEvidence.result)
    let action = try #require(parsed.actions.first)
    #expect(parsed.actions.count == 1)
    #expect(action.actionIndex == 3)
    #expect(action.process.count == processByteCount)
    #expect(action.process == process)
    #expect(parsed.terminal == "complete")
}

@Test func linuxVzPackageRootRuntimeResultRejectsEvidenceFrameBeyondCurrentLimit() {
    let transcript = runtimeResultFrame(
        kind: 1,
        actionIndex: 0,
        payload: Data("bounded transcript".utf8)
    )
    let oversized = runtimeResultFrame(
        kind: 4,
        actionIndex: 3,
        payload: Data(
            repeating: 0x41,
            count: maximumLinuxVzPackageRootRuntimeEvidenceFrameBytesV1 + 1
        )
    )
    var result = Data(capacity: transcript.count + oversized.count)
    result.append(transcript)
    result.append(oversized)

    #expect(throws: LinuxVzPackageRootRuntimeResultError.limitExceeded) {
        try parseLinuxVzPackageRootRuntimeResultV1(result)
    }
}

private func packageExecutionSerial(result: Data) -> Data {
    let encoded = result.base64EncodedString()
    var lines = [
        "WHOATHERE_PACKAGE_EXECUTION_BEGIN",
        "WHOATHERE_CAPABILITY signed_execution_inputs=verified_exact",
        "WHOATHERE_CAPABILITY rootfs=verified_exact_read_only",
        "WHOATHERE_CAPABILITY external_route_configured=false",
        "WHOATHERE_PACKAGE_EXECUTION_RESULT_BASE64_BEGIN",
    ]
    lines.reserveCapacity(lines.count + (encoded.utf8.count + 75) / 76 + 5)
    var index = encoded.startIndex
    while index < encoded.endIndex {
        let end = encoded.index(index, offsetBy: 76, limitedBy: encoded.endIndex)
            ?? encoded.endIndex
        lines.append(String(encoded[index..<end]))
        index = end
    }
    lines.append(
        "WHOATHERE_PACKAGE_EXECUTION_RESULT_BASE64_END sha256=\(sha256(result)) byte_length=\(result.count)"
    )
    lines.append("WHOATHERE_PACKAGE_EXECUTION_OK")
    lines.append("WHOATHERE_CAPABILITY package_execution=true")
    lines.append("WHOATHERE_CAPABILITY sync_back=false")
    return Data((lines.joined(separator: "\n") + "\n").utf8)
}

private func runtimeResultFrame(kind: UInt16, actionIndex: UInt32, payload: Data) -> Data {
    var frame = Data("WTPKRR01".utf8)
    appendBigEndian(UInt16(1), to: &frame)
    appendBigEndian(kind, to: &frame)
    appendBigEndian(actionIndex, to: &frame)
    appendBigEndian(UInt64(payload.count), to: &frame)
    frame.append(Data(SHA256.hash(data: payload)))
    frame.append(payload)
    return frame
}

private func appendBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func appendBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}
