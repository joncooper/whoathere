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
