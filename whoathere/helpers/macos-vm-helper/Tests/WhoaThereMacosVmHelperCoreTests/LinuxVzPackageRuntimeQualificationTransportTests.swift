import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzRuntimeQualificationTransportIsBoundedAndDomainSeparated() throws {
    let request = Data("request".utf8)
    let frame = try encodeLinuxVzPackageRuntimeQualificationRequest(request)
    #expect(try decodeLinuxVzPackageRuntimeQualificationRequestFrame(frame) == request)

    var response = Data("WHVZRQP1".utf8)
    appendUInt32(6, to: &response)
    appendUInt32(8, to: &response)
    appendUInt32(7, to: &response)
    response.append(Data("probe\n".utf8))
    response.append(Data("evidence".utf8))
    response.append(Data("receipt".utf8))
    let decoded = try decodeLinuxVzPackageRuntimeQualificationResponse(response)
    #expect(decoded.probeReport == Data("probe\n".utf8))
    #expect(decoded.processEvidence == Data("evidence".utf8))
    #expect(decoded.guestReceipt == Data("receipt".utf8))

    var wrongMagic = frame
    wrongMagic[0] ^= 1
    #expect(throws: LinuxVzPackageRuntimeQualificationTransportError.invalidMagic) {
        try decodeLinuxVzPackageRuntimeQualificationRequestFrame(wrongMagic)
    }
    #expect(throws: LinuxVzPackageRuntimeQualificationTransportError.invalidLength) {
        try decodeLinuxVzPackageRuntimeQualificationResponse(response.dropLast())
    }
    var trailing = response
    trailing.append(0)
    #expect(throws: LinuxVzPackageRuntimeQualificationTransportError.trailingBytes) {
        try decodeLinuxVzPackageRuntimeQualificationResponse(trailing)
    }
}

private func appendUInt32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}
