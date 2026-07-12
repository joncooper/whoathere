import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzGuestSignerTransportDecodesExactFrames() throws {
    var request = Data("WHVZGSQ1".utf8)
    request.append(contentsOf: [0, 0, 0, 3, 0, 0, 0, 4])
    request.append(Data("run".utf8))
    request.append(Data("test".utf8))
    let decoded = try decodeLinuxVzGuestSignerRequest(request)
    #expect(decoded.runSpec == Data("run".utf8))
    #expect(decoded.challenge == Data("test".utf8))

    var response = Data("WHVZGSP1".utf8)
    response.append(contentsOf: [0, 0, 0, 7])
    response.append(Data("receipt".utf8))
    #expect(try decodeLinuxVzGuestSignerResponse(response) == Data("receipt".utf8))
}

@Test func linuxVzGuestSignerTransportRejectsMalformedFrames() throws {
    #expect(throws: LinuxVzGuestSignerTransportError.empty) {
        try decodeLinuxVzGuestSignerRequest(Data())
    }
    var request = Data("WHVZGSQ1".utf8)
    request.append(contentsOf: [0, 0, 0, 3, 0, 0, 0, 4])
    request.append(Data("run".utf8))
    request.append(Data("test".utf8))
    #expect(throws: LinuxVzGuestSignerTransportError.invalidLength) {
        try decodeLinuxVzGuestSignerRequest(request.dropLast())
    }
    request.append(0)
    #expect(throws: LinuxVzGuestSignerTransportError.trailingBytes) {
        try decodeLinuxVzGuestSignerRequest(request)
    }

    var response = Data("XHVZGSP1".utf8)
    response.append(contentsOf: [0, 0, 0, 1, 0])
    #expect(throws: LinuxVzGuestSignerTransportError.invalidMagic) {
        try decodeLinuxVzGuestSignerResponse(response)
    }
}
