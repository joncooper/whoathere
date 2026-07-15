import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzPackageHostIPv4FrameDecodesStrictRedactedUDPObservation() throws {
    let frame = packageHostRawFrameAttachmentUDP()
    let decoded = try decodeLinuxVzPackageHostIPv4FrameV1(
        frame,
        expectedSourceMAC: linuxVzInertGuestNetworkMACV1
    )
    #expect(decoded.transport == .udp)
    #expect(decoded.destinationClass == .documentation)
    #expect(decoded.sourcePort == 49_152)
    #expect(decoded.destinationPort == 40_553)
    #expect(decoded.transportPayloadByteCount == 16)
    #expect(decoded.tcpFlags == nil)
    #expect(decoded.frameSHA256.hasPrefix("sha256:"))
    #expect(decoded.networkLayerCorrelationSHA256 ==
        "sha256:3e6baece59efbbc17f2135b6d036b7aec82ebc22f27c30e8064c756b4269f9ff")

    let token = try decoded.destinationTokenSHA256(
        sensorSessionChallengeSHA256:
            "sha256:0a6d2053eb627f5f1ed55c993237d3bd832dc1b72f4084c40c9a224e83d6c965",
        eventKind: "sendto",
        enterSourceSequence: 16
    )
    #expect(token ==
        "sha256:3ef258ec5ef33c871db55bb52239931372585c08ad3fbafda224bc498ad0ed7b")
}

@Test func linuxVzPackageHostIPv4FrameAcceptsPackageRuntimeMAC() throws {
    var frame = [UInt8](packageHostRawFrameAttachmentUDP())
    frame.replaceSubrange(6..<12, with: linuxVzPackageGuestNetworkMACV1)
    let decoded = try decodeLinuxVzPackageHostIPv4FrameV1(
        Data(frame),
        expectedSourceMAC: linuxVzPackageGuestNetworkMACV1
    )
    #expect(decoded.destinationPort == 40_553)
}

@Test func linuxVzPackageHostIPv4FrameDecodesChecksumValidTCPSyn() throws {
    let decoded = try decodeLinuxVzPackageHostIPv4FrameV1(
        packageHostIPv4TCPSyn(),
        expectedSourceMAC: linuxVzInertGuestNetworkMACV1
    )
    #expect(decoded.transport == .tcp)
    #expect(decoded.destinationClass == .documentation)
    #expect(decoded.sourcePort == 49_152)
    #expect(decoded.destinationPort == 443)
    #expect(decoded.transportPayloadByteCount == 0)
    #expect(decoded.tcpFlags == 0x02)
}

@Test func linuxVzPackageHostIPv4FrameRejectsWrongMACFragmentAndChecksums() throws {
    let exact = packageHostRawFrameAttachmentUDP()
    #expect(throws: LinuxVzPackageHostIPv4FrameError.invalidEthernet) {
        try decodeLinuxVzPackageHostIPv4FrameV1(
            exact,
            expectedSourceMAC: linuxVzPackageGuestNetworkMACV1
        )
    }
    var fragmented = [UInt8](exact)
    fragmented[20] = 0x20
    fragmented[24] = 0
    fragmented[25] = 0
    let correctedHeader = packageHostInternetChecksum(Array(fragmented[14..<34]))
    fragmented[24] = UInt8(correctedHeader >> 8)
    fragmented[25] = UInt8(correctedHeader & 0xff)
    #expect(throws: LinuxVzPackageHostIPv4FrameError.fragmentedIPv4) {
        try decodeLinuxVzPackageHostIPv4FrameV1(
            Data(fragmented),
            expectedSourceMAC: linuxVzInertGuestNetworkMACV1
        )
    }
    var corrupt = [UInt8](exact)
    corrupt[42] ^= 0xff
    #expect(throws: LinuxVzPackageHostIPv4FrameError.invalidChecksum) {
        try decodeLinuxVzPackageHostIPv4FrameV1(
            Data(corrupt),
            expectedSourceMAC: linuxVzInertGuestNetworkMACV1
        )
    }
    var noUDPChecksum = [UInt8](exact)
    noUDPChecksum[40] = 0
    noUDPChecksum[41] = 0
    #expect(throws: LinuxVzPackageHostIPv4FrameError.invalidTransport) {
        try decodeLinuxVzPackageHostIPv4FrameV1(
            Data(noUDPChecksum),
            expectedSourceMAC: linuxVzInertGuestNetworkMACV1
        )
    }
}

@Test func linuxVzPackageHostIPv4FrameDestinationTokenRejectsAndChangesBindings() throws {
    let decoded = try decodeLinuxVzPackageHostIPv4FrameV1(
        packageHostRawFrameAttachmentUDP(),
        expectedSourceMAC: linuxVzInertGuestNetworkMACV1
    )
    let challenge =
        "sha256:0a6d2053eb627f5f1ed55c993237d3bd832dc1b72f4084c40c9a224e83d6c965"
    let exact = try decoded.destinationTokenSHA256(
        sensorSessionChallengeSHA256: challenge,
        eventKind: "sendto",
        enterSourceSequence: 16
    )
    let changedSequence = try decoded.destinationTokenSHA256(
        sensorSessionChallengeSHA256: challenge,
        eventKind: "sendto",
        enterSourceSequence: 18
    )
    #expect(exact != changedSequence)
    let changedKind = try decoded.destinationTokenSHA256(
        sensorSessionChallengeSHA256: challenge,
        eventKind: "connect",
        enterSourceSequence: 16
    )
    #expect(exact != changedKind)
    #expect(throws: LinuxVzPackageHostIPv4FrameError.invalidCorrelationBinding) {
        try decoded.destinationTokenSHA256(
            sensorSessionChallengeSHA256: challenge,
            eventKind: "sendmsg",
            enterSourceSequence: 16
        )
    }
    #expect(throws: LinuxVzPackageHostIPv4FrameError.invalidCorrelationBinding) {
        try decoded.destinationTokenSHA256(
            sensorSessionChallengeSHA256: "sha256:BAD",
            eventKind: "sendto",
            enterSourceSequence: 16
        )
    }
}

private func packageHostRawFrameAttachmentUDP() -> Data {
    let payload = [UInt8]("WHOATHERE_RAW_V1".utf8)
    let udpLength = 8 + payload.count
    let totalLength = 20 + udpLength
    var frame: [UInt8] = [
        0x02,0x57,0x48,0x4f,0x41,0xfe, 0x02,0x57,0x48,0x4f,0x41,0x31, 0x08,0x00,
        0x45,0x00,UInt8(totalLength >> 8),UInt8(totalLength & 0xff),0x12,0x34,0x40,0x00,
        0x40,0x11,0x00,0x00, 192,0,2,2, 192,0,2,1,
        0xc0,0x00,0x9e,0x69,UInt8(udpLength >> 8),UInt8(udpLength & 0xff),0,0
    ]
    frame.append(contentsOf: payload)
    let ipChecksum = packageHostInternetChecksum(Array(frame[14..<34]))
    frame[24] = UInt8(ipChecksum >> 8)
    frame[25] = UInt8(ipChecksum & 0xff)
    var pseudo = Array(frame[26..<34]) + [0,17,UInt8(udpLength >> 8),UInt8(udpLength & 0xff)]
    pseudo.append(contentsOf: frame[34..<frame.count])
    let udpChecksum = packageHostInternetChecksum(pseudo)
    frame[40] = UInt8(udpChecksum >> 8)
    frame[41] = UInt8(udpChecksum & 0xff)
    return Data(frame)
}

private func packageHostIPv4TCPSyn() -> Data {
    let totalLength = 40
    var frame: [UInt8] = [
        0x02,0x57,0x48,0x4f,0x41,0xfe, 0x02,0x57,0x48,0x4f,0x41,0x31, 0x08,0x00,
        0x45,0x00,0x00,UInt8(totalLength),0x12,0x34,0x40,0x00,
        0x40,0x06,0x00,0x00, 192,0,2,2, 192,0,2,1,
        0xc0,0x00,0x01,0xbb, 0x01,0x02,0x03,0x04, 0,0,0,0,
        0x50,0x02,0xff,0xff,0,0,0,0
    ]
    let ipChecksum = packageHostInternetChecksum(Array(frame[14..<34]))
    frame[24] = UInt8(ipChecksum >> 8)
    frame[25] = UInt8(ipChecksum & 0xff)
    var pseudo = Array(frame[26..<34]) + [0,6,0,20]
    pseudo.append(contentsOf: frame[34..<54])
    let tcpChecksum = packageHostInternetChecksum(pseudo)
    frame[50] = UInt8(tcpChecksum >> 8)
    frame[51] = UInt8(tcpChecksum & 0xff)
    return Data(frame)
}

private func packageHostInternetChecksum(_ bytes: [UInt8]) -> UInt16 {
    var sum: UInt64 = 0
    var index = 0
    while index + 1 < bytes.count {
        sum += UInt64(UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]))
        index += 2
    }
    if index < bytes.count { sum += UInt64(UInt16(bytes[index]) << 8) }
    while sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
    return ~UInt16(sum)
}
