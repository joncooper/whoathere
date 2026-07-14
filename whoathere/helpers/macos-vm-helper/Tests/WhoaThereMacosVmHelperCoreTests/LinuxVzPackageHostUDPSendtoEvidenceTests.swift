import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let packageHostUDPSendtoChallenge =
    "sha256:0a6d2053eb627f5f1ed55c993237d3bd832dc1b72f4084c40c9a224e83d6c965"
private let packageHostUDPSendtoToken =
    "sha256:3ef258ec5ef33c871db55bb52239931372585c08ad3fbafda224bc498ad0ed7b"

@Test func linuxVzPackageHostUDPSendtoEvidenceBindsExactFrameAndGuestIntent() throws {
    let expected = try packageHostUDPSendtoExpected()
    let collection = try packageHostUDPSendtoCollection(
        frames: [packageHostUDPSendtoFrame()]
    )
    let evidence = try makeLinuxVzPackageHostUDPSendtoEvidenceV1(
        expected: expected,
        collection: collection,
        expectedSourceMAC: linuxVzInertGuestNetworkMACV1
    )

    #expect(evidence == (try decodeLinuxVzPackageHostUDPSendtoEvidenceV1(
        evidence.canonicalJSON,
        expected: expected
    )))
    #expect(evidence.destinationTokenSHA256 == packageHostUDPSendtoToken)
    #expect(evidence.frameSHA256 ==
        "sha256:68a91108eb3257418ef82965c5c5ba6d2b5aa8aaded43647c25aad1be43caf1e")
    #expect(evidence.payloadSHA256 ==
        "sha256:9ce0d72ff3ceaf553b65168fe59983dc4093c392fa61ec1db3f916055640b818")
    #expect(evidence.sourcePort == 49_152)
    #expect(evidence.destinationPort == 40_553)
    #expect(evidence.payloadByteCount == 16)
    #expect(evidence.selectedCorrelationComplete)
    #expect(!evidence.broadHostFrameCoverageComplete)
    let text = try #require(String(data: evidence.canonicalJSON, encoding: .utf8))
    #expect(!text.contains("192.0.2.1"))
    #expect(!text.contains("WHOATHERE_RAW_V1"))
}

@Test func linuxVzPackageHostUDPSendtoEvidenceRejectsWrongIntentAndFrame() throws {
    let collection = try packageHostUDPSendtoCollection(
        frames: [packageHostUDPSendtoFrame()]
    )
    let wrongToken = try LinuxVzPackageExpectedHostUDPSendtoV1(
        rootNetworkEvidenceSHA256: packageHostDigest("network"),
        processEvidenceSHA256: packageHostDigest("process"),
        sensorSessionChallengeSHA256: packageHostUDPSendtoChallenge,
        destinationTokenSHA256: packageHostDigest("wrong-token"),
        destinationClass: .documentation,
        destinationPort: 40_553,
        enterSourceSequence: 16,
        syscallResult: 16
    )
    #expect(throws: LinuxVzPackageHostUDPSendtoEvidenceError.correlationMismatch) {
        try makeLinuxVzPackageHostUDPSendtoEvidenceV1(
            expected: wrongToken,
            collection: collection,
            expectedSourceMAC: linuxVzInertGuestNetworkMACV1
        )
    }
    #expect(throws: LinuxVzPackageHostUDPSendtoEvidenceError.invalidFrame) {
        try makeLinuxVzPackageHostUDPSendtoEvidenceV1(
            expected: try packageHostUDPSendtoExpected(),
            collection: collection,
            expectedSourceMAC: linuxVzPackageGuestNetworkMACV1
        )
    }
}

@Test func linuxVzPackageHostUDPSendtoEvidenceRejectsIncompleteCollection() throws {
    let twoFrames = try packageHostUDPSendtoCollection(
        frames: [packageHostUDPSendtoFrame(), packageHostUDPSendtoFrame()]
    )
    #expect(throws: LinuxVzPackageHostUDPSendtoEvidenceError.incompleteCollection) {
        try makeLinuxVzPackageHostUDPSendtoEvidenceV1(
            expected: try packageHostUDPSendtoExpected(),
            collection: twoFrames,
            expectedSourceMAC: linuxVzInertGuestNetworkMACV1
        )
    }
    let dropped = LinuxVzBoundedHostRawFrameCollection(
        retainedFrames: [packageHostUDPSendtoFrame()],
        ingressFrameCount: 2,
        droppedFrameCount: 1,
        truncatedFrameCount: 0,
        healthy: true,
        terminal: "bounded_queue_overflow_accounted"
    )
    #expect(throws: LinuxVzPackageHostUDPSendtoEvidenceError.incompleteCollection) {
        try makeLinuxVzPackageHostUDPSendtoEvidenceV1(
            expected: try packageHostUDPSendtoExpected(),
            collection: dropped,
            expectedSourceMAC: linuxVzInertGuestNetworkMACV1
        )
    }
}

@Test func linuxVzPackageHostUDPSendtoEvidenceRejectsTamperAndOverclaim() throws {
    let expected = try packageHostUDPSendtoExpected()
    let evidence = try makeLinuxVzPackageHostUDPSendtoEvidenceV1(
        expected: expected,
        collection: try packageHostUDPSendtoCollection(
            frames: [packageHostUDPSendtoFrame()]
        ),
        expectedSourceMAC: linuxVzInertGuestNetworkMACV1
    )
    for (section, field, changed): (String, String, Any) in [
        ("binding", "root_network_evidence_sha256", packageHostDigest("rebound")),
        ("collector", "dropped_frame_count", "1"),
        ("coverage", "broad_host_frame_coverage_complete", true),
        ("coverage", "raw_addresses_serialized", true),
        ("event", "destination_port", "53"),
        ("event", "syscall_result", "15"),
    ] {
        var value = try #require(
            JSONSerialization.jsonObject(with: evidence.canonicalJSON) as? [String: Any]
        )
        var nested = try #require(value[section] as? [String: Any])
        nested[field] = changed
        value[section] = nested
        #expect(throws: (any Error).self) {
            try decodeLinuxVzPackageHostUDPSendtoEvidenceV1(
                canonicalJSONData(value),
                expected: expected
            )
        }
    }
    let pretty = try JSONSerialization.data(
        withJSONObject: JSONSerialization.jsonObject(with: evidence.canonicalJSON),
        options: [.prettyPrinted, .sortedKeys]
    )
    #expect(throws: LinuxVzPackageHostUDPSendtoEvidenceError.nonCanonical) {
        try decodeLinuxVzPackageHostUDPSendtoEvidenceV1(pretty, expected: expected)
    }
}

private func packageHostUDPSendtoExpected() throws -> LinuxVzPackageExpectedHostUDPSendtoV1 {
    try LinuxVzPackageExpectedHostUDPSendtoV1(
        rootNetworkEvidenceSHA256: packageHostDigest("network"),
        processEvidenceSHA256: packageHostDigest("process"),
        sensorSessionChallengeSHA256: packageHostUDPSendtoChallenge,
        destinationTokenSHA256: packageHostUDPSendtoToken,
        destinationClass: .documentation,
        destinationPort: 40_553,
        enterSourceSequence: 16,
        syscallResult: 16
    )
}

private func packageHostUDPSendtoCollection(
    frames: [Data]
) throws -> LinuxVzBoundedHostRawFrameCollection {
    var sockets = [Int32](repeating: -1, count: 2)
    guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0 else {
        throw LinuxVzPackageHostUDPSendtoEvidenceError.invalidFrame
    }
    defer {
        close(sockets[0])
        close(sockets[1])
    }
    for frame in frames {
        let sent = frame.withUnsafeBytes { bytes in
            send(sockets[0], bytes.baseAddress, bytes.count, 0)
        }
        guard sent == frame.count else {
            throw LinuxVzPackageHostUDPSendtoEvidenceError.invalidFrame
        }
    }
    let collector = try LinuxVzBoundedHostRawFrameCollector(capacity: 8)
    collector.requestStop()
    return collector.collect(fileDescriptor: sockets[1])
}

private func packageHostUDPSendtoFrame() -> Data {
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
    let ipChecksum = packageHostUDPSendtoChecksum(Array(frame[14..<34]))
    frame[24] = UInt8(ipChecksum >> 8)
    frame[25] = UInt8(ipChecksum & 0xff)
    var pseudo = Array(frame[26..<34]) + [0,17,UInt8(udpLength >> 8),UInt8(udpLength & 0xff)]
    pseudo.append(contentsOf: frame[34..<frame.count])
    let udpChecksum = packageHostUDPSendtoChecksum(pseudo)
    frame[40] = UInt8(udpChecksum >> 8)
    frame[41] = UInt8(udpChecksum & 0xff)
    return Data(frame)
}

private func packageHostUDPSendtoChecksum(_ bytes: [UInt8]) -> UInt16 {
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

private func packageHostDigest(_ label: String) -> String {
    sha256(Data(label.utf8))
}
