import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private func networkGuestValue() -> [String: Any] {
    [
        "descendant_teardown_complete": true,
        "dropped_event_count": "0",
        "event_count": "4",
        "event_sequence_end": "4",
        "event_sequence_start": "1",
        "events": [
            ["actor_pid":"10","cgroup_id":"21","kind":"fork","sequence":"1","subject_pid":"11","timestamp_ns":"100"],
            ["actor_pid":"11","cgroup_id":"21","kind":"exec","sequence":"2","subject_pid":"11","timestamp_ns":"200"],
            ["actor_pid":"11","cgroup_id":"21","kind":"connect","sequence":"3","subject_pid":"11","timestamp_ns":"300"],
            ["actor_pid":"11","cgroup_id":"21","kind":"exit","sequence":"4","subject_pid":"11","timestamp_ns":"400"]
        ],
        "evidence_truncated": false,
        "fixture_case": "ipv4_connect",
        "heartbeat_count": "2",
        "network_action": "tcp_connect",
        "network_family": "ipv4",
        "network_protocol": "tcp",
        "network_socket_state": "syn_sent",
        "network_source": "192.0.2.2",
        "network_source_port": "49152",
        "network_target": "192.0.2.1",
        "network_target_port": "443",
        "package_gid": "65534",
        "package_uid": "65534",
        "reaped_process_count": "1",
        "schema_version": linuxVzNetworkEvidencePayloadSchemaV1,
        "sensor_healthy": true
    ]
}

@Test func networkGuestEvidenceBindsExactIPv4SinkholeTuple() throws {
    let payload = try canonicalJSONData(networkGuestValue())
    let evidence = try decodeLinuxVzNetworkEvidenceJSONV1(payload)
    #expect(evidence.fixtureCase == "ipv4_connect")
    #expect(evidence.sourcePort == 49152)
    #expect(evidence.claims.eventCount == 4)

    var rebound = networkGuestValue()
    rebound["network_target"] = "169.254.169.254"
    #expect(throws: LinuxVzNetworkEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzNetworkEvidenceJSONV1(canonicalJSONData(rebound))
    }
}

@Test func networkGuestEvidenceBindsExactIPv6SinkholeTuple() throws {
    var value = networkGuestValue()
    value["fixture_case"] = "ipv6_connect"
    value["network_family"] = "ipv6"
    value["network_source"] = "2001:db8::2"
    value["network_target"] = "2001:db8::1"
    let evidence = try decodeLinuxVzNetworkEvidenceJSONV1(canonicalJSONData(value))
    #expect(evidence.fixtureCase == "ipv6_connect")
    #expect(evidence.sourcePort == 49152)
}

@Test func networkGuestEvidenceBindsUDPSendtoSinkholeTuple() throws {
    var value = networkGuestValue()
    value["fixture_case"] = "udp_send"
    value["network_action"] = "udp_send"
    value["network_protocol"] = "udp"
    value["network_socket_state"] = "unconnected_bound"
    var events = try #require(value["events"] as? [[String: Any]])
    events[2]["kind"] = "sendto"
    value["events"] = events
    let evidence = try decodeLinuxVzNetworkEvidenceJSONV1(canonicalJSONData(value))
    #expect(evidence.fixtureCase == "udp_send")
    #expect(evidence.sourcePort == 49152)
}

@Test func networkGuestEvidenceBindsEstablishedLoopbackSinkholeTuple() throws {
    var value = networkGuestValue()
    value["fixture_case"] = "loopback_connect"
    value["network_socket_state"] = "established"
    value["network_source"] = "127.0.0.1"
    value["network_target"] = "127.0.0.1"
    value["network_target_port"] = "40552"
    let evidence = try decodeLinuxVzNetworkEvidenceJSONV1(canonicalJSONData(value))
    #expect(evidence.fixtureCase == "loopback_connect")
    #expect(evidence.sourcePort == 49152)
}

@Test func networkGuestEvidenceBindsExactPrivateAddressSinkholeTuple() throws {
    var value = networkGuestValue()
    value["fixture_case"] = "private_address_connect"
    value["network_source"] = "10.0.0.2"
    value["network_target"] = "10.0.0.1"
    let evidence = try decodeLinuxVzNetworkEvidenceJSONV1(canonicalJSONData(value))
    #expect(evidence.fixtureCase == "private_address_connect")
    #expect(evidence.sourcePort == 49152)
}

@Test func networkHostEvidenceBindsOneExactIPv4Syn() throws {
    let evidence = try makeLinuxVzIPv4ConnectHostEvidencePayload(
        sourcePort: 49152,
        rawFrameCount: 1,
        matchedFrameCount: 1,
        unexpectedFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        storageDeviceCount: 0
    )
    #expect(evidence.sourcePort == 49152)
    #expect(evidence.claims.eventCount == 7)

    var value = try #require(
        JSONSerialization.jsonObject(with: evidence.canonicalJSON) as? [String: Any]
    )
    value["unexpected_frame_count"] = "1"
    #expect(throws: LinuxVzHostEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzNetworkHostEvidencePayload(canonicalJSONData(value))
    }
}

@Test func networkHostEvidenceBindsOneExactIPv6Syn() throws {
    let evidence = try makeLinuxVzIPv6ConnectHostEvidencePayload(
        sourcePort: 49152,
        rawFrameCount: 2,
        matchedFrameCount: 1,
        unexpectedFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        storageDeviceCount: 0
    )
    #expect(evidence.fixtureCase == "ipv6_connect")
    #expect(evidence.sourcePort == 49152)
}

@Test func networkHostEvidenceBindsOneExactIPv4UDPDatagram() throws {
    let evidence = try makeLinuxVzUDPSendHostEvidencePayload(
        sourcePort: 49152,
        rawFrameCount: 1,
        matchedFrameCount: 1,
        unexpectedFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        storageDeviceCount: 0
    )
    #expect(evidence.fixtureCase == "udp_send")
    #expect(evidence.sourcePort == 49152)
}

@Test func networkHostEvidenceBindsOneExactPrivateAddressIPv4Syn() throws {
    let evidence = try makeLinuxVzPrivateAddressConnectHostEvidencePayload(
        sourcePort: 49152,
        rawFrameCount: 1,
        matchedFrameCount: 1,
        unexpectedFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        storageDeviceCount: 0
    )
    #expect(evidence.fixtureCase == "private_address_connect")
    #expect(evidence.sourcePort == 49152)
}

private func internetChecksum(_ bytes: [UInt8]) -> UInt16 {
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

private func exactSinkholeSYN() -> Data {
    var frame: [UInt8] = [
        0x02,0x57,0x48,0x4f,0x41,0xfe, 0x02,0x57,0x48,0x4f,0x41,0x31, 0x08,0x00,
        0x45,0x00,0x00,0x28,0x12,0x34,0x40,0x00,0x40,0x06,0x00,0x00,
        192,0,2,2, 192,0,2,1,
        0xc0,0x00,0x01,0xbb, 0x01,0x02,0x03,0x04, 0x00,0x00,0x00,0x00,
        0x50,0x02,0xff,0xff,0x00,0x00,0x00,0x00
    ]
    let ipChecksum = internetChecksum(Array(frame[14..<34]))
    frame[24] = UInt8(ipChecksum >> 8)
    frame[25] = UInt8(ipChecksum & 0xff)
    var pseudo = Array(frame[26..<34]) + [0, 6, 0, 20]
    pseudo.append(contentsOf: frame[34..<54])
    let tcpChecksum = internetChecksum(pseudo)
    frame[50] = UInt8(tcpChecksum >> 8)
    frame[51] = UInt8(tcpChecksum & 0xff)
    return Data(frame)
}

private func exactPrivateSinkholeSYN() -> Data {
    var frame = [UInt8](exactSinkholeSYN())
    frame.replaceSubrange(26..<34, with: [10,0,0,2, 10,0,0,1])
    frame[24] = 0
    frame[25] = 0
    let ipChecksum = internetChecksum(Array(frame[14..<34]))
    frame[24] = UInt8(ipChecksum >> 8)
    frame[25] = UInt8(ipChecksum & 0xff)
    frame[50] = 0
    frame[51] = 0
    var pseudo = Array(frame[26..<34]) + [0, 6, 0, 20]
    pseudo.append(contentsOf: frame[34..<54])
    let tcpChecksum = internetChecksum(pseudo)
    frame[50] = UInt8(tcpChecksum >> 8)
    frame[51] = UInt8(tcpChecksum & 0xff)
    return Data(frame)
}

private func exactIPv6SinkholeSYN() -> Data {
    var frame: [UInt8] = [
        0x02,0x57,0x48,0x4f,0x41,0xfe, 0x02,0x57,0x48,0x4f,0x41,0x31, 0x86,0xdd,
        0x60,0x00,0x00,0x00, 0x00,0x14, 0x06,0x40,
        0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,2,
        0x20,0x01,0x0d,0xb8, 0,0,0,0, 0,0,0,0, 0,0,0,1,
        0xc0,0x00,0x01,0xbb, 0x01,0x02,0x03,0x04, 0,0,0,0,
        0x50,0x02,0xff,0xff,0,0,0,0
    ]
    var pseudo = Array(frame[22..<54]) + [0,0,0,20, 0,0,0,6]
    pseudo.append(contentsOf: frame[54..<74])
    let checksum = internetChecksum(pseudo)
    frame[70] = UInt8(checksum >> 8)
    frame[71] = UInt8(checksum & 0xff)
    return Data(frame)
}

private func exactIPv4SinkholeUDP() -> Data {
    let payload = [UInt8]("WHOATHERE_UDP_V1".utf8)
    let udpLength = 8 + payload.count
    let totalLength = 20 + udpLength
    var frame: [UInt8] = [
        0x02,0x57,0x48,0x4f,0x41,0xfe, 0x02,0x57,0x48,0x4f,0x41,0x31, 0x08,0x00,
        0x45,0x00,UInt8(totalLength >> 8),UInt8(totalLength & 0xff),0x12,0x34,0x40,0x00,
        0x40,0x11,0x00,0x00, 192,0,2,2, 192,0,2,1,
        0xc0,0x00,0x01,0xbb,UInt8(udpLength >> 8),UInt8(udpLength & 0xff),0,0
    ]
    frame.append(contentsOf: payload)
    let ipChecksum = internetChecksum(Array(frame[14..<34]))
    frame[24] = UInt8(ipChecksum >> 8)
    frame[25] = UInt8(ipChecksum & 0xff)
    var pseudo = Array(frame[26..<34]) + [0,17,UInt8(udpLength >> 8),UInt8(udpLength & 0xff)]
    pseudo.append(contentsOf: frame[34..<frame.count])
    let udpChecksum = internetChecksum(pseudo)
    frame[40] = UInt8(udpChecksum >> 8)
    frame[41] = UInt8(udpChecksum & 0xff)
    return Data(frame)
}

private func exactIPv6MLDv2Report() -> Data {
    var frame: [UInt8] = [
        0x33,0x33,0,0,0,0x16, 0x02,0x57,0x48,0x4f,0x41,0x31, 0x86,0xdd,
        0x60,0,0,0, 0,36, 0,1,
        0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
        0xff,0x02,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x16,
        58,0,5,2,0,0,1,0,
        143,0,0,0, 0,0,0,1,
        4,0,0,0,
        0xff,0x02,0,0, 0,0,0,0, 0,0,0,1, 0xff,0,0,2
    ]
    var pseudo = Array(frame[22..<54]) + [0,0,0,28, 0,0,0,58]
    pseudo.append(contentsOf: frame[62..<90])
    let checksum = internetChecksum(pseudo)
    frame[64] = UInt8(checksum >> 8)
    frame[65] = UInt8(checksum & 0xff)
    return Data(frame)
}

@Test func ipv4SinkholeFrameParserRequiresTupleFlagsLengthAndChecksums() {
    let frame = exactSinkholeSYN()
    #expect(linuxVzIsExactIPv4SinkholeSYNFrame(frame, sourcePort: 49152))
    #expect(!linuxVzIsExactIPv4SinkholeSYNFrame(frame, sourcePort: 49153))

    var changedTarget = frame
    changedTarget[33] = 2
    #expect(!linuxVzIsExactIPv4SinkholeSYNFrame(changedTarget, sourcePort: 49152))

    var trailing = frame
    trailing.append(0)
    #expect(!linuxVzIsExactIPv4SinkholeSYNFrame(trailing, sourcePort: 49152))

    var fragmented = frame
    fragmented[20] |= 0x20
    fragmented[24] = 0
    fragmented[25] = 0
    let fragmentedChecksum = internetChecksum(Array(fragmented[14..<34]))
    fragmented[24] = UInt8(fragmentedChecksum >> 8)
    fragmented[25] = UInt8(fragmentedChecksum & 0xff)
    #expect(!linuxVzIsExactIPv4SinkholeSYNFrame(fragmented, sourcePort: 49152))
}

@Test func privateAddressSinkholeFrameParserRequiresExactPrivateTuple() {
    let frame = exactPrivateSinkholeSYN()
    #expect(linuxVzIsExactIPv4PrivateSinkholeSYNFrame(frame, sourcePort: 49152))
    #expect(!linuxVzIsExactIPv4PrivateSinkholeSYNFrame(frame, sourcePort: 49153))
    #expect(!linuxVzIsExactIPv4SinkholeSYNFrame(frame, sourcePort: 49152))
    #expect(!linuxVzIsExactIPv4PrivateSinkholeSYNFrame(exactSinkholeSYN(), sourcePort: 49152))
}

@Test func ipv6SinkholeFrameParserRequiresExactTupleAndChecksum() {
    let frame = exactIPv6SinkholeSYN()
    #expect(linuxVzIsExactIPv6SinkholeSYNFrame(frame, sourcePort: 49152))
    #expect(!linuxVzIsExactIPv6SinkholeSYNFrame(frame, sourcePort: 49153))

    var changedTarget = frame
    changedTarget[53] = 2
    #expect(!linuxVzIsExactIPv6SinkholeSYNFrame(changedTarget, sourcePort: 49152))

    var trailing = frame
    trailing.append(0)
    #expect(!linuxVzIsExactIPv6SinkholeSYNFrame(trailing, sourcePort: 49152))
}

@Test func ipv4UDPSinkholeFrameParserRequiresExactPayloadTupleAndChecksums() {
    let frame = exactIPv4SinkholeUDP()
    #expect(linuxVzIsExactIPv4SinkholeUDPFrame(frame, sourcePort: 49152))
    #expect(!linuxVzIsExactIPv4SinkholeUDPFrame(frame, sourcePort: 49153))

    var changedPayload = frame
    changedPayload[changedPayload.count - 1] ^= 1
    #expect(!linuxVzIsExactIPv4SinkholeUDPFrame(changedPayload, sourcePort: 49152))

    var zeroChecksum = frame
    zeroChecksum[40] = 0
    zeroChecksum[41] = 0
    #expect(!linuxVzIsExactIPv4SinkholeUDPFrame(zeroChecksum, sourcePort: 49152))
}

@Test func ipv6MLDv2BootstrapParserRequiresExactFixedGroup() {
    let frame = exactIPv6MLDv2Report()
    #expect(linuxVzIsExactIPv6MLDv2BootstrapFrame(frame))
    var changedGroup = frame
    changedGroup[89] = 3
    #expect(!linuxVzIsExactIPv6MLDv2BootstrapFrame(changedGroup))
}
