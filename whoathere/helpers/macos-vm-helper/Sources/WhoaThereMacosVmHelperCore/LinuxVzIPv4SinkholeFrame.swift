import Foundation

public func linuxVzIsExactIPv4SinkholeSYNFrame(
    _ frame: Data,
    sourcePort: UInt16
) -> Bool {
    let bytes = [UInt8](frame)
    let sourceMAC: [UInt8] = [0x02, 0x57, 0x48, 0x4f, 0x41, 0x31]
    let targetMAC: [UInt8] = [0x02, 0x57, 0x48, 0x4f, 0x41, 0xfe]
    guard bytes.count >= 54,
          Array(bytes[0..<6]) == targetMAC,
          Array(bytes[6..<12]) == sourceMAC,
          bytes[12] == 0x08, bytes[13] == 0x00,
          bytes[14] == 0x45,
          bytes[23] == 0x06,
          Array(bytes[26..<30]) == [192, 0, 2, 2],
          Array(bytes[30..<34]) == [192, 0, 2, 1] else {
        return false
    }
    let totalLength = Int(bytes[16]) << 8 | Int(bytes[17])
    let fragment = UInt16(bytes[20]) << 8 | UInt16(bytes[21])
    let tcpHeaderLength = Int(bytes[46] >> 4) * 4
    guard totalLength == bytes.count - 14,
          fragment & 0xbfff == 0,
          tcpHeaderLength >= 20,
          totalLength == 20 + tcpHeaderLength,
          (UInt16(bytes[34]) << 8 | UInt16(bytes[35])) == sourcePort,
          (UInt16(bytes[36]) << 8 | UInt16(bytes[37])) == 443,
          bytes[46] & 0x0f == 0,
          bytes[47] == 0x02,
          linuxVzChecksumValid(Array(bytes[14..<34])) else {
        return false
    }
    let tcpLength = totalLength - 20
    var pseudoHeader = Array(bytes[26..<34])
    pseudoHeader.append(0)
    pseudoHeader.append(6)
    pseudoHeader.append(UInt8((tcpLength >> 8) & 0xff))
    pseudoHeader.append(UInt8(tcpLength & 0xff))
    pseudoHeader.append(contentsOf: bytes[34..<(34 + tcpLength)])
    return linuxVzChecksumValid(pseudoHeader)
}

public func linuxVzIsExactIPv4SinkholeUDPFrame(
    _ frame: Data,
    sourcePort: UInt16
) -> Bool {
    let bytes = [UInt8](frame)
    let sourceMAC: [UInt8] = [0x02, 0x57, 0x48, 0x4f, 0x41, 0x31]
    let targetMAC: [UInt8] = [0x02, 0x57, 0x48, 0x4f, 0x41, 0xfe]
    let payload = [UInt8]("WHOATHERE_UDP_V1".utf8)
    guard bytes.count == 14 + 20 + 8 + payload.count,
          Array(bytes[0..<6]) == targetMAC,
          Array(bytes[6..<12]) == sourceMAC,
          bytes[12] == 0x08, bytes[13] == 0x00,
          bytes[14] == 0x45,
          bytes[23] == 0x11,
          Array(bytes[26..<30]) == [192, 0, 2, 2],
          Array(bytes[30..<34]) == [192, 0, 2, 1] else {
        return false
    }
    let totalLength = Int(bytes[16]) << 8 | Int(bytes[17])
    let fragment = UInt16(bytes[20]) << 8 | UInt16(bytes[21])
    let udpLength = Int(bytes[38]) << 8 | Int(bytes[39])
    let udpChecksum = UInt16(bytes[40]) << 8 | UInt16(bytes[41])
    guard totalLength == bytes.count - 14,
          totalLength == 20 + udpLength,
          fragment & 0xbfff == 0,
          udpLength == 8 + payload.count,
          (UInt16(bytes[34]) << 8 | UInt16(bytes[35])) == sourcePort,
          (UInt16(bytes[36]) << 8 | UInt16(bytes[37])) == 443,
          udpChecksum != 0,
          Array(bytes[42..<bytes.count]) == payload,
          linuxVzChecksumValid(Array(bytes[14..<34])) else {
        return false
    }
    var pseudoHeader = Array(bytes[26..<34])
    pseudoHeader.append(0)
    pseudoHeader.append(17)
    pseudoHeader.append(UInt8((udpLength >> 8) & 0xff))
    pseudoHeader.append(UInt8(udpLength & 0xff))
    pseudoHeader.append(contentsOf: bytes[34..<bytes.count])
    return linuxVzChecksumValid(pseudoHeader)
}

public func linuxVzIsExactIPv6SinkholeSYNFrame(
    _ frame: Data,
    sourcePort: UInt16
) -> Bool {
    let bytes = [UInt8](frame)
    let sourceMAC: [UInt8] = [0x02, 0x57, 0x48, 0x4f, 0x41, 0x31]
    let targetMAC: [UInt8] = [0x02, 0x57, 0x48, 0x4f, 0x41, 0xfe]
    let sourceAddress: [UInt8] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
    ]
    let targetAddress: [UInt8] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
    ]
    guard bytes.count >= 74,
          Array(bytes[0..<6]) == targetMAC,
          Array(bytes[6..<12]) == sourceMAC,
          bytes[12] == 0x86, bytes[13] == 0xdd,
          bytes[14] >> 4 == 6,
          bytes[20] == 6,
          Array(bytes[22..<38]) == sourceAddress,
          Array(bytes[38..<54]) == targetAddress else {
        return false
    }
    let payloadLength = Int(bytes[18]) << 8 | Int(bytes[19])
    let tcpHeaderLength = Int(bytes[66] >> 4) * 4
    guard payloadLength == bytes.count - 54,
          tcpHeaderLength >= 20,
          payloadLength == tcpHeaderLength,
          (UInt16(bytes[54]) << 8 | UInt16(bytes[55])) == sourcePort,
          (UInt16(bytes[56]) << 8 | UInt16(bytes[57])) == 443,
          bytes[66] & 0x0f == 0,
          bytes[67] == 0x02 else {
        return false
    }
    var pseudoHeader = Array(bytes[22..<54])
    pseudoHeader.append(contentsOf: [
        UInt8((payloadLength >> 24) & 0xff), UInt8((payloadLength >> 16) & 0xff),
        UInt8((payloadLength >> 8) & 0xff), UInt8(payloadLength & 0xff),
        0, 0, 0, 6
    ])
    pseudoHeader.append(contentsOf: bytes[54..<(54 + payloadLength)])
    return linuxVzChecksumValid(pseudoHeader)
}

public func linuxVzIsExactIPv6MLDv2BootstrapFrame(_ frame: Data) -> Bool {
    let bytes = [UInt8](frame)
    let sourceMAC: [UInt8] = [0x02, 0x57, 0x48, 0x4f, 0x41, 0x31]
    let targetMAC: [UInt8] = [0x33, 0x33, 0x00, 0x00, 0x00, 0x16]
    let unspecified = [UInt8](repeating: 0, count: 16)
    let allMLDv2Routers: [UInt8] = [
        0xff,0x02,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x16
    ]
    let solicitedNode: [UInt8] = [
        0xff,0x02,0,0, 0,0,0,0, 0,0,0,1, 0xff,0,0,2
    ]
    guard bytes.count == 90,
          Array(bytes[0..<6]) == targetMAC,
          Array(bytes[6..<12]) == sourceMAC,
          bytes[12] == 0x86, bytes[13] == 0xdd,
          bytes[14] >> 4 == 6,
          bytes[18] == 0, bytes[19] == 36,
          bytes[20] == 0, bytes[21] == 1,
          Array(bytes[22..<38]) == unspecified,
          Array(bytes[38..<54]) == allMLDv2Routers,
          Array(bytes[54..<62]) == [58,0,5,2,0,0,1,0],
          bytes[62] == 143, bytes[63] == 0,
          bytes[66] == 0, bytes[67] == 0,
          bytes[68] == 0, bytes[69] == 1,
          bytes[70] == 4, bytes[71] == 0,
          bytes[72] == 0, bytes[73] == 0,
          Array(bytes[74..<90]) == solicitedNode else {
        return false
    }
    let icmpLength = 28
    var pseudoHeader = Array(bytes[22..<54])
    pseudoHeader.append(contentsOf: [0,0,0,UInt8(icmpLength), 0,0,0,58])
    pseudoHeader.append(contentsOf: bytes[62..<90])
    return linuxVzChecksumValid(pseudoHeader)
}

private func linuxVzChecksumValid(_ bytes: [UInt8]) -> Bool {
    var sum: UInt64 = 0
    var index = 0
    while index + 1 < bytes.count {
        sum += UInt64(UInt16(bytes[index]) << 8 | UInt16(bytes[index + 1]))
        index += 2
    }
    if index < bytes.count { sum += UInt64(UInt16(bytes[index]) << 8) }
    while sum > 0xffff { sum = (sum & 0xffff) + (sum >> 16) }
    return sum == 0xffff
}
