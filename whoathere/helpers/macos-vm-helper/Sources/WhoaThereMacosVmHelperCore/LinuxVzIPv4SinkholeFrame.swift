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
