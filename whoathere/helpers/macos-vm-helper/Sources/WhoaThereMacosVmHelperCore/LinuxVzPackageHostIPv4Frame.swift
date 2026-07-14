import CryptoKit
import Foundation

public let linuxVzInertGuestNetworkMACV1 = Data([0x02, 0x57, 0x48, 0x4f, 0x41, 0x31])
public let linuxVzPackageGuestNetworkMACV1 = Data([0x02, 0x57, 0x48, 0x4f, 0x41, 0x32])
public let linuxVzHostSinkholeNetworkMACV1 = Data([0x02, 0x57, 0x48, 0x4f, 0x41, 0xfe])

public enum LinuxVzPackageHostIPv4FrameError: Error, Equatable {
    case invalidEthernet
    case invalidIPv4
    case fragmentedIPv4
    case unsupportedTransport
    case invalidTransport
    case invalidChecksum
    case invalidCorrelationBinding
}

public enum LinuxVzPackageHostFrameTransportV1: String, Equatable, Sendable {
    case tcp
    case udp
}

public enum LinuxVzPackageHostDestinationClassV1: String, Equatable, Sendable {
    case unspecified
    case loopback
    case `private`
    case linkLocal = "link_local"
    case metadata
    case documentation
    case multicast
    case broadcast
    case `public`
}

public struct LinuxVzPackageHostIPv4FrameV1: Equatable, Sendable {
    public let frameSHA256: String
    public let transport: LinuxVzPackageHostFrameTransportV1
    public let destinationClass: LinuxVzPackageHostDestinationClassV1
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let transportPayloadByteCount: Int
    public let tcpFlags: UInt8?

    fileprivate let destinationAddress: Data

    public func destinationTokenSHA256(
        sensorSessionChallengeSHA256: String,
        eventKind: String,
        enterSourceSequence: UInt64
    ) throws -> String {
        guard linuxVzPackageHostFrameDigestV1(sensorSessionChallengeSHA256),
              enterSourceSequence > 0,
              eventKind == "connect" || eventKind == "sendto" else {
            throw LinuxVzPackageHostIPv4FrameError.invalidCorrelationBinding
        }
        var input = Data(
            "whoathere.linux_vz_package_root_network_target_token.v1\0".utf8
        )
        input.append(Data(sensorSessionChallengeSHA256.utf8))
        input.append(0)
        input.append(Data(eventKind.utf8))
        input.append(0)
        input.append(Data("ipv4".utf8))
        input.append(0)
        var port = destinationPort.bigEndian
        var sequence = enterSourceSequence.bigEndian
        withUnsafeBytes(of: &port) { input.append(contentsOf: $0) }
        withUnsafeBytes(of: &sequence) { input.append(contentsOf: $0) }
        input.append(destinationAddress)
        defer { input.resetBytes(in: 0..<input.count) }
        return linuxVzPackageHostFrameSHA256V1(input)
    }
}

public func decodeLinuxVzPackageHostIPv4FrameV1(
    _ frame: Data,
    expectedSourceMAC: Data,
    expectedDestinationMAC: Data = linuxVzHostSinkholeNetworkMACV1
) throws -> LinuxVzPackageHostIPv4FrameV1 {
    let bytes = [UInt8](frame)
    guard expectedSourceMAC.count == 6, expectedDestinationMAC.count == 6,
          bytes.count >= 14 + 20,
          Data(bytes[0..<6]) == expectedDestinationMAC,
          Data(bytes[6..<12]) == expectedSourceMAC,
          bytes[12] == 0x08, bytes[13] == 0x00 else {
        throw LinuxVzPackageHostIPv4FrameError.invalidEthernet
    }
    let version = bytes[14] >> 4
    let headerByteCount = Int(bytes[14] & 0x0f) * 4
    guard version == 4, headerByteCount >= 20, bytes.count >= 14 + headerByteCount,
          bytes[22] > 0 else {
        throw LinuxVzPackageHostIPv4FrameError.invalidIPv4
    }
    let totalByteCount = Int(bytes[16]) << 8 | Int(bytes[17])
    guard totalByteCount == bytes.count - 14, totalByteCount >= headerByteCount else {
        throw LinuxVzPackageHostIPv4FrameError.invalidIPv4
    }
    guard linuxVzPackageHostChecksumValidV1(
        Array(bytes[14..<(14 + headerByteCount)])
    ) else {
        throw LinuxVzPackageHostIPv4FrameError.invalidChecksum
    }
    let fragment = UInt16(bytes[20]) << 8 | UInt16(bytes[21])
    guard fragment & 0xbfff == 0 else {
        throw LinuxVzPackageHostIPv4FrameError.fragmentedIPv4
    }
    let sourceAddress = Data(bytes[26..<30])
    let destinationAddress = Data(bytes[30..<34])
    let transportStart = 14 + headerByteCount
    let transportByteCount = totalByteCount - headerByteCount
    guard transportByteCount >= 8 else {
        throw LinuxVzPackageHostIPv4FrameError.invalidTransport
    }
    let sourcePort = UInt16(bytes[transportStart]) << 8
        | UInt16(bytes[transportStart + 1])
    let destinationPort = UInt16(bytes[transportStart + 2]) << 8
        | UInt16(bytes[transportStart + 3])
    guard sourcePort > 0, destinationPort > 0 else {
        throw LinuxVzPackageHostIPv4FrameError.invalidTransport
    }

    let transport: LinuxVzPackageHostFrameTransportV1
    let transportPayloadByteCount: Int
    let tcpFlags: UInt8?
    var pseudoHeader = [UInt8](sourceAddress + destinationAddress)
    pseudoHeader.append(0)
    pseudoHeader.append(bytes[23])
    pseudoHeader.append(UInt8((transportByteCount >> 8) & 0xff))
    pseudoHeader.append(UInt8(transportByteCount & 0xff))
    pseudoHeader.append(contentsOf: bytes[transportStart..<bytes.count])

    switch bytes[23] {
    case 6:
        guard transportByteCount >= 20 else {
            throw LinuxVzPackageHostIPv4FrameError.invalidTransport
        }
        let tcpHeaderByteCount = Int(bytes[transportStart + 12] >> 4) * 4
        guard tcpHeaderByteCount >= 20, tcpHeaderByteCount <= transportByteCount,
              bytes[transportStart + 12] & 0x0f == 0 else {
            throw LinuxVzPackageHostIPv4FrameError.invalidTransport
        }
        transport = .tcp
        transportPayloadByteCount = transportByteCount - tcpHeaderByteCount
        tcpFlags = bytes[transportStart + 13]
    case 17:
        let udpByteCount = Int(bytes[transportStart + 4]) << 8
            | Int(bytes[transportStart + 5])
        let udpChecksum = UInt16(bytes[transportStart + 6]) << 8
            | UInt16(bytes[transportStart + 7])
        guard udpByteCount == transportByteCount, udpByteCount >= 8,
              udpChecksum != 0 else {
            throw LinuxVzPackageHostIPv4FrameError.invalidTransport
        }
        transport = .udp
        transportPayloadByteCount = udpByteCount - 8
        tcpFlags = nil
    default:
        throw LinuxVzPackageHostIPv4FrameError.unsupportedTransport
    }
    guard linuxVzPackageHostChecksumValidV1(pseudoHeader) else {
        throw LinuxVzPackageHostIPv4FrameError.invalidChecksum
    }
    return LinuxVzPackageHostIPv4FrameV1(
        frameSHA256: linuxVzPackageHostFrameSHA256V1(frame),
        transport: transport,
        destinationClass: linuxVzPackageHostIPv4ClassV1([UInt8](destinationAddress)),
        sourcePort: sourcePort,
        destinationPort: destinationPort,
        transportPayloadByteCount: transportPayloadByteCount,
        tcpFlags: tcpFlags,
        destinationAddress: destinationAddress
    )
}

private func linuxVzPackageHostIPv4ClassV1(
    _ address: [UInt8]
) -> LinuxVzPackageHostDestinationClassV1 {
    if address == [0, 0, 0, 0] { return .unspecified }
    if address[0] == 127 { return .loopback }
    if address == [169, 254, 169, 254] { return .metadata }
    if address[0] == 10
        || (address[0] == 172 && (16...31).contains(address[1]))
        || (address[0] == 192 && address[1] == 168) {
        return .private
    }
    if address[0] == 169 && address[1] == 254 { return .linkLocal }
    if (address[0] == 192 && address[1] == 0 && address[2] == 2)
        || (address[0] == 198 && address[1] == 51 && address[2] == 100)
        || (address[0] == 203 && address[1] == 0 && address[2] == 113) {
        return .documentation
    }
    if (224...239).contains(address[0]) { return .multicast }
    if address == [255, 255, 255, 255] { return .broadcast }
    return .public
}

private func linuxVzPackageHostChecksumValidV1(_ bytes: [UInt8]) -> Bool {
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

private func linuxVzPackageHostFrameSHA256V1(_ data: Data) -> String {
    "sha256:" + SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

private func linuxVzPackageHostFrameDigestV1(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy { byte in
            (byte >= 48 && byte <= 57) || (byte >= 97 && byte <= 102)
        }
}
