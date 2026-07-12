import Foundation

public let linuxVzGuestSignerRequestMagicV1 = Data("WHVZGSQ1".utf8)
public let linuxVzGuestSignerResponseMagicV1 = Data("WHVZGSP1".utf8)
public let maximumLinuxVzGuestSignerRunSpecBytesV1 = 256 * 1024
public let maximumLinuxVzGuestSignerChallengeBytesV1 = 64 * 1024
public let maximumLinuxVzGuestSignerReceiptBytesV1 = 1024 * 1024
public let maximumLinuxVzGuestSignerRequestFrameBytesV1 = 16
    + maximumLinuxVzGuestSignerRunSpecBytesV1
    + maximumLinuxVzGuestSignerChallengeBytesV1
public let maximumLinuxVzGuestSignerResponseFrameBytesV1 = 12
    + maximumLinuxVzGuestSignerReceiptBytesV1

public enum LinuxVzGuestSignerTransportError: Error, Equatable {
    case empty
    case limitExceeded
    case invalidMagic
    case invalidLength
    case trailingBytes
}

public struct LinuxVzGuestSignerRequest: Equatable, Sendable {
    public let runSpec: Data
    public let challenge: Data
}

public func decodeLinuxVzGuestSignerRequest(
    _ frame: Data
) throws -> LinuxVzGuestSignerRequest {
    guard !frame.isEmpty else { throw LinuxVzGuestSignerTransportError.empty }
    guard frame.count <= maximumLinuxVzGuestSignerRequestFrameBytesV1 else {
        throw LinuxVzGuestSignerTransportError.limitExceeded
    }
    guard frame.count >= 16, frame.prefix(8) == linuxVzGuestSignerRequestMagicV1 else {
        throw LinuxVzGuestSignerTransportError.invalidMagic
    }
    let runSpecLength = Int(try linuxVzGuestSignerUInt32(frame, offset: 8))
    let challengeLength = Int(try linuxVzGuestSignerUInt32(frame, offset: 12))
    try linuxVzGuestSignerValidateLength(
        runSpecLength,
        maximum: maximumLinuxVzGuestSignerRunSpecBytesV1
    )
    try linuxVzGuestSignerValidateLength(
        challengeLength,
        maximum: maximumLinuxVzGuestSignerChallengeBytesV1
    )
    guard runSpecLength <= Int.max - 16,
          challengeLength <= Int.max - 16 - runSpecLength else {
        throw LinuxVzGuestSignerTransportError.invalidLength
    }
    let expected = 16 + runSpecLength + challengeLength
    guard frame.count >= expected else {
        throw LinuxVzGuestSignerTransportError.invalidLength
    }
    guard frame.count == expected else {
        throw LinuxVzGuestSignerTransportError.trailingBytes
    }
    return LinuxVzGuestSignerRequest(
        runSpec: frame.subdata(in: 16..<(16 + runSpecLength)),
        challenge: frame.subdata(in: (16 + runSpecLength)..<expected)
    )
}

public func decodeLinuxVzGuestSignerResponse(_ frame: Data) throws -> Data {
    guard !frame.isEmpty else { throw LinuxVzGuestSignerTransportError.empty }
    guard frame.count <= maximumLinuxVzGuestSignerResponseFrameBytesV1 else {
        throw LinuxVzGuestSignerTransportError.limitExceeded
    }
    guard frame.count >= 12, frame.prefix(8) == linuxVzGuestSignerResponseMagicV1 else {
        throw LinuxVzGuestSignerTransportError.invalidMagic
    }
    let receiptLength = Int(try linuxVzGuestSignerUInt32(frame, offset: 8))
    try linuxVzGuestSignerValidateLength(
        receiptLength,
        maximum: maximumLinuxVzGuestSignerReceiptBytesV1
    )
    guard receiptLength <= Int.max - 12 else {
        throw LinuxVzGuestSignerTransportError.invalidLength
    }
    let expected = 12 + receiptLength
    guard frame.count >= expected else {
        throw LinuxVzGuestSignerTransportError.invalidLength
    }
    guard frame.count == expected else {
        throw LinuxVzGuestSignerTransportError.trailingBytes
    }
    return frame.subdata(in: 12..<expected)
}

private func linuxVzGuestSignerUInt32(_ data: Data, offset: Int) throws -> UInt32 {
    guard offset >= 0, data.count >= offset + 4 else {
        throw LinuxVzGuestSignerTransportError.invalidLength
    }
    return data[offset..<(offset + 4)].reduce(UInt32(0)) { value, byte in
        (value << 8) | UInt32(byte)
    }
}

private func linuxVzGuestSignerValidateLength(_ length: Int, maximum: Int) throws {
    guard length > 0 else { throw LinuxVzGuestSignerTransportError.empty }
    guard length <= maximum else { throw LinuxVzGuestSignerTransportError.limitExceeded }
}
