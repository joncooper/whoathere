import Foundation

public let linuxVzRuntimeQualificationRequestMagicV1 = Data("WHVZRQQ1".utf8)
public let linuxVzRuntimeQualificationResponseMagicV1 = Data("WHVZRQP1".utf8)
public let maximumLinuxVzRuntimeQualificationRequestFrameBytesV1 = 12 + 64 * 1024
public let maximumLinuxVzRuntimeQualificationResponseFrameBytesV1 =
    20 + 4 * 1024 + 1024 * 1024 + 1024 * 1024

public enum LinuxVzPackageRuntimeQualificationTransportError: Error, Equatable {
    case empty
    case limitExceeded
    case invalidMagic
    case invalidLength
    case trailingBytes
}

public struct LinuxVzPackageRuntimeQualificationResponse: Equatable, Sendable {
    public let probeReport: Data
    public let processEvidence: Data
    public let guestReceipt: Data
}

public func encodeLinuxVzPackageRuntimeQualificationRequest(
    _ request: Data
) throws -> Data {
    guard !request.isEmpty else {
        throw LinuxVzPackageRuntimeQualificationTransportError.empty
    }
    guard request.count <= 64 * 1024, request.count <= Int(UInt32.max) else {
        throw LinuxVzPackageRuntimeQualificationTransportError.limitExceeded
    }
    var frame = Data()
    frame.append(linuxVzRuntimeQualificationRequestMagicV1)
    linuxVzRuntimeQualificationAppendUInt32(UInt32(request.count), to: &frame)
    frame.append(request)
    return frame
}

public func decodeLinuxVzPackageRuntimeQualificationRequestFrame(
    _ frame: Data
) throws -> Data {
    guard !frame.isEmpty else {
        throw LinuxVzPackageRuntimeQualificationTransportError.empty
    }
    guard frame.count <= maximumLinuxVzRuntimeQualificationRequestFrameBytesV1 else {
        throw LinuxVzPackageRuntimeQualificationTransportError.limitExceeded
    }
    guard frame.count >= 12,
          frame.prefix(8) == linuxVzRuntimeQualificationRequestMagicV1 else {
        throw LinuxVzPackageRuntimeQualificationTransportError.invalidMagic
    }
    let length = try linuxVzRuntimeQualificationUInt32(frame, offset: 8)
    guard length > 0, length <= 64 * 1024 else {
        throw LinuxVzPackageRuntimeQualificationTransportError.invalidLength
    }
    let expected = 12 + Int(length)
    guard frame.count >= expected else {
        throw LinuxVzPackageRuntimeQualificationTransportError.invalidLength
    }
    guard frame.count == expected else {
        throw LinuxVzPackageRuntimeQualificationTransportError.trailingBytes
    }
    return frame.subdata(in: 12..<expected)
}

public func decodeLinuxVzPackageRuntimeQualificationResponse(
    _ frame: Data
) throws -> LinuxVzPackageRuntimeQualificationResponse {
    guard !frame.isEmpty else {
        throw LinuxVzPackageRuntimeQualificationTransportError.empty
    }
    guard frame.count <= maximumLinuxVzRuntimeQualificationResponseFrameBytesV1 else {
        throw LinuxVzPackageRuntimeQualificationTransportError.limitExceeded
    }
    guard frame.count >= 20,
          frame.prefix(8) == linuxVzRuntimeQualificationResponseMagicV1 else {
        throw LinuxVzPackageRuntimeQualificationTransportError.invalidMagic
    }
    let probeLength = try linuxVzRuntimeQualificationUInt32(frame, offset: 8)
    let evidenceLength = try linuxVzRuntimeQualificationUInt32(frame, offset: 12)
    let receiptLength = try linuxVzRuntimeQualificationUInt32(frame, offset: 16)
    guard probeLength > 0, probeLength <= 4 * 1024,
          evidenceLength > 0, evidenceLength <= 1024 * 1024,
          receiptLength > 0, receiptLength <= 1024 * 1024 else {
        throw LinuxVzPackageRuntimeQualificationTransportError.invalidLength
    }
    let probeEnd = 20 + Int(probeLength)
    let evidenceEnd = probeEnd + Int(evidenceLength)
    let expected = evidenceEnd + Int(receiptLength)
    guard frame.count >= expected else {
        throw LinuxVzPackageRuntimeQualificationTransportError.invalidLength
    }
    guard frame.count == expected else {
        throw LinuxVzPackageRuntimeQualificationTransportError.trailingBytes
    }
    return LinuxVzPackageRuntimeQualificationResponse(
        probeReport: frame.subdata(in: 20..<probeEnd),
        processEvidence: frame.subdata(in: probeEnd..<evidenceEnd),
        guestReceipt: frame.subdata(in: evidenceEnd..<expected)
    )
}

private func linuxVzRuntimeQualificationAppendUInt32(_ value: UInt32, to data: inout Data) {
    data.append(UInt8((value >> 24) & 0xff))
    data.append(UInt8((value >> 16) & 0xff))
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func linuxVzRuntimeQualificationUInt32(_ data: Data, offset: Int) throws -> UInt32 {
    guard offset >= 0, offset + 4 <= data.count else {
        throw LinuxVzPackageRuntimeQualificationTransportError.invalidLength
    }
    return data[offset..<(offset + 4)].reduce(UInt32(0)) { value, byte in
        (value << 8) | UInt32(byte)
    }
}
