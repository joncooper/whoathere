import Darwin
import Foundation

public let sdistGuestControlMagicV1 = Data("WHOSCTL1".utf8)
public let sdistGuestControlVersionV1: UInt16 = 1
public let sdistGuestControlPrefixBytesV1 = 16
public let maximumSdistGuestControlBodyBytesV1 = 64 * 1024

public enum SdistGuestControlFrameType: UInt16, Sendable {
    case authenticationChallenge = 1
    case authenticationResponse = 2
    case stagingReceipt = 3
}

public enum SdistGuestControlError: Error, Equatable, CustomStringConvertible {
    case invalidDescriptor
    case invalidMagic
    case unsupportedVersion
    case unsupportedFrameType
    case unexpectedFrameType
    case bodyLimitExceeded
    case truncated
    case trailingData
    case timeout
    case ioFailed

    public var description: String {
        switch self {
        case .invalidDescriptor: return "sdist_guest_control_descriptor_invalid"
        case .invalidMagic: return "sdist_guest_control_magic_invalid"
        case .unsupportedVersion: return "sdist_guest_control_version_unsupported"
        case .unsupportedFrameType: return "sdist_guest_control_type_unsupported"
        case .unexpectedFrameType: return "sdist_guest_control_type_unexpected"
        case .bodyLimitExceeded: return "sdist_guest_control_body_limit_exceeded"
        case .truncated: return "sdist_guest_control_truncated"
        case .trailingData: return "sdist_guest_control_trailing_data"
        case .timeout: return "sdist_guest_control_timeout"
        case .ioFailed: return "sdist_guest_control_io_failed"
        }
    }
}

public func writeSdistGuestControlFrame(
    descriptor: Int32,
    frameType: SdistGuestControlFrameType,
    body: Data,
    timeoutMillis: Int32
) throws {
    guard descriptor >= 0 else { throw SdistGuestControlError.invalidDescriptor }
    guard !body.isEmpty, body.count <= maximumSdistGuestControlBodyBytesV1,
          let bodyLength = UInt32(exactly: body.count) else {
        throw SdistGuestControlError.bodyLimitExceeded
    }
    var frame = Data()
    frame.reserveCapacity(sdistGuestControlPrefixBytesV1 + body.count)
    frame.append(sdistGuestControlMagicV1)
    appendSdistControlBigEndian(sdistGuestControlVersionV1, to: &frame)
    appendSdistControlBigEndian(frameType.rawValue, to: &frame)
    appendSdistControlBigEndian(bodyLength, to: &frame)
    frame.append(body)
    let deadline = try sdistControlDeadline(timeoutMillis)
    try frame.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return }
        var offset = 0
        while offset < raw.count {
            try waitForSdistControlDescriptor(
                descriptor, events: Int16(POLLOUT), deadline: deadline
            )
            let sent = send(
                descriptor,
                base.advanced(by: offset),
                raw.count - offset,
                MSG_DONTWAIT | MSG_NOSIGNAL
            )
            if sent > 0 {
                offset += sent
            } else if sent < 0 && [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) {
                continue
            } else {
                throw SdistGuestControlError.ioFailed
            }
        }
    }
}

public func readSdistGuestControlFrame(
    descriptor: Int32,
    expectedType: SdistGuestControlFrameType,
    maximumBodyBytes: Int,
    timeoutMillis: Int32
) throws -> Data {
    guard descriptor >= 0 else { throw SdistGuestControlError.invalidDescriptor }
    guard maximumBodyBytes > 0,
          maximumBodyBytes <= maximumSdistGuestControlBodyBytesV1 else {
        throw SdistGuestControlError.bodyLimitExceeded
    }
    let deadline = try sdistControlDeadline(timeoutMillis)
    let prefix = try receiveSdistControlExactly(
        descriptor, count: sdistGuestControlPrefixBytesV1, deadline: deadline
    )
    guard prefix.prefix(8) == sdistGuestControlMagicV1 else {
        throw SdistGuestControlError.invalidMagic
    }
    guard sdistControlUInt16(prefix, at: 8) == sdistGuestControlVersionV1 else {
        throw SdistGuestControlError.unsupportedVersion
    }
    guard let observedType = SdistGuestControlFrameType(
        rawValue: sdistControlUInt16(prefix, at: 10)
    ) else {
        throw SdistGuestControlError.unsupportedFrameType
    }
    guard observedType == expectedType else {
        throw SdistGuestControlError.unexpectedFrameType
    }
    let length = Int(sdistControlUInt32(prefix, at: 12))
    guard length > 0, length <= maximumBodyBytes else {
        throw SdistGuestControlError.bodyLimitExceeded
    }
    return try receiveSdistControlExactly(descriptor, count: length, deadline: deadline)
}

public func requireSdistGuestControlEOF(
    descriptor: Int32,
    timeoutMillis: Int32
) throws {
    guard descriptor >= 0 else { throw SdistGuestControlError.invalidDescriptor }
    let deadline = try sdistControlDeadline(timeoutMillis)
    try waitForSdistControlDescriptor(descriptor, events: Int16(POLLIN), deadline: deadline)
    var byte: UInt8 = 0
    let count = recv(descriptor, &byte, 1, MSG_DONTWAIT)
    if count == 0 { return }
    if count > 0 { throw SdistGuestControlError.trailingData }
    if [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) {
        throw SdistGuestControlError.timeout
    }
    throw SdistGuestControlError.ioFailed
}

private func receiveSdistControlExactly(
    _ descriptor: Int32,
    count: Int,
    deadline: UInt64
) throws -> Data {
    var data = Data(count: count)
    var offset = 0
    try data.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress else { return }
        while offset < count {
            try waitForSdistControlDescriptor(
                descriptor, events: Int16(POLLIN), deadline: deadline
            )
            let received = recv(
                descriptor,
                base.advanced(by: offset),
                count - offset,
                MSG_DONTWAIT
            )
            if received > 0 {
                offset += received
            } else if received == 0 {
                throw SdistGuestControlError.truncated
            } else if [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) {
                continue
            } else {
                throw SdistGuestControlError.ioFailed
            }
        }
    }
    return data
}

private func sdistControlDeadline(_ timeoutMillis: Int32) throws -> UInt64 {
    guard timeoutMillis > 0 else { throw SdistGuestControlError.timeout }
    let now = DispatchTime.now().uptimeNanoseconds
    let addition = UInt64(timeoutMillis) * 1_000_000
    let (deadline, overflow) = now.addingReportingOverflow(addition)
    guard !overflow else { throw SdistGuestControlError.timeout }
    return deadline
}

private func waitForSdistControlDescriptor(
    _ descriptor: Int32,
    events: Int16,
    deadline: UInt64
) throws {
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw SdistGuestControlError.timeout }
        let remainingNanoseconds = deadline - now
        let remainingMillis = max(
            1,
            min(UInt64(Int32.max), (remainingNanoseconds + 999_999) / 1_000_000)
        )
        var descriptorState = pollfd(fd: descriptor, events: events, revents: 0)
        let result = poll(&descriptorState, 1, Int32(remainingMillis))
        if result > 0 {
            if descriptorState.revents & Int16(POLLNVAL | POLLERR) != 0 {
                throw SdistGuestControlError.ioFailed
            }
            if descriptorState.revents & events != 0
                || descriptorState.revents & Int16(POLLHUP) != 0 {
                return
            }
        } else if result == 0 {
            throw SdistGuestControlError.timeout
        } else if errno != EINTR {
            throw SdistGuestControlError.ioFailed
        }
    }
}

private func sdistControlUInt16(_ data: Data, at offset: Int) -> UInt16 {
    data[offset..<offset + 2].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
}

private func sdistControlUInt32(_ data: Data, at offset: Int) -> UInt32 {
    data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

private func appendSdistControlBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendSdistControlBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}
