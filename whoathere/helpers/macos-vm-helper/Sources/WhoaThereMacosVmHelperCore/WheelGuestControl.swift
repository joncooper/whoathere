import Darwin
import Foundation

public let wheelGuestControlMagicV1 = Data("WHOWCTL1".utf8)
public let wheelGuestControlVersionV1: UInt16 = 1
public let wheelGuestControlPrefixBytesV1 = 16
public let maximumWheelGuestControlBodyBytesV1 = 64 * 1024

public enum WheelGuestControlFrameType: UInt16, Sendable {
    case authenticationChallenge = 1
    case authenticationResponse = 2
    case stagingReceipt = 3
}

public enum WheelGuestControlError: Error, Equatable, CustomStringConvertible {
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
        case .invalidDescriptor: return "wheel_guest_control_descriptor_invalid"
        case .invalidMagic: return "wheel_guest_control_magic_invalid"
        case .unsupportedVersion: return "wheel_guest_control_version_unsupported"
        case .unsupportedFrameType: return "wheel_guest_control_type_unsupported"
        case .unexpectedFrameType: return "wheel_guest_control_type_unexpected"
        case .bodyLimitExceeded: return "wheel_guest_control_body_limit_exceeded"
        case .truncated: return "wheel_guest_control_truncated"
        case .trailingData: return "wheel_guest_control_trailing_data"
        case .timeout: return "wheel_guest_control_timeout"
        case .ioFailed: return "wheel_guest_control_io_failed"
        }
    }
}

public func writeWheelGuestControlFrame(
    descriptor: Int32,
    frameType: WheelGuestControlFrameType,
    body: Data,
    timeoutMillis: Int32
) throws {
    guard descriptor >= 0 else { throw WheelGuestControlError.invalidDescriptor }
    guard !body.isEmpty, body.count <= maximumWheelGuestControlBodyBytesV1,
          let bodyLength = UInt32(exactly: body.count) else {
        throw WheelGuestControlError.bodyLimitExceeded
    }
    var frame = Data()
    frame.reserveCapacity(wheelGuestControlPrefixBytesV1 + body.count)
    frame.append(wheelGuestControlMagicV1)
    appendWheelControlBigEndian(wheelGuestControlVersionV1, to: &frame)
    appendWheelControlBigEndian(frameType.rawValue, to: &frame)
    appendWheelControlBigEndian(bodyLength, to: &frame)
    frame.append(body)
    let deadline = try wheelControlDeadline(timeoutMillis)
    try frame.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return }
        var offset = 0
        while offset < raw.count {
            try waitForWheelControlDescriptor(
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
                throw WheelGuestControlError.ioFailed
            }
        }
    }
}

public func readWheelGuestControlFrame(
    descriptor: Int32,
    expectedType: WheelGuestControlFrameType,
    maximumBodyBytes: Int,
    timeoutMillis: Int32
) throws -> Data {
    guard descriptor >= 0 else { throw WheelGuestControlError.invalidDescriptor }
    guard maximumBodyBytes > 0,
          maximumBodyBytes <= maximumWheelGuestControlBodyBytesV1 else {
        throw WheelGuestControlError.bodyLimitExceeded
    }
    let deadline = try wheelControlDeadline(timeoutMillis)
    let prefix = try receiveWheelControlExactly(
        descriptor, count: wheelGuestControlPrefixBytesV1, deadline: deadline
    )
    guard prefix.prefix(8) == wheelGuestControlMagicV1 else {
        throw WheelGuestControlError.invalidMagic
    }
    guard wheelControlUInt16(prefix, at: 8) == wheelGuestControlVersionV1 else {
        throw WheelGuestControlError.unsupportedVersion
    }
    guard let observedType = WheelGuestControlFrameType(
        rawValue: wheelControlUInt16(prefix, at: 10)
    ) else {
        throw WheelGuestControlError.unsupportedFrameType
    }
    guard observedType == expectedType else {
        throw WheelGuestControlError.unexpectedFrameType
    }
    let length = Int(wheelControlUInt32(prefix, at: 12))
    guard length > 0, length <= maximumBodyBytes else {
        throw WheelGuestControlError.bodyLimitExceeded
    }
    return try receiveWheelControlExactly(descriptor, count: length, deadline: deadline)
}

public func requireWheelGuestControlEOF(
    descriptor: Int32,
    timeoutMillis: Int32
) throws {
    guard descriptor >= 0 else { throw WheelGuestControlError.invalidDescriptor }
    let deadline = try wheelControlDeadline(timeoutMillis)
    try waitForWheelControlDescriptor(descriptor, events: Int16(POLLIN), deadline: deadline)
    var byte: UInt8 = 0
    let count = recv(descriptor, &byte, 1, MSG_DONTWAIT)
    if count == 0 { return }
    if count > 0 { throw WheelGuestControlError.trailingData }
    if [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) {
        throw WheelGuestControlError.timeout
    }
    throw WheelGuestControlError.ioFailed
}

private func receiveWheelControlExactly(
    _ descriptor: Int32,
    count: Int,
    deadline: UInt64
) throws -> Data {
    var data = Data(count: count)
    var offset = 0
    try data.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress else { return }
        while offset < count {
            try waitForWheelControlDescriptor(
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
                throw WheelGuestControlError.truncated
            } else if [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) {
                continue
            } else {
                throw WheelGuestControlError.ioFailed
            }
        }
    }
    return data
}

private func wheelControlDeadline(_ timeoutMillis: Int32) throws -> UInt64 {
    guard timeoutMillis > 0 else { throw WheelGuestControlError.timeout }
    let now = DispatchTime.now().uptimeNanoseconds
    let addition = UInt64(timeoutMillis) * 1_000_000
    let (deadline, overflow) = now.addingReportingOverflow(addition)
    guard !overflow else { throw WheelGuestControlError.timeout }
    return deadline
}

private func waitForWheelControlDescriptor(
    _ descriptor: Int32,
    events: Int16,
    deadline: UInt64
) throws {
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw WheelGuestControlError.timeout }
        let remainingNanoseconds = deadline - now
        let remainingMillis = max(
            1,
            min(UInt64(Int32.max), (remainingNanoseconds + 999_999) / 1_000_000)
        )
        var descriptorState = pollfd(fd: descriptor, events: events, revents: 0)
        let result = poll(&descriptorState, 1, Int32(remainingMillis))
        if result > 0 {
            if descriptorState.revents & Int16(POLLNVAL | POLLERR) != 0 {
                throw WheelGuestControlError.ioFailed
            }
            if descriptorState.revents & events != 0
                || descriptorState.revents & Int16(POLLHUP) != 0 {
                return
            }
        } else if result == 0 {
            throw WheelGuestControlError.timeout
        } else if errno != EINTR {
            throw WheelGuestControlError.ioFailed
        }
    }
}

private func wheelControlUInt16(_ data: Data, at offset: Int) -> UInt16 {
    data[offset..<offset + 2].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
}

private func wheelControlUInt32(_ data: Data, at offset: Int) -> UInt32 {
    data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

private func appendWheelControlBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendWheelControlBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}
