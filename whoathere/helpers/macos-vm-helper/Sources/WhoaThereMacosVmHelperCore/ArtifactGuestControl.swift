import Darwin
import Foundation

public let artifactGuestControlMagicV1 = Data("WHOACTL1".utf8)
public let artifactGuestControlVersionV1: UInt16 = 1
public let artifactGuestControlPrefixBytesV1 = 16
public let maximumArtifactGuestControlBodyBytesV1 = 64 * 1024

public enum ArtifactGuestControlFrameType: UInt16, Sendable {
    case authenticationChallenge = 1
    case authenticationResponse = 2
    case stagingReceipt = 3
}

public enum ArtifactGuestControlError: Error, Equatable, CustomStringConvertible {
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
        case .invalidDescriptor: return "artifact_guest_control_descriptor_invalid"
        case .invalidMagic: return "artifact_guest_control_magic_invalid"
        case .unsupportedVersion: return "artifact_guest_control_version_unsupported"
        case .unsupportedFrameType: return "artifact_guest_control_type_unsupported"
        case .unexpectedFrameType: return "artifact_guest_control_type_unexpected"
        case .bodyLimitExceeded: return "artifact_guest_control_body_limit_exceeded"
        case .truncated: return "artifact_guest_control_truncated"
        case .trailingData: return "artifact_guest_control_trailing_data"
        case .timeout: return "artifact_guest_control_timeout"
        case .ioFailed: return "artifact_guest_control_io_failed"
        }
    }
}

public struct ArtifactGuestAuthenticatedSession: Equatable, Sendable {
    public let challenge: ArtifactGuestAuthChallenge
    public let observation: ArtifactGuestAuthObservation
}

public func authenticateArtifactGuestConnection(
    descriptor: Int32,
    prelude: ArtifactRunSubmissionPrelude,
    base: LockedArtifactRunBase,
    clone: DisposableArtifactRunClone,
    timeoutMillis: Int32 = 10_000
) throws -> ArtifactGuestAuthenticatedSession {
    guard base.identity == prelude.backendIdentity else {
        throw ArtifactGuestAuthenticationError.invalidChallenge
    }
    let cloneBinding = artifactCloneBindingSHA256(base: base, clone: clone)
    let challenge = try makeArtifactGuestAuthChallenge(
        prelude: prelude,
        cloneBindingSHA256: cloneBinding,
        guestAuthPublicKey: base.guestAuthPublicKeyData
    )
    try writeArtifactGuestControlFrame(
        descriptor: descriptor,
        frameType: .authenticationChallenge,
        body: challenge.canonicalJSON,
        timeoutMillis: timeoutMillis
    )
    let response = try readArtifactGuestControlFrame(
        descriptor: descriptor,
        expectedType: .authenticationResponse,
        maximumBodyBytes: maximumArtifactGuestAuthBytesV1,
        timeoutMillis: timeoutMillis
    )
    let observation = try verifyArtifactGuestAuthResponse(
        response,
        challenge: challenge,
        prelude: prelude,
        guestAuthPublicKey: base.guestAuthPublicKeyData
    )
    return ArtifactGuestAuthenticatedSession(
        challenge: challenge,
        observation: observation
    )
}

public func writeArtifactGuestControlFrame(
    descriptor: Int32,
    frameType: ArtifactGuestControlFrameType,
    body: Data,
    timeoutMillis: Int32
) throws {
    guard descriptor >= 0 else { throw ArtifactGuestControlError.invalidDescriptor }
    guard !body.isEmpty, body.count <= maximumArtifactGuestControlBodyBytesV1,
          let bodyLength = UInt32(exactly: body.count) else {
        throw ArtifactGuestControlError.bodyLimitExceeded
    }
    var frame = Data()
    frame.reserveCapacity(artifactGuestControlPrefixBytesV1 + body.count)
    frame.append(artifactGuestControlMagicV1)
    appendControlBigEndian(artifactGuestControlVersionV1, to: &frame)
    appendControlBigEndian(frameType.rawValue, to: &frame)
    appendControlBigEndian(bodyLength, to: &frame)
    frame.append(body)
    let deadline = try controlDeadline(timeoutMillis)
    try frame.withUnsafeBytes { raw in
        guard let base = raw.baseAddress else { return }
        var offset = 0
        while offset < raw.count {
            try waitForDescriptor(descriptor, events: Int16(POLLOUT), deadline: deadline)
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
                throw ArtifactGuestControlError.ioFailed
            }
        }
    }
}

public func readArtifactGuestControlFrame(
    descriptor: Int32,
    expectedType: ArtifactGuestControlFrameType,
    maximumBodyBytes: Int,
    timeoutMillis: Int32
) throws -> Data {
    guard descriptor >= 0 else { throw ArtifactGuestControlError.invalidDescriptor }
    guard maximumBodyBytes > 0,
          maximumBodyBytes <= maximumArtifactGuestControlBodyBytesV1 else {
        throw ArtifactGuestControlError.bodyLimitExceeded
    }
    let deadline = try controlDeadline(timeoutMillis)
    let prefix = try receiveControlExactly(
        descriptor, count: artifactGuestControlPrefixBytesV1, deadline: deadline
    )
    guard prefix.prefix(8) == artifactGuestControlMagicV1 else {
        throw ArtifactGuestControlError.invalidMagic
    }
    guard controlUInt16(prefix, at: 8) == artifactGuestControlVersionV1 else {
        throw ArtifactGuestControlError.unsupportedVersion
    }
    guard let observedType = ArtifactGuestControlFrameType(
        rawValue: controlUInt16(prefix, at: 10)
    ) else {
        throw ArtifactGuestControlError.unsupportedFrameType
    }
    guard observedType == expectedType else {
        throw ArtifactGuestControlError.unexpectedFrameType
    }
    let length = Int(controlUInt32(prefix, at: 12))
    guard length > 0, length <= maximumBodyBytes else {
        throw ArtifactGuestControlError.bodyLimitExceeded
    }
    return try receiveControlExactly(descriptor, count: length, deadline: deadline)
}

public func requireArtifactGuestControlEOF(
    descriptor: Int32,
    timeoutMillis: Int32
) throws {
    guard descriptor >= 0 else { throw ArtifactGuestControlError.invalidDescriptor }
    let deadline = try controlDeadline(timeoutMillis)
    try waitForDescriptor(descriptor, events: Int16(POLLIN), deadline: deadline)
    var byte: UInt8 = 0
    let count = recv(descriptor, &byte, 1, MSG_DONTWAIT)
    if count == 0 { return }
    if count > 0 { throw ArtifactGuestControlError.trailingData }
    if [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) {
        throw ArtifactGuestControlError.timeout
    }
    throw ArtifactGuestControlError.ioFailed
}

private func receiveControlExactly(
    _ descriptor: Int32,
    count: Int,
    deadline: UInt64
) throws -> Data {
    var data = Data(count: count)
    var offset = 0
    try data.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress else { return }
        while offset < count {
            try waitForDescriptor(descriptor, events: Int16(POLLIN), deadline: deadline)
            let received = recv(
                descriptor,
                base.advanced(by: offset),
                count - offset,
                MSG_DONTWAIT
            )
            if received > 0 {
                offset += received
            } else if received == 0 {
                throw ArtifactGuestControlError.truncated
            } else if [EINTR, EAGAIN, EWOULDBLOCK].contains(errno) {
                continue
            } else {
                throw ArtifactGuestControlError.ioFailed
            }
        }
    }
    return data
}

private func controlDeadline(_ timeoutMillis: Int32) throws -> UInt64 {
    guard timeoutMillis > 0 else { throw ArtifactGuestControlError.timeout }
    let now = DispatchTime.now().uptimeNanoseconds
    let addition = UInt64(timeoutMillis) * 1_000_000
    let (deadline, overflow) = now.addingReportingOverflow(addition)
    guard !overflow else { throw ArtifactGuestControlError.timeout }
    return deadline
}

private func waitForDescriptor(
    _ descriptor: Int32,
    events: Int16,
    deadline: UInt64
) throws {
    while true {
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadline else { throw ArtifactGuestControlError.timeout }
        let remainingNanoseconds = deadline - now
        let remainingMillis = max(
            1,
            min(UInt64(Int32.max), (remainingNanoseconds + 999_999) / 1_000_000)
        )
        var descriptorState = pollfd(fd: descriptor, events: events, revents: 0)
        let result = poll(&descriptorState, 1, Int32(remainingMillis))
        if result > 0 {
            if descriptorState.revents & Int16(POLLNVAL | POLLERR) != 0 {
                throw ArtifactGuestControlError.ioFailed
            }
            if descriptorState.revents & events != 0 || descriptorState.revents & Int16(POLLHUP) != 0 {
                return
            }
        } else if result == 0 {
            throw ArtifactGuestControlError.timeout
        } else if errno != EINTR {
            throw ArtifactGuestControlError.ioFailed
        }
    }
}

private func controlUInt16(_ data: Data, at offset: Int) -> UInt16 {
    data[offset..<offset + 2].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
}

private func controlUInt32(_ data: Data, at offset: Int) -> UInt32 {
    data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

private func appendControlBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendControlBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}
