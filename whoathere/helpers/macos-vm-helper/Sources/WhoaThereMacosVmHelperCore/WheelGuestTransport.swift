import Darwin
import Foundation

public let wheelGuestSubmissionMagicV1 = Data("WHOWGST1".utf8)
public let wheelGuestSubmissionVersionV1: UInt16 = 1
public let wheelGuestSubmissionFrameTypeV1: UInt16 = 1

public enum WheelGuestTransportError: Error, Equatable, CustomStringConvertible {
    case invalidDescriptor
    case writeFailed
    case writeShutdownFailed

    public var description: String {
        switch self {
        case .invalidDescriptor: return "wheel_guest_transport_descriptor_invalid"
        case .writeFailed: return "wheel_guest_transport_write_failed"
        case .writeShutdownFailed: return "wheel_guest_transport_write_shutdown_failed"
        }
    }
}

/// Forwards one already-validated wheel submission to an authenticated guest connection.
///
/// Authentication must complete before this type is constructed by a lifecycle caller. The
/// forwarder preserves the canonical wheel header and raw artifact bytes, changes only the
/// transport-domain magic, and closes its write side after exactly one complete submission.
public final class WheelGuestSubmissionForwarder {
    private let descriptor: Int32
    private let reader: WheelRunSubmissionReader
    private var started = false

    public init(descriptor: Int32, reader: WheelRunSubmissionReader) throws {
        guard descriptor >= 0 else {
            throw WheelGuestTransportError.invalidDescriptor
        }
        self.descriptor = descriptor
        self.reader = reader
    }

    public func forward() throws -> WheelRunTransportObservation {
        guard !started else {
            throw WheelGuestTransportError.writeFailed
        }
        started = true
        do {
            var prefix = Data()
            prefix.reserveCapacity(wheelSubmissionPrefixBytesV1)
            prefix.append(wheelGuestSubmissionMagicV1)
            appendWheelGuestBigEndian(wheelGuestSubmissionVersionV1, to: &prefix)
            appendWheelGuestBigEndian(wheelGuestSubmissionFrameTypeV1, to: &prefix)
            appendWheelGuestBigEndian(UInt32(reader.canonicalHeaderData.count), to: &prefix)
            appendWheelGuestBigEndian(reader.prelude.artifactByteLength, to: &prefix)
            prefix.append(reader.expectedArtifactDigest)
            guard prefix.count == wheelSubmissionPrefixBytesV1 else {
                throw WheelGuestTransportError.writeFailed
            }
            try sendAll(prefix)
            try sendAll(reader.canonicalHeaderData)
            let observation = try reader.consumeArtifact { [self] chunk in
                try sendAll(chunk)
            }
            guard shutdown(descriptor, SHUT_WR) == 0 else {
                throw WheelGuestTransportError.writeShutdownFailed
            }
            return observation
        } catch {
            _ = shutdown(descriptor, SHUT_WR)
            throw error
        }
    }

    private func sendAll(_ data: Data) throws {
        try data.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else { return }
            var offset = 0
            while offset < rawBuffer.count {
                let sent = Darwin.send(
                    descriptor,
                    base.advanced(by: offset),
                    rawBuffer.count - offset,
                    MSG_NOSIGNAL
                )
                if sent > 0 {
                    offset += sent
                    continue
                }
                if sent < 0 && errno == EINTR { continue }
                throw WheelGuestTransportError.writeFailed
            }
        }
    }
}

private func appendWheelGuestBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendWheelGuestBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func appendWheelGuestBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}
