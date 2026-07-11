import Darwin
import Foundation

public let sdistGuestSubmissionMagicV1 = Data("WHOSGST1".utf8)
public let sdistGuestSubmissionVersionV1: UInt16 = 1
public let sdistGuestSubmissionFrameTypeV1: UInt16 = 1

public enum SdistGuestTransportError: Error, Equatable, CustomStringConvertible {
    case invalidDescriptor
    case writeFailed
    case writeShutdownFailed

    public var description: String {
        switch self {
        case .invalidDescriptor: return "sdist_guest_transport_descriptor_invalid"
        case .writeFailed: return "sdist_guest_transport_write_failed"
        case .writeShutdownFailed: return "sdist_guest_transport_write_shutdown_failed"
        }
    }
}

/// Forwards one authority-consumed sdist submission to an already-authenticated guest connection.
/// The host header and exact body are preserved; only the transport-domain magic changes.
public final class SdistGuestSubmissionForwarder {
    private let descriptor: Int32
    private let authorized: AuthorizedSdistRunSubmission
    private var started = false

    public init(
        descriptor: Int32,
        authorized: AuthorizedSdistRunSubmission
    ) throws {
        guard descriptor >= 0 else { throw SdistGuestTransportError.invalidDescriptor }
        self.descriptor = descriptor
        self.authorized = authorized
    }

    public func forward(
        shutdownWriteSide: Bool = true
    ) throws -> SdistRunTransportObservation {
        guard !started else { throw SdistGuestTransportError.writeFailed }
        started = true
        let reader = authorized.submissionReader
        do {
            var prefix = Data()
            prefix.reserveCapacity(sdistSubmissionPrefixBytesV1)
            prefix.append(sdistGuestSubmissionMagicV1)
            appendSdistGuestBigEndian(sdistGuestSubmissionVersionV1, to: &prefix)
            appendSdistGuestBigEndian(sdistGuestSubmissionFrameTypeV1, to: &prefix)
            appendSdistGuestBigEndian(UInt32(reader.canonicalHeaderData.count), to: &prefix)
            appendSdistGuestBigEndian(reader.prelude.artifactByteLength, to: &prefix)
            prefix.append(reader.expectedArtifactDigest)
            guard prefix.count == sdistSubmissionPrefixBytesV1 else {
                throw SdistGuestTransportError.writeFailed
            }
            try sendAll(prefix)
            try sendAll(reader.canonicalHeaderData)
            let observation = try authorized.consumeArtifact { [self] chunk in
                try sendAll(chunk)
            }
            if shutdownWriteSide {
                guard shutdown(descriptor, SHUT_WR) == 0 else {
                    throw SdistGuestTransportError.writeShutdownFailed
                }
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
                throw SdistGuestTransportError.writeFailed
            }
        }
    }
}

private func appendSdistGuestBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendSdistGuestBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func appendSdistGuestBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}
