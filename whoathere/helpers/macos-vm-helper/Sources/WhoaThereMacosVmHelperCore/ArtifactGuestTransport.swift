import Darwin
import Foundation

public let artifactGuestSubmissionMagicV1 = Data("WHOAGST1".utf8)
public let artifactGuestSubmissionVersionV1: UInt16 = 1
public let artifactGuestSubmissionFrameTypeV1: UInt16 = 1

public enum ArtifactGuestTransportError: Error, Equatable, CustomStringConvertible {
    case invalidDescriptor
    case writeFailed
    case writeShutdownFailed

    public var description: String {
        switch self {
        case .invalidDescriptor: return "artifact_guest_transport_descriptor_invalid"
        case .writeFailed: return "artifact_guest_transport_write_failed"
        case .writeShutdownFailed: return "artifact_guest_transport_write_shutdown_failed"
        }
    }
}

public final class ArtifactGuestSubmissionForwarder {
    private let descriptor: Int32
    private let reader: ArtifactRunSubmissionReader
    private var started = false

    public init(descriptor: Int32, reader: ArtifactRunSubmissionReader) throws {
        guard descriptor >= 0 else {
            throw ArtifactGuestTransportError.invalidDescriptor
        }
        self.descriptor = descriptor
        self.reader = reader
    }

    public func forward() throws -> ArtifactRunTransportObservation {
        guard !started else {
            throw ArtifactGuestTransportError.writeFailed
        }
        started = true
        do {
            var prefix = Data()
            prefix.reserveCapacity(artifactSubmissionPrefixBytesV1)
            prefix.append(artifactGuestSubmissionMagicV1)
            appendBigEndian(artifactGuestSubmissionVersionV1, to: &prefix)
            appendBigEndian(artifactGuestSubmissionFrameTypeV1, to: &prefix)
            appendBigEndian(UInt32(reader.canonicalHeaderData.count), to: &prefix)
            appendBigEndian(reader.prelude.artifactByteLength, to: &prefix)
            prefix.append(reader.expectedArtifactDigest)
            guard prefix.count == artifactSubmissionPrefixBytesV1 else {
                throw ArtifactGuestTransportError.writeFailed
            }
            try sendAll(prefix)
            try sendAll(reader.canonicalHeaderData)
            let observation = try reader.consumeArtifact { [self] chunk in
                try sendAll(chunk)
            }
            guard shutdown(descriptor, SHUT_WR) == 0 else {
                throw ArtifactGuestTransportError.writeShutdownFailed
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
                throw ArtifactGuestTransportError.writeFailed
            }
        }
    }
}

private func appendBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func appendBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}
