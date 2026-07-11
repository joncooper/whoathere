import CryptoKit
import Darwin
import Foundation

public let sdistBuildClosureMagicV1 = Data("WHOASCL1".utf8)
public let sdistGuestBuildClosureMagicV1 = Data("WHOSGCL1".utf8)
public let sdistBuildClosureVersionV1: UInt16 = 1
public let sdistBuildClosureFrameTypeV1: UInt16 = 1
public let sdistBuildClosurePrefixBytesV1 = 96
public let maximumSdistBuildClosureManifestBytesV1 = 256 * 1024
public let maximumSdistBuildClosureArtifactsV1 = 64
public let maximumSdistBuildClosurePayloadBytesV1: UInt64 = 128 * 1024 * 1024

public enum SdistBuildClosureTransportError: Error, Equatable, CustomStringConvertible {
    case invalidMagic
    case unsupportedVersion
    case unsupportedFrameType
    case invalidPrefix
    case manifestLimitExceeded
    case artifactCountLimitExceeded
    case payloadLimitExceeded
    case manifestInvalid
    case bindingMismatch
    case truncated
    case trailingData
    case artifactDigestMismatch
    case payloadDigestMismatch
    case inputReadFailed
    case writeFailed
    case writeShutdownFailed

    public var description: String {
        switch self {
        case .invalidMagic: return "sdist_build_closure_magic_invalid"
        case .unsupportedVersion: return "sdist_build_closure_version_unsupported"
        case .unsupportedFrameType: return "sdist_build_closure_type_unsupported"
        case .invalidPrefix: return "sdist_build_closure_prefix_invalid"
        case .manifestLimitExceeded: return "sdist_build_closure_manifest_limit_exceeded"
        case .artifactCountLimitExceeded:
            return "sdist_build_closure_artifact_count_limit_exceeded"
        case .payloadLimitExceeded: return "sdist_build_closure_payload_limit_exceeded"
        case .manifestInvalid: return "sdist_build_closure_manifest_invalid"
        case .bindingMismatch: return "sdist_build_closure_binding_mismatch"
        case .truncated: return "sdist_build_closure_truncated"
        case .trailingData: return "sdist_build_closure_trailing_data"
        case .artifactDigestMismatch: return "sdist_build_closure_artifact_digest_mismatch"
        case .payloadDigestMismatch: return "sdist_build_closure_payload_digest_mismatch"
        case .inputReadFailed: return "sdist_build_closure_input_read_failed"
        case .writeFailed: return "sdist_build_closure_write_failed"
        case .writeShutdownFailed: return "sdist_build_closure_write_shutdown_failed"
        }
    }
}

public struct SdistBuildClosureTransportObservation: Equatable, Sendable {
    public let closureSHA256: String
    public let payloadSHA256: String
    public let artifactCount: Int
    public let payloadByteLength: UInt64
}

/// A closure channel can only be constructed from an authority-consumed sdist submission. The
/// canonical manifest is repeated on the separate channel, but it must match the manifest already
/// authenticated inside the run spec byte-for-byte before any closure artifact byte is consumed.
public final class AuthorizedSdistBuildClosureSubmission {
    public let manifest: SdistBuildClosureManifest

    private let handle: FileHandle
    private let cancellation: SdistRunCancellationState?
    fileprivate let expectedPayloadDigest: Data
    private var consumed = false

    fileprivate init(
        handle: FileHandle,
        cancellation: SdistRunCancellationState?,
        expectedPayloadDigest: Data,
        manifest: SdistBuildClosureManifest
    ) {
        self.handle = handle
        self.cancellation = cancellation
        self.expectedPayloadDigest = expectedPayloadDigest
        self.manifest = manifest
    }

    public func consumePayload(
        chunkSink: (Int, SdistBuildClosureArtifact, Data) throws -> Void = { _, _, _ in }
    ) throws -> SdistBuildClosureTransportObservation {
        guard !consumed else { throw SdistBuildClosureTransportError.trailingData }
        consumed = true
        var payloadHasher = SHA256()
        for (index, artifact) in manifest.artifacts.enumerated() {
            var artifactHasher = SHA256()
            var remaining = artifact.artifactByteLength
            while remaining > 0 {
                let requested = Int(min(remaining, UInt64(64 * 1024)))
                let chunk = try closureReadExactly(
                    handle,
                    count: requested,
                    cancellation: cancellation
                )
                artifactHasher.update(data: chunk)
                payloadHasher.update(data: chunk)
                try chunkSink(index, artifact, chunk)
                remaining -= UInt64(chunk.count)
            }
            guard sdistClosureDigestString(Data(artifactHasher.finalize()))
                    == artifact.artifactSHA256 else {
                throw SdistBuildClosureTransportError.artifactDigestMismatch
            }
        }
        guard Data(payloadHasher.finalize()) == expectedPayloadDigest else {
            throw SdistBuildClosureTransportError.payloadDigestMismatch
        }
        try closureWaitUntilReadable(handle, cancellation: cancellation)
        do {
            if let trailing = try handle.read(upToCount: 1), !trailing.isEmpty {
                throw SdistBuildClosureTransportError.trailingData
            }
        } catch let error as SdistBuildClosureTransportError {
            throw error
        } catch {
            try cancellation?.throwIfRequested()
            throw SdistBuildClosureTransportError.inputReadFailed
        }
        return SdistBuildClosureTransportObservation(
            closureSHA256: manifest.closureSHA256,
            payloadSHA256: sdistClosureDigestString(expectedPayloadDigest),
            artifactCount: manifest.artifacts.count,
            payloadByteLength: manifest.payloadByteLength
        )
    }
}

/// Reframes the already-authorized closure channel into its guest-only domain. The canonical
/// manifest and exact payload bytes are unchanged, and the guest write side closes only after the
/// independently bounded closure frame is complete.
public final class SdistGuestBuildClosureForwarder {
    private let descriptor: Int32
    private let authorized: AuthorizedSdistBuildClosureSubmission
    private var started = false

    public init(
        descriptor: Int32,
        authorized: AuthorizedSdistBuildClosureSubmission
    ) throws {
        guard descriptor >= 0 else { throw SdistBuildClosureTransportError.writeFailed }
        self.descriptor = descriptor
        self.authorized = authorized
    }

    public func forward() throws -> SdistBuildClosureTransportObservation {
        guard !started else { throw SdistBuildClosureTransportError.writeFailed }
        started = true
        do {
            var prefix = Data()
            prefix.append(sdistGuestBuildClosureMagicV1)
            appendClosureBigEndian(sdistBuildClosureVersionV1, to: &prefix)
            appendClosureBigEndian(sdistBuildClosureFrameTypeV1, to: &prefix)
            appendClosureBigEndian(UInt32(authorized.manifest.canonicalJSON.count), to: &prefix)
            appendClosureBigEndian(UInt32(authorized.manifest.artifacts.count), to: &prefix)
            appendClosureBigEndian(UInt32(0), to: &prefix)
            appendClosureBigEndian(authorized.manifest.payloadByteLength, to: &prefix)
            prefix.append(try sdistClosureRawDigest(authorized.manifest.closureSHA256))
            prefix.append(authorized.expectedPayloadDigest)
            guard prefix.count == sdistBuildClosurePrefixBytesV1 else {
                throw SdistBuildClosureTransportError.writeFailed
            }
            try sendAll(prefix)
            try sendAll(authorized.manifest.canonicalJSON)
            let observation = try authorized.consumePayload { [self] _, _, chunk in
                try sendAll(chunk)
            }
            guard shutdown(descriptor, SHUT_WR) == 0 else {
                throw SdistBuildClosureTransportError.writeShutdownFailed
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
                throw SdistBuildClosureTransportError.writeFailed
            }
        }
    }
}

public func beginAuthorizedSdistBuildClosureSubmission(
    from handle: FileHandle,
    authorized: AuthorizedSdistRunSubmission,
    cancellation: SdistRunCancellationState? = nil
) throws -> AuthorizedSdistBuildClosureSubmission {
    guard authorized.authority.replayStatePersisted else {
        throw SdistBuildClosureTransportError.bindingMismatch
    }
    let prefix = try closureReadExactly(
        handle,
        count: sdistBuildClosurePrefixBytesV1,
        cancellation: cancellation
    )
    guard prefix.prefix(8) == sdistBuildClosureMagicV1 else {
        throw SdistBuildClosureTransportError.invalidMagic
    }
    guard closureUInt16(prefix, at: 8) == sdistBuildClosureVersionV1 else {
        throw SdistBuildClosureTransportError.unsupportedVersion
    }
    guard closureUInt16(prefix, at: 10) == sdistBuildClosureFrameTypeV1 else {
        throw SdistBuildClosureTransportError.unsupportedFrameType
    }
    let manifestLength = Int(closureUInt32(prefix, at: 12))
    let artifactCount = Int(closureUInt32(prefix, at: 16))
    guard prefix[20..<24].allSatisfy({ $0 == 0 }) else {
        throw SdistBuildClosureTransportError.invalidPrefix
    }
    let payloadLength = closureUInt64(prefix, at: 24)
    guard manifestLength > 0,
          manifestLength <= maximumSdistBuildClosureManifestBytesV1 else {
        throw SdistBuildClosureTransportError.manifestLimitExceeded
    }
    guard artifactCount <= maximumSdistBuildClosureArtifactsV1 else {
        throw SdistBuildClosureTransportError.artifactCountLimitExceeded
    }
    guard payloadLength <= maximumSdistBuildClosurePayloadBytesV1 else {
        throw SdistBuildClosureTransportError.payloadLimitExceeded
    }
    let manifest = authorized.prelude.buildClosure
    let closureDigest = Data(prefix[32..<64])
    let payloadDigest = Data(prefix[64..<96])
    let manifestBytes = try closureReadExactly(
        handle,
        count: manifestLength,
        cancellation: cancellation
    )
    let expectedClosureDigest = try sdistClosureRawDigest(manifest.closureSHA256)
    guard manifestBytes == manifest.canonicalJSON,
          closureDigest == expectedClosureDigest,
          artifactCount == manifest.artifacts.count,
          payloadLength == manifest.payloadByteLength else {
        throw SdistBuildClosureTransportError.bindingMismatch
    }
    return AuthorizedSdistBuildClosureSubmission(
        handle: handle,
        cancellation: cancellation,
        expectedPayloadDigest: payloadDigest,
        manifest: manifest
    )
}

private func closureReadExactly(
    _ handle: FileHandle,
    count: Int,
    cancellation: SdistRunCancellationState?
) throws -> Data {
    var result = Data()
    result.reserveCapacity(count)
    do {
        while result.count < count {
            try closureWaitUntilReadable(handle, cancellation: cancellation)
            let requested = min(64 * 1024, count - result.count)
            guard let chunk = try handle.read(upToCount: requested), !chunk.isEmpty else {
                throw SdistBuildClosureTransportError.truncated
            }
            result.append(chunk)
        }
    } catch let error as SdistBuildClosureTransportError {
        throw error
    } catch {
        try cancellation?.throwIfRequested()
        throw SdistBuildClosureTransportError.inputReadFailed
    }
    return result
}

private func closureWaitUntilReadable(
    _ handle: FileHandle,
    cancellation: SdistRunCancellationState?
) throws {
    guard let cancellation else { return }
    let descriptor = handle.fileDescriptor
    guard descriptor >= 0 else { throw SdistBuildClosureTransportError.inputReadFailed }
    while true {
        try cancellation.throwIfRequested()
        var item = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
        let result = Darwin.poll(&item, 1, 100)
        if result > 0 {
            try cancellation.throwIfRequested()
            guard item.revents & Int16(POLLNVAL) == 0 else {
                throw SdistBuildClosureTransportError.inputReadFailed
            }
            return
        }
        if result == 0 { continue }
        if errno == EINTR { continue }
        try cancellation.throwIfRequested()
        throw SdistBuildClosureTransportError.inputReadFailed
    }
}

private func closureUInt16(_ data: Data, at offset: Int) -> UInt16 {
    data[offset..<offset + 2].reduce(UInt16(0)) { ($0 << 8) | UInt16($1) }
}

private func closureUInt32(_ data: Data, at offset: Int) -> UInt32 {
    data[offset..<offset + 4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
}

private func closureUInt64(_ data: Data, at offset: Int) -> UInt64 {
    data[offset..<offset + 8].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
}

private func sdistClosureRawDigest(_ value: String) throws -> Data {
    guard value.utf8.count == 71, value.hasPrefix("sha256:") else {
        throw SdistBuildClosureTransportError.manifestInvalid
    }
    var output = Data()
    output.reserveCapacity(32)
    let hex = value.dropFirst(7)
    var index = hex.startIndex
    for _ in 0..<32 {
        let next = hex.index(index, offsetBy: 2)
        guard let byte = UInt8(hex[index..<next], radix: 16) else {
            throw SdistBuildClosureTransportError.manifestInvalid
        }
        output.append(byte)
        index = next
    }
    return output
}

private func sdistClosureDigestString(_ rawDigest: Data) -> String {
    "sha256:" + rawDigest.map { String(format: "%02x", $0) }.joined()
}

private func appendClosureBigEndian(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendClosureBigEndian(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func appendClosureBigEndian(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}
