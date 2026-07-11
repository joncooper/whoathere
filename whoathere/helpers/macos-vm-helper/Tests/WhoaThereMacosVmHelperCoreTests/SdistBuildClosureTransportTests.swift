import CryptoKit
import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func authorizedSdistClosureChannelStreamsExactSeparatelyBoundedBytes() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: [
            "kind": "build_exact_sdist",
            "build_mode": "pep517",
            "build_backend": "setuptools.build_meta",
            "backend_paths": [String](),
            "build_requires_sha256": sha256(Data("setuptools>=75".utf8))
        ],
        scenarioIndex: 91,
        declarationSetSHA256: sha256(Data("setuptools>=75".utf8))
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authorityFixture = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID("9"),
        prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: authorityFixture.root) }
    let authorized = try beginAndAuthorizeSdistRunSubmission(
        from: sdistFileHandle(fixture.frame),
        authorityLayout: authorityFixture.layout,
        authorityID: authorityFixture.authorityID,
        expectedAuthorityRecordSHA256: authorityFixture.recordSHA256,
        nowUnixSeconds: authorityFixture.now
    )
    let payloads = [sdistBuildClosureArtifactBytes()]
    let frame = try sdistClosureFrame(
        manifest: authorized.prelude.buildClosure,
        payloads: payloads
    )
    let closure = try beginAuthorizedSdistBuildClosureSubmission(
        from: sdistFileHandle(frame),
        authorized: authorized
    )
    var observed = Data()
    let observation = try closure.consumePayload { index, artifact, chunk in
        #expect(index == 0)
        #expect(artifact.normalizedName == "setuptools")
        observed.append(chunk)
    }
    #expect(observed == payloads[0])
    #expect(observation.closureSHA256 == authorized.prelude.buildClosureSHA256)
    #expect(observation.payloadSHA256 == sha256(payloads[0]))
    #expect(observation.artifactCount == 1)
    #expect(observation.payloadByteLength == UInt64(payloads[0].count))
    #expect(throws: SdistBuildClosureTransportError.trailingData) {
        try closure.consumePayload()
    }
}

@Test func authorizedSdistClosureForwarderChangesOnlyGuestDomainAndCloses() throws {
    let (authorized, authorityFixture) = try authorizedClosureFixture(index: 93, digit: "7")
    defer { try? FileManager.default.removeItem(at: authorityFixture.root) }
    let frame = try sdistClosureFrame(
        manifest: authorized.prelude.buildClosure,
        payloads: [sdistBuildClosureArtifactBytes()]
    )
    let closure = try beginAuthorizedSdistBuildClosureSubmission(
        from: sdistFileHandle(frame),
        authorized: authorized
    )
    var descriptors = [Int32](repeating: -1, count: 2)
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0)
    defer {
        if descriptors[0] >= 0 { close(descriptors[0]) }
        if descriptors[1] >= 0 { close(descriptors[1]) }
    }
    let finished = DispatchSemaphore(value: 0)
    let result = SdistClosureForwardResult()
    let hostDescriptor = descriptors[0]
    let closureBox = SdistClosureUncheckedBox(value: closure)
    DispatchQueue.global(qos: .userInitiated).async {
        do {
            result.store(.success(try SdistGuestBuildClosureForwarder(
                descriptor: hostDescriptor,
                authorized: closureBox.value
            ).forward()))
        } catch {
            result.store(.failure(error))
        }
        finished.signal()
    }
    var guest = Data()
    var buffer = [UInt8](repeating: 0, count: 8 * 1024)
    while true {
        let count = Darwin.read(descriptors[1], &buffer, buffer.count)
        if count == 0 { break }
        #expect(count > 0)
        guest.append(contentsOf: buffer[0..<max(0, count)])
    }
    #expect(guest.prefix(8) == sdistGuestBuildClosureMagicV1)
    #expect(guest.dropFirst(8) == frame.dropFirst(8))
    #expect(finished.wait(timeout: .now() + .seconds(2)) == .success)
    _ = try result.load()?.get()
}

@Test func sdistClosureChannelRejectsCrossDomainMutationTrailingAndManifestRebinding() throws {
    let (authorized, authorityFixture) = try authorizedClosureFixture(index: 92, digit: "8")
    defer { try? FileManager.default.removeItem(at: authorityFixture.root) }
    let payloads = [sdistBuildClosureArtifactBytes()]
    let frame = try sdistClosureFrame(
        manifest: authorized.prelude.buildClosure,
        payloads: payloads
    )

    var guestDomain = frame
    guestDomain.replaceSubrange(0..<8, with: sdistGuestBuildClosureMagicV1)
    #expect(throws: SdistBuildClosureTransportError.invalidMagic) {
        _ = try beginAuthorizedSdistBuildClosureSubmission(
            from: sdistFileHandle(guestDomain),
            authorized: authorized
        )
    }

    var mutated = frame
    mutated[mutated.count - 1] ^= 1
    let mutatedReader = try beginAuthorizedSdistBuildClosureSubmission(
        from: sdistFileHandle(mutated),
        authorized: authorized
    )
    #expect(throws: SdistBuildClosureTransportError.artifactDigestMismatch) {
        try mutatedReader.consumePayload()
    }

    var trailing = frame
    trailing.append(0)
    let trailingReader = try beginAuthorizedSdistBuildClosureSubmission(
        from: sdistFileHandle(trailing),
        authorized: authorized
    )
    #expect(throws: SdistBuildClosureTransportError.trailingData) {
        try trailingReader.consumePayload()
    }

    var rebound = frame
    rebound[32] ^= 1
    #expect(throws: SdistBuildClosureTransportError.bindingMismatch) {
        _ = try beginAuthorizedSdistBuildClosureSubmission(
            from: sdistFileHandle(rebound),
            authorized: authorized
        )
    }
}

private func authorizedClosureFixture(
    index: Int,
    digit: Character
) throws -> (AuthorizedSdistRunSubmission, AuthorizedSdistAuthorityFixture) {
    let declaration = sha256(Data("setuptools>=75".utf8))
    let fixture = try sdistSubmissionFixture(
        scenario: [
            "kind": "build_exact_sdist",
            "build_mode": "pep517",
            "build_backend": "setuptools.build_meta",
            "backend_paths": [String](),
            "build_requires_sha256": declaration
        ],
        scenarioIndex: index,
        declarationSetSHA256: declaration
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authorityFixture = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID(digit),
        prelude: prelude
    )
    let authorized = try beginAndAuthorizeSdistRunSubmission(
        from: sdistFileHandle(fixture.frame),
        authorityLayout: authorityFixture.layout,
        authorityID: authorityFixture.authorityID,
        expectedAuthorityRecordSHA256: authorityFixture.recordSHA256,
        nowUnixSeconds: authorityFixture.now
    )
    return (authorized, authorityFixture)
}

func sdistClosureFrame(
    manifest: SdistBuildClosureManifest,
    payloads: [Data]
) throws -> Data {
    #expect(payloads.count == manifest.artifacts.count)
    let payload = payloads.reduce(into: Data()) { $0.append($1) }
    var prefix = Data()
    prefix.append(sdistBuildClosureMagicV1)
    appendClosureInteger(sdistBuildClosureVersionV1, to: &prefix)
    appendClosureInteger(sdistBuildClosureFrameTypeV1, to: &prefix)
    appendClosureInteger(UInt32(manifest.canonicalJSON.count), to: &prefix)
    appendClosureInteger(UInt32(payloads.count), to: &prefix)
    appendClosureInteger(UInt32(0), to: &prefix)
    appendClosureInteger(UInt64(payload.count), to: &prefix)
    prefix.append(try rawClosureDigest(manifest.closureSHA256))
    prefix.append(Data(SHA256.hash(data: payload)))
    #expect(prefix.count == sdistBuildClosurePrefixBytesV1)
    var frame = prefix
    frame.append(manifest.canonicalJSON)
    frame.append(payload)
    return frame
}

private func rawClosureDigest(_ digest: String) throws -> Data {
    let hex = digest.dropFirst(7)
    var output = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        output.append(try #require(UInt8(hex[index..<next], radix: 16)))
        index = next
    }
    return output
}

private func appendClosureInteger(_ value: UInt16, to data: inout Data) {
    data.append(UInt8((value >> 8) & 0xff))
    data.append(UInt8(value & 0xff))
}

private func appendClosureInteger(_ value: UInt32, to data: inout Data) {
    for shift in stride(from: 24, through: 0, by: -8) {
        data.append(UInt8((value >> UInt32(shift)) & 0xff))
    }
}

private func appendClosureInteger(_ value: UInt64, to data: inout Data) {
    for shift in stride(from: 56, through: 0, by: -8) {
        data.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

private final class SdistClosureForwardResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<SdistBuildClosureTransportObservation, Error>?

    func store(_ value: Result<SdistBuildClosureTransportObservation, Error>) {
        lock.lock()
        self.value = value
        lock.unlock()
    }

    func load() -> Result<SdistBuildClosureTransportObservation, Error>? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private struct SdistClosureUncheckedBox<Value>: @unchecked Sendable {
    let value: Value
}
