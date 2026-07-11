import CryptoKit
import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func controlFramesAreTypedBoundedAndRequireExplicitFinalEOF() throws {
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let challenge = Data("{\"challenge\":\"inert\"}".utf8)
    try writeArtifactGuestControlFrame(
        descriptor: sockets[0],
        frameType: .authenticationChallenge,
        body: challenge,
        timeoutMillis: 1_000
    )
    #expect(
        try readArtifactGuestControlFrame(
            descriptor: sockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1024,
            timeoutMillis: 1_000
        ) == challenge
    )

    let response = Data("{\"response\":\"inert\"}".utf8)
    try writeArtifactGuestControlFrame(
        descriptor: sockets[1],
        frameType: .authenticationResponse,
        body: response,
        timeoutMillis: 1_000
    )
    #expect(
        try readArtifactGuestControlFrame(
            descriptor: sockets[0],
            expectedType: .authenticationResponse,
            maximumBodyBytes: 1024,
            timeoutMillis: 1_000
        ) == response
    )
    #expect(shutdown(sockets[1], SHUT_WR) == 0)
    try requireArtifactGuestControlEOF(descriptor: sockets[0], timeoutMillis: 1_000)
}

@Test func controlFramesRejectWrongTypeAndBoundIdleWaits() throws {
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    try writeArtifactGuestControlFrame(
        descriptor: sockets[0],
        frameType: .authenticationResponse,
        body: Data("{}".utf8),
        timeoutMillis: 1_000
    )
    #expect(throws: ArtifactGuestControlError.unexpectedFrameType) {
        try readArtifactGuestControlFrame(
            descriptor: sockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1024,
            timeoutMillis: 1_000
        )
    }
    #expect(throws: ArtifactGuestControlError.timeout) {
        try readArtifactGuestControlFrame(
            descriptor: sockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1024,
            timeoutMillis: 10
        )
    }
}

@Test func authenticatedConnectionCompletesBeforeAnyArtifactForwarding() throws {
    let fixture = try lifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let base = try verifyAndLockArtifactRunBase(
        layout: fixture.layout,
        identity: fixture.identity,
        helperURL: fixture.helperURL
    )
    let clone = try base.createDisposableClone()
    defer { try? clone.cleanup() }
    let prelude = ArtifactRunSubmissionPrelude(
        runSpecSHA256: sha256(Data("control run spec".utf8)),
        templateSHA256: sha256(Data("control template".utf8)),
        challengeBindingSHA256: sha256(Data("control challenge".utf8)),
        executionBindingSHA256: sha256(Data("control execution".utf8)),
        artifactSHA256: sha256(Data("control artifact".utf8)),
        artifactByteLength: 1,
        headerByteLength: 1,
        scenarioID: "control-scenario",
        environment: "ci_false",
        backendIdentity: fixture.identity
    )

    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let resultBox = GuestAuthResultBox()
    let finished = DispatchSemaphore(value: 0)
    let guestDescriptor = sockets[1]
    DispatchQueue.global(qos: .userInitiated).async {
        do {
            let challengeData = try readArtifactGuestControlFrame(
                descriptor: guestDescriptor,
                expectedType: .authenticationChallenge,
                maximumBodyBytes: maximumArtifactGuestAuthBytesV1,
                timeoutMillis: 1_000
            )
            let challenge = try decodeArtifactGuestAuthChallenge(challengeData)
            let response = try signedGuestAuthResponse(
                challenge: challenge,
                prelude: prelude
            )
            try writeArtifactGuestControlFrame(
                descriptor: guestDescriptor,
                frameType: .authenticationResponse,
                body: response,
                timeoutMillis: 1_000
            )
            resultBox.store(.success(()))
        } catch {
            resultBox.store(.failure(error))
        }
        finished.signal()
    }

    let authenticated = try authenticateArtifactGuestConnection(
        descriptor: sockets[0],
        prelude: prelude,
        base: base,
        clone: clone,
        timeoutMillis: 1_000
    )
    #expect(authenticated.observation.signatureVerified)
    #expect(
        authenticated.observation.cloneBindingSHA256
            == artifactCloneBindingSHA256(base: base, clone: clone)
    )
    #expect(finished.wait(timeout: .now() + 1) == .success)
    try resultBox.load()?.get()
}

@Test func nonExecutingSessionOrdersAuthenticationArtifactStagingReceiptAndEOF() throws {
    let fixture = try lifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let base = try verifyAndLockArtifactRunBase(
        layout: fixture.layout,
        identity: fixture.identity,
        helperURL: fixture.helperURL
    )
    let clone = try base.createDisposableClone()
    defer { try? clone.cleanup() }
    let submission = try artifactSubmissionFixture()
    let reader = try beginArtifactSubmission(from: sessionFileHandle(submission.frame))
    #expect(reader.prelude.backendIdentity == base.identity)

    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let resultBox = GuestAuthResultBox()
    let finished = DispatchSemaphore(value: 0)
    let guestDescriptor = sockets[1]
    let prelude = reader.prelude
    DispatchQueue.global(qos: .userInitiated).async {
        do {
            let challengeData = try readArtifactGuestControlFrame(
                descriptor: guestDescriptor,
                expectedType: .authenticationChallenge,
                maximumBodyBytes: maximumArtifactGuestAuthBytesV1,
                timeoutMillis: 1_000
            )
            let challenge = try decodeArtifactGuestAuthChallenge(challengeData)
            let authResponse = try signedGuestAuthResponse(
                challenge: challenge,
                prelude: prelude
            )
            try writeArtifactGuestControlFrame(
                descriptor: guestDescriptor,
                frameType: .authenticationResponse,
                body: authResponse,
                timeoutMillis: 1_000
            )

            var guestFrame = try readSessionToEOF(guestDescriptor)
            guard guestFrame.prefix(8) == artifactGuestSubmissionMagicV1 else {
                throw ArtifactGuestTransportError.writeFailed
            }
            guestFrame.replaceSubrange(0..<8, with: artifactSubmissionMagicV1)
            let transport = try inspectArtifactSubmission(
                from: sessionFileHandle(guestFrame)
            )
            let receipt = try signedGuestStagingReceipt(
                challenge: challenge,
                prelude: prelude,
                transport: transport,
                device: 123,
                inode: 456
            )
            try writeArtifactGuestControlFrame(
                descriptor: guestDescriptor,
                frameType: .stagingReceipt,
                body: receipt,
                timeoutMillis: 1_000
            )
            guard shutdown(guestDescriptor, SHUT_WR) == 0 else {
                throw ArtifactGuestControlError.ioFailed
            }
            resultBox.store(.success(()))
        } catch {
            resultBox.store(.failure(error))
        }
        finished.signal()
    }

    let observation = try runNonExecutingArtifactGuestSession(
        descriptor: sockets[0],
        reader: reader,
        base: base,
        clone: clone,
        timeoutMillis: 1_000
    )
    #expect(observation.authentication.signatureVerified)
    #expect(observation.transport.artifactSHA256 == submission.artifactSHA256)
    #expect(observation.stagingReceipt.signatureVerified)
    #expect(observation.stagingReceipt.stagedDevice == 123)
    #expect(observation.stagingReceipt.stagedInode == 456)
    #expect(observation.packageExecutionEnabled == false)
    #expect(finished.wait(timeout: .now() + 1) == .success)
    try resultBox.load()?.get()
}

private final class GuestAuthResultBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<Void, Error>?

    func store(_ value: Result<Void, Error>) {
        lock.lock()
        self.value = value
        lock.unlock()
    }

    func load() -> Result<Void, Error>? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

private func signedGuestStagingReceipt(
    challenge: ArtifactGuestAuthChallenge,
    prelude: ArtifactRunSubmissionPrelude,
    transport: ArtifactRunTransportObservation,
    device: UInt64,
    inode: UInt64
) throws -> Data {
    let unsigned: [String: Any] = [
        "schema_version": artifactGuestStagingReceiptSchemaV1,
        "status": "staged_no_execution",
        "challenge_sha256": sha256(challenge.canonicalJSON),
        "execution_binding_sha256": challenge.executionBindingSHA256,
        "run_spec_sha256": challenge.runSpecSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "artifact_sha256": transport.artifactSHA256,
        "artifact_byte_length": String(transport.artifactByteLength),
        "first_rehash_sha256": transport.artifactSHA256,
        "first_rehash_byte_length": String(transport.artifactByteLength),
        "staged_device": String(device),
        "staged_inode": String(inode),
        "artifact_file_mode": "0444",
        "staging_directory_mode": "0711",
        "package_uid": String(prelude.backendIdentity.packageUID),
        "package_gid": String(prelude.backendIdentity.packageGID),
        "package_execution_enabled": false
    ]
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data("whoathere.artifact_guest_staging_receipt.signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let key = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 7, count: 32)
    )
    let signature = try key.signature(for: message)
    var receipt = unsigned
    receipt["signature_ed25519_hex"] = signature.map {
        String(format: "%02x", $0)
    }.joined()
    return try canonicalJSONData(receipt)
}

private func readSessionToEOF(_ descriptor: Int32) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let count = recv(descriptor, &buffer, buffer.count, 0)
        if count == 0 { return result }
        guard count > 0 else {
            if errno == EINTR { continue }
            throw ArtifactGuestControlError.ioFailed
        }
        result.append(contentsOf: buffer[0..<count])
    }
}

private func sessionFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}
