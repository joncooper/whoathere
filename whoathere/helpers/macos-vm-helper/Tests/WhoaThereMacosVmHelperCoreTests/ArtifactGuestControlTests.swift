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
