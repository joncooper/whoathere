import Darwin
import CryptoKit
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func authorizedSdistSubmissionBurnsAuthorityBeforeExposingExactBody() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"], scenarioIndex: 81
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authority = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID("1"), prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }

    let authorized = try beginAndAuthorizeSdistRunSubmission(
        from: sdistFileHandle(fixture.frame),
        authorityLayout: authority.layout,
        authorityID: authority.authorityID,
        expectedAuthorityRecordSHA256: authority.recordSHA256,
        nowUnixSeconds: authority.now
    )
    #expect(authorized.authority.replayStatePersisted)
    #expect(authorized.prelude.buildClosureSHA256 == fixture.buildClosureSHA256)
    #expect(authorizedSdistPathExists(authority.consumedURL.path))
    #expect(!authorizedSdistPathExists(authority.pendingURL.path))
    var exact = Data()
    let observation = try authorized.consumeArtifact { exact.append($0) }
    #expect(exact == fixture.artifact)
    #expect(observation.artifactSHA256 == fixture.artifactSHA256)
    #expect(throws: ArtifactRunProtocolError.trailingData) {
        try authorized.consumeArtifact()
    }
}

@Test func failedSdistAuthorizationBurnsAuthorityAndLeavesBodyUnread() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "inspect_derived_wheel"], scenarioIndex: 82
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authority = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID("2"),
        prelude: prelude,
        buildClosureSHA256: sha256(Data("rebound closure".utf8))
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }

    let pipe = Pipe()
    pipe.fileHandleForWriting.write(fixture.frame)
    try pipe.fileHandleForWriting.close()
    #expect(throws: SdistRunAuthorityError.bindingMismatch) {
        try beginAndAuthorizeSdistRunSubmission(
            from: pipe.fileHandleForReading,
            authorityLayout: authority.layout,
            authorityID: authority.authorityID,
            expectedAuthorityRecordSHA256: authority.recordSHA256,
            nowUnixSeconds: authority.now
        )
    }
    #expect(authorizedSdistPathExists(authority.consumedURL.path))

    // Only the prefix and header were consumed; the complete inert body remains available.
    let remaining = try pipe.fileHandleForReading.readToEnd() ?? Data()
    #expect(remaining == fixture.artifact)
}

@Test func authorizedSdistForwarderChangesOnlyGuestDomainAndClosesWriteSide() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"], scenarioIndex: 83
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authority = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID("3"), prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }
    let authorized = try beginAndAuthorizeSdistRunSubmission(
        from: sdistFileHandle(fixture.frame),
        authorityLayout: authority.layout,
        authorityID: authority.authorityID,
        expectedAuthorityRecordSHA256: authority.recordSHA256,
        nowUnixSeconds: authority.now
    )

    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let forwarder = try SdistGuestSubmissionForwarder(
        descriptor: sockets[0], authorized: authorized
    )
    let observation = try forwarder.forward()
    let received = try readAuthorizedSdistGuestToEOF(sockets[1])
    #expect(received.prefix(8) == sdistGuestSubmissionMagicV1)
    #expect(received.count == fixture.frame.count)
    #expect(received[8...] == fixture.frame[8...])
    #expect(observation.buildClosureSHA256 == fixture.buildClosureSHA256)
    #expect(observation.artifactSHA256 == fixture.artifactSHA256)
    #expect(throws: SdistGuestTransportError.writeFailed) {
        try forwarder.forward()
    }
}

@Test func sdistGuestAuthenticationIsClosureAndAuthorityBound() throws {
    let privateKey = Curve25519.Signing.PrivateKey()
    let publicKey = privateKey.publicKey.rawRepresentation
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"],
        scenarioIndex: 84,
        guestAuthPublicKeySHA256: sha256(publicKey)
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authority = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID("4"), prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }
    let authorized = try beginAndAuthorizeSdistRunSubmission(
        from: sdistFileHandle(fixture.frame),
        authorityLayout: authority.layout,
        authorityID: authority.authorityID,
        expectedAuthorityRecordSHA256: authority.recordSHA256,
        nowUnixSeconds: authority.now
    )
    let cloneBinding = sdistCloneBindingSHA256(
        baseGenerationID: prelude.backendIdentity.baseGenerationID,
        runID: "sdist-run-84",
        diskSHA256: prelude.backendIdentity.baseDiskSHA256,
        auxiliaryStorageSHA256: prelude.backendIdentity.baseAuxiliaryStorageSHA256
    )
    let challenge = try makeSdistGuestAuthChallenge(
        authorized: authorized,
        cloneBindingSHA256: cloneBinding,
        guestAuthPublicKey: publicKey
    )
    #expect(challenge.buildClosureSHA256 == fixture.buildClosureSHA256)
    let decoded = try decodeSdistGuestAuthChallenge(challenge.canonicalJSON)
    #expect(decoded == challenge)

    let unsigned: [String: Any] = [
        "schema_version": sdistGuestAuthResponseSchemaV1,
        "challenge_sha256": sha256(challenge.canonicalJSON),
        "execution_binding_sha256": challenge.executionBindingSHA256,
        "run_spec_sha256": challenge.runSpecSHA256,
        "build_closure_sha256": challenge.buildClosureSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "guest_supervisor_sha256": prelude.backendIdentity.guestSupervisorSHA256,
        "runner_configuration_sha256": prelude.backendIdentity.runnerConfigurationSHA256,
        "package_uid": String(prelude.backendIdentity.packageUID),
        "package_gid": String(prelude.backendIdentity.packageGID)
    ]
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data("whoathere.sdist_guest_auth.response_signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    var response = unsigned
    response["signature_ed25519_hex"] = try privateKey.signature(for: message).map {
        String(format: "%02x", $0)
    }.joined()
    let observation = try verifySdistGuestAuthResponse(
        canonicalJSONData(response),
        challenge: challenge,
        authorized: authorized,
        guestAuthPublicKey: publicKey
    )
    #expect(observation.signatureVerified)
    #expect(observation.buildClosureSHA256 == fixture.buildClosureSHA256)

    var forgedSignature = response
    forgedSignature["signature_ed25519_hex"] = String(repeating: "00", count: 64)
    #expect(throws: SdistGuestAuthenticationError.signatureFailed) {
        try verifySdistGuestAuthResponse(
            canonicalJSONData(forgedSignature),
            challenge: challenge,
            authorized: authorized,
            guestAuthPublicKey: publicKey
        )
    }
    #expect(throws: SdistGuestAuthenticationError.publicKeyMismatch) {
        try verifySdistGuestAuthResponse(
            canonicalJSONData(response),
            challenge: challenge,
            authorized: authorized,
            guestAuthPublicKey: Curve25519.Signing.PrivateKey().publicKey.rawRepresentation
        )
    }

    var rebound = response
    rebound["build_closure_sha256"] = sha256(Data("other closure".utf8))
    #expect(throws: SdistGuestAuthenticationError.invalidResponse) {
        try verifySdistGuestAuthResponse(
            canonicalJSONData(rebound),
            challenge: challenge,
            authorized: authorized,
            guestAuthPublicKey: publicKey
        )
    }
    var wheelChallenge = try #require(
        JSONSerialization.jsonObject(with: challenge.canonicalJSON) as? [String: Any]
    )
    wheelChallenge["schema_version"] = wheelGuestAuthChallengeSchemaV1
    #expect(throws: SdistGuestAuthenticationError.nonCanonical) {
        try decodeSdistGuestAuthChallenge(canonicalJSONData(wheelChallenge))
    }
}

@Test func sdistStagingReceiptProvesNoExecutionSyncOrClosureMaterialization() throws {
    let privateKey = Curve25519.Signing.PrivateKey()
    let publicKey = privateKey.publicKey.rawRepresentation
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "inspect_derived_wheel"],
        scenarioIndex: 85,
        guestAuthPublicKeySHA256: sha256(publicKey)
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authority = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID("5"), prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }
    let authorized = try beginAndAuthorizeSdistRunSubmission(
        from: sdistFileHandle(fixture.frame),
        authorityLayout: authority.layout,
        authorityID: authority.authorityID,
        expectedAuthorityRecordSHA256: authority.recordSHA256,
        nowUnixSeconds: authority.now
    )
    let challenge = try makeSdistGuestAuthChallenge(
        authorized: authorized,
        cloneBindingSHA256: sha256(Data("sdist clone".utf8)),
        guestAuthPublicKey: publicKey
    )
    let authObservation = SdistGuestAuthObservation(
        challengeSHA256: sha256(challenge.canonicalJSON),
        executionBindingSHA256: challenge.executionBindingSHA256,
        runSpecSHA256: challenge.runSpecSHA256,
        buildClosureSHA256: challenge.buildClosureSHA256,
        cloneBindingSHA256: challenge.cloneBindingSHA256,
        guestSupervisorSHA256: prelude.backendIdentity.guestSupervisorSHA256,
        runnerConfigurationSHA256: prelude.backendIdentity.runnerConfigurationSHA256,
        packageUID: prelude.backendIdentity.packageUID,
        packageGID: prelude.backendIdentity.packageGID,
        signatureVerified: true
    )
    let authenticated = SdistGuestAuthenticatedSession(
        challenge: challenge, observation: authObservation
    )
    let transport = try authorized.consumeArtifact()
    let unsigned: [String: Any] = [
        "schema_version": sdistGuestStagingReceiptSchemaV1,
        "status": "staged_no_execution_no_closure_materialization",
        "challenge_sha256": sha256(challenge.canonicalJSON),
        "execution_binding_sha256": challenge.executionBindingSHA256,
        "run_spec_sha256": challenge.runSpecSHA256,
        "build_closure_sha256": challenge.buildClosureSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "artifact_sha256": transport.artifactSHA256,
        "artifact_byte_length": String(transport.artifactByteLength),
        "first_rehash_sha256": transport.artifactSHA256,
        "first_rehash_byte_length": String(transport.artifactByteLength),
        "staged_device": "42",
        "staged_inode": "84",
        "artifact_file_name": "artifact.sdist",
        "artifact_file_mode": "0444",
        "staging_directory_mode": "0711",
        "package_uid": String(prelude.backendIdentity.packageUID),
        "package_gid": String(prelude.backendIdentity.packageGID),
        "package_execution_enabled": false,
        "sync_back_enabled": false,
        "build_closure_materialized": false
    ]
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data("whoathere.sdist_guest_staging_receipt.signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    var receipt = unsigned
    receipt["signature_ed25519_hex"] = try privateKey.signature(for: message).map {
        String(format: "%02x", $0)
    }.joined()
    let observation = try verifySdistGuestStagingReceipt(
        canonicalJSONData(receipt),
        authenticated: authenticated,
        authorized: authorized,
        transport: transport,
        guestAuthPublicKey: publicKey
    )
    #expect(observation.signatureVerified)
    #expect(!observation.packageExecutionEnabled)
    #expect(!observation.syncBackEnabled)
    #expect(!observation.buildClosureMaterialized)
    #expect(observation.buildClosureSHA256 == fixture.buildClosureSHA256)

    var unsafe = receipt
    unsafe["build_closure_materialized"] = true
    #expect(throws: SdistGuestAuthenticationError.invalidResponse) {
        try verifySdistGuestStagingReceipt(
            canonicalJSONData(unsafe),
            authenticated: authenticated,
            authorized: authorized,
            transport: transport,
            guestAuthPublicKey: publicKey
        )
    }
}

@Test func nonExecutingSdistSessionOrdersAuthorityAuthTransferReceiptAndEOF() throws {
    let privateKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 9, count: 32)
    )
    let publicKey = privateKey.publicKey.rawRepresentation
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "import_root", "module": "swift_sdist_fixture"],
        scenarioIndex: 86,
        guestAuthPublicKeySHA256: sha256(publicKey)
    )
    let prelude = try beginSdistSubmission(from: sdistFileHandle(fixture.frame)).prelude
    let authority = try authorizedSdistAuthorityFixture(
        authorityID: authorizedSdistAuthorityID("6"), prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }
    let authorized = try beginAndAuthorizeSdistRunSubmission(
        from: sdistFileHandle(fixture.frame),
        authorityLayout: authority.layout,
        authorityID: authority.authorityID,
        expectedAuthorityRecordSHA256: authority.recordSHA256,
        nowUnixSeconds: authority.now
    )
    let cloneBinding = sha256(Data("sdist session clone".utf8))
    let expectedBuildClosureSHA256 = fixture.buildClosureSHA256
    let expectedChallengeBindingSHA256 = fixture.challengeBindingSHA256

    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let resultBox = SdistSessionResultBox()
    let finished = DispatchSemaphore(value: 0)
    let guestDescriptor = sockets[1]
    DispatchQueue.global(qos: .userInitiated).async {
        do {
            let challengeData = try readSdistGuestControlFrame(
                descriptor: guestDescriptor,
                expectedType: .authenticationChallenge,
                maximumBodyBytes: maximumSdistGuestAuthBytesV1,
                timeoutMillis: 5_000
            )
            let challenge = try decodeSdistGuestAuthChallenge(challengeData)
            #expect(challenge.buildClosureSHA256 == expectedBuildClosureSHA256)
            #expect(challenge.cloneBindingSHA256 == cloneBinding)
            try writeSdistGuestControlFrame(
                descriptor: guestDescriptor,
                frameType: .authenticationResponse,
                body: try signedSdistSessionAuthResponse(
                    challenge: challenge,
                    prelude: prelude,
                    privateKey: privateKey
                ),
                timeoutMillis: 5_000
            )

            var guestFrame = try readSdistSessionToEOF(guestDescriptor)
            guard guestFrame.prefix(8) == sdistGuestSubmissionMagicV1 else {
                throw SdistGuestTransportError.writeFailed
            }
            guestFrame.replaceSubrange(0..<8, with: sdistSubmissionMagicV1)
            let transport = try inspectSdistSubmission(
                from: sdistFileHandle(guestFrame),
                expectedChallengeBindingSHA256: expectedChallengeBindingSHA256
            )
            try writeSdistGuestControlFrame(
                descriptor: guestDescriptor,
                frameType: .stagingReceipt,
                body: try signedSdistSessionStagingReceipt(
                    challenge: challenge,
                    prelude: prelude,
                    transport: transport,
                    privateKey: privateKey,
                    device: 321,
                    inode: 654
                ),
                timeoutMillis: 5_000
            )
            guard shutdown(guestDescriptor, SHUT_WR) == 0 else {
                throw SdistGuestControlError.ioFailed
            }
            resultBox.store(.success(()))
        } catch {
            resultBox.store(.failure(error))
        }
        finished.signal()
    }

    let observation = try runNonExecutingSdistGuestSession(
        descriptor: sockets[0],
        authorized: authorized,
        cloneBindingSHA256: cloneBinding,
        guestAuthPublicKey: publicKey,
        timeoutMillis: 5_000
    )
    #expect(observation.authentication.signatureVerified)
    #expect(observation.transport.artifactSHA256 == fixture.artifactSHA256)
    #expect(observation.transport.buildClosureSHA256 == fixture.buildClosureSHA256)
    #expect(observation.stagingReceipt.signatureVerified)
    #expect(observation.stagingReceipt.stagedDevice == 321)
    #expect(observation.stagingReceipt.stagedInode == 654)
    #expect(!observation.packageExecutionEnabled)
    #expect(!observation.syncBackEnabled)
    #expect(!observation.buildClosureMaterialized)
    #expect(finished.wait(timeout: .now() + 5) == .success)
    try resultBox.load()?.get()
}

struct AuthorizedSdistAuthorityFixture {
    let root: URL
    let layout: SdistRunAuthorityLayout
    let authorityID: String
    let pendingURL: URL
    let consumedURL: URL
    let recordSHA256: String
    let now: UInt64
}

func authorizedSdistAuthorityFixture(
    authorityID: String,
    prelude: SdistRunSubmissionPrelude,
    buildClosureSHA256: String? = nil
) throws -> AuthorizedSdistAuthorityFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-authorized-sdist-\(UUID().uuidString)", isDirectory: true
    )
    let state = root.appendingPathComponent("state", isDirectory: true)
    let layout = SdistRunAuthorityLayout(stateDirectory: state)
    for directory in [
        root, state, layout.rootDirectory, layout.pendingDirectory, layout.consumedDirectory
    ] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        guard chmod(directory.path, 0o700) == 0 else {
            throw SdistRunAuthorityError.layoutUnsafe
        }
    }
    let now: UInt64 = 2_000_000_000
    let record = try canonicalJSONData([
        "schema_version": sdistRunAuthoritySchemaV1,
        "authority_id": authorityID,
        "challenge_binding_sha256": prelude.challengeBindingSHA256,
        "run_spec_sha256": prelude.runSpecSHA256,
        "artifact_sha256": prelude.artifactSHA256,
        "build_closure_sha256": buildClosureSHA256 ?? prelude.buildClosureSHA256,
        "issued_at_unix_seconds": String(now - 10),
        "expires_at_unix_seconds": String(now + 120)
    ])
    let pendingURL = layout.pendingURL(authorityID: authorityID)
    try record.write(to: pendingURL)
    guard chmod(pendingURL.path, 0o600) == 0 else {
        throw SdistRunAuthorityError.authorityFileUnsafe
    }
    return AuthorizedSdistAuthorityFixture(
        root: root,
        layout: layout,
        authorityID: authorityID,
        pendingURL: pendingURL,
        consumedURL: layout.consumedURL(authorityID: authorityID),
        recordSHA256: sha256(record),
        now: now
    )
}

func authorizedSdistAuthorityID(_ digit: Character) -> String {
    "sdist-authority-" + String(repeating: String(digit), count: 64)
}

private func authorizedSdistPathExists(_ path: String) -> Bool {
    var status = stat()
    return lstat(path, &status) == 0
}

private func readAuthorizedSdistGuestToEOF(_ descriptor: Int32) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let count = recv(descriptor, &buffer, buffer.count, 0)
        if count == 0 { return result }
        guard count > 0 else {
            if errno == EINTR { continue }
            throw SdistGuestTransportError.writeFailed
        }
        result.append(contentsOf: buffer[0..<count])
    }
}

private final class SdistSessionResultBox: @unchecked Sendable {
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

private func signedSdistSessionAuthResponse(
    challenge: SdistGuestAuthChallenge,
    prelude: SdistRunSubmissionPrelude,
    privateKey: Curve25519.Signing.PrivateKey
) throws -> Data {
    let unsigned: [String: Any] = [
        "schema_version": sdistGuestAuthResponseSchemaV1,
        "challenge_sha256": sha256(challenge.canonicalJSON),
        "execution_binding_sha256": challenge.executionBindingSHA256,
        "run_spec_sha256": challenge.runSpecSHA256,
        "build_closure_sha256": challenge.buildClosureSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "guest_supervisor_sha256": prelude.backendIdentity.guestSupervisorSHA256,
        "runner_configuration_sha256": prelude.backendIdentity.runnerConfigurationSHA256,
        "package_uid": String(prelude.backendIdentity.packageUID),
        "package_gid": String(prelude.backendIdentity.packageGID)
    ]
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data("whoathere.sdist_guest_auth.response_signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    var response = unsigned
    response["signature_ed25519_hex"] = try privateKey.signature(for: message).map {
        String(format: "%02x", $0)
    }.joined()
    return try canonicalJSONData(response)
}

private func signedSdistSessionStagingReceipt(
    challenge: SdistGuestAuthChallenge,
    prelude: SdistRunSubmissionPrelude,
    transport: SdistRunTransportObservation,
    privateKey: Curve25519.Signing.PrivateKey,
    device: UInt64,
    inode: UInt64
) throws -> Data {
    let unsigned: [String: Any] = [
        "schema_version": sdistGuestStagingReceiptSchemaV1,
        "status": "staged_no_execution_no_closure_materialization",
        "challenge_sha256": sha256(challenge.canonicalJSON),
        "execution_binding_sha256": challenge.executionBindingSHA256,
        "run_spec_sha256": challenge.runSpecSHA256,
        "build_closure_sha256": challenge.buildClosureSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "artifact_sha256": transport.artifactSHA256,
        "artifact_byte_length": String(transport.artifactByteLength),
        "first_rehash_sha256": transport.artifactSHA256,
        "first_rehash_byte_length": String(transport.artifactByteLength),
        "staged_device": String(device),
        "staged_inode": String(inode),
        "artifact_file_name": "artifact.sdist",
        "artifact_file_mode": "0444",
        "staging_directory_mode": "0711",
        "package_uid": String(prelude.backendIdentity.packageUID),
        "package_gid": String(prelude.backendIdentity.packageGID),
        "package_execution_enabled": false,
        "sync_back_enabled": false,
        "build_closure_materialized": false
    ]
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data("whoathere.sdist_guest_staging_receipt.signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    var receipt = unsigned
    receipt["signature_ed25519_hex"] = try privateKey.signature(for: message).map {
        String(format: "%02x", $0)
    }.joined()
    return try canonicalJSONData(receipt)
}

private func readSdistSessionToEOF(_ descriptor: Int32) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let count = recv(descriptor, &buffer, buffer.count, 0)
        if count == 0 { return result }
        guard count > 0 else {
            if errno == EINTR { continue }
            throw SdistGuestControlError.ioFailed
        }
        result.append(contentsOf: buffer[0..<count])
    }
}
