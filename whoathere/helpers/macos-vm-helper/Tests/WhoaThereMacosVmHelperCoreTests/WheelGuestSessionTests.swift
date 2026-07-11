import CryptoKit
import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func nonExecutingWheelSessionOrdersAuthorityAuthTransferReceiptAndEOF() throws {
    let privateKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 7, count: 32)
    )
    let publicKey = privateKey.publicKey.rawRepresentation
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "import_root", "module": "wheel_fixture"],
        scenarioIndex: 51,
        guestAuthPublicKeySHA256: sha256(publicKey)
    )
    let expectedChallengeBindingSHA256 = fixture.challengeBindingSHA256
    let reader = try beginWheelSubmission(
        from: wheelSessionFileHandle(fixture.frame),
        expectedChallengeBindingSHA256: expectedChallengeBindingSHA256
    )
    let prelude = reader.prelude
    let cloneBinding = sha256(Data("wheel session clone".utf8))

    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let resultBox = WheelSessionResultBox()
    let finished = DispatchSemaphore(value: 0)
    let guestDescriptor = sockets[1]
    DispatchQueue.global(qos: .userInitiated).async {
        do {
            let challengeData = try readWheelGuestControlFrame(
                descriptor: guestDescriptor,
                expectedType: .authenticationChallenge,
                maximumBodyBytes: maximumWheelGuestAuthBytesV1,
                timeoutMillis: 5_000
            )
            let challenge = try decodeWheelGuestAuthChallenge(challengeData)
            #expect(challenge.cloneBindingSHA256 == cloneBinding)
            let authResponse = try signedWheelSessionAuthResponse(
                challenge: challenge,
                prelude: prelude,
                privateKey: privateKey
            )
            try writeWheelGuestControlFrame(
                descriptor: guestDescriptor,
                frameType: .authenticationResponse,
                body: authResponse,
                timeoutMillis: 5_000
            )

            var guestFrame = try readWheelSessionToEOF(guestDescriptor)
            guard guestFrame.prefix(8) == wheelGuestSubmissionMagicV1 else {
                throw WheelGuestTransportError.writeFailed
            }
            guestFrame.replaceSubrange(0..<8, with: wheelSubmissionMagicV1)
            let transport = try inspectWheelSubmission(
                from: wheelSessionFileHandle(guestFrame),
                expectedChallengeBindingSHA256: expectedChallengeBindingSHA256
            )
            let receipt = try signedWheelSessionStagingReceipt(
                challenge: challenge,
                prelude: prelude,
                transport: transport,
                privateKey: privateKey,
                device: 123,
                inode: 456
            )
            try writeWheelGuestControlFrame(
                descriptor: guestDescriptor,
                frameType: .stagingReceipt,
                body: receipt,
                timeoutMillis: 5_000
            )
            guard shutdown(guestDescriptor, SHUT_WR) == 0 else {
                throw WheelGuestControlError.ioFailed
            }
            resultBox.store(.success(()))
        } catch {
            resultBox.store(.failure(error))
        }
        finished.signal()
    }

    let observation = try runNonExecutingWheelGuestSession(
        descriptor: sockets[0],
        reader: reader,
        expectedChallengeBindingSHA256: expectedChallengeBindingSHA256,
        cloneBindingSHA256: cloneBinding,
        guestAuthPublicKey: publicKey,
        timeoutMillis: 5_000
    )
    #expect(observation.authentication.signatureVerified)
    #expect(observation.transport.artifactSHA256 == fixture.artifactSHA256)
    #expect(observation.transport.artifactByteLength == UInt64(fixture.artifact.count))
    #expect(observation.stagingReceipt.signatureVerified)
    #expect(observation.stagingReceipt.stagedDevice == 123)
    #expect(observation.stagingReceipt.stagedInode == 456)
    #expect(observation.packageExecutionEnabled == false)
    #expect(finished.wait(timeout: .now() + 5) == .success)
    try resultBox.load()?.get()
}

@Test func wheelSessionRejectsWrongPreissuedAuthorityBeforeAuthOrArtifactConsumption() throws {
    let privateKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 7, count: 32)
    )
    let publicKey = privateKey.publicKey.rawRepresentation
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "install_exact_wheel"],
        scenarioIndex: 52,
        guestAuthPublicKeySHA256: sha256(publicKey)
    )
    let reader = try beginWheelSubmission(
        from: wheelSessionFileHandle(fixture.frame),
        expectedChallengeBindingSHA256: fixture.challengeBindingSHA256
    )
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    #expect(throws: WheelGuestAuthenticationError.invalidChallenge) {
        try runNonExecutingWheelGuestSession(
            descriptor: sockets[0],
            reader: reader,
            expectedChallengeBindingSHA256: sha256(Data("wrong authority".utf8)),
            cloneBindingSHA256: sha256(Data("wheel session clone".utf8)),
            guestAuthPublicKey: publicKey,
            timeoutMillis: 100
        )
    }
    let transport = try reader.consumeArtifact()
    #expect(transport.artifactSHA256 == fixture.artifactSHA256)
}

private final class WheelSessionResultBox: @unchecked Sendable {
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

private func signedWheelSessionAuthResponse(
    challenge: WheelGuestAuthChallenge,
    prelude: WheelRunSubmissionPrelude,
    privateKey: Curve25519.Signing.PrivateKey
) throws -> Data {
    let unsigned: [String: Any] = [
        "schema_version": wheelGuestAuthResponseSchemaV1,
        "challenge_sha256": sha256(challenge.canonicalJSON),
        "execution_binding_sha256": challenge.executionBindingSHA256,
        "run_spec_sha256": challenge.runSpecSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256,
        "guest_supervisor_sha256": prelude.backendIdentity.guestSupervisorSHA256,
        "runner_configuration_sha256": prelude.backendIdentity.runnerConfigurationSHA256,
        "package_uid": String(prelude.backendIdentity.packageUID),
        "package_gid": String(prelude.backendIdentity.packageGID)
    ]
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data("whoathere.wheel_guest_auth.response_signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let signature = try privateKey.signature(for: message)
    var response = unsigned
    response["signature_ed25519_hex"] = signature.map {
        String(format: "%02x", $0)
    }.joined()
    return try canonicalJSONData(response)
}

private func signedWheelSessionStagingReceipt(
    challenge: WheelGuestAuthChallenge,
    prelude: WheelRunSubmissionPrelude,
    transport: WheelRunTransportObservation,
    privateKey: Curve25519.Signing.PrivateKey,
    device: UInt64,
    inode: UInt64
) throws -> Data {
    let unsigned: [String: Any] = [
        "schema_version": wheelGuestStagingReceiptSchemaV1,
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
        "artifact_file_name": "artifact.whl",
        "artifact_file_mode": "0444",
        "staging_directory_mode": "0711",
        "package_uid": String(prelude.backendIdentity.packageUID),
        "package_gid": String(prelude.backendIdentity.packageGID),
        "package_execution_enabled": false
    ]
    let unsignedData = try canonicalJSONData(unsigned)
    var message = Data("whoathere.wheel_guest_staging_receipt.signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let signature = try privateKey.signature(for: message)
    var receipt = unsigned
    receipt["signature_ed25519_hex"] = signature.map {
        String(format: "%02x", $0)
    }.joined()
    return try canonicalJSONData(receipt)
}

private func readWheelSessionToEOF(_ descriptor: Int32) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let count = recv(descriptor, &buffer, buffer.count, 0)
        if count == 0 { return result }
        guard count > 0 else {
            if errno == EINTR { continue }
            throw WheelGuestControlError.ioFailed
        }
        result.append(contentsOf: buffer[0..<count])
    }
}

private func wheelSessionFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}
