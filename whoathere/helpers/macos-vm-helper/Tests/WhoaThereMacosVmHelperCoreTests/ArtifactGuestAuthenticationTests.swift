import CryptoKit
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func guestAuthenticationVerifiesFreshEd25519SignedMeasuredClaims() throws {
    let fixture = try artifactSubmissionFixture()
    let prelude = try beginArtifactSubmission(
        from: guestAuthFileHandle(fixture.frame)
    ).prelude
    let publicKey = try guestAuthTestPublicKey()
    let cloneBinding = sha256(Data("clone binding".utf8))
    let challenge = try makeArtifactGuestAuthChallenge(
        executionBindingSHA256: prelude.executionBindingSHA256,
        runSpecSHA256: prelude.runSpecSHA256,
        cloneBindingSHA256: cloneBinding,
        expectedPublicKeySHA256: prelude.backendIdentity.guestAuthPublicKeySHA256,
        guestAuthPublicKey: publicKey,
        nonce: Data(repeating: 9, count: 32)
    )
    #expect(try decodeArtifactGuestAuthChallenge(challenge.canonicalJSON) == challenge)

    let response = try signedGuestAuthResponse(challenge: challenge, prelude: prelude)
    let observation = try verifyArtifactGuestAuthResponse(
        response,
        challenge: challenge,
        prelude: prelude,
        guestAuthPublicKey: publicKey
    )
    #expect(observation.signatureVerified)
    #expect(observation.cloneBindingSHA256 == cloneBinding)
    #expect(observation.packageUID == 502)
    #expect(observation.packageGID == 502)

    let fresh = try makeArtifactGuestAuthChallenge(
        executionBindingSHA256: prelude.executionBindingSHA256,
        runSpecSHA256: prelude.runSpecSHA256,
        cloneBindingSHA256: cloneBinding,
        expectedPublicKeySHA256: prelude.backendIdentity.guestAuthPublicKeySHA256,
        guestAuthPublicKey: publicKey,
        nonce: Data(repeating: 10, count: 32)
    )
    #expect(throws: ArtifactGuestAuthenticationError.invalidResponse) {
        try verifyArtifactGuestAuthResponse(
            response,
            challenge: fresh,
            prelude: prelude,
            guestAuthPublicKey: publicKey
        )
    }

    var badSignature = try JSONSerialization.jsonObject(with: response) as! [String: Any]
    var signature = badSignature["signature_ed25519_hex"] as! String
    let last = signature.last == "0" ? "1" : "0"
    signature.replaceSubrange(signature.index(before: signature.endIndex)..., with: last)
    badSignature["signature_ed25519_hex"] = signature
    let badSignatureData = try canonicalJSONData(badSignature)
    #expect(throws: ArtifactGuestAuthenticationError.signatureFailed) {
        try verifyArtifactGuestAuthResponse(
            badSignatureData,
            challenge: challenge,
            prelude: prelude,
            guestAuthPublicKey: publicKey
        )
    }

    var noncanonical = Data(" ".utf8)
    noncanonical.append(challenge.canonicalJSON)
    #expect(throws: ArtifactGuestAuthenticationError.nonCanonical) {
        try decodeArtifactGuestAuthChallenge(noncanonical)
    }
}

@Test func cloneAuthenticationBindingChangesForEveryDisposableClone() throws {
    let fixture = try lifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let base = try verifyAndLockArtifactRunBase(
        layout: fixture.layout,
        identity: fixture.identity,
        helperURL: fixture.helperURL
    )
    let first = try base.createDisposableClone()
    let second = try base.createDisposableClone()
    let firstBinding = artifactCloneBindingSHA256(base: base, clone: first)
    let secondBinding = artifactCloneBindingSHA256(base: base, clone: second)
    #expect(firstBinding != secondBinding)
    try first.cleanup()
    try second.cleanup()
}

@Test func rustGuestAuthGoldenResponseVerifiesInSwift() throws {
    let challengeData = Data(#"{"clone_binding_sha256":"sha256:92514cfc03f94cbbc544178a0e7b999522b708efd7db40bd0c3d3796f9515564","execution_binding_sha256":"sha256:0adeabc9b469d31f8f4074566c3aec953f83419cc5700ece10e2c6c63272daf2","guest_auth_public_key_sha256":"sha256:fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889","nonce_hex":"0909090909090909090909090909090909090909090909090909090909090909","run_spec_sha256":"sha256:3626162ee4f7e66251d3d4fd61e2414e2153f65311611ebb72efc42565984fa3","schema_version":"whoathere.artifact_guest_auth_challenge.v1"}"#.utf8)
    let responseData = Data(#"{"challenge_sha256":"sha256:c5d93c1b625d9725401bbb47a3914fc65c54e74969e4c3031e2ac2565ee372cc","clone_binding_sha256":"sha256:92514cfc03f94cbbc544178a0e7b999522b708efd7db40bd0c3d3796f9515564","execution_binding_sha256":"sha256:0adeabc9b469d31f8f4074566c3aec953f83419cc5700ece10e2c6c63272daf2","guest_supervisor_sha256":"sha256:2c70f775aa20c6807b3fa4c5a05c8f5ab466d7c0c4e588280cd7ccbead6ae3a3","package_gid":"502","package_uid":"502","run_spec_sha256":"sha256:3626162ee4f7e66251d3d4fd61e2414e2153f65311611ebb72efc42565984fa3","runner_configuration_sha256":"sha256:153857d8963121612c0fff30058d06703606855e9bc96a83e45964ce0586dca3","schema_version":"whoathere.artifact_guest_auth_response.v1","signature_ed25519_hex":"e4096174087ef60f64ebf9ccadfaa2c13e214a9bfe391b8b8bac85f86f443e5e408fdff74cbb17c9672d895d7ef43446e710611c31415e9be4dc811c34e69709"}"#.utf8)
    let challenge = try decodeArtifactGuestAuthChallenge(challengeData)
    let publicKey = try guestAuthTestPublicKey()
    #expect(sha256(publicKey) == challenge.guestAuthPublicKeySHA256)
    let backend = ArtifactRunBackendIdentity(
        baseGenerationID: "golden-base",
        baseDiskSHA256: sha256(Data("disk".utf8)),
        baseAuxiliaryStorageSHA256: sha256(Data("aux".utf8)),
        hardwareModelSHA256: sha256(Data("hardware".utf8)),
        machineIdentifierSHA256: sha256(Data("machine".utf8)),
        cpuCount: 4,
        memoryMiB: 6_144,
        postProvisioningReceiptSHA256: sha256(Data("receipt".utf8)),
        helperSHA256: sha256(Data("helper".utf8)),
        guestSupervisorSHA256: sha256(Data("guest supervisor".utf8)),
        guestAuthPublicKeySHA256: sha256(publicKey),
        runnerConfigurationSHA256: sha256(Data("runner configuration".utf8)),
        packageUID: 502,
        packageGID: 502,
        nodeVersion: "22.17.0",
        nodeExecutableSHA256: sha256(Data("node".utf8)),
        npmVersion: "11.18.0",
        npmCLISHA256: sha256(Data("npm".utf8)),
        cloneImplementationSHA256: sha256(Data("clone".utf8)),
        guestProtocolSHA256: sha256(Data("whoathere.artifact_scenario.v1".utf8))
    )
    let prelude = ArtifactRunSubmissionPrelude(
        runSpecSHA256: challenge.runSpecSHA256,
        templateSHA256: sha256(Data("template".utf8)),
        challengeBindingSHA256: sha256(Data("challenge binding".utf8)),
        executionBindingSHA256: challenge.executionBindingSHA256,
        artifactSHA256: sha256(Data("artifact".utf8)),
        artifactByteLength: 1,
        headerByteLength: 1,
        scenarioID: "golden-scenario",
        environment: "ci_false",
        backendIdentity: backend
    )
    let observation = try verifyArtifactGuestAuthResponse(
        responseData,
        challenge: challenge,
        prelude: prelude,
        guestAuthPublicKey: publicKey
    )
    #expect(observation.signatureVerified)
}

func signedGuestAuthResponse(
    challenge: ArtifactGuestAuthChallenge,
    prelude: ArtifactRunSubmissionPrelude
) throws -> Data {
    let unsigned: [String: Any] = [
        "schema_version": artifactGuestAuthResponseSchemaV1,
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
    var message = Data("whoathere.artifact_guest_auth.response_signature.v1\0".utf8)
    message.append(challenge.canonicalJSON)
    message.append(0)
    message.append(unsignedData)
    let privateKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 7, count: 32)
    )
    let signature = try privateKey.signature(for: message)
    var response = unsigned
    response["signature_ed25519_hex"] = signature.map {
        String(format: "%02x", $0)
    }.joined()
    return try canonicalJSONData(response)
}

private func guestAuthFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}
