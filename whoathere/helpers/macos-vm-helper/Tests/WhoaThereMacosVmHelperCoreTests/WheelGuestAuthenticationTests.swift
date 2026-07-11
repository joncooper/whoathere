import CryptoKit
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

let wheelAuthGoldenChallenge = Data(#"{"clone_binding_sha256":"sha256:29bea0252f37265b288224ebf9b5220fd7d9696fc64aa65f4d6322560182cb51","execution_binding_sha256":"sha256:26ba19f41ff9747505dcbc06292c2debb15a97fe8cb80f2a7625ceba0653356d","guest_auth_public_key_sha256":"sha256:fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889","nonce_hex":"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b","run_spec_sha256":"sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e","schema_version":"whoathere.wheel_guest_auth_challenge.v1"}"#.utf8)

let wheelAuthGoldenResponse = Data(#"{"challenge_sha256":"sha256:763b43adeed736fc4fe75497780a71f412e4ea13628f50b63e0448c44e1c6d41","clone_binding_sha256":"sha256:29bea0252f37265b288224ebf9b5220fd7d9696fc64aa65f4d6322560182cb51","execution_binding_sha256":"sha256:26ba19f41ff9747505dcbc06292c2debb15a97fe8cb80f2a7625ceba0653356d","guest_supervisor_sha256":"sha256:0d2f2274c6f58bd4cc5430838896cc59b5e5ed4840de084cea26af903f93276e","package_gid":"499","package_uid":"499","run_spec_sha256":"sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e","runner_configuration_sha256":"sha256:0e539a3c126c40c4efdfae8fb67ad5fb81f57660a4de665743586531faafc67b","schema_version":"whoathere.wheel_guest_auth_response.v1","signature_ed25519_hex":"deca32783d5e3774da376dad89cce630f9c9ddc69cf14abffcb921213e6fc9c2832f3d97c7b6d62062829f74843281aa8ebbe52f0876199871dcbd461dc6bb01"}"#.utf8)

@Test func rustWheelGuestAuthGoldenIsEncodedAndVerifiedBySwift() throws {
    let publicKey = try guestAuthTestPublicKey()
    let challenge = try decodeWheelGuestAuthChallenge(wheelAuthGoldenChallenge)
    #expect(challenge.guestAuthPublicKeySHA256 == sha256(publicKey))
    let prelude = goldenWheelAuthPrelude(publicKey: publicKey)

    let generated = try makeWheelGuestAuthChallenge(
        executionBindingSHA256: prelude.executionBindingSHA256,
        runSpecSHA256: prelude.runSpecSHA256,
        cloneBindingSHA256: challenge.cloneBindingSHA256,
        expectedPublicKeySHA256: prelude.backendIdentity.guestAuthPublicKeySHA256,
        guestAuthPublicKey: publicKey,
        nonce: Data(repeating: 11, count: 32)
    )
    #expect(generated.canonicalJSON == wheelAuthGoldenChallenge)

    let observation = try verifyWheelGuestAuthResponse(
        wheelAuthGoldenResponse,
        challenge: challenge,
        prelude: prelude,
        guestAuthPublicKey: publicKey
    )
    #expect(observation.signatureVerified)
    #expect(observation.challengeSHA256 == sha256(wheelAuthGoldenChallenge))
    #expect(observation.executionBindingSHA256 == prelude.executionBindingSHA256)
    #expect(observation.runSpecSHA256 == prelude.runSpecSHA256)
    #expect(observation.packageUID == 499)
    #expect(observation.packageGID == 499)
}

@Test func wheelGuestAuthRejectsNpmSchemaReplayTamperingAndWrongPublicKey() throws {
    let publicKey = try guestAuthTestPublicKey()
    let challenge = try decodeWheelGuestAuthChallenge(wheelAuthGoldenChallenge)
    let prelude = goldenWheelAuthPrelude(publicKey: publicKey)

    var npmSchema = try #require(
        JSONSerialization.jsonObject(with: wheelAuthGoldenChallenge) as? [String: Any]
    )
    npmSchema["schema_version"] = artifactGuestAuthChallengeSchemaV1
    #expect(throws: WheelGuestAuthenticationError.nonCanonical) {
        try decodeWheelGuestAuthChallenge(try canonicalJSONData(npmSchema))
    }

    let fresh = try makeWheelGuestAuthChallenge(
        executionBindingSHA256: prelude.executionBindingSHA256,
        runSpecSHA256: prelude.runSpecSHA256,
        cloneBindingSHA256: challenge.cloneBindingSHA256,
        expectedPublicKeySHA256: prelude.backendIdentity.guestAuthPublicKeySHA256,
        guestAuthPublicKey: publicKey,
        nonce: Data(repeating: 12, count: 32)
    )
    #expect(throws: WheelGuestAuthenticationError.invalidResponse) {
        try verifyWheelGuestAuthResponse(
            wheelAuthGoldenResponse,
            challenge: fresh,
            prelude: prelude,
            guestAuthPublicKey: publicKey
        )
    }

    var tampered = try #require(
        JSONSerialization.jsonObject(with: wheelAuthGoldenResponse) as? [String: Any]
    )
    var signature = try #require(tampered["signature_ed25519_hex"] as? String)
    signature.replaceSubrange(signature.index(before: signature.endIndex)..., with: "0")
    tampered["signature_ed25519_hex"] = signature
    #expect(throws: WheelGuestAuthenticationError.signatureFailed) {
        try verifyWheelGuestAuthResponse(
            try canonicalJSONData(tampered),
            challenge: challenge,
            prelude: prelude,
            guestAuthPublicKey: publicKey
        )
    }

    let otherKey = try Curve25519.Signing.PrivateKey(
        rawRepresentation: Data(repeating: 8, count: 32)
    ).publicKey.rawRepresentation
    #expect(throws: WheelGuestAuthenticationError.publicKeyMismatch) {
        try verifyWheelGuestAuthResponse(
            wheelAuthGoldenResponse,
            challenge: challenge,
            prelude: prelude,
            guestAuthPublicKey: otherKey
        )
    }
}

@Test func wheelCloneBindingChangesAcrossRunAndDiskIdentity() {
    let first = wheelCloneBindingSHA256(
        baseGenerationID: "wheel-base-v1",
        runID: "wheel-run-1",
        diskSHA256: sha256(Data("wheel disk 1".utf8)),
        auxiliaryStorageSHA256: sha256(Data("wheel aux".utf8))
    )
    let changedRun = wheelCloneBindingSHA256(
        baseGenerationID: "wheel-base-v1",
        runID: "wheel-run-2",
        diskSHA256: sha256(Data("wheel disk 1".utf8)),
        auxiliaryStorageSHA256: sha256(Data("wheel aux".utf8))
    )
    let changedDisk = wheelCloneBindingSHA256(
        baseGenerationID: "wheel-base-v1",
        runID: "wheel-run-1",
        diskSHA256: sha256(Data("wheel disk 2".utf8)),
        auxiliaryStorageSHA256: sha256(Data("wheel aux".utf8))
    )
    #expect(first != changedRun)
    #expect(first != changedDisk)
}

func goldenWheelAuthPrelude(publicKey: Data) -> WheelRunSubmissionPrelude {
    let backend = WheelRunBackendIdentity(
        baseGenerationID: "wheel-golden-base",
        baseDiskSHA256: sha256(Data("wheel base disk".utf8)),
        baseAuxiliaryStorageSHA256: sha256(Data("wheel base aux".utf8)),
        hardwareModelSHA256: sha256(Data("wheel hardware".utf8)),
        machineIdentifierSHA256: sha256(Data("wheel machine".utf8)),
        cpuCount: 4,
        memoryMiB: 6_144,
        postProvisioningReceiptSHA256: sha256(Data("wheel receipt".utf8)),
        helperSHA256: sha256(Data("wheel helper".utf8)),
        guestSupervisorSHA256: sha256(Data("wheel guest supervisor".utf8)),
        guestAuthPublicKeySHA256: sha256(publicKey),
        runnerConfigurationSHA256: sha256(Data("wheel runner configuration".utf8)),
        packageUsername: "_whoatherepkg",
        packageUID: 499,
        packageGID: 499,
        pythonVersion: "3.12.13",
        pythonExecutableSHA256: sha256(Data("wheel python".utf8)),
        pipVersion: "26.1.2",
        pipCLISHA256: sha256(Data("wheel pip".utf8)),
        cloneImplementationSHA256: sha256(Data("wheel clone".utf8)),
        guestProtocolSHA256: sha256(Data("whoathere.wheel_artifact_scenario.v1".utf8))
    )
    return WheelRunSubmissionPrelude(
        runSpecSHA256: sha256(Data("wheel run spec".utf8)),
        templateSHA256: sha256(Data("wheel template".utf8)),
        challengeBindingSHA256: sha256(Data("wheel challenge binding".utf8)),
        executionBindingSHA256: sha256(Data("wheel execution binding".utf8)),
        artifactSHA256: sha256(Data("wheel artifact".utf8)),
        artifactByteLength: 205,
        headerByteLength: 1,
        scenarioID: "wheel-golden-scenario",
        scenarioKind: "install_exact_wheel",
        backendIdentity: backend
    )
}
