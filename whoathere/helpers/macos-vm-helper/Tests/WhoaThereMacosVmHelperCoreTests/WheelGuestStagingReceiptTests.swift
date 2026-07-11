import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let wheelStagingReceiptGolden = Data(#"{"artifact_byte_length":"205","artifact_file_mode":"0444","artifact_file_name":"artifact.whl","artifact_sha256":"sha256:b0d81135ac556bd1bd195274005aed8ae034601b9393d1900347076a4e8928b1","challenge_sha256":"sha256:763b43adeed736fc4fe75497780a71f412e4ea13628f50b63e0448c44e1c6d41","clone_binding_sha256":"sha256:29bea0252f37265b288224ebf9b5220fd7d9696fc64aa65f4d6322560182cb51","execution_binding_sha256":"sha256:26ba19f41ff9747505dcbc06292c2debb15a97fe8cb80f2a7625ceba0653356d","first_rehash_byte_length":"205","first_rehash_sha256":"sha256:b0d81135ac556bd1bd195274005aed8ae034601b9393d1900347076a4e8928b1","package_execution_enabled":false,"package_gid":"499","package_uid":"499","run_spec_sha256":"sha256:6ed9490f306948340b695150470fee00b434f28442914867c0750b067abf228e","schema_version":"whoathere.wheel_guest_staging_receipt.v1","signature_ed25519_hex":"4a5e8648d3d1757c69af3c66bfc6bfdd50ac12af8bbe3cc59219a0810f224e14836e5836d7f33830594d7d777125ef2e67cde9019790635be978868fa51fdf04","staged_device":"123","staged_inode":"456","staging_directory_mode":"0711","status":"staged_no_execution"}"#.utf8)

@Test func rustWheelStagingReceiptGoldenVerifiesInSwift() throws {
    let publicKey = try guestAuthTestPublicKey()
    let prelude = goldenWheelAuthPrelude(publicKey: publicKey)
    let challenge = try decodeWheelGuestAuthChallenge(wheelAuthGoldenChallenge)
    let authObservation = try verifyWheelGuestAuthResponse(
        wheelAuthGoldenResponse,
        challenge: challenge,
        prelude: prelude,
        guestAuthPublicKey: publicKey
    )
    let authenticated = WheelGuestAuthenticatedSession(
        challenge: challenge,
        observation: authObservation
    )
    let transport = goldenWheelTransport(prelude: prelude)
    let receipt = try verifyWheelGuestStagingReceipt(
        wheelStagingReceiptGolden,
        authenticated: authenticated,
        prelude: prelude,
        transport: transport,
        guestAuthPublicKey: publicKey
    )
    #expect(receipt.signatureVerified)
    #expect(receipt.artifactSHA256 == prelude.artifactSHA256)
    #expect(receipt.artifactByteLength == 205)
    #expect(receipt.firstRehashSHA256 == prelude.artifactSHA256)
    #expect(receipt.stagedDevice == 123)
    #expect(receipt.stagedInode == 456)
    #expect(receipt.packageUID == 499)
    #expect(receipt.packageGID == 499)
    #expect(receipt.packageExecutionEnabled == false)
}

@Test func wheelStagingReceiptRejectsExecutionWrongFileInodeAndSignature() throws {
    let publicKey = try guestAuthTestPublicKey()
    let prelude = goldenWheelAuthPrelude(publicKey: publicKey)
    let challenge = try decodeWheelGuestAuthChallenge(wheelAuthGoldenChallenge)
    let authObservation = try verifyWheelGuestAuthResponse(
        wheelAuthGoldenResponse,
        challenge: challenge,
        prelude: prelude,
        guestAuthPublicKey: publicKey
    )
    let authenticated = WheelGuestAuthenticatedSession(
        challenge: challenge,
        observation: authObservation
    )
    let transport = goldenWheelTransport(prelude: prelude)

    for (key, value): (String, Any) in [
        ("package_execution_enabled", true),
        ("artifact_file_name", "artifact.tgz")
    ] {
        var changed = try #require(
            JSONSerialization.jsonObject(with: wheelStagingReceiptGolden) as? [String: Any]
        )
        changed[key] = value
        #expect(throws: WheelGuestAuthenticationError.invalidResponse) {
            try verifyWheelGuestStagingReceipt(
                try canonicalJSONData(changed),
                authenticated: authenticated,
                prelude: prelude,
                transport: transport,
                guestAuthPublicKey: publicKey
            )
        }
    }

    var changedInode = try #require(
        JSONSerialization.jsonObject(with: wheelStagingReceiptGolden) as? [String: Any]
    )
    changedInode["staged_inode"] = "457"
    #expect(throws: WheelGuestAuthenticationError.signatureFailed) {
        try verifyWheelGuestStagingReceipt(
            try canonicalJSONData(changedInode),
            authenticated: authenticated,
            prelude: prelude,
            transport: transport,
            guestAuthPublicKey: publicKey
        )
    }

    var badSignature = try #require(
        JSONSerialization.jsonObject(with: wheelStagingReceiptGolden) as? [String: Any]
    )
    var signature = try #require(badSignature["signature_ed25519_hex"] as? String)
    signature.replaceSubrange(signature.index(before: signature.endIndex)..., with: "0")
    badSignature["signature_ed25519_hex"] = signature
    #expect(throws: WheelGuestAuthenticationError.signatureFailed) {
        try verifyWheelGuestStagingReceipt(
            try canonicalJSONData(badSignature),
            authenticated: authenticated,
            prelude: prelude,
            transport: transport,
            guestAuthPublicKey: publicKey
        )
    }
}

private func goldenWheelTransport(
    prelude: WheelRunSubmissionPrelude
) -> WheelRunTransportObservation {
    WheelRunTransportObservation(
        runSpecSHA256: prelude.runSpecSHA256,
        templateSHA256: prelude.templateSHA256,
        challengeBindingSHA256: prelude.challengeBindingSHA256,
        executionBindingSHA256: prelude.executionBindingSHA256,
        artifactSHA256: prelude.artifactSHA256,
        artifactByteLength: prelude.artifactByteLength,
        headerByteLength: prelude.headerByteLength,
        scenarioID: prelude.scenarioID,
        scenarioKind: prelude.scenarioKind,
        backendIdentity: prelude.backendIdentity
    )
}
