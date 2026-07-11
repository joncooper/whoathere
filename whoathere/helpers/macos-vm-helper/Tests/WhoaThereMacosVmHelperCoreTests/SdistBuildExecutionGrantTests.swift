import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func sdistBuildExecutionGrantIsExactBoundAndZeroizesInputs() throws {
    var capability = Data(repeating: 0x42, count: 32)
    let capabilitySHA256 = sha256(capability)
    let runSpecSHA256 = sha256(Data("grant run spec".utf8))
    let executionInput = "whoathere.macos_sdist_submission_execution_binding.v1\0"
        + capabilitySHA256 + "\0" + runSpecSHA256
    let challenge = try makeSdistGuestAuthChallenge(
        executionBindingSHA256: sha256(Data(executionInput.utf8)),
        runSpecSHA256: runSpecSHA256,
        buildClosureSHA256: sha256(Data("grant closure".utf8)),
        cloneBindingSHA256: sha256(Data("grant clone".utf8)),
        expectedPublicKeySHA256: sha256(Data(repeating: 0x31, count: 32)),
        guestAuthPublicKey: Data(repeating: 0x31, count: 32),
        nonce: Data(repeating: 0x24, count: 32)
    )
    var observedBodySHA256: String?
    try withSdistBuildExecutionGrant(capability: &capability, challenge: challenge) { body in
        observedBodySHA256 = sha256(body)
        let object = try #require(
            JSONSerialization.jsonObject(with: body) as? [String: Any]
        )
        #expect(try canonicalJSONData(object) == body)
        #expect(Set(object.keys) == Set([
            "schema_version", "capability_hex", "challenge_sha256",
            "execution_binding_sha256", "run_spec_sha256", "build_closure_sha256",
            "clone_binding_sha256"
        ]))
        #expect(object["schema_version"] as? String == sdistBuildExecutionGrantSchemaV1)
        #expect(object["capability_hex"] as? String == String(repeating: "42", count: 32))
        #expect(object["challenge_sha256"] as? String == sha256(challenge.canonicalJSON))
        #expect(object["execution_binding_sha256"] as? String == challenge.executionBindingSHA256)
        #expect(object["run_spec_sha256"] as? String == challenge.runSpecSHA256)
        #expect(object["build_closure_sha256"] as? String == challenge.buildClosureSHA256)
        #expect(object["clone_binding_sha256"] as? String == challenge.cloneBindingSHA256)
    }
    #expect(
        observedBodySHA256
            == "sha256:c8539fc3e006ce3a6723213b6439e80372e335afa1ef332009a73550aad447e2"
    )
    #expect(capability == Data(repeating: 0, count: 32))

    var wrong = Data(repeating: 0x43, count: 32)
    #expect(throws: SdistBuildExecutionGrantError.bindingMismatch) {
        try withSdistBuildExecutionGrant(capability: &wrong, challenge: challenge) { _ in }
    }
    #expect(wrong == Data(repeating: 0, count: 32))

    var short = Data(repeating: 0x42, count: 31)
    #expect(throws: SdistBuildExecutionGrantError.invalidCapability) {
        try withSdistBuildExecutionGrant(capability: &short, challenge: challenge) { _ in }
    }
    #expect(short == Data(repeating: 0, count: 31))
}
