import Foundation

public let sdistBuildExecutionGrantSchemaV1 = "whoathere.sdist_build_execution_grant.v1"
public let maximumSdistBuildExecutionGrantBytesV1 = 16 * 1024

public enum SdistBuildExecutionGrantError: Error, Equatable, CustomStringConvertible {
    case invalidCapability
    case bindingMismatch
    case limitExceeded

    public var description: String {
        switch self {
        case .invalidCapability: return "sdist_build_execution_grant_capability_invalid"
        case .bindingMismatch: return "sdist_build_execution_grant_binding_mismatch"
        case .limitExceeded: return "sdist_build_execution_grant_limit_exceeded"
        }
    }
}

/// Builds the secret-bearing grant only for the duration of `bodySink`, then overwrites both the
/// caller's capability and this function's grant buffer. Production callers should write the body
/// directly as a `.buildExecutionGrant` control frame and must not retain a copy.
public func withSdistBuildExecutionGrant<T>(
    capability: inout Data,
    challenge: SdistGuestAuthChallenge,
    bodySink: (Data) throws -> T
) throws -> T {
    defer {
        capability.resetBytes(in: 0..<capability.count)
    }
    guard capability.count == 32 else {
        throw SdistBuildExecutionGrantError.invalidCapability
    }
    let capabilitySHA256 = sha256(capability)
    let executionInput = "whoathere.macos_sdist_submission_execution_binding.v1\0"
        + capabilitySHA256 + "\0" + challenge.runSpecSHA256
    guard sha256(Data(executionInput.utf8)) == challenge.executionBindingSHA256 else {
        throw SdistBuildExecutionGrantError.bindingMismatch
    }
    let bodyObject: [String: Any] = [
        "schema_version": sdistBuildExecutionGrantSchemaV1,
        "capability_hex": capability.map { String(format: "%02x", $0) }.joined(),
        "challenge_sha256": sha256(challenge.canonicalJSON),
        "execution_binding_sha256": challenge.executionBindingSHA256,
        "run_spec_sha256": challenge.runSpecSHA256,
        "build_closure_sha256": challenge.buildClosureSHA256,
        "clone_binding_sha256": challenge.cloneBindingSHA256
    ]
    var body = try canonicalJSONData(bodyObject)
    defer {
        body.resetBytes(in: 0..<body.count)
    }
    guard !body.isEmpty, body.count <= maximumSdistBuildExecutionGrantBytesV1 else {
        throw SdistBuildExecutionGrantError.limitExceeded
    }
    return try bodySink(body)
}
