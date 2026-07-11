import Foundation

public struct WheelGuestNonExecutingSessionObservation: Equatable, Sendable {
    public let authentication: WheelGuestAuthObservation
    public let transport: WheelRunTransportObservation
    public let stagingReceipt: WheelGuestStagingReceiptObservation
    public let packageExecutionEnabled: Bool
}

public func authenticateWheelGuestConnection(
    descriptor: Int32,
    prelude: WheelRunSubmissionPrelude,
    expectedChallengeBindingSHA256: String,
    cloneBindingSHA256: String,
    guestAuthPublicKey: Data,
    timeoutMillis: Int32 = 10_000
) throws -> WheelGuestAuthenticatedSession {
    guard prelude.challengeBindingSHA256 == expectedChallengeBindingSHA256 else {
        throw WheelGuestAuthenticationError.invalidChallenge
    }
    let challenge = try makeWheelGuestAuthChallenge(
        prelude: prelude,
        cloneBindingSHA256: cloneBindingSHA256,
        guestAuthPublicKey: guestAuthPublicKey
    )
    try writeWheelGuestControlFrame(
        descriptor: descriptor,
        frameType: .authenticationChallenge,
        body: challenge.canonicalJSON,
        timeoutMillis: timeoutMillis
    )
    let response = try readWheelGuestControlFrame(
        descriptor: descriptor,
        expectedType: .authenticationResponse,
        maximumBodyBytes: maximumWheelGuestAuthBytesV1,
        timeoutMillis: timeoutMillis
    )
    let observation = try verifyWheelGuestAuthResponse(
        response,
        challenge: challenge,
        prelude: prelude,
        guestAuthPublicKey: guestAuthPublicKey
    )
    return WheelGuestAuthenticatedSession(
        challenge: challenge,
        observation: observation
    )
}

public func receiveWheelGuestStagingReceipt(
    descriptor: Int32,
    authenticated: WheelGuestAuthenticatedSession,
    prelude: WheelRunSubmissionPrelude,
    transport: WheelRunTransportObservation,
    guestAuthPublicKey: Data,
    timeoutMillis: Int32 = 10_000
) throws -> WheelGuestStagingReceiptObservation {
    let body = try readWheelGuestControlFrame(
        descriptor: descriptor,
        expectedType: .stagingReceipt,
        maximumBodyBytes: maximumWheelGuestAuthBytesV1,
        timeoutMillis: timeoutMillis
    )
    let observation = try verifyWheelGuestStagingReceipt(
        body,
        authenticated: authenticated,
        prelude: prelude,
        transport: transport,
        guestAuthPublicKey: guestAuthPublicKey
    )
    try requireWheelGuestControlEOF(
        descriptor: descriptor,
        timeoutMillis: timeoutMillis
    )
    return observation
}

public func runNonExecutingWheelGuestSession(
    descriptor: Int32,
    reader: WheelRunSubmissionReader,
    expectedChallengeBindingSHA256: String,
    cloneBindingSHA256: String,
    guestAuthPublicKey: Data,
    timeoutMillis: Int32 = 10_000
) throws -> WheelGuestNonExecutingSessionObservation {
    let prelude = reader.prelude
    let authenticated = try authenticateWheelGuestConnection(
        descriptor: descriptor,
        prelude: prelude,
        expectedChallengeBindingSHA256: expectedChallengeBindingSHA256,
        cloneBindingSHA256: cloneBindingSHA256,
        guestAuthPublicKey: guestAuthPublicKey,
        timeoutMillis: timeoutMillis
    )
    let transport = try WheelGuestSubmissionForwarder(
        descriptor: descriptor,
        reader: reader
    ).forward()
    let receipt = try receiveWheelGuestStagingReceipt(
        descriptor: descriptor,
        authenticated: authenticated,
        prelude: prelude,
        transport: transport,
        guestAuthPublicKey: guestAuthPublicKey,
        timeoutMillis: timeoutMillis
    )
    return WheelGuestNonExecutingSessionObservation(
        authentication: authenticated.observation,
        transport: transport,
        stagingReceipt: receipt,
        packageExecutionEnabled: false
    )
}
