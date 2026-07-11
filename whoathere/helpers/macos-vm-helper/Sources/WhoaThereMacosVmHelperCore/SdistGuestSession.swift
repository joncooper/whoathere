import Foundation

public struct SdistGuestNonExecutingSessionObservation: Equatable, Sendable {
    public let authentication: SdistGuestAuthObservation
    public let transport: SdistRunTransportObservation
    public let closureTransport: SdistBuildClosureTransportObservation
    public let stagingReceipt: SdistGuestStagingReceiptObservation
    public let packageExecutionEnabled: Bool
    public let syncBackEnabled: Bool
    public let buildClosureMaterialized: Bool
}

public func authenticateSdistGuestConnection(
    descriptor: Int32,
    authorized: AuthorizedSdistRunSubmission,
    cloneBindingSHA256: String,
    guestAuthPublicKey: Data,
    timeoutMillis: Int32 = 10_000
) throws -> SdistGuestAuthenticatedSession {
    let challenge = try makeSdistGuestAuthChallenge(
        authorized: authorized,
        cloneBindingSHA256: cloneBindingSHA256,
        guestAuthPublicKey: guestAuthPublicKey
    )
    try writeSdistGuestControlFrame(
        descriptor: descriptor,
        frameType: .authenticationChallenge,
        body: challenge.canonicalJSON,
        timeoutMillis: timeoutMillis
    )
    let response = try readSdistGuestControlFrame(
        descriptor: descriptor,
        expectedType: .authenticationResponse,
        maximumBodyBytes: maximumSdistGuestAuthBytesV1,
        timeoutMillis: timeoutMillis
    )
    let observation = try verifySdistGuestAuthResponse(
        response,
        challenge: challenge,
        authorized: authorized,
        guestAuthPublicKey: guestAuthPublicKey
    )
    return SdistGuestAuthenticatedSession(
        challenge: challenge,
        observation: observation
    )
}

public func receiveSdistGuestStagingReceipt(
    descriptor: Int32,
    authenticated: SdistGuestAuthenticatedSession,
    authorized: AuthorizedSdistRunSubmission,
    transport: SdistRunTransportObservation,
    closureTransport: SdistBuildClosureTransportObservation,
    guestAuthPublicKey: Data,
    timeoutMillis: Int32 = 10_000
) throws -> SdistGuestStagingReceiptObservation {
    let body = try readSdistGuestControlFrame(
        descriptor: descriptor,
        expectedType: .stagingReceipt,
        maximumBodyBytes: maximumSdistGuestAuthBytesV1,
        timeoutMillis: timeoutMillis
    )
    let observation = try verifySdistGuestStagingReceipt(
        body,
        authenticated: authenticated,
        authorized: authorized,
        transport: transport,
        closureTransport: closureTransport,
        guestAuthPublicKey: guestAuthPublicKey
    )
    try requireSdistGuestControlEOF(
        descriptor: descriptor,
        timeoutMillis: timeoutMillis
    )
    return observation
}

/// Runs the complete authenticated sdist staging protocol without materializing the build closure
/// and without enabling package execution or sync-back.
public func runNonExecutingSdistGuestSession(
    descriptor: Int32,
    authorized: AuthorizedSdistRunSubmission,
    closure: AuthorizedSdistBuildClosureSubmission,
    cloneBindingSHA256: String,
    guestAuthPublicKey: Data,
    timeoutMillis: Int32 = 10_000
) throws -> SdistGuestNonExecutingSessionObservation {
    let authenticated = try authenticateSdistGuestConnection(
        descriptor: descriptor,
        authorized: authorized,
        cloneBindingSHA256: cloneBindingSHA256,
        guestAuthPublicKey: guestAuthPublicKey,
        timeoutMillis: timeoutMillis
    )
    let transport = try SdistGuestSubmissionForwarder(
        descriptor: descriptor,
        authorized: authorized
    ).forward(shutdownWriteSide: false)
    let closureTransport = try SdistGuestBuildClosureForwarder(
        descriptor: descriptor,
        authorized: closure
    ).forward()
    let receipt = try receiveSdistGuestStagingReceipt(
        descriptor: descriptor,
        authenticated: authenticated,
        authorized: authorized,
        transport: transport,
        closureTransport: closureTransport,
        guestAuthPublicKey: guestAuthPublicKey,
        timeoutMillis: timeoutMillis
    )
    return SdistGuestNonExecutingSessionObservation(
        authentication: authenticated.observation,
        transport: transport,
        closureTransport: closureTransport,
        stagingReceipt: receipt,
        packageExecutionEnabled: false,
        syncBackEnabled: false,
        buildClosureMaterialized: false
    )
}
