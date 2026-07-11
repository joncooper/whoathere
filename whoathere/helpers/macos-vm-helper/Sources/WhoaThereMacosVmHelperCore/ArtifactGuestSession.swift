import Foundation

public struct ArtifactGuestNonExecutingSessionObservation: Equatable, Sendable {
    public let authentication: ArtifactGuestAuthObservation
    public let transport: ArtifactRunTransportObservation
    public let stagingReceipt: ArtifactGuestStagingReceiptObservation
    public let packageExecutionEnabled: Bool
}

public func runNonExecutingArtifactGuestSession(
    descriptor: Int32,
    reader: ArtifactRunSubmissionReader,
    base: LockedArtifactRunBase,
    clone: DisposableArtifactRunClone,
    timeoutMillis: Int32 = 10_000
) throws -> ArtifactGuestNonExecutingSessionObservation {
    let prelude = reader.prelude
    let authenticated = try authenticateArtifactGuestConnection(
        descriptor: descriptor,
        prelude: prelude,
        base: base,
        clone: clone,
        timeoutMillis: timeoutMillis
    )
    let transport = try ArtifactGuestSubmissionForwarder(
        descriptor: descriptor,
        reader: reader
    ).forward()
    let receipt = try receiveArtifactGuestStagingReceipt(
        descriptor: descriptor,
        authenticated: authenticated,
        prelude: prelude,
        transport: transport,
        base: base,
        timeoutMillis: timeoutMillis
    )
    return ArtifactGuestNonExecutingSessionObservation(
        authentication: authenticated.observation,
        transport: transport,
        stagingReceipt: receipt,
        packageExecutionEnabled: false
    )
}
