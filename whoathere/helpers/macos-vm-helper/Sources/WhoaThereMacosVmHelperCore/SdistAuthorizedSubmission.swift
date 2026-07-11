import Foundation

/// The only helper-core value that can expose sdist artifact bytes after authority consumption.
/// Production routing should construct this value directly from standard input and never retain a
/// separate `SdistRunSubmissionReader`.
public final class AuthorizedSdistRunSubmission {
    public let prelude: SdistRunSubmissionPrelude
    public let authority: ConsumedSdistRunAuthority

    private let reader: SdistRunSubmissionReader

    fileprivate init(
        reader: SdistRunSubmissionReader,
        authority: ConsumedSdistRunAuthority
    ) throws {
        let prelude = reader.prelude
        guard authority.replayStatePersisted,
              authority.challengeBindingSHA256 == prelude.challengeBindingSHA256,
              authority.runSpecSHA256 == prelude.runSpecSHA256,
              authority.artifactSHA256 == prelude.artifactSHA256,
              authority.buildClosureSHA256 == prelude.buildClosureSHA256 else {
            throw SdistRunAuthorityError.bindingMismatch
        }
        self.reader = reader
        self.prelude = prelude
        self.authority = authority
    }

    public func consumeArtifact(
        chunkSink: (Data) throws -> Void = { _ in }
    ) throws -> SdistRunTransportObservation {
        try reader.consumeArtifact(chunkSink: chunkSink)
    }

    var submissionReader: SdistRunSubmissionReader { reader }
}

/// Validates the bounded header and burns the matching authority before returning any API that can
/// consume artifact bytes. An authority failure leaves the body unread and permanently spends any
/// record that reached the burn-first transition.
public func beginAndAuthorizeSdistRunSubmission(
    from handle: FileHandle,
    authorityLayout: SdistRunAuthorityLayout,
    authorityID: String,
    expectedAuthorityRecordSHA256: String,
    nowUnixSeconds: UInt64
) throws -> AuthorizedSdistRunSubmission {
    let reader = try beginSdistSubmission(from: handle)
    let authority = try consumeSdistRunAuthority(
        layout: authorityLayout,
        authorityID: authorityID,
        expectedAuthorityRecordSHA256: expectedAuthorityRecordSHA256,
        prelude: reader.prelude,
        nowUnixSeconds: nowUnixSeconds
    )
    return try AuthorizedSdistRunSubmission(reader: reader, authority: authority)
}
