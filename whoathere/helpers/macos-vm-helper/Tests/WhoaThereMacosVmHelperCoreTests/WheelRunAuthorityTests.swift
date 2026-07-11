import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func wheelAuthorityIsAtomicallyConsumedOnceBeforeArtifactBytes() throws {
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "install_exact_wheel"],
        scenarioIndex: 61
    )
    let reader = try beginWheelSubmission(from: wheelAuthorityFileHandle(fixture.frame))
    let authority = try wheelAuthorityFixture(
        authorityID: "authority-once-61",
        prelude: reader.prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }

    let consumed = try consumeWheelRunAuthority(
        layout: authority.layout,
        authorityID: authority.authorityID,
        prelude: reader.prelude,
        nowUnixSeconds: authority.now
    )
    #expect(consumed.challengeBindingSHA256 == fixture.challengeBindingSHA256)
    #expect(consumed.runSpecSHA256 == fixture.runSpecSHA256)
    #expect(consumed.artifactSHA256 == fixture.artifactSHA256)
    #expect(consumed.replayStatePersisted)
    #expect(!wheelAuthorityPathExists(authority.pendingURL.path))
    #expect(wheelAuthorityPathExists(consumed.consumedURL.path))

    let transport = try reader.consumeArtifact()
    #expect(transport.artifactSHA256 == fixture.artifactSHA256)

    let replayReader = try beginWheelSubmission(from: wheelAuthorityFileHandle(fixture.frame))
    #expect(throws: WheelRunAuthorityError.authorityAlreadyConsumed) {
        try consumeWheelRunAuthority(
            layout: authority.layout,
            authorityID: authority.authorityID,
            prelude: replayReader.prelude,
            nowUnixSeconds: authority.now
        )
    }
}

@Test func reboundWheelAuthorityIsSpentFailClosedWithoutConsumingArtifact() throws {
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "import_root", "module": "wheel_fixture"],
        scenarioIndex: 62
    )
    let reader = try beginWheelSubmission(from: wheelAuthorityFileHandle(fixture.frame))
    let authority = try wheelAuthorityFixture(
        authorityID: "authority-rebound-62",
        prelude: reader.prelude,
        artifactSHA256: sha256(Data("wrong wheel".utf8))
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }

    #expect(throws: WheelRunAuthorityError.bindingMismatch) {
        try consumeWheelRunAuthority(
            layout: authority.layout,
            authorityID: authority.authorityID,
            prelude: reader.prelude,
            nowUnixSeconds: authority.now
        )
    }
    #expect(!wheelAuthorityPathExists(authority.pendingURL.path))
    #expect(wheelAuthorityPathExists(authority.consumedURL.path))
    let transport = try reader.consumeArtifact()
    #expect(transport.artifactSHA256 == fixture.artifactSHA256)

    try authority.record.write(to: authority.pendingURL)
    try wheelAuthoritySetMode(authority.pendingURL, 0o600)
    let replayReader = try beginWheelSubmission(from: wheelAuthorityFileHandle(fixture.frame))
    #expect(throws: WheelRunAuthorityError.authorityAlreadyConsumed) {
        try consumeWheelRunAuthority(
            layout: authority.layout,
            authorityID: authority.authorityID,
            prelude: replayReader.prelude,
            nowUnixSeconds: authority.now
        )
    }
}

private struct WheelAuthorityFixture {
    let root: URL
    let layout: WheelRunAuthorityLayout
    let authorityID: String
    let pendingURL: URL
    let consumedURL: URL
    let record: Data
    let now: UInt64
}

private func wheelAuthorityFixture(
    authorityID: String,
    prelude: WheelRunSubmissionPrelude,
    artifactSHA256: String? = nil
) throws -> WheelAuthorityFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-wheel-authority-\(UUID().uuidString)", isDirectory: true
    )
    let state = root.appendingPathComponent("state", isDirectory: true)
    let layout = WheelRunAuthorityLayout(stateDirectory: state)
    for directory in [root, state, layout.rootDirectory, layout.pendingDirectory,
                      layout.consumedDirectory] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try wheelAuthoritySetMode(directory, 0o700)
    }
    let now: UInt64 = 2_000_000_000
    let record = try canonicalJSONData([
        "schema_version": wheelRunAuthoritySchemaV1,
        "authority_id": authorityID,
        "challenge_binding_sha256": prelude.challengeBindingSHA256,
        "run_spec_sha256": prelude.runSpecSHA256,
        "artifact_sha256": artifactSHA256 ?? prelude.artifactSHA256,
        "issued_at_unix_seconds": String(now - 10),
        "expires_at_unix_seconds": String(now + 120)
    ])
    let pendingURL = layout.pendingURL(authorityID: authorityID)
    try record.write(to: pendingURL)
    try wheelAuthoritySetMode(pendingURL, 0o600)
    return WheelAuthorityFixture(
        root: root,
        layout: layout,
        authorityID: authorityID,
        pendingURL: pendingURL,
        consumedURL: layout.consumedURL(authorityID: authorityID),
        record: record,
        now: now
    )
}

private func wheelAuthoritySetMode(_ url: URL, _ mode: mode_t) throws {
    guard chmod(url.path, mode) == 0 else {
        throw WheelRunAuthorityError.layoutUnsafe
    }
}

private func wheelAuthorityPathExists(_ path: String) -> Bool {
    var status = stat()
    return lstat(path, &status) == 0
}

private func wheelAuthorityFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}
