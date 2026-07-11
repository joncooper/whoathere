import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func sdistAuthorityIsConsumedOnceBeforeArtifactBytesAndBindsClosure() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"], scenarioIndex: 71
    )
    let reader = try beginSdistSubmission(from: sdistFileHandle(fixture.frame))
    let authority = try sdistAuthorityFixture(
        authorityID: sdistAuthorityID("a"), prelude: reader.prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }

    let consumed = try consumeSdistRunAuthority(
        layout: authority.layout,
        authorityID: authority.authorityID,
        expectedAuthorityRecordSHA256: authority.recordSHA256,
        prelude: reader.prelude,
        nowUnixSeconds: authority.now
    )
    #expect(consumed.challengeBindingSHA256 == fixture.challengeBindingSHA256)
    #expect(consumed.runSpecSHA256 == fixture.runSpecSHA256)
    #expect(consumed.artifactSHA256 == fixture.artifactSHA256)
    #expect(consumed.buildClosureSHA256 == fixture.buildClosureSHA256)
    #expect(consumed.authorityRecordSHA256 == authority.recordSHA256)
    #expect(consumed.consumedAtUnixSeconds == authority.now)
    #expect(consumed.replayStatePersisted)
    #expect(!sdistAuthorityPathExists(authority.pendingURL.path))
    #expect(sdistAuthorityPathExists(consumed.consumedURL.path))

    let transport = try reader.consumeArtifact()
    #expect(transport.artifactSHA256 == fixture.artifactSHA256)

    let replayReader = try beginSdistSubmission(from: sdistFileHandle(fixture.frame))
    #expect(throws: SdistRunAuthorityError.authorityAlreadyConsumed) {
        try consumeSdistRunAuthority(
            layout: authority.layout,
            authorityID: authority.authorityID,
            expectedAuthorityRecordSHA256: authority.recordSHA256,
            prelude: replayReader.prelude,
            nowUnixSeconds: authority.now
        )
    }
}

@Test func reboundSdistClosureIsSpentWithoutConsumingArtifact() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "import_root", "module": "swift_sdist_fixture"],
        scenarioIndex: 72
    )
    let reader = try beginSdistSubmission(from: sdistFileHandle(fixture.frame))
    let authority = try sdistAuthorityFixture(
        authorityID: sdistAuthorityID("b"),
        prelude: reader.prelude,
        buildClosureSHA256: sha256(Data("wrong build closure".utf8))
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }

    #expect(throws: SdistRunAuthorityError.bindingMismatch) {
        try consumeSdistRunAuthority(
            layout: authority.layout,
            authorityID: authority.authorityID,
            expectedAuthorityRecordSHA256: authority.recordSHA256,
            prelude: reader.prelude,
            nowUnixSeconds: authority.now
        )
    }
    #expect(!sdistAuthorityPathExists(authority.pendingURL.path))
    #expect(sdistAuthorityPathExists(authority.consumedURL.path))

    // A still-readable body proves authority failed before the artifact reader was advanced.
    let transport = try reader.consumeArtifact()
    #expect(transport.artifactSHA256 == fixture.artifactSHA256)

    let replayReader = try beginSdistSubmission(from: sdistFileHandle(fixture.frame))
    #expect(throws: SdistRunAuthorityError.authorityAlreadyConsumed) {
        try consumeSdistRunAuthority(
            layout: authority.layout,
            authorityID: authority.authorityID,
            expectedAuthorityRecordSHA256: authority.recordSHA256,
            prelude: replayReader.prelude,
            nowUnixSeconds: authority.now
        )
    }
}

@Test func expiredAndTamperedSdistAuthoritiesStayBurned() throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "inspect_derived_wheel"], scenarioIndex: 73
    )
    let prelude = try beginSdistSubmission(
        from: sdistFileHandle(fixture.frame)
    ).prelude

    let expired = try sdistAuthorityFixture(
        authorityID: sdistAuthorityID("c"),
        prelude: prelude,
        issuedAt: 1_999_999_900,
        expiresAt: 2_000_000_000
    )
    defer { try? FileManager.default.removeItem(at: expired.root) }
    #expect(throws: SdistRunAuthorityError.authorityExpired) {
        try consumeSdistRunAuthority(
            layout: expired.layout,
            authorityID: expired.authorityID,
            expectedAuthorityRecordSHA256: expired.recordSHA256,
            prelude: prelude,
            nowUnixSeconds: expired.now
        )
    }
    #expect(sdistAuthorityPathExists(expired.consumedURL.path))
    #expect(throws: SdistRunAuthorityError.authorityAlreadyConsumed) {
        try consumeSdistRunAuthority(
            layout: expired.layout,
            authorityID: expired.authorityID,
            expectedAuthorityRecordSHA256: expired.recordSHA256,
            prelude: prelude,
            nowUnixSeconds: expired.now - 1
        )
    }

    let tampered = try sdistAuthorityFixture(
        authorityID: sdistAuthorityID("d"), prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: tampered.root) }
    #expect(throws: SdistRunAuthorityError.authorityInvalid) {
        try consumeSdistRunAuthority(
            layout: tampered.layout,
            authorityID: tampered.authorityID,
            expectedAuthorityRecordSHA256: sha256(Data("different record".utf8)),
            prelude: prelude,
            nowUnixSeconds: tampered.now
        )
    }
    #expect(sdistAuthorityPathExists(tampered.consumedURL.path))
    #expect(throws: SdistRunAuthorityError.authorityAlreadyConsumed) {
        try consumeSdistRunAuthority(
            layout: tampered.layout,
            authorityID: tampered.authorityID,
            expectedAuthorityRecordSHA256: tampered.recordSHA256,
            prelude: prelude,
            nowUnixSeconds: tampered.now
        )
    }
}

private enum SdistAuthorityRaceResult: Sendable, Equatable {
    case consumed
    case alreadyConsumed
    case unexpected(String)
}

@Test func concurrentSdistAuthorityConsumptionHasExactlyOneWinner() async throws {
    let fixture = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"], scenarioIndex: 74
    )
    let prelude = try beginSdistSubmission(
        from: sdistFileHandle(fixture.frame)
    ).prelude
    let authority = try sdistAuthorityFixture(
        authorityID: sdistAuthorityID("e"), prelude: prelude
    )
    defer { try? FileManager.default.removeItem(at: authority.root) }

    let layout = authority.layout
    let authorityID = authority.authorityID
    let recordSHA256 = authority.recordSHA256
    let now = authority.now
    let results = await withTaskGroup(of: SdistAuthorityRaceResult.self) { group in
        for _ in 0..<12 {
            group.addTask {
                do {
                    _ = try consumeSdistRunAuthority(
                        layout: layout,
                        authorityID: authorityID,
                        expectedAuthorityRecordSHA256: recordSHA256,
                        prelude: prelude,
                        nowUnixSeconds: now
                    )
                    return .consumed
                } catch SdistRunAuthorityError.authorityAlreadyConsumed {
                    return .alreadyConsumed
                } catch {
                    return .unexpected(String(describing: error))
                }
            }
        }
        var values = [SdistAuthorityRaceResult]()
        for await value in group { values.append(value) }
        return values
    }
    #expect(results.filter { $0 == .consumed }.count == 1)
    #expect(results.filter { $0 == .alreadyConsumed }.count == 11)
    #expect(results.filter {
        if case .unexpected = $0 { return true }
        return false
    }.isEmpty)
}

private struct SdistAuthorityFixture {
    let root: URL
    let layout: SdistRunAuthorityLayout
    let authorityID: String
    let pendingURL: URL
    let consumedURL: URL
    let record: Data
    let recordSHA256: String
    let now: UInt64
}

private func sdistAuthorityFixture(
    authorityID: String,
    prelude: SdistRunSubmissionPrelude,
    artifactSHA256: String? = nil,
    buildClosureSHA256: String? = nil,
    issuedAt: UInt64? = nil,
    expiresAt: UInt64? = nil
) throws -> SdistAuthorityFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-sdist-authority-\(UUID().uuidString)", isDirectory: true
    )
    let state = root.appendingPathComponent("state", isDirectory: true)
    let layout = SdistRunAuthorityLayout(stateDirectory: state)
    for directory in [
        root, state, layout.rootDirectory, layout.pendingDirectory, layout.consumedDirectory
    ] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try sdistAuthoritySetMode(directory, 0o700)
    }
    let now: UInt64 = 2_000_000_000
    let record = try canonicalJSONData([
        "schema_version": sdistRunAuthoritySchemaV1,
        "authority_id": authorityID,
        "challenge_binding_sha256": prelude.challengeBindingSHA256,
        "run_spec_sha256": prelude.runSpecSHA256,
        "artifact_sha256": artifactSHA256 ?? prelude.artifactSHA256,
        "build_closure_sha256": buildClosureSHA256 ?? prelude.buildClosureSHA256,
        "issued_at_unix_seconds": String(issuedAt ?? now - 10),
        "expires_at_unix_seconds": String(expiresAt ?? now + 120)
    ])
    let pendingURL = layout.pendingURL(authorityID: authorityID)
    try record.write(to: pendingURL)
    try sdistAuthoritySetMode(pendingURL, 0o600)
    return SdistAuthorityFixture(
        root: root,
        layout: layout,
        authorityID: authorityID,
        pendingURL: pendingURL,
        consumedURL: layout.consumedURL(authorityID: authorityID),
        record: record,
        recordSHA256: sha256(record),
        now: now
    )
}

private func sdistAuthorityID(_ digit: Character) -> String {
    "sdist-authority-" + String(repeating: String(digit), count: 64)
}

private func sdistAuthoritySetMode(_ url: URL, _ mode: mode_t) throws {
    guard chmod(url.path, mode) == 0 else {
        throw SdistRunAuthorityError.layoutUnsafe
    }
}

private func sdistAuthorityPathExists(_ path: String) -> Bool {
    var status = stat()
    return lstat(path, &status) == 0
}
