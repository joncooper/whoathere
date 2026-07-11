import Darwin
import Foundation

public let sdistRunAuthoritySchemaV1 = "whoathere.sdist_run_authority.v1"
public let maximumSdistRunAuthorityLifetimeSecondsV1: UInt64 = 15 * 60
public let maximumSdistRunAuthorityRecordBytesV1 = 64 * 1024

public enum SdistRunAuthorityError: Error, Equatable, CustomStringConvertible {
    case authorityIDInvalid
    case expectedRecordDigestInvalid
    case layoutUnsafe
    case authorityMissing
    case authorityAlreadyConsumed
    case reservationFailed
    case persistenceFailed
    case authorityFileUnsafe
    case authorityInvalid
    case authorityExpired
    case bindingMismatch

    public var description: String {
        switch self {
        case .authorityIDInvalid: return "sdist_run_authority_id_invalid"
        case .expectedRecordDigestInvalid: return "sdist_run_authority_record_digest_invalid"
        case .layoutUnsafe: return "sdist_run_authority_layout_unsafe"
        case .authorityMissing: return "sdist_run_authority_missing"
        case .authorityAlreadyConsumed: return "sdist_run_authority_already_consumed"
        case .reservationFailed: return "sdist_run_authority_reservation_failed"
        case .persistenceFailed: return "sdist_run_authority_persistence_failed"
        case .authorityFileUnsafe: return "sdist_run_authority_file_unsafe"
        case .authorityInvalid: return "sdist_run_authority_invalid"
        case .authorityExpired: return "sdist_run_authority_expired"
        case .bindingMismatch: return "sdist_run_authority_binding_mismatch"
        }
    }
}

public struct SdistRunAuthorityLayout: Equatable, Sendable {
    public let rootDirectory: URL
    public let pendingDirectory: URL
    public let consumedDirectory: URL

    public init(stateDirectory: URL) {
        rootDirectory = stateDirectory.appendingPathComponent(
            "sdist-authorities", isDirectory: true
        )
        pendingDirectory = rootDirectory.appendingPathComponent("pending", isDirectory: true)
        consumedDirectory = rootDirectory.appendingPathComponent("consumed", isDirectory: true)
    }

    public func pendingURL(authorityID: String) -> URL {
        pendingDirectory.appendingPathComponent("\(authorityID).json")
    }

    public func consumedURL(authorityID: String) -> URL {
        consumedDirectory.appendingPathComponent("\(authorityID).json")
    }
}

public struct ConsumedSdistRunAuthority: Equatable, Sendable {
    public let authorityID: String
    public let challengeBindingSHA256: String
    public let runSpecSHA256: String
    public let artifactSHA256: String
    public let buildClosureSHA256: String
    public let issuedAtUnixSeconds: UInt64
    public let expiresAtUnixSeconds: UInt64
    public let authorityRecordSHA256: String
    public let consumedAtUnixSeconds: UInt64
    public let consumedURL: URL
    public let replayStatePersisted: Bool
}

/// Burns one pre-issued authority before validating its contents. Invalid, expired, tampered,
/// rebound, and successfully used records all remain in the consumed directory.
public func consumeSdistRunAuthority(
    layout: SdistRunAuthorityLayout,
    authorityID: String,
    expectedAuthorityRecordSHA256: String,
    prelude: SdistRunSubmissionPrelude,
    nowUnixSeconds: UInt64
) throws -> ConsumedSdistRunAuthority {
    guard validSdistRunAuthorityID(authorityID) else {
        throw SdistRunAuthorityError.authorityIDInvalid
    }
    guard validSdistRunAuthorityDigest(expectedAuthorityRecordSHA256) else {
        throw SdistRunAuthorityError.expectedRecordDigestInvalid
    }
    try requireSdistRunAuthorityDirectory(layout.rootDirectory)
    let rootDescriptor = try openSdistRunAuthorityDirectory(layout.rootDirectory)
    defer { _ = close(rootDescriptor) }
    let pendingDescriptor = try openSdistRunAuthorityDirectory(layout.pendingDirectory)
    defer { _ = close(pendingDescriptor) }
    let consumedDescriptor = try openSdistRunAuthorityDirectory(layout.consumedDirectory)
    defer { _ = close(consumedDescriptor) }

    let name = "\(authorityID).json"
    errno = 0
    let renamed = name.withCString { source in
        name.withCString { destination in
            renameatx_np(
                pendingDescriptor,
                source,
                consumedDescriptor,
                destination,
                UInt32(RENAME_EXCL)
            )
        }
    }
    guard renamed == 0 else {
        if errno == EEXIST {
            throw SdistRunAuthorityError.authorityAlreadyConsumed
        }
        if errno == ENOENT {
            var status = stat()
            let consumedExists = name.withCString {
                fstatat(consumedDescriptor, $0, &status, AT_SYMLINK_NOFOLLOW)
            } == 0
            throw consumedExists
                ? SdistRunAuthorityError.authorityAlreadyConsumed
                : SdistRunAuthorityError.authorityMissing
        }
        throw SdistRunAuthorityError.reservationFailed
    }
    guard fsync(pendingDescriptor) == 0,
          fsync(consumedDescriptor) == 0,
          fsync(rootDescriptor) == 0 else {
        throw SdistRunAuthorityError.persistenceFailed
    }

    let descriptor = name.withCString {
        openat(consumedDescriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else {
        throw SdistRunAuthorityError.authorityFileUnsafe
    }
    defer { _ = close(descriptor) }
    var opened = stat()
    var path = stat()
    guard fstat(descriptor, &opened) == 0,
          name.withCString({
              fstatat(consumedDescriptor, $0, &path, AT_SYMLINK_NOFOLLOW)
          }) == 0,
          opened.st_mode & S_IFMT == S_IFREG,
          path.st_mode & S_IFMT == S_IFREG,
          opened.st_dev == path.st_dev,
          opened.st_ino == path.st_ino,
          opened.st_uid == geteuid(),
          opened.st_nlink == 1,
          opened.st_mode & 0o777 == 0o600,
          opened.st_size > 0,
          opened.st_size <= maximumSdistRunAuthorityRecordBytesV1 else {
        throw SdistRunAuthorityError.authorityFileUnsafe
    }
    let data = try readSdistRunAuthorityRecord(
        descriptor: descriptor,
        expectedLength: Int(opened.st_size)
    )
    guard sha256(data) == expectedAuthorityRecordSHA256 else {
        throw SdistRunAuthorityError.authorityInvalid
    }
    guard let record = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(record) == data,
          Set(record.keys) == Set([
              "artifact_sha256", "authority_id", "build_closure_sha256",
              "challenge_binding_sha256", "expires_at_unix_seconds",
              "issued_at_unix_seconds", "run_spec_sha256", "schema_version"
          ]),
          record["schema_version"] as? String == sdistRunAuthoritySchemaV1,
          record["authority_id"] as? String == authorityID,
          let challenge = record["challenge_binding_sha256"] as? String,
          let runSpec = record["run_spec_sha256"] as? String,
          let artifact = record["artifact_sha256"] as? String,
          let buildClosure = record["build_closure_sha256"] as? String,
          validSdistRunAuthorityDigest(challenge),
          validSdistRunAuthorityDigest(runSpec),
          validSdistRunAuthorityDigest(artifact),
          validSdistRunAuthorityDigest(buildClosure),
          let issuedText = record["issued_at_unix_seconds"] as? String,
          let expiresText = record["expires_at_unix_seconds"] as? String,
          let issued = canonicalSdistRunAuthorityUInt64(issuedText),
          let expires = canonicalSdistRunAuthorityUInt64(expiresText),
          issued != 0,
          expires > issued,
          expires - issued <= maximumSdistRunAuthorityLifetimeSecondsV1 else {
        throw SdistRunAuthorityError.authorityInvalid
    }
    guard issued <= nowUnixSeconds, nowUnixSeconds < expires else {
        throw SdistRunAuthorityError.authorityExpired
    }
    guard challenge == prelude.challengeBindingSHA256,
          runSpec == prelude.runSpecSHA256,
          artifact == prelude.artifactSHA256,
          buildClosure == prelude.buildClosureSHA256 else {
        throw SdistRunAuthorityError.bindingMismatch
    }
    return ConsumedSdistRunAuthority(
        authorityID: authorityID,
        challengeBindingSHA256: challenge,
        runSpecSHA256: runSpec,
        artifactSHA256: artifact,
        buildClosureSHA256: buildClosure,
        issuedAtUnixSeconds: issued,
        expiresAtUnixSeconds: expires,
        authorityRecordSHA256: sha256(data),
        consumedAtUnixSeconds: nowUnixSeconds,
        consumedURL: layout.consumedURL(authorityID: authorityID),
        replayStatePersisted: true
    )
}

private func requireSdistRunAuthorityDirectory(_ url: URL) throws {
    var status = stat()
    guard lstat(url.path, &status) == 0,
          status.st_mode & S_IFMT == S_IFDIR,
          status.st_uid == geteuid(),
          status.st_mode & 0o777 == 0o700 else {
        throw SdistRunAuthorityError.layoutUnsafe
    }
}

private func openSdistRunAuthorityDirectory(_ url: URL) throws -> Int32 {
    try requireSdistRunAuthorityDirectory(url)
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else { throw SdistRunAuthorityError.layoutUnsafe }
    return descriptor
}

private func readSdistRunAuthorityRecord(
    descriptor: Int32,
    expectedLength: Int
) throws -> Data {
    var data = Data()
    data.reserveCapacity(expectedLength)
    var buffer = [UInt8](repeating: 0, count: 4 * 1024)
    while data.count < expectedLength {
        let requested = min(buffer.count, expectedLength - data.count)
        let count = read(descriptor, &buffer, requested)
        if count > 0 {
            data.append(contentsOf: buffer[0..<count])
        } else if count < 0 && errno == EINTR {
            continue
        } else {
            throw SdistRunAuthorityError.authorityFileUnsafe
        }
    }
    var trailing: UInt8 = 0
    guard read(descriptor, &trailing, 1) == 0 else {
        throw SdistRunAuthorityError.authorityFileUnsafe
    }
    return data
}

private func validSdistRunAuthorityID(_ value: String) -> Bool {
    guard value.hasPrefix("sdist-authority-") else { return false }
    let suffix = value.dropFirst("sdist-authority-".count)
    return suffix.utf8.count == 64 && suffix.utf8.allSatisfy {
        ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
    }
}

private func validSdistRunAuthorityDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func canonicalSdistRunAuthorityUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}
