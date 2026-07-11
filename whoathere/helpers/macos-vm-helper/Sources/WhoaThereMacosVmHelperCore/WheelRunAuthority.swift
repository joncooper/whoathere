import Darwin
import Foundation

public let wheelRunAuthoritySchemaV1 = "whoathere.wheel_run_authority.v1"
public let maximumWheelRunAuthorityLifetimeSecondsV1: UInt64 = 15 * 60

public enum WheelRunAuthorityError: Error, Equatable, CustomStringConvertible {
    case authorityIDInvalid
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
        case .authorityIDInvalid: return "wheel_run_authority_id_invalid"
        case .layoutUnsafe: return "wheel_run_authority_layout_unsafe"
        case .authorityMissing: return "wheel_run_authority_missing"
        case .authorityAlreadyConsumed: return "wheel_run_authority_already_consumed"
        case .reservationFailed: return "wheel_run_authority_reservation_failed"
        case .persistenceFailed: return "wheel_run_authority_persistence_failed"
        case .authorityFileUnsafe: return "wheel_run_authority_file_unsafe"
        case .authorityInvalid: return "wheel_run_authority_invalid"
        case .authorityExpired: return "wheel_run_authority_expired"
        case .bindingMismatch: return "wheel_run_authority_binding_mismatch"
        }
    }
}

public struct WheelRunAuthorityLayout: Equatable, Sendable {
    public let rootDirectory: URL
    public let pendingDirectory: URL
    public let consumedDirectory: URL

    public init(stateDirectory: URL) {
        rootDirectory = stateDirectory.appendingPathComponent(
            "wheel-authorities", isDirectory: true
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

public struct ConsumedWheelRunAuthority: Equatable, Sendable {
    public let authorityID: String
    public let challengeBindingSHA256: String
    public let runSpecSHA256: String
    public let artifactSHA256: String
    public let issuedAtUnixSeconds: UInt64
    public let expiresAtUnixSeconds: UInt64
    public let authorityRecordSHA256: String
    public let consumedURL: URL
    public let replayStatePersisted: Bool
}

/// Atomically moves one pre-issued authority record from pending to consumed before validating it.
/// Invalid, expired, or rebound records remain consumed so that every attempted use is single-shot.
public func consumeWheelRunAuthority(
    layout: WheelRunAuthorityLayout,
    authorityID: String,
    prelude: WheelRunSubmissionPrelude,
    nowUnixSeconds: UInt64
) throws -> ConsumedWheelRunAuthority {
    guard validWheelRunAuthorityID(authorityID) else {
        throw WheelRunAuthorityError.authorityIDInvalid
    }
    try requireWheelRunAuthorityDirectory(layout.rootDirectory)
    let pendingDescriptor = try openWheelRunAuthorityDirectory(layout.pendingDirectory)
    defer { _ = close(pendingDescriptor) }
    let consumedDescriptor = try openWheelRunAuthorityDirectory(layout.consumedDirectory)
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
            throw WheelRunAuthorityError.authorityAlreadyConsumed
        }
        if errno == ENOENT {
            var status = stat()
            let consumedExists = name.withCString {
                fstatat(consumedDescriptor, $0, &status, AT_SYMLINK_NOFOLLOW)
            } == 0
            throw consumedExists
                ? WheelRunAuthorityError.authorityAlreadyConsumed
                : WheelRunAuthorityError.authorityMissing
        }
        throw WheelRunAuthorityError.reservationFailed
    }
    guard fsync(pendingDescriptor) == 0, fsync(consumedDescriptor) == 0 else {
        throw WheelRunAuthorityError.persistenceFailed
    }

    let descriptor = name.withCString {
        openat(consumedDescriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else {
        throw WheelRunAuthorityError.authorityFileUnsafe
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
          opened.st_size <= 4 * 1024 else {
        throw WheelRunAuthorityError.authorityFileUnsafe
    }
    let data = try readWheelRunAuthorityRecord(
        descriptor: descriptor,
        expectedLength: Int(opened.st_size)
    )
    guard let record = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
          try canonicalJSONData(record) == data,
          Set(record.keys) == Set([
              "artifact_sha256", "authority_id", "challenge_binding_sha256",
              "expires_at_unix_seconds", "issued_at_unix_seconds", "run_spec_sha256",
              "schema_version"
          ]),
          record["schema_version"] as? String == wheelRunAuthoritySchemaV1,
          record["authority_id"] as? String == authorityID,
          let challenge = record["challenge_binding_sha256"] as? String,
          let runSpec = record["run_spec_sha256"] as? String,
          let artifact = record["artifact_sha256"] as? String,
          validWheelRunAuthorityDigest(challenge),
          validWheelRunAuthorityDigest(runSpec),
          validWheelRunAuthorityDigest(artifact),
          let issuedText = record["issued_at_unix_seconds"] as? String,
          let expiresText = record["expires_at_unix_seconds"] as? String,
          let issued = canonicalWheelRunAuthorityUInt64(issuedText),
          let expires = canonicalWheelRunAuthorityUInt64(expiresText),
          issued <= expires,
          expires - issued <= maximumWheelRunAuthorityLifetimeSecondsV1 else {
        throw WheelRunAuthorityError.authorityInvalid
    }
    guard issued <= nowUnixSeconds, nowUnixSeconds <= expires else {
        throw WheelRunAuthorityError.authorityExpired
    }
    guard challenge == prelude.challengeBindingSHA256,
          runSpec == prelude.runSpecSHA256,
          artifact == prelude.artifactSHA256 else {
        throw WheelRunAuthorityError.bindingMismatch
    }
    return ConsumedWheelRunAuthority(
        authorityID: authorityID,
        challengeBindingSHA256: challenge,
        runSpecSHA256: runSpec,
        artifactSHA256: artifact,
        issuedAtUnixSeconds: issued,
        expiresAtUnixSeconds: expires,
        authorityRecordSHA256: sha256(data),
        consumedURL: layout.consumedURL(authorityID: authorityID),
        replayStatePersisted: true
    )
}

private func requireWheelRunAuthorityDirectory(_ url: URL) throws {
    var status = stat()
    guard lstat(url.path, &status) == 0,
          status.st_mode & S_IFMT == S_IFDIR,
          status.st_uid == geteuid(),
          status.st_mode & 0o777 == 0o700 else {
        throw WheelRunAuthorityError.layoutUnsafe
    }
}

private func openWheelRunAuthorityDirectory(_ url: URL) throws -> Int32 {
    try requireWheelRunAuthorityDirectory(url)
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw WheelRunAuthorityError.layoutUnsafe
    }
    return descriptor
}

private func readWheelRunAuthorityRecord(
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
            throw WheelRunAuthorityError.authorityFileUnsafe
        }
    }
    var trailing: UInt8 = 0
    guard read(descriptor, &trailing, 1) == 0 else {
        throw WheelRunAuthorityError.authorityFileUnsafe
    }
    return data
}

private func validWheelRunAuthorityID(_ value: String) -> Bool {
    guard !value.isEmpty, value.utf8.count <= 128,
          value.unicodeScalars.allSatisfy({ $0.isASCII }) else {
        return false
    }
    return value.utf8.allSatisfy { byte in
        (byte >= 48 && byte <= 57) || (byte >= 65 && byte <= 90)
            || (byte >= 97 && byte <= 122) || [45, 95].contains(byte)
    }
}

private func validWheelRunAuthorityDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}

private func canonicalWheelRunAuthorityUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) else {
        return nil
    }
    return UInt64(value)
}
