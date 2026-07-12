import CryptoKit
import Darwin
import Foundation

private enum KeygenError: Error {
    case usage
    case unsafeDirectory
    case writeFailed
}

@main
private struct LinuxVzHostKeygen {
    static func main() {
        do {
            guard CommandLine.arguments.count == 2,
                  CommandLine.arguments[1].hasPrefix("/") else {
                throw KeygenError.usage
            }
            let directory = CommandLine.arguments[1]
            try validateDirectory(directory)
            let privateKey = Curve25519.Signing.PrivateKey()
            var seed = privateKey.rawRepresentation
            defer { seed.resetBytes(in: 0..<seed.count) }
            let publicKey = privateKey.publicKey.rawRepresentation
            let seedPath = directory + "/host-ed25519.seed"
            let publicPath = directory + "/host-ed25519-public-key.bin"
            do {
                try writeNewPrivateFile(seedPath, data: seed)
                try writeNewPrivateFile(publicPath, data: publicKey)
            } catch {
                unlink(seedPath)
                unlink(publicPath)
                throw error
            }
            let digest = SHA256.hash(data: publicKey).map {
                String(format: "%02x", $0)
            }.joined()
            print(
                "{\"private_key_exported\":false,\"public_key_sha256\":\"sha256:\(digest)\",\"schema_version\":\"whoathere.linux_vz_host_keygen_result.v1\",\"status\":\"ok\"}"
            )
        } catch KeygenError.usage {
            fputs("usage: whoathere-linux-vz-host-keygen /absolute/mode-0700-directory\n", stderr)
            exit(64)
        } catch {
            fputs("whoathere_linux_vz_host_keygen_failed\n", stderr)
            exit(70)
        }
    }

    private static func validateDirectory(_ path: String) throws {
        var metadata = stat()
        var linkMetadata = stat()
        guard lstat(path, &linkMetadata) == 0,
              stat(path, &metadata) == 0,
              linkMetadata.st_mode & S_IFMT == S_IFDIR,
              metadata.st_mode & S_IFMT == S_IFDIR,
              linkMetadata.st_dev == metadata.st_dev,
              linkMetadata.st_ino == metadata.st_ino,
              metadata.st_uid == geteuid(),
              metadata.st_mode & 0o777 == 0o700 else {
            throw KeygenError.unsafeDirectory
        }
    }

    private static func writeNewPrivateFile(_ path: String, data: Data) throws {
        let descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw KeygenError.writeFailed }
        defer { close(descriptor) }
        try data.withUnsafeBytes { raw in
            var offset = 0
            while offset < raw.count {
                let count = Darwin.write(
                    descriptor,
                    raw.baseAddress!.advanced(by: offset),
                    raw.count - offset
                )
                if count > 0 { offset += count; continue }
                if count < 0 && errno == EINTR { continue }
                throw KeygenError.writeFailed
            }
        }
        guard fsync(descriptor) == 0 else { throw KeygenError.writeFailed }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0,
              metadata.st_mode & S_IFMT == S_IFREG,
              metadata.st_uid == geteuid(),
              metadata.st_nlink == 1,
              metadata.st_mode & 0o777 == 0o600,
              metadata.st_size == data.count else {
            throw KeygenError.writeFailed
        }
    }
}
