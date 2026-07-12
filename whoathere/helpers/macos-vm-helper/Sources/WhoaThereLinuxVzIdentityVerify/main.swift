import Foundation
import WhoaThereMacosVmHelperCore

@main
private struct LinuxVzIdentityVerify {
    static func main() {
        do {
            guard CommandLine.arguments.count == 3,
                  CommandLine.arguments[1].hasPrefix("/") else {
                throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
            }
            let url = URL(fileURLWithPath: CommandLine.arguments[1])
            let values = try url.resourceValues(forKeys: [
                .isRegularFileKey, .isSymbolicLinkKey, .fileSizeKey
            ])
            guard values.isRegularFile == true, values.isSymbolicLink != true,
                  let size = values.fileSize, size > 0,
                  size <= maximumLinuxVzTelemetryBackendIdentityBytesV1 else {
                throw LinuxVzTelemetryBackendIdentityError.invalidIdentity
            }
            let data = try Data(contentsOf: url, options: [.mappedIfSafe])
            let identity = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
                data,
                expectedTelemetryRequirementsSHA256: CommandLine.arguments[2]
            )
            let result: [String: Any] = [
                "execution_authority": identity.executionAuthorityPermitted,
                "identity_sha256": identity.identitySHA256,
                "package_execution": false,
                "package_gid": String(identity.packageGID),
                "package_uid": String(identity.packageUID),
                "qualification_state": "candidate_unqualified",
                "schema_version": "whoathere.linux_vz_backend_identity_verification.v1",
                "sync_back": false
            ]
            let output = try JSONSerialization.data(
                withJSONObject: result,
                options: [.sortedKeys, .withoutEscapingSlashes]
            )
            print(String(decoding: output, as: UTF8.self))
        } catch {
            fputs("whoathere Linux VZ identity verification failed: \(error)\n", stderr)
            exit(70)
        }
    }
}
