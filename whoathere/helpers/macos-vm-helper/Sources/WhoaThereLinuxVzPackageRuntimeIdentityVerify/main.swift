import Foundation
import WhoaThereMacosVmHelperCore

private enum IdentityVerifyError: Error {
    case usage
    case invalidPath
}

private struct Options {
    let runtimeDirectory: URL
    let expectedRootfsSHA256: String
    let expectedRootfsByteLength: UInt64
    let expectedRuntimeManifestSHA256: String
    let expectedPackageRunnerSHA256: String

    static func parse(_ arguments: [String]) throws -> Self {
        var values: [String: String] = [:]
        var index = 1
        while index < arguments.count {
            guard index + 1 < arguments.count,
                  values.updateValue(arguments[index + 1], forKey: arguments[index]) == nil else {
                throw IdentityVerifyError.usage
            }
            index += 2
        }
        let expectedKeys = Set([
            "--runtime-directory", "--expected-rootfs-sha256",
            "--expected-rootfs-byte-length", "--expected-runtime-manifest-sha256",
            "--expected-package-runner-sha256"
        ])
        guard Set(values.keys) == expectedKeys,
              let runtimeDirectory = values["--runtime-directory"],
              runtimeDirectory.hasPrefix("/"),
              let rootfsSHA256 = values["--expected-rootfs-sha256"],
              let rootfsLengthText = values["--expected-rootfs-byte-length"],
              let rootfsByteLength = strictUInt64(rootfsLengthText),
              let manifestSHA256 = values["--expected-runtime-manifest-sha256"],
              let runnerSHA256 = values["--expected-package-runner-sha256"] else {
            throw IdentityVerifyError.usage
        }
        let runtimeURL = URL(fileURLWithPath: runtimeDirectory, isDirectory: true)
        let valuesForPath = try runtimeURL.resourceValues(
            forKeys: [.isDirectoryKey, .isSymbolicLinkKey]
        )
        guard valuesForPath.isDirectory == true,
              valuesForPath.isSymbolicLink != true else {
            throw IdentityVerifyError.invalidPath
        }
        return Self(
            runtimeDirectory: runtimeURL,
            expectedRootfsSHA256: rootfsSHA256,
            expectedRootfsByteLength: rootfsByteLength,
            expectedRuntimeManifestSHA256: manifestSHA256,
            expectedPackageRunnerSHA256: runnerSHA256
        )
    }
}

@main
private enum LinuxVzPackageRuntimeIdentityVerifyMain {
    static func main() {
        do {
            let options = try Options.parse(CommandLine.arguments)
            let base = try verifyAndLockLinuxVzPackageRuntimeBase(
                layout: LinuxVzPackageRuntimeBaseLayout(
                    runtimeDirectory: options.runtimeDirectory
                ),
                expectedRootfsSHA256: options.expectedRootfsSHA256,
                expectedRootfsByteLength: options.expectedRootfsByteLength,
                expectedRuntimeManifestSHA256: options.expectedRuntimeManifestSHA256,
                expectedPackageRunnerSHA256: options.expectedPackageRunnerSHA256
            )
            let clone = try base.createDisposableClone()
            try clone.verifyReadyForAttachment()
            let cloneBindingSHA256 = clone.cloneBindingSHA256
            let cloneInitialRootfsSHA256 = clone.initialRootfsSHA256
            try clone.cleanup()
            print(
                "{\"candidate_runtime_qualified\":false,"
                    + "\"clone_binding_sha256\":\"\(cloneBindingSHA256)\","
                    + "\"clone_destroyed\":true,"
                    + "\"clone_initial_rootfs_sha256\":\"\(cloneInitialRootfsSHA256)\","
                    + "\"manifest_sha256\":\"\(base.measurement.runtimeManifestSHA256)\","
                    + "\"package_execution\":false,"
                    + "\"package_runner_sha256\":\"\(base.measurement.packageRunnerSHA256)\","
                    + "\"rootfs_byte_length\":\"\(base.measurement.rootfsByteLength)\","
                    + "\"rootfs_sha256\":\"\(base.measurement.rootfsSHA256)\","
                    + "\"schema_version\":"
                    + "\"whoathere.linux_vz_package_runtime_identity_verification.v1\","
                    + "\"status\":\"exact_candidate_runtime_and_clone_verified\","
                    + "\"sync_back\":false}"
            )
        } catch IdentityVerifyError.usage {
            fputs(
                "usage: whoathere-linux-vz-package-runtime-identity-verify "
                    + "--runtime-directory PATH --expected-rootfs-sha256 SHA256 "
                    + "--expected-rootfs-byte-length BYTES "
                    + "--expected-runtime-manifest-sha256 SHA256 "
                    + "--expected-package-runner-sha256 SHA256\n",
                stderr
            )
            Foundation.exit(64)
        } catch {
            fputs("whoathere Linux VZ package runtime identity verification failed: \(error)\n", stderr)
            Foundation.exit(65)
        }
    }
}

private func strictUInt64(_ value: String) -> UInt64? {
    guard !value.isEmpty, value.utf8.count <= 20,
          value == "0" || !value.hasPrefix("0"),
          value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }),
          let parsed = UInt64(value), parsed > 0 else {
        return nil
    }
    return parsed
}
