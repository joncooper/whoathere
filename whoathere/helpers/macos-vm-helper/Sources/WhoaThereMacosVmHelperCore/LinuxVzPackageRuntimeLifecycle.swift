import Darwin
import Foundation

public let linuxVzPackageRuntimeCloneBindingSchemaV1 =
    "whoathere.linux_vz_package_runtime_clone_binding.v1"
public let linuxVzPackageRuntimeCloneImplementationSHA256V1 = sha256(
    Data("whoathere.swift.fclonefileat.direct.v1".utf8)
)

public struct LinuxVzPackageRuntimeBaseLayout: Equatable, Sendable {
    public let stateDirectory: URL
    public let bundleDirectory: URL
    public let runtimeRunsDirectory: URL
    public let rootfsURL: URL
    public let runtimeManifestURL: URL
    public let packageRunnerURL: URL

    public init(stateDirectory: URL) {
        self.stateDirectory = stateDirectory
        bundleDirectory = stateDirectory.appendingPathComponent("bundle", isDirectory: true)
        runtimeRunsDirectory = stateDirectory.appendingPathComponent(
            "linux-vz-package-runtime-runs", isDirectory: true
        )
        rootfsURL = bundleDirectory.appendingPathComponent("rootfs.ext2")
        runtimeManifestURL = bundleDirectory.appendingPathComponent("runtime-manifest.json")
        packageRunnerURL = bundleDirectory.appendingPathComponent("package-runtime-probe")
    }

    public init(runtimeDirectory: URL) {
        stateDirectory = runtimeDirectory.deletingLastPathComponent()
        bundleDirectory = runtimeDirectory
        runtimeRunsDirectory = stateDirectory.appendingPathComponent(
            "linux-vz-package-runtime-runs", isDirectory: true
        )
        rootfsURL = runtimeDirectory.appendingPathComponent("rootfs.ext2")
        runtimeManifestURL = runtimeDirectory.appendingPathComponent("runtime-manifest.json")
        packageRunnerURL = runtimeDirectory.appendingPathComponent("package-runtime-probe")
    }
}

public struct LinuxVzPackageRuntimeBaseMeasurement: Equatable, Sendable {
    public let rootfsSHA256: String
    public let rootfsByteLength: UInt64
    public let runtimeManifestSHA256: String
    public let packageRunnerSHA256: String
}

public final class LockedLinuxVzPackageRuntimeBase {
    public let layout: LinuxVzPackageRuntimeBaseLayout
    public let manifest: ParsedLinuxVzPackageRuntimeManifest
    public let measurement: LinuxVzPackageRuntimeBaseMeasurement

    private let rootfs: LockedMeasuredFile
    private let runtimeManifest: LockedMeasuredFile
    private let packageRunner: LockedMeasuredFile

    fileprivate init(
        layout: LinuxVzPackageRuntimeBaseLayout,
        manifest: ParsedLinuxVzPackageRuntimeManifest,
        measurement: LinuxVzPackageRuntimeBaseMeasurement,
        rootfs: LockedMeasuredFile,
        runtimeManifest: LockedMeasuredFile,
        packageRunner: LockedMeasuredFile
    ) {
        self.layout = layout
        self.manifest = manifest
        self.measurement = measurement
        self.rootfs = rootfs
        self.runtimeManifest = runtimeManifest
        self.packageRunner = packageRunner
    }

    deinit {
        for descriptor in [rootfs.descriptor, runtimeManifest.descriptor, packageRunner.descriptor] {
            _ = flock(descriptor, LOCK_UN)
            _ = close(descriptor)
        }
    }

    public func createDisposableClone() throws -> DisposableLinuxVzPackageRuntimeClone {
        try verifyFileIdentity(rootfs)
        try verifyFileIdentity(runtimeManifest)
        try verifyFileIdentity(packageRunner)
        let rootDescriptor = try openOrCreateSecureDirectory(layout.runtimeRunsDirectory)
        var runDescriptor: Int32 = -1
        var runID = ""
        do {
            runID = try randomRunID()
            guard runID.withCString({ mkdirat(rootDescriptor, $0, 0o700) }) == 0 else {
                throw ArtifactRunLifecycleError.runDirectoryFailed
            }
            runDescriptor = runID.withCString {
                openat(rootDescriptor, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            }
            guard runDescriptor >= 0 else {
                throw ArtifactRunLifecycleError.runDirectoryFailed
            }
            try cloneMeasuredFile(rootfs, into: runDescriptor, name: "rootfs.ext2")
            guard "rootfs.ext2".withCString({
                fchmodat(runDescriptor, $0, 0o600, 0)
            }) == 0 else {
                throw ArtifactRunLifecycleError.cloneVerificationFailed
            }
            let cloneFile = try verifyClone(
                in: runDescriptor, name: "rootfs.ext2", source: rootfs
            )
            let binding = try canonicalJSONData([
                "base_rootfs_sha256": rootfs.sha256,
                "clone_file_device": String(cloneFile.device),
                "clone_file_inode": String(cloneFile.inode),
                "clone_implementation_sha256":
                    linuxVzPackageRuntimeCloneImplementationSHA256V1,
                "initial_rootfs_sha256": cloneFile.sha256,
                "run_id": runID,
                "schema_version": linuxVzPackageRuntimeCloneBindingSchemaV1
            ])
            try verifyFileIdentity(rootfs)
            try verifyFileIdentity(runtimeManifest)
            try verifyFileIdentity(packageRunner)
            return DisposableLinuxVzPackageRuntimeClone(
                base: self,
                baseRootfsSHA256: measurement.rootfsSHA256,
                rootDescriptor: rootDescriptor,
                runDescriptor: runDescriptor,
                runID: runID,
                runDirectory: layout.runtimeRunsDirectory.appendingPathComponent(
                    runID, isDirectory: true
                ),
                cloneFile: cloneFile,
                cloneBindingCanonicalJSON: binding
            )
        } catch {
            if runDescriptor >= 0 {
                _ = "rootfs.ext2".withCString { unlinkat(runDescriptor, $0, 0) }
                _ = close(runDescriptor)
            }
            if !runID.isEmpty {
                _ = runID.withCString { unlinkat(rootDescriptor, $0, AT_REMOVEDIR) }
            }
            _ = close(rootDescriptor)
            throw error
        }
    }
}

public final class LockedLinuxVzPackageExecutionRuntimeBase {
    public let layout: LinuxVzPackageRuntimeBaseLayout
    public let manifest: ParsedLinuxVzPackageExecutionRuntimeManifest
    public let measurement: LinuxVzPackageRuntimeBaseMeasurement

    private let rootfs: LockedMeasuredFile
    private let runtimeManifest: LockedMeasuredFile
    private let packageRunner: LockedMeasuredFile

    fileprivate init(
        layout: LinuxVzPackageRuntimeBaseLayout,
        manifest: ParsedLinuxVzPackageExecutionRuntimeManifest,
        measurement: LinuxVzPackageRuntimeBaseMeasurement,
        rootfs: LockedMeasuredFile,
        runtimeManifest: LockedMeasuredFile,
        packageRunner: LockedMeasuredFile
    ) {
        self.layout = layout
        self.manifest = manifest
        self.measurement = measurement
        self.rootfs = rootfs
        self.runtimeManifest = runtimeManifest
        self.packageRunner = packageRunner
    }

    deinit {
        for descriptor in [rootfs.descriptor, runtimeManifest.descriptor, packageRunner.descriptor] {
            _ = flock(descriptor, LOCK_UN)
            _ = close(descriptor)
        }
    }

    public func createDisposableClone() throws -> DisposableLinuxVzPackageRuntimeClone {
        try verifyFileIdentity(rootfs)
        try verifyFileIdentity(runtimeManifest)
        try verifyFileIdentity(packageRunner)
        let rootDescriptor = try openOrCreateSecureDirectory(layout.runtimeRunsDirectory)
        var runDescriptor: Int32 = -1
        var runID = ""
        do {
            runID = try randomRunID()
            guard runID.withCString({ mkdirat(rootDescriptor, $0, 0o700) }) == 0 else {
                throw ArtifactRunLifecycleError.runDirectoryFailed
            }
            runDescriptor = runID.withCString {
                openat(rootDescriptor, $0, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
            }
            guard runDescriptor >= 0 else {
                throw ArtifactRunLifecycleError.runDirectoryFailed
            }
            try cloneMeasuredFile(rootfs, into: runDescriptor, name: "rootfs.ext2")
            guard "rootfs.ext2".withCString({
                fchmodat(runDescriptor, $0, 0o600, 0)
            }) == 0 else {
                throw ArtifactRunLifecycleError.cloneVerificationFailed
            }
            let cloneFile = try verifyClone(
                in: runDescriptor, name: "rootfs.ext2", source: rootfs
            )
            let binding = try canonicalJSONData([
                "base_rootfs_sha256": rootfs.sha256,
                "clone_file_device": String(cloneFile.device),
                "clone_file_inode": String(cloneFile.inode),
                "clone_implementation_sha256":
                    linuxVzPackageRuntimeCloneImplementationSHA256V1,
                "initial_rootfs_sha256": cloneFile.sha256,
                "run_id": runID,
                "schema_version": linuxVzPackageRuntimeCloneBindingSchemaV1
            ])
            try verifyFileIdentity(rootfs)
            try verifyFileIdentity(runtimeManifest)
            try verifyFileIdentity(packageRunner)
            return DisposableLinuxVzPackageRuntimeClone(
                base: self,
                baseRootfsSHA256: measurement.rootfsSHA256,
                rootDescriptor: rootDescriptor,
                runDescriptor: runDescriptor,
                runID: runID,
                runDirectory: layout.runtimeRunsDirectory.appendingPathComponent(
                    runID, isDirectory: true
                ),
                cloneFile: cloneFile,
                cloneBindingCanonicalJSON: binding
            )
        } catch {
            if runDescriptor >= 0 {
                _ = "rootfs.ext2".withCString { unlinkat(runDescriptor, $0, 0) }
                _ = close(runDescriptor)
            }
            if !runID.isEmpty {
                _ = runID.withCString { unlinkat(rootDescriptor, $0, AT_REMOVEDIR) }
            }
            _ = close(rootDescriptor)
            throw error
        }
    }
}

public final class DisposableLinuxVzPackageRuntimeClone {
    public let runID: String
    public let runDirectory: URL
    public let rootfsURL: URL
    public let initialRootfsSHA256: String
    public let rootfsByteLength: UInt64
    public let cloneBindingCanonicalJSON: Data
    public let cloneBindingSHA256: String

    private let base: AnyObject
    private let baseRootfsSHA256: String
    private let cloneDevice: UInt64
    private let cloneInode: UInt64
    private var rootDescriptor: Int32
    private var runDescriptor: Int32
    private var cleaned = false
    private var preserveOnDeinit = false

    fileprivate init(
        base: AnyObject,
        baseRootfsSHA256: String,
        rootDescriptor: Int32,
        runDescriptor: Int32,
        runID: String,
        runDirectory: URL,
        cloneFile: LockedMeasuredFile,
        cloneBindingCanonicalJSON: Data
    ) {
        self.base = base
        self.baseRootfsSHA256 = baseRootfsSHA256
        self.rootDescriptor = rootDescriptor
        self.runDescriptor = runDescriptor
        self.runID = runID
        self.runDirectory = runDirectory
        rootfsURL = runDirectory.appendingPathComponent("rootfs.ext2")
        initialRootfsSHA256 = cloneFile.sha256
        rootfsByteLength = cloneFile.byteLength
        cloneDevice = cloneFile.device
        cloneInode = cloneFile.inode
        self.cloneBindingCanonicalJSON = cloneBindingCanonicalJSON
        cloneBindingSHA256 = sha256(cloneBindingCanonicalJSON)
    }

    deinit {
        if preserveOnDeinit {
            closeDescriptors()
        } else {
            try? cleanup()
        }
    }

    public func verifyReadyForAttachment() throws {
        guard !cleaned, runDescriptor >= 0 else {
            throw ArtifactRunLifecycleError.cloneVerificationFailed
        }
        let descriptor = "rootfs.ext2".withCString {
            openat(runDescriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
        }
        guard descriptor >= 0 else {
            throw ArtifactRunLifecycleError.cloneVerificationFailed
        }
        defer { _ = close(descriptor) }
        var status = stat()
        guard fstat(descriptor, &status) == 0,
              status.st_mode & S_IFMT == S_IFREG,
              status.st_nlink == 1,
              status.st_uid == geteuid(),
              status.st_mode & 0o777 == 0o600,
              UInt64(status.st_dev) == cloneDevice,
              status.st_ino == cloneInode,
              UInt64(status.st_size) == rootfsByteLength else {
            throw ArtifactRunLifecycleError.cloneVerificationFailed
        }
        let (digest, _) = try hashDescriptor(
            descriptor, expectedLength: rootfsByteLength, captureData: false
        )
        guard digest == initialRootfsSHA256,
              digest == baseRootfsSHA256 else {
            throw ArtifactRunLifecycleError.cloneVerificationFailed
        }
    }

    public func cleanup() throws {
        guard !cleaned else { return }
        var failed = false
        if runDescriptor >= 0 {
            let result = "rootfs.ext2".withCString { unlinkat(runDescriptor, $0, 0) }
            if result != 0 && errno != ENOENT { failed = true }
        }
        if rootDescriptor >= 0 {
            let removed = runID.withCString {
                unlinkat(rootDescriptor, $0, AT_REMOVEDIR)
            }
            if removed != 0 && errno != ENOENT { failed = true }
            var status = stat()
            let observed = runID.withCString {
                fstatat(rootDescriptor, $0, &status, AT_SYMLINK_NOFOLLOW)
            }
            if observed == 0 || errno != ENOENT { failed = true }
        }
        guard !failed else { throw ArtifactRunLifecycleError.cleanupFailed }
        var closeFailed = false
        if runDescriptor >= 0 {
            if close(runDescriptor) != 0 { closeFailed = true }
            runDescriptor = -1
        }
        if rootDescriptor >= 0 {
            if close(rootDescriptor) != 0 { closeFailed = true }
            rootDescriptor = -1
        }
        cleaned = true
        guard !closeFailed else { throw ArtifactRunLifecycleError.cleanupFailed }
    }

    public func preserveUntilVerifiedVMStop() {
        guard !cleaned else { return }
        preserveOnDeinit = true
    }

    private func closeDescriptors() {
        if runDescriptor >= 0 {
            _ = close(runDescriptor)
            runDescriptor = -1
        }
        if rootDescriptor >= 0 {
            _ = close(rootDescriptor)
            rootDescriptor = -1
        }
    }
}

public func verifyAndLockLinuxVzPackageRuntimeBase(
    layout: LinuxVzPackageRuntimeBaseLayout,
    expectedRootfsSHA256: String,
    expectedRootfsByteLength: UInt64,
    expectedRuntimeManifestSHA256: String,
    expectedPackageRunnerSHA256: String
) throws -> LockedLinuxVzPackageRuntimeBase {
    try requireSecureDirectory(layout.stateDirectory)
    try requireSecureDirectory(layout.bundleDirectory)
    var files: [LockedMeasuredFile] = []
    do {
        let rootfs = try openLockedMeasuredFile(layout.rootfsURL, dataLimit: nil)
        files.append(rootfs)
        let runtimeManifest = try openLockedMeasuredFile(
            layout.runtimeManifestURL,
            dataLimit: UInt64(maximumLinuxVzPackageRuntimeManifestBytesV1)
        )
        files.append(runtimeManifest)
        let packageRunner = try openLockedMeasuredFile(layout.packageRunnerURL, dataLimit: nil)
        files.append(packageRunner)
        guard let manifestData = runtimeManifest.boundedData else {
            throw ArtifactRunLifecycleError.baseFileUnsafe
        }
        let manifest = try decodeLinuxVzPackageRuntimeManifest(manifestData)
        guard rootfs.sha256 == expectedRootfsSHA256,
              rootfs.byteLength == expectedRootfsByteLength,
              runtimeManifest.sha256 == expectedRuntimeManifestSHA256,
              packageRunner.sha256 == expectedPackageRunnerSHA256,
              manifest.rootfsSHA256 == rootfs.sha256,
              manifest.rootfsByteLength == rootfs.byteLength,
              manifest.manifestSHA256 == runtimeManifest.sha256,
              manifest.packageRunnerSHA256 == packageRunner.sha256 else {
            throw ArtifactRunLifecycleError.baseDigestMismatch
        }
        return LockedLinuxVzPackageRuntimeBase(
            layout: layout,
            manifest: manifest,
            measurement: LinuxVzPackageRuntimeBaseMeasurement(
                rootfsSHA256: rootfs.sha256,
                rootfsByteLength: rootfs.byteLength,
                runtimeManifestSHA256: runtimeManifest.sha256,
                packageRunnerSHA256: packageRunner.sha256
            ),
            rootfs: rootfs,
            runtimeManifest: runtimeManifest,
            packageRunner: packageRunner
        )
    } catch {
        for file in files {
            _ = flock(file.descriptor, LOCK_UN)
            _ = close(file.descriptor)
        }
        throw error
    }
}

public func verifyAndLockLinuxVzPackageExecutionRuntimeBase(
    layout: LinuxVzPackageRuntimeBaseLayout,
    expectedRootfsSHA256: String,
    expectedRootfsByteLength: UInt64,
    expectedRuntimeManifestSHA256: String,
    expectedPackageRunnerSHA256: String
) throws -> LockedLinuxVzPackageExecutionRuntimeBase {
    try requireSecureDirectory(layout.stateDirectory)
    try requireSecureDirectory(layout.bundleDirectory)
    var files: [LockedMeasuredFile] = []
    do {
        let rootfs = try openLockedMeasuredFile(layout.rootfsURL, dataLimit: nil)
        files.append(rootfs)
        let runtimeManifest = try openLockedMeasuredFile(
            layout.runtimeManifestURL,
            dataLimit: UInt64(maximumLinuxVzPackageExecutionRuntimeManifestBytesV1)
        )
        files.append(runtimeManifest)
        let packageRunner = try openLockedMeasuredFile(layout.packageRunnerURL, dataLimit: nil)
        files.append(packageRunner)
        guard let manifestData = runtimeManifest.boundedData else {
            throw ArtifactRunLifecycleError.baseFileUnsafe
        }
        let manifest = try decodeLinuxVzPackageExecutionRuntimeManifest(manifestData)
        guard rootfs.sha256 == expectedRootfsSHA256,
              rootfs.byteLength == expectedRootfsByteLength,
              runtimeManifest.sha256 == expectedRuntimeManifestSHA256,
              packageRunner.sha256 == expectedPackageRunnerSHA256,
              manifest.rootfsSHA256 == rootfs.sha256,
              manifest.rootfsByteLength == rootfs.byteLength,
              manifest.manifestSHA256 == runtimeManifest.sha256,
              manifest.packageRunnerSHA256 == packageRunner.sha256 else {
            throw ArtifactRunLifecycleError.baseDigestMismatch
        }
        return LockedLinuxVzPackageExecutionRuntimeBase(
            layout: layout,
            manifest: manifest,
            measurement: LinuxVzPackageRuntimeBaseMeasurement(
                rootfsSHA256: rootfs.sha256,
                rootfsByteLength: rootfs.byteLength,
                runtimeManifestSHA256: runtimeManifest.sha256,
                packageRunnerSHA256: packageRunner.sha256
            ),
            rootfs: rootfs,
            runtimeManifest: runtimeManifest,
            packageRunner: packageRunner
        )
    } catch {
        for file in files {
            _ = flock(file.descriptor, LOCK_UN)
            _ = close(file.descriptor)
        }
        throw error
    }
}
