import CryptoKit
import Darwin
import Foundation
import Security

public enum ArtifactRunLifecycleError: Error, Equatable, CustomStringConvertible {
    case baseLayoutUnsafe
    case baseRuntimeActive
    case baseFileUnsafe
    case baseLockUnavailable
    case baseDigestMismatch
    case helperDigestMismatch
    case provisioningReceiptInvalid
    case wheelProvisioningReceiptInvalid
    case sdistProvisioningReceiptInvalid
    case metadataLimitExceeded
    case randomGenerationFailed
    case runDirectoryFailed
    case cloneUnsupported
    case cloneFailed
    case cloneVerificationFailed
    case cleanupFailed
    case virtualizationMetadataInvalid
    case virtualizationConfigurationInvalid

    public var description: String {
        switch self {
        case .baseLayoutUnsafe: return "artifact_run_base_layout_unsafe"
        case .baseRuntimeActive: return "artifact_run_base_runtime_active"
        case .baseFileUnsafe: return "artifact_run_base_file_unsafe"
        case .baseLockUnavailable: return "artifact_run_base_lock_unavailable"
        case .baseDigestMismatch: return "artifact_run_base_digest_mismatch"
        case .helperDigestMismatch: return "artifact_run_helper_digest_mismatch"
        case .provisioningReceiptInvalid:
            return "artifact_run_supervisor_provisioning_receipt_invalid"
        case .wheelProvisioningReceiptInvalid:
            return "wheel_run_supervisor_provisioning_receipt_invalid"
        case .sdistProvisioningReceiptInvalid:
            return "sdist_run_supervisor_provisioning_receipt_invalid"
        case .metadataLimitExceeded: return "artifact_run_metadata_limit_exceeded"
        case .randomGenerationFailed: return "artifact_run_random_generation_failed"
        case .runDirectoryFailed: return "artifact_run_directory_failed"
        case .cloneUnsupported: return "artifact_run_apfs_clone_unsupported"
        case .cloneFailed: return "artifact_run_apfs_clone_failed"
        case .cloneVerificationFailed: return "artifact_run_apfs_clone_verification_failed"
        case .cleanupFailed: return "artifact_run_clone_cleanup_failed"
        case .virtualizationMetadataInvalid: return "artifact_run_virtualization_metadata_invalid"
        case .virtualizationConfigurationInvalid:
            return "artifact_run_virtualization_configuration_invalid"
        }
    }
}

public struct ArtifactRunBaseLayout: Equatable, Sendable {
    public let stateDirectory: URL
    public let bundleDirectory: URL
    public let artifactRunsDirectory: URL
    public let diskURL: URL
    public let auxiliaryStorageURL: URL
    public let hardwareModelURL: URL
    public let machineIdentifierURL: URL
    public let guestAuthPublicKeyURL: URL
    public let postProvisioningReceiptURL: URL
    public let runtimePIDURL: URL

    public init(stateDirectory: URL) {
        self.stateDirectory = stateDirectory
        bundleDirectory = stateDirectory.appendingPathComponent("bundle", isDirectory: true)
        artifactRunsDirectory = stateDirectory.appendingPathComponent(
            "artifact-runs", isDirectory: true
        )
        diskURL = bundleDirectory.appendingPathComponent("disk.img")
        auxiliaryStorageURL = bundleDirectory.appendingPathComponent("auxiliary-storage")
        hardwareModelURL = bundleDirectory.appendingPathComponent("hardware-model.bin")
        machineIdentifierURL = bundleDirectory.appendingPathComponent("machine-identifier.bin")
        guestAuthPublicKeyURL = bundleDirectory.appendingPathComponent(
            "artifact-supervisor-public-key.bin"
        )
        postProvisioningReceiptURL = bundleDirectory.appendingPathComponent(
            "artifact-supervisor-provisioning.json"
        )
        runtimePIDURL = bundleDirectory.appendingPathComponent("runtime.pid")
    }
}

public struct ArtifactRunBaseMeasurement: Equatable, Sendable {
    public let baseGenerationID: String
    public let diskSHA256: String
    public let diskByteLength: UInt64
    public let auxiliaryStorageSHA256: String
    public let auxiliaryStorageByteLength: UInt64
    public let hardwareModelSHA256: String
    public let machineIdentifierSHA256: String
    public let guestAuthPublicKeySHA256: String
    public let postProvisioningReceiptSHA256: String
    public let helperSHA256: String
}

struct LockedMeasuredFile {
    let descriptor: Int32
    let device: UInt64
    let inode: UInt64
    let byteLength: UInt64
    let sha256: String
    let boundedData: Data?
}

public final class LockedArtifactRunBase {
    public let layout: ArtifactRunBaseLayout
    public let identity: ArtifactRunBackendIdentity
    public let measurement: ArtifactRunBaseMeasurement
    public let hardwareModelData: Data
    public let machineIdentifierData: Data
    public let guestAuthPublicKeyData: Data

    private let disk: LockedMeasuredFile
    private let auxiliaryStorage: LockedMeasuredFile
    private let heldDescriptors: [Int32]

    fileprivate init(
        layout: ArtifactRunBaseLayout,
        identity: ArtifactRunBackendIdentity,
        measurement: ArtifactRunBaseMeasurement,
        hardwareModelData: Data,
        machineIdentifierData: Data,
        guestAuthPublicKeyData: Data,
        disk: LockedMeasuredFile,
        auxiliaryStorage: LockedMeasuredFile,
        heldDescriptors: [Int32]
    ) {
        self.layout = layout
        self.identity = identity
        self.measurement = measurement
        self.hardwareModelData = hardwareModelData
        self.machineIdentifierData = machineIdentifierData
        self.guestAuthPublicKeyData = guestAuthPublicKeyData
        self.disk = disk
        self.auxiliaryStorage = auxiliaryStorage
        self.heldDescriptors = heldDescriptors
    }

    deinit {
        for descriptor in heldDescriptors {
            _ = flock(descriptor, LOCK_UN)
            _ = close(descriptor)
        }
    }

    public func createDisposableClone() throws -> DisposableArtifactRunClone {
        try verifyFileIdentity(disk)
        try verifyFileIdentity(auxiliaryStorage)
        let rootDescriptor = try openOrCreateSecureDirectory(layout.artifactRunsDirectory)
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
            try cloneMeasuredFile(disk, into: runDescriptor, name: "disk.img")
            try cloneMeasuredFile(
                auxiliaryStorage, into: runDescriptor, name: "auxiliary-storage"
            )
            let diskClone = try verifyClone(
                in: runDescriptor, name: "disk.img", source: disk
            )
            let auxiliaryClone = try verifyClone(
                in: runDescriptor, name: "auxiliary-storage", source: auxiliaryStorage
            )
            try verifyFileIdentity(disk)
            try verifyFileIdentity(auxiliaryStorage)
            return DisposableArtifactRunClone(
                base: self,
                rootDescriptor: rootDescriptor,
                runDescriptor: runDescriptor,
                runID: runID,
                runDirectory: layout.artifactRunsDirectory.appendingPathComponent(
                    runID, isDirectory: true
                ),
                diskClone: diskClone,
                auxiliaryClone: auxiliaryClone
            )
        } catch {
            if runDescriptor >= 0 {
                removeCloneMembers(runDescriptor)
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

public final class DisposableArtifactRunClone {
    public let runID: String
    public let runDirectory: URL
    public let diskURL: URL
    public let auxiliaryStorageURL: URL
    public let diskSHA256: String
    public let auxiliaryStorageSHA256: String

    private let base: LockedArtifactRunBase
    private var rootDescriptor: Int32
    private var runDescriptor: Int32
    private var cleaned = false

    fileprivate init(
        base: LockedArtifactRunBase,
        rootDescriptor: Int32,
        runDescriptor: Int32,
        runID: String,
        runDirectory: URL,
        diskClone: LockedMeasuredFile,
        auxiliaryClone: LockedMeasuredFile
    ) {
        self.base = base
        self.rootDescriptor = rootDescriptor
        self.runDescriptor = runDescriptor
        self.runID = runID
        self.runDirectory = runDirectory
        diskURL = runDirectory.appendingPathComponent("disk.img")
        auxiliaryStorageURL = runDirectory.appendingPathComponent("auxiliary-storage")
        diskSHA256 = diskClone.sha256
        auxiliaryStorageSHA256 = auxiliaryClone.sha256
    }

    deinit {
        try? cleanup()
    }

    public func cleanup() throws {
        guard !cleaned else { return }
        var failed = false
        if runDescriptor >= 0 {
            for name in ["disk.img", "auxiliary-storage"] {
                let result = name.withCString { unlinkat(runDescriptor, $0, 0) }
                if result != 0 && errno != ENOENT { failed = true }
            }
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
        guard !failed else {
            throw ArtifactRunLifecycleError.cleanupFailed
        }
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
        guard !closeFailed else {
            throw ArtifactRunLifecycleError.cleanupFailed
        }
    }
}

public func verifyAndLockArtifactRunBase(
    layout: ArtifactRunBaseLayout,
    identity: ArtifactRunBackendIdentity,
    helperURL: URL
) throws -> LockedArtifactRunBase {
    try requireSecureDirectory(layout.stateDirectory)
    try requireSecureDirectory(layout.bundleDirectory)
    try requireStoppedRuntime(layout.runtimePIDURL)

    var files: [LockedMeasuredFile] = []
    do {
        let disk = try openLockedMeasuredFile(layout.diskURL, dataLimit: nil)
        files.append(disk)
        let auxiliary = try openLockedMeasuredFile(layout.auxiliaryStorageURL, dataLimit: nil)
        files.append(auxiliary)
        let hardware = try openLockedMeasuredFile(
            layout.hardwareModelURL, dataLimit: 1024 * 1024
        )
        files.append(hardware)
        let machine = try openLockedMeasuredFile(
            layout.machineIdentifierURL, dataLimit: 1024 * 1024
        )
        files.append(machine)
        let receipt = try openLockedMeasuredFile(
            layout.postProvisioningReceiptURL, dataLimit: 4 * 1024 * 1024
        )
        files.append(receipt)
        let guestAuthPublicKey = try openLockedMeasuredFile(
            layout.guestAuthPublicKeyURL, dataLimit: 32
        )
        files.append(guestAuthPublicKey)
        let helper = try openLockedMeasuredFile(helperURL, dataLimit: 64 * 1024 * 1024)
        files.append(helper)

        guard disk.sha256 == identity.baseDiskSHA256,
              auxiliary.sha256 == identity.baseAuxiliaryStorageSHA256,
              hardware.sha256 == identity.hardwareModelSHA256,
              machine.sha256 == identity.machineIdentifierSHA256,
              guestAuthPublicKey.sha256 == identity.guestAuthPublicKeySHA256,
              receipt.sha256 == identity.postProvisioningReceiptSHA256 else {
            throw ArtifactRunLifecycleError.baseDigestMismatch
        }
        guard helper.sha256 == identity.helperSHA256 else {
            throw ArtifactRunLifecycleError.helperDigestMismatch
        }
        guard let hardwareData = hardware.boundedData,
              let machineData = machine.boundedData,
              let receiptData = receipt.boundedData,
              let guestAuthPublicKeyData = guestAuthPublicKey.boundedData,
              guestAuthPublicKeyData.count == 32 else {
            throw ArtifactRunLifecycleError.baseFileUnsafe
        }
        _ = try verifyArtifactSupervisorProvisioningReceipt(
            receiptData,
            identity: identity,
            guestAuthPublicKey: guestAuthPublicKeyData
        )
        let measurement = ArtifactRunBaseMeasurement(
            baseGenerationID: identity.baseGenerationID,
            diskSHA256: disk.sha256,
            diskByteLength: disk.byteLength,
            auxiliaryStorageSHA256: auxiliary.sha256,
            auxiliaryStorageByteLength: auxiliary.byteLength,
            hardwareModelSHA256: hardware.sha256,
            machineIdentifierSHA256: machine.sha256,
            guestAuthPublicKeySHA256: guestAuthPublicKey.sha256,
            postProvisioningReceiptSHA256: receipt.sha256,
            helperSHA256: helper.sha256
        )
        return LockedArtifactRunBase(
            layout: layout,
            identity: identity,
            measurement: measurement,
            hardwareModelData: hardwareData,
            machineIdentifierData: machineData,
            guestAuthPublicKeyData: guestAuthPublicKeyData,
            disk: disk,
            auxiliaryStorage: auxiliary,
            heldDescriptors: files.map(\.descriptor)
        )
    } catch {
        for file in files {
            _ = flock(file.descriptor, LOCK_UN)
            _ = close(file.descriptor)
        }
        throw error
    }
}

public struct WheelRunBaseLayout: Equatable, Sendable {
    public let stateDirectory: URL
    public let bundleDirectory: URL
    public let wheelRunsDirectory: URL
    public let diskURL: URL
    public let auxiliaryStorageURL: URL
    public let hardwareModelURL: URL
    public let machineIdentifierURL: URL
    public let guestAuthPublicKeyURL: URL
    public let postProvisioningReceiptURL: URL
    public let runtimePIDURL: URL

    public init(stateDirectory: URL) {
        self.stateDirectory = stateDirectory
        bundleDirectory = stateDirectory.appendingPathComponent("bundle", isDirectory: true)
        wheelRunsDirectory = stateDirectory.appendingPathComponent(
            "wheel-runs", isDirectory: true
        )
        diskURL = bundleDirectory.appendingPathComponent("disk.img")
        auxiliaryStorageURL = bundleDirectory.appendingPathComponent("auxiliary-storage")
        hardwareModelURL = bundleDirectory.appendingPathComponent("hardware-model.bin")
        machineIdentifierURL = bundleDirectory.appendingPathComponent("machine-identifier.bin")
        guestAuthPublicKeyURL = bundleDirectory.appendingPathComponent(
            "wheel-supervisor-public-key.bin"
        )
        postProvisioningReceiptURL = bundleDirectory.appendingPathComponent(
            "wheel-supervisor-provisioning.json"
        )
        runtimePIDURL = bundleDirectory.appendingPathComponent("runtime.pid")
    }
}

public struct WheelRunBaseMeasurement: Equatable, Sendable {
    public let baseGenerationID: String
    public let diskSHA256: String
    public let diskByteLength: UInt64
    public let auxiliaryStorageSHA256: String
    public let auxiliaryStorageByteLength: UInt64
    public let hardwareModelSHA256: String
    public let machineIdentifierSHA256: String
    public let guestAuthPublicKeySHA256: String
    public let postProvisioningReceiptSHA256: String
    public let helperSHA256: String
}

public final class LockedWheelRunBase {
    public let layout: WheelRunBaseLayout
    public let identity: WheelRunBackendIdentity
    public let measurement: WheelRunBaseMeasurement
    public let hardwareModelData: Data
    public let machineIdentifierData: Data
    public let guestAuthPublicKeyData: Data

    private let disk: LockedMeasuredFile
    private let auxiliaryStorage: LockedMeasuredFile
    private let heldDescriptors: [Int32]

    fileprivate init(
        layout: WheelRunBaseLayout,
        identity: WheelRunBackendIdentity,
        measurement: WheelRunBaseMeasurement,
        hardwareModelData: Data,
        machineIdentifierData: Data,
        guestAuthPublicKeyData: Data,
        disk: LockedMeasuredFile,
        auxiliaryStorage: LockedMeasuredFile,
        heldDescriptors: [Int32]
    ) {
        self.layout = layout
        self.identity = identity
        self.measurement = measurement
        self.hardwareModelData = hardwareModelData
        self.machineIdentifierData = machineIdentifierData
        self.guestAuthPublicKeyData = guestAuthPublicKeyData
        self.disk = disk
        self.auxiliaryStorage = auxiliaryStorage
        self.heldDescriptors = heldDescriptors
    }

    deinit {
        for descriptor in heldDescriptors {
            _ = flock(descriptor, LOCK_UN)
            _ = close(descriptor)
        }
    }

    public func createDisposableClone() throws -> DisposableWheelRunClone {
        try verifyFileIdentity(disk)
        try verifyFileIdentity(auxiliaryStorage)
        let rootDescriptor = try openOrCreateSecureDirectory(layout.wheelRunsDirectory)
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
            try cloneMeasuredFile(disk, into: runDescriptor, name: "disk.img")
            try cloneMeasuredFile(
                auxiliaryStorage, into: runDescriptor, name: "auxiliary-storage"
            )
            let diskClone = try verifyClone(
                in: runDescriptor, name: "disk.img", source: disk
            )
            let auxiliaryClone = try verifyClone(
                in: runDescriptor, name: "auxiliary-storage", source: auxiliaryStorage
            )
            try verifyFileIdentity(disk)
            try verifyFileIdentity(auxiliaryStorage)
            return DisposableWheelRunClone(
                base: self,
                rootDescriptor: rootDescriptor,
                runDescriptor: runDescriptor,
                runID: runID,
                runDirectory: layout.wheelRunsDirectory.appendingPathComponent(
                    runID, isDirectory: true
                ),
                diskClone: diskClone,
                auxiliaryClone: auxiliaryClone
            )
        } catch {
            if runDescriptor >= 0 {
                removeCloneMembers(runDescriptor)
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

public final class DisposableWheelRunClone {
    public let runID: String
    public let runDirectory: URL
    public let diskURL: URL
    public let auxiliaryStorageURL: URL
    public let diskSHA256: String
    public let auxiliaryStorageSHA256: String

    private let base: LockedWheelRunBase
    private var rootDescriptor: Int32
    private var runDescriptor: Int32
    private var cleaned = false

    fileprivate init(
        base: LockedWheelRunBase,
        rootDescriptor: Int32,
        runDescriptor: Int32,
        runID: String,
        runDirectory: URL,
        diskClone: LockedMeasuredFile,
        auxiliaryClone: LockedMeasuredFile
    ) {
        self.base = base
        self.rootDescriptor = rootDescriptor
        self.runDescriptor = runDescriptor
        self.runID = runID
        self.runDirectory = runDirectory
        diskURL = runDirectory.appendingPathComponent("disk.img")
        auxiliaryStorageURL = runDirectory.appendingPathComponent("auxiliary-storage")
        diskSHA256 = diskClone.sha256
        auxiliaryStorageSHA256 = auxiliaryClone.sha256
    }

    deinit {
        try? cleanup()
    }

    public func cleanup() throws {
        guard !cleaned else { return }
        var failed = false
        if runDescriptor >= 0 {
            for name in ["disk.img", "auxiliary-storage"] {
                let result = name.withCString { unlinkat(runDescriptor, $0, 0) }
                if result != 0 && errno != ENOENT { failed = true }
            }
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
        guard !failed else {
            throw ArtifactRunLifecycleError.cleanupFailed
        }
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
        guard !closeFailed else {
            throw ArtifactRunLifecycleError.cleanupFailed
        }
    }
}

public func verifyAndLockWheelRunBase(
    layout: WheelRunBaseLayout,
    identity: WheelRunBackendIdentity,
    helperURL: URL
) throws -> LockedWheelRunBase {
    try requireSecureDirectory(layout.stateDirectory)
    try requireSecureDirectory(layout.bundleDirectory)
    try requireStoppedRuntime(layout.runtimePIDURL)

    var files: [LockedMeasuredFile] = []
    do {
        let disk = try openLockedMeasuredFile(layout.diskURL, dataLimit: nil)
        files.append(disk)
        let auxiliary = try openLockedMeasuredFile(layout.auxiliaryStorageURL, dataLimit: nil)
        files.append(auxiliary)
        let hardware = try openLockedMeasuredFile(
            layout.hardwareModelURL, dataLimit: 1024 * 1024
        )
        files.append(hardware)
        let machine = try openLockedMeasuredFile(
            layout.machineIdentifierURL, dataLimit: 1024 * 1024
        )
        files.append(machine)
        let receipt = try openLockedMeasuredFile(
            layout.postProvisioningReceiptURL, dataLimit: 4 * 1024 * 1024
        )
        files.append(receipt)
        let guestAuthPublicKey = try openLockedMeasuredFile(
            layout.guestAuthPublicKeyURL, dataLimit: 32
        )
        files.append(guestAuthPublicKey)
        let helper = try openLockedMeasuredFile(helperURL, dataLimit: 64 * 1024 * 1024)
        files.append(helper)

        guard disk.sha256 == identity.baseDiskSHA256,
              auxiliary.sha256 == identity.baseAuxiliaryStorageSHA256,
              hardware.sha256 == identity.hardwareModelSHA256,
              machine.sha256 == identity.machineIdentifierSHA256,
              guestAuthPublicKey.sha256 == identity.guestAuthPublicKeySHA256,
              receipt.sha256 == identity.postProvisioningReceiptSHA256 else {
            throw ArtifactRunLifecycleError.baseDigestMismatch
        }
        guard helper.sha256 == identity.helperSHA256 else {
            throw ArtifactRunLifecycleError.helperDigestMismatch
        }
        guard let hardwareData = hardware.boundedData,
              let machineData = machine.boundedData,
              let receiptData = receipt.boundedData,
              let guestAuthPublicKeyData = guestAuthPublicKey.boundedData,
              guestAuthPublicKeyData.count == 32 else {
            throw ArtifactRunLifecycleError.baseFileUnsafe
        }
        _ = try verifyWheelSupervisorProvisioningReceipt(
            receiptData,
            identity: identity,
            guestAuthPublicKey: guestAuthPublicKeyData
        )
        let measurement = WheelRunBaseMeasurement(
            baseGenerationID: identity.baseGenerationID,
            diskSHA256: disk.sha256,
            diskByteLength: disk.byteLength,
            auxiliaryStorageSHA256: auxiliary.sha256,
            auxiliaryStorageByteLength: auxiliary.byteLength,
            hardwareModelSHA256: hardware.sha256,
            machineIdentifierSHA256: machine.sha256,
            guestAuthPublicKeySHA256: guestAuthPublicKey.sha256,
            postProvisioningReceiptSHA256: receipt.sha256,
            helperSHA256: helper.sha256
        )
        return LockedWheelRunBase(
            layout: layout,
            identity: identity,
            measurement: measurement,
            hardwareModelData: hardwareData,
            machineIdentifierData: machineData,
            guestAuthPublicKeyData: guestAuthPublicKeyData,
            disk: disk,
            auxiliaryStorage: auxiliary,
            heldDescriptors: files.map(\.descriptor)
        )
    } catch {
        for file in files {
            _ = flock(file.descriptor, LOCK_UN)
            _ = close(file.descriptor)
        }
        throw error
    }
}

func requireSecureDirectory(_ url: URL) throws {
    var status = stat()
    guard lstat(url.path, &status) == 0,
          status.st_mode & S_IFMT == S_IFDIR,
          status.st_uid == geteuid(),
          status.st_mode & 0o022 == 0 else {
        throw ArtifactRunLifecycleError.baseLayoutUnsafe
    }
}

func requireStoppedRuntime(_ pidURL: URL) throws {
    var status = stat()
    if lstat(pidURL.path, &status) != 0 {
        guard errno == ENOENT else {
            throw ArtifactRunLifecycleError.baseRuntimeActive
        }
        return
    }
    guard status.st_mode & S_IFMT == S_IFREG,
          status.st_uid == geteuid(),
          status.st_mode & 0o022 == 0,
          status.st_size > 0,
          status.st_size <= 32,
          let bytes = try? Data(contentsOf: pidURL, options: [.uncached]),
          let text = String(data: bytes, encoding: .utf8)?.trimmingCharacters(
            in: .whitespacesAndNewlines
          ),
          let pid = Int32(text), pid > 0 else {
        throw ArtifactRunLifecycleError.baseRuntimeActive
    }
    errno = 0
    guard kill(pid, 0) != 0, errno == ESRCH else {
        throw ArtifactRunLifecycleError.baseRuntimeActive
    }
}

func openLockedMeasuredFile(
    _ url: URL,
    dataLimit: UInt64?
) throws -> LockedMeasuredFile {
    let descriptor = open(url.path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
    var shouldClose = true
    defer {
        if shouldClose { _ = close(descriptor) }
    }
    var status = stat()
    guard fstat(descriptor, &status) == 0,
          status.st_mode & S_IFMT == S_IFREG,
          status.st_nlink == 1,
          status.st_uid == geteuid(),
          status.st_mode & 0o022 == 0,
          status.st_size > 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
    let byteLength = UInt64(status.st_size)
    if let dataLimit, byteLength > dataLimit {
        throw ArtifactRunLifecycleError.metadataLimitExceeded
    }
    guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
        throw ArtifactRunLifecycleError.baseLockUnavailable
    }
    do {
        let (digest, data) = try hashDescriptor(
            descriptor, expectedLength: byteLength, captureData: dataLimit != nil
        )
        shouldClose = false
        return LockedMeasuredFile(
            descriptor: descriptor,
            device: UInt64(status.st_dev),
            inode: status.st_ino,
            byteLength: byteLength,
            sha256: digest,
            boundedData: data
        )
    } catch {
        _ = flock(descriptor, LOCK_UN)
        throw error
    }
}

func hashDescriptor(
    _ descriptor: Int32,
    expectedLength: UInt64,
    captureData: Bool
) throws -> (String, Data?) {
    guard lseek(descriptor, 0, SEEK_SET) == 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
    var hasher = SHA256()
    var captured = captureData ? Data() : nil
    var observed: UInt64 = 0
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
        let count = read(descriptor, &buffer, buffer.count)
        if count == 0 { break }
        guard count > 0 else {
            if errno == EINTR { continue }
            throw ArtifactRunLifecycleError.baseFileUnsafe
        }
        let chunk = Data(buffer[0..<count])
        hasher.update(data: chunk)
        captured?.append(chunk)
        observed += UInt64(count)
        guard observed <= expectedLength else {
            throw ArtifactRunLifecycleError.baseFileUnsafe
        }
    }
    guard observed == expectedLength, lseek(descriptor, 0, SEEK_SET) == 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
    let digest = "sha256:" + hasher.finalize().map { String(format: "%02x", $0) }.joined()
    return (digest, captured)
}

func verifyFileIdentity(_ file: LockedMeasuredFile) throws {
    var status = stat()
    guard fstat(file.descriptor, &status) == 0,
          UInt64(status.st_dev) == file.device,
          status.st_ino == file.inode,
          UInt64(status.st_size) == file.byteLength,
          status.st_mode & S_IFMT == S_IFREG,
          status.st_nlink == 1,
          status.st_uid == geteuid(),
          status.st_mode & 0o022 == 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
}

func openOrCreateSecureDirectory(_ url: URL) throws -> Int32 {
    if mkdir(url.path, 0o700) != 0 && errno != EEXIST {
        throw ArtifactRunLifecycleError.runDirectoryFailed
    }
    try requireSecureDirectory(url)
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else {
        throw ArtifactRunLifecycleError.runDirectoryFailed
    }
    return descriptor
}

func randomRunID() throws -> String {
    var bytes = [UInt8](repeating: 0, count: 16)
    guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
        throw ArtifactRunLifecycleError.randomGenerationFailed
    }
    return bytes.map { String(format: "%02x", $0) }.joined()
}

func cloneMeasuredFile(
    _ source: LockedMeasuredFile,
    into directoryDescriptor: Int32,
    name: String
) throws {
    errno = 0
    let result = name.withCString {
        fclonefileat(source.descriptor, directoryDescriptor, $0, 0)
    }
    guard result == 0 else {
        if errno == ENOTSUP || errno == EXDEV {
            throw ArtifactRunLifecycleError.cloneUnsupported
        }
        throw ArtifactRunLifecycleError.cloneFailed
    }
}

func verifyClone(
    in directoryDescriptor: Int32,
    name: String,
    source: LockedMeasuredFile
) throws -> LockedMeasuredFile {
    let descriptor = name.withCString {
        openat(directoryDescriptor, $0, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
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
          status.st_mode & 0o022 == 0,
          UInt64(status.st_size) == source.byteLength,
          !(UInt64(status.st_dev) == source.device && status.st_ino == source.inode) else {
        throw ArtifactRunLifecycleError.cloneVerificationFailed
    }
    let (digest, _) = try hashDescriptor(
        descriptor, expectedLength: source.byteLength, captureData: false
    )
    guard digest == source.sha256 else {
        throw ArtifactRunLifecycleError.cloneVerificationFailed
    }
    return LockedMeasuredFile(
        descriptor: -1,
        device: UInt64(status.st_dev),
        inode: status.st_ino,
        byteLength: source.byteLength,
        sha256: digest,
        boundedData: nil
    )
}

func removeCloneMembers(_ runDescriptor: Int32) {
    for name in ["disk.img", "auxiliary-storage"] {
        _ = name.withCString { unlinkat(runDescriptor, $0, 0) }
    }
}
