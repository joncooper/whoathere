import Darwin
import Foundation

public struct SdistRunBaseLayout: Equatable, Sendable {
    public let stateDirectory: URL
    public let bundleDirectory: URL
    public let sdistRunsDirectory: URL
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
        sdistRunsDirectory = stateDirectory.appendingPathComponent(
            "sdist-runs", isDirectory: true
        )
        diskURL = bundleDirectory.appendingPathComponent("disk.img")
        auxiliaryStorageURL = bundleDirectory.appendingPathComponent("auxiliary-storage")
        hardwareModelURL = bundleDirectory.appendingPathComponent("hardware-model.bin")
        machineIdentifierURL = bundleDirectory.appendingPathComponent("machine-identifier.bin")
        guestAuthPublicKeyURL = bundleDirectory.appendingPathComponent(
            "sdist-supervisor-public-key.bin"
        )
        postProvisioningReceiptURL = bundleDirectory.appendingPathComponent(
            "sdist-supervisor-provisioning.json"
        )
        runtimePIDURL = bundleDirectory.appendingPathComponent("runtime.pid")
    }
}

public struct SdistRunBaseMeasurement: Equatable, Sendable {
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

public final class LockedSdistRunBase {
    public let layout: SdistRunBaseLayout
    public let identity: SdistRunBackendIdentity
    public let measurement: SdistRunBaseMeasurement
    public let hardwareModelData: Data
    public let machineIdentifierData: Data
    public let guestAuthPublicKeyData: Data

    private let disk: LockedMeasuredFile
    private let auxiliaryStorage: LockedMeasuredFile
    private let heldDescriptors: [Int32]

    fileprivate init(
        layout: SdistRunBaseLayout,
        identity: SdistRunBackendIdentity,
        measurement: SdistRunBaseMeasurement,
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

    public func createDisposableClone() throws -> DisposableSdistRunClone {
        try verifyFileIdentity(disk)
        try verifyFileIdentity(auxiliaryStorage)
        let rootDescriptor = try openOrCreateSecureDirectory(layout.sdistRunsDirectory)
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
            return DisposableSdistRunClone(
                rootDescriptor: rootDescriptor,
                runDescriptor: runDescriptor,
                runID: runID,
                runDirectory: layout.sdistRunsDirectory.appendingPathComponent(
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

public final class DisposableSdistRunClone {
    public let runID: String
    public let runDirectory: URL
    public let diskURL: URL
    public let auxiliaryStorageURL: URL
    public let diskSHA256: String
    public let auxiliaryStorageSHA256: String

    private var rootDescriptor: Int32
    private var runDescriptor: Int32
    private var cleaned = false

    fileprivate init(
        rootDescriptor: Int32,
        runDescriptor: Int32,
        runID: String,
        runDirectory: URL,
        diskClone: LockedMeasuredFile,
        auxiliaryClone: LockedMeasuredFile
    ) {
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
}

public func verifyAndLockSdistRunBase(
    layout: SdistRunBaseLayout,
    identity: SdistRunBackendIdentity,
    helperURL: URL
) throws -> LockedSdistRunBase {
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
        _ = try verifySdistSupervisorProvisioningReceipt(
            receiptData,
            identity: identity,
            guestAuthPublicKey: guestAuthPublicKeyData
        )
        let measurement = SdistRunBaseMeasurement(
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
        return LockedSdistRunBase(
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
