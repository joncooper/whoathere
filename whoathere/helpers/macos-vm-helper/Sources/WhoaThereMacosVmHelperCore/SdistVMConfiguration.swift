import Foundation
@preconcurrency import Virtualization

public struct SdistVMConfigurationContract: Equatable, Sendable {
    public let diskURL: URL
    public let auxiliaryStorageURL: URL
    public let cpuCount: Int
    public let memoryBytes: UInt64
    public let networkDeviceCount: Int
    public let socketDeviceCount: Int
    public let writableStorageDeviceCount: Int
    public let guestToolsAttached: Bool
    public let guestVSOCKPort: UInt32
}

public func sdistVMConfigurationContract(
    base: LockedSdistRunBase,
    clone: DisposableSdistRunClone
) throws -> SdistVMConfigurationContract {
    let (memoryBytes, overflow) = base.identity.memoryMiB.multipliedReportingOverflow(
        by: 1_048_576
    )
    guard !overflow else {
        throw ArtifactRunLifecycleError.virtualizationConfigurationInvalid
    }
    return SdistVMConfigurationContract(
        diskURL: clone.diskURL,
        auxiliaryStorageURL: clone.auxiliaryStorageURL,
        cpuCount: Int(base.identity.cpuCount),
        memoryBytes: memoryBytes,
        networkDeviceCount: 0,
        socketDeviceCount: 1,
        writableStorageDeviceCount: 1,
        guestToolsAttached: false,
        guestVSOCKPort: sdistGuestVSOCKPortV1
    )
}

public func buildSdistScenarioConfiguration(
    base: LockedSdistRunBase,
    clone: DisposableSdistRunClone
) throws -> VZVirtualMachineConfiguration {
    let contract = try sdistVMConfigurationContract(base: base, clone: clone)
    guard let hardwareModel = VZMacHardwareModel(
        dataRepresentation: base.hardwareModelData
    ), hardwareModel.isSupported,
          let machineIdentifier = VZMacMachineIdentifier(
            dataRepresentation: base.machineIdentifierData
          ),
          contract.cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
          contract.cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount,
          contract.memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
          contract.memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize else {
        throw ArtifactRunLifecycleError.virtualizationMetadataInvalid
    }

    let auxiliaryStorage = VZMacAuxiliaryStorage(url: contract.auxiliaryStorageURL)
    let platform = VZMacPlatformConfiguration()
    platform.hardwareModel = hardwareModel
    platform.machineIdentifier = machineIdentifier
    platform.auxiliaryStorage = auxiliaryStorage

    let diskAttachment: VZDiskImageStorageDeviceAttachment
    do {
        diskAttachment = try VZDiskImageStorageDeviceAttachment(
            url: contract.diskURL,
            readOnly: false
        )
    } catch {
        throw ArtifactRunLifecycleError.virtualizationConfigurationInvalid
    }
    let storage = VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)
    let graphics = VZMacGraphicsDeviceConfiguration()
    graphics.displays = [
        VZMacGraphicsDisplayConfiguration(
            widthInPixels: 1024,
            heightInPixels: 768,
            pixelsPerInch: 80
        )
    ]

    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = platform
    configuration.bootLoader = VZMacOSBootLoader()
    configuration.cpuCount = contract.cpuCount
    configuration.memorySize = contract.memoryBytes
    configuration.storageDevices = [storage]
    configuration.networkDevices = []
    configuration.graphicsDevices = [graphics]
    configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
    configuration.keyboards = [VZUSBKeyboardConfiguration()]
    configuration.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
    do {
        try configuration.validate()
    } catch {
        throw ArtifactRunLifecycleError.virtualizationConfigurationInvalid
    }
    return configuration
}
