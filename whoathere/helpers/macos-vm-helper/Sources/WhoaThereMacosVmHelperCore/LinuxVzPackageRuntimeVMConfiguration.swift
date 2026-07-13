import Foundation
@preconcurrency import Virtualization

public enum LinuxVzPackageRuntimeVMConfigurationError: Error, Equatable {
    case invalidKernel
    case invalidInitramfs
    case invalidResources
    case invalidNetworkSocket
    case invalidMacAddress
    case invalidClone
    case virtualizationUnsupported
    case invalidConfiguration(String)
}

public struct LinuxVzPackageRuntimeVMConfigurationContract: Equatable, Sendable {
    public let kernelURL: URL
    public let initramfsURL: URL
    public let rootfsCloneURL: URL
    public let cloneBindingSHA256: String
    public let cpuCount: Int
    public let memoryBytes: UInt64
    public let networkDeviceCount: Int
    public let serialPortCount: Int
    public let socketDeviceCount: Int
    public let storageDeviceCount: Int
    public let writableStorageDeviceCount: Int
    public let directoryShareCount: Int
    public let networkTopology: String
    public let commandLine: String
}

public func linuxVzPackageRuntimeVMConfigurationContract(
    kernelURL: URL,
    initramfsURL: URL,
    clone: DisposableLinuxVzPackageRuntimeClone,
    cpuCount: Int = 2,
    memoryBytes: UInt64 = 1024 * 1024 * 1024
) throws -> LinuxVzPackageRuntimeVMConfigurationContract {
    guard try linuxVzPackageRuntimeRegularNonSymlink(kernelURL) else {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidKernel
    }
    guard try linuxVzPackageRuntimeRegularNonSymlink(initramfsURL) else {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidInitramfs
    }
    guard cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
          cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount,
          memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
          memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize else {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidResources
    }
    do {
        try clone.verifyReadyForAttachment()
    } catch {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidClone
    }
    return LinuxVzPackageRuntimeVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        rootfsCloneURL: clone.rootfsURL,
        cloneBindingSHA256: clone.cloneBindingSHA256,
        cpuCount: cpuCount,
        memoryBytes: memoryBytes,
        networkDeviceCount: 1,
        serialPortCount: 1,
        socketDeviceCount: 1,
        storageDeviceCount: 1,
        writableStorageDeviceCount: 1,
        directoryShareCount: 0,
        networkTopology: "host_raw_frame_sinkhole_no_external_route",
        commandLine: linuxVzInertKernelCommandLineV1
    )
}

public func buildLinuxVzPackageRuntimeVMConfiguration(
    kernelURL: URL,
    initramfsURL: URL,
    clone: DisposableLinuxVzPackageRuntimeClone,
    serialInput: FileHandle?,
    serialOutput: FileHandle?,
    rawFrameSocket: FileHandle,
    cpuCount: Int = 2,
    memoryBytes: UInt64 = 1024 * 1024 * 1024
) throws -> VZVirtualMachineConfiguration {
    guard VZVirtualMachine.isSupported else {
        throw LinuxVzPackageRuntimeVMConfigurationError.virtualizationUnsupported
    }
    let contract = try linuxVzPackageRuntimeVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        clone: clone,
        cpuCount: cpuCount,
        memoryBytes: memoryBytes
    )
    guard rawFrameSocket.fileDescriptor >= 0 else {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidNetworkSocket
    }

    let bootLoader = VZLinuxBootLoader(kernelURL: contract.kernelURL)
    bootLoader.initialRamdiskURL = contract.initramfsURL
    bootLoader.commandLine = contract.commandLine

    let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
    serial.attachment = VZFileHandleSerialPortAttachment(
        fileHandleForReading: serialInput,
        fileHandleForWriting: serialOutput
    )
    let network = VZVirtioNetworkDeviceConfiguration()
    network.attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: rawFrameSocket)
    guard let macAddress = VZMACAddress(string: "02:57:48:4f:41:32") else {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidMacAddress
    }
    network.macAddress = macAddress
    let diskAttachment: VZDiskImageStorageDeviceAttachment
    do {
        diskAttachment = try VZDiskImageStorageDeviceAttachment(
            url: contract.rootfsCloneURL,
            readOnly: false
        )
    } catch {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidClone
    }
    let storage = VZVirtioBlockDeviceConfiguration(attachment: diskAttachment)

    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = VZGenericPlatformConfiguration()
    configuration.bootLoader = bootLoader
    configuration.cpuCount = contract.cpuCount
    configuration.memorySize = contract.memoryBytes
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    configuration.serialPorts = [serial]
    configuration.networkDevices = [network]
    configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
    configuration.storageDevices = [storage]
    configuration.directorySharingDevices = []
    do {
        try configuration.validate()
    } catch {
        throw LinuxVzPackageRuntimeVMConfigurationError.invalidConfiguration(
            String(describing: error)
        )
    }
    return configuration
}

private func linuxVzPackageRuntimeRegularNonSymlink(_ url: URL) throws -> Bool {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    return values.isRegularFile == true && values.isSymbolicLink != true
}
