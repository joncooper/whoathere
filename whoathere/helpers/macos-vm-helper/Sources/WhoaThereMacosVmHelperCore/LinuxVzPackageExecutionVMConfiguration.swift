import Foundation
@preconcurrency import Virtualization

public enum LinuxVzPackageExecutionVMConfigurationError: Error, Equatable {
    case invalidKernel
    case invalidInitramfs
    case invalidClone
    case invalidResources
    case invalidNetworkSocket
    case invalidMacAddress
    case virtualizationUnsupported
    case invalidConfiguration(String)
}

public struct LinuxVzPackageExecutionVMConfigurationContract: Equatable, Sendable {
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
    public let rootfsReadOnly: Bool
    public let networkTopology: String
    public let commandLine: String
}

public func linuxVzPackageExecutionVMConfigurationContract(
    kernelURL: URL,
    initramfsURL: URL,
    clone: DisposableLinuxVzPackageRuntimeClone,
    cpuCount: Int = 2,
    memoryBytes: UInt64 = 1024 * 1024 * 1024
) throws -> LinuxVzPackageExecutionVMConfigurationContract {
    guard try linuxVzPackageExecutionRegularNonSymlink(kernelURL) else {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidKernel
    }
    guard try linuxVzPackageExecutionRegularNonSymlink(initramfsURL) else {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidInitramfs
    }
    do {
        try clone.verifyReadyForAttachment()
    } catch {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidClone
    }
    guard cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
          cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount,
          memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
          memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize else {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidResources
    }
    return LinuxVzPackageExecutionVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        rootfsCloneURL: clone.rootfsURL,
        cloneBindingSHA256: clone.cloneBindingSHA256,
        cpuCount: cpuCount,
        memoryBytes: memoryBytes,
        networkDeviceCount: 1,
        serialPortCount: 1,
        socketDeviceCount: 0,
        storageDeviceCount: 1,
        writableStorageDeviceCount: 0,
        directoryShareCount: 0,
        rootfsReadOnly: true,
        networkTopology: "host_raw_frame_sinkhole_no_external_route",
        commandLine: linuxVzInertKernelCommandLineV1
    )
}

public func buildLinuxVzPackageExecutionVMConfiguration(
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
        throw LinuxVzPackageExecutionVMConfigurationError.virtualizationUnsupported
    }
    let contract = try linuxVzPackageExecutionVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        clone: clone,
        cpuCount: cpuCount,
        memoryBytes: memoryBytes
    )
    guard rawFrameSocket.fileDescriptor >= 0 else {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidNetworkSocket
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
    guard let macAddress = VZMACAddress(string: "02:57:48:4f:41:34") else {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidMacAddress
    }
    network.macAddress = macAddress
    let diskAttachment: VZDiskImageStorageDeviceAttachment
    do {
        diskAttachment = try VZDiskImageStorageDeviceAttachment(
            url: contract.rootfsCloneURL,
            readOnly: true
        )
    } catch {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidClone
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
    configuration.socketDevices = []
    configuration.storageDevices = [storage]
    configuration.directorySharingDevices = []
    do {
        try configuration.validate()
    } catch {
        throw LinuxVzPackageExecutionVMConfigurationError.invalidConfiguration(
            String(describing: error)
        )
    }
    return configuration
}

private func linuxVzPackageExecutionRegularNonSymlink(_ url: URL) throws -> Bool {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    return values.isRegularFile == true && values.isSymbolicLink != true
}
