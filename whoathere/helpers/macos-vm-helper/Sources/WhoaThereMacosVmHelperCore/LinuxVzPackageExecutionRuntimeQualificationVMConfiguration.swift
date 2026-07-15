import Foundation
@preconcurrency import Virtualization

public enum LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError: Error, Equatable {
    case invalidKernel
    case invalidInitramfs
    case invalidRootfs
    case invalidResources
    case invalidNetworkSocket
    case invalidMacAddress
    case virtualizationUnsupported
    case invalidConfiguration(String)
}

public struct LinuxVzPackageExecutionRuntimeQualificationVMConfigurationContract:
    Equatable, Sendable
{
    public let kernelURL: URL
    public let initramfsURL: URL
    public let rootfsURL: URL
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

public func linuxVzPackageExecutionRuntimeQualificationVMConfigurationContract(
    kernelURL: URL,
    initramfsURL: URL,
    rootfsURL: URL,
    cpuCount: Int = 2,
    memoryBytes: UInt64 = 1024 * 1024 * 1024
) throws -> LinuxVzPackageExecutionRuntimeQualificationVMConfigurationContract {
    guard try executionRuntimeQualificationRegularNonSymlink(kernelURL) else {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidKernel
    }
    guard try executionRuntimeQualificationRegularNonSymlink(initramfsURL) else {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidInitramfs
    }
    guard try executionRuntimeQualificationRegularNonSymlink(rootfsURL) else {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidRootfs
    }
    guard cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
          cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount,
          memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
          memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize else {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidResources
    }
    return LinuxVzPackageExecutionRuntimeQualificationVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        rootfsURL: rootfsURL,
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

public func buildLinuxVzPackageExecutionRuntimeQualificationVMConfiguration(
    kernelURL: URL,
    initramfsURL: URL,
    rootfsURL: URL,
    serialInput: FileHandle?,
    serialOutput: FileHandle?,
    rawFrameSocket: FileHandle,
    cpuCount: Int = 2,
    memoryBytes: UInt64 = 1024 * 1024 * 1024
) throws -> VZVirtualMachineConfiguration {
    guard VZVirtualMachine.isSupported else {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError
            .virtualizationUnsupported
    }
    let contract = try linuxVzPackageExecutionRuntimeQualificationVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        rootfsURL: rootfsURL,
        cpuCount: cpuCount,
        memoryBytes: memoryBytes
    )
    guard rawFrameSocket.fileDescriptor >= 0 else {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidNetworkSocket
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
    guard let macAddress = VZMACAddress(string: "02:57:48:4f:41:33") else {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidMacAddress
    }
    network.macAddress = macAddress
    let diskAttachment: VZDiskImageStorageDeviceAttachment
    do {
        diskAttachment = try VZDiskImageStorageDeviceAttachment(
            url: contract.rootfsURL,
            readOnly: true
        )
    } catch {
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidRootfs
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
        throw LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidConfiguration(
            String(describing: error)
        )
    }
    return configuration
}

private func executionRuntimeQualificationRegularNonSymlink(_ url: URL) throws -> Bool {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    return values.isRegularFile == true && values.isSymbolicLink != true
}
