import Foundation
@preconcurrency import Virtualization

public let linuxVzInertKernelCommandLineV1 =
    "console=hvc0 rdinit=/init panic=0 reboot=k loglevel=6"

public enum LinuxVzInertVMConfigurationError: Error, Equatable {
    case invalidKernel
    case invalidInitramfs
    case invalidResources
    case invalidNetworkSocket
    case invalidMacAddress
    case virtualizationUnsupported
    case invalidConfiguration(String)
}

public struct LinuxVzInertVMConfigurationContract: Equatable, Sendable {
    public let kernelURL: URL
    public let initramfsURL: URL
    public let cpuCount: Int
    public let memoryBytes: UInt64
    public let networkDeviceCount: Int
    public let serialPortCount: Int
    public let socketDeviceCount: Int
    public let storageDeviceCount: Int
    public let directoryShareCount: Int
    public let networkTopology: String
    public let commandLine: String
}

public func linuxVzInertVMConfigurationContract(
    kernelURL: URL,
    initramfsURL: URL,
    cpuCount: Int = 2,
    memoryBytes: UInt64 = 512 * 1024 * 1024
) throws -> LinuxVzInertVMConfigurationContract {
    guard try linuxVzRegularNonSymlink(kernelURL) else {
        throw LinuxVzInertVMConfigurationError.invalidKernel
    }
    guard try linuxVzRegularNonSymlink(initramfsURL) else {
        throw LinuxVzInertVMConfigurationError.invalidInitramfs
    }
    guard cpuCount >= VZVirtualMachineConfiguration.minimumAllowedCPUCount,
          cpuCount <= VZVirtualMachineConfiguration.maximumAllowedCPUCount,
          memoryBytes >= VZVirtualMachineConfiguration.minimumAllowedMemorySize,
          memoryBytes <= VZVirtualMachineConfiguration.maximumAllowedMemorySize else {
        throw LinuxVzInertVMConfigurationError.invalidResources
    }
    return LinuxVzInertVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        cpuCount: cpuCount,
        memoryBytes: memoryBytes,
        networkDeviceCount: 1,
        serialPortCount: 1,
        socketDeviceCount: 1,
        storageDeviceCount: 0,
        directoryShareCount: 0,
        networkTopology: "host_raw_frame_sinkhole_no_external_route",
        commandLine: linuxVzInertKernelCommandLineV1
    )
}

public func buildLinuxVzInertVMConfiguration(
    kernelURL: URL,
    initramfsURL: URL,
    serialInput: FileHandle?,
    serialOutput: FileHandle?,
    rawFrameSocket: FileHandle,
    cpuCount: Int = 2,
    memoryBytes: UInt64 = 512 * 1024 * 1024
) throws -> VZVirtualMachineConfiguration {
    guard VZVirtualMachine.isSupported else {
        throw LinuxVzInertVMConfigurationError.virtualizationUnsupported
    }
    let contract = try linuxVzInertVMConfigurationContract(
        kernelURL: kernelURL,
        initramfsURL: initramfsURL,
        cpuCount: cpuCount,
        memoryBytes: memoryBytes
    )
    guard rawFrameSocket.fileDescriptor >= 0 else {
        throw LinuxVzInertVMConfigurationError.invalidNetworkSocket
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
    guard let macAddress = VZMACAddress(string: "02:57:48:4f:41:31") else {
        throw LinuxVzInertVMConfigurationError.invalidMacAddress
    }
    network.macAddress = macAddress

    let configuration = VZVirtualMachineConfiguration()
    configuration.platform = VZGenericPlatformConfiguration()
    configuration.bootLoader = bootLoader
    configuration.cpuCount = contract.cpuCount
    configuration.memorySize = contract.memoryBytes
    configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
    configuration.serialPorts = [serial]
    configuration.networkDevices = [network]
    configuration.socketDevices = [VZVirtioSocketDeviceConfiguration()]
    configuration.storageDevices = []
    configuration.directorySharingDevices = []
    do {
        try configuration.validate()
    } catch {
        throw LinuxVzInertVMConfigurationError.invalidConfiguration(
            String(describing: error)
        )
    }
    return configuration
}

private func linuxVzRegularNonSymlink(_ url: URL) throws -> Bool {
    let values = try url.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    return values.isRegularFile == true && values.isSymbolicLink != true
}
