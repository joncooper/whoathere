import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzInertConfigurationHasOneRawFrameNICAndNoStorageOrShares() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-linux-vz-config-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let kernel = root.appendingPathComponent("kernel")
    let initramfs = root.appendingPathComponent("initramfs")
    #expect(FileManager.default.createFile(atPath: kernel.path, contents: Data("kernel".utf8)))
    #expect(FileManager.default.createFile(atPath: initramfs.path, contents: Data("initramfs".utf8)))
    let contract = try linuxVzInertVMConfigurationContract(
        kernelURL: kernel,
        initramfsURL: initramfs
    )
    #expect(contract.cpuCount == 2)
    #expect(contract.memoryBytes == 512 * 1024 * 1024)
    #expect(contract.networkDeviceCount == 1)
    #expect(contract.serialPortCount == 1)
    #expect(contract.socketDeviceCount == 1)
    #expect(contract.storageDeviceCount == 0)
    #expect(contract.directoryShareCount == 0)
    #expect(contract.networkTopology == "host_raw_frame_sinkhole_no_external_route")
    #expect(contract.commandLine == linuxVzInertKernelCommandLineV1)
}

@Test func linuxVzInertConfigurationRejectsSymlinkInputsAndInvalidResources() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-linux-vz-invalid-config-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let kernel = root.appendingPathComponent("kernel")
    let initramfs = root.appendingPathComponent("initramfs")
    let kernelLink = root.appendingPathComponent("kernel-link")
    #expect(FileManager.default.createFile(atPath: kernel.path, contents: Data("kernel".utf8)))
    #expect(FileManager.default.createFile(atPath: initramfs.path, contents: Data("initramfs".utf8)))
    try FileManager.default.createSymbolicLink(at: kernelLink, withDestinationURL: kernel)

    #expect(throws: LinuxVzInertVMConfigurationError.invalidKernel) {
        try linuxVzInertVMConfigurationContract(
            kernelURL: kernelLink,
            initramfsURL: initramfs
        )
    }
    #expect(throws: LinuxVzInertVMConfigurationError.invalidResources) {
        try linuxVzInertVMConfigurationContract(
            kernelURL: kernel,
            initramfsURL: initramfs,
            cpuCount: 0
        )
    }
}
