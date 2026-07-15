import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func executionRuntimeQualificationConfigurationIsReadOnlyAndSinkholed() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-execution-runtime-qualification-config-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let kernel = root.appendingPathComponent("kernel")
    let initramfs = root.appendingPathComponent("initramfs")
    let rootfs = root.appendingPathComponent("rootfs.ext2")
    for (url, bytes) in [(kernel, "kernel"), (initramfs, "initramfs"), (rootfs, "rootfs")] {
        #expect(FileManager.default.createFile(atPath: url.path, contents: Data(bytes.utf8)))
    }
    let contract = try linuxVzPackageExecutionRuntimeQualificationVMConfigurationContract(
        kernelURL: kernel,
        initramfsURL: initramfs,
        rootfsURL: rootfs
    )
    #expect(contract.cpuCount == 2)
    #expect(contract.memoryBytes == 1024 * 1024 * 1024)
    #expect(contract.networkDeviceCount == 1)
    #expect(contract.socketDeviceCount == 0)
    #expect(contract.storageDeviceCount == 1)
    #expect(contract.writableStorageDeviceCount == 0)
    #expect(contract.rootfsReadOnly)
    #expect(contract.directoryShareCount == 0)
    #expect(contract.networkTopology == "host_raw_frame_sinkhole_no_external_route")
}

@Test func executionRuntimeQualificationConfigurationRejectsRootfsSymlink() throws {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-execution-runtime-qualification-invalid-\(UUID().uuidString)",
        isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: root) }
    let kernel = root.appendingPathComponent("kernel")
    let initramfs = root.appendingPathComponent("initramfs")
    let rootfs = root.appendingPathComponent("rootfs.ext2")
    let rootfsLink = root.appendingPathComponent("rootfs-link.ext2")
    for (url, bytes) in [(kernel, "kernel"), (initramfs, "initramfs"), (rootfs, "rootfs")] {
        #expect(FileManager.default.createFile(atPath: url.path, contents: Data(bytes.utf8)))
    }
    try FileManager.default.createSymbolicLink(at: rootfsLink, withDestinationURL: rootfs)
    #expect(throws: LinuxVzPackageExecutionRuntimeQualificationVMConfigurationError.invalidRootfs) {
        try linuxVzPackageExecutionRuntimeQualificationVMConfigurationContract(
            kernelURL: kernel,
            initramfsURL: initramfs,
            rootfsURL: rootfsLink
        )
    }
}
