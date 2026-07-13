import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzPackageRuntimeBaseCreatesUniqueMeasuredWritableClones() throws {
    let fixture = try linuxVzPackageRuntimeLifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let base = try verifyAndLockLinuxVzPackageRuntimeBase(
        layout: fixture.layout,
        expectedRootfsSHA256: sha256(fixture.manifest.rootfs),
        expectedRootfsByteLength: UInt64(fixture.manifest.rootfs.count),
        expectedRuntimeManifestSHA256: sha256(fixture.manifest.data),
        expectedPackageRunnerSHA256: sha256(fixture.manifest.runner)
    )
    #expect(base.measurement.rootfsSHA256 == sha256(fixture.manifest.rootfs))
    #expect(base.manifest.packageUID == 65_534)
    let first = try base.createDisposableClone()
    let second = try base.createDisposableClone()
    #expect(first.runID != second.runID)
    #expect(first.cloneBindingSHA256 != second.cloneBindingSHA256)
    #expect(first.initialRootfsSHA256 == base.measurement.rootfsSHA256)
    #expect(try linuxVzRuntimeInode(first.rootfsURL)
        != linuxVzRuntimeInode(fixture.layout.rootfsURL))
    #expect(try linuxVzRuntimeMode(first.rootfsURL) == 0o600)
    try first.verifyReadyForAttachment()
    try second.verifyReadyForAttachment()

    let kernel = fixture.root.appendingPathComponent("kernel")
    let initramfs = fixture.root.appendingPathComponent("initramfs")
    try Data("kernel".utf8).write(to: kernel)
    try Data("initramfs".utf8).write(to: initramfs)
    let contract = try linuxVzPackageRuntimeVMConfigurationContract(
        kernelURL: kernel,
        initramfsURL: initramfs,
        clone: first
    )
    #expect(contract.rootfsCloneURL == first.rootfsURL)
    #expect(contract.cloneBindingSHA256 == first.cloneBindingSHA256)
    #expect(contract.cpuCount == 2)
    #expect(contract.memoryBytes == 1024 * 1024 * 1024)
    #expect(contract.networkDeviceCount == 1)
    #expect(contract.serialPortCount == 1)
    #expect(contract.socketDeviceCount == 1)
    #expect(contract.storageDeviceCount == 1)
    #expect(contract.writableStorageDeviceCount == 1)
    #expect(contract.directoryShareCount == 0)
    #expect(contract.networkTopology == "host_raw_frame_sinkhole_no_external_route")

    let firstPath = first.runDirectory.path
    let secondPath = second.runDirectory.path
    try first.cleanup()
    try second.cleanup()
    #expect(!linuxVzRuntimePathExists(firstPath))
    #expect(!linuxVzRuntimePathExists(secondPath))
}

@Test func linuxVzPackageRuntimeBaseAndCloneFailClosedOnRebinding() throws {
    do {
        let fixture = try linuxVzPackageRuntimeLifecycleFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        #expect(throws: ArtifactRunLifecycleError.baseDigestMismatch) {
            try verifyAndLockLinuxVzPackageRuntimeBase(
                layout: fixture.layout,
                expectedRootfsSHA256: sha256(Data("wrong rootfs".utf8)),
                expectedRootfsByteLength: UInt64(fixture.manifest.rootfs.count),
                expectedRuntimeManifestSHA256: sha256(fixture.manifest.data),
                expectedPackageRunnerSHA256: sha256(fixture.manifest.runner)
            )
        }
    }
    do {
        let fixture = try linuxVzPackageRuntimeLifecycleFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        let base = try verifyAndLockLinuxVzPackageRuntimeBase(
            layout: fixture.layout,
            expectedRootfsSHA256: sha256(fixture.manifest.rootfs),
            expectedRootfsByteLength: UInt64(fixture.manifest.rootfs.count),
            expectedRuntimeManifestSHA256: sha256(fixture.manifest.data),
            expectedPackageRunnerSHA256: sha256(fixture.manifest.runner)
        )
        let clone = try base.createDisposableClone()
        var changed = try Data(contentsOf: clone.rootfsURL)
        changed[changed.startIndex] ^= 0xff
        try changed.write(to: clone.rootfsURL)
        try linuxVzRuntimeSetMode(clone.rootfsURL, 0o600)
        #expect(throws: ArtifactRunLifecycleError.cloneVerificationFailed) {
            try clone.verifyReadyForAttachment()
        }
        #expect(throws: LinuxVzPackageRuntimeVMConfigurationError.invalidClone) {
            let kernel = fixture.root.appendingPathComponent("changed-kernel")
            let initramfs = fixture.root.appendingPathComponent("changed-initramfs")
            try Data("kernel".utf8).write(to: kernel)
            try Data("initramfs".utf8).write(to: initramfs)
            _ = try linuxVzPackageRuntimeVMConfigurationContract(
                kernelURL: kernel,
                initramfsURL: initramfs,
                clone: clone
            )
        }
    }
}

private struct LinuxVzPackageRuntimeLifecycleFixture {
    let root: URL
    let layout: LinuxVzPackageRuntimeBaseLayout
    let manifest: LinuxVzPackageRuntimeManifestFixture
}

private func linuxVzPackageRuntimeLifecycleFixture()
    throws -> LinuxVzPackageRuntimeLifecycleFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-linux-vz-package-runtime-lifecycle-\(UUID().uuidString)",
        isDirectory: true
    )
    let state = root.appendingPathComponent("state", isDirectory: true)
    let layout = LinuxVzPackageRuntimeBaseLayout(stateDirectory: state)
    for directory in [root, state, layout.bundleDirectory] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try linuxVzRuntimeSetMode(directory, 0o700)
    }
    let manifest = try linuxVzPackageRuntimeManifestFixture()
    for (url, data, mode): (URL, Data, mode_t) in [
        (layout.rootfsURL, manifest.rootfs, 0o400),
        (layout.runtimeManifestURL, manifest.data, 0o400),
        (layout.packageRunnerURL, manifest.runner, 0o500)
    ] {
        try data.write(to: url)
        try linuxVzRuntimeSetMode(url, mode)
    }
    return LinuxVzPackageRuntimeLifecycleFixture(
        root: root,
        layout: layout,
        manifest: manifest
    )
}

private func linuxVzRuntimeSetMode(_ url: URL, _ mode: mode_t) throws {
    guard chmod(url.path, mode) == 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
}

private func linuxVzRuntimeInode(_ url: URL) throws -> UInt64 {
    var status = stat()
    guard lstat(url.path, &status) == 0 else {
        throw ArtifactRunLifecycleError.cloneVerificationFailed
    }
    return status.st_ino
}

private func linuxVzRuntimeMode(_ url: URL) throws -> mode_t {
    var status = stat()
    guard lstat(url.path, &status) == 0 else {
        throw ArtifactRunLifecycleError.cloneVerificationFailed
    }
    return status.st_mode & 0o777
}

private func linuxVzRuntimePathExists(_ path: String) -> Bool {
    var status = stat()
    return lstat(path, &status) == 0
}
