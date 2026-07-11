import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func measuredWheelBaseCreatesAPFSCloneWithZeroNetworkContractAndCleans() throws {
    let fixture = try wheelLifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    let base = try verifyAndLockWheelRunBase(
        layout: fixture.layout,
        identity: fixture.identity,
        helperURL: fixture.helperURL
    )
    #expect(base.measurement.diskSHA256 == fixture.identity.baseDiskSHA256)
    #expect(base.measurement.auxiliaryStorageSHA256 == fixture.identity.baseAuxiliaryStorageSHA256)
    #expect(base.guestAuthPublicKeyData == fixture.guestAuthPublicKey)

    let first = try base.createDisposableClone()
    let second = try base.createDisposableClone()
    #expect(first.runID != second.runID)
    #expect(try Data(contentsOf: first.diskURL) == fixture.disk)
    #expect(try wheelLifecycleInode(first.diskURL) != wheelLifecycleInode(fixture.layout.diskURL))
    let contract = try wheelVMConfigurationContract(base: base, clone: first)
    #expect(contract.cpuCount == 4)
    #expect(contract.memoryBytes == 6_144 * 1_048_576)
    #expect(contract.networkDeviceCount == 0)
    #expect(contract.socketDeviceCount == 1)
    #expect(contract.writableStorageDeviceCount == 1)
    #expect(contract.guestToolsAttached == false)
    #expect(contract.guestVSOCKPort == wheelGuestVSOCKPortV1)

    let firstPath = first.runDirectory.path
    let secondPath = second.runDirectory.path
    try first.cleanup()
    try second.cleanup()
    #expect(!wheelLifecyclePathExists(firstPath))
    #expect(!wheelLifecyclePathExists(secondPath))
}

@Test func wheelBaseRejectsWrongProvisionedSupervisorAndActiveRuntimeBeforeClone() throws {
    do {
        let fixture = try wheelLifecycleFixture(
            receiptSupervisorSHA256: sha256(Data("wrong wheel supervisor".utf8))
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        #expect(throws: ArtifactRunLifecycleError.wheelProvisioningReceiptInvalid) {
            try verifyAndLockWheelRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
        #expect(!wheelLifecyclePathExists(fixture.layout.wheelRunsDirectory.path))
    }

    do {
        let fixture = try wheelLifecycleFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try Data("\(getpid())\n".utf8).write(to: fixture.layout.runtimePIDURL)
        try wheelLifecycleSetMode(fixture.layout.runtimePIDURL, 0o600)
        #expect(throws: ArtifactRunLifecycleError.baseRuntimeActive) {
            try verifyAndLockWheelRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
    }
}

private struct WheelLifecycleFixture {
    let root: URL
    let layout: WheelRunBaseLayout
    let helperURL: URL
    let identity: WheelRunBackendIdentity
    let disk: Data
    let guestAuthPublicKey: Data
}

private func wheelLifecycleFixture(
    receiptSupervisorSHA256: String? = nil
) throws -> WheelLifecycleFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-wheel-lifecycle-\(UUID().uuidString)", isDirectory: true
    )
    let state = root.appendingPathComponent("state", isDirectory: true)
    let layout = WheelRunBaseLayout(stateDirectory: state)
    for directory in [root, state, layout.bundleDirectory] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try wheelLifecycleSetMode(directory, 0o700)
    }

    let disk = Data("wheel base disk".utf8)
    let auxiliary = Data("wheel base aux".utf8)
    let hardware = Data("hardware model".utf8)
    let machine = Data("machine identifier".utf8)
    let helper = Data("helper".utf8)
    let guestAuthPublicKey = Data(repeating: 11, count: 32)
    let receipt = try wheelSupervisorProvisioningFixtureData(
        guestAuthPublicKey: guestAuthPublicKey,
        guestSupervisorSHA256: receiptSupervisorSHA256
            ?? sha256(Data("wheel supervisor".utf8))
    )
    let submission = try wheelSubmissionFixture(
        scenario: ["kind": "install_exact_wheel"],
        scenarioIndex: 71,
        guestAuthPublicKeySHA256: sha256(guestAuthPublicKey),
        postProvisioningReceiptSHA256: sha256(receipt)
    )
    let reader = try beginWheelSubmission(from: wheelLifecycleFileHandle(submission.frame))
    let identity = reader.prelude.backendIdentity
    let helperURL = root.appendingPathComponent("helper")
    for (url, data, mode): (URL, Data, mode_t) in [
        (layout.diskURL, disk, 0o600),
        (layout.auxiliaryStorageURL, auxiliary, 0o600),
        (layout.hardwareModelURL, hardware, 0o600),
        (layout.machineIdentifierURL, machine, 0o600),
        (layout.guestAuthPublicKeyURL, guestAuthPublicKey, 0o600),
        (layout.postProvisioningReceiptURL, receipt, 0o600),
        (helperURL, helper, 0o500)
    ] {
        try data.write(to: url)
        try wheelLifecycleSetMode(url, mode)
    }
    return WheelLifecycleFixture(
        root: root,
        layout: layout,
        helperURL: helperURL,
        identity: identity,
        disk: disk,
        guestAuthPublicKey: guestAuthPublicKey
    )
}

func wheelSupervisorProvisioningFixtureData(
    guestAuthPublicKey: Data,
    guestSupervisorSHA256: String = sha256(Data("wheel supervisor".utf8))
) throws -> Data {
    try canonicalJSONData([
        "schema_version": wheelSupervisorProvisioningReceiptSchemaV1,
        "base_generation_id": "wheel-base-generation-inert-v1",
        "guest_supervisor_sha256": guestSupervisorSHA256,
        "guest_auth_public_key_sha256": sha256(guestAuthPublicKey),
        "runner_configuration_sha256": sha256(Data("wheel runner".utf8)),
        "python_executable_sha256": sha256(Data("python executable".utf8)),
        "python_version": "3.12.13",
        "pip_cli_sha256": sha256(Data("pip cli".utf8)),
        "pip_version": "26.1.2",
        "clone_implementation_sha256": sha256(
            Data("whoathere.swift.fclonefileat.direct.v1".utf8)
        ),
        "guest_protocol_sha256": sha256(
            Data("whoathere.wheel_artifact_scenario.v1".utf8)
        ),
        "cpu_count": "4",
        "memory_mib": "6144",
        "package_uid": "499",
        "package_gid": "499",
        "package_username": "_whoatherepkg",
        "wheel_vsock_port": String(wheelGuestVSOCKPortV1),
        "package_execution_enabled": false,
        "sync_back_enabled": false
    ])
}

private func wheelLifecycleSetMode(_ url: URL, _ mode: mode_t) throws {
    guard chmod(url.path, mode) == 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
}

private func wheelLifecycleInode(_ url: URL) throws -> UInt64 {
    var status = stat()
    guard lstat(url.path, &status) == 0 else {
        throw ArtifactRunLifecycleError.cloneVerificationFailed
    }
    return status.st_ino
}

private func wheelLifecyclePathExists(_ path: String) -> Bool {
    var status = stat()
    return lstat(path, &status) == 0
}

private func wheelLifecycleFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}
