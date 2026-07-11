import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func measuredBaseCreatesDistinctAPFSClonesAndVerifiesAbsenceAfterCleanup() throws {
    let fixture = try lifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    let base = try verifyAndLockArtifactRunBase(
        layout: fixture.layout,
        identity: fixture.identity,
        helperURL: fixture.helperURL
    )
    #expect(base.measurement.diskSHA256 == fixture.identity.baseDiskSHA256)
    #expect(base.measurement.auxiliaryStorageSHA256 == fixture.identity.baseAuxiliaryStorageSHA256)
    #expect(base.hardwareModelData == fixture.hardwareModel)
    #expect(base.machineIdentifierData == fixture.machineIdentifier)
    #expect(base.guestAuthPublicKeyData == fixture.guestAuthPublicKey)

    let first = try base.createDisposableClone()
    let second = try base.createDisposableClone()
    #expect(first.runID != second.runID)
    #expect(first.runDirectory != second.runDirectory)
    #expect(try Data(contentsOf: first.diskURL) == fixture.disk)
    #expect(try Data(contentsOf: first.auxiliaryStorageURL) == fixture.auxiliaryStorage)
    #expect(try inode(first.diskURL) != inode(fixture.layout.diskURL))
    #expect(try inode(first.auxiliaryStorageURL) != inode(fixture.layout.auxiliaryStorageURL))
    let configuration = try artifactVMConfigurationContract(base: base, clone: first)
    #expect(configuration.diskURL == first.diskURL)
    #expect(configuration.auxiliaryStorageURL == first.auxiliaryStorageURL)
    #expect(configuration.cpuCount == 4)
    #expect(configuration.memoryBytes == 6_144 * 1_048_576)
    #expect(configuration.networkDeviceCount == 0)
    #expect(configuration.socketDeviceCount == 1)
    #expect(configuration.writableStorageDeviceCount == 1)
    #expect(configuration.guestToolsAttached == false)

    let firstPath = first.runDirectory.path
    let secondPath = second.runDirectory.path
    try first.cleanup()
    try second.cleanup()
    #expect(lstatExists(firstPath) == false)
    #expect(lstatExists(secondPath) == false)
}

@Test func measuredBaseRejectsDigestMismatchSymlinkAndActiveRuntimeBeforeClone() throws {
    do {
        let fixture = try lifecycleFixture(diskDigestOverride: sha256(Data("wrong disk".utf8)))
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        #expect(throws: ArtifactRunLifecycleError.baseDigestMismatch) {
            try verifyAndLockArtifactRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.layout.artifactRunsDirectory.path))
    }

    do {
        let fixture = try lifecycleFixture(
            receiptSupervisorDigestOverride: sha256(Data("different supervisor".utf8))
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        #expect(throws: ArtifactRunLifecycleError.provisioningReceiptInvalid) {
            try verifyAndLockArtifactRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
        #expect(!FileManager.default.fileExists(atPath: fixture.layout.artifactRunsDirectory.path))
    }

    do {
        let fixture = try lifecycleFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try FileManager.default.removeItem(at: fixture.layout.diskURL)
        try FileManager.default.createSymbolicLink(
            at: fixture.layout.diskURL,
            withDestinationURL: fixture.layout.auxiliaryStorageURL
        )
        #expect(throws: ArtifactRunLifecycleError.baseFileUnsafe) {
            try verifyAndLockArtifactRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
    }

    do {
        let fixture = try lifecycleFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try Data("\(getpid())\n".utf8).write(to: fixture.layout.runtimePIDURL)
        try setMode(fixture.layout.runtimePIDURL, 0o600)
        #expect(throws: ArtifactRunLifecycleError.baseRuntimeActive) {
            try verifyAndLockArtifactRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
    }
}

@Test func cloneCleanupFailurePreservesPathAndCanBeRetried() throws {
    let fixture = try lifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }
    let base = try verifyAndLockArtifactRunBase(
        layout: fixture.layout,
        identity: fixture.identity,
        helperURL: fixture.helperURL
    )
    let clone = try base.createDisposableClone()
    let unexpected = clone.runDirectory.appendingPathComponent("unexpected")
    try Data("cleanup fault".utf8).write(to: unexpected)
    try setMode(unexpected, 0o600)

    #expect(throws: ArtifactRunLifecycleError.cleanupFailed) {
        try clone.cleanup()
    }
    #expect(lstatExists(clone.runDirectory.path))
    try FileManager.default.removeItem(at: unexpected)
    try clone.cleanup()
    #expect(lstatExists(clone.runDirectory.path) == false)
}

struct LifecycleFixture {
    let root: URL
    let layout: ArtifactRunBaseLayout
    let helperURL: URL
    let identity: ArtifactRunBackendIdentity
    let disk: Data
    let auxiliaryStorage: Data
    let hardwareModel: Data
    let machineIdentifier: Data
    let guestAuthPublicKey: Data
}

func lifecycleFixture(
    diskDigestOverride: String? = nil,
    receiptSupervisorDigestOverride: String? = nil
) throws -> LifecycleFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-artifact-lifecycle-\(UUID().uuidString)", isDirectory: true
    )
    let layout = ArtifactRunBaseLayout(stateDirectory: root)
    try FileManager.default.createDirectory(
        at: layout.bundleDirectory,
        withIntermediateDirectories: true,
        attributes: [.posixPermissions: 0o700]
    )
    try setMode(root, 0o700)
    try setMode(layout.bundleDirectory, 0o700)

    let disk = Data("base disk".utf8)
    let auxiliary = Data("base aux".utf8)
    let hardware = Data("hardware model".utf8)
    let machine = Data("machine identifier".utf8)
    let guestAuthPublicKey = try guestAuthTestPublicKey()
    let receipt = try artifactSupervisorProvisioningFixtureData(
        guestAuthPublicKey: guestAuthPublicKey,
        guestSupervisorSHA256: receiptSupervisorDigestOverride
            ?? sha256(Data("supervisor".utf8))
    )
    let helper = Data("helper".utf8)
    let helperURL = root.appendingPathComponent("helper-fixture")
    for (url, data) in [
        (layout.diskURL, disk),
        (layout.auxiliaryStorageURL, auxiliary),
        (layout.hardwareModelURL, hardware),
        (layout.machineIdentifierURL, machine),
        (layout.guestAuthPublicKeyURL, guestAuthPublicKey),
        (layout.postProvisioningReceiptURL, receipt),
        (helperURL, helper)
    ] {
        try data.write(to: url)
        try setMode(url, 0o600)
    }

    let identity = ArtifactRunBackendIdentity(
        baseGenerationID: "base-generation-inert-v1",
        baseDiskSHA256: diskDigestOverride ?? sha256(disk),
        baseAuxiliaryStorageSHA256: sha256(auxiliary),
        hardwareModelSHA256: sha256(hardware),
        machineIdentifierSHA256: sha256(machine),
        cpuCount: 4,
        memoryMiB: 6_144,
        postProvisioningReceiptSHA256: sha256(receipt),
        helperSHA256: sha256(helper),
        guestSupervisorSHA256: sha256(Data("supervisor".utf8)),
        guestAuthPublicKeySHA256: sha256(guestAuthPublicKey),
        runnerConfigurationSHA256: sha256(Data("runner".utf8)),
        packageUID: 502,
        packageGID: 502,
        nodeVersion: "22.17.0",
        nodeExecutableSHA256: sha256(Data("node executable".utf8)),
        npmVersion: "11.18.0",
        npmCLISHA256: sha256(Data("npm cli".utf8)),
        cloneImplementationSHA256: sha256(
            Data("whoathere.swift.fclonefileat.direct.v1".utf8)
        ),
        guestProtocolSHA256: sha256(Data("whoathere.artifact_scenario.v1".utf8))
    )
    return LifecycleFixture(
        root: root,
        layout: layout,
        helperURL: helperURL,
        identity: identity,
        disk: disk,
        auxiliaryStorage: auxiliary,
        hardwareModel: hardware,
        machineIdentifier: machine,
        guestAuthPublicKey: guestAuthPublicKey
    )
}

func artifactSupervisorProvisioningFixtureData(
    guestAuthPublicKey: Data,
    guestSupervisorSHA256: String = sha256(Data("supervisor".utf8))
) throws -> Data {
    try canonicalJSONData([
        "artifact_vsock_port": "47079",
        "base_generation_id": "base-generation-inert-v1",
        "clone_implementation_sha256": sha256(
            Data("whoathere.swift.fclonefileat.direct.v1".utf8)
        ),
        "cpu_count": "4",
        "guest_auth_public_key_sha256": sha256(guestAuthPublicKey),
        "guest_supervisor_sha256": guestSupervisorSHA256,
        "memory_mib": "6144",
        "node_executable_sha256": sha256(Data("node executable".utf8)),
        "node_version": "22.17.0",
        "npm_cli_sha256": sha256(Data("npm cli".utf8)),
        "npm_version": "11.18.0",
        "package_execution_enabled": false,
        "package_gid": "502",
        "package_uid": "502",
        "package_username": "_whoatherepkg",
        "runner_configuration_sha256": sha256(Data("runner".utf8)),
        "schema_version": artifactSupervisorProvisioningReceiptSchemaV1,
        "sync_back_enabled": false
    ])
}

private func setMode(_ url: URL, _ mode: mode_t) throws {
    guard chmod(url.path, mode) == 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
}

private func inode(_ url: URL) throws -> UInt64 {
    var status = stat()
    guard lstat(url.path, &status) == 0 else {
        throw ArtifactRunLifecycleError.cloneVerificationFailed
    }
    return status.st_ino
}

private func lstatExists(_ path: String) -> Bool {
    var status = stat()
    return lstat(path, &status) == 0
}
