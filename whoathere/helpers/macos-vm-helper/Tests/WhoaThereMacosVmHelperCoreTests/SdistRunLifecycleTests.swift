import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func measuredSdistBaseCreatesDistinctAPFSClonesAndCleans() throws {
    let fixture = try sdistLifecycleFixture()
    defer { try? FileManager.default.removeItem(at: fixture.root) }

    let base = try verifyAndLockSdistRunBase(
        layout: fixture.layout,
        identity: fixture.identity,
        helperURL: fixture.helperURL
    )
    #expect(base.measurement.diskSHA256 == fixture.identity.baseDiskSHA256)
    #expect(base.measurement.auxiliaryStorageSHA256
        == fixture.identity.baseAuxiliaryStorageSHA256)
    #expect(base.guestAuthPublicKeyData == fixture.guestAuthPublicKey)

    let first = try base.createDisposableClone()
    let second = try base.createDisposableClone()
    #expect(first.runID != second.runID)
    #expect(try Data(contentsOf: first.diskURL) == fixture.disk)
    #expect(try sdistLifecycleInode(first.diskURL)
        != sdistLifecycleInode(fixture.layout.diskURL))
    #expect(first.diskSHA256 == fixture.identity.baseDiskSHA256)
    #expect(first.auxiliaryStorageSHA256 == fixture.identity.baseAuxiliaryStorageSHA256)
    let contract = try sdistVMConfigurationContract(base: base, clone: first)
    #expect(contract.cpuCount == 4)
    #expect(contract.memoryBytes == 6_144 * 1_048_576)
    #expect(contract.networkDeviceCount == 0)
    #expect(contract.socketDeviceCount == 1)
    #expect(contract.writableStorageDeviceCount == 1)
    #expect(!contract.guestToolsAttached)
    #expect(contract.guestVSOCKPort == 47_081)

    let firstPath = first.runDirectory.path
    let secondPath = second.runDirectory.path
    try first.cleanup()
    try second.cleanup()
    #expect(!sdistLifecyclePathExists(firstPath))
    #expect(!sdistLifecyclePathExists(secondPath))
}

@Test func sdistBaseRejectsWrongReceiptAndActiveRuntimeBeforeClone() throws {
    do {
        let fixture = try sdistLifecycleFixture(
            receiptSupervisorSHA256: sha256(Data("wrong sdist supervisor".utf8))
        )
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        #expect(throws: ArtifactRunLifecycleError.sdistProvisioningReceiptInvalid) {
            try verifyAndLockSdistRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
        #expect(!sdistLifecyclePathExists(fixture.layout.sdistRunsDirectory.path))
    }

    do {
        let fixture = try sdistLifecycleFixture()
        defer { try? FileManager.default.removeItem(at: fixture.root) }
        try Data("\(getpid())\n".utf8).write(to: fixture.layout.runtimePIDURL)
        try sdistLifecycleSetMode(fixture.layout.runtimePIDURL, 0o600)
        #expect(throws: ArtifactRunLifecycleError.baseRuntimeActive) {
            try verifyAndLockSdistRunBase(
                layout: fixture.layout,
                identity: fixture.identity,
                helperURL: fixture.helperURL
            )
        }
    }
}

private struct SdistLifecycleFixture {
    let root: URL
    let layout: SdistRunBaseLayout
    let helperURL: URL
    let identity: SdistRunBackendIdentity
    let disk: Data
    let guestAuthPublicKey: Data
}

private func sdistLifecycleFixture(
    receiptSupervisorSHA256: String? = nil
) throws -> SdistLifecycleFixture {
    let root = FileManager.default.temporaryDirectory.appendingPathComponent(
        "whoathere-sdist-lifecycle-\(UUID().uuidString)", isDirectory: true
    )
    let state = root.appendingPathComponent("state", isDirectory: true)
    let layout = SdistRunBaseLayout(stateDirectory: state)
    for directory in [root, state, layout.bundleDirectory] {
        try FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: false,
            attributes: [.posixPermissions: 0o700]
        )
        try sdistLifecycleSetMode(directory, 0o700)
    }

    let disk = Data("sdist base disk".utf8)
    let auxiliary = Data("sdist base aux".utf8)
    let hardware = Data("hardware model".utf8)
    let machine = Data("machine identifier".utf8)
    let helper = Data("helper".utf8)
    let guestAuthPublicKey = Data(repeating: 19, count: 32)
    let provisional = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"],
        scenarioIndex: 93,
        guestAuthPublicKeySHA256: sha256(guestAuthPublicKey)
    )
    let provisionalIdentity = try beginSdistSubmission(
        from: sdistFileHandle(provisional.frame)
    ).prelude.backendIdentity
    var receiptObject = try #require(
        JSONSerialization.jsonObject(
            with: sdistProvisioningReceiptFixture(
                identity: provisionalIdentity,
                guestAuthPublicKey: guestAuthPublicKey
            )
        ) as? [String: Any]
    )
    if let receiptSupervisorSHA256 {
        receiptObject["guest_supervisor_sha256"] = receiptSupervisorSHA256
    }
    let receipt = try canonicalJSONData(receiptObject)
    let submission = try sdistSubmissionFixture(
        scenario: ["kind": "install_derived_wheel"],
        scenarioIndex: 93,
        guestAuthPublicKeySHA256: sha256(guestAuthPublicKey),
        postProvisioningReceiptSHA256: sha256(receipt)
    )
    let identity = try beginSdistSubmission(
        from: sdistFileHandle(submission.frame)
    ).prelude.backendIdentity
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
        try sdistLifecycleSetMode(url, mode)
    }
    return SdistLifecycleFixture(
        root: root,
        layout: layout,
        helperURL: helperURL,
        identity: identity,
        disk: disk,
        guestAuthPublicKey: guestAuthPublicKey
    )
}

private func sdistLifecycleSetMode(_ url: URL, _ mode: mode_t) throws {
    guard chmod(url.path, mode) == 0 else {
        throw ArtifactRunLifecycleError.baseFileUnsafe
    }
}

private func sdistLifecycleInode(_ url: URL) throws -> UInt64 {
    var status = stat()
    guard lstat(url.path, &status) == 0 else {
        throw ArtifactRunLifecycleError.cloneVerificationFailed
    }
    return status.st_ino
}

private func sdistLifecyclePathExists(_ path: String) -> Bool {
    var status = stat()
    return lstat(path, &status) == 0
}
