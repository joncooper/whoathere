import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func parsesInitArguments() throws {
    let options = try parseArguments([
        "init",
        "--state-dir", "/tmp/whoathere-vm",
        "--image=/tmp/disk.img",
        "--memory-mib", "8192",
        "--disk-gib=60",
        "--execute",
        "--json"
    ])

    #expect(options.command == .`init`)
    #expect(options.stateDir == "/tmp/whoathere-vm")
    #expect(options.imagePath == "/tmp/disk.img")
    #expect(options.memoryMiB == 8192)
    #expect(options.diskGiB == 60)
    #expect(options.execute)
    #expect(options.json)
}

@Test func rejectsUnknownFlag() throws {
    do {
        _ = try parseArguments(["status", "--surprise"])
        Issue.record("expected unknown flag rejection")
    } catch let error as ArgumentError {
        #expect(error == .unknownFlag("--surprise"))
    }
}

@Test func bundleLayoutUsesManagedStateDir() {
    let layout = BundleLayout(stateDir: URL(fileURLWithPath: "/tmp/whoathere-vm", isDirectory: true))
    #expect(layout.bundleDir.path == "/tmp/whoathere-vm/bundle")
    #expect(layout.diskPath.path == "/tmp/whoathere-vm/bundle/disk.img")
    #expect(layout.runtimePidPath.path == "/tmp/whoathere-vm/bundle/runtime.pid")
    #expect(layout.savedStatePath.path == "/tmp/whoathere-vm/bundle/saved-state.bin")
    #expect(layout.logsDir.path == "/tmp/whoathere-vm/logs")
    #expect(layout.runsDir.path == "/tmp/whoathere-vm/runs")
}

@Test func parsesRestoreImageArguments() throws {
    let options = try parseArguments([
        "init",
        "--state-dir", "/tmp/whoathere-vm",
        "--restore-image", "/tmp/macos.ipsw",
        "--execute"
    ])

    #expect(options.command == .`init`)
    #expect(options.restoreImagePath == "/tmp/macos.ipsw")
    #expect(options.execute)
}
