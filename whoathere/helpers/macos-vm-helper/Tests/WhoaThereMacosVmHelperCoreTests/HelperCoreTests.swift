import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func defaultsUseRestoreSafeDiskSize() {
    let options = HelperOptions(command: .status)
    #expect(defaultDiskGiB == 64)
    #expect(minimumRestoreDiskGiB == 64)
    #expect(options.diskGiB == minimumRestoreDiskGiB)
}

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
    #expect(layout.healthProofPath.path == "/tmp/whoathere-vm/bundle/health.json")
    #expect(layout.guestHealthProofPath.path == "/tmp/whoathere-vm/bundle/guest-health.json")
    #expect(layout.guestProvisioningReceiptPath.path == "/tmp/whoathere-vm/bundle/guest-provisioning.json")
    #expect(layout.guestToolsImagePath.path == "/tmp/whoathere-vm/bundle/guest-tools.dmg")
    #expect(layout.runtimeShutdownPath.path == "/tmp/whoathere-vm/bundle/shutdown.json")
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

@Test func parsesFetchLatestRestoreImageArgument() throws {
    let options = try parseArguments([
        "init",
        "--state-dir", "/tmp/whoathere-vm",
        "--fetch-latest-restore-image",
        "--execute"
    ])

    #expect(options.command == .`init`)
    #expect(options.fetchLatestRestoreImage)
    #expect(options.execute)
}

@Test func parsesUpgradeLocalManifestArguments() throws {
    let options = try parseArguments([
        "upgrade-local-manifest",
        "--state-dir", "/tmp/whoathere-vm",
        "--execute",
        "--json"
    ])

    #expect(options.command == .upgradeLocalManifest)
    #expect(options.stateDir == "/tmp/whoathere-vm")
    #expect(options.execute)
    #expect(options.json)
}

@Test func parsesDetonationArguments() throws {
    let options = try parseArguments([
        "detonate",
        "--state-dir", "/tmp/whoathere-vm",
        "--tool=npm",
        "--command-class", "npm_install_detonation",
        "--fixture", "clean_npm_lifecycle",
        "--timeout-seconds=45",
        "--execute",
        "--json",
        "--",
        "ci"
    ])

    #expect(options.command == .detonate)
    #expect(options.stateDir == "/tmp/whoathere-vm")
    #expect(options.detonationTool == "npm")
    #expect(options.detonationCommandClass == "npm_install_detonation")
    #expect(options.detonationFixture == "clean_npm_lifecycle")
    #expect(options.detonationTimeoutSeconds == 45)
    #expect(options.detonationArgs == ["ci"])
    #expect(options.execute)
    #expect(options.json)
}

@Test func parsesProjectDetonationArguments() throws {
    let options = try parseArguments([
        "detonate",
        "--state-dir", "/tmp/whoathere-vm",
        "--tool", "pip",
        "--command-class=pip_install_detonation",
        "--fixture", "project_mirror",
        "--project-payload-path", "/tmp/whoathere-vm/runs/project-payloads/1.payload.hex",
        "--project-workflow=pip_project_install",
        "--project-import-module", "whoathere_clean",
        "--project-api-probe",
        "--project-requirements-path=requirements.txt",
        "--sync-back",
        "--execute",
        "--",
        "install",
        "."
    ])

    #expect(options.command == .detonate)
    #expect(options.stateDir == "/tmp/whoathere-vm")
    #expect(options.detonationTool == "pip")
    #expect(options.detonationCommandClass == "pip_install_detonation")
    #expect(options.detonationFixture == "project_mirror")
    #expect(options.detonationProjectPayloadPath == "/tmp/whoathere-vm/runs/project-payloads/1.payload.hex")
    #expect(options.detonationProjectWorkflow == "pip_project_install")
    #expect(options.detonationProjectImportModule == "whoathere_clean")
    #expect(options.detonationProjectApiProbe)
    #expect(options.detonationProjectRequirementsPath == "requirements.txt")
    #expect(options.detonationSyncBack)
    #expect(options.detonationArgs == ["install", "."])
    #expect(options.execute)
}

@Test func guestHealthProofAcceptsMatchingRuntimeHostAndGuestEvidence() {
    let runtime = runtimeState()
    let host = hostProof()
    let guest = guestProof()

    let reasons = validateGuestHealthProof(
        runtimeState: runtime,
        hostProof: host,
        guestProof: guest,
        runtimePID: 1234,
        expectedHelperVersion: helperVersion,
        expectedProtocol: "whoathere.guest_ready.v1",
        expectedPort: 47078
    )

    #expect(reasons.isEmpty)
}

@Test func guestHealthProofRejectsWrongSessionChallengeAndImageDigest() {
    let runtime = runtimeState()
    let host = hostProof()
    var guest = guestProof()
    guest["vm_session_id"] = "wrong-session"
    guest["guest_readiness_challenge_sha256"] = "wrong-challenge-hash"
    guest["image_digest"] = "sha256:wrong"

    let reasons = validateGuestHealthProof(
        runtimeState: runtime,
        hostProof: host,
        guestProof: guest,
        runtimePID: 1234,
        expectedHelperVersion: helperVersion,
        expectedProtocol: "whoathere.guest_ready.v1",
        expectedPort: 47078
    )

    #expect(reasons.contains("guest_proof_session_mismatch"))
    #expect(reasons.contains("guest_proof_challenge_hash_mismatch"))
    #expect(reasons.contains("guest_proof_image_digest_mismatch"))
}

@Test func guestHealthProofRejectsHostProofMismatch() {
    let runtime = runtimeState()
    var host = hostProof()
    let guest = guestProof()
    host["guest_readiness_challenge_sha256"] = "wrong-challenge-hash"
    host["host_runtime_health_proven"] = false

    let reasons = validateGuestHealthProof(
        runtimeState: runtime,
        hostProof: host,
        guestProof: guest,
        runtimePID: 1234,
        expectedHelperVersion: helperVersion,
        expectedProtocol: "whoathere.guest_ready.v1",
        expectedPort: 47078
    )

    #expect(reasons.contains("host_proof_challenge_hash_mismatch"))
    #expect(reasons.contains("host_runtime_health_not_proven"))
}

@Test func guestHealthProofRejectsProtocolAndPortMismatch() {
    let runtime = runtimeState()
    let host = hostProof()
    var guest = guestProof()
    guest["guest_readiness_protocol"] = "unexpected"
    guest["guest_readiness_port"] = 1

    let reasons = validateGuestHealthProof(
        runtimeState: runtime,
        hostProof: host,
        guestProof: guest,
        runtimePID: 1234,
        expectedHelperVersion: helperVersion,
        expectedProtocol: "whoathere.guest_ready.v1",
        expectedPort: 47078
    )

    #expect(reasons.contains("guest_proof_protocol_mismatch"))
    #expect(reasons.contains("guest_proof_port_mismatch"))
}

@Test func guestHealthProofRejectsHighRiskExecutionEnabledMarkers() {
    var runtime = runtimeState()
    var host = hostProof()
    var guest = guestProof()
    runtime["high_risk_package_execution_enabled"] = true
    host["high_risk_package_execution_enabled"] = true
    guest["high_risk_package_execution_enabled"] = true

    let reasons = validateGuestHealthProof(
        runtimeState: runtime,
        hostProof: host,
        guestProof: guest,
        runtimePID: 1234,
        expectedHelperVersion: helperVersion,
        expectedProtocol: "whoathere.guest_ready.v1",
        expectedPort: 47078
    )

    #expect(reasons.contains("runtime_state_high_risk_execution_not_disabled"))
    #expect(reasons.contains("host_proof_high_risk_execution_not_disabled"))
    #expect(reasons.contains("guest_proof_high_risk_execution_not_disabled"))
}

private func runtimeState() -> [String: Any] {
    [
        "schema_version": bundleSchemaVersion,
        "helper_version": helperVersion,
        "runtime_pid": 1234,
        "vm_session_id": "session-1",
        "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "guest_readiness_challenge_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "high_risk_package_execution_enabled": false
    ]
}

private func hostProof() -> [String: Any] {
    [
        "schema_version": bundleSchemaVersion,
        "helper_version": helperVersion,
        "runtime_pid": 1234,
        "vm_session_id": "session-1",
        "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "health_proof_type": "host_vm_start_only",
        "host_runtime_health_proven": true,
        "guest_readiness_challenge_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "high_risk_package_execution_enabled": false
    ]
}

private func guestProof() -> [String: Any] {
    [
        "schema_version": bundleSchemaVersion,
        "helper_version": helperVersion,
        "runtime_pid": 1234,
        "vm_session_id": "session-1",
        "image_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "health_proof_type": "guest_vsock_readiness",
        "guest_health_proven": true,
        "guest_readiness_protocol": "whoathere.guest_ready.v1",
        "guest_readiness_port": 47078,
        "guest_readiness_challenge_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "high_risk_package_execution_enabled": false
    ]
}
