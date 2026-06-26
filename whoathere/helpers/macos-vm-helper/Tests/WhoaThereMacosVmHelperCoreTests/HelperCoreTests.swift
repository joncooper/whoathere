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
    #expect(layout.healthProofPath.path == "/tmp/whoathere-vm/bundle/health.json")
    #expect(layout.guestHealthProofPath.path == "/tmp/whoathere-vm/bundle/guest-health.json")
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
