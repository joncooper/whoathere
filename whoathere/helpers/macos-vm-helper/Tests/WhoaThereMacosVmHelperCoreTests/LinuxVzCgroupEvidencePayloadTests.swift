import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private func cgroupTestBackend() -> UnqualifiedLinuxVzTelemetryBackendIdentity {
    UnqualifiedLinuxVzTelemetryBackendIdentity(
        canonicalJSON: Data("backend".utf8),
        identitySHA256: "sha256:" + String(repeating: "0", count: 64),
        baseGenerationID: "base",
        linuxDistributionID: "alpine-aarch64",
        kernelRelease: "6.18.35-0-virt",
        kernelImageSHA256: "sha256:" + String(repeating: "1", count: 64),
        initramfsSHA256: "sha256:" + String(repeating: "2", count: 64),
        rootDiskSHA256: "sha256:" + String(repeating: "3", count: 64),
        kernelConfigSHA256: "sha256:" + String(repeating: "4", count: 64),
        btfSHA256: "sha256:" + String(repeating: "5", count: 64),
        guestRunnerSHA256: "sha256:" + String(repeating: "6", count: 64),
        guestSensorSHA256: "sha256:" + String(repeating: "7", count: 64),
        guestBPFBundleSHA256: "sha256:" + String(repeating: "8", count: 64),
        guestSensorConfigurationSHA256: "sha256:" + String(repeating: "9", count: 64),
        guestEvidencePublicKeySHA256: "sha256:" + String(repeating: "a", count: 64),
        hostHelperSHA256: "sha256:" + String(repeating: "b", count: 64),
        hostPacketSensorSHA256: "sha256:" + String(repeating: "c", count: 64),
        hostPacketSensorConfigurationSHA256: "sha256:" + String(repeating: "d", count: 64),
        hostEvidencePublicKeySHA256: "sha256:" + String(repeating: "e", count: 64),
        telemetryRequirementsSHA256: "sha256:" + String(repeating: "f", count: 64),
        packageUID: 65534,
        packageGID: 65534
    )
}

@Test func cgroupEvidenceBindsRuntimeMembershipAndTeardown() throws {
    let backend = cgroupTestBackend()
    let payload = #"{"cgroup2_filesystem_magic":"63677270","child_cgroup_created":true,"child_cgroup_name":"whoathere-cgroup-v2-probe","child_cgroup_removed":true,"child_cgroup_type":"domain","child_empty_after_return":true,"child_membership_observed":true,"child_populated_observed":true,"controller_count":"3","controllers":["cpu","memory","pids"],"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"5","event_sequence_end":"5","event_sequence_start":"1","evidence_truncated":false,"fixture_case":"cgroup_v2","heartbeat_count":"2","membership_pid":"42","membership_process_binding":"measured_guest_signer_process","mount_path":"/sys/fs/cgroup","mountinfo_filesystem":"cgroup2","package_gid":"65534","package_uid":"65534","schema_version":"whoathere.linux_vz_cgroup_evidence_payload.v1","sensor_healthy":true}"#
    let serial = Data((linuxVzCgroupEvidenceSerialPrefixV1 + payload + "\n").utf8)
    let evidence = try decodeLinuxVzCgroupEvidencePayloadV1(serial, backend: backend)
    #expect(evidence.controllers == ["cpu", "memory", "pids"])
    #expect(evidence.membershipPID == 42)
    #expect(evidence.claims.descendantTeardownComplete)

    var object = try #require(
        JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any]
    )
    object["child_cgroup_removed"] = false
    let changed = try canonicalJSONData(object)
    #expect(throws: LinuxVzCgroupEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzCgroupEvidencePayloadV1(
            Data(linuxVzCgroupEvidenceSerialPrefixV1.utf8) + changed + Data("\n".utf8),
            backend: backend
        )
    }
}
