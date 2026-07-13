import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private func platformTestBackend() -> UnqualifiedLinuxVzTelemetryBackendIdentity {
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

@Test func platformEvidenceBindsKernelConfigAndRuntimeBTFIdentity() throws {
    let backend = platformTestBackend()
    let payload = #"{"btf_byte_length":"4096","descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"2","event_sequence_end":"2","event_sequence_start":"1","evidence_truncated":false,"fixture_case":"kernel_config_and_btf","heartbeat_count":"2","kernel_btf_magic":"9feb","kernel_btf_sha256":"sha256:5555555555555555555555555555555555555555555555555555555555555555","kernel_config_binding":"measured_backend_manifest","kernel_config_sha256":"sha256:4444444444444444444444444444444444444444444444444444444444444444","kernel_release":"6.18.35-0-virt","package_gid":"65534","package_uid":"65534","schema_version":"whoathere.linux_vz_platform_evidence_payload.v1","sensor_healthy":true}"#
    let serial = Data((linuxVzPlatformEvidenceSerialPrefixV1 + payload + "\n").utf8)
    let evidence = try decodeLinuxVzPlatformEvidencePayloadV1(serial, backend: backend)
    #expect(evidence.btfByteLength == 4096)
    #expect(evidence.claims.sensorHealthy)
    #expect(evidence.claims.observedTerminal == "observation_complete")

    var object = try #require(
        JSONSerialization.jsonObject(with: Data(payload.utf8)) as? [String: Any]
    )
    object["kernel_config_sha256"] = "sha256:" + String(repeating: "0", count: 64)
    let changed = try canonicalJSONData(object)
    #expect(throws: LinuxVzPlatformEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzPlatformEvidencePayloadV1(
            Data(linuxVzPlatformEvidenceSerialPrefixV1.utf8) + changed + Data("\n".utf8),
            backend: backend
        )
    }
}
