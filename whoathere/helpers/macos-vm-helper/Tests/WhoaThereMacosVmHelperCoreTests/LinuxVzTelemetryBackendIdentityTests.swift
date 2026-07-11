import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let linuxVzRequirementsSHA256 =
    "sha256:3ff8c862243232fbc48ec91d5926e587bf9817f678853d02d9730cde2c464946"

@Test func unqualifiedLinuxVzIdentityMatchesRustAndCannotAuthorizeExecution() throws {
    let data = try canonicalJSONData(linuxVzIdentityFixture())
    let identity = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
        data,
        expectedTelemetryRequirementsSHA256: linuxVzRequirementsSHA256
    )
    #expect(
        identity.identitySHA256
            == "sha256:216bab68b7bb40cbcc999112f7f4d823cdeb4ffc05990c4f73e6b36977e438b1"
    )
    #expect(identity.baseGenerationID == "linux-vz-base-generation-inert-v1")
    #expect(identity.linuxDistributionID == "whoathere-linux-inert-v1")
    #expect(identity.kernelRelease == "6.12.0-whoathere-inert-v1")
    #expect(identity.telemetryRequirementsSHA256 == linuxVzRequirementsSHA256)
    #expect(identity.packageUID == 499)
    #expect(identity.packageGID == 499)
    #expect(!identity.executionAuthorityPermitted)
}

@Test func linuxVzIdentityRejectsQualificationRebindingUnknownsAndNoncanonicalWire() throws {
    let fixture = linuxVzIdentityFixture()

    var qualified = fixture
    qualified["qualification_state"] = "qualified"
    #expect(throws: LinuxVzTelemetryBackendIdentityError.invalidIdentity) {
        try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            try canonicalJSONData(qualified),
            expectedTelemetryRequirementsSHA256: linuxVzRequirementsSHA256
        )
    }

    #expect(throws: LinuxVzTelemetryBackendIdentityError.requirementsMismatch) {
        try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            try canonicalJSONData(fixture),
            expectedTelemetryRequirementsSHA256: sha256(Data("other requirements".utf8))
        )
    }

    var unknown = fixture
    unknown["execution_enabled"] = true
    #expect(throws: LinuxVzTelemetryBackendIdentityError.invalidIdentity) {
        try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            try canonicalJSONData(unknown),
            expectedTelemetryRequirementsSHA256: linuxVzRequirementsSHA256
        )
    }

    var noncanonical = try canonicalJSONData(fixture)
    noncanonical.append(0x0a)
    #expect(throws: LinuxVzTelemetryBackendIdentityError.nonCanonical) {
        try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            noncanonical,
            expectedTelemetryRequirementsSHA256: linuxVzRequirementsSHA256
        )
    }
}

private func linuxVzIdentityFixture() -> [String: Any] {
    [
        "schema_version": linuxVzTelemetryBackendIdentitySchemaV1,
        "qualification_state": "candidate_unqualified",
        "base_generation_id": "linux-vz-base-generation-inert-v1",
        "linux_distribution_id": "whoathere-linux-inert-v1",
        "kernel_release": "6.12.0-whoathere-inert-v1",
        "kernel_image_sha256": sha256(Data("inert kernel image".utf8)),
        "initramfs_sha256": sha256(Data("inert initramfs".utf8)),
        "root_disk_sha256": sha256(Data("inert root disk".utf8)),
        "kernel_config_sha256": sha256(Data("inert kernel config".utf8)),
        "btf_sha256": sha256(Data("inert kernel btf".utf8)),
        "guest_runner_sha256": sha256(Data("inert guest runner".utf8)),
        "guest_sensor_sha256": sha256(Data("inert guest sensor".utf8)),
        "guest_bpf_bundle_sha256": sha256(Data("inert guest bpf bundle".utf8)),
        "guest_sensor_configuration_sha256": sha256(
            Data("inert guest sensor configuration".utf8)
        ),
        "guest_evidence_public_key_sha256": sha256(
            Data("inert guest evidence public key".utf8)
        ),
        "host_helper_sha256": sha256(Data("inert host helper".utf8)),
        "host_packet_sensor_sha256": sha256(Data("inert host packet sensor".utf8)),
        "host_packet_sensor_configuration_sha256": sha256(
            Data("inert host packet configuration".utf8)
        ),
        "host_evidence_public_key_sha256": sha256(
            Data("inert host evidence public key".utf8)
        ),
        "telemetry_requirements_sha256": linuxVzRequirementsSHA256,
        "package_uid": "499",
        "package_gid": "499"
    ]
}
