import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzConformanceRunSpecMatchesRustAndDisablesPackageExecution() throws {
    let fixture = try linuxVzConformanceFixture()
    let data = try canonicalJSONData(fixture)
    let spec = try decodeLinuxVzTelemetryConformanceRunSpec(data)
    #expect(
        spec.runSpecSHA256
            == "sha256:4fd12743b8a404e68e171058b13c4ae797d35548cad068fc6a08fd23c410bf4b"
    )
    #expect(spec.fixture == "network_intent")
    #expect(spec.fixtureCase == "dns_plaintext")
    #expect(spec.expectedTerminal == "observation_complete")
    #expect(spec.expectedSensors.count == 7)
    #expect(!spec.packageExecutionAuthorityPermitted)
}

@Test func linuxVzConformanceRunSpecAcceptsEveryClosedCaseExactly() throws {
    let base = try linuxVzConformanceFixture()
    let cases = linuxVzAllTelemetryConformanceCasesV1()
    #expect(cases.count == 38)
    #expect(Set(cases).count == cases.count)
    for fixtureCase in cases {
        let fixture = try #require(linuxVzConformanceFixture(fixtureCase))
        let expectedTerminal = try #require(
            linuxVzConformanceExpectedTerminal(fixtureCase)
        )
        let expectedSensors = try #require(linuxVzConformanceExpectedSensors(fixture))
        var value = base
        value["fixture_case"] = fixtureCase
        value["fixture"] = fixture
        value["expected_terminal"] = expectedTerminal
        value["expected_sensors"] = expectedSensors
        let decoded = try decodeLinuxVzTelemetryConformanceRunSpec(
            try canonicalJSONData(value)
        )
        #expect(decoded.fixtureCase == fixtureCase)
        #expect(decoded.expectedTerminal == expectedTerminal)
        #expect(!decoded.packageExecutionAuthorityPermitted)
    }
}

@Test func linuxVzConformanceChallengeMatchesRustAndRejectsRebinding() throws {
    let runValue = try linuxVzConformanceFixture(
        runID: "linux-vz-conformance-run-challenge-golden",
        evidenceID: "linux-vz-conformance-evidence-challenge-golden"
    )
    let runData = try canonicalJSONData(runValue)
    let runSpec = try decodeLinuxVzTelemetryConformanceRunSpec(runData)
    let backendValue = try #require(runValue["backend_identity"] as? [String: Any])
    let requirementsSHA256 = try #require(
        runValue["telemetry_requirements_sha256"] as? String
    )
    let backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
        try canonicalJSONData(backendValue),
        expectedTelemetryRequirementsSHA256: requirementsSHA256
    )
    var challenge: [String: Any] = [
        "schema_version": linuxVzTelemetryConformanceChallengeSchemaV1,
        "nonce_hex": String(repeating: "42", count: 32),
        "challenge_purpose": "trusted_inert_telemetry_conformance_only",
        "run_spec_sha256": runSpec.runSpecSHA256,
        "backend_identity_sha256": backend.identitySHA256,
        "telemetry_requirements_sha256": requirementsSHA256,
        "clone_binding_sha256": sha256(Data("inert disposable clone binding".utf8)),
        "guest_evidence_public_key_sha256": backend.guestEvidencePublicKeySHA256,
        "host_evidence_public_key_sha256": backend.hostEvidencePublicKeySHA256,
        "package_execution": "disabled",
        "sync_back_policy": "structurally_absent"
    ]
    let data = try canonicalJSONData(challenge)
    let decoded = try decodeLinuxVzTelemetryConformanceChallenge(
        data,
        expectedRunSpec: runSpec,
        expectedBackend: backend
    )
    #expect(
        decoded.challengeSHA256
            == "sha256:28136636fa8be52022213f238b9a39b55c35a837eb8262552dc5eeae55400ff6"
    )
    #expect(!decoded.packageExecutionAuthorityPermitted)

    challenge["package_execution"] = "enabled"
    #expect(throws: LinuxVzTelemetryConformanceEvidenceError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceChallenge(
            try canonicalJSONData(challenge),
            expectedRunSpec: runSpec,
            expectedBackend: backend
        )
    }
}

@Test func linuxVzConformanceRunSpecRejectsSensorGapsExecutionAndRebinding() throws {
    let fixture = try linuxVzConformanceFixture()

    var missing = fixture
    var sensors = try #require(missing["expected_sensors"] as? [String])
    sensors.removeLast()
    missing["expected_sensors"] = sensors
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(missing))
    }

    var executing = fixture
    executing["package_execution"] = "enabled"
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(executing))
    }

    var relabeled = fixture
    relabeled["fixture_case"] = "mmap_access"
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(relabeled))
    }

    var substituted = fixture
    substituted["fixture_binary_sha256"] = sha256(Data("unmeasured fixture binary".utf8))
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(substituted))
    }

    var unknown = fixture
    unknown["execute"] = true
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.invalidSchema) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(unknown))
    }

    var rebound = fixture
    rebound["backend_identity_sha256"] = sha256(Data("rebound backend".utf8))
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(rebound))
    }

    var requirementsGap = fixture
    var requirements = try #require(
        requirementsGap["telemetry_requirements"] as? [String: Any]
    )
    var required = try #require(requirements["required_sensors"] as? [String])
    required.removeLast()
    requirements["required_sensors"] = required
    requirementsGap["telemetry_requirements"] = requirements
    requirementsGap["telemetry_requirements_sha256"] = sha256(
        try canonicalJSONData(requirements)
    )
    #expect(throws: LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch) {
        try decodeLinuxVzTelemetryConformanceRunSpec(try canonicalJSONData(requirementsGap))
    }
}

private func linuxVzConformanceFixture(
    runID: String = "linux-vz-conformance-run-golden",
    evidenceID: String = "linux-vz-conformance-evidence-golden"
) throws -> [String: Any] {
    let requirements = linuxVzRequirementsFixture()
    let requirementsData = try canonicalJSONData(requirements)
    let requirementsSHA256 = sha256(requirementsData)
    let backend = linuxVzConformanceBackendFixture(
        requirementsSHA256: requirementsSHA256
    )
    let backendData = try canonicalJSONData(backend)
    let fixtureBinarySHA256 = try #require(backend["guest_runner_sha256"] as? String)
    return [
        "schema_version": linuxVzTelemetryConformanceRunSpecSchemaV1,
        "canonicalization": "rfc8785.jcs.v1",
        "conformance_run_id": runID,
        "evidence_id": evidenceID,
        "fixture": "network_intent",
        "fixture_case": "dns_plaintext",
        "fixture_binary_sha256": fixtureBinarySHA256,
        "expected_terminal": "observation_complete",
        "expected_sensors": [
            "guest_network_intent", "host_raw_frames", "dns_sinkhole", "http_sinkhole",
            "process_listener_diff", "sensor_health_heartbeat", "dropped_event_accounting"
        ],
        "telemetry_requirements": requirements,
        "telemetry_requirements_sha256": requirementsSHA256,
        "backend_identity": backend,
        "backend_identity_sha256": sha256(backendData),
        "execution_posture": "trusted_inert_fixture_only_no_package_code",
        "package_execution": "disabled",
        "network_topology": "host_raw_frame_sinkhole_no_external_route",
        "external_network": "no_external_route",
        "clone_policy": "one_boot_one_fixture_destroy_clone",
        "sync_back_policy": "structurally_absent",
        "limits": [
            "wall_clock_millis": "30000",
            "max_guest_events": "1000000",
            "max_host_frames": "65536",
            "max_evidence_bytes": "16777216"
        ],
        "guest_protocol": linuxVzTelemetryConformanceProtocolV1
    ]
}

private func linuxVzRequirementsFixture() -> [String: Any] {
    [
        "schema_version": linuxVzProtectedTelemetryRequirementsSchemaV1,
        "backend_class": "linux_vz_bulk",
        "required_sensors": linuxVzRequiredTelemetrySensorsV1(),
        "network_topology": "host_raw_frame_sinkhole_no_external_route",
        "drop_policy": "incomplete_on_any_gap",
        "process_attribution": "cgroup_and_kernel_lineage",
        "file_observation": "fanotify_permission_plus_bpf_mmap",
        "evidence_authority": "guest_signed_and_host_corroborated",
        "package_privilege": "dedicated_uid_gid_no_capabilities",
        "scenario_reuse": "one_boot_one_scenario_destroy_clone",
        "sync_back_policy": "structurally_absent",
        "limitations": [
            "encrypted_payload_content_not_decrypted",
            "fanotify_mmap_requires_bpf_corroboration",
            "guest_kernel_compromise_can_suppress_guest_sensors_host_frames_remain"
        ]
    ]
}

private func linuxVzConformanceBackendFixture(
    requirementsSHA256: String
) -> [String: Any] {
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
        "telemetry_requirements_sha256": requirementsSHA256,
        "package_uid": "499",
        "package_gid": "499"
    ]
}
