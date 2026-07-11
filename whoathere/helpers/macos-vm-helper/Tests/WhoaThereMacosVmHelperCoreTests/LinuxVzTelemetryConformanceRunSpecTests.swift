import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzConformanceRunSpecMatchesRustAndDisablesPackageExecution() throws {
    let fixture = try linuxVzConformanceFixture()
    let data = try canonicalJSONData(fixture)
    let spec = try decodeLinuxVzTelemetryConformanceRunSpec(data)
    #expect(
        spec.runSpecSHA256
            == "sha256:325a67c4e1690f2b04b6735d5f4463beb248ce68e15868e0337d4b0443ddd671"
    )
    #expect(spec.fixture == "network_intent")
    #expect(spec.expectedSensors.count == 7)
    #expect(!spec.packageExecutionAuthorityPermitted)
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

private func linuxVzConformanceFixture() throws -> [String: Any] {
    let requirements = linuxVzRequirementsFixture()
    let requirementsData = try canonicalJSONData(requirements)
    let requirementsSHA256 = sha256(requirementsData)
    let backend = linuxVzConformanceBackendFixture(
        requirementsSHA256: requirementsSHA256
    )
    let backendData = try canonicalJSONData(backend)
    return [
        "schema_version": linuxVzTelemetryConformanceRunSpecSchemaV1,
        "canonicalization": "rfc8785.jcs.v1",
        "conformance_run_id": "linux-vz-conformance-run-golden",
        "evidence_id": "linux-vz-conformance-evidence-golden",
        "fixture": "network_intent",
        "fixture_binary_sha256": sha256(Data("inert golden conformance fixture".utf8)),
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
        "telemetry_requirements_sha256": requirementsSHA256,
        "package_uid": "499",
        "package_gid": "499"
    ]
}
