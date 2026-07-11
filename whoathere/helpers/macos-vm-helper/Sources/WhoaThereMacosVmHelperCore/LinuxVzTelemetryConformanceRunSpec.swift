import Foundation

public let linuxVzTelemetryConformanceRunSpecSchemaV1 =
    "whoathere.macos_linux_vz_telemetry_conformance_run_spec.v1"
public let linuxVzTelemetryConformanceProtocolV1 =
    "whoathere.linux_vz_telemetry_conformance.v1"
public let maximumLinuxVzTelemetryConformanceRunSpecBytesV1 = 256 * 1024

public enum LinuxVzTelemetryConformanceRunSpecError: Error, Equatable,
    CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidIdentity
    case invalidFixture
    case requirementsMismatch
    case backend(LinuxVzTelemetryBackendIdentityError)
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_telemetry_conformance_run_spec_empty"
        case .limitExceeded: return "linux_vz_telemetry_conformance_run_spec_limit_exceeded"
        case .invalidSchema: return "linux_vz_telemetry_conformance_run_spec_schema_invalid"
        case .invalidIdentity: return "linux_vz_telemetry_conformance_run_spec_identity_invalid"
        case .invalidFixture: return "linux_vz_telemetry_conformance_run_spec_fixture_invalid"
        case .requirementsMismatch: return "linux_vz_telemetry_conformance_requirements_mismatch"
        case .backend(let error): return error.description
        case .nonCanonical: return "linux_vz_telemetry_conformance_run_spec_noncanonical"
        }
    }
}

public struct LinuxVzTelemetryConformanceRunSpec: Equatable, Sendable {
    public let canonicalJSON: Data
    public let runSpecSHA256: String
    public let conformanceRunID: String
    public let evidenceID: String
    public let fixture: String
    public let fixtureCase: String
    public let fixtureBinarySHA256: String
    public let expectedTerminal: String
    public let expectedSensors: [String]
    public let telemetryRequirementsSHA256: String
    public let backendIdentitySHA256: String

    public var packageExecutionAuthorityPermitted: Bool { false }
}

func linuxVzConformanceExpectedGuestSensors(_ runSpec: LinuxVzTelemetryConformanceRunSpec) -> [String] {
    let hostOnly = Set([
        "host_raw_frames", "dns_sinkhole", "http_sinkhole", "vm_clone_lifecycle"
    ])
    return runSpec.expectedSensors.filter { !hostOnly.contains($0) }
}

func linuxVzConformanceExpectedHostSensors(_ runSpec: LinuxVzTelemetryConformanceRunSpec) -> [String] {
    let host = Set([
        "host_raw_frames", "dns_sinkhole", "http_sinkhole", "vm_clone_lifecycle",
        "sensor_health_heartbeat", "dropped_event_accounting"
    ])
    return runSpec.expectedSensors.filter { host.contains($0) }
}

public func decodeLinuxVzTelemetryConformanceRunSpec(
    _ data: Data
) throws -> LinuxVzTelemetryConformanceRunSpec {
    guard !data.isEmpty else { throw LinuxVzTelemetryConformanceRunSpecError.empty }
    guard data.count <= maximumLinuxVzTelemetryConformanceRunSpecBytesV1 else {
        throw LinuxVzTelemetryConformanceRunSpecError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTelemetryConformanceRunSpecError.invalidSchema
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzTelemetryConformanceRunSpecError.nonCanonical
    }
    guard Set(value.keys) == Set([
        "schema_version", "canonicalization", "conformance_run_id", "evidence_id",
        "fixture", "fixture_case", "fixture_binary_sha256", "expected_terminal",
        "expected_sensors", "telemetry_requirements",
        "telemetry_requirements_sha256", "backend_identity", "backend_identity_sha256",
        "execution_posture", "package_execution", "network_topology", "external_network",
        "clone_policy", "sync_back_policy", "limits", "guest_protocol"
    ]) else {
        throw LinuxVzTelemetryConformanceRunSpecError.invalidSchema
    }
    guard value["schema_version"] as? String == linuxVzTelemetryConformanceRunSpecSchemaV1,
          value["canonicalization"] as? String == "rfc8785.jcs.v1",
          value["execution_posture"] as? String
            == "trusted_inert_fixture_only_no_package_code",
          value["package_execution"] as? String == "disabled",
          value["network_topology"] as? String
            == "host_raw_frame_sinkhole_no_external_route",
          value["external_network"] as? String == "no_external_route",
          value["clone_policy"] as? String == "one_boot_one_fixture_destroy_clone",
          value["sync_back_policy"] as? String == "structurally_absent",
          value["guest_protocol"] as? String == linuxVzTelemetryConformanceProtocolV1,
          let runID = value["conformance_run_id"] as? String,
          let evidenceID = value["evidence_id"] as? String,
          linuxVzConformanceValidIdentity(runID),
          linuxVzConformanceValidIdentity(evidenceID),
          let fixture = value["fixture"] as? String,
          let fixtureCase = value["fixture_case"] as? String,
          fixture == linuxVzConformanceFixture(fixtureCase),
          let expectedTerminal = value["expected_terminal"] as? String,
          expectedTerminal == linuxVzConformanceExpectedTerminal(fixtureCase),
          let expectedSensors = value["expected_sensors"] as? [String],
          expectedSensors == linuxVzConformanceExpectedSensors(fixture),
          let fixtureDigest = value["fixture_binary_sha256"] as? String,
          linuxVzConformanceValidDigest(fixtureDigest),
          let requirementsValue = value["telemetry_requirements"] as? [String: Any],
          let requirementsDigest = value["telemetry_requirements_sha256"] as? String,
          linuxVzConformanceValidDigest(requirementsDigest),
          let backendValue = value["backend_identity"] as? [String: Any],
          let backendDigest = value["backend_identity_sha256"] as? String,
          linuxVzConformanceValidDigest(backendDigest),
          let limits = value["limits"] as? [String: Any],
          Set(limits.keys) == Set([
              "wall_clock_millis", "max_guest_events", "max_host_frames", "max_evidence_bytes"
          ]),
          limits["wall_clock_millis"] as? String == "30000",
          limits["max_guest_events"] as? String == "1000000",
          limits["max_host_frames"] as? String == "65536",
          limits["max_evidence_bytes"] as? String == "16777216" else {
        throw LinuxVzTelemetryConformanceRunSpecError.invalidSchema
    }
    let requirementsData = try canonicalJSONData(requirementsValue)
    let requirements: LinuxVzProtectedTelemetryRequirements
    do {
        requirements = try decodeLinuxVzProtectedTelemetryRequirements(requirementsData)
    } catch {
        throw LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch
    }
    guard requirements.requirementsSHA256 == requirementsDigest else {
        throw LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch
    }
    let backendData = try canonicalJSONData(backendValue)
    let backend: UnqualifiedLinuxVzTelemetryBackendIdentity
    do {
        backend = try decodeUnqualifiedLinuxVzTelemetryBackendIdentity(
            backendData,
            expectedTelemetryRequirementsSHA256: requirements.requirementsSHA256
        )
    } catch let error as LinuxVzTelemetryBackendIdentityError {
        throw LinuxVzTelemetryConformanceRunSpecError.backend(error)
    }
    guard backend.identitySHA256 == backendDigest, !backend.executionAuthorityPermitted else {
        throw LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch
    }
    guard fixtureDigest == backend.guestRunnerSHA256 else {
        throw LinuxVzTelemetryConformanceRunSpecError.requirementsMismatch
    }
    return LinuxVzTelemetryConformanceRunSpec(
        canonicalJSON: data,
        runSpecSHA256: sha256(data),
        conformanceRunID: runID,
        evidenceID: evidenceID,
        fixture: fixture,
        fixtureCase: fixtureCase,
        fixtureBinarySHA256: fixtureDigest,
        expectedTerminal: expectedTerminal,
        expectedSensors: expectedSensors,
        telemetryRequirementsSHA256: requirementsDigest,
        backendIdentitySHA256: backendDigest
    )
}

func linuxVzAllTelemetryConformanceCasesV1() -> [String] {
    [
        "kernel_config_and_btf", "cgroup_v2", "fanotify_permission",
        "bpf_program_types", "raw_frame_attachment", "fork_exec_exit", "reparenting",
        "double_fork_daemonization", "setsid_escape", "credential_change",
        "dynamic_library_load", "protected_open_read_write_rename_delete", "mmap_access",
        "ipv4_connect", "ipv6_connect", "udp_send", "loopback_connect",
        "private_address_connect", "link_local_connect", "metadata_address_connect",
        "public_address_connect", "dns_plaintext", "dns_malformed", "encrypted_dns_connect",
        "bpf_reservation_failure", "fanotify_queue_overflow", "host_frame_overflow",
        "normal_exit", "timeout", "term_resistance", "escaped_session", "reparented_child",
        "background_listener", "channel_interruption", "vm_stop", "guest_sensor_death",
        "host_sensor_death", "all_protected_assets_denied"
    ]
}

func linuxVzConformanceFixture(_ fixtureCase: String) -> String? {
    let platform = Set([
        "kernel_config_and_btf", "cgroup_v2", "fanotify_permission", "bpf_program_types",
        "raw_frame_attachment"
    ])
    let process = Set([
        "fork_exec_exit", "reparenting", "double_fork_daemonization", "setsid_escape",
        "credential_change", "dynamic_library_load"
    ])
    let file = Set(["protected_open_read_write_rename_delete", "mmap_access"])
    let network = Set([
        "ipv4_connect", "ipv6_connect", "udp_send", "loopback_connect",
        "private_address_connect", "link_local_connect", "metadata_address_connect",
        "public_address_connect", "dns_plaintext", "dns_malformed", "encrypted_dns_connect"
    ])
    let drops = Set([
        "bpf_reservation_failure", "fanotify_queue_overflow", "host_frame_overflow"
    ])
    let teardown = Set([
        "normal_exit", "timeout", "term_resistance", "escaped_session", "reparented_child",
        "background_listener", "channel_interruption", "vm_stop"
    ])
    if platform.contains(fixtureCase) { return "platform_capabilities" }
    if process.contains(fixtureCase) { return "process_lineage" }
    if file.contains(fixtureCase) { return "file_canary" }
    if network.contains(fixtureCase) { return "network_intent" }
    if drops.contains(fixtureCase) { return "drop_accounting" }
    if teardown.contains(fixtureCase) { return "teardown_stress" }
    if ["guest_sensor_death", "host_sensor_death"].contains(fixtureCase) {
        return "sensor_tamper"
    }
    if fixtureCase == "all_protected_assets_denied" { return "package_isolation" }
    return nil
}

func linuxVzConformanceExpectedTerminal(_ fixtureCase: String) -> String? {
    if [
        "bpf_reservation_failure", "fanotify_queue_overflow", "host_frame_overflow"
    ].contains(fixtureCase) {
        return "incomplete_on_injected_gap"
    }
    if [
        "timeout", "term_resistance", "escaped_session", "reparented_child",
        "background_listener"
    ].contains(fixtureCase) {
        return "timeout_with_teardown"
    }
    if [
        "channel_interruption", "vm_stop", "guest_sensor_death", "host_sensor_death"
    ].contains(fixtureCase) {
        return "infrastructure_error_with_teardown"
    }
    if fixtureCase == "all_protected_assets_denied" {
        return "access_denied_with_complete_evidence"
    }
    if linuxVzAllTelemetryConformanceCasesV1().contains(fixtureCase) {
        return "observation_complete"
    }
    return nil
}

func linuxVzConformanceExpectedSensors(_ fixture: String) -> [String]? {
    switch fixture {
    case "platform_capabilities":
        return [
            "sensor_health_heartbeat", "dropped_event_accounting", "vm_clone_lifecycle"
        ]
    case "process_lineage":
        return [
            "process_fork_exec_exit", "process_credentials", "dynamic_library_load",
            "sensor_health_heartbeat", "dropped_event_accounting"
        ]
    case "file_canary":
        return [
            "file_open_read_write", "file_mmap", "persistence_writes", "file_system_diff",
            "sensor_health_heartbeat", "dropped_event_accounting"
        ]
    case "network_intent":
        return [
            "guest_network_intent", "host_raw_frames", "dns_sinkhole", "http_sinkhole",
            "process_listener_diff", "sensor_health_heartbeat", "dropped_event_accounting"
        ]
    case "drop_accounting":
        return ["sensor_health_heartbeat", "dropped_event_accounting"]
    case "teardown_stress":
        return [
            "process_fork_exec_exit", "process_listener_diff", "descendant_teardown",
            "sensor_health_heartbeat", "dropped_event_accounting", "vm_clone_lifecycle"
        ]
    case "sensor_tamper":
        return [
            "process_credentials", "file_open_read_write", "host_raw_frames",
            "sensor_health_heartbeat", "dropped_event_accounting", "vm_clone_lifecycle"
        ]
    case "package_isolation":
        return [
            "process_credentials", "file_open_read_write", "sensor_health_heartbeat",
            "dropped_event_accounting", "vm_clone_lifecycle"
        ]
    default:
        return nil
    }
}

private func linuxVzConformanceValidIdentity(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 128
        && value.unicodeScalars.allSatisfy { scalar in
            scalar.isASCII && (
                (scalar.value >= 48 && scalar.value <= 57)
                    || (scalar.value >= 65 && scalar.value <= 90)
                    || (scalar.value >= 97 && scalar.value <= 122)
                    || [45, 46, 95].contains(scalar.value)
            )
        }
}

private func linuxVzConformanceValidDigest(_ value: String) -> Bool {
    value.utf8.count == 71 && value.hasPrefix("sha256:")
        && value.dropFirst(7).utf8.allSatisfy {
            ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102)
        }
}
