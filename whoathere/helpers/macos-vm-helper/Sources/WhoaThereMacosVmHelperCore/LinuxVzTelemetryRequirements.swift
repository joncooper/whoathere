import Foundation

public let linuxVzProtectedTelemetryRequirementsSchemaV1 =
    "whoathere.artifact_protected_telemetry_requirements.v1"
public let maximumLinuxVzProtectedTelemetryRequirementsBytesV1 = 64 * 1024

public enum LinuxVzTelemetryRequirementsError: Error, Equatable, CustomStringConvertible {
    case empty
    case limitExceeded
    case invalidSchema
    case invalidPolicy
    case nonCanonical

    public var description: String {
        switch self {
        case .empty: return "linux_vz_telemetry_requirements_empty"
        case .limitExceeded: return "linux_vz_telemetry_requirements_limit_exceeded"
        case .invalidSchema: return "linux_vz_telemetry_requirements_schema_invalid"
        case .invalidPolicy: return "linux_vz_telemetry_requirements_policy_invalid"
        case .nonCanonical: return "linux_vz_telemetry_requirements_noncanonical"
        }
    }
}

public struct LinuxVzProtectedTelemetryRequirements: Equatable, Sendable {
    public let canonicalJSON: Data
    public let requirementsSHA256: String
    public let requiredSensors: [String]
    public let limitations: [String]
}

public func decodeLinuxVzProtectedTelemetryRequirements(
    _ data: Data
) throws -> LinuxVzProtectedTelemetryRequirements {
    guard !data.isEmpty else { throw LinuxVzTelemetryRequirementsError.empty }
    guard data.count <= maximumLinuxVzProtectedTelemetryRequirementsBytesV1 else {
        throw LinuxVzTelemetryRequirementsError.limitExceeded
    }
    guard let value = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw LinuxVzTelemetryRequirementsError.invalidPolicy
    }
    guard try canonicalJSONData(value) == data else {
        throw LinuxVzTelemetryRequirementsError.nonCanonical
    }
    guard Set(value.keys) == Set([
        "schema_version", "backend_class", "required_sensors", "network_topology",
        "drop_policy", "process_attribution", "file_observation", "evidence_authority",
        "package_privilege", "scenario_reuse", "sync_back_policy", "limitations"
    ]) else {
        throw LinuxVzTelemetryRequirementsError.invalidPolicy
    }
    guard value["schema_version"] as? String
            == linuxVzProtectedTelemetryRequirementsSchemaV1 else {
        throw LinuxVzTelemetryRequirementsError.invalidSchema
    }
    let expectedSensors = linuxVzRequiredTelemetrySensorsV1()
    let expectedLimitations = [
        "encrypted_payload_content_not_decrypted",
        "fanotify_mmap_requires_bpf_corroboration",
        "guest_kernel_compromise_can_suppress_guest_sensors_host_frames_remain"
    ]
    guard value["backend_class"] as? String == "linux_vz_bulk",
          value["required_sensors"] as? [String] == expectedSensors,
          value["network_topology"] as? String
            == "host_raw_frame_sinkhole_no_external_route",
          value["drop_policy"] as? String == "incomplete_on_any_gap",
          value["process_attribution"] as? String == "cgroup_and_kernel_lineage",
          value["file_observation"] as? String == "fanotify_permission_plus_bpf_mmap",
          value["evidence_authority"] as? String == "guest_signed_and_host_corroborated",
          value["package_privilege"] as? String == "dedicated_uid_gid_no_capabilities",
          value["scenario_reuse"] as? String == "one_boot_one_scenario_destroy_clone",
          value["sync_back_policy"] as? String == "structurally_absent",
          value["limitations"] as? [String] == expectedLimitations else {
        throw LinuxVzTelemetryRequirementsError.invalidPolicy
    }
    return LinuxVzProtectedTelemetryRequirements(
        canonicalJSON: data,
        requirementsSHA256: sha256(data),
        requiredSensors: expectedSensors,
        limitations: expectedLimitations
    )
}

func linuxVzRequiredTelemetrySensorsV1() -> [String] {
    [
        "process_fork_exec_exit", "process_credentials", "dynamic_library_load",
        "file_open_read_write", "file_mmap", "persistence_writes",
        "guest_network_intent", "host_raw_frames", "dns_sinkhole", "http_sinkhole",
        "process_listener_diff", "file_system_diff", "descendant_teardown",
        "sensor_health_heartbeat", "dropped_event_accounting", "vm_clone_lifecycle"
    ]
}
