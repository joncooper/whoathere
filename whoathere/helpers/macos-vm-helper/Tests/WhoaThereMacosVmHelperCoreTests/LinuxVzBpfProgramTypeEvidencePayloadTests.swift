import Foundation
@testable import WhoaThereMacosVmHelperCore
import Testing

@Test func linuxVzBpfProgramTypeEvidenceBindsLoadAttachTriggerAndTeardown() throws {
    var value = bpfProgramTypeEvidenceValue()
    let evidence = try decodeLinuxVzBpfProgramTypeEvidencePayloadV1(
        Data(linuxVzBpfProgramTypeEvidenceSerialPrefixV1.utf8) + canonicalJSONData(value)
    )
    #expect(evidence.packageUID == 65534)
    #expect(evidence.rawTracepointActorPID == 411)
    #expect(evidence.rawTracepointCgroupID == 21)
    #expect(evidence.rawTracepointProgramID == 43)
    #expect(evidence.socketFilterProgramID == 44)
    #expect(evidence.claims.sensorHealthy)
    #expect(evidence.claims.droppedEventCount == 0)

    value["socket_filter_output_bytes"] = "8"
    #expect(throws: LinuxVzBpfProgramTypeEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzBpfProgramTypeEvidencePayloadV1(
            Data(linuxVzBpfProgramTypeEvidenceSerialPrefixV1.utf8) + canonicalJSONData(value)
        )
    }
}

private func bpfProgramTypeEvidenceValue() -> [String: Any] {
    [
        "descendant_teardown_complete": true,
        "dropped_event_count": "0",
        "event_count": "2",
        "event_sequence_end": "2",
        "event_sequence_start": "1",
        "evidence_truncated": false,
        "fixture_case": "bpf_program_types",
        "heartbeat_count": "2",
        "observation_map_type": "BPF_MAP_TYPE_ARRAY",
        "package_gid": "65534",
        "package_uid": "65534",
        "raw_tracepoint_actor_pid": "411",
        "raw_tracepoint_attach_command": "BPF_RAW_TRACEPOINT_OPEN",
        "raw_tracepoint_cgroup_id": "21",
        "raw_tracepoint_name": "sys_enter",
        "raw_tracepoint_observation_count": "1",
        "raw_tracepoint_program_id": "43",
        "raw_tracepoint_program_type": "BPF_PROG_TYPE_RAW_TRACEPOINT",
        "raw_tracepoint_timestamp_ns": "1000",
        "resource_teardown_complete": true,
        "schema_version": linuxVzBpfProgramTypeEvidencePayloadSchemaV1,
        "sensor_healthy": true,
        "socket_filter_attach_option": "SO_ATTACH_BPF",
        "socket_filter_input_bytes": "8",
        "socket_filter_output_bytes": "4",
        "socket_filter_program_id": "44",
        "socket_filter_program_type": "BPF_PROG_TYPE_SOCKET_FILTER"
    ]
}
