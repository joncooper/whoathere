import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let validProcessPayload =
    #"{"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"42","timestamp_ns":"300"}],"evidence_truncated":false,"heartbeat_count":"2","package_gid":"65534","package_uid":"65534","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true}"#

private let validDoubleForkPayload =
    #"{"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"43","cgroup_id":"9001","kind":"fork","sequence":"2","subject_pid":"44","timestamp_ns":"200"},{"actor_pid":"44","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"44","timestamp_ns":"300"}],"evidence_truncated":false,"exec_count":"1","exit_count":"3","fixture_case":"double_fork_daemonization","fork_count":"3","heartbeat_count":"2","package_gid":"65534","package_uid":"65534","reaped_process_count":"3","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true}"#

private let validReparentingPayload =
    #"{"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"4","event_sequence_end":"4","event_sequence_start":"1","events":[{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"fork","sequence":"2","subject_pid":"43","timestamp_ns":"200"},{"actor_pid":"41","cgroup_id":"9001","kind":"reparent","sequence":"3","subject_pid":"43","timestamp_ns":"300"},{"actor_pid":"43","cgroup_id":"9001","kind":"exit","sequence":"4","subject_pid":"43","timestamp_ns":"400"}],"evidence_truncated":false,"exec_count":"1","exit_count":"2","fixture_case":"reparenting","fork_count":"2","heartbeat_count":"2","package_gid":"65534","package_uid":"65534","reaped_process_count":"2","reparent_target":"protected_subreaper","reparented_process_count":"1","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true}"#

private let validSetsidPayload =
    #"{"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"4","event_sequence_end":"4","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"setsid","sequence":"3","subject_pid":"42","timestamp_ns":"300"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"4","subject_pid":"42","timestamp_ns":"400"}],"evidence_truncated":false,"exec_count":"1","exit_count":"1","fixture_case":"setsid_escape","fork_count":"1","heartbeat_count":"2","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true,"session_escape_count":"1","session_target":"new_session_leader"}"#

private let validCredentialPayload =
    #"{"credential_change_count":"3","credential_target":"uid_65534_gid_65534_no_supplementary_groups","descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"6","event_sequence_end":"6","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"setgroups","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"setgid","sequence":"3","subject_pid":"42","timestamp_ns":"300"},{"actor_pid":"42","cgroup_id":"9001","kind":"setuid","sequence":"4","subject_pid":"42","timestamp_ns":"400"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"5","subject_pid":"42","timestamp_ns":"500"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"6","subject_pid":"42","timestamp_ns":"600"}],"evidence_truncated":false,"exec_count":"1","exit_count":"1","fixture_case":"credential_change","fork_count":"1","heartbeat_count":"2","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true}"#

private let validDynamicLibraryPayload =
    #"{"descendant_teardown_complete":true,"dropped_event_count":"0","dynamic_library_load_count":"1","dynamic_library_target":"measured_inert_fixture_library","event_count":"4","event_sequence_end":"4","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"dynamic_library_load","sequence":"3","subject_pid":"42","timestamp_ns":"300"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"4","subject_pid":"42","timestamp_ns":"400"}],"evidence_truncated":false,"exec_count":"2","exit_count":"1","fixture_case":"dynamic_library_load","fork_count":"1","heartbeat_count":"2","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true}"#

@Test func processEvidencePayloadBindsOrderedCgroupLineageAndReceiptClaims() throws {
    let serial = Data(
        (linuxVzProcessEvidenceSerialPrefixV1 + validProcessPayload + "\r\n").utf8
    )
    let payload = try decodeLinuxVzProcessEvidencePayloadV1(serial)
    #expect(payload.canonicalJSON == Data(validProcessPayload.utf8))
    #expect(payload.eventSequenceStart == 1)
    #expect(payload.eventSequenceEnd == 3)
    #expect(payload.eventCount == 3)
    #expect(payload.heartbeatCount == 2)
    #expect(payload.droppedEventCount == 0)
    #expect(payload.sensorHealthy)
    #expect(!payload.evidenceTruncated)
    #expect(payload.descendantTeardownComplete)
    #expect(payload.packageUID == 65534)
    #expect(payload.packageGID == 65534)
    #expect(payload.fixtureCase == "fork_exec_exit")
}

@Test func processEvidencePayloadBindsDoubleForkCountsAndDaemonTeardown() throws {
    let serial = Data(
        (linuxVzProcessEvidenceSerialPrefixV1 + validDoubleForkPayload + "\n").utf8
    )
    let payload = try decodeLinuxVzProcessEvidencePayloadV1(serial)
    #expect(payload.canonicalJSON == Data(validDoubleForkPayload.utf8))
    #expect(payload.fixtureCase == "double_fork_daemonization")
    #expect(payload.eventCount == 3)
    #expect(payload.descendantTeardownComplete)

    var object = try #require(
        JSONSerialization.jsonObject(with: Data(validDoubleForkPayload.utf8)) as? [String: Any]
    )
    object["fork_count"] = "2"
    let changed = try canonicalJSONData(object)
    #expect(throws: LinuxVzProcessEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzProcessEvidencePayloadV1(
            Data(linuxVzProcessEvidenceSerialPrefixV1.utf8) + changed + Data("\n".utf8)
        )
    }
}

@Test func processEvidencePayloadBindsReparentingToProtectedSubreaper() throws {
    let serial = Data(
        (linuxVzProcessEvidenceSerialPrefixV1 + validReparentingPayload + "\n").utf8
    )
    let payload = try decodeLinuxVzProcessEvidencePayloadV1(serial)
    #expect(payload.canonicalJSON == Data(validReparentingPayload.utf8))
    #expect(payload.fixtureCase == "reparenting")
    #expect(payload.eventCount == 4)
    #expect(payload.descendantTeardownComplete)

    var object = try #require(
        JSONSerialization.jsonObject(with: Data(validReparentingPayload.utf8))
            as? [String: Any]
    )
    object["reparent_target"] = "package_process"
    let changed = try canonicalJSONData(object)
    #expect(throws: LinuxVzProcessEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzProcessEvidencePayloadV1(
            Data(linuxVzProcessEvidenceSerialPrefixV1.utf8) + changed + Data("\n".utf8)
        )
    }
}

@Test func processEvidencePayloadBindsSetsidToNewSessionLeader() throws {
    let serial = Data((linuxVzProcessEvidenceSerialPrefixV1 + validSetsidPayload + "\n").utf8)
    let payload = try decodeLinuxVzProcessEvidencePayloadV1(serial)
    #expect(payload.canonicalJSON == Data(validSetsidPayload.utf8))
    #expect(payload.fixtureCase == "setsid_escape")
    #expect(payload.eventCount == 4)
    #expect(payload.descendantTeardownComplete)

    var object = try #require(
        JSONSerialization.jsonObject(with: Data(validSetsidPayload.utf8)) as? [String: Any]
    )
    object["session_target"] = "inherited_session"
    let changed = try canonicalJSONData(object)
    #expect(throws: LinuxVzProcessEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzProcessEvidencePayloadV1(
            Data(linuxVzProcessEvidenceSerialPrefixV1.utf8) + changed + Data("\n".utf8)
        )
    }
}

@Test func processEvidencePayloadBindsCredentialDropSequenceAndTarget() throws {
    let serial = Data((linuxVzProcessEvidenceSerialPrefixV1 + validCredentialPayload + "\n").utf8)
    let payload = try decodeLinuxVzProcessEvidencePayloadV1(serial)
    #expect(payload.canonicalJSON == Data(validCredentialPayload.utf8))
    #expect(payload.fixtureCase == "credential_change")
    #expect(payload.eventCount == 6)
    #expect(payload.descendantTeardownComplete)

    var object = try #require(
        JSONSerialization.jsonObject(with: Data(validCredentialPayload.utf8)) as? [String: Any]
    )
    object["credential_target"] = "uid_0_gid_0"
    let changed = try canonicalJSONData(object)
    #expect(throws: LinuxVzProcessEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzProcessEvidencePayloadV1(
            Data(linuxVzProcessEvidenceSerialPrefixV1.utf8) + changed + Data("\n".utf8)
        )
    }
}

@Test func processEvidencePayloadBindsMeasuredDynamicLibraryLoad() throws {
    let serial = Data(
        (linuxVzProcessEvidenceSerialPrefixV1 + validDynamicLibraryPayload + "\n").utf8
    )
    let payload = try decodeLinuxVzProcessEvidencePayloadV1(serial)
    #expect(payload.canonicalJSON == Data(validDynamicLibraryPayload.utf8))
    #expect(payload.fixtureCase == "dynamic_library_load")
    #expect(payload.eventCount == 4)

    var object = try #require(
        JSONSerialization.jsonObject(with: Data(validDynamicLibraryPayload.utf8))
            as? [String: Any]
    )
    object["dynamic_library_target"] = "unmeasured_library"
    let changed = try canonicalJSONData(object)
    #expect(throws: LinuxVzProcessEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzProcessEvidencePayloadV1(
            Data(linuxVzProcessEvidenceSerialPrefixV1.utf8) + changed + Data("\n".utf8)
        )
    }
}

@Test func processEvidencePayloadRejectsDuplicateReorderedDroppedAndNoncanonicalEvidence() throws {
    let line = linuxVzProcessEvidenceSerialPrefixV1 + validProcessPayload + "\n"
    #expect(throws: LinuxVzProcessEvidencePayloadError.duplicate) {
        try decodeLinuxVzProcessEvidencePayloadV1(Data((line + line).utf8))
    }

    for (field, value, error) in [
        ("dropped_event_count", "1", LinuxVzProcessEvidencePayloadError.invalidSchema),
        ("heartbeat_count", "0", LinuxVzProcessEvidencePayloadError.invalidSchema),
        ("event_sequence_end", "4", LinuxVzProcessEvidencePayloadError.invalidSchema),
    ] {
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(validProcessPayload.utf8)) as? [String: Any]
        )
        object[field] = value
        let data = try canonicalJSONData(object)
        #expect(throws: error) {
            try decodeLinuxVzProcessEvidencePayloadV1(
                Data(linuxVzProcessEvidenceSerialPrefixV1.utf8) + data + Data("\n".utf8)
            )
        }
    }

    let spaced = Data(
        (linuxVzProcessEvidenceSerialPrefixV1 + "{ \"schema_version\":\"x\" }\n").utf8
    )
    #expect(throws: LinuxVzProcessEvidencePayloadError.nonCanonical) {
        try decodeLinuxVzProcessEvidencePayloadV1(spaced)
    }
}
