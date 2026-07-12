import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let validNormalExitPayload =
    #"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"5000000000","deadline_reached":false,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"42","timestamp_ns":"300"}],"evidence_truncated":false,"fixture_case":"normal_exit","fixture_exit_status":"0","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"natural_exit","termination_signal_count":"0"}"#

private let validTimeoutPayload =
    #"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"1000000000","deadline_reached":true,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"4","event_sequence_end":"4","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"41","cgroup_id":"9001","kind":"signal_term","sequence":"3","subject_pid":"42","timestamp_ns":"300"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"4","subject_pid":"42","timestamp_ns":"400"}],"evidence_truncated":false,"fixture_case":"timeout","fixture_termination_signal":"15","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"deadline","termination_signal_count":"1"}"#

private let normalExitPrefix = "WHOATHERE_GUEST_TEARDOWN_EVIDENCE "

@Test func teardownEvidenceBindsNaturalExitLineageAndCompleteCleanup() throws {
    let payload = try decodeLinuxVzTeardownEvidencePayloadV1(
        Data((normalExitPrefix + validNormalExitPayload + "\r\n").utf8)
    )
    #expect(payload.canonicalJSON == Data(validNormalExitPayload.utf8))
    #expect(payload.fixtureCase == "normal_exit")
    #expect(payload.packageUID == 65534)
    #expect(payload.packageGID == 65534)
    #expect(payload.claims.eventCount == 3)
    #expect(payload.claims.observedTerminal == "observation_complete")
    #expect(payload.claims.sensorHealthy)
    #expect(payload.claims.descendantTeardownComplete)
}

@Test func teardownEvidenceRejectsDuplicateAndForgedCleanupSignalOrLineage() throws {
    let line = normalExitPrefix + validNormalExitPayload + "\n"
    #expect(throws: LinuxVzTeardownEvidencePayloadError.duplicate) {
        try decodeLinuxVzTeardownEvidencePayloadV1(Data((line + line).utf8))
    }
    for (field, changed) in [
        ("cgroup_removed", false as Any),
        ("deadline_reached", true as Any),
        ("termination_signal_count", "1" as Any),
        ("fixture_exit_status", "1" as Any),
    ] {
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(validNormalExitPayload.utf8))
                as? [String: Any]
        )
        object[field] = changed
        let data = try canonicalJSONData(object)
        #expect(throws: LinuxVzTeardownEvidencePayloadError.invalidSchema) {
            try decodeLinuxVzTeardownEvidencePayloadV1(
                Data(normalExitPrefix.utf8) + data + Data("\n".utf8)
            )
        }
    }

    var reordered = try #require(
        JSONSerialization.jsonObject(with: Data(validNormalExitPayload.utf8)) as? [String: Any]
    )
    var events = try #require(reordered["events"] as? [[String: Any]])
    events[1]["timestamp_ns"] = "99"
    reordered["events"] = events
    let data = try canonicalJSONData(reordered)
    #expect(throws: LinuxVzTeardownEvidencePayloadError.invalidEvent) {
        try decodeLinuxVzTeardownEvidencePayloadV1(
            Data(normalExitPrefix.utf8) + data + Data("\n".utf8)
        )
    }
}

@Test func teardownEvidenceBindsTimeoutTermLineageAndCompleteCleanup() throws {
    let payload = try decodeLinuxVzTeardownEvidencePayloadV1(
        Data((normalExitPrefix + validTimeoutPayload + "\n").utf8)
    )
    #expect(payload.canonicalJSON == Data(validTimeoutPayload.utf8))
    #expect(payload.fixtureCase == "timeout")
    #expect(payload.claims.eventCount == 4)
    #expect(payload.claims.observedTerminal == "timeout_with_teardown")
    #expect(payload.claims.droppedEventCount == 0)
    #expect(payload.claims.descendantTeardownComplete)
}

@Test func teardownEvidenceRejectsForgedTimeoutDeadlineSignalAndActor() throws {
    for (field, changed) in [
        ("deadline_reached", false as Any),
        ("fixture_termination_signal", "9" as Any),
        ("kill_signal_count", "1" as Any),
    ] {
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(validTimeoutPayload.utf8)) as? [String: Any]
        )
        object[field] = changed
        let data = try canonicalJSONData(object)
        #expect(throws: LinuxVzTeardownEvidencePayloadError.invalidSchema) {
            try decodeLinuxVzTeardownEvidencePayloadV1(
                Data(normalExitPrefix.utf8) + data + Data("\n".utf8)
            )
        }
    }

    var rebound = try #require(
        JSONSerialization.jsonObject(with: Data(validTimeoutPayload.utf8)) as? [String: Any]
    )
    var events = try #require(rebound["events"] as? [[String: Any]])
    events[2]["actor_pid"] = "42"
    rebound["events"] = events
    let data = try canonicalJSONData(rebound)
    #expect(throws: LinuxVzTeardownEvidencePayloadError.invalidEvent) {
        try decodeLinuxVzTeardownEvidencePayloadV1(
            Data(normalExitPrefix.utf8) + data + Data("\n".utf8)
        )
    }
}
