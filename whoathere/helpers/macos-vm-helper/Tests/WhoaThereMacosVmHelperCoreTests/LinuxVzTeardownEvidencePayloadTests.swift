import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let validNormalExitPayload =
    #"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"5000000000","deadline_reached":false,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"42","timestamp_ns":"300"}],"evidence_truncated":false,"fixture_case":"normal_exit","fixture_exit_status":"0","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"natural_exit","termination_signal_count":"0"}"#

private let validTimeoutPayload =
    #"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"1000000000","deadline_reached":true,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"4","event_sequence_end":"4","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"41","cgroup_id":"9001","kind":"signal_term","sequence":"3","subject_pid":"42","timestamp_ns":"300"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"4","subject_pid":"42","timestamp_ns":"400"}],"evidence_truncated":false,"fixture_case":"timeout","fixture_termination_signal":"15","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"deadline","termination_signal_count":"1"}"#

private let validTermResistancePayload =
    #"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"1000000000","deadline_reached":true,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"5","event_sequence_end":"5","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"41","cgroup_id":"9001","kind":"signal_term","sequence":"3","subject_pid":"42","timestamp_ns":"300"},{"actor_pid":"41","cgroup_id":"9001","kind":"signal_kill","sequence":"4","subject_pid":"42","timestamp_ns":"600"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"5","subject_pid":"42","timestamp_ns":"700"}],"evidence_truncated":false,"fixture_case":"term_resistance","fixture_termination_signal":"9","heartbeat_count":"2","kill_signal_count":"1","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"deadline","term_grace_limit_ns":"250000000","term_grace_reached":true,"term_resistance_proven":true,"termination_signal_count":"1"}"#

private let validEscapedSessionPayload =
    #"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"1000000000","deadline_reached":true,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"5","event_sequence_end":"5","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"setsid","sequence":"3","subject_pid":"42","timestamp_ns":"300"},{"actor_pid":"41","cgroup_id":"9001","kind":"signal_term","sequence":"4","subject_pid":"42","timestamp_ns":"1400"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"5","subject_pid":"42","timestamp_ns":"1500"}],"evidence_truncated":false,"fixture_case":"escaped_session","fixture_termination_signal":"15","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"session_escape_count":"1","session_target":"new_session_leader_at_deadline","teardown_trigger":"deadline","termination_signal_count":"1"}"#

private let validReparentedChildPayload =
    #"{"cgroup_empty_after_reap":true,"cgroup_removed":true,"deadline_limit_ns":"1000000000","deadline_reached":true,"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"5","event_sequence_end":"5","event_sequence_start":"1","events":[{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"fork","sequence":"2","subject_pid":"43","timestamp_ns":"200"},{"actor_pid":"41","cgroup_id":"9001","kind":"reparent","sequence":"3","subject_pid":"43","timestamp_ns":"300"},{"actor_pid":"41","cgroup_id":"9001","kind":"signal_term","sequence":"4","subject_pid":"43","timestamp_ns":"1400"},{"actor_pid":"43","cgroup_id":"9001","kind":"exit","sequence":"5","subject_pid":"43","timestamp_ns":"1500"}],"evidence_truncated":false,"fixture_case":"reparented_child","fixture_termination_signal":"15","fork_count":"2","heartbeat_count":"2","kill_signal_count":"0","package_gid":"65534","package_uid":"65534","reaped_process_count":"2","reparent_target":"protected_subreaper_at_deadline","reparented_process_count":"1","schema_version":"whoathere.linux_vz_teardown_evidence_payload.v1","sensor_healthy":true,"sensor_teardown_complete":true,"teardown_trigger":"deadline","termination_signal_count":"1"}"#

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

@Test func teardownEvidenceBindsTermResistanceGraceKillAndCompleteCleanup() throws {
    let payload = try decodeLinuxVzTeardownEvidencePayloadV1(
        Data((normalExitPrefix + validTermResistancePayload + "\n").utf8)
    )
    #expect(payload.canonicalJSON == Data(validTermResistancePayload.utf8))
    #expect(payload.fixtureCase == "term_resistance")
    #expect(payload.claims.eventCount == 5)
    #expect(payload.claims.observedTerminal == "timeout_with_teardown")
    #expect(payload.claims.droppedEventCount == 0)
    #expect(payload.claims.descendantTeardownComplete)
}

@Test func teardownEvidenceRejectsForgedTermResistanceGraceKillAndActor() throws {
    for (field, changed) in [
        ("term_grace_reached", false as Any),
        ("fixture_termination_signal", "15" as Any),
        ("kill_signal_count", "0" as Any),
    ] {
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(validTermResistancePayload.utf8))
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

    var rebound = try #require(
        JSONSerialization.jsonObject(with: Data(validTermResistancePayload.utf8))
            as? [String: Any]
    )
    var events = try #require(rebound["events"] as? [[String: Any]])
    events[3]["actor_pid"] = "42"
    rebound["events"] = events
    let data = try canonicalJSONData(rebound)
    #expect(throws: LinuxVzTeardownEvidencePayloadError.invalidEvent) {
        try decodeLinuxVzTeardownEvidencePayloadV1(
            Data(normalExitPrefix.utf8) + data + Data("\n".utf8)
        )
    }
}

@Test func teardownEvidenceBindsEscapedSessionAtDeadlineAndCompleteCleanup() throws {
    let payload = try decodeLinuxVzTeardownEvidencePayloadV1(
        Data((normalExitPrefix + validEscapedSessionPayload + "\n").utf8)
    )
    #expect(payload.canonicalJSON == Data(validEscapedSessionPayload.utf8))
    #expect(payload.fixtureCase == "escaped_session")
    #expect(payload.claims.eventCount == 5)
    #expect(payload.claims.observedTerminal == "timeout_with_teardown")
    #expect(payload.claims.droppedEventCount == 0)
    #expect(payload.claims.descendantTeardownComplete)
}

@Test func teardownEvidenceRejectsForgedEscapedSessionSignalAndLineage() throws {
    for (field, changed) in [
        ("session_escape_count", "0" as Any),
        ("session_target", "new_session_leader" as Any),
        ("fixture_termination_signal", "9" as Any),
    ] {
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(validEscapedSessionPayload.utf8))
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

    var rebound = try #require(
        JSONSerialization.jsonObject(with: Data(validEscapedSessionPayload.utf8))
            as? [String: Any]
    )
    var events = try #require(rebound["events"] as? [[String: Any]])
    events[3]["actor_pid"] = "42"
    rebound["events"] = events
    let data = try canonicalJSONData(rebound)
    #expect(throws: LinuxVzTeardownEvidencePayloadError.invalidEvent) {
        try decodeLinuxVzTeardownEvidencePayloadV1(
            Data(normalExitPrefix.utf8) + data + Data("\n".utf8)
        )
    }
}

@Test func teardownEvidenceBindsReparentedChildAtDeadlineAndCompleteCleanup() throws {
    let payload = try decodeLinuxVzTeardownEvidencePayloadV1(
        Data((normalExitPrefix + validReparentedChildPayload + "\n").utf8)
    )
    #expect(payload.canonicalJSON == Data(validReparentedChildPayload.utf8))
    #expect(payload.fixtureCase == "reparented_child")
    #expect(payload.claims.eventCount == 5)
    #expect(payload.claims.observedTerminal == "timeout_with_teardown")
    #expect(payload.claims.droppedEventCount == 0)
    #expect(payload.claims.descendantTeardownComplete)
}

@Test func teardownEvidenceRejectsForgedReparentedChildSignalAndLineage() throws {
    for (field, changed) in [
        ("reaped_process_count", "1" as Any),
        ("reparent_target", "protected_subreaper" as Any),
        ("fixture_termination_signal", "9" as Any),
    ] {
        var object = try #require(
            JSONSerialization.jsonObject(with: Data(validReparentedChildPayload.utf8))
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

    var rebound = try #require(
        JSONSerialization.jsonObject(with: Data(validReparentedChildPayload.utf8))
            as? [String: Any]
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
