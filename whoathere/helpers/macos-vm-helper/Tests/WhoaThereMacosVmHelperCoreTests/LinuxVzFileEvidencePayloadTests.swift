import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzFileEvidencePayloadDerivesStrictClaims() throws {
    let payload = try fileEvidencePayload()
    let evidence = try decodeLinuxVzFileEvidencePayload(
        Data("WHOATHERE_GUEST_FILE_EVIDENCE ".utf8) + payload + Data("\r\n".utf8)
    )
    #expect(evidence.fixtureCase == "protected_open_read_write_rename_delete")
    #expect(evidence.packageUID == 65534)
    #expect(evidence.claims.eventCount == 8)
    #expect(evidence.claims.droppedEventCount == 0)
    #expect(evidence.claims.descendantTeardownComplete)
}

@Test func linuxVzFileEvidencePayloadRejectsRebindingAndGaps() throws {
    let payload = try fileEvidencePayload()
    var value = try #require(
        JSONSerialization.jsonObject(with: payload) as? [String: Any]
    )
    value["mmap_bpf_correlated"] = false
    #expect(throws: LinuxVzFileEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzFileEvidencePayload(
            Data("WHOATHERE_GUEST_FILE_EVIDENCE ".utf8) + canonicalJSONData(value)
        )
    }
    value = try #require(JSONSerialization.jsonObject(with: payload) as? [String: Any])
    var events = try #require(value["events"] as? [[String: Any]])
    events[6]["timestamp_ns"] = "6"
    value["events"] = events
    #expect(throws: LinuxVzFileEvidencePayloadError.invalidEvent) {
        try decodeLinuxVzFileEvidencePayload(
            Data("WHOATHERE_GUEST_FILE_EVIDENCE ".utf8) + canonicalJSONData(value)
        )
    }
}

private func fileEvidencePayload() throws -> Data {
    let kinds = [
        "file_open", "file_read", "file_write", "file_rename", "file_delete",
        "file_mmap", "persistence_write", "file_system_diff"
    ]
    let events = kinds.enumerated().map { index, kind in
        [
            "actor_pid": "411", "cgroup_id": "21", "kind": kind,
            "sequence": String(index + 1), "timestamp_ns": String(index + 1)
        ]
    }
    return try canonicalJSONData([
        "descendant_teardown_complete": true,
        "dropped_event_count": "0",
        "event_count": "8",
        "event_sequence_end": "8",
        "event_sequence_start": "1",
        "events": events,
        "evidence_truncated": false,
        "fanotify_permission_responses": "2",
        "file_system_diff_complete": true,
        "fixture_case": "protected_open_read_write_rename_delete",
        "heartbeat_count": "2",
        "mmap_bpf_correlated": true,
        "package_gid": "65534",
        "package_uid": "65534",
        "persistence_target": "fake_user_startup",
        "raw_paths_captured": false,
        "schema_version": linuxVzFileEvidencePayloadSchemaV1,
        "sensor_healthy": true
    ])
}
