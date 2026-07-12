import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private func fanotifyOverflowJSON(
    dropped: String = "192",
    observed: String = "64",
    markerCount: String = "1",
    restored: Bool = true,
    uniqueInodes: String = "256"
) throws -> Data {
    try canonicalJSONData([
        "descendant_teardown_complete": true,
        "dropped_event_count": dropped,
        "event_count": "1",
        "event_sequence_end": "1",
        "event_sequence_start": "1",
        "events": [[
            "actor_pid": "10",
            "kind": "fanotify_queue_overflow",
            "sequence": "1",
            "timestamp_ns": "100"
        ]],
        "evidence_truncated": false,
        "fanotify_observed_event_count": observed,
        "fanotify_overflow_marker_count": markerCount,
        "fanotify_queue_limit_injected": "64",
        "fanotify_queue_limit_original": "16384",
        "fanotify_queue_limit_restored": restored,
        "fanotify_trigger_count": "256",
        "fanotify_unique_inode_count": uniqueInodes,
        "fixture_case": "fanotify_queue_overflow",
        "heartbeat_count": "2",
        "injection_kind": "fanotify_queue_limit_exhaustion",
        "package_gid": "65534",
        "package_uid": "65534",
        "schema_version": linuxVzFanotifyOverflowEvidencePayloadSchemaV1,
        "sensor_healthy": true
    ])
}

@Test func linuxVzFanotifyOverflowEvidenceDerivesExactIncompleteClaims() throws {
    let json = try fanotifyOverflowJSON()
    let serial = Data("WHOATHERE_GUEST_FANOTIFY_OVERFLOW_EVIDENCE ".utf8)
        + json + Data("\n".utf8)
    let evidence = try decodeLinuxVzFanotifyOverflowEvidencePayloadV1(serial)
    #expect(evidence.canonicalJSON == json)
    #expect(evidence.fixtureCase == "fanotify_queue_overflow")
    #expect(evidence.packageUID == 65534)
    #expect(evidence.packageGID == 65534)
    #expect(evidence.droppedEventCount == 192)
    #expect(evidence.claims.observedTerminal == "incomplete_on_injected_gap")
}

@Test func linuxVzFanotifyOverflowEvidenceRejectsUnprovenDropAccounting() throws {
    for json in [
        try fanotifyOverflowJSON(dropped: "191"),
        try fanotifyOverflowJSON(observed: "63"),
        try fanotifyOverflowJSON(markerCount: "0"),
        try fanotifyOverflowJSON(restored: false),
        try fanotifyOverflowJSON(uniqueInodes: "255")
    ] {
        #expect(throws: LinuxVzFanotifyOverflowEvidencePayloadError.invalidSchema) {
            try decodeLinuxVzFanotifyOverflowEvidenceJSONV1(json)
        }
    }
}

@Test func linuxVzFanotifyOverflowEvidenceRequiresOneCanonicalSerialRecord() throws {
    let json = try fanotifyOverflowJSON()
    let line = Data("WHOATHERE_GUEST_FANOTIFY_OVERFLOW_EVIDENCE ".utf8) + json
    #expect(throws: LinuxVzFanotifyOverflowEvidencePayloadError.missing) {
        try decodeLinuxVzFanotifyOverflowEvidencePayloadV1(Data("missing\n".utf8))
    }
    #expect(throws: LinuxVzFanotifyOverflowEvidencePayloadError.duplicate) {
        try decodeLinuxVzFanotifyOverflowEvidencePayloadV1(line + Data("\n".utf8) + line)
    }
}
