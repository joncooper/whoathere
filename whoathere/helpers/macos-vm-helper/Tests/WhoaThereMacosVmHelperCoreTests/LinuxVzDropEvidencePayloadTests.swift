import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private func dropEvidenceJSON(
    dropped: String = "1878",
    successes: String = "170",
    attempts: String = "2048",
    injectionKind: String = "ringbuf_reserve_exhaustion"
) throws -> Data {
    try canonicalJSONData([
        "descendant_teardown_complete": true,
        "dropped_event_count": dropped,
        "event_count": "1",
        "event_sequence_end": "1",
        "event_sequence_start": "1",
        "events": [[
            "actor_pid": "10",
            "kind": "bpf_reservation_failure",
            "sequence": "1",
            "timestamp_ns": "100"
        ]],
        "evidence_truncated": false,
        "fixture_case": "bpf_reservation_failure",
        "heartbeat_count": "2",
        "injection_kind": injectionKind,
        "package_gid": "65534",
        "package_uid": "65534",
        "reservation_attempt_count": attempts,
        "reservation_success_count": successes,
        "ring_buffer_capacity_bytes": "4096",
        "schema_version": linuxVzDropEvidencePayloadSchemaV1,
        "sensor_healthy": true
    ])
}

@Test func linuxVzDropEvidenceDerivesIncompleteClaimsFromProtectedCounts() throws {
    let json = try dropEvidenceJSON()
    let serial = Data("boot\nWHOATHERE_GUEST_DROP_EVIDENCE ".utf8) + json + Data("\nend\n".utf8)
    let payload = try decodeLinuxVzDropEvidencePayloadV1(serial)
    #expect(payload.canonicalJSON == json)
    #expect(payload.fixtureCase == "bpf_reservation_failure")
    #expect(payload.packageUID == 65534)
    #expect(payload.packageGID == 65534)
    #expect(payload.droppedEventCount == 1878)
    #expect(payload.claims.droppedEventCount == 1878)
    #expect(payload.claims.observedTerminal == "incomplete_on_injected_gap")
}

@Test func linuxVzDropEvidenceRejectsSyntheticAndUnaccountedCounts() throws {
    for json in [
        try dropEvidenceJSON(dropped: "0"),
        try dropEvidenceJSON(successes: "0"),
        try dropEvidenceJSON(attempts: "2049"),
        try dropEvidenceJSON(injectionKind: "synthetic_counter")
    ] {
        #expect(throws: LinuxVzDropEvidencePayloadError.invalidSchema) {
            try decodeLinuxVzDropEvidenceJSONV1(json)
        }
    }
}

@Test func linuxVzDropEvidenceRequiresExactlyOneCanonicalSerialRecord() throws {
    let json = try dropEvidenceJSON()
    let line = Data("WHOATHERE_GUEST_DROP_EVIDENCE ".utf8) + json
    #expect(throws: LinuxVzDropEvidencePayloadError.missing) {
        try decodeLinuxVzDropEvidencePayloadV1(Data("no drop evidence\n".utf8))
    }
    #expect(throws: LinuxVzDropEvidencePayloadError.duplicate) {
        try decodeLinuxVzDropEvidencePayloadV1(line + Data("\n".utf8) + line)
    }
    var noncanonical = json
    noncanonical.append(0x0a)
    #expect(throws: LinuxVzDropEvidencePayloadError.nonCanonical) {
        try decodeLinuxVzDropEvidenceJSONV1(noncanonical)
    }
}
