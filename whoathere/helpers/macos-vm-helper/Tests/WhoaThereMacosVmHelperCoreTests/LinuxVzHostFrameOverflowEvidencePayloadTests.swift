import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private func hostFrameGuestJSON(
    transmitted: String = "512",
    triggers: String = "512",
    txDropped: String = "0"
) throws -> Data {
    try canonicalJSONData([
        "descendant_teardown_complete": true,
        "dropped_event_count": "0",
        "event_count": "1",
        "event_sequence_end": "1",
        "event_sequence_start": "1",
        "events": [[
            "actor_pid": "10",
            "kind": "host_frame_overflow_trigger",
            "sequence": "1",
            "timestamp_ns": "100"
        ]],
        "evidence_truncated": false,
        "fixture_case": "host_frame_overflow",
        "heartbeat_count": "2",
        "host_frame_payload_bytes": "16",
        "host_frame_source_port": "49152",
        "host_frame_transmitted_count": transmitted,
        "host_frame_trigger_count": triggers,
        "host_frame_tx_dropped_count": txDropped,
        "host_frame_tx_error_count": "0",
        "package_gid": "65534",
        "package_uid": "65534",
        "schema_version": linuxVzHostFrameOverflowGuestEvidencePayloadSchemaV1,
        "sensor_healthy": true,
        "traffic_kind": "sequenced_udp_sinkhole_frames"
    ])
}

@Test func linuxVzHostFrameOverflowGuestEvidenceBindsExactTransmittedSet() throws {
    let json = try hostFrameGuestJSON()
    let serial = Data("WHOATHERE_GUEST_HOST_FRAME_OVERFLOW_EVIDENCE ".utf8)
        + json + Data("\n".utf8)
    let evidence = try decodeLinuxVzHostFrameOverflowGuestEvidencePayloadV1(serial)
    #expect(evidence.sourcePort == 49152)
    #expect(evidence.triggerCount == 512)
    #expect(evidence.claims.droppedEventCount == 0)
    #expect(evidence.claims.observedTerminal == "incomplete_on_injected_gap")
}

@Test func linuxVzHostFrameOverflowGuestEvidenceRejectsTxRebinding() throws {
    for json in [
        try hostFrameGuestJSON(transmitted: "511"),
        try hostFrameGuestJSON(triggers: "511"),
        try hostFrameGuestJSON(txDropped: "1")
    ] {
        #expect(throws: LinuxVzHostFrameOverflowGuestEvidencePayloadError.invalidSchema) {
            try decodeLinuxVzHostFrameOverflowGuestEvidenceJSONV1(json)
        }
    }
}

@Test func linuxVzHostFrameOverflowHostEvidenceBindsExactGap() throws {
    let evidence = try makeLinuxVzHostFrameOverflowHostEvidencePayloadV1(
        triggerFrameCount: 512,
        ingressFrameCount: 512,
        observedFrameCount: 64,
        uniqueSequenceCount: 64,
        duplicateFrameCount: 0,
        unexpectedFrameCount: 0,
        sourcePort: 49152,
        hostFrameQueueCapacity: 64,
        packetSensorHealthy: true,
        packetSensorTerminal: "bounded_queue_overflow_accounted",
        storageDeviceCount: 0
    )
    #expect(evidence.observedFrameCount == 64)
    #expect(evidence.droppedFrameCount == 448)
    #expect(evidence.claims.droppedFrameCount == 448)
    #expect(evidence.claims.observedTerminal == "incomplete_on_injected_gap")
}

@Test func linuxVzHostFrameOverflowHostEvidenceRejectsUnprovenGap() throws {
    for parameters in [
        (observed: UInt64(512), unique: UInt64(512), duplicate: UInt64(0), unexpected: UInt64(0)),
        (observed: UInt64(64), unique: UInt64(63), duplicate: UInt64(0), unexpected: UInt64(0)),
        (observed: UInt64(64), unique: UInt64(64), duplicate: UInt64(1), unexpected: UInt64(0)),
        (observed: UInt64(64), unique: UInt64(64), duplicate: UInt64(0), unexpected: UInt64(1))
    ] {
        #expect(throws: LinuxVzHostFrameOverflowHostEvidencePayloadError.invalidSchema) {
            try makeLinuxVzHostFrameOverflowHostEvidencePayloadV1(
                triggerFrameCount: 512,
                ingressFrameCount: 512,
                observedFrameCount: parameters.observed,
                uniqueSequenceCount: parameters.unique,
                duplicateFrameCount: parameters.duplicate,
                unexpectedFrameCount: parameters.unexpected,
                sourcePort: 49152,
                hostFrameQueueCapacity: 64,
                packetSensorHealthy: true,
                packetSensorTerminal: "bounded_queue_overflow_accounted",
                storageDeviceCount: 0
            )
        }
    }
}
