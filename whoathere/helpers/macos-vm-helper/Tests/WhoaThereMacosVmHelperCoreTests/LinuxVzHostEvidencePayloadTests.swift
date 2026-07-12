import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzHostEvidencePayloadDerivesStrictInertClaims() throws {
    let payload = try makeLinuxVzInertHostEvidencePayload(
        rawFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        guestChannelTerminated: true,
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    #expect(payload == (try decodeLinuxVzHostEvidencePayload(payload.canonicalJSON)))
    #expect(payload.rawFrameCount == 0)
    #expect(payload.claims.vmStarted)
    #expect(payload.claims.vmStopped)
    #expect(payload.claims.cloneDestroyed)
    #expect(payload.claims.externalFramesForwarded == 0)
    #expect(payload.claims.observedTerminal == "observation_complete")
    let incomplete = try decodeLinuxVzHostEvidencePayload(
        payload.canonicalJSON,
        observedTerminal: "incomplete_on_injected_gap"
    )
    #expect(incomplete.claims.observedTerminal == "incomplete_on_injected_gap")
    let timeout = try decodeLinuxVzHostEvidencePayload(
        payload.canonicalJSON,
        observedTerminal: "timeout_with_teardown"
    )
    #expect(timeout.claims.observedTerminal == "timeout_with_teardown")
    #expect(throws: LinuxVzHostEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzHostEvidencePayload(
            payload.canonicalJSON,
            observedTerminal: "observation_complete_despite_gap"
        )
    }
}

@Test func linuxVzHostEvidencePayloadRejectsChangedObservation() throws {
    let payload = try makeLinuxVzInertHostEvidencePayload(
        rawFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        guestChannelTerminated: true,
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    var value = try #require(
        JSONSerialization.jsonObject(with: payload.canonicalJSON) as? [String: Any]
    )
    value["raw_frame_count"] = "1"
    let changed = try canonicalJSONData(value)
    #expect(throws: LinuxVzHostEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzHostEvidencePayload(changed)
    }
    var noncanonical = payload.canonicalJSON
    noncanonical.append(0x0A)
    #expect(throws: LinuxVzHostEvidencePayloadError.nonCanonical) {
        try decodeLinuxVzHostEvidencePayload(noncanonical)
    }
}

@Test func linuxVzHostEvidenceBindsExactChannelInterruption() throws {
    let payload = try makeLinuxVzChannelInterruptionHostEvidencePayload(
        requestFrameBytes: 5_082,
        rawFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    #expect(payload.channelInterruptionKind == "host_write_half_close_after_request_header")
    #expect(payload.channelRequestFrameBytes == 5_082)
    #expect(payload.channelResponseBytes == 0)
    #expect(payload.channelTransmittedPrefixBytes == 16)
    #expect(payload.claims.observedTerminal == "infrastructure_error_with_teardown")
    #expect(payload == (try decodeLinuxVzHostEvidencePayload(
        payload.canonicalJSON,
        observedTerminal: "infrastructure_error_with_teardown",
        expectedChannelRequestFrameBytes: 5_082
    )))
}

@Test func linuxVzHostEvidenceRejectsChannelInterruptionRebinding() throws {
    let payload = try makeLinuxVzChannelInterruptionHostEvidencePayload(
        requestFrameBytes: 5_082,
        rawFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    #expect(throws: LinuxVzHostEvidencePayloadError.invalidSchema) {
        try decodeLinuxVzHostEvidencePayload(
            payload.canonicalJSON,
            observedTerminal: "infrastructure_error_with_teardown",
            expectedChannelRequestFrameBytes: 5_083
        )
    }
    for (field, changed) in [
        ("channel_interruption_kind", "socket_closed"),
        ("channel_request_frame_bytes", "16"),
        ("channel_response_bytes", "1"),
        ("channel_transmitted_prefix_bytes", "15"),
    ] {
        var value = try #require(
            JSONSerialization.jsonObject(with: payload.canonicalJSON) as? [String: Any]
        )
        value[field] = changed
        let data = try canonicalJSONData(value)
        #expect(throws: LinuxVzHostEvidencePayloadError.invalidSchema) {
            try decodeLinuxVzHostEvidencePayload(
                data,
                observedTerminal: "infrastructure_error_with_teardown",
                expectedChannelRequestFrameBytes: 5_082
            )
        }
    }
}
