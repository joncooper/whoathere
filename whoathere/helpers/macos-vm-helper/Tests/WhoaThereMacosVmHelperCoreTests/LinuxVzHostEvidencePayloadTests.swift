import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzHostEvidenceBindsExactHostSensorDeath() throws {
    let payload = try makeLinuxVzHostSensorDeathHostEvidencePayload(
        requestFrameBytes: 5_082,
        responseBytes: 4_096,
        rawFrameCount: 0,
        packetSensorHealthy: false,
        packetSensorTerminal: "injected_sensor_death",
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    #expect(payload.hostSensorDeathKind ==
        "host_packet_sensor_worker_terminated_after_full_request")
    #expect(payload.hostSensorDeathRequestFrameBytes == 5_082)
    #expect(payload.hostSensorDeathTransmittedRequestBytes == 5_082)
    #expect(payload.hostSensorDeathResponseBytes == 4_096)
    #expect(payload.hostSensorDeathWorkerStarted == true)
    #expect(payload.hostSensorDeathInjected == true)
    #expect(payload.hostSensorDeathWorkerTerminated == true)
    #expect(!payload.claims.packetSensorHealthy)
    #expect(payload.claims.observedTerminal == "infrastructure_error_with_teardown")
    #expect(payload == (try decodeLinuxVzHostEvidencePayload(
        payload.canonicalJSON,
        observedTerminal: "infrastructure_error_with_teardown",
        expectedHostSensorDeathRequestFrameBytes: 5_082,
        expectedHostSensorDeathResponseBytes: 4_096
    )))
}

@Test func linuxVzHostEvidenceRejectsHostSensorDeathRebinding() throws {
    let payload = try makeLinuxVzHostSensorDeathHostEvidencePayload(
        requestFrameBytes: 5_082,
        responseBytes: 4_096,
        rawFrameCount: 0,
        packetSensorHealthy: false,
        packetSensorTerminal: "injected_sensor_death",
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    for (field, changed): (String, Any) in [
        ("host_sensor_death_request_frame_bytes", "16"),
        ("host_sensor_death_response_bytes", "0"),
        ("host_sensor_death_worker_started", false),
        ("host_sensor_death_injected", false),
        ("host_sensor_death_worker_terminated", false),
        ("packet_sensor_healthy", true),
    ] {
        var value = try #require(
            JSONSerialization.jsonObject(with: payload.canonicalJSON) as? [String: Any]
        )
        value[field] = changed
        #expect(throws: LinuxVzHostEvidencePayloadError.invalidSchema) {
            try decodeLinuxVzHostEvidencePayload(
                canonicalJSONData(value),
                observedTerminal: "infrastructure_error_with_teardown",
                expectedHostSensorDeathRequestFrameBytes: 5_082,
                expectedHostSensorDeathResponseBytes: 4_096
            )
        }
    }
}

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

@Test func linuxVzHostEvidenceBindsExactVmStop() throws {
    let payload = try makeLinuxVzVmStopHostEvidencePayload(
        requestFrameBytes: 5_082,
        rawFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    #expect(payload.vmStopKind == "host_stop_after_guest_fixture_active")
    #expect(payload.vmStopRequestFrameBytes == 5_082)
    #expect(payload.vmStopTransmittedRequestBytes == 5_082)
    #expect(payload.vmStopResponseBytes == 0)
    #expect(payload.vmStopFixtureActiveMarkerObserved == true)
    #expect(payload.claims.observedTerminal == "infrastructure_error_with_teardown")
    #expect(payload == (try decodeLinuxVzHostEvidencePayload(
        payload.canonicalJSON,
        observedTerminal: "infrastructure_error_with_teardown",
        expectedVmStopRequestFrameBytes: 5_082
    )))
}

@Test func linuxVzHostEvidenceRejectsVmStopRebinding() throws {
    let payload = try makeLinuxVzVmStopHostEvidencePayload(
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
            expectedVmStopRequestFrameBytes: 5_083
        )
    }
    for (field, changed): (String, Any) in [
        ("vm_stop_kind", "socket_closed"),
        ("vm_stop_request_frame_bytes", "16"),
        ("vm_stop_transmitted_request_bytes", "5081"),
        ("vm_stop_response_bytes", "1"),
        ("vm_stop_fixture_active_marker_observed", false),
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
                expectedVmStopRequestFrameBytes: 5_082
            )
        }
    }
}

@Test func linuxVzHostEvidenceBindsExactGuestSensorDeath() throws {
    let payload = try makeLinuxVzGuestSensorDeathHostEvidencePayload(
        requestFrameBytes: 5_082,
        rawFrameCount: 0,
        packetSensorHealthy: true,
        packetSensorTerminal: "drained_would_block",
        vmStarted: true,
        vmStopped: true,
        cloneDestroyed: true,
        storageDeviceCount: 0
    )
    #expect(payload.guestSensorDeathKind ==
        "guest_signer_sigkill_after_protected_sensor_ready")
    #expect(payload.guestSensorDeathRequestFrameBytes == 5_082)
    #expect(payload.guestSensorDeathTransmittedRequestBytes == 5_082)
    #expect(payload.guestSensorDeathResponseBytes == 0)
    #expect(payload.guestSensorDeathFixtureActiveMarkerObserved == true)
    #expect(payload.guestSensorDeathSignal == 9)
    #expect(payload.claims.observedTerminal == "infrastructure_error_with_teardown")
    #expect(payload == (try decodeLinuxVzHostEvidencePayload(
        payload.canonicalJSON,
        observedTerminal: "infrastructure_error_with_teardown",
        expectedGuestSensorDeathRequestFrameBytes: 5_082
    )))
}

@Test func linuxVzHostEvidenceRejectsGuestSensorDeathRebinding() throws {
    let payload = try makeLinuxVzGuestSensorDeathHostEvidencePayload(
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
            expectedGuestSensorDeathRequestFrameBytes: 5_083
        )
    }
    for (field, changed): (String, Any) in [
        ("guest_sensor_death_kind", "sensor_exit"),
        ("guest_sensor_death_request_frame_bytes", "16"),
        ("guest_sensor_death_transmitted_request_bytes", "5081"),
        ("guest_sensor_death_response_bytes", "1"),
        ("guest_sensor_death_signal", "15"),
        ("guest_sensor_death_fixture_active_marker_observed", false),
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
                expectedGuestSensorDeathRequestFrameBytes: 5_082
            )
        }
    }
}
