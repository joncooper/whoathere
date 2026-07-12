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
