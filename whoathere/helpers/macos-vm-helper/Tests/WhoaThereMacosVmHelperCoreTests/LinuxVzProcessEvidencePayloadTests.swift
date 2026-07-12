import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

private let validProcessPayload =
    #"{"descendant_teardown_complete":true,"dropped_event_count":"0","event_count":"3","event_sequence_end":"3","event_sequence_start":"1","events":[{"actor_pid":"41","cgroup_id":"9001","kind":"fork","sequence":"1","subject_pid":"42","timestamp_ns":"100"},{"actor_pid":"42","cgroup_id":"9001","kind":"exec","sequence":"2","subject_pid":"42","timestamp_ns":"200"},{"actor_pid":"42","cgroup_id":"9001","kind":"exit","sequence":"3","subject_pid":"42","timestamp_ns":"300"}],"evidence_truncated":false,"heartbeat_count":"2","package_gid":"65534","package_uid":"65534","schema_version":"whoathere.linux_vz_process_evidence_payload.v1","sensor_healthy":true}"#

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
