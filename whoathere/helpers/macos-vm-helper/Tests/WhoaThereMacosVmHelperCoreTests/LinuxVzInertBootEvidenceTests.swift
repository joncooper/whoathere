import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzInertBootEvidenceRequiresEveryExactCapabilityLine() {
    let completeLines = linuxVzInertRequiredCapabilityMarkersV1 + [linuxVzInertSuccessMarkerV1]
    let complete = Data((completeLines.joined(separator: "\r\n") + "\r\n").utf8)
    #expect(linuxVzInertSerialContainsExactMarker(complete, marker: linuxVzInertSuccessMarkerV1))
    #expect(linuxVzInertMissingCapabilityMarkers(complete).isEmpty)

    let omitted = Data(
        (completeLines.dropFirst().joined(separator: "\n") + "\n").utf8
    )
    #expect(linuxVzInertMissingCapabilityMarkers(omitted) == [
        linuxVzInertRequiredCapabilityMarkersV1[0]
    ])
}

@Test func linuxVzInertBootEvidenceRejectsMarkerSubstrings() {
    let forged = Data(
        ("prefix-" + linuxVzInertSuccessMarkerV1 + "-suffix\n").utf8
    )
    #expect(!linuxVzInertSerialContainsExactMarker(forged, marker: linuxVzInertSuccessMarkerV1))
}

@Test func linuxVzInertBootEvidenceV2RequiresProtectedProcessSensorLines() {
    let completeLines = linuxVzInertRequiredEvidenceMarkersV2 + [linuxVzInertSuccessMarkerV1]
    let complete = Data((completeLines.joined(separator: "\n") + "\n").utf8)
    #expect(linuxVzInertMissingRequiredEvidenceMarkersV2(complete).isEmpty)

    let missingSensor = Data(
        ((linuxVzInertRequiredCapabilityMarkersV1 + [linuxVzInertSuccessMarkerV1])
            .joined(separator: "\n") + "\n").utf8
    )
    #expect(linuxVzInertMissingRequiredEvidenceMarkersV2(missingSensor)
        == linuxVzInertProcessSensorMarkersV2)
}
