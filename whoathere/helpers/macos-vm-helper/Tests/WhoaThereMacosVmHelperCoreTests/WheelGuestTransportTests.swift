import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func wheelGuestForwarderPreservesCanonicalHeaderAndExactRawArtifactThenClosesWriteSide() throws {
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "import_root", "module": "wheel_fixture"],
        scenarioIndex: 41
    )
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }

    let reader = try beginWheelSubmission(from: wheelGuestTransportFileHandle(fixture.frame))
    let forwarder = try WheelGuestSubmissionForwarder(
        descriptor: sockets[0], reader: reader
    )
    let observation = try forwarder.forward()
    let received = try readWheelGuestToEOF(sockets[1])
    #expect(received.prefix(8) == wheelGuestSubmissionMagicV1)
    #expect(received.count == fixture.frame.count)
    #expect(received[8...] == fixture.frame[8...])
    #expect(observation.runSpecSHA256 == fixture.runSpecSHA256)
    #expect(observation.artifactSHA256 == fixture.artifactSHA256)
    #expect(observation.artifactByteLength == UInt64(fixture.artifact.count))

    var hostShape = received
    hostShape.replaceSubrange(0..<8, with: wheelSubmissionMagicV1)
    let reparsed = try inspectWheelSubmission(
        from: wheelGuestTransportFileHandle(hostShape),
        expectedChallengeBindingSHA256: fixture.challengeBindingSHA256
    )
    #expect(reparsed.runSpecSHA256 == observation.runSpecSHA256)
    #expect(reparsed.artifactSHA256 == observation.artifactSHA256)
}

@Test func wheelGuestForwarderIsSingleUseAndFailsWithoutSignalWhenPeerIsClosed() throws {
    let fixture = try wheelSubmissionFixture(
        scenario: ["kind": "install_exact_wheel"], scenarioIndex: 42
    )

    var successSockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &successSockets) == 0)
    guard successSockets[0] >= 0, successSockets[1] >= 0 else { return }
    defer {
        _ = close(successSockets[0])
        _ = close(successSockets[1])
    }
    let reader = try beginWheelSubmission(from: wheelGuestTransportFileHandle(fixture.frame))
    let forwarder = try WheelGuestSubmissionForwarder(
        descriptor: successSockets[0], reader: reader
    )
    _ = try forwarder.forward()
    _ = try readWheelGuestToEOF(successSockets[1])
    #expect(throws: WheelGuestTransportError.writeFailed) {
        try forwarder.forward()
    }

    var closedSockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &closedSockets) == 0)
    guard closedSockets[0] >= 0, closedSockets[1] >= 0 else { return }
    _ = close(closedSockets[1])
    defer { _ = close(closedSockets[0]) }
    let closedReader = try beginWheelSubmission(
        from: wheelGuestTransportFileHandle(fixture.frame)
    )
    let closedForwarder = try WheelGuestSubmissionForwarder(
        descriptor: closedSockets[0], reader: closedReader
    )
    #expect(throws: WheelGuestTransportError.writeFailed) {
        try closedForwarder.forward()
    }
}

private func wheelGuestTransportFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}

private func readWheelGuestToEOF(_ descriptor: Int32) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let count = recv(descriptor, &buffer, buffer.count, 0)
        if count == 0 { return result }
        guard count > 0 else {
            if errno == EINTR { continue }
            throw WheelGuestTransportError.writeFailed
        }
        result.append(contentsOf: buffer[0..<count])
    }
}
