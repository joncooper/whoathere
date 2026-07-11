import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func guestForwarderPreservesCanonicalHeaderAndExactRawArtifactThenClosesWriteSide() throws {
    let fixture = try artifactSubmissionFixture().frame
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }

    let reader = try beginArtifactSubmission(from: guestTransportFileHandle(fixture))
    let forwarder = try ArtifactGuestSubmissionForwarder(
        descriptor: sockets[0], reader: reader
    )
    let observation = try forwarder.forward()
    let received = try readToEOF(sockets[1])
    #expect(received.prefix(8) == artifactGuestSubmissionMagicV1)
    #expect(received.count == fixture.count)
    #expect(received[8...] == fixture[8...])
    #expect(observation.artifactByteLength == 8)

    var hostShape = received
    hostShape.replaceSubrange(0..<8, with: artifactSubmissionMagicV1)
    let reparsed = try inspectArtifactSubmission(from: guestTransportFileHandle(hostShape))
    #expect(reparsed.runSpecSHA256 == observation.runSpecSHA256)
    #expect(reparsed.artifactSHA256 == observation.artifactSHA256)
}

@Test func guestForwarderFailsWithoutSignalWhenPeerIsClosed() throws {
    let fixture = try artifactSubmissionFixture().frame
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    _ = close(sockets[1])
    defer { _ = close(sockets[0]) }

    let reader = try beginArtifactSubmission(from: guestTransportFileHandle(fixture))
    let forwarder = try ArtifactGuestSubmissionForwarder(
        descriptor: sockets[0], reader: reader
    )
    #expect(throws: ArtifactGuestTransportError.writeFailed) {
        try forwarder.forward()
    }
}

private func guestTransportFileHandle(_ data: Data) -> FileHandle {
    let pipe = Pipe()
    pipe.fileHandleForWriting.write(data)
    try? pipe.fileHandleForWriting.close()
    return pipe.fileHandleForReading
}

private func readToEOF(_ descriptor: Int32) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 16 * 1024)
    while true {
        let count = recv(descriptor, &buffer, buffer.count, 0)
        if count == 0 { return result }
        guard count > 0 else {
            if errno == EINTR { continue }
            throw ArtifactGuestTransportError.writeFailed
        }
        result.append(contentsOf: buffer[0..<count])
    }
}
