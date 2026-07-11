import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func sdistControlFramesAreDistinctTypedBoundedAndEOFChecked() throws {
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let body = Data("inert sdist challenge".utf8)
    try writeSdistGuestControlFrame(
        descriptor: sockets[0],
        frameType: .authenticationChallenge,
        body: body,
        timeoutMillis: 1_000
    )
    let received = try readSdistGuestControlFrame(
        descriptor: sockets[1],
        expectedType: .authenticationChallenge,
        maximumBodyBytes: 1_024,
        timeoutMillis: 1_000
    )
    #expect(received == body)
    let grant = Data("inert secret-bearing execution grant".utf8)
    try writeSdistGuestControlFrame(
        descriptor: sockets[0],
        frameType: .buildExecutionGrant,
        body: grant,
        timeoutMillis: 1_000
    )
    #expect(try readSdistGuestControlFrame(
        descriptor: sockets[1],
        expectedType: .buildExecutionGrant,
        maximumBodyBytes: 1_024,
        timeoutMillis: 1_000
    ) == grant)
    #expect(throws: SdistGuestControlError.bodyLimitExceeded) {
        try writeSdistGuestControlFrame(
            descriptor: sockets[0],
            frameType: .stagingReceipt,
            body: Data(),
            timeoutMillis: 1_000
        )
    }
    #expect(shutdown(sockets[0], SHUT_WR) == 0)
    try requireSdistGuestControlEOF(descriptor: sockets[1], timeoutMillis: 1_000)
}

@Test func sdistControlRejectsWheelMagicAndUnexpectedType() throws {
    var wheelSockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &wheelSockets) == 0)
    guard wheelSockets[0] >= 0, wheelSockets[1] >= 0 else { return }
    defer {
        _ = close(wheelSockets[0])
        _ = close(wheelSockets[1])
    }
    try writeWheelGuestControlFrame(
        descriptor: wheelSockets[0],
        frameType: .authenticationChallenge,
        body: Data("wheel".utf8),
        timeoutMillis: 1_000
    )
    #expect(throws: SdistGuestControlError.invalidMagic) {
        try readSdistGuestControlFrame(
            descriptor: wheelSockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1_024,
            timeoutMillis: 1_000
        )
    }

    var typeSockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &typeSockets) == 0)
    guard typeSockets[0] >= 0, typeSockets[1] >= 0 else { return }
    defer {
        _ = close(typeSockets[0])
        _ = close(typeSockets[1])
    }
    try writeSdistGuestControlFrame(
        descriptor: typeSockets[0],
        frameType: .stagingReceipt,
        body: Data("receipt".utf8),
        timeoutMillis: 1_000
    )
    #expect(throws: SdistGuestControlError.unexpectedFrameType) {
        try readSdistGuestControlFrame(
            descriptor: typeSockets[1],
            expectedType: .authenticationResponse,
            maximumBodyBytes: 1_024,
            timeoutMillis: 1_000
        )
    }
}
