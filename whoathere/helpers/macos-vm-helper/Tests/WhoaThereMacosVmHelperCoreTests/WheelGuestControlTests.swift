import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func wheelControlFramesAreTypedBoundedAndRequireExplicitEOF() throws {
    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    let challenge = Data("{\"wheel_challenge\":\"inert\"}".utf8)
    try writeWheelGuestControlFrame(
        descriptor: sockets[0],
        frameType: .authenticationChallenge,
        body: challenge,
        timeoutMillis: 1_000
    )
    #expect(
        try readWheelGuestControlFrame(
            descriptor: sockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1024,
            timeoutMillis: 1_000
        ) == challenge
    )

    let response = Data("{\"wheel_response\":\"inert\"}".utf8)
    try writeWheelGuestControlFrame(
        descriptor: sockets[1],
        frameType: .authenticationResponse,
        body: response,
        timeoutMillis: 1_000
    )
    #expect(
        try readWheelGuestControlFrame(
            descriptor: sockets[0],
            expectedType: .authenticationResponse,
            maximumBodyBytes: 1024,
            timeoutMillis: 1_000
        ) == response
    )
    #expect(shutdown(sockets[1], SHUT_WR) == 0)
    try requireWheelGuestControlEOF(descriptor: sockets[0], timeoutMillis: 1_000)
}

@Test func wheelControlRejectsNpmMagicWrongTypeLimitsAndIdleWaits() throws {
    var npmSockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &npmSockets) == 0)
    guard npmSockets[0] >= 0, npmSockets[1] >= 0 else { return }
    var npmFrame = Data()
    npmFrame.append(artifactGuestControlMagicV1)
    npmFrame.append(contentsOf: [0, 1, 0, 1, 0, 0, 0, 2])
    npmFrame.append(Data("{}".utf8))
    #expect(
        send(npmSockets[0], [UInt8](npmFrame), npmFrame.count, MSG_NOSIGNAL) == npmFrame.count
    )
    #expect(throws: WheelGuestControlError.invalidMagic) {
        try readWheelGuestControlFrame(
            descriptor: npmSockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1024,
            timeoutMillis: 1_000
        )
    }
    _ = close(npmSockets[0])
    _ = close(npmSockets[1])

    var sockets: [Int32] = [-1, -1]
    #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &sockets) == 0)
    guard sockets[0] >= 0, sockets[1] >= 0 else { return }
    defer {
        _ = close(sockets[0])
        _ = close(sockets[1])
    }
    try writeWheelGuestControlFrame(
        descriptor: sockets[0],
        frameType: .authenticationResponse,
        body: Data("{}".utf8),
        timeoutMillis: 1_000
    )
    #expect(throws: WheelGuestControlError.unexpectedFrameType) {
        try readWheelGuestControlFrame(
            descriptor: sockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1024,
            timeoutMillis: 1_000
        )
    }
    #expect(throws: WheelGuestControlError.bodyLimitExceeded) {
        try writeWheelGuestControlFrame(
            descriptor: sockets[0],
            frameType: .authenticationChallenge,
            body: Data(),
            timeoutMillis: 1_000
        )
    }
    #expect(throws: WheelGuestControlError.timeout) {
        try readWheelGuestControlFrame(
            descriptor: sockets[1],
            expectedType: .authenticationChallenge,
            maximumBodyBytes: 1024,
            timeoutMillis: 10
        )
    }
}
