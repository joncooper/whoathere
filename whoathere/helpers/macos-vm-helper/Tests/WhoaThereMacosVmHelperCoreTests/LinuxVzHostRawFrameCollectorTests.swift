import Darwin
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func linuxVzHostRawFrameCollectorDrainsQueuedDatagramsAfterStop() throws {
    var sockets = [Int32](repeating: -1, count: 2)
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0)
    defer {
        close(sockets[0])
        close(sockets[1])
    }
    try sendHostRawFrameFixture(Data([1, 2, 3]), descriptor: sockets[0])
    try sendHostRawFrameFixture(Data([4, 5]), descriptor: sockets[0])

    let collector = try LinuxVzBoundedHostRawFrameCollector(capacity: 4)
    collector.requestStop()
    let collection = collector.collect(fileDescriptor: sockets[1])

    #expect(collection.retainedFrames == [Data([1, 2, 3]), Data([4, 5])])
    #expect(collection.ingressFrameCount == 2)
    #expect(collection.retainedFrameCount == 2)
    #expect(collection.droppedFrameCount == 0)
    #expect(collection.truncatedFrameCount == 0)
    #expect(collection.healthy)
    #expect(collection.terminal == "drained_after_stop")
}

@Test func linuxVzHostRawFrameCollectorAccountsBoundedRetentionOverflow() throws {
    var sockets = [Int32](repeating: -1, count: 2)
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0)
    defer {
        close(sockets[0])
        close(sockets[1])
    }
    for byte in UInt8(1)...UInt8(3) {
        try sendHostRawFrameFixture(Data([byte]), descriptor: sockets[0])
    }

    let collector = try LinuxVzBoundedHostRawFrameCollector(capacity: 2)
    collector.requestStop()
    let collection = collector.collect(fileDescriptor: sockets[1])

    #expect(collection.ingressFrameCount == 3)
    #expect(collection.retainedFrameCount == 2)
    #expect(collection.droppedFrameCount == 1)
    #expect(collection.truncatedFrameCount == 0)
    #expect(collection.healthy)
    #expect(collection.terminal == "bounded_queue_overflow_accounted")
}

@Test func linuxVzHostRawFrameCollectorRejectsTruncatedEvidence() throws {
    var sockets = [Int32](repeating: -1, count: 2)
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0)
    defer {
        close(sockets[0])
        close(sockets[1])
    }
    try sendHostRawFrameFixture(Data(repeating: 0xa5, count: 16), descriptor: sockets[0])

    let collector = try LinuxVzBoundedHostRawFrameCollector(
        capacity: 2,
        maximumFrameBytes: 8
    )
    collector.requestStop()
    let collection = collector.collect(fileDescriptor: sockets[1])

    #expect(collection.ingressFrameCount == 1)
    #expect(collection.retainedFrameCount == 0)
    #expect(collection.droppedFrameCount == 1)
    #expect(collection.truncatedFrameCount == 1)
    #expect(!collection.healthy)
    #expect(collection.terminal == "truncated_frame")
}

@Test func linuxVzHostRawFrameCollectorRejectsInvalidConfigurationAndReuse() throws {
    #expect(throws: LinuxVzHostRawFrameCollectorError.invalidCapacity) {
        try LinuxVzBoundedHostRawFrameCollector(capacity: 0)
    }
    #expect(throws: LinuxVzHostRawFrameCollectorError.invalidFrameLimit) {
        try LinuxVzBoundedHostRawFrameCollector(capacity: 1, maximumFrameBytes: 0)
    }

    var sockets = [Int32](repeating: -1, count: 2)
    #expect(socketpair(AF_UNIX, SOCK_DGRAM, 0, &sockets) == 0)
    defer {
        close(sockets[0])
        close(sockets[1])
    }
    let collector = try LinuxVzBoundedHostRawFrameCollector(capacity: 1)
    collector.requestStop()
    #expect(collector.collect(fileDescriptor: sockets[1]).healthy)
    let reused = collector.collect(fileDescriptor: sockets[1])
    #expect(!reused.healthy)
    #expect(reused.terminal == "invalid_collector_lifecycle")
}

private enum LinuxVzHostRawFrameCollectorTestError: Error {
    case sendFailed
}

private func sendHostRawFrameFixture(_ data: Data, descriptor: Int32) throws {
    let sent = data.withUnsafeBytes { bytes in
        send(descriptor, bytes.baseAddress, bytes.count, 0)
    }
    guard sent == data.count else {
        throw LinuxVzHostRawFrameCollectorTestError.sendFailed
    }
}
