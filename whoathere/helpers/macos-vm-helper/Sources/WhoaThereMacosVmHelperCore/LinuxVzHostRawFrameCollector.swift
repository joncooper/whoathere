import Darwin
import Foundation

public let linuxVzMaximumHostRawFrameBytesV1 = 65_535
public let linuxVzMaximumRetainedHostRawFramesV1 = 4_096

public enum LinuxVzHostRawFrameCollectorError: Error, Equatable {
    case invalidCapacity
    case invalidFrameLimit
}

public struct LinuxVzBoundedHostRawFrameCollection: Equatable, Sendable {
    public let retainedFrames: [Data]
    public let ingressFrameCount: Int
    public let droppedFrameCount: Int
    public let truncatedFrameCount: Int
    public let healthy: Bool
    public let terminal: String

    public var retainedFrameCount: Int { retainedFrames.count }
}

/// Continuously drains the host side of a VZ raw-frame datagram socket.
///
/// The collector bounds retained bytes while counting every received datagram. A caller must
/// request stop only after the VM can no longer emit frames; the collector then performs one final
/// drain through `EAGAIN` before returning. Any socket error or truncated datagram makes the
/// collection unhealthy. Retention overflow is explicit and must be treated as incomplete evidence.
public final class LinuxVzBoundedHostRawFrameCollector: @unchecked Sendable {
    private let lock = NSLock()
    private let capacity: Int
    private let maximumFrameBytes: Int
    private var stopRequested = false
    private var runStarted = false
    private var runFinished = false

    public init(
        capacity: Int,
        maximumFrameBytes: Int = linuxVzMaximumHostRawFrameBytesV1
    ) throws {
        guard capacity > 0, capacity <= linuxVzMaximumRetainedHostRawFramesV1 else {
            throw LinuxVzHostRawFrameCollectorError.invalidCapacity
        }
        guard maximumFrameBytes > 0,
              maximumFrameBytes <= linuxVzMaximumHostRawFrameBytesV1 else {
            throw LinuxVzHostRawFrameCollectorError.invalidFrameLimit
        }
        self.capacity = capacity
        self.maximumFrameBytes = maximumFrameBytes
    }

    public func requestStop() {
        lock.lock()
        stopRequested = true
        lock.unlock()
    }

    public func collect(fileDescriptor: Int32) -> LinuxVzBoundedHostRawFrameCollection {
        lock.lock()
        guard !runStarted, !runFinished, fileDescriptor >= 0 else {
            lock.unlock()
            return LinuxVzBoundedHostRawFrameCollection(
                retainedFrames: [],
                ingressFrameCount: 0,
                droppedFrameCount: 0,
                truncatedFrameCount: 0,
                healthy: false,
                terminal: "invalid_collector_lifecycle"
            )
        }
        runStarted = true
        lock.unlock()

        var retainedFrames = [Data]()
        retainedFrames.reserveCapacity(capacity)
        var ingressFrameCount = 0
        var droppedFrameCount = 0
        var truncatedFrameCount = 0
        var socketHealthy = true
        var buffer = [UInt8](repeating: 0, count: maximumFrameBytes)

        while true {
            let (received, messageWasTruncated) = buffer.withUnsafeMutableBytes { bytes in
                var vector = iovec(iov_base: bytes.baseAddress, iov_len: bytes.count)
                var message = msghdr()
                return withUnsafeMutablePointer(to: &vector) { vectorPointer in
                    message.msg_iov = vectorPointer
                    message.msg_iovlen = 1
                    let result = recvmsg(fileDescriptor, &message, MSG_DONTWAIT)
                    return (result, message.msg_flags & MSG_TRUNC != 0)
                }
            }
            if received >= 0 {
                ingressFrameCount += 1
                if messageWasTruncated {
                    truncatedFrameCount += 1
                    droppedFrameCount += 1
                } else if retainedFrames.count < capacity {
                    retainedFrames.append(Data(buffer.prefix(received)))
                } else {
                    droppedFrameCount += 1
                }
                continue
            }
            if errno == EINTR { continue }
            if errno != EAGAIN && errno != EWOULDBLOCK {
                socketHealthy = false
                break
            }
            lock.lock()
            let shouldStop = stopRequested
            lock.unlock()
            if shouldStop { break }
            usleep(1_000)
        }

        let terminal: String
        if !socketHealthy {
            terminal = "socket_error"
        } else if truncatedFrameCount > 0 {
            terminal = "truncated_frame"
        } else if droppedFrameCount > 0 {
            terminal = "bounded_queue_overflow_accounted"
        } else {
            terminal = "drained_after_stop"
        }
        lock.lock()
        runFinished = true
        lock.unlock()
        return LinuxVzBoundedHostRawFrameCollection(
            retainedFrames: retainedFrames,
            ingressFrameCount: ingressFrameCount,
            droppedFrameCount: droppedFrameCount,
            truncatedFrameCount: truncatedFrameCount,
            healthy: socketHealthy && truncatedFrameCount == 0,
            terminal: terminal
        )
    }
}
