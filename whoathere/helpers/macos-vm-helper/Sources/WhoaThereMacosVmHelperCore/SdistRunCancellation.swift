import Dispatch
import Foundation

public enum SdistRunCancellationReason: String, Equatable, Sendable {
    case interruptSignal = "sdist_run_cancelled_by_sigint"
    case terminationSignal = "sdist_run_cancelled_by_sigterm"
}

public enum SdistRunCancellationError: Error, Equatable, CustomStringConvertible, Sendable {
    case cancelled(SdistRunCancellationReason)

    public var description: String {
        switch self {
        case .cancelled(let reason):
            return reason.rawValue
        }
    }
}

public enum SdistRunWaitOutcome: Equatable, Sendable {
    case completed
    case timedOut
    case cancelled(SdistRunCancellationReason)
}

/// A process-local, first-writer-wins cancellation latch. Signal handlers only set this latch;
/// teardown remains on the normal orchestration path so VM stop and guest-session termination can
/// be proven before a disposable clone is deleted.
public final class SdistRunCancellationState: @unchecked Sendable {
    private let lock = NSLock()
    private var storedReason: SdistRunCancellationReason?

    public init() {}

    @discardableResult
    public func request(_ reason: SdistRunCancellationReason) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard storedReason == nil else { return false }
        storedReason = reason
        return true
    }

    public var reason: SdistRunCancellationReason? {
        lock.lock()
        defer { lock.unlock() }
        return storedReason
    }

    public func throwIfRequested() throws {
        if let reason {
            throw SdistRunCancellationError.cancelled(reason)
        }
    }
}

/// Waits in bounded slices so SIGINT/SIGTERM cancellation can rejoin the ordinary fail-closed
/// teardown path instead of terminating the process while a VM or VSOCK session may still exist.
public func waitForSdistRunCompletion(
    _ completion: DispatchSemaphore,
    cancellation: SdistRunCancellationState,
    timeoutMilliseconds: UInt64,
    pollIntervalMilliseconds: UInt64 = 100
) -> SdistRunWaitOutcome {
    if let reason = cancellation.reason {
        return .cancelled(reason)
    }
    guard timeoutMilliseconds > 0 else { return .timedOut }

    let pollMilliseconds = max(UInt64(1), pollIntervalMilliseconds)
    let timeoutNanoseconds = timeoutMilliseconds.multipliedReportingOverflow(by: 1_000_000)
    let started = DispatchTime.now().uptimeNanoseconds
    let deadline = started.addingReportingOverflow(timeoutNanoseconds.partialValue)
    let deadlineNanoseconds = timeoutNanoseconds.overflow || deadline.overflow
        ? UInt64.max
        : deadline.partialValue

    while true {
        if let reason = cancellation.reason {
            return .cancelled(reason)
        }
        let now = DispatchTime.now().uptimeNanoseconds
        guard now < deadlineNanoseconds else { return .timedOut }
        let remainingNanoseconds = deadlineNanoseconds - now
        let pollNanoseconds = pollMilliseconds.multipliedReportingOverflow(by: 1_000_000)
        let boundedPollNanoseconds = pollNanoseconds.overflow
            ? remainingNanoseconds
            : min(remainingNanoseconds, pollNanoseconds.partialValue)
        let dispatchSlice = Int(min(boundedPollNanoseconds, UInt64(Int.max)))
        if completion.wait(timeout: .now() + .nanoseconds(dispatchSlice)) == .success {
            if let reason = cancellation.reason {
                return .cancelled(reason)
            }
            return .completed
        }
    }
}
