import Dispatch
import Foundation
import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func sdistCancellationIsFirstWriterWins() throws {
    let cancellation = SdistRunCancellationState()

    #expect(cancellation.reason == nil)
    #expect(cancellation.request(.interruptSignal))
    #expect(!cancellation.request(.terminationSignal))
    #expect(cancellation.reason == .interruptSignal)
    #expect(throws: SdistRunCancellationError.cancelled(.interruptSignal)) {
        try cancellation.throwIfRequested()
    }
}

@Test func sdistCompletionWaitReturnsCompleted() {
    let completion = DispatchSemaphore(value: 0)
    let cancellation = SdistRunCancellationState()
    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + .milliseconds(10)) {
        completion.signal()
    }

    #expect(waitForSdistRunCompletion(
        completion,
        cancellation: cancellation,
        timeoutMilliseconds: 1_000
    ) == .completed)
}

@Test func sdistCompletionWaitIsInterruptibleWithoutConsumingCompletion() {
    let completion = DispatchSemaphore(value: 0)
    let cancellation = SdistRunCancellationState()
    let requestFinished = DispatchSemaphore(value: 0)

    DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + .milliseconds(25)) {
        cancellation.request(.terminationSignal)
        requestFinished.signal()
    }

    #expect(waitForSdistRunCompletion(
        completion,
        cancellation: cancellation,
        timeoutMilliseconds: 2_000,
        pollIntervalMilliseconds: 10
    ) == .cancelled(.terminationSignal))
    #expect(requestFinished.wait(timeout: .now() + .seconds(1)) == .success)
    #expect(completion.wait(timeout: .now()) == .timedOut)
}

@Test func sdistCompletionWaitTimesOutFailClosed() {
    let completion = DispatchSemaphore(value: 0)
    let cancellation = SdistRunCancellationState()

    #expect(waitForSdistRunCompletion(
        completion,
        cancellation: cancellation,
        timeoutMilliseconds: 20,
        pollIntervalMilliseconds: 5
    ) == .timedOut)
}

@Test func sdistSubmissionInputReadCanBeCancelledBeforeVMOrAuthority() throws {
    let pipe = Pipe()
    defer {
        try? pipe.fileHandleForReading.close()
        try? pipe.fileHandleForWriting.close()
    }
    let cancellation = SdistRunCancellationState()
    let result = SdistCancellationTestResult()
    let finished = DispatchSemaphore(value: 0)

    DispatchQueue.global(qos: .userInitiated).async {
        do {
            _ = try beginSdistSubmission(
                from: pipe.fileHandleForReading,
                cancellation: cancellation
            )
            result.store("unexpected_success")
        } catch {
            result.store(String(describing: error))
        }
        finished.signal()
    }

    Thread.sleep(forTimeInterval: 0.025)
    cancellation.request(.interruptSignal)
    #expect(finished.wait(timeout: .now() + .seconds(1)) == .success)
    #expect(result.load() == SdistRunCancellationReason.interruptSignal.rawValue)
}

private final class SdistCancellationTestResult: @unchecked Sendable {
    private let lock = NSLock()
    private var value: String?

    func store(_ value: String) {
        lock.lock()
        self.value = value
        lock.unlock()
    }

    func load() -> String? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
