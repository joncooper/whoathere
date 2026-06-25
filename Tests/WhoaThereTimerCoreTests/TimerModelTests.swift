import XCTest
@testable import WhoaThereTimerCore

final class TimerModelTests: XCTestCase {
    func testIdleStatusIsCompact() {
        let model = TimerModel(loadPersistedState: false)

        XCTAssertEqual(model.statusTitle, "TC")
        XCTAssertEqual(model.stateLabel, "Ready")
        XCTAssertFalse(model.isActive)
    }

    func testStartPauseResumeAndLogInterval() {
        let model = TimerModel(loadPersistedState: false)
        model.setNote("Menu bar timer work")

        model.startOrResume()
        XCTAssertEqual(model.state, .running)
        XCTAssertTrue(model.isActive)

        model.pause()
        XCTAssertEqual(model.state, .paused)

        model.startOrResume()
        XCTAssertEqual(model.state, .running)

        Thread.sleep(forTimeInterval: 1.05)
        model.stopAndSave()

        XCTAssertEqual(model.state, .idle)
        XCTAssertEqual(model.entries.count, 1)
        XCTAssertEqual(model.entries[0].note, "Menu bar timer work")
        XCTAssertGreaterThanOrEqual(model.entries[0].duration, 1)
    }

    func testEmptyLoggedNoteFallsBackToConsultingWork() {
        let model = TimerModel(loadPersistedState: false)

        model.startOrResume()
        Thread.sleep(forTimeInterval: 1.05)
        model.stopAndSave()

        XCTAssertEqual(model.entries.first?.note, "Consulting work")
    }

    func testImmediateStopDoesNotLogEntry() {
        let model = TimerModel(loadPersistedState: false)

        model.startOrResume()
        model.stopAndSave()

        XCTAssertEqual(model.state, .idle)
        XCTAssertTrue(model.entries.isEmpty)
    }

    func testDiscardKeepsExistingEntries() {
        let model = TimerModel(loadPersistedState: false)

        model.startOrResume()
        Thread.sleep(forTimeInterval: 1.05)
        model.stopAndSave()
        XCTAssertEqual(model.entries.count, 1)

        model.startOrResume()
        model.discardCurrentInterval()

        XCTAssertEqual(model.state, .idle)
        XCTAssertEqual(model.entries.count, 1)
    }

    func testRecentEntriesAreNotLimitedToToday() {
        let model = TimerModel(loadPersistedState: false)
        let now = Date()
        model.entries = [
            TimeEntry(
                start: now.addingTimeInterval(-24 * 3600),
                end: now.addingTimeInterval(-23 * 3600),
                note: "Yesterday",
                duration: 3600
            ),
            TimeEntry(
                start: now.addingTimeInterval(-48 * 3600),
                end: now.addingTimeInterval(-46 * 3600),
                note: "Two days ago",
                duration: 2 * 3600
            ),
            TimeEntry(
                start: now.addingTimeInterval(-72 * 3600),
                end: now.addingTimeInterval(-69 * 3600),
                note: "Three days ago",
                duration: 3 * 3600
            ),
            TimeEntry(
                start: now.addingTimeInterval(-96 * 3600),
                end: now.addingTimeInterval(-92 * 3600),
                note: "Not visible",
                duration: 4 * 3600
            )
        ]

        XCTAssertEqual(model.recentEntries.map(\.note), ["Yesterday", "Two days ago", "Three days ago"])
        XCTAssertEqual(model.recentEntriesHours, 6, accuracy: 0.001)
    }

    func testTickOnlyNotifiesWhileRunning() {
        let model = TimerModel(loadPersistedState: false)
        var changeCount = 0
        model.onChange = {
            changeCount += 1
        }

        model.tick()
        XCTAssertEqual(changeCount, 0)

        model.startOrResume()
        changeCount = 0
        model.tick()
        XCTAssertEqual(changeCount, 1)

        model.pause()
        changeCount = 0
        model.tick()
        XCTAssertEqual(changeCount, 0)
    }
}
