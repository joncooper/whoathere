import AppKit
import XCTest
@testable import WhoaThereTimerCore

final class AnchoredPanelPlacementTests: XCTestCase {
    func testCentersArrowUnderStatusItemWhenThereIsRoom() {
        let buttonRect = NSRect(x: 900, y: 880, width: 42, height: 24)
        let visibleFrame = NSRect(x: 0, y: 0, width: 1200, height: 900)
        let panelSize = NSSize(width: 326, height: 354)

        let placement = AnchoredPanelPlacement.calculate(
            buttonRect: buttonRect,
            visibleFrame: visibleFrame,
            panelSize: panelSize
        )

        XCTAssertEqual(placement.frame.origin.y, 528)
        XCTAssertEqual(placement.frame.size, panelSize)
        XCTAssertEqual(placement.frame.origin.x + placement.arrowX, buttonRect.midX, accuracy: 0.001)
    }

    func testClampsToRightEdgeAndKeepsArrowWithinPanel() {
        let buttonRect = NSRect(x: 1170, y: 880, width: 24, height: 24)
        let visibleFrame = NSRect(x: 0, y: 0, width: 1200, height: 900)
        let panelSize = NSSize(width: 326, height: 354)

        let placement = AnchoredPanelPlacement.calculate(
            buttonRect: buttonRect,
            visibleFrame: visibleFrame,
            panelSize: panelSize
        )

        XCTAssertEqual(placement.frame.maxX, visibleFrame.maxX - 8, accuracy: 0.001)
        XCTAssertGreaterThanOrEqual(placement.arrowX, 22)
        XCTAssertLessThanOrEqual(placement.arrowX, panelSize.width - 22)
    }

    func testClampsToLeftEdgeAndKeepsArrowWithinPanel() {
        let buttonRect = NSRect(x: 4, y: 880, width: 24, height: 24)
        let visibleFrame = NSRect(x: 0, y: 0, width: 1200, height: 900)
        let panelSize = NSSize(width: 326, height: 354)

        let placement = AnchoredPanelPlacement.calculate(
            buttonRect: buttonRect,
            visibleFrame: visibleFrame,
            panelSize: panelSize
        )

        XCTAssertEqual(placement.frame.minX, visibleFrame.minX + 8, accuracy: 0.001)
        XCTAssertGreaterThanOrEqual(placement.arrowX, 22)
        XCTAssertLessThanOrEqual(placement.arrowX, panelSize.width - 22)
    }

    func testPlacementRespectsNegativeScreenOrigin() {
        let buttonRect = NSRect(x: -420, y: 880, width: 32, height: 24)
        let visibleFrame = NSRect(x: -800, y: 0, width: 800, height: 900)
        let panelSize = NSSize(width: 326, height: 354)

        let placement = AnchoredPanelPlacement.calculate(
            buttonRect: buttonRect,
            visibleFrame: visibleFrame,
            panelSize: panelSize
        )

        XCTAssertGreaterThanOrEqual(placement.frame.minX, visibleFrame.minX + 8)
        XCTAssertLessThanOrEqual(placement.frame.maxX, visibleFrame.maxX - 8)
        XCTAssertEqual(placement.frame.origin.x + placement.arrowX, buttonRect.midX, accuracy: 0.001)
    }

    func testEscapeKeyClosesAndOtherKeysPassThrough() {
        XCTAssertEqual(PanelKeyDecision.keyDown(keyCode: 53), .closeAndConsume)
        XCTAssertEqual(PanelKeyDecision.keyDown(keyCode: 36), .passThrough)
        XCTAssertEqual(PanelKeyDecision.keyDown(keyCode: 49), .passThrough)
    }

    func testMenuBarPanelPolicyDoesNotImmediatelyDismissOnActivationChanges() {
        let policy = TimerPanelPresentationPolicy.menuBarAttachedPanel

        XCTAssertFalse(policy.hidesOnDeactivate)
        XCTAssertFalse(policy.closesOnApplicationResignActive)
        XCTAssertEqual(policy.windowLevel.rawValue, NSWindow.Level.popUpMenu.rawValue)
    }

    func testStatusItemPresentationByState() {
        let idle = TimerModel(loadPersistedState: false)
        XCTAssertEqual(StatusItemPresentation.presentation(for: idle).title, "TC")
        XCTAssertEqual(StatusItemPresentation.presentation(for: idle).emphasis, .idle)
        XCTAssertFalse(StatusItemPresentation.presentation(for: idle).usesMonospacedDigits)

        let running = TimerModel.preview(state: .running, elapsed: 74)
        let runningPresentation = StatusItemPresentation.presentation(for: running)
        XCTAssertEqual(runningPresentation.emphasis, .running)
        XCTAssertTrue(runningPresentation.title.hasPrefix("● "))
        XCTAssertTrue(runningPresentation.usesMonospacedDigits)

        let paused = TimerModel.preview(state: .paused, elapsed: 74)
        let pausedPresentation = StatusItemPresentation.presentation(for: paused)
        XCTAssertEqual(pausedPresentation.emphasis, .paused)
        XCTAssertTrue(pausedPresentation.title.hasPrefix("Ⅱ "))
        XCTAssertTrue(pausedPresentation.usesMonospacedDigits)
    }
}
