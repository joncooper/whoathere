import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func sdistCloneCleanupRequiresVMStopAndTerminatedGuestSession() {
    #expect(sdistRunCloneCleanupDisposition(
        vmStopSucceeded: true, guestSessionTerminated: true
    ) == .cleanupAuthorized)
    #expect(sdistRunCloneCleanupDisposition(
        vmStopSucceeded: false, guestSessionTerminated: true
    ) == .retainBecauseVMStopUnproven)
    #expect(sdistRunCloneCleanupDisposition(
        vmStopSucceeded: true, guestSessionTerminated: false
    ) == .retainBecauseGuestSessionUnterminated)
}

@Test func sdistGuestTerminationDistinguishesNoConnectionFromLiveAcceptedSession() {
    #expect(sdistGuestSessionTerminationProven(
        connectionAccepted: false,
        sessionCompletionObserved: false
    ))
    #expect(!sdistGuestSessionTerminationProven(
        connectionAccepted: true,
        sessionCompletionObserved: false
    ))
    #expect(sdistGuestSessionTerminationProven(
        connectionAccepted: true,
        sessionCompletionObserved: true
    ))
}
