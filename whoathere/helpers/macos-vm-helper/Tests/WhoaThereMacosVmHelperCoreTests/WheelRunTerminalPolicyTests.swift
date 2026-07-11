import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func wheelCloneCleanupRequiresProvenVMStopAndTerminatedGuestChannel() {
    #expect(
        wheelRunCloneCleanupDisposition(
            vmStopSucceeded: true,
            guestSessionTerminated: true
        ) == .cleanupAuthorized
    )
    #expect(
        wheelRunCloneCleanupDisposition(
            vmStopSucceeded: false,
            guestSessionTerminated: true
        ) == .retainBecauseVMStopUnproven
    )
    #expect(
        wheelRunCloneCleanupDisposition(
            vmStopSucceeded: true,
            guestSessionTerminated: false
        ) == .retainBecauseGuestSessionUnterminated
    )
    #expect(
        wheelRunCloneCleanupDisposition(
            vmStopSucceeded: false,
            guestSessionTerminated: false
        ) == .retainBecauseVMStopUnproven
    )
}
