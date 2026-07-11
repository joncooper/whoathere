import Testing
@testable import WhoaThereMacosVmHelperCore

@Test func cloneCleanupRequiresBothProvenVMStopAndTerminatedGuestSession() {
    #expect(
        artifactRunCloneCleanupDisposition(
            vmStopSucceeded: true,
            guestSessionTerminated: true
        ) == .cleanupAuthorized
    )
    #expect(
        artifactRunCloneCleanupDisposition(
            vmStopSucceeded: false,
            guestSessionTerminated: true
        ) == .retainBecauseVMStopUnproven
    )
    #expect(
        artifactRunCloneCleanupDisposition(
            vmStopSucceeded: true,
            guestSessionTerminated: false
        ) == .retainBecauseGuestSessionUnterminated
    )
    #expect(
        artifactRunCloneCleanupDisposition(
            vmStopSucceeded: false,
            guestSessionTerminated: false
        ) == .retainBecauseVMStopUnproven
    )
    #expect(
        ArtifactRunCloneCleanupDisposition.retainBecauseVMStopUnproven.reasonCode
            == "artifact_run_clone_cleanup_blocked_by_unproven_vm_stop"
    )
    #expect(ArtifactRunCloneCleanupDisposition.cleanupAuthorized.reasonCode == nil)
}
