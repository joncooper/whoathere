import Foundation

public enum ArtifactRunCloneCleanupDisposition: Equatable, Sendable {
    case cleanupAuthorized
    case retainBecauseVMStopUnproven
    case retainBecauseGuestSessionUnterminated

    public var reasonCode: String? {
        switch self {
        case .cleanupAuthorized:
            return nil
        case .retainBecauseVMStopUnproven:
            return "artifact_run_clone_cleanup_blocked_by_unproven_vm_stop"
        case .retainBecauseGuestSessionUnterminated:
            return "artifact_run_clone_cleanup_blocked_by_live_guest_session"
        }
    }
}

public func artifactRunCloneCleanupDisposition(
    vmStopSucceeded: Bool,
    guestSessionTerminated: Bool
) -> ArtifactRunCloneCleanupDisposition {
    guard vmStopSucceeded else { return .retainBecauseVMStopUnproven }
    guard guestSessionTerminated else { return .retainBecauseGuestSessionUnterminated }
    return .cleanupAuthorized
}
