import Foundation

public enum SdistRunCloneCleanupDisposition: Equatable, Sendable {
    case cleanupAuthorized
    case retainBecauseVMStopUnproven
    case retainBecauseGuestSessionUnterminated

    public var reasonCode: String? {
        switch self {
        case .cleanupAuthorized:
            return nil
        case .retainBecauseVMStopUnproven:
            return "sdist_run_clone_cleanup_blocked_by_unproven_vm_stop"
        case .retainBecauseGuestSessionUnterminated:
            return "sdist_run_clone_cleanup_blocked_by_live_guest_session"
        }
    }
}

public func sdistRunCloneCleanupDisposition(
    vmStopSucceeded: Bool,
    guestSessionTerminated: Bool
) -> SdistRunCloneCleanupDisposition {
    guard vmStopSucceeded else { return .retainBecauseVMStopUnproven }
    guard guestSessionTerminated else { return .retainBecauseGuestSessionUnterminated }
    return .cleanupAuthorized
}
