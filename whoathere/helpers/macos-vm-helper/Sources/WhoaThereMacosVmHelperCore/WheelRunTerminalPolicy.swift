import Foundation

public enum WheelRunCloneCleanupDisposition: Equatable, Sendable {
    case cleanupAuthorized
    case retainBecauseVMStopUnproven
    case retainBecauseGuestSessionUnterminated

    public var reasonCode: String? {
        switch self {
        case .cleanupAuthorized:
            return nil
        case .retainBecauseVMStopUnproven:
            return "wheel_run_clone_cleanup_blocked_by_unproven_vm_stop"
        case .retainBecauseGuestSessionUnterminated:
            return "wheel_run_clone_cleanup_blocked_by_live_guest_session"
        }
    }
}

public func wheelRunCloneCleanupDisposition(
    vmStopSucceeded: Bool,
    guestSessionTerminated: Bool
) -> WheelRunCloneCleanupDisposition {
    guard vmStopSucceeded else { return .retainBecauseVMStopUnproven }
    guard guestSessionTerminated else { return .retainBecauseGuestSessionUnterminated }
    return .cleanupAuthorized
}
