//! Bounded, non-secret diagnostics for the qualified macOS Linux VZ helper.
//!
//! The helper owns the detailed failure body. Product reports expose only the
//! fixed classes below so a VM or package-controlled string cannot become a
//! reason code or leak into ordinary logs.

pub(crate) const MAX_LINUX_VZ_HELPER_RESULT_WIRE_BYTES_V1: usize = 64 * 1024;

pub(crate) fn linux_vz_helper_failure_class_v1(reason: Option<&str>) -> &'static str {
    let Some(reason) = reason else {
        return "helper_failure_reason_missing";
    };
    match reason {
        "usage" => "helper_failure_usage",
        "raw_frame_socket_pair_failed" => "helper_failure_raw_frame_socket_pair",
        "vm_stop_unproven" => "helper_failure_vm_stop_unproven",
        "execution_timeout" => "helper_failure_execution_timeout",
        "empty" => "helper_failure_serial_evidence_empty",
        "limitExceeded" => "helper_failure_serial_evidence_limit_exceeded",
        "missingTerminal" => "helper_failure_serial_evidence_missing_terminal",
        "malformedSection" => "helper_failure_serial_evidence_malformed_section",
        "invalidBase64" => "helper_failure_serial_evidence_invalid_base64",
        "digestMismatch" => "helper_failure_serial_evidence_digest_mismatch",
        "lengthMismatch" => "helper_failure_serial_evidence_length_mismatch",
        "verification_backend_kernel_binding" => "helper_failure_backend_kernel_binding",
        "verification_authority_binding" => "helper_failure_authority_binding",
        "verification_grant_expired_before_boot" => "helper_failure_grant_expired_before_boot",
        "verification_vm_contract" => "helper_failure_vm_contract",
        "verification_raw_frame_collector_completion" => {
            "helper_failure_raw_frame_collector_completion"
        }
        "verification_raw_frame_evidence_incomplete" => {
            "helper_failure_raw_frame_evidence_incomplete"
        }
        "verification_runtime_result_binding" => "helper_failure_runtime_result_binding",
        "verification_runtime_result_action_missing" => {
            "helper_failure_runtime_result_action_missing"
        }
        "verification_runtime_result_action_identity" => {
            "helper_failure_runtime_result_action_identity"
        }
        "verification_image_identity_changed" => "helper_failure_image_identity_changed",
        "verification_execution_image_schema" => "helper_failure_execution_image_schema",
        "verification_execution_image_digest" => "helper_failure_execution_image_digest",
        "verification_execution_image_time" => "helper_failure_execution_image_time",
        "verification_execution_image_binding" => "helper_failure_execution_image_binding",
        "builder_execution_bundle_launch" => "helper_failure_execution_bundle_launch",
        "builder_execution_image_launch" => "helper_failure_execution_image_launch",
        "vm_start_timeout" => "helper_failure_vm_start_timeout",
        _ if canonical_i32_suffix(reason, "builder_execution_bundle_exit_") => {
            "helper_failure_execution_bundle_exit"
        }
        _ if canonical_i32_suffix(reason, "builder_execution_image_exit_") => {
            "helper_failure_execution_image_exit"
        }
        _ if reason.starts_with("invalid_input_") => "helper_failure_invalid_input",
        _ if reason.starts_with("vm_start_") => "helper_failure_vm_start",
        _ if reason.starts_with("verification_execution_image_") => {
            "helper_failure_execution_image_verification"
        }
        _ if reason.starts_with("verification_") => "helper_failure_verification",
        _ => "helper_failure_unclassified",
    }
}

fn canonical_i32_suffix(reason: &str, prefix: &str) -> bool {
    reason.strip_prefix(prefix).is_some_and(|value| {
        value
            .parse::<i32>()
            .ok()
            .is_some_and(|parsed| parsed.to_string() == value)
    })
}

#[cfg(test)]
mod tests {
    use super::linux_vz_helper_failure_class_v1;

    #[test]
    fn helper_failure_classes_never_forward_raw_reason_text() {
        assert_eq!(
            linux_vz_helper_failure_class_v1(Some("builder_execution_bundle_exit_74")),
            "helper_failure_execution_bundle_exit"
        );
        assert_eq!(
            linux_vz_helper_failure_class_v1(Some("unknown_SECRET_CANARY_TEXT")),
            "helper_failure_unclassified"
        );
        assert_eq!(
            linux_vz_helper_failure_class_v1(Some("builder_execution_bundle_exit_074")),
            "helper_failure_unclassified"
        );
        assert_eq!(
            linux_vz_helper_failure_class_v1(Some("malformedSection")),
            "helper_failure_serial_evidence_malformed_section"
        );
    }
}
