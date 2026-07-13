use crate::{
    decode_linux_vz_package_runtime_qualification_request_v1,
    decode_linux_vz_package_runtime_qualification_response_v1,
    decode_linux_vz_process_evidence_payload_v1,
    verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1,
    verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1,
    LinuxVzTelemetryConformanceCaseV1, MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
    MacosLinuxVzPackageRuntimeQualificationRequestV1,
    MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactTelemetrySyncBackPolicyV1;

pub const MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_runtime_qualification_record.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_BYTES_V1: usize = 128 * 1024;

const RECORD_AUTHORITY_V1: &str =
    "verified_guest_and_host_fixed_nonexecuting_runtime_qualification";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageRuntimeQualificationStateV1 {
    FixedNonexecutingProbePassed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageExecutionRunnerCapabilityV1 {
    NotQualified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeQualificationRecordWireV1 {
    schema_version: String,
    authority: String,
    qualification_state: MacosLinuxVzPackageRuntimeQualificationStateV1,
    execution_runner_capability: MacosLinuxVzPackageExecutionRunnerCapabilityV1,
    qualification_request_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    conformance_evidence_set_sha256: Sha256Digest,
    kernel_image_sha256: Sha256Digest,
    qualified_initramfs_sha256: Sha256Digest,
    qualified_guest_signer_sha256: Sha256Digest,
    qualified_protected_sensor_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    runtime_qualification_initramfs_sha256: Sha256Digest,
    runtime_qualification_guest_agent_sha256: Sha256Digest,
    runtime_qualification_guest_init_sha256: Sha256Digest,
    runtime_qualification_module_bundle_sha256: Sha256Digest,
    candidate_runtime_rootfs_sha256: Sha256Digest,
    candidate_runtime_rootfs_byte_length: String,
    candidate_runtime_manifest_sha256: Sha256Digest,
    candidate_package_runner_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    request_frame_sha256: Sha256Digest,
    response_frame_sha256: Sha256Digest,
    expected_probe_report_sha256: Sha256Digest,
    observed_probe_report_sha256: Sha256Digest,
    process_evidence_sha256: Sha256Digest,
    process_evidence_byte_length: String,
    guest_receipt_sha256: Sha256Digest,
    host_evidence_sha256: Sha256Digest,
    host_receipt_sha256: Sha256Digest,
    event_sequence_start: String,
    event_sequence_end: String,
    event_count: String,
    heartbeat_count: String,
    dropped_event_count: String,
    package_uid: String,
    package_gid: String,
    sensor_healthy: bool,
    evidence_truncated: bool,
    descendant_teardown_complete: bool,
    guest_receipt_verified: bool,
    host_receipt_verified: bool,
    nonexecuting_probe_observed: bool,
    raw_frame_count: String,
    external_frames_forwarded: String,
    public_network_route_present: bool,
    vm_stopped: bool,
    clone_destroyed: bool,
    execution_authority_issuance_permitted: bool,
    package_execution: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageRuntimeQualificationRecordV1 {
    canonical_json: Vec<u8>,
    record_sha256: Sha256Digest,
    wire: RuntimeQualificationRecordWireV1,
}

impl fmt::Debug for MacosLinuxVzPackageRuntimeQualificationRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageRuntimeQualificationRecordV1")
            .field("record_sha256", &self.record_sha256)
            .field(
                "qualification_request_sha256",
                &self.wire.qualification_request_sha256,
            )
            .field(
                "candidate_runtime_rootfs_sha256",
                &self.wire.candidate_runtime_rootfs_sha256,
            )
            .field(
                "execution_runner_capability",
                &self.wire.execution_runner_capability,
            )
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosLinuxVzPackageRuntimeQualificationRecordV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn record_sha256(&self) -> &Sha256Digest {
        &self.record_sha256
    }

    pub fn qualification_request_sha256(&self) -> &Sha256Digest {
        &self.wire.qualification_request_sha256
    }

    pub fn qualified_telemetry_backend_sha256(&self) -> &Sha256Digest {
        &self.wire.qualified_telemetry_backend_sha256
    }

    pub fn candidate_runtime_rootfs_sha256(&self) -> &Sha256Digest {
        &self.wire.candidate_runtime_rootfs_sha256
    }

    pub fn candidate_runtime_manifest_sha256(&self) -> &Sha256Digest {
        &self.wire.candidate_runtime_manifest_sha256
    }

    pub fn candidate_package_runner_sha256(&self) -> &Sha256Digest {
        &self.wire.candidate_package_runner_sha256
    }

    pub const fn qualification_state(&self) -> MacosLinuxVzPackageRuntimeQualificationStateV1 {
        self.wire.qualification_state
    }

    pub const fn execution_runner_capability(
        &self,
    ) -> MacosLinuxVzPackageExecutionRunnerCapabilityV1 {
        self.wire.execution_runner_capability
    }

    pub const fn execution_authority_issuance_permitted(&self) -> bool {
        false
    }

    pub const fn package_execution_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzPackageRuntimeQualificationRecordErrorV1 {
    RequestFrameInvalid,
    ResponseFrameInvalid,
    ProcessEvidenceInvalid,
    EvidenceBindingMismatch,
    GuestReceiptInvalid,
    HostReceiptInvalid,
    Empty,
    LimitExceeded,
    InvalidRecord,
    NonCanonical,
    Serialization,
}

impl MacosLinuxVzPackageRuntimeQualificationRecordErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::RequestFrameInvalid => {
                "macos_linux_vz_runtime_qualification_record_request_frame_invalid"
            }
            Self::ResponseFrameInvalid => {
                "macos_linux_vz_runtime_qualification_record_response_frame_invalid"
            }
            Self::ProcessEvidenceInvalid => {
                "macos_linux_vz_runtime_qualification_record_process_evidence_invalid"
            }
            Self::EvidenceBindingMismatch => {
                "macos_linux_vz_runtime_qualification_record_evidence_binding_mismatch"
            }
            Self::GuestReceiptInvalid => {
                "macos_linux_vz_runtime_qualification_record_guest_receipt_invalid"
            }
            Self::HostReceiptInvalid => {
                "macos_linux_vz_runtime_qualification_record_host_receipt_invalid"
            }
            Self::Empty => "macos_linux_vz_runtime_qualification_record_empty",
            Self::LimitExceeded => "macos_linux_vz_runtime_qualification_record_limit_exceeded",
            Self::InvalidRecord => "macos_linux_vz_runtime_qualification_record_invalid",
            Self::NonCanonical => "macos_linux_vz_runtime_qualification_record_noncanonical",
            Self::Serialization => {
                "macos_linux_vz_runtime_qualification_record_serialization_failed"
            }
        }
    }
}

impl fmt::Display for MacosLinuxVzPackageRuntimeQualificationRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzPackageRuntimeQualificationRecordErrorV1 {}

#[allow(clippy::too_many_arguments)]
pub fn build_macos_linux_vz_package_runtime_qualification_record_v1(
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    request_frame: &[u8],
    response_frame: &[u8],
    host_evidence_bytes: &[u8],
    host_receipt_bytes: &[u8],
    guest_verifying_key_bytes: [u8; 32],
    host_verifying_key_bytes: [u8; 32],
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRecordV1,
    MacosLinuxVzPackageRuntimeQualificationRecordErrorV1,
> {
    let decoded_request = decode_linux_vz_package_runtime_qualification_request_v1(request_frame)
        .map_err(|_| {
        MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::RequestFrameInvalid
    })?;
    if decoded_request != request.canonical_json_v1() {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::EvidenceBindingMismatch);
    }
    let response = decode_linux_vz_package_runtime_qualification_response_v1(response_frame)
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::ResponseFrameInvalid)?;
    if response.probe_report() != MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1 {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::EvidenceBindingMismatch);
    }
    let process = decode_linux_vz_process_evidence_payload_v1(response.process_evidence())
        .map_err(|_| {
            MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::ProcessEvidenceInvalid
        })?;
    if process.fixture_case() != LinuxVzTelemetryConformanceCaseV1::ForkExecExit
        || process.package_uid() != request.package_uid()
        || process.package_gid() != request.package_gid()
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::EvidenceBindingMismatch);
    }
    let process_claims = process.guest_observation_claims_v1().map_err(|_| {
        MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::ProcessEvidenceInvalid
    })?;
    let guest_claims = MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1::new(
        request,
        process_claims.clone(),
        response.probe_report(),
        request.candidate_runtime_rootfs_sha256().clone(),
    )
    .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::GuestReceiptInvalid)?;
    let guest_verified = verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
        request,
        response.guest_receipt(),
        guest_verifying_key_bytes,
        &guest_claims,
    )
    .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::GuestReceiptInvalid)?;
    let host_verified = verify_macos_linux_vz_package_runtime_qualification_host_receipt_v1(
        request,
        request_frame,
        response_frame,
        host_evidence_bytes,
        host_receipt_bytes,
        host_verifying_key_bytes,
    )
    .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::HostReceiptInvalid)?;
    if guest_verified.qualification_request_sha256() != request.request_sha256()
        || host_verified.qualification_request_sha256() != request.request_sha256()
        || host_verified.clone_binding_sha256() != request.clone_binding_sha256()
        || guest_verified.package_execution_authority_permitted()
        || guest_verified.sync_back_permitted()
        || host_verified.execution_authority_permitted()
        || host_verified.package_execution_permitted()
        || host_verified.sync_back_permitted()
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::EvidenceBindingMismatch);
    }

    build_record_from_wire_v1(RuntimeQualificationRecordWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_SCHEMA_V1.to_string(),
        authority: RECORD_AUTHORITY_V1.to_string(),
        qualification_state:
            MacosLinuxVzPackageRuntimeQualificationStateV1::FixedNonexecutingProbePassed,
        execution_runner_capability: MacosLinuxVzPackageExecutionRunnerCapabilityV1::NotQualified,
        qualification_request_sha256: request.request_sha256().clone(),
        qualified_telemetry_backend_sha256: request.qualified_telemetry_backend_sha256().clone(),
        backend_identity_sha256: request.backend_identity_sha256().clone(),
        telemetry_requirements_sha256: request.telemetry_requirements_sha256().clone(),
        conformance_evidence_set_sha256: request.conformance_evidence_set_sha256().clone(),
        kernel_image_sha256: request.kernel_image_sha256().clone(),
        qualified_initramfs_sha256: request.qualified_initramfs_sha256().clone(),
        qualified_guest_signer_sha256: request.qualified_guest_signer_sha256().clone(),
        qualified_protected_sensor_sha256: request.qualified_protected_sensor_sha256().clone(),
        guest_evidence_public_key_sha256: request.guest_evidence_public_key_sha256().clone(),
        host_evidence_public_key_sha256: request.host_evidence_public_key_sha256().clone(),
        runtime_qualification_initramfs_sha256: request
            .runtime_qualification_initramfs_sha256()
            .clone(),
        runtime_qualification_guest_agent_sha256: request
            .runtime_qualification_guest_agent_sha256()
            .clone(),
        runtime_qualification_guest_init_sha256: request
            .runtime_qualification_guest_init_sha256()
            .clone(),
        runtime_qualification_module_bundle_sha256: request
            .runtime_qualification_module_bundle_sha256()
            .clone(),
        candidate_runtime_rootfs_sha256: request.candidate_runtime_rootfs_sha256().clone(),
        candidate_runtime_rootfs_byte_length: request
            .candidate_runtime_rootfs_byte_length()
            .to_string(),
        candidate_runtime_manifest_sha256: request.candidate_runtime_manifest_sha256().clone(),
        candidate_package_runner_sha256: request.candidate_package_runner_sha256().clone(),
        request_challenge_sha256: request.request_challenge_sha256().clone(),
        clone_binding_sha256: request.clone_binding_sha256().clone(),
        request_frame_sha256: Sha256Digest::from_bytes(request_frame),
        response_frame_sha256: Sha256Digest::from_bytes(response_frame),
        expected_probe_report_sha256: request.expected_probe_report_sha256().clone(),
        observed_probe_report_sha256: Sha256Digest::from_bytes(response.probe_report()),
        process_evidence_sha256: process_claims.evidence_payload_sha256().clone(),
        process_evidence_byte_length: process_claims.evidence_byte_length().to_string(),
        guest_receipt_sha256: Sha256Digest::from_bytes(response.guest_receipt()),
        host_evidence_sha256: host_verified.host_evidence_sha256().clone(),
        host_receipt_sha256: Sha256Digest::from_bytes(host_receipt_bytes),
        event_sequence_start: process_claims.event_sequence_start().to_string(),
        event_sequence_end: process_claims.event_sequence_end().to_string(),
        event_count: process_claims.event_count().to_string(),
        heartbeat_count: process_claims.heartbeat_count().to_string(),
        dropped_event_count: process_claims.dropped_event_count().to_string(),
        package_uid: request.package_uid().to_string(),
        package_gid: request.package_gid().to_string(),
        sensor_healthy: process_claims.sensor_healthy(),
        evidence_truncated: process_claims.evidence_truncated(),
        descendant_teardown_complete: process_claims.descendant_teardown_complete(),
        guest_receipt_verified: true,
        host_receipt_verified: true,
        nonexecuting_probe_observed: true,
        raw_frame_count: "0".to_string(),
        external_frames_forwarded: "0".to_string(),
        public_network_route_present: false,
        vm_stopped: true,
        clone_destroyed: true,
        execution_authority_issuance_permitted: false,
        package_execution: false,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn verify_macos_linux_vz_package_runtime_qualification_record_v1(
    record_bytes: &[u8],
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    request_frame: &[u8],
    response_frame: &[u8],
    host_evidence_bytes: &[u8],
    host_receipt_bytes: &[u8],
    guest_verifying_key_bytes: [u8; 32],
    host_verifying_key_bytes: [u8; 32],
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRecordV1,
    MacosLinuxVzPackageRuntimeQualificationRecordErrorV1,
> {
    let supplied = decode_macos_linux_vz_package_runtime_qualification_record_v1(record_bytes)?;
    let rebuilt = build_macos_linux_vz_package_runtime_qualification_record_v1(
        request,
        request_frame,
        response_frame,
        host_evidence_bytes,
        host_receipt_bytes,
        guest_verifying_key_bytes,
        host_verifying_key_bytes,
    )?;
    if supplied != rebuilt {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::EvidenceBindingMismatch);
    }
    Ok(supplied)
}

pub fn decode_macos_linux_vz_package_runtime_qualification_record_v1(
    bytes: &[u8],
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRecordV1,
    MacosLinuxVzPackageRuntimeQualificationRecordErrorV1,
> {
    if bytes.is_empty() {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::Empty);
    }
    if bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_BYTES_V1 {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = RuntimeQualificationRecordWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::NonCanonical);
    }
    build_record_from_wire_v1(wire)
}

fn build_record_from_wire_v1(
    wire: RuntimeQualificationRecordWireV1,
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRecordV1,
    MacosLinuxVzPackageRuntimeQualificationRecordErrorV1,
> {
    validate_wire_v1(&wire)?;
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::Serialization)?;
    if canonical_json.len() > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_BYTES_V1 {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::LimitExceeded);
    }
    let record_sha256 = Sha256Digest::from_bytes(&canonical_json);
    Ok(MacosLinuxVzPackageRuntimeQualificationRecordV1 {
        canonical_json,
        record_sha256,
        wire,
    })
}

fn validate_wire_v1(
    wire: &RuntimeQualificationRecordWireV1,
) -> Result<(), MacosLinuxVzPackageRuntimeQualificationRecordErrorV1> {
    let empty = Sha256Digest::from_bytes(&[]);
    let digests = [
        &wire.qualification_request_sha256,
        &wire.qualified_telemetry_backend_sha256,
        &wire.backend_identity_sha256,
        &wire.telemetry_requirements_sha256,
        &wire.conformance_evidence_set_sha256,
        &wire.kernel_image_sha256,
        &wire.qualified_initramfs_sha256,
        &wire.qualified_guest_signer_sha256,
        &wire.qualified_protected_sensor_sha256,
        &wire.guest_evidence_public_key_sha256,
        &wire.host_evidence_public_key_sha256,
        &wire.runtime_qualification_initramfs_sha256,
        &wire.runtime_qualification_guest_agent_sha256,
        &wire.runtime_qualification_guest_init_sha256,
        &wire.runtime_qualification_module_bundle_sha256,
        &wire.candidate_runtime_rootfs_sha256,
        &wire.candidate_runtime_manifest_sha256,
        &wire.candidate_package_runner_sha256,
        &wire.request_challenge_sha256,
        &wire.clone_binding_sha256,
        &wire.request_frame_sha256,
        &wire.response_frame_sha256,
        &wire.expected_probe_report_sha256,
        &wire.observed_probe_report_sha256,
        &wire.process_evidence_sha256,
        &wire.guest_receipt_sha256,
        &wire.host_evidence_sha256,
        &wire.host_receipt_sha256,
    ];
    let valid = wire.schema_version
        == MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_SCHEMA_V1
        && wire.authority == RECORD_AUTHORITY_V1
        && wire.qualification_state
            == MacosLinuxVzPackageRuntimeQualificationStateV1::FixedNonexecutingProbePassed
        && wire.execution_runner_capability
            == MacosLinuxVzPackageExecutionRunnerCapabilityV1::NotQualified
        && !digests.contains(&&empty)
        && wire.expected_probe_report_sha256
            == Sha256Digest::from_bytes(MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1)
        && wire.observed_probe_report_sha256 == wire.expected_probe_report_sha256
        && wire.process_evidence_byte_length != "0"
        && valid_decimal_v1(&wire.candidate_runtime_rootfs_byte_length)
        && wire.candidate_runtime_rootfs_byte_length != "0"
        && valid_decimal_v1(&wire.process_evidence_byte_length)
        && valid_decimal_v1(&wire.package_uid)
        && valid_decimal_v1(&wire.package_gid)
        && wire.event_sequence_start == "1"
        && wire.event_sequence_end == "3"
        && wire.event_count == "3"
        && valid_decimal_v1(&wire.heartbeat_count)
        && wire.heartbeat_count != "0"
        && wire.dropped_event_count == "0"
        && wire.sensor_healthy
        && !wire.evidence_truncated
        && wire.descendant_teardown_complete
        && wire.guest_receipt_verified
        && wire.host_receipt_verified
        && wire.nonexecuting_probe_observed
        && wire.raw_frame_count == "0"
        && wire.external_frames_forwarded == "0"
        && !wire.public_network_route_present
        && wire.vm_stopped
        && wire.clone_destroyed
        && !wire.execution_authority_issuance_permitted
        && !wire.package_execution
        && wire.sync_back_policy == ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent;
    if !valid {
        return Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord);
    }
    Ok(())
}

fn valid_decimal_v1(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value == "0" || !value.starts_with('0'))
        && value.parse::<u64>().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn inert_wire() -> RuntimeQualificationRecordWireV1 {
        RuntimeQualificationRecordWireV1 {
            schema_version: MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_RECORD_SCHEMA_V1
                .to_string(),
            authority: RECORD_AUTHORITY_V1.to_string(),
            qualification_state:
                MacosLinuxVzPackageRuntimeQualificationStateV1::FixedNonexecutingProbePassed,
            execution_runner_capability:
                MacosLinuxVzPackageExecutionRunnerCapabilityV1::NotQualified,
            qualification_request_sha256: digest("request"),
            qualified_telemetry_backend_sha256: digest("qualified backend"),
            backend_identity_sha256: digest("backend identity"),
            telemetry_requirements_sha256: digest("requirements"),
            conformance_evidence_set_sha256: digest("conformance"),
            kernel_image_sha256: digest("kernel"),
            qualified_initramfs_sha256: digest("base initramfs"),
            qualified_guest_signer_sha256: digest("guest signer"),
            qualified_protected_sensor_sha256: digest("sensor"),
            guest_evidence_public_key_sha256: digest("guest public key"),
            host_evidence_public_key_sha256: digest("host public key"),
            runtime_qualification_initramfs_sha256: digest("qualification initramfs"),
            runtime_qualification_guest_agent_sha256: digest("agent"),
            runtime_qualification_guest_init_sha256: digest("init"),
            runtime_qualification_module_bundle_sha256: digest("modules"),
            candidate_runtime_rootfs_sha256: digest("rootfs"),
            candidate_runtime_rootfs_byte_length: "1048576".to_string(),
            candidate_runtime_manifest_sha256: digest("runtime manifest"),
            candidate_package_runner_sha256: digest("runner"),
            request_challenge_sha256: digest("challenge"),
            clone_binding_sha256: digest("clone"),
            request_frame_sha256: digest("request frame"),
            response_frame_sha256: digest("response frame"),
            expected_probe_report_sha256: Sha256Digest::from_bytes(
                MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
            ),
            observed_probe_report_sha256: Sha256Digest::from_bytes(
                MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
            ),
            process_evidence_sha256: digest("process evidence"),
            process_evidence_byte_length: "512".to_string(),
            guest_receipt_sha256: digest("guest receipt"),
            host_evidence_sha256: digest("host evidence"),
            host_receipt_sha256: digest("host receipt"),
            event_sequence_start: "1".to_string(),
            event_sequence_end: "3".to_string(),
            event_count: "3".to_string(),
            heartbeat_count: "1".to_string(),
            dropped_event_count: "0".to_string(),
            package_uid: "65534".to_string(),
            package_gid: "65534".to_string(),
            sensor_healthy: true,
            evidence_truncated: false,
            descendant_teardown_complete: true,
            guest_receipt_verified: true,
            host_receipt_verified: true,
            nonexecuting_probe_observed: true,
            raw_frame_count: "0".to_string(),
            external_frames_forwarded: "0".to_string(),
            public_network_route_present: false,
            vm_stopped: true,
            clone_destroyed: true,
            execution_authority_issuance_permitted: false,
            package_execution: false,
            sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
        }
    }

    #[test]
    fn canonical_record_round_trips_without_granting_execution() {
        let record = build_record_from_wire_v1(inert_wire()).expect("record");
        let decoded = decode_macos_linux_vz_package_runtime_qualification_record_v1(
            record.canonical_json_v1(),
        )
        .expect("decode");
        assert_eq!(decoded, record);
        assert_eq!(
            decoded.qualification_state(),
            MacosLinuxVzPackageRuntimeQualificationStateV1::FixedNonexecutingProbePassed
        );
        assert_eq!(
            decoded.execution_runner_capability(),
            MacosLinuxVzPackageExecutionRunnerCapabilityV1::NotQualified
        );
        assert!(!decoded.execution_authority_issuance_permitted());
        assert!(!decoded.package_execution_permitted());
        assert!(!decoded.sync_back_permitted());
    }

    #[test]
    fn record_rejects_any_execution_or_sync_back_upgrade() {
        let mut wire = inert_wire();
        wire.execution_authority_issuance_permitted = true;
        assert_eq!(
            build_record_from_wire_v1(wire),
            Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)
        );

        let mut wire = inert_wire();
        wire.package_execution = true;
        assert_eq!(
            build_record_from_wire_v1(wire),
            Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)
        );

        let record = build_record_from_wire_v1(inert_wire()).expect("record");
        let mut wire: serde_json::Value =
            serde_json::from_slice(record.canonical_json_v1()).expect("json");
        wire["sync_back_policy"] = serde_json::Value::String("present".to_string());
        let wire = serde_json_canonicalizer::to_vec(&wire).expect("canonical");
        assert_eq!(
            decode_macos_linux_vz_package_runtime_qualification_record_v1(&wire),
            Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)
        );
    }

    #[test]
    fn record_rejects_missing_sensor_and_lifecycle_proof() {
        let mut wire = inert_wire();
        wire.dropped_event_count = "1".to_string();
        assert_eq!(
            build_record_from_wire_v1(wire),
            Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)
        );

        let mut wire = inert_wire();
        wire.clone_destroyed = false;
        assert_eq!(
            build_record_from_wire_v1(wire),
            Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)
        );
    }

    #[test]
    fn record_decoder_rejects_noncanonical_or_unknown_fields() {
        let record = build_record_from_wire_v1(inert_wire()).expect("record");
        let mut noncanonical = b" ".to_vec();
        noncanonical.extend_from_slice(record.canonical_json_v1());
        assert_eq!(
            decode_macos_linux_vz_package_runtime_qualification_record_v1(&noncanonical),
            Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::NonCanonical)
        );

        let mut value: serde_json::Value =
            serde_json::from_slice(record.canonical_json_v1()).expect("json");
        value
            .as_object_mut()
            .expect("object")
            .insert("unexpected".to_string(), serde_json::Value::Bool(true));
        let extra = serde_json_canonicalizer::to_vec(&value).expect("canonical");
        assert_eq!(
            decode_macos_linux_vz_package_runtime_qualification_record_v1(&extra),
            Err(MacosLinuxVzPackageRuntimeQualificationRecordErrorV1::InvalidRecord)
        );
    }
}
