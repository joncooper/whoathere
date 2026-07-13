use crate::{
    LinuxVzTelemetryConformanceObservedTerminalV1, LinuxVzTelemetryGuestObservationClaimsV1,
    MacosLinuxVzPackageRuntimeQualificationRequestV1, MacosLinuxVzTelemetryEvidenceErrorV1,
    MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{ArtifactProtectedTelemetrySensorV1, ArtifactTelemetrySyncBackPolicyV1};
use zeroize::Zeroize;

pub const MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_GUEST_RECEIPT_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_runtime_qualification_guest_receipt.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_GUEST_RECEIPT_BYTES_V1: usize =
    1024 * 1024;
pub const MACOS_LINUX_VZ_PACKAGE_RUNTIME_ROOTFS_UUID_V1: &str =
    "57484F41-5448-4552-5254-554E54494D45";
const RUNTIME_QUALIFICATION_GUEST_RECEIPT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.macos_linux_vz_package_runtime_qualification_guest_receipt.signature.v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1 {
    process: LinuxVzTelemetryGuestObservationClaimsV1,
    observed_probe_report_sha256: Sha256Digest,
    rootfs_block_device_sha256: Sha256Digest,
}

impl MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1 {
    pub fn new(
        request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
        process: LinuxVzTelemetryGuestObservationClaimsV1,
        observed_probe_report: &[u8],
        rootfs_block_device_sha256: Sha256Digest,
    ) -> Result<Self, MacosLinuxVzTelemetryEvidenceErrorV1> {
        let value = Self {
            process,
            observed_probe_report_sha256: Sha256Digest::from_bytes(observed_probe_report),
            rootfs_block_device_sha256,
        };
        value.validate(request)?;
        Ok(value)
    }

    fn validate(
        &self,
        request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    ) -> Result<(), MacosLinuxVzTelemetryEvidenceErrorV1> {
        if !request.fixed_nonexecuting_probe_permitted()
            || request.package_execution_authority_permitted()
            || request.sync_back_permitted()
            || self.observed_probe_report_sha256 != *request.expected_probe_report_sha256()
            || self.observed_probe_report_sha256
                != Sha256Digest::from_bytes(MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1)
            || self.rootfs_block_device_sha256 != *request.candidate_runtime_rootfs_sha256()
            || self.process.observed_terminal()
                != LinuxVzTelemetryConformanceObservedTerminalV1::ObservationComplete
            || !self.process.sensor_healthy()
            || self.process.evidence_truncated()
            || !self.process.descendant_teardown_complete()
            || self.process.dropped_event_count() != 0
            || self.process.event_count() != 3
            || self.process.event_sequence_start() != 1
            || self.process.event_sequence_end() != 3
        {
            return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
        }
        Ok(())
    }

    pub fn process(&self) -> &LinuxVzTelemetryGuestObservationClaimsV1 {
        &self.process
    }

    pub fn observed_probe_report_sha256(&self) -> &Sha256Digest {
        &self.observed_probe_report_sha256
    }

    pub fn rootfs_block_device_sha256(&self) -> &Sha256Digest {
        &self.rootfs_block_device_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedRuntimeQualificationGuestReceiptWireV1 {
    schema_version: String,
    authority: String,
    qualification_request_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    conformance_evidence_set_sha256: Sha256Digest,
    kernel_image_sha256: Sha256Digest,
    qualified_initramfs_sha256: Sha256Digest,
    qualified_guest_signer_sha256: Sha256Digest,
    qualified_protected_sensor_sha256: Sha256Digest,
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
    expected_probe_report_sha256: Sha256Digest,
    observed_probe_report_sha256: Sha256Digest,
    rootfs_block_device: String,
    rootfs_block_device_sha256: Sha256Digest,
    rootfs_filesystem_type: String,
    rootfs_filesystem_uuid: String,
    rootfs_mount_options: Vec<String>,
    package_runner_path: String,
    package_runner_argument: String,
    package_runner_exit_status: String,
    process_evidence_payload_sha256: Sha256Digest,
    process_evidence_byte_length: String,
    event_sequence_start: String,
    event_sequence_end: String,
    event_count: String,
    heartbeat_count: String,
    dropped_event_count: String,
    sensor_healthy: bool,
    evidence_truncated: bool,
    descendant_teardown_complete: bool,
    observed_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    package_uid: String,
    package_gid: String,
    package_capabilities_present: bool,
    public_network_reachable: bool,
    nonexecuting_probe_observed: bool,
    execution_authority_issued: bool,
    package_execution: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeQualificationGuestReceiptWireV1 {
    schema_version: String,
    authority: String,
    qualification_request_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    conformance_evidence_set_sha256: Sha256Digest,
    kernel_image_sha256: Sha256Digest,
    qualified_initramfs_sha256: Sha256Digest,
    qualified_guest_signer_sha256: Sha256Digest,
    qualified_protected_sensor_sha256: Sha256Digest,
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
    expected_probe_report_sha256: Sha256Digest,
    observed_probe_report_sha256: Sha256Digest,
    rootfs_block_device: String,
    rootfs_block_device_sha256: Sha256Digest,
    rootfs_filesystem_type: String,
    rootfs_filesystem_uuid: String,
    rootfs_mount_options: Vec<String>,
    package_runner_path: String,
    package_runner_argument: String,
    package_runner_exit_status: String,
    process_evidence_payload_sha256: Sha256Digest,
    process_evidence_byte_length: String,
    event_sequence_start: String,
    event_sequence_end: String,
    event_count: String,
    heartbeat_count: String,
    dropped_event_count: String,
    sensor_healthy: bool,
    evidence_truncated: bool,
    descendant_teardown_complete: bool,
    observed_sensors: Vec<ArtifactProtectedTelemetrySensorV1>,
    package_uid: String,
    package_gid: String,
    package_capabilities_present: bool,
    public_network_reachable: bool,
    nonexecuting_probe_observed: bool,
    execution_authority_issued: bool,
    package_execution: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
    signature_ed25519_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMacosLinuxVzPackageRuntimeQualificationGuestReceiptV1 {
    qualification_request_sha256: Sha256Digest,
    claims: MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
}

impl VerifiedMacosLinuxVzPackageRuntimeQualificationGuestReceiptV1 {
    pub fn qualification_request_sha256(&self) -> &Sha256Digest {
        &self.qualification_request_sha256
    }

    pub fn claims(&self) -> &MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1 {
        &self.claims
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn sign_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    claims: &MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
    mut signing_seed: [u8; 32],
) -> Result<Vec<u8>, MacosLinuxVzTelemetryEvidenceErrorV1> {
    claims.validate(request)?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    if Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes())
        != *request.guest_evidence_public_key_sha256()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }
    let unsigned = unsigned_receipt_v1(request, claims);
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    let signature = signing_key.sign(&signature_message_v1(
        request.canonical_json_v1(),
        &unsigned_bytes,
    ));
    let receipt = RuntimeQualificationGuestReceiptWireV1::from_unsigned(
        unsigned,
        lower_hex_v1(&signature.to_bytes()),
    );
    let bytes = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    if bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_GUEST_RECEIPT_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::LimitExceeded);
    }
    Ok(bytes)
}

pub fn verify_macos_linux_vz_package_runtime_qualification_guest_receipt_v1(
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    receipt_bytes: &[u8],
    verifying_key_bytes: [u8; 32],
    expected_claims: &MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
) -> Result<
    VerifiedMacosLinuxVzPackageRuntimeQualificationGuestReceiptV1,
    MacosLinuxVzTelemetryEvidenceErrorV1,
> {
    expected_claims.validate(request)?;
    if receipt_bytes.is_empty() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::Empty);
    }
    if receipt_bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_GUEST_RECEIPT_BYTES_V1
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::LimitExceeded);
    }
    if Sha256Digest::from_bytes(&verifying_key_bytes) != *request.guest_evidence_public_key_sha256()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch)?;
    if verifying_key.is_weak() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::PublicKeyMismatch);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(receipt_bytes);
    let receipt = RuntimeQualificationGuestReceiptWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt)?;
    let canonical = serde_json_canonicalizer::to_vec(&receipt)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    if canonical != receipt_bytes || !valid_signature_hex_v1(&receipt.signature_ed25519_hex) {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::NonCanonical);
    }
    let signature_hex = receipt.signature_ed25519_hex.clone();
    let unsigned = receipt.into_unsigned();
    let expected = unsigned_receipt_v1(request, expected_claims);
    if unsigned != expected {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    let signature = Signature::from_bytes(&decode_signature_v1(&signature_hex)?);
    verifying_key
        .verify_strict(
            &signature_message_v1(request.canonical_json_v1(), &unsigned_bytes),
            &signature,
        )
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::SignatureFailed)?;
    Ok(
        VerifiedMacosLinuxVzPackageRuntimeQualificationGuestReceiptV1 {
            qualification_request_sha256: request.request_sha256().clone(),
            claims: expected_claims.clone(),
        },
    )
}

fn observed_sensors_v1() -> Vec<ArtifactProtectedTelemetrySensorV1> {
    vec![
        ArtifactProtectedTelemetrySensorV1::ProcessForkExecExit,
        ArtifactProtectedTelemetrySensorV1::ProcessCredentials,
        ArtifactProtectedTelemetrySensorV1::DescendantTeardown,
        ArtifactProtectedTelemetrySensorV1::SensorHealthHeartbeat,
        ArtifactProtectedTelemetrySensorV1::DroppedEventAccounting,
    ]
}

fn unsigned_receipt_v1(
    request: &MacosLinuxVzPackageRuntimeQualificationRequestV1,
    claims: &MacosLinuxVzPackageRuntimeQualificationGuestClaimsV1,
) -> UnsignedRuntimeQualificationGuestReceiptWireV1 {
    let process = claims.process();
    UnsignedRuntimeQualificationGuestReceiptWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_GUEST_RECEIPT_SCHEMA_V1
            .to_string(),
        authority: "guest_protected_runtime_qualification".to_string(),
        qualification_request_sha256: request.request_sha256().clone(),
        qualified_telemetry_backend_sha256: request.qualified_telemetry_backend_sha256().clone(),
        backend_identity_sha256: request.backend_identity_sha256().clone(),
        telemetry_requirements_sha256: request.telemetry_requirements_sha256().clone(),
        conformance_evidence_set_sha256: request.conformance_evidence_set_sha256().clone(),
        kernel_image_sha256: request.kernel_image_sha256().clone(),
        qualified_initramfs_sha256: request.qualified_initramfs_sha256().clone(),
        qualified_guest_signer_sha256: request.qualified_guest_signer_sha256().clone(),
        qualified_protected_sensor_sha256: request.qualified_protected_sensor_sha256().clone(),
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
        expected_probe_report_sha256: request.expected_probe_report_sha256().clone(),
        observed_probe_report_sha256: claims.observed_probe_report_sha256().clone(),
        rootfs_block_device: "/dev/vda".to_string(),
        rootfs_block_device_sha256: claims.rootfs_block_device_sha256().clone(),
        rootfs_filesystem_type: "ext2".to_string(),
        rootfs_filesystem_uuid: MACOS_LINUX_VZ_PACKAGE_RUNTIME_ROOTFS_UUID_V1.to_string(),
        rootfs_mount_options: vec!["nodev".to_string(), "nosuid".to_string(), "ro".to_string()],
        package_runner_path: "/runtime/whoathere/package-runtime-probe".to_string(),
        package_runner_argument: "fork_exec_exit".to_string(),
        package_runner_exit_status: "0".to_string(),
        process_evidence_payload_sha256: process.evidence_payload_sha256().clone(),
        process_evidence_byte_length: process.evidence_byte_length().to_string(),
        event_sequence_start: process.event_sequence_start().to_string(),
        event_sequence_end: process.event_sequence_end().to_string(),
        event_count: process.event_count().to_string(),
        heartbeat_count: process.heartbeat_count().to_string(),
        dropped_event_count: process.dropped_event_count().to_string(),
        sensor_healthy: process.sensor_healthy(),
        evidence_truncated: process.evidence_truncated(),
        descendant_teardown_complete: process.descendant_teardown_complete(),
        observed_sensors: observed_sensors_v1(),
        package_uid: request.package_uid().to_string(),
        package_gid: request.package_gid().to_string(),
        package_capabilities_present: false,
        public_network_reachable: false,
        nonexecuting_probe_observed: true,
        execution_authority_issued: false,
        package_execution: false,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    }
}

impl RuntimeQualificationGuestReceiptWireV1 {
    fn from_unsigned(
        value: UnsignedRuntimeQualificationGuestReceiptWireV1,
        signature_ed25519_hex: String,
    ) -> Self {
        Self {
            schema_version: value.schema_version,
            authority: value.authority,
            qualification_request_sha256: value.qualification_request_sha256,
            qualified_telemetry_backend_sha256: value.qualified_telemetry_backend_sha256,
            backend_identity_sha256: value.backend_identity_sha256,
            telemetry_requirements_sha256: value.telemetry_requirements_sha256,
            conformance_evidence_set_sha256: value.conformance_evidence_set_sha256,
            kernel_image_sha256: value.kernel_image_sha256,
            qualified_initramfs_sha256: value.qualified_initramfs_sha256,
            qualified_guest_signer_sha256: value.qualified_guest_signer_sha256,
            qualified_protected_sensor_sha256: value.qualified_protected_sensor_sha256,
            runtime_qualification_initramfs_sha256: value.runtime_qualification_initramfs_sha256,
            runtime_qualification_guest_agent_sha256: value
                .runtime_qualification_guest_agent_sha256,
            runtime_qualification_guest_init_sha256: value.runtime_qualification_guest_init_sha256,
            runtime_qualification_module_bundle_sha256: value
                .runtime_qualification_module_bundle_sha256,
            candidate_runtime_rootfs_sha256: value.candidate_runtime_rootfs_sha256,
            candidate_runtime_rootfs_byte_length: value.candidate_runtime_rootfs_byte_length,
            candidate_runtime_manifest_sha256: value.candidate_runtime_manifest_sha256,
            candidate_package_runner_sha256: value.candidate_package_runner_sha256,
            request_challenge_sha256: value.request_challenge_sha256,
            clone_binding_sha256: value.clone_binding_sha256,
            expected_probe_report_sha256: value.expected_probe_report_sha256,
            observed_probe_report_sha256: value.observed_probe_report_sha256,
            rootfs_block_device: value.rootfs_block_device,
            rootfs_block_device_sha256: value.rootfs_block_device_sha256,
            rootfs_filesystem_type: value.rootfs_filesystem_type,
            rootfs_filesystem_uuid: value.rootfs_filesystem_uuid,
            rootfs_mount_options: value.rootfs_mount_options,
            package_runner_path: value.package_runner_path,
            package_runner_argument: value.package_runner_argument,
            package_runner_exit_status: value.package_runner_exit_status,
            process_evidence_payload_sha256: value.process_evidence_payload_sha256,
            process_evidence_byte_length: value.process_evidence_byte_length,
            event_sequence_start: value.event_sequence_start,
            event_sequence_end: value.event_sequence_end,
            event_count: value.event_count,
            heartbeat_count: value.heartbeat_count,
            dropped_event_count: value.dropped_event_count,
            sensor_healthy: value.sensor_healthy,
            evidence_truncated: value.evidence_truncated,
            descendant_teardown_complete: value.descendant_teardown_complete,
            observed_sensors: value.observed_sensors,
            package_uid: value.package_uid,
            package_gid: value.package_gid,
            package_capabilities_present: value.package_capabilities_present,
            public_network_reachable: value.public_network_reachable,
            nonexecuting_probe_observed: value.nonexecuting_probe_observed,
            execution_authority_issued: value.execution_authority_issued,
            package_execution: value.package_execution,
            sync_back_policy: value.sync_back_policy,
            signature_ed25519_hex,
        }
    }

    fn into_unsigned(self) -> UnsignedRuntimeQualificationGuestReceiptWireV1 {
        UnsignedRuntimeQualificationGuestReceiptWireV1 {
            schema_version: self.schema_version,
            authority: self.authority,
            qualification_request_sha256: self.qualification_request_sha256,
            qualified_telemetry_backend_sha256: self.qualified_telemetry_backend_sha256,
            backend_identity_sha256: self.backend_identity_sha256,
            telemetry_requirements_sha256: self.telemetry_requirements_sha256,
            conformance_evidence_set_sha256: self.conformance_evidence_set_sha256,
            kernel_image_sha256: self.kernel_image_sha256,
            qualified_initramfs_sha256: self.qualified_initramfs_sha256,
            qualified_guest_signer_sha256: self.qualified_guest_signer_sha256,
            qualified_protected_sensor_sha256: self.qualified_protected_sensor_sha256,
            runtime_qualification_initramfs_sha256: self.runtime_qualification_initramfs_sha256,
            runtime_qualification_guest_agent_sha256: self.runtime_qualification_guest_agent_sha256,
            runtime_qualification_guest_init_sha256: self.runtime_qualification_guest_init_sha256,
            runtime_qualification_module_bundle_sha256: self
                .runtime_qualification_module_bundle_sha256,
            candidate_runtime_rootfs_sha256: self.candidate_runtime_rootfs_sha256,
            candidate_runtime_rootfs_byte_length: self.candidate_runtime_rootfs_byte_length,
            candidate_runtime_manifest_sha256: self.candidate_runtime_manifest_sha256,
            candidate_package_runner_sha256: self.candidate_package_runner_sha256,
            request_challenge_sha256: self.request_challenge_sha256,
            clone_binding_sha256: self.clone_binding_sha256,
            expected_probe_report_sha256: self.expected_probe_report_sha256,
            observed_probe_report_sha256: self.observed_probe_report_sha256,
            rootfs_block_device: self.rootfs_block_device,
            rootfs_block_device_sha256: self.rootfs_block_device_sha256,
            rootfs_filesystem_type: self.rootfs_filesystem_type,
            rootfs_filesystem_uuid: self.rootfs_filesystem_uuid,
            rootfs_mount_options: self.rootfs_mount_options,
            package_runner_path: self.package_runner_path,
            package_runner_argument: self.package_runner_argument,
            package_runner_exit_status: self.package_runner_exit_status,
            process_evidence_payload_sha256: self.process_evidence_payload_sha256,
            process_evidence_byte_length: self.process_evidence_byte_length,
            event_sequence_start: self.event_sequence_start,
            event_sequence_end: self.event_sequence_end,
            event_count: self.event_count,
            heartbeat_count: self.heartbeat_count,
            dropped_event_count: self.dropped_event_count,
            sensor_healthy: self.sensor_healthy,
            evidence_truncated: self.evidence_truncated,
            descendant_teardown_complete: self.descendant_teardown_complete,
            observed_sensors: self.observed_sensors,
            package_uid: self.package_uid,
            package_gid: self.package_gid,
            package_capabilities_present: self.package_capabilities_present,
            public_network_reachable: self.public_network_reachable,
            nonexecuting_probe_observed: self.nonexecuting_probe_observed,
            execution_authority_issued: self.execution_authority_issued,
            package_execution: self.package_execution,
            sync_back_policy: self.sync_back_policy,
        }
    }
}

fn signature_message_v1(request: &[u8], unsigned_receipt: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        RUNTIME_QUALIFICATION_GUEST_RECEIPT_SIGNATURE_DOMAIN_V1.len()
            + 16
            + request.len()
            + unsigned_receipt.len(),
    );
    message.extend_from_slice(RUNTIME_QUALIFICATION_GUEST_RECEIPT_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(&(request.len() as u64).to_be_bytes());
    message.extend_from_slice(request);
    message.extend_from_slice(&(unsigned_receipt.len() as u64).to_be_bytes());
    message.extend_from_slice(unsigned_receipt);
    message
}

fn lower_hex_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn valid_signature_hex_v1(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_signature_v1(value: &str) -> Result<[u8; 64], MacosLinuxVzTelemetryEvidenceErrorV1> {
    if !valid_signature_hex_v1(value) {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt);
    }
    let mut output = [0_u8; 64];
    let bytes = value.as_bytes();
    for index in 0..64 {
        output[index] =
            (hex_nibble_v1(bytes[index * 2])? << 4) | hex_nibble_v1(bytes[index * 2 + 1])?;
    }
    Ok(output)
}

fn hex_nibble_v1(value: u8) -> Result<u8, MacosLinuxVzTelemetryEvidenceErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidReceipt),
    }
}
