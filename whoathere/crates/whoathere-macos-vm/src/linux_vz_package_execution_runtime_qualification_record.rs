use crate::{
    decode_linux_vz_package_execution_runtime_qualification_probe_v1,
    QualifiedMacosLinuxVzTelemetryBackendV1,
    VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactTelemetrySyncBackPolicyV1;
use zeroize::Zeroize;

pub const MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_execution_runtime_qualification_record.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1: usize =
    256 * 1024;

const RECORD_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.macos_linux_vz_package_execution_runtime_qualification_record.signature.v1\0";
const EXECUTION_RUNTIME_MANIFEST_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_execution_runtime_manifest.v1";
const QUALIFICATION_IMAGE_MANIFEST_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_execution_runtime_rootfs_qualification_image_manifest.v1";
const PHYSICAL_BOOT_RESULT_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_execution_runtime_rootfs_qualification_boot_result.v1";
const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ExecutionRuntimeQualificationStateV1 {
    PhysicalReadOnlyRuntimeQualificationVerified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRuntimeManifestWireV1 {
    alpine_release: String,
    architecture: String,
    builder_source_sha256: Sha256Digest,
    candidate_runtime_qualification: String,
    cargo_lock_sha256: Sha256Digest,
    container_builder_source_sha256: Sha256Digest,
    external_network: String,
    image_state: String,
    node_executable_sha256: Sha256Digest,
    node_version: String,
    npm_cli_sha256: Sha256Digest,
    npm_version: String,
    package_execution: bool,
    package_execution_authority: String,
    package_gid: String,
    package_runner_byte_length: String,
    package_runner_mode: String,
    package_runner_path: String,
    package_runner_sha256: Sha256Digest,
    package_uid: String,
    pip_entrypoint_sha256: Sha256Digest,
    pip_version: String,
    python_executable_sha256: Sha256Digest,
    python_version: String,
    reproducible_epoch: String,
    rootfs_byte_length: String,
    rootfs_format: String,
    rootfs_sha256: Sha256Digest,
    rootfs_tar_byte_length: String,
    rootfs_tar_sha256: Sha256Digest,
    rootfs_uuid: String,
    runtime_common_source_sha256: Sha256Digest,
    runtime_container_arm64_image_id: Sha256Digest,
    runtime_container_digest: Sha256Digest,
    runtime_inputs_lock_sha256: Sha256Digest,
    runtime_source_closure_sha256: Sha256Digest,
    schema_version: String,
    source_minirootfs_sha256: Sha256Digest,
    sync_back: bool,
    workspace_manifest_sha256: Sha256Digest,
}

impl ExecutionRuntimeManifestWireV1 {
    fn validate_v1(&self) -> Result<(), ExecutionRuntimeQualificationRecordErrorV1> {
        let rootfs_length = canonical_positive_u64_v1(&self.rootfs_byte_length)?;
        let rootfs_tar_length = canonical_positive_u64_v1(&self.rootfs_tar_byte_length)?;
        let runner_length = canonical_positive_u64_v1(&self.package_runner_byte_length)?;
        let empty = Sha256Digest::from_bytes(&[]);
        let independently_measured = [
            &self.rootfs_sha256,
            &self.rootfs_tar_sha256,
            &self.package_runner_sha256,
            &self.node_executable_sha256,
            &self.npm_cli_sha256,
            &self.python_executable_sha256,
            &self.pip_entrypoint_sha256,
        ];
        let all_manifest_digests = [
            &self.builder_source_sha256,
            &self.cargo_lock_sha256,
            &self.container_builder_source_sha256,
            &self.node_executable_sha256,
            &self.npm_cli_sha256,
            &self.package_runner_sha256,
            &self.pip_entrypoint_sha256,
            &self.python_executable_sha256,
            &self.rootfs_sha256,
            &self.rootfs_tar_sha256,
            &self.runtime_container_arm64_image_id,
            &self.runtime_container_digest,
            &self.runtime_common_source_sha256,
            &self.runtime_inputs_lock_sha256,
            &self.runtime_source_closure_sha256,
            &self.source_minirootfs_sha256,
            &self.workspace_manifest_sha256,
        ];
        if self.schema_version != EXECUTION_RUNTIME_MANIFEST_SCHEMA_V1
            || self.alpine_release != "3.24.1"
            || self.architecture != "aarch64"
            || self.candidate_runtime_qualification != "required"
            || self.external_network != "structurally_absent"
            || self.image_state != "candidate_exact_bytes_not_yet_execution_qualified"
            || self.node_version != "v24.17.0"
            || self.npm_version != "11.12.1"
            || self.python_version != "3.14.5"
            || self.pip_version != "26.1.2"
            || self.package_execution
            || self.package_execution_authority
                != "structurally_unavailable_until_verified_qualification_and_signed_one_use_grant"
            || self.package_gid != PACKAGE_GID_V1.to_string()
            || self.package_runner_mode != "fixed_root_coordinator_authenticated_evidence_v1"
            || self.package_runner_path != "/whoathere/package-root-runtime"
            || self.package_uid != PACKAGE_UID_V1.to_string()
            || self.reproducible_epoch != "1783900800"
            || self.rootfs_format != "raw_ext2_block_image_v1"
            || self.rootfs_uuid != "57484f41-5448-4552-5254-554e54494d45"
            || self.runtime_container_arm64_image_id
                != parsed_digest_v1(
                    "sha256:1991bd789d7184290c3cce84fd6af068b8b745e9bddf178661ce7f5ecf68135c",
                )?
            || self.runtime_container_digest
                != parsed_digest_v1(
                    "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
                )?
            || self.source_minirootfs_sha256
                != parsed_digest_v1(
                    "sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
                )?
            || self.sync_back
            || rootfs_length > 64 * 1024 * 1024 * 1024
            || rootfs_tar_length > 64 * 1024 * 1024 * 1024
            || runner_length > 64 * 1024 * 1024
            || all_manifest_digests.contains(&&empty)
            || independently_measured.contains(&&empty)
            || independently_measured
                .iter()
                .enumerate()
                .any(|(index, digest)| independently_measured[..index].contains(digest))
        {
            return Err(ExecutionRuntimeQualificationRecordErrorV1::RuntimeManifestInvalid);
        }
        Ok(())
    }

    fn rootfs_byte_length_v1(&self) -> u64 {
        self.rootfs_byte_length
            .parse()
            .expect("validated rootfs byte length")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRuntimeQualificationImageManifestWireV1 {
    architecture: String,
    base_initramfs_sha256: Sha256Digest,
    builder_source_sha256: Sha256Digest,
    candidate_runtime_manifest_sha256: Sha256Digest,
    candidate_runtime_rootfs_byte_length: String,
    candidate_runtime_rootfs_sha256: Sha256Digest,
    execution_authority_issued: bool,
    external_network: String,
    guest_evidence_public_key_sha256: Sha256Digest,
    node_executable_sha256: Sha256Digest,
    npm_cli_sha256: Sha256Digest,
    package_execution: bool,
    package_execution_runtime_sha256: Sha256Digest,
    pip_entrypoint_sha256: Sha256Digest,
    python_executable_sha256: Sha256Digest,
    qualification_init_sha256: Sha256Digest,
    qualification_init_source_sha256: Sha256Digest,
    qualification_initramfs_sha256: Sha256Digest,
    qualification_operation: String,
    qualification_overlay_cpio_gzip_sha256: Sha256Digest,
    qualification_overlay_cpio_sha256: Sha256Digest,
    rootfs_attachment: String,
    schema_version: String,
    sync_back: bool,
    writer_source_sha256: Sha256Digest,
}

impl ExecutionRuntimeQualificationImageManifestWireV1 {
    fn validate_v1(
        &self,
        runtime: &ExecutionRuntimeManifestWireV1,
        runtime_manifest_source_sha256: &Sha256Digest,
        guest_evidence_public_key_sha256: &Sha256Digest,
    ) -> Result<(), ExecutionRuntimeQualificationRecordErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let image_components = [
            &self.base_initramfs_sha256,
            &self.builder_source_sha256,
            &self.qualification_init_sha256,
            &self.qualification_init_source_sha256,
            &self.qualification_initramfs_sha256,
            &self.qualification_overlay_cpio_gzip_sha256,
            &self.qualification_overlay_cpio_sha256,
            &self.writer_source_sha256,
        ];
        if self.schema_version != QUALIFICATION_IMAGE_MANIFEST_SCHEMA_V1
            || self.architecture != "aarch64"
            || self.qualification_operation
                != "fixed_root_coordinator_custody_probe_from_exact_read_only_rootfs"
            || self.rootfs_attachment != "virtio_block_read_only"
            || self.external_network != "host_raw_frame_sinkhole_no_external_route"
            || self.execution_authority_issued
            || self.package_execution
            || self.sync_back
            || self.candidate_runtime_manifest_sha256 != *runtime_manifest_source_sha256
            || self.candidate_runtime_rootfs_sha256 != runtime.rootfs_sha256
            || canonical_positive_u64_v1(&self.candidate_runtime_rootfs_byte_length)?
                != runtime.rootfs_byte_length_v1()
            || self.package_execution_runtime_sha256 != runtime.package_runner_sha256
            || self.node_executable_sha256 != runtime.node_executable_sha256
            || self.npm_cli_sha256 != runtime.npm_cli_sha256
            || self.python_executable_sha256 != runtime.python_executable_sha256
            || self.pip_entrypoint_sha256 != runtime.pip_entrypoint_sha256
            || self.guest_evidence_public_key_sha256 != *guest_evidence_public_key_sha256
            || image_components.contains(&&empty)
            || image_components
                .iter()
                .enumerate()
                .any(|(index, digest)| image_components[..index].contains(digest))
        {
            return Err(ExecutionRuntimeQualificationRecordErrorV1::ImageManifestInvalid);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PhysicalQualificationBootResultWireV1 {
    directory_share_count: String,
    evidence_byte_length: String,
    evidence_payload_sha256: Sha256Digest,
    evidence_valid: bool,
    execution_authority_issued: bool,
    execution_grant_consumed: bool,
    execution_request_consumed: bool,
    exit_code: i64,
    external_route: bool,
    failure_marker_present: bool,
    guest_evidence_public_key_sha256: Sha256Digest,
    image_identity_stable: bool,
    initramfs_sha256: Sha256Digest,
    kernel_command_line: String,
    kernel_sha256: Sha256Digest,
    malware_execution: bool,
    missing_required_markers: Vec<String>,
    network_topology: String,
    node_executable_sha256: Sha256Digest,
    npm_cli_sha256: Sha256Digest,
    operation: String,
    package_execution: bool,
    packet_sensor_healthy: bool,
    packet_sensor_terminal: String,
    pip_entrypoint_sha256: Sha256Digest,
    python_executable_sha256: Sha256Digest,
    raw_frame_count: u64,
    raw_frame_dropped_count: u64,
    raw_frame_retained_count: u64,
    raw_frame_truncated_count: u64,
    required_marker_count: u64,
    root_disk_present: bool,
    root_disk_read_only: bool,
    rootfs_identity_stable: bool,
    runner_ambient_capabilities: String,
    runner_bounding_capabilities: String,
    runner_effective_capabilities: String,
    runner_inheritable_capabilities: String,
    runner_open_descriptor_count: String,
    runner_permitted_capabilities: String,
    runner_pid: String,
    runner_thread_count: String,
    runtime_manifest_identity_stable: bool,
    runtime_manifest_sha256: Sha256Digest,
    runtime_qualification_image_manifest_identity_stable: bool,
    runtime_qualification_image_manifest_sha256: Sha256Digest,
    runtime_rootfs_byte_length: String,
    runtime_rootfs_sha256: Sha256Digest,
    runtime_sha256: Sha256Digest,
    schema_version: String,
    service_pid: String,
    status: String,
    storage_device_count: String,
    sync_back: bool,
    virtualization_supported: bool,
    vm_stopped: bool,
    writable_storage_device_count: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRuntimeQualificationClaimsWireV1 {
    qualification_state: ExecutionRuntimeQualificationStateV1,
    qualification_authority: String,
    qualified_telemetry_backend_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    conformance_evidence_set_sha256: Sha256Digest,
    runtime_manifest_source_sha256: Sha256Digest,
    runtime_manifest: ExecutionRuntimeManifestWireV1,
    qualification_image_manifest_source_sha256: Sha256Digest,
    qualification_image_manifest: ExecutionRuntimeQualificationImageManifestWireV1,
    physical_host_boot_result_source_sha256: Sha256Digest,
    physical_host_boot_result: PhysicalQualificationBootResultWireV1,
    guest_probe_evidence_sha256: Sha256Digest,
    guest_probe_evidence: serde_json::Value,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    execution_grant_issuer_public_key_sha256: Sha256Digest,
    package_uid: String,
    package_gid: String,
    package_execution_scope: String,
    execution_authority_issuance_permitted: bool,
    package_execution_during_qualification: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedExecutionRuntimeQualificationRecordWireV1 {
    schema_version: String,
    signed_claims: ExecutionRuntimeQualificationClaimsWireV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRuntimeQualificationRecordWireV1 {
    schema_version: String,
    signed_claims: ExecutionRuntimeQualificationClaimsWireV1,
    signature_ed25519_hex: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageExecutionRuntimeQualificationRecordV1 {
    canonical_json: Vec<u8>,
    record_sha256: Sha256Digest,
}

impl fmt::Debug for MacosLinuxVzPackageExecutionRuntimeQualificationRecordV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionRuntimeQualificationRecordV1")
            .field("record_sha256", &self.record_sha256)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosLinuxVzPackageExecutionRuntimeQualificationRecordV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn record_sha256(&self) -> &Sha256Digest {
        &self.record_sha256
    }

    pub const fn execution_authority_issuance_permitted(&self) -> bool {
        true
    }

    pub const fn package_execution_during_qualification(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionRuntimeQualificationRecordErrorV1 {
    Empty,
    LimitExceeded,
    InvalidRecord,
    NonCanonical,
    Serialization,
    RuntimeManifestInvalid,
    ImageManifestInvalid,
    HostResultInvalid,
    ProbeEvidenceInvalid,
    BackendBindingMismatch,
    KeyInvalid,
    SignatureInvalid,
    BindingMismatch,
    QualificationInvalid,
}

impl ExecutionRuntimeQualificationRecordErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "macos_linux_vz_execution_runtime_qualification_record_empty",
            Self::LimitExceeded => {
                "macos_linux_vz_execution_runtime_qualification_record_limit_exceeded"
            }
            Self::InvalidRecord => "macos_linux_vz_execution_runtime_qualification_record_invalid",
            Self::NonCanonical => {
                "macos_linux_vz_execution_runtime_qualification_record_noncanonical"
            }
            Self::Serialization => {
                "macos_linux_vz_execution_runtime_qualification_record_serialization_failed"
            }
            Self::RuntimeManifestInvalid => {
                "macos_linux_vz_execution_runtime_qualification_manifest_invalid"
            }
            Self::ImageManifestInvalid => {
                "macos_linux_vz_execution_runtime_qualification_image_manifest_invalid"
            }
            Self::HostResultInvalid => {
                "macos_linux_vz_execution_runtime_qualification_host_result_invalid"
            }
            Self::ProbeEvidenceInvalid => {
                "macos_linux_vz_execution_runtime_qualification_probe_invalid"
            }
            Self::BackendBindingMismatch => {
                "macos_linux_vz_execution_runtime_qualification_backend_mismatch"
            }
            Self::KeyInvalid => "macos_linux_vz_execution_runtime_qualification_key_invalid",
            Self::SignatureInvalid => {
                "macos_linux_vz_execution_runtime_qualification_signature_invalid"
            }
            Self::BindingMismatch => {
                "macos_linux_vz_execution_runtime_qualification_binding_mismatch"
            }
            Self::QualificationInvalid => "macos_linux_vz_execution_runtime_qualification_invalid",
        }
    }
}

impl fmt::Display for ExecutionRuntimeQualificationRecordErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ExecutionRuntimeQualificationRecordErrorV1 {}

#[allow(clippy::too_many_arguments)]
pub fn build_macos_linux_vz_package_execution_runtime_qualification_record_v1(
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    runtime_manifest_bytes: &[u8],
    qualification_image_manifest_bytes: &[u8],
    physical_host_boot_result_bytes: &[u8],
    guest_probe_evidence_bytes: &[u8],
    guest_evidence_public_key: [u8; 32],
    mut host_evidence_signing_seed: [u8; 32],
    execution_grant_issuer_public_key: [u8; 32],
) -> Result<
    MacosLinuxVzPackageExecutionRuntimeQualificationRecordV1,
    ExecutionRuntimeQualificationRecordErrorV1,
> {
    let signing_key = SigningKey::from_bytes(&host_evidence_signing_seed);
    host_evidence_signing_seed.zeroize();
    let host_evidence_public_key = signing_key.verifying_key().to_bytes();
    validate_public_keys_v1(
        &guest_evidence_public_key,
        &host_evidence_public_key,
        &execution_grant_issuer_public_key,
    )?;

    let runtime_manifest: ExecutionRuntimeManifestWireV1 =
        decode_canonical_newline_json_v1(runtime_manifest_bytes)?;
    runtime_manifest.validate_v1()?;
    let runtime_manifest_source_sha256 = Sha256Digest::from_bytes(runtime_manifest_bytes);
    let qualification_image_manifest: ExecutionRuntimeQualificationImageManifestWireV1 =
        decode_canonical_newline_json_v1(qualification_image_manifest_bytes)?;
    let qualification_image_manifest_source_sha256 =
        Sha256Digest::from_bytes(qualification_image_manifest_bytes);
    let physical_host_boot_result: PhysicalQualificationBootResultWireV1 =
        decode_canonical_newline_json_v1(physical_host_boot_result_bytes)?;
    let physical_host_boot_result_source_sha256 =
        Sha256Digest::from_bytes(physical_host_boot_result_bytes);
    let guest_key_sha256 = Sha256Digest::from_bytes(&guest_evidence_public_key);
    let host_key_sha256 = Sha256Digest::from_bytes(&host_evidence_public_key);
    let grant_key_sha256 = Sha256Digest::from_bytes(&execution_grant_issuer_public_key);
    qualification_image_manifest.validate_v1(
        &runtime_manifest,
        &runtime_manifest_source_sha256,
        &guest_key_sha256,
    )?;
    let probe = decode_linux_vz_package_execution_runtime_qualification_probe_v1(
        guest_probe_evidence_bytes,
        &runtime_manifest.package_runner_sha256,
        &guest_key_sha256,
    )
    .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::ProbeEvidenceInvalid)?;
    let guest_probe_evidence = serde_json::from_slice(guest_probe_evidence_bytes)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::ProbeEvidenceInvalid)?;

    let claims = ExecutionRuntimeQualificationClaimsWireV1 {
        qualification_state:
            ExecutionRuntimeQualificationStateV1::PhysicalReadOnlyRuntimeQualificationVerified,
        qualification_authority: "qualified_backend_host_evidence_key".to_string(),
        qualified_telemetry_backend_sha256: qualified_backend.qualified_backend_sha256().clone(),
        backend_identity_sha256: qualified_backend.backend_identity_sha256().clone(),
        telemetry_requirements_sha256: qualified_backend.telemetry_requirements_sha256().clone(),
        conformance_evidence_set_sha256: qualified_backend
            .conformance_evidence_set_sha256()
            .clone(),
        runtime_manifest_source_sha256,
        runtime_manifest,
        qualification_image_manifest_source_sha256,
        qualification_image_manifest,
        physical_host_boot_result_source_sha256,
        physical_host_boot_result,
        guest_probe_evidence_sha256: probe.evidence_sha256().clone(),
        guest_probe_evidence,
        guest_evidence_public_key_sha256: guest_key_sha256,
        host_evidence_public_key_sha256: host_key_sha256,
        execution_grant_issuer_public_key_sha256: grant_key_sha256,
        package_uid: PACKAGE_UID_V1.to_string(),
        package_gid: PACKAGE_GID_V1.to_string(),
        package_execution_scope: "one_typed_scenario_one_attempt".to_string(),
        execution_authority_issuance_permitted: true,
        package_execution_during_qualification: false,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    };
    validate_claims_v1(
        &claims,
        qualified_backend,
        &guest_evidence_public_key,
        &host_evidence_public_key,
        &execution_grant_issuer_public_key,
    )?;
    let unsigned = UnsignedExecutionRuntimeQualificationRecordWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_SCHEMA_V1
            .to_string(),
        signed_claims: claims.clone(),
    };
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::Serialization)?;
    let signature = signing_key.sign(&signature_message_v1(&unsigned_bytes));
    drop(signing_key);
    let wire = ExecutionRuntimeQualificationRecordWireV1 {
        schema_version: unsigned.schema_version,
        signed_claims: claims,
        signature_ed25519_hex: lower_hex_v1(&signature.to_bytes()),
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len()
            > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::LimitExceeded);
    }
    let (record, _) = decode_and_verify_record_v1(
        &canonical_json,
        qualified_backend,
        &guest_evidence_public_key,
        &host_evidence_public_key,
        &execution_grant_issuer_public_key,
    )?;
    Ok(record)
}

pub fn verify_macos_linux_vz_package_execution_runtime_qualification_record_v1(
    record_bytes: &[u8],
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    guest_evidence_public_key: [u8; 32],
    host_evidence_public_key: [u8; 32],
    execution_grant_issuer_public_key: [u8; 32],
) -> Result<
    VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1,
    ExecutionRuntimeQualificationRecordErrorV1,
> {
    let (_, qualification) = decode_and_verify_record_v1(
        record_bytes,
        qualified_backend,
        &guest_evidence_public_key,
        &host_evidence_public_key,
        &execution_grant_issuer_public_key,
    )?;
    Ok(qualification)
}

fn decode_and_verify_record_v1(
    record_bytes: &[u8],
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    guest_evidence_public_key: &[u8; 32],
    host_evidence_public_key: &[u8; 32],
    execution_grant_issuer_public_key: &[u8; 32],
) -> Result<
    (
        MacosLinuxVzPackageExecutionRuntimeQualificationRecordV1,
        VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1,
    ),
    ExecutionRuntimeQualificationRecordErrorV1,
> {
    if record_bytes.is_empty() {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::Empty);
    }
    if record_bytes.len()
        > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_BYTES_V1
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::LimitExceeded);
    }
    validate_public_keys_v1(
        guest_evidence_public_key,
        host_evidence_public_key,
        execution_grant_issuer_public_key,
    )?;
    let wire: ExecutionRuntimeQualificationRecordWireV1 = decode_canonical_json_v1(record_bytes)?;
    if wire.schema_version
        != MACOS_LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_RECORD_SCHEMA_V1
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::InvalidRecord);
    }
    validate_claims_v1(
        &wire.signed_claims,
        qualified_backend,
        guest_evidence_public_key,
        host_evidence_public_key,
        execution_grant_issuer_public_key,
    )?;
    let unsigned = UnsignedExecutionRuntimeQualificationRecordWireV1 {
        schema_version: wire.schema_version.clone(),
        signed_claims: wire.signed_claims.clone(),
    };
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::Serialization)?;
    let signature = Signature::from_bytes(&decode_signature_v1(&wire.signature_ed25519_hex)?);
    let verifying_key = VerifyingKey::from_bytes(host_evidence_public_key)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::KeyInvalid)?;
    verifying_key
        .verify_strict(&signature_message_v1(&unsigned_bytes), &signature)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::SignatureInvalid)?;

    let record_sha256 = Sha256Digest::from_bytes(record_bytes);
    let claims = &wire.signed_claims;
    let qualification =
        VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1::from_verified_record_v1(
            record_sha256.clone(),
            claims.qualified_telemetry_backend_sha256.clone(),
            claims.runtime_manifest.rootfs_sha256.clone(),
            claims.runtime_manifest.rootfs_byte_length_v1(),
            claims.runtime_manifest_source_sha256.clone(),
            claims.runtime_manifest.package_runner_sha256.clone(),
            claims.runtime_manifest.node_executable_sha256.clone(),
            claims.runtime_manifest.npm_cli_sha256.clone(),
            claims.runtime_manifest.python_executable_sha256.clone(),
            claims.runtime_manifest.pip_entrypoint_sha256.clone(),
            claims.guest_evidence_public_key_sha256.clone(),
            claims.host_evidence_public_key_sha256.clone(),
            claims.execution_grant_issuer_public_key_sha256.clone(),
            PACKAGE_UID_V1,
            PACKAGE_GID_V1,
        )
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::QualificationInvalid)?;
    Ok((
        MacosLinuxVzPackageExecutionRuntimeQualificationRecordV1 {
            canonical_json: record_bytes.to_vec(),
            record_sha256,
        },
        qualification,
    ))
}

fn validate_claims_v1(
    claims: &ExecutionRuntimeQualificationClaimsWireV1,
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    guest_evidence_public_key: &[u8; 32],
    host_evidence_public_key: &[u8; 32],
    execution_grant_issuer_public_key: &[u8; 32],
) -> Result<(), ExecutionRuntimeQualificationRecordErrorV1> {
    let guest_key_sha256 = Sha256Digest::from_bytes(guest_evidence_public_key);
    let host_key_sha256 = Sha256Digest::from_bytes(host_evidence_public_key);
    let grant_key_sha256 = Sha256Digest::from_bytes(execution_grant_issuer_public_key);
    if claims.qualification_state
        != ExecutionRuntimeQualificationStateV1::PhysicalReadOnlyRuntimeQualificationVerified
        || claims.qualification_authority != "qualified_backend_host_evidence_key"
        || claims.qualified_telemetry_backend_sha256
            != *qualified_backend.qualified_backend_sha256()
        || claims.backend_identity_sha256 != *qualified_backend.backend_identity_sha256()
        || claims.telemetry_requirements_sha256
            != *qualified_backend.telemetry_requirements_sha256()
        || claims.conformance_evidence_set_sha256
            != *qualified_backend.conformance_evidence_set_sha256()
        || claims.host_evidence_public_key_sha256
            != *qualified_backend.host_evidence_public_key_sha256()
        || claims.host_evidence_public_key_sha256 != host_key_sha256
        || claims.guest_evidence_public_key_sha256 != guest_key_sha256
        || claims.execution_grant_issuer_public_key_sha256 != grant_key_sha256
        || claims.package_uid != PACKAGE_UID_V1.to_string()
        || claims.package_gid != PACKAGE_GID_V1.to_string()
        || qualified_backend.package_uid() != PACKAGE_UID_V1
        || qualified_backend.package_gid() != PACKAGE_GID_V1
        || claims.package_execution_scope != "one_typed_scenario_one_attempt"
        || !claims.execution_authority_issuance_permitted
        || claims.package_execution_during_qualification
        || claims.sync_back_policy != ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::BackendBindingMismatch);
    }
    claims.runtime_manifest.validate_v1()?;
    let manifest_source = canonical_newline_bytes_v1(&claims.runtime_manifest)?;
    if Sha256Digest::from_bytes(&manifest_source) != claims.runtime_manifest_source_sha256 {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::RuntimeManifestInvalid);
    }
    claims.qualification_image_manifest.validate_v1(
        &claims.runtime_manifest,
        &claims.runtime_manifest_source_sha256,
        &guest_key_sha256,
    )?;
    let image_source = canonical_newline_bytes_v1(&claims.qualification_image_manifest)?;
    if Sha256Digest::from_bytes(&image_source) != claims.qualification_image_manifest_source_sha256
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::ImageManifestInvalid);
    }
    let host_source = canonical_newline_bytes_v1(&claims.physical_host_boot_result)?;
    if Sha256Digest::from_bytes(&host_source) != claims.physical_host_boot_result_source_sha256 {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::HostResultInvalid);
    }
    let probe_bytes = serde_json_canonicalizer::to_vec(&claims.guest_probe_evidence)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::Serialization)?;
    if Sha256Digest::from_bytes(&probe_bytes) != claims.guest_probe_evidence_sha256 {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::ProbeEvidenceInvalid);
    }
    let probe = decode_linux_vz_package_execution_runtime_qualification_probe_v1(
        &probe_bytes,
        &claims.runtime_manifest.package_runner_sha256,
        &guest_key_sha256,
    )
    .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::ProbeEvidenceInvalid)?;
    validate_host_result_v1(
        &claims.physical_host_boot_result,
        &claims.runtime_manifest,
        &claims.runtime_manifest_source_sha256,
        &claims.qualification_image_manifest,
        &claims.qualification_image_manifest_source_sha256,
        &probe,
        probe_bytes.len(),
        &guest_key_sha256,
    )
}

#[allow(clippy::too_many_arguments)]
fn validate_host_result_v1(
    host: &PhysicalQualificationBootResultWireV1,
    runtime: &ExecutionRuntimeManifestWireV1,
    runtime_manifest_source_sha256: &Sha256Digest,
    image: &ExecutionRuntimeQualificationImageManifestWireV1,
    image_manifest_source_sha256: &Sha256Digest,
    probe: &crate::LinuxVzPackageExecutionRuntimeQualificationProbeEvidenceV1,
    probe_byte_length: usize,
    guest_key_sha256: &Sha256Digest,
) -> Result<(), ExecutionRuntimeQualificationRecordErrorV1> {
    if host.schema_version != PHYSICAL_BOOT_RESULT_SCHEMA_V1
        || host.status != "ok"
        || host.operation != "linux_vz_package_execution_runtime_rootfs_qualification"
        || host.kernel_command_line != "console=hvc0 rdinit=/init panic=0 reboot=k loglevel=6"
        || host.network_topology != "host_raw_frame_sinkhole_no_external_route"
        || !host.virtualization_supported
        || !host.image_identity_stable
        || !host.vm_stopped
        || !host.evidence_valid
        || host.evidence_payload_sha256 != *probe.evidence_sha256()
        || canonical_positive_u64_v1(&host.evidence_byte_length)? != probe_byte_length as u64
        || canonical_positive_u64_v1(&host.service_pid)? != probe.service_pid() as u64
        || canonical_positive_u64_v1(&host.runner_pid)? != probe.runner_pid() as u64
        || canonical_positive_u64_v1(&host.runner_thread_count)?
            != probe.runner_thread_count() as u64
        || canonical_positive_u64_v1(&host.runner_open_descriptor_count)?
            != probe.runner_open_descriptor_count() as u64
        || host.runner_inheritable_capabilities
            != format!("{:016x}", probe.runner_inheritable_capabilities())
        || host.runner_permitted_capabilities
            != format!("{:016x}", probe.runner_permitted_capabilities())
        || host.runner_effective_capabilities
            != format!("{:016x}", probe.runner_effective_capabilities())
        || host.runner_bounding_capabilities
            != format!("{:016x}", probe.runner_bounding_capabilities())
        || host.runner_ambient_capabilities
            != format!("{:016x}", probe.runner_ambient_capabilities())
        || host.required_marker_count != 11
        || !host.missing_required_markers.is_empty()
        || host.failure_marker_present
        || host.raw_frame_count != 0
        || host.raw_frame_retained_count != 0
        || host.raw_frame_dropped_count != 0
        || host.raw_frame_truncated_count != 0
        || !host.packet_sensor_healthy
        || host.packet_sensor_terminal != "drained_after_stop"
        || host.external_route
        || !host.root_disk_present
        || !host.root_disk_read_only
        || !host.rootfs_identity_stable
        || !host.runtime_manifest_identity_stable
        || !host.runtime_qualification_image_manifest_identity_stable
        || host.storage_device_count != "1"
        || host.writable_storage_device_count != "0"
        || host.directory_share_count != "0"
        || host.execution_authority_issued
        || host.execution_grant_consumed
        || host.execution_request_consumed
        || host.package_execution
        || host.malware_execution
        || host.sync_back
        || host.exit_code != 0
        || host.runtime_sha256 != runtime.package_runner_sha256
        || host.runtime_manifest_sha256 != *runtime_manifest_source_sha256
        || host.runtime_qualification_image_manifest_sha256 != *image_manifest_source_sha256
        || host.runtime_rootfs_sha256 != runtime.rootfs_sha256
        || canonical_positive_u64_v1(&host.runtime_rootfs_byte_length)?
            != runtime.rootfs_byte_length_v1()
        || host.node_executable_sha256 != runtime.node_executable_sha256
        || host.npm_cli_sha256 != runtime.npm_cli_sha256
        || host.python_executable_sha256 != runtime.python_executable_sha256
        || host.pip_entrypoint_sha256 != runtime.pip_entrypoint_sha256
        || host.guest_evidence_public_key_sha256 != *guest_key_sha256
        || host.initramfs_sha256 != image.qualification_initramfs_sha256
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::HostResultInvalid);
    }
    let empty = Sha256Digest::from_bytes(&[]);
    if host.kernel_sha256 == empty || host.kernel_sha256 == host.initramfs_sha256 {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::HostResultInvalid);
    }
    Ok(())
}

fn validate_public_keys_v1(
    guest: &[u8; 32],
    host: &[u8; 32],
    grant: &[u8; 32],
) -> Result<(), ExecutionRuntimeQualificationRecordErrorV1> {
    if guest == host || guest == grant || host == grant {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::KeyInvalid);
    }
    for key in [guest, host, grant] {
        let key = VerifyingKey::from_bytes(key)
            .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::KeyInvalid)?;
        if key.is_weak() {
            return Err(ExecutionRuntimeQualificationRecordErrorV1::KeyInvalid);
        }
    }
    Ok(())
}

fn decode_canonical_newline_json_v1<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, ExecutionRuntimeQualificationRecordErrorV1> {
    if bytes.is_empty() {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::Empty);
    }
    if bytes.len() > 128 * 1024 {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::LimitExceeded);
    }
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::InvalidRecord)?;
    let canonical = canonical_newline_bytes_v1(&value)?;
    if canonical != bytes {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::NonCanonical);
    }
    Ok(value)
}

fn decode_canonical_json_v1<T: DeserializeOwned + Serialize>(
    bytes: &[u8],
) -> Result<T, ExecutionRuntimeQualificationRecordErrorV1> {
    let value: T = serde_json::from_slice(bytes)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::InvalidRecord)?;
    let canonical = serde_json_canonicalizer::to_vec(&value)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::NonCanonical);
    }
    Ok(value)
}

fn canonical_newline_bytes_v1<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, ExecutionRuntimeQualificationRecordErrorV1> {
    let mut bytes = serde_json_canonicalizer::to_vec(value)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::Serialization)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn canonical_positive_u64_v1(
    value: &str,
) -> Result<u64, ExecutionRuntimeQualificationRecordErrorV1> {
    if value.is_empty()
        || value.len() > 20
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::BindingMismatch);
    }
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or(ExecutionRuntimeQualificationRecordErrorV1::BindingMismatch)
}

fn parsed_digest_v1(
    value: &str,
) -> Result<Sha256Digest, ExecutionRuntimeQualificationRecordErrorV1> {
    Sha256Digest::parse(value)
        .map_err(|_| ExecutionRuntimeQualificationRecordErrorV1::RuntimeManifestInvalid)
}

fn signature_message_v1(unsigned_record: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(RECORD_SIGNATURE_DOMAIN_V1.len() + 8 + unsigned_record.len());
    message.extend_from_slice(RECORD_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(&(unsigned_record.len() as u64).to_be_bytes());
    message.extend_from_slice(unsigned_record);
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

fn decode_signature_v1(
    value: &str,
) -> Result<[u8; 64], ExecutionRuntimeQualificationRecordErrorV1> {
    if value.len() != 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ExecutionRuntimeQualificationRecordErrorV1::SignatureInvalid);
    }
    let mut output = [0_u8; 64];
    let bytes = value.as_bytes();
    for index in 0..64 {
        output[index] =
            (hex_nibble_v1(bytes[index * 2])? << 4) | hex_nibble_v1(bytes[index * 2 + 1])?;
    }
    Ok(output)
}

fn hex_nibble_v1(value: u8) -> Result<u8, ExecutionRuntimeQualificationRecordErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(ExecutionRuntimeQualificationRecordErrorV1::SignatureInvalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_qualified_macos_linux_vz_telemetry_backend_v1;

    const GUEST_SEED: [u8; 32] = [11_u8; 32];
    const HOST_SEED: [u8; 32] = [22_u8; 32];
    const GRANT_SEED: [u8; 32] = [33_u8; 32];
    const BACKEND_GUEST_SEED: [u8; 32] = [44_u8; 32];

    struct FixtureV1 {
        backend: QualifiedMacosLinuxVzTelemetryBackendV1,
        runtime_manifest: Vec<u8>,
        image_manifest: Vec<u8>,
        host_result: Vec<u8>,
        probe: Vec<u8>,
        guest_public_key: [u8; 32],
        host_public_key: [u8; 32],
        grant_public_key: [u8; 32],
    }

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn pinned_digest(value: &str) -> Sha256Digest {
        Sha256Digest::parse(value).expect("pinned digest")
    }

    fn fixture_v1() -> FixtureV1 {
        let guest_public_key = SigningKey::from_bytes(&GUEST_SEED)
            .verifying_key()
            .to_bytes();
        let host_public_key = SigningKey::from_bytes(&HOST_SEED)
            .verifying_key()
            .to_bytes();
        let grant_public_key = SigningKey::from_bytes(&GRANT_SEED)
            .verifying_key()
            .to_bytes();
        let backend_guest_public_key = SigningKey::from_bytes(&BACKEND_GUEST_SEED)
            .verifying_key()
            .to_bytes();
        let backend = test_qualified_macos_linux_vz_telemetry_backend_v1(
            Sha256Digest::from_bytes(&backend_guest_public_key),
            Sha256Digest::from_bytes(&host_public_key),
        );
        let runtime = ExecutionRuntimeManifestWireV1 {
            alpine_release: "3.24.1".to_string(),
            architecture: "aarch64".to_string(),
            builder_source_sha256: digest("builder"),
            candidate_runtime_qualification: "required".to_string(),
            cargo_lock_sha256: digest("cargo lock"),
            container_builder_source_sha256: digest("container builder"),
            external_network: "structurally_absent".to_string(),
            image_state: "candidate_exact_bytes_not_yet_execution_qualified".to_string(),
            node_executable_sha256: digest("node"),
            node_version: "v24.17.0".to_string(),
            npm_cli_sha256: digest("npm"),
            npm_version: "11.12.1".to_string(),
            package_execution: false,
            package_execution_authority:
                "structurally_unavailable_until_verified_qualification_and_signed_one_use_grant"
                    .to_string(),
            package_gid: "65534".to_string(),
            package_runner_byte_length: "4535048".to_string(),
            package_runner_mode: "fixed_root_coordinator_authenticated_evidence_v1".to_string(),
            package_runner_path: "/whoathere/package-root-runtime".to_string(),
            package_runner_sha256: digest("package runner"),
            package_uid: "65534".to_string(),
            pip_entrypoint_sha256: digest("pip"),
            pip_version: "26.1.2".to_string(),
            python_executable_sha256: digest("python"),
            python_version: "3.14.5".to_string(),
            reproducible_epoch: "1783900800".to_string(),
            rootfs_byte_length: "1073741824".to_string(),
            rootfs_format: "raw_ext2_block_image_v1".to_string(),
            rootfs_sha256: digest("rootfs"),
            rootfs_tar_byte_length: "143278080".to_string(),
            rootfs_tar_sha256: digest("rootfs tar"),
            rootfs_uuid: "57484f41-5448-4552-5254-554e54494d45".to_string(),
            runtime_common_source_sha256: digest("runtime common source"),
            runtime_container_arm64_image_id: pinned_digest(
                "sha256:1991bd789d7184290c3cce84fd6af068b8b745e9bddf178661ce7f5ecf68135c",
            ),
            runtime_container_digest: pinned_digest(
                "sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b",
            ),
            runtime_inputs_lock_sha256: digest("runtime lock"),
            runtime_source_closure_sha256: digest("runtime source closure"),
            schema_version: EXECUTION_RUNTIME_MANIFEST_SCHEMA_V1.to_string(),
            source_minirootfs_sha256: pinned_digest(
                "sha256:f55a90f69052c5bd6f92cb09a8f47065970830b194c917a006fb94028e721259",
            ),
            sync_back: false,
            workspace_manifest_sha256: digest("workspace manifest"),
        };
        let runtime_manifest = canonical_newline_bytes_v1(&runtime).expect("runtime manifest");
        let runtime_manifest_sha256 = Sha256Digest::from_bytes(&runtime_manifest);
        let image = ExecutionRuntimeQualificationImageManifestWireV1 {
            architecture: "aarch64".to_string(),
            base_initramfs_sha256: digest("base initramfs"),
            builder_source_sha256: digest("image builder"),
            candidate_runtime_manifest_sha256: runtime_manifest_sha256.clone(),
            candidate_runtime_rootfs_byte_length: runtime.rootfs_byte_length.clone(),
            candidate_runtime_rootfs_sha256: runtime.rootfs_sha256.clone(),
            execution_authority_issued: false,
            external_network: "host_raw_frame_sinkhole_no_external_route".to_string(),
            guest_evidence_public_key_sha256: Sha256Digest::from_bytes(&guest_public_key),
            node_executable_sha256: runtime.node_executable_sha256.clone(),
            npm_cli_sha256: runtime.npm_cli_sha256.clone(),
            package_execution: false,
            package_execution_runtime_sha256: runtime.package_runner_sha256.clone(),
            pip_entrypoint_sha256: runtime.pip_entrypoint_sha256.clone(),
            python_executable_sha256: runtime.python_executable_sha256.clone(),
            qualification_init_sha256: digest("qualification init"),
            qualification_init_source_sha256: digest("qualification init source"),
            qualification_initramfs_sha256: digest("qualification initramfs"),
            qualification_operation:
                "fixed_root_coordinator_custody_probe_from_exact_read_only_rootfs".to_string(),
            qualification_overlay_cpio_gzip_sha256: digest("qualification cpio gzip"),
            qualification_overlay_cpio_sha256: digest("qualification cpio"),
            rootfs_attachment: "virtio_block_read_only".to_string(),
            schema_version: QUALIFICATION_IMAGE_MANIFEST_SCHEMA_V1.to_string(),
            sync_back: false,
            writer_source_sha256: digest("image writer"),
        };
        let image_manifest = canonical_newline_bytes_v1(&image).expect("image manifest");
        let image_manifest_sha256 = Sha256Digest::from_bytes(&image_manifest);
        let probe_value = serde_json::json!({
            "coordinator_split_exercised": true,
            "execution_authority_issued": false,
            "execution_grant_consumed": false,
            "execution_request_consumed": false,
            "fixed_execution_entrypoint_measured": true,
            "no_new_privileges": true,
            "package_execution": false,
            "ptrace_capability_present": false,
            "root_credentials_verified": true,
            "runner_ambient_capabilities": "0000000000000000",
            "runner_bounding_capabilities": "000001fffff7ffff",
            "runner_control_release_bound": true,
            "runner_effective_capabilities": "000001fffff7ffff",
            "runner_exit_status": "0",
            "runner_inheritable_capabilities": "0000000000000000",
            "runner_open_descriptor_count": "4",
            "runner_parent_death_signal_sigkill": true,
            "runner_permitted_capabilities": "000001fffff7ffff",
            "runner_pid": "101",
            "runner_seed_descriptor_closed": true,
            "runner_self_dumpable": false,
            "runner_thread_count": "1",
            "runner_unexpected_descriptor_count": "0",
            "runtime_sha256": runtime.package_runner_sha256,
            "schema_version": crate::LINUX_VZ_PACKAGE_EXECUTION_RUNTIME_QUALIFICATION_PROBE_SCHEMA_V1,
            "seed_byte_length": "32",
            "seed_pipe_exact_eof": true,
            "seed_public_key_sha256": Sha256Digest::from_bytes(&guest_public_key),
            "seed_read_after_runner_boundary_verification": true,
            "service_dumpable": false,
            "service_pid": "100",
            "sync_back": false,
            "tracer_absent": true
        });
        let probe = serde_json_canonicalizer::to_vec(&probe_value).expect("probe");
        let host = PhysicalQualificationBootResultWireV1 {
            directory_share_count: "0".to_string(),
            evidence_byte_length: probe.len().to_string(),
            evidence_payload_sha256: Sha256Digest::from_bytes(&probe),
            evidence_valid: true,
            execution_authority_issued: false,
            execution_grant_consumed: false,
            execution_request_consumed: false,
            exit_code: 0,
            external_route: false,
            failure_marker_present: false,
            guest_evidence_public_key_sha256: Sha256Digest::from_bytes(&guest_public_key),
            image_identity_stable: true,
            initramfs_sha256: image.qualification_initramfs_sha256.clone(),
            kernel_command_line: "console=hvc0 rdinit=/init panic=0 reboot=k loglevel=6"
                .to_string(),
            kernel_sha256: digest("kernel"),
            malware_execution: false,
            missing_required_markers: Vec::new(),
            network_topology: "host_raw_frame_sinkhole_no_external_route".to_string(),
            node_executable_sha256: runtime.node_executable_sha256.clone(),
            npm_cli_sha256: runtime.npm_cli_sha256.clone(),
            operation: "linux_vz_package_execution_runtime_rootfs_qualification".to_string(),
            package_execution: false,
            packet_sensor_healthy: true,
            packet_sensor_terminal: "drained_after_stop".to_string(),
            pip_entrypoint_sha256: runtime.pip_entrypoint_sha256.clone(),
            python_executable_sha256: runtime.python_executable_sha256.clone(),
            raw_frame_count: 0,
            raw_frame_dropped_count: 0,
            raw_frame_retained_count: 0,
            raw_frame_truncated_count: 0,
            required_marker_count: 11,
            root_disk_present: true,
            root_disk_read_only: true,
            rootfs_identity_stable: true,
            runner_ambient_capabilities: "0000000000000000".to_string(),
            runner_bounding_capabilities: "000001fffff7ffff".to_string(),
            runner_effective_capabilities: "000001fffff7ffff".to_string(),
            runner_inheritable_capabilities: "0000000000000000".to_string(),
            runner_open_descriptor_count: "4".to_string(),
            runner_permitted_capabilities: "000001fffff7ffff".to_string(),
            runner_pid: "101".to_string(),
            runner_thread_count: "1".to_string(),
            runtime_manifest_identity_stable: true,
            runtime_manifest_sha256,
            runtime_qualification_image_manifest_identity_stable: true,
            runtime_qualification_image_manifest_sha256: image_manifest_sha256,
            runtime_rootfs_byte_length: runtime.rootfs_byte_length.clone(),
            runtime_rootfs_sha256: runtime.rootfs_sha256.clone(),
            runtime_sha256: runtime.package_runner_sha256.clone(),
            schema_version: PHYSICAL_BOOT_RESULT_SCHEMA_V1.to_string(),
            service_pid: "100".to_string(),
            status: "ok".to_string(),
            storage_device_count: "1".to_string(),
            sync_back: false,
            virtualization_supported: true,
            vm_stopped: true,
            writable_storage_device_count: "0".to_string(),
        };
        let host_result = canonical_newline_bytes_v1(&host).expect("host result");
        FixtureV1 {
            backend,
            runtime_manifest,
            image_manifest,
            host_result,
            probe,
            guest_public_key,
            host_public_key,
            grant_public_key,
        }
    }

    #[test]
    fn signed_physical_record_is_the_production_qualification_path() {
        let fixture = fixture_v1();
        let record = build_macos_linux_vz_package_execution_runtime_qualification_record_v1(
            &fixture.backend,
            &fixture.runtime_manifest,
            &fixture.image_manifest,
            &fixture.host_result,
            &fixture.probe,
            fixture.guest_public_key,
            HOST_SEED,
            fixture.grant_public_key,
        )
        .expect("build record");
        assert!(record.execution_authority_issuance_permitted());
        assert!(!record.package_execution_during_qualification());
        assert!(!record.sync_back_permitted());

        let qualification =
            verify_macos_linux_vz_package_execution_runtime_qualification_record_v1(
                record.canonical_json_v1(),
                &fixture.backend,
                fixture.guest_public_key,
                fixture.host_public_key,
                fixture.grant_public_key,
            )
            .expect("verify record");
        assert_eq!(
            qualification.qualification_record_sha256(),
            record.record_sha256()
        );
        assert_eq!(
            qualification.qualified_telemetry_backend_sha256(),
            fixture.backend.qualified_backend_sha256()
        );
        assert_eq!(qualification.node_executable_sha256(), &digest("node"));
        assert_eq!(qualification.npm_cli_sha256(), &digest("npm"));
        assert_eq!(qualification.python_executable_sha256(), &digest("python"));
        assert_eq!(qualification.pip_entrypoint_sha256(), &digest("pip"));
        assert_eq!(qualification.node_version(), "24.17.0");
        assert_eq!(qualification.npm_version(), "11.12.1");
        assert_eq!(qualification.python_version(), "3.14.5");
        assert_eq!(qualification.pip_version(), "26.1.2");
        let candidate =
            crate::MacosLinuxVzCandidatePackageRuntimeV1::from_verified_execution_runtime_qualification_v1(
                &qualification,
            )
            .expect("candidate identity from verified runtime");
        assert_eq!(
            candidate.rootfs_sha256(),
            qualification.execution_runtime_rootfs_sha256()
        );
        assert_eq!(
            candidate.runtime_manifest_sha256(),
            qualification.execution_runtime_manifest_sha256()
        );
        assert!(qualification.execution_authority_issuance_permitted());
        assert!(!qualification.sync_back_permitted());
    }

    #[test]
    fn signature_tampering_cannot_create_opaque_qualification() {
        let fixture = fixture_v1();
        let record = build_macos_linux_vz_package_execution_runtime_qualification_record_v1(
            &fixture.backend,
            &fixture.runtime_manifest,
            &fixture.image_manifest,
            &fixture.host_result,
            &fixture.probe,
            fixture.guest_public_key,
            HOST_SEED,
            fixture.grant_public_key,
        )
        .expect("build record");
        let mut value: serde_json::Value =
            serde_json::from_slice(record.canonical_json_v1()).expect("record json");
        let signature = value["signature_ed25519_hex"].as_str().expect("signature");
        let replacement = if signature.starts_with('0') { '1' } else { '0' };
        value["signature_ed25519_hex"] =
            serde_json::Value::String(format!("{replacement}{}", &signature[1..]));
        let tampered = serde_json_canonicalizer::to_vec(&value).expect("tampered record");
        assert_eq!(
            verify_macos_linux_vz_package_execution_runtime_qualification_record_v1(
                &tampered,
                &fixture.backend,
                fixture.guest_public_key,
                fixture.host_public_key,
                fixture.grant_public_key,
            ),
            Err(ExecutionRuntimeQualificationRecordErrorV1::SignatureInvalid)
        );
    }

    #[test]
    fn unsafe_physical_result_is_never_signed() {
        let mut fixture = fixture_v1();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fixture.host_result).expect("host result json");
        value["package_execution"] = serde_json::Value::Bool(true);
        fixture.host_result = canonical_newline_bytes_v1(&value).expect("mutated host result");
        assert_eq!(
            build_macos_linux_vz_package_execution_runtime_qualification_record_v1(
                &fixture.backend,
                &fixture.runtime_manifest,
                &fixture.image_manifest,
                &fixture.host_result,
                &fixture.probe,
                fixture.guest_public_key,
                HOST_SEED,
                fixture.grant_public_key,
            ),
            Err(ExecutionRuntimeQualificationRecordErrorV1::HostResultInvalid)
        );
    }

    #[test]
    fn backend_host_key_substitution_is_rejected() {
        let fixture = fixture_v1();
        let wrong_host_seed = [55_u8; 32];
        assert_eq!(
            build_macos_linux_vz_package_execution_runtime_qualification_record_v1(
                &fixture.backend,
                &fixture.runtime_manifest,
                &fixture.image_manifest,
                &fixture.host_result,
                &fixture.probe,
                fixture.guest_public_key,
                wrong_host_seed,
                fixture.grant_public_key,
            ),
            Err(ExecutionRuntimeQualificationRecordErrorV1::BackendBindingMismatch)
        );
    }
}
