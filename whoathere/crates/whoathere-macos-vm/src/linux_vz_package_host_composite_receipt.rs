use crate::{
    LinuxVzPackageHostUdpSendtoEvidenceV1, MacosLinuxVzPackageAuthorityRequestV1,
    MacosLinuxVzPackageExecutionGrantObservationV1, VerifiedLinuxVzPackageRootEvidenceReceiptV1,
    LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V2,
};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_HOST_COMPOSITE_EVIDENCE_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_host_composite_evidence.v1";
pub const LINUX_VZ_PACKAGE_HOST_COMPOSITE_RECEIPT_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_host_composite_receipt.v1";
pub const MAX_LINUX_VZ_PACKAGE_HOST_COMPOSITE_EVIDENCE_BYTES_V1: usize = 512 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_HOST_COMPOSITE_RECEIPT_BYTES_V1: usize = 64 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_HOST_COMPOSITE_RECEIPT_LIFETIME_SECONDS_V1: u64 = 10 * 60;

const HOST_COMPOSITE_RECEIPT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.linux_vz_package_host_composite_receipt.signature.v1\0";
const HOST_COMPOSITE_EVIDENCE_AUTHORITY_V1: &str = "mac_host_lifecycle_and_raw_frame_composer";
const HOST_COMPOSITE_RECEIPT_AUTHORITY_V1: &str = "mac_host_composite_evidence_signer";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageHostCompositeReceiptErrorV1 {
    Empty,
    LimitExceeded,
    InvalidLifecycle,
    InvalidBinding,
    InvalidEvidence,
    InvalidReceipt,
    NonCanonical,
    PublicKeyMismatch,
    SignatureFailed,
    InvalidTime,
    Serialization,
}

impl LinuxVzPackageHostCompositeReceiptErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "linux_vz_package_host_composite_empty",
            Self::LimitExceeded => "linux_vz_package_host_composite_limit_exceeded",
            Self::InvalidLifecycle => "linux_vz_package_host_composite_lifecycle_invalid",
            Self::InvalidBinding => "linux_vz_package_host_composite_binding_invalid",
            Self::InvalidEvidence => "linux_vz_package_host_composite_evidence_invalid",
            Self::InvalidReceipt => "linux_vz_package_host_composite_receipt_invalid",
            Self::NonCanonical => "linux_vz_package_host_composite_noncanonical",
            Self::PublicKeyMismatch => "linux_vz_package_host_composite_public_key_mismatch",
            Self::SignatureFailed => "linux_vz_package_host_composite_signature_failed",
            Self::InvalidTime => "linux_vz_package_host_composite_time_invalid",
            Self::Serialization => "linux_vz_package_host_composite_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageHostCompositeReceiptErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageHostCompositeReceiptErrorV1 {}

/// Mac-observed lifecycle values supplied to the independent verifier.
///
/// Construction is fail-closed: a missing stop, unstable image, surviving clone, forwarded frame,
/// unsorted reference, or raw/empty reference cannot be represented as an accepted lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageExpectedHostCompositeLifecycleV1 {
    serial_log_sha256: Sha256Digest,
    restricted_evidence_reference_sha256s: Vec<Sha256Digest>,
    vm_started: bool,
    guest_channel_terminated: bool,
    vm_stopped: bool,
    image_identity_stable: bool,
    clone_destroyed_after_stop: bool,
    external_frames_forwarded: u64,
}

impl LinuxVzPackageExpectedHostCompositeLifecycleV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_v1(
        serial_log_sha256: Sha256Digest,
        restricted_evidence_reference_sha256s: Vec<Sha256Digest>,
        vm_started: bool,
        guest_channel_terminated: bool,
        vm_stopped: bool,
        image_identity_stable: bool,
        clone_destroyed_after_stop: bool,
        external_frames_forwarded: u64,
    ) -> Result<Self, LinuxVzPackageHostCompositeReceiptErrorV1> {
        let value = Self {
            serial_log_sha256,
            restricted_evidence_reference_sha256s,
            vm_started,
            guest_channel_terminated,
            vm_stopped,
            image_identity_stable,
            clone_destroyed_after_stop,
            external_frames_forwarded,
        };
        value.validate_v1()?;
        Ok(value)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageHostCompositeReceiptErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        if self.serial_log_sha256 == empty
            || self.restricted_evidence_reference_sha256s.is_empty()
            || self
                .restricted_evidence_reference_sha256s
                .iter()
                .any(|digest| digest == &empty || digest == &self.serial_log_sha256)
            || self
                .restricted_evidence_reference_sha256s
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
            || !self.vm_started
            || !self.guest_channel_terminated
            || !self.vm_stopped
            || !self.image_identity_stable
            || !self.clone_destroyed_after_stop
            || self.external_frames_forwarded != 0
        {
            return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidLifecycle);
        }
        Ok(())
    }
}

/// Opaque expected bindings built only from already verified request, grant, guest receipt, host
/// packet evidence, and independently observed Mac lifecycle state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageHostCompositeExpectedBindingsV1 {
    artifact_sha256: Sha256Digest,
    package_authority_request_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    guest_root_receipt_sha256: Sha256Digest,
    guest_process_evidence_sha256: Sha256Digest,
    guest_file_evidence_sha256: Sha256Digest,
    guest_network_evidence_sha256: Sha256Digest,
    host_network_evidence_sha256: Sha256Digest,
    host_frame_sha256: Sha256Digest,
    host_egress_packet_correlation_sha256: Sha256Digest,
    root_evidence_complete: bool,
    lifecycle: LinuxVzPackageExpectedHostCompositeLifecycleV1,
}

impl LinuxVzPackageHostCompositeExpectedBindingsV1 {
    pub fn from_verified_sources_v1(
        request: &MacosLinuxVzPackageAuthorityRequestV1,
        grant: &MacosLinuxVzPackageExecutionGrantObservationV1,
        root: &VerifiedLinuxVzPackageRootEvidenceReceiptV1,
        host_network: &LinuxVzPackageHostUdpSendtoEvidenceV1,
        lifecycle: LinuxVzPackageExpectedHostCompositeLifecycleV1,
    ) -> Result<Self, LinuxVzPackageHostCompositeReceiptErrorV1> {
        lifecycle.validate_v1()?;
        if !grant.consumed()
            || !grant.execution_request_consumed()
            || request.sync_back_permitted()
            || grant.sync_back_permitted()
            || root.sync_back_permitted()
            || !root.host_composition_required()
            || root.authoritative_verdict_permitted()
            || request.request_sha256() != grant.package_authority_request_sha256()
            || request.clone_binding_sha256() != grant.clone_binding_sha256()
            || request.artifact_sha256() != root.artifact_sha256()
            || grant.execution_grant_sha256() != root.execution_grant_sha256()
            || host_network.root_network_evidence_sha256() != root.network_evidence_sha256()
            || host_network.process_evidence_sha256() != root.process_evidence_sha256()
            || host_network.payload_sha256()
                != &Sha256Digest::from_bytes(host_network.canonical_json())
            || !host_network.selected_correlation_complete()
            || host_network.broad_host_frame_coverage_complete()
            || grant.guest_evidence_public_key_sha256() == grant.host_evidence_public_key_sha256()
        {
            return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidBinding);
        }
        let value = Self {
            artifact_sha256: request.artifact_sha256().clone(),
            package_authority_request_sha256: request.request_sha256().clone(),
            execution_grant_sha256: grant.execution_grant_sha256().clone(),
            clone_binding_sha256: request.clone_binding_sha256().clone(),
            execution_runtime_rootfs_sha256: request.candidate_runtime_rootfs_sha256().clone(),
            execution_runtime_manifest_sha256: request.candidate_runtime_manifest_sha256().clone(),
            package_execution_runner_sha256: request.candidate_package_runner_sha256().clone(),
            guest_evidence_public_key_sha256: grant.guest_evidence_public_key_sha256().clone(),
            host_evidence_public_key_sha256: grant.host_evidence_public_key_sha256().clone(),
            guest_root_receipt_sha256: root.receipt_sha256().clone(),
            guest_process_evidence_sha256: root.process_evidence_sha256().clone(),
            guest_file_evidence_sha256: root.file_evidence_sha256().clone(),
            guest_network_evidence_sha256: root.network_evidence_sha256().clone(),
            host_network_evidence_sha256: host_network.payload_sha256().clone(),
            host_frame_sha256: host_network.frame_sha256().clone(),
            host_egress_packet_correlation_sha256: host_network
                .egress_packet_correlation_sha256()
                .clone(),
            root_evidence_complete: root.evidence_complete(),
            lifecycle,
        };
        value.validate_v1()?;
        Ok(value)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageHostCompositeReceiptErrorV1> {
        self.lifecycle.validate_v1()?;
        let empty = Sha256Digest::from_bytes(&[]);
        let digests = [
            &self.clone_binding_sha256,
            &self.execution_runtime_rootfs_sha256,
            &self.execution_runtime_manifest_sha256,
            &self.package_execution_runner_sha256,
            &self.host_evidence_public_key_sha256,
            &self.lifecycle.serial_log_sha256,
        ];
        if digests.contains(&&empty)
            || digests
                .iter()
                .enumerate()
                .any(|(index, digest)| digests[..index].contains(digest))
            || self
                .lifecycle
                .restricted_evidence_reference_sha256s
                .iter()
                .any(|reference| digests.contains(&reference))
            || self.guest_evidence_public_key_sha256 == self.host_evidence_public_key_sha256
        {
            return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidBinding);
        }
        Ok(())
    }

    pub fn host_evidence_public_key_sha256(&self) -> &Sha256Digest {
        &self.host_evidence_public_key_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostCompositeEventWireV1 {
    event: String,
    sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostCompositeEvidenceWireV1 {
    schema_version: String,
    authority: String,
    artifact_sha256: Sha256Digest,
    package_authority_request_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    guest_root_receipt_sha256: Sha256Digest,
    guest_process_evidence_sha256: Sha256Digest,
    guest_file_evidence_sha256: Sha256Digest,
    guest_network_evidence_sha256: Sha256Digest,
    host_network_evidence_schema: String,
    host_network_evidence_sha256: Sha256Digest,
    host_frame_sha256: Sha256Digest,
    host_egress_packet_correlation_sha256: Sha256Digest,
    serial_log_sha256: Sha256Digest,
    restricted_evidence_reference_sha256s: Vec<Sha256Digest>,
    events: Vec<HostCompositeEventWireV1>,
    event_sequence_start: String,
    event_sequence_end: String,
    event_count: String,
    root_evidence_complete: bool,
    selected_udp_sendto_host_correlation_complete: bool,
    broad_host_network_coverage_complete: bool,
    host_lifecycle_complete: bool,
    composite_evidence_complete: bool,
    vm_started: bool,
    guest_channel_terminated: bool,
    vm_stopped: bool,
    image_identity_stable: bool,
    clone_destroyed_after_stop: bool,
    external_frames_forwarded: String,
    public_network_route_present: bool,
    restricted_evidence_references_are_digests_only: bool,
    verdict_state: String,
    authoritative_verdict_permitted: bool,
    sync_back_policy: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageHostCompositeEvidenceV1 {
    canonical_json: Vec<u8>,
    evidence_sha256: Sha256Digest,
    root_receipt_sha256: Sha256Digest,
    host_network_evidence_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
}

impl LinuxVzPackageHostCompositeEvidenceV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }
    pub fn evidence_sha256(&self) -> &Sha256Digest {
        &self.evidence_sha256
    }
    pub fn root_receipt_sha256(&self) -> &Sha256Digest {
        &self.root_receipt_sha256
    }
    pub fn host_network_evidence_sha256(&self) -> &Sha256Digest {
        &self.host_network_evidence_sha256
    }
    pub const fn composite_evidence_complete(&self) -> bool {
        false
    }
    pub const fn authoritative_verdict_permitted(&self) -> bool {
        false
    }
    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn decode_linux_vz_package_host_composite_evidence_v1(
    bytes: &[u8],
    expected: &LinuxVzPackageHostCompositeExpectedBindingsV1,
) -> Result<LinuxVzPackageHostCompositeEvidenceV1, LinuxVzPackageHostCompositeReceiptErrorV1> {
    expected.validate_v1()?;
    if bytes.is_empty() {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::Empty);
    }
    if bytes.len() > MAX_LINUX_VZ_PACKAGE_HOST_COMPOSITE_EVIDENCE_BYTES_V1 {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = HostCompositeEvidenceWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::InvalidEvidence)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::InvalidEvidence)?;
    let canonical = canonical_json_v1(&wire)?;
    if canonical != bytes {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::NonCanonical);
    }
    if wire != expected_evidence_wire_v1(expected) {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidBinding);
    }
    Ok(LinuxVzPackageHostCompositeEvidenceV1 {
        canonical_json: canonical,
        evidence_sha256: Sha256Digest::from_bytes(bytes),
        root_receipt_sha256: expected.guest_root_receipt_sha256.clone(),
        host_network_evidence_sha256: expected.host_network_evidence_sha256.clone(),
        artifact_sha256: expected.artifact_sha256.clone(),
        execution_grant_sha256: expected.execution_grant_sha256.clone(),
        clone_binding_sha256: expected.clone_binding_sha256.clone(),
    })
}

fn expected_evidence_wire_v1(
    expected: &LinuxVzPackageHostCompositeExpectedBindingsV1,
) -> HostCompositeEvidenceWireV1 {
    let event_names = [
        "guest_root_receipt_verified",
        "host_raw_frame_correlated_and_drained",
        "guest_channel_terminated",
        "vm_stopped",
        "image_identity_remeasured_stable",
        "clone_destroyed_after_stop",
    ];
    HostCompositeEvidenceWireV1 {
        schema_version: LINUX_VZ_PACKAGE_HOST_COMPOSITE_EVIDENCE_SCHEMA_V1.to_string(),
        authority: HOST_COMPOSITE_EVIDENCE_AUTHORITY_V1.to_string(),
        artifact_sha256: expected.artifact_sha256.clone(),
        package_authority_request_sha256: expected.package_authority_request_sha256.clone(),
        execution_grant_sha256: expected.execution_grant_sha256.clone(),
        clone_binding_sha256: expected.clone_binding_sha256.clone(),
        execution_runtime_rootfs_sha256: expected.execution_runtime_rootfs_sha256.clone(),
        execution_runtime_manifest_sha256: expected.execution_runtime_manifest_sha256.clone(),
        package_execution_runner_sha256: expected.package_execution_runner_sha256.clone(),
        guest_evidence_public_key_sha256: expected.guest_evidence_public_key_sha256.clone(),
        host_evidence_public_key_sha256: expected.host_evidence_public_key_sha256.clone(),
        guest_root_receipt_sha256: expected.guest_root_receipt_sha256.clone(),
        guest_process_evidence_sha256: expected.guest_process_evidence_sha256.clone(),
        guest_file_evidence_sha256: expected.guest_file_evidence_sha256.clone(),
        guest_network_evidence_sha256: expected.guest_network_evidence_sha256.clone(),
        host_network_evidence_schema: LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V2
            .to_string(),
        host_network_evidence_sha256: expected.host_network_evidence_sha256.clone(),
        host_frame_sha256: expected.host_frame_sha256.clone(),
        host_egress_packet_correlation_sha256: expected
            .host_egress_packet_correlation_sha256
            .clone(),
        serial_log_sha256: expected.lifecycle.serial_log_sha256.clone(),
        restricted_evidence_reference_sha256s: expected
            .lifecycle
            .restricted_evidence_reference_sha256s
            .clone(),
        events: event_names
            .iter()
            .enumerate()
            .map(|(index, event)| HostCompositeEventWireV1 {
                event: (*event).to_string(),
                sequence: (index + 1).to_string(),
            })
            .collect(),
        event_sequence_start: "1".to_string(),
        event_sequence_end: "6".to_string(),
        event_count: "6".to_string(),
        root_evidence_complete: expected.root_evidence_complete,
        selected_udp_sendto_host_correlation_complete: true,
        broad_host_network_coverage_complete: false,
        host_lifecycle_complete: true,
        composite_evidence_complete: false,
        vm_started: expected.lifecycle.vm_started,
        guest_channel_terminated: expected.lifecycle.guest_channel_terminated,
        vm_stopped: expected.lifecycle.vm_stopped,
        image_identity_stable: expected.lifecycle.image_identity_stable,
        clone_destroyed_after_stop: expected.lifecycle.clone_destroyed_after_stop,
        external_frames_forwarded: expected.lifecycle.external_frames_forwarded.to_string(),
        public_network_route_present: false,
        restricted_evidence_references_are_digests_only: true,
        verdict_state: "inconclusive_incomplete_coverage".to_string(),
        authoritative_verdict_permitted: false,
        sync_back_policy: "structurally_absent".to_string(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedHostCompositeReceiptWireV1 {
    schema_version: String,
    authority: String,
    composite_evidence_sha256: Sha256Digest,
    guest_root_receipt_sha256: Sha256Digest,
    host_network_evidence_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    host_lifecycle_complete: bool,
    selected_udp_sendto_host_correlation_complete: bool,
    broad_host_network_coverage_complete: bool,
    composite_evidence_complete: bool,
    verdict_state: String,
    authoritative_verdict_permitted: bool,
    sync_back_policy: String,
    created_at_unix_seconds: String,
    expires_at_unix_seconds: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostCompositeReceiptWireV1 {
    schema_version: String,
    authority: String,
    composite_evidence_sha256: Sha256Digest,
    guest_root_receipt_sha256: Sha256Digest,
    host_network_evidence_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    host_lifecycle_complete: bool,
    selected_udp_sendto_host_correlation_complete: bool,
    broad_host_network_coverage_complete: bool,
    composite_evidence_complete: bool,
    verdict_state: String,
    authoritative_verdict_permitted: bool,
    sync_back_policy: String,
    created_at_unix_seconds: String,
    expires_at_unix_seconds: String,
    signature_ed25519_hex: String,
}

impl HostCompositeReceiptWireV1 {
    fn into_unsigned(self) -> UnsignedHostCompositeReceiptWireV1 {
        UnsignedHostCompositeReceiptWireV1 {
            schema_version: self.schema_version,
            authority: self.authority,
            composite_evidence_sha256: self.composite_evidence_sha256,
            guest_root_receipt_sha256: self.guest_root_receipt_sha256,
            host_network_evidence_sha256: self.host_network_evidence_sha256,
            artifact_sha256: self.artifact_sha256,
            execution_grant_sha256: self.execution_grant_sha256,
            clone_binding_sha256: self.clone_binding_sha256,
            host_evidence_public_key_sha256: self.host_evidence_public_key_sha256,
            host_lifecycle_complete: self.host_lifecycle_complete,
            selected_udp_sendto_host_correlation_complete: self
                .selected_udp_sendto_host_correlation_complete,
            broad_host_network_coverage_complete: self.broad_host_network_coverage_complete,
            composite_evidence_complete: self.composite_evidence_complete,
            verdict_state: self.verdict_state,
            authoritative_verdict_permitted: self.authoritative_verdict_permitted,
            sync_back_policy: self.sync_back_policy,
            created_at_unix_seconds: self.created_at_unix_seconds,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLinuxVzPackageHostCompositeReceiptV1 {
    receipt_sha256: Sha256Digest,
    composite_evidence_sha256: Sha256Digest,
    root_receipt_sha256: Sha256Digest,
    host_network_evidence_sha256: Sha256Digest,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl VerifiedLinuxVzPackageHostCompositeReceiptV1 {
    pub fn receipt_sha256(&self) -> &Sha256Digest {
        &self.receipt_sha256
    }
    pub fn composite_evidence_sha256(&self) -> &Sha256Digest {
        &self.composite_evidence_sha256
    }
    pub fn root_receipt_sha256(&self) -> &Sha256Digest {
        &self.root_receipt_sha256
    }
    pub fn host_network_evidence_sha256(&self) -> &Sha256Digest {
        &self.host_network_evidence_sha256
    }
    pub const fn created_at_unix_seconds(&self) -> u64 {
        self.created_at_unix_seconds
    }
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
    pub const fn composite_evidence_complete(&self) -> bool {
        false
    }
    pub const fn authoritative_verdict_permitted(&self) -> bool {
        false
    }
    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn verify_linux_vz_package_host_composite_receipt_v1(
    evidence_bytes: &[u8],
    receipt_bytes: &[u8],
    expected: &LinuxVzPackageHostCompositeExpectedBindingsV1,
    host_verifying_key_bytes: [u8; 32],
    observed_at_unix_seconds: u64,
) -> Result<VerifiedLinuxVzPackageHostCompositeReceiptV1, LinuxVzPackageHostCompositeReceiptErrorV1>
{
    let evidence = decode_linux_vz_package_host_composite_evidence_v1(evidence_bytes, expected)?;
    if receipt_bytes.is_empty() {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::Empty);
    }
    if receipt_bytes.len() > MAX_LINUX_VZ_PACKAGE_HOST_COMPOSITE_RECEIPT_BYTES_V1 {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::LimitExceeded);
    }
    if Sha256Digest::from_bytes(&host_verifying_key_bytes)
        != expected.host_evidence_public_key_sha256
    {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::PublicKeyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&host_verifying_key_bytes)
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::PublicKeyMismatch)?;
    if verifying_key.is_weak() {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::PublicKeyMismatch);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(receipt_bytes);
    let wire = HostCompositeReceiptWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::InvalidReceipt)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::InvalidReceipt)?;
    if canonical_json_v1(&wire)? != receipt_bytes
        || !valid_signature_hex_v1(&wire.signature_ed25519_hex)
    {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::NonCanonical);
    }
    let signature_hex = wire.signature_ed25519_hex.clone();
    let unsigned = wire.into_unsigned();
    let created_at_unix_seconds = decimal_u64_v1(&unsigned.created_at_unix_seconds)?;
    let expires_at_unix_seconds = decimal_u64_v1(&unsigned.expires_at_unix_seconds)?;
    validate_time_v1(
        created_at_unix_seconds,
        expires_at_unix_seconds,
        observed_at_unix_seconds,
    )?;
    let expected_unsigned = expected_unsigned_receipt_v1(
        &evidence,
        expected,
        created_at_unix_seconds,
        expires_at_unix_seconds,
    );
    if unsigned != expected_unsigned {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidBinding);
    }
    let unsigned_bytes = canonical_json_v1(&unsigned)?;
    let signature = Signature::from_bytes(&decode_signature_v1(&signature_hex)?);
    verifying_key
        .verify_strict(
            &signature_message_v1(evidence_bytes, &unsigned_bytes),
            &signature,
        )
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::SignatureFailed)?;
    Ok(VerifiedLinuxVzPackageHostCompositeReceiptV1 {
        receipt_sha256: Sha256Digest::from_bytes(receipt_bytes),
        composite_evidence_sha256: evidence.evidence_sha256,
        root_receipt_sha256: evidence.root_receipt_sha256,
        host_network_evidence_sha256: evidence.host_network_evidence_sha256,
        created_at_unix_seconds,
        expires_at_unix_seconds,
    })
}

fn expected_unsigned_receipt_v1(
    evidence: &LinuxVzPackageHostCompositeEvidenceV1,
    expected: &LinuxVzPackageHostCompositeExpectedBindingsV1,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
) -> UnsignedHostCompositeReceiptWireV1 {
    UnsignedHostCompositeReceiptWireV1 {
        schema_version: LINUX_VZ_PACKAGE_HOST_COMPOSITE_RECEIPT_SCHEMA_V1.to_string(),
        authority: HOST_COMPOSITE_RECEIPT_AUTHORITY_V1.to_string(),
        composite_evidence_sha256: evidence.evidence_sha256.clone(),
        guest_root_receipt_sha256: evidence.root_receipt_sha256.clone(),
        host_network_evidence_sha256: evidence.host_network_evidence_sha256.clone(),
        artifact_sha256: evidence.artifact_sha256.clone(),
        execution_grant_sha256: evidence.execution_grant_sha256.clone(),
        clone_binding_sha256: evidence.clone_binding_sha256.clone(),
        host_evidence_public_key_sha256: expected.host_evidence_public_key_sha256.clone(),
        host_lifecycle_complete: true,
        selected_udp_sendto_host_correlation_complete: true,
        broad_host_network_coverage_complete: false,
        composite_evidence_complete: false,
        verdict_state: "inconclusive_incomplete_coverage".to_string(),
        authoritative_verdict_permitted: false,
        sync_back_policy: "structurally_absent".to_string(),
        created_at_unix_seconds: created_at_unix_seconds.to_string(),
        expires_at_unix_seconds: expires_at_unix_seconds.to_string(),
    }
}

fn validate_time_v1(
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    observed_at_unix_seconds: u64,
) -> Result<(), LinuxVzPackageHostCompositeReceiptErrorV1> {
    let lifetime = expires_at_unix_seconds
        .checked_sub(created_at_unix_seconds)
        .ok_or(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidTime)?;
    if created_at_unix_seconds == 0
        || lifetime == 0
        || lifetime > MAX_LINUX_VZ_PACKAGE_HOST_COMPOSITE_RECEIPT_LIFETIME_SECONDS_V1
        || observed_at_unix_seconds < created_at_unix_seconds
        || observed_at_unix_seconds >= expires_at_unix_seconds
    {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidTime);
    }
    Ok(())
}

fn signature_message_v1(evidence: &[u8], unsigned_receipt: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        HOST_COMPOSITE_RECEIPT_SIGNATURE_DOMAIN_V1.len()
            + 16
            + evidence.len()
            + unsigned_receipt.len(),
    );
    message.extend_from_slice(HOST_COMPOSITE_RECEIPT_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(&(evidence.len() as u64).to_be_bytes());
    message.extend_from_slice(evidence);
    message.extend_from_slice(&(unsigned_receipt.len() as u64).to_be_bytes());
    message.extend_from_slice(unsigned_receipt);
    message
}

fn canonical_json_v1<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, LinuxVzPackageHostCompositeReceiptErrorV1> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::Serialization)
}

fn decimal_u64_v1(value: &str) -> Result<u64, LinuxVzPackageHostCompositeReceiptErrorV1> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| LinuxVzPackageHostCompositeReceiptErrorV1::InvalidReceipt)?;
    if parsed.to_string() != value {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidReceipt);
    }
    Ok(parsed)
}

fn valid_signature_hex_v1(value: &str) -> bool {
    value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_signature_v1(value: &str) -> Result<[u8; 64], LinuxVzPackageHostCompositeReceiptErrorV1> {
    if !valid_signature_hex_v1(value) {
        return Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidReceipt);
    }
    let mut output = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        output[index] = (hex_nibble_v1(pair[0])? << 4) | hex_nibble_v1(pair[1])?;
    }
    Ok(output)
}

fn hex_nibble_v1(value: u8) -> Result<u8, LinuxVzPackageHostCompositeReceiptErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidReceipt),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_linux_vz_package_host_udp_sendto_evidence_v1,
        linux_vz_package_authority_request::test_macos_linux_vz_package_authority_request_for_execution_v1,
        linux_vz_package_execution_grant::{
            test_burn_macos_linux_vz_package_execution_request_v1,
            test_macos_linux_vz_package_execution_grant_observation_with_evidence_keys_v1,
        },
        linux_vz_package_root_evidence_receipt::test_verified_linux_vz_package_root_evidence_receipt_v1,
        LinuxVzPackageExpectedHostUdpSendtoV1, LinuxVzPackageHostDestinationClassV1,
        MacosLinuxVzPackageArtifactKindV1,
    };
    use ed25519_dalek::{Signer, SigningKey};

    const HOST_SIGNING_SEED: [u8; 32] = [44_u8; 32];
    const CREATED_AT: u64 = 1_750_000_010;
    const EXPIRES_AT: u64 = 1_750_000_310;
    // Captured from the independently implemented CryptoKit signer over the pinned evidence and
    // unsigned receipt. Rust verifies this exact Swift-produced signature and receipt digest.
    const SWIFT_GOLDEN_SIGNATURE: &str =
        "2f0482e3d8bf065631a41bb917dc0198121166fd195c3a51566f31cc3df1b96690dcf7057c09cc31557c781e9e35a3e37fff6fb8d9a367067b89d26676b3e20d";

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn host_network_v2() -> LinuxVzPackageHostUdpSendtoEvidenceV1 {
        let expected = LinuxVzPackageExpectedHostUdpSendtoV1::new_v1(
            Sha256Digest::from_bytes(br#"{"type":"network"}"#),
            Sha256Digest::from_bytes(br#"{"type":"process"}"#),
            digest("sensor session challenge"),
            digest("host destination token"),
            digest("host egress packet correlation"),
            LinuxVzPackageHostDestinationClassV1::Documentation,
            40_553,
            16,
            16,
        )
        .expect("expected host network");
        let value = serde_json::json!({
            "binding": {
                "egress_packet_correlation_sha256": digest("host egress packet correlation"),
                "process_evidence_sha256": Sha256Digest::from_bytes(br#"{"type":"process"}"#),
                "root_network_evidence_sha256": Sha256Digest::from_bytes(br#"{"type":"network"}"#),
                "sensor_session_challenge_sha256": digest("sensor session challenge")
            },
            "collector": {
                "dropped_frame_count": "0", "healthy": true, "ingress_frame_count": "1",
                "retained_frame_count": "1", "terminal": "drained_after_stop",
                "truncated_frame_count": "0"
            },
            "coverage": {
                "broad_host_frame_coverage_complete": false,
                "correlated_transmitted_event_count": "1", "raw_addresses_serialized": false,
                "raw_frame_bytes_serialized": false,
                "selected_udp_sendto_correlation_complete": true,
                "unobserved_capabilities": [
                    "ipv6_host_frames", "kernel_socket_buffer_drop_accounting",
                    "non_udp_sendto_host_frames", "retransmission_and_multi_frame_events"
                ]
            },
            "event": {
                "destination_class": "documentation", "destination_port": "40553",
                "destination_token_sha256": digest("host destination token"),
                "enter_source_sequence": "16", "event_kind": "sendto",
                "frame_sha256": digest("host frame"),
                "network_layer_correlation_sha256": digest("host egress packet correlation"),
                "source_port": "49152", "syscall_result": "16", "transport": "udp",
                "transport_payload_byte_count": "16"
            },
            "schema_version": LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V2
        });
        let bytes = serde_json_canonicalizer::to_vec(&value).expect("canonical host network");
        decode_linux_vz_package_host_udp_sendto_evidence_v1(&bytes, &expected)
            .expect("host network")
    }

    fn swift_fixture_expected() -> LinuxVzPackageHostCompositeExpectedBindingsV1 {
        let guest_key = SigningKey::from_bytes(&[73_u8; 32]);
        let host_key = SigningKey::from_bytes(&HOST_SIGNING_SEED);
        let host_network = host_network_v2();
        LinuxVzPackageHostCompositeExpectedBindingsV1 {
            artifact_sha256: digest("artifact"),
            package_authority_request_sha256: digest("authority request"),
            execution_grant_sha256: digest("execution grant"),
            clone_binding_sha256: digest("clone binding"),
            execution_runtime_rootfs_sha256: digest("runtime rootfs"),
            execution_runtime_manifest_sha256: digest("runtime manifest"),
            package_execution_runner_sha256: digest("package runner"),
            guest_evidence_public_key_sha256: Sha256Digest::from_bytes(
                guest_key.verifying_key().as_bytes(),
            ),
            host_evidence_public_key_sha256: Sha256Digest::from_bytes(
                host_key.verifying_key().as_bytes(),
            ),
            guest_root_receipt_sha256: Sha256Digest::parse(
                "sha256:dc91df448364fa0d8ddb2fb60d4f7c89027f3326d7ae9136a70bebaedc6d8a22",
            )
            .expect("root receipt"),
            guest_process_evidence_sha256: Sha256Digest::from_bytes(br#"{"type":"process"}"#),
            guest_file_evidence_sha256: Sha256Digest::from_bytes(br#"{"type":"file"}"#),
            guest_network_evidence_sha256: Sha256Digest::from_bytes(br#"{"type":"network"}"#),
            host_network_evidence_sha256: host_network.payload_sha256().clone(),
            host_frame_sha256: host_network.frame_sha256().clone(),
            host_egress_packet_correlation_sha256: host_network
                .egress_packet_correlation_sha256()
                .clone(),
            root_evidence_complete: false,
            lifecycle: LinuxVzPackageExpectedHostCompositeLifecycleV1::new_v1(
                digest("host serial log"),
                vec![digest("restricted raw evidence reference")],
                true,
                true,
                true,
                true,
                true,
                0,
            )
            .expect("lifecycle"),
        }
    }

    #[test]
    fn verified_sources_supply_both_evidence_keys_without_caller_rebinding() {
        let guest_key = SigningKey::from_bytes(&[73_u8; 32]);
        let host_key = SigningKey::from_bytes(&HOST_SIGNING_SEED);
        let request = test_macos_linux_vz_package_authority_request_for_execution_v1(
            digest("authority request"),
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            digest("artifact"),
            digest("request challenge"),
            digest("clone binding"),
        );
        let grant = test_macos_linux_vz_package_execution_grant_observation_with_evidence_keys_v1(
            &request,
            Sha256Digest::from_bytes(guest_key.verifying_key().as_bytes()),
            Sha256Digest::from_bytes(host_key.verifying_key().as_bytes()),
        );
        let host_network = host_network_v2();
        let root = test_verified_linux_vz_package_root_evidence_receipt_v1(
            &request,
            &grant,
            digest("root receipt"),
            digest("sensor session challenge"),
            host_network.process_evidence_sha256().clone(),
            digest("file evidence"),
            host_network.root_network_evidence_sha256().clone(),
            false,
        );
        let lifecycle = LinuxVzPackageExpectedHostCompositeLifecycleV1::new_v1(
            digest("serial log"),
            vec![digest("restricted evidence")],
            true,
            true,
            true,
            true,
            true,
            0,
        )
        .expect("lifecycle");
        assert_eq!(
            LinuxVzPackageHostCompositeExpectedBindingsV1::from_verified_sources_v1(
                &request,
                &grant,
                &root,
                &host_network,
                lifecycle.clone(),
            ),
            Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidBinding)
        );
        test_burn_macos_linux_vz_package_execution_request_v1(&grant);
        let expected = LinuxVzPackageHostCompositeExpectedBindingsV1::from_verified_sources_v1(
            &request,
            &grant,
            &root,
            &host_network,
            lifecycle,
        )
        .expect("verified bindings");
        assert_eq!(
            expected.host_evidence_public_key_sha256(),
            &Sha256Digest::from_bytes(host_key.verifying_key().as_bytes())
        );
    }

    fn signed_fixture_v1(
        evidence: &LinuxVzPackageHostCompositeEvidenceV1,
        expected: &LinuxVzPackageHostCompositeExpectedBindingsV1,
    ) -> Vec<u8> {
        let unsigned = expected_unsigned_receipt_v1(evidence, expected, CREATED_AT, EXPIRES_AT);
        let unsigned_bytes = canonical_json_v1(&unsigned).expect("unsigned");
        let signing_key = SigningKey::from_bytes(&HOST_SIGNING_SEED);
        let signature = signing_key.sign(&signature_message_v1(
            evidence.canonical_json_v1(),
            &unsigned_bytes,
        ));
        receipt_with_signature_v1(unsigned, &lower_hex_v1(&signature.to_bytes()))
    }

    fn receipt_with_signature_v1(
        unsigned: UnsignedHostCompositeReceiptWireV1,
        signature_hex: &str,
    ) -> Vec<u8> {
        let mut value = serde_json::to_value(unsigned).expect("receipt value");
        value.as_object_mut().expect("receipt object").insert(
            "signature_ed25519_hex".to_string(),
            serde_json::Value::String(signature_hex.to_string()),
        );
        serde_json_canonicalizer::to_vec(&value).expect("receipt")
    }

    #[test]
    fn swift_shaped_composite_is_independently_verified_and_never_authorizes() {
        let expected = swift_fixture_expected();
        expected.validate_v1().expect("expected bindings");
        let evidence_bytes =
            canonical_json_v1(&expected_evidence_wire_v1(&expected)).expect("evidence");
        let evidence =
            decode_linux_vz_package_host_composite_evidence_v1(&evidence_bytes, &expected)
                .expect("decode evidence");
        let unsigned = expected_unsigned_receipt_v1(&evidence, &expected, CREATED_AT, EXPIRES_AT);
        let receipt = receipt_with_signature_v1(unsigned, SWIFT_GOLDEN_SIGNATURE);
        let host_key = SigningKey::from_bytes(&HOST_SIGNING_SEED);
        let verified = verify_linux_vz_package_host_composite_receipt_v1(
            &evidence_bytes,
            &receipt,
            &expected,
            host_key.verifying_key().to_bytes(),
            CREATED_AT,
        )
        .expect("verify receipt");
        assert_eq!(
            verified.composite_evidence_sha256(),
            evidence.evidence_sha256()
        );
        assert!(!verified.composite_evidence_complete());
        assert!(!verified.authoritative_verdict_permitted());
        assert!(!verified.sync_back_permitted());
        assert_eq!(
            evidence.evidence_sha256().as_str(),
            "sha256:ab65634f16bbdf22c57a4f5146fa5e7885720b9722b3a1b8cd1c2b65fb46c5ee"
        );
        assert_eq!(
            verified.receipt_sha256().as_str(),
            "sha256:60e4cf6cfc353c32f34248b0240d23111a7f57b8157a16778ec122bbec3181a9"
        );
    }

    #[test]
    fn composite_rejects_rebinding_overclaim_wrong_key_time_and_signature() {
        let expected = swift_fixture_expected();
        let evidence_bytes =
            canonical_json_v1(&expected_evidence_wire_v1(&expected)).expect("evidence");
        let evidence =
            decode_linux_vz_package_host_composite_evidence_v1(&evidence_bytes, &expected)
                .expect("decode evidence");
        let receipt = signed_fixture_v1(&evidence, &expected);
        let host_key = SigningKey::from_bytes(&HOST_SIGNING_SEED);

        let mut overclaim: serde_json::Value =
            serde_json::from_slice(&evidence_bytes).expect("evidence json");
        overclaim["composite_evidence_complete"] = serde_json::Value::Bool(true);
        let overclaim = serde_json_canonicalizer::to_vec(&overclaim).expect("overclaim");
        assert_eq!(
            decode_linux_vz_package_host_composite_evidence_v1(&overclaim, &expected),
            Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidBinding)
        );
        assert_eq!(
            verify_linux_vz_package_host_composite_receipt_v1(
                &evidence_bytes,
                &receipt,
                &expected,
                SigningKey::from_bytes(&[9_u8; 32])
                    .verifying_key()
                    .to_bytes(),
                CREATED_AT,
            ),
            Err(LinuxVzPackageHostCompositeReceiptErrorV1::PublicKeyMismatch)
        );
        assert_eq!(
            verify_linux_vz_package_host_composite_receipt_v1(
                &evidence_bytes,
                &receipt,
                &expected,
                host_key.verifying_key().to_bytes(),
                EXPIRES_AT,
            ),
            Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidTime)
        );
        let mut forged: serde_json::Value = serde_json::from_slice(&receipt).expect("receipt json");
        forged["signature_ed25519_hex"] = serde_json::Value::String("0".repeat(128));
        let forged = serde_json_canonicalizer::to_vec(&forged).expect("forged");
        assert_eq!(
            verify_linux_vz_package_host_composite_receipt_v1(
                &evidence_bytes,
                &forged,
                &expected,
                host_key.verifying_key().to_bytes(),
                CREATED_AT,
            ),
            Err(LinuxVzPackageHostCompositeReceiptErrorV1::SignatureFailed)
        );

        assert_eq!(
            LinuxVzPackageExpectedHostCompositeLifecycleV1::new_v1(
                digest("serial"),
                vec![digest("restricted")],
                true,
                true,
                false,
                true,
                true,
                0,
            ),
            Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidLifecycle)
        );
        let mut unsorted_references = vec![digest("restricted-a"), digest("restricted-z")];
        unsorted_references.sort_by(|left, right| left.as_str().cmp(right.as_str()));
        unsorted_references.reverse();
        assert_eq!(
            LinuxVzPackageExpectedHostCompositeLifecycleV1::new_v1(
                digest("serial"),
                unsorted_references,
                true,
                true,
                true,
                true,
                true,
                0,
            ),
            Err(LinuxVzPackageHostCompositeReceiptErrorV1::InvalidLifecycle)
        );
    }

    fn lower_hex_v1(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
