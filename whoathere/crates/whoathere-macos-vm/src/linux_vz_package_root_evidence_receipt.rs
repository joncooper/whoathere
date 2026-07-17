#[cfg(test)]
use crate::LinuxVzPackageRootFileEvidenceEventV1;
use crate::{
    LinuxVzPackageProcessCompletionV1, LinuxVzPackageRootFileEvidenceV1,
    LinuxVzPackageRootNetworkEvidenceV1, LinuxVzPackageRootProcessEvidenceV1,
    LinuxVzPackageRootSensorIdentityV1, MacosLinuxVzPackageArtifactKindV1,
    MacosLinuxVzPackageAuthorityRequestV1, MacosLinuxVzPackageExecutionGrantObservationV1,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use whoathere_artifact::Sha256Digest;
use zeroize::{Zeroize, Zeroizing};

pub const LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_root_evidence_receipt.v1";
pub const LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_SCHEMA_V2: &str =
    "whoathere.linux_vz_package_root_evidence_receipt.v2";
pub const MAX_LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_BYTES_V1: usize = 256 * 1024;
pub const MAX_LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_LIFETIME_SECONDS_V1: u64 = 10 * 60;

const ROOT_EVIDENCE_RECEIPT_AUTHORITY_V1: &str = "guest_protected_sensor";
const ROOT_EVIDENCE_RECEIPT_SIGNATURE_DOMAIN_V2: &[u8] =
    b"whoathere.linux_vz_package_root_evidence_receipt.signature.v2\0";
const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageRootEvidenceReceiptErrorV1 {
    ActionAlreadyConsumed,
    SigningAuthorityAlreadyIssued,
    BindingMismatch,
    InvalidEvidence,
    InvalidCoverage,
    InvalidTime,
    PublicKeyMismatch,
    InvalidReceipt,
    NonCanonical,
    SignatureFailed,
    NotYetValid,
    Expired,
    LimitExceeded,
    Serialization,
}

impl LinuxVzPackageRootEvidenceReceiptErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::ActionAlreadyConsumed => {
                "linux_vz_package_root_evidence_receipt_action_already_consumed"
            }
            Self::SigningAuthorityAlreadyIssued => {
                "linux_vz_package_root_evidence_receipt_signing_authority_already_issued"
            }
            Self::BindingMismatch => "linux_vz_package_root_evidence_receipt_binding_mismatch",
            Self::InvalidEvidence => "linux_vz_package_root_evidence_receipt_evidence_invalid",
            Self::InvalidCoverage => "linux_vz_package_root_evidence_receipt_coverage_invalid",
            Self::InvalidTime => "linux_vz_package_root_evidence_receipt_time_invalid",
            Self::PublicKeyMismatch => "linux_vz_package_root_evidence_receipt_public_key_mismatch",
            Self::InvalidReceipt => "linux_vz_package_root_evidence_receipt_invalid",
            Self::NonCanonical => "linux_vz_package_root_evidence_receipt_noncanonical",
            Self::SignatureFailed => "linux_vz_package_root_evidence_receipt_signature_failed",
            Self::NotYetValid => "linux_vz_package_root_evidence_receipt_not_yet_valid",
            Self::Expired => "linux_vz_package_root_evidence_receipt_expired",
            Self::LimitExceeded => "linux_vz_package_root_evidence_receipt_limit_exceeded",
            Self::Serialization => "linux_vz_package_root_evidence_receipt_serialization_failed",
        }
    }
}

impl fmt::Display for LinuxVzPackageRootEvidenceReceiptErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageRootEvidenceReceiptErrorV1 {}

/// Exact, already-validated guest evidence and execution bindings to be signed by the protected
/// guest evidence authority.
///
/// Construction requires the decoded root process, file, and network evidence objects. This
/// receipt authenticates their exact canonical bytes and their honestly incomplete coverage; it
/// does not turn guest evidence into a verdict and it does not claim host-frame or VM-destruction
/// observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageRootEvidenceReceiptClaimsV1 {
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    package_authority_request_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    execution_grant_issued_at_unix_seconds: u64,
    execution_grant_verified_at_unix_seconds: u64,
    execution_grant_expires_at_unix_seconds: u64,
    execution_runtime_qualification_record_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    scenario_kind_sha256: Sha256Digest,
    scenario_policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    grant_challenge_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    guest_evidence_signer_sha256: Sha256Digest,
    protected_sensor_bundle_sha256: Sha256Digest,
    sensor_configuration_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    cgroup_name: String,
    cgroup_id: u64,
    root_runner_pid: u32,
    leader_pid: u32,
    process_started_monotonic_nanoseconds: u64,
    process_ended_monotonic_nanoseconds: u64,
    leader_supervisor_wait_status: u16,
    leader_terminal: crate::LinuxVzPackageProcessTerminalV1,
    leader_exit_status: Option<u8>,
    leader_termination_signal: Option<u8>,
    heartbeat_count: u64,
    process_evidence_sha256: Sha256Digest,
    process_evidence_byte_length: usize,
    process_source_event_count: u64,
    process_observation_count: usize,
    file_evidence_sha256: Sha256Digest,
    file_evidence_byte_length: usize,
    file_event_count: usize,
    file_change_count: usize,
    network_evidence_sha256: Sha256Digest,
    network_evidence_byte_length: usize,
    network_event_count: usize,
    egress_event_count: usize,
    egress_packet_coverage_complete: bool,
    egress_dropped_event_count: u64,
    egress_discarded_record_count: u64,
    connect_sendto_intent_coverage_complete: bool,
    guest_intent_coverage_complete: bool,
    host_frame_correlation_complete: bool,
    dns_intent_coverage_complete: bool,
    http_observation_complete: bool,
    composite_network_coverage_complete: bool,
    unobserved_network_capabilities: Vec<String>,
    file_declared_scope_complete: bool,
    file_global_mount_coverage_complete: bool,
    evidence_complete: bool,
    created_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl LinuxVzPackageRootEvidenceReceiptClaimsV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn from_validated_root_evidence_v1(
        request: &MacosLinuxVzPackageAuthorityRequestV1,
        grant: &MacosLinuxVzPackageExecutionGrantObservationV1,
        sensor_identity: &LinuxVzPackageRootSensorIdentityV1,
        sensor_session_challenge_sha256: Sha256Digest,
        launch_contract_sha256: Sha256Digest,
        process_plan_sha256: Sha256Digest,
        action_index: usize,
        cgroup_name: String,
        cgroup_id: u64,
        root_runner_pid: u32,
        leader_pid: u32,
        completion: &LinuxVzPackageProcessCompletionV1,
        heartbeat_count: u64,
        process: &LinuxVzPackageRootProcessEvidenceV1,
        file: &LinuxVzPackageRootFileEvidenceV1,
        network: &LinuxVzPackageRootNetworkEvidenceV1,
        created_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, LinuxVzPackageRootEvidenceReceiptErrorV1> {
        if request.request_sha256() != grant.package_authority_request_sha256()
            || request.request_challenge_sha256() != grant.request_challenge_sha256()
            || request.clone_binding_sha256() != grant.clone_binding_sha256()
            || request.qualified_telemetry_backend_sha256()
                != sensor_identity.qualified_telemetry_backend_sha256()
            || request.qualified_telemetry_backend_sha256() == request.request_challenge_sha256()
            || grant.package_uid() != PACKAGE_UID_V1
            || grant.package_gid() != PACKAGE_GID_V1
            || !grant.consumed()
            || !grant.execution_request_consumed()
            || request.sync_back_permitted()
            || grant.sync_back_permitted()
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch);
        }
        if sensor_session_challenge_sha256 == *request.request_challenge_sha256()
            || sensor_session_challenge_sha256 == *grant.grant_challenge_sha256()
            || sensor_session_challenge_sha256 == *grant.attempt_binding_sha256()
            || sensor_session_challenge_sha256 == *grant.clone_binding_sha256()
            || sensor_session_challenge_sha256 == Sha256Digest::from_bytes(&[])
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch);
        }
        if network.process_evidence_sha256() != process.payload_sha256()
            || process.payload_sha256() != &Sha256Digest::from_bytes(process.canonical_json_v1())
            || file.payload_sha256() != &Sha256Digest::from_bytes(file.canonical_json_v1())
            || network.payload_sha256() != &Sha256Digest::from_bytes(network.canonical_json_v1())
            || process.canonical_json_v1().is_empty()
            || file.canonical_json_v1().is_empty()
            || network.canonical_json_v1().is_empty()
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidEvidence);
        }
        if !process.coverage_complete()
            || process.raw_arguments_captured()
            || process.raw_exec_paths_captured()
            || !file.declared_scope_complete()
            || file.raw_paths_captured()
            || network.raw_addresses_serialized()
            || !network.connect_sendto_intent_coverage_complete()
            || !network.egress_packet_coverage_complete()
            || network.egress_dropped_event_count() != 0
            || network.egress_discarded_record_count() != 0
            || network.composite_network_coverage_complete()
                != (network.guest_intent_coverage_complete()
                    && network.host_frame_correlation_complete()
                    && network.dns_intent_coverage_complete()
                    && network.http_observation_complete())
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidCoverage);
        }
        if action_index == 0
            || cgroup_name != format!("whoathere-package-action-{action_index}")
            || cgroup_id == 0
            || root_runner_pid <= 1
            || leader_pid <= 1
            || leader_pid == root_runner_pid
            || heartbeat_count < 2
            || completion.process_started_monotonic_nanoseconds() == 0
            || completion.process_ended_monotonic_nanoseconds()
                <= completion.process_started_monotonic_nanoseconds()
            || process.leader_exit_monotonic_nanoseconds()
                < completion.process_started_monotonic_nanoseconds()
            || process.leader_exit_monotonic_nanoseconds()
                > completion.process_ended_monotonic_nanoseconds()
            || file.diff_completed_monotonic_nanoseconds()
                <= completion.process_ended_monotonic_nanoseconds()
            || process.leader_supervisor_wait_status() != completion.supervisor_wait_status()
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch);
        }

        let evidence_complete = process.coverage_complete()
            && file.declared_scope_complete()
            && file.global_mount_coverage_complete()
            && network.composite_network_coverage_complete();
        let value = Self {
            artifact_kind: request.artifact_kind(),
            artifact_sha256: request.artifact_sha256().clone(),
            artifact_byte_length: request.artifact_byte_length(),
            package_authority_request_sha256: request.request_sha256().clone(),
            execution_grant_sha256: grant.execution_grant_sha256().clone(),
            execution_grant_issued_at_unix_seconds: grant.issued_at_unix_seconds(),
            execution_grant_verified_at_unix_seconds: grant.verified_at_unix_seconds(),
            execution_grant_expires_at_unix_seconds: grant.expires_at_unix_seconds(),
            execution_runtime_qualification_record_sha256: grant
                .execution_runtime_qualification_record_sha256()
                .clone(),
            scenario_plan_sha256: request.scenario_plan_sha256().clone(),
            scenario_template_sha256: request.scenario_template_sha256().clone(),
            scenario_kind_sha256: request.scenario_kind_sha256().clone(),
            scenario_policy_sha256: request.scenario_policy_sha256().clone(),
            dependency_closure_sha256: request.dependency_closure_sha256().clone(),
            runtime_profile_sha256: request.runtime_profile_sha256().clone(),
            execution_runtime_rootfs_sha256: request.candidate_runtime_rootfs_sha256().clone(),
            execution_runtime_manifest_sha256: request.candidate_runtime_manifest_sha256().clone(),
            package_execution_runner_sha256: request.candidate_package_runner_sha256().clone(),
            qualified_telemetry_backend_sha256: request
                .qualified_telemetry_backend_sha256()
                .clone(),
            request_challenge_sha256: request.request_challenge_sha256().clone(),
            grant_challenge_sha256: grant.grant_challenge_sha256().clone(),
            attempt_binding_sha256: grant.attempt_binding_sha256().clone(),
            clone_binding_sha256: request.clone_binding_sha256().clone(),
            sensor_session_challenge_sha256,
            guest_evidence_public_key_sha256: grant.guest_evidence_public_key_sha256().clone(),
            guest_evidence_signer_sha256: sensor_identity.guest_evidence_signer_sha256().clone(),
            protected_sensor_bundle_sha256: sensor_identity
                .protected_sensor_bundle_sha256()
                .clone(),
            sensor_configuration_sha256: sensor_identity.sensor_configuration_sha256().clone(),
            launch_contract_sha256,
            process_plan_sha256,
            action_index,
            cgroup_name,
            cgroup_id,
            root_runner_pid,
            leader_pid,
            process_started_monotonic_nanoseconds: completion
                .process_started_monotonic_nanoseconds(),
            process_ended_monotonic_nanoseconds: completion.process_ended_monotonic_nanoseconds(),
            leader_supervisor_wait_status: completion.supervisor_wait_status(),
            leader_terminal: completion.terminal(),
            leader_exit_status: completion.exit_status(),
            leader_termination_signal: completion.termination_signal(),
            heartbeat_count,
            process_evidence_sha256: process.payload_sha256().clone(),
            process_evidence_byte_length: process.canonical_json_v1().len(),
            process_source_event_count: process.source_event_count(),
            process_observation_count: process.observations().len(),
            file_evidence_sha256: file.payload_sha256().clone(),
            file_evidence_byte_length: file.canonical_json_v1().len(),
            file_event_count: file.events().len(),
            file_change_count: file.changes().len(),
            network_evidence_sha256: network.payload_sha256().clone(),
            network_evidence_byte_length: network.canonical_json_v1().len(),
            network_event_count: network.events().len(),
            egress_event_count: network.egress_observations().len(),
            egress_packet_coverage_complete: network.egress_packet_coverage_complete(),
            egress_dropped_event_count: network.egress_dropped_event_count(),
            egress_discarded_record_count: network.egress_discarded_record_count(),
            connect_sendto_intent_coverage_complete: network
                .connect_sendto_intent_coverage_complete(),
            guest_intent_coverage_complete: network.guest_intent_coverage_complete(),
            host_frame_correlation_complete: network.host_frame_correlation_complete(),
            dns_intent_coverage_complete: network.dns_intent_coverage_complete(),
            http_observation_complete: network.http_observation_complete(),
            composite_network_coverage_complete: network.composite_network_coverage_complete(),
            unobserved_network_capabilities: network.unobserved_capabilities().to_vec(),
            file_declared_scope_complete: file.declared_scope_complete(),
            file_global_mount_coverage_complete: file.global_mount_coverage_complete(),
            evidence_complete,
            created_at_unix_seconds,
            expires_at_unix_seconds,
        };
        value.validate_v1()?;
        Ok(value)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageRootEvidenceReceiptErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let required_digests = [
            &self.artifact_sha256,
            &self.package_authority_request_sha256,
            &self.execution_grant_sha256,
            &self.execution_runtime_qualification_record_sha256,
            &self.scenario_plan_sha256,
            &self.scenario_template_sha256,
            &self.scenario_kind_sha256,
            &self.scenario_policy_sha256,
            &self.dependency_closure_sha256,
            &self.runtime_profile_sha256,
            &self.execution_runtime_rootfs_sha256,
            &self.execution_runtime_manifest_sha256,
            &self.package_execution_runner_sha256,
            &self.qualified_telemetry_backend_sha256,
            &self.request_challenge_sha256,
            &self.grant_challenge_sha256,
            &self.attempt_binding_sha256,
            &self.clone_binding_sha256,
            &self.sensor_session_challenge_sha256,
            &self.guest_evidence_public_key_sha256,
            &self.guest_evidence_signer_sha256,
            &self.protected_sensor_bundle_sha256,
            &self.sensor_configuration_sha256,
            &self.launch_contract_sha256,
            &self.process_plan_sha256,
            &self.process_evidence_sha256,
            &self.file_evidence_sha256,
            &self.network_evidence_sha256,
        ];
        if required_digests.contains(&&empty)
            || required_digests
                .iter()
                .enumerate()
                .any(|(index, digest)| required_digests[..index].contains(digest))
            || self.artifact_byte_length == 0
            || self.process_evidence_byte_length == 0
            || self.file_evidence_byte_length == 0
            || self.network_evidence_byte_length == 0
            || self.process_source_event_count == 0
            || self.process_observation_count == 0
            || self.process_observation_count > self.process_source_event_count as usize
            || self.heartbeat_count < 2
            || self.action_index == 0
            || self.cgroup_name != format!("whoathere-package-action-{}", self.action_index)
            || self.cgroup_id == 0
            || self.root_runner_pid <= 1
            || self.leader_pid <= 1
            || self.root_runner_pid == self.leader_pid
            || self.process_started_monotonic_nanoseconds == 0
            || self.process_ended_monotonic_nanoseconds
                <= self.process_started_monotonic_nanoseconds
            || self.execution_grant_issued_at_unix_seconds == 0
            || self.execution_grant_verified_at_unix_seconds
                < self.execution_grant_issued_at_unix_seconds
            || self.execution_grant_expires_at_unix_seconds
                <= self.execution_grant_verified_at_unix_seconds
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidEvidence);
        }
        let expected_complete = self.file_declared_scope_complete
            && self.file_global_mount_coverage_complete
            && self.composite_network_coverage_complete;
        if !self.connect_sendto_intent_coverage_complete
            || !self.egress_packet_coverage_complete
            || self.egress_dropped_event_count != 0
            || self.egress_discarded_record_count != 0
            || self.composite_network_coverage_complete
                != (self.guest_intent_coverage_complete
                    && self.host_frame_correlation_complete
                    && self.dns_intent_coverage_complete
                    && self.http_observation_complete)
            || self.evidence_complete != expected_complete
            || (self.evidence_complete && !self.unobserved_network_capabilities.is_empty())
            || (!self.evidence_complete && self.unobserved_network_capabilities.is_empty())
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidCoverage);
        }
        let lifetime = self
            .expires_at_unix_seconds
            .checked_sub(self.created_at_unix_seconds)
            .ok_or(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidTime)?;
        if self.created_at_unix_seconds < self.execution_grant_verified_at_unix_seconds
            || self.created_at_unix_seconds >= self.execution_grant_expires_at_unix_seconds
            || self.expires_at_unix_seconds > self.execution_grant_expires_at_unix_seconds
            || lifetime == 0
            || lifetime > MAX_LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_LIFETIME_SECONDS_V1
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidTime);
        }
        Ok(())
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn sensor_session_challenge_sha256(&self) -> &Sha256Digest {
        &self.sensor_session_challenge_sha256
    }

    pub fn process_evidence_sha256(&self) -> &Sha256Digest {
        &self.process_evidence_sha256
    }

    pub fn file_evidence_sha256(&self) -> &Sha256Digest {
        &self.file_evidence_sha256
    }

    pub fn network_evidence_sha256(&self) -> &Sha256Digest {
        &self.network_evidence_sha256
    }

    pub const fn evidence_complete(&self) -> bool {
        self.evidence_complete
    }

    pub const fn host_composition_required(&self) -> bool {
        true
    }

    pub const fn authoritative_verdict_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

/// Protected guest authority for receipts emitted after one exact execution request was consumed.
///
/// The signing key never crosses this interface, and every nonzero action index is burned before
/// claims validation. A malformed evidence attempt therefore cannot be repaired and re-signed for
/// the same package process action.
pub struct LinuxVzPackageRootEvidenceSigningAuthorityV1<'execution> {
    request: &'execution MacosLinuxVzPackageAuthorityRequestV1,
    grant: &'execution MacosLinuxVzPackageExecutionGrantObservationV1,
    signing_key: SigningKey,
    burned_action_indexes: BTreeSet<usize>,
}

impl fmt::Debug for LinuxVzPackageRootEvidenceSigningAuthorityV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxVzPackageRootEvidenceSigningAuthorityV1")
            .field(
                "package_authority_request_sha256",
                &self.request.request_sha256(),
            )
            .field(
                "execution_grant_sha256",
                &self.grant.execution_grant_sha256(),
            )
            .field("burned_action_count", &self.burned_action_indexes.len())
            .field("signing_key", &"<protected-and-zeroized-on-drop>")
            .finish()
    }
}

impl<'execution> LinuxVzPackageRootEvidenceSigningAuthorityV1<'execution> {
    pub fn from_consumed_execution_v1(
        request: &'execution MacosLinuxVzPackageAuthorityRequestV1,
        grant: &'execution MacosLinuxVzPackageExecutionGrantObservationV1,
        mut signing_seed: Zeroizing<[u8; 32]>,
    ) -> Result<Self, LinuxVzPackageRootEvidenceReceiptErrorV1> {
        if !grant.consumed()
            || !grant.execution_request_consumed()
            || request.sync_back_permitted()
            || grant.sync_back_permitted()
            || grant.package_uid() != PACKAGE_UID_V1
            || grant.package_gid() != PACKAGE_GID_V1
            || request.request_sha256() != grant.package_authority_request_sha256()
            || request.request_challenge_sha256() != grant.request_challenge_sha256()
            || request.clone_binding_sha256() != grant.clone_binding_sha256()
            || grant.issued_at_unix_seconds() == 0
            || grant.verified_at_unix_seconds() < grant.issued_at_unix_seconds()
            || grant.verified_at_unix_seconds() >= grant.expires_at_unix_seconds()
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch);
        }
        if !grant.burn_root_evidence_signing_authority_v1() {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::SigningAuthorityAlreadyIssued);
        }
        let signing_key = SigningKey::from_bytes(&signing_seed);
        signing_seed.zeroize();
        if signing_key.verifying_key().is_weak()
            || Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes())
                != *grant.guest_evidence_public_key_sha256()
        {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch);
        }
        Ok(Self {
            request,
            grant,
            signing_key,
            burned_action_indexes: BTreeSet::new(),
        })
    }

    pub fn sign_bound_claims_v1(
        &mut self,
        claims: &LinuxVzPackageRootEvidenceReceiptClaimsV1,
    ) -> Result<Vec<u8>, LinuxVzPackageRootEvidenceReceiptErrorV1> {
        if claims.action_index == 0 {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch);
        }
        if !self.burned_action_indexes.insert(claims.action_index) {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::ActionAlreadyConsumed);
        }
        claims.validate_v1()?;
        if !self.claims_match_execution_v1(claims) {
            return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch);
        }
        sign_linux_vz_package_root_evidence_receipt_with_key_v1(claims, &self.signing_key)
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn request_v1(&self) -> &'execution MacosLinuxVzPackageAuthorityRequestV1 {
        self.request
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn grant_v1(
        &self,
    ) -> &'execution MacosLinuxVzPackageExecutionGrantObservationV1 {
        self.grant
    }

    fn claims_match_execution_v1(
        &self,
        claims: &LinuxVzPackageRootEvidenceReceiptClaimsV1,
    ) -> bool {
        claims.artifact_kind == self.request.artifact_kind()
            && claims.artifact_sha256 == *self.request.artifact_sha256()
            && claims.artifact_byte_length == self.request.artifact_byte_length()
            && claims.package_authority_request_sha256 == *self.request.request_sha256()
            && claims.execution_grant_sha256 == *self.grant.execution_grant_sha256()
            && claims.execution_grant_issued_at_unix_seconds == self.grant.issued_at_unix_seconds()
            && claims.execution_grant_verified_at_unix_seconds
                == self.grant.verified_at_unix_seconds()
            && claims.execution_grant_expires_at_unix_seconds
                == self.grant.expires_at_unix_seconds()
            && claims.execution_runtime_qualification_record_sha256
                == *self.grant.execution_runtime_qualification_record_sha256()
            && claims.scenario_plan_sha256 == *self.request.scenario_plan_sha256()
            && claims.scenario_template_sha256 == *self.request.scenario_template_sha256()
            && claims.scenario_kind_sha256 == *self.request.scenario_kind_sha256()
            && claims.scenario_policy_sha256 == *self.request.scenario_policy_sha256()
            && claims.dependency_closure_sha256 == *self.request.dependency_closure_sha256()
            && claims.runtime_profile_sha256 == *self.request.runtime_profile_sha256()
            && claims.execution_runtime_rootfs_sha256
                == *self.request.candidate_runtime_rootfs_sha256()
            && claims.execution_runtime_manifest_sha256
                == *self.request.candidate_runtime_manifest_sha256()
            && claims.package_execution_runner_sha256
                == *self.request.candidate_package_runner_sha256()
            && claims.qualified_telemetry_backend_sha256
                == *self.request.qualified_telemetry_backend_sha256()
            && claims.request_challenge_sha256 == *self.request.request_challenge_sha256()
            && claims.grant_challenge_sha256 == *self.grant.grant_challenge_sha256()
            && claims.attempt_binding_sha256 == *self.grant.attempt_binding_sha256()
            && claims.clone_binding_sha256 == *self.request.clone_binding_sha256()
            && claims.guest_evidence_public_key_sha256
                == *self.grant.guest_evidence_public_key_sha256()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedRootEvidenceReceiptWireV1 {
    schema_version: String,
    authority: String,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: String,
    package_authority_request_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    execution_grant_issued_at_unix_seconds: String,
    execution_grant_verified_at_unix_seconds: String,
    execution_grant_expires_at_unix_seconds: String,
    execution_runtime_qualification_record_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    scenario_kind_sha256: Sha256Digest,
    scenario_policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    grant_challenge_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    guest_evidence_signer_sha256: Sha256Digest,
    protected_sensor_bundle_sha256: Sha256Digest,
    sensor_configuration_sha256: Sha256Digest,
    launch_contract_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: String,
    cgroup_name: String,
    cgroup_id: String,
    root_runner_pid: String,
    leader_pid: String,
    process_started_monotonic_nanoseconds: String,
    process_ended_monotonic_nanoseconds: String,
    leader_supervisor_wait_status: String,
    leader_terminal: crate::LinuxVzPackageProcessTerminalV1,
    leader_exit_status: Option<String>,
    leader_termination_signal: Option<String>,
    heartbeat_count: String,
    process_evidence_sha256: Sha256Digest,
    process_evidence_byte_length: String,
    process_source_event_count: String,
    process_observation_count: String,
    file_evidence_sha256: Sha256Digest,
    file_evidence_byte_length: String,
    file_event_count: String,
    file_change_count: String,
    network_evidence_sha256: Sha256Digest,
    network_evidence_byte_length: String,
    network_event_count: String,
    egress_event_count: String,
    egress_packet_coverage_complete: bool,
    egress_dropped_event_count: String,
    egress_discarded_record_count: String,
    connect_sendto_intent_coverage_complete: bool,
    guest_intent_coverage_complete: bool,
    host_frame_correlation_complete: bool,
    dns_intent_coverage_complete: bool,
    http_observation_complete: bool,
    composite_network_coverage_complete: bool,
    unobserved_network_capabilities: Vec<String>,
    process_coverage_complete: bool,
    file_declared_scope_complete: bool,
    file_global_mount_coverage_complete: bool,
    evidence_complete: bool,
    evidence_truncated: bool,
    dropped_event_count: String,
    public_network_route_present: bool,
    raw_arguments_captured: bool,
    raw_exec_paths_captured: bool,
    raw_file_paths_captured: bool,
    raw_network_addresses_captured: bool,
    package_uid: String,
    package_gid: String,
    sync_back: bool,
    host_composition_required: bool,
    vm_destruction_observed: bool,
    authoritative_verdict_permitted: bool,
    key_id_sha256: Sha256Digest,
    created_at_unix_seconds: String,
    expires_at_unix_seconds: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootEvidenceReceiptWireV1 {
    claims: UnsignedRootEvidenceReceiptWireV1,
    signature_ed25519_hex: String,
}

impl RootEvidenceReceiptWireV1 {
    fn from_unsigned(claims: UnsignedRootEvidenceReceiptWireV1, signature: String) -> Self {
        Self {
            claims,
            signature_ed25519_hex: signature,
        }
    }

    fn into_unsigned(self) -> UnsignedRootEvidenceReceiptWireV1 {
        self.claims
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLinuxVzPackageRootEvidenceReceiptV1 {
    receipt_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    leader_pid: u32,
    process_evidence_sha256: Sha256Digest,
    file_evidence_sha256: Sha256Digest,
    file_evidence_byte_length: usize,
    file_event_count: usize,
    network_evidence_sha256: Sha256Digest,
    evidence_complete: bool,
}

impl VerifiedLinuxVzPackageRootEvidenceReceiptV1 {
    pub fn receipt_sha256(&self) -> &Sha256Digest {
        &self.receipt_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn sensor_session_challenge_sha256(&self) -> &Sha256Digest {
        &self.sensor_session_challenge_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    /// The signed process leader for this action. Keeping it in the verified projection lets
    /// downstream evidence partitioners reject tooling-leader marker activity without reparsing
    /// producer-authored JSON.
    pub const fn leader_pid(&self) -> u32 {
        self.leader_pid
    }

    pub fn process_evidence_sha256(&self) -> &Sha256Digest {
        &self.process_evidence_sha256
    }

    pub fn file_evidence_sha256(&self) -> &Sha256Digest {
        &self.file_evidence_sha256
    }

    pub const fn file_evidence_byte_length(&self) -> usize {
        self.file_evidence_byte_length
    }

    pub const fn file_event_count(&self) -> usize {
        self.file_event_count
    }

    pub fn network_evidence_sha256(&self) -> &Sha256Digest {
        &self.network_evidence_sha256
    }

    pub const fn evidence_complete(&self) -> bool {
        self.evidence_complete
    }

    pub const fn host_composition_required(&self) -> bool {
        true
    }

    pub const fn authoritative_verdict_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn test_verified_linux_vz_package_root_evidence_receipt_v1(
    request: &MacosLinuxVzPackageAuthorityRequestV1,
    grant: &MacosLinuxVzPackageExecutionGrantObservationV1,
    receipt_sha256: Sha256Digest,
    sensor_session_challenge_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    process_evidence_sha256: Sha256Digest,
    file_evidence_sha256: Sha256Digest,
    file_evidence_byte_length: usize,
    file_event_count: usize,
    network_evidence_sha256: Sha256Digest,
    evidence_complete: bool,
) -> VerifiedLinuxVzPackageRootEvidenceReceiptV1 {
    VerifiedLinuxVzPackageRootEvidenceReceiptV1 {
        receipt_sha256,
        artifact_sha256: request.artifact_sha256().clone(),
        execution_grant_sha256: grant.execution_grant_sha256().clone(),
        sensor_session_challenge_sha256,
        process_plan_sha256,
        action_index,
        leader_pid: 42,
        process_evidence_sha256,
        file_evidence_sha256,
        file_evidence_byte_length,
        file_event_count,
        network_evidence_sha256,
        evidence_complete,
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub(crate) fn test_linux_vz_package_root_evidence_receipt_claims_for_file_v1(
    request: &MacosLinuxVzPackageAuthorityRequestV1,
    grant: &MacosLinuxVzPackageExecutionGrantObservationV1,
    file: &LinuxVzPackageRootFileEvidenceV1,
    process_plan_sha256: Sha256Digest,
    action_index: usize,
    cgroup_id: u64,
    root_runner_pid: u32,
    leader_pid: u32,
    process_started_monotonic_nanoseconds: u64,
    process_ended_monotonic_nanoseconds: u64,
    signing_seed: [u8; 32],
) -> LinuxVzPackageRootEvidenceReceiptClaimsV1 {
    let process_evidence = br#"{"type":"process"}"#;
    let network_evidence = br#"{"type":"network"}"#;
    let verifying_key = SigningKey::from_bytes(&signing_seed).verifying_key();
    assert_eq!(
        grant.guest_evidence_public_key_sha256(),
        &Sha256Digest::from_bytes(verifying_key.as_bytes())
    );
    assert_eq!(
        file.events()
            .iter()
            .map(LinuxVzPackageRootFileEvidenceEventV1::cgroup_id)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([cgroup_id])
    );
    let claims = LinuxVzPackageRootEvidenceReceiptClaimsV1 {
        artifact_kind: request.artifact_kind(),
        artifact_sha256: request.artifact_sha256().clone(),
        artifact_byte_length: request.artifact_byte_length(),
        package_authority_request_sha256: request.request_sha256().clone(),
        execution_grant_sha256: grant.execution_grant_sha256().clone(),
        execution_grant_issued_at_unix_seconds: grant.issued_at_unix_seconds(),
        execution_grant_verified_at_unix_seconds: grant.verified_at_unix_seconds(),
        execution_grant_expires_at_unix_seconds: grant.expires_at_unix_seconds(),
        execution_runtime_qualification_record_sha256: grant
            .execution_runtime_qualification_record_sha256()
            .clone(),
        scenario_plan_sha256: request.scenario_plan_sha256().clone(),
        scenario_template_sha256: request.scenario_template_sha256().clone(),
        scenario_kind_sha256: request.scenario_kind_sha256().clone(),
        scenario_policy_sha256: request.scenario_policy_sha256().clone(),
        dependency_closure_sha256: request.dependency_closure_sha256().clone(),
        runtime_profile_sha256: request.runtime_profile_sha256().clone(),
        execution_runtime_rootfs_sha256: request.candidate_runtime_rootfs_sha256().clone(),
        execution_runtime_manifest_sha256: request.candidate_runtime_manifest_sha256().clone(),
        package_execution_runner_sha256: request.candidate_package_runner_sha256().clone(),
        qualified_telemetry_backend_sha256: request.qualified_telemetry_backend_sha256().clone(),
        request_challenge_sha256: request.request_challenge_sha256().clone(),
        grant_challenge_sha256: grant.grant_challenge_sha256().clone(),
        attempt_binding_sha256: grant.attempt_binding_sha256().clone(),
        clone_binding_sha256: request.clone_binding_sha256().clone(),
        sensor_session_challenge_sha256: Sha256Digest::from_bytes(b"sensor session challenge"),
        guest_evidence_public_key_sha256: grant.guest_evidence_public_key_sha256().clone(),
        guest_evidence_signer_sha256: Sha256Digest::from_bytes(b"guest evidence signer"),
        protected_sensor_bundle_sha256: Sha256Digest::from_bytes(b"protected sensor bundle"),
        sensor_configuration_sha256: Sha256Digest::from_bytes(b"sensor configuration"),
        launch_contract_sha256: Sha256Digest::from_bytes(b"launch contract"),
        process_plan_sha256,
        action_index,
        cgroup_name: format!("whoathere-package-action-{action_index}"),
        cgroup_id,
        root_runner_pid,
        leader_pid,
        process_started_monotonic_nanoseconds,
        process_ended_monotonic_nanoseconds,
        leader_supervisor_wait_status: 0,
        leader_terminal: crate::LinuxVzPackageProcessTerminalV1::Exited,
        leader_exit_status: Some(0),
        leader_termination_signal: None,
        heartbeat_count: 2,
        process_evidence_sha256: Sha256Digest::from_bytes(process_evidence),
        process_evidence_byte_length: process_evidence.len(),
        process_source_event_count: 1,
        process_observation_count: 1,
        file_evidence_sha256: file.payload_sha256().clone(),
        file_evidence_byte_length: file.canonical_json_v1().len(),
        file_event_count: file.events().len(),
        file_change_count: file.changes().len(),
        network_evidence_sha256: Sha256Digest::from_bytes(network_evidence),
        network_evidence_byte_length: network_evidence.len(),
        network_event_count: 0,
        egress_event_count: 0,
        egress_packet_coverage_complete: true,
        egress_dropped_event_count: 0,
        egress_discarded_record_count: 0,
        connect_sendto_intent_coverage_complete: true,
        guest_intent_coverage_complete: false,
        host_frame_correlation_complete: false,
        dns_intent_coverage_complete: false,
        http_observation_complete: false,
        composite_network_coverage_complete: false,
        unobserved_network_capabilities: vec![
            "additional_network_syscalls".to_string(),
            "dns_intent".to_string(),
            "host_frame_correlation".to_string(),
            "http_observation".to_string(),
        ],
        file_declared_scope_complete: file.declared_scope_complete(),
        file_global_mount_coverage_complete: file.global_mount_coverage_complete(),
        evidence_complete: false,
        created_at_unix_seconds: grant.verified_at_unix_seconds() + 1,
        expires_at_unix_seconds: grant.expires_at_unix_seconds() - 1,
    };
    claims.validate_v1().expect("test root receipt claims");
    claims
}

pub fn sign_linux_vz_package_root_evidence_receipt_v1(
    claims: &LinuxVzPackageRootEvidenceReceiptClaimsV1,
    mut signing_seed: [u8; 32],
) -> Result<Vec<u8>, LinuxVzPackageRootEvidenceReceiptErrorV1> {
    claims.validate_v1()?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    if Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes())
        != claims.guest_evidence_public_key_sha256
    {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch);
    }
    sign_linux_vz_package_root_evidence_receipt_with_key_v1(claims, &signing_key)
}

fn sign_linux_vz_package_root_evidence_receipt_with_key_v1(
    claims: &LinuxVzPackageRootEvidenceReceiptClaimsV1,
    signing_key: &SigningKey,
) -> Result<Vec<u8>, LinuxVzPackageRootEvidenceReceiptErrorV1> {
    let unsigned = unsigned_receipt_v1(claims);
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::Serialization)?;
    let signature = signing_key.sign(&signature_message_v1(&unsigned_bytes));
    let wire =
        RootEvidenceReceiptWireV1::from_unsigned(unsigned, lower_hex_v1(&signature.to_bytes()));
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::Serialization)?;
    if bytes.is_empty() || bytes.len() > MAX_LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_BYTES_V1 {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::LimitExceeded);
    }
    Ok(bytes)
}

pub fn verify_linux_vz_package_root_evidence_receipt_v1(
    claims: &LinuxVzPackageRootEvidenceReceiptClaimsV1,
    receipt_bytes: &[u8],
    verifying_key_bytes: [u8; 32],
    observed_at_unix_seconds: u64,
) -> Result<VerifiedLinuxVzPackageRootEvidenceReceiptV1, LinuxVzPackageRootEvidenceReceiptErrorV1> {
    claims.validate_v1()?;
    if observed_at_unix_seconds < claims.created_at_unix_seconds {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::NotYetValid);
    }
    if observed_at_unix_seconds >= claims.expires_at_unix_seconds {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::Expired);
    }
    if receipt_bytes.is_empty()
        || receipt_bytes.len() > MAX_LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_BYTES_V1
    {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::LimitExceeded);
    }
    if Sha256Digest::from_bytes(&verifying_key_bytes) != claims.guest_evidence_public_key_sha256 {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch)?;
    if verifying_key.is_weak() {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(receipt_bytes);
    let wire = RootEvidenceReceiptWireV1::deserialize(&mut deserializer)
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidReceipt)?;
    deserializer
        .end()
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidReceipt)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::Serialization)?;
    if canonical != receipt_bytes || !valid_signature_hex_v1(&wire.signature_ed25519_hex) {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::NonCanonical);
    }
    let signature_hex = wire.signature_ed25519_hex.clone();
    let unsigned = wire.into_unsigned();
    let expected = unsigned_receipt_v1(claims);
    if unsigned != expected {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch);
    }
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::Serialization)?;
    let signature = Signature::from_bytes(&decode_signature_v1(&signature_hex)?);
    verifying_key
        .verify_strict(&signature_message_v1(&unsigned_bytes), &signature)
        .map_err(|_| LinuxVzPackageRootEvidenceReceiptErrorV1::SignatureFailed)?;
    Ok(VerifiedLinuxVzPackageRootEvidenceReceiptV1 {
        receipt_sha256: Sha256Digest::from_bytes(receipt_bytes),
        artifact_sha256: claims.artifact_sha256.clone(),
        execution_grant_sha256: claims.execution_grant_sha256.clone(),
        sensor_session_challenge_sha256: claims.sensor_session_challenge_sha256.clone(),
        process_plan_sha256: claims.process_plan_sha256.clone(),
        action_index: claims.action_index,
        leader_pid: claims.leader_pid,
        process_evidence_sha256: claims.process_evidence_sha256.clone(),
        file_evidence_sha256: claims.file_evidence_sha256.clone(),
        file_evidence_byte_length: claims.file_evidence_byte_length,
        file_event_count: claims.file_event_count,
        network_evidence_sha256: claims.network_evidence_sha256.clone(),
        evidence_complete: claims.evidence_complete,
    })
}

fn unsigned_receipt_v1(
    claims: &LinuxVzPackageRootEvidenceReceiptClaimsV1,
) -> UnsignedRootEvidenceReceiptWireV1 {
    UnsignedRootEvidenceReceiptWireV1 {
        schema_version: LINUX_VZ_PACKAGE_ROOT_EVIDENCE_RECEIPT_SCHEMA_V2.to_string(),
        authority: ROOT_EVIDENCE_RECEIPT_AUTHORITY_V1.to_string(),
        artifact_kind: claims.artifact_kind,
        artifact_sha256: claims.artifact_sha256.clone(),
        artifact_byte_length: claims.artifact_byte_length.to_string(),
        package_authority_request_sha256: claims.package_authority_request_sha256.clone(),
        execution_grant_sha256: claims.execution_grant_sha256.clone(),
        execution_grant_issued_at_unix_seconds: claims
            .execution_grant_issued_at_unix_seconds
            .to_string(),
        execution_grant_verified_at_unix_seconds: claims
            .execution_grant_verified_at_unix_seconds
            .to_string(),
        execution_grant_expires_at_unix_seconds: claims
            .execution_grant_expires_at_unix_seconds
            .to_string(),
        execution_runtime_qualification_record_sha256: claims
            .execution_runtime_qualification_record_sha256
            .clone(),
        scenario_plan_sha256: claims.scenario_plan_sha256.clone(),
        scenario_template_sha256: claims.scenario_template_sha256.clone(),
        scenario_kind_sha256: claims.scenario_kind_sha256.clone(),
        scenario_policy_sha256: claims.scenario_policy_sha256.clone(),
        dependency_closure_sha256: claims.dependency_closure_sha256.clone(),
        runtime_profile_sha256: claims.runtime_profile_sha256.clone(),
        execution_runtime_rootfs_sha256: claims.execution_runtime_rootfs_sha256.clone(),
        execution_runtime_manifest_sha256: claims.execution_runtime_manifest_sha256.clone(),
        package_execution_runner_sha256: claims.package_execution_runner_sha256.clone(),
        qualified_telemetry_backend_sha256: claims.qualified_telemetry_backend_sha256.clone(),
        request_challenge_sha256: claims.request_challenge_sha256.clone(),
        grant_challenge_sha256: claims.grant_challenge_sha256.clone(),
        attempt_binding_sha256: claims.attempt_binding_sha256.clone(),
        clone_binding_sha256: claims.clone_binding_sha256.clone(),
        sensor_session_challenge_sha256: claims.sensor_session_challenge_sha256.clone(),
        guest_evidence_public_key_sha256: claims.guest_evidence_public_key_sha256.clone(),
        guest_evidence_signer_sha256: claims.guest_evidence_signer_sha256.clone(),
        protected_sensor_bundle_sha256: claims.protected_sensor_bundle_sha256.clone(),
        sensor_configuration_sha256: claims.sensor_configuration_sha256.clone(),
        launch_contract_sha256: claims.launch_contract_sha256.clone(),
        process_plan_sha256: claims.process_plan_sha256.clone(),
        action_index: claims.action_index.to_string(),
        cgroup_name: claims.cgroup_name.clone(),
        cgroup_id: claims.cgroup_id.to_string(),
        root_runner_pid: claims.root_runner_pid.to_string(),
        leader_pid: claims.leader_pid.to_string(),
        process_started_monotonic_nanoseconds: claims
            .process_started_monotonic_nanoseconds
            .to_string(),
        process_ended_monotonic_nanoseconds: claims.process_ended_monotonic_nanoseconds.to_string(),
        leader_supervisor_wait_status: claims.leader_supervisor_wait_status.to_string(),
        leader_terminal: claims.leader_terminal,
        leader_exit_status: claims.leader_exit_status.map(|value| value.to_string()),
        leader_termination_signal: claims
            .leader_termination_signal
            .map(|value| value.to_string()),
        heartbeat_count: claims.heartbeat_count.to_string(),
        process_evidence_sha256: claims.process_evidence_sha256.clone(),
        process_evidence_byte_length: claims.process_evidence_byte_length.to_string(),
        process_source_event_count: claims.process_source_event_count.to_string(),
        process_observation_count: claims.process_observation_count.to_string(),
        file_evidence_sha256: claims.file_evidence_sha256.clone(),
        file_evidence_byte_length: claims.file_evidence_byte_length.to_string(),
        file_event_count: claims.file_event_count.to_string(),
        file_change_count: claims.file_change_count.to_string(),
        network_evidence_sha256: claims.network_evidence_sha256.clone(),
        network_evidence_byte_length: claims.network_evidence_byte_length.to_string(),
        network_event_count: claims.network_event_count.to_string(),
        egress_event_count: claims.egress_event_count.to_string(),
        egress_packet_coverage_complete: claims.egress_packet_coverage_complete,
        egress_dropped_event_count: claims.egress_dropped_event_count.to_string(),
        egress_discarded_record_count: claims.egress_discarded_record_count.to_string(),
        connect_sendto_intent_coverage_complete: claims.connect_sendto_intent_coverage_complete,
        guest_intent_coverage_complete: claims.guest_intent_coverage_complete,
        host_frame_correlation_complete: claims.host_frame_correlation_complete,
        dns_intent_coverage_complete: claims.dns_intent_coverage_complete,
        http_observation_complete: claims.http_observation_complete,
        composite_network_coverage_complete: claims.composite_network_coverage_complete,
        unobserved_network_capabilities: claims.unobserved_network_capabilities.clone(),
        process_coverage_complete: true,
        file_declared_scope_complete: claims.file_declared_scope_complete,
        file_global_mount_coverage_complete: claims.file_global_mount_coverage_complete,
        evidence_complete: claims.evidence_complete,
        evidence_truncated: false,
        dropped_event_count: "0".to_string(),
        public_network_route_present: false,
        raw_arguments_captured: false,
        raw_exec_paths_captured: false,
        raw_file_paths_captured: false,
        raw_network_addresses_captured: false,
        package_uid: PACKAGE_UID_V1.to_string(),
        package_gid: PACKAGE_GID_V1.to_string(),
        sync_back: false,
        host_composition_required: true,
        vm_destruction_observed: false,
        authoritative_verdict_permitted: false,
        key_id_sha256: claims.guest_evidence_public_key_sha256.clone(),
        created_at_unix_seconds: claims.created_at_unix_seconds.to_string(),
        expires_at_unix_seconds: claims.expires_at_unix_seconds.to_string(),
    }
}

fn signature_message_v1(unsigned_receipt: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        ROOT_EVIDENCE_RECEIPT_SIGNATURE_DOMAIN_V2.len() + unsigned_receipt.len(),
    );
    message.extend_from_slice(ROOT_EVIDENCE_RECEIPT_SIGNATURE_DOMAIN_V2);
    message.extend_from_slice(unsigned_receipt);
    message
}

fn lower_hex_v1(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

fn valid_signature_hex_v1(value: &str) -> bool {
    value.len() == 128
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn decode_signature_v1(value: &str) -> Result<[u8; 64], LinuxVzPackageRootEvidenceReceiptErrorV1> {
    if !valid_signature_hex_v1(value) {
        return Err(LinuxVzPackageRootEvidenceReceiptErrorV1::NonCanonical);
    }
    let mut bytes = [0_u8; 64];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble_v1(pair[0])? << 4) | hex_nibble_v1(pair[1])?;
    }
    Ok(bytes)
}

fn hex_nibble_v1(byte: u8) -> Result<u8, LinuxVzPackageRootEvidenceReceiptErrorV1> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(LinuxVzPackageRootEvidenceReceiptErrorV1::NonCanonical),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        linux_vz_package_authority_request::test_macos_linux_vz_package_authority_request_for_execution_v1,
        linux_vz_package_execution_grant::{
            test_burn_macos_linux_vz_package_execution_request_v1,
            test_macos_linux_vz_package_execution_grant_observation_with_evidence_keys_v1,
        },
    };

    const SIGNING_SEED: [u8; 32] = [73_u8; 32];
    const GRANT_VERIFIED_AT: u64 = 1_750_000_000;
    const CREATED_AT: u64 = GRANT_VERIFIED_AT + 1;
    const EXPIRES_AT: u64 = CREATED_AT + 300;
    const GRANT_EXPIRES_AT: u64 = EXPIRES_AT + 60;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn claims_v1() -> LinuxVzPackageRootEvidenceReceiptClaimsV1 {
        let public_key = SigningKey::from_bytes(&SIGNING_SEED).verifying_key();
        LinuxVzPackageRootEvidenceReceiptClaimsV1 {
            artifact_kind: MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            artifact_sha256: digest("artifact"),
            artifact_byte_length: 4096,
            package_authority_request_sha256: digest("authority request"),
            execution_grant_sha256: digest("execution grant"),
            execution_grant_issued_at_unix_seconds: GRANT_VERIFIED_AT - 60,
            execution_grant_verified_at_unix_seconds: GRANT_VERIFIED_AT,
            execution_grant_expires_at_unix_seconds: GRANT_EXPIRES_AT,
            execution_runtime_qualification_record_sha256: digest("qualification record"),
            scenario_plan_sha256: digest("scenario plan"),
            scenario_template_sha256: digest("scenario template"),
            scenario_kind_sha256: digest("scenario kind"),
            scenario_policy_sha256: digest("scenario policy"),
            dependency_closure_sha256: digest("dependency closure"),
            runtime_profile_sha256: digest("runtime profile"),
            execution_runtime_rootfs_sha256: digest("runtime rootfs"),
            execution_runtime_manifest_sha256: digest("runtime manifest"),
            package_execution_runner_sha256: digest("package runner"),
            qualified_telemetry_backend_sha256: digest("telemetry backend"),
            request_challenge_sha256: digest("request challenge"),
            grant_challenge_sha256: digest("grant challenge"),
            attempt_binding_sha256: digest("attempt binding"),
            clone_binding_sha256: digest("clone binding"),
            sensor_session_challenge_sha256: digest("sensor session challenge"),
            guest_evidence_public_key_sha256: Sha256Digest::from_bytes(public_key.as_bytes()),
            guest_evidence_signer_sha256: digest("guest evidence signer"),
            protected_sensor_bundle_sha256: digest("protected sensor bundle"),
            sensor_configuration_sha256: digest("sensor configuration"),
            launch_contract_sha256: digest("launch contract"),
            process_plan_sha256: digest("process plan"),
            action_index: 1,
            cgroup_name: "whoathere-package-action-1".to_string(),
            cgroup_id: 9001,
            root_runner_pid: 40,
            leader_pid: 42,
            process_started_monotonic_nanoseconds: 100,
            process_ended_monotonic_nanoseconds: 300,
            leader_supervisor_wait_status: 0,
            leader_terminal: crate::LinuxVzPackageProcessTerminalV1::Exited,
            leader_exit_status: Some(0),
            leader_termination_signal: None,
            heartbeat_count: 2,
            process_evidence_sha256: digest("process evidence"),
            process_evidence_byte_length: 6303,
            process_source_event_count: 18,
            process_observation_count: 10,
            file_evidence_sha256: digest("file evidence"),
            file_evidence_byte_length: 6373,
            file_event_count: 6,
            file_change_count: 1,
            network_evidence_sha256: digest("network evidence"),
            network_evidence_byte_length: 2459,
            network_event_count: 2,
            egress_event_count: 1,
            egress_packet_coverage_complete: true,
            egress_dropped_event_count: 0,
            egress_discarded_record_count: 0,
            connect_sendto_intent_coverage_complete: true,
            guest_intent_coverage_complete: false,
            host_frame_correlation_complete: false,
            dns_intent_coverage_complete: false,
            http_observation_complete: false,
            composite_network_coverage_complete: false,
            unobserved_network_capabilities: vec![
                "additional_network_syscalls".to_string(),
                "dns_intent".to_string(),
                "host_frame_correlation".to_string(),
                "http_observation".to_string(),
            ],
            file_declared_scope_complete: true,
            file_global_mount_coverage_complete: false,
            evidence_complete: false,
            created_at_unix_seconds: CREATED_AT,
            expires_at_unix_seconds: EXPIRES_AT,
        }
    }

    fn verifying_key_v1() -> [u8; 32] {
        *SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .as_bytes()
    }

    fn exact_consumed_execution_v1() -> (
        MacosLinuxVzPackageAuthorityRequestV1,
        MacosLinuxVzPackageExecutionGrantObservationV1,
    ) {
        let request = test_macos_linux_vz_package_authority_request_for_execution_v1(
            digest("authority request"),
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            digest("artifact"),
            digest("request challenge"),
            digest("clone binding"),
        );
        let grant = test_macos_linux_vz_package_execution_grant_observation_with_evidence_keys_v1(
            &request,
            Sha256Digest::from_bytes(&verifying_key_v1()),
            digest("host evidence key"),
        );
        (request, grant)
    }

    fn claims_bound_to_execution_v1(
        request: &MacosLinuxVzPackageAuthorityRequestV1,
        grant: &MacosLinuxVzPackageExecutionGrantObservationV1,
    ) -> LinuxVzPackageRootEvidenceReceiptClaimsV1 {
        let mut claims = claims_v1();
        claims.artifact_kind = request.artifact_kind();
        claims.artifact_sha256 = request.artifact_sha256().clone();
        claims.artifact_byte_length = request.artifact_byte_length();
        claims.package_authority_request_sha256 = request.request_sha256().clone();
        claims.execution_grant_sha256 = grant.execution_grant_sha256().clone();
        claims.execution_grant_issued_at_unix_seconds = grant.issued_at_unix_seconds();
        claims.execution_grant_verified_at_unix_seconds = grant.verified_at_unix_seconds();
        claims.execution_grant_expires_at_unix_seconds = grant.expires_at_unix_seconds();
        claims.execution_runtime_qualification_record_sha256 = grant
            .execution_runtime_qualification_record_sha256()
            .clone();
        claims.scenario_plan_sha256 = request.scenario_plan_sha256().clone();
        claims.scenario_template_sha256 = request.scenario_template_sha256().clone();
        claims.scenario_kind_sha256 = request.scenario_kind_sha256().clone();
        claims.scenario_policy_sha256 = request.scenario_policy_sha256().clone();
        claims.dependency_closure_sha256 = request.dependency_closure_sha256().clone();
        claims.runtime_profile_sha256 = request.runtime_profile_sha256().clone();
        claims.execution_runtime_rootfs_sha256 = request.candidate_runtime_rootfs_sha256().clone();
        claims.execution_runtime_manifest_sha256 =
            request.candidate_runtime_manifest_sha256().clone();
        claims.package_execution_runner_sha256 = request.candidate_package_runner_sha256().clone();
        claims.qualified_telemetry_backend_sha256 =
            request.qualified_telemetry_backend_sha256().clone();
        claims.request_challenge_sha256 = request.request_challenge_sha256().clone();
        claims.grant_challenge_sha256 = grant.grant_challenge_sha256().clone();
        claims.attempt_binding_sha256 = grant.attempt_binding_sha256().clone();
        claims.clone_binding_sha256 = request.clone_binding_sha256().clone();
        claims.guest_evidence_public_key_sha256 = grant.guest_evidence_public_key_sha256().clone();
        claims.created_at_unix_seconds = grant.verified_at_unix_seconds() + 1;
        claims.expires_at_unix_seconds = grant.expires_at_unix_seconds() - 1;
        claims
    }

    fn cross_language_claims_v2() -> LinuxVzPackageRootEvidenceReceiptClaimsV1 {
        let mut claims = claims_v1();
        let process = br#"{"type":"process"}"#;
        let file = br#"{"type":"file"}"#;
        let network = br#"{"type":"network"}"#;
        claims.process_evidence_sha256 = Sha256Digest::from_bytes(process);
        claims.process_evidence_byte_length = process.len();
        claims.file_evidence_sha256 = Sha256Digest::from_bytes(file);
        claims.file_evidence_byte_length = file.len();
        claims.network_evidence_sha256 = Sha256Digest::from_bytes(network);
        claims.network_evidence_byte_length = network.len();
        claims
    }

    #[test]
    fn cross_language_root_receipt_fixture_v2_is_stable() {
        let claims = cross_language_claims_v2();
        let receipt = sign_linux_vz_package_root_evidence_receipt_v1(&claims, SIGNING_SEED)
            .expect("sign receipt");
        let wire: serde_json::Value = serde_json::from_slice(&receipt).expect("receipt json");
        assert_eq!(
            wire["signature_ed25519_hex"].as_str().expect("signature"),
            "053fa74681b22607ebc86a26d7341d07da26cb0b091f0a6c94683e09569740a2\
             f989a9a360ba134bf65bce99ab705553d66ca25eb88784fe94ae55a1e9a78701"
        );
        assert_eq!(
            Sha256Digest::from_bytes(&receipt).as_str(),
            "sha256:dc91df448364fa0d8ddb2fb60d4f7c89027f3326d7ae9136a70bebaedc6d8a22"
        );
        assert_eq!(
            lower_hex_v1(&verifying_key_v1()),
            "772c8a442b7db06e166cfbc1ccbcbcde6f3eba76a4e98ef3ffc519502237d6ef"
        );
        assert_eq!(
            Sha256Digest::from_bytes(
                &serde_json_canonicalizer::to_vec(&wire["claims"]).expect("claims")
            )
            .as_str(),
            "sha256:9c24aa8dd83ad562f72415d1c110bff61548412b2f18aedf75e182cc39d776f9"
        );
    }

    #[test]
    fn protected_signer_requires_consumed_request_and_burns_each_action() {
        let (wrong_key_request, wrong_key_grant) = exact_consumed_execution_v1();
        assert!(matches!(
            LinuxVzPackageRootEvidenceSigningAuthorityV1::from_consumed_execution_v1(
                &wrong_key_request,
                &wrong_key_grant,
                Zeroizing::new(SIGNING_SEED),
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch)
        ));
        assert!(!wrong_key_grant.root_evidence_signing_authority_issued());
        test_burn_macos_linux_vz_package_execution_request_v1(&wrong_key_grant);
        assert!(matches!(
            LinuxVzPackageRootEvidenceSigningAuthorityV1::from_consumed_execution_v1(
                &wrong_key_request,
                &wrong_key_grant,
                Zeroizing::new([8_u8; 32]),
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch)
        ));
        assert!(wrong_key_grant.root_evidence_signing_authority_issued());
        assert!(matches!(
            LinuxVzPackageRootEvidenceSigningAuthorityV1::from_consumed_execution_v1(
                &wrong_key_request,
                &wrong_key_grant,
                Zeroizing::new(SIGNING_SEED),
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::SigningAuthorityAlreadyIssued)
        ));

        let (request, grant) = exact_consumed_execution_v1();
        test_burn_macos_linux_vz_package_execution_request_v1(&grant);
        let claims = claims_bound_to_execution_v1(&request, &grant);
        let mut authority =
            LinuxVzPackageRootEvidenceSigningAuthorityV1::from_consumed_execution_v1(
                &request,
                &grant,
                Zeroizing::new(SIGNING_SEED),
            )
            .expect("protected signing authority");
        assert!(grant.root_evidence_signing_authority_issued());
        assert!(matches!(
            LinuxVzPackageRootEvidenceSigningAuthorityV1::from_consumed_execution_v1(
                &request,
                &grant,
                Zeroizing::new(SIGNING_SEED),
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::SigningAuthorityAlreadyIssued)
        ));
        let debug = format!("{authority:?}");
        assert!(debug.contains(grant.execution_grant_sha256().as_str()));
        assert!(!debug.contains(&lower_hex_v1(&SIGNING_SEED)));
        let receipt = authority
            .sign_bound_claims_v1(&claims)
            .expect("bound receipt");
        let verified = verify_linux_vz_package_root_evidence_receipt_v1(
            &claims,
            &receipt,
            verifying_key_v1(),
            claims.created_at_unix_seconds,
        )
        .expect("verified protected receipt");
        assert!(!verified.evidence_complete());
        assert!(verified.host_composition_required());
        assert!(!verified.authoritative_verdict_permitted());
        assert!(!verified.sync_back_permitted());
        assert_eq!(
            authority.sign_bound_claims_v1(&claims),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::ActionAlreadyConsumed)
        );
    }

    #[test]
    fn protected_signer_burns_rebound_action_before_validation_or_retry() {
        let (request, grant) = exact_consumed_execution_v1();
        test_burn_macos_linux_vz_package_execution_request_v1(&grant);
        let valid = claims_bound_to_execution_v1(&request, &grant);
        let mut rebound = valid.clone();
        rebound.artifact_sha256 = digest("rebound artifact");
        let mut authority =
            LinuxVzPackageRootEvidenceSigningAuthorityV1::from_consumed_execution_v1(
                &request,
                &grant,
                Zeroizing::new(SIGNING_SEED),
            )
            .expect("protected signing authority");
        assert_eq!(
            authority.sign_bound_claims_v1(&rebound),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch)
        );
        assert_eq!(
            authority.sign_bound_claims_v1(&valid),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::ActionAlreadyConsumed)
        );
    }

    #[test]
    fn signed_receipt_binds_exact_incomplete_evidence_without_verdict_authority() {
        let claims = claims_v1();
        let receipt = sign_linux_vz_package_root_evidence_receipt_v1(&claims, SIGNING_SEED)
            .expect("sign receipt");
        let verified = verify_linux_vz_package_root_evidence_receipt_v1(
            &claims,
            &receipt,
            verifying_key_v1(),
            CREATED_AT,
        )
        .expect("verify receipt");
        assert_eq!(verified.artifact_sha256(), claims.artifact_sha256());
        assert_eq!(
            verified.execution_grant_sha256(),
            claims.execution_grant_sha256()
        );
        assert_eq!(
            verified.process_evidence_sha256(),
            claims.process_evidence_sha256()
        );
        assert_eq!(
            verified.file_evidence_sha256(),
            claims.file_evidence_sha256()
        );
        assert_eq!(
            verified.network_evidence_sha256(),
            claims.network_evidence_sha256()
        );
        assert!(!verified.evidence_complete());
        assert!(verified.host_composition_required());
        assert!(!verified.authoritative_verdict_permitted());
        assert!(!verified.sync_back_permitted());
    }

    #[test]
    fn evidence_rebinding_and_signature_mutation_are_rejected() {
        let claims = claims_v1();
        let receipt = sign_linux_vz_package_root_evidence_receipt_v1(&claims, SIGNING_SEED)
            .expect("sign receipt");
        let mut rebound = claims.clone();
        rebound.network_evidence_sha256 = digest("different network evidence");
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &rebound,
                &receipt,
                verifying_key_v1(),
                CREATED_AT,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::BindingMismatch)
        );

        let mut value: serde_json::Value = serde_json::from_slice(&receipt).expect("receipt json");
        value["signature_ed25519_hex"] = serde_json::Value::String("00".repeat(64));
        let mutated = serde_json_canonicalizer::to_vec(&value).expect("canonical mutation");
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &claims,
                &mutated,
                verifying_key_v1(),
                CREATED_AT,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::SignatureFailed)
        );
    }

    #[test]
    fn canonical_time_key_and_coverage_fail_closed() {
        let claims = claims_v1();
        let receipt = sign_linux_vz_package_root_evidence_receipt_v1(&claims, SIGNING_SEED)
            .expect("sign receipt");
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &claims,
                &receipt,
                verifying_key_v1(),
                CREATED_AT - 1,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::NotYetValid)
        );
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &claims,
                &receipt,
                verifying_key_v1(),
                EXPIRES_AT,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::Expired)
        );
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &claims, &receipt, [8_u8; 32], CREATED_AT,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch)
        );

        let mut whitespace = receipt.clone();
        whitespace.push(b'\n');
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &claims,
                &whitespace,
                verifying_key_v1(),
                CREATED_AT,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::NonCanonical)
        );

        let mut overclaim = claims;
        overclaim.evidence_complete = true;
        assert_eq!(
            sign_linux_vz_package_root_evidence_receipt_v1(&overclaim, SIGNING_SEED),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidCoverage)
        );

        let mut missing_egress = claims_v1();
        missing_egress.egress_packet_coverage_complete = false;
        assert_eq!(
            sign_linux_vz_package_root_evidence_receipt_v1(&missing_egress, SIGNING_SEED),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidCoverage)
        );

        let mut dropped_egress = claims_v1();
        dropped_egress.egress_dropped_event_count = 1;
        assert_eq!(
            sign_linux_vz_package_root_evidence_receipt_v1(&dropped_egress, SIGNING_SEED),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::InvalidCoverage)
        );
    }
}
