use crate::{MacosLinuxVzPackageArtifactKindV1, MacosLinuxVzPackageAuthorityRequestV1};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactTelemetrySyncBackPolicyV1;
use zeroize::Zeroize;

pub const MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_execution_grant.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_BYTES_V1: usize = 64 * 1024;
pub const MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_LIFETIME_SECONDS_V1: u64 = 15 * 60;

const EXECUTION_GRANT_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.macos_linux_vz_package_execution_grant.signature.v1\0";
const EXECUTION_GRANT_AUTHORITY_V1: &str = "distinct_package_execution_grant_issuer";
const PACKAGE_UID_V1: u32 = 65_534;
const PACKAGE_GID_V1: u32 = 65_534;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageExecutionScopeV1 {
    OneTypedScenarioOneAttempt,
}

/// Opaque proof that a separately measured execution-capable runtime passed its future physical
/// qualification gate. There is intentionally no public constructor in this checkpoint. A later
/// evidence verifier must be the only production path that can create this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1 {
    qualification_record_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_rootfs_byte_length: u64,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    execution_grant_issuer_public_key_sha256: Sha256Digest,
    package_uid: u32,
    package_gid: u32,
}

impl VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1 {
    pub fn qualification_record_sha256(&self) -> &Sha256Digest {
        &self.qualification_record_sha256
    }

    pub fn qualified_telemetry_backend_sha256(&self) -> &Sha256Digest {
        &self.qualified_telemetry_backend_sha256
    }

    pub fn execution_runtime_rootfs_sha256(&self) -> &Sha256Digest {
        &self.execution_runtime_rootfs_sha256
    }

    pub const fn execution_runtime_rootfs_byte_length(&self) -> u64 {
        self.execution_runtime_rootfs_byte_length
    }

    pub fn execution_runtime_manifest_sha256(&self) -> &Sha256Digest {
        &self.execution_runtime_manifest_sha256
    }

    pub fn package_execution_runner_sha256(&self) -> &Sha256Digest {
        &self.package_execution_runner_sha256
    }

    pub fn execution_grant_issuer_public_key_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_issuer_public_key_sha256
    }

    pub const fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub const fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub const fn execution_authority_issuance_permitted(&self) -> bool {
        true
    }

    pub const fn package_execution_scope(&self) -> MacosLinuxVzPackageExecutionScopeV1 {
        MacosLinuxVzPackageExecutionScopeV1::OneTypedScenarioOneAttempt
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }

    fn validate(&self) -> Result<(), MacosLinuxVzPackageExecutionGrantErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let digests = [
            &self.qualification_record_sha256,
            &self.qualified_telemetry_backend_sha256,
            &self.execution_runtime_rootfs_sha256,
            &self.execution_runtime_manifest_sha256,
            &self.package_execution_runner_sha256,
            &self.guest_evidence_public_key_sha256,
            &self.host_evidence_public_key_sha256,
            &self.execution_grant_issuer_public_key_sha256,
        ];
        if digests.contains(&&empty)
            || digests
                .iter()
                .enumerate()
                .any(|(index, digest)| digests[..index].contains(digest))
            || self.execution_runtime_rootfs_byte_length == 0
            || self.package_uid != PACKAGE_UID_V1
            || self.package_gid != PACKAGE_GID_V1
        {
            return Err(MacosLinuxVzPackageExecutionGrantErrorV1::QualificationInvalid);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageExecutionGrantContextV1 {
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    package_authority_request_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    execution_runtime_qualification_record_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_rootfs_byte_length: u64,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    execution_grant_issuer_public_key_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    grant_challenge_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    package_uid: u32,
    package_gid: u32,
}

impl fmt::Debug for MacosLinuxVzPackageExecutionGrantContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionGrantContextV1")
            .field(
                "package_authority_request_sha256",
                &self.package_authority_request_sha256,
            )
            .field(
                "execution_runtime_qualification_record_sha256",
                &self.execution_runtime_qualification_record_sha256,
            )
            .field("grant_challenge_sha256", &self.grant_challenge_sha256)
            .field("attempt_binding_sha256", &self.attempt_binding_sha256)
            .field("clone_binding_sha256", &self.clone_binding_sha256)
            .field("issued_at_unix_seconds", &self.issued_at_unix_seconds)
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

impl MacosLinuxVzPackageExecutionGrantContextV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request: &MacosLinuxVzPackageAuthorityRequestV1,
        qualification: &VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1,
        grant_challenge: [u8; 32],
        attempt_binding_sha256: Sha256Digest,
        issued_at_unix_seconds: u64,
        lifetime_seconds: u64,
    ) -> Result<Self, MacosLinuxVzPackageExecutionGrantErrorV1> {
        qualification.validate()?;
        let expires_at_unix_seconds = issued_at_unix_seconds
            .checked_add(lifetime_seconds)
            .ok_or(MacosLinuxVzPackageExecutionGrantErrorV1::InvalidTime)?;
        let grant_challenge_sha256 = Sha256Digest::from_bytes(&grant_challenge);
        let empty = Sha256Digest::from_bytes(&[]);
        if request.package_execution_authority_permitted()
            || request.sync_back_permitted()
            || !qualification.execution_authority_issuance_permitted()
            || qualification.sync_back_permitted()
            || request.qualified_telemetry_backend_sha256()
                != qualification.qualified_telemetry_backend_sha256()
            || request.candidate_runtime_rootfs_sha256()
                != qualification.execution_runtime_rootfs_sha256()
            || request.candidate_runtime_rootfs_byte_length()
                != qualification.execution_runtime_rootfs_byte_length()
            || request.candidate_runtime_manifest_sha256()
                != qualification.execution_runtime_manifest_sha256()
            || request.candidate_package_runner_sha256()
                != qualification.package_execution_runner_sha256()
            || grant_challenge == [0_u8; 32]
            || attempt_binding_sha256 == empty
            || grant_challenge_sha256 == *request.request_challenge_sha256()
            || grant_challenge_sha256 == *request.clone_binding_sha256()
            || grant_challenge_sha256 == attempt_binding_sha256
            || attempt_binding_sha256 == *request.request_challenge_sha256()
            || attempt_binding_sha256 == *request.clone_binding_sha256()
            || issued_at_unix_seconds == 0
            || lifetime_seconds == 0
            || lifetime_seconds > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_LIFETIME_SECONDS_V1
            || expires_at_unix_seconds <= issued_at_unix_seconds
        {
            return Err(MacosLinuxVzPackageExecutionGrantErrorV1::ContextBindingMismatch);
        }
        Ok(Self {
            artifact_kind: request.artifact_kind(),
            artifact_sha256: request.artifact_sha256().clone(),
            package_authority_request_sha256: request.request_sha256().clone(),
            scenario_plan_sha256: request.scenario_plan_sha256().clone(),
            scenario_template_sha256: request.scenario_template_sha256().clone(),
            runtime_profile_sha256: request.runtime_profile_sha256().clone(),
            qualified_telemetry_backend_sha256: request
                .qualified_telemetry_backend_sha256()
                .clone(),
            execution_runtime_qualification_record_sha256: qualification
                .qualification_record_sha256()
                .clone(),
            execution_runtime_rootfs_sha256: qualification
                .execution_runtime_rootfs_sha256()
                .clone(),
            execution_runtime_rootfs_byte_length: qualification
                .execution_runtime_rootfs_byte_length(),
            execution_runtime_manifest_sha256: qualification
                .execution_runtime_manifest_sha256()
                .clone(),
            package_execution_runner_sha256: qualification
                .package_execution_runner_sha256()
                .clone(),
            execution_grant_issuer_public_key_sha256: qualification
                .execution_grant_issuer_public_key_sha256()
                .clone(),
            request_challenge_sha256: request.request_challenge_sha256().clone(),
            grant_challenge_sha256,
            attempt_binding_sha256,
            clone_binding_sha256: request.clone_binding_sha256().clone(),
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            package_uid: qualification.package_uid(),
            package_gid: qualification.package_gid(),
        })
    }

    pub fn package_authority_request_sha256(&self) -> &Sha256Digest {
        &self.package_authority_request_sha256
    }

    pub fn execution_runtime_qualification_record_sha256(&self) -> &Sha256Digest {
        &self.execution_runtime_qualification_record_sha256
    }

    pub fn grant_challenge_sha256(&self) -> &Sha256Digest {
        &self.grant_challenge_sha256
    }

    pub fn attempt_binding_sha256(&self) -> &Sha256Digest {
        &self.attempt_binding_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    pub const fn package_execution_scope(&self) -> MacosLinuxVzPackageExecutionScopeV1 {
        MacosLinuxVzPackageExecutionScopeV1::OneTypedScenarioOneAttempt
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzPackageExecutionGrantErrorV1 {
    QualificationInvalid,
    ContextBindingMismatch,
    InvalidTime,
    PublicKeyMismatch,
    InvalidGrant,
    NonCanonical,
    SignatureFailed,
    AlreadyConsumed,
    NotYetValid,
    Expired,
    LimitExceeded,
    Serialization,
}

impl MacosLinuxVzPackageExecutionGrantErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::QualificationInvalid => "macos_linux_vz_execution_grant_qualification_invalid",
            Self::ContextBindingMismatch => {
                "macos_linux_vz_execution_grant_context_binding_mismatch"
            }
            Self::InvalidTime => "macos_linux_vz_execution_grant_time_invalid",
            Self::PublicKeyMismatch => "macos_linux_vz_execution_grant_public_key_mismatch",
            Self::InvalidGrant => "macos_linux_vz_execution_grant_invalid",
            Self::NonCanonical => "macos_linux_vz_execution_grant_noncanonical",
            Self::SignatureFailed => "macos_linux_vz_execution_grant_signature_failed",
            Self::AlreadyConsumed => "macos_linux_vz_execution_grant_already_consumed",
            Self::NotYetValid => "macos_linux_vz_execution_grant_not_yet_valid",
            Self::Expired => "macos_linux_vz_execution_grant_expired",
            Self::LimitExceeded => "macos_linux_vz_execution_grant_limit_exceeded",
            Self::Serialization => "macos_linux_vz_execution_grant_serialization_failed",
        }
    }
}

impl fmt::Display for MacosLinuxVzPackageExecutionGrantErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzPackageExecutionGrantErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UnsignedExecutionGrantWireV1 {
    schema_version: String,
    authority: String,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    package_authority_request_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    execution_runtime_qualification_record_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_rootfs_byte_length: String,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    execution_grant_issuer_public_key_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    grant_challenge_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    issued_at_unix_seconds: String,
    expires_at_unix_seconds: String,
    package_uid: String,
    package_gid: String,
    attempt_limit: String,
    execution_scope: MacosLinuxVzPackageExecutionScopeV1,
    public_network_route_present: bool,
    execution_authority_issued: bool,
    package_execution_permitted: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionGrantWireV1 {
    schema_version: String,
    authority: String,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    package_authority_request_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    execution_runtime_qualification_record_sha256: Sha256Digest,
    execution_runtime_rootfs_sha256: Sha256Digest,
    execution_runtime_rootfs_byte_length: String,
    execution_runtime_manifest_sha256: Sha256Digest,
    package_execution_runner_sha256: Sha256Digest,
    execution_grant_issuer_public_key_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    grant_challenge_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    issued_at_unix_seconds: String,
    expires_at_unix_seconds: String,
    package_uid: String,
    package_gid: String,
    attempt_limit: String,
    execution_scope: MacosLinuxVzPackageExecutionScopeV1,
    public_network_route_present: bool,
    execution_authority_issued: bool,
    package_execution_permitted: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
    signature_ed25519_hex: String,
}

impl ExecutionGrantWireV1 {
    fn from_unsigned(value: UnsignedExecutionGrantWireV1, signature_ed25519_hex: String) -> Self {
        Self {
            schema_version: value.schema_version,
            authority: value.authority,
            artifact_kind: value.artifact_kind,
            artifact_sha256: value.artifact_sha256,
            package_authority_request_sha256: value.package_authority_request_sha256,
            scenario_plan_sha256: value.scenario_plan_sha256,
            scenario_template_sha256: value.scenario_template_sha256,
            runtime_profile_sha256: value.runtime_profile_sha256,
            qualified_telemetry_backend_sha256: value.qualified_telemetry_backend_sha256,
            execution_runtime_qualification_record_sha256: value
                .execution_runtime_qualification_record_sha256,
            execution_runtime_rootfs_sha256: value.execution_runtime_rootfs_sha256,
            execution_runtime_rootfs_byte_length: value.execution_runtime_rootfs_byte_length,
            execution_runtime_manifest_sha256: value.execution_runtime_manifest_sha256,
            package_execution_runner_sha256: value.package_execution_runner_sha256,
            execution_grant_issuer_public_key_sha256: value
                .execution_grant_issuer_public_key_sha256,
            request_challenge_sha256: value.request_challenge_sha256,
            grant_challenge_sha256: value.grant_challenge_sha256,
            attempt_binding_sha256: value.attempt_binding_sha256,
            clone_binding_sha256: value.clone_binding_sha256,
            issued_at_unix_seconds: value.issued_at_unix_seconds,
            expires_at_unix_seconds: value.expires_at_unix_seconds,
            package_uid: value.package_uid,
            package_gid: value.package_gid,
            attempt_limit: value.attempt_limit,
            execution_scope: value.execution_scope,
            public_network_route_present: value.public_network_route_present,
            execution_authority_issued: value.execution_authority_issued,
            package_execution_permitted: value.package_execution_permitted,
            sync_back_policy: value.sync_back_policy,
            signature_ed25519_hex,
        }
    }

    fn into_unsigned(self) -> UnsignedExecutionGrantWireV1 {
        UnsignedExecutionGrantWireV1 {
            schema_version: self.schema_version,
            authority: self.authority,
            artifact_kind: self.artifact_kind,
            artifact_sha256: self.artifact_sha256,
            package_authority_request_sha256: self.package_authority_request_sha256,
            scenario_plan_sha256: self.scenario_plan_sha256,
            scenario_template_sha256: self.scenario_template_sha256,
            runtime_profile_sha256: self.runtime_profile_sha256,
            qualified_telemetry_backend_sha256: self.qualified_telemetry_backend_sha256,
            execution_runtime_qualification_record_sha256: self
                .execution_runtime_qualification_record_sha256,
            execution_runtime_rootfs_sha256: self.execution_runtime_rootfs_sha256,
            execution_runtime_rootfs_byte_length: self.execution_runtime_rootfs_byte_length,
            execution_runtime_manifest_sha256: self.execution_runtime_manifest_sha256,
            package_execution_runner_sha256: self.package_execution_runner_sha256,
            execution_grant_issuer_public_key_sha256: self.execution_grant_issuer_public_key_sha256,
            request_challenge_sha256: self.request_challenge_sha256,
            grant_challenge_sha256: self.grant_challenge_sha256,
            attempt_binding_sha256: self.attempt_binding_sha256,
            clone_binding_sha256: self.clone_binding_sha256,
            issued_at_unix_seconds: self.issued_at_unix_seconds,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            package_uid: self.package_uid,
            package_gid: self.package_gid,
            attempt_limit: self.attempt_limit,
            execution_scope: self.execution_scope,
            public_network_route_present: self.public_network_route_present,
            execution_authority_issued: self.execution_authority_issued,
            package_execution_permitted: self.package_execution_permitted,
            sync_back_policy: self.sync_back_policy,
        }
    }
}

pub struct MacosLinuxVzPackageExecutionGrantBytesV1 {
    bytes: Vec<u8>,
}

impl MacosLinuxVzPackageExecutionGrantBytesV1 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for MacosLinuxVzPackageExecutionGrantBytesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionGrantBytesV1")
            .field("byte_length", &self.bytes.len())
            .field("bytes", &"<redacted-and-zeroized-on-drop>")
            .finish()
    }
}

impl Drop for MacosLinuxVzPackageExecutionGrantBytesV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct MacosLinuxVzPackageExecutionGrantObservationV1 {
    execution_grant_sha256: Sha256Digest,
    package_authority_request_sha256: Sha256Digest,
    execution_runtime_qualification_record_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    grant_challenge_sha256: Sha256Digest,
    attempt_binding_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    verified_at_unix_seconds: u64,
    package_uid: u32,
    package_gid: u32,
    consumed: bool,
}

impl MacosLinuxVzPackageExecutionGrantObservationV1 {
    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn package_authority_request_sha256(&self) -> &Sha256Digest {
        &self.package_authority_request_sha256
    }

    pub fn execution_runtime_qualification_record_sha256(&self) -> &Sha256Digest {
        &self.execution_runtime_qualification_record_sha256
    }

    pub fn request_challenge_sha256(&self) -> &Sha256Digest {
        &self.request_challenge_sha256
    }

    pub fn grant_challenge_sha256(&self) -> &Sha256Digest {
        &self.grant_challenge_sha256
    }

    pub fn attempt_binding_sha256(&self) -> &Sha256Digest {
        &self.attempt_binding_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    pub const fn verified_at_unix_seconds(&self) -> u64 {
        self.verified_at_unix_seconds
    }

    pub const fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub const fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub const fn consumed(&self) -> bool {
        self.consumed
    }

    pub const fn package_execution_scope(&self) -> MacosLinuxVzPackageExecutionScopeV1 {
        MacosLinuxVzPackageExecutionScopeV1::OneTypedScenarioOneAttempt
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

pub fn sign_macos_linux_vz_package_execution_grant_v1(
    context: &MacosLinuxVzPackageExecutionGrantContextV1,
    mut signing_seed: [u8; 32],
) -> Result<MacosLinuxVzPackageExecutionGrantBytesV1, MacosLinuxVzPackageExecutionGrantErrorV1> {
    let signing_key = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    if Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes())
        != context.execution_grant_issuer_public_key_sha256
    {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::PublicKeyMismatch);
    }
    let unsigned = unsigned_grant_v1(context);
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::Serialization)?;
    let signature = signing_key.sign(&signature_message_v1(&unsigned_bytes));
    let wire = ExecutionGrantWireV1::from_unsigned(unsigned, lower_hex_v1(&signature.to_bytes()));
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::Serialization)?;
    if bytes.is_empty() || bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_BYTES_V1 {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzPackageExecutionGrantBytesV1 { bytes })
}

pub struct MacosLinuxVzPackageExecutionGrantVerifierV1 {
    context: MacosLinuxVzPackageExecutionGrantContextV1,
    verifying_key: VerifyingKey,
    consumed: AtomicBool,
}

impl fmt::Debug for MacosLinuxVzPackageExecutionGrantVerifierV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageExecutionGrantVerifierV1")
            .field("context", &self.context)
            .field("consumed", &self.consumed.load(Ordering::Acquire))
            .finish()
    }
}

impl MacosLinuxVzPackageExecutionGrantVerifierV1 {
    pub fn new(
        context: MacosLinuxVzPackageExecutionGrantContextV1,
        verifying_key_bytes: [u8; 32],
    ) -> Result<Self, MacosLinuxVzPackageExecutionGrantErrorV1> {
        if Sha256Digest::from_bytes(&verifying_key_bytes)
            != context.execution_grant_issuer_public_key_sha256
        {
            return Err(MacosLinuxVzPackageExecutionGrantErrorV1::PublicKeyMismatch);
        }
        let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
            .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::PublicKeyMismatch)?;
        if verifying_key.is_weak() {
            return Err(MacosLinuxVzPackageExecutionGrantErrorV1::PublicKeyMismatch);
        }
        Ok(Self {
            context,
            verifying_key,
            consumed: AtomicBool::new(false),
        })
    }

    /// Burns the verifier before time checks, parsing, canonicalization, binding, or signature
    /// verification. Invalid, premature, expired, rebound, and valid grants are all one-shot.
    pub fn verify_and_consume(
        &self,
        mut bytes: Vec<u8>,
        observed_unix_seconds: u64,
    ) -> Result<
        MacosLinuxVzPackageExecutionGrantObservationV1,
        MacosLinuxVzPackageExecutionGrantErrorV1,
    > {
        let result = if self.consumed.swap(true, Ordering::AcqRel) {
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::AlreadyConsumed)
        } else {
            decode_and_verify_grant_v1(
                &bytes,
                &self.context,
                &self.verifying_key,
                observed_unix_seconds,
            )
        };
        bytes.zeroize();
        result
    }

    pub fn consumed(&self) -> bool {
        self.consumed.load(Ordering::Acquire)
    }
}

fn decode_and_verify_grant_v1(
    bytes: &[u8],
    context: &MacosLinuxVzPackageExecutionGrantContextV1,
    verifying_key: &VerifyingKey,
    observed_unix_seconds: u64,
) -> Result<MacosLinuxVzPackageExecutionGrantObservationV1, MacosLinuxVzPackageExecutionGrantErrorV1>
{
    if observed_unix_seconds < context.issued_at_unix_seconds {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::NotYetValid);
    }
    if observed_unix_seconds >= context.expires_at_unix_seconds {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::Expired);
    }
    if bytes.is_empty() || bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_BYTES_V1 {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = ExecutionGrantWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::InvalidGrant)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::InvalidGrant)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::Serialization)?;
    if canonical != bytes || !valid_signature_hex_v1(&wire.signature_ed25519_hex) {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::NonCanonical);
    }
    let signature_hex = wire.signature_ed25519_hex.clone();
    let unsigned = wire.into_unsigned();
    if unsigned != unsigned_grant_v1(context) {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::ContextBindingMismatch);
    }
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::Serialization)?;
    let signature = Signature::from_bytes(&decode_signature_v1(&signature_hex)?);
    verifying_key
        .verify_strict(&signature_message_v1(&unsigned_bytes), &signature)
        .map_err(|_| MacosLinuxVzPackageExecutionGrantErrorV1::SignatureFailed)?;
    Ok(MacosLinuxVzPackageExecutionGrantObservationV1 {
        execution_grant_sha256: Sha256Digest::from_bytes(bytes),
        package_authority_request_sha256: context.package_authority_request_sha256.clone(),
        execution_runtime_qualification_record_sha256: context
            .execution_runtime_qualification_record_sha256
            .clone(),
        request_challenge_sha256: context.request_challenge_sha256.clone(),
        grant_challenge_sha256: context.grant_challenge_sha256.clone(),
        attempt_binding_sha256: context.attempt_binding_sha256.clone(),
        clone_binding_sha256: context.clone_binding_sha256.clone(),
        issued_at_unix_seconds: context.issued_at_unix_seconds,
        expires_at_unix_seconds: context.expires_at_unix_seconds,
        verified_at_unix_seconds: observed_unix_seconds,
        package_uid: context.package_uid,
        package_gid: context.package_gid,
        consumed: true,
    })
}

fn unsigned_grant_v1(
    context: &MacosLinuxVzPackageExecutionGrantContextV1,
) -> UnsignedExecutionGrantWireV1 {
    UnsignedExecutionGrantWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_EXECUTION_GRANT_SCHEMA_V1.to_string(),
        authority: EXECUTION_GRANT_AUTHORITY_V1.to_string(),
        artifact_kind: context.artifact_kind,
        artifact_sha256: context.artifact_sha256.clone(),
        package_authority_request_sha256: context.package_authority_request_sha256.clone(),
        scenario_plan_sha256: context.scenario_plan_sha256.clone(),
        scenario_template_sha256: context.scenario_template_sha256.clone(),
        runtime_profile_sha256: context.runtime_profile_sha256.clone(),
        qualified_telemetry_backend_sha256: context.qualified_telemetry_backend_sha256.clone(),
        execution_runtime_qualification_record_sha256: context
            .execution_runtime_qualification_record_sha256
            .clone(),
        execution_runtime_rootfs_sha256: context.execution_runtime_rootfs_sha256.clone(),
        execution_runtime_rootfs_byte_length: context
            .execution_runtime_rootfs_byte_length
            .to_string(),
        execution_runtime_manifest_sha256: context.execution_runtime_manifest_sha256.clone(),
        package_execution_runner_sha256: context.package_execution_runner_sha256.clone(),
        execution_grant_issuer_public_key_sha256: context
            .execution_grant_issuer_public_key_sha256
            .clone(),
        request_challenge_sha256: context.request_challenge_sha256.clone(),
        grant_challenge_sha256: context.grant_challenge_sha256.clone(),
        attempt_binding_sha256: context.attempt_binding_sha256.clone(),
        clone_binding_sha256: context.clone_binding_sha256.clone(),
        issued_at_unix_seconds: context.issued_at_unix_seconds.to_string(),
        expires_at_unix_seconds: context.expires_at_unix_seconds.to_string(),
        package_uid: context.package_uid.to_string(),
        package_gid: context.package_gid.to_string(),
        attempt_limit: "1".to_string(),
        execution_scope: MacosLinuxVzPackageExecutionScopeV1::OneTypedScenarioOneAttempt,
        public_network_route_present: false,
        execution_authority_issued: true,
        package_execution_permitted: true,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    }
}

#[cfg(test)]
pub(crate) fn test_macos_linux_vz_package_execution_grant_observation_v1(
    request: &MacosLinuxVzPackageAuthorityRequestV1,
) -> MacosLinuxVzPackageExecutionGrantObservationV1 {
    MacosLinuxVzPackageExecutionGrantObservationV1 {
        execution_grant_sha256: Sha256Digest::from_bytes(b"test exact signed execution grant"),
        package_authority_request_sha256: request.request_sha256().clone(),
        execution_runtime_qualification_record_sha256: Sha256Digest::from_bytes(
            b"test execution runtime qualification record",
        ),
        request_challenge_sha256: request.request_challenge_sha256().clone(),
        grant_challenge_sha256: Sha256Digest::from_bytes(b"test grant challenge"),
        attempt_binding_sha256: Sha256Digest::from_bytes(b"test attempt binding"),
        clone_binding_sha256: request.clone_binding_sha256().clone(),
        issued_at_unix_seconds: 1_784_044_800,
        expires_at_unix_seconds: 1_784_045_100,
        verified_at_unix_seconds: 1_784_044_801,
        package_uid: PACKAGE_UID_V1,
        package_gid: PACKAGE_GID_V1,
        consumed: true,
    }
}

fn signature_message_v1(unsigned_grant: &[u8]) -> Vec<u8> {
    let mut message =
        Vec::with_capacity(EXECUTION_GRANT_SIGNATURE_DOMAIN_V1.len() + 8 + unsigned_grant.len());
    message.extend_from_slice(EXECUTION_GRANT_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(&(unsigned_grant.len() as u64).to_be_bytes());
    message.extend_from_slice(unsigned_grant);
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

fn decode_signature_v1(value: &str) -> Result<[u8; 64], MacosLinuxVzPackageExecutionGrantErrorV1> {
    if !valid_signature_hex_v1(value) {
        return Err(MacosLinuxVzPackageExecutionGrantErrorV1::InvalidGrant);
    }
    let mut output = [0_u8; 64];
    let bytes = value.as_bytes();
    for index in 0..64 {
        output[index] =
            (hex_nibble_v1(bytes[index * 2])? << 4) | hex_nibble_v1(bytes[index * 2 + 1])?;
    }
    Ok(output)
}

fn hex_nibble_v1(value: u8) -> Result<u8, MacosLinuxVzPackageExecutionGrantErrorV1> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(MacosLinuxVzPackageExecutionGrantErrorV1::InvalidGrant),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_SEED: [u8; 32] = [17_u8; 32];

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn context() -> MacosLinuxVzPackageExecutionGrantContextV1 {
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        MacosLinuxVzPackageExecutionGrantContextV1 {
            artifact_kind: MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            artifact_sha256: digest("artifact"),
            package_authority_request_sha256: digest("package authority request"),
            scenario_plan_sha256: digest("scenario plan"),
            scenario_template_sha256: digest("scenario template"),
            runtime_profile_sha256: digest("runtime profile"),
            qualified_telemetry_backend_sha256: digest("qualified telemetry backend"),
            execution_runtime_qualification_record_sha256: digest(
                "execution runtime qualification record",
            ),
            execution_runtime_rootfs_sha256: digest("execution runtime rootfs"),
            execution_runtime_rootfs_byte_length: 1_073_741_824,
            execution_runtime_manifest_sha256: digest("execution runtime manifest"),
            package_execution_runner_sha256: digest("package execution runner"),
            execution_grant_issuer_public_key_sha256: Sha256Digest::from_bytes(&public_key),
            request_challenge_sha256: digest("request challenge"),
            grant_challenge_sha256: digest("grant challenge"),
            attempt_binding_sha256: digest("attempt binding"),
            clone_binding_sha256: digest("clone binding"),
            issued_at_unix_seconds: 1_784_044_800,
            expires_at_unix_seconds: 1_784_045_100,
            package_uid: PACKAGE_UID_V1,
            package_gid: PACKAGE_GID_V1,
        }
    }

    fn qualification() -> VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1 {
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        VerifiedMacosLinuxVzPackageExecutionRuntimeQualificationV1 {
            qualification_record_sha256: digest("qualification record"),
            qualified_telemetry_backend_sha256: digest("telemetry backend"),
            execution_runtime_rootfs_sha256: digest("rootfs"),
            execution_runtime_rootfs_byte_length: 1_073_741_824,
            execution_runtime_manifest_sha256: digest("manifest"),
            package_execution_runner_sha256: digest("runner"),
            guest_evidence_public_key_sha256: digest("guest evidence key"),
            host_evidence_public_key_sha256: digest("host evidence key"),
            execution_grant_issuer_public_key_sha256: Sha256Digest::from_bytes(&public_key),
            package_uid: PACKAGE_UID_V1,
            package_gid: PACKAGE_GID_V1,
        }
    }

    #[test]
    fn opaque_qualification_requires_distinct_measured_keys_and_runtime() {
        let qualification = qualification();
        qualification.validate().expect("valid qualification");

        let mut reused_key = qualification.clone();
        reused_key.execution_grant_issuer_public_key_sha256 =
            reused_key.host_evidence_public_key_sha256.clone();
        assert_eq!(
            reused_key.validate(),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::QualificationInvalid)
        );

        let mut empty_runtime = qualification;
        empty_runtime.execution_runtime_rootfs_byte_length = 0;
        assert_eq!(
            empty_runtime.validate(),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::QualificationInvalid)
        );
    }

    #[test]
    fn exact_signed_grant_is_one_attempt_and_never_syncs_back() {
        let context = context();
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let grant =
            sign_macos_linux_vz_package_execution_grant_v1(&context, SIGNING_SEED).expect("sign");
        let verifier =
            MacosLinuxVzPackageExecutionGrantVerifierV1::new(context.clone(), public_key)
                .expect("verifier");
        let observed = verifier
            .verify_and_consume(grant.as_bytes().to_vec(), context.issued_at_unix_seconds())
            .expect("verify");
        assert!(observed.consumed());
        assert_eq!(
            observed.package_execution_scope(),
            MacosLinuxVzPackageExecutionScopeV1::OneTypedScenarioOneAttempt
        );
        assert!(!observed.sync_back_permitted());
        assert_eq!(
            observed.package_authority_request_sha256(),
            context.package_authority_request_sha256()
        );
        assert_eq!(
            observed.execution_grant_sha256(),
            &Sha256Digest::from_bytes(grant.as_bytes())
        );
        assert_eq!(
            observed.request_challenge_sha256(),
            &context.request_challenge_sha256
        );
        assert_eq!(
            observed.verified_at_unix_seconds(),
            context.issued_at_unix_seconds()
        );
        assert_eq!(
            verifier
                .verify_and_consume(grant.as_bytes().to_vec(), context.issued_at_unix_seconds()),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::AlreadyConsumed)
        );
    }

    #[test]
    fn execution_request_derivation_burns_before_artifact_or_scenario_validation() {
        let context = context();
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let grant =
            sign_macos_linux_vz_package_execution_grant_v1(&context, SIGNING_SEED).expect("sign");
        let verifier =
            MacosLinuxVzPackageExecutionGrantVerifierV1::new(context.clone(), public_key)
                .expect("verifier");
        let observed = verifier
            .verify_and_consume(grant.as_bytes().to_vec(), context.issued_at_unix_seconds())
            .expect("verify");
        let authority_request =
            crate::linux_vz_package_authority_request::test_macos_linux_vz_package_authority_request_for_execution_v1(
                context.package_authority_request_sha256.clone(),
                context.artifact_kind,
                context.artifact_sha256.clone(),
                context.request_challenge_sha256.clone(),
                context.clone_binding_sha256.clone(),
            );
        let authorizer = crate::MacosLinuxVzPackageExecutionRequestAuthorizerV1::new(observed)
            .expect("request authorizer");
        assert_eq!(
            authorizer
                .build_and_consume(&authority_request, b"", b"", b"")
                .expect_err("empty artifact must fail"),
            crate::MacosLinuxVzPackageExecutionRequestErrorV1::ArtifactMismatch
        );
        assert!(authorizer.consumed());
        assert_eq!(
            authorizer
                .build_and_consume(&authority_request, b"x", b"plan", b"template")
                .expect_err("burned authorizer must reject retry"),
            crate::MacosLinuxVzPackageExecutionRequestErrorV1::AlreadyConsumed
        );
    }

    #[test]
    fn invalid_attempt_burns_before_parse_and_cannot_retry() {
        let context = context();
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let grant =
            sign_macos_linux_vz_package_execution_grant_v1(&context, SIGNING_SEED).expect("sign");
        let verifier =
            MacosLinuxVzPackageExecutionGrantVerifierV1::new(context.clone(), public_key)
                .expect("verifier");
        assert_eq!(
            verifier.verify_and_consume(b"not a grant".to_vec(), context.issued_at_unix_seconds()),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::InvalidGrant)
        );
        assert!(verifier.consumed());
        assert_eq!(
            verifier
                .verify_and_consume(grant.as_bytes().to_vec(), context.issued_at_unix_seconds()),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::AlreadyConsumed)
        );
    }

    #[test]
    fn context_rebinding_and_wrong_keys_fail_closed() {
        let context = context();
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let grant =
            sign_macos_linux_vz_package_execution_grant_v1(&context, SIGNING_SEED).expect("sign");
        let mut rebound = context.clone();
        rebound.clone_binding_sha256 = digest("different clone");
        let verifier = MacosLinuxVzPackageExecutionGrantVerifierV1::new(rebound, public_key)
            .expect("verifier");
        assert_eq!(
            verifier
                .verify_and_consume(grant.as_bytes().to_vec(), context.issued_at_unix_seconds()),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::ContextBindingMismatch)
        );
        assert_eq!(
            MacosLinuxVzPackageExecutionGrantVerifierV1::new(context, [9_u8; 32]).map(|_| ()),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::PublicKeyMismatch)
        );
    }

    #[test]
    fn premature_and_expired_attempts_burn_before_parsing() {
        let context = context();
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let premature =
            MacosLinuxVzPackageExecutionGrantVerifierV1::new(context.clone(), public_key)
                .expect("verifier");
        assert_eq!(
            premature.verify_and_consume(b"invalid".to_vec(), context.issued_at_unix_seconds() - 1),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::NotYetValid)
        );
        assert!(premature.consumed());

        let expired = MacosLinuxVzPackageExecutionGrantVerifierV1::new(context.clone(), public_key)
            .expect("verifier");
        assert_eq!(
            expired.verify_and_consume(b"invalid".to_vec(), context.expires_at_unix_seconds()),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::Expired)
        );
        assert!(expired.consumed());
    }

    #[test]
    fn signature_mutation_is_consumed_and_rejected() {
        let context = context();
        let public_key = SigningKey::from_bytes(&SIGNING_SEED)
            .verifying_key()
            .to_bytes();
        let grant =
            sign_macos_linux_vz_package_execution_grant_v1(&context, SIGNING_SEED).expect("sign");
        let mut value: serde_json::Value = serde_json::from_slice(grant.as_bytes()).expect("json");
        value["signature_ed25519_hex"] = serde_json::Value::String("00".repeat(64));
        let mutated = serde_json_canonicalizer::to_vec(&value).expect("canonical");
        let verifier =
            MacosLinuxVzPackageExecutionGrantVerifierV1::new(context.clone(), public_key)
                .expect("verifier");
        assert_eq!(
            verifier.verify_and_consume(mutated, context.issued_at_unix_seconds()),
            Err(MacosLinuxVzPackageExecutionGrantErrorV1::SignatureFailed)
        );
        assert!(verifier.consumed());
    }
}
