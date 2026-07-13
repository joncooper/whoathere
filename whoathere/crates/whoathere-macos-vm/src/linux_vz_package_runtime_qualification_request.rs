use crate::{
    MacosLinuxVzCandidatePackageRuntimeV1, QualifiedMacosLinuxVzTelemetryBackendV1,
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_ROOTFS_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactTelemetrySyncBackPolicyV1;

pub const MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_runtime_qualification_request.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1: usize = 64 * 1024;
pub const MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1: &[u8] = b"{\"execution_authority\":false,\"package_execution\":false,\"schema_version\":\"whoathere.linux_vz_package_runtime_probe.v1\",\"status\":\"candidate_runtime_nonexecuting\",\"sync_back\":false}\n";

const MAX_RUNTIME_QUALIFICATION_INITRAMFS_BYTES_V1: usize = 1024 * 1024 * 1024;
const MAX_RUNTIME_QUALIFICATION_GUEST_AGENT_BYTES_V1: usize = 16 * 1024 * 1024;
const MAX_RUNTIME_QUALIFICATION_GUEST_INIT_BYTES_V1: usize = 1024 * 1024;
const MAX_RUNTIME_QUALIFICATION_MODULE_BUNDLE_BYTES_V1: usize = 256 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzRuntimeQualificationOperationV1 {
    FixedNonexecutingProbe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzRuntimeQualificationStoragePolicyV1 {
    OneUniqueWritableCloneDestroyAfterVmStop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzRuntimeQualificationNetworkPolicyV1 {
    HostRawFrameSinkholeNoExternalRoute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzRuntimeQualificationDirectorySharePolicyV1 {
    StructurallyAbsent,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageRuntimeQualificationImageV1 {
    initramfs_sha256: Sha256Digest,
    guest_agent_sha256: Sha256Digest,
    guest_init_sha256: Sha256Digest,
    module_bundle_sha256: Sha256Digest,
}

impl MacosLinuxVzPackageRuntimeQualificationImageV1 {
    pub fn from_exact_bytes(
        initramfs_bytes: &[u8],
        guest_agent_bytes: &[u8],
        guest_init_bytes: &[u8],
        module_bundle_bytes: &[u8],
    ) -> Result<Self, MacosLinuxVzPackageRuntimeQualificationRequestErrorV1> {
        if initramfs_bytes.is_empty()
            || initramfs_bytes.len() > MAX_RUNTIME_QUALIFICATION_INITRAMFS_BYTES_V1
            || guest_agent_bytes.is_empty()
            || guest_agent_bytes.len() > MAX_RUNTIME_QUALIFICATION_GUEST_AGENT_BYTES_V1
            || guest_init_bytes.is_empty()
            || guest_init_bytes.len() > MAX_RUNTIME_QUALIFICATION_GUEST_INIT_BYTES_V1
            || module_bundle_bytes.is_empty()
            || module_bundle_bytes.len() > MAX_RUNTIME_QUALIFICATION_MODULE_BUNDLE_BYTES_V1
        {
            return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::ImageInvalid);
        }
        let value = Self {
            initramfs_sha256: Sha256Digest::from_bytes(initramfs_bytes),
            guest_agent_sha256: Sha256Digest::from_bytes(guest_agent_bytes),
            guest_init_sha256: Sha256Digest::from_bytes(guest_init_bytes),
            module_bundle_sha256: Sha256Digest::from_bytes(module_bundle_bytes),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(&self) -> Result<(), MacosLinuxVzPackageRuntimeQualificationRequestErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        let digests = [
            &self.initramfs_sha256,
            &self.guest_agent_sha256,
            &self.guest_init_sha256,
            &self.module_bundle_sha256,
        ];
        if digests.contains(&&empty)
            || digests
                .iter()
                .enumerate()
                .any(|(index, digest)| digests[..index].contains(digest))
        {
            return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::ImageInvalid);
        }
        Ok(())
    }

    pub fn initramfs_sha256(&self) -> &Sha256Digest {
        &self.initramfs_sha256
    }

    pub fn guest_agent_sha256(&self) -> &Sha256Digest {
        &self.guest_agent_sha256
    }

    pub fn guest_init_sha256(&self) -> &Sha256Digest {
        &self.guest_init_sha256
    }

    pub fn module_bundle_sha256(&self) -> &Sha256Digest {
        &self.module_bundle_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeQualificationRequestWireV1 {
    schema_version: String,
    operation: MacosLinuxVzRuntimeQualificationOperationV1,
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
    expected_probe_report_sha256: Sha256Digest,
    protected_sensor_case: String,
    package_runner_argument: String,
    request_challenge_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    package_uid: String,
    package_gid: String,
    storage_policy: MacosLinuxVzRuntimeQualificationStoragePolicyV1,
    network_policy: MacosLinuxVzRuntimeQualificationNetworkPolicyV1,
    directory_share_policy: MacosLinuxVzRuntimeQualificationDirectorySharePolicyV1,
    public_resolver_reachable: bool,
    nonexecuting_probe_permitted: bool,
    execution_authority_issued: bool,
    package_execution_permitted: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageRuntimeQualificationRequestV1 {
    canonical_json: Vec<u8>,
    request_sha256: Sha256Digest,
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
    candidate_runtime_rootfs_byte_length: u64,
    candidate_runtime_manifest_sha256: Sha256Digest,
    candidate_package_runner_sha256: Sha256Digest,
    expected_probe_report_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    package_uid: u32,
    package_gid: u32,
}

impl fmt::Debug for MacosLinuxVzPackageRuntimeQualificationRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageRuntimeQualificationRequestV1")
            .field("request_sha256", &self.request_sha256)
            .field(
                "qualified_telemetry_backend_sha256",
                &self.qualified_telemetry_backend_sha256,
            )
            .field(
                "runtime_qualification_initramfs_sha256",
                &self.runtime_qualification_initramfs_sha256,
            )
            .field(
                "candidate_runtime_rootfs_sha256",
                &self.candidate_runtime_rootfs_sha256,
            )
            .field("request_challenge_sha256", &self.request_challenge_sha256)
            .field("clone_binding_sha256", &self.clone_binding_sha256)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosLinuxVzPackageRuntimeQualificationRequestV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn qualified_telemetry_backend_sha256(&self) -> &Sha256Digest {
        &self.qualified_telemetry_backend_sha256
    }

    pub fn backend_identity_sha256(&self) -> &Sha256Digest {
        &self.backend_identity_sha256
    }

    pub fn telemetry_requirements_sha256(&self) -> &Sha256Digest {
        &self.telemetry_requirements_sha256
    }

    pub fn conformance_evidence_set_sha256(&self) -> &Sha256Digest {
        &self.conformance_evidence_set_sha256
    }

    pub fn kernel_image_sha256(&self) -> &Sha256Digest {
        &self.kernel_image_sha256
    }

    pub fn qualified_initramfs_sha256(&self) -> &Sha256Digest {
        &self.qualified_initramfs_sha256
    }

    pub fn qualified_guest_signer_sha256(&self) -> &Sha256Digest {
        &self.qualified_guest_signer_sha256
    }

    pub fn qualified_protected_sensor_sha256(&self) -> &Sha256Digest {
        &self.qualified_protected_sensor_sha256
    }

    pub fn guest_evidence_public_key_sha256(&self) -> &Sha256Digest {
        &self.guest_evidence_public_key_sha256
    }

    pub fn host_evidence_public_key_sha256(&self) -> &Sha256Digest {
        &self.host_evidence_public_key_sha256
    }

    pub fn runtime_qualification_initramfs_sha256(&self) -> &Sha256Digest {
        &self.runtime_qualification_initramfs_sha256
    }

    pub fn runtime_qualification_guest_agent_sha256(&self) -> &Sha256Digest {
        &self.runtime_qualification_guest_agent_sha256
    }

    pub fn runtime_qualification_guest_init_sha256(&self) -> &Sha256Digest {
        &self.runtime_qualification_guest_init_sha256
    }

    pub fn runtime_qualification_module_bundle_sha256(&self) -> &Sha256Digest {
        &self.runtime_qualification_module_bundle_sha256
    }

    pub fn candidate_runtime_rootfs_sha256(&self) -> &Sha256Digest {
        &self.candidate_runtime_rootfs_sha256
    }

    pub const fn candidate_runtime_rootfs_byte_length(&self) -> u64 {
        self.candidate_runtime_rootfs_byte_length
    }

    pub fn candidate_runtime_manifest_sha256(&self) -> &Sha256Digest {
        &self.candidate_runtime_manifest_sha256
    }

    pub fn candidate_package_runner_sha256(&self) -> &Sha256Digest {
        &self.candidate_package_runner_sha256
    }

    pub fn expected_probe_report_sha256(&self) -> &Sha256Digest {
        &self.expected_probe_report_sha256
    }

    pub fn request_challenge_sha256(&self) -> &Sha256Digest {
        &self.request_challenge_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub const fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub const fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub const fn fixed_nonexecuting_probe_permitted(&self) -> bool {
        true
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzPackageRuntimeQualificationRequestErrorV1 {
    BackendNotEligible,
    BackendMismatch,
    CandidateRuntimeInvalid,
    ImageInvalid,
    ChallengeInvalid,
    CloneBindingInvalid,
    InvalidRequest,
    NonCanonical,
    BindingMismatch,
    LimitExceeded,
    Serialization,
}

impl MacosLinuxVzPackageRuntimeQualificationRequestErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::BackendNotEligible => "macos_linux_vz_runtime_qualification_backend_not_eligible",
            Self::BackendMismatch => "macos_linux_vz_runtime_qualification_backend_mismatch",
            Self::CandidateRuntimeInvalid => {
                "macos_linux_vz_runtime_qualification_candidate_runtime_invalid"
            }
            Self::ImageInvalid => "macos_linux_vz_runtime_qualification_image_invalid",
            Self::ChallengeInvalid => "macos_linux_vz_runtime_qualification_challenge_invalid",
            Self::CloneBindingInvalid => {
                "macos_linux_vz_runtime_qualification_clone_binding_invalid"
            }
            Self::InvalidRequest => "macos_linux_vz_runtime_qualification_request_invalid",
            Self::NonCanonical => "macos_linux_vz_runtime_qualification_request_noncanonical",
            Self::BindingMismatch => {
                "macos_linux_vz_runtime_qualification_request_binding_mismatch"
            }
            Self::LimitExceeded => "macos_linux_vz_runtime_qualification_request_limit_exceeded",
            Self::Serialization => "macos_linux_vz_runtime_qualification_serialization_failed",
        }
    }
}

impl fmt::Display for MacosLinuxVzPackageRuntimeQualificationRequestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzPackageRuntimeQualificationRequestErrorV1 {}

fn request_from_wire_v1(
    wire: RuntimeQualificationRequestWireV1,
    canonical_json: Vec<u8>,
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRequestV1,
    MacosLinuxVzPackageRuntimeQualificationRequestErrorV1,
> {
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::LimitExceeded);
    }
    if wire.schema_version != MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_SCHEMA_V1
        || wire.operation != MacosLinuxVzRuntimeQualificationOperationV1::FixedNonexecutingProbe
        || wire.protected_sensor_case != "fork_exec_exit"
        || wire.package_runner_argument != "fork_exec_exit"
        || wire.storage_policy
            != MacosLinuxVzRuntimeQualificationStoragePolicyV1::OneUniqueWritableCloneDestroyAfterVmStop
        || wire.network_policy
            != MacosLinuxVzRuntimeQualificationNetworkPolicyV1::HostRawFrameSinkholeNoExternalRoute
        || wire.directory_share_policy
            != MacosLinuxVzRuntimeQualificationDirectorySharePolicyV1::StructurallyAbsent
        || wire.public_resolver_reachable
        || !wire.nonexecuting_probe_permitted
        || wire.execution_authority_issued
        || wire.package_execution_permitted
        || wire.sync_back_policy != ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::InvalidRequest);
    }
    let candidate_runtime_rootfs_byte_length =
        strict_positive_decimal_u64_v1(&wire.candidate_runtime_rootfs_byte_length)
            .filter(|length| *length <= MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_ROOTFS_BYTES_V1)
            .ok_or(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::InvalidRequest)?;
    let package_uid = strict_positive_decimal_u32_v1(&wire.package_uid)
        .ok_or(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::InvalidRequest)?;
    let package_gid = strict_positive_decimal_u32_v1(&wire.package_gid)
        .ok_or(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::InvalidRequest)?;
    let empty = Sha256Digest::from_bytes(&[]);
    let all_digests = [
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
        &wire.expected_probe_report_sha256,
        &wire.request_challenge_sha256,
        &wire.clone_binding_sha256,
    ];
    let candidate_digests = [
        &wire.candidate_runtime_rootfs_sha256,
        &wire.candidate_runtime_manifest_sha256,
        &wire.candidate_package_runner_sha256,
    ];
    let image_digests = [
        &wire.runtime_qualification_initramfs_sha256,
        &wire.runtime_qualification_guest_agent_sha256,
        &wire.runtime_qualification_guest_init_sha256,
        &wire.runtime_qualification_module_bundle_sha256,
    ];
    if all_digests.contains(&&empty)
        || candidate_digests
            .iter()
            .enumerate()
            .any(|(index, digest)| candidate_digests[..index].contains(digest))
        || image_digests
            .iter()
            .enumerate()
            .any(|(index, digest)| image_digests[..index].contains(digest))
        || wire.runtime_qualification_initramfs_sha256 == wire.qualified_initramfs_sha256
        || wire.runtime_qualification_guest_agent_sha256 == wire.qualified_guest_signer_sha256
        || wire.runtime_qualification_module_bundle_sha256 == wire.qualified_protected_sensor_sha256
        || wire.expected_probe_report_sha256
            != Sha256Digest::from_bytes(MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1)
        || wire.clone_binding_sha256 == wire.request_challenge_sha256
        || wire.clone_binding_sha256 == wire.candidate_runtime_rootfs_sha256
        || wire.clone_binding_sha256 == wire.runtime_qualification_initramfs_sha256
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::BindingMismatch);
    }

    Ok(MacosLinuxVzPackageRuntimeQualificationRequestV1 {
        request_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        qualified_telemetry_backend_sha256: wire.qualified_telemetry_backend_sha256,
        backend_identity_sha256: wire.backend_identity_sha256,
        telemetry_requirements_sha256: wire.telemetry_requirements_sha256,
        conformance_evidence_set_sha256: wire.conformance_evidence_set_sha256,
        kernel_image_sha256: wire.kernel_image_sha256,
        qualified_initramfs_sha256: wire.qualified_initramfs_sha256,
        qualified_guest_signer_sha256: wire.qualified_guest_signer_sha256,
        qualified_protected_sensor_sha256: wire.qualified_protected_sensor_sha256,
        guest_evidence_public_key_sha256: wire.guest_evidence_public_key_sha256,
        host_evidence_public_key_sha256: wire.host_evidence_public_key_sha256,
        runtime_qualification_initramfs_sha256: wire.runtime_qualification_initramfs_sha256,
        runtime_qualification_guest_agent_sha256: wire.runtime_qualification_guest_agent_sha256,
        runtime_qualification_guest_init_sha256: wire.runtime_qualification_guest_init_sha256,
        runtime_qualification_module_bundle_sha256: wire.runtime_qualification_module_bundle_sha256,
        candidate_runtime_rootfs_sha256: wire.candidate_runtime_rootfs_sha256,
        candidate_runtime_rootfs_byte_length,
        candidate_runtime_manifest_sha256: wire.candidate_runtime_manifest_sha256,
        candidate_package_runner_sha256: wire.candidate_package_runner_sha256,
        expected_probe_report_sha256: wire.expected_probe_report_sha256,
        request_challenge_sha256: wire.request_challenge_sha256,
        clone_binding_sha256: wire.clone_binding_sha256,
        package_uid,
        package_gid,
    })
}

fn strict_positive_decimal_u64_v1(value: &str) -> Option<u64> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse::<u64>().ok().filter(|parsed| *parsed > 0)
}

fn strict_positive_decimal_u32_v1(value: &str) -> Option<u32> {
    if value.is_empty()
        || value.len() > 10
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    value.parse::<u32>().ok().filter(|parsed| *parsed > 0)
}

#[allow(clippy::too_many_arguments)]
pub fn build_macos_linux_vz_package_runtime_qualification_request_v1(
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    backend_identity: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    candidate_runtime: &MacosLinuxVzCandidatePackageRuntimeV1,
    qualification_image: &MacosLinuxVzPackageRuntimeQualificationImageV1,
    request_challenge: [u8; 32],
    clone_binding_sha256: Sha256Digest,
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRequestV1,
    MacosLinuxVzPackageRuntimeQualificationRequestErrorV1,
> {
    if !qualified_backend.eligible_for_typed_package_execution_authority_request()
        || qualified_backend.package_execution_authority_permitted()
        || qualified_backend.sync_back_permitted()
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::BackendNotEligible);
    }
    let backend_identity_sha256 = backend_identity
        .identity_sha256_v1()
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::BackendMismatch)?;
    if qualified_backend.backend_identity_sha256() != &backend_identity_sha256
        || qualified_backend.telemetry_requirements_sha256()
            != backend_identity.telemetry_requirements_sha256()
        || backend_identity.execution_authority_permitted()
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::BackendMismatch);
    }
    candidate_runtime.validate().map_err(|_| {
        MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::CandidateRuntimeInvalid
    })?;
    qualification_image.validate()?;
    if qualification_image.initramfs_sha256() == backend_identity.initramfs_sha256()
        || qualification_image.guest_agent_sha256() == backend_identity.guest_sensor_sha256()
        || qualification_image.module_bundle_sha256() == backend_identity.guest_bpf_bundle_sha256()
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::ImageInvalid);
    }
    if request_challenge == [0_u8; 32] {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::ChallengeInvalid);
    }
    let request_challenge_sha256 = Sha256Digest::from_bytes(&request_challenge);
    let empty_sha256 = Sha256Digest::from_bytes(&[]);
    if clone_binding_sha256 == empty_sha256
        || clone_binding_sha256 == request_challenge_sha256
        || clone_binding_sha256 == *candidate_runtime.rootfs_sha256()
        || clone_binding_sha256 == *qualification_image.initramfs_sha256()
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::CloneBindingInvalid);
    }

    let wire = RuntimeQualificationRequestWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_SCHEMA_V1.to_string(),
        operation: MacosLinuxVzRuntimeQualificationOperationV1::FixedNonexecutingProbe,
        qualified_telemetry_backend_sha256: qualified_backend
            .qualified_backend_sha256()
            .clone(),
        backend_identity_sha256,
        telemetry_requirements_sha256: qualified_backend
            .telemetry_requirements_sha256()
            .clone(),
        conformance_evidence_set_sha256: qualified_backend
            .conformance_evidence_set_sha256()
            .clone(),
        kernel_image_sha256: backend_identity.kernel_image_sha256().clone(),
        qualified_initramfs_sha256: backend_identity.initramfs_sha256().clone(),
        qualified_guest_signer_sha256: backend_identity.guest_sensor_sha256().clone(),
        qualified_protected_sensor_sha256: backend_identity.guest_bpf_bundle_sha256().clone(),
        guest_evidence_public_key_sha256: backend_identity
            .guest_evidence_public_key_sha256()
            .clone(),
        host_evidence_public_key_sha256: backend_identity
            .host_evidence_public_key_sha256()
            .clone(),
        runtime_qualification_initramfs_sha256: qualification_image.initramfs_sha256().clone(),
        runtime_qualification_guest_agent_sha256: qualification_image
            .guest_agent_sha256()
            .clone(),
        runtime_qualification_guest_init_sha256: qualification_image.guest_init_sha256().clone(),
        runtime_qualification_module_bundle_sha256: qualification_image
            .module_bundle_sha256()
            .clone(),
        candidate_runtime_rootfs_sha256: candidate_runtime.rootfs_sha256().clone(),
        candidate_runtime_rootfs_byte_length: candidate_runtime.rootfs_byte_length().to_string(),
        candidate_runtime_manifest_sha256: candidate_runtime.runtime_manifest_sha256().clone(),
        candidate_package_runner_sha256: candidate_runtime.package_runner_sha256().clone(),
        expected_probe_report_sha256: Sha256Digest::from_bytes(
            MACOS_LINUX_VZ_PACKAGE_RUNTIME_PROBE_REPORT_V1,
        ),
        protected_sensor_case: "fork_exec_exit".to_string(),
        package_runner_argument: "fork_exec_exit".to_string(),
        request_challenge_sha256: request_challenge_sha256.clone(),
        clone_binding_sha256: clone_binding_sha256.clone(),
        package_uid: backend_identity.package_uid().to_string(),
        package_gid: backend_identity.package_gid().to_string(),
        storage_policy:
            MacosLinuxVzRuntimeQualificationStoragePolicyV1::OneUniqueWritableCloneDestroyAfterVmStop,
        network_policy:
            MacosLinuxVzRuntimeQualificationNetworkPolicyV1::HostRawFrameSinkholeNoExternalRoute,
        directory_share_policy:
            MacosLinuxVzRuntimeQualificationDirectorySharePolicyV1::StructurallyAbsent,
        public_resolver_reachable: false,
        nonexecuting_probe_permitted: true,
        execution_authority_issued: false,
        package_execution_permitted: false,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::Serialization)?;
    request_from_wire_v1(wire, canonical_json)
}

pub fn decode_macos_linux_vz_package_runtime_qualification_request_v1(
    bytes: &[u8],
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRequestV1,
    MacosLinuxVzPackageRuntimeQualificationRequestErrorV1,
> {
    if bytes.is_empty()
        || bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_RUNTIME_QUALIFICATION_REQUEST_BYTES_V1
    {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = RuntimeQualificationRequestWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::InvalidRequest)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::InvalidRequest)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::NonCanonical);
    }
    request_from_wire_v1(wire, canonical)
}

#[allow(clippy::too_many_arguments)]
pub fn decode_and_verify_macos_linux_vz_package_runtime_qualification_request_v1(
    bytes: &[u8],
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    backend_identity: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    candidate_runtime: &MacosLinuxVzCandidatePackageRuntimeV1,
    qualification_image: &MacosLinuxVzPackageRuntimeQualificationImageV1,
    request_challenge: [u8; 32],
    clone_binding_sha256: Sha256Digest,
) -> Result<
    MacosLinuxVzPackageRuntimeQualificationRequestV1,
    MacosLinuxVzPackageRuntimeQualificationRequestErrorV1,
> {
    let decoded = decode_macos_linux_vz_package_runtime_qualification_request_v1(bytes)?;
    let expected = build_macos_linux_vz_package_runtime_qualification_request_v1(
        qualified_backend,
        backend_identity,
        candidate_runtime,
        qualification_image,
        request_challenge,
        clone_binding_sha256,
    )?;
    if expected.canonical_json_v1() != decoded.canonical_json_v1() {
        return Err(MacosLinuxVzPackageRuntimeQualificationRequestErrorV1::BindingMismatch);
    }
    Ok(expected)
}
