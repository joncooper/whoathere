use crate::QualifiedMacosLinuxVzTelemetryBackendV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::OpenOptions;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    decode_and_validate_artifact_scenario_plan_v1,
    decode_and_validate_artifact_scenario_template_v1, decode_and_validate_sdist_scenario_plan_v1,
    decode_and_validate_sdist_scenario_template_v1, decode_and_validate_wheel_scenario_plan_v1,
    decode_and_validate_wheel_scenario_template_v1, ArtifactCloneDispositionV1,
    ArtifactNetworkPolicyV1, ArtifactPackagePrivilegeV1, ArtifactRuntimeTargetV1,
    ArtifactScenarioKindV1, ArtifactTelemetrySyncBackPolicyV1, ArtifactTransportV1,
};

pub const MACOS_LINUX_VZ_PACKAGE_AUTHORITY_REQUEST_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_package_authority_request.v1";
pub const MAX_MACOS_LINUX_VZ_PACKAGE_AUTHORITY_REQUEST_BYTES_V1: usize = 64 * 1024;
pub const MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_ROOTFS_BYTES_V1: u64 = 64 * 1024 * 1024 * 1024;
pub const MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_MANIFEST_BYTES_V1: usize = 1024 * 1024;
pub const MAX_MACOS_LINUX_VZ_CANDIDATE_PACKAGE_RUNNER_BYTES_V1: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzPackageArtifactKindV1 {
    NpmTarball,
    PypiWheel,
    PypiSdist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzCandidateRuntimeQualificationStateV1 {
    CandidateExactBytesNotYetIndependentlyQualified,
}

/// Exact candidate runtime components bound into an authority request.
///
/// This identity is intentionally not a runtime qualification. Constructing it computes exact
/// digests but grants no execution capability; a later gate must independently prove that the
/// rootfs contains the committed runtimes and runner before issuing any one-use grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLinuxVzCandidatePackageRuntimeV1 {
    rootfs_sha256: Sha256Digest,
    rootfs_byte_length: u64,
    runtime_manifest_sha256: Sha256Digest,
    package_runner_sha256: Sha256Digest,
}

impl MacosLinuxVzCandidatePackageRuntimeV1 {
    pub fn from_exact_bytes(
        rootfs_bytes: &[u8],
        runtime_manifest_bytes: &[u8],
        package_runner_bytes: &[u8],
    ) -> Result<Self, MacosLinuxVzPackageAuthorityRequestErrorV1> {
        if rootfs_bytes.is_empty()
            || rootfs_bytes.len() as u64 > MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_ROOTFS_BYTES_V1
            || runtime_manifest_bytes.is_empty()
            || runtime_manifest_bytes.len() > MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_MANIFEST_BYTES_V1
            || package_runner_bytes.is_empty()
            || package_runner_bytes.len() > MAX_MACOS_LINUX_VZ_CANDIDATE_PACKAGE_RUNNER_BYTES_V1
        {
            return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid);
        }
        let value = Self {
            rootfs_sha256: Sha256Digest::from_bytes(rootfs_bytes),
            rootfs_byte_length: rootfs_bytes.len() as u64,
            runtime_manifest_sha256: Sha256Digest::from_bytes(runtime_manifest_bytes),
            package_runner_sha256: Sha256Digest::from_bytes(package_runner_bytes),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn from_exact_files(
        rootfs_path: &Path,
        runtime_manifest_path: &Path,
        package_runner_path: &Path,
    ) -> Result<Self, MacosLinuxVzPackageAuthorityRequestErrorV1> {
        let (rootfs_sha256, rootfs_byte_length) = hash_regular_nofollow_v1(
            rootfs_path,
            MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_ROOTFS_BYTES_V1,
        )?;
        let runtime_manifest_bytes = read_regular_nofollow_v1(
            runtime_manifest_path,
            MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_MANIFEST_BYTES_V1 as u64,
        )?;
        let package_runner_bytes = read_regular_nofollow_v1(
            package_runner_path,
            MAX_MACOS_LINUX_VZ_CANDIDATE_PACKAGE_RUNNER_BYTES_V1 as u64,
        )?;
        let value = Self {
            rootfs_sha256,
            rootfs_byte_length,
            runtime_manifest_sha256: Sha256Digest::from_bytes(&runtime_manifest_bytes),
            package_runner_sha256: Sha256Digest::from_bytes(&package_runner_bytes),
        };
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn validate(&self) -> Result<(), MacosLinuxVzPackageAuthorityRequestErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        if self.rootfs_byte_length == 0
            || self.rootfs_byte_length > MAX_MACOS_LINUX_VZ_CANDIDATE_RUNTIME_ROOTFS_BYTES_V1
            || self.rootfs_sha256 == empty
            || self.runtime_manifest_sha256 == empty
            || self.package_runner_sha256 == empty
            || self.rootfs_sha256 == self.runtime_manifest_sha256
            || self.rootfs_sha256 == self.package_runner_sha256
            || self.runtime_manifest_sha256 == self.package_runner_sha256
        {
            return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid);
        }
        Ok(())
    }

    pub fn rootfs_sha256(&self) -> &Sha256Digest {
        &self.rootfs_sha256
    }

    pub const fn rootfs_byte_length(&self) -> u64 {
        self.rootfs_byte_length
    }

    pub fn runtime_manifest_sha256(&self) -> &Sha256Digest {
        &self.runtime_manifest_sha256
    }

    pub fn package_runner_sha256(&self) -> &Sha256Digest {
        &self.package_runner_sha256
    }
}

fn read_regular_nofollow_v1(
    path: &Path,
    maximum: u64,
) -> Result<Vec<u8>, MacosLinuxVzPackageAuthorityRequestErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?;
    let metadata = file
        .metadata()
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > maximum {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid);
    }
    Ok(bytes)
}

fn hash_regular_nofollow_v1(
    path: &Path,
    maximum: u64,
) -> Result<(Sha256Digest, u64), MacosLinuxVzPackageAuthorityRequestErrorV1> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?;
    let metadata = file
        .metadata()
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?;
    let length = metadata.len();
    if !metadata.file_type().is_file() || length == 0 || length > maximum {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid);
    }
    let mut hasher = Sha256::new();
    let mut observed = 0_u64;
    let mut buffer = vec![0_u8; 1024 * 1024];
    while observed < length {
        let requested = usize::try_from((length - observed).min(buffer.len() as u64))
            .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?;
        let count = file
            .read(&mut buffer[..requested])
            .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?;
        if count == 0 {
            return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid);
        }
        hasher.update(&buffer[..count]);
        observed += count as u64;
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?
        != 0
    {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid);
    }
    let digest = hasher.finalize();
    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        text.push(HEX[(byte >> 4) as usize] as char);
        text.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok((
        Sha256Digest::parse(text)
            .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::CandidateRuntimeInvalid)?,
        length,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageAuthorityRequestWireV1 {
    schema_version: String,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: String,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_plan_id: String,
    scenario_template_sha256: Sha256Digest,
    scenario_id: String,
    scenario_kind: serde_json::Value,
    scenario_kind_sha256: Sha256Digest,
    scenario_policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    runtime_target: ArtifactRuntimeTargetV1,
    runtime_profile_sha256: Sha256Digest,
    candidate_runtime_qualification_state: MacosLinuxVzCandidateRuntimeQualificationStateV1,
    candidate_runtime_rootfs_sha256: Sha256Digest,
    candidate_runtime_rootfs_byte_length: String,
    candidate_runtime_manifest_sha256: Sha256Digest,
    candidate_package_runner_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    conformance_evidence_set_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    artifact_transport: ArtifactTransportV1,
    network_policy: ArtifactNetworkPolicyV1,
    package_privilege: ArtifactPackagePrivilegeV1,
    clone_disposition: ArtifactCloneDispositionV1,
    execution_eligibility: String,
    execution_authority_issued: bool,
    package_execution_permitted: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzPackageAuthorityRequestV1 {
    canonical_json: Vec<u8>,
    request_sha256: Sha256Digest,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_sha256: Sha256Digest,
    scenario_plan_sha256: Sha256Digest,
    scenario_template_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
    qualified_telemetry_backend_sha256: Sha256Digest,
    request_challenge_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
}

impl fmt::Debug for MacosLinuxVzPackageAuthorityRequestV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzPackageAuthorityRequestV1")
            .field("request_sha256", &self.request_sha256)
            .field("artifact_kind", &self.artifact_kind)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("scenario_plan_sha256", &self.scenario_plan_sha256)
            .field("scenario_template_sha256", &self.scenario_template_sha256)
            .field("runtime_profile_sha256", &self.runtime_profile_sha256)
            .field(
                "qualified_telemetry_backend_sha256",
                &self.qualified_telemetry_backend_sha256,
            )
            .field("request_challenge_sha256", &self.request_challenge_sha256)
            .field("clone_binding_sha256", &self.clone_binding_sha256)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosLinuxVzPackageAuthorityRequestV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub const fn artifact_kind(&self) -> MacosLinuxVzPackageArtifactKindV1 {
        self.artifact_kind
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn scenario_plan_sha256(&self) -> &Sha256Digest {
        &self.scenario_plan_sha256
    }

    pub fn scenario_template_sha256(&self) -> &Sha256Digest {
        &self.scenario_template_sha256
    }

    pub fn runtime_profile_sha256(&self) -> &Sha256Digest {
        &self.runtime_profile_sha256
    }

    pub fn qualified_telemetry_backend_sha256(&self) -> &Sha256Digest {
        &self.qualified_telemetry_backend_sha256
    }

    pub fn request_challenge_sha256(&self) -> &Sha256Digest {
        &self.request_challenge_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub const fn eligible_for_independent_runtime_qualification(&self) -> bool {
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
pub enum MacosLinuxVzPackageAuthorityRequestErrorV1 {
    BackendNotEligible,
    ArtifactInvalid,
    ScenarioPlanInvalid,
    ScenarioTemplateInvalid,
    PlanTemplateMismatch,
    RuntimeTargetMismatch,
    CandidateRuntimeInvalid,
    ChallengeInvalid,
    CloneBindingInvalid,
    InvalidRequest,
    NonCanonical,
    BindingMismatch,
    LimitExceeded,
    Serialization,
}

impl MacosLinuxVzPackageAuthorityRequestErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::BackendNotEligible => "macos_linux_vz_package_authority_backend_not_eligible",
            Self::ArtifactInvalid => "macos_linux_vz_package_authority_artifact_invalid",
            Self::ScenarioPlanInvalid => "macos_linux_vz_package_authority_plan_invalid",
            Self::ScenarioTemplateInvalid => "macos_linux_vz_package_authority_template_invalid",
            Self::PlanTemplateMismatch => "macos_linux_vz_package_authority_plan_template_mismatch",
            Self::RuntimeTargetMismatch => {
                "macos_linux_vz_package_authority_runtime_target_mismatch"
            }
            Self::CandidateRuntimeInvalid => {
                "macos_linux_vz_package_authority_candidate_runtime_invalid"
            }
            Self::ChallengeInvalid => "macos_linux_vz_package_authority_challenge_invalid",
            Self::CloneBindingInvalid => "macos_linux_vz_package_authority_clone_invalid",
            Self::InvalidRequest => "macos_linux_vz_package_authority_request_invalid",
            Self::NonCanonical => "macos_linux_vz_package_authority_request_noncanonical",
            Self::BindingMismatch => "macos_linux_vz_package_authority_binding_mismatch",
            Self::LimitExceeded => "macos_linux_vz_package_authority_limit_exceeded",
            Self::Serialization => "macos_linux_vz_package_authority_serialization_failed",
        }
    }
}

impl fmt::Display for MacosLinuxVzPackageAuthorityRequestErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzPackageAuthorityRequestErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosLinuxVzTypedPackageScenarioBindingV1 {
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    artifact_byte_length: u64,
    scenario_plan_sha256: Sha256Digest,
    scenario_plan_id: String,
    scenario_template_sha256: Sha256Digest,
    scenario_id: String,
    scenario_kind: serde_json::Value,
    scenario_kind_sha256: Sha256Digest,
    scenario_policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
}

impl MacosLinuxVzTypedPackageScenarioBindingV1 {
    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn envelope_sha256(&self) -> &Sha256Digest {
        &self.envelope_sha256
    }

    pub fn manifest_sha256(&self) -> &Sha256Digest {
        &self.manifest_sha256
    }

    pub const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn scenario_plan_sha256(&self) -> &Sha256Digest {
        &self.scenario_plan_sha256
    }

    pub fn scenario_template_sha256(&self) -> &Sha256Digest {
        &self.scenario_template_sha256
    }

    pub fn scenario_policy_sha256(&self) -> &Sha256Digest {
        &self.scenario_policy_sha256
    }

    pub fn dependency_closure_sha256(&self) -> &Sha256Digest {
        &self.dependency_closure_sha256
    }

    pub fn runtime_profile_sha256(&self) -> &Sha256Digest {
        &self.runtime_profile_sha256
    }

    pub const fn runtime_target(&self) -> ArtifactRuntimeTargetV1 {
        ArtifactRuntimeTargetV1::LinuxArm64
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }

    pub const fn sync_back_permitted(&self) -> bool {
        false
    }
}

#[allow(clippy::too_many_arguments)]
pub fn build_macos_linux_vz_package_authority_request_v1(
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_bytes: &[u8],
    scenario_plan_bytes: &[u8],
    scenario_template_bytes: &[u8],
    candidate_runtime: &MacosLinuxVzCandidatePackageRuntimeV1,
    request_challenge: [u8; 32],
    clone_binding_sha256: Sha256Digest,
) -> Result<MacosLinuxVzPackageAuthorityRequestV1, MacosLinuxVzPackageAuthorityRequestErrorV1> {
    if !qualified_backend.eligible_for_typed_package_execution_authority_request()
        || qualified_backend.package_execution_authority_permitted()
        || qualified_backend.sync_back_permitted()
    {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::BackendNotEligible);
    }
    if artifact_bytes.is_empty() {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::ArtifactInvalid);
    }
    candidate_runtime.validate()?;
    if request_challenge == [0_u8; 32] {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::ChallengeInvalid);
    }
    let request_challenge_sha256 = Sha256Digest::from_bytes(&request_challenge);
    let empty_sha256 = Sha256Digest::from_bytes(&[]);
    if clone_binding_sha256 == empty_sha256 || clone_binding_sha256 == request_challenge_sha256 {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::CloneBindingInvalid);
    }

    let binding = validate_macos_linux_vz_typed_package_scenario_binding_v1(
        artifact_kind,
        scenario_plan_bytes,
        scenario_template_bytes,
    )?;
    let exact_artifact_sha256 = Sha256Digest::from_bytes(artifact_bytes);
    if binding.artifact_sha256 != exact_artifact_sha256
        || binding.artifact_byte_length != artifact_bytes.len() as u64
    {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::ArtifactInvalid);
    }

    let wire = PackageAuthorityRequestWireV1 {
        schema_version: MACOS_LINUX_VZ_PACKAGE_AUTHORITY_REQUEST_SCHEMA_V1.to_string(),
        artifact_kind,
        artifact_sha256: binding.artifact_sha256.clone(),
        artifact_byte_length: binding.artifact_byte_length.to_string(),
        envelope_sha256: binding.envelope_sha256,
        manifest_sha256: binding.manifest_sha256,
        scenario_plan_sha256: binding.scenario_plan_sha256.clone(),
        scenario_plan_id: binding.scenario_plan_id,
        scenario_template_sha256: binding.scenario_template_sha256.clone(),
        scenario_id: binding.scenario_id,
        scenario_kind: binding.scenario_kind,
        scenario_kind_sha256: binding.scenario_kind_sha256,
        scenario_policy_sha256: binding.scenario_policy_sha256,
        dependency_closure_sha256: binding.dependency_closure_sha256,
        runtime_target: ArtifactRuntimeTargetV1::LinuxArm64,
        runtime_profile_sha256: binding.runtime_profile_sha256.clone(),
        candidate_runtime_qualification_state:
            MacosLinuxVzCandidateRuntimeQualificationStateV1::CandidateExactBytesNotYetIndependentlyQualified,
        candidate_runtime_rootfs_sha256: candidate_runtime.rootfs_sha256.clone(),
        candidate_runtime_rootfs_byte_length: candidate_runtime.rootfs_byte_length.to_string(),
        candidate_runtime_manifest_sha256: candidate_runtime.runtime_manifest_sha256.clone(),
        candidate_package_runner_sha256: candidate_runtime.package_runner_sha256.clone(),
        qualified_telemetry_backend_sha256: qualified_backend.qualified_backend_sha256().clone(),
        backend_identity_sha256: qualified_backend.backend_identity_sha256().clone(),
        telemetry_requirements_sha256: qualified_backend.telemetry_requirements_sha256().clone(),
        conformance_evidence_set_sha256: qualified_backend
            .conformance_evidence_set_sha256()
            .clone(),
        request_challenge_sha256: request_challenge_sha256.clone(),
        clone_binding_sha256: clone_binding_sha256.clone(),
        artifact_transport: ArtifactTransportV1::DigestCheckedBoundedRawBytes,
        network_policy: ArtifactNetworkPolicyV1::NoNetworkDevice,
        package_privilege: ArtifactPackagePrivilegeV1::DedicatedUnprivilegedUidGid,
        clone_disposition: ArtifactCloneDispositionV1::DestroyClone,
        execution_eligibility:
            "independent_runtime_qualification_then_one_use_execution_grant".to_string(),
        execution_authority_issued: false,
        package_execution_permitted: false,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::Serialization)?;
    if canonical_json.is_empty()
        || canonical_json.len() > MAX_MACOS_LINUX_VZ_PACKAGE_AUTHORITY_REQUEST_BYTES_V1
    {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzPackageAuthorityRequestV1 {
        request_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        artifact_kind,
        artifact_sha256: exact_artifact_sha256,
        scenario_plan_sha256: binding.scenario_plan_sha256,
        scenario_template_sha256: binding.scenario_template_sha256,
        runtime_profile_sha256: binding.runtime_profile_sha256,
        qualified_telemetry_backend_sha256: qualified_backend.qualified_backend_sha256().clone(),
        request_challenge_sha256,
        clone_binding_sha256,
    })
}

#[allow(clippy::too_many_arguments)]
pub fn decode_and_verify_macos_linux_vz_package_authority_request_v1(
    bytes: &[u8],
    qualified_backend: &QualifiedMacosLinuxVzTelemetryBackendV1,
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    artifact_bytes: &[u8],
    scenario_plan_bytes: &[u8],
    scenario_template_bytes: &[u8],
    candidate_runtime: &MacosLinuxVzCandidatePackageRuntimeV1,
    request_challenge: [u8; 32],
    clone_binding_sha256: Sha256Digest,
) -> Result<MacosLinuxVzPackageAuthorityRequestV1, MacosLinuxVzPackageAuthorityRequestErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_MACOS_LINUX_VZ_PACKAGE_AUTHORITY_REQUEST_BYTES_V1 {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = PackageAuthorityRequestWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::InvalidRequest)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::InvalidRequest)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::NonCanonical);
    }
    let expected = build_macos_linux_vz_package_authority_request_v1(
        qualified_backend,
        artifact_kind,
        artifact_bytes,
        scenario_plan_bytes,
        scenario_template_bytes,
        candidate_runtime,
        request_challenge,
        clone_binding_sha256,
    )?;
    if expected.canonical_json_v1() != bytes {
        return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::BindingMismatch);
    }
    Ok(expected)
}

pub fn validate_macos_linux_vz_typed_package_scenario_binding_v1(
    artifact_kind: MacosLinuxVzPackageArtifactKindV1,
    scenario_plan_bytes: &[u8],
    scenario_template_bytes: &[u8],
) -> Result<MacosLinuxVzTypedPackageScenarioBindingV1, MacosLinuxVzPackageAuthorityRequestErrorV1> {
    let binding = match artifact_kind {
        MacosLinuxVzPackageArtifactKindV1::NpmTarball => {
            let plan = decode_and_validate_artifact_scenario_plan_v1(scenario_plan_bytes)
                .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::ScenarioPlanInvalid)?;
            let template =
                decode_and_validate_artifact_scenario_template_v1(scenario_template_bytes)
                    .map_err(|_| {
                        MacosLinuxVzPackageAuthorityRequestErrorV1::ScenarioTemplateInvalid
                    })?;
            if template.runtime_target() != ArtifactRuntimeTargetV1::LinuxArm64 {
                return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::RuntimeTargetMismatch);
            }
            let selected = plan
                .templates()
                .iter()
                .any(|(scenario_id, environment, digest)| {
                    scenario_id == template.scenario_id()
                        && *environment == template.environment()
                        && digest == template.template_sha256()
                });
            if !selected
                || plan.artifact_sha256() != template.artifact_sha256()
                || plan.envelope_sha256() != template.envelope_sha256()
                || plan.manifest_sha256() != template.manifest_sha256()
                || plan.policy_sha256() != template.policy_sha256()
            {
                return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::PlanTemplateMismatch);
            }
            scenario_binding_v1(
                plan.artifact_sha256().clone(),
                template.envelope_sha256().clone(),
                template.manifest_sha256().clone(),
                template.artifact_byte_length(),
                plan.plan_sha256().clone(),
                plan.plan_id().to_string(),
                template.template_sha256().clone(),
                template.scenario_id().to_string(),
                &ArtifactScenarioKindV1::NpmLocalTarballInstall {
                    environment: template.environment(),
                },
                template.policy_sha256().clone(),
                template.dependency_closure_sha256().clone(),
                template.runtime_profile_sha256().clone(),
            )?
        }
        MacosLinuxVzPackageArtifactKindV1::PypiWheel => {
            let plan = decode_and_validate_wheel_scenario_plan_v1(scenario_plan_bytes)
                .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::ScenarioPlanInvalid)?;
            let template = decode_and_validate_wheel_scenario_template_v1(scenario_template_bytes)
                .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::ScenarioTemplateInvalid)?;
            if template.runtime_target() != ArtifactRuntimeTargetV1::LinuxArm64 {
                return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::RuntimeTargetMismatch);
            }
            let selected = plan.templates().iter().any(|(scenario_id, kind, digest)| {
                scenario_id == template.scenario_id()
                    && kind == template.scenario_kind()
                    && digest == template.template_sha256()
            });
            if !selected
                || plan.artifact_sha256() != template.artifact_sha256()
                || plan.envelope_sha256() != template.envelope_sha256()
                || plan.manifest_sha256() != template.manifest_sha256()
                || plan.policy_sha256() != template.policy_sha256()
            {
                return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::PlanTemplateMismatch);
            }
            scenario_binding_v1(
                plan.artifact_sha256().clone(),
                template.envelope_sha256().clone(),
                template.manifest_sha256().clone(),
                template.artifact_byte_length(),
                plan.plan_sha256().clone(),
                plan.plan_id().to_string(),
                template.template_sha256().clone(),
                template.scenario_id().to_string(),
                template.scenario_kind(),
                template.policy_sha256().clone(),
                template.dependency_closure_sha256().clone(),
                template.runtime_profile_sha256().clone(),
            )?
        }
        MacosLinuxVzPackageArtifactKindV1::PypiSdist => {
            let plan = decode_and_validate_sdist_scenario_plan_v1(scenario_plan_bytes)
                .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::ScenarioPlanInvalid)?;
            let template = decode_and_validate_sdist_scenario_template_v1(scenario_template_bytes)
                .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::ScenarioTemplateInvalid)?;
            if template.runtime_target() != ArtifactRuntimeTargetV1::LinuxArm64 {
                return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::RuntimeTargetMismatch);
            }
            let selected = plan.templates().iter().any(|(scenario_id, kind, digest)| {
                scenario_id == template.scenario_id()
                    && kind == template.scenario_kind()
                    && digest == template.template_sha256()
            });
            if !selected
                || plan.artifact_sha256() != template.artifact_sha256()
                || plan.envelope_sha256() != template.envelope_sha256()
                || plan.manifest_sha256() != template.manifest_sha256()
                || plan.policy_sha256() != template.policy_sha256()
            {
                return Err(MacosLinuxVzPackageAuthorityRequestErrorV1::PlanTemplateMismatch);
            }
            scenario_binding_v1(
                plan.artifact_sha256().clone(),
                template.envelope_sha256().clone(),
                template.manifest_sha256().clone(),
                template.artifact_byte_length(),
                plan.plan_sha256().clone(),
                plan.plan_id().to_string(),
                template.template_sha256().clone(),
                template.scenario_id().to_string(),
                template.scenario_kind(),
                template.policy_sha256().clone(),
                template.build_closure_sha256().clone(),
                template.runtime_profile_sha256().clone(),
            )?
        }
    };
    Ok(binding)
}

#[allow(clippy::too_many_arguments)]
fn scenario_binding_v1<T: Serialize>(
    artifact_sha256: Sha256Digest,
    envelope_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    artifact_byte_length: u64,
    scenario_plan_sha256: Sha256Digest,
    scenario_plan_id: String,
    scenario_template_sha256: Sha256Digest,
    scenario_id: String,
    scenario_kind: &T,
    scenario_policy_sha256: Sha256Digest,
    dependency_closure_sha256: Sha256Digest,
    runtime_profile_sha256: Sha256Digest,
) -> Result<MacosLinuxVzTypedPackageScenarioBindingV1, MacosLinuxVzPackageAuthorityRequestErrorV1> {
    let scenario_kind = serde_json::to_value(scenario_kind)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::Serialization)?;
    let scenario_kind_bytes = serde_json_canonicalizer::to_vec(&scenario_kind)
        .map_err(|_| MacosLinuxVzPackageAuthorityRequestErrorV1::Serialization)?;
    Ok(MacosLinuxVzTypedPackageScenarioBindingV1 {
        artifact_sha256,
        envelope_sha256,
        manifest_sha256,
        artifact_byte_length,
        scenario_plan_sha256,
        scenario_plan_id,
        scenario_template_sha256,
        scenario_id,
        scenario_kind_sha256: Sha256Digest::from_bytes(&scenario_kind_bytes),
        scenario_kind,
        scenario_policy_sha256,
        dependency_closure_sha256,
        runtime_profile_sha256,
    })
}
