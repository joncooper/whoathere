use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    decode_and_validate_artifact_scenario_template_v1, ArtifactScenarioTemplateV1,
    ValidatedArtifactScenarioTemplateWireV1,
};

pub const MACOS_ARTIFACT_RUN_SPEC_SCHEMA_V1: &str = "whoathere.macos_artifact_run_spec.v1";
pub const MACOS_ARTIFACT_RUN_SPEC_CANONICALIZATION_V1: &str = "rfc8785.jcs.v1";
pub const MACOS_ARTIFACT_GUEST_PROTOCOL_V1: &str = "whoathere.artifact_scenario.v1";
pub const MAX_MACOS_ARTIFACT_RUN_SPEC_BYTES_V1: usize = 512 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosArtifactRunErrorV1 {
    InvalidBackendIdentity,
    BackendCapabilityMismatch,
    InvalidTemplate,
    InvalidRunSpec,
    Serialization,
    LimitExceeded,
    InvalidSubmission,
    ArtifactDigestMismatch,
    IoFailed,
}

impl MacosArtifactRunErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidBackendIdentity => "macos_artifact_backend_identity_invalid",
            Self::BackendCapabilityMismatch => "macos_artifact_backend_capability_mismatch",
            Self::InvalidTemplate => "macos_artifact_template_invalid",
            Self::InvalidRunSpec => "macos_artifact_run_spec_invalid",
            Self::Serialization => "macos_artifact_serialization_failed",
            Self::LimitExceeded => "macos_artifact_limit_exceeded",
            Self::InvalidSubmission => "macos_artifact_submission_invalid",
            Self::ArtifactDigestMismatch => "macos_artifact_digest_mismatch",
            Self::IoFailed => "macos_artifact_io_failed",
        }
    }
}

impl fmt::Display for MacosArtifactRunErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosArtifactRunErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosArtifactClonePolicyV1 {
    ApfsCloneRequiredNoCopyFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosArtifactNetworkConfigurationV1 {
    ZeroNetworkDevices,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosArtifactVmReusePolicyV1 {
    OneBootOneScenarioDestroyClone,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosArtifactBackendIdentityV1 {
    base_generation_id: String,
    base_disk_sha256: Sha256Digest,
    base_auxiliary_storage_sha256: Sha256Digest,
    hardware_model_sha256: Sha256Digest,
    machine_identifier_sha256: Sha256Digest,
    cpu_count: u16,
    memory_mib: u64,
    post_provisioning_receipt_sha256: Sha256Digest,
    helper_sha256: Sha256Digest,
    guest_supervisor_sha256: Sha256Digest,
    guest_auth_public_key_sha256: Sha256Digest,
    runner_configuration_sha256: Sha256Digest,
    package_uid: u32,
    package_gid: u32,
    node_version: String,
    node_executable_sha256: Sha256Digest,
    npm_version: String,
    npm_cli_sha256: Sha256Digest,
    clone_implementation_sha256: Sha256Digest,
    guest_protocol_sha256: Sha256Digest,
}

impl fmt::Debug for MacosArtifactBackendIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosArtifactBackendIdentityV1")
            .field("base_generation_id", &self.base_generation_id)
            .field("base_disk_sha256", &self.base_disk_sha256)
            .field(
                "base_auxiliary_storage_sha256",
                &self.base_auxiliary_storage_sha256,
            )
            .field("hardware_model_sha256", &self.hardware_model_sha256)
            .field("machine_identifier_sha256", &self.machine_identifier_sha256)
            .field("cpu_count", &self.cpu_count)
            .field("memory_mib", &self.memory_mib)
            .field(
                "post_provisioning_receipt_sha256",
                &self.post_provisioning_receipt_sha256,
            )
            .field("helper_sha256", &self.helper_sha256)
            .field("guest_supervisor_sha256", &self.guest_supervisor_sha256)
            .field(
                "guest_auth_public_key_sha256",
                &self.guest_auth_public_key_sha256,
            )
            .field(
                "runner_configuration_sha256",
                &self.runner_configuration_sha256,
            )
            .field("package_uid", &self.package_uid)
            .field("package_gid", &self.package_gid)
            .field("node_version", &self.node_version)
            .field("node_executable_sha256", &self.node_executable_sha256)
            .field("npm_version", &self.npm_version)
            .field("npm_cli_sha256", &self.npm_cli_sha256)
            .field(
                "clone_implementation_sha256",
                &self.clone_implementation_sha256,
            )
            .field("guest_protocol_sha256", &self.guest_protocol_sha256)
            .finish()
    }
}

impl MacosArtifactBackendIdentityV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base_generation_id: impl Into<String>,
        base_disk_sha256: Sha256Digest,
        base_auxiliary_storage_sha256: Sha256Digest,
        hardware_model_sha256: Sha256Digest,
        machine_identifier_sha256: Sha256Digest,
        cpu_count: u16,
        memory_mib: u64,
        post_provisioning_receipt_sha256: Sha256Digest,
        helper_sha256: Sha256Digest,
        guest_supervisor_sha256: Sha256Digest,
        guest_auth_public_key_sha256: Sha256Digest,
        runner_configuration_sha256: Sha256Digest,
        package_uid: u32,
        package_gid: u32,
        node_version: impl Into<String>,
        node_executable_sha256: Sha256Digest,
        npm_version: impl Into<String>,
        npm_cli_sha256: Sha256Digest,
        clone_implementation_sha256: Sha256Digest,
    ) -> Result<Self, MacosArtifactRunErrorV1> {
        let value = Self {
            base_generation_id: base_generation_id.into(),
            base_disk_sha256,
            base_auxiliary_storage_sha256,
            hardware_model_sha256,
            machine_identifier_sha256,
            cpu_count,
            memory_mib,
            post_provisioning_receipt_sha256,
            helper_sha256,
            guest_supervisor_sha256,
            guest_auth_public_key_sha256,
            runner_configuration_sha256,
            package_uid,
            package_gid,
            node_version: node_version.into(),
            node_executable_sha256,
            npm_version: npm_version.into(),
            npm_cli_sha256,
            clone_implementation_sha256,
            guest_protocol_sha256: Sha256Digest::from_bytes(
                MACOS_ARTIFACT_GUEST_PROTOCOL_V1.as_bytes(),
            ),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn base_generation_id(&self) -> &str {
        &self.base_generation_id
    }

    pub fn node_version(&self) -> &str {
        &self.node_version
    }

    pub fn hardware_model_sha256(&self) -> &Sha256Digest {
        &self.hardware_model_sha256
    }

    pub fn machine_identifier_sha256(&self) -> &Sha256Digest {
        &self.machine_identifier_sha256
    }

    pub const fn cpu_count(&self) -> u16 {
        self.cpu_count
    }

    pub const fn memory_mib(&self) -> u64 {
        self.memory_mib
    }

    pub const fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub const fn package_gid(&self) -> u32 {
        self.package_gid
    }

    pub fn node_executable_sha256(&self) -> &Sha256Digest {
        &self.node_executable_sha256
    }

    pub fn npm_version(&self) -> &str {
        &self.npm_version
    }

    pub fn npm_cli_sha256(&self) -> &Sha256Digest {
        &self.npm_cli_sha256
    }

    fn validate(&self) -> Result<(), MacosArtifactRunErrorV1> {
        if !valid_identity_v1(&self.base_generation_id)
            || self.cpu_count == 0
            || self.memory_mib < 1_024
            || self.memory_mib > 1_048_576
            || self.package_uid == 0
            || self.package_gid == 0
            || !valid_version_v1(&self.node_version)
            || !valid_version_v1(&self.npm_version)
            || self.guest_protocol_sha256
                != Sha256Digest::from_bytes(MACOS_ARTIFACT_GUEST_PROTOCOL_V1.as_bytes())
        {
            return Err(MacosArtifactRunErrorV1::InvalidBackendIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosArtifactBackendCapabilitiesV1 {
    identity: MacosArtifactBackendIdentityV1,
    clone_policy: MacosArtifactClonePolicyV1,
    network_configuration: MacosArtifactNetworkConfigurationV1,
    reuse_policy: MacosArtifactVmReusePolicyV1,
}

impl MacosArtifactBackendCapabilitiesV1 {
    pub fn inert_first_slice(identity: MacosArtifactBackendIdentityV1) -> Self {
        Self {
            identity,
            clone_policy: MacosArtifactClonePolicyV1::ApfsCloneRequiredNoCopyFallback,
            network_configuration: MacosArtifactNetworkConfigurationV1::ZeroNetworkDevices,
            reuse_policy: MacosArtifactVmReusePolicyV1::OneBootOneScenarioDestroyClone,
        }
    }

    pub fn identity(&self) -> &MacosArtifactBackendIdentityV1 {
        &self.identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MacosArtifactRunSpecWireV1 {
    schema_version: String,
    canonicalization: String,
    template: serde_json::Value,
    template_sha256: Sha256Digest,
    backend_identity: MacosArtifactBackendIdentityV1,
    clone_policy: MacosArtifactClonePolicyV1,
    network_configuration: MacosArtifactNetworkConfigurationV1,
    reuse_policy: MacosArtifactVmReusePolicyV1,
    guest_protocol: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosArtifactRunSpecV1 {
    canonical_json: Vec<u8>,
    run_spec_sha256: Sha256Digest,
    template_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    scenario_id: String,
    backend_identity: MacosArtifactBackendIdentityV1,
}

impl fmt::Debug for MacosArtifactRunSpecV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosArtifactRunSpecV1")
            .field("run_spec_sha256", &self.run_spec_sha256)
            .field("template_sha256", &self.template_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("artifact_byte_length", &self.artifact_byte_length)
            .field("scenario_id", &self.scenario_id)
            .field("backend_identity", &self.backend_identity)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosArtifactRunSpecV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn run_spec_sha256(&self) -> &Sha256Digest {
        &self.run_spec_sha256
    }

    pub fn template_sha256(&self) -> &Sha256Digest {
        &self.template_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn backend_identity(&self) -> &MacosArtifactBackendIdentityV1 {
        &self.backend_identity
    }
}

pub fn compile_macos_artifact_run_spec_v1(
    template: &ArtifactScenarioTemplateV1,
    backend: &MacosArtifactBackendCapabilitiesV1,
) -> Result<MacosArtifactRunSpecV1, MacosArtifactRunErrorV1> {
    backend.identity.validate()?;
    let template_bytes = template
        .canonical_json_v1()
        .map_err(|_| MacosArtifactRunErrorV1::InvalidTemplate)?;
    if Sha256Digest::from_bytes(&template_bytes) != *template.template_sha256() {
        return Err(MacosArtifactRunErrorV1::InvalidTemplate);
    }
    let validated = decode_and_validate_artifact_scenario_template_v1(&template_bytes)
        .map_err(|_| MacosArtifactRunErrorV1::InvalidTemplate)?;
    require_backend_match_v1(&validated, &backend.identity)?;
    let template_value = serde_json::from_slice(&template_bytes)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    let wire = MacosArtifactRunSpecWireV1 {
        schema_version: MACOS_ARTIFACT_RUN_SPEC_SCHEMA_V1.to_string(),
        canonicalization: MACOS_ARTIFACT_RUN_SPEC_CANONICALIZATION_V1.to_string(),
        template: template_value,
        template_sha256: template.template_sha256().clone(),
        backend_identity: backend.identity.clone(),
        clone_policy: backend.clone_policy,
        network_configuration: backend.network_configuration,
        reuse_policy: backend.reuse_policy,
        guest_protocol: MACOS_ARTIFACT_GUEST_PROTOCOL_V1.to_string(),
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    if canonical_json.len() > MAX_MACOS_ARTIFACT_RUN_SPEC_BYTES_V1 {
        return Err(MacosArtifactRunErrorV1::LimitExceeded);
    }
    let run_spec_sha256 = Sha256Digest::from_bytes(&canonical_json);
    Ok(MacosArtifactRunSpecV1 {
        canonical_json,
        run_spec_sha256,
        template_sha256: template.template_sha256().clone(),
        artifact_sha256: validated.artifact_sha256().clone(),
        artifact_byte_length: validated.artifact_byte_length(),
        scenario_id: validated.scenario_id().to_string(),
        backend_identity: backend.identity.clone(),
    })
}

pub fn decode_and_validate_macos_artifact_run_spec_v1(
    bytes: &[u8],
) -> Result<MacosArtifactRunSpecV1, MacosArtifactRunErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_MACOS_ARTIFACT_RUN_SPEC_BYTES_V1 {
        return Err(MacosArtifactRunErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = MacosArtifactRunSpecWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosArtifactRunErrorV1::InvalidRunSpec)?;
    deserializer
        .end()
        .map_err(|_| MacosArtifactRunErrorV1::InvalidRunSpec)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    if canonical != bytes
        || wire.schema_version != MACOS_ARTIFACT_RUN_SPEC_SCHEMA_V1
        || wire.canonicalization != MACOS_ARTIFACT_RUN_SPEC_CANONICALIZATION_V1
        || wire.clone_policy != MacosArtifactClonePolicyV1::ApfsCloneRequiredNoCopyFallback
        || wire.network_configuration != MacosArtifactNetworkConfigurationV1::ZeroNetworkDevices
        || wire.reuse_policy != MacosArtifactVmReusePolicyV1::OneBootOneScenarioDestroyClone
        || wire.guest_protocol != MACOS_ARTIFACT_GUEST_PROTOCOL_V1
    {
        return Err(MacosArtifactRunErrorV1::InvalidRunSpec);
    }
    wire.backend_identity.validate()?;
    let template_bytes = serde_json_canonicalizer::to_vec(&wire.template)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    if Sha256Digest::from_bytes(&template_bytes) != wire.template_sha256 {
        return Err(MacosArtifactRunErrorV1::InvalidRunSpec);
    }
    let validated = decode_and_validate_artifact_scenario_template_v1(&template_bytes)
        .map_err(|_| MacosArtifactRunErrorV1::InvalidTemplate)?;
    require_backend_match_v1(&validated, &wire.backend_identity)?;
    Ok(MacosArtifactRunSpecV1 {
        canonical_json: canonical,
        run_spec_sha256: Sha256Digest::from_bytes(bytes),
        template_sha256: wire.template_sha256,
        artifact_sha256: validated.artifact_sha256().clone(),
        artifact_byte_length: validated.artifact_byte_length(),
        scenario_id: validated.scenario_id().to_string(),
        backend_identity: wire.backend_identity,
    })
}

fn require_backend_match_v1(
    template: &ValidatedArtifactScenarioTemplateWireV1,
    backend: &MacosArtifactBackendIdentityV1,
) -> Result<(), MacosArtifactRunErrorV1> {
    if template.node_version() != backend.node_version
        || template.node_executable_sha256() != &backend.node_executable_sha256
        || template.npm_version() != backend.npm_version
        || template.npm_cli_sha256() != &backend.npm_cli_sha256
    {
        return Err(MacosArtifactRunErrorV1::BackendCapabilityMismatch);
    }
    Ok(())
}

fn valid_identity_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
}

fn valid_version_v1(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}
