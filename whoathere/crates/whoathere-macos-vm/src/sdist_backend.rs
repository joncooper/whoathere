use crate::{
    MacosArtifactClonePolicyV1, MacosArtifactNetworkConfigurationV1, MacosArtifactRunErrorV1,
    MacosArtifactVmReusePolicyV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    decode_and_validate_sdist_scenario_template_v1, SdistScenarioKindV1, SdistScenarioTemplateV1,
    ValidatedSdistScenarioTemplateWireV1,
};

pub const MACOS_SDIST_RUN_SPEC_SCHEMA_V1: &str = "whoathere.macos_sdist_run_spec.v1";
pub const MACOS_SDIST_RUN_SPEC_CANONICALIZATION_V1: &str = "rfc8785.jcs.v1";
pub const MACOS_SDIST_GUEST_PROTOCOL_V1: &str = "whoathere.sdist_artifact_scenario.v1";
pub const MAX_MACOS_SDIST_RUN_SPEC_BYTES_V1: usize = 512 * 1024;
pub const MACOS_SDIST_PACKAGE_USERNAME_V1: &str = "_whoatherepkg";

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MacosSdistBackendIdentityV1 {
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
    package_username: String,
    package_uid: u32,
    package_gid: u32,
    python_version: String,
    python_executable_sha256: Sha256Digest,
    pip_version: String,
    pip_cli_sha256: Sha256Digest,
    clone_implementation_sha256: Sha256Digest,
    guest_protocol_sha256: Sha256Digest,
}

impl fmt::Debug for MacosSdistBackendIdentityV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSdistBackendIdentityV1")
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
            .field("package_username", &self.package_username)
            .field("package_uid", &self.package_uid)
            .field("package_gid", &self.package_gid)
            .field("python_version", &self.python_version)
            .field("python_executable_sha256", &self.python_executable_sha256)
            .field("pip_version", &self.pip_version)
            .field("pip_cli_sha256", &self.pip_cli_sha256)
            .field(
                "clone_implementation_sha256",
                &self.clone_implementation_sha256,
            )
            .field("guest_protocol_sha256", &self.guest_protocol_sha256)
            .finish()
    }
}

impl MacosSdistBackendIdentityV1 {
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
        python_version: impl Into<String>,
        python_executable_sha256: Sha256Digest,
        pip_version: impl Into<String>,
        pip_cli_sha256: Sha256Digest,
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
            package_username: MACOS_SDIST_PACKAGE_USERNAME_V1.to_string(),
            package_uid,
            package_gid,
            python_version: python_version.into(),
            python_executable_sha256,
            pip_version: pip_version.into(),
            pip_cli_sha256,
            clone_implementation_sha256,
            guest_protocol_sha256: Sha256Digest::from_bytes(
                MACOS_SDIST_GUEST_PROTOCOL_V1.as_bytes(),
            ),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn base_generation_id(&self) -> &str {
        &self.base_generation_id
    }

    pub fn hardware_model_sha256(&self) -> &Sha256Digest {
        &self.hardware_model_sha256
    }

    pub fn machine_identifier_sha256(&self) -> &Sha256Digest {
        &self.machine_identifier_sha256
    }

    pub fn guest_supervisor_sha256(&self) -> &Sha256Digest {
        &self.guest_supervisor_sha256
    }

    pub fn guest_auth_public_key_sha256(&self) -> &Sha256Digest {
        &self.guest_auth_public_key_sha256
    }

    pub fn runner_configuration_sha256(&self) -> &Sha256Digest {
        &self.runner_configuration_sha256
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

    pub fn package_username(&self) -> &str {
        &self.package_username
    }

    pub fn python_version(&self) -> &str {
        &self.python_version
    }

    pub fn python_executable_sha256(&self) -> &Sha256Digest {
        &self.python_executable_sha256
    }

    pub fn pip_version(&self) -> &str {
        &self.pip_version
    }

    pub fn pip_cli_sha256(&self) -> &Sha256Digest {
        &self.pip_cli_sha256
    }

    fn validate(&self) -> Result<(), MacosArtifactRunErrorV1> {
        if !valid_identity(&self.base_generation_id)
            || self.cpu_count == 0
            || self.memory_mib < 1_024
            || self.memory_mib > 1_048_576
            || self.package_username != MACOS_SDIST_PACKAGE_USERNAME_V1
            || self.package_uid == 0
            || self.package_gid == 0
            || !valid_version(&self.python_version)
            || !valid_version(&self.pip_version)
            || self.guest_protocol_sha256
                != Sha256Digest::from_bytes(MACOS_SDIST_GUEST_PROTOCOL_V1.as_bytes())
        {
            return Err(MacosArtifactRunErrorV1::InvalidBackendIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosSdistBackendCapabilitiesV1 {
    identity: MacosSdistBackendIdentityV1,
    clone_policy: MacosArtifactClonePolicyV1,
    network_configuration: MacosArtifactNetworkConfigurationV1,
    reuse_policy: MacosArtifactVmReusePolicyV1,
}

impl MacosSdistBackendCapabilitiesV1 {
    pub fn inert_first_slice(identity: MacosSdistBackendIdentityV1) -> Self {
        Self {
            identity,
            clone_policy: MacosArtifactClonePolicyV1::ApfsCloneRequiredNoCopyFallback,
            network_configuration: MacosArtifactNetworkConfigurationV1::ZeroNetworkDevices,
            reuse_policy: MacosArtifactVmReusePolicyV1::OneBootOneScenarioDestroyClone,
        }
    }

    pub fn identity(&self) -> &MacosSdistBackendIdentityV1 {
        &self.identity
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacosSdistRunSpecWireV1 {
    schema_version: String,
    canonicalization: String,
    template: serde_json::Value,
    template_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    backend_identity: MacosSdistBackendIdentityV1,
    clone_policy: MacosArtifactClonePolicyV1,
    network_configuration: MacosArtifactNetworkConfigurationV1,
    reuse_policy: MacosArtifactVmReusePolicyV1,
    guest_protocol: String,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosSdistRunSpecV1 {
    canonical_json: Vec<u8>,
    run_spec_sha256: Sha256Digest,
    template_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    build_closure_sha256: Sha256Digest,
    scenario_id: String,
    scenario_kind: SdistScenarioKindV1,
    backend_identity: MacosSdistBackendIdentityV1,
}

impl fmt::Debug for MacosSdistRunSpecV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSdistRunSpecV1")
            .field("run_spec_sha256", &self.run_spec_sha256)
            .field("template_sha256", &self.template_sha256)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("artifact_byte_length", &self.artifact_byte_length)
            .field("build_closure_sha256", &self.build_closure_sha256)
            .field("scenario_id", &self.scenario_id)
            .field("scenario_kind", &self.scenario_kind)
            .field("backend_identity", &self.backend_identity)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosSdistRunSpecV1 {
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

    pub fn build_closure_sha256(&self) -> &Sha256Digest {
        &self.build_closure_sha256
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn scenario_kind(&self) -> &SdistScenarioKindV1 {
        &self.scenario_kind
    }

    pub fn backend_identity(&self) -> &MacosSdistBackendIdentityV1 {
        &self.backend_identity
    }
}

pub fn compile_macos_sdist_run_spec_v1(
    template: &SdistScenarioTemplateV1,
    backend: &MacosSdistBackendCapabilitiesV1,
) -> Result<MacosSdistRunSpecV1, MacosArtifactRunErrorV1> {
    backend.identity.validate()?;
    let template_bytes = template
        .canonical_json_v1()
        .map_err(|_| MacosArtifactRunErrorV1::InvalidTemplate)?;
    if Sha256Digest::from_bytes(&template_bytes) != *template.template_sha256() {
        return Err(MacosArtifactRunErrorV1::InvalidTemplate);
    }
    let validated = decode_and_validate_sdist_scenario_template_v1(&template_bytes)
        .map_err(|_| MacosArtifactRunErrorV1::InvalidTemplate)?;
    require_backend_match(&validated, &backend.identity)?;
    let template_value = serde_json::from_slice(&template_bytes)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    let wire = MacosSdistRunSpecWireV1 {
        schema_version: MACOS_SDIST_RUN_SPEC_SCHEMA_V1.to_string(),
        canonicalization: MACOS_SDIST_RUN_SPEC_CANONICALIZATION_V1.to_string(),
        template: template_value,
        template_sha256: template.template_sha256().clone(),
        build_closure_sha256: validated.build_closure_sha256().clone(),
        backend_identity: backend.identity.clone(),
        clone_policy: backend.clone_policy,
        network_configuration: backend.network_configuration,
        reuse_policy: backend.reuse_policy,
        guest_protocol: MACOS_SDIST_GUEST_PROTOCOL_V1.to_string(),
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    if canonical_json.len() > MAX_MACOS_SDIST_RUN_SPEC_BYTES_V1 {
        return Err(MacosArtifactRunErrorV1::LimitExceeded);
    }
    Ok(MacosSdistRunSpecV1 {
        run_spec_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        template_sha256: template.template_sha256().clone(),
        artifact_sha256: validated.artifact_sha256().clone(),
        artifact_byte_length: validated.artifact_byte_length(),
        build_closure_sha256: validated.build_closure_sha256().clone(),
        scenario_id: validated.scenario_id().to_string(),
        scenario_kind: validated.scenario_kind().clone(),
        backend_identity: backend.identity.clone(),
    })
}

pub fn decode_and_validate_macos_sdist_run_spec_v1(
    bytes: &[u8],
) -> Result<MacosSdistRunSpecV1, MacosArtifactRunErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_MACOS_SDIST_RUN_SPEC_BYTES_V1 {
        return Err(MacosArtifactRunErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = MacosSdistRunSpecWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosArtifactRunErrorV1::InvalidRunSpec)?;
    deserializer
        .end()
        .map_err(|_| MacosArtifactRunErrorV1::InvalidRunSpec)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    if canonical != bytes
        || wire.schema_version != MACOS_SDIST_RUN_SPEC_SCHEMA_V1
        || wire.canonicalization != MACOS_SDIST_RUN_SPEC_CANONICALIZATION_V1
        || wire.clone_policy != MacosArtifactClonePolicyV1::ApfsCloneRequiredNoCopyFallback
        || wire.network_configuration != MacosArtifactNetworkConfigurationV1::ZeroNetworkDevices
        || wire.reuse_policy != MacosArtifactVmReusePolicyV1::OneBootOneScenarioDestroyClone
        || wire.guest_protocol != MACOS_SDIST_GUEST_PROTOCOL_V1
    {
        return Err(MacosArtifactRunErrorV1::InvalidRunSpec);
    }
    wire.backend_identity.validate()?;
    let template_bytes = serde_json_canonicalizer::to_vec(&wire.template)
        .map_err(|_| MacosArtifactRunErrorV1::Serialization)?;
    if Sha256Digest::from_bytes(&template_bytes) != wire.template_sha256 {
        return Err(MacosArtifactRunErrorV1::InvalidRunSpec);
    }
    let validated = decode_and_validate_sdist_scenario_template_v1(&template_bytes)
        .map_err(|_| MacosArtifactRunErrorV1::InvalidTemplate)?;
    if validated.build_closure_sha256() != &wire.build_closure_sha256 {
        return Err(MacosArtifactRunErrorV1::InvalidRunSpec);
    }
    require_backend_match(&validated, &wire.backend_identity)?;
    Ok(MacosSdistRunSpecV1 {
        canonical_json: canonical,
        run_spec_sha256: Sha256Digest::from_bytes(bytes),
        template_sha256: wire.template_sha256,
        artifact_sha256: validated.artifact_sha256().clone(),
        artifact_byte_length: validated.artifact_byte_length(),
        build_closure_sha256: wire.build_closure_sha256,
        scenario_id: validated.scenario_id().to_string(),
        scenario_kind: validated.scenario_kind().clone(),
        backend_identity: wire.backend_identity,
    })
}

fn require_backend_match(
    template: &ValidatedSdistScenarioTemplateWireV1,
    backend: &MacosSdistBackendIdentityV1,
) -> Result<(), MacosArtifactRunErrorV1> {
    if template.python_version() != backend.python_version
        || template.python_executable_sha256() != &backend.python_executable_sha256
        || template.pip_version() != backend.pip_version
        || template.pip_cli_sha256() != &backend.pip_cli_sha256
    {
        return Err(MacosArtifactRunErrorV1::BackendCapabilityMismatch);
    }
    Ok(())
}

fn valid_identity(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.is_ascii()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'@')
        })
}

fn valid_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'+'))
}
