use crate::{
    LinuxVzTelemetryConformancePackageExecutionV1, MacosLinuxVzTelemetryConformanceRunSpecV1,
    UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactTelemetrySyncBackPolicyV1;

pub const MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_CHALLENGE_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_telemetry_conformance_challenge.v1";
pub const MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzTelemetryConformanceChallengePurposeV1 {
    TrustedInertTelemetryConformanceOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinuxVzTelemetryConformanceChallengeWireV1 {
    schema_version: String,
    nonce_hex: String,
    challenge_purpose: LinuxVzTelemetryConformanceChallengePurposeV1,
    run_spec_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
    package_execution: LinuxVzTelemetryConformancePackageExecutionV1,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosLinuxVzTelemetryConformanceChallengeV1 {
    canonical_json: Vec<u8>,
    challenge_sha256: Sha256Digest,
    nonce_hex: String,
    run_spec_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    guest_evidence_public_key_sha256: Sha256Digest,
    host_evidence_public_key_sha256: Sha256Digest,
}

impl fmt::Debug for MacosLinuxVzTelemetryConformanceChallengeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosLinuxVzTelemetryConformanceChallengeV1")
            .field("challenge_sha256", &self.challenge_sha256)
            .field(
                "nonce_sha256",
                &Sha256Digest::from_bytes(self.nonce_hex.as_bytes()),
            )
            .field("run_spec_sha256", &self.run_spec_sha256)
            .field("backend_identity_sha256", &self.backend_identity_sha256)
            .field(
                "telemetry_requirements_sha256",
                &self.telemetry_requirements_sha256,
            )
            .field("clone_binding_sha256", &self.clone_binding_sha256)
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosLinuxVzTelemetryConformanceChallengeV1 {
    pub fn new(
        nonce: [u8; 32],
        run_spec: &MacosLinuxVzTelemetryConformanceRunSpecV1,
        backend_identity: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
        clone_binding_sha256: Sha256Digest,
    ) -> Result<Self, MacosLinuxVzTelemetryEvidenceErrorV1> {
        let backend_identity_sha256 = backend_identity
            .identity_sha256_v1()
            .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::BackendMismatch)?;
        if run_spec.backend_identity_sha256() != &backend_identity_sha256
            || run_spec.telemetry_requirements_sha256()
                != backend_identity.telemetry_requirements_sha256()
            || run_spec.package_execution_authority_permitted()
            || backend_identity.execution_authority_permitted()
        {
            return Err(MacosLinuxVzTelemetryEvidenceErrorV1::BackendMismatch);
        }
        let wire = LinuxVzTelemetryConformanceChallengeWireV1 {
            schema_version: MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_CHALLENGE_SCHEMA_V1.to_string(),
            nonce_hex: lower_hex_v1(&nonce),
            challenge_purpose:
                LinuxVzTelemetryConformanceChallengePurposeV1::TrustedInertTelemetryConformanceOnly,
            run_spec_sha256: run_spec.run_spec_sha256().clone(),
            backend_identity_sha256,
            telemetry_requirements_sha256: run_spec.telemetry_requirements_sha256().clone(),
            clone_binding_sha256,
            guest_evidence_public_key_sha256: backend_identity
                .guest_evidence_public_key_sha256()
                .clone(),
            host_evidence_public_key_sha256: backend_identity
                .host_evidence_public_key_sha256()
                .clone(),
            package_execution: LinuxVzTelemetryConformancePackageExecutionV1::Disabled,
            sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
        };
        validate_and_build_challenge_v1(wire, run_spec, backend_identity)
    }

    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn challenge_sha256(&self) -> &Sha256Digest {
        &self.challenge_sha256
    }

    pub fn run_spec_sha256(&self) -> &Sha256Digest {
        &self.run_spec_sha256
    }

    pub fn backend_identity_sha256(&self) -> &Sha256Digest {
        &self.backend_identity_sha256
    }

    pub fn telemetry_requirements_sha256(&self) -> &Sha256Digest {
        &self.telemetry_requirements_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub fn guest_evidence_public_key_sha256(&self) -> &Sha256Digest {
        &self.guest_evidence_public_key_sha256
    }

    pub fn host_evidence_public_key_sha256(&self) -> &Sha256Digest {
        &self.host_evidence_public_key_sha256
    }

    pub const fn package_execution_authority_permitted(&self) -> bool {
        false
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosLinuxVzTelemetryEvidenceErrorV1 {
    Empty,
    LimitExceeded,
    InvalidSchema,
    InvalidNonce,
    RunSpecMismatch,
    BackendMismatch,
    CloneMismatch,
    NonCanonical,
    Serialization,
}

impl MacosLinuxVzTelemetryEvidenceErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "macos_linux_vz_telemetry_evidence_empty",
            Self::LimitExceeded => "macos_linux_vz_telemetry_evidence_limit_exceeded",
            Self::InvalidSchema => "macos_linux_vz_telemetry_evidence_schema_invalid",
            Self::InvalidNonce => "macos_linux_vz_telemetry_evidence_nonce_invalid",
            Self::RunSpecMismatch => "macos_linux_vz_telemetry_evidence_run_spec_mismatch",
            Self::BackendMismatch => "macos_linux_vz_telemetry_evidence_backend_mismatch",
            Self::CloneMismatch => "macos_linux_vz_telemetry_evidence_clone_mismatch",
            Self::NonCanonical => "macos_linux_vz_telemetry_evidence_noncanonical",
            Self::Serialization => "macos_linux_vz_telemetry_evidence_serialization_failed",
        }
    }
}

impl fmt::Display for MacosLinuxVzTelemetryEvidenceErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzTelemetryEvidenceErrorV1 {}

pub fn decode_and_validate_macos_linux_vz_telemetry_conformance_challenge_v1(
    bytes: &[u8],
    expected_run_spec: &MacosLinuxVzTelemetryConformanceRunSpecV1,
    expected_backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<MacosLinuxVzTelemetryConformanceChallengeV1, MacosLinuxVzTelemetryEvidenceErrorV1> {
    if bytes.is_empty() {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::Empty);
    }
    if bytes.len() > MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = LinuxVzTelemetryConformanceChallengeWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidSchema)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::InvalidSchema)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::NonCanonical);
    }
    validate_and_build_challenge_v1(wire, expected_run_spec, expected_backend)
}

fn validate_and_build_challenge_v1(
    wire: LinuxVzTelemetryConformanceChallengeWireV1,
    expected_run_spec: &MacosLinuxVzTelemetryConformanceRunSpecV1,
    expected_backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<MacosLinuxVzTelemetryConformanceChallengeV1, MacosLinuxVzTelemetryEvidenceErrorV1> {
    if wire.schema_version != MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_CHALLENGE_SCHEMA_V1
        || wire.challenge_purpose
            != LinuxVzTelemetryConformanceChallengePurposeV1::TrustedInertTelemetryConformanceOnly
        || wire.package_execution != LinuxVzTelemetryConformancePackageExecutionV1::Disabled
        || wire.sync_back_policy != ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidSchema);
    }
    if !valid_lower_hex_v1(&wire.nonce_hex, 64) {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::InvalidNonce);
    }
    if wire.run_spec_sha256 != *expected_run_spec.run_spec_sha256()
        || expected_run_spec.package_execution_authority_permitted()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::RunSpecMismatch);
    }
    let backend_sha256 = expected_backend
        .identity_sha256_v1()
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::BackendMismatch)?;
    if wire.backend_identity_sha256 != backend_sha256
        || wire.backend_identity_sha256 != *expected_run_spec.backend_identity_sha256()
        || wire.telemetry_requirements_sha256 != *expected_backend.telemetry_requirements_sha256()
        || wire.telemetry_requirements_sha256 != *expected_run_spec.telemetry_requirements_sha256()
        || wire.guest_evidence_public_key_sha256
            != *expected_backend.guest_evidence_public_key_sha256()
        || wire.host_evidence_public_key_sha256
            != *expected_backend.host_evidence_public_key_sha256()
        || expected_backend.execution_authority_permitted()
    {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::BackendMismatch);
    }
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzTelemetryEvidenceErrorV1::Serialization)?;
    if canonical_json.len() > MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryEvidenceErrorV1::LimitExceeded);
    }
    Ok(MacosLinuxVzTelemetryConformanceChallengeV1 {
        challenge_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        nonce_hex: wire.nonce_hex,
        run_spec_sha256: wire.run_spec_sha256,
        backend_identity_sha256: wire.backend_identity_sha256,
        telemetry_requirements_sha256: wire.telemetry_requirements_sha256,
        clone_binding_sha256: wire.clone_binding_sha256,
        guest_evidence_public_key_sha256: wire.guest_evidence_public_key_sha256,
        host_evidence_public_key_sha256: wire.host_evidence_public_key_sha256,
    })
}

fn lower_hex_v1(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn valid_lower_hex_v1(value: &str, expected_length: usize) -> bool {
    value.len() == expected_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
