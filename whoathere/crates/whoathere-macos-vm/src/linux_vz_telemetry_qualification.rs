use crate::{
    LinuxVzTelemetryConformanceCaseV1, UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    VerifiedLinuxVzTelemetryConformanceCaseV1, ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactTelemetrySyncBackPolicyV1;

pub const MACOS_LINUX_VZ_QUALIFIED_TELEMETRY_BACKEND_SCHEMA_V1: &str =
    "whoathere.macos_linux_vz_qualified_telemetry_backend.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacosLinuxVzTelemetryQualifiedStateV1 {
    CompleteInertConformanceMatrixVerified,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualifiedCaseBindingWireV1 {
    fixture_case: LinuxVzTelemetryConformanceCaseV1,
    challenge_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    guest_receipt_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct QualifiedBackendWireV1 {
    schema_version: String,
    qualification_state: MacosLinuxVzTelemetryQualifiedStateV1,
    backend_identity: serde_json::Value,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    conformance_cases: Vec<QualifiedCaseBindingWireV1>,
    conformance_case_count: String,
    conformance_evidence_set_sha256: Sha256Digest,
    clone_policy: String,
    execution_eligibility: String,
    execution_authority_issued: bool,
    sync_back_policy: ArtifactTelemetrySyncBackPolicyV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct QualifiedMacosLinuxVzTelemetryBackendV1 {
    canonical_json: Vec<u8>,
    qualified_backend_sha256: Sha256Digest,
    backend_identity_sha256: Sha256Digest,
    telemetry_requirements_sha256: Sha256Digest,
    conformance_evidence_set_sha256: Sha256Digest,
    guest_sensor_sha256: Sha256Digest,
    guest_bpf_bundle_sha256: Sha256Digest,
    guest_sensor_configuration_sha256: Sha256Digest,
}

impl fmt::Debug for QualifiedMacosLinuxVzTelemetryBackendV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QualifiedMacosLinuxVzTelemetryBackendV1")
            .field("qualified_backend_sha256", &self.qualified_backend_sha256)
            .field("backend_identity_sha256", &self.backend_identity_sha256)
            .field(
                "telemetry_requirements_sha256",
                &self.telemetry_requirements_sha256,
            )
            .field(
                "conformance_evidence_set_sha256",
                &self.conformance_evidence_set_sha256,
            )
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl QualifiedMacosLinuxVzTelemetryBackendV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn qualified_backend_sha256(&self) -> &Sha256Digest {
        &self.qualified_backend_sha256
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

    pub fn guest_sensor_sha256(&self) -> &Sha256Digest {
        &self.guest_sensor_sha256
    }

    pub fn guest_bpf_bundle_sha256(&self) -> &Sha256Digest {
        &self.guest_bpf_bundle_sha256
    }

    pub fn guest_sensor_configuration_sha256(&self) -> &Sha256Digest {
        &self.guest_sensor_configuration_sha256
    }

    pub const fn eligible_for_typed_package_execution_authority_request(&self) -> bool {
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
pub enum MacosLinuxVzTelemetryQualificationErrorV1 {
    IncompleteMatrix,
    DuplicateCase,
    MixedBackend,
    MixedRequirements,
    ChallengeReuse,
    RunSpecReuse,
    CloneReuse,
    ExecutionAuthorityPresent,
    BackendInvalid,
    Serialization,
    LimitExceeded,
}

impl MacosLinuxVzTelemetryQualificationErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::IncompleteMatrix => "macos_linux_vz_telemetry_qualification_matrix_incomplete",
            Self::DuplicateCase => "macos_linux_vz_telemetry_qualification_case_duplicate",
            Self::MixedBackend => "macos_linux_vz_telemetry_qualification_backend_mixed",
            Self::MixedRequirements => "macos_linux_vz_telemetry_qualification_requirements_mixed",
            Self::ChallengeReuse => "macos_linux_vz_telemetry_qualification_challenge_reused",
            Self::RunSpecReuse => "macos_linux_vz_telemetry_qualification_run_spec_reused",
            Self::CloneReuse => "macos_linux_vz_telemetry_qualification_clone_reused",
            Self::ExecutionAuthorityPresent => {
                "macos_linux_vz_telemetry_qualification_execution_authority_present"
            }
            Self::BackendInvalid => "macos_linux_vz_telemetry_qualification_backend_invalid",
            Self::Serialization => "macos_linux_vz_telemetry_qualification_serialization_failed",
            Self::LimitExceeded => "macos_linux_vz_telemetry_qualification_limit_exceeded",
        }
    }
}

impl fmt::Display for MacosLinuxVzTelemetryQualificationErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosLinuxVzTelemetryQualificationErrorV1 {}

pub fn qualify_macos_linux_vz_telemetry_backend_v1(
    backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
    verified_cases: Vec<VerifiedLinuxVzTelemetryConformanceCaseV1>,
) -> Result<QualifiedMacosLinuxVzTelemetryBackendV1, MacosLinuxVzTelemetryQualificationErrorV1> {
    if backend.execution_authority_permitted() {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::ExecutionAuthorityPresent);
    }
    if verified_cases.len() != ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1.len() {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::IncompleteMatrix);
    }
    let backend_bytes = backend
        .canonical_json_v1()
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid)?;
    let backend_sha256 = Sha256Digest::from_bytes(&backend_bytes);
    let requirements_sha256 = backend.telemetry_requirements_sha256().clone();
    let mut seen_cases = BTreeSet::new();
    let mut seen_challenges = BTreeSet::new();
    let mut seen_run_specs = BTreeSet::new();
    let mut seen_clones = BTreeSet::new();
    let mut bindings = Vec::with_capacity(verified_cases.len());
    for case in verified_cases {
        if case.package_execution_authority_permitted() {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::ExecutionAuthorityPresent);
        }
        if case.backend_identity_sha256() != &backend_sha256 {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::MixedBackend);
        }
        if case.telemetry_requirements_sha256() != &requirements_sha256 {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::MixedRequirements);
        }
        if !seen_cases.insert(case.fixture_case()) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::DuplicateCase);
        }
        if !seen_challenges.insert(case.challenge_sha256().clone()) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::ChallengeReuse);
        }
        if !seen_run_specs.insert(case.run_spec_sha256().clone()) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::RunSpecReuse);
        }
        if !seen_clones.insert(case.clone_binding_sha256().clone()) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::CloneReuse);
        }
        bindings.push(QualifiedCaseBindingWireV1 {
            fixture_case: case.fixture_case(),
            challenge_sha256: case.challenge_sha256().clone(),
            run_spec_sha256: case.run_spec_sha256().clone(),
            clone_binding_sha256: case.clone_binding_sha256().clone(),
            guest_receipt_present: case.guest_receipt_present(),
        });
    }
    let expected: BTreeSet<_> = ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1
        .into_iter()
        .collect();
    if seen_cases != expected {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::IncompleteMatrix);
    }
    bindings.sort_by_key(|binding| binding.fixture_case);
    let evidence_bytes = serde_json_canonicalizer::to_vec(&bindings)
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::Serialization)?;
    let evidence_sha256 = Sha256Digest::from_bytes(&evidence_bytes);
    let wire = QualifiedBackendWireV1 {
        schema_version: MACOS_LINUX_VZ_QUALIFIED_TELEMETRY_BACKEND_SCHEMA_V1.to_string(),
        qualification_state:
            MacosLinuxVzTelemetryQualifiedStateV1::CompleteInertConformanceMatrixVerified,
        backend_identity: serde_json::from_slice(&backend_bytes)
            .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::Serialization)?,
        backend_identity_sha256: backend_sha256.clone(),
        telemetry_requirements_sha256: requirements_sha256.clone(),
        conformance_cases: bindings,
        conformance_case_count: ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1
            .len()
            .to_string(),
        conformance_evidence_set_sha256: evidence_sha256.clone(),
        clone_policy: "one_unique_clone_per_case_destroyed".to_string(),
        execution_eligibility: "typed_package_scenario_authority_request_only".to_string(),
        execution_authority_issued: false,
        sync_back_policy: ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent,
    };
    let canonical_json = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::Serialization)?;
    if canonical_json.len() > crate::MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1 {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::LimitExceeded);
    }
    Ok(QualifiedMacosLinuxVzTelemetryBackendV1 {
        qualified_backend_sha256: Sha256Digest::from_bytes(&canonical_json),
        canonical_json,
        backend_identity_sha256: backend_sha256,
        telemetry_requirements_sha256: requirements_sha256,
        conformance_evidence_set_sha256: evidence_sha256,
        guest_sensor_sha256: backend.guest_sensor_sha256().clone(),
        guest_bpf_bundle_sha256: backend.guest_bpf_bundle_sha256().clone(),
        guest_sensor_configuration_sha256: backend.guest_sensor_configuration_sha256().clone(),
    })
}

pub fn decode_qualified_macos_linux_vz_telemetry_backend_v1(
    bytes: &[u8],
    expected_backend: &UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1,
) -> Result<QualifiedMacosLinuxVzTelemetryBackendV1, MacosLinuxVzTelemetryQualificationErrorV1> {
    if bytes.is_empty()
        || bytes.len() > crate::MAX_MACOS_LINUX_VZ_TELEMETRY_CONFORMANCE_EVIDENCE_BYTES_V1
    {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = QualifiedBackendWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid)?;
    deserializer
        .end()
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::Serialization)?;
    if canonical != bytes {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid);
    }
    let expected_backend_bytes = expected_backend
        .canonical_json_v1()
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid)?;
    let expected_backend_value: serde_json::Value = serde_json::from_slice(&expected_backend_bytes)
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid)?;
    let expected_backend_sha256 = Sha256Digest::from_bytes(&expected_backend_bytes);
    let expected_requirements_sha256 = expected_backend.telemetry_requirements_sha256().clone();
    if wire.schema_version != MACOS_LINUX_VZ_QUALIFIED_TELEMETRY_BACKEND_SCHEMA_V1
        || wire.qualification_state
            != MacosLinuxVzTelemetryQualifiedStateV1::CompleteInertConformanceMatrixVerified
        || wire.backend_identity != expected_backend_value
        || wire.backend_identity_sha256 != expected_backend_sha256
        || wire.telemetry_requirements_sha256 != expected_requirements_sha256
        || wire.clone_policy != "one_unique_clone_per_case_destroyed"
        || wire.execution_eligibility != "typed_package_scenario_authority_request_only"
        || wire.execution_authority_issued
        || wire.sync_back_policy != ArtifactTelemetrySyncBackPolicyV1::StructurallyAbsent
        || wire.conformance_case_count
            != ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1
                .len()
                .to_string()
        || wire.conformance_cases.len() != ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1.len()
    {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid);
    }

    let expected_cases: BTreeSet<_> = ALL_LINUX_VZ_TELEMETRY_CONFORMANCE_CASES_V1
        .into_iter()
        .collect();
    let mut seen_cases = BTreeSet::new();
    let mut seen_challenges = BTreeSet::new();
    let mut seen_run_specs = BTreeSet::new();
    let mut seen_clones = BTreeSet::new();
    let empty = Sha256Digest::from_bytes(&[]);
    for binding in &wire.conformance_cases {
        if binding.challenge_sha256 == empty
            || binding.run_spec_sha256 == empty
            || binding.clone_binding_sha256 == empty
            || binding.challenge_sha256 == binding.run_spec_sha256
            || binding.challenge_sha256 == binding.clone_binding_sha256
            || binding.run_spec_sha256 == binding.clone_binding_sha256
        {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid);
        }
        if !seen_cases.insert(binding.fixture_case) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::DuplicateCase);
        }
        if !seen_challenges.insert(binding.challenge_sha256.clone()) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::ChallengeReuse);
        }
        if !seen_run_specs.insert(binding.run_spec_sha256.clone()) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::RunSpecReuse);
        }
        if !seen_clones.insert(binding.clone_binding_sha256.clone()) {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::CloneReuse);
        }
        if binding.fixture_case == LinuxVzTelemetryConformanceCaseV1::GuestSensorDeath
            && binding.guest_receipt_present
        {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid);
        }
        if !matches!(
            binding.fixture_case,
            LinuxVzTelemetryConformanceCaseV1::GuestSensorDeath
                | LinuxVzTelemetryConformanceCaseV1::ChannelInterruption
                | LinuxVzTelemetryConformanceCaseV1::VmStop
        ) && !binding.guest_receipt_present
        {
            return Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid);
        }
    }
    if seen_cases != expected_cases {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::IncompleteMatrix);
    }
    let mut sorted_bindings = wire.conformance_cases.clone();
    sorted_bindings.sort_by_key(|binding| binding.fixture_case);
    if sorted_bindings != wire.conformance_cases {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid);
    }
    let evidence_bytes = serde_json_canonicalizer::to_vec(&wire.conformance_cases)
        .map_err(|_| MacosLinuxVzTelemetryQualificationErrorV1::Serialization)?;
    let evidence_sha256 = Sha256Digest::from_bytes(&evidence_bytes);
    if wire.conformance_evidence_set_sha256 != evidence_sha256 {
        return Err(MacosLinuxVzTelemetryQualificationErrorV1::BackendInvalid);
    }
    Ok(QualifiedMacosLinuxVzTelemetryBackendV1 {
        canonical_json: canonical,
        qualified_backend_sha256: Sha256Digest::from_bytes(bytes),
        backend_identity_sha256: expected_backend_sha256,
        telemetry_requirements_sha256: expected_requirements_sha256,
        conformance_evidence_set_sha256: evidence_sha256,
        guest_sensor_sha256: expected_backend.guest_sensor_sha256().clone(),
        guest_bpf_bundle_sha256: expected_backend.guest_bpf_bundle_sha256().clone(),
        guest_sensor_configuration_sha256: expected_backend
            .guest_sensor_configuration_sha256()
            .clone(),
    })
}
