//! Backend-neutral execution-bundle v2 contract.
//!
//! This module binds the exact bytes staged as `artifact.bin` to one already
//! compiled typed scenario. It describes VM execution eligibility; it does not
//! execute packages, interpret evidence, or authorize admission.

use crate::{
    artifact::valid_identity_component_v1, ArtifactScenarioKindV1, SdistScenarioClassV1,
    WheelScenarioClassV1, MAX_ARTIFACT_SCENARIO_BYTES_V1,
};
use serde::{Deserialize, Deserializer, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const EXECUTION_BUNDLE_SCHEMA_V2: &str = "whoathere.execution_bundle.v2";
pub const EXECUTION_BUNDLE_CANONICALIZATION_V2: &str = "rfc8785.jcs.v1";
pub const EXECUTION_BUNDLE_ARTIFACT_FILE_V2: &str = "artifact.bin";
pub const EXECUTION_BUNDLE_CLOSURE_FILE_V2: &str = "closure.bin";
pub const MAX_EXECUTION_BUNDLE_WIRE_BYTES_V2: usize = 64 * 1024;
pub const MAX_EXECUTION_BUNDLE_CLOSURE_BYTES_V2: u64 = 128 * 1024 * 1024;
pub const MAX_EXECUTION_BUNDLE_ACTIONS_V2: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionBundleErrorV2 {
    InvalidSchemaIdentity,
    InvalidPolicyIdentity,
    InvalidArtifactBinding,
    InvalidScenarioIdentity,
    ArtifactScenarioMismatch,
    InvalidActionCount,
    InvalidClosureBinding,
    MissingRequiredClosure,
    UnexpectedClosure,
    InvalidPreflight,
    BundleDigestMismatch,
    InvalidWire,
    WireLimitExceeded,
    Serialization,
}

impl ExecutionBundleErrorV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidSchemaIdentity => "execution_bundle_v2_schema_identity_invalid",
            Self::InvalidPolicyIdentity => "execution_bundle_v2_policy_identity_invalid",
            Self::InvalidArtifactBinding => "execution_bundle_v2_artifact_binding_invalid",
            Self::InvalidScenarioIdentity => "execution_bundle_v2_scenario_identity_invalid",
            Self::ArtifactScenarioMismatch => "execution_bundle_v2_artifact_scenario_mismatch",
            Self::InvalidActionCount => "execution_bundle_v2_action_count_invalid",
            Self::InvalidClosureBinding => "execution_bundle_v2_closure_binding_invalid",
            Self::MissingRequiredClosure => "execution_bundle_v2_required_closure_missing",
            Self::UnexpectedClosure => "execution_bundle_v2_closure_unexpected",
            Self::InvalidPreflight => "execution_bundle_v2_preflight_invalid",
            Self::BundleDigestMismatch => "execution_bundle_v2_digest_mismatch",
            Self::InvalidWire => "execution_bundle_v2_wire_invalid",
            Self::WireLimitExceeded => "execution_bundle_v2_wire_limit_exceeded",
            Self::Serialization => "execution_bundle_v2_serialization_failed",
        }
    }
}

impl fmt::Display for ExecutionBundleErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ExecutionBundleErrorV2 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBundleArtifactKindV2 {
    NpmTgz,
    Wheel,
    Sdist,
}

/// The typed class of the selected, separately compiled scenario contract.
///
/// `scenario_sha256` in [`ExecutionBundleSelectedScenarioV2`] binds the full
/// scenario template, including any import root, entry point, or build details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "artifact_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutionBundleScenarioKindV2 {
    NpmTgz {
        scenario: ArtifactScenarioKindV1,
    },
    Wheel {
        scenario_class: WheelScenarioClassV1,
    },
    Sdist {
        scenario_class: SdistScenarioClassV1,
    },
}

impl ExecutionBundleScenarioKindV2 {
    pub const fn artifact_kind(&self) -> ExecutionBundleArtifactKindV2 {
        match self {
            Self::NpmTgz { .. } => ExecutionBundleArtifactKindV2::NpmTgz,
            Self::Wheel { .. } => ExecutionBundleArtifactKindV2::Wheel,
            Self::Sdist { .. } => ExecutionBundleArtifactKindV2::Sdist,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBundleSelectedScenarioV2 {
    scenario_id: String,
    kind: ExecutionBundleScenarioKindV2,
    scenario_sha256: Sha256Digest,
}

impl ExecutionBundleSelectedScenarioV2 {
    pub fn new(
        scenario_id: impl Into<String>,
        kind: ExecutionBundleScenarioKindV2,
        scenario_sha256: Sha256Digest,
    ) -> Result<Self, ExecutionBundleErrorV2> {
        let value = Self {
            scenario_id: scenario_id.into(),
            kind,
            scenario_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }

    pub fn kind(&self) -> &ExecutionBundleScenarioKindV2 {
        &self.kind
    }

    pub fn scenario_sha256(&self) -> &Sha256Digest {
        &self.scenario_sha256
    }

    fn validate(&self) -> Result<(), ExecutionBundleErrorV2> {
        if !valid_identity_component_v1(&self.scenario_id) {
            return Err(ExecutionBundleErrorV2::InvalidScenarioIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBundlePolicyIdentityV2 {
    policy_id: String,
    policy_sha256: Sha256Digest,
}

impl ExecutionBundlePolicyIdentityV2 {
    pub fn new(
        policy_id: impl Into<String>,
        policy_sha256: Sha256Digest,
    ) -> Result<Self, ExecutionBundleErrorV2> {
        let value = Self {
            policy_id: policy_id.into(),
            policy_sha256,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn policy_id(&self) -> &str {
        &self.policy_id
    }

    pub fn policy_sha256(&self) -> &Sha256Digest {
        &self.policy_sha256
    }

    fn validate(&self) -> Result<(), ExecutionBundleErrorV2> {
        if !valid_identity_component_v1(&self.policy_id) {
            return Err(ExecutionBundleErrorV2::InvalidPolicyIdentity);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBundleClosureKindV2 {
    Dependency,
    Build,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBundleClosureRequirementV2 {
    NotRequired,
    Dependency,
    Build,
}

impl ExecutionBundleClosureRequirementV2 {
    const fn required_kind(self) -> Option<ExecutionBundleClosureKindV2> {
        match self {
            Self::NotRequired => None,
            Self::Dependency => Some(ExecutionBundleClosureKindV2::Dependency),
            Self::Build => Some(ExecutionBundleClosureKindV2::Build),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBundleClosureV2 {
    file_name: String,
    kind: ExecutionBundleClosureKindV2,
    sha256: Sha256Digest,
    byte_length: u64,
}

impl ExecutionBundleClosureV2 {
    pub fn new(
        kind: ExecutionBundleClosureKindV2,
        sha256: Sha256Digest,
        byte_length: u64,
    ) -> Result<Self, ExecutionBundleErrorV2> {
        let value = Self {
            file_name: EXECUTION_BUNDLE_CLOSURE_FILE_V2.to_string(),
            kind,
            sha256,
            byte_length,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn file_name(&self) -> &str {
        &self.file_name
    }

    pub const fn kind(&self) -> ExecutionBundleClosureKindV2 {
        self.kind
    }

    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    pub const fn byte_length(&self) -> u64 {
        self.byte_length
    }

    pub fn matches_bytes(&self, bytes: &[u8]) -> bool {
        self.byte_length == bytes.len() as u64 && self.sha256 == Sha256Digest::from_bytes(bytes)
    }

    fn validate(&self) -> Result<(), ExecutionBundleErrorV2> {
        if self.file_name != EXECUTION_BUNDLE_CLOSURE_FILE_V2
            || self.byte_length == 0
            || self.byte_length > MAX_EXECUTION_BUNDLE_CLOSURE_BYTES_V2
        {
            return Err(ExecutionBundleErrorV2::InvalidClosureBinding);
        }
        Ok(())
    }
}

/// Pre-execution state. There is intentionally no `clean` or `safe` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBundlePreflightDispositionV2 {
    ReadyForDisposableVm,
    Inconclusive,
    ManualReview,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBundlePreflightReasonV2 {
    MissingDependencyClosure,
    MissingBuildClosure,
    UnresolvedDependencies,
    UnsupportedDependency,
    UnsupportedArtifactForm,
    UnsupportedNativeTag,
    IncompleteArtifactMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionBundlePreflightV2 {
    disposition: ExecutionBundlePreflightDispositionV2,
    reasons: Vec<ExecutionBundlePreflightReasonV2>,
}

impl ExecutionBundlePreflightV2 {
    pub fn ready_for_disposable_vm() -> Self {
        Self {
            disposition: ExecutionBundlePreflightDispositionV2::ReadyForDisposableVm,
            reasons: Vec::new(),
        }
    }

    pub fn inconclusive(
        reasons: Vec<ExecutionBundlePreflightReasonV2>,
    ) -> Result<Self, ExecutionBundleErrorV2> {
        Self::new(ExecutionBundlePreflightDispositionV2::Inconclusive, reasons)
    }

    pub fn manual_review(
        reasons: Vec<ExecutionBundlePreflightReasonV2>,
    ) -> Result<Self, ExecutionBundleErrorV2> {
        Self::new(ExecutionBundlePreflightDispositionV2::ManualReview, reasons)
    }

    fn new(
        disposition: ExecutionBundlePreflightDispositionV2,
        reasons: Vec<ExecutionBundlePreflightReasonV2>,
    ) -> Result<Self, ExecutionBundleErrorV2> {
        let value = Self {
            disposition,
            reasons,
        };
        value.validate()?;
        Ok(value)
    }

    pub const fn disposition(&self) -> ExecutionBundlePreflightDispositionV2 {
        self.disposition
    }

    pub fn reasons(&self) -> &[ExecutionBundlePreflightReasonV2] {
        &self.reasons
    }

    pub fn permits_vm_execution(&self) -> bool {
        self.disposition == ExecutionBundlePreflightDispositionV2::ReadyForDisposableVm
    }

    pub const fn authorizes_admission(&self) -> bool {
        false
    }

    pub const fn establishes_clean_behavior(&self) -> bool {
        false
    }

    fn validate(&self) -> Result<(), ExecutionBundleErrorV2> {
        if self.reasons.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ExecutionBundleErrorV2::InvalidPreflight);
        }
        match self.disposition {
            ExecutionBundlePreflightDispositionV2::ReadyForDisposableVm
                if self.reasons.is_empty() =>
            {
                Ok(())
            }
            ExecutionBundlePreflightDispositionV2::Inconclusive
            | ExecutionBundlePreflightDispositionV2::ManualReview
                if !self.reasons.is_empty() =>
            {
                Ok(())
            }
            _ => Err(ExecutionBundleErrorV2::InvalidPreflight),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionBundleInputV2 {
    pub artifact_kind: ExecutionBundleArtifactKindV2,
    pub artifact_sha256: Sha256Digest,
    pub artifact_byte_length: u64,
    pub selected_scenario: ExecutionBundleSelectedScenarioV2,
    pub expected_action_count: u32,
    pub closure_requirement: ExecutionBundleClosureRequirementV2,
    pub closure: Option<ExecutionBundleClosureV2>,
    pub policy: ExecutionBundlePolicyIdentityV2,
    pub preflight: ExecutionBundlePreflightV2,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExecutionBundleV2 {
    schema_version: String,
    canonicalization: String,
    artifact_file_name: String,
    artifact_kind: ExecutionBundleArtifactKindV2,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    selected_scenario: ExecutionBundleSelectedScenarioV2,
    expected_action_count: u32,
    closure_requirement: ExecutionBundleClosureRequirementV2,
    closure: Option<ExecutionBundleClosureV2>,
    policy: ExecutionBundlePolicyIdentityV2,
    preflight: ExecutionBundlePreflightV2,
    bundle_sha256: Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionBundleWireV2 {
    schema_version: String,
    canonicalization: String,
    artifact_file_name: String,
    artifact_kind: ExecutionBundleArtifactKindV2,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    selected_scenario: ExecutionBundleSelectedScenarioV2,
    expected_action_count: u32,
    closure_requirement: ExecutionBundleClosureRequirementV2,
    closure: Option<ExecutionBundleClosureV2>,
    policy: ExecutionBundlePolicyIdentityV2,
    preflight: ExecutionBundlePreflightV2,
    bundle_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ExecutionBundleDigestWireV2<'a> {
    schema_version: &'a str,
    canonicalization: &'a str,
    artifact_file_name: &'a str,
    artifact_kind: ExecutionBundleArtifactKindV2,
    artifact_sha256: &'a Sha256Digest,
    artifact_byte_length: u64,
    selected_scenario: &'a ExecutionBundleSelectedScenarioV2,
    expected_action_count: u32,
    closure_requirement: ExecutionBundleClosureRequirementV2,
    closure: Option<&'a ExecutionBundleClosureV2>,
    policy: &'a ExecutionBundlePolicyIdentityV2,
    preflight: &'a ExecutionBundlePreflightV2,
}

impl ExecutionBundleV2 {
    pub fn new(input: ExecutionBundleInputV2) -> Result<Self, ExecutionBundleErrorV2> {
        let mut value = Self {
            schema_version: EXECUTION_BUNDLE_SCHEMA_V2.to_string(),
            canonicalization: EXECUTION_BUNDLE_CANONICALIZATION_V2.to_string(),
            artifact_file_name: EXECUTION_BUNDLE_ARTIFACT_FILE_V2.to_string(),
            artifact_kind: input.artifact_kind,
            artifact_sha256: input.artifact_sha256,
            artifact_byte_length: input.artifact_byte_length,
            selected_scenario: input.selected_scenario,
            expected_action_count: input.expected_action_count,
            closure_requirement: input.closure_requirement,
            closure: input.closure,
            policy: input.policy,
            preflight: input.preflight,
            bundle_sha256: Sha256Digest::from_bytes(&[]),
        };
        value.validate_fields()?;
        value.bundle_sha256 = value.compute_bundle_sha256()?;
        Ok(value)
    }

    pub fn schema_version(&self) -> &str {
        &self.schema_version
    }

    pub fn artifact_file_name(&self) -> &str {
        &self.artifact_file_name
    }

    pub const fn artifact_kind(&self) -> ExecutionBundleArtifactKindV2 {
        self.artifact_kind
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub const fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }

    pub fn selected_scenario(&self) -> &ExecutionBundleSelectedScenarioV2 {
        &self.selected_scenario
    }

    pub const fn expected_action_count(&self) -> u32 {
        self.expected_action_count
    }

    pub const fn closure_requirement(&self) -> ExecutionBundleClosureRequirementV2 {
        self.closure_requirement
    }

    pub fn closure(&self) -> Option<&ExecutionBundleClosureV2> {
        self.closure.as_ref()
    }

    pub fn policy(&self) -> &ExecutionBundlePolicyIdentityV2 {
        &self.policy
    }

    pub fn preflight(&self) -> &ExecutionBundlePreflightV2 {
        &self.preflight
    }

    pub fn bundle_sha256(&self) -> &Sha256Digest {
        &self.bundle_sha256
    }

    pub fn matches_artifact_bytes(&self, bytes: &[u8]) -> bool {
        self.artifact_byte_length == bytes.len() as u64
            && self.artifact_sha256 == Sha256Digest::from_bytes(bytes)
    }

    pub fn canonical_json_v2(&self) -> Result<Vec<u8>, ExecutionBundleErrorV2> {
        self.validate()?;
        let bytes = serde_json_canonicalizer::to_vec(self)
            .map_err(|_| ExecutionBundleErrorV2::Serialization)?;
        if bytes.len() > MAX_EXECUTION_BUNDLE_WIRE_BYTES_V2 {
            return Err(ExecutionBundleErrorV2::WireLimitExceeded);
        }
        Ok(bytes)
    }

    pub fn validate(&self) -> Result<(), ExecutionBundleErrorV2> {
        self.validate_fields()?;
        if self.bundle_sha256 != self.compute_bundle_sha256()? {
            return Err(ExecutionBundleErrorV2::BundleDigestMismatch);
        }
        Ok(())
    }

    fn validate_fields(&self) -> Result<(), ExecutionBundleErrorV2> {
        if self.schema_version != EXECUTION_BUNDLE_SCHEMA_V2
            || self.canonicalization != EXECUTION_BUNDLE_CANONICALIZATION_V2
        {
            return Err(ExecutionBundleErrorV2::InvalidSchemaIdentity);
        }
        if self.artifact_file_name != EXECUTION_BUNDLE_ARTIFACT_FILE_V2
            || self.artifact_byte_length == 0
            || self.artifact_byte_length > MAX_ARTIFACT_SCENARIO_BYTES_V1
        {
            return Err(ExecutionBundleErrorV2::InvalidArtifactBinding);
        }
        self.selected_scenario.validate()?;
        if self.selected_scenario.kind.artifact_kind() != self.artifact_kind {
            return Err(ExecutionBundleErrorV2::ArtifactScenarioMismatch);
        }
        if self.expected_action_count == 0
            || self.expected_action_count > MAX_EXECUTION_BUNDLE_ACTIONS_V2
        {
            return Err(ExecutionBundleErrorV2::InvalidActionCount);
        }
        self.policy.validate()?;
        self.preflight.validate()?;
        if matches!(
            self.closure_requirement,
            ExecutionBundleClosureRequirementV2::Build
        ) && self.artifact_kind != ExecutionBundleArtifactKindV2::Sdist
        {
            return Err(ExecutionBundleErrorV2::InvalidClosureBinding);
        }
        match (
            self.closure_requirement.required_kind(),
            self.closure.as_ref(),
        ) {
            (None, None) => {}
            (None, Some(_)) => return Err(ExecutionBundleErrorV2::UnexpectedClosure),
            (Some(required), Some(closure)) => {
                closure.validate()?;
                if closure.kind != required {
                    return Err(ExecutionBundleErrorV2::InvalidClosureBinding);
                }
            }
            (Some(required), None) => {
                if self.preflight.permits_vm_execution()
                    || !self.preflight.reasons.contains(&match required {
                        ExecutionBundleClosureKindV2::Dependency => {
                            ExecutionBundlePreflightReasonV2::MissingDependencyClosure
                        }
                        ExecutionBundleClosureKindV2::Build => {
                            ExecutionBundlePreflightReasonV2::MissingBuildClosure
                        }
                    })
                {
                    return Err(ExecutionBundleErrorV2::MissingRequiredClosure);
                }
            }
        }
        if self.preflight.permits_vm_execution()
            && self.preflight.reasons.iter().any(|reason| {
                matches!(
                    reason,
                    ExecutionBundlePreflightReasonV2::MissingDependencyClosure
                        | ExecutionBundlePreflightReasonV2::MissingBuildClosure
                        | ExecutionBundlePreflightReasonV2::UnresolvedDependencies
                        | ExecutionBundlePreflightReasonV2::UnsupportedDependency
                        | ExecutionBundlePreflightReasonV2::UnsupportedArtifactForm
                        | ExecutionBundlePreflightReasonV2::UnsupportedNativeTag
                        | ExecutionBundlePreflightReasonV2::IncompleteArtifactMetadata
                )
            })
        {
            return Err(ExecutionBundleErrorV2::InvalidPreflight);
        }
        Ok(())
    }

    fn compute_bundle_sha256(&self) -> Result<Sha256Digest, ExecutionBundleErrorV2> {
        let bytes = serde_json_canonicalizer::to_vec(&ExecutionBundleDigestWireV2 {
            schema_version: &self.schema_version,
            canonicalization: &self.canonicalization,
            artifact_file_name: &self.artifact_file_name,
            artifact_kind: self.artifact_kind,
            artifact_sha256: &self.artifact_sha256,
            artifact_byte_length: self.artifact_byte_length,
            selected_scenario: &self.selected_scenario,
            expected_action_count: self.expected_action_count,
            closure_requirement: self.closure_requirement,
            closure: self.closure.as_ref(),
            policy: &self.policy,
            preflight: &self.preflight,
        })
        .map_err(|_| ExecutionBundleErrorV2::Serialization)?;
        Ok(Sha256Digest::from_bytes(&bytes))
    }
}

impl From<ExecutionBundleWireV2> for ExecutionBundleV2 {
    fn from(wire: ExecutionBundleWireV2) -> Self {
        Self {
            schema_version: wire.schema_version,
            canonicalization: wire.canonicalization,
            artifact_file_name: wire.artifact_file_name,
            artifact_kind: wire.artifact_kind,
            artifact_sha256: wire.artifact_sha256,
            artifact_byte_length: wire.artifact_byte_length,
            selected_scenario: wire.selected_scenario,
            expected_action_count: wire.expected_action_count,
            closure_requirement: wire.closure_requirement,
            closure: wire.closure,
            policy: wire.policy,
            preflight: wire.preflight,
            bundle_sha256: wire.bundle_sha256,
        }
    }
}

impl<'de> Deserialize<'de> for ExecutionBundleV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Self::from(ExecutionBundleWireV2::deserialize(deserializer)?);
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

pub fn decode_and_validate_execution_bundle_v2(
    bytes: &[u8],
) -> Result<ExecutionBundleV2, ExecutionBundleErrorV2> {
    if bytes.is_empty() {
        return Err(ExecutionBundleErrorV2::InvalidWire);
    }
    if bytes.len() > MAX_EXECUTION_BUNDLE_WIRE_BYTES_V2 {
        return Err(ExecutionBundleErrorV2::WireLimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = ExecutionBundleWireV2::deserialize(&mut deserializer)
        .map_err(|_| ExecutionBundleErrorV2::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| ExecutionBundleErrorV2::InvalidWire)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ExecutionBundleErrorV2::Serialization)?;
    if canonical != bytes {
        return Err(ExecutionBundleErrorV2::InvalidWire);
    }
    let value = ExecutionBundleV2::from(wire);
    value.validate()?;
    Ok(value)
}
