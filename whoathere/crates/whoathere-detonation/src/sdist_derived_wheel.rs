use crate::artifact::valid_version_component_v1;
use crate::{
    expected_wheel_scenario_kinds_v1, supported_wheel_console_command_name_v1,
    ArtifactScenarioCompileErrorV1, SdistBuildClosureV1, WheelConsoleArgumentProfileV1,
    WheelScenarioKindV1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use whoathere_artifact::{
    normalize_artifact, normalize_derived_wheel, ArtifactEnvelope, ArtifactFormat,
    ArtifactManifest, Ecosystem, NormalizationCompleteness, NormalizationLimits, PackageIdentity,
    Sha256Digest,
};

pub const PREPARED_SDIST_DERIVED_WHEEL_BUILD_SCHEMA_V1: &str =
    "whoathere.prepared_sdist_derived_wheel_build.v1";
pub const SDIST_GET_REQUIRES_FOR_BUILD_WHEEL_RESULT_SCHEMA_V1: &str =
    "whoathere.sdist_get_requires_for_build_wheel_result.v1";
pub const DERIVED_WHEEL_PROBE_MANIFEST_SCHEMA_V1: &str =
    "whoathere.derived_wheel_probe_manifest.v1";
pub const SDIST_DERIVED_WHEEL_CANONICALIZATION_V1: &str = "rfc8785.jcs.v1";
pub const SDIST_GET_REQUIRES_FOR_BUILD_WHEEL_HOOK_V1: &str = "pep517.get_requires_for_build_wheel";
pub const MAX_SDIST_DYNAMIC_BUILD_REQUIREMENTS_V1: usize = 256;
pub const MAX_SDIST_DYNAMIC_BUILD_REQUIREMENT_BYTES_V1: usize = 512;
pub const MAX_DERIVED_WHEEL_CONTRACT_WIRE_BYTES_V1: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdistDerivedWheelContractErrorV1 {
    InvalidSourceManifest,
    SourceArtifactIdentityMismatch,
    SourceManifestArtifactMismatch,
    InvalidBuildClosure,
    InvalidPreparedBuild,
    InvalidHookResult,
    BindingMismatch,
    InvalidProbeManifest,
    InvalidWire,
    Serialization,
}

impl SdistDerivedWheelContractErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidSourceManifest => "sdist_derived_wheel_source_manifest_invalid",
            Self::SourceArtifactIdentityMismatch => {
                "sdist_derived_wheel_source_artifact_identity_mismatch"
            }
            Self::SourceManifestArtifactMismatch => {
                "sdist_derived_wheel_source_manifest_artifact_mismatch"
            }
            Self::InvalidBuildClosure => "sdist_derived_wheel_build_closure_invalid",
            Self::InvalidPreparedBuild => "sdist_derived_wheel_prepared_build_invalid",
            Self::InvalidHookResult => "sdist_derived_wheel_hook_result_invalid",
            Self::BindingMismatch => "sdist_derived_wheel_binding_mismatch",
            Self::InvalidProbeManifest => "sdist_derived_wheel_probe_manifest_invalid",
            Self::InvalidWire => "sdist_derived_wheel_wire_invalid",
            Self::Serialization => "sdist_derived_wheel_serialization_failed",
        }
    }
}

impl fmt::Display for SdistDerivedWheelContractErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for SdistDerivedWheelContractErrorV1 {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistDerivedWheelManualReviewReasonV1 {
    SourceNormalizationIncomplete,
    SourceArtifactLimitUnsupported,
    ZipSdistPending,
    LegacySetupPyPending,
    SourceRuntimeDependenciesUnsupported,
    SourceNativeMaterialUnsupported,
    NonExactBuildRequirementUnsupported,
    FixedBuildClosureMismatch,
    BuildClosureArtifactUnsupported,
    GetRequiresForBuildWheelFailed,
    DynamicBuildRequirementsUnsupported,
    NoDerivedWheelProduced,
    MultipleDerivedWheelsProduced,
    DerivedWheelInvalid,
    DerivedWheelIdentityDrift,
    DerivedWheelRuntimeDependenciesUnsupported,
    DerivedWheelNativeOrTagUnsupported,
    DerivedWheelScriptsUnsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistDerivedWheelReviewStageV1 {
    SourcePreparation,
    DynamicBuildRequirements,
    DerivedWheelSeal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdistDerivedWheelManualReviewV1 {
    stage: SdistDerivedWheelReviewStageV1,
    reason: SdistDerivedWheelManualReviewReasonV1,
    source_artifact_sha256: Sha256Digest,
    evidence_binding_sha256: Sha256Digest,
    observed_count: u64,
}

impl SdistDerivedWheelManualReviewV1 {
    fn new(
        stage: SdistDerivedWheelReviewStageV1,
        reason: SdistDerivedWheelManualReviewReasonV1,
        source_artifact_sha256: Sha256Digest,
        evidence_binding_sha256: Sha256Digest,
        observed_count: u64,
    ) -> Self {
        Self {
            stage,
            reason,
            source_artifact_sha256,
            evidence_binding_sha256,
            observed_count,
        }
    }

    pub const fn stage(&self) -> SdistDerivedWheelReviewStageV1 {
        self.stage
    }

    pub const fn reason(&self) -> SdistDerivedWheelManualReviewReasonV1 {
        self.reason
    }

    pub fn source_artifact_sha256(&self) -> &Sha256Digest {
        &self.source_artifact_sha256
    }

    pub fn evidence_binding_sha256(&self) -> &Sha256Digest {
        &self.evidence_binding_sha256
    }

    pub fn observed_count(&self) -> u64 {
        self.observed_count
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SdistDerivedWheelPreparationOutcomeV1 {
    Prepared(Box<PreparedSdistDerivedWheelBuildV1>),
    InconclusiveManualReview(SdistDerivedWheelManualReviewV1),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerivedWheelProbeSealOutcomeV1 {
    Sealed(Box<DerivedWheelProbeManifestV1>),
    InconclusiveManualReview(SdistDerivedWheelManualReviewV1),
}

/// Exact bytes for one wheel named by an [`SdistBuildClosureV1`].
///
/// The preparation contract rehashes and safely normalizes every material. Merely presenting a
/// digest-bearing closure declaration is not enough to authorize the build.
#[derive(Debug, Clone, Copy)]
pub struct SdistBuildClosureMaterialV1<'a> {
    pub artifact_filename: &'a str,
    pub artifact_bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedSdistDerivedWheelBuildV1 {
    schema_version: String,
    canonicalization: String,
    source_artifact_sha256: Sha256Digest,
    source_artifact_byte_length: u64,
    source_envelope_sha256: Sha256Digest,
    source_manifest_sha256: Sha256Digest,
    source_package: PackageIdentity,
    source_artifact_format: ArtifactFormat,
    canonical_package_root: String,
    build_backend: String,
    backend_paths: Vec<String>,
    declared_build_requirements: Vec<String>,
    build_closure_sha256: Sha256Digest,
    build_closure_materials_sha256: Sha256Digest,
    prepared_build_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PreparedSdistDerivedWheelBuildDigestWireV1<'a> {
    schema_version: &'a str,
    canonicalization: &'a str,
    source_artifact_sha256: &'a Sha256Digest,
    source_artifact_byte_length: u64,
    source_envelope_sha256: &'a Sha256Digest,
    source_manifest_sha256: &'a Sha256Digest,
    source_package: &'a PackageIdentity,
    source_artifact_format: ArtifactFormat,
    canonical_package_root: &'a str,
    build_backend: &'a str,
    backend_paths: &'a [String],
    declared_build_requirements: &'a [String],
    build_closure_sha256: &'a Sha256Digest,
    build_closure_materials_sha256: &'a Sha256Digest,
}

impl PreparedSdistDerivedWheelBuildV1 {
    fn digest_wire(&self) -> PreparedSdistDerivedWheelBuildDigestWireV1<'_> {
        PreparedSdistDerivedWheelBuildDigestWireV1 {
            schema_version: &self.schema_version,
            canonicalization: &self.canonicalization,
            source_artifact_sha256: &self.source_artifact_sha256,
            source_artifact_byte_length: self.source_artifact_byte_length,
            source_envelope_sha256: &self.source_envelope_sha256,
            source_manifest_sha256: &self.source_manifest_sha256,
            source_package: &self.source_package,
            source_artifact_format: self.source_artifact_format,
            canonical_package_root: &self.canonical_package_root,
            build_backend: &self.build_backend,
            backend_paths: &self.backend_paths,
            declared_build_requirements: &self.declared_build_requirements,
            build_closure_sha256: &self.build_closure_sha256,
            build_closure_materials_sha256: &self.build_closure_materials_sha256,
        }
    }

    pub fn validate(&self) -> Result<(), SdistDerivedWheelContractErrorV1> {
        if self.schema_version != PREPARED_SDIST_DERIVED_WHEEL_BUILD_SCHEMA_V1
            || self.canonicalization != SDIST_DERIVED_WHEEL_CANONICALIZATION_V1
            || !valid_package_identity(&self.source_package)
            || self.source_artifact_format != ArtifactFormat::SdistTarGzip
            || self.source_artifact_byte_length == 0
            || !valid_nested_root(&self.canonical_package_root)
            || !valid_backend_target(&self.build_backend)
            || !valid_sorted_backend_paths(&self.backend_paths)
            || !valid_declared_build_requirement_list(&self.declared_build_requirements)
        {
            return Err(SdistDerivedWheelContractErrorV1::InvalidPreparedBuild);
        }
        let bytes = canonical_bytes(&self.digest_wire())?;
        if self.prepared_build_sha256 != Sha256Digest::from_bytes(&bytes) {
            return Err(SdistDerivedWheelContractErrorV1::InvalidPreparedBuild);
        }
        Ok(())
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, SdistDerivedWheelContractErrorV1> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn source_artifact_sha256(&self) -> &Sha256Digest {
        &self.source_artifact_sha256
    }

    pub fn source_artifact_byte_length(&self) -> u64 {
        self.source_artifact_byte_length
    }

    pub fn source_manifest_sha256(&self) -> &Sha256Digest {
        &self.source_manifest_sha256
    }

    pub fn source_envelope_sha256(&self) -> &Sha256Digest {
        &self.source_envelope_sha256
    }

    pub fn source_package(&self) -> &PackageIdentity {
        &self.source_package
    }

    pub fn canonical_package_root(&self) -> &str {
        &self.canonical_package_root
    }

    pub fn build_backend(&self) -> &str {
        &self.build_backend
    }

    pub fn backend_paths(&self) -> &[String] {
        &self.backend_paths
    }

    pub fn declared_build_requirements(&self) -> &[String] {
        &self.declared_build_requirements
    }

    pub fn build_closure_sha256(&self) -> &Sha256Digest {
        &self.build_closure_sha256
    }

    pub fn build_closure_materials_sha256(&self) -> &Sha256Digest {
        &self.build_closure_materials_sha256
    }

    pub fn prepared_build_sha256(&self) -> &Sha256Digest {
        &self.prepared_build_sha256
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdistGetRequiresForBuildWheelStatusV1 {
    Completed,
    BackendFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdistGetRequiresForBuildWheelResultV1 {
    schema_version: String,
    canonicalization: String,
    hook: String,
    prepared_build_sha256: Sha256Digest,
    status: SdistGetRequiresForBuildWheelStatusV1,
    requirements: Vec<String>,
    result_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct SdistGetRequiresForBuildWheelResultDigestWireV1<'a> {
    schema_version: &'a str,
    canonicalization: &'a str,
    hook: &'a str,
    prepared_build_sha256: &'a Sha256Digest,
    status: SdistGetRequiresForBuildWheelStatusV1,
    requirements: &'a [String],
}

impl SdistGetRequiresForBuildWheelResultV1 {
    pub fn new(
        prepared: &PreparedSdistDerivedWheelBuildV1,
        status: SdistGetRequiresForBuildWheelStatusV1,
        mut requirements: Vec<String>,
    ) -> Result<Self, SdistDerivedWheelContractErrorV1> {
        prepared.validate()?;
        requirements.sort();
        if !valid_observed_requirement_list(&requirements)
            || requirements.len() > MAX_SDIST_DYNAMIC_BUILD_REQUIREMENTS_V1
        {
            return Err(SdistDerivedWheelContractErrorV1::InvalidHookResult);
        }
        let mut value = Self {
            schema_version: SDIST_GET_REQUIRES_FOR_BUILD_WHEEL_RESULT_SCHEMA_V1.to_string(),
            canonicalization: SDIST_DERIVED_WHEEL_CANONICALIZATION_V1.to_string(),
            hook: SDIST_GET_REQUIRES_FOR_BUILD_WHEEL_HOOK_V1.to_string(),
            prepared_build_sha256: prepared.prepared_build_sha256.clone(),
            status,
            requirements,
            result_sha256: Sha256Digest::from_bytes(&[]),
        };
        value.result_sha256 = Sha256Digest::from_bytes(&canonical_bytes(&value.digest_wire())?);
        Ok(value)
    }

    fn digest_wire(&self) -> SdistGetRequiresForBuildWheelResultDigestWireV1<'_> {
        SdistGetRequiresForBuildWheelResultDigestWireV1 {
            schema_version: &self.schema_version,
            canonicalization: &self.canonicalization,
            hook: &self.hook,
            prepared_build_sha256: &self.prepared_build_sha256,
            status: self.status,
            requirements: &self.requirements,
        }
    }

    pub fn validate(&self) -> Result<(), SdistDerivedWheelContractErrorV1> {
        if self.schema_version != SDIST_GET_REQUIRES_FOR_BUILD_WHEEL_RESULT_SCHEMA_V1
            || self.canonicalization != SDIST_DERIVED_WHEEL_CANONICALIZATION_V1
            || self.hook != SDIST_GET_REQUIRES_FOR_BUILD_WHEEL_HOOK_V1
            || !valid_observed_requirement_list(&self.requirements)
            || self.requirements.len() > MAX_SDIST_DYNAMIC_BUILD_REQUIREMENTS_V1
        {
            return Err(SdistDerivedWheelContractErrorV1::InvalidHookResult);
        }
        let expected = Sha256Digest::from_bytes(&canonical_bytes(&self.digest_wire())?);
        if self.result_sha256 != expected {
            return Err(SdistDerivedWheelContractErrorV1::InvalidHookResult);
        }
        Ok(())
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, SdistDerivedWheelContractErrorV1> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn prepared_build_sha256(&self) -> &Sha256Digest {
        &self.prepared_build_sha256
    }

    pub const fn status(&self) -> SdistGetRequiresForBuildWheelStatusV1 {
        self.status
    }

    pub fn requirements(&self) -> &[String] {
        &self.requirements
    }

    pub fn result_sha256(&self) -> &Sha256Digest {
        &self.result_sha256
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DerivedWheelCandidateV1<'a> {
    pub artifact_filename: &'a str,
    pub artifact_bytes: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedWheelProbeManifestV1 {
    schema_version: String,
    canonicalization: String,
    source_artifact_sha256: Sha256Digest,
    source_envelope_sha256: Sha256Digest,
    source_manifest_sha256: Sha256Digest,
    source_package: PackageIdentity,
    prepared_build_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    get_requires_result_sha256: Sha256Digest,
    derived_artifact_filename: String,
    derived_artifact_sha256: Sha256Digest,
    derived_artifact_byte_length: u64,
    derived_manifest_sha256: Sha256Digest,
    derived_package: PackageIdentity,
    probes: Vec<WheelScenarioKindV1>,
    signed_vm_build_transcript_verified: bool,
    probe_manifest_sha256: Sha256Digest,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct DerivedWheelProbeManifestDigestWireV1<'a> {
    schema_version: &'a str,
    canonicalization: &'a str,
    source_artifact_sha256: &'a Sha256Digest,
    source_envelope_sha256: &'a Sha256Digest,
    source_manifest_sha256: &'a Sha256Digest,
    source_package: &'a PackageIdentity,
    prepared_build_sha256: &'a Sha256Digest,
    build_closure_sha256: &'a Sha256Digest,
    get_requires_result_sha256: &'a Sha256Digest,
    derived_artifact_filename: &'a str,
    derived_artifact_sha256: &'a Sha256Digest,
    derived_artifact_byte_length: u64,
    derived_manifest_sha256: &'a Sha256Digest,
    derived_package: &'a PackageIdentity,
    probes: &'a [WheelScenarioKindV1],
    signed_vm_build_transcript_verified: bool,
}

impl DerivedWheelProbeManifestV1 {
    fn digest_wire(&self) -> DerivedWheelProbeManifestDigestWireV1<'_> {
        DerivedWheelProbeManifestDigestWireV1 {
            schema_version: &self.schema_version,
            canonicalization: &self.canonicalization,
            source_artifact_sha256: &self.source_artifact_sha256,
            source_envelope_sha256: &self.source_envelope_sha256,
            source_manifest_sha256: &self.source_manifest_sha256,
            source_package: &self.source_package,
            prepared_build_sha256: &self.prepared_build_sha256,
            build_closure_sha256: &self.build_closure_sha256,
            get_requires_result_sha256: &self.get_requires_result_sha256,
            derived_artifact_filename: &self.derived_artifact_filename,
            derived_artifact_sha256: &self.derived_artifact_sha256,
            derived_artifact_byte_length: self.derived_artifact_byte_length,
            derived_manifest_sha256: &self.derived_manifest_sha256,
            derived_package: &self.derived_package,
            probes: &self.probes,
            signed_vm_build_transcript_verified: self.signed_vm_build_transcript_verified,
        }
    }

    pub fn validate(&self) -> Result<(), SdistDerivedWheelContractErrorV1> {
        if self.schema_version != DERIVED_WHEEL_PROBE_MANIFEST_SCHEMA_V1
            || self.canonicalization != SDIST_DERIVED_WHEEL_CANONICALIZATION_V1
            || !valid_package_identity(&self.source_package)
            || !valid_package_identity(&self.derived_package)
            || self.source_package.normalized_name != self.derived_package.normalized_name
            || self.source_package.version != self.derived_package.version
            || self.derived_artifact_byte_length == 0
            || !valid_derived_wheel_filename(&self.derived_artifact_filename, &self.derived_package)
            || !valid_derived_probe_set(&self.probes)
            || self.signed_vm_build_transcript_verified
        {
            return Err(SdistDerivedWheelContractErrorV1::InvalidProbeManifest);
        }
        let expected = Sha256Digest::from_bytes(&canonical_bytes(&self.digest_wire())?);
        if self.probe_manifest_sha256 != expected {
            return Err(SdistDerivedWheelContractErrorV1::InvalidProbeManifest);
        }
        Ok(())
    }

    pub fn canonical_json_v1(&self) -> Result<Vec<u8>, SdistDerivedWheelContractErrorV1> {
        self.validate()?;
        canonical_bytes(self)
    }

    pub fn source_artifact_sha256(&self) -> &Sha256Digest {
        &self.source_artifact_sha256
    }

    pub fn source_manifest_sha256(&self) -> &Sha256Digest {
        &self.source_manifest_sha256
    }

    pub fn source_envelope_sha256(&self) -> &Sha256Digest {
        &self.source_envelope_sha256
    }

    pub fn source_package(&self) -> &PackageIdentity {
        &self.source_package
    }

    pub fn prepared_build_sha256(&self) -> &Sha256Digest {
        &self.prepared_build_sha256
    }

    pub fn build_closure_sha256(&self) -> &Sha256Digest {
        &self.build_closure_sha256
    }

    pub fn get_requires_result_sha256(&self) -> &Sha256Digest {
        &self.get_requires_result_sha256
    }

    pub fn derived_artifact_filename(&self) -> &str {
        &self.derived_artifact_filename
    }

    pub fn derived_artifact_sha256(&self) -> &Sha256Digest {
        &self.derived_artifact_sha256
    }

    pub fn derived_artifact_byte_length(&self) -> u64 {
        self.derived_artifact_byte_length
    }

    pub fn derived_manifest_sha256(&self) -> &Sha256Digest {
        &self.derived_manifest_sha256
    }

    pub fn derived_package(&self) -> &PackageIdentity {
        &self.derived_package
    }

    pub fn probes(&self) -> &[WheelScenarioKindV1] {
        &self.probes
    }

    pub fn probe_manifest_sha256(&self) -> &Sha256Digest {
        &self.probe_manifest_sha256
    }

    /// This structural contract is not a signed VM build transcript.
    pub const fn signed_vm_build_transcript_verified(&self) -> bool {
        false
    }

    pub const fn establishes_clean_behavior(&self) -> bool {
        false
    }
}

/// Validate one exact, normalized, nested-root PEP 517 sdist and its complete offline closure.
///
/// This is pass one of the alpha contract. It intentionally does not derive import probes from
/// source-tree package-root guesses. Those probes can only appear after pass two normalizes the
/// exact derived wheel.
pub fn prepare_sdist_derived_wheel_build_v1(
    source_envelope: &ArtifactEnvelope,
    source_manifest: &ArtifactManifest,
    source_artifact_bytes: &[u8],
    build_closure: &SdistBuildClosureV1,
    build_closure_materials: &[SdistBuildClosureMaterialV1<'_>],
    limits: NormalizationLimits,
) -> Result<SdistDerivedWheelPreparationOutcomeV1, SdistDerivedWheelContractErrorV1> {
    source_envelope
        .validate()
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidSourceManifest)?;
    source_manifest
        .validate()
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidSourceManifest)?;
    let source_digest = Sha256Digest::from_bytes(source_artifact_bytes);
    if source_artifact_bytes.is_empty()
        || source_envelope.ecosystem != Ecosystem::Pypi
        || source_envelope.original_sha256 != source_digest
        || source_envelope.original_byte_length != source_artifact_bytes.len() as u64
        || source_manifest.artifact_sha256 != source_digest
    {
        return Err(SdistDerivedWheelContractErrorV1::SourceArtifactIdentityMismatch);
    }
    let reparsed = normalize_artifact(source_envelope, source_artifact_bytes, limits)
        .map_err(|_| SdistDerivedWheelContractErrorV1::SourceManifestArtifactMismatch)?;
    if &reparsed.manifest != source_manifest {
        return Err(SdistDerivedWheelContractErrorV1::SourceManifestArtifactMismatch);
    }
    let source_envelope_sha256 = source_envelope
        .envelope_sha256()
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidSourceManifest)?;
    let source_binding = source_manifest.manifest_sha256.clone();
    let review = |reason, count| {
        SdistDerivedWheelPreparationOutcomeV1::InconclusiveManualReview(
            SdistDerivedWheelManualReviewV1::new(
                SdistDerivedWheelReviewStageV1::SourcePreparation,
                reason,
                source_digest.clone(),
                source_binding.clone(),
                count,
            ),
        )
    };
    if source_manifest.normalization_completeness != NormalizationCompleteness::Complete {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::SourceNormalizationIncomplete,
            0,
        ));
    }
    if source_artifact_bytes.len() as u64 > limits.max_original_bytes {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::SourceArtifactLimitUnsupported,
            source_artifact_bytes.len() as u64,
        ));
    }
    match source_manifest.magic_detected_format {
        ArtifactFormat::SdistTarGzip => {}
        ArtifactFormat::SdistZip => {
            return Ok(review(
                SdistDerivedWheelManualReviewReasonV1::ZipSdistPending,
                0,
            ));
        }
        _ => return Err(SdistDerivedWheelContractErrorV1::InvalidSourceManifest),
    }
    let source_package = source_manifest
        .identity
        .as_ref()
        .ok_or(SdistDerivedWheelContractErrorV1::InvalidSourceManifest)?;
    let sdist = source_manifest
        .metadata
        .sdist
        .as_ref()
        .ok_or(SdistDerivedWheelContractErrorV1::InvalidSourceManifest)?;
    if source_package.ecosystem != Ecosystem::Pypi
        || !valid_nested_root(&source_manifest.canonical_package_root)
    {
        return Err(SdistDerivedWheelContractErrorV1::InvalidSourceManifest);
    }
    let Some(build_backend) = sdist.build_backend.as_deref() else {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::LegacySetupPyPending,
            0,
        ));
    };
    if sdist.pyproject_file_id.is_none()
        || !valid_backend_target(build_backend)
        || !valid_sorted_backend_paths(&sdist.backend_paths)
        || !valid_declared_build_requirement_list(&sdist.build_requires)
    {
        return Err(SdistDerivedWheelContractErrorV1::InvalidSourceManifest);
    }
    if !sdist.requires_dist.is_empty() {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::SourceRuntimeDependenciesUnsupported,
            sdist.requires_dist.len() as u64,
        ));
    }
    if !source_manifest.native_binary_file_ids.is_empty() {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::SourceNativeMaterialUnsupported,
            source_manifest.native_binary_file_ids.len() as u64,
        ));
    }

    let exact_build_requirements = match exact_alpha_build_requirements(&sdist.build_requires) {
        Some(value) => value,
        None => {
            return Ok(review(
                SdistDerivedWheelManualReviewReasonV1::NonExactBuildRequirementUnsupported,
                sdist.build_requires.len() as u64,
            ));
        }
    };

    build_closure
        .validate()
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidBuildClosure)?;
    let expected_closure =
        match SdistBuildClosureV1::new(&sdist.build_requires, build_closure.artifacts().to_vec()) {
            Ok(value) => value,
            Err(ArtifactScenarioCompileErrorV1::UnsupportedDependencyClosure) => {
                return Ok(review(
                    SdistDerivedWheelManualReviewReasonV1::FixedBuildClosureMismatch,
                    build_closure.artifacts().len() as u64,
                ));
            }
            Err(_) => return Err(SdistDerivedWheelContractErrorV1::InvalidBuildClosure),
        };
    if &expected_closure != build_closure {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::FixedBuildClosureMismatch,
            build_closure.artifacts().len() as u64,
        ));
    }
    if !closure_matches_exact_alpha_requirements(build_closure, &exact_build_requirements) {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::FixedBuildClosureMismatch,
            build_closure.artifacts().len() as u64,
        ));
    }
    let material_set_sha256 =
        match validate_build_closure_materials(build_closure, build_closure_materials, limits)? {
            Some(digest) => digest,
            None => {
                return Ok(review(
                    SdistDerivedWheelManualReviewReasonV1::BuildClosureArtifactUnsupported,
                    build_closure_materials.len() as u64,
                ));
            }
        };

    let mut prepared = PreparedSdistDerivedWheelBuildV1 {
        schema_version: PREPARED_SDIST_DERIVED_WHEEL_BUILD_SCHEMA_V1.to_string(),
        canonicalization: SDIST_DERIVED_WHEEL_CANONICALIZATION_V1.to_string(),
        source_artifact_sha256: source_digest,
        source_artifact_byte_length: source_artifact_bytes.len() as u64,
        source_envelope_sha256,
        source_manifest_sha256: source_manifest.manifest_sha256.clone(),
        source_package: source_package.clone(),
        source_artifact_format: source_manifest.magic_detected_format,
        canonical_package_root: source_manifest.canonical_package_root.clone(),
        build_backend: build_backend.to_string(),
        backend_paths: sdist.backend_paths.clone(),
        declared_build_requirements: sdist.build_requires.clone(),
        build_closure_sha256: build_closure.closure_sha256().clone(),
        build_closure_materials_sha256: material_set_sha256,
        prepared_build_sha256: Sha256Digest::from_bytes(&[]),
    };
    prepared.prepared_build_sha256 =
        Sha256Digest::from_bytes(&canonical_bytes(&prepared.digest_wire())?);
    prepared.validate()?;
    Ok(SdistDerivedWheelPreparationOutcomeV1::Prepared(Box::new(
        prepared,
    )))
}

/// Re-run pass one against the exact source and closure bytes and compare the immutable result.
pub fn verify_prepared_sdist_derived_wheel_build_v1(
    prepared: &PreparedSdistDerivedWheelBuildV1,
    source_envelope: &ArtifactEnvelope,
    source_manifest: &ArtifactManifest,
    source_artifact_bytes: &[u8],
    build_closure: &SdistBuildClosureV1,
    build_closure_materials: &[SdistBuildClosureMaterialV1<'_>],
    limits: NormalizationLimits,
) -> Result<(), SdistDerivedWheelContractErrorV1> {
    prepared.validate()?;
    match prepare_sdist_derived_wheel_build_v1(
        source_envelope,
        source_manifest,
        source_artifact_bytes,
        build_closure,
        build_closure_materials,
        limits,
    )? {
        SdistDerivedWheelPreparationOutcomeV1::Prepared(rebuilt)
            if rebuilt.as_ref() == prepared =>
        {
            Ok(())
        }
        _ => Err(SdistDerivedWheelContractErrorV1::BindingMismatch),
    }
}

/// Seal the one exact derived wheel and generate its complete trigger matrix from that wheel.
///
/// This is pass two. Non-empty dynamic requirements and unsupported wheel properties are explicit
/// inconclusive/manual-review outcomes; none can be interpreted as a clean package.
pub fn seal_derived_wheel_probe_manifest_v1(
    prepared: &PreparedSdistDerivedWheelBuildV1,
    hook_result: &SdistGetRequiresForBuildWheelResultV1,
    candidates: &[DerivedWheelCandidateV1<'_>],
    limits: NormalizationLimits,
) -> Result<DerivedWheelProbeSealOutcomeV1, SdistDerivedWheelContractErrorV1> {
    prepared.validate()?;
    hook_result.validate()?;
    if hook_result.prepared_build_sha256 != prepared.prepared_build_sha256 {
        return Err(SdistDerivedWheelContractErrorV1::BindingMismatch);
    }
    let source_digest = prepared.source_artifact_sha256.clone();
    let review = |reason, binding, count| {
        DerivedWheelProbeSealOutcomeV1::InconclusiveManualReview(
            SdistDerivedWheelManualReviewV1::new(
                SdistDerivedWheelReviewStageV1::DerivedWheelSeal,
                reason,
                source_digest.clone(),
                binding,
                count,
            ),
        )
    };
    if hook_result.status != SdistGetRequiresForBuildWheelStatusV1::Completed {
        return Ok(DerivedWheelProbeSealOutcomeV1::InconclusiveManualReview(
            SdistDerivedWheelManualReviewV1::new(
                SdistDerivedWheelReviewStageV1::DynamicBuildRequirements,
                SdistDerivedWheelManualReviewReasonV1::GetRequiresForBuildWheelFailed,
                source_digest.clone(),
                hook_result.result_sha256.clone(),
                hook_result.requirements.len() as u64,
            ),
        ));
    }
    if !hook_result.requirements.is_empty() {
        return Ok(DerivedWheelProbeSealOutcomeV1::InconclusiveManualReview(
            SdistDerivedWheelManualReviewV1::new(
                SdistDerivedWheelReviewStageV1::DynamicBuildRequirements,
                SdistDerivedWheelManualReviewReasonV1::DynamicBuildRequirementsUnsupported,
                source_digest.clone(),
                hook_result.result_sha256.clone(),
                hook_result.requirements.len() as u64,
            ),
        ));
    }
    if candidates.is_empty() {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::NoDerivedWheelProduced,
            hook_result.result_sha256.clone(),
            0,
        ));
    }
    if candidates.len() != 1 {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::MultipleDerivedWheelsProduced,
            hash_candidate_set(candidates)?,
            candidates.len() as u64,
        ));
    }
    let candidate = candidates[0];
    let candidate_digest = Sha256Digest::from_bytes(candidate.artifact_bytes);
    let normalized = match normalize_derived_wheel(
        candidate.artifact_filename,
        candidate.artifact_bytes,
        limits,
    ) {
        Ok(value) => value,
        Err(_) => {
            return Ok(review(
                SdistDerivedWheelManualReviewReasonV1::DerivedWheelInvalid,
                candidate_digest,
                1,
            ));
        }
    };
    if normalized.manifest.normalization_completeness != NormalizationCompleteness::Complete {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::DerivedWheelInvalid,
            candidate_digest,
            1,
        ));
    }
    let derived_package = normalized
        .manifest
        .identity
        .as_ref()
        .ok_or(SdistDerivedWheelContractErrorV1::InvalidProbeManifest)?;
    if derived_package.ecosystem != Ecosystem::Pypi
        || derived_package.normalized_name != prepared.source_package.normalized_name
        || derived_package.version != prepared.source_package.version
    {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::DerivedWheelIdentityDrift,
            candidate_digest,
            1,
        ));
    }
    let wheel = normalized
        .manifest
        .metadata
        .wheel
        .as_ref()
        .ok_or(SdistDerivedWheelContractErrorV1::InvalidProbeManifest)?;
    if !wheel.requires_dist.is_empty() {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::DerivedWheelRuntimeDependenciesUnsupported,
            candidate_digest,
            wheel.requires_dist.len() as u64,
        ));
    }
    if !supported_pure_python_wheel(&normalized.manifest) {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::DerivedWheelNativeOrTagUnsupported,
            candidate_digest,
            wheel.tags.len() as u64,
        ));
    }
    if !wheel.script_file_ids.is_empty() {
        return Ok(review(
            SdistDerivedWheelManualReviewReasonV1::DerivedWheelScriptsUnsupported,
            candidate_digest,
            wheel.script_file_ids.len() as u64,
        ));
    }
    let probes = expected_wheel_scenario_kinds_v1(&normalized.manifest)
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidProbeManifest)?;
    if !valid_derived_probe_set(&probes) {
        return Err(SdistDerivedWheelContractErrorV1::InvalidProbeManifest);
    }
    let mut manifest = DerivedWheelProbeManifestV1 {
        schema_version: DERIVED_WHEEL_PROBE_MANIFEST_SCHEMA_V1.to_string(),
        canonicalization: SDIST_DERIVED_WHEEL_CANONICALIZATION_V1.to_string(),
        source_artifact_sha256: prepared.source_artifact_sha256.clone(),
        source_envelope_sha256: prepared.source_envelope_sha256.clone(),
        source_manifest_sha256: prepared.source_manifest_sha256.clone(),
        source_package: prepared.source_package.clone(),
        prepared_build_sha256: prepared.prepared_build_sha256.clone(),
        build_closure_sha256: prepared.build_closure_sha256.clone(),
        get_requires_result_sha256: hook_result.result_sha256.clone(),
        derived_artifact_filename: candidate.artifact_filename.to_string(),
        derived_artifact_sha256: normalized.manifest.artifact_sha256.clone(),
        derived_artifact_byte_length: candidate.artifact_bytes.len() as u64,
        derived_manifest_sha256: normalized.manifest.manifest_sha256.clone(),
        derived_package: derived_package.clone(),
        probes,
        signed_vm_build_transcript_verified: false,
        probe_manifest_sha256: Sha256Digest::from_bytes(&[]),
    };
    manifest.probe_manifest_sha256 =
        Sha256Digest::from_bytes(&canonical_bytes(&manifest.digest_wire())?);
    manifest.validate()?;
    Ok(DerivedWheelProbeSealOutcomeV1::Sealed(Box::new(manifest)))
}

/// Re-normalize exact wheel bytes and verify every structural source/build/output binding.
///
/// This remains non-authenticated until a separately verified signed VM build transcript binds the
/// prepared build, hook result, and candidate output. It cannot establish clean behavior.
pub fn verify_derived_wheel_probe_manifest_v1(
    manifest: &DerivedWheelProbeManifestV1,
    expected_prepared: &PreparedSdistDerivedWheelBuildV1,
    expected_hook_result: &SdistGetRequiresForBuildWheelResultV1,
    artifact_filename: &str,
    artifact_bytes: &[u8],
    limits: NormalizationLimits,
) -> Result<(), SdistDerivedWheelContractErrorV1> {
    manifest.validate()?;
    expected_prepared.validate()?;
    expected_hook_result.validate()?;
    // `prepared_build_sha256` transitively binds the selected backend, backend paths, declared
    // requirements, closure descriptor digest, and rehashed closure-material set. The explicit
    // fields below make the source, hook, and derived-output edges independently checkable too.
    if expected_hook_result.prepared_build_sha256 != expected_prepared.prepared_build_sha256
        || expected_hook_result.status != SdistGetRequiresForBuildWheelStatusV1::Completed
        || !expected_hook_result.requirements.is_empty()
        || manifest.source_artifact_sha256 != expected_prepared.source_artifact_sha256
        || manifest.source_envelope_sha256 != expected_prepared.source_envelope_sha256
        || manifest.source_manifest_sha256 != expected_prepared.source_manifest_sha256
        || manifest.source_package != expected_prepared.source_package
        || manifest.prepared_build_sha256 != expected_prepared.prepared_build_sha256
        || manifest.build_closure_sha256 != expected_prepared.build_closure_sha256
        || manifest.get_requires_result_sha256 != expected_hook_result.result_sha256
    {
        return Err(SdistDerivedWheelContractErrorV1::BindingMismatch);
    }
    if manifest.derived_artifact_filename != artifact_filename
        || manifest.derived_artifact_byte_length != artifact_bytes.len() as u64
        || manifest.derived_artifact_sha256 != Sha256Digest::from_bytes(artifact_bytes)
    {
        return Err(SdistDerivedWheelContractErrorV1::BindingMismatch);
    }
    let normalized = normalize_derived_wheel(artifact_filename, artifact_bytes, limits)
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidProbeManifest)?;
    let package = normalized
        .manifest
        .identity
        .as_ref()
        .ok_or(SdistDerivedWheelContractErrorV1::InvalidProbeManifest)?;
    let probes = expected_wheel_scenario_kinds_v1(&normalized.manifest)
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidProbeManifest)?;
    if manifest.derived_manifest_sha256 != normalized.manifest.manifest_sha256
        || &manifest.derived_package != package
        || manifest.probes != probes
        || !supported_pure_python_wheel(&normalized.manifest)
    {
        return Err(SdistDerivedWheelContractErrorV1::BindingMismatch);
    }
    Ok(())
}

pub fn decode_and_validate_prepared_sdist_derived_wheel_build_v1(
    bytes: &[u8],
) -> Result<PreparedSdistDerivedWheelBuildV1, SdistDerivedWheelContractErrorV1> {
    decode_canonical(bytes, |value: &PreparedSdistDerivedWheelBuildV1| {
        value.validate()
    })
}

pub fn decode_and_validate_sdist_get_requires_for_build_wheel_result_v1(
    bytes: &[u8],
) -> Result<SdistGetRequiresForBuildWheelResultV1, SdistDerivedWheelContractErrorV1> {
    decode_canonical(bytes, |value: &SdistGetRequiresForBuildWheelResultV1| {
        value.validate()
    })
}

pub fn decode_and_validate_derived_wheel_probe_manifest_v1(
    bytes: &[u8],
) -> Result<DerivedWheelProbeManifestV1, SdistDerivedWheelContractErrorV1> {
    decode_canonical(bytes, |value: &DerivedWheelProbeManifestV1| {
        value.validate()
    })
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ClosureMaterialDigestWireV1<'a> {
    artifact_filename: &'a str,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
}

fn validate_build_closure_materials(
    closure: &SdistBuildClosureV1,
    materials: &[SdistBuildClosureMaterialV1<'_>],
    limits: NormalizationLimits,
) -> Result<Option<Sha256Digest>, SdistDerivedWheelContractErrorV1> {
    if materials.len() != closure.artifacts().len() {
        return Ok(None);
    }
    let mut descriptors_by_filename = BTreeMap::new();
    for descriptor in closure.artifacts() {
        if descriptors_by_filename
            .insert(descriptor.artifact_filename(), descriptor)
            .is_some()
        {
            return Ok(None);
        }
    }
    let mut materials_by_filename = BTreeMap::new();
    for material in materials {
        if materials_by_filename
            .insert(material.artifact_filename, material.artifact_bytes)
            .is_some()
        {
            return Ok(None);
        }
    }
    if descriptors_by_filename
        .keys()
        .ne(materials_by_filename.keys())
    {
        return Ok(None);
    }

    let mut digest_records = Vec::with_capacity(materials.len());
    for (artifact_filename, descriptor) in descriptors_by_filename {
        let artifact_bytes = materials_by_filename
            .get(artifact_filename)
            .copied()
            .ok_or(SdistDerivedWheelContractErrorV1::InvalidBuildClosure)?;
        if descriptor.artifact_byte_length() != artifact_bytes.len() as u64
            || descriptor.artifact_sha256() != &Sha256Digest::from_bytes(artifact_bytes)
        {
            return Ok(None);
        }
        let normalized = match normalize_derived_wheel(artifact_filename, artifact_bytes, limits) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
        let package = match normalized.manifest.identity.as_ref() {
            Some(value) => value,
            None => return Ok(None),
        };
        let wheel = match normalized.manifest.metadata.wheel.as_ref() {
            Some(value) => value,
            None => return Ok(None),
        };
        if package.normalized_name != descriptor.normalized_name()
            || package.version != descriptor.version()
            || normalized.manifest.normalization_completeness != NormalizationCompleteness::Complete
            || !wheel.requires_dist.is_empty()
            || !wheel.script_file_ids.is_empty()
            || !supported_pure_python_wheel(&normalized.manifest)
        {
            return Ok(None);
        }
        digest_records.push(ClosureMaterialDigestWireV1 {
            artifact_filename,
            artifact_sha256: Sha256Digest::from_bytes(artifact_bytes),
            artifact_byte_length: artifact_bytes.len() as u64,
        });
    }
    Ok(Some(Sha256Digest::from_bytes(&canonical_bytes(
        &digest_records,
    )?)))
}

fn supported_pure_python_wheel(manifest: &ArtifactManifest) -> bool {
    let Some(wheel) = manifest.metadata.wheel.as_ref() else {
        return false;
    };
    wheel.root_is_purelib == Some(true)
        && wheel.tags.len() == 1
        && wheel.tags[0] == "py3-none-any"
        && wheel.native_tags.is_empty()
        && manifest.native_binary_file_ids.is_empty()
}

fn valid_derived_probe_set(probes: &[WheelScenarioKindV1]) -> bool {
    if probes.is_empty()
        || probes.first() != Some(&WheelScenarioKindV1::InstallExactWheel)
        || probes.windows(2).any(|pair| pair[0] >= pair[1])
        || probes
            .iter()
            .filter(|probe| matches!(probe, WheelScenarioKindV1::InstallExactWheel))
            .count()
            != 1
    {
        return false;
    }
    if !probes.iter().all(|probe| match probe {
        WheelScenarioKindV1::InstallExactWheel => true,
        WheelScenarioKindV1::FreshInterpreterPth { pth_file_ids } => {
            !pth_file_ids.is_empty() && !pth_file_ids.windows(2).any(|pair| pair[0] >= pair[1])
        }
        WheelScenarioKindV1::ImportRoot { module } => valid_python_target(module),
        WheelScenarioKindV1::ConsoleEntryPoint {
            command_name,
            module,
            callable,
            target_sha256,
            ..
        } => {
            valid_console_name(command_name)
                && valid_python_target(module)
                && valid_python_target(callable)
                && target_sha256
                    == &Sha256Digest::from_bytes(format!("{module}:{callable}").as_bytes())
        }
    }) {
        return false;
    }

    let mut profiles_by_entry_point = BTreeMap::new();
    for probe in probes {
        if let WheelScenarioKindV1::ConsoleEntryPoint {
            command_name,
            module,
            callable,
            target_sha256,
            argument_profile,
        } = probe
        {
            let profiles = profiles_by_entry_point
                .entry((command_name, module, callable, target_sha256))
                .or_insert_with(BTreeSet::new);
            if !profiles.insert(*argument_profile) {
                return false;
            }
        }
    }
    let required_profiles = BTreeSet::from([
        WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperHelp,
        WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperNoArguments,
    ]);
    profiles_by_entry_point
        .values()
        .all(|profiles| profiles == &required_profiles)
}

fn valid_python_target(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.is_ascii()
        && value.split('.').all(|component| {
            let mut bytes = component.bytes();
            bytes
                .next()
                .is_some_and(|byte| byte == b'_' || byte.is_ascii_alphabetic())
                && bytes.all(|byte| byte == b'_' || byte.is_ascii_alphanumeric())
        })
}

fn valid_console_name(value: &str) -> bool {
    supported_wheel_console_command_name_v1(value)
}

fn valid_backend_target(value: &str) -> bool {
    let mut pieces = value.split(':');
    let module = pieces.next().unwrap_or_default();
    let object = pieces.next();
    pieces.next().is_none() && valid_python_target(module) && object.is_none_or(valid_python_target)
}

fn valid_nested_root(value: &str) -> bool {
    value != "."
        && !value.is_empty()
        && value.len() <= 255
        && value.is_ascii()
        && !value.contains('/')
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_sorted_backend_paths(paths: &[String]) -> bool {
    !paths.windows(2).any(|pair| pair[0] >= pair[1])
        && paths.iter().all(|path| {
            !path.is_empty()
                && path.len() <= 512
                && path.is_ascii()
                && !path.starts_with('/')
                && !path.ends_with('/')
                && !path.contains('\\')
                && path.split('/').all(|component| {
                    !component.is_empty()
                        && component != "."
                        && component != ".."
                        && !component.bytes().any(|byte| byte.is_ascii_control())
                })
        })
}

fn exact_alpha_build_requirements(requirements: &[String]) -> Option<Vec<(String, String)>> {
    let mut parsed = Vec::with_capacity(requirements.len());
    for requirement in requirements {
        if requirement.matches("==").count() != 1 {
            return None;
        }
        let (name, version) = requirement.split_once("==")?;
        if normalize_pypi_name(name).as_deref() != Some(name)
            || !valid_version_component_v1(version)
            || requirement != &format!("{name}=={version}")
            || parsed
                .iter()
                .any(|(existing_name, _): &(String, String)| existing_name == name)
        {
            return None;
        }
        parsed.push((name.to_string(), version.to_string()));
    }
    Some(parsed)
}

fn closure_matches_exact_alpha_requirements(
    closure: &SdistBuildClosureV1,
    requirements: &[(String, String)],
) -> bool {
    closure.artifacts().len() == requirements.len()
        && requirements.iter().all(|(name, version)| {
            closure
                .artifacts()
                .iter()
                .any(|artifact| artifact.normalized_name() == name && artifact.version() == version)
        })
}

fn valid_observed_requirement_list(requirements: &[String]) -> bool {
    requirements.len() <= MAX_SDIST_DYNAMIC_BUILD_REQUIREMENTS_V1
        && !requirements.windows(2).any(|pair| pair[0] >= pair[1])
        && requirements.iter().all(|requirement| {
            !requirement.is_empty()
                && requirement.len() <= MAX_SDIST_DYNAMIC_BUILD_REQUIREMENT_BYTES_V1
                && requirement.is_ascii()
                && !requirement.bytes().any(|byte| byte.is_ascii_control())
        })
}

fn valid_declared_build_requirement_list(requirements: &[String]) -> bool {
    valid_observed_requirement_list(requirements)
        && requirements.iter().all(|requirement| {
            !requirement.contains('@')
                && !requirement.contains(';')
                && requirement
                    .split(|character: char| {
                        character.is_whitespace()
                            || matches!(character, '[' | '<' | '>' | '=' | '!' | '~')
                    })
                    .next()
                    .and_then(normalize_pypi_name)
                    .is_some()
        })
}

fn valid_package_identity(package: &PackageIdentity) -> bool {
    package.ecosystem == Ecosystem::Pypi
        && normalize_pypi_name(&package.display_name).as_deref()
            == Some(package.normalized_name.as_str())
        && !package.version.is_empty()
        && package.version.len() <= 128
        && package.version.is_ascii()
        && !package
            .version
            .bytes()
            .any(|byte| byte.is_ascii_control() || matches!(byte, b'/' | b'\\'))
}

fn normalize_pypi_name(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return None;
    }
    let mut output = String::new();
    let mut separator = false;
    for byte in value.bytes() {
        if matches!(byte, b'-' | b'_' | b'.') {
            if !separator && !output.is_empty() {
                output.push('-');
            }
            separator = true;
        } else {
            output.push((byte as char).to_ascii_lowercase());
            separator = false;
        }
    }
    while output.ends_with('-') {
        output.pop();
    }
    (!output.is_empty()).then_some(output)
}

fn valid_derived_wheel_filename(filename: &str, package: &PackageIdentity) -> bool {
    let distribution = package.normalized_name.replace('-', "_");
    if filename.len() > 255
        || !filename.is_ascii()
        || filename.contains('/')
        || filename.contains('\\')
    {
        return false;
    }
    let prefix = format!("{distribution}-{}-", package.version);
    let Some(tags) = filename
        .strip_prefix(&prefix)
        .and_then(|value| value.strip_suffix(".whl"))
    else {
        return false;
    };
    let parts = tags.split('-').collect::<Vec<_>>();
    match parts.as_slice() {
        ["py3", "none", "any"] => true,
        [build, "py3", "none", "any"] => {
            build
                .bytes()
                .next()
                .is_some_and(|byte| byte.is_ascii_digit())
                && build
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        }
        _ => false,
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct CandidateDigestWireV1<'a> {
    artifact_filename: &'a str,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
}

fn hash_candidate_set(
    candidates: &[DerivedWheelCandidateV1<'_>],
) -> Result<Sha256Digest, SdistDerivedWheelContractErrorV1> {
    let values = candidates
        .iter()
        .map(|candidate| CandidateDigestWireV1 {
            artifact_filename: candidate.artifact_filename,
            artifact_sha256: Sha256Digest::from_bytes(candidate.artifact_bytes),
            artifact_byte_length: candidate.artifact_bytes.len() as u64,
        })
        .collect::<Vec<_>>();
    Ok(Sha256Digest::from_bytes(&canonical_bytes(&values)?))
}

fn canonical_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, SdistDerivedWheelContractErrorV1> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|_| SdistDerivedWheelContractErrorV1::Serialization)
}

fn decode_canonical<T, F>(bytes: &[u8], validate: F) -> Result<T, SdistDerivedWheelContractErrorV1>
where
    T: for<'de> Deserialize<'de> + Serialize,
    F: FnOnce(&T) -> Result<(), SdistDerivedWheelContractErrorV1>,
{
    if bytes.is_empty() || bytes.len() > MAX_DERIVED_WHEEL_CONTRACT_WIRE_BYTES_V1 {
        return Err(SdistDerivedWheelContractErrorV1::InvalidWire);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer)
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidWire)?;
    deserializer
        .end()
        .map_err(|_| SdistDerivedWheelContractErrorV1::InvalidWire)?;
    validate(&value)?;
    if canonical_bytes(&value)? != bytes {
        return Err(SdistDerivedWheelContractErrorV1::InvalidWire);
    }
    Ok(value)
}
