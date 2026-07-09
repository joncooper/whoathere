use crate::ArtifactModelError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use whoathere_hash::sha256_digest;

pub const ARTIFACT_ENVELOPE_SCHEMA_VERSION: &str = "whoathere.artifact_envelope.v1";
pub const ARTIFACT_MANIFEST_SCHEMA_VERSION: &str = "whoathere.artifact_manifest.v1";
pub const ARTIFACT_MANIFEST_CANONICALIZATION_VERSION: &str =
    "whoathere.artifact_manifest.canonical_json.v1";

/// Canonical lowercase `sha256:<64 hex characters>` digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        let Some(hex) = value.strip_prefix("sha256:") else {
            return Err("SHA-256 digest must start with `sha256:`".to_string());
        };
        if hex.len() != 64
            || !hex
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(
                "SHA-256 digest must contain 64 lowercase hexadecimal characters".to_string(),
            );
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(sha256_digest(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for Sha256Digest {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::parse(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ecosystem {
    Npm,
    Pypi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactSourceType {
    Registry,
    ApprovedCustody,
    LocalFile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionMethod {
    RegistryDownload,
    ApprovedCustodyImport,
    LocalInertFixture,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    NpmTarGzip,
    WheelZip,
    SdistTarGzip,
    SdistZip,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FormatCorroboration {
    DeclaredMatchesMagic,
    NoDeclaredFormat,
    DeclaredMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactEnvelopeInput {
    pub ecosystem: Ecosystem,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub source_coordinate: String,
    pub source_type: ArtifactSourceType,
    pub acquired_at: String,
    pub acquisition_method: AcquisitionMethod,
    pub original_filename: String,
    pub declared_format: Option<ArtifactFormat>,
    pub custody_reference: String,
    pub resolver_metadata_sha256: Option<Sha256Digest>,
    pub registry_metadata_sha256: Option<Sha256Digest>,
    pub policy_version: String,
    pub requires_external_dependency_resolution: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactEnvelope {
    pub schema_version: String,
    pub ecosystem: Ecosystem,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub source_coordinate: String,
    pub source_type: ArtifactSourceType,
    pub acquired_at: String,
    pub acquisition_method: AcquisitionMethod,
    pub original_filename: String,
    pub original_byte_length: u64,
    pub original_sha256: Sha256Digest,
    pub magic_detected_format: ArtifactFormat,
    pub declared_format: Option<ArtifactFormat>,
    pub format_corroboration: FormatCorroboration,
    pub custody_reference: String,
    pub resolver_metadata_sha256: Option<Sha256Digest>,
    pub registry_metadata_sha256: Option<Sha256Digest>,
    pub policy_version: String,
    pub requires_external_dependency_resolution: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactEnvelopeWire {
    schema_version: String,
    ecosystem: Ecosystem,
    package_name: Option<String>,
    package_version: Option<String>,
    source_coordinate: String,
    source_type: ArtifactSourceType,
    acquired_at: String,
    acquisition_method: AcquisitionMethod,
    original_filename: String,
    original_byte_length: u64,
    original_sha256: Sha256Digest,
    magic_detected_format: ArtifactFormat,
    declared_format: Option<ArtifactFormat>,
    format_corroboration: FormatCorroboration,
    custody_reference: String,
    resolver_metadata_sha256: Option<Sha256Digest>,
    registry_metadata_sha256: Option<Sha256Digest>,
    policy_version: String,
    requires_external_dependency_resolution: bool,
}

impl<'de> Deserialize<'de> for ArtifactEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ArtifactEnvelopeWire::deserialize(deserializer)?;
        let envelope = Self {
            schema_version: wire.schema_version,
            ecosystem: wire.ecosystem,
            package_name: wire.package_name,
            package_version: wire.package_version,
            source_coordinate: wire.source_coordinate,
            source_type: wire.source_type,
            acquired_at: wire.acquired_at,
            acquisition_method: wire.acquisition_method,
            original_filename: wire.original_filename,
            original_byte_length: wire.original_byte_length,
            original_sha256: wire.original_sha256,
            magic_detected_format: wire.magic_detected_format,
            declared_format: wire.declared_format,
            format_corroboration: wire.format_corroboration,
            custody_reference: wire.custody_reference,
            resolver_metadata_sha256: wire.resolver_metadata_sha256,
            registry_metadata_sha256: wire.registry_metadata_sha256,
            policy_version: wire.policy_version,
            requires_external_dependency_resolution: wire.requires_external_dependency_resolution,
        };
        envelope.validate().map_err(serde::de::Error::custom)?;
        Ok(envelope)
    }
}

impl ArtifactEnvelope {
    pub fn from_original_bytes(
        input: ArtifactEnvelopeInput,
        original_bytes: &[u8],
        magic_detected_format: ArtifactFormat,
    ) -> Self {
        let format_corroboration = match input.declared_format {
            Some(declared) if declared == magic_detected_format => {
                FormatCorroboration::DeclaredMatchesMagic
            }
            Some(_) => FormatCorroboration::DeclaredMismatch,
            None => FormatCorroboration::NoDeclaredFormat,
        };
        Self {
            schema_version: ARTIFACT_ENVELOPE_SCHEMA_VERSION.to_string(),
            ecosystem: input.ecosystem,
            package_name: input.package_name,
            package_version: input.package_version,
            source_coordinate: input.source_coordinate,
            source_type: input.source_type,
            acquired_at: input.acquired_at,
            acquisition_method: input.acquisition_method,
            original_filename: input.original_filename,
            original_byte_length: original_bytes.len() as u64,
            original_sha256: Sha256Digest::from_bytes(original_bytes),
            magic_detected_format,
            declared_format: input.declared_format,
            format_corroboration,
            custody_reference: input.custody_reference,
            resolver_metadata_sha256: input.resolver_metadata_sha256,
            registry_metadata_sha256: input.registry_metadata_sha256,
            policy_version: input.policy_version,
            requires_external_dependency_resolution: input.requires_external_dependency_resolution,
        }
    }

    pub fn matches_original_bytes(&self, bytes: &[u8]) -> bool {
        self.original_byte_length == bytes.len() as u64
            && self.original_sha256 == Sha256Digest::from_bytes(bytes)
    }

    pub fn verify_magic_format(&self, detected: ArtifactFormat) -> bool {
        self.magic_detected_format == detected
            && self.format_corroboration != FormatCorroboration::DeclaredMismatch
    }

    pub fn canonical_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn envelope_sha256(&self) -> Result<Sha256Digest, serde_json::Error> {
        self.canonical_json()
            .map(|bytes| Sha256Digest::from_bytes(&bytes))
    }

    pub fn validate(&self) -> Result<(), ArtifactModelError> {
        if self.schema_version != ARTIFACT_ENVELOPE_SCHEMA_VERSION {
            return Err(ArtifactModelError::InvalidContract(
                "unsupported artifact envelope schema version".to_string(),
            ));
        }
        if self.magic_detected_format == ArtifactFormat::Unknown {
            return Err(ArtifactModelError::InvalidContract(
                "artifact envelope has unknown magic format".to_string(),
            ));
        }
        let expected_corroboration = match self.declared_format {
            Some(declared) if declared == self.magic_detected_format => {
                FormatCorroboration::DeclaredMatchesMagic
            }
            Some(_) => FormatCorroboration::DeclaredMismatch,
            None => FormatCorroboration::NoDeclaredFormat,
        };
        if self.format_corroboration != expected_corroboration
            || self.format_corroboration == FormatCorroboration::DeclaredMismatch
        {
            return Err(ArtifactModelError::InvalidContract(
                "artifact format corroboration is invalid or mismatched".to_string(),
            ));
        }
        if self.source_coordinate.is_empty()
            || self.acquired_at.is_empty()
            || self.original_filename.is_empty()
            || self.custody_reference.is_empty()
            || self.policy_version.is_empty()
        {
            return Err(ArtifactModelError::InvalidContract(
                "artifact envelope contains an empty required field".to_string(),
            ));
        }
        if self.original_byte_length == 0 {
            return Err(ArtifactModelError::InvalidContract(
                "artifact envelope original byte length is zero".to_string(),
            ));
        }
        if self.source_type == ArtifactSourceType::Registry {
            let (name, version) = self
                .package_name
                .as_deref()
                .zip(self.package_version.as_deref())
                .ok_or_else(|| {
                    ArtifactModelError::InvalidContract(
                        "registry artifact envelope lacks package name or version".to_string(),
                    )
                })?;
            let expected = match self.ecosystem {
                Ecosystem::Npm => format!("npm:{name}@{version}"),
                Ecosystem::Pypi => format!("pypi:{name}=={version}"),
            };
            if self.source_coordinate != expected {
                return Err(ArtifactModelError::InvalidContract(format!(
                    "registry source coordinate must be `{expected}`"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageIdentity {
    pub ecosystem: Ecosystem,
    pub display_name: String,
    pub normalized_name: String,
    pub version: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemberType {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberRecord {
    pub file_id: Sha256Digest,
    pub normalized_path: String,
    pub original_path: String,
    pub member_type: MemberType,
    pub mode: Option<u32>,
    pub size: u64,
    pub sha256: Sha256Digest,
}

impl MemberRecord {
    pub fn from_bytes(
        artifact_sha256: &Sha256Digest,
        normalized_path: String,
        original_path: String,
        member_type: MemberType,
        mode: Option<u32>,
        bytes: &[u8],
    ) -> Self {
        let sha256 = Sha256Digest::from_bytes(bytes);
        let file_id =
            Self::compute_file_id(artifact_sha256, &normalized_path, member_type, &sha256);
        Self {
            file_id,
            normalized_path,
            original_path,
            member_type,
            mode,
            size: bytes.len() as u64,
            sha256,
        }
    }

    pub fn compute_file_id(
        artifact_sha256: &Sha256Digest,
        normalized_path: &str,
        member_type: MemberType,
        content_sha256: &Sha256Digest,
    ) -> Sha256Digest {
        let member_type = match member_type {
            MemberType::File => "file",
            MemberType::Directory => "directory",
        };
        let file_identity = format!(
            "whoathere.file.v1\0{}\0{}\0{}\0{}",
            artifact_sha256, normalized_path, content_sha256, member_type
        );
        Sha256Digest::from_bytes(file_identity.as_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExcludedMemberRecord {
    pub original_path: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestIssue {
    pub reason_code: String,
    pub path: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchiveAnomaly {
    pub reason_code: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizationCompleteness {
    Complete,
    Incomplete,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyDeclaration {
    pub group: String,
    pub name: String,
    pub requirement: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NpmMetadata {
    pub package_json_file_id: Option<Sha256Digest>,
    pub lifecycle_scripts: BTreeMap<String, String>,
    pub bin_targets: BTreeMap<String, String>,
    pub export_targets: Vec<String>,
    pub dependency_declarations: Vec<DependencyDeclaration>,
    pub requires_offline_closure: bool,
    pub implicit_node_gyp_rebuild: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WheelMetadata {
    pub dist_info_directory: Option<String>,
    pub metadata_file_id: Option<Sha256Digest>,
    pub wheel_file_id: Option<Sha256Digest>,
    pub record_file_id: Option<Sha256Digest>,
    pub entry_points_file_id: Option<Sha256Digest>,
    pub wheel_version: Option<String>,
    pub root_is_purelib: Option<bool>,
    pub tags: Vec<String>,
    pub console_entry_points: BTreeMap<String, String>,
    pub entry_points: BTreeMap<String, BTreeMap<String, String>>,
    pub pth_file_ids: Vec<Sha256Digest>,
    pub script_file_ids: Vec<Sha256Digest>,
    pub import_roots: Vec<String>,
    pub native_tags: Vec<String>,
    pub requires_dist: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SdistMetadata {
    pub pkg_info_file_id: Option<Sha256Digest>,
    pub pyproject_file_id: Option<Sha256Digest>,
    pub setup_py_file_id: Option<Sha256Digest>,
    pub setup_cfg_file_id: Option<Sha256Digest>,
    pub build_backend: Option<String>,
    pub build_requires: Vec<String>,
    pub backend_paths: Vec<String>,
    pub package_roots: Vec<String>,
    pub requires_dist: Vec<String>,
    pub dynamic_build_requirements_possible: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactMetadata {
    pub npm: Option<NpmMetadata>,
    pub wheel: Option<WheelMetadata>,
    pub sdist: Option<SdistMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactManifestInput {
    pub artifact_sha256: Sha256Digest,
    pub magic_detected_format: ArtifactFormat,
    pub canonical_package_root: String,
    pub identity: Option<PackageIdentity>,
    pub members: Vec<MemberRecord>,
    pub excluded_members: Vec<ExcludedMemberRecord>,
    pub issues: Vec<ManifestIssue>,
    pub anomalies: Vec<ArchiveAnomaly>,
    pub normalization_completeness: NormalizationCompleteness,
    pub metadata: ArtifactMetadata,
    pub executable_text_file_ids: Vec<Sha256Digest>,
    pub native_binary_file_ids: Vec<Sha256Digest>,
}

impl ArtifactManifestInput {
    pub fn new(
        artifact_sha256: Sha256Digest,
        magic_detected_format: ArtifactFormat,
        canonical_package_root: String,
        identity: Option<PackageIdentity>,
    ) -> Self {
        Self {
            artifact_sha256,
            magic_detected_format,
            canonical_package_root,
            identity,
            members: Vec::new(),
            excluded_members: Vec::new(),
            issues: Vec::new(),
            anomalies: Vec::new(),
            normalization_completeness: NormalizationCompleteness::Complete,
            metadata: ArtifactMetadata::default(),
            executable_text_file_ids: Vec::new(),
            native_binary_file_ids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ArtifactManifest {
    pub schema_version: String,
    pub canonicalization_version: String,
    pub artifact_sha256: Sha256Digest,
    pub manifest_sha256: Sha256Digest,
    pub magic_detected_format: ArtifactFormat,
    pub canonical_package_root: String,
    pub identity: Option<PackageIdentity>,
    pub members: Vec<MemberRecord>,
    pub total_member_count: u64,
    pub total_expanded_size: u64,
    pub excluded_members: Vec<ExcludedMemberRecord>,
    pub issues: Vec<ManifestIssue>,
    pub anomalies: Vec<ArchiveAnomaly>,
    pub normalization_completeness: NormalizationCompleteness,
    pub metadata: ArtifactMetadata,
    pub executable_text_file_ids: Vec<Sha256Digest>,
    pub native_binary_file_ids: Vec<Sha256Digest>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactManifestWire {
    schema_version: String,
    canonicalization_version: String,
    artifact_sha256: Sha256Digest,
    manifest_sha256: Sha256Digest,
    magic_detected_format: ArtifactFormat,
    canonical_package_root: String,
    identity: Option<PackageIdentity>,
    members: Vec<MemberRecord>,
    total_member_count: u64,
    total_expanded_size: u64,
    excluded_members: Vec<ExcludedMemberRecord>,
    issues: Vec<ManifestIssue>,
    anomalies: Vec<ArchiveAnomaly>,
    normalization_completeness: NormalizationCompleteness,
    metadata: ArtifactMetadata,
    executable_text_file_ids: Vec<Sha256Digest>,
    native_binary_file_ids: Vec<Sha256Digest>,
}

impl<'de> Deserialize<'de> for ArtifactManifest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ArtifactManifestWire::deserialize(deserializer)?;
        let manifest = Self {
            schema_version: wire.schema_version,
            canonicalization_version: wire.canonicalization_version,
            artifact_sha256: wire.artifact_sha256,
            manifest_sha256: wire.manifest_sha256,
            magic_detected_format: wire.magic_detected_format,
            canonical_package_root: wire.canonical_package_root,
            identity: wire.identity,
            members: wire.members,
            total_member_count: wire.total_member_count,
            total_expanded_size: wire.total_expanded_size,
            excluded_members: wire.excluded_members,
            issues: wire.issues,
            anomalies: wire.anomalies,
            normalization_completeness: wire.normalization_completeness,
            metadata: wire.metadata,
            executable_text_file_ids: wire.executable_text_file_ids,
            native_binary_file_ids: wire.native_binary_file_ids,
        };
        manifest.validate().map_err(serde::de::Error::custom)?;
        Ok(manifest)
    }
}

#[derive(Serialize)]
struct CanonicalManifest<'a> {
    schema_version: &'a str,
    canonicalization_version: &'a str,
    artifact_sha256: &'a Sha256Digest,
    magic_detected_format: ArtifactFormat,
    canonical_package_root: &'a str,
    identity: &'a Option<PackageIdentity>,
    members: &'a [MemberRecord],
    total_member_count: u64,
    total_expanded_size: u64,
    excluded_members: &'a [ExcludedMemberRecord],
    issues: &'a [ManifestIssue],
    anomalies: &'a [ArchiveAnomaly],
    normalization_completeness: NormalizationCompleteness,
    metadata: &'a ArtifactMetadata,
    executable_text_file_ids: &'a [Sha256Digest],
    native_binary_file_ids: &'a [Sha256Digest],
}

impl ArtifactManifest {
    pub fn new(mut input: ArtifactManifestInput) -> Result<Self, ArtifactModelError> {
        canonicalize_input(&mut input);
        let total_member_count = input.members.len() as u64;
        let total_expanded_size = input
            .members
            .iter()
            .try_fold(0u64, |total, member| total.checked_add(member.size));
        let total_expanded_size =
            total_expanded_size.ok_or(ArtifactModelError::ExpandedSizeOverflow)?;
        let mut manifest = Self {
            schema_version: ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
            canonicalization_version: ARTIFACT_MANIFEST_CANONICALIZATION_VERSION.to_string(),
            artifact_sha256: input.artifact_sha256,
            manifest_sha256: Sha256Digest::from_bytes(&[]),
            magic_detected_format: input.magic_detected_format,
            canonical_package_root: input.canonical_package_root,
            identity: input.identity,
            members: input.members,
            total_member_count,
            total_expanded_size,
            excluded_members: input.excluded_members,
            issues: input.issues,
            anomalies: input.anomalies,
            normalization_completeness: input.normalization_completeness,
            metadata: input.metadata,
            executable_text_file_ids: input.executable_text_file_ids,
            native_binary_file_ids: input.native_binary_file_ids,
        };
        manifest.refresh_manifest_sha256()?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn canonical_payload(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&CanonicalManifest {
            schema_version: &self.schema_version,
            canonicalization_version: &self.canonicalization_version,
            artifact_sha256: &self.artifact_sha256,
            magic_detected_format: self.magic_detected_format,
            canonical_package_root: &self.canonical_package_root,
            identity: &self.identity,
            members: &self.members,
            total_member_count: self.total_member_count,
            total_expanded_size: self.total_expanded_size,
            excluded_members: &self.excluded_members,
            issues: &self.issues,
            anomalies: &self.anomalies,
            normalization_completeness: self.normalization_completeness,
            metadata: &self.metadata,
            executable_text_file_ids: &self.executable_text_file_ids,
            native_binary_file_ids: &self.native_binary_file_ids,
        })
    }

    pub fn recompute_manifest_sha256(&self) -> Result<Sha256Digest, serde_json::Error> {
        self.canonical_payload()
            .map(|payload| Sha256Digest::from_bytes(&payload))
    }

    fn refresh_manifest_sha256(&mut self) -> Result<(), serde_json::Error> {
        self.manifest_sha256 = self.recompute_manifest_sha256()?;
        Ok(())
    }

    pub fn verify_manifest_sha256(&self) -> Result<bool, serde_json::Error> {
        self.recompute_manifest_sha256()
            .map(|computed| computed == self.manifest_sha256)
    }

    pub fn validate(&self) -> Result<(), ArtifactModelError> {
        if self.schema_version != ARTIFACT_MANIFEST_SCHEMA_VERSION
            || self.canonicalization_version != ARTIFACT_MANIFEST_CANONICALIZATION_VERSION
        {
            return Err(ArtifactModelError::InvalidContract(
                "unsupported artifact manifest schema or canonicalization version".to_string(),
            ));
        }
        if self.total_member_count != self.members.len() as u64 {
            return Err(ArtifactModelError::InvalidContract(
                "manifest member count does not match members".to_string(),
            ));
        }
        let total = self
            .members
            .iter()
            .try_fold(0u64, |sum, member| sum.checked_add(member.size));
        if total.ok_or(ArtifactModelError::ExpandedSizeOverflow)? != self.total_expanded_size {
            return Err(ArtifactModelError::InvalidContract(
                "manifest expanded size does not match members".to_string(),
            ));
        }
        if self.members.windows(2).any(|pair| {
            pair[0]
                .normalized_path
                .cmp(&pair[1].normalized_path)
                .then_with(|| pair[0].original_path.cmp(&pair[1].original_path))
                .is_ge()
        }) {
            return Err(ArtifactModelError::InvalidContract(
                "manifest members are duplicated or not canonically ordered".to_string(),
            ));
        }
        let mut file_ids = BTreeSet::new();
        for member in &self.members {
            let expected = MemberRecord::compute_file_id(
                &self.artifact_sha256,
                &member.normalized_path,
                member.member_type,
                &member.sha256,
            );
            if member.file_id != expected || !file_ids.insert(member.file_id.clone()) {
                return Err(ArtifactModelError::InvalidContract(
                    "manifest contains an invalid or duplicate file id".to_string(),
                ));
            }
        }
        for file_id in self
            .executable_text_file_ids
            .iter()
            .chain(&self.native_binary_file_ids)
        {
            if !file_ids.contains(file_id) {
                return Err(ArtifactModelError::InvalidContract(
                    "manifest inventory references an unknown file id".to_string(),
                ));
            }
        }
        let identity = self.identity.as_ref().ok_or_else(|| {
            ArtifactModelError::InvalidContract("manifest package identity is missing".to_string())
        })?;
        let metadata_valid = match self.magic_detected_format {
            ArtifactFormat::NpmTarGzip => {
                identity.ecosystem == Ecosystem::Npm
                    && self.metadata.npm.is_some()
                    && self.metadata.wheel.is_none()
                    && self.metadata.sdist.is_none()
            }
            ArtifactFormat::WheelZip => {
                identity.ecosystem == Ecosystem::Pypi
                    && self.metadata.npm.is_none()
                    && self.metadata.wheel.is_some()
                    && self.metadata.sdist.is_none()
            }
            ArtifactFormat::SdistTarGzip | ArtifactFormat::SdistZip => {
                identity.ecosystem == Ecosystem::Pypi
                    && self.metadata.npm.is_none()
                    && self.metadata.wheel.is_none()
                    && self.metadata.sdist.is_some()
            }
            ArtifactFormat::Unknown => false,
        };
        if !metadata_valid {
            return Err(ArtifactModelError::InvalidContract(
                "manifest format, ecosystem, identity, and metadata disagree".to_string(),
            ));
        }
        for metadata_file_id in self.metadata_file_ids() {
            if !file_ids.contains(metadata_file_id) {
                return Err(ArtifactModelError::InvalidContract(
                    "manifest metadata references an unknown file id".to_string(),
                ));
            }
        }
        if !self.verify_manifest_sha256()? {
            return Err(ArtifactModelError::InvalidContract(
                "manifest digest does not match its canonical payload".to_string(),
            ));
        }
        Ok(())
    }

    fn metadata_file_ids(&self) -> Vec<&Sha256Digest> {
        let mut values = Vec::new();
        if let Some(npm) = &self.metadata.npm {
            values.extend(npm.package_json_file_id.iter());
        }
        if let Some(wheel) = &self.metadata.wheel {
            values.extend(wheel.metadata_file_id.iter());
            values.extend(wheel.wheel_file_id.iter());
            values.extend(wheel.record_file_id.iter());
            values.extend(wheel.entry_points_file_id.iter());
            values.extend(wheel.pth_file_ids.iter());
            values.extend(wheel.script_file_ids.iter());
        }
        if let Some(sdist) = &self.metadata.sdist {
            values.extend(sdist.pkg_info_file_id.iter());
            values.extend(sdist.pyproject_file_id.iter());
            values.extend(sdist.setup_py_file_id.iter());
            values.extend(sdist.setup_cfg_file_id.iter());
        }
        values
    }
}

/// Exact normalized file content retained for deterministic and AI scanners.
///
/// This type intentionally does not implement `Serialize`, preventing source
/// bytes from being included accidentally in normal evidence envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedMemberContent {
    pub file_id: Sha256Digest,
    pub normalized_path: String,
    pub sha256: Sha256Digest,
    bytes: Vec<u8>,
}

impl NormalizedMemberContent {
    pub(crate) fn from_record(record: &MemberRecord, bytes: &[u8]) -> Self {
        Self {
            file_id: record.file_id.clone(),
            normalized_path: record.normalized_path.clone(),
            sha256: record.sha256.clone(),
            bytes: bytes.to_vec(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A manifest and its immutable-in-memory normalized file view from one parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedArtifact {
    pub manifest: ArtifactManifest,
    contents: BTreeMap<Sha256Digest, NormalizedMemberContent>,
}

impl NormalizedArtifact {
    pub(crate) fn from_parts(
        manifest: ArtifactManifest,
        contents: BTreeMap<Sha256Digest, NormalizedMemberContent>,
    ) -> Result<Self, ArtifactModelError> {
        let artifact = Self { manifest, contents };
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn file(&self, file_id: &Sha256Digest) -> Option<&NormalizedMemberContent> {
        self.contents.get(file_id)
    }

    pub fn files(&self) -> impl Iterator<Item = &NormalizedMemberContent> {
        self.contents.values()
    }

    pub fn into_manifest(self) -> ArtifactManifest {
        self.manifest
    }

    pub fn validate(&self) -> Result<(), ArtifactModelError> {
        self.manifest.validate()?;
        let expected = self
            .manifest
            .members
            .iter()
            .filter(|member| member.member_type == MemberType::File)
            .map(|member| (member.file_id.clone(), member))
            .collect::<BTreeMap<_, _>>();
        if expected.len() != self.contents.len() {
            return Err(ArtifactModelError::InvalidContract(
                "normalized content set does not match manifest files".to_string(),
            ));
        }
        for (file_id, content) in &self.contents {
            let member = expected.get(file_id).ok_or_else(|| {
                ArtifactModelError::InvalidContract(
                    "normalized content references an unknown file id".to_string(),
                )
            })?;
            if content.file_id != *file_id
                || content.normalized_path != member.normalized_path
                || content.sha256 != member.sha256
                || content.bytes.len() as u64 != member.size
                || Sha256Digest::from_bytes(&content.bytes) != member.sha256
            {
                return Err(ArtifactModelError::InvalidContract(
                    "normalized content does not match its manifest member".to_string(),
                ));
            }
        }
        Ok(())
    }
}

impl Deref for NormalizedArtifact {
    type Target = ArtifactManifest;

    fn deref(&self) -> &Self::Target {
        &self.manifest
    }
}

fn canonicalize_input(input: &mut ArtifactManifestInput) {
    input.members.sort_by(|left, right| {
        left.normalized_path
            .cmp(&right.normalized_path)
            .then_with(|| left.original_path.cmp(&right.original_path))
    });
    input.excluded_members.sort_by(|left, right| {
        left.original_path
            .cmp(&right.original_path)
            .then_with(|| left.reason_code.cmp(&right.reason_code))
    });
    input.issues.sort_by(|left, right| {
        left.reason_code
            .cmp(&right.reason_code)
            .then_with(|| left.path.cmp(&right.path))
            .then_with(|| left.detail.cmp(&right.detail))
    });
    input.anomalies.sort_by(|left, right| {
        left.reason_code
            .cmp(&right.reason_code)
            .then_with(|| left.path.cmp(&right.path))
    });
    sort_dedup_digests(&mut input.executable_text_file_ids);
    sort_dedup_digests(&mut input.native_binary_file_ids);
    if let Some(npm) = input.metadata.npm.as_mut() {
        npm.export_targets.sort();
        npm.export_targets.dedup();
        npm.dependency_declarations.sort_by(|left, right| {
            left.group
                .cmp(&right.group)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.requirement.cmp(&right.requirement))
        });
        npm.dependency_declarations.dedup();
    }
    if let Some(wheel) = input.metadata.wheel.as_mut() {
        wheel.tags.sort();
        wheel.tags.dedup();
        wheel.import_roots.sort();
        wheel.import_roots.dedup();
        wheel.native_tags.sort();
        wheel.native_tags.dedup();
        wheel.requires_dist.sort();
        wheel.requires_dist.dedup();
        sort_dedup_digests(&mut wheel.pth_file_ids);
        sort_dedup_digests(&mut wheel.script_file_ids);
    }
    if let Some(sdist) = input.metadata.sdist.as_mut() {
        sdist.build_requires.sort();
        sdist.build_requires.dedup();
        sdist.backend_paths.sort();
        sdist.backend_paths.dedup();
        sdist.package_roots.sort();
        sdist.package_roots.dedup();
        sdist.requires_dist.sort();
        sdist.requires_dist.dedup();
    }
}

fn sort_dedup_digests(values: &mut Vec<Sha256Digest>) {
    values.sort();
    values.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ArtifactEnvelopeInput {
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("inert".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "npm:inert@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-09T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "inert-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "fixture:inert".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "test".to_string(),
            requires_external_dependency_resolution: false,
        }
    }

    #[test]
    fn sha256_digest_rejects_noncanonical_values() {
        assert!(Sha256Digest::parse("abc").is_err());
        assert!(Sha256Digest::parse(format!("sha256:{}", "A".repeat(64))).is_err());
        assert!(Sha256Digest::parse(format!("sha256:{}", "0".repeat(63))).is_err());
        assert_eq!(
            Sha256Digest::from_bytes(b"abc").as_str(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn envelope_identity_is_the_original_bytes() {
        let envelope = ArtifactEnvelope::from_original_bytes(
            input(),
            b"exact artifact bytes",
            ArtifactFormat::NpmTarGzip,
        );
        assert!(envelope.matches_original_bytes(b"exact artifact bytes"));
        assert!(!envelope.matches_original_bytes(b"changed artifact bytes"));
        assert!(envelope.verify_magic_format(ArtifactFormat::NpmTarGzip));

        let mut unknown_field = serde_json::to_value(&envelope).expect("serialize envelope");
        unknown_field
            .as_object_mut()
            .expect("envelope object")
            .insert("attacker_field".to_string(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<ArtifactEnvelope>(unknown_field).is_err());

        let mut forged_corroboration =
            serde_json::to_value(&envelope).expect("serialize envelope again");
        forged_corroboration
            .as_object_mut()
            .expect("envelope object")
            .insert(
                "format_corroboration".to_string(),
                serde_json::Value::String("declared_mismatch".to_string()),
            );
        assert!(serde_json::from_value::<ArtifactEnvelope>(forged_corroboration).is_err());
    }

    #[test]
    fn manifest_hash_excludes_itself_and_is_order_stable() {
        let artifact = Sha256Digest::from_bytes(b"artifact");
        let first = MemberRecord::from_bytes(
            &artifact,
            "a".to_string(),
            "root/a".to_string(),
            MemberType::File,
            Some(0o644),
            b"a",
        );
        let second = MemberRecord::from_bytes(
            &artifact,
            "b".to_string(),
            "root/b".to_string(),
            MemberType::File,
            Some(0o644),
            b"b",
        );
        let identity = PackageIdentity {
            ecosystem: Ecosystem::Npm,
            display_name: "inert".to_string(),
            normalized_name: "inert".to_string(),
            version: "1.0.0".to_string(),
        };
        let npm_metadata = NpmMetadata {
            package_json_file_id: Some(first.file_id.clone()),
            ..NpmMetadata::default()
        };
        let mut left = ArtifactManifestInput::new(
            artifact.clone(),
            ArtifactFormat::NpmTarGzip,
            "root".to_string(),
            Some(identity.clone()),
        );
        left.members = vec![second.clone(), first.clone()];
        left.metadata.npm = Some(npm_metadata.clone());
        let mut right = ArtifactManifestInput::new(
            artifact,
            ArtifactFormat::NpmTarGzip,
            "root".to_string(),
            Some(identity),
        );
        right.members = vec![first, second];
        right.metadata.npm = Some(npm_metadata);

        let left = ArtifactManifest::new(left).expect("left manifest");
        let mut right = ArtifactManifest::new(right).expect("right manifest");
        assert_eq!(
            left.manifest_sha256.as_str(),
            "sha256:e7dc1405ee5ea6310eb68b0c5b6e1ed5401f032e32f46ba5a6fa13d4a7fe03bf",
            "canonicalization changes require an explicit version bump and shared vectors"
        );
        assert_eq!(left.manifest_sha256, right.manifest_sha256);
        assert!(left.verify_manifest_sha256().expect("verify"));
        let round_trip = serde_json::to_vec(&left).expect("serialize manifest");
        assert_eq!(
            serde_json::from_slice::<ArtifactManifest>(&round_trip)
                .expect("strictly deserialize manifest"),
            left
        );
        let mut forged_schema = serde_json::to_value(&left).expect("manifest value");
        forged_schema
            .as_object_mut()
            .expect("manifest object")
            .insert(
                "schema_version".to_string(),
                serde_json::Value::String("attacker.schema.v9".to_string()),
            );
        assert!(serde_json::from_value::<ArtifactManifest>(forged_schema).is_err());
        let recomputed = right.recompute_manifest_sha256().expect("recompute");
        right.manifest_sha256 = Sha256Digest::from_bytes(b"tampered digest field");
        assert_eq!(
            right.recompute_manifest_sha256().expect("recompute again"),
            recomputed
        );
        assert!(!right
            .verify_manifest_sha256()
            .expect("verify after field change"));
    }
}
