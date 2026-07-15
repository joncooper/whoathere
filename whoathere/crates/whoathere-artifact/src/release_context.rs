use crate::{ArtifactModelError, Ecosystem, Sha256Digest};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;

pub const RELEASE_CONTEXT_SCHEMA_VERSION: &str = "whoathere.release_context.v1";
pub const RELEASE_CONTEXT_ASSESSMENT_SCHEMA_VERSION: &str =
    "whoathere.release_context_assessment.v1";

const MAX_PACKAGE_NAME_BYTES: usize = 512;
const MAX_COORDINATE_VALUE_BYTES: usize = 1_024;
const MAX_URL_BYTES: usize = 2_048;
const MAX_IDENTITY_VALUE_BYTES: usize = 2_048;
const MAX_ATTESTATIONS: usize = 64;
const MAX_DEPENDENCIES: usize = 4_096;

/// The package coordinate requested by the caller before registry resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestedPackageCoordinate {
    pub ecosystem: Ecosystem,
    pub package_name: String,
    pub requirement: String,
}

impl RequestedPackageCoordinate {
    fn validate(&self) -> Result<(), ArtifactModelError> {
        validate_text(
            "requested package name",
            &self.package_name,
            MAX_PACKAGE_NAME_BYTES,
        )?;
        validate_text(
            "requested package requirement",
            &self.requirement,
            MAX_COORDINATE_VALUE_BYTES,
        )
    }
}

/// The exact package coordinate selected by the resolver.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedPackageCoordinate {
    pub ecosystem: Ecosystem,
    pub package_name: String,
    pub version: String,
}

impl ResolvedPackageCoordinate {
    fn validate(&self) -> Result<(), ArtifactModelError> {
        validate_text(
            "resolved package name",
            &self.package_name,
            MAX_PACKAGE_NAME_BYTES,
        )?;
        validate_text(
            "resolved package version",
            &self.version,
            MAX_COORDINATE_VALUE_BYTES,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegistryOriginKind {
    NpmOfficial,
    PypiOfficial,
    Custom,
}

/// Registry identity and the digest of the metadata used to resolve this release.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryOrigin {
    pub kind: RegistryOriginKind,
    pub canonical_origin: String,
    pub metadata_sha256: Sha256Digest,
}

impl RegistryOrigin {
    fn validate_for(&self, ecosystem: Ecosystem) -> Result<(), ArtifactModelError> {
        validate_https_origin(&self.canonical_origin)?;
        match (self.kind, ecosystem) {
            (RegistryOriginKind::NpmOfficial, Ecosystem::Npm) => {
                if self.canonical_origin != "https://registry.npmjs.org" {
                    return invalid(
                        "official npm registry origin must be `https://registry.npmjs.org`",
                    );
                }
            }
            (RegistryOriginKind::PypiOfficial, Ecosystem::Pypi) => {
                if self.canonical_origin != "https://pypi.org" {
                    return invalid("official PyPI registry origin must be `https://pypi.org`");
                }
            }
            (RegistryOriginKind::Custom, _) => {}
            _ => {
                return invalid("registry origin kind does not match the package ecosystem");
            }
        }
        Ok(())
    }

    fn same_registry_as(&self, other: &Self) -> bool {
        self.kind == other.kind && self.canonical_origin == other.canonical_origin
    }
}

/// Inputs used to compute release age against a policy cooldown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseTiming {
    pub observed_at_unix_seconds: u64,
    pub published_at_unix_seconds: Option<u64>,
    pub cooldown_seconds: u64,
}

impl ReleaseTiming {
    pub fn publish_age_seconds(&self) -> Option<u64> {
        self.published_at_unix_seconds
            .and_then(|published| self.observed_at_unix_seconds.checked_sub(published))
    }

    pub fn cooldown_active(&self) -> Option<bool> {
        self.publish_age_seconds()
            .map(|age| age < self.cooldown_seconds)
    }

    fn validate(&self) -> Result<(), ArtifactModelError> {
        if self.observed_at_unix_seconds == 0 {
            return invalid("release context observation time must be non-zero");
        }
        if let Some(published) = self.published_at_unix_seconds {
            if published == 0 {
                return invalid("registry publication time must be non-zero when present");
            }
            if published > self.observed_at_unix_seconds {
                return invalid("registry publication time is after the observation time");
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublisherIdentityKind {
    NpmAccount,
    PypiAccount,
    OidcSubject,
    Other,
}

/// Stable publisher identity, separate from mutable display metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublisherIdentity {
    pub kind: PublisherIdentityKind,
    pub stable_id: String,
    pub display_name: Option<String>,
}

impl PublisherIdentity {
    fn validate_for(&self, ecosystem: Ecosystem) -> Result<(), ArtifactModelError> {
        validate_text(
            "publisher stable identity",
            &self.stable_id,
            MAX_IDENTITY_VALUE_BYTES,
        )?;
        if let Some(display_name) = &self.display_name {
            validate_text(
                "publisher display name",
                display_name,
                MAX_IDENTITY_VALUE_BYTES,
            )?;
        }
        if matches!(
            (self.kind, ecosystem),
            (PublisherIdentityKind::NpmAccount, Ecosystem::Pypi)
                | (PublisherIdentityKind::PypiAccount, Ecosystem::Npm)
        ) {
            return invalid("publisher identity kind does not match the package ecosystem");
        }
        Ok(())
    }

    fn same_principal_as(&self, other: &Self) -> bool {
        self.kind == other.kind && self.stable_id == other.stable_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkflowProvider {
    GithubActions,
    GitlabCi,
    Other,
}

/// Stable release-workflow identity. All fields participate in continuity checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseWorkflowIdentity {
    pub provider: WorkflowProvider,
    pub repository: String,
    pub workflow_ref: String,
    pub issuer: String,
    pub subject: String,
}

impl ReleaseWorkflowIdentity {
    fn validate(&self) -> Result<(), ArtifactModelError> {
        validate_text(
            "workflow repository",
            &self.repository,
            MAX_IDENTITY_VALUE_BYTES,
        )?;
        validate_text(
            "workflow reference",
            &self.workflow_ref,
            MAX_IDENTITY_VALUE_BYTES,
        )?;
        validate_text("workflow issuer", &self.issuer, MAX_IDENTITY_VALUE_BYTES)?;
        validate_text("workflow subject", &self.subject, MAX_IDENTITY_VALUE_BYTES)
    }

    fn same_workflow_as(&self, other: &Self) -> bool {
        self.provider == other.provider
            && self.repository == other.repository
            && self.workflow_ref == other.workflow_ref
            && self.issuer == other.issuer
            && self.subject == other.subject
    }
}

/// Immutable source reference claimed for a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceReference {
    pub repository_url: String,
    pub revision: String,
    pub subdirectory: Option<String>,
}

impl SourceReference {
    fn validate(&self) -> Result<(), ArtifactModelError> {
        validate_https_url("source repository URL", &self.repository_url)?;
        validate_text("source revision", &self.revision, MAX_IDENTITY_VALUE_BYTES)?;
        if let Some(subdirectory) = &self.subdirectory {
            validate_text(
                "source subdirectory",
                subdirectory,
                MAX_IDENTITY_VALUE_BYTES,
            )?;
            if subdirectory.starts_with('/')
                || subdirectory.ends_with('/')
                || subdirectory.contains('\\')
                || subdirectory
                    .split('/')
                    .any(|part| part.is_empty() || part == "." || part == "..")
            {
                return invalid("source subdirectory must be a normalized relative path");
            }
        }
        Ok(())
    }
}

/// A previous exact release used only for continuity and difference context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PriorRelease {
    pub coordinate: ResolvedPackageCoordinate,
    pub artifact_sha256: Sha256Digest,
    pub registry_origin: RegistryOrigin,
    pub source_reference: Option<SourceReference>,
    pub publisher_identity: Option<PublisherIdentity>,
    pub workflow_identity: Option<ReleaseWorkflowIdentity>,
}

impl PriorRelease {
    fn validate_for(
        &self,
        current_coordinate: &ResolvedPackageCoordinate,
        current_artifact_sha256: &Sha256Digest,
    ) -> Result<(), ArtifactModelError> {
        self.coordinate.validate()?;
        if self.coordinate.ecosystem != current_coordinate.ecosystem
            || self.coordinate.package_name != current_coordinate.package_name
        {
            return invalid("prior release must identify the same package as the current release");
        }
        if self.coordinate.version == current_coordinate.version {
            return invalid("prior release version must differ from the current release version");
        }
        if &self.artifact_sha256 == current_artifact_sha256 {
            return invalid("prior and current releases must not share the same artifact digest");
        }
        self.registry_origin
            .validate_for(current_coordinate.ecosystem)?;
        if let Some(source_reference) = &self.source_reference {
            source_reference.validate()?;
        }
        if let Some(publisher) = &self.publisher_identity {
            publisher.validate_for(current_coordinate.ecosystem)?;
        }
        if let Some(workflow) = &self.workflow_identity {
            workflow.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationKind {
    RegistryProvenance,
    SlsaProvenance,
    SigstoreBundle,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationVerification {
    Verified,
    Invalid,
    Unverified,
    Unsupported,
}

/// A verification result bound to a particular attestation statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseAttestation {
    pub kind: AttestationKind,
    pub verification: AttestationVerification,
    pub statement_sha256: Sha256Digest,
    pub subject_sha256: Sha256Digest,
    pub issuer: Option<String>,
    pub predicate_type: Option<String>,
}

impl ReleaseAttestation {
    fn validate_for(&self, artifact_sha256: &Sha256Digest) -> Result<(), ArtifactModelError> {
        if let Some(issuer) = &self.issuer {
            validate_text("attestation issuer", issuer, MAX_IDENTITY_VALUE_BYTES)?;
        }
        if let Some(predicate_type) = &self.predicate_type {
            validate_text(
                "attestation predicate type",
                predicate_type,
                MAX_IDENTITY_VALUE_BYTES,
            )?;
        }
        if self.verification == AttestationVerification::Verified {
            if &self.subject_sha256 != artifact_sha256 {
                return invalid("verified attestation subject does not match the current artifact");
            }
            if self.issuer.is_none() || self.predicate_type.is_none() {
                return invalid(
                    "verified attestation must identify both its issuer and predicate type",
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyArtifact {
    pub coordinate: ResolvedPackageCoordinate,
    pub artifact_sha256: Sha256Digest,
    pub registry_origin: RegistryOrigin,
}

impl DependencyArtifact {
    fn validate_for(&self, ecosystem: Ecosystem) -> Result<(), ArtifactModelError> {
        self.coordinate.validate()?;
        if self.coordinate.ecosystem != ecosystem {
            return invalid("dependency ecosystem must match the root package ecosystem");
        }
        self.registry_origin.validate_for(ecosystem)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyClosureStatus {
    Complete,
    Incomplete,
    Unavailable,
    NotRequired,
}

/// Exact artifacts observed while resolving the package's dependency closure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyClosureContext {
    pub status: DependencyClosureStatus,
    pub closure_sha256: Option<Sha256Digest>,
    pub artifacts: Vec<DependencyArtifact>,
}

impl DependencyClosureContext {
    fn canonicalize(&mut self) {
        self.artifacts.sort();
    }

    fn validate_for(&self, ecosystem: Ecosystem) -> Result<(), ArtifactModelError> {
        if self.artifacts.len() > MAX_DEPENDENCIES {
            return invalid("dependency closure exceeds the artifact-count limit");
        }
        match self.status {
            DependencyClosureStatus::Complete if self.closure_sha256.is_none() => {
                return invalid("complete dependency closure lacks a closure digest");
            }
            DependencyClosureStatus::Incomplete if self.closure_sha256.is_some() => {
                return invalid("incomplete dependency closure must not claim a closure digest");
            }
            DependencyClosureStatus::Unavailable | DependencyClosureStatus::NotRequired
                if self.closure_sha256.is_some() || !self.artifacts.is_empty() =>
            {
                return invalid(
                    "unavailable or unnecessary dependency closure must not contain artifacts or a digest",
                );
            }
            _ => {}
        }

        let mut previous: Option<&DependencyArtifact> = None;
        for artifact in &self.artifacts {
            artifact.validate_for(ecosystem)?;
            if previous.is_some_and(|value| value.coordinate == artifact.coordinate) {
                return invalid(
                    "dependency closure must identify exactly one artifact per coordinate",
                );
            }
            if previous.is_some_and(|value| value >= artifact) {
                return invalid(
                    "dependency closure artifacts must be unique and canonically ordered",
                );
            }
            previous = Some(artifact);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceArtifactComparisonStatus {
    VerifiedMatch,
    Mismatch,
    Inconclusive,
    NotPerformed,
    SourceUnavailable,
}

/// Posture of a source-tree to published-artifact comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceArtifactComparison {
    pub status: SourceArtifactComparisonStatus,
    pub source_reference: Option<SourceReference>,
    pub source_snapshot_sha256: Option<Sha256Digest>,
    pub evidence_sha256: Option<Sha256Digest>,
}

impl SourceArtifactComparison {
    fn validate(&self) -> Result<(), ArtifactModelError> {
        if let Some(source_reference) = &self.source_reference {
            source_reference.validate()?;
        }
        match self.status {
            SourceArtifactComparisonStatus::VerifiedMatch
            | SourceArtifactComparisonStatus::Mismatch => {
                if self.source_reference.is_none()
                    || self.source_snapshot_sha256.is_none()
                    || self.evidence_sha256.is_none()
                {
                    return invalid(
                        "conclusive source comparison requires a source reference, snapshot digest, and evidence digest",
                    );
                }
            }
            SourceArtifactComparisonStatus::Inconclusive => {
                if self.source_reference.is_none() || self.evidence_sha256.is_none() {
                    return invalid(
                        "inconclusive source comparison requires a source reference and evidence digest",
                    );
                }
            }
            SourceArtifactComparisonStatus::NotPerformed => {
                if self.source_snapshot_sha256.is_some() || self.evidence_sha256.is_some() {
                    return invalid(
                        "unperformed source comparison must not claim comparison evidence",
                    );
                }
            }
            SourceArtifactComparisonStatus::SourceUnavailable => {
                if self.source_reference.is_some()
                    || self.source_snapshot_sha256.is_some()
                    || self.evidence_sha256.is_some()
                {
                    return invalid(
                        "unavailable source comparison must not claim source or comparison evidence",
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseContextInput {
    pub artifact_sha256: Sha256Digest,
    pub requested: RequestedPackageCoordinate,
    pub resolved: ResolvedPackageCoordinate,
    pub registry_origin: RegistryOrigin,
    pub timing: ReleaseTiming,
    pub prior_release: Option<PriorRelease>,
    pub publisher_identity: Option<PublisherIdentity>,
    pub workflow_identity: Option<ReleaseWorkflowIdentity>,
    pub attestations: Vec<ReleaseAttestation>,
    pub dependency_closure: DependencyClosureContext,
    pub source_comparison: SourceArtifactComparison,
}

/// Registry and release metadata bound to an exact artifact.
///
/// This context is deliberately non-authorizing: it can add information or
/// escalate review, but it cannot waive artifact scanning or establish a
/// behavior-specific malware detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseContext {
    pub schema_version: String,
    pub artifact_sha256: Sha256Digest,
    pub requested: RequestedPackageCoordinate,
    pub resolved: ResolvedPackageCoordinate,
    pub registry_origin: RegistryOrigin,
    pub timing: ReleaseTiming,
    pub prior_release: Option<PriorRelease>,
    pub publisher_identity: Option<PublisherIdentity>,
    pub workflow_identity: Option<ReleaseWorkflowIdentity>,
    pub attestations: Vec<ReleaseAttestation>,
    pub dependency_closure: DependencyClosureContext,
    pub source_comparison: SourceArtifactComparison,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseContextWire {
    schema_version: String,
    artifact_sha256: Sha256Digest,
    requested: RequestedPackageCoordinate,
    resolved: ResolvedPackageCoordinate,
    registry_origin: RegistryOrigin,
    timing: ReleaseTiming,
    prior_release: Option<PriorRelease>,
    publisher_identity: Option<PublisherIdentity>,
    workflow_identity: Option<ReleaseWorkflowIdentity>,
    attestations: Vec<ReleaseAttestation>,
    dependency_closure: DependencyClosureContext,
    source_comparison: SourceArtifactComparison,
}

impl<'de> Deserialize<'de> for ReleaseContext {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReleaseContextWire::deserialize(deserializer)?;
        let context = Self {
            schema_version: wire.schema_version,
            artifact_sha256: wire.artifact_sha256,
            requested: wire.requested,
            resolved: wire.resolved,
            registry_origin: wire.registry_origin,
            timing: wire.timing,
            prior_release: wire.prior_release,
            publisher_identity: wire.publisher_identity,
            workflow_identity: wire.workflow_identity,
            attestations: wire.attestations,
            dependency_closure: wire.dependency_closure,
            source_comparison: wire.source_comparison,
        };
        context.validate().map_err(serde::de::Error::custom)?;
        Ok(context)
    }
}

impl ReleaseContext {
    pub fn new(mut input: ReleaseContextInput) -> Result<Self, ArtifactModelError> {
        input
            .attestations
            .sort_by(|left, right| left.statement_sha256.cmp(&right.statement_sha256));
        input.dependency_closure.canonicalize();
        let context = Self {
            schema_version: RELEASE_CONTEXT_SCHEMA_VERSION.to_string(),
            artifact_sha256: input.artifact_sha256,
            requested: input.requested,
            resolved: input.resolved,
            registry_origin: input.registry_origin,
            timing: input.timing,
            prior_release: input.prior_release,
            publisher_identity: input.publisher_identity,
            workflow_identity: input.workflow_identity,
            attestations: input.attestations,
            dependency_closure: input.dependency_closure,
            source_comparison: input.source_comparison,
        };
        context.validate()?;
        Ok(context)
    }

    pub fn validate(&self) -> Result<(), ArtifactModelError> {
        if self.schema_version != RELEASE_CONTEXT_SCHEMA_VERSION {
            return invalid("unsupported release context schema version");
        }
        self.requested.validate()?;
        self.resolved.validate()?;
        if self.requested.ecosystem != self.resolved.ecosystem
            || self.requested.package_name != self.resolved.package_name
        {
            return invalid("requested and resolved package coordinates disagree");
        }
        self.registry_origin.validate_for(self.resolved.ecosystem)?;
        self.timing.validate()?;
        if let Some(prior_release) = &self.prior_release {
            prior_release.validate_for(&self.resolved, &self.artifact_sha256)?;
        }
        if let Some(publisher) = &self.publisher_identity {
            publisher.validate_for(self.resolved.ecosystem)?;
        }
        if let Some(workflow) = &self.workflow_identity {
            workflow.validate()?;
        }
        if self.attestations.len() > MAX_ATTESTATIONS {
            return invalid("release context exceeds the attestation-count limit");
        }
        let mut previous_attestation: Option<&Sha256Digest> = None;
        for attestation in &self.attestations {
            attestation.validate_for(&self.artifact_sha256)?;
            if previous_attestation.is_some_and(|value| value >= &attestation.statement_sha256) {
                return invalid("attestations must be unique and canonically ordered");
            }
            previous_attestation = Some(&attestation.statement_sha256);
        }
        self.dependency_closure
            .validate_for(self.resolved.ecosystem)?;
        self.source_comparison.validate()?;
        Ok(())
    }

    pub fn assess(&self) -> Result<ReleaseContextAssessment, ArtifactModelError> {
        self.validate()?;
        let mut signals = BTreeSet::from([
            ReleaseContextSignal::ArtifactScanningRequired,
            ReleaseContextSignal::CoordinateResolved,
        ]);

        match self.timing.cooldown_active() {
            Some(true) => {
                signals.insert(ReleaseContextSignal::FreshReleaseCooldownActive);
            }
            Some(false) => {
                signals.insert(ReleaseContextSignal::FreshReleaseCooldownSatisfied);
            }
            None => {
                signals.insert(ReleaseContextSignal::PublishAgeUnavailable);
            }
        }

        match &self.prior_release {
            None => {
                signals.insert(ReleaseContextSignal::PriorReleaseUnavailable);
            }
            Some(prior) => {
                if self
                    .registry_origin
                    .same_registry_as(&prior.registry_origin)
                {
                    signals.insert(ReleaseContextSignal::RegistryOriginContinuous);
                } else {
                    signals.insert(ReleaseContextSignal::RegistryOriginChanged);
                }
                add_publisher_signals(
                    &mut signals,
                    self.publisher_identity.as_ref(),
                    prior.publisher_identity.as_ref(),
                );
                add_workflow_signals(
                    &mut signals,
                    self.workflow_identity.as_ref(),
                    prior.workflow_identity.as_ref(),
                );
            }
        }
        if self.prior_release.is_none() {
            if self.publisher_identity.is_none() {
                signals.insert(ReleaseContextSignal::PublisherIdentityUnavailable);
            } else {
                signals.insert(ReleaseContextSignal::PublisherIdentityBaselineUnavailable);
            }
            if self.workflow_identity.is_none() {
                signals.insert(ReleaseContextSignal::WorkflowIdentityUnavailable);
            } else {
                signals.insert(ReleaseContextSignal::WorkflowIdentityBaselineUnavailable);
            }
        }

        if self.attestations.is_empty() {
            signals.insert(ReleaseContextSignal::AttestationUnavailable);
        } else {
            for attestation in &self.attestations {
                signals.insert(match attestation.verification {
                    AttestationVerification::Verified => {
                        ReleaseContextSignal::VerifiedAttestationPresent
                    }
                    AttestationVerification::Invalid => {
                        ReleaseContextSignal::InvalidAttestationPresent
                    }
                    AttestationVerification::Unverified | AttestationVerification::Unsupported => {
                        ReleaseContextSignal::UnverifiedAttestationPresent
                    }
                });
            }
        }

        signals.insert(match self.dependency_closure.status {
            DependencyClosureStatus::Complete => ReleaseContextSignal::DependencyClosureComplete,
            DependencyClosureStatus::Incomplete => {
                ReleaseContextSignal::DependencyClosureIncomplete
            }
            DependencyClosureStatus::Unavailable => {
                ReleaseContextSignal::DependencyClosureUnavailable
            }
            DependencyClosureStatus::NotRequired => {
                ReleaseContextSignal::DependencyClosureNotRequired
            }
        });
        signals.insert(match self.source_comparison.status {
            SourceArtifactComparisonStatus::VerifiedMatch => {
                ReleaseContextSignal::SourceArtifactVerifiedMatch
            }
            SourceArtifactComparisonStatus::Mismatch => {
                ReleaseContextSignal::SourceArtifactMismatch
            }
            SourceArtifactComparisonStatus::Inconclusive => {
                ReleaseContextSignal::SourceArtifactComparisonInconclusive
            }
            SourceArtifactComparisonStatus::NotPerformed => {
                ReleaseContextSignal::SourceArtifactComparisonNotPerformed
            }
            SourceArtifactComparisonStatus::SourceUnavailable => {
                ReleaseContextSignal::SourceUnavailable
            }
        });

        ReleaseContextAssessment::from_signals(self.artifact_sha256.clone(), signals)
    }
}

fn add_publisher_signals(
    signals: &mut BTreeSet<ReleaseContextSignal>,
    current: Option<&PublisherIdentity>,
    prior: Option<&PublisherIdentity>,
) {
    signals.insert(match (current, prior) {
        (Some(current), Some(prior)) if current.same_principal_as(prior) => {
            ReleaseContextSignal::PublisherIdentityContinuous
        }
        (Some(_), Some(_)) => ReleaseContextSignal::PublisherIdentityChanged,
        (Some(_), None) => ReleaseContextSignal::PublisherIdentityBaselineUnavailable,
        (None, Some(_)) => ReleaseContextSignal::PublisherIdentityUnavailable,
        (None, None) => ReleaseContextSignal::PublisherIdentityUnavailable,
    });
}

fn add_workflow_signals(
    signals: &mut BTreeSet<ReleaseContextSignal>,
    current: Option<&ReleaseWorkflowIdentity>,
    prior: Option<&ReleaseWorkflowIdentity>,
) {
    signals.insert(match (current, prior) {
        (Some(current), Some(prior)) if current.same_workflow_as(prior) => {
            ReleaseContextSignal::WorkflowIdentityContinuous
        }
        (Some(_), Some(_)) | (None, Some(_)) => ReleaseContextSignal::WorkflowIdentityChanged,
        (Some(_), None) => ReleaseContextSignal::WorkflowIdentityBaselineUnavailable,
        (None, None) => ReleaseContextSignal::WorkflowIdentityUnavailable,
    });
}

/// Release-context outcomes intentionally exclude allow and malicious verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseContextDisposition {
    Informational,
    ManualReview,
    Suspicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseContextSignal {
    ArtifactScanningRequired,
    CoordinateResolved,
    FreshReleaseCooldownSatisfied,
    FreshReleaseCooldownActive,
    PublishAgeUnavailable,
    PriorReleaseUnavailable,
    RegistryOriginContinuous,
    RegistryOriginChanged,
    PublisherIdentityContinuous,
    PublisherIdentityChanged,
    PublisherIdentityUnavailable,
    PublisherIdentityBaselineUnavailable,
    WorkflowIdentityContinuous,
    WorkflowIdentityChanged,
    WorkflowIdentityUnavailable,
    WorkflowIdentityBaselineUnavailable,
    VerifiedAttestationPresent,
    InvalidAttestationPresent,
    UnverifiedAttestationPresent,
    AttestationUnavailable,
    DependencyClosureComplete,
    DependencyClosureIncomplete,
    DependencyClosureUnavailable,
    DependencyClosureNotRequired,
    SourceArtifactVerifiedMatch,
    SourceArtifactMismatch,
    SourceArtifactComparisonInconclusive,
    SourceArtifactComparisonNotPerformed,
    SourceUnavailable,
}

impl ReleaseContextSignal {
    pub fn disposition(self) -> ReleaseContextDisposition {
        match self {
            Self::RegistryOriginChanged
            | Self::PublisherIdentityChanged
            | Self::WorkflowIdentityChanged
            | Self::InvalidAttestationPresent
            | Self::SourceArtifactMismatch => ReleaseContextDisposition::Suspicious,
            Self::FreshReleaseCooldownActive
            | Self::PublishAgeUnavailable
            | Self::PublisherIdentityUnavailable
            | Self::UnverifiedAttestationPresent
            | Self::DependencyClosureIncomplete
            | Self::DependencyClosureUnavailable
            | Self::SourceArtifactComparisonInconclusive
            | Self::SourceArtifactComparisonNotPerformed
            | Self::SourceUnavailable => ReleaseContextDisposition::ManualReview,
            _ => ReleaseContextDisposition::Informational,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseContextObservation {
    pub signal: ReleaseContextSignal,
    pub disposition: ReleaseContextDisposition,
}

/// A non-authorizing assessment of registry and release context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseContextAssessment {
    pub schema_version: String,
    pub artifact_sha256: Sha256Digest,
    pub disposition: ReleaseContextDisposition,
    pub artifact_scanning_required: bool,
    pub observations: Vec<ReleaseContextObservation>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReleaseContextAssessmentWire {
    schema_version: String,
    artifact_sha256: Sha256Digest,
    disposition: ReleaseContextDisposition,
    artifact_scanning_required: bool,
    observations: Vec<ReleaseContextObservation>,
}

impl<'de> Deserialize<'de> for ReleaseContextAssessment {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ReleaseContextAssessmentWire::deserialize(deserializer)?;
        let assessment = Self {
            schema_version: wire.schema_version,
            artifact_sha256: wire.artifact_sha256,
            disposition: wire.disposition,
            artifact_scanning_required: wire.artifact_scanning_required,
            observations: wire.observations,
        };
        assessment.validate().map_err(serde::de::Error::custom)?;
        Ok(assessment)
    }
}

impl ReleaseContextAssessment {
    fn from_signals(
        artifact_sha256: Sha256Digest,
        signals: BTreeSet<ReleaseContextSignal>,
    ) -> Result<Self, ArtifactModelError> {
        let observations = signals
            .into_iter()
            .map(|signal| ReleaseContextObservation {
                signal,
                disposition: signal.disposition(),
            })
            .collect::<Vec<_>>();
        let disposition = aggregate_disposition(&observations);
        let assessment = Self {
            schema_version: RELEASE_CONTEXT_ASSESSMENT_SCHEMA_VERSION.to_string(),
            artifact_sha256,
            disposition,
            artifact_scanning_required: true,
            observations,
        };
        assessment.validate()?;
        Ok(assessment)
    }

    pub fn validate(&self) -> Result<(), ArtifactModelError> {
        if self.schema_version != RELEASE_CONTEXT_ASSESSMENT_SCHEMA_VERSION {
            return invalid("unsupported release context assessment schema version");
        }
        if !self.artifact_scanning_required {
            return invalid("release context assessment cannot waive artifact scanning");
        }
        if self.observations.is_empty() {
            return invalid("release context assessment has no observations");
        }
        let mut previous: Option<ReleaseContextSignal> = None;
        let mut scanning_required_signal = false;
        for observation in &self.observations {
            if observation.disposition != observation.signal.disposition() {
                return invalid("release context observation disposition is invalid");
            }
            if previous.is_some_and(|signal| signal >= observation.signal) {
                return invalid(
                    "release context observations must be unique and canonically ordered",
                );
            }
            previous = Some(observation.signal);
            scanning_required_signal |=
                observation.signal == ReleaseContextSignal::ArtifactScanningRequired;
        }
        if !scanning_required_signal {
            return invalid("release context assessment lacks the artifact-scanning requirement");
        }
        if self.disposition != aggregate_disposition(&self.observations) {
            return invalid(
                "release context assessment disposition does not match its observations",
            );
        }
        Ok(())
    }

    pub fn requires_manual_review(&self) -> bool {
        self.disposition != ReleaseContextDisposition::Informational
    }

    /// Release metadata never has admission authority.
    pub fn authorizes_admission(&self) -> bool {
        false
    }

    /// Release metadata alone never constitutes behavior-specific malware evidence.
    pub fn establishes_malicious_behavior(&self) -> bool {
        false
    }
}

fn aggregate_disposition(observations: &[ReleaseContextObservation]) -> ReleaseContextDisposition {
    if observations
        .iter()
        .any(|observation| observation.disposition == ReleaseContextDisposition::Suspicious)
    {
        ReleaseContextDisposition::Suspicious
    } else if observations
        .iter()
        .any(|observation| observation.disposition == ReleaseContextDisposition::ManualReview)
    {
        ReleaseContextDisposition::ManualReview
    } else {
        ReleaseContextDisposition::Informational
    }
}

fn validate_text(
    field: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ArtifactModelError> {
    if value.is_empty() || value.trim() != value {
        return invalid(format!("{field} must be non-empty and trimmed"));
    }
    if value.len() > max_bytes {
        return invalid(format!("{field} exceeds its byte limit"));
    }
    if value.chars().any(char::is_control) {
        return invalid(format!("{field} contains a control character"));
    }
    Ok(())
}

fn validate_https_origin(value: &str) -> Result<(), ArtifactModelError> {
    validate_https_url("registry canonical origin", value)?;
    let authority = value
        .strip_prefix("https://")
        .expect("HTTPS URL prefix checked");
    if authority.contains('/') {
        return invalid("registry canonical origin must not contain a path");
    }
    if value != value.to_ascii_lowercase() {
        return invalid("registry canonical origin must be lowercase");
    }
    Ok(())
}

fn validate_https_url(field: &'static str, value: &str) -> Result<(), ArtifactModelError> {
    validate_text(field, value, MAX_URL_BYTES)?;
    let Some(remainder) = value.strip_prefix("https://") else {
        return invalid(format!("{field} must use HTTPS"));
    };
    let authority = remainder.split('/').next().unwrap_or_default();
    if authority.is_empty()
        || authority.contains('@')
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_whitespace)
    {
        return invalid(format!(
            "{field} is not a canonical credential-free HTTPS URL"
        ));
    }
    Ok(())
}

fn invalid<T>(message: impl Into<String>) -> Result<T, ArtifactModelError> {
    Err(ArtifactModelError::InvalidContract(message.into()))
}
