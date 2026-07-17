use crate::{
    LinuxVzPackageFilePathClassV1, LinuxVzPackageRootFileEvidenceAccessOutcomeV1,
    LinuxVzPackageRootFileEvidenceEventKindV1, LinuxVzPackageRootFileEvidenceEventV1,
    LinuxVzPackageRootFileEvidencePathNamespaceV1, LinuxVzPackageRootFileEvidenceV1,
    VerifiedLinuxVzPackageHostCompositeReceiptV1, VerifiedLinuxVzPackageRootEvidenceReceiptV1,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fmt;
use whoathere_artifact::Sha256Digest;

pub const LINUX_VZ_PACKAGE_VERIFIED_FILE_EVENT_PARTITION_SCHEMA_V1: &str =
    "whoathere.linux_vz_package_verified_file_event_partition.v1";
/// Shares the aggregate root-runtime result ceiling so the bounded projection of a valid 16 MiB,
/// 131,072-event file stream cannot be generated successfully and then rejected by its verifier.
pub const MAX_LINUX_VZ_PACKAGE_VERIFIED_FILE_EVENT_PARTITION_BYTES_V1: usize =
    crate::MAX_LINUX_VZ_PACKAGE_ROOT_RUNTIME_RESULT_BYTES_V1;

const VERIFIED_FILE_EVENT_ID_DOMAIN_V1: &[u8] =
    b"whoathere.linux_vz_package_verified_file_event.id.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinuxVzPackageVerifiedFileEventPartitionErrorV1 {
    InvalidExpectedBinding,
    ReceiptBindingMismatch,
    FileEvidenceBindingMismatch,
    SignedDenominatorMismatch,
    InvalidEventPartition,
    Serialization,
}

impl LinuxVzPackageVerifiedFileEventPartitionErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidExpectedBinding => {
                "linux_vz_package_verified_file_event_partition_expected_binding_invalid"
            }
            Self::ReceiptBindingMismatch => {
                "linux_vz_package_verified_file_event_partition_receipt_binding_mismatch"
            }
            Self::FileEvidenceBindingMismatch => {
                "linux_vz_package_verified_file_event_partition_file_evidence_binding_mismatch"
            }
            Self::SignedDenominatorMismatch => {
                "linux_vz_package_verified_file_event_partition_signed_denominator_mismatch"
            }
            Self::InvalidEventPartition => "linux_vz_package_verified_file_event_partition_invalid",
            Self::Serialization => {
                "linux_vz_package_verified_file_event_partition_serialization_failed"
            }
        }
    }
}

impl fmt::Display for LinuxVzPackageVerifiedFileEventPartitionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LinuxVzPackageVerifiedFileEventPartitionErrorV1 {}

/// Trusted orchestration bindings for the deliberately narrow one-action verifier slice.
///
/// These values must come from the execution plan and independently verified receipts. The
/// constructor accepts no producer-authored observation, label, reason string, or verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageExpectedSingleActionFilePartitionV1 {
    artifact_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    root_receipt_sha256: Sha256Digest,
    host_receipt_sha256: Sha256Digest,
    file_evidence_sha256: Sha256Digest,
    expected_action_count: usize,
    action_index: usize,
}

impl LinuxVzPackageExpectedSingleActionFilePartitionV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new_v1(
        artifact_sha256: Sha256Digest,
        execution_grant_sha256: Sha256Digest,
        process_plan_sha256: Sha256Digest,
        root_receipt_sha256: Sha256Digest,
        host_receipt_sha256: Sha256Digest,
        file_evidence_sha256: Sha256Digest,
        expected_action_count: usize,
        action_index: usize,
    ) -> Result<Self, LinuxVzPackageVerifiedFileEventPartitionErrorV1> {
        let value = Self {
            artifact_sha256,
            execution_grant_sha256,
            process_plan_sha256,
            root_receipt_sha256,
            host_receipt_sha256,
            file_evidence_sha256,
            expected_action_count,
            action_index,
        };
        value.validate_v1()?;
        Ok(value)
    }

    fn validate_v1(&self) -> Result<(), LinuxVzPackageVerifiedFileEventPartitionErrorV1> {
        let empty = Sha256Digest::from_bytes(&[]);
        if [
            &self.artifact_sha256,
            &self.execution_grant_sha256,
            &self.process_plan_sha256,
            &self.root_receipt_sha256,
            &self.host_receipt_sha256,
            &self.file_evidence_sha256,
        ]
        .contains(&&empty)
            || self.expected_action_count != 1
            || self.action_index != 1
        {
            return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidExpectedBinding);
        }
        Ok(())
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn root_receipt_sha256(&self) -> &Sha256Digest {
        &self.root_receipt_sha256
    }

    pub fn host_receipt_sha256(&self) -> &Sha256Digest {
        &self.host_receipt_sha256
    }

    pub fn file_evidence_sha256(&self) -> &Sha256Digest {
        &self.file_evidence_sha256
    }

    pub const fn expected_action_count(&self) -> usize {
        self.expected_action_count
    }

    pub const fn action_index(&self) -> usize {
        self.action_index
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzPackageVerifiedFileEventDispositionV1 {
    ProjectedSensitiveSshRead,
    RecognizedOrdinaryWorkspaceOpen,
    UnsupportedKnownFileEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageVerifiedFileEventV1 {
    source_sequence: u64,
    event_id: String,
    event_sha256: Sha256Digest,
    disposition: LinuxVzPackageVerifiedFileEventDispositionV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxVzPackageVerifiedFileObservationKindV1 {
    SensitiveSshRead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxVzPackageVerifiedFileObservationV1 {
    observation_kind: LinuxVzPackageVerifiedFileObservationKindV1,
    source_event_id: String,
    source_event_sha256: Sha256Digest,
    source_sequence: u64,
}

impl LinuxVzPackageVerifiedFileObservationV1 {
    pub const fn observation_kind(&self) -> LinuxVzPackageVerifiedFileObservationKindV1 {
        self.observation_kind
    }

    pub fn source_event_id(&self) -> &str {
        &self.source_event_id
    }

    pub fn source_event_sha256(&self) -> &Sha256Digest {
        &self.source_event_sha256
    }

    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }
}

impl LinuxVzPackageVerifiedFileEventV1 {
    pub const fn source_sequence(&self) -> u64 {
        self.source_sequence
    }

    pub fn event_id(&self) -> &str {
        &self.event_id
    }

    pub fn event_sha256(&self) -> &Sha256Digest {
        &self.event_sha256
    }

    pub const fn disposition(&self) -> LinuxVzPackageVerifiedFileEventDispositionV1 {
        self.disposition
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedFileEventPartitionBindingWireV1<'a> {
    action_index: String,
    artifact_sha256: &'a Sha256Digest,
    execution_grant_sha256: &'a Sha256Digest,
    expected_action_count: String,
    file_evidence_sha256: &'a Sha256Digest,
    host_receipt_sha256: &'a Sha256Digest,
    process_plan_sha256: &'a Sha256Digest,
    root_receipt_sha256: &'a Sha256Digest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedFileEventPartitionCoverageWireV1 {
    authoritative_verdict_permitted: bool,
    file_event_partition_complete: bool,
    file_event_projection_coverage_complete: bool,
    host_composite_evidence_complete: bool,
    observed_clean_permitted: bool,
    producer_observations_consumed: bool,
    root_evidence_complete: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedFileEventPartitionCountsWireV1 {
    ordinary_workspace_open_count: String,
    partitioned_event_count: String,
    projected_sensitive_ssh_read_count: String,
    source_event_count: String,
    unsupported_event_count: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedFileEventPartitionDigestWireV1<'a> {
    binding: VerifiedFileEventPartitionBindingWireV1<'a>,
    counts: VerifiedFileEventPartitionCountsWireV1,
    coverage: VerifiedFileEventPartitionCoverageWireV1,
    events: &'a [LinuxVzPackageVerifiedFileEventV1],
    observations: &'a [LinuxVzPackageVerifiedFileObservationV1],
    schema_version: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerifiedFileEventPartitionWireV1<'a> {
    binding: VerifiedFileEventPartitionBindingWireV1<'a>,
    counts: VerifiedFileEventPartitionCountsWireV1,
    coverage: VerifiedFileEventPartitionCoverageWireV1,
    events: &'a [LinuxVzPackageVerifiedFileEventV1],
    observations: &'a [LinuxVzPackageVerifiedFileObservationV1],
    partition_sha256: &'a Sha256Digest,
    schema_version: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinuxVzPackageVerifiedFileEventPartitionV1 {
    canonical_json: Vec<u8>,
    output_sha256: Sha256Digest,
    partition_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    execution_grant_sha256: Sha256Digest,
    process_plan_sha256: Sha256Digest,
    root_receipt_sha256: Sha256Digest,
    host_receipt_sha256: Sha256Digest,
    file_evidence_sha256: Sha256Digest,
    action_index: usize,
    source_event_count: usize,
    projected_sensitive_ssh_read_count: usize,
    recognized_ordinary_workspace_open_count: usize,
    unsupported_event_count: usize,
    events: Vec<LinuxVzPackageVerifiedFileEventV1>,
    observations: Vec<LinuxVzPackageVerifiedFileObservationV1>,
    root_evidence_complete: bool,
}

impl LinuxVzPackageVerifiedFileEventPartitionV1 {
    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }

    pub fn partition_sha256(&self) -> &Sha256Digest {
        &self.partition_sha256
    }

    pub fn output_sha256(&self) -> &Sha256Digest {
        &self.output_sha256
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn execution_grant_sha256(&self) -> &Sha256Digest {
        &self.execution_grant_sha256
    }

    pub fn process_plan_sha256(&self) -> &Sha256Digest {
        &self.process_plan_sha256
    }

    pub fn root_receipt_sha256(&self) -> &Sha256Digest {
        &self.root_receipt_sha256
    }

    pub fn host_receipt_sha256(&self) -> &Sha256Digest {
        &self.host_receipt_sha256
    }

    pub fn file_evidence_sha256(&self) -> &Sha256Digest {
        &self.file_evidence_sha256
    }

    pub const fn action_index(&self) -> usize {
        self.action_index
    }

    pub const fn source_event_count(&self) -> usize {
        self.source_event_count
    }

    pub const fn partitioned_event_count(&self) -> usize {
        self.events.len()
    }

    pub const fn projected_sensitive_ssh_read_count(&self) -> usize {
        self.projected_sensitive_ssh_read_count
    }

    pub const fn recognized_ordinary_workspace_open_count(&self) -> usize {
        self.recognized_ordinary_workspace_open_count
    }

    pub const fn unsupported_event_count(&self) -> usize {
        self.unsupported_event_count
    }

    pub fn events(&self) -> &[LinuxVzPackageVerifiedFileEventV1] {
        &self.events
    }

    pub fn observations(&self) -> &[LinuxVzPackageVerifiedFileObservationV1] {
        &self.observations
    }

    pub const fn positive_observation_present(&self) -> bool {
        self.projected_sensitive_ssh_read_count > 0
    }

    pub const fn file_event_partition_complete(&self) -> bool {
        true
    }

    pub const fn file_event_projection_coverage_complete(&self) -> bool {
        self.unsupported_event_count == 0
    }

    pub const fn root_evidence_complete(&self) -> bool {
        self.root_evidence_complete
    }

    pub const fn host_composite_evidence_complete(&self) -> bool {
        false
    }

    pub const fn producer_observations_consumed(&self) -> bool {
        false
    }

    pub const fn observed_clean_permitted(&self) -> bool {
        false
    }

    pub const fn authoritative_verdict_permitted(&self) -> bool {
        false
    }
}

pub fn verify_linux_vz_package_single_action_file_partition_v1(
    expected: &LinuxVzPackageExpectedSingleActionFilePartitionV1,
    root: &VerifiedLinuxVzPackageRootEvidenceReceiptV1,
    host: &VerifiedLinuxVzPackageHostCompositeReceiptV1,
    file: &LinuxVzPackageRootFileEvidenceV1,
) -> Result<
    LinuxVzPackageVerifiedFileEventPartitionV1,
    LinuxVzPackageVerifiedFileEventPartitionErrorV1,
> {
    expected.validate_v1()?;
    if expected.artifact_sha256 != *root.artifact_sha256()
        || expected.execution_grant_sha256 != *root.execution_grant_sha256()
        || expected.process_plan_sha256 != *root.process_plan_sha256()
        || expected.action_index != root.action_index()
    {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::ReceiptBindingMismatch);
    }
    if expected.root_receipt_sha256 != *root.receipt_sha256()
        || expected.host_receipt_sha256 != *host.receipt_sha256()
        || host.root_receipt_sha256() != root.receipt_sha256()
    {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::ReceiptBindingMismatch);
    }
    if expected.file_evidence_sha256 != *file.payload_sha256()
        || root.file_evidence_sha256() != file.payload_sha256()
        || file.payload_sha256() != &Sha256Digest::from_bytes(file.canonical_json_v1())
    {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::FileEvidenceBindingMismatch);
    }
    if root.file_evidence_byte_length() != file.canonical_json_v1().len()
        || root.file_event_count() != file.events().len()
    {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::SignedDenominatorMismatch);
    }

    let mut events = Vec::with_capacity(file.events().len());
    let mut event_ids = BTreeSet::new();
    let mut observations = Vec::new();
    let mut projected_sensitive_ssh_read_count = 0usize;
    let mut recognized_ordinary_workspace_open_count = 0usize;
    let mut unsupported_event_count = 0usize;
    for (offset, source) in file.events().iter().enumerate() {
        let expected_sequence = u64::try_from(offset)
            .ok()
            .and_then(|value| value.checked_add(1))
            .ok_or(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition)?;
        if source.source_sequence() != expected_sequence {
            return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition);
        }
        let disposition = classify_file_event_v1(source);
        match disposition {
            LinuxVzPackageVerifiedFileEventDispositionV1::ProjectedSensitiveSshRead => {
                projected_sensitive_ssh_read_count += 1;
            }
            LinuxVzPackageVerifiedFileEventDispositionV1::RecognizedOrdinaryWorkspaceOpen => {
                recognized_ordinary_workspace_open_count += 1;
            }
            LinuxVzPackageVerifiedFileEventDispositionV1::UnsupportedKnownFileEvent => {
                unsupported_event_count += 1;
            }
        }
        let event_sha256 = primitive_file_event_digest_v1(source)?;
        let event_id = verified_file_event_id_v1(expected, source.source_sequence(), &event_sha256);
        if !event_ids.insert(event_id.clone()) {
            return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition);
        }
        events.push(LinuxVzPackageVerifiedFileEventV1 {
            source_sequence: source.source_sequence(),
            event_id: event_id.clone(),
            event_sha256: event_sha256.clone(),
            disposition,
        });
        if disposition == LinuxVzPackageVerifiedFileEventDispositionV1::ProjectedSensitiveSshRead {
            observations.push(LinuxVzPackageVerifiedFileObservationV1 {
                observation_kind: LinuxVzPackageVerifiedFileObservationKindV1::SensitiveSshRead,
                source_event_id: event_id,
                source_event_sha256: event_sha256,
                source_sequence: source.source_sequence(),
            });
        }
    }
    let accounted = projected_sensitive_ssh_read_count
        .checked_add(recognized_ordinary_workspace_open_count)
        .and_then(|count| count.checked_add(unsupported_event_count))
        .ok_or(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition)?;
    if events.len() != file.events().len() || accounted != file.events().len() {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition);
    }
    if observations.len() != projected_sensitive_ssh_read_count {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition);
    }

    let binding = partition_binding_wire_v1(expected);
    let counts = partition_counts_wire_v1(
        file.events().len(),
        projected_sensitive_ssh_read_count,
        recognized_ordinary_workspace_open_count,
        unsupported_event_count,
    );
    let coverage = partition_coverage_wire_v1(root, unsupported_event_count);
    let digest_wire = VerifiedFileEventPartitionDigestWireV1 {
        binding,
        counts,
        coverage,
        events: &events,
        observations: &observations,
        schema_version: LINUX_VZ_PACKAGE_VERIFIED_FILE_EVENT_PARTITION_SCHEMA_V1,
    };
    let digest_canonical = canonical_json_v1(&digest_wire)?;
    let partition_sha256 = Sha256Digest::from_bytes(&digest_canonical);
    let wire = VerifiedFileEventPartitionWireV1 {
        binding: partition_binding_wire_v1(expected),
        counts: partition_counts_wire_v1(
            file.events().len(),
            projected_sensitive_ssh_read_count,
            recognized_ordinary_workspace_open_count,
            unsupported_event_count,
        ),
        coverage: partition_coverage_wire_v1(root, unsupported_event_count),
        events: &events,
        observations: &observations,
        partition_sha256: &partition_sha256,
        schema_version: LINUX_VZ_PACKAGE_VERIFIED_FILE_EVENT_PARTITION_SCHEMA_V1,
    };
    let canonical_json = canonical_json_v1(&wire)?;
    if canonical_json.len() > MAX_LINUX_VZ_PACKAGE_VERIFIED_FILE_EVENT_PARTITION_BYTES_V1 {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition);
    }
    let output_sha256 = Sha256Digest::from_bytes(&canonical_json);
    Ok(LinuxVzPackageVerifiedFileEventPartitionV1 {
        canonical_json,
        output_sha256,
        partition_sha256,
        artifact_sha256: expected.artifact_sha256.clone(),
        execution_grant_sha256: expected.execution_grant_sha256.clone(),
        process_plan_sha256: expected.process_plan_sha256.clone(),
        root_receipt_sha256: expected.root_receipt_sha256.clone(),
        host_receipt_sha256: expected.host_receipt_sha256.clone(),
        file_evidence_sha256: expected.file_evidence_sha256.clone(),
        action_index: expected.action_index,
        source_event_count: file.events().len(),
        projected_sensitive_ssh_read_count,
        recognized_ordinary_workspace_open_count,
        unsupported_event_count,
        events,
        observations,
        root_evidence_complete: root.evidence_complete(),
    })
}

/// Reconstructs the native partition from the same independently verified inputs and requires an
/// externally supplied serialized result to match the canonical native output exactly.
pub fn verify_linux_vz_package_single_action_file_partition_output_v1(
    expected: &LinuxVzPackageExpectedSingleActionFilePartitionV1,
    root: &VerifiedLinuxVzPackageRootEvidenceReceiptV1,
    host: &VerifiedLinuxVzPackageHostCompositeReceiptV1,
    file: &LinuxVzPackageRootFileEvidenceV1,
    serialized_partition: &[u8],
) -> Result<
    LinuxVzPackageVerifiedFileEventPartitionV1,
    LinuxVzPackageVerifiedFileEventPartitionErrorV1,
> {
    if serialized_partition.is_empty()
        || serialized_partition.len() > MAX_LINUX_VZ_PACKAGE_VERIFIED_FILE_EVENT_PARTITION_BYTES_V1
    {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition);
    }
    let partition =
        verify_linux_vz_package_single_action_file_partition_v1(expected, root, host, file)?;
    if serialized_partition != partition.canonical_json_v1() {
        return Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition);
    }
    Ok(partition)
}

fn classify_file_event_v1(
    event: &LinuxVzPackageRootFileEvidenceEventV1,
) -> LinuxVzPackageVerifiedFileEventDispositionV1 {
    if event.kind() == LinuxVzPackageRootFileEvidenceEventKindV1::Read
        && event.path_class() == LinuxVzPackageFilePathClassV1::SensitiveSsh
        && event.outcome() == LinuxVzPackageRootFileEvidenceAccessOutcomeV1::Observed
    {
        LinuxVzPackageVerifiedFileEventDispositionV1::ProjectedSensitiveSshRead
    } else if event.kind() == LinuxVzPackageRootFileEvidenceEventKindV1::Open
        && event.path_class() == LinuxVzPackageFilePathClassV1::Workspace
        && event.namespace() == LinuxVzPackageRootFileEvidencePathNamespaceV1::WorkspaceRelative
        && event.outcome() == LinuxVzPackageRootFileEvidenceAccessOutcomeV1::Observed
    {
        LinuxVzPackageVerifiedFileEventDispositionV1::RecognizedOrdinaryWorkspaceOpen
    } else {
        LinuxVzPackageVerifiedFileEventDispositionV1::UnsupportedKnownFileEvent
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct PrimitiveFileEventWireV1<'a> {
    access_outcome: &'static str,
    actor_pid: String,
    cgroup_id: String,
    event_kind: &'static str,
    path_class: &'static str,
    path_namespace: &'static str,
    path_token_sha256: &'a Sha256Digest,
    source_sequence: String,
    timestamp_monotonic_nanoseconds: String,
}

fn primitive_file_event_digest_v1(
    event: &LinuxVzPackageRootFileEvidenceEventV1,
) -> Result<Sha256Digest, LinuxVzPackageVerifiedFileEventPartitionErrorV1> {
    let wire = PrimitiveFileEventWireV1 {
        access_outcome: access_outcome_name_v1(event.outcome()),
        actor_pid: event.actor_pid().to_string(),
        cgroup_id: event.cgroup_id().to_string(),
        event_kind: event_kind_name_v1(event.kind()),
        path_class: path_class_name_v1(event.path_class()),
        path_namespace: path_namespace_name_v1(event.namespace()),
        path_token_sha256: event.path_token_sha256(),
        source_sequence: event.source_sequence().to_string(),
        timestamp_monotonic_nanoseconds: event.timestamp_monotonic_nanoseconds().to_string(),
    };
    Ok(Sha256Digest::from_bytes(&canonical_json_v1(&wire)?))
}

fn verified_file_event_id_v1(
    expected: &LinuxVzPackageExpectedSingleActionFilePartitionV1,
    source_sequence: u64,
    event_sha256: &Sha256Digest,
) -> String {
    let mut digest = Sha256::new();
    digest.update(VERIFIED_FILE_EVENT_ID_DOMAIN_V1);
    for value in [
        expected.artifact_sha256.as_str().as_bytes(),
        expected.execution_grant_sha256.as_str().as_bytes(),
        expected.process_plan_sha256.as_str().as_bytes(),
        expected.root_receipt_sha256.as_str().as_bytes(),
        expected.host_receipt_sha256.as_str().as_bytes(),
        expected.file_evidence_sha256.as_str().as_bytes(),
        event_sha256.as_str().as_bytes(),
    ] {
        digest.update((value.len() as u64).to_be_bytes());
        digest.update(value);
    }
    digest.update((expected.action_index as u64).to_be_bytes());
    digest.update(source_sequence.to_be_bytes());
    let encoded = Sha256Digest::from_bytes(&digest.finalize()).as_str()[7..].to_string();
    format!("file-event-{encoded}")
}

fn partition_binding_wire_v1(
    expected: &LinuxVzPackageExpectedSingleActionFilePartitionV1,
) -> VerifiedFileEventPartitionBindingWireV1<'_> {
    VerifiedFileEventPartitionBindingWireV1 {
        action_index: expected.action_index.to_string(),
        artifact_sha256: &expected.artifact_sha256,
        execution_grant_sha256: &expected.execution_grant_sha256,
        expected_action_count: expected.expected_action_count.to_string(),
        file_evidence_sha256: &expected.file_evidence_sha256,
        host_receipt_sha256: &expected.host_receipt_sha256,
        process_plan_sha256: &expected.process_plan_sha256,
        root_receipt_sha256: &expected.root_receipt_sha256,
    }
}

fn partition_counts_wire_v1(
    source_event_count: usize,
    projected_sensitive_ssh_read_count: usize,
    recognized_ordinary_workspace_open_count: usize,
    unsupported_event_count: usize,
) -> VerifiedFileEventPartitionCountsWireV1 {
    VerifiedFileEventPartitionCountsWireV1 {
        ordinary_workspace_open_count: recognized_ordinary_workspace_open_count.to_string(),
        partitioned_event_count: source_event_count.to_string(),
        projected_sensitive_ssh_read_count: projected_sensitive_ssh_read_count.to_string(),
        source_event_count: source_event_count.to_string(),
        unsupported_event_count: unsupported_event_count.to_string(),
    }
}

fn partition_coverage_wire_v1(
    root: &VerifiedLinuxVzPackageRootEvidenceReceiptV1,
    unsupported_event_count: usize,
) -> VerifiedFileEventPartitionCoverageWireV1 {
    VerifiedFileEventPartitionCoverageWireV1 {
        authoritative_verdict_permitted: false,
        file_event_partition_complete: true,
        file_event_projection_coverage_complete: unsupported_event_count == 0,
        host_composite_evidence_complete: false,
        observed_clean_permitted: false,
        producer_observations_consumed: false,
        root_evidence_complete: root.evidence_complete(),
    }
}

fn canonical_json_v1<T: Serialize>(
    value: &T,
) -> Result<Vec<u8>, LinuxVzPackageVerifiedFileEventPartitionErrorV1> {
    serde_json_canonicalizer::to_vec(value)
        .map_err(|_| LinuxVzPackageVerifiedFileEventPartitionErrorV1::Serialization)
}

const fn event_kind_name_v1(value: LinuxVzPackageRootFileEvidenceEventKindV1) -> &'static str {
    match value {
        LinuxVzPackageRootFileEvidenceEventKindV1::Open => "open",
        LinuxVzPackageRootFileEvidenceEventKindV1::Read => "read",
        LinuxVzPackageRootFileEvidenceEventKindV1::Write => "write",
        LinuxVzPackageRootFileEvidenceEventKindV1::OpenExec => "open_exec",
    }
}

const fn access_outcome_name_v1(
    value: LinuxVzPackageRootFileEvidenceAccessOutcomeV1,
) -> &'static str {
    match value {
        LinuxVzPackageRootFileEvidenceAccessOutcomeV1::Observed => "observed",
        LinuxVzPackageRootFileEvidenceAccessOutcomeV1::Denied => "denied",
    }
}

const fn path_namespace_name_v1(
    value: LinuxVzPackageRootFileEvidencePathNamespaceV1,
) -> &'static str {
    match value {
        LinuxVzPackageRootFileEvidencePathNamespaceV1::Absolute => "absolute",
        LinuxVzPackageRootFileEvidencePathNamespaceV1::WorkspaceRelative => "workspace_relative",
    }
}

const fn path_class_name_v1(value: LinuxVzPackageFilePathClassV1) -> &'static str {
    match value {
        LinuxVzPackageFilePathClassV1::Workspace => "workspace",
        LinuxVzPackageFilePathClassV1::PackageCache => "package_cache",
        LinuxVzPackageFilePathClassV1::Runtime => "runtime",
        LinuxVzPackageFilePathClassV1::ProtectedCanary => "protected_canary",
        LinuxVzPackageFilePathClassV1::ProtectedSensor => "protected_sensor",
        LinuxVzPackageFilePathClassV1::SensitiveCredential => "sensitive_credential",
        LinuxVzPackageFilePathClassV1::SensitiveSsh => "sensitive_ssh",
        LinuxVzPackageFilePathClassV1::PersistenceStartup => "persistence_startup",
        LinuxVzPackageFilePathClassV1::Other => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode_linux_vz_package_host_udp_sendto_evidence_v1,
        decode_linux_vz_package_root_file_evidence_v1,
        linux_vz_package_authority_request::test_macos_linux_vz_package_authority_request_for_execution_v1,
        linux_vz_package_execution_grant::{
            test_burn_macos_linux_vz_package_execution_request_v1,
            test_macos_linux_vz_package_execution_grant_observation_with_evidence_keys_v1,
        },
        linux_vz_package_host_composite_receipt::test_sign_linux_vz_package_host_composite_receipt_v1,
        linux_vz_package_root_evidence_receipt::test_linux_vz_package_root_evidence_receipt_claims_for_file_v1,
        linux_vz_package_root_file_evidence::encode_linux_vz_package_root_file_evidence_v1,
        linux_vz_package_sensor_file_collector::LinuxVzPackageRootFileCollectionV1,
        sign_linux_vz_package_root_evidence_receipt_v1,
        verify_linux_vz_package_host_composite_receipt_v1,
        verify_linux_vz_package_root_evidence_receipt_v1,
        LinuxVzPackageExpectedHostCompositeLifecycleV1, LinuxVzPackageExpectedHostUdpSendtoV1,
        LinuxVzPackageExpectedRootFileEvidenceV1, LinuxVzPackageHostDestinationClassV1,
        LinuxVzPackageHostUdpSendtoEvidenceV1, LinuxVzPackageProcessCompletionV1,
        LinuxVzPackageProcessTerminalV1, LinuxVzPackageRootEvidenceReceiptClaimsV1,
        LinuxVzPackageRootEvidenceReceiptErrorV1, MacosLinuxVzPackageArtifactKindV1,
        LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V2,
    };
    use ed25519_dalek::SigningKey;

    const GUEST_SIGNING_SEED: [u8; 32] = [73_u8; 32];
    const HOST_SIGNING_SEED: [u8; 32] = [44_u8; 32];
    const ACTION_INDEX: usize = 1;
    const CGROUP_ID: u64 = 9_001;
    const ROOT_RUNNER_PID: u32 = 40;
    const LEADER_PID: u32 = 42;
    const STARTED_MONOTONIC: u64 = 100;
    const ENDED_MONOTONIC: u64 = 300;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn host_network_v2() -> LinuxVzPackageHostUdpSendtoEvidenceV1 {
        let expected = LinuxVzPackageExpectedHostUdpSendtoV1::new_v1(
            Sha256Digest::from_bytes(br#"{"type":"network"}"#),
            Sha256Digest::from_bytes(br#"{"type":"process"}"#),
            digest("sensor session challenge"),
            digest("host destination token"),
            digest("host egress packet correlation"),
            LinuxVzPackageHostDestinationClassV1::Documentation,
            40_553,
            16,
            16,
        )
        .expect("expected host network");
        let value = serde_json::json!({
            "binding": {
                "egress_packet_correlation_sha256": digest("host egress packet correlation"),
                "process_evidence_sha256": Sha256Digest::from_bytes(br#"{"type":"process"}"#),
                "root_network_evidence_sha256": Sha256Digest::from_bytes(br#"{"type":"network"}"#),
                "sensor_session_challenge_sha256": digest("sensor session challenge")
            },
            "collector": {
                "dropped_frame_count": "0",
                "healthy": true,
                "ingress_frame_count": "1",
                "retained_frame_count": "1",
                "terminal": "drained_after_stop",
                "truncated_frame_count": "0"
            },
            "coverage": {
                "broad_host_frame_coverage_complete": false,
                "correlated_transmitted_event_count": "1",
                "raw_addresses_serialized": false,
                "raw_frame_bytes_serialized": false,
                "selected_udp_sendto_correlation_complete": true,
                "unobserved_capabilities": [
                    "ipv6_host_frames",
                    "kernel_socket_buffer_drop_accounting",
                    "non_udp_sendto_host_frames",
                    "retransmission_and_multi_frame_events"
                ]
            },
            "event": {
                "destination_class": "documentation",
                "destination_port": "40553",
                "destination_token_sha256": digest("host destination token"),
                "enter_source_sequence": "16",
                "event_kind": "sendto",
                "frame_sha256": digest("host frame"),
                "network_layer_correlation_sha256": digest("host egress packet correlation"),
                "source_port": "49152",
                "syscall_result": "16",
                "transport": "udp",
                "transport_payload_byte_count": "16"
            },
            "schema_version": LINUX_VZ_PACKAGE_HOST_UDP_SENDTO_EVIDENCE_SCHEMA_V2
        });
        let bytes = serde_json_canonicalizer::to_vec(&value).expect("canonical host network");
        decode_linux_vz_package_host_udp_sendto_evidence_v1(&bytes, &expected)
            .expect("host network")
    }

    struct SignedFixtureV1 {
        expected: LinuxVzPackageExpectedSingleActionFilePartitionV1,
        root: VerifiedLinuxVzPackageRootEvidenceReceiptV1,
        host: VerifiedLinuxVzPackageHostCompositeReceiptV1,
        file: LinuxVzPackageRootFileEvidenceV1,
        file_expected: LinuxVzPackageExpectedRootFileEvidenceV1,
        root_claims: LinuxVzPackageRootEvidenceReceiptClaimsV1,
        root_receipt: Vec<u8>,
        guest_verifying_key: [u8; 32],
        root_observed_at_unix_seconds: u64,
    }

    fn signed_fixture_v1(include_unsupported: bool) -> SignedFixtureV1 {
        let guest_key = SigningKey::from_bytes(&GUEST_SIGNING_SEED);
        let host_key = SigningKey::from_bytes(&HOST_SIGNING_SEED);
        let guest_verifying_key = guest_key.verifying_key().to_bytes();
        let request = test_macos_linux_vz_package_authority_request_for_execution_v1(
            digest("partition authority request"),
            MacosLinuxVzPackageArtifactKindV1::NpmTarball,
            digest("partition artifact"),
            digest("partition request challenge"),
            digest("partition clone binding"),
        );
        let grant = test_macos_linux_vz_package_execution_grant_observation_with_evidence_keys_v1(
            &request,
            Sha256Digest::from_bytes(&guest_verifying_key),
            Sha256Digest::from_bytes(host_key.verifying_key().as_bytes()),
        );
        let completion = LinuxVzPackageProcessCompletionV1::from_parts_v1(
            STARTED_MONOTONIC,
            ENDED_MONOTONIC,
            0,
            LinuxVzPackageProcessTerminalV1::Exited,
            Some(0),
            None,
        )
        .expect("completion");
        let process_plan_sha256 = digest("partition process plan");
        let file_expected = LinuxVzPackageExpectedRootFileEvidenceV1::from_action_v1(
            digest("sensor session challenge"),
            digest("launch contract"),
            process_plan_sha256.clone(),
            ACTION_INDEX,
            format!("whoathere-package-action-{ACTION_INDEX}"),
            CGROUP_ID,
            ROOT_RUNNER_PID,
            LEADER_PID,
            &completion,
        )
        .expect("file expected binding");
        let collection = if include_unsupported {
            LinuxVzPackageRootFileCollectionV1::denominator_fixture_with_unsupported_v1(
                file_expected.sensor_session_challenge_sha256(),
                CGROUP_ID,
                LEADER_PID,
                STARTED_MONOTONIC,
                ENDED_MONOTONIC,
            )
        } else {
            LinuxVzPackageRootFileCollectionV1::denominator_fixture_v1(
                file_expected.sensor_session_challenge_sha256(),
                CGROUP_ID,
                LEADER_PID,
                STARTED_MONOTONIC,
                ENDED_MONOTONIC,
            )
        };
        let file = encode_linux_vz_package_root_file_evidence_v1(&file_expected, &collection)
            .expect("file evidence");
        let root_claims = test_linux_vz_package_root_evidence_receipt_claims_for_file_v1(
            &request,
            &grant,
            &file,
            process_plan_sha256.clone(),
            ACTION_INDEX,
            CGROUP_ID,
            ROOT_RUNNER_PID,
            LEADER_PID,
            STARTED_MONOTONIC,
            ENDED_MONOTONIC,
            GUEST_SIGNING_SEED,
        );
        let root_receipt =
            sign_linux_vz_package_root_evidence_receipt_v1(&root_claims, GUEST_SIGNING_SEED)
                .expect("signed root receipt");
        let root_observed_at_unix_seconds = grant.verified_at_unix_seconds() + 1;
        let root = verify_linux_vz_package_root_evidence_receipt_v1(
            &root_claims,
            &root_receipt,
            guest_verifying_key,
            root_observed_at_unix_seconds,
        )
        .expect("verified root receipt");

        test_burn_macos_linux_vz_package_execution_request_v1(&grant);
        let host_network = host_network_v2();
        let lifecycle = LinuxVzPackageExpectedHostCompositeLifecycleV1::new_v1(
            digest("partition host serial log"),
            vec![digest("partition restricted evidence reference")],
            true,
            true,
            true,
            true,
            true,
            0,
        )
        .expect("host lifecycle");
        let host_expected =
            crate::LinuxVzPackageHostCompositeExpectedBindingsV1::from_verified_sources_v1(
                &request,
                &grant,
                &root,
                &host_network,
                lifecycle,
            )
            .expect("host expected binding");
        let host_created = grant.verified_at_unix_seconds() + 2;
        let host_expires = grant.expires_at_unix_seconds() - 2;
        let (host_evidence, host_receipt, host_verifying_key) =
            test_sign_linux_vz_package_host_composite_receipt_v1(
                &host_expected,
                HOST_SIGNING_SEED,
                host_created,
                host_expires,
            )
            .expect("signed host receipt");
        let host = verify_linux_vz_package_host_composite_receipt_v1(
            &host_evidence,
            &host_receipt,
            &host_expected,
            host_verifying_key,
            host_created,
        )
        .expect("verified host receipt");
        let expected = LinuxVzPackageExpectedSingleActionFilePartitionV1::new_v1(
            request.artifact_sha256().clone(),
            grant.execution_grant_sha256().clone(),
            process_plan_sha256,
            root.receipt_sha256().clone(),
            host.receipt_sha256().clone(),
            file.payload_sha256().clone(),
            1,
            ACTION_INDEX,
        )
        .expect("partition expected binding");
        SignedFixtureV1 {
            expected,
            root,
            host,
            file,
            file_expected,
            root_claims,
            root_receipt,
            guest_verifying_key,
            root_observed_at_unix_seconds,
        }
    }

    #[test]
    fn signed_two_event_fixture_projects_one_typed_observation_and_partitions_exactly() {
        let fixture = signed_fixture_v1(false);
        let partition = verify_linux_vz_package_single_action_file_partition_v1(
            &fixture.expected,
            &fixture.root,
            &fixture.host,
            &fixture.file,
        )
        .expect("verified partition");
        assert_eq!(partition.source_event_count(), 2);
        assert_eq!(partition.partitioned_event_count(), 2);
        assert_eq!(partition.projected_sensitive_ssh_read_count(), 1);
        assert_eq!(partition.recognized_ordinary_workspace_open_count(), 1);
        assert_eq!(partition.unsupported_event_count(), 0);
        assert_eq!(partition.observations().len(), 1);
        assert_eq!(
            partition.observations()[0].observation_kind(),
            LinuxVzPackageVerifiedFileObservationKindV1::SensitiveSshRead
        );
        assert_eq!(
            partition.events()[0].disposition(),
            LinuxVzPackageVerifiedFileEventDispositionV1::ProjectedSensitiveSshRead
        );
        assert_eq!(
            partition.events()[1].disposition(),
            LinuxVzPackageVerifiedFileEventDispositionV1::RecognizedOrdinaryWorkspaceOpen
        );
        assert!(partition.positive_observation_present());
        assert!(partition.file_event_partition_complete());
        assert!(partition.file_event_projection_coverage_complete());
        assert!(!partition.root_evidence_complete());
        assert!(!partition.host_composite_evidence_complete());
        assert!(!partition.observed_clean_permitted());
        assert!(!partition.authoritative_verdict_permitted());
        assert!(!partition.producer_observations_consumed());
        assert_eq!(
            partition.output_sha256(),
            &Sha256Digest::from_bytes(partition.canonical_json_v1())
        );
        verify_linux_vz_package_single_action_file_partition_output_v1(
            &fixture.expected,
            &fixture.root,
            &fixture.host,
            &fixture.file,
            partition.canonical_json_v1(),
        )
        .expect("reconstructed canonical partition");
    }

    #[test]
    fn unsupported_event_preserves_positive_and_forces_projection_incomplete_never_clean() {
        let fixture = signed_fixture_v1(true);
        let partition = verify_linux_vz_package_single_action_file_partition_v1(
            &fixture.expected,
            &fixture.root,
            &fixture.host,
            &fixture.file,
        )
        .expect("verified partition");
        assert_eq!(partition.source_event_count(), 3);
        assert_eq!(partition.partitioned_event_count(), 3);
        assert_eq!(partition.projected_sensitive_ssh_read_count(), 1);
        assert_eq!(partition.recognized_ordinary_workspace_open_count(), 1);
        assert_eq!(partition.unsupported_event_count(), 1);
        assert_eq!(partition.observations().len(), 1);
        assert!(partition.positive_observation_present());
        assert!(partition.file_event_partition_complete());
        assert!(!partition.file_event_projection_coverage_complete());
        assert!(!partition.observed_clean_permitted());
        assert!(!partition.authoritative_verdict_permitted());
    }

    #[test]
    fn serialized_output_tamper_is_rejected_by_signed_input_reconstruction() {
        let fixture = signed_fixture_v1(false);
        let partition = verify_linux_vz_package_single_action_file_partition_v1(
            &fixture.expected,
            &fixture.root,
            &fixture.host,
            &fixture.file,
        )
        .expect("verified partition");
        let mut value: serde_json::Value =
            serde_json::from_slice(partition.canonical_json_v1()).expect("partition json");
        value["coverage"]["observed_clean_permitted"] = serde_json::Value::Bool(true);
        let tampered = serde_json_canonicalizer::to_vec(&value).expect("canonical tamper");
        assert_eq!(
            verify_linux_vz_package_single_action_file_partition_output_v1(
                &fixture.expected,
                &fixture.root,
                &fixture.host,
                &fixture.file,
                &tampered,
            ),
            Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidEventPartition)
        );
    }

    #[test]
    fn file_event_omission_and_ordinal_mutation_fail_before_partitioning() {
        let fixture = signed_fixture_v1(false);
        let mut omitted: serde_json::Value =
            serde_json::from_slice(fixture.file.canonical_json_v1()).expect("file json");
        omitted["events"].as_array_mut().expect("events").remove(1);
        let omitted = serde_json_canonicalizer::to_vec(&omitted).expect("canonical omission");
        assert_eq!(
            decode_linux_vz_package_root_file_evidence_v1(&fixture.file_expected, &omitted),
            Err(crate::LinuxVzPackageRootFileEvidenceErrorV1::InvalidCoverage)
        );

        let mut reordered: serde_json::Value =
            serde_json::from_slice(fixture.file.canonical_json_v1()).expect("file json");
        reordered["events"][1]["source_sequence"] = serde_json::Value::String("3".to_string());
        let reordered = serde_json_canonicalizer::to_vec(&reordered).expect("canonical ordinal");
        assert_eq!(
            decode_linux_vz_package_root_file_evidence_v1(&fixture.file_expected, &reordered),
            Err(crate::LinuxVzPackageRootFileEvidenceErrorV1::InvalidEvent)
        );
    }

    #[test]
    fn root_signature_and_key_tamper_are_rejected_before_partitioning() {
        let fixture = signed_fixture_v1(false);
        let mut receipt: serde_json::Value =
            serde_json::from_slice(&fixture.root_receipt).expect("root receipt json");
        receipt["signature_ed25519_hex"] = serde_json::Value::String("00".repeat(64));
        let receipt = serde_json_canonicalizer::to_vec(&receipt).expect("canonical receipt");
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &fixture.root_claims,
                &receipt,
                fixture.guest_verifying_key,
                fixture.root_observed_at_unix_seconds,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::SignatureFailed)
        );
        assert_eq!(
            verify_linux_vz_package_root_evidence_receipt_v1(
                &fixture.root_claims,
                &fixture.root_receipt,
                SigningKey::from_bytes(&[99_u8; 32])
                    .verifying_key()
                    .to_bytes(),
                fixture.root_observed_at_unix_seconds,
            ),
            Err(LinuxVzPackageRootEvidenceReceiptErrorV1::PublicKeyMismatch)
        );
    }

    #[test]
    fn trusted_binding_rejects_foreign_artifact_grant_receipt_and_file_replay() {
        let fixture = signed_fixture_v1(false);
        let foreign_file_fixture = signed_fixture_v1(true);
        let rebound_artifact = LinuxVzPackageExpectedSingleActionFilePartitionV1::new_v1(
            digest("foreign artifact"),
            fixture.expected.execution_grant_sha256().clone(),
            fixture.expected.process_plan_sha256().clone(),
            fixture.expected.root_receipt_sha256().clone(),
            fixture.expected.host_receipt_sha256().clone(),
            fixture.expected.file_evidence_sha256().clone(),
            1,
            1,
        )
        .expect("foreign expected binding");
        assert_eq!(
            verify_linux_vz_package_single_action_file_partition_v1(
                &rebound_artifact,
                &fixture.root,
                &fixture.host,
                &fixture.file,
            ),
            Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::ReceiptBindingMismatch)
        );
        let rebound_grant = LinuxVzPackageExpectedSingleActionFilePartitionV1::new_v1(
            fixture.expected.artifact_sha256().clone(),
            digest("foreign execution grant"),
            fixture.expected.process_plan_sha256().clone(),
            fixture.expected.root_receipt_sha256().clone(),
            fixture.expected.host_receipt_sha256().clone(),
            fixture.expected.file_evidence_sha256().clone(),
            1,
            1,
        )
        .expect("foreign expected binding");
        assert_eq!(
            verify_linux_vz_package_single_action_file_partition_v1(
                &rebound_grant,
                &fixture.root,
                &fixture.host,
                &fixture.file,
            ),
            Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::ReceiptBindingMismatch)
        );
        assert_eq!(
            verify_linux_vz_package_single_action_file_partition_v1(
                &fixture.expected,
                &fixture.root,
                &fixture.host,
                &foreign_file_fixture.file,
            ),
            Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::FileEvidenceBindingMismatch)
        );
        assert_eq!(
            verify_linux_vz_package_single_action_file_partition_v1(
                &fixture.expected,
                &foreign_file_fixture.root,
                &fixture.host,
                &fixture.file,
            ),
            Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::ReceiptBindingMismatch)
        );
        assert_eq!(
            verify_linux_vz_package_single_action_file_partition_v1(
                &fixture.expected,
                &fixture.root,
                &foreign_file_fixture.host,
                &fixture.file,
            ),
            Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::ReceiptBindingMismatch)
        );
    }

    #[test]
    fn one_action_scope_is_explicit_and_cannot_overclaim_clean() {
        let fixture = signed_fixture_v1(false);
        assert_eq!(fixture.expected.expected_action_count(), 1);
        assert_eq!(fixture.expected.action_index(), 1);
        assert_eq!(
            LinuxVzPackageExpectedSingleActionFilePartitionV1::new_v1(
                fixture.expected.artifact_sha256().clone(),
                fixture.expected.execution_grant_sha256().clone(),
                fixture.expected.process_plan_sha256().clone(),
                fixture.expected.root_receipt_sha256().clone(),
                fixture.expected.host_receipt_sha256().clone(),
                fixture.expected.file_evidence_sha256().clone(),
                2,
                1,
            ),
            Err(LinuxVzPackageVerifiedFileEventPartitionErrorV1::InvalidExpectedBinding)
        );
    }
}
