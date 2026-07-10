//! Bounded macOS process execution for the Artifact Review v2 inert fixture.
//!
//! This crate deliberately does not support Ollama, HTTP, model discovery,
//! model pulls, shell commands, or package execution. It exercises a
//! request-bound, digest-checked process-adapter contract with one compiled
//! inert binary. It is not a sandbox or VM: network, memory, process-count,
//! and full descendant containment are explicitly unenforced, and a same-user
//! staged-path replacement race is not excluded. Its records are always
//! unauthenticated and cannot authorize an allow decision. Restricted capture
//! bytes can also exist in detector-owned output buffers and allocator memory;
//! this crate does not claim comprehensive memory zeroization.

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use whoathere_artifact::{NormalizedArtifact, Sha256Digest};
use whoathere_detector::{
    ArtifactReviewChannelIsolationV2, ArtifactReviewModelIdentityV2,
    ArtifactReviewPrivacyPostureV2, ArtifactReviewProviderIdentityV2,
    ArtifactReviewProviderOutputV2, ArtifactReviewRequestV2, ArtifactReviewWorkItemStatusV2,
    ArtifactStaticAnalysis, MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2,
    MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2,
    MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2,
};
use whoathere_evidence::v2::ArtifactEvidenceSubjectV2;

pub const INERT_PROVIDER_ADAPTER_ID_V2: &str = "whoathere-inert-artifact-review-provider";
pub const INERT_PROVIDER_ADAPTER_VERSION_V2: &str = "1.0.0";
pub const INERT_PROVIDER_MODEL_ID_PREFIX_V2: &str = "whoathere-inert-fixture-";
pub const INERT_PROVIDER_MODEL_VERSION_V2: &str = "1.0.0";

pub const MAX_LOCAL_PROVIDER_EXECUTABLE_BYTES_V2: usize = 64 * 1024 * 1024;
pub const MAX_LOCAL_PROVIDER_STDERR_BYTES_V2: usize = 64 * 1024;
pub const MAX_LOCAL_PROVIDER_TOTAL_STDERR_BYTES_V2: usize = 2 * 1024 * 1024;
pub const MAX_LOCAL_PROVIDER_TOTAL_INPUT_BYTES_V2: usize = 64 * 1024 * 1024;
pub const MAX_LOCAL_PROVIDER_EVIDENCE_EXECUTION_ID_BYTES_V2: usize = 256;

const MAX_PER_CALL_TIMEOUT_V2: Duration = Duration::from_secs(5 * 60);
const MAX_GLOBAL_TIMEOUT_V2: Duration = Duration::from_secs(30 * 60);
const MAX_TERMINATION_GRACE_V2: Duration = Duration::from_secs(5);
const POLL_INTERVAL_MILLIS: i32 = 5;
const INERT_PROVIDER_READY_MARKER_V2: &[u8] = b"whoathere-inert-provider-ready-v2\n";

static RUN_DIRECTORY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderProtocolV2 {
    InertFixtureStdinV1,
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedLocalProviderV2 {
    request_sha256: Sha256Digest,
    provider: ArtifactReviewProviderIdentityV2,
    model: ArtifactReviewModelIdentityV2,
    executable_path: PathBuf,
    protocol: LocalProviderProtocolV2,
}

impl std::fmt::Debug for AuthorizedLocalProviderV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedLocalProviderV2")
            .field("request_sha256", &self.request_sha256)
            .field("provider_adapter_sha256", &self.provider.adapter_sha256)
            .field("model_content_sha256", &self.model.model_content_sha256)
            .field("protocol", &self.protocol)
            .field("executable_path", &"<redacted>")
            .finish()
    }
}

impl AuthorizedLocalProviderV2 {
    pub fn new_inert_fixture(
        request: &ArtifactReviewRequestV2,
        executable_path: PathBuf,
    ) -> Result<Self, LocalProviderRuntimeErrorV2> {
        let provider = request.provider().clone();
        let model = request.model().clone();
        if provider.adapter_id != INERT_PROVIDER_ADAPTER_ID_V2
            || provider.adapter_version != INERT_PROVIDER_ADAPTER_VERSION_V2
            || !is_supported_inert_fixture_model_id_v2(&model.model_id)
            || model.model_version != INERT_PROVIDER_MODEL_VERSION_V2
            || !executable_path.is_absolute()
        {
            return Err(LocalProviderRuntimeErrorV2::InvalidAuthorization);
        }
        if model.model_content_sha256
            != inert_fixture_model_content_sha256_v2(&provider.adapter_sha256, &model.model_id)?
        {
            return Err(LocalProviderRuntimeErrorV2::InvalidAuthorization);
        }
        Ok(Self {
            request_sha256: request
                .request_sha256()
                .map_err(|_| LocalProviderRuntimeErrorV2::InvalidAuthorization)?,
            provider,
            model,
            executable_path,
            protocol: LocalProviderProtocolV2::InertFixtureStdinV1,
        })
    }

    pub fn provider(&self) -> &ArtifactReviewProviderIdentityV2 {
        &self.provider
    }

    pub fn model(&self) -> &ArtifactReviewModelIdentityV2 {
        &self.model
    }

    pub fn protocol(&self) -> LocalProviderProtocolV2 {
        self.protocol
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct LocalProviderEvidenceExecutionBindingV2 {
    challenge_id: String,
    evidence_id: String,
    run_id: String,
    challenge_binding_sha256: Sha256Digest,
}

impl std::fmt::Debug for LocalProviderEvidenceExecutionBindingV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalProviderEvidenceExecutionBindingV2")
            .field(
                "challenge_id_sha256",
                &Sha256Digest::from_bytes(self.challenge_id.as_bytes()),
            )
            .field(
                "evidence_id_sha256",
                &Sha256Digest::from_bytes(self.evidence_id.as_bytes()),
            )
            .field(
                "run_id_sha256",
                &Sha256Digest::from_bytes(self.run_id.as_bytes()),
            )
            .field("challenge_binding_sha256", &self.challenge_binding_sha256)
            .finish()
    }
}

impl LocalProviderEvidenceExecutionBindingV2 {
    pub fn new(
        challenge_id: impl Into<String>,
        evidence_id: impl Into<String>,
        run_id: impl Into<String>,
        challenge_binding_sha256: Sha256Digest,
    ) -> Result<Self, LocalProviderRuntimeErrorV2> {
        let binding = Self {
            challenge_id: challenge_id.into(),
            evidence_id: evidence_id.into(),
            run_id: run_id.into(),
            challenge_binding_sha256,
        };
        if !valid_local_provider_evidence_execution_id_v2(&binding.challenge_id)
            || !valid_local_provider_evidence_execution_id_v2(&binding.evidence_id)
            || !valid_local_provider_evidence_execution_id_v2(&binding.run_id)
        {
            return Err(LocalProviderRuntimeErrorV2::InvalidEvidenceExecutionBinding);
        }
        Ok(binding)
    }

    pub fn challenge_id(&self) -> &str {
        &self.challenge_id
    }

    pub fn evidence_id(&self) -> &str {
        &self.evidence_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    pub fn challenge_binding_sha256(&self) -> &Sha256Digest {
        &self.challenge_binding_sha256
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn can_authorize_allow(&self) -> bool {
        false
    }
}

fn valid_local_provider_evidence_execution_id_v2(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_LOCAL_PROVIDER_EVIDENCE_EXECUTION_ID_BYTES_V2
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
        && value != "."
        && value != ".."
}

pub fn inert_fixture_model_content_sha256_v2(
    provider_adapter_sha256: &Sha256Digest,
    model_id: &str,
) -> Result<Sha256Digest, LocalProviderRuntimeErrorV2> {
    if !is_supported_inert_fixture_model_id_v2(model_id) {
        return Err(LocalProviderRuntimeErrorV2::InvalidAuthorization);
    }
    Ok(Sha256Digest::from_bytes(
        format!(
            "whoathere.inert_artifact_review_behavior.v2\0{}\0{}\0{}",
            provider_adapter_sha256, model_id, INERT_PROVIDER_MODEL_VERSION_V2
        )
        .as_bytes(),
    ))
}

fn is_supported_inert_fixture_model_id_v2(model_id: &str) -> bool {
    matches!(
        model_id,
        "whoathere-inert-fixture-echo"
            | "whoathere-inert-fixture-stderr"
            | "whoathere-inert-fixture-malformed"
            | "whoathere-inert-fixture-stdout-overflow"
            | "whoathere-inert-fixture-stderr-overflow"
            | "whoathere-inert-fixture-hang"
            | "whoathere-inert-fixture-ignore-term"
            | "whoathere-inert-fixture-nonzero"
            | "whoathere-inert-fixture-descendant"
            | "whoathere-inert-fixture-environment"
            | "whoathere-inert-fixture-prefix-then-block-next"
            | "whoathere-inert-fixture-fd-hygiene"
    )
}

#[derive(Clone, PartialEq, Eq)]
pub struct LocalProviderRuntimePolicyV2 {
    runtime_root: PathBuf,
    per_call_timeout: Duration,
    global_timeout: Duration,
    termination_grace: Duration,
}

impl std::fmt::Debug for LocalProviderRuntimePolicyV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalProviderRuntimePolicyV2")
            .field("runtime_root", &"<redacted>")
            .field("per_call_timeout", &self.per_call_timeout)
            .field("global_timeout", &self.global_timeout)
            .field("termination_grace", &self.termination_grace)
            .finish()
    }
}

impl LocalProviderRuntimePolicyV2 {
    pub fn new(
        runtime_root: PathBuf,
        per_call_timeout: Duration,
        global_timeout: Duration,
        termination_grace: Duration,
    ) -> Result<Self, LocalProviderRuntimeErrorV2> {
        if !runtime_root.is_absolute()
            || per_call_timeout.is_zero()
            || global_timeout.is_zero()
            || termination_grace.is_zero()
            || per_call_timeout > global_timeout
            || per_call_timeout > MAX_PER_CALL_TIMEOUT_V2
            || global_timeout > MAX_GLOBAL_TIMEOUT_V2
            || termination_grace > MAX_TERMINATION_GRACE_V2
        {
            return Err(LocalProviderRuntimeErrorV2::InvalidRuntimePolicy);
        }
        Ok(Self {
            runtime_root,
            per_call_timeout,
            global_timeout,
            termination_grace,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct ArtifactReviewCancellationTokenV2 {
    cancelled: Arc<AtomicBool>,
}

impl ArtifactReviewCancellationTokenV2 {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderTerminationReasonV2 {
    Completed,
    NonZeroExit,
    StdoutLimitExceeded,
    StderrLimitExceeded,
    PerCallTimeout,
    GlobalTimeout,
    Cancelled,
    InputWriteFailed,
    OutputReadFailed,
    ProtocolHandshakeFailed,
    LingeringProcessGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderTerminalPhaseV2 {
    Preflight,
    RunSetup,
    Invocation,
    RunDirectoryCleanup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderNetworkIsolationV2 {
    NotEnforcedCallerAuthorizedExecutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderHostIsolationV2 {
    NotSandboxedCallerAuthorizedExecutable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderModelIdentityPostureV2 {
    SyntheticBehaviorLabelBoundToVerifiedAdapterBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderResourceIsolationV2 {
    WallClockStreamCapsAndDescriptorClosureOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderExecutableIdentityPostureV2 {
    DigestVerifiedPrivateStagedPathSameUserRaceNotExcluded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProviderInvocationRecordV2 {
    request_sha256: Sha256Digest,
    invocation_sha256: Sha256Digest,
    work_item_id: Sha256Digest,
    provider_adapter_sha256: Sha256Digest,
    model_content_sha256: Sha256Digest,
    provider_input_sha256: Sha256Digest,
    provider_input_byte_len: u64,
    stdout_capture_sha256: Sha256Digest,
    stdout_capture_byte_len: u64,
    stderr_capture_sha256: Sha256Digest,
    stderr_capture_byte_len: u64,
    provider_output_status: ArtifactReviewWorkItemStatusV2,
    termination_reason: LocalProviderTerminationReasonV2,
    exit_code: Option<i32>,
    channel_isolation: ArtifactReviewChannelIsolationV2,
    stdout_eof_verified: bool,
    stderr_eof_verified: bool,
    process_group_cleanup_verified: bool,
    descendant_containment_verified: bool,
    kill_escalated: bool,
    network_isolation: LocalProviderNetworkIsolationV2,
    host_isolation: LocalProviderHostIsolationV2,
    model_identity_posture: LocalProviderModelIdentityPostureV2,
    resource_isolation: LocalProviderResourceIsolationV2,
    executable_identity_posture: LocalProviderExecutableIdentityPostureV2,
    elapsed_millis: u64,
}

impl LocalProviderInvocationRecordV2 {
    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn work_item_id(&self) -> &Sha256Digest {
        &self.work_item_id
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn invocation_sha256(&self) -> &Sha256Digest {
        &self.invocation_sha256
    }

    pub fn provider_input_sha256(&self) -> &Sha256Digest {
        &self.provider_input_sha256
    }

    pub fn provider_input_byte_len(&self) -> u64 {
        self.provider_input_byte_len
    }

    pub fn stdout_capture_sha256(&self) -> &Sha256Digest {
        &self.stdout_capture_sha256
    }

    pub fn stdout_capture_byte_len(&self) -> u64 {
        self.stdout_capture_byte_len
    }

    pub fn stderr_capture_sha256(&self) -> &Sha256Digest {
        &self.stderr_capture_sha256
    }

    pub fn stderr_capture_byte_len(&self) -> u64 {
        self.stderr_capture_byte_len
    }

    pub fn provider_output_status(&self) -> ArtifactReviewWorkItemStatusV2 {
        self.provider_output_status
    }

    pub fn termination_reason(&self) -> LocalProviderTerminationReasonV2 {
        self.termination_reason
    }

    pub fn exit_code(&self) -> Option<i32> {
        self.exit_code
    }

    pub fn channel_isolation(&self) -> ArtifactReviewChannelIsolationV2 {
        self.channel_isolation
    }

    pub fn stdout_eof_verified(&self) -> bool {
        self.stdout_eof_verified
    }

    pub fn stderr_eof_verified(&self) -> bool {
        self.stderr_eof_verified
    }

    pub fn process_group_cleanup_verified(&self) -> bool {
        self.process_group_cleanup_verified
    }

    pub fn descendant_containment_verified(&self) -> bool {
        self.descendant_containment_verified
    }

    pub fn kill_escalated(&self) -> bool {
        self.kill_escalated
    }

    pub fn network_isolation(&self) -> LocalProviderNetworkIsolationV2 {
        self.network_isolation
    }

    pub fn host_isolation(&self) -> LocalProviderHostIsolationV2 {
        self.host_isolation
    }

    pub fn model_identity_posture(&self) -> LocalProviderModelIdentityPostureV2 {
        self.model_identity_posture
    }

    pub fn resource_isolation(&self) -> LocalProviderResourceIsolationV2 {
        self.resource_isolation
    }

    pub fn executable_identity_posture(&self) -> LocalProviderExecutableIdentityPostureV2 {
        self.executable_identity_posture
    }

    pub fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }

    pub fn provider_adapter_sha256(&self) -> &Sha256Digest {
        &self.provider_adapter_sha256
    }

    pub fn model_content_sha256(&self) -> &Sha256Digest {
        &self.model_content_sha256
    }
}

/// Exact classification of every work item planned by a local provider run.
///
/// Construction rejects unknown, duplicate, missing, or multiply classified
/// identifiers. This is structural bookkeeping only; it is unauthenticated
/// and cannot authorize an allow decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProviderWorkPartitionV2 {
    expected_work_item_ids: Vec<Sha256Digest>,
    recorded_work_item_ids: Vec<Sha256Digest>,
    attempted_without_capture_work_item_ids: Vec<Sha256Digest>,
    unattempted_work_item_ids: Vec<Sha256Digest>,
}

impl LocalProviderWorkPartitionV2 {
    pub fn new(
        expected_work_item_ids: Vec<Sha256Digest>,
        recorded_work_item_ids: Vec<Sha256Digest>,
        attempted_without_capture_work_item_ids: Vec<Sha256Digest>,
        unattempted_work_item_ids: Vec<Sha256Digest>,
    ) -> Result<Self, LocalProviderRuntimeErrorV2> {
        if expected_work_item_ids.iter().collect::<HashSet<_>>().len()
            != expected_work_item_ids.len()
            || recorded_work_item_ids.len() > expected_work_item_ids.len()
            || recorded_work_item_ids != expected_work_item_ids[..recorded_work_item_ids.len()]
        {
            return Err(LocalProviderRuntimeErrorV2::InvalidWorkPartition);
        }

        let next_index = recorded_work_item_ids.len();
        let suffix_is_exact = match attempted_without_capture_work_item_ids.as_slice() {
            [] => unattempted_work_item_ids == expected_work_item_ids[next_index..],
            [attempted] => {
                expected_work_item_ids.get(next_index) == Some(attempted)
                    && unattempted_work_item_ids == expected_work_item_ids[next_index + 1..]
            }
            _ => false,
        };
        if !suffix_is_exact {
            return Err(LocalProviderRuntimeErrorV2::InvalidWorkPartition);
        }

        Ok(Self {
            expected_work_item_ids,
            recorded_work_item_ids,
            attempted_without_capture_work_item_ids,
            unattempted_work_item_ids,
        })
    }

    pub fn expected_work_item_ids(&self) -> &[Sha256Digest] {
        &self.expected_work_item_ids
    }

    pub fn recorded_work_item_ids(&self) -> &[Sha256Digest] {
        &self.recorded_work_item_ids
    }

    pub fn attempted_without_capture_work_item_ids(&self) -> &[Sha256Digest] {
        &self.attempted_without_capture_work_item_ids
    }

    pub fn unattempted_work_item_ids(&self) -> &[Sha256Digest] {
        &self.unattempted_work_item_ids
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn can_authorize_allow(&self) -> bool {
        false
    }
}

/// Raw bounded provider streams retained for a future trusted verifier.
///
/// The bytes are intentionally inaccessible through ordinary getters and are
/// never included in `Debug`. A verifier must explicitly consume the capture
/// and handle the restricted byte view synchronously. These buffers and the
/// duplicate detector-output buffers are not guaranteed to be zeroized on
/// drop; a future verifier must minimize their lifetime and treat process
/// memory as restricted.
pub struct RestrictedLocalProviderCaptureV2 {
    work_item_id: Sha256Digest,
    stdout_capture: Vec<u8>,
    stderr_capture: Vec<u8>,
}

impl std::fmt::Debug for RestrictedLocalProviderCaptureV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestrictedLocalProviderCaptureV2")
            .field("work_item_id", &self.work_item_id)
            .field("stdout_capture_sha256", &self.stdout_capture_sha256())
            .field("stdout_capture_byte_len", &self.stdout_capture.len())
            .field("stderr_capture_sha256", &self.stderr_capture_sha256())
            .field("stderr_capture_byte_len", &self.stderr_capture.len())
            .field("stdout_capture", &"<restricted>")
            .field("stderr_capture", &"<restricted>")
            .finish()
    }
}

impl RestrictedLocalProviderCaptureV2 {
    fn new(
        work_item_id: Sha256Digest,
        stdout_capture: Vec<u8>,
        stderr_capture: Vec<u8>,
    ) -> Result<Self, LocalProviderRuntimeErrorV2> {
        if stdout_capture.len() > MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2
            || stderr_capture.len() > MAX_LOCAL_PROVIDER_STDERR_BYTES_V2
        {
            return Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence);
        }
        Ok(Self {
            work_item_id,
            stdout_capture,
            stderr_capture,
        })
    }

    pub fn work_item_id(&self) -> &Sha256Digest {
        &self.work_item_id
    }

    pub fn stdout_capture_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&self.stdout_capture)
    }

    pub fn stdout_capture_byte_len(&self) -> u64 {
        self.stdout_capture.len() as u64
    }

    pub fn stderr_capture_sha256(&self) -> Sha256Digest {
        Sha256Digest::from_bytes(&self.stderr_capture)
    }

    pub fn stderr_capture_byte_len(&self) -> u64 {
        self.stderr_capture.len() as u64
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn can_authorize_allow(&self) -> bool {
        false
    }

    pub fn consume<R>(
        self,
        consumer: impl FnOnce(RestrictedLocalProviderCaptureViewV2<'_>) -> R,
    ) -> R {
        consumer(RestrictedLocalProviderCaptureViewV2 {
            work_item_id: &self.work_item_id,
            stdout_capture: &self.stdout_capture,
            stderr_capture: &self.stderr_capture,
        })
    }
}

pub struct RestrictedLocalProviderCaptureViewV2<'a> {
    work_item_id: &'a Sha256Digest,
    stdout_capture: &'a [u8],
    stderr_capture: &'a [u8],
}

impl std::fmt::Debug for RestrictedLocalProviderCaptureViewV2<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RestrictedLocalProviderCaptureViewV2")
            .field("work_item_id", self.work_item_id)
            .field(
                "stdout_capture_sha256",
                &Sha256Digest::from_bytes(self.stdout_capture),
            )
            .field("stdout_capture_byte_len", &self.stdout_capture.len())
            .field(
                "stderr_capture_sha256",
                &Sha256Digest::from_bytes(self.stderr_capture),
            )
            .field("stderr_capture_byte_len", &self.stderr_capture.len())
            .field("stdout_capture", &"<restricted>")
            .field("stderr_capture", &"<restricted>")
            .finish()
    }
}

impl RestrictedLocalProviderCaptureViewV2<'_> {
    pub fn work_item_id(&self) -> &Sha256Digest {
        self.work_item_id
    }

    pub fn stdout_bytes(&self) -> &[u8] {
        self.stdout_capture
    }

    pub fn stderr_bytes(&self) -> &[u8] {
        self.stderr_capture
    }
}

pub struct LocalProviderRunV2 {
    provider_outputs: Vec<ArtifactReviewProviderOutputV2>,
    invocation_records: Vec<LocalProviderInvocationRecordV2>,
    restricted_captures: Vec<RestrictedLocalProviderCaptureV2>,
    work_partition: LocalProviderWorkPartitionV2,
    terminal_error: Option<LocalProviderRuntimeErrorV2>,
    terminal_phase: Option<LocalProviderTerminalPhaseV2>,
    terminal_error_work_item_id: Option<Sha256Digest>,
    run_directory_cleanup_verified: bool,
    secondary_cleanup_error: Option<LocalProviderRuntimeErrorV2>,
}

impl std::fmt::Debug for LocalProviderRunV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalProviderRunV2")
            .field("provider_output_count", &self.provider_outputs.len())
            .field("invocation_record_count", &self.invocation_records.len())
            .field("restricted_capture_count", &self.restricted_captures.len())
            .field(
                "attempted_without_capture_work_item_count",
                &self
                    .work_partition
                    .attempted_without_capture_work_item_ids
                    .len(),
            )
            .field(
                "unattempted_work_item_count",
                &self.work_partition.unattempted_work_item_ids.len(),
            )
            .field("terminal_error", &self.terminal_error)
            .field("terminal_phase", &self.terminal_phase)
            .field(
                "terminal_error_has_work_item",
                &self.terminal_error_work_item_id.is_some(),
            )
            .field(
                "run_directory_cleanup_verified",
                &self.run_directory_cleanup_verified,
            )
            .field("secondary_cleanup_error", &self.secondary_cleanup_error)
            .field("provider_output_bytes", &"<redacted>")
            .finish()
    }
}

impl LocalProviderRunV2 {
    pub fn provider_outputs(&self) -> &[ArtifactReviewProviderOutputV2] {
        &self.provider_outputs
    }

    pub fn invocation_records(&self) -> &[LocalProviderInvocationRecordV2] {
        &self.invocation_records
    }

    pub fn restricted_captures(&self) -> &[RestrictedLocalProviderCaptureV2] {
        &self.restricted_captures
    }

    pub fn work_partition(&self) -> &LocalProviderWorkPartitionV2 {
        &self.work_partition
    }

    pub fn expected_work_item_ids(&self) -> &[Sha256Digest] {
        self.work_partition.expected_work_item_ids()
    }

    pub fn recorded_work_item_ids(&self) -> &[Sha256Digest] {
        self.work_partition.recorded_work_item_ids()
    }

    pub fn attempted_without_capture_work_item_ids(&self) -> &[Sha256Digest] {
        self.work_partition
            .attempted_without_capture_work_item_ids()
    }

    pub fn unattempted_work_item_ids(&self) -> &[Sha256Digest] {
        self.work_partition.unattempted_work_item_ids()
    }

    pub fn terminal_error(&self) -> Option<LocalProviderRuntimeErrorV2> {
        self.terminal_error
    }

    pub fn terminal_phase(&self) -> Option<LocalProviderTerminalPhaseV2> {
        self.terminal_phase
    }

    pub fn terminal_error_work_item_id(&self) -> Option<&Sha256Digest> {
        self.terminal_error_work_item_id.as_ref()
    }

    pub fn run_directory_cleanup_verified(&self) -> bool {
        self.run_directory_cleanup_verified
    }

    pub fn secondary_cleanup_error(&self) -> Option<LocalProviderRuntimeErrorV2> {
        self.secondary_cleanup_error
    }

    /// Returns true only when every planned provider work item was dispatched
    /// without a runtime/cleanup error. This is not a clean or safe verdict.
    pub fn is_dispatch_complete(&self) -> bool {
        self.terminal_error.is_none()
            && self.secondary_cleanup_error.is_none()
            && self
                .work_partition
                .attempted_without_capture_work_item_ids
                .is_empty()
            && self.work_partition.unattempted_work_item_ids.is_empty()
            && self.work_partition.recorded_work_item_ids.len()
                == self.work_partition.expected_work_item_ids.len()
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn can_authorize_allow(&self) -> bool {
        false
    }

    pub fn into_provider_outputs(self) -> Vec<ArtifactReviewProviderOutputV2> {
        self.provider_outputs
    }

    /// Consumes the run and transfers its restricted raw captures to a future
    /// verifier. Prefer `into_evidence_parts` when the verifier must retain the
    /// records, partition, and terminal state alongside those captures.
    pub fn into_restricted_captures(self) -> Vec<RestrictedLocalProviderCaptureV2> {
        self.restricted_captures
    }

    /// Atomically transfers every runtime evidence component into an owned,
    /// still-unauthenticated verifier input.
    pub fn into_evidence_parts(self) -> LocalProviderRunEvidencePartsV2 {
        LocalProviderRunEvidencePartsV2 {
            provider_outputs: self.provider_outputs,
            invocation_records: self.invocation_records,
            restricted_captures: self.restricted_captures,
            work_partition: self.work_partition,
            terminal_state: LocalProviderRunTerminalStateV2 {
                terminal_error: self.terminal_error,
                terminal_phase: self.terminal_phase,
                terminal_error_work_item_id: self.terminal_error_work_item_id,
                run_directory_cleanup_verified: self.run_directory_cleanup_verified,
                secondary_cleanup_error: self.secondary_cleanup_error,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalProviderRunTerminalStateV2 {
    terminal_error: Option<LocalProviderRuntimeErrorV2>,
    terminal_phase: Option<LocalProviderTerminalPhaseV2>,
    terminal_error_work_item_id: Option<Sha256Digest>,
    run_directory_cleanup_verified: bool,
    secondary_cleanup_error: Option<LocalProviderRuntimeErrorV2>,
}

impl LocalProviderRunTerminalStateV2 {
    pub fn terminal_error(&self) -> Option<LocalProviderRuntimeErrorV2> {
        self.terminal_error
    }

    pub fn terminal_phase(&self) -> Option<LocalProviderTerminalPhaseV2> {
        self.terminal_phase
    }

    pub fn terminal_error_work_item_id(&self) -> Option<&Sha256Digest> {
        self.terminal_error_work_item_id.as_ref()
    }

    pub fn run_directory_cleanup_verified(&self) -> bool {
        self.run_directory_cleanup_verified
    }

    pub fn secondary_cleanup_error(&self) -> Option<LocalProviderRuntimeErrorV2> {
        self.secondary_cleanup_error
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn can_authorize_allow(&self) -> bool {
        false
    }
}

pub struct LocalProviderRunEvidencePartsV2 {
    provider_outputs: Vec<ArtifactReviewProviderOutputV2>,
    invocation_records: Vec<LocalProviderInvocationRecordV2>,
    restricted_captures: Vec<RestrictedLocalProviderCaptureV2>,
    work_partition: LocalProviderWorkPartitionV2,
    terminal_state: LocalProviderRunTerminalStateV2,
}

impl std::fmt::Debug for LocalProviderRunEvidencePartsV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LocalProviderRunEvidencePartsV2")
            .field("provider_output_count", &self.provider_outputs.len())
            .field("invocation_record_count", &self.invocation_records.len())
            .field("restricted_capture_count", &self.restricted_captures.len())
            .field("work_partition", &self.work_partition)
            .field("terminal_state", &self.terminal_state)
            .field("provider_output_bytes", &"<redacted>")
            .field("restricted_capture_bytes", &"<restricted>")
            .finish()
    }
}

pub type LocalProviderRunEvidenceComponentsV2 = (
    Vec<ArtifactReviewProviderOutputV2>,
    Vec<LocalProviderInvocationRecordV2>,
    Vec<RestrictedLocalProviderCaptureV2>,
    LocalProviderWorkPartitionV2,
    LocalProviderRunTerminalStateV2,
);

impl LocalProviderRunEvidencePartsV2 {
    pub fn provider_outputs(&self) -> &[ArtifactReviewProviderOutputV2] {
        &self.provider_outputs
    }

    pub fn invocation_records(&self) -> &[LocalProviderInvocationRecordV2] {
        &self.invocation_records
    }

    pub fn restricted_captures(&self) -> &[RestrictedLocalProviderCaptureV2] {
        &self.restricted_captures
    }

    pub fn work_partition(&self) -> &LocalProviderWorkPartitionV2 {
        &self.work_partition
    }

    pub fn terminal_state(&self) -> &LocalProviderRunTerminalStateV2 {
        &self.terminal_state
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn can_authorize_allow(&self) -> bool {
        false
    }

    pub fn into_parts(self) -> LocalProviderRunEvidenceComponentsV2 {
        (
            self.provider_outputs,
            self.invocation_records,
            self.restricted_captures,
            self.work_partition,
            self.terminal_state,
        )
    }
}

/// A local provider run whose evidence identity was fixed before execution.
///
/// There is deliberately no conversion from `LocalProviderRunV2`; only
/// `run_local_provider_for_evidence_v2` can construct this type.
///
/// ```compile_fail
/// use whoathere_artifact_review_runtime::{
///     EvidenceBoundLocalProviderRunV2, LocalProviderRunV2,
/// };
/// fn wrap_after_execution(run: LocalProviderRunV2) -> EvidenceBoundLocalProviderRunV2 {
///     run.into()
/// }
/// ```
pub struct EvidenceBoundLocalProviderRunV2 {
    binding: LocalProviderEvidenceExecutionBindingV2,
    started_at_unix_seconds: u64,
    finished_at_unix_seconds: u64,
    run: LocalProviderRunV2,
}

impl std::fmt::Debug for EvidenceBoundLocalProviderRunV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EvidenceBoundLocalProviderRunV2")
            .field("binding", &self.binding)
            .field("started_at_unix_seconds", &self.started_at_unix_seconds)
            .field("finished_at_unix_seconds", &self.finished_at_unix_seconds)
            .field("run", &self.run)
            .finish()
    }
}

impl EvidenceBoundLocalProviderRunV2 {
    pub fn binding(&self) -> &LocalProviderEvidenceExecutionBindingV2 {
        &self.binding
    }

    pub fn started_at_unix_seconds(&self) -> u64 {
        self.started_at_unix_seconds
    }

    pub fn finished_at_unix_seconds(&self) -> u64 {
        self.finished_at_unix_seconds
    }

    pub fn local_provider_run(&self) -> &LocalProviderRunV2 {
        &self.run
    }

    pub fn is_authenticated(&self) -> bool {
        false
    }

    pub fn can_authorize_allow(&self) -> bool {
        false
    }

    pub fn into_parts(
        self,
    ) -> (
        LocalProviderEvidenceExecutionBindingV2,
        u64,
        u64,
        LocalProviderRunV2,
    ) {
        (
            self.binding,
            self.started_at_unix_seconds,
            self.finished_at_unix_seconds,
            self.run,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalProviderRuntimeErrorV2 {
    InvalidRequest,
    InvalidAuthorization,
    InvalidEvidenceExecutionBinding,
    AuthorizationMismatch,
    HostedReviewNotAuthorized,
    InvalidRuntimePolicy,
    UnsupportedPlatform,
    RuntimeRootInvalid,
    RunDirectoryCreationFailed,
    RunDirectoryCleanupFailed,
    ExecutableOpenFailed,
    ExecutableMetadataInvalid,
    ExecutableLimitExceeded,
    ExecutableDigestMismatch,
    ExecutableStagingFailed,
    ProviderInputInvalid,
    ProviderCaptureInvalid,
    InvalidWorkPartition,
    InvalidRunEvidence,
    SystemClockInvalid,
    ProcessSpawnFailed,
    ProcessControlFailed,
    ProcessCleanupFailed,
}

impl LocalProviderRuntimeErrorV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidRequest => "artifact_review_local_runtime_request_invalid",
            Self::InvalidAuthorization => "artifact_review_local_runtime_authorization_invalid",
            Self::InvalidEvidenceExecutionBinding => {
                "artifact_review_local_runtime_evidence_execution_binding_invalid"
            }
            Self::AuthorizationMismatch => "artifact_review_local_runtime_authorization_mismatch",
            Self::HostedReviewNotAuthorized => {
                "artifact_review_local_runtime_hosted_review_not_authorized"
            }
            Self::InvalidRuntimePolicy => "artifact_review_local_runtime_policy_invalid",
            Self::UnsupportedPlatform => "artifact_review_local_runtime_platform_unsupported",
            Self::RuntimeRootInvalid => "artifact_review_local_runtime_root_invalid",
            Self::RunDirectoryCreationFailed => {
                "artifact_review_local_runtime_run_directory_creation_failed"
            }
            Self::RunDirectoryCleanupFailed => {
                "artifact_review_local_runtime_run_directory_cleanup_failed"
            }
            Self::ExecutableOpenFailed => "artifact_review_local_runtime_executable_open_failed",
            Self::ExecutableMetadataInvalid => {
                "artifact_review_local_runtime_executable_metadata_invalid"
            }
            Self::ExecutableLimitExceeded => {
                "artifact_review_local_runtime_executable_limit_exceeded"
            }
            Self::ExecutableDigestMismatch => {
                "artifact_review_local_runtime_executable_digest_mismatch"
            }
            Self::ExecutableStagingFailed => {
                "artifact_review_local_runtime_executable_staging_failed"
            }
            Self::ProviderInputInvalid => "artifact_review_local_runtime_provider_input_invalid",
            Self::ProviderCaptureInvalid => {
                "artifact_review_local_runtime_provider_capture_invalid"
            }
            Self::InvalidWorkPartition => "artifact_review_local_runtime_work_partition_invalid",
            Self::InvalidRunEvidence => "artifact_review_local_runtime_run_evidence_invalid",
            Self::SystemClockInvalid => "artifact_review_local_runtime_system_clock_invalid",
            Self::ProcessSpawnFailed => "artifact_review_local_runtime_process_spawn_failed",
            Self::ProcessControlFailed => "artifact_review_local_runtime_process_control_failed",
            Self::ProcessCleanupFailed => "artifact_review_local_runtime_process_cleanup_failed",
        }
    }
}

impl std::fmt::Display for LocalProviderRuntimeErrorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for LocalProviderRuntimeErrorV2 {}

struct PreparedInvocationV2 {
    work_item_id: Sha256Digest,
    invocation_sha256: Sha256Digest,
    provider_input: Vec<u8>,
}

fn unattempted_work_item_ids_from(
    request: &ArtifactReviewRequestV2,
    start: usize,
) -> Vec<Sha256Digest> {
    request.work_items()[start..]
        .iter()
        .map(|item| item.work_item_id().clone())
        .collect()
}

fn expected_work_item_ids(request: &ArtifactReviewRequestV2) -> Vec<Sha256Digest> {
    unattempted_work_item_ids_from(request, 0)
}

fn validate_terminal_work_item_binding(
    work_partition: &LocalProviderWorkPartitionV2,
    terminal_error: Option<LocalProviderRuntimeErrorV2>,
    terminal_phase: Option<LocalProviderTerminalPhaseV2>,
    terminal_error_work_item_id: Option<&Sha256Digest>,
) -> Result<(), LocalProviderRuntimeErrorV2> {
    let all_work_unattempted = work_partition.recorded_work_item_ids().is_empty()
        && work_partition
            .attempted_without_capture_work_item_ids()
            .is_empty()
        && work_partition.unattempted_work_item_ids() == work_partition.expected_work_item_ids();
    let valid = match (terminal_error, terminal_phase) {
        (None, None) => {
            terminal_error_work_item_id.is_none()
                && work_partition
                    .attempted_without_capture_work_item_ids()
                    .is_empty()
        }
        (Some(_), Some(LocalProviderTerminalPhaseV2::Preflight)) => {
            all_work_unattempted
                && terminal_error_work_item_id.is_some_and(|work_item_id| {
                    work_partition
                        .expected_work_item_ids()
                        .contains(work_item_id)
                })
        }
        (Some(_), Some(LocalProviderTerminalPhaseV2::RunSetup)) => {
            all_work_unattempted && terminal_error_work_item_id.is_none()
        }
        (Some(_), Some(LocalProviderTerminalPhaseV2::Invocation)) => {
            let next_terminal_item = work_partition
                .attempted_without_capture_work_item_ids()
                .first()
                .or_else(|| work_partition.unattempted_work_item_ids().first());
            terminal_error_work_item_id.is_some()
                && terminal_error_work_item_id == next_terminal_item
        }
        (Some(_), Some(LocalProviderTerminalPhaseV2::RunDirectoryCleanup)) => {
            terminal_error_work_item_id.is_none()
                && work_partition
                    .attempted_without_capture_work_item_ids()
                    .is_empty()
        }
        _ => false,
    };
    valid
        .then_some(())
        .ok_or(LocalProviderRuntimeErrorV2::InvalidRunEvidence)
}

fn all_unattempted_terminal_run(
    request: &ArtifactReviewRequestV2,
    primary_error: LocalProviderRuntimeErrorV2,
    run_directory_cleanup_verified: bool,
    secondary_cleanup_error: Option<LocalProviderRuntimeErrorV2>,
) -> Result<LocalProviderRunV2, LocalProviderRuntimeErrorV2> {
    new_validated_local_provider_run(
        expected_work_item_ids(request),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        unattempted_work_item_ids_from(request, 0),
        Some(primary_error),
        Some(LocalProviderTerminalPhaseV2::RunSetup),
        None,
        run_directory_cleanup_verified,
        secondary_cleanup_error,
    )
}

fn all_unattempted_preflight_failure_run(
    request: &ArtifactReviewRequestV2,
    primary_error: LocalProviderRuntimeErrorV2,
    failing_work_item_id: Sha256Digest,
) -> Result<LocalProviderRunV2, LocalProviderRuntimeErrorV2> {
    new_validated_local_provider_run(
        expected_work_item_ids(request),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        unattempted_work_item_ids_from(request, 0),
        Some(primary_error),
        Some(LocalProviderTerminalPhaseV2::Preflight),
        Some(failing_work_item_id),
        true,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn new_validated_local_provider_run(
    expected_work_item_ids: Vec<Sha256Digest>,
    provider_outputs: Vec<ArtifactReviewProviderOutputV2>,
    invocation_records: Vec<LocalProviderInvocationRecordV2>,
    restricted_captures: Vec<RestrictedLocalProviderCaptureV2>,
    attempted_without_capture_work_item_ids: Vec<Sha256Digest>,
    unattempted_work_item_ids: Vec<Sha256Digest>,
    terminal_error: Option<LocalProviderRuntimeErrorV2>,
    terminal_phase: Option<LocalProviderTerminalPhaseV2>,
    terminal_error_work_item_id: Option<Sha256Digest>,
    run_directory_cleanup_verified: bool,
    secondary_cleanup_error: Option<LocalProviderRuntimeErrorV2>,
) -> Result<LocalProviderRunV2, LocalProviderRuntimeErrorV2> {
    if provider_outputs.len() != invocation_records.len()
        || invocation_records.len() != restricted_captures.len()
    {
        return Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence);
    }

    let mut total_stdout_bytes = 0usize;
    let mut total_stderr_bytes = 0usize;
    for ((output, record), capture) in provider_outputs
        .iter()
        .zip(&invocation_records)
        .zip(&restricted_captures)
    {
        let expected_output_status = match record.termination_reason() {
            LocalProviderTerminationReasonV2::Completed => {
                ArtifactReviewWorkItemStatusV2::Completed
            }
            LocalProviderTerminationReasonV2::StdoutLimitExceeded => {
                ArtifactReviewWorkItemStatusV2::Truncated
            }
            _ => ArtifactReviewWorkItemStatusV2::Failed,
        };
        let eof_claims_consistent = match record.termination_reason() {
            LocalProviderTerminationReasonV2::Completed
            | LocalProviderTerminationReasonV2::NonZeroExit => {
                record.stdout_eof_verified() && record.stderr_eof_verified()
            }
            LocalProviderTerminationReasonV2::StdoutLimitExceeded => !record.stdout_eof_verified(),
            LocalProviderTerminationReasonV2::StderrLimitExceeded => !record.stderr_eof_verified(),
            _ => true,
        };
        total_stdout_bytes = total_stdout_bytes
            .checked_add(output.captured_output_len())
            .ok_or(LocalProviderRuntimeErrorV2::InvalidRunEvidence)?;
        total_stderr_bytes = total_stderr_bytes
            .checked_add(capture.stderr_capture.len())
            .ok_or(LocalProviderRuntimeErrorV2::InvalidRunEvidence)?;
        if output.work_item_id() != record.work_item_id()
            || output.work_item_id() != capture.work_item_id()
            || output.status() != record.provider_output_status()
            || output.status() != expected_output_status
            || !eof_claims_consistent
            || output.captured_output_sha256() != record.stdout_capture_sha256().clone()
            || output.captured_output_len() as u64 != record.stdout_capture_byte_len()
            || capture.stdout_capture_sha256() != record.stdout_capture_sha256().clone()
            || capture.stdout_capture_byte_len() != record.stdout_capture_byte_len()
            || capture.stderr_capture_sha256() != record.stderr_capture_sha256().clone()
            || capture.stderr_capture_byte_len() != record.stderr_capture_byte_len()
        {
            return Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence);
        }
    }
    if total_stdout_bytes > MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2
        || total_stderr_bytes > MAX_LOCAL_PROVIDER_TOTAL_STDERR_BYTES_V2
    {
        return Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence);
    }

    let recorded_work_item_ids = invocation_records
        .iter()
        .map(|record| record.work_item_id().clone())
        .collect::<Vec<_>>();
    let work_partition = LocalProviderWorkPartitionV2::new(
        expected_work_item_ids,
        recorded_work_item_ids,
        attempted_without_capture_work_item_ids,
        unattempted_work_item_ids,
    )?;
    validate_terminal_work_item_binding(
        &work_partition,
        terminal_error,
        terminal_phase,
        terminal_error_work_item_id.as_ref(),
    )?;

    Ok(LocalProviderRunV2 {
        provider_outputs,
        invocation_records,
        restricted_captures,
        work_partition,
        terminal_error,
        terminal_phase,
        terminal_error_work_item_id,
        run_directory_cleanup_verified,
        secondary_cleanup_error,
    })
}

pub fn run_local_provider_v2(
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    authorization: &AuthorizedLocalProviderV2,
    policy: &LocalProviderRuntimePolicyV2,
    cancellation: &ArtifactReviewCancellationTokenV2,
) -> Result<LocalProviderRunV2, LocalProviderRuntimeErrorV2> {
    if !cfg!(target_os = "macos") {
        return Err(LocalProviderRuntimeErrorV2::UnsupportedPlatform);
    }
    let started = Instant::now();
    let global_deadline = started
        .checked_add(policy.global_timeout)
        .ok_or(LocalProviderRuntimeErrorV2::InvalidRuntimePolicy)?;
    request
        .validate(subject, artifact, analysis)
        .map_err(|_| LocalProviderRuntimeErrorV2::InvalidRequest)?;
    if request.privacy_posture() != ArtifactReviewPrivacyPostureV2::LocalOnly {
        return Err(LocalProviderRuntimeErrorV2::HostedReviewNotAuthorized);
    }
    if request.provider() != authorization.provider()
        || request.model() != authorization.model()
        || authorization.protocol() != LocalProviderProtocolV2::InertFixtureStdinV1
        || &request
            .request_sha256()
            .map_err(|_| LocalProviderRuntimeErrorV2::InvalidRequest)?
            != authorization.request_sha256()
    {
        return Err(LocalProviderRuntimeErrorV2::AuthorizationMismatch);
    }
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| LocalProviderRuntimeErrorV2::InvalidRequest)?;
    if cancellation.is_cancelled() || Instant::now() >= global_deadline {
        return new_validated_local_provider_run(
            expected_work_item_ids(request),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            unattempted_work_item_ids_from(request, 0),
            None,
            None,
            None,
            true,
            None,
        );
    }

    let mut prepared = Vec::new();
    let mut total_input_bytes = 0usize;
    let mut preflight_stopped = false;
    for work_item in request.work_items() {
        if cancellation.is_cancelled() || Instant::now() >= global_deadline {
            preflight_stopped = true;
            break;
        }
        let failing_work_item_id = work_item.work_item_id().clone();
        let invocation = match request.invocation(artifact, work_item.work_item_id()) {
            Ok(invocation) => invocation,
            Err(_) => {
                return all_unattempted_preflight_failure_run(
                    request,
                    LocalProviderRuntimeErrorV2::InvalidRequest,
                    failing_work_item_id,
                );
            }
        };
        let provider_input = match invocation.canonical_provider_input_json_v2() {
            Ok(provider_input) => provider_input,
            Err(_) => {
                return all_unattempted_preflight_failure_run(
                    request,
                    LocalProviderRuntimeErrorV2::ProviderInputInvalid,
                    failing_work_item_id,
                );
            }
        };
        if provider_input.len() > MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2 {
            return all_unattempted_preflight_failure_run(
                request,
                LocalProviderRuntimeErrorV2::ProviderInputInvalid,
                failing_work_item_id,
            );
        }
        let Some(next_total) = total_input_bytes.checked_add(provider_input.len()) else {
            return all_unattempted_preflight_failure_run(
                request,
                LocalProviderRuntimeErrorV2::ProviderInputInvalid,
                failing_work_item_id,
            );
        };
        if next_total > MAX_LOCAL_PROVIDER_TOTAL_INPUT_BYTES_V2 {
            return all_unattempted_preflight_failure_run(
                request,
                LocalProviderRuntimeErrorV2::ProviderInputInvalid,
                failing_work_item_id,
            );
        }
        total_input_bytes = next_total;
        prepared.push(PreparedInvocationV2 {
            work_item_id: work_item.work_item_id().clone(),
            invocation_sha256: invocation.invocation_sha256().clone(),
            provider_input,
        });
    }
    if preflight_stopped {
        return new_validated_local_provider_run(
            expected_work_item_ids(request),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            unattempted_work_item_ids_from(request, 0),
            None,
            None,
            None,
            true,
            None,
        );
    }

    if let Err(error) = ensure_private_runtime_root(&policy.runtime_root) {
        return all_unattempted_terminal_run(request, error, true, None);
    }
    let run_directory = match create_private_run_directory(&policy.runtime_root) {
        Ok(run_directory) => run_directory,
        Err(failure) => {
            return all_unattempted_terminal_run(
                request,
                failure.primary_error,
                failure.run_directory_cleanup_verified,
                failure.secondary_cleanup_error,
            );
        }
    };
    let mut run_directory_guard = RunDirectoryGuard::new(run_directory.clone());
    let staged_executable = match stage_verified_executable(
        &authorization.executable_path,
        &run_directory,
        &authorization.provider.adapter_sha256,
    ) {
        Ok(executable) => executable,
        Err(primary_error) => {
            let (run_directory_cleanup_verified, secondary_cleanup_error) =
                match run_directory_guard.cleanup() {
                    Ok(()) => (true, None),
                    Err(cleanup_error) => (false, Some(cleanup_error)),
                };
            return all_unattempted_terminal_run(
                request,
                primary_error,
                run_directory_cleanup_verified,
                secondary_cleanup_error,
            );
        }
    };

    let mut provider_outputs = Vec::new();
    let mut invocation_records = Vec::new();
    let mut restricted_captures = Vec::new();
    let mut attempted_without_capture_work_item_ids = Vec::new();
    let mut unattempted_work_item_ids = unattempted_work_item_ids_from(request, prepared.len());
    let mut terminal_error = None;
    let mut terminal_phase = None;
    let mut terminal_error_work_item_id = None;
    let mut total_stdout_bytes = 0usize;
    let mut total_stderr_bytes = 0usize;

    for (index, prepared_invocation) in prepared.iter().enumerate() {
        if cancellation.is_cancelled()
            || Instant::now() >= global_deadline
            || total_stdout_bytes >= MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2
            || total_stderr_bytes >= MAX_LOCAL_PROVIDER_TOTAL_STDERR_BYTES_V2
        {
            unattempted_work_item_ids = unattempted_work_item_ids_from(request, index);
            break;
        }
        let stdout_limit = MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2
            .min(MAX_ARTIFACT_REVIEW_TOTAL_PROVIDER_OUTPUT_BYTES_V2 - total_stdout_bytes);
        let stderr_limit = MAX_LOCAL_PROVIDER_STDERR_BYTES_V2
            .min(MAX_LOCAL_PROVIDER_TOTAL_STDERR_BYTES_V2 - total_stderr_bytes);
        let invocation_directory = run_directory.join(format!("invocation-{index:06}"));
        if let Err(error) = create_invocation_directories(&invocation_directory) {
            terminal_error = Some(error);
            terminal_phase = Some(LocalProviderTerminalPhaseV2::Invocation);
            terminal_error_work_item_id = Some(prepared_invocation.work_item_id.clone());
            unattempted_work_item_ids = unattempted_work_item_ids_from(request, index);
            break;
        }
        let execution = match execute_provider_invocation(
            &staged_executable,
            &invocation_directory,
            &prepared_invocation.provider_input,
            stdout_limit,
            stderr_limit,
            policy.per_call_timeout,
            global_deadline,
            policy.termination_grace,
            cancellation,
        ) {
            Ok(execution) => execution,
            Err(failure) => {
                terminal_error = Some(failure.error);
                terminal_phase = Some(LocalProviderTerminalPhaseV2::Invocation);
                terminal_error_work_item_id = Some(prepared_invocation.work_item_id.clone());
                let expected = expected_work_item_ids(request);
                let (attempted, unattempted) = terminal_invocation_failure_classification(
                    &expected,
                    index,
                    failure.attempt_state,
                )?;
                attempted_without_capture_work_item_ids.extend(attempted);
                unattempted_work_item_ids = unattempted;
                break;
            }
        };
        total_stdout_bytes += execution.stdout_capture.len();
        total_stderr_bytes += execution.stderr_capture.len();

        let provider_output = match execution.termination_reason {
            LocalProviderTerminationReasonV2::Completed => {
                ArtifactReviewProviderOutputV2::new_complete(
                    prepared_invocation.work_item_id.clone(),
                    execution.stdout_capture.clone(),
                    ArtifactReviewChannelIsolationV2::CollapsedPrompt,
                )
            }
            LocalProviderTerminationReasonV2::StdoutLimitExceeded => {
                ArtifactReviewProviderOutputV2::new_truncated_capture(
                    prepared_invocation.work_item_id.clone(),
                    execution.stdout_capture.clone(),
                    ArtifactReviewChannelIsolationV2::CollapsedPrompt,
                )
            }
            _ => ArtifactReviewProviderOutputV2::new_failed_capture(
                prepared_invocation.work_item_id.clone(),
                execution.stdout_capture.clone(),
                ArtifactReviewChannelIsolationV2::CollapsedPrompt,
                execution.stdout_eof_verified,
            ),
        };
        let provider_output = match provider_output {
            Ok(provider_output) => provider_output,
            Err(_) => {
                terminal_error = Some(LocalProviderRuntimeErrorV2::ProviderCaptureInvalid);
                terminal_phase = Some(LocalProviderTerminalPhaseV2::Invocation);
                terminal_error_work_item_id = Some(prepared_invocation.work_item_id.clone());
                attempted_without_capture_work_item_ids
                    .push(prepared_invocation.work_item_id.clone());
                unattempted_work_item_ids = unattempted_work_item_ids_from(request, index + 1);
                break;
            }
        };
        let provider_output_status = provider_output.status();
        let provider_input_sha256 = Sha256Digest::from_bytes(&prepared_invocation.provider_input);
        let stdout_capture_sha256 = Sha256Digest::from_bytes(&execution.stdout_capture);
        let stderr_capture_sha256 = Sha256Digest::from_bytes(&execution.stderr_capture);
        let restricted_capture = match RestrictedLocalProviderCaptureV2::new(
            prepared_invocation.work_item_id.clone(),
            execution.stdout_capture,
            execution.stderr_capture,
        ) {
            Ok(capture) => capture,
            Err(error) => {
                terminal_error = Some(error);
                terminal_phase = Some(LocalProviderTerminalPhaseV2::Invocation);
                terminal_error_work_item_id = Some(prepared_invocation.work_item_id.clone());
                attempted_without_capture_work_item_ids
                    .push(prepared_invocation.work_item_id.clone());
                unattempted_work_item_ids = unattempted_work_item_ids_from(request, index + 1);
                break;
            }
        };
        let invocation_record = LocalProviderInvocationRecordV2 {
            request_sha256: request_sha256.clone(),
            invocation_sha256: prepared_invocation.invocation_sha256.clone(),
            work_item_id: prepared_invocation.work_item_id.clone(),
            provider_adapter_sha256: authorization.provider.adapter_sha256.clone(),
            model_content_sha256: authorization.model.model_content_sha256.clone(),
            provider_input_sha256,
            provider_input_byte_len: prepared_invocation.provider_input.len() as u64,
            stdout_capture_sha256,
            stdout_capture_byte_len: restricted_capture.stdout_capture_byte_len(),
            stderr_capture_sha256,
            stderr_capture_byte_len: restricted_capture.stderr_capture_byte_len(),
            provider_output_status,
            termination_reason: execution.termination_reason,
            exit_code: execution.exit_code,
            channel_isolation: ArtifactReviewChannelIsolationV2::CollapsedPrompt,
            stdout_eof_verified: execution.stdout_eof_verified,
            stderr_eof_verified: execution.stderr_eof_verified,
            process_group_cleanup_verified: execution.process_group_cleanup_verified,
            descendant_containment_verified: false,
            kill_escalated: execution.kill_escalated,
            network_isolation:
                LocalProviderNetworkIsolationV2::NotEnforcedCallerAuthorizedExecutable,
            host_isolation: LocalProviderHostIsolationV2::NotSandboxedCallerAuthorizedExecutable,
            model_identity_posture:
                LocalProviderModelIdentityPostureV2::SyntheticBehaviorLabelBoundToVerifiedAdapterBytes,
            resource_isolation:
                LocalProviderResourceIsolationV2::WallClockStreamCapsAndDescriptorClosureOnly,
            executable_identity_posture: LocalProviderExecutableIdentityPostureV2::DigestVerifiedPrivateStagedPathSameUserRaceNotExcluded,
            elapsed_millis: execution.elapsed.as_millis().min(u128::from(u64::MAX)) as u64,
        };
        invocation_records.push(invocation_record);
        provider_outputs.push(provider_output);
        restricted_captures.push(restricted_capture);

        if matches!(
            execution.termination_reason,
            LocalProviderTerminationReasonV2::Cancelled
                | LocalProviderTerminationReasonV2::GlobalTimeout
                | LocalProviderTerminationReasonV2::PerCallTimeout
        ) {
            unattempted_work_item_ids = unattempted_work_item_ids_from(request, index + 1);
            break;
        }
    }

    drop(staged_executable);
    let mut run = new_validated_local_provider_run(
        expected_work_item_ids(request),
        provider_outputs,
        invocation_records,
        restricted_captures,
        attempted_without_capture_work_item_ids,
        unattempted_work_item_ids,
        terminal_error,
        terminal_phase,
        terminal_error_work_item_id,
        false,
        None,
    )?;
    match run_directory_guard.cleanup() {
        Ok(()) => run.run_directory_cleanup_verified = true,
        Err(error) if run.terminal_error.is_some() => {
            run.secondary_cleanup_error = Some(error);
        }
        Err(error) => {
            run.terminal_error = Some(error);
            run.terminal_phase = Some(LocalProviderTerminalPhaseV2::RunDirectoryCleanup);
        }
    }
    Ok(run)
}

#[allow(clippy::too_many_arguments)]
pub fn run_local_provider_for_evidence_v2(
    binding: LocalProviderEvidenceExecutionBindingV2,
    subject: &ArtifactEvidenceSubjectV2,
    artifact: &NormalizedArtifact,
    analysis: &ArtifactStaticAnalysis,
    request: &ArtifactReviewRequestV2,
    authorization: &AuthorizedLocalProviderV2,
    policy: &LocalProviderRuntimePolicyV2,
    cancellation: &ArtifactReviewCancellationTokenV2,
) -> Result<EvidenceBoundLocalProviderRunV2, LocalProviderRuntimeErrorV2> {
    let started_at_unix_seconds = host_unix_seconds_v2()?;
    let run = run_local_provider_v2(
        subject,
        artifact,
        analysis,
        request,
        authorization,
        policy,
        cancellation,
    )?;
    let finished_at_unix_seconds = host_unix_seconds_v2()?;
    validate_host_time_range_v2(started_at_unix_seconds, finished_at_unix_seconds)?;
    Ok(EvidenceBoundLocalProviderRunV2 {
        binding,
        started_at_unix_seconds,
        finished_at_unix_seconds,
        run,
    })
}

fn host_unix_seconds_v2() -> Result<u64, LocalProviderRuntimeErrorV2> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| LocalProviderRuntimeErrorV2::SystemClockInvalid)
}

fn validate_host_time_range_v2(
    started_at_unix_seconds: u64,
    finished_at_unix_seconds: u64,
) -> Result<(), LocalProviderRuntimeErrorV2> {
    if started_at_unix_seconds == 0
        || finished_at_unix_seconds == 0
        || started_at_unix_seconds > finished_at_unix_seconds
    {
        return Err(LocalProviderRuntimeErrorV2::SystemClockInvalid);
    }
    Ok(())
}

struct ProcessExecutionResult {
    stdout_capture: Vec<u8>,
    stderr_capture: Vec<u8>,
    stdout_eof_verified: bool,
    stderr_eof_verified: bool,
    process_group_cleanup_verified: bool,
    kill_escalated: bool,
    termination_reason: LocalProviderTerminationReasonV2,
    exit_code: Option<i32>,
    elapsed: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProviderInvocationAttemptStateV2 {
    NotStarted,
    StartedWithoutCapture,
}

fn terminal_invocation_failure_classification(
    expected_work_item_ids: &[Sha256Digest],
    index: usize,
    attempt_state: ProviderInvocationAttemptStateV2,
) -> Result<(Vec<Sha256Digest>, Vec<Sha256Digest>), LocalProviderRuntimeErrorV2> {
    if index >= expected_work_item_ids.len() {
        return Err(LocalProviderRuntimeErrorV2::InvalidWorkPartition);
    }
    Ok(match attempt_state {
        ProviderInvocationAttemptStateV2::NotStarted => {
            (Vec::new(), expected_work_item_ids[index..].to_vec())
        }
        ProviderInvocationAttemptStateV2::StartedWithoutCapture => (
            vec![expected_work_item_ids[index].clone()],
            expected_work_item_ids[index + 1..].to_vec(),
        ),
    })
}

struct ProviderInvocationFailureV2 {
    error: LocalProviderRuntimeErrorV2,
    attempt_state: ProviderInvocationAttemptStateV2,
}

impl ProviderInvocationFailureV2 {
    fn not_started(error: LocalProviderRuntimeErrorV2) -> Self {
        Self {
            error,
            attempt_state: ProviderInvocationAttemptStateV2::NotStarted,
        }
    }

    fn started_without_capture(error: LocalProviderRuntimeErrorV2) -> Self {
        Self {
            error,
            attempt_state: ProviderInvocationAttemptStateV2::StartedWithoutCapture,
        }
    }
}

#[derive(Default)]
struct ProcessExecutionFacts {
    cancelled: bool,
    global_timeout: bool,
    per_call_timeout: bool,
    stdout_limit_exceeded: bool,
    stderr_limit_exceeded: bool,
    input_write_failed: bool,
    output_read_failed: bool,
    protocol_handshake_failed: bool,
    lingering_process_group: bool,
}

impl ProcessExecutionFacts {
    fn requires_cleanup(&self) -> bool {
        self.cancelled
            || self.global_timeout
            || self.per_call_timeout
            || self.stdout_limit_exceeded
            || self.stderr_limit_exceeded
            || self.input_write_failed
            || self.output_read_failed
            || self.protocol_handshake_failed
            || self.lingering_process_group
    }

    fn termination_reason(&self, status: ExitStatus) -> LocalProviderTerminationReasonV2 {
        if self.cancelled {
            LocalProviderTerminationReasonV2::Cancelled
        } else if self.global_timeout {
            LocalProviderTerminationReasonV2::GlobalTimeout
        } else if self.per_call_timeout {
            LocalProviderTerminationReasonV2::PerCallTimeout
        } else if self.stdout_limit_exceeded {
            LocalProviderTerminationReasonV2::StdoutLimitExceeded
        } else if self.stderr_limit_exceeded {
            LocalProviderTerminationReasonV2::StderrLimitExceeded
        } else if self.input_write_failed {
            LocalProviderTerminationReasonV2::InputWriteFailed
        } else if self.output_read_failed {
            LocalProviderTerminationReasonV2::OutputReadFailed
        } else if self.protocol_handshake_failed {
            LocalProviderTerminationReasonV2::ProtocolHandshakeFailed
        } else if self.lingering_process_group {
            LocalProviderTerminationReasonV2::LingeringProcessGroup
        } else if status.success() {
            LocalProviderTerminationReasonV2::Completed
        } else {
            LocalProviderTerminationReasonV2::NonZeroExit
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_provider_invocation(
    executable: &VerifiedStagedExecutable,
    invocation_directory: &Path,
    provider_input: &[u8],
    stdout_limit: usize,
    stderr_limit: usize,
    per_call_timeout: Duration,
    global_deadline: Instant,
    termination_grace: Duration,
    cancellation: &ArtifactReviewCancellationTokenV2,
) -> Result<ProcessExecutionResult, ProviderInvocationFailureV2> {
    executable
        .verify_path_identity()
        .map_err(ProviderInvocationFailureV2::not_started)?;
    let started = Instant::now();
    let cwd = invocation_directory.join("cwd");
    let home = invocation_directory.join("home");
    let temporary = invocation_directory.join("tmp");

    let spawned = spawn_provider_process_macos(executable.exec_path(), &cwd, &home, &temporary)
        .map_err(ProviderInvocationFailureV2::not_started)?;
    (|| -> Result<ProcessExecutionResult, LocalProviderRuntimeErrorV2> {
        let mut call_deadline = None;
        let SpawnedProviderProcess {
            process_id,
            stdin: provider_stdin,
            mut stdout,
            mut stderr,
        } = spawned;
        let mut process = ChildProcessGroupGuard::new(process_id)?;
        executable.verify_path_identity()?;
        let mut stdin = Some(provider_stdin);
        set_nonblocking(
            stdin
                .as_ref()
                .ok_or(LocalProviderRuntimeErrorV2::ProcessControlFailed)?
                .as_raw_fd(),
        )?;
        set_nonblocking(stdout.as_raw_fd())?;
        set_nonblocking(stderr.as_raw_fd())?;

        let mut stdin_open = true;
        let mut stdin_offset = 0usize;
        let mut stdout_open = true;
        let mut stderr_open = true;
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut stdout_capture = Vec::new();
        let mut stderr_capture = Vec::new();
        let mut facts = ProcessExecutionFacts::default();
        let mut provider_ready = false;
        let mut leader_exited = false;
        let mut cleanup_started = None;
        let mut kill_attempted = false;
        let mut kill_escalated = false;

        loop {
            let now = Instant::now();
            if cleanup_started.is_none() {
                if cancellation.is_cancelled() {
                    facts.cancelled = true;
                }
                if now >= global_deadline {
                    facts.global_timeout = true;
                }
                if call_deadline.is_some_and(|deadline| now >= deadline) && now < global_deadline {
                    facts.per_call_timeout = true;
                }
            }

            if !leader_exited {
                leader_exited = process.leader_has_exited_without_reaping()?;
            }

            if facts.requires_cleanup() && cleanup_started.is_none() {
                cleanup_started = Some(Instant::now());
                stdin_open = false;
                stdin.take();
                process.send_group_signal(libc::SIGTERM)?;
            }

            if cleanup_started.is_none() {
                poll_process_pipes(
                    if stdin_open {
                        stdin.as_ref().map(AsRawFd::as_raw_fd)
                    } else {
                        None
                    },
                    if stdout_open {
                        Some(stdout.as_raw_fd())
                    } else {
                        None
                    },
                    if stderr_open {
                        Some(stderr.as_raw_fd())
                    } else {
                        None
                    },
                )?;
                if stdin_open {
                    let write_result = {
                        let input_pipe = stdin
                            .as_mut()
                            .ok_or(LocalProviderRuntimeErrorV2::ProcessControlFailed)?;
                        write_nonblocking(input_pipe, &provider_input[stdin_offset..])
                    };
                    match write_result {
                        Ok(written) => {
                            stdin_offset += written;
                            if stdin_offset == provider_input.len() {
                                stdin_open = false;
                                // Closing stdin proves the complete canonical input was delivered.
                                stdin.take();
                            }
                        }
                        Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                        Err(_) => {
                            facts.input_write_failed = true;
                        }
                    }
                }
            } else {
                poll_process_pipes(
                    None,
                    if stdout_open {
                        Some(stdout.as_raw_fd())
                    } else {
                        None
                    },
                    if stderr_open {
                        Some(stderr.as_raw_fd())
                    } else {
                        None
                    },
                )?;
            }

            if stdout_open {
                match read_nonblocking_capture(&mut stdout, &mut stdout_capture, stdout_limit) {
                    Ok(CaptureProgress::Pending) => {}
                    Ok(CaptureProgress::Eof) => {
                        stdout_open = false;
                        stdout_eof = true;
                    }
                    Ok(CaptureProgress::Overflow) => {
                        stdout_open = false;
                        facts.stdout_limit_exceeded = true;
                    }
                    Err(_) => {
                        stdout_open = false;
                        facts.output_read_failed = true;
                    }
                }
            }
            if stderr_open {
                match read_nonblocking_capture(&mut stderr, &mut stderr_capture, stderr_limit) {
                    Ok(CaptureProgress::Pending) => {}
                    Ok(CaptureProgress::Eof) => {
                        stderr_open = false;
                        stderr_eof = true;
                    }
                    Ok(CaptureProgress::Overflow) => {
                        stderr_open = false;
                        facts.stderr_limit_exceeded = true;
                    }
                    Err(_) => {
                        stderr_open = false;
                        facts.output_read_failed = true;
                    }
                }
            }

            if !provider_ready && stderr_capture.starts_with(INERT_PROVIDER_READY_MARKER_V2) {
                provider_ready = true;
                call_deadline = Some(
                    Instant::now()
                        .checked_add(per_call_timeout)
                        .ok_or(LocalProviderRuntimeErrorV2::InvalidRuntimePolicy)?
                        .min(global_deadline),
                );
            }

            if leader_exited && cleanup_started.is_none() {
                if !provider_ready {
                    facts.protocol_handshake_failed = true;
                } else if process.group_has_other_members()? {
                    facts.lingering_process_group = true;
                } else if stdin_offset != provider_input.len() {
                    facts.input_write_failed = true;
                } else if stdout_eof && stderr_eof {
                    break;
                }
            }

            if facts.requires_cleanup() && cleanup_started.is_none() {
                continue;
            }
            if let Some(cleanup_start) = cleanup_started {
                if !leader_exited {
                    leader_exited = process.leader_has_exited_without_reaping()?;
                }
                let group_has_other_members = process.group_has_other_members()?;
                let kill_deadline = cleanup_start
                    .checked_add(termination_grace)
                    .ok_or(LocalProviderRuntimeErrorV2::InvalidRuntimePolicy)?;
                if !kill_attempted
                    && Instant::now() >= kill_deadline
                    && (!leader_exited || group_has_other_members)
                {
                    kill_attempted = true;
                    kill_escalated = process.send_group_signal(libc::SIGKILL)?;
                }
                let hard_deadline = kill_deadline
                    .checked_add(termination_grace)
                    .ok_or(LocalProviderRuntimeErrorV2::InvalidRuntimePolicy)?;
                if leader_exited
                    && !group_has_other_members
                    && (!stdout_open || stdout_eof)
                    && (!stderr_open || stderr_eof)
                {
                    break;
                }
                if Instant::now() >= hard_deadline {
                    return Err(LocalProviderRuntimeErrorV2::ProcessCleanupFailed);
                }
            }
        }

        if !leader_exited || process.group_has_other_members()? {
            return Err(LocalProviderRuntimeErrorV2::ProcessCleanupFailed);
        }
        let leader_status = process.reap()?;
        process.disarm();
        if stdin_offset != provider_input.len() {
            facts.input_write_failed = true;
        }
        if !stdout_eof && !facts.stdout_limit_exceeded {
            facts.output_read_failed = true;
        }
        if !stderr_eof && !facts.stderr_limit_exceeded {
            facts.output_read_failed = true;
        }
        let reason = facts.termination_reason(leader_status);
        Ok(ProcessExecutionResult {
            stdout_capture,
            stderr_capture,
            stdout_eof_verified: stdout_eof,
            stderr_eof_verified: stderr_eof,
            process_group_cleanup_verified: true,
            kill_escalated,
            termination_reason: reason,
            exit_code: leader_status.code(),
            elapsed: started.elapsed(),
        })
    })()
    .map_err(ProviderInvocationFailureV2::started_without_capture)
}

fn ensure_private_runtime_root(path: &Path) -> Result<(), LocalProviderRuntimeErrorV2> {
    match fs::symlink_metadata(path) {
        Ok(_) => validate_private_directory(path, LocalProviderRuntimeErrorV2::RuntimeRootInvalid),
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder
                .create(path)
                .map_err(|_| LocalProviderRuntimeErrorV2::RuntimeRootInvalid)?;
            validate_private_directory(path, LocalProviderRuntimeErrorV2::RuntimeRootInvalid)
        }
        Err(_) => Err(LocalProviderRuntimeErrorV2::RuntimeRootInvalid),
    }
}

struct RunDirectoryCreationFailureV2 {
    primary_error: LocalProviderRuntimeErrorV2,
    run_directory_cleanup_verified: bool,
    secondary_cleanup_error: Option<LocalProviderRuntimeErrorV2>,
}

impl RunDirectoryCreationFailureV2 {
    fn without_owned_directory() -> Self {
        Self {
            primary_error: LocalProviderRuntimeErrorV2::RunDirectoryCreationFailed,
            run_directory_cleanup_verified: true,
            secondary_cleanup_error: None,
        }
    }

    fn after_created_directory(path: PathBuf) -> Self {
        let mut guard = RunDirectoryGuard::new(path);
        match guard.cleanup() {
            Ok(()) => Self::without_owned_directory(),
            Err(cleanup_error) => Self {
                primary_error: LocalProviderRuntimeErrorV2::RunDirectoryCreationFailed,
                run_directory_cleanup_verified: false,
                secondary_cleanup_error: Some(cleanup_error),
            },
        }
    }
}

fn create_private_run_directory(root: &Path) -> Result<PathBuf, RunDirectoryCreationFailureV2> {
    for _ in 0..128 {
        let counter = RUN_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = root.join(format!("run-{}-{counter}", std::process::id()));
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        match builder.create(&path) {
            Ok(()) => {
                if validate_private_directory(
                    &path,
                    LocalProviderRuntimeErrorV2::RunDirectoryCreationFailed,
                )
                .is_err()
                {
                    return Err(RunDirectoryCreationFailureV2::after_created_directory(path));
                }
                return Ok(path);
            }
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(RunDirectoryCreationFailureV2::without_owned_directory()),
        }
    }
    Err(RunDirectoryCreationFailureV2::without_owned_directory())
}

fn create_invocation_directories(path: &Path) -> Result<(), LocalProviderRuntimeErrorV2> {
    create_private_directory(path)?;
    for name in ["cwd", "home", "tmp"] {
        create_private_directory(&path.join(name))?;
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), LocalProviderRuntimeErrorV2> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|_| LocalProviderRuntimeErrorV2::RunDirectoryCreationFailed)?;
    validate_private_directory(
        path,
        LocalProviderRuntimeErrorV2::RunDirectoryCreationFailed,
    )
}

fn validate_private_directory(
    path: &Path,
    error: LocalProviderRuntimeErrorV2,
) -> Result<(), LocalProviderRuntimeErrorV2> {
    let metadata = fs::symlink_metadata(path).map_err(|_| error)?;
    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != current_uid
        || metadata.mode() & 0o700 != 0o700
        || metadata.mode() & 0o077 != 0
    {
        return Err(error);
    }
    Ok(())
}

fn stage_verified_executable(
    source_path: &Path,
    run_directory: &Path,
    expected_sha256: &Sha256Digest,
) -> Result<VerifiedStagedExecutable, LocalProviderRuntimeErrorV2> {
    if !source_path.is_absolute() {
        return Err(LocalProviderRuntimeErrorV2::InvalidAuthorization);
    }
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(source_path)
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableOpenFailed)?;
    let metadata = source
        .metadata()
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableMetadataInvalid)?;
    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != current_uid
        || metadata.mode() & 0o100 == 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o7000 != 0
    {
        return Err(LocalProviderRuntimeErrorV2::ExecutableMetadataInvalid);
    }
    if metadata.len() == 0 || metadata.len() > MAX_LOCAL_PROVIDER_EXECUTABLE_BYTES_V2 as u64 {
        return Err(LocalProviderRuntimeErrorV2::ExecutableLimitExceeded);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    std::io::Read::by_ref(&mut source)
        .take(MAX_LOCAL_PROVIDER_EXECUTABLE_BYTES_V2 as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableOpenFailed)?;
    if bytes.is_empty() || bytes.len() > MAX_LOCAL_PROVIDER_EXECUTABLE_BYTES_V2 {
        return Err(LocalProviderRuntimeErrorV2::ExecutableLimitExceeded);
    }
    if &Sha256Digest::from_bytes(&bytes) != expected_sha256 {
        return Err(LocalProviderRuntimeErrorV2::ExecutableDigestMismatch);
    }

    let staged_path = run_directory.join("authorized-provider");
    let mut staged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&staged_path)
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
    staged
        .write_all(&bytes)
        .and_then(|_| staged.sync_all())
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
    fs::set_permissions(&staged_path, fs::Permissions::from_mode(0o500))
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
    drop(staged);
    let mut reopened = open_staged_executable(&staged_path)?;
    let mut staged_bytes = Vec::with_capacity(bytes.len());
    std::io::Read::by_ref(&mut reopened)
        .take(MAX_LOCAL_PROVIDER_EXECUTABLE_BYTES_V2 as u64 + 1)
        .read_to_end(&mut staged_bytes)
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
    if staged_bytes != bytes || Sha256Digest::from_bytes(&staged_bytes) != *expected_sha256 {
        return Err(LocalProviderRuntimeErrorV2::ExecutableDigestMismatch);
    }
    Ok(VerifiedStagedExecutable {
        exec_path: staged_path,
        expected_sha256: expected_sha256.clone(),
        _file: reopened,
    })
}

struct VerifiedStagedExecutable {
    exec_path: PathBuf,
    expected_sha256: Sha256Digest,
    _file: File,
}

impl VerifiedStagedExecutable {
    fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    fn verify_path_identity(&self) -> Result<(), LocalProviderRuntimeErrorV2> {
        let held_metadata = self
            ._file
            .metadata()
            .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
        let mut candidate = open_staged_executable(&self.exec_path)?;
        let candidate_metadata = candidate
            .metadata()
            .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
        if candidate_metadata.dev() != held_metadata.dev()
            || candidate_metadata.ino() != held_metadata.ino()
            || candidate_metadata.len() != held_metadata.len()
        {
            return Err(LocalProviderRuntimeErrorV2::ExecutableDigestMismatch);
        }
        let mut bytes = Vec::with_capacity(candidate_metadata.len() as usize);
        std::io::Read::by_ref(&mut candidate)
            .take(MAX_LOCAL_PROVIDER_EXECUTABLE_BYTES_V2 as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
        if bytes.len() != candidate_metadata.len() as usize
            || Sha256Digest::from_bytes(&bytes) != self.expected_sha256
        {
            return Err(LocalProviderRuntimeErrorV2::ExecutableDigestMismatch);
        }
        Ok(())
    }
}

fn open_staged_executable(path: &Path) -> Result<File, LocalProviderRuntimeErrorV2> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
    let metadata = file
        .metadata()
        .map_err(|_| LocalProviderRuntimeErrorV2::ExecutableStagingFailed)?;
    // SAFETY: geteuid has no preconditions.
    let current_uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.uid() != current_uid
        || metadata.mode() & 0o777 != 0o500
        || metadata.len() == 0
        || metadata.len() > MAX_LOCAL_PROVIDER_EXECUTABLE_BYTES_V2 as u64
    {
        return Err(LocalProviderRuntimeErrorV2::ExecutableStagingFailed);
    }
    Ok(file)
}

struct RunDirectoryGuard {
    path: PathBuf,
    active: bool,
}

impl RunDirectoryGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, active: true }
    }

    fn cleanup(&mut self) -> Result<(), LocalProviderRuntimeErrorV2> {
        if !self.active {
            return Ok(());
        }
        match fs::symlink_metadata(&self.path) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
                fs::remove_dir_all(&self.path)
                    .map_err(|_| LocalProviderRuntimeErrorV2::RunDirectoryCleanupFailed)?;
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            _ => return Err(LocalProviderRuntimeErrorV2::RunDirectoryCleanupFailed),
        }
        match fs::symlink_metadata(&self.path) {
            Err(error) if error.kind() == ErrorKind::NotFound => {
                self.active = false;
                Ok(())
            }
            _ => Err(LocalProviderRuntimeErrorV2::RunDirectoryCleanupFailed),
        }
    }
}

impl Drop for RunDirectoryGuard {
    fn drop(&mut self) {
        if self.active {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

struct SpawnedProviderProcess {
    process_id: libc::pid_t,
    stdin: File,
    stdout: File,
    stderr: File,
}

struct SpawnFileActions(libc::posix_spawn_file_actions_t);

impl SpawnFileActions {
    fn new() -> Result<Self, LocalProviderRuntimeErrorV2> {
        let mut actions = std::ptr::null_mut();
        // SAFETY: actions points to writable opaque action storage.
        if unsafe { libc::posix_spawn_file_actions_init(&mut actions) } != 0 {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
        Ok(Self(actions))
    }

    fn duplicate(
        &mut self,
        source: i32,
        destination: i32,
    ) -> Result<(), LocalProviderRuntimeErrorV2> {
        // SAFETY: the actions object is initialized and both descriptors are
        // validated live pipe descriptors or standard descriptor numbers.
        if unsafe { libc::posix_spawn_file_actions_adddup2(&mut self.0, source, destination) } != 0
        {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
        Ok(())
    }

    fn close(&mut self, descriptor: i32) -> Result<(), LocalProviderRuntimeErrorV2> {
        // SAFETY: the actions object is initialized and descriptor is a live
        // child-side pipe descriptor.
        if unsafe { libc::posix_spawn_file_actions_addclose(&mut self.0, descriptor) } != 0 {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
        Ok(())
    }

    fn change_directory(&mut self, path: &CString) -> Result<(), LocalProviderRuntimeErrorV2> {
        // SAFETY: the actions object is initialized and path is NUL-terminated
        // for the duration of this call. The function copies the path.
        if unsafe { posix_spawn_file_actions_addchdir_np(&mut self.0, path.as_ptr()) } != 0 {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
        Ok(())
    }
}

impl Drop for SpawnFileActions {
    fn drop(&mut self) {
        // SAFETY: the actions object was initialized in new and is destroyed
        // exactly once here.
        unsafe {
            libc::posix_spawn_file_actions_destroy(&mut self.0);
        }
    }
}

struct SpawnAttributes(libc::posix_spawnattr_t);

impl SpawnAttributes {
    fn new() -> Result<Self, LocalProviderRuntimeErrorV2> {
        let mut attributes = std::ptr::null_mut();
        // SAFETY: attributes points to writable opaque attribute storage.
        if unsafe { libc::posix_spawnattr_init(&mut attributes) } != 0 {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
        Ok(Self(attributes))
    }

    fn set_dedicated_process_group_and_close_unlisted_descriptors(
        &mut self,
    ) -> Result<(), LocalProviderRuntimeErrorV2> {
        // A zero group value with POSIX_SPAWN_SETPGROUP creates a group whose
        // id is the spawned process pid.
        // SAFETY: the attribute object is initialized.
        if unsafe { libc::posix_spawnattr_setpgroup(&mut self.0, 0) } != 0 {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
        let flags = libc::POSIX_SPAWN_SETPGROUP | libc::POSIX_SPAWN_CLOEXEC_DEFAULT;
        let flags = libc::c_short::try_from(flags)
            .map_err(|_| LocalProviderRuntimeErrorV2::ProcessSpawnFailed)?;
        // SAFETY: the attribute object is initialized and the flags are
        // supported macOS posix_spawn flags.
        if unsafe { libc::posix_spawnattr_setflags(&mut self.0, flags) } != 0 {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
        Ok(())
    }
}

impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        // SAFETY: the attribute object was initialized in new and is destroyed
        // exactly once here.
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.0);
        }
    }
}

fn spawn_provider_process_macos(
    executable: &Path,
    cwd: &Path,
    home: &Path,
    temporary: &Path,
) -> Result<SpawnedProviderProcess, LocalProviderRuntimeErrorV2> {
    if !cfg!(target_os = "macos") {
        return Err(LocalProviderRuntimeErrorV2::UnsupportedPlatform);
    }
    let (stdin_read, stdin_write) = create_cloexec_pipe()?;
    let (stdout_read, stdout_write) = create_cloexec_pipe()?;
    let (stderr_read, stderr_write) = create_cloexec_pipe()?;
    for descriptor in [
        stdin_read.as_raw_fd(),
        stdin_write.as_raw_fd(),
        stdout_read.as_raw_fd(),
        stdout_write.as_raw_fd(),
        stderr_read.as_raw_fd(),
        stderr_write.as_raw_fd(),
    ] {
        if descriptor <= libc::STDERR_FILENO {
            return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
        }
    }

    let executable_c = path_to_c_string(executable)?;
    let cwd_c = path_to_c_string(cwd)?;
    let mut arguments = [
        executable_c.as_ptr().cast_mut(),
        c"artifact-review-v2-stdin".as_ptr().cast_mut(),
        std::ptr::null_mut(),
    ];
    let environment_storage = [
        environment_path_entry("HOME", home)?,
        environment_path_entry("TMPDIR", temporary)?,
        CString::new("LANG=C").map_err(|_| LocalProviderRuntimeErrorV2::ProcessSpawnFailed)?,
        CString::new("LC_ALL=C").map_err(|_| LocalProviderRuntimeErrorV2::ProcessSpawnFailed)?,
        CString::new("TZ=UTC").map_err(|_| LocalProviderRuntimeErrorV2::ProcessSpawnFailed)?,
    ];
    let mut environment = environment_storage
        .iter()
        .map(|entry| entry.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect::<Vec<_>>();

    let mut actions = SpawnFileActions::new()?;
    actions.duplicate(stdin_read.as_raw_fd(), libc::STDIN_FILENO)?;
    actions.duplicate(stdout_write.as_raw_fd(), libc::STDOUT_FILENO)?;
    actions.duplicate(stderr_write.as_raw_fd(), libc::STDERR_FILENO)?;
    actions.close(stdin_read.as_raw_fd())?;
    actions.close(stdout_write.as_raw_fd())?;
    actions.close(stderr_write.as_raw_fd())?;
    actions.change_directory(&cwd_c)?;

    let mut attributes = SpawnAttributes::new()?;
    attributes.set_dedicated_process_group_and_close_unlisted_descriptors()?;
    let mut process_id = 0;
    // SAFETY: all C strings and pointer arrays remain alive and NUL-terminated
    // for the call. Actions and attributes are initialized. posix_spawn writes
    // one pid on success and does not retain the arrays.
    let spawn_result = unsafe {
        libc::posix_spawn(
            &mut process_id,
            executable_c.as_ptr(),
            &actions.0,
            &attributes.0,
            arguments.as_mut_ptr(),
            environment.as_mut_ptr(),
        )
    };
    if spawn_result != 0 || process_id <= 0 {
        return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
    }

    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);
    Ok(SpawnedProviderProcess {
        process_id,
        stdin: File::from(stdin_write),
        stdout: File::from(stdout_read),
        stderr: File::from(stderr_read),
    })
}

fn create_cloexec_pipe() -> Result<(OwnedFd, OwnedFd), LocalProviderRuntimeErrorV2> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to writable storage for two pipe fds.
    if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
    }
    // SAFETY: pipe returned two newly owned descriptors.
    let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: pipe returned two newly owned descriptors.
    let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_close_on_exec(read.as_raw_fd())?;
    set_close_on_exec(write.as_raw_fd())?;
    Ok((read, write))
}

fn set_close_on_exec(descriptor: i32) -> Result<(), LocalProviderRuntimeErrorV2> {
    // SAFETY: fcntl reads flags from a live owned descriptor.
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 {
        return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
    }
    // SAFETY: fcntl updates only the close-on-exec descriptor flag.
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(LocalProviderRuntimeErrorV2::ProcessSpawnFailed);
    }
    Ok(())
}

fn path_to_c_string(path: &Path) -> Result<CString, LocalProviderRuntimeErrorV2> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| LocalProviderRuntimeErrorV2::ProcessSpawnFailed)
}

fn environment_path_entry(name: &str, path: &Path) -> Result<CString, LocalProviderRuntimeErrorV2> {
    let mut bytes = Vec::with_capacity(name.len() + 1 + path.as_os_str().as_bytes().len());
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(b'=');
    bytes.extend_from_slice(path.as_os_str().as_bytes());
    CString::new(bytes).map_err(|_| LocalProviderRuntimeErrorV2::ProcessSpawnFailed)
}

struct ChildProcessGroupGuard {
    process_id: libc::pid_t,
    process_group_id: i32,
    exit_observed_unreaped: bool,
    reaped: bool,
    disarmed: bool,
}

impl ChildProcessGroupGuard {
    fn new(process_id: libc::pid_t) -> Result<Self, LocalProviderRuntimeErrorV2> {
        if process_id <= 0 {
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
        let process_group_id = process_id;
        // SAFETY: getpgid only reads kernel process metadata for the live or
        // waitable child pid returned by spawn.
        if unsafe { libc::getpgid(process_group_id) } != process_group_id {
            // SAFETY: the requested process group id is the freshly spawned
            // child pid. This is emergency cleanup before the guard exists.
            unsafe {
                libc::kill(-process_group_id, libc::SIGKILL);
                libc::kill(process_id, libc::SIGKILL);
            }
            reap_raw_child_best_effort(process_id);
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
        Ok(Self {
            process_id,
            process_group_id,
            exit_observed_unreaped: false,
            reaped: false,
            disarmed: false,
        })
    }

    fn leader_has_exited_without_reaping(&mut self) -> Result<bool, LocalProviderRuntimeErrorV2> {
        if self.reaped {
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
        if self.exit_observed_unreaped {
            return Ok(true);
        }
        loop {
            let mut information = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
            // SAFETY: information points to writable siginfo storage, the
            // guarded child pid remains owned by this process, and WNOWAIT
            // keeps the child waitable so its pid/group cannot be reused.
            let result = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.process_group_id as libc::id_t,
                    information.as_mut_ptr(),
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if result < 0 {
                if io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                    continue;
                }
                return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
            }
            // SAFETY: successful waitid initialized siginfo. A zero si_pid is
            // the WNOHANG "no state change" result.
            let information = unsafe { information.assume_init() };
            let observed_pid = unsafe { information.si_pid() };
            if observed_pid == 0 {
                return Ok(false);
            }
            if observed_pid != self.process_group_id
                || !matches!(
                    information.si_code,
                    libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
                )
            {
                return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
            }
            self.exit_observed_unreaped = true;
            return Ok(true);
        }
    }

    fn send_group_signal(&self, signal: i32) -> Result<bool, LocalProviderRuntimeErrorV2> {
        if self.reaped {
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
        // SAFETY: a negative pid addresses the dedicated child process group.
        let result = unsafe { libc::kill(-self.process_group_id, signal) };
        if result == 0 {
            return Ok(true);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(false)
        } else {
            Err(LocalProviderRuntimeErrorV2::ProcessControlFailed)
        }
    }

    #[cfg(target_os = "macos")]
    fn group_has_other_members(&mut self) -> Result<bool, LocalProviderRuntimeErrorV2> {
        const MAX_OBSERVED_GROUP_MEMBERS: usize = 4_096;
        if self.reaped {
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
        let mut capacity = 16usize;
        loop {
            let mut process_ids = vec![0 as libc::pid_t; capacity];
            let buffer_bytes = capacity
                .checked_mul(std::mem::size_of::<libc::pid_t>())
                .and_then(|bytes| i32::try_from(bytes).ok())
                .ok_or(LocalProviderRuntimeErrorV2::ProcessControlFailed)?;
            // libproc can collapse an underlying failure into a zero return,
            // so errno must be cleared and checked around the query.
            // SAFETY: __error returns this thread's writable errno pointer.
            unsafe {
                *libc::__error() = 0;
            }
            // SAFETY: process_ids is writable pid_t storage and buffer_bytes
            // is its exact byte length. The return value is a PID count.
            let returned_count = unsafe {
                proc_listpgrppids(
                    self.process_group_id,
                    process_ids.as_mut_ptr().cast(),
                    buffer_bytes,
                )
            };
            // SAFETY: __error returns this thread's errno pointer.
            let query_errno = unsafe { *libc::__error() };
            if returned_count < 0 || query_errno != 0 {
                return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
            }
            let count = usize::try_from(returned_count)
                .map_err(|_| LocalProviderRuntimeErrorV2::ProcessControlFailed)?;
            if count > capacity {
                return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
            }
            if count == capacity {
                if capacity == MAX_OBSERVED_GROUP_MEMBERS {
                    return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
                }
                capacity = (capacity * 2).min(MAX_OBSERVED_GROUP_MEMBERS);
                continue;
            }
            let returned = &process_ids[..count];
            if returned.iter().any(|pid| *pid <= 0) {
                return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
            }
            if returned.contains(&self.process_group_id) {
                return Ok(returned.iter().any(|pid| *pid != self.process_group_id));
            }
            // The leader can exit after the caller's waitid observation but
            // before this independent libproc query. macOS then omits the
            // waitable zombie even though it remains owned and unreaped. Every
            // returned live PID is necessarily another member regardless of
            // whether that leader transition has been observed yet.
            if !returned.is_empty() {
                return Ok(true);
            }

            // Refresh the durable waitid observation when the successful group
            // query is empty. A still-live omitted leader does not make the
            // empty result sufficient for cleanup: callers also require their
            // separate leader-exited fact before they can break or reap. If the
            // leader exited in the query window, this records that proof for
            // the next loop iteration without turning the normal transition
            // into ProcessControlFailed.
            let _ = self.leader_has_exited_without_reaping()?;
            return Ok(false);
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn group_has_other_members(&mut self) -> Result<bool, LocalProviderRuntimeErrorV2> {
        Err(LocalProviderRuntimeErrorV2::UnsupportedPlatform)
    }

    fn reap(&mut self) -> Result<ExitStatus, LocalProviderRuntimeErrorV2> {
        if self.reaped || !self.exit_observed_unreaped {
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
        loop {
            let mut raw_status = 0;
            // SAFETY: process_id is the live waitable child owned by this
            // process and raw_status points to writable wait status storage.
            let waited = unsafe { libc::waitpid(self.process_id, &mut raw_status, 0) };
            if waited == self.process_id {
                self.reaped = true;
                return Ok(ExitStatus::from_raw(raw_status));
            }
            if waited < 0 && io::Error::last_os_error().kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
    }

    fn disarm(&mut self) {
        if self.reaped {
            self.disarmed = true;
        }
    }
}

impl Drop for ChildProcessGroupGuard {
    fn drop(&mut self) {
        if self.disarmed || self.reaped {
            return;
        }
        // SAFETY: the group id is the pid assigned to this guarded child.
        unsafe {
            libc::kill(-self.process_group_id, libc::SIGKILL);
            libc::kill(self.process_id, libc::SIGKILL);
        }
        reap_raw_child_best_effort(self.process_id);
    }
}

fn reap_raw_child_best_effort(process_id: libc::pid_t) {
    loop {
        let mut raw_status = 0;
        // SAFETY: process_id names the freshly spawned child and raw_status is
        // writable storage. This helper is used only on emergency cleanup.
        let waited = unsafe { libc::waitpid(process_id, &mut raw_status, 0) };
        if waited == process_id {
            return;
        }
        if waited < 0 && io::Error::last_os_error().kind() == ErrorKind::Interrupted {
            continue;
        }
        return;
    }
}

#[cfg(target_os = "macos")]
extern "C" {
    fn posix_spawn_file_actions_addchdir_np(
        actions: *mut libc::posix_spawn_file_actions_t,
        path: *const libc::c_char,
    ) -> libc::c_int;
}

#[cfg(test)]
mod partition_tests {
    use super::*;

    fn work_item_ids() -> Vec<Sha256Digest> {
        [
            b"first".as_slice(),
            b"second".as_slice(),
            b"third".as_slice(),
        ]
        .into_iter()
        .map(Sha256Digest::from_bytes)
        .collect()
    }

    #[test]
    fn terminal_failure_classification_distinguishes_pre_and_post_spawn() {
        let expected = work_item_ids();
        let recorded = vec![expected[0].clone()];

        let (pre_attempted, pre_unattempted) = terminal_invocation_failure_classification(
            &expected,
            1,
            ProviderInvocationAttemptStateV2::NotStarted,
        )
        .expect("valid pre-spawn classification");
        assert!(pre_attempted.is_empty());
        assert_eq!(pre_unattempted, expected[1..]);
        LocalProviderWorkPartitionV2::new(
            expected.clone(),
            recorded.clone(),
            pre_attempted,
            pre_unattempted,
        )
        .expect("pre-spawn failure keeps current item unattempted");

        let (post_attempted, post_unattempted) = terminal_invocation_failure_classification(
            &expected,
            1,
            ProviderInvocationAttemptStateV2::StartedWithoutCapture,
        )
        .expect("valid post-spawn classification");
        assert_eq!(
            post_attempted.as_slice(),
            std::slice::from_ref(&expected[1])
        );
        assert_eq!(post_unattempted, expected[2..]);
        LocalProviderWorkPartitionV2::new(
            expected.clone(),
            recorded,
            post_attempted,
            post_unattempted,
        )
        .expect("post-spawn failure isolates the attempted item");

        assert!(matches!(
            terminal_invocation_failure_classification(
                &expected,
                expected.len(),
                ProviderInvocationAttemptStateV2::NotStarted,
            ),
            Err(LocalProviderRuntimeErrorV2::InvalidWorkPartition)
        ));
    }

    #[test]
    fn terminal_work_item_must_be_the_next_unrecorded_item() {
        let expected = work_item_ids();
        let pre_spawn_partition = LocalProviderWorkPartitionV2::new(
            expected.clone(),
            vec![expected[0].clone()],
            Vec::new(),
            expected[1..].to_vec(),
        )
        .expect("sequential pre-spawn partition");
        validate_terminal_work_item_binding(
            &pre_spawn_partition,
            Some(LocalProviderRuntimeErrorV2::ProcessSpawnFailed),
            Some(LocalProviderTerminalPhaseV2::Invocation),
            Some(&expected[1]),
        )
        .expect("first unattempted item is the terminal item");
        assert!(matches!(
            validate_terminal_work_item_binding(
                &pre_spawn_partition,
                Some(LocalProviderRuntimeErrorV2::ProcessSpawnFailed),
                Some(LocalProviderTerminalPhaseV2::Invocation),
                Some(&expected[2]),
            ),
            Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence)
        ));

        let post_spawn_partition = LocalProviderWorkPartitionV2::new(
            expected.clone(),
            vec![expected[0].clone()],
            vec![expected[1].clone()],
            expected[2..].to_vec(),
        )
        .expect("sequential post-spawn partition");
        assert!(matches!(
            validate_terminal_work_item_binding(
                &post_spawn_partition,
                Some(LocalProviderRuntimeErrorV2::ProcessControlFailed),
                Some(LocalProviderTerminalPhaseV2::Invocation),
                None,
            ),
            Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence)
        ));
    }

    #[test]
    fn preflight_phase_can_bind_a_later_item_without_claiming_dispatch() {
        let expected = work_item_ids();
        let partition = LocalProviderWorkPartitionV2::new(
            expected.clone(),
            Vec::new(),
            Vec::new(),
            expected.clone(),
        )
        .expect("all-unattempted preflight partition");
        validate_terminal_work_item_binding(
            &partition,
            Some(LocalProviderRuntimeErrorV2::ProviderInputInvalid),
            Some(LocalProviderTerminalPhaseV2::Preflight),
            Some(&expected[2]),
        )
        .expect("later preflight item is bound without a dispatch claim");
        assert!(matches!(
            validate_terminal_work_item_binding(
                &partition,
                Some(LocalProviderRuntimeErrorV2::ProviderInputInvalid),
                Some(LocalProviderTerminalPhaseV2::Invocation),
                Some(&expected[2]),
            ),
            Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence)
        ));
        assert!(matches!(
            validate_terminal_work_item_binding(
                &partition,
                Some(LocalProviderRuntimeErrorV2::ProviderInputInvalid),
                Some(LocalProviderTerminalPhaseV2::Preflight),
                None,
            ),
            Err(LocalProviderRuntimeErrorV2::InvalidRunEvidence)
        ));
    }

    #[test]
    fn evidence_bound_host_time_range_is_present_and_ordered() {
        validate_host_time_range_v2(1, 1).expect("equal nonzero second is ordered");
        validate_host_time_range_v2(1, 2).expect("increasing seconds are ordered");
        assert_eq!(
            validate_host_time_range_v2(0, 1),
            Err(LocalProviderRuntimeErrorV2::SystemClockInvalid)
        );
        assert_eq!(
            validate_host_time_range_v2(2, 1),
            Err(LocalProviderRuntimeErrorV2::SystemClockInvalid)
        );
    }
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
extern "C" {
    fn proc_listpgrppids(
        process_group_id: libc::pid_t,
        buffer: *mut libc::c_void,
        buffer_size: libc::c_int,
    ) -> libc::c_int;
}

fn set_nonblocking(fd: i32) -> Result<(), LocalProviderRuntimeErrorV2> {
    // SAFETY: fcntl is called with a live child-pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
    }
    // SAFETY: fcntl updates only the descriptor's file status flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
    }
    Ok(())
}

fn poll_process_pipes(
    stdin_fd: Option<i32>,
    stdout_fd: Option<i32>,
    stderr_fd: Option<i32>,
) -> Result<(), LocalProviderRuntimeErrorV2> {
    let mut descriptors = [
        libc::pollfd {
            fd: stdin_fd.unwrap_or(-1),
            events: libc::POLLOUT,
            revents: 0,
        },
        libc::pollfd {
            fd: stdout_fd.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: stderr_fd.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    // SAFETY: descriptors points to a valid fixed-size pollfd array.
    let result = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            POLL_INTERVAL_MILLIS,
        )
    };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() != ErrorKind::Interrupted {
            return Err(LocalProviderRuntimeErrorV2::ProcessControlFailed);
        }
    }
    Ok(())
}

fn write_nonblocking(stdin: &mut File, bytes: &[u8]) -> io::Result<usize> {
    if bytes.is_empty() {
        return Ok(0);
    }
    stdin.write(&bytes[..bytes.len().min(16 * 1024)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureProgress {
    Pending,
    Eof,
    Overflow,
}

fn read_nonblocking_capture<R: Read>(
    reader: &mut R,
    capture: &mut Vec<u8>,
    limit: usize,
) -> io::Result<CaptureProgress> {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let remaining = limit.saturating_sub(capture.len());
        let read_len = buffer.len().min(remaining.saturating_add(1)).max(1);
        match reader.read(&mut buffer[..read_len]) {
            Ok(0) => return Ok(CaptureProgress::Eof),
            Ok(count) => {
                let retained = count.min(remaining);
                capture.extend_from_slice(&buffer[..retained]);
                if count > remaining {
                    return Ok(CaptureProgress::Overflow);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                return Ok(CaptureProgress::Pending)
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    fn private_test_root(label: &str) -> PathBuf {
        for _ in 0..128 {
            let counter = RUN_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "whoathere-artifact-review-runtime-unit-{label}-{}-{counter}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => return path,
                Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create private unit-test root: {error}"),
            }
        }
        panic!("could not create private unit-test root")
    }

    #[test]
    fn run_directory_cleanup_is_explicit_and_fail_closed() {
        let root = private_test_root("cleanup");
        let run_directory = root.join("run");
        create_private_directory(&run_directory).expect("create guarded run directory");
        let mut guard = RunDirectoryGuard::new(run_directory.clone());
        guard.cleanup().expect("remove guarded run directory");
        assert!(!run_directory.exists());
        guard.cleanup().expect("verified cleanup is idempotent");

        let invalid_path = root.join("not-a-directory");
        fs::write(&invalid_path, b"not a run directory").expect("create invalid guard target");
        let mut invalid_guard = RunDirectoryGuard::new(invalid_path.clone());
        assert_eq!(
            invalid_guard.cleanup(),
            Err(LocalProviderRuntimeErrorV2::RunDirectoryCleanupFailed)
        );
        drop(invalid_guard);
        fs::remove_file(invalid_path).expect("remove invalid guard target");
        fs::remove_dir(root).expect("remove private unit-test root");
    }

    #[test]
    fn occupied_staging_path_reports_staging_error_and_remains_cleanup_capable() {
        let root = private_test_root("staging-failure");
        let source_path = root.join("provider-source");
        fs::copy("/usr/bin/true", &source_path).expect("copy inert executable source");
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o500))
            .expect("set safe executable mode");
        let expected_sha256 =
            Sha256Digest::from_bytes(&fs::read(&source_path).expect("read executable source"));
        let run_directory = root.join("run");
        create_private_directory(&run_directory).expect("create private run directory");
        fs::write(
            run_directory.join("authorized-provider"),
            b"occupied staging destination",
        )
        .expect("occupy staging destination");

        assert!(matches!(
            stage_verified_executable(&source_path, &run_directory, &expected_sha256),
            Err(LocalProviderRuntimeErrorV2::ExecutableStagingFailed)
        ));
        let mut guard = RunDirectoryGuard::new(run_directory.clone());
        guard
            .cleanup()
            .expect("staging failure directory remains explicitly cleanable");
        assert!(!run_directory.exists());
        fs::remove_file(source_path).expect("remove executable source");
        fs::remove_dir(root).expect("remove private unit-test root");
    }

    #[test]
    fn leader_exit_is_observed_without_reaping_and_post_reap_group_use_is_rejected() {
        let root = private_test_root("waitid");
        let spawned = spawn_provider_process_macos(Path::new("/usr/bin/true"), &root, &root, &root)
            .expect("spawn inert true process");
        let SpawnedProviderProcess {
            process_id,
            stdin,
            stdout,
            stderr,
        } = spawned;
        drop((stdin, stdout, stderr));
        let mut process = ChildProcessGroupGuard::new(process_id).expect("dedicated process group");
        let deadline = Instant::now() + Duration::from_secs(2);
        while !process
            .leader_has_exited_without_reaping()
            .expect("observe waitable leader")
        {
            assert!(Instant::now() < deadline, "leader did not exit in time");
            std::thread::yield_now();
        }
        assert!(process
            .leader_has_exited_without_reaping()
            .expect("cached unreaped observation"));
        assert!(!process
            .group_has_other_members()
            .expect("leader is the only group member"));
        assert!(process.reap().expect("reap observed leader").success());
        assert!(matches!(
            process.leader_has_exited_without_reaping(),
            Err(LocalProviderRuntimeErrorV2::ProcessControlFailed)
        ));
        assert!(matches!(
            process.group_has_other_members(),
            Err(LocalProviderRuntimeErrorV2::ProcessControlFailed)
        ));
        process.disarm();
        fs::remove_dir(root).expect("remove waitid test root");
    }
}
