//! Subscription-authenticated hosted CLI adapters for Artifact Review v2.
//!
//! These adapters invoke vendor-supported local clients in a private, empty
//! working directory. Package bytes are carried only inside the bounded
//! canonical provider input on stdin; no artifact path is exposed and no
//! package code is executed. The clients' control-plane network access remains
//! necessary and is not a detonation network. Receipts describe host-observed
//! facts and never attest provider internals or authorize package admission.

use crate::ArtifactReviewCancellationTokenV2;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::ffi::OsString;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileExt, MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use whoathere_artifact::{NormalizedArtifact, Sha256Digest};
use whoathere_detector::{
    artifact_review_model_output_schema_json_v2, ArtifactReviewChannelIsolationV2,
    ArtifactReviewCoverageCompletenessV2, ArtifactReviewModelIdentityPostureV2,
    ArtifactReviewProviderIdentityV2, ArtifactReviewProviderOutputV2, ArtifactReviewRequestV2,
    ArtifactReviewWorkItemStatusV2, MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2,
    MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2,
};

pub const ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V3: &str =
    "whoathere.artifact_ai_provider_receipt.v3";
pub const ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V2: &str = ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V3;
pub const ARTIFACT_AI_PROVIDER_READINESS_SCHEMA_V2: &str =
    "whoathere.artifact_ai_provider_readiness.v3";
pub const VERIFIED_HOSTED_RUNTIME_BATCH_SCHEMA_V3: &str =
    "whoathere.verified_hosted_runtime_batch.v3";
pub const VERIFIED_HOSTED_RUNTIME_ROW_SCHEMA_V3: &str = "whoathere.verified_hosted_runtime_row.v3";
pub const CLAUDE_SUBSCRIPTION_ADAPTER_ID_V2: &str =
    "whoathere-claude-code-subscription-artifact-review";
pub const CLAUDE_SUBSCRIPTION_ADAPTER_VERSION_V2: &str = "1.2.0";
pub const CODEX_SUBSCRIPTION_ADAPTER_ID_V2: &str = "whoathere-codex-subscription-artifact-review";
pub const CODEX_SUBSCRIPTION_ADAPTER_VERSION_V2: &str = "1.2.0";
pub const CLAUDE_CODE_SUPPORTED_VERSION_V2: &str = "2.1.211 (Claude Code)";
pub const CODEX_CLI_SUPPORTED_VERSION_V2: &str = "codex-cli 0.144.4";

const CLAUDE_ADAPTER_CONTRACT_V2: &str = "whoathere.hosted_cli_adapter.claude.v2\0measured_native_exec\0claude_print\0input_text\0safe_mode\0no_tools\0no_session\0no_settings\0empty_mcp_servers\0strict_json_schema\0subscription_only\0auth_continuity\0nonblocking_capture\0nonessential_traffic_disabled\0autoupdater_disabled";
const CODEX_ADAPTER_CONTRACT_V2: &str = "whoathere.hosted_cli_adapter.codex.v2\0measured_native_exec\0codex_exec_0.144.4\0ephemeral\0read_only\0ignore_user_config\0ignore_rules\0strict_config\0openai_chatgpt_forced\0known_tool_surfaces_disabled\0web_disabled\0history_disabled\0strict_json_schema\0auth_continuity\0nonblocking_capture";
const MAX_CLIENT_EXECUTABLE_BYTES_V2: u64 = 512 * 1024 * 1024;
const MAX_READINESS_CAPTURE_BYTES_V2: usize = 32 * 1024;
const MAX_HOSTED_STDERR_CAPTURE_BYTES_V2: usize = 128 * 1024;
const MAX_CLIENT_VERSION_BYTES_V2: usize = 512;
const MAX_AUTH_STATUS_BYTES_V2: usize = 8 * 1024;
const MAX_HOSTED_TIMEOUT_V2: Duration = Duration::from_secs(10 * 60);
const MAX_TERMINATION_GRACE_V2: Duration = Duration::from_secs(5);
const DEFAULT_READINESS_TIMEOUT_V2: Duration = Duration::from_secs(30);
const MAX_READINESS_TIMEOUT_V2: Duration = Duration::from_secs(2 * 60);
const POLL_INTERVAL_V2: Duration = Duration::from_millis(10);
const MAX_HOSTED_RUNTIME_BINDING_ID_BYTES_V3: usize = 512;
const MAX_HOSTED_RUNTIME_CHALLENGE_LIFETIME_SECONDS_V3: u64 = 60 * 60;
#[cfg(not(target_os = "macos"))]
const HELD_EXECUTABLE_FD_V2: libc::c_int = 198;
pub const HOSTED_AUTH_HOME_MARKER_FILE_V3: &str = ".whoathere-dedicated-hosted-auth-v3";
pub const HOSTED_AUTH_HOME_MARKER_CONTENT_V3: &[u8] =
    b"whoathere.dedicated_hosted_subscription_auth_home.v3\n";

const CODEX_DISABLED_TOOL_FEATURES_V2: &[&str] = &[
    "apps",
    "enable_mcp_apps",
    "auth_elicitation",
    "browser_use",
    "browser_use_external",
    "computer_use",
    "in_app_browser",
    "image_generation",
    "workspace_dependencies",
    "plugins",
    "plugin_sharing",
    "remote_plugin",
    "skill_mcp_dependency_install",
    "tool_call_mcp_elicitation",
    "tool_suggest",
    "multi_agent",
    "multi_agent_v2",
    "enable_fanout",
    "shell_tool",
    "unified_exec",
    "shell_snapshot",
    "hooks",
    "goals",
    "network_proxy",
    "standalone_web_search",
    "artifact",
    "code_mode",
    "code_mode_only",
    "request_permissions_tool",
];

static HOSTED_RUN_COUNTER_V2: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAiProviderKindV2 {
    Claude,
    Codex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAiProviderTransportV2 {
    ClaudeCodePrintCliV1,
    CodexExecCliV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAiAuthenticationModeV2 {
    ClaudeSubscription,
    ChatGptSubscription,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAiReadinessStatusV2 {
    Ready,
    ClientExecutionFailed,
    ClientTimedOut,
    Cancelled,
    ClientIdentityChanged,
    ClientVersionInvalid,
    ClientArgumentContractUnsupported,
    IsolationCheckFailed,
    SubscriptionNotAuthenticated,
    ApiKeyAuthenticationRejected,
    AmbiguousAuthenticationRejected,
    AuthenticationStatusInvalid,
    AuthenticationHomeInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAiExecutionStatusV2 {
    Completed,
    ClientNonZeroExit,
    TimedOut,
    Cancelled,
    StdoutLimitExceeded,
    StderrLimitExceeded,
    OutputCaptureIncomplete,
    ProcessCleanupFailed,
    OutputEnvelopeInvalid,
    ClientIdentityChanged,
    IsolationCheckFailed,
    AuthenticationContinuityFailed,
    ObservedModelMismatch,
    PostExecutionVerificationFailed,
}

/// Describes what the host can honestly establish about a requested control.
/// A successful client exit never upgrades provider-internal behavior to a
/// host-verified fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAiControlPostureV2 {
    HostVerified,
    RequestedClientEnforcedProviderOpaque,
    ProviderHostedOpaque,
    NotEstablished,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedCliExecutableFormatV2 {
    Elf64Native,
    MachO64Native,
    MachOFatNative,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostedCliExecutableInspectionV2 {
    sha256: Sha256Digest,
    byte_len: u64,
    format: HostedCliExecutableFormatV2,
}

impl HostedCliExecutableInspectionV2 {
    pub fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    pub const fn byte_len(&self) -> u64 {
        self.byte_len
    }

    pub const fn format(&self) -> HostedCliExecutableFormatV2 {
        self.format
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactAiObservedModelV2 {
    Unavailable,
    Present { model_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAiAvailableInferenceControlsV2 {
    pub requested_model_control: ArtifactAiControlPostureV2,
    pub strict_output_schema_control: ArtifactAiControlPostureV2,
    pub read_only_sandbox_control: ArtifactAiControlPostureV2,
    pub tools_disabled_control: ArtifactAiControlPostureV2,
    pub web_search_disabled_control: ArtifactAiControlPostureV2,
    pub session_persistence_disabled_control: ArtifactAiControlPostureV2,
    pub user_customizations_disabled_control: ArtifactAiControlPostureV2,
    pub memory_disabled_control: ArtifactAiControlPostureV2,
    pub seed_control_exposed: bool,
    pub temperature_control_exposed: bool,
    pub top_p_control_exposed: bool,
    pub context_tokens_control_exposed: bool,
    pub max_output_tokens_control_exposed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAiProviderReadinessV2 {
    schema_version: String,
    provider: ArtifactAiProviderKindV2,
    transport: ArtifactAiProviderTransportV2,
    status: ArtifactAiReadinessStatusV2,
    authentication_mode: Option<ArtifactAiAuthenticationModeV2>,
    client_executable_sha256: Sha256Digest,
    client_version: Option<String>,
    version_capture_sha256: Sha256Digest,
    argument_probe_stdout_sha256: Sha256Digest,
    argument_probe_stderr_sha256: Sha256Digest,
    auth_status_stdout_sha256: Sha256Digest,
    auth_status_stderr_sha256: Sha256Digest,
    auth_observation_sha256: Sha256Digest,
    argument_contract_sha256: Sha256Digest,
    argument_contract_posture: ArtifactAiControlPostureV2,
    authentication_home_posture: ArtifactAiControlPostureV2,
    client_executable_posture: ArtifactAiControlPostureV2,
    available_inference_controls: ArtifactAiAvailableInferenceControlsV2,
    empty_working_directory_posture: ArtifactAiControlPostureV2,
    host_filesystem_isolation_posture: ArtifactAiControlPostureV2,
    api_key_environment_stripped: bool,
    interactive_login_attempted: bool,
}

impl ArtifactAiProviderReadinessV2 {
    pub fn status(&self) -> ArtifactAiReadinessStatusV2 {
        self.status
    }

    pub fn authentication_mode(&self) -> Option<ArtifactAiAuthenticationModeV2> {
        self.authentication_mode
    }

    pub fn client_version(&self) -> Option<&str> {
        self.client_version.as_deref()
    }

    pub const fn interactive_login_attempted(&self) -> bool {
        self.interactive_login_attempted
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAiProviderReceiptV2 {
    schema_version: String,
    provider: ArtifactAiProviderKindV2,
    transport: ArtifactAiProviderTransportV2,
    authentication_mode: ArtifactAiAuthenticationModeV2,
    client_version: String,
    client_executable_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    work_item_id: Sha256Digest,
    invocation_sha256: Sha256Digest,
    provider_adapter_sha256: Sha256Digest,
    model_identity_sha256: Sha256Digest,
    model_identity_posture: ArtifactReviewModelIdentityPostureV2,
    requested_model: String,
    observed_model: ArtifactAiObservedModelV2,
    prompt_template_sha256: Sha256Digest,
    model_output_schema_sha256: Sha256Digest,
    provider_input_sha256: Sha256Digest,
    provider_input_byte_len: u64,
    effective_arguments_sha256: Sha256Digest,
    effective_environment_sha256: Sha256Digest,
    trusted_instruction_sha256: Sha256Digest,
    pre_auth_observation_sha256: Sha256Digest,
    post_auth_observation_sha256: Option<Sha256Digest>,
    raw_stdout_sha256: Sha256Digest,
    raw_stdout_byte_len: u64,
    raw_stderr_sha256: Sha256Digest,
    raw_stderr_byte_len: u64,
    model_output_sha256: Option<Sha256Digest>,
    model_output_byte_len: Option<u64>,
    started_at_unix_millis: u64,
    finished_at_unix_millis: u64,
    elapsed_millis: u64,
    status: ArtifactAiExecutionStatusV2,
    available_inference_controls: ArtifactAiAvailableInferenceControlsV2,
    strict_output_schema_requested: bool,
    api_key_environment_stripped: bool,
    empty_working_directory_before_verified: bool,
    empty_working_directory_after_verified: bool,
    authentication_home_isolation_posture: ArtifactAiControlPostureV2,
    empty_working_directory_posture: ArtifactAiControlPostureV2,
    customizations_disabled_posture: ArtifactAiControlPostureV2,
    model_tools_disabled_posture: ArtifactAiControlPostureV2,
    model_web_access_disabled_posture: ArtifactAiControlPostureV2,
    host_filesystem_isolation_posture: ArtifactAiControlPostureV2,
    provider_control_plane_isolation_posture: ArtifactAiControlPostureV2,
    detached_descendant_containment_posture: ArtifactAiControlPostureV2,
    package_artifact_path_exposed: bool,
    package_code_executed: bool,
    stdin_write_complete: bool,
    stdout_eof_verified: bool,
    stderr_eof_verified: bool,
    pipe_drain_timed_out: bool,
    process_group_cleanup_verified: bool,
    run_directory_cleanup_verified: bool,
    client_executable_posture: ArtifactAiControlPostureV2,
}

impl std::fmt::Debug for ArtifactAiProviderReceiptV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactAiProviderReceiptV2")
            .field("provider", &self.provider)
            .field("transport", &self.transport)
            .field("authentication_mode", &self.authentication_mode)
            .field("client_version", &self.client_version)
            .field("request_sha256", &self.request_sha256)
            .field("work_item_id", &self.work_item_id)
            .field("invocation_sha256", &self.invocation_sha256)
            .field("model_identity_sha256", &self.model_identity_sha256)
            .field("status", &self.status)
            .field("provider_input", &"<redacted>")
            .field("provider_stdout", &"<redacted>")
            .field("provider_stderr", &"<redacted>")
            .finish()
    }
}

impl ArtifactAiProviderReceiptV2 {
    pub fn status(&self) -> ArtifactAiExecutionStatusV2 {
        self.status
    }

    pub fn provider(&self) -> ArtifactAiProviderKindV2 {
        self.provider
    }

    pub fn transport(&self) -> ArtifactAiProviderTransportV2 {
        self.transport
    }

    pub fn authentication_mode(&self) -> ArtifactAiAuthenticationModeV2 {
        self.authentication_mode
    }

    pub fn model_identity_sha256(&self) -> &Sha256Digest {
        &self.model_identity_sha256
    }

    pub fn model_identity_posture(&self) -> &ArtifactReviewModelIdentityPostureV2 {
        &self.model_identity_posture
    }

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn work_item_id(&self) -> &Sha256Digest {
        &self.work_item_id
    }

    pub fn started_at_unix_millis(&self) -> u64 {
        self.started_at_unix_millis
    }

    pub fn finished_at_unix_millis(&self) -> u64 {
        self.finished_at_unix_millis
    }

    pub fn elapsed_millis(&self) -> u64 {
        self.elapsed_millis
    }

    pub fn raw_stdout_byte_len(&self) -> u64 {
        self.raw_stdout_byte_len
    }

    pub fn raw_stderr_byte_len(&self) -> u64 {
        self.raw_stderr_byte_len
    }

    pub fn model_output_byte_len(&self) -> Option<u64> {
        self.model_output_byte_len
    }

    pub fn model_output_sha256(&self) -> Option<&Sha256Digest> {
        self.model_output_sha256.as_ref()
    }

    pub fn canonical_json_v3(&self) -> Result<Vec<u8>, ArtifactAiProviderErrorV2> {
        serde_json_canonicalizer::to_vec(self).map_err(|_| ArtifactAiProviderErrorV2::Serialization)
    }

    pub fn canonical_json_v2(&self) -> Result<Vec<u8>, ArtifactAiProviderErrorV2> {
        self.canonical_json_v3()
    }

    pub fn receipt_sha256(&self) -> Result<Sha256Digest, ArtifactAiProviderErrorV2> {
        self.canonical_json_v2()
            .map(|bytes| Sha256Digest::from_bytes(&bytes))
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }

    pub const fn isolation_complete_for_no_finding(&self) -> bool {
        false
    }
}

pub struct ArtifactAiInvocationOutcomeV2 {
    provider_output: ArtifactReviewProviderOutputV2,
    receipt: ArtifactAiProviderReceiptV2,
    provider_output_bytes: Vec<u8>,
    output_channel_isolation: ArtifactReviewChannelIsolationV2,
    output_no_truncation_verified: bool,
}

impl std::fmt::Debug for ArtifactAiInvocationOutcomeV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ArtifactAiInvocationOutcomeV2")
            .field("provider_output", &self.provider_output)
            .field("receipt", &self.receipt)
            .finish()
    }
}

impl ArtifactAiInvocationOutcomeV2 {
    pub fn provider_output(&self) -> &ArtifactReviewProviderOutputV2 {
        &self.provider_output
    }

    pub fn receipt(&self) -> &ArtifactAiProviderReceiptV2 {
        &self.receipt
    }

    pub fn into_parts(self) -> (ArtifactReviewProviderOutputV2, ArtifactAiProviderReceiptV2) {
        (self.provider_output, self.receipt)
    }
}

/// A caller-issued, single-use value that authorizes one exact hosted runtime
/// batch. Consuming the value prevents accidental in-process reuse; durable
/// replay prevention remains the issuing authority's responsibility.
#[derive(Debug, PartialEq, Eq)]
pub struct HostedRuntimeChallengeV3 {
    authority_id: String,
    challenge_id: String,
    evidence_id: String,
    run_id: String,
    challenge_binding_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    expected_work_set_sha256: Sha256Digest,
    expected_work_item_count: u32,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl HostedRuntimeChallengeV3 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        authority_id: impl Into<String>,
        challenge_id: impl Into<String>,
        evidence_id: impl Into<String>,
        run_id: impl Into<String>,
        challenge_binding_sha256: Sha256Digest,
        request_sha256: Sha256Digest,
        expected_work_set_sha256: Sha256Digest,
        expected_work_item_count: u32,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
    ) -> Result<Self, ArtifactAiProviderErrorV2> {
        let authority_id = authority_id.into();
        let challenge_id = challenge_id.into();
        let evidence_id = evidence_id.into();
        let run_id = run_id.into();
        if !valid_hosted_runtime_binding_id_v3(&authority_id)
            || !valid_hosted_runtime_binding_id_v3(&challenge_id)
            || !valid_hosted_runtime_binding_id_v3(&evidence_id)
            || !valid_hosted_runtime_binding_id_v3(&run_id)
            || expected_work_item_count == 0
            || issued_at_unix_seconds >= expires_at_unix_seconds
            || expires_at_unix_seconds
                .checked_sub(issued_at_unix_seconds)
                .is_none_or(|lifetime| lifetime > MAX_HOSTED_RUNTIME_CHALLENGE_LIFETIME_SECONDS_V3)
        {
            return Err(ArtifactAiProviderErrorV2::InvalidRuntimeChallenge);
        }
        Ok(Self {
            authority_id,
            challenge_id,
            evidence_id,
            run_id,
            challenge_binding_sha256,
            request_sha256,
            expected_work_set_sha256,
            expected_work_item_count,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
        })
    }

    pub fn authority_id(&self) -> &str {
        &self.authority_id
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

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn expected_work_set_sha256(&self) -> &Sha256Digest {
        &self.expected_work_set_sha256
    }

    pub const fn expected_work_item_count(&self) -> u32 {
        self.expected_work_item_count
    }

    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifiedHostedRuntimeRowStateV3 {
    Complete,
    IncompletePositive,
    Truncated,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedRuntimeRowFailureV3 {
    ClientNonZeroExit,
    TimedOut,
    Cancelled,
    StdoutLimitExceeded,
    StderrLimitExceeded,
    OutputCaptureIncomplete,
    ProcessCleanupFailed,
    OutputEnvelopeInvalid,
    ClientIdentityChanged,
    IsolationCheckFailed,
    AuthenticationContinuityFailed,
    ObservedModelMismatch,
    PostExecutionVerificationFailed,
    InternalOutputStateMismatch,
}

/// Public, pure digest input. Constructing this value does not construct or
/// authenticate a runtime row; it only makes independent recomputation
/// possible for an evidence signer.
pub struct HostedRuntimeRowBindingInputV3<'a> {
    pub work_item_id: &'a Sha256Digest,
    pub state: VerifiedHostedRuntimeRowStateV3,
    pub failure_reason: Option<HostedRuntimeRowFailureV3>,
    pub output_status: ArtifactReviewWorkItemStatusV2,
    pub output_channel_isolation: ArtifactReviewChannelIsolationV2,
    pub output_no_truncation_verified: bool,
    pub provider_output_bytes: &'a [u8],
    pub receipt_canonical_json: &'a [u8],
}

/// Public, pure digest input. This projection binds the complete challenge,
/// request/work set, timing envelope, model posture, and independently
/// recomputed row digests without making those claims authoritative.
pub struct HostedRuntimeBatchBindingInputV3<'a> {
    pub authority_id: &'a str,
    pub challenge_id: &'a str,
    pub evidence_id: &'a str,
    pub run_id: &'a str,
    pub challenge_binding_sha256: &'a Sha256Digest,
    pub request_sha256: &'a Sha256Digest,
    pub expected_work_set_sha256: &'a Sha256Digest,
    pub expected_work_item_count: u32,
    pub expected_work_item_ids: &'a [Sha256Digest],
    pub provider: ArtifactAiProviderKindV2,
    pub model_identity_sha256: &'a Sha256Digest,
    pub model_identity_posture: &'a ArtifactReviewModelIdentityPostureV2,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub started_at_unix_millis: u64,
    pub finished_at_unix_millis: u64,
    pub coverage_complete: bool,
    pub row_sha256s: &'a [Sha256Digest],
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostedRuntimeExpectedWorkSetWireV3<'a> {
    schema_version: &'static str,
    request_sha256: &'a str,
    work_item_ids: Vec<&'a str>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostedRuntimeRowBindingWireV3<'a> {
    schema_version: &'static str,
    work_item_id: &'a Sha256Digest,
    state: VerifiedHostedRuntimeRowStateV3,
    failure_reason: Option<HostedRuntimeRowFailureV3>,
    output_status: ArtifactReviewWorkItemStatusV2,
    output_channel_isolation: ArtifactReviewChannelIsolationV2,
    output_no_truncation_verified: bool,
    provider_output_sha256: Sha256Digest,
    provider_output_byte_len: u64,
    receipt_sha256: Sha256Digest,
    receipt_byte_len: u64,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct HostedRuntimeBatchBindingWireV3<'a> {
    schema_version: &'static str,
    authority_id: &'a str,
    challenge_id: &'a str,
    evidence_id: &'a str,
    run_id: &'a str,
    challenge_binding_sha256: &'a Sha256Digest,
    request_sha256: &'a Sha256Digest,
    expected_work_set_sha256: &'a Sha256Digest,
    expected_work_item_count: u32,
    expected_work_item_ids: &'a [Sha256Digest],
    provider: ArtifactAiProviderKindV2,
    model_identity_sha256: &'a Sha256Digest,
    model_identity_posture: &'a ArtifactReviewModelIdentityPostureV2,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    started_at_unix_millis: u64,
    finished_at_unix_millis: u64,
    coverage_complete: bool,
    row_sha256s: &'a [Sha256Digest],
}

pub fn hosted_expected_work_set_sha256_v3(
    request: &ArtifactReviewRequestV2,
) -> Result<Sha256Digest, ArtifactAiProviderErrorV2> {
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactAiProviderErrorV2::RequestBindingMismatch)?;
    let work_item_ids = exact_request_work_item_ids_v3(request)?;
    let wire = HostedRuntimeExpectedWorkSetWireV3 {
        schema_version: "whoathere.artifact_review_expected_work_set.v2",
        request_sha256: request_sha256.as_str(),
        work_item_ids: work_item_ids.iter().map(Sha256Digest::as_str).collect(),
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactAiProviderErrorV2::Serialization)?;
    Ok(Sha256Digest::from_bytes(&canonical))
}

pub fn recompute_verified_hosted_runtime_row_sha256_v3(
    input: &HostedRuntimeRowBindingInputV3<'_>,
) -> Result<Sha256Digest, ArtifactAiProviderErrorV2> {
    let provider_output_byte_len = u64::try_from(input.provider_output_bytes.len())
        .map_err(|_| ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid)?;
    let receipt_byte_len = u64::try_from(input.receipt_canonical_json.len())
        .map_err(|_| ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid)?;
    let wire = HostedRuntimeRowBindingWireV3 {
        schema_version: VERIFIED_HOSTED_RUNTIME_ROW_SCHEMA_V3,
        work_item_id: input.work_item_id,
        state: input.state,
        failure_reason: input.failure_reason,
        output_status: input.output_status,
        output_channel_isolation: input.output_channel_isolation,
        output_no_truncation_verified: input.output_no_truncation_verified,
        provider_output_sha256: Sha256Digest::from_bytes(input.provider_output_bytes),
        provider_output_byte_len,
        receipt_sha256: Sha256Digest::from_bytes(input.receipt_canonical_json),
        receipt_byte_len,
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactAiProviderErrorV2::Serialization)?;
    Ok(Sha256Digest::from_bytes(&canonical))
}

pub fn recompute_verified_hosted_runtime_batch_sha256_v3(
    input: &HostedRuntimeBatchBindingInputV3<'_>,
) -> Result<Sha256Digest, ArtifactAiProviderErrorV2> {
    let wire = HostedRuntimeBatchBindingWireV3 {
        schema_version: VERIFIED_HOSTED_RUNTIME_BATCH_SCHEMA_V3,
        authority_id: input.authority_id,
        challenge_id: input.challenge_id,
        evidence_id: input.evidence_id,
        run_id: input.run_id,
        challenge_binding_sha256: input.challenge_binding_sha256,
        request_sha256: input.request_sha256,
        expected_work_set_sha256: input.expected_work_set_sha256,
        expected_work_item_count: input.expected_work_item_count,
        expected_work_item_ids: input.expected_work_item_ids,
        provider: input.provider,
        model_identity_sha256: input.model_identity_sha256,
        model_identity_posture: input.model_identity_posture,
        issued_at_unix_seconds: input.issued_at_unix_seconds,
        expires_at_unix_seconds: input.expires_at_unix_seconds,
        started_at_unix_millis: input.started_at_unix_millis,
        finished_at_unix_millis: input.finished_at_unix_millis,
        coverage_complete: input.coverage_complete,
        row_sha256s: input.row_sha256s,
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactAiProviderErrorV2::Serialization)?;
    Ok(Sha256Digest::from_bytes(&canonical))
}

pub struct VerifiedHostedRuntimeRowV3 {
    work_item_id: Sha256Digest,
    state: VerifiedHostedRuntimeRowStateV3,
    failure_reason: Option<HostedRuntimeRowFailureV3>,
    provider_output: ArtifactReviewProviderOutputV2,
    provider_output_bytes: Vec<u8>,
    output_channel_isolation: ArtifactReviewChannelIsolationV2,
    output_no_truncation_verified: bool,
    receipt: ArtifactAiProviderReceiptV2,
    receipt_canonical_json: Vec<u8>,
    row_sha256: Sha256Digest,
}

impl std::fmt::Debug for VerifiedHostedRuntimeRowV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedHostedRuntimeRowV3")
            .field("work_item_id", &self.work_item_id)
            .field("state", &self.state)
            .field("failure_reason", &self.failure_reason)
            .field("provider_output", &"<redacted>")
            .field("receipt", &"<redacted>")
            .field("row_sha256", &self.row_sha256)
            .finish()
    }
}

impl VerifiedHostedRuntimeRowV3 {
    pub fn work_item_id(&self) -> &Sha256Digest {
        &self.work_item_id
    }

    pub const fn state(&self) -> VerifiedHostedRuntimeRowStateV3 {
        self.state
    }

    pub const fn failure_reason(&self) -> Option<HostedRuntimeRowFailureV3> {
        self.failure_reason
    }

    pub fn provider_output(&self) -> &ArtifactReviewProviderOutputV2 {
        &self.provider_output
    }

    pub fn provider_output_bytes(&self) -> &[u8] {
        &self.provider_output_bytes
    }

    pub const fn output_channel_isolation(&self) -> ArtifactReviewChannelIsolationV2 {
        self.output_channel_isolation
    }

    pub const fn output_no_truncation_verified(&self) -> bool {
        self.output_no_truncation_verified
    }

    pub fn receipt(&self) -> &ArtifactAiProviderReceiptV2 {
        &self.receipt
    }

    pub fn receipt_canonical_json_v3(&self) -> &[u8] {
        &self.receipt_canonical_json
    }

    pub fn row_sha256(&self) -> &Sha256Digest {
        &self.row_sha256
    }

    pub fn into_parts(
        self,
    ) -> (
        ArtifactReviewProviderOutputV2,
        ArtifactAiProviderReceiptV2,
        Vec<u8>,
        Vec<u8>,
    ) {
        (
            self.provider_output,
            self.receipt,
            self.provider_output_bytes,
            self.receipt_canonical_json,
        )
    }
}

pub struct VerifiedHostedRuntimeBatchV3 {
    authority_id: String,
    challenge_id: String,
    evidence_id: String,
    run_id: String,
    challenge_binding_sha256: Sha256Digest,
    request_sha256: Sha256Digest,
    expected_work_set_sha256: Sha256Digest,
    expected_work_item_count: u32,
    expected_work_item_ids: Vec<Sha256Digest>,
    provider: ArtifactAiProviderKindV2,
    model_identity_sha256: Sha256Digest,
    model_identity_posture: ArtifactReviewModelIdentityPostureV2,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    started_at_unix_millis: u64,
    finished_at_unix_millis: u64,
    coverage_complete: bool,
    rows: Vec<VerifiedHostedRuntimeRowV3>,
    runtime_batch_sha256: Sha256Digest,
}

impl std::fmt::Debug for VerifiedHostedRuntimeBatchV3 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VerifiedHostedRuntimeBatchV3")
            .field("authority_id", &self.authority_id)
            .field("challenge_id", &self.challenge_id)
            .field("evidence_id", &self.evidence_id)
            .field("run_id", &self.run_id)
            .field("request_sha256", &self.request_sha256)
            .field("expected_work_item_count", &self.expected_work_item_count)
            .field("coverage_complete", &self.coverage_complete)
            .field("row_count", &self.rows.len())
            .field("runtime_batch_sha256", &self.runtime_batch_sha256)
            .finish()
    }
}

impl VerifiedHostedRuntimeBatchV3 {
    pub fn authority_id(&self) -> &str {
        &self.authority_id
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

    pub fn request_sha256(&self) -> &Sha256Digest {
        &self.request_sha256
    }

    pub fn expected_work_set_sha256(&self) -> &Sha256Digest {
        &self.expected_work_set_sha256
    }

    pub const fn expected_work_item_count(&self) -> u32 {
        self.expected_work_item_count
    }

    pub fn expected_work_item_ids(&self) -> &[Sha256Digest] {
        &self.expected_work_item_ids
    }

    pub const fn provider(&self) -> ArtifactAiProviderKindV2 {
        self.provider
    }

    pub fn model_identity_sha256(&self) -> &Sha256Digest {
        &self.model_identity_sha256
    }

    pub fn model_identity_posture(&self) -> &ArtifactReviewModelIdentityPostureV2 {
        &self.model_identity_posture
    }

    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    pub const fn started_at_unix_millis(&self) -> u64 {
        self.started_at_unix_millis
    }

    pub const fn finished_at_unix_millis(&self) -> u64 {
        self.finished_at_unix_millis
    }

    pub const fn coverage_complete(&self) -> bool {
        self.coverage_complete
    }

    pub fn rows(&self) -> &[VerifiedHostedRuntimeRowV3] {
        &self.rows
    }

    pub fn runtime_batch_sha256(&self) -> &Sha256Digest {
        &self.runtime_batch_sha256
    }

    pub fn into_rows(self) -> Vec<VerifiedHostedRuntimeRowV3> {
        self.rows
    }
}

pub fn validate_verified_hosted_runtime_row_v3(
    row: &VerifiedHostedRuntimeRowV3,
) -> Result<(), ArtifactAiProviderErrorV2> {
    let receipt_json = row.receipt.canonical_json_v3()?;
    let expected_state = runtime_row_state_v3(
        row.receipt.status,
        row.provider_output.status(),
        &row.provider_output_bytes,
    )?;
    let expected_failure = runtime_row_failure_v3(
        row.receipt.status,
        row.provider_output.status(),
        expected_state,
    );
    let expected_channel = match row.receipt.provider {
        ArtifactAiProviderKindV2::Claude => {
            ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted
        }
        ArtifactAiProviderKindV2::Codex => ArtifactReviewChannelIsolationV2::CollapsedPrompt,
    };
    let expected_no_truncation = match row.provider_output.status() {
        ArtifactReviewWorkItemStatusV2::Completed => true,
        ArtifactReviewWorkItemStatusV2::Truncated => false,
        ArtifactReviewWorkItemStatusV2::Failed => row.receipt.stdout_eof_verified,
    };
    let output_sha256 = Sha256Digest::from_bytes(&row.provider_output_bytes);
    let output_len = u64::try_from(row.provider_output_bytes.len())
        .map_err(|_| ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid)?;
    let receipt_model_output_matches = if row.provider_output_bytes.is_empty() {
        true
    } else {
        row.receipt.model_output_sha256.as_ref() == Some(&output_sha256)
            && row.receipt.model_output_byte_len == Some(output_len)
    };
    let elapsed_matches = row
        .receipt
        .finished_at_unix_millis
        .checked_sub(row.receipt.started_at_unix_millis)
        == Some(row.receipt.elapsed_millis);
    if row.receipt.schema_version != ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V3
        || row.work_item_id != row.receipt.work_item_id
        || &row.work_item_id != row.provider_output.work_item_id()
        || row.provider_output.captured_output_sha256() != output_sha256
        || row.provider_output.captured_output_len() != row.provider_output_bytes.len()
        || row.receipt_canonical_json != receipt_json
        || row.state != expected_state
        || row.failure_reason != expected_failure
        || row.output_channel_isolation != expected_channel
        || row.output_no_truncation_verified != expected_no_truncation
        || !receipt_model_output_matches
        || !elapsed_matches
        || row.receipt.model_identity_posture
            != ArtifactReviewModelIdentityPostureV2::ProviderHostedOpaqueVersion
        || !row.receipt.run_directory_cleanup_verified
        || !row.receipt.process_group_cleanup_verified
    {
        return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
    }
    let recomputed =
        recompute_verified_hosted_runtime_row_sha256_v3(&HostedRuntimeRowBindingInputV3 {
            work_item_id: &row.work_item_id,
            state: row.state,
            failure_reason: row.failure_reason,
            output_status: row.provider_output.status(),
            output_channel_isolation: row.output_channel_isolation,
            output_no_truncation_verified: row.output_no_truncation_verified,
            provider_output_bytes: &row.provider_output_bytes,
            receipt_canonical_json: &row.receipt_canonical_json,
        })?;
    if recomputed != row.row_sha256 {
        return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
    }
    Ok(())
}

pub fn validate_verified_hosted_runtime_batch_v3(
    batch: &VerifiedHostedRuntimeBatchV3,
) -> Result<(), ArtifactAiProviderErrorV2> {
    let expected_count = usize::try_from(batch.expected_work_item_count)
        .map_err(|_| ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid)?;
    let issued_at_millis = batch
        .issued_at_unix_seconds
        .checked_mul(1_000)
        .ok_or(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid)?;
    let expires_at_millis = batch
        .expires_at_unix_seconds
        .checked_mul(1_000)
        .ok_or(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid)?;
    if !valid_hosted_runtime_binding_id_v3(&batch.authority_id)
        || !valid_hosted_runtime_binding_id_v3(&batch.challenge_id)
        || !valid_hosted_runtime_binding_id_v3(&batch.evidence_id)
        || !valid_hosted_runtime_binding_id_v3(&batch.run_id)
        || expected_count == 0
        || batch.expected_work_item_ids.len() != expected_count
        || batch.rows.len() != expected_count
        || batch.started_at_unix_millis < issued_at_millis
        || batch.finished_at_unix_millis < batch.started_at_unix_millis
        || batch.finished_at_unix_millis >= expires_at_millis
        || batch.model_identity_posture
            != ArtifactReviewModelIdentityPostureV2::ProviderHostedOpaqueVersion
        || batch.coverage_complete
            && batch
                .rows
                .iter()
                .any(|row| row.state != VerifiedHostedRuntimeRowStateV3::Complete)
    {
        return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
    }
    let mut seen = HashSet::with_capacity(expected_count);
    for (expected_id, row) in batch.expected_work_item_ids.iter().zip(&batch.rows) {
        if expected_id != row.work_item_id()
            || !seen.insert(expected_id)
            || row.receipt.request_sha256 != batch.request_sha256
            || row.receipt.provider != batch.provider
            || row.receipt.model_identity_sha256 != batch.model_identity_sha256
            || row.receipt.model_identity_posture != batch.model_identity_posture
        {
            return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
        }
        validate_verified_hosted_runtime_row_v3(row)?;
    }
    if expected_work_set_sha256_from_parts_v3(&batch.request_sha256, &batch.expected_work_item_ids)?
        != batch.expected_work_set_sha256
    {
        return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
    }
    let row_sha256s: Vec<Sha256Digest> = batch
        .rows
        .iter()
        .map(|row| row.row_sha256.clone())
        .collect();
    let recomputed =
        recompute_verified_hosted_runtime_batch_sha256_v3(&HostedRuntimeBatchBindingInputV3 {
            authority_id: &batch.authority_id,
            challenge_id: &batch.challenge_id,
            evidence_id: &batch.evidence_id,
            run_id: &batch.run_id,
            challenge_binding_sha256: &batch.challenge_binding_sha256,
            request_sha256: &batch.request_sha256,
            expected_work_set_sha256: &batch.expected_work_set_sha256,
            expected_work_item_count: batch.expected_work_item_count,
            expected_work_item_ids: &batch.expected_work_item_ids,
            provider: batch.provider,
            model_identity_sha256: &batch.model_identity_sha256,
            model_identity_posture: &batch.model_identity_posture,
            issued_at_unix_seconds: batch.issued_at_unix_seconds,
            expires_at_unix_seconds: batch.expires_at_unix_seconds,
            started_at_unix_millis: batch.started_at_unix_millis,
            finished_at_unix_millis: batch.finished_at_unix_millis,
            coverage_complete: batch.coverage_complete,
            row_sha256s: &row_sha256s,
        })?;
    if recomputed != batch.runtime_batch_sha256 {
        return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
    }
    Ok(())
}

pub fn validate_verified_hosted_runtime_batch_against_request_v3(
    batch: &VerifiedHostedRuntimeBatchV3,
    request: &ArtifactReviewRequestV2,
) -> Result<(), ArtifactAiProviderErrorV2> {
    validate_verified_hosted_runtime_batch_v3(batch)?;
    let request_sha256 = request
        .request_sha256()
        .map_err(|_| ArtifactAiProviderErrorV2::RequestBindingMismatch)?;
    let work_item_ids = exact_request_work_item_ids_v3(request)?;
    let expected_coverage_complete = request.coverage().completeness()
        == ArtifactReviewCoverageCompletenessV2::Complete
        && batch
            .rows
            .iter()
            .all(|row| row.state == VerifiedHostedRuntimeRowStateV3::Complete);
    if batch.request_sha256 != request_sha256
        || batch.expected_work_item_ids != work_item_ids
        || batch.expected_work_set_sha256 != hosted_expected_work_set_sha256_v3(request)?
        || request.provider() != &hosted_cli_provider_identity_v2(batch.provider)
        || batch.model_identity_sha256 != request.model().identity_sha256()
        || &batch.model_identity_posture != request.model().identity_posture()
        || batch.coverage_complete != expected_coverage_complete
    {
        return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
    }
    Ok(())
}

fn valid_hosted_runtime_binding_id_v3(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_HOSTED_RUNTIME_BINDING_ID_BYTES_V3
        && value.as_bytes().iter().all(|byte| byte.is_ascii_graphic())
}

fn exact_request_work_item_ids_v3(
    request: &ArtifactReviewRequestV2,
) -> Result<Vec<Sha256Digest>, ArtifactAiProviderErrorV2> {
    let ids: Vec<Sha256Digest> = request
        .work_items()
        .iter()
        .map(|item| item.work_item_id().clone())
        .collect();
    if ids.is_empty()
        || ids.len() > u32::MAX as usize
        || ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactAiProviderErrorV2::ExpectedWorkSetMismatch);
    }
    Ok(ids)
}

fn expected_work_set_sha256_from_parts_v3(
    request_sha256: &Sha256Digest,
    work_item_ids: &[Sha256Digest],
) -> Result<Sha256Digest, ArtifactAiProviderErrorV2> {
    if work_item_ids.is_empty()
        || work_item_ids.len() > u32::MAX as usize
        || work_item_ids.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(ArtifactAiProviderErrorV2::ExpectedWorkSetMismatch);
    }
    let wire = HostedRuntimeExpectedWorkSetWireV3 {
        schema_version: "whoathere.artifact_review_expected_work_set.v2",
        request_sha256: request_sha256.as_str(),
        work_item_ids: work_item_ids.iter().map(Sha256Digest::as_str).collect(),
    };
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| ArtifactAiProviderErrorV2::Serialization)?;
    Ok(Sha256Digest::from_bytes(&canonical))
}

fn runtime_row_state_v3(
    receipt_status: ArtifactAiExecutionStatusV2,
    output_status: ArtifactReviewWorkItemStatusV2,
    output_bytes: &[u8],
) -> Result<VerifiedHostedRuntimeRowStateV3, ArtifactAiProviderErrorV2> {
    match (receipt_status, output_status) {
        (ArtifactAiExecutionStatusV2::Completed, ArtifactReviewWorkItemStatusV2::Completed) => {
            Ok(VerifiedHostedRuntimeRowStateV3::Complete)
        }
        (_, ArtifactReviewWorkItemStatusV2::Completed)
            if model_output_has_positive_finding_v2(output_bytes) =>
        {
            Ok(VerifiedHostedRuntimeRowStateV3::IncompletePositive)
        }
        (_, ArtifactReviewWorkItemStatusV2::Truncated) => {
            Ok(VerifiedHostedRuntimeRowStateV3::Truncated)
        }
        (_, ArtifactReviewWorkItemStatusV2::Failed) => Ok(VerifiedHostedRuntimeRowStateV3::Failed),
        _ => Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid),
    }
}

fn runtime_row_failure_v3(
    receipt_status: ArtifactAiExecutionStatusV2,
    output_status: ArtifactReviewWorkItemStatusV2,
    state: VerifiedHostedRuntimeRowStateV3,
) -> Option<HostedRuntimeRowFailureV3> {
    if state == VerifiedHostedRuntimeRowStateV3::Complete {
        return None;
    }
    Some(match receipt_status {
        ArtifactAiExecutionStatusV2::Completed => {
            if output_status == ArtifactReviewWorkItemStatusV2::Truncated {
                HostedRuntimeRowFailureV3::OutputCaptureIncomplete
            } else {
                HostedRuntimeRowFailureV3::InternalOutputStateMismatch
            }
        }
        ArtifactAiExecutionStatusV2::ClientNonZeroExit => {
            HostedRuntimeRowFailureV3::ClientNonZeroExit
        }
        ArtifactAiExecutionStatusV2::TimedOut => HostedRuntimeRowFailureV3::TimedOut,
        ArtifactAiExecutionStatusV2::Cancelled => HostedRuntimeRowFailureV3::Cancelled,
        ArtifactAiExecutionStatusV2::StdoutLimitExceeded => {
            HostedRuntimeRowFailureV3::StdoutLimitExceeded
        }
        ArtifactAiExecutionStatusV2::StderrLimitExceeded => {
            HostedRuntimeRowFailureV3::StderrLimitExceeded
        }
        ArtifactAiExecutionStatusV2::OutputCaptureIncomplete => {
            HostedRuntimeRowFailureV3::OutputCaptureIncomplete
        }
        ArtifactAiExecutionStatusV2::ProcessCleanupFailed => {
            HostedRuntimeRowFailureV3::ProcessCleanupFailed
        }
        ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid => {
            HostedRuntimeRowFailureV3::OutputEnvelopeInvalid
        }
        ArtifactAiExecutionStatusV2::ClientIdentityChanged => {
            HostedRuntimeRowFailureV3::ClientIdentityChanged
        }
        ArtifactAiExecutionStatusV2::IsolationCheckFailed => {
            HostedRuntimeRowFailureV3::IsolationCheckFailed
        }
        ArtifactAiExecutionStatusV2::AuthenticationContinuityFailed => {
            HostedRuntimeRowFailureV3::AuthenticationContinuityFailed
        }
        ArtifactAiExecutionStatusV2::ObservedModelMismatch => {
            HostedRuntimeRowFailureV3::ObservedModelMismatch
        }
        ArtifactAiExecutionStatusV2::PostExecutionVerificationFailed => {
            HostedRuntimeRowFailureV3::PostExecutionVerificationFailed
        }
    })
}

#[derive(Clone)]
pub struct AuthorizedHostedCliProviderV2 {
    request_sha256: Sha256Digest,
    provider: ArtifactReviewProviderIdentityV2,
    model_identity_sha256: Sha256Digest,
    requested_model: String,
    kind: ArtifactAiProviderKindV2,
    executable: Arc<HeldNativeExecutableV2>,
}

impl PartialEq for AuthorizedHostedCliProviderV2 {
    fn eq(&self, other: &Self) -> bool {
        self.request_sha256 == other.request_sha256
            && self.provider == other.provider
            && self.model_identity_sha256 == other.model_identity_sha256
            && self.requested_model == other.requested_model
            && self.kind == other.kind
            && self.executable.identity == other.executable.identity
            && self.executable.inspection == other.executable.inspection
    }
}

impl Eq for AuthorizedHostedCliProviderV2 {}

impl std::fmt::Debug for AuthorizedHostedCliProviderV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthorizedHostedCliProviderV2")
            .field("request_sha256", &self.request_sha256)
            .field("provider", &self.kind)
            .field("provider_adapter_sha256", &self.provider.adapter_sha256)
            .field("model_identity_sha256", &self.model_identity_sha256)
            .field(
                "client_executable_sha256",
                &self.executable.inspection.sha256,
            )
            .field("executable_path", &"<redacted>")
            .finish()
    }
}

impl AuthorizedHostedCliProviderV2 {
    pub fn new_claude_subscription(
        request: &ArtifactReviewRequestV2,
        executable_path: PathBuf,
        expected_executable_sha256: Sha256Digest,
    ) -> Result<Self, ArtifactAiProviderErrorV2> {
        Self::new(
            request,
            ArtifactAiProviderKindV2::Claude,
            executable_path,
            expected_executable_sha256,
        )
    }

    pub fn new_codex_subscription(
        request: &ArtifactReviewRequestV2,
        executable_path: PathBuf,
        expected_executable_sha256: Sha256Digest,
    ) -> Result<Self, ArtifactAiProviderErrorV2> {
        Self::new(
            request,
            ArtifactAiProviderKindV2::Codex,
            executable_path,
            expected_executable_sha256,
        )
    }

    fn new(
        request: &ArtifactReviewRequestV2,
        kind: ArtifactAiProviderKindV2,
        executable_path: PathBuf,
        expected_executable_sha256: Sha256Digest,
    ) -> Result<Self, ArtifactAiProviderErrorV2> {
        if request.privacy_posture()
            != whoathere_detector::ArtifactReviewPrivacyPostureV2::ApprovedHosted
            || !matches!(
                request.model().identity_posture(),
                ArtifactReviewModelIdentityPostureV2::ProviderHostedOpaqueVersion
            )
            || request.provider() != &hosted_cli_provider_identity_v2(kind)
            || !executable_path.is_absolute()
        {
            return Err(ArtifactAiProviderErrorV2::InvalidAuthorization);
        }
        let executable = HeldNativeExecutableV2::open(&executable_path)?;
        if executable.inspection.sha256 != expected_executable_sha256 {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableDigestMismatch);
        }
        Ok(Self {
            request_sha256: request
                .request_sha256()
                .map_err(|_| ArtifactAiProviderErrorV2::InvalidAuthorization)?,
            provider: request.provider().clone(),
            model_identity_sha256: request.model().identity_sha256(),
            requested_model: request.model().model_id.clone(),
            kind,
            executable: Arc::new(executable),
        })
    }

    pub fn kind(&self) -> ArtifactAiProviderKindV2 {
        self.kind
    }

    pub fn executable_sha256(&self) -> &Sha256Digest {
        &self.executable.inspection.sha256
    }

    pub const fn is_authenticated(&self) -> bool {
        false
    }

    pub const fn can_authorize_allow(&self) -> bool {
        false
    }

    pub fn invoke_verified_batch_v3(
        &self,
        challenge: HostedRuntimeChallengeV3,
        request: &ArtifactReviewRequestV2,
        artifact: &NormalizedArtifact,
        policy: &HostedCliRuntimePolicyV2,
        cancellation: &ArtifactReviewCancellationTokenV2,
    ) -> Result<VerifiedHostedRuntimeBatchV3, ArtifactAiProviderErrorV2> {
        let request_sha256 = request
            .request_sha256()
            .map_err(|_| ArtifactAiProviderErrorV2::RequestBindingMismatch)?;
        let expected_work_item_ids = exact_request_work_item_ids_v3(request)?;
        let expected_work_item_count = u32::try_from(expected_work_item_ids.len())
            .map_err(|_| ArtifactAiProviderErrorV2::ExpectedWorkSetMismatch)?;
        let expected_work_set_sha256 = hosted_expected_work_set_sha256_v3(request)?;
        let preflight_seconds = unix_seconds_v3()?;
        if request_sha256 != self.request_sha256
            || challenge.request_sha256 != request_sha256
            || challenge.expected_work_set_sha256 != expected_work_set_sha256
            || challenge.expected_work_item_count != expected_work_item_count
            || request.provider() != &self.provider
            || request.model().identity_sha256() != self.model_identity_sha256
            || request.model().identity_posture()
                != &ArtifactReviewModelIdentityPostureV2::ProviderHostedOpaqueVersion
        {
            return Err(ArtifactAiProviderErrorV2::ExpectedWorkSetMismatch);
        }
        if preflight_seconds < challenge.issued_at_unix_seconds
            || preflight_seconds >= challenge.expires_at_unix_seconds
        {
            return Err(ArtifactAiProviderErrorV2::RuntimeChallengeExpired);
        }

        let started_at_unix_millis = unix_millis_v2()?;
        let mut rows = Vec::with_capacity(expected_work_item_ids.len());
        for work_item_id in &expected_work_item_ids {
            if unix_seconds_v3()? >= challenge.expires_at_unix_seconds {
                return Err(ArtifactAiProviderErrorV2::RuntimeChallengeExpired);
            }
            let outcome = self.invoke(request, artifact, work_item_id, policy, cancellation)?;
            let ArtifactAiInvocationOutcomeV2 {
                provider_output,
                receipt,
                provider_output_bytes,
                output_channel_isolation,
                output_no_truncation_verified,
            } = outcome;
            if !receipt.run_directory_cleanup_verified
                || !receipt.process_group_cleanup_verified
                || receipt.request_sha256 != request_sha256
                || receipt.work_item_id != *work_item_id
                || receipt.model_identity_sha256 != self.model_identity_sha256
                || receipt.model_identity_posture
                    != ArtifactReviewModelIdentityPostureV2::ProviderHostedOpaqueVersion
            {
                return Err(ArtifactAiProviderErrorV2::RuntimeBatchBindingInvalid);
            }
            let state = runtime_row_state_v3(
                receipt.status,
                provider_output.status(),
                &provider_output_bytes,
            )?;
            let failure_reason =
                runtime_row_failure_v3(receipt.status, provider_output.status(), state);
            let receipt_canonical_json = receipt.canonical_json_v3()?;
            let row_sha256 =
                recompute_verified_hosted_runtime_row_sha256_v3(&HostedRuntimeRowBindingInputV3 {
                    work_item_id,
                    state,
                    failure_reason,
                    output_status: provider_output.status(),
                    output_channel_isolation,
                    output_no_truncation_verified,
                    provider_output_bytes: &provider_output_bytes,
                    receipt_canonical_json: &receipt_canonical_json,
                })?;
            let row = VerifiedHostedRuntimeRowV3 {
                work_item_id: work_item_id.clone(),
                state,
                failure_reason,
                provider_output,
                provider_output_bytes,
                output_channel_isolation,
                output_no_truncation_verified,
                receipt,
                receipt_canonical_json,
                row_sha256,
            };
            validate_verified_hosted_runtime_row_v3(&row)?;
            rows.push(row);
        }
        let finished_at_unix_millis = unix_millis_v2()?;
        if finished_at_unix_millis < started_at_unix_millis
            || finished_at_unix_millis / 1_000 >= challenge.expires_at_unix_seconds
        {
            return Err(ArtifactAiProviderErrorV2::RuntimeChallengeExpired);
        }
        let coverage_complete = request.coverage().completeness()
            == ArtifactReviewCoverageCompletenessV2::Complete
            && rows
                .iter()
                .all(|row| row.state == VerifiedHostedRuntimeRowStateV3::Complete);
        let row_sha256s: Vec<Sha256Digest> =
            rows.iter().map(|row| row.row_sha256.clone()).collect();
        let runtime_batch_sha256 =
            recompute_verified_hosted_runtime_batch_sha256_v3(&HostedRuntimeBatchBindingInputV3 {
                authority_id: &challenge.authority_id,
                challenge_id: &challenge.challenge_id,
                evidence_id: &challenge.evidence_id,
                run_id: &challenge.run_id,
                challenge_binding_sha256: &challenge.challenge_binding_sha256,
                request_sha256: &request_sha256,
                expected_work_set_sha256: &expected_work_set_sha256,
                expected_work_item_count,
                expected_work_item_ids: &expected_work_item_ids,
                provider: self.kind,
                model_identity_sha256: &self.model_identity_sha256,
                model_identity_posture: request.model().identity_posture(),
                issued_at_unix_seconds: challenge.issued_at_unix_seconds,
                expires_at_unix_seconds: challenge.expires_at_unix_seconds,
                started_at_unix_millis,
                finished_at_unix_millis,
                coverage_complete,
                row_sha256s: &row_sha256s,
            })?;
        let batch = VerifiedHostedRuntimeBatchV3 {
            authority_id: challenge.authority_id,
            challenge_id: challenge.challenge_id,
            evidence_id: challenge.evidence_id,
            run_id: challenge.run_id,
            challenge_binding_sha256: challenge.challenge_binding_sha256,
            request_sha256,
            expected_work_set_sha256,
            expected_work_item_count,
            expected_work_item_ids,
            provider: self.kind,
            model_identity_sha256: self.model_identity_sha256.clone(),
            model_identity_posture: request.model().identity_posture().clone(),
            issued_at_unix_seconds: challenge.issued_at_unix_seconds,
            expires_at_unix_seconds: challenge.expires_at_unix_seconds,
            started_at_unix_millis,
            finished_at_unix_millis,
            coverage_complete,
            rows,
            runtime_batch_sha256,
        };
        validate_verified_hosted_runtime_batch_against_request_v3(&batch, request)?;
        Ok(batch)
    }

    fn remeasure_executable_bounded(
        &self,
        cancellation: &ArtifactReviewCancellationTokenV2,
        timeout: Duration,
    ) -> Result<ExecutableIdentityCheckV2, ArtifactAiProviderErrorV2> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or(ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
        self.executable
            .verify_unchanged_bounded(cancellation, deadline)
    }
}

/// Opens with `O_NOFOLLOW`, hashes through the held descriptor, validates the
/// host-native executable format, and never loads the complete client into
/// memory. The descriptor is discarded after this inspection-only call.
pub fn inspect_hosted_cli_executable_v2(
    path: &Path,
) -> Result<HostedCliExecutableInspectionV2, ArtifactAiProviderErrorV2> {
    HeldNativeExecutableV2::open(path).map(|executable| executable.inspection)
}

pub fn hosted_cli_provider_identity_v2(
    kind: ArtifactAiProviderKindV2,
) -> ArtifactReviewProviderIdentityV2 {
    let (adapter_id, adapter_version) = match kind {
        ArtifactAiProviderKindV2::Claude => (
            CLAUDE_SUBSCRIPTION_ADAPTER_ID_V2,
            CLAUDE_SUBSCRIPTION_ADAPTER_VERSION_V2,
        ),
        ArtifactAiProviderKindV2::Codex => (
            CODEX_SUBSCRIPTION_ADAPTER_ID_V2,
            CODEX_SUBSCRIPTION_ADAPTER_VERSION_V2,
        ),
    };
    ArtifactReviewProviderIdentityV2 {
        adapter_id: adapter_id.to_string(),
        adapter_version: adapter_version.to_string(),
        adapter_sha256: provider_adapter_contract_sha256_v2(kind),
    }
}

fn provider_adapter_contract_sha256_v2(kind: ArtifactAiProviderKindV2) -> Sha256Digest {
    let mut bytes = b"whoathere.hosted_cli_adapter.measured_contract.v3\0".to_vec();
    let (contract, version) = match kind {
        ArtifactAiProviderKindV2::Claude => {
            (CLAUDE_ADAPTER_CONTRACT_V2, CLAUDE_CODE_SUPPORTED_VERSION_V2)
        }
        ArtifactAiProviderKindV2::Codex => {
            (CODEX_ADAPTER_CONTRACT_V2, CODEX_CLI_SUPPORTED_VERSION_V2)
        }
    };
    append_length_prefixed_v2(&mut bytes, contract.as_bytes());
    append_length_prefixed_v2(&mut bytes, version.as_bytes());
    append_length_prefixed_v2(
        &mut bytes,
        if cfg!(target_os = "macos") {
            b"macos_measured_canonical_path_exec_with_descriptor_identity_checks".as_slice()
        } else {
            b"held_descriptor_exec".as_slice()
        },
    );
    for argument in provider_invocation_arguments_v2(
        kind,
        "<REQUESTED_MODEL>",
        Path::new("/<PRIVATE_SCHEMA_PATH>"),
        Path::new("/<EMPTY_WORKING_DIRECTORY>"),
    ) {
        append_length_prefixed_v2(&mut bytes, argument.as_os_str().as_bytes());
    }
    for argument in provider_auth_arguments_v2(kind) {
        append_length_prefixed_v2(&mut bytes, argument.as_os_str().as_bytes());
    }
    for environment_contract in [
        "HOME=<DEDICATED_AUTH_HOME>",
        "TMPDIR=<PRIVATE_RUN_TMP>",
        "LANG=C",
        "LC_ALL=C",
        "TZ=UTC",
        "PATH=/usr/bin:/bin:/usr/sbin:/sbin",
        match kind {
            ArtifactAiProviderKindV2::Claude => {
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1;DISABLE_AUTOUPDATER=1"
            }
            ArtifactAiProviderKindV2::Codex => "CODEX_HOME=<DEDICATED_AUTH_HOME>",
        },
    ] {
        append_length_prefixed_v2(&mut bytes, environment_contract.as_bytes());
    }
    Sha256Digest::from_bytes(&bytes)
}

#[derive(Clone, PartialEq, Eq)]
pub struct HostedCliRuntimePolicyV2 {
    runtime_root: PathBuf,
    authentication_home: PathBuf,
    authentication_home_identity: DirectoryIdentityV2,
    timeout: Duration,
    readiness_timeout: Duration,
    termination_grace: Duration,
}

impl std::fmt::Debug for HostedCliRuntimePolicyV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostedCliRuntimePolicyV2")
            .field("runtime_root", &"<redacted>")
            .field("authentication_home", &"<redacted>")
            .field("timeout", &self.timeout)
            .field("readiness_timeout", &self.readiness_timeout)
            .field("termination_grace", &self.termination_grace)
            .finish()
    }
}

impl HostedCliRuntimePolicyV2 {
    pub fn new(
        runtime_root: PathBuf,
        authentication_home: PathBuf,
        timeout: Duration,
        termination_grace: Duration,
    ) -> Result<Self, ArtifactAiProviderErrorV2> {
        if timeout.is_zero()
            || timeout > MAX_HOSTED_TIMEOUT_V2
            || termination_grace.is_zero()
            || termination_grace > MAX_TERMINATION_GRACE_V2
        {
            return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
        }
        let runtime_root = canonical_runtime_root_candidate_v2(&runtime_root)?;
        let (authentication_home, authentication_home_identity) =
            validate_authentication_home_v2(&authentication_home)?;
        if paths_overlap_v2(&runtime_root, &authentication_home) {
            return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
        }
        Ok(Self {
            runtime_root,
            authentication_home,
            authentication_home_identity,
            timeout,
            readiness_timeout: DEFAULT_READINESS_TIMEOUT_V2,
            termination_grace,
        })
    }

    pub fn with_readiness_timeout(
        mut self,
        readiness_timeout: Duration,
    ) -> Result<Self, ArtifactAiProviderErrorV2> {
        if readiness_timeout.is_zero() || readiness_timeout > MAX_READINESS_TIMEOUT_V2 {
            return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
        }
        self.readiness_timeout = readiness_timeout;
        Ok(self)
    }

    fn revalidate_authentication_home(&self) -> Result<bool, ArtifactAiProviderErrorV2> {
        let (canonical, identity) = validate_authentication_home_v2(&self.authentication_home)?;
        Ok(canonical == self.authentication_home && identity == self.authentication_home_identity)
    }
}

pub trait ArtifactAiProviderV2 {
    fn readiness(
        &self,
        policy: &HostedCliRuntimePolicyV2,
        cancellation: &ArtifactReviewCancellationTokenV2,
    ) -> Result<ArtifactAiProviderReadinessV2, ArtifactAiProviderErrorV2>;

    fn invoke(
        &self,
        request: &ArtifactReviewRequestV2,
        artifact: &NormalizedArtifact,
        work_item_id: &Sha256Digest,
        policy: &HostedCliRuntimePolicyV2,
        cancellation: &ArtifactReviewCancellationTokenV2,
    ) -> Result<ArtifactAiInvocationOutcomeV2, ArtifactAiProviderErrorV2>;
}

impl ArtifactAiProviderV2 for AuthorizedHostedCliProviderV2 {
    fn readiness(
        &self,
        policy: &HostedCliRuntimePolicyV2,
        cancellation: &ArtifactReviewCancellationTokenV2,
    ) -> Result<ArtifactAiProviderReadinessV2, ArtifactAiProviderErrorV2> {
        let authentication_home_valid = policy.revalidate_authentication_home()?;
        prepare_runtime_root_v2(&policy.runtime_root)?;
        let mut run = PrivateHostedRunV2::new(&policy.runtime_root)?;
        let empty_before = directory_is_empty_v2(run.cwd_dir())?;
        let empty_environment = sanitized_environment_v2(self, policy, run.tmp_dir());
        let version_args = vec![OsString::from("--version")];
        let version = execute_bounded_command_v2(CommandSpecV2 {
            authorization: self,
            args: &version_args,
            stdin: &[],
            cwd: run.cwd_dir(),
            environment: &empty_environment,
            stdout_limit: MAX_READINESS_CAPTURE_BYTES_V2,
            stderr_limit: MAX_READINESS_CAPTURE_BYTES_V2,
            timeout: policy.readiness_timeout,
            termination_grace: policy.termination_grace,
            cancellation,
        })?;
        let schema_path = run.control_dir().join("parser-probe-schema.json");
        write_private_file_v2(
            &schema_path,
            artifact_review_model_output_schema_json_v2().as_bytes(),
        )?;
        let parser_probe_args = provider_parser_probe_arguments_v2(
            self.kind,
            &self.requested_model,
            &schema_path,
            run.cwd_dir(),
        );
        let parser_probe = if version.cancelled || version.timed_out {
            CapturedCommandV2::skipped(version.cancelled, version.timed_out)
        } else {
            execute_bounded_command_v2(CommandSpecV2 {
                authorization: self,
                args: &parser_probe_args,
                stdin: &[],
                cwd: run.cwd_dir(),
                environment: &empty_environment,
                stdout_limit: MAX_READINESS_CAPTURE_BYTES_V2,
                stderr_limit: MAX_READINESS_CAPTURE_BYTES_V2,
                timeout: policy.readiness_timeout,
                termination_grace: policy.termination_grace,
                cancellation,
            })?
        };
        let auth_args = provider_auth_arguments_v2(self.kind);
        let auth = if version.cancelled
            || version.timed_out
            || parser_probe.cancelled
            || parser_probe.timed_out
        {
            CapturedCommandV2::skipped(
                version.cancelled || parser_probe.cancelled,
                version.timed_out || parser_probe.timed_out,
            )
        } else {
            execute_bounded_command_v2(CommandSpecV2 {
                authorization: self,
                args: &auth_args,
                stdin: &[],
                cwd: run.cwd_dir(),
                environment: &empty_environment,
                stdout_limit: MAX_AUTH_STATUS_BYTES_V2,
                stderr_limit: MAX_AUTH_STATUS_BYTES_V2,
                timeout: policy.readiness_timeout,
                termination_grace: policy.termination_grace,
                cancellation,
            })?
        };
        let identity_check =
            self.remeasure_executable_bounded(cancellation, policy.readiness_timeout)?;
        let identity_unchanged = identity_check == ExecutableIdentityCheckV2::Unchanged;
        let version_text = strict_identity_capture_v2(&version.stdout, MAX_CLIENT_VERSION_BYTES_V2);
        let auth_observation = classify_authentication_v2(self.kind, auth);
        let authentication_home_unchanged = policy.revalidate_authentication_home()?;
        let empty_after = directory_is_empty_v2(run.cwd_dir())?;
        let version_supported = version_text
            .as_deref()
            .is_some_and(|version| supported_client_version_v2(self.kind, version));
        let status = if identity_check == ExecutableIdentityCheckV2::Changed {
            ArtifactAiReadinessStatusV2::ClientIdentityChanged
        } else if identity_check == ExecutableIdentityCheckV2::Cancelled {
            ArtifactAiReadinessStatusV2::Cancelled
        } else if identity_check == ExecutableIdentityCheckV2::TimedOut {
            ArtifactAiReadinessStatusV2::ClientTimedOut
        } else if !authentication_home_valid || !authentication_home_unchanged {
            ArtifactAiReadinessStatusV2::AuthenticationHomeInvalid
        } else if !empty_before || !empty_after {
            ArtifactAiReadinessStatusV2::IsolationCheckFailed
        } else if version.cancelled || parser_probe.cancelled || auth_observation.capture.cancelled
        {
            ArtifactAiReadinessStatusV2::Cancelled
        } else if version.timed_out || parser_probe.timed_out || auth_observation.capture.timed_out
        {
            ArtifactAiReadinessStatusV2::ClientTimedOut
        } else if !command_completed(&version) || !command_completed(&auth_observation.capture) {
            ArtifactAiReadinessStatusV2::ClientExecutionFailed
        } else if !command_completed(&parser_probe) {
            ArtifactAiReadinessStatusV2::ClientArgumentContractUnsupported
        } else if version_text.is_none() {
            ArtifactAiReadinessStatusV2::ClientVersionInvalid
        } else if !version_supported {
            ArtifactAiReadinessStatusV2::ClientArgumentContractUnsupported
        } else if auth_observation.status != ArtifactAiReadinessStatusV2::Ready {
            auth_observation.status
        } else {
            ArtifactAiReadinessStatusV2::Ready
        };
        let readiness = ArtifactAiProviderReadinessV2 {
            schema_version: ARTIFACT_AI_PROVIDER_READINESS_SCHEMA_V2.to_string(),
            provider: self.kind,
            transport: provider_transport_v2(self.kind),
            status,
            authentication_mode: auth_observation.mode,
            client_executable_sha256: self.executable.inspection.sha256.clone(),
            client_version: version_text,
            version_capture_sha256: Sha256Digest::from_bytes(&version.stdout),
            argument_probe_stdout_sha256: Sha256Digest::from_bytes(&parser_probe.stdout),
            argument_probe_stderr_sha256: Sha256Digest::from_bytes(&parser_probe.stderr),
            auth_status_stdout_sha256: Sha256Digest::from_bytes(&auth_observation.capture.stdout),
            auth_status_stderr_sha256: Sha256Digest::from_bytes(&auth_observation.capture.stderr),
            auth_observation_sha256: auth_observation.digest,
            argument_contract_sha256: argument_contract_sha256_v2(self.kind),
            argument_contract_posture: if version_supported && command_completed(&parser_probe) {
                ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque
            } else {
                ArtifactAiControlPostureV2::NotEstablished
            },
            authentication_home_posture: if authentication_home_valid
                && authentication_home_unchanged
            {
                ArtifactAiControlPostureV2::HostVerified
            } else {
                ArtifactAiControlPostureV2::NotEstablished
            },
            client_executable_posture: if identity_unchanged {
                ArtifactAiControlPostureV2::HostVerified
            } else {
                ArtifactAiControlPostureV2::NotEstablished
            },
            available_inference_controls: available_inference_controls_v2(self.kind),
            empty_working_directory_posture: if empty_before && empty_after {
                ArtifactAiControlPostureV2::HostVerified
            } else {
                ArtifactAiControlPostureV2::NotEstablished
            },
            host_filesystem_isolation_posture: ArtifactAiControlPostureV2::NotEstablished,
            api_key_environment_stripped: true,
            interactive_login_attempted: false,
        };
        run.cleanup()?;
        Ok(readiness)
    }

    fn invoke(
        &self,
        request: &ArtifactReviewRequestV2,
        artifact: &NormalizedArtifact,
        work_item_id: &Sha256Digest,
        policy: &HostedCliRuntimePolicyV2,
        cancellation: &ArtifactReviewCancellationTokenV2,
    ) -> Result<ArtifactAiInvocationOutcomeV2, ArtifactAiProviderErrorV2> {
        if request
            .request_sha256()
            .map_err(|_| ArtifactAiProviderErrorV2::RequestBindingMismatch)?
            != self.request_sha256
            || request.provider() != &self.provider
            || request.model().identity_sha256() != self.model_identity_sha256
        {
            return Err(ArtifactAiProviderErrorV2::RequestBindingMismatch);
        }
        let readiness = self.readiness(policy, cancellation)?;
        if readiness.status != ArtifactAiReadinessStatusV2::Ready {
            return Err(ArtifactAiProviderErrorV2::ProviderNotReady);
        }
        let authentication_mode = readiness
            .authentication_mode
            .ok_or(ArtifactAiProviderErrorV2::ProviderNotReady)?;
        let client_version = readiness
            .client_version
            .ok_or(ArtifactAiProviderErrorV2::ProviderNotReady)?;
        let invocation = request
            .invocation(artifact, work_item_id)
            .map_err(|_| ArtifactAiProviderErrorV2::RequestBindingMismatch)?;
        let provider_input = invocation
            .canonical_provider_input_json_v2()
            .map_err(|_| ArtifactAiProviderErrorV2::ProviderInputInvalid)?;
        if provider_input.len() > MAX_ARTIFACT_REVIEW_PROVIDER_INPUT_BYTES_V2 {
            return Err(ArtifactAiProviderErrorV2::ProviderInputInvalid);
        }

        prepare_runtime_root_v2(&policy.runtime_root)?;
        let mut run = PrivateHostedRunV2::new(&policy.runtime_root)?;
        let empty_before = directory_is_empty_v2(run.cwd_dir())?;
        let schema_path = run.control_dir().join("model-output-schema.json");
        write_private_file_v2(
            &schema_path,
            artifact_review_model_output_schema_json_v2().as_bytes(),
        )?;
        let environment = sanitized_environment_v2(self, policy, run.tmp_dir());
        let args = provider_invocation_arguments_v2(
            self.kind,
            request.model().model_id.as_str(),
            &schema_path,
            run.cwd_dir(),
        );
        let auth_args = provider_auth_arguments_v2(self.kind);
        let pre_auth = classify_authentication_v2(
            self.kind,
            execute_bounded_command_v2(CommandSpecV2 {
                authorization: self,
                args: &auth_args,
                stdin: &[],
                cwd: run.cwd_dir(),
                environment: &environment,
                stdout_limit: MAX_AUTH_STATUS_BYTES_V2,
                stderr_limit: MAX_AUTH_STATUS_BYTES_V2,
                timeout: policy.readiness_timeout,
                termination_grace: policy.termination_grace,
                cancellation,
            })?,
        );
        if pre_auth.status != ArtifactAiReadinessStatusV2::Ready
            || pre_auth.mode != Some(authentication_mode)
            || !policy.revalidate_authentication_home()?
            || self.remeasure_executable_bounded(cancellation, policy.readiness_timeout)?
                != ExecutableIdentityCheckV2::Unchanged
        {
            return Err(ArtifactAiProviderErrorV2::ProviderNotReady);
        }
        let started_at_unix_millis = unix_millis_v2()?;
        let execution = execute_bounded_command_v2(CommandSpecV2 {
            authorization: self,
            args: &args,
            stdin: &provider_input,
            cwd: run.cwd_dir(),
            environment: &environment,
            stdout_limit: MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2,
            stderr_limit: MAX_HOSTED_STDERR_CAPTURE_BYTES_V2,
            timeout: policy.timeout,
            termination_grace: policy.termination_grace,
            cancellation,
        })?;
        let mut post_execution_verification_failed = false;
        let post_auth = if command_capture_allows_auth_recheck_v2(&execution) {
            match execute_bounded_command_v2(CommandSpecV2 {
                authorization: self,
                args: &auth_args,
                stdin: &[],
                cwd: run.cwd_dir(),
                environment: &environment,
                stdout_limit: MAX_AUTH_STATUS_BYTES_V2,
                stderr_limit: MAX_AUTH_STATUS_BYTES_V2,
                timeout: policy.readiness_timeout,
                termination_grace: policy.termination_grace,
                cancellation,
            }) {
                Ok(capture) => Some(classify_authentication_v2(self.kind, capture)),
                Err(_) => {
                    post_execution_verification_failed = true;
                    None
                }
            }
        } else {
            None
        };
        let post_identity_check = self
            .remeasure_executable_bounded(cancellation, policy.readiness_timeout)
            .unwrap_or_else(|_| {
                post_execution_verification_failed = true;
                ExecutableIdentityCheckV2::Changed
            });
        if matches!(
            post_identity_check,
            ExecutableIdentityCheckV2::Cancelled | ExecutableIdentityCheckV2::TimedOut
        ) {
            post_execution_verification_failed = true;
        }
        let identity_unchanged = post_identity_check == ExecutableIdentityCheckV2::Unchanged;
        let authentication_home_unchanged =
            policy.revalidate_authentication_home().unwrap_or_else(|_| {
                post_execution_verification_failed = true;
                false
            });
        let empty_after = directory_is_empty_v2(run.cwd_dir()).unwrap_or_else(|_| {
            post_execution_verification_failed = true;
            false
        });
        let finished_at_unix_millis = unix_millis_v2().unwrap_or_else(|_| {
            post_execution_verification_failed = true;
            started_at_unix_millis
        });
        let elapsed_millis = finished_at_unix_millis
            .checked_sub(started_at_unix_millis)
            .unwrap_or_else(|| {
                post_execution_verification_failed = true;
                0
            });

        let strict_extracted = extract_model_output_v2(self.kind, &execution.stdout).ok();
        let preserved_positive = strict_extracted
            .as_deref()
            .filter(|output| model_output_has_positive_finding_v2(output))
            .map(ToOwned::to_owned)
            .or_else(|| extract_positive_model_output_prefix_v2(self.kind, &execution.stdout));
        let observed_model = observed_model_v2(self.kind, &execution.stdout);
        let authentication_continuous = post_auth.as_ref().is_some_and(|observation| {
            observation.status == ArtifactAiReadinessStatusV2::Ready
                && observation.mode == Some(authentication_mode)
        });
        let observed_model_matches = observed_model_matches_v2(
            self.kind,
            request.model().model_id.as_str(),
            &observed_model,
        );
        let mut status = execution_status_v2(&execution);
        if status == ArtifactAiExecutionStatusV2::Completed && post_execution_verification_failed {
            status = ArtifactAiExecutionStatusV2::PostExecutionVerificationFailed;
        }
        if status == ArtifactAiExecutionStatusV2::Completed && !identity_unchanged {
            status = ArtifactAiExecutionStatusV2::ClientIdentityChanged;
        }
        if status == ArtifactAiExecutionStatusV2::Completed
            && (!authentication_home_unchanged || !empty_before || !empty_after)
        {
            status = ArtifactAiExecutionStatusV2::IsolationCheckFailed;
        }
        if status == ArtifactAiExecutionStatusV2::Completed && strict_extracted.is_none() {
            status = ArtifactAiExecutionStatusV2::OutputEnvelopeInvalid;
        }
        if status == ArtifactAiExecutionStatusV2::Completed && !authentication_continuous {
            status = ArtifactAiExecutionStatusV2::AuthenticationContinuityFailed;
        }
        if status == ArtifactAiExecutionStatusV2::Completed && !observed_model_matches {
            status = ArtifactAiExecutionStatusV2::ObservedModelMismatch;
        }
        let model_output = strict_extracted.or(preserved_positive).unwrap_or_default();
        let channel_isolation = match self.kind {
            ArtifactAiProviderKindV2::Claude => {
                ArtifactReviewChannelIsolationV2::SeparateTrustedAndUntrusted
            }
            ArtifactAiProviderKindV2::Codex => ArtifactReviewChannelIsolationV2::CollapsedPrompt,
        };
        let preserve_structured_output = !model_output.is_empty()
            && (status == ArtifactAiExecutionStatusV2::Completed
                || model_output_has_positive_finding_v2(&model_output));
        let (provider_output, provider_output_bytes, output_no_truncation_verified) =
            if preserve_structured_output {
                (
                    ArtifactReviewProviderOutputV2::new_complete(
                        work_item_id.clone(),
                        model_output.clone(),
                        channel_isolation,
                    ),
                    model_output.clone(),
                    true,
                )
            } else if status == ArtifactAiExecutionStatusV2::StdoutLimitExceeded {
                (
                    ArtifactReviewProviderOutputV2::new_truncated_capture(
                        work_item_id.clone(),
                        Vec::new(),
                        channel_isolation,
                    ),
                    Vec::new(),
                    false,
                )
            } else {
                (
                    ArtifactReviewProviderOutputV2::new_failed_capture(
                        work_item_id.clone(),
                        Vec::new(),
                        channel_isolation,
                        execution.stdout_eof_verified,
                    ),
                    Vec::new(),
                    execution.stdout_eof_verified,
                )
            };
        let provider_output =
            provider_output.map_err(|_| ArtifactAiProviderErrorV2::ProviderOutputInvalid)?;
        let controls = available_inference_controls_v2(self.kind);
        let receipt = ArtifactAiProviderReceiptV2 {
            schema_version: ARTIFACT_AI_PROVIDER_RECEIPT_SCHEMA_V2.to_string(),
            provider: self.kind,
            transport: provider_transport_v2(self.kind),
            authentication_mode,
            client_version,
            client_executable_sha256: self.executable.inspection.sha256.clone(),
            request_sha256: self.request_sha256.clone(),
            work_item_id: work_item_id.clone(),
            invocation_sha256: invocation.invocation_sha256().clone(),
            provider_adapter_sha256: self.provider.adapter_sha256.clone(),
            model_identity_sha256: self.model_identity_sha256.clone(),
            model_identity_posture: request.model().identity_posture().clone(),
            requested_model: request.model().model_id.clone(),
            observed_model,
            prompt_template_sha256: request.prompt().template_sha256.clone(),
            model_output_schema_sha256: request.model_output_schema_sha256().clone(),
            provider_input_sha256: Sha256Digest::from_bytes(&provider_input),
            provider_input_byte_len: provider_input.len() as u64,
            effective_arguments_sha256: digest_os_pairs_v2(&args),
            effective_environment_sha256: digest_environment_v2(&environment),
            trusted_instruction_sha256: Sha256Digest::from_bytes(
                whoathere_detector::artifact_review_system_prompt_v2().as_bytes(),
            ),
            pre_auth_observation_sha256: pre_auth.digest,
            post_auth_observation_sha256: post_auth
                .as_ref()
                .map(|observation| observation.digest.clone()),
            raw_stdout_sha256: Sha256Digest::from_bytes(&execution.stdout),
            raw_stdout_byte_len: execution.stdout.len() as u64,
            raw_stderr_sha256: Sha256Digest::from_bytes(&execution.stderr),
            raw_stderr_byte_len: execution.stderr.len() as u64,
            model_output_sha256: (!model_output.is_empty())
                .then(|| Sha256Digest::from_bytes(&model_output)),
            model_output_byte_len: (!model_output.is_empty()).then_some(model_output.len() as u64),
            started_at_unix_millis,
            finished_at_unix_millis,
            elapsed_millis,
            status,
            available_inference_controls: controls,
            strict_output_schema_requested: true,
            api_key_environment_stripped: true,
            empty_working_directory_before_verified: empty_before,
            empty_working_directory_after_verified: empty_after,
            authentication_home_isolation_posture: if authentication_home_unchanged {
                ArtifactAiControlPostureV2::HostVerified
            } else {
                ArtifactAiControlPostureV2::NotEstablished
            },
            empty_working_directory_posture: if empty_before && empty_after {
                ArtifactAiControlPostureV2::HostVerified
            } else {
                ArtifactAiControlPostureV2::NotEstablished
            },
            customizations_disabled_posture:
                ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque,
            model_tools_disabled_posture:
                ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque,
            model_web_access_disabled_posture:
                ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque,
            host_filesystem_isolation_posture: ArtifactAiControlPostureV2::NotEstablished,
            provider_control_plane_isolation_posture:
                ArtifactAiControlPostureV2::ProviderHostedOpaque,
            detached_descendant_containment_posture: ArtifactAiControlPostureV2::NotEstablished,
            package_artifact_path_exposed: false,
            package_code_executed: false,
            stdin_write_complete: execution.stdin_write_complete,
            stdout_eof_verified: execution.stdout_eof_verified,
            stderr_eof_verified: execution.stderr_eof_verified,
            pipe_drain_timed_out: execution.pipe_drain_timed_out,
            process_group_cleanup_verified: execution.process_group_cleanup_verified,
            run_directory_cleanup_verified: false,
            client_executable_posture: if identity_unchanged {
                ArtifactAiControlPostureV2::HostVerified
            } else {
                ArtifactAiControlPostureV2::NotEstablished
            },
        };
        let mut receipt = receipt;
        if run.cleanup().is_ok() {
            receipt.run_directory_cleanup_verified = true;
        } else {
            receipt.status = ArtifactAiExecutionStatusV2::ProcessCleanupFailed;
        }
        Ok(ArtifactAiInvocationOutcomeV2 {
            provider_output,
            receipt,
            provider_output_bytes,
            output_channel_isolation: channel_isolation,
            output_no_truncation_verified,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactAiProviderErrorV2 {
    InvalidAuthorization,
    InvalidRuntimeChallenge,
    RuntimeChallengeExpired,
    ExpectedWorkSetMismatch,
    RuntimeBatchBindingInvalid,
    InvalidRuntimePolicy,
    ClientExecutableInvalid,
    ClientExecutableWrapperRejected,
    ClientExecutableArchitectureUnsupported,
    ClientExecutableIdentityChanged,
    ClientExecutableLimitExceeded,
    ClientExecutableDigestMismatch,
    RuntimeRootInvalid,
    RunDirectoryFailed,
    RunDirectoryCleanupFailed,
    ControlFileFailed,
    ProcessSpawnFailed,
    ProcessControlFailed,
    ProviderNotReady,
    RequestBindingMismatch,
    ProviderInputInvalid,
    ProviderOutputInvalid,
    SystemClockInvalid,
    Serialization,
}

impl ArtifactAiProviderErrorV2 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidAuthorization => "artifact_ai_provider_authorization_invalid",
            Self::InvalidRuntimeChallenge => "artifact_ai_provider_runtime_challenge_invalid",
            Self::RuntimeChallengeExpired => "artifact_ai_provider_runtime_challenge_expired",
            Self::ExpectedWorkSetMismatch => "artifact_ai_provider_expected_work_set_mismatch",
            Self::RuntimeBatchBindingInvalid => {
                "artifact_ai_provider_runtime_batch_binding_invalid"
            }
            Self::InvalidRuntimePolicy => "artifact_ai_provider_runtime_policy_invalid",
            Self::ClientExecutableInvalid => "artifact_ai_provider_client_executable_invalid",
            Self::ClientExecutableWrapperRejected => {
                "artifact_ai_provider_client_executable_wrapper_rejected"
            }
            Self::ClientExecutableArchitectureUnsupported => {
                "artifact_ai_provider_client_executable_architecture_unsupported"
            }
            Self::ClientExecutableIdentityChanged => {
                "artifact_ai_provider_client_executable_identity_changed"
            }
            Self::ClientExecutableLimitExceeded => {
                "artifact_ai_provider_client_executable_limit_exceeded"
            }
            Self::ClientExecutableDigestMismatch => {
                "artifact_ai_provider_client_executable_digest_mismatch"
            }
            Self::RuntimeRootInvalid => "artifact_ai_provider_runtime_root_invalid",
            Self::RunDirectoryFailed => "artifact_ai_provider_run_directory_failed",
            Self::RunDirectoryCleanupFailed => "artifact_ai_provider_run_directory_cleanup_failed",
            Self::ControlFileFailed => "artifact_ai_provider_control_file_failed",
            Self::ProcessSpawnFailed => "artifact_ai_provider_process_spawn_failed",
            Self::ProcessControlFailed => "artifact_ai_provider_process_control_failed",
            Self::ProviderNotReady => "artifact_ai_provider_not_ready",
            Self::RequestBindingMismatch => "artifact_ai_provider_request_binding_mismatch",
            Self::ProviderInputInvalid => "artifact_ai_provider_input_invalid",
            Self::ProviderOutputInvalid => "artifact_ai_provider_output_invalid",
            Self::SystemClockInvalid => "artifact_ai_provider_system_clock_invalid",
            Self::Serialization => "artifact_ai_provider_serialization_failed",
        }
    }
}

impl std::fmt::Display for ArtifactAiProviderErrorV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for ArtifactAiProviderErrorV2 {}

fn provider_transport_v2(kind: ArtifactAiProviderKindV2) -> ArtifactAiProviderTransportV2 {
    match kind {
        ArtifactAiProviderKindV2::Claude => ArtifactAiProviderTransportV2::ClaudeCodePrintCliV1,
        ArtifactAiProviderKindV2::Codex => ArtifactAiProviderTransportV2::CodexExecCliV1,
    }
}

fn available_inference_controls_v2(
    kind: ArtifactAiProviderKindV2,
) -> ArtifactAiAvailableInferenceControlsV2 {
    let requested = ArtifactAiControlPostureV2::RequestedClientEnforcedProviderOpaque;
    ArtifactAiAvailableInferenceControlsV2 {
        requested_model_control: requested,
        strict_output_schema_control: requested,
        read_only_sandbox_control: if kind == ArtifactAiProviderKindV2::Codex {
            requested
        } else {
            ArtifactAiControlPostureV2::NotEstablished
        },
        tools_disabled_control: requested,
        web_search_disabled_control: requested,
        session_persistence_disabled_control: requested,
        user_customizations_disabled_control: requested,
        memory_disabled_control: ArtifactAiControlPostureV2::NotEstablished,
        seed_control_exposed: false,
        temperature_control_exposed: false,
        top_p_control_exposed: false,
        context_tokens_control_exposed: false,
        max_output_tokens_control_exposed: false,
    }
}

fn provider_invocation_arguments_v2(
    kind: ArtifactAiProviderKindV2,
    model_id: &str,
    schema_path: &Path,
    cwd: &Path,
) -> Vec<OsString> {
    match kind {
        ArtifactAiProviderKindV2::Claude => vec![
            OsString::from("--print"),
            OsString::from("--input-format"),
            OsString::from("text"),
            OsString::from("--safe-mode"),
            OsString::from("--disable-slash-commands"),
            OsString::from("--no-chrome"),
            OsString::from("--no-session-persistence"),
            OsString::from("--setting-sources"),
            OsString::from(""),
            OsString::from("--permission-mode"),
            OsString::from("plan"),
            OsString::from("--tools"),
            OsString::from(""),
            OsString::from("--strict-mcp-config"),
            OsString::from("--mcp-config"),
            OsString::from(r#"{"mcpServers":{}}"#),
            OsString::from("--system-prompt"),
            OsString::from(whoathere_detector::artifact_review_system_prompt_v2()),
            OsString::from("--json-schema"),
            OsString::from(whoathere_detector::artifact_review_model_output_schema_json_v2()),
            OsString::from("--output-format"),
            OsString::from("json"),
            OsString::from("--model"),
            OsString::from(model_id),
        ],
        ArtifactAiProviderKindV2::Codex => {
            let mut args = vec![
                OsString::from("exec"),
                OsString::from("--ephemeral"),
                OsString::from("--sandbox"),
                OsString::from("read-only"),
                OsString::from("--ignore-user-config"),
                OsString::from("--ignore-rules"),
                OsString::from("--strict-config"),
                OsString::from("--skip-git-repo-check"),
                OsString::from("--output-schema"),
                schema_path.as_os_str().to_owned(),
                OsString::from("--color"),
                OsString::from("never"),
                OsString::from("--model"),
                OsString::from(model_id),
            ];
            for feature in CODEX_DISABLED_TOOL_FEATURES_V2 {
                args.push(OsString::from("--disable"));
                args.push(OsString::from(feature));
            }
            args.extend([
                OsString::from("-c"),
                OsString::from("model_provider=\"openai\""),
                OsString::from("-c"),
                OsString::from("forced_login_method=\"chatgpt\""),
                OsString::from("-c"),
                OsString::from("web_search=\"disabled\""),
                OsString::from("-c"),
                OsString::from("apps._default.enabled=false"),
                OsString::from("-c"),
                OsString::from("mcp_servers={}"),
                OsString::from("-c"),
                OsString::from("history.persistence=\"none\""),
                OsString::from("-c"),
                OsString::from("check_for_update_on_startup=false"),
                OsString::from("-c"),
                OsString::from("feedback.enabled=false"),
                OsString::from("-c"),
                OsString::from("analytics.enabled=false"),
                OsString::from("-c"),
                OsString::from("approval_policy=\"never\""),
                OsString::from("-c"),
                OsString::from(format!(
                    "developer_instructions={}",
                    serde_json::to_string(whoathere_detector::artifact_review_system_prompt_v2())
                        .expect("static Artifact Review system prompt serializes")
                )),
                OsString::from("-C"),
                cwd.as_os_str().to_owned(),
                OsString::from("-"),
            ]);
            args
        }
    }
}

fn provider_parser_probe_arguments_v2(
    kind: ArtifactAiProviderKindV2,
    model_id: &str,
    schema_path: &Path,
    cwd: &Path,
) -> Vec<OsString> {
    let mut arguments = provider_invocation_arguments_v2(kind, model_id, schema_path, cwd);
    match kind {
        ArtifactAiProviderKindV2::Claude => arguments.push(OsString::from("--help")),
        ArtifactAiProviderKindV2::Codex => {
            let insertion = arguments.len().saturating_sub(1);
            arguments.insert(insertion, OsString::from("--help"));
        }
    }
    arguments
}

fn sanitized_environment_v2(
    authorization: &AuthorizedHostedCliProviderV2,
    policy: &HostedCliRuntimePolicyV2,
    tmp_dir: &Path,
) -> Vec<(OsString, OsString)> {
    let mut environment = vec![
        (
            OsString::from("HOME"),
            policy.authentication_home.as_os_str().to_owned(),
        ),
        (OsString::from("TMPDIR"), tmp_dir.as_os_str().to_owned()),
        (OsString::from("LANG"), OsString::from("C")),
        (OsString::from("LC_ALL"), OsString::from("C")),
        (OsString::from("TZ"), OsString::from("UTC")),
        (
            OsString::from("PATH"),
            OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"),
        ),
    ];
    if authorization.kind == ArtifactAiProviderKindV2::Codex {
        environment.push((
            OsString::from("CODEX_HOME"),
            policy.authentication_home.as_os_str().to_owned(),
        ));
    } else {
        environment.extend([
            (
                OsString::from("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"),
                OsString::from("1"),
            ),
            (OsString::from("DISABLE_AUTOUPDATER"), OsString::from("1")),
        ]);
    }
    environment
}

struct AuthenticationObservationV2 {
    capture: CapturedCommandV2,
    mode: Option<ArtifactAiAuthenticationModeV2>,
    status: ArtifactAiReadinessStatusV2,
    digest: Sha256Digest,
}

fn classify_authentication_v2(
    kind: ArtifactAiProviderKindV2,
    capture: CapturedCommandV2,
) -> AuthenticationObservationV2 {
    let (mode, status) = if !command_completed(&capture) {
        (None, ArtifactAiReadinessStatusV2::ClientExecutionFailed)
    } else {
        let stdout = String::from_utf8_lossy(&capture.stdout);
        let stderr = String::from_utf8_lossy(&capture.stderr);
        let combined = format!("{stdout}\n{stderr}");
        let lower = combined.to_ascii_lowercase();
        let api_marker = lower.contains("api key")
            || lower.contains("apikey")
            || lower.contains("api_key")
            || lower.contains("authmethod\":\"api");
        match kind {
            ArtifactAiProviderKindV2::Claude => {
                #[derive(Deserialize)]
                #[serde(rename_all = "camelCase", deny_unknown_fields)]
                struct ClaudeAuthStatusV2 {
                    logged_in: bool,
                    auth_method: String,
                    api_provider: String,
                }
                match serde_json::from_slice::<ClaudeAuthStatusV2>(&capture.stdout) {
                    Ok(observed) => {
                        let method = observed.auth_method.to_ascii_lowercase();
                        let provider = observed.api_provider.to_ascii_lowercase();
                        let subscription_marker = method.contains("oauth")
                            || method.contains("claude.ai")
                            || method.contains("subscription");
                        if api_marker && subscription_marker {
                            (
                                None,
                                ArtifactAiReadinessStatusV2::AmbiguousAuthenticationRejected,
                            )
                        } else if !observed.logged_in {
                            (
                                None,
                                ArtifactAiReadinessStatusV2::SubscriptionNotAuthenticated,
                            )
                        } else if api_marker || method.contains("api") || provider != "firstparty" {
                            (
                                None,
                                ArtifactAiReadinessStatusV2::ApiKeyAuthenticationRejected,
                            )
                        } else if !subscription_marker {
                            (
                                None,
                                ArtifactAiReadinessStatusV2::AuthenticationStatusInvalid,
                            )
                        } else {
                            (
                                Some(ArtifactAiAuthenticationModeV2::ClaudeSubscription),
                                ArtifactAiReadinessStatusV2::Ready,
                            )
                        }
                    }
                    Err(_) => (
                        None,
                        ArtifactAiReadinessStatusV2::AuthenticationStatusInvalid,
                    ),
                }
            }
            ArtifactAiProviderKindV2::Codex => {
                let chatgpt_marker = combined.contains("Logged in using ChatGPT");
                if chatgpt_marker && api_marker {
                    (
                        None,
                        ArtifactAiReadinessStatusV2::AmbiguousAuthenticationRejected,
                    )
                } else if api_marker {
                    (
                        None,
                        ArtifactAiReadinessStatusV2::ApiKeyAuthenticationRejected,
                    )
                } else if lower.contains("not logged in") {
                    (
                        None,
                        ArtifactAiReadinessStatusV2::SubscriptionNotAuthenticated,
                    )
                } else if chatgpt_marker {
                    (
                        Some(ArtifactAiAuthenticationModeV2::ChatGptSubscription),
                        ArtifactAiReadinessStatusV2::Ready,
                    )
                } else {
                    (
                        None,
                        ArtifactAiReadinessStatusV2::AuthenticationStatusInvalid,
                    )
                }
            }
        }
    };
    let digest = authentication_observation_sha256_v2(&capture, mode, status);
    AuthenticationObservationV2 {
        capture,
        mode,
        status,
        digest,
    }
}

fn provider_auth_arguments_v2(kind: ArtifactAiProviderKindV2) -> Vec<OsString> {
    match kind {
        ArtifactAiProviderKindV2::Claude => vec![
            OsString::from("auth"),
            OsString::from("status"),
            OsString::from("--json"),
        ],
        ArtifactAiProviderKindV2::Codex => {
            vec![OsString::from("login"), OsString::from("status")]
        }
    }
}

fn supported_client_version_v2(kind: ArtifactAiProviderKindV2, version: &str) -> bool {
    match kind {
        ArtifactAiProviderKindV2::Claude => version == CLAUDE_CODE_SUPPORTED_VERSION_V2,
        ArtifactAiProviderKindV2::Codex => version == CODEX_CLI_SUPPORTED_VERSION_V2,
    }
}

fn argument_contract_sha256_v2(kind: ArtifactAiProviderKindV2) -> Sha256Digest {
    provider_adapter_contract_sha256_v2(kind)
}

fn authentication_observation_sha256_v2(
    capture: &CapturedCommandV2,
    mode: Option<ArtifactAiAuthenticationModeV2>,
    status: ArtifactAiReadinessStatusV2,
) -> Sha256Digest {
    let mut bytes = b"whoathere.hosted_auth_observation.v2\0".to_vec();
    append_length_prefixed_v2(
        &mut bytes,
        Sha256Digest::from_bytes(&capture.stdout)
            .as_str()
            .as_bytes(),
    );
    append_length_prefixed_v2(
        &mut bytes,
        Sha256Digest::from_bytes(&capture.stderr)
            .as_str()
            .as_bytes(),
    );
    bytes.extend_from_slice(
        &capture
            .status
            .as_ref()
            .and_then(ExitStatus::code)
            .unwrap_or(i32::MIN)
            .to_be_bytes(),
    );
    bytes.push(capture.timed_out as u8);
    bytes.push(capture.cancelled as u8);
    bytes.push(status as u8);
    bytes.push(mode.map_or(u8::MAX, |value| value as u8));
    Sha256Digest::from_bytes(&bytes)
}

fn command_capture_allows_auth_recheck_v2(capture: &CapturedCommandV2) -> bool {
    command_completed(capture)
}

fn observed_model_matches_v2(
    kind: ArtifactAiProviderKindV2,
    requested_model: &str,
    observed_model: &ArtifactAiObservedModelV2,
) -> bool {
    match (kind, observed_model) {
        (ArtifactAiProviderKindV2::Claude, ArtifactAiObservedModelV2::Present { model_id }) => {
            model_id == requested_model
        }
        (ArtifactAiProviderKindV2::Claude, ArtifactAiObservedModelV2::Unavailable) => false,
        (ArtifactAiProviderKindV2::Codex, _) => true,
    }
}

fn digest_os_pairs_v2(values: &[OsString]) -> Sha256Digest {
    let mut bytes = b"whoathere.hosted_effective_arguments.v2\0".to_vec();
    for value in values {
        append_length_prefixed_v2(&mut bytes, value.as_os_str().as_bytes());
    }
    Sha256Digest::from_bytes(&bytes)
}

fn digest_environment_v2(values: &[(OsString, OsString)]) -> Sha256Digest {
    let mut bytes = b"whoathere.hosted_effective_environment.v2\0".to_vec();
    for (name, value) in values {
        append_length_prefixed_v2(&mut bytes, name.as_os_str().as_bytes());
        append_length_prefixed_v2(&mut bytes, value.as_os_str().as_bytes());
    }
    Sha256Digest::from_bytes(&bytes)
}

fn append_length_prefixed_v2(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}

fn extract_model_output_v2(
    kind: ArtifactAiProviderKindV2,
    stdout: &[u8],
) -> Result<Vec<u8>, ArtifactAiProviderErrorV2> {
    let value: Value = serde_json::from_slice(stdout)
        .map_err(|_| ArtifactAiProviderErrorV2::ProviderOutputInvalid)?;
    let model_value = match kind {
        ArtifactAiProviderKindV2::Claude => {
            if value.get("type").and_then(Value::as_str) != Some("result")
                || value.get("is_error").and_then(Value::as_bool) == Some(true)
            {
                return Err(ArtifactAiProviderErrorV2::ProviderOutputInvalid);
            }
            if let Some(value) = value.get("structured_output") {
                value.clone()
            } else if let Some(result) = value.get("result").and_then(Value::as_str) {
                serde_json::from_str(result)
                    .map_err(|_| ArtifactAiProviderErrorV2::ProviderOutputInvalid)?
            } else {
                return Err(ArtifactAiProviderErrorV2::ProviderOutputInvalid);
            }
        }
        ArtifactAiProviderKindV2::Codex => value,
    };
    let bytes = serde_json::to_vec(&model_value)
        .map_err(|_| ArtifactAiProviderErrorV2::ProviderOutputInvalid)?;
    if bytes.is_empty() || bytes.len() > MAX_ARTIFACT_REVIEW_PROVIDER_OUTPUT_BYTES_V2 {
        return Err(ArtifactAiProviderErrorV2::ProviderOutputInvalid);
    }
    Ok(bytes)
}

fn model_output_has_positive_finding_v2(model_output: &[u8]) -> bool {
    serde_json::from_slice::<Value>(model_output)
        .ok()
        .is_some_and(|value| {
            value.get("verdict").and_then(Value::as_str) == Some("suspicious")
                && value
                    .get("findings")
                    .and_then(Value::as_array)
                    .is_some_and(|findings| !findings.is_empty())
        })
}

fn extract_positive_model_output_prefix_v2(
    kind: ArtifactAiProviderKindV2,
    stdout: &[u8],
) -> Option<Vec<u8>> {
    let mut values = serde_json::Deserializer::from_slice(stdout).into_iter::<Value>();
    let first = values.next()?.ok()?;
    let first_bytes = serde_json::to_vec(&first).ok()?;
    let model_output = extract_model_output_v2(kind, &first_bytes).ok()?;
    model_output_has_positive_finding_v2(&model_output).then_some(model_output)
}

fn observed_model_v2(kind: ArtifactAiProviderKindV2, stdout: &[u8]) -> ArtifactAiObservedModelV2 {
    if kind == ArtifactAiProviderKindV2::Claude {
        if let Ok(value) = serde_json::from_slice::<Value>(stdout) {
            if let Some(model_id) = value.get("model").and_then(Value::as_str) {
                if valid_identity_text_v2(model_id, 256) {
                    return ArtifactAiObservedModelV2::Present {
                        model_id: model_id.to_string(),
                    };
                }
            }
            for field in ["modelUsage", "model_usage"] {
                if let Some(models) = value.get(field).and_then(Value::as_object) {
                    if models.len() == 1 {
                        if let Some(model_id) = models.keys().next() {
                            if valid_identity_text_v2(model_id, 256) {
                                return ArtifactAiObservedModelV2::Present {
                                    model_id: model_id.to_string(),
                                };
                            }
                        }
                    }
                }
            }
        }
    }
    ArtifactAiObservedModelV2::Unavailable
}

fn strict_identity_capture_v2(bytes: &[u8], limit: usize) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?.trim();
    valid_identity_text_v2(text, limit).then(|| text.to_string())
}

fn valid_identity_text_v2(value: &str, limit: usize) -> bool {
    !value.is_empty()
        && value.len() <= limit
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileIdentityV2 {
    device: u64,
    inode: u64,
    byte_len: u64,
    mode: u32,
    owner: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentityV2 {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            byte_len: metadata.len(),
            mode: metadata.mode(),
            owner: metadata.uid(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

struct HeldNativeExecutableV2 {
    file: File,
    canonical_path: PathBuf,
    identity: FileIdentityV2,
    inspection: HostedCliExecutableInspectionV2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecutableIdentityCheckV2 {
    Unchanged,
    Changed,
    Cancelled,
    TimedOut,
}

impl std::fmt::Debug for HeldNativeExecutableV2 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HeldNativeExecutableV2")
            .field("canonical_path", &"<redacted>")
            .field("identity", &self.identity)
            .field("inspection", &self.inspection)
            .finish()
    }
}

impl HeldNativeExecutableV2 {
    fn open(path: &Path) -> Result<Self, ArtifactAiProviderErrorV2> {
        if !path.is_absolute() {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableInvalid);
        }
        let path_metadata = fs::symlink_metadata(path)
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        if path_metadata.file_type().is_symlink() {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableWrapperRejected);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        let before = file
            .metadata()
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        let identity = FileIdentityV2::from_metadata(&before);
        if !before.is_file() || before.mode() & 0o111 == 0 {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableInvalid);
        }
        if before.len() == 0 || before.len() > MAX_CLIENT_EXECUTABLE_BYTES_V2 {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableLimitExceeded);
        }
        let canonical_path = fs::canonicalize(path)
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        let canonical_identity = fs::metadata(&canonical_path)
            .map(|metadata| FileIdentityV2::from_metadata(&metadata))
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        if canonical_identity != identity {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableIdentityChanged);
        }
        let (sha256, prefix) = stream_executable_sha256_v2(&file, before.len())?;
        let after = file
            .metadata()
            .map(|metadata| FileIdentityV2::from_metadata(&metadata))
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        if before.len() != after.byte_len || identity != after {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableIdentityChanged);
        }
        let format = validate_native_executable_format_v2(&prefix)?;
        Ok(Self {
            file,
            canonical_path,
            identity,
            inspection: HostedCliExecutableInspectionV2 {
                sha256,
                byte_len: before.len(),
                format,
            },
        })
    }

    fn verify_unchanged_bounded(
        &self,
        cancellation: &ArtifactReviewCancellationTokenV2,
        deadline: Instant,
    ) -> Result<ExecutableIdentityCheckV2, ArtifactAiProviderErrorV2> {
        if cancellation.is_cancelled() {
            return Ok(ExecutableIdentityCheckV2::Cancelled);
        }
        if Instant::now() >= deadline {
            return Ok(ExecutableIdentityCheckV2::TimedOut);
        }
        let before = self
            .file
            .metadata()
            .map(|metadata| FileIdentityV2::from_metadata(&metadata))
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        let path_identity = fs::metadata(&self.canonical_path)
            .map(|metadata| FileIdentityV2::from_metadata(&metadata))
            .ok();
        if before != self.identity || path_identity.as_ref() != Some(&self.identity) {
            return Ok(ExecutableIdentityCheckV2::Changed);
        }
        let Some((sha256, prefix)) = stream_executable_sha256_bounded_v2(
            &self.file,
            self.identity.byte_len,
            cancellation,
            deadline,
        )?
        else {
            return Ok(if cancellation.is_cancelled() {
                ExecutableIdentityCheckV2::Cancelled
            } else {
                ExecutableIdentityCheckV2::TimedOut
            });
        };
        let after = self
            .file
            .metadata()
            .map(|metadata| FileIdentityV2::from_metadata(&metadata))
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        Ok(
            if after == self.identity
                && sha256 == self.inspection.sha256
                && validate_native_executable_format_v2(&prefix).ok()
                    == Some(self.inspection.format)
            {
                ExecutableIdentityCheckV2::Unchanged
            } else {
                ExecutableIdentityCheckV2::Changed
            },
        )
    }
}

fn stream_executable_sha256_v2(
    file: &File,
    byte_len: u64,
) -> Result<(Sha256Digest, Vec<u8>), ArtifactAiProviderErrorV2> {
    let mut hasher = StreamingSha256V2::new();
    let mut prefix = Vec::with_capacity(4096);
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < byte_len {
        let remaining = usize::try_from((byte_len - offset).min(buffer.len() as u64))
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        let count = file
            .read_at(&mut buffer[..remaining], offset)
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        if count == 0 {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableIdentityChanged);
        }
        hasher.update(&buffer[..count]);
        if prefix.len() < 4096 {
            let retain = (4096 - prefix.len()).min(count);
            prefix.extend_from_slice(&buffer[..retain]);
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or(ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
    }
    if offset != byte_len {
        return Err(ArtifactAiProviderErrorV2::ClientExecutableIdentityChanged);
    }
    Ok((hasher.finish_digest(), prefix))
}

fn stream_executable_sha256_bounded_v2(
    file: &File,
    byte_len: u64,
    cancellation: &ArtifactReviewCancellationTokenV2,
    deadline: Instant,
) -> Result<Option<(Sha256Digest, Vec<u8>)>, ArtifactAiProviderErrorV2> {
    let mut hasher = StreamingSha256V2::new();
    let mut prefix = Vec::with_capacity(4096);
    let mut buffer = [0u8; 64 * 1024];
    let mut offset = 0u64;
    while offset < byte_len {
        if cancellation.is_cancelled() || Instant::now() >= deadline {
            return Ok(None);
        }
        let remaining = usize::try_from((byte_len - offset).min(buffer.len() as u64))
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        let count = file
            .read_at(&mut buffer[..remaining], offset)
            .map_err(|_| ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
        if count == 0 {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableIdentityChanged);
        }
        hasher.update(&buffer[..count]);
        if prefix.len() < 4096 {
            let retain = (4096 - prefix.len()).min(count);
            prefix.extend_from_slice(&buffer[..retain]);
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or(ArtifactAiProviderErrorV2::ClientExecutableInvalid)?;
    }
    if offset != byte_len {
        return Err(ArtifactAiProviderErrorV2::ClientExecutableIdentityChanged);
    }
    Ok(Some((hasher.finish_digest(), prefix)))
}

fn validate_native_executable_format_v2(
    prefix: &[u8],
) -> Result<HostedCliExecutableFormatV2, ArtifactAiProviderErrorV2> {
    if prefix.starts_with(b"#!") {
        return Err(ArtifactAiProviderErrorV2::ClientExecutableWrapperRejected);
    }
    #[cfg(target_os = "linux")]
    {
        if prefix.len() < 20 || &prefix[..4] != b"\x7fELF" || prefix[4] != 2 {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported);
        }
        let little_endian = prefix[5] == 1;
        if !little_endian {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported);
        }
        let machine = u16::from_le_bytes([prefix[18], prefix[19]]);
        #[cfg(target_arch = "x86_64")]
        let expected_machine = 62u16;
        #[cfg(target_arch = "aarch64")]
        let expected_machine = 183u16;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let expected_machine = u16::MAX;
        if machine != expected_machine {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported);
        }
        return Ok(HostedCliExecutableFormatV2::Elf64Native);
    }
    #[cfg(target_os = "macos")]
    {
        let expected_cpu = {
            #[cfg(target_arch = "aarch64")]
            {
                0x0100_000cu32
            }
            #[cfg(target_arch = "x86_64")]
            {
                0x0100_0007u32
            }
        };
        if prefix.len() >= 8 && &prefix[..4] == b"\xcf\xfa\xed\xfe" {
            let cpu = u32::from_le_bytes(prefix[4..8].try_into().expect("fixed slice"));
            return (cpu == expected_cpu)
                .then_some(HostedCliExecutableFormatV2::MachO64Native)
                .ok_or(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported);
        }
        if prefix.len() >= 8 && &prefix[..4] == b"\xfe\xed\xfa\xcf" {
            let cpu = u32::from_be_bytes(prefix[4..8].try_into().expect("fixed slice"));
            return (cpu == expected_cpu)
                .then_some(HostedCliExecutableFormatV2::MachO64Native)
                .ok_or(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported);
        }
        if prefix.len() >= 8
            && (&prefix[..4] == b"\xca\xfe\xba\xbe" || &prefix[..4] == b"\xbe\xba\xfe\xca")
        {
            let big_endian = &prefix[..4] == b"\xca\xfe\xba\xbe";
            let read_u32 = |bytes: &[u8]| {
                let value: [u8; 4] = bytes.try_into().expect("fixed slice");
                if big_endian {
                    u32::from_be_bytes(value)
                } else {
                    u32::from_le_bytes(value)
                }
            };
            let count = read_u32(&prefix[4..8]) as usize;
            if count == 0 || count > 64 || prefix.len() < 8 + count * 20 {
                return Err(ArtifactAiProviderErrorV2::ClientExecutableInvalid);
            }
            for index in 0..count {
                let start = 8 + index * 20;
                if read_u32(&prefix[start..start + 4]) == expected_cpu {
                    return Ok(HostedCliExecutableFormatV2::MachOFatNative);
                }
            }
            return Err(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported);
        }
        if prefix.len() >= 8
            && (&prefix[..4] == b"\xca\xfe\xba\xbf" || &prefix[..4] == b"\xbf\xba\xfe\xca")
        {
            let big_endian = &prefix[..4] == b"\xca\xfe\xba\xbf";
            let read_u32 = |bytes: &[u8]| {
                let value: [u8; 4] = bytes.try_into().expect("fixed slice");
                if big_endian {
                    u32::from_be_bytes(value)
                } else {
                    u32::from_le_bytes(value)
                }
            };
            let count = read_u32(&prefix[4..8]) as usize;
            if count == 0 || count > 64 || prefix.len() < 8 + count * 32 {
                return Err(ArtifactAiProviderErrorV2::ClientExecutableInvalid);
            }
            for index in 0..count {
                let start = 8 + index * 32;
                if read_u32(&prefix[start..start + 4]) == expected_cpu {
                    return Ok(HostedCliExecutableFormatV2::MachOFatNative);
                }
            }
            return Err(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported);
        }
        Err(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = prefix;
        Err(ArtifactAiProviderErrorV2::ClientExecutableArchitectureUnsupported)
    }
}

struct StreamingSha256V2 {
    state: [u32; 8],
    block: [u8; 64],
    block_len: usize,
    byte_len: u64,
}

impl StreamingSha256V2 {
    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            block: [0; 64],
            block_len: 0,
            byte_len: 0,
        }
    }

    fn update(&mut self, mut bytes: &[u8]) {
        self.byte_len = self.byte_len.wrapping_add(bytes.len() as u64);
        if self.block_len != 0 {
            let copy = (64 - self.block_len).min(bytes.len());
            self.block[self.block_len..self.block_len + copy].copy_from_slice(&bytes[..copy]);
            self.block_len += copy;
            bytes = &bytes[copy..];
            if self.block_len < 64 {
                return;
            }
            let block = self.block;
            self.compress(&block);
            self.block_len = 0;
        }
        while bytes.len() >= 64 {
            let block: &[u8; 64] = bytes[..64].try_into().expect("fixed SHA-256 block");
            self.compress(block);
            bytes = &bytes[64..];
        }
        self.block[..bytes.len()].copy_from_slice(bytes);
        self.block_len = bytes.len();
    }

    fn finish_digest(mut self) -> Sha256Digest {
        let bit_len = self.byte_len.wrapping_mul(8);
        let mut padding = [0u8; 128];
        padding[0] = 0x80;
        let padding_len = if self.block_len < 56 {
            56 - self.block_len
        } else {
            120 - self.block_len
        };
        self.update(&padding[..padding_len]);
        self.update(&bit_len.to_be_bytes());
        let mut hex = String::with_capacity(64);
        for word in self.state {
            use std::fmt::Write as _;
            write!(&mut hex, "{word:08x}").expect("write to String");
        }
        Sha256Digest::parse(format!("sha256:{hex}")).expect("valid SHA-256 digest")
    }

    fn compress(&mut self, block: &[u8; 64]) {
        const K: [u32; 64] = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2,
        ];
        let mut schedule = [0u32; 64];
        for (index, chunk) in block.chunks_exact(4).enumerate() {
            schedule[index] = u32::from_be_bytes(chunk.try_into().expect("fixed word"));
        }
        for index in 16..64 {
            let s0 = schedule[index - 15].rotate_right(7)
                ^ schedule[index - 15].rotate_right(18)
                ^ (schedule[index - 15] >> 3);
            let s1 = schedule[index - 2].rotate_right(17)
                ^ schedule[index - 2].rotate_right(19)
                ^ (schedule[index - 2] >> 10);
            schedule[index] = schedule[index - 16]
                .wrapping_add(s0)
                .wrapping_add(schedule[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choice = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choice)
                .wrapping_add(K[index])
                .wrapping_add(schedule[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        for (state, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *state = state.wrapping_add(value);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryIdentityV2 {
    device: u64,
    inode: u64,
    owner: u32,
    mode: u32,
}

fn validate_authentication_home_v2(
    path: &Path,
) -> Result<(PathBuf, DirectoryIdentityV2), ArtifactAiProviderErrorV2> {
    if !path.is_absolute() || !lexically_normal_absolute_v2(path) {
        return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    let link_metadata =
        fs::symlink_metadata(path).map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    if link_metadata.file_type().is_symlink() || !link_metadata.is_dir() {
        return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    let metadata =
        fs::metadata(&canonical).map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    let expected_owner = unsafe { libc::geteuid() };
    if !metadata.is_dir() || metadata.uid() != expected_owner || metadata.mode() & 0o777 != 0o700 {
        return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    let marker_path = canonical.join(HOSTED_AUTH_HOME_MARKER_FILE_V3);
    let mut marker = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&marker_path)
        .map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    let marker_before = marker
        .metadata()
        .map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    if !marker_before.is_file()
        || marker_before.uid() != expected_owner
        || marker_before.mode() & 0o777 != 0o600
        || marker_before.len() != HOSTED_AUTH_HOME_MARKER_CONTENT_V3.len() as u64
    {
        return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    let mut marker_content = [0u8; HOSTED_AUTH_HOME_MARKER_CONTENT_V3.len()];
    marker
        .read_exact(&mut marker_content)
        .map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    let mut trailing = [0u8; 1];
    if marker
        .read(&mut trailing)
        .map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?
        != 0
        || marker_content.as_slice() != HOSTED_AUTH_HOME_MARKER_CONTENT_V3
    {
        return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    let marker_after = marker
        .metadata()
        .map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    if marker_before.dev() != marker_after.dev()
        || marker_before.ino() != marker_after.ino()
        || marker_before.len() != marker_after.len()
        || marker_before.mode() != marker_after.mode()
        || marker_before.uid() != marker_after.uid()
        || marker_before.mtime() != marker_after.mtime()
        || marker_before.mtime_nsec() != marker_after.mtime_nsec()
        || marker_before.ctime() != marker_after.ctime()
        || marker_before.ctime_nsec() != marker_after.ctime_nsec()
    {
        return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    Ok((
        canonical,
        DirectoryIdentityV2 {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
            mode: metadata.mode(),
        },
    ))
}

fn canonical_runtime_root_candidate_v2(path: &Path) -> Result<PathBuf, ArtifactAiProviderErrorV2> {
    if !path.is_absolute() || !lexically_normal_absolute_v2(path) {
        return Err(ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    if path.exists() {
        return fs::canonicalize(path).map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy);
    }
    let parent = path
        .parent()
        .ok_or(ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    let leaf = path
        .file_name()
        .ok_or(ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    fs::canonicalize(parent)
        .map(|canonical| canonical.join(leaf))
        .map_err(|_| ArtifactAiProviderErrorV2::InvalidRuntimePolicy)
}

fn lexically_normal_absolute_v2(path: &Path) -> bool {
    path.is_absolute()
        && path.components().all(|component| {
            matches!(
                component,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
}

fn paths_overlap_v2(first: &Path, second: &Path) -> bool {
    first == second || first.starts_with(second) || second.starts_with(first)
}

struct PrivateHostedRunV2 {
    path: PathBuf,
    cwd: PathBuf,
    control: PathBuf,
    tmp: PathBuf,
    cleaned: bool,
}

impl PrivateHostedRunV2 {
    fn new(root: &Path) -> Result<Self, ArtifactAiProviderErrorV2> {
        for _ in 0..128 {
            let counter = HOSTED_RUN_COUNTER_V2.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!(
                "hosted-artifact-review-{}-{counter}",
                std::process::id()
            ));
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&path) {
                Ok(()) => {
                    for name in ["cwd", "control", "tmp"] {
                        let mut child = DirBuilder::new();
                        child.mode(0o700);
                        child
                            .create(path.join(name))
                            .map_err(|_| ArtifactAiProviderErrorV2::RunDirectoryFailed)?;
                    }
                    return Ok(Self {
                        cwd: path.join("cwd"),
                        control: path.join("control"),
                        tmp: path.join("tmp"),
                        path,
                        cleaned: false,
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(_) => return Err(ArtifactAiProviderErrorV2::RunDirectoryFailed),
            }
        }
        Err(ArtifactAiProviderErrorV2::RunDirectoryFailed)
    }

    fn cwd_dir(&self) -> &Path {
        &self.cwd
    }

    fn control_dir(&self) -> &Path {
        &self.control
    }

    fn tmp_dir(&self) -> &Path {
        &self.tmp
    }

    fn cleanup(&mut self) -> Result<(), ArtifactAiProviderErrorV2> {
        fs::remove_dir_all(&self.path)
            .map_err(|_| ArtifactAiProviderErrorV2::RunDirectoryCleanupFailed)?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for PrivateHostedRunV2 {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn prepare_runtime_root_v2(path: &Path) -> Result<(), ArtifactAiProviderErrorV2> {
    if !path.exists() {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|_| ArtifactAiProviderErrorV2::RuntimeRootInvalid)?;
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| ArtifactAiProviderErrorV2::RuntimeRootInvalid)?;
    let canonical =
        fs::canonicalize(path).map_err(|_| ArtifactAiProviderErrorV2::RuntimeRootInvalid)?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o700
        || canonical != path
    {
        return Err(ArtifactAiProviderErrorV2::RuntimeRootInvalid);
    }
    Ok(())
}

fn write_private_file_v2(path: &Path, bytes: &[u8]) -> Result<(), ArtifactAiProviderErrorV2> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| ArtifactAiProviderErrorV2::ControlFileFailed)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| ArtifactAiProviderErrorV2::ControlFileFailed)
}

fn directory_is_empty_v2(path: &Path) -> Result<bool, ArtifactAiProviderErrorV2> {
    fs::read_dir(path)
        .map_err(|_| ArtifactAiProviderErrorV2::RunDirectoryFailed)
        .map(|mut entries| entries.next().is_none())
}

struct CommandSpecV2<'a> {
    authorization: &'a AuthorizedHostedCliProviderV2,
    args: &'a [OsString],
    stdin: &'a [u8],
    cwd: &'a Path,
    environment: &'a [(OsString, OsString)],
    stdout_limit: usize,
    stderr_limit: usize,
    timeout: Duration,
    termination_grace: Duration,
    cancellation: &'a ArtifactReviewCancellationTokenV2,
}

struct CapturedCommandV2 {
    status: Option<ExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    stdout_limit_exceeded: bool,
    stderr_limit_exceeded: bool,
    stdin_write_complete: bool,
    stdout_eof_verified: bool,
    stderr_eof_verified: bool,
    pipe_drain_timed_out: bool,
    input_write_failed: bool,
    output_read_failed: bool,
    timed_out: bool,
    cancelled: bool,
    process_group_cleanup_verified: bool,
}

impl CapturedCommandV2 {
    fn skipped(cancelled: bool, timed_out: bool) -> Self {
        Self {
            status: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            stdout_limit_exceeded: false,
            stderr_limit_exceeded: false,
            stdin_write_complete: false,
            stdout_eof_verified: false,
            stderr_eof_verified: false,
            pipe_drain_timed_out: false,
            input_write_failed: false,
            output_read_failed: false,
            timed_out,
            cancelled,
            process_group_cleanup_verified: true,
        }
    }
}

struct HostedChildProcessGuardV2 {
    child: Child,
    process_group: libc::pid_t,
    termination_grace: Duration,
    armed: bool,
}

impl HostedChildProcessGuardV2 {
    fn new(child: Child, termination_grace: Duration) -> Self {
        let process_group = child.id() as libc::pid_t;
        Self {
            child,
            process_group,
            termination_grace,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    fn bounded_cleanup(&mut self) {
        let _ = send_process_group_signal_v2(self.process_group, libc::SIGTERM);
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = send_process_signal_v2(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
        let term_deadline = Instant::now()
            .checked_add(self.termination_grace)
            .unwrap_or_else(Instant::now);
        while Instant::now() < term_deadline {
            let reaped = self.child.try_wait().ok().flatten().is_some();
            let group_gone = matches!(process_group_exists_v2(self.process_group), Ok(false));
            if reaped && group_gone {
                return;
            }
            std::thread::sleep(POLL_INTERVAL_V2);
        }
        let _ = send_process_group_signal_v2(self.process_group, libc::SIGKILL);
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = send_process_signal_v2(self.child.id() as libc::pid_t, libc::SIGKILL);
        }
        let kill_deadline = Instant::now()
            .checked_add(self.termination_grace)
            .unwrap_or_else(Instant::now);
        while Instant::now() < kill_deadline {
            let reaped = self.child.try_wait().ok().flatten().is_some();
            let group_gone = matches!(process_group_exists_v2(self.process_group), Ok(false));
            if reaped && group_gone {
                return;
            }
            std::thread::sleep(POLL_INTERVAL_V2);
        }
        let _ = self.child.try_wait();
    }
}

impl Drop for HostedChildProcessGuardV2 {
    fn drop(&mut self) {
        if self.armed {
            self.bounded_cleanup();
        }
    }
}

fn execute_bounded_command_v2(
    spec: CommandSpecV2<'_>,
) -> Result<CapturedCommandV2, ArtifactAiProviderErrorV2> {
    if spec.cancellation.is_cancelled() {
        return Ok(CapturedCommandV2::skipped(true, false));
    }
    let deadline = Instant::now()
        .checked_add(spec.timeout)
        .ok_or(ArtifactAiProviderErrorV2::InvalidRuntimePolicy)?;
    match spec
        .authorization
        .executable
        .verify_unchanged_bounded(spec.cancellation, deadline)?
    {
        ExecutableIdentityCheckV2::Unchanged => {}
        ExecutableIdentityCheckV2::Changed => {
            return Err(ArtifactAiProviderErrorV2::ClientExecutableIdentityChanged);
        }
        ExecutableIdentityCheckV2::Cancelled => {
            return Ok(CapturedCommandV2::skipped(true, false));
        }
        ExecutableIdentityCheckV2::TimedOut => {
            return Ok(CapturedCommandV2::skipped(false, true));
        }
    }
    #[cfg(not(target_os = "macos"))]
    let held_fd = spec.authorization.executable.file.as_raw_fd();
    let mut command = Command::new(hosted_executable_process_path_v2(spec.authorization));
    command
        .arg0(&spec.authorization.executable.canonical_path)
        .args(spec.args)
        .current_dir(spec.cwd)
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0);
    // Linux can execute the held descriptor through procfs, so the closure
    // preserves it at the fixed descriptor used by the command path. Darwin
    // exposes no `fexecve`/`execveat` and rejects execution through `/dev/fd`;
    // there we execute the measured canonical path while retaining the held
    // descriptor for the immediate before/after identity checks.
    #[cfg(not(target_os = "macos"))]
    // SAFETY: the closure performs only async-signal-safe descriptor operations
    // between fork and exec. The held source descriptor stays alive through
    // `spawn`, and the fixed target is cleared of close-on-exec.
    unsafe {
        command.pre_exec(move || {
            if held_fd != HELD_EXECUTABLE_FD_V2 && libc::dup2(held_fd, HELD_EXECUTABLE_FD_V2) < 0 {
                return Err(io::Error::last_os_error());
            }
            let flags = libc::fcntl(HELD_EXECUTABLE_FD_V2, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(
                    HELD_EXECUTABLE_FD_V2,
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                ) < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    for (name, value) in spec.environment {
        command.env(name, value);
    }
    let child = command
        .spawn()
        .map_err(|_| ArtifactAiProviderErrorV2::ProcessSpawnFailed)?;
    let mut child = HostedChildProcessGuardV2::new(child, spec.termination_grace);
    let process_group = child.process_group;
    let stdin = child
        .child
        .stdin
        .take()
        .ok_or(ArtifactAiProviderErrorV2::ProcessControlFailed)?;
    let mut stdout = Some(
        child
            .child
            .stdout
            .take()
            .ok_or(ArtifactAiProviderErrorV2::ProcessControlFailed)?,
    );
    let mut stderr = Some(
        child
            .child
            .stderr
            .take()
            .ok_or(ArtifactAiProviderErrorV2::ProcessControlFailed)?,
    );
    let mut stdin = if spec.stdin.is_empty() {
        None
    } else {
        Some(stdin)
    };
    if let Some(pipe) = &stdin {
        set_nonblocking_v2(pipe.as_raw_fd())?;
    }
    set_nonblocking_v2(
        stdout
            .as_ref()
            .ok_or(ArtifactAiProviderErrorV2::ProcessControlFailed)?
            .as_raw_fd(),
    )?;
    set_nonblocking_v2(
        stderr
            .as_ref()
            .ok_or(ArtifactAiProviderErrorV2::ProcessControlFailed)?
            .as_raw_fd(),
    )?;

    let mut status = None;
    let mut stdout_capture = Vec::new();
    let mut stderr_capture = Vec::new();
    let mut stdin_offset = 0usize;
    let mut stdout_eof_verified = false;
    let mut stderr_eof_verified = false;
    let mut stdout_limit_exceeded = false;
    let mut stderr_limit_exceeded = false;
    let mut input_write_failed = false;
    let mut output_read_failed = false;
    let mut pipe_drain_timed_out = false;
    let mut timed_out = false;
    let mut cancelled = false;
    let mut termination_started = None;
    let mut sigkill_sent = false;
    let mut pipe_drain_deadline = None;
    let mut cleanup_operations_succeeded = true;
    loop {
        let now = Instant::now();
        if status.is_none() {
            match child.try_wait() {
                Ok(Some(observed)) => {
                    status = Some(observed);
                    stdin.take();
                    pipe_drain_deadline =
                        Some(now.checked_add(spec.termination_grace).unwrap_or_else(|| {
                            cleanup_operations_succeeded = false;
                            now
                        }));
                }
                Ok(None) => {}
                Err(_) => {
                    output_read_failed = true;
                    cleanup_operations_succeeded = false;
                }
            }
        }
        if termination_started.is_none() && spec.cancellation.is_cancelled() {
            cancelled = true;
        }
        if termination_started.is_none() && now >= deadline {
            timed_out = true;
        }

        let abnormal = cancelled
            || timed_out
            || stdout_limit_exceeded
            || stderr_limit_exceeded
            || input_write_failed
            || output_read_failed;
        let lingering_original_group = if status.is_some() {
            match process_group_exists_v2(process_group) {
                Ok(value) => value,
                Err(_) => {
                    cleanup_operations_succeeded = false;
                    true
                }
            }
        } else {
            false
        };
        if termination_started.is_none() && (abnormal || lingering_original_group) {
            termination_started = Some(now);
            stdin.take();
            if send_process_group_signal_v2(process_group, libc::SIGTERM).is_err() {
                cleanup_operations_succeeded = false;
            }
            if status.is_none() && send_process_signal_v2(process_group, libc::SIGTERM).is_err() {
                cleanup_operations_succeeded = false;
            }
            pipe_drain_deadline =
                Some(now.checked_add(spec.termination_grace).unwrap_or_else(|| {
                    cleanup_operations_succeeded = false;
                    now
                }));
        }

        if poll_command_pipes_v2(
            stdin.as_ref().map(AsRawFd::as_raw_fd),
            stdout.as_ref().map(AsRawFd::as_raw_fd),
            stderr.as_ref().map(AsRawFd::as_raw_fd),
        )
        .is_err()
        {
            output_read_failed = true;
            cleanup_operations_succeeded = false;
        }
        if let Some(pipe) = &mut stdin {
            match write_nonblocking_v2(pipe, &spec.stdin[stdin_offset..]) {
                Ok(count) => {
                    stdin_offset += count;
                    if stdin_offset == spec.stdin.len() {
                        stdin.take();
                    }
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(_) => {
                    input_write_failed = true;
                    stdin.take();
                }
            }
        }
        if let Some(pipe) = &mut stdout {
            match read_nonblocking_capture_v2(pipe, &mut stdout_capture, spec.stdout_limit) {
                Ok(CaptureProgressV2::Pending) => {}
                Ok(CaptureProgressV2::Eof) => {
                    stdout_eof_verified = true;
                    stdout.take();
                }
                Ok(CaptureProgressV2::Overflow) => {
                    stdout_limit_exceeded = true;
                    stdout.take();
                }
                Err(_) => {
                    output_read_failed = true;
                    stdout.take();
                }
            }
        }
        if let Some(pipe) = &mut stderr {
            match read_nonblocking_capture_v2(pipe, &mut stderr_capture, spec.stderr_limit) {
                Ok(CaptureProgressV2::Pending) => {}
                Ok(CaptureProgressV2::Eof) => {
                    stderr_eof_verified = true;
                    stderr.take();
                }
                Ok(CaptureProgressV2::Overflow) => {
                    stderr_limit_exceeded = true;
                    stderr.take();
                }
                Err(_) => {
                    output_read_failed = true;
                    stderr.take();
                }
            }
        }

        let now = Instant::now();
        if let Some(started) = termination_started {
            let kill_deadline = started
                .checked_add(spec.termination_grace)
                .unwrap_or_else(|| {
                    cleanup_operations_succeeded = false;
                    started
                });
            if !sigkill_sent && now >= kill_deadline {
                sigkill_sent = true;
                if send_process_group_signal_v2(process_group, libc::SIGKILL).is_err() {
                    cleanup_operations_succeeded = false;
                }
                if status.is_none() && send_process_signal_v2(process_group, libc::SIGKILL).is_err()
                {
                    cleanup_operations_succeeded = false;
                }
            }
            let hard_deadline = kill_deadline
                .checked_add(spec.termination_grace)
                .unwrap_or_else(|| {
                    cleanup_operations_succeeded = false;
                    kill_deadline
                });
            if now >= hard_deadline {
                if status.is_none() {
                    match child.try_wait() {
                        Ok(observed) => status = observed,
                        Err(_) => {
                            output_read_failed = true;
                            cleanup_operations_succeeded = false;
                        }
                    }
                }
                if status.is_none() || !matches!(process_group_exists_v2(process_group), Ok(false))
                {
                    cleanup_operations_succeeded = false;
                }
                if stdout.is_some() || stderr.is_some() {
                    pipe_drain_timed_out = true;
                }
                stdout.take();
                stderr.take();
                break;
            }
        }
        if pipe_drain_deadline.is_some_and(|drain_deadline| now >= drain_deadline)
            && (stdout.is_some() || stderr.is_some())
        {
            pipe_drain_timed_out = true;
            stdout.take();
            stderr.take();
        }
        if status.is_some()
            && stdout.is_none()
            && stderr.is_none()
            && matches!(process_group_exists_v2(process_group), Ok(false))
        {
            break;
        }
    }
    let process_group_cleanup_verified = cleanup_operations_succeeded
        && status.is_some()
        && matches!(process_group_exists_v2(process_group), Ok(false));
    if process_group_cleanup_verified {
        child.disarm();
    }
    let stdin_write_complete = stdin_offset == spec.stdin.len();
    Ok(CapturedCommandV2 {
        status,
        stdout: stdout_capture,
        stderr: stderr_capture,
        stdout_limit_exceeded,
        stderr_limit_exceeded,
        stdin_write_complete,
        stdout_eof_verified,
        stderr_eof_verified,
        pipe_drain_timed_out,
        input_write_failed,
        output_read_failed,
        timed_out,
        cancelled,
        process_group_cleanup_verified,
    })
}

#[cfg(target_os = "macos")]
fn hosted_executable_process_path_v2(authorization: &AuthorizedHostedCliProviderV2) -> &Path {
    &authorization.executable.canonical_path
}

#[cfg(not(target_os = "macos"))]
fn hosted_executable_process_path_v2(_: &AuthorizedHostedCliProviderV2) -> &Path {
    Path::new("/proc/self/fd/198")
}

fn set_nonblocking_v2(fd: libc::c_int) -> Result<(), ArtifactAiProviderErrorV2> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(ArtifactAiProviderErrorV2::ProcessControlFailed);
    }
    Ok(())
}

fn poll_command_pipes_v2(
    stdin_fd: Option<libc::c_int>,
    stdout_fd: Option<libc::c_int>,
    stderr_fd: Option<libc::c_int>,
) -> Result<(), ArtifactAiProviderErrorV2> {
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
    let timeout = i32::try_from(POLL_INTERVAL_V2.as_millis()).unwrap_or(10);
    let result = unsafe {
        libc::poll(
            descriptors.as_mut_ptr(),
            descriptors.len() as libc::nfds_t,
            timeout,
        )
    };
    if result < 0 && io::Error::last_os_error().kind() != ErrorKind::Interrupted {
        return Err(ArtifactAiProviderErrorV2::ProcessControlFailed);
    }
    Ok(())
}

fn write_nonblocking_v2(stdin: &mut ChildStdin, bytes: &[u8]) -> io::Result<usize> {
    if bytes.is_empty() {
        return Ok(0);
    }
    stdin.write(&bytes[..bytes.len().min(16 * 1024)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureProgressV2 {
    Pending,
    Eof,
    Overflow,
}

fn read_nonblocking_capture_v2(
    stream: &mut impl Read,
    capture: &mut Vec<u8>,
    limit: usize,
) -> io::Result<CaptureProgressV2> {
    let mut chunk = [0u8; 16 * 1024];
    loop {
        let remaining = limit.saturating_sub(capture.len());
        let read_len = chunk.len().min(remaining.saturating_add(1)).max(1);
        match stream.read(&mut chunk[..read_len]) {
            Ok(0) => return Ok(CaptureProgressV2::Eof),
            Ok(count) => {
                let retained = count.min(remaining);
                capture.extend_from_slice(&chunk[..retained]);
                if count > remaining {
                    return Ok(CaptureProgressV2::Overflow);
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                return Ok(CaptureProgressV2::Pending)
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

fn command_completed(capture: &CapturedCommandV2) -> bool {
    capture.status.as_ref().is_some_and(ExitStatus::success)
        && !capture.stdout_limit_exceeded
        && !capture.stderr_limit_exceeded
        && capture.stdin_write_complete
        && capture.stdout_eof_verified
        && capture.stderr_eof_verified
        && !capture.pipe_drain_timed_out
        && !capture.input_write_failed
        && !capture.output_read_failed
        && !capture.timed_out
        && !capture.cancelled
        && capture.process_group_cleanup_verified
}

fn execution_status_v2(capture: &CapturedCommandV2) -> ArtifactAiExecutionStatusV2 {
    if capture.cancelled {
        ArtifactAiExecutionStatusV2::Cancelled
    } else if capture.timed_out {
        ArtifactAiExecutionStatusV2::TimedOut
    } else if capture.stdout_limit_exceeded {
        ArtifactAiExecutionStatusV2::StdoutLimitExceeded
    } else if capture.stderr_limit_exceeded {
        ArtifactAiExecutionStatusV2::StderrLimitExceeded
    } else if capture.pipe_drain_timed_out
        || capture.input_write_failed
        || capture.output_read_failed
        || !capture.stdin_write_complete
        || !capture.stdout_eof_verified
        || !capture.stderr_eof_verified
    {
        ArtifactAiExecutionStatusV2::OutputCaptureIncomplete
    } else if !capture.process_group_cleanup_verified {
        ArtifactAiExecutionStatusV2::ProcessCleanupFailed
    } else if command_completed(capture) {
        ArtifactAiExecutionStatusV2::Completed
    } else {
        ArtifactAiExecutionStatusV2::ClientNonZeroExit
    }
}

fn send_process_group_signal_v2(
    process_group: libc::pid_t,
    signal: libc::c_int,
) -> Result<(), ArtifactAiProviderErrorV2> {
    let result = unsafe { libc::kill(-process_group, signal) };
    if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(ArtifactAiProviderErrorV2::ProcessControlFailed);
    }
    Ok(())
}

fn send_process_signal_v2(
    process_id: libc::pid_t,
    signal: libc::c_int,
) -> Result<(), ArtifactAiProviderErrorV2> {
    let result = unsafe { libc::kill(process_id, signal) };
    if result != 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
        return Err(ArtifactAiProviderErrorV2::ProcessControlFailed);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn process_group_exists_v2(process_group: libc::pid_t) -> Result<bool, ArtifactAiProviderErrorV2> {
    let mut process_ids = [0 as libc::pid_t; 64];
    let buffer_size = i32::try_from(std::mem::size_of_val(&process_ids))
        .map_err(|_| ArtifactAiProviderErrorV2::ProcessControlFailed)?;
    // libproc may report zero while leaving errno set, so clear and inspect it
    // around the bounded process-group query.
    // SAFETY: __error returns this thread's writable errno pointer.
    unsafe {
        *libc::__error() = 0;
    }
    // SAFETY: process_ids is writable pid_t storage and buffer_size is its
    // exact byte length.
    let count = unsafe {
        hosted_proc_listpgrppids_v2(process_group, process_ids.as_mut_ptr().cast(), buffer_size)
    };
    // SAFETY: __error returns this thread's errno value.
    let query_errno = unsafe { *libc::__error() };
    if count > 0 {
        return Ok(true);
    }
    if count == 0 || query_errno == libc::ESRCH {
        return Ok(false);
    }
    Err(ArtifactAiProviderErrorV2::ProcessControlFailed)
}

#[cfg(not(target_os = "macos"))]
fn process_group_exists_v2(process_group: libc::pid_t) -> Result<bool, ArtifactAiProviderErrorV2> {
    // SAFETY: signal zero performs existence/permission checking only.
    let result = unsafe { libc::kill(-process_group, 0) };
    if result == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(ArtifactAiProviderErrorV2::ProcessControlFailed),
    }
}

#[cfg(target_os = "macos")]
#[link(name = "proc")]
extern "C" {
    #[link_name = "proc_listpgrppids"]
    fn hosted_proc_listpgrppids_v2(
        process_group_id: libc::pid_t,
        buffer: *mut libc::c_void,
        buffer_size: libc::c_int,
    ) -> libc::c_int;
}

fn unix_millis_v2() -> Result<u64, ArtifactAiProviderErrorV2> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ArtifactAiProviderErrorV2::SystemClockInvalid)?
        .as_millis();
    u64::try_from(millis).map_err(|_| ArtifactAiProviderErrorV2::SystemClockInvalid)
}

fn unix_seconds_v3() -> Result<u64, ArtifactAiProviderErrorV2> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ArtifactAiProviderErrorV2::SystemClockInvalid)
        .map(|duration| duration.as_secs())
}
