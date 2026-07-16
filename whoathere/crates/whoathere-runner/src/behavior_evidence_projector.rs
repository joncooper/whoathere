//! Narrow projection of already-separated package execution evidence into the
//! detector's observe-only behavior bundle.
//!
//! This module deliberately does not verify receipt signatures, inspect raw
//! paths or packets, invoke AI, or make an admission decision. The caller must
//! independently authenticate the evidence before relying on it. Until a host
//! composite receipt is present, every projected modality remains incomplete.

use serde_json::{Map, Value};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use whoathere_detector::{
    BehaviorAnalysisBundleInputV1, BehaviorAnalysisBundleV1, BehaviorAnalysisErrorV1,
    BehaviorEvidenceCoverageV1, BehaviorEvidenceEventV1, BehaviorEvidenceModalityV1,
    BehaviorEvidenceSignalV1, CanaryActionV1, CanaryClassV1, FileOperationV1, FileTargetClassV1,
    NetworkActionV1, NetworkDestinationClassV1, PackageTriggerV1, ProcessActionV1,
};

const ROOT_RECEIPT_SCHEMA_V2: &str = "whoathere.linux_vz_package_root_evidence_receipt.v2";
const ROOT_PROCESS_SCHEMA_V1: &str = "whoathere.linux_vz_package_root_process_evidence.v1";
const ROOT_FILE_SCHEMA_V1: &str = "whoathere.linux_vz_package_root_file_evidence.v1";
const ROOT_NETWORK_SCHEMA_V2: &str = "whoathere.linux_vz_package_root_network_evidence.v2";
const HOST_EXECUTION_RUN_SCHEMA_V1: &str = "whoathere.linux_vz_package_execution_result.v1";

const MAX_ROOT_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_SENSOR_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;
const MAX_HOST_EXECUTION_RUN_BYTES: usize = 1024 * 1024;
const MAX_PROJECTED_EVENTS: usize = 50_000;

#[derive(Debug, Clone, Copy)]
pub struct ExactDetonationBehaviorProjectionInputV1<'a> {
    pub artifact_sha256: &'a Sha256Digest,
    pub manifest_sha256: &'a Sha256Digest,
    pub scenario_id: &'a str,
    pub scenario_sha256: &'a Sha256Digest,
    pub process_plan_sha256: &'a Sha256Digest,
    pub run_id: &'a str,
    pub host_execution_run_sha256: &'a Sha256Digest,
    pub root_receipt_json: &'a [u8],
    pub process_evidence_json: &'a [u8],
    pub file_evidence_json: &'a [u8],
    pub network_evidence_json: &'a [u8],
    pub host_execution_run_json: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BehaviorEvidenceProjectionErrorV1 {
    Empty,
    LimitExceeded,
    InvalidJson,
    NonCanonical,
    InvalidSchema,
    MissingField,
    InvalidField,
    BindingMismatch,
    BundleInvalid,
}

impl BehaviorEvidenceProjectionErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Empty => "behavior_evidence_projection_empty",
            Self::LimitExceeded => "behavior_evidence_projection_limit_exceeded",
            Self::InvalidJson => "behavior_evidence_projection_json_invalid",
            Self::NonCanonical => "behavior_evidence_projection_json_noncanonical",
            Self::InvalidSchema => "behavior_evidence_projection_schema_invalid",
            Self::MissingField => "behavior_evidence_projection_field_missing",
            Self::InvalidField => "behavior_evidence_projection_field_invalid",
            Self::BindingMismatch => "behavior_evidence_projection_binding_mismatch",
            Self::BundleInvalid => "behavior_evidence_projection_bundle_invalid",
        }
    }
}

impl fmt::Display for BehaviorEvidenceProjectionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for BehaviorEvidenceProjectionErrorV1 {}

impl From<BehaviorAnalysisErrorV1> for BehaviorEvidenceProjectionErrorV1 {
    fn from(_: BehaviorAnalysisErrorV1) -> Self {
        Self::BundleInvalid
    }
}

#[derive(Debug)]
struct PendingEventV1 {
    timestamp_monotonic_nanoseconds: u64,
    modality_order: u8,
    source_sequence: u64,
    source_index: usize,
    event_id: String,
    signal: BehaviorEvidenceSignalV1,
}

#[derive(Debug)]
struct ProcessProjectionV1 {
    events: Vec<PendingEventV1>,
    observation_count: usize,
    coverage_complete: bool,
}

#[derive(Debug)]
struct FileProjectionV1 {
    events: Vec<PendingEventV1>,
    event_count: usize,
    declared_scope_complete: bool,
    global_mount_coverage_complete: bool,
}

#[derive(Debug)]
struct NetworkProjectionV1 {
    events: Vec<PendingEventV1>,
    event_count: usize,
    connect_sendto_coverage_complete: bool,
    target_detail_complete: bool,
    dns_coverage_complete: bool,
    http_coverage_complete: bool,
    host_frame_correlation_complete: bool,
}

#[derive(Debug)]
struct HostExecutionCoverageV1 {
    independent_root_verification_complete: bool,
    host_composition_complete: bool,
    lifecycle_complete: bool,
}

/// Projects only allowlisted, typed fields from canonical evidence JSON.
///
/// All emitted events cite the canonical root-receipt digest. The supplied host
/// execution-run digest is bound into the bundle's host-receipt slot, but the
/// coverage explicitly remains incomplete unless that record says independent
/// root verification and host composition both completed.
pub fn project_exact_detonation_behavior_v1(
    input: ExactDetonationBehaviorProjectionInputV1<'_>,
) -> Result<BehaviorAnalysisBundleV1, BehaviorEvidenceProjectionErrorV1> {
    let root_receipt = canonical_object(input.root_receipt_json, MAX_ROOT_RECEIPT_BYTES)?;
    let process = canonical_object(input.process_evidence_json, MAX_SENSOR_EVIDENCE_BYTES)?;
    let file = canonical_object(input.file_evidence_json, MAX_SENSOR_EVIDENCE_BYTES)?;
    let network = canonical_object(input.network_evidence_json, MAX_SENSOR_EVIDENCE_BYTES)?;
    let host_run = canonical_object(input.host_execution_run_json, MAX_HOST_EXECUTION_RUN_BYTES)?;

    let root_receipt_sha256 = Sha256Digest::from_bytes(input.root_receipt_json);
    let process_sha256 = Sha256Digest::from_bytes(input.process_evidence_json);
    let file_sha256 = Sha256Digest::from_bytes(input.file_evidence_json);
    let network_sha256 = Sha256Digest::from_bytes(input.network_evidence_json);
    let host_run_sha256 = Sha256Digest::from_bytes(input.host_execution_run_json);
    if &host_run_sha256 != input.host_execution_run_sha256 {
        return Err(BehaviorEvidenceProjectionErrorV1::BindingMismatch);
    }

    let process_projection = project_process_v1(&process, input)?;
    let file_projection = project_file_v1(&file, input)?;
    let network_projection = project_network_v1(&network, input, &process_sha256)?;

    validate_root_receipt_bindings_v1(
        &root_receipt,
        input,
        &process_sha256,
        &file_sha256,
        &network_sha256,
        process_projection.observation_count,
        file_projection.event_count,
        network_projection.event_count,
    )?;
    let host_coverage = validate_host_execution_run_v1(
        &host_run,
        input,
        &root_receipt_sha256,
        &process_sha256,
        &file_sha256,
        &network_sha256,
    )?;

    let host_composition_missing = !host_coverage.independent_root_verification_complete
        || !host_coverage.host_composition_complete;
    let mut coverage = Vec::with_capacity(BehaviorEvidenceModalityV1::ALL.len());
    coverage.push(coverage_v1(
        BehaviorEvidenceModalityV1::Process,
        limitation_codes(&[
            (
                host_composition_missing,
                "independent_host_composition_missing",
            ),
            (
                !process_projection.coverage_complete,
                "process_evidence_coverage_incomplete",
            ),
        ]),
    )?);
    coverage.push(coverage_v1(
        BehaviorEvidenceModalityV1::Filesystem,
        limitation_codes(&[
            (
                host_composition_missing,
                "independent_host_composition_missing",
            ),
            (
                !file_projection.declared_scope_complete,
                "declared_filesystem_scope_incomplete",
            ),
            (
                !file_projection.global_mount_coverage_complete,
                "global_filesystem_coverage_incomplete",
            ),
        ]),
    )?);
    coverage.push(coverage_v1(
        BehaviorEvidenceModalityV1::Canary,
        limitation_codes(&[
            (
                host_composition_missing,
                "independent_host_composition_missing",
            ),
            (
                !file_projection.global_mount_coverage_complete,
                "global_filesystem_coverage_incomplete",
            ),
            (true, "canary_egress_correlation_incomplete"),
        ]),
    )?);
    coverage.push(coverage_v1(
        BehaviorEvidenceModalityV1::Network,
        limitation_codes(&[
            (
                host_composition_missing,
                "independent_host_composition_missing",
            ),
            (
                !network_projection.connect_sendto_coverage_complete,
                "connect_sendto_coverage_incomplete",
            ),
            (
                !network_projection.target_detail_complete,
                "network_target_detail_incomplete",
            ),
            (
                !network_projection.host_frame_correlation_complete,
                "host_frame_correlation_incomplete",
            ),
            (
                !network_projection.dns_coverage_complete,
                "dns_intent_coverage_incomplete",
            ),
            (
                !network_projection.http_coverage_complete,
                "http_observation_coverage_incomplete",
            ),
        ]),
    )?);
    coverage.push(coverage_v1(
        BehaviorEvidenceModalityV1::Scenario,
        limitation_codes(&[
            (
                host_composition_missing,
                "independent_host_composition_missing",
            ),
            (!host_coverage.lifecycle_complete, "vm_lifecycle_incomplete"),
        ]),
    )?);

    let mut pending = process_projection.events;
    pending.extend(file_projection.events);
    pending.extend(network_projection.events);
    if pending.len() > MAX_PROJECTED_EVENTS {
        return Err(BehaviorEvidenceProjectionErrorV1::LimitExceeded);
    }
    pending.sort_by_key(|event| {
        (
            event.timestamp_monotonic_nanoseconds,
            event.modality_order,
            event.source_sequence,
            event.source_index,
        )
    });
    let events = pending
        .into_iter()
        .enumerate()
        .map(|(index, event)| {
            let sequence = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or(BehaviorEvidenceProjectionErrorV1::LimitExceeded)?;
            BehaviorEvidenceEventV1::new(
                sequence,
                event.event_id,
                root_receipt_sha256.clone(),
                event.signal,
                None,
            )
            .map_err(BehaviorEvidenceProjectionErrorV1::from)
        })
        .collect::<Result<Vec<_>, _>>()?;

    BehaviorAnalysisBundleV1::new(
        BehaviorAnalysisBundleInputV1 {
            artifact_sha256: input.artifact_sha256.clone(),
            manifest_sha256: input.manifest_sha256.clone(),
            scenario_id: input.scenario_id.to_string(),
            scenario_sha256: input.scenario_sha256.clone(),
            run_id: input.run_id.to_string(),
            root_receipt_sha256,
            host_receipt_sha256: host_run_sha256,
        },
        coverage,
        events,
    )
    .map_err(BehaviorEvidenceProjectionErrorV1::from)
}

fn project_process_v1(
    process: &Map<String, Value>,
    input: ExactDetonationBehaviorProjectionInputV1<'_>,
) -> Result<ProcessProjectionV1, BehaviorEvidenceProjectionErrorV1> {
    require_schema(process, ROOT_PROCESS_SCHEMA_V1)?;
    let binding = object_field(process, "binding")?;
    require_digest(binding, "process_plan_sha256", input.process_plan_sha256)?;
    let leader_pid = decimal_u64_field(binding, "leader_pid")?;
    if leader_pid <= 1 {
        return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
    }
    let coverage = object_field(process, "coverage")?;
    let observations = array_field(process, "observations")?;
    require_count(coverage, "observation_count", observations.len())?;
    let coverage_complete = bool_field(coverage, "coverage_complete")?
        && bool_field(coverage, "continuous_drain")?
        && bool_field(coverage, "process_sensor_healthy")?
        && !bool_field(coverage, "evidence_truncated")?
        && decimal_u64_field(coverage, "dropped_event_count")? == 0
        && decimal_u64_field(coverage, "discarded_record_count")? == 0;

    let trigger = package_trigger_for_scenario(input.scenario_id);
    let mut events = Vec::new();
    for (index, observation) in observations.iter().enumerate() {
        let observation = observation
            .as_object()
            .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidField)?;
        match string_field(observation, "observation_kind")? {
            "syscall" => continue,
            "lifecycle" => {}
            _ => return Err(BehaviorEvidenceProjectionErrorV1::InvalidField),
        }
        let lifecycle = string_field(observation, "lifecycle_kind")?;
        if !matches!(lifecycle, "fork" | "exec" | "exit") {
            return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
        }
        if lifecycle == "exit" {
            continue;
        }
        let source_sequence = decimal_u64_field(observation, "source_sequence")?;
        let timestamp = decimal_u64_field(observation, "timestamp_monotonic_nanoseconds")?;
        let subject_pid = decimal_u64_field(observation, "subject_pid")?;
        if source_sequence == 0 || timestamp == 0 || subject_pid <= 1 {
            return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
        }
        let signal = if lifecycle == "exec" && subject_pid == leader_pid {
            trigger.map_or(
                BehaviorEvidenceSignalV1::Process {
                    action: ProcessActionV1::OrdinaryChild,
                    trigger: None,
                },
                |trigger| BehaviorEvidenceSignalV1::Process {
                    action: ProcessActionV1::PackageTrigger,
                    trigger: Some(trigger),
                },
            )
        } else {
            BehaviorEvidenceSignalV1::Process {
                action: ProcessActionV1::OrdinaryChild,
                trigger: None,
            }
        };
        events.push(PendingEventV1 {
            timestamp_monotonic_nanoseconds: timestamp,
            modality_order: 0,
            source_sequence,
            source_index: index,
            event_id: format!("process-{source_sequence}-{lifecycle}-{index}"),
            signal,
        });
    }
    Ok(ProcessProjectionV1 {
        events,
        observation_count: observations.len(),
        coverage_complete,
    })
}

fn project_file_v1(
    file: &Map<String, Value>,
    input: ExactDetonationBehaviorProjectionInputV1<'_>,
) -> Result<FileProjectionV1, BehaviorEvidenceProjectionErrorV1> {
    require_schema(file, ROOT_FILE_SCHEMA_V1)?;
    let binding = object_field(file, "binding")?;
    require_digest(binding, "process_plan_sha256", input.process_plan_sha256)?;
    let coverage = object_field(file, "coverage")?;
    let source_events = array_field(file, "events")?;
    require_count(coverage, "source_event_count", source_events.len())?;
    let declared_scope_complete = bool_field(coverage, "declared_scope_complete")?
        && bool_field(coverage, "file_sensor_healthy")?
        && !bool_field(coverage, "evidence_truncated")?
        && decimal_u64_field(coverage, "fanotify_overflow_count")? == 0;
    let global_mount_coverage_complete = bool_field(coverage, "global_mount_coverage_complete")?;

    let mut events = Vec::new();
    for (index, source_event) in source_events.iter().enumerate() {
        let source_event = source_event
            .as_object()
            .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidField)?;
        let event_kind = string_field(source_event, "event_kind")?;
        if !matches!(event_kind, "open" | "read" | "write" | "open_exec") {
            return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
        }
        if !matches!(event_kind, "open" | "read") {
            continue;
        }
        if !matches!(
            string_field(source_event, "access_outcome")?,
            "observed" | "denied"
        ) {
            return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
        }
        let path_class = string_field(source_event, "path_class")?;
        let signal = match path_class {
            "sensitive_credential" => BehaviorEvidenceSignalV1::Filesystem {
                operation: FileOperationV1::Read,
                target: FileTargetClassV1::CredentialFile,
            },
            "protected_canary" => BehaviorEvidenceSignalV1::Canary {
                action: CanaryActionV1::Read,
                canary: CanaryClassV1::NpmToken,
            },
            _ => continue,
        };
        let source_sequence = decimal_u64_field(source_event, "source_sequence")?;
        let timestamp = decimal_u64_field(source_event, "timestamp_monotonic_nanoseconds")?;
        if source_sequence == 0 || timestamp == 0 {
            return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
        }
        events.push(PendingEventV1 {
            timestamp_monotonic_nanoseconds: timestamp,
            modality_order: if path_class == "protected_canary" {
                2
            } else {
                1
            },
            source_sequence,
            source_index: index,
            event_id: format!("file-{source_sequence}-{path_class}-{event_kind}-{index}"),
            signal,
        });
    }
    Ok(FileProjectionV1 {
        events,
        event_count: source_events.len(),
        declared_scope_complete,
        global_mount_coverage_complete,
    })
}

fn project_network_v1(
    network: &Map<String, Value>,
    input: ExactDetonationBehaviorProjectionInputV1<'_>,
    process_sha256: &Sha256Digest,
) -> Result<NetworkProjectionV1, BehaviorEvidenceProjectionErrorV1> {
    require_schema(network, ROOT_NETWORK_SCHEMA_V2)?;
    let binding = object_field(network, "binding")?;
    require_digest(binding, "process_plan_sha256", input.process_plan_sha256)?;
    require_digest(binding, "process_evidence_sha256", process_sha256)?;
    let coverage = object_field(network, "coverage")?;
    let source_events = array_field(network, "events")?;
    require_count(coverage, "network_event_count", source_events.len())?;

    let connect_sendto_coverage_complete =
        bool_field(coverage, "connect_sendto_intent_coverage_complete")?
            && bool_field(coverage, "process_sensor_healthy")?
            && !bool_field(coverage, "evidence_truncated")?
            && decimal_u64_field(coverage, "dropped_event_count")? == 0
            && decimal_u64_field(coverage, "discarded_record_count")? == 0;
    let target_detail_complete = bool_field(coverage, "target_detail_complete")?;
    let dns_coverage_complete = bool_field(coverage, "dns_intent_coverage_complete")?;
    let http_coverage_complete = bool_field(coverage, "http_observation_complete")?;
    let host_frame_correlation_complete = bool_field(coverage, "host_frame_correlation_complete")?;

    let mut events = Vec::with_capacity(source_events.len());
    for (index, source_event) in source_events.iter().enumerate() {
        let source_event = source_event
            .as_object()
            .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidField)?;
        let event_kind = string_field(source_event, "event_kind")?;
        let action = match event_kind {
            "connect" => NetworkActionV1::Connect,
            "sendto" => NetworkActionV1::Send,
            _ => return Err(BehaviorEvidenceProjectionErrorV1::InvalidField),
        };
        let destination = match string_field(source_event, "target_status")? {
            "observed" => {
                if source_event.contains_key("target_unavailable_reason") {
                    return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
                }
                map_network_destination_v1(string_field(source_event, "destination_class")?)?
            }
            "unavailable" => {
                if source_event
                    .get("target_unavailable_reason")
                    .and_then(Value::as_str)
                    != Some("sendto_destination_detail_unavailable")
                    || [
                        "address_family",
                        "destination_class",
                        "destination_port",
                        "destination_token_sha256",
                    ]
                    .iter()
                    .any(|field| source_event.contains_key(*field))
                {
                    return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
                }
                NetworkDestinationClassV1::Unavailable
            }
            _ => return Err(BehaviorEvidenceProjectionErrorV1::InvalidField),
        };
        let source_sequence = decimal_u64_field(source_event, "enter_source_sequence")?;
        let timestamp = decimal_u64_field(source_event, "enter_timestamp_monotonic_nanoseconds")?;
        if source_sequence == 0 || timestamp == 0 {
            return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
        }
        events.push(PendingEventV1 {
            timestamp_monotonic_nanoseconds: timestamp,
            modality_order: 3,
            source_sequence,
            source_index: index,
            event_id: format!("network-{source_sequence}-{event_kind}-{index}"),
            signal: BehaviorEvidenceSignalV1::Network {
                action,
                destination,
            },
        });
    }
    Ok(NetworkProjectionV1 {
        events,
        event_count: source_events.len(),
        connect_sendto_coverage_complete,
        target_detail_complete,
        dns_coverage_complete,
        http_coverage_complete,
        host_frame_correlation_complete,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_root_receipt_bindings_v1(
    root_receipt: &Map<String, Value>,
    input: ExactDetonationBehaviorProjectionInputV1<'_>,
    process_sha256: &Sha256Digest,
    file_sha256: &Sha256Digest,
    network_sha256: &Sha256Digest,
    process_observation_count: usize,
    file_event_count: usize,
    network_event_count: usize,
) -> Result<(), BehaviorEvidenceProjectionErrorV1> {
    let claims = object_field(root_receipt, "claims")?;
    require_schema(claims, ROOT_RECEIPT_SCHEMA_V2)?;
    require_digest(claims, "artifact_sha256", input.artifact_sha256)?;
    require_digest(claims, "scenario_plan_sha256", input.scenario_sha256)?;
    require_digest(claims, "process_plan_sha256", input.process_plan_sha256)?;
    require_digest(claims, "process_evidence_sha256", process_sha256)?;
    require_digest(claims, "file_evidence_sha256", file_sha256)?;
    require_digest(claims, "network_evidence_sha256", network_sha256)?;
    require_length(
        claims,
        "process_evidence_byte_length",
        input.process_evidence_json.len(),
    )?;
    require_length(
        claims,
        "file_evidence_byte_length",
        input.file_evidence_json.len(),
    )?;
    require_length(
        claims,
        "network_evidence_byte_length",
        input.network_evidence_json.len(),
    )?;
    require_count(
        claims,
        "process_observation_count",
        process_observation_count,
    )?;
    require_count(claims, "file_event_count", file_event_count)?;
    require_count(claims, "network_event_count", network_event_count)?;
    if !bool_field(claims, "host_composition_required")?
        || bool_field(claims, "authoritative_verdict_permitted")?
        || bool_field(claims, "sync_back")?
        || bool_field(claims, "public_network_route_present")?
        || bool_field(claims, "raw_arguments_captured")?
        || bool_field(claims, "raw_exec_paths_captured")?
        || bool_field(claims, "raw_file_paths_captured")?
        || bool_field(claims, "raw_network_addresses_captured")?
    {
        return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
    }
    let signature = string_field(root_receipt, "signature_ed25519_hex")?;
    if signature.len() != 128
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
    }
    Ok(())
}

fn validate_host_execution_run_v1(
    host_run: &Map<String, Value>,
    input: ExactDetonationBehaviorProjectionInputV1<'_>,
    root_receipt_sha256: &Sha256Digest,
    process_sha256: &Sha256Digest,
    file_sha256: &Sha256Digest,
    network_sha256: &Sha256Digest,
) -> Result<HostExecutionCoverageV1, BehaviorEvidenceProjectionErrorV1> {
    require_schema(host_run, HOST_EXECUTION_RUN_SCHEMA_V1)?;
    require_digest(host_run, "artifact_sha256", input.artifact_sha256)?;
    for (digest_field, length_field, digest, bytes) in [
        (
            "root_receipt_sha256",
            "root_receipt_byte_length",
            root_receipt_sha256,
            input.root_receipt_json,
        ),
        (
            "process_evidence_sha256",
            "process_evidence_byte_length",
            process_sha256,
            input.process_evidence_json,
        ),
        (
            "file_evidence_sha256",
            "file_evidence_byte_length",
            file_sha256,
            input.file_evidence_json,
        ),
        (
            "network_evidence_sha256",
            "network_evidence_byte_length",
            network_sha256,
            input.network_evidence_json,
        ),
    ] {
        require_digest(host_run, digest_field, digest)?;
        require_length(host_run, length_field, bytes.len())?;
    }
    if bool_field(host_run, "authoritative_verdict_permitted")?
        || bool_field(host_run, "public_network_route_present")?
        || bool_field(host_run, "sync_back")?
    {
        return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
    }
    Ok(HostExecutionCoverageV1 {
        independent_root_verification_complete: bool_field(
            host_run,
            "guest_root_receipt_independently_verified",
        )?,
        host_composition_complete: bool_field(host_run, "host_composition_complete")?,
        lifecycle_complete: bool_field(host_run, "vm_started")?
            && bool_field(host_run, "vm_stopped")?
            && bool_field(host_run, "clone_destroyed")?
            && bool_field(host_run, "image_identity_stable")?,
    })
}

fn package_trigger_for_scenario(scenario_id: &str) -> Option<PackageTriggerV1> {
    let value = scenario_id.to_ascii_lowercase();
    if value.contains("npm") {
        if value.contains("bin") {
            Some(PackageTriggerV1::NpmBin)
        } else if value.contains("import") {
            Some(PackageTriggerV1::NpmImport)
        } else {
            Some(PackageTriggerV1::NpmLifecycle)
        }
    } else if value.contains("wheel") {
        if value.contains("pth") {
            Some(PackageTriggerV1::WheelPth)
        } else if value.contains("entry") || value.contains("console") {
            Some(PackageTriggerV1::WheelEntryPoint)
        } else {
            Some(PackageTriggerV1::WheelImport)
        }
    } else if value.contains("sdist") {
        if value.contains("setup") {
            Some(PackageTriggerV1::SdistSetupPy)
        } else if value.contains("import") {
            Some(PackageTriggerV1::SdistImport)
        } else {
            Some(PackageTriggerV1::SdistBuildBackend)
        }
    } else {
        None
    }
}

fn map_network_destination_v1(
    value: &str,
) -> Result<NetworkDestinationClassV1, BehaviorEvidenceProjectionErrorV1> {
    match value {
        "metadata" => Ok(NetworkDestinationClassV1::CloudMetadata),
        "public" => Ok(NetworkDestinationClassV1::ExternalInternet),
        "unspecified" | "loopback" | "private" | "link_local" | "documentation" | "multicast"
        | "broadcast" => Ok(NetworkDestinationClassV1::LocalSinkhole),
        _ => Err(BehaviorEvidenceProjectionErrorV1::InvalidField),
    }
}

fn limitation_codes(entries: &[(bool, &'static str)]) -> Vec<String> {
    let mut codes = entries
        .iter()
        .filter_map(|(present, code)| present.then_some((*code).to_string()))
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    codes
}

fn coverage_v1(
    modality: BehaviorEvidenceModalityV1,
    limitation_codes: Vec<String>,
) -> Result<BehaviorEvidenceCoverageV1, BehaviorEvidenceProjectionErrorV1> {
    if limitation_codes.is_empty() {
        Ok(BehaviorEvidenceCoverageV1::complete(modality))
    } else {
        BehaviorEvidenceCoverageV1::incomplete(modality, limitation_codes)
            .map_err(BehaviorEvidenceProjectionErrorV1::from)
    }
}

fn canonical_object(
    bytes: &[u8],
    maximum_bytes: usize,
) -> Result<Map<String, Value>, BehaviorEvidenceProjectionErrorV1> {
    if bytes.is_empty() {
        return Err(BehaviorEvidenceProjectionErrorV1::Empty);
    }
    if bytes.len() > maximum_bytes {
        return Err(BehaviorEvidenceProjectionErrorV1::LimitExceeded);
    }
    let value: Value = serde_json::from_slice(bytes)
        .map_err(|_| BehaviorEvidenceProjectionErrorV1::InvalidJson)?;
    if serde_json::to_vec(&value).map_err(|_| BehaviorEvidenceProjectionErrorV1::InvalidJson)?
        != bytes
    {
        return Err(BehaviorEvidenceProjectionErrorV1::NonCanonical);
    }
    value
        .as_object()
        .cloned()
        .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidJson)
}

fn require_schema(
    object: &Map<String, Value>,
    expected: &str,
) -> Result<(), BehaviorEvidenceProjectionErrorV1> {
    if string_field(object, "schema_version")? == expected {
        Ok(())
    } else {
        Err(BehaviorEvidenceProjectionErrorV1::InvalidSchema)
    }
}

fn object_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Map<String, Value>, BehaviorEvidenceProjectionErrorV1> {
    object
        .get(key)
        .ok_or(BehaviorEvidenceProjectionErrorV1::MissingField)?
        .as_object()
        .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidField)
}

fn array_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Vec<Value>, BehaviorEvidenceProjectionErrorV1> {
    object
        .get(key)
        .ok_or(BehaviorEvidenceProjectionErrorV1::MissingField)?
        .as_array()
        .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidField)
}

fn string_field<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, BehaviorEvidenceProjectionErrorV1> {
    object
        .get(key)
        .ok_or(BehaviorEvidenceProjectionErrorV1::MissingField)?
        .as_str()
        .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidField)
}

fn bool_field(
    object: &Map<String, Value>,
    key: &str,
) -> Result<bool, BehaviorEvidenceProjectionErrorV1> {
    object
        .get(key)
        .ok_or(BehaviorEvidenceProjectionErrorV1::MissingField)?
        .as_bool()
        .ok_or(BehaviorEvidenceProjectionErrorV1::InvalidField)
}

fn decimal_u64_field(
    object: &Map<String, Value>,
    key: &str,
) -> Result<u64, BehaviorEvidenceProjectionErrorV1> {
    let value = string_field(object, key)?;
    if value.is_empty()
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BehaviorEvidenceProjectionErrorV1::InvalidField);
    }
    value
        .parse()
        .map_err(|_| BehaviorEvidenceProjectionErrorV1::InvalidField)
}

fn require_digest(
    object: &Map<String, Value>,
    key: &str,
    expected: &Sha256Digest,
) -> Result<(), BehaviorEvidenceProjectionErrorV1> {
    let value = string_field(object, key)?;
    Sha256Digest::parse(value.to_string())
        .map_err(|_| BehaviorEvidenceProjectionErrorV1::InvalidField)?;
    if value == expected.as_str() {
        Ok(())
    } else {
        Err(BehaviorEvidenceProjectionErrorV1::BindingMismatch)
    }
}

fn require_length(
    object: &Map<String, Value>,
    key: &str,
    expected: usize,
) -> Result<(), BehaviorEvidenceProjectionErrorV1> {
    let actual = decimal_u64_field(object, key)?;
    let expected =
        u64::try_from(expected).map_err(|_| BehaviorEvidenceProjectionErrorV1::LimitExceeded)?;
    if actual == expected {
        Ok(())
    } else {
        Err(BehaviorEvidenceProjectionErrorV1::BindingMismatch)
    }
}

fn require_count(
    object: &Map<String, Value>,
    key: &str,
    expected: usize,
) -> Result<(), BehaviorEvidenceProjectionErrorV1> {
    require_length(object, key, expected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn digest(label: &str) -> Sha256Digest {
        Sha256Digest::from_bytes(label.as_bytes())
    }

    fn canonical(value: Value) -> Vec<u8> {
        serde_json::to_vec(&value).expect("fixture JSON")
    }

    struct Fixtures {
        artifact: Sha256Digest,
        manifest: Sha256Digest,
        scenario: Sha256Digest,
        process_plan: Sha256Digest,
        host_run_sha256: Sha256Digest,
        root: Vec<u8>,
        process: Vec<u8>,
        file: Vec<u8>,
        network: Vec<u8>,
        host_run: Vec<u8>,
    }

    impl Fixtures {
        fn input(&self) -> ExactDetonationBehaviorProjectionInputV1<'_> {
            ExactDetonationBehaviorProjectionInputV1 {
                artifact_sha256: &self.artifact,
                manifest_sha256: &self.manifest,
                scenario_id: "inert.npm.postinstall.ci_false.v1",
                scenario_sha256: &self.scenario,
                process_plan_sha256: &self.process_plan,
                run_id: "inert-run-1",
                host_execution_run_sha256: &self.host_run_sha256,
                root_receipt_json: &self.root,
                process_evidence_json: &self.process,
                file_evidence_json: &self.file,
                network_evidence_json: &self.network,
                host_execution_run_json: &self.host_run,
            }
        }
    }

    fn fixtures() -> Fixtures {
        let artifact = digest("artifact");
        let manifest = digest("manifest");
        let scenario = digest("scenario");
        let process_plan = digest("process-plan");
        let process = canonical(json!({
            "binding": {"leader_pid": "42", "process_plan_sha256": process_plan},
            "coverage": {
                "continuous_drain": true, "coverage_complete": true,
                "discarded_record_count": "0", "dropped_event_count": "0",
                "evidence_truncated": false, "observation_count": "2",
                "process_sensor_healthy": true
            },
            "observations": [
                {"lifecycle_kind": "exec", "observation_kind": "lifecycle",
                 "source_sequence": "1", "subject_pid": "42",
                 "timestamp_monotonic_nanoseconds": "100"},
                {"lifecycle_kind": "fork", "observation_kind": "lifecycle",
                 "source_sequence": "2", "subject_pid": "43",
                 "timestamp_monotonic_nanoseconds": "200"}
            ],
            "schema_version": ROOT_PROCESS_SCHEMA_V1
        }));
        let process_sha = Sha256Digest::from_bytes(&process);
        let file = canonical(json!({
            "binding": {"process_plan_sha256": process_plan},
            "coverage": {
                "declared_scope_complete": true, "evidence_truncated": false,
                "fanotify_overflow_count": "0", "file_sensor_healthy": true,
                "global_mount_coverage_complete": false, "source_event_count": "2"
            },
            "events": [
                {"access_outcome": "observed", "event_kind": "read",
                 "path_class": "sensitive_credential", "source_sequence": "1",
                 "timestamp_monotonic_nanoseconds": "150"},
                {"access_outcome": "observed", "event_kind": "open",
                 "path_class": "protected_canary", "source_sequence": "2",
                 "timestamp_monotonic_nanoseconds": "250"}
            ],
            "schema_version": ROOT_FILE_SCHEMA_V1
        }));
        let network = canonical(json!({
            "binding": {"process_evidence_sha256": process_sha,
                         "process_plan_sha256": process_plan},
            "coverage": {
                "connect_sendto_intent_coverage_complete": true,
                "discarded_record_count": "0", "dns_intent_coverage_complete": false,
                "dropped_event_count": "0", "evidence_truncated": false,
                "host_frame_correlation_complete": false,
                "http_observation_complete": false, "network_event_count": "2",
                "process_sensor_healthy": true, "target_detail_complete": false
            },
            "events": [
                {"destination_class": "public", "enter_source_sequence": "3",
                 "enter_timestamp_monotonic_nanoseconds": "175", "event_kind": "connect",
                 "target_status": "observed"},
                {"enter_source_sequence": "5",
                 "enter_timestamp_monotonic_nanoseconds": "275", "event_kind": "sendto",
                 "target_status": "unavailable",
                 "target_unavailable_reason": "sendto_destination_detail_unavailable"}
            ],
            "schema_version": ROOT_NETWORK_SCHEMA_V2
        }));
        let process_sha = Sha256Digest::from_bytes(&process);
        let file_sha = Sha256Digest::from_bytes(&file);
        let network_sha = Sha256Digest::from_bytes(&network);
        let root = canonical(json!({
            "claims": {
                "artifact_sha256": artifact, "authoritative_verdict_permitted": false,
                "file_evidence_byte_length": file.len().to_string(),
                "file_evidence_sha256": file_sha, "file_event_count": "2",
                "host_composition_required": true, "network_evidence_byte_length": network.len().to_string(),
                "network_evidence_sha256": network_sha, "network_event_count": "2",
                "process_evidence_byte_length": process.len().to_string(),
                "process_evidence_sha256": process_sha, "process_observation_count": "2",
                "public_network_route_present": false, "raw_arguments_captured": false,
                "raw_exec_paths_captured": false, "raw_file_paths_captured": false,
                "raw_network_addresses_captured": false, "scenario_plan_sha256": scenario,
                "process_plan_sha256": process_plan,
                "schema_version": ROOT_RECEIPT_SCHEMA_V2, "sync_back": false
            },
            "signature_ed25519_hex": "0".repeat(128)
        }));
        let root_sha = Sha256Digest::from_bytes(&root);
        let host_run = canonical(json!({
            "artifact_sha256": artifact, "authoritative_verdict_permitted": false,
            "clone_destroyed": true, "file_evidence_byte_length": file.len().to_string(),
            "file_evidence_sha256": file_sha, "guest_root_receipt_independently_verified": false,
            "host_composition_complete": false, "image_identity_stable": true,
            "network_evidence_byte_length": network.len().to_string(),
            "network_evidence_sha256": network_sha,
            "process_evidence_byte_length": process.len().to_string(),
            "process_evidence_sha256": process_sha, "public_network_route_present": false,
            "root_receipt_byte_length": root.len().to_string(), "root_receipt_sha256": root_sha,
            "schema_version": HOST_EXECUTION_RUN_SCHEMA_V1, "sync_back": false,
            "vm_started": true, "vm_stopped": true
        }));
        let host_run_sha256 = Sha256Digest::from_bytes(&host_run);
        Fixtures {
            artifact,
            manifest,
            scenario,
            process_plan,
            host_run_sha256,
            root,
            process,
            file,
            network,
            host_run,
        }
    }

    #[test]
    fn projects_stable_typed_timeline_without_raw_evidence() {
        let fixtures = fixtures();
        let bundle =
            project_exact_detonation_behavior_v1(fixtures.input()).expect("project inert evidence");
        assert!(!bundle.is_complete());
        assert_eq!(bundle.events().len(), 6);
        assert!(matches!(
            bundle.events()[0].signal(),
            BehaviorEvidenceSignalV1::Process {
                action: ProcessActionV1::PackageTrigger,
                trigger: Some(PackageTriggerV1::NpmLifecycle)
            }
        ));
        assert!(matches!(
            bundle.events()[1].signal(),
            BehaviorEvidenceSignalV1::Filesystem {
                operation: FileOperationV1::Read,
                target: FileTargetClassV1::CredentialFile
            }
        ));
        assert!(matches!(
            bundle.events()[2].signal(),
            BehaviorEvidenceSignalV1::Network {
                action: NetworkActionV1::Connect,
                destination: NetworkDestinationClassV1::ExternalInternet
            }
        ));
        assert!(matches!(
            bundle.events()[4].signal(),
            BehaviorEvidenceSignalV1::Canary {
                action: CanaryActionV1::Read,
                canary: CanaryClassV1::NpmToken
            }
        ));
        assert!(matches!(
            bundle.events()[5].signal(),
            BehaviorEvidenceSignalV1::Network {
                action: NetworkActionV1::Send,
                destination: NetworkDestinationClassV1::Unavailable
            }
        ));
        assert!(bundle.coverage().iter().any(|item| {
            item.modality() == BehaviorEvidenceModalityV1::Network
                && item
                    .limitation_codes()
                    .iter()
                    .any(|code| code == "network_target_detail_incomplete")
        }));
        assert!(bundle.events().iter().all(|event| {
            event.source_receipt_sha256() == &Sha256Digest::from_bytes(&fixtures.root)
                && event.untrusted_detail().is_none()
        }));
        assert!(bundle.coverage().iter().all(|item| {
            item.limitation_codes()
                .iter()
                .any(|code| code == "independent_host_composition_missing")
        }));
    }

    #[test]
    fn rejects_unbound_host_execution_run_digest() {
        let fixtures = fixtures();
        let wrong = digest("wrong-host-run");
        let mut input = fixtures.input();
        input.host_execution_run_sha256 = &wrong;
        assert_eq!(
            project_exact_detonation_behavior_v1(input),
            Err(BehaviorEvidenceProjectionErrorV1::BindingMismatch)
        );
    }

    #[test]
    fn rejects_unbound_process_plan_digest() {
        let fixtures = fixtures();
        let wrong = digest("wrong-process-plan");
        let mut input = fixtures.input();
        input.process_plan_sha256 = &wrong;
        assert_eq!(
            project_exact_detonation_behavior_v1(input),
            Err(BehaviorEvidenceProjectionErrorV1::BindingMismatch)
        );
    }
}
