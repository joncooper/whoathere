use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::{Ecosystem, NormalizationLimits, Sha256Digest};
use whoathere_detector::ArtifactFindingCategory;
use whoathere_runner::{
    decode_and_validate_retained_exact_artifact_report_input_v1,
    decode_and_validate_retained_exact_artifact_report_v1, inspect_exact_artifact_v1,
    read_and_validate_retained_exact_artifact_report_v1, ExactArtifactDispositionV1,
    ExactArtifactFindingKindV1, ExactArtifactInspectionRequestV1, ExactArtifactObservationV1,
    ExactArtifactThreatClassV1, RetainedExactArtifactReportPostureV1,
    MAX_EXACT_ARTIFACT_RETAINED_REPORT_BYTES_V1,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempRoot(std::path::PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create isolated retained-report root");
        Self(path)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn npm_tgz(name: &str, source: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, bytes) in [
        (
            "package/package.json",
            format!(
                r#"{{"name":"{name}","version":"1.0.0","scripts":{{"postinstall":"node index.js"}},"main":"index.js"}}"#
            )
            .into_bytes(),
        ),
        ("package/index.js", source.to_vec()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, path, Cursor::new(bytes))
            .expect("append retained-report fixture member");
    }
    archive
        .into_inner()
        .expect("finish retained-report tar")
        .finish()
        .expect("finish retained-report gzip")
}

fn saved_report(
    root: &TempRoot,
    label: &str,
    source: &[u8],
) -> (std::path::PathBuf, String, Value) {
    let artifact = root.path().join(format!("{label}-1.0.0.tgz"));
    let quarantine = root.path().join(format!("{label}-state"));
    std::fs::write(&artifact, npm_tgz(label, source)).expect("write retained-report artifact");
    let report = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &artifact,
            quarantine_root: &quarantine,
            ecosystem: Some(Ecosystem::Npm),
            acquired_at: "2026-07-15T00:00:00Z",
            ai_requested: false,
            ai_provider: None,
            behavior_observation_requested: false,
            detonation_requested: false,
            normalization_limits: NormalizationLimits::default(),
        },
        None,
        None,
    )
    .expect("produce retained exact-artifact report");
    let report_bytes = report
        .to_pretty_json()
        .expect("serialize retained exact-artifact report")
        .into_bytes();
    let report_path = root.path().join(format!("{label}-inspection.json"));
    std::fs::write(&report_path, &report_bytes).expect("save retained report");
    let report_sha256 = Sha256Digest::from_bytes(&report_bytes).to_string();
    let report_value = serde_json::from_slice(&report_bytes).expect("parse retained report value");

    std::fs::remove_file(&artifact).expect("delete original artifact before retained rendering");
    std::fs::remove_dir_all(&quarantine)
        .expect("delete quarantine state before retained rendering");
    (report_path, report_sha256, report_value)
}

fn reject_value(mutator: impl FnOnce(&mut Value), original: &Value) {
    let mut value = original.clone();
    mutator(&mut value);
    let bytes = serde_json::to_vec(&value).expect("serialize retained-report mutation");
    let sha256 = Sha256Digest::from_bytes(&bytes).to_string();
    let error = decode_and_validate_retained_exact_artifact_report_v1(&bytes, &sha256)
        .expect_err("retained-report mutation must be rejected");
    assert!(matches!(
        error.reason_code(),
        "retained_report_json_invalid"
            | "retained_report_schema_unsupported"
            | "retained_report_semantics_invalid"
    ));
}

fn sanitized_projection(mut report: Value) -> Value {
    let deterministic_receipt = report["stages"]
        .as_array()
        .expect("report stages")
        .iter()
        .find(|stage| stage["stage"] == "deterministic_analysis")
        .and_then(|stage| stage["result_sha256"].as_str())
        .expect("deterministic receipt")
        .to_string();

    let top = report.as_object_mut().expect("report object");
    top.insert("sanitized_projection".to_string(), Value::Bool(true));
    top.insert(
        "raw_source_or_telemetry_included".to_string(),
        Value::Bool(false),
    );
    let identity = top
        .get_mut("identity")
        .and_then(Value::as_object_mut)
        .expect("report identity");
    for omitted in [
        "cas_object_key",
        "source_coordinate",
        "package_name",
        "package_version",
    ] {
        identity.remove(omitted);
    }
    let plan = top
        .get_mut("scenario_plan")
        .and_then(Value::as_object_mut)
        .expect("scenario plan");
    let intent_count = plan
        .remove("intents")
        .and_then(|intents| intents.as_array().map(Vec::len))
        .expect("scenario intents");
    plan.insert("intent_count".to_string(), Value::from(intent_count));
    for observation in top
        .get_mut("observations")
        .and_then(Value::as_array_mut)
        .expect("observations")
    {
        let evidence = observation
            .get_mut("evidence")
            .and_then(Value::as_object_mut)
            .expect("static evidence");
        evidence.insert(
            "source_receipt_sha256".to_string(),
            Value::String(deterministic_receipt.clone()),
        );
        evidence.insert("package_source_included".to_string(), Value::Bool(false));
        evidence.insert("selected_bytes_included".to_string(), Value::Bool(false));
    }
    report
}

fn decode_projection(value: &Value) -> whoathere_runner::ValidatedRetainedExactArtifactReportV1 {
    let bytes = serde_json::to_vec(value).expect("serialize sanitized projection");
    let digest = Sha256Digest::from_bytes(&bytes).to_string();
    decode_and_validate_retained_exact_artifact_report_input_v1(&bytes, &digest)
        .expect("validate sanitized projection")
}

fn reject_projection(mutator: impl FnOnce(&mut Value), original: &Value) {
    let mut value = original.clone();
    mutator(&mut value);
    let bytes = serde_json::to_vec(&value).expect("serialize projection mutation");
    let digest = Sha256Digest::from_bytes(&bytes).to_string();
    let error = decode_and_validate_retained_exact_artifact_report_input_v1(&bytes, &digest)
        .expect_err("projection mutation must be rejected");
    assert!(matches!(
        error.reason_code(),
        "retained_report_json_invalid"
            | "retained_report_schema_unsupported"
            | "retained_report_semantics_invalid"
    ));
}

fn coherently_downgrade_first_allowlisted_projection_finding(value: &mut Value) {
    let observations = value["observations"]
        .as_array_mut()
        .expect("projection observations");
    let index = observations
        .iter()
        .position(|observation| {
            observation["behavior_detection_eligible"] == Value::Bool(true)
                && observation["finding_kind"]["kind"]
                    != Value::String("environment_exfiltration_capability".to_string())
        })
        .expect("current allowlisted projection finding");
    let mut core_value = observations[index].clone();
    let evidence = core_value["evidence"]
        .as_object_mut()
        .expect("projected static evidence");
    let source_receipt = evidence
        .remove("source_receipt_sha256")
        .expect("projected source receipt");
    let package_source_included = evidence
        .remove("package_source_included")
        .expect("projected package-source flag");
    let selected_bytes_included = evidence
        .remove("selected_bytes_included")
        .expect("projected selected-bytes flag");
    let original: ExactArtifactObservationV1 =
        serde_json::from_value(core_value).expect("decode projected observation core");
    let downgraded = ExactArtifactObservationV1::new(
        original.source,
        original.threat_class,
        original.finding_kind,
        original.confidence,
        original.artifact_sha256,
        original.manifest_sha256,
        original.evidence,
        original.coverage,
        original.coverage_gap_codes,
        false,
    )
    .expect("recompute coherently downgraded observation");
    let mut downgraded_value = serde_json::to_value(downgraded).expect("encode downgraded core");
    let downgraded_evidence = downgraded_value["evidence"]
        .as_object_mut()
        .expect("downgraded evidence object");
    downgraded_evidence.insert("source_receipt_sha256".to_string(), source_receipt);
    downgraded_evidence.insert(
        "package_source_included".to_string(),
        package_source_included,
    );
    downgraded_evidence.insert(
        "selected_bytes_included".to_string(),
        selected_bytes_included,
    );
    observations[index] = downgraded_value;
    observations.sort_by(|left, right| {
        left["observation_sha256"]
            .as_str()
            .cmp(&right["observation_sha256"].as_str())
    });
    let count = observations
        .iter()
        .filter(|observation| observation["behavior_detection_eligible"] == Value::Bool(true))
        .count();
    value["behavior_detection_count"] = Value::from(count);
    if count == 0 {
        value["status"] = Value::String("inconclusive".to_string());
        value["verdict"] = Value::String("inconclusive".to_string());
        value["exit_code"] = Value::from(22_i64);
    }
}

#[test]
fn retained_report_renders_from_validated_bytes_after_artifact_and_state_are_deleted() {
    let root = TempRoot::new("whoathere-retained-report-artifact-free");
    let (positive_path, positive_sha256, _) = saved_report(
        &root,
        "retained-static-positive",
        br#"const token = process.env.NPM_TOKEN;
const fs = require('node:fs');
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
const https = require('node:https');
https.request({method: 'POST'});
require('node:child_process').spawn('printf', [token, config.length]);
"#,
    );
    let positive =
        read_and_validate_retained_exact_artifact_report_v1(&positive_path, &positive_sha256)
            .expect("validate retained static-positive report");
    assert_eq!(positive.status, ExactArtifactDispositionV1::Findings);
    assert_eq!(positive.exit_code, 20);
    assert!(positive.behavior_detection_count > 0);

    let (review_path, review_sha256, _) =
        saved_report(&root, "retained-review", b"module.exports = 'inert';\n");
    let review = read_and_validate_retained_exact_artifact_report_v1(&review_path, &review_sha256)
        .expect("validate retained review report");
    assert_eq!(review.status, ExactArtifactDispositionV1::Inconclusive);
    assert_eq!(review.exit_code, 22);
    assert_eq!(review.behavior_detection_count, 0);
}

#[test]
fn retained_report_rejects_digest_json_schema_binding_verdict_and_authority_mutations() {
    let root = TempRoot::new("whoathere-retained-report-mutations");
    let (report_path, report_sha256, report) = saved_report(
        &root,
        "retained-mutation-positive",
        br#"const token = process.env.NPM_TOKEN;
const fs = require('node:fs');
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
const https = require('node:https');
https.request({method: 'POST'});
require('node:child_process').spawn('printf', [token, config.length]);
"#,
    );
    let bytes = std::fs::read(&report_path).expect("read saved retained report");

    let wrong_digest = Sha256Digest::from_bytes(b"different report").to_string();
    assert_eq!(
        decode_and_validate_retained_exact_artifact_report_v1(&bytes, &wrong_digest)
            .expect_err("wrong retained digest")
            .reason_code(),
        "retained_report_sha256_mismatch"
    );
    let mut whitespace_mutation = bytes.clone();
    whitespace_mutation.push(b'\n');
    assert_eq!(
        decode_and_validate_retained_exact_artifact_report_v1(&whitespace_mutation, &report_sha256)
            .expect_err("whitespace changes exact retained bytes")
            .reason_code(),
        "retained_report_sha256_mismatch"
    );
    let truncated = &bytes[..bytes.len() / 2];
    let truncated_sha256 = Sha256Digest::from_bytes(truncated).to_string();
    assert_eq!(
        decode_and_validate_retained_exact_artifact_report_v1(truncated, &truncated_sha256)
            .expect_err("truncated retained JSON")
            .reason_code(),
        "retained_report_json_invalid"
    );
    let trailing = b"{} trailing";
    let trailing_sha256 = Sha256Digest::from_bytes(trailing).to_string();
    assert_eq!(
        decode_and_validate_retained_exact_artifact_report_v1(trailing, &trailing_sha256)
            .expect_err("trailing retained JSON data")
            .reason_code(),
        "retained_report_json_invalid"
    );
    let duplicate = b"{\"schema_version\":\"whoathere.exact_artifact_inspection.v1\",\"schema_version\":\"whoathere.exact_artifact_inspection.v1\"}";
    let duplicate_sha256 = Sha256Digest::from_bytes(duplicate).to_string();
    assert_eq!(
        decode_and_validate_retained_exact_artifact_report_v1(duplicate, &duplicate_sha256)
            .expect_err("duplicate retained JSON field")
            .reason_code(),
        "retained_report_json_invalid"
    );

    reject_value(
        |value| {
            value["unknown_top_level"] = Value::Bool(true);
        },
        &report,
    );
    reject_value(
        |value| {
            value["identity"]["unknown_nested"] = Value::Bool(true);
        },
        &report,
    );
    reject_value(
        |value| {
            value["scenario_plan"]["intents"][0]["kind"]["unknown_nested"] = Value::Bool(true);
        },
        &report,
    );
    reject_value(
        |value| {
            value["schema_version"] = Value::String("whoathere.future.v9".to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["status"] = Value::String("future_status".to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["identity"]["artifact_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other artifact").to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["stages"][0]["manifest_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other manifest").to_string());
        },
        &report,
    );
    for (stage_index, impossible_status) in [
        (0, "incomplete"),
        (1, "findings"),
        (2, "not_requested"),
        (3, "not_requested"),
        (4, "findings"),
        (5, "findings"),
        (6, "findings"),
    ] {
        reject_value(
            |value| {
                value["stages"][stage_index]["status"] =
                    Value::String(impossible_status.to_string());
            },
            &report,
        );
    }
    reject_value(
        |value| {
            value["stages"][4]["request_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"forged request").to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["stages"][3]["reason_codes"] =
                serde_json::json!(["exact_artifact_ai_not_requested"]);
        },
        &report,
    );
    reject_value(
        |value| {
            value["scenario_plan"]["reason_codes"] = Value::Array(
                (0..129)
                    .map(|index| Value::String(format!("retained_plan_reason_{index:03}")))
                    .collect(),
            );
        },
        &report,
    );
    reject_value(
        |value| {
            value["stages"][3]["status"] = Value::String("complete".to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["scenario_plan"]["plan_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other plan").to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["scenario_plan"]["intents"][0]["intent_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other intent").to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["observations"][0]["observation_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other observation").to_string());
        },
        &report,
    );
    reject_value(
        |value| {
            value["behavior_detection_count"] = Value::from(0_u64);
        },
        &report,
    );
    reject_value(
        |value| {
            value["verdict"] = Value::String("inconclusive".to_string());
            value["exit_code"] = Value::from(22);
        },
        &report,
    );
    for field in ["admission_authority", "observed_clean", "sync_back_enabled"] {
        reject_value(
            |value| {
                value[field] = Value::Bool(true);
            },
            &report,
        );
    }
}

#[test]
fn retained_report_reader_rejects_nonregular_empty_and_oversized_inputs() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("whoathere-retained-report-file-boundary");
    let expected = Sha256Digest::from_bytes(b"irrelevant").to_string();

    let empty = root.path().join("empty.json");
    std::fs::write(&empty, b"").expect("write empty retained report");
    assert_eq!(
        read_and_validate_retained_exact_artifact_report_v1(&empty, &expected)
            .expect_err("empty retained report")
            .reason_code(),
        "retained_report_size_out_of_bounds"
    );

    let directory = root.path().join("directory.json");
    std::fs::create_dir(&directory).expect("create retained-report directory control");
    assert_eq!(
        read_and_validate_retained_exact_artifact_report_v1(&directory, &expected)
            .expect_err("directory retained report")
            .reason_code(),
        "retained_report_path_not_regular_file"
    );

    let target = root.path().join("target.json");
    std::fs::write(&target, b"{}").expect("write symlink target");
    let link = root.path().join("link.json");
    symlink(&target, &link).expect("create retained-report symlink control");
    assert_eq!(
        read_and_validate_retained_exact_artifact_report_v1(&link, &expected)
            .expect_err("symlink retained report")
            .reason_code(),
        "retained_report_path_not_regular_file"
    );

    let oversized = root.path().join("oversized.json");
    let file = std::fs::File::create(&oversized).expect("create oversized retained report");
    file.set_len((MAX_EXACT_ARTIFACT_RETAINED_REPORT_BYTES_V1 + 1) as u64)
        .expect("size oversized retained report");
    assert_eq!(
        read_and_validate_retained_exact_artifact_report_v1(&oversized, &expected)
            .expect_err("oversized retained report")
            .reason_code(),
        "retained_report_size_out_of_bounds"
    );
}

#[test]
fn retained_report_sanitized_projection_is_disjoint_and_rederives_current_policy() {
    let root = TempRoot::new("whoathere-retained-projection");
    let (_, _, full) = saved_report(
        &root,
        "retained-projection-positive",
        br#"const token = process.env.NPM_TOKEN;
const fs = require('node:fs');
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
const https = require('node:https');
https.request({method: 'POST'});
require('node:child_process').spawn('printf', [token, config.length]);
"#,
    );
    let projection = sanitized_projection(full.clone());
    let validated = decode_projection(&projection);
    assert_eq!(
        validated.posture(),
        RetainedExactArtifactReportPostureV1::SanitizedProjectionV1
    );
    assert_eq!(
        validated.report().status,
        ExactArtifactDispositionV1::Findings
    );
    assert_eq!(validated.report().exit_code, 20);
    assert!(validated.report().behavior_detection_count > 0);

    let projection_bytes = serde_json::to_vec(&projection).expect("serialize projection");
    let projection_digest = Sha256Digest::from_bytes(&projection_bytes).to_string();
    assert_eq!(
        decode_and_validate_retained_exact_artifact_report_v1(
            &projection_bytes,
            &projection_digest
        )
        .expect_err("complete decoder must remain closed")
        .reason_code(),
        "retained_report_json_invalid"
    );

    let full_bytes = serde_json::to_vec(&full).expect("serialize complete report");
    let full_digest = Sha256Digest::from_bytes(&full_bytes).to_string();
    let complete =
        decode_and_validate_retained_exact_artifact_report_input_v1(&full_bytes, &full_digest)
            .expect("combined decoder preserves complete V1");
    assert_eq!(
        complete.posture(),
        RetainedExactArtifactReportPostureV1::CompleteV1
    );

    let legacy_source: ExactArtifactObservationV1 = full["observations"]
        .as_array()
        .expect("full observations")
        .first()
        .cloned()
        .map(serde_json::from_value)
        .expect("static finding exists")
        .expect("decode static finding");
    let legacy_only = ExactArtifactObservationV1::new(
        legacy_source.source,
        ExactArtifactThreatClassV1::NetworkAndExfiltration,
        ExactArtifactFindingKindV1::DeterministicStatic(
            ArtifactFindingCategory::EnvironmentExfiltrationCapability,
        ),
        legacy_source.confidence,
        legacy_source.artifact_sha256,
        legacy_source.manifest_sha256,
        legacy_source.evidence,
        legacy_source.coverage,
        legacy_source.coverage_gap_codes,
        true,
    )
    .expect("construct historically eligible generic environment finding");
    let mut legacy_full = full;
    legacy_full["observations"] = serde_json::json!([legacy_only]);
    legacy_full["stages"][2]["observation_count"] = Value::from(1_u64);
    legacy_full["behavior_detection_count"] = Value::from(1_u64);
    legacy_full["status"] = Value::String("findings".to_string());
    legacy_full["verdict"] = Value::String("malicious".to_string());
    legacy_full["exit_code"] = Value::from(20_i64);
    let legacy_projection = sanitized_projection(legacy_full);
    let current = decode_projection(&legacy_projection);
    assert_eq!(
        current.report().status,
        ExactArtifactDispositionV1::Inconclusive
    );
    assert_eq!(current.report().exit_code, 22);
    assert_eq!(current.report().behavior_detection_count, 0);
    assert!(!current.report().observations[0].behavior_detection_eligible);
}

#[test]
fn retained_report_sanitized_projection_rejects_shape_binding_receipt_and_authority_mutations() {
    let root = TempRoot::new("whoathere-retained-projection-mutations");
    let (_, _, full) = saved_report(
        &root,
        "retained-projection-mutations",
        br#"const token = process.env.NPM_TOKEN;
const fs = require('node:fs');
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
require('node:https').request({method: 'POST'});
require('node:child_process').spawn('printf', [token, config.length]);
"#,
    );
    let projection = sanitized_projection(full);
    decode_projection(&projection);

    reject_projection(
        |value| value["unknown_projection_field"] = Value::Bool(true),
        &projection,
    );
    reject_projection(
        |value| {
            value
                .as_object_mut()
                .expect("projection object")
                .remove("sanitized_projection");
        },
        &projection,
    );
    reject_projection(
        |value| value["expected_label"] = Value::String("malicious".to_string()),
        &projection,
    );
    reject_projection(
        |value| value["identity"]["unknown_identity_field"] = Value::Bool(true),
        &projection,
    );
    reject_projection(
        |value| value["identity"]["package_name"] = Value::String("trusted-name".to_string()),
        &projection,
    );
    reject_projection(
        |value| value["observations"][0]["evidence"]["unknown_evidence_field"] = Value::Bool(true),
        &projection,
    );
    for field in [
        "sanitized_projection",
        "admission_authority",
        "observed_clean",
        "sync_back_enabled",
    ] {
        reject_projection(
            |value| value[field] = Value::Bool(!value[field].as_bool().unwrap()),
            &projection,
        );
    }
    reject_projection(
        |value| value["raw_source_or_telemetry_included"] = Value::Bool(true),
        &projection,
    );
    reject_projection(
        |value| value["observations"][0]["evidence"]["package_source_included"] = Value::Bool(true),
        &projection,
    );
    reject_projection(
        |value| value["observations"][0]["evidence"]["selected_bytes_included"] = Value::Bool(true),
        &projection,
    );
    reject_projection(
        |value| {
            value["observations"][0]["evidence"]["source_receipt_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other source receipt").to_string())
        },
        &projection,
    );
    reject_projection(
        |value| {
            value["observations"][0]["observation_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other observation").to_string())
        },
        &projection,
    );
    reject_projection(
        |value| {
            let current = value["observations"][0]["behavior_detection_eligible"]
                .as_bool()
                .expect("eligibility bool");
            value["observations"][0]["behavior_detection_eligible"] = Value::Bool(!current);
        },
        &projection,
    );
    reject_projection(
        coherently_downgrade_first_allowlisted_projection_finding,
        &projection,
    );
    reject_projection(
        |value| {
            value["observations"][0]["evidence"]["location"]["range"]["end_byte"] =
                Value::from(9_999_999_u64)
        },
        &projection,
    );
    reject_projection(
        |value| {
            value["identity"]["artifact_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other artifact").to_string())
        },
        &projection,
    );
    reject_projection(
        |value| value["scenario_plan"]["intent_count"] = Value::from(129_u64),
        &projection,
    );
    reject_projection(
        |value| {
            value["stages"][3]["result_sha256"] =
                Value::String(Sha256Digest::from_bytes(b"other plan").to_string())
        },
        &projection,
    );
    reject_projection(
        |value| value["behavior_detection_count"] = Value::from(0_u64),
        &projection,
    );
    reject_projection(
        |value| {
            value["verdict"] = Value::String("inconclusive".to_string());
            value["exit_code"] = Value::from(22_i64);
        },
        &projection,
    );
    reject_projection(
        |value| value["observations"][0]["source"] = Value::String("ai_behavioral".to_string()),
        &projection,
    );
}
