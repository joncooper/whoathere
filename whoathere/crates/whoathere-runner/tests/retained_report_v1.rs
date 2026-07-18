use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::Value;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::{Ecosystem, NormalizationLimits, Sha256Digest};
use whoathere_runner::{
    decode_and_validate_retained_exact_artifact_report_v1, inspect_exact_artifact_v1,
    read_and_validate_retained_exact_artifact_report_v1, ExactArtifactDispositionV1,
    ExactArtifactInspectionRequestV1, MAX_EXACT_ARTIFACT_RETAINED_REPORT_BYTES_V1,
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
