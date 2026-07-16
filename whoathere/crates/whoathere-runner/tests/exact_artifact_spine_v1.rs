use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::{
    AcquisitionMethod, ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_cache::VerifiedArtifactLease;
use whoathere_detector::{
    ArtifactFindingCategory, ArtifactReviewFindingCategoryV2, ArtifactStaticAnalysis,
    EvidenceRange, FindingLocation,
};
use whoathere_detonation::{ArtifactScenarioKindV1, SdistScenarioKindV1};
use whoathere_runner::{
    canonical_utc_timestamp_from_unix_seconds_v1, inspect_exact_artifact_v1,
    BoundOptionalEvidenceOutcomeV1, BoundOptionalEvidenceV1, ExactArtifactAdapterRequestV1,
    ExactArtifactAiAdapterV1, ExactArtifactDetonationAdapterV1, ExactArtifactDispositionV1,
    ExactArtifactEvidenceReferenceV1, ExactArtifactFindingKindV1, ExactArtifactInspectionRequestV1,
    ExactArtifactObservationConfidenceV1, ExactArtifactObservationCoverageV1,
    ExactArtifactObservationSourceV1, ExactArtifactObservationV1, ExactArtifactOptionalResultV1,
    ExactArtifactScenarioKindV1, ExactArtifactScenarioPlanV1, ExactArtifactStageStatusV1,
    ExactArtifactThreatClassV1, OptionalAdapterErrorV1, PreparedArtifact,
};
use zip::write::SimpleFileOptions;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

#[test]
fn canonical_timestamp_formatter_covers_epoch_and_leap_day() {
    assert_eq!(
        canonical_utc_timestamp_from_unix_seconds_v1(0).expect("epoch timestamp"),
        "1970-01-01T00:00:00Z"
    );
    assert_eq!(
        canonical_utc_timestamp_from_unix_seconds_v1(1_709_251_200)
            .expect("2024 leap-day boundary"),
        "2024-03-01T00:00:00Z"
    );
}

struct TempRoot(std::path::PathBuf);

impl TempRoot {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "{label}-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("create isolated test root");
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

fn append_tar_file(archive: &mut tar::Builder<GzEncoder<Vec<u8>>>, path: &str, bytes: &[u8]) {
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
        .expect("append inert fixture member");
}

fn npm_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "package/package.json",
        br#"{"name":"spine-inert","version":"1.0.0","scripts":{"postinstall":"node index.js"},"main":"index.js","exports":"./index.js","bin":{"spine-inert":"cli.js"}}"#,
    );
    append_tar_file(
        &mut archive,
        "package/index.js",
        b"module.exports = 'inert';\n",
    );
    append_tar_file(
        &mut archive,
        "package/cli.js",
        b"#!/usr/bin/env node\nprocess.exit(0);\n",
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

const NPM_CAPABILITY_FIXTURE: &[u8] = br#"const fs = require('node:fs');
const token = process.env.NPM_TOKEN;
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
const https = require('node:https');
https.request({method: 'POST'});
const child = require('node:child_process');
child.spawn('printf', [token, config.length]);
"#;

fn npm_capability_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "package/package.json",
        br#"{"name":"spine-capability","version":"1.0.0","scripts":{"postinstall":"node boot.js"},"main":"boot.js"}"#,
    );
    append_tar_file(
        &mut archive,
        "package/boot.js",
        b"require('./lib/collect');\n",
    );
    append_tar_file(
        &mut archive,
        "package/lib/collect.js",
        NPM_CAPABILITY_FIXTURE,
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn npm_network_context_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "package/package.json",
        br#"{"name":"spine-network-context","version":"1.0.0","scripts":{"postinstall":"node index.js"},"main":"index.js"}"#,
    );
    append_tar_file(
        &mut archive,
        "package/index.js",
        b"const https = require('node:https');\nhttps.request('https://example.invalid/status');\n",
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn wheel_zip() -> Vec<u8> {
    const METADATA: &[u8] = b"Metadata-Version: 2.3\nName: spine-wheel\nVersion: 1.0.0\n";
    const WHEEL: &[u8] = b"Wheel-Version: 1.0\nGenerator: whoathere-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
    const ENTRY_POINTS: &[u8] = b"[console_scripts]\nspine-wheel = spine_wheel.cli:main\n";
    const INIT: &[u8] = b"VALUE = 'inert'\n";
    const CLI: &[u8] = b"def main():\n    return 0\n";
    const PTH: &[u8] = b"import spine_wheel\n";
    let dist_info = "spine_wheel-1.0.0.dist-info";
    let mut members = vec![
        (format!("{dist_info}/METADATA"), METADATA),
        (format!("{dist_info}/WHEEL"), WHEEL),
        (format!("{dist_info}/entry_points.txt"), ENTRY_POINTS),
        ("spine_wheel/__init__.py".to_string(), INIT),
        ("spine_wheel/cli.py".to_string(), CLI),
        ("spine_wheel.pth".to_string(), PTH),
    ];
    let record_path = format!("{dist_info}/RECORD");
    let mut record = String::new();
    for (path, bytes) in &members {
        record.push_str(&format!(
            "{path},{},{}\n",
            wheel_record_hash(bytes),
            bytes.len()
        ));
    }
    record.push_str(&format!("{record_path},,\n"));
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in members.drain(..) {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start wheel member");
        writer.write_all(bytes).expect("write wheel member");
    }
    writer
        .start_file(record_path, SimpleFileOptions::default())
        .expect("start RECORD");
    writer.write_all(record.as_bytes()).expect("write RECORD");
    writer.finish().expect("finish wheel").into_inner()
}

fn sdist_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "spine-sdist-1.0.0/PKG-INFO",
        b"Metadata-Version: 2.3\nName: spine-sdist\nVersion: 1.0.0\n",
    );
    append_tar_file(
        &mut archive,
        "spine-sdist-1.0.0/pyproject.toml",
        b"[build-system]\nrequires = []\nbuild-backend = \"setuptools.build_meta\"\n\n[project]\nname = \"spine-sdist\"\nversion = \"1.0.0\"\n",
    );
    append_tar_file(
        &mut archive,
        "spine-sdist-1.0.0/src/spine_sdist/__init__.py",
        b"VALUE = 'inert'\n",
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn legacy_sdist_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, bytes) in legacy_sdist_members() {
        append_tar_file(&mut archive, path, bytes);
    }
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn legacy_sdist_zip() -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in legacy_sdist_members() {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start legacy sdist member");
        writer.write_all(bytes).expect("write legacy sdist member");
    }
    writer
        .finish()
        .expect("finish legacy sdist zip")
        .into_inner()
}

fn legacy_sdist_members() -> [(&'static str, &'static [u8]); 3] {
    [
        (
            "legacy-spine-1.0.0/PKG-INFO",
            b"Metadata-Version: 2.3\nName: legacy-spine\nVersion: 1.0.0\n",
        ),
        (
            "legacy-spine-1.0.0/setup.py",
            b"from setuptools import setup\nsetup()\n",
        ),
        (
            "legacy-spine-1.0.0/legacy_spine/__init__.py",
            b"VALUE = 'inert'\n",
        ),
    ]
}

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest_hex = whoathere_hash::sha256_hex(bytes);
    let digest_bytes = digest_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is ASCII"), 16)
                .expect("valid hex")
        })
        .collect::<Vec<_>>();
    format!("sha256={}", base64_url_no_pad(&digest_bytes))
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::new();
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }
    output
}

fn inspect(
    root: &TempRoot,
    filename: &str,
    bytes: &[u8],
    ecosystem: Option<Ecosystem>,
    requests: (bool, bool),
    adapters: (
        Option<&dyn ExactArtifactAiAdapterV1>,
        Option<&dyn ExactArtifactDetonationAdapterV1>,
    ),
) -> whoathere_runner::ExactArtifactInspectionReportV1 {
    let (ai_requested, detonation_requested) = requests;
    let (ai, detonation) = adapters;
    let artifact_path = root.path().join(filename);
    std::fs::write(&artifact_path, bytes).expect("write inert artifact fixture");
    let cas = root.path().join("cas");
    inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &artifact_path,
            quarantine_root: &cas,
            ecosystem,
            acquired_at: "2026-07-15T00:00:00Z",
            ai_requested,
            ai_provider: ai_requested.then_some("mock-ai"),
            detonation_requested,
            normalization_limits: NormalizationLimits::default(),
        },
        ai,
        detonation,
    )
    .expect("inspect inert artifact")
}

#[test]
fn npm_exact_bytes_bind_static_analysis_and_all_declared_trigger_intents() {
    let root = TempRoot::new("whoathere-exact-spine-npm");
    let bytes = npm_tgz();
    let report = inspect(
        &root,
        "spine-inert-1.0.0.tgz",
        &bytes,
        None,
        (true, true),
        (None, None),
    );

    assert_eq!(
        report.identity.artifact_sha256,
        Sha256Digest::from_bytes(&bytes).to_string()
    );
    assert_eq!(report.identity.ecosystem, Ecosystem::Npm);
    assert_eq!(report.identity.source_type, ArtifactSourceType::LocalFile);
    assert_eq!(
        report.identity.acquisition_method,
        AcquisitionMethod::LocalFileImport
    );
    assert!(report
        .identity
        .source_coordinate
        .starts_with("local-file:sha256:"));
    assert!(!report.identity.source_coordinate.contains("approved"));
    assert_eq!(report.identity.package_name.as_deref(), Some("spine-inert"));
    assert_eq!(report.scenario_plan.intents.len(), 4);
    assert!(report.scenario_plan.intents.iter().any(|intent| matches!(
        intent.kind,
        ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmLocalTarballInstall { .. })
    )));
    assert!(report.scenario_plan.intents.iter().any(|intent| matches!(
        intent.kind,
        ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmMainOrExportProbe)
    )));
    assert!(report.scenario_plan.intents.iter().any(|intent| matches!(
        intent.kind,
        ExactArtifactScenarioKindV1::Npm(ArtifactScenarioKindV1::NpmBinProbe)
    )));
    assert!(report.stages.iter().any(|stage| {
        stage.stage == "ai_review" && stage.status == ExactArtifactStageStatusV1::Unavailable
    }));
    assert!(report.stages.iter().any(|stage| {
        stage.stage == "detonation" && stage.status == ExactArtifactStageStatusV1::Unavailable
    }));
    assert!(!report.admission_authority);
    assert!(!report.observed_clean);
    assert!(!report.sync_back_enabled);
}

#[test]
fn deterministic_package_detection_survives_as_an_exact_cited_product_observation() {
    let root = TempRoot::new("whoathere-exact-spine-deterministic-observation");
    let bytes = npm_capability_tgz();
    let report = inspect(
        &root,
        "spine-capability-1.0.0.tgz",
        &bytes,
        Some(Ecosystem::Npm),
        (false, false),
        (None, None),
    );

    let observation = report
        .observations
        .iter()
        .find(|observation| {
            observation.finding_kind
                == ExactArtifactFindingKindV1::DeterministicStatic(
                    ArtifactFindingCategory::CredentialExfiltrationCapability,
                )
        })
        .expect("credential exfiltration capability must survive product fusion");
    assert_eq!(
        observation.source,
        ExactArtifactObservationSourceV1::DeterministicStatic
    );
    assert_eq!(
        observation.artifact_sha256.as_str(),
        report.identity.artifact_sha256
    );
    assert_eq!(
        observation.manifest_sha256.as_str(),
        report.identity.manifest_sha256
    );
    assert!(observation.behavior_detection_eligible);
    let ExactArtifactEvidenceReferenceV1::DeterministicStatic {
        evidence_sha256,
        location:
            FindingLocation::File {
                file_sha256,
                range,
                selected_bytes_sha256,
                ..
            },
    } = &observation.evidence
    else {
        panic!("deterministic package detection must retain its exact file citation");
    };
    assert_ne!(evidence_sha256, &Sha256Digest::from_bytes(b""));
    assert_eq!(
        file_sha256,
        &Sha256Digest::from_bytes(NPM_CAPABILITY_FIXTURE)
    );
    let (start, end) = match range {
        EvidenceRange::Lines {
            start_byte,
            end_byte,
            ..
        }
        | EvidenceRange::Bytes {
            start_byte,
            end_byte,
        } => (*start_byte as usize, *end_byte as usize),
    };
    assert!(start < end && end <= NPM_CAPABILITY_FIXTURE.len());
    assert_eq!(
        selected_bytes_sha256,
        &Sha256Digest::from_bytes(&NPM_CAPABILITY_FIXTURE[start..end])
    );
    assert_eq!(
        report.verdict,
        whoathere_runner::ExactArtifactVerdictV1::Malicious
    );
    assert_eq!(report.status, ExactArtifactDispositionV1::Findings);
    assert!(report.behavior_detection_count > 0);
    assert!(!report.admission_authority);
    assert!(!report.observed_clean);
    assert!(!report.sync_back_enabled);
}

#[test]
fn ordinary_static_network_capability_is_preserved_without_a_malware_verdict() {
    let root = TempRoot::new("whoathere-exact-spine-network-context");
    let report = inspect(
        &root,
        "spine-network-context-1.0.0.tgz",
        &npm_network_context_tgz(),
        Some(Ecosystem::Npm),
        (false, false),
        (None, None),
    );

    let observation = report
        .observations
        .iter()
        .find(|observation| {
            observation.finding_kind
                == ExactArtifactFindingKindV1::DeterministicStatic(
                    ArtifactFindingCategory::NetworkCapability,
                )
        })
        .expect("network capability remains visible for review");
    assert!(!observation.behavior_detection_eligible);
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert_eq!(
        report.verdict,
        whoathere_runner::ExactArtifactVerdictV1::Inconclusive
    );
    assert_eq!(report.exit_code, 22);
    assert_eq!(report.behavior_detection_count, 0);
    assert!(!report.admission_authority);
    assert!(!report.observed_clean);
}

#[test]
fn ingress_rejects_symlinks_and_oversize_files_before_normalization() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("whoathere-exact-spine-ingress");
    let target = root.path().join("target.tgz");
    let link = root.path().join("link.tgz");
    std::fs::write(&target, b"not opened through a link").expect("write symlink target");
    symlink(&target, &link).expect("create symlink fixture");
    let link_error = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &link,
            quarantine_root: &root.path().join("link-cas"),
            ecosystem: Some(Ecosystem::Npm),
            acquired_at: "2026-07-15T00:00:00Z",
            ai_requested: false,
            ai_provider: None,
            detonation_requested: false,
            normalization_limits: NormalizationLimits::default(),
        },
        None,
        None,
    )
    .expect_err("symlink ingress must fail closed");
    assert_eq!(
        link_error.reason_code(),
        "exact_artifact_path_not_regular_file"
    );

    let oversized = root.path().join("oversized.tgz");
    std::fs::write(&oversized, b"12").expect("write oversized fixture");
    let size_error = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &oversized,
            quarantine_root: &root.path().join("size-cas"),
            ecosystem: Some(Ecosystem::Npm),
            acquired_at: "2026-07-15T00:00:00Z",
            ai_requested: false,
            ai_provider: None,
            detonation_requested: false,
            normalization_limits: NormalizationLimits {
                max_original_bytes: 1,
                ..NormalizationLimits::default()
            },
        },
        None,
        None,
    )
    .expect_err("oversize ingress must fail before allocation or normalization");
    assert_eq!(
        size_error.reason_code(),
        "exact_artifact_size_out_of_bounds"
    );
}

#[test]
fn wheel_compiles_install_pth_import_and_console_intents() {
    let root = TempRoot::new("whoathere-exact-spine-wheel");
    let report = inspect(
        &root,
        "spine_wheel-1.0.0-py3-none-any.whl",
        &wheel_zip(),
        None,
        (false, false),
        (None, None),
    );

    assert_eq!(report.identity.ecosystem, Ecosystem::Pypi);
    assert_eq!(
        report.scenario_plan.status,
        ExactArtifactStageStatusV1::Complete
    );
    assert_eq!(report.scenario_plan.intents.len(), 5);
    assert!(report
        .scenario_plan
        .intents
        .iter()
        .all(|intent| matches!(intent.kind, ExactArtifactScenarioKindV1::Wheel(_))));
    assert!(!report.scenario_plan.executable);
    assert_eq!(report.scenario_plan.runtime_binding_status, "not_bound");
}

#[test]
fn nested_sdist_compiles_typed_matrix_but_reports_missing_build_closure() {
    let root = TempRoot::new("whoathere-exact-spine-sdist");
    let report = inspect(
        &root,
        "spine-sdist-1.0.0.tar.gz",
        &sdist_tgz(),
        Some(Ecosystem::Pypi),
        (false, false),
        (None, None),
    );

    assert_eq!(report.identity.package_name.as_deref(), Some("spine-sdist"));
    assert_eq!(
        report.scenario_plan.status,
        ExactArtifactStageStatusV1::Incomplete
    );
    assert!(report
        .scenario_plan
        .reason_codes
        .contains(&"exact_artifact_sdist_build_closure_required".to_string()));
    assert!(report
        .scenario_plan
        .reason_codes
        .contains(&"exact_artifact_sdist_dynamic_build_requirements_possible".to_string()));
    assert!(report
        .scenario_plan
        .reason_codes
        .contains(&"exact_artifact_derived_wheel_probe_manifest_required".to_string()));
    assert_eq!(report.scenario_plan.intents.len(), 2);
    assert!(report.scenario_plan.intents.iter().all(|intent| matches!(
        intent.kind,
        ExactArtifactScenarioKindV1::Sdist(SdistScenarioKindV1::BuildExactSdist { .. })
            | ExactArtifactScenarioKindV1::Sdist(SdistScenarioKindV1::InspectDerivedWheel)
    )));
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!report.observed_clean);
}

#[test]
fn legacy_tar_and_zip_sdists_never_claim_a_complete_post_build_probe_matrix() {
    for (label, filename, bytes) in [
        ("tar", "legacy-spine-1.0.0.tar.gz", legacy_sdist_tgz()),
        ("zip", "legacy-spine-1.0.0.zip", legacy_sdist_zip()),
    ] {
        let root = TempRoot::new(&format!("whoathere-exact-spine-legacy-{label}"));
        let report = inspect(
            &root,
            filename,
            &bytes,
            Some(Ecosystem::Pypi),
            (false, false),
            (None, None),
        );

        assert_eq!(
            report.scenario_plan.status,
            ExactArtifactStageStatusV1::Incomplete
        );
        assert!(!report.scenario_plan.executable);
        assert_eq!(report.scenario_plan.runtime_binding_status, "not_bound");
        assert!(report
            .scenario_plan
            .reason_codes
            .contains(&"exact_artifact_derived_wheel_probe_manifest_required".to_string()));
        assert_eq!(report.scenario_plan.intents.len(), 2);
        assert!(report.scenario_plan.intents.iter().all(|intent| matches!(
            intent.kind,
            ExactArtifactScenarioKindV1::Sdist(SdistScenarioKindV1::BuildExactSdist { .. })
                | ExactArtifactScenarioKindV1::Sdist(SdistScenarioKindV1::InspectDerivedWheel)
        )));
        assert!(!report.scenario_plan.intents.iter().any(|intent| matches!(
            intent.kind,
            ExactArtifactScenarioKindV1::Sdist(SdistScenarioKindV1::InstallDerivedWheel)
                | ExactArtifactScenarioKindV1::Sdist(SdistScenarioKindV1::ImportRoot { .. })
        )));
        assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
        assert!(!report.observed_clean);
    }
}

fn optional_result(
    request: &ExactArtifactAdapterRequestV1,
    outcome: BoundOptionalEvidenceOutcomeV1,
    reason_code: &str,
) -> BoundOptionalEvidenceV1 {
    optional_result_for_request_sha(&request.request_sha256, outcome, reason_code)
}

fn optional_result_for_request_sha(
    request_sha256: &str,
    outcome: BoundOptionalEvidenceOutcomeV1,
    reason_code: &str,
) -> BoundOptionalEvidenceV1 {
    let canonical_result_bytes = ExactArtifactOptionalResultV1::new(
        request_sha256.to_string(),
        outcome,
        vec![reason_code.to_string()],
    )
    .expect("valid optional result")
    .to_canonical_json_bytes()
    .expect("canonical optional result");
    BoundOptionalEvidenceV1 {
        canonical_result_bytes,
        behavior_bundles: Vec::new(),
    }
}

#[derive(Default)]
struct ReplayingAi {
    first_request_sha256: std::sync::Mutex<Option<String>>,
}

impl ExactArtifactAiAdapterV1 for ReplayingAi {
    fn provider_id(&self) -> &str {
        "mock-ai"
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn analyze(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        prepared: &PreparedArtifact,
        deterministic: &ArtifactStaticAnalysis,
        scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        assert_eq!(request.stage, "ai_review");
        assert_eq!(request.provider, self.provider_id());
        assert_eq!(
            request.artifact_sha256,
            prepared.evidence_subject().artifact_sha256()
        );
        assert_eq!(
            request.envelope_sha256,
            prepared.evidence_subject().envelope_sha256()
        );
        assert_eq!(
            request.manifest_sha256,
            prepared.evidence_subject().manifest_sha256()
        );
        assert_eq!(request.scenario_plan_sha256, scenarios.plan_sha256);
        let deterministic_sha256 = deterministic
            .analysis_sha256()
            .expect("deterministic analysis digest");
        assert_eq!(
            request.deterministic_analysis_sha256.as_deref(),
            Some(deterministic_sha256.as_str())
        );
        let mut stored = self
            .first_request_sha256
            .lock()
            .expect("request replay lock");
        let echoed_request_sha256 = stored
            .get_or_insert_with(|| request.request_sha256.clone())
            .clone();
        let result = optional_result_for_request_sha(
            &echoed_request_sha256,
            BoundOptionalEvidenceOutcomeV1::BoundedNoFinding,
            "mock_bounded_no_finding",
        );
        Ok(result)
    }
}

struct NonCanonicalResultAi;

impl ExactArtifactAiAdapterV1 for NonCanonicalResultAi {
    fn provider_id(&self) -> &str {
        "mock-ai"
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn analyze(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        _prepared: &PreparedArtifact,
        _deterministic: &ArtifactStaticAnalysis,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        let mut result = optional_result(
            request,
            BoundOptionalEvidenceOutcomeV1::Incomplete,
            "mock_finding",
        );
        result.canonical_result_bytes.push(b'\n');
        Ok(result)
    }
}

struct MaliciousLookingReasonOnlyAi;

impl ExactArtifactAiAdapterV1 for MaliciousLookingReasonOnlyAi {
    fn provider_id(&self) -> &str {
        "mock-ai"
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn analyze(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        _prepared: &PreparedArtifact,
        _deterministic: &ArtifactStaticAnalysis,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        Ok(optional_result(
            request,
            BoundOptionalEvidenceOutcomeV1::Incomplete,
            "credential_exfiltration_detected",
        ))
    }
}

struct FindingsWithIncompleteCoverageAi;

impl ExactArtifactAiAdapterV1 for FindingsWithIncompleteCoverageAi {
    fn provider_id(&self) -> &str {
        "mock-ai"
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn analyze(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        prepared: &PreparedArtifact,
        _deterministic: &ArtifactStaticAnalysis,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        let observation = mock_ai_observation(prepared);
        let result = ExactArtifactOptionalResultV1::with_evidence(
            request.request_sha256.clone(),
            BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage,
            vec!["mock_finding_with_incomplete_coverage".to_string()],
            vec![observation],
            Vec::new(),
        )?;
        Ok(BoundOptionalEvidenceV1 {
            canonical_result_bytes: result.to_canonical_json_bytes()?,
            behavior_bundles: Vec::new(),
        })
    }
}

struct ContextOnlyAi;

impl ExactArtifactAiAdapterV1 for ContextOnlyAi {
    fn provider_id(&self) -> &str {
        "mock-ai"
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn analyze(
        &self,
        request: &ExactArtifactAdapterRequestV1,
        prepared: &PreparedArtifact,
        _deterministic: &ArtifactStaticAnalysis,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        let observation =
            mock_ai_observation_for(prepared, ArtifactReviewFindingCategoryV2::NetworkCapability);
        let result = ExactArtifactOptionalResultV1::with_evidence(
            request.request_sha256.clone(),
            BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage,
            vec!["mock_context_with_incomplete_coverage".to_string()],
            vec![observation],
            Vec::new(),
        )?;
        Ok(BoundOptionalEvidenceV1 {
            canonical_result_bytes: result.to_canonical_json_bytes()?,
            behavior_bundles: Vec::new(),
        })
    }
}

struct MustNotRunProviderMismatch;

impl ExactArtifactAiAdapterV1 for MustNotRunProviderMismatch {
    fn provider_id(&self) -> &str {
        "different-ai"
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn analyze(
        &self,
        _request: &ExactArtifactAdapterRequestV1,
        _prepared: &PreparedArtifact,
        _deterministic: &ArtifactStaticAnalysis,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        panic!("a provider mismatch must never reach the AI adapter")
    }
}

struct MustNotRunUnboundDetonation;

impl ExactArtifactDetonationAdapterV1 for MustNotRunUnboundDetonation {
    fn provider_id(&self) -> &str {
        "mock-detonation"
    }

    fn readiness_reason(&self) -> Option<&'static str> {
        None
    }

    fn detonate(
        &self,
        _request: &ExactArtifactAdapterRequestV1,
        _artifact: &VerifiedArtifactLease,
        _prepared: &PreparedArtifact,
        _scenarios: &ExactArtifactScenarioPlanV1,
    ) -> Result<BoundOptionalEvidenceV1, OptionalAdapterErrorV1> {
        panic!("an unbound scenario plan must never reach the detonation adapter")
    }
}

#[test]
fn optional_request_digest_rejects_replay_across_exact_artifacts() {
    let root = TempRoot::new("whoathere-exact-spine-adapter-replay");
    let adapter = ReplayingAi::default();
    let first = inspect(
        &root,
        "spine_wheel-1.0.0-py3-none-any.whl",
        &wheel_zip(),
        None,
        (true, false),
        (Some(&adapter), None),
    );
    let second = inspect(
        &root,
        "spine-inert-1.0.0.tgz",
        &npm_tgz(),
        None,
        (true, false),
        (Some(&adapter), None),
    );

    assert!(first.stages.iter().any(|stage| {
        stage.stage == "ai_review" && stage.status == ExactArtifactStageStatusV1::Complete
    }));
    assert!(second.stages.iter().any(|stage| {
        stage.stage == "ai_review"
            && stage.status == ExactArtifactStageStatusV1::Error
            && stage
                .reason_codes
                .contains(&"exact_artifact_optional_evidence_request_binding_invalid".to_string())
    }));
    assert_eq!(first.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!first.admission_authority);
    assert!(!first.observed_clean);
    assert!(!second.admission_authority);
    assert!(!second.observed_clean);
}

#[test]
fn optional_result_bytes_must_be_canonical_and_are_hashed_by_the_product() {
    let root = TempRoot::new("whoathere-exact-spine-adapter-result");
    let tampered = inspect(
        &root,
        "spine_wheel-1.0.0-py3-none-any.whl",
        &wheel_zip(),
        Some(Ecosystem::Pypi),
        (true, false),
        (Some(&NonCanonicalResultAi), None),
    );
    assert!(tampered.stages.iter().any(|stage| {
        stage.stage == "ai_review"
            && stage.status == ExactArtifactStageStatusV1::Error
            && stage
                .reason_codes
                .contains(&"exact_artifact_optional_result_not_canonical".to_string())
    }));

    let accepted = inspect(
        &root,
        "spine_wheel-1.0.0-py3-none-any.whl",
        &wheel_zip(),
        Some(Ecosystem::Pypi),
        (true, false),
        (Some(&FindingsWithIncompleteCoverageAi), None),
    );
    let ai_stage = accepted
        .stages
        .iter()
        .find(|stage| stage.stage == "ai_review")
        .expect("AI stage");
    let canonical = ExactArtifactOptionalResultV1::with_evidence(
        ai_stage
            .request_sha256
            .clone()
            .expect("bound AI request digest"),
        BoundOptionalEvidenceOutcomeV1::FindingsWithIncompleteCoverage,
        vec!["mock_finding_with_incomplete_coverage".to_string()],
        accepted
            .observations
            .iter()
            .filter(|observation| {
                observation.source == ExactArtifactObservationSourceV1::AiSourceReview
            })
            .cloned()
            .collect(),
        Vec::new(),
    )
    .expect("valid combined result")
    .to_canonical_json_bytes()
    .expect("canonical combined result");
    let expected_result_sha256 = Sha256Digest::from_bytes(&canonical).to_string();
    assert_eq!(
        ai_stage.status,
        ExactArtifactStageStatusV1::FindingsWithIncompleteCoverage
    );
    assert_eq!(
        ai_stage.result_sha256.as_deref(),
        Some(expected_result_sha256.as_str())
    );
    assert!(ai_stage.request_sha256.is_some());
    assert_eq!(accepted.status, ExactArtifactDispositionV1::Findings);
    assert_eq!(
        accepted.verdict,
        whoathere_runner::ExactArtifactVerdictV1::Malicious
    );
    assert_eq!(accepted.exit_code, 20);
    assert_eq!(accepted.behavior_detection_count, 0);
    assert!(accepted
        .observations
        .iter()
        .filter(|observation| {
            observation.source == ExactArtifactObservationSourceV1::AiSourceReview
        })
        .all(|observation| !observation.behavior_detection_eligible));
    assert!(!accepted.admission_authority);
    assert!(!accepted.observed_clean);
}

#[test]
fn malicious_looking_reason_strings_without_typed_observations_never_drive_a_verdict() {
    let root = TempRoot::new("whoathere-exact-spine-reason-only");
    let report = inspect(
        &root,
        "spine-inert-1.0.0.tgz",
        &npm_tgz(),
        Some(Ecosystem::Npm),
        (true, false),
        (Some(&MaliciousLookingReasonOnlyAi), None),
    );

    assert!(report.observations.is_empty());
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert_eq!(
        report.verdict,
        whoathere_runner::ExactArtifactVerdictV1::Inconclusive
    );
    assert_eq!(report.exit_code, 22);
    assert_eq!(report.behavior_detection_count, 0);
    assert!(report
        .reason_codes
        .contains(&"credential_exfiltration_detected".to_string()));
    assert!(!report.admission_authority);
    assert!(!report.observed_clean);
    assert!(!report.sync_back_enabled);
}

#[test]
fn contextual_ai_source_finding_is_preserved_without_a_malware_verdict() {
    let root = TempRoot::new("whoathere-exact-spine-ai-context");
    let report = inspect(
        &root,
        "spine-inert-1.0.0.tgz",
        &npm_tgz(),
        Some(Ecosystem::Npm),
        (true, false),
        (Some(&ContextOnlyAi), None),
    );

    assert!(report.observations.iter().any(|observation| {
        observation.finding_kind
            == ExactArtifactFindingKindV1::AiSourceReview(
                ArtifactReviewFindingCategoryV2::NetworkCapability,
            )
    }));
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert_eq!(
        report.verdict,
        whoathere_runner::ExactArtifactVerdictV1::Inconclusive
    );
    assert_eq!(report.exit_code, 22);
    assert_eq!(report.behavior_detection_count, 0);
    assert!(!report.admission_authority);
    assert!(!report.observed_clean);
}

fn mock_ai_observation(prepared: &PreparedArtifact) -> ExactArtifactObservationV1 {
    mock_ai_observation_for(
        prepared,
        ArtifactReviewFindingCategoryV2::CredentialExfiltration,
    )
}

fn mock_ai_observation_for(
    prepared: &PreparedArtifact,
    category: ArtifactReviewFindingCategoryV2,
) -> ExactArtifactObservationV1 {
    let file = prepared
        .normalized()
        .files()
        .find(|file| !file.bytes().is_empty())
        .expect("mock AI citation target");
    ExactArtifactObservationV1::new(
        ExactArtifactObservationSourceV1::AiSourceReview,
        ExactArtifactThreatClassV1::NetworkAndExfiltration,
        ExactArtifactFindingKindV1::AiSourceReview(category),
        ExactArtifactObservationConfidenceV1::Moderate,
        Sha256Digest::parse(prepared.evidence_subject().artifact_sha256().to_string())
            .expect("artifact digest"),
        Sha256Digest::parse(prepared.evidence_subject().manifest_sha256().to_string())
            .expect("manifest digest"),
        ExactArtifactEvidenceReferenceV1::AiSourceReview {
            finding_id_sha256: Sha256Digest::from_bytes(b"mock-ai-finding"),
            evidence_sha256: Sha256Digest::from_bytes(b"mock-ai-evidence"),
            file_id: file.file_id.clone(),
            file_sha256: file.sha256.clone(),
            start_byte: 0,
            end_byte: 1,
            start_line: 1,
            end_line: 1,
            selected_sha256: Sha256Digest::from_bytes(&file.bytes()[..1]),
        },
        ExactArtifactObservationCoverageV1::Incomplete,
        vec!["mock_ai_coverage_incomplete".to_string()],
        false,
    )
    .expect("valid mock AI observation")
}

#[test]
fn provider_mismatch_and_unbound_detonation_never_invoke_adapters() {
    let root = TempRoot::new("whoathere-exact-spine-adapter-provider");
    let report = inspect(
        &root,
        "spine_wheel-1.0.0-py3-none-any.whl",
        &wheel_zip(),
        None,
        (true, true),
        (
            Some(&MustNotRunProviderMismatch),
            Some(&MustNotRunUnboundDetonation),
        ),
    );

    assert!(report.stages.iter().any(|stage| {
        stage.stage == "ai_review"
            && stage.status == ExactArtifactStageStatusV1::Unavailable
            && stage
                .reason_codes
                .contains(&"exact_artifact_ai_provider_mismatch".to_string())
    }));
    assert!(report.stages.iter().any(|stage| {
        stage.stage == "detonation"
            && stage.status == ExactArtifactStageStatusV1::Incomplete
            && stage
                .reason_codes
                .contains(&"exact_artifact_runtime_binding_not_verified".to_string())
    }));
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!report.admission_authority);
    assert!(!report.observed_clean);
}
