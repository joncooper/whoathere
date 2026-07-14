use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use whoathere_artifact::{
    normalize_artifact, normalize_derived_wheel, AcquisitionMethod, ArtifactEnvelope,
    ArtifactEnvelopeInput, ArtifactFormat, ArtifactManifest, ArtifactSourceType, Ecosystem,
    NormalizationCompleteness, NormalizationError, NormalizationLimits, Sha256Digest,
};
use zip::write::SimpleFileOptions;

const NPM_PACKAGE_JSON: &[u8] = include_bytes!("fixtures/npm-noncanonical/package.json");
const NPM_CLI: &[u8] = include_bytes!("fixtures/npm-noncanonical/bin/cli.js");
const NPM_INDEX: &[u8] = include_bytes!("fixtures/npm-noncanonical/lib/index.js");
const NPM_LIFECYCLE: &[u8] = include_bytes!("fixtures/npm-noncanonical/lifecycle-canary.js");

const WHEEL_METADATA: &[u8] = include_bytes!("fixtures/wheel/fixture_pkg-1.2.3.dist-info/METADATA");
const WHEEL_DESCRIPTION: &[u8] = include_bytes!("fixtures/wheel/fixture_pkg-1.2.3.dist-info/WHEEL");
const WHEEL_ENTRY_POINTS: &[u8] =
    include_bytes!("fixtures/wheel/fixture_pkg-1.2.3.dist-info/entry_points.txt");
const WHEEL_PTH: &[u8] = include_bytes!("fixtures/wheel/fixture_pkg.pth");
const WHEEL_INIT: &[u8] = include_bytes!("fixtures/wheel/fixture_pkg/__init__.py");
const WHEEL_CLI: &[u8] = include_bytes!("fixtures/wheel/fixture_pkg/cli.py");

const SDIST_PKG_INFO: &[u8] = include_bytes!("fixtures/sdist-nested/nested_sdist-2.0.0/PKG-INFO");
const SDIST_PYPROJECT: &[u8] =
    include_bytes!("fixtures/sdist-nested/nested_sdist-2.0.0/pyproject.toml");
const SDIST_SETUP_CFG: &[u8] = include_bytes!("fixtures/sdist-nested/nested_sdist-2.0.0/setup.cfg");
const SDIST_SETUP_PY: &[u8] = include_bytes!("fixtures/sdist-nested/nested_sdist-2.0.0/setup.py");
const SDIST_INIT: &[u8] =
    include_bytes!("fixtures/sdist-nested/nested_sdist-2.0.0/src/nested_sdist/__init__.py");

fn envelope(
    ecosystem: Ecosystem,
    name: &str,
    version: &str,
    filename: &str,
    format: ArtifactFormat,
    bytes: &[u8],
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
            custody_reference: format!("inert-fixture:{filename}"),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "artifact-normalization-test.v1".to_string(),
            requires_external_dependency_resolution: matches!(
                format,
                ArtifactFormat::NpmTarGzip
                    | ArtifactFormat::SdistTarGzip
                    | ArtifactFormat::SdistZip
            ),
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
            .expect("append inert tar member");
    }
    archive
        .into_inner()
        .expect("finish inert tar archive")
        .finish()
        .expect("finish inert gzip stream")
}

fn npm_tgz() -> Vec<u8> {
    const ROOT: &str = "noncanonical-whoathere-inert-1.2.3";
    tar_gzip(&[
        (&format!("{ROOT}/package.json"), NPM_PACKAGE_JSON, 0o644),
        (&format!("{ROOT}/bin/cli.js"), NPM_CLI, 0o755),
        (&format!("{ROOT}/lib/index.js"), NPM_INDEX, 0o644),
        (&format!("{ROOT}/lifecycle-canary.js"), NPM_LIFECYCLE, 0o644),
    ])
}

fn sdist_tgz() -> Vec<u8> {
    const ROOT: &str = "nested_sdist-2.0.0";
    tar_gzip(&[
        (&format!("{ROOT}/PKG-INFO"), SDIST_PKG_INFO, 0o644),
        (&format!("{ROOT}/pyproject.toml"), SDIST_PYPROJECT, 0o644),
        (&format!("{ROOT}/setup.cfg"), SDIST_SETUP_CFG, 0o644),
        (&format!("{ROOT}/setup.py"), SDIST_SETUP_PY, 0o644),
        (
            &format!("{ROOT}/src/nested_sdist/__init__.py"),
            SDIST_INIT,
            0o644,
        ),
    ])
}

fn wheel_zip() -> Vec<u8> {
    const DIST_INFO: &str = "fixture_pkg-1.2.3.dist-info";
    let mut members = vec![
        (format!("{DIST_INFO}/METADATA"), WHEEL_METADATA),
        (format!("{DIST_INFO}/WHEEL"), WHEEL_DESCRIPTION),
        (format!("{DIST_INFO}/entry_points.txt"), WHEEL_ENTRY_POINTS),
        ("fixture_pkg.pth".to_string(), WHEEL_PTH),
        ("fixture_pkg/__init__.py".to_string(), WHEEL_INIT),
        ("fixture_pkg/cli.py".to_string(), WHEEL_CLI),
    ];
    let record_path = format!("{DIST_INFO}/RECORD");
    let mut record = String::new();
    for (path, bytes) in &members {
        record.push_str(path);
        record.push(',');
        record.push_str(&wheel_record_hash(bytes));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str(&record_path);
    record.push_str(",,\n");

    let cursor = Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    for (path, bytes) in members.drain(..) {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start inert wheel member");
        writer.write_all(bytes).expect("write inert wheel member");
    }
    writer
        .start_file(record_path, SimpleFileOptions::default())
        .expect("start inert wheel RECORD");
    writer
        .write_all(record.as_bytes())
        .expect("write inert wheel RECORD");
    writer
        .finish()
        .expect("finish inert wheel ZIP")
        .into_inner()
}

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest_hex = whoathere_hash::sha256_hex(bytes);
    let digest_bytes = digest_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).expect("SHA-256 hex is ASCII");
            u8::from_str_radix(pair, 16).expect("SHA-256 output is hexadecimal")
        })
        .collect::<Vec<_>>();
    format!("sha256={}", base64_url_no_pad(&digest_bytes))
}

fn base64_url_no_pad(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity((bytes.len() * 4).div_ceil(3));
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

fn assert_complete_manifest(
    manifest: &ArtifactManifest,
    envelope: &ArtifactEnvelope,
    bytes: &[u8],
    expected_members: usize,
) {
    assert!(envelope.matches_original_bytes(bytes));
    assert_eq!(envelope.original_sha256, Sha256Digest::from_bytes(bytes));
    assert_eq!(manifest.artifact_sha256, envelope.original_sha256);
    assert_eq!(
        manifest.normalization_completeness,
        NormalizationCompleteness::Complete
    );
    assert_eq!(manifest.members.len(), expected_members);
    assert_eq!(manifest.total_member_count, expected_members as u64);
    assert!(manifest.excluded_members.is_empty());
    assert!(manifest.issues.is_empty());
    assert!(manifest
        .verify_manifest_sha256()
        .expect("verify manifest hash"));
    assert!(manifest.validate().is_ok());
    assert_eq!(
        manifest.manifest_sha256,
        manifest
            .recompute_manifest_sha256()
            .expect("recompute manifest hash")
    );
}

#[test]
fn normalizes_noncanonical_root_npm_tgz_from_exact_bytes() {
    let bytes = npm_tgz();
    let envelope = envelope(
        Ecosystem::Npm,
        "@whoathere/inert-lifecycle-fixture",
        "1.2.3",
        "inert-lifecycle-fixture-1.2.3.tgz",
        ArtifactFormat::NpmTarGzip,
        &bytes,
    );
    let manifest = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert npm tgz");

    assert_complete_manifest(&manifest, &envelope, &bytes, 4);
    assert_eq!(manifest.files().count(), 4);
    assert!(manifest.files().all(|file| !file.bytes().is_empty()));
    assert_eq!(
        manifest.canonical_package_root,
        "noncanonical-whoathere-inert-1.2.3"
    );
    assert!(manifest.anomalies.iter().any(|anomaly| {
        anomaly.reason_code == "npm_noncanonical_package_root"
            && anomaly.path.as_deref() == Some("noncanonical-whoathere-inert-1.2.3")
    }));
    let identity = manifest.identity.as_ref().expect("npm identity");
    assert_eq!(identity.ecosystem, Ecosystem::Npm);
    assert_eq!(identity.display_name, "@whoathere/inert-lifecycle-fixture");
    assert_eq!(identity.normalized_name, identity.display_name);
    assert_eq!(identity.version, "1.2.3");

    let npm = manifest.metadata.npm.as_ref().expect("npm metadata");
    assert_eq!(
        npm.lifecycle_scripts.get("preinstall").map(String::as_str),
        Some("node lifecycle-canary.js preinstall")
    );
    assert_eq!(
        npm.lifecycle_scripts.get("install").map(String::as_str),
        Some("node lifecycle-canary.js install")
    );
    assert_eq!(
        npm.lifecycle_scripts.get("postinstall").map(String::as_str),
        Some("node lifecycle-canary.js postinstall")
    );
    assert_eq!(
        npm.bin_targets.get("whoathere-inert").map(String::as_str),
        Some("bin/cli.js")
    );
    assert_eq!(npm.export_targets, vec!["./lib/index.js"]);
    assert_eq!(npm.dependency_declarations.len(), 1);
    let dependency = &npm.dependency_declarations[0];
    assert_eq!(dependency.group, "dependencies");
    assert_eq!(dependency.name, "inert-offline-dependency");
    assert_eq!(dependency.requirement, "1.0.0");
    assert!(npm.requires_offline_closure);
}

#[test]
fn normalizes_wheel_zip_with_complete_record_and_execution_surfaces() {
    let bytes = wheel_zip();
    let envelope = envelope(
        Ecosystem::Pypi,
        "fixture-pkg",
        "1.2.3",
        "fixture_pkg-1.2.3-py3-none-any.whl",
        ArtifactFormat::WheelZip,
        &bytes,
    );
    let manifest = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert wheel");

    assert_complete_manifest(&manifest, &envelope, &bytes, 7);
    assert_eq!(manifest.canonical_package_root, ".");
    assert!(manifest.anomalies.is_empty());
    let identity = manifest.identity.as_ref().expect("wheel identity");
    assert_eq!(identity.ecosystem, Ecosystem::Pypi);
    assert_eq!(identity.display_name, "fixture-pkg");
    assert_eq!(identity.normalized_name, "fixture-pkg");
    assert_eq!(identity.version, "1.2.3");

    let wheel = manifest.metadata.wheel.as_ref().expect("wheel metadata");
    assert_eq!(
        wheel.dist_info_directory.as_deref(),
        Some("fixture_pkg-1.2.3.dist-info")
    );
    assert_eq!(wheel.tags, vec!["py3-none-any"]);
    assert!(wheel.native_tags.is_empty());
    assert_eq!(wheel.import_roots, vec!["fixture_pkg"]);
    assert_eq!(
        wheel
            .console_entry_points
            .get("whoathere-inert")
            .map(String::as_str),
        Some("fixture_pkg.cli:main")
    );
    assert!(wheel.entry_points_file_id.is_some());
    let pth_member = manifest
        .members
        .iter()
        .find(|member| member.normalized_path == "fixture_pkg.pth")
        .expect("wheel .pth member");
    assert_eq!(wheel.pth_file_ids, vec![pth_member.file_id.clone()]);
}

#[test]
fn normalizes_derived_wheel_without_fabricating_acquisition_provenance() {
    let bytes = wheel_zip();
    let normalized = normalize_derived_wheel(
        "fixture_pkg-1.2.3-py3-none-any.whl",
        &bytes,
        NormalizationLimits::default(),
    )
    .expect("normalize inert derived wheel");

    assert_eq!(
        normalized.manifest.artifact_sha256,
        Sha256Digest::from_bytes(&bytes)
    );
    assert_eq!(
        normalized
            .manifest
            .identity
            .as_ref()
            .map(|identity| (identity.normalized_name.as_str(), identity.version.as_str())),
        Some(("fixture-pkg", "1.2.3"))
    );
    assert_eq!(
        normalized.manifest.normalization_completeness,
        NormalizationCompleteness::Complete
    );
    assert!(normalized.manifest.issues.is_empty());
    assert!(normalized
        .manifest
        .verify_manifest_sha256()
        .expect("manifest digest"));

    assert!(matches!(
        normalize_derived_wheel(
            "renamed-9.9.9-py3-none-any.whl",
            &bytes,
            NormalizationLimits::default()
        ),
        Err(NormalizationError::IdentityMismatch(_))
    ));
}

#[test]
fn rejects_wheel_paths_ambiguous_parts_and_invalid_build_tags() {
    let bytes = wheel_zip();
    for filename in [
        "../fixture_pkg-1.2.3-py3-none-any.whl",
        "fixture_pkg-1.2.3-extra-py3-none-any-extra.whl",
        "fixture_pkg-1.2.3-build-py3-none-any.whl",
    ] {
        let envelope = envelope(
            Ecosystem::Pypi,
            "fixture-pkg",
            "1.2.3",
            filename,
            ArtifactFormat::WheelZip,
            &bytes,
        );
        assert!(matches!(
            normalize_artifact(&envelope, &bytes, NormalizationLimits::default()),
            Err(NormalizationError::IdentityMismatch(_))
        ));
    }
}

#[test]
fn normalizes_nested_root_sdist_tgz_with_pep517_and_setup_metadata() {
    let bytes = sdist_tgz();
    let envelope = envelope(
        Ecosystem::Pypi,
        "nested-sdist",
        "2.0.0",
        "nested_sdist-2.0.0.tar.gz",
        ArtifactFormat::SdistTarGzip,
        &bytes,
    );
    let manifest = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert sdist");

    assert_complete_manifest(&manifest, &envelope, &bytes, 5);
    assert_eq!(manifest.canonical_package_root, "nested_sdist-2.0.0");
    assert!(manifest.anomalies.is_empty());
    let identity = manifest.identity.as_ref().expect("sdist identity");
    assert_eq!(identity.ecosystem, Ecosystem::Pypi);
    assert_eq!(identity.display_name, "nested-sdist");
    assert_eq!(identity.normalized_name, "nested-sdist");
    assert_eq!(identity.version, "2.0.0");

    let sdist = manifest.metadata.sdist.as_ref().expect("sdist metadata");
    assert_eq!(
        sdist.build_backend.as_deref(),
        Some("setuptools.build_meta")
    );
    assert_eq!(
        sdist.build_requires,
        vec!["setuptools==75.0.0", "wheel==0.44.0"]
    );
    assert!(sdist.pkg_info_file_id.is_some());
    assert!(sdist.pyproject_file_id.is_some());
    assert!(sdist.setup_py_file_id.is_some());
    assert!(sdist.setup_cfg_file_id.is_some());
    assert_eq!(sdist.package_roots, vec!["src/nested_sdist"]);
    assert!(sdist.backend_paths.is_empty());
    assert!(sdist.dynamic_build_requirements_possible);
}

#[test]
fn rejects_a_one_byte_mutation_against_the_exact_byte_envelope() {
    let bytes = npm_tgz();
    let envelope = envelope(
        Ecosystem::Npm,
        "@whoathere/inert-lifecycle-fixture",
        "1.2.3",
        "inert-lifecycle-fixture-1.2.3.tgz",
        ArtifactFormat::NpmTarGzip,
        &bytes,
    );
    let mut mutated = bytes.clone();
    let last = mutated.last_mut().expect("nonempty npm tgz");
    *last ^= 1;

    assert!(!envelope.matches_original_bytes(&mutated));
    assert!(matches!(
        normalize_artifact(&envelope, &mutated, NormalizationLimits::default()),
        Err(NormalizationError::ArtifactIdentityMismatch)
    ));
}
