use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Cursor, Write};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, NormalizedArtifact, Sha256Digest,
};
use whoathere_detonation::{
    decode_and_validate_derived_wheel_probe_manifest_v1,
    decode_and_validate_prepared_sdist_derived_wheel_build_v1,
    decode_and_validate_sdist_get_requires_for_build_wheel_result_v1,
    prepare_sdist_derived_wheel_build_v1, seal_derived_wheel_probe_manifest_v1,
    verify_derived_wheel_probe_manifest_v1, verify_prepared_sdist_derived_wheel_build_v1,
    DerivedWheelCandidateV1, DerivedWheelProbeManifestV1, DerivedWheelProbeSealOutcomeV1,
    PreparedSdistDerivedWheelBuildV1, SdistBuildClosureArtifactFormatV1,
    SdistBuildClosureArtifactV1, SdistBuildClosureMaterialV1, SdistBuildClosureV1,
    SdistDerivedWheelContractErrorV1, SdistDerivedWheelManualReviewReasonV1,
    SdistDerivedWheelPreparationOutcomeV1, SdistGetRequiresForBuildWheelResultV1,
    SdistGetRequiresForBuildWheelStatusV1, WheelConsoleArgumentProfileV1, WheelScenarioKindV1,
};
use zip::write::SimpleFileOptions;

const SOURCE_ROOT: &str = "nested_sdist-2.0.0";
const PEP517_PYPROJECT: &str = r#"[build-system]
requires = ["setuptools==75.0.0", "wheel==0.44.0"]
build-backend = "setuptools.build_meta"

[project]
name = "nested-sdist"
version = "2.0.0"
"#;
const EMPTY_CLOSURE_PEP517_PYPROJECT: &str = r#"[build-system]
requires = []
build-backend = "fixture_backend"
backend-path = ["backend"]

[project]
name = "nested-sdist"
version = "2.0.0"
"#;

struct SdistFixture {
    bytes: Vec<u8>,
    envelope: ArtifactEnvelope,
    artifact: NormalizedArtifact,
}

struct ClosureFixture {
    closure: SdistBuildClosureV1,
    files: Vec<(String, Vec<u8>)>,
}

impl ClosureFixture {
    fn materials(&self) -> Vec<SdistBuildClosureMaterialV1<'_>> {
        self.files
            .iter()
            .map(|(filename, bytes)| SdistBuildClosureMaterialV1 {
                artifact_filename: filename,
                artifact_bytes: bytes,
            })
            .collect()
    }
}

fn tar_gzip(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for (path, bytes) in entries {
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
            .expect("append inert sdist member");
    }
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn zip_archive(entries: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (path, bytes) in entries {
        writer
            .start_file(path, SimpleFileOptions::default())
            .expect("start zip member");
        writer.write_all(bytes).expect("write zip member");
    }
    writer.finish().expect("finish zip").into_inner()
}

fn source_entries(pyproject: Option<&str>) -> Vec<(String, Vec<u8>)> {
    let mut entries = vec![
        (
            format!("{SOURCE_ROOT}/PKG-INFO"),
            b"Metadata-Version: 2.3\nName: nested-sdist\nVersion: 2.0.0\nSummary: inert two-pass fixture\n"
                .to_vec(),
        ),
        (
            format!("{SOURCE_ROOT}/setup.py"),
            b"from setuptools import setup\nsetup()\n".to_vec(),
        ),
        (
            format!("{SOURCE_ROOT}/src/guessed_from_source/__init__.py"),
            b"SOURCE_ONLY = True\n".to_vec(),
        ),
    ];
    if let Some(pyproject) = pyproject {
        entries.push((
            format!("{SOURCE_ROOT}/pyproject.toml"),
            pyproject.as_bytes().to_vec(),
        ));
    }
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    entries
}

fn normalize_source(
    bytes: Vec<u8>,
    format: ArtifactFormat,
    filename: &str,
    requires_external_dependency_resolution: bool,
) -> SdistFixture {
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("nested-sdist".to_string()),
            package_version: Some("2.0.0".to_string()),
            source_coordinate: "fixture:nested-sdist@2.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-15T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: filename.to_string(),
            declared_format: Some(format),
            custody_reference: "inert-fixture:sdist-derived-wheel-contract".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "sdist-derived-wheel-contract-test.v1".to_string(),
            requires_external_dependency_resolution,
        },
        &bytes,
        format,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())
        .expect("normalize inert source sdist");
    SdistFixture {
        bytes,
        envelope,
        artifact,
    }
}

fn pep517_source() -> SdistFixture {
    normalize_source(
        tar_gzip(&source_entries(Some(PEP517_PYPROJECT))),
        ArtifactFormat::SdistTarGzip,
        "nested_sdist-2.0.0.tar.gz",
        true,
    )
}

fn pep517_source_with_extra_member() -> SdistFixture {
    let mut entries = source_entries(Some(PEP517_PYPROJECT));
    entries.push((
        format!("{SOURCE_ROOT}/REPLAY-DIFFERENT-BYTES.txt"),
        b"same coordinate, different exact source artifact\n".to_vec(),
    ));
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    normalize_source(
        tar_gzip(&entries),
        ArtifactFormat::SdistTarGzip,
        "nested_sdist-2.0.0.tar.gz",
        true,
    )
}

fn empty_closure_pep517_source() -> SdistFixture {
    let mut entries = source_entries(Some(EMPTY_CLOSURE_PEP517_PYPROJECT));
    entries.push((
        format!("{SOURCE_ROOT}/backend/fixture_backend.py"),
        b"def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n    return 'nested_sdist-2.0.0-py3-none-any.whl'\n"
            .to_vec(),
    ));
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    normalize_source(
        tar_gzip(&entries),
        ArtifactFormat::SdistTarGzip,
        "nested_sdist-2.0.0.tar.gz",
        true,
    )
}

fn non_exact_requirement_source() -> SdistFixture {
    let pyproject = PEP517_PYPROJECT.replace("setuptools==75.0.0", "setuptools>=75.0.0");
    normalize_source(
        tar_gzip(&source_entries(Some(&pyproject))),
        ArtifactFormat::SdistTarGzip,
        "nested_sdist-2.0.0.tar.gz",
        true,
    )
}

fn legacy_source() -> SdistFixture {
    normalize_source(
        tar_gzip(&source_entries(None)),
        ArtifactFormat::SdistTarGzip,
        "nested_sdist-2.0.0.tar.gz",
        false,
    )
}

fn zip_source() -> SdistFixture {
    normalize_source(
        zip_archive(&source_entries(Some(PEP517_PYPROJECT))),
        ArtifactFormat::SdistZip,
        "nested_sdist-2.0.0.zip",
        true,
    )
}

fn wheel_zip(members: &[(String, Vec<u8>)], dist_info: &str) -> Vec<u8> {
    wheel_zip_with_record_tamper(members, dist_info, false)
}

fn wheel_zip_with_record_tamper(
    members: &[(String, Vec<u8>)],
    dist_info: &str,
    tamper_record_hash: bool,
) -> Vec<u8> {
    let record_path = format!("{dist_info}/RECORD");
    let mut record = String::new();
    for (path, bytes) in members {
        record.push_str(path);
        record.push(',');
        record.push_str(&wheel_record_hash(bytes));
        record.push(',');
        record.push_str(&bytes.len().to_string());
        record.push('\n');
    }
    record.push_str(&record_path);
    record.push_str(",,\n");
    if tamper_record_hash {
        let hash_start = record
            .find("sha256=")
            .expect("generated RECORD hash marker")
            + "sha256=".len();
        let replacement = if record.as_bytes()[hash_start] == b'A' {
            "B"
        } else {
            "A"
        };
        record.replace_range(hash_start..hash_start + 1, replacement);
    }

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

fn wheel_record_hash(bytes: &[u8]) -> String {
    let digest_hex = whoathere_hash::sha256_hex(bytes);
    let digest_bytes = digest_hex
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex utf8"), 16).expect("hex byte")
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

struct SimpleWheelSpec<'a> {
    display_name: &'a str,
    normalized_name: &'a str,
    version: &'a str,
    tag: &'a str,
    pure: bool,
    metadata_extra: &'a str,
    package_members: &'a [(&'a str, &'a [u8])],
    entry_points: Option<&'a str>,
}

fn simple_wheel(spec: SimpleWheelSpec<'_>) -> (String, Vec<u8>) {
    let SimpleWheelSpec {
        display_name,
        normalized_name,
        version,
        tag,
        pure,
        metadata_extra,
        package_members,
        entry_points,
    } = spec;
    let distribution = normalized_name.replace('-', "_");
    let dist_info = format!("{distribution}-{version}.dist-info");
    let filename = format!("{distribution}-{version}-{tag}.whl");
    let metadata = format!(
        "Metadata-Version: 2.3\nName: {display_name}\nVersion: {version}\n{metadata_extra}"
    );
    let wheel = format!(
        "Wheel-Version: 1.0\nGenerator: whoathere-inert\nRoot-Is-Purelib: {pure}\nTag: {tag}\n"
    );
    let mut members = vec![
        (format!("{dist_info}/METADATA"), metadata.into_bytes()),
        (format!("{dist_info}/WHEEL"), wheel.into_bytes()),
    ];
    if let Some(entry_points) = entry_points {
        members.push((
            format!("{dist_info}/entry_points.txt"),
            entry_points.as_bytes().to_vec(),
        ));
    }
    members.extend(
        package_members
            .iter()
            .map(|(path, bytes)| ((*path).to_string(), (*bytes).to_vec())),
    );
    members.sort_by(|left, right| left.0.cmp(&right.0));
    let bytes = wheel_zip(&members, &dist_info);
    (filename, bytes)
}

fn closure_fixture() -> ClosureFixture {
    let setuptools = simple_wheel(SimpleWheelSpec {
        display_name: "setuptools",
        normalized_name: "setuptools",
        version: "75.0.0",
        tag: "py3-none-any",
        pure: true,
        metadata_extra: "",
        package_members: &[("setuptools/__init__.py", b"VERSION = '75.0.0'\n")],
        entry_points: None,
    });
    let wheel = simple_wheel(SimpleWheelSpec {
        display_name: "wheel",
        normalized_name: "wheel",
        version: "0.44.0",
        tag: "py3-none-any",
        pure: true,
        metadata_extra: "",
        package_members: &[("wheel/__init__.py", b"VERSION = '0.44.0'\n")],
        entry_points: None,
    });
    let files = vec![setuptools, wheel];
    let artifacts = files
        .iter()
        .map(|(filename, bytes)| {
            let (name, version) = if filename.starts_with("setuptools-") {
                ("setuptools", "75.0.0")
            } else {
                ("wheel", "0.44.0")
            };
            SdistBuildClosureArtifactV1::new(
                name,
                version,
                filename,
                SdistBuildClosureArtifactFormatV1::Wheel,
                Sha256Digest::from_bytes(bytes),
                bytes.len() as u64,
            )
            .expect("exact closure wheel")
        })
        .collect::<Vec<_>>();
    let closure = SdistBuildClosureV1::new(
        &[
            "setuptools==75.0.0".to_string(),
            "wheel==0.44.0".to_string(),
        ],
        artifacts,
    )
    .expect("fixed wheel-only closure");
    ClosureFixture { closure, files }
}

fn wrong_version_closure_fixture() -> ClosureFixture {
    let setuptools = simple_wheel(SimpleWheelSpec {
        display_name: "setuptools",
        normalized_name: "setuptools",
        version: "74.0.0",
        tag: "py3-none-any",
        pure: true,
        metadata_extra: "",
        package_members: &[("setuptools/__init__.py", b"VERSION = '74.0.0'\n")],
        entry_points: None,
    });
    let wheel = simple_wheel(SimpleWheelSpec {
        display_name: "wheel",
        normalized_name: "wheel",
        version: "0.44.0",
        tag: "py3-none-any",
        pure: true,
        metadata_extra: "",
        package_members: &[("wheel/__init__.py", b"VERSION = '0.44.0'\n")],
        entry_points: None,
    });
    let files = vec![setuptools, wheel];
    let artifacts = vec![
        SdistBuildClosureArtifactV1::new(
            "setuptools",
            "74.0.0",
            &files[0].0,
            SdistBuildClosureArtifactFormatV1::Wheel,
            Sha256Digest::from_bytes(&files[0].1),
            files[0].1.len() as u64,
        )
        .expect("wrong-version exact closure wheel"),
        SdistBuildClosureArtifactV1::new(
            "wheel",
            "0.44.0",
            &files[1].0,
            SdistBuildClosureArtifactFormatV1::Wheel,
            Sha256Digest::from_bytes(&files[1].1),
            files[1].1.len() as u64,
        )
        .expect("wheel closure wheel"),
    ];
    let closure = SdistBuildClosureV1::new(
        &[
            "setuptools==75.0.0".to_string(),
            "wheel==0.44.0".to_string(),
        ],
        artifacts,
    )
    .expect("legacy closure type accepts name-only satisfaction");
    ClosureFixture { closure, files }
}

fn derived_wheel() -> (String, Vec<u8>) {
    simple_wheel(SimpleWheelSpec {
        display_name: "nested-sdist",
        normalized_name: "nested-sdist",
        version: "2.0.0",
        tag: "py3-none-any",
        pure: true,
        metadata_extra: "",
        package_members: &[
            (
                "activation.pth",
                b"import actual_one.bootstrap\n" as &[u8],
            ),
            ("actual_one/__init__.py", b"ONE = True\n"),
            ("actual_one/bootstrap.py", b"BOOT = True\n"),
            ("actual_one/cli.py", b"def main(): return 0\n"),
            ("actual_two/__init__.py", b"TWO = True\n"),
            ("actual_two/cli.py", b"def main(): return 0\n"),
        ],
        entry_points: Some(
            "[console_scripts]\nactual-one = actual_one.cli:main\nactual-two = actual_two.cli:main\n",
        ),
    })
}

fn derived_wheel_with_invalid_record() -> (String, Vec<u8>) {
    let distribution = "nested_sdist";
    let version = "2.0.0";
    let tag = "py3-none-any";
    let dist_info = format!("{distribution}-{version}.dist-info");
    let filename = format!("{distribution}-{version}-{tag}.whl");
    let mut members = vec![
        (
            format!("{dist_info}/METADATA"),
            b"Metadata-Version: 2.3\nName: nested-sdist\nVersion: 2.0.0\n".to_vec(),
        ),
        (
            format!("{dist_info}/WHEEL"),
            b"Wheel-Version: 1.0\nGenerator: whoathere-inert\nRoot-Is-Purelib: true\nTag: py3-none-any\n".to_vec(),
        ),
        ("actual/__init__.py".to_string(), b"VALUE = 1\n".to_vec()),
    ];
    members.sort_by(|left, right| left.0.cmp(&right.0));
    (
        filename,
        wheel_zip_with_record_tamper(&members, &dist_info, true),
    )
}

fn prepared(source: &SdistFixture, closure: &ClosureFixture) -> PreparedSdistDerivedWheelBuildV1 {
    match prepare_sdist_derived_wheel_build_v1(
        &source.envelope,
        &source.artifact.manifest,
        &source.bytes,
        &closure.closure,
        &closure.materials(),
        NormalizationLimits::default(),
    )
    .expect("prepare result")
    {
        SdistDerivedWheelPreparationOutcomeV1::Prepared(value) => *value,
        other => panic!("expected prepared build, got {other:?}"),
    }
}

fn empty_hook(
    prepared: &PreparedSdistDerivedWheelBuildV1,
) -> SdistGetRequiresForBuildWheelResultV1 {
    SdistGetRequiresForBuildWheelResultV1::new(
        prepared,
        SdistGetRequiresForBuildWheelStatusV1::Completed,
        Vec::new(),
    )
    .expect("empty dynamic requirements")
}

fn sealed_manifest(
    prepared: &PreparedSdistDerivedWheelBuildV1,
    hook: &SdistGetRequiresForBuildWheelResultV1,
    wheel: &(String, Vec<u8>),
) -> DerivedWheelProbeManifestV1 {
    match seal_derived_wheel_probe_manifest_v1(
        prepared,
        hook,
        &[DerivedWheelCandidateV1 {
            artifact_filename: &wheel.0,
            artifact_bytes: &wheel.1,
        }],
        NormalizationLimits::default(),
    )
    .expect("seal result")
    {
        DerivedWheelProbeSealOutcomeV1::Sealed(value) => *value,
        other => panic!("expected sealed manifest, got {other:?}"),
    }
}

fn seal_reason(
    prepared: &PreparedSdistDerivedWheelBuildV1,
    hook: &SdistGetRequiresForBuildWheelResultV1,
    candidates: &[DerivedWheelCandidateV1<'_>],
) -> SdistDerivedWheelManualReviewReasonV1 {
    match seal_derived_wheel_probe_manifest_v1(
        prepared,
        hook,
        candidates,
        NormalizationLimits::default(),
    )
    .expect("manual-review seal result")
    {
        DerivedWheelProbeSealOutcomeV1::InconclusiveManualReview(review) => review.reason(),
        other => panic!("expected manual review, got {other:?}"),
    }
}

fn preparation_reason(
    source: &SdistFixture,
    closure: &ClosureFixture,
) -> SdistDerivedWheelManualReviewReasonV1 {
    match prepare_sdist_derived_wheel_build_v1(
        &source.envelope,
        &source.artifact.manifest,
        &source.bytes,
        &closure.closure,
        &closure.materials(),
        NormalizationLimits::default(),
    )
    .expect("manual-review preparation result")
    {
        SdistDerivedWheelPreparationOutcomeV1::InconclusiveManualReview(review) => review.reason(),
        other => panic!("expected manual review, got {other:?}"),
    }
}

#[test]
fn nested_pep517_two_pass_contract_uses_only_the_exact_derived_wheel_for_probes() {
    let source = pep517_source();
    let closure = closure_fixture();
    let prepared = prepared(&source, &closure);
    assert_eq!(
        prepared.source_artifact_sha256(),
        &Sha256Digest::from_bytes(&source.bytes)
    );
    assert_eq!(
        prepared.source_envelope_sha256(),
        &source
            .envelope
            .envelope_sha256()
            .expect("source envelope digest")
    );
    assert_eq!(prepared.source_package().normalized_name, "nested-sdist");
    assert_eq!(prepared.source_package().version, "2.0.0");
    assert_eq!(prepared.canonical_package_root(), SOURCE_ROOT);
    assert_eq!(prepared.build_backend(), "setuptools.build_meta");
    assert_eq!(
        prepared.build_closure_sha256(),
        closure.closure.closure_sha256()
    );
    verify_prepared_sdist_derived_wheel_build_v1(
        &prepared,
        &source.envelope,
        &source.artifact.manifest,
        &source.bytes,
        &closure.closure,
        &closure.materials(),
        NormalizationLimits::default(),
    )
    .expect("exact source and closure re-verify prepared build");

    let hook = empty_hook(&prepared);
    let wheel = derived_wheel();
    let manifest = sealed_manifest(&prepared, &hook, &wheel);
    assert_eq!(
        manifest.source_artifact_sha256(),
        prepared.source_artifact_sha256()
    );
    assert_eq!(
        manifest.prepared_build_sha256(),
        prepared.prepared_build_sha256()
    );
    assert_eq!(manifest.get_requires_result_sha256(), hook.result_sha256());
    assert!(!manifest.signed_vm_build_transcript_verified());
    assert!(!manifest.establishes_clean_behavior());
    assert_eq!(manifest.derived_package().normalized_name, "nested-sdist");
    assert_eq!(manifest.derived_package().version, "2.0.0");
    assert_eq!(manifest.probes().len(), 8);
    assert!(manifest.probes().iter().any(|probe| matches!(
        probe,
        WheelScenarioKindV1::FreshInterpreterPth { pth_file_ids } if pth_file_ids.len() == 1
    )));
    for expected in ["actual_one", "actual_two"] {
        assert!(manifest.probes().iter().any(|probe| matches!(
            probe,
            WheelScenarioKindV1::ImportRoot { module } if module == expected
        )));
    }
    for expected in ["actual-one", "actual-two"] {
        for argument_profile in [
            WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperHelp,
            WheelConsoleArgumentProfileV1::InstalledGeneratedWrapperNoArguments,
        ] {
            assert!(manifest.probes().iter().any(|probe| matches!(
                probe,
                WheelScenarioKindV1::ConsoleEntryPoint {
                    command_name,
                    argument_profile: observed_profile,
                    ..
                } if command_name == expected && observed_profile == &argument_profile
            )));
        }
    }
    assert!(!manifest
        .probes()
        .iter()
        .any(|probe| matches!(probe, WheelScenarioKindV1::ImportRoot { module } if module == "guessed_from_source")));
    verify_derived_wheel_probe_manifest_v1(
        &manifest,
        &prepared,
        &hook,
        &wheel.0,
        &wheel.1,
        NormalizationLimits::default(),
    )
    .expect("exact derived wheel re-verifies manifest");

    let prepared_wire = prepared.canonical_json_v1().expect("prepared wire");
    assert_eq!(
        decode_and_validate_prepared_sdist_derived_wheel_build_v1(&prepared_wire)
            .expect("decode prepared"),
        prepared
    );
    let hook_wire = hook.canonical_json_v1().expect("hook wire");
    assert_eq!(
        decode_and_validate_sdist_get_requires_for_build_wheel_result_v1(&hook_wire)
            .expect("decode hook"),
        hook
    );
    let manifest_wire = manifest.canonical_json_v1().expect("manifest wire");
    assert_eq!(
        decode_and_validate_derived_wheel_probe_manifest_v1(&manifest_wire)
            .expect("decode manifest"),
        manifest
    );
}

#[test]
fn closure_material_order_is_keyed_and_canonical() {
    let source = pep517_source();
    let closure = closure_fixture();
    let canonical = prepared(&source, &closure);
    let mut reversed_files = closure.files.clone();
    reversed_files.reverse();
    let reversed_materials = reversed_files
        .iter()
        .map(|(filename, bytes)| SdistBuildClosureMaterialV1 {
            artifact_filename: filename,
            artifact_bytes: bytes,
        })
        .collect::<Vec<_>>();
    let reversed = match prepare_sdist_derived_wheel_build_v1(
        &source.envelope,
        &source.artifact.manifest,
        &source.bytes,
        &closure.closure,
        &reversed_materials,
        NormalizationLimits::default(),
    )
    .expect("reordered closure materials")
    {
        SdistDerivedWheelPreparationOutcomeV1::Prepared(value) => *value,
        other => panic!("expected keyed closure preparation, got {other:?}"),
    };
    assert_eq!(reversed, canonical);
    assert_eq!(
        reversed.build_closure_materials_sha256(),
        canonical.build_closure_materials_sha256()
    );
}

#[test]
fn duplicate_or_missing_material_keys_are_inconclusive() {
    let source = pep517_source();
    let closure = closure_fixture();
    let materials = closure.materials();
    let cases = [
        vec![
            materials[0],
            SdistBuildClosureMaterialV1 {
                artifact_filename: materials[0].artifact_filename,
                artifact_bytes: materials[1].artifact_bytes,
            },
        ],
        vec![
            materials[0],
            SdistBuildClosureMaterialV1 {
                artifact_filename: "missing-counterpart-0.44.0-py3-none-any.whl",
                artifact_bytes: materials[1].artifact_bytes,
            },
        ],
    ];
    for material_set in cases {
        let outcome = prepare_sdist_derived_wheel_build_v1(
            &source.envelope,
            &source.artifact.manifest,
            &source.bytes,
            &closure.closure,
            &material_set,
            NormalizationLimits::default(),
        )
        .expect("invalid material keys are a manual-review outcome");
        assert!(matches!(
            outcome,
            SdistDerivedWheelPreparationOutcomeV1::InconclusiveManualReview(review)
                if review.reason()
                    == SdistDerivedWheelManualReviewReasonV1::BuildClosureArtifactUnsupported
        ));
    }
}

#[test]
fn exact_empty_pep517_closure_is_a_bound_prepared_build() {
    let source = empty_closure_pep517_source();
    let closure = SdistBuildClosureV1::new(&[], Vec::new()).expect("empty exact closure");
    let materials: [SdistBuildClosureMaterialV1<'_>; 0] = [];
    let prepared = match prepare_sdist_derived_wheel_build_v1(
        &source.envelope,
        &source.artifact.manifest,
        &source.bytes,
        &closure,
        &materials,
        NormalizationLimits::default(),
    )
    .expect("empty closure preparation")
    {
        SdistDerivedWheelPreparationOutcomeV1::Prepared(value) => *value,
        other => panic!("expected prepared empty closure, got {other:?}"),
    };
    assert_eq!(prepared.build_backend(), "fixture_backend");
    assert_eq!(prepared.backend_paths(), &["backend".to_string()]);
    assert!(prepared.declared_build_requirements().is_empty());
    assert_eq!(prepared.build_closure_sha256(), closure.closure_sha256());
    verify_prepared_sdist_derived_wheel_build_v1(
        &prepared,
        &source.envelope,
        &source.artifact.manifest,
        &source.bytes,
        &closure,
        &materials,
        NormalizationLimits::default(),
    )
    .expect("empty closure re-verifies without positional material assumptions");
}

#[test]
fn source_digest_closure_material_legacy_and_zip_contracts_fail_closed() {
    let source = pep517_source();
    let closure = closure_fixture();
    let mut changed_source = source.bytes.clone();
    changed_source.push(0);
    assert_eq!(
        prepare_sdist_derived_wheel_build_v1(
            &source.envelope,
            &source.artifact.manifest,
            &changed_source,
            &closure.closure,
            &closure.materials(),
            NormalizationLimits::default(),
        ),
        Err(SdistDerivedWheelContractErrorV1::SourceArtifactIdentityMismatch)
    );

    let mut substituted_manifest = source.artifact.manifest.clone();
    substituted_manifest
        .metadata
        .sdist
        .as_mut()
        .expect("sdist metadata")
        .build_backend = Some("benign_substitute.backend".to_string());
    substituted_manifest.manifest_sha256 = substituted_manifest
        .recompute_manifest_sha256()
        .expect("recompute substituted backend manifest");
    substituted_manifest
        .validate()
        .expect("self-consistent substituted backend manifest");
    assert_eq!(
        prepare_sdist_derived_wheel_build_v1(
            &source.envelope,
            &substituted_manifest,
            &source.bytes,
            &closure.closure,
            &closure.materials(),
            NormalizationLimits::default(),
        ),
        Err(SdistDerivedWheelContractErrorV1::SourceManifestArtifactMismatch)
    );

    let mut corrupted_files = closure.files.clone();
    corrupted_files[0].1.push(0);
    let corrupted_materials = corrupted_files
        .iter()
        .map(|(filename, bytes)| SdistBuildClosureMaterialV1 {
            artifact_filename: filename,
            artifact_bytes: bytes,
        })
        .collect::<Vec<_>>();
    let outcome = prepare_sdist_derived_wheel_build_v1(
        &source.envelope,
        &source.artifact.manifest,
        &source.bytes,
        &closure.closure,
        &corrupted_materials,
        NormalizationLimits::default(),
    )
    .expect("corrupt closure material is manual review");
    assert!(matches!(
        outcome,
        SdistDerivedWheelPreparationOutcomeV1::InconclusiveManualReview(review)
            if review.reason()
                == SdistDerivedWheelManualReviewReasonV1::BuildClosureArtifactUnsupported
    ));

    for (fixture, reason) in [
        (
            legacy_source(),
            SdistDerivedWheelManualReviewReasonV1::LegacySetupPyPending,
        ),
        (
            zip_source(),
            SdistDerivedWheelManualReviewReasonV1::ZipSdistPending,
        ),
    ] {
        let outcome = prepare_sdist_derived_wheel_build_v1(
            &fixture.envelope,
            &fixture.artifact.manifest,
            &fixture.bytes,
            &closure.closure,
            &closure.materials(),
            NormalizationLimits::default(),
        )
        .expect("unsupported source disposition");
        assert!(matches!(
            outcome,
            SdistDerivedWheelPreparationOutcomeV1::InconclusiveManualReview(review)
                if review.reason() == reason
        ));
    }
}

#[test]
fn alpha_build_closure_requires_canonical_exact_versions() {
    assert_eq!(
        preparation_reason(&non_exact_requirement_source(), &closure_fixture()),
        SdistDerivedWheelManualReviewReasonV1::NonExactBuildRequirementUnsupported
    );
    assert_eq!(
        preparation_reason(&pep517_source(), &wrong_version_closure_fixture()),
        SdistDerivedWheelManualReviewReasonV1::FixedBuildClosureMismatch
    );
}

#[test]
fn hook_and_output_cardinality_are_explicit_inconclusive_results() {
    let source = pep517_source();
    let closure = closure_fixture();
    let prepared = prepared(&source, &closure);
    let failed = SdistGetRequiresForBuildWheelResultV1::new(
        &prepared,
        SdistGetRequiresForBuildWheelStatusV1::BackendFailed,
        Vec::new(),
    )
    .expect("failed hook result");
    assert_eq!(
        seal_reason(&prepared, &failed, &[]),
        SdistDerivedWheelManualReviewReasonV1::GetRequiresForBuildWheelFailed
    );
    let dynamic = SdistGetRequiresForBuildWheelResultV1::new(
        &prepared,
        SdistGetRequiresForBuildWheelStatusV1::Completed,
        vec!["cython==3.0.0".to_string()],
    )
    .expect("dynamic hook result");
    assert_eq!(
        seal_reason(&prepared, &dynamic, &[]),
        SdistDerivedWheelManualReviewReasonV1::DynamicBuildRequirementsUnsupported
    );

    let empty = empty_hook(&prepared);
    assert_eq!(
        seal_reason(&prepared, &empty, &[]),
        SdistDerivedWheelManualReviewReasonV1::NoDerivedWheelProduced
    );
    let first = derived_wheel();
    let second = derived_wheel();
    let candidates = [
        DerivedWheelCandidateV1 {
            artifact_filename: &first.0,
            artifact_bytes: &first.1,
        },
        DerivedWheelCandidateV1 {
            artifact_filename: &second.0,
            artifact_bytes: &second.1,
        },
    ];
    assert_eq!(
        seal_reason(&prepared, &empty, &candidates),
        SdistDerivedWheelManualReviewReasonV1::MultipleDerivedWheelsProduced
    );
}

#[test]
fn derived_identity_dependencies_native_tags_and_invalid_record_never_seal() {
    let source = pep517_source();
    let closure = closure_fixture();
    let prepared = prepared(&source, &closure);
    let hook = empty_hook(&prepared);

    let drift = simple_wheel(SimpleWheelSpec {
        display_name: "other-package",
        normalized_name: "other-package",
        version: "2.0.0",
        tag: "py3-none-any",
        pure: true,
        metadata_extra: "",
        package_members: &[("other_package/__init__.py", b"DRIFT = True\n")],
        entry_points: None,
    });
    assert_eq!(
        seal_reason(
            &prepared,
            &hook,
            &[DerivedWheelCandidateV1 {
                artifact_filename: &drift.0,
                artifact_bytes: &drift.1,
            }]
        ),
        SdistDerivedWheelManualReviewReasonV1::DerivedWheelIdentityDrift
    );

    let dependency = simple_wheel(SimpleWheelSpec {
        display_name: "nested-sdist",
        normalized_name: "nested-sdist",
        version: "2.0.0",
        tag: "py3-none-any",
        pure: true,
        metadata_extra: "Requires-Dist: requests>=2\n",
        package_members: &[("actual/__init__.py", b"DEPENDENCY = True\n")],
        entry_points: None,
    });
    assert_eq!(
        seal_reason(
            &prepared,
            &hook,
            &[DerivedWheelCandidateV1 {
                artifact_filename: &dependency.0,
                artifact_bytes: &dependency.1,
            }]
        ),
        SdistDerivedWheelManualReviewReasonV1::DerivedWheelRuntimeDependenciesUnsupported
    );

    let native = simple_wheel(SimpleWheelSpec {
        display_name: "nested-sdist",
        normalized_name: "nested-sdist",
        version: "2.0.0",
        tag: "cp312-cp312-macosx_11_0_arm64",
        pure: false,
        metadata_extra: "",
        package_members: &[("actual/native.so", b"inert native inventory")],
        entry_points: None,
    });
    assert_eq!(
        seal_reason(
            &prepared,
            &hook,
            &[DerivedWheelCandidateV1 {
                artifact_filename: &native.0,
                artifact_bytes: &native.1,
            }]
        ),
        SdistDerivedWheelManualReviewReasonV1::DerivedWheelNativeOrTagUnsupported
    );

    let (filename, invalid_record) = derived_wheel_with_invalid_record();
    assert_eq!(
        seal_reason(
            &prepared,
            &hook,
            &[DerivedWheelCandidateV1 {
                artifact_filename: &filename,
                artifact_bytes: &invalid_record,
            }]
        ),
        SdistDerivedWheelManualReviewReasonV1::DerivedWheelInvalid
    );
}

#[test]
fn canonical_contracts_reject_tampering_and_manifest_rebinding() {
    let source = pep517_source();
    let closure = closure_fixture();
    let prepared = prepared(&source, &closure);
    let hook = empty_hook(&prepared);
    let wheel = derived_wheel();
    let manifest = sealed_manifest(&prepared, &hook, &wheel);

    let canonical = manifest.canonical_json_v1().expect("manifest wire");
    let mut value: serde_json::Value = serde_json::from_slice(&canonical).expect("manifest value");
    value["probes"] = serde_json::json!([{"kind":"install_exact_wheel"}]);
    let tampered = serde_json_canonicalizer::to_vec(&value).expect("canonical tamper");
    assert_eq!(
        decode_and_validate_derived_wheel_probe_manifest_v1(&tampered),
        Err(SdistDerivedWheelContractErrorV1::InvalidProbeManifest)
    );

    let mut changed_wheel = wheel.1.clone();
    changed_wheel.push(0);
    assert_eq!(
        verify_derived_wheel_probe_manifest_v1(
            &manifest,
            &prepared,
            &hook,
            &wheel.0,
            &changed_wheel,
            NormalizationLimits::default(),
        ),
        Err(SdistDerivedWheelContractErrorV1::BindingMismatch)
    );

    let mut noncanonical = b" ".to_vec();
    noncanonical.extend_from_slice(&canonical);
    assert_eq!(
        decode_and_validate_derived_wheel_probe_manifest_v1(&noncanonical),
        Err(SdistDerivedWheelContractErrorV1::InvalidWire)
    );
}

#[test]
fn recomputed_probe_hash_cannot_replay_a_same_coordinate_source() {
    let original_source = pep517_source();
    let replay_source = pep517_source_with_extra_member();
    assert_eq!(
        &original_source.envelope.source_coordinate,
        &replay_source.envelope.source_coordinate
    );
    assert_eq!(
        original_source.artifact.manifest.identity.as_ref(),
        replay_source.artifact.manifest.identity.as_ref()
    );
    assert_ne!(&original_source.bytes, &replay_source.bytes);

    let closure = closure_fixture();
    let original_prepared = prepared(&original_source, &closure);
    let replay_prepared = prepared(&replay_source, &closure);
    let original_hook = empty_hook(&original_prepared);
    let replay_hook = empty_hook(&replay_prepared);
    let wheel = derived_wheel();
    let original_manifest = sealed_manifest(&original_prepared, &original_hook, &wheel);

    // Model an attacker who rewrites every exposed source binding and then recomputes the
    // unkeyed structural hash. Decoding succeeds, but caller-supplied expected build/hook
    // authority still rejects the cross-source replay.
    let mut value: serde_json::Value = serde_json::from_slice(
        &original_manifest
            .canonical_json_v1()
            .expect("original manifest wire"),
    )
    .expect("original manifest value");
    value["source_artifact_sha256"] =
        serde_json::to_value(replay_prepared.source_artifact_sha256())
            .expect("source digest value");
    value["source_envelope_sha256"] =
        serde_json::to_value(replay_prepared.source_envelope_sha256())
            .expect("envelope digest value");
    value["source_manifest_sha256"] =
        serde_json::to_value(replay_prepared.source_manifest_sha256())
            .expect("manifest digest value");
    value["prepared_build_sha256"] = serde_json::to_value(replay_prepared.prepared_build_sha256())
        .expect("prepared digest value");
    value["get_requires_result_sha256"] =
        serde_json::to_value(replay_hook.result_sha256()).expect("hook digest value");
    let object = value.as_object_mut().expect("manifest object");
    object.remove("probe_manifest_sha256");
    let digest_wire = serde_json_canonicalizer::to_vec(&value).expect("replay digest wire");
    value["probe_manifest_sha256"] =
        serde_json::to_value(Sha256Digest::from_bytes(&digest_wire)).expect("probe digest value");
    let replay_wire = serde_json_canonicalizer::to_vec(&value).expect("replay manifest wire");
    let replay_manifest = decode_and_validate_derived_wheel_probe_manifest_v1(&replay_wire)
        .expect("self-consistent recomputed replay manifest");

    assert_eq!(
        verify_derived_wheel_probe_manifest_v1(
            &replay_manifest,
            &original_prepared,
            &original_hook,
            &wheel.0,
            &wheel.1,
            NormalizationLimits::default(),
        ),
        Err(SdistDerivedWheelContractErrorV1::BindingMismatch)
    );
    verify_derived_wheel_probe_manifest_v1(
        &replay_manifest,
        &replay_prepared,
        &replay_hook,
        &wheel.0,
        &wheel.1,
        NormalizationLimits::default(),
    )
    .expect("recomputed manifest remains a valid structural binding for replay source only");
}
