use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Cursor;
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits,
};
use whoathere_runner::{
    project_offline_exact_sdist_behavior_v1, OfflineExactSdistBehaviorProjectionRequestV1,
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

fn pep517_sdist(marker: &[u8]) -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "offline-sdist-1.0.0/PKG-INFO",
        b"Metadata-Version: 2.3\nName: offline-sdist\nVersion: 1.0.0\n",
    );
    append_tar_file(
        &mut archive,
        "offline-sdist-1.0.0/pyproject.toml",
        b"[build-system]\nrequires = []\nbuild-backend = \"setuptools.build_meta\"\n\n[project]\nname = \"offline-sdist\"\nversion = \"1.0.0\"\n",
    );
    append_tar_file(
        &mut archive,
        "offline-sdist-1.0.0/src/offline_sdist/__init__.py",
        marker,
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn envelope(bytes: &[u8]) -> ArtifactEnvelope {
    ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Pypi,
            package_name: Some("offline-sdist".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:offline-sdist@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-16T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "offline-sdist-1.0.0.tar.gz".to_string(),
            declared_format: Some(ArtifactFormat::SdistTarGzip),
            custody_reference: "inert-fixture:offline-sdist-1.0.0.tar.gz".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "offline-sdist-projection-test.v1".to_string(),
            requires_external_dependency_resolution: true,
        },
        bytes,
        ArtifactFormat::SdistTarGzip,
    )
}

struct RetainedOuterBindings {
    artifact_path: std::path::PathBuf,
    envelope_path: std::path::PathBuf,
    manifest_path: std::path::PathBuf,
    evidence_directory: std::path::PathBuf,
}

fn retain_outer_bindings(root: &std::path::Path, artifact_bytes: &[u8]) -> RetainedOuterBindings {
    let artifact_path = root.join("artifact.bin");
    let envelope_path = root.join("artifact-envelope.json");
    let manifest_path = root.join("artifact-manifest.json");
    let evidence_directory = root.join("evidence");
    let envelope = envelope(artifact_bytes);
    let normalized = normalize_artifact(&envelope, artifact_bytes, NormalizationLimits::default())
        .expect("normalize inert PEP 517 sdist");
    std::fs::write(&artifact_path, artifact_bytes).expect("retain exact artifact");
    std::fs::write(
        &envelope_path,
        envelope.canonical_json().expect("canonical envelope"),
    )
    .expect("retain canonical envelope");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec(&normalized.manifest).expect("canonical manifest"),
    )
    .expect("retain canonical manifest");
    std::fs::create_dir(&evidence_directory).expect("create retained evidence directory");
    std::fs::write(evidence_directory.join("retained-marker.txt"), b"unchanged")
        .expect("write retained evidence marker");
    RetainedOuterBindings {
        artifact_path,
        envelope_path,
        manifest_path,
        evidence_directory,
    }
}

fn request<'a>(
    retained: &'a RetainedOuterBindings,
    scenario_index: usize,
) -> OfflineExactSdistBehaviorProjectionRequestV1<'a> {
    OfflineExactSdistBehaviorProjectionRequestV1 {
        artifact_path: &retained.artifact_path,
        artifact_envelope_path: &retained.envelope_path,
        artifact_manifest_path: &retained.manifest_path,
        evidence_directory: &retained.evidence_directory,
        scenario_index,
        normalization_limits: NormalizationLimits::default(),
    }
}

#[test]
fn offline_sdist_projection_accepts_exact_outer_bindings_without_mutating_evidence() {
    let root = TempRoot::new("whoathere-offline-exact-sdist");
    let retained = retain_outer_bindings(root.path(), &pep517_sdist(b"VALUE = 'inert'\n"));
    let entries_before = std::fs::read_dir(&retained.evidence_directory)
        .expect("read evidence directory before projection")
        .map(|entry| entry.expect("evidence entry").file_name())
        .collect::<Vec<_>>();
    let marker_before = std::fs::read(retained.evidence_directory.join("retained-marker.txt"))
        .expect("read retained marker before projection");

    let error = project_offline_exact_sdist_behavior_v1(request(&retained, 0))
        .expect_err("fixture deliberately omits helper evidence");

    assert_eq!(
        error.reason_code(),
        "sdist_behavior_projection_evidence_unavailable",
        "all exact artifact, envelope, manifest, and scenario bindings were accepted before the shared read-only projector requested evidence"
    );
    assert_eq!(
        std::fs::read_dir(&retained.evidence_directory)
            .expect("read evidence directory after projection")
            .map(|entry| entry.expect("evidence entry").file_name())
            .collect::<Vec<_>>(),
        entries_before
    );
    assert_eq!(
        std::fs::read(retained.evidence_directory.join("retained-marker.txt"))
            .expect("read retained marker after projection"),
        marker_before
    );
    assert!(!retained
        .evidence_directory
        .join("behavior-bundle.json")
        .exists());
}

#[test]
fn offline_sdist_projection_rejects_artifact_manifest_and_scenario_substitution() {
    let root = TempRoot::new("whoathere-offline-exact-sdist-substitution");
    let original = pep517_sdist(b"VALUE = 'original'\n");
    let retained = retain_outer_bindings(root.path(), &original);

    let substituted_artifact_path = root.path().join("substituted-artifact.bin");
    let substituted = pep517_sdist(b"VALUE = 'substituted'\n");
    std::fs::write(&substituted_artifact_path, &substituted).expect("write substituted artifact");
    let artifact_error =
        project_offline_exact_sdist_behavior_v1(OfflineExactSdistBehaviorProjectionRequestV1 {
            artifact_path: &substituted_artifact_path,
            ..request(&retained, 0)
        })
        .expect_err("artifact substitution must fail closed");
    assert_eq!(
        artifact_error.reason_code(),
        "sdist_behavior_projection_artifact_envelope_binding_mismatch"
    );

    let substituted_envelope = envelope(&substituted);
    let substituted_manifest = normalize_artifact(
        &substituted_envelope,
        &substituted,
        NormalizationLimits::default(),
    )
    .expect("normalize substituted inert sdist")
    .manifest;
    let substituted_manifest_path = root.path().join("substituted-manifest.json");
    std::fs::write(
        &substituted_manifest_path,
        serde_json::to_vec(&substituted_manifest).expect("canonical substituted manifest"),
    )
    .expect("write substituted manifest");
    let manifest_error =
        project_offline_exact_sdist_behavior_v1(OfflineExactSdistBehaviorProjectionRequestV1 {
            artifact_manifest_path: &substituted_manifest_path,
            ..request(&retained, 0)
        })
        .expect_err("manifest substitution must fail closed");
    assert_eq!(
        manifest_error.reason_code(),
        "sdist_behavior_projection_artifact_manifest_binding_mismatch"
    );

    let scenario_error = project_offline_exact_sdist_behavior_v1(request(&retained, usize::MAX))
        .expect_err("scenario substitution must fail closed");
    assert_eq!(
        scenario_error.reason_code(),
        "sdist_behavior_projection_scenario_index_invalid"
    );
}
