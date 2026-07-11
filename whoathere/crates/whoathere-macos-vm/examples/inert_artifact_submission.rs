use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{self, Cursor};
use whoathere_artifact::{
    normalize_artifact, AcquisitionMethod, ArtifactEnvelope, ArtifactEnvelopeInput, ArtifactFormat,
    ArtifactSourceType, Ecosystem, NormalizationLimits, Sha256Digest,
};
use whoathere_detonation::{
    compile_artifact_scenarios_v1, ArtifactScenarioCompilationRequestV1,
    ArtifactScenarioExecutionIdentityV1, ArtifactScenarioIdentitySetV1, ArtifactScenarioPolicyV1,
    NpmRuntimeProfileV1,
};
use whoathere_evidence::v2::{canonical_cas_object_key_for_artifact, ArtifactEvidenceSubjectV2};
use whoathere_macos_vm::{
    compile_macos_artifact_run_spec_v1, write_macos_artifact_submission_frame_v1,
    MacosArtifactBackendCapabilitiesV1, MacosArtifactBackendIdentityV1,
    MacosArtifactSubmissionBindingsV1, MacosArtifactSubmissionHeaderV1,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = npm_tgz(&[
        (
            "package/package.json",
            br#"{"name":"rust-swift-protocol-fixture","version":"1.0.0","scripts":{"postinstall":"node post.js"}}"#,
        ),
        ("package/post.js", b"process.exit(0)"),
    ])?;
    let envelope = ArtifactEnvelope::from_original_bytes(
        ArtifactEnvelopeInput {
            ecosystem: Ecosystem::Npm,
            package_name: Some("rust-swift-protocol-fixture".to_string()),
            package_version: Some("1.0.0".to_string()),
            source_coordinate: "fixture:rust-swift-protocol-fixture@1.0.0".to_string(),
            source_type: ArtifactSourceType::LocalFile,
            acquired_at: "2026-07-10T00:00:00Z".to_string(),
            acquisition_method: AcquisitionMethod::LocalInertFixture,
            original_filename: "rust-swift-protocol-fixture-1.0.0.tgz".to_string(),
            declared_format: Some(ArtifactFormat::NpmTarGzip),
            custody_reference: "repository-inert-cross-language-fixture".to_string(),
            resolver_metadata_sha256: None,
            registry_metadata_sha256: None,
            policy_version: "macos-artifact-protocol-smoke.v1".to_string(),
            requires_external_dependency_resolution: false,
        },
        &bytes,
        ArtifactFormat::NpmTarGzip,
    );
    let artifact = normalize_artifact(&envelope, &bytes, NormalizationLimits::default())?;
    let cas_key = canonical_cas_object_key_for_artifact(artifact.manifest.artifact_sha256.as_str())
        .map_err(|_| io::Error::other("could not derive the canonical artifact CAS key"))?;
    let subject = ArtifactEvidenceSubjectV2::new(
        artifact.manifest.artifact_sha256.as_str(),
        envelope.envelope_sha256()?.as_str(),
        artifact.manifest.manifest_sha256.as_str(),
        cas_key,
    )
    .map_err(|_| io::Error::other("could not construct the artifact evidence subject"))?;
    let node_sha256 = Sha256Digest::from_bytes(b"cross-language measured node");
    let npm_sha256 = Sha256Digest::from_bytes(b"cross-language measured npm");
    let runtime = NpmRuntimeProfileV1::new(
        "macos-arm64-node22-npm11-cross-language-inert",
        "22.17.0",
        node_sha256.clone(),
        "11.18.0",
        npm_sha256.clone(),
    )?;
    let policy = ArtifactScenarioPolicyV1::inert_qualification_only(
        envelope.original_sha256.clone(),
        runtime,
    )?;
    let identities = ArtifactScenarioIdentitySetV1::new(
        "cross-language-plan",
        ArtifactScenarioExecutionIdentityV1::new(
            "cross-language-job-false",
            "cross-language-run-false",
            "cross-language-evidence-false",
            "cross-language-scenario-false",
        )?,
        ArtifactScenarioExecutionIdentityV1::new(
            "cross-language-job-true",
            "cross-language-run-true",
            "cross-language-evidence-true",
            "cross-language-scenario-true",
        )?,
    )?;
    let plan = compile_artifact_scenarios_v1(ArtifactScenarioCompilationRequestV1 {
        envelope: &envelope,
        manifest: &artifact.manifest,
        subject: &subject,
        policy: &policy,
        identities: &identities,
    })?;
    let backend =
        MacosArtifactBackendCapabilitiesV1::inert_first_slice(MacosArtifactBackendIdentityV1::new(
            "cross-language-base-generation",
            Sha256Digest::from_bytes(b"cross-language base disk"),
            Sha256Digest::from_bytes(b"cross-language auxiliary storage"),
            Sha256Digest::from_bytes(b"cross-language hardware model"),
            Sha256Digest::from_bytes(b"cross-language machine identifier"),
            4,
            6_144,
            Sha256Digest::from_bytes(b"cross-language provisioning receipt"),
            Sha256Digest::from_bytes(b"cross-language helper"),
            Sha256Digest::from_bytes(b"cross-language supervisor"),
            Sha256Digest::from_bytes(b"cross-language runner"),
            "22.17.0",
            node_sha256,
            "11.18.0",
            npm_sha256,
            Sha256Digest::from_bytes(b"cross-language APFS clone implementation"),
        )?);
    let run_spec = compile_macos_artifact_run_spec_v1(&plan.templates()[0], &backend)?;
    let bindings = MacosArtifactSubmissionBindingsV1::for_run_spec(
        Sha256Digest::from_bytes(b"cross-language challenge"),
        &run_spec,
    );
    let header = MacosArtifactSubmissionHeaderV1::new(run_spec, bindings)?;
    write_macos_artifact_submission_frame_v1(&mut io::stdout().lock(), &header, &bytes)?;
    Ok(())
}

fn npm_tgz(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, io::Error> {
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
        archive.append_data(&mut header, *path, Cursor::new(*bytes))?;
    }
    archive.into_inner()?.finish()
}
