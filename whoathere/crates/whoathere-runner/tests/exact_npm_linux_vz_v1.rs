use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::Cursor;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::{NormalizationLimits, Sha256Digest};
use whoathere_runner::{
    inspect_exact_artifact_v1, ExactArtifactDispositionV1, ExactArtifactInspectionRequestV1,
    ExactArtifactStageStatusV1, LinuxVzExactNpmDetonationAdapterV1,
    LinuxVzExactNpmDetonationConfigV1,
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

fn npm_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "package/package.json",
        br#"{"name":"detonation-inert","version":"1.0.0","scripts":{"postinstall":"node postinstall.js"}}"#,
    );
    append_tar_file(
        &mut archive,
        "package/postinstall.js",
        b"process.stdout.write('inert');\n",
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn npm_main_with_dev_dependencies_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "package/package.json",
        br#"{"name":"detonation-main-dev-only","version":"1.0.0","main":"index.js","bin":{"detonation-main-dev-only":"cli.js"},"scripts":{"postinstall":"node postinstall.js"},"devDependencies":{"rollup":"1.0.0"}}"#,
    );
    append_tar_file(
        &mut archive,
        "package/postinstall.js",
        b"process.stdout.write('inert');\n",
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

fn npm_runtime_dependency_tgz() -> Vec<u8> {
    let encoder = GzEncoder::new(Vec::new(), Compression::default());
    let mut archive = tar::Builder::new(encoder);
    append_tar_file(
        &mut archive,
        "package/package.json",
        br#"{"name":"detonation-runtime-dependency","version":"1.0.0","scripts":{"postinstall":"node postinstall.js"},"dependencies":{"left-pad":"1.3.0"}}"#,
    );
    append_tar_file(
        &mut archive,
        "package/postinstall.js",
        b"process.stdout.write('inert');\n",
    );
    archive
        .into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip")
}

fn write_mock_helper(root: &std::path::Path, artifact_sha256: &str) -> std::path::PathBuf {
    let path = root.join("mock-linux-vz-helper.sh");
    let script = format!(
        r#"#!/bin/sh
artifact=""
environment=""
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --artifact) artifact="$2" ;;
    --artifact-envelope) artifact_envelope="$2" ;;
    --artifact-manifest) artifact_manifest="$2" ;;
    --artifact-kind) artifact_kind="$2" ;;
    --build-closure) build_closure="$2" ;;
    --environment) environment="$2" ;;
    --output-directory) output="$2" ;;
  esac
  shift 2
done
cp "$artifact" "$output/seen-artifact.bin"
cp "$artifact_envelope" "$output/seen-artifact-envelope.json"
cp "$artifact_manifest" "$output/seen-artifact-manifest.json"
if [ -n "$build_closure" ]; then
  cp "$build_closure" "$output/seen-dependency-closure.frame"
fi
printf '%s\n' "$artifact_kind" > "$output/seen-artifact-kind.txt"
printf '%s\n' "$environment" > "$output/seen-environment.txt"
printf '{{"schema_version":"whoathere.linux_vz_package_execution_result.v1","status":"package_process_complete_evidence_pending_host_composition","environment":"%s","artifact_sha256":"{artifact_sha256}","authoritative_verdict_permitted":false,"public_network_route_present":false,"vm_started":true,"vm_stopped":true,"clone_destroyed":true,"image_identity_stable":true,"package_execution":true,"sync_back":false}}\n' "$environment"
"#
    );
    std::fs::write(&path, script.as_bytes()).expect("write mock helper");
    let mut permissions = std::fs::metadata(&path)
        .expect("mock helper metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("make mock helper executable");
    path
}

fn write_failed_mock_helper(root: &std::path::Path) -> std::path::PathBuf {
    let path = root.join("mock-linux-vz-failed-helper.sh");
    let script = r#"#!/bin/sh
environment=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --environment) environment="$2" ;;
  esac
  shift 2
done
printf 'NPM_TOKEN_CANARY_SECRET raw package stdout\n' >&2
printf '{"schema_version":"whoathere.linux_vz_package_execution_result.v1","status":"failed_closed","reason":"builder_execution_bundle_exit_74","environment":"%s","authoritative_verdict_permitted":false,"public_network_route_present":false,"vm_started":false,"vm_stopped":false,"clone_destroyed":false,"image_identity_stable":false,"package_execution":false,"sync_back":false}\n' "$environment"
exit 70
"#;
    std::fs::write(&path, script.as_bytes()).expect("write failed mock helper");
    let mut permissions = std::fs::metadata(&path)
        .expect("failed mock helper metadata")
        .permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&path, permissions).expect("make failed mock helper executable");
    path
}

fn adapter_config(
    root: &std::path::Path,
    helper_path: std::path::PathBuf,
) -> LinuxVzExactNpmDetonationConfigV1 {
    let input = root.join("input.bin");
    std::fs::write(&input, b"inert runtime input").expect("write inert runtime input");
    let runtime_directory = root.join("runtime");
    std::fs::create_dir(&runtime_directory).expect("create inert runtime directory");
    let helper_sha256 = Sha256Digest::from_bytes(
        &std::fs::read(&helper_path).expect("read mock helper for identity"),
    )
    .to_string();
    LinuxVzExactNpmDetonationConfigV1 {
        helper_path,
        kernel_path: input.clone(),
        base_initramfs_path: input.clone(),
        runtime_directory,
        bundle_builder_path: input.clone(),
        image_builder_path: input.clone(),
        backend_identity_path: input.clone(),
        qualified_backend_path: input.clone(),
        qualification_record_path: input.clone(),
        guest_public_key_path: input.clone(),
        host_public_key_path: input.clone(),
        grant_public_key_path: input.clone(),
        grant_signing_seed_path: input.clone(),
        guest_signing_seed_path: input,
        dependency_closure_path: None,
        output_root: root.join("evidence-output"),
        timeout_seconds: 60,
        helper_sha256: Some(helper_sha256),
    }
}

#[test]
fn exact_npm_adapter_runs_both_ci_profiles_with_the_verified_artifact_bytes() {
    let root = TempRoot::new("whoathere-exact-npm-linux-vz");
    let artifact = npm_tgz();
    let artifact_sha256 = Sha256Digest::from_bytes(&artifact).to_string();
    let artifact_path = root.path().join("detonation-inert-1.0.0.tgz");
    std::fs::write(&artifact_path, &artifact).expect("write exact npm fixture");
    let helper_path = write_mock_helper(root.path(), &artifact_sha256);
    let config = adapter_config(root.path(), helper_path);
    let output_root = config.output_root.clone();
    let adapter = LinuxVzExactNpmDetonationAdapterV1::new(config).expect("ready mock adapter");

    let report = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &artifact_path,
            quarantine_root: &root.path().join("cas"),
            ecosystem: None,
            acquired_at: "2026-07-15T12:34:56Z",
            ai_requested: false,
            ai_provider: None,
            behavior_observation_requested: false,
            detonation_requested: true,
            normalization_limits: NormalizationLimits::default(),
        },
        None,
        Some(&adapter),
    )
    .expect("run exact npm detonation adapter");

    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert_eq!(
        report.scenario_plan.status,
        ExactArtifactStageStatusV1::Complete
    );
    assert_eq!(report.scenario_plan.runtime_binding_status, "verified");
    assert!(report.scenario_plan.executable);
    let detonation = report
        .stages
        .iter()
        .find(|stage| stage.stage == "detonation")
        .expect("detonation stage");
    assert_eq!(detonation.status, ExactArtifactStageStatusV1::Incomplete);
    assert!(detonation
        .reason_codes
        .contains(&"vm_evidence_captured_pending_analysis".to_string()));
    assert!(detonation
        .reason_codes
        .contains(&"vm_evidence_output_preserved".to_string()));

    let run_roots = std::fs::read_dir(&output_root)
        .expect("read retained output root")
        .map(|entry| entry.expect("retained run entry").path())
        .collect::<Vec<_>>();
    assert_eq!(run_roots.len(), 1);
    for environment in ["ci_false", "ci_true"] {
        let evidence = run_roots[0].join(environment).join("evidence");
        assert_eq!(
            std::fs::read(evidence.join("seen-artifact.bin")).expect("mock saw artifact"),
            artifact
        );
        assert_eq!(
            std::fs::read_to_string(evidence.join("seen-environment.txt"))
                .expect("mock saw environment"),
            format!("{environment}\n")
        );
        assert_eq!(
            std::fs::read_to_string(evidence.join("seen-artifact-kind.txt"))
                .expect("mock saw artifact kind"),
            "npm_tgz\n"
        );
        assert_eq!(
            std::fs::read(run_roots[0].join(environment).join("artifact.tgz"))
                .expect("retained materialized artifact"),
            artifact
        );
        let envelope: serde_json::Value = serde_json::from_slice(
            &std::fs::read(evidence.join("seen-artifact-envelope.json"))
                .expect("mock saw artifact envelope"),
        )
        .expect("artifact envelope JSON");
        assert_eq!(envelope["acquired_at"], "2026-07-15T12:34:56Z");
        assert!(envelope["custody_reference"]
            .as_str()
            .is_some_and(|value| value.starts_with("quarantine-cas:")));
        assert_eq!(envelope["policy_version"], "exact-artifact-inspection-v1");
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(evidence.join("seen-artifact-manifest.json"))
                .expect("mock saw artifact manifest"),
        )
        .expect("artifact manifest JSON");
        assert_eq!(manifest["artifact_sha256"], artifact_sha256);
    }
    assert!(!report.observed_clean);
    assert!(!report.admission_authority);
    assert!(!report.sync_back_enabled);
}

#[test]
fn exact_npm_adapter_runs_planned_install_profiles_and_retains_other_trigger_gaps() {
    let root = TempRoot::new("whoathere-exact-npm-linux-vz-partial");
    let artifact = npm_main_with_dev_dependencies_tgz();
    let artifact_sha256 = Sha256Digest::from_bytes(&artifact).to_string();
    let artifact_path = root.path().join("detonation-main-dev-only-1.0.0.tgz");
    std::fs::write(&artifact_path, &artifact).expect("write exact npm fixture");
    let helper_path = write_mock_helper(root.path(), &artifact_sha256);
    let config = adapter_config(root.path(), helper_path);
    let output_root = config.output_root.clone();
    let adapter = LinuxVzExactNpmDetonationAdapterV1::new(config).expect("ready mock adapter");

    let report = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &artifact_path,
            quarantine_root: &root.path().join("cas"),
            ecosystem: None,
            acquired_at: "2026-07-16T12:34:56Z",
            ai_requested: false,
            ai_provider: None,
            behavior_observation_requested: false,
            detonation_requested: true,
            normalization_limits: NormalizationLimits::default(),
        },
        None,
        Some(&adapter),
    )
    .expect("run partial exact npm detonation adapter");

    assert_eq!(
        report.scenario_plan.status,
        ExactArtifactStageStatusV1::Incomplete
    );
    assert_eq!(report.scenario_plan.runtime_binding_status, "verified");
    assert!(report.scenario_plan.executable);
    assert_eq!(report.scenario_plan.intents.len(), 2);
    assert!(!report
        .reason_codes
        .contains(&"exact_artifact_dependency_closure_required".to_string()));
    assert!(report
        .scenario_plan
        .reason_codes
        .contains(&"exact_artifact_npm_main_or_export_probe_runtime_not_qualified".to_string()));
    assert!(report
        .scenario_plan
        .reason_codes
        .contains(&"exact_artifact_npm_bin_probe_runtime_not_qualified".to_string()));
    let detonation = report
        .stages
        .iter()
        .find(|stage| stage.stage == "detonation")
        .expect("detonation stage");
    assert!(detonation
        .reason_codes
        .contains(&"vm_evidence_captured_pending_analysis".to_string()));

    let run_roots = std::fs::read_dir(&output_root)
        .expect("read retained output root")
        .map(|entry| entry.expect("retained run entry").path())
        .collect::<Vec<_>>();
    assert_eq!(run_roots.len(), 1);
    for environment in ["ci_false", "ci_true"] {
        let evidence = run_roots[0].join(environment).join("evidence");
        assert_eq!(
            std::fs::read_to_string(evidence.join("seen-environment.txt"))
                .expect("mock saw environment"),
            format!("{environment}\n")
        );
    }
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!report.observed_clean);
    assert!(!report.admission_authority);
    assert!(!report.sync_back_enabled);
}

#[test]
fn exact_npm_adapter_runs_both_profiles_with_the_exact_sealed_dependency_closure() {
    let root = TempRoot::new("whoathere-exact-npm-linux-vz-runtime-dependency");
    let artifact = npm_runtime_dependency_tgz();
    let artifact_sha256 = Sha256Digest::from_bytes(&artifact).to_string();
    let artifact_path = root.path().join("detonation-runtime-dependency-1.0.0.tgz");
    std::fs::write(&artifact_path, &artifact).expect("write exact npm fixture");
    let helper_path = write_mock_helper(root.path(), &artifact_sha256);
    // The adapter is a custody/pass-through boundary. Structural frame and payload validation is
    // performed by the execution-bundle builder, whose tests use the real frame encoder.
    let dependency_closure = b"opaque sealed dependency closure frame".to_vec();
    let dependency_closure_path = root.path().join("dependency-closure.frame");
    std::fs::write(&dependency_closure_path, &dependency_closure)
        .expect("write exact dependency closure");
    let mut config = adapter_config(root.path(), helper_path);
    config.dependency_closure_path = Some(dependency_closure_path);
    let output_root = config.output_root.clone();
    let adapter = LinuxVzExactNpmDetonationAdapterV1::new(config).expect("ready mock adapter");

    let report = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &artifact_path,
            quarantine_root: &root.path().join("cas"),
            ecosystem: None,
            acquired_at: "2026-07-16T12:34:56Z",
            ai_requested: false,
            ai_provider: None,
            behavior_observation_requested: false,
            detonation_requested: true,
            normalization_limits: NormalizationLimits::default(),
        },
        None,
        Some(&adapter),
    )
    .expect("runtime dependency closure remains a supported inconclusive result");

    assert_eq!(
        report.scenario_plan.status,
        ExactArtifactStageStatusV1::Incomplete
    );
    assert_eq!(report.scenario_plan.runtime_binding_status, "verified");
    assert!(report.scenario_plan.executable);
    assert!(report
        .reason_codes
        .contains(&"exact_artifact_dependency_closure_required".to_string()));
    let detonation = report
        .stages
        .iter()
        .find(|stage| stage.stage == "detonation")
        .expect("detonation stage");
    assert!(detonation
        .reason_codes
        .contains(&"vm_evidence_captured_pending_analysis".to_string()));
    let run_roots = std::fs::read_dir(&output_root)
        .expect("read retained output root")
        .map(|entry| entry.expect("retained run entry").path())
        .collect::<Vec<_>>();
    assert_eq!(run_roots.len(), 1);
    for environment in ["ci_false", "ci_true"] {
        let retained = std::fs::read(
            run_roots[0]
                .join(environment)
                .join("evidence/seen-dependency-closure.frame"),
        )
        .expect("mock saw dependency closure");
        assert_eq!(retained, dependency_closure);
    }
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!report.observed_clean);
    assert!(!report.admission_authority);
    assert!(!report.sync_back_enabled);
}

#[test]
fn exact_npm_adapter_keeps_missing_dependency_closure_inconclusive_and_unexecuted() {
    let root = TempRoot::new("whoathere-exact-npm-linux-vz-missing-closure");
    let artifact = npm_runtime_dependency_tgz();
    let artifact_sha256 = Sha256Digest::from_bytes(&artifact).to_string();
    let artifact_path = root.path().join("detonation-runtime-dependency-1.0.0.tgz");
    std::fs::write(&artifact_path, &artifact).expect("write exact npm fixture");
    let helper_path = write_mock_helper(root.path(), &artifact_sha256);
    let config = adapter_config(root.path(), helper_path);
    let output_root = config.output_root.clone();
    let adapter = LinuxVzExactNpmDetonationAdapterV1::new(config).expect("ready mock adapter");

    let report = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &artifact_path,
            quarantine_root: &root.path().join("cas"),
            ecosystem: None,
            acquired_at: "2026-07-16T12:34:56Z",
            ai_requested: false,
            ai_provider: None,
            behavior_observation_requested: false,
            detonation_requested: true,
            normalization_limits: NormalizationLimits::default(),
        },
        None,
        Some(&adapter),
    )
    .expect("missing closure remains an inconclusive result");

    assert_eq!(report.scenario_plan.runtime_binding_status, "not_bound");
    assert!(!report.scenario_plan.executable);
    assert!(report
        .reason_codes
        .contains(&"exact_artifact_dependency_closure_required".to_string()));
    assert!(!output_root.exists(), "helper must not run without closure");
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!report.observed_clean);
}

#[test]
fn exact_npm_failed_helper_exposes_only_a_typed_failure_class() {
    let root = TempRoot::new("whoathere-exact-npm-linux-vz-failed-helper");
    let artifact = npm_tgz();
    let artifact_path = root.path().join("detonation-inert-1.0.0.tgz");
    std::fs::write(&artifact_path, &artifact).expect("write exact npm fixture");
    let helper_path = write_failed_mock_helper(root.path());
    let config = adapter_config(root.path(), helper_path);
    let adapter = LinuxVzExactNpmDetonationAdapterV1::new(config).expect("ready failed adapter");

    let report = inspect_exact_artifact_v1(
        ExactArtifactInspectionRequestV1 {
            artifact_path: &artifact_path,
            quarantine_root: &root.path().join("cas"),
            ecosystem: None,
            acquired_at: "2026-07-16T12:34:56Z",
            ai_requested: false,
            ai_provider: None,
            behavior_observation_requested: false,
            detonation_requested: true,
            normalization_limits: NormalizationLimits::default(),
        },
        None,
        Some(&adapter),
    )
    .expect("failed helper remains an inconclusive product result");

    for environment in ["ci_false", "ci_true"] {
        assert!(report
            .reason_codes
            .contains(&format!("vm_{environment}_helper_process_failed")));
        assert!(report.reason_codes.contains(&format!(
            "vm_{environment}_helper_failure_execution_bundle_exit"
        )));
    }
    let report_json = serde_json::to_string(&report).expect("serialize report");
    assert!(!report_json.contains("builder_execution_bundle_exit_74"));
    assert!(!report_json.contains("NPM_TOKEN_CANARY_SECRET"));
    assert!(!report_json.contains("raw package stdout"));
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!report.observed_clean);
    assert!(!report.admission_authority);
    assert!(!report.sync_back_enabled);
}
