use std::io::{Cursor, Write};
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::{NormalizationLimits, Sha256Digest};
use whoathere_runner::{
    inspect_exact_artifact_v1, ExactArtifactDispositionV1, ExactArtifactInspectionRequestV1,
    ExactArtifactStageStatusV1, LinuxVzExactWheelDetonationAdapterV1,
    LinuxVzExactWheelDetonationConfigV1,
};
use zip::write::SimpleFileOptions;

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

fn wheel_zip() -> Vec<u8> {
    wheel_zip_with_metadata_extra("")
}

fn wheel_zip_with_metadata_extra(metadata_extra: &str) -> Vec<u8> {
    let metadata = format!(
        "Metadata-Version: 2.3\nName: exact-wheel-detonation\nVersion: 1.0.0\n{metadata_extra}"
    );
    const WHEEL: &[u8] = b"Wheel-Version: 1.0\nGenerator: whoathere-test\nRoot-Is-Purelib: true\nTag: py3-none-any\n";
    const ENTRY_POINTS: &[u8] =
        b"[console_scripts]\nexact-wheel = exact_wheel_detonation.cli:main\n";
    const INIT: &[u8] = b"VALUE = 'inert'\n";
    const CLI: &[u8] = b"def main():\n    return 0\n";
    const PTH: &[u8] = b"import exact_wheel_detonation\n";
    let dist_info = "exact_wheel_detonation-1.0.0.dist-info";
    let mut members = vec![
        (format!("{dist_info}/METADATA"), metadata.into_bytes()),
        (format!("{dist_info}/WHEEL"), WHEEL.to_vec()),
        (
            format!("{dist_info}/entry_points.txt"),
            ENTRY_POINTS.to_vec(),
        ),
        (
            "exact_wheel_detonation/__init__.py".to_string(),
            INIT.to_vec(),
        ),
        ("exact_wheel_detonation/cli.py".to_string(), CLI.to_vec()),
        ("exact_wheel_detonation.pth".to_string(), PTH.to_vec()),
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
        writer.write_all(&bytes).expect("write wheel member");
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

fn write_mock_helper(root: &std::path::Path, artifact_sha256: &str) -> std::path::PathBuf {
    let path = root.join("mock-linux-vz-wheel-helper.sh");
    let script = format!(
        r#"#!/bin/sh
artifact=""
artifact_kind=""
scenario_index=""
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --artifact) artifact="$2" ;;
    --artifact-envelope) artifact_envelope="$2" ;;
    --artifact-manifest) artifact_manifest="$2" ;;
    --artifact-kind) artifact_kind="$2" ;;
    --scenario-index) scenario_index="$2" ;;
    --output-directory) output="$2" ;;
  esac
  shift 2
done
cp "$artifact" "$output/seen-artifact.bin"
cp "$artifact_envelope" "$output/seen-artifact-envelope.json"
cp "$artifact_manifest" "$output/seen-artifact-manifest.json"
printf '%s\n' "$artifact_kind" > "$output/seen-artifact-kind.txt"
printf '%s\n' "$scenario_index" > "$output/seen-scenario-index.txt"
printf '{{"schema_version":"whoathere.linux_vz_package_execution_result.v1","status":"package_process_complete_evidence_pending_host_composition","artifact_kind":"wheel","scenario_index":"%s","artifact_sha256":"{artifact_sha256}","authoritative_verdict_permitted":false,"public_network_route_present":false,"vm_started":true,"vm_stopped":true,"clone_destroyed":true,"image_identity_stable":true,"package_execution":true,"sync_back":false}}\n' "$scenario_index"
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
    let path = root.join("mock-linux-vz-wheel-failed-helper.sh");
    let script = r#"#!/bin/sh
scenario_index=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --scenario-index) scenario_index="$2" ;;
  esac
  shift 2
done
printf 'PYPI_TOKEN_CANARY_SECRET raw package stdout\n' >&2
printf '{"schema_version":"whoathere.linux_vz_package_execution_result.v1","status":"failed_closed","reason":"builder_execution_image_exit_70","artifact_kind":"wheel","scenario_index":"%s","authoritative_verdict_permitted":false,"public_network_route_present":false,"vm_started":false,"vm_stopped":false,"clone_destroyed":false,"image_identity_stable":false,"package_execution":false,"sync_back":false}\n' "$scenario_index"
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
) -> LinuxVzExactWheelDetonationConfigV1 {
    let input = root.join("input.bin");
    std::fs::write(&input, b"inert runtime input").expect("write inert runtime input");
    let runtime_directory = root.join("runtime");
    std::fs::create_dir(&runtime_directory).expect("create inert runtime directory");
    let helper_sha256 = Sha256Digest::from_bytes(
        &std::fs::read(&helper_path).expect("read mock helper for identity"),
    )
    .to_string();
    LinuxVzExactWheelDetonationConfigV1 {
        artifact_kind: "pypi_wheel".to_string(),
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
        output_root: root.join("evidence-output"),
        timeout_seconds: 60,
        helper_sha256: Some(helper_sha256),
    }
}

#[test]
fn exact_wheel_adapter_runs_every_intent_with_the_verified_artifact_bytes() {
    let root = TempRoot::new("whoathere-exact-wheel-linux-vz");
    let artifact = wheel_zip();
    let artifact_sha256 = Sha256Digest::from_bytes(&artifact).to_string();
    let artifact_path = root
        .path()
        .join("exact_wheel_detonation-1.0.0-py3-none-any.whl");
    std::fs::write(&artifact_path, &artifact).expect("write exact wheel fixture");
    let helper_path = write_mock_helper(root.path(), &artifact_sha256);
    let config = adapter_config(root.path(), helper_path);
    let output_root = config.output_root.clone();
    let mut wrong_kind = config.clone();
    wrong_kind.artifact_kind = "npm_tarball".to_string();
    assert_eq!(
        LinuxVzExactWheelDetonationAdapterV1::new(wrong_kind)
            .expect_err("wheel config discriminator must fail closed")
            .reason_code(),
        "linux_vz_exact_wheel_artifact_kind_invalid"
    );
    let adapter = LinuxVzExactWheelDetonationAdapterV1::new(config).expect("ready mock adapter");

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
    .expect("run exact wheel detonation adapter");

    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert_eq!(report.identity.artifact_sha256, artifact_sha256);
    assert_eq!(
        report.scenario_plan.status,
        ExactArtifactStageStatusV1::Complete
    );
    assert_eq!(report.scenario_plan.intents.len(), 5);
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
        .contains(&"vm_wheel_evidence_captured_pending_analysis".to_string()));

    let run_roots = std::fs::read_dir(&output_root)
        .expect("read retained output root")
        .map(|entry| entry.expect("retained run entry").path())
        .collect::<Vec<_>>();
    assert_eq!(run_roots.len(), 1);
    for scenario_index in 0..5 {
        let action = run_roots[0]
            .join(format!("action-{scenario_index:04}"))
            .join("evidence");
        assert_eq!(
            std::fs::read(action.join("seen-artifact.bin")).expect("mock saw artifact"),
            artifact
        );
        assert_eq!(
            std::fs::read_to_string(action.join("seen-artifact-kind.txt"))
                .expect("mock saw artifact kind"),
            "wheel\n"
        );
        assert_eq!(
            std::fs::read_to_string(action.join("seen-scenario-index.txt"))
                .expect("mock saw scenario index"),
            format!("{scenario_index}\n")
        );
        let envelope: serde_json::Value = serde_json::from_slice(
            &std::fs::read(action.join("seen-artifact-envelope.json"))
                .expect("mock saw artifact envelope"),
        )
        .expect("artifact envelope JSON");
        assert_eq!(envelope["acquired_at"], "2026-07-16T12:34:56Z");
        assert!(envelope["custody_reference"]
            .as_str()
            .is_some_and(|value| value.starts_with("quarantine-cas:")));
        assert_eq!(envelope["policy_version"], "exact-artifact-inspection-v1");
        let manifest: serde_json::Value = serde_json::from_slice(
            &std::fs::read(action.join("seen-artifact-manifest.json"))
                .expect("mock saw artifact manifest"),
        )
        .expect("artifact manifest JSON");
        assert_eq!(manifest["artifact_sha256"], artifact_sha256);
        assert!(detonation.reason_codes.contains(&format!(
            "vm_wheel_action_{scenario_index}_evidence_incomplete"
        )));
    }
    assert!(!report.observed_clean);
    assert!(!report.admission_authority);
    assert!(!report.sync_back_enabled);
}

#[test]
fn dependency_bearing_pure_wheel_is_runtime_bound_and_executed_without_dependencies() {
    let root = TempRoot::new("whoathere-exact-wheel-linux-vz-dependencies");
    let artifact = wheel_zip_with_metadata_extra("Requires-Dist: requests>=2\n");
    let artifact_sha256 = Sha256Digest::from_bytes(&artifact).to_string();
    let artifact_path = root
        .path()
        .join("exact_wheel_detonation-1.0.0-py3-none-any.whl");
    std::fs::write(&artifact_path, &artifact).expect("write dependency-bearing wheel fixture");
    let helper_path = write_mock_helper(root.path(), &artifact_sha256);
    let config = adapter_config(root.path(), helper_path);
    let output_root = config.output_root.clone();
    let adapter = LinuxVzExactWheelDetonationAdapterV1::new(config).expect("ready mock adapter");

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
    .expect("run dependency-bearing exact wheel detonation adapter");

    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert_eq!(
        report.scenario_plan.status,
        ExactArtifactStageStatusV1::Incomplete
    );
    assert!(report.scenario_plan.executable);
    assert_eq!(report.scenario_plan.runtime_binding_status, "verified");
    assert!(report
        .scenario_plan
        .reason_codes
        .contains(&"exact_artifact_dependency_closure_required".to_string()));
    let detonation = report
        .stages
        .iter()
        .find(|stage| stage.stage == "detonation")
        .expect("detonation stage");
    assert_eq!(detonation.status, ExactArtifactStageStatusV1::Incomplete);
    assert!(detonation
        .reason_codes
        .contains(&"vm_wheel_dependency_closure_not_installed".to_string()));
    assert_eq!(
        std::fs::read_dir(output_root)
            .expect("read retained output root")
            .count(),
        1
    );
    assert!(!report.observed_clean);
    assert!(!report.admission_authority);
    assert!(!report.sync_back_enabled);
}

#[test]
fn exact_wheel_failed_helper_exposes_only_an_action_bound_typed_failure_class() {
    let root = TempRoot::new("whoathere-exact-wheel-linux-vz-failed-helper");
    let artifact = wheel_zip();
    let artifact_path = root
        .path()
        .join("exact_wheel_detonation-1.0.0-py3-none-any.whl");
    std::fs::write(&artifact_path, &artifact).expect("write exact wheel fixture");
    let helper_path = write_failed_mock_helper(root.path());
    let config = adapter_config(root.path(), helper_path);
    let adapter = LinuxVzExactWheelDetonationAdapterV1::new(config).expect("ready failed adapter");

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

    for scenario_index in 0..report.scenario_plan.intents.len() {
        assert!(report.reason_codes.contains(&format!(
            "vm_wheel_action_{scenario_index}_helper_process_failed"
        )));
        assert!(report.reason_codes.contains(&format!(
            "vm_wheel_action_{scenario_index}_helper_failure_execution_image_exit"
        )));
    }
    let report_json = serde_json::to_string(&report).expect("serialize report");
    assert!(!report_json.contains("builder_execution_image_exit_70"));
    assert!(!report_json.contains("PYPI_TOKEN_CANARY_SECRET"));
    assert!(!report_json.contains("raw package stdout"));
    assert_eq!(report.status, ExactArtifactDispositionV1::Inconclusive);
    assert!(!report.observed_clean);
    assert!(!report.admission_authority);
    assert!(!report.sync_back_enabled);
}
