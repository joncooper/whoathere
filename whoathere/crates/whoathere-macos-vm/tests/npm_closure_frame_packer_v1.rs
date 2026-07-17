use serde_json::json;
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
};
use whoathere_macos_vm::{
    decode_macos_sdist_build_closure_frame_v1, NPM_CLOSURE_FRAME_PACK_RESULT_SCHEMA_V1,
    NPM_CLOSURE_FRAME_RECIPE_SCHEMA_V1,
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(1);

struct TempRoot(PathBuf);

impl TempRoot {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "whoathere-npm-closure-frame-pack-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create test root");
        Self(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn packer() -> &'static str {
    env!("CARGO_BIN_EXE_whoathere-npm-closure-frame-pack")
}

fn descriptor(name: &str, version: &str, bytes: &[u8]) -> SdistBuildClosureArtifactV1 {
    SdistBuildClosureArtifactV1::new(
        name,
        version,
        format!("{name}-{version}.tgz"),
        SdistBuildClosureArtifactFormatV1::NpmTarGzip,
        Sha256Digest::from_bytes(bytes),
        bytes.len() as u64,
    )
    .expect("valid npm descriptor")
}

fn write_recipe(
    root: &Path,
    direct_requirements: &[&str],
    descriptors: &[SdistBuildClosureArtifactV1],
) -> PathBuf {
    let recipe = json!({
        "schema_version": NPM_CLOSURE_FRAME_RECIPE_SCHEMA_V1,
        "direct_requirements": direct_requirements,
        "artifact_descriptors": descriptors,
    });
    let bytes = serde_json_canonicalizer::to_vec(&recipe).expect("canonical recipe");
    let path = root.join("recipe.json");
    fs::write(&path, bytes).expect("write recipe");
    path
}

fn run(recipe: &Path, output: &Path, artifacts: &[PathBuf]) -> Output {
    let mut command = Command::new(packer());
    command.arg(recipe).arg(output);
    command.args(artifacts);
    command.output().expect("run packer")
}

#[test]
fn valid_recipe_round_trips_and_writes_a_private_new_frame() {
    let root = TempRoot::new();
    let alpha = b"\x1f\x8binert-alpha-tarball";
    let beta = b"\x1f\x8binert-beta-tarball";
    let alpha_path = root.0.join("alpha-1.0.0.tgz");
    let beta_path = root.0.join("beta-2.0.0.tgz");
    fs::write(&alpha_path, alpha).expect("write alpha");
    fs::write(&beta_path, beta).expect("write beta");
    let descriptors = vec![
        descriptor("alpha", "1.0.0", alpha),
        descriptor("beta", "2.0.0", beta),
    ];
    let requirements = ["alpha ^1.0.0", "beta >=2.0.0"];
    let recipe = write_recipe(&root.0, &requirements, &descriptors);
    let output_path = root.0.join("closure.frame");

    let output = run(
        &recipe,
        &output_path,
        &[alpha_path.clone(), beta_path.clone()],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).expect("result JSON");
    assert_eq!(
        result["schema_version"],
        NPM_CLOSURE_FRAME_PACK_RESULT_SCHEMA_V1
    );
    assert_eq!(result["artifact_count"], 2);
    assert_eq!(
        result["payload_byte_length"],
        (alpha.len() + beta.len()) as u64
    );

    let frame = fs::read(&output_path).expect("read frame");
    let closure = SdistBuildClosureV1::new(&requirements.map(str::to_string), descriptors)
        .expect("expected closure");
    let (payload, observation) =
        decode_macos_sdist_build_closure_frame_v1(&frame, &closure).expect("decode frame");
    assert_eq!(payload, [alpha.as_slice(), beta.as_slice()].concat());
    assert_eq!(result["closure_sha256"], closure.closure_sha256().as_str());
    assert_eq!(
        result["payload_sha256"],
        observation.payload_sha256().as_str()
    );
    assert_eq!(
        result["frame_sha256"],
        Sha256Digest::from_bytes(&frame).as_str()
    );
    assert_eq!(
        fs::metadata(output_path).expect("output metadata").mode() & 0o777,
        0o600
    );
}

#[test]
fn direct_requirement_key_without_a_descriptor_fails_closed() {
    let root = TempRoot::new();
    let bytes = b"\x1f\x8binert-alpha-tarball";
    let artifact = root.0.join("alpha-1.0.0.tgz");
    fs::write(&artifact, bytes).expect("write artifact");
    let recipe = write_recipe(
        &root.0,
        &["missing ^1.0.0"],
        &[descriptor("alpha", "1.0.0", bytes)],
    );
    let output_path = root.0.join("closure.frame");

    let result = run(&recipe, &output_path, &[artifact]);
    assert!(!result.status.success());
    assert!(!output_path.exists());
}

#[test]
fn descriptor_or_input_reordering_fails_closed() {
    let alpha = b"\x1f\x8binert-alpha-tarball";
    let beta = b"\x1f\x8binert-beta-tarball";

    let reordered_recipe_root = TempRoot::new();
    let alpha_path = reordered_recipe_root.0.join("alpha-1.0.0.tgz");
    let beta_path = reordered_recipe_root.0.join("beta-2.0.0.tgz");
    fs::write(&alpha_path, alpha).expect("write alpha");
    fs::write(&beta_path, beta).expect("write beta");
    let reordered_recipe = write_recipe(
        &reordered_recipe_root.0,
        &["alpha ^1.0.0", "beta ^2.0.0"],
        &[
            descriptor("beta", "2.0.0", beta),
            descriptor("alpha", "1.0.0", alpha),
        ],
    );
    let result = run(
        &reordered_recipe,
        &reordered_recipe_root.0.join("reordered.frame"),
        &[beta_path, alpha_path],
    );
    assert!(!result.status.success());

    let reordered_input_root = TempRoot::new();
    let alpha_path = reordered_input_root.0.join("alpha-1.0.0.tgz");
    let beta_path = reordered_input_root.0.join("beta-2.0.0.tgz");
    fs::write(&alpha_path, alpha).expect("write alpha");
    fs::write(&beta_path, beta).expect("write beta");
    let recipe = write_recipe(
        &reordered_input_root.0,
        &["alpha ^1.0.0", "beta ^2.0.0"],
        &[
            descriptor("alpha", "1.0.0", alpha),
            descriptor("beta", "2.0.0", beta),
        ],
    );
    let output_path = reordered_input_root.0.join("reordered.frame");
    let result = run(&recipe, &output_path, &[beta_path, alpha_path]);
    assert!(!result.status.success());
    assert!(!output_path.exists());
}

#[test]
fn symlink_artifact_is_rejected() {
    let root = TempRoot::new();
    let bytes = b"\x1f\x8binert-alpha-tarball";
    let target = root.0.join("stored-artifact");
    let artifact = root.0.join("alpha-1.0.0.tgz");
    fs::write(&target, bytes).expect("write target");
    symlink(&target, &artifact).expect("create artifact symlink");
    let recipe = write_recipe(
        &root.0,
        &["alpha ^1.0.0"],
        &[descriptor("alpha", "1.0.0", bytes)],
    );
    let output_path = root.0.join("closure.frame");

    let result = run(&recipe, &output_path, &[artifact]);
    assert!(!result.status.success());
    assert!(!output_path.exists());
}

#[test]
fn existing_output_is_never_replaced() {
    let root = TempRoot::new();
    let bytes = b"\x1f\x8binert-alpha-tarball";
    let artifact = root.0.join("alpha-1.0.0.tgz");
    fs::write(&artifact, bytes).expect("write artifact");
    let recipe = write_recipe(
        &root.0,
        &["alpha ^1.0.0"],
        &[descriptor("alpha", "1.0.0", bytes)],
    );
    let output_path = root.0.join("closure.frame");
    fs::write(&output_path, b"preexisting sentinel").expect("write sentinel");

    let result = run(&recipe, &output_path, &[artifact]);
    assert!(!result.status.success());
    assert_eq!(
        fs::read(output_path).expect("read sentinel"),
        b"preexisting sentinel"
    );
}

#[test]
fn descriptor_hash_and_length_are_verified_before_output() {
    let bytes = b"\x1f\x8binert-alpha-tarball";

    let digest_root = TempRoot::new();
    let artifact = digest_root.0.join("alpha-1.0.0.tgz");
    fs::write(&artifact, bytes).expect("write artifact");
    let wrong_digest = descriptor("alpha", "1.0.0", b"different bytes");
    let recipe = write_recipe(&digest_root.0, &["alpha ^1.0.0"], &[wrong_digest]);
    let output_path = digest_root.0.join("closure.frame");
    assert!(!run(&recipe, &output_path, &[artifact]).status.success());
    assert!(!output_path.exists());

    let length_root = TempRoot::new();
    let artifact = length_root.0.join("alpha-1.0.0.tgz");
    fs::write(&artifact, bytes).expect("write artifact");
    let descriptor_value = json!({
        "normalized_name": "alpha",
        "version": "1.0.0",
        "artifact_filename": "alpha-1.0.0.tgz",
        "artifact_format": "npm_tar_gzip",
        "artifact_sha256": Sha256Digest::from_bytes(bytes),
        "artifact_byte_length": bytes.len() + 1,
    });
    let recipe_value = json!({
        "schema_version": NPM_CLOSURE_FRAME_RECIPE_SCHEMA_V1,
        "direct_requirements": ["alpha ^1.0.0"],
        "artifact_descriptors": [descriptor_value],
    });
    let recipe = length_root.0.join("recipe.json");
    fs::write(
        &recipe,
        serde_json_canonicalizer::to_vec(&recipe_value).expect("canonical recipe"),
    )
    .expect("write recipe");
    let output_path = length_root.0.join("closure.frame");
    assert!(!run(&recipe, &output_path, &[artifact]).status.success());
    assert!(!output_path.exists());
}
