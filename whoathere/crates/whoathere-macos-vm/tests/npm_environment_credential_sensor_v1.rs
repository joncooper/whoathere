#[path = "../src/linux_vz_package_npm_environment_credential_sensor.rs"]
#[allow(dead_code)]
mod sensor;

use sensor::{
    fixed_linux_vz_package_npm_environment_credential_sensor_binding_v1,
    verify_linux_vz_package_npm_environment_credential_sensor_hook_v1,
    LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1,
    LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1,
    LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1,
};
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const NODE_HARNESS: &str = r#"
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(process.argv[1], 'utf8');
const lifecycle = process.argv[2] === 'lifecycle';
const expression = process.argv[3];
const calls = [];
const fakeFs = {
  constants: fs.constants,
  openSync(path) { calls.push(['open', path]); return 19; },
  writeSync(descriptor, value) { calls.push(['write', descriptor, value]); },
  closeSync(descriptor) { calls.push(['close', descriptor]); },
};
const fakeProcess = {
  env: {
    PATH: '/usr/bin:/bin',
    NPM_TOKEN: 'fake-never-emitted-npm-token',
    GITHUB_TOKEN: 'fake-never-emitted-github-token',
    AWS_ACCESS_KEY_ID: 'AKIAFAKEUNISSUED',
    ...(lifecycle ? {npm_lifecycle_event: 'preinstall'} : {}),
  },
};
const context = vm.createContext({
  Object, Proxy, Reflect, Set,
  process: fakeProcess,
  require(name) {
    if (name !== 'node:fs') throw new Error(`unexpected module ${name}`);
    return fakeFs;
  },
});
vm.runInContext(source, context, {filename: 'measured-preload.cjs'});
vm.runInContext(expression, context, {filename: 'inert-package.js'});
process.stdout.write(JSON.stringify(calls));
"#;

fn run_exact_hook(lifecycle: bool, expression: &str) -> Vec<Vec<serde_json::Value>> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "whoathere-npm-environment-sensor-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory).expect("create test directory");
    let hook = directory.join("measured-preload.cjs");
    fs::write(
        &hook,
        LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1,
    )
    .expect("write exact hook");
    let output = Command::new("node")
        .args([
            "-e",
            NODE_HARNESS,
            hook.to_str().expect("utf8 hook path"),
            if lifecycle { "lifecycle" } else { "leader" },
            expression,
        ])
        .output()
        .expect("run inert node hook harness");
    fs::remove_dir_all(&directory).expect("remove test directory");
    assert!(
        output.status.success(),
        "node harness failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("marker calls")
}

fn opened_paths(calls: &[Vec<serde_json::Value>]) -> Vec<&str> {
    calls
        .iter()
        .filter(|call| call.first().and_then(serde_json::Value::as_str) == Some("open"))
        .map(|call| call[1].as_str().expect("opened path"))
        .collect()
}

#[test]
fn fixed_binding_commits_to_hook_and_every_marker_identity() {
    let binding = fixed_linux_vz_package_npm_environment_credential_sensor_binding_v1()
        .expect("fixed binding");
    assert_eq!(binding.markers().len(), 3);
    assert_eq!(
        binding.node_options_value_v1(),
        format!("--require={}", binding.hook_absolute_path())
    );
    assert_eq!(
        binding
            .marker(LinuxVzPackageNpmEnvironmentCredentialMarkerKindV1::NpmToken)
            .environment_name(),
        Some("NPM_TOKEN")
    );
    assert!(binding.markers().iter().all(|marker| marker
        .marker_absolute_path()
        .starts_with("/run/whoathere/home/.whoathere-canaries/")));
    verify_linux_vz_package_npm_environment_credential_sensor_hook_v1(
        LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1,
        &binding,
    )
    .expect("exact hook verifies");
}

#[test]
fn tampered_hook_cannot_satisfy_the_measured_binding() {
    let binding = fixed_linux_vz_package_npm_environment_credential_sensor_binding_v1()
        .expect("fixed binding");
    let mut tampered = LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1.to_vec();
    tampered[0] ^= 1;
    assert_eq!(
        verify_linux_vz_package_npm_environment_credential_sensor_hook_v1(&tampered, &binding),
        Err(LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1::HookMeasurementMismatch)
    );
    assert_eq!(
        verify_linux_vz_package_npm_environment_credential_sensor_hook_v1(
            &LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1
                [..LINUX_VZ_PACKAGE_NPM_ENVIRONMENT_CREDENTIAL_SENSOR_HOOK_V1.len() - 1],
            &binding,
        ),
        Err(LinuxVzPackageNpmEnvironmentCredentialSensorErrorV1::HookMeasurementMismatch)
    );
}

#[test]
fn npm_leader_and_untouched_lifecycle_do_not_false_positive() {
    let leader = run_exact_hook(false, "void process.env.NPM_TOKEN");
    assert!(opened_paths(&leader).is_empty());

    let untouched = run_exact_hook(true, "void process.env.PATH");
    let paths = opened_paths(&untouched);
    assert!(paths.is_empty());
    assert!(
        !String::from_utf8_lossy(&serde_json::to_vec(&untouched).expect("serialize calls"))
            .contains("fake-never-emitted")
    );
}

#[test]
fn lifecycle_credential_access_records_only_the_unauthenticated_support_marker() {
    let calls = run_exact_hook(
        true,
        "void process.env.NPM_TOKEN; void process.env.NPM_TOKEN",
    );
    let paths = opened_paths(&calls);
    assert_eq!(paths.len(), 1, "one idempotent read marker");
    assert!(paths[0].ends_with("/environment-read-npm-token"));
    assert!(!paths.iter().any(|path| path.contains("github")));
    assert!(!paths.iter().any(|path| path.contains("aws")));
}

#[test]
fn membership_and_descriptor_checks_are_environment_accesses() {
    for expression in [
        "void ('GITHUB_TOKEN' in process.env)",
        "void Object.getOwnPropertyDescriptor(process.env, 'AWS_ACCESS_KEY_ID')",
    ] {
        let calls = run_exact_hook(true, expression);
        assert_eq!(opened_paths(&calls).len(), 1);
    }
}
