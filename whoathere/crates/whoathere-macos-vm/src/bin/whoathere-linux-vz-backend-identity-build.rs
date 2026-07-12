use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::ArtifactProtectedTelemetryRequirementsV1;
use whoathere_macos_vm::UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1;

fn main() {
    if let Err(error) = run() {
        eprintln!("whoathere Linux VZ backend identity build failed: {error}");
        std::process::exit(70);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if arguments.len() != 9 || arguments[1..].iter().any(|value| !value.starts_with('/')) {
        return Err("usage: identity-build MANIFEST HELPER GUEST_KEY HOST_KEY GUEST_CONFIG HOST_CONFIG ROOT_ABSENCE OUTPUT".into());
    }
    let manifest_bytes = read_bounded(&arguments[1], 256 * 1024)?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)?;
    let canonical_manifest = serde_json_canonicalizer::to_vec(&manifest)?;
    let mut canonical_manifest_with_newline = canonical_manifest.clone();
    canonical_manifest_with_newline.push(b'\n');
    if manifest_bytes != canonical_manifest && manifest_bytes != canonical_manifest_with_newline {
        return Err("image manifest is not canonical JSON".into());
    }
    let signed_image = match manifest["schema_version"].as_str() {
        Some("whoathere.linux_vz_inert_image_manifest.v5") => false,
        Some("whoathere.linux_vz_signed_inert_image_manifest.v1") => true,
        _ => return Err("image manifest schema is not supported".into()),
    };
    if manifest["image_state"] != "candidate_unqualified"
        || manifest["external_network"] != "no_external_route"
        || manifest["sync_back_policy"] != "structurally_absent"
        || signed_image
            && (manifest["package_execution"] != "disabled"
                || manifest["root_disk"] != "structurally_absent"
                || manifest["guest_seed_provisioning"] != "root_owned_mode_0600_initramfs_path")
    {
        return Err("image manifest is not an exact unqualified contract".into());
    }

    let helper = read_bounded(&arguments[2], 64 * 1024 * 1024)?;
    let guest_key = read_exact_key(&arguments[3])?;
    let host_key = read_exact_key(&arguments[4])?;
    let guest_config = read_canonical_json(&arguments[5])?;
    let host_config = read_canonical_json(&arguments[6])?;
    let root_absence = read_canonical_json(&arguments[7])?;
    let requirements = ArtifactProtectedTelemetryRequirementsV1::linux_vz_bulk_v1();
    let identity = UnqualifiedMacosLinuxVzTelemetryBackendIdentityV1::new(
        if signed_image {
            "alpine-3.24.1-aarch64-signed-inert-v1"
        } else {
            "alpine-3.24.1-aarch64-btf-pinned-v7"
        },
        "alpine-3.24.1-aarch64",
        required_string(&manifest, "kernel_release")?,
        required_digest(&manifest, "kernel_image_sha256")?,
        required_digest(
            &manifest,
            if signed_image {
                "whoathere_signed_initramfs_sha256"
            } else {
                "whoathere_initramfs_sha256"
            },
        )?,
        Sha256Digest::from_bytes(&root_absence),
        required_digest(
            &manifest,
            if signed_image {
                "kernel_config_sha256"
            } else {
                "config_sha256"
            },
        )?,
        required_digest(&manifest, "kernel_btf_sha256")?,
        required_digest(
            &manifest,
            if signed_image {
                "process_fixture_child_sha256"
            } else {
                "guest_init_sha256"
            },
        )?,
        required_digest(
            &manifest,
            if signed_image {
                "guest_signer_sha256"
            } else {
                "process_sensor_probe_sha256"
            },
        )?,
        required_digest(&manifest, "process_sensor_probe_sha256")?,
        Sha256Digest::from_bytes(&guest_config),
        Sha256Digest::from_bytes(&guest_key),
        Sha256Digest::from_bytes(&helper),
        Sha256Digest::from_bytes(&helper),
        Sha256Digest::from_bytes(&host_config),
        Sha256Digest::from_bytes(&host_key),
        &requirements,
        65534,
        65534,
    )?;
    let canonical = identity.canonical_json_v1()?;
    let output = Path::new(&arguments[8]);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(output)?;
    file.write_all(&canonical)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(output)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != canonical.len() as u64
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err("identity output verification failed".into());
    }
    println!(
        "{{\"execution_authority\":false,\"identity_sha256\":\"{}\",\"package_execution\":false,\"schema_version\":\"whoathere.linux_vz_backend_identity_build_result.v1\",\"sync_back\":false}}",
        identity.identity_sha256_v1()?
    );
    Ok(())
}

fn read_bounded(path: &str, maximum: u64) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = Path::new(path);
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > maximum {
        return Err("input is not a bounded regular non-symlink file".into());
    }
    let mut value = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum + 1).read_to_end(&mut value)?;
    if value.is_empty() || value.len() as u64 > maximum {
        return Err("input is not a bounded regular non-symlink file".into());
    }
    Ok(value)
}

fn read_exact_key(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value = read_bounded(path, 32)?;
    if value.len() != 32 {
        return Err("evidence public key must be exactly 32 bytes".into());
    }
    Ok(value)
}

fn read_canonical_json(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let value = read_bounded(path, 64 * 1024)?;
    let json: Value = serde_json::from_slice(&value)?;
    let canonical = serde_json_canonicalizer::to_vec(&json)?;
    let mut canonical_with_newline = canonical.clone();
    canonical_with_newline.push(b'\n');
    if value != canonical && value != canonical_with_newline {
        return Err("configuration must be canonical JSON".into());
    }
    Ok(canonical)
}

fn required_string(value: &Value, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    value[key]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("manifest field missing: {key}").into())
}

fn required_digest(value: &Value, key: &str) -> Result<Sha256Digest, Box<dyn std::error::Error>> {
    Ok(Sha256Digest::parse(required_string(value, key)?)?)
}
