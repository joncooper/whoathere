use crate::{
    decode_macos_sdist_build_closure_frame_v1, encode_macos_sdist_build_closure_frame_v1,
    MAX_MACOS_SDIST_BUILD_CLOSURE_ARTIFACTS_V1, MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1,
    MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::{
    SdistBuildClosureArtifactFormatV1, SdistBuildClosureArtifactV1, SdistBuildClosureV1,
};

pub const NPM_CLOSURE_FRAME_RECIPE_SCHEMA_V1: &str = "whoathere.npm_closure_frame_recipe.v1";
pub const NPM_CLOSURE_FRAME_PACK_RESULT_SCHEMA_V1: &str =
    "whoathere.npm_closure_frame_pack_result.v1";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NpmClosureFrameRecipeV1 {
    schema_version: String,
    direct_requirements: Vec<String>,
    artifact_descriptors: Vec<SdistBuildClosureArtifactV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NpmClosureFramePackResultV1 {
    schema_version: &'static str,
    closure_sha256: Sha256Digest,
    payload_sha256: Sha256Digest,
    frame_sha256: Sha256Digest,
    artifact_count: usize,
    payload_byte_length: u64,
}

impl NpmClosureFramePackResultV1 {
    pub fn closure_sha256(&self) -> &Sha256Digest {
        &self.closure_sha256
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn frame_sha256(&self) -> &Sha256Digest {
        &self.frame_sha256
    }

    pub fn artifact_count(&self) -> usize {
        self.artifact_count
    }

    pub fn payload_byte_length(&self) -> u64 {
        self.payload_byte_length
    }

    pub fn canonical_json_v1(&self) -> io::Result<Vec<u8>> {
        serde_json_canonicalizer::to_vec(self)
            .map_err(|_| invalid_data("npm closure pack result serialization failed"))
    }
}

/// Build one exact, offline npm dependency-closure frame from already acquired tarballs.
///
/// This function performs no package resolution, fetching, extraction, or execution. The caller
/// supplies one absolute artifact path per descriptor, in descriptor order.
pub fn pack_npm_closure_frame_v1(
    recipe_path: &Path,
    artifact_paths: &[PathBuf],
    output_path: &Path,
) -> io::Result<NpmClosureFramePackResultV1> {
    if !recipe_path.is_absolute()
        || !output_path.is_absolute()
        || artifact_paths.iter().any(|path| !path.is_absolute())
    {
        return Err(invalid_input("npm closure pack paths must be absolute"));
    }

    let recipe_bytes = read_regular_bounded_v1(
        recipe_path,
        MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1 as u64,
    )?;
    let recipe: NpmClosureFrameRecipeV1 = serde_json::from_slice(&recipe_bytes)
        .map_err(|_| invalid_data("npm closure recipe is invalid"))?;
    if recipe.schema_version != NPM_CLOSURE_FRAME_RECIPE_SCHEMA_V1 {
        return Err(invalid_data("npm closure recipe schema is unsupported"));
    }
    let canonical_recipe = serde_json_canonicalizer::to_vec(&recipe)
        .map_err(|_| invalid_data("npm closure recipe serialization failed"))?;
    if canonical_recipe != recipe_bytes {
        return Err(invalid_data("npm closure recipe is not canonical JSON"));
    }
    if recipe.artifact_descriptors.is_empty()
        || recipe.artifact_descriptors.len() > MAX_MACOS_SDIST_BUILD_CLOSURE_ARTIFACTS_V1
        || artifact_paths.len() != recipe.artifact_descriptors.len()
    {
        return Err(invalid_data(
            "npm closure recipe artifact count does not match inputs",
        ));
    }
    if recipe.artifact_descriptors.iter().any(|descriptor| {
        descriptor.artifact_format() != SdistBuildClosureArtifactFormatV1::NpmTarGzip
    }) {
        return Err(invalid_data(
            "npm closure recipe contains a non-npm artifact",
        ));
    }

    let closure = SdistBuildClosureV1::new(
        &recipe.direct_requirements,
        recipe.artifact_descriptors.clone(),
    )
    .map_err(|_| invalid_data("npm closure recipe declarations are invalid"))?;

    let mut payload_byte_length = 0_u64;
    let mut artifact_bytes = Vec::with_capacity(artifact_paths.len());
    for (descriptor, path) in closure.artifacts().iter().zip(artifact_paths) {
        let basename = path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| invalid_data("npm closure artifact basename is invalid"))?;
        if basename != descriptor.artifact_filename() {
            return Err(invalid_data(
                "npm closure artifact basename does not match descriptor order",
            ));
        }
        let bytes = read_regular_exact_v1(path, descriptor.artifact_byte_length())?;
        if Sha256Digest::from_bytes(&bytes) != *descriptor.artifact_sha256() {
            return Err(invalid_data(
                "npm closure artifact digest does not match descriptor",
            ));
        }
        payload_byte_length = payload_byte_length
            .checked_add(bytes.len() as u64)
            .filter(|length| *length <= MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1)
            .ok_or_else(|| invalid_data("npm closure payload exceeds limit"))?;
        artifact_bytes.push(bytes);
    }

    let frame = encode_macos_sdist_build_closure_frame_v1(&closure, &artifact_bytes)
        .map_err(|_| invalid_data("npm closure frame encoding failed"))?;
    let (verified_payload, observation) =
        decode_macos_sdist_build_closure_frame_v1(&frame, &closure)
            .map_err(|_| invalid_data("npm closure frame verification failed"))?;
    let mut verified_offset = 0_usize;
    let payload_matches = artifact_bytes.iter().all(|bytes| {
        let end = verified_offset.checked_add(bytes.len());
        let matches = end.and_then(|end| verified_payload.get(verified_offset..end))
            == Some(bytes.as_slice());
        if let Some(end) = end {
            verified_offset = end;
        }
        matches
    }) && verified_offset == verified_payload.len();
    if !payload_matches
        || observation.closure_sha256() != closure.closure_sha256()
        || observation.artifact_count() != closure.artifacts().len()
        || observation.payload_byte_length() != payload_byte_length
    {
        return Err(invalid_data("npm closure frame round-trip mismatch"));
    }

    write_new_private_v1(output_path, &frame)?;
    Ok(NpmClosureFramePackResultV1 {
        schema_version: NPM_CLOSURE_FRAME_PACK_RESULT_SCHEMA_V1,
        closure_sha256: closure.closure_sha256().clone(),
        payload_sha256: observation.payload_sha256().clone(),
        frame_sha256: Sha256Digest::from_bytes(&frame),
        artifact_count: observation.artifact_count(),
        payload_byte_length: observation.payload_byte_length(),
    })
}

fn read_regular_exact_v1(path: &Path, expected_length: u64) -> io::Result<Vec<u8>> {
    if expected_length == 0 || expected_length > MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1 {
        return Err(invalid_data("npm closure artifact length is invalid"));
    }
    let bytes = read_regular_bounded_v1(path, expected_length)?;
    if bytes.len() as u64 != expected_length {
        return Err(invalid_data(
            "npm closure artifact length does not match descriptor",
        ));
    }
    Ok(bytes)
}

fn read_regular_bounded_v1(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
    let path_before = fs::symlink_metadata(path)?;
    if !path_before.file_type().is_file() || path_before.len() == 0 || path_before.len() > maximum {
        return Err(invalid_data(
            "npm closure input is not a bounded regular non-symlink file",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.len() == 0
        || metadata.len() > maximum
        || metadata.dev() != path_before.dev()
        || metadata.ino() != path_before.ino()
    {
        return Err(invalid_data(
            "npm closure input is not a bounded regular non-symlink file",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)?;
    let path_after = fs::symlink_metadata(path)?;
    if bytes.is_empty()
        || bytes.len() as u64 != metadata.len()
        || path_after.dev() != metadata.dev()
        || path_after.ino() != metadata.ino()
        || !path_after.file_type().is_file()
    {
        return Err(invalid_data(
            "npm closure input changed while it was being read",
        ));
    }
    Ok(bytes)
}

fn write_new_private_v1(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    let path_metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || !path_metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != bytes.len() as u64
        || metadata.dev() != path_metadata.dev()
        || metadata.ino() != path_metadata.ino()
    {
        return Err(invalid_data("npm closure output verification failed"));
    }
    Ok(())
}

fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
