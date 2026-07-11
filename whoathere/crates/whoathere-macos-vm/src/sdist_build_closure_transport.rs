use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{Cursor, Read, Write};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::SdistBuildClosureV1;

pub const MACOS_SDIST_BUILD_CLOSURE_MAGIC_V1: &[u8; 8] = b"WHOASCL1";
pub const MACOS_SDIST_GUEST_BUILD_CLOSURE_MAGIC_V1: &[u8; 8] = b"WHOSGCL1";
pub const MACOS_SDIST_BUILD_CLOSURE_VERSION_V1: u16 = 1;
pub const MACOS_SDIST_BUILD_CLOSURE_FRAME_TYPE_V1: u16 = 1;
pub const MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1: usize = 96;
pub const MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1: usize = 256 * 1024;
pub const MAX_MACOS_SDIST_BUILD_CLOSURE_ARTIFACTS_V1: usize = 64;
pub const MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosSdistBuildClosureTransportErrorV1 {
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedFrameType,
    InvalidPrefix,
    ManifestLimitExceeded,
    ArtifactCountLimitExceeded,
    PayloadLimitExceeded,
    ManifestInvalid,
    BindingMismatch,
    Truncated,
    TrailingData,
    ArtifactDigestMismatch,
    PayloadDigestMismatch,
    IoFailed,
    Serialization,
}

impl MacosSdistBuildClosureTransportErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidMagic => "macos_sdist_build_closure_magic_invalid",
            Self::UnsupportedVersion => "macos_sdist_build_closure_version_unsupported",
            Self::UnsupportedFrameType => "macos_sdist_build_closure_type_unsupported",
            Self::InvalidPrefix => "macos_sdist_build_closure_prefix_invalid",
            Self::ManifestLimitExceeded => "macos_sdist_build_closure_manifest_limit_exceeded",
            Self::ArtifactCountLimitExceeded => {
                "macos_sdist_build_closure_artifact_count_limit_exceeded"
            }
            Self::PayloadLimitExceeded => "macos_sdist_build_closure_payload_limit_exceeded",
            Self::ManifestInvalid => "macos_sdist_build_closure_manifest_invalid",
            Self::BindingMismatch => "macos_sdist_build_closure_binding_mismatch",
            Self::Truncated => "macos_sdist_build_closure_truncated",
            Self::TrailingData => "macos_sdist_build_closure_trailing_data",
            Self::ArtifactDigestMismatch => "macos_sdist_build_closure_artifact_digest_mismatch",
            Self::PayloadDigestMismatch => "macos_sdist_build_closure_payload_digest_mismatch",
            Self::IoFailed => "macos_sdist_build_closure_io_failed",
            Self::Serialization => "macos_sdist_build_closure_serialization_failed",
        }
    }
}

impl fmt::Display for MacosSdistBuildClosureTransportErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosSdistBuildClosureTransportErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosSdistBuildClosureTransportObservationV1 {
    closure_sha256: Sha256Digest,
    payload_sha256: Sha256Digest,
    artifact_count: usize,
    payload_byte_length: u64,
}

impl MacosSdistBuildClosureTransportObservationV1 {
    pub fn closure_sha256(&self) -> &Sha256Digest {
        &self.closure_sha256
    }

    pub fn payload_sha256(&self) -> &Sha256Digest {
        &self.payload_sha256
    }

    pub fn artifact_count(&self) -> usize {
        self.artifact_count
    }

    pub fn payload_byte_length(&self) -> u64 {
        self.payload_byte_length
    }
}

pub fn encode_macos_sdist_build_closure_frame_v1(
    closure: &SdistBuildClosureV1,
    artifact_bytes: &[Vec<u8>],
) -> Result<Vec<u8>, MacosSdistBuildClosureTransportErrorV1> {
    encode_build_closure_frame_v1(MACOS_SDIST_BUILD_CLOSURE_MAGIC_V1, closure, artifact_bytes)
}

pub fn encode_macos_sdist_guest_build_closure_frame_v1(
    closure: &SdistBuildClosureV1,
    artifact_bytes: &[Vec<u8>],
) -> Result<Vec<u8>, MacosSdistBuildClosureTransportErrorV1> {
    encode_build_closure_frame_v1(
        MACOS_SDIST_GUEST_BUILD_CLOSURE_MAGIC_V1,
        closure,
        artifact_bytes,
    )
}

pub fn decode_macos_sdist_build_closure_frame_v1(
    bytes: &[u8],
    expected: &SdistBuildClosureV1,
) -> Result<
    (Vec<u8>, MacosSdistBuildClosureTransportObservationV1),
    MacosSdistBuildClosureTransportErrorV1,
> {
    let mut payload = Vec::new();
    let observation = stream_build_closure_frame_v1(
        &mut Cursor::new(bytes),
        &mut payload,
        MACOS_SDIST_BUILD_CLOSURE_MAGIC_V1,
        expected,
    )?;
    Ok((payload, observation))
}

pub fn stream_macos_sdist_guest_build_closure_v1<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    expected: &SdistBuildClosureV1,
) -> Result<MacosSdistBuildClosureTransportObservationV1, MacosSdistBuildClosureTransportErrorV1> {
    stream_build_closure_frame_v1(
        reader,
        writer,
        MACOS_SDIST_GUEST_BUILD_CLOSURE_MAGIC_V1,
        expected,
    )
}

fn encode_build_closure_frame_v1(
    magic: &[u8; 8],
    closure: &SdistBuildClosureV1,
    artifact_bytes: &[Vec<u8>],
) -> Result<Vec<u8>, MacosSdistBuildClosureTransportErrorV1> {
    let manifest = closure
        .canonical_json_v1()
        .map_err(|_| MacosSdistBuildClosureTransportErrorV1::Serialization)?;
    validate_manifest_and_payload_shape_v1(closure, artifact_bytes, manifest.len())?;
    let payload_byte_length = artifact_bytes.iter().try_fold(0_u64, |total, bytes| {
        total
            .checked_add(bytes.len() as u64)
            .ok_or(MacosSdistBuildClosureTransportErrorV1::PayloadLimitExceeded)
    })?;
    let mut payload_hasher = Sha256::new();
    for bytes in artifact_bytes {
        payload_hasher.update(bytes);
    }
    let payload_sha256 = digest_from_raw_v1(&payload_hasher.finalize())?;
    let capacity = MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1
        .checked_add(manifest.len())
        .and_then(|value| value.checked_add(payload_byte_length as usize))
        .ok_or(MacosSdistBuildClosureTransportErrorV1::PayloadLimitExceeded)?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(magic);
    output.extend_from_slice(&MACOS_SDIST_BUILD_CLOSURE_VERSION_V1.to_be_bytes());
    output.extend_from_slice(&MACOS_SDIST_BUILD_CLOSURE_FRAME_TYPE_V1.to_be_bytes());
    output.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
    output.extend_from_slice(&(artifact_bytes.len() as u32).to_be_bytes());
    output.extend_from_slice(&0_u32.to_be_bytes());
    output.extend_from_slice(&payload_byte_length.to_be_bytes());
    output.extend_from_slice(&digest_bytes_v1(closure.closure_sha256())?);
    output.extend_from_slice(&digest_bytes_v1(&payload_sha256)?);
    if output.len() != MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1 {
        return Err(MacosSdistBuildClosureTransportErrorV1::Serialization);
    }
    output.extend_from_slice(&manifest);
    for bytes in artifact_bytes {
        output.extend_from_slice(bytes);
    }
    Ok(output)
}

fn stream_build_closure_frame_v1<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    expected_magic: &[u8; 8],
    expected: &SdistBuildClosureV1,
) -> Result<MacosSdistBuildClosureTransportObservationV1, MacosSdistBuildClosureTransportErrorV1> {
    let mut prefix = [0_u8; MACOS_SDIST_BUILD_CLOSURE_PREFIX_BYTES_V1];
    read_exact_v1(reader, &mut prefix)?;
    if &prefix[..8] != expected_magic {
        return Err(MacosSdistBuildClosureTransportErrorV1::InvalidMagic);
    }
    if u16::from_be_bytes(prefix[8..10].try_into().expect("fixed prefix"))
        != MACOS_SDIST_BUILD_CLOSURE_VERSION_V1
    {
        return Err(MacosSdistBuildClosureTransportErrorV1::UnsupportedVersion);
    }
    if u16::from_be_bytes(prefix[10..12].try_into().expect("fixed prefix"))
        != MACOS_SDIST_BUILD_CLOSURE_FRAME_TYPE_V1
    {
        return Err(MacosSdistBuildClosureTransportErrorV1::UnsupportedFrameType);
    }
    let manifest_length =
        u32::from_be_bytes(prefix[12..16].try_into().expect("fixed prefix")) as usize;
    let artifact_count =
        u32::from_be_bytes(prefix[16..20].try_into().expect("fixed prefix")) as usize;
    if prefix[20..24] != [0_u8; 4] {
        return Err(MacosSdistBuildClosureTransportErrorV1::InvalidPrefix);
    }
    let payload_byte_length = u64::from_be_bytes(prefix[24..32].try_into().expect("fixed prefix"));
    if manifest_length == 0 || manifest_length > MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1 {
        return Err(MacosSdistBuildClosureTransportErrorV1::ManifestLimitExceeded);
    }
    if artifact_count > MAX_MACOS_SDIST_BUILD_CLOSURE_ARTIFACTS_V1 {
        return Err(MacosSdistBuildClosureTransportErrorV1::ArtifactCountLimitExceeded);
    }
    if payload_byte_length > MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1 {
        return Err(MacosSdistBuildClosureTransportErrorV1::PayloadLimitExceeded);
    }
    let closure_sha256 = digest_from_raw_v1(&prefix[32..64])?;
    let payload_sha256 = digest_from_raw_v1(&prefix[64..96])?;
    let mut manifest = vec![0_u8; manifest_length];
    read_exact_v1(reader, &mut manifest)?;
    let observed: SdistBuildClosureV1 = serde_json::from_slice(&manifest)
        .map_err(|_| MacosSdistBuildClosureTransportErrorV1::ManifestInvalid)?;
    let canonical = observed
        .canonical_json_v1()
        .map_err(|_| MacosSdistBuildClosureTransportErrorV1::ManifestInvalid)?;
    if canonical != manifest
        || observed != *expected
        || closure_sha256 != *expected.closure_sha256()
        || artifact_count != expected.artifacts().len()
    {
        return Err(MacosSdistBuildClosureTransportErrorV1::BindingMismatch);
    }
    let expected_payload_length = expected.artifacts().iter().try_fold(0_u64, |total, item| {
        total
            .checked_add(item.artifact_byte_length())
            .ok_or(MacosSdistBuildClosureTransportErrorV1::PayloadLimitExceeded)
    })?;
    if expected_payload_length != payload_byte_length {
        return Err(MacosSdistBuildClosureTransportErrorV1::BindingMismatch);
    }

    let mut payload_hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    for artifact in expected.artifacts() {
        let mut remaining = artifact.artifact_byte_length();
        let mut artifact_hasher = Sha256::new();
        while remaining > 0 {
            let requested = usize::try_from(remaining.min(buffer.len() as u64))
                .map_err(|_| MacosSdistBuildClosureTransportErrorV1::PayloadLimitExceeded)?;
            read_exact_v1(reader, &mut buffer[..requested])?;
            artifact_hasher.update(&buffer[..requested]);
            payload_hasher.update(&buffer[..requested]);
            writer
                .write_all(&buffer[..requested])
                .map_err(|_| MacosSdistBuildClosureTransportErrorV1::IoFailed)?;
            remaining -= requested as u64;
        }
        if digest_from_raw_v1(&artifact_hasher.finalize())? != *artifact.artifact_sha256() {
            return Err(MacosSdistBuildClosureTransportErrorV1::ArtifactDigestMismatch);
        }
    }
    if digest_from_raw_v1(&payload_hasher.finalize())? != payload_sha256 {
        return Err(MacosSdistBuildClosureTransportErrorV1::PayloadDigestMismatch);
    }
    let mut trailing = [0_u8; 1];
    match reader.read(&mut trailing) {
        Ok(0) => {}
        Ok(_) => return Err(MacosSdistBuildClosureTransportErrorV1::TrailingData),
        Err(_) => return Err(MacosSdistBuildClosureTransportErrorV1::IoFailed),
    }
    Ok(MacosSdistBuildClosureTransportObservationV1 {
        closure_sha256,
        payload_sha256,
        artifact_count,
        payload_byte_length,
    })
}

fn validate_manifest_and_payload_shape_v1(
    closure: &SdistBuildClosureV1,
    artifact_bytes: &[Vec<u8>],
    manifest_length: usize,
) -> Result<(), MacosSdistBuildClosureTransportErrorV1> {
    if manifest_length == 0 || manifest_length > MAX_MACOS_SDIST_BUILD_CLOSURE_MANIFEST_BYTES_V1 {
        return Err(MacosSdistBuildClosureTransportErrorV1::ManifestLimitExceeded);
    }
    if artifact_bytes.len() != closure.artifacts().len()
        || artifact_bytes.len() > MAX_MACOS_SDIST_BUILD_CLOSURE_ARTIFACTS_V1
    {
        return Err(MacosSdistBuildClosureTransportErrorV1::ArtifactCountLimitExceeded);
    }
    let mut total = 0_u64;
    for (declared, bytes) in closure.artifacts().iter().zip(artifact_bytes) {
        if declared.artifact_byte_length() != bytes.len() as u64
            || *declared.artifact_sha256() != Sha256Digest::from_bytes(bytes)
        {
            return Err(MacosSdistBuildClosureTransportErrorV1::ArtifactDigestMismatch);
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or(MacosSdistBuildClosureTransportErrorV1::PayloadLimitExceeded)?;
    }
    if total > MAX_MACOS_SDIST_BUILD_CLOSURE_PAYLOAD_BYTES_V1 {
        return Err(MacosSdistBuildClosureTransportErrorV1::PayloadLimitExceeded);
    }
    Ok(())
}

fn read_exact_v1<R: Read>(
    reader: &mut R,
    buffer: &mut [u8],
) -> Result<(), MacosSdistBuildClosureTransportErrorV1> {
    let mut offset = 0;
    while offset < buffer.len() {
        match reader.read(&mut buffer[offset..]) {
            Ok(0) => return Err(MacosSdistBuildClosureTransportErrorV1::Truncated),
            Ok(read) => offset += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(MacosSdistBuildClosureTransportErrorV1::IoFailed),
        }
    }
    Ok(())
}

fn digest_bytes_v1(
    digest: &Sha256Digest,
) -> Result<[u8; 32], MacosSdistBuildClosureTransportErrorV1> {
    let text = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(MacosSdistBuildClosureTransportErrorV1::Serialization)?;
    if text.len() != 64 {
        return Err(MacosSdistBuildClosureTransportErrorV1::Serialization);
    }
    let mut bytes = [0_u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        *output = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| MacosSdistBuildClosureTransportErrorV1::Serialization)?;
    }
    Ok(bytes)
}

fn digest_from_raw_v1(
    bytes: &[u8],
) -> Result<Sha256Digest, MacosSdistBuildClosureTransportErrorV1> {
    if bytes.len() != 32 {
        return Err(MacosSdistBuildClosureTransportErrorV1::InvalidPrefix);
    }
    let mut text = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut text, "{byte:02x}")
            .map_err(|_| MacosSdistBuildClosureTransportErrorV1::InvalidPrefix)?;
    }
    Sha256Digest::parse(format!("sha256:{text}"))
        .map_err(|_| MacosSdistBuildClosureTransportErrorV1::InvalidPrefix)
}
