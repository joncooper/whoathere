use crate::{
    decode_and_validate_macos_artifact_run_spec_v1, MacosArtifactRunSpecV1,
    MAX_MACOS_ARTIFACT_RUN_SPEC_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::io::{self, Write};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::MAX_ARTIFACT_SCENARIO_BYTES_V1;

pub const MACOS_ARTIFACT_SUBMISSION_HEADER_SCHEMA_V1: &str =
    "whoathere.macos_artifact_submission_header.v1";
pub const MACOS_ARTIFACT_SUBMISSION_MAGIC_V1: [u8; 8] = *b"WHOAART1";
pub const MACOS_ARTIFACT_SUBMISSION_VERSION_V1: u16 = 1;
pub const MACOS_ARTIFACT_SUBMISSION_FRAME_TYPE_V1: u16 = 1;
pub const MAX_MACOS_ARTIFACT_SUBMISSION_HEADER_BYTES_V1: usize =
    MAX_MACOS_ARTIFACT_RUN_SPEC_BYTES_V1 + 64 * 1024;
pub const MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1: usize = 8 + 2 + 2 + 4 + 8 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosArtifactSubmissionErrorV1 {
    InvalidHeader,
    Serialization,
    HeaderLimitExceeded,
    ArtifactLimitExceeded,
    ArtifactDigestMismatch,
    InvalidMagic,
    UnsupportedVersion,
    UnsupportedFrameType,
    RunSpecInvalid,
    BindingMismatch,
    Truncated,
    TrailingData,
    IoFailed,
}

impl MacosArtifactSubmissionErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidHeader => "macos_artifact_submission_header_invalid",
            Self::Serialization => "macos_artifact_submission_serialization_failed",
            Self::HeaderLimitExceeded => "macos_artifact_submission_header_limit_exceeded",
            Self::ArtifactLimitExceeded => "macos_artifact_submission_artifact_limit_exceeded",
            Self::ArtifactDigestMismatch => "macos_artifact_submission_artifact_digest_mismatch",
            Self::InvalidMagic => "macos_artifact_submission_magic_invalid",
            Self::UnsupportedVersion => "macos_artifact_submission_version_unsupported",
            Self::UnsupportedFrameType => "macos_artifact_submission_frame_type_unsupported",
            Self::RunSpecInvalid => "macos_artifact_submission_run_spec_invalid",
            Self::BindingMismatch => "macos_artifact_submission_binding_mismatch",
            Self::Truncated => "macos_artifact_submission_truncated",
            Self::TrailingData => "macos_artifact_submission_trailing_data",
            Self::IoFailed => "macos_artifact_submission_io_failed",
        }
    }
}

impl fmt::Display for MacosArtifactSubmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosArtifactSubmissionErrorV1 {}

impl From<io::Error> for MacosArtifactSubmissionErrorV1 {
    fn from(_: io::Error) -> Self {
        Self::IoFailed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosArtifactSubmissionBindingsV1 {
    challenge_binding_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
}

impl MacosArtifactSubmissionBindingsV1 {
    pub fn for_run_spec(
        challenge_binding_sha256: Sha256Digest,
        run_spec: &MacosArtifactRunSpecV1,
    ) -> Self {
        let execution_binding_sha256 =
            execution_binding_sha256_v1(&challenge_binding_sha256, run_spec.run_spec_sha256());
        Self {
            challenge_binding_sha256,
            execution_binding_sha256,
        }
    }

    pub fn challenge_binding_sha256(&self) -> &Sha256Digest {
        &self.challenge_binding_sha256
    }

    pub fn execution_binding_sha256(&self) -> &Sha256Digest {
        &self.execution_binding_sha256
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacosArtifactSubmissionHeaderWireV1 {
    schema_version: String,
    run_spec: serde_json::Value,
    run_spec_sha256: Sha256Digest,
    challenge_binding_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
    artifact_transport_ceiling: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosArtifactSubmissionHeaderV1 {
    run_spec: MacosArtifactRunSpecV1,
    bindings: MacosArtifactSubmissionBindingsV1,
    canonical_json: Vec<u8>,
}

impl fmt::Debug for MacosArtifactSubmissionHeaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosArtifactSubmissionHeaderV1")
            .field("run_spec_sha256", &self.run_spec.run_spec_sha256())
            .field("template_sha256", &self.run_spec.template_sha256())
            .field(
                "challenge_binding_sha256",
                &self.bindings.challenge_binding_sha256,
            )
            .field(
                "execution_binding_sha256",
                &self.bindings.execution_binding_sha256,
            )
            .field("artifact_sha256", &self.run_spec.artifact_sha256())
            .field(
                "artifact_byte_length",
                &self.run_spec.artifact_byte_length(),
            )
            .field("canonical_json", &"<redacted>")
            .finish()
    }
}

impl MacosArtifactSubmissionHeaderV1 {
    pub fn new(
        run_spec: MacosArtifactRunSpecV1,
        bindings: MacosArtifactSubmissionBindingsV1,
    ) -> Result<Self, MacosArtifactSubmissionErrorV1> {
        if bindings.execution_binding_sha256
            != execution_binding_sha256_v1(
                &bindings.challenge_binding_sha256,
                run_spec.run_spec_sha256(),
            )
        {
            return Err(MacosArtifactSubmissionErrorV1::BindingMismatch);
        }
        let canonical_json = canonical_header_v1(&run_spec, &bindings)?;
        Ok(Self {
            run_spec,
            bindings,
            canonical_json,
        })
    }

    pub fn run_spec(&self) -> &MacosArtifactRunSpecV1 {
        &self.run_spec
    }

    pub fn bindings(&self) -> &MacosArtifactSubmissionBindingsV1 {
        &self.bindings
    }

    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }
}

fn canonical_header_v1(
    run_spec: &MacosArtifactRunSpecV1,
    bindings: &MacosArtifactSubmissionBindingsV1,
) -> Result<Vec<u8>, MacosArtifactSubmissionErrorV1> {
    let run_spec_value = serde_json::from_slice(run_spec.canonical_json_v1())
        .map_err(|_| MacosArtifactSubmissionErrorV1::RunSpecInvalid)?;
    let wire = MacosArtifactSubmissionHeaderWireV1 {
        schema_version: MACOS_ARTIFACT_SUBMISSION_HEADER_SCHEMA_V1.to_string(),
        run_spec: run_spec_value,
        run_spec_sha256: run_spec.run_spec_sha256().clone(),
        challenge_binding_sha256: bindings.challenge_binding_sha256.clone(),
        execution_binding_sha256: bindings.execution_binding_sha256.clone(),
        artifact_sha256: run_spec.artifact_sha256().clone(),
        artifact_byte_length: run_spec.artifact_byte_length(),
        artifact_transport_ceiling: MAX_ARTIFACT_SCENARIO_BYTES_V1,
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosArtifactSubmissionErrorV1::Serialization)?;
    if bytes.len() > MAX_MACOS_ARTIFACT_SUBMISSION_HEADER_BYTES_V1 {
        return Err(MacosArtifactSubmissionErrorV1::HeaderLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosArtifactSubmissionFrameV1 {
    header: MacosArtifactSubmissionHeaderV1,
    artifact_bytes: Vec<u8>,
}

impl fmt::Debug for MacosArtifactSubmissionFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosArtifactSubmissionFrameV1")
            .field("header", &self.header)
            .field("artifact_byte_length", &self.artifact_bytes.len())
            .field("artifact_bytes", &"<redacted>")
            .finish()
    }
}

impl MacosArtifactSubmissionFrameV1 {
    pub fn header(&self) -> &MacosArtifactSubmissionHeaderV1 {
        &self.header
    }

    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }
}

pub fn write_macos_artifact_submission_frame_v1<W: Write>(
    writer: &mut W,
    header: &MacosArtifactSubmissionHeaderV1,
    artifact_bytes: &[u8],
) -> Result<(), MacosArtifactSubmissionErrorV1> {
    let run_spec = header.run_spec();
    if artifact_bytes.is_empty()
        || artifact_bytes.len() as u64 != run_spec.artifact_byte_length()
        || artifact_bytes.len() as u64 > MAX_ARTIFACT_SCENARIO_BYTES_V1
    {
        return Err(MacosArtifactSubmissionErrorV1::ArtifactLimitExceeded);
    }
    if Sha256Digest::from_bytes(artifact_bytes) != *run_spec.artifact_sha256() {
        return Err(MacosArtifactSubmissionErrorV1::ArtifactDigestMismatch);
    }
    let header_bytes = header.canonical_json_v1();
    if header_bytes.is_empty() || header_bytes.len() > MAX_MACOS_ARTIFACT_SUBMISSION_HEADER_BYTES_V1
    {
        return Err(MacosArtifactSubmissionErrorV1::HeaderLimitExceeded);
    }
    let header_len = u32::try_from(header_bytes.len())
        .map_err(|_| MacosArtifactSubmissionErrorV1::HeaderLimitExceeded)?;
    let raw_digest = digest_to_raw_v1(run_spec.artifact_sha256())?;

    writer.write_all(&MACOS_ARTIFACT_SUBMISSION_MAGIC_V1)?;
    writer.write_all(&MACOS_ARTIFACT_SUBMISSION_VERSION_V1.to_be_bytes())?;
    writer.write_all(&MACOS_ARTIFACT_SUBMISSION_FRAME_TYPE_V1.to_be_bytes())?;
    writer.write_all(&header_len.to_be_bytes())?;
    writer.write_all(&run_spec.artifact_byte_length().to_be_bytes())?;
    writer.write_all(&raw_digest)?;
    writer.write_all(header_bytes)?;
    writer.write_all(artifact_bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn encode_macos_artifact_submission_frame_v1(
    header: &MacosArtifactSubmissionHeaderV1,
    artifact_bytes: &[u8],
) -> Result<Vec<u8>, MacosArtifactSubmissionErrorV1> {
    let capacity = MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1
        .checked_add(header.canonical_json_v1().len())
        .and_then(|value| value.checked_add(artifact_bytes.len()))
        .ok_or(MacosArtifactSubmissionErrorV1::ArtifactLimitExceeded)?;
    let mut encoded = Vec::with_capacity(capacity);
    write_macos_artifact_submission_frame_v1(&mut encoded, header, artifact_bytes)?;
    Ok(encoded)
}

pub fn decode_macos_artifact_submission_frame_v1(
    encoded: &[u8],
    expected_bindings: &MacosArtifactSubmissionBindingsV1,
) -> Result<MacosArtifactSubmissionFrameV1, MacosArtifactSubmissionErrorV1> {
    if encoded.len() < MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1 {
        return Err(MacosArtifactSubmissionErrorV1::Truncated);
    }
    if encoded[..8] != MACOS_ARTIFACT_SUBMISSION_MAGIC_V1 {
        return Err(MacosArtifactSubmissionErrorV1::InvalidMagic);
    }
    let version = u16::from_be_bytes(
        encoded[8..10]
            .try_into()
            .map_err(|_| MacosArtifactSubmissionErrorV1::Truncated)?,
    );
    if version != MACOS_ARTIFACT_SUBMISSION_VERSION_V1 {
        return Err(MacosArtifactSubmissionErrorV1::UnsupportedVersion);
    }
    let frame_type = u16::from_be_bytes(
        encoded[10..12]
            .try_into()
            .map_err(|_| MacosArtifactSubmissionErrorV1::Truncated)?,
    );
    if frame_type != MACOS_ARTIFACT_SUBMISSION_FRAME_TYPE_V1 {
        return Err(MacosArtifactSubmissionErrorV1::UnsupportedFrameType);
    }
    let header_len = u32::from_be_bytes(
        encoded[12..16]
            .try_into()
            .map_err(|_| MacosArtifactSubmissionErrorV1::Truncated)?,
    ) as usize;
    if header_len == 0 || header_len > MAX_MACOS_ARTIFACT_SUBMISSION_HEADER_BYTES_V1 {
        return Err(MacosArtifactSubmissionErrorV1::HeaderLimitExceeded);
    }
    let artifact_len = u64::from_be_bytes(
        encoded[16..24]
            .try_into()
            .map_err(|_| MacosArtifactSubmissionErrorV1::Truncated)?,
    );
    if artifact_len == 0 || artifact_len > MAX_ARTIFACT_SCENARIO_BYTES_V1 {
        return Err(MacosArtifactSubmissionErrorV1::ArtifactLimitExceeded);
    }
    let expected_total = MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1
        .checked_add(header_len)
        .and_then(|value| value.checked_add(usize::try_from(artifact_len).ok()?))
        .ok_or(MacosArtifactSubmissionErrorV1::ArtifactLimitExceeded)?;
    if encoded.len() < expected_total {
        return Err(MacosArtifactSubmissionErrorV1::Truncated);
    }
    if encoded.len() > expected_total {
        return Err(MacosArtifactSubmissionErrorV1::TrailingData);
    }
    let raw_digest: [u8; 32] = encoded[24..56]
        .try_into()
        .map_err(|_| MacosArtifactSubmissionErrorV1::Truncated)?;
    let prefix_digest = raw_to_digest_v1(raw_digest)?;
    let header_start = MACOS_ARTIFACT_SUBMISSION_FIXED_PREFIX_BYTES_V1;
    let artifact_start = header_start + header_len;
    let header_bytes = &encoded[header_start..artifact_start];
    let artifact_bytes = &encoded[artifact_start..];

    let mut deserializer = serde_json::Deserializer::from_slice(header_bytes);
    let wire = MacosArtifactSubmissionHeaderWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosArtifactSubmissionErrorV1::InvalidHeader)?;
    deserializer
        .end()
        .map_err(|_| MacosArtifactSubmissionErrorV1::InvalidHeader)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosArtifactSubmissionErrorV1::Serialization)?;
    if canonical != header_bytes
        || wire.schema_version != MACOS_ARTIFACT_SUBMISSION_HEADER_SCHEMA_V1
        || wire.artifact_transport_ceiling != MAX_ARTIFACT_SCENARIO_BYTES_V1
    {
        return Err(MacosArtifactSubmissionErrorV1::InvalidHeader);
    }
    if wire.challenge_binding_sha256 != expected_bindings.challenge_binding_sha256
        || wire.execution_binding_sha256 != expected_bindings.execution_binding_sha256
    {
        return Err(MacosArtifactSubmissionErrorV1::BindingMismatch);
    }
    let run_spec_bytes = serde_json_canonicalizer::to_vec(&wire.run_spec)
        .map_err(|_| MacosArtifactSubmissionErrorV1::Serialization)?;
    if Sha256Digest::from_bytes(&run_spec_bytes) != wire.run_spec_sha256 {
        return Err(MacosArtifactSubmissionErrorV1::RunSpecInvalid);
    }
    let run_spec = decode_and_validate_macos_artifact_run_spec_v1(&run_spec_bytes)
        .map_err(|_| MacosArtifactSubmissionErrorV1::RunSpecInvalid)?;
    let derived_execution_binding =
        execution_binding_sha256_v1(&wire.challenge_binding_sha256, run_spec.run_spec_sha256());
    if wire.execution_binding_sha256 != derived_execution_binding {
        return Err(MacosArtifactSubmissionErrorV1::BindingMismatch);
    }
    if wire.run_spec_sha256 != *run_spec.run_spec_sha256()
        || wire.artifact_sha256 != *run_spec.artifact_sha256()
        || wire.artifact_byte_length != run_spec.artifact_byte_length()
        || wire.artifact_byte_length != artifact_len
        || wire.artifact_sha256 != prefix_digest
        || Sha256Digest::from_bytes(artifact_bytes) != prefix_digest
    {
        return Err(MacosArtifactSubmissionErrorV1::ArtifactDigestMismatch);
    }
    let header = MacosArtifactSubmissionHeaderV1 {
        run_spec,
        bindings: expected_bindings.clone(),
        canonical_json: canonical,
    };
    Ok(MacosArtifactSubmissionFrameV1 {
        header,
        artifact_bytes: artifact_bytes.to_vec(),
    })
}

fn execution_binding_sha256_v1(
    challenge_binding_sha256: &Sha256Digest,
    run_spec_sha256: &Sha256Digest,
) -> Sha256Digest {
    Sha256Digest::from_bytes(
        format!(
            "whoathere.macos_artifact_submission_execution_binding.v1\0{}\0{}",
            challenge_binding_sha256, run_spec_sha256
        )
        .as_bytes(),
    )
}

fn digest_to_raw_v1(digest: &Sha256Digest) -> Result<[u8; 32], MacosArtifactSubmissionErrorV1> {
    let hexadecimal = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(MacosArtifactSubmissionErrorV1::InvalidHeader)?;
    let mut raw = [0u8; 32];
    for (index, output) in raw.iter_mut().enumerate() {
        let offset = index * 2;
        *output = u8::from_str_radix(&hexadecimal[offset..offset + 2], 16)
            .map_err(|_| MacosArtifactSubmissionErrorV1::InvalidHeader)?;
    }
    Ok(raw)
}

fn raw_to_digest_v1(raw: [u8; 32]) -> Result<Sha256Digest, MacosArtifactSubmissionErrorV1> {
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}")
            .map_err(|_| MacosArtifactSubmissionErrorV1::Serialization)?;
    }
    Sha256Digest::parse(value).map_err(|_| MacosArtifactSubmissionErrorV1::InvalidHeader)
}
