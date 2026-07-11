use crate::{
    decode_and_validate_macos_wheel_run_spec_v1, MacosWheelRunSpecV1,
    MAX_MACOS_WHEEL_RUN_SPEC_BYTES_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use std::io::{self, Read, Write};
use whoathere_artifact::Sha256Digest;
use whoathere_detonation::MAX_ARTIFACT_SCENARIO_BYTES_V1;

pub const MACOS_WHEEL_SUBMISSION_HEADER_SCHEMA_V1: &str =
    "whoathere.macos_wheel_submission_header.v1";
pub const MACOS_WHEEL_SUBMISSION_MAGIC_V1: [u8; 8] = *b"WHOAWHE1";
pub const MACOS_WHEEL_GUEST_SUBMISSION_MAGIC_V1: [u8; 8] = *b"WHOWGST1";
pub const MACOS_WHEEL_SUBMISSION_VERSION_V1: u16 = 1;
pub const MACOS_WHEEL_SUBMISSION_FRAME_TYPE_V1: u16 = 1;
pub const MAX_MACOS_WHEEL_SUBMISSION_HEADER_BYTES_V1: usize =
    MAX_MACOS_WHEEL_RUN_SPEC_BYTES_V1 + 64 * 1024;
pub const MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1: usize = 8 + 2 + 2 + 4 + 8 + 32;
const MACOS_WHEEL_EXECUTION_BINDING_DOMAIN_V1: &str =
    "whoathere.macos_wheel_submission_execution_binding.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosWheelSubmissionErrorV1 {
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

impl MacosWheelSubmissionErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidHeader => "macos_wheel_submission_header_invalid",
            Self::Serialization => "macos_wheel_submission_serialization_failed",
            Self::HeaderLimitExceeded => "macos_wheel_submission_header_limit_exceeded",
            Self::ArtifactLimitExceeded => "macos_wheel_submission_artifact_limit_exceeded",
            Self::ArtifactDigestMismatch => "macos_wheel_submission_artifact_digest_mismatch",
            Self::InvalidMagic => "macos_wheel_submission_magic_invalid",
            Self::UnsupportedVersion => "macos_wheel_submission_version_unsupported",
            Self::UnsupportedFrameType => "macos_wheel_submission_frame_type_unsupported",
            Self::RunSpecInvalid => "macos_wheel_submission_run_spec_invalid",
            Self::BindingMismatch => "macos_wheel_submission_binding_mismatch",
            Self::Truncated => "macos_wheel_submission_truncated",
            Self::TrailingData => "macos_wheel_submission_trailing_data",
            Self::IoFailed => "macos_wheel_submission_io_failed",
        }
    }
}

impl fmt::Display for MacosWheelSubmissionErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosWheelSubmissionErrorV1 {}

impl From<io::Error> for MacosWheelSubmissionErrorV1 {
    fn from(_: io::Error) -> Self {
        Self::IoFailed
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosWheelSubmissionBindingsV1 {
    challenge_binding_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
}

impl MacosWheelSubmissionBindingsV1 {
    pub fn for_run_spec(
        challenge_binding_sha256: Sha256Digest,
        run_spec: &MacosWheelRunSpecV1,
    ) -> Self {
        let execution_binding_sha256 = macos_wheel_execution_binding_sha256_v1(
            &challenge_binding_sha256,
            run_spec.run_spec_sha256(),
        );
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
struct MacosWheelSubmissionHeaderWireV1 {
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
pub struct MacosWheelSubmissionHeaderV1 {
    run_spec: MacosWheelRunSpecV1,
    bindings: MacosWheelSubmissionBindingsV1,
    canonical_json: Vec<u8>,
}

impl fmt::Debug for MacosWheelSubmissionHeaderV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosWheelSubmissionHeaderV1")
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

impl MacosWheelSubmissionHeaderV1 {
    pub fn new(
        run_spec: MacosWheelRunSpecV1,
        bindings: MacosWheelSubmissionBindingsV1,
    ) -> Result<Self, MacosWheelSubmissionErrorV1> {
        if bindings.execution_binding_sha256
            != macos_wheel_execution_binding_sha256_v1(
                &bindings.challenge_binding_sha256,
                run_spec.run_spec_sha256(),
            )
        {
            return Err(MacosWheelSubmissionErrorV1::BindingMismatch);
        }
        let canonical_json = canonical_wheel_header_v1(&run_spec, &bindings)?;
        Ok(Self {
            run_spec,
            bindings,
            canonical_json,
        })
    }

    pub fn run_spec(&self) -> &MacosWheelRunSpecV1 {
        &self.run_spec
    }

    pub fn bindings(&self) -> &MacosWheelSubmissionBindingsV1 {
        &self.bindings
    }

    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
    }
}

fn canonical_wheel_header_v1(
    run_spec: &MacosWheelRunSpecV1,
    bindings: &MacosWheelSubmissionBindingsV1,
) -> Result<Vec<u8>, MacosWheelSubmissionErrorV1> {
    let run_spec_value = serde_json::from_slice(run_spec.canonical_json_v1())
        .map_err(|_| MacosWheelSubmissionErrorV1::RunSpecInvalid)?;
    let wire = MacosWheelSubmissionHeaderWireV1 {
        schema_version: MACOS_WHEEL_SUBMISSION_HEADER_SCHEMA_V1.to_string(),
        run_spec: run_spec_value,
        run_spec_sha256: run_spec.run_spec_sha256().clone(),
        challenge_binding_sha256: bindings.challenge_binding_sha256.clone(),
        execution_binding_sha256: bindings.execution_binding_sha256.clone(),
        artifact_sha256: run_spec.artifact_sha256().clone(),
        artifact_byte_length: run_spec.artifact_byte_length(),
        artifact_transport_ceiling: MAX_ARTIFACT_SCENARIO_BYTES_V1,
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosWheelSubmissionErrorV1::Serialization)?;
    if bytes.len() > MAX_MACOS_WHEEL_SUBMISSION_HEADER_BYTES_V1 {
        return Err(MacosWheelSubmissionErrorV1::HeaderLimitExceeded);
    }
    Ok(bytes)
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosWheelSubmissionFrameV1 {
    header: MacosWheelSubmissionHeaderV1,
    artifact_bytes: Vec<u8>,
}

impl fmt::Debug for MacosWheelSubmissionFrameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosWheelSubmissionFrameV1")
            .field("header", &self.header)
            .field("artifact_byte_length", &self.artifact_bytes.len())
            .field("artifact_bytes", &"<redacted>")
            .finish()
    }
}

impl MacosWheelSubmissionFrameV1 {
    pub fn header(&self) -> &MacosWheelSubmissionHeaderV1 {
        &self.header
    }

    pub fn artifact_bytes(&self) -> &[u8] {
        &self.artifact_bytes
    }
}

pub fn write_macos_wheel_submission_frame_v1<W: Write>(
    writer: &mut W,
    header: &MacosWheelSubmissionHeaderV1,
    artifact_bytes: &[u8],
) -> Result<(), MacosWheelSubmissionErrorV1> {
    let run_spec = header.run_spec();
    if artifact_bytes.is_empty()
        || artifact_bytes.len() as u64 != run_spec.artifact_byte_length()
        || artifact_bytes.len() as u64 > MAX_ARTIFACT_SCENARIO_BYTES_V1
    {
        return Err(MacosWheelSubmissionErrorV1::ArtifactLimitExceeded);
    }
    if Sha256Digest::from_bytes(artifact_bytes) != *run_spec.artifact_sha256() {
        return Err(MacosWheelSubmissionErrorV1::ArtifactDigestMismatch);
    }
    let header_bytes = header.canonical_json_v1();
    if header_bytes.is_empty() || header_bytes.len() > MAX_MACOS_WHEEL_SUBMISSION_HEADER_BYTES_V1 {
        return Err(MacosWheelSubmissionErrorV1::HeaderLimitExceeded);
    }
    let header_len = u32::try_from(header_bytes.len())
        .map_err(|_| MacosWheelSubmissionErrorV1::HeaderLimitExceeded)?;
    let raw_digest = wheel_digest_to_raw_v1(run_spec.artifact_sha256())?;

    writer.write_all(&MACOS_WHEEL_SUBMISSION_MAGIC_V1)?;
    writer.write_all(&MACOS_WHEEL_SUBMISSION_VERSION_V1.to_be_bytes())?;
    writer.write_all(&MACOS_WHEEL_SUBMISSION_FRAME_TYPE_V1.to_be_bytes())?;
    writer.write_all(&header_len.to_be_bytes())?;
    writer.write_all(&run_spec.artifact_byte_length().to_be_bytes())?;
    writer.write_all(&raw_digest)?;
    writer.write_all(header_bytes)?;
    writer.write_all(artifact_bytes)?;
    writer.flush()?;
    Ok(())
}

pub fn encode_macos_wheel_submission_frame_v1(
    header: &MacosWheelSubmissionHeaderV1,
    artifact_bytes: &[u8],
) -> Result<Vec<u8>, MacosWheelSubmissionErrorV1> {
    let capacity = MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1
        .checked_add(header.canonical_json_v1().len())
        .and_then(|value| value.checked_add(artifact_bytes.len()))
        .ok_or(MacosWheelSubmissionErrorV1::ArtifactLimitExceeded)?;
    let mut encoded = Vec::with_capacity(capacity);
    write_macos_wheel_submission_frame_v1(&mut encoded, header, artifact_bytes)?;
    Ok(encoded)
}

pub fn decode_macos_wheel_submission_frame_v1(
    encoded: &[u8],
    expected_bindings: &MacosWheelSubmissionBindingsV1,
) -> Result<MacosWheelSubmissionFrameV1, MacosWheelSubmissionErrorV1> {
    if encoded.len() < MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1 {
        return Err(MacosWheelSubmissionErrorV1::Truncated);
    }
    if encoded[..8] != MACOS_WHEEL_SUBMISSION_MAGIC_V1 {
        return Err(MacosWheelSubmissionErrorV1::InvalidMagic);
    }
    let version = u16::from_be_bytes(
        encoded[8..10]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    );
    if version != MACOS_WHEEL_SUBMISSION_VERSION_V1 {
        return Err(MacosWheelSubmissionErrorV1::UnsupportedVersion);
    }
    let frame_type = u16::from_be_bytes(
        encoded[10..12]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    );
    if frame_type != MACOS_WHEEL_SUBMISSION_FRAME_TYPE_V1 {
        return Err(MacosWheelSubmissionErrorV1::UnsupportedFrameType);
    }
    let header_len = u32::from_be_bytes(
        encoded[12..16]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    ) as usize;
    if header_len == 0 || header_len > MAX_MACOS_WHEEL_SUBMISSION_HEADER_BYTES_V1 {
        return Err(MacosWheelSubmissionErrorV1::HeaderLimitExceeded);
    }
    let artifact_len = u64::from_be_bytes(
        encoded[16..24]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    );
    if artifact_len == 0 || artifact_len > MAX_ARTIFACT_SCENARIO_BYTES_V1 {
        return Err(MacosWheelSubmissionErrorV1::ArtifactLimitExceeded);
    }
    let expected_total = MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1
        .checked_add(header_len)
        .and_then(|value| value.checked_add(usize::try_from(artifact_len).ok()?))
        .ok_or(MacosWheelSubmissionErrorV1::ArtifactLimitExceeded)?;
    if encoded.len() < expected_total {
        return Err(MacosWheelSubmissionErrorV1::Truncated);
    }
    if encoded.len() > expected_total {
        return Err(MacosWheelSubmissionErrorV1::TrailingData);
    }
    let raw_digest: [u8; 32] = encoded[24..56]
        .try_into()
        .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?;
    let prefix_digest = wheel_raw_to_digest_v1(raw_digest);
    let header_start = MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1;
    let artifact_start = header_start + header_len;
    let header = decode_wheel_submission_header_v1(
        &encoded[header_start..artifact_start],
        artifact_len,
        &prefix_digest,
        Some(expected_bindings),
    )?;
    let artifact_bytes = &encoded[artifact_start..];
    if Sha256Digest::from_bytes(artifact_bytes) != prefix_digest {
        return Err(MacosWheelSubmissionErrorV1::ArtifactDigestMismatch);
    }
    Ok(MacosWheelSubmissionFrameV1 {
        header,
        artifact_bytes: artifact_bytes.to_vec(),
    })
}

fn decode_wheel_submission_header_v1(
    header_bytes: &[u8],
    artifact_len: u64,
    prefix_digest: &Sha256Digest,
    expected_bindings: Option<&MacosWheelSubmissionBindingsV1>,
) -> Result<MacosWheelSubmissionHeaderV1, MacosWheelSubmissionErrorV1> {
    let mut deserializer = serde_json::Deserializer::from_slice(header_bytes);
    let wire = MacosWheelSubmissionHeaderWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosWheelSubmissionErrorV1::InvalidHeader)?;
    deserializer
        .end()
        .map_err(|_| MacosWheelSubmissionErrorV1::InvalidHeader)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosWheelSubmissionErrorV1::Serialization)?;
    if canonical != header_bytes
        || wire.schema_version != MACOS_WHEEL_SUBMISSION_HEADER_SCHEMA_V1
        || wire.artifact_transport_ceiling != MAX_ARTIFACT_SCENARIO_BYTES_V1
    {
        return Err(MacosWheelSubmissionErrorV1::InvalidHeader);
    }
    if let Some(expected) = expected_bindings {
        if wire.challenge_binding_sha256 != expected.challenge_binding_sha256
            || wire.execution_binding_sha256 != expected.execution_binding_sha256
        {
            return Err(MacosWheelSubmissionErrorV1::BindingMismatch);
        }
    }
    let run_spec_bytes = serde_json_canonicalizer::to_vec(&wire.run_spec)
        .map_err(|_| MacosWheelSubmissionErrorV1::Serialization)?;
    if Sha256Digest::from_bytes(&run_spec_bytes) != wire.run_spec_sha256 {
        return Err(MacosWheelSubmissionErrorV1::RunSpecInvalid);
    }
    let run_spec = decode_and_validate_macos_wheel_run_spec_v1(&run_spec_bytes)
        .map_err(|_| MacosWheelSubmissionErrorV1::RunSpecInvalid)?;
    let derived_execution_binding = macos_wheel_execution_binding_sha256_v1(
        &wire.challenge_binding_sha256,
        run_spec.run_spec_sha256(),
    );
    if wire.execution_binding_sha256 != derived_execution_binding {
        return Err(MacosWheelSubmissionErrorV1::BindingMismatch);
    }
    if wire.run_spec_sha256 != *run_spec.run_spec_sha256()
        || wire.artifact_sha256 != *run_spec.artifact_sha256()
        || wire.artifact_byte_length != run_spec.artifact_byte_length()
        || wire.artifact_byte_length != artifact_len
        || wire.artifact_sha256 != *prefix_digest
    {
        return Err(MacosWheelSubmissionErrorV1::ArtifactDigestMismatch);
    }
    let bindings = MacosWheelSubmissionBindingsV1 {
        challenge_binding_sha256: wire.challenge_binding_sha256,
        execution_binding_sha256: wire.execution_binding_sha256,
    };
    Ok(MacosWheelSubmissionHeaderV1 {
        run_spec,
        bindings,
        canonical_json: canonical,
    })
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosWheelGuestSubmissionObservationV1 {
    header: MacosWheelSubmissionHeaderV1,
    artifact_sha256: Sha256Digest,
    artifact_byte_length: u64,
}

impl fmt::Debug for MacosWheelGuestSubmissionObservationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosWheelGuestSubmissionObservationV1")
            .field("header", &self.header)
            .field("artifact_sha256", &self.artifact_sha256)
            .field("artifact_byte_length", &self.artifact_byte_length)
            .finish()
    }
}

impl MacosWheelGuestSubmissionObservationV1 {
    pub fn header(&self) -> &MacosWheelSubmissionHeaderV1 {
        &self.header
    }

    pub fn artifact_sha256(&self) -> &Sha256Digest {
        &self.artifact_sha256
    }

    pub fn artifact_byte_length(&self) -> u64 {
        self.artifact_byte_length
    }
}

/// Decode one authenticated helper-to-guest wheel frame without buffering the artifact.
///
/// The caller owns the sink and must discard it on every error. Success proves the complete
/// declared body, SHA-256, canonical wheel run spec, and transport EOF. Challenge authority must
/// already have been established by the wheel-specific authenticated guest session before the
/// helper forwards this frame.
pub fn stream_macos_wheel_guest_submission_v1<R: Read, W: Write>(
    reader: &mut R,
    artifact_sink: &mut W,
) -> Result<MacosWheelGuestSubmissionObservationV1, MacosWheelSubmissionErrorV1> {
    let mut prefix = [0_u8; MACOS_WHEEL_SUBMISSION_FIXED_PREFIX_BYTES_V1];
    read_exact_wheel_submission_v1(reader, &mut prefix)?;
    if prefix[..8] != MACOS_WHEEL_GUEST_SUBMISSION_MAGIC_V1 {
        return Err(MacosWheelSubmissionErrorV1::InvalidMagic);
    }
    let version = u16::from_be_bytes(
        prefix[8..10]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    );
    if version != MACOS_WHEEL_SUBMISSION_VERSION_V1 {
        return Err(MacosWheelSubmissionErrorV1::UnsupportedVersion);
    }
    let frame_type = u16::from_be_bytes(
        prefix[10..12]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    );
    if frame_type != MACOS_WHEEL_SUBMISSION_FRAME_TYPE_V1 {
        return Err(MacosWheelSubmissionErrorV1::UnsupportedFrameType);
    }
    let header_len = u32::from_be_bytes(
        prefix[12..16]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    ) as usize;
    if header_len == 0 || header_len > MAX_MACOS_WHEEL_SUBMISSION_HEADER_BYTES_V1 {
        return Err(MacosWheelSubmissionErrorV1::HeaderLimitExceeded);
    }
    let artifact_len = u64::from_be_bytes(
        prefix[16..24]
            .try_into()
            .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?,
    );
    if artifact_len == 0 || artifact_len > MAX_ARTIFACT_SCENARIO_BYTES_V1 {
        return Err(MacosWheelSubmissionErrorV1::ArtifactLimitExceeded);
    }
    let raw_digest: [u8; 32] = prefix[24..56]
        .try_into()
        .map_err(|_| MacosWheelSubmissionErrorV1::Truncated)?;
    let prefix_digest = wheel_raw_to_digest_v1(raw_digest);
    let mut header_bytes = vec![0_u8; header_len];
    read_exact_wheel_submission_v1(reader, &mut header_bytes)?;
    let header =
        decode_wheel_submission_header_v1(&header_bytes, artifact_len, &prefix_digest, None)?;

    let mut hasher = Sha256::new();
    let mut remaining = artifact_len;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining > 0 {
        let requested = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|_| MacosWheelSubmissionErrorV1::ArtifactLimitExceeded)?;
        read_exact_wheel_submission_v1(reader, &mut buffer[..requested])?;
        hasher.update(&buffer[..requested]);
        artifact_sink.write_all(&buffer[..requested])?;
        remaining -= requested as u64;
    }
    let observed_raw: [u8; 32] = hasher.finalize().into();
    if observed_raw != raw_digest {
        return Err(MacosWheelSubmissionErrorV1::ArtifactDigestMismatch);
    }
    let mut trailing = [0_u8; 1];
    loop {
        match reader.read(&mut trailing) {
            Ok(0) => break,
            Ok(_) => return Err(MacosWheelSubmissionErrorV1::TrailingData),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(MacosWheelSubmissionErrorV1::IoFailed),
        }
    }
    artifact_sink.flush()?;
    Ok(MacosWheelGuestSubmissionObservationV1 {
        header,
        artifact_sha256: prefix_digest,
        artifact_byte_length: artifact_len,
    })
}

fn read_exact_wheel_submission_v1<R: Read>(
    reader: &mut R,
    mut destination: &mut [u8],
) -> Result<(), MacosWheelSubmissionErrorV1> {
    while !destination.is_empty() {
        match reader.read(destination) {
            Ok(0) => return Err(MacosWheelSubmissionErrorV1::Truncated),
            Ok(count) => destination = &mut destination[count..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(MacosWheelSubmissionErrorV1::IoFailed),
        }
    }
    Ok(())
}

pub fn macos_wheel_execution_binding_sha256_v1(
    challenge_binding_sha256: &Sha256Digest,
    run_spec_sha256: &Sha256Digest,
) -> Sha256Digest {
    Sha256Digest::from_bytes(
        format!(
            "{MACOS_WHEEL_EXECUTION_BINDING_DOMAIN_V1}\0{challenge_binding_sha256}\0{run_spec_sha256}"
        )
        .as_bytes(),
    )
}

fn wheel_digest_to_raw_v1(digest: &Sha256Digest) -> Result<[u8; 32], MacosWheelSubmissionErrorV1> {
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(MacosWheelSubmissionErrorV1::ArtifactDigestMismatch)?;
    let mut raw = [0_u8; 32];
    for (index, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
        raw[index] = u8::from_str_radix(
            std::str::from_utf8(pair)
                .map_err(|_| MacosWheelSubmissionErrorV1::ArtifactDigestMismatch)?,
            16,
        )
        .map_err(|_| MacosWheelSubmissionErrorV1::ArtifactDigestMismatch)?;
    }
    Ok(raw)
}

fn wheel_raw_to_digest_v1(raw: [u8; 32]) -> Sha256Digest {
    let mut value = String::with_capacity(71);
    value.push_str("sha256:");
    for byte in raw {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("write digest hex");
    }
    Sha256Digest::parse(value).expect("raw digest is canonical")
}
