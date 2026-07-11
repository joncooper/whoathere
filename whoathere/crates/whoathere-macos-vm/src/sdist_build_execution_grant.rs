use crate::{macos_sdist_execution_binding_sha256_v1, MacosSdistGuestAuthChallengeV1};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use whoathere_artifact::Sha256Digest;
use zeroize::{Zeroize, Zeroizing};

pub const MACOS_SDIST_BUILD_EXECUTION_GRANT_SCHEMA_V1: &str =
    "whoathere.sdist_build_execution_grant.v1";
pub const MAX_MACOS_SDIST_BUILD_EXECUTION_GRANT_BYTES_V1: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosSdistBuildExecutionGrantErrorV1 {
    InvalidGrant,
    NonCanonical,
    BindingMismatch,
    AlreadyConsumed,
    LimitExceeded,
    Serialization,
}

impl MacosSdistBuildExecutionGrantErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidGrant => "macos_sdist_build_execution_grant_invalid",
            Self::NonCanonical => "macos_sdist_build_execution_grant_noncanonical",
            Self::BindingMismatch => "macos_sdist_build_execution_grant_binding_mismatch",
            Self::AlreadyConsumed => "macos_sdist_build_execution_grant_already_consumed",
            Self::LimitExceeded => "macos_sdist_build_execution_grant_limit_exceeded",
            Self::Serialization => "macos_sdist_build_execution_grant_serialization_failed",
        }
    }
}

impl fmt::Display for MacosSdistBuildExecutionGrantErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosSdistBuildExecutionGrantErrorV1 {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MacosSdistBuildExecutionGrantWireV1 {
    schema_version: String,
    capability_hex: String,
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
}

impl Drop for MacosSdistBuildExecutionGrantWireV1 {
    fn drop(&mut self) {
        self.capability_hex.zeroize();
    }
}

pub struct MacosSdistBuildExecutionGrantBytesV1 {
    bytes: Vec<u8>,
}

impl MacosSdistBuildExecutionGrantBytesV1 {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Debug for MacosSdistBuildExecutionGrantBytesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSdistBuildExecutionGrantBytesV1")
            .field("byte_length", &self.bytes.len())
            .field("bytes", &"<redacted-and-zeroized-on-drop>")
            .finish()
    }
}

impl Drop for MacosSdistBuildExecutionGrantBytesV1 {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosSdistBuildExecutionGrantObservationV1 {
    capability_sha256: Sha256Digest,
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    consumed: bool,
}

impl MacosSdistBuildExecutionGrantObservationV1 {
    pub fn capability_sha256(&self) -> &Sha256Digest {
        &self.capability_sha256
    }

    pub fn challenge_sha256(&self) -> &Sha256Digest {
        &self.challenge_sha256
    }

    pub fn execution_binding_sha256(&self) -> &Sha256Digest {
        &self.execution_binding_sha256
    }

    pub fn run_spec_sha256(&self) -> &Sha256Digest {
        &self.run_spec_sha256
    }

    pub fn build_closure_sha256(&self) -> &Sha256Digest {
        &self.build_closure_sha256
    }

    pub fn clone_binding_sha256(&self) -> &Sha256Digest {
        &self.clone_binding_sha256
    }

    pub fn consumed(&self) -> bool {
        self.consumed
    }
}

pub struct MacosSdistBuildExecutionGrantVerifierV1 {
    challenge: MacosSdistGuestAuthChallengeV1,
    consumed: AtomicBool,
}

impl fmt::Debug for MacosSdistBuildExecutionGrantVerifierV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSdistBuildExecutionGrantVerifierV1")
            .field(
                "challenge_sha256",
                &Sha256Digest::from_bytes(self.challenge.canonical_json_v1()),
            )
            .field("consumed", &self.consumed.load(Ordering::Acquire))
            .finish()
    }
}

impl MacosSdistBuildExecutionGrantVerifierV1 {
    pub fn new(challenge: MacosSdistGuestAuthChallengeV1) -> Self {
        Self {
            challenge,
            consumed: AtomicBool::new(false),
        }
    }

    /// Burns this verifier before parsing. Invalid, rebound, and valid grants are all one-shot.
    pub fn verify_and_consume(
        &self,
        mut bytes: Vec<u8>,
    ) -> Result<MacosSdistBuildExecutionGrantObservationV1, MacosSdistBuildExecutionGrantErrorV1>
    {
        let result = if self.consumed.swap(true, Ordering::AcqRel) {
            Err(MacosSdistBuildExecutionGrantErrorV1::AlreadyConsumed)
        } else {
            decode_and_verify_grant_v1(&bytes, &self.challenge)
        };
        bytes.zeroize();
        result
    }

    pub fn consumed(&self) -> bool {
        self.consumed.load(Ordering::Acquire)
    }
}

/// Encodes the secret half of a pre-issued execution capability. The capability is accepted only
/// when its SHA-256 recreates the challenge binding already committed into the exact submission's
/// execution binding. Callers must release these bytes only after a separately verified staging
/// proof; this low-level primitive deliberately does not make that policy decision.
pub fn encode_macos_sdist_build_execution_grant_v1(
    capability: [u8; 32],
    challenge: &MacosSdistGuestAuthChallengeV1,
) -> Result<MacosSdistBuildExecutionGrantBytesV1, MacosSdistBuildExecutionGrantErrorV1> {
    let capability = Zeroizing::new(capability);
    let capability_sha256 = Sha256Digest::from_bytes(capability.as_ref());
    if macos_sdist_execution_binding_sha256_v1(&capability_sha256, challenge.run_spec_sha256())
        != *challenge.execution_binding_sha256()
    {
        return Err(MacosSdistBuildExecutionGrantErrorV1::BindingMismatch);
    }
    let wire = MacosSdistBuildExecutionGrantWireV1 {
        schema_version: MACOS_SDIST_BUILD_EXECUTION_GRANT_SCHEMA_V1.to_string(),
        capability_hex: lower_hex_grant_v1(capability.as_ref()),
        challenge_sha256: Sha256Digest::from_bytes(challenge.canonical_json_v1()),
        execution_binding_sha256: challenge.execution_binding_sha256().clone(),
        run_spec_sha256: challenge.run_spec_sha256().clone(),
        build_closure_sha256: challenge.build_closure_sha256().clone(),
        clone_binding_sha256: challenge.clone_binding_sha256().clone(),
    };
    let bytes = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosSdistBuildExecutionGrantErrorV1::Serialization)?;
    if bytes.is_empty() || bytes.len() > MAX_MACOS_SDIST_BUILD_EXECUTION_GRANT_BYTES_V1 {
        return Err(MacosSdistBuildExecutionGrantErrorV1::LimitExceeded);
    }
    Ok(MacosSdistBuildExecutionGrantBytesV1 { bytes })
}

fn decode_and_verify_grant_v1(
    bytes: &[u8],
    challenge: &MacosSdistGuestAuthChallengeV1,
) -> Result<MacosSdistBuildExecutionGrantObservationV1, MacosSdistBuildExecutionGrantErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_MACOS_SDIST_BUILD_EXECUTION_GRANT_BYTES_V1 {
        return Err(MacosSdistBuildExecutionGrantErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = MacosSdistBuildExecutionGrantWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosSdistBuildExecutionGrantErrorV1::InvalidGrant)?;
    deserializer
        .end()
        .map_err(|_| MacosSdistBuildExecutionGrantErrorV1::InvalidGrant)?;
    let canonical = Zeroizing::new(
        serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| MacosSdistBuildExecutionGrantErrorV1::Serialization)?,
    );
    if canonical.as_slice() != bytes
        || wire.schema_version != MACOS_SDIST_BUILD_EXECUTION_GRANT_SCHEMA_V1
        || !valid_lower_hex_grant_v1(&wire.capability_hex, 64)
    {
        return Err(MacosSdistBuildExecutionGrantErrorV1::NonCanonical);
    }
    let capability = Zeroizing::new(decode_capability_grant_v1(&wire.capability_hex)?);
    let capability_sha256 = Sha256Digest::from_bytes(capability.as_ref());
    let expected_challenge_sha256 = Sha256Digest::from_bytes(challenge.canonical_json_v1());
    if wire.challenge_sha256 != expected_challenge_sha256
        || wire.execution_binding_sha256 != *challenge.execution_binding_sha256()
        || wire.run_spec_sha256 != *challenge.run_spec_sha256()
        || wire.build_closure_sha256 != *challenge.build_closure_sha256()
        || wire.clone_binding_sha256 != *challenge.clone_binding_sha256()
        || macos_sdist_execution_binding_sha256_v1(&capability_sha256, challenge.run_spec_sha256())
            != *challenge.execution_binding_sha256()
    {
        return Err(MacosSdistBuildExecutionGrantErrorV1::BindingMismatch);
    }
    Ok(MacosSdistBuildExecutionGrantObservationV1 {
        capability_sha256,
        challenge_sha256: wire.challenge_sha256.clone(),
        execution_binding_sha256: wire.execution_binding_sha256.clone(),
        run_spec_sha256: wire.run_spec_sha256.clone(),
        build_closure_sha256: wire.build_closure_sha256.clone(),
        clone_binding_sha256: wire.clone_binding_sha256.clone(),
        consumed: true,
    })
}

fn lower_hex_grant_v1(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn valid_lower_hex_grant_v1(value: &str, exact_length: usize) -> bool {
    value.len() == exact_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_capability_grant_v1(
    value: &str,
) -> Result<[u8; 32], MacosSdistBuildExecutionGrantErrorV1> {
    if !valid_lower_hex_grant_v1(value, 64) {
        return Err(MacosSdistBuildExecutionGrantErrorV1::InvalidGrant);
    }
    let mut decoded = [0_u8; 32];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| MacosSdistBuildExecutionGrantErrorV1::InvalidGrant)?;
    }
    Ok(decoded)
}
