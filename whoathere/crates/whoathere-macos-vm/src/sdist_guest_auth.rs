use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use whoathere_artifact::Sha256Digest;
use zeroize::Zeroize;

pub const MACOS_SDIST_GUEST_AUTH_CHALLENGE_SCHEMA_V1: &str =
    "whoathere.sdist_guest_auth_challenge.v1";
pub const MACOS_SDIST_GUEST_AUTH_RESPONSE_SCHEMA_V1: &str =
    "whoathere.sdist_guest_auth_response.v1";
pub const MAX_MACOS_SDIST_GUEST_AUTH_BYTES_V1: usize = 16 * 1024;
const SDIST_RESPONSE_SIGNATURE_DOMAIN_V1: &[u8] =
    b"whoathere.sdist_guest_auth.response_signature.v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacosSdistGuestAuthErrorV1 {
    InvalidChallenge,
    InvalidResponse,
    NonCanonical,
    PublicKeyMismatch,
    SignatureFailed,
    Serialization,
    LimitExceeded,
}

impl MacosSdistGuestAuthErrorV1 {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::InvalidChallenge => "macos_sdist_guest_auth_challenge_invalid",
            Self::InvalidResponse => "macos_sdist_guest_auth_response_invalid",
            Self::NonCanonical => "macos_sdist_guest_auth_noncanonical",
            Self::PublicKeyMismatch => "macos_sdist_guest_auth_public_key_mismatch",
            Self::SignatureFailed => "macos_sdist_guest_auth_signature_failed",
            Self::Serialization => "macos_sdist_guest_auth_serialization_failed",
            Self::LimitExceeded => "macos_sdist_guest_auth_limit_exceeded",
        }
    }
}

impl fmt::Display for MacosSdistGuestAuthErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.reason_code())
    }
}

impl std::error::Error for MacosSdistGuestAuthErrorV1 {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdistGuestAuthChallengeWireV1 {
    schema_version: String,
    nonce_hex: String,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    guest_auth_public_key_sha256: Sha256Digest,
}

#[derive(Clone, PartialEq, Eq)]
pub struct MacosSdistGuestAuthChallengeV1 {
    canonical_json: Vec<u8>,
    nonce_hex: String,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    guest_auth_public_key_sha256: Sha256Digest,
}

impl fmt::Debug for MacosSdistGuestAuthChallengeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MacosSdistGuestAuthChallengeV1")
            .field(
                "nonce_sha256",
                &Sha256Digest::from_bytes(self.nonce_hex.as_bytes()),
            )
            .field("execution_binding_sha256", &self.execution_binding_sha256)
            .field("run_spec_sha256", &self.run_spec_sha256)
            .field("build_closure_sha256", &self.build_closure_sha256)
            .field("clone_binding_sha256", &self.clone_binding_sha256)
            .field(
                "guest_auth_public_key_sha256",
                &self.guest_auth_public_key_sha256,
            )
            .finish()
    }
}

impl MacosSdistGuestAuthChallengeV1 {
    pub fn new(
        nonce: [u8; 32],
        execution_binding_sha256: Sha256Digest,
        run_spec_sha256: Sha256Digest,
        build_closure_sha256: Sha256Digest,
        clone_binding_sha256: Sha256Digest,
        guest_auth_public_key_sha256: Sha256Digest,
    ) -> Result<Self, MacosSdistGuestAuthErrorV1> {
        let nonce_hex = lower_hex_v1(&nonce);
        let wire = SdistGuestAuthChallengeWireV1 {
            schema_version: MACOS_SDIST_GUEST_AUTH_CHALLENGE_SCHEMA_V1.to_string(),
            nonce_hex: nonce_hex.clone(),
            execution_binding_sha256: execution_binding_sha256.clone(),
            run_spec_sha256: run_spec_sha256.clone(),
            build_closure_sha256: build_closure_sha256.clone(),
            clone_binding_sha256: clone_binding_sha256.clone(),
            guest_auth_public_key_sha256: guest_auth_public_key_sha256.clone(),
        };
        let canonical_json = serde_json_canonicalizer::to_vec(&wire)
            .map_err(|_| MacosSdistGuestAuthErrorV1::Serialization)?;
        let challenge = Self {
            canonical_json,
            nonce_hex,
            execution_binding_sha256,
            run_spec_sha256,
            build_closure_sha256,
            clone_binding_sha256,
            guest_auth_public_key_sha256,
        };
        challenge.validate()?;
        Ok(challenge)
    }

    pub fn canonical_json_v1(&self) -> &[u8] {
        &self.canonical_json
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

    pub fn guest_auth_public_key_sha256(&self) -> &Sha256Digest {
        &self.guest_auth_public_key_sha256
    }

    fn validate(&self) -> Result<(), MacosSdistGuestAuthErrorV1> {
        if self.canonical_json.is_empty()
            || self.canonical_json.len() > MAX_MACOS_SDIST_GUEST_AUTH_BYTES_V1
            || !valid_lower_hex_v1(&self.nonce_hex, 64)
        {
            return Err(MacosSdistGuestAuthErrorV1::InvalidChallenge);
        }
        Ok(())
    }
}

pub fn decode_macos_sdist_guest_auth_challenge_v1(
    bytes: &[u8],
) -> Result<MacosSdistGuestAuthChallengeV1, MacosSdistGuestAuthErrorV1> {
    if bytes.is_empty() || bytes.len() > MAX_MACOS_SDIST_GUEST_AUTH_BYTES_V1 {
        return Err(MacosSdistGuestAuthErrorV1::LimitExceeded);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let wire = SdistGuestAuthChallengeWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosSdistGuestAuthErrorV1::InvalidChallenge)?;
    deserializer
        .end()
        .map_err(|_| MacosSdistGuestAuthErrorV1::InvalidChallenge)?;
    let canonical = serde_json_canonicalizer::to_vec(&wire)
        .map_err(|_| MacosSdistGuestAuthErrorV1::Serialization)?;
    if canonical != bytes
        || wire.schema_version != MACOS_SDIST_GUEST_AUTH_CHALLENGE_SCHEMA_V1
        || !valid_lower_hex_v1(&wire.nonce_hex, 64)
    {
        return Err(MacosSdistGuestAuthErrorV1::NonCanonical);
    }
    let challenge = MacosSdistGuestAuthChallengeV1 {
        canonical_json: canonical,
        nonce_hex: wire.nonce_hex,
        execution_binding_sha256: wire.execution_binding_sha256,
        run_spec_sha256: wire.run_spec_sha256,
        build_closure_sha256: wire.build_closure_sha256,
        clone_binding_sha256: wire.clone_binding_sha256,
        guest_auth_public_key_sha256: wire.guest_auth_public_key_sha256,
    };
    challenge.validate()?;
    Ok(challenge)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdistGuestAuthUnsignedResponseWireV1 {
    schema_version: String,
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    guest_supervisor_sha256: Sha256Digest,
    runner_configuration_sha256: Sha256Digest,
    package_uid: String,
    package_gid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SdistGuestAuthResponseWireV1 {
    schema_version: String,
    challenge_sha256: Sha256Digest,
    execution_binding_sha256: Sha256Digest,
    run_spec_sha256: Sha256Digest,
    build_closure_sha256: Sha256Digest,
    clone_binding_sha256: Sha256Digest,
    guest_supervisor_sha256: Sha256Digest,
    runner_configuration_sha256: Sha256Digest,
    package_uid: String,
    package_gid: String,
    signature_ed25519_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacosSdistGuestAuthClaimsV1 {
    guest_supervisor_sha256: Sha256Digest,
    runner_configuration_sha256: Sha256Digest,
    package_uid: u32,
    package_gid: u32,
}

impl MacosSdistGuestAuthClaimsV1 {
    pub fn new(
        guest_supervisor_sha256: Sha256Digest,
        runner_configuration_sha256: Sha256Digest,
        package_uid: u32,
        package_gid: u32,
    ) -> Result<Self, MacosSdistGuestAuthErrorV1> {
        if package_uid == 0 || package_gid == 0 {
            return Err(MacosSdistGuestAuthErrorV1::InvalidResponse);
        }
        Ok(Self {
            guest_supervisor_sha256,
            runner_configuration_sha256,
            package_uid,
            package_gid,
        })
    }

    pub fn guest_supervisor_sha256(&self) -> &Sha256Digest {
        &self.guest_supervisor_sha256
    }

    pub fn runner_configuration_sha256(&self) -> &Sha256Digest {
        &self.runner_configuration_sha256
    }

    pub fn package_uid(&self) -> u32 {
        self.package_uid
    }

    pub fn package_gid(&self) -> u32 {
        self.package_gid
    }
}

pub fn sign_macos_sdist_guest_auth_response_v1(
    challenge: &MacosSdistGuestAuthChallengeV1,
    mut signing_seed: [u8; 32],
    claims: &MacosSdistGuestAuthClaimsV1,
) -> Result<Vec<u8>, MacosSdistGuestAuthErrorV1> {
    challenge.validate()?;
    let signing_key = SigningKey::from_bytes(&signing_seed);
    signing_seed.zeroize();
    if Sha256Digest::from_bytes(signing_key.verifying_key().as_bytes())
        != *challenge.guest_auth_public_key_sha256()
    {
        return Err(MacosSdistGuestAuthErrorV1::PublicKeyMismatch);
    }
    let unsigned = unsigned_response_v1(challenge, claims);
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosSdistGuestAuthErrorV1::Serialization)?;
    let signature = signing_key.sign(&response_signature_message_v1(
        challenge.canonical_json_v1(),
        &unsigned_bytes,
    ));
    let response = SdistGuestAuthResponseWireV1 {
        schema_version: unsigned.schema_version,
        challenge_sha256: unsigned.challenge_sha256,
        execution_binding_sha256: unsigned.execution_binding_sha256,
        run_spec_sha256: unsigned.run_spec_sha256,
        build_closure_sha256: unsigned.build_closure_sha256,
        clone_binding_sha256: unsigned.clone_binding_sha256,
        guest_supervisor_sha256: unsigned.guest_supervisor_sha256,
        runner_configuration_sha256: unsigned.runner_configuration_sha256,
        package_uid: unsigned.package_uid,
        package_gid: unsigned.package_gid,
        signature_ed25519_hex: lower_hex_v1(&signature.to_bytes()),
    };
    let bytes = serde_json_canonicalizer::to_vec(&response)
        .map_err(|_| MacosSdistGuestAuthErrorV1::Serialization)?;
    if bytes.len() > MAX_MACOS_SDIST_GUEST_AUTH_BYTES_V1 {
        return Err(MacosSdistGuestAuthErrorV1::LimitExceeded);
    }
    Ok(bytes)
}

pub fn verify_macos_sdist_guest_auth_response_v1(
    challenge: &MacosSdistGuestAuthChallengeV1,
    response_bytes: &[u8],
    verifying_key_bytes: [u8; 32],
    expected_claims: &MacosSdistGuestAuthClaimsV1,
) -> Result<(), MacosSdistGuestAuthErrorV1> {
    challenge.validate()?;
    if response_bytes.is_empty() || response_bytes.len() > MAX_MACOS_SDIST_GUEST_AUTH_BYTES_V1 {
        return Err(MacosSdistGuestAuthErrorV1::LimitExceeded);
    }
    if Sha256Digest::from_bytes(&verifying_key_bytes) != *challenge.guest_auth_public_key_sha256() {
        return Err(MacosSdistGuestAuthErrorV1::PublicKeyMismatch);
    }
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|_| MacosSdistGuestAuthErrorV1::PublicKeyMismatch)?;
    if verifying_key.is_weak() {
        return Err(MacosSdistGuestAuthErrorV1::PublicKeyMismatch);
    }
    let mut deserializer = serde_json::Deserializer::from_slice(response_bytes);
    let response = SdistGuestAuthResponseWireV1::deserialize(&mut deserializer)
        .map_err(|_| MacosSdistGuestAuthErrorV1::InvalidResponse)?;
    deserializer
        .end()
        .map_err(|_| MacosSdistGuestAuthErrorV1::InvalidResponse)?;
    let canonical = serde_json_canonicalizer::to_vec(&response)
        .map_err(|_| MacosSdistGuestAuthErrorV1::Serialization)?;
    if canonical != response_bytes || !valid_lower_hex_v1(&response.signature_ed25519_hex, 128) {
        return Err(MacosSdistGuestAuthErrorV1::NonCanonical);
    }
    let signature_hex = response.signature_ed25519_hex.clone();
    let unsigned = SdistGuestAuthUnsignedResponseWireV1 {
        schema_version: response.schema_version,
        challenge_sha256: response.challenge_sha256,
        execution_binding_sha256: response.execution_binding_sha256,
        run_spec_sha256: response.run_spec_sha256,
        build_closure_sha256: response.build_closure_sha256,
        clone_binding_sha256: response.clone_binding_sha256,
        guest_supervisor_sha256: response.guest_supervisor_sha256,
        runner_configuration_sha256: response.runner_configuration_sha256,
        package_uid: response.package_uid,
        package_gid: response.package_gid,
    };
    if unsigned != unsigned_response_v1(challenge, expected_claims) {
        return Err(MacosSdistGuestAuthErrorV1::InvalidResponse);
    }
    let unsigned_bytes = serde_json_canonicalizer::to_vec(&unsigned)
        .map_err(|_| MacosSdistGuestAuthErrorV1::Serialization)?;
    let signature = Signature::from_bytes(&decode_hex_array_v1::<64>(&signature_hex)?);
    verifying_key
        .verify_strict(
            &response_signature_message_v1(challenge.canonical_json_v1(), &unsigned_bytes),
            &signature,
        )
        .map_err(|_| MacosSdistGuestAuthErrorV1::SignatureFailed)
}

fn unsigned_response_v1(
    challenge: &MacosSdistGuestAuthChallengeV1,
    claims: &MacosSdistGuestAuthClaimsV1,
) -> SdistGuestAuthUnsignedResponseWireV1 {
    SdistGuestAuthUnsignedResponseWireV1 {
        schema_version: MACOS_SDIST_GUEST_AUTH_RESPONSE_SCHEMA_V1.to_string(),
        challenge_sha256: Sha256Digest::from_bytes(challenge.canonical_json_v1()),
        execution_binding_sha256: challenge.execution_binding_sha256.clone(),
        run_spec_sha256: challenge.run_spec_sha256.clone(),
        build_closure_sha256: challenge.build_closure_sha256.clone(),
        clone_binding_sha256: challenge.clone_binding_sha256.clone(),
        guest_supervisor_sha256: claims.guest_supervisor_sha256.clone(),
        runner_configuration_sha256: claims.runner_configuration_sha256.clone(),
        package_uid: claims.package_uid.to_string(),
        package_gid: claims.package_gid.to_string(),
    }
}

fn response_signature_message_v1(challenge: &[u8], unsigned_response: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        SDIST_RESPONSE_SIGNATURE_DOMAIN_V1.len() + challenge.len() + 1 + unsigned_response.len(),
    );
    message.extend_from_slice(SDIST_RESPONSE_SIGNATURE_DOMAIN_V1);
    message.extend_from_slice(challenge);
    message.push(0);
    message.extend_from_slice(unsigned_response);
    message
}

fn lower_hex_v1(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut value, "{byte:02x}").expect("writing to String cannot fail");
    }
    value
}

fn valid_lower_hex_v1(value: &str, exact_length: usize) -> bool {
    value.len() == exact_length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn decode_hex_array_v1<const N: usize>(value: &str) -> Result<[u8; N], MacosSdistGuestAuthErrorV1> {
    if !valid_lower_hex_v1(value, N * 2) {
        return Err(MacosSdistGuestAuthErrorV1::InvalidResponse);
    }
    let mut decoded = [0_u8; N];
    for (index, output) in decoded.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| MacosSdistGuestAuthErrorV1::InvalidResponse)?;
    }
    Ok(decoded)
}
